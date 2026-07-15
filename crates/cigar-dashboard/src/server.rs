//! Authenticated loopback HTTP shell and verified static asset serving.

use crate::{
    AvailabilityState, BootstrapAuthority, ControlError, ControlPlane, CursorAuthority,
    CursorError, CursorKind, DashboardConfig, DashboardProtocolCatalog, EventError,
    EvidenceDescriptor, HistoryClient, HistoryError, HistoryStore, RunProfile, RunProfileRegistry,
    RunRecord, SafeEventBroker, SessionError, SessionManager, StaticAssets, StatusMonitor,
    StatusService, VerifiedAsset, write_bootstrap_file,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Json, Path, RawQuery, State};
use axum::http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, ETAG,
    HOST, ORIGIN, SET_COOKIE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_stream::StreamExt as _;
use tower_http::limit::RequestBodyLimitLayer;
use zeroize::Zeroizing;

const SESSION_COOKIE: &str = "cigar_dashboard_session";
const CSRF_HEADER: &str = "x-cigar-csrf";
const SESSION_TTL: Duration = Duration::from_secs(60 * 60);
const SESSION_CAPACITY: usize = 16;
const MAX_BOOTSTRAP_BODY_TOKEN: usize = 64;
const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 100;
const MAX_PAGE_QUERY_BYTES: usize = 384;
const CSP: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'";

/// Stable content-free dashboard server failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardServerError {
    /// Validated frontend assets could not be loaded.
    AssetsUnavailable,
    /// A bootstrap authority or browser session store could not be created.
    SessionUnavailable,
    /// The owner-only one-time bootstrap file could not be created.
    BootstrapUnavailable,
    /// An explicitly configured reviewed run-profile registry failed validation.
    ProfileRegistryUnavailable,
    /// The content-safe aggregate status service could not initialize.
    StatusUnavailable,
    /// The bounded content-safe event broker could not initialize.
    EventsUnavailable,
    /// The dashboard-owned event history could not open safely.
    HistoryUnavailable,
    /// The short-lived pagination cursor authority could not initialize.
    CursorUnavailable,
    /// Enabled reviewed controls could not establish their safe native supervisor boundary.
    ControlUnavailable,
}

impl fmt::Display for DashboardServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AssetsUnavailable => "dashboard assets are unavailable",
            Self::SessionUnavailable => "dashboard session authority is unavailable",
            Self::BootstrapUnavailable => "dashboard bootstrap channel is unavailable",
            Self::ProfileRegistryUnavailable => "dashboard run-profile registry is unavailable",
            Self::StatusUnavailable => "dashboard status service is unavailable",
            Self::EventsUnavailable => "dashboard event service is unavailable",
            Self::HistoryUnavailable => "dashboard history service is unavailable",
            Self::CursorUnavailable => "dashboard cursor service is unavailable",
            Self::ControlUnavailable => "dashboard control service is unavailable",
        })
    }
}

impl std::error::Error for DashboardServerError {}

#[derive(Clone)]
struct AppState {
    sessions: Arc<SessionManager>,
    assets: StaticAssets,
    target_alias: Arc<str>,
    control_enabled: bool,
    profile_registry: Option<Arc<RunProfileRegistry>>,
    control: Option<ControlPlane>,
    status: StatusService,
    events: SafeEventBroker,
    history: HistoryClient,
    cursors: CursorAuthority,
    expected_host: Arc<str>,
    expected_origin: Arc<str>,
    bootstrap_file: Arc<PathBuf>,
    max_request_bytes: usize,
}

/// Fully initialized dashboard application with one unconsumed bootstrap credential.
pub struct DashboardApplication {
    state: AppState,
    history: HistoryStore,
    bootstrap_token: Zeroizing<String>,
    listen: SocketAddr,
}

impl DashboardApplication {
    /// Validates immutable assets and creates one owner-only bootstrap channel.
    pub fn initialize(config: &DashboardConfig) -> Result<Self, DashboardServerError> {
        let assets = StaticAssets::load(&config.server.asset_directory)
            .map_err(|_error| DashboardServerError::AssetsUnavailable)?;
        let (bootstrap, token) = BootstrapAuthority::generate()
            .map_err(|_error| DashboardServerError::SessionUnavailable)?;
        let sessions = SessionManager::new(bootstrap, SESSION_TTL, SESSION_CAPACITY)
            .map_err(|_error| DashboardServerError::SessionUnavailable)?;
        let profile_registry = config
            .control
            .profile_registry
            .as_deref()
            .map(RunProfileRegistry::load)
            .transpose()
            .map_err(|_error| DashboardServerError::ProfileRegistryUnavailable)?
            .map(Arc::new);
        let bootstrap_file = config
            .server
            .runtime_directory
            .join("dashboard-bootstrap.token");
        write_bootstrap_file(&bootstrap_file, &token)
            .map_err(|_error| DashboardServerError::BootstrapUnavailable)?;
        let expected_host = config.server.listen.to_string();
        let expected_origin = format!("http://{expected_host}");
        let history = HistoryStore::open(&config.history, config.server.max_event_bytes)
            .map_err(|_error| DashboardServerError::HistoryUnavailable)?;
        let cursors = CursorAuthority::generate()
            .map_err(|_error| DashboardServerError::CursorUnavailable)?;
        let events = SafeEventBroker::new_seeded(
            config.history.max_events_per_run.min(10_000),
            config.history.max_bytes,
            config.server.max_event_bytes,
            config.server.max_sse_subscribers,
            history.retained_events(),
        )
        .map_err(|_error| DashboardServerError::EventsUnavailable)?;
        events
            .attach_sink(history.sink())
            .map_err(|_error| DashboardServerError::HistoryUnavailable)?;
        let status = StatusService::with_events(
            config.display.target_alias.clone(),
            config.control.enabled,
            events.clone(),
        )
        .map_err(|_error| DashboardServerError::StatusUnavailable)?;
        let history_client = history.client();
        let control = if config.control.enabled {
            let registry = profile_registry
                .as_ref()
                .ok_or(DashboardServerError::ControlUnavailable)?
                .clone();
            Some(
                ControlPlane::initialize(config, registry, history_client.clone(), events.clone())
                    .map_err(|_error| DashboardServerError::ControlUnavailable)?,
            )
        } else {
            None
        };
        Ok(Self {
            state: AppState {
                sessions: Arc::new(sessions),
                assets,
                target_alias: Arc::from(config.display.target_alias.as_str()),
                control_enabled: config.control.enabled,
                profile_registry,
                control,
                status,
                events,
                history: history_client,
                cursors,
                expected_host: Arc::from(expected_host),
                expected_origin: Arc::from(expected_origin),
                bootstrap_file: Arc::new(bootstrap_file),
                max_request_bytes: config.server.max_request_bytes,
            },
            history,
            bootstrap_token: token,
            listen: config.server.listen,
        })
    }

    /// Returns the configured numeric loopback listener.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Returns the one-time URL fragment token. Callers must not log it after initial presentation.
    #[must_use]
    pub fn bootstrap_token(&self) -> &str {
        &self.bootstrap_token
    }

    /// Builds the bounded Axum application.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(health))
            .route("/api/v1/session:exchange", post(exchange_session))
            .route("/api/v1/session:csrf", post(rotate_csrf))
            .route("/api/v1/session:logout", post(logout_session))
            .route("/api/v1/bootstrap", get(bootstrap))
            .route("/api/v1/protocol", get(protocol))
            .route("/api/v1/run-profiles", get(run_profiles))
            .route("/api/v1/status", get(status))
            .route("/api/v1/events", get(events))
            .route("/api/v1/runs", get(runs).post(start_run))
            .route("/api/v1/runs/{run_id}", get(run_detail).post(cancel_run))
            .route("/api/v1/evidence", get(evidence))
            .route("/api/v1/evidence/{evidence_id}", get(evidence_detail))
            .fallback(static_fallback)
            .layer(RequestBodyLimitLayer::new(self.state.max_request_bytes))
            .with_state(self.state.clone())
    }

    /// Removes the no-longer-useful bootstrap file after shutdown.
    pub fn cleanup_bootstrap_file(&self) {
        match fs::remove_file(self.state.bootstrap_file.as_ref()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_error) => {}
        }
        let _ignored = self.history.shutdown();
    }

    /// Cancels and settles every dashboard-owned child before history is closed.
    pub async fn shutdown_controls(&self, deadline: Duration) {
        if let Some(control) = &self.state.control {
            control.shutdown(deadline).await;
        }
    }

    /// Starts the typed SDK status monitor without changing daemon state.
    #[must_use]
    pub fn start_status_monitor(&self, config: &DashboardConfig) -> StatusMonitor {
        StatusMonitor::start(self.state.status.clone(), config.target.clone())
    }
}

impl fmt::Debug for DashboardApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DashboardApplication")
            .field("listen", &self.listen)
            .field("asset_count", &self.state.assets.file_count())
            .field("control_enabled", &self.state.control_enabled)
            .field("history", &self.history)
            .field(
                "profile_count",
                &self
                    .state
                    .profile_registry
                    .as_deref()
                    .map_or(0, |registry| registry.profiles().len()),
            )
            .field("bootstrap_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeRequest {
    bootstrap_secret: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExchangeResponse<'a> {
    schema_version: &'static str,
    csrf_token: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CsrfResponse<'a> {
    schema_version: &'static str,
    csrf_token: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapResponse<'a> {
    schema_version: &'static str,
    sidecar_version: &'static str,
    target_alias: &'a str,
    control_enabled: bool,
    asset_count: usize,
    max_request_bytes: usize,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HealthResponse {
    live: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RunProfilesResponse<'a> {
    schema_version: &'static str,
    control_enabled: bool,
    registry_digest: Option<String>,
    source_revision: Option<&'a str>,
    profiles: Vec<RunProfile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRunRequest {
    profile_id: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RunsResponse<'a> {
    schema_version: &'static str,
    runs: &'a [RunRecord],
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceResponse<'a> {
    schema_version: &'static str,
    evidence: &'a [EvidenceDescriptor],
    next_cursor: Option<String>,
}

struct PageRequest {
    limit: usize,
    cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DashboardProblem<'a> {
    r#type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    correlation_id: &'a str,
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    secure_json(Json(HealthResponse { live: true }).into_response())
}

async fn exchange_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = validate_same_origin(&state, &headers) {
        return request_guard_problem(error);
    }
    if !has_json_content_type(&headers) {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard content type is invalid",
        );
    }
    let request: ExchangeRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "DASHBOARD_INVALID_ARGUMENT",
                "Dashboard request is invalid",
            );
        }
    };
    if request.bootstrap_secret.len() > MAX_BOOTSTRAP_BODY_TOKEN {
        return problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard request is invalid",
        );
    }
    let credentials = match state.sessions.exchange(&request.bootstrap_secret) {
        Ok(credentials) => credentials,
        Err(error) => return session_problem(error),
    };
    let mut response = secure_json(
        (
            StatusCode::CREATED,
            Json(ExchangeResponse {
                schema_version: "cigar.dashboard-session.v1",
                csrf_token: credentials.csrf_token(),
            }),
        )
            .into_response(),
    );
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600",
        credentials.session_token()
    );
    let Ok(cookie_header) = HeaderValue::from_str(&cookie) else {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DASHBOARD_INTERNAL",
            "Dashboard request failed",
        );
    };
    response.headers_mut().insert(SET_COOKIE, cookie_header);
    match fs::remove_file(state.bootstrap_file.as_ref()) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_error) => {}
    }
    response
}

async fn rotate_csrf(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(error) = validate_same_origin(&state, &headers) {
        return request_guard_problem(error);
    }
    if !body.is_empty() {
        return problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard CSRF rotation request must be empty",
        );
    }
    let session = match authorize(&state, &headers, false) {
        Ok(session) => session,
        Err(error) => return session_problem(error),
    };
    let csrf = match state.sessions.rotate_csrf(&session) {
        Ok(csrf) => csrf,
        Err(error) => return session_problem(error),
    };
    secure_json(
        Json(CsrfResponse {
            schema_version: "cigar.dashboard-session.v1",
            csrf_token: &csrf,
        })
        .into_response(),
    )
}

async fn bootstrap(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    secure_json(
        Json(BootstrapResponse {
            schema_version: "cigar.dashboard-bootstrap.v1",
            sidecar_version: env!("CARGO_PKG_VERSION"),
            target_alias: &state.target_alias,
            control_enabled: state.control_enabled,
            asset_count: state.assets.file_count(),
            max_request_bytes: state.max_request_bytes,
        })
        .into_response(),
    )
}

async fn run_profiles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    let registry = state.profile_registry.as_deref();
    let profiles = state.control.as_ref().map_or_else(
        || {
            registry.map_or_else(Vec::new, |registry| {
                registry
                    .profiles()
                    .iter()
                    .map(|profile| {
                        if profile.availability_state() == AvailabilityState::Available {
                            profile.with_availability(AvailabilityState::ControlDisabled)
                        } else {
                            profile.clone()
                        }
                    })
                    .collect()
            })
        },
        ControlPlane::public_profiles,
    );
    secure_json(
        Json(RunProfilesResponse {
            schema_version: "cigar.dashboard-run-profiles.v1",
            control_enabled: state.control_enabled,
            registry_digest: registry.map(RunProfileRegistry::digest_hex),
            source_revision: registry.map(RunProfileRegistry::source_revision),
            profiles,
        })
        .into_response(),
    )
}

async fn start_run(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(error) = validate_same_origin(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, true) {
        return session_problem(error);
    }
    if !has_exact_json_content_type(&headers) {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard content type is invalid",
        );
    }
    let request: StartRunRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "DASHBOARD_INVALID_ARGUMENT",
                "Dashboard run request is invalid",
            );
        }
    };
    let Some(control) = &state.control else {
        return control_problem(ControlError::Unavailable);
    };
    match control.start(&request.profile_id) {
        Ok(run) => secure_json((StatusCode::ACCEPTED, Json(run)).into_response()),
        Err(error) => control_problem(error),
    }
}

async fn cancel_run(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = validate_same_origin(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, true) {
        return session_problem(error);
    }
    if !body.is_empty() {
        return problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard cancellation request must be empty",
        );
    }
    let Some(run_id) = run_id.strip_suffix(":cancel") else {
        return problem(
            StatusCode::NOT_FOUND,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard control route was not found",
        );
    };
    let Some(control) = &state.control else {
        return control_problem(ControlError::Unavailable);
    };
    match control.cancel(run_id) {
        Ok(run) => secure_json((StatusCode::ACCEPTED, Json(run)).into_response()),
        Err(error) => control_problem(error),
    }
}

async fn protocol(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    let mut response = Response::new(Body::from(DashboardProtocolCatalog::generated_json()));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    secure_json(response)
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    secure_json(Json(state.status.snapshot().await).into_response())
}

async fn events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    let last_event_sequence = match last_event_sequence(&headers) {
        Ok(sequence) => sequence,
        Err(error) => return event_problem(error),
    };
    let stream = match state.events.subscribe(last_event_sequence) {
        Ok(stream) => stream,
        Err(error) => return event_problem(error),
    };
    let stream = stream.map(|result| {
        let event = result?;
        let sequence = event.sequence().to_string();
        let kind = event.kind_name();
        let data = event.to_json()?;
        Ok::<Event, EventError>(
            Event::default()
                .id(sequence)
                .event(kind)
                .data(data)
                .retry(Duration::from_secs(2)),
        )
    });
    secure_json(
        Sse::new(stream)
            .keep_alive(
                KeepAlive::new()
                    .interval(Duration::from_secs(15))
                    .text("keep-alive"),
            )
            .into_response(),
    )
}

async fn runs(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    let request = match parse_page_query(raw_query.as_deref()) {
        Ok(request) => request,
        Err(error) => return cursor_problem(error),
    };
    let after = match request.cursor.as_deref() {
        Some(cursor) => match state.cursors.decode(CursorKind::Runs, cursor) {
            Ok(position) => Some(position),
            Err(error) => return cursor_problem(error),
        },
        None => None,
    };
    let client = state.history.clone();
    let page = match tokio::task::spawn_blocking(move || {
        client.list_runs_page(request.limit, after)
    })
    .await
    {
        Ok(Ok(page)) => page,
        Ok(Err(error)) => return history_problem(error),
        Err(_error) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "DASHBOARD_INTERNAL",
                "Dashboard history service is unavailable",
            );
        }
    };
    let next_cursor = match page
        .next
        .as_ref()
        .map(|position| state.cursors.encode(CursorKind::Runs, position))
        .transpose()
    {
        Ok(cursor) => cursor,
        Err(error) => return cursor_problem(error),
    };
    secure_json(
        Json(RunsResponse {
            schema_version: "cigar.dashboard-runs.v1",
            runs: &page.records,
            next_cursor,
        })
        .into_response(),
    )
}

async fn run_detail(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    if run_id.len() != 36 {
        return history_problem(HistoryError::InvalidRun);
    }
    let client = state.history.clone();
    let run = match tokio::task::spawn_blocking(move || client.get_run(&run_id)).await {
        Ok(Ok(run)) => run,
        Ok(Err(error)) => return history_problem(error),
        Err(_error) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "DASHBOARD_INTERNAL",
                "Dashboard history service is unavailable",
            );
        }
    };
    secure_json(Json(run).into_response())
}

async fn evidence(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    let request = match parse_page_query(raw_query.as_deref()) {
        Ok(request) => request,
        Err(error) => return cursor_problem(error),
    };
    let after = match request.cursor.as_deref() {
        Some(cursor) => match state.cursors.decode(CursorKind::Evidence, cursor) {
            Ok(position) => Some(position),
            Err(error) => return cursor_problem(error),
        },
        None => None,
    };
    let client = state.history.clone();
    let page =
        match tokio::task::spawn_blocking(move || client.list_evidence_page(request.limit, after))
            .await
        {
            Ok(Ok(page)) => page,
            Ok(Err(error)) => return history_problem(error),
            Err(_error) => {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "DASHBOARD_INTERNAL",
                    "Dashboard history service is unavailable",
                );
            }
        };
    let next_cursor = match page
        .next
        .as_ref()
        .map(|position| state.cursors.encode(CursorKind::Evidence, position))
        .transpose()
    {
        Ok(cursor) => cursor,
        Err(error) => return cursor_problem(error),
    };
    secure_json(
        Json(EvidenceResponse {
            schema_version: "cigar.dashboard-evidence-index.v1",
            evidence: &page.records,
            next_cursor,
        })
        .into_response(),
    )
}

async fn evidence_detail(
    State(state): State<AppState>,
    Path(evidence_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if let Err(error) = authorize(&state, &headers, false) {
        return session_problem(error);
    }
    if evidence_id.is_empty() || evidence_id.len() > 128 {
        return history_problem(HistoryError::InvalidEvidence);
    }
    let client = state.history.clone();
    let descriptor =
        match tokio::task::spawn_blocking(move || client.get_evidence(&evidence_id)).await {
            Ok(Ok(descriptor)) => descriptor,
            Ok(Err(error)) => return history_problem(error),
            Err(_error) => {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "DASHBOARD_INTERNAL",
                    "Dashboard history service is unavailable",
                );
            }
        };
    secure_json(Json(descriptor).into_response())
}

async fn logout_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_same_origin(&state, &headers) {
        return request_guard_problem(error);
    }
    let token = match authorize(&state, &headers, true) {
        Ok(token) => token,
        Err(error) => return session_problem(error),
    };
    if let Err(error) = state.sessions.revoke(&token) {
        return session_problem(error);
    }
    let mut response = secure_json(StatusCode::NO_CONTENT.into_response());
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "cigar_dashboard_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    response
}

async fn static_fallback(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_host(&state, &headers) {
        return request_guard_problem(error);
    }
    if method != Method::GET && method != Method::HEAD {
        return problem(
            StatusCode::METHOD_NOT_ALLOWED,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard method is not allowed",
        );
    }
    if uri.path().starts_with("/api/") {
        return problem(
            StatusCode::NOT_FOUND,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard route was not found",
        );
    }
    let requested = uri.path().strip_prefix('/').map_or(uri.path(), |path| path);
    let asset = if requested.is_empty() {
        state.assets.index()
    } else if let Some(asset) = state.assets.get(requested) {
        asset
    } else if accepts_html(&headers) && !requested.contains('.') && !requested.contains('%') {
        state.assets.index()
    } else {
        return problem(
            StatusCode::NOT_FOUND,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard asset was not found",
        );
    };
    asset_response(
        asset,
        method == Method::HEAD,
        requested == "index.html" || requested.is_empty(),
    )
}

fn asset_response(asset: &VerifiedAsset, head: bool, no_store: bool) -> Response {
    let body = if head {
        Body::empty()
    } else {
        Body::from(asset.bytes().to_vec())
    };
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(asset.media_type()));
    if let Ok(length) = HeaderValue::from_str(&asset.bytes().len().to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, length);
    }
    if let Ok(etag) = HeaderValue::from_str(&asset.etag()) {
        response.headers_mut().insert(ETAG, etag);
    }
    response.headers_mut().insert(
        CACHE_CONTROL,
        if no_store {
            HeaderValue::from_static("no-store")
        } else {
            HeaderValue::from_static("public, max-age=31536000, immutable")
        },
    );
    secure_headers(response)
}

fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    csrf_required: bool,
) -> Result<Zeroizing<String>, SessionError> {
    let token = session_cookie(headers)?;
    let csrf = if csrf_required {
        Some(unique_header(headers, CSRF_HEADER).ok_or(SessionError::CsrfRejected)?)
    } else {
        None
    };
    state.sessions.authorize(&token, csrf)?;
    Ok(token)
}

fn session_cookie(headers: &HeaderMap) -> Result<Zeroizing<String>, SessionError> {
    let mut cookie_headers = headers.get_all(COOKIE).iter();
    let value = cookie_headers
        .next()
        .ok_or(SessionError::Unauthorized)?
        .to_str()
        .map_err(|_error| SessionError::Unauthorized)?;
    if cookie_headers.next().is_some() || value.len() > 4096 {
        return Err(SessionError::Unauthorized);
    }
    let mut found = None;
    for item in value.split(';') {
        let Some((name, candidate)) = item.trim().split_once('=') else {
            return Err(SessionError::Unauthorized);
        };
        if name == SESSION_COOKIE {
            if found.is_some() || candidate.is_empty() || candidate.len() > 64 {
                return Err(SessionError::Unauthorized);
            }
            found = Some(Zeroizing::new(candidate.to_owned()));
        }
    }
    found.ok_or(SessionError::Unauthorized)
}

#[derive(Clone, Copy)]
enum RequestGuardError {
    HostRejected,
    OriginRejected,
}

fn validate_same_origin(state: &AppState, headers: &HeaderMap) -> Result<(), RequestGuardError> {
    validate_host(state, headers)?;
    let origin =
        unique_header(headers, ORIGIN.as_str()).ok_or(RequestGuardError::OriginRejected)?;
    if origin == state.expected_origin.as_ref() {
        Ok(())
    } else {
        Err(RequestGuardError::OriginRejected)
    }
}

fn validate_host(state: &AppState, headers: &HeaderMap) -> Result<(), RequestGuardError> {
    if unique_header(headers, HOST.as_str()) == Some(state.expected_host.as_ref()) {
        Ok(())
    } else {
        Err(RequestGuardError::HostRejected)
    }
}

fn request_guard_problem(error: RequestGuardError) -> Response {
    match error {
        RequestGuardError::HostRejected => problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard request host was rejected",
        ),
        RequestGuardError::OriginRejected => problem(
            StatusCode::FORBIDDEN,
            "DASHBOARD_CSRF_REJECTED",
            "Dashboard request origin was rejected",
        ),
    }
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn accepts_html(headers: &HeaderMap) -> bool {
    unique_header(headers, ACCEPT.as_str()).is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|item| item == "text/html" || item.starts_with("text/html;"))
    })
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    unique_header(headers, CONTENT_TYPE.as_str()).is_some_and(|value| {
        value
            .split_once(';')
            .map_or(value, |(media_type, _parameters)| media_type)
            .trim()
            .eq_ignore_ascii_case("application/json")
    })
}

fn has_exact_json_content_type(headers: &HeaderMap) -> bool {
    unique_header(headers, CONTENT_TYPE.as_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

fn last_event_sequence(headers: &HeaderMap) -> Result<Option<u64>, EventError> {
    let name = HeaderName::from_static("last-event-id");
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(EventError::InvalidResume);
    }
    let value = value.to_str().map_err(|_error| EventError::InvalidResume)?;
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EventError::InvalidResume);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_error| EventError::InvalidResume)
}

fn parse_page_query(source: Option<&str>) -> Result<PageRequest, CursorError> {
    let Some(source) = source else {
        return Ok(PageRequest {
            limit: DEFAULT_PAGE_SIZE,
            cursor: None,
        });
    };
    if source.is_empty() {
        return Ok(PageRequest {
            limit: DEFAULT_PAGE_SIZE,
            cursor: None,
        });
    }
    if source.len() > MAX_PAGE_QUERY_BYTES
        || source.contains(['%', '+'])
        || !source.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CursorError::InvalidCursor);
    }
    let mut limit = None;
    let mut cursor = None;
    for field in source.split('&') {
        let (name, value) = field.split_once('=').ok_or(CursorError::InvalidCursor)?;
        if value.is_empty() || value.contains('=') {
            return Err(CursorError::InvalidCursor);
        }
        match name {
            "limit" if limit.is_none() => {
                if value.len() > 3
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(CursorError::InvalidCursor);
                }
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_error| CursorError::InvalidCursor)?;
                if !(1..=MAX_PAGE_SIZE).contains(&parsed) {
                    return Err(CursorError::InvalidCursor);
                }
                limit = Some(parsed);
            }
            "cursor" if cursor.is_none() => {
                if value.len() > 256
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(CursorError::InvalidCursor);
                }
                cursor = Some(value.to_owned());
            }
            _ => return Err(CursorError::InvalidCursor),
        }
    }
    Ok(PageRequest {
        limit: limit.unwrap_or(DEFAULT_PAGE_SIZE),
        cursor,
    })
}

fn session_problem(error: SessionError) -> Response {
    match error {
        SessionError::Unauthorized => problem(
            StatusCode::UNAUTHORIZED,
            "DASHBOARD_AUTH_REQUIRED",
            "Dashboard authentication is required",
        ),
        SessionError::CsrfRejected => problem(
            StatusCode::FORBIDDEN,
            "DASHBOARD_CSRF_REJECTED",
            "Dashboard CSRF proof was rejected",
        ),
        SessionError::StoreUnavailable => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "DASHBOARD_INTERNAL",
            "Dashboard session service is unavailable",
        ),
        SessionError::RandomUnavailable
        | SessionError::InvalidConfiguration
        | SessionError::BootstrapFileUnavailable => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DASHBOARD_INTERNAL",
            "Dashboard request failed",
        ),
    }
}

fn event_problem(error: EventError) -> Response {
    match error {
        EventError::InvalidEvent | EventError::InvalidResume => problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard event request is invalid",
        ),
        EventError::LimitExceeded | EventError::SubscriberLimit => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "DASHBOARD_LIMIT_EXCEEDED",
            "Dashboard event limit was reached",
        ),
        EventError::IdentityUnavailable
        | EventError::SequenceExhausted
        | EventError::StoreUnavailable => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "DASHBOARD_INTERNAL",
            "Dashboard event service is unavailable",
        ),
    }
}

fn cursor_problem(error: CursorError) -> Response {
    match error {
        CursorError::InvalidCursor => problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard pagination cursor is invalid",
        ),
        CursorError::AuthorityUnavailable => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "DASHBOARD_INTERNAL",
            "Dashboard cursor service is unavailable",
        ),
    }
}

fn history_problem(error: HistoryError) -> Response {
    match error {
        HistoryError::InvalidRun
        | HistoryError::InvalidTransition
        | HistoryError::InvalidEvidence => problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard history request is invalid",
        ),
        HistoryError::RunNotFound | HistoryError::EvidenceNotFound => problem(
            StatusCode::NOT_FOUND,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard history record was not found",
        ),
        HistoryError::LimitExceeded => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "DASHBOARD_LIMIT_EXCEEDED",
            "Dashboard history limit was reached",
        ),
        HistoryError::UnsafePath
        | HistoryError::InvalidDatabase
        | HistoryError::InvalidEvent
        | HistoryError::DiskFull
        | HistoryError::WriterUnavailable => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "DASHBOARD_INTERNAL",
            "Dashboard history service is unavailable",
        ),
    }
}

fn control_problem(error: ControlError) -> Response {
    match error {
        ControlError::InvalidRequest => problem(
            StatusCode::BAD_REQUEST,
            "DASHBOARD_INVALID_ARGUMENT",
            "Dashboard control request is invalid",
        ),
        ControlError::Unavailable
        | ControlError::SourceMismatch
        | ControlError::RecoveryRequired => problem(
            StatusCode::CONFLICT,
            "DASHBOARD_CONTROL_UNAVAILABLE",
            "Dashboard control profile is unavailable",
        ),
        ControlError::Capacity => problem(
            StatusCode::TOO_MANY_REQUESTS,
            "DASHBOARD_LIMIT_EXCEEDED",
            "Dashboard control capacity was reached",
        ),
        ControlError::UnsafePath | ControlError::Persistence | ControlError::SpawnFailed => {
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "DASHBOARD_INTERNAL",
                "Dashboard control service is unavailable",
            )
        }
    }
}

fn problem(status: StatusCode, code: &'static str, title: &'static str) -> Response {
    let correlation_id = correlation_id();
    let mut response = (
        status,
        Json(DashboardProblem {
            r#type: "https://cigar.dev/problems/dashboard",
            title,
            status: status.as_u16(),
            code,
            correlation_id: &correlation_id,
        }),
    )
        .into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    secure_json(response)
}

fn correlation_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_millis())
        & ((1_u128 << 48) - 1);
    let mut random = [0_u8; 16];
    if getrandom::fill(&mut random).is_err() {
        random = [0_u8; 16];
    }
    let entropy = u128::from_be_bytes(random);
    let mut value = (timestamp << 80) | (entropy & ((1_u128 << 76) - 1));
    value = (value & !(0xf_u128 << 76)) | (0x7_u128 << 76);
    value = (value & !(0x3_u128 << 62)) | (0x2_u128 << 62);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) & 0xffff_ffff,
        (value >> 80) & 0xffff,
        (value >> 64) & 0xffff,
        (value >> 48) & 0xffff,
        value & 0xffff_ffff_ffff
    )
}

fn secure_json(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    secure_headers(response)
}

fn secure_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), geolocation=(), microphone=(), payment=(), usb=()"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::{DashboardApplication, SESSION_COOKIE, parse_page_query};
    use crate::{CursorError, DashboardConfig, RunRecord};
    use axum::body::{Body, to_bytes};
    use axum::http::header::{
        CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, ORIGIN, SET_COOKIE,
    };
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use tower::ServiceExt as _;

    const VALID: &str = include_str!("../../../tests/dashboard/fixtures/dashboard-valid.toml");
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn page_query_is_canonical_bounded_and_unique() -> Result<(), Box<dyn std::error::Error>> {
        let default = parse_page_query(None)?;
        assert_eq!(default.limit, 25);
        assert!(default.cursor.is_none());
        let explicit = parse_page_query(Some("cursor=abc_123&limit=10"))?;
        assert_eq!(explicit.limit, 10);
        assert_eq!(explicit.cursor.as_deref(), Some("abc_123"));
        for invalid in [
            "limit=0",
            "limit=01",
            "limit=101",
            "limit=1&limit=2",
            "cursor=a&cursor=b",
            "cursor=a%2Fb",
            "unknown=value",
        ] {
            assert!(matches!(
                parse_page_query(Some(invalid)),
                Err(CursorError::InvalidCursor)
            ));
        }
        Ok(())
    }

    fn application() -> Result<(DashboardApplication, tempfile::TempDir), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let runtime = directory.path().join("runtime");
        let assets = directory.path().join("assets");
        fs::create_dir(&runtime)?;
        fs::create_dir(&assets)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
        }
        let html = b"<!doctype html><title>CIGAR</title>";
        fs::write(assets.join("index.html"), html)?;
        let digest: [u8; 32] = Sha256::digest(html).into();
        let digest_hex = digest.iter().fold(
            String::with_capacity(digest.len() * 2),
            |mut output, byte| {
                use std::fmt::Write as _;
                if write!(output, "{byte:02x}").is_err() {
                    return String::new();
                }
                output
            },
        );
        fs::write(
            assets.join("asset-manifest.v1.json"),
            serde_json::to_vec(&json!({
                "schema_version": "cigar.dashboard-asset-manifest.v1",
                "files": [{
                    "path": "index.html",
                    "sha256": digest_hex,
                    "size": html.len(),
                    "media_type": "text/html; charset=utf-8"
                }]
            }))?,
        )?;
        let source = VALID
            .replace("/tmp/cigar-dashboard/runtime", &runtime.to_string_lossy())
            .replace("/tmp/cigar-dashboard/assets", &assets.to_string_lossy())
            .replace(
                "/tmp/cigar-dashboard/history.sqlite3",
                &directory.path().join("history.sqlite3").to_string_lossy(),
            );
        let config = DashboardConfig::from_toml(&source)?;
        Ok((DashboardApplication::initialize(&config)?, directory))
    }

    #[tokio::test]
    async fn static_shell_has_strict_security_headers() -> Result<(), Box<dyn std::error::Error>> {
        let (application, _directory) = application()?;
        let response = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, "127.0.0.1:7460")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert!(response.headers().contains_key(CONTENT_SECURITY_POLICY));
        Ok(())
    }

    #[tokio::test]
    async fn one_time_exchange_creates_authenticated_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let (application, _directory) = application()?;
        let secret = application.bootstrap_token().to_owned();
        let exchange = application
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/session:exchange")
                    .header(HOST, "127.0.0.1:7460")
                    .header(ORIGIN, "http://127.0.0.1:7460")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "bootstrap_secret": secret
                    }))?))?,
            )
            .await?;
        assert_eq!(exchange.status(), StatusCode::CREATED);
        let cookie = exchange
            .headers()
            .get(SET_COOKIE)
            .ok_or("set-cookie missing")?
            .to_str()?
            .split(';')
            .next()
            .ok_or("session cookie missing")?
            .to_owned();
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=")));
        let body = to_bytes(exchange.into_body(), 4096).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert!(payload.get("csrf_token").and_then(Value::as_str).is_some());

        let bootstrap = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/bootstrap")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(bootstrap.status(), StatusCode::OK);

        let profiles = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/run-profiles")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(profiles.status(), StatusCode::OK);
        let body = to_bytes(profiles.into_body(), 16_384).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload.get("control_enabled").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            payload
                .get("profiles")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let rotated = application
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/session:csrf")
                    .header(HOST, "127.0.0.1:7460")
                    .header(ORIGIN, "http://127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(rotated.status(), StatusCode::OK);
        let body = to_bytes(rotated.into_body(), 4096).await?;
        let rotated: Value = serde_json::from_slice(&body)?;
        let csrf = rotated
            .get("csrf_token")
            .and_then(Value::as_str)
            .ok_or("rotated csrf missing")?;

        let disabled_control = application
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/runs")
                    .header(HOST, "127.0.0.1:7460")
                    .header(ORIGIN, "http://127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .header(CONTENT_TYPE, "application/json")
                    .header("x-cigar-csrf", csrf)
                    .body(Body::from(r#"{"profile_id":"dashboard-contracts"}"#))?,
            )
            .await?;
        assert_eq!(disabled_control.status(), StatusCode::CONFLICT);

        let protocol = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/protocol")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(protocol.status(), StatusCode::OK);
        let body = to_bytes(protocol.into_body(), 64 * 1024).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload.get("schema_version").and_then(Value::as_str),
            Some("cigar.dashboard-protocol.v1")
        );
        assert_eq!(payload.get("service_count"), Some(&Value::from(7)));
        assert_eq!(payload.get("operation_count"), Some(&Value::from(45)));

        let runs = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/runs")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(runs.status(), StatusCode::OK);
        let body = to_bytes(runs.into_body(), 16_384).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload.get("schema_version").and_then(Value::as_str),
            Some("cigar.dashboard-runs.v1")
        );
        assert_eq!(
            payload.get("runs").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );

        for ordinal in 1..=3 {
            application.state.history.create_run(RunRecord::queued(
                "soak-smoke",
                DIGEST,
                DIGEST,
                &format!("revision-{ordinal}"),
            )?)?;
        }
        let first_page = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/runs?limit=2")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(first_page.status(), StatusCode::OK);
        let body = to_bytes(first_page.into_body(), 16_384).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload.get("runs").and_then(Value::as_array).map(Vec::len),
            Some(2)
        );
        let cursor = payload
            .get("next_cursor")
            .and_then(Value::as_str)
            .ok_or("next cursor missing")?;
        let second_page = application
            .router()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/runs?limit=2&cursor={cursor}"))
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(second_page.status(), StatusCode::OK);
        let body = to_bytes(second_page.into_body(), 16_384).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload.get("runs").and_then(Value::as_array).map(Vec::len),
            Some(1)
        );
        assert_eq!(payload.get("next_cursor"), Some(&Value::Null));

        let malformed_run = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/runs/not-a-run")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(malformed_run.status(), StatusCode::BAD_REQUEST);

        let malformed_page = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/runs?limit=0")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(malformed_page.status(), StatusCode::BAD_REQUEST);

        let evidence = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/evidence")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(evidence.status(), StatusCode::OK);
        let body = to_bytes(evidence.into_body(), 16_384).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload.get("schema_version").and_then(Value::as_str),
            Some("cigar.dashboard-evidence-index.v1")
        );
        assert_eq!(
            payload
                .get("evidence")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let status = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(status.status(), StatusCode::OK);
        let body = to_bytes(status.into_body(), 16_384).await?;
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(payload.get("aggregate"), Some(&Value::from("starting")));

        let events = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/events")
                    .header(HOST, "127.0.0.1:7460")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(events.status(), StatusCode::OK);
        assert!(
            events
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/event-stream"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn host_origin_and_unknown_api_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (application, _directory) = application()?;
        let bad_host = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, "attacker.invalid")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(bad_host.status(), StatusCode::BAD_REQUEST);

        let bad_origin = application
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/session:exchange")
                    .header(HOST, "127.0.0.1:7460")
                    .header(ORIGIN, "http://attacker.invalid")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

        let api = application
            .router()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/not-real")
                    .header(HOST, "127.0.0.1:7460")
                    .header("accept", "text/html")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(api.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            api.headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
        Ok(())
    }
}
