//! Bounded daemon HTTP/SSE transport and compatibility negotiation.

use crate::{
    CallOptions, CancellationToken, Client, ClientTransport, ErrorKind, SdkError, SdkFuture,
    TransportCall, TransportEventStream,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::generated::HttpMethod;
use cigar_api::{
    CapabilitiesResponse, EmptyRequest, EventEnvelope, MetricsResponse, ReadinessResponse,
    ResponseEnvelope, VersionResponse, decode_operation_payload, encode_operation_payload,
};
use cigar_protocol::{Problem, RetryClass};
use futures_util::StreamExt as _;
use reqwest::header::{
    AUTHORIZATION, CONTENT_TYPE, ETAG, HeaderMap, HeaderName, HeaderValue, IF_MATCH,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroize as _;

const HEADER_IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const HEADER_LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const HEADER_NEXT_PAGE_CURSOR: HeaderName = HeaderName::from_static("x-cigar-next-page-cursor");
const HEADER_OPERATION_ID: HeaderName = HeaderName::from_static("x-cigar-operation-id");
const HEADER_TIMEOUT_MS: HeaderName = HeaderName::from_static("x-cigar-timeout-ms");
const HEADER_UNCOMPRESSED_LENGTH: HeaderName =
    HeaderName::from_static("x-cigar-uncompressed-length");
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";
const SSE_CONTENT_TYPE: &str = "text/event-stream";
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";
const MAX_AUTHORIZATION_BYTES: usize = 8_192;
const MAX_SSE_FRAME_BYTES: usize = cigar_api::MAX_EVENT_PAYLOAD_BYTES * 2;

/// Redacted validated authorization header supplied by a credential provider.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationValue(String);

impl AuthorizationValue {
    /// Creates one bounded visible-ASCII authorization value.
    pub fn new(value: impl Into<String>) -> Result<Self, SdkError> {
        let mut value = value.into();
        if value.is_empty()
            || value.len() > MAX_AUTHORIZATION_BYTES
            || value.bytes().any(|byte| !matches!(byte, 0x20..=0x7e))
        {
            value.zeroize();
            return Err(configuration_error());
        }
        Ok(Self(value))
    }

    fn header_value(&self) -> Result<HeaderValue, SdkError> {
        HeaderValue::from_str(&self.0).map_err(|_failure| configuration_error())
    }
}

impl fmt::Debug for AuthorizationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationValue([REDACTED])")
    }
}

impl Drop for AuthorizationValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Object-safe dynamic credential source called for each daemon exchange.
pub trait AuthorizationProvider: Send + Sync {
    /// Returns a fresh authorization value, or `None` only for explicit cleartext loopback use.
    ///
    /// Remote HTTPS clients reject a missing provider during construction and reject a provider
    /// that later returns `None` before any request is sent.
    fn authorization<'a>(&'a self) -> SdkFuture<'a, Result<Option<AuthorizationValue>, SdkError>>;
}

/// Static redacted credential provider for fixed local or service tokens.
pub struct StaticAuthorization {
    value: AuthorizationValue,
}

impl StaticAuthorization {
    /// Wraps one already validated value.
    #[must_use]
    pub const fn new(value: AuthorizationValue) -> Self {
        Self { value }
    }

    /// Loads one exact authorization header from a descriptor-bound owner-only file.
    ///
    /// A single trailing LF or CRLF is removed. The remaining bytes must be the complete visible
    /// ASCII header value, for example `Bearer <token>`; the value and path are never included in
    /// diagnostics or `Debug` output.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let value = read_authorization_file(path.as_ref())?;
        Ok(Self { value })
    }
}

impl AuthorizationProvider for StaticAuthorization {
    fn authorization<'a>(&'a self) -> SdkFuture<'a, Result<Option<AuthorizationValue>, SdkError>> {
        Box::pin(async move { Ok(Some(self.value.clone())) })
    }
}

impl fmt::Debug for StaticAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticAuthorization([REDACTED])")
    }
}

fn read_authorization_file(path: &Path) -> Result<AuthorizationValue, SdkError> {
    if !path.is_absolute() {
        return Err(configuration_error());
    }
    let link = std::fs::symlink_metadata(path).map_err(|_failure| configuration_error())?;
    if link.file_type().is_symlink()
        || !link.is_file()
        || link.len() == 0
        || link.len() > MAX_AUTHORIZATION_BYTES as u64
    {
        return Err(configuration_error());
    }
    let mut file = open_bounded_read(path).map_err(|_failure| configuration_error())?;
    let opened = file.metadata().map_err(|_failure| configuration_error())?;
    if !opened.is_file()
        || !same_authorization_file(&link, &opened)
        || !safe_authorization_metadata(&opened)
    {
        return Err(configuration_error());
    }
    let capacity = usize::try_from(opened.len()).map_err(|_failure| configuration_error())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take((MAX_AUTHORIZATION_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_failure| configuration_error())?;
    let after_read = file.metadata().map_err(|_failure| configuration_error())?;
    let final_link = std::fs::symlink_metadata(path).map_err(|_failure| configuration_error())?;
    if final_link.file_type().is_symlink()
        || !same_authorization_file(&opened, &after_read)
        || !same_authorization_file(&after_read, &final_link)
        || !stable_authorization_file(&opened, &after_read)
        || u64::try_from(bytes.len()).ok() != Some(after_read.len())
    {
        bytes.zeroize();
        return Err(configuration_error());
    }
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len().saturating_sub(2));
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len().saturating_sub(1));
    }
    let result = String::from_utf8(bytes).map_err(|failure| {
        let mut invalid = failure.into_bytes();
        invalid.zeroize();
        configuration_error()
    })?;
    AuthorizationValue::new(result)
}

#[cfg(unix)]
fn same_authorization_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_authorization_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

#[cfg(unix)]
fn stable_authorization_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
}

#[cfg(not(unix))]
fn stable_authorization_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn safe_authorization_metadata(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

#[cfg(unix)]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    open_bounded_read_before_final(path, || Ok(()))
}

#[cfg(unix)]
fn open_bounded_read_before_final(
    path: &Path,
    before_final: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;

    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if names.is_empty() && !absolute => absolute = true,
            Component::Normal(name) => names.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(invalid_read_path()),
        }
    }
    if !absolute {
        return Err(invalid_read_path());
    }
    let (file_name, ancestors) = names.split_last().ok_or_else(invalid_read_path)?;
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)?;
    validate_read_ancestor(&directory.metadata()?)?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            *ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)?;
        validate_read_ancestor(&directory.metadata()?)?;
    }
    before_final()?;
    openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(unix)]
fn validate_read_ancestor(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if metadata.is_dir()
        && (owner == 0 || owner == rustix::process::geteuid().as_raw())
        && (!writable_by_others || protected_sticky_root)
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe file ancestor",
        ))
    }
}

#[cfg(unix)]
fn invalid_read_path() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid file path")
}

#[cfg(not(unix))]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// Required server API and protocol line accepted during connection negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityPolicy {
    api_version: String,
    protocol_min: String,
    protocol_max: String,
}

impl CompatibilityPolicy {
    /// Creates a bounded compatibility requirement.
    pub fn new(
        api_version: impl Into<String>,
        protocol_min: impl Into<String>,
        protocol_max: impl Into<String>,
    ) -> Result<Self, SdkError> {
        let policy = Self {
            api_version: api_version.into(),
            protocol_min: protocol_min.into(),
            protocol_max: protocol_max.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), SdkError> {
        let minimum = parse_protocol_selector(&self.protocol_min);
        let maximum = parse_protocol_selector(&self.protocol_max);
        let valid_range = minimum.zip(maximum).is_some_and(|(minimum, maximum)| {
            minimum.minor.is_some()
                && minimum.major == maximum.major
                && selector_at_or_before(minimum, maximum)
        });
        if self.api_version != "v1" || !valid_range {
            Err(configuration_error())
        } else {
            Ok(())
        }
    }
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        Self {
            api_version: "v1".to_owned(),
            protocol_min: cigar_protocol::PROTOCOL_MIN.to_owned(),
            protocol_max: cigar_protocol::PROTOCOL_MAX.to_owned(),
        }
    }
}

/// Server compatibility records retained after successful negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerCompatibility {
    /// Stable build and supported protocol range.
    pub version: VersionResponse,
    /// Bounded enabled capabilities and limits.
    pub capabilities: CapabilitiesResponse,
}

/// Validated daemon client builder.
pub struct RemoteClientBuilder {
    endpoint: reqwest::Url,
    authorization: Option<Arc<dyn AuthorizationProvider>>,
    compatibility: CompatibilityPolicy,
    allow_insecure_loopback: bool,
    connect_timeout: Duration,
}

impl RemoteClientBuilder {
    /// Parses a daemon origin. HTTPS is required unless loopback HTTP is explicitly enabled.
    pub fn new(endpoint: &str) -> Result<Self, SdkError> {
        let endpoint = reqwest::Url::parse(endpoint).map_err(|_failure| configuration_error())?;
        Ok(Self {
            endpoint,
            authorization: None,
            compatibility: CompatibilityPolicy::default(),
            allow_insecure_loopback: false,
            connect_timeout: Duration::from_secs(10),
        })
    }

    /// Uses a dynamic, extension-compatible credential provider.
    #[must_use]
    pub fn authorization_provider(mut self, authorization: Arc<dyn AuthorizationProvider>) -> Self {
        self.authorization = Some(authorization);
        self
    }

    /// Allows cleartext HTTP only for an explicit loopback endpoint.
    #[must_use]
    pub fn allow_insecure_loopback(mut self, allow: bool) -> Self {
        self.allow_insecure_loopback = allow;
        self
    }

    /// Replaces the required server compatibility line.
    #[must_use]
    pub fn compatibility_policy(mut self, compatibility: CompatibilityPolicy) -> Self {
        self.compatibility = compatibility;
        self
    }

    /// Sets a bounded TCP/TLS connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Result<Self, SdkError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(configuration_error());
        }
        self.connect_timeout = timeout;
        Ok(self)
    }

    /// Builds the transport, negotiates API/protocol compatibility, then returns the client.
    pub async fn connect(self) -> Result<(Client, ServerCompatibility), SdkError> {
        self.compatibility.validate()?;
        validate_endpoint(&self.endpoint, self.allow_insecure_loopback)?;
        let authorization_required = requires_authorization(&self.endpoint);
        if authorization_required && self.authorization.is_none() {
            return Err(configuration_error());
        }
        let _provider_result = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .user_agent(concat!("cigar-sdk-rust/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_failure| SdkError::transport())?;
        let transport = Arc::new(DaemonHttpTransport {
            endpoint: self.endpoint,
            http,
            authorization: self.authorization,
            authorization_required,
        });
        let client = Client::from_transport(transport);
        let compatibility = client.negotiate(&self.compatibility).await?;
        Ok((client, compatibility))
    }
}

impl fmt::Debug for RemoteClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteClientBuilder")
            .field("scheme", &self.endpoint.scheme())
            .field("has_authorization", &self.authorization.is_some())
            .field("compatibility", &self.compatibility)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl Client {
    /// Fetches and verifies the server API/protocol compatibility records.
    pub async fn negotiate(
        &self,
        policy: &CompatibilityPolicy,
    ) -> Result<ServerCompatibility, SdkError> {
        policy.validate()?;
        let version = self
            .get_version(EmptyRequest {}, CallOptions::read())
            .await?
            .value;
        let capabilities = self
            .get_capabilities(EmptyRequest {}, CallOptions::read())
            .await?
            .value;
        let required_minimum = parse_protocol_selector(&policy.protocol_min);
        let required_maximum = parse_protocol_selector(&policy.protocol_max);
        let server_minimum = parse_protocol_selector(&version.protocol_min);
        let server_maximum = parse_protocol_selector(&version.protocol_max);
        let selected = parse_protocol_selector(&capabilities.protocol_version);
        let compatible = capabilities.api_version == policy.api_version
            && required_minimum
                .zip(required_maximum)
                .zip(server_minimum.zip(server_maximum))
                .is_some_and(
                    |((required_minimum, required_maximum), (server_minimum, server_maximum))| {
                        ranges_overlap(
                            required_minimum,
                            required_maximum,
                            server_minimum,
                            server_maximum,
                        )
                    },
                )
            && selected
                .zip(required_minimum)
                .is_some_and(|(selected, required)| selected.major == required.major);
        if !compatible {
            return Err(SdkError::local(
                ErrorKind::IncompatibleServer,
                RetryClass::Never,
                "server API or protocol line is incompatible",
            ));
        }
        Ok(ServerCompatibility {
            version,
            capabilities,
        })
    }
}

struct DaemonHttpTransport {
    endpoint: reqwest::Url,
    http: reqwest::Client,
    authorization: Option<Arc<dyn AuthorizationProvider>>,
    authorization_required: bool,
}

impl ClientTransport for DaemonHttpTransport {
    fn unary<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<ResponseEnvelope, SdkError>> {
        Box::pin(async move {
            let request = self.request(&call, false).await?;
            let response = send_with_lifecycle(request, &call).await?;
            decode_unary_response(response, &call).await
        })
    }

    fn subscribe<'a>(
        &'a self,
        call: TransportCall,
    ) -> SdkFuture<'a, Result<TransportEventStream, SdkError>> {
        Box::pin(async move {
            let request = self.request(&call, true).await?;
            let response = send_with_lifecycle(request, &call).await?;
            if !response.status().is_success() {
                return Err(decode_problem_response(response, &call).await?);
            }
            let content_type = content_type(response.headers())?;
            if !content_type
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case(SSE_CONTENT_TYPE))
            {
                return Err(crate::client::protocol_error());
            }
            Ok(sse_stream(response, call))
        })
    }
}

impl DaemonHttpTransport {
    async fn request(
        &self,
        call: &TransportCall,
        stream: bool,
    ) -> Result<reqwest::RequestBuilder, SdkError> {
        let mut url = operation_url(&self.endpoint, call)?;
        if call.contract().http_method == HttpMethod::Get
            && ((!stream && call.envelope().page_cursor().is_some())
                || call.envelope().page_size().is_some())
        {
            let mut query = url.query_pairs_mut();
            if !stream && let Some(cursor) = call.envelope().page_cursor() {
                query.append_pair("page_cursor", cursor);
            }
            if let Some(size) = call.envelope().page_size() {
                query.append_pair("page_size", &size.to_string());
            }
        }
        let method = match call.contract().http_method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
        };
        let timeout = call
            .deadline()
            .checked_duration_since(Instant::now())
            .ok_or_else(crate::client::deadline_error)?;
        let timeout_ms =
            u64::try_from(timeout.as_millis().max(1)).map_err(|_failure| configuration_error())?;
        let mut request = self
            .http
            .request(method, url)
            .header(HEADER_OPERATION_ID, call.contract().operation_id)
            .header(HEADER_TIMEOUT_MS, timeout_ms.to_string());
        let authorization = match &self.authorization {
            Some(provider) => provider.authorization().await?,
            None => None,
        };
        if self.authorization_required && authorization.is_none() {
            return Err(configuration_error());
        }
        if let Some(value) = authorization {
            request = request.header(AUTHORIZATION, value.header_value()?);
        }
        if stream && let Some(cursor) = call.envelope().page_cursor() {
            request = request.header(HEADER_LAST_EVENT_ID, cursor);
        }
        if call.contract().http_method == HttpMethod::Post {
            let wire = HttpOperationRequest {
                operation_id: call.contract().operation_id,
                payload_cbor: URL_SAFE_NO_PAD.encode(call.envelope().payload_cbor()),
                dry_run: call.envelope().dry_run(),
                idempotency_key: call.envelope().idempotency_key(),
                expected_revision: call.envelope().expected_revision(),
                page_cursor: call.envelope().page_cursor(),
                page_size: call.envelope().page_size(),
                path_parameters: call
                    .envelope()
                    .path_parameters()
                    .iter()
                    .map(|parameter| HttpPathParameter {
                        name: parameter.name(),
                        value: parameter.value(),
                    })
                    .collect(),
            };
            let body = serde_json::to_vec(&wire).map_err(|_failure| configuration_error())?;
            if body.len() > cigar_api::MAX_HTTP_BODY_BYTES {
                return Err(configuration_error());
            }
            request = request
                .header(CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(HEADER_UNCOMPRESSED_LENGTH, body.len().to_string())
                .body(body);
            if let Some(key) = call.envelope().idempotency_key() {
                request = request.header(HEADER_IDEMPOTENCY_KEY, key);
            }
            if let Some(revision) = call.envelope().expected_revision() {
                request = request.header(IF_MATCH, revision);
            }
        }
        Ok(request)
    }
}

#[derive(Serialize)]
struct HttpOperationRequest<'a> {
    operation_id: &'a str,
    payload_cbor: String,
    dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_revision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_size: Option<u32>,
    path_parameters: Vec<HttpPathParameter<'a>>,
}

#[derive(Serialize)]
struct HttpPathParameter<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpOperationResponse {
    operation_id: String,
    payload_cbor: String,
    #[serde(default)]
    semantic_etag: Option<String>,
    #[serde(default)]
    next_page_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpOperationEvent {
    operation_id: String,
    event_id: String,
    payload_cbor: String,
}

async fn send_with_lifecycle(
    request: reqwest::RequestBuilder,
    call: &TransportCall,
) -> Result<reqwest::Response, SdkError> {
    if call.cancellation().is_cancelled() {
        return Err(crate::client::cancelled_error());
    }
    tokio::select! {
        result = request.send() => result.map_err(|_failure| SdkError::transport()),
        () = call.cancellation().cancelled() => Err(crate::client::cancelled_error()),
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
            Err(crate::client::deadline_error())
        }
    }
}

async fn decode_unary_response(
    response: reqwest::Response,
    call: &TransportCall,
) -> Result<ResponseEnvelope, SdkError> {
    let status = response.status();
    let headers = response.headers().clone();
    let media_type = content_type(&headers)?.to_owned();
    if media_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(PROBLEM_CONTENT_TYPE))
    {
        return Err(decode_problem_response(response, call).await?);
    }
    let bytes = collect_bounded(response, cigar_api::MAX_HTTP_BODY_BYTES, call).await?;
    if status.is_success()
        && call.contract().operation_id == "getMetrics"
        && media_type.eq_ignore_ascii_case(OPENMETRICS_CONTENT_TYPE)
    {
        let text = String::from_utf8(bytes).map_err(|_failure| crate::client::protocol_error())?;
        let payload = encode_operation_payload(
            &MetricsResponse { media_type, text },
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
        )
        .map_err(|_failure| crate::client::protocol_error())?;
        return ResponseEnvelope::new("getMetrics", payload, None, None)
            .map_err(|_failure| crate::client::protocol_error());
    }
    let typed_unhealthy_readiness = call.contract().operation_id == "getReadiness"
        && status == reqwest::StatusCode::SERVICE_UNAVAILABLE;
    if (!status.is_success() && !typed_unhealthy_readiness) || !is_json_content_type(&media_type) {
        return Err(crate::client::protocol_error());
    }
    strict_json(&bytes)?;
    let wire: HttpOperationResponse =
        serde_json::from_slice(&bytes).map_err(|_failure| crate::client::protocol_error())?;
    if wire.operation_id != call.contract().operation_id {
        return Err(crate::client::protocol_error());
    }
    let payload = decode_base64url(&wire.payload_cbor, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)?;
    if call.contract().operation_id == "getReadiness" {
        let readiness = decode_operation_payload::<ReadinessResponse>(
            &payload,
            cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
        )
        .map_err(|_failure| crate::client::protocol_error())?;
        let status_matches_payload = match status {
            reqwest::StatusCode::OK => readiness.ready,
            reqwest::StatusCode::SERVICE_UNAVAILABLE => !readiness.ready,
            _ => false,
        };
        if !status_matches_payload {
            return Err(crate::client::protocol_error());
        }
    }
    let etag = reconcile_header(&headers, &ETAG, wire.semantic_etag)?;
    let cursor = reconcile_header(&headers, &HEADER_NEXT_PAGE_CURSOR, wire.next_page_cursor)?;
    ResponseEnvelope::new(wire.operation_id, payload, etag, cursor)
        .map_err(|_failure| crate::client::protocol_error())
}

async fn decode_problem_response(
    response: reqwest::Response,
    call: &TransportCall,
) -> Result<SdkError, SdkError> {
    let status = response.status().as_u16();
    let media_type = content_type(response.headers())?;
    if !media_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(PROBLEM_CONTENT_TYPE))
    {
        return Err(crate::client::protocol_error());
    }
    let bytes = collect_bounded(response, 64 * 1024, call).await?;
    strict_json(&bytes)?;
    let problem: Problem =
        serde_json::from_slice(&bytes).map_err(|_failure| crate::client::protocol_error())?;
    if problem.http_status != status {
        return Err(crate::client::protocol_error());
    }
    SdkError::from_problem(problem)
}

async fn collect_bounded(
    response: reqwest::Response,
    maximum: usize,
    call: &TransportCall,
) -> Result<Vec<u8>, SdkError> {
    if response.content_length().is_some_and(|length| {
        usize::try_from(length)
            .ok()
            .is_none_or(|value| value > maximum)
    }) {
        return Err(crate::client::protocol_error());
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    loop {
        let next = tokio::select! {
            value = stream.next() => value,
            () = call.cancellation().cancelled() => return Err(crate::client::cancelled_error()),
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
                return Err(crate::client::deadline_error());
            }
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|_failure| SdkError::transport())?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(crate::client::protocol_error());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn sse_stream(response: reqwest::Response, call: TransportCall) -> TransportEventStream {
    let cancellation = call.cancellation().clone();
    let producer_cancellation = cancellation.clone();
    let (sender, receiver) = mpsc::channel(32);
    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        let mut buffered = Vec::new();
        loop {
            let next = tokio::select! {
                value = stream.next() => value,
                () = producer_cancellation.cancelled() => {
                    let _ignored = sender.send(Err(crate::client::cancelled_error())).await;
                    break;
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(call.deadline())) => {
                    let _ignored = sender.send(Err(crate::client::deadline_error())).await;
                    break;
                }
            };
            let Some(chunk) = next else {
                if !buffered.is_empty() {
                    let _ignored = sender.send(Err(crate::client::protocol_error())).await;
                }
                break;
            };
            let Ok(chunk) = chunk else {
                let _ignored = sender.send(Err(SdkError::transport())).await;
                break;
            };
            if buffered
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_SSE_FRAME_BYTES)
            {
                let _ignored = sender.send(Err(crate::client::protocol_error())).await;
                break;
            }
            buffered.extend_from_slice(&chunk);
            while let Some((frame_end, delimiter_length)) = find_sse_frame(&buffered) {
                let Some(frame) = buffered.get(..frame_end).map(<[u8]>::to_vec) else {
                    let _ignored = sender.send(Err(crate::client::protocol_error())).await;
                    return;
                };
                let Some(drain_end) = frame_end
                    .checked_add(delimiter_length)
                    .filter(|end| *end <= buffered.len())
                else {
                    let _ignored = sender.send(Err(crate::client::protocol_error())).await;
                    return;
                };
                buffered.drain(..drain_end);
                let item = decode_sse_frame(&frame, call.contract().operation_id);
                let terminal = item.is_err();
                if sender.send(item).await.is_err() || terminal {
                    return;
                }
            }
        }
    });
    Box::pin(RemoteEventStream {
        receiver,
        cancellation,
    })
}

struct RemoteEventStream {
    receiver: mpsc::Receiver<Result<EventEnvelope, SdkError>>,
    cancellation: CancellationToken,
}

impl futures_core::Stream for RemoteEventStream {
    type Item = Result<EventEnvelope, SdkError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Drop for RemoteEventStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn decode_sse_frame(frame: &[u8], operation_id: &str) -> Result<EventEnvelope, SdkError> {
    let text = std::str::from_utf8(frame).map_err(|_failure| crate::client::protocol_error())?;
    let mut event_kind = None;
    let mut event_id = None;
    let mut data = None;
    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        let target = match name {
            "event" => &mut event_kind,
            "id" => &mut event_id,
            "data" => &mut data,
            _ => return Err(crate::client::protocol_error()),
        };
        if target.replace(value).is_some() {
            return Err(crate::client::protocol_error());
        }
    }
    let data = data.ok_or_else(crate::client::protocol_error)?;
    strict_json(data.as_bytes())?;
    if event_kind == Some("problem") {
        let problem: Problem =
            serde_json::from_str(data).map_err(|_failure| crate::client::protocol_error())?;
        return Err(SdkError::from_problem(problem)?);
    }
    if event_kind.is_some() {
        return Err(crate::client::protocol_error());
    }
    let wire: HttpOperationEvent =
        serde_json::from_str(data).map_err(|_failure| crate::client::protocol_error())?;
    if wire.operation_id != operation_id || event_id != Some(wire.event_id.as_str()) {
        return Err(crate::client::protocol_error());
    }
    let payload = decode_base64url(&wire.payload_cbor, cigar_api::MAX_EVENT_PAYLOAD_BYTES)?;
    EventEnvelope::new(wire.operation_id, wire.event_id, payload)
        .map_err(|_failure| crate::client::protocol_error())
}

fn operation_url(endpoint: &reqwest::Url, call: &TransportCall) -> Result<reqwest::Url, SdkError> {
    let mut path = call.contract().http_path.to_owned();
    for parameter in call.envelope().path_parameters() {
        path = path.replace(&format!("{{{}}}", parameter.name()), parameter.value());
    }
    if path.contains('{') || path.contains('}') {
        return Err(configuration_error());
    }
    endpoint
        .join(path.trim_start_matches('/'))
        .map_err(|_failure| configuration_error())
}

fn validate_endpoint(endpoint: &reqwest::Url, allow_loopback: bool) -> Result<(), SdkError> {
    let root_path = endpoint.path().is_empty() || endpoint.path() == "/";
    let no_extras = endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
        && root_path;
    let secure = endpoint.scheme() == "https" && endpoint.host_str().is_some();
    let loopback_http = endpoint.scheme() == "http"
        && allow_loopback
        && endpoint.host_str().is_some_and(is_loopback_host);
    if no_extras && (secure || loopback_http) {
        Ok(())
    } else {
        Err(configuration_error())
    }
}

fn requires_authorization(endpoint: &reqwest::Url) -> bool {
    endpoint.scheme() == "https"
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn reconcile_header(
    headers: &HeaderMap,
    name: &HeaderName,
    body: Option<String>,
) -> Result<Option<String>, SdkError> {
    let header = headers
        .get(name)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_failure| crate::client::protocol_error())?;
    if let (Some(header), Some(body)) = (&header, &body)
        && header != body
    {
        return Err(crate::client::protocol_error());
    }
    Ok(header.or(body))
}

fn decode_base64url(encoded: &str, maximum: usize) -> Result<Vec<u8>, SdkError> {
    if encoded.len()
        > maximum
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(4)
    {
        return Err(crate::client::protocol_error());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_failure| crate::client::protocol_error())?;
    if bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(crate::client::protocol_error());
    }
    Ok(bytes)
}

fn strict_json(bytes: &[u8]) -> Result<(), SdkError> {
    cigar_canon::parse_strict_json(bytes)
        .map(|_node| ())
        .map_err(|_failure| crate::client::protocol_error())
}

fn content_type(headers: &HeaderMap) -> Result<&str, SdkError> {
    headers
        .get(CONTENT_TYPE)
        .ok_or_else(crate::client::protocol_error)?
        .to_str()
        .map_err(|_failure| crate::client::protocol_error())
}

fn is_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    parts
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        && parts.all(|parameter| parameter.trim().eq_ignore_ascii_case("charset=utf-8"))
}

fn find_sse_frame(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| (position, 2))
        .or_else(|| {
            bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| (position, 4))
        })
}

#[derive(Clone, Copy)]
struct ProtocolSelector {
    major: u64,
    minor: Option<u64>,
}

fn parse_protocol_selector(selector: &str) -> Option<ProtocolSelector> {
    let (major, remainder) = selector.split_once('.')?;
    if remainder.is_empty() || remainder.contains('.') {
        return None;
    }
    let major = major.parse().ok()?;
    let minor = if remainder == "x" {
        None
    } else {
        Some(remainder.parse().ok()?)
    };
    Some(ProtocolSelector { major, minor })
}

fn selector_at_or_before(left: ProtocolSelector, right: ProtocolSelector) -> bool {
    left.major < right.major
        || left.major == right.major
            && match (left.minor, right.minor) {
                (_, None) => true,
                (Some(left), Some(right)) => left <= right,
                (None, Some(_right)) => false,
            }
}

fn ranges_overlap(
    first_minimum: ProtocolSelector,
    first_maximum: ProtocolSelector,
    second_minimum: ProtocolSelector,
    second_maximum: ProtocolSelector,
) -> bool {
    first_minimum.major == first_maximum.major
        && second_minimum.major == second_maximum.major
        && first_minimum.major == second_minimum.major
        && first_minimum.minor.is_some()
        && second_minimum.minor.is_some()
        && selector_at_or_before(first_minimum, second_maximum)
        && selector_at_or_before(second_minimum, first_maximum)
}

const fn configuration_error() -> SdkError {
    SdkError::local(
        ErrorKind::InvalidConfiguration,
        RetryClass::Never,
        "remote client configuration is invalid",
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::open_bounded_read_before_final;
    use super::{
        parse_protocol_selector, ranges_overlap, requires_authorization, validate_endpoint,
    };

    #[test]
    fn remote_endpoint_authority_is_one_closed_https_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = reqwest::Url::parse("https://service.example:8443/")?;
        assert!(validate_endpoint(&valid, false).is_ok());
        assert!(requires_authorization(&valid));

        let loopback = reqwest::Url::parse("http://127.0.0.1:4317/")?;
        assert!(validate_endpoint(&loopback, true).is_ok());
        assert!(validate_endpoint(&loopback, false).is_err());
        assert!(!requires_authorization(&loopback));

        for value in [
            "http://service.example/",
            "https://user@service.example/",
            "https://user:password@service.example/",
            "https://service.example/v1",
            "https://service.example/?tenant=other",
            "https://service.example/#fragment",
            "file:///private/socket",
        ] {
            let endpoint = reqwest::Url::parse(value)?;
            assert!(
                validate_endpoint(&endpoint, true).is_err(),
                "endpoint {value:?} must fail closed"
            );
        }
        Ok(())
    }

    #[test]
    fn protocol_ranges_require_a_real_overlap() -> Result<(), Box<dyn std::error::Error>> {
        let one_zero = parse_protocol_selector("1.0").ok_or("missing 1.0")?;
        let one_one = parse_protocol_selector("1.1").ok_or("missing 1.1")?;
        let one_two = parse_protocol_selector("1.2").ok_or("missing 1.2")?;
        let one_x = parse_protocol_selector("1.x").ok_or("missing 1.x")?;
        let two_zero = parse_protocol_selector("2.0").ok_or("missing 2.0")?;
        let two_x = parse_protocol_selector("2.x").ok_or("missing 2.x")?;
        assert!(ranges_overlap(one_zero, one_x, one_two, one_x));
        assert!(!ranges_overlap(one_zero, one_one, one_two, one_x));
        assert!(!ranges_overlap(one_zero, one_x, two_zero, two_x));
        assert!(parse_protocol_selector("1.2.3").is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn authorization_reads_reject_symlinked_ancestors_and_pin_open_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read as _;
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let trusted = root.join("trusted");
        let replacement = root.join("replacement");
        std::fs::create_dir(&trusted)?;
        std::fs::create_dir(&replacement)?;
        std::fs::write(trusted.join("value"), b"trusted")?;
        std::fs::write(replacement.join("value"), b"substituted")?;

        let alias = root.join("alias");
        symlink(&trusted, &alias)?;
        assert!(open_bounded_read_before_final(&alias.join("value"), || Ok(())).is_err());

        let moved = root.join("moved");
        let requested = trusted.join("value");
        let mut opened = open_bounded_read_before_final(&requested, || {
            std::fs::rename(&trusted, &moved)?;
            std::fs::rename(&replacement, &trusted)?;
            Ok(())
        })?;
        let mut value = String::new();
        opened.read_to_string(&mut value)?;
        assert_eq!(value, "trusted");
        assert_eq!(std::fs::read_to_string(&requested)?, "substituted");
        Ok(())
    }
}
