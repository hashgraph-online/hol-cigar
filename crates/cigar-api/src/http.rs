//! Exact Axum HTTP/JSON and resumable server-sent-event binding.

use crate::generated::{HttpMethod, OPERATIONS, OperationContract, StreamKind};
use crate::service::{
    ContextInput, EnvelopeError, EventEnvelope, FacadeEventStream, MAX_OPERATION_PAYLOAD_BYTES,
    PathParameter, RequestEnvelope, ResponseEnvelope, ServiceKernel, TransportMetricEvent,
    TransportMetricsObserver, VerifiedClientIdentity,
};
use crate::{ApiError, CancellationToken, TraceId};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_canon::{CanonicalNode, from_deterministic_cbor};
use cigar_protocol::ErrorCode;
use flate2::read::GzDecoder;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::poll_fn;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;

/// Maximum encoded HTTP/JSON body accepted before base64 payload decoding.
pub const MAX_HTTP_BODY_BYTES: usize = (MAX_OPERATION_PAYLOAD_BYTES * 4 / 3) + (64 * 1024);
/// Maximum compressed HTTP entity size accepted before gzip expansion.
pub const MAX_HTTP_COMPRESSED_BODY_BYTES: usize = MAX_HTTP_BODY_BYTES;

const HEADER_OPERATION_ID: HeaderName = HeaderName::from_static("x-cigar-operation-id");
const HEADER_TIMEOUT_MS: HeaderName = HeaderName::from_static("x-cigar-timeout-ms");
const HEADER_TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
const HEADER_UNCOMPRESSED_LENGTH: HeaderName =
    HeaderName::from_static("x-cigar-uncompressed-length");
const HEADER_IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const HEADER_LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const HEADER_NEXT_PAGE_CURSOR: HeaderName = HeaderName::from_static("x-cigar-next-page-cursor");
const HEADER_TRACE_ID: HeaderName = HeaderName::from_static("x-cigar-trace-id");
const HEADER_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Returns every registered HTTP method, path template, and operation identity.
#[must_use]
pub fn registered_http_routes() -> Vec<(HttpMethod, &'static str, &'static str)> {
    OPERATIONS
        .iter()
        .map(|contract| {
            (
                contract.http_method,
                contract.http_path,
                contract.operation_id,
            )
        })
        .collect()
}

/// Matches only a frozen v1 method and path, rejecting aliases and encoded path parameters.
#[must_use]
pub fn match_http_operation(method: HttpMethod, path: &str) -> Option<&'static OperationContract> {
    OPERATIONS.iter().find(|contract| {
        contract.http_method == method && path_matches_template(contract.http_path, path)
    })
}

fn path_matches_template(template: &str, path: &str) -> bool {
    extract_path_parameters(template, path).is_ok()
}

fn extract_path_parameters(
    template: &str,
    path: &str,
) -> Result<Vec<PathParameter>, EnvelopeError> {
    if template.ends_with('/') != path.ends_with('/') {
        return Err(EnvelopeError::InvalidArgument);
    }
    let mut template_segments = template.split('/');
    let mut path_segments = path.split('/');
    let mut parameters = Vec::new();
    loop {
        match (template_segments.next(), path_segments.next()) {
            (Some(template_segment), Some(path_segment)) => {
                if let Some(parameter) = extract_segment_parameter(template_segment, path_segment)?
                {
                    parameters.push(parameter);
                }
            }
            (None, None) => {
                parameters.sort_unstable_by(|left, right| left.name().cmp(right.name()));
                if !parameters.windows(2).all(|window| {
                    matches!((window.first(), window.get(1)), (Some(left), Some(right)) if left.name() < right.name())
                }) {
                    return Err(EnvelopeError::InvalidArgument);
                }
                return Ok(parameters);
            }
            _ => return Err(EnvelopeError::InvalidArgument),
        }
    }
}

fn extract_segment_parameter(
    template: &str,
    value: &str,
) -> Result<Option<PathParameter>, EnvelopeError> {
    let Some(open) = template.find('{') else {
        return if template == value {
            Ok(None)
        } else {
            Err(EnvelopeError::InvalidArgument)
        };
    };
    let Some(close) = template.find('}') else {
        return Err(EnvelopeError::InvalidArgument);
    };
    if close <= open + 1 || template.get(close + 1..).is_none() {
        return Err(EnvelopeError::InvalidArgument);
    }
    let Some(prefix) = template.get(..open) else {
        return Err(EnvelopeError::InvalidArgument);
    };
    let Some(suffix) = template.get(close + 1..) else {
        return Err(EnvelopeError::InvalidArgument);
    };
    let Some(parameter) = value
        .strip_prefix(prefix)
        .and_then(|remaining| remaining.strip_suffix(suffix))
    else {
        return Err(EnvelopeError::InvalidArgument);
    };
    let name = template
        .get(open + 1..close)
        .ok_or(EnvelopeError::InvalidArgument)?;
    PathParameter::new(name, parameter).map(Some)
}

/// Builds only the exact generated routes for HTTP/gRPC server multiplexing.
pub fn http_routes(kernel: ServiceKernel) -> Router {
    let state = Arc::new(HttpState { kernel });
    generated_routes().with_state(state)
}

/// Builds the exact generated Axum API plus content-safe route and method fallbacks.
pub fn http_router(kernel: ServiceKernel) -> Router {
    let state = Arc::new(HttpState { kernel });
    generated_routes()
        .fallback(unknown_route)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
}

fn generated_routes() -> Router<Arc<HttpState>> {
    let mut router = Router::new();
    let mut registered = BTreeSet::new();
    for contract in OPERATIONS {
        let path = axum_route_pattern(contract.http_path);
        let method_key = matches!(contract.http_method, HttpMethod::Post);
        if !registered.insert((method_key, path.clone())) {
            continue;
        }
        router = match contract.http_method {
            HttpMethod::Get => router.route(&path, get(dispatch_http).head(method_not_allowed)),
            HttpMethod::Post => router.route(&path, post(dispatch_http)),
        };
    }
    router
}

fn axum_route_pattern(contract_path: &str) -> String {
    contract_path
        .split('/')
        .enumerate()
        .map(|(ordinal, segment)| {
            if segment.contains('{') {
                format!("{{parameter_{ordinal}}}")
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

struct HttpState {
    kernel: ServiceKernel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpOperationRequest {
    operation_id: String,
    payload_cbor: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    idempotency_key: Option<String>,
    #[serde(default)]
    expected_revision: Option<String>,
    #[serde(default)]
    page_cursor: Option<String>,
    #[serde(default)]
    page_size: Option<u32>,
    path_parameters: Vec<HttpPathParameter>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpPathParameter {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct HttpOperationResponse<'a> {
    operation_id: &'a str,
    payload_cbor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_etag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_page_cursor: Option<&'a str>,
}

#[derive(Serialize)]
struct HttpOperationEvent<'a> {
    operation_id: &'a str,
    event_id: &'a str,
    payload_cbor: String,
}

async fn dispatch_http(
    State(state): State<Arc<HttpState>>,
    OriginalUri(original_uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    let Some(method) = generated_method(request.method()) else {
        return problem_response(state.kernel.public_error(ErrorCode::InvalidArgument));
    };
    let Some(contract) = match_http_operation(method, original_uri.path()) else {
        return problem_response(state.kernel.public_error(ErrorCode::InvalidArgument));
    };

    match prepare_http_request(&state.kernel, contract, request).await {
        Ok(prepared) => execute_http(&state.kernel, contract, prepared).await,
        Err(error) => problem_response(error),
    }
}

struct PreparedHttpRequest {
    context_input: ContextInput,
    request: RequestEnvelope,
}

async fn prepare_http_request(
    kernel: &ServiceKernel,
    contract: &'static OperationContract,
    request: Request<Body>,
) -> Result<PreparedHttpRequest, ApiError> {
    let (parts, body) = request.into_parts();
    let verified_client_identity = parts.extensions.get::<VerifiedClientIdentity>().cloned();
    let path_parameters = extract_path_parameters(contract.http_path, parts.uri.path())
        .map_err(|error| kernel.public_error(error.error_code()))?;
    validate_unique_security_headers(&parts.headers)
        .map_err(|error| kernel.public_error(error.error_code()))?;
    let operation_header = unique_header(&parts.headers, &HEADER_OPERATION_ID)
        .map_err(|error| kernel.public_error(error.error_code()))?;
    if operation_header.is_some_and(|operation| operation != contract.operation_id) {
        return Err(kernel.public_error(ErrorCode::InvalidArgument));
    }

    let authorization = unique_header(&parts.headers, &AUTHORIZATION)
        .map_err(|error| kernel.public_error(error.error_code()))?
        .map(str::to_owned);
    let trace_id = unique_header(&parts.headers, &HEADER_TRACEPARENT)
        .map_err(|error| kernel.public_error(error.error_code()))?
        .map(parse_traceparent)
        .transpose()
        .map_err(|error| kernel.public_error(error.error_code()))?;
    let timeout = parse_http_timeout(&parts.headers, kernel)
        .map_err(|error| kernel.public_error(error.error_code()))?;
    let body_timeout = timeout.min(kernel.config().default_timeout());
    let cancellation = CancellationToken::new();
    let body_cancellation = cancellation.clone();
    let context_input = ContextInput::new(
        contract,
        authorization,
        trace_id,
        timeout,
        cancellation,
        verified_client_identity,
    )
    .map_err(|error| kernel.public_error(error.error_code()))?;

    let idempotency_header = unique_header(&parts.headers, &HEADER_IDEMPOTENCY_KEY)
        .map_err(|error| kernel.public_error(error.error_code()))?
        .map(str::to_owned);
    let revision_header = unique_header(&parts.headers, &IF_MATCH)
        .map_err(|error| kernel.public_error(error.error_code()))?
        .map(str::to_owned);

    let request = match contract.http_method {
        HttpMethod::Post => {
            validate_http_body_metadata(&parts.headers)
                .map_err(|error| kernel.public_error(error.error_code()))?;
            let bytes =
                tokio::time::timeout(body_timeout, to_bytes(body, MAX_HTTP_COMPRESSED_BODY_BYTES))
                    .await
                    .map_err(|_| {
                        body_cancellation.cancel();
                        kernel.public_error(ErrorCode::DeadlineExceeded)
                    })?
                    .map_err(|_| kernel.public_error(ErrorCode::LimitExceeded))?;
            let bytes = decode_http_body(&parts.headers, &bytes, kernel.config())
                .map_err(|error| kernel.public_error(error.error_code()))?;
            cigar_canon::parse_strict_json(&bytes)
                .map_err(|_| kernel.public_error(ErrorCode::InvalidArgument))?;
            let wire: HttpOperationRequest = serde_json::from_slice(&bytes)
                .map_err(|_| kernel.public_error(ErrorCode::InvalidArgument))?;
            if wire.operation_id != contract.operation_id {
                return Err(kernel.public_error(ErrorCode::InvalidArgument));
            }
            let payload_cbor = URL_SAFE_NO_PAD
                .decode(wire.payload_cbor.as_bytes())
                .map_err(|_| kernel.public_error(ErrorCode::InvalidArgument))?;
            let idempotency_key =
                reconcile_metadata(idempotency_header, wire.idempotency_key, contract.mutation)
                    .map_err(|error| kernel.public_error(error.error_code()))?;
            let expected_revision = reconcile_metadata(
                revision_header,
                wire.expected_revision,
                matches!(
                    contract.revision_requirement,
                    crate::generated::RevisionRequirement::Required
                ),
            )
            .map_err(|error| kernel.public_error(error.error_code()))?;
            let wire_path_parameters = wire
                .path_parameters
                .into_iter()
                .map(|parameter| PathParameter::new(parameter.name, parameter.value))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| kernel.public_error(error.error_code()))?;
            if wire_path_parameters != path_parameters {
                return Err(kernel.public_error(ErrorCode::InvalidArgument));
            }
            RequestEnvelope::new_with_dry_run(
                wire.operation_id,
                payload_cbor,
                wire.dry_run,
                idempotency_key,
                expected_revision,
                wire.page_cursor,
                wire.page_size,
                wire_path_parameters,
            )
            .map_err(|error| kernel.public_error(error.error_code()))?
        }
        HttpMethod::Get => {
            if idempotency_header.is_some() || revision_header.is_some() {
                return Err(kernel.public_error(ErrorCode::InvalidArgument));
            }
            let (mut page_cursor, page_size) = parse_page_query(&parts.uri)
                .map_err(|error| kernel.public_error(error.error_code()))?;
            let last_event_id = unique_header(&parts.headers, &HEADER_LAST_EVENT_ID)
                .map_err(|error| kernel.public_error(error.error_code()))?
                .map(str::to_owned);
            if contract.stream_kind == StreamKind::ServerStream {
                if let (Some(query_cursor), Some(event_id)) = (&page_cursor, &last_event_id)
                    && query_cursor != event_id
                {
                    return Err(kernel.public_error(ErrorCode::InvalidArgument));
                }
                if last_event_id.is_some() {
                    page_cursor = last_event_id;
                }
            } else if last_event_id.is_some() {
                return Err(kernel.public_error(ErrorCode::InvalidArgument));
            }
            RequestEnvelope::new(
                contract.operation_id,
                Vec::new(),
                None,
                None,
                page_cursor,
                page_size,
                path_parameters,
            )
            .map_err(|error| kernel.public_error(error.error_code()))?
        }
    };

    Ok(PreparedHttpRequest {
        context_input,
        request,
    })
}

async fn execute_http(
    kernel: &ServiceKernel,
    contract: &'static OperationContract,
    prepared: PreparedHttpRequest,
) -> Response {
    let context = match kernel.resolve_context(prepared.context_input).await {
        Ok(context) => context,
        Err(error) => return problem_response(error),
    };
    let trace_id = context.trace_id().as_str().to_owned();
    match contract.stream_kind {
        StreamKind::Unary => match kernel.call(contract, context, prepared.request).await {
            Ok(response) => unary_response(&response, &trace_id),
            Err(error) => problem_response(error),
        },
        StreamKind::ServerStream => {
            let cancellation = context.cancellation().clone();
            match kernel.subscribe(contract, context, prepared.request).await {
                Ok(stream) => sse_response(
                    stream,
                    cancellation,
                    kernel.config().stream_buffer_capacity(),
                    trace_id,
                    kernel.metrics_observer(),
                ),
                Err(error) => problem_response(error),
            }
        }
    }
}

fn unary_response(response: &ResponseEnvelope, trace_id: &str) -> Response {
    if let Some(metrics) = openmetrics_response(response, trace_id) {
        return metrics;
    }
    let wire = HttpOperationResponse {
        operation_id: response.operation_id().as_str(),
        payload_cbor: URL_SAFE_NO_PAD.encode(response.payload_cbor()),
        semantic_etag: response.semantic_etag(),
        next_page_cursor: response.next_page_cursor(),
    };
    let Ok(bytes) = serde_json::to_vec(&wire) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    };
    let status = readiness_http_status(response).unwrap_or(StatusCode::OK);
    let mut output = (status, [(CONTENT_TYPE, "application/json")], bytes).into_response();
    if let Some(etag) = response.semantic_etag().and_then(header_value) {
        output.headers_mut().insert(ETAG, etag);
    }
    if let Some(cursor) = response.next_page_cursor().and_then(header_value) {
        output.headers_mut().insert(HEADER_NEXT_PAGE_CURSOR, cursor);
    }
    if let Some(trace) = header_value(trace_id) {
        output.headers_mut().insert(HEADER_TRACE_ID, trace);
    }
    output
}

fn readiness_http_status(response: &ResponseEnvelope) -> Option<StatusCode> {
    if response.operation_id().as_str() != "getReadiness" {
        return None;
    }
    let CanonicalNode::Map(payload) = from_deterministic_cbor(response.payload_cbor()).ok()? else {
        return Some(StatusCode::INTERNAL_SERVER_ERROR);
    };
    match payload.get("ready") {
        Some(CanonicalNode::Boolean(true)) => Some(StatusCode::OK),
        Some(CanonicalNode::Boolean(false)) => Some(StatusCode::SERVICE_UNAVAILABLE),
        _ => Some(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn openmetrics_response(response: &ResponseEnvelope, trace_id: &str) -> Option<Response> {
    if response.operation_id().as_str() != "getMetrics"
        || response.semantic_etag().is_some()
        || response.next_page_cursor().is_some()
    {
        return None;
    }
    let CanonicalNode::Map(payload) = from_deterministic_cbor(response.payload_cbor()).ok()? else {
        return None;
    };
    let Some(CanonicalNode::Text(media_type)) = payload.get("media_type") else {
        return None;
    };
    let Some(CanonicalNode::Text(text)) = payload.get("text") else {
        return None;
    };
    if payload.len() != 2 || media_type != OPENMETRICS_CONTENT_TYPE {
        return None;
    }
    let mut output = ([(CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)], text.clone()).into_response();
    if let Some(trace) = header_value(trace_id) {
        output.headers_mut().insert(HEADER_TRACE_ID, trace);
    }
    Some(output)
}

fn sse_response(
    stream: FacadeEventStream,
    cancellation: CancellationToken,
    capacity: usize,
    trace_id: String,
    metrics: Option<Arc<dyn TransportMetricsObserver>>,
) -> Response {
    let receiver = bounded_receiver(stream, cancellation, capacity, metrics);
    let stream = HttpEventStream { receiver };
    let mut response = Sse::new(stream).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    response
        .headers_mut()
        .insert(HEADER_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    if let Some(trace) = header_value(&trace_id) {
        response.headers_mut().insert(HEADER_TRACE_ID, trace);
    }
    response
}

struct ReceiverEventStream {
    receiver: mpsc::Receiver<Result<EventEnvelope, ApiError>>,
    cancellation: CancellationToken,
    metrics: Option<Arc<dyn TransportMetricsObserver>>,
}

impl Stream for ReceiverEventStream {
    type Item = Result<EventEnvelope, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Drop for ReceiverEventStream {
    fn drop(&mut self) {
        if !self.cancellation.is_cancelled()
            && let Some(metrics) = &self.metrics
        {
            metrics.record_transport_metric(TransportMetricEvent::StreamCancelled);
        }
        self.cancellation.cancel();
    }
}

fn bounded_receiver(
    mut source: FacadeEventStream,
    cancellation: CancellationToken,
    capacity: usize,
    metrics: Option<Arc<dyn TransportMetricsObserver>>,
) -> ReceiverEventStream {
    let (sender, receiver) = mpsc::channel(capacity);
    let producer_cancellation = cancellation.clone();
    let producer_metrics = metrics.clone();
    tokio::spawn(async move {
        loop {
            let item = poll_fn(|context| source.as_mut().poll_next(context)).await;
            let Some(item) = item else {
                break;
            };
            let terminal = item.is_err();
            match sender.try_send(item) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(item)) => {
                    if let Some(metrics) = &producer_metrics {
                        metrics.record_transport_metric(TransportMetricEvent::StreamBlocked);
                    }
                    if sender.send(item).await.is_err() {
                        break;
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_item)) => break,
            }
            if terminal {
                break;
            }
        }
        producer_cancellation.cancel();
    });
    ReceiverEventStream {
        receiver,
        cancellation,
        metrics,
    }
}

struct HttpEventStream {
    receiver: ReceiverEventStream,
}

impl Stream for HttpEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.receiver).poll_next(context) {
            Poll::Ready(Some(Ok(event))) => {
                let wire = HttpOperationEvent {
                    operation_id: event.operation_id().as_str(),
                    event_id: event.event_id(),
                    payload_cbor: URL_SAFE_NO_PAD.encode(event.payload_cbor()),
                };
                let data = match serde_json::to_string(&wire) {
                    Ok(data) => data,
                    Err(_) => "{\"code\":\"INTERNAL\"}".to_owned(),
                };
                Poll::Ready(Some(Ok(Event::default().id(event.event_id()).data(data))))
            }
            Poll::Ready(Some(Err(error))) => {
                let (_, bytes) = crate::service::problem_json(error);
                let data = String::from_utf8_lossy(&bytes).into_owned();
                Poll::Ready(Some(Ok(Event::default().event("problem").data(data))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn problem_response(error: ApiError) -> Response {
    let (status, bytes) = crate::service::problem_json(error);
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, [(CONTENT_TYPE, "application/problem+json")], bytes).into_response()
}

async fn unknown_route(State(state): State<Arc<HttpState>>) -> Response {
    problem_response(state.kernel.public_error(ErrorCode::InvalidArgument))
}

async fn method_not_allowed(State(state): State<Arc<HttpState>>) -> Response {
    let mut response = problem_response(state.kernel.public_error(ErrorCode::InvalidArgument));
    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    response
}

fn generated_method(method: &Method) -> Option<HttpMethod> {
    if method == Method::GET {
        Some(HttpMethod::Get)
    } else if method == Method::POST {
        Some(HttpMethod::Post)
    } else {
        None
    }
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, EnvelopeError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(EnvelopeError::InvalidArgument);
    }
    first
        .map(|value| value.to_str().map_err(|_| EnvelopeError::InvalidArgument))
        .transpose()
}

fn validate_unique_security_headers(headers: &HeaderMap) -> Result<(), EnvelopeError> {
    for name in [
        &AUTHORIZATION,
        &CONTENT_ENCODING,
        &CONTENT_LENGTH,
        &CONTENT_TYPE,
        &IF_MATCH,
        &HEADER_IDEMPOTENCY_KEY,
        &HEADER_LAST_EVENT_ID,
        &HEADER_OPERATION_ID,
        &HEADER_TIMEOUT_MS,
        &HEADER_TRACEPARENT,
        &HEADER_UNCOMPRESSED_LENGTH,
    ] {
        let _ = unique_header(headers, name)?;
    }
    Ok(())
}

fn validate_http_body_metadata(headers: &HeaderMap) -> Result<(), EnvelopeError> {
    let content_type = unique_header(headers, &CONTENT_TYPE)?;
    if !content_type.is_some_and(valid_json_content_type) {
        return Err(EnvelopeError::InvalidArgument);
    }
    if unique_header(headers, &CONTENT_ENCODING)?.is_some_and(|value| {
        !value.eq_ignore_ascii_case("identity") && !value.eq_ignore_ascii_case("gzip")
    }) {
        return Err(EnvelopeError::InvalidArgument);
    }
    if let Some(length) = unique_header(headers, &CONTENT_LENGTH)? {
        let length = length
            .parse::<usize>()
            .map_err(|_| EnvelopeError::InvalidArgument)?;
        if length > MAX_HTTP_COMPRESSED_BODY_BYTES {
            return Err(EnvelopeError::LimitExceeded);
        }
    }
    Ok(())
}

fn valid_json_content_type(value: &str) -> bool {
    let mut components = value.split(';');
    components
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
        && components.all(|parameter| parameter.trim().eq_ignore_ascii_case("charset=utf-8"))
}

fn decode_http_body(
    headers: &HeaderMap,
    encoded: &[u8],
    config: crate::TransportConfig,
) -> Result<Vec<u8>, EnvelopeError> {
    let expanded_limit = config
        .maximum_expanded_request_bytes()
        .min(MAX_HTTP_BODY_BYTES);
    if encoded.len() > expanded_limit {
        return Err(EnvelopeError::LimitExceeded);
    }
    let declared = unique_header(headers, &HEADER_UNCOMPRESSED_LENGTH)?
        .map(|length| {
            length
                .parse::<usize>()
                .map_err(|_| EnvelopeError::InvalidArgument)
        })
        .transpose()?;
    if declared.is_some_and(|length| length > expanded_limit) {
        return Err(EnvelopeError::LimitExceeded);
    }
    let gzip = unique_header(headers, &CONTENT_ENCODING)?
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("gzip"));
    let decoded = if gzip {
        if encoded.is_empty() || declared.is_none() {
            return Err(EnvelopeError::InvalidArgument);
        }
        let expanded_read_limit = u64::try_from(expanded_limit)
            .map_err(|_| EnvelopeError::LimitExceeded)?
            .saturating_add(1);
        let mut decoder = GzDecoder::new(encoded).take(expanded_read_limit);
        let mut decoded = Vec::new();
        decoder
            .read_to_end(&mut decoded)
            .map_err(|_| EnvelopeError::InvalidArgument)?;
        if decoded.len() > expanded_limit {
            return Err(EnvelopeError::LimitExceeded);
        }
        let maximum_expanded = encoded
            .len()
            .checked_mul(config.maximum_expansion_ratio() as usize)
            .ok_or(EnvelopeError::LimitExceeded)?;
        if decoded.len() > maximum_expanded {
            return Err(EnvelopeError::LimitExceeded);
        }
        decoded
    } else {
        encoded.to_vec()
    };
    if declared.is_some_and(|length| length != decoded.len()) {
        return Err(EnvelopeError::InvalidArgument);
    }
    Ok(decoded)
}

fn reconcile_metadata(
    header: Option<String>,
    body: Option<String>,
    required: bool,
) -> Result<Option<String>, EnvelopeError> {
    let body = body.filter(|value| !value.is_empty());
    if let (Some(header), Some(body)) = (&header, &body)
        && header != body
    {
        return Err(EnvelopeError::InvalidArgument);
    }
    if required != header.is_some() || (!required && body.is_some()) {
        return Err(EnvelopeError::InvalidArgument);
    }
    Ok(header)
}

fn parse_page_query(uri: &Uri) -> Result<(Option<String>, Option<u32>), EnvelopeError> {
    let mut cursor = None;
    let mut size = None;
    let Some(query) = uri.query() else {
        return Ok((cursor, size));
    };
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            return Err(EnvelopeError::InvalidArgument);
        };
        match name {
            "page_cursor" if cursor.is_none() && !value.is_empty() => {
                cursor = Some(value.to_owned());
            }
            "page_size" if size.is_none() => {
                size = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| EnvelopeError::InvalidArgument)?,
                );
            }
            _ => return Err(EnvelopeError::InvalidArgument),
        }
    }
    Ok((cursor, size))
}

fn parse_http_timeout(
    headers: &HeaderMap,
    kernel: &ServiceKernel,
) -> Result<Duration, EnvelopeError> {
    let Some(value) = unique_header(headers, &HEADER_TIMEOUT_MS)? else {
        return Ok(kernel.config().default_timeout());
    };
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| EnvelopeError::InvalidArgument)?;
    if milliseconds == 0 {
        return Err(EnvelopeError::InvalidArgument);
    }
    Ok(Duration::from_millis(milliseconds).min(kernel.config().maximum_timeout()))
}

fn parse_traceparent(value: &str) -> Result<TraceId, EnvelopeError> {
    let mut parts = value.split('-');
    let version = parts.next();
    let trace = parts.next();
    let parent = parts.next();
    let flags = parts.next();
    if parts.next().is_some()
        || version != Some("00")
        || !parent.is_some_and(|parent| {
            parent.len() == 16
                && parent.bytes().all(|byte| byte.is_ascii_hexdigit())
                && parent.bytes().any(|byte| byte != b'0')
        })
        || !flags.is_some_and(|flags| {
            flags.len() == 2 && flags.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(EnvelopeError::InvalidArgument);
    }
    TraceId::new(trace.unwrap_or_default()).map_err(|_| EnvelopeError::InvalidArgument)
}

fn header_value(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        OPENMETRICS_CONTENT_TYPE, bounded_receiver, match_http_operation, registered_http_routes,
        unary_response,
    };
    use crate::generated::{HttpMethod, OPERATION_COUNT, OPERATIONS};
    use crate::{
        CancellationToken, EventEnvelope, FacadeEventStream, ResponseEnvelope,
        TransportMetricEvent, TransportMetricsObserver,
    };
    use axum::body::to_bytes;
    use axum::http::header::CONTENT_TYPE;
    use cigar_canon::{parse_strict_json, to_deterministic_cbor};
    use futures_core::Stream;
    use std::collections::BTreeSet;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    #[derive(Default)]
    struct TestMetrics {
        blocked: AtomicU64,
        cancelled: AtomicU64,
    }

    impl TransportMetricsObserver for TestMetrics {
        fn record_transport_metric(&self, event: TransportMetricEvent) {
            match event {
                TransportMetricEvent::StreamBlocked => {
                    self.blocked.fetch_add(1, Ordering::Relaxed);
                }
                TransportMetricEvent::StreamCancelled => {
                    self.cancelled.fetch_add(1, Ordering::Relaxed);
                }
                TransportMetricEvent::ApiFailure | TransportMetricEvent::StreamOpened => {}
            }
        }
    }

    struct BurstStream(VecDeque<Result<EventEnvelope, crate::ApiError>>);

    impl Stream for BurstStream {
        type Item = Result<EventEnvelope, crate::ApiError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    #[test]
    fn exact_registry_has_all_45_routes_without_aliases() {
        let routes = registered_http_routes();
        assert_eq!(routes.len(), OPERATION_COUNT);
        let unique = routes
            .iter()
            .map(|(method, path, operation)| (format!("{method:?}"), *path, *operation))
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), OPERATION_COUNT);
        for contract in OPERATIONS {
            let concrete = contract
                .http_path
                .replace("{source_id}", "source-1")
                .replace("{atom_id}", "atom-1")
                .replace("{bundle_id}", "bundle-1")
                .replace("{space_id}", "space-1")
                .replace("{conflict_id}", "conflict-1")
                .replace("{handoff_id}", "handoff-1")
                .replace("{effect_id}", "effect-1")
                .replace("{replay_id}", "replay-1");
            assert_eq!(
                match_http_operation(contract.http_method, &concrete),
                Some(contract)
            );
            assert!(
                match_http_operation(contract.http_method, &(concrete.clone() + "/")).is_none()
            );
            let wrong_method = match contract.http_method {
                HttpMethod::Get => HttpMethod::Post,
                HttpMethod::Post => HttpMethod::Get,
            };
            assert!(match_http_operation(wrong_method, &concrete).is_none());
        }
        assert!(match_http_operation(HttpMethod::Get, "/V1/version").is_none());
        assert!(
            match_http_operation(HttpMethod::Get, "/v1/context/bundles/bundle%2Falias").is_none()
        );
    }

    #[tokio::test]
    async fn metrics_binding_is_directly_scrapeable_openmetrics()
    -> Result<(), Box<dyn std::error::Error>> {
        let node = parse_strict_json(
            br##"{"media_type":"application/openmetrics-text; version=1.0.0; charset=utf-8","text":"# HELP cigar_ready Ready.\n# TYPE cigar_ready gauge\ncigar_ready 1\n# EOF\n"}"##,
        )?;
        let response =
            ResponseEnvelope::new("getMetrics", to_deterministic_cbor(&node)?, None, None)?;
        let response = unary_response(&response, "0123456789abcdef0123456789abcdef");
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(OPENMETRICS_CONTENT_TYPE)
        );
        let body = to_bytes(response.into_body(), 4096).await?;
        assert_eq!(
            body.as_ref(),
            b"# HELP cigar_ready Ready.\n# TYPE cigar_ready gauge\ncigar_ready 1\n# EOF\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_stream_reports_real_full_buffer_and_early_cancellation()
    -> Result<(), Box<dyn std::error::Error>> {
        let events = VecDeque::from([
            Ok(EventEnvelope::new(
                "subscribeSpaceEvents",
                "event-1",
                vec![0xa0],
            )?),
            Ok(EventEnvelope::new(
                "subscribeSpaceEvents",
                "event-2",
                vec![0xa0],
            )?),
        ]);
        let source: FacadeEventStream = Box::pin(BurstStream(events));
        let metrics = Arc::new(TestMetrics::default());
        let observer: Arc<dyn TransportMetricsObserver> = metrics.clone();
        let receiver = bounded_receiver(source, CancellationToken::new(), 1, Some(observer));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while metrics.blocked.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(metrics.blocked.load(Ordering::Relaxed), 1);
        drop(receiver);
        assert_eq!(metrics.cancelled.load(Ordering::Relaxed), 1);
        Ok(())
    }
}
