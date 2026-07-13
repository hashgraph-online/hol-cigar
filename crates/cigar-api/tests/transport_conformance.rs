//! Differential and boundary conformance for the HTTP and gRPC service adapters.

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH};
use axum::http::{Request as HttpRequest, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::generated::AuthClass;
use cigar_api::proto::OperationRequest as GrpcOperationRequest;
use cigar_api::{
    ApiError, AuthenticatedIdentity, CancellationToken, ContextInput, EventEnvelope,
    FacadeEventStream, GrpcService, MAX_GRPC_MESSAGE_BYTES, MAX_HTTP_BODY_BYTES, OperationId,
    PrincipalId, RequestAuthority, RequestContext, RequestEnvelope, ResponseEnvelope,
    ServiceFacade, ServiceFuture, ServiceKernel, TenantId, TraceId, TransportConfig,
    VerifiedClientIdentity, http_router,
};
use cigar_protocol::{ErrorCode, RecordId, UtcTimestamp};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_core::Stream;
use prost::Message as _;
use serde::Deserialize;
use std::convert::Infallible;
use std::future::pending;
use std::io::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::Request as GrpcRequest;
use tonic::metadata::MetadataValue;
use tower::ServiceExt;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";
const CORRELATION_ID: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7890";
type VerifiedIdentityObservation = Option<(String, String)>;

#[derive(Clone)]
struct TestAuthority {
    correlation: RecordId,
    observed_timeouts: Arc<Mutex<Vec<Duration>>>,
    observed_verified_identities: Arc<Mutex<Vec<VerifiedIdentityObservation>>>,
}

impl TestAuthority {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            correlation: RecordId::new(CORRELATION_ID)?,
            observed_timeouts: Arc::new(Mutex::new(Vec::new())),
            observed_verified_identities: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn timeouts(&self) -> Vec<Duration> {
        match self.observed_timeouts.lock() {
            Ok(timeouts) => timeouts.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn verified_identities(&self) -> Vec<VerifiedIdentityObservation> {
        match self.observed_verified_identities.lock() {
            Ok(identities) => identities.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl RequestAuthority for TestAuthority {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        Box::pin(async move {
            let verified_identity = input.verified_client_identity().map(|identity| {
                (
                    identity.tenant().as_str().to_owned(),
                    identity.principal().as_str().to_owned(),
                )
            });
            if let Ok(mut identities) = self.observed_verified_identities.lock() {
                identities.push(verified_identity);
            }
            if matches!(input.auth_class(), AuthClass::Tenant | AuthClass::Operator)
                && input.authorization() != Some("Bearer valid")
            {
                return Err(self.public_error(ErrorCode::UnknownPrincipal));
            }
            if let Ok(mut timeouts) = self.observed_timeouts.lock() {
                timeouts.push(input.timeout());
            }
            let accepted_nanos = i128::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| self.public_error(ErrorCode::Internal))?
                    .as_nanos(),
            )
            .map_err(|_| self.public_error(ErrorCode::Internal))?;
            let accepted = UtcTimestamp::from_unix_nanos(accepted_nanos)
                .map_err(|_| self.public_error(ErrorCode::Internal))?;
            let timeout_nanos = i128::try_from(input.timeout().as_nanos())
                .map_err(|_| self.public_error(ErrorCode::Internal))?;
            let deadline = UtcTimestamp::from_unix_nanos(accepted.unix_nanos() + timeout_nanos)
                .map_err(|_| self.public_error(ErrorCode::Internal))?;
            let trace = match input.trace_id() {
                Some(trace) => trace.clone(),
                None => {
                    TraceId::new(TRACE_ID).map_err(|_| self.public_error(ErrorCode::Internal))?
                }
            };
            RequestContext::new(
                AuthenticatedIdentity::from_verified_credentials(
                    TenantId::new("tenant-a")
                        .map_err(|_| self.public_error(ErrorCode::Internal))?,
                    PrincipalId::new("principal-a")
                        .map_err(|_| self.public_error(ErrorCode::Internal))?,
                ),
                input.operation_id().clone(),
                deadline,
                trace,
                input.cancellation().clone(),
                accepted,
            )
            .map_err(|_| self.public_error(ErrorCode::Internal))
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.correlation.clone())
    }
}

struct TestFacade {
    correlation: RecordId,
    requests: Mutex<Vec<RequestEnvelope>>,
    stream_cancellation: Mutex<Option<CancellationToken>>,
    stream_events: usize,
    stream_polls: Arc<AtomicUsize>,
}

impl TestFacade {
    fn new(stream_events: usize) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            correlation: RecordId::new(CORRELATION_ID)?,
            requests: Mutex::new(Vec::new()),
            stream_cancellation: Mutex::new(None),
            stream_events,
            stream_polls: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn requests(&self) -> Vec<RequestEnvelope> {
        match self.requests.lock() {
            Ok(requests) => requests.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn stream_token(&self) -> Option<CancellationToken> {
        match self.stream_cancellation.lock() {
            Ok(token) => token.clone(),
            Err(_) => None,
        }
    }
}

impl ServiceFacade for TestFacade {
    fn call<'a>(
        &'a self,
        _context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request.clone());
        }
        let correlation = self.correlation.clone();
        Box::pin(async move {
            if request.payload_cbor() == b"deny" {
                return Err(ApiError::new(ErrorCode::PolicyDenied, correlation));
            }
            ResponseEnvelope::new(
                request.operation_id().as_str(),
                request.payload_cbor().to_vec(),
                Some("\"semantic-1\"".to_owned()),
                Some("next-page-1".to_owned()),
            )
            .map_err(|_| ApiError::new(ErrorCode::Internal, correlation))
        })
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request);
        }
        if let Ok(mut token) = self.stream_cancellation.lock() {
            *token = Some(context.cancellation().clone());
        }
        let stream: FacadeEventStream = Box::pin(CountingEventStream {
            remaining: self.stream_events,
            ordinal: 42,
            polls: Arc::clone(&self.stream_polls),
            correlation: self.correlation.clone(),
        });
        Box::pin(async move { Ok(stream) })
    }
}

struct CountingEventStream {
    remaining: usize,
    ordinal: usize,
    polls: Arc<AtomicUsize>,
    correlation: RecordId,
}

impl Stream for CountingEventStream {
    type Item = Result<EventEnvelope, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        self.polls.fetch_add(1, Ordering::SeqCst);
        let event_id = format!("event-{}", self.ordinal);
        self.ordinal += 1;
        self.remaining -= 1;
        let event = EventEnvelope::new(
            "subscribeSpaceEvents",
            event_id,
            vec![u8::try_from(self.remaining % 256).unwrap_or_default()],
        )
        .map_err(|_| ApiError::new(ErrorCode::Internal, self.correlation.clone()));
        Poll::Ready(Some(event))
    }
}

fn fixture(
    stream_events: usize,
    stream_capacity: usize,
) -> Result<(ServiceKernel, Arc<TestFacade>, TestAuthority), Box<dyn std::error::Error>> {
    let facade = Arc::new(TestFacade::new(stream_events)?);
    let authority = TestAuthority::new()?;
    let config = TransportConfig::new(
        Duration::from_secs(30),
        Duration::from_secs(120),
        stream_capacity,
    )?;
    let kernel = ServiceKernel::new(
        Arc::clone(&facade) as Arc<dyn ServiceFacade>,
        Arc::new(authority.clone()),
        config,
    );
    Ok((kernel, facade, authority))
}

fn grpc_unary_request(
    operation: &str,
    payload: Vec<u8>,
    idempotency_key: Option<&str>,
) -> GrpcRequest<GrpcOperationRequest> {
    let mut request = GrpcRequest::new(GrpcOperationRequest {
        operation_id: operation.to_owned(),
        idempotency_key: idempotency_key.unwrap_or_default().to_owned(),
        expected_revision: String::new(),
        payload_cbor: payload,
        page_cursor: "page-1".to_owned(),
        page_size: 25,
        path_parameters: Vec::new(),
        dry_run: false,
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer valid"));
    request
        .metadata_mut()
        .insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    if idempotency_key.is_some() {
        request
            .metadata_mut()
            .insert("idempotency-key", MetadataValue::from_static("request-1"));
    }
    request
}

fn http_unary_request(
    operation: &str,
    payload: &[u8],
    body_idempotency_key: Option<&str>,
    header_idempotency_key: Option<&str>,
) -> Result<HttpRequest<Body>, Box<dyn std::error::Error>> {
    let mut body = serde_json::json!({
        "operation_id": operation,
        "payload_cbor": URL_SAFE_NO_PAD.encode(payload),
        "page_cursor": "page-1",
        "page_size": 25,
        "path_parameters": []
    });
    if let Some(key) = body_idempotency_key {
        body.as_object_mut()
            .ok_or("HTTP request fixture must be an object")?
            .insert(
                "idempotency_key".to_owned(),
                serde_json::Value::String(key.to_owned()),
            );
    }
    let path = if operation == "ingestCatalog" {
        "/v1/catalog:ingest"
    } else {
        "/v1/catalog:query"
    };
    let mut builder = HttpRequest::post(path)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT);
    if let Some(key) = header_idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    Ok(builder.body(Body::from(serde_json::to_vec(&body)?))?)
}

fn ingest_json(payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "operation_id": "ingestCatalog",
        "payload_cbor": URL_SAFE_NO_PAD.encode(payload),
        "idempotency_key": "request-1",
        "path_parameters": []
    }))?)
}

fn gzip(input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}

struct OneFrameThenPending {
    frame: Option<Vec<u8>>,
}

impl Stream for OneFrameThenPending {
    type Item = Result<Vec<u8>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.frame.take() {
            Some(frame) => Poll::Ready(Some(Ok(frame))),
            None => Poll::Pending,
        }
    }
}

#[derive(Deserialize)]
struct WireResponse {
    operation_id: String,
    payload_cbor: String,
    semantic_etag: Option<String>,
    next_page_cursor: Option<String>,
}

#[tokio::test]
async fn unary_success_and_error_semantics_are_byte_identical_across_transports()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(1, 2)?;
    let http = http_router(kernel.clone());
    let grpc = GrpcService::new(kernel);

    let http_response = http
        .clone()
        .oneshot(http_unary_request(
            "ingestCatalog",
            b"canonical-cbor",
            Some("request-1"),
            Some("request-1"),
        )?)
        .await?;
    assert_eq!(http_response.status(), StatusCode::OK);
    assert_eq!(
        http_response.headers().get(ETAG),
        Some(&axum::http::HeaderValue::from_static("\"semantic-1\""))
    );
    let http_body = to_bytes(http_response.into_body(), 4096).await?;
    let http_wire: WireResponse = serde_json::from_slice(&http_body)?;

    let grpc_response = grpc
        .dispatch_unary(
            "ingestCatalog",
            grpc_unary_request(
                "ingestCatalog",
                b"canonical-cbor".to_vec(),
                Some("request-1"),
            ),
        )
        .await?;
    assert_eq!(
        URL_SAFE_NO_PAD.decode(http_wire.payload_cbor)?,
        grpc_response.get_ref().payload_cbor
    );
    assert_eq!(http_wire.operation_id, grpc_response.get_ref().operation_id);
    assert_eq!(
        http_wire.semantic_etag.as_deref(),
        Some(grpc_response.get_ref().semantic_etag.as_str())
    );
    assert_eq!(
        http_wire.next_page_cursor.as_deref(),
        Some(grpc_response.get_ref().next_page_cursor.as_str())
    );
    let requests = facade.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests.first(), requests.get(1));

    let http_error = http
        .oneshot(http_unary_request(
            "ingestCatalog",
            b"deny",
            Some("request-1"),
            Some("request-1"),
        )?)
        .await?;
    assert_eq!(http_error.status(), StatusCode::FORBIDDEN);
    let http_problem = to_bytes(http_error.into_body(), 4096).await?;
    let grpc_error = grpc
        .dispatch_unary(
            "ingestCatalog",
            grpc_unary_request("ingestCatalog", b"deny".to_vec(), Some("request-1")),
        )
        .await
        .err()
        .ok_or("expected gRPC policy error")?;
    assert_eq!(grpc_error.code(), tonic::Code::PermissionDenied);
    assert_eq!(http_problem.as_ref(), grpc_error.details());
    Ok(())
}

#[tokio::test]
async fn verified_peer_identity_flows_only_through_typed_transport_extensions()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _, authority) = fixture(1, 2)?;
    let router = http_router(kernel.clone());
    let mut forged_header = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    forged_header
        .headers_mut()
        .insert("x-client-san", "tenant-forged/principal-forged".parse()?);
    assert_eq!(
        router.clone().oneshot(forged_header).await?.status(),
        StatusCode::OK
    );

    let verified = VerifiedClientIdentity::from_verified_tls_peer(
        TenantId::new("tenant-mtls")?,
        PrincipalId::new("principal-mtls")?,
    )?;
    let rendered = format!("{verified:?}");
    assert!(!rendered.contains("tenant-mtls"));
    assert!(!rendered.contains("principal-mtls"));
    let mut verified_http = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    verified_http.extensions_mut().insert(verified.clone());
    assert_eq!(
        router.oneshot(verified_http).await?.status(),
        StatusCode::OK
    );

    let mut verified_grpc =
        grpc_unary_request("ingestCatalog", b"payload".to_vec(), Some("request-1"));
    verified_grpc.extensions_mut().insert(verified);
    assert!(
        GrpcService::new(kernel)
            .dispatch_unary("ingestCatalog", verified_grpc)
            .await
            .is_ok()
    );
    assert_eq!(
        authority.verified_identities(),
        vec![
            None,
            Some(("tenant-mtls".to_owned(), "principal-mtls".to_owned())),
            Some(("tenant-mtls".to_owned(), "principal-mtls".to_owned())),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn malformed_oversized_and_forged_http_metadata_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _, _) = fixture(1, 2)?;
    let router = http_router(kernel);

    let missing_idempotency = router
        .clone()
        .oneshot(http_unary_request("ingestCatalog", b"payload", None, None)?)
        .await?;
    assert_eq!(missing_idempotency.status(), StatusCode::BAD_REQUEST);

    let body_only_idempotency = router
        .clone()
        .oneshot(http_unary_request(
            "ingestCatalog",
            b"payload",
            Some("request-1"),
            None,
        )?)
        .await?;
    assert_eq!(body_only_idempotency.status(), StatusCode::BAD_REQUEST);

    let forged_idempotency = router
        .clone()
        .oneshot(http_unary_request(
            "ingestCatalog",
            b"payload",
            Some("forged"),
            Some("request-1"),
        )?)
        .await?;
    assert_eq!(forged_idempotency.status(), StatusCode::BAD_REQUEST);

    let mut malformed_trace = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    malformed_trace
        .headers_mut()
        .insert("traceparent", "forged".parse()?);
    let malformed_trace = router.clone().oneshot(malformed_trace).await?;
    assert_eq!(malformed_trace.status(), StatusCode::BAD_REQUEST);

    let mut duplicate = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    duplicate
        .headers_mut()
        .append("idempotency-key", "second-key".parse()?);
    let duplicate = router.clone().oneshot(duplicate).await?;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);

    let mut oversized = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    oversized.headers_mut().insert(
        CONTENT_LENGTH,
        (MAX_HTTP_BODY_BYTES + 1).to_string().parse()?,
    );
    let oversized = router.clone().oneshot(oversized).await?;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    let oversized_problem = to_bytes(oversized.into_body(), 4096).await?;
    let oversized_problem: serde_json::Value = serde_json::from_slice(&oversized_problem)?;
    assert_eq!(
        oversized_problem
            .get("code")
            .and_then(serde_json::Value::as_str),
        Some("LIMIT_EXCEEDED")
    );

    let mut forged_length = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    forged_length
        .headers_mut()
        .insert("x-cigar-uncompressed-length", "1".parse()?);
    let forged_length = router.oneshot(forged_length).await?;
    assert_eq!(forged_length.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn incomplete_http_body_is_stopped_by_the_server_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let facade = Arc::new(TestFacade::new(1)?);
    let authority = TestAuthority::new()?;
    let config = TransportConfig::new(Duration::from_millis(20), Duration::from_secs(1), 2)?;
    let kernel = ServiceKernel::new(
        Arc::clone(&facade) as Arc<dyn ServiceFacade>,
        Arc::new(authority.clone()),
        config,
    );
    let request = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("idempotency-key", "request-1")
        .header("x-cigar-timeout-ms", "500")
        .body(Body::from_stream(OneFrameThenPending {
            frame: Some(b"{\"operation_id\":\"ingestCatalog\",".to_vec()),
        }))?;

    let response = tokio::time::timeout(
        Duration::from_millis(250),
        http_router(kernel).oneshot(request),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let problem = to_bytes(response.into_body(), 4096).await?;
    let problem: serde_json::Value = serde_json::from_slice(&problem)?;
    assert_eq!(
        problem.get("code").and_then(serde_json::Value::as_str),
        Some("DEADLINE_EXCEEDED")
    );
    assert!(authority.timeouts().is_empty());
    assert!(facade.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn implicit_head_aliases_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(1, 2)?;
    let response = http_router(kernel)
        .oneshot(HttpRequest::head("/v1/version").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(facade.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn strict_http_json_rejects_duplicate_security_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _, _) = fixture(1, 2)?;
    let router = http_router(kernel);
    let payload = URL_SAFE_NO_PAD.encode(b"payload");
    for body in [
        format!(
            "{{\"operation_id\":\"ingestCatalog\",\"operation_id\":\"queryCatalog\",\"payload_cbor\":\"{payload}\",\"idempotency_key\":\"request-1\",\"path_parameters\":[]}}"
        ),
        format!(
            "{{\"operation_id\":\"ingestCatalog\",\"payload_cbor\":\"{payload}\",\"idempotency_key\":\"request-1\",\"idempotency_key\":\"forged\",\"path_parameters\":[]}}"
        ),
    ] {
        let request = HttpRequest::post("/v1/catalog:ingest")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer valid")
            .header("traceparent", TRACEPARENT)
            .header("idempotency-key", "request-1")
            .body(Body::from(body))?;
        assert_eq!(
            router.clone().oneshot(request).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

#[tokio::test]
async fn http_json_bytes_require_unpadded_base64url() -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(1, 2)?;
    let router = http_router(kernel);
    for invalid in ["oA==", "+/8"] {
        let body = serde_json::to_vec(&serde_json::json!({
            "operation_id": "ingestCatalog",
            "payload_cbor": invalid,
            "idempotency_key": "request-1",
            "path_parameters": []
        }))?;
        let request = HttpRequest::post("/v1/catalog:ingest")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer valid")
            .header("idempotency-key", "request-1")
            .body(Body::from(body))?;
        assert_eq!(
            router.clone().oneshot(request).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(facade.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn gzip_requests_enforce_expanded_size_ratio_and_declared_length()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _, _) = fixture(1, 2)?;
    let router = http_router(kernel);
    let json = ingest_json(b"compressed-payload")?;
    let compressed = gzip(&json)?;
    let success = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .header("content-encoding", "gzip")
        .header("x-cigar-uncompressed-length", json.len().to_string())
        .body(Body::from(compressed.clone()))?;
    assert_eq!(
        router.clone().oneshot(success).await?.status(),
        StatusCode::OK
    );

    let mismatched = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .header("content-encoding", "gzip")
        .header("x-cigar-uncompressed-length", (json.len() + 1).to_string())
        .body(Body::from(compressed))?;
    assert_eq!(
        router.clone().oneshot(mismatched).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let bomb_json = ingest_json(&vec![0_u8; 128 * 1024])?;
    let bomb = gzip(&bomb_json)?;
    assert!(bomb_json.len() > bomb.len().saturating_mul(64));
    let bomb_request = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .header("content-encoding", "gzip")
        .header("x-cigar-uncompressed-length", bomb_json.len().to_string())
        .body(Body::from(bomb))?;
    let bomb_response = router.clone().oneshot(bomb_request).await?;
    assert_eq!(bomb_response.status(), StatusCode::BAD_REQUEST);
    let problem = to_bytes(bomb_response.into_body(), 4096).await?;
    let problem: serde_json::Value = serde_json::from_slice(&problem)?;
    assert_eq!(
        problem.get("code").and_then(serde_json::Value::as_str),
        Some("LIMIT_EXCEEDED")
    );

    let unsupported = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .header("content-encoding", "br")
        .body(Body::from(json))?;
    assert_eq!(
        router.oneshot(unsupported).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn deployment_limit_caps_identity_and_fully_expanded_gzip_entities()
-> Result<(), Box<dyn std::error::Error>> {
    let facade = Arc::new(TestFacade::new(1)?);
    let authority = TestAuthority::new()?;
    let config = TransportConfig::with_compression_limits(
        Duration::from_secs(30),
        Duration::from_secs(30),
        2,
        1_024,
    )?
    .with_maximum_expanded_request_bytes(1_024)?;
    let kernel = ServiceKernel::new(
        Arc::clone(&facade) as Arc<dyn ServiceFacade>,
        Arc::new(authority),
        config,
    );
    let router = http_router(kernel);
    let expanded = ingest_json(&vec![0_u8; 1_500])?;
    assert!(expanded.len() > config.maximum_expanded_request_bytes());

    let identity = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("idempotency-key", "request-1")
        .body(Body::from(expanded.clone()))?;
    assert_eq!(
        router.clone().oneshot(identity).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let compressed = gzip(&expanded)?;
    assert!(compressed.len() < config.maximum_expanded_request_bytes());
    let gzip = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("idempotency-key", "request-1")
        .header("content-encoding", "gzip")
        .header("x-cigar-uncompressed-length", expanded.len().to_string())
        .body(Body::from(compressed))?;
    assert_eq!(
        router.oneshot(gzip).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert!(facade.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn grpc_request_compression_fails_closed_and_identity_lengths_are_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, _, _) = fixture(1, 2)?;
    let grpc = GrpcService::new(kernel);
    let mut compressed = grpc_unary_request(
        "ingestCatalog",
        b"compressed-payload".to_vec(),
        Some("request-1"),
    );
    compressed
        .metadata_mut()
        .insert("grpc-encoding", MetadataValue::from_static("gzip"));
    let compressed_length = compressed.get_ref().encoded_len();
    compressed
        .metadata_mut()
        .insert("x-cigar-compressed-length", MetadataValue::from_static("8"));
    compressed.metadata_mut().insert(
        "x-cigar-uncompressed-length",
        MetadataValue::try_from(compressed_length.to_string())?,
    );
    assert_eq!(
        grpc.dispatch_unary("ingestCatalog", compressed)
            .await
            .err()
            .ok_or("expected compressed gRPC request rejection")?
            .code(),
        tonic::Code::InvalidArgument
    );

    let mut identity = grpc_unary_request(
        "ingestCatalog",
        b"identity-payload".to_vec(),
        Some("request-1"),
    );
    let identity_length = identity.get_ref().encoded_len();
    identity.metadata_mut().insert(
        "x-cigar-uncompressed-length",
        MetadataValue::try_from(identity_length.to_string())?,
    );
    assert!(grpc.dispatch_unary("ingestCatalog", identity).await.is_ok());

    let mut mismatch = grpc_unary_request(
        "ingestCatalog",
        b"identity-payload".to_vec(),
        Some("request-1"),
    );
    let mismatch_length = mismatch.get_ref().encoded_len();
    mismatch.metadata_mut().insert(
        "x-cigar-uncompressed-length",
        MetadataValue::try_from((mismatch_length + 1).to_string())?,
    );
    assert_eq!(
        grpc.dispatch_unary("ingestCatalog", mismatch)
            .await
            .err()
            .ok_or("expected gRPC declared-length error")?
            .code(),
        tonic::Code::InvalidArgument
    );

    let (limited_kernel, _, _) = fixture(1, 2)?;
    let limited = GrpcService::new(limited_kernel).with_max_message_bytes(32)?;
    assert_eq!(limited.maximum_message_bytes(), 32);
    assert_eq!(
        limited
            .dispatch_unary(
                "ingestCatalog",
                grpc_unary_request("ingestCatalog", vec![0; 64], Some("request-1")),
            )
            .await
            .err()
            .ok_or("expected deployment message limit")?
            .code(),
        tonic::Code::ResourceExhausted
    );
    Ok(())
}

#[tokio::test]
async fn revisioned_mutations_and_grpc_bounds_are_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(1, 2)?;
    let router = http_router(kernel.clone());
    let body = serde_json::json!({
        "operation_id": "tombstoneAtom",
        "payload_cbor": URL_SAFE_NO_PAD.encode(b"payload"),
        "idempotency_key": "request-1",
        "path_parameters": [{"name": "atom_id", "value": "atom-1"}]
    });
    let no_revision = HttpRequest::post("/v1/catalog/atoms/atom-1:tombstone")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .body(Body::from(serde_json::to_vec(&body)?))?;
    assert_eq!(
        router.clone().oneshot(no_revision).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let with_revision = HttpRequest::post("/v1/catalog/atoms/atom-1:tombstone")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .header(IF_MATCH, "revision-1")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operation_id": "tombstoneAtom",
            "payload_cbor": URL_SAFE_NO_PAD.encode(b"payload"),
            "idempotency_key": "request-1",
            "expected_revision": "revision-1",
            "path_parameters": [{"name": "atom_id", "value": "atom-1"}]
        }))?))?;
    assert_eq!(
        router.clone().oneshot(with_revision).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        facade
            .requests()
            .last()
            .and_then(|request| request.path_parameters().first())
            .map(|parameter| (parameter.name(), parameter.value())),
        Some(("atom_id", "atom-1"))
    );
    let mismatched_path = HttpRequest::post("/v1/catalog/atoms/atom-1:tombstone")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .header(IF_MATCH, "revision-1")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operation_id": "tombstoneAtom",
            "payload_cbor": URL_SAFE_NO_PAD.encode(b"payload"),
            "idempotency_key": "request-1",
            "expected_revision": "revision-1",
            "path_parameters": [{"name": "atom_id", "value": "atom-2"}]
        }))?))?;
    assert_eq!(
        router.oneshot(mismatched_path).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let grpc = GrpcService::new(kernel);
    let mut forged_operation =
        grpc_unary_request("ingestCatalog", b"payload".to_vec(), Some("request-1"));
    forged_operation.metadata_mut().insert(
        "x-cigar-operation-id",
        MetadataValue::from_static("queryCatalog"),
    );
    assert_eq!(
        grpc.dispatch_unary("ingestCatalog", forged_operation)
            .await
            .err()
            .ok_or("expected forged operation error")?
            .code(),
        tonic::Code::InvalidArgument
    );

    let mut oversized = grpc_unary_request("ingestCatalog", b"small".to_vec(), Some("request-1"));
    oversized.metadata_mut().insert(
        "x-cigar-uncompressed-length",
        MetadataValue::try_from((MAX_GRPC_MESSAGE_BYTES + 1).to_string())?,
    );
    assert_eq!(
        grpc.dispatch_unary("ingestCatalog", oversized)
            .await
            .err()
            .ok_or("expected gRPC limit error")?
            .code(),
        tonic::Code::ResourceExhausted
    );
    Ok(())
}

fn grpc_tombstone_request(
    path_parameters: Vec<cigar_api::proto::PathParameter>,
) -> GrpcRequest<GrpcOperationRequest> {
    let mut request = GrpcRequest::new(GrpcOperationRequest {
        operation_id: "tombstoneAtom".to_owned(),
        idempotency_key: "request-1".to_owned(),
        expected_revision: "revision-1".to_owned(),
        payload_cbor: b"payload".to_vec(),
        page_cursor: String::new(),
        page_size: 0,
        path_parameters,
        dry_run: false,
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer valid"));
    request
        .metadata_mut()
        .insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    request
        .metadata_mut()
        .insert("idempotency-key", MetadataValue::from_static("request-1"));
    request
        .metadata_mut()
        .insert("if-match", MetadataValue::from_static("revision-1"));
    request
}

#[tokio::test]
async fn path_bindings_are_identical_and_duplicate_missing_or_extra_names_fail()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(1, 2)?;
    let grpc = GrpcService::new(kernel);
    let exact = vec![cigar_api::proto::PathParameter {
        name: "atom_id".to_owned(),
        value: "atom-1".to_owned(),
    }];
    assert!(
        grpc.dispatch_unary("tombstoneAtom", grpc_tombstone_request(exact.clone()))
            .await
            .is_ok()
    );
    assert_eq!(
        facade
            .requests()
            .last()
            .and_then(|request| request.path_parameters().first())
            .map(|parameter| (parameter.name(), parameter.value())),
        Some(("atom_id", "atom-1"))
    );

    let binding = exact
        .first()
        .cloned()
        .ok_or("exact path fixture is empty")?;
    let duplicate = vec![binding.clone(), binding.clone()];
    let extra = vec![
        binding,
        cigar_api::proto::PathParameter {
            name: "space_id".to_owned(),
            value: "space-1".to_owned(),
        },
    ];
    for parameters in [Vec::new(), duplicate, extra] {
        assert_eq!(
            grpc.dispatch_unary("tombstoneAtom", grpc_tombstone_request(parameters))
                .await
                .err()
                .ok_or("expected invalid path bindings")?
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    Ok(())
}

#[tokio::test]
async fn sse_resume_cursor_event_identity_and_trace_are_preserved()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, authority) = fixture(1, 2)?;
    let request = HttpRequest::get("/v1/spaces/space-1/events?page_size=10")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("last-event-id", "event-41")
        .header("x-cigar-timeout-ms", "999999")
        .body(Body::empty())?;
    let response = http_router(kernel).oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-cigar-trace-id"),
        Some(&axum::http::HeaderValue::from_static(TRACE_ID))
    );
    let bytes = to_bytes(response.into_body(), 4096).await?;
    let rendered = String::from_utf8(bytes.to_vec())?;
    assert!(rendered.contains("id: event-42"));
    assert!(rendered.contains("\"operation_id\":\"subscribeSpaceEvents\""));
    assert_eq!(
        facade
            .requests()
            .last()
            .and_then(RequestEnvelope::page_cursor),
        Some("event-41")
    );
    assert_eq!(authority.timeouts().last(), Some(&Duration::from_secs(120)));
    Ok(())
}

#[tokio::test]
async fn grpc_stream_queue_is_bounded_and_disconnect_cancels_upstream()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(100, 1)?;
    let grpc = GrpcService::new(kernel);
    let mut request = GrpcRequest::new(GrpcOperationRequest {
        operation_id: "subscribeSpaceEvents".to_owned(),
        idempotency_key: String::new(),
        expected_revision: String::new(),
        payload_cbor: Vec::new(),
        page_cursor: String::new(),
        page_size: 10,
        path_parameters: vec![cigar_api::proto::PathParameter {
            name: "space_id".to_owned(),
            value: "space-1".to_owned(),
        }],
        dry_run: false,
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer valid"));
    request
        .metadata_mut()
        .insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    request
        .metadata_mut()
        .insert("last-event-id", MetadataValue::from_static("event-41"));
    let response = grpc
        .dispatch_stream("subscribeSpaceEvents", request)
        .await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let polls = facade.stream_polls.load(Ordering::SeqCst);
    assert!((1..=2).contains(&polls));
    assert_eq!(
        facade
            .requests()
            .last()
            .and_then(RequestEnvelope::page_cursor),
        Some("event-41")
    );
    drop(response);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        facade
            .stream_token()
            .is_some_and(|token| token.is_cancelled())
    );
    Ok(())
}

#[tokio::test]
async fn dry_run_intent_survives_http_and_grpc_normalization_without_changing_governance()
-> Result<(), Box<dyn std::error::Error>> {
    let (kernel, facade, _) = fixture(1, 4)?;
    let router = http_router(kernel.clone());
    let body = serde_json::json!({
        "operation_id": "ingestCatalog",
        "payload_cbor": URL_SAFE_NO_PAD.encode([0xa0]),
        "dry_run": true,
        "idempotency_key": "request-1",
        "path_parameters": []
    });
    let request = HttpRequest::post("/v1/catalog:ingest")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer valid")
        .header("traceparent", TRACEPARENT)
        .header("idempotency-key", "request-1")
        .body(Body::from(serde_json::to_vec(&body)?))?;
    assert_eq!(router.oneshot(request).await?.status(), StatusCode::OK);
    assert_eq!(
        facade.requests().last().map(RequestEnvelope::dry_run),
        Some(true)
    );

    let mut grpc_request = grpc_unary_request("ingestCatalog", vec![0xa0], Some("request-1"));
    grpc_request.get_mut().dry_run = true;
    GrpcService::new(kernel)
        .dispatch_unary("ingestCatalog", grpc_request)
        .await?;
    assert_eq!(
        facade.requests().last().map(RequestEnvelope::dry_run),
        Some(true)
    );
    Ok(())
}

struct PendingFacade {
    correlation: RecordId,
    cancellation: Arc<Mutex<Option<CancellationToken>>>,
}

struct PendingEventStream;

impl Stream for PendingEventStream {
    type Item = Result<EventEnvelope, ApiError>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

struct HangingSubscriptionFacade {
    correlation: RecordId,
    cancellation: Arc<Mutex<Option<CancellationToken>>>,
}

impl ServiceFacade for HangingSubscriptionFacade {
    fn call<'a>(
        &'a self,
        _context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        let error = ApiError::new(ErrorCode::Internal, self.correlation.clone());
        Box::pin(async move { Err(error) })
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        if let Ok(mut cancellation) = self.cancellation.lock() {
            *cancellation = Some(context.cancellation().clone());
        }
        let stream: FacadeEventStream = Box::pin(PendingEventStream);
        Box::pin(async move { Ok(stream) })
    }
}

impl ServiceFacade for PendingFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        if let Ok(mut cancellation) = self.cancellation.lock() {
            *cancellation = Some(context.cancellation().clone());
        }
        Box::pin(async move { pending::<Result<ResponseEnvelope, ApiError>>().await })
    }

    fn subscribe<'a>(
        &'a self,
        _context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        let error = ApiError::new(ErrorCode::Internal, self.correlation.clone());
        Box::pin(async move { Err(error) })
    }
}

#[tokio::test]
async fn hanging_facades_time_out_and_cancel_for_http_and_grpc()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = TestAuthority::new()?;
    let cancellation = Arc::new(Mutex::new(None));
    let facade = Arc::new(PendingFacade {
        correlation: RecordId::new(CORRELATION_ID)?,
        cancellation: Arc::clone(&cancellation),
    });
    let kernel = ServiceKernel::new(
        Arc::clone(&facade) as Arc<dyn ServiceFacade>,
        Arc::new(authority),
        TransportConfig::with_compression_limits(
            Duration::from_millis(10),
            Duration::from_millis(20),
            2,
            64,
        )?,
    );
    let mut http_request = http_unary_request(
        "ingestCatalog",
        b"payload",
        Some("request-1"),
        Some("request-1"),
    )?;
    http_request
        .headers_mut()
        .insert("x-cigar-timeout-ms", "10".parse()?);
    let http_response = tokio::time::timeout(
        Duration::from_millis(100),
        http_router(kernel.clone()).oneshot(http_request),
    )
    .await??;
    assert_eq!(http_response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        cancellation
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .is_some_and(|token| token.is_cancelled())
    );

    let mut grpc_request =
        grpc_unary_request("ingestCatalog", b"payload".to_vec(), Some("request-1"));
    grpc_request
        .metadata_mut()
        .insert("grpc-timeout", MetadataValue::from_static("10m"));
    let grpc_error = tokio::time::timeout(
        Duration::from_millis(100),
        GrpcService::new(kernel).dispatch_unary("ingestCatalog", grpc_request),
    )
    .await?
    .err()
    .ok_or("expected gRPC deadline")?;
    assert_eq!(grpc_error.code(), tonic::Code::DeadlineExceeded);
    assert!(
        cancellation
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .is_some_and(|token| token.is_cancelled())
    );
    Ok(())
}

#[tokio::test]
async fn stream_lifetime_ends_at_the_effective_deadline() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = TestAuthority::new()?;
    let cancellation = Arc::new(Mutex::new(None));
    let facade = Arc::new(HangingSubscriptionFacade {
        correlation: RecordId::new(CORRELATION_ID)?,
        cancellation: Arc::clone(&cancellation),
    });
    let kernel = ServiceKernel::new(
        facade as Arc<dyn ServiceFacade>,
        Arc::new(authority),
        TransportConfig::with_compression_limits(
            Duration::from_millis(10),
            Duration::from_millis(20),
            2,
            64,
        )?,
    );
    let mut request = GrpcRequest::new(GrpcOperationRequest {
        operation_id: "subscribeSpaceEvents".to_owned(),
        idempotency_key: String::new(),
        expected_revision: String::new(),
        payload_cbor: Vec::new(),
        page_cursor: String::new(),
        page_size: 0,
        path_parameters: vec![cigar_api::proto::PathParameter {
            name: "space_id".to_owned(),
            value: "space-1".to_owned(),
        }],
        dry_run: false,
    });
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer valid"));
    request
        .metadata_mut()
        .insert("traceparent", MetadataValue::from_static(TRACEPARENT));
    request
        .metadata_mut()
        .insert("grpc-timeout", MetadataValue::from_static("10m"));
    let mut stream = GrpcService::new(kernel)
        .dispatch_stream("subscribeSpaceEvents", request)
        .await?
        .into_inner();
    let item = tokio::time::timeout(
        Duration::from_millis(100),
        std::future::poll_fn(|context| stream.as_mut().poll_next(context)),
    )
    .await?
    .ok_or("deadline stream ended without a status")?;
    assert_eq!(
        item.err().ok_or("expected stream deadline status")?.code(),
        tonic::Code::DeadlineExceeded
    );
    assert!(
        cancellation
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .is_some_and(|token| token.is_cancelled())
    );
    Ok(())
}

#[tokio::test]
async fn dropping_an_inflight_unary_rpc_cancels_the_facade_context()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = TestAuthority::new()?;
    let cancellation = Arc::new(Mutex::new(None));
    let facade = Arc::new(PendingFacade {
        correlation: RecordId::new(CORRELATION_ID)?,
        cancellation: Arc::clone(&cancellation),
    });
    let kernel = ServiceKernel::new(
        facade as Arc<dyn ServiceFacade>,
        Arc::new(authority),
        TransportConfig::default(),
    );
    let grpc = GrpcService::new(kernel);
    let task = tokio::spawn(async move {
        grpc.dispatch_unary(
            "ingestCatalog",
            grpc_unary_request("ingestCatalog", b"payload".to_vec(), Some("request-1")),
        )
        .await
    });
    for _ in 0..20 {
        if cancellation
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .is_some()
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    assert!(
        cancellation
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .is_some_and(|token| token.is_cancelled())
    );
    Ok(())
}

#[test]
fn operation_identity_type_rejects_transport_aliases() {
    assert!(OperationId::new("queryCatalog").is_ok());
    assert!(OperationId::new("QueryCatalog").is_err());
}
