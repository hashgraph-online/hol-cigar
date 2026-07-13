//! Every frozen operation has one embedded implementation and identical HTTP/gRPC semantics.

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_api::generated::{HttpMethod, OPERATIONS, StreamKind};
use cigar_api::proto::{OperationRequest as GrpcOperationRequest, PathParameter as GrpcPath};
use cigar_api::{
    ApiError, AuthenticatedIdentity, CancellationToken, CompleteServiceFacade,
    CompleteServiceFacadeBuilder, ContextInput, EventEnvelope, FacadeErrorFactory,
    FacadeEventStream, GrpcService, OperationId, PathParameter, PrincipalId, RequestAuthority,
    RequestContext, RequestEnvelope, ResponseEnvelope, ServiceFacade, ServiceFuture, ServiceKernel,
    StreamOperationHandler, TenantId, TraceId, TransportConfig, UnaryOperationHandler, http_router,
};
use cigar_protocol::{ErrorCode, RecordId, UtcTimestamp};
use futures_core::Stream;
use serde::Deserialize;
use serde_json::json;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::Request as GrpcRequest;
use tonic::metadata::MetadataValue;
use tower::ServiceExt as _;

const CORRELATION: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f7890";
const TRACE: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct Errors(RecordId);

impl Errors {
    fn error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.0.clone())
    }
}

impl FacadeErrorFactory for Errors {
    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.error(code)
    }
}

impl RequestAuthority for Errors {
    fn resolve<'a>(
        &'a self,
        input: ContextInput,
    ) -> ServiceFuture<'a, Result<RequestContext, ApiError>> {
        Box::pin(async move {
            context(
                self,
                input.operation_id().clone(),
                input.cancellation().clone(),
            )
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        FacadeErrorFactory::public_error(self, code)
    }
}

struct EchoUnary {
    operation_id: &'static str,
    correlation: RecordId,
}

impl UnaryOperationHandler for EchoUnary {
    fn operation_id(&self) -> &'static str {
        self.operation_id
    }

    fn call<'a>(
        &'a self,
        _context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        let operation = self.operation_id;
        let payload = request.payload_cbor().to_vec();
        let correlation = self.correlation.clone();
        Box::pin(async move {
            ResponseEnvelope::new(
                operation,
                payload,
                Some("\"semantic-v1\"".to_owned()),
                Some("next-v1".to_owned()),
            )
            .map_err(|_| ApiError::new(ErrorCode::Internal, correlation))
        })
    }
}

struct SpaceEvents(RecordId);

impl StreamOperationHandler for SpaceEvents {
    fn operation_id(&self) -> &'static str {
        "subscribeSpaceEvents"
    }

    fn subscribe<'a>(
        &'a self,
        _context: RequestContext,
        _request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        let correlation = self.0.clone();
        Box::pin(async move {
            let event = EventEnvelope::new("subscribeSpaceEvents", "event-1", vec![0xa0])
                .map_err(|_| ApiError::new(ErrorCode::Internal, correlation))?;
            Ok(Box::pin(OneEvent(Some(event))) as FacadeEventStream)
        })
    }
}

struct OneEvent(Option<EventEnvelope>);

impl Stream for OneEvent {
    type Item = Result<EventEnvelope, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.take().map(Ok))
    }
}

fn complete_facade() -> Result<CompleteServiceFacade, Box<dyn std::error::Error>> {
    let errors = Arc::new(Errors(RecordId::new(CORRELATION)?));
    let mut builder = CompleteServiceFacadeBuilder::new(errors);
    for operation in OPERATIONS {
        match operation.stream_kind {
            StreamKind::Unary => {
                builder.register_unary(Arc::new(EchoUnary {
                    operation_id: operation.operation_id,
                    correlation: RecordId::new(CORRELATION)?,
                }))?;
            }
            StreamKind::ServerStream => {
                builder.register_stream(Arc::new(SpaceEvents(RecordId::new(CORRELATION)?)))?;
            }
        }
    }
    Ok(builder.build()?)
}

fn context(
    errors: &Errors,
    operation: OperationId,
    cancellation: CancellationToken,
) -> Result<RequestContext, ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| errors.error(ErrorCode::Internal))?;
    let accepted = UtcTimestamp::from_unix_nanos(
        i128::try_from(now.as_nanos()).map_err(|_| errors.error(ErrorCode::Internal))?,
    )
    .map_err(|_| errors.error(ErrorCode::Internal))?;
    let deadline =
        UtcTimestamp::from_unix_nanos(accepted.unix_nanos() + i128::from(30_000_000_000_u64))
            .map_err(|_| errors.error(ErrorCode::Internal))?;
    RequestContext::new(
        AuthenticatedIdentity::from_verified_credentials(
            TenantId::new("tenant-a").map_err(|_| errors.error(ErrorCode::Internal))?,
            PrincipalId::new("principal-a").map_err(|_| errors.error(ErrorCode::Internal))?,
        ),
        operation,
        deadline,
        TraceId::new(TRACE).map_err(|_| errors.error(ErrorCode::Internal))?,
        cancellation,
        accepted,
    )
    .map_err(|_| errors.error(ErrorCode::Internal))
}

fn bindings(template: &str) -> Result<(String, Vec<PathParameter>), Box<dyn std::error::Error>> {
    let mut path = template.to_owned();
    let mut parameters = Vec::new();
    while let Some(open) = path.find('{') {
        let relative_close = path[open + 1..].find('}').ok_or("unclosed template")?;
        let close = open + 1 + relative_close;
        let name = path[open + 1..close].to_owned();
        let value = format!("{name}-v1").replace('_', "-");
        path.replace_range(open..=close, &value);
        parameters.push(PathParameter::new(name, value)?);
    }
    parameters.sort();
    Ok((path, parameters))
}

fn envelope(
    operation: &'static cigar_api::generated::OperationContract,
    parameters: Vec<PathParameter>,
) -> Result<RequestEnvelope, Box<dyn std::error::Error>> {
    Ok(RequestEnvelope::new(
        operation.operation_id,
        if operation.http_method == HttpMethod::Post {
            vec![0xa0]
        } else {
            Vec::new()
        },
        operation.mutation.then(|| "idem-v1".to_owned()),
        matches!(
            operation.revision_requirement,
            cigar_api::generated::RevisionRequirement::Required
        )
        .then(|| "revision-v1".to_owned()),
        None,
        None,
        parameters,
    )?)
}

fn http_request(
    operation: &'static cigar_api::generated::OperationContract,
    path: String,
    request: &RequestEnvelope,
) -> Result<HttpRequest<Body>, Box<dyn std::error::Error>> {
    let mut builder = HttpRequest::builder()
        .method(match operation.http_method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
        })
        .uri(path)
        .header(AUTHORIZATION, "Bearer valid");
    if let Some(key) = request.idempotency_key() {
        builder = builder.header("idempotency-key", key);
    }
    if let Some(revision) = request.expected_revision() {
        builder = builder.header(IF_MATCH, revision);
    }
    let body = if operation.http_method == HttpMethod::Post {
        builder = builder.header(CONTENT_TYPE, "application/json");
        let path_parameters: Vec<_> = request
            .path_parameters()
            .iter()
            .map(|parameter| json!({"name": parameter.name(), "value": parameter.value()}))
            .collect();
        let mut wire = json!({
            "operation_id": operation.operation_id,
            "payload_cbor": URL_SAFE_NO_PAD.encode(request.payload_cbor()),
            "path_parameters": path_parameters
        });
        if let Some(key) = request.idempotency_key() {
            wire.as_object_mut()
                .ok_or("HTTP operation fixture must be an object")?
                .insert("idempotency_key".to_owned(), json!(key));
        }
        if let Some(revision) = request.expected_revision() {
            wire.as_object_mut()
                .ok_or("HTTP operation fixture must be an object")?
                .insert("expected_revision".to_owned(), json!(revision));
        }
        Body::from(serde_json::to_vec(&wire)?)
    } else {
        Body::empty()
    };
    Ok(builder.body(body)?)
}

fn grpc_request(request: &RequestEnvelope) -> GrpcRequest<GrpcOperationRequest> {
    let mut grpc = GrpcRequest::new(GrpcOperationRequest {
        operation_id: request.operation_id().as_str().to_owned(),
        idempotency_key: request.idempotency_key().unwrap_or_default().to_owned(),
        expected_revision: request.expected_revision().unwrap_or_default().to_owned(),
        payload_cbor: request.payload_cbor().to_vec(),
        page_cursor: String::new(),
        page_size: 0,
        path_parameters: request
            .path_parameters()
            .iter()
            .map(|parameter| GrpcPath {
                name: parameter.name().to_owned(),
                value: parameter.value().to_owned(),
            })
            .collect(),
        dry_run: request.dry_run(),
    });
    grpc.metadata_mut()
        .insert("authorization", MetadataValue::from_static("Bearer valid"));
    if request.idempotency_key().is_some() {
        grpc.metadata_mut()
            .insert("idempotency-key", MetadataValue::from_static("idem-v1"));
    }
    if request.expected_revision().is_some() {
        grpc.metadata_mut()
            .insert("if-match", MetadataValue::from_static("revision-v1"));
    }
    grpc
}

#[derive(Deserialize)]
struct HttpWireResponse {
    operation_id: String,
    payload_cbor: String,
    semantic_etag: Option<String>,
    next_page_cursor: Option<String>,
}

#[tokio::test]
async fn all_44_unary_operations_are_identical_embedded_http_and_grpc()
-> Result<(), Box<dyn std::error::Error>> {
    let facade = Arc::new(complete_facade()?);
    let authority = Arc::new(Errors(RecordId::new(CORRELATION)?));
    let kernel = ServiceKernel::new(
        Arc::clone(&facade) as Arc<dyn ServiceFacade>,
        Arc::clone(&authority) as Arc<dyn RequestAuthority>,
        TransportConfig::new(Duration::from_secs(30), Duration::from_secs(30), 4)?,
    );
    let http = http_router(kernel.clone());
    let grpc = GrpcService::new(kernel);
    let mut compared = 0_usize;

    for operation in OPERATIONS
        .iter()
        .filter(|operation| operation.stream_kind == StreamKind::Unary)
    {
        let (path, parameters) = bindings(operation.http_path)?;
        let request = envelope(operation, parameters)?;
        let embedded = facade
            .call(
                context(
                    authority.as_ref(),
                    request.operation_id().clone(),
                    CancellationToken::new(),
                )?,
                request.clone(),
            )
            .await?;

        let http_response = http
            .clone()
            .oneshot(http_request(operation, path, &request)?)
            .await?;
        assert_eq!(
            http_response.status(),
            StatusCode::OK,
            "{}",
            operation.operation_id
        );
        let http_body = to_bytes(http_response.into_body(), 32 * 1024).await?;
        let http_wire: HttpWireResponse = serde_json::from_slice(&http_body)?;

        let grpc_wire = grpc
            .dispatch_unary(operation.operation_id, grpc_request(&request))
            .await?
            .into_inner();

        assert_eq!(embedded.operation_id().as_str(), operation.operation_id);
        assert_eq!(http_wire.operation_id, operation.operation_id);
        assert_eq!(grpc_wire.operation_id, operation.operation_id);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(http_wire.payload_cbor)?,
            embedded.payload_cbor()
        );
        assert_eq!(grpc_wire.payload_cbor, embedded.payload_cbor());
        assert_eq!(http_wire.semantic_etag.as_deref(), embedded.semantic_etag());
        assert_eq!(
            grpc_wire.semantic_etag,
            embedded.semantic_etag().unwrap_or_default()
        );
        assert_eq!(
            http_wire.next_page_cursor.as_deref(),
            embedded.next_page_cursor()
        );
        assert_eq!(
            grpc_wire.next_page_cursor,
            embedded.next_page_cursor().unwrap_or_default()
        );
        compared += 1;
    }
    assert_eq!(compared, 44);
    Ok(())
}

#[tokio::test]
async fn sole_stream_operation_is_identical_embedded_http_sse_and_grpc()
-> Result<(), Box<dyn std::error::Error>> {
    let operation = OPERATIONS
        .iter()
        .find(|operation| operation.stream_kind == StreamKind::ServerStream)
        .ok_or("stream contract missing")?;
    let facade = Arc::new(complete_facade()?);
    let authority = Arc::new(Errors(RecordId::new(CORRELATION)?));
    let kernel = ServiceKernel::new(
        Arc::clone(&facade) as Arc<dyn ServiceFacade>,
        Arc::clone(&authority) as Arc<dyn RequestAuthority>,
        TransportConfig::new(Duration::from_secs(30), Duration::from_secs(30), 4)?,
    );
    let http = http_router(kernel.clone());
    let grpc = GrpcService::new(kernel);
    let (path, parameters) = bindings(operation.http_path)?;
    let request = envelope(operation, parameters)?;

    let mut embedded = facade
        .subscribe(
            context(
                authority.as_ref(),
                request.operation_id().clone(),
                CancellationToken::new(),
            )?,
            request.clone(),
        )
        .await?;
    let embedded_event = poll_fn(|context| embedded.as_mut().poll_next(context))
        .await
        .ok_or("embedded event missing")??;

    let http_response = http
        .oneshot(http_request(operation, path, &request)?)
        .await?;
    assert_eq!(http_response.status(), StatusCode::OK);
    let sse = String::from_utf8(
        to_bytes(http_response.into_body(), 32 * 1024)
            .await?
            .to_vec(),
    )?;
    assert!(sse.contains("id: event-1"));
    assert!(sse.contains("\"operation_id\":\"subscribeSpaceEvents\""));
    assert!(sse.contains(&URL_SAFE_NO_PAD.encode(embedded_event.payload_cbor())));

    let mut grpc_stream = grpc
        .dispatch_stream(operation.operation_id, grpc_request(&request))
        .await?
        .into_inner();
    let grpc_event = poll_fn(|context| grpc_stream.as_mut().poll_next(context))
        .await
        .ok_or("gRPC event missing")??;
    assert_eq!(
        grpc_event.operation_id,
        embedded_event.operation_id().as_str()
    );
    assert_eq!(grpc_event.event_id, embedded_event.event_id());
    assert_eq!(grpc_event.payload_cbor, embedded_event.payload_cbor());
    Ok(())
}
