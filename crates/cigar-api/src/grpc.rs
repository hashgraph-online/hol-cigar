//! Generated Tonic gRPC binding over the transport-neutral service kernel.

use crate::generated::{OperationContract, RevisionRequirement, StreamKind};
use crate::service::{
    ContextInput, EnvelopeError, FacadeEventStream, MAX_OPERATION_PAYLOAD_BYTES, PathParameter,
    RequestEnvelope, ResponseEnvelope, ServiceKernel, TransportMetricEvent,
    TransportMetricsObserver, VerifiedClientIdentity, operation_by_id,
};
use crate::{ApiError, CancellationToken, TraceId};
use cigar_protocol::ErrorCode;
use futures_core::Stream;
use prost::Message as _;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};
use tonic::{Code, Request, Response, Status};

/// Protobuf messages, clients, and service traits generated from the frozen v1 schema.
pub mod proto {
    tonic::include_proto!("cigar.v1");
}

/// Maximum decoded gRPC message size, including bounded envelope metadata.
pub const MAX_GRPC_MESSAGE_BYTES: usize = MAX_OPERATION_PAYLOAD_BYTES + (64 * 1024);

const META_AUTHORIZATION: &str = "authorization";
const META_IDEMPOTENCY_KEY: &str = "idempotency-key";
const META_IF_MATCH: &str = "if-match";
const META_LAST_EVENT_ID: &str = "last-event-id";
const META_OPERATION_ID: &str = "x-cigar-operation-id";
const META_TIMEOUT: &str = "grpc-timeout";
const META_TRACEPARENT: &str = "traceparent";
const META_UNCOMPRESSED_LENGTH: &str = "x-cigar-uncompressed-length";
const META_COMPRESSED_LENGTH: &str = "x-cigar-compressed-length";
const META_ENCODING: &str = "grpc-encoding";
const META_ETAG: &str = "etag";
const META_NEXT_CURSOR: &str = "x-cigar-next-page-cursor";
const META_TRACE_ID: &str = "x-cigar-trace-id";

/// All seven generated gRPC services backed by one shared embedded kernel.
#[derive(Clone, Debug)]
pub struct GrpcService {
    kernel: ServiceKernel,
    maximum_message_bytes: usize,
}

impl GrpcService {
    /// Creates a gRPC adapter around the injected service kernel.
    #[must_use]
    pub const fn new(kernel: ServiceKernel) -> Self {
        Self {
            kernel,
            maximum_message_bytes: MAX_GRPC_MESSAGE_BYTES,
        }
    }

    /// Applies a deployment-specific message bound no larger than the frozen protocol maximum.
    pub fn with_max_message_bytes(
        mut self,
        maximum_message_bytes: usize,
    ) -> Result<Self, EnvelopeError> {
        if maximum_message_bytes == 0 || maximum_message_bytes > MAX_GRPC_MESSAGE_BYTES {
            return Err(EnvelopeError::InvalidArgument);
        }
        self.maximum_message_bytes = maximum_message_bytes;
        Ok(self)
    }

    /// Returns the effective deployment and protocol message bound.
    #[must_use]
    pub const fn maximum_message_bytes(&self) -> usize {
        self.maximum_message_bytes
    }

    /// Dispatches one generated unary RPC with the same semantic validation as HTTP.
    pub async fn dispatch_unary(
        &self,
        operation_id: &'static str,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        let contract = operation_by_id(operation_id)
            .filter(|contract| contract.stream_kind == StreamKind::Unary)
            .ok_or_else(|| status_from_error(self.kernel.public_error(ErrorCode::Internal)))?;
        let prepared =
            prepare_grpc_request(&self.kernel, contract, request, self.maximum_message_bytes)?;
        let context = self
            .kernel
            .resolve_context(prepared.context_input)
            .await
            .map_err(status_from_error)?;
        let trace_id = context.trace_id().as_str().to_owned();
        let response = self
            .kernel
            .call(contract, context, prepared.request)
            .await
            .map_err(status_from_error)?;
        Ok(grpc_unary_response(response, &trace_id))
    }

    /// Dispatches one generated server-streaming RPC with bounded queueing and cancellation.
    pub async fn dispatch_stream(
        &self,
        operation_id: &'static str,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<GrpcEventStream>, Status> {
        let contract = operation_by_id(operation_id)
            .filter(|contract| contract.stream_kind == StreamKind::ServerStream)
            .ok_or_else(|| status_from_error(self.kernel.public_error(ErrorCode::Internal)))?;
        let prepared =
            prepare_grpc_request(&self.kernel, contract, request, self.maximum_message_bytes)?;
        let context = self
            .kernel
            .resolve_context(prepared.context_input)
            .await
            .map_err(status_from_error)?;
        let trace_id = context.trace_id().as_str().to_owned();
        let cancellation = context.cancellation().clone();
        let source = self
            .kernel
            .subscribe(contract, context, prepared.request)
            .await
            .map_err(status_from_error)?;
        let receiver = bounded_grpc_receiver(
            source,
            cancellation,
            self.kernel.config().stream_buffer_capacity(),
            self.kernel.metrics_observer(),
        );
        let stream: GrpcEventStream = Box::pin(receiver);
        let mut response = Response::new(stream);
        insert_response_metadata(response.metadata_mut(), META_TRACE_ID, &trace_id);
        Ok(response)
    }

    /// Returns the bounded Catalog server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn catalog_server(self) -> proto::catalog_service_server::CatalogServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::catalog_service_server::CatalogServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }

    /// Returns the bounded Context server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn context_server(self) -> proto::context_service_server::ContextServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::context_service_server::ContextServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }

    /// Returns the bounded Space server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn space_server(self) -> proto::space_service_server::SpaceServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::space_service_server::SpaceServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }

    /// Returns the bounded Handoff server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn handoff_server(self) -> proto::handoff_service_server::HandoffServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::handoff_service_server::HandoffServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }

    /// Returns the bounded Effect server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn effect_server(self) -> proto::effect_service_server::EffectServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::effect_service_server::EffectServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }

    /// Returns the bounded Replay server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn replay_server(self) -> proto::replay_service_server::ReplayServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::replay_service_server::ReplayServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }

    /// Returns the bounded operational server with gzip responses and decoded-message limits.
    #[must_use]
    pub fn operations_server(
        self,
    ) -> proto::operations_service_server::OperationsServiceServer<Self> {
        let maximum = self.maximum_message_bytes;
        proto::operations_service_server::OperationsServiceServer::new(self)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(maximum)
            .max_encoding_message_size(maximum)
    }
}

struct PreparedGrpcRequest {
    context_input: ContextInput,
    request: RequestEnvelope,
}

fn prepare_grpc_request(
    kernel: &ServiceKernel,
    contract: &'static OperationContract,
    request: Request<proto::OperationRequest>,
    maximum_message_bytes: usize,
) -> Result<PreparedGrpcRequest, Status> {
    validate_unique_metadata(request.metadata())
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let verified_client_identity = request
        .extensions()
        .get::<VerifiedClientIdentity>()
        .cloned();
    let authorization = unique_metadata(request.metadata(), META_AUTHORIZATION)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(str::to_owned);
    let trace_id = unique_metadata(request.metadata(), META_TRACEPARENT)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(parse_traceparent)
        .transpose()
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let timeout = parse_grpc_timeout(request.metadata(), kernel)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let operation_header = unique_metadata(request.metadata(), META_OPERATION_ID)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    if operation_header.is_some_and(|value| value != contract.operation_id) {
        return Err(status_from_error(
            kernel.public_error(ErrorCode::InvalidArgument),
        ));
    }
    let idempotency_header = unique_metadata(request.metadata(), META_IDEMPOTENCY_KEY)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(str::to_owned);
    let revision_header = unique_metadata(request.metadata(), META_IF_MATCH)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(str::to_owned);
    let last_event_id = unique_metadata(request.metadata(), META_LAST_EVENT_ID)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(str::to_owned);
    let declared_length = unique_metadata(request.metadata(), META_UNCOMPRESSED_LENGTH)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| EnvelopeError::InvalidArgument)
        })
        .transpose()
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let compressed_length = unique_metadata(request.metadata(), META_COMPRESSED_LENGTH)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| EnvelopeError::InvalidArgument)
        })
        .transpose()
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let encoding = unique_metadata(request.metadata(), META_ENCODING)
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?
        .map(str::to_owned);

    let wire = request.into_inner();
    let expanded_message_length = wire.encoded_len();
    if wire.operation_id != contract.operation_id {
        return Err(status_from_error(
            kernel.public_error(ErrorCode::InvalidArgument),
        ));
    }
    validate_grpc_compression(
        encoding.as_deref(),
        compressed_length,
        declared_length,
        expanded_message_length,
        maximum_message_bytes,
        kernel.config(),
    )
    .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let idempotency_key = reconcile_metadata(
        idempotency_header,
        nonempty(wire.idempotency_key),
        contract.mutation,
    )
    .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let expected_revision = reconcile_metadata(
        revision_header,
        nonempty(wire.expected_revision),
        contract.revision_requirement == RevisionRequirement::Required,
    )
    .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let mut page_cursor = nonempty(wire.page_cursor);
    if contract.stream_kind == StreamKind::ServerStream {
        if let (Some(cursor), Some(event_id)) = (&page_cursor, &last_event_id)
            && cursor != event_id
        {
            return Err(status_from_error(
                kernel.public_error(ErrorCode::InvalidArgument),
            ));
        }
        if last_event_id.is_some() {
            page_cursor = last_event_id;
        }
    } else if last_event_id.is_some() {
        return Err(status_from_error(
            kernel.public_error(ErrorCode::InvalidArgument),
        ));
    }
    let page_size = (wire.page_size != 0).then_some(wire.page_size);
    let path_parameters = wire
        .path_parameters
        .into_iter()
        .map(|parameter| PathParameter::new(parameter.name, parameter.value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let normalized = RequestEnvelope::new_with_dry_run(
        wire.operation_id,
        wire.payload_cbor,
        wire.dry_run,
        idempotency_key,
        expected_revision,
        page_cursor,
        page_size,
        path_parameters,
    )
    .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    let context_input = ContextInput::new(
        contract,
        authorization,
        trace_id,
        timeout,
        CancellationToken::new(),
        verified_client_identity,
    )
    .map_err(|error| status_from_error(kernel.public_error(error.error_code())))?;
    Ok(PreparedGrpcRequest {
        context_input,
        request: normalized,
    })
}

fn grpc_unary_response(
    response: ResponseEnvelope,
    trace_id: &str,
) -> Response<proto::OperationResponse> {
    let etag = response.semantic_etag().unwrap_or_default().to_owned();
    let next_cursor = response.next_page_cursor().unwrap_or_default().to_owned();
    let message = proto::OperationResponse {
        operation_id: response.operation_id().as_str().to_owned(),
        payload_cbor: response.payload_cbor().to_vec(),
        semantic_etag: etag,
        next_page_cursor: next_cursor,
    };
    let mut output = Response::new(message);
    if let Some(etag) = response.semantic_etag() {
        insert_response_metadata(output.metadata_mut(), META_ETAG, etag);
    }
    if let Some(cursor) = response.next_page_cursor() {
        insert_response_metadata(output.metadata_mut(), META_NEXT_CURSOR, cursor);
    }
    insert_response_metadata(output.metadata_mut(), META_TRACE_ID, trace_id);
    output
}

fn insert_response_metadata(metadata: &mut MetadataMap, key: &'static str, value: &str) {
    if let Ok(value) = MetadataValue::<Ascii>::try_from(value) {
        metadata.insert(key, value);
    }
}

fn unique_metadata<'a>(
    metadata: &'a MetadataMap,
    key: &'static str,
) -> Result<Option<&'a str>, EnvelopeError> {
    let mut values = metadata.get_all(key).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(EnvelopeError::InvalidArgument);
    }
    first
        .map(|value| value.to_str().map_err(|_| EnvelopeError::InvalidArgument))
        .transpose()
}

fn validate_unique_metadata(metadata: &MetadataMap) -> Result<(), EnvelopeError> {
    for key in [
        META_AUTHORIZATION,
        META_COMPRESSED_LENGTH,
        META_ENCODING,
        META_IDEMPOTENCY_KEY,
        META_IF_MATCH,
        META_LAST_EVENT_ID,
        META_OPERATION_ID,
        META_TIMEOUT,
        META_TRACEPARENT,
        META_UNCOMPRESSED_LENGTH,
    ] {
        let _ = unique_metadata(metadata, key)?;
    }
    Ok(())
}

fn validate_grpc_compression(
    encoding: Option<&str>,
    compressed_length: Option<usize>,
    declared_length: Option<usize>,
    actual_expanded_length: usize,
    maximum_message_bytes: usize,
    config: crate::TransportConfig,
) -> Result<(), EnvelopeError> {
    let maximum_expanded = maximum_message_bytes.min(config.maximum_expanded_request_bytes());
    if actual_expanded_length > maximum_expanded {
        return Err(EnvelopeError::LimitExceeded);
    }
    if declared_length.is_some_and(|length| length > maximum_expanded) {
        return Err(EnvelopeError::LimitExceeded);
    }
    if declared_length.is_some_and(|length| length != actual_expanded_length) {
        return Err(EnvelopeError::InvalidArgument);
    }
    match encoding {
        None | Some("identity") => {
            if compressed_length.is_some() {
                return Err(EnvelopeError::InvalidArgument);
            }
        }
        // Tonic exposes the message only after decompression, so the service cannot
        // independently measure compressed bytes or enforce an expansion ratio. Do
        // not trust caller-supplied length metadata as a substitute for wire facts.
        // The generated servers therefore decline request compression entirely.
        Some(_) => return Err(EnvelopeError::InvalidArgument),
    }
    Ok(())
}

fn reconcile_metadata(
    metadata: Option<String>,
    message: Option<String>,
    required: bool,
) -> Result<Option<String>, EnvelopeError> {
    if let (Some(metadata), Some(message)) = (&metadata, &message)
        && metadata != message
    {
        return Err(EnvelopeError::InvalidArgument);
    }
    if required != message.is_some() || (!required && metadata.is_some()) {
        return Err(EnvelopeError::InvalidArgument);
    }
    Ok(message)
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn parse_grpc_timeout(
    metadata: &MetadataMap,
    kernel: &ServiceKernel,
) -> Result<Duration, EnvelopeError> {
    let Some(value) = unique_metadata(metadata, META_TIMEOUT)? else {
        return Ok(kernel.config().default_timeout());
    };
    if value.len() < 2 || value.len() > 9 {
        return Err(EnvelopeError::InvalidArgument);
    }
    let Some((digits, unit)) = value.split_at_checked(value.len() - 1) else {
        return Err(EnvelopeError::InvalidArgument);
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|_| EnvelopeError::InvalidArgument)?;
    if amount == 0 {
        return Err(EnvelopeError::InvalidArgument);
    }
    let timeout = match unit {
        "H" => Duration::from_secs(
            amount
                .checked_mul(3600)
                .ok_or(EnvelopeError::LimitExceeded)?,
        ),
        "M" => Duration::from_secs(amount.checked_mul(60).ok_or(EnvelopeError::LimitExceeded)?),
        "S" => Duration::from_secs(amount),
        "m" => Duration::from_millis(amount),
        "u" => Duration::from_micros(amount),
        "n" => Duration::from_nanos(amount),
        _ => return Err(EnvelopeError::InvalidArgument),
    };
    Ok(timeout.min(kernel.config().maximum_timeout()))
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

fn status_from_error(error: ApiError) -> Status {
    let code = grpc_code(error.code());
    let message = error.code().definition().message;
    let (_, details) = crate::service::problem_json(error);
    Status::with_details(code, message, details.into())
}

fn grpc_code(code: ErrorCode) -> Code {
    match code.grpc_status() {
        "INVALID_ARGUMENT" => Code::InvalidArgument,
        "RESOURCE_EXHAUSTED" => Code::ResourceExhausted,
        "UNAUTHENTICATED" => Code::Unauthenticated,
        "PERMISSION_DENIED" => Code::PermissionDenied,
        "UNAVAILABLE" => Code::Unavailable,
        "FAILED_PRECONDITION" => Code::FailedPrecondition,
        "ABORTED" => Code::Aborted,
        "DEADLINE_EXCEEDED" => Code::DeadlineExceeded,
        "INTERNAL" => Code::Internal,
        _ => Code::Unknown,
    }
}

/// Boxed Tonic server-event stream used by the generated Space service.
pub type GrpcEventStream =
    Pin<Box<dyn Stream<Item = Result<proto::OperationEvent, Status>> + Send + 'static>>;

struct GrpcReceiverStream {
    receiver: mpsc::Receiver<Result<proto::OperationEvent, Status>>,
    cancellation: CancellationToken,
    metrics: Option<std::sync::Arc<dyn TransportMetricsObserver>>,
}

impl Stream for GrpcReceiverStream {
    type Item = Result<proto::OperationEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Drop for GrpcReceiverStream {
    fn drop(&mut self) {
        if !self.cancellation.is_cancelled()
            && let Some(metrics) = &self.metrics
        {
            metrics.record_transport_metric(TransportMetricEvent::StreamCancelled);
        }
        self.cancellation.cancel();
    }
}

fn bounded_grpc_receiver(
    mut source: FacadeEventStream,
    cancellation: CancellationToken,
    capacity: usize,
    metrics: Option<std::sync::Arc<dyn TransportMetricsObserver>>,
) -> GrpcReceiverStream {
    let (sender, receiver) = mpsc::channel(capacity);
    let producer_cancellation = cancellation.clone();
    let producer_metrics = metrics.clone();
    tokio::spawn(async move {
        loop {
            let item = poll_fn(|context| source.as_mut().poll_next(context)).await;
            let Some(item) = item else {
                break;
            };
            let item = item.map(|event| proto::OperationEvent {
                operation_id: event.operation_id().as_str().to_owned(),
                event_id: event.event_id().to_owned(),
                payload_cbor: event.payload_cbor().to_vec(),
            });
            let item = item.map_err(status_from_error);
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
    GrpcReceiverStream {
        receiver,
        cancellation,
        metrics,
    }
}

macro_rules! unary_service_impl {
    ($trait:path; $(($method:ident, $operation:literal)),+ $(,)?) => {
        #[tonic::async_trait]
        impl $trait for GrpcService {
            $(
                async fn $method(
                    &self,
                    request: Request<proto::OperationRequest>,
                ) -> Result<Response<proto::OperationResponse>, Status> {
                    self.dispatch_unary($operation, request).await
                }
            )+
        }
    };
}

unary_service_impl!(proto::catalog_service_server::CatalogService;
    (discover_sources, "discoverSources"),
    (ingest_catalog, "ingestCatalog"),
    (get_source_status, "getSourceStatus"),
    (query_catalog, "queryCatalog"),
    (batch_atoms, "batchAtoms"),
    (tombstone_atom, "tombstoneAtom"),
);

unary_service_impl!(proto::context_service_server::ContextService;
    (create_context_plan, "createContextPlan"),
    (compile_context_bundle, "compileContextBundle"),
    (compile_context_delta, "compileContextDelta"),
    (get_context_bundle, "getContextBundle"),
    (get_context_bundle_manifest, "getContextBundleManifest"),
    (explain_context_bundle, "explainContextBundle"),
    (materialize_context_bundle, "materializeContextBundle"),
    (revalidate_context_bundle, "revalidateContextBundle"),
);

#[tonic::async_trait]
impl proto::space_service_server::SpaceService for GrpcService {
    type SubscribeSpaceEventsStream = GrpcEventStream;

    async fn create_space(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("createSpace", request).await
    }

    async fn fork_space(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("forkSpace", request).await
    }

    async fn publish_space(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("publishSpace", request).await
    }

    async fn get_space_log(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("getSpaceLog", request).await
    }

    async fn subscribe_space_events(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<Self::SubscribeSpaceEventsStream>, Status> {
        self.dispatch_stream("subscribeSpaceEvents", request).await
    }

    async fn create_space_checkpoint(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("createSpaceCheckpoint", request).await
    }

    async fn list_space_conflicts(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("listSpaceConflicts", request).await
    }

    async fn resolve_space_conflict(
        &self,
        request: Request<proto::OperationRequest>,
    ) -> Result<Response<proto::OperationResponse>, Status> {
        self.dispatch_unary("resolveSpaceConflict", request).await
    }
}

unary_service_impl!(proto::handoff_service_server::HandoffService;
    (create_handoff, "createHandoff"),
    (preview_handoff, "previewHandoff"),
    (accept_handoff, "acceptHandoff"),
    (revoke_handoff, "revokeHandoff"),
    (record_handoff_result, "recordHandoffResult"),
    (merge_handoff, "mergeHandoff"),
);

unary_service_impl!(proto::effect_service_server::EffectService;
    (prepare_effect, "prepareEffect"),
    (authorize_effect, "authorizeEffect"),
    (dispatch_effect, "dispatchEffect"),
    (get_effect_status, "getEffectStatus"),
    (reconcile_effect, "reconcileEffect"),
    (compensate_effect, "compensateEffect"),
);

unary_service_impl!(proto::replay_service_server::ReplayService;
    (create_replay, "createReplay"),
    (run_observational_replay, "runObservationalReplay"),
    (compare_live_replay, "compareLiveReplay"),
    (get_replay_completeness, "getReplayCompleteness"),
);

unary_service_impl!(proto::operations_service_server::OperationsService;
    (get_liveness, "getLiveness"),
    (get_readiness, "getReadiness"),
    (get_version, "getVersion"),
    (get_capabilities, "getCapabilities"),
    (get_configuration, "getConfiguration"),
    (get_diagnostics, "getDiagnostics"),
    (get_metrics, "getMetrics"),
);

#[cfg(test)]
mod tests {
    use super::{GrpcService, grpc_code, parse_grpc_timeout, proto};
    use crate::service::ServiceKernel;
    use cigar_protocol::ErrorCode;
    use tonic::Request;
    use tonic::metadata::MetadataValue;

    #[test]
    fn every_public_error_has_a_known_grpc_mapping() {
        for code in [
            ErrorCode::InvalidArgument,
            ErrorCode::LimitExceeded,
            ErrorCode::UnknownPrincipal,
            ErrorCode::PolicyDenied,
            ErrorCode::SourceUnavailable,
            ErrorCode::RevisionConflict,
            ErrorCode::DeadlineExceeded,
            ErrorCode::Internal,
        ] {
            assert_ne!(grpc_code(code), tonic::Code::Unknown);
        }
    }

    #[test]
    fn generated_request_type_retains_exact_binary_payload() {
        let request = proto::OperationRequest {
            operation_id: "queryCatalog".to_owned(),
            idempotency_key: "request-1".to_owned(),
            expected_revision: String::new(),
            payload_cbor: vec![0, 1, 2, 255],
            page_cursor: "cursor".to_owned(),
            page_size: 10,
            path_parameters: Vec::new(),
            dry_run: false,
        };
        assert_eq!(request.payload_cbor, [0, 1, 2, 255]);
    }

    // Signature-level assertion: callers can construct all generated bounded server wrappers.
    fn _server_constructors(service: GrpcService) {
        let _ = service.clone().catalog_server();
        let _ = service.clone().context_server();
        let _ = service.clone().space_server();
        let _ = service.clone().handoff_server();
        let _ = service.clone().effect_server();
        let _ = service.clone().replay_server();
        let _ = service.operations_server();
    }

    // Keep imported transport types exercised without a network-only test.
    fn _metadata_shape(kernel: &ServiceKernel) {
        let mut request = Request::new(proto::OperationRequest::default());
        request
            .metadata_mut()
            .insert("grpc-timeout", MetadataValue::from_static("25m"));
        assert!(parse_grpc_timeout(request.metadata(), kernel).is_ok());
    }
}
