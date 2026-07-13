//! Parallel typed client shared by embedded and remote transports.

use crate::verify::verify_typed_response;
use crate::{
    CallOptions, ClientTransport, ErrorKind, SdkError, TransportCall, TransportEventStream,
};
use cigar_api::generated::{
    IdempotencyRequirement, OperationContract, RevisionRequirement, StreamKind,
};
use cigar_api::{
    EventEnvelope, OperationPayload, TypedOperation, TypedPayloadError, decode_operation_payload,
    encode_operation_payload, typed_operation_contract,
};
use cigar_protocol::{PageCursor, RetryClass};
use futures_core::Stream;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// Number of frozen typed operations exposed by this SDK.
pub const RUST_OPERATION_COUNT: usize = 45;

/// Exact operation inventory used by cross-language capability generation.
pub const RUST_OPERATION_IDS: [&str; RUST_OPERATION_COUNT] = [
    "discoverSources",
    "ingestCatalog",
    "getSourceStatus",
    "queryCatalog",
    "batchAtoms",
    "tombstoneAtom",
    "createContextPlan",
    "compileContextBundle",
    "compileContextDelta",
    "getContextBundle",
    "getContextBundleManifest",
    "explainContextBundle",
    "materializeContextBundle",
    "revalidateContextBundle",
    "createSpace",
    "forkSpace",
    "publishSpace",
    "getSpaceLog",
    "subscribeSpaceEvents",
    "createSpaceCheckpoint",
    "listSpaceConflicts",
    "resolveSpaceConflict",
    "createHandoff",
    "previewHandoff",
    "acceptHandoff",
    "revokeHandoff",
    "recordHandoffResult",
    "mergeHandoff",
    "prepareEffect",
    "authorizeEffect",
    "dispatchEffect",
    "getEffectStatus",
    "reconcileEffect",
    "compensateEffect",
    "createReplay",
    "runObservationalReplay",
    "compareLiveReplay",
    "getReplayCompleteness",
    "getLiveness",
    "getReadiness",
    "getVersion",
    "getCapabilities",
    "getConfiguration",
    "getDiagnostics",
    "getMetrics",
];

/// One typed response plus immutable pagination and semantic-cache metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    /// Operation-specific response payload.
    pub value: T,
    /// Strong server semantic ETag, when available.
    pub semantic_etag: Option<String>,
    /// Opaque protocol-native continuation cursor, when another page exists.
    pub next_cursor: Option<PageCursor>,
}

/// One typed resumable stream event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEvent<T> {
    /// Stable event identity accepted as a resume cursor.
    pub event_id: String,
    /// Operation-specific event payload.
    pub payload: T,
}

impl<T> StreamEvent<T> {
    /// Returns a validated token that resumes after this exact event.
    pub fn resume_token(&self) -> Result<crate::StreamResumeToken, SdkError> {
        crate::StreamResumeToken::new(self.event_id.clone())
    }
}

/// Boxed typed stream returned by high-level stream operations.
pub type SdkEventStream<T> =
    Pin<Box<dyn Stream<Item = Result<StreamEvent<T>, SdkError>> + Send + 'static>>;

type PageFuture<O> =
    Pin<Box<dyn Future<Output = Result<Page<<O as TypedOperation>::Response>, SdkError>> + Send>>;

/// Lazy typed paginator that follows only server-issued opaque cursors.
pub struct PageStream<O>
where
    O: TypedOperation,
    O::Request: Clone,
{
    client: Client,
    request: O::Request,
    options: CallOptions,
    in_flight: Option<PageFuture<O>>,
    finished: bool,
}

impl<O> fmt::Debug for PageStream<O>
where
    O: TypedOperation,
    O::Request: Clone,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageStream")
            .field("operation_id", &O::OPERATION_ID)
            .field("in_flight", &self.in_flight.is_some())
            .field("finished", &self.finished)
            .finish()
    }
}

impl<O> Unpin for PageStream<O>
where
    O: TypedOperation,
    O::Request: Clone,
{
}

impl<O> Stream for PageStream<O>
where
    O: TypedOperation,
    O::Request: Clone,
{
    type Item = Result<Page<O::Response>, SdkError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if self.in_flight.is_none() {
            let client = self.client.clone();
            let request = self.request.clone();
            let options = self.options.clone();
            self.in_flight = Some(Box::pin(
                async move { client.call::<O>(request, options).await },
            ));
        }
        let Some(future) = self.in_flight.as_mut() else {
            self.finished = true;
            return Poll::Ready(Some(Err(protocol_error())));
        };
        match future.as_mut().poll(context) {
            Poll::Ready(Ok(page)) => {
                self.in_flight = None;
                if let Some(cursor) = &page.next_cursor {
                    use base64::Engine as _;
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    self.options.page_cursor = Some(URL_SAFE_NO_PAD.encode(cursor.as_bytes()));
                } else {
                    self.finished = true;
                }
                Poll::Ready(Some(Ok(page)))
            }
            Poll::Ready(Err(error)) => {
                self.in_flight = None;
                self.finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Cloneable high-level client with identical embedded and remote semantics.
#[derive(Clone)]
pub struct Client {
    transport: Arc<dyn ClientTransport>,
}

impl Client {
    /// Creates a client around an extension-provided object-safe transport.
    #[must_use]
    pub fn from_transport(transport: Arc<dyn ClientTransport>) -> Self {
        Self { transport }
    }

    /// Creates a lazy typed paginator from options containing an explicit page size.
    pub fn paginate<O>(
        &self,
        request: O::Request,
        options: CallOptions,
    ) -> Result<PageStream<O>, SdkError>
    where
        O: TypedOperation,
        O::Request: Clone,
    {
        let contract = typed_operation_contract::<O>().ok_or_else(protocol_error)?;
        if contract.stream_kind != StreamKind::Unary
            || options.page_size.is_none()
            || options.stream_resume
        {
            return Err(SdkError::local(
                ErrorKind::InvalidConfiguration,
                RetryClass::Never,
                "paginator requires a unary operation and explicit page size",
            ));
        }
        Ok(PageStream {
            client: self.clone(),
            request,
            options,
            in_flight: None,
            finished: false,
        })
    }

    /// Executes any frozen unary marker with canonical typed payload conversion.
    pub async fn call<O>(
        &self,
        request: O::Request,
        options: CallOptions,
    ) -> Result<Page<O::Response>, SdkError>
    where
        O: TypedOperation,
    {
        let contract = typed_operation_contract::<O>().ok_or_else(protocol_error)?;
        if contract.stream_kind != StreamKind::Unary {
            return Err(SdkError::local(
                ErrorKind::InvalidArgument,
                RetryClass::Never,
                "streaming operation requires subscribe",
            ));
        }
        if options.stream_resume {
            return Err(SdkError::local(
                ErrorKind::InvalidConfiguration,
                RetryClass::Never,
                "stream resume token cannot be used for a unary operation",
            ));
        }
        let deadline = Instant::now()
            .checked_add(options.timeout)
            .ok_or_else(deadline_error)?;
        let envelope = request_envelope::<O>(&request, &options)?;
        let retry = options.retry;
        let cancellation = options.cancellation.clone();
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            let call =
                TransportCall::new(contract, envelope.clone(), deadline, cancellation.clone());
            let result = self.transport.unary(call).await;
            match result {
                Ok(response) => {
                    if response.operation_id().as_str() != O::OPERATION_ID {
                        return Err(protocol_error());
                    }
                    let value = decode_operation_payload::<O::Response>(
                        response.payload_cbor(),
                        cigar_api::MAX_OPERATION_PAYLOAD_BYTES,
                    )
                    .map_err(payload_error)?;
                    verify_typed_response::<O>(&value)?;
                    let next_cursor = response.next_page_cursor().map(decode_cursor).transpose()?;
                    return Ok(Page {
                        value,
                        semantic_etag: response.semantic_etag().map(str::to_owned),
                        next_cursor,
                    });
                }
                Err(error)
                    if attempt < retry.maximum_attempts()
                        && retry_allowed(contract, &envelope, &error) =>
                {
                    wait_for_retry(retry.backoff(attempt), deadline, cancellation.clone()).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Opens any frozen server-stream marker with canonical event decoding.
    pub async fn subscribe<O>(
        &self,
        request: O::Request,
        options: CallOptions,
    ) -> Result<SdkEventStream<O::Event>, SdkError>
    where
        O: TypedOperation,
    {
        let contract = typed_operation_contract::<O>().ok_or_else(protocol_error)?;
        if contract.stream_kind != StreamKind::ServerStream {
            return Err(SdkError::local(
                ErrorKind::InvalidArgument,
                RetryClass::Never,
                "unary operation requires call",
            ));
        }
        if options.page_cursor.is_some() && !options.stream_resume {
            return Err(SdkError::local(
                ErrorKind::InvalidConfiguration,
                RetryClass::Never,
                "stream resume requires an exact stream resume token",
            ));
        }
        let deadline = Instant::now()
            .checked_add(options.timeout)
            .ok_or_else(deadline_error)?;
        let envelope = request_envelope::<O>(&request, &options)?;
        let cancellation = options.cancellation.clone();
        let source = self
            .transport
            .subscribe(TransportCall::new(
                contract,
                envelope,
                deadline,
                cancellation.clone(),
            ))
            .await?;
        Ok(Box::pin(DecodedEventStream::<O> {
            source,
            ended: false,
            cancellation,
            operation: std::marker::PhantomData,
        }))
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Client { transport: [REDACTED] }")
    }
}

macro_rules! unary_methods {
    ($(($method:ident, $marker:ty, $operation:literal)),+ $(,)?) => {
        impl Client {
            $(
                #[doc = concat!("Executes the frozen `", $operation, "` operation.")]
                pub async fn $method(
                    &self,
                    request: <$marker as TypedOperation>::Request,
                    options: CallOptions,
                ) -> Result<Page<<$marker as TypedOperation>::Response>, SdkError> {
                    self.call::<$marker>(request, options).await
                }
            )+
        }
    };
}

unary_methods! {
    (discover_sources, cigar_api::DiscoverSourcesOperation, "discoverSources"),
    (ingest_catalog, cigar_api::IngestCatalogOperation, "ingestCatalog"),
    (get_source_status, cigar_api::GetSourceStatusOperation, "getSourceStatus"),
    (query_catalog, cigar_api::QueryCatalogOperation, "queryCatalog"),
    (batch_atoms, cigar_api::BatchAtomsOperation, "batchAtoms"),
    (tombstone_atom, cigar_api::TombstoneAtomOperation, "tombstoneAtom"),
    (create_context_plan, cigar_api::CreateContextPlanOperation, "createContextPlan"),
    (compile_context_bundle, cigar_api::CompileContextBundleOperation, "compileContextBundle"),
    (compile_context_delta, cigar_api::CompileContextDeltaOperation, "compileContextDelta"),
    (get_context_bundle, cigar_api::GetContextBundleOperation, "getContextBundle"),
    (get_context_bundle_manifest, cigar_api::GetContextBundleManifestOperation, "getContextBundleManifest"),
    (explain_context_bundle, cigar_api::ExplainContextBundleOperation, "explainContextBundle"),
    (materialize_context_bundle, cigar_api::MaterializeContextBundleOperation, "materializeContextBundle"),
    (revalidate_context_bundle, cigar_api::RevalidateContextBundleOperation, "revalidateContextBundle"),
    (create_space, cigar_api::CreateSpaceOperation, "createSpace"),
    (fork_space, cigar_api::ForkSpaceOperation, "forkSpace"),
    (publish_space, cigar_api::PublishSpaceOperation, "publishSpace"),
    (get_space_log, cigar_api::GetSpaceLogOperation, "getSpaceLog"),
    (create_space_checkpoint, cigar_api::CreateSpaceCheckpointOperation, "createSpaceCheckpoint"),
    (list_space_conflicts, cigar_api::ListSpaceConflictsOperation, "listSpaceConflicts"),
    (resolve_space_conflict, cigar_api::ResolveSpaceConflictOperation, "resolveSpaceConflict"),
    (create_handoff, cigar_api::CreateHandoffOperation, "createHandoff"),
    (preview_handoff, cigar_api::PreviewHandoffOperation, "previewHandoff"),
    (accept_handoff, cigar_api::AcceptHandoffOperation, "acceptHandoff"),
    (revoke_handoff, cigar_api::RevokeHandoffOperation, "revokeHandoff"),
    (record_handoff_result, cigar_api::RecordHandoffResultOperation, "recordHandoffResult"),
    (merge_handoff, cigar_api::MergeHandoffOperation, "mergeHandoff"),
    (prepare_effect, cigar_api::PrepareEffectOperation, "prepareEffect"),
    (authorize_effect, cigar_api::AuthorizeEffectOperation, "authorizeEffect"),
    (dispatch_effect, cigar_api::DispatchEffectOperation, "dispatchEffect"),
    (get_effect_status, cigar_api::GetEffectStatusOperation, "getEffectStatus"),
    (reconcile_effect, cigar_api::ReconcileEffectOperation, "reconcileEffect"),
    (compensate_effect, cigar_api::CompensateEffectOperation, "compensateEffect"),
    (create_replay, cigar_api::CreateReplayOperation, "createReplay"),
    (run_observational_replay, cigar_api::RunObservationalReplayOperation, "runObservationalReplay"),
    (compare_live_replay, cigar_api::CompareLiveReplayOperation, "compareLiveReplay"),
    (get_replay_completeness, cigar_api::GetReplayCompletenessOperation, "getReplayCompleteness"),
    (get_liveness, cigar_api::GetLivenessOperation, "getLiveness"),
    (get_readiness, cigar_api::GetReadinessOperation, "getReadiness"),
    (get_version, cigar_api::GetVersionOperation, "getVersion"),
    (get_capabilities, cigar_api::GetCapabilitiesOperation, "getCapabilities"),
    (get_configuration, cigar_api::GetConfigurationOperation, "getConfiguration"),
    (get_diagnostics, cigar_api::GetDiagnosticsOperation, "getDiagnostics"),
    (get_metrics, cigar_api::GetMetricsOperation, "getMetrics"),
}

impl Client {
    /// Opens the frozen resumable context-space event stream.
    pub async fn subscribe_space_events(
        &self,
        request: cigar_api::SpaceIdRequest,
        options: CallOptions,
    ) -> Result<SdkEventStream<cigar_api::SpaceEventPayload>, SdkError> {
        self.subscribe::<cigar_api::SubscribeSpaceEventsOperation>(request, options)
            .await
    }
}

fn request_envelope<O: TypedOperation>(
    request: &O::Request,
    options: &CallOptions,
) -> Result<cigar_api::RequestEnvelope, SdkError> {
    let contract = typed_operation_contract::<O>().ok_or_else(protocol_error)?;
    let needs_key = contract.idempotency_requirement == IdempotencyRequirement::Required;
    let needs_revision = contract.revision_requirement == RevisionRequirement::Required;
    if needs_key != options.idempotency_key.is_some()
        || needs_revision != options.expected_revision.is_some()
        || options
            .expected_revision
            .is_some_and(|revision| revision.0 == 0)
    {
        return Err(SdkError::local(
            ErrorKind::InvalidConfiguration,
            RetryClass::Never,
            "operation metadata does not satisfy the frozen contract",
        ));
    }
    let payload = encode_operation_payload(request, cigar_api::MAX_OPERATION_PAYLOAD_BYTES)
        .map_err(payload_error)?;
    let mut path_parameters = request
        .path_bindings()
        .into_iter()
        .map(|(name, value)| cigar_api::PathParameter::new(name, value).map_err(envelope_error))
        .collect::<Result<Vec<_>, _>>()?;
    path_parameters.sort_unstable_by(|left, right| left.name().cmp(right.name()));
    cigar_api::RequestEnvelope::new_with_dry_run(
        O::OPERATION_ID,
        payload,
        options.dry_run,
        options
            .idempotency_key
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        options.expected_revision.map(|value| value.0.to_string()),
        options.page_cursor.clone(),
        options.page_size,
        path_parameters,
    )
    .map_err(envelope_error)
}

fn retry_allowed(
    contract: &'static OperationContract,
    envelope: &cigar_api::RequestEnvelope,
    error: &SdkError,
) -> bool {
    if contract.operation_id == cigar_api::DispatchEffectOperation::OPERATION_ID {
        return false;
    }
    let repeat_safe = !contract.mutation || envelope.idempotency_key().is_some();
    repeat_safe
        && (error.is_transport_failure()
            || matches!(
                error.retry_class(),
                RetryClass::Safe | RetryClass::AfterBackoff
            ))
}

async fn wait_for_retry(
    duration: std::time::Duration,
    deadline: Instant,
    cancellation: crate::CancellationToken,
) -> Result<(), SdkError> {
    let wake = Instant::now()
        .checked_add(duration)
        .map(|instant| instant.min(deadline))
        .ok_or_else(deadline_error)?;
    if wake >= deadline {
        return Err(deadline_error());
    }
    tokio::select! {
        () = cancellation.cancelled() => Err(cancelled_error()),
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => Ok(()),
    }
}

fn decode_cursor(encoded: &str) -> Result<PageCursor, SdkError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_failure| protocol_error())?;
    let cursor = PageCursor::new(bytes).map_err(|_failure| protocol_error())?;
    let canonical = URL_SAFE_NO_PAD.encode(cursor.as_bytes());
    if canonical != encoded {
        return Err(protocol_error());
    }
    Ok(cursor)
}

struct DecodedEventStream<O: TypedOperation> {
    source: TransportEventStream,
    ended: bool,
    cancellation: crate::CancellationToken,
    operation: std::marker::PhantomData<O>,
}

impl<O: TypedOperation> Unpin for DecodedEventStream<O> {}

impl<O: TypedOperation> Drop for DecodedEventStream<O> {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl<O: TypedOperation> Stream for DecodedEventStream<O> {
    type Item = Result<StreamEvent<O::Event>, SdkError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        match this.source.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(event))) => {
                let decoded = decode_event::<O>(&event);
                if decoded.is_err() {
                    this.ended = true;
                }
                Poll::Ready(Some(decoded))
            }
            Poll::Ready(Some(Err(error))) => {
                this.ended = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn decode_event<O: TypedOperation>(
    event: &EventEnvelope,
) -> Result<StreamEvent<O::Event>, SdkError> {
    if event.operation_id().as_str() != O::OPERATION_ID {
        return Err(protocol_error());
    }
    let payload = decode_operation_payload::<O::Event>(
        event.payload_cbor(),
        cigar_api::MAX_EVENT_PAYLOAD_BYTES,
    )
    .map_err(payload_error)?;
    Ok(StreamEvent {
        event_id: event.event_id().to_owned(),
        payload,
    })
}

fn payload_error(_failure: TypedPayloadError) -> SdkError {
    SdkError::local(
        ErrorKind::Protocol,
        RetryClass::Never,
        "typed payload failed frozen canonical validation",
    )
}

fn envelope_error(_failure: cigar_api::EnvelopeError) -> SdkError {
    SdkError::local(
        ErrorKind::InvalidArgument,
        RetryClass::Never,
        "request envelope failed frozen validation",
    )
}

pub(crate) const fn protocol_error() -> SdkError {
    SdkError::local(
        ErrorKind::Protocol,
        RetryClass::Never,
        "peer response disagrees with the frozen protocol",
    )
}

pub(crate) const fn cancelled_error() -> SdkError {
    SdkError::local(
        ErrorKind::Cancelled,
        RetryClass::Never,
        "operation was cancelled",
    )
}

pub(crate) const fn deadline_error() -> SdkError {
    SdkError::local(
        ErrorKind::DeadlineExceeded,
        RetryClass::Never,
        "operation deadline elapsed",
    )
}
