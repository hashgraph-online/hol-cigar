//! Quota and durable-idempotency governance for the transport-neutral service facade.
//!
//! This decorator authenticates no callers and interprets no domain cursors. Authentication is
//! completed before the facade is called, while scope-bound cursor verification remains the
//! responsibility of the domain handler that owns each cursor format and snapshot contract.

use cigar_api::generated::{StreamKind, operation_by_id};
use cigar_api::{
    ApiError, ExactResponse, FacadeEventStream, IdempotencyBinding, IdempotencyError,
    IdempotencyPermit, IdempotencyRepository, IdempotencyReservation, QuotaLease, QuotaManager,
    RequestContext, RequestEnvelope, ResponseEnvelope, ServiceFacade, ServiceFuture,
};
use cigar_canon::from_deterministic_cbor;
use cigar_crypto::MonotonicUuidV7Generator;
use cigar_protocol::{ContentDigest, ErrorCode, IdempotencyKey, RecordId};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_stream::Stream;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"cigar.api.normalized-request.v1\0";
const RESPONSE_MAGIC: &[u8; 8] = b"CGRRSP\0\x01";
const MAX_IDEMPOTENCY_WAIT: Duration = Duration::from_secs(120);

/// Invalid governed-facade configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedFacadeError {
    /// The pending-reservation wait must be positive and bounded.
    InvalidWaitBound,
    /// A valid last-resort correlation identity could not be initialized.
    CorrelationUnavailable,
}

impl fmt::Display for GovernedFacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWaitBound => formatter
                .write_str("idempotency wait must be positive and no more than 120 seconds"),
            Self::CorrelationUnavailable => {
                formatter.write_str("correlation identity initialization failed")
            }
        }
    }
}

impl std::error::Error for GovernedFacadeError {}

/// Explicit proof that a failed mutation dispatch performed no durable write or external effect.
///
/// Only a trusted mutation executor that rejects before dispatch, or that has transactionally
/// established rollback, should construct this proof. Ordinary [`ServiceFacade`] errors are
/// deliberately treated as indeterminate because they may have occurred after publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoMutationProof {
    private: (),
}

impl NoMutationProof {
    /// Attests that a trusted executor rejected the request before any mutation was dispatched.
    #[must_use]
    pub const fn rejected_before_dispatch() -> Self {
        Self { private: () }
    }
}

/// Safety-classified result of executing one mutation.
pub enum MutationExecution {
    /// The delegate returned a response after mutation execution.
    Applied(ResponseEnvelope),
    /// The trusted executor proved that it made no durable mutation or external effect.
    ProvenNoMutation {
        /// Content-safe error returned to the caller after reservation abandonment succeeds.
        error: ApiError,
        /// Explicit safety proof; its presence prevents accidental abandonment on ordinary errors.
        proof: NoMutationProof,
    },
    /// Execution failed at an unknown point and therefore must retain its reservation.
    Indeterminate(ApiError),
}

impl fmt::Debug for MutationExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied(response) => formatter.debug_tuple("Applied").field(response).finish(),
            Self::ProvenNoMutation { error, proof } => formatter
                .debug_struct("ProvenNoMutation")
                .field("error", error)
                .field("proof", proof)
                .finish(),
            Self::Indeterminate(error) => {
                formatter.debug_tuple("Indeterminate").field(error).finish()
            }
        }
    }
}

/// Trusted dispatch boundary that can provide an explicit no-mutation proof.
pub trait MutationExecutor: Send + Sync {
    /// Executes one generated mutation through the injected domain facade.
    fn execute<'a>(
        &'a self,
        delegate: &'a dyn ServiceFacade,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, MutationExecution>;
}

/// Default executor that conservatively classifies every delegate error as indeterminate.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConservativeMutationExecutor;

impl MutationExecutor for ConservativeMutationExecutor {
    fn execute<'a>(
        &'a self,
        delegate: &'a dyn ServiceFacade,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, MutationExecution> {
        Box::pin(async move {
            match delegate.call(context, request).await {
                Ok(response) => MutationExecution::Applied(response),
                Err(error) => MutationExecution::Indeterminate(error),
            }
        })
    }
}

/// Service facade decorator enforcing concurrency quotas and durable mutation idempotency.
pub struct GovernedFacade {
    delegate: Arc<dyn ServiceFacade>,
    idempotency: Arc<dyn IdempotencyRepository>,
    quotas: QuotaManager,
    maximum_wait: Duration,
    mutation_executor: Arc<dyn MutationExecutor>,
    correlations: FreshCorrelationIds,
}

impl GovernedFacade {
    /// Creates a facade with conservative mutation-error handling.
    pub fn new(
        delegate: Arc<dyn ServiceFacade>,
        idempotency: Arc<dyn IdempotencyRepository>,
        quotas: QuotaManager,
        maximum_wait: Duration,
    ) -> Result<Self, GovernedFacadeError> {
        Self::with_mutation_executor(
            delegate,
            idempotency,
            quotas,
            maximum_wait,
            Arc::new(ConservativeMutationExecutor),
        )
    }

    /// Creates a facade with a trusted proof-bearing mutation execution boundary.
    pub fn with_mutation_executor(
        delegate: Arc<dyn ServiceFacade>,
        idempotency: Arc<dyn IdempotencyRepository>,
        quotas: QuotaManager,
        maximum_wait: Duration,
        mutation_executor: Arc<dyn MutationExecutor>,
    ) -> Result<Self, GovernedFacadeError> {
        if maximum_wait.is_zero() || maximum_wait > MAX_IDEMPOTENCY_WAIT {
            return Err(GovernedFacadeError::InvalidWaitBound);
        }
        Ok(Self {
            delegate,
            idempotency,
            quotas,
            maximum_wait,
            mutation_executor,
            correlations: FreshCorrelationIds::new()?,
        })
    }

    /// Returns content-safe quota accounting for diagnostics and leak verification.
    #[must_use]
    pub fn quota_snapshot(&self) -> cigar_api::QuotaSnapshot {
        self.quotas.snapshot()
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        ApiError::new(code, self.correlations.next())
    }

    fn idempotency_error(&self, error: IdempotencyError) -> ApiError {
        let code = match error {
            IdempotencyError::RequestCollision => ErrorCode::RevisionConflict,
            IdempotencyError::WaitTimedOut => ErrorCode::DeadlineExceeded,
            IdempotencyError::ResponseTooLarge => ErrorCode::LimitExceeded,
            IdempotencyError::TokenExhausted => ErrorCode::RateLimited,
            IdempotencyError::Unavailable => ErrorCode::DependencyUnavailable,
            IdempotencyError::InvalidPermit | IdempotencyError::ReservationNotFound => {
                ErrorCode::Internal
            }
        };
        self.public_error(code)
    }

    fn acquire(&self, context: &RequestContext) -> Result<QuotaLease, ApiError> {
        self.quotas
            .acquire(context.identity().tenant())
            .map_err(|_error| self.public_error(ErrorCode::RateLimited))
    }

    async fn reserve(
        &self,
        binding: IdempotencyBinding,
    ) -> Result<IdempotencyReservation, ApiError> {
        let repository = Arc::clone(&self.idempotency);
        tokio::task::spawn_blocking(move || repository.reserve(&binding))
            .await
            .map_err(|_error| self.public_error(ErrorCode::Internal))?
            .map_err(|error| self.idempotency_error(error))
    }

    async fn wait_for_completion(
        &self,
        binding: IdempotencyBinding,
    ) -> Result<ExactResponse, ApiError> {
        let repository = Arc::clone(&self.idempotency);
        let maximum_wait = self.maximum_wait;
        tokio::task::spawn_blocking(move || repository.wait_for_completion(&binding, maximum_wait))
            .await
            .map_err(|_error| self.public_error(ErrorCode::Internal))?
            .map_err(|error| self.idempotency_error(error))
    }

    async fn complete(
        &self,
        permit: IdempotencyPermit,
        response: ExactResponse,
    ) -> Result<ExactResponse, ApiError> {
        let repository = Arc::clone(&self.idempotency);
        tokio::task::spawn_blocking(move || repository.complete(permit, response))
            .await
            .map_err(|_error| self.public_error(ErrorCode::Internal))?
            .map_err(|error| self.idempotency_error(error))
    }

    async fn abandon(&self, permit: IdempotencyPermit) -> Result<(), ApiError> {
        let repository = Arc::clone(&self.idempotency);
        tokio::task::spawn_blocking(move || repository.abandon(permit))
            .await
            .map_err(|_error| self.public_error(ErrorCode::Internal))?
            .map_err(|error| self.idempotency_error(error))
    }

    fn replay(
        &self,
        expected_operation: &str,
        response: &ExactResponse,
    ) -> Result<ResponseEnvelope, ApiError> {
        decode_response(expected_operation, response.as_bytes())
            .map_err(|failure| self.public_error(failure.error_code()))
    }

    async fn call_mutation(
        &self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> Result<ResponseEnvelope, ApiError> {
        let operation = request.operation_id().as_str().to_owned();
        let key = request
            .idempotency_key()
            .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))
            .and_then(|key| {
                IdempotencyKey::new(key.to_owned())
                    .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))
            })?;
        let digest = normalized_request_digest(&request)
            .map_err(|failure| self.public_error(failure.error_code()))?;
        let binding = IdempotencyBinding::new(
            context.identity().tenant().clone(),
            context.identity().principal().clone(),
            request.operation_id().clone(),
            key,
            digest,
        );
        match self.reserve(binding.clone()).await? {
            IdempotencyReservation::Replay(response) => self.replay(&operation, &response),
            IdempotencyReservation::Pending => {
                let response = self.wait_for_completion(binding).await?;
                self.replay(&operation, &response)
            }
            IdempotencyReservation::Execute(permit) => {
                match self
                    .mutation_executor
                    .execute(self.delegate.as_ref(), context, request)
                    .await
                {
                    MutationExecution::Applied(response) => {
                        let exact = encode_response(&operation, &response)
                            .and_then(|bytes| {
                                ExactResponse::new(bytes).map_err(ResponseCodecError::from)
                            })
                            .map_err(|failure| match failure {
                                ResponseCodecError::Idempotency(error) => {
                                    self.idempotency_error(error)
                                }
                                other => self.public_error(other.error_code()),
                            })?;
                        let stored = self.complete(permit, exact).await?;
                        self.replay(&operation, &stored)
                    }
                    MutationExecution::ProvenNoMutation { error, proof: _ } => {
                        self.abandon(permit).await?;
                        Err(error)
                    }
                    MutationExecution::Indeterminate(error) => {
                        // The permit is intentionally consumed without abandonment. A later retry
                        // observes Pending until reconciliation proves and records the outcome.
                        drop(permit);
                        Err(error)
                    }
                }
            }
        }
    }
}

impl ServiceFacade for GovernedFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        Box::pin(async move {
            let _quota = self.acquire(&context)?;
            if context.operation() != request.operation_id() {
                return Err(self.public_error(ErrorCode::InvalidArgument));
            }
            let contract = operation_by_id(request.operation_id().as_str())
                .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))?;
            if contract.stream_kind != StreamKind::Unary {
                return Err(self.public_error(ErrorCode::InvalidArgument));
            }
            if contract.mutation {
                self.call_mutation(context, request).await
            } else if request.idempotency_key().is_some() {
                Err(self.public_error(ErrorCode::InvalidArgument))
            } else {
                self.delegate.call(context, request).await
            }
        })
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        Box::pin(async move {
            let quota = self.acquire(&context)?;
            if context.operation() != request.operation_id() {
                return Err(self.public_error(ErrorCode::InvalidArgument));
            }
            let contract = operation_by_id(request.operation_id().as_str())
                .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))?;
            if contract.stream_kind != StreamKind::ServerStream
                || contract.mutation
                || request.idempotency_key().is_some()
            {
                return Err(self.public_error(ErrorCode::InvalidArgument));
            }
            let stream = self.delegate.subscribe(context, request).await?;
            Ok(Box::pin(QuotaEventStream {
                inner: stream,
                quota: Some(quota),
            }) as FacadeEventStream)
        })
    }
}

impl fmt::Debug for GovernedFacade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedFacade")
            .field("delegate", &"[INJECTED]")
            .field("idempotency", &"[INJECTED]")
            .field("quotas", &self.quotas)
            .field("maximum_wait", &self.maximum_wait)
            .field("mutation_executor", &"[INJECTED]")
            .finish()
    }
}

struct QuotaEventStream {
    inner: FacadeEventStream,
    quota: Option<QuotaLease>,
}

impl Stream for QuotaEventStream {
    type Item = <FacadeEventStream as Stream>::Item;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = self.inner.as_mut().poll_next(context);
        if matches!(result, Poll::Ready(None)) {
            self.quota.take();
        }
        result
    }
}

struct FreshCorrelationIds {
    primary: MonotonicUuidV7Generator,
    fallback_sequence: AtomicU64,
    final_fallback: RecordId,
}

impl FreshCorrelationIds {
    fn new() -> Result<Self, GovernedFacadeError> {
        let final_fallback = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000000")
            .map_err(|_error| GovernedFacadeError::CorrelationUnavailable)?;
        Ok(Self {
            primary: MonotonicUuidV7Generator::default(),
            fallback_sequence: AtomicU64::new(1),
            final_fallback,
        })
    }

    fn next(&self) -> RecordId {
        if let Ok(identifier) = self.primary.generate()
            && let Ok(record_id) = RecordId::new(identifier.to_string())
        {
            return record_id;
        }
        let sequence = self.fallback_sequence.fetch_add(1, Ordering::Relaxed);
        let rendered = format!(
            "01890f47-8e7d-7b42-a1d2-{:012x}",
            sequence & 0x0000_ffff_ffff_ffff
        );
        match RecordId::new(rendered) {
            Ok(record_id) => record_id,
            Err(_error) => {
                // The fixed version/variant template and masked 48-bit suffix are valid by
                // construction. Retain a valid final identity if that invariant is ever broken.
                self.final_fallback.clone()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestDigestError {
    NonCanonicalPayload,
    InvalidDigest,
}

impl RequestDigestError {
    const fn error_code(self) -> ErrorCode {
        match self {
            Self::NonCanonicalPayload => ErrorCode::InvalidArgument,
            Self::InvalidDigest => ErrorCode::Internal,
        }
    }
}

fn normalized_request_digest(
    request: &RequestEnvelope,
) -> Result<ContentDigest, RequestDigestError> {
    from_deterministic_cbor(request.payload_cbor())
        .map_err(|_error| RequestDigestError::NonCanonicalPayload)?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    digest_field(&mut hasher, 1, request.operation_id().as_str().as_bytes());
    digest_field(&mut hasher, 2, request.payload_cbor());
    digest_optional(&mut hasher, 3, request.expected_revision());
    digest_optional(&mut hasher, 4, request.page_cursor());
    hasher.update([5]);
    match request.page_size() {
        Some(page_size) => {
            hasher.update([1]);
            hasher.update(page_size.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update([6]);
    hasher.update(
        u64::try_from(request.path_parameters().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for parameter in request.path_parameters() {
        digest_field(&mut hasher, 7, parameter.name().as_bytes());
        digest_field(&mut hasher, 8, parameter.value().as_bytes());
    }
    digest_field(&mut hasher, 9, &[u8::from(request.dry_run())]);
    let mut rendered = String::with_capacity(68);
    rendered.push_str("1220");
    for byte in hasher.finalize() {
        let _ignored = write!(&mut rendered, "{byte:02x}");
    }
    ContentDigest::new(rendered).map_err(|_error| RequestDigestError::InvalidDigest)
}

fn digest_field(hasher: &mut Sha256, tag: u8, value: &[u8]) {
    hasher.update([tag]);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn digest_optional(hasher: &mut Sha256, tag: u8, value: Option<&str>) {
    hasher.update([tag]);
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseCodecError {
    Malformed,
    LimitExceeded,
    OperationMismatch,
    NonCanonicalPayload,
    Idempotency(IdempotencyError),
}

impl ResponseCodecError {
    const fn error_code(self) -> ErrorCode {
        match self {
            Self::Malformed | Self::OperationMismatch | Self::NonCanonicalPayload => {
                ErrorCode::Internal
            }
            Self::LimitExceeded | Self::Idempotency(IdempotencyError::ResponseTooLarge) => {
                ErrorCode::LimitExceeded
            }
            Self::Idempotency(_) => ErrorCode::Internal,
        }
    }
}

impl From<IdempotencyError> for ResponseCodecError {
    fn from(error: IdempotencyError) -> Self {
        Self::Idempotency(error)
    }
}

fn encode_response(
    expected_operation: &str,
    response: &ResponseEnvelope,
) -> Result<Vec<u8>, ResponseCodecError> {
    if response.operation_id().as_str() != expected_operation {
        return Err(ResponseCodecError::OperationMismatch);
    }
    from_deterministic_cbor(response.payload_cbor())
        .map_err(|_error| ResponseCodecError::NonCanonicalPayload)?;
    let mut output = Vec::with_capacity(
        RESPONSE_MAGIC
            .len()
            .saturating_add(response.payload_cbor().len())
            .saturating_add(64),
    );
    output.extend_from_slice(RESPONSE_MAGIC);
    push_u16_bytes(&mut output, expected_operation.as_bytes())?;
    push_u32_bytes(&mut output, response.payload_cbor())?;
    push_optional_u16(&mut output, response.semantic_etag())?;
    push_optional_u32(&mut output, response.next_page_cursor())?;
    Ok(output)
}

fn decode_response(
    expected_operation: &str,
    bytes: &[u8],
) -> Result<ResponseEnvelope, ResponseCodecError> {
    let mut decoder = ResponseDecoder::new(bytes);
    if decoder.read_exact(RESPONSE_MAGIC.len())? != RESPONSE_MAGIC {
        return Err(ResponseCodecError::Malformed);
    }
    let operation = decoder.read_u16_string()?;
    if operation != expected_operation {
        return Err(ResponseCodecError::OperationMismatch);
    }
    let payload = decoder.read_u32_bytes()?.to_vec();
    from_deterministic_cbor(&payload).map_err(|_error| ResponseCodecError::NonCanonicalPayload)?;
    let semantic_etag = decoder.read_optional_u16_string()?;
    let next_page_cursor = decoder.read_optional_u32_string()?;
    if !decoder.is_finished() {
        return Err(ResponseCodecError::Malformed);
    }
    ResponseEnvelope::new(operation, payload, semantic_etag, next_page_cursor)
        .map_err(|_error| ResponseCodecError::Malformed)
}

fn push_u16_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ResponseCodecError> {
    let length = u16::try_from(value.len()).map_err(|_error| ResponseCodecError::LimitExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_u32_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ResponseCodecError> {
    let length = u32::try_from(value.len()).map_err(|_error| ResponseCodecError::LimitExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_optional_u16(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), ResponseCodecError> {
    match value {
        Some(value) => {
            output.push(1);
            push_u16_bytes(output, value.as_bytes())
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn push_optional_u32(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), ResponseCodecError> {
    match value {
        Some(value) => {
            output.push(1);
            push_u32_bytes(output, value.as_bytes())
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

struct ResponseDecoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> ResponseDecoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], ResponseCodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ResponseCodecError::LimitExceeded)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(ResponseCodecError::Malformed)?;
        self.position = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ResponseCodecError> {
        self.read_exact(2)?
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_error| ResponseCodecError::Malformed)
    }

    fn read_u32(&mut self) -> Result<u32, ResponseCodecError> {
        self.read_exact(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_error| ResponseCodecError::Malformed)
    }

    fn read_u8(&mut self) -> Result<u8, ResponseCodecError> {
        self.read_exact(1)?
            .first()
            .copied()
            .ok_or(ResponseCodecError::Malformed)
    }

    fn read_u16_string(&mut self) -> Result<String, ResponseCodecError> {
        let length = usize::from(self.read_u16()?);
        let value = self.read_exact(length)?;
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_error| ResponseCodecError::Malformed)
    }

    fn read_u32_bytes(&mut self) -> Result<&'a [u8], ResponseCodecError> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_error| ResponseCodecError::LimitExceeded)?;
        self.read_exact(length)
    }

    fn read_optional_u16_string(&mut self) -> Result<Option<String>, ResponseCodecError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => self.read_u16_string().map(Some),
            _ => Err(ResponseCodecError::Malformed),
        }
    }

    fn read_optional_u32_string(&mut self) -> Result<Option<String>, ResponseCodecError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => {
                let value = self.read_u32_bytes()?;
                std::str::from_utf8(value)
                    .map(str::to_owned)
                    .map(Some)
                    .map_err(|_error| ResponseCodecError::Malformed)
            }
            _ => Err(ResponseCodecError::Malformed),
        }
    }

    fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConservativeMutationExecutor, GovernedFacade, MutationExecution, MutationExecutor,
        NoMutationProof, normalized_request_digest,
    };
    use cigar_api::{
        ApiError, AuthenticatedIdentity, CancellationToken, EventEnvelope, ExactResponse,
        FacadeEventStream, IdempotencyBinding, IdempotencyError, IdempotencyPermit,
        IdempotencyRepository, IdempotencyReservation, MAX_OPERATION_PAYLOAD_BYTES, OperationId,
        PathParameter, PrincipalId, QuotaLimits, QuotaManager, RequestContext, RequestEnvelope,
        ResponseEnvelope, ServiceFacade, ServiceFuture, TenantId, TraceId,
    };
    use cigar_canon::{CanonicalNode, to_deterministic_cbor};
    use cigar_protocol::{ErrorCode, RecordId, UtcTimestamp};
    use cigar_store::{InMemoryStore, ServiceRepository};
    use std::error::Error;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{Notify, mpsc};
    use tokio_stream::StreamExt as _;
    use tokio_stream::wrappers::ReceiverStream;

    struct TestFacade {
        executions: AtomicUsize,
        fail: AtomicBool,
        block: AtomicBool,
        started: Notify,
        release: Notify,
        stream_senders: Mutex<Vec<mpsc::Sender<Result<EventEnvelope, ApiError>>>>,
        dependency_error: ApiError,
        internal_error: ApiError,
    }

    impl TestFacade {
        fn new() -> Result<Self, Box<dyn Error>> {
            let correlation = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
            Ok(Self {
                executions: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                block: AtomicBool::new(false),
                started: Notify::new(),
                release: Notify::new(),
                stream_senders: Mutex::new(Vec::new()),
                dependency_error: ApiError::new(
                    ErrorCode::DependencyUnavailable,
                    correlation.clone(),
                ),
                internal_error: ApiError::new(ErrorCode::Internal, correlation),
            })
        }
    }

    impl ServiceFacade for TestFacade {
        fn call<'a>(
            &'a self,
            _context: RequestContext,
            request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
            Box::pin(async move {
                self.executions.fetch_add(1, Ordering::SeqCst);
                if self.block.load(Ordering::SeqCst) {
                    self.started.notify_one();
                    self.release.notified().await;
                }
                if self.fail.load(Ordering::SeqCst) {
                    return Err(self.dependency_error.clone());
                }
                ResponseEnvelope::new(
                    request.operation_id().as_str(),
                    to_deterministic_cbor(&CanonicalNode::Map(Default::default()))
                        .map_err(|_error| self.internal_error.clone())?,
                    Some("\"v1\"".to_owned()),
                    None,
                )
                .map_err(|_error| self.internal_error.clone())
            })
        }

        fn subscribe<'a>(
            &'a self,
            _context: RequestContext,
            _request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
            Box::pin(async move {
                let (sender, receiver) = mpsc::channel(1);
                match self.stream_senders.lock() {
                    Ok(mut senders) => senders.push(sender),
                    Err(poisoned) => poisoned.into_inner().push(sender),
                }
                Ok(Box::pin(ReceiverStream::new(receiver)) as FacadeEventStream)
            })
        }
    }

    fn timestamp(value: i128) -> Result<UtcTimestamp, Box<dyn Error>> {
        Ok(UtcTimestamp::from_unix_nanos(value)?)
    }

    fn context(operation: &str, tenant: &str) -> Result<RequestContext, Box<dyn Error>> {
        Ok(RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new(tenant)?,
                PrincipalId::new("principal-a")?,
            ),
            OperationId::new(operation)?,
            timestamp(100)?,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            CancellationToken::new(),
            timestamp(10)?,
        )?)
    }

    fn payload(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(to_deterministic_cbor(&CanonicalNode::Text(
            value.to_owned(),
        ))?)
    }

    fn mutation_request(value: &str, key: &str) -> Result<RequestEnvelope, Box<dyn Error>> {
        Ok(RequestEnvelope::new(
            "ingestCatalog",
            payload(value)?,
            Some(key.to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?)
    }

    #[test]
    fn dry_run_intent_is_bound_into_the_idempotency_request_digest() -> Result<(), Box<dyn Error>> {
        let execute = mutation_request("same", "same-key")?;
        let preview = RequestEnvelope::new_with_dry_run(
            "ingestCatalog",
            payload("same")?,
            true,
            Some("same-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let execute_digest =
            normalized_request_digest(&execute).map_err(|_error| "execute digest failed")?;
        let preview_digest =
            normalized_request_digest(&preview).map_err(|_error| "preview digest failed")?;
        assert_ne!(execute_digest, preview_digest);
        Ok(())
    }

    fn stream_request() -> Result<RequestEnvelope, Box<dyn Error>> {
        Ok(RequestEnvelope::new(
            "subscribeSpaceEvents",
            payload("stream")?,
            None,
            None,
            None,
            None,
            vec![PathParameter::new("space_id", "space-a")?],
        )?)
    }

    fn governed(
        delegate: Arc<TestFacade>,
        repository: Arc<dyn IdempotencyRepository>,
        quotas: QuotaManager,
        wait: Duration,
    ) -> Result<Arc<GovernedFacade>, Box<dyn Error>> {
        let delegate: Arc<dyn ServiceFacade> = delegate;
        Ok(Arc::new(GovernedFacade::new(
            delegate, repository, quotas, wait,
        )?))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_identical_mutation_executes_once_and_replays() -> Result<(), Box<dyn Error>>
    {
        let delegate = Arc::new(TestFacade::new()?);
        delegate.block.store(true, Ordering::SeqCst);
        let repository: Arc<dyn IdempotencyRepository> =
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new());
        let quotas = QuotaManager::new(QuotaLimits::new(4, 4)?);
        let facade = governed(
            Arc::clone(&delegate),
            repository,
            quotas,
            Duration::from_secs(1),
        )?;
        let first_facade = Arc::clone(&facade);
        let first = tokio::spawn(async move {
            first_facade
                .call(
                    context("ingestCatalog", "tenant-a").map_err(|_| "invalid context")?,
                    mutation_request("same", "key-one").map_err(|_| "invalid request")?,
                )
                .await
                .map_err(|_| "first call failed")
        });
        delegate.started.notified().await;
        let second_facade = Arc::clone(&facade);
        let second = tokio::spawn(async move {
            second_facade
                .call(
                    context("ingestCatalog", "tenant-a").map_err(|_| "invalid context")?,
                    mutation_request("same", "key-one").map_err(|_| "invalid request")?,
                )
                .await
                .map_err(|_| "second call failed")
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        delegate.release.notify_one();
        let first_response = first.await.map_err(|_| "first task failed")??;
        let second_response = second.await.map_err(|_| "second task failed")??;
        assert_eq!(first_response, second_response);
        assert_eq!(delegate.executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn changed_request_with_same_key_is_rejected_as_collision() -> Result<(), Box<dyn Error>>
    {
        let delegate = Arc::new(TestFacade::new()?);
        let repository: Arc<dyn IdempotencyRepository> =
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new());
        let facade = governed(
            Arc::clone(&delegate),
            repository,
            QuotaManager::new(QuotaLimits::new(2, 2)?),
            Duration::from_millis(50),
        )?;
        facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("first", "same-key")?,
            )
            .await?;
        let error = facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("changed", "same-key")?,
            )
            .await
            .err()
            .ok_or("collision unexpectedly succeeded")?;
        assert_eq!(error.code(), ErrorCode::RevisionConflict);
        assert_eq!(delegate.executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quota_exhaustion_is_content_safe_and_release_is_automatic()
    -> Result<(), Box<dyn Error>> {
        let delegate = Arc::new(TestFacade::new()?);
        delegate.block.store(true, Ordering::SeqCst);
        let quotas = QuotaManager::new(QuotaLimits::new(1, 1)?);
        let facade = governed(
            Arc::clone(&delegate),
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new()),
            quotas.clone(),
            Duration::from_secs(1),
        )?;
        let held_facade = Arc::clone(&facade);
        let held = tokio::spawn(async move {
            held_facade
                .call(
                    context("ingestCatalog", "tenant-a").map_err(|_| "invalid context")?,
                    mutation_request("held", "held-key").map_err(|_| "invalid request")?,
                )
                .await
                .map_err(|_| "held call failed")
        });
        delegate.started.notified().await;
        let rejected = facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("other", "other-key")?,
            )
            .await
            .err()
            .ok_or("quota exhaustion unexpectedly succeeded")?;
        assert_eq!(rejected.code(), ErrorCode::RateLimited);
        delegate.release.notify_one();
        held.await.map_err(|_| "held task failed")??;
        assert_eq!(quotas.snapshot().global_in_use(), 0);
        delegate.block.store(false, Ordering::SeqCst);
        facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("after", "after-key")?,
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn stream_owns_quota_until_end_or_drop() -> Result<(), Box<dyn Error>> {
        let delegate = Arc::new(TestFacade::new()?);
        let quotas = QuotaManager::new(QuotaLimits::new(1, 1)?);
        let facade = governed(
            Arc::clone(&delegate),
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new()),
            quotas.clone(),
            Duration::from_millis(50),
        )?;
        let stream = facade
            .subscribe(
                context("subscribeSpaceEvents", "tenant-a")?,
                stream_request()?,
            )
            .await?;
        assert_eq!(quotas.snapshot().global_in_use(), 1);
        let rejected = facade
            .subscribe(
                context("subscribeSpaceEvents", "tenant-a")?,
                stream_request()?,
            )
            .await
            .err()
            .ok_or("second stream unexpectedly admitted")?;
        assert_eq!(rejected.code(), ErrorCode::RateLimited);
        drop(stream);
        assert_eq!(quotas.snapshot().global_in_use(), 0);
        let mut admitted = facade
            .subscribe(
                context("subscribeSpaceEvents", "tenant-a")?,
                stream_request()?,
            )
            .await?;
        // Dropping the retained sender produces end-of-stream and releases without waiting for the
        // stream object itself to be dropped.
        match delegate.stream_senders.lock() {
            Ok(mut senders) => senders.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
        drop(admitted.next().await);
        drop(admitted);
        assert_eq!(quotas.snapshot().global_in_use(), 0);
        Ok(())
    }

    struct MalformedReplayRepository;

    impl IdempotencyRepository for MalformedReplayRepository {
        fn reserve(
            &self,
            _binding: &IdempotencyBinding,
        ) -> Result<IdempotencyReservation, IdempotencyError> {
            Ok(IdempotencyReservation::Replay(ExactResponse::new(
                b"not-a-response".to_vec(),
            )?))
        }

        fn complete(
            &self,
            _permit: IdempotencyPermit,
            _response: ExactResponse,
        ) -> Result<ExactResponse, IdempotencyError> {
            Err(IdempotencyError::InvalidPermit)
        }

        fn abandon(&self, _permit: IdempotencyPermit) -> Result<(), IdempotencyError> {
            Err(IdempotencyError::InvalidPermit)
        }

        fn wait_for_completion(
            &self,
            _binding: &IdempotencyBinding,
            _maximum_wait: Duration,
        ) -> Result<ExactResponse, IdempotencyError> {
            Err(IdempotencyError::ReservationNotFound)
        }
    }

    #[tokio::test]
    async fn malformed_replay_bytes_fail_closed_without_delegate_execution()
    -> Result<(), Box<dyn Error>> {
        let delegate = Arc::new(TestFacade::new()?);
        let facade = governed(
            Arc::clone(&delegate),
            Arc::new(MalformedReplayRepository),
            QuotaManager::new(QuotaLimits::new(1, 1)?),
            Duration::from_millis(50),
        )?;
        let error = facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("payload", "key")?,
            )
            .await
            .err()
            .ok_or("malformed replay unexpectedly succeeded")?;
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(delegate.executions.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delegate_error_conservatively_retains_reservation() -> Result<(), Box<dyn Error>> {
        let delegate = Arc::new(TestFacade::new()?);
        delegate.fail.store(true, Ordering::SeqCst);
        let facade = governed(
            Arc::clone(&delegate),
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new()),
            QuotaManager::new(QuotaLimits::new(2, 2)?),
            Duration::from_millis(20),
        )?;
        let first = facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("payload", "key")?,
            )
            .await
            .err()
            .ok_or("delegate failure unexpectedly succeeded")?;
        assert_eq!(first.code(), ErrorCode::DependencyUnavailable);
        let retry = facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("payload", "key")?,
            )
            .await
            .err()
            .ok_or("pending retry unexpectedly succeeded")?;
        assert_eq!(retry.code(), ErrorCode::DeadlineExceeded);
        assert_eq!(delegate.executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    struct ProveOnceExecutor {
        rejected: AtomicBool,
        rejection: ApiError,
    }

    impl MutationExecutor for ProveOnceExecutor {
        fn execute<'a>(
            &'a self,
            delegate: &'a dyn ServiceFacade,
            context: RequestContext,
            request: RequestEnvelope,
        ) -> ServiceFuture<'a, MutationExecution> {
            Box::pin(async move {
                if !self.rejected.swap(true, Ordering::SeqCst) {
                    MutationExecution::ProvenNoMutation {
                        error: self.rejection.clone(),
                        proof: NoMutationProof::rejected_before_dispatch(),
                    }
                } else {
                    ConservativeMutationExecutor
                        .execute(delegate, context, request)
                        .await
                }
            })
        }
    }

    #[tokio::test]
    async fn explicit_no_mutation_proof_is_the_only_abandonment_path() -> Result<(), Box<dyn Error>>
    {
        let delegate = Arc::new(TestFacade::new()?);
        let delegate_object: Arc<dyn ServiceFacade> = delegate.clone();
        let facade = GovernedFacade::with_mutation_executor(
            delegate_object,
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new()),
            QuotaManager::new(QuotaLimits::new(1, 1)?),
            Duration::from_millis(50),
            Arc::new(ProveOnceExecutor {
                rejected: AtomicBool::new(false),
                rejection: ApiError::new(
                    ErrorCode::PolicyDenied,
                    RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
                ),
            }),
        )?;
        let first = facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("payload", "key")?,
            )
            .await
            .err()
            .ok_or("proven rejection unexpectedly succeeded")?;
        assert_eq!(first.code(), ErrorCode::PolicyDenied);
        facade
            .call(
                context("ingestCatalog", "tenant-a")?,
                mutation_request("payload", "key")?,
            )
            .await?;
        assert_eq!(delegate.executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    struct BoundaryFacade {
        executions: AtomicUsize,
        response_payload: Vec<u8>,
        internal_error: ApiError,
    }

    impl ServiceFacade for BoundaryFacade {
        fn call<'a>(
            &'a self,
            _context: RequestContext,
            request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
            Box::pin(async move {
                self.executions.fetch_add(1, Ordering::SeqCst);
                ResponseEnvelope::new(
                    request.operation_id().as_str(),
                    self.response_payload.clone(),
                    Some(format!("\"{}\"", "e".repeat(254))),
                    Some("c".repeat(4_096)),
                )
                .map_err(|_error| self.internal_error.clone())
            })
        }

        fn subscribe<'a>(
            &'a self,
            _context: RequestContext,
            _request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
            Box::pin(async move { Err(self.internal_error.clone()) })
        }
    }

    fn maximum_canonical_payload() -> Result<Vec<u8>, Box<dyn Error>> {
        let content_length = MAX_OPERATION_PAYLOAD_BYTES
            .checked_sub(5)
            .ok_or("payload bound is too small for a u32 CBOR byte string")?;
        let encoded_length = u32::try_from(content_length)?;
        let mut payload = Vec::with_capacity(MAX_OPERATION_PAYLOAD_BYTES);
        payload.push(0x5a);
        payload.extend_from_slice(&encoded_length.to_be_bytes());
        payload.resize(MAX_OPERATION_PAYLOAD_BYTES, 0x5c);
        Ok(payload)
    }

    #[tokio::test]
    async fn maximum_payload_and_metadata_fit_durable_exact_replay() -> Result<(), Box<dyn Error>> {
        let maximum_payload = maximum_canonical_payload()?;
        let correlation = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
        let delegate = Arc::new(BoundaryFacade {
            executions: AtomicUsize::new(0),
            response_payload: maximum_payload.clone(),
            internal_error: ApiError::new(ErrorCode::Internal, correlation.clone()),
        });
        let store: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let durable: Arc<dyn IdempotencyRepository> =
            Arc::new(crate::DurableIdempotencyRepository::new(store, correlation));
        let delegate_object: Arc<dyn ServiceFacade> = delegate.clone();
        let facade = GovernedFacade::new(
            delegate_object,
            durable,
            QuotaManager::new(QuotaLimits::new(1, 1)?),
            Duration::from_secs(1),
        )?;
        let request = RequestEnvelope::new(
            "ingestCatalog",
            maximum_payload,
            Some("maximum-boundary".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let first = facade
            .call(context("ingestCatalog", "tenant-a")?, request.clone())
            .await?;
        let replay = facade
            .call(context("ingestCatalog", "tenant-a")?, request)
            .await?;
        assert_eq!(first, replay);
        assert_eq!(replay.payload_cbor().len(), MAX_OPERATION_PAYLOAD_BYTES);
        assert_eq!(replay.semantic_etag().map(str::len), Some(256));
        assert_eq!(replay.next_page_cursor().map(str::len), Some(4_096));
        assert_eq!(delegate.executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn debug_output_redacts_payload_key_and_authenticated_scope() -> Result<(), Box<dyn Error>> {
        let delegate = Arc::new(TestFacade::new()?);
        let facade = governed(
            delegate,
            Arc::new(cigar_api::InMemoryIdempotencyRepository::new()),
            QuotaManager::new(QuotaLimits::new(1, 1)?),
            Duration::from_millis(50),
        )?;
        let request = mutation_request("super-secret-payload", "super-secret-key")?;
        let rendered = format!(
            "{facade:?} {request:?} {:?}",
            context("ingestCatalog", "super-secret-tenant")?
        );
        for protected in [
            "super-secret-payload",
            "super-secret-key",
            "super-secret-tenant",
        ] {
            assert!(!rendered.contains(protected));
        }
        Ok(())
    }
}
