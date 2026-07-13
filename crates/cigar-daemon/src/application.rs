//! Complete embedded application facade with mandatory API governance.

use crate::{GovernedFacade, GovernedFacadeError, MutationExecutor};
use cigar_api::{
    ApiError, CompleteServiceFacade, CompleteServiceFacadeBuilder, FacadeErrorFactory,
    FacadeEventStream, HandlerRegistryError, IdempotencyRepository, QuotaLimits, QuotaManager,
    RequestContext, RequestEnvelope, ResponseEnvelope, ServiceFacade, ServiceFuture,
    TypedOperation, TypedStreamAdapter, TypedStreamService, TypedUnaryAdapter, TypedUnaryService,
};
use cigar_crypto::MonotonicUuidV7Generator;
use cigar_protocol::{ErrorCode, RecordId};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Process-wide content-safe API error authority for application and adapter failures.
pub struct DaemonFacadeErrorFactory {
    ids: MonotonicUuidV7Generator,
    fallback_correlation: RecordId,
}

impl DaemonFacadeErrorFactory {
    /// Creates an error authority with monotonic UUIDv7 correlation identities.
    pub fn new() -> Result<Self, cigar_protocol::ValidationErrors> {
        Ok(Self {
            ids: MonotonicUuidV7Generator::default(),
            fallback_correlation: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        })
    }
}

impl FacadeErrorFactory for DaemonFacadeErrorFactory {
    fn public_error(&self, code: ErrorCode) -> ApiError {
        let correlation = self
            .ids
            .generate()
            .ok()
            .and_then(|value| RecordId::new(value.to_string()).ok())
            .unwrap_or_else(|| self.fallback_correlation.clone());
        ApiError::new(code, correlation)
    }
}

impl fmt::Debug for DaemonFacadeErrorFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonFacadeErrorFactory")
            .field("correlation_ids", &"[MONOTONIC UUIDV7]")
            .finish()
    }
}

/// Typed construction surface for the exact generated operation registry.
///
/// Domain groups register only sealed operation markers, so a handler cannot claim a misspelled
/// or wrong-kind operation identity. [`Self::build`] still fails unless all 45 operations are
/// present exactly once.
pub struct ProductionApplicationBuilder {
    inner: CompleteServiceFacadeBuilder,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl ProductionApplicationBuilder {
    /// Starts an empty exact-operation application registry.
    #[must_use]
    pub fn new(errors: Arc<dyn FacadeErrorFactory>) -> Self {
        Self {
            inner: CompleteServiceFacadeBuilder::new(Arc::clone(&errors)),
            errors,
        }
    }

    /// Registers one marker-bound unary service.
    pub fn register_unary<O, H>(
        &mut self,
        handler: Arc<H>,
    ) -> Result<&mut Self, HandlerRegistryError>
    where
        O: TypedOperation,
        H: TypedUnaryService<O> + 'static,
    {
        self.inner
            .register_unary(Arc::new(TypedUnaryAdapter::<O, H>::new(
                handler,
                Arc::clone(&self.errors),
            )))?;
        Ok(self)
    }

    /// Registers one marker-bound server-streaming service.
    pub fn register_stream<O, H>(
        &mut self,
        handler: Arc<H>,
    ) -> Result<&mut Self, HandlerRegistryError>
    where
        O: TypedOperation,
        H: TypedStreamService<O> + 'static,
    {
        self.inner
            .register_stream(Arc::new(TypedStreamAdapter::<O, H>::new(
                handler,
                Arc::clone(&self.errors),
            )))?;
        Ok(self)
    }

    /// Seals the registry only when every frozen operation has one correctly typed handler.
    pub fn build(self) -> Result<CompleteServiceFacade, HandlerRegistryError> {
        self.inner.build()
    }
}

impl fmt::Debug for ProductionApplicationBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionApplicationBuilder")
            .field("registry", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Production application boundary proven complete for all generated operations and decorated
/// with global/per-tenant admission control plus durable mutation idempotency.
///
/// Construction accepts only a [`CompleteServiceFacade`], so an application missing even one of
/// the 45 frozen v1 embedded handlers cannot be served by the production daemon.
pub struct ProductionFacade {
    inner: GovernedFacade,
}

impl ProductionFacade {
    /// Applies mandatory quotas and durable idempotency with conservative mutation recovery.
    pub fn new(
        complete: CompleteServiceFacade,
        idempotency: Arc<dyn IdempotencyRepository>,
        limits: QuotaLimits,
        maximum_idempotency_wait: Duration,
    ) -> Result<Self, GovernedFacadeError> {
        Ok(Self {
            inner: GovernedFacade::new(
                Arc::new(complete),
                idempotency,
                QuotaManager::new(limits),
                maximum_idempotency_wait,
            )?,
        })
    }

    /// Applies mandatory governance with a trusted proof-bearing mutation executor.
    pub fn with_mutation_executor(
        complete: CompleteServiceFacade,
        idempotency: Arc<dyn IdempotencyRepository>,
        limits: QuotaLimits,
        maximum_idempotency_wait: Duration,
        mutation_executor: Arc<dyn MutationExecutor>,
    ) -> Result<Self, GovernedFacadeError> {
        Ok(Self {
            inner: GovernedFacade::with_mutation_executor(
                Arc::new(complete),
                idempotency,
                QuotaManager::new(limits),
                maximum_idempotency_wait,
                mutation_executor,
            )?,
        })
    }

    /// Returns content-safe quota accounting for operational leak checks.
    #[must_use]
    pub fn quota_snapshot(&self) -> cigar_api::QuotaSnapshot {
        self.inner.quota_snapshot()
    }
}

impl ServiceFacade for ProductionFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        self.inner.call(context, request)
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        self.inner.subscribe(context, request)
    }
}

impl fmt::Debug for ProductionFacade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionFacade")
            .field("operation_registry", &"[COMPLETE]")
            .field("governance", &self.inner)
            .finish()
    }
}
