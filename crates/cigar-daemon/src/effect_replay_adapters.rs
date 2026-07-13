//! Typed production adapters for the effect and replay service families.
//!
//! The adapters in this module are deliberately thin authority boundaries. Caller payloads are
//! decoded by `cigar-api`; authenticated transport subjects are resolved through the durable
//! domain-identity mapper; and every domain identity, timestamp, policy decision, effect event,
//! execution identity, and live authorization is supplied by server-owned dependencies.

use crate::application::ProductionApplicationBuilder;
use crate::authority::AuthorityClock;
use crate::composition::DaemonWorkers;
use crate::domain_identity::{DomainIdentityError, DomainIdentityResolver, ResolvedDomainIdentity};
use crate::durable_replay::{DurableReplayArchive, DurableReplayReservationLedger};
use crate::production_effects::{EffectArgumentVault, EffectArgumentVaultError};
use crate::replay_jobs::{
    DurableReplayJobService, ReplayExecutionWindow, ReplayJobError, ReplayJobErrorCode,
    ReplayJobPhase, VersionedReplayJob,
};
use crate::worker::{
    BlockingPool, BlockingPoolError, BlockingPoolErrorCode, WorkerJob, WorkerKind,
};
use cigar_api::{
    ApiError, AuthorizeEffectOperation, AuthorizeEffectRequest, CompareLiveReplayOperation,
    CompareLiveReplayRequest, CompensateEffectOperation, CompensateEffectRequest,
    CreateReplayOperation, CreateReplayRequest, DispatchEffectOperation, EffectIdRequest,
    EffectStatusResponse, FacadeErrorFactory, GetEffectStatusOperation,
    GetReplayCompletenessOperation, HandlerRegistryError, PrepareEffectOperation,
    PrepareEffectRequest, ReconcileEffectOperation, ReplayIdRequest, ReplayJobResponse,
    ReplayJobStatus, RequestContext, RunObservationalReplayOperation, ServiceFuture, TenantId,
    TypedRequest, TypedResponse, TypedUnaryService,
};
use cigar_crypto::MonotonicUuidV7Generator;
use cigar_effects::{
    ConnectorDescriptor, DurableEffectRecord, EffectAuthorization, EffectConnector, EffectEngine,
    EffectError, EffectErrorCode, EffectRecordAuthenticator, compensation_spec_digest,
    effect_intent_digest, effect_target_digest,
};
use cigar_protocol::{
    ApprovalKind, Capability, CompensationLink, EffectApproval, EffectIntent, EffectState,
    ErrorCode, ExpectedRevision, ExtensionMap, IdempotencyKey, ReconciliationOutcome, RecordId,
    ReplayCompleteness, ReplayExecution, ReplayMode, ReplayRequest, ReplayStatus, RetryPolicy,
    RiskLevel, SchemaVersion, UtcTimestamp, Validate,
};
use cigar_replay::{
    LiveAuthorizationVerifier, LiveEffectGate, LiveReplayAuthorization, LiveReplayProvider,
    ReplayContext, ReplayEngine, ReplayErrorCode,
};
use cigar_store::{
    AccessContext, CancellationToken as StoreCancellation, Repository, ServiceBatch, ServiceError,
    ServiceErrorCode, ServiceExpectedVersion, ServiceRecordLocator, ServiceRecordSelection,
    ServiceRecordWrite, ServiceRepository, ServiceResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

const EFFECT_ACCESS_PURPOSE: &str = "daemon.effect-service.v1";
const LIVE_AUTHORIZATION_NAMESPACE: &str = "replay.live-authorization.v1";
const LIVE_AUTHORIZATION_SCHEMA: &str = "cigar.persisted-live-replay-authorization.v1";

enum EffectBlockingFailure {
    Effect(EffectError),
    Public(ErrorCode),
}

/// Stable construction failure for effect/replay adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectReplayAdapterBuildError {
    /// A connector panicked, drifted, was invalid, or duplicated another selector.
    InvalidConnectorSet,
}

impl fmt::Display for EffectReplayAdapterBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("effect/replay adapter dependencies are invalid")
    }
}

impl std::error::Error for EffectReplayAdapterBuildError {}

/// Exact effect operation presented to the current server-side policy evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPolicyAction {
    /// Persist a new intent.
    Prepare,
    /// Bind an approval and authorize dispatch.
    Authorize,
    /// Claim and perform one fenced dispatch.
    Dispatch,
    /// Read the disclosure-safe status projection.
    Read,
    /// Reconcile an explicitly unknown effect.
    Reconcile,
    /// Link an independently authorized compensation child.
    Compensate,
}

/// Current policy result from a trusted evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPolicyDecision {
    policy_allows: bool,
    capabilities: BTreeSet<Capability>,
}

impl EffectPolicyDecision {
    /// Creates a current policy decision and its exact effective capabilities.
    #[must_use]
    pub fn new(policy_allows: bool, capabilities: BTreeSet<Capability>) -> Self {
        Self {
            policy_allows,
            capabilities,
        }
    }

    fn into_authorization(self, actor_id: RecordId, now: UtcTimestamp) -> EffectAuthorization {
        EffectAuthorization {
            actor_id,
            capabilities: self.capabilities,
            policy_allows: self.policy_allows,
            now,
        }
    }
}

/// Content-free failure from the injected current policy boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPolicyFailure {
    /// Current policy state could not be evaluated safely.
    Unavailable,
}

impl fmt::Display for EffectPolicyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("effect policy evaluation is unavailable")
    }
}

impl std::error::Error for EffectPolicyFailure {}

/// Trusted current policy and capability evaluator for effect operations.
pub trait EffectPolicyEvaluator: Send + Sync {
    /// Evaluates one operation for a server-resolved identity and immutable intent.
    fn evaluate(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        action: EffectPolicyAction,
        intent: &EffectIntent,
        approval_kind: Option<ApprovalKind>,
    ) -> Result<EffectPolicyDecision, EffectPolicyFailure>;
}

/// Server-owned dispatch gate closed before shutdown starts draining effects.
pub trait EffectDispatchGate: Send + Sync {
    /// Returns true only while a new durable dispatch claim may be started or sent.
    fn dispatch_claims_allowed(&self) -> bool;

    /// Atomically admits connector entry immediately before a worker send.
    ///
    /// Returning true linearizes the send before any later shutdown gate closure. Implementations
    /// with a stronger dispatch-drain primitive may override this method.
    fn begin_dispatch_send(&self) -> bool {
        self.dispatch_claims_allowed()
    }
}

impl EffectDispatchGate for DaemonWorkers {
    fn dispatch_claims_allowed(&self) -> bool {
        DaemonWorkers::dispatch_claims_allowed(self)
    }
}

/// Best-effort in-memory wakeup queue for an already durable dispatch claim.
pub trait EffectDispatchQueue: Send + Sync {
    /// Enqueues one wakeup. Failure never invalidates or removes the durable outbox claim.
    fn enqueue(&self, job: WorkerJob) -> Result<(), EffectDispatchQueueError>;
}

/// Content-free best-effort wakeup enqueue failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectDispatchQueueError;

impl fmt::Display for EffectDispatchQueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("effect dispatch wakeup queue is unavailable")
    }
}

impl std::error::Error for EffectDispatchQueueError {}

impl EffectDispatchQueue for DaemonWorkers {
    fn enqueue(&self, job: WorkerJob) -> Result<(), EffectDispatchQueueError> {
        self.try_enqueue(WorkerKind::Outbox, job)
            .map_err(|_error| EffectDispatchQueueError)
    }
}

/// Closed effect worker operation requiring current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectWorkerAction {
    /// Enter a connector mutation for an already durable fenced attempt.
    Dispatch,
    /// Query a connector to reconcile an explicitly ambiguous attempt.
    Reconcile,
}

/// Content-free failure from current worker policy/capability resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectWorkerAuthorityError;

impl fmt::Display for EffectWorkerAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("effect worker authority is unavailable")
    }
}

impl std::error::Error for EffectWorkerAuthorityError {}

/// Current server-side authority resolver for durable effect workers.
pub trait EffectWorkerAuthority: Send + Sync {
    /// Resolves current policy and effective capabilities at exactly `now`.
    ///
    /// A current denial is represented by an authorization with `policy_allows == false` or
    /// insufficient capabilities so the effect kernel can durably finalize without sending.
    /// Infrastructure or indeterminate policy failures return an error and leave the claim intact.
    fn authorize(
        &self,
        tenant_id: &RecordId,
        action: EffectWorkerAction,
        record: &DurableEffectRecord,
        now: UtcTimestamp,
    ) -> Result<EffectAuthorization, EffectWorkerAuthorityError>;
}

/// Stable outcome of one bounded effect worker attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectWorkerOutcome {
    /// One durable effect record advanced.
    Advanced,
    /// The wakeup was an idempotent duplicate for already advanced truth.
    AlreadyComplete,
    /// Work remains durable but dispatch/reconciliation is not currently admissible.
    Deferred,
}

/// Content-free failure from a durable effect worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectWorkerError;

impl fmt::Display for EffectWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("durable effect worker failed")
    }
}

impl std::error::Error for EffectWorkerError {}

/// Complete dependencies for real outbox and reconciliation processing.
pub struct EffectWorkerProcessorDependencies<R: Repository> {
    /// Shared durable effect repository.
    pub repository: Arc<R>,
    /// Current worker policy and effective-capability resolver.
    pub authority: Arc<dyn EffectWorkerAuthority>,
    /// Trusted current semantic clock.
    pub clock: Arc<dyn AuthorityClock>,
    /// Server-owned receipt, report, and event identity source.
    pub ids: Arc<dyn ApplicationIdGenerator>,
    /// Shutdown gate checked immediately before connector entry.
    pub dispatch_gate: Arc<dyn EffectDispatchGate>,
    /// Tenant-scoped protected-argument resolver staged only after a durable claim exists.
    pub argument_vault: Arc<dyn EffectArgumentVault>,
    /// Immutable connector set shared with the API adapter.
    pub connectors: Vec<Arc<dyn EffectConnector>>,
}

/// Real synchronous worker used only from the daemon's bounded blocking pool.
pub struct EffectWorkerProcessor<R: Repository> {
    repository: Arc<R>,
    authenticator: Option<Arc<dyn EffectRecordAuthenticator>>,
    authority: Arc<dyn EffectWorkerAuthority>,
    clock: Arc<dyn AuthorityClock>,
    ids: Arc<dyn ApplicationIdGenerator>,
    dispatch_gate: Arc<dyn EffectDispatchGate>,
    argument_vault: Arc<dyn EffectArgumentVault>,
    connectors: Vec<Arc<dyn EffectConnector>>,
    descriptors: BTreeMap<String, ConnectorDescriptor>,
}

impl<R: Repository> fmt::Debug for EffectWorkerProcessor<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectWorkerProcessor")
            .field("repository", &"[INJECTED]")
            .field("connector_count", &self.connectors.len())
            .finish_non_exhaustive()
    }
}

impl<R: Repository> EffectWorkerProcessor<R> {
    /// Validates and constructs the effect worker without a no-op connector fallback.
    pub fn new(
        dependencies: EffectWorkerProcessorDependencies<R>,
    ) -> Result<Self, EffectReplayAdapterBuildError> {
        Self::build(dependencies, None)
    }

    /// Constructs a production worker with one shared tenant-key record authenticator.
    pub fn new_with_authenticator(
        dependencies: EffectWorkerProcessorDependencies<R>,
        authenticator: Arc<dyn EffectRecordAuthenticator>,
    ) -> Result<Self, EffectReplayAdapterBuildError> {
        Self::build(dependencies, Some(authenticator))
    }

    fn build(
        dependencies: EffectWorkerProcessorDependencies<R>,
        authenticator: Option<Arc<dyn EffectRecordAuthenticator>>,
    ) -> Result<Self, EffectReplayAdapterBuildError> {
        let mut descriptors = BTreeMap::new();
        for connector in &dependencies.connectors {
            let descriptor = catch_unwind(AssertUnwindSafe(|| connector.descriptor()))
                .map_err(|_panic| EffectReplayAdapterBuildError::InvalidConnectorSet)?;
            descriptor
                .validate()
                .map_err(|_error| EffectReplayAdapterBuildError::InvalidConnectorSet)?;
            if descriptors
                .insert(descriptor.connector.clone(), descriptor)
                .is_some()
            {
                return Err(EffectReplayAdapterBuildError::InvalidConnectorSet);
            }
        }
        Ok(Self {
            repository: dependencies.repository,
            authenticator,
            authority: dependencies.authority,
            clock: dependencies.clock,
            ids: dependencies.ids,
            dispatch_gate: dependencies.dispatch_gate,
            argument_vault: dependencies.argument_vault,
            connectors: dependencies.connectors,
            descriptors,
        })
    }

    fn id(&self) -> Result<RecordId, EffectWorkerError> {
        self.ids.generate().map_err(|_error| EffectWorkerError)
    }

    fn engine(&self, tenant_id: RecordId) -> Result<EffectEngine<R>, EffectWorkerError> {
        let access = AccessContext::new(tenant_id, EFFECT_ACCESS_PURPOSE)
            .map_err(|_error| EffectWorkerError)?;
        let engine = match &self.authenticator {
            Some(authenticator) => EffectEngine::new_with_authenticator(
                Arc::clone(&self.repository),
                access,
                Arc::clone(authenticator),
            ),
            None => EffectEngine::new(Arc::clone(&self.repository), access),
        };
        for connector in &self.connectors {
            engine
                .register_connector(Arc::clone(connector))
                .map_err(|_error| EffectWorkerError)?;
        }
        Ok(engine)
    }

    /// Returns whether shutdown still permits discovery of new effect connector work.
    #[must_use]
    pub fn work_admission_allowed(&self) -> bool {
        self.dispatch_gate.dispatch_claims_allowed()
    }

    /// Returns whether one current unknown record is eligible for a bounded reconciliation pass.
    #[must_use]
    pub fn reconciliation_due(record: &DurableEffectRecord, now: UtcTimestamp) -> bool {
        reconciliation_is_due(record, now)
    }

    /// Returns whether the immutable registered connector supports reconciliation for this intent.
    #[must_use]
    pub fn reconciliation_supported(&self, record: &DurableEffectRecord) -> bool {
        self.descriptors
            .get(&record.intent.connector)
            .and_then(|descriptor| descriptor.operation(&record.intent.operation))
            .is_some_and(|operation| operation.supports_reconciliation)
    }

    /// Processes one exact queued durable record reference.
    pub fn process_job(
        &self,
        kind: WorkerKind,
        job: &WorkerJob,
    ) -> Result<EffectWorkerOutcome, EffectWorkerError> {
        let tenant_id = RecordId::new(job.tenant.as_str()).map_err(|_error| EffectWorkerError)?;
        match kind {
            WorkerKind::Outbox => {
                self.process_dispatch(&tenant_id, &job.record_id, job.expected_revision)
            }
            WorkerKind::Reconciliation => {
                self.process_reconciliation(&tenant_id, &job.record_id, job.expected_revision)
            }
            _ => Err(EffectWorkerError),
        }
    }

    /// Processes one exact durable dispatch claim.
    pub fn process_dispatch(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        expected: Option<ExpectedRevision>,
    ) -> Result<EffectWorkerOutcome, EffectWorkerError> {
        let engine = self.engine(tenant_id.clone())?;
        let record = engine.get(effect_id).map_err(|_error| EffectWorkerError)?;
        if record.state != EffectState::Dispatching {
            return Ok(EffectWorkerOutcome::AlreadyComplete);
        }
        if expected.is_some_and(|expected| expected.0 != record.effect_version) {
            return Err(EffectWorkerError);
        }
        if !self.dispatch_gate.dispatch_claims_allowed() {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        let now = self.clock.now().map_err(|_error| EffectWorkerError)?;
        let authorization = self
            .authority
            .authorize(tenant_id, EffectWorkerAction::Dispatch, &record, now)
            .map_err(|_error| EffectWorkerError)?;
        if authorization.now != now {
            return Err(EffectWorkerError);
        }
        let permit = engine
            .resume_dispatch(effect_id, record.effect_version)
            .map_err(|_error| EffectWorkerError)?;
        if !dispatch_can_enter_connector(&record, &authorization)? {
            return engine
                .dispatch(permit, self.id()?, self.id()?, &authorization)
                .map(|_record| EffectWorkerOutcome::Advanced)
                .map_err(|_error| EffectWorkerError);
        }
        self.argument_vault
            .stage(tenant_id, &record.intent)
            .map_err(|_error| EffectWorkerError)?;
        let current_now = self.clock.now().map_err(|_error| EffectWorkerError)?;
        if current_now < now {
            return Err(EffectWorkerError);
        }
        let current_authorization = self
            .authority
            .authorize(
                tenant_id,
                EffectWorkerAction::Dispatch,
                &record,
                current_now,
            )
            .map_err(|_error| EffectWorkerError)?;
        if current_authorization.now != current_now
            || current_authorization.actor_id != authorization.actor_id
        {
            return Err(EffectWorkerError);
        }
        if !dispatch_can_enter_connector(&record, &current_authorization)? {
            return engine
                .dispatch(permit, self.id()?, self.id()?, &current_authorization)
                .map(|_record| EffectWorkerOutcome::Advanced)
                .map_err(|_error| EffectWorkerError);
        }
        if !self.dispatch_gate.begin_dispatch_send() {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        engine
            .dispatch(permit, self.id()?, self.id()?, &current_authorization)
            .map(|_record| EffectWorkerOutcome::Advanced)
            .map_err(|_error| EffectWorkerError)
    }

    /// Processes one exact unknown-effect reconciliation without another mutation send.
    pub fn process_reconciliation(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        expected: Option<ExpectedRevision>,
    ) -> Result<EffectWorkerOutcome, EffectWorkerError> {
        let engine = self.engine(tenant_id.clone())?;
        let record = engine.get(effect_id).map_err(|_error| EffectWorkerError)?;
        if record.state != EffectState::Unknown {
            return Ok(EffectWorkerOutcome::AlreadyComplete);
        }
        if expected.is_some_and(|expected| expected.0 != record.effect_version) {
            return Err(EffectWorkerError);
        }
        if !self.reconciliation_supported(&record) {
            return Ok(EffectWorkerOutcome::AlreadyComplete);
        }
        if !self.dispatch_gate.dispatch_claims_allowed() {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        let now = self.clock.now().map_err(|_error| EffectWorkerError)?;
        if !reconciliation_is_due(&record, now) {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        let authorization = self
            .authority
            .authorize(tenant_id, EffectWorkerAction::Reconcile, &record, now)
            .map_err(|_error| EffectWorkerError)?;
        if authorization.now != now {
            return Err(EffectWorkerError);
        }
        if !authorization.permits_reconciliation() {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        self.argument_vault
            .stage(tenant_id, &record.intent)
            .map_err(|_error| EffectWorkerError)?;
        let current_now = self.clock.now().map_err(|_error| EffectWorkerError)?;
        if current_now < now {
            return Err(EffectWorkerError);
        }
        let current_authorization = self
            .authority
            .authorize(
                tenant_id,
                EffectWorkerAction::Reconcile,
                &record,
                current_now,
            )
            .map_err(|_error| EffectWorkerError)?;
        if current_authorization.now != current_now
            || current_authorization.actor_id != authorization.actor_id
        {
            return Err(EffectWorkerError);
        }
        if !current_authorization.permits_reconciliation() {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        if !self.dispatch_gate.begin_dispatch_send() {
            return Ok(EffectWorkerOutcome::Deferred);
        }
        engine
            .reconcile(
                effect_id,
                record.effect_version,
                self.id()?,
                self.id()?,
                &current_authorization,
            )
            .map(|_record| EffectWorkerOutcome::Advanced)
            .map_err(|_error| EffectWorkerError)
    }
}

fn dispatch_can_enter_connector(
    record: &DurableEffectRecord,
    authorization: &EffectAuthorization,
) -> Result<bool, EffectWorkerError> {
    let attempt = record.attempts.last().ok_or(EffectWorkerError)?;
    Ok(authorization.permits_dispatch(&record.intent)
        && authorization.now >= record.intent.created_at
        && authorization.now < record.intent.expires_at
        && authorization.now < attempt.deadline
        && record
            .approval
            .as_ref()
            .is_none_or(|approval| authorization.now < approval.expires_at))
}

fn reconciliation_is_due(record: &DurableEffectRecord, now: UtcTimestamp) -> bool {
    match record.reconciliations.last() {
        None => true,
        Some(report) if report.outcome == ReconciliationOutcome::Inconclusive => report
            .certainty_window_end
            .is_some_and(|window_end| now >= window_end),
        Some(_terminal_observation) => false,
    }
}

/// Server-owned protocol identity source.
pub trait ApplicationIdGenerator: Send + Sync {
    /// Generates one new UUIDv7 protocol record identity.
    fn generate(&self) -> Result<RecordId, ApplicationIdError>;
}

/// Content-free application identity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationIdError;

impl fmt::Display for ApplicationIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("server identity generation failed")
    }
}

impl std::error::Error for ApplicationIdError {}

/// Production monotonic UUIDv7 identity source.
#[derive(Default)]
pub struct MonotonicApplicationIds {
    inner: MonotonicUuidV7Generator,
}

impl ApplicationIdGenerator for MonotonicApplicationIds {
    fn generate(&self) -> Result<RecordId, ApplicationIdError> {
        let generated = self.inner.generate().map_err(|_error| ApplicationIdError)?;
        RecordId::new(generated.to_string()).map_err(|_error| ApplicationIdError)
    }
}

impl fmt::Debug for MonotonicApplicationIds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MonotonicApplicationIds([SERVER-RANDOM])")
    }
}

/// Complete dependencies for the six effect handlers.
pub struct EffectServiceDependencies<R: Repository> {
    /// Shared durable effect repository.
    pub repository: Arc<R>,
    /// Durable authenticated-subject to domain-identity resolver.
    pub identities: Arc<dyn DomainIdentityResolver>,
    /// Current policy and effective-capability evaluator.
    pub policy: Arc<dyn EffectPolicyEvaluator>,
    /// Trusted server clock.
    pub clock: Arc<dyn AuthorityClock>,
    /// Trusted server identity source.
    pub ids: Arc<dyn ApplicationIdGenerator>,
    /// Shutdown/readiness dispatch gate.
    pub dispatch_gate: Arc<dyn EffectDispatchGate>,
    /// Best-effort bounded wakeup queue for already durable outbox claims.
    pub dispatch_queue: Arc<dyn EffectDispatchQueue>,
    /// Tenant-scoped protected-argument validator; API handlers never stage connector arguments.
    pub argument_vault: Arc<dyn EffectArgumentVault>,
    /// Bounded blocking pool used for connector and reconciliation boundaries.
    pub blocking_pool: BlockingPool,
    /// Immutable registered connector set.
    pub connectors: Vec<Arc<dyn EffectConnector>>,
    /// Content-safe public error factory.
    pub errors: Arc<dyn FacadeErrorFactory>,
}

/// Typed implementation of all six frozen EffectService operations.
pub struct EffectServiceHandlers<R: Repository> {
    repository: Arc<R>,
    authenticator: Option<Arc<dyn EffectRecordAuthenticator>>,
    identities: Arc<dyn DomainIdentityResolver>,
    policy: Arc<dyn EffectPolicyEvaluator>,
    clock: Arc<dyn AuthorityClock>,
    ids: Arc<dyn ApplicationIdGenerator>,
    dispatch_gate: Arc<dyn EffectDispatchGate>,
    dispatch_queue: Arc<dyn EffectDispatchQueue>,
    argument_vault: Arc<dyn EffectArgumentVault>,
    blocking_pool: BlockingPool,
    connectors: Vec<Arc<dyn EffectConnector>>,
    descriptors: BTreeMap<String, ConnectorDescriptor>,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl<R: Repository + 'static> EffectServiceHandlers<R> {
    /// Validates and constructs the complete effect handler family.
    pub fn new(
        dependencies: EffectServiceDependencies<R>,
    ) -> Result<Self, EffectReplayAdapterBuildError> {
        Self::build(dependencies, None)
    }

    /// Constructs the handler family with one shared tenant-key record authenticator.
    pub fn new_with_authenticator(
        dependencies: EffectServiceDependencies<R>,
        authenticator: Arc<dyn EffectRecordAuthenticator>,
    ) -> Result<Self, EffectReplayAdapterBuildError> {
        Self::build(dependencies, Some(authenticator))
    }

    fn build(
        dependencies: EffectServiceDependencies<R>,
        authenticator: Option<Arc<dyn EffectRecordAuthenticator>>,
    ) -> Result<Self, EffectReplayAdapterBuildError> {
        let mut descriptors = BTreeMap::new();
        for connector in &dependencies.connectors {
            let descriptor = catch_unwind(AssertUnwindSafe(|| connector.descriptor()))
                .map_err(|_panic| EffectReplayAdapterBuildError::InvalidConnectorSet)?;
            descriptor
                .validate()
                .map_err(|_error| EffectReplayAdapterBuildError::InvalidConnectorSet)?;
            if descriptors
                .insert(descriptor.connector.clone(), descriptor)
                .is_some()
            {
                return Err(EffectReplayAdapterBuildError::InvalidConnectorSet);
            }
        }
        Ok(Self {
            repository: dependencies.repository,
            authenticator,
            identities: dependencies.identities,
            policy: dependencies.policy,
            clock: dependencies.clock,
            ids: dependencies.ids,
            dispatch_gate: dependencies.dispatch_gate,
            dispatch_queue: dependencies.dispatch_queue,
            argument_vault: dependencies.argument_vault,
            blocking_pool: dependencies.blocking_pool,
            connectors: dependencies.connectors,
            descriptors,
            errors: dependencies.errors,
        })
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.errors.public_error(code)
    }

    fn now_active(&self, context: &RequestContext) -> Result<UtcTimestamp, ApiError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| self.public_error(ErrorCode::Internal))?;
        context
            .check_active(now)
            .map_err(|_error| self.public_error(ErrorCode::DeadlineExceeded))?;
        Ok(now)
    }

    fn resolve_identity(
        &self,
        context: &RequestContext,
    ) -> Result<ResolvedDomainIdentity, ApiError> {
        self.identities
            .resolve(context)
            .map_err(|error| self.map_identity_error(error))
    }

    fn map_identity_error(&self, error: DomainIdentityError) -> ApiError {
        let code = match error.code() {
            crate::domain_identity::DomainIdentityErrorCode::Cancelled => {
                ErrorCode::DeadlineExceeded
            }
            crate::domain_identity::DomainIdentityErrorCode::InvalidMapping => {
                ErrorCode::IntegrityFailure
            }
            crate::domain_identity::DomainIdentityErrorCode::Unavailable => {
                ErrorCode::DependencyUnavailable
            }
        };
        self.public_error(code)
    }

    fn engine(&self, tenant_id: RecordId) -> Result<EffectEngine<R>, ApiError> {
        let access = AccessContext::new(tenant_id, EFFECT_ACCESS_PURPOSE)
            .map_err(|_error| self.public_error(ErrorCode::Internal))?;
        let engine = match &self.authenticator {
            Some(authenticator) => EffectEngine::new_with_authenticator(
                Arc::clone(&self.repository),
                access,
                Arc::clone(authenticator),
            ),
            None => EffectEngine::new(Arc::clone(&self.repository), access),
        };
        for connector in &self.connectors {
            engine
                .register_connector(Arc::clone(connector))
                .map_err(|error| self.map_effect_error(error, false))?;
        }
        Ok(engine)
    }

    fn authorization(
        &self,
        context: &RequestContext,
        identity: &ResolvedDomainIdentity,
        action: EffectPolicyAction,
        intent: &EffectIntent,
        approval_kind: Option<ApprovalKind>,
        now: UtcTimestamp,
    ) -> Result<EffectAuthorization, ApiError> {
        let decision = self
            .policy
            .evaluate(context, identity, action, intent, approval_kind)
            .map_err(|_error| self.public_error(ErrorCode::DependencyUnavailable))?;
        if !decision.policy_allows {
            return Err(self.public_error(ErrorCode::PolicyDenied));
        }
        Ok(decision.into_authorization(identity.principal_id.clone(), now))
    }

    fn id(&self) -> Result<RecordId, ApiError> {
        self.ids
            .generate()
            .map_err(|_error| self.public_error(ErrorCode::Internal))
    }

    fn expected_revision(&self, value: Option<&str>) -> Result<u64, ApiError> {
        let value = value.ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))?;
        let value = match value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        {
            Some(unquoted) => unquoted,
            None if !value.starts_with('"') && !value.ends_with('"') => value,
            None => return Err(self.public_error(ErrorCode::InvalidArgument)),
        };
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(self.public_error(ErrorCode::InvalidArgument));
        }
        value
            .parse::<u64>()
            .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))
    }

    fn project(&self, record: &DurableEffectRecord) -> Result<EffectStatusResponse, ApiError> {
        Ok(EffectStatusResponse {
            effect_id: record.intent.effect_id.clone(),
            state: record.state,
            effect_version: record.effect_version,
            intent_digest: record.intent_digest.clone(),
            attempt_count: u32::try_from(record.attempts.len())
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            reconciliation_count: u32::try_from(record.reconciliations.len())
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
        })
    }

    fn response(
        &self,
        record: &DurableEffectRecord,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        Ok(TypedResponse {
            payload: self.project(record)?,
            semantic_etag: Some(format!("\"{}\"", record.effect_version)),
            next_page_cursor: None,
        })
    }

    fn map_effect_error(&self, error: EffectError, existence_hidden: bool) -> ApiError {
        let code = match error.code() {
            EffectErrorCode::InvalidInput | EffectErrorCode::InvalidTransition => {
                ErrorCode::InvalidArgument
            }
            EffectErrorCode::NotFound if existence_hidden => ErrorCode::PolicyDenied,
            EffectErrorCode::NotFound => ErrorCode::PolicyDenied,
            EffectErrorCode::Unauthorized => ErrorCode::PolicyDenied,
            EffectErrorCode::RevisionConflict | EffectErrorCode::IdempotencyCollision => {
                ErrorCode::RevisionConflict
            }
            EffectErrorCode::UnsafeRetry => ErrorCode::UnsafeRetry,
            EffectErrorCode::CorruptJournal => ErrorCode::IntegrityFailure,
            EffectErrorCode::Expired => ErrorCode::ApprovalStale,
            EffectErrorCode::Cancelled => ErrorCode::DeadlineExceeded,
            EffectErrorCode::Unavailable => ErrorCode::DependencyUnavailable,
            EffectErrorCode::LimitExceeded => ErrorCode::LimitExceeded,
        };
        self.public_error(code)
    }

    fn map_argument_vault_error(&self, error: EffectArgumentVaultError) -> ApiError {
        let code = match error {
            EffectArgumentVaultError::InvalidArguments | EffectArgumentVaultError::NotFound => {
                ErrorCode::InvalidArgument
            }
            EffectArgumentVaultError::LimitExceeded => ErrorCode::LimitExceeded,
            EffectArgumentVaultError::Unavailable => ErrorCode::DependencyUnavailable,
        };
        self.public_error(code)
    }

    fn map_blocking_error(&self, error: BlockingPoolError) -> ApiError {
        let code = match error.code() {
            BlockingPoolErrorCode::Exhausted => ErrorCode::RateLimited,
            BlockingPoolErrorCode::NotAccepting => ErrorCode::DependencyDegraded,
            BlockingPoolErrorCode::Cancelled | BlockingPoolErrorCode::DeadlineExceeded => {
                ErrorCode::DeadlineExceeded
            }
            BlockingPoolErrorCode::TaskFailed => ErrorCode::Internal,
        };
        self.public_error(code)
    }

    fn map_effect_blocking_failure(&self, error: EffectBlockingFailure) -> ApiError {
        match error {
            EffectBlockingFailure::Effect(error) => self.map_effect_error(error, false),
            EffectBlockingFailure::Public(code) => self.public_error(code),
        }
    }

    fn blocking_deadline(
        &self,
        context: &RequestContext,
        now: UtcTimestamp,
    ) -> Result<tokio::time::Instant, ApiError> {
        let remaining = context
            .deadline()
            .unix_nanos()
            .checked_sub(now.unix_nanos())
            .filter(|value| *value > 0)
            .ok_or_else(|| self.public_error(ErrorCode::DeadlineExceeded))?;
        let remaining = u64::try_from(remaining)
            .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?;
        tokio::time::Instant::now()
            .checked_add(Duration::from_nanos(remaining))
            .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))
    }

    fn prepare_intent(
        &self,
        request: PrepareEffectRequest,
        idempotency_key: Option<&str>,
        now: UtcTimestamp,
    ) -> Result<EffectIntent, ApiError> {
        let key = idempotency_key
            .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))
            .and_then(|value| {
                IdempotencyKey::new(value.to_owned())
                    .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))
            })?;
        let expiry_nanos = now
            .unix_nanos()
            .checked_add(i128::from(request.ttl_seconds) * 1_000_000_000)
            .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
        let expires_at = UtcTimestamp::from_unix_nanos(expiry_nanos)
            .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?;
        let intent = EffectIntent {
            schema_version: SchemaVersion::new("cigar.effect-intent", 1)
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            effect_id: self.id()?,
            connector: request.connector,
            operation: request.operation,
            arguments_digest: request.arguments_digest,
            encrypted_arguments: request.encrypted_arguments,
            target: request.target,
            preconditions: request.preconditions,
            result_schema_digest: request.result_schema_digest,
            risk: request.risk,
            source_decision_id: request.source_decision_id,
            bundle_id: request.bundle_id,
            required_capability: request.required_capability,
            idempotency_scope: request.idempotency_scope,
            idempotency_key: key,
            retry_policy: request.retry_policy,
            created_at: now,
            expires_at,
            compensation: request.compensation,
            extensions: ExtensionMap::default(),
        };
        intent
            .validate()
            .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))?;
        Ok(intent)
    }

    fn validate_connector_intent(&self, intent: &EffectIntent) -> Result<(), ApiError> {
        let descriptor = self
            .descriptors
            .get(&intent.connector)
            .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))?;
        let operation = descriptor
            .operation(&intent.operation)
            .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))?;
        let retry_supported = match intent.retry_policy {
            RetryPolicy::Never => true,
            RetryPolicy::SameKeyIdempotent { .. } => operation.same_key_idempotent,
            RetryPolicy::ReconcileBeforeRetry => operation.supports_reconciliation,
        };
        let compensation_supported = intent.compensation.as_ref().is_none_or(|compensation| {
            operation.supports_compensation
                && descriptor.operation(&compensation.operation).is_some()
        });
        if retry_supported && compensation_supported {
            Ok(())
        } else {
            Err(self.public_error(ErrorCode::InvalidArgument))
        }
    }

    async fn prepare_effect(
        &self,
        context: RequestContext,
        request: TypedRequest<PrepareEffectRequest>,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let intent =
            self.prepare_intent(request.payload, request.metadata.idempotency_key(), now)?;
        self.validate_connector_intent(&intent)?;
        let authorization = self.authorization(
            &context,
            &identity,
            EffectPolicyAction::Prepare,
            &intent,
            None,
            now,
        )?;
        if !authorization.permits_proposal() {
            return Err(self.public_error(ErrorCode::InvalidCapability));
        }
        self.argument_vault
            .validate(&identity.tenant_id, &intent)
            .map_err(|error| self.map_argument_vault_error(error))?;
        if request.metadata.dry_run() {
            let digest = effect_intent_digest(&intent)
                .map_err(|error| self.map_effect_error(error, false))?;
            return Ok(TypedResponse::new(EffectStatusResponse {
                effect_id: intent.effect_id,
                state: EffectState::Prepared,
                effect_version: 0,
                intent_digest: digest,
                attempt_count: 0,
                reconciliation_count: 0,
            }));
        }
        let engine = self.engine(identity.tenant_id)?;
        let record = engine
            .prepare(intent, &authorization)
            .map_err(|error| self.map_effect_error(error, false))?;
        self.response(&record)
    }

    fn build_approval(
        &self,
        record: &DurableEffectRecord,
        request: &AuthorizeEffectRequest,
        actor_id: &RecordId,
        now: UtcTimestamp,
    ) -> Result<Option<EffectApproval>, ApiError> {
        let Some(draft) = &request.approval else {
            return Ok(None);
        };
        let requested_expiry = now
            .unix_nanos()
            .checked_add(i128::from(draft.ttl_seconds) * 1_000_000_000)
            .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
        let expiry = requested_expiry.min(record.intent.expires_at.unix_nanos());
        let approval = EffectApproval {
            schema_version: SchemaVersion::new("cigar.effect-approval", 1)
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            approval_id: draft.approval_id.clone(),
            effect_id: record.intent.effect_id.clone(),
            intent_digest: record.intent_digest.clone(),
            target_digest: effect_target_digest(&record.intent.target)
                .map_err(|error| self.map_effect_error(error, false))?,
            risk: record.intent.risk,
            bundle_id: record.intent.bundle_id.clone(),
            conditions_digest: draft.conditions_digest.clone(),
            approver_id: actor_id.clone(),
            kind: draft.kind,
            approved_at: now,
            expires_at: UtcTimestamp::from_unix_nanos(expiry)
                .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?,
        };
        approval
            .validate()
            .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))?;
        Ok(Some(approval))
    }

    async fn authorize_effect(
        &self,
        context: RequestContext,
        request: TypedRequest<AuthorizeEffectRequest>,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let engine = self.engine(identity.tenant_id.clone())?;
        let current = engine
            .get(&request.payload.effect_id)
            .map_err(|error| self.map_effect_error(error, true))?;
        let expected = self.expected_revision(request.metadata.expected_revision())?;
        if current.effect_version != expected {
            return Err(self.public_error(ErrorCode::RevisionConflict));
        }
        let approval_kind = request.payload.approval.as_ref().map(|draft| draft.kind);
        let authorization = self.authorization(
            &context,
            &identity,
            EffectPolicyAction::Authorize,
            &current.intent,
            approval_kind,
            now,
        )?;
        let approval =
            self.build_approval(&current, &request.payload, &identity.principal_id, now)?;
        if request.metadata.dry_run() {
            validate_authorization_preview(&current, approval.as_ref(), &authorization)
                .map_err(|error| self.map_effect_error(error, false))?;
            let mut projected = self.project(&current)?;
            projected.state = EffectState::Authorized;
            projected.effect_version = projected
                .effect_version
                .checked_add(1)
                .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
            return Ok(TypedResponse::new(projected));
        }
        let record = engine
            .authorize(
                &request.payload.effect_id,
                expected,
                self.id()?,
                approval,
                &authorization,
            )
            .map_err(|error| self.map_effect_error(error, false))?;
        self.response(&record)
    }

    async fn dispatch_effect(
        &self,
        context: RequestContext,
        request: TypedRequest<EffectIdRequest>,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let engine = self.engine(identity.tenant_id.clone())?;
        let current = engine
            .get(&request.payload.effect_id)
            .map_err(|error| self.map_effect_error(error, true))?;
        let expected = self.expected_revision(request.metadata.expected_revision())?;
        if current.effect_version != expected {
            return Err(self.public_error(ErrorCode::RevisionConflict));
        }
        if !self.dispatch_gate.dispatch_claims_allowed() {
            return Err(self.public_error(ErrorCode::DependencyDegraded));
        }
        let authorization = self.authorization(
            &context,
            &identity,
            EffectPolicyAction::Dispatch,
            &current.intent,
            None,
            now,
        )?;
        validate_dispatch_preview(&current, &authorization)
            .map_err(|error| self.map_effect_error(error, false))?;
        if request.metadata.dry_run() {
            let mut projected = self.project(&current)?;
            projected.state = EffectState::Dispatching;
            projected.effect_version = projected
                .effect_version
                .checked_add(1)
                .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
            projected.attempt_count = projected
                .attempt_count
                .checked_add(1)
                .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
            return Ok(TypedResponse::new(projected));
        }
        let descriptor = self
            .descriptors
            .get(&current.intent.connector)
            .ok_or_else(|| self.public_error(ErrorCode::InvalidArgument))?;
        let maximum = i128::from(descriptor.maximum_dispatch_nanos);
        let deadline_nanos = now
            .unix_nanos()
            .checked_add(maximum)
            .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?
            .min(context.deadline().unix_nanos())
            .min(current.intent.expires_at.unix_nanos());
        let deadline = UtcTimestamp::from_unix_nanos(deadline_nanos)
            .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?;
        let _permit = engine
            .claim_dispatch(
                &request.payload.effect_id,
                expected,
                self.id()?,
                self.id()?,
                self.id()?,
                deadline,
                &authorization,
            )
            .map_err(|error| self.map_effect_error(error, false))?;
        let record = engine
            .get(&request.payload.effect_id)
            .map_err(|error| self.map_effect_error(error, false))?;
        let job = WorkerJob {
            tenant: TenantId::new(identity.tenant_id.as_str())
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            record_id: record.intent.effect_id.clone(),
            expected_revision: Some(ExpectedRevision(record.effect_version)),
        };
        // The queue is only a latency hint. Its own failure closes readiness, while the committed
        // effect outbox remains authoritative for the worker's bounded durable idle scan.
        let _queue_result = self.dispatch_queue.enqueue(job);
        self.response(&record)
    }

    async fn get_effect_status(
        &self,
        context: RequestContext,
        request: TypedRequest<EffectIdRequest>,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let engine = self.engine(identity.tenant_id.clone())?;
        let record = engine
            .get(&request.payload.effect_id)
            .map_err(|error| self.map_effect_error(error, true))?;
        let _authorization = self.authorization(
            &context,
            &identity,
            EffectPolicyAction::Read,
            &record.intent,
            None,
            now,
        )?;
        self.response(&record)
    }

    async fn reconcile_effect(
        &self,
        context: RequestContext,
        request: TypedRequest<EffectIdRequest>,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let engine = self.engine(identity.tenant_id.clone())?;
        let current = engine
            .get(&request.payload.effect_id)
            .map_err(|error| self.map_effect_error(error, true))?;
        let expected = self.expected_revision(request.metadata.expected_revision())?;
        if current.effect_version != expected {
            return Err(self.public_error(ErrorCode::RevisionConflict));
        }
        let authorization = self.authorization(
            &context,
            &identity,
            EffectPolicyAction::Reconcile,
            &current.intent,
            None,
            now,
        )?;
        validate_reconciliation_preview(&current, &authorization, &self.descriptors)
            .map_err(|error| self.map_effect_error(error, false))?;
        if request.metadata.dry_run() {
            return self.response(&current);
        }
        let effect_id = request.payload.effect_id;
        let report_id = self.id()?;
        let event_id = self.id()?;
        let cancellation = context.cancellation().clone();
        let blocking_deadline = self.blocking_deadline(&context, now)?;
        let blocking_context = context.clone();
        let blocking_identity = identity;
        let blocking_intent = current.intent.clone();
        let blocking_clock = Arc::clone(&self.clock);
        let blocking_policy = Arc::clone(&self.policy);
        let result = self
            .blocking_pool
            .run(cancellation, blocking_deadline, move |cancellation| {
                if cancellation.is_cancelled() {
                    return Err(EffectBlockingFailure::Effect(EffectError::new(
                        EffectErrorCode::Cancelled,
                    )));
                }
                let current_now = blocking_clock
                    .now()
                    .map_err(|_error| EffectBlockingFailure::Public(ErrorCode::Internal))?;
                blocking_context
                    .check_active(current_now)
                    .map_err(|_error| EffectBlockingFailure::Public(ErrorCode::DeadlineExceeded))?;
                let decision = blocking_policy
                    .evaluate(
                        &blocking_context,
                        &blocking_identity,
                        EffectPolicyAction::Reconcile,
                        &blocking_intent,
                        None,
                    )
                    .map_err(|_error| {
                        EffectBlockingFailure::Public(ErrorCode::DependencyUnavailable)
                    })?;
                if !decision.policy_allows {
                    return Err(EffectBlockingFailure::Public(ErrorCode::PolicyDenied));
                }
                let current_authorization =
                    decision.into_authorization(blocking_identity.principal_id, current_now);
                engine
                    .reconcile(
                        &effect_id,
                        expected,
                        report_id,
                        event_id,
                        &current_authorization,
                    )
                    .map_err(EffectBlockingFailure::Effect)
            })
            .await
            .map_err(|error| self.map_blocking_error(error))?;
        let record = result.map_err(|error| self.map_effect_blocking_failure(error))?;
        self.response(&record)
    }

    async fn compensate_effect(
        &self,
        context: RequestContext,
        request: TypedRequest<CompensateEffectRequest>,
    ) -> Result<TypedResponse<EffectStatusResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let engine = self.engine(identity.tenant_id.clone())?;
        let original = engine
            .get(&request.payload.effect_id)
            .map_err(|error| self.map_effect_error(error, true))?;
        let child = engine
            .get(&request.payload.compensation_effect_id)
            .map_err(|error| self.map_effect_error(error, true))?;
        let expected = self.expected_revision(request.metadata.expected_revision())?;
        if original.effect_version != expected {
            return Err(self.public_error(ErrorCode::RevisionConflict));
        }
        let authorization = self.authorization(
            &context,
            &identity,
            EffectPolicyAction::Compensate,
            &original.intent,
            None,
            now,
        )?;
        let link = CompensationLink {
            schema_version: SchemaVersion::new("cigar.compensation-link", 1)
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            original_effect_id: request.payload.effect_id.clone(),
            compensation_effect_id: request.payload.compensation_effect_id.clone(),
            compensation_spec_digest: request.payload.compensation_spec_digest,
            created_at: now,
        };
        validate_authorized_compensation_preview(&original, &child, &link, &authorization)
            .map_err(|error| self.map_effect_error(error, false))?;
        if request.metadata.dry_run() {
            let mut projected = self.project(&original)?;
            projected.state = EffectState::CompensationPending;
            projected.effect_version = projected
                .effect_version
                .checked_add(1)
                .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))?;
            return Ok(TypedResponse::new(projected));
        }
        let record = engine
            .request_authorized_compensation(
                &request.payload.effect_id,
                expected,
                self.id()?,
                &authorization,
                link,
            )
            .map_err(|error| self.map_effect_error(error, false))?;
        self.response(&record)
    }
}

impl<R: Repository + 'static> fmt::Debug for EffectServiceHandlers<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectServiceHandlers")
            .field("repository", &"[INJECTED]")
            .field("connector_count", &self.connectors.len())
            .field("policy", &"[INJECTED]")
            .finish_non_exhaustive()
    }
}

fn validate_authorization_preview(
    record: &DurableEffectRecord,
    approval: Option<&EffectApproval>,
    authorization: &EffectAuthorization,
) -> Result<(), EffectError> {
    if !record.state.can_transition_to(EffectState::Authorized)
        || !authorization.permits_dispatch(&record.intent)
        || authorization.now < record.intent.created_at
        || authorization.now >= record.intent.expires_at
    {
        return Err(EffectError::new(EffectErrorCode::Unauthorized));
    }
    match approval {
        Some(approval)
            if approval.effect_id == record.intent.effect_id
                && approval.intent_digest == record.intent_digest
                && approval.target_digest == effect_target_digest(&record.intent.target)?
                && approval.risk == record.intent.risk
                && approval.bundle_id == record.intent.bundle_id
                && authorization.now >= approval.approved_at
                && authorization.now < approval.expires_at
                && (!matches!(record.intent.risk, RiskLevel::High | RiskLevel::Critical)
                    || approval.kind == ApprovalKind::Human) =>
        {
            Ok(())
        }
        None if record.intent.risk == RiskLevel::Low => Ok(()),
        Some(_) | None => Err(EffectError::new(EffectErrorCode::Unauthorized)),
    }
}

fn validate_dispatch_preview(
    record: &DurableEffectRecord,
    authorization: &EffectAuthorization,
) -> Result<(), EffectError> {
    if !authorization.permits_dispatch(&record.intent)
        || authorization.now < record.intent.created_at
        || authorization.now >= record.intent.expires_at
        || record
            .approval
            .as_ref()
            .is_some_and(|approval| authorization.now >= approval.expires_at)
    {
        return Err(EffectError::new(EffectErrorCode::Unauthorized));
    }
    match record.state {
        EffectState::Authorized if record.attempts.is_empty() => Ok(()),
        EffectState::AuthorizedForRetry => match record.intent.retry_policy {
            RetryPolicy::Never => Err(EffectError::new(EffectErrorCode::UnsafeRetry)),
            RetryPolicy::SameKeyIdempotent { max_attempts }
                if usize::from(max_attempts) > record.attempts.len() =>
            {
                Ok(())
            }
            RetryPolicy::ReconcileBeforeRetry
                if record.reconciliations.last().is_some_and(|report| {
                    report.outcome == cigar_protocol::ReconciliationOutcome::ProvenNotExecuted
                }) =>
            {
                Ok(())
            }
            RetryPolicy::SameKeyIdempotent { .. } | RetryPolicy::ReconcileBeforeRetry => {
                Err(EffectError::new(EffectErrorCode::UnsafeRetry))
            }
        },
        EffectState::Authorized => Err(EffectError::new(EffectErrorCode::CorruptJournal)),
        _ => Err(EffectError::new(EffectErrorCode::InvalidTransition)),
    }
}

fn validate_reconciliation_preview(
    record: &DurableEffectRecord,
    authorization: &EffectAuthorization,
    descriptors: &BTreeMap<String, ConnectorDescriptor>,
) -> Result<(), EffectError> {
    let operation = descriptors
        .get(&record.intent.connector)
        .and_then(|descriptor| descriptor.operation(&record.intent.operation))
        .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidInput))?;
    if record.state != EffectState::Unknown || !authorization.permits_reconciliation() {
        Err(EffectError::new(EffectErrorCode::Unauthorized))
    } else if record.attempts.is_empty() {
        Err(EffectError::new(EffectErrorCode::CorruptJournal))
    } else if !operation.supports_reconciliation {
        Err(EffectError::new(EffectErrorCode::UnsafeRetry))
    } else {
        Ok(())
    }
}

fn validate_authorized_compensation_preview(
    original: &DurableEffectRecord,
    child: &DurableEffectRecord,
    link: &CompensationLink,
    authorization: &EffectAuthorization,
) -> Result<(), EffectError> {
    link.validate()
        .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
    let compensation = original
        .intent
        .compensation
        .as_ref()
        .ok_or_else(|| EffectError::new(EffectErrorCode::InvalidTransition))?;
    if !original
        .state
        .can_transition_to(EffectState::CompensationPending)
        || link.original_effect_id != original.intent.effect_id
        || link.compensation_effect_id != child.intent.effect_id
        || link.compensation_spec_digest != compensation_spec_digest(compensation)?
        || link.created_at > authorization.now
        || !authorization.permits_dispatch(&original.intent)
        || child.state != EffectState::Authorized
        || child.intent.connector != original.intent.connector
        || child.intent.operation != compensation.operation
        || child.intent.arguments_digest != compensation.arguments_digest
        || child.intent.encrypted_arguments != compensation.encrypted_arguments
    {
        Err(EffectError::new(EffectErrorCode::Unauthorized))
    } else {
        Ok(())
    }
}

impl<R: Repository + 'static> TypedUnaryService<PrepareEffectOperation>
    for EffectServiceHandlers<R>
{
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<PrepareEffectRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<EffectStatusResponse>, ApiError>> {
        Box::pin(async move { self.prepare_effect(context, request).await })
    }
}

impl<R: Repository + 'static> TypedUnaryService<AuthorizeEffectOperation>
    for EffectServiceHandlers<R>
{
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<AuthorizeEffectRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<EffectStatusResponse>, ApiError>> {
        Box::pin(async move { self.authorize_effect(context, request).await })
    }
}

impl<R: Repository + 'static> TypedUnaryService<DispatchEffectOperation>
    for EffectServiceHandlers<R>
{
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<EffectIdRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<EffectStatusResponse>, ApiError>> {
        Box::pin(async move { self.dispatch_effect(context, request).await })
    }
}

impl<R: Repository + 'static> TypedUnaryService<GetEffectStatusOperation>
    for EffectServiceHandlers<R>
{
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<EffectIdRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<EffectStatusResponse>, ApiError>> {
        Box::pin(async move { self.get_effect_status(context, request).await })
    }
}

impl<R: Repository + 'static> TypedUnaryService<ReconcileEffectOperation>
    for EffectServiceHandlers<R>
{
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<EffectIdRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<EffectStatusResponse>, ApiError>> {
        Box::pin(async move { self.reconcile_effect(context, request).await })
    }
}

impl<R: Repository + 'static> TypedUnaryService<CompensateEffectOperation>
    for EffectServiceHandlers<R>
{
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<CompensateEffectRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<EffectStatusResponse>, ApiError>> {
        Box::pin(async move { self.compensate_effect(context, request).await })
    }
}

/// Stable durable-live-authorization repository failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveAuthorizationRepositoryError {
    /// The trusted issuer supplied a malformed record.
    InvalidInput,
    /// The authorization is absent in the exact tenant scope.
    NotFound,
    /// The identity was already bound to different authorization semantics.
    Conflict,
    /// Cooperative storage cancellation was observed.
    Cancelled,
    /// Durable storage was unavailable or contained an invalid record.
    Unavailable,
}

impl fmt::Display for LiveAuthorizationRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("live replay authorization repository operation failed")
    }
}

impl std::error::Error for LiveAuthorizationRepositoryError {}

/// Tenant-scoped lookup boundary for separately issued live replay authorizations.
pub trait LiveReplayAuthorizationRepository: Send + Sync {
    /// Loads one exact persisted authorization by its server-issued identity.
    fn get(
        &self,
        tenant_id: &RecordId,
        authorization_id: &RecordId,
        cancellation: &StoreCancellation,
    ) -> Result<LiveReplayAuthorization, LiveAuthorizationRepositoryError>;
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedLiveAuthorization {
    schema_version: String,
    authorization_id: RecordId,
    authorization: LiveReplayAuthorization,
}

impl PersistedLiveAuthorization {
    fn validate(&self) -> Result<(), LiveAuthorizationRepositoryError> {
        let authorization = &self.authorization;
        if self.schema_version != LIVE_AUTHORIZATION_SCHEMA
            || authorization
                .schema_version
                .require_v1("cigar.live-replay-authorization")
                .is_err()
            || authorization.expires_at < authorization.not_before
            || authorization.authorized_effect_intents.len()
                > cigar_protocol::limits::MAX_REPLAY_REFERENCES
            || !authorization
                .authorized_effect_intents
                .windows(2)
                .all(|window| window.first() < window.get(1))
        {
            Err(LiveAuthorizationRepositoryError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

/// Durable tenant-partitioned repository for separately issued live replay authorizations.
pub struct DurableLiveReplayAuthorizationRepository {
    repository: Arc<dyn ServiceRepository>,
}

impl DurableLiveReplayAuthorizationRepository {
    /// Creates the repository over the shared durable service-record store.
    #[must_use]
    pub fn new(repository: Arc<dyn ServiceRepository>) -> Self {
        Self { repository }
    }

    /// Persists an authorization produced and verified by a trusted issuance path.
    ///
    /// Repeating the exact same identity and authorization is idempotent. Binding the identity to
    /// different semantics fails closed and never overwrites the first record.
    pub fn persist_issued(
        &self,
        tenant_id: RecordId,
        authorization_id: RecordId,
        authorization: LiveReplayAuthorization,
        cancellation: &StoreCancellation,
    ) -> Result<(), LiveAuthorizationRepositoryError> {
        if cancellation.is_cancelled() {
            return Err(LiveAuthorizationRepositoryError::Cancelled);
        }
        let record = PersistedLiveAuthorization {
            schema_version: LIVE_AUTHORIZATION_SCHEMA.to_owned(),
            authorization_id: authorization_id.clone(),
            authorization,
        };
        record.validate()?;
        let bytes = serde_json::to_vec(&record)
            .map_err(|_error| LiveAuthorizationRepositoryError::Unavailable)?;
        let write = ServiceRecordWrite::new(
            LIVE_AUTHORIZATION_NAMESPACE,
            authorization_id.as_str(),
            ServiceExpectedVersion::Absent,
            bytes,
        )
        .map_err(map_live_authorization_store_error)?;
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_live_authorization_store_error)?;
        let batch = ServiceBatch::new(tenant_id.clone(), vec![write], response)
            .map_err(map_live_authorization_store_error)?;
        match self.repository.service_commit(batch, cancellation) {
            Ok(_receipt) => Ok(()),
            Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                let existing = self.get(&tenant_id, &authorization_id, cancellation)?;
                if existing == record.authorization {
                    Ok(())
                } else {
                    Err(LiveAuthorizationRepositoryError::Conflict)
                }
            }
            Err(error) => Err(map_live_authorization_store_error(error)),
        }
    }

    fn load_record(
        &self,
        tenant_id: &RecordId,
        authorization_id: &RecordId,
        cancellation: &StoreCancellation,
    ) -> Result<PersistedLiveAuthorization, LiveAuthorizationRepositoryError> {
        let locator = ServiceRecordLocator::new(
            tenant_id.clone(),
            LIVE_AUTHORIZATION_NAMESPACE,
            authorization_id.as_str(),
        )
        .map_err(map_live_authorization_store_error)?;
        let item = self
            .repository
            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
            .map_err(map_live_authorization_store_error)?
            .ok_or(LiveAuthorizationRepositoryError::NotFound)?;
        cigar_canon::parse_strict_json(item.bytes())
            .map_err(|_error| LiveAuthorizationRepositoryError::Unavailable)?;
        let record: PersistedLiveAuthorization = serde_json::from_slice(item.bytes())
            .map_err(|_error| LiveAuthorizationRepositoryError::Unavailable)?;
        record
            .validate()
            .map_err(|_error| LiveAuthorizationRepositoryError::Unavailable)?;
        if &record.authorization_id != authorization_id {
            return Err(LiveAuthorizationRepositoryError::Unavailable);
        }
        Ok(record)
    }
}

impl LiveReplayAuthorizationRepository for DurableLiveReplayAuthorizationRepository {
    fn get(
        &self,
        tenant_id: &RecordId,
        authorization_id: &RecordId,
        cancellation: &StoreCancellation,
    ) -> Result<LiveReplayAuthorization, LiveAuthorizationRepositoryError> {
        self.load_record(tenant_id, authorization_id, cancellation)
            .map(|record| record.authorization)
    }
}

impl fmt::Debug for DurableLiveReplayAuthorizationRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableLiveReplayAuthorizationRepository")
            .field("repository", &"[INJECTED]")
            .finish()
    }
}

fn map_live_authorization_store_error(error: ServiceError) -> LiveAuthorizationRepositoryError {
    match error.code() {
        ServiceErrorCode::InvalidInput | ServiceErrorCode::LimitExceeded => {
            LiveAuthorizationRepositoryError::InvalidInput
        }
        ServiceErrorCode::NotFound => LiveAuthorizationRepositoryError::NotFound,
        ServiceErrorCode::RevisionConflict | ServiceErrorCode::IdempotencyConflict => {
            LiveAuthorizationRepositoryError::Conflict
        }
        ServiceErrorCode::Cancelled => LiveAuthorizationRepositoryError::Cancelled,
        ServiceErrorCode::CursorScopeMismatch
        | ServiceErrorCode::InjectedAbort
        | ServiceErrorCode::Unavailable => LiveAuthorizationRepositoryError::Unavailable,
    }
}

/// Tenant-bound live-only dependencies used to construct a replay engine.
pub struct ReplayLiveServices {
    /// Current signature, revocation, principal, and policy verifier.
    pub verifier: Arc<dyn LiveAuthorizationVerifier>,
    /// Explicit live model/tool/connector provider.
    pub provider: Arc<dyn LiveReplayProvider>,
    /// Independent authorization and dispatch boundary for new live effects.
    pub effect_gate: Arc<dyn LiveEffectGate>,
}

/// Content-free replay live-service construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayLiveServicesError;

impl fmt::Display for ReplayLiveServicesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tenant replay live services are unavailable")
    }
}

impl std::error::Error for ReplayLiveServicesError {}

/// Factory that binds all live replay boundaries to one server-resolved tenant.
pub trait ReplayLiveServicesFactory: Send + Sync {
    /// Returns the exact tenant-bound verifier, provider, and effect gate.
    fn for_tenant(
        &self,
        tenant_id: &RecordId,
    ) -> Result<ReplayLiveServices, ReplayLiveServicesError>;
}

/// Complete dependencies for the four replay handlers.
pub struct ReplayServiceDependencies {
    /// Shared durable service repository used by archive, jobs, reservations, and drafts.
    pub repository: Arc<dyn ServiceRepository>,
    /// Durable authenticated-subject to domain-identity resolver.
    pub identities: Arc<dyn DomainIdentityResolver>,
    /// Separately persisted live authorizations addressed only by server-issued ID.
    pub live_authorizations: Arc<dyn LiveReplayAuthorizationRepository>,
    /// Tenant-bound current live replay services.
    pub live_services: Arc<dyn ReplayLiveServicesFactory>,
    /// Trusted server clock.
    pub clock: Arc<dyn AuthorityClock>,
    /// Trusted server identity source.
    pub ids: Arc<dyn ApplicationIdGenerator>,
    /// Bounded blocking pool used for durable replay and every live provider boundary.
    pub blocking_pool: BlockingPool,
    /// Content-safe public error factory.
    pub errors: Arc<dyn FacadeErrorFactory>,
}

/// Typed implementation of all four frozen ReplayService operations.
pub struct ReplayServiceHandlers {
    repository: Arc<dyn ServiceRepository>,
    identities: Arc<dyn DomainIdentityResolver>,
    live_authorizations: Arc<dyn LiveReplayAuthorizationRepository>,
    live_services: Arc<dyn ReplayLiveServicesFactory>,
    clock: Arc<dyn AuthorityClock>,
    ids: Arc<dyn ApplicationIdGenerator>,
    blocking_pool: BlockingPool,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl ReplayServiceHandlers {
    /// Creates the complete replay handler family.
    #[must_use]
    pub fn new(dependencies: ReplayServiceDependencies) -> Self {
        Self {
            repository: dependencies.repository,
            identities: dependencies.identities,
            live_authorizations: dependencies.live_authorizations,
            live_services: dependencies.live_services,
            clock: dependencies.clock,
            ids: dependencies.ids,
            blocking_pool: dependencies.blocking_pool,
            errors: dependencies.errors,
        }
    }

    fn public_error(&self, code: ErrorCode) -> ApiError {
        self.errors.public_error(code)
    }

    fn now_active(&self, context: &RequestContext) -> Result<UtcTimestamp, ApiError> {
        let now = self
            .clock
            .now()
            .map_err(|_error| self.public_error(ErrorCode::Internal))?;
        context
            .check_active(now)
            .map_err(|_error| self.public_error(ErrorCode::DeadlineExceeded))?;
        Ok(now)
    }

    fn resolve_identity(
        &self,
        context: &RequestContext,
    ) -> Result<ResolvedDomainIdentity, ApiError> {
        self.identities.resolve(context).map_err(|error| {
            let code = match error.code() {
                crate::domain_identity::DomainIdentityErrorCode::Cancelled => {
                    ErrorCode::DeadlineExceeded
                }
                crate::domain_identity::DomainIdentityErrorCode::InvalidMapping => {
                    ErrorCode::IntegrityFailure
                }
                crate::domain_identity::DomainIdentityErrorCode::Unavailable => {
                    ErrorCode::DependencyUnavailable
                }
            };
            self.public_error(code)
        })
    }

    fn id(&self) -> Result<RecordId, ApiError> {
        self.ids
            .generate()
            .map_err(|_error| self.public_error(ErrorCode::Internal))
    }

    fn store_cancellation(&self, context: &RequestContext) -> StoreCancellation {
        let cancellation = StoreCancellation::default();
        if context.cancellation().is_cancelled() {
            cancellation.cancel();
        }
        cancellation
    }

    fn map_blocking_error(&self, error: BlockingPoolError) -> ApiError {
        let code = match error.code() {
            BlockingPoolErrorCode::Exhausted => ErrorCode::RateLimited,
            BlockingPoolErrorCode::NotAccepting => ErrorCode::DependencyDegraded,
            BlockingPoolErrorCode::Cancelled | BlockingPoolErrorCode::DeadlineExceeded => {
                ErrorCode::DeadlineExceeded
            }
            BlockingPoolErrorCode::TaskFailed => ErrorCode::Internal,
        };
        self.public_error(code)
    }

    fn blocking_deadline(
        &self,
        context: &RequestContext,
        now: UtcTimestamp,
    ) -> Result<tokio::time::Instant, ApiError> {
        let remaining = context
            .deadline()
            .unix_nanos()
            .checked_sub(now.unix_nanos())
            .filter(|value| *value > 0)
            .ok_or_else(|| self.public_error(ErrorCode::DeadlineExceeded))?;
        let remaining = u64::try_from(remaining)
            .map_err(|_error| self.public_error(ErrorCode::LimitExceeded))?;
        tokio::time::Instant::now()
            .checked_add(Duration::from_nanos(remaining))
            .ok_or_else(|| self.public_error(ErrorCode::LimitExceeded))
    }

    async fn run_linked_blocking<T, E, F>(
        &self,
        context: &RequestContext,
        deadline: tokio::time::Instant,
        store_cancellation: StoreCancellation,
        job: F,
    ) -> Result<Result<T, E>, ApiError>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(StoreCancellation) -> Result<T, E> + Send + 'static,
    {
        let cancellation = context.cancellation().clone();
        let cancel_store = {
            let store_cancellation = store_cancellation.clone();
            move || store_cancellation.cancel()
        };
        let result = self
            .blocking_pool
            .run_with_cancel(cancellation, deadline, cancel_store, move |_cancellation| {
                job(store_cancellation)
            })
            .await
            .map_err(|error| self.map_blocking_error(error))?;
        Ok(result)
    }

    async fn run_replay_job<T, F>(
        &self,
        context: &RequestContext,
        deadline: tokio::time::Instant,
        store_cancellation: StoreCancellation,
        job: F,
    ) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(StoreCancellation) -> Result<T, ReplayJobError> + Send + 'static,
    {
        self.run_linked_blocking(context, deadline, store_cancellation, job)
            .await?
            .map_err(|error| self.map_job_error(error))
    }

    fn jobs(
        &self,
        tenant_id: RecordId,
        cancellation: StoreCancellation,
        deadline: std::time::Instant,
    ) -> Result<(DurableReplayJobService, ReplayLiveServices), ApiError> {
        let live = self
            .live_services
            .for_tenant(&tenant_id)
            .map_err(|_error| self.public_error(ErrorCode::DependencyUnavailable))?;
        let archive = Arc::new(DurableReplayArchive::new_with_cancellation(
            Arc::clone(&self.repository),
            tenant_id.clone(),
            cancellation.clone(),
        ));
        let reservations = Arc::new(DurableReplayReservationLedger::new_with_cancellation(
            Arc::clone(&self.repository),
            tenant_id.clone(),
            cancellation.clone(),
        ));
        let engine = Arc::new(ReplayEngine::with_live_services_and_reservations(
            archive,
            Arc::clone(&live.verifier),
            Arc::clone(&live.provider),
            Arc::clone(&live.effect_gate),
            reservations,
        ));
        let replay_context = ReplayContext::new(
            Arc::new({
                let cancellation = cancellation.clone();
                move || cancellation.is_cancelled()
            }),
            Some(deadline),
        );
        Ok((
            DurableReplayJobService::new_with_context(
                Arc::clone(&self.repository),
                tenant_id,
                engine,
                replay_context,
            ),
            live,
        ))
    }

    fn linked_jobs(
        &self,
        context: &RequestContext,
        now: UtcTimestamp,
        tenant_id: RecordId,
    ) -> Result<
        (
            DurableReplayJobService,
            ReplayLiveServices,
            StoreCancellation,
            tokio::time::Instant,
        ),
        ApiError,
    > {
        let deadline = self.blocking_deadline(context, now)?;
        let cancellation = self.store_cancellation(context);
        let (jobs, live) = self.jobs(tenant_id, cancellation.clone(), deadline.into_std())?;
        Ok((jobs, live, cancellation, deadline))
    }

    fn execution_window(
        &self,
        context: &RequestContext,
    ) -> Result<ReplayExecutionWindow, ApiError> {
        let started_at = self.now_active(context)?;
        let completed_at = self
            .clock
            .now()
            .map_err(|_error| self.public_error(ErrorCode::Internal))?;
        if completed_at < started_at {
            return Err(self.public_error(ErrorCode::Internal));
        }
        context
            .check_active(completed_at)
            .map_err(|_error| self.public_error(ErrorCode::DeadlineExceeded))?;
        Ok(ReplayExecutionWindow {
            execution_id: self.id()?,
            started_at,
            completed_at,
        })
    }

    fn map_job_error(&self, error: ReplayJobError) -> ApiError {
        let code = match error.code() {
            ReplayJobErrorCode::InvalidInput => ErrorCode::InvalidArgument,
            ReplayJobErrorCode::NotFound => ErrorCode::PolicyDenied,
            ReplayJobErrorCode::Conflict => ErrorCode::RevisionConflict,
            ReplayJobErrorCode::Cancelled => ErrorCode::DeadlineExceeded,
            ReplayJobErrorCode::Unavailable => ErrorCode::DependencyUnavailable,
            ReplayJobErrorCode::Replay(code) => match code {
                ReplayErrorCode::InvalidRequest | ReplayErrorCode::LiveModeRequired => {
                    ErrorCode::InvalidArgument
                }
                ReplayErrorCode::DecisionNotFound => ErrorCode::PolicyDenied,
                ReplayErrorCode::ArchiveIntegrity | ReplayErrorCode::ProtocolViolation => {
                    ErrorCode::IntegrityFailure
                }
                ReplayErrorCode::ArchiveUnavailable
                | ReplayErrorCode::RecordedProviderFailure
                | ReplayErrorCode::LiveProviderFailure
                | ReplayErrorCode::Unavailable => ErrorCode::DependencyUnavailable,
                ReplayErrorCode::ExecutionIdReused => ErrorCode::RevisionConflict,
                ReplayErrorCode::LiveAuthorizationInvalid
                | ReplayErrorCode::LiveAuthorizationReused => ErrorCode::LiveAuthorizationRequired,
                ReplayErrorCode::EffectAuthorizationInvalid => ErrorCode::PolicyDenied,
            },
        };
        self.public_error(code)
    }

    fn map_live_authorization_error(&self, error: LiveAuthorizationRepositoryError) -> ApiError {
        let code = match error {
            LiveAuthorizationRepositoryError::InvalidInput => ErrorCode::InvalidArgument,
            LiveAuthorizationRepositoryError::NotFound => ErrorCode::LiveAuthorizationRequired,
            LiveAuthorizationRepositoryError::Conflict => ErrorCode::RevisionConflict,
            LiveAuthorizationRepositoryError::Cancelled => ErrorCode::DeadlineExceeded,
            LiveAuthorizationRepositoryError::Unavailable => ErrorCode::DependencyUnavailable,
        };
        self.public_error(code)
    }

    fn request(
        &self,
        request_id: RecordId,
        requester: RecordId,
        payload: CreateReplayRequest,
    ) -> Result<ReplayRequest, ApiError> {
        let request = ReplayRequest {
            schema_version: SchemaVersion::new("cigar.replay-request", 1)
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            request_id,
            decision_id: payload.decision_id,
            mode: payload.mode,
            requested_by: requester,
            live_authorization_digest: None,
            simulate_effects: payload.simulate_effects,
            authorized_effect_intents: Vec::new(),
        };
        request
            .validate()
            .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))?;
        Ok(request)
    }

    fn job_response(&self, job: &VersionedReplayJob) -> Result<ReplayJobResponse, ApiError> {
        let execution = job.record.execution.clone();
        let status = match job.record.phase {
            ReplayJobPhase::Pending => match job.record.request.mode {
                ReplayMode::Observational => ReplayJobStatus::PendingObservational,
                ReplayMode::LiveComparison => ReplayJobStatus::PendingLive,
                ReplayMode::EvidenceReproduction | ReplayMode::InvocationReproduction => {
                    ReplayJobStatus::Running
                }
            },
            ReplayJobPhase::Running => ReplayJobStatus::Running,
            ReplayJobPhase::Complete => match execution.as_ref().map(|value| value.status) {
                Some(ReplayStatus::Complete) => ReplayJobStatus::Complete,
                Some(ReplayStatus::Incomplete) => ReplayJobStatus::Incomplete,
                Some(ReplayStatus::Running | ReplayStatus::Failed) | None => {
                    return Err(self.public_error(ErrorCode::IntegrityFailure));
                }
            },
            ReplayJobPhase::Failed | ReplayJobPhase::Interrupted => ReplayJobStatus::Failed,
        };
        Ok(ReplayJobResponse {
            replay_id: job.record.request.request_id.clone(),
            mode: job.record.request.mode,
            status,
            execution,
        })
    }

    fn preview_execution(
        &self,
        request_id: RecordId,
        mode: ReplayMode,
        completeness: ReplayCompleteness,
        started_at: UtcTimestamp,
    ) -> Result<ReplayExecution, ApiError> {
        let execution = ReplayExecution {
            schema_version: SchemaVersion::new("cigar.replay-execution", 1)
                .map_err(|_error| self.public_error(ErrorCode::Internal))?,
            execution_id: self.id()?,
            request_id,
            mode,
            status: ReplayStatus::Running,
            completeness,
            reconstructed_input_digest: None,
            observation_digest: None,
            egress_permitted: false,
            effect_dispatch_permitted: false,
            started_at,
            completed_at: None,
        };
        execution
            .validate()
            .map_err(|_error| self.public_error(ErrorCode::Internal))?;
        Ok(execution)
    }

    async fn create_replay(
        &self,
        context: RequestContext,
        request: TypedRequest<CreateReplayRequest>,
    ) -> Result<TypedResponse<ReplayJobResponse>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let request_id = self.id()?;
        if request.metadata.dry_run() {
            let status = match request.payload.mode {
                ReplayMode::EvidenceReproduction | ReplayMode::InvocationReproduction => {
                    ReplayJobStatus::Running
                }
                ReplayMode::Observational => ReplayJobStatus::PendingObservational,
                ReplayMode::LiveComparison => ReplayJobStatus::PendingLive,
            };
            return Ok(TypedResponse::new(ReplayJobResponse {
                replay_id: request_id,
                mode: request.payload.mode,
                status,
                execution: None,
            }));
        }
        let (jobs, _live, store_cancellation, deadline) =
            self.linked_jobs(&context, now, identity.tenant_id)?;
        if request.payload.mode == ReplayMode::LiveComparison {
            let decision_id = request.payload.decision_id;
            let requested_by = identity.principal_id;
            let simulate_effects = request.payload.simulate_effects;
            let draft = self
                .run_replay_job(
                    &context,
                    deadline,
                    store_cancellation,
                    move |cancellation| {
                        jobs.create_live_draft(
                            request_id,
                            decision_id,
                            requested_by,
                            simulate_effects,
                            &cancellation,
                        )
                    },
                )
                .await?;
            return Ok(TypedResponse::new(ReplayJobResponse {
                replay_id: draft.record.request_id,
                mode: ReplayMode::LiveComparison,
                status: ReplayJobStatus::PendingLive,
                execution: None,
            }));
        }
        let replay_request = self.request(request_id, identity.principal_id, request.payload)?;
        let job = match replay_request.mode {
            ReplayMode::EvidenceReproduction | ReplayMode::InvocationReproduction => {
                let window = ReplayExecutionWindow {
                    execution_id: self.id()?,
                    started_at: now,
                    completed_at: self
                        .clock
                        .now()
                        .map_err(|_error| self.public_error(ErrorCode::Internal))?,
                };
                self.run_replay_job(
                    &context,
                    deadline,
                    store_cancellation,
                    move |cancellation| {
                        jobs.create_and_reconstruct(replay_request, window, &cancellation)
                    },
                )
                .await
            }
            ReplayMode::Observational => {
                self.run_replay_job(
                    &context,
                    deadline,
                    store_cancellation,
                    move |cancellation| jobs.create_pending(replay_request, &cancellation),
                )
                .await
            }
            ReplayMode::LiveComparison => {
                return Err(self.public_error(ErrorCode::Internal));
            }
        }?;
        Ok(TypedResponse::new(self.job_response(&job)?))
    }

    async fn run_observational(
        &self,
        context: RequestContext,
        request: TypedRequest<ReplayIdRequest>,
    ) -> Result<TypedResponse<ReplayExecution>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let (jobs, _live, cancellation, deadline) =
            self.linked_jobs(&context, now, identity.tenant_id)?;
        if request.metadata.dry_run() {
            let replay_id = request.payload.replay_id;
            let lookup_replay_id = replay_id.clone();
            let actor_id = identity.principal_id;
            let job = self
                .run_replay_job(&context, deadline, cancellation, move |cancellation| {
                    jobs.get(&lookup_replay_id, &actor_id, &cancellation)
                })
                .await?;
            if job.record.request.mode != ReplayMode::Observational {
                return Err(self.public_error(ErrorCode::InvalidArgument));
            }
            return Ok(TypedResponse::new(self.preview_execution(
                replay_id,
                ReplayMode::Observational,
                job.record.completeness,
                now,
            )?));
        }
        let replay_id = request.payload.replay_id;
        let actor_id = identity.principal_id;
        let window = self.execution_window(&context)?;
        let job = self
            .run_replay_job(&context, deadline, cancellation, move |cancellation| {
                jobs.run_observational(&replay_id, &actor_id, window, &cancellation)
            })
            .await?;
        let execution = job
            .record
            .execution
            .ok_or_else(|| self.public_error(ErrorCode::IntegrityFailure))?;
        Ok(TypedResponse::new(execution))
    }

    async fn compare_live(
        &self,
        context: RequestContext,
        request: TypedRequest<CompareLiveReplayRequest>,
    ) -> Result<TypedResponse<ReplayExecution>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let (jobs, live, cancellation, deadline) =
            self.linked_jobs(&context, now, identity.tenant_id.clone())?;
        let authorizations = Arc::clone(&self.live_authorizations);
        let authorization_tenant = identity.tenant_id.clone();
        let authorization_id = request.payload.live_authorization_id;
        let authorization = self
            .run_linked_blocking(
                &context,
                deadline,
                cancellation.clone(),
                move |cancellation| {
                    authorizations.get(&authorization_tenant, &authorization_id, &cancellation)
                },
            )
            .await?
            .map_err(|error| self.map_live_authorization_error(error))?;
        if request.metadata.dry_run() {
            let replay_id = request.payload.replay_id;
            let lookup_replay_id = replay_id.clone();
            let actor_id = identity.principal_id.clone();
            let draft = self
                .run_replay_job(
                    &context,
                    deadline,
                    cancellation.clone(),
                    move |cancellation| {
                        jobs.get_live_draft(&lookup_replay_id, &actor_id, &cancellation)
                    },
                )
                .await?;
            let preview_request = ReplayRequest {
                schema_version: SchemaVersion::new("cigar.replay-request", 1)
                    .map_err(|_error| self.public_error(ErrorCode::Internal))?,
                request_id: draft.record.request_id.clone(),
                decision_id: draft.record.decision_id,
                mode: ReplayMode::LiveComparison,
                requested_by: identity.principal_id,
                live_authorization_digest: Some(authorization.authorization_digest.clone()),
                simulate_effects: draft.record.simulate_effects,
                authorized_effect_intents: authorization.authorized_effect_intents.clone(),
            };
            preview_request
                .validate()
                .map_err(|_error| self.public_error(ErrorCode::InvalidArgument))?;
            authorization
                .validate_binding(&preview_request)
                .map_err(|_error| self.public_error(ErrorCode::LiveAuthorizationRequired))?;
            let verifier = Arc::clone(&live.verifier);
            let verification = authorization.clone();
            let trusted_now = self
                .run_linked_blocking(&context, deadline, cancellation, move |_cancellation| {
                    verifier.verify_current(&verification)
                })
                .await?
                .map_err(|_error| self.public_error(ErrorCode::LiveAuthorizationRequired))?;
            if trusted_now < authorization.not_before || trusted_now > authorization.expires_at {
                return Err(self.public_error(ErrorCode::LiveAuthorizationRequired));
            }
            return Ok(TypedResponse::new(self.preview_execution(
                replay_id,
                ReplayMode::LiveComparison,
                draft.record.completeness,
                now,
            )?));
        }
        let replay_id = request.payload.replay_id;
        let actor_id = identity.principal_id;
        let window = self.execution_window(&context)?;
        let job = self
            .run_replay_job(&context, deadline, cancellation, move |cancellation| {
                jobs.bind_and_compare_live(
                    &replay_id,
                    &actor_id,
                    &authorization,
                    window,
                    &cancellation,
                )
            })
            .await?;
        let execution = job
            .record
            .execution
            .ok_or_else(|| self.public_error(ErrorCode::IntegrityFailure))?;
        Ok(TypedResponse::new(execution))
    }

    async fn replay_completeness(
        &self,
        context: RequestContext,
        request: TypedRequest<ReplayIdRequest>,
    ) -> Result<TypedResponse<ReplayCompleteness>, ApiError> {
        let now = self.now_active(&context)?;
        let identity = self.resolve_identity(&context)?;
        let (jobs, _live, cancellation, deadline) =
            self.linked_jobs(&context, now, identity.tenant_id)?;
        let replay_id = request.payload.replay_id;
        let actor_id = identity.principal_id;
        let completeness = self
            .run_replay_job(
                &context,
                deadline,
                cancellation,
                move |cancellation| match jobs.get(&replay_id, &actor_id, &cancellation) {
                    Ok(job) => Ok(job.record.completeness),
                    Err(error) if error.code() == ReplayJobErrorCode::NotFound => jobs
                        .get_live_draft(&replay_id, &actor_id, &cancellation)
                        .map(|draft| draft.record.completeness),
                    Err(error) => Err(error),
                },
            )
            .await?;
        Ok(TypedResponse::new(completeness))
    }
}

impl fmt::Debug for ReplayServiceHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayServiceHandlers")
            .field("repository", &"[INJECTED]")
            .field("live_authorizations", &"[DURABLE]")
            .field("live_services", &"[TENANT-BOUND]")
            .finish_non_exhaustive()
    }
}

impl TypedUnaryService<CreateReplayOperation> for ReplayServiceHandlers {
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<CreateReplayRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<ReplayJobResponse>, ApiError>> {
        Box::pin(async move { self.create_replay(context, request).await })
    }
}

impl TypedUnaryService<RunObservationalReplayOperation> for ReplayServiceHandlers {
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<ReplayIdRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<ReplayExecution>, ApiError>> {
        Box::pin(async move { self.run_observational(context, request).await })
    }
}

impl TypedUnaryService<CompareLiveReplayOperation> for ReplayServiceHandlers {
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<CompareLiveReplayRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<ReplayExecution>, ApiError>> {
        Box::pin(async move { self.compare_live(context, request).await })
    }
}

impl TypedUnaryService<GetReplayCompletenessOperation> for ReplayServiceHandlers {
    fn call_typed<'a>(
        &'a self,
        context: RequestContext,
        request: TypedRequest<ReplayIdRequest>,
    ) -> ServiceFuture<'a, Result<TypedResponse<ReplayCompleteness>, ApiError>> {
        Box::pin(async move { self.replay_completeness(context, request).await })
    }
}

/// Registers all ten effect/replay typed handlers into the global exact-operation builder.
pub fn register_effect_replay_handlers<R: Repository + 'static>(
    builder: &mut ProductionApplicationBuilder,
    effects: Arc<EffectServiceHandlers<R>>,
    replay: Arc<ReplayServiceHandlers>,
) -> Result<(), HandlerRegistryError> {
    builder.register_unary::<PrepareEffectOperation, _>(Arc::clone(&effects))?;
    builder.register_unary::<AuthorizeEffectOperation, _>(Arc::clone(&effects))?;
    builder.register_unary::<DispatchEffectOperation, _>(Arc::clone(&effects))?;
    builder.register_unary::<GetEffectStatusOperation, _>(Arc::clone(&effects))?;
    builder.register_unary::<ReconcileEffectOperation, _>(Arc::clone(&effects))?;
    builder.register_unary::<CompensateEffectOperation, _>(effects)?;
    builder.register_unary::<CreateReplayOperation, _>(Arc::clone(&replay))?;
    builder.register_unary::<RunObservationalReplayOperation, _>(Arc::clone(&replay))?;
    builder.register_unary::<CompareLiveReplayOperation, _>(Arc::clone(&replay))?;
    builder.register_unary::<GetReplayCompletenessOperation, _>(replay)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationIdError, ApplicationIdGenerator, DurableLiveReplayAuthorizationRepository,
        EffectDispatchGate, EffectDispatchQueue, EffectDispatchQueueError, EffectPolicyAction,
        EffectPolicyDecision, EffectPolicyEvaluator, EffectPolicyFailure,
        EffectServiceDependencies, EffectServiceHandlers, EffectWorkerAction,
        EffectWorkerAuthority, EffectWorkerAuthorityError, EffectWorkerOutcome,
        EffectWorkerProcessor, EffectWorkerProcessorDependencies, LiveAuthorizationRepositoryError,
        LiveReplayAuthorizationRepository, ReplayLiveServices, ReplayLiveServicesError,
        ReplayLiveServicesFactory, ReplayServiceDependencies, ReplayServiceHandlers,
    };
    use crate::authority::{AuthorityClock, AuthorityError};
    use crate::domain_identity::{
        DomainIdentityError, DomainIdentityResolver, ResolvedDomainIdentity,
    };
    use crate::production_effects::{EffectArgumentVault, EffectArgumentVaultError};
    use crate::worker::{BlockingPool, WorkerJob, WorkerKind};
    use cigar_api::{
        AuthenticatedIdentity, AuthorizeEffectOperation, AuthorizeEffectRequest, CancellationToken,
        CreateReplayOperation, CreateReplayRequest, DispatchEffectOperation, EffectIdRequest,
        EffectStatusResponse, FacadeErrorFactory, GetEffectStatusOperation,
        GetReplayCompletenessOperation, OperationId, PathParameter, PrepareEffectOperation,
        PrepareEffectRequest, PrincipalId, ReplayIdRequest, ReplayJobResponse, ReplayJobStatus,
        RequestContext, RequestEnvelope, TenantId, TraceId, TypedUnaryAdapter,
        UnaryOperationHandler, decode_operation_payload, encode_operation_payload,
    };
    use cigar_effects::{
        ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation,
        EffectAuthorization, EffectConnector, EffectEngine, EffectError, EffectErrorCode,
        PreconditionReport, ReconcileObservation,
    };
    use cigar_protocol::{
        BlobRef, Capability, ContentDigest, EffectIntent, EffectState, ErrorCode, ExpectedRevision,
        MediaType, RecordId, ReplayCompleteness, ReplayMode, RetryPolicy, RiskLevel, UtcTimestamp,
        VersionId,
    };
    use cigar_replay::{
        LiveAuthorizationVerifier, LiveEffectDispatch, LiveEffectGate, LiveReplayAuthorization,
        LiveReplayInvocation, LiveReplayOutput, LiveReplayProvider, ReplayArchive, ReplayError,
        ReplayErrorCode,
    };
    use cigar_store::{
        AccessContext, CancellationToken as StoreCancellation, EffectRecoveryPage,
        EffectRecoveryQuery, InMemoryStore, OutboxRecoveryPage, OutboxRecoveryQuery, Repository,
        ServiceBatch, ServiceBatchReceipt, ServiceError, ServiceListPage, ServiceListQuery,
        ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRepository,
        SqliteStore, WorkerLocator, WorkerState, WorkerUpdate,
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    static NEXT_EFFECT_ID_BLOCK: AtomicU64 = AtomicU64::new(1_000_000);

    fn record(value: u64) -> TestResult<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(value: u64) -> TestResult<ContentDigest> {
        let hash = Sha256::digest(value.to_be_bytes());
        let mut encoded = String::from("1220");
        for byte in hash {
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(ContentDigest::new(encoded)?)
    }

    fn version(value: u64) -> TestResult<VersionId> {
        Ok(VersionId::new(digest(value)?.as_str())?)
    }

    fn timestamp(second: u8) -> TestResult<UtcTimestamp> {
        Ok(UtcTimestamp::parse_rfc3339(&format!(
            "2026-07-11T12:00:{second:02}Z"
        ))?)
    }

    struct FixedClock(UtcTimestamp);

    impl AuthorityClock for FixedClock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            Ok(self.0)
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            i64::try_from(self.0.unix_nanos() / 1_000_000_000)
                .map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    struct AdvancingClock {
        first: UtcTimestamp,
        second: UtcTimestamp,
        observed: AtomicBool,
    }

    impl AuthorityClock for AdvancingClock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            Ok(if self.observed.swap(true, Ordering::AcqRel) {
                self.second
            } else {
                self.first
            })
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            i64::try_from(self.second.unix_nanos() / 1_000_000_000)
                .map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    struct FixedIdentity {
        tenant_id: RecordId,
        principal_id: RecordId,
    }

    impl DomainIdentityResolver for FixedIdentity {
        fn resolve(
            &self,
            _context: &RequestContext,
        ) -> Result<ResolvedDomainIdentity, DomainIdentityError> {
            Ok(ResolvedDomainIdentity {
                tenant_id: self.tenant_id.clone(),
                principal_id: self.principal_id.clone(),
            })
        }
    }

    struct AllowEffects;

    impl EffectPolicyEvaluator for AllowEffects {
        fn evaluate(
            &self,
            _context: &RequestContext,
            _identity: &ResolvedDomainIdentity,
            _action: EffectPolicyAction,
            _intent: &EffectIntent,
            _approval_kind: Option<cigar_protocol::ApprovalKind>,
        ) -> Result<EffectPolicyDecision, EffectPolicyFailure> {
            Ok(EffectPolicyDecision::new(
                true,
                [
                    Capability::ProposeEffect,
                    Capability::ApproveEffect,
                    Capability::ReconcileEffect,
                    Capability::InvokeTool,
                ]
                .into_iter()
                .collect(),
            ))
        }
    }

    struct DenyEffects;

    impl EffectPolicyEvaluator for DenyEffects {
        fn evaluate(
            &self,
            _context: &RequestContext,
            _identity: &ResolvedDomainIdentity,
            _action: EffectPolicyAction,
            _intent: &EffectIntent,
            _approval_kind: Option<cigar_protocol::ApprovalKind>,
        ) -> Result<EffectPolicyDecision, EffectPolicyFailure> {
            Ok(EffectPolicyDecision::new(false, BTreeSet::new()))
        }
    }

    struct WorkerAuthority {
        actor_id: RecordId,
        allowed: AtomicBool,
        available: AtomicBool,
    }

    impl WorkerAuthority {
        fn allowed(actor_id: RecordId) -> Self {
            Self {
                actor_id,
                allowed: AtomicBool::new(true),
                available: AtomicBool::new(true),
            }
        }
    }

    impl EffectWorkerAuthority for WorkerAuthority {
        fn authorize(
            &self,
            _tenant_id: &RecordId,
            _action: EffectWorkerAction,
            _record: &cigar_effects::DurableEffectRecord,
            now: UtcTimestamp,
        ) -> Result<EffectAuthorization, EffectWorkerAuthorityError> {
            if !self.available.load(Ordering::Acquire) {
                return Err(EffectWorkerAuthorityError);
            }
            let allowed = self.allowed.load(Ordering::Acquire);
            Ok(EffectAuthorization {
                actor_id: self.actor_id.clone(),
                capabilities: if allowed {
                    [
                        Capability::ProposeEffect,
                        Capability::ApproveEffect,
                        Capability::ReconcileEffect,
                        Capability::InvokeTool,
                    ]
                    .into_iter()
                    .collect()
                } else {
                    BTreeSet::new()
                },
                policy_allows: allowed,
                now,
            })
        }
    }

    struct TestIds(AtomicU64);

    impl ApplicationIdGenerator for TestIds {
        fn generate(&self) -> Result<RecordId, ApplicationIdError> {
            let value = self.0.fetch_add(1, Ordering::SeqCst);
            RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{value:012x}"))
                .map_err(|_error| ApplicationIdError)
        }
    }

    struct Gate(AtomicBool);

    impl EffectDispatchGate for Gate {
        fn dispatch_claims_allowed(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct CloseAtConnectorEntryGate;

    impl EffectDispatchGate for CloseAtConnectorEntryGate {
        fn dispatch_claims_allowed(&self) -> bool {
            true
        }

        fn begin_dispatch_send(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct OpenArgumentVault {
        validations: AtomicUsize,
        stages: AtomicUsize,
    }

    impl EffectArgumentVault for OpenArgumentVault {
        fn validate(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            self.validations.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn stage(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            self.stages.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct RejectingArgumentVault(EffectArgumentVaultError);

    impl EffectArgumentVault for RejectingArgumentVault {
        fn validate(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            Err(self.0)
        }

        fn stage(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            Err(self.0)
        }
    }

    struct RevokingArgumentVault {
        authority: Arc<WorkerAuthority>,
    }

    impl EffectArgumentVault for RevokingArgumentVault {
        fn validate(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            Ok(())
        }

        fn stage(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            self.authority.allowed.store(false, Ordering::Release);
            Ok(())
        }
    }

    #[derive(Default)]
    struct DispatchQueue {
        jobs: Mutex<Vec<WorkerJob>>,
        reject: AtomicBool,
    }

    impl DispatchQueue {
        fn pop(&self) -> TestResult<WorkerJob> {
            self.jobs
                .lock()
                .map_err(|_error| "dispatch queue lock poisoned")?
                .pop()
                .ok_or_else(|| "dispatch queue is empty".into())
        }
    }

    impl EffectDispatchQueue for DispatchQueue {
        fn enqueue(&self, job: WorkerJob) -> Result<(), EffectDispatchQueueError> {
            if self.reject.load(Ordering::Acquire) {
                return Err(EffectDispatchQueueError);
            }
            self.jobs
                .lock()
                .map_err(|_error| EffectDispatchQueueError)?
                .push(job);
            Ok(())
        }
    }

    struct Errors {
        correlation_id: RecordId,
    }

    impl FacadeErrorFactory for Errors {
        fn public_error(&self, code: ErrorCode) -> cigar_api::ApiError {
            cigar_api::ApiError::new(code, self.correlation_id.clone())
        }
    }

    fn errors() -> TestResult<Arc<Errors>> {
        Ok(Arc::new(Errors {
            correlation_id: record(65_535)?,
        }))
    }

    struct Connector {
        calls: AtomicUsize,
    }

    impl Connector {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl EffectConnector for Connector {
        fn descriptor(&self) -> ConnectorDescriptor {
            ConnectorDescriptor {
                connector: "test.connector".to_owned(),
                operations: vec![ConnectorOperation {
                    operation: "send".to_owned(),
                    same_key_idempotent: false,
                    supports_reconciliation: true,
                    supports_compensation: false,
                }],
                maximum_dispatch_nanos: 1_000_000_000,
            }
        }

        fn check_preconditions(
            &self,
            _intent: &EffectIntent,
            _now: UtcTimestamp,
        ) -> Result<PreconditionReport, EffectError> {
            Ok(PreconditionReport {
                satisfied: true,
                evidence: BTreeSet::new(),
            })
        }

        fn dispatch(
            &self,
            _context: &DispatchContext<'_>,
        ) -> Result<DispatchObservation, EffectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(DispatchObservation::Succeeded {
                remote_operation_id: "remote-1".to_owned(),
                response_digest: digest(90)
                    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
                verification_digest: digest(91)
                    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?,
            })
        }

        fn reconcile(
            &self,
            _context: &DispatchContext<'_>,
        ) -> Result<ReconcileObservation, EffectError> {
            Ok(ReconcileObservation::ConfirmedSuccess(digest(92).map_err(
                |_error| EffectError::new(EffectErrorCode::Unavailable),
            )?))
        }
    }

    struct DeniedLiveServices;

    impl LiveAuthorizationVerifier for DeniedLiveServices {
        fn verify_current(
            &self,
            _authorization: &LiveReplayAuthorization,
        ) -> Result<UtcTimestamp, ReplayError> {
            Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid))
        }
    }

    impl LiveReplayProvider for DeniedLiveServices {
        fn execute(
            &self,
            _invocation: &LiveReplayInvocation,
        ) -> Result<LiveReplayOutput, ReplayError> {
            Err(ReplayError::new(ReplayErrorCode::LiveProviderFailure))
        }
    }

    impl LiveEffectGate for DeniedLiveServices {
        fn authorize_and_dispatch(
            &self,
            _dispatch: &LiveEffectDispatch,
        ) -> Result<(), ReplayError> {
            Err(ReplayError::new(
                ReplayErrorCode::EffectAuthorizationInvalid,
            ))
        }
    }

    struct DeniedLiveFactory;

    impl ReplayLiveServicesFactory for DeniedLiveFactory {
        fn for_tenant(
            &self,
            _tenant_id: &RecordId,
        ) -> Result<ReplayLiveServices, ReplayLiveServicesError> {
            let denied = Arc::new(DeniedLiveServices);
            Ok(ReplayLiveServices {
                verifier: denied.clone(),
                provider: denied.clone(),
                effect_gate: denied,
            })
        }
    }

    fn request_context_with(
        operation: &str,
        deadline: UtcTimestamp,
        cancellation: CancellationToken,
    ) -> TestResult<RequestContext> {
        RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new("transport-tenant")?,
                PrincipalId::new("transport-principal")?,
            ),
            OperationId::new(operation)?,
            deadline,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            cancellation,
            timestamp(1)?,
        )
        .map_err(Into::into)
    }

    fn request_context(operation: &str) -> TestResult<RequestContext> {
        request_context_with(operation, timestamp(50)?, CancellationToken::new())
    }

    fn prepare_payload() -> TestResult<PrepareEffectRequest> {
        Ok(PrepareEffectRequest {
            connector: "test.connector".to_owned(),
            operation: "send".to_owned(),
            arguments_digest: digest(1)?,
            encrypted_arguments: BlobRef {
                digest: digest(2)?,
                size_bytes: 3,
                media_type: MediaType::new("application/octet-stream")?,
            },
            target: "target".to_owned(),
            preconditions: Vec::new(),
            result_schema_digest: digest(3)?,
            risk: RiskLevel::Low,
            source_decision_id: version(4)?,
            bundle_id: version(5)?,
            required_capability: Capability::InvokeTool,
            idempotency_scope: "test-scope".to_owned(),
            retry_policy: RetryPolicy::Never,
            ttl_seconds: 30,
            compensation: None,
        })
    }

    fn effect_handlers(
        store: Arc<InMemoryStore>,
        connector: Arc<Connector>,
        gate: Arc<Gate>,
    ) -> TestResult<Arc<EffectServiceHandlers<InMemoryStore>>> {
        effect_handlers_with_queue(
            store,
            connector,
            gate,
            Arc::new(AllowEffects),
            BlockingPool::new(2, 2)?,
            Arc::new(DispatchQueue::default()),
        )
    }

    fn effect_handlers_with(
        store: Arc<InMemoryStore>,
        connector: Arc<Connector>,
        gate: Arc<Gate>,
        policy: Arc<dyn EffectPolicyEvaluator>,
        blocking_pool: BlockingPool,
    ) -> TestResult<Arc<EffectServiceHandlers<InMemoryStore>>> {
        effect_handlers_with_queue(
            store,
            connector,
            gate,
            policy,
            blocking_pool,
            Arc::new(DispatchQueue::default()),
        )
    }

    fn effect_handlers_with_queue(
        store: Arc<InMemoryStore>,
        connector: Arc<Connector>,
        gate: Arc<Gate>,
        policy: Arc<dyn EffectPolicyEvaluator>,
        blocking_pool: BlockingPool,
        dispatch_queue: Arc<DispatchQueue>,
    ) -> TestResult<Arc<EffectServiceHandlers<InMemoryStore>>> {
        effect_handlers_with_queue_and_vault(
            store,
            connector,
            gate,
            policy,
            blocking_pool,
            dispatch_queue,
            Arc::new(OpenArgumentVault::default()),
        )
    }

    fn effect_handlers_with_queue_and_vault(
        store: Arc<InMemoryStore>,
        connector: Arc<Connector>,
        gate: Arc<Gate>,
        policy: Arc<dyn EffectPolicyEvaluator>,
        blocking_pool: BlockingPool,
        dispatch_queue: Arc<DispatchQueue>,
        argument_vault: Arc<dyn EffectArgumentVault>,
    ) -> TestResult<Arc<EffectServiceHandlers<InMemoryStore>>> {
        effect_handlers_for_repository(
            store,
            connector,
            gate,
            policy,
            blocking_pool,
            dispatch_queue,
            argument_vault,
        )
    }

    fn effect_handlers_for_repository<R: Repository + 'static>(
        store: Arc<R>,
        connector: Arc<Connector>,
        gate: Arc<dyn EffectDispatchGate>,
        policy: Arc<dyn EffectPolicyEvaluator>,
        blocking_pool: BlockingPool,
        dispatch_queue: Arc<dyn EffectDispatchQueue>,
        argument_vault: Arc<dyn EffectArgumentVault>,
    ) -> TestResult<Arc<EffectServiceHandlers<R>>> {
        let connector: Arc<dyn EffectConnector> = connector;
        let effect_id_start = NEXT_EFFECT_ID_BLOCK.fetch_add(10_000, Ordering::AcqRel);
        Ok(Arc::new(EffectServiceHandlers::new(
            EffectServiceDependencies {
                repository: store,
                identities: Arc::new(FixedIdentity {
                    tenant_id: record(10)?,
                    principal_id: record(11)?,
                }),
                policy,
                clock: Arc::new(FixedClock(timestamp(2)?)),
                ids: Arc::new(TestIds(AtomicU64::new(effect_id_start))),
                dispatch_gate: gate,
                dispatch_queue,
                argument_vault,
                blocking_pool,
                connectors: vec![connector],
                errors: errors()?,
            },
        )?))
    }

    fn replay_handlers(
        repository: Arc<dyn ServiceRepository>,
        id_start: u64,
    ) -> TestResult<Arc<ReplayServiceHandlers>> {
        let live_authorizations = Arc::new(DurableLiveReplayAuthorizationRepository::new(
            Arc::clone(&repository),
        ));
        Ok(Arc::new(ReplayServiceHandlers::new(
            ReplayServiceDependencies {
                repository,
                identities: Arc::new(FixedIdentity {
                    tenant_id: record(10)?,
                    principal_id: record(11)?,
                }),
                live_authorizations,
                live_services: Arc::new(DeniedLiveFactory),
                clock: Arc::new(FixedClock(timestamp(2)?)),
                ids: Arc::new(TestIds(AtomicU64::new(id_start))),
                blocking_pool: BlockingPool::new(2, 4)?,
                errors: errors()?,
            },
        )))
    }

    struct PausedGetRepository {
        inner: Arc<InMemoryStore>,
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
        observed_cancellation: Mutex<Option<StoreCancellation>>,
        commits: AtomicUsize,
    }

    impl PausedGetRepository {
        fn new(entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> Self {
            Self {
                inner: Arc::new(InMemoryStore::default()),
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(release),
                observed_cancellation: Mutex::new(None),
                commits: AtomicUsize::new(0),
            }
        }

        fn observed_cancellation(&self) -> TestResult<StoreCancellation> {
            self.observed_cancellation
                .lock()
                .map_err(|_error| "observed cancellation lock poisoned")?
                .clone()
                .ok_or_else(|| "repository did not observe a cancellation token".into())
        }
    }

    impl ServiceRepository for PausedGetRepository {
        fn service_get(
            &self,
            locator: &ServiceRecordLocator,
            selection: ServiceRecordSelection,
            cancellation: &StoreCancellation,
        ) -> Result<Option<ServiceRecord>, ServiceError> {
            let entered = self
                .entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(entered) = entered {
                *self
                    .observed_cancellation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(cancellation.clone());
                if entered.send(()).is_ok() {
                    let _released = self
                        .release
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                }
            }
            self.inner.service_get(locator, selection, cancellation)
        }

        fn service_list(
            &self,
            query: &ServiceListQuery,
            cancellation: &StoreCancellation,
        ) -> Result<ServiceListPage, ServiceError> {
            self.inner.service_list(query, cancellation)
        }

        fn service_commit(
            &self,
            batch: ServiceBatch,
            cancellation: &StoreCancellation,
        ) -> Result<ServiceBatchReceipt, ServiceError> {
            self.commits.fetch_add(1, Ordering::AcqRel);
            self.inner.service_commit(batch, cancellation)
        }

        fn effect_recovery(
            &self,
            query: &EffectRecoveryQuery,
            cancellation: &StoreCancellation,
        ) -> Result<EffectRecoveryPage, ServiceError> {
            self.inner.effect_recovery(query, cancellation)
        }

        fn outbox_recovery(
            &self,
            query: &OutboxRecoveryQuery,
            cancellation: &StoreCancellation,
        ) -> Result<OutboxRecoveryPage, ServiceError> {
            self.inner.outbox_recovery(query, cancellation)
        }

        fn worker_get(
            &self,
            locator: &WorkerLocator,
            cancellation: &StoreCancellation,
        ) -> Result<Option<WorkerState>, ServiceError> {
            self.inner.worker_get(locator, cancellation)
        }

        fn worker_update(
            &self,
            locator: &WorkerLocator,
            update: WorkerUpdate,
            cancellation: &StoreCancellation,
        ) -> Result<WorkerState, ServiceError> {
            self.inner.worker_update(locator, update, cancellation)
        }
    }

    async fn prepare_effect_for<R: Repository + 'static>(
        handlers: Arc<EffectServiceHandlers<R>>,
        key: &str,
    ) -> TestResult<EffectStatusResponse> {
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let adapter = TypedUnaryAdapter::<PrepareEffectOperation, _>::new(handlers, errors);
        let request = RequestEnvelope::new_with_dry_run(
            "prepareEffect",
            encode_operation_payload(&prepare_payload()?, 16 * 1024 * 1024)?,
            false,
            Some(key.to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let response = adapter
            .call(request_context("prepareEffect")?, request)
            .await?;
        Ok(decode_operation_payload(
            response.payload_cbor(),
            16 * 1024 * 1024,
        )?)
    }

    async fn authorize_effect_for<R: Repository + 'static>(
        handlers: Arc<EffectServiceHandlers<R>>,
        prepared: &EffectStatusResponse,
        key: &str,
    ) -> TestResult<EffectStatusResponse> {
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let adapter = TypedUnaryAdapter::<AuthorizeEffectOperation, _>::new(handlers, errors);
        let request = RequestEnvelope::new_with_dry_run(
            "authorizeEffect",
            encode_operation_payload(
                &AuthorizeEffectRequest {
                    effect_id: prepared.effect_id.clone(),
                    approval: None,
                },
                16 * 1024 * 1024,
            )?,
            false,
            Some(key.to_owned()),
            Some(prepared.effect_version.to_string()),
            None,
            None,
            vec![PathParameter::new(
                "effect_id",
                prepared.effect_id.as_str(),
            )?],
        )?;
        let response = adapter
            .call(request_context("authorizeEffect")?, request)
            .await?;
        Ok(decode_operation_payload(
            response.payload_cbor(),
            16 * 1024 * 1024,
        )?)
    }

    fn dispatch_request(effect: &EffectStatusResponse, key: &str) -> TestResult<RequestEnvelope> {
        Ok(RequestEnvelope::new_with_dry_run(
            "dispatchEffect",
            encode_operation_payload(
                &EffectIdRequest {
                    effect_id: effect.effect_id.clone(),
                },
                16 * 1024 * 1024,
            )?,
            false,
            Some(key.to_owned()),
            Some(effect.effect_version.to_string()),
            None,
            None,
            vec![PathParameter::new("effect_id", effect.effect_id.as_str())?],
        )?)
    }

    #[tokio::test]
    async fn effect_handlers_prepare_authorize_and_dispatch_real_kernel_state() -> TestResult {
        let store = Arc::new(InMemoryStore::default());
        let connector = Arc::new(Connector::new());
        let gate = Arc::new(Gate(AtomicBool::new(true)));
        let queue = Arc::new(DispatchQueue::default());
        let handlers = effect_handlers_with_queue(
            Arc::clone(&store),
            Arc::clone(&connector),
            Arc::clone(&gate),
            Arc::new(AllowEffects),
            BlockingPool::new(2, 2)?,
            Arc::clone(&queue),
        )?;
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;

        let prepare = TypedUnaryAdapter::<PrepareEffectOperation, _>::new(
            Arc::clone(&handlers),
            Arc::clone(&errors),
        );
        let prepare_request = RequestEnvelope::new_with_dry_run(
            "prepareEffect",
            encode_operation_payload(&prepare_payload()?, 16 * 1024 * 1024)?,
            false,
            Some("effect-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let prepared_response = prepare
            .call(request_context("prepareEffect")?, prepare_request)
            .await
            .map_err(|error| {
                std::io::Error::other(format!("prepareEffect adapter failed: {:?}", error.code()))
            })?;
        assert_eq!(prepared_response.semantic_etag(), Some("\"0\""));
        let prepared: EffectStatusResponse =
            decode_operation_payload(prepared_response.payload_cbor(), 16 * 1024 * 1024)?;
        assert_eq!(prepared.state, EffectState::Prepared);

        let authorize = TypedUnaryAdapter::<AuthorizeEffectOperation, _>::new(
            Arc::clone(&handlers),
            Arc::clone(&errors),
        );
        let authorize_request = RequestEnvelope::new_with_dry_run(
            "authorizeEffect",
            encode_operation_payload(
                &AuthorizeEffectRequest {
                    effect_id: prepared.effect_id.clone(),
                    approval: None,
                },
                16 * 1024 * 1024,
            )?,
            false,
            Some("authorize-key".to_owned()),
            Some("\"0\"".to_owned()),
            None,
            None,
            vec![PathParameter::new(
                "effect_id",
                prepared.effect_id.as_str(),
            )?],
        )?;
        let authorized_response = authorize
            .call(request_context("authorizeEffect")?, authorize_request)
            .await
            .map_err(|error| {
                std::io::Error::other(format!(
                    "authorizeEffect adapter failed: {:?}",
                    error.code()
                ))
            })?;
        assert_eq!(authorized_response.semantic_etag(), Some("\"1\""));
        let authorized: EffectStatusResponse =
            decode_operation_payload(authorized_response.payload_cbor(), 16 * 1024 * 1024)?;
        assert_eq!(authorized.state, EffectState::Authorized);
        assert_eq!(authorized.effect_version, 1);

        let dispatch = TypedUnaryAdapter::<DispatchEffectOperation, _>::new(handlers, errors);
        let dispatch_request = RequestEnvelope::new_with_dry_run(
            "dispatchEffect",
            encode_operation_payload(
                &EffectIdRequest {
                    effect_id: prepared.effect_id,
                },
                16 * 1024 * 1024,
            )?,
            false,
            Some("dispatch-key".to_owned()),
            Some("1".to_owned()),
            None,
            None,
            vec![PathParameter::new(
                "effect_id",
                authorized.effect_id.as_str(),
            )?],
        )?;
        let dispatched_response = dispatch
            .call(request_context("dispatchEffect")?, dispatch_request)
            .await
            .map_err(|error| {
                std::io::Error::other(format!("dispatchEffect adapter failed: {:?}", error.code()))
            })?;
        let dispatched: EffectStatusResponse =
            decode_operation_payload(dispatched_response.payload_cbor(), 16 * 1024 * 1024)?;
        assert_eq!(dispatched.state, EffectState::Dispatching);
        assert_eq!(dispatched.attempt_count, 1);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);

        let worker_vault = Arc::new(OpenArgumentVault::default());
        let worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: Arc::new(WorkerAuthority::allowed(record(12)?)),
            clock: Arc::new(FixedClock(timestamp(2)?)),
            ids: Arc::new(TestIds(AtomicU64::new(1_000))),
            dispatch_gate: gate,
            argument_vault: worker_vault.clone(),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            worker.process_job(WorkerKind::Outbox, &queue.pop()?)?,
            EffectWorkerOutcome::Advanced
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(worker_vault.stages.load(Ordering::Acquire), 1);

        let verification_engine =
            EffectEngine::new(store, AccessContext::new(record(10)?, "verification")?);
        verification_engine.register_connector(connector)?;
        let retained = verification_engine.get(&dispatched.effect_id)?;
        assert_eq!(retained.state, EffectState::Succeeded);
        assert_eq!(retained.receipts.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_restart_retains_claimed_effect_and_worker_completes_exactly_once() -> TestResult
    {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("daemon-effect-restart.sqlite3");
        let connector = Arc::new(Connector::new());
        let gate = Arc::new(Gate(AtomicBool::new(true)));

        let (claimed, job) = {
            let store = Arc::new(SqliteStore::open(&database)?);
            let queue = Arc::new(DispatchQueue::default());
            let handlers = effect_handlers_for_repository(
                store,
                Arc::clone(&connector),
                gate.clone(),
                Arc::new(AllowEffects),
                BlockingPool::new(2, 2)?,
                queue.clone(),
                Arc::new(OpenArgumentVault::default()),
            )?;
            let prepared = prepare_effect_for(Arc::clone(&handlers), "restart-prepare").await?;
            let authorized =
                authorize_effect_for(Arc::clone(&handlers), &prepared, "restart-authorize").await?;
            let error_factory: Arc<dyn FacadeErrorFactory> = errors()?;
            let dispatch =
                TypedUnaryAdapter::<DispatchEffectOperation, _>::new(handlers, error_factory);
            let response = dispatch
                .call(
                    request_context("dispatchEffect")?,
                    dispatch_request(&authorized, "restart-dispatch")?,
                )
                .await?;
            let claimed: EffectStatusResponse =
                decode_operation_payload(response.payload_cbor(), 16 * 1024 * 1024)?;
            assert_eq!(claimed.state, EffectState::Dispatching);
            assert_eq!(claimed.attempt_count, 1);
            assert_eq!(connector.calls.load(Ordering::Acquire), 0);
            (claimed, queue.pop()?)
        };

        {
            let reopened = Arc::new(SqliteStore::open(&database)?);
            let verification = EffectEngine::new(
                Arc::clone(&reopened),
                AccessContext::new(record(10)?, "restart-before-worker")?,
            );
            verification.register_connector(connector.clone())?;
            let durable_claim = verification.get(&claimed.effect_id)?;
            assert_eq!(durable_claim.state, EffectState::Dispatching);
            assert_eq!(durable_claim.effect_version, claimed.effect_version);
            assert_eq!(durable_claim.attempts.len(), 1);

            let worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
                repository: reopened,
                authority: Arc::new(WorkerAuthority::allowed(record(12)?)),
                clock: Arc::new(FixedClock(timestamp(2)?)),
                ids: Arc::new(TestIds(AtomicU64::new(10_000))),
                dispatch_gate: gate,
                argument_vault: Arc::new(OpenArgumentVault::default()),
                connectors: vec![connector.clone()],
            })?;
            assert_eq!(
                worker.process_job(WorkerKind::Outbox, &job)?,
                EffectWorkerOutcome::Advanced
            );
            assert_eq!(
                worker.process_job(WorkerKind::Outbox, &job)?,
                EffectWorkerOutcome::AlreadyComplete
            );
            assert_eq!(connector.calls.load(Ordering::Acquire), 1);
        }

        let reopened = Arc::new(SqliteStore::open(&database)?);
        reopened.integrity_check()?;
        let verification = EffectEngine::new(
            reopened,
            AccessContext::new(record(10)?, "restart-after-worker")?,
        );
        verification.register_connector(connector)?;
        let completed = verification.get(&claimed.effect_id)?;
        assert_eq!(completed.state, EffectState::Succeeded);
        assert_eq!(completed.attempts.len(), 1);
        assert_eq!(completed.receipts.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn prepare_validates_protected_arguments_for_real_and_dry_run_without_staging()
    -> TestResult {
        let vault = Arc::new(OpenArgumentVault::default());
        let handlers = effect_handlers_with_queue_and_vault(
            Arc::new(InMemoryStore::default()),
            Arc::new(Connector::new()),
            Arc::new(Gate(AtomicBool::new(true))),
            Arc::new(AllowEffects),
            BlockingPool::new(1, 1)?,
            Arc::new(DispatchQueue::default()),
            vault.clone(),
        )?;
        let error_factory: Arc<dyn FacadeErrorFactory> = errors()?;
        let prepare = TypedUnaryAdapter::<PrepareEffectOperation, _>::new(handlers, error_factory);
        for (key, dry_run) in [("vault-real", false), ("vault-preview", true)] {
            let request = RequestEnvelope::new_with_dry_run(
                "prepareEffect",
                encode_operation_payload(&prepare_payload()?, 16 * 1024 * 1024)?,
                dry_run,
                Some(key.to_owned()),
                None,
                None,
                None,
                Vec::new(),
            )?;
            prepare
                .call(request_context("prepareEffect")?, request)
                .await?;
        }
        assert_eq!(vault.validations.load(Ordering::Acquire), 2);
        assert_eq!(vault.stages.load(Ordering::Acquire), 0);

        for (failure, expected) in [
            (
                EffectArgumentVaultError::InvalidArguments,
                ErrorCode::InvalidArgument,
            ),
            (
                EffectArgumentVaultError::NotFound,
                ErrorCode::InvalidArgument,
            ),
            (
                EffectArgumentVaultError::LimitExceeded,
                ErrorCode::LimitExceeded,
            ),
            (
                EffectArgumentVaultError::Unavailable,
                ErrorCode::DependencyUnavailable,
            ),
        ] {
            let handlers = effect_handlers_with_queue_and_vault(
                Arc::new(InMemoryStore::default()),
                Arc::new(Connector::new()),
                Arc::new(Gate(AtomicBool::new(true))),
                Arc::new(AllowEffects),
                BlockingPool::new(1, 1)?,
                Arc::new(DispatchQueue::default()),
                Arc::new(RejectingArgumentVault(failure)),
            )?;
            let error_factory: Arc<dyn FacadeErrorFactory> = errors()?;
            let prepare =
                TypedUnaryAdapter::<PrepareEffectOperation, _>::new(handlers, error_factory);
            let request = RequestEnvelope::new_with_dry_run(
                "prepareEffect",
                encode_operation_payload(&prepare_payload()?, 16 * 1024 * 1024)?,
                true,
                Some("vault-denied".to_owned()),
                None,
                None,
                None,
                Vec::new(),
            )?;
            let error = prepare
                .call(request_context("prepareEffect")?, request)
                .await
                .err()
                .ok_or("rejecting argument vault unexpectedly allowed prepare")?;
            assert_eq!(error.code(), expected);
        }
        Ok(())
    }

    #[tokio::test]
    async fn effect_read_denial_and_absence_share_one_existence_hidden_error() -> TestResult {
        let store = Arc::new(InMemoryStore::default());
        let connector = Arc::new(Connector::new());
        let gate = Arc::new(Gate(AtomicBool::new(true)));
        let allowed = effect_handlers(
            Arc::clone(&store),
            Arc::clone(&connector),
            Arc::clone(&gate),
        )?;
        let prepared = prepare_effect_for(Arc::clone(&allowed), "hidden-effect").await?;
        let denied = effect_handlers_with(
            store,
            connector,
            gate,
            Arc::new(DenyEffects),
            BlockingPool::new(1, 1)?,
        )?;
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let denied_adapter =
            TypedUnaryAdapter::<GetEffectStatusOperation, _>::new(denied, Arc::clone(&errors));
        let missing_adapter =
            TypedUnaryAdapter::<GetEffectStatusOperation, _>::new(allowed, errors);

        let get_request = |effect_id: RecordId| -> TestResult<RequestEnvelope> {
            Ok(RequestEnvelope::new_with_dry_run(
                "getEffectStatus",
                encode_operation_payload(
                    &EffectIdRequest {
                        effect_id: effect_id.clone(),
                    },
                    16 * 1024 * 1024,
                )?,
                false,
                None,
                None,
                None,
                None,
                vec![PathParameter::new("effect_id", effect_id.as_str())?],
            )?)
        };
        let denied_error = denied_adapter
            .call(
                request_context("getEffectStatus")?,
                get_request(prepared.effect_id)?,
            )
            .await
            .err()
            .ok_or("policy-denied effect read unexpectedly succeeded")?;
        let missing_error = missing_adapter
            .call(
                request_context("getEffectStatus")?,
                get_request(record(9_999)?)?,
            )
            .await
            .err()
            .ok_or("absent effect read unexpectedly succeeded")?;
        assert_eq!(denied_error.code(), ErrorCode::PolicyDenied);
        assert_eq!(missing_error.code(), ErrorCode::PolicyDenied);
        assert_eq!(
            denied_error.correlation_id(),
            missing_error.correlation_id()
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_worker_rechecks_gate_policy_deadline_and_lost_wakeup() -> TestResult {
        let store = Arc::new(InMemoryStore::default());
        let connector = Arc::new(Connector::new());
        let gate = Arc::new(Gate(AtomicBool::new(true)));
        let queue = Arc::new(DispatchQueue::default());
        let handlers = effect_handlers_with_queue(
            Arc::clone(&store),
            Arc::clone(&connector),
            Arc::clone(&gate),
            Arc::new(AllowEffects),
            BlockingPool::new(1, 2)?,
            Arc::clone(&queue),
        )?;
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let dispatch =
            TypedUnaryAdapter::<DispatchEffectOperation, _>::new(Arc::clone(&handlers), errors);

        let prepared = prepare_effect_for(Arc::clone(&handlers), "gate-prepare").await?;
        let authorized =
            authorize_effect_for(Arc::clone(&handlers), &prepared, "gate-authorize").await?;
        let response = dispatch
            .call(
                request_context("dispatchEffect")?,
                dispatch_request(&authorized, "gate-dispatch")?,
            )
            .await?;
        let claimed: EffectStatusResponse =
            decode_operation_payload(response.payload_cbor(), 16 * 1024 * 1024)?;
        assert_eq!(claimed.state, EffectState::Dispatching);
        let job = queue.pop()?;

        let authority = Arc::new(WorkerAuthority::allowed(record(12)?));
        let worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: authority.clone(),
            clock: Arc::new(FixedClock(timestamp(2)?)),
            ids: Arc::new(TestIds(AtomicU64::new(2_000))),
            dispatch_gate: gate.clone(),
            argument_vault: Arc::new(OpenArgumentVault::default()),
            connectors: vec![connector.clone()],
        })?;
        let mut stale_job = job.clone();
        stale_job.expected_revision = Some(ExpectedRevision(
            claimed
                .effect_version
                .checked_add(1)
                .ok_or("effect version overflow")?,
        ));
        assert!(worker.process_job(WorkerKind::Outbox, &stale_job).is_err());
        let wrong_tenant_job = WorkerJob {
            tenant: TenantId::new(record(99)?.as_str())?,
            record_id: job.record_id.clone(),
            expected_revision: job.expected_revision,
        };
        assert!(
            worker
                .process_job(WorkerKind::Outbox, &wrong_tenant_job)
                .is_err()
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        let race_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: Arc::new(WorkerAuthority::allowed(record(16)?)),
            clock: Arc::new(FixedClock(timestamp(2)?)),
            ids: Arc::new(TestIds(AtomicU64::new(2_250))),
            dispatch_gate: Arc::new(CloseAtConnectorEntryGate),
            argument_vault: Arc::new(OpenArgumentVault::default()),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            race_worker.process_job(WorkerKind::Outbox, &job)?,
            EffectWorkerOutcome::Deferred
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        gate.0.store(false, Ordering::Release);
        assert_eq!(
            worker.process_job(WorkerKind::Outbox, &job)?,
            EffectWorkerOutcome::Deferred
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);

        gate.0.store(true, Ordering::Release);
        let rejecting_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: Arc::new(WorkerAuthority::allowed(record(15)?)),
            clock: Arc::new(FixedClock(timestamp(2)?)),
            ids: Arc::new(TestIds(AtomicU64::new(2_500))),
            dispatch_gate: gate.clone(),
            argument_vault: Arc::new(RejectingArgumentVault(
                EffectArgumentVaultError::Unavailable,
            )),
            connectors: vec![connector.clone()],
        })?;
        assert!(
            rejecting_worker
                .process_job(WorkerKind::Outbox, &job)
                .is_err()
        );
        let before_denial = EffectEngine::new(
            Arc::clone(&store),
            AccessContext::new(record(10)?, "stage-failure-verification")?,
        );
        before_denial.register_connector(connector.clone())?;
        assert_eq!(
            before_denial.get(&claimed.effect_id)?.state,
            EffectState::Dispatching
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);

        authority.allowed.store(false, Ordering::Release);
        assert_eq!(
            worker.process_job(WorkerKind::Outbox, &job)?,
            EffectWorkerOutcome::Advanced
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        let verification = EffectEngine::new(
            Arc::clone(&store),
            AccessContext::new(record(10)?, "verification")?,
        );
        verification.register_connector(connector.clone())?;
        assert_eq!(
            verification.get(&claimed.effect_id)?.state,
            EffectState::Failed
        );

        let deadline = prepare_effect_for(Arc::clone(&handlers), "deadline-prepare").await?;
        let deadline =
            authorize_effect_for(Arc::clone(&handlers), &deadline, "deadline-authorize").await?;
        dispatch
            .call(
                request_context("dispatchEffect")?,
                dispatch_request(&deadline, "deadline-dispatch")?,
            )
            .await?;
        let deadline_job = queue.pop()?;
        let deadline_vault = Arc::new(OpenArgumentVault::default());
        let deadline_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: Arc::new(WorkerAuthority::allowed(record(13)?)),
            clock: Arc::new(AdvancingClock {
                first: timestamp(2)?,
                second: timestamp(4)?,
                observed: AtomicBool::new(false),
            }),
            ids: Arc::new(TestIds(AtomicU64::new(3_000))),
            dispatch_gate: gate.clone(),
            argument_vault: deadline_vault.clone(),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            deadline_worker.process_job(WorkerKind::Outbox, &deadline_job)?,
            EffectWorkerOutcome::Advanced
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        assert_eq!(deadline_vault.stages.load(Ordering::Acquire), 1);
        assert_eq!(
            verification.get(&deadline.effect_id)?.state,
            EffectState::Failed
        );

        queue.reject.store(true, Ordering::Release);
        let lost = prepare_effect_for(Arc::clone(&handlers), "lost-prepare").await?;
        let lost = authorize_effect_for(Arc::clone(&handlers), &lost, "lost-authorize").await?;
        let response = dispatch
            .call(
                request_context("dispatchEffect")?,
                dispatch_request(&lost, "lost-dispatch")?,
            )
            .await?;
        let lost: EffectStatusResponse =
            decode_operation_payload(response.payload_cbor(), 16 * 1024 * 1024)?;
        assert_eq!(lost.state, EffectState::Dispatching);
        assert!(
            queue
                .jobs
                .lock()
                .map_err(|_error| "queue lock poisoned")?
                .is_empty()
        );
        let recovered_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: Arc::new(WorkerAuthority::allowed(record(14)?)),
            clock: Arc::new(FixedClock(timestamp(2)?)),
            ids: Arc::new(TestIds(AtomicU64::new(4_000))),
            dispatch_gate: gate,
            argument_vault: Arc::new(OpenArgumentVault::default()),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            recovered_worker.process_dispatch(
                &record(10)?,
                &lost.effect_id,
                Some(cigar_protocol::ExpectedRevision(lost.effect_version)),
            )?,
            EffectWorkerOutcome::Advanced
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            verification.get(&lost.effect_id)?.state,
            EffectState::Succeeded
        );

        queue.reject.store(false, Ordering::Release);
        let revoked = prepare_effect_for(Arc::clone(&handlers), "revoked-prepare").await?;
        let revoked =
            authorize_effect_for(Arc::clone(&handlers), &revoked, "revoked-authorize").await?;
        let response = dispatch
            .call(
                request_context("dispatchEffect")?,
                dispatch_request(&revoked, "revoked-dispatch")?,
            )
            .await?;
        let revoked: EffectStatusResponse =
            decode_operation_payload(response.payload_cbor(), 16 * 1024 * 1024)?;
        let revoked_job = queue.pop()?;
        let revocable_authority = Arc::new(WorkerAuthority::allowed(record(17)?));
        let revoked_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: store,
            authority: revocable_authority.clone(),
            clock: Arc::new(FixedClock(timestamp(2)?)),
            ids: Arc::new(TestIds(AtomicU64::new(4_500))),
            dispatch_gate: Arc::new(Gate(AtomicBool::new(true))),
            argument_vault: Arc::new(RevokingArgumentVault {
                authority: revocable_authority,
            }),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            revoked_worker.process_job(WorkerKind::Outbox, &revoked_job)?,
            EffectWorkerOutcome::Advanced
        );
        assert_eq!(
            verification.get(&revoked.effect_id)?.state,
            EffectState::Failed
        );
        assert_eq!(connector.calls.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_worker_reloads_unknown_and_rechecks_gate_policy_and_vault() -> TestResult
    {
        let store = Arc::new(InMemoryStore::default());
        let connector = Arc::new(Connector::new());
        let gate = Arc::new(Gate(AtomicBool::new(true)));
        let queue = Arc::new(DispatchQueue::default());
        let handlers = effect_handlers_with_queue(
            Arc::clone(&store),
            Arc::clone(&connector),
            Arc::clone(&gate),
            Arc::new(AllowEffects),
            BlockingPool::new(1, 2)?,
            Arc::clone(&queue),
        )?;
        let prepared = prepare_effect_for(Arc::clone(&handlers), "reconcile-prepare").await?;
        let authorized =
            authorize_effect_for(Arc::clone(&handlers), &prepared, "reconcile-authorize").await?;
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let dispatch = TypedUnaryAdapter::<DispatchEffectOperation, _>::new(handlers, errors);
        let response = dispatch
            .call(
                request_context("dispatchEffect")?,
                dispatch_request(&authorized, "reconcile-dispatch")?,
            )
            .await?;
        let claimed: EffectStatusResponse =
            decode_operation_payload(response.payload_cbor(), 16 * 1024 * 1024)?;
        let _lost_wakeup = queue.pop()?;

        let engine = EffectEngine::new(
            Arc::clone(&store),
            AccessContext::new(record(10)?, "reconciliation-worker-test")?,
        );
        engine.register_connector(connector.clone())?;
        let unknown = engine.recover_inflight(
            &claimed.effect_id,
            claimed.effect_version,
            record(5_000)?,
            record(11)?,
            timestamp(3)?,
            digest(5_001)?,
        )?;
        assert_eq!(unknown.state, EffectState::Unknown);
        let job = WorkerJob {
            tenant: TenantId::new(record(10)?.as_str())?,
            record_id: claimed.effect_id.clone(),
            expected_revision: Some(ExpectedRevision(unknown.effect_version)),
        };

        let denied_authority = Arc::new(WorkerAuthority::allowed(record(12)?));
        denied_authority.allowed.store(false, Ordering::Release);
        let denied_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: denied_authority,
            clock: Arc::new(FixedClock(timestamp(4)?)),
            ids: Arc::new(TestIds(AtomicU64::new(5_100))),
            dispatch_gate: gate,
            argument_vault: Arc::new(OpenArgumentVault::default()),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            denied_worker.process_job(WorkerKind::Reconciliation, &job)?,
            EffectWorkerOutcome::Deferred
        );
        assert_eq!(engine.get(&claimed.effect_id)?.state, EffectState::Unknown);

        let race_worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: Arc::clone(&store),
            authority: Arc::new(WorkerAuthority::allowed(record(12)?)),
            clock: Arc::new(FixedClock(timestamp(4)?)),
            ids: Arc::new(TestIds(AtomicU64::new(5_200))),
            dispatch_gate: Arc::new(CloseAtConnectorEntryGate),
            argument_vault: Arc::new(OpenArgumentVault::default()),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            race_worker.process_job(WorkerKind::Reconciliation, &job)?,
            EffectWorkerOutcome::Deferred
        );
        assert_eq!(engine.get(&claimed.effect_id)?.state, EffectState::Unknown);

        let vault = Arc::new(OpenArgumentVault::default());
        let worker = EffectWorkerProcessor::new(EffectWorkerProcessorDependencies {
            repository: store,
            authority: Arc::new(WorkerAuthority::allowed(record(12)?)),
            clock: Arc::new(FixedClock(timestamp(4)?)),
            ids: Arc::new(TestIds(AtomicU64::new(5_300))),
            dispatch_gate: Arc::new(Gate(AtomicBool::new(true))),
            argument_vault: vault.clone(),
            connectors: vec![connector.clone()],
        })?;
        assert_eq!(
            worker.process_job(WorkerKind::Reconciliation, &job)?,
            EffectWorkerOutcome::Advanced
        );
        let reconciled = engine.get(&claimed.effect_id)?;
        assert_eq!(reconciled.state, EffectState::Succeeded);
        assert_eq!(reconciled.reconciliations.len(), 1);
        assert_eq!(connector.calls.load(Ordering::Acquire), 0);
        assert_eq!(vault.stages.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn replay_handlers_complete_and_reopen_jobs_and_live_drafts() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("typed-replay-adapter.sqlite3");
        let evidence_replay_id;
        let live_replay_id;
        let expected_completeness;

        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let archive = crate::DurableReplayArchive::new(Arc::clone(&repository), record(10)?);
            let capture = crate::durable_replay::tests::capture_fixture()?;
            let decision_id = capture.archive.decision.decision_id.clone();
            archive.put_capture(&capture)?;
            let handlers = replay_handlers(repository, 1_000)?;
            let errors: Arc<dyn FacadeErrorFactory> = errors()?;
            let create = TypedUnaryAdapter::<CreateReplayOperation, _>::new(
                Arc::clone(&handlers),
                Arc::clone(&errors),
            );

            let evidence_request = RequestEnvelope::new_with_dry_run(
                "createReplay",
                encode_operation_payload(
                    &CreateReplayRequest {
                        decision_id: decision_id.clone(),
                        mode: ReplayMode::EvidenceReproduction,
                        simulate_effects: true,
                    },
                    16 * 1024 * 1024,
                )?,
                false,
                Some("evidence-replay".to_owned()),
                None,
                None,
                None,
                Vec::new(),
            )?;
            let evidence_response = create
                .call(request_context("createReplay")?, evidence_request)
                .await?;
            let evidence: ReplayJobResponse =
                decode_operation_payload(evidence_response.payload_cbor(), 16 * 1024 * 1024)?;
            assert_eq!(evidence.status, ReplayJobStatus::Complete);
            let execution = evidence.execution.ok_or("missing evidence execution")?;
            evidence_replay_id = evidence.replay_id;
            expected_completeness = execution.completeness;

            let live_request = RequestEnvelope::new_with_dry_run(
                "createReplay",
                encode_operation_payload(
                    &CreateReplayRequest {
                        decision_id,
                        mode: ReplayMode::LiveComparison,
                        simulate_effects: true,
                    },
                    16 * 1024 * 1024,
                )?,
                false,
                Some("live-replay".to_owned()),
                None,
                None,
                None,
                Vec::new(),
            )?;
            let live_response = create
                .call(request_context("createReplay")?, live_request)
                .await?;
            let live: ReplayJobResponse =
                decode_operation_payload(live_response.payload_cbor(), 16 * 1024 * 1024)?;
            assert_eq!(live.status, ReplayJobStatus::PendingLive);
            assert!(live.execution.is_none());
            live_replay_id = live.replay_id;
        }

        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let handlers = replay_handlers(repository, 2_000)?;
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let completeness = TypedUnaryAdapter::<GetReplayCompletenessOperation, _>::new(
            handlers,
            Arc::clone(&errors),
        );
        for replay_id in [evidence_replay_id, live_replay_id] {
            let request = RequestEnvelope::new_with_dry_run(
                "getReplayCompleteness",
                encode_operation_payload(
                    &ReplayIdRequest {
                        replay_id: replay_id.clone(),
                    },
                    16 * 1024 * 1024,
                )?,
                false,
                None,
                None,
                None,
                None,
                vec![PathParameter::new("replay_id", replay_id.as_str())?],
            )?;
            let response = completeness
                .call(request_context("getReplayCompleteness")?, request)
                .await?;
            let reopened: ReplayCompleteness =
                decode_operation_payload(response.payload_cbor(), 16 * 1024 * 1024)?;
            assert_eq!(reopened, expected_completeness);
            assert!(reopened.missing.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn replay_request_cancellation_reaches_in_flight_repository_token() -> TestResult {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let repository = Arc::new(PausedGetRepository::new(entered_tx, release_rx));
        let handlers = replay_handlers(repository.clone(), 3_000)?;
        let errors: Arc<dyn FacadeErrorFactory> = errors()?;
        let create =
            TypedUnaryAdapter::<CreateReplayOperation, _>::new(Arc::clone(&handlers), errors);
        let request = RequestEnvelope::new_with_dry_run(
            "createReplay",
            encode_operation_payload(
                &CreateReplayRequest {
                    decision_id: version(3_001)?,
                    mode: ReplayMode::EvidenceReproduction,
                    simulate_effects: true,
                },
                16 * 1024 * 1024,
            )?,
            false,
            Some("cancel-in-flight-replay".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let request_cancellation = CancellationToken::new();
        let context =
            request_context_with("createReplay", timestamp(50)?, request_cancellation.clone())?;
        let call = tokio::spawn(async move { create.call(context, request).await });

        tokio::task::spawn_blocking(move || entered_rx.recv()).await??;
        request_cancellation.cancel();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), call).await;
        let repository_token_cancelled = repository.observed_cancellation()?.is_cancelled();
        release_tx.send(())?;
        let response = outcome??;
        let error = match response {
            Ok(_response) => return Err("cancelled replay request unexpectedly succeeded".into()),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::DeadlineExceeded);
        assert!(
            repository_token_cancelled,
            "the in-flight repository operation retained a detached cancellation token"
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !handlers.blocking_pool.is_drained() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(repository.commits.load(Ordering::Acquire), 0);
        Ok(())
    }

    fn live_authorization(value: u64) -> TestResult<LiveReplayAuthorization> {
        Ok(LiveReplayAuthorization {
            schema_version: cigar_protocol::SchemaVersion::new(
                "cigar.live-replay-authorization",
                1,
            )?,
            authorization_digest: digest(value)?,
            nonce: record(value + 1)?,
            request_id: record(value + 2)?,
            decision_id: version(value + 3)?,
            requested_by: record(value + 4)?,
            authorized_effect_intents: Vec::new(),
            not_before: timestamp(1)?,
            expires_at: timestamp(20)?,
            policy_snapshot_digest: digest(value + 5)?,
        })
    }

    #[test]
    fn live_authorizations_are_durable_idempotent_and_tenant_partitioned() -> TestResult {
        let store = Arc::new(InMemoryStore::default());
        let repository: Arc<dyn cigar_store::ServiceRepository> = store;
        let authorizations = DurableLiveReplayAuthorizationRepository::new(repository);
        let tenant = record(500)?;
        let other_tenant = record(501)?;
        let authorization_id = record(502)?;
        let authorization = live_authorization(600)?;
        let cancellation = StoreCancellation::default();

        authorizations.persist_issued(
            tenant.clone(),
            authorization_id.clone(),
            authorization.clone(),
            &cancellation,
        )?;
        authorizations.persist_issued(
            tenant.clone(),
            authorization_id.clone(),
            authorization.clone(),
            &cancellation,
        )?;
        assert_eq!(
            authorizations.get(&tenant, &authorization_id, &cancellation)?,
            authorization
        );
        assert_eq!(
            authorizations
                .get(&other_tenant, &authorization_id, &cancellation)
                .err(),
            Some(LiveAuthorizationRepositoryError::NotFound)
        );
        assert_eq!(
            authorizations
                .persist_issued(
                    tenant,
                    authorization_id,
                    live_authorization(700)?,
                    &cancellation,
                )
                .err(),
            Some(LiveAuthorizationRepositoryError::Conflict)
        );
        Ok(())
    }

    #[test]
    fn replay_mode_is_retained_in_authorization_fixture() -> TestResult {
        let authorization = live_authorization(800)?;
        let request = cigar_protocol::ReplayRequest {
            schema_version: cigar_protocol::SchemaVersion::new("cigar.replay-request", 1)?,
            request_id: authorization.request_id.clone(),
            decision_id: authorization.decision_id.clone(),
            mode: ReplayMode::LiveComparison,
            requested_by: authorization.requested_by.clone(),
            live_authorization_digest: Some(authorization.authorization_digest.clone()),
            simulate_effects: true,
            authorized_effect_intents: Vec::new(),
        };
        authorization.validate_binding(&request)?;
        Ok(())
    }
}
