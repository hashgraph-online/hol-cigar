//! Identity-only context-cycle state tracking shared by embedded and remote callers.

use cigar_protocol::{ContentDigest, DiffStatus, EffectState, RecordId, VersionId};
use std::fmt;

/// Maximum verified deltas before a successful full-bundle compile resets the chain.
pub const MAX_WORKFLOW_DELTA_CHAIN_LENGTH: u16 = 8;
/// Maximum exact cycle identities retained for one replayable workflow.
pub const MAX_WORKFLOW_REPLAY_CYCLES: usize = 64;

/// Closed workflow context-cycle phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkflowContextPhase {
    /// No context plan has been created.
    New,
    /// `createContextPlan` completed and its bundle must be loaded.
    PlanCreated,
    /// A changed target bundle was loaded and requires a delta from the active base.
    TargetBundleLoaded,
    /// `compileContextDelta` completed and must be locally applied and verified.
    DeltaCompiled,
    /// The current semantic bundle is exact and ready for materialization or a post-result fence.
    BundleReady,
    /// Provider-ready bytes were materialized for the current bundle.
    Materialized,
    /// A model invocation identity is durable but its result is not yet recorded.
    ModelInvocationPending,
    /// The exact model result identity is durable.
    ModelResultRecorded,
    /// A proposed effect intent is durable.
    EffectPrepared,
    /// Governed result or observation atoms were published.
    ObservationRecorded,
    /// The active bundle was revalidated immediately before effect authorization.
    EffectAuthorizationRevalidated,
    /// The durable effect is authorized and needs a fresh bundle revalidation.
    EffectAuthorized,
    /// The current bundle was revalidated immediately before dispatch.
    EffectRevalidated,
    /// A durable fenced dispatch is in progress.
    EffectDispatching,
    /// Dispatch outcome is ambiguous and must be reconciled.
    EffectAmbiguous,
    /// The effect reached one terminal state.
    EffectSettled,
    /// The completed cycle was checkpointed.
    Checkpointed,
    /// The workflow completed and awaits replay verification.
    Finished,
    /// Observational replay was verified.
    ReplayVerified,
    /// Cancellation, revocation, or invalidation terminally fenced all late results.
    Quarantined,
}

/// Closed reason that an in-flight workflow stopped accepting provider or tool results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowQuarantineReason {
    /// Caller cancellation ended the authoritative lifetime.
    Cancelled,
    /// Current authority was explicitly revoked.
    Revoked,
    /// Exact bundle revalidation failed.
    Invalidated,
}

impl WorkflowQuarantineReason {
    /// Stable shared-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Revoked => "revoked",
            Self::Invalidated => "invalidated",
        }
    }
}

impl WorkflowContextPhase {
    /// Stable shared-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::PlanCreated => "plan_created",
            Self::TargetBundleLoaded => "target_bundle_loaded",
            Self::DeltaCompiled => "delta_compiled",
            Self::BundleReady => "bundle_ready",
            Self::Materialized => "materialized",
            Self::ModelInvocationPending => "model_invocation_pending",
            Self::ModelResultRecorded => "model_result_recorded",
            Self::EffectPrepared => "effect_prepared",
            Self::ObservationRecorded => "observation_recorded",
            Self::EffectAuthorizationRevalidated => "effect_authorization_revalidated",
            Self::EffectAuthorized => "effect_authorized",
            Self::EffectRevalidated => "effect_revalidated",
            Self::EffectDispatching => "effect_dispatching",
            Self::EffectAmbiguous => "effect_ambiguous",
            Self::EffectSettled => "effect_settled",
            Self::Checkpointed => "checkpointed",
            Self::Finished => "finished",
            Self::ReplayVerified => "replay_verified",
            Self::Quarantined => "quarantined",
        }
    }
}

/// Exact action a recovered caller must resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkflowResumeAction {
    /// Call `createContextPlan`.
    CreateContextPlan,
    /// Call `compileContextBundle`.
    CompileContextBundle,
    /// Call `compileContextDelta`.
    CompileContextDelta,
    /// Apply and verify the sealed delta locally.
    ApplyContextDelta,
    /// Call `materializeContextBundle`.
    MaterializeContextBundle,
    /// Persist the next model invocation identity before invoking.
    BeginModelInvocation,
    /// Recover or reconcile the already durable model invocation.
    ResumeModelInvocation,
    /// Either persist a proposed effect or ingest a no-effect observation.
    PrepareEffectOrIngestObservation,
    /// Ingest the governed observation/result atoms.
    IngestObservation,
    /// Authorize the pending effect, or checkpoint when no effect exists.
    AuthorizeEffectOrCheckpoint,
    /// Call `revalidateContextBundle`.
    RevalidateContextBundle,
    /// Call `dispatchEffect` exactly once for the durable fence.
    DispatchEffect,
    /// Call `getEffectStatus` without redispatching.
    ObserveEffect,
    /// Call `reconcileEffect` before considering a retry.
    ReconcileEffect,
    /// Durably checkpoint the completed cycle.
    Checkpoint,
    /// Materialize the next turn or finish the workflow.
    MaterializeOrFinish,
    /// Create and run observational replay.
    Replay,
    /// No workflow action remains.
    Complete,
}

impl WorkflowResumeAction {
    /// Stable shared-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateContextPlan => "create_context_plan",
            Self::CompileContextBundle => "compile_context_bundle",
            Self::CompileContextDelta => "compile_context_delta",
            Self::ApplyContextDelta => "apply_context_delta",
            Self::MaterializeContextBundle => "materialize_context_bundle",
            Self::BeginModelInvocation => "begin_model_invocation",
            Self::ResumeModelInvocation => "resume_model_invocation",
            Self::PrepareEffectOrIngestObservation => "prepare_effect_or_ingest_observation",
            Self::IngestObservation => "ingest_observation",
            Self::AuthorizeEffectOrCheckpoint => "authorize_effect_or_checkpoint",
            Self::RevalidateContextBundle => "revalidate_context_bundle",
            Self::DispatchEffect => "dispatch_effect",
            Self::ObserveEffect => "observe_effect",
            Self::ReconcileEffect => "reconcile_effect",
            Self::Checkpoint => "checkpoint",
            Self::MaterializeOrFinish => "materialize_or_finish",
            Self::Replay => "replay",
            Self::Complete => "complete",
        }
    }

    /// Existing v1 operation that implements this action, when it is a server operation.
    #[must_use]
    pub const fn operation_id(self) -> Option<&'static str> {
        match self {
            Self::CreateContextPlan => Some("createContextPlan"),
            Self::CompileContextBundle => Some("compileContextBundle"),
            Self::CompileContextDelta => Some("compileContextDelta"),
            Self::MaterializeContextBundle => Some("materializeContextBundle"),
            Self::IngestObservation => Some("ingestCatalog"),
            Self::AuthorizeEffectOrCheckpoint => Some("authorizeEffect"),
            Self::RevalidateContextBundle => Some("revalidateContextBundle"),
            Self::DispatchEffect => Some("dispatchEffect"),
            Self::ObserveEffect => Some("getEffectStatus"),
            Self::ReconcileEffect => Some("reconcileEffect"),
            Self::Replay => Some("createReplay"),
            Self::ApplyContextDelta
            | Self::BeginModelInvocation
            | Self::ResumeModelInvocation
            | Self::PrepareEffectOrIngestObservation
            | Self::Checkpoint
            | Self::MaterializeOrFinish
            | Self::Complete => None,
        }
    }
}

/// Stable local workflow-state failure category, shared by all four SDKs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkflowSessionErrorCode {
    /// The event is not legal in the current phase.
    InvalidTransition,
    /// An event field or state is outside the closed contract.
    InvalidEvent,
    /// An event substituted an immutable plan, bundle, delta, invocation, or effect identity.
    IdentityMismatch,
    /// Current bundle revalidation failed closed.
    Invalidated,
    /// A monotonic bounded counter overflowed.
    LimitExceeded,
}

impl WorkflowSessionErrorCode {
    /// Stable shared-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTransition => "invalid_transition",
            Self::InvalidEvent => "invalid_event",
            Self::IdentityMismatch => "identity_mismatch",
            Self::Invalidated => "invalidated",
            Self::LimitExceeded => "limit_exceeded",
        }
    }
}

/// Stable event inventory in shared-contract order.
pub const WORKFLOW_SESSION_EVENT_NAMES: [&str; 17] = [
    "plan_created",
    "bundle_compiled",
    "delta_compiled",
    "delta_applied",
    "materialized",
    "model_invocation_started",
    "model_result_recorded",
    "effect_prepared",
    "observation_recorded",
    "effect_authorized",
    "effect_revalidated",
    "effect_dispatched",
    "effect_observed",
    "cycle_checkpointed",
    "finished",
    "replay_verified",
    "context_quarantined",
];

/// Content-safe local workflow state-machine failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WorkflowSessionError {
    code: WorkflowSessionErrorCode,
}

impl WorkflowSessionError {
    const fn new(code: WorkflowSessionErrorCode) -> Self {
        Self { code }
    }

    /// Stable failure category.
    #[must_use]
    pub const fn code(self) -> WorkflowSessionErrorCode {
        self.code
    }
}

impl fmt::Debug for WorkflowSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowSessionError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for WorkflowSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "workflow context transition failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for WorkflowSessionError {}

/// One successful boundary observation applied to [`WorkflowContextSession`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkflowSessionEvent {
    /// Successful `createContextPlan` identity tuple.
    PlanCreated {
        /// Persisted plan identity.
        plan_id: RecordId,
        /// Persisted compiled bundle identity returned with the plan.
        bundle_id: VersionId,
        /// Normalized contract digest bound into the plan and bundle.
        contract_digest: ContentDigest,
    },
    /// Successful `compileContextBundle` identity tuple.
    BundleCompiled {
        /// Loaded semantic bundle.
        bundle_id: VersionId,
        /// Contract digest carried by the bundle.
        contract_digest: ContentDigest,
    },
    /// Successful `compileContextDelta` identity tuple.
    DeltaCompiled {
        /// Exact current base bundle.
        base_bundle_id: VersionId,
        /// Exact pending target bundle.
        target_bundle_id: VersionId,
        /// Sealed delta-record digest.
        delta_digest: ContentDigest,
    },
    /// Successful local sealed-delta application and target verification.
    DeltaApplied {
        /// Verified base bundle.
        base_bundle_id: VersionId,
        /// Reproduced target bundle.
        target_bundle_id: VersionId,
        /// Exact applied delta digest.
        delta_digest: ContentDigest,
    },
    /// Successful `materializeContextBundle` identity tuple.
    Materialized {
        /// Materialized bundle.
        bundle_id: VersionId,
        /// Exact tokenizer implementation fingerprint.
        tokenizer_fingerprint: ContentDigest,
        /// Exact materializer implementation fingerprint.
        materializer_fingerprint: ContentDigest,
        /// Exact physical input tokens.
        physical_input_tokens: u32,
    },
    /// Durable invocation identity written before crossing the model boundary.
    ModelInvocationStarted {
        /// Stable invocation identity used for recovery and billing reconciliation.
        invocation_id: RecordId,
        /// Digest of the exact provider request envelope.
        request_digest: ContentDigest,
        /// Provider-facing idempotency key digest persisted before billing can begin.
        idempotency_key_digest: ContentDigest,
    },
    /// Durable exact model result identity.
    ModelResultRecorded {
        /// Invocation whose result was recorded.
        invocation_id: RecordId,
        /// Digest of the exact protected model result.
        result_digest: ContentDigest,
    },
    /// Successful `prepareEffect` result.
    EffectPrepared {
        /// Durable effect identity.
        effect_id: RecordId,
        /// Immutable effect intent digest.
        intent_digest: ContentDigest,
        /// Monotonic effect version.
        effect_version: u64,
        /// Must be [`EffectState::Prepared`].
        state: EffectState,
        /// Must be zero before dispatch.
        attempt_count: u32,
        /// Must be zero before reconciliation.
        reconciliation_count: u32,
    },
    /// Governed observation/result publication identity.
    ObservationRecorded {
        /// Exact publication digest.
        publication_digest: ContentDigest,
        /// Non-zero durable catalog revision.
        revision: u64,
    },
    /// Successful `authorizeEffect` result.
    EffectAuthorized {
        /// Durable effect identity.
        effect_id: RecordId,
        /// Immutable effect intent digest.
        intent_digest: ContentDigest,
        /// Strictly newer effect version.
        effect_version: u64,
        /// Must be [`EffectState::Authorized`].
        state: EffectState,
        /// Must equal the current durable attempt count.
        attempt_count: u32,
        /// Must equal the current durable reconciliation count.
        reconciliation_count: u32,
    },
    /// Successful current `revalidateContextBundle` result.
    EffectRevalidated {
        /// Revalidated active bundle.
        bundle_id: VersionId,
        /// False terminally quarantines the session.
        valid: bool,
    },
    /// Successful single `dispatchEffect` call result.
    EffectDispatched {
        /// Durable effect identity.
        effect_id: RecordId,
        /// Immutable effect intent digest.
        intent_digest: ContentDigest,
        /// Strictly newer effect version.
        effect_version: u64,
        /// Dispatching, unknown, or terminal result state.
        state: EffectState,
        /// Must advance by exactly one durable attempt.
        attempt_count: u32,
        /// Must not change at dispatch.
        reconciliation_count: u32,
    },
    /// Successful effect status or reconciliation observation.
    EffectObserved {
        /// Durable effect identity.
        effect_id: RecordId,
        /// Immutable effect intent digest.
        intent_digest: ContentDigest,
        /// Same version is allowed only for the same state.
        effect_version: u64,
        /// Closed observed effect state.
        state: EffectState,
        /// Monotonic durable dispatch-attempt count.
        attempt_count: u32,
        /// Monotonic durable reconciliation count.
        reconciliation_count: u32,
    },
    /// Durable completion checkpoint for the current cycle.
    CycleCheckpointed,
    /// Workflow terminal decision after at least one checkpointed cycle.
    Finished,
    /// Verified observational replay identities.
    ReplayVerified {
        /// Replayed decision identity.
        decision_id: VersionId,
        /// Replay execution identity.
        execution_id: RecordId,
        /// Exact candidate transcript produced by observational replay.
        candidate: WorkflowContextReplayIdentity,
    },
    /// Terminally fence the exact active context and quarantine all late results.
    ContextQuarantined {
        /// Exact active semantic bundle root.
        bundle_id: VersionId,
        /// Closed cancellation or invalidation category.
        reason: WorkflowQuarantineReason,
    },
}

#[derive(Clone, Eq, PartialEq)]
struct ContextIdentity {
    plan_id: RecordId,
    bundle_id: VersionId,
    contract_digest: ContentDigest,
}

#[derive(Clone, Eq, PartialEq)]
struct DeltaIdentity {
    base_bundle_id: VersionId,
    target_bundle_id: VersionId,
    delta_digest: ContentDigest,
}

#[derive(Clone, Eq, PartialEq)]
struct EffectIdentity {
    effect_id: RecordId,
    intent_digest: ContentDigest,
    effect_version: u64,
    state: EffectState,
    attempt_count: u32,
    reconciliation_count: u32,
}

#[derive(Clone, Eq, PartialEq)]
struct MaterializationIdentity {
    bundle_id: VersionId,
    tokenizer_fingerprint: ContentDigest,
    materializer_fingerprint: ContentDigest,
    physical_input_tokens: u32,
}

#[derive(Clone, Eq, PartialEq)]
struct InvocationIdentity {
    invocation_id: RecordId,
    request_digest: ContentDigest,
    idempotency_key_digest: ContentDigest,
}

/// Exact selected delta identity retained for replay comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowDeltaReplayIdentity {
    /// Exact prior semantic root.
    pub base_bundle_id: VersionId,
    /// Exact selected target semantic root.
    pub target_bundle_id: VersionId,
    /// Digest of the sealed delta.
    pub delta_digest: ContentDigest,
}

/// Exact terminal effect decision retained for replay comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowEffectReplayIdentity {
    /// Durable effect identity.
    pub effect_id: RecordId,
    /// Immutable effect intent digest.
    pub intent_digest: ContentDigest,
    /// Final durable effect version.
    pub effect_version: u64,
    /// Final terminal effect state.
    pub state: EffectState,
    /// Durable dispatch attempt count.
    pub attempt_count: u32,
    /// Durable reconciliation count.
    pub reconciliation_count: u32,
}

/// Exact content-free identity transcript for one completed context cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowContextCycleIdentity {
    /// Selected plan identity.
    pub plan_id: RecordId,
    /// Selected semantic bundle root.
    pub bundle_id: VersionId,
    /// Selected requirement-contract digest.
    pub contract_digest: ContentDigest,
    /// Applied delta, absent for a full-root selection.
    pub selected_delta: Option<WorkflowDeltaReplayIdentity>,
    /// Bundle actually materialized for the provider request.
    pub materialized_bundle_id: VersionId,
    /// Exact tokenizer fingerprint.
    pub tokenizer_fingerprint: ContentDigest,
    /// Exact materializer fingerprint.
    pub materializer_fingerprint: ContentDigest,
    /// Exact physical input tokens.
    pub physical_input_tokens: u32,
    /// Stable provider invocation identity.
    pub invocation_id: RecordId,
    /// Digest of the exact provider request.
    pub request_digest: ContentDigest,
    /// Digest of the provider-facing idempotency key.
    pub idempotency_key_digest: ContentDigest,
    /// Digest of the exact protected model result.
    pub model_result_digest: ContentDigest,
    /// Terminal tool/effect decision, if one existed.
    pub effect: Option<WorkflowEffectReplayIdentity>,
    /// Exact governed outcome/publication digest.
    pub outcome_digest: ContentDigest,
    /// Non-zero durable outcome revision.
    pub outcome_revision: u64,
}

/// Bounded exact baseline or candidate transcript for a workflow replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowContextReplayIdentity {
    /// Ordered completed context cycles.
    pub cycles: Vec<WorkflowContextCycleIdentity>,
}

/// Fixed replay comparison dimensions for workflow diagnosis and verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowContextReplayComparison {
    /// Plan, full bundle, and delta selection equality.
    pub bundle_delta_selection: DiffStatus,
    /// Exact materialization identity equality.
    pub materialization: DiffStatus,
    /// Invocation and protected model-result equality.
    pub model_result_identity: DiffStatus,
    /// Terminal tool/effect decision equality.
    pub tool_effect_decisions: DiffStatus,
    /// Governed outcome identity equality.
    pub outcome: DiffStatus,
    /// True only when every dimension is equal.
    pub exact_match: bool,
}

/// Copy-safe, identity-only SDK helper for one deterministic workflow context lifecycle.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkflowContextSession {
    phase: WorkflowContextPhase,
    completed_turns: u32,
    delta_chain_length: u16,
    active_context: Option<ContextIdentity>,
    pending_context: Option<ContextIdentity>,
    pending_delta: Option<DeltaIdentity>,
    selected_delta: Option<DeltaIdentity>,
    materialization: Option<MaterializationIdentity>,
    invocation: Option<InvocationIdentity>,
    model_result_digest: Option<ContentDigest>,
    observation_digest: Option<ContentDigest>,
    observation_revision: Option<u64>,
    effect: Option<EffectIdentity>,
    completed_cycles: Vec<WorkflowContextCycleIdentity>,
    replay_verified: bool,
    quarantine_reason: Option<WorkflowQuarantineReason>,
}

impl fmt::Debug for WorkflowContextSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowContextSession")
            .field("phase", &self.phase)
            .field("completed_turns", &self.completed_turns)
            .field("delta_chain_length", &self.delta_chain_length)
            .field("has_active_context", &self.active_context.is_some())
            .field("has_pending_context", &self.pending_context.is_some())
            .field("has_pending_delta", &self.pending_delta.is_some())
            .field("has_selected_delta", &self.selected_delta.is_some())
            .field("has_invocation", &self.invocation.is_some())
            .field("has_provider_idempotency_key", &self.invocation.is_some())
            .field("has_model_result", &self.model_result_digest.is_some())
            .field("has_observation", &self.observation_digest.is_some())
            .field(
                "effect_state",
                &self.effect.as_ref().map(|effect| effect.state),
            )
            .field("completed_cycle_count", &self.completed_cycles.len())
            .field("quarantine_reason", &self.quarantine_reason)
            .finish_non_exhaustive()
    }
}

impl Default for WorkflowContextSession {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkflowContextSession {
    /// Creates an empty context cycle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: WorkflowContextPhase::New,
            completed_turns: 0,
            delta_chain_length: 0,
            active_context: None,
            pending_context: None,
            pending_delta: None,
            selected_delta: None,
            materialization: None,
            invocation: None,
            model_result_digest: None,
            observation_digest: None,
            observation_revision: None,
            effect: None,
            completed_cycles: Vec::new(),
            replay_verified: false,
            quarantine_reason: None,
        }
    }

    /// Current closed phase.
    #[must_use]
    pub const fn phase(&self) -> WorkflowContextPhase {
        self.phase
    }

    /// Number of durably checkpointed turns.
    #[must_use]
    pub const fn completed_turns(&self) -> u32 {
        self.completed_turns
    }

    /// Number of applied deltas since the last future full-bundle checkpoint reset.
    #[must_use]
    pub const fn delta_chain_length(&self) -> u16 {
        self.delta_chain_length
    }

    /// Current exact semantic bundle root.
    #[must_use]
    pub fn active_bundle_id(&self) -> Option<&VersionId> {
        self.active_context
            .as_ref()
            .map(|context| &context.bundle_id)
    }

    /// Returns the exact bounded identity transcript after the workflow has finished.
    pub fn replay_identity(&self) -> Result<WorkflowContextReplayIdentity, WorkflowSessionError> {
        if !matches!(
            self.phase,
            WorkflowContextPhase::Finished | WorkflowContextPhase::ReplayVerified
        ) || self.completed_cycles.is_empty()
        {
            return Err(invalid_transition());
        }
        Ok(WorkflowContextReplayIdentity {
            cycles: self.completed_cycles.clone(),
        })
    }

    /// Produces a fixed comparison view without accepting a mismatched replay.
    pub fn compare_replay(
        &self,
        candidate: &WorkflowContextReplayIdentity,
    ) -> Result<WorkflowContextReplayComparison, WorkflowSessionError> {
        let baseline = self.replay_identity()?;
        if candidate.cycles.is_empty()
            || candidate.cycles.len() > MAX_WORKFLOW_REPLAY_CYCLES
            || candidate.cycles.iter().any(|cycle| {
                cycle.physical_input_tokens == 0
                    || cycle.outcome_revision == 0
                    || cycle.selected_delta.as_ref().is_some_and(|delta| {
                        delta.target_bundle_id != cycle.bundle_id
                            || delta.base_bundle_id != cycle.materialized_bundle_id
                            || delta.base_bundle_id == delta.target_bundle_id
                    })
                    || cycle.effect.as_ref().is_some_and(|effect| {
                        effect.effect_version == 0
                            || !effect_state_terminal(effect.state)
                            || !effect_counts_valid(
                                effect.state,
                                effect.attempt_count,
                                effect.reconciliation_count,
                            )
                    })
            })
        {
            return Err(invalid_event());
        }
        Ok(compare_workflow_replay(&baseline, candidate))
    }

    /// Exact next action after restart.
    #[must_use]
    pub const fn resume_action(&self) -> WorkflowResumeAction {
        match self.phase {
            WorkflowContextPhase::New | WorkflowContextPhase::ObservationRecorded => {
                WorkflowResumeAction::CreateContextPlan
            }
            WorkflowContextPhase::PlanCreated => WorkflowResumeAction::CompileContextBundle,
            WorkflowContextPhase::TargetBundleLoaded => WorkflowResumeAction::CompileContextDelta,
            WorkflowContextPhase::DeltaCompiled => WorkflowResumeAction::ApplyContextDelta,
            WorkflowContextPhase::BundleReady => {
                if self.model_result_digest.is_some() {
                    if self.effect.is_some() {
                        WorkflowResumeAction::RevalidateContextBundle
                    } else {
                        WorkflowResumeAction::Checkpoint
                    }
                } else {
                    WorkflowResumeAction::MaterializeContextBundle
                }
            }
            WorkflowContextPhase::Materialized => WorkflowResumeAction::BeginModelInvocation,
            WorkflowContextPhase::ModelInvocationPending => {
                WorkflowResumeAction::ResumeModelInvocation
            }
            WorkflowContextPhase::ModelResultRecorded => {
                WorkflowResumeAction::PrepareEffectOrIngestObservation
            }
            WorkflowContextPhase::EffectPrepared => WorkflowResumeAction::IngestObservation,
            WorkflowContextPhase::EffectAuthorizationRevalidated => {
                WorkflowResumeAction::AuthorizeEffectOrCheckpoint
            }
            WorkflowContextPhase::EffectAuthorized => WorkflowResumeAction::RevalidateContextBundle,
            WorkflowContextPhase::EffectRevalidated => WorkflowResumeAction::DispatchEffect,
            WorkflowContextPhase::EffectDispatching => WorkflowResumeAction::ObserveEffect,
            WorkflowContextPhase::EffectAmbiguous => WorkflowResumeAction::ReconcileEffect,
            WorkflowContextPhase::EffectSettled => WorkflowResumeAction::Checkpoint,
            WorkflowContextPhase::Checkpointed => WorkflowResumeAction::MaterializeOrFinish,
            WorkflowContextPhase::Finished => WorkflowResumeAction::Replay,
            WorkflowContextPhase::ReplayVerified => WorkflowResumeAction::Complete,
            WorkflowContextPhase::Quarantined => WorkflowResumeAction::Complete,
        }
    }

    /// Applies one successful boundary event atomically. Failure leaves the session unchanged.
    pub fn advance(&mut self, event: WorkflowSessionEvent) -> Result<(), WorkflowSessionError> {
        let mut next = self.clone();
        next.apply(event)?;
        *self = next;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one auditable closed transition table"
    )]
    fn apply(&mut self, event: WorkflowSessionEvent) -> Result<(), WorkflowSessionError> {
        match event {
            WorkflowSessionEvent::PlanCreated {
                plan_id,
                bundle_id,
                contract_digest,
            } => {
                require_phase(
                    self.phase,
                    &[
                        WorkflowContextPhase::New,
                        WorkflowContextPhase::ObservationRecorded,
                    ],
                )?;
                self.pending_context = Some(ContextIdentity {
                    plan_id,
                    bundle_id,
                    contract_digest,
                });
                self.pending_delta = None;
                self.phase = WorkflowContextPhase::PlanCreated;
            }
            WorkflowSessionEvent::BundleCompiled {
                bundle_id,
                contract_digest,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::PlanCreated])?;
                let pending = self
                    .pending_context
                    .as_ref()
                    .ok_or_else(invalid_transition)?;
                if pending.bundle_id != bundle_id || pending.contract_digest != contract_digest {
                    return Err(identity_mismatch());
                }
                if self
                    .active_context
                    .as_ref()
                    .is_none_or(|active| active.bundle_id == pending.bundle_id)
                {
                    self.active_context = self.pending_context.take();
                    self.selected_delta = None;
                    if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
                        self.delta_chain_length = 0;
                    }
                    self.phase = WorkflowContextPhase::BundleReady;
                } else if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
                    self.active_context = self.pending_context.take();
                    self.selected_delta = None;
                    self.delta_chain_length = 0;
                    self.phase = WorkflowContextPhase::BundleReady;
                } else {
                    self.phase = WorkflowContextPhase::TargetBundleLoaded;
                }
            }
            WorkflowSessionEvent::DeltaCompiled {
                base_bundle_id,
                target_bundle_id,
                delta_digest,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::TargetBundleLoaded])?;
                if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
                    return Err(limit_exceeded());
                }
                let active = self
                    .active_context
                    .as_ref()
                    .ok_or_else(invalid_transition)?;
                let pending = self
                    .pending_context
                    .as_ref()
                    .ok_or_else(invalid_transition)?;
                if active.bundle_id != base_bundle_id || pending.bundle_id != target_bundle_id {
                    return Err(identity_mismatch());
                }
                self.pending_delta = Some(DeltaIdentity {
                    base_bundle_id,
                    target_bundle_id,
                    delta_digest,
                });
                self.phase = WorkflowContextPhase::DeltaCompiled;
            }
            WorkflowSessionEvent::DeltaApplied {
                base_bundle_id,
                target_bundle_id,
                delta_digest,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::DeltaCompiled])?;
                let pending = self.pending_delta.as_ref().ok_or_else(invalid_transition)?;
                if pending.base_bundle_id != base_bundle_id
                    || pending.target_bundle_id != target_bundle_id
                    || pending.delta_digest != delta_digest
                {
                    return Err(identity_mismatch());
                }
                if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
                    return Err(limit_exceeded());
                }
                self.delta_chain_length += 1;
                self.selected_delta = Some(pending.clone());
                self.active_context = self.pending_context.take();
                self.pending_delta = None;
                self.phase = WorkflowContextPhase::BundleReady;
            }
            WorkflowSessionEvent::Materialized {
                bundle_id,
                tokenizer_fingerprint,
                materializer_fingerprint,
                physical_input_tokens,
            } => {
                require_phase(
                    self.phase,
                    &[
                        WorkflowContextPhase::BundleReady,
                        WorkflowContextPhase::Checkpointed,
                    ],
                )?;
                if self.model_result_digest.is_some() || physical_input_tokens == 0 {
                    return Err(invalid_event());
                }
                if self.active_bundle_id() != Some(&bundle_id) {
                    return Err(identity_mismatch());
                }
                self.materialization = Some(MaterializationIdentity {
                    bundle_id,
                    tokenizer_fingerprint,
                    materializer_fingerprint,
                    physical_input_tokens,
                });
                self.phase = WorkflowContextPhase::Materialized;
            }
            WorkflowSessionEvent::ModelInvocationStarted {
                invocation_id,
                request_digest,
                idempotency_key_digest,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::Materialized])?;
                self.invocation = Some(InvocationIdentity {
                    invocation_id,
                    request_digest,
                    idempotency_key_digest,
                });
                self.phase = WorkflowContextPhase::ModelInvocationPending;
            }
            WorkflowSessionEvent::ModelResultRecorded {
                invocation_id,
                result_digest,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::ModelInvocationPending])?;
                if self
                    .invocation
                    .as_ref()
                    .is_none_or(|identity| identity.invocation_id != invocation_id)
                {
                    return Err(identity_mismatch());
                }
                self.model_result_digest = Some(result_digest);
                self.phase = WorkflowContextPhase::ModelResultRecorded;
            }
            WorkflowSessionEvent::EffectPrepared {
                effect_id,
                intent_digest,
                effect_version,
                state,
                attempt_count,
                reconciliation_count,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::ModelResultRecorded])?;
                if self.effect.is_some()
                    || effect_version == 0
                    || state != EffectState::Prepared
                    || attempt_count != 0
                    || reconciliation_count != 0
                {
                    return Err(invalid_event());
                }
                self.effect = Some(EffectIdentity {
                    effect_id,
                    intent_digest,
                    effect_version,
                    state,
                    attempt_count,
                    reconciliation_count,
                });
                self.phase = WorkflowContextPhase::EffectPrepared;
            }
            WorkflowSessionEvent::ObservationRecorded {
                publication_digest,
                revision,
            } => {
                require_phase(
                    self.phase,
                    &[
                        WorkflowContextPhase::ModelResultRecorded,
                        WorkflowContextPhase::EffectPrepared,
                    ],
                )?;
                if revision == 0 {
                    return Err(invalid_event());
                }
                self.observation_digest = Some(publication_digest);
                self.observation_revision = Some(revision);
                self.phase = WorkflowContextPhase::ObservationRecorded;
            }
            WorkflowSessionEvent::EffectAuthorized {
                effect_id,
                intent_digest,
                effect_version,
                state,
                attempt_count,
                reconciliation_count,
            } => {
                require_phase(
                    self.phase,
                    &[WorkflowContextPhase::EffectAuthorizationRevalidated],
                )?;
                if self.model_result_digest.is_none() || state != EffectState::Authorized {
                    return Err(invalid_event());
                }
                let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
                if attempt_count != current.attempt_count
                    || reconciliation_count != current.reconciliation_count
                {
                    return Err(invalid_event());
                }
                self.update_effect(
                    EffectIdentity {
                        effect_id,
                        intent_digest,
                        effect_version,
                        state,
                        attempt_count,
                        reconciliation_count,
                    },
                    true,
                )?;
                self.phase = WorkflowContextPhase::EffectAuthorized;
            }
            WorkflowSessionEvent::EffectRevalidated { bundle_id, valid } => {
                let before_authorization = self.phase == WorkflowContextPhase::BundleReady
                    && self.model_result_digest.is_some()
                    && self
                        .effect
                        .as_ref()
                        .is_some_and(|effect| effect.state == EffectState::Prepared);
                if !before_authorization && self.phase != WorkflowContextPhase::EffectAuthorized {
                    return Err(invalid_transition());
                }
                if self.active_bundle_id() != Some(&bundle_id) {
                    return Err(identity_mismatch());
                }
                if !valid {
                    self.enter_quarantine(WorkflowQuarantineReason::Invalidated);
                } else {
                    self.phase = if before_authorization {
                        WorkflowContextPhase::EffectAuthorizationRevalidated
                    } else {
                        WorkflowContextPhase::EffectRevalidated
                    };
                }
            }
            WorkflowSessionEvent::EffectDispatched {
                effect_id,
                intent_digest,
                effect_version,
                state,
                attempt_count,
                reconciliation_count,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::EffectRevalidated])?;
                if !dispatch_result_state(state) {
                    return Err(invalid_event());
                }
                let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
                if current.attempt_count.checked_add(1) != Some(attempt_count)
                    || reconciliation_count != current.reconciliation_count
                {
                    return Err(invalid_event());
                }
                self.update_effect(
                    EffectIdentity {
                        effect_id,
                        intent_digest,
                        effect_version,
                        state,
                        attempt_count,
                        reconciliation_count,
                    },
                    true,
                )?;
                self.phase = effect_phase(state)?;
            }
            WorkflowSessionEvent::EffectObserved {
                effect_id,
                intent_digest,
                effect_version,
                state,
                attempt_count,
                reconciliation_count,
            } => {
                let allowed = match self.phase {
                    WorkflowContextPhase::EffectDispatching => {
                        state == EffectState::Dispatching
                            || state == EffectState::Unknown
                            || effect_state_terminal(state)
                    }
                    WorkflowContextPhase::EffectAmbiguous => {
                        state == EffectState::Unknown
                            || state == EffectState::AuthorizedForRetry
                            || effect_state_terminal(state)
                    }
                    _ => false,
                };
                if !allowed {
                    return Err(invalid_transition());
                }
                let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
                if attempt_count < current.attempt_count
                    || reconciliation_count < current.reconciliation_count
                    || state == EffectState::AuthorizedForRetry
                        && (attempt_count != current.attempt_count
                            || reconciliation_count <= current.reconciliation_count)
                {
                    return Err(invalid_event());
                }
                self.update_effect(
                    EffectIdentity {
                        effect_id,
                        intent_digest,
                        effect_version,
                        state,
                        attempt_count,
                        reconciliation_count,
                    },
                    false,
                )?;
                self.phase = effect_phase(state)?;
            }
            WorkflowSessionEvent::CycleCheckpointed => {
                let effect_complete = match &self.effect {
                    None => self.phase == WorkflowContextPhase::BundleReady,
                    Some(effect) => {
                        self.phase == WorkflowContextPhase::EffectSettled
                            && effect_state_terminal(effect.state)
                    }
                };
                if !effect_complete
                    || self.model_result_digest.is_none()
                    || self.observation_digest.is_none()
                {
                    return Err(invalid_transition());
                }
                if self.completed_cycles.len() >= MAX_WORKFLOW_REPLAY_CYCLES {
                    return Err(limit_exceeded());
                }
                let selected = self
                    .active_context
                    .as_ref()
                    .ok_or_else(invalid_transition)?;
                let materialization = self
                    .materialization
                    .as_ref()
                    .ok_or_else(invalid_transition)?;
                let invocation = self.invocation.as_ref().ok_or_else(invalid_transition)?;
                self.completed_cycles.push(WorkflowContextCycleIdentity {
                    plan_id: selected.plan_id.clone(),
                    bundle_id: selected.bundle_id.clone(),
                    contract_digest: selected.contract_digest.clone(),
                    selected_delta: self.selected_delta.as_ref().map(|delta| {
                        WorkflowDeltaReplayIdentity {
                            base_bundle_id: delta.base_bundle_id.clone(),
                            target_bundle_id: delta.target_bundle_id.clone(),
                            delta_digest: delta.delta_digest.clone(),
                        }
                    }),
                    materialized_bundle_id: materialization.bundle_id.clone(),
                    tokenizer_fingerprint: materialization.tokenizer_fingerprint.clone(),
                    materializer_fingerprint: materialization.materializer_fingerprint.clone(),
                    physical_input_tokens: materialization.physical_input_tokens,
                    invocation_id: invocation.invocation_id.clone(),
                    request_digest: invocation.request_digest.clone(),
                    idempotency_key_digest: invocation.idempotency_key_digest.clone(),
                    model_result_digest: self
                        .model_result_digest
                        .clone()
                        .ok_or_else(invalid_transition)?,
                    effect: self
                        .effect
                        .as_ref()
                        .map(|effect| WorkflowEffectReplayIdentity {
                            effect_id: effect.effect_id.clone(),
                            intent_digest: effect.intent_digest.clone(),
                            effect_version: effect.effect_version,
                            state: effect.state,
                            attempt_count: effect.attempt_count,
                            reconciliation_count: effect.reconciliation_count,
                        }),
                    outcome_digest: self
                        .observation_digest
                        .clone()
                        .ok_or_else(invalid_transition)?,
                    outcome_revision: self.observation_revision.ok_or_else(invalid_transition)?,
                });
                self.completed_turns = self
                    .completed_turns
                    .checked_add(1)
                    .ok_or_else(limit_exceeded)?;
                self.pending_context = None;
                self.pending_delta = None;
                self.selected_delta = None;
                self.materialization = None;
                self.invocation = None;
                self.model_result_digest = None;
                self.observation_digest = None;
                self.observation_revision = None;
                self.effect = None;
                self.phase = WorkflowContextPhase::Checkpointed;
            }
            WorkflowSessionEvent::Finished => {
                require_phase(self.phase, &[WorkflowContextPhase::Checkpointed])?;
                if self.completed_turns == 0 {
                    return Err(invalid_transition());
                }
                self.phase = WorkflowContextPhase::Finished;
            }
            WorkflowSessionEvent::ReplayVerified {
                decision_id: _decision_id,
                execution_id: _execution_id,
                candidate,
            } => {
                require_phase(self.phase, &[WorkflowContextPhase::Finished])?;
                if !self.compare_replay(&candidate)?.exact_match {
                    return Err(identity_mismatch());
                }
                self.replay_verified = true;
                self.phase = WorkflowContextPhase::ReplayVerified;
            }
            WorkflowSessionEvent::ContextQuarantined { bundle_id, reason } => {
                if matches!(
                    self.phase,
                    WorkflowContextPhase::New
                        | WorkflowContextPhase::Finished
                        | WorkflowContextPhase::ReplayVerified
                        | WorkflowContextPhase::Quarantined
                ) {
                    return Err(invalid_transition());
                }
                if self.active_bundle_id() != Some(&bundle_id) {
                    return Err(identity_mismatch());
                }
                self.enter_quarantine(reason);
            }
        }
        Ok(())
    }

    fn update_effect(
        &mut self,
        candidate: EffectIdentity,
        require_new_version: bool,
    ) -> Result<(), WorkflowSessionError> {
        if candidate.effect_version == 0
            || !effect_counts_valid(
                candidate.state,
                candidate.attempt_count,
                candidate.reconciliation_count,
            )
        {
            return Err(invalid_event());
        }
        let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
        let version_valid = if require_new_version {
            candidate.effect_version > current.effect_version
        } else {
            candidate.effect_version > current.effect_version
                || (candidate.effect_version == current.effect_version
                    && candidate.state == current.state)
        };
        if candidate.effect_id != current.effect_id
            || candidate.intent_digest != current.intent_digest
            || !version_valid
        {
            return Err(identity_mismatch());
        }
        self.effect = Some(candidate);
        Ok(())
    }

    fn enter_quarantine(&mut self, reason: WorkflowQuarantineReason) {
        self.pending_context = None;
        self.pending_delta = None;
        self.selected_delta = None;
        self.materialization = None;
        self.invocation = None;
        self.model_result_digest = None;
        self.observation_digest = None;
        self.observation_revision = None;
        self.effect = None;
        self.replay_verified = false;
        self.quarantine_reason = Some(reason);
        self.phase = WorkflowContextPhase::Quarantined;
    }
}

fn compare_workflow_replay(
    baseline: &WorkflowContextReplayIdentity,
    candidate: &WorkflowContextReplayIdentity,
) -> WorkflowContextReplayComparison {
    let same_length = baseline.cycles.len() == candidate.cycles.len();
    let bundle_delta_selection = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| {
                    baseline.plan_id == candidate.plan_id
                        && baseline.bundle_id == candidate.bundle_id
                        && baseline.contract_digest == candidate.contract_digest
                        && baseline.selected_delta == candidate.selected_delta
                }),
    );
    let materialization = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| {
                    baseline.materialized_bundle_id == candidate.materialized_bundle_id
                        && baseline.tokenizer_fingerprint == candidate.tokenizer_fingerprint
                        && baseline.materializer_fingerprint == candidate.materializer_fingerprint
                        && baseline.physical_input_tokens == candidate.physical_input_tokens
                }),
    );
    let model_result_identity = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| {
                    baseline.invocation_id == candidate.invocation_id
                        && baseline.request_digest == candidate.request_digest
                        && baseline.idempotency_key_digest == candidate.idempotency_key_digest
                        && baseline.model_result_digest == candidate.model_result_digest
                }),
    );
    let tool_effect_decisions = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| baseline.effect == candidate.effect),
    );
    let outcome = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| {
                    baseline.outcome_digest == candidate.outcome_digest
                        && baseline.outcome_revision == candidate.outcome_revision
                }),
    );
    WorkflowContextReplayComparison {
        bundle_delta_selection,
        materialization,
        model_result_identity,
        tool_effect_decisions,
        outcome,
        exact_match: [
            bundle_delta_selection,
            materialization,
            model_result_identity,
            tool_effect_decisions,
            outcome,
        ]
        .into_iter()
        .all(|status| status == DiffStatus::Equal),
    }
}

const fn comparison_status(equal: bool) -> DiffStatus {
    if equal {
        DiffStatus::Equal
    } else {
        DiffStatus::Different
    }
}

fn require_phase(
    phase: WorkflowContextPhase,
    allowed: &[WorkflowContextPhase],
) -> Result<(), WorkflowSessionError> {
    if allowed.contains(&phase) {
        Ok(())
    } else {
        Err(invalid_transition())
    }
}

const fn dispatch_result_state(state: EffectState) -> bool {
    matches!(state, EffectState::Dispatching | EffectState::Unknown) || effect_state_terminal(state)
}

fn effect_phase(state: EffectState) -> Result<WorkflowContextPhase, WorkflowSessionError> {
    match state {
        EffectState::Dispatching => Ok(WorkflowContextPhase::EffectDispatching),
        EffectState::Unknown => Ok(WorkflowContextPhase::EffectAmbiguous),
        EffectState::AuthorizedForRetry => Ok(WorkflowContextPhase::EffectAuthorized),
        state if effect_state_terminal(state) => Ok(WorkflowContextPhase::EffectSettled),
        _ => Err(invalid_event()),
    }
}

const fn effect_state_terminal(state: EffectState) -> bool {
    matches!(
        state,
        EffectState::Succeeded
            | EffectState::Failed
            | EffectState::ManualResolution
            | EffectState::Rejected
            | EffectState::Expired
            | EffectState::Cancelled
            | EffectState::Compensated
            | EffectState::CompensationFailed
    )
}

const fn effect_counts_valid(state: EffectState, attempts: u32, reconciliations: u32) -> bool {
    if reconciliations != 0 && attempts == 0 {
        return false;
    }
    match state {
        EffectState::Prepared | EffectState::Authorized => attempts == 0 && reconciliations == 0,
        EffectState::Dispatching
        | EffectState::Succeeded
        | EffectState::Failed
        | EffectState::Unknown
        | EffectState::Compensated
        | EffectState::CompensationFailed => attempts != 0,
        EffectState::AuthorizedForRetry => attempts != 0 && reconciliations != 0,
        EffectState::ManualResolution => attempts != 0 && reconciliations != 0,
        EffectState::Rejected => attempts == 0 && reconciliations == 0,
        EffectState::Expired | EffectState::Cancelled => true,
        EffectState::PendingApproval
        | EffectState::CompensationPending
        | EffectState::Compensating => false,
    }
}

const fn invalid_transition() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::InvalidTransition)
}

const fn invalid_event() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::InvalidEvent)
}

const fn identity_mismatch() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::IdentityMismatch)
}

const fn limit_exceeded() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::LimitExceeded)
}
