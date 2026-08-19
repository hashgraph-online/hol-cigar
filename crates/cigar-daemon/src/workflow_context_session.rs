//! Identity-only workflow context-cycle coordination over existing v1 operations.

use cigar_protocol::{
    ContentDigest, ContextBundle, DiffStatus, EffectState, RecordId, Validate, VersionId,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum verified deltas permitted before a compiled full bundle becomes the new checkpoint.
pub(crate) const MAX_WORKFLOW_DELTA_CHAIN_LENGTH: u16 = 8;
/// Maximum exact cycle identities retained in one replayable workflow session.
pub(crate) const MAX_WORKFLOW_REPLAY_CYCLES: usize = 64;

pub(crate) trait WorkflowPlanRecord {
    fn is_valid(&self) -> bool;
    fn plan_id(&self) -> &RecordId;
    fn bundle_id(&self) -> &VersionId;
    fn contract_digest(&self) -> &ContentDigest;
}

pub(crate) trait WorkflowDeltaRecord {
    fn is_valid(&self) -> bool;
    fn base_bundle_id(&self) -> &VersionId;
    fn target_bundle_id(&self) -> &VersionId;
    fn delta_digest(&self) -> &ContentDigest;
}

pub(crate) trait WorkflowAppliedDeltaRecord {
    fn base_bundle_id(&self) -> &VersionId;
    fn target_bundle_id(&self) -> &VersionId;
    fn delta_digest(&self) -> &ContentDigest;
}

pub(crate) trait WorkflowMaterializationRecord {
    fn is_valid(&self) -> bool;
    fn bundle_id(&self) -> &VersionId;
    fn tokenizer_fingerprint(&self) -> &ContentDigest;
    fn materializer_fingerprint(&self) -> &ContentDigest;
    fn physical_input_tokens(&self) -> u32;
}

pub(crate) trait WorkflowEffectStatusRecord {
    fn is_valid(&self) -> bool;
    fn effect_id(&self) -> &RecordId;
    fn intent_digest(&self) -> &ContentDigest;
    fn effect_version(&self) -> u64;
    fn state(&self) -> EffectState;
    fn attempt_count(&self) -> u32;
    fn reconciliation_count(&self) -> u32;
}

pub(crate) trait WorkflowRevalidationRecord {
    fn is_valid(&self) -> bool;
    fn bundle_id(&self) -> &VersionId;
    fn valid(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkflowContextPhase {
    New,
    PlanCreated,
    TargetBundleLoaded,
    DeltaCompiled,
    BundleReady,
    Materialized,
    ModelInvocationPending,
    ModelResultRecorded,
    EffectPrepared,
    ObservationRecorded,
    EffectAuthorizationRevalidated,
    EffectAuthorized,
    EffectRevalidated,
    EffectDispatching,
    EffectAmbiguous,
    EffectSettled,
    Checkpointed,
    Finished,
    ReplayVerified,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkflowQuarantineReason {
    Cancelled,
    Revoked,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowResumeAction {
    CreateContextPlan,
    CompileContextBundle,
    CompileContextDelta,
    ApplyContextDelta,
    MaterializeContextBundle,
    BeginModelInvocation,
    ResumeModelInvocation,
    PrepareEffectOrIngestObservation,
    IngestObservation,
    AuthorizeEffectOrCheckpoint,
    RevalidateContextBundle,
    DispatchEffect,
    ObserveEffect,
    ReconcileEffect,
    Checkpoint,
    MaterializeOrFinish,
    Replay,
    Complete,
}

impl WorkflowResumeAction {
    pub(crate) const fn operation_id(self) -> Option<&'static str> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowSessionErrorCode {
    InvalidTransition,
    InvalidResponse,
    IdentityMismatch,
    Invalidated,
    LimitExceeded,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct WorkflowSessionError {
    code: WorkflowSessionErrorCode,
}

impl WorkflowSessionError {
    const fn new(code: WorkflowSessionErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> WorkflowSessionErrorCode {
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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContextIdentity {
    plan_id: RecordId,
    bundle_id: VersionId,
    contract_digest: ContentDigest,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeltaIdentity {
    base_bundle_id: VersionId,
    target_bundle_id: VersionId,
    delta_digest: ContentDigest,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializationIdentity {
    bundle_id: VersionId,
    tokenizer_fingerprint: ContentDigest,
    materializer_fingerprint: ContentDigest,
    physical_input_tokens: u32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InvocationIdentity {
    invocation_id: RecordId,
    request_digest: ContentDigest,
    idempotency_key_digest: ContentDigest,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectIdentity {
    effect_id: RecordId,
    intent_digest: ContentDigest,
    effect_version: u64,
    state: EffectState,
    attempt_count: u32,
    reconciliation_count: u32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowContextCycleIdentity {
    selected_context: ContextIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_delta: Option<DeltaIdentity>,
    materialization: MaterializationIdentity,
    invocation: InvocationIdentity,
    model_result_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect: Option<EffectIdentity>,
    outcome_digest: ContentDigest,
    outcome_revision: u64,
}

/// Exact, content-free baseline or replay identity for every checkpointed workflow cycle.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkflowContextReplayIdentity {
    cycles: Vec<WorkflowContextCycleIdentity>,
}

/// Fixed comparison view that separates deterministic context selection from live-result drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowContextReplayComparison {
    pub(crate) bundle_delta_selection: DiffStatus,
    pub(crate) materialization: DiffStatus,
    pub(crate) model_result_identity: DiffStatus,
    pub(crate) tool_effect_decisions: DiffStatus,
    pub(crate) outcome: DiffStatus,
    pub(crate) exact_match: bool,
}

/// Daemon-internal state machine that composes existing operations into one context cycle.
///
/// The state contains identities and bounded counters only. Source text, prompts, model output,
/// tool arguments, and materialized bytes remain in their governed stores.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkflowContextSession {
    phase: WorkflowContextPhase,
    completed_turns: u32,
    delta_chain_length: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_context: Option<ContextIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_context: Option<ContextIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_delta: Option<DeltaIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_delta: Option<DeltaIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    materialization: Option<MaterializationIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation: Option<InvocationIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_result_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect: Option<EffectIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    completed_cycles: Vec<WorkflowContextCycleIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_decision_id: Option<VersionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_execution_id: Option<RecordId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            .field("has_materialization", &self.materialization.is_some())
            .field("has_invocation", &self.invocation.is_some())
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
    pub(crate) const fn new() -> Self {
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
            replay_decision_id: None,
            replay_execution_id: None,
            quarantine_reason: None,
        }
    }

    pub(crate) const fn phase(&self) -> WorkflowContextPhase {
        self.phase
    }

    pub(crate) const fn completed_turns(&self) -> u32 {
        self.completed_turns
    }

    pub(crate) const fn delta_chain_length(&self) -> u16 {
        self.delta_chain_length
    }

    pub(crate) fn active_bundle_id(&self) -> Option<&VersionId> {
        self.active_context
            .as_ref()
            .map(|context| &context.bundle_id)
    }

    pub(crate) const fn resume_action(&self) -> WorkflowResumeAction {
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

    /// Rejects any durable representation that could not have been produced by the closed
    /// transition table. This is intentionally stricter than Serde shape validation.
    pub(crate) fn validate_restored(&self) -> Result<(), WorkflowSessionError> {
        if self.delta_chain_length > MAX_WORKFLOW_DELTA_CHAIN_LENGTH
            || self.completed_cycles.len() > MAX_WORKFLOW_REPLAY_CYCLES
            || usize::try_from(self.completed_turns).ok() != Some(self.completed_cycles.len())
            || self
                .completed_cycles
                .iter()
                .any(|cycle| !cycle_identity_valid(cycle))
            || self.delta_chain_length == MAX_WORKFLOW_DELTA_CHAIN_LENGTH
                && matches!(
                    self.phase,
                    WorkflowContextPhase::TargetBundleLoaded | WorkflowContextPhase::DeltaCompiled
                )
            || self.pending_delta.as_ref().is_some_and(|delta| {
                self.active_context
                    .as_ref()
                    .is_none_or(|active| active.bundle_id != delta.base_bundle_id)
                    || self
                        .pending_context
                        .as_ref()
                        .is_none_or(|pending| pending.bundle_id != delta.target_bundle_id)
            })
            || self.selected_delta.as_ref().is_some_and(|delta| {
                self.active_context
                    .as_ref()
                    .is_none_or(|active| active.bundle_id != delta.target_bundle_id)
                    || self.materialization.as_ref().is_none_or(|materialization| {
                        materialization.bundle_id != delta.base_bundle_id
                    })
            })
            || self.selected_delta.is_some()
                && (self.model_result_digest.is_none() || self.pending_delta.is_some())
            || self
                .materialization
                .as_ref()
                .is_some_and(|materialization| {
                    materialization.physical_input_tokens == 0
                        || self.model_result_digest.is_none()
                            && self
                                .active_context
                                .as_ref()
                                .is_none_or(|active| active.bundle_id != materialization.bundle_id)
                })
            || self.model_result_digest.is_some() && self.invocation.is_none()
            || self.observation_digest.is_some() != self.observation_revision.is_some()
            || self
                .observation_revision
                .is_some_and(|revision| revision == 0)
            || self.observation_digest.is_some() && self.model_result_digest.is_none()
            || self.effect.as_ref().is_some_and(|effect| {
                effect.effect_version == 0
                    || self.model_result_digest.is_none()
                    || !effect_counts_valid(
                        effect.state,
                        effect.attempt_count,
                        effect.reconciliation_count,
                    )
            })
            || self.replay_decision_id.is_some() != self.replay_execution_id.is_some()
            || self.replay_decision_id.is_some()
                != matches!(self.phase, WorkflowContextPhase::ReplayVerified)
            || self.quarantine_reason.is_some()
                != matches!(self.phase, WorkflowContextPhase::Quarantined)
            || self.pending_context.is_some()
                != matches!(
                    self.phase,
                    WorkflowContextPhase::PlanCreated
                        | WorkflowContextPhase::TargetBundleLoaded
                        | WorkflowContextPhase::DeltaCompiled
                )
            || self.pending_delta.is_some()
                != matches!(self.phase, WorkflowContextPhase::DeltaCompiled)
        {
            return Err(invalid_response());
        }

        let has_cycle_result = self.materialization.is_some()
            && self.invocation.is_some()
            && self.model_result_digest.is_some()
            && self.observation_digest.is_some();
        let no_cycle_artifacts = self.pending_context.is_none()
            && self.pending_delta.is_none()
            && self.selected_delta.is_none()
            && self.materialization.is_none()
            && self.invocation.is_none()
            && self.model_result_digest.is_none()
            && self.observation_digest.is_none()
            && self.observation_revision.is_none()
            && self.effect.is_none();
        let valid = match self.phase {
            WorkflowContextPhase::New => {
                self.completed_turns == 0
                    && self.delta_chain_length == 0
                    && self.active_context.is_none()
                    && no_cycle_artifacts
                    && self.replay_decision_id.is_none()
            }
            WorkflowContextPhase::PlanCreated => {
                self.pending_context.is_some()
                    && self.pending_delta.is_none()
                    && ((self.active_context.is_none()
                        && self.completed_turns == 0
                        && self.invocation.is_none()
                        && self.model_result_digest.is_none()
                        && self.observation_digest.is_none()
                        && self.effect.is_none())
                        || (self.active_context.is_some()
                            && has_cycle_result
                            && self
                                .effect
                                .as_ref()
                                .is_none_or(|effect| effect.state == EffectState::Prepared)))
            }
            WorkflowContextPhase::TargetBundleLoaded => {
                self.active_context.is_some()
                    && self.pending_context.is_some()
                    && self.pending_delta.is_none()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_none_or(|effect| effect.state == EffectState::Prepared)
            }
            WorkflowContextPhase::DeltaCompiled => {
                self.active_context.is_some()
                    && self.pending_context.is_some()
                    && self.pending_delta.is_some()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_none_or(|effect| effect.state == EffectState::Prepared)
            }
            WorkflowContextPhase::BundleReady => {
                self.active_context.is_some()
                    && self.pending_context.is_none()
                    && self.pending_delta.is_none()
                    && ((self.model_result_digest.is_none()
                        && self.materialization.is_none()
                        && self.invocation.is_none()
                        && self.observation_digest.is_none()
                        && self.effect.is_none())
                        || (has_cycle_result
                            && self
                                .effect
                                .as_ref()
                                .is_none_or(|effect| effect.state == EffectState::Prepared)))
            }
            WorkflowContextPhase::Materialized => {
                self.active_context.is_some()
                    && self.pending_context.is_none()
                    && self.pending_delta.is_none()
                    && self.materialization.is_some()
                    && self.invocation.is_none()
                    && self.model_result_digest.is_none()
                    && self.observation_digest.is_none()
                    && self.effect.is_none()
            }
            WorkflowContextPhase::ModelInvocationPending => {
                self.active_context.is_some()
                    && self.materialization.is_some()
                    && self.invocation.is_some()
                    && self.model_result_digest.is_none()
                    && self.observation_digest.is_none()
                    && self.effect.is_none()
            }
            WorkflowContextPhase::ModelResultRecorded => {
                self.active_context.is_some()
                    && self.materialization.is_some()
                    && self.invocation.is_some()
                    && self.model_result_digest.is_some()
                    && self.observation_digest.is_none()
                    && self.effect.is_none()
            }
            WorkflowContextPhase::EffectPrepared => {
                self.active_context.is_some()
                    && self.materialization.is_some()
                    && self.invocation.is_some()
                    && self.model_result_digest.is_some()
                    && self.observation_digest.is_none()
                    && self
                        .effect
                        .as_ref()
                        .is_some_and(|effect| effect.state == EffectState::Prepared)
            }
            WorkflowContextPhase::ObservationRecorded => {
                self.active_context.is_some()
                    && self.materialization.is_some()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_none_or(|effect| effect.state == EffectState::Prepared)
            }
            WorkflowContextPhase::EffectAuthorized => {
                self.active_context.is_some()
                    && self.pending_context.is_none()
                    && self.pending_delta.is_none()
                    && has_cycle_result
                    && self.effect.as_ref().is_some_and(|effect| {
                        matches!(
                            effect.state,
                            EffectState::Authorized | EffectState::AuthorizedForRetry
                        )
                    })
            }
            WorkflowContextPhase::EffectAuthorizationRevalidated => {
                self.active_context.is_some()
                    && self.pending_context.is_none()
                    && self.pending_delta.is_none()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_some_and(|effect| effect.state == EffectState::Prepared)
            }
            WorkflowContextPhase::EffectRevalidated => {
                self.active_context.is_some()
                    && has_cycle_result
                    && self.effect.as_ref().is_some_and(|effect| {
                        matches!(
                            effect.state,
                            EffectState::Authorized | EffectState::AuthorizedForRetry
                        )
                    })
            }
            WorkflowContextPhase::EffectDispatching => {
                self.active_context.is_some()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_some_and(|effect| effect.state == EffectState::Dispatching)
            }
            WorkflowContextPhase::EffectAmbiguous => {
                self.active_context.is_some()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_some_and(|effect| effect.state == EffectState::Unknown)
            }
            WorkflowContextPhase::EffectSettled => {
                self.active_context.is_some()
                    && has_cycle_result
                    && self
                        .effect
                        .as_ref()
                        .is_some_and(|effect| effect_state_terminal(effect.state))
            }
            WorkflowContextPhase::Checkpointed | WorkflowContextPhase::Finished => {
                self.active_context.is_some()
                    && self.completed_turns != 0
                    && no_cycle_artifacts
                    && self.replay_decision_id.is_none()
            }
            WorkflowContextPhase::ReplayVerified => {
                self.active_context.is_some()
                    && self.completed_turns != 0
                    && no_cycle_artifacts
                    && self.replay_decision_id.is_some()
            }
            WorkflowContextPhase::Quarantined => {
                self.active_context.is_some()
                    && no_cycle_artifacts
                    && self.replay_decision_id.is_none()
                    && self.quarantine_reason.is_some()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(invalid_response())
        }
    }

    pub(crate) fn record_plan_created(
        &mut self,
        response: &impl WorkflowPlanRecord,
    ) -> Result<(), WorkflowSessionError> {
        if !matches!(
            self.phase,
            WorkflowContextPhase::New | WorkflowContextPhase::ObservationRecorded
        ) {
            return Err(invalid_transition());
        }
        if !response.is_valid() {
            return Err(invalid_response());
        }
        self.pending_context = Some(ContextIdentity {
            plan_id: response.plan_id().clone(),
            bundle_id: response.bundle_id().clone(),
            contract_digest: response.contract_digest().clone(),
        });
        self.pending_delta = None;
        self.phase = WorkflowContextPhase::PlanCreated;
        Ok(())
    }

    pub(crate) fn record_bundle_compiled(
        &mut self,
        bundle: &ContextBundle,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::PlanCreated {
            return Err(invalid_transition());
        }
        bundle.validate().map_err(|_error| invalid_response())?;
        let pending = self
            .pending_context
            .as_ref()
            .ok_or_else(invalid_transition)?;
        if pending.bundle_id != bundle.bundle_id
            || pending.contract_digest != bundle.contract_digest
        {
            return Err(identity_mismatch());
        }
        match &self.active_context {
            None => {
                self.active_context = self.pending_context.take();
                self.selected_delta = None;
                self.phase = WorkflowContextPhase::BundleReady;
            }
            Some(active) if active.bundle_id == pending.bundle_id => {
                self.active_context = self.pending_context.take();
                self.selected_delta = None;
                if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
                    self.delta_chain_length = 0;
                }
                self.phase = WorkflowContextPhase::BundleReady;
            }
            Some(_active) if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH => {
                self.active_context = self.pending_context.take();
                self.selected_delta = None;
                self.delta_chain_length = 0;
                self.phase = WorkflowContextPhase::BundleReady;
            }
            Some(_active) => {
                self.phase = WorkflowContextPhase::TargetBundleLoaded;
            }
        }
        Ok(())
    }

    pub(crate) fn record_delta_compiled(
        &mut self,
        response: &impl WorkflowDeltaRecord,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::TargetBundleLoaded {
            return Err(invalid_transition());
        }
        if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
            return Err(limit_exceeded());
        }
        if !response.is_valid() {
            return Err(invalid_response());
        }
        let active = self
            .active_context
            .as_ref()
            .ok_or_else(invalid_transition)?;
        let pending = self
            .pending_context
            .as_ref()
            .ok_or_else(invalid_transition)?;
        if response.base_bundle_id() != &active.bundle_id
            || response.target_bundle_id() != &pending.bundle_id
        {
            return Err(identity_mismatch());
        }
        self.pending_delta = Some(DeltaIdentity {
            base_bundle_id: response.base_bundle_id().clone(),
            target_bundle_id: response.target_bundle_id().clone(),
            delta_digest: response.delta_digest().clone(),
        });
        self.phase = WorkflowContextPhase::DeltaCompiled;
        Ok(())
    }

    pub(crate) fn record_delta_applied(
        &mut self,
        applied: &impl WorkflowAppliedDeltaRecord,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::DeltaCompiled {
            return Err(invalid_transition());
        }
        let pending_delta = self.pending_delta.as_ref().ok_or_else(invalid_transition)?;
        let pending_context = self
            .pending_context
            .as_ref()
            .ok_or_else(invalid_transition)?;
        if &pending_delta.base_bundle_id != applied.base_bundle_id()
            || &pending_delta.target_bundle_id != applied.target_bundle_id()
            || &pending_delta.delta_digest != applied.delta_digest()
            || pending_context.bundle_id != *applied.target_bundle_id()
        {
            return Err(identity_mismatch());
        }
        if self.delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH {
            return Err(limit_exceeded());
        }
        self.delta_chain_length += 1;
        self.selected_delta = Some(pending_delta.clone());
        self.active_context = self.pending_context.take();
        self.pending_delta = None;
        self.phase = WorkflowContextPhase::BundleReady;
        Ok(())
    }

    pub(crate) fn record_materialized(
        &mut self,
        response: &impl WorkflowMaterializationRecord,
    ) -> Result<(), WorkflowSessionError> {
        if !matches!(
            self.phase,
            WorkflowContextPhase::BundleReady | WorkflowContextPhase::Checkpointed
        ) || self.model_result_digest.is_some()
        {
            return Err(invalid_transition());
        }
        if !response.is_valid() {
            return Err(invalid_response());
        }
        let active = self
            .active_context
            .as_ref()
            .ok_or_else(invalid_transition)?;
        if response.bundle_id() != &active.bundle_id {
            return Err(identity_mismatch());
        }
        self.materialization = Some(MaterializationIdentity {
            bundle_id: response.bundle_id().clone(),
            tokenizer_fingerprint: response.tokenizer_fingerprint().clone(),
            materializer_fingerprint: response.materializer_fingerprint().clone(),
            physical_input_tokens: response.physical_input_tokens(),
        });
        self.phase = WorkflowContextPhase::Materialized;
        Ok(())
    }

    pub(crate) fn begin_model_invocation(
        &mut self,
        invocation_id: RecordId,
        request_digest: ContentDigest,
        idempotency_key_digest: ContentDigest,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::Materialized {
            return Err(invalid_transition());
        }
        self.invocation = Some(InvocationIdentity {
            invocation_id,
            request_digest,
            idempotency_key_digest,
        });
        self.phase = WorkflowContextPhase::ModelInvocationPending;
        Ok(())
    }

    pub(crate) fn record_model_result(
        &mut self,
        invocation_id: &RecordId,
        result_digest: ContentDigest,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::ModelInvocationPending {
            return Err(invalid_transition());
        }
        let invocation = self.invocation.as_ref().ok_or_else(invalid_transition)?;
        if &invocation.invocation_id != invocation_id {
            return Err(identity_mismatch());
        }
        self.model_result_digest = Some(result_digest);
        self.phase = WorkflowContextPhase::ModelResultRecorded;
        Ok(())
    }

    pub(crate) fn record_effect_prepared(
        &mut self,
        response: &impl WorkflowEffectStatusRecord,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::ModelResultRecorded || self.effect.is_some() {
            return Err(invalid_transition());
        }
        validate_effect_response(response)?;
        if response.state() != EffectState::Prepared {
            return Err(invalid_response());
        }
        self.effect = Some(effect_identity(response));
        self.phase = WorkflowContextPhase::EffectPrepared;
        Ok(())
    }

    pub(crate) fn record_observation(
        &mut self,
        publication_digest: ContentDigest,
        revision: u64,
    ) -> Result<(), WorkflowSessionError> {
        if !matches!(
            self.phase,
            WorkflowContextPhase::ModelResultRecorded | WorkflowContextPhase::EffectPrepared
        ) {
            return Err(invalid_transition());
        }
        if revision == 0 {
            return Err(invalid_response());
        }
        self.observation_digest = Some(publication_digest);
        self.observation_revision = Some(revision);
        self.phase = WorkflowContextPhase::ObservationRecorded;
        Ok(())
    }

    pub(crate) fn record_effect_authorized(
        &mut self,
        response: &impl WorkflowEffectStatusRecord,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::EffectAuthorizationRevalidated
            || self.model_result_digest.is_none()
        {
            return Err(invalid_transition());
        }
        validate_effect_response(response)?;
        if response.state() != EffectState::Authorized
            || self.effect.as_ref().is_none_or(|effect| {
                response.attempt_count() != effect.attempt_count
                    || response.reconciliation_count() != effect.reconciliation_count
            })
        {
            return Err(invalid_response());
        }
        self.update_effect(response, true)?;
        self.phase = WorkflowContextPhase::EffectAuthorized;
        Ok(())
    }

    pub(crate) fn record_effect_revalidated(
        &mut self,
        response: &impl WorkflowRevalidationRecord,
    ) -> Result<(), WorkflowSessionError> {
        let before_authorization = self.phase == WorkflowContextPhase::BundleReady
            && self.model_result_digest.is_some()
            && self
                .effect
                .as_ref()
                .is_some_and(|effect| effect.state == EffectState::Prepared);
        if !before_authorization && self.phase != WorkflowContextPhase::EffectAuthorized {
            return Err(invalid_transition());
        }
        if !response.is_valid() {
            return Err(invalid_response());
        }
        let active = self
            .active_context
            .as_ref()
            .ok_or_else(invalid_transition)?;
        if response.bundle_id() != &active.bundle_id {
            return Err(identity_mismatch());
        }
        if !response.valid() {
            self.enter_quarantine(WorkflowQuarantineReason::Invalidated);
            return Ok(());
        }
        self.phase = if before_authorization {
            WorkflowContextPhase::EffectAuthorizationRevalidated
        } else {
            WorkflowContextPhase::EffectRevalidated
        };
        Ok(())
    }

    pub(crate) fn quarantine_context(
        &mut self,
        bundle_id: &VersionId,
        reason: WorkflowQuarantineReason,
    ) -> Result<(), WorkflowSessionError> {
        if matches!(
            self.phase,
            WorkflowContextPhase::New
                | WorkflowContextPhase::Finished
                | WorkflowContextPhase::ReplayVerified
                | WorkflowContextPhase::Quarantined
        ) {
            return Err(invalid_transition());
        }
        if self.active_bundle_id() != Some(bundle_id) {
            return Err(identity_mismatch());
        }
        self.enter_quarantine(reason);
        Ok(())
    }

    pub(crate) fn record_effect_dispatched(
        &mut self,
        response: &impl WorkflowEffectStatusRecord,
    ) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::EffectRevalidated {
            return Err(invalid_transition());
        }
        validate_effect_response(response)?;
        let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
        if current.attempt_count.checked_add(1) != Some(response.attempt_count())
            || response.reconciliation_count() != current.reconciliation_count
        {
            return Err(invalid_response());
        }
        self.update_effect(response, true)?;
        self.phase = effect_phase(response.state())?;
        Ok(())
    }

    pub(crate) fn record_effect_observed(
        &mut self,
        response: &impl WorkflowEffectStatusRecord,
    ) -> Result<(), WorkflowSessionError> {
        let state_allowed = match self.phase {
            WorkflowContextPhase::EffectDispatching => {
                response.state() == EffectState::Dispatching
                    || response.state() == EffectState::Unknown
                    || effect_state_terminal(response.state())
            }
            WorkflowContextPhase::EffectAmbiguous => {
                response.state() == EffectState::Unknown
                    || response.state() == EffectState::AuthorizedForRetry
                    || effect_state_terminal(response.state())
            }
            _ => false,
        };
        if !state_allowed {
            return Err(invalid_transition());
        }
        validate_effect_response(response)?;
        let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
        if response.attempt_count() < current.attempt_count
            || response.reconciliation_count() < current.reconciliation_count
            || response.state() == EffectState::AuthorizedForRetry
                && (response.attempt_count() != current.attempt_count
                    || response.reconciliation_count() <= current.reconciliation_count)
        {
            return Err(invalid_response());
        }
        self.update_effect(response, false)?;
        self.phase = effect_phase(response.state())?;
        Ok(())
    }

    pub(crate) fn checkpoint_cycle(&mut self) -> Result<(), WorkflowSessionError> {
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
        let cycle = WorkflowContextCycleIdentity {
            selected_context: self.active_context.clone().ok_or_else(invalid_transition)?,
            selected_delta: self.selected_delta.clone(),
            materialization: self
                .materialization
                .clone()
                .ok_or_else(invalid_transition)?,
            invocation: self.invocation.clone().ok_or_else(invalid_transition)?,
            model_result_digest: self
                .model_result_digest
                .clone()
                .ok_or_else(invalid_transition)?,
            effect: self.effect.clone(),
            outcome_digest: self
                .observation_digest
                .clone()
                .ok_or_else(invalid_transition)?,
            outcome_revision: self.observation_revision.ok_or_else(invalid_transition)?,
        };
        if !cycle_identity_valid(&cycle) {
            return Err(invalid_response());
        }
        self.completed_cycles.push(cycle);
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
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::Checkpointed || self.completed_turns == 0 {
            return Err(invalid_transition());
        }
        self.phase = WorkflowContextPhase::Finished;
        Ok(())
    }

    /// Returns the exact bounded identity transcript used as the replay baseline.
    pub(crate) fn replay_identity(
        &self,
    ) -> Result<WorkflowContextReplayIdentity, WorkflowSessionError> {
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

    /// Compares every exact cycle identity while keeping decision dimensions separate.
    pub(crate) fn compare_replay(
        &self,
        candidate: &WorkflowContextReplayIdentity,
    ) -> Result<WorkflowContextReplayComparison, WorkflowSessionError> {
        let baseline = self.replay_identity()?;
        if candidate.cycles.is_empty()
            || candidate.cycles.len() > MAX_WORKFLOW_REPLAY_CYCLES
            || candidate
                .cycles
                .iter()
                .any(|cycle| !cycle_identity_valid(cycle))
        {
            return Err(invalid_response());
        }
        Ok(compare_workflow_replay(&baseline, candidate))
    }

    pub(crate) fn record_replay_verified(
        &mut self,
        decision_id: VersionId,
        execution_id: RecordId,
        candidate: &WorkflowContextReplayIdentity,
    ) -> Result<WorkflowContextReplayComparison, WorkflowSessionError> {
        if self.phase != WorkflowContextPhase::Finished {
            return Err(invalid_transition());
        }
        let comparison = self.compare_replay(candidate)?;
        if !comparison.exact_match {
            return Err(identity_mismatch());
        }
        self.replay_decision_id = Some(decision_id);
        self.replay_execution_id = Some(execution_id);
        self.phase = WorkflowContextPhase::ReplayVerified;
        Ok(comparison)
    }

    fn update_effect(
        &mut self,
        response: &impl WorkflowEffectStatusRecord,
        require_new_version: bool,
    ) -> Result<(), WorkflowSessionError> {
        let current = self.effect.as_ref().ok_or_else(invalid_transition)?;
        let version_valid = if require_new_version {
            response.effect_version() > current.effect_version
        } else {
            response.effect_version() > current.effect_version
                || (response.effect_version() == current.effect_version
                    && response.state() == current.state)
        };
        if response.effect_id() != &current.effect_id
            || response.intent_digest() != &current.intent_digest
            || !version_valid
        {
            return Err(identity_mismatch());
        }
        self.effect = Some(effect_identity(response));
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
        self.replay_decision_id = None;
        self.replay_execution_id = None;
        self.quarantine_reason = Some(reason);
        self.phase = WorkflowContextPhase::Quarantined;
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_record(data: &[u8]) {
    const MAX_FUZZ_SESSION_BYTES: usize = 1_048_576;

    if data.len() > MAX_FUZZ_SESSION_BYTES {
        return;
    }
    let Ok(node) = cigar_canon::parse_strict_json(data) else {
        return;
    };
    let Ok(normalized) = cigar_canon::to_normalized_json(&node) else {
        return;
    };
    let Ok(session) = serde_json::from_slice::<WorkflowContextSession>(&normalized) else {
        return;
    };
    let first = session
        .validate_restored()
        .map_err(WorkflowSessionError::code);
    let second = session
        .validate_restored()
        .map_err(WorkflowSessionError::code);
    assert_eq!(
        first, second,
        "workflow-session validation must be deterministic"
    );
    if first.is_ok() {
        let encoded =
            serde_json::to_vec(&session).expect("a validated workflow session must serialize");
        let restored: WorkflowContextSession =
            serde_json::from_slice(&encoded).expect("a serialized workflow session must decode");
        assert_eq!(session, restored, "workflow-session round trip drifted");
        assert!(
            restored.validate_restored().is_ok(),
            "a validated workflow session became invalid after round trip"
        );
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
                    baseline.selected_context == candidate.selected_context
                        && baseline.selected_delta == candidate.selected_delta
                }),
    );
    let materialization = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| baseline.materialization == candidate.materialization),
    );
    let model_result_identity = comparison_status(
        same_length
            && baseline
                .cycles
                .iter()
                .zip(&candidate.cycles)
                .all(|(baseline, candidate)| {
                    baseline.invocation == candidate.invocation
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

fn cycle_identity_valid(cycle: &WorkflowContextCycleIdentity) -> bool {
    cycle.materialization.physical_input_tokens != 0
        && cycle.outcome_revision != 0
        && cycle.selected_delta.as_ref().is_none_or(|delta| {
            delta.target_bundle_id == cycle.selected_context.bundle_id
                && delta.base_bundle_id != delta.target_bundle_id
                && delta.base_bundle_id == cycle.materialization.bundle_id
        })
        && cycle.effect.as_ref().is_none_or(|effect| {
            effect.effect_version != 0
                && effect_state_terminal(effect.state)
                && effect_counts_valid(
                    effect.state,
                    effect.attempt_count,
                    effect.reconciliation_count,
                )
        })
}

fn validate_effect_response(
    response: &impl WorkflowEffectStatusRecord,
) -> Result<(), WorkflowSessionError> {
    if !response.is_valid()
        || response.effect_version() == 0
        || !effect_counts_valid(
            response.state(),
            response.attempt_count(),
            response.reconciliation_count(),
        )
    {
        Err(invalid_response())
    } else {
        Ok(())
    }
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

fn effect_identity(response: &impl WorkflowEffectStatusRecord) -> EffectIdentity {
    EffectIdentity {
        effect_id: response.effect_id().clone(),
        intent_digest: response.intent_digest().clone(),
        effect_version: response.effect_version(),
        state: response.state(),
        attempt_count: response.attempt_count(),
        reconciliation_count: response.reconciliation_count(),
    }
}

fn effect_phase(state: EffectState) -> Result<WorkflowContextPhase, WorkflowSessionError> {
    match state {
        EffectState::Dispatching => Ok(WorkflowContextPhase::EffectDispatching),
        EffectState::Unknown => Ok(WorkflowContextPhase::EffectAmbiguous),
        EffectState::AuthorizedForRetry => Ok(WorkflowContextPhase::EffectAuthorized),
        state if effect_state_terminal(state) => Ok(WorkflowContextPhase::EffectSettled),
        _ => Err(invalid_response()),
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

const fn invalid_transition() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::InvalidTransition)
}

const fn invalid_response() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::InvalidResponse)
}

const fn identity_mismatch() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::IdentityMismatch)
}

const fn limit_exceeded() -> WorkflowSessionError {
    WorkflowSessionError::new(WorkflowSessionErrorCode::LimitExceeded)
}

#[cfg(all(test, not(feature = "qualification-miri-isolated")))]
mod tests {
    use super::{
        MAX_WORKFLOW_DELTA_CHAIN_LENGTH, WorkflowContextPhase, WorkflowContextSession,
        WorkflowQuarantineReason, WorkflowResumeAction, WorkflowSessionErrorCode, effect_identity,
    };
    use cigar_api::{
        ContextDeltaResponse, ContextPlanResponse, EffectStatusResponse, MaterializationResponse,
        RevalidationResponse,
    };
    use cigar_compiler::{SealedDelta, apply_delta_verified, generate_delta};
    use cigar_protocol::{
        CandidateDisposition, ContentDigest, ContextBlock, ContextBundle, ContextPlan, DiffStatus,
        EffectState, ExtensionMap, FixedPoint, LaneKind, MaterializedContext, MediaType, PlanLane,
        RecordId, RepresentationKind, SchemaVersion, Validate, VersionId,
    };
    use std::error::Error;

    fn digest(character: char) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn version(character: char) -> Result<VersionId, Box<dyn Error>> {
        Ok(VersionId::new(digest(character)?.as_str())?)
    }

    fn record(suffix: u8) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f78{suffix:02x}"
        ))?)
    }

    fn bundle(
        bundle_character: char,
        block_character: char,
        contract_character: char,
    ) -> Result<ContextBundle, Box<dyn Error>> {
        let block_id = version(block_character)?;
        let bundle = ContextBundle {
            schema_version: SchemaVersion::new("cigar.context-bundle", 1)?,
            bundle_id: version(bundle_character)?,
            contract_digest: digest(contract_character)?,
            manifest_digest: digest('d')?,
            blocks: vec![ContextBlock {
                block_id: block_id.clone(),
                lane: LaneKind::Evidence,
                representation: RepresentationKind::Exact,
                content_digest: digest(block_character)?,
                token_count: 1,
                provenance: vec![block_id],
                transform_receipt: None,
            }],
            total_tokens: 1,
            extensions: ExtensionMap::default(),
        };
        bundle.validate()?;
        Ok(bundle)
    }

    fn plan_response(
        plan_suffix: u8,
        bundle: &ContextBundle,
    ) -> Result<ContextPlanResponse, Box<dyn Error>> {
        let block = bundle.blocks.first().ok_or("missing block")?;
        let plan = ContextPlan {
            schema_version: SchemaVersion::new("cigar.context-plan", 1)?,
            plan_id: record(plan_suffix)?,
            contract_digest: bundle.contract_digest.clone(),
            catalog_watermark: digest('e')?,
            total_input_tokens: 10,
            lanes: vec![PlanLane {
                kind: LaneKind::Evidence,
                budget_tokens: 10,
                candidate_versions: vec![block.block_id.clone()],
            }],
            dispositions: vec![(
                block.block_id.clone(),
                CandidateDisposition::Selected {
                    lane: LaneKind::Evidence,
                    score: FixedPoint::new(1)?,
                },
            )],
            extensions: ExtensionMap::default(),
        };
        plan.validate()?;
        Ok(ContextPlanResponse {
            plan,
            bundle_id: bundle.bundle_id.clone(),
            manifest_digest: bundle.manifest_digest.clone(),
        })
    }

    fn materialization(bundle: &ContextBundle) -> Result<MaterializationResponse, Box<dyn Error>> {
        Ok(MaterializationResponse {
            context: MaterializedContext {
                schema_version: SchemaVersion::new("cigar.materialized-context", 1)?,
                bundle_id: bundle.bundle_id.clone(),
                media_type: MediaType::new("application/json")?,
                bytes: vec![b'x'],
                token_count: 1,
                tokenizer_fingerprint: digest('f')?,
                materializer_fingerprint: digest('1')?,
            },
            physical_input_tokens: 1,
        })
    }

    fn effect(
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        version: u64,
        state: EffectState,
    ) -> EffectStatusResponse {
        EffectStatusResponse {
            effect_id: effect_id.clone(),
            state,
            effect_version: version,
            intent_digest: intent_digest.clone(),
            attempt_count: match state {
                EffectState::Prepared | EffectState::Authorized => 0,
                _ if version >= 5 => 2,
                _ => 1,
            },
            reconciliation_count: u32::from(version >= 4),
        }
    }

    fn advance_to_model_result(
        session: &mut WorkflowContextSession,
        initial: &ContextBundle,
    ) -> Result<RecordId, Box<dyn Error>> {
        session.record_plan_created(&plan_response(1, initial)?)?;
        session.record_bundle_compiled(initial)?;
        session.record_materialized(&materialization(initial)?)?;
        let invocation_id = record(2)?;
        session.begin_model_invocation(invocation_id.clone(), digest('2')?, digest('8')?)?;
        session.record_model_result(&invocation_id, digest('3')?)?;
        Ok(invocation_id)
    }

    fn advance_delta(
        session: &mut WorkflowContextSession,
        base: &ContextBundle,
        target: &ContextBundle,
    ) -> Result<(), Box<dyn Error>> {
        session.record_plan_created(&plan_response(3, target)?)?;
        session.record_bundle_compiled(target)?;
        let sealed = generate_delta(base, target)?;
        let response = ContextDeltaResponse {
            delta: sealed.delta.clone(),
            delta_digest: sealed.delta_digest.clone(),
        };
        session.record_delta_compiled(&response)?;
        let applied = apply_delta_verified(base, target, &sealed)?;
        session.record_delta_applied(&applied)?;
        Ok(())
    }

    #[test]
    fn no_effect_cycle_has_one_closed_operation_order_and_replay_terminal()
    -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let target = bundle('b', '2', '3')?;
        let mut session = WorkflowContextSession::new();
        assert_eq!(
            session.resume_action().operation_id(),
            Some("createContextPlan")
        );
        advance_to_model_result(&mut session, &initial)?;
        session.record_observation(digest('4')?, 1)?;
        advance_delta(&mut session, &initial, &target)?;
        assert_eq!(session.delta_chain_length(), 1);
        assert_eq!(session.active_bundle_id(), Some(&target.bundle_id));
        assert_eq!(session.resume_action(), WorkflowResumeAction::Checkpoint);
        let mut incoherent_restored = session.clone();
        incoherent_restored
            .materialization
            .as_mut()
            .ok_or("missing materialization")?
            .bundle_id = target.bundle_id.clone();
        assert_eq!(
            incoherent_restored
                .validate_restored()
                .map_err(|error| error.code()),
            Err(WorkflowSessionErrorCode::InvalidResponse)
        );
        session.checkpoint_cycle()?;
        assert_eq!(session.completed_turns(), 1);
        assert_eq!(session.phase(), WorkflowContextPhase::Checkpointed);
        session.finish()?;
        let baseline = session.replay_identity()?;
        let exact = session.compare_replay(&baseline)?;
        assert!(exact.exact_match);
        assert_eq!(exact.bundle_delta_selection, DiffStatus::Equal);
        assert_eq!(exact.materialization, DiffStatus::Equal);
        assert_eq!(exact.model_result_identity, DiffStatus::Equal);
        assert_eq!(exact.tool_effect_decisions, DiffStatus::Equal);
        assert_eq!(exact.outcome, DiffStatus::Equal);

        let mut incoherent_replay = baseline.clone();
        let delta = incoherent_replay
            .cycles
            .first_mut()
            .and_then(|cycle| cycle.selected_delta.as_mut())
            .ok_or("missing replay delta")?;
        delta.base_bundle_id = version('8')?;
        assert_eq!(
            session
                .compare_replay(&incoherent_replay)
                .map_err(|error| error.code()),
            Err(WorkflowSessionErrorCode::InvalidResponse)
        );

        let mut changed_selection = baseline.clone();
        let Some(cycle) = changed_selection.cycles.first_mut() else {
            return Err("replay baseline omitted its completed cycle".into());
        };
        cycle.selected_context.plan_id = record(7)?;
        let comparison = session.compare_replay(&changed_selection)?;
        assert_eq!(comparison.bundle_delta_selection, DiffStatus::Different);
        assert_eq!(comparison.model_result_identity, DiffStatus::Equal);
        assert!(!comparison.exact_match);

        let mut changed_materialization = baseline.clone();
        let Some(cycle) = changed_materialization.cycles.first_mut() else {
            return Err("replay baseline omitted its completed cycle".into());
        };
        cycle.materialization.tokenizer_fingerprint = digest('7')?;
        let comparison = session.compare_replay(&changed_materialization)?;
        assert_eq!(comparison.materialization, DiffStatus::Different);
        assert_eq!(comparison.bundle_delta_selection, DiffStatus::Equal);

        let mut impossible_effect = baseline.clone();
        let effect_id = record(8)?;
        let mut terminal = effect(&effect_id, &digest('8')?, 3, EffectState::Succeeded);
        terminal.attempt_count = 0;
        impossible_effect
            .cycles
            .first_mut()
            .ok_or("replay baseline omitted its completed cycle")?
            .effect = Some(effect_identity(&terminal));
        assert_eq!(
            session
                .compare_replay(&impossible_effect)
                .map_err(|error| error.code()),
            Err(WorkflowSessionErrorCode::InvalidResponse)
        );

        let mut changed_result = baseline.clone();
        let Some(cycle) = changed_result.cycles.first_mut() else {
            return Err("replay baseline omitted its completed cycle".into());
        };
        cycle.model_result_digest = digest('7')?;
        let comparison = session.compare_replay(&changed_result)?;
        assert_eq!(comparison.model_result_identity, DiffStatus::Different);
        assert_eq!(comparison.outcome, DiffStatus::Equal);

        let mut changed_effect = baseline.clone();
        let replay_effect_id = record(8)?;
        let Some(cycle) = changed_effect.cycles.first_mut() else {
            return Err("replay baseline omitted its completed cycle".into());
        };
        cycle.effect = Some(effect_identity(&effect(
            &replay_effect_id,
            &digest('8')?,
            3,
            EffectState::Succeeded,
        )));
        let comparison = session.compare_replay(&changed_effect)?;
        assert_eq!(comparison.tool_effect_decisions, DiffStatus::Different);
        assert_eq!(comparison.model_result_identity, DiffStatus::Equal);

        let mut changed_outcome = baseline.clone();
        let Some(cycle) = changed_outcome.cycles.first_mut() else {
            return Err("replay baseline omitted its completed cycle".into());
        };
        cycle.outcome_digest = digest('8')?;
        let comparison = session.compare_replay(&changed_outcome)?;
        assert_eq!(comparison.outcome, DiffStatus::Different);
        assert_eq!(comparison.tool_effect_decisions, DiffStatus::Equal);
        let Err(error) =
            session.record_replay_verified(version('9')?, record(9)?, &changed_selection)
        else {
            return Err("mismatched context replay unexpectedly verified".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::IdentityMismatch);
        assert_eq!(session.phase(), WorkflowContextPhase::Finished);
        session.record_replay_verified(version('9')?, record(9)?, &baseline)?;
        assert_eq!(session.phase(), WorkflowContextPhase::ReplayVerified);
        assert_eq!(session.resume_action(), WorkflowResumeAction::Complete);
        Ok(())
    }

    #[test]
    fn delta_chain_bound_promotes_verified_full_bundle_and_resets() -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let target = bundle('b', '2', '3')?;
        let checkpoint = bundle('c', '3', '4')?;
        let mut session = WorkflowContextSession::new();
        advance_to_model_result(&mut session, &initial)?;
        session.record_observation(digest('4')?, 1)?;
        session.record_plan_created(&plan_response(3, &target)?)?;
        session.record_bundle_compiled(&target)?;
        let mut forged_at_bound = session.clone();
        forged_at_bound.delta_chain_length = MAX_WORKFLOW_DELTA_CHAIN_LENGTH;
        let Err(error) = forged_at_bound.validate_restored() else {
            return Err("restored delta-ready session at the chain bound was accepted".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidResponse);
        session.delta_chain_length = MAX_WORKFLOW_DELTA_CHAIN_LENGTH - 1;
        let sealed = generate_delta(&initial, &target)?;
        session.record_delta_compiled(&ContextDeltaResponse {
            delta: sealed.delta.clone(),
            delta_digest: sealed.delta_digest.clone(),
        })?;
        session.record_delta_applied(&apply_delta_verified(&initial, &target, &sealed)?)?;
        assert_eq!(
            session.delta_chain_length(),
            MAX_WORKFLOW_DELTA_CHAIN_LENGTH
        );

        session.checkpoint_cycle()?;
        session.record_materialized(&materialization(&target)?)?;
        let invocation_id = record(4)?;
        session.begin_model_invocation(invocation_id.clone(), digest('5')?, digest('8')?)?;
        session.record_model_result(&invocation_id, digest('6')?)?;
        session.record_observation(digest('7')?, 2)?;
        session.record_plan_created(&plan_response(5, &checkpoint)?)?;
        session.record_bundle_compiled(&checkpoint)?;

        assert_eq!(session.phase(), WorkflowContextPhase::BundleReady);
        assert_eq!(session.active_bundle_id(), Some(&checkpoint.bundle_id));
        assert_eq!(session.delta_chain_length(), 0);
        assert_eq!(session.resume_action(), WorkflowResumeAction::Checkpoint);
        let Err(error) = session.record_delta_compiled(&ContextDeltaResponse {
            delta: sealed.delta,
            delta_digest: sealed.delta_digest,
        }) else {
            return Err("delta unexpectedly accepted after forced full checkpoint".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
        session.validate_restored()?;
        Ok(())
    }

    #[test]
    fn ambiguous_effect_requires_reconciliation_and_fresh_revalidation_before_retry()
    -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let target = bundle('b', '2', '3')?;
        let effect_id = record(7)?;
        let intent_digest = digest('7')?;
        let mut session = WorkflowContextSession::new();
        advance_to_model_result(&mut session, &initial)?;
        session.record_effect_prepared(&effect(
            &effect_id,
            &intent_digest,
            1,
            EffectState::Prepared,
        ))?;
        session.record_observation(digest('4')?, 1)?;
        advance_delta(&mut session, &initial, &target)?;
        assert_eq!(
            session.resume_action(),
            WorkflowResumeAction::RevalidateContextBundle
        );
        session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: true,
            reasons: Vec::new(),
        })?;
        assert_eq!(
            session.phase(),
            WorkflowContextPhase::EffectAuthorizationRevalidated
        );
        session.record_effect_authorized(&effect(
            &effect_id,
            &intent_digest,
            2,
            EffectState::Authorized,
        ))?;
        session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: true,
            reasons: Vec::new(),
        })?;
        session.record_effect_dispatched(&effect(
            &effect_id,
            &intent_digest,
            3,
            EffectState::Unknown,
        ))?;
        assert_eq!(
            session.resume_action().operation_id(),
            Some("reconcileEffect")
        );
        let mut missing_reconciliation = effect(
            &effect_id,
            &intent_digest,
            4,
            EffectState::AuthorizedForRetry,
        );
        missing_reconciliation.reconciliation_count = 0;
        let Err(error) = session.record_effect_observed(&missing_reconciliation) else {
            return Err("retry without a reconciliation record unexpectedly succeeded".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidResponse);
        assert_eq!(session.phase(), WorkflowContextPhase::EffectAmbiguous);
        session.record_effect_observed(&effect(
            &effect_id,
            &intent_digest,
            4,
            EffectState::AuthorizedForRetry,
        ))?;
        assert_eq!(session.phase(), WorkflowContextPhase::EffectAuthorized);
        let Err(error) = session.record_effect_dispatched(&effect(
            &effect_id,
            &intent_digest,
            5,
            EffectState::Succeeded,
        )) else {
            return Err("dispatch without revalidation unexpectedly succeeded".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
        session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: true,
            reasons: Vec::new(),
        })?;
        session.record_effect_dispatched(&effect(
            &effect_id,
            &intent_digest,
            5,
            EffectState::Succeeded,
        ))?;
        session.checkpoint_cycle()?;
        Ok(())
    }

    #[test]
    fn mismatched_delta_effect_and_revalidation_identities_fail_closed()
    -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let target = bundle('b', '2', '3')?;
        let mut session = WorkflowContextSession::new();
        advance_to_model_result(&mut session, &initial)?;
        session.record_observation(digest('4')?, 1)?;
        session.record_plan_created(&plan_response(3, &target)?)?;
        session.record_bundle_compiled(&target)?;
        let sealed = generate_delta(&initial, &target)?;
        let wrong = ContextDeltaResponse {
            delta: cigar_protocol::ContextDelta {
                base_bundle_id: version('8')?,
                ..sealed.delta.clone()
            },
            delta_digest: sealed.delta_digest.clone(),
        };
        let Err(error) = session.record_delta_compiled(&wrong) else {
            return Err("wrong base unexpectedly compiled".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::IdentityMismatch);

        let response = ContextDeltaResponse {
            delta: sealed.delta.clone(),
            delta_digest: sealed.delta_digest.clone(),
        };
        session.record_delta_compiled(&response)?;
        let substituted = SealedDelta {
            delta: sealed.delta,
            delta_digest: digest('8')?,
        };
        assert!(apply_delta_verified(&initial, &target, &substituted).is_err());
        Ok(())
    }

    #[test]
    fn invalid_revalidation_quarantines_the_effect_fence() -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let target = bundle('b', '2', '3')?;
        let effect_id = record(7)?;
        let intent_digest = digest('7')?;
        let mut session = WorkflowContextSession::new();
        advance_to_model_result(&mut session, &initial)?;
        session.record_effect_prepared(&effect(
            &effect_id,
            &intent_digest,
            1,
            EffectState::Prepared,
        ))?;
        session.record_observation(digest('4')?, 1)?;
        advance_delta(&mut session, &initial, &target)?;
        session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: false,
            reasons: vec!["policy_revision_changed".to_owned()],
        })?;
        assert_eq!(session.phase(), WorkflowContextPhase::Quarantined);
        assert_eq!(session.resume_action(), WorkflowResumeAction::Complete);
        let Err(error) = session.record_effect_authorized(&effect(
            &effect_id,
            &intent_digest,
            2,
            EffectState::Authorized,
        )) else {
            return Err("authorization after invalidation unexpectedly succeeded".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
        session.validate_restored()?;
        Ok(())
    }

    #[test]
    fn cancellation_and_revocation_quarantine_late_provider_and_tool_results()
    -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let mut provider_session = WorkflowContextSession::new();
        provider_session.record_plan_created(&plan_response(1, &initial)?)?;
        provider_session.record_bundle_compiled(&initial)?;
        provider_session.record_materialized(&materialization(&initial)?)?;
        let invocation_id = record(2)?;
        provider_session.begin_model_invocation(
            invocation_id.clone(),
            digest('2')?,
            digest('8')?,
        )?;
        provider_session
            .quarantine_context(&initial.bundle_id, WorkflowQuarantineReason::Cancelled)?;
        let Err(error) = provider_session.record_model_result(&invocation_id, digest('3')?) else {
            return Err("late provider result after cancellation was accepted".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
        assert_eq!(provider_session.phase(), WorkflowContextPhase::Quarantined);
        provider_session.validate_restored()?;

        let target = bundle('b', '2', '3')?;
        let effect_id = record(7)?;
        let intent_digest = digest('7')?;
        let mut tool_session = WorkflowContextSession::new();
        advance_to_model_result(&mut tool_session, &initial)?;
        tool_session.record_effect_prepared(&effect(
            &effect_id,
            &intent_digest,
            1,
            EffectState::Prepared,
        ))?;
        tool_session.record_observation(digest('4')?, 1)?;
        advance_delta(&mut tool_session, &initial, &target)?;
        tool_session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: true,
            reasons: Vec::new(),
        })?;
        tool_session.record_effect_authorized(&effect(
            &effect_id,
            &intent_digest,
            2,
            EffectState::Authorized,
        ))?;
        tool_session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: true,
            reasons: Vec::new(),
        })?;
        tool_session.record_effect_dispatched(&effect(
            &effect_id,
            &intent_digest,
            3,
            EffectState::Unknown,
        ))?;
        tool_session.quarantine_context(&target.bundle_id, WorkflowQuarantineReason::Revoked)?;
        let Err(error) = tool_session.record_effect_observed(&effect(
            &effect_id,
            &intent_digest,
            4,
            EffectState::Succeeded,
        )) else {
            return Err("late tool result after revocation was accepted".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
        assert_eq!(tool_session.phase(), WorkflowContextPhase::Quarantined);
        tool_session.validate_restored()?;
        Ok(())
    }

    #[test]
    fn debug_output_contains_only_counts_and_presence_flags() -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let mut session = WorkflowContextSession::new();
        advance_to_model_result(&mut session, &initial)?;
        let output = format!("{session:?}");
        assert!(!output.contains(initial.bundle_id.as_str()));
        assert!(!output.contains(digest('3')?.as_str()));
        assert!(output.contains("has_model_result: true"));
        Ok(())
    }

    #[test]
    fn durable_identity_snapshot_round_trips_and_rejects_impossible_phase()
    -> Result<(), Box<dyn Error>> {
        let initial = bundle('a', '1', '2')?;
        let mut session = WorkflowContextSession::new();
        advance_to_model_result(&mut session, &initial)?;
        session.validate_restored()?;
        let bytes = serde_json::to_vec(&session)?;
        cigar_canon::parse_strict_json(&bytes)?;
        let restored: WorkflowContextSession = serde_json::from_slice(&bytes)?;
        assert_eq!(restored, session);
        restored.validate_restored()?;

        let mut impossible = serde_json::to_value(&session)?;
        let object = impossible
            .as_object_mut()
            .ok_or("workflow checkpoint is not an object")?;
        object.insert(
            "phase".to_owned(),
            serde_json::Value::String("effect_revalidated".to_owned()),
        );
        let impossible: WorkflowContextSession = serde_json::from_value(impossible)?;
        let Err(error) = impossible.validate_restored() else {
            return Err("impossible restored phase unexpectedly validated".into());
        };
        assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidResponse);
        Ok(())
    }
}
