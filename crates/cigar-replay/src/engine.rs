//! Strict replay execution across evidence, invocation, observational, and live modes.

use crate::{
    DecisionArchive, DecisionArtifact, DependencyRole, InvocationEnvelope, MissingDependencyReason,
    MissingDependencyRow, RecordedProviderEntry, RecordedProviderExpectation, RecordedProviderTape,
    ReplayArchive, ReplayDimensionDigests, ReplayFoundationError, ReplayFoundationErrorCode,
    compare_replay_dimensions,
};
use cigar_protocol::limits::MAX_REPLAY_REFERENCES;
use cigar_protocol::{
    ContentDigest, DependencyKind, RecordId, ReplayCompleteness, ReplayDiff, ReplayExecution,
    ReplayMode, ReplayRequest, ReplayStatus, SchemaVersion, UtcTimestamp, Validate, VersionId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Stable, content-free replay execution failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayErrorCode {
    /// The request, execution identity, time range, or live output is invalid.
    InvalidRequest,
    /// The exact source decision does not exist.
    DecisionNotFound,
    /// The archived decision root or retained artifact was altered.
    ArchiveIntegrity,
    /// An archive backend could not complete a read.
    ArchiveUnavailable,
    /// An execution identity was already used by this engine.
    ExecutionIdReused,
    /// A non-live entry point was asked to perform a live replay.
    LiveModeRequired,
    /// Live authorization was missing, stale, incorrectly bound, or denied.
    LiveAuthorizationInvalid,
    /// A one-use live authorization was presented more than once.
    LiveAuthorizationReused,
    /// A recorded-only provider rejected the exact transcript.
    RecordedProviderFailure,
    /// The configured live provider failed or returned an invalid result.
    LiveProviderFailure,
    /// New effect dispatch was not independently authorized.
    EffectAuthorizationInvalid,
    /// A generated protocol result violated its schema invariants.
    ProtocolViolation,
    /// Internal synchronization state was unavailable.
    Unavailable,
}

/// Content-free replay execution error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplayError {
    code: ReplayErrorCode,
}

impl ReplayError {
    /// Creates one stable replay failure.
    #[must_use]
    pub const fn new(code: ReplayErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ReplayErrorCode {
        self.code
    }
}

impl fmt::Debug for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "replay execution failed: {:?}", self.code)
    }
}

impl std::error::Error for ReplayError {}

/// One authoritative replay lifetime observed across archives, providers, reservations, and
/// effect dispatch. A late dependency result is quarantined by checking both before and after
/// every potentially blocking boundary.
#[derive(Clone)]
pub struct ReplayContext {
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    deadline: Option<Instant>,
}

impl ReplayContext {
    /// Creates a linked lifetime from a cancellation observer and optional absolute deadline.
    #[must_use]
    pub fn new(cancelled: Arc<dyn Fn() -> bool + Send + Sync>, deadline: Option<Instant>) -> Self {
        Self {
            cancelled,
            deadline,
        }
    }

    /// Creates an unbounded context for embedded callers that have no request lifetime.
    #[must_use]
    pub fn unbounded() -> Self {
        Self::new(Arc::new(|| false), None)
    }

    /// Rejects cancelled or expired work without exposing request content.
    pub fn check_active(&self) -> Result<(), ReplayError> {
        if (self.cancelled)()
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Err(ReplayError::new(ReplayErrorCode::Unavailable))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ReplayContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayContext")
            .field("cancelled", &(self.cancelled)())
            .field("has_deadline", &self.deadline.is_some())
            .finish()
    }
}

/// Observable counts proving which external live boundaries were crossed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayExternalCallCounters {
    /// Current live-authorization checks.
    pub live_authorization_checks: u64,
    /// Live consumer, tool, or connector executions.
    pub live_provider_calls: u64,
    /// Newly authorized logical effects dispatched by live replay.
    pub live_effect_dispatches: u64,
}

#[derive(Default)]
struct AtomicReplayCounters {
    live_authorization_checks: AtomicU64,
    live_provider_calls: AtomicU64,
    live_effect_dispatches: AtomicU64,
}

impl AtomicReplayCounters {
    fn snapshot(&self) -> ReplayExternalCallCounters {
        ReplayExternalCallCounters {
            live_authorization_checks: self.live_authorization_checks.load(Ordering::SeqCst),
            live_provider_calls: self.live_provider_calls.load(Ordering::SeqCst),
            live_effect_dispatches: self.live_effect_dispatches.load(Ordering::SeqCst),
        }
    }
}

/// Protected replay output. Debug output deliberately omits exact retained bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayResult {
    /// Observable protocol execution record.
    pub execution: ReplayExecution,
    /// Exact missing rows, never silently substituted with current state.
    pub missing_dependencies: Vec<MissingDependencyRow>,
    /// Exact reconstructed invocation bytes for invocation-capable complete modes.
    reconstructed_invocation: Option<ReconstructedInvocation>,
    /// Exact recorded or live observations in their original order.
    observations: Vec<Vec<u8>>,
    /// Structured comparison produced by a complete live replay.
    pub diff: Option<ReplayDiff>,
    /// External-boundary counters after this execution.
    pub external_calls: ReplayExternalCallCounters,
}

impl ReplayResult {
    /// Returns exact reconstructed invocation bytes to an authorized caller.
    #[must_use]
    pub fn reconstructed_invocation(&self) -> Option<&[u8]> {
        self.reconstructed_invocation
            .as_ref()
            .map(ReconstructedInvocation::exact_input)
    }

    /// Returns the complete protected invocation reconstruction.
    #[must_use]
    pub const fn invocation(&self) -> Option<&ReconstructedInvocation> {
        self.reconstructed_invocation.as_ref()
    }

    /// Returns exact replay observations to an authorized caller.
    #[must_use]
    pub fn observations(&self) -> &[Vec<u8>] {
        &self.observations
    }
}

/// Side-effect-free exact dependency inspection for a persisted replay request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayInspection {
    /// Category-level completeness suitable for the public replay status surface.
    pub completeness: ReplayCompleteness,
    /// Exact retained dependency rows for an authorized diagnostic caller.
    pub missing_dependencies: Vec<MissingDependencyRow>,
}

impl fmt::Debug for ReplayResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayResult")
            .field("execution", &self.execution)
            .field("missing_dependencies", &self.missing_dependencies)
            .field(
                "reconstructed_invocation_bytes",
                &self
                    .reconstructed_invocation
                    .as_ref()
                    .map(|invocation| invocation.exact_input.len()),
            )
            .field("observation_count", &self.observations.len())
            .field("diff", &self.diff)
            .field("external_calls", &self.external_calls)
            .finish_non_exhaustive()
    }
}

/// One exact implementation or schema artifact required by an invocation.
#[derive(Clone, Eq, PartialEq)]
pub struct ReconstructedComponent {
    /// Exact component role.
    pub role: DependencyRole,
    /// Raw digest of the retained component bytes.
    pub content_digest: ContentDigest,
    /// Exact implementation or schema fingerprint.
    pub fingerprint: ContentDigest,
    exact_bytes: Vec<u8>,
}

impl ReconstructedComponent {
    /// Returns exact protected component or schema bytes.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

impl fmt::Debug for ReconstructedComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconstructedComponent")
            .field("role", &self.role)
            .field("content_digest", &self.content_digest)
            .field("fingerprint", &self.fingerprint)
            .field("exact_bytes", &self.exact_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Complete observable invocation envelope and its exact protected byte dependencies.
#[derive(Clone, Eq, PartialEq)]
pub struct ReconstructedInvocation {
    /// Exact observable invocation metadata.
    pub envelope: InvocationEnvelope,
    exact_input: Vec<u8>,
    exact_parameters: Vec<u8>,
    exact_materialization: Vec<u8>,
    components: Vec<ReconstructedComponent>,
}

impl ReconstructedInvocation {
    /// Returns exact final consumer input bytes.
    #[must_use]
    pub fn exact_input(&self) -> &[u8] {
        &self.exact_input
    }

    /// Returns exact declared invocation parameter bytes.
    #[must_use]
    pub fn exact_parameters(&self) -> &[u8] {
        &self.exact_parameters
    }

    /// Returns exact provider-ready materialized context bytes.
    #[must_use]
    pub fn exact_materialization(&self) -> &[u8] {
        &self.exact_materialization
    }

    /// Returns exact runtime, consumer, adapter, tokenizer, tool, and environment artifacts.
    #[must_use]
    pub fn components(&self) -> &[ReconstructedComponent] {
        &self.components
    }
}

impl fmt::Debug for ReconstructedInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconstructedInvocation")
            .field("envelope", &self.envelope)
            .field("exact_input_bytes", &self.exact_input.len())
            .field("exact_parameter_bytes", &self.exact_parameters.len())
            .field(
                "exact_materialization_bytes",
                &self.exact_materialization.len(),
            )
            .field("components", &self.components)
            .finish_non_exhaustive()
    }
}

/// One separately issued, one-use authorization for a particular live replay request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveReplayAuthorization {
    /// Must be `cigar.live-replay-authorization.v1`.
    pub schema_version: SchemaVersion,
    /// Signed or MAC-bound authorization digest supplied by the request.
    pub authorization_digest: ContentDigest,
    /// Unique authorization nonce.
    pub nonce: RecordId,
    /// Exact request authorized for live execution.
    pub request_id: RecordId,
    /// Exact immutable source decision.
    pub decision_id: VersionId,
    /// Authenticated requester authorized to execute it.
    pub requested_by: RecordId,
    /// Exact new effect identities authorized for this execution.
    pub authorized_effect_intents: Vec<RecordId>,
    /// First instant at which current verification may accept the authorization.
    pub not_before: UtcTimestamp,
    /// Last instant at which current verification may accept the authorization.
    pub expires_at: UtcTimestamp,
    /// Current policy snapshot against which the proof was issued.
    pub policy_snapshot_digest: ContentDigest,
}

impl LiveReplayAuthorization {
    /// Validates the immutable request, requester, decision, effects, and digest binding without
    /// consuming the authorization or consulting current policy.
    pub fn validate_binding(&self, request: &ReplayRequest) -> Result<(), ReplayError> {
        let sorted_unique = self.authorized_effect_intents.len() <= MAX_REPLAY_REFERENCES
            && self
                .authorized_effect_intents
                .windows(2)
                .all(|pair| pair.first() < pair.get(1));
        if self
            .schema_version
            .require_v1("cigar.live-replay-authorization")
            .is_err()
            || !sorted_unique
            || self.request_id != request.request_id
            || self.decision_id != request.decision_id
            || self.requested_by != request.requested_by
            || self.authorized_effect_intents != request.authorized_effect_intents
            || request.live_authorization_digest.as_ref() != Some(&self.authorization_digest)
            || self.expires_at < self.not_before
        {
            return Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid));
        }
        Ok(())
    }

    fn validate_window(&self, trusted_now: UtcTimestamp) -> Result<(), ReplayError> {
        if self.not_before > trusted_now || self.expires_at < trusted_now {
            return Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid));
        }
        Ok(())
    }
}

/// Current verifier for a live authorization proof and current policy state.
pub trait LiveAuthorizationVerifier: Send + Sync {
    /// Verifies signature/MAC, revocation, principal, and current policy binding.
    ///
    /// The returned instant comes from the verifier's trusted clock and is used for the validity
    /// window check. A replay request caller cannot supply it.
    fn verify_current(
        &self,
        authorization: &LiveReplayAuthorization,
    ) -> Result<UtcTimestamp, ReplayError>;

    /// Verifies current authority under the same replay lifetime.
    fn verify_current_with_context(
        &self,
        authorization: &LiveReplayAuthorization,
        context: &ReplayContext,
    ) -> Result<UtcTimestamp, ReplayError> {
        context.check_active()?;
        let now = self.verify_current(authorization)?;
        context.check_active()?;
        Ok(now)
    }
}

/// Protected exact invocation passed only to the explicit live provider boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct LiveReplayInvocation {
    /// New execution identity, distinct from the source decision.
    pub execution_id: RecordId,
    /// Source replay request identity.
    pub request_id: RecordId,
    /// Immutable source decision identity.
    pub source_decision_id: VersionId,
    /// Digest of exact invocation bytes.
    pub input_digest: ContentDigest,
    reconstructed: ReconstructedInvocation,
}

impl LiveReplayInvocation {
    /// Returns exact protected invocation bytes to the configured live provider.
    #[must_use]
    pub fn exact_input(&self) -> &[u8] {
        self.reconstructed.exact_input()
    }

    /// Returns exact protected invocation parameter bytes.
    #[must_use]
    pub fn exact_parameters(&self) -> &[u8] {
        self.reconstructed.exact_parameters()
    }

    /// Returns the complete protected invocation reconstruction.
    #[must_use]
    pub const fn reconstructed(&self) -> &ReconstructedInvocation {
        &self.reconstructed
    }
}

impl fmt::Debug for LiveReplayInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveReplayInvocation")
            .field("execution_id", &self.execution_id)
            .field("request_id", &self.request_id)
            .field("source_decision_id", &self.source_decision_id)
            .field("input_digest", &self.input_digest)
            .field("reconstructed", &self.reconstructed)
            .finish_non_exhaustive()
    }
}

/// Observable output of a newly authorized live provider execution.
#[derive(Clone, Eq, PartialEq)]
pub struct LiveReplayOutput {
    /// Candidate semantic dimensions, excluding the observation digest derived by the engine.
    pub dimensions: ReplayDimensionDigests,
    /// New effect identities proposed by this live execution.
    pub effect_intents: Vec<RecordId>,
    observations: Vec<Vec<u8>>,
}

impl LiveReplayOutput {
    /// Creates one bounded live output. Empty individual observations remain exact values.
    pub fn new(
        dimensions: ReplayDimensionDigests,
        effect_intents: Vec<RecordId>,
        observations: Vec<Vec<u8>>,
    ) -> Result<Self, ReplayError> {
        let observation_bytes = observations.iter().try_fold(0_usize, |total, value| {
            if value.len() > crate::MAX_DECISION_ARTIFACT_BYTES {
                return Err(ReplayError::new(ReplayErrorCode::LiveProviderFailure));
            }
            total
                .checked_add(value.len())
                .ok_or_else(|| ReplayError::new(ReplayErrorCode::LiveProviderFailure))
        })?;
        let sorted_unique_effects = effect_intents.len() <= MAX_REPLAY_REFERENCES
            && effect_intents
                .windows(2)
                .all(|pair| pair.first() < pair.get(1));
        if observations.len() > MAX_REPLAY_REFERENCES
            || observation_bytes > crate::MAX_DECISION_CAPTURE_BYTES
            || !sorted_unique_effects
        {
            return Err(ReplayError::new(ReplayErrorCode::LiveProviderFailure));
        }
        Ok(Self {
            dimensions,
            effect_intents,
            observations,
        })
    }

    /// Returns exact protected live observations.
    #[must_use]
    pub fn observations(&self) -> &[Vec<u8>] {
        &self.observations
    }
}

impl fmt::Debug for LiveReplayOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveReplayOutput")
            .field("dimensions", &self.dimensions)
            .field("effect_intents", &self.effect_intents)
            .field("observation_count", &self.observations.len())
            .finish_non_exhaustive()
    }
}

/// Explicit live consumer/tool/connector boundary.
pub trait LiveReplayProvider: Send + Sync {
    /// Executes a new live invocation. Non-live replay never calls this method.
    fn execute(&self, invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError>;

    /// Executes while observing and quarantining results outside the authoritative lifetime.
    fn execute_with_context(
        &self,
        invocation: &LiveReplayInvocation,
        context: &ReplayContext,
    ) -> Result<LiveReplayOutput, ReplayError> {
        context.check_active()?;
        let output = self.execute(invocation)?;
        context.check_active()?;
        Ok(output)
    }
}

/// Fresh effect-dispatch request, intentionally unable to carry old approvals or receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveEffectDispatch {
    /// New replay execution identity.
    pub execution_id: RecordId,
    /// Source replay request identity.
    pub request_id: RecordId,
    /// Immutable source decision identity.
    pub source_decision_id: VersionId,
    /// Exact new logical effect identities.
    pub effect_intents: Vec<RecordId>,
    /// Current one-use live authorization digest.
    pub live_authorization_digest: ContentDigest,
}

/// Independent current authorization and dispatch gate for new live effects.
pub trait LiveEffectGate: Send + Sync {
    /// Reauthorizes and dispatches the exact new effect identities.
    fn authorize_and_dispatch(&self, dispatch: &LiveEffectDispatch) -> Result<(), ReplayError>;

    /// Reauthorizes and dispatches under the exact replay lifetime.
    fn authorize_and_dispatch_with_context(
        &self,
        dispatch: &LiveEffectDispatch,
        context: &ReplayContext,
    ) -> Result<(), ReplayError> {
        context.check_active()?;
        self.authorize_and_dispatch(dispatch)?;
        context.check_active()
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
    fn execute(&self, _invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError> {
        Err(ReplayError::new(ReplayErrorCode::LiveProviderFailure))
    }
}

impl LiveEffectGate for DeniedLiveServices {
    fn authorize_and_dispatch(&self, _dispatch: &LiveEffectDispatch) -> Result<(), ReplayError> {
        Err(ReplayError::new(
            ReplayErrorCode::EffectAuthorizationInvalid,
        ))
    }
}

#[derive(Default)]
struct ReplayState {
    execution_ids: BTreeSet<RecordId>,
    live_authorization_nonces: BTreeSet<RecordId>,
    live_authorization_digests: BTreeSet<ContentDigest>,
}

/// Atomic reservation repository for replay execution and live-authorization identities.
///
/// Daemon deployments provide a durable implementation. The in-memory implementation is the
/// hermetic embedded reference and can be shared by multiple engine instances.
pub trait ReplayReservationLedger: Send + Sync {
    /// Atomically reserves a globally unique replay execution identity.
    fn reserve_execution(&self, execution_id: &RecordId) -> Result<bool, ReplayError>;

    /// Atomically reserves both the one-use authorization nonce and digest.
    fn reserve_live_authorization(
        &self,
        nonce: &RecordId,
        digest: &ContentDigest,
    ) -> Result<bool, ReplayError>;
}

/// Thread-safe in-memory reservation ledger for embedded and test use.
#[derive(Default)]
pub struct InMemoryReplayReservationLedger {
    state: Mutex<ReplayState>,
}

impl fmt::Debug for InMemoryReplayReservationLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().ok();
        formatter
            .debug_struct("InMemoryReplayReservationLedger")
            .field(
                "execution_count",
                &state.as_ref().map(|value| value.execution_ids.len()),
            )
            .field(
                "authorization_count",
                &state
                    .as_ref()
                    .map(|value| value.live_authorization_digests.len()),
            )
            .finish()
    }
}

impl ReplayReservationLedger for InMemoryReplayReservationLedger {
    fn reserve_execution(&self, execution_id: &RecordId) -> Result<bool, ReplayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))?;
        Ok(state.execution_ids.insert(execution_id.clone()))
    }

    fn reserve_live_authorization(
        &self,
        nonce: &RecordId,
        digest: &ContentDigest,
    ) -> Result<bool, ReplayError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))?;
        if state.live_authorization_nonces.contains(nonce)
            || state.live_authorization_digests.contains(digest)
        {
            return Ok(false);
        }
        state.live_authorization_nonces.insert(nonce.clone());
        state.live_authorization_digests.insert(digest.clone());
        Ok(true)
    }
}

/// Thread-safe strict replay engine with no current-data fallback.
pub struct ReplayEngine {
    archive: Arc<dyn ReplayArchive>,
    live_verifier: Arc<dyn LiveAuthorizationVerifier>,
    live_provider: Arc<dyn LiveReplayProvider>,
    effect_gate: Arc<dyn LiveEffectGate>,
    reservations: Arc<dyn ReplayReservationLedger>,
    counters: AtomicReplayCounters,
}

impl fmt::Debug for ReplayEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayEngine")
            .field("external_calls", &self.counters.snapshot())
            .finish_non_exhaustive()
    }
}

impl ReplayEngine {
    /// Creates a replay engine whose live surfaces are closed by default.
    #[must_use]
    pub fn new<A>(archive: Arc<A>) -> Self
    where
        A: ReplayArchive + 'static,
    {
        let denied = Arc::new(DeniedLiveServices);
        Self {
            archive,
            live_verifier: denied.clone(),
            live_provider: denied.clone(),
            effect_gate: denied,
            reservations: Arc::new(InMemoryReplayReservationLedger::default()),
            counters: AtomicReplayCounters::default(),
        }
    }

    /// Creates an engine with explicit live-only services.
    #[must_use]
    pub fn with_live_services<A>(
        archive: Arc<A>,
        live_verifier: Arc<dyn LiveAuthorizationVerifier>,
        live_provider: Arc<dyn LiveReplayProvider>,
        effect_gate: Arc<dyn LiveEffectGate>,
    ) -> Self
    where
        A: ReplayArchive + 'static,
    {
        Self::with_live_services_and_reservations(
            archive,
            live_verifier,
            live_provider,
            effect_gate,
            Arc::new(InMemoryReplayReservationLedger::default()),
        )
    }

    /// Creates an engine with explicit live services and a shareable durable reservation ledger.
    #[must_use]
    pub fn with_live_services_and_reservations<A>(
        archive: Arc<A>,
        live_verifier: Arc<dyn LiveAuthorizationVerifier>,
        live_provider: Arc<dyn LiveReplayProvider>,
        effect_gate: Arc<dyn LiveEffectGate>,
        reservations: Arc<dyn ReplayReservationLedger>,
    ) -> Self
    where
        A: ReplayArchive + 'static,
    {
        Self {
            archive,
            live_verifier,
            live_provider,
            effect_gate,
            reservations,
            counters: AtomicReplayCounters::default(),
        }
    }

    /// Returns process-local external live-boundary counters.
    #[must_use]
    pub fn external_call_counters(&self) -> ReplayExternalCallCounters {
        self.counters.snapshot()
    }

    /// Computes exact retained dependency completeness without reserving an execution, invoking a
    /// provider, permitting egress, or dispatching an effect.
    pub fn inspect_completeness(
        &self,
        request: &ReplayRequest,
    ) -> Result<ReplayInspection, ReplayError> {
        self.inspect_completeness_with_context(request, &ReplayContext::unbounded())
    }

    /// Computes completeness while preserving one authoritative request lifetime.
    pub fn inspect_completeness_with_context(
        &self,
        request: &ReplayRequest,
        context: &ReplayContext,
    ) -> Result<ReplayInspection, ReplayError> {
        context.check_active()?;
        request
            .validate()
            .map_err(|_error| ReplayError::new(ReplayErrorCode::InvalidRequest))?;
        let loaded = self.load_exact(request, context)?;
        context.check_active()?;
        Ok(ReplayInspection {
            completeness: loaded.completeness,
            missing_dependencies: loaded.missing,
        })
    }

    /// Computes exact retained dependency completeness for an unbound replay draft. This does not
    /// construct or reserve a [`ReplayRequest`] and is therefore safe before a separately issued
    /// live authorization is bound to the job.
    pub fn inspect_completeness_for(
        &self,
        decision_id: &VersionId,
        mode: ReplayMode,
    ) -> Result<ReplayInspection, ReplayError> {
        self.inspect_completeness_for_with_context(decision_id, mode, &ReplayContext::unbounded())
    }

    /// Computes draft completeness under one authoritative request lifetime.
    pub fn inspect_completeness_for_with_context(
        &self,
        decision_id: &VersionId,
        mode: ReplayMode,
        context: &ReplayContext,
    ) -> Result<ReplayInspection, ReplayError> {
        context.check_active()?;
        let loaded = self.load_exact_for(decision_id, mode, context)?;
        context.check_active()?;
        Ok(ReplayInspection {
            completeness: loaded.completeness,
            missing_dependencies: loaded.missing,
        })
    }

    /// Executes evidence, invocation, or observational replay without any live call surface.
    pub fn replay_non_live(
        &self,
        request: &ReplayRequest,
        execution_id: RecordId,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
    ) -> Result<ReplayResult, ReplayError> {
        self.replay_non_live_with_context(
            request,
            execution_id,
            started_at,
            completed_at,
            &ReplayContext::unbounded(),
        )
    }

    /// Executes non-live replay under one authoritative request lifetime.
    pub fn replay_non_live_with_context(
        &self,
        request: &ReplayRequest,
        execution_id: RecordId,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
        context: &ReplayContext,
    ) -> Result<ReplayResult, ReplayError> {
        context.check_active()?;
        self.validate_request(request, &execution_id, started_at, completed_at)?;
        if request.mode == ReplayMode::LiveComparison {
            return Err(ReplayError::new(ReplayErrorCode::LiveModeRequired));
        }
        self.reserve_execution(execution_id.clone(), context)?;
        let loaded = self.load_exact(request, context)?;
        if !loaded.missing.is_empty() {
            context.check_active()?;
            return self.incomplete_result(request, execution_id, started_at, completed_at, loaded);
        }

        let mut reconstructed = None;
        let mut observations = Vec::new();
        let mut observation_digest = None;
        let reconstructed_input_digest = match request.mode {
            ReplayMode::EvidenceReproduction => None,
            ReplayMode::InvocationReproduction | ReplayMode::Observational => {
                let invocation = reconstruct_invocation(&loaded)?;
                let input_digest = invocation.envelope.input_digest.clone();
                reconstructed = Some(invocation);
                Some(input_digest)
            }
            ReplayMode::LiveComparison => {
                return Err(ReplayError::new(ReplayErrorCode::LiveModeRequired));
            }
        };

        if request.mode == ReplayMode::Observational {
            let entries = recorded_entries(&loaded)?;
            let mut tape = RecordedProviderTape::new(entries)
                .map_err(|_error| ReplayError::new(ReplayErrorCode::RecordedProviderFailure))?;
            for recorded in &loaded.archive.manifest.observations {
                context.check_active()?;
                let expected = RecordedProviderExpectation::new(
                    recorded.ordinal,
                    recorded.kind,
                    recorded.provider_fingerprint.clone(),
                    recorded.request_digest.clone(),
                    recorded.subject_id.clone(),
                );
                let entry = tape
                    .consume(&expected)
                    .map_err(|_error| ReplayError::new(ReplayErrorCode::RecordedProviderFailure))?;
                observations.push(entry.protected_response().to_vec());
            }
            let counters = tape
                .finish()
                .map_err(|_error| ReplayError::new(ReplayErrorCode::RecordedProviderFailure))?;
            if counters.live_calls() != 0 {
                return Err(ReplayError::new(ReplayErrorCode::RecordedProviderFailure));
            }
            observation_digest = Some(framed_observation_digest(&observations)?);
        }

        let execution = complete_execution(
            request,
            execution_id,
            loaded.completeness.clone(),
            reconstructed_input_digest,
            observation_digest,
            false,
            false,
            started_at,
            completed_at,
        )?;
        context.check_active()?;
        Ok(ReplayResult {
            execution,
            missing_dependencies: Vec::new(),
            reconstructed_invocation: reconstructed,
            observations,
            diff: None,
            external_calls: ReplayExternalCallCounters::default(),
        })
    }

    /// Executes an explicitly authorized live comparison as a new execution.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_live(
        &self,
        request: &ReplayRequest,
        authorization: &LiveReplayAuthorization,
        execution_id: RecordId,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
    ) -> Result<ReplayResult, ReplayError> {
        self.replay_live_with_context(
            request,
            authorization,
            execution_id,
            started_at,
            completed_at,
            &ReplayContext::unbounded(),
        )
    }

    /// Executes live comparison under one authoritative request lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_live_with_context(
        &self,
        request: &ReplayRequest,
        authorization: &LiveReplayAuthorization,
        execution_id: RecordId,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
        context: &ReplayContext,
    ) -> Result<ReplayResult, ReplayError> {
        context.check_active()?;
        self.validate_request(request, &execution_id, started_at, completed_at)?;
        if request.mode != ReplayMode::LiveComparison {
            return Err(ReplayError::new(ReplayErrorCode::LiveModeRequired));
        }
        self.reserve_execution(execution_id.clone(), context)?;
        let loaded = self.load_exact(request, context)?;
        if !loaded.missing.is_empty() {
            context.check_active()?;
            return self.incomplete_result(request, execution_id, started_at, completed_at, loaded);
        }
        authorization.validate_binding(request)?;
        if request.authorized_effect_intents.iter().any(|effect_id| {
            loaded
                .archive
                .decision
                .effects
                .binary_search(effect_id)
                .is_ok()
        }) {
            return Err(ReplayError::new(
                ReplayErrorCode::EffectAuthorizationInvalid,
            ));
        }
        self.reserve_live_authorization(
            authorization.nonce.clone(),
            authorization.authorization_digest.clone(),
            context,
        )?;
        self.counters
            .live_authorization_checks
            .fetch_add(1, Ordering::SeqCst);
        let trusted_now = self
            .live_verifier
            .verify_current_with_context(authorization, context)
            .map_err(|_error| ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid))?;
        authorization.validate_window(trusted_now)?;

        let reconstructed = reconstruct_invocation(&loaded)?;
        let input_digest = reconstructed.envelope.input_digest.clone();
        let invocation = LiveReplayInvocation {
            execution_id: execution_id.clone(),
            request_id: request.request_id.clone(),
            source_decision_id: request.decision_id.clone(),
            input_digest: input_digest.clone(),
            reconstructed: reconstructed.clone(),
        };
        self.counters
            .live_provider_calls
            .fetch_add(1, Ordering::SeqCst);
        let mut live_output = self
            .live_provider
            .execute_with_context(&invocation, context)
            .map_err(|_error| ReplayError::new(ReplayErrorCode::LiveProviderFailure))?;
        let dispatch = if request.simulate_effects {
            None
        } else {
            if live_output.effect_intents != request.authorized_effect_intents {
                return Err(ReplayError::new(
                    ReplayErrorCode::EffectAuthorizationInvalid,
                ));
            }
            Some(LiveEffectDispatch {
                execution_id: execution_id.clone(),
                request_id: request.request_id.clone(),
                source_decision_id: request.decision_id.clone(),
                effect_intents: live_output.effect_intents.clone(),
                live_authorization_digest: authorization.authorization_digest.clone(),
            })
        };
        let dispatched = u64::try_from(request.authorized_effect_intents.len())
            .map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))?;
        let observation_digest = framed_observation_digest(&live_output.observations)?;
        live_output.dimensions.observations = Some(observation_digest.clone());
        live_output.dimensions.effect_plan =
            Some(digest_serializable(&live_output.effect_intents)?);
        let baseline = archived_dimensions(&loaded)?;
        let diff = compare_replay_dimensions(
            request.decision_id.clone(),
            execution_id.clone(),
            &baseline,
            &live_output.dimensions,
        )
        .map_err(map_foundation_error)?;
        let execution = complete_execution(
            request,
            execution_id.clone(),
            loaded.completeness.clone(),
            Some(input_digest),
            Some(observation_digest),
            true,
            !request.simulate_effects,
            started_at,
            completed_at,
        )?;
        context.check_active()?;
        if let Some(dispatch) = dispatch.as_ref() {
            self.effect_gate
                .authorize_and_dispatch_with_context(dispatch, context)
                .map_err(|_error| ReplayError::new(ReplayErrorCode::EffectAuthorizationInvalid))?;
            self.counters
                .live_effect_dispatches
                .fetch_add(dispatched, Ordering::SeqCst);
        }
        context.check_active()?;
        Ok(ReplayResult {
            execution,
            missing_dependencies: Vec::new(),
            reconstructed_invocation: Some(reconstructed),
            observations: live_output.observations,
            diff: Some(diff),
            external_calls: ReplayExternalCallCounters {
                live_authorization_checks: 1,
                live_provider_calls: 1,
                live_effect_dispatches: if request.simulate_effects {
                    0
                } else {
                    dispatched
                },
            },
        })
    }

    fn validate_request(
        &self,
        request: &ReplayRequest,
        execution_id: &RecordId,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
    ) -> Result<(), ReplayError> {
        if request.validate().is_err()
            || completed_at < started_at
            || execution_id == &request.request_id
        {
            return Err(ReplayError::new(ReplayErrorCode::InvalidRequest));
        }
        Ok(())
    }

    fn reserve_execution(
        &self,
        execution_id: RecordId,
        context: &ReplayContext,
    ) -> Result<(), ReplayError> {
        context.check_active()?;
        if !self.reservations.reserve_execution(&execution_id)? {
            return Err(ReplayError::new(ReplayErrorCode::ExecutionIdReused));
        }
        context.check_active()?;
        Ok(())
    }

    fn reserve_live_authorization(
        &self,
        nonce: RecordId,
        digest: ContentDigest,
        context: &ReplayContext,
    ) -> Result<(), ReplayError> {
        context.check_active()?;
        if !self
            .reservations
            .reserve_live_authorization(&nonce, &digest)?
        {
            return Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationReused));
        }
        context.check_active()?;
        Ok(())
    }

    fn load_exact(
        &self,
        request: &ReplayRequest,
        context: &ReplayContext,
    ) -> Result<LoadedReplay, ReplayError> {
        self.load_exact_for(&request.decision_id, request.mode, context)
    }

    fn load_exact_for(
        &self,
        decision_id: &VersionId,
        mode: ReplayMode,
        context: &ReplayContext,
    ) -> Result<LoadedReplay, ReplayError> {
        context.check_active()?;
        let archive = self
            .archive
            .get_decision(decision_id)
            .map_err(map_foundation_error)?
            .ok_or_else(|| ReplayError::new(ReplayErrorCode::DecisionNotFound))?;
        context.check_active()?;
        if &archive.decision.decision_id != decision_id || archive.validate().is_err() {
            return Err(ReplayError::new(ReplayErrorCode::ArchiveIntegrity));
        }
        let mut artifacts = BTreeMap::new();
        let mut category_available = BTreeMap::<DependencyKind, bool>::new();
        let mut missing = Vec::new();
        for dependency in archive
            .manifest
            .dependencies
            .iter()
            .filter(|dependency| dependency.required_modes.contains(&mode))
        {
            context.check_active()?;
            category_available.entry(dependency.kind).or_insert(true);
            let artifact = self
                .archive
                .get_artifact(&dependency.content_digest)
                .map_err(map_foundation_error)?;
            context.check_active()?;
            let reason = match artifact.as_ref() {
                None => Some(MissingDependencyReason::Missing),
                Some(value)
                    if value.validate().is_err()
                        || value.content_digest != dependency.content_digest =>
                {
                    return Err(ReplayError::new(ReplayErrorCode::ArchiveIntegrity));
                }
                Some(_value) => None,
            };
            if let Some(reason) = reason {
                category_available.insert(dependency.kind, false);
                missing.push(MissingDependencyRow {
                    kind: dependency.kind,
                    role: dependency.role,
                    content_digest: dependency.content_digest.clone(),
                    required_mode: mode,
                    reason,
                });
            } else if let Some(value) = artifact {
                artifacts.insert(dependency.content_digest.clone(), value);
            }
        }
        missing.sort_by(|left, right| {
            (&left.kind, &left.role, &left.content_digest).cmp(&(
                &right.kind,
                &right.role,
                &right.content_digest,
            ))
        });
        let mut available = Vec::new();
        let mut missing_kinds = Vec::new();
        for (kind, is_available) in category_available {
            context.check_active()?;
            if is_available {
                available.push(kind);
            } else {
                missing_kinds.push(kind);
            }
        }
        context.check_active()?;
        Ok(LoadedReplay {
            archive,
            artifacts,
            completeness: ReplayCompleteness {
                available,
                missing: missing_kinds,
            },
            missing,
        })
    }

    fn incomplete_result(
        &self,
        request: &ReplayRequest,
        execution_id: RecordId,
        started_at: UtcTimestamp,
        completed_at: UtcTimestamp,
        loaded: LoadedReplay,
    ) -> Result<ReplayResult, ReplayError> {
        let execution = ReplayExecution {
            schema_version: replay_execution_schema()?,
            execution_id,
            request_id: request.request_id.clone(),
            mode: request.mode,
            status: ReplayStatus::Incomplete,
            completeness: loaded.completeness,
            reconstructed_input_digest: None,
            observation_digest: None,
            egress_permitted: false,
            effect_dispatch_permitted: false,
            started_at,
            completed_at: Some(completed_at),
        };
        execution
            .validate()
            .map_err(|_error| ReplayError::new(ReplayErrorCode::ProtocolViolation))?;
        Ok(ReplayResult {
            execution,
            missing_dependencies: loaded.missing,
            reconstructed_invocation: None,
            observations: Vec::new(),
            diff: None,
            external_calls: ReplayExternalCallCounters::default(),
        })
    }
}

struct LoadedReplay {
    archive: DecisionArchive,
    artifacts: BTreeMap<ContentDigest, DecisionArtifact>,
    completeness: ReplayCompleteness,
    missing: Vec<MissingDependencyRow>,
}

fn reconstruct_invocation(loaded: &LoadedReplay) -> Result<ReconstructedInvocation, ReplayError> {
    let input = required_role_artifact(loaded, DependencyRole::Invocation)?;
    let parameters = required_role_artifact(loaded, DependencyRole::InvocationParameters)?;
    let materialization = required_role_artifact(loaded, DependencyRole::Materialization)?;
    let mut components = Vec::new();
    for dependency in &loaded.archive.manifest.dependencies {
        if !is_invocation_component(dependency.role) {
            continue;
        }
        let artifact = loaded
            .artifacts
            .get(&dependency.content_digest)
            .ok_or_else(|| ReplayError::new(ReplayErrorCode::ArchiveIntegrity))?;
        let fingerprint = dependency
            .fingerprint
            .clone()
            .ok_or_else(|| ReplayError::new(ReplayErrorCode::ArchiveIntegrity))?;
        components.push(ReconstructedComponent {
            role: dependency.role,
            content_digest: artifact.content_digest.clone(),
            fingerprint,
            exact_bytes: artifact.bytes().to_vec(),
        });
    }
    Ok(ReconstructedInvocation {
        envelope: loaded.archive.manifest.invocation.clone(),
        exact_input: input.bytes().to_vec(),
        exact_parameters: parameters.bytes().to_vec(),
        exact_materialization: materialization.bytes().to_vec(),
        components,
    })
}

fn is_invocation_component(role: DependencyRole) -> bool {
    matches!(
        role,
        DependencyRole::Tokenizer
            | DependencyRole::Materializer
            | DependencyRole::Adapter
            | DependencyRole::Consumer
            | DependencyRole::Runtime
            | DependencyRole::ToolSchema
            | DependencyRole::Environment
    )
}

fn required_role_artifact(
    loaded: &LoadedReplay,
    role: DependencyRole,
) -> Result<&DecisionArtifact, ReplayError> {
    let mut matching = loaded
        .archive
        .manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.role == role)
        .filter_map(|dependency| loaded.artifacts.get(&dependency.content_digest));
    let artifact = matching
        .next()
        .ok_or_else(|| ReplayError::new(ReplayErrorCode::ArchiveIntegrity))?;
    if matching.next().is_some() {
        return Err(ReplayError::new(ReplayErrorCode::ArchiveIntegrity));
    }
    Ok(artifact)
}

fn recorded_entries(loaded: &LoadedReplay) -> Result<Vec<RecordedProviderEntry>, ReplayError> {
    loaded
        .archive
        .manifest
        .observations
        .iter()
        .map(|observation| {
            let artifact = loaded
                .artifacts
                .get(&observation.response_digest)
                .ok_or_else(|| ReplayError::new(ReplayErrorCode::ArchiveIntegrity))?;
            RecordedProviderEntry::new(observation.clone(), artifact.bytes().to_vec())
                .map_err(|_error| ReplayError::new(ReplayErrorCode::RecordedProviderFailure))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn complete_execution(
    request: &ReplayRequest,
    execution_id: RecordId,
    completeness: ReplayCompleteness,
    reconstructed_input_digest: Option<ContentDigest>,
    observation_digest: Option<ContentDigest>,
    egress_permitted: bool,
    effect_dispatch_permitted: bool,
    started_at: UtcTimestamp,
    completed_at: UtcTimestamp,
) -> Result<ReplayExecution, ReplayError> {
    let execution = ReplayExecution {
        schema_version: replay_execution_schema()?,
        execution_id,
        request_id: request.request_id.clone(),
        mode: request.mode,
        status: ReplayStatus::Complete,
        completeness,
        reconstructed_input_digest,
        observation_digest,
        egress_permitted,
        effect_dispatch_permitted,
        started_at,
        completed_at: Some(completed_at),
    };
    execution
        .validate()
        .map_err(|_error| ReplayError::new(ReplayErrorCode::ProtocolViolation))?;
    Ok(execution)
}

fn replay_execution_schema() -> Result<SchemaVersion, ReplayError> {
    SchemaVersion::new("cigar.replay-execution", 1)
        .map_err(|_error| ReplayError::new(ReplayErrorCode::ProtocolViolation))
}

/// Computes SHA-256 over ordered `u32be length || exact bytes` observation frames.
pub fn framed_observation_digest(observations: &[Vec<u8>]) -> Result<ContentDigest, ReplayError> {
    if observations.len() > MAX_REPLAY_REFERENCES {
        return Err(ReplayError::new(ReplayErrorCode::InvalidRequest));
    }
    let mut hasher = Sha256::new();
    let mut aggregate_bytes = 0_usize;
    for observation in observations {
        if observation.len() > crate::MAX_DECISION_ARTIFACT_BYTES {
            return Err(ReplayError::new(ReplayErrorCode::InvalidRequest));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(observation.len())
            .ok_or_else(|| ReplayError::new(ReplayErrorCode::InvalidRequest))?;
        if aggregate_bytes > crate::MAX_DECISION_CAPTURE_BYTES {
            return Err(ReplayError::new(ReplayErrorCode::InvalidRequest));
        }
        let length = u32::try_from(observation.len())
            .map_err(|_error| ReplayError::new(ReplayErrorCode::InvalidRequest))?;
        hasher.update(length.to_be_bytes());
        hasher.update(observation);
    }
    let hash = hasher.finalize();
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))?;
    }
    ContentDigest::new(encoded).map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))
}

/// Computes the canonical component-dimension digest used by [`ReplayDiff`].
pub fn component_dimension_digest(
    components: &[ReconstructedComponent],
) -> Result<ContentDigest, ReplayError> {
    let identities = components
        .iter()
        .map(|component| (component.role, &component.fingerprint))
        .collect::<Vec<_>>();
    digest_serializable(&identities)
}

fn archived_dimensions(loaded: &LoadedReplay) -> Result<ReplayDimensionDigests, ReplayError> {
    let observations = recorded_entries(loaded)?
        .into_iter()
        .map(|entry| entry.protected_response().to_vec())
        .collect::<Vec<_>>();
    let decision = &loaded.archive.decision;
    let components = loaded
        .archive
        .manifest
        .dependencies
        .iter()
        .filter(|dependency| is_invocation_component(dependency.role))
        .map(|dependency| {
            dependency
                .fingerprint
                .as_ref()
                .map(|fingerprint| (dependency.role, fingerprint))
                .ok_or_else(|| ReplayError::new(ReplayErrorCode::ArchiveIntegrity))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReplayDimensionDigests {
        semantic_context: Some(
            ContentDigest::new(decision.bundle_id.as_str())
                .map_err(|_error| ReplayError::new(ReplayErrorCode::ArchiveIntegrity))?,
        ),
        materialization: Some(decision.materialization_digest.clone()),
        components: Some(digest_serializable(&components)?),
        output_claims: Some(digest_serializable(&(
            &decision.output_artifacts,
            &decision.asserted_claims,
            &decision.evidence,
            &decision.uncertainty,
        ))?),
        verification: Some(digest_serializable(&decision.verification_receipts)?),
        effect_plan: Some(digest_serializable(&decision.effects)?),
        observations: Some(framed_observation_digest(&observations)?),
    })
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<ContentDigest, ReplayError> {
    let bytes = crate::digest::canonical_record_bytes(value).map_err(map_foundation_error)?;
    crate::digest::raw_content_digest(&bytes).map_err(map_foundation_error)
}

fn map_foundation_error(error: ReplayFoundationError) -> ReplayError {
    match error.code() {
        ReplayFoundationErrorCode::NotFound => ReplayError::new(ReplayErrorCode::DecisionNotFound),
        ReplayFoundationErrorCode::IntegrityFailure | ReplayFoundationErrorCode::Collision => {
            ReplayError::new(ReplayErrorCode::ArchiveIntegrity)
        }
        ReplayFoundationErrorCode::Unavailable => {
            ReplayError::new(ReplayErrorCode::ArchiveUnavailable)
        }
        ReplayFoundationErrorCode::InvalidInput | ReplayFoundationErrorCode::LimitExceeded => {
            ReplayError::new(ReplayErrorCode::ProtocolViolation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryReplayReservationLedger, ReplayReservationLedger};
    use cigar_protocol::{ContentDigest, RecordId};
    use std::sync::{Arc, Barrier};

    #[test]
    fn reservation_ledger_is_atomic_for_execution_nonce_and_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let ledger = Arc::new(InMemoryReplayReservationLedger::default());
        let execution = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?;
        assert!(ledger.reserve_execution(&execution)?);
        assert!(!ledger.reserve_execution(&execution)?);

        let nonce = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000002")?;
        let digest = ContentDigest::new(format!("1220{}", "a".repeat(64)))?;
        let barrier = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for _worker in 0..8 {
            let worker_ledger = Arc::clone(&ledger);
            let worker_nonce = nonce.clone();
            let worker_digest = digest.clone();
            let worker_barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_ledger.reserve_live_authorization(&worker_nonce, &worker_digest)
            }));
        }
        barrier.wait();
        let mut winners = 0_u64;
        for worker in workers {
            let reserved = worker
                .join()
                .map_err(|_panic| "reservation worker panicked")??;
            if reserved {
                winners = winners.saturating_add(1);
            }
        }
        assert_eq!(winners, 1);

        let different_nonce = RecordId::new("01890f47-8e7d-7b42-a1d2-000000000003")?;
        assert!(!ledger.reserve_live_authorization(&different_nonce, &digest)?);
        let different_digest = ContentDigest::new(format!("1220{}", "b".repeat(64)))?;
        assert!(!ledger.reserve_live_authorization(&nonce, &different_digest)?);
        Ok(())
    }
}
