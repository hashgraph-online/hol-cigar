//! Durable replay jobs with explicit interrupted-state recovery.

use cigar_canon::parse_strict_json;
use cigar_protocol::{
    RecordId, ReplayCompleteness, ReplayDiff, ReplayExecution, ReplayMode, ReplayRequest,
    ReplayStatus, UtcTimestamp, Validate, VersionId, limits::MAX_REPLAY_REFERENCES,
};
use cigar_replay::{
    LiveReplayAuthorization, MissingDependencyRow, ReplayContext, ReplayEngine, ReplayError,
    ReplayErrorCode, ReplayExternalCallCounters, ReplayResult,
};
use cigar_store::{
    CancellationToken, ServiceBatch, ServiceError, ServiceErrorCode, ServiceExpectedVersion,
    ServiceListQuery, ServiceListScope, ServiceRecord, ServiceRecordLocator,
    ServiceRecordSelection, ServiceRecordWrite, ServiceRepository, ServiceResponse,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

const JOB_NAMESPACE: &str = "replay.job.v1";
const JOB_SCHEMA: &str = "cigar.replay-job.v1";
const LIVE_DRAFT_NAMESPACE: &str = "replay.live-draft.v1";
const LIVE_DRAFT_SCHEMA: &str = "cigar.live-replay-draft.v1";
const MAX_RECOVERY_PAGE: usize = 1_000;

/// Stable replay-job failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayJobErrorCode {
    /// A request, transition, identity, or time range was invalid.
    InvalidInput,
    /// The job is absent or deliberately existence-hidden.
    NotFound,
    /// Another writer or execution owns the current job transition.
    Conflict,
    /// Storage cancellation was observed.
    Cancelled,
    /// The durable job repository is unavailable or corrupt.
    Unavailable,
    /// The replay engine rejected or failed the requested execution.
    Replay(ReplayErrorCode),
}

/// Content-free durable replay-job error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplayJobError {
    code: ReplayJobErrorCode,
}

impl ReplayJobError {
    const fn new(code: ReplayJobErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ReplayJobErrorCode {
        self.code
    }
}

impl fmt::Debug for ReplayJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayJobError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ReplayJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "replay job failed: {:?}", self.code)
    }
}

impl std::error::Error for ReplayJobError {}

impl From<ReplayError> for ReplayJobError {
    fn from(error: ReplayError) -> Self {
        Self::new(ReplayJobErrorCode::Replay(error.code()))
    }
}

/// Durable replay-job lifecycle. A process death is never presented as success.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayJobPhase {
    /// Request and exact dependency inspection are durable; no execution is reserved.
    Pending,
    /// An execution identity is durable and the engine may be running.
    Running,
    /// A complete or explicitly incomplete protocol execution is durable.
    Complete,
    /// The engine returned a stable content-free failure.
    Failed,
    /// Startup observed a process death while the job was running.
    Interrupted,
}

/// Serializable mirror of replay-engine failures retained without protected content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayJobFailure {
    /// The replay request failed protocol validation.
    InvalidRequest,
    /// The selected source decision does not exist in the authorized archive scope.
    DecisionNotFound,
    /// Retained archive bytes or semantic identities failed integrity validation.
    ArchiveIntegrity,
    /// The exact archive dependency could not be read safely.
    ArchiveUnavailable,
    /// An execution identity was already reserved by another attempt.
    ExecutionIdReused,
    /// The requested engine entry point did not match live mode.
    LiveModeRequired,
    /// The live authorization was malformed, expired, or bound to another request.
    LiveAuthorizationInvalid,
    /// The one-use live authorization had already been consumed.
    LiveAuthorizationReused,
    /// A recorded provider rejected the deterministic observation tape.
    RecordedProviderFailure,
    /// The explicitly authorized live provider failed.
    LiveProviderFailure,
    /// A requested live effect was not covered by the exact authorization.
    EffectAuthorizationInvalid,
    /// The engine produced an invalid protocol record.
    ProtocolViolation,
    /// An engine dependency was unavailable without a safer specific category.
    Unavailable,
}

impl From<ReplayErrorCode> for ReplayJobFailure {
    fn from(code: ReplayErrorCode) -> Self {
        match code {
            ReplayErrorCode::InvalidRequest => Self::InvalidRequest,
            ReplayErrorCode::DecisionNotFound => Self::DecisionNotFound,
            ReplayErrorCode::ArchiveIntegrity => Self::ArchiveIntegrity,
            ReplayErrorCode::ArchiveUnavailable => Self::ArchiveUnavailable,
            ReplayErrorCode::ExecutionIdReused => Self::ExecutionIdReused,
            ReplayErrorCode::LiveModeRequired => Self::LiveModeRequired,
            ReplayErrorCode::LiveAuthorizationInvalid => Self::LiveAuthorizationInvalid,
            ReplayErrorCode::LiveAuthorizationReused => Self::LiveAuthorizationReused,
            ReplayErrorCode::RecordedProviderFailure => Self::RecordedProviderFailure,
            ReplayErrorCode::LiveProviderFailure => Self::LiveProviderFailure,
            ReplayErrorCode::EffectAuthorizationInvalid => Self::EffectAuthorizationInvalid,
            ReplayErrorCode::ProtocolViolation => Self::ProtocolViolation,
            ReplayErrorCode::Unavailable => Self::Unavailable,
        }
    }
}

/// Content-safe retained live-boundary counters for one execution.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredReplayCounters {
    /// Number of live authorization boundary checks made by this attempt.
    pub live_authorization_checks: u64,
    /// Number of live provider calls made by this attempt.
    pub live_provider_calls: u64,
    /// Number of newly authorized effect intents dispatched by this attempt.
    pub live_effect_dispatches: u64,
}

impl From<ReplayExternalCallCounters> for StoredReplayCounters {
    fn from(value: ReplayExternalCallCounters) -> Self {
        Self {
            live_authorization_checks: value.live_authorization_checks,
            live_provider_calls: value.live_provider_calls,
            live_effect_dispatches: value.live_effect_dispatches,
        }
    }
}

/// Strict durable replay job. Protected invocation and observation bytes remain in the archive.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayJobRecord {
    schema_version: String,
    /// Exact replay request, including the authenticated requester selected by the server.
    pub request: ReplayRequest,
    /// Current durable job phase.
    pub phase: ReplayJobPhase,
    /// Side-effect-free exact dependency inspection at the latest transition.
    pub completeness: ReplayCompleteness,
    /// Execution reserved for the current or most recent attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<RecordId>,
    /// Durable protocol execution after completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ReplayExecution>,
    /// Exact unavailable dependency rows; protected bytes are never stored here.
    pub missing_dependencies: Vec<MissingDependencyRow>,
    /// Structured live comparison, present only for a complete live job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<ReplayDiff>,
    /// Stable engine failure retained only for failed jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<ReplayJobFailure>,
    /// Content-safe external-boundary counts for the completed attempt.
    pub external_calls: StoredReplayCounters,
}

impl ReplayJobRecord {
    fn pending(
        request: ReplayRequest,
        completeness: ReplayCompleteness,
        missing_dependencies: Vec<MissingDependencyRow>,
    ) -> Self {
        Self {
            schema_version: JOB_SCHEMA.to_owned(),
            request,
            phase: ReplayJobPhase::Pending,
            completeness,
            execution_id: None,
            execution: None,
            missing_dependencies,
            diff: None,
            failure: None,
            external_calls: StoredReplayCounters::default(),
        }
    }

    fn validate(&self) -> Result<(), ReplayJobError> {
        self.request.validate().map_err(|_error| invalid_input())?;
        if !completeness_is_canonical(&self.completeness)
            || self.schema_version != JOB_SCHEMA
            || !missing_rows_are_canonical(&self.missing_dependencies)
        {
            return Err(invalid_input());
        }
        let shape_valid = match self.phase {
            ReplayJobPhase::Pending => {
                self.execution_id.is_none()
                    && self.execution.is_none()
                    && self.diff.is_none()
                    && self.failure.is_none()
            }
            ReplayJobPhase::Running | ReplayJobPhase::Interrupted => {
                self.execution_id.is_some()
                    && self.execution.is_none()
                    && self.diff.is_none()
                    && self.failure.is_none()
            }
            ReplayJobPhase::Failed => {
                self.execution_id.is_some()
                    && self.execution.is_none()
                    && self.diff.is_none()
                    && self.failure.is_some()
            }
            ReplayJobPhase::Complete => {
                self.execution_id.is_some()
                    && self.execution.is_some()
                    && self.failure.is_none()
                    && self.execution.as_ref().is_some_and(|execution| {
                        matches!(
                            execution.status,
                            ReplayStatus::Complete | ReplayStatus::Incomplete
                        ) && if self.request.mode == ReplayMode::LiveComparison
                            && execution.status == ReplayStatus::Complete
                        {
                            self.diff.is_some()
                        } else {
                            self.diff.is_none()
                        }
                    })
            }
        };
        if !shape_valid {
            return Err(invalid_input());
        }
        if let Some(execution) = &self.execution {
            execution.validate().map_err(|_error| invalid_input())?;
            if Some(&execution.execution_id) != self.execution_id.as_ref()
                || execution.request_id != self.request.request_id
                || execution.mode != self.request.mode
                || execution.completeness != self.completeness
            {
                return Err(invalid_input());
            }
        }
        if let Some(diff) = &self.diff {
            diff.validate().map_err(|_error| invalid_input())?;
        }
        Ok(())
    }
}

impl fmt::Debug for ReplayJobRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayJobRecord")
            .field("request_id", &self.request.request_id)
            .field("decision_id", &self.request.decision_id)
            .field("mode", &self.request.mode)
            .field("phase", &self.phase)
            .field("execution_id", &self.execution_id)
            .field("missing_dependency_count", &self.missing_dependencies.len())
            .field("has_diff", &self.diff.is_some())
            .field("failure", &self.failure)
            .field("external_calls", &self.external_calls)
            .finish_non_exhaustive()
    }
}

/// One trusted server-selected execution identity and time observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayExecutionWindow {
    /// Trusted server-selected identity for the new execution attempt.
    pub execution_id: RecordId,
    /// Trusted start observation for the attempt.
    pub started_at: UtcTimestamp,
    /// Trusted completion observation for the attempt.
    pub completed_at: UtcTimestamp,
}

impl ReplayExecutionWindow {
    fn validate_for(&self, request: &ReplayRequest) -> Result<(), ReplayJobError> {
        if self.execution_id == request.request_id || self.completed_at < self.started_at {
            Err(invalid_input())
        } else {
            Ok(())
        }
    }
}

/// A durable job paired with its optimistic logical-record version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedReplayJob {
    /// Optimistic durable record version.
    pub version: u64,
    /// Strict decoded replay job.
    pub record: ReplayJobRecord,
}

/// Durable binding state for a live replay draft.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiveReplayDraftPhase {
    /// The draft has no authorization proof and cannot cross a live boundary.
    Unbound,
    /// One exact authorization and execution identity were atomically bound.
    Bound {
        /// Digest of the separately verified authorization.
        authorization_digest: cigar_protocol::ContentDigest,
        /// Single execution identity reserved by the binding transition.
        execution_id: RecordId,
    },
}

/// Persisted live replay state before a separately issued authorization is selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveReplayDraftRecord {
    schema_version: String,
    /// Stable replay/job identity selected by the server.
    pub request_id: RecordId,
    /// Exact immutable source decision.
    pub decision_id: VersionId,
    /// Server-resolved authenticated requester.
    pub requested_by: RecordId,
    /// Whether every effect must remain simulated.
    pub simulate_effects: bool,
    /// Exact dependency inspection for live mode without a fabricated authorization digest.
    pub completeness: ReplayCompleteness,
    /// Detailed exact missing dependency rows.
    pub missing_dependencies: Vec<MissingDependencyRow>,
    /// Current one-way binding state.
    pub phase: LiveReplayDraftPhase,
}

impl LiveReplayDraftRecord {
    fn validate(&self) -> Result<(), ReplayJobError> {
        if self.schema_version != LIVE_DRAFT_SCHEMA
            || !completeness_is_canonical(&self.completeness)
            || !missing_rows_are_canonical(&self.missing_dependencies)
        {
            return Err(invalid_input());
        }
        Ok(())
    }
}

/// One durable live draft paired with its optimistic record version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedLiveReplayDraft {
    /// Optimistic durable record version.
    pub version: u64,
    /// Strict decoded live draft.
    pub record: LiveReplayDraftRecord,
}

/// Tenant-scoped replay job service over an exact replay engine and service repository.
pub struct DurableReplayJobService {
    repository: Arc<dyn ServiceRepository>,
    tenant_id: RecordId,
    engine: Arc<ReplayEngine>,
    context: ReplayContext,
}

impl DurableReplayJobService {
    /// Creates a job service; the engine should use the same durable archive and reservation scope.
    #[must_use]
    pub fn new(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        engine: Arc<ReplayEngine>,
    ) -> Self {
        Self {
            repository,
            tenant_id,
            engine,
            context: ReplayContext::unbounded(),
        }
    }

    /// Creates a job service whose engine and every injected dependency share one request
    /// lifetime.
    #[must_use]
    pub fn new_with_context(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
        engine: Arc<ReplayEngine>,
        context: ReplayContext,
    ) -> Self {
        Self {
            repository,
            tenant_id,
            engine,
            context,
        }
    }

    fn ensure_active(&self, cancellation: &CancellationToken) -> Result<(), ReplayJobError> {
        if cancellation.is_cancelled() || self.context.check_active().is_err() {
            Err(ReplayJobError::new(ReplayJobErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Persists an unbound live replay draft without fabricating an authorization digest or
    /// reserving an execution. Exact dependency inspection remains side-effect free.
    pub fn create_live_draft(
        &self,
        request_id: RecordId,
        decision_id: VersionId,
        requested_by: RecordId,
        simulate_effects: bool,
        cancellation: &CancellationToken,
    ) -> Result<VersionedLiveReplayDraft, ReplayJobError> {
        self.ensure_active(cancellation)?;
        let inspection = self.engine.inspect_completeness_for_with_context(
            &decision_id,
            ReplayMode::LiveComparison,
            &self.context,
        )?;
        self.ensure_active(cancellation)?;
        let record = LiveReplayDraftRecord {
            schema_version: LIVE_DRAFT_SCHEMA.to_owned(),
            request_id: request_id.clone(),
            decision_id,
            requested_by,
            simulate_effects,
            completeness: inspection.completeness,
            missing_dependencies: inspection.missing_dependencies,
            phase: LiveReplayDraftPhase::Unbound,
        };
        record.validate()?;
        match self.commit_live_draft(&record, ServiceExpectedVersion::Absent, cancellation) {
            Ok(version) => Ok(VersionedLiveReplayDraft { version, record }),
            Err(error) if error.code() == ReplayJobErrorCode::Conflict => {
                let existing = self
                    .load_live_draft(&request_id, cancellation)?
                    .ok_or_else(|| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
                if existing.record.decision_id == record.decision_id
                    && existing.record.requested_by == record.requested_by
                    && existing.record.simulate_effects == record.simulate_effects
                {
                    Ok(existing)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Returns one exact owner-visible live draft, existence-hiding all other scopes.
    pub fn get_live_draft(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<VersionedLiveReplayDraft, ReplayJobError> {
        let loaded = self
            .load_live_draft(request_id, cancellation)?
            .ok_or_else(not_found)?;
        if &loaded.record.requested_by != actor_id {
            return Err(not_found());
        }
        Ok(loaded)
    }

    /// Atomically binds one separately verified live authorization and running execution before
    /// any live provider or effect boundary is crossed. A bound draft can never select a second
    /// authorization or execution identity.
    pub fn bind_and_compare_live(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        authorization: &LiveReplayAuthorization,
        window: ReplayExecutionWindow,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        self.ensure_active(cancellation)?;
        let draft = self.get_live_draft(request_id, actor_id, cancellation)?;
        if let LiveReplayDraftPhase::Bound {
            authorization_digest,
            execution_id,
        } = &draft.record.phase
        {
            if authorization_digest != &authorization.authorization_digest
                || execution_id != &window.execution_id
            {
                return Err(ReplayJobError::new(ReplayJobErrorCode::Conflict));
            }
            let existing = self.get(request_id, actor_id, cancellation)?;
            return if existing.record.phase == ReplayJobPhase::Complete {
                Ok(existing)
            } else {
                Err(ReplayJobError::new(ReplayJobErrorCode::Conflict))
            };
        }
        let request = ReplayRequest {
            schema_version: cigar_protocol::SchemaVersion::new("cigar.replay-request", 1)
                .map_err(|_error| invalid_input())?,
            request_id: request_id.clone(),
            decision_id: draft.record.decision_id.clone(),
            mode: ReplayMode::LiveComparison,
            requested_by: actor_id.clone(),
            live_authorization_digest: Some(authorization.authorization_digest.clone()),
            simulate_effects: draft.record.simulate_effects,
            authorized_effect_intents: authorization.authorized_effect_intents.clone(),
        };
        request.validate().map_err(|_error| invalid_input())?;
        authorization.validate_binding(&request)?;
        window.validate_for(&request)?;

        let mut running_record = ReplayJobRecord::pending(
            request,
            draft.record.completeness.clone(),
            draft.record.missing_dependencies.clone(),
        );
        running_record.phase = ReplayJobPhase::Running;
        running_record.execution_id = Some(window.execution_id.clone());
        running_record.validate()?;
        let mut bound_draft = draft.record;
        bound_draft.phase = LiveReplayDraftPhase::Bound {
            authorization_digest: authorization.authorization_digest.clone(),
            execution_id: window.execution_id.clone(),
        };
        bound_draft.validate()?;
        let version =
            self.commit_live_binding(&running_record, &bound_draft, draft.version, cancellation)?;
        let running = VersionedReplayJob {
            version,
            record: running_record,
        };
        self.ensure_active(cancellation)?;
        let result = self.engine.replay_live_with_context(
            &running.record.request,
            authorization,
            window.execution_id,
            window.started_at,
            window.completed_at,
            &self.context,
        );
        self.finish_engine_result(running, result, cancellation)
    }

    /// Persists an observational or live job without running it.
    pub fn create_pending(
        &self,
        request: ReplayRequest,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        if !matches!(
            request.mode,
            ReplayMode::Observational | ReplayMode::LiveComparison
        ) {
            return Err(invalid_input());
        }
        self.create_record(request, cancellation)
    }

    /// Persists and immediately executes an evidence or invocation reconstruction.
    pub fn create_and_reconstruct(
        &self,
        request: ReplayRequest,
        window: ReplayExecutionWindow,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        if !matches!(
            request.mode,
            ReplayMode::EvidenceReproduction | ReplayMode::InvocationReproduction
        ) {
            return Err(invalid_input());
        }
        let job = self.create_record(request, cancellation)?;
        if job.record.phase == ReplayJobPhase::Complete {
            return Ok(job);
        }
        let request_id = job.record.request.request_id.clone();
        self.execute_non_live(
            &request_id,
            &job.record.request.requested_by,
            window,
            cancellation,
        )
    }

    /// Runs one persisted observational replay through recorded-only providers.
    pub fn run_observational(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        window: ReplayExecutionWindow,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        let job = self.get(request_id, actor_id, cancellation)?;
        if job.record.request.mode != ReplayMode::Observational {
            return Err(invalid_input());
        }
        self.execute_non_live(request_id, actor_id, window, cancellation)
    }

    /// Runs one persisted live comparison after exact one-use authorization verification.
    pub fn compare_live(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        authorization: &LiveReplayAuthorization,
        window: ReplayExecutionWindow,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        let running = self.begin_execution(
            request_id,
            actor_id,
            ReplayMode::LiveComparison,
            &window,
            cancellation,
        )?;
        if running.record.phase == ReplayJobPhase::Complete {
            return Ok(running);
        }
        let result = self.engine.replay_live_with_context(
            &running.record.request,
            authorization,
            window.execution_id,
            window.started_at,
            window.completed_at,
            &self.context,
        );
        self.finish_engine_result(running, result, cancellation)
    }

    /// Returns one exact owner-visible job, existence-hiding all other scopes.
    pub fn get(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        let loaded = self.load(request_id, cancellation)?.ok_or_else(not_found)?;
        if &loaded.record.request.requested_by != actor_id {
            return Err(not_found());
        }
        Ok(loaded)
    }

    /// Marks every startup-observed running job interrupted; no partial execution becomes success.
    pub fn recover_interrupted(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<u64, ReplayJobError> {
        let scope = ServiceListScope::new(self.tenant_id.clone(), JOB_NAMESPACE, None)
            .map_err(map_store_error)?;
        let mut cursor = None;
        let mut recovered = 0_u64;
        loop {
            let page = self
                .repository
                .service_list(
                    &ServiceListQuery::new(scope.clone(), MAX_RECOVERY_PAGE, cursor)
                        .map_err(map_store_error)?,
                    cancellation,
                )
                .map_err(map_store_error)?;
            for item in page.items {
                let mut record = decode_record(&item)?;
                if record.phase == ReplayJobPhase::Running {
                    record.phase = ReplayJobPhase::Interrupted;
                    self.commit(
                        &record,
                        ServiceExpectedVersion::Version(item.version()),
                        cancellation,
                    )?;
                    recovered = recovered
                        .checked_add(1)
                        .ok_or_else(|| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
                }
            }
            cursor = page.next;
            if cursor.is_none() {
                return Ok(recovered);
            }
        }
    }

    fn create_record(
        &self,
        request: ReplayRequest,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        self.ensure_active(cancellation)?;
        request.validate().map_err(|_error| invalid_input())?;
        let inspection = self
            .engine
            .inspect_completeness_with_context(&request, &self.context)?;
        self.ensure_active(cancellation)?;
        let record = ReplayJobRecord::pending(
            request.clone(),
            inspection.completeness,
            inspection.missing_dependencies,
        );
        match self.commit(&record, ServiceExpectedVersion::Absent, cancellation) {
            Ok(version) => Ok(VersionedReplayJob { version, record }),
            Err(error) if error.code() == ReplayJobErrorCode::Conflict => {
                let existing = self
                    .load(&request.request_id, cancellation)?
                    .ok_or_else(|| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
                if existing.record.request == request {
                    Ok(existing)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn execute_non_live(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        window: ReplayExecutionWindow,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        let loaded = self.load(request_id, cancellation)?.ok_or_else(not_found)?;
        let mode = loaded.record.request.mode;
        if mode == ReplayMode::LiveComparison {
            return Err(invalid_input());
        }
        let running = self.begin_execution(request_id, actor_id, mode, &window, cancellation)?;
        if running.record.phase == ReplayJobPhase::Complete {
            return Ok(running);
        }
        let result = self.engine.replay_non_live_with_context(
            &running.record.request,
            window.execution_id,
            window.started_at,
            window.completed_at,
            &self.context,
        );
        self.finish_engine_result(running, result, cancellation)
    }

    fn begin_execution(
        &self,
        request_id: &RecordId,
        actor_id: &RecordId,
        expected_mode: ReplayMode,
        window: &ReplayExecutionWindow,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        let mut loaded = self.get(request_id, actor_id, cancellation)?;
        window.validate_for(&loaded.record.request)?;
        if loaded.record.request.mode != expected_mode {
            return Err(invalid_input());
        }
        if loaded.record.phase == ReplayJobPhase::Complete {
            return if loaded.record.execution_id.as_ref() == Some(&window.execution_id) {
                Ok(loaded)
            } else {
                Err(ReplayJobError::new(ReplayJobErrorCode::Conflict))
            };
        }
        if !matches!(
            loaded.record.phase,
            ReplayJobPhase::Pending | ReplayJobPhase::Interrupted | ReplayJobPhase::Failed
        ) {
            return Err(ReplayJobError::new(ReplayJobErrorCode::Conflict));
        }
        loaded.record.phase = ReplayJobPhase::Running;
        loaded.record.execution_id = Some(window.execution_id.clone());
        loaded.record.execution = None;
        loaded.record.diff = None;
        loaded.record.failure = None;
        loaded.record.external_calls = StoredReplayCounters::default();
        let version = self.commit(
            &loaded.record,
            ServiceExpectedVersion::Version(loaded.version),
            cancellation,
        )?;
        loaded.version = version;
        Ok(loaded)
    }

    fn finish_engine_result(
        &self,
        mut running: VersionedReplayJob,
        result: Result<ReplayResult, ReplayError>,
        cancellation: &CancellationToken,
    ) -> Result<VersionedReplayJob, ReplayJobError> {
        self.ensure_active(cancellation)?;
        match result {
            Ok(result) => {
                running.record.phase = ReplayJobPhase::Complete;
                running.record.completeness = result.execution.completeness.clone();
                running.record.execution = Some(result.execution);
                running.record.missing_dependencies = result.missing_dependencies;
                running.record.diff = result.diff;
                running.record.failure = None;
                running.record.external_calls = result.external_calls.into();
                running.record.validate()?;
                self.ensure_active(cancellation)?;
                running.version = self.commit(
                    &running.record,
                    ServiceExpectedVersion::Version(running.version),
                    cancellation,
                )?;
                Ok(running)
            }
            Err(error) => {
                running.record.phase = ReplayJobPhase::Failed;
                running.record.execution = None;
                running.record.diff = None;
                running.record.failure = Some(error.code().into());
                running.record.external_calls = self.engine.external_call_counters().into();
                running.record.validate()?;
                self.ensure_active(cancellation)?;
                let _version = self.commit(
                    &running.record,
                    ServiceExpectedVersion::Version(running.version),
                    cancellation,
                )?;
                Err(error.into())
            }
        }
    }

    fn load_live_draft(
        &self,
        request_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<Option<VersionedLiveReplayDraft>, ReplayJobError> {
        let locator = ServiceRecordLocator::new(
            self.tenant_id.clone(),
            LIVE_DRAFT_NAMESPACE,
            request_id.as_str(),
        )
        .map_err(map_store_error)?;
        self.repository
            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
            .map_err(map_store_error)?
            .map(|item| {
                let record = decode_live_draft(&item)?;
                if record.request_id != *request_id {
                    return Err(ReplayJobError::new(ReplayJobErrorCode::Unavailable));
                }
                Ok(VersionedLiveReplayDraft {
                    version: item.version(),
                    record,
                })
            })
            .transpose()
    }

    fn commit_live_draft(
        &self,
        record: &LiveReplayDraftRecord,
        expected: ServiceExpectedVersion,
        cancellation: &CancellationToken,
    ) -> Result<u64, ReplayJobError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record)
            .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
        let write = ServiceRecordWrite::new(
            LIVE_DRAFT_NAMESPACE,
            record.request_id.as_str(),
            expected,
            bytes,
        )
        .map_err(map_store_error)?;
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_store_error)?;
        let batch = ServiceBatch::new(self.tenant_id.clone(), vec![write], response)
            .map_err(map_store_error)?;
        let receipt = self
            .repository
            .service_commit(batch, cancellation)
            .map_err(map_store_error)?;
        receipt
            .records
            .first()
            .map(|record| record.version)
            .ok_or_else(|| ReplayJobError::new(ReplayJobErrorCode::Unavailable))
    }

    fn commit_live_binding(
        &self,
        job: &ReplayJobRecord,
        draft: &LiveReplayDraftRecord,
        draft_version: u64,
        cancellation: &CancellationToken,
    ) -> Result<u64, ReplayJobError> {
        job.validate()?;
        draft.validate()?;
        let job_bytes = serde_json::to_vec(job)
            .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
        let draft_bytes = serde_json::to_vec(draft)
            .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
        let writes = vec![
            ServiceRecordWrite::new(
                JOB_NAMESPACE,
                job.request.request_id.as_str(),
                ServiceExpectedVersion::Absent,
                job_bytes,
            )
            .map_err(map_store_error)?,
            ServiceRecordWrite::new(
                LIVE_DRAFT_NAMESPACE,
                draft.request_id.as_str(),
                ServiceExpectedVersion::Version(draft_version),
                draft_bytes,
            )
            .map_err(map_store_error)?,
        ];
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_store_error)?;
        let batch =
            ServiceBatch::new(self.tenant_id.clone(), writes, response).map_err(map_store_error)?;
        let receipt = self
            .repository
            .service_commit(batch, cancellation)
            .map_err(map_store_error)?;
        receipt
            .records
            .iter()
            .find(|record| {
                record.namespace == JOB_NAMESPACE && record.key == job.request.request_id.as_str()
            })
            .map(|record| record.version)
            .ok_or_else(|| ReplayJobError::new(ReplayJobErrorCode::Unavailable))
    }

    fn load(
        &self,
        request_id: &RecordId,
        cancellation: &CancellationToken,
    ) -> Result<Option<VersionedReplayJob>, ReplayJobError> {
        let locator =
            ServiceRecordLocator::new(self.tenant_id.clone(), JOB_NAMESPACE, request_id.as_str())
                .map_err(map_store_error)?;
        self.repository
            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
            .map_err(map_store_error)?
            .map(|item| {
                let record = decode_record(&item)?;
                if record.request.request_id != *request_id {
                    return Err(ReplayJobError::new(ReplayJobErrorCode::Unavailable));
                }
                Ok(VersionedReplayJob {
                    version: item.version(),
                    record,
                })
            })
            .transpose()
    }

    fn commit(
        &self,
        record: &ReplayJobRecord,
        expected: ServiceExpectedVersion,
        cancellation: &CancellationToken,
    ) -> Result<u64, ReplayJobError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record)
            .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
        let write = ServiceRecordWrite::new(
            JOB_NAMESPACE,
            record.request.request_id.as_str(),
            expected,
            bytes,
        )
        .map_err(map_store_error)?;
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_store_error)?;
        let batch = ServiceBatch::new(self.tenant_id.clone(), vec![write], response)
            .map_err(map_store_error)?;
        let receipt = self
            .repository
            .service_commit(batch, cancellation)
            .map_err(map_store_error)?;
        receipt
            .records
            .first()
            .map(|record| record.version)
            .ok_or_else(|| ReplayJobError::new(ReplayJobErrorCode::Unavailable))
    }
}

impl fmt::Debug for DurableReplayJobService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableReplayJobService")
            .field("tenant", &"[BOUND]")
            .field("engine", &self.engine)
            .finish_non_exhaustive()
    }
}

fn decode_record(item: &ServiceRecord) -> Result<ReplayJobRecord, ReplayJobError> {
    parse_strict_json(item.bytes())
        .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
    let record: ReplayJobRecord = serde_json::from_slice(item.bytes())
        .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
    record.validate()?;
    Ok(record)
}

fn decode_live_draft(item: &ServiceRecord) -> Result<LiveReplayDraftRecord, ReplayJobError> {
    parse_strict_json(item.bytes())
        .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
    let record: LiveReplayDraftRecord = serde_json::from_slice(item.bytes())
        .map_err(|_error| ReplayJobError::new(ReplayJobErrorCode::Unavailable))?;
    record.validate()?;
    Ok(record)
}

fn missing_rows_are_canonical(rows: &[MissingDependencyRow]) -> bool {
    rows.len() <= MAX_REPLAY_REFERENCES
        && rows.windows(2).all(|window| {
            window
                .first()
                .zip(window.get(1))
                .is_some_and(|(left, right)| {
                    (&left.kind, &left.role, &left.content_digest)
                        < (&right.kind, &right.role, &right.content_digest)
                })
        })
}

fn completeness_is_canonical(completeness: &ReplayCompleteness) -> bool {
    completeness.available.len() <= MAX_REPLAY_REFERENCES
        && completeness.missing.len() <= MAX_REPLAY_REFERENCES
        && completeness.available.windows(2).all(|window| {
            window
                .first()
                .zip(window.get(1))
                .is_some_and(|(left, right)| left < right)
        })
        && completeness.missing.windows(2).all(|window| {
            window
                .first()
                .zip(window.get(1))
                .is_some_and(|(left, right)| left < right)
        })
        && completeness
            .available
            .iter()
            .all(|dependency| completeness.missing.binary_search(dependency).is_err())
}

fn map_store_error(error: ServiceError) -> ReplayJobError {
    let code = match error.code() {
        ServiceErrorCode::RevisionConflict | ServiceErrorCode::IdempotencyConflict => {
            ReplayJobErrorCode::Conflict
        }
        ServiceErrorCode::NotFound => ReplayJobErrorCode::NotFound,
        ServiceErrorCode::Cancelled => ReplayJobErrorCode::Cancelled,
        ServiceErrorCode::InvalidInput
        | ServiceErrorCode::LimitExceeded
        | ServiceErrorCode::CursorScopeMismatch
        | ServiceErrorCode::InjectedAbort
        | ServiceErrorCode::Unavailable => ReplayJobErrorCode::Unavailable,
    };
    ReplayJobError::new(code)
}

const fn invalid_input() -> ReplayJobError {
    ReplayJobError::new(ReplayJobErrorCode::InvalidInput)
}

const fn not_found() -> ReplayJobError {
    ReplayJobError::new(ReplayJobErrorCode::NotFound)
}

#[cfg(test)]
mod tests {
    use super::{
        DurableReplayJobService, LiveReplayDraftPhase, ReplayExecutionWindow, ReplayJobErrorCode,
        ReplayJobPhase,
    };
    use crate::DurableReplayArchive;
    use crate::durable_replay::tests::capture_fixture;
    use cigar_protocol::{
        ContentDigest, RecordId, ReplayMode, ReplayRequest, ReplayStatus, SchemaVersion,
        UtcTimestamp, VersionId,
    };
    use cigar_replay::{LiveReplayAuthorization, ReplayArchive, ReplayEngine, ReplayErrorCode};
    use cigar_store::{CancellationToken, InMemoryStore, ServiceRepository, SqliteStore};
    use std::error::Error;
    use std::sync::{Arc, Barrier};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn record(value: u64) -> TestResult<RecordId> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn time(second: u8) -> TestResult<UtcTimestamp> {
        Ok(UtcTimestamp::parse_rfc3339(&format!(
            "2026-07-11T12:00:{second:02}Z"
        ))?)
    }

    fn digest(value: char) -> TestResult<ContentDigest> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            value.to_string().repeat(64)
        ))?)
    }

    fn request(
        decision_id: VersionId,
        request_id: RecordId,
        requested_by: RecordId,
        mode: ReplayMode,
    ) -> TestResult<ReplayRequest> {
        Ok(ReplayRequest {
            schema_version: SchemaVersion::new("cigar.replay-request", 1)?,
            request_id,
            decision_id,
            mode,
            requested_by,
            live_authorization_digest: None,
            simulate_effects: true,
            authorized_effect_intents: Vec::new(),
        })
    }

    fn seed_engine(
        repository: Arc<dyn ServiceRepository>,
        tenant_id: RecordId,
    ) -> TestResult<(VersionId, Arc<ReplayEngine>)> {
        let capture = capture_fixture()?;
        let decision_id = capture.archive.decision.decision_id.clone();
        let archive = Arc::new(DurableReplayArchive::new(repository, tenant_id));
        archive.put_capture(&capture)?;
        Ok((decision_id, Arc::new(ReplayEngine::new(archive))))
    }

    #[test]
    fn completed_job_is_idempotent_owner_scoped_and_survives_sqlite_restart() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("replay-jobs.sqlite3");
        let tenant_id = record(1)?;
        let actor_id = record(2)?;
        let request_id = record(3)?;
        let execution_id = record(4)?;
        let window = ReplayExecutionWindow {
            execution_id,
            started_at: time(10)?,
            completed_at: time(11)?,
        };

        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let (decision_id, engine) = seed_engine(Arc::clone(&repository), tenant_id.clone())?;
            let service = DurableReplayJobService::new(repository, tenant_id.clone(), engine);
            let replay_request = request(
                decision_id,
                request_id.clone(),
                actor_id.clone(),
                ReplayMode::EvidenceReproduction,
            )?;
            let completed = service.create_and_reconstruct(
                replay_request.clone(),
                window.clone(),
                &CancellationToken::default(),
            )?;
            assert_eq!(completed.record.phase, ReplayJobPhase::Complete);
            assert_eq!(
                completed
                    .record
                    .execution
                    .as_ref()
                    .map(|value| value.status),
                Some(ReplayStatus::Complete)
            );

            let repeated = service.create_and_reconstruct(
                replay_request,
                window.clone(),
                &CancellationToken::default(),
            )?;
            assert_eq!(repeated, completed);
            let hidden = match service.get(&request_id, &record(99)?, &CancellationToken::default())
            {
                Err(error) => error,
                Ok(_job) => {
                    return Err(std::io::Error::other(
                        "another actor learned that the replay job exists",
                    )
                    .into());
                }
            };
            assert_eq!(hidden.code(), ReplayJobErrorCode::NotFound);
        }

        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let archive = Arc::new(DurableReplayArchive::new(
            Arc::clone(&repository),
            tenant_id.clone(),
        ));
        let service = DurableReplayJobService::new(
            repository,
            tenant_id,
            Arc::new(ReplayEngine::new(archive)),
        );
        let reopened = service.get(&request_id, &actor_id, &CancellationToken::default())?;
        assert_eq!(reopened.record.phase, ReplayJobPhase::Complete);
        assert_eq!(reopened.record.execution_id, Some(window.execution_id));
        Ok(())
    }

    #[test]
    fn startup_marks_running_jobs_interrupted_and_allows_a_new_attempt() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("interrupted-replay.sqlite3");
        let tenant_id = record(10)?;
        let actor_id = record(11)?;
        let request_id = record(12)?;

        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let (decision_id, engine) = seed_engine(Arc::clone(&repository), tenant_id.clone())?;
            let service = DurableReplayJobService::new(repository, tenant_id.clone(), engine);
            service.create_pending(
                request(
                    decision_id,
                    request_id.clone(),
                    actor_id.clone(),
                    ReplayMode::Observational,
                )?,
                &CancellationToken::default(),
            )?;
            let running = service.begin_execution(
                &request_id,
                &actor_id,
                ReplayMode::Observational,
                &ReplayExecutionWindow {
                    execution_id: record(13)?,
                    started_at: time(12)?,
                    completed_at: time(13)?,
                },
                &CancellationToken::default(),
            )?;
            assert_eq!(running.record.phase, ReplayJobPhase::Running);
        }

        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let archive = Arc::new(DurableReplayArchive::new(
            Arc::clone(&repository),
            tenant_id.clone(),
        ));
        let service = DurableReplayJobService::new(
            repository,
            tenant_id,
            Arc::new(ReplayEngine::new(archive)),
        );
        assert_eq!(
            service.recover_interrupted(&CancellationToken::default())?,
            1
        );
        assert_eq!(
            service
                .get(&request_id, &actor_id, &CancellationToken::default())?
                .record
                .phase,
            ReplayJobPhase::Interrupted
        );
        let completed = service.run_observational(
            &request_id,
            &actor_id,
            ReplayExecutionWindow {
                execution_id: record(14)?,
                started_at: time(14)?,
                completed_at: time(15)?,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(completed.record.phase, ReplayJobPhase::Complete);
        Ok(())
    }

    #[test]
    fn concurrent_execution_reservation_has_exactly_one_winner() -> TestResult {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let tenant_id = record(20)?;
        let actor_id = record(21)?;
        let request_id = record(22)?;
        let (decision_id, engine) = seed_engine(Arc::clone(&repository), tenant_id.clone())?;
        let service = Arc::new(DurableReplayJobService::new(repository, tenant_id, engine));
        service.create_pending(
            request(
                decision_id,
                request_id.clone(),
                actor_id.clone(),
                ReplayMode::Observational,
            )?,
            &CancellationToken::default(),
        )?;

        let worker_count = 12;
        let barrier = Arc::new(Barrier::new(worker_count));
        let mut workers = Vec::new();
        for _worker in 0..worker_count {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            let request_id = request_id.clone();
            let actor_id = actor_id.clone();
            let window = ReplayExecutionWindow {
                execution_id: record(23)?,
                started_at: time(16)?,
                completed_at: time(17)?,
            };
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                service.begin_execution(
                    &request_id,
                    &actor_id,
                    ReplayMode::Observational,
                    &window,
                    &CancellationToken::default(),
                )
            }));
        }

        let mut winners = 0_usize;
        for worker in workers {
            match worker.join().map_err(|_panic| "replay worker panicked")? {
                Ok(job) => {
                    assert_eq!(job.record.phase, ReplayJobPhase::Running);
                    winners = winners.checked_add(1).ok_or("winner count overflow")?;
                }
                Err(error) => assert_eq!(error.code(), ReplayJobErrorCode::Conflict),
            }
        }
        assert_eq!(winners, 1);
        Ok(())
    }

    #[test]
    fn live_draft_binds_once_before_a_denied_live_boundary_and_survives_restart() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("live-draft.sqlite3");
        let tenant_id = record(30)?;
        let actor_id = record(31)?;
        let request_id = record(32)?;
        let decision_id;
        let authorization = {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let seeded = seed_engine(Arc::clone(&repository), tenant_id.clone())?;
            decision_id = seeded.0.clone();
            let service = DurableReplayJobService::new(repository, tenant_id.clone(), seeded.1);
            let draft = service.create_live_draft(
                request_id.clone(),
                decision_id.clone(),
                actor_id.clone(),
                true,
                &CancellationToken::default(),
            )?;
            assert_eq!(draft.record.phase, LiveReplayDraftPhase::Unbound);
            assert!(draft.record.completeness.missing.is_empty());
            LiveReplayAuthorization {
                schema_version: SchemaVersion::new("cigar.live-replay-authorization", 1)?,
                authorization_digest: digest('a')?,
                nonce: record(33)?,
                request_id: request_id.clone(),
                decision_id: decision_id.clone(),
                requested_by: actor_id.clone(),
                authorized_effect_intents: Vec::new(),
                not_before: time(1)?,
                expires_at: time(50)?,
                policy_snapshot_digest: digest('b')?,
            }
        };

        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let archive = Arc::new(DurableReplayArchive::new(
            Arc::clone(&repository),
            tenant_id.clone(),
        ));
        let service = DurableReplayJobService::new(
            repository,
            tenant_id,
            Arc::new(ReplayEngine::new(archive)),
        );
        let window = ReplayExecutionWindow {
            execution_id: record(34)?,
            started_at: time(20)?,
            completed_at: time(21)?,
        };
        let failure = service
            .bind_and_compare_live(
                &request_id,
                &actor_id,
                &authorization,
                window.clone(),
                &CancellationToken::default(),
            )
            .err()
            .ok_or("denied live verifier unexpectedly allowed execution")?;
        assert_eq!(
            failure.code(),
            ReplayJobErrorCode::Replay(ReplayErrorCode::LiveAuthorizationInvalid)
        );
        assert_eq!(
            service
                .get(&request_id, &actor_id, &CancellationToken::default())?
                .record
                .phase,
            ReplayJobPhase::Failed
        );
        assert!(matches!(
            service
                .get_live_draft(&request_id, &actor_id, &CancellationToken::default())?
                .record
                .phase,
            LiveReplayDraftPhase::Bound { execution_id, .. } if execution_id == window.execution_id
        ));
        let second = service.bind_and_compare_live(
            &request_id,
            &actor_id,
            &authorization,
            ReplayExecutionWindow {
                execution_id: record(35)?,
                started_at: time(22)?,
                completed_at: time(23)?,
            },
            &CancellationToken::default(),
        );
        assert_eq!(
            second.map_err(|error| error.code()),
            Err(ReplayJobErrorCode::Conflict)
        );
        Ok(())
    }
}
