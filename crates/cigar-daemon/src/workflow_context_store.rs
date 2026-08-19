//! Tenant-partitioned durable identity checkpoints for workflow context sessions.

use crate::CatalogContextAuthorization;
use crate::workflow_context_session::{WorkflowContextSession, WorkflowResumeAction};
use cigar_canon::parse_strict_json;
use cigar_protocol::{
    Classification, ContentDigest, ContextContract, InstructionAuthority, RecordId, Validate,
    limits::MAX_PURPOSE_BYTES, limits::MAX_SCOPE_PROJECTS,
};
use cigar_store::{
    CancellationToken, ServiceBatch, ServiceError, ServiceErrorCode, ServiceExpectedVersion,
    ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite,
    ServiceRepository, ServiceResponse,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

const SESSION_NAMESPACE: &str = "context.workflow-session.v1";
const SESSION_SCHEMA: &str = "cigar.workflow-context-checkpoint.v1";
const MAX_PROCESSOR_BYTES: usize = 256;

/// Stable, content-free failure category for durable workflow identity checkpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowContextStoreErrorCode {
    InvalidScope,
    ScopeMismatch,
    NotFound,
    RevisionConflict,
    IntegrityFailure,
    LimitExceeded,
    Cancelled,
    Unavailable,
}

/// Content-safe durable workflow checkpoint failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct WorkflowContextStoreError {
    code: WorkflowContextStoreErrorCode,
}

impl WorkflowContextStoreError {
    const fn new(code: WorkflowContextStoreErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> WorkflowContextStoreErrorCode {
        self.code
    }
}

impl fmt::Debug for WorkflowContextStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowContextStoreError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for WorkflowContextStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "durable workflow context operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for WorkflowContextStoreError {}

/// Exact governance partition inherited from the active retained bundle.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkflowContextScope {
    tenant_id: RecordId,
    project_ids: Vec<RecordId>,
    purpose: String,
    processor: String,
    maximum_classification: Classification,
    maximum_instruction_authority: InstructionAuthority,
    policy_digest: ContentDigest,
}

impl WorkflowContextScope {
    /// Derives a checkpoint partition only from the normalized bundle contract and trusted current
    /// authorization. Caller-authored replacement scope values are never accepted independently.
    pub(crate) fn for_contract(
        tenant_id: RecordId,
        contract: &ContextContract,
        authorization: &CatalogContextAuthorization,
    ) -> Result<Self, WorkflowContextStoreError> {
        contract.validate().map_err(|_error| invalid_scope())?;
        let authorized_projects: Vec<_> = authorization.project_ids.iter().cloned().collect();
        if contract.project_ids != authorized_projects || contract.purpose != authorization.purpose
        {
            return Err(WorkflowContextStoreError::new(
                WorkflowContextStoreErrorCode::ScopeMismatch,
            ));
        }
        let scope = Self {
            tenant_id,
            project_ids: authorized_projects,
            purpose: authorization.purpose.clone(),
            processor: authorization.processor.clone(),
            maximum_classification: authorization.maximum_classification,
            maximum_instruction_authority: authorization.maximum_instruction_authority,
            policy_digest: authorization.policy_digest.clone(),
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), WorkflowContextStoreError> {
        if self.project_ids.is_empty()
            || self.project_ids.len() > MAX_SCOPE_PROJECTS
            || self
                .project_ids
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left >= right))
            || self.purpose.is_empty()
            || self.purpose.len() > MAX_PURPOSE_BYTES
            || self.processor.is_empty()
            || self.processor.len() > MAX_PROCESSOR_BYTES
            || self
                .purpose
                .bytes()
                .chain(self.processor.bytes())
                .any(|byte| byte.is_ascii_control())
        {
            Err(invalid_scope())
        } else {
            Ok(())
        }
    }

    const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }
}

impl fmt::Debug for WorkflowContextScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowContextScope")
            .field("tenant_scope", &"[BOUND]")
            .field("project_count", &self.project_ids.len())
            .field("purpose_bytes", &self.purpose.len())
            .field("processor_bytes", &self.processor.len())
            .field("maximum_classification", &self.maximum_classification)
            .field(
                "maximum_instruction_authority",
                &self.maximum_instruction_authority,
            )
            .field("policy_bound", &true)
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableWorkflowContext {
    schema_version: String,
    workflow_id: RecordId,
    scope: WorkflowContextScope,
    session: WorkflowContextSession,
}

impl DurableWorkflowContext {
    fn new(
        workflow_id: RecordId,
        scope: WorkflowContextScope,
        session: WorkflowContextSession,
    ) -> Result<Self, WorkflowContextStoreError> {
        scope.validate()?;
        session
            .validate_restored()
            .map_err(|_error| integrity_failure())?;
        Ok(Self {
            schema_version: SESSION_SCHEMA.to_owned(),
            workflow_id,
            scope,
            session,
        })
    }

    fn validate(
        &self,
        workflow_id: &RecordId,
        scope: &WorkflowContextScope,
    ) -> Result<(), WorkflowContextStoreError> {
        self.scope
            .validate()
            .map_err(|_error| integrity_failure())?;
        if self.schema_version != SESSION_SCHEMA || self.workflow_id != *workflow_id {
            return Err(integrity_failure());
        }
        if self.scope != *scope {
            return Err(WorkflowContextStoreError::new(
                WorkflowContextStoreErrorCode::ScopeMismatch,
            ));
        }
        self.session
            .validate_restored()
            .map_err(|_error| integrity_failure())
    }
}

/// Exact immutable checkpoint loaded from one logical workflow record.
pub(crate) struct LoadedWorkflowContext {
    session: WorkflowContextSession,
    version: u64,
    digest: ContentDigest,
}

impl LoadedWorkflowContext {
    pub(crate) const fn session(&self) -> &WorkflowContextSession {
        &self.session
    }

    pub(crate) const fn version(&self) -> u64 {
        self.version
    }

    pub(crate) const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Exact content-free operation or local boundary to resume after a crash.
    pub(crate) const fn resume_action(&self) -> WorkflowResumeAction {
        self.session.resume_action()
    }
}

impl fmt::Debug for LoadedWorkflowContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedWorkflowContext")
            .field("session", &self.session)
            .field("version", &self.version)
            .field("digest", &self.digest)
            .finish()
    }
}

/// CAS-protected workflow checkpoint repository over the production service store.
pub(crate) struct WorkflowContextStore {
    repository: Arc<dyn ServiceRepository>,
}

impl WorkflowContextStore {
    pub(crate) fn new(repository: Arc<dyn ServiceRepository>) -> Self {
        Self { repository }
    }

    /// Creates the first immutable identity-only checkpoint.
    pub(crate) fn create(
        &self,
        workflow_id: RecordId,
        scope: WorkflowContextScope,
        session: WorkflowContextSession,
        cancellation: &CancellationToken,
    ) -> Result<LoadedWorkflowContext, WorkflowContextStoreError> {
        let durable = DurableWorkflowContext::new(workflow_id.clone(), scope, session)?;
        self.commit(
            &workflow_id,
            durable,
            ServiceExpectedVersion::Absent,
            cancellation,
        )
    }

    /// Replaces one exact current logical version. A stale writer cannot overwrite recovery state.
    pub(crate) fn save(
        &self,
        workflow_id: &RecordId,
        scope: &WorkflowContextScope,
        expected_version: u64,
        session: WorkflowContextSession,
        cancellation: &CancellationToken,
    ) -> Result<LoadedWorkflowContext, WorkflowContextStoreError> {
        if expected_version == 0 {
            return Err(WorkflowContextStoreError::new(
                WorkflowContextStoreErrorCode::RevisionConflict,
            ));
        }
        let current = self.load(workflow_id, scope, cancellation)?;
        if current.version != expected_version {
            return Err(WorkflowContextStoreError::new(
                WorkflowContextStoreErrorCode::RevisionConflict,
            ));
        }
        let durable = DurableWorkflowContext::new(workflow_id.clone(), scope.clone(), session)?;
        self.commit(
            workflow_id,
            durable,
            ServiceExpectedVersion::Version(expected_version),
            cancellation,
        )
    }

    /// Checkpoints one transition with lost-response idempotency.
    ///
    /// Repeating an already committed exact session returns the current version and digest without
    /// another write. A stale request carrying different state remains a revision conflict.
    pub(crate) fn checkpoint_transition(
        &self,
        workflow_id: &RecordId,
        scope: &WorkflowContextScope,
        expected_version: u64,
        session: WorkflowContextSession,
        cancellation: &CancellationToken,
    ) -> Result<LoadedWorkflowContext, WorkflowContextStoreError> {
        if expected_version == 0 {
            return Err(WorkflowContextStoreError::new(
                WorkflowContextStoreErrorCode::RevisionConflict,
            ));
        }
        let durable = DurableWorkflowContext::new(workflow_id.clone(), scope.clone(), session)?;
        let current = self.load(workflow_id, scope, cancellation)?;
        let immediately_preceding = expected_version
            .checked_add(1)
            .is_some_and(|version| version == current.version);
        if current.session == durable.session
            && (current.version == expected_version || immediately_preceding)
        {
            return Ok(current);
        }
        if current.version != expected_version {
            return Err(WorkflowContextStoreError::new(
                WorkflowContextStoreErrorCode::RevisionConflict,
            ));
        }
        self.commit(
            workflow_id,
            durable,
            ServiceExpectedVersion::Version(expected_version),
            cancellation,
        )
    }

    /// Loads only after exact tenant, project, purpose, classification, and policy equality.
    pub(crate) fn load(
        &self,
        workflow_id: &RecordId,
        scope: &WorkflowContextScope,
        cancellation: &CancellationToken,
    ) -> Result<LoadedWorkflowContext, WorkflowContextStoreError> {
        scope.validate()?;
        let locator = ServiceRecordLocator::new(
            scope.tenant_id().clone(),
            SESSION_NAMESPACE,
            workflow_id.as_str(),
        )
        .map_err(map_service_error)?;
        let record = self
            .repository
            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
            .map_err(map_service_error)?
            .ok_or_else(not_found)?;
        decode_record(record, workflow_id, scope)
    }

    fn commit(
        &self,
        workflow_id: &RecordId,
        durable: DurableWorkflowContext,
        expected: ServiceExpectedVersion,
        cancellation: &CancellationToken,
    ) -> Result<LoadedWorkflowContext, WorkflowContextStoreError> {
        durable.validate(workflow_id, &durable.scope)?;
        let bytes = serde_json::to_vec(&durable).map_err(|_error| integrity_failure())?;
        let write =
            ServiceRecordWrite::new(SESSION_NAMESPACE, workflow_id.as_str(), expected, bytes)
                .map_err(map_service_error)?;
        let response = ServiceResponse::new(204, "application/octet-stream", Vec::new())
            .map_err(map_service_error)?;
        let batch = ServiceBatch::new(durable.scope.tenant_id().clone(), vec![write], response)
            .map_err(map_service_error)?;
        let receipt = self
            .repository
            .service_commit(batch, cancellation)
            .map_err(map_service_error)?;
        let [record] = receipt.records.as_slice() else {
            return Err(integrity_failure());
        };
        if record.namespace != SESSION_NAMESPACE || record.key != workflow_id.as_str() {
            return Err(integrity_failure());
        }
        Ok(LoadedWorkflowContext {
            session: durable.session,
            version: record.version,
            digest: record.digest.clone(),
        })
    }
}

impl fmt::Debug for WorkflowContextStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowContextStore")
            .field("repository", &"[INJECTED]")
            .finish()
    }
}

fn decode_record(
    record: ServiceRecord,
    workflow_id: &RecordId,
    scope: &WorkflowContextScope,
) -> Result<LoadedWorkflowContext, WorkflowContextStoreError> {
    parse_strict_json(record.bytes()).map_err(|_error| integrity_failure())?;
    let durable: DurableWorkflowContext =
        serde_json::from_slice(record.bytes()).map_err(|_error| integrity_failure())?;
    durable.validate(workflow_id, scope)?;
    Ok(LoadedWorkflowContext {
        session: durable.session,
        version: record.version(),
        digest: record.digest().clone(),
    })
}

fn map_service_error(error: ServiceError) -> WorkflowContextStoreError {
    let code = match error.code() {
        ServiceErrorCode::InvalidInput => WorkflowContextStoreErrorCode::IntegrityFailure,
        ServiceErrorCode::NotFound => WorkflowContextStoreErrorCode::NotFound,
        ServiceErrorCode::RevisionConflict | ServiceErrorCode::IdempotencyConflict => {
            WorkflowContextStoreErrorCode::RevisionConflict
        }
        ServiceErrorCode::CursorScopeMismatch => WorkflowContextStoreErrorCode::ScopeMismatch,
        ServiceErrorCode::LimitExceeded => WorkflowContextStoreErrorCode::LimitExceeded,
        ServiceErrorCode::Cancelled => WorkflowContextStoreErrorCode::Cancelled,
        ServiceErrorCode::InjectedAbort | ServiceErrorCode::Unavailable => {
            WorkflowContextStoreErrorCode::Unavailable
        }
    };
    WorkflowContextStoreError::new(code)
}

const fn invalid_scope() -> WorkflowContextStoreError {
    WorkflowContextStoreError::new(WorkflowContextStoreErrorCode::InvalidScope)
}

const fn integrity_failure() -> WorkflowContextStoreError {
    WorkflowContextStoreError::new(WorkflowContextStoreErrorCode::IntegrityFailure)
}

const fn not_found() -> WorkflowContextStoreError {
    WorkflowContextStoreError::new(WorkflowContextStoreErrorCode::NotFound)
}

#[cfg(test)]
mod tests {
    use super::{
        SESSION_NAMESPACE, WorkflowContextScope, WorkflowContextStore,
        WorkflowContextStoreErrorCode,
    };
    use crate::workflow_context_session::{
        WorkflowContextPhase, WorkflowContextSession, WorkflowResumeAction,
    };
    use cigar_api::{
        ContextDeltaResponse, ContextPlanResponse, EffectStatusResponse, MaterializationResponse,
        RevalidationResponse,
    };
    use cigar_compiler::{apply_delta_verified, generate_delta};
    use cigar_protocol::{
        CandidateDisposition, Classification, ContentDigest, ContextBlock, ContextBundle,
        ContextPlan, EffectState, ExtensionMap, FixedPoint, LaneKind, MaterializedContext,
        MediaType, PlanLane, RecordId, RepresentationKind, SchemaVersion, Validate, VersionId,
    };
    use cigar_store::{
        CancellationToken, InMemoryStore, ServiceRecordLocator, ServiceRecordSelection,
        ServiceRepository,
    };
    use std::error::Error;
    use std::sync::Arc;

    fn record(suffix: u8) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f78{suffix:02x}"
        ))?)
    }

    fn digest(character: char) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn version(character: char) -> Result<VersionId, Box<dyn Error>> {
        Ok(VersionId::new(digest(character)?.as_str())?)
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
            attempt_count: u32::from(matches!(
                state,
                EffectState::Dispatching | EffectState::Unknown
            )),
            reconciliation_count: 0,
        }
    }

    fn persist_and_recover(
        store: &WorkflowContextStore,
        workflow_id: &RecordId,
        scope: &WorkflowContextScope,
        expected_version: u64,
        session: &WorkflowContextSession,
        action: WorkflowResumeAction,
        cancellation: &CancellationToken,
    ) -> Result<u64, Box<dyn Error>> {
        let committed = store.checkpoint_transition(
            workflow_id,
            scope,
            expected_version,
            session.clone(),
            cancellation,
        )?;
        assert_eq!(committed.resume_action(), action);
        let replayed = store.checkpoint_transition(
            workflow_id,
            scope,
            expected_version,
            session.clone(),
            cancellation,
        )?;
        assert_eq!(replayed.version(), committed.version());
        assert_eq!(replayed.digest(), committed.digest());
        let impossible_future = committed
            .version()
            .checked_add(10)
            .ok_or("fixture version overflow")?;
        let Err(impossible) = store.checkpoint_transition(
            workflow_id,
            scope,
            impossible_future,
            session.clone(),
            cancellation,
        ) else {
            return Err("future checkpoint version unexpectedly replayed".into());
        };
        assert_eq!(
            impossible.code(),
            WorkflowContextStoreErrorCode::RevisionConflict
        );
        let recovered = store.load(workflow_id, scope, cancellation)?;
        assert_eq!(recovered.session(), session);
        assert_eq!(recovered.resume_action(), action);
        Ok(recovered.version())
    }

    fn scope(
        tenant: RecordId,
        project: RecordId,
        purpose: &str,
        classification: Classification,
        policy: char,
    ) -> Result<WorkflowContextScope, Box<dyn Error>> {
        let scope = WorkflowContextScope {
            tenant_id: tenant,
            project_ids: vec![project],
            purpose: purpose.to_owned(),
            processor: "local".to_owned(),
            maximum_classification: classification,
            maximum_instruction_authority: cigar_protocol::InstructionAuthority::Project,
            policy_digest: digest(policy)?,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[test]
    fn checkpoint_round_trip_is_cas_versioned_and_identity_only() -> Result<(), Box<dyn Error>> {
        let repository = Arc::new(InMemoryStore::default());
        let service: Arc<dyn ServiceRepository> = repository.clone();
        let store = WorkflowContextStore::new(service);
        let tenant = record(1)?;
        let workflow_id = record(2)?;
        let scope = scope(
            tenant.clone(),
            record(3)?,
            "coding",
            Classification::Confidential,
            '3',
        )?;
        let cancellation = CancellationToken::default();
        let created = store.create(
            workflow_id.clone(),
            scope.clone(),
            WorkflowContextSession::new(),
            &cancellation,
        )?;
        assert_eq!(created.version(), 1);
        assert_eq!(created.session().phase(), WorkflowContextPhase::New);
        assert!(!created.digest().as_str().is_empty());
        let loaded = store.load(&workflow_id, &scope, &cancellation)?;
        assert_eq!(loaded.version(), created.version());
        assert_eq!(loaded.session(), created.session());
        let saved = store.save(
            &workflow_id,
            &scope,
            loaded.version(),
            loaded.session().clone(),
            &cancellation,
        )?;
        assert_eq!(saved.version(), 2);
        let Err(stale) = store.save(
            &workflow_id,
            &scope,
            loaded.version(),
            loaded.session().clone(),
            &cancellation,
        ) else {
            return Err("stale checkpoint unexpectedly overwrote the current version".into());
        };
        assert_eq!(
            stale.code(),
            WorkflowContextStoreErrorCode::RevisionConflict
        );

        let locator = ServiceRecordLocator::new(tenant, SESSION_NAMESPACE, workflow_id.as_str())?;
        let record = repository
            .service_get(&locator, ServiceRecordSelection::Latest, &cancellation)?
            .ok_or("missing durable workflow checkpoint")?;
        let text = std::str::from_utf8(record.bytes())?;
        for forbidden in [
            "source_text",
            "prompt",
            "model_output",
            "materialized_bytes",
            "tool_arguments",
            "workflow-content-canary",
        ] {
            assert!(!text.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn every_durable_boundary_recovers_one_idempotent_exact_action() -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let store = WorkflowContextStore::new(repository);
        let workflow_id = record(22)?;
        let scope = scope(
            record(21)?,
            record(23)?,
            "workflow-recovery",
            Classification::Confidential,
            '3',
        )?;
        let cancellation = CancellationToken::default();
        let mut session = WorkflowContextSession::new();
        let created = store.create(
            workflow_id.clone(),
            scope.clone(),
            session.clone(),
            &cancellation,
        )?;
        let initial = bundle('a', '1', '2')?;
        let target = bundle('b', '2', '3')?;

        session.record_plan_created(&plan_response(24, &initial)?)?;
        session.record_bundle_compiled(&initial)?;
        session.record_materialized(&materialization(&initial)?)?;
        let mut version = persist_and_recover(
            &store,
            &workflow_id,
            &scope,
            created.version(),
            &session,
            WorkflowResumeAction::BeginModelInvocation,
            &cancellation,
        )?;

        let invocation_id = record(25)?;
        session.begin_model_invocation(invocation_id.clone(), digest('4')?, digest('8')?)?;
        session.record_model_result(&invocation_id, digest('5')?)?;
        version = persist_and_recover(
            &store,
            &workflow_id,
            &scope,
            version,
            &session,
            WorkflowResumeAction::PrepareEffectOrIngestObservation,
            &cancellation,
        )?;

        let effect_id = record(26)?;
        let intent_digest = digest('6')?;
        session.record_effect_prepared(&effect(
            &effect_id,
            &intent_digest,
            1,
            EffectState::Prepared,
        ))?;
        version = persist_and_recover(
            &store,
            &workflow_id,
            &scope,
            version,
            &session,
            WorkflowResumeAction::IngestObservation,
            &cancellation,
        )?;

        session.record_observation(digest('7')?, 1)?;
        version = persist_and_recover(
            &store,
            &workflow_id,
            &scope,
            version,
            &session,
            WorkflowResumeAction::CreateContextPlan,
            &cancellation,
        )?;

        session.record_plan_created(&plan_response(27, &target)?)?;
        session.record_bundle_compiled(&target)?;
        let sealed = generate_delta(&initial, &target)?;
        session.record_delta_compiled(&ContextDeltaResponse {
            delta: sealed.delta.clone(),
            delta_digest: sealed.delta_digest.clone(),
        })?;
        session.record_delta_applied(&apply_delta_verified(&initial, &target, &sealed)?)?;
        session.record_effect_revalidated(&RevalidationResponse {
            bundle_id: target.bundle_id.clone(),
            valid: true,
            reasons: Vec::new(),
        })?;
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
        version = persist_and_recover(
            &store,
            &workflow_id,
            &scope,
            version,
            &session,
            WorkflowResumeAction::DispatchEffect,
            &cancellation,
        )?;

        session.record_effect_dispatched(&effect(
            &effect_id,
            &intent_digest,
            3,
            EffectState::Unknown,
        ))?;
        let final_version = persist_and_recover(
            &store,
            &workflow_id,
            &scope,
            version,
            &session,
            WorkflowResumeAction::ReconcileEffect,
            &cancellation,
        )?;
        assert_eq!(final_version, created.version() + 6);
        Ok(())
    }

    #[test]
    fn every_bundle_governance_boundary_is_required_on_load() -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let store = WorkflowContextStore::new(repository);
        let tenant = record(10)?;
        let workflow_id = record(11)?;
        let expected = scope(
            tenant.clone(),
            record(12)?,
            "coding",
            Classification::Confidential,
            '4',
        )?;
        let cancellation = CancellationToken::default();
        store.create(
            workflow_id.clone(),
            expected.clone(),
            WorkflowContextSession::new(),
            &cancellation,
        )?;
        let mut substitutions = vec![
            scope(
                tenant.clone(),
                record(13)?,
                "coding",
                Classification::Confidential,
                '4',
            )?,
            scope(
                tenant.clone(),
                record(12)?,
                "review",
                Classification::Confidential,
                '4',
            )?,
            scope(
                tenant.clone(),
                record(12)?,
                "coding",
                Classification::Restricted,
                '4',
            )?,
            scope(
                tenant,
                record(12)?,
                "coding",
                Classification::Confidential,
                '5',
            )?,
        ];
        let mut processor = expected.clone();
        processor.processor = "external".to_owned();
        substitutions.push(processor);
        let mut authority = expected.clone();
        authority.maximum_instruction_authority = cigar_protocol::InstructionAuthority::System;
        substitutions.push(authority);
        for substitution in substitutions {
            let Err(error) = store.load(&workflow_id, &substitution, &cancellation) else {
                return Err("substituted governance scope unexpectedly loaded".into());
            };
            assert_eq!(error.code(), WorkflowContextStoreErrorCode::ScopeMismatch);
        }
        let other_tenant = scope(
            record(14)?,
            record(12)?,
            "coding",
            Classification::Confidential,
            '4',
        )?;
        let Err(error) = store.load(&workflow_id, &other_tenant, &cancellation) else {
            return Err("cross-tenant lookup unexpectedly resolved the checkpoint".into());
        };
        assert_eq!(error.code(), WorkflowContextStoreErrorCode::NotFound);
        Ok(())
    }
}
