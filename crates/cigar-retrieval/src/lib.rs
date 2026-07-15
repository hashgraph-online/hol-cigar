//! Exact, lexical, temporal, graph, and optional vector candidate generation.

mod contract;
#[cfg(target_os = "macos")]
mod durable_vector;
mod executor;
mod index;
mod local_vector;
mod planner;
mod vector;
mod worker;

pub use contract::*;
#[cfg(target_os = "macos")]
pub use durable_vector::{
    DurableLocalVectorError, DurableLocalVectorErrorCode, DurableLocalVectorFailpoint,
    DurableLocalVectorFallbackReason, DurableLocalVectorGenerationDescriptor,
    DurableLocalVectorStartup, DurableLocalVectorStore,
};
pub use executor::{ExecutedStage, StagedRetrieval, StagedRetrievalResult};
pub use index::{InMemoryIndexManager, IndexBuild, IndexGenerationDescriptor};
pub use local_vector::{
    DETERMINISTIC_LOCAL_VECTOR_MODEL_ID, DETERMINISTIC_LOCAL_VECTOR_PREPROCESSING_ID,
    DeterministicLocalVectorProcessor, LOCAL_VECTOR_ADAPTER_VERSION, LocalVectorAdapterEnablement,
    LocalVectorConfiguration, LocalVectorDistanceMetric, LocalVectorEntry, LocalVectorParameters,
    LocalVectorQuantization, MAX_LOCAL_VECTOR_ENTRIES, MAX_LOCAL_VECTOR_IDENTIFIER_BYTES,
    SealedLocalVectorAdapter, configure_local_vector_adapter,
};
pub use planner::{PlannedStage, QueryPlan, QueryPlanner, QueryPlannerProfile};
pub use vector::{
    MAX_QUANTIZED_VECTOR_VALUE, MAX_VECTOR_DIMENSIONS, MIN_QUANTIZED_VECTOR_VALUE,
    ProcessorApprovedVector, QueryVectorProcessor, VectorAdapter, VectorIndexBinding,
    VectorNeighbor, VectorQuery,
};
pub use worker::{IndexSnapshot, IndexSnapshotProvider, IndexWorker, IndexWorkerReceipt};

#[cfg(test)]
pub(crate) mod test_support {
    use crate::AuthorizedPartition;
    use cigar_policy::{
        CapabilityContext, CompiledPolicyEngine, PolicyProfile, PolicyRequest, PolicyResource,
    };
    use cigar_protocol::{
        Capability, Classification, ContentDigest, InstructionAuthority, Lifecycle, RecordId,
        UtcTimestamp,
    };
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::sync::{Arc, Mutex, OnceLock};

    static TEST_AUTHORITIES: OnceLock<Mutex<Vec<Arc<CompiledPolicyEngine>>>> = OnceLock::new();

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorized_partition(
        tenant_id: RecordId,
        principal_id: RecordId,
        project_ids: BTreeSet<RecordId>,
        purpose: &str,
        processor: &str,
        maximum_classification: Classification,
        maximum_instruction_authority: InstructionAuthority,
        vector_capability: bool,
        valid_at: UtcTimestamp,
        observed_as_of: UtcTimestamp,
    ) -> Result<AuthorizedPartition, Box<dyn Error>> {
        let (partition, engine) = authorized_partition_and_engine(
            tenant_id,
            principal_id,
            project_ids,
            purpose,
            processor,
            maximum_classification,
            maximum_instruction_authority,
            vector_capability,
            valid_at,
            observed_as_of,
        )?;
        TEST_AUTHORITIES
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .map_err(|_error| "test policy authority lock poisoned")?
            .push(engine);
        Ok(partition)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorized_partition_and_engine(
        tenant_id: RecordId,
        principal_id: RecordId,
        project_ids: BTreeSet<RecordId>,
        purpose: &str,
        processor: &str,
        maximum_classification: Classification,
        maximum_instruction_authority: InstructionAuthority,
        vector_capability: bool,
        valid_at: UtcTimestamp,
        observed_as_of: UtcTimestamp,
    ) -> Result<(AuthorizedPartition, Arc<CompiledPolicyEngine>), Box<dyn Error>> {
        let engine = Arc::new(CompiledPolicyEngine::default());
        engine.install(
            PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            },
            observed_as_of,
        )?;
        let required_capability = if vector_capability {
            Capability::CompileContext
        } else {
            Capability::ReadContext
        };
        let capabilities = BTreeSet::from([required_capability]);
        let allowed_processors = BTreeSet::from([processor.to_owned()]);
        let allowed_purposes = BTreeSet::from([purpose.to_owned()]);
        let expires_at = UtcTimestamp::from_unix_nanos(
            observed_as_of
                .unix_nanos()
                .checked_add(60_000_000_000)
                .ok_or("authorization timestamp overflow")?,
        )?;
        let input_digest = ContentDigest::new(format!("1220{}", "a5".repeat(32)))?;
        let grant_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6ffff0")?;
        let requests: Vec<_> = project_ids
            .iter()
            .cloned()
            .map(|project_id| PolicyRequest {
                resource: PolicyResource::Partition,
                input_digest: input_digest.clone(),
                principal_id: principal_id.clone(),
                principal_active: true,
                tenant_id: tenant_id.clone(),
                authenticated_tenant_id: tenant_id.clone(),
                project_id: Some(project_id),
                allowed_project_ids: project_ids.clone(),
                purpose: purpose.to_owned(),
                allowed_purposes: allowed_purposes.clone(),
                processor: Some(processor.to_owned()),
                allowed_processors: allowed_processors.clone(),
                classification: Classification::Public,
                maximum_classification,
                residency_allowed: true,
                egress_allowed: true,
                lifecycle: Lifecycle::Active,
                integrity_verified: true,
                valid_at,
                valid_from: valid_at,
                valid_until: Some(expires_at),
                observed_at: observed_as_of,
                observed_as_of,
                freshness_expires_at: None,
                instruction_authority: InstructionAuthority::Data,
                maximum_instruction_authority,
                excluded: false,
                modality_supported: true,
                capability: Some(CapabilityContext {
                    subject_id: principal_id.clone(),
                    grant_id: Some(grant_id.clone()),
                    capabilities: capabilities.clone(),
                    project_ids: project_ids.clone(),
                    processors: allowed_processors.clone(),
                    expires_at,
                }),
                required_capability: Some(required_capability),
                bound_policy_digest: None,
                effect_risk: None,
                effect_approved: false,
                effect_constraints_satisfied: true,
                fencing_required: false,
                fencing_verified: false,
                decision_expires_at: expires_at,
            })
            .collect();
        let authorization = engine.authorize_retrieval_partition(&requests)?;
        let partition = AuthorizedPartition::from_policy_authorization(authorization)?;
        Ok((partition, engine))
    }
}
