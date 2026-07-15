//! Deterministic bounded expansion of semantic requirements into retrieval stages.

use crate::{
    AuthorizedPartition, QueryVectorProcessor, RetrievalConsistency, RetrievalError,
    RetrievalErrorCode, RetrievalRequest, RetrievalStage,
};
use cigar_protocol::{ContentDigest, ContextRequirement, RequirementSelector};
use cigar_store::StoreRevision;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

/// Maximum expanded stages in one retrieval plan.
pub const MAX_PLANNED_STAGES: usize = 16_384;

/// Versioned deterministic stage caps and timeouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryPlannerProfile {
    /// Exact-selector result cap per requirement.
    pub exact_cap: usize,
    /// Metadata result cap per requirement.
    pub metadata_cap: usize,
    /// Lexical result cap per requirement.
    pub lexical_cap: usize,
    /// Optional vector result cap per requirement.
    pub vector_cap: usize,
    /// Timeout assigned to every exact stage.
    pub exact_timeout: Duration,
    /// Timeout assigned to every metadata stage.
    pub metadata_timeout: Duration,
    /// Timeout assigned to every lexical stage.
    pub lexical_timeout: Duration,
    /// Timeout assigned to every optional vector stage.
    pub vector_timeout: Duration,
}

impl Default for QueryPlannerProfile {
    fn default() -> Self {
        Self {
            exact_cap: 16,
            metadata_cap: 256,
            lexical_cap: 256,
            vector_cap: 128,
            exact_timeout: Duration::from_millis(250),
            metadata_timeout: Duration::from_millis(500),
            lexical_timeout: Duration::from_millis(750),
            vector_timeout: Duration::from_millis(1_000),
        }
    }
}

/// One independent request with its immutable execution policy.
#[derive(Clone, Eq, PartialEq)]
pub struct PlannedStage {
    /// Zero-based requirement that introduced the stage.
    pub requirement_index: usize,
    /// Whether absence is a compile-blocking condition.
    pub blocking: bool,
    /// Metadata-only authorized request.
    pub request: RetrievalRequest,
    /// Exact per-stage timeout.
    pub timeout: Duration,
    /// Digest over normalized query semantics and execution policy.
    pub query_fingerprint: ContentDigest,
}

impl fmt::Debug for PlannedStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlannedStage")
            .field("requirement_index", &self.requirement_index)
            .field("blocking", &self.blocking)
            .field("stage", &self.request.stage)
            .field("cap", &self.request.limit)
            .field("timeout", &self.timeout)
            .field("query_fingerprint", &self.query_fingerprint)
            .finish()
    }
}

/// Deterministically ordered authorized stage plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPlan {
    /// Independent bounded stages in requirement and channel order.
    pub stages: Vec<PlannedStage>,
    /// Digest over all stage fingerprints and the pinned revision.
    pub plan_fingerprint: ContentDigest,
    /// Exact catalog revision required by the plan.
    pub required_revision: StoreRevision,
}

/// Stateless deterministic query planner.
#[derive(Clone, Copy, Debug, Default)]
pub struct QueryPlanner {
    profile: QueryPlannerProfile,
}

impl QueryPlanner {
    /// Creates a planner after validating every configured cap and timeout.
    pub fn new(profile: QueryPlannerProfile) -> Result<Self, RetrievalError> {
        let caps = [
            profile.exact_cap,
            profile.metadata_cap,
            profile.lexical_cap,
            profile.vector_cap,
        ];
        let timeouts = [
            profile.exact_timeout,
            profile.metadata_timeout,
            profile.lexical_timeout,
            profile.vector_timeout,
        ];
        if caps
            .iter()
            .any(|cap| *cap == 0 || *cap > crate::MAX_CANDIDATES)
            || timeouts.iter().any(Duration::is_zero)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        Ok(Self { profile })
    }

    /// Expands exact and query requirements without inspecting catalog content.
    pub fn plan(
        &self,
        requirements: &[ContextRequirement],
        partition: &AuthorizedPartition,
        required_revision: StoreRevision,
        consistency: RetrievalConsistency,
        vector_available: bool,
    ) -> Result<QueryPlan, RetrievalError> {
        self.plan_internal(
            requirements,
            partition,
            required_revision,
            consistency,
            vector_available,
            None,
        )
    }

    /// Expands requirements and constructs vector inputs only after validating authorization.
    ///
    /// Passing `None` omits the optional vector stage. A configured processor receives only the
    /// opaque exact partition digest and the normalized bounded terms, never the original query.
    pub fn plan_with_vector_processor(
        &self,
        requirements: &[ContextRequirement],
        partition: &AuthorizedPartition,
        required_revision: StoreRevision,
        consistency: RetrievalConsistency,
        vector_processor: Option<&dyn QueryVectorProcessor>,
    ) -> Result<QueryPlan, RetrievalError> {
        self.plan_internal(
            requirements,
            partition,
            required_revision,
            consistency,
            vector_processor.is_some(),
            vector_processor,
        )
    }

    fn plan_internal(
        &self,
        requirements: &[ContextRequirement],
        partition: &AuthorizedPartition,
        required_revision: StoreRevision,
        consistency: RetrievalConsistency,
        vector_available: bool,
        vector_processor: Option<&dyn QueryVectorProcessor>,
    ) -> Result<QueryPlan, RetrievalError> {
        partition.validate()?;
        let mut stages = Vec::new();
        for (requirement_index, requirement) in requirements.iter().enumerate() {
            match &requirement.selector {
                RequirementSelector::Exact(version) => {
                    let mut request = base_request(
                        RetrievalStage::Exact,
                        partition,
                        required_revision,
                        consistency,
                        self.profile.exact_cap,
                        false,
                    );
                    request.exact_versions.insert(version.clone());
                    push_stage(
                        &mut stages,
                        requirement_index,
                        requirement.blocking,
                        request,
                        self.profile.exact_timeout,
                    )?;
                }
                RequirementSelector::Query(query) => {
                    let terms = normalize_query(query)?;
                    for (stage, cap, timeout) in [
                        (
                            RetrievalStage::Metadata,
                            self.profile.metadata_cap,
                            self.profile.metadata_timeout,
                        ),
                        (
                            RetrievalStage::Lexical,
                            self.profile.lexical_cap,
                            self.profile.lexical_timeout,
                        ),
                    ] {
                        let mut request = base_request(
                            stage,
                            partition,
                            required_revision,
                            consistency,
                            cap,
                            false,
                        );
                        request.terms.clone_from(&terms);
                        push_stage(
                            &mut stages,
                            requirement_index,
                            requirement.blocking,
                            request,
                            timeout,
                        )?;
                    }
                    if vector_available && partition.vector_allowed() {
                        let mut request = base_request(
                            RetrievalStage::Vector,
                            partition,
                            required_revision,
                            consistency,
                            self.profile.vector_cap,
                            true,
                        );
                        request.terms = terms;
                        if let Some(processor) = vector_processor {
                            request.approved_vector =
                                Some(processor.approve_query(partition, &request.terms)?);
                        }
                        push_stage(
                            &mut stages,
                            requirement_index,
                            false,
                            request,
                            self.profile.vector_timeout,
                        )?;
                    }
                }
            }
            if stages.len() > MAX_PLANNED_STAGES {
                return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
            }
        }
        let plan_fingerprint = plan_fingerprint(&stages, required_revision)?;
        Ok(QueryPlan {
            stages,
            plan_fingerprint,
            required_revision,
        })
    }
}

fn base_request(
    stage: RetrievalStage,
    partition: &AuthorizedPartition,
    required_revision: StoreRevision,
    consistency: RetrievalConsistency,
    limit: usize,
    allow_fallback: bool,
) -> RetrievalRequest {
    RetrievalRequest {
        stage,
        partition: partition.clone(),
        required_revision,
        consistency,
        exact_versions: BTreeSet::new(),
        atom_ids: BTreeSet::new(),
        lineage_ids: BTreeSet::new(),
        content_digests: BTreeSet::new(),
        canonical_uris: BTreeSet::new(),
        source_revisions: BTreeSet::new(),
        paths: BTreeSet::new(),
        terms: BTreeSet::new(),
        approved_vector: None,
        graph_roots: BTreeSet::new(),
        graph_depth: 0,
        limit,
        allow_fallback,
    }
}

fn normalize_query(query: &str) -> Result<BTreeSet<String>, RetrievalError> {
    let terms: BTreeSet<_> = query
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect();
    if terms.is_empty()
        || terms.len() > crate::MAX_QUERY_TERMS
        || terms.iter().any(|term| term.len() > 256)
    {
        Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded))
    } else {
        Ok(terms)
    }
}

fn push_stage(
    stages: &mut Vec<PlannedStage>,
    requirement_index: usize,
    blocking: bool,
    request: RetrievalRequest,
    timeout: Duration,
) -> Result<(), RetrievalError> {
    request.validate()?;
    let query_fingerprint = query_fingerprint(requirement_index, blocking, &request, timeout)?;
    stages.push(PlannedStage {
        requirement_index,
        blocking,
        request,
        timeout,
        query_fingerprint,
    });
    Ok(())
}

fn query_fingerprint(
    requirement_index: usize,
    blocking: bool,
    request: &RetrievalRequest,
    timeout: Duration,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-RETRIEVAL-QUERY\0v1\0");
    hasher.update(
        u64::try_from(requirement_index)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hasher.update([u8::from(blocking)]);
    hasher.update([stage_code(request.stage)]);
    match request.consistency {
        RetrievalConsistency::Strong => hasher.update([0]),
        RetrievalConsistency::BoundedStale { max_revision_lag } => {
            hasher.update([1]);
            hasher.update(max_revision_lag.to_be_bytes());
        }
    }
    update_fingerprint_field(
        &mut hasher,
        request.partition.partition_digest().as_str().as_bytes(),
    )?;
    hasher.update(request.required_revision.0.to_be_bytes());
    hasher.update(
        u64::try_from(request.limit)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hasher.update(timeout.as_nanos().to_be_bytes());
    hasher.update(request.graph_depth.to_be_bytes());
    hasher.update([u8::from(request.allow_fallback)]);
    for version in &request.exact_versions {
        update_fingerprint_field(&mut hasher, version.as_str().as_bytes())?;
    }
    for atom_id in &request.atom_ids {
        update_fingerprint_field(&mut hasher, atom_id.as_str().as_bytes())?;
    }
    for lineage_id in &request.lineage_ids {
        update_fingerprint_field(&mut hasher, lineage_id.as_str().as_bytes())?;
    }
    for digest in &request.content_digests {
        update_fingerprint_field(&mut hasher, digest.as_str().as_bytes())?;
    }
    for uri in &request.canonical_uris {
        update_fingerprint_field(&mut hasher, uri.as_str().as_bytes())?;
    }
    for revision in &request.source_revisions {
        update_fingerprint_field(&mut hasher, revision.as_bytes())?;
    }
    for path in &request.paths {
        update_fingerprint_field(&mut hasher, path.as_bytes())?;
    }
    for term in &request.terms {
        update_fingerprint_field(&mut hasher, term.as_bytes())?;
    }
    if let Some(vector) = &request.approved_vector {
        update_fingerprint_field(&mut hasher, vector.commitment().as_str().as_bytes())?;
    }
    for root in &request.graph_roots {
        update_fingerprint_field(&mut hasher, root.as_str().as_bytes())?;
    }
    finish_digest(hasher)
}

const fn stage_code(stage: RetrievalStage) -> u8 {
    match stage {
        RetrievalStage::Exact => 0,
        RetrievalStage::Metadata => 1,
        RetrievalStage::Lexical => 2,
        RetrievalStage::Vector => 3,
        RetrievalStage::Graph => 4,
        RetrievalStage::Augment => 5,
    }
}

fn update_fingerprint_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), RetrievalError> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hasher.update(value);
    Ok(())
}

fn plan_fingerprint(
    stages: &[PlannedStage],
    revision: StoreRevision,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-RETRIEVAL-PLAN\0v1\0");
    hasher.update(revision.0.to_be_bytes());
    hasher.update(
        u64::try_from(stages.len())
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for stage in stages {
        update_fingerprint_field(&mut hasher, stage.query_fingerprint.as_str().as_bytes())?;
    }
    finish_digest(hasher)
}

fn finish_digest(hasher: Sha256) -> Result<ContentDigest, RetrievalError> {
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?;
    }
    ContentDigest::new(value)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))
}

#[cfg(test)]
mod tests {
    use super::{QueryPlanner, QueryPlannerProfile};
    use crate::{AuthorizedPartition, RetrievalConsistency, RetrievalErrorCode, RetrievalStage};
    use cigar_protocol::{
        Classification, ContextRequirement, InstructionAuthority, RecordId, UtcTimestamp,
    };
    use cigar_store::StoreRevision;
    use std::error::Error;

    fn partition() -> Result<AuthorizedPartition, Box<dyn Error>> {
        crate::test_support::authorized_partition(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?,
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7804")?,
            [RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7802")?]
                .into_iter()
                .collect(),
            "coding",
            "local",
            Classification::Internal,
            InstructionAuthority::Project,
            true,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:02Z")?,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:02Z")?,
        )
    }

    fn requirement(
        selector: serde_json::Value,
        blocking: bool,
    ) -> Result<ContextRequirement, Box<dyn Error>> {
        Ok(serde_json::from_value(serde_json::json!({
            "semantic_type": "documentation",
            "selector": selector,
            "minimum_authority": 1,
            "minimum_coverage": 0,
            "blocking": blocking
        }))?)
    }

    #[test]
    fn plan_is_deterministic_capped_and_query_redacted() -> Result<(), Box<dyn Error>> {
        let exact = requirement(
            serde_json::json!({"type":"exact", "value": format!("1220{}", "b".repeat(64))}),
            true,
        )?;
        let query = requirement(
            serde_json::json!({"type":"query", "value":"Private_Symbol implementation"}),
            false,
        )?;
        let profile = QueryPlannerProfile {
            exact_cap: 1,
            metadata_cap: 17,
            lexical_cap: 19,
            vector_cap: 11,
            ..QueryPlannerProfile::default()
        };
        let planner = QueryPlanner::new(profile)?;
        let requirements = vec![exact, query];
        let first = planner.plan(
            &requirements,
            &partition()?,
            StoreRevision(42),
            RetrievalConsistency::Strong,
            true,
        )?;
        let second = planner.plan(
            &requirements,
            &partition()?,
            StoreRevision(42),
            RetrievalConsistency::Strong,
            true,
        )?;
        let bounded = planner.plan(
            &requirements,
            &partition()?,
            StoreRevision(42),
            RetrievalConsistency::BoundedStale {
                max_revision_lag: 3,
            },
            true,
        )?;
        assert_eq!(first, second);
        assert_ne!(
            first.plan_fingerprint, bounded.plan_fingerprint,
            "consistency semantics must be bound into the plan identity"
        );
        let first_query = first.stages.first().ok_or("missing first query")?;
        let bounded_query = bounded.stages.first().ok_or("missing bounded query")?;
        assert_ne!(
            first_query.query_fingerprint, bounded_query.query_fingerprint,
            "consistency semantics must be bound into every query identity"
        );
        assert_eq!(first.stages.len(), 4);
        assert_eq!(
            first
                .stages
                .iter()
                .map(|stage| (stage.request.stage, stage.request.limit, stage.blocking))
                .collect::<Vec<_>>(),
            vec![
                (RetrievalStage::Exact, 1, true),
                (RetrievalStage::Metadata, 17, false),
                (RetrievalStage::Lexical, 19, false),
                (RetrievalStage::Vector, 11, false),
            ]
        );
        assert!(!format!("{first:?}").contains("Private_Symbol"));
        assert_eq!(first.required_revision, StoreRevision(42));
        Ok(())
    }

    #[test]
    fn invalid_profiles_and_empty_normalized_queries_fail_before_execution()
    -> Result<(), Box<dyn Error>> {
        let invalid = QueryPlannerProfile {
            exact_cap: 0,
            ..QueryPlannerProfile::default()
        };
        assert_eq!(
            QueryPlanner::new(invalid).err().map(|error| error.code()),
            Some(RetrievalErrorCode::InvalidMetadata)
        );
        let empty = requirement(serde_json::json!({"type":"query", "value":"---"}), true)?;
        assert_eq!(
            QueryPlanner::default()
                .plan(
                    &[empty],
                    &partition()?,
                    StoreRevision(1),
                    RetrievalConsistency::Strong,
                    false,
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::LimitExceeded)
        );
        Ok(())
    }
}
