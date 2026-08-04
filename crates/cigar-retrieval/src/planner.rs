//! Deterministic bounded expansion of semantic requirements into retrieval stages.

use crate::{
    AuthorizedPartition, CandidateBounds, CandidateSelectionProfile, QueryVectorProcessor,
    RetrievalCapacity, RetrievalConsistency, RetrievalError, RetrievalErrorCode, RetrievalProfile,
    RetrievalRequest, RetrievalStage,
};
use cigar_protocol::{AtomKind, ContentDigest, ContextRequirement, LaneKind, RequirementSelector};
use cigar_store::StoreRevision;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
    /// Benchmark-profile graph depth following an exact root.
    pub exact_graph_depth: u16,
    /// Graph stage result cap.
    pub graph_cap: usize,
    /// Graph stage timeout.
    pub graph_timeout: Duration,
    /// Whether query requirements add a current-state augmentation stage.
    pub augment_queries: bool,
    /// Augmentation result cap.
    pub augment_cap: usize,
    /// Augmentation stage timeout.
    pub augment_timeout: Duration,
    /// Post-governance compiler-intake bounds and deterministic diversity policy.
    pub candidate_selection: CandidateSelectionProfile,
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
            exact_graph_depth: 0,
            graph_cap: 128,
            graph_timeout: Duration::from_millis(750),
            augment_queries: false,
            augment_cap: 128,
            augment_timeout: Duration::from_millis(500),
            candidate_selection: CandidateSelectionProfile::default(),
        }
    }
}

impl QueryPlannerProfile {
    /// Honey 0.9.2 H1 bounded graph planning profile.
    #[must_use]
    pub fn balanced_v2_candidate() -> Self {
        Self {
            exact_graph_depth: 2,
            ..Self::default()
        }
    }

    /// Separate benchmark-only current-state augmentation ablation.
    #[must_use]
    pub fn bounded_augmentation_candidate() -> Self {
        Self {
            augment_queries: true,
            ..Self::default()
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
    /// Fully derived post-governance candidate bounds bound into `plan_fingerprint`.
    pub candidate_bounds: CandidateBounds,
}

/// Stateless deterministic query planner.
#[derive(Clone, Copy, Debug)]
pub struct QueryPlanner {
    profile: QueryPlannerProfile,
    retrieval_profile: RetrievalProfile,
}

struct PlanInputs<'a> {
    partition: &'a AuthorizedPartition,
    required_revision: StoreRevision,
    consistency: RetrievalConsistency,
    vector_available: bool,
    vector_processor: Option<&'a dyn QueryVectorProcessor>,
    capacity: Option<&'a RetrievalCapacity>,
}

impl QueryPlanner {
    /// Creates a planner after validating every configured cap and timeout.
    pub fn new(profile: QueryPlannerProfile) -> Result<Self, RetrievalError> {
        Self::new_with_retrieval_profile(profile, RetrievalProfile::BalancedV1)
    }

    /// Creates a planner whose fingerprint binds one exact score profile.
    pub fn new_with_retrieval_profile(
        profile: QueryPlannerProfile,
        retrieval_profile: RetrievalProfile,
    ) -> Result<Self, RetrievalError> {
        let caps = [
            profile.exact_cap,
            profile.metadata_cap,
            profile.lexical_cap,
            profile.vector_cap,
            profile.graph_cap,
            profile.augment_cap,
        ];
        let timeouts = [
            profile.exact_timeout,
            profile.metadata_timeout,
            profile.lexical_timeout,
            profile.vector_timeout,
            profile.graph_timeout,
            profile.augment_timeout,
        ];
        if caps
            .iter()
            .any(|cap| *cap == 0 || *cap > crate::MAX_CANDIDATES)
            || timeouts.iter().any(Duration::is_zero)
            || profile.exact_graph_depth > crate::MAX_GRAPH_DEPTH
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        profile.candidate_selection.validate()?;
        Ok(Self {
            profile,
            retrieval_profile,
        })
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
            PlanInputs {
                partition,
                required_revision,
                consistency,
                vector_available,
                vector_processor: None,
                capacity: None,
            },
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
            PlanInputs {
                partition,
                required_revision,
                consistency,
                vector_available: vector_processor.is_some(),
                vector_processor,
                capacity: None,
            },
        )
    }

    /// Expands requirements with token/item-derived optional allowances and no vector processor.
    pub fn plan_bounded(
        &self,
        requirements: &[ContextRequirement],
        capacity: &RetrievalCapacity,
        partition: &AuthorizedPartition,
        required_revision: StoreRevision,
        consistency: RetrievalConsistency,
        vector_available: bool,
    ) -> Result<QueryPlan, RetrievalError> {
        self.plan_internal(
            requirements,
            PlanInputs {
                partition,
                required_revision,
                consistency,
                vector_available,
                vector_processor: None,
                capacity: Some(capacity),
            },
        )
    }

    /// Expands requirements with token/item-derived allowances and an optional approved vector.
    pub fn plan_bounded_with_vector_processor(
        &self,
        requirements: &[ContextRequirement],
        capacity: &RetrievalCapacity,
        partition: &AuthorizedPartition,
        required_revision: StoreRevision,
        consistency: RetrievalConsistency,
        vector_processor: Option<&dyn QueryVectorProcessor>,
    ) -> Result<QueryPlan, RetrievalError> {
        self.plan_internal(
            requirements,
            PlanInputs {
                partition,
                required_revision,
                consistency,
                vector_available: vector_processor.is_some(),
                vector_processor,
                capacity: Some(capacity),
            },
        )
    }

    fn plan_internal(
        &self,
        requirements: &[ContextRequirement],
        inputs: PlanInputs<'_>,
    ) -> Result<QueryPlan, RetrievalError> {
        let PlanInputs {
            partition,
            required_revision,
            consistency,
            vector_available,
            vector_processor,
            capacity,
        } = inputs;
        partition.validate()?;
        self.profile.candidate_selection.validate()?;
        let candidate_bounds = capacity.map_or_else(
            || legacy_candidate_bounds(requirements, self.profile),
            |capacity| {
                derive_candidate_bounds(requirements, capacity, self.profile.candidate_selection)
            },
        )?;
        let mut stages = Vec::new();
        for (requirement_index, requirement) in requirements.iter().enumerate() {
            match &requirement.selector {
                RequirementSelector::Exact(version) => {
                    let mut request = base_request(
                        RetrievalStage::Exact,
                        partition,
                        required_revision,
                        consistency,
                        requirement.semantic_type,
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
                    if self.profile.exact_graph_depth > 0 {
                        let mut graph = base_request(
                            RetrievalStage::Graph,
                            partition,
                            required_revision,
                            consistency,
                            requirement.semantic_type,
                            self.profile.graph_cap,
                            false,
                        );
                        graph.graph_roots.insert(version.clone());
                        graph.graph_depth = self.profile.exact_graph_depth;
                        push_stage(
                            &mut stages,
                            requirement_index,
                            false,
                            graph,
                            self.profile.graph_timeout,
                        )?;
                    }
                }
                RequirementSelector::Query(query) => {
                    let terms = normalize_query(query)?;
                    let available_channels =
                        2_usize + usize::from(vector_available && partition.vector_allowed());
                    let requirement_limit = candidate_bounds
                        .requirement_limits
                        .get(&requirement_index)
                        .copied()
                        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?;
                    let mut channel_index = 0_usize;
                    for (stage, configured_cap, timeout) in [
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
                        let cap = if capacity.is_some() {
                            distributed_channel_limit(
                                requirement_limit,
                                available_channels,
                                channel_index,
                            )?
                            .min(configured_cap)
                            .min(self.profile.candidate_selection.maximum_per_stage)
                        } else {
                            configured_cap
                        };
                        channel_index = channel_index.saturating_add(1);
                        let mut request = base_request(
                            stage,
                            partition,
                            required_revision,
                            consistency,
                            requirement.semantic_type,
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
                        let vector_cap = if capacity.is_some() {
                            distributed_channel_limit(
                                requirement_limit,
                                available_channels,
                                channel_index,
                            )?
                            .min(self.profile.vector_cap)
                            .min(self.profile.candidate_selection.maximum_per_stage)
                        } else {
                            self.profile.vector_cap
                        };
                        let mut request = base_request(
                            RetrievalStage::Vector,
                            partition,
                            required_revision,
                            consistency,
                            requirement.semantic_type,
                            vector_cap,
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
                    if self.profile.augment_queries {
                        let augment = base_request(
                            RetrievalStage::Augment,
                            partition,
                            required_revision,
                            consistency,
                            requirement.semantic_type,
                            self.profile.augment_cap,
                            false,
                        );
                        push_stage(
                            &mut stages,
                            requirement_index,
                            false,
                            augment,
                            self.profile.augment_timeout,
                        )?;
                    }
                }
            }
            if stages.len() > MAX_PLANNED_STAGES {
                return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
            }
        }
        let plan_fingerprint = plan_fingerprint(
            &stages,
            required_revision,
            &candidate_bounds,
            self.retrieval_profile,
        )?;
        Ok(QueryPlan {
            stages,
            plan_fingerprint,
            required_revision,
            candidate_bounds,
        })
    }
}

impl Default for QueryPlanner {
    fn default() -> Self {
        Self {
            profile: QueryPlannerProfile::default(),
            retrieval_profile: RetrievalProfile::BalancedV1,
        }
    }
}

fn distributed_channel_limit(
    requirement_limit: usize,
    channel_count: usize,
    channel_index: usize,
) -> Result<usize, RetrievalError> {
    if channel_count == 0 || channel_index >= channel_count || requirement_limit < channel_count {
        return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
    }
    Ok(requirement_limit / channel_count
        + usize::from(channel_index < requirement_limit % channel_count))
}

fn derive_candidate_bounds(
    requirements: &[ContextRequirement],
    capacity: &RetrievalCapacity,
    profile: CandidateSelectionProfile,
) -> Result<CandidateBounds, RetrievalError> {
    profile.validate()?;
    let mut query_requirements_by_lane = BTreeMap::<LaneKind, Vec<usize>>::new();
    let mut requirement_limits = BTreeMap::new();
    for (index, requirement) in requirements.iter().enumerate() {
        let lane = lane_for_atom_kind(requirement.semantic_type);
        if !capacity.lane_input_tokens.contains_key(&lane) {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        if matches!(requirement.selector, RequirementSelector::Exact(_)) {
            requirement_limits.insert(index, profile.maximum_protected_per_requirement);
        } else {
            query_requirements_by_lane
                .entry(lane)
                .or_default()
                .push(index);
        }
    }
    let mut lane_limits = BTreeMap::new();
    for (lane, tokens) in &capacity.lane_input_tokens {
        let token_items = usize::try_from(*tokens / profile.token_to_item_floor)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .max(1);
        let maximum = capacity
            .maximum_items
            .get(lane)
            .map_or(token_items, |maximum| {
                token_items.min(usize::from(*maximum))
            });
        let possible_items = maximum.max(
            capacity
                .minimum_items
                .get(lane)
                .map_or(0, |minimum| usize::from(*minimum)),
        );
        let lane_limit = possible_items
            .checked_mul(profile.oversubscription_factor)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .clamp(profile.minimum_per_requirement, profile.maximum_per_lane);
        lane_limits.insert(*lane, lane_limit);
        let query_indices = query_requirements_by_lane
            .get(lane)
            .map_or(&[][..], Vec::as_slice);
        if query_indices.is_empty() {
            continue;
        }
        let minimum_total = query_indices
            .len()
            .checked_mul(profile.minimum_per_requirement)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        if minimum_total > profile.maximum_per_lane {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        let distributed_total = lane_limit.max(minimum_total);
        for (offset, requirement_index) in query_indices.iter().enumerate() {
            let allowance = (distributed_total / query_indices.len()
                + usize::from(offset < distributed_total % query_indices.len()))
            .clamp(
                profile.minimum_per_requirement,
                profile.maximum_per_requirement,
            );
            requirement_limits.insert(*requirement_index, allowance);
        }
    }
    if requirement_limits.len() != requirements.len() {
        return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
    }
    Ok(CandidateBounds {
        requirement_limits,
        lane_limits,
        profile,
    })
}

fn legacy_candidate_bounds(
    requirements: &[ContextRequirement],
    planner: QueryPlannerProfile,
) -> Result<CandidateBounds, RetrievalError> {
    planner.candidate_selection.validate()?;
    let mut requirement_limits = BTreeMap::new();
    let mut lane_limits = BTreeMap::new();
    for (index, requirement) in requirements.iter().enumerate() {
        let limit = match requirement.selector {
            RequirementSelector::Exact(_) => planner.exact_cap,
            RequirementSelector::Query(_) => planner
                .metadata_cap
                .checked_add(planner.lexical_cap)
                .and_then(|value| value.checked_add(planner.vector_cap))
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
        };
        requirement_limits.insert(index, limit);
        lane_limits.insert(
            lane_for_atom_kind(requirement.semantic_type),
            planner.candidate_selection.maximum_per_lane,
        );
    }
    Ok(CandidateBounds {
        requirement_limits,
        lane_limits,
        profile: planner.candidate_selection,
    })
}

const fn lane_for_atom_kind(kind: AtomKind) -> LaneKind {
    match kind {
        AtomKind::Instruction | AtomKind::Policy => LaneKind::Rules,
        AtomKind::Decision | AtomKind::Conversation => LaneKind::History,
        AtomKind::ToolResult | AtomKind::Schema => LaneKind::Tools,
        AtomKind::SourceCode | AtomKind::Documentation | AtomKind::Test | AtomKind::Artifact => {
            LaneKind::Evidence
        }
    }
}

fn base_request(
    stage: RetrievalStage,
    partition: &AuthorizedPartition,
    required_revision: StoreRevision,
    consistency: RetrievalConsistency,
    atom_kind: AtomKind,
    limit: usize,
    allow_fallback: bool,
) -> RetrievalRequest {
    RetrievalRequest {
        stage,
        partition: partition.clone(),
        required_revision,
        consistency,
        atom_kinds: BTreeSet::from([atom_kind]),
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
    for atom_kind in &request.atom_kinds {
        hasher.update([atom_kind_code(*atom_kind)]);
    }
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

const fn atom_kind_code(kind: AtomKind) -> u8 {
    match kind {
        AtomKind::Instruction => 0,
        AtomKind::SourceCode => 1,
        AtomKind::Documentation => 2,
        AtomKind::Decision => 3,
        AtomKind::Conversation => 4,
        AtomKind::ToolResult => 5,
        AtomKind::Schema => 6,
        AtomKind::Policy => 7,
        AtomKind::Test => 8,
        AtomKind::Artifact => 9,
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
    bounds: &CandidateBounds,
    retrieval_profile: RetrievalProfile,
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    if retrieval_profile == RetrievalProfile::BalancedV1 {
        hasher.update(b"CIGAR-RETRIEVAL-PLAN\0v2\0");
    } else {
        hasher.update(b"CIGAR-RETRIEVAL-PLAN\0v3\0");
        update_fingerprint_field(&mut hasher, retrieval_profile.identifier().as_bytes())?;
        update_fingerprint_field(&mut hasher, retrieval_profile.digest()?.as_str().as_bytes())?;
    }
    hasher.update(revision.0.to_be_bytes());
    hasher.update(
        u64::try_from(stages.len())
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for stage in stages {
        update_fingerprint_field(&mut hasher, stage.query_fingerprint.as_str().as_bytes())?;
    }
    for (requirement, limit) in &bounds.requirement_limits {
        update_usize(&mut hasher, *requirement)?;
        update_usize(&mut hasher, *limit)?;
    }
    for (lane, limit) in &bounds.lane_limits {
        hasher.update([lane_code(*lane)]);
        update_usize(&mut hasher, *limit)?;
    }
    let profile = bounds.profile;
    for value in [
        profile.minimum_per_requirement,
        profile.maximum_per_requirement,
        profile.oversubscription_factor,
        profile.maximum_per_lane,
        profile.maximum_per_stage,
        profile.maximum_protected_per_requirement,
        profile.maximum_protected_per_request,
        profile.maximum_per_source,
        profile.maximum_per_lineage,
        profile.maximum_per_content_family,
        profile.maximum_raw_candidates,
        profile.absolute_compiler_candidates,
    ] {
        update_usize(&mut hasher, value)?;
    }
    hasher.update(profile.token_to_item_floor.to_be_bytes());
    for penalty in [
        profile.same_source_penalty,
        profile.same_lineage_penalty,
        profile.same_content_penalty,
        profile.same_kind_penalty,
    ] {
        hasher.update(penalty.to_be_bytes());
    }
    finish_digest(hasher)
}

fn update_usize(hasher: &mut Sha256, value: usize) -> Result<(), RetrievalError> {
    hasher.update(
        u64::try_from(value)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    Ok(())
}

const fn lane_code(lane: LaneKind) -> u8 {
    match lane {
        LaneKind::Rules => 0,
        LaneKind::Task => 1,
        LaneKind::Evidence => 2,
        LaneKind::History => 3,
        LaneKind::Tools => 4,
    }
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
    use crate::{
        AuthorizedPartition, RetrievalCapacity, RetrievalConsistency, RetrievalErrorCode,
        RetrievalStage,
    };
    use cigar_protocol::{
        Classification, ContextRequirement, InstructionAuthority, LaneKind, RecordId, UtcTimestamp,
    };
    use cigar_store::StoreRevision;
    use std::collections::BTreeMap;
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

    #[test]
    fn v2_planning_adds_only_bounded_graph_and_augmentation_stages() -> Result<(), Box<dyn Error>> {
        let exact = requirement(
            serde_json::json!({"type":"exact", "value": format!("1220{}", "b".repeat(64))}),
            true,
        )?;
        let query = requirement(
            serde_json::json!({"type":"query", "value":"ExactSymbol helper"}),
            false,
        )?;
        let plan = QueryPlanner::new(QueryPlannerProfile::bounded_augmentation_candidate())?.plan(
            &[exact, query],
            &partition()?,
            StoreRevision(42),
            RetrievalConsistency::Strong,
            false,
        )?;
        assert_eq!(
            plan.stages
                .iter()
                .map(|stage| stage.request.stage)
                .collect::<Vec<_>>(),
            vec![
                RetrievalStage::Exact,
                RetrievalStage::Metadata,
                RetrievalStage::Lexical,
                RetrievalStage::Augment,
            ]
        );
        assert!(plan.stages.iter().all(|stage| stage.request.limit <= 256));
        let graph = QueryPlanner::new(QueryPlannerProfile::balanced_v2_candidate())?.plan(
            &[requirement(
                serde_json::json!({"type":"exact", "value": format!("1220{}", "c".repeat(64))}),
                true,
            )?],
            &partition()?,
            StoreRevision(42),
            RetrievalConsistency::Strong,
            false,
        )?;
        let graph_stage = graph.stages.get(1).ok_or("missing graph stage")?;
        assert_eq!(graph_stage.request.stage, RetrievalStage::Graph);
        assert_eq!(graph_stage.request.graph_depth, 2);
        Ok(())
    }

    #[test]
    fn bounded_query_distributes_one_requirement_allowance_across_channels()
    -> Result<(), Box<dyn Error>> {
        let query = requirement(
            serde_json::json!({"type":"query", "value":"bounded context"}),
            true,
        )?;
        let capacity = RetrievalCapacity::new(
            BTreeMap::from([(LaneKind::Evidence, 4_000)]),
            BTreeMap::new(),
            BTreeMap::new(),
        )?;
        let plan = QueryPlanner::default().plan_bounded(
            &[query],
            &capacity,
            &partition()?,
            StoreRevision(42),
            RetrievalConsistency::Strong,
            true,
        )?;
        let total: usize = plan.stages.iter().map(|stage| stage.request.limit).sum();
        assert_eq!(plan.stages.len(), 3);
        assert_eq!(total, 8);
        assert!(plan.stages.iter().all(|stage| stage.request.limit <= 3));
        Ok(())
    }
}
