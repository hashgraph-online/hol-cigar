//! Post-governance alias coalescing, caps, and deterministic quantized diversity.

use crate::{
    CandidateFeatures, CandidateRef, MatchEvidence, QueryPlan, RetrievalContext, RetrievalError,
    RetrievalErrorCode, RetrievalProfile, StagedRetrievalResult,
};
use cigar_protocol::{
    AtomKind, Classification, ContentDigest, InstructionAuthority, LaneKind, LineageId, SourceUri,
    VersionId,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// One compiler-intake candidate with complete requirement coverage and protection state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedCandidate {
    /// Stable authorized metadata selected from all channel aliases for this version.
    pub candidate: CandidateRef,
    /// Sorted requirements whose authorized stages returned this candidate or its content family.
    pub requirement_indices: BTreeSet<usize>,
    /// Whether exact, blocking, policy, or higher-authority semantics bypassed ordinary caps.
    pub protected: bool,
}

/// Content-free accounting for one post-governance reduction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BoundedCandidateCounts {
    /// Raw stage references before same-version alias coalescing.
    pub raw_stage_candidates: usize,
    /// Unique governed versions after channel alias coalescing.
    pub after_version_coalescing: usize,
    /// Protected candidates outside ordinary competition.
    pub protected_candidates: usize,
    /// Optional candidates after authenticated content-family coalescing.
    pub after_content_coalescing: usize,
    /// Optional candidates after per-source, lineage, and content-family caps.
    pub after_family_caps: usize,
    /// Final protected plus diverse optional compiler intake.
    pub submitted_candidates: usize,
}

/// Deterministically ordered bounded candidates for compiler intake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRetrievalResult {
    /// Exact plan identity whose bounds and stage results were reduced.
    pub plan_fingerprint: ContentDigest,
    /// Stable metadata-only protected plus optional candidates.
    pub candidates: Vec<BoundedCandidate>,
    /// Closed aggregate stage counts.
    pub counts: BoundedCandidateCounts,
}

#[derive(Clone)]
struct MergedCandidate {
    candidate: CandidateRef,
    requirement_indices: BTreeSet<usize>,
    protected: bool,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ContentFamilyKey {
    atom_kind: AtomKind,
    content_digest: ContentDigest,
    classification: Classification,
    instruction_authority: InstructionAuthority,
}

/// Stateless requirement-aware candidate reducer.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequirementAwareCandidateReducer;

impl RequirementAwareCandidateReducer {
    /// Coalesces only authorized stage output, preserves protected candidates, and bounds optional
    /// compiler intake using the exact policy frozen in `plan.plan_fingerprint`.
    pub fn reduce(
        &self,
        plan: &QueryPlan,
        retrieval: &StagedRetrievalResult,
        context: &RetrievalContext,
    ) -> Result<BoundedRetrievalResult, RetrievalError> {
        self.reduce_with_profile(plan, retrieval, context, RetrievalProfile::BalancedV1)
    }

    /// Reduces and validates candidates under one exact score profile.
    pub fn reduce_with_profile(
        &self,
        plan: &QueryPlan,
        retrieval: &StagedRetrievalResult,
        context: &RetrievalContext,
        retrieval_profile: RetrievalProfile,
    ) -> Result<BoundedRetrievalResult, RetrievalError> {
        context.check()?;
        plan.candidate_bounds.profile.validate()?;
        if retrieval.plan_fingerprint != plan.plan_fingerprint
            || retrieval.stages.len() != plan.stages.len()
        {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        let mut merged = BTreeMap::<VersionId, MergedCandidate>::new();
        let mut counts = BoundedCandidateCounts::default();
        for (planned, executed) in plan.stages.iter().zip(&retrieval.stages) {
            context.check()?;
            if planned.requirement_index != executed.requirement_index
                || planned.blocking != executed.blocking
                || planned.request.stage != executed.stage
                || planned.query_fingerprint != executed.query_fingerprint
                || executed.batch.candidates.len() > planned.request.limit
            {
                return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
            }
            counts.raw_stage_candidates = counts
                .raw_stage_candidates
                .checked_add(executed.batch.candidates.len())
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
            for candidate in &executed.batch.candidates {
                context.check()?;
                validate_candidate(candidate, retrieval_profile)?;
                let is_protected = planned.blocking
                    || candidate.evidence.contains(&MatchEvidence::ExactIdentity)
                    || candidate.atom_kind == AtomKind::Policy
                    || candidate.instruction_authority >= InstructionAuthority::Project;
                match merged.get_mut(&candidate.version_id) {
                    Some(current) => {
                        merge_same_version(&mut current.candidate, candidate, retrieval_profile)?;
                        current
                            .requirement_indices
                            .insert(planned.requirement_index);
                        current.protected |= is_protected;
                    }
                    None => {
                        merged.insert(
                            candidate.version_id.clone(),
                            MergedCandidate {
                                candidate: candidate.clone(),
                                requirement_indices: BTreeSet::from([planned.requirement_index]),
                                protected: is_protected,
                            },
                        );
                    }
                }
            }
        }
        counts.after_version_coalescing = merged.len();

        let profile = plan.candidate_bounds.profile;
        let mut protected = Vec::new();
        let mut optional = Vec::new();
        let mut protected_by_requirement = BTreeMap::<usize, usize>::new();
        for candidate in merged.into_values() {
            if candidate.protected {
                for requirement in &candidate.requirement_indices {
                    let count = protected_by_requirement.entry(*requirement).or_default();
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
                    if *count > profile.maximum_protected_per_requirement {
                        return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
                    }
                }
                protected.push(candidate);
            } else {
                optional.push(candidate);
            }
        }
        protected.sort_by(merged_candidate_order);
        if protected.len() > profile.maximum_protected_per_request
            || protected.len() > profile.absolute_compiler_candidates
        {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        counts.protected_candidates = protected.len();

        let mut content_families = BTreeMap::<ContentFamilyKey, Vec<MergedCandidate>>::new();
        for candidate in optional {
            content_families
                .entry(content_family(&candidate.candidate))
                .or_default()
                .push(candidate);
        }
        let mut coalesced = Vec::with_capacity(content_families.len());
        for family in content_families.values_mut() {
            family.sort_by(merged_candidate_order);
            let mut representative = family
                .first()
                .cloned()
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            for alias in family.iter().skip(1) {
                representative
                    .requirement_indices
                    .extend(alias.requirement_indices.iter().copied());
            }
            coalesced.push(representative);
        }
        coalesced.sort_by(merged_candidate_order);
        counts.after_content_coalescing = coalesced.len();

        let raw_optional_limit = profile
            .maximum_raw_candidates
            .saturating_sub(protected.len());
        coalesced.truncate(raw_optional_limit);
        let mut source_counts = BTreeMap::<SourceUri, usize>::new();
        let mut lineage_counts = BTreeMap::<LineageId, usize>::new();
        let mut family_counts = BTreeMap::<ContentFamilyKey, usize>::new();
        let mut capped = Vec::new();
        for candidate in coalesced {
            context.check()?;
            let source_count = source_counts
                .get(&candidate.candidate.canonical_uri)
                .copied()
                .unwrap_or_default();
            let lineage_count = lineage_counts
                .get(&candidate.candidate.lineage_id)
                .copied()
                .unwrap_or_default();
            let family = content_family(&candidate.candidate);
            let family_count = family_counts.get(&family).copied().unwrap_or_default();
            if source_count >= profile.maximum_per_source
                || lineage_count >= profile.maximum_per_lineage
                || family_count >= profile.maximum_per_content_family
            {
                continue;
            }
            *source_counts
                .entry(candidate.candidate.canonical_uri.clone())
                .or_default() += 1;
            *lineage_counts
                .entry(candidate.candidate.lineage_id.clone())
                .or_default() += 1;
            *family_counts.entry(family).or_default() += 1;
            capped.push(candidate);
        }
        counts.after_family_caps = capped.len();

        let mut selected = protected;
        let mut optional_lane_counts = BTreeMap::<LaneKind, usize>::new();
        let mut requirement_counts = BTreeMap::<usize, usize>::new();
        for candidate in &selected {
            for requirement in &candidate.requirement_indices {
                *requirement_counts.entry(*requirement).or_default() += 1;
            }
        }
        while selected.len() < profile.absolute_compiler_candidates {
            context.check()?;
            let best = capped
                .iter()
                .enumerate()
                .filter(|(_index, candidate)| {
                    let lane = lane_for_atom_kind(candidate.candidate.atom_kind);
                    let lane_limit = plan
                        .candidate_bounds
                        .lane_limits
                        .get(&lane)
                        .copied()
                        .unwrap_or_default();
                    optional_lane_counts.get(&lane).copied().unwrap_or_default() < lane_limit
                        && candidate.requirement_indices.iter().any(|requirement| {
                            requirement_counts
                                .get(requirement)
                                .copied()
                                .unwrap_or_default()
                                < plan
                                    .candidate_bounds
                                    .requirement_limits
                                    .get(requirement)
                                    .copied()
                                    .unwrap_or_default()
                        })
                })
                .map(|(index, candidate)| {
                    adjusted_score(candidate, &selected, profile)
                        .map(|score| (index, score, candidate))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .max_by(|left, right| {
                    left.1
                        .cmp(&right.1)
                        .then_with(|| merged_candidate_order(right.2, left.2))
                });
            let Some((index, _score, _candidate)) = best else {
                break;
            };
            let winner = capped.remove(index);
            let lane = lane_for_atom_kind(winner.candidate.atom_kind);
            *optional_lane_counts.entry(lane).or_default() += 1;
            for requirement in &winner.requirement_indices {
                *requirement_counts.entry(*requirement).or_default() += 1;
            }
            selected.push(winner);
        }
        selected.sort_by(merged_candidate_order);
        counts.submitted_candidates = selected.len();
        let candidates = selected
            .into_iter()
            .map(|candidate| BoundedCandidate {
                candidate: candidate.candidate,
                requirement_indices: candidate.requirement_indices,
                protected: candidate.protected,
            })
            .collect();
        Ok(BoundedRetrievalResult {
            plan_fingerprint: plan.plan_fingerprint.clone(),
            candidates,
            counts,
        })
    }
}

fn validate_candidate(
    candidate: &CandidateRef,
    retrieval_profile: RetrievalProfile,
) -> Result<(), RetrievalError> {
    validate_candidate_score(
        candidate.features,
        candidate.total_score,
        !candidate.evidence.is_empty(),
        retrieval_profile,
    )
}

fn validate_candidate_score(
    features: CandidateFeatures,
    total_score: i64,
    has_evidence: bool,
    retrieval_profile: RetrievalProfile,
) -> Result<(), RetrievalError> {
    if features.estimated_tokens == 0
        || total_score != features.score(retrieval_profile)?
        || !has_evidence
    {
        Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
    } else {
        Ok(())
    }
}

fn merge_same_version(
    current: &mut CandidateRef,
    candidate: &CandidateRef,
    retrieval_profile: RetrievalProfile,
) -> Result<(), RetrievalError> {
    if current.version_id != candidate.version_id
        || current.lineage_id != candidate.lineage_id
        || current.content_digest != candidate.content_digest
        || current.atom_kind != candidate.atom_kind
        || current.canonical_uri != candidate.canonical_uri
        || current.relative_path != candidate.relative_path
        || current.instruction_authority != candidate.instruction_authority
        || current.classification != candidate.classification
        || current.features.estimated_tokens != candidate.features.estimated_tokens
    {
        return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
    }
    current.evidence.extend(candidate.evidence.iter().cloned());
    current.features = merge_features(current.features, candidate.features);
    current.total_score = current.features.score(retrieval_profile)?;
    Ok(())
}

fn merge_features(left: CandidateFeatures, right: CandidateFeatures) -> CandidateFeatures {
    CandidateFeatures {
        requirement_match: left.requirement_match.max(right.requirement_match),
        exact_match: left.exact_match.max(right.exact_match),
        lexical_match: left.lexical_match.max(right.lexical_match),
        semantic_match: left.semantic_match.max(right.semantic_match),
        graph_proximity: left.graph_proximity.max(right.graph_proximity),
        project_proximity: left.project_proximity.max(right.project_proximity),
        task_proximity: left.task_proximity.max(right.task_proximity),
        authority: left.authority.max(right.authority),
        verification: left.verification.max(right.verification),
        freshness: left.freshness.max(right.freshness),
        novelty: left.novelty.max(right.novelty),
        conflict_risk: left.conflict_risk.max(right.conflict_risk),
        staleness: left.staleness.max(right.staleness),
        estimated_tokens: left.estimated_tokens,
        requirement_coverage_bits: left.requirement_coverage_bits | right.requirement_coverage_bits,
        entity_coverage_bits: left.entity_coverage_bits | right.entity_coverage_bits,
    }
}

fn adjusted_score(
    candidate: &MergedCandidate,
    selected: &[MergedCandidate],
    profile: crate::CandidateSelectionProfile,
) -> Result<i64, RetrievalError> {
    let maximum_similarity = selected
        .iter()
        .map(|prior| similarity_penalty(&candidate.candidate, &prior.candidate, profile))
        .max()
        .unwrap_or_default();
    candidate
        .candidate
        .total_score
        .checked_sub(maximum_similarity)
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
}

fn similarity_penalty(
    left: &CandidateRef,
    right: &CandidateRef,
    profile: crate::CandidateSelectionProfile,
) -> i64 {
    let mut penalty = 0_i64;
    if left.canonical_uri == right.canonical_uri {
        penalty = penalty.max(profile.same_source_penalty);
    }
    if left.lineage_id == right.lineage_id {
        penalty = penalty.max(profile.same_lineage_penalty);
    }
    if content_family(left) == content_family(right) {
        penalty = penalty.max(profile.same_content_penalty);
    }
    if left.atom_kind == right.atom_kind {
        penalty = penalty.max(profile.same_kind_penalty);
    }
    penalty
}

fn content_family(candidate: &CandidateRef) -> ContentFamilyKey {
    ContentFamilyKey {
        atom_kind: candidate.atom_kind,
        content_digest: candidate.content_digest.clone(),
        classification: candidate.classification,
        instruction_authority: candidate.instruction_authority,
    }
}

fn merged_candidate_order(left: &MergedCandidate, right: &MergedCandidate) -> Ordering {
    candidate_order(&left.candidate, &right.candidate)
}

fn candidate_order(left: &CandidateRef, right: &CandidateRef) -> Ordering {
    right
        .total_score
        .cmp(&left.total_score)
        .then_with(|| {
            left.features
                .estimated_tokens
                .cmp(&right.features.estimated_tokens)
        })
        .then_with(|| {
            left.canonical_uri
                .as_str()
                .cmp(right.canonical_uri.as_str())
        })
        .then_with(|| {
            left.relative_path
                .as_ref()
                .map(cigar_protocol::RelativePath::as_bytes)
                .cmp(
                    &right
                        .relative_path
                        .as_ref()
                        .map(cigar_protocol::RelativePath::as_bytes),
                )
        })
        .then_with(|| left.version_id.cmp(&right.version_id))
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

#[cfg(test)]
mod tests {
    use super::{RequirementAwareCandidateReducer, validate_candidate_score};
    use crate::{
        BoundedRetrievalResult, CandidateBatch, CandidateFeatures, CandidateRef, ExecutedStage,
        MatchEvidence, QueryPlan, QueryPlanner, RetrievalCapacity, RetrievalConsistency,
        RetrievalContext, RetrievalDisclosure, RetrievalProfile, RetrievalStage,
        StagedRetrievalResult,
    };
    use cigar_protocol::{
        AtomKind, Classification, ContentDigest, ContextRequirement, InstructionAuthority,
        LaneKind, LineageId, RecordId, SourceUri, UtcTimestamp, VersionId,
    };
    use cigar_store::{CancellationToken, StoreRevision};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::time::{Duration, Instant};

    fn digest(value: u64) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!("1220{value:064x}"))?)
    }

    fn version(value: u64) -> Result<VersionId, Box<dyn Error>> {
        Ok(VersionId::new(format!("1220{value:064x}"))?)
    }

    fn lineage(value: u64) -> Result<LineageId, Box<dyn Error>> {
        Ok(LineageId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
        ))?)
    }

    fn partition() -> Result<crate::AuthorizedPartition, Box<dyn Error>> {
        crate::test_support::authorized_partition(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?,
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7804")?,
            [RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7802")?]
                .into_iter()
                .collect(),
            "coding",
            "local",
            Classification::Internal,
            InstructionAuthority::System,
            false,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:02Z")?,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:02Z")?,
        )
    }

    fn requirement(
        exact: Option<u64>,
        blocking: bool,
    ) -> Result<ContextRequirement, Box<dyn Error>> {
        let selector = exact.map_or_else(
            || serde_json::json!({"type":"query", "value":"bounded evidence"}),
            |value| serde_json::json!({"type":"exact", "value": format!("1220{value:064x}")}),
        );
        Ok(serde_json::from_value(serde_json::json!({
            "semantic_type": "documentation",
            "selector": selector,
            "minimum_authority": 1,
            "minimum_coverage": 0,
            "blocking": blocking
        }))?)
    }

    fn capacity(maximum_items: u16) -> Result<RetrievalCapacity, Box<dyn Error>> {
        Ok(RetrievalCapacity::new(
            BTreeMap::from([(LaneKind::Evidence, 1_024)]),
            BTreeMap::from([(LaneKind::Evidence, maximum_items)]),
            BTreeMap::from([(LaneKind::Evidence, 1)]),
        )?)
    }

    fn candidate(
        value: u64,
        source: u64,
        lineage_value: u64,
        content: u64,
        score: u16,
    ) -> Result<CandidateRef, Box<dyn Error>> {
        candidate_for_profile(
            value,
            source,
            lineage_value,
            content,
            score,
            RetrievalProfile::BalancedV1,
        )
    }

    fn candidate_for_profile(
        value: u64,
        source: u64,
        lineage_value: u64,
        content: u64,
        score: u16,
        retrieval_profile: RetrievalProfile,
    ) -> Result<CandidateRef, Box<dyn Error>> {
        let features = CandidateFeatures {
            requirement_match: score,
            lexical_match: score,
            project_proximity: 10_000,
            authority: 2_500,
            freshness: 10_000,
            estimated_tokens: 10,
            ..CandidateFeatures::default()
        };
        Ok(CandidateRef {
            version_id: version(value)?,
            lineage_id: lineage(lineage_value)?,
            content_digest: digest(content)?,
            atom_kind: AtomKind::Documentation,
            canonical_uri: SourceUri::new(format!("file:///source/{source}.md"))?,
            relative_path: None,
            instruction_authority: InstructionAuthority::Data,
            classification: Classification::Internal,
            features,
            total_score: features.score(retrieval_profile)?,
            evidence: BTreeSet::from([MatchEvidence::Lexical]),
        })
    }

    fn result(
        plan: &QueryPlan,
        candidates: &[Vec<CandidateRef>],
    ) -> Result<StagedRetrievalResult, Box<dyn Error>> {
        let stages = plan
            .stages
            .iter()
            .enumerate()
            .map(|(index, planned)| {
                Ok(ExecutedStage {
                    requirement_index: planned.requirement_index,
                    blocking: planned.blocking,
                    stage: planned.request.stage,
                    query_fingerprint: planned.query_fingerprint.clone(),
                    batch: CandidateBatch {
                        candidates: candidates.get(index).cloned().unwrap_or_default(),
                        disclosure: RetrievalDisclosure {
                            generation_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7803")?,
                            index_fingerprint: digest(900)?,
                            built_through_revision: StoreRevision(7),
                            actual_revision_lag: 0,
                            fallback_used: false,
                            last_verified_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
                        },
                    },
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        Ok(StagedRetrievalResult {
            plan_fingerprint: plan.plan_fingerprint.clone(),
            stages,
        })
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    #[test]
    fn v2_score_profile_is_bound_reproduced_and_not_reinterpreted_as_v1()
    -> Result<(), Box<dyn Error>> {
        let plan = QueryPlanner::new_with_retrieval_profile(
            crate::QueryPlannerProfile::balanced_v2_candidate(),
            RetrievalProfile::BalancedV2Candidate,
        )?
        .plan_bounded(
            &[requirement(None, false)?],
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let v2_candidate =
            candidate_for_profile(80, 1, 1, 800, 8_000, RetrievalProfile::BalancedV2Candidate)?;
        assert_ne!(
            v2_candidate.total_score,
            v2_candidate.features.balanced_score()?
        );
        let candidates = vec![vec![v2_candidate.clone()], vec![v2_candidate.clone()]];
        let reduced = RequirementAwareCandidateReducer.reduce_with_profile(
            &plan,
            &result(&plan, &candidates)?,
            &context(),
            RetrievalProfile::BalancedV2Candidate,
        )?;
        let accepted = reduced
            .candidates
            .first()
            .ok_or("missing accepted candidate")?;
        assert_eq!(
            accepted.candidate.total_score,
            accepted
                .candidate
                .features
                .score(RetrievalProfile::BalancedV2Candidate)?
        );

        let mut v1_reinterpreted = v2_candidate;
        v1_reinterpreted.total_score = v1_reinterpreted.features.balanced_score()?;
        assert_eq!(
            RequirementAwareCandidateReducer
                .reduce_with_profile(
                    &plan,
                    &result(&plan, &[vec![v1_reinterpreted], Vec::new()])?,
                    &context(),
                    RetrievalProfile::BalancedV2Candidate,
                )
                .map_err(|error| error.code()),
            Err(crate::RetrievalErrorCode::CorruptGeneration)
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            max_shrink_iters: 16_384,
            rng_seed: RngSeed::Fixed(0x00c1_6a19_0009_0001),
            ..ProptestConfig::default()
        })]

        #[test]
        fn every_accepted_score_is_reproducible_and_one_bit_tampering_is_rejected(
            requirement_match in 0_u16..=10_000,
            exact_match in 0_u16..=10_000,
            lexical_match in 0_u16..=10_000,
            semantic_match in 0_u16..=10_000,
            graph_proximity in 0_u16..=10_000,
            project_proximity in 0_u16..=10_000,
            task_proximity in 0_u16..=10_000,
            authority in 0_u16..=10_000,
            verification in 0_u16..=10_000,
            freshness in 0_u16..=10_000,
            novelty in 0_u16..=10_000,
            conflict_risk in 0_u16..=10_000,
            staleness in 0_u16..=10_000,
            estimated_tokens in 1_u32..=1_000_000,
            use_v2 in any::<bool>(),
        ) {
            let retrieval_profile = if use_v2 {
                RetrievalProfile::BalancedV2Candidate
            } else {
                RetrievalProfile::BalancedV1
            };
            let features = CandidateFeatures {
                requirement_match,
                exact_match,
                lexical_match,
                semantic_match,
                graph_proximity,
                project_proximity,
                task_proximity,
                authority,
                verification,
                freshness,
                novelty,
                conflict_risk,
                staleness,
                estimated_tokens,
                requirement_coverage_bits: 0,
                entity_coverage_bits: 0,
            };
            let total_score = match features.score(retrieval_profile) {
                Ok(score) => score,
                Err(error) => {
                    prop_assert!(false, "bounded features failed to score: {error}");
                    0
                }
            };
            prop_assert!(validate_candidate_score(
                features,
                total_score,
                true,
                retrieval_profile,
            ).is_ok());
            prop_assert_eq!(
                validate_candidate_score(features, total_score ^ 1, true, retrieval_profile)
                    .map_err(|error| error.code()),
                Err(crate::RetrievalErrorCode::CorruptGeneration),
            );
        }
    }

    #[test]
    fn lane_capacity_derives_small_stable_stage_and_requirement_bounds()
    -> Result<(), Box<dyn Error>> {
        let requirements = vec![requirement(None, false)?];
        let plan = QueryPlanner::default().plan_bounded(
            &requirements,
            &capacity(2)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        assert_eq!(plan.candidate_bounds.requirement_limits.get(&0), Some(&8));
        assert_eq!(
            plan.candidate_bounds.lane_limits.get(&LaneKind::Evidence),
            Some(&8)
        );
        assert_eq!(
            plan.stages
                .iter()
                .map(|stage| (stage.request.stage, stage.request.limit))
                .collect::<Vec<_>>(),
            vec![(RetrievalStage::Metadata, 4), (RetrievalStage::Lexical, 4)]
        );
        let smaller = QueryPlanner::default().plan_bounded(
            &requirements,
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        assert_ne!(plan.plan_fingerprint, smaller.plan_fingerprint);
        assert_eq!(
            smaller.candidate_bounds.requirement_limits.get(&0),
            Some(&4)
        );
        assert_eq!(
            smaller
                .stages
                .first()
                .ok_or("missing smaller bounded stage")?
                .request
                .limit,
            2
        );
        Ok(())
    }

    #[test]
    fn flood_alias_content_caps_and_diversity_are_permutation_stable() -> Result<(), Box<dyn Error>>
    {
        let requirements = vec![requirement(None, false)?];
        let plan = QueryPlanner::default().plan_bounded(
            &requirements,
            &capacity(2)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let alias = candidate(1, 1, 1, 101, 10_000)?;
        let first = vec![
            alias.clone(),
            candidate(2, 1, 2, 102, 9_900)?,
            candidate(3, 1, 3, 103, 9_800)?,
            candidate(4, 1, 4, 104, 9_700)?,
        ];
        let second = vec![
            alias,
            candidate(5, 5, 5, 105, 9_600)?,
            candidate(6, 6, 5, 106, 9_500)?,
            candidate(7, 7, 7, 105, 9_400)?,
        ];
        let base = result(&plan, &[first.clone(), second.clone()])?;
        let expected = RequirementAwareCandidateReducer.reduce(&plan, &base, &context())?;
        assert_eq!(expected.counts.raw_stage_candidates, 8);
        assert_eq!(expected.counts.after_version_coalescing, 7);
        assert!(expected.counts.after_content_coalescing < 7);
        assert!(expected.counts.after_family_caps <= 4);
        assert!(expected.counts.submitted_candidates <= 8);
        assert!(expected.counts.submitted_candidates.saturating_sub(1) < 10);
        let source_one = expected
            .candidates
            .iter()
            .filter(|candidate| candidate.candidate.canonical_uri.as_str() == "file:///source/1.md")
            .count();
        assert!(source_one <= 2);

        for permutation in 0..8_usize {
            let mut left = first.clone();
            let mut right = second.clone();
            let left_length = left.len();
            let right_length = right.len();
            left.rotate_left(permutation % left_length);
            right.rotate_right(permutation % right_length);
            if permutation % 2 == 1 {
                left.reverse();
                right.reverse();
            }
            let permuted = result(&plan, &[left, right])?;
            let reduced = RequirementAwareCandidateReducer.reduce(&plan, &permuted, &context())?;
            assert_eq!(reduced, expected);
        }
        Ok(())
    }

    #[test]
    fn exact_blocking_policy_and_high_authority_candidates_bypass_optional_caps()
    -> Result<(), Box<dyn Error>> {
        let requirements = vec![requirement(Some(50), true)?, requirement(None, false)?];
        let plan = QueryPlanner::default().plan_bounded(
            &requirements,
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let mut exact = candidate(50, 1, 1, 500, 1)?;
        exact.evidence = BTreeSet::from([MatchEvidence::ExactIdentity]);
        exact.features.exact_match = 1;
        exact.total_score = exact.features.balanced_score()?;
        let mut policy = candidate(51, 1, 1, 500, 1)?;
        policy.atom_kind = AtomKind::Policy;
        let mut authority = candidate(52, 1, 1, 500, 1)?;
        authority.instruction_authority = InstructionAuthority::Project;
        authority.features.authority = 7_500;
        authority.total_score = authority.features.balanced_score()?;
        let high_rank = candidate(53, 2, 2, 501, 10_000)?;
        let stages = vec![
            vec![exact.clone()],
            vec![policy.clone(), high_rank.clone()],
            vec![authority.clone(), high_rank],
        ];
        let reduced: BoundedRetrievalResult =
            RequirementAwareCandidateReducer.reduce(&plan, &result(&plan, &stages)?, &context())?;
        let versions: BTreeSet<_> = reduced
            .candidates
            .iter()
            .map(|candidate| candidate.candidate.version_id.clone())
            .collect();
        assert!(versions.contains(&exact.version_id));
        assert!(versions.contains(&policy.version_id));
        assert!(versions.contains(&authority.version_id));
        assert_eq!(reduced.counts.protected_candidates, 3);
        Ok(())
    }

    #[test]
    fn cancellation_and_plan_or_stage_drift_fail_before_submission() -> Result<(), Box<dyn Error>> {
        let plan = QueryPlanner::default().plan_bounded(
            &[requirement(None, false)?],
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let candidates = vec![vec![candidate(60, 1, 1, 600, 5_000)?], Vec::new()];
        let mut retrieval = result(&plan, &candidates)?;
        retrieval.plan_fingerprint = digest(999)?;
        assert_eq!(
            RequirementAwareCandidateReducer
                .reduce(&plan, &retrieval, &context())
                .map_err(|error| error.code()),
            Err(crate::RetrievalErrorCode::CorruptGeneration)
        );
        let cancelled = context();
        cancelled.cancellation.cancel();
        let clean = result(&plan, &candidates)?;
        assert_eq!(
            RequirementAwareCandidateReducer
                .reduce(&plan, &clean, &cancelled)
                .map_err(|error| error.code()),
            Err(crate::RetrievalErrorCode::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn frozen_hiero_shaped_hundred_request_intake_stays_below_ten_to_one()
    -> Result<(), Box<dyn Error>> {
        let plan = QueryPlanner::default().plan_bounded(
            &[requirement(None, false)?],
            &capacity(2)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let mut maximum_displaced_per_selected = 0_usize;
        for workflow in 0..100_u64 {
            let mut stage_candidates = Vec::new();
            for stage in &plan.stages {
                let candidates = (0..u64::try_from(stage.request.limit)?)
                    .map(|index| {
                        candidate(
                            10_000 + workflow * 100 + index,
                            index % 12,
                            1_000 + index % 24,
                            20_000 + index % 18,
                            5_000,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                stage_candidates.push(candidates);
            }
            let reduced = RequirementAwareCandidateReducer.reduce(
                &plan,
                &result(&plan, &stage_candidates)?,
                &context(),
            )?;
            assert!(!reduced.candidates.is_empty());
            maximum_displaced_per_selected =
                maximum_displaced_per_selected.max(reduced.candidates.len().saturating_sub(1));
        }
        assert!(maximum_displaced_per_selected < 10);
        Ok(())
    }

    #[test]
    fn protected_flood_fails_at_the_explicit_request_bound() -> Result<(), Box<dyn Error>> {
        let requirements = (0..257_u64)
            .map(|index| requirement(Some(30_000 + index), true))
            .collect::<Result<Vec<_>, _>>()?;
        let plan = QueryPlanner::default().plan_bounded(
            &requirements,
            &capacity(2)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let stages = (0..257_u64)
            .map(|index| {
                let mut exact = candidate(30_000 + index, index, 2_000 + index, 40_000 + index, 1)?;
                exact.evidence = BTreeSet::from([MatchEvidence::ExactIdentity]);
                exact.features.exact_match = 1;
                exact.total_score = exact.features.balanced_score()?;
                Ok(vec![exact])
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        assert_eq!(
            RequirementAwareCandidateReducer
                .reduce(&plan, &result(&plan, &stages)?, &context())
                .map_err(|error| error.code()),
            Err(crate::RetrievalErrorCode::LimitExceeded)
        );
        Ok(())
    }
}
