//! Post-governance alias coalescing, caps, and deterministic quantized diversity.

use crate::ranking_workspace::{RankingWorkspace, ranking_evidence, ranking_evidence_digest};
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
    /// Profile-bound, content-free winner-versus-runner-up evidence for requirement-aware ranking.
    pub ranking_evidence: Option<RequirementRankingEvidence>,
}

/// Stable reason an intake candidate was retained by requirement-aware ranking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateSelectionBasis {
    /// Exact, policy, or high-authority semantics bypassed ordinary competition.
    Protected,
    /// The candidate covered at least one still-uncovered blocking requirement.
    CriticalRequirement,
    /// The candidate added nonblocking requirement coverage.
    Requirement,
    /// The candidate won on its remaining deterministic score and diversity factors.
    Score,
}

/// Content-free score decomposition for one deterministic ranking comparison.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidateRankingFactors {
    /// Profile-validated retrieval score before contextual gains and penalties.
    pub base_score: i64,
    /// Gain from newly covered blocking requirements.
    pub critical_requirement_gain: i64,
    /// Gain from other newly covered requirements.
    pub requirement_gain: i64,
    /// Gain from distinct query concepts not already represented.
    pub concept_gain: i64,
    /// Gain from source, section, and evidence-kind diversity.
    pub diversity_gain: i64,
    /// Penalty for a weak generic lexical match.
    pub generic_penalty: i64,
    /// Penalty for redundant requirements and query concepts.
    pub redundancy_penalty: i64,
    /// Existing authenticated source, lineage, content, or kind similarity penalty.
    pub similarity_penalty: i64,
    /// Final checked score used for the deterministic comparison.
    pub adjusted_score: i64,
}

/// Reproducible explanation for one retained compiler-intake candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRankingDecision {
    /// One-based deterministic selection ordinal.
    pub ordinal: usize,
    /// Candidate retained at this ordinal.
    pub selected_version: VersionId,
    /// Why the candidate entered the retained set.
    pub basis: CandidateSelectionBasis,
    /// Number of newly covered requirements.
    pub newly_covered_requirements: usize,
    /// Number of newly covered blocking requirements.
    pub newly_covered_critical_requirements: usize,
    /// Number of newly covered distinct query-concept bits.
    pub newly_covered_concepts: u32,
    /// Whether the candidate introduced a new canonical source.
    pub source_diversity: bool,
    /// Whether the candidate introduced a new source section/path.
    pub section_diversity: bool,
    /// Whether the candidate introduced a new evidence kind.
    pub kind_diversity: bool,
    /// Exact factor decomposition for the selected candidate.
    pub factors: CandidateRankingFactors,
    /// Deterministic runner-up at the same selection state; v4 records retained runners only.
    pub next_best_version: Option<VersionId>,
    /// Runner-up adjusted score at the same selection state.
    pub next_best_adjusted_score: Option<i64>,
    /// Blocking requirements still uncovered after this decision.
    pub uncovered_critical_after: usize,
}

/// Complete digest-bound H2 ranking evidence carried into compilation and signed manifests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequirementRankingEvidence {
    /// Exact retrieval plan whose candidates and ranking configuration were used.
    pub plan_fingerprint: ContentDigest,
    /// Exact scoring-profile identifier.
    pub retrieval_profile_id: String,
    /// Exact scoring-profile digest.
    pub retrieval_profile_digest: ContentDigest,
    /// Sorted blocking requirement indices declared by the plan.
    pub critical_requirements: BTreeSet<usize>,
    /// Sorted blocking requirements not represented after bounded ranking.
    pub uncovered_critical_requirements: BTreeSet<usize>,
    /// Protected and competitive decisions in deterministic selection order.
    pub decisions: Vec<CandidateRankingDecision>,
    /// Content digest over every preceding field and decision factor.
    pub evidence_digest: ContentDigest,
}

impl RequirementRankingEvidence {
    /// Creates complete H2 evidence and derives its content digest from every explanation field.
    pub fn new(
        plan_fingerprint: ContentDigest,
        critical_requirements: BTreeSet<usize>,
        uncovered_critical_requirements: BTreeSet<usize>,
        decisions: Vec<CandidateRankingDecision>,
    ) -> Result<Self, RetrievalError> {
        Self::new_for_profile(
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
            plan_fingerprint,
            critical_requirements,
            uncovered_critical_requirements,
            decisions,
        )
    }

    /// Creates complete CIGAR 0.9.4 ranking evidence under the risk-reserved v4 profile.
    pub fn new_v4(
        plan_fingerprint: ContentDigest,
        critical_requirements: BTreeSet<usize>,
        uncovered_critical_requirements: BTreeSet<usize>,
        decisions: Vec<CandidateRankingDecision>,
    ) -> Result<Self, RetrievalError> {
        Self::new_for_profile(
            RetrievalProfile::BalancedV4,
            plan_fingerprint,
            critical_requirements,
            uncovered_critical_requirements,
            decisions,
        )
    }

    pub(crate) fn new_for_profile(
        profile: RetrievalProfile,
        plan_fingerprint: ContentDigest,
        critical_requirements: BTreeSet<usize>,
        uncovered_critical_requirements: BTreeSet<usize>,
        decisions: Vec<CandidateRankingDecision>,
    ) -> Result<Self, RetrievalError> {
        let evidence = Self::build_for_profile(
            profile,
            plan_fingerprint,
            critical_requirements,
            uncovered_critical_requirements,
            decisions,
        )?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub(crate) fn new_trusted_for_profile(
        profile: RetrievalProfile,
        plan_fingerprint: ContentDigest,
        critical_requirements: BTreeSet<usize>,
        uncovered_critical_requirements: BTreeSet<usize>,
        decisions: Vec<CandidateRankingDecision>,
    ) -> Result<Self, RetrievalError> {
        Self::build_for_profile(
            profile,
            plan_fingerprint,
            critical_requirements,
            uncovered_critical_requirements,
            decisions,
        )
    }

    fn build_for_profile(
        profile: RetrievalProfile,
        plan_fingerprint: ContentDigest,
        critical_requirements: BTreeSet<usize>,
        uncovered_critical_requirements: BTreeSet<usize>,
        decisions: Vec<CandidateRankingDecision>,
    ) -> Result<Self, RetrievalError> {
        if !profile.requirement_aware() {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        let retrieval_profile_id = profile.identifier().to_owned();
        let retrieval_profile_digest = profile.digest()?;
        let evidence_digest = ranking_evidence_digest(
            &plan_fingerprint,
            &retrieval_profile_id,
            &retrieval_profile_digest,
            &critical_requirements,
            &uncovered_critical_requirements,
            &decisions,
        )?;
        Ok(Self {
            plan_fingerprint,
            retrieval_profile_id,
            retrieval_profile_digest,
            critical_requirements,
            uncovered_critical_requirements,
            decisions,
            evidence_digest,
        })
    }

    /// Reproduces and validates the complete content-free explanation contract.
    pub fn validate(&self) -> Result<(), RetrievalError> {
        let profile = [
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
            RetrievalProfile::BalancedV4,
        ]
        .into_iter()
        .find(|profile| self.retrieval_profile_id == profile.identifier())
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let selection = if profile == RetrievalProfile::BalancedV4 {
            crate::QueryPlannerProfile::balanced_v4().candidate_selection
        } else {
            crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate()
                .candidate_selection
        };
        let selected = self
            .decisions
            .iter()
            .map(|decision| &decision.selected_version)
            .collect::<BTreeSet<_>>();
        let mut remaining_critical = self.critical_requirements.len();
        let decisions_valid = self.decisions.iter().enumerate().all(|(index, decision)| {
            let noncritical_requirements = decision
                .newly_covered_requirements
                .checked_sub(decision.newly_covered_critical_requirements);
            let expected_critical_gain = weighted_count(
                selection.critical_requirement_gain,
                decision.newly_covered_critical_requirements,
            );
            let expected_requirement_gain = noncritical_requirements
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
                .and_then(|count| weighted_count(selection.requirement_gain, count));
            let expected_concept_gain = weighted_count(
                selection.concept_gain,
                usize::try_from(decision.newly_covered_concepts).unwrap_or(usize::MAX),
            );
            let expected_diversity_gain = [
                (selection.source_diversity_gain, decision.source_diversity),
                (selection.section_diversity_gain, decision.section_diversity),
                (selection.kind_diversity_gain, decision.kind_diversity),
            ]
            .into_iter()
            .try_fold(0_i64, |total, (gain, applies)| {
                total
                    .checked_add(if applies { gain } else { 0 })
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
            });
            let expected_adjusted = decision
                .factors
                .base_score
                .checked_add(decision.factors.critical_requirement_gain)
                .and_then(|value| value.checked_add(decision.factors.requirement_gain))
                .and_then(|value| value.checked_add(decision.factors.concept_gain))
                .and_then(|value| value.checked_add(decision.factors.diversity_gain))
                .and_then(|value| value.checked_sub(decision.factors.generic_penalty))
                .and_then(|value| value.checked_sub(decision.factors.redundancy_penalty))
                .and_then(|value| value.checked_sub(decision.factors.similarity_penalty));
            let expected_basis = if decision.newly_covered_critical_requirements > 0 {
                CandidateSelectionBasis::CriticalRequirement
            } else if decision.newly_covered_requirements > 0 {
                CandidateSelectionBasis::Requirement
            } else {
                decision.basis
            };
            remaining_critical = remaining_critical
                .checked_sub(decision.newly_covered_critical_requirements)
                .unwrap_or(usize::MAX);
            decision.ordinal == index + 1
                && decision.next_best_version.is_some()
                    == decision.next_best_adjusted_score.is_some()
                && decision.next_best_version.as_ref() != Some(&decision.selected_version)
                && decision.next_best_version.as_ref().is_none_or(|version| {
                    profile != RetrievalProfile::BalancedV4 || selected.contains(version)
                })
                && decision
                    .next_best_adjusted_score
                    .is_none_or(|runner_up| decision.factors.adjusted_score >= runner_up)
                && expected_critical_gain == Ok(decision.factors.critical_requirement_gain)
                && expected_requirement_gain == Ok(decision.factors.requirement_gain)
                && expected_concept_gain == Ok(decision.factors.concept_gain)
                && expected_diversity_gain == Ok(decision.factors.diversity_gain)
                && [0, selection.generic_match_penalty].contains(&decision.factors.generic_penalty)
                && decision.factors.redundancy_penalty >= 0
                && decision.factors.similarity_penalty >= 0
                && expected_adjusted == Some(decision.factors.adjusted_score)
                && expected_basis == decision.basis
                && decision.uncovered_critical_after == remaining_critical
        });
        if self.retrieval_profile_id != profile.identifier()
            || self.retrieval_profile_digest != profile.digest()?
            || !self
                .uncovered_critical_requirements
                .is_subset(&self.critical_requirements)
            || remaining_critical != self.uncovered_critical_requirements.len()
            || selected.len() != self.decisions.len()
            || !decisions_valid
            || self.evidence_digest
                != ranking_evidence_digest(
                    &self.plan_fingerprint,
                    &self.retrieval_profile_id,
                    &self.retrieval_profile_digest,
                    &self.critical_requirements,
                    &self.uncovered_critical_requirements,
                    &self.decisions,
                )?
        {
            Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
pub(super) struct MergedCandidate {
    pub(super) candidate: CandidateRef,
    pub(super) requirement_indices: BTreeSet<usize>,
    pub(super) protected: bool,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ContentFamilyKey {
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
        self.reduce_internal(plan, retrieval, context, retrieval_profile, None)
    }

    /// Reduces a v4 plan whose risk classes were bound to one trusted operation class.
    pub fn reduce_v4_for_operation(
        &self,
        plan: &QueryPlan,
        retrieval: &StagedRetrievalResult,
        context: &RetrievalContext,
        operation_class: cigar_protocol::OperationClass,
    ) -> Result<BoundedRetrievalResult, RetrievalError> {
        self.reduce_internal(
            plan,
            retrieval,
            context,
            RetrievalProfile::BalancedV4,
            Some(operation_class),
        )
    }

    fn reduce_internal(
        &self,
        plan: &QueryPlan,
        retrieval: &StagedRetrievalResult,
        context: &RetrievalContext,
        retrieval_profile: RetrievalProfile,
        operation_class: Option<cigar_protocol::OperationClass>,
    ) -> Result<BoundedRetrievalResult, RetrievalError> {
        context.check()?;
        plan.candidate_bounds.profile.validate()?;
        if retrieval.plan_fingerprint != plan.plan_fingerprint
            || retrieval.stages.len() != plan.stages.len()
        {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        let requirement_aware = retrieval_profile.requirement_aware();
        let v4_risk_classes = if retrieval_profile == RetrievalProfile::BalancedV4 {
            plan.requirement_risk_classes(operation_class)?
        } else {
            Vec::new()
        };
        let critical_requirements = plan
            .stages
            .iter()
            .filter_map(|stage| stage.blocking.then_some(stage.requirement_index))
            .collect::<BTreeSet<_>>();
        if requirement_aware && critical_requirements.len() > 256 {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
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

        let mut selected;
        let mut ranking_decisions = Vec::new();
        let mut dense_uncovered_critical = None;
        let optional_candidates_absent = capped.is_empty();
        if requirement_aware {
            // Every protected candidate remains in compiler intake. H2 only gives that immutable
            // set a requirement-aware explanation order so a blocking stage can never lose recall
            // merely because another candidate happened to satisfy the same coarse requirement.
            let remaining = protected;
            let mut workspace = RankingWorkspace::new(
                &remaining,
                &critical_requirements,
                profile,
                &plan.candidate_bounds,
                &[],
            )?;
            while workspace.active_count() > 0 {
                let Some((winner, runner_up)) = workspace.winner_and_runner_up(false, context)?
                else {
                    return Err(RetrievalError::new(
                        RetrievalErrorCode::RequiredCandidateMissing,
                    ));
                };
                let candidate = remaining
                    .get(winner.ordinal)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                let evaluation = winner.evaluation;
                let basis = if evaluation.newly_covered_critical_requirements > 0 {
                    CandidateSelectionBasis::CriticalRequirement
                } else if evaluation.newly_covered_requirements > 0 {
                    CandidateSelectionBasis::Requirement
                } else {
                    CandidateSelectionBasis::Protected
                };
                ranking_decisions.push(CandidateRankingDecision {
                    ordinal: ranking_decisions.len() + 1,
                    selected_version: candidate.candidate.version_id.clone(),
                    basis,
                    newly_covered_requirements: evaluation.newly_covered_requirements,
                    newly_covered_critical_requirements: evaluation
                        .newly_covered_critical_requirements,
                    newly_covered_concepts: evaluation.newly_covered_concepts,
                    source_diversity: evaluation.source_diversity,
                    section_diversity: evaluation.section_diversity,
                    kind_diversity: evaluation.kind_diversity,
                    factors: evaluation.factors,
                    next_best_version: runner_up
                        .map(|ranked| {
                            remaining
                                .get(ranked.ordinal)
                                .map(|candidate| candidate.candidate.version_id.clone())
                                .ok_or_else(|| {
                                    RetrievalError::new(RetrievalErrorCode::CorruptGeneration)
                                })
                        })
                        .transpose()?,
                    next_best_adjusted_score: runner_up
                        .map(|ranked| ranked.evaluation.factors.adjusted_score),
                    uncovered_critical_after: workspace.uncovered_critical_after(winner.ordinal),
                });
                workspace.include(winner.ordinal, false)?;
            }
            if retrieval_profile == RetrievalProfile::BalancedV4 {
                dense_uncovered_critical = Some(workspace.uncovered_critical_requirements());
            }
            drop(workspace);
            selected = remaining;
        } else {
            selected = protected;
        }
        if requirement_aware && !capped.is_empty() {
            let mut workspace = if retrieval_profile == RetrievalProfile::BalancedV4 {
                RankingWorkspace::new_v4(
                    &capped,
                    &critical_requirements,
                    profile,
                    &plan.candidate_bounds,
                    &selected,
                    &v4_risk_classes,
                )?
            } else {
                RankingWorkspace::new(
                    &capped,
                    &critical_requirements,
                    profile,
                    &plan.candidate_bounds,
                    &selected,
                )?
            };
            let mut selected_count = selected.len();
            while selected_count < profile.absolute_compiler_candidates {
                context.check()?;
                let Some((winner, runner_up)) = workspace.winner_and_runner_up(true, context)?
                else {
                    break;
                };
                let candidate = capped
                    .get(winner.ordinal)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                let evaluation = winner.evaluation;
                let basis = if evaluation.newly_covered_critical_requirements > 0 {
                    CandidateSelectionBasis::CriticalRequirement
                } else if evaluation.newly_covered_requirements > 0 {
                    CandidateSelectionBasis::Requirement
                } else {
                    CandidateSelectionBasis::Score
                };
                ranking_decisions.push(CandidateRankingDecision {
                    ordinal: ranking_decisions.len() + 1,
                    selected_version: candidate.candidate.version_id.clone(),
                    basis,
                    newly_covered_requirements: evaluation.newly_covered_requirements,
                    newly_covered_critical_requirements: evaluation
                        .newly_covered_critical_requirements,
                    newly_covered_concepts: evaluation.newly_covered_concepts,
                    source_diversity: evaluation.source_diversity,
                    section_diversity: evaluation.section_diversity,
                    kind_diversity: evaluation.kind_diversity,
                    factors: evaluation.factors,
                    next_best_version: runner_up
                        .map(|ranked| {
                            capped
                                .get(ranked.ordinal)
                                .map(|candidate| candidate.candidate.version_id.clone())
                                .ok_or_else(|| {
                                    RetrievalError::new(RetrievalErrorCode::CorruptGeneration)
                                })
                        })
                        .transpose()?,
                    next_best_adjusted_score: runner_up
                        .map(|ranked| ranked.evaluation.factors.adjusted_score),
                    uncovered_critical_after: workspace.uncovered_critical_after(winner.ordinal),
                });
                workspace.include(winner.ordinal, true)?;
                selected_count = selected_count
                    .checked_add(1)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
            }
            dense_uncovered_critical = Some(workspace.uncovered_critical_requirements());
            let selected_flags = workspace.into_selected_flags();
            selected.extend(
                capped
                    .into_iter()
                    .zip(selected_flags)
                    .filter_map(|(candidate, retained)| (retained != 0).then_some(candidate)),
            );
        } else if !requirement_aware {
            let mut optional_lane_counts = BTreeMap::<LaneKind, usize>::new();
            let mut requirement_counts = BTreeMap::<usize, usize>::new();
            for candidate in &selected {
                for requirement in &candidate.requirement_indices {
                    *requirement_counts.entry(*requirement).or_default() += 1;
                }
            }
            let mut ranking_state =
                LegacySimilarityState::from_selected(&selected, &capped, profile);
            while selected.len() < profile.absolute_compiler_candidates {
                context.check()?;
                let mut ranked = capped
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
                        legacy_adjusted_score(candidate, &ranking_state)
                            .map(|score| (index, score, candidate))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ranked.sort_by(|left, right| {
                    right
                        .1
                        .cmp(&left.1)
                        .then_with(|| merged_candidate_order(left.2, right.2))
                });
                let Some((index, _score, _candidate)) = ranked.first().cloned() else {
                    break;
                };
                let winner = capped.remove(index);
                let lane = lane_for_atom_kind(winner.candidate.atom_kind);
                *optional_lane_counts.entry(lane).or_default() += 1;
                for requirement in &winner.requirement_indices {
                    *requirement_counts.entry(*requirement).or_default() += 1;
                }
                ranking_state.include(&winner, &capped, profile);
                selected.push(winner);
            }
        }
        let uncovered_critical_requirements = if let Some(uncovered) = dense_uncovered_critical {
            uncovered
        } else {
            let covered_requirements = selected
                .iter()
                .flat_map(|candidate| candidate.requirement_indices.iter().copied())
                .collect::<BTreeSet<_>>();
            critical_requirements
                .difference(&covered_requirements)
                .copied()
                .collect::<BTreeSet<_>>()
        };
        if requirement_aware && !uncovered_critical_requirements.is_empty() {
            return Err(RetrievalError::new(
                RetrievalErrorCode::RequiredCandidateMissing,
            ));
        }
        if !(requirement_aware && optional_candidates_absent) {
            selected.sort_by(merged_candidate_order);
        }
        counts.submitted_candidates = selected.len();
        if retrieval_profile == RetrievalProfile::BalancedV4 {
            let retained_versions = selected
                .iter()
                .map(|candidate| &candidate.candidate.version_id)
                .collect::<BTreeSet<_>>();
            for decision in &mut ranking_decisions {
                if decision
                    .next_best_version
                    .as_ref()
                    .is_some_and(|version| !retained_versions.contains(version))
                {
                    decision.next_best_version = None;
                    decision.next_best_adjusted_score = None;
                }
            }
        }
        let candidates = selected
            .into_iter()
            .map(|candidate| BoundedCandidate {
                candidate: candidate.candidate,
                requirement_indices: candidate.requirement_indices,
                protected: candidate.protected,
            })
            .collect();
        let ranking_evidence = requirement_aware
            .then(|| {
                ranking_evidence(
                    plan,
                    retrieval_profile,
                    critical_requirements,
                    uncovered_critical_requirements,
                    ranking_decisions,
                )
            })
            .transpose()?;
        Ok(BoundedRetrievalResult {
            plan_fingerprint: plan.plan_fingerprint.clone(),
            candidates,
            counts,
            ranking_evidence,
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

#[derive(Default)]
struct LegacySimilarityState {
    similarity_penalties: BTreeMap<VersionId, i64>,
}

impl LegacySimilarityState {
    fn from_selected(
        selected: &[MergedCandidate],
        remaining: &[MergedCandidate],
        profile: crate::CandidateSelectionProfile,
    ) -> Self {
        let mut state = Self::default();
        for candidate in selected {
            state.include(candidate, remaining, profile);
        }
        state
    }

    fn include(
        &mut self,
        selected: &MergedCandidate,
        remaining: &[MergedCandidate],
        profile: crate::CandidateSelectionProfile,
    ) {
        for candidate in remaining {
            let penalty = similarity_penalty(&candidate.candidate, &selected.candidate, profile);
            self.similarity_penalties
                .entry(candidate.candidate.version_id.clone())
                .and_modify(|current| *current = (*current).max(penalty))
                .or_insert(penalty);
        }
    }

    fn similarity_penalty(&self, candidate: &MergedCandidate) -> i64 {
        self.similarity_penalties
            .get(&candidate.candidate.version_id)
            .copied()
            .unwrap_or_default()
    }
}

fn legacy_adjusted_score(
    candidate: &MergedCandidate,
    state: &LegacySimilarityState,
) -> Result<i64, RetrievalError> {
    let similarity_penalty = state.similarity_penalty(candidate);
    candidate
        .candidate
        .total_score
        .checked_sub(similarity_penalty)
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
}

fn weighted_count(weight: i64, count: usize) -> Result<i64, RetrievalError> {
    weight
        .checked_mul(
            i64::try_from(count)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
        )
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

pub(super) fn content_family(candidate: &CandidateRef) -> ContentFamilyKey {
    ContentFamilyKey {
        atom_kind: candidate.atom_kind,
        content_digest: candidate.content_digest.clone(),
        classification: candidate.classification,
        instruction_authority: candidate.instruction_authority,
    }
}

pub(super) fn merged_candidate_order(left: &MergedCandidate, right: &MergedCandidate) -> Ordering {
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
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::{MergedCandidate, RequirementAwareCandidateReducer, validate_candidate_score};
    use crate::ranking_workspace::{
        CANCELLATION_SCAN_STRIDE, RankEvaluation, RankingWorkspace, ranking_evidence_digest,
        scan_poll_due,
    };
    use crate::{
        BoundedRetrievalResult, CandidateBatch, CandidateBounds, CandidateFeatures, CandidateRef,
        ExecutedStage, MatchEvidence, QueryPlan, QueryPlanner, RequirementRiskClass,
        RetrievalCapacity, RetrievalConsistency, RetrievalContext, RetrievalDisclosure,
        RetrievalProfile, RetrievalStage, StagedRetrievalResult,
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

    #[derive(Default)]
    struct ReferenceRankingState {
        covered_requirements: BTreeSet<usize>,
        covered_concepts: u64,
        sources: BTreeSet<SourceUri>,
        sections: BTreeSet<(SourceUri, Option<Vec<u8>>)>,
        kinds: BTreeSet<AtomKind>,
        similarity_penalties: BTreeMap<VersionId, i64>,
    }

    impl ReferenceRankingState {
        fn include<'a>(
            &mut self,
            selected: &MergedCandidate,
            remaining: impl IntoIterator<Item = &'a MergedCandidate>,
            profile: crate::CandidateSelectionProfile,
        ) {
            self.covered_requirements
                .extend(selected.requirement_indices.iter().copied());
            self.covered_concepts |= selected.candidate.features.entity_coverage_bits;
            self.sources
                .insert(selected.candidate.canonical_uri.clone());
            self.sections.insert((
                selected.candidate.canonical_uri.clone(),
                selected
                    .candidate
                    .relative_path
                    .as_ref()
                    .map(|path| path.as_bytes().to_vec()),
            ));
            self.kinds.insert(selected.candidate.atom_kind);
            for candidate in remaining {
                let penalty =
                    super::similarity_penalty(&candidate.candidate, &selected.candidate, profile);
                self.similarity_penalties
                    .entry(candidate.candidate.version_id.clone())
                    .and_modify(|current| *current = (*current).max(penalty))
                    .or_insert(penalty);
            }
        }
    }

    fn reference_evaluation(
        candidate: &MergedCandidate,
        critical_requirements: &BTreeSet<usize>,
        profile: crate::CandidateSelectionProfile,
        state: &ReferenceRankingState,
    ) -> Result<RankEvaluation, crate::RetrievalError> {
        let new_requirements = candidate
            .requirement_indices
            .difference(&state.covered_requirements)
            .copied()
            .collect::<BTreeSet<_>>();
        let newly_covered_critical_requirements =
            new_requirements.intersection(critical_requirements).count();
        let newly_covered_requirements = new_requirements.len();
        let newly_covered_noncritical = newly_covered_requirements
            .checked_sub(newly_covered_critical_requirements)
            .ok_or_else(|| crate::RetrievalError::new(crate::RetrievalErrorCode::LimitExceeded))?;
        let concepts = candidate.candidate.features.entity_coverage_bits;
        let newly_covered_concepts = (concepts & !state.covered_concepts).count_ones();
        let redundant_concepts = (concepts & state.covered_concepts).count_ones();
        let redundant_requirements = candidate
            .requirement_indices
            .intersection(&state.covered_requirements)
            .count();
        let section = (
            candidate.candidate.canonical_uri.clone(),
            candidate
                .candidate
                .relative_path
                .as_ref()
                .map(|path| path.as_bytes().to_vec()),
        );
        let source_diversity = !state.sources.contains(&candidate.candidate.canonical_uri);
        let section_diversity = !state.sections.contains(&section);
        let kind_diversity = !state.kinds.contains(&candidate.candidate.atom_kind);
        let generic_match = candidate
            .candidate
            .evidence
            .contains(&MatchEvidence::Lexical)
            && concepts.count_ones() <= 1
            && !candidate.candidate.evidence.iter().any(|evidence| {
                matches!(
                    evidence,
                    MatchEvidence::ExactIdentity
                        | MatchEvidence::ExactPath
                        | MatchEvidence::DeclaredTerm
                )
            });
        let critical_requirement_gain = super::weighted_count(
            profile.critical_requirement_gain,
            newly_covered_critical_requirements,
        )?;
        let requirement_gain =
            super::weighted_count(profile.requirement_gain, newly_covered_noncritical)?;
        let concept_gain = super::weighted_count(
            profile.concept_gain,
            usize::try_from(newly_covered_concepts).map_err(|_error| {
                crate::RetrievalError::new(crate::RetrievalErrorCode::LimitExceeded)
            })?,
        )?;
        let diversity_gain = [
            (profile.source_diversity_gain, source_diversity),
            (profile.section_diversity_gain, section_diversity),
            (profile.kind_diversity_gain, kind_diversity),
        ]
        .into_iter()
        .try_fold(0_i64, |total, (gain, applies)| {
            total
                .checked_add(if applies { gain } else { 0 })
                .ok_or_else(|| crate::RetrievalError::new(crate::RetrievalErrorCode::LimitExceeded))
        })?;
        let generic_penalty = if generic_match {
            profile.generic_match_penalty
        } else {
            0
        };
        let redundancy_penalty = super::weighted_count(
            profile.redundant_requirement_penalty,
            redundant_requirements,
        )?
        .checked_add(super::weighted_count(
            profile.redundant_concept_penalty,
            usize::try_from(redundant_concepts).map_err(|_error| {
                crate::RetrievalError::new(crate::RetrievalErrorCode::LimitExceeded)
            })?,
        )?)
        .ok_or_else(|| crate::RetrievalError::new(crate::RetrievalErrorCode::LimitExceeded))?;
        let similarity_penalty = state
            .similarity_penalties
            .get(&candidate.candidate.version_id)
            .copied()
            .unwrap_or_default();
        let adjusted_score = candidate
            .candidate
            .total_score
            .checked_add(critical_requirement_gain)
            .and_then(|value| value.checked_add(requirement_gain))
            .and_then(|value| value.checked_add(concept_gain))
            .and_then(|value| value.checked_add(diversity_gain))
            .and_then(|value| value.checked_sub(generic_penalty))
            .and_then(|value| value.checked_sub(redundancy_penalty))
            .and_then(|value| value.checked_sub(similarity_penalty))
            .ok_or_else(|| crate::RetrievalError::new(crate::RetrievalErrorCode::LimitExceeded))?;
        Ok(RankEvaluation {
            factors: super::CandidateRankingFactors {
                base_score: candidate.candidate.total_score,
                critical_requirement_gain,
                requirement_gain,
                concept_gain,
                diversity_gain,
                generic_penalty,
                redundancy_penalty,
                similarity_penalty,
                adjusted_score,
            },
            newly_covered_requirements,
            newly_covered_critical_requirements,
            newly_covered_concepts,
            source_diversity,
            section_diversity,
            kind_diversity,
        })
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ReferenceStep {
        selected: VersionId,
        evaluation: RankEvaluation,
        runner_up: Option<(VersionId, i64)>,
        uncovered_after: usize,
    }

    fn reference_sequence(
        candidates: &[MergedCandidate],
        critical: &BTreeSet<usize>,
        profile: crate::CandidateSelectionProfile,
    ) -> Result<(Vec<ReferenceStep>, BTreeSet<usize>), crate::RetrievalError> {
        let mut active = (0..candidates.len()).collect::<Vec<_>>();
        let mut state = ReferenceRankingState::default();
        let mut steps = Vec::new();
        while !active.is_empty() {
            let uncovered = critical
                .difference(&state.covered_requirements)
                .copied()
                .collect::<BTreeSet<_>>();
            let mut ranked = active
                .iter()
                .copied()
                .filter(|ordinal| {
                    uncovered.is_empty()
                        || !candidates[*ordinal]
                            .requirement_indices
                            .is_disjoint(&uncovered)
                })
                .map(|ordinal| {
                    reference_evaluation(&candidates[ordinal], critical, profile, &state)
                        .map(|evaluation| (ordinal, evaluation))
                })
                .collect::<Result<Vec<_>, _>>()?;
            ranked.sort_by(|left, right| {
                right
                    .1
                    .factors
                    .adjusted_score
                    .cmp(&left.1.factors.adjusted_score)
                    .then_with(|| {
                        super::merged_candidate_order(&candidates[left.0], &candidates[right.0])
                    })
            });
            let Some((winner, evaluation)) = ranked.first().copied() else {
                break;
            };
            let runner_up = ranked.get(1).map(|(ordinal, evaluation)| {
                (
                    candidates[*ordinal].candidate.version_id.clone(),
                    evaluation.factors.adjusted_score,
                )
            });
            let mut covered_after = state.covered_requirements.clone();
            covered_after.extend(candidates[winner].requirement_indices.iter().copied());
            steps.push(ReferenceStep {
                selected: candidates[winner].candidate.version_id.clone(),
                evaluation,
                runner_up,
                uncovered_after: critical.difference(&covered_after).count(),
            });
            active.retain(|ordinal| *ordinal != winner);
            state.include(
                &candidates[winner],
                active.iter().map(|ordinal| &candidates[*ordinal]),
                profile,
            );
        }
        let uncovered = critical
            .difference(&state.covered_requirements)
            .copied()
            .collect();
        Ok((steps, uncovered))
    }

    fn dense_sequence(
        candidates: &[MergedCandidate],
        critical: &BTreeSet<usize>,
        profile: crate::CandidateSelectionProfile,
    ) -> Result<(Vec<ReferenceStep>, BTreeSet<usize>), crate::RetrievalError> {
        let bounds = CandidateBounds {
            requirement_limits: (0..256).map(|index| (index, 512)).collect(),
            lane_limits: [
                LaneKind::Rules,
                LaneKind::Task,
                LaneKind::History,
                LaneKind::Tools,
                LaneKind::Evidence,
            ]
            .into_iter()
            .map(|lane| (lane, 512))
            .collect(),
            profile,
        };
        let mut workspace = RankingWorkspace::new(candidates, critical, profile, &bounds, &[])?;
        let mut steps = Vec::new();
        while workspace.active_count() > 0 {
            let Some((winner, runner_up)) = workspace.winner_and_runner_up(false, &context())?
            else {
                break;
            };
            steps.push(ReferenceStep {
                selected: candidates[winner.ordinal].candidate.version_id.clone(),
                evaluation: winner.evaluation,
                runner_up: runner_up.map(|runner| {
                    (
                        candidates[runner.ordinal].candidate.version_id.clone(),
                        runner.evaluation.factors.adjusted_score,
                    )
                }),
                uncovered_after: workspace.uncovered_critical_after(winner.ordinal),
            });
            workspace.include(winner.ordinal, false)?;
        }
        Ok((steps, workspace.uncovered_critical_requirements()))
    }

    fn generated_pool(pool: u64) -> Result<Vec<MergedCandidate>, Box<dyn Error>> {
        let mut state = pool.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut output = Vec::new();
        for ordinal in 0..8_u64 {
            let random = next();
            let identity = pool
                .checked_mul(8)
                .and_then(|value| value.checked_add(ordinal))
                .and_then(|value| value.checked_add(1_000))
                .ok_or("generated identity overflow")?;
            let mut item = candidate_for_profile(
                identity,
                random % 5,
                random.rotate_left(7) % 17,
                random.rotate_left(13) % 29,
                u16::try_from(1_000 + random % 9_001)?,
                RetrievalProfile::BalancedV2RequirementAwareCandidate,
            )?;
            item.features.entity_coverage_bits = random.rotate_left(23);
            if random & 1 != 0 {
                item.evidence.insert(MatchEvidence::DeclaredTerm);
            }
            item.atom_kind = match random % 4 {
                0 => AtomKind::SourceCode,
                1 => AtomKind::Documentation,
                2 => AtomKind::Test,
                _ => AtomKind::Artifact,
            };
            item.total_score = item
                .features
                .score(RetrievalProfile::BalancedV2RequirementAwareCandidate)?;
            let mut requirements = (0..16)
                .filter(|index| random.rotate_left(31) & (1_u64 << index) != 0)
                .collect::<BTreeSet<_>>();
            if requirements.is_empty() {
                requirements.insert(usize::try_from(random % 16)?);
            }
            output.push(MergedCandidate {
                candidate: item,
                requirement_indices: requirements,
                protected: true,
            });
        }
        output.sort_by(super::merged_candidate_order);
        Ok(output)
    }

    #[test]
    fn dense_workspace_matches_sorting_reference_for_102400_generated_cases()
    -> Result<(), Box<dyn Error>> {
        let profile = crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate()
            .candidate_selection;
        let profile_id = RetrievalProfile::BalancedV2RequirementAwareCandidate.identifier();
        let profile_digest = RetrievalProfile::BalancedV2RequirementAwareCandidate.digest()?;
        let plan_fingerprint = digest(42)?;
        let mut cases = 0_usize;
        for pool_id in 0..1_024_u64 {
            let candidates = generated_pool(pool_id)?;
            for variant in 0..100_u64 {
                let critical = (0..16)
                    .filter(|index| {
                        let mask = pool_id.rotate_left(11) ^ variant.wrapping_mul(0x9e37_79b9);
                        mask & (1_u64 << index) != 0
                    })
                    .collect::<BTreeSet<_>>();
                let reference = reference_sequence(&candidates, &critical, profile)?;
                let dense = dense_sequence(&candidates, &critical, profile)?;
                assert_eq!(dense, reference, "pool {pool_id}, variant {variant}");
                let decisions = dense
                    .0
                    .iter()
                    .enumerate()
                    .map(|(index, step)| super::CandidateRankingDecision {
                        ordinal: index + 1,
                        selected_version: step.selected.clone(),
                        basis: if step.evaluation.newly_covered_critical_requirements > 0 {
                            super::CandidateSelectionBasis::CriticalRequirement
                        } else if step.evaluation.newly_covered_requirements > 0 {
                            super::CandidateSelectionBasis::Requirement
                        } else {
                            super::CandidateSelectionBasis::Protected
                        },
                        newly_covered_requirements: step.evaluation.newly_covered_requirements,
                        newly_covered_critical_requirements: step
                            .evaluation
                            .newly_covered_critical_requirements,
                        newly_covered_concepts: step.evaluation.newly_covered_concepts,
                        source_diversity: step.evaluation.source_diversity,
                        section_diversity: step.evaluation.section_diversity,
                        kind_diversity: step.evaluation.kind_diversity,
                        factors: step.evaluation.factors,
                        next_best_version: step.runner_up.as_ref().map(|runner| runner.0.clone()),
                        next_best_adjusted_score: step.runner_up.as_ref().map(|runner| runner.1),
                        uncovered_critical_after: step.uncovered_after,
                    })
                    .collect::<Vec<_>>();
                let digest = ranking_evidence_digest(
                    &plan_fingerprint,
                    profile_id,
                    &profile_digest,
                    &critical,
                    &dense.1,
                    &decisions,
                )?;
                assert_eq!(digest.as_str().len(), 68);
                cases += 1;
            }
        }
        assert_eq!(cases, 102_400);
        Ok(())
    }

    #[test]
    fn ranking_similarity_cache_updates_each_candidate_pair_once() -> Result<(), Box<dyn Error>> {
        const CANDIDATES: usize = 128;
        let remaining = (0..CANDIDATES)
            .map(|index| {
                Ok(MergedCandidate {
                    candidate: candidate(
                        u64::try_from(index + 1)?,
                        u64::try_from(index + 1)?,
                        u64::try_from(index + 1)?,
                        u64::try_from(index + 1)?,
                        8_000,
                    )?,
                    requirement_indices: BTreeSet::from([0]),
                    protected: false,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let profile = crate::CandidateSelectionProfile::default();
        let bounds = CandidateBounds {
            requirement_limits: BTreeMap::from([(0, CANDIDATES)]),
            lane_limits: BTreeMap::from([(LaneKind::Evidence, CANDIDATES)]),
            profile,
        };
        let mut workspace =
            RankingWorkspace::new(&remaining, &BTreeSet::new(), profile, &bounds, &[])?;
        while workspace.active_count() > 0 {
            let (winner, _runner_up) = workspace
                .winner_and_runner_up(false, &context())?
                .ok_or("missing dense winner")?;
            workspace.include(winner.ordinal, false)?;
        }

        let cached_updates = CANDIDATES * (CANDIDATES - 1) / 2;
        let prior_rescans = CANDIDATES * (CANDIDATES - 1) * (CANDIDATES + 1) / 6;
        assert_eq!(workspace.similarity_update_count(), cached_updates);
        assert_eq!(cached_updates, 8_128);
        assert_eq!(prior_rescans, 349_504);
        Ok(())
    }

    #[test]
    fn v4_reserves_independent_effect_evidence_then_stops_at_nonpositive_marginal_utility()
    -> Result<(), Box<dyn Error>> {
        let profile = crate::QueryPlannerProfile::balanced_v4().candidate_selection;
        let mut candidates = [
            (1, 1, 1, 1, 9_000),
            (2, 1, 2, 2, 8_900),
            (3, 2, 2, 2, 8_800),
            (4, 3, 3, 3, 8_700),
        ]
        .into_iter()
        .map(|(value, source, lineage, content, score)| {
            Ok(MergedCandidate {
                candidate: candidate_for_profile(
                    value,
                    source,
                    lineage,
                    content,
                    score,
                    RetrievalProfile::BalancedV4,
                )?,
                requirement_indices: BTreeSet::from([0]),
                protected: false,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        candidates.sort_by(super::merged_candidate_order);
        let bounds = CandidateBounds {
            requirement_limits: BTreeMap::from([(0, candidates.len())]),
            lane_limits: BTreeMap::from([(LaneKind::Evidence, candidates.len())]),
            profile,
        };
        let mut v4 = RankingWorkspace::new_v4(
            &candidates,
            &BTreeSet::from([0]),
            profile,
            &bounds,
            &[],
            &[RequirementRiskClass::CriticalEffect],
        )?;
        let first = v4
            .winner_and_runner_up(true, &context())?
            .ok_or("missing primary evidence")?
            .0;
        assert_eq!(candidates[first.ordinal].candidate.version_id, version(1)?);
        v4.include(first.ordinal, true)?;

        let second = v4
            .winner_and_runner_up(true, &context())?
            .ok_or("missing independent corroborator")?
            .0;
        assert_eq!(candidates[second.ordinal].candidate.version_id, version(3)?);
        v4.include(second.ordinal, true)?;
        assert!(v4.winner_and_runner_up(true, &context())?.is_none());

        let mut v3 =
            RankingWorkspace::new(&candidates, &BTreeSet::from([0]), profile, &bounds, &[])?;
        let mut v3_selected = 0;
        while let Some((winner, _)) = v3.winner_and_runner_up(true, &context())? {
            v3.include(winner.ordinal, true)?;
            v3_selected += 1;
        }
        assert_eq!(v3_selected, candidates.len());
        Ok(())
    }

    #[test]
    fn v4_reducer_emits_valid_profile_bound_evidence_and_reduces_redundant_intake()
    -> Result<(), Box<dyn Error>> {
        let v4_plan = QueryPlanner::new_with_retrieval_profile(
            crate::QueryPlannerProfile::balanced_v4(),
            RetrievalProfile::BalancedV4,
        )?
        .plan_bounded(
            &[requirement(None, false)?],
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let v3_plan = QueryPlanner::new_with_retrieval_profile(
            crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?
        .plan_bounded(
            &[requirement(None, false)?],
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let first = candidate_for_profile(93, 1, 1, 903, 9_000, RetrievalProfile::BalancedV4)?;
        let second = candidate_for_profile(94, 2, 2, 904, 8_000, RetrievalProfile::BalancedV4)?;
        let batches = vec![vec![first.clone(), second.clone()], vec![first, second]];
        let v4 = RequirementAwareCandidateReducer.reduce_with_profile(
            &v4_plan,
            &result(&v4_plan, &batches)?,
            &context(),
            RetrievalProfile::BalancedV4,
        )?;
        let v3 = RequirementAwareCandidateReducer.reduce_with_profile(
            &v3_plan,
            &result(&v3_plan, &batches)?,
            &context(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        assert_eq!(v4.candidates.len(), 1);
        assert_eq!(v3.candidates.len(), 2);
        let evidence = v4.ranking_evidence.ok_or("missing v4 evidence")?;
        assert_eq!(
            evidence.retrieval_profile_id,
            "cigar.retrieval-profile.balanced.v4"
        );
        evidence.validate()?;
        assert_eq!(evidence.decisions.len(), 1);
        assert_eq!(evidence.decisions[0].next_best_version, None);
        assert_eq!(evidence.decisions[0].next_best_adjusted_score, None);
        Ok(())
    }

    #[test]
    fn dense_requirement_bit_boundaries_and_fast_paths_are_fail_closed()
    -> Result<(), Box<dyn Error>> {
        let profile = crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate()
            .candidate_selection;
        let boundaries = BTreeSet::from([0, 63, 64, 127, 128, 191, 192, 255]);
        let item = MergedCandidate {
            candidate: candidate_for_profile(
                91,
                1,
                1,
                901,
                8_000,
                RetrievalProfile::BalancedV2RequirementAwareCandidate,
            )?,
            requirement_indices: boundaries.clone(),
            protected: true,
        };
        let bounds = CandidateBounds {
            requirement_limits: boundaries.iter().map(|index| (*index, 1)).collect(),
            lane_limits: BTreeMap::from([(LaneKind::Evidence, 1)]),
            profile,
        };
        let candidates = vec![item.clone()];
        let mut workspace = RankingWorkspace::new(&candidates, &boundaries, profile, &bounds, &[])?;
        let (winner, runner_up) = workspace
            .winner_and_runner_up(false, &context())?
            .ok_or("one-candidate fast path did not select")?;
        assert!(runner_up.is_none());
        assert_eq!(
            winner.evaluation.newly_covered_requirements,
            boundaries.len()
        );
        assert_eq!(
            winner.evaluation.newly_covered_critical_requirements,
            boundaries.len()
        );
        workspace.include(winner.ordinal, false)?;
        assert!(workspace.uncovered_critical_requirements().is_empty());
        assert!(workspace.winner_and_runner_up(false, &context())?.is_none());

        let empty: Vec<MergedCandidate> = Vec::new();
        let empty_workspace =
            RankingWorkspace::new(&empty, &BTreeSet::new(), profile, &bounds, &[])?;
        assert!(
            empty_workspace
                .winner_and_runner_up(false, &context())?
                .is_none()
        );

        let zero_bounds = CandidateBounds {
            requirement_limits: BTreeMap::from([(0, 0)]),
            lane_limits: BTreeMap::from([(LaneKind::Evidence, 0)]),
            profile,
        };
        let optional = MergedCandidate {
            requirement_indices: BTreeSet::from([0]),
            protected: false,
            ..item.clone()
        };
        let optional_candidates = vec![optional];
        let zero_workspace = RankingWorkspace::new(
            &optional_candidates,
            &BTreeSet::new(),
            profile,
            &zero_bounds,
            &[],
        )?;
        assert!(
            zero_workspace
                .winner_and_runner_up(true, &context())?
                .is_none()
        );

        let preselected = vec![MergedCandidate {
            requirement_indices: BTreeSet::from([0]),
            protected: true,
            ..item.clone()
        }];
        let covered_workspace = RankingWorkspace::new(
            &optional_candidates,
            &BTreeSet::from([0]),
            profile,
            &bounds,
            &preselected,
        )?;
        let (covered_winner, _) = covered_workspace
            .winner_and_runner_up(false, &context())?
            .ok_or("already-covered fast path did not select")?;
        assert_eq!(
            covered_winner
                .evaluation
                .newly_covered_critical_requirements,
            0
        );

        let invalid = vec![MergedCandidate {
            requirement_indices: BTreeSet::from([256]),
            ..item
        }];
        assert_eq!(
            RankingWorkspace::new(&invalid, &BTreeSet::new(), profile, &bounds, &[])
                .err()
                .map(crate::RetrievalError::code),
            Some(crate::RetrievalErrorCode::LimitExceeded)
        );
        assert_eq!(CANCELLATION_SCAN_STRIDE, 32);
        let mut previous_poll = 0;
        for ordinal in (0..=512).filter(|ordinal| scan_poll_due(*ordinal)) {
            assert!(ordinal - previous_poll <= CANCELLATION_SCAN_STRIDE);
            previous_poll = ordinal;
        }
        assert_eq!(previous_poll, 512);

        let oversized_bounds = CandidateBounds {
            requirement_limits: BTreeMap::from([(0, usize::from(u16::MAX) + 1)]),
            lane_limits: BTreeMap::from([(LaneKind::Evidence, 1)]),
            profile,
        };
        assert_eq!(
            RankingWorkspace::new(
                &optional_candidates,
                &BTreeSet::new(),
                profile,
                &oversized_bounds,
                &[],
            )
            .err()
            .map(crate::RetrievalError::code),
            Some(crate::RetrievalErrorCode::LimitExceeded)
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled_context = RetrievalContext {
            cancellation,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        assert_eq!(
            covered_workspace
                .winner_and_runner_up(false, &cancelled_context)
                .map_err(crate::RetrievalError::code),
            Err(crate::RetrievalErrorCode::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn dense_ranking_arithmetic_fails_closed_at_integer_bounds() -> Result<(), Box<dyn Error>> {
        assert_eq!(super::weighted_count(i64::MAX, 1)?, i64::MAX);
        assert_eq!(
            super::weighted_count(i64::MAX, 2)
                .err()
                .map(crate::RetrievalError::code),
            Some(crate::RetrievalErrorCode::LimitExceeded)
        );
        assert_eq!(
            super::weighted_count(1, usize::MAX)
                .err()
                .map(crate::RetrievalError::code),
            Some(crate::RetrievalErrorCode::LimitExceeded)
        );

        let profile = crate::CandidateSelectionProfile {
            critical_requirement_gain: i64::MAX,
            ..crate::QueryPlannerProfile::balanced_v4().candidate_selection
        };
        let candidates = vec![MergedCandidate {
            candidate: candidate_for_profile(92, 1, 1, 902, 8_000, RetrievalProfile::BalancedV4)?,
            requirement_indices: BTreeSet::from([0]),
            protected: false,
        }];
        let bounds = CandidateBounds {
            requirement_limits: BTreeMap::from([(0, 1)]),
            lane_limits: BTreeMap::from([(LaneKind::Evidence, 1)]),
            profile,
        };
        let workspace = RankingWorkspace::new_v4(
            &candidates,
            &BTreeSet::from([0]),
            profile,
            &bounds,
            &[],
            &[RequirementRiskClass::Blocking],
        )?;
        assert_eq!(
            workspace
                .winner_and_runner_up(true, &context())
                .map_err(crate::RetrievalError::code),
            Err(crate::RetrievalErrorCode::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    #[ignore = "explicit H094-200 measurement matrix"]
    fn benchmark_dense_ranking_candidate_critical_and_protected_matrix()
    -> Result<(), Box<dyn Error>> {
        let profile = crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate()
            .candidate_selection;
        for candidate_count in [0_usize, 1, 2, 8, 32, 64, 128, 256, 512] {
            for critical_count in [0_usize, 1, 8, 64, 256] {
                for protected_percent in [0_usize, 10, 50, 100] {
                    let requirement_modulus = critical_count.max(1);
                    let mut all = (0..candidate_count)
                        .map(|index| {
                            Ok(MergedCandidate {
                                candidate: candidate_for_profile(
                                    u64::try_from(index + 1)?,
                                    u64::try_from(index % 17 + 1)?,
                                    u64::try_from(index % 31 + 1)?,
                                    u64::try_from(index % 47 + 1)?,
                                    u16::try_from(5_000 + index % 5_001)?,
                                    RetrievalProfile::BalancedV2RequirementAwareCandidate,
                                )?,
                                requirement_indices: BTreeSet::from([index % requirement_modulus]),
                                protected: false,
                            })
                        })
                        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
                    all.sort_by(super::merged_candidate_order);
                    let protected_count = candidate_count
                        .checked_mul(protected_percent)
                        .ok_or("protected count overflow")?
                        / 100;
                    let preselected = all[..protected_count].to_vec();
                    let candidates = all[protected_count..].to_vec();
                    let critical = (0..critical_count).collect::<BTreeSet<_>>();
                    let requirement_limits = (0..requirement_modulus)
                        .map(|requirement| (requirement, candidate_count.max(1)))
                        .collect();
                    let bounds = CandidateBounds {
                        requirement_limits,
                        lane_limits: BTreeMap::from([(LaneKind::Evidence, candidate_count.max(1))]),
                        profile,
                    };
                    let started = Instant::now();
                    let mut workspace = RankingWorkspace::new(
                        &candidates,
                        &critical,
                        profile,
                        &bounds,
                        &preselected,
                    )?;
                    let mut selected = preselected.len();
                    while let Some((winner, _runner_up)) =
                        workspace.winner_and_runner_up(true, &context())?
                    {
                        workspace.include(winner.ordinal, true)?;
                        selected = selected.checked_add(1).ok_or("selected count overflow")?;
                    }
                    std::hint::black_box(&workspace);
                    println!(
                        "{{\"candidates\":{candidate_count},\"critical\":{critical_count},\"protected_percent\":{protected_percent},\"selected\":{selected},\"elapsed_ns\":{}}}",
                        started.elapsed().as_nanos()
                    );
                }
            }
        }
        Ok(())
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

    #[test]
    fn h2_ranking_covers_critical_requirements_before_a_higher_scoring_generic_match()
    -> Result<(), Box<dyn Error>> {
        let requirements = vec![requirement(None, true)?, requirement(None, true)?];
        let plan = QueryPlanner::new_with_retrieval_profile(
            crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?
        .plan_bounded(
            &requirements,
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let mut generic = candidate_for_profile(
            81,
            1,
            1,
            801,
            9_500,
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        generic.features.entity_coverage_bits = 0b0001;
        generic.total_score = generic
            .features
            .score(RetrievalProfile::BalancedV2RequirementAwareCandidate)?;
        let mut useful = candidate_for_profile(
            82,
            2,
            2,
            802,
            8_000,
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        useful.features.entity_coverage_bits = 0b1110;
        useful.total_score = useful
            .features
            .score(RetrievalProfile::BalancedV2RequirementAwareCandidate)?;
        let mut stages = vec![Vec::new(); plan.stages.len()];
        for (index, stage) in plan.stages.iter().enumerate() {
            if stage.request.stage == RetrievalStage::Lexical {
                *stages.get_mut(index).ok_or("missing stage slot")? =
                    if stage.requirement_index == 0 {
                        vec![generic.clone(), useful.clone()]
                    } else {
                        vec![useful.clone()]
                    };
            }
        }
        let reduced = RequirementAwareCandidateReducer.reduce_with_profile(
            &plan,
            &result(&plan, &stages)?,
            &context(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        let evidence = reduced
            .ranking_evidence
            .ok_or("missing H2 ranking evidence")?;
        evidence.validate()?;
        assert_eq!(
            evidence.evidence_digest.as_str(),
            "12208d1eb384fb39a929aab2ce1d79efdd9034be8218abf4eccf9e6871d0ccd71602"
        );
        assert!(evidence.uncovered_critical_requirements.is_empty());
        let decision = evidence.decisions.first().ok_or("missing H2 decision")?;
        assert_eq!(decision.selected_version, useful.version_id);
        assert_eq!(
            decision.basis,
            super::CandidateSelectionBasis::CriticalRequirement
        );
        assert_eq!(decision.newly_covered_critical_requirements, 2);
        assert_eq!(decision.newly_covered_concepts, 3);
        assert_eq!(decision.next_best_version, Some(generic.version_id.clone()));
        assert!(
            decision.factors.adjusted_score
                > decision
                    .next_best_adjusted_score
                    .ok_or("missing runner-up score")?
        );
        let generic_decision = evidence
            .decisions
            .iter()
            .find(|item| item.selected_version == generic.version_id)
            .ok_or("generic candidate was not explicitly explained")?;
        assert_eq!(generic_decision.factors.generic_penalty, 2_000_000);
        assert!(generic_decision.factors.redundancy_penalty > 0);
        Ok(())
    }

    #[test]
    fn h2_ties_explanations_and_evidence_digest_are_permutation_stable()
    -> Result<(), Box<dyn Error>> {
        let plan = QueryPlanner::new_with_retrieval_profile(
            crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?
        .plan_bounded(
            &[requirement(None, false)?],
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let mut earlier = candidate_for_profile(
            83,
            3,
            3,
            803,
            8_000,
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        earlier.canonical_uri = SourceUri::new("file:///source/a.md")?;
        earlier.features.entity_coverage_bits = 0b11;
        earlier.total_score = earlier
            .features
            .score(RetrievalProfile::BalancedV2RequirementAwareCandidate)?;
        let mut later = earlier.clone();
        later.version_id = version(84)?;
        later.lineage_id = lineage(4)?;
        later.content_digest = digest(804)?;
        later.canonical_uri = SourceUri::new("file:///source/z.md")?;
        let first = vec![vec![later.clone(), earlier.clone()], Vec::new()];
        let second = vec![vec![earlier.clone(), later.clone()], Vec::new()];
        let left = RequirementAwareCandidateReducer.reduce_with_profile(
            &plan,
            &result(&plan, &first)?,
            &context(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        let right = RequirementAwareCandidateReducer.reduce_with_profile(
            &plan,
            &result(&plan, &second)?,
            &context(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        assert_eq!(left, right);
        let evidence = left.ranking_evidence.ok_or("missing ranking evidence")?;
        let first_decision = evidence.decisions.first().ok_or("missing first decision")?;
        assert_eq!(first_decision.selected_version, earlier.version_id);
        assert_eq!(first_decision.next_best_version, Some(later.version_id));
        let mut corrupted = evidence;
        corrupted
            .decisions
            .first_mut()
            .ok_or("missing decision to corrupt")?
            .factors
            .adjusted_score ^= 1;
        assert_eq!(
            corrupted.validate().map_err(|error| error.code()),
            Err(crate::RetrievalErrorCode::CorruptGeneration)
        );
        Ok(())
    }

    #[test]
    fn h2_partial_store_reports_missing_critical_coverage_without_silent_degradation()
    -> Result<(), Box<dyn Error>> {
        let requirements = vec![requirement(None, true)?, requirement(None, true)?];
        let plan = QueryPlanner::new_with_retrieval_profile(
            crate::QueryPlannerProfile::balanced_v2_requirement_aware_candidate(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?
        .plan_bounded(
            &requirements,
            &capacity(1)?,
            &partition()?,
            StoreRevision(7),
            RetrievalConsistency::Strong,
            false,
        )?;
        let available = candidate_for_profile(
            85,
            1,
            1,
            805,
            9_000,
            RetrievalProfile::BalancedV2RequirementAwareCandidate,
        )?;
        let mut stages = vec![Vec::new(); plan.stages.len()];
        let available_stage = plan
            .stages
            .iter()
            .position(|stage| {
                stage.requirement_index == 0 && stage.request.stage == RetrievalStage::Lexical
            })
            .ok_or("missing first requirement lexical stage")?;
        *stages
            .get_mut(available_stage)
            .ok_or("missing available stage slot")? = vec![available];
        assert_eq!(
            RequirementAwareCandidateReducer
                .reduce_with_profile(
                    &plan,
                    &result(&plan, &stages)?,
                    &context(),
                    RetrievalProfile::BalancedV2RequirementAwareCandidate,
                )
                .map_err(|error| error.code()),
            Err(crate::RetrievalErrorCode::RequiredCandidateMissing)
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
            profile_index in 0_u8..4,
        ) {
            let retrieval_profile = match profile_index {
                0 => RetrievalProfile::BalancedV1,
                1 => RetrievalProfile::BalancedV2Candidate,
                2 => RetrievalProfile::BalancedV2RequirementAwareCandidate,
                _ => RetrievalProfile::BalancedV4,
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

        #[test]
        fn weighted_count_matches_checked_i64_multiplication(
            weight in any::<i64>(),
            count in any::<u16>(),
        ) {
            let expected = weight.checked_mul(i64::from(count));
            let actual = super::weighted_count(weight, usize::from(count));
            match expected {
                Some(value) => prop_assert_eq!(actual, Ok(value)),
                None => prop_assert_eq!(
                    actual.map_err(|error| error.code()),
                    Err(crate::RetrievalErrorCode::LimitExceeded),
                ),
            }
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
