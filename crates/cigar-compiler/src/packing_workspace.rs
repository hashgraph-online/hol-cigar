//! Dense, ordinal-indexed value-of-information packing for the opt-in v4 profile.

use crate::compiler::{candidate_order, candidate_utility, choose_representation};
use crate::{
    CompilerCandidate, CompilerError, CompilerErrorCode, CompilerProfile, DispositionRecord,
    FrozenInputs, LossClass, PackingDecision, PackingDecisionBasis, PackingDominanceDecision,
    PackingDominanceReason, PackingEvidence, PackingStopReason, RepresentationVariant, Selection,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    Classification, ContentDigest, ContextContract, InstructionAuthority, LaneKind, OperationClass,
    RepresentationKind, RequirementSelector, VersionId,
};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

const LANE_COUNT: usize = 5;
const REQUIREMENT_WORDS: usize = 16;
const INDEPENDENT_REQUIREMENT_FREE_FAST_PATH_MAX: usize = 1_024;
const V4_BASE_SCORE_DIVISOR: i64 = 32;
const V4_NEW_REQUIREMENT_GAIN: i64 = 400_000;
const V4_INDEPENDENT_EVIDENCE_GAIN: i64 = 350_000;
const V4_EFFECT_CORROBORATION_GAIN: i64 = 400_000;
const V4_NEW_ENTITY_GAIN: i64 = 120_000;
const V4_AUTHORITY_GAIN_PER_POINT: i64 = 30;
const V4_FRESHNESS_GAIN_PER_POINT: i64 = 15;
const V4_CONFLICT_EVIDENCE_GAIN: i64 = 250_000;
const V4_LANE_DIVERSITY_GAIN: i64 = 75_000;
const V4_REDUNDANT_REQUIREMENT_PENALTY: i64 = 250_000;
const V4_REDUNDANT_ENTITY_PENALTY: i64 = 20_000;
const V4_DEPENDENCY_ITEM_PENALTY: i64 = 40_000;
const V4_INCREMENTAL_TOKEN_PENALTY: i64 = 250;
const V4_ADMISSION_FLOOR: i64 = 320_000;

/// Binds every non-profile v4 packing policy choice to the compiler profile digest.
///
/// Keep this next to the constants it commits to so changing a packing coefficient or a
/// qualitative rule cannot silently reuse artifacts produced by the previous policy.
pub(crate) fn update_profile_digest(hasher: &mut Sha256) {
    hasher.update(b"CIGAR-COMPILER-V4-POLICY\0v1\0");
    for value in [
        V4_BASE_SCORE_DIVISOR,
        V4_NEW_REQUIREMENT_GAIN,
        V4_INDEPENDENT_EVIDENCE_GAIN,
        V4_EFFECT_CORROBORATION_GAIN,
        V4_NEW_ENTITY_GAIN,
        V4_AUTHORITY_GAIN_PER_POINT,
        V4_FRESHNESS_GAIN_PER_POINT,
        V4_CONFLICT_EVIDENCE_GAIN,
        V4_LANE_DIVERSITY_GAIN,
        V4_REDUNDANT_REQUIREMENT_PENALTY,
        V4_REDUNDANT_ENTITY_PENALTY,
        V4_DEPENDENCY_ITEM_PENALTY,
        V4_INCREMENTAL_TOKEN_PENALTY,
        V4_ADMISSION_FLOOR,
    ] {
        hasher.update(value.to_be_bytes());
    }
    hasher.update(b"independent-source-lineage-content\0");
    hasher.update(b"risk-external-mutation-blocking\0");
    hasher.update(b"conservative-same-source-lineage-closure-conflict-position\0");
    hasher.update(b"repair-disabled-benchmark-gated\0");
    hasher.update(b"stop-positive-contextual-marginal-utility\0");
    hasher.update(b"exact-representation-counts-tokenizer-pinned-closure-cache\0");
    hasher.update(b"allocation-free-static-scan-exhausted-fast-path\0");
}

#[derive(Clone)]
struct ChosenRepresentations {
    optional: RepresentationVariant,
    lossless: Option<RepresentationVariant>,
}

#[derive(Clone)]
struct ClosureMember {
    ordinal: usize,
    representation: RepresentationVariant,
    utility: i64,
}

#[derive(Clone)]
enum ClosureMembers {
    Single(ClosureMember),
    Multiple(Vec<ClosureMember>),
}

impl ClosureMembers {
    fn len(&self) -> usize {
        match self {
            Self::Single(_member) => 1,
            Self::Multiple(members) => members.len(),
        }
    }

    fn get(&self, index: usize) -> Option<&ClosureMember> {
        match self {
            Self::Single(member) => (index == 0).then_some(member),
            Self::Multiple(members) => members.get(index),
        }
    }

    fn iter(&self) -> impl Iterator<Item = &ClosureMember> {
        let single = match self {
            Self::Single(member) => Some(member),
            Self::Multiple(_members) => None,
        };
        let multiple = match self {
            Self::Single(_member) => None,
            Self::Multiple(members) => Some(members.as_slice()),
        };
        single.into_iter().chain(multiple.into_iter().flatten())
    }
}

#[derive(Clone)]
struct ClosureCache {
    members: ClosureMembers,
    lane_tokens: [u32; LANE_COUNT],
    lane_counts: [u16; LANE_COUNT],
    requirement_bits: RequirementBits,
    entity_bits: u64,
    lane_bits: u8,
}

impl Default for ClosureCache {
    fn default() -> Self {
        Self {
            members: ClosureMembers::Multiple(Vec::new()),
            lane_tokens: [0; LANE_COUNT],
            lane_counts: [0; LANE_COUNT],
            requirement_bits: RequirementBits::default(),
            entity_bits: 0,
            lane_bits: 0,
        }
    }
}

struct CandidateState {
    source_ordinal: u16,
    lineage_ordinal: u16,
    content_ordinal: u16,
    optional_closure: ClosureCache,
    lossless_closure: Option<ClosureCache>,
    exact_requirement_protected: bool,
    sole_blocking_protected: bool,
}

impl CandidateState {
    fn closure(&self, lossless_root: bool) -> &ClosureCache {
        if lossless_root {
            self.lossless_closure
                .as_ref()
                .unwrap_or(&self.optional_closure)
        } else {
            &self.optional_closure
        }
    }
}

#[derive(Default)]
struct RequirementState {
    selected_count: u16,
    source_ordinals: Vec<u16>,
    lineage_ordinals: Vec<u16>,
    content_ordinals: Vec<u16>,
    maximum_authority: u16,
    maximum_freshness: u16,
    conflict_evidence: bool,
}

#[derive(Clone, Copy, Default)]
struct ClosureDelta {
    closure_items: usize,
    lane_tokens: [u32; LANE_COUNT],
    lane_counts: [u16; LANE_COUNT],
    newly_covered_requirements: RequirementBits,
    independently_corroborated_requirements: RequirementBits,
    repeated_requirements: RequirementBits,
    entity_bits: u64,
    authority_gain: u16,
    freshness_gain: u16,
    conflict_evidence: bool,
    effect_adjacent: bool,
    lane_diverse: bool,
}

#[derive(Clone, Copy, Default)]
struct RequirementBits([u64; REQUIREMENT_WORDS]);

impl RequirementBits {
    fn insert(&mut self, requirement: usize) -> Result<(), CompilerError> {
        let word = requirement / 64;
        let bit = u32::try_from(requirement % 64)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        let slot = get_mut(&mut self.0, word)?;
        *slot |= 1_u64
            .checked_shl(bit)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        Ok(())
    }

    fn contains(&self, requirement: usize) -> bool {
        let word = requirement / 64;
        let Ok(bit) = u32::try_from(requirement % 64) else {
            return false;
        };
        self.0
            .get(word)
            .is_some_and(|value| value & (1_u64 << bit) != 0)
    }

    fn len(&self) -> usize {
        self.0.iter().map(|value| value.count_ones() as usize).sum()
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|value| *value == 0)
    }

    fn union(self, other: Self) -> Self {
        let mut output = Self::default();
        for index in 0..REQUIREMENT_WORDS {
            let left = self.0.get(index).copied().unwrap_or_default();
            let right = other.0.get(index).copied().unwrap_or_default();
            if let Some(slot) = output.0.get_mut(index) {
                *slot = left | right;
            };
        }
        output
    }

    fn intersects(self, other: Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .any(|(left, right)| left & right != 0)
    }
}

#[derive(Clone, Copy)]
struct EvaluatedRoot {
    ordinal: usize,
    utility: i64,
    delta: ClosureDelta,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct EvaluationHeapEntry {
    utility: i64,
    tokens: u32,
    ranking_priority: usize,
    ordinal: usize,
    generation: u32,
}

impl Ord for EvaluationHeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let left = i128::from(self.utility) * i128::from(other.tokens.max(1));
        let right = i128::from(other.utility) * i128::from(self.tokens.max(1));
        left.cmp(&right)
            .then_with(|| self.utility.cmp(&other.utility))
            .then_with(|| other.ranking_priority.cmp(&self.ranking_priority))
            .then_with(|| other.ordinal.cmp(&self.ordinal))
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

impl PartialOrd for EvaluationHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub(crate) struct PackingResult {
    pub(crate) selected: BTreeMap<VersionId, Selection>,
    pub(crate) evidence: PackingEvidence,
}

struct EligibleCandidates<'a> {
    candidates: &'a BTreeMap<VersionId, CompilerCandidate>,
    dispositions: &'a BTreeMap<VersionId, DispositionRecord>,
}

impl<'a> EligibleCandidates<'a> {
    fn get(&self, version: &VersionId) -> Option<&'a CompilerCandidate> {
        (!self.dispositions.contains_key(version))
            .then(|| self.candidates.get(version))
            .flatten()
    }

    fn keys(&self) -> impl Iterator<Item = &'a VersionId> + '_ {
        self.candidates
            .keys()
            .filter(|version| !self.dispositions.contains_key(*version))
    }

    fn values(&self) -> impl Iterator<Item = &'a CompilerCandidate> + '_ {
        self.candidates.iter().filter_map(|(version, candidate)| {
            (!self.dispositions.contains_key(version)).then_some(candidate)
        })
    }

    fn len(&self) -> usize {
        self.keys().count()
    }

    fn is_empty(&self) -> bool {
        self.keys().next().is_none()
    }
}

pub(crate) fn pack_v4(
    contract: &ContextContract,
    frozen: &FrozenInputs,
    profile: &CompilerProfile,
    candidates: &BTreeMap<VersionId, CompilerCandidate>,
    dispositions: &BTreeMap<VersionId, DispositionRecord>,
    ranking_priorities: Option<&BTreeMap<VersionId, usize>>,
) -> Result<PackingResult, CompilerError> {
    let eligible = EligibleCandidates {
        candidates,
        dispositions,
    };
    if let Some(result) = try_pack_independent_requirement_free(
        contract,
        frozen,
        profile,
        &eligible,
        ranking_priorities,
    )? {
        return Ok(result);
    }
    if let Some(result) =
        try_pack_independent_blocking(contract, frozen, profile, &eligible, ranking_priorities)?
    {
        return Ok(result);
    }
    let mut workspace =
        PackingWorkspace::new(contract, frozen, profile, &eligible, ranking_priorities)?;
    workspace.select_mandatory()?;
    workspace.ensure_mandatory_fits()?;
    workspace.select_first_blocking()?;
    workspace.satisfy_lane_minima()?;
    if !workspace.has_competitive_optional()? {
        return workspace.finish();
    }
    workspace.compute_dominance()?;
    workspace.reserve_effect_corroboration()?;
    workspace.pack_positive_marginal()?;
    workspace.finish()
}

/// Packs independently sourced, requirement-free candidates with a bounded linear winner scan.
///
/// The guards exclude every shape that needs closure, dominance, requirement, mandatory, or lane
/// limit state. The scan applies the same marginal utility, capacity, and tie-breaking rules as the
/// general heap path, but does not allocate its per-candidate closure workspace.
fn try_pack_independent_requirement_free(
    contract: &ContextContract,
    frozen: &FrozenInputs,
    profile: &CompilerProfile,
    eligible: &EligibleCandidates<'_>,
    ranking_priorities: Option<&BTreeMap<VersionId, usize>>,
) -> Result<Option<PackingResult>, CompilerError> {
    if !contract.requirements.is_empty()
        || eligible.len() > INDEPENDENT_REQUIREMENT_FREE_FAST_PATH_MAX
        || !profile.minimum_items.is_empty()
        || !profile.maximum_items.is_empty()
        || eligible.values().any(|candidate| {
            candidate.mandatory
                || candidate.policy_outcome != PolicyOutcome::Allow
                || !candidate.requirement_indices.is_empty()
                || !candidate.dependencies.is_empty()
                || candidate.representations.len() != 1
                || candidate
                    .representations
                    .first()
                    .is_none_or(|representation| representation.loss != LossClass::Lossless)
        })
        || !globally_independent(eligible)
    {
        return Ok(None);
    }

    let mut versions = eligible.keys().cloned().collect::<Vec<_>>();
    versions.sort_by(|left, right| {
        eligible.get(left).zip(eligible.get(right)).map_or_else(
            || left.cmp(right),
            |(left, right)| candidate_order(left, right),
        )
    });
    let workspace_fingerprint = workspace_fingerprint(frozen, eligible, &versions)?;
    let lane_budgets = lane_array_u32(&contract.budget.lane_input_tokens, 0);
    let mut lane_tokens = [0_u32; LANE_COUNT];
    let mut lane_counts = [0_u16; LANE_COUNT];
    let mut entity_bits = 0_u64;
    let mut selected_bits = vec![false; versions.len()];
    let mut selected = BTreeMap::new();
    let mut decisions = Vec::new();
    let stop_reason = loop {
        let mut remaining = false;
        let mut positive_infeasible = false;
        let mut winner = None;
        for (ordinal, version) in versions.iter().enumerate() {
            if selected_bits.get(ordinal).copied().unwrap_or(true) {
                continue;
            }
            let candidate = eligible
                .get(version)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
            if candidate.features.lexical_match < profile.minimum_lexical_match {
                continue;
            }
            remaining = true;
            let representation = candidate
                .representations
                .first()
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
            let new_entities = candidate.entity_coverage_bits & !entity_bits;
            if new_entities == 0 && candidate.features.conflict_risk == 0 {
                continue;
            }
            let redundant_entities = candidate.entity_coverage_bits & entity_bits;
            let utility = candidate_utility(candidate, representation, profile)?;
            let lane = lane_index(candidate.lane);
            let marginal_utility = marginal_utility_from_factors(MarginalFactors {
                candidate_utility: utility,
                tokens: representation.token_count,
                new_requirements: 0,
                independent_requirements: 0,
                effect_gain: false,
                new_entities: i64::from(new_entities.count_ones()),
                authority_gain: 0,
                freshness_gain: 0,
                conflict_gain: candidate.features.conflict_risk > 0,
                lane_diverse: get(&lane_counts, lane)? == &0,
                repeated_requirements: 0,
                redundant_entities: i64::from(redundant_entities.count_ones()),
                dependency_items: 0,
            })?;
            if marginal_utility <= 0 {
                continue;
            }
            let lane_budget = *get(&lane_budgets, lane)?;
            let fits = get(&lane_tokens, lane)?
                .checked_add(representation.token_count)
                .is_some_and(|tokens| tokens <= lane_budget);
            if !fits {
                positive_infeasible = true;
                continue;
            }
            let entry = EvaluationHeapEntry {
                utility: marginal_utility,
                tokens: representation.token_count,
                ranking_priority: ranking_priorities
                    .and_then(|priorities| priorities.get(version))
                    .copied()
                    .unwrap_or(usize::MAX),
                ordinal,
                generation: 0,
            };
            if winner.as_ref().is_none_or(|(best, _, _, _)| entry > *best) {
                winner = Some((entry, utility, new_entities, lane));
            }
        }

        let Some((winner, utility, new_entities, lane)) = winner else {
            break if positive_infeasible {
                PackingStopReason::CapacitySaturated
            } else if remaining {
                PackingStopReason::NonPositiveMarginalUtility
            } else {
                PackingStopReason::Exhausted
            };
        };
        let version = get(&versions, winner.ordinal)?;
        let candidate = eligible
            .get(version)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let representation = candidate
            .representations
            .first()
            .cloned()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        *get_mut(&mut selected_bits, winner.ordinal)? = true;
        *get_mut(&mut lane_tokens, lane)? = get(&lane_tokens, lane)?
            .checked_add(representation.token_count)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        *get_mut(&mut lane_counts, lane)? = get(&lane_counts, lane)?
            .checked_add(1)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        entity_bits |= candidate.entity_coverage_bits;
        decisions.push(PackingDecision {
            ordinal: decisions.len().saturating_add(1),
            selected_version: version.clone(),
            basis: PackingDecisionBasis::MarginalUtility,
            marginal_utility: winner.utility,
            incremental_tokens: representation.token_count,
            closure_items: 1,
            newly_covered_requirements: 0,
            independently_corroborated_requirements: 0,
            newly_covered_entities: new_entities.count_ones(),
            effect_adjacent: false,
        });
        selected.insert(
            version.clone(),
            Selection {
                candidate: candidate.clone(),
                representation,
                utility,
            },
        );
    };

    let profile_digest = frozen.compiler_profile_digest.clone();
    let dominance_decisions = Vec::new();
    let evidence_digest = packing_evidence_digest(
        &profile.profile_id,
        &profile_digest,
        &frozen.tokenizer_fingerprint,
        &workspace_fingerprint,
        &decisions,
        &dominance_decisions,
        stop_reason,
    )?;
    Ok(Some(PackingResult {
        selected,
        evidence: PackingEvidence {
            compiler_profile_id: profile.profile_id.clone(),
            compiler_profile_digest: profile_digest,
            tokenizer_fingerprint: frozen.tokenizer_fingerprint.clone(),
            workspace_fingerprint,
            decisions,
            dominance_decisions,
            stop_reason,
            evidence_digest,
        },
    }))
}

/// Packs the small, independent, blocking-only shape without constructing the
/// general closure workspace. Every guard below is a proof obligation: any
/// unsupported provenance, representation, policy, or value-of-information
/// shape falls through to the general packer.
fn try_pack_independent_blocking(
    contract: &ContextContract,
    frozen: &FrozenInputs,
    profile: &CompilerProfile,
    eligible: &EligibleCandidates<'_>,
    ranking_priorities: Option<&BTreeMap<VersionId, usize>>,
) -> Result<Option<PackingResult>, CompilerError> {
    if eligible.is_empty()
        || eligible.len() > 64
        || eligible.len() < contract.requirements.len()
        || !profile.minimum_items.is_empty()
        || !profile.maximum_items.is_empty()
        || contract.operation_class == OperationClass::ExternalMutation
        || contract
            .requirements
            .iter()
            .any(|requirement| !requirement.blocking)
        || eligible.values().any(|candidate| {
            candidate.mandatory
                || candidate.policy_outcome != PolicyOutcome::Allow
                || !candidate.dependencies.is_empty()
                || candidate.requirement_indices.len() != 1
                || candidate.representations.len() != 1
                || candidate
                    .representations
                    .first()
                    .is_none_or(|representation| representation.loss != LossClass::Lossless)
                || candidate
                    .requirement_indices
                    .first()
                    .is_none_or(|requirement| *requirement >= contract.requirements.len())
        })
        || !globally_independent(eligible)
    {
        return Ok(None);
    }

    let mut versions = eligible.keys().cloned().collect::<Vec<_>>();
    versions.sort_by(|left, right| {
        eligible.get(left).zip(eligible.get(right)).map_or_else(
            || left.cmp(right),
            |(left, right)| candidate_order(left, right),
        )
    });
    let workspace_fingerprint = workspace_fingerprint(frozen, eligible, &versions)?;
    let lane_budgets = lane_array_u32(&contract.budget.lane_input_tokens, 0);
    let mut lane_tokens = [0_u32; LANE_COUNT];
    let mut lane_counts = [0_u16; LANE_COUNT];
    let mut entity_bits = 0_u64;
    let mut selected_bits = 0_u64;
    let mut root_by_requirement = vec![usize::MAX; contract.requirements.len()];
    let mut selected = BTreeMap::new();
    let mut decisions = Vec::with_capacity(contract.requirements.len());
    for requirement in 0..contract.requirements.len() {
        let mut best = None;
        let mut best_priority = usize::MAX;
        for (ordinal, version) in versions.iter().enumerate() {
            let candidate = eligible
                .get(version)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
            if candidate.requirement_indices.first().copied() != Some(requirement)
                || candidate.features.lexical_match < profile.minimum_lexical_match
            {
                continue;
            }
            let representation = candidate
                .representations
                .first()
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
            let lane = lane_index(candidate.lane);
            let lane_budget = *get(&lane_budgets, lane)?;
            let fits = get(&lane_tokens, lane)?
                .checked_add(representation.token_count)
                .is_some_and(|tokens| tokens <= lane_budget);
            if !fits {
                continue;
            }
            let priority = ranking_priorities
                .and_then(|values| values.get(version))
                .copied()
                .unwrap_or(usize::MAX);
            // `versions` is already in candidate order, so retaining the
            // earlier ordinal reproduces the general packer's tie break.
            if best.is_none() || priority < best_priority {
                best = Some(ordinal);
                best_priority = priority;
            }
        }
        let Some(root) = best else {
            return Ok(None);
        };
        *get_mut(&mut root_by_requirement, requirement)? = root;
        let version = get(&versions, root)?;
        let candidate = eligible
            .get(version)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let representation = candidate
            .representations
            .first()
            .cloned()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let lane = lane_index(candidate.lane);
        let lane_diverse = *get(&lane_counts, lane)? == 0;
        let updated_tokens = get(&lane_tokens, lane)?
            .checked_add(representation.token_count)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        *get_mut(&mut lane_tokens, lane)? = updated_tokens;
        *get_mut(&mut lane_counts, lane)? = get(&lane_counts, lane)?
            .checked_add(1)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;

        let new_entities = candidate.entity_coverage_bits & !entity_bits;
        let redundant_entities = candidate.entity_coverage_bits & entity_bits;
        let utility = candidate_utility(candidate, &representation, profile)?;
        let marginal_utility = marginal_utility_from_factors(MarginalFactors {
            candidate_utility: utility,
            tokens: representation.token_count,
            new_requirements: 1,
            independent_requirements: 0,
            effect_gain: false,
            new_entities: i64::from(new_entities.count_ones()),
            authority_gain: candidate.features.authority,
            freshness_gain: candidate.features.freshness,
            conflict_gain: candidate.features.conflict_risk > 0,
            lane_diverse,
            repeated_requirements: 0,
            redundant_entities: i64::from(redundant_entities.count_ones()),
            dependency_items: 0,
        })?;
        entity_bits |= candidate.entity_coverage_bits;
        let bit = u32::try_from(root)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        selected_bits |= 1_u64
            .checked_shl(bit)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        decisions.push(PackingDecision {
            ordinal: decisions.len().saturating_add(1),
            selected_version: version.clone(),
            basis: PackingDecisionBasis::BlockingRequirement,
            marginal_utility,
            incremental_tokens: representation.token_count,
            closure_items: 1,
            newly_covered_requirements: 1,
            independently_corroborated_requirements: 0,
            newly_covered_entities: new_entities.count_ones(),
            effect_adjacent: false,
        });
        selected.insert(
            version.clone(),
            Selection {
                candidate: candidate.clone(),
                representation,
                utility,
            },
        );
    }

    let mut remaining = false;
    for (ordinal, version) in versions.iter().enumerate() {
        let bit = u32::try_from(ordinal)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        if selected_bits & (1_u64 << bit) != 0 {
            continue;
        }
        let candidate = eligible
            .get(version)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        if candidate.features.lexical_match < profile.minimum_lexical_match {
            continue;
        }
        remaining = true;
        let requirement = candidate
            .requirement_indices
            .first()
            .copied()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let primary = eligible
            .get(get(&versions, *get(&root_by_requirement, requirement)?)?)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let representation = candidate
            .representations
            .first()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let utility = candidate_utility(candidate, representation, profile)?;
        let new_entities = candidate.entity_coverage_bits & !entity_bits;
        let redundant_entities = candidate.entity_coverage_bits & entity_bits;
        let lane = lane_index(candidate.lane);
        let marginal_utility = marginal_utility_from_factors(MarginalFactors {
            candidate_utility: utility,
            tokens: representation.token_count,
            new_requirements: 0,
            independent_requirements: 1,
            effect_gain: false,
            new_entities: i64::from(new_entities.count_ones()),
            authority_gain: candidate
                .features
                .authority
                .saturating_sub(primary.features.authority),
            freshness_gain: candidate
                .features
                .freshness
                .saturating_sub(primary.features.freshness),
            conflict_gain: candidate.features.conflict_risk > 0,
            lane_diverse: *get(&lane_counts, lane)? == 0,
            repeated_requirements: 1,
            redundant_entities: i64::from(redundant_entities.count_ones()),
            dependency_items: 0,
        })?;
        // A positive candidate requires the general feasibility/heap path.
        if marginal_utility > 0 {
            return Ok(None);
        }
    }

    let profile_digest = frozen.compiler_profile_digest.clone();
    let dominance_decisions = Vec::new();
    let stop_reason = if remaining {
        PackingStopReason::NonPositiveMarginalUtility
    } else {
        PackingStopReason::Exhausted
    };
    let evidence_digest = packing_evidence_digest(
        &profile.profile_id,
        &profile_digest,
        &frozen.tokenizer_fingerprint,
        &workspace_fingerprint,
        &decisions,
        &dominance_decisions,
        stop_reason,
    )?;
    Ok(Some(PackingResult {
        selected,
        evidence: PackingEvidence {
            compiler_profile_id: profile.profile_id.clone(),
            compiler_profile_digest: profile_digest,
            tokenizer_fingerprint: frozen.tokenizer_fingerprint.clone(),
            workspace_fingerprint,
            decisions,
            dominance_decisions,
            stop_reason,
            evidence_digest,
        },
    }))
}

fn globally_independent(eligible: &EligibleCandidates<'_>) -> bool {
    for (index, left) in eligible.values().enumerate() {
        for right in eligible.values().skip(index.saturating_add(1)) {
            let left_content = left
                .representations
                .first()
                .map(|representation| &representation.content_digest);
            let right_content = right
                .representations
                .first()
                .map(|representation| &representation.content_digest);
            if left.canonical_uri == right.canonical_uri
                || left.lineage_id == right.lineage_id
                || left_content == right_content
            {
                return false;
            }
        }
    }
    true
}

#[derive(Clone, Copy)]
struct MarginalFactors {
    candidate_utility: i64,
    tokens: u32,
    new_requirements: i64,
    independent_requirements: i64,
    effect_gain: bool,
    new_entities: i64,
    authority_gain: u16,
    freshness_gain: u16,
    conflict_gain: bool,
    lane_diverse: bool,
    repeated_requirements: i64,
    redundant_entities: i64,
    dependency_items: i64,
}

fn marginal_utility_from_factors(factors: MarginalFactors) -> Result<i64, CompilerError> {
    let base = factors
        .candidate_utility
        .checked_div(V4_BASE_SCORE_DIVISOR)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    [
        (V4_NEW_REQUIREMENT_GAIN, factors.new_requirements, true),
        (
            V4_INDEPENDENT_EVIDENCE_GAIN,
            factors.independent_requirements,
            true,
        ),
        (
            V4_EFFECT_CORROBORATION_GAIN,
            i64::from(factors.effect_gain),
            true,
        ),
        (V4_NEW_ENTITY_GAIN, factors.new_entities, true),
        (
            V4_AUTHORITY_GAIN_PER_POINT,
            i64::from(factors.authority_gain),
            true,
        ),
        (
            V4_FRESHNESS_GAIN_PER_POINT,
            i64::from(factors.freshness_gain),
            true,
        ),
        (
            V4_CONFLICT_EVIDENCE_GAIN,
            i64::from(factors.conflict_gain),
            true,
        ),
        (
            V4_LANE_DIVERSITY_GAIN,
            i64::from(factors.lane_diverse),
            true,
        ),
        (
            V4_REDUNDANT_REQUIREMENT_PENALTY,
            factors.repeated_requirements,
            false,
        ),
        (
            V4_REDUNDANT_ENTITY_PENALTY,
            factors.redundant_entities,
            false,
        ),
        (V4_DEPENDENCY_ITEM_PENALTY, factors.dependency_items, false),
        (
            V4_INCREMENTAL_TOKEN_PENALTY,
            i64::from(factors.tokens),
            false,
        ),
        (V4_ADMISSION_FLOOR, 1, false),
    ]
    .into_iter()
    .try_fold(base, |utility, (weight, count, add)| {
        let amount = weight
            .checked_mul(count)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        if add {
            utility.checked_add(amount)
        } else {
            utility.checked_sub(amount)
        }
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))
    })
}

struct PackingWorkspace<'a> {
    contract: &'a ContextContract,
    frozen: &'a FrozenInputs,
    profile: &'a CompilerProfile,
    versions: Vec<VersionId>,
    candidates: Vec<&'a CompilerCandidate>,
    states: Vec<CandidateState>,
    selected_bits: Vec<bool>,
    dependency_bits: Vec<bool>,
    dominated_by: Vec<Option<usize>>,
    requirement_state: Vec<RequirementState>,
    requirement_candidates: Vec<Vec<usize>>,
    lane_tokens: [u32; LANE_COUNT],
    lane_counts: [u16; LANE_COUNT],
    lane_budgets: [u32; LANE_COUNT],
    lane_minima: [u16; LANE_COUNT],
    lane_maxima: [u16; LANE_COUNT],
    entity_bits: u64,
    source_count: usize,
    ranking_priorities: Vec<usize>,
    selected: BTreeMap<VersionId, Selection>,
    decisions: Vec<PackingDecision>,
    dominance_decisions: Vec<PackingDominanceDecision>,
    stop_reason: PackingStopReason,
    workspace_fingerprint: ContentDigest,
}

impl<'a> PackingWorkspace<'a> {
    fn new(
        contract: &'a ContextContract,
        frozen: &'a FrozenInputs,
        profile: &'a CompilerProfile,
        eligible: &EligibleCandidates<'a>,
        ranking_priorities: Option<&BTreeMap<VersionId, usize>>,
    ) -> Result<Self, CompilerError> {
        let mut versions = eligible.keys().cloned().collect::<Vec<_>>();
        versions.sort_by(|left, right| {
            eligible.get(left).zip(eligible.get(right)).map_or_else(
                || left.cmp(right),
                |(left, right)| candidate_order(left, right),
            )
        });
        let candidates = versions
            .iter()
            .map(|version| {
                eligible
                    .get(version)
                    .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ranking_priorities = versions
            .iter()
            .map(|version| {
                ranking_priorities
                    .and_then(|values| values.get(version))
                    .copied()
                    .unwrap_or(usize::MAX)
            })
            .collect();
        let ordinal_by_version = if candidates
            .iter()
            .any(|candidate| !candidate.dependencies.is_empty())
        {
            versions
                .iter()
                .enumerate()
                .map(|(ordinal, version)| (version.clone(), ordinal))
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
        let representations = candidates
            .iter()
            .map(|candidate| {
                let optional = choose_representation(candidate, profile, false)?;
                let lossless = if optional.loss == LossClass::Lossless {
                    None
                } else {
                    Some(choose_representation(candidate, profile, true)?)
                };
                Ok(ChosenRepresentations { optional, lossless })
            })
            .collect::<Result<Vec<_>, CompilerError>>()?;
        let source_ordinals = intern_strings(
            candidates
                .iter()
                .map(|candidate| candidate.canonical_uri.as_str()),
        )?;
        let lineage_ordinals = intern_strings(
            candidates
                .iter()
                .map(|candidate| candidate.lineage_id.as_str()),
        )?;
        let content_ordinals = intern_strings(
            representations
                .iter()
                .map(|chosen| chosen.optional.content_digest.as_str()),
        )?;
        let mut requirement_candidates = (0..contract.requirements.len())
            .map(|_requirement| Vec::new())
            .collect::<Vec<_>>();
        for (ordinal, candidate) in candidates.iter().enumerate() {
            for requirement in &candidate.requirement_indices {
                get_mut(&mut requirement_candidates, *requirement)?.push(ordinal);
            }
        }
        let mut states = Vec::with_capacity(versions.len());
        for ordinal in 0..versions.len() {
            let version = get(&versions, ordinal)?;
            let candidate = eligible
                .get(version)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
            let optional_closure = build_closure(
                ordinal,
                false,
                profile,
                eligible,
                &versions,
                &ordinal_by_version,
                &representations,
            )?;
            let lossless_closure = get(&representations, ordinal)?
                .lossless
                .as_ref()
                .map(|_representation| {
                    build_closure(
                        ordinal,
                        true,
                        profile,
                        eligible,
                        &versions,
                        &ordinal_by_version,
                        &representations,
                    )
                })
                .transpose()?;
            let exact_requirement_protected = contract.requirements.iter().any(|requirement| {
                matches!(&requirement.selector, RequirementSelector::Exact(required) if required == version)
            });
            let sole_blocking_protected = candidate.requirement_indices.iter().any(|requirement| {
                contract
                    .requirements
                    .get(*requirement)
                    .is_some_and(|value| value.blocking)
                    && requirement_candidates
                        .get(*requirement)
                        .is_some_and(|ordinals| ordinals.len() == 1)
            });
            states.push(CandidateState {
                source_ordinal: *get(&source_ordinals.ordinals, ordinal)?,
                lineage_ordinal: *get(&lineage_ordinals.ordinals, ordinal)?,
                content_ordinal: *get(&content_ordinals.ordinals, ordinal)?,
                optional_closure,
                lossless_closure,
                exact_requirement_protected,
                sole_blocking_protected,
            });
        }
        let lane_budgets = lane_array_u32(&contract.budget.lane_input_tokens, 0);
        let lane_minima = lane_array_u16(&profile.minimum_items, 0);
        let lane_maxima = lane_array_u16(&profile.maximum_items, u16::MAX);
        let workspace_fingerprint = workspace_fingerprint(frozen, eligible, &versions)?;
        Ok(Self {
            contract,
            frozen,
            profile,
            selected_bits: vec![false; versions.len()],
            dependency_bits: vec![false; versions.len()],
            dominated_by: vec![None; versions.len()],
            requirement_state: (0..contract.requirements.len())
                .map(|_index| RequirementState::default())
                .collect(),
            requirement_candidates,
            lane_tokens: [0; LANE_COUNT],
            lane_counts: [0; LANE_COUNT],
            lane_budgets,
            lane_minima,
            lane_maxima,
            entity_bits: 0,
            source_count: source_ordinals.unique_count,
            ranking_priorities,
            selected: BTreeMap::new(),
            decisions: Vec::new(),
            dominance_decisions: Vec::new(),
            stop_reason: PackingStopReason::Exhausted,
            versions,
            candidates,
            states,
            workspace_fingerprint,
        })
    }

    fn select_mandatory(&mut self) -> Result<(), CompilerError> {
        for ordinal in 0..self.versions.len() {
            if self.candidate(ordinal)?.mandatory && !self.is_selected(ordinal)? {
                self.admit(ordinal, true, PackingDecisionBasis::Mandatory, None)?;
            }
        }
        Ok(())
    }

    fn ensure_mandatory_fits(&self) -> Result<(), CompilerError> {
        if (0..LANE_COUNT).any(|lane| {
            self.lane_tokens.get(lane).copied().unwrap_or(u32::MAX)
                > self.lane_budgets.get(lane).copied().unwrap_or_default()
                || self.lane_counts.get(lane).copied().unwrap_or(u16::MAX)
                    > self.lane_maxima.get(lane).copied().unwrap_or_default()
        }) {
            let minimum = self
                .lane_tokens
                .iter()
                .try_fold(0_u32, |total, value| total.checked_add(*value))
                .unwrap_or(u32::MAX);
            Err(CompilerError::budget(minimum))
        } else {
            Ok(())
        }
    }

    fn select_first_blocking(&mut self) -> Result<(), CompilerError> {
        for requirement in 0..self.contract.requirements.len() {
            let blocking = self
                .contract
                .requirements
                .get(requirement)
                .is_some_and(|value| value.blocking);
            if !blocking || self.requirement_count(requirement)? > 0 {
                continue;
            }
            let candidates = self
                .requirement_candidates
                .get(requirement)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?
                .iter()
                .copied();
            if candidates.clone().next().is_none() {
                return Err(CompilerError::new(CompilerErrorCode::RequiredMissing));
            }
            let choice = self.best_static(candidates, false)?;
            let Some(ordinal) = choice else {
                return Err(CompilerError::new(CompilerErrorCode::BudgetUnsatisfiable));
            };
            self.admit(
                ordinal,
                true,
                PackingDecisionBasis::BlockingRequirement,
                None,
            )?;
        }
        Ok(())
    }

    fn satisfy_lane_minima(&mut self) -> Result<(), CompilerError> {
        for lane in 0..LANE_COUNT {
            let minimum = self.lane_minima.get(lane).copied().unwrap_or_default();
            while self.lane_counts.get(lane).copied().unwrap_or_default() < minimum {
                let choices = (0..self.versions.len()).filter(|ordinal| {
                    !self.is_selected(*ordinal).unwrap_or(true)
                        && self
                            .candidate(*ordinal)
                            .is_ok_and(|candidate| lane_index(candidate.lane) == lane)
                });
                let choice = self.best_static(choices, false)?;
                let Some(ordinal) = choice else {
                    return Err(CompilerError::new(CompilerErrorCode::BudgetUnsatisfiable));
                };
                self.admit(ordinal, false, PackingDecisionBasis::LaneMinimum, None)?;
            }
        }
        Ok(())
    }

    fn compute_dominance(&mut self) -> Result<(), CompilerError> {
        if self.source_count == self.versions.len() {
            return Ok(());
        }
        let mut comparable = Vec::with_capacity(self.versions.len());
        for ordinal in 0..self.versions.len() {
            let candidate = self.candidate(ordinal)?;
            let state = self.state(ordinal)?;
            comparable.push((
                candidate.lane,
                state.source_ordinal,
                state.lineage_ordinal,
                ordinal,
            ));
        }
        comparable.sort_unstable();
        for group in comparable
            .chunk_by(|left, right| (left.0, left.1, left.2) == (right.0, right.1, right.2))
        {
            if group.len() < 2 {
                continue;
            }
            for dominated in group.iter().map(|value| value.3) {
                if self.is_selected(dominated)? || self.is_protected(dominated)? {
                    continue;
                }
                let mut winner = None;
                for dominating in group.iter().map(|value| value.3) {
                    if dominating == dominated || !self.dominates(dominating, dominated)? {
                        continue;
                    }
                    if winner.is_none_or(|current| {
                        self.static_order(dominating, current) == Ordering::Less
                    }) {
                        winner = Some(dominating);
                    }
                }
                if let Some(dominating) = winner {
                    *get_mut(&mut self.dominated_by, dominated)? = Some(dominating);
                    self.dominance_decisions.push(PackingDominanceDecision {
                        dominated_version: self.version(dominated)?.clone(),
                        dominating_version: self.version(dominating)?.clone(),
                        reason: PackingDominanceReason::SameProvenanceNoWeakerValue,
                    });
                }
            }
        }
        self.dominance_decisions.sort_by(|left, right| {
            left.dominated_version
                .cmp(&right.dominated_version)
                .then_with(|| left.dominating_version.cmp(&right.dominating_version))
        });
        Ok(())
    }

    fn reserve_effect_corroboration(&mut self) -> Result<(), CompilerError> {
        if self.contract.operation_class != OperationClass::ExternalMutation {
            return Ok(());
        }
        for requirement in 0..self.contract.requirements.len() {
            if !self
                .contract
                .requirements
                .get(requirement)
                .is_some_and(|value| value.blocking)
                || self.requirement_count(requirement)? != 1
            {
                continue;
            }
            let choices = (0..self.versions.len()).filter(|ordinal| {
                !self.is_selected(*ordinal).unwrap_or(true)
                    && self.dominated_by.get(*ordinal).is_some_and(Option::is_none)
                    && self
                        .candidate(*ordinal)
                        .is_ok_and(|candidate| candidate.requirement_indices.contains(&requirement))
                    && self.independent_for_requirement(*ordinal, requirement) == Ok(true)
            });
            if let Some(ordinal) = self.best_static(choices, false)? {
                self.admit(
                    ordinal,
                    false,
                    PackingDecisionBasis::IndependentCorroboration,
                    None,
                )?;
            }
        }
        Ok(())
    }

    fn pack_positive_marginal(&mut self) -> Result<(), CompilerError> {
        let mut remaining = false;
        let mut positive = false;
        for ordinal in 0..self.versions.len() {
            if self.is_selected(ordinal)?
                || self.is_dominated(ordinal)?
                || self.candidate(ordinal)?.features.lexical_match
                    < self.profile.minimum_lexical_match
            {
                continue;
            }
            remaining = true;
            if self
                .evaluate_optional(ordinal)?
                .is_some_and(|evaluated| evaluated.utility > 0)
            {
                positive = true;
                break;
            }
        }
        if !positive {
            self.stop_reason = if remaining {
                PackingStopReason::NonPositiveMarginalUtility
            } else {
                PackingStopReason::Exhausted
            };
            return Ok(());
        }
        let mut evaluations = (0..self.versions.len())
            .map(|ordinal| self.evaluate_optional(ordinal))
            .collect::<Result<Vec<_>, _>>()?;
        let mut generations = vec![0_u32; self.versions.len()];
        let mut heap = BinaryHeap::with_capacity(self.versions.len());
        for evaluated in evaluations.iter().flatten() {
            heap.push(self.heap_entry(*evaluated, 0)?);
        }
        let mut deferred = Vec::new();
        loop {
            let mut winner = None;
            let mut positive_infeasible = false;
            deferred.clear();
            while let Some(entry) = heap.pop() {
                if generations.get(entry.ordinal).copied() != Some(entry.generation)
                    || self.is_selected(entry.ordinal)?
                    || self.is_dominated(entry.ordinal)?
                {
                    continue;
                }
                let Some(evaluated) = get(&evaluations, entry.ordinal)?.as_ref() else {
                    continue;
                };
                if evaluated.utility <= 0 {
                    deferred.push(entry);
                    break;
                }
                if !self.delta_fits(&evaluated.delta) {
                    positive_infeasible = true;
                    deferred.push(entry);
                    continue;
                }
                winner = Some(*evaluated);
                break;
            }
            heap.extend(deferred.iter().copied());
            let Some(winner) = winner else {
                let remaining = (0..self.versions.len()).any(|ordinal| {
                    !self.is_selected(ordinal).unwrap_or(true)
                        && !self.is_dominated(ordinal).unwrap_or(true)
                        && self.candidate(ordinal).is_ok_and(|candidate| {
                            candidate.features.lexical_match >= self.profile.minimum_lexical_match
                        })
                });
                self.stop_reason = if positive_infeasible {
                    PackingStopReason::CapacitySaturated
                } else if remaining {
                    PackingStopReason::NonPositiveMarginalUtility
                } else {
                    PackingStopReason::Exhausted
                };
                return Ok(());
            };
            let changed_requirements = winner
                .delta
                .newly_covered_requirements
                .union(winner.delta.repeated_requirements);
            let changed_entities = winner.delta.entity_bits & !self.entity_bits;
            let mut changed_lanes = 0_u8;
            for lane in 0..LANE_COUNT {
                if winner
                    .delta
                    .lane_counts
                    .get(lane)
                    .copied()
                    .unwrap_or_default()
                    > 0
                    && self.lane_counts.get(lane).copied().unwrap_or_default() == 0
                {
                    let bit = u32::try_from(lane)
                        .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
                    changed_lanes |= 1_u8
                        .checked_shl(bit)
                        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
                }
            }
            self.admit(
                winner.ordinal,
                false,
                PackingDecisionBasis::MarginalUtility,
                Some((winner.utility, winner.delta)),
            )?;
            self.refresh_affected_evaluations(
                &mut evaluations,
                &mut generations,
                &mut heap,
                winner.ordinal,
                changed_requirements,
                changed_entities,
                changed_lanes,
            )?;
        }
    }

    fn evaluate_optional(&self, ordinal: usize) -> Result<Option<EvaluatedRoot>, CompilerError> {
        if self.is_selected(ordinal)? || self.is_dominated(ordinal)? {
            return Ok(None);
        }
        let candidate = self.candidate(ordinal)?;
        if candidate.features.lexical_match < self.profile.minimum_lexical_match {
            return Ok(None);
        }
        let delta = self.closure_delta(ordinal, false)?;
        if delta.closure_items == 0 || !self.second_evidence_is_admissible(ordinal, &delta)? {
            return Ok(None);
        }
        Ok(Some(EvaluatedRoot {
            ordinal,
            utility: self.marginal_utility(ordinal, &delta)?,
            delta,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh_affected_evaluations(
        &self,
        evaluations: &mut [Option<EvaluatedRoot>],
        generations: &mut [u32],
        heap: &mut BinaryHeap<EvaluationHeapEntry>,
        selected_root: usize,
        changed_requirements: RequirementBits,
        changed_entities: u64,
        changed_lanes: u8,
    ) -> Result<(), CompilerError> {
        let selected_closure = &self.state(selected_root)?.optional_closure;
        for ordinal in 0..self.versions.len() {
            if self.is_selected(ordinal)? || self.is_dominated(ordinal)? {
                if get(evaluations, ordinal)?.is_some() {
                    *get_mut(evaluations, ordinal)? = None;
                    increment_generation(generations, ordinal)?;
                }
                continue;
            }
            let closure = &self.state(ordinal)?.optional_closure;
            let affected = closure.requirement_bits.intersects(changed_requirements)
                || closure.entity_bits & changed_entities != 0
                || closure.lane_bits & changed_lanes != 0
                || closures_overlap(closure, selected_closure);
            if affected {
                *get_mut(evaluations, ordinal)? = self.evaluate_optional(ordinal)?;
                let generation = increment_generation(generations, ordinal)?;
                if let Some(evaluated) = get(evaluations, ordinal)?.as_ref() {
                    heap.push(self.heap_entry(*evaluated, generation)?);
                }
            }
        }
        Ok(())
    }

    fn heap_entry(
        &self,
        evaluated: EvaluatedRoot,
        generation: u32,
    ) -> Result<EvaluationHeapEntry, CompilerError> {
        Ok(EvaluationHeapEntry {
            utility: evaluated.utility,
            tokens: delta_tokens(&evaluated.delta).unwrap_or(u32::MAX),
            ranking_priority: get(&self.ranking_priorities, evaluated.ordinal).copied()?,
            ordinal: evaluated.ordinal,
            generation,
        })
    }

    fn best_static(
        &self,
        ordinals: impl IntoIterator<Item = usize>,
        lossless_root: bool,
    ) -> Result<Option<usize>, CompilerError> {
        let mut best = None;
        for ordinal in ordinals {
            if self.is_selected(ordinal)? {
                continue;
            }
            let candidate = self.candidate(ordinal)?;
            if candidate.features.lexical_match < self.profile.minimum_lexical_match {
                continue;
            }
            let delta = self.closure_delta(ordinal, lossless_root)?;
            if !self.delta_fits(&delta) {
                continue;
            }
            if best
                .is_none_or(|current| self.ranked_static_order(ordinal, current) == Ordering::Less)
            {
                best = Some(ordinal);
            }
        }
        Ok(best)
    }

    fn has_competitive_optional(&self) -> Result<bool, CompilerError> {
        for ordinal in 0..self.versions.len() {
            if !self.is_selected(ordinal)?
                && self.candidate(ordinal)?.features.lexical_match
                    >= self.profile.minimum_lexical_match
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn admit(
        &mut self,
        root: usize,
        lossless_root: bool,
        basis: PackingDecisionBasis,
        evaluated: Option<(i64, ClosureDelta)>,
    ) -> Result<(), CompilerError> {
        let (marginal_utility, delta) = if let Some(value) = evaluated {
            value
        } else {
            let delta = self.closure_delta(root, lossless_root)?;
            let utility = self.marginal_utility(root, &delta)?;
            (utility, delta)
        };
        let incremental_tokens = delta
            .lane_tokens
            .iter()
            .try_fold(0_u32, |total, value| total.checked_add(*value))
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        let closure_items = delta.closure_items;
        let newly_covered_requirements = delta.newly_covered_requirements.len();
        let independently_corroborated_requirements =
            delta.independently_corroborated_requirements.len();
        let newly_covered_entities = (delta.entity_bits & !self.entity_bits).count_ones();
        let effect_adjacent = delta.effect_adjacent;
        let member_count = self.state(root)?.closure(lossless_root).members.len();
        for index in 0..member_count {
            let member = self
                .state(root)?
                .closure(lossless_root)
                .members
                .get(index)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
            let member_ordinal = member.ordinal;
            let representation = member.representation.clone();
            let utility = member.utility;
            self.select_member(root, member_ordinal, representation, utility)?;
        }
        let ordinal = self
            .decisions
            .len()
            .checked_add(1)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        self.decisions.push(PackingDecision {
            ordinal,
            selected_version: self.version(root)?.clone(),
            basis,
            marginal_utility,
            incremental_tokens,
            closure_items,
            newly_covered_requirements,
            independently_corroborated_requirements,
            newly_covered_entities,
            effect_adjacent,
        });
        Ok(())
    }

    fn select_member(
        &mut self,
        root: usize,
        member_ordinal: usize,
        representation: RepresentationVariant,
        utility: i64,
    ) -> Result<(), CompilerError> {
        if self.is_selected(member_ordinal)? {
            return Ok(());
        }
        let candidate = self.candidate(member_ordinal)?.clone();
        let state = self.state(member_ordinal)?;
        let source_ordinal = state.source_ordinal;
        let lineage_ordinal = state.lineage_ordinal;
        let content_ordinal = state.content_ordinal;
        let lane = lane_index(candidate.lane);
        let lane_tokens = self
            .lane_tokens
            .get(lane)
            .copied()
            .and_then(|value| value.checked_add(representation.token_count))
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        *get_mut(&mut self.lane_tokens, lane)? = lane_tokens;
        let lane_count = self
            .lane_counts
            .get(lane)
            .copied()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        *get_mut(&mut self.lane_counts, lane)? = lane_count;
        self.entity_bits |= candidate.entity_coverage_bits;
        for requirement in &candidate.requirement_indices {
            let requirement_state = get_mut(&mut self.requirement_state, *requirement)?;
            requirement_state.selected_count = requirement_state
                .selected_count
                .checked_add(1)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
            push_unique(&mut requirement_state.source_ordinals, source_ordinal);
            push_unique(&mut requirement_state.lineage_ordinals, lineage_ordinal);
            push_unique(&mut requirement_state.content_ordinals, content_ordinal);
            requirement_state.maximum_authority = requirement_state
                .maximum_authority
                .max(candidate.features.authority);
            requirement_state.maximum_freshness = requirement_state
                .maximum_freshness
                .max(candidate.features.freshness);
            requirement_state.conflict_evidence |= candidate.features.conflict_risk > 0;
        }
        *get_mut(&mut self.selected_bits, member_ordinal)? = true;
        if member_ordinal != root {
            *get_mut(&mut self.dependency_bits, member_ordinal)? = true;
        }
        self.selected.insert(
            candidate.version_id.clone(),
            Selection {
                candidate,
                representation,
                utility,
            },
        );
        Ok(())
    }

    fn closure_delta(
        &self,
        root: usize,
        lossless_root: bool,
    ) -> Result<ClosureDelta, CompilerError> {
        let closure = self.state(root)?.closure(lossless_root);
        let mut delta = ClosureDelta::default();
        for member in closure.members.iter() {
            if self.is_selected(member.ordinal)? {
                continue;
            }
            let candidate = self.candidate(member.ordinal)?;
            let state = self.state(member.ordinal)?;
            let lane = lane_index(candidate.lane);
            add_u32(
                &mut delta.lane_tokens,
                lane,
                member.representation.token_count,
            )?;
            add_u16(&mut delta.lane_counts, lane, 1)?;
            delta.lane_diverse |= self.lane_counts.get(lane).copied().unwrap_or_default() == 0;
            delta.entity_bits |= candidate.entity_coverage_bits;
            delta.conflict_evidence |= candidate.features.conflict_risk > 0;
            for requirement in &candidate.requirement_indices {
                let requirement_state = get(&self.requirement_state, *requirement)?;
                if requirement_state.selected_count == 0 {
                    delta.newly_covered_requirements.insert(*requirement)?;
                } else {
                    delta.repeated_requirements.insert(*requirement)?;
                    if independent(
                        requirement_state,
                        state.source_ordinal,
                        state.lineage_ordinal,
                        state.content_ordinal,
                    ) {
                        delta
                            .independently_corroborated_requirements
                            .insert(*requirement)?;
                    }
                }
                delta.authority_gain = delta.authority_gain.max(
                    candidate
                        .features
                        .authority
                        .saturating_sub(requirement_state.maximum_authority),
                );
                delta.freshness_gain = delta.freshness_gain.max(
                    candidate
                        .features
                        .freshness
                        .saturating_sub(requirement_state.maximum_freshness),
                );
                delta.effect_adjacent |= self.contract.operation_class
                    == OperationClass::ExternalMutation
                    && self
                        .contract
                        .requirements
                        .get(*requirement)
                        .is_some_and(|value| value.blocking);
            }
            delta.closure_items = delta
                .closure_items
                .checked_add(1)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        }
        Ok(delta)
    }

    fn marginal_utility(&self, root: usize, delta: &ClosureDelta) -> Result<i64, CompilerError> {
        let candidate = self.candidate(root)?;
        let candidate_utility = root_member(root, &self.state(root)?.optional_closure)?.utility;
        let dependency_items = delta.closure_items.saturating_sub(1);
        let tokens = delta
            .lane_tokens
            .iter()
            .try_fold(0_u32, |total, value| total.checked_add(*value))
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        let lane_diverse = delta.lane_diverse;
        let effect_gain = i64::from(
            delta.effect_adjacent
                && candidate
                    .requirement_indices
                    .iter()
                    .any(|requirement| self.requirement_count(*requirement) == Ok(1)),
        );
        marginal_utility_from_factors(MarginalFactors {
            candidate_utility,
            tokens,
            new_requirements: i64_count(delta.newly_covered_requirements.len())?,
            independent_requirements: i64_count(
                delta.independently_corroborated_requirements.len(),
            )?,
            effect_gain: effect_gain != 0,
            new_entities: i64::from((delta.entity_bits & !self.entity_bits).count_ones()),
            authority_gain: delta.authority_gain,
            freshness_gain: delta.freshness_gain,
            conflict_gain: delta.conflict_evidence,
            lane_diverse,
            repeated_requirements: i64_count(delta.repeated_requirements.len())?,
            redundant_entities: i64::from((delta.entity_bits & self.entity_bits).count_ones()),
            dependency_items: i64_count(dependency_items)?,
        })
    }

    fn second_evidence_is_admissible(
        &self,
        root: usize,
        delta: &ClosureDelta,
    ) -> Result<bool, CompilerError> {
        if !delta.newly_covered_requirements.is_empty() {
            return Ok(true);
        }
        let candidate = self.candidate(root)?;
        let contextual_gain = delta.entity_bits & !self.entity_bits != 0
            || delta.authority_gain > 0
            || delta.freshness_gain > 0
            || delta.conflict_evidence;
        for requirement in &candidate.requirement_indices {
            if !self
                .contract
                .requirements
                .get(*requirement)
                .is_some_and(|value| value.blocking)
            {
                continue;
            }
            let count = self.requirement_count(*requirement)?;
            if count == 1 {
                let effect_adjacent =
                    self.contract.operation_class == OperationClass::ExternalMutation;
                let independent = delta
                    .independently_corroborated_requirements
                    .contains(*requirement);
                if !(independent || effect_adjacent || contextual_gain) {
                    return Ok(false);
                }
            } else if count >= 2 && !contextual_gain {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn delta_fits(&self, delta: &ClosureDelta) -> bool {
        (0..LANE_COUNT).all(|lane| {
            let tokens = self.lane_tokens.get(lane).copied().and_then(|value| {
                delta
                    .lane_tokens
                    .get(lane)
                    .and_then(|added| value.checked_add(*added))
            });
            let counts = self.lane_counts.get(lane).copied().and_then(|value| {
                delta
                    .lane_counts
                    .get(lane)
                    .and_then(|added| value.checked_add(*added))
            });
            tokens.is_some_and(|value| {
                value <= self.lane_budgets.get(lane).copied().unwrap_or_default()
            }) && counts.is_some_and(|value| {
                value <= self.lane_maxima.get(lane).copied().unwrap_or_default()
            })
        })
    }

    fn dominates(&self, left: usize, right: usize) -> Result<bool, CompilerError> {
        let left_candidate = self.candidate(left)?;
        let right_candidate = self.candidate(right)?;
        let left_state = self.state(left)?;
        let right_state = self.state(right)?;
        if right_candidate.mandatory
            || right_candidate.policy_outcome == PolicyOutcome::Redact
            || left_candidate.lane != right_candidate.lane
            || left_candidate.policy_outcome != right_candidate.policy_outcome
            || left_candidate.classification != right_candidate.classification
            || left_candidate.instruction_authority != right_candidate.instruction_authority
            || left_candidate.provenance_digest != right_candidate.provenance_digest
            || left_state.source_ordinal != right_state.source_ordinal
            || left_state.lineage_ordinal != right_state.lineage_ordinal
            || !left_candidate
                .requirement_indices
                .is_superset(&right_candidate.requirement_indices)
            || left_candidate.entity_coverage_bits | right_candidate.entity_coverage_bits
                != left_candidate.entity_coverage_bits
            || left_candidate.claim != right_candidate.claim
            || left_candidate.features.authority < right_candidate.features.authority
            || left_candidate.features.verification < right_candidate.features.verification
            || left_candidate.features.freshness < right_candidate.features.freshness
            || left_candidate.features.conflict_risk != right_candidate.features.conflict_risk
            || left_state.optional_closure.members.len()
                != right_state.optional_closure.members.len()
            || !left_state
                .optional_closure
                .lane_tokens
                .iter()
                .zip(right_state.optional_closure.lane_tokens.iter())
                .all(|(left_tokens, right_tokens)| left_tokens <= right_tokens)
        {
            return Ok(false);
        }
        let left_dependencies = closure_dependencies(left, &left_state.optional_closure);
        let right_dependencies = closure_dependencies(right, &right_state.optional_closure);
        if left_dependencies != right_dependencies {
            return Ok(false);
        }
        let left_member = root_member(left, &left_state.optional_closure)?;
        let right_member = root_member(right, &right_state.optional_closure)?;
        if left_member.representation.loss > right_member.representation.loss {
            return Ok(false);
        }
        let left_utility = left_member.utility;
        let right_utility = right_member.utility;
        Ok(left_utility > right_utility
            || (left_utility == right_utility && self.static_order(left, right) == Ordering::Less))
    }

    fn ranked_static_order(&self, left: usize, right: usize) -> Ordering {
        let left_priority = self
            .ranking_priorities
            .get(left)
            .copied()
            .unwrap_or(usize::MAX);
        let right_priority = self
            .ranking_priorities
            .get(right)
            .copied()
            .unwrap_or(usize::MAX);
        left_priority
            .cmp(&right_priority)
            .then_with(|| self.static_order(left, right))
    }

    fn static_order(&self, left: usize, right: usize) -> Ordering {
        match (self.candidate(left), self.candidate(right)) {
            (Ok(left), Ok(right)) => candidate_order(left, right),
            _ => left.cmp(&right),
        }
    }

    fn independent_for_requirement(
        &self,
        ordinal: usize,
        requirement: usize,
    ) -> Result<bool, CompilerError> {
        let state = self.state(ordinal)?;
        Ok(independent(
            get(&self.requirement_state, requirement)?,
            state.source_ordinal,
            state.lineage_ordinal,
            state.content_ordinal,
        ))
    }

    fn is_protected(&self, ordinal: usize) -> Result<bool, CompilerError> {
        let candidate = self.candidate(ordinal)?;
        let state = self.state(ordinal)?;
        Ok(candidate.mandatory
            || candidate.policy_outcome == PolicyOutcome::Redact
            || state.exact_requirement_protected
            || state.sole_blocking_protected
            || self.dependency_bits.get(ordinal).copied().unwrap_or(true))
    }

    fn is_selected(&self, ordinal: usize) -> Result<bool, CompilerError> {
        self.selected_bits
            .get(ordinal)
            .copied()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))
    }

    fn is_dominated(&self, ordinal: usize) -> Result<bool, CompilerError> {
        self.dominated_by
            .get(ordinal)
            .map(Option::is_some)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))
    }

    fn requirement_count(&self, requirement: usize) -> Result<u16, CompilerError> {
        Ok(get(&self.requirement_state, requirement)?.selected_count)
    }

    fn candidate(&self, ordinal: usize) -> Result<&CompilerCandidate, CompilerError> {
        get(&self.candidates, ordinal).copied()
    }

    fn version(&self, ordinal: usize) -> Result<&VersionId, CompilerError> {
        get(&self.versions, ordinal)
    }

    fn state(&self, ordinal: usize) -> Result<&CandidateState, CompilerError> {
        get(&self.states, ordinal)
    }

    fn finish(self) -> Result<PackingResult, CompilerError> {
        let profile_digest = self.frozen.compiler_profile_digest.clone();
        let evidence_digest = packing_evidence_digest(
            &self.profile.profile_id,
            &profile_digest,
            &self.frozen.tokenizer_fingerprint,
            &self.workspace_fingerprint,
            &self.decisions,
            &self.dominance_decisions,
            self.stop_reason,
        )?;
        let evidence = PackingEvidence {
            compiler_profile_id: self.profile.profile_id.clone(),
            compiler_profile_digest: profile_digest,
            tokenizer_fingerprint: self.frozen.tokenizer_fingerprint.clone(),
            workspace_fingerprint: self.workspace_fingerprint,
            decisions: self.decisions,
            dominance_decisions: self.dominance_decisions,
            stop_reason: self.stop_reason,
            evidence_digest,
        };
        Ok(PackingResult {
            selected: self.selected,
            evidence,
        })
    }
}

impl PackingEvidence {
    /// Recomputes and validates the complete content-free v4 explanation.
    pub fn validate(&self) -> Result<(), CompilerError> {
        let ordinals_valid = self
            .decisions
            .iter()
            .enumerate()
            .all(|(index, decision)| decision.ordinal == index.saturating_add(1));
        let unique_roots = self
            .decisions
            .iter()
            .map(|decision| &decision.selected_version)
            .collect::<BTreeSet<_>>();
        let dominance_sorted = self.dominance_decisions.windows(2).all(|pair| {
            pair.first().zip(pair.get(1)).is_none_or(|(left, right)| {
                left.dominated_version < right.dominated_version
                    || (left.dominated_version == right.dominated_version
                        && left.dominating_version < right.dominating_version)
            })
        });
        let expected = packing_evidence_digest(
            &self.compiler_profile_id,
            &self.compiler_profile_digest,
            &self.tokenizer_fingerprint,
            &self.workspace_fingerprint,
            &self.decisions,
            &self.dominance_decisions,
            self.stop_reason,
        )?;
        if self.compiler_profile_id != "cigar.compiler-profile.balanced.v4"
            || !ordinals_valid
            || unique_roots.len() != self.decisions.len()
            || !dominance_sorted
            || expected != self.evidence_digest
        {
            Err(CompilerError::new(CompilerErrorCode::InvalidInput))
        } else {
            Ok(())
        }
    }
}

struct InternedStrings {
    ordinals: Vec<u16>,
    unique_count: usize,
}

fn intern_strings<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<InternedStrings, CompilerError> {
    let mut entries = values.enumerate().collect::<Vec<_>>();
    if entries.len() > usize::from(u16::MAX) {
        return Err(CompilerError::new(CompilerErrorCode::LimitExceeded));
    }
    entries.sort_unstable_by(|(left_position, left), (right_position, right)| {
        left.cmp(right)
            .then_with(|| left_position.cmp(right_position))
    });
    let mut output = vec![0_u16; entries.len()];
    let mut previous = None;
    let mut unique_count = 0_usize;
    for (position, value) in entries {
        if previous.is_none_or(|previous| previous != value) {
            unique_count = unique_count
                .checked_add(1)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        }
        let ordinal = u16::try_from(unique_count.saturating_sub(1))
            .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        *output
            .get_mut(position)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))? = ordinal;
        previous = Some(value);
    }
    Ok(InternedStrings {
        ordinals: output,
        unique_count,
    })
}

fn build_closure(
    root: usize,
    root_lossless: bool,
    profile: &CompilerProfile,
    eligible: &EligibleCandidates<'_>,
    versions: &[VersionId],
    ordinal_by_version: &BTreeMap<VersionId, usize>,
    representations: &[ChosenRepresentations],
) -> Result<ClosureCache, CompilerError> {
    let candidate = eligible
        .get(get(versions, root)?)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
    if candidate.dependencies.is_empty() {
        let chosen = get(representations, root)?;
        let representation = if root_lossless {
            chosen.lossless.as_ref().unwrap_or(&chosen.optional).clone()
        } else {
            chosen.optional.clone()
        };
        let mut cache = ClosureCache {
            members: ClosureMembers::Single(ClosureMember {
                ordinal: root,
                utility: candidate_utility(candidate, &representation, profile)?,
                representation: representation.clone(),
            }),
            ..ClosureCache::default()
        };
        let lane = lane_index(candidate.lane);
        add_u32(&mut cache.lane_tokens, lane, representation.token_count)?;
        add_u16(&mut cache.lane_counts, lane, 1)?;
        include_closure_summary(&mut cache, candidate)?;
        return Ok(cache);
    }
    let mut visited = BTreeSet::new();
    let mut members = Vec::new();
    append_closure(
        root,
        root,
        root_lossless,
        profile,
        eligible,
        versions,
        ordinal_by_version,
        representations,
        &mut visited,
        &mut members,
    )?;
    let mut cache = ClosureCache {
        members: ClosureMembers::Multiple(members),
        ..ClosureCache::default()
    };
    let member_count = cache.members.len();
    for index in 0..member_count {
        let member = cache
            .members
            .get(index)
            .cloned()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
        let candidate = eligible
            .get(get(versions, member.ordinal)?)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
        let lane = lane_index(candidate.lane);
        add_u32(
            &mut cache.lane_tokens,
            lane,
            member.representation.token_count,
        )?;
        add_u16(&mut cache.lane_counts, lane, 1)?;
        include_closure_summary(&mut cache, candidate)?;
    }
    Ok(cache)
}

fn include_closure_summary(
    cache: &mut ClosureCache,
    candidate: &CompilerCandidate,
) -> Result<(), CompilerError> {
    for requirement in &candidate.requirement_indices {
        cache.requirement_bits.insert(*requirement)?;
    }
    cache.entity_bits |= candidate.entity_coverage_bits;
    let lane = u32::try_from(lane_index(candidate.lane))
        .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    cache.lane_bits |= 1_u8
        .checked_shl(lane)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_closure(
    ordinal: usize,
    root: usize,
    root_lossless: bool,
    profile: &CompilerProfile,
    eligible: &EligibleCandidates<'_>,
    versions: &[VersionId],
    ordinal_by_version: &BTreeMap<VersionId, usize>,
    representations: &[ChosenRepresentations],
    visited: &mut BTreeSet<usize>,
    members: &mut Vec<ClosureMember>,
) -> Result<(), CompilerError> {
    if !visited.insert(ordinal) {
        return Ok(());
    }
    let candidate = eligible
        .get(get(versions, ordinal)?)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
    for dependency in &candidate.dependencies {
        let dependency_ordinal = ordinal_by_version
            .get(dependency)
            .copied()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
        append_closure(
            dependency_ordinal,
            root,
            root_lossless,
            profile,
            eligible,
            versions,
            ordinal_by_version,
            representations,
            visited,
            members,
        )?;
    }
    let chosen = get(representations, ordinal)?;
    let representation = if ordinal == root && !root_lossless {
        chosen.optional.clone()
    } else {
        chosen.lossless.as_ref().unwrap_or(&chosen.optional).clone()
    };
    members.push(ClosureMember {
        ordinal,
        utility: candidate_utility(candidate, &representation, profile)?,
        representation,
    });
    Ok(())
}

fn closure_dependencies(root: usize, closure: &ClosureCache) -> BTreeSet<usize> {
    closure
        .members
        .iter()
        .filter_map(|member| (member.ordinal != root).then_some(member.ordinal))
        .collect()
}

fn closures_overlap(left: &ClosureCache, right: &ClosureCache) -> bool {
    left.members.iter().any(|left_member| {
        right
            .members
            .iter()
            .any(|right_member| left_member.ordinal == right_member.ordinal)
    })
}

fn root_member(root: usize, closure: &ClosureCache) -> Result<&ClosureMember, CompilerError> {
    closure
        .members
        .iter()
        .find(|member| member.ordinal == root)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))
}

fn independent(state: &RequirementState, source: u16, lineage: u16, content: u16) -> bool {
    !state.source_ordinals.contains(&source)
        && !state.lineage_ordinals.contains(&lineage)
        && !state.content_ordinals.contains(&content)
}

fn push_unique(values: &mut Vec<u16>, value: u16) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn lane_index(lane: LaneKind) -> usize {
    match lane {
        LaneKind::Rules => 0,
        LaneKind::Task => 1,
        LaneKind::Evidence => 2,
        LaneKind::History => 3,
        LaneKind::Tools => 4,
    }
}

fn lanes() -> [(LaneKind, usize); LANE_COUNT] {
    [
        (LaneKind::Rules, 0),
        (LaneKind::Task, 1),
        (LaneKind::Evidence, 2),
        (LaneKind::History, 3),
        (LaneKind::Tools, 4),
    ]
}

fn lane_array_u32(values: &BTreeMap<LaneKind, u32>, default: u32) -> [u32; LANE_COUNT] {
    let mut output = [default; LANE_COUNT];
    for (lane, ordinal) in lanes() {
        if let Some(value) = values.get(&lane)
            && let Some(slot) = output.get_mut(ordinal)
        {
            *slot = *value;
        }
    }
    output
}

fn lane_array_u16(values: &BTreeMap<LaneKind, u16>, default: u16) -> [u16; LANE_COUNT] {
    let mut output = [default; LANE_COUNT];
    for (lane, ordinal) in lanes() {
        if let Some(value) = values.get(&lane)
            && let Some(slot) = output.get_mut(ordinal)
        {
            *slot = *value;
        }
    }
    output
}

fn add_u32(values: &mut [u32], ordinal: usize, value: u32) -> Result<(), CompilerError> {
    let slot = get_mut(values, ordinal)?;
    *slot = slot
        .checked_add(value)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    Ok(())
}

fn add_u16(values: &mut [u16], ordinal: usize, value: u16) -> Result<(), CompilerError> {
    let slot = get_mut(values, ordinal)?;
    *slot = slot
        .checked_add(value)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    Ok(())
}

fn delta_tokens(delta: &ClosureDelta) -> Option<u32> {
    delta
        .lane_tokens
        .iter()
        .try_fold(0_u32, |total, value| total.checked_add(*value))
}

fn i64_count(value: usize) -> Result<i64, CompilerError> {
    i64::try_from(value).map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))
}

fn increment_generation(values: &mut [u32], ordinal: usize) -> Result<u32, CompilerError> {
    let generation = get_mut(values, ordinal)?;
    *generation = generation
        .checked_add(1)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    Ok(*generation)
}

fn get<T>(values: &[T], ordinal: usize) -> Result<&T, CompilerError> {
    values
        .get(ordinal)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))
}

fn get_mut<T>(values: &mut [T], ordinal: usize) -> Result<&mut T, CompilerError> {
    values
        .get_mut(ordinal)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))
}

fn workspace_fingerprint(
    frozen: &FrozenInputs,
    eligible: &EligibleCandidates<'_>,
    versions: &[VersionId],
) -> Result<ContentDigest, CompilerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PACKING-WORKSPACE\0v2\0");
    hash_bytes(
        &mut hasher,
        frozen.compiler_profile_digest.as_str().as_bytes(),
    )?;
    hash_bytes(
        &mut hasher,
        frozen.tokenizer_fingerprint.as_str().as_bytes(),
    )?;
    hash_usize(&mut hasher, versions.len())?;
    for version in versions {
        let candidate = eligible
            .get(version)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        hash_bytes(&mut hasher, version.as_str().as_bytes())?;
        hash_bytes(&mut hasher, candidate.logical_id.as_str().as_bytes())?;
        hash_bytes(&mut hasher, candidate.lineage_id.as_str().as_bytes())?;
        hash_bytes(&mut hasher, candidate.canonical_uri.as_str().as_bytes())?;
        hasher.update([lane_index(candidate.lane) as u8]);
        hasher.update([u8::from(candidate.mandatory)]);
        hasher.update([policy_code(candidate.policy_outcome)]);
        hasher.update([classification_code(candidate.classification)]);
        hasher.update([authority_code(candidate.instruction_authority)]);
        hash_usize(&mut hasher, candidate.requirement_indices.len())?;
        for requirement in &candidate.requirement_indices {
            hash_usize(&mut hasher, *requirement)?;
        }
        hasher.update(candidate.entity_coverage_bits.to_be_bytes());
        for value in [
            candidate.features.requirement_match,
            candidate.features.exact_match,
            candidate.features.lexical_match,
            candidate.features.semantic_match,
            candidate.features.graph_proximity,
            candidate.features.project_proximity,
            candidate.features.task_proximity,
            candidate.features.authority,
            candidate.features.verification,
            candidate.features.freshness,
            candidate.features.novelty,
            candidate.features.conflict_risk,
            candidate.features.staleness,
        ] {
            hasher.update(value.to_be_bytes());
        }
        hasher.update(candidate.features.estimated_tokens.to_be_bytes());
        hasher.update(candidate.features.requirement_coverage_bits.to_be_bytes());
        hasher.update(candidate.features.entity_coverage_bits.to_be_bytes());
        hash_usize(&mut hasher, candidate.dependencies.len())?;
        for dependency in &candidate.dependencies {
            hash_bytes(&mut hasher, dependency.as_str().as_bytes())?;
        }
        hash_usize(&mut hasher, candidate.representations.len())?;
        for representation in &candidate.representations {
            hasher.update([representation_code(representation.kind)]);
            hash_bytes(
                &mut hasher,
                representation.content_digest.as_str().as_bytes(),
            )?;
            hasher.update(representation.token_count.to_be_bytes());
            hasher.update([loss_code(representation.loss)]);
            if let Some(receipt) = &representation.transform_receipt {
                hasher.update([1]);
                hash_bytes(&mut hasher, receipt.as_str().as_bytes())?;
            } else {
                hasher.update([0]);
            }
        }
        if let Some(claim) = &candidate.claim {
            hasher.update([1]);
            hash_bytes(&mut hasher, claim.key.as_bytes())?;
            hash_bytes(&mut hasher, claim.value_digest.as_str().as_bytes())?;
            hasher.update(claim.valid_at.unix_nanos().to_be_bytes());
            hasher.update(claim.observed_at.unix_nanos().to_be_bytes());
            hasher.update(claim.authority.to_be_bytes());
            hasher.update([u8::from(claim.verified)]);
        } else {
            hasher.update([0]);
        }
        hash_bytes(&mut hasher, candidate.provenance_digest.as_str().as_bytes())?;
    }
    content_digest(hasher)
}

#[allow(clippy::too_many_arguments)]
fn packing_evidence_digest(
    profile_id: &str,
    profile_digest: &ContentDigest,
    tokenizer_fingerprint: &ContentDigest,
    workspace_fingerprint: &ContentDigest,
    decisions: &[PackingDecision],
    dominance: &[PackingDominanceDecision],
    stop_reason: PackingStopReason,
) -> Result<ContentDigest, CompilerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-PACKING-EVIDENCE\0v1\0");
    hasher.update(profile_id);
    hasher.update(profile_digest.as_str());
    hasher.update(tokenizer_fingerprint.as_str());
    hasher.update(workspace_fingerprint.as_str());
    hash_usize(&mut hasher, decisions.len())?;
    for decision in decisions {
        hash_usize(&mut hasher, decision.ordinal)?;
        hasher.update(decision.selected_version.as_str());
        hasher.update([basis_code(decision.basis)]);
        hasher.update(decision.marginal_utility.to_be_bytes());
        hasher.update(decision.incremental_tokens.to_be_bytes());
        hash_usize(&mut hasher, decision.closure_items)?;
        hash_usize(&mut hasher, decision.newly_covered_requirements)?;
        hash_usize(
            &mut hasher,
            decision.independently_corroborated_requirements,
        )?;
        hasher.update(decision.newly_covered_entities.to_be_bytes());
        hasher.update([u8::from(decision.effect_adjacent)]);
    }
    hash_usize(&mut hasher, dominance.len())?;
    for decision in dominance {
        hasher.update(decision.dominated_version.as_str());
        hasher.update(decision.dominating_version.as_str());
        hasher.update([dominance_reason_code(decision.reason)]);
    }
    hasher.update([stop_code(stop_reason)]);
    content_digest(hasher)
}

fn hash_usize(hasher: &mut Sha256, value: usize) -> Result<(), CompilerError> {
    let value = u64::try_from(value)
        .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) -> Result<(), CompilerError> {
    hash_usize(hasher, value.len())?;
    hasher.update(value);
    Ok(())
}

fn content_digest(hasher: Sha256) -> Result<ContentDigest, CompilerError> {
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hasher.finalize() {
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0f));
    }
    ContentDigest::new(encoded)
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))
}

fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    })
}

const fn loss_code(loss: LossClass) -> u8 {
    match loss {
        LossClass::Lossless => 0,
        LossClass::Extractive => 1,
        LossClass::VerifiedLossy => 2,
    }
}

const fn policy_code(outcome: PolicyOutcome) -> u8 {
    match outcome {
        PolicyOutcome::Deny => 0,
        PolicyOutcome::Quarantine => 1,
        PolicyOutcome::RequireRefresh => 2,
        PolicyOutcome::Redact => 3,
        PolicyOutcome::RequireApproval => 4,
        PolicyOutcome::Allow => 5,
    }
}

const fn classification_code(classification: Classification) -> u8 {
    match classification {
        Classification::Public => 0,
        Classification::Internal => 1,
        Classification::Confidential => 2,
        Classification::Restricted => 3,
    }
}

const fn authority_code(authority: InstructionAuthority) -> u8 {
    match authority {
        InstructionAuthority::Data => 0,
        InstructionAuthority::Advisory => 1,
        InstructionAuthority::Project => 2,
        InstructionAuthority::System => 3,
    }
}

const fn representation_code(kind: RepresentationKind) -> u8 {
    match kind {
        RepresentationKind::Exact => 0,
        RepresentationKind::Extracted => 1,
        RepresentationKind::Summarized => 2,
        RepresentationKind::Redacted => 3,
    }
}

const fn basis_code(basis: PackingDecisionBasis) -> u8 {
    match basis {
        PackingDecisionBasis::Mandatory => 0,
        PackingDecisionBasis::BlockingRequirement => 1,
        PackingDecisionBasis::IndependentCorroboration => 2,
        PackingDecisionBasis::LaneMinimum => 3,
        PackingDecisionBasis::MarginalUtility => 4,
    }
}

const fn dominance_reason_code(reason: PackingDominanceReason) -> u8 {
    match reason {
        PackingDominanceReason::SameProvenanceNoWeakerValue => 0,
    }
}

const fn stop_code(reason: PackingStopReason) -> u8 {
    match reason {
        PackingStopReason::Exhausted => 0,
        PackingStopReason::NonPositiveMarginalUtility => 1,
        PackingStopReason::CapacitySaturated => 2,
    }
}
