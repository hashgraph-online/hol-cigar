//! Deterministic normalize, reconcile, close, pack, repair, and seal pipeline.

use crate::{
    CompileOutput, CompileRequest, CompilerCandidate, CompilerError, CompilerErrorCode,
    CompilerProfile, DispositionRecord, FrozenInputs, InvalidationRegistration, LossClass,
    RepresentationVariant, Selection, manifest_entries,
};
use cigar_canon::{
    SemanticEnvelopeProfile, normalize_nfc, parse_strict_json, semantic_multihash_v1,
    to_deterministic_cbor,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    CandidateDisposition, ContentDigest, ContextBlock, ContextBundle, ContextContract, ContextPlan,
    DispositionReason, ExtensionMap, FixedPoint, LaneKind, PlanLane, RepresentationKind,
    RequirementSelector, SchemaVersion, SelectionManifest, Validate, VersionId,
};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

const MAX_CANDIDATES: usize = 10_000;
const MAX_DEPENDENCY_VISITS: usize = 100_000;
const MAX_BALANCED_SCORE: i64 = 10_100_000;

/// Stateless default deterministic compiler; it performs no model or network calls.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicCompiler;

impl DeterministicCompiler {
    /// Runs the full deterministic compile path and seals protocol records.
    pub fn compile(&self, request: CompileRequest) -> Result<CompileOutput, CompilerError> {
        let contract = normalize_contract(request.contract)?;
        validate_profile(&request.profile)?;
        validate_frozen(&contract, &request.profile, &request.frozen)?;
        let contract_digest = contract_digest(&contract)?;
        let mut candidates = canonical_candidates(request.candidates, contract.requirements.len())?;
        validate_dependencies(&candidates)?;
        let mut dispositions = initial_dispositions(&candidates)?;
        reconcile_logical_duplicates(&mut candidates, &mut dispositions);
        reconcile_claims(&mut candidates, &mut dispositions)?;

        let eligible: BTreeMap<_, _> = candidates
            .iter()
            .filter(|(version, _candidate)| !dispositions.contains_key(*version))
            .map(|(version, candidate)| (version.clone(), candidate.clone()))
            .collect();
        let mut selected = BTreeMap::new();
        let mandatory_roots = mandatory_roots(&contract, &eligible)?;
        for version in mandatory_roots {
            insert_with_closure(&version, &eligible, &request.profile, true, &mut selected)?;
        }
        enforce_budget(&contract, &selected)?;
        enforce_profile_item_limits(&request.profile, &eligible, &selected, false)?;
        satisfy_lane_minima(&contract, &request.profile, &eligible, &mut selected)?;
        pack_optional(&contract, &request.profile, &eligible, &mut selected)?;
        local_swaps(&contract, &request.profile, &eligible, &mut selected)?;
        enforce_budget(&contract, &selected)?;
        enforce_profile_item_limits(&request.profile, &eligible, &selected, true)?;
        ensure_blocking_requirements(&contract, &selected)?;

        finalize_dispositions(&candidates, &selected, &mut dispositions)?;
        seal(
            contract,
            contract_digest,
            request.frozen,
            selected,
            dispositions,
        )
    }
}

fn normalize_contract(mut contract: ContextContract) -> Result<ContextContract, CompilerError> {
    contract.job_goal = normalize_space(&normalize_nfc(&contract.job_goal));
    contract.purpose = normalize_space(&normalize_nfc(&contract.purpose)).to_lowercase();
    contract.target.provider = normalize_space(&contract.target.provider).to_lowercase();
    contract.target.model_family = normalize_space(&contract.target.model_family).to_lowercase();
    contract.project_ids.sort();
    contract.project_ids.dedup();
    for requirement in &mut contract.requirements {
        if let RequirementSelector::Query(query) = &mut requirement.selector {
            *query = normalize_space(&normalize_nfc(query));
        }
    }
    contract
        .validate()
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))?;
    Ok(contract)
}

fn normalize_space(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_profile(profile: &CompilerProfile) -> Result<(), CompilerError> {
    if profile.profile_id != "cigar.compiler-profile.balanced.v1"
        || profile.local_swap_passes > crate::MAX_LOCAL_SWAP_PASSES
        || profile.local_swap_alternatives == 0
        || profile.local_swap_alternatives > 256
        || profile.requirement_coverage_weight < 0
        || profile.entity_coverage_weight < 0
        || profile.loss_penalty < 0
        || profile.maximum_items.values().any(|maximum| *maximum == 0)
        || profile.minimum_items.iter().any(|(lane, minimum)| {
            profile
                .maximum_items
                .get(lane)
                .is_some_and(|maximum| minimum > maximum)
        })
    {
        Err(CompilerError::new(CompilerErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn validate_frozen(
    contract: &ContextContract,
    profile: &CompilerProfile,
    frozen: &FrozenInputs,
) -> Result<(), CompilerError> {
    if frozen.index_fingerprints.is_empty()
        || frozen.tokenizer_fingerprint != contract.target.tokenizer_fingerprint
        || frozen.materializer_fingerprint != contract.target.materializer_fingerprint
        || frozen.compiler_profile_digest != profile_digest(profile)?
    {
        Err(CompilerError::new(CompilerErrorCode::PinMismatch))
    } else {
        Ok(())
    }
}

fn canonical_candidates(
    candidates: Vec<CompilerCandidate>,
    requirement_count: usize,
) -> Result<BTreeMap<VersionId, CompilerCandidate>, CompilerError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(CompilerError::new(CompilerErrorCode::LimitExceeded));
    }
    let mut output = BTreeMap::new();
    for mut candidate in candidates {
        candidate
            .features
            .balanced_score()
            .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        if candidate.representations.is_empty()
            || candidate.requirement_indices.len() > 1_024
            || candidate
                .requirement_indices
                .iter()
                .any(|index| *index >= requirement_count)
        {
            return Err(CompilerError::new(CompilerErrorCode::InvalidInput));
        }
        candidate.representations.sort_by(representation_order);
        let mut identities = BTreeSet::new();
        for representation in &candidate.representations {
            let receipt_required = matches!(
                representation.kind,
                RepresentationKind::Extracted | RepresentationKind::Summarized
            );
            if representation.token_count == 0
                || receipt_required != representation.transform_receipt.is_some()
                || !identities.insert((representation.kind, representation.content_digest.clone()))
            {
                return Err(CompilerError::new(CompilerErrorCode::InvalidInput));
            }
        }
        let version = candidate.version_id.clone();
        if output.insert(version, candidate).is_some() {
            return Err(CompilerError::new(CompilerErrorCode::InvalidInput));
        }
    }
    Ok(output)
}

fn representation_order(left: &RepresentationVariant, right: &RepresentationVariant) -> Ordering {
    left.loss
        .cmp(&right.loss)
        .then_with(|| left.token_count.cmp(&right.token_count))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.content_digest.cmp(&right.content_digest))
}

fn initial_dispositions(
    candidates: &BTreeMap<VersionId, CompilerCandidate>,
) -> Result<BTreeMap<VersionId, DispositionRecord>, CompilerError> {
    let mut output = BTreeMap::new();
    for (version, candidate) in candidates {
        let reason = candidate
            .pre_exclusion_reason
            .or(match candidate.policy_outcome {
                PolicyOutcome::Allow | PolicyOutcome::Redact => None,
                PolicyOutcome::Deny | PolicyOutcome::Quarantine => {
                    Some(DispositionReason::ScopeDenied)
                }
                PolicyOutcome::RequireRefresh => Some(DispositionReason::TemporalMismatch),
                PolicyOutcome::RequireApproval => Some(DispositionReason::TrustInsufficient),
            });
        if let Some(reason) = reason {
            if candidate.mandatory {
                return Err(CompilerError::new(CompilerErrorCode::PolicyDenied));
            }
            let disposition = if candidate.policy_outcome == PolicyOutcome::Redact {
                CandidateDisposition::Redacted { reason }
            } else {
                CandidateDisposition::Excluded { reason }
            };
            output.insert(
                version.clone(),
                DispositionRecord {
                    disposition,
                    reasons: BTreeSet::from([reason]),
                    provenance_digest: candidate.provenance_digest.clone(),
                },
            );
        }
    }
    Ok(output)
}

fn reconcile_logical_duplicates(
    candidates: &mut BTreeMap<VersionId, CompilerCandidate>,
    dispositions: &mut BTreeMap<VersionId, DispositionRecord>,
) {
    let mut groups: BTreeMap<VersionId, Vec<VersionId>> = BTreeMap::new();
    for (version, candidate) in candidates.iter() {
        if !dispositions.contains_key(version) {
            groups
                .entry(candidate.logical_id.clone())
                .or_default()
                .push(version.clone());
        }
    }
    for versions in groups.values_mut() {
        versions.sort_by(|left, right| candidate_order(&candidates[left], &candidates[right]));
        for duplicate in versions.iter().skip(1) {
            let candidate = &candidates[duplicate];
            dispositions.insert(
                duplicate.clone(),
                excluded(
                    candidate,
                    DispositionReason::LifecycleIneligible,
                    BTreeSet::from([DispositionReason::LifecycleIneligible]),
                ),
            );
        }
    }
}

fn reconcile_claims(
    candidates: &mut BTreeMap<VersionId, CompilerCandidate>,
    dispositions: &mut BTreeMap<VersionId, DispositionRecord>,
) -> Result<(), CompilerError> {
    let mut groups: BTreeMap<String, Vec<VersionId>> = BTreeMap::new();
    for (version, candidate) in candidates.iter() {
        if !dispositions.contains_key(version)
            && let Some(claim) = &candidate.claim
        {
            groups
                .entry(claim.key.clone())
                .or_default()
                .push(version.clone());
        }
    }
    for versions in groups.values_mut() {
        if versions.len() < 2 {
            continue;
        }
        versions.sort_by(|left, right| claim_order(&candidates[left], &candidates[right]));
        let winner = versions
            .first()
            .cloned()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        let winner_candidate = &candidates[&winner];
        let winner_claim = winner_candidate
            .claim
            .as_ref()
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
        for loser in versions.iter().skip(1) {
            let loser_candidate = &candidates[loser];
            let loser_claim = loser_candidate
                .claim
                .as_ref()
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidInput))?;
            if winner_claim.value_digest != loser_claim.value_digest {
                if claim_rank(winner_candidate) == claim_rank(loser_candidate)
                    && (matches!(winner_candidate.lane, LaneKind::Rules | LaneKind::Task)
                        || matches!(loser_candidate.lane, LaneKind::Rules | LaneKind::Task))
                {
                    return Err(CompilerError::new(
                        CompilerErrorCode::UnresolvedCriticalConflict,
                    ));
                }
                dispositions.insert(
                    loser.clone(),
                    excluded(
                        loser_candidate,
                        DispositionReason::ConflictLost,
                        BTreeSet::from([DispositionReason::ConflictLost]),
                    ),
                );
            }
        }
    }
    Ok(())
}

fn claim_rank(candidate: &CompilerCandidate) -> (i128, i128, u16, bool) {
    candidate.claim.as_ref().map_or((0, 0, 0, false), |claim| {
        (
            claim.valid_at.unix_nanos(),
            claim.observed_at.unix_nanos(),
            claim.authority,
            claim.verified,
        )
    })
}

fn claim_order(left: &CompilerCandidate, right: &CompilerCandidate) -> Ordering {
    claim_rank(right)
        .cmp(&claim_rank(left))
        .then_with(|| candidate_order(left, right))
}

fn validate_dependencies(
    candidates: &BTreeMap<VersionId, CompilerCandidate>,
) -> Result<(), CompilerError> {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut visits = 0_usize;
    for version in candidates.keys() {
        visit_dependency(
            version,
            candidates,
            &mut visiting,
            &mut visited,
            &mut visits,
        )?;
    }
    Ok(())
}

fn visit_dependency(
    version: &VersionId,
    candidates: &BTreeMap<VersionId, CompilerCandidate>,
    visiting: &mut BTreeSet<VersionId>,
    visited: &mut BTreeSet<VersionId>,
    visits: &mut usize,
) -> Result<(), CompilerError> {
    if visited.contains(version) {
        return Ok(());
    }
    *visits = visits
        .checked_add(1)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    if *visits > MAX_DEPENDENCY_VISITS || !visiting.insert(version.clone()) {
        return Err(CompilerError::new(CompilerErrorCode::InvalidDependency));
    }
    let candidate = candidates
        .get(version)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
    for dependency in &candidate.dependencies {
        if !candidates.contains_key(dependency) {
            return Err(CompilerError::new(CompilerErrorCode::InvalidDependency));
        }
        visit_dependency(dependency, candidates, visiting, visited, visits)?;
    }
    visiting.remove(version);
    visited.insert(version.clone());
    Ok(())
}

fn mandatory_roots(
    contract: &ContextContract,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
) -> Result<BTreeSet<VersionId>, CompilerError> {
    let mut roots: BTreeSet<_> = eligible
        .iter()
        .filter(|(_version, candidate)| candidate.mandatory)
        .map(|(version, _candidate)| version.clone())
        .collect();
    for (index, requirement) in contract.requirements.iter().enumerate() {
        if !requirement.blocking {
            continue;
        }
        let best = eligible
            .iter()
            .filter(|(_version, candidate)| candidate.requirement_indices.contains(&index))
            .min_by(|(_left_version, left), (_right_version, right)| candidate_order(left, right))
            .map(|(version, _candidate)| version.clone())
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::RequiredMissing))?;
        roots.insert(best);
    }
    Ok(roots)
}

fn insert_with_closure(
    version: &VersionId,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    profile: &CompilerProfile,
    lossless_required: bool,
    selected: &mut BTreeMap<VersionId, Selection>,
) -> Result<(), CompilerError> {
    if selected.contains_key(version) {
        return Ok(());
    }
    let candidate = eligible
        .get(version)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
    for dependency in &candidate.dependencies {
        insert_with_closure(dependency, eligible, profile, true, selected)?;
    }
    let representation = choose_representation(candidate, profile, lossless_required)?;
    let utility = candidate_utility(candidate, &representation, profile)?;
    selected.insert(
        version.clone(),
        Selection {
            candidate: candidate.clone(),
            representation,
            utility,
        },
    );
    Ok(())
}

fn choose_representation(
    candidate: &CompilerCandidate,
    profile: &CompilerProfile,
    lossless_required: bool,
) -> Result<RepresentationVariant, CompilerError> {
    candidate
        .representations
        .iter()
        .filter(|representation| !lossless_required || representation.loss == LossClass::Lossless)
        .max_by(|left, right| {
            let left_utility = candidate_utility(candidate, left, profile).unwrap_or(i64::MIN);
            let right_utility = candidate_utility(candidate, right, profile).unwrap_or(i64::MIN);
            ratio_order(
                left_utility,
                left.token_count,
                right_utility,
                right.token_count,
            )
            .then_with(|| representation_order(right, left))
        })
        .cloned()
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::BudgetUnsatisfiable))
}

fn candidate_utility(
    candidate: &CompilerCandidate,
    representation: &RepresentationVariant,
    profile: &CompilerProfile,
) -> Result<i64, CompilerError> {
    let base = candidate
        .features
        .balanced_score()
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))?;
    let requirement_count = i64::try_from(candidate.requirement_indices.len())
        .map_err(|_error| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    let entity_count = i64::from(candidate.entity_coverage_bits.count_ones());
    let loss = match representation.loss {
        LossClass::Lossless => 0_i64,
        LossClass::Extractive => 1,
        LossClass::VerifiedLossy => 2,
    };
    base.checked_add(
        profile
            .requirement_coverage_weight
            .checked_mul(requirement_count)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?,
    )
    .and_then(|value| {
        profile
            .entity_coverage_weight
            .checked_mul(entity_count)
            .and_then(|gain| value.checked_add(gain))
    })
    .and_then(|value| {
        profile
            .loss_penalty
            .checked_mul(loss)
            .and_then(|penalty| value.checked_sub(penalty))
    })
    .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))
}

fn satisfy_lane_minima(
    contract: &ContextContract,
    profile: &CompilerProfile,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    selected: &mut BTreeMap<VersionId, Selection>,
) -> Result<(), CompilerError> {
    for (lane, minimum) in &profile.minimum_items {
        if !eligible.values().any(|candidate| candidate.lane == *lane) {
            continue;
        }
        while selected
            .values()
            .filter(|selection| &selection.candidate.lane == lane)
            .count()
            < usize::from(*minimum)
        {
            let choice = ranked_unselected(eligible, selected, Some(*lane), profile)?
                .into_iter()
                .find(|version| closure_fits(version, contract, eligible, profile, selected))
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::BudgetUnsatisfiable))?;
            insert_with_closure(&choice, eligible, profile, false, selected)?;
        }
    }
    Ok(())
}

fn pack_optional(
    contract: &ContextContract,
    profile: &CompilerProfile,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    selected: &mut BTreeMap<VersionId, Selection>,
) -> Result<(), CompilerError> {
    let mut used = current_usage(selected)?;
    for version in ranked_unselected(eligible, selected, None, profile)? {
        if lane_at_cap(&eligible[&version], profile, selected) {
            continue;
        }
        let representation = choose_representation(&eligible[&version], profile, false)?;
        if candidate_utility(&eligible[&version], &representation, profile)? <= 0 {
            continue;
        }
        let Some((proposed_usage, additions)) =
            usage_with_closure(&version, eligible, profile, selected, &used)
        else {
            continue;
        };
        if !usage_fits(contract, &proposed_usage)
            || !additions_respect_item_maxima(&additions, eligible, profile, selected)
        {
            continue;
        }
        insert_with_closure(&version, eligible, profile, false, selected)?;
        used = proposed_usage;
    }
    Ok(())
}

fn ranked_unselected(
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    selected: &BTreeMap<VersionId, Selection>,
    lane: Option<LaneKind>,
    profile: &CompilerProfile,
) -> Result<Vec<VersionId>, CompilerError> {
    let mut values = Vec::new();
    for (version, candidate) in eligible {
        if selected.contains_key(version) || lane.is_some_and(|expected| candidate.lane != expected)
        {
            continue;
        }
        let representation = choose_representation(candidate, profile, false)?;
        let utility = candidate_utility(candidate, &representation, profile)?;
        values.push((version.clone(), utility, representation.token_count));
    }
    values.sort_by(|left, right| {
        ratio_order(right.1, right.2, left.1, left.2)
            .then_with(|| candidate_order(&eligible[&left.0], &eligible[&right.0]))
    });
    Ok(values.into_iter().map(|value| value.0).collect())
}

fn ratio_order(
    left_utility: i64,
    left_tokens: u32,
    right_utility: i64,
    right_tokens: u32,
) -> Ordering {
    let left = i128::from(left_utility) * i128::from(right_tokens.max(1));
    let right = i128::from(right_utility) * i128::from(left_tokens.max(1));
    left.cmp(&right)
}

fn closure_fits(
    version: &VersionId,
    contract: &ContextContract,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    profile: &CompilerProfile,
    selected: &BTreeMap<VersionId, Selection>,
) -> bool {
    current_usage(selected)
        .ok()
        .and_then(|used| usage_with_closure(version, eligible, profile, selected, &used))
        .is_some_and(|(used, additions)| {
            usage_fits(contract, &used)
                && additions_respect_item_maxima(&additions, eligible, profile, selected)
        })
}

fn current_usage(
    selected: &BTreeMap<VersionId, Selection>,
) -> Result<BTreeMap<LaneKind, u32>, CompilerError> {
    let mut used = BTreeMap::<LaneKind, u32>::new();
    for selection in selected.values() {
        let total = used.entry(selection.candidate.lane).or_default();
        *total = total
            .checked_add(selection.representation.token_count)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    }
    Ok(used)
}

fn usage_with_closure(
    version: &VersionId,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    profile: &CompilerProfile,
    selected: &BTreeMap<VersionId, Selection>,
    used: &BTreeMap<LaneKind, u32>,
) -> Option<(BTreeMap<LaneKind, u32>, BTreeSet<VersionId>)> {
    let mut proposed = used.clone();
    let mut additions = BTreeSet::new();
    collect_closure_cost(
        version,
        false,
        eligible,
        profile,
        selected,
        &mut additions,
        &mut proposed,
    )
    .ok()?;
    Some((proposed, additions))
}

fn additions_respect_item_maxima(
    additions: &BTreeSet<VersionId>,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    profile: &CompilerProfile,
    selected: &BTreeMap<VersionId, Selection>,
) -> bool {
    let mut counts = BTreeMap::<LaneKind, usize>::new();
    for selection in selected.values() {
        *counts.entry(selection.candidate.lane).or_default() += 1;
    }
    for version in additions {
        let Some(candidate) = eligible.get(version) else {
            return false;
        };
        *counts.entry(candidate.lane).or_default() += 1;
    }
    profile.maximum_items.iter().all(|(lane, maximum)| {
        counts.get(lane).copied().unwrap_or_default() <= usize::from(*maximum)
    })
}

fn usage_fits(contract: &ContextContract, used: &BTreeMap<LaneKind, u32>) -> bool {
    used.iter().all(|(lane, tokens)| {
        contract
            .budget
            .lane_input_tokens
            .get(lane)
            .is_some_and(|budget| tokens <= budget)
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_closure_cost(
    version: &VersionId,
    lossless_required: bool,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    profile: &CompilerProfile,
    selected: &BTreeMap<VersionId, Selection>,
    additions: &mut BTreeSet<VersionId>,
    used: &mut BTreeMap<LaneKind, u32>,
) -> Result<(), CompilerError> {
    if selected.contains_key(version) || !additions.insert(version.clone()) {
        return Ok(());
    }
    let candidate = eligible
        .get(version)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
    for dependency in &candidate.dependencies {
        collect_closure_cost(
            dependency, true, eligible, profile, selected, additions, used,
        )?;
    }
    let representation = choose_representation(candidate, profile, lossless_required)?;
    let total = used.entry(candidate.lane).or_default();
    *total = total
        .checked_add(representation.token_count)
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    Ok(())
}

fn lane_at_cap(
    candidate: &CompilerCandidate,
    profile: &CompilerProfile,
    selected: &BTreeMap<VersionId, Selection>,
) -> bool {
    profile
        .maximum_items
        .get(&candidate.lane)
        .is_some_and(|maximum| {
            selected
                .values()
                .filter(|selection| selection.candidate.lane == candidate.lane)
                .count()
                >= usize::from(*maximum)
        })
}

fn local_swaps(
    contract: &ContextContract,
    profile: &CompilerProfile,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    selected: &mut BTreeMap<VersionId, Selection>,
) -> Result<(), CompilerError> {
    if selected.len() == eligible.len() {
        return Ok(());
    }
    for _pass in 0..profile.local_swap_passes {
        let mut changed = false;
        let selected_optional: Vec<_> = selected
            .iter()
            .filter(|(_version, selection)| !selection.candidate.mandatory)
            .map(|(version, _selection)| version.clone())
            .collect();
        'outer: for removed in selected_optional {
            let Some(removed_selection) = selected.get(&removed).cloned() else {
                continue;
            };
            let mut base = selected.clone();
            base.remove(&removed);
            if selected
                .values()
                .any(|selection| selection.candidate.dependencies.contains(&removed))
            {
                continue;
            }
            let mut alternatives = ranked_unselected(
                eligible,
                selected,
                Some(removed_selection.candidate.lane),
                profile,
            )?;
            alternatives.truncate(usize::from(profile.local_swap_alternatives));
            for added in &alternatives {
                let mut proposed = base.clone();
                insert_with_closure(added, eligible, profile, false, &mut proposed)?;
                if repaired_selection_is_feasible(contract, profile, eligible, &proposed)
                    && proposed
                        .get(added)
                        .is_some_and(|selection| selection.utility > removed_selection.utility)
                {
                    *selected = proposed;
                    changed = true;
                    break 'outer;
                }
            }
            for (left_index, left) in alternatives.iter().enumerate() {
                for right in alternatives.iter().skip(left_index + 1) {
                    let mut proposed = base.clone();
                    insert_with_closure(left, eligible, profile, false, &mut proposed)?;
                    insert_with_closure(right, eligible, profile, false, &mut proposed)?;
                    let added_utility = proposed
                        .iter()
                        .filter(|(version, _selection)| !base.contains_key(*version))
                        .try_fold(0_i64, |total, (_version, selection)| {
                            total.checked_add(selection.utility)
                        })
                        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
                    if added_utility > removed_selection.utility
                        && repaired_selection_is_feasible(contract, profile, eligible, &proposed)
                    {
                        *selected = proposed;
                        changed = true;
                        break 'outer;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

fn repaired_selection_is_feasible(
    contract: &ContextContract,
    profile: &CompilerProfile,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    proposed: &BTreeMap<VersionId, Selection>,
) -> bool {
    enforce_budget(contract, proposed).is_ok()
        && enforce_profile_item_limits(profile, eligible, proposed, false).is_ok()
        && ensure_blocking_requirements(contract, proposed).is_ok()
}

fn enforce_budget(
    contract: &ContextContract,
    selected: &BTreeMap<VersionId, Selection>,
) -> Result<(), CompilerError> {
    let mut used = BTreeMap::<LaneKind, u32>::new();
    for selection in selected.values() {
        let total = used.entry(selection.candidate.lane).or_default();
        *total = total
            .checked_add(selection.representation.token_count)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    }
    let minimum_required = used
        .values()
        .try_fold(0_u32, |total, value| total.checked_add(*value));
    for (lane, tokens) in used {
        let budget = contract
            .budget
            .lane_input_tokens
            .get(&lane)
            .copied()
            .unwrap_or_default();
        if tokens > budget {
            return Err(CompilerError::budget(minimum_required.unwrap_or(u32::MAX)));
        }
    }
    Ok(())
}

fn enforce_profile_item_limits(
    profile: &CompilerProfile,
    eligible: &BTreeMap<VersionId, CompilerCandidate>,
    selected: &BTreeMap<VersionId, Selection>,
    enforce_minima: bool,
) -> Result<(), CompilerError> {
    let mut selected_counts = BTreeMap::<LaneKind, usize>::new();
    for selection in selected.values() {
        *selected_counts.entry(selection.candidate.lane).or_default() += 1;
    }
    if profile.maximum_items.iter().any(|(lane, maximum)| {
        selected_counts.get(lane).copied().unwrap_or_default() > usize::from(*maximum)
    }) {
        return Err(CompilerError::new(CompilerErrorCode::BudgetUnsatisfiable));
    }
    if enforce_minima
        && profile.minimum_items.iter().any(|(lane, minimum)| {
            eligible.values().any(|candidate| candidate.lane == *lane)
                && selected_counts.get(lane).copied().unwrap_or_default() < usize::from(*minimum)
        })
    {
        return Err(CompilerError::new(CompilerErrorCode::BudgetUnsatisfiable));
    }
    Ok(())
}

fn ensure_blocking_requirements(
    contract: &ContextContract,
    selected: &BTreeMap<VersionId, Selection>,
) -> Result<(), CompilerError> {
    for (index, requirement) in contract.requirements.iter().enumerate() {
        if requirement.blocking
            && !selected
                .values()
                .any(|selection| selection.candidate.requirement_indices.contains(&index))
        {
            return Err(CompilerError::new(CompilerErrorCode::RequiredMissing));
        }
    }
    Ok(())
}

fn finalize_dispositions(
    candidates: &BTreeMap<VersionId, CompilerCandidate>,
    selected: &BTreeMap<VersionId, Selection>,
    dispositions: &mut BTreeMap<VersionId, DispositionRecord>,
) -> Result<(), CompilerError> {
    for (version, candidate) in candidates {
        if let Some(selection) = selected.get(version) {
            dispositions.insert(
                version.clone(),
                DispositionRecord {
                    disposition: CandidateDisposition::Selected {
                        lane: candidate.lane,
                        score: quantized_score(selection.utility)?,
                    },
                    reasons: BTreeSet::new(),
                    provenance_digest: candidate.provenance_digest.clone(),
                },
            );
        } else if !dispositions.contains_key(version) {
            dispositions.insert(
                version.clone(),
                excluded(
                    candidate,
                    DispositionReason::BudgetDisplaced,
                    BTreeSet::from([DispositionReason::BudgetDisplaced]),
                ),
            );
        }
    }
    Ok(())
}

fn quantized_score(utility: i64) -> Result<FixedPoint, CompilerError> {
    let clamped = utility.clamp(0, MAX_BALANCED_SCORE);
    let scaled = clamped
        .checked_mul(i64::from(FixedPoint::ONE))
        .and_then(|value| value.checked_div(MAX_BALANCED_SCORE))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    FixedPoint::new(scaled).map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))
}

fn excluded(
    candidate: &CompilerCandidate,
    reason: DispositionReason,
    reasons: BTreeSet<DispositionReason>,
) -> DispositionRecord {
    DispositionRecord {
        disposition: CandidateDisposition::Excluded { reason },
        reasons,
        provenance_digest: candidate.provenance_digest.clone(),
    }
}

fn candidate_order(left: &CompilerCandidate, right: &CompilerCandidate) -> Ordering {
    let left_score = left.features.balanced_score().unwrap_or(i64::MIN);
    let right_score = right.features.balanced_score().unwrap_or(i64::MIN);
    right_score
        .cmp(&left_score)
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
        .then_with(|| left.version_id.cmp(&right.version_id))
}

fn seal(
    contract: ContextContract,
    contract_digest: ContentDigest,
    frozen: FrozenInputs,
    selected: BTreeMap<VersionId, Selection>,
    dispositions: BTreeMap<VersionId, DispositionRecord>,
) -> Result<CompileOutput, CompilerError> {
    let lanes = contract
        .budget
        .lane_input_tokens
        .iter()
        .map(|(kind, budget_tokens)| PlanLane {
            kind: *kind,
            budget_tokens: *budget_tokens,
            candidate_versions: selected
                .iter()
                .filter(|(_version, selection)| selection.candidate.lane == *kind)
                .map(|(version, _selection)| version.clone())
                .collect(),
        })
        .collect();
    let plan_id = deterministic_record_id(&[
        b"CIGAR-CONTEXT-PLAN\0v1\0",
        contract_digest.as_str().as_bytes(),
        frozen.catalog_watermark.as_str().as_bytes(),
        frozen.policy_digest.as_str().as_bytes(),
        frozen.retrieval_plan_digest.as_str().as_bytes(),
    ])?;
    let plan = ContextPlan {
        schema_version: SchemaVersion::new("cigar.context-plan", 1)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?,
        plan_id,
        contract_digest: contract_digest.clone(),
        catalog_watermark: frozen.catalog_watermark.clone(),
        total_input_tokens: contract.budget.total_input_tokens,
        lanes,
        dispositions: dispositions
            .iter()
            .map(|(version, record)| (version.clone(), record.disposition.clone()))
            .collect(),
        extensions: ExtensionMap::default(),
    };
    plan.validate()
        .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;

    let placeholder = VersionId::new(format!("1220{}", "0".repeat(64)))
        .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;
    let mut manifest = SelectionManifest {
        schema_version: SchemaVersion::new("cigar.selection-manifest", 1)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?,
        manifest_id: placeholder.clone(),
        contract_digest: contract_digest.clone(),
        entries: manifest_entries(&dispositions),
        extensions: ExtensionMap::default(),
    };
    manifest.manifest_id = VersionId::new(
        semantic_multihash_v1(SemanticEnvelopeProfile::Manifest, &manifest)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?,
    )
    .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;
    manifest
        .validate()
        .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;
    let manifest_digest = ContentDigest::new(manifest.manifest_id.as_str())
        .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;

    let mut blocks = Vec::with_capacity(selected.len());
    for selection in selected.values() {
        let provenance = closure_provenance(&selection.candidate, &selected)?;
        let block_id = block_id(selection, &provenance)?;
        blocks.push(ContextBlock {
            block_id,
            lane: selection.candidate.lane,
            representation: selection.representation.kind,
            content_digest: selection.representation.content_digest.clone(),
            token_count: selection.representation.token_count,
            provenance,
            transform_receipt: selection.representation.transform_receipt.clone(),
        });
    }
    blocks.sort_by(|left, right| {
        left.lane
            .cmp(&right.lane)
            .then_with(|| left.block_id.cmp(&right.block_id))
    });
    let total_tokens = blocks
        .iter()
        .try_fold(0_u32, |total, block| total.checked_add(block.token_count))
        .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
    let mut bundle = ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?,
        bundle_id: placeholder,
        contract_digest: contract_digest.clone(),
        manifest_digest,
        blocks,
        total_tokens,
        extensions: ExtensionMap::default(),
    };
    bundle.bundle_id = VersionId::new(
        semantic_multihash_v1(SemanticEnvelopeProfile::Bundle, &bundle)
            .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?,
    )
    .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;
    bundle
        .validate()
        .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))?;
    let invalidation = InvalidationRegistration {
        catalog_versions: selected.keys().cloned().collect(),
        policy_digest: frozen.policy_digest,
        index_fingerprints: frozen.index_fingerprints,
        retrieval_plan_digest: frozen.retrieval_plan_digest,
        compiler_profile_digest: frozen.compiler_profile_digest,
    };
    Ok(CompileOutput {
        normalized_contract: contract,
        plan,
        manifest,
        bundle,
        invalidation,
    })
}

fn closure_provenance(
    candidate: &CompilerCandidate,
    selected: &BTreeMap<VersionId, Selection>,
) -> Result<Vec<VersionId>, CompilerError> {
    let mut provenance = BTreeSet::from([candidate.version_id.clone()]);
    let mut frontier: Vec<_> = candidate.dependencies.iter().cloned().collect();
    let mut visits = 0_usize;
    while let Some(version) = frontier.pop() {
        visits = visits
            .checked_add(1)
            .ok_or_else(|| CompilerError::new(CompilerErrorCode::LimitExceeded))?;
        if visits > MAX_DEPENDENCY_VISITS {
            return Err(CompilerError::new(CompilerErrorCode::LimitExceeded));
        }
        if provenance.insert(version.clone()) {
            let dependency = selected
                .get(&version)
                .ok_or_else(|| CompilerError::new(CompilerErrorCode::InvalidDependency))?;
            frontier.extend(dependency.candidate.dependencies.iter().cloned());
        }
    }
    Ok(provenance.into_iter().collect())
}

fn block_id(selection: &Selection, provenance: &[VersionId]) -> Result<VersionId, CompilerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-CONTEXT-BLOCK\0v1\0");
    hasher.update(selection.candidate.version_id.as_str());
    hasher.update(selection.representation.content_digest.as_str());
    hasher.update(format!("{:?}", selection.candidate.lane));
    hasher.update(format!("{:?}", selection.representation.kind));
    for version in provenance {
        hasher.update(version.as_str());
    }
    VersionId::new(multihash(hasher))
        .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))
}

fn contract_digest(contract: &ContextContract) -> Result<ContentDigest, CompilerError> {
    let json = serde_json::to_vec(contract)
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))?;
    let node = parse_strict_json(&json)
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))?;
    let cbor = to_deterministic_cbor(&node)
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-CONTEXT-CONTRACT\0v1\0");
    hasher.update(cbor);
    ContentDigest::new(multihash(hasher))
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))
}

fn profile_digest(profile: &CompilerProfile) -> Result<ContentDigest, CompilerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-COMPILER-PROFILE\0v1\0");
    hasher.update(profile.profile_id.as_bytes());
    for (lane, value) in &profile.minimum_items {
        hasher.update(format!("{lane:?}"));
        hasher.update(value.to_be_bytes());
    }
    for (lane, value) in &profile.maximum_items {
        hasher.update(format!("{lane:?}"));
        hasher.update(value.to_be_bytes());
    }
    hasher.update(profile.local_swap_passes.to_be_bytes());
    hasher.update(profile.local_swap_alternatives.to_be_bytes());
    hasher.update(profile.requirement_coverage_weight.to_be_bytes());
    hasher.update(profile.entity_coverage_weight.to_be_bytes());
    hasher.update(profile.loss_penalty.to_be_bytes());
    ContentDigest::new(multihash(hasher))
        .map_err(|_error| CompilerError::new(CompilerErrorCode::InvalidInput))
}

/// Computes the deterministic profile digest required by `FrozenInputs`.
pub fn compiler_profile_digest(profile: &CompilerProfile) -> Result<ContentDigest, CompilerError> {
    profile_digest(profile)
}

fn multihash(hasher: Sha256) -> String {
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn deterministic_record_id(parts: &[&[u8]]) -> Result<cigar_protocol::RecordId, CompilerError> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    cigar_protocol::RecordId::new(format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    ))
    .map_err(|_error| CompilerError::new(CompilerErrorCode::SealFailed))
}
