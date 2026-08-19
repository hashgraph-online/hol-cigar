//! Dense request-scoped state for requirement-aware candidate ranking.

use crate::bounded::{
    CandidateRankingDecision, CandidateRankingFactors, MergedCandidate, RequirementRankingEvidence,
};
use crate::{
    CandidateBounds, CandidateSelectionProfile, MatchEvidence, QueryPlan, RequirementRiskClass,
    RetrievalContext, RetrievalError, RetrievalErrorCode, RetrievalProfile,
};
use cigar_protocol::{AtomKind, ContentDigest, LaneKind};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;

pub(super) const MAX_DENSE_REQUIREMENTS: usize = 256;
const REQUIREMENT_WORDS: usize = MAX_DENSE_REQUIREMENTS / u64::BITS as usize;
pub(super) const CANCELLATION_SCAN_STRIDE: usize = 32;
const LANE_COUNT: usize = 5;
const ATOM_KIND_COUNT: usize = 10;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RequirementBits([u64; REQUIREMENT_WORDS]);

impl RequirementBits {
    fn from_indices<'a>(
        indices: impl IntoIterator<Item = &'a usize>,
    ) -> Result<Self, RetrievalError> {
        let mut output = Self::default();
        for index in indices {
            if *index >= MAX_DENSE_REQUIREMENTS {
                return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
            }
            let word = index / u64::BITS as usize;
            let bit = index % u64::BITS as usize;
            let word = output
                .0
                .get_mut(word)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
            *word |= 1_u64 << bit;
        }
        Ok(output)
    }

    fn union_assign(&mut self, other: Self) {
        for (left, right) in self.0.iter_mut().zip(other.0) {
            *left |= right;
        }
    }

    fn difference(self, other: Self) -> Self {
        let mut output = Self::default();
        for ((output, left), right) in output.0.iter_mut().zip(self.0).zip(other.0) {
            *output = left & !right;
        }
        output
    }

    fn intersection(self, other: Self) -> Self {
        let mut output = Self::default();
        for ((output, left), right) in output.0.iter_mut().zip(self.0).zip(other.0) {
            *output = left & right;
        }
        output
    }

    fn is_empty(self) -> bool {
        self.0.into_iter().all(|word| word == 0)
    }

    fn count(self) -> usize {
        self.0
            .into_iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    fn indices(self) -> BTreeSet<usize> {
        let mut output = BTreeSet::new();
        for (word_index, word) in self.0.into_iter().enumerate() {
            for bit in 0..u64::BITS as usize {
                if word & (1_u64 << bit) != 0 {
                    output.insert(word_index * u64::BITS as usize + bit);
                }
            }
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RankEvaluation {
    pub(super) factors: CandidateRankingFactors,
    pub(super) newly_covered_requirements: usize,
    pub(super) newly_covered_critical_requirements: usize,
    pub(super) newly_covered_concepts: u32,
    pub(super) source_diversity: bool,
    pub(super) section_diversity: bool,
    pub(super) kind_diversity: bool,
}

impl RankEvaluation {
    fn contextual_utility(self) -> Result<i64, RetrievalError> {
        self.factors
            .critical_requirement_gain
            .checked_add(self.factors.requirement_gain)
            .and_then(|value| value.checked_add(self.factors.concept_gain))
            .and_then(|value| value.checked_add(self.factors.diversity_gain))
            .and_then(|value| value.checked_sub(self.factors.generic_penalty))
            .and_then(|value| value.checked_sub(self.factors.redundancy_penalty))
            .and_then(|value| value.checked_sub(self.factors.similarity_penalty))
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RankedCandidate {
    pub(super) ordinal: usize,
    pub(super) evaluation: RankEvaluation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvidenceIdentity {
    source: u16,
    lineage: u16,
    content_family: u16,
}

impl EvidenceIdentity {
    const fn independent_from(self, other: Self) -> bool {
        self.source != other.source
            && self.lineage != other.lineage
            && self.content_family != other.content_family
    }
}

/// Canonical-ordinal state reused across every selection round in one request.
pub(super) struct RankingWorkspace<'a> {
    candidates: &'a [MergedCandidate],
    active: Vec<u8>,
    active_count: usize,
    requirement_bits: Vec<RequirementBits>,
    critical_bits: RequirementBits,
    covered_bits: RequirementBits,
    covered_concepts: u64,
    source_ordinals: Vec<u16>,
    section_ordinals: Vec<u16>,
    lineage_ordinals: Vec<u16>,
    content_family_ordinals: Vec<u16>,
    kind_ordinals: Vec<u16>,
    selected_sources: Vec<u8>,
    selected_sections: Vec<u8>,
    selected_kinds: [u8; ATOM_KIND_COUNT],
    similarity_penalties: Vec<i64>,
    lane_limits: [usize; LANE_COUNT],
    lane_counts: [u16; LANE_COUNT],
    requirement_limits: Vec<usize>,
    requirement_counts: Vec<u16>,
    reservation_targets: Vec<u8>,
    reservation_counts: Vec<u8>,
    primary_identities: Vec<Option<EvidenceIdentity>>,
    v4_policy: bool,
    profile: CandidateSelectionProfile,
    #[cfg(test)]
    similarity_updates: usize,
}

impl<'a> RankingWorkspace<'a> {
    pub(super) fn new(
        candidates: &'a [MergedCandidate],
        critical_requirements: &BTreeSet<usize>,
        profile: CandidateSelectionProfile,
        bounds: &CandidateBounds,
        preselected: &[MergedCandidate],
    ) -> Result<Self, RetrievalError> {
        Self::new_with_risk_classes(
            candidates,
            critical_requirements,
            profile,
            bounds,
            preselected,
            &[],
            false,
        )
    }

    pub(super) fn new_v4(
        candidates: &'a [MergedCandidate],
        critical_requirements: &BTreeSet<usize>,
        profile: CandidateSelectionProfile,
        bounds: &CandidateBounds,
        preselected: &[MergedCandidate],
        risk_classes: &[RequirementRiskClass],
    ) -> Result<Self, RetrievalError> {
        Self::new_with_risk_classes(
            candidates,
            critical_requirements,
            profile,
            bounds,
            preselected,
            risk_classes,
            true,
        )
    }

    fn new_with_risk_classes(
        candidates: &'a [MergedCandidate],
        critical_requirements: &BTreeSet<usize>,
        profile: CandidateSelectionProfile,
        bounds: &CandidateBounds,
        preselected: &[MergedCandidate],
        risk_classes: &[RequirementRiskClass],
        v4_policy: bool,
    ) -> Result<Self, RetrievalError> {
        let requirement_bits = candidates
            .iter()
            .map(|candidate| RequirementBits::from_indices(&candidate.requirement_indices))
            .collect::<Result<Vec<_>, _>>()?;
        let critical_bits = RequirementBits::from_indices(critical_requirements)?;
        let requirement_count = candidates
            .iter()
            .chain(preselected)
            .flat_map(|candidate| candidate.requirement_indices.iter().copied())
            .chain(critical_requirements.iter().copied())
            .max()
            .map_or(0, |maximum| maximum.saturating_add(1));
        if requirement_count > MAX_DENSE_REQUIREMENTS {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }
        if v4_policy && risk_classes.len() != requirement_count {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        if candidates
            .len()
            .checked_add(preselected.len())
            .is_none_or(|count| count > usize::from(u16::MAX))
            || bounds
                .lane_limits
                .values()
                .chain(bounds.requirement_limits.values())
                .any(|limit| *limit > usize::from(u16::MAX))
        {
            return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
        }

        let InternedOrdinals {
            candidates: source_ordinals,
            preselected: preselected_sources,
            unique_count: source_count,
        } = intern_sources(candidates, preselected)?;
        let InternedOrdinals {
            candidates: section_ordinals,
            preselected: preselected_sections,
            unique_count: section_count,
        } = intern_sections(candidates, preselected)?;
        let InternedOrdinals {
            candidates: lineage_ordinals,
            preselected: preselected_lineages,
            unique_count: _lineage_count,
        } = intern_lineages(candidates, preselected)?;
        let InternedOrdinals {
            candidates: content_family_ordinals,
            preselected: preselected_content_families,
            unique_count: _content_family_count,
        } = intern_content_families(candidates, preselected)?;
        let InternedOrdinals {
            candidates: kind_ordinals,
            preselected: preselected_kinds,
            unique_count: _kind_count,
        } = intern_kinds(candidates, preselected);
        let mut output = Self {
            candidates,
            active: vec![1; candidates.len()],
            active_count: candidates.len(),
            requirement_bits,
            critical_bits,
            covered_bits: RequirementBits::default(),
            covered_concepts: 0,
            source_ordinals,
            section_ordinals,
            lineage_ordinals,
            content_family_ordinals,
            kind_ordinals,
            selected_sources: vec![0; source_count],
            selected_sections: vec![0; section_count],
            selected_kinds: [0; ATOM_KIND_COUNT],
            similarity_penalties: vec![0; candidates.len()],
            lane_limits: lane_limits(bounds),
            lane_counts: [0; LANE_COUNT],
            requirement_limits: (0..requirement_count)
                .map(|requirement| {
                    bounds
                        .requirement_limits
                        .get(&requirement)
                        .copied()
                        .unwrap_or_default()
                })
                .collect(),
            requirement_counts: vec![0; requirement_count],
            reservation_targets: if v4_policy {
                risk_classes
                    .iter()
                    .map(|risk_class| risk_class.reserved_evidence())
                    .collect()
            } else {
                vec![0; requirement_count]
            },
            reservation_counts: vec![0; requirement_count],
            primary_identities: vec![None; requirement_count],
            v4_policy,
            profile,
            #[cfg(test)]
            similarity_updates: 0,
        };
        for (index, selected) in preselected.iter().enumerate() {
            output.include_external(
                selected,
                preselected_sources
                    .get(index)
                    .copied()
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
                preselected_sections
                    .get(index)
                    .copied()
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
                preselected_lineages
                    .get(index)
                    .copied()
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
                preselected_content_families
                    .get(index)
                    .copied()
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
                preselected_kinds
                    .get(index)
                    .copied()
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
            )?;
        }
        Ok(output)
    }

    pub(super) fn active_count(&self) -> usize {
        self.active_count
    }

    pub(super) fn uncovered_critical_requirements(&self) -> BTreeSet<usize> {
        self.critical_bits.difference(self.covered_bits).indices()
    }

    pub(super) fn uncovered_critical_after(&self, ordinal: usize) -> usize {
        let mut covered = self.covered_bits;
        if let Some(bits) = self.requirement_bits.get(ordinal) {
            covered.union_assign(*bits);
        }
        self.critical_bits.difference(covered).count()
    }

    pub(super) fn into_selected_flags(mut self) -> Vec<u8> {
        for active in &mut self.active {
            *active = u8::from(*active == 0);
        }
        self.active
    }

    pub(super) fn winner_and_runner_up(
        &self,
        bounded: bool,
        context: &RetrievalContext,
    ) -> Result<Option<(RankedCandidate, Option<RankedCandidate>)>, RetrievalError> {
        if self.active_count == 0 {
            return Ok(None);
        }
        context.check()?;
        let uncovered = self.critical_bits.difference(self.covered_bits);
        let require_reservation = bounded && self.v4_policy && self.has_unmet_reservations();
        let require_critical = !require_reservation && !uncovered.is_empty();
        if bounded && !self.has_remaining_capacity() {
            return Ok(None);
        }
        if self.active_count == 1 {
            let ordinal = self
                .active
                .iter()
                .position(|active| *active != 0)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            if !self.is_eligible(
                ordinal,
                bounded,
                require_critical,
                require_reservation,
                uncovered,
            ) {
                return Ok(None);
            }
            let evaluation = self.evaluate(ordinal)?;
            if bounded
                && self.v4_policy
                && !require_reservation
                && evaluation.contextual_utility()? <= 0
            {
                return Ok(None);
            }
            return Ok(Some((
                RankedCandidate {
                    ordinal,
                    evaluation,
                },
                None,
            )));
        }
        let mut winner: Option<RankedCandidate> = None;
        let mut runner_up: Option<RankedCandidate> = None;
        for ordinal in 0..self.candidates.len() {
            if scan_poll_due(ordinal) {
                context.check()?;
            }
            if !self.is_eligible(
                ordinal,
                bounded,
                require_critical,
                require_reservation,
                uncovered,
            ) {
                continue;
            }
            let evaluation = self.evaluate(ordinal)?;
            if bounded
                && self.v4_policy
                && !require_reservation
                && evaluation.contextual_utility()? <= 0
            {
                continue;
            }
            let ranked = RankedCandidate {
                ordinal,
                evaluation,
            };
            if winner.is_none_or(|current| self.is_better(ranked, current)) {
                runner_up = winner;
                winner = Some(ranked);
            } else if runner_up.is_none_or(|current| self.is_better(ranked, current)) {
                runner_up = Some(ranked);
            }
        }
        Ok(winner.map(|winner| (winner, runner_up)))
    }

    fn is_eligible(
        &self,
        ordinal: usize,
        bounded: bool,
        require_critical: bool,
        require_reservation: bool,
        uncovered: RequirementBits,
    ) -> bool {
        self.active.get(ordinal).copied().unwrap_or_default() != 0
            && (!bounded || self.within_bounds(ordinal))
            && (!require_critical
                || self
                    .requirement_bits
                    .get(ordinal)
                    .is_some_and(|bits| !bits.intersection(uncovered).is_empty()))
            && (!require_reservation || self.advances_reservation(ordinal))
    }

    fn has_unmet_reservations(&self) -> bool {
        self.reservation_counts
            .iter()
            .zip(&self.reservation_targets)
            .any(|(count, target)| count < target)
    }

    fn advances_reservation(&self, ordinal: usize) -> bool {
        let Some(candidate) = self.candidates.get(ordinal) else {
            return false;
        };
        let Some(identity) = self.evidence_identity(ordinal) else {
            return false;
        };
        candidate.requirement_indices.iter().any(|requirement| {
            let Some((&count, &target)) = self
                .reservation_counts
                .get(*requirement)
                .zip(self.reservation_targets.get(*requirement))
            else {
                return false;
            };
            count < target
                && (count == 0
                    || self
                        .primary_identities
                        .get(*requirement)
                        .and_then(|primary| *primary)
                        .is_some_and(|primary| identity.independent_from(primary)))
        })
    }

    fn evidence_identity(&self, ordinal: usize) -> Option<EvidenceIdentity> {
        Some(EvidenceIdentity {
            source: *self.source_ordinals.get(ordinal)?,
            lineage: *self.lineage_ordinals.get(ordinal)?,
            content_family: *self.content_family_ordinals.get(ordinal)?,
        })
    }

    fn has_remaining_capacity(&self) -> bool {
        self.lane_counts
            .into_iter()
            .zip(self.lane_limits)
            .any(|(count, limit)| usize::from(count) < limit)
            && self
                .requirement_counts
                .iter()
                .zip(&self.requirement_limits)
                .any(|(count, limit)| usize::from(*count) < *limit)
    }

    pub(super) fn include(
        &mut self,
        ordinal: usize,
        count_optional_lane: bool,
    ) -> Result<(), RetrievalError> {
        let active = self
            .active
            .get_mut(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        if *active == 0 {
            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
        }
        *active = 0;
        self.active_count = self
            .active_count
            .checked_sub(1)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let candidate = self
            .candidates
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let identity_ordinals = (
            *self
                .source_ordinals
                .get(ordinal)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
            *self
                .section_ordinals
                .get(ordinal)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
            *self
                .lineage_ordinals
                .get(ordinal)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
            *self
                .content_family_ordinals
                .get(ordinal)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
            *self
                .kind_ordinals
                .get(ordinal)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?,
        );
        self.include_identity(candidate, identity_ordinals, count_optional_lane)
    }

    fn include_external(
        &mut self,
        candidate: &MergedCandidate,
        source_ordinal: u16,
        section_ordinal: u16,
        lineage_ordinal: u16,
        content_family_ordinal: u16,
        kind_ordinal: u16,
    ) -> Result<(), RetrievalError> {
        self.include_identity(
            candidate,
            (
                source_ordinal,
                section_ordinal,
                lineage_ordinal,
                content_family_ordinal,
                kind_ordinal,
            ),
            false,
        )
    }

    fn include_identity(
        &mut self,
        candidate: &MergedCandidate,
        identity_ordinals: (u16, u16, u16, u16, u16),
        count_optional_lane: bool,
    ) -> Result<(), RetrievalError> {
        let bits = RequirementBits::from_indices(&candidate.requirement_indices)?;
        self.covered_bits.union_assign(bits);
        self.covered_concepts |= candidate.candidate.features.entity_coverage_bits;
        let (
            source_ordinal,
            section_ordinal,
            lineage_ordinal,
            content_family_ordinal,
            kind_ordinal,
        ) = identity_ordinals;
        *self
            .selected_sources
            .get_mut(usize::from(source_ordinal))
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))? = 1;
        *self
            .selected_sections
            .get_mut(usize::from(section_ordinal))
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))? = 1;
        *self
            .selected_kinds
            .get_mut(usize::from(kind_ordinal))
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))? = 1;
        for requirement in &candidate.requirement_indices {
            let count = self
                .requirement_counts
                .get_mut(*requirement)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        if self.v4_policy {
            let identity = EvidenceIdentity {
                source: source_ordinal,
                lineage: lineage_ordinal,
                content_family: content_family_ordinal,
            };
            for requirement in &candidate.requirement_indices {
                let target = *self
                    .reservation_targets
                    .get(*requirement)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                let count = self
                    .reservation_counts
                    .get_mut(*requirement)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                if *count >= target {
                    continue;
                }
                let primary = self
                    .primary_identities
                    .get_mut(*requirement)
                    .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
                if *count == 0 {
                    *primary = Some(identity);
                    *count = 1;
                } else if primary.is_some_and(|value| identity.independent_from(value)) {
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
                }
            }
        }
        if count_optional_lane {
            let lane = lane_ordinal(lane_for_atom_kind(candidate.candidate.atom_kind));
            let count = self
                .lane_counts
                .get_mut(lane)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        for remaining in 0..self.candidates.len() {
            if self.active.get(remaining).copied().unwrap_or_default() == 0 {
                continue;
            }
            let mut penalty = 0_i64;
            if self.source_ordinals.get(remaining) == Some(&source_ordinal) {
                penalty = penalty.max(self.profile.same_source_penalty);
            }
            if self.lineage_ordinals.get(remaining) == Some(&lineage_ordinal) {
                penalty = penalty.max(self.profile.same_lineage_penalty);
            }
            if self.content_family_ordinals.get(remaining) == Some(&content_family_ordinal) {
                penalty = penalty.max(self.profile.same_content_penalty);
            }
            if self.kind_ordinals.get(remaining) == Some(&kind_ordinal) {
                penalty = penalty.max(self.profile.same_kind_penalty);
            }
            let current = self
                .similarity_penalties
                .get_mut(remaining)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            *current = (*current).max(penalty);
            #[cfg(test)]
            {
                self.similarity_updates = self.similarity_updates.saturating_add(1);
            }
        }
        Ok(())
    }

    fn within_bounds(&self, ordinal: usize) -> bool {
        let Some(candidate) = self.candidates.get(ordinal) else {
            return false;
        };
        let lane = lane_ordinal(lane_for_atom_kind(candidate.candidate.atom_kind));
        self.lane_counts
            .get(lane)
            .zip(self.lane_limits.get(lane))
            .is_some_and(|(count, limit)| usize::from(*count) < *limit)
            && candidate.requirement_indices.iter().any(|requirement| {
                self.requirement_counts
                    .get(*requirement)
                    .zip(self.requirement_limits.get(*requirement))
                    .is_some_and(|(count, limit)| usize::from(*count) < *limit)
            })
    }

    fn evaluate(&self, ordinal: usize) -> Result<RankEvaluation, RetrievalError> {
        let candidate = self
            .candidates
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let candidate_bits = *self
            .requirement_bits
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let new_requirements = candidate_bits.difference(self.covered_bits);
        let newly_covered_critical_requirements =
            new_requirements.intersection(self.critical_bits).count();
        let newly_covered_requirements = new_requirements.count();
        let newly_covered_noncritical = newly_covered_requirements
            .checked_sub(newly_covered_critical_requirements)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        let candidate_concepts = candidate.candidate.features.entity_coverage_bits;
        let newly_covered_concepts = (candidate_concepts & !self.covered_concepts).count_ones();
        let redundant_concepts = (candidate_concepts & self.covered_concepts).count_ones();
        let redundant_requirements = candidate_bits.intersection(self.covered_bits).count();
        let source_ordinal = *self
            .source_ordinals
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let section_ordinal = *self
            .section_ordinals
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let kind_ordinal = *self
            .kind_ordinals
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
        let source_diversity = self
            .selected_sources
            .get(usize::from(source_ordinal))
            .copied()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?
            == 0;
        let section_diversity = self
            .selected_sections
            .get(usize::from(section_ordinal))
            .copied()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?
            == 0;
        let kind_diversity = self
            .selected_kinds
            .get(usize::from(kind_ordinal))
            .copied()
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?
            == 0;
        let generic_match = candidate
            .candidate
            .evidence
            .contains(&MatchEvidence::Lexical)
            && candidate_concepts.count_ones() <= 1
            && !candidate.candidate.evidence.iter().any(|evidence| {
                matches!(
                    evidence,
                    MatchEvidence::ExactIdentity
                        | MatchEvidence::ExactPath
                        | MatchEvidence::DeclaredTerm
                )
            });
        let critical_requirement_gain = weighted_count(
            self.profile.critical_requirement_gain,
            newly_covered_critical_requirements,
        )?;
        let requirement_gain =
            weighted_count(self.profile.requirement_gain, newly_covered_noncritical)?;
        let concept_gain = weighted_count(
            self.profile.concept_gain,
            usize::try_from(newly_covered_concepts)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
        )?;
        let diversity_gain = [
            (self.profile.source_diversity_gain, source_diversity),
            (self.profile.section_diversity_gain, section_diversity),
            (self.profile.kind_diversity_gain, kind_diversity),
        ]
        .into_iter()
        .try_fold(0_i64, |total, (gain, applies)| {
            total
                .checked_add(if applies { gain } else { 0 })
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
        })?;
        let generic_penalty = if generic_match {
            self.profile.generic_match_penalty
        } else {
            0
        };
        let redundancy_penalty = weighted_count(
            self.profile.redundant_requirement_penalty,
            redundant_requirements,
        )?
        .checked_add(weighted_count(
            self.profile.redundant_concept_penalty,
            usize::try_from(redundant_concepts)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
        )?)
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        let similarity_penalty = *self
            .similarity_penalties
            .get(ordinal)
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
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
            .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        Ok(RankEvaluation {
            factors: CandidateRankingFactors {
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

    fn is_better(&self, left: RankedCandidate, right: RankedCandidate) -> bool {
        left.evaluation
            .factors
            .adjusted_score
            .cmp(&right.evaluation.factors.adjusted_score)
            .then_with(|| right.ordinal.cmp(&left.ordinal))
            == Ordering::Greater
    }

    #[cfg(test)]
    pub(super) const fn similarity_update_count(&self) -> usize {
        self.similarity_updates
    }
}

pub(super) const fn scan_poll_due(ordinal: usize) -> bool {
    ordinal > 0 && ordinal.is_multiple_of(CANCELLATION_SCAN_STRIDE)
}

struct InternedOrdinals {
    candidates: Vec<u16>,
    preselected: Vec<u16>,
    unique_count: usize,
}

fn intern_by(
    candidates: &[MergedCandidate],
    preselected: &[MergedCandidate],
    compare: impl Fn(&MergedCandidate, &MergedCandidate) -> Ordering,
) -> Result<InternedOrdinals, RetrievalError> {
    let total = candidates
        .len()
        .checked_add(preselected.len())
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
    if total > usize::from(u16::MAX) {
        return Err(RetrievalError::new(RetrievalErrorCode::LimitExceeded));
    }
    let mut entries = candidates
        .iter()
        .chain(preselected)
        .enumerate()
        .collect::<Vec<_>>();
    entries.sort_unstable_by(|(left_position, left), (right_position, right)| {
        compare(left, right).then_with(|| left_position.cmp(right_position))
    });
    let mut candidate_ordinals = vec![0; candidates.len()];
    let mut preselected_ordinals = vec![0; preselected.len()];
    let mut unique_count = 0_usize;
    let mut previous = None;
    for (position, candidate) in entries {
        let starts_group =
            previous.is_none_or(|previous| compare(previous, candidate) != Ordering::Equal);
        if starts_group {
            unique_count = unique_count
                .checked_add(1)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        let ordinal = u16::try_from(unique_count.saturating_sub(1))
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        if position < candidates.len() {
            *candidate_ordinals
                .get_mut(position)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))? =
                ordinal;
        } else {
            let index = position
                .checked_sub(candidates.len())
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))?;
            *preselected_ordinals
                .get_mut(index)
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::CorruptGeneration))? =
                ordinal;
        }
        previous = Some(candidate);
    }
    Ok(InternedOrdinals {
        candidates: candidate_ordinals,
        preselected: preselected_ordinals,
        unique_count,
    })
}

fn intern_sources(
    candidates: &[MergedCandidate],
    preselected: &[MergedCandidate],
) -> Result<InternedOrdinals, RetrievalError> {
    intern_by(candidates, preselected, |left, right| {
        left.candidate
            .canonical_uri
            .cmp(&right.candidate.canonical_uri)
    })
}

fn intern_sections(
    candidates: &[MergedCandidate],
    preselected: &[MergedCandidate],
) -> Result<InternedOrdinals, RetrievalError> {
    intern_by(candidates, preselected, |left, right| {
        left.candidate
            .canonical_uri
            .cmp(&right.candidate.canonical_uri)
            .then_with(|| {
                left.candidate
                    .relative_path
                    .cmp(&right.candidate.relative_path)
            })
    })
}

fn intern_lineages(
    candidates: &[MergedCandidate],
    preselected: &[MergedCandidate],
) -> Result<InternedOrdinals, RetrievalError> {
    intern_by(candidates, preselected, |left, right| {
        left.candidate.lineage_id.cmp(&right.candidate.lineage_id)
    })
}

fn intern_content_families(
    candidates: &[MergedCandidate],
    preselected: &[MergedCandidate],
) -> Result<InternedOrdinals, RetrievalError> {
    intern_by(candidates, preselected, |left, right| {
        left.candidate
            .atom_kind
            .cmp(&right.candidate.atom_kind)
            .then_with(|| {
                left.candidate
                    .content_digest
                    .cmp(&right.candidate.content_digest)
            })
            .then_with(|| {
                left.candidate
                    .classification
                    .cmp(&right.candidate.classification)
            })
            .then_with(|| {
                left.candidate
                    .instruction_authority
                    .cmp(&right.candidate.instruction_authority)
            })
    })
}

fn intern_kinds(
    candidates: &[MergedCandidate],
    preselected: &[MergedCandidate],
) -> InternedOrdinals {
    InternedOrdinals {
        candidates: candidates
            .iter()
            .map(|candidate| atom_kind_ordinal(candidate.candidate.atom_kind))
            .collect(),
        preselected: preselected
            .iter()
            .map(|candidate| atom_kind_ordinal(candidate.candidate.atom_kind))
            .collect(),
        unique_count: ATOM_KIND_COUNT,
    }
}

const fn atom_kind_ordinal(kind: AtomKind) -> u16 {
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

fn lane_limits(bounds: &CandidateBounds) -> [usize; LANE_COUNT] {
    let mut output = [0; LANE_COUNT];
    for lane in [
        LaneKind::Rules,
        LaneKind::Task,
        LaneKind::History,
        LaneKind::Tools,
        LaneKind::Evidence,
    ] {
        if let Some(limit) = output.get_mut(lane_ordinal(lane)) {
            *limit = bounds.lane_limits.get(&lane).copied().unwrap_or_default();
        }
    }
    output
}

const fn lane_ordinal(lane: LaneKind) -> usize {
    match lane {
        LaneKind::Rules => 0,
        LaneKind::Task => 1,
        LaneKind::History => 2,
        LaneKind::Tools => 3,
        LaneKind::Evidence => 4,
    }
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

fn weighted_count(weight: i64, count: usize) -> Result<i64, RetrievalError> {
    weight
        .checked_mul(
            i64::try_from(count)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?,
        )
        .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))
}

pub(super) fn ranking_evidence(
    plan: &QueryPlan,
    retrieval_profile: RetrievalProfile,
    critical_requirements: BTreeSet<usize>,
    uncovered_critical_requirements: BTreeSet<usize>,
    decisions: Vec<CandidateRankingDecision>,
) -> Result<RequirementRankingEvidence, RetrievalError> {
    if !retrieval_profile.requirement_aware() {
        return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
    }
    RequirementRankingEvidence::new_trusted_for_profile(
        retrieval_profile,
        plan.plan_fingerprint.clone(),
        critical_requirements,
        uncovered_critical_requirements,
        decisions,
    )
}

pub(super) fn ranking_evidence_digest(
    plan_fingerprint: &ContentDigest,
    retrieval_profile_id: &str,
    retrieval_profile_digest: &ContentDigest,
    critical_requirements: &BTreeSet<usize>,
    uncovered_critical_requirements: &BTreeSet<usize>,
    decisions: &[CandidateRankingDecision],
) -> Result<ContentDigest, RetrievalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-REQUIREMENT-RANKING-EVIDENCE\0v1\0");
    hasher.update(plan_fingerprint.as_str().as_bytes());
    hasher.update(retrieval_profile_id.as_bytes());
    hasher.update(retrieval_profile_digest.as_str().as_bytes());
    for requirement in critical_requirements {
        hash_usize(&mut hasher, *requirement)?;
    }
    hasher.update([0xff]);
    for requirement in uncovered_critical_requirements {
        hash_usize(&mut hasher, *requirement)?;
    }
    for decision in decisions {
        hash_usize(&mut hasher, decision.ordinal)?;
        hasher.update(decision.selected_version.as_str().as_bytes());
        hasher.update([match decision.basis {
            crate::CandidateSelectionBasis::Protected => 0,
            crate::CandidateSelectionBasis::CriticalRequirement => 1,
            crate::CandidateSelectionBasis::Requirement => 2,
            crate::CandidateSelectionBasis::Score => 3,
        }]);
        hash_usize(&mut hasher, decision.newly_covered_requirements)?;
        hash_usize(&mut hasher, decision.newly_covered_critical_requirements)?;
        hasher.update(decision.newly_covered_concepts.to_be_bytes());
        hasher.update([
            u8::from(decision.source_diversity),
            u8::from(decision.section_diversity),
            u8::from(decision.kind_diversity),
        ]);
        for value in [
            decision.factors.base_score,
            decision.factors.critical_requirement_gain,
            decision.factors.requirement_gain,
            decision.factors.concept_gain,
            decision.factors.diversity_gain,
            decision.factors.generic_penalty,
            decision.factors.redundancy_penalty,
            decision.factors.similarity_penalty,
            decision.factors.adjusted_score,
        ] {
            hasher.update(value.to_be_bytes());
        }
        match &decision.next_best_version {
            Some(version) => {
                hasher.update([1]);
                hasher.update(version.as_str().as_bytes());
            }
            None => hasher.update([0]),
        }
        match decision.next_best_adjusted_score {
            Some(score) => {
                hasher.update([1]);
                hasher.update(score.to_be_bytes());
            }
            None => hasher.update([0]),
        }
        hash_usize(&mut hasher, decision.uncovered_critical_after)?;
    }
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        let _ = write!(&mut value, "{byte:02x}");
    }
    ContentDigest::new(value)
        .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))
}

fn hash_usize(hasher: &mut Sha256, value: usize) -> Result<(), RetrievalError> {
    hasher.update(
        u64::try_from(value)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    Ok(())
}
