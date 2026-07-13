//! Deterministic compilation plans, bundles, manifests, materialization, and deltas.

use crate::limits::{
    MAX_CONTEXT_BLOCKS, MAX_MATERIALIZED_BYTES, MAX_PLAN_CANDIDATES, MAX_PLAN_LANES,
    MAX_REASON_CODES,
};
use crate::primitive::base64url;
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    ContentDigest, ExtensionMap, FixedPoint, LaneKind, MediaType, RecordId, SchemaVersion,
    Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Stable exclusion and non-selection reason codes.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DispositionReason {
    /// Candidate was outside the authorized scope.
    ScopeDenied,
    /// Purpose did not authorize candidate use.
    PurposeDenied,
    /// Candidate was temporally ineligible.
    TemporalMismatch,
    /// Candidate trust or authority was insufficient.
    TrustInsufficient,
    /// Instruction authority was insufficient.
    InstructionAuthorityDenied,
    /// Processor constraints were not satisfied.
    ProcessorDenied,
    /// Integrity verification failed.
    IntegrityFailed,
    /// A higher-ranked candidate displaced this one under budget.
    BudgetDisplaced,
    /// Candidate was superseded or tombstoned.
    LifecycleIneligible,
    /// Candidate conflicted with a mandatory higher-authority item.
    ConflictLost,
    /// Required context could not be found.
    RequiredMissing,
}

/// Deterministic disposition of one retrieval candidate.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateDisposition {
    /// Selected into a specific lane with a fixed-point score.
    Selected {
        /// Selected lane.
        lane: LaneKind,
        /// Deterministic score in millionths.
        score: FixedPoint,
    },
    /// Excluded with a stable reason.
    Excluded {
        /// Primary exclusion reason.
        reason: DispositionReason,
    },
    /// Redacted while preserving safe explanation that a candidate existed.
    Redacted {
        /// Primary redaction reason.
        reason: DispositionReason,
    },
    /// Required selector had no authorized matching candidate.
    RequiredMissing,
}

/// One standard lane in a deterministic context plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLane {
    /// Lane kind.
    pub kind: LaneKind,
    /// Exact token budget for this lane.
    pub budget_tokens: u32,
    /// Sorted unique candidate semantic versions assigned to the lane.
    #[schemars(length(max = MAX_PLAN_CANDIDATES))]
    pub candidate_versions: Vec<VersionId>,
}

/// Deterministic planner output before representation transforms and packing.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPlan {
    /// Must be `cigar.context-plan.v1`.
    pub schema_version: SchemaVersion,
    /// Unique plan observation identity.
    pub plan_id: RecordId,
    /// Digest of the normalized input contract.
    pub contract_digest: ContentDigest,
    /// Catalog/index watermark used for retrieval.
    pub catalog_watermark: ContentDigest,
    /// Exact aggregate input-token budget.
    pub total_input_tokens: u32,
    /// Sorted unique lanes.
    #[schemars(length(min = 1, max = MAX_PLAN_LANES))]
    pub lanes: Vec<PlanLane>,
    /// Sorted disposition table containing every considered candidate.
    #[schemars(length(max = MAX_PLAN_CANDIDATES))]
    pub dispositions: Vec<(VersionId, CandidateDisposition)>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl Validate for ContextPlan {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.context-plan") {
            errors.merge(found);
        }
        if self.lanes.is_empty() || self.lanes.len() > MAX_PLAN_LANES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/lanes",
                "plan lanes must be non-empty and bounded",
            ));
        }
        if !sorted_unique_by(&self.lanes, |first, second| first.kind.cmp(&second.kind)) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/lanes",
                "plan lanes must be sorted and unique by kind",
            ));
        }
        let lane_sum = self
            .lanes
            .iter()
            .try_fold(0_u32, |total, lane| total.checked_add(lane.budget_tokens));
        if lane_sum != Some(self.total_input_tokens)
            || self.lanes.iter().any(|lane| lane.budget_tokens == 0)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/lanes",
                "non-zero lane budgets must sum exactly to total input tokens",
            ));
        }
        let mut assigned = BTreeSet::new();
        for (index, lane) in self.lanes.iter().enumerate() {
            if lane.candidate_versions.len() > MAX_PLAN_CANDIDATES
                || !strictly_sorted_unique(&lane.candidate_versions)
            {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    format!("/lanes/{index}/candidate_versions"),
                    "lane candidates must be sorted and unique",
                ));
            }
            for version in &lane.candidate_versions {
                if !assigned.insert(version) {
                    errors.push(issue(
                        ValidationCode::InvalidValue,
                        "/lanes",
                        "candidate version cannot be assigned to multiple lanes",
                    ));
                }
            }
        }
        if self.dispositions.len() > MAX_PLAN_CANDIDATES
            || !sorted_unique_by(&self.dispositions, |first, second| first.0.cmp(&second.0))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/dispositions",
                "candidate dispositions must be bounded, sorted, and unique",
            ));
        }
        for (version, disposition) in &self.dispositions {
            let selected = matches!(disposition, CandidateDisposition::Selected { .. });
            if selected != assigned.contains(version) {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    "/dispositions",
                    "selected disposition and lane assignment disagree",
                ));
            }
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
    }
}

/// Evidence-carrying representation selected for one context block.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationKind {
    /// Exact source content.
    Exact,
    /// Deterministically extracted source span.
    Extracted,
    /// Evidence-backed deterministic summary.
    Summarized,
    /// Redacted marker with no protected content.
    Redacted,
}

/// One packed, provenance-complete semantic block.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBlock {
    /// Content-derived block identity.
    pub block_id: VersionId,
    /// Destination lane.
    pub lane: LaneKind,
    /// Representation kind.
    pub representation: RepresentationKind,
    /// Exact digest of rendered block content.
    pub content_digest: ContentDigest,
    /// Exact physical tokens under the target tokenizer.
    pub token_count: u32,
    /// Sorted unique catalog versions that prove provenance.
    #[schemars(length(min = 1, max = MAX_CONTEXT_BLOCKS))]
    pub provenance: Vec<VersionId>,
    /// Evidence receipt for a non-exact transform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform_receipt: Option<ContentDigest>,
}

impl ContextBlock {
    fn validate_into(&self, index: usize, errors: &mut ValidationErrors) {
        if self.token_count == 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                format!("/blocks/{index}/token_count"),
                "context block token count must be non-zero",
            ));
        }
        if self.provenance.is_empty()
            || self.provenance.len() > MAX_CONTEXT_BLOCKS
            || !strictly_sorted_unique(&self.provenance)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                format!("/blocks/{index}/provenance"),
                "block provenance must be non-empty, sorted, and unique",
            ));
        }
        let receipt_required = !matches!(
            self.representation,
            RepresentationKind::Exact | RepresentationKind::Redacted
        );
        if receipt_required != self.transform_receipt.is_some() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                format!("/blocks/{index}/transform_receipt"),
                "extracted and summarized blocks require exactly one transform receipt",
            ));
        }
    }
}

/// Deterministically ordered bundle ready for materialization.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBundle {
    /// Must be `cigar.context-bundle.v1`.
    pub schema_version: SchemaVersion,
    /// Content-derived bundle identity.
    pub bundle_id: VersionId,
    /// Normalized contract digest.
    pub contract_digest: ContentDigest,
    /// Selection manifest digest.
    pub manifest_digest: ContentDigest,
    /// Ordered blocks grouped by standard lane ordering.
    #[schemars(length(max = MAX_CONTEXT_BLOCKS))]
    pub blocks: Vec<ContextBlock>,
    /// Exact total physical tokens across blocks.
    pub total_tokens: u32,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl Validate for ContextBundle {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.context-bundle") {
            errors.merge(found);
        }
        if self.blocks.len() > MAX_CONTEXT_BLOCKS
            || !sorted_unique_by(&self.blocks, |first, second| {
                first
                    .lane
                    .cmp(&second.lane)
                    .then_with(|| first.block_id.cmp(&second.block_id))
            })
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/blocks",
                "bundle blocks must be bounded, sorted, and unique",
            ));
        }
        let sum = self
            .blocks
            .iter()
            .try_fold(0_u32, |total, block| total.checked_add(block.token_count));
        if sum != Some(self.total_tokens) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/total_tokens",
                "bundle token total must equal the exact block sum",
            ));
        }
        for (index, block) in self.blocks.iter().enumerate() {
            block.validate_into(index, &mut errors);
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
    }
}

/// Complete explanation entry for one considered catalog version.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Considered catalog version.
    pub version_id: VersionId,
    /// Final deterministic disposition.
    pub disposition: CandidateDisposition,
    /// Sorted unique supplementary reason codes.
    #[schemars(length(max = MAX_REASON_CODES))]
    pub reason_codes: Vec<DispositionReason>,
    /// Digest proving catalog-derived provenance.
    pub provenance_digest: ContentDigest,
}

/// Complete selection and exclusion explanation for a bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionManifest {
    /// Must be `cigar.selection-manifest.v1`.
    pub schema_version: SchemaVersion,
    /// Content-derived manifest identity.
    pub manifest_id: VersionId,
    /// Normalized contract digest.
    pub contract_digest: ContentDigest,
    /// Sorted unique entry for every considered candidate.
    #[schemars(length(max = MAX_PLAN_CANDIDATES))]
    pub entries: Vec<ManifestEntry>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl Validate for SelectionManifest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.selection-manifest") {
            errors.merge(found);
        }
        if self.entries.len() > MAX_PLAN_CANDIDATES
            || !sorted_unique_by(&self.entries, |first, second| {
                first.version_id.cmp(&second.version_id)
            })
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/entries",
                "manifest entries must be bounded, sorted, and unique",
            ));
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.reason_codes.len() > MAX_REASON_CODES
                || !strictly_sorted_unique(&entry.reason_codes)
            {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    format!("/entries/{index}/reason_codes"),
                    "reason codes must be bounded, sorted, and unique",
                ));
            }
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
    }
}

/// Provider-ready bytes with exact tokenizer and materializer evidence.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedContext {
    /// Must be `cigar.materialized-context.v1`.
    pub schema_version: SchemaVersion,
    /// Source bundle identity.
    pub bundle_id: VersionId,
    /// Target media type.
    pub media_type: MediaType,
    /// Provider-ready bytes encoded as unpadded base64url in JSON.
    #[schemars(with = "String")]
    #[schemars(length(min = 2, max = 89_478_486))]
    #[serde(with = "base64url")]
    pub bytes: Vec<u8>,
    /// Exact physical tokens under the recorded tokenizer.
    pub token_count: u32,
    /// Tokenizer fingerprint used for accounting.
    pub tokenizer_fingerprint: ContentDigest,
    /// Materializer fingerprint used for rendering.
    pub materializer_fingerprint: ContentDigest,
}

impl fmt::Debug for MaterializedContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedContext")
            .field("schema_version", &self.schema_version)
            .field("bundle_id", &self.bundle_id)
            .field("media_type", &self.media_type)
            .field("byte_count", &self.bytes.len())
            .field("token_count", &self.token_count)
            .field("tokenizer_fingerprint", &self.tokenizer_fingerprint)
            .field("materializer_fingerprint", &self.materializer_fingerprint)
            .finish()
    }
}

impl Validate for MaterializedContext {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.materialized-context") {
            errors.merge(found);
        }
        if self.bytes.is_empty() || self.bytes.len() > MAX_MATERIALIZED_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/bytes",
                "materialized bytes must be non-empty and bounded",
            ));
        }
        if self.token_count == 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/token_count",
                "materialized token count must be non-zero",
            ));
        }
        errors.into_result()
    }
}

/// Deterministic block delta between two bundle identities.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextDelta {
    /// Must be `cigar.context-delta.v1`.
    pub schema_version: SchemaVersion,
    /// Required provider-present base bundle.
    pub base_bundle_id: VersionId,
    /// Resulting target bundle.
    pub target_bundle_id: VersionId,
    /// Sorted unique blocks added or replaced.
    #[schemars(length(max = MAX_CONTEXT_BLOCKS))]
    pub added_blocks: Vec<ContextBlock>,
    /// Sorted unique block identities removed from the base.
    #[schemars(length(max = MAX_CONTEXT_BLOCKS))]
    pub removed_block_ids: Vec<VersionId>,
    /// Exact token count after applying the delta.
    pub resulting_tokens: u32,
}

impl Validate for ContextDelta {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.context-delta") {
            errors.merge(found);
        }
        if self.base_bundle_id == self.target_bundle_id {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/target_bundle_id",
                "delta target must differ from its base",
            ));
        }
        if self.added_blocks.len() > MAX_CONTEXT_BLOCKS
            || self.removed_block_ids.len() > MAX_CONTEXT_BLOCKS
            || !sorted_unique_by(&self.added_blocks, |first, second| {
                first.block_id.cmp(&second.block_id)
            })
            || !strictly_sorted_unique(&self.removed_block_ids)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/added_blocks",
                "delta block sets must be bounded, sorted, and unique",
            ));
        }
        let removed: BTreeSet<_> = self.removed_block_ids.iter().collect();
        if self
            .added_blocks
            .iter()
            .any(|block| removed.contains(&block.block_id))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/added_blocks",
                "the same block cannot be both added and removed",
            ));
        }
        for (index, block) in self.added_blocks.iter().enumerate() {
            block.validate_into(index, &mut errors);
        }
        errors.into_result()
    }
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|window| match (window.first(), window.get(1)) {
            (Some(first), Some(second)) => first < second,
            _ => false,
        })
}

fn sorted_unique_by<T>(values: &[T], compare: impl Fn(&T, &T) -> std::cmp::Ordering) -> bool {
    values
        .windows(2)
        .all(|window| match (window.first(), window.get(1)) {
            (Some(first), Some(second)) => compare(first, second).is_lt(),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateDisposition, ContextBlock, ContextBundle, ContextDelta, ContextPlan, PlanLane,
        RepresentationKind,
    };
    use crate::{ContentDigest, ExtensionMap, FixedPoint, LaneKind, RecordId, Validate, VersionId};

    fn content(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn version(character: char) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn block() -> Result<ContextBlock, Box<dyn std::error::Error>> {
        Ok(ContextBlock {
            block_id: version('a')?,
            lane: LaneKind::Evidence,
            representation: RepresentationKind::Exact,
            content_digest: content('b')?,
            token_count: 10,
            provenance: vec![version('c')?],
            transform_receipt: None,
        })
    }

    #[test]
    fn plan_requires_lane_and_disposition_agreement() -> Result<(), Box<dyn std::error::Error>> {
        let candidate = version('d')?;
        let plan = ContextPlan {
            schema_version: "cigar.context-plan.v1".parse()?,
            plan_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7830")?,
            contract_digest: content('e')?,
            catalog_watermark: content('f')?,
            total_input_tokens: 100,
            lanes: vec![PlanLane {
                kind: LaneKind::Evidence,
                budget_tokens: 100,
                candidate_versions: vec![candidate.clone()],
            }],
            dispositions: vec![(
                candidate,
                CandidateDisposition::Selected {
                    lane: LaneKind::Evidence,
                    score: FixedPoint::new(500_000)?,
                },
            )],
            extensions: ExtensionMap::default(),
        };
        plan.validate()?;
        Ok(())
    }

    #[test]
    fn bundle_token_sum_and_transform_evidence_are_enforced()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut block = block()?;
        block.representation = RepresentationKind::Summarized;
        let bundle = ContextBundle {
            schema_version: "cigar.context-bundle.v1".parse()?,
            bundle_id: version('d')?,
            contract_digest: content('e')?,
            manifest_digest: content('f')?,
            blocks: vec![block],
            total_tokens: 11,
            extensions: ExtensionMap::default(),
        };
        let Err(errors) = bundle.validate() else {
            return Err("invalid bundle unexpectedly passed".into());
        };
        assert!(errors.len() >= 2);
        Ok(())
    }

    #[test]
    fn delta_rejects_same_base_and_overlapping_block_sets() -> Result<(), Box<dyn std::error::Error>>
    {
        let bundle = version('d')?;
        let block = block()?;
        let delta = ContextDelta {
            schema_version: "cigar.context-delta.v1".parse()?,
            base_bundle_id: bundle.clone(),
            target_bundle_id: bundle,
            removed_block_ids: vec![block.block_id.clone()],
            added_blocks: vec![block],
            resulting_tokens: 10,
        };
        let Err(errors) = delta.validate() else {
            return Err("invalid delta unexpectedly passed".into());
        };
        assert!(errors.len() >= 2);
        Ok(())
    }
}
