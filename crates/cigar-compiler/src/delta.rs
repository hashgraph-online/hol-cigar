//! Exact context delta generation, application, acknowledgement, and repair requests.

use crate::materializer::{MaterializationError, digest};
use cigar_protocol::{
    ContentDigest, ContextBlock, ContextBundle, ContextDelta, SchemaVersion, Validate, VersionId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Content-free delta failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeltaError {
    /// A bundle or delta violates protocol invariants.
    InvalidInput,
    /// The supplied base is not the exact required base.
    WrongBase,
    /// The sealed delta digest does not match its bytes.
    Tampered,
    /// Applying the delta does not reproduce the exact target bundle.
    TargetMismatch,
    /// Stable digest generation failed.
    Digest,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "context delta failed: {self:?}")
    }
}

impl std::error::Error for DeltaError {}

/// Delta paired with the exact digest of its serialized protocol record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedDelta {
    /// Deterministic block delta.
    pub delta: ContextDelta,
    /// SHA-256 multihash of the exact stable JSON delta record.
    pub delta_digest: ContentDigest,
}

/// Opaque evidence that one sealed delta reproduced its exact declared target.
///
/// Values can be constructed only by [`apply_delta_verified`], so acknowledgement cannot be
/// emitted for an unverified or tampered delta record.
#[derive(Clone, Eq, PartialEq)]
pub struct AppliedDelta {
    bundle: ContextBundle,
    base_bundle_id: VersionId,
    target_bundle_id: VersionId,
    delta_digest: ContentDigest,
    reuse: DeltaReuseEvidence,
}

impl fmt::Debug for AppliedDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppliedDelta")
            .field("bundle", &"[OPAQUE]")
            .field("base_bundle_id", &"[OPAQUE]")
            .field("target_bundle_id", &"[OPAQUE]")
            .field("delta_digest", &"[OPAQUE]")
            .field("reuse", &self.reuse)
            .finish()
    }
}

/// Exact content-free accounting for semantic blocks omitted from a verified delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeltaReuseEvidence {
    /// Exact target blocks reused byte-for-byte by semantic block identity.
    pub reused_blocks: u32,
    /// Exact logical target tokens carried by reused blocks.
    pub reused_tokens: u32,
    /// Exact complete blocks transmitted in the delta.
    pub added_blocks: u32,
    /// Exact base block identities removed by the delta.
    pub removed_blocks: u32,
}

impl AppliedDelta {
    /// Exact reconstructed target bundle.
    #[must_use]
    pub const fn bundle(&self) -> &ContextBundle {
        &self.bundle
    }

    /// Exact base identity that was verified during application.
    #[must_use]
    pub const fn base_bundle_id(&self) -> &VersionId {
        &self.base_bundle_id
    }

    /// Exact target identity reproduced during application.
    #[must_use]
    pub const fn target_bundle_id(&self) -> &VersionId {
        &self.target_bundle_id
    }

    /// Digest of the exact delta record that was applied.
    #[must_use]
    pub const fn delta_digest(&self) -> &ContentDigest {
        &self.delta_digest
    }

    /// Exact verified semantic-reuse accounting.
    #[must_use]
    pub const fn reuse(&self) -> DeltaReuseEvidence {
        self.reuse
    }
}

/// Auditable provider acknowledgement of one exact target transition.
#[derive(Clone, Eq, PartialEq)]
pub struct DeltaAcknowledgement {
    /// Provider session that accepted the target.
    pub provider_session: String,
    /// Target configuration fingerprint.
    pub target_fingerprint: ContentDigest,
    /// Applied base bundle.
    pub base_bundle_id: VersionId,
    /// Accepted target bundle.
    pub target_bundle_id: VersionId,
    /// Exact applied delta digest.
    pub delta_digest: ContentDigest,
    /// Monotonic observation sequence.
    pub sequence: u64,
}

impl fmt::Debug for DeltaAcknowledgement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeltaAcknowledgement")
            .field("provider_session", &"[OPAQUE]")
            .field("target_fingerprint", &"[OPAQUE]")
            .field("base_bundle_id", &"[OPAQUE]")
            .field("target_bundle_id", &"[OPAQUE]")
            .field("delta_digest", &"[OPAQUE]")
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// Explicit request to recompile because a target's physical limit changed.
#[derive(Clone, Eq, PartialEq)]
pub struct TargetOverflowRepairRequest {
    /// Bundle that overflowed under the current target.
    pub bundle_id: VersionId,
    /// Current target fingerprint.
    pub target_fingerprint: ContentDigest,
    /// Exact materialized tokens observed.
    pub observed_tokens: u32,
    /// Current hard input limit.
    pub maximum_input_tokens: u32,
}

impl fmt::Debug for TargetOverflowRepairRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetOverflowRepairRequest")
            .field("bundle_id", &"[OPAQUE]")
            .field("target_fingerprint", &"[OPAQUE]")
            .field("observed_tokens", &self.observed_tokens)
            .field("maximum_input_tokens", &self.maximum_input_tokens)
            .finish()
    }
}

impl TargetOverflowRepairRequest {
    /// Creates a request only for an actual non-zero overflow.
    #[must_use]
    pub fn new(
        bundle_id: VersionId,
        target_fingerprint: ContentDigest,
        observed_tokens: u32,
        maximum_input_tokens: u32,
    ) -> Option<Self> {
        (maximum_input_tokens > 0 && observed_tokens > maximum_input_tokens).then_some(Self {
            bundle_id,
            target_fingerprint,
            observed_tokens,
            maximum_input_tokens,
        })
    }
}

/// Generates the minimal deterministic block delta between exact bundle identities.
pub fn generate_delta(
    base: &ContextBundle,
    target: &ContextBundle,
) -> Result<SealedDelta, DeltaError> {
    base.validate().map_err(|_error| DeltaError::InvalidInput)?;
    target
        .validate()
        .map_err(|_error| DeltaError::InvalidInput)?;
    if base.bundle_id == target.bundle_id {
        return Err(DeltaError::InvalidInput);
    }
    let base_by_id: BTreeMap<_, _> = base
        .blocks
        .iter()
        .map(|block| (&block.block_id, block))
        .collect();
    let target_by_id: BTreeMap<_, _> = target
        .blocks
        .iter()
        .map(|block| (&block.block_id, block))
        .collect();
    if target_by_id.iter().any(|(id, block)| {
        base_by_id
            .get(id)
            .is_some_and(|base_block| *base_block != *block)
    }) {
        return Err(DeltaError::InvalidInput);
    }
    let added_blocks = target_by_id
        .iter()
        .filter(|(id, _block)| !base_by_id.contains_key(*id))
        .map(|(_id, block)| (*block).clone())
        .collect();
    let removed_block_ids = base_by_id
        .keys()
        .filter(|id| !target_by_id.contains_key(*id))
        .map(|id| (*id).clone())
        .collect();
    let delta = ContextDelta {
        schema_version: SchemaVersion::new("cigar.context-delta", 1)
            .map_err(|_error| DeltaError::Digest)?,
        base_bundle_id: base.bundle_id.clone(),
        target_bundle_id: target.bundle_id.clone(),
        added_blocks,
        removed_block_ids,
        resulting_tokens: target.total_tokens,
    };
    delta
        .validate()
        .map_err(|_error| DeltaError::InvalidInput)?;
    let delta_digest = delta_digest(&delta)?;
    Ok(SealedDelta {
        delta,
        delta_digest,
    })
}

/// Applies a sealed delta and proves it reproduces the exact expected target bundle.
pub fn apply_delta(
    base: &ContextBundle,
    expected_target: &ContextBundle,
    sealed: &SealedDelta,
) -> Result<ContextBundle, DeltaError> {
    apply_delta_verified(base, expected_target, sealed).map(|applied| applied.bundle)
}

/// Applies and verifies a sealed delta, returning opaque acknowledgement evidence.
pub fn apply_delta_verified(
    base: &ContextBundle,
    expected_target: &ContextBundle,
    sealed: &SealedDelta,
) -> Result<AppliedDelta, DeltaError> {
    base.validate().map_err(|_error| DeltaError::InvalidInput)?;
    expected_target
        .validate()
        .map_err(|_error| DeltaError::InvalidInput)?;
    sealed
        .delta
        .validate()
        .map_err(|_error| DeltaError::InvalidInput)?;
    if delta_digest(&sealed.delta)? != sealed.delta_digest {
        return Err(DeltaError::Tampered);
    }
    if sealed.delta.base_bundle_id != base.bundle_id {
        return Err(DeltaError::WrongBase);
    }
    if sealed.delta.target_bundle_id != expected_target.bundle_id {
        return Err(DeltaError::TargetMismatch);
    }
    let mut blocks: BTreeMap<VersionId, ContextBlock> = base
        .blocks
        .iter()
        .map(|block| (block.block_id.clone(), block.clone()))
        .collect();
    for block_id in &sealed.delta.removed_block_ids {
        if blocks.remove(block_id).is_none() {
            return Err(DeltaError::WrongBase);
        }
    }
    for block in &sealed.delta.added_blocks {
        if blocks
            .insert(block.block_id.clone(), block.clone())
            .is_some()
        {
            return Err(DeltaError::InvalidInput);
        }
    }
    let actual_ids: BTreeSet<_> = blocks.keys().collect();
    let expected_ids: BTreeSet<_> = expected_target
        .blocks
        .iter()
        .map(|block| &block.block_id)
        .collect();
    let exact_blocks = expected_target
        .blocks
        .iter()
        .all(|block| blocks.get(&block.block_id) == Some(block));
    if actual_ids != expected_ids
        || !exact_blocks
        || sealed.delta.resulting_tokens != expected_target.total_tokens
    {
        return Err(DeltaError::TargetMismatch);
    }
    let base_by_id: BTreeMap<_, _> = base
        .blocks
        .iter()
        .map(|block| (&block.block_id, block))
        .collect();
    let reused: Vec<_> = expected_target
        .blocks
        .iter()
        .filter(|block| {
            base_by_id
                .get(&block.block_id)
                .is_some_and(|base_block| *base_block == *block)
        })
        .collect();
    let reused_tokens = reused
        .iter()
        .try_fold(0_u32, |total, block| total.checked_add(block.token_count))
        .ok_or(DeltaError::InvalidInput)?;
    let reuse = DeltaReuseEvidence {
        reused_blocks: u32::try_from(reused.len()).map_err(|_error| DeltaError::InvalidInput)?,
        reused_tokens,
        added_blocks: u32::try_from(sealed.delta.added_blocks.len())
            .map_err(|_error| DeltaError::InvalidInput)?,
        removed_blocks: u32::try_from(sealed.delta.removed_block_ids.len())
            .map_err(|_error| DeltaError::InvalidInput)?,
    };
    if reuse.reused_blocks.checked_add(reuse.added_blocks)
        != u32::try_from(expected_target.blocks.len()).ok()
    {
        return Err(DeltaError::TargetMismatch);
    }
    Ok(AppliedDelta {
        bundle: expected_target.clone(),
        base_bundle_id: base.bundle_id.clone(),
        target_bundle_id: expected_target.bundle_id.clone(),
        delta_digest: sealed.delta_digest.clone(),
        reuse,
    })
}

/// Creates an auditable acknowledgement after exact application succeeds.
pub fn acknowledge_delta(
    provider_session: impl Into<String>,
    target_fingerprint: ContentDigest,
    applied: &AppliedDelta,
    sequence: u64,
) -> Option<DeltaAcknowledgement> {
    let provider_session = provider_session.into();
    (!provider_session.is_empty() && sequence > 0).then(|| DeltaAcknowledgement {
        provider_session,
        target_fingerprint,
        base_bundle_id: applied.base_bundle_id.clone(),
        target_bundle_id: applied.target_bundle_id.clone(),
        delta_digest: applied.delta_digest.clone(),
        sequence,
    })
}

fn delta_digest(delta: &ContextDelta) -> Result<ContentDigest, DeltaError> {
    let bytes = serde_json::to_vec(delta).map_err(|_error| DeltaError::Digest)?;
    digest(&bytes).map_err(|error| match error {
        MaterializationError::InvalidInput
        | MaterializationError::ContentMismatch
        | MaterializationError::LimitExceeded
        | MaterializationError::Serialization => DeltaError::Digest,
    })
}
