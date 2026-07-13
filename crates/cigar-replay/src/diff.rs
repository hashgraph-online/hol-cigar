//! Structured replay comparison across semantic and observational dimensions.

use crate::{ReplayFoundationError, ReplayFoundationErrorCode};
use cigar_protocol::{
    ContentDigest, DiffStatus, RecordId, ReplayDiff, SchemaVersion, Validate, VersionId,
};

/// A fixed, bounded set of digests used to compare one replay result.
///
/// Each present value is a validated SHA-256 multihash. Absence means that the
/// corresponding dimension could not be reconstructed and must be reported as
/// unavailable rather than equal or different.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplayDimensionDigests {
    /// Digest of the selected semantic context.
    pub semantic_context: Option<ContentDigest>,
    /// Digest of the exact materialized input bytes.
    pub materialization: Option<ContentDigest>,
    /// Digest of the runtime, consumer, adapter, and environment fingerprints.
    pub components: Option<ContentDigest>,
    /// Digest of the ordered output claims.
    pub output_claims: Option<ContentDigest>,
    /// Digest of the verification results and their evidence.
    pub verification: Option<ContentDigest>,
    /// Digest of the declared effect plan.
    pub effect_plan: Option<ContentDigest>,
    /// Digest of the ordered consumer, tool, and connector observations.
    pub observations: Option<ContentDigest>,
}

/// Compares baseline and candidate replay dimensions without conflating
/// provider variance with compiler nondeterminism.
pub fn compare_replay_dimensions(
    decision_id: VersionId,
    execution_id: RecordId,
    baseline: &ReplayDimensionDigests,
    candidate: &ReplayDimensionDigests,
) -> Result<ReplayDiff, ReplayFoundationError> {
    let semantic_context = compare_digest(
        baseline.semantic_context.as_ref(),
        candidate.semantic_context.as_ref(),
    );
    let materialization = compare_digest(
        baseline.materialization.as_ref(),
        candidate.materialization.as_ref(),
    );
    let diff = ReplayDiff {
        schema_version: SchemaVersion::new("cigar.replay-diff", 1).map_err(|_error| {
            ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput)
        })?,
        decision_id,
        execution_id,
        semantic_context,
        materialization,
        components: compare_digest(baseline.components.as_ref(), candidate.components.as_ref()),
        output_claims: compare_digest(
            baseline.output_claims.as_ref(),
            candidate.output_claims.as_ref(),
        ),
        verification: compare_digest(
            baseline.verification.as_ref(),
            candidate.verification.as_ref(),
        ),
        effect_plan: compare_digest(
            baseline.effect_plan.as_ref(),
            candidate.effect_plan.as_ref(),
        ),
        observations: compare_digest(
            baseline.observations.as_ref(),
            candidate.observations.as_ref(),
        ),
        compiler_deterministic: semantic_context == DiffStatus::Equal
            && materialization == DiffStatus::Equal,
    };
    diff.validate()
        .map_err(|_error| ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput))?;
    Ok(diff)
}

fn compare_digest(
    baseline: Option<&ContentDigest>,
    candidate: Option<&ContentDigest>,
) -> DiffStatus {
    match (baseline, candidate) {
        (Some(baseline), Some(candidate)) if baseline == candidate => DiffStatus::Equal,
        (Some(_), Some(_)) => DiffStatus::Different,
        (None, _) | (_, None) => DiffStatus::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayDimensionDigests, compare_replay_dimensions};
    use cigar_protocol::{ContentDigest, DiffStatus, RecordId, Validate, VersionId};

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn decision_id() -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!("1220{}", "a".repeat(64)))?)
    }

    fn execution_id() -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?)
    }

    fn complete_dimensions() -> Result<ReplayDimensionDigests, Box<dyn std::error::Error>> {
        Ok(ReplayDimensionDigests {
            semantic_context: Some(digest('1')?),
            materialization: Some(digest('2')?),
            components: Some(digest('3')?),
            output_claims: Some(digest('4')?),
            verification: Some(digest('5')?),
            effect_plan: Some(digest('6')?),
            observations: Some(digest('7')?),
        })
    }

    #[test]
    fn equal_dimensions_are_valid_and_compiler_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let baseline = complete_dimensions()?;
        let diff =
            compare_replay_dimensions(decision_id()?, execution_id()?, &baseline, &baseline)?;

        assert_eq!(diff.semantic_context, DiffStatus::Equal);
        assert_eq!(diff.observations, DiffStatus::Equal);
        assert!(diff.compiler_deterministic);
        diff.validate()?;
        Ok(())
    }

    #[test]
    fn observation_only_variance_does_not_imply_compiler_nondeterminism()
    -> Result<(), Box<dyn std::error::Error>> {
        let baseline = complete_dimensions()?;
        let mut candidate = baseline.clone();
        candidate.observations = Some(digest('8')?);

        let diff =
            compare_replay_dimensions(decision_id()?, execution_id()?, &baseline, &candidate)?;

        assert_eq!(diff.semantic_context, DiffStatus::Equal);
        assert_eq!(diff.materialization, DiffStatus::Equal);
        assert_eq!(diff.observations, DiffStatus::Different);
        assert!(diff.compiler_deterministic);
        diff.validate()?;
        Ok(())
    }

    #[test]
    fn absent_evidence_is_unavailable_and_never_assumed_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let baseline = complete_dimensions()?;
        let mut candidate = baseline.clone();
        candidate.materialization = None;
        candidate.verification = None;

        let diff =
            compare_replay_dimensions(decision_id()?, execution_id()?, &baseline, &candidate)?;

        assert_eq!(diff.materialization, DiffStatus::Unavailable);
        assert_eq!(diff.verification, DiffStatus::Unavailable);
        assert!(!diff.compiler_deterministic);
        diff.validate()?;
        Ok(())
    }

    #[test]
    fn semantic_or_materialized_variance_is_compiler_nondeterminism()
    -> Result<(), Box<dyn std::error::Error>> {
        let baseline = complete_dimensions()?;
        let mut candidate = baseline.clone();
        candidate.semantic_context = Some(digest('9')?);

        let diff =
            compare_replay_dimensions(decision_id()?, execution_id()?, &baseline, &candidate)?;

        assert_eq!(diff.semantic_context, DiffStatus::Different);
        assert!(!diff.compiler_deterministic);
        diff.validate()?;
        Ok(())
    }
}
