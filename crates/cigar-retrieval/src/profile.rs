//! Digest-bound retrieval intelligence profiles.

use crate::{CandidateFeatures, RetrievalError, RetrievalErrorCode};
use cigar_protocol::ContentDigest;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

static BALANCED_V1_DIGEST: OnceLock<Result<ContentDigest, RetrievalError>> = OnceLock::new();
static BALANCED_V2_CANDIDATE_DIGEST: OnceLock<Result<ContentDigest, RetrievalError>> =
    OnceLock::new();
static BALANCED_V2_REQUIREMENT_AWARE_DIGEST: OnceLock<Result<ContentDigest, RetrievalError>> =
    OnceLock::new();
static BALANCED_V4_DIGEST: OnceLock<Result<ContentDigest, RetrievalError>> = OnceLock::new();

/// Frozen, digest-bound retrieval profiles used by published Honey and H1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetrievalProfile {
    /// Exact Honey 0.9.1 behavior and 0.9.2 rollback weights.
    #[default]
    BalancedV1,
    /// Honey 0.9.2 H1 integer lexical/metadata/graph profile.
    BalancedV2Candidate,
    /// Requirement-aware ranking refinement over the first experimental profile.
    BalancedV2RequirementAwareCandidate,
    /// CIGAR 0.9.4 risk-reserved retrieval with marginal-utility stopping.
    BalancedV4,
}

impl RetrievalProfile {
    /// Stable profile identifier.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::BalancedV1 => "cigar.retrieval-profile.balanced.v1",
            Self::BalancedV2Candidate => "cigar.retrieval-profile.balanced.v2-candidate.1",
            Self::BalancedV2RequirementAwareCandidate => {
                "cigar.retrieval-profile.balanced.v2-candidate.2"
            }
            Self::BalancedV4 => "cigar.retrieval-profile.balanced.v4",
        }
    }

    /// Fixed positive and negative feature weights in struct-field order.
    #[must_use]
    pub const fn weights(self) -> ([i64; 11], [i64; 2]) {
        match self {
            Self::BalancedV1 => ([280, 150, 110, 80, 90, 70, 60, 90, 45, 35, 30], [130, 100]),
            Self::BalancedV2Candidate => {
                ([280, 190, 145, 65, 90, 70, 85, 100, 70, 35, 45], [145, 110])
            }
            Self::BalancedV2RequirementAwareCandidate | Self::BalancedV4 => (
                [180, 190, 260, 65, 90, 70, 100, 100, 70, 35, 50],
                [145, 110],
            ),
        }
    }

    /// Bounded graph depth and whether current-state augmentation is enabled.
    #[must_use]
    pub const fn planning(self) -> (u16, bool) {
        match self {
            Self::BalancedV1 => (0, false),
            Self::BalancedV2Candidate
            | Self::BalancedV2RequirementAwareCandidate
            | Self::BalancedV4 => (2, false),
        }
    }

    /// Whether this profile uses requirement-aware post-governance ranking evidence.
    #[must_use]
    pub const fn requirement_aware(self) -> bool {
        matches!(
            self,
            Self::BalancedV2RequirementAwareCandidate | Self::BalancedV4
        )
    }

    /// Immutable algorithm/configuration digest.
    pub fn digest(self) -> Result<ContentDigest, RetrievalError> {
        let digest = match self {
            Self::BalancedV1 => &BALANCED_V1_DIGEST,
            Self::BalancedV2Candidate => &BALANCED_V2_CANDIDATE_DIGEST,
            Self::BalancedV2RequirementAwareCandidate => &BALANCED_V2_REQUIREMENT_AWARE_DIGEST,
            Self::BalancedV4 => &BALANCED_V4_DIGEST,
        };
        digest.get_or_init(|| self.compute_digest()).clone()
    }

    fn compute_digest(self) -> Result<ContentDigest, RetrievalError> {
        let mut hasher = Sha256::new();
        hasher.update(b"CIGAR-RETRIEVAL-PROFILE\0v1\0");
        hasher.update(self.identifier().as_bytes());
        let (positive, negative) = self.weights();
        for value in positive.into_iter().chain(negative) {
            hasher.update(value.to_be_bytes());
        }
        let (depth, augment) = self.planning();
        hasher.update(depth.to_be_bytes());
        hasher.update([u8::from(augment)]);
        if self == Self::BalancedV4 {
            // Digest-bind the v4-only dense/risk/stop semantics. Selection weights and bounds are
            // additionally bound into every plan fingerprint.
            hasher.update(b"CIGAR-RETRIEVAL-V4-POLICY\0v1\0");
            hasher.update(256_u16.to_be_bytes());
            hasher.update(32_u16.to_be_bytes());
            hasher.update([2, 1, 0, 0, 0]);
            hasher.update(b"independent-source-lineage-content\0");
            hasher.update(b"positive-contextual-marginal-utility\0");
        }
        let mut digest = String::from("1220");
        use std::fmt::Write as _;
        for byte in hasher.finalize() {
            let _ = write!(&mut digest, "{byte:02x}");
        }
        ContentDigest::new(digest)
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))
    }
}

impl CandidateFeatures {
    /// Checked deterministic score for one explicit profile.
    pub fn score(self, profile: RetrievalProfile) -> Result<i64, RetrievalError> {
        let normalized = [
            self.requirement_match,
            self.exact_match,
            self.lexical_match,
            self.semantic_match,
            self.graph_proximity,
            self.project_proximity,
            self.task_proximity,
            self.authority,
            self.verification,
            self.freshness,
            self.novelty,
            self.conflict_risk,
            self.staleness,
        ];
        if normalized
            .iter()
            .any(|value| *value > crate::MAX_FEATURE_VALUE)
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        let (positive, negative) = profile.weights();
        let mut score = 0_i64;
        for (weight, value) in positive.into_iter().zip(normalized[..11].iter()) {
            score = score
                .checked_add(weight * i64::from(*value))
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        for (weight, value) in negative.into_iter().zip(normalized[11..].iter()) {
            score = score
                .checked_sub(weight * i64::from(*value))
                .ok_or_else(|| RetrievalError::new(RetrievalErrorCode::LimitExceeded))?;
        }
        Ok(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn v1_score_is_the_frozen_golden_and_profiles_have_distinct_digests()
    -> Result<(), Box<dyn Error>> {
        let features = CandidateFeatures {
            requirement_match: 10_000,
            exact_match: 9_000,
            lexical_match: 8_000,
            semantic_match: 7_000,
            graph_proximity: 6_000,
            project_proximity: 5_000,
            task_proximity: 4_000,
            authority: 3_000,
            verification: 2_000,
            freshness: 1_000,
            novelty: 500,
            conflict_risk: 250,
            staleness: 125,
            ..CandidateFeatures::default()
        };
        assert_eq!(features.balanced_score()?, 7_085_000);
        assert_eq!(
            features.balanced_score()?,
            features.score(RetrievalProfile::BalancedV1)?
        );
        assert_ne!(
            RetrievalProfile::BalancedV1.digest()?,
            RetrievalProfile::BalancedV2Candidate.digest()?
        );
        assert_ne!(
            RetrievalProfile::BalancedV2Candidate.digest()?,
            RetrievalProfile::BalancedV2RequirementAwareCandidate.digest()?
        );
        assert_ne!(
            RetrievalProfile::BalancedV2RequirementAwareCandidate.digest()?,
            RetrievalProfile::BalancedV4.digest()?
        );
        assert_eq!(
            RetrievalProfile::BalancedV1.digest()?.as_str(),
            "1220c605f248bd6f9d7c476324630b0839fb4c7423009f47f3f13b8b1a62cfeb72ea"
        );
        assert_eq!(
            RetrievalProfile::BalancedV2Candidate.digest()?.as_str(),
            "12208f5c83267949db9ed969f9b5f153c2be125b7d54875e2d72acad556b9a28183c"
        );
        assert_eq!(
            RetrievalProfile::BalancedV2RequirementAwareCandidate
                .digest()?
                .as_str(),
            "12200a182e948a6f1db35e59b32a5ea9963807f26796303c65065385b84c33f1316a"
        );
        assert_eq!(
            RetrievalProfile::BalancedV4.identifier(),
            "cigar.retrieval-profile.balanced.v4"
        );
        assert_eq!(
            RetrievalProfile::BalancedV4.digest()?.as_str(),
            "1220f5e7f91cefdaea9b0748999b173fa38e005a350a6f533396e281d1c342c2d910"
        );
        Ok(())
    }

    #[test]
    fn integer_score_matches_brute_force_dot_product() -> Result<(), Box<dyn Error>> {
        for value in [0_u16, 1, 5_000, 10_000] {
            let features = CandidateFeatures {
                requirement_match: value,
                exact_match: value,
                lexical_match: value,
                semantic_match: value,
                graph_proximity: value,
                project_proximity: value,
                task_proximity: value,
                authority: value,
                verification: value,
                freshness: value,
                novelty: value,
                conflict_risk: value,
                staleness: value,
                ..CandidateFeatures::default()
            };
            let (positive, negative) = RetrievalProfile::BalancedV2Candidate.weights();
            let expected = (positive.into_iter().sum::<i64>() - negative.into_iter().sum::<i64>())
                * i64::from(value);
            assert_eq!(
                features.score(RetrievalProfile::BalancedV2Candidate)?,
                expected
            );
        }
        Ok(())
    }
}
