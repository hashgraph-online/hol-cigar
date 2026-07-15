//! Strict content-safe evidence descriptors stored separately from receipt bytes.

use crate::events::{bounded_identifier, now_rfc3339, uuid_v7, uuid_v7_is_valid};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const EVIDENCE_SCHEMA: &str = "cigar.dashboard-evidence-descriptor.v1";

/// Stable content-free evidence descriptor validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    /// One descriptor field was outside the closed schema.
    InvalidEvidence,
    /// An opaque descriptor identity or timestamp could not be generated.
    IdentityUnavailable,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEvidence => "dashboard evidence descriptor is invalid",
            Self::IdentityUnavailable => "dashboard evidence identity is unavailable",
        })
    }
}

impl std::error::Error for EvidenceError {}

/// Evidence strength derived by an independent receipt verifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceCategory {
    /// Documentation or fixture evidence with no development claim.
    Sample,
    /// Evidence from a development source checkout.
    Development,
    /// Evidence bound to an exact release candidate source tree.
    CandidateBound,
    /// Evidence produced from an exact installed artifact.
    InstalledArtifact,
    /// Candidate and artifact bindings satisfy the release evidence contract.
    ReleaseQualifying,
}

impl EvidenceCategory {
    /// Returns the stable storage and wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sample => "sample",
            Self::Development => "development",
            Self::CandidateBound => "candidate-bound",
            Self::InstalledArtifact => "installed-artifact",
            Self::ReleaseQualifying => "release-qualifying",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, EvidenceError> {
        match value {
            "sample" => Ok(Self::Sample),
            "development" => Ok(Self::Development),
            "candidate-bound" => Ok(Self::CandidateBound),
            "installed-artifact" => Ok(Self::InstalledArtifact),
            "release-qualifying" => Ok(Self::ReleaseQualifying),
            _ => Err(EvidenceError::InvalidEvidence),
        }
    }
}

/// Descriptor validity after strict receipt verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// Every required receipt and binding check passed.
    Valid,
    /// One or more receipt or binding checks failed.
    Invalid,
    /// The run ended without enough information for a complete claim.
    Partial,
}

impl EvidenceStatus {
    /// Returns the stable storage and wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Partial => "partial",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, EvidenceError> {
        match value {
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "partial" => Ok(Self::Partial),
            _ => Err(EvidenceError::InvalidEvidence),
        }
    }
}

/// Sanitized receipt metadata; it contains no path, log, credential, or protocol payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDescriptor {
    schema_version: String,
    evidence_id: String,
    run_id: String,
    schema_id: String,
    category: EvidenceCategory,
    status: EvidenceStatus,
    observed_at: String,
    receipt_digest: String,
    source_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_digest: Option<String>,
}

impl EvidenceDescriptor {
    /// Constructs a strict descriptor from the output of an independent receipt verifier.
    pub(crate) fn verified(
        run_id: &str,
        schema_id: &str,
        category: EvidenceCategory,
        status: EvidenceStatus,
        receipt_digest: &str,
        source_revision: &str,
        artifact_digest: Option<&str>,
    ) -> Result<Self, EvidenceError> {
        let record = Self {
            schema_version: EVIDENCE_SCHEMA.to_owned(),
            evidence_id: format!(
                "evidence-{}",
                uuid_v7().map_err(|_error| EvidenceError::IdentityUnavailable)?
            ),
            run_id: run_id.to_owned(),
            schema_id: schema_id.to_owned(),
            category,
            status,
            observed_at: now_rfc3339().map_err(|_error| EvidenceError::IdentityUnavailable)?,
            receipt_digest: receipt_digest.to_owned(),
            source_revision: source_revision.to_owned(),
            artifact_digest: artifact_digest.map(str::to_owned),
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the opaque descriptor identifier.
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    /// Returns the run that produced this descriptor.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the independently derived evidence category.
    #[must_use]
    pub const fn category(&self) -> EvidenceCategory {
        self.category
    }

    /// Returns the strict receipt verification result.
    #[must_use]
    pub const fn status(&self) -> EvidenceStatus {
        self.status
    }

    pub(crate) fn schema_id(&self) -> &str {
        &self.schema_id
    }

    pub(crate) fn observed_at(&self) -> &str {
        &self.observed_at
    }

    pub(crate) fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub(crate) fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub(crate) fn artifact_digest(&self) -> Option<&str> {
        self.artifact_digest.as_deref()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_storage(
        evidence_id: String,
        run_id: String,
        schema_id: String,
        category: String,
        status: String,
        observed_at: String,
        receipt_digest: String,
        source_revision: String,
        artifact_digest: Option<String>,
    ) -> Result<Self, EvidenceError> {
        let descriptor = Self {
            schema_version: EVIDENCE_SCHEMA.to_owned(),
            evidence_id,
            run_id,
            schema_id,
            category: EvidenceCategory::from_str(&category)?,
            status: EvidenceStatus::from_str(&status)?,
            observed_at,
            receipt_digest,
            source_revision,
            artifact_digest,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(crate) fn validate(&self) -> Result<(), EvidenceError> {
        let category_binding_is_valid = match self.category {
            EvidenceCategory::Sample | EvidenceCategory::Development => true,
            EvidenceCategory::InstalledArtifact => self.artifact_digest.is_some(),
            // The v1 descriptor does not carry a source-tree/archive binding or an authenticated
            // signature/provenance chain. Refuse stronger labels until a verifier supplies a
            // versioned record that can represent those facts without inference.
            EvidenceCategory::CandidateBound | EvidenceCategory::ReleaseQualifying => false,
        };
        if self.schema_version != EVIDENCE_SCHEMA
            || !bounded_identifier(&self.evidence_id)
            || !self.evidence_id.starts_with("evidence-")
            || !uuid_v7_is_valid(&self.run_id)
            || !bounded_identifier(&self.schema_id)
            || OffsetDateTime::parse(&self.observed_at, &Rfc3339).is_err()
            || !sha256(&self.receipt_digest)
            || !source_revision(&self.source_revision)
            || self
                .artifact_digest
                .as_deref()
                .is_some_and(|digest| !sha256(digest))
            || !category_binding_is_valid
        {
            return Err(EvidenceError::InvalidEvidence);
        }
        Ok(())
    }
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn source_revision(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::{EvidenceCategory, EvidenceDescriptor, EvidenceStatus};
    use crate::RunRecord;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn descriptor_contains_only_closed_safe_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        let descriptor = EvidenceDescriptor::verified(
            run.run_id(),
            "cigar.soak-result.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            DIGEST,
            "revision-1",
            Some(DIGEST),
        )?;
        let value = serde_json::to_value(descriptor)?;
        assert_eq!(
            value.get("category"),
            Some(&serde_json::json!("development"))
        );
        assert!(value.get("path").is_none());
        Ok(())
    }

    #[test]
    fn stronger_categories_require_representable_verified_bindings()
    -> Result<(), Box<dyn std::error::Error>> {
        let run = RunRecord::queued("dashboard-contracts", DIGEST, DIGEST, "revision-1")?;
        assert!(
            EvidenceDescriptor::verified(
                run.run_id(),
                "cigar.dashboard-installed-artifact.v1",
                EvidenceCategory::InstalledArtifact,
                EvidenceStatus::Partial,
                DIGEST,
                "revision-1",
                None,
            )
            .is_err()
        );
        assert!(
            EvidenceDescriptor::verified(
                run.run_id(),
                "cigar.dashboard-installed-artifact.v1",
                EvidenceCategory::InstalledArtifact,
                EvidenceStatus::Partial,
                DIGEST,
                "revision-1",
                Some(DIGEST),
            )
            .is_ok()
        );
        for category in [
            EvidenceCategory::CandidateBound,
            EvidenceCategory::ReleaseQualifying,
        ] {
            assert!(
                EvidenceDescriptor::verified(
                    run.run_id(),
                    "cigar.dashboard-installed-artifact.v1",
                    category,
                    EvidenceStatus::Valid,
                    DIGEST,
                    "revision-1",
                    Some(DIGEST),
                )
                .is_err()
            );
        }
        Ok(())
    }
}
