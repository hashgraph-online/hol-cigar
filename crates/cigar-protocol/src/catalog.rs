//! Immutable source snapshots and typed provenance graph edges.

use crate::limits::MAX_SOURCE_REVISION_BYTES;
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    ContentDigest, ExtensionMap, Lifecycle, RecordId, SchemaVersion, SourceUri, UtcTimestamp,
    Validate, VersionId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Atomic connector snapshot from which catalog records are published.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    /// Must be `cigar.source-snapshot.v1`.
    pub schema_version: SchemaVersion,
    /// Unique immutable snapshot identity.
    pub snapshot_id: RecordId,
    /// Connector root URI.
    pub source_uri: SourceUri,
    /// Connector-specific immutable revision.
    #[schemars(length(min = 1, max = MAX_SOURCE_REVISION_BYTES))]
    pub source_revision: String,
    /// UTC observation time.
    pub captured_at: UtcTimestamp,
    /// Digest over the connector snapshot manifest.
    pub manifest_digest: ContentDigest,
    /// Number of source entries represented by the manifest.
    pub entry_count: u64,
    /// Exact aggregate byte count represented by the manifest.
    pub total_bytes: u64,
    /// Whether the connector completed without omissions.
    pub complete: bool,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for SourceSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSnapshot")
            .field("schema_version", &self.schema_version)
            .field("snapshot_id", &self.snapshot_id)
            .field("source_uri", &self.source_uri)
            .field("source_revision_bytes", &self.source_revision.len())
            .field("captured_at", &self.captured_at)
            .field("manifest_digest", &self.manifest_digest)
            .field("entry_count", &self.entry_count)
            .field("total_bytes", &self.total_bytes)
            .field("complete", &self.complete)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Validate for SourceSnapshot {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.source-snapshot") {
            errors.merge(found);
        }
        if self.source_revision.is_empty() || self.source_revision.len() > MAX_SOURCE_REVISION_BYTES
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/source_revision",
                "source revision must be non-empty and bounded",
            ));
        }
        if self.entry_count == 0 && self.total_bytes != 0 {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/total_bytes",
                "an empty snapshot cannot report non-zero aggregate bytes",
            ));
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
    }
}

/// Closed typed provenance and semantic graph edges.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Source version depends on target version.
    DependsOn,
    /// Source version defines target symbol or concept.
    Defines,
    /// Source version references target version.
    References,
    /// Source version supersedes target version.
    Supersedes,
    /// Source version contradicts target version.
    Contradicts,
    /// Source version provides evidence supporting target version.
    Supports,
    /// Source version was derived from target version.
    DerivedFrom,
    /// Source version applies to target version.
    AppliesTo,
}

/// Immutable typed edge in the catalog provenance graph.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEdge {
    /// Must be `cigar.edge.v1`.
    pub schema_version: SchemaVersion,
    /// Unique immutable edge identity.
    pub edge_id: RecordId,
    /// Source semantic version.
    pub from_version: VersionId,
    /// Target semantic version.
    pub to_version: VersionId,
    /// Published edge semantics.
    pub kind: EdgeKind,
    /// Snapshot manifest that proves this edge's origin.
    pub provenance_digest: ContentDigest,
    /// Current edge lifecycle.
    pub lifecycle: Lifecycle,
    /// Required successor edge when superseded and forbidden otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<RecordId>,
    /// Stable bounded extensions.
    pub extensions: ExtensionMap,
}

impl fmt::Debug for ContextEdge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextEdge")
            .field("schema_version", &self.schema_version)
            .field("edge_id", &self.edge_id)
            .field("from_version", &self.from_version)
            .field("to_version", &self.to_version)
            .field("kind", &self.kind)
            .field("provenance_digest", &self.provenance_digest)
            .field("lifecycle", &self.lifecycle)
            .field("has_successor", &self.superseded_by.is_some())
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Validate for ContextEdge {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if let Err(found) = self.schema_version.require_v1("cigar.edge") {
            errors.merge(found);
        }
        if self.from_version == self.to_version {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/to_version",
                "catalog edge cannot reference the same version at both ends",
            ));
        }
        match (self.lifecycle, self.superseded_by.is_some()) {
            (Lifecycle::Superseded, false) => errors.push(issue(
                ValidationCode::InvalidValue,
                "/superseded_by",
                "superseded edge requires a successor edge",
            )),
            (Lifecycle::Active | Lifecycle::Tombstoned | Lifecycle::Quarantined, true) => {
                errors.push(issue(
                    ValidationCode::InvalidValue,
                    "/superseded_by",
                    "only a superseded edge may name a successor",
                ));
            }
            (Lifecycle::Superseded, true)
            | (Lifecycle::Active | Lifecycle::Tombstoned | Lifecycle::Quarantined, false) => {}
        }
        if let Err(found) = self.extensions.validate_known(&BTreeSet::new()) {
            errors.merge(found);
        }
        errors.into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::{ContextEdge, EdgeKind, SourceSnapshot};
    use crate::{
        ContentDigest, ExtensionMap, Lifecycle, RecordId, SourceUri, UtcTimestamp, Validate,
        VersionId,
    };

    fn content_digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
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

    #[test]
    fn snapshot_validates_empty_manifest_consistency() -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = SourceSnapshot {
            schema_version: "cigar.source-snapshot.v1".parse()?,
            snapshot_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7810")?,
            source_uri: SourceUri::new("file:///fixture")?,
            source_revision: "revision-1".to_owned(),
            captured_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
            manifest_digest: content_digest('a')?,
            entry_count: 0,
            total_bytes: 0,
            complete: true,
            extensions: ExtensionMap::default(),
        };
        snapshot.validate()?;
        snapshot.total_bytes = 1;
        assert!(snapshot.validate().is_err());
        Ok(())
    }

    #[test]
    fn edge_rejects_self_reference_and_invalid_lifecycle() -> Result<(), Box<dyn std::error::Error>>
    {
        let version = version('b')?;
        let edge = ContextEdge {
            schema_version: "cigar.edge.v1".parse()?,
            edge_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7811")?,
            from_version: version.clone(),
            to_version: version,
            kind: EdgeKind::DependsOn,
            provenance_digest: content_digest('c')?,
            lifecycle: Lifecycle::Superseded,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        };
        let Err(errors) = edge.validate() else {
            return Err("invalid edge unexpectedly passed".into());
        };
        assert!(errors.len() >= 2);
        Ok(())
    }
}
