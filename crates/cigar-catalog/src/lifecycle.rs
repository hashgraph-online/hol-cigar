//! Immutable supersession provenance, tombstones, and bitemporal lineage selection.

use crate::{CatalogError, CatalogErrorCode};
use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
use cigar_protocol::{
    ContentDigest, ContextAtomV1, ContextEdge, EdgeKind, ExtensionMap, Lifecycle, LineageId,
    RecordId, UtcTimestamp, Validate, VersionId,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Pure lifecycle transition builder that never mutates a prior immutable atom.
#[derive(Clone, Copy, Debug, Default)]
pub struct LifecyclePlanner;

impl LifecyclePlanner {
    /// Creates active successor provenance while retaining the prior immutable version.
    pub fn supersession_edge(
        prior: &ContextAtomV1,
        successor: &ContextAtomV1,
        provenance_digest: ContentDigest,
    ) -> Result<ContextEdge, CatalogError> {
        if prior.lineage_id != successor.lineage_id
            || prior.version_id == successor.version_id
            || successor.temporal.observed_at < prior.temporal.observed_at
            || successor.lifecycle != Lifecycle::Active
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        let edge = ContextEdge {
            schema_version: "cigar.edge.v1"
                .parse()
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            edge_id: RecordId::new(deterministic_uuid(&[
                b"CIGAR-SUPERSESSION-EDGE\0v1\0",
                successor.version_id.as_str().as_bytes(),
                prior.version_id.as_str().as_bytes(),
            ]))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            from_version: successor.version_id.clone(),
            to_version: prior.version_id.clone(),
            kind: EdgeKind::Supersedes,
            provenance_digest,
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        };
        edge.validate()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        Ok(edge)
    }

    /// Creates a new immutable tombstone in the prior lineage at deletion observation time.
    pub fn tombstone(
        prior: &ContextAtomV1,
        observed_at: UtcTimestamp,
    ) -> Result<ContextAtomV1, CatalogError> {
        if observed_at < prior.temporal.observed_at || observed_at <= prior.temporal.valid_from {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let placeholder = VersionId::new(format!("1220{}", "0".repeat(64)))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let mut tombstone = prior.clone();
        tombstone.atom_id = RecordId::new(deterministic_uuid(&[
            b"CIGAR-TOMBSTONE-RECORD\0v1\0",
            prior.version_id.as_str().as_bytes(),
            &observed_at.unix_nanos().to_be_bytes(),
        ]))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        tombstone.version_id = placeholder;
        tombstone.temporal.observed_at = observed_at;
        tombstone.temporal.valid_from = observed_at;
        tombstone.temporal.valid_until = None;
        tombstone.lifecycle = Lifecycle::Tombstoned;
        tombstone.superseded_by = None;
        tombstone.version_id = VersionId::new(
            semantic_multihash_v1(SemanticEnvelopeProfile::Atom, &tombstone)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
        )
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        tombstone
            .validate()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        Ok(tombstone)
    }
}

/// Deterministic bitemporal lineage view over immutable atom history.
#[derive(Clone, Copy, Debug, Default)]
pub struct BitemporalCatalogView;

impl BitemporalCatalogView {
    /// Selects the latest observation per lineage valid at the requested semantic and system time.
    #[must_use]
    pub fn select(
        atoms: &[ContextAtomV1],
        valid_at: UtcTimestamp,
        observed_as_of: UtcTimestamp,
    ) -> Vec<ContextAtomV1> {
        let mut selected: BTreeMap<LineageId, &ContextAtomV1> = BTreeMap::new();
        for atom in atoms {
            if atom.temporal.observed_at > observed_as_of
                || atom.temporal.valid_from > valid_at
                || atom
                    .temporal
                    .valid_until
                    .is_some_and(|valid_until| valid_at >= valid_until)
            {
                continue;
            }
            let replace = selected.get(&atom.lineage_id).is_none_or(|current| {
                (atom.temporal.observed_at, &atom.version_id)
                    > (current.temporal.observed_at, &current.version_id)
            });
            if replace {
                selected.insert(atom.lineage_id.clone(), atom);
            }
        }
        selected
            .into_values()
            .filter(|atom| atom.lifecycle == Lifecycle::Active)
            .cloned()
            .collect()
    }
}

fn deterministic_uuid(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    )
}

#[cfg(test)]
mod tests {
    use super::{BitemporalCatalogView, LifecyclePlanner};
    use cigar_protocol::{
        AtomKind, AtomPayload, Classification, ContentDigest, ContextAtomV1, ExtensionMap,
        FixedPoint, GovernanceEnvelope, InstructionAuthority, Lifecycle, LineageId,
        QualityEnvelope, RecordId, RetrievalEnvelope, ScopeEnvelope, SourceDescriptor, SourceUri,
        TemporalEnvelope, UtcTimestamp, VersionId,
    };

    fn atom(
        version_character: char,
        valid_from: &str,
        observed_at: &str,
    ) -> Result<ContextAtomV1, Box<dyn std::error::Error>> {
        let suffix = if version_character == 'a' { "90" } else { "91" };
        Ok(ContextAtomV1 {
            schema_version: "cigar.atom.v1".parse()?,
            atom_id: RecordId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f78{suffix}"))?,
            lineage_id: LineageId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
            version_id: VersionId::new(format!(
                "1220{}",
                version_character.to_string().repeat(64)
            ))?,
            content_digest: ContentDigest::new(format!("1220{}", "c".repeat(64)))?,
            kind: AtomKind::Documentation,
            payload: AtomPayload::InlineText("fixture".to_owned()),
            source: SourceDescriptor {
                uri: SourceUri::new("file:///fixture")?,
                relative_path: None,
                revision: "revision".to_owned(),
                snapshot_digest: ContentDigest::new(format!("1220{}", "d".repeat(64)))?,
            },
            scope: ScopeEnvelope {
                tenant_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7893")?,
                project_ids: vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7894")?],
            },
            temporal: TemporalEnvelope {
                valid_from: UtcTimestamp::parse_rfc3339(valid_from)?,
                valid_until: None,
                observed_at: UtcTimestamp::parse_rfc3339(observed_at)?,
            },
            governance: GovernanceEnvelope {
                classification: Classification::Internal,
                allowed_purposes: vec!["coding".to_owned()],
                processor_constraints: Vec::new(),
                instruction_authority: InstructionAuthority::Data,
            },
            quality: QualityEnvelope {
                confidence: FixedPoint::new(1_000_000)?,
                coverage: FixedPoint::new(1_000_000)?,
                authority: 1,
            },
            retrieval: RetrievalEnvelope {
                exact_terms: Vec::new(),
                lexical_enabled: true,
                embedding_eligible: false,
            },
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn late_correction_selects_in_both_time_axes() -> Result<(), Box<dyn std::error::Error>> {
        let original = atom('a', "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")?;
        let correction = atom('b', "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")?;
        let valid = UtcTimestamp::parse_rfc3339("2026-01-15T00:00:00Z")?;
        let january = BitemporalCatalogView::select(
            &[original.clone(), correction.clone()],
            valid,
            UtcTimestamp::parse_rfc3339("2026-01-20T00:00:00Z")?,
        );
        assert_eq!(
            january.first().map(|atom| &atom.version_id),
            Some(&original.version_id)
        );
        let february = BitemporalCatalogView::select(
            &[original.clone(), correction.clone()],
            valid,
            UtcTimestamp::parse_rfc3339("2026-02-02T00:00:00Z")?,
        );
        assert_eq!(
            february.first().map(|atom| &atom.version_id),
            Some(&correction.version_id)
        );
        let edge = LifecyclePlanner::supersession_edge(
            &original,
            &correction,
            ContentDigest::new(format!("1220{}", "e".repeat(64)))?,
        )?;
        assert_eq!(edge.to_version, original.version_id);
        Ok(())
    }

    #[test]
    fn tombstone_removes_lineage_after_deletion_time() -> Result<(), Box<dyn std::error::Error>> {
        let original = atom('a', "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")?;
        let deleted_at = UtcTimestamp::parse_rfc3339("2026-03-01T00:00:00Z")?;
        let tombstone = LifecyclePlanner::tombstone(&original, deleted_at)?;
        let selected = BitemporalCatalogView::select(
            &[original, tombstone],
            UtcTimestamp::parse_rfc3339("2026-03-02T00:00:00Z")?,
            UtcTimestamp::parse_rfc3339("2026-03-02T00:00:00Z")?,
        );
        assert!(selected.is_empty());
        Ok(())
    }

    #[test]
    fn future_effective_fact_does_not_hide_current_truth_early()
    -> Result<(), Box<dyn std::error::Error>> {
        let current = atom('a', "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")?;
        let future = atom('b', "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")?;
        let observed = UtcTimestamp::parse_rfc3339("2026-03-01T00:00:00Z")?;
        let before = BitemporalCatalogView::select(
            &[current.clone(), future.clone()],
            UtcTimestamp::parse_rfc3339("2026-03-01T00:00:00Z")?,
            observed,
        );
        assert_eq!(
            before.first().map(|atom| &atom.version_id),
            Some(&current.version_id)
        );
        let after = BitemporalCatalogView::select(
            &[current, future.clone()],
            UtcTimestamp::parse_rfc3339("2026-04-02T00:00:00Z")?,
            observed,
        );
        assert_eq!(
            after.first().map(|atom| &atom.version_id),
            Some(&future.version_id)
        );
        Ok(())
    }
}
