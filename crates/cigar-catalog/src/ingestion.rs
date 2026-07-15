//! Atomic snapshot-to-atom publication with exact idempotent retry semantics.

use crate::{
    Atomizer, ByteRange, CatalogError, CatalogErrorCode, ConnectorContext, DiscoveryDisposition,
    DiscoveryPlan, IngestionReceipt, SourceConnector, SourceRecord, SourceSnapshotBatch,
};
use cigar_protocol::{
    ContentDigest, ContextAtomV1, ContextEdge, IdempotencyKey, Lifecycle, LineageId, RecordId,
    RelativePath, Validate, VersionId,
};
use cigar_store::{
    AccessContext, AtomSelector, IdempotencyIdentity, OutboxMessage, ReadTransaction, Repository,
    SnapshotSelection, StoreError, StoreErrorCode, StoreRevision, WriteTransaction,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Capability, optimistic revision, and retry identity for one ingestion transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestionRequest {
    /// Tenant and purpose capability.
    pub access: AccessContext,
    /// Exact repository revision expected before publication.
    pub expected_revision: StoreRevision,
    /// Caller-controlled retry identity.
    pub idempotency_key: IdempotencyKey,
}

/// Stateless atomic ingestion coordinator.
#[derive(Clone, Copy, Debug, Default)]
pub struct IngestionService;

impl IngestionService {
    /// Snapshots, rescans, atomizes, validates provenance, and atomically publishes one revision.
    pub fn ingest<R: Repository>(
        &self,
        repository: &R,
        request: IngestionRequest,
        connector: &dyn SourceConnector,
        atomizers: &[&dyn Atomizer],
        context: &ConnectorContext,
    ) -> Result<IngestionReceipt, CatalogError> {
        context.check()?;
        let batch = connector.snapshot(None, context)?;
        self.ingest_batch(repository, request, connector, atomizers, context, batch)
    }

    /// Ingests only records accepted by one exact, freshly revalidated discovery plan.
    ///
    /// The connector snapshot is acquired after preview revalidation and every included record
    /// must still have the same immutable metadata. Excluded and quarantined records never reach
    /// reads or atomizers. This closes the preview-to-ingestion policy gap without trusting a
    /// caller-supplied path list.
    pub fn ingest_discovered<R: Repository>(
        &self,
        repository: &R,
        request: IngestionRequest,
        connector: &dyn SourceConnector,
        atomizers: &[&dyn Atomizer],
        discovery: &DiscoveryPlan,
        context: &ConnectorContext,
    ) -> Result<IngestionReceipt, CatalogError> {
        context.check()?;
        let mut batch = connector.snapshot(None, context)?;
        if discovery.root != batch.snapshot.source_uri {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let included: BTreeMap<&RelativePath, &SourceRecord> = discovery
            .entries
            .iter()
            .filter(|entry| entry.disposition == DiscoveryDisposition::Include)
            .map(|entry| (&entry.record.relative_path, &entry.record))
            .collect();
        let snapshot_by_path: BTreeMap<&RelativePath, &SourceRecord> = batch
            .records
            .iter()
            .map(|record| (&record.relative_path, record))
            .collect();
        if included.len()
            != usize::try_from(discovery.included_count)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
            || included
                .iter()
                .any(|(path, expected)| snapshot_by_path.get(path).copied() != Some(*expected))
        {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        batch.records.retain(|record| {
            included
                .get(&record.relative_path)
                .is_some_and(|expected| **expected == *record)
        });
        self.ingest_batch(repository, request, connector, atomizers, context, batch)
    }

    fn ingest_batch<R: Repository>(
        &self,
        repository: &R,
        request: IngestionRequest,
        connector: &dyn SourceConnector,
        atomizers: &[&dyn Atomizer],
        context: &ConnectorContext,
        mut batch: SourceSnapshotBatch,
    ) -> Result<IngestionReceipt, CatalogError> {
        if !batch.snapshot.complete {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let existing = load_current_atoms(
            repository,
            &request.access,
            request.expected_revision,
            context,
        )?;
        advance_source_observation(&mut batch.snapshot, &existing)?;
        let prior_snapshot = load_snapshot(
            repository,
            &request.access,
            request.expected_revision,
            &batch.snapshot.snapshot_id,
            context,
        )?;
        let active_by_lineage = latest_active_by_lineage(&existing);
        let mut atoms = Vec::new();
        let mut edges = Vec::new();
        let mut processed_paths = BTreeSet::new();
        for record in &batch.records {
            context.check()?;
            if active_by_lineage.values().any(|atom| {
                atom.source.uri == batch.snapshot.source_uri
                    && atom.source.relative_path.as_ref() == Some(&record.relative_path)
                    && atom.source.revision == record.revision
            }) {
                continue;
            }
            processed_paths.insert(record.relative_path.clone());
            let bytes = read_record(connector, record, context)?;
            if crate::scan_secrets(&bytes).must_quarantine() {
                return Err(CatalogError::new(CatalogErrorCode::Denied));
            }
            let atomizer = select_atomizer(atomizers, record, bytes.len())?;
            let descriptor = atomizer.descriptor();
            let output = atomizer.atomize(
                crate::AtomizationRequest {
                    record,
                    bytes: &bytes,
                    snapshot: &batch.snapshot,
                },
                context,
            )?;
            validate_output(
                record,
                &batch.snapshot,
                &descriptor,
                &request.access,
                &output.atoms,
                &output.edges,
            )?;
            atoms.extend(output.atoms);
            edges.extend(output.edges);
        }
        for atom in &atoms {
            if let Some(prior) = active_by_lineage.get(&atom.lineage_id)
                && prior.version_id != atom.version_id
            {
                edges.push(crate::LifecyclePlanner::supersession_edge(
                    prior,
                    atom,
                    batch.snapshot.manifest_digest.clone(),
                )?);
            }
        }
        let current_paths: BTreeSet<&RelativePath> = batch
            .records
            .iter()
            .map(|record| &record.relative_path)
            .collect();
        let new_lineages: BTreeSet<LineageId> =
            atoms.iter().map(|atom| atom.lineage_id.clone()).collect();
        let mut tombstoned_atoms = 0_u64;
        for prior in active_by_lineage.values() {
            let lifecycle_ended = prior.source.relative_path.as_ref().is_some_and(|path| {
                !current_paths.contains(path)
                    || (processed_paths.contains(path) && !new_lineages.contains(&prior.lineage_id))
            });
            if prior.source.uri == batch.snapshot.source_uri && lifecycle_ended {
                atoms.push(crate::LifecyclePlanner::tombstone(
                    prior,
                    batch.snapshot.captured_at,
                )?);
                tombstoned_atoms = tombstoned_atoms
                    .checked_add(1)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
            }
        }
        atoms.sort_by(|left, right| left.version_id.cmp(&right.version_id));
        edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        ensure_unique_atoms(&atoms)?;
        ensure_unique_edges(&edges)?;
        validate_edge_targets(
            repository,
            &request.access,
            request.expected_revision,
            &atoms,
            &edges,
            context,
        )?;
        let publication_digest = publication_digest(
            request.access.tenant_id(),
            &batch.snapshot.snapshot_id,
            &batch.snapshot.manifest_digest,
            &atoms,
            &edges,
        )?;
        let idempotency = IdempotencyIdentity::new(
            "catalog.ingest.v1",
            request.idempotency_key,
            publication_digest.clone(),
        )
        .map_err(map_store_error)?;
        let snapshot_id = batch.snapshot.snapshot_id.clone();
        let published_atoms = u64::try_from(atoms.len())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        if atoms.is_empty() && edges.is_empty() {
            if let Some(existing_snapshot) = prior_snapshot {
                if !same_snapshot_capture(&existing_snapshot, &batch.snapshot) {
                    return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
                }
                return Ok(IngestionReceipt {
                    revision: request.expected_revision,
                    snapshot_id,
                    published_atoms: 0,
                    tombstoned_atoms: 0,
                    publication_digest,
                });
            }
        } else if atoms.is_empty() {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        let mut write = repository
            .begin_write(
                request.access,
                request.expected_revision,
                context.cancellation(),
            )
            .map_err(map_store_error)?;
        write
            .stage_snapshot(batch.snapshot)
            .map_err(map_store_error)?;
        if !atoms.is_empty() {
            write.publish_atoms(atoms, edges).map_err(map_store_error)?;
        }
        write
            .enqueue_outbox(OutboxMessage {
                message_id: RecordId::new(deterministic_uuid(&[
                    b"CIGAR-CATALOG-OUTBOX\0v1\0",
                    publication_digest.as_str().as_bytes(),
                ]))
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
                topic: "catalog.committed".to_owned(),
                payload_digest: publication_digest.clone(),
            })
            .map_err(map_store_error)?;
        context.check()?;
        let receipt = write.commit(Some(idempotency)).map_err(map_store_error)?;
        Ok(IngestionReceipt {
            revision: receipt.revision,
            snapshot_id,
            published_atoms,
            tombstoned_atoms,
            publication_digest,
        })
    }
}

fn advance_source_observation(
    snapshot: &mut cigar_protocol::SourceSnapshot,
    existing: &[ContextAtomV1],
) -> Result<(), CatalogError> {
    let Some(latest) = existing
        .iter()
        .filter(|atom| atom.source.uri == snapshot.source_uri)
        .map(|atom| atom.temporal.observed_at)
        .max()
    else {
        return Ok(());
    };
    snapshot.captured_at = monotonic_source_observation(snapshot.captured_at, latest)?;
    Ok(())
}

fn monotonic_source_observation(
    captured_at: cigar_protocol::UtcTimestamp,
    latest: cigar_protocol::UtcTimestamp,
) -> Result<cigar_protocol::UtcTimestamp, CatalogError> {
    if captured_at > latest {
        return Ok(captured_at);
    }
    cigar_protocol::UtcTimestamp::from_unix_nanos(
        latest
            .unix_nanos()
            .checked_add(1)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
    )
    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidMetadata))
}

fn load_snapshot<R: Repository>(
    repository: &R,
    access: &AccessContext,
    revision: StoreRevision,
    snapshot_id: &RecordId,
    context: &ConnectorContext,
) -> Result<Option<cigar_protocol::SourceSnapshot>, CatalogError> {
    repository
        .begin_read(
            access.clone(),
            SnapshotSelection::Revision(revision),
            context.cancellation(),
        )
        .map_err(map_store_error)?
        .get_snapshot(snapshot_id)
        .map_err(map_store_error)
}

fn same_snapshot_capture(
    existing: &cigar_protocol::SourceSnapshot,
    current: &cigar_protocol::SourceSnapshot,
) -> bool {
    let mut normalized = current.clone();
    normalized.captured_at = existing.captured_at;
    existing == &normalized
}

fn load_current_atoms<R: Repository>(
    repository: &R,
    access: &AccessContext,
    revision: StoreRevision,
    context: &ConnectorContext,
) -> Result<Vec<ContextAtomV1>, CatalogError> {
    let read = repository
        .begin_read(
            access.clone(),
            SnapshotSelection::Revision(revision),
            context.cancellation(),
        )
        .map_err(map_store_error)?;
    let mut atoms = Vec::new();
    let mut cursor = None;
    loop {
        context.check()?;
        let page = read
            .query_atoms(AtomSelector::default(), 1_000, cursor.as_ref())
            .map_err(map_store_error)?;
        atoms.extend(page.items);
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(atoms)
}

fn latest_active_by_lineage(atoms: &[ContextAtomV1]) -> BTreeMap<LineageId, &ContextAtomV1> {
    let mut latest = BTreeMap::new();
    for atom in atoms {
        let replace = latest
            .get(&atom.lineage_id)
            .is_none_or(|current: &&ContextAtomV1| {
                (atom.temporal.observed_at, &atom.version_id)
                    > (current.temporal.observed_at, &current.version_id)
            });
        if replace {
            latest.insert(atom.lineage_id.clone(), atom);
        }
    }
    latest.retain(|_lineage, atom| atom.lifecycle == Lifecycle::Active);
    latest
}

fn read_record(
    connector: &dyn SourceConnector,
    record: &SourceRecord,
    context: &ConnectorContext,
) -> Result<Vec<u8>, CatalogError> {
    if record.size_bytes == 0 {
        return Ok(Vec::new());
    }
    connector
        .read(record, ByteRange::new(0, record.size_bytes)?, context)
        .map(crate::BoundedBytes::into_vec)
}

fn select_atomizer<'a>(
    atomizers: &'a [&dyn Atomizer],
    record: &SourceRecord,
    input_bytes: usize,
) -> Result<&'a dyn Atomizer, CatalogError> {
    let mut matches = atomizers.iter().filter(|atomizer| {
        let descriptor = atomizer.descriptor();
        descriptor.media_types.contains(&record.media_type)
    });
    let selected = matches
        .next()
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::Unavailable))?;
    if matches.next().is_some() {
        return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
    }
    let descriptor = selected.descriptor();
    if input_bytes > descriptor.max_input_bytes {
        return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
    }
    Ok(*selected)
}

fn validate_output(
    record: &SourceRecord,
    snapshot: &cigar_protocol::SourceSnapshot,
    descriptor: &crate::AtomizerDescriptor,
    access: &AccessContext,
    atoms: &[ContextAtomV1],
    edges: &[ContextEdge],
) -> Result<(), CatalogError> {
    for atom in atoms {
        if atom.lifecycle != Lifecycle::Active
            || atom.superseded_by.is_some()
            || atom.source.uri != snapshot.source_uri
            || atom.source.relative_path.as_ref() != Some(&record.relative_path)
            || atom.source.revision != record.revision
            || atom.source.snapshot_digest != snapshot.manifest_digest
            || atom.scope.tenant_id != *access.tenant_id()
            || atom.scope != descriptor.scope
            || atom.governance != descriptor.governance
            || atom.quality != descriptor.quality
            || atom.retrieval.lexical_enabled != descriptor.lexical_enabled
            || atom.retrieval.embedding_eligible != descriptor.embedding_eligible
            || atom
                .governance
                .allowed_purposes
                .binary_search_by(|purpose| purpose.as_str().cmp(access.purpose()))
                .is_err()
            || atom.governance.instruction_authority > descriptor.authority_ceiling
            || !descriptor.produced_kinds.contains(&atom.kind)
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        atom.validate()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
    }
    for edge in edges {
        if edge.lifecycle != Lifecycle::Active
            || edge.superseded_by.is_some()
            || edge.provenance_digest != snapshot.manifest_digest
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        edge.validate()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
    }
    Ok(())
}

fn ensure_unique_atoms(atoms: &[ContextAtomV1]) -> Result<(), CatalogError> {
    if atoms.windows(2).any(|window| {
        window.first().map(|atom| &atom.version_id) == window.get(1).map(|atom| &atom.version_id)
    }) {
        Err(CatalogError::new(CatalogErrorCode::InvalidRecord))
    } else {
        Ok(())
    }
}

fn ensure_unique_edges(edges: &[ContextEdge]) -> Result<(), CatalogError> {
    if edges.windows(2).any(|window| {
        window.first().map(|edge| &edge.edge_id) == window.get(1).map(|edge| &edge.edge_id)
    }) {
        Err(CatalogError::new(CatalogErrorCode::InvalidRecord))
    } else {
        Ok(())
    }
}

fn validate_edge_targets<R: Repository>(
    repository: &R,
    access: &AccessContext,
    expected_revision: StoreRevision,
    atoms: &[ContextAtomV1],
    edges: &[ContextEdge],
    context: &ConnectorContext,
) -> Result<(), CatalogError> {
    let read = repository
        .begin_read(
            access.clone(),
            SnapshotSelection::Revision(expected_revision),
            context.cancellation(),
        )
        .map_err(map_store_error)?;
    let new_versions: BTreeSet<&VersionId> = atoms.iter().map(|atom| &atom.version_id).collect();
    for edge in edges {
        for endpoint in [&edge.from_version, &edge.to_version] {
            if !new_versions.contains(endpoint)
                && read.get_atom(endpoint).map_err(map_store_error)?.is_none()
            {
                return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
            }
        }
    }
    Ok(())
}

fn publication_digest(
    tenant_id: &RecordId,
    snapshot_id: &RecordId,
    manifest: &ContentDigest,
    atoms: &[ContextAtomV1],
    edges: &[ContextEdge],
) -> Result<ContentDigest, CatalogError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-INGESTION-PUBLICATION\0v2\0");
    hasher.update(tenant_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(snapshot_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(manifest.as_str().as_bytes());
    for atom in atoms {
        hasher.update(atom.version_id.as_str().as_bytes());
    }
    for edge in edges {
        hasher.update(edge.edge_id.as_str().as_bytes());
    }
    let digest = hasher.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    }
    ContentDigest::new(value).map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
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

fn map_store_error(error: StoreError) -> CatalogError {
    let code = match error.code() {
        StoreErrorCode::InvalidContext => CatalogErrorCode::Denied,
        StoreErrorCode::NotFound => CatalogErrorCode::NotFound,
        StoreErrorCode::RevisionConflict => CatalogErrorCode::SourceChanged,
        StoreErrorCode::InvalidRecord | StoreErrorCode::MixedSnapshot => {
            CatalogErrorCode::InvalidRecord
        }
        StoreErrorCode::LimitExceeded => CatalogErrorCode::LimitExceeded,
        StoreErrorCode::Cancelled => CatalogErrorCode::Cancelled,
        StoreErrorCode::InjectedAbort | StoreErrorCode::Unavailable => {
            CatalogErrorCode::Unavailable
        }
    };
    CatalogError::new(code)
}

#[cfg(test)]
mod tests {
    use super::{monotonic_source_observation, publication_digest};
    use cigar_protocol::{ContentDigest, UtcTimestamp};

    #[test]
    fn publication_digest_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let tenant = cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?;
        let other_tenant = cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000002")?;
        let snapshot = cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000003")?;
        let other_snapshot = cigar_protocol::RecordId::new("01890f47-8e7d-7b42-a1d2-000000000004")?;
        let manifest = ContentDigest::new(format!("1220{}", "a".repeat(64)))?;
        let first = publication_digest(&tenant, &snapshot, &manifest, &[], &[])?;
        let second = publication_digest(&tenant, &snapshot, &manifest, &[], &[])?;
        assert_eq!(first, second);
        assert_ne!(
            first,
            publication_digest(&other_tenant, &snapshot, &manifest, &[], &[])?
        );
        assert_ne!(
            first,
            publication_digest(&tenant, &other_snapshot, &manifest, &[], &[])?
        );
        Ok(())
    }

    #[test]
    fn source_observation_uses_a_monotonic_logical_successor_when_wall_clock_regresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let captured_at = UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?;
        let latest = UtcTimestamp::parse_rfc3339("2026-07-10T00:00:01Z")?;
        let observed_at = monotonic_source_observation(captured_at, latest)?;
        assert_eq!(
            observed_at.unix_nanos(),
            latest
                .unix_nanos()
                .checked_add(1)
                .ok_or("fixture timestamp overflow")?
        );
        let future = UtcTimestamp::parse_rfc3339("2027-01-01T00:00:00Z")?;
        assert_eq!(monotonic_source_observation(future, latest)?, future);
        Ok(())
    }
}
