//! Snapshot-pinned public atom lookup and atomic lifecycle mutations.

use crate::{CatalogError, CatalogErrorCode, LifecyclePlanner};
use cigar_protocol::{
    ContentDigest, ContextAtomV1, IdempotencyKey, RecordId, UtcTimestamp, VersionId,
};
use cigar_store::{
    AccessContext, CancellationToken, IdempotencyIdentity, OutboxMessage, ReadTransaction,
    Repository, SnapshotSelection, StoreError, StoreErrorCode, StoreRevision, WriteTransaction,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Maximum atom identities accepted by one ordered lookup.
pub const MAX_ATOM_BATCH_ITEMS: usize = cigar_store::MAX_ATOM_BATCH_ITEMS;

/// Ordered, per-item-existence-hiding result from one immutable repository snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomBatch {
    /// Exact repository revision shared by every result position.
    pub revision: StoreRevision,
    /// Results in request order; `None` means absent or not visible to the supplied capability.
    pub atoms: Vec<Option<ContextAtomV1>>,
}

/// Stable result of one atomic immutable tombstone publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TombstoneReceipt {
    /// Repository revision that atomically published the tombstone and invalidation outbox item.
    pub revision: StoreRevision,
    /// Public identity supplied for the prior current atom.
    pub prior_atom_id: RecordId,
    /// Semantic version of the prior current atom.
    pub prior_version_id: VersionId,
    /// Deterministic public identity of the immutable tombstone record.
    pub tombstone_atom_id: RecordId,
    /// Canonical semantic version of the immutable tombstone record.
    pub tombstone_version_id: VersionId,
    /// Exact invalidation outbox identity supplied by the trusted application layer.
    pub invalidation_message_id: RecordId,
    /// Digest binding the invalidation payload to the prior and tombstone versions.
    pub invalidation_digest: ContentDigest,
    /// True when the native repository idempotency record returned the prior commit.
    pub replayed: bool,
}

/// Stateless catalog operations over trusted repository capabilities and server-owned inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct CatalogAtomService;

impl CatalogAtomService {
    /// Resolves unique public atom identities against one authorized immutable snapshot.
    ///
    /// Input order is preserved. Missing and cross-tenant identities are represented identically
    /// as `None`; no per-item not-found error or tenant oracle is exposed.
    pub fn batch_atoms<R: Repository>(
        &self,
        repository: &R,
        access: AccessContext,
        selection: SnapshotSelection,
        atom_ids: &[RecordId],
        cancellation: CancellationToken,
    ) -> Result<AtomBatch, CatalogError> {
        check_cancellation(&cancellation)?;
        if atom_ids.len() > MAX_ATOM_BATCH_ITEMS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let mut unique = BTreeSet::new();
        if atom_ids.iter().any(|atom_id| !unique.insert(atom_id)) {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let read = repository
            .begin_read(access, selection, cancellation.clone())
            .map_err(map_store_error)?;
        let revision = read.revision();
        let atoms = read.get_atoms_by_id(atom_ids).map_err(map_store_error)?;
        check_cancellation(&cancellation)?;
        Ok(AtomBatch { revision, atoms })
    }

    /// Publishes an immutable tombstone and its invalidation outbox item in one native commit.
    ///
    /// `access`, `observed_at`, and `invalidation_message_id` are trusted application inputs, not
    /// values accepted as authority from a transport DTO. The route atom identity is resolved in
    /// the exact expected revision and must still be that lineage's current active record there.
    #[allow(clippy::too_many_arguments)]
    pub fn tombstone_atom<R: Repository>(
        &self,
        repository: &R,
        access: AccessContext,
        expected_revision: StoreRevision,
        idempotency_key: IdempotencyKey,
        atom_id: RecordId,
        observed_at: UtcTimestamp,
        invalidation_message_id: RecordId,
        cancellation: CancellationToken,
    ) -> Result<TombstoneReceipt, CatalogError> {
        check_cancellation(&cancellation)?;
        let request_digest = tombstone_request_digest(
            &access,
            expected_revision,
            &atom_id,
            observed_at,
            &invalidation_message_id,
        )?;
        let idempotency =
            IdempotencyIdentity::new("catalog.tombstone-atom.v1", idempotency_key, request_digest)
                .map_err(map_store_error)?;

        let latest = repository
            .begin_read(
                access.clone(),
                SnapshotSelection::Latest,
                cancellation.clone(),
            )
            .map_err(map_store_error)?;
        let prior_commit = latest
            .idempotent_result(&idempotency)
            .map_err(map_store_error)?;
        drop(latest);

        let selected = repository
            .begin_read(
                access.clone(),
                SnapshotSelection::Revision(expected_revision),
                cancellation.clone(),
            )
            .map_err(map_store_error)?;
        let prior = selected
            .get_active_atom_by_id(&atom_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::NotFound))?;
        let tombstone = LifecyclePlanner::tombstone(&prior, observed_at)?;
        let invalidation_digest = invalidation_digest(&prior, &tombstone)?;
        check_cancellation(&cancellation)?;

        if let Some(committed) = prior_commit {
            return Ok(tombstone_receipt(
                committed.revision,
                true,
                &prior,
                &tombstone,
                invalidation_message_id,
                invalidation_digest,
            ));
        }

        let mut write = repository
            .begin_write(access, expected_revision, cancellation.clone())
            .map_err(map_store_error)?;
        write
            .publish_atoms(vec![tombstone.clone()], Vec::new())
            .map_err(map_store_error)?;
        write
            .enqueue_outbox(OutboxMessage {
                message_id: invalidation_message_id.clone(),
                topic: "catalog.atom-tombstoned".to_owned(),
                payload_digest: invalidation_digest.clone(),
            })
            .map_err(map_store_error)?;
        check_cancellation(&cancellation)?;
        let committed = write.commit(Some(idempotency)).map_err(map_store_error)?;
        Ok(tombstone_receipt(
            committed.revision,
            committed.replayed,
            &prior,
            &tombstone,
            invalidation_message_id,
            invalidation_digest,
        ))
    }
}

fn tombstone_receipt(
    revision: StoreRevision,
    replayed: bool,
    prior: &ContextAtomV1,
    tombstone: &ContextAtomV1,
    invalidation_message_id: RecordId,
    invalidation_digest: ContentDigest,
) -> TombstoneReceipt {
    TombstoneReceipt {
        revision,
        prior_atom_id: prior.atom_id.clone(),
        prior_version_id: prior.version_id.clone(),
        tombstone_atom_id: tombstone.atom_id.clone(),
        tombstone_version_id: tombstone.version_id.clone(),
        invalidation_message_id,
        invalidation_digest,
        replayed,
    }
}

fn tombstone_request_digest(
    access: &AccessContext,
    expected_revision: StoreRevision,
    atom_id: &RecordId,
    observed_at: UtcTimestamp,
    invalidation_message_id: &RecordId,
) -> Result<ContentDigest, CatalogError> {
    digest_parts(&[
        b"CIGAR-CATALOG-TOMBSTONE-REQUEST\0v1\0",
        access.tenant_id().as_str().as_bytes(),
        access.purpose().as_bytes(),
        &expected_revision.0.to_be_bytes(),
        atom_id.as_str().as_bytes(),
        &observed_at.unix_nanos().to_be_bytes(),
        invalidation_message_id.as_str().as_bytes(),
    ])
}

fn invalidation_digest(
    prior: &ContextAtomV1,
    tombstone: &ContextAtomV1,
) -> Result<ContentDigest, CatalogError> {
    digest_parts(&[
        b"CIGAR-CATALOG-ATOM-INVALIDATION\0v1\0",
        prior.atom_id.as_str().as_bytes(),
        prior.version_id.as_str().as_bytes(),
        tombstone.atom_id.as_str().as_bytes(),
        tombstone.version_id.as_str().as_bytes(),
        &tombstone.temporal.observed_at.unix_nanos().to_be_bytes(),
    ])
}

fn digest_parts(parts: &[&[u8]]) -> Result<ContentDigest, CatalogError> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    }
    ContentDigest::new(value).map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn check_cancellation(cancellation: &CancellationToken) -> Result<(), CatalogError> {
    if cancellation.is_cancelled() {
        Err(CatalogError::new(CatalogErrorCode::Cancelled))
    } else {
        Ok(())
    }
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
    use super::{CatalogAtomService, MAX_ATOM_BATCH_ITEMS};
    use crate::{CatalogErrorCode, LifecyclePlanner};
    use cigar_protocol::{
        AtomKind, AtomPayload, Classification, ContentDigest, ContextAtomV1, ExtensionMap,
        FixedPoint, GovernanceEnvelope, IdempotencyKey, InstructionAuthority, Lifecycle, LineageId,
        QualityEnvelope, RecordId, RetrievalEnvelope, ScopeEnvelope, SourceDescriptor, SourceUri,
        TemporalEnvelope, UtcTimestamp, VersionId,
    };
    use cigar_store::{
        AccessContext, CancellationToken, InMemoryStore, ReadTransaction, Repository,
        SnapshotSelection, SqliteStore, StoreRevision, WriteTransaction,
    };
    use std::sync::Arc;

    fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn lineage(value: u64) -> Result<LineageId, Box<dyn std::error::Error>> {
        Ok(LineageId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!("1220{value:064x}"))?)
    }

    fn atom(
        tenant_id: &RecordId,
        atom_value: u64,
        lineage_value: u64,
        version_value: u64,
    ) -> Result<ContextAtomV1, Box<dyn std::error::Error>> {
        Ok(ContextAtomV1 {
            schema_version: "cigar.atom.v1".parse()?,
            atom_id: record(atom_value)?,
            lineage_id: lineage(lineage_value)?,
            version_id: version(version_value)?,
            content_digest: ContentDigest::new(format!("1220{}", "c".repeat(64)))?,
            kind: AtomKind::Documentation,
            payload: AtomPayload::InlineText(format!("fixture-{atom_value}")),
            source: SourceDescriptor {
                uri: SourceUri::new(format!("file:///fixture-{atom_value}"))?,
                relative_path: None,
                revision: format!("revision-{version_value}"),
                snapshot_digest: ContentDigest::new(format!("1220{}", "d".repeat(64)))?,
            },
            scope: ScopeEnvelope {
                tenant_id: tenant_id.clone(),
                project_ids: vec![record(900)?],
            },
            temporal: TemporalEnvelope {
                valid_from: UtcTimestamp::parse_rfc3339("2026-01-01T00:00:00Z")?,
                valid_until: None,
                observed_at: UtcTimestamp::parse_rfc3339("2026-01-02T00:00:00Z")?,
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

    fn access_context(tenant: u64) -> Result<AccessContext, Box<dyn std::error::Error>> {
        Ok(AccessContext::new(record(tenant)?, "coding")?)
    }

    fn seed<R: Repository>(
        repository: &R,
        access: &AccessContext,
        expected_revision: StoreRevision,
        atoms: Vec<ContextAtomV1>,
    ) -> Result<StoreRevision, Box<dyn std::error::Error>> {
        let mut write = repository.begin_write(
            access.clone(),
            expected_revision,
            CancellationToken::default(),
        )?;
        write.publish_atoms(atoms, Vec::new())?;
        Ok(write.commit(None)?.revision)
    }

    fn deleted_at() -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
        Ok(UtcTimestamp::parse_rfc3339("2026-03-01T00:00:00Z")?)
    }

    #[test]
    fn ordered_batch_lookup_is_snapshot_pinned_bounded_and_existence_hiding()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryStore::default();
        let access = access_context(100)?;
        let first = atom(access.tenant_id(), 1, 11, 1)?;
        let second = atom(access.tenant_id(), 2, 12, 2)?;
        assert_eq!(
            seed(
                &store,
                &access,
                StoreRevision(0),
                vec![first.clone(), second.clone()]
            )?,
            StoreRevision(1)
        );
        let missing = record(99)?;
        let service = CatalogAtomService;
        let batch = service.batch_atoms(
            &store,
            access.clone(),
            SnapshotSelection::Latest,
            &[
                second.atom_id.clone(),
                missing.clone(),
                first.atom_id.clone(),
            ],
            CancellationToken::default(),
        )?;
        assert_eq!(batch.revision, StoreRevision(1));
        assert_eq!(
            batch.atoms,
            vec![Some(second.clone()), None, Some(first.clone())]
        );
        assert_eq!(
            service
                .batch_atoms(
                    &store,
                    access.clone(),
                    SnapshotSelection::Revision(StoreRevision(0)),
                    std::slice::from_ref(&first.atom_id),
                    CancellationToken::default(),
                )?
                .atoms,
            vec![None]
        );
        assert_eq!(
            service
                .batch_atoms(
                    &store,
                    access_context(101)?,
                    SnapshotSelection::Latest,
                    &[first.atom_id.clone(), missing.clone()],
                    CancellationToken::default(),
                )?
                .atoms,
            vec![None, None]
        );
        assert_eq!(
            service
                .batch_atoms(
                    &store,
                    access.clone(),
                    SnapshotSelection::Latest,
                    &[first.atom_id.clone(), first.atom_id.clone()],
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::InvalidMetadata)
        );
        let oversized = (0..=MAX_ATOM_BATCH_ITEMS)
            .map(|index| record(1_000 + u64::try_from(index).unwrap_or(u64::MAX)))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            service
                .batch_atoms(
                    &store,
                    access.clone(),
                    SnapshotSelection::Latest,
                    &oversized,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::LimitExceeded)
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service
                .batch_atoms(&store, access, SnapshotSelection::Latest, &[], cancellation,)
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn tombstone_is_atomic_idempotent_and_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryStore::default();
        let access = access_context(100)?;
        let original = atom(access.tenant_id(), 1, 11, 1)?;
        seed(&store, &access, StoreRevision(0), vec![original.clone()])?;
        let service = CatalogAtomService;
        let key = IdempotencyKey::new("tombstone-key")?;
        let message_id = record(500)?;
        let observed_at = deleted_at()?;

        store.fail_next_commit();
        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access.clone(),
                    StoreRevision(1),
                    key.clone(),
                    original.atom_id.clone(),
                    observed_at,
                    message_id.clone(),
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::Unavailable)
        );
        assert_eq!(store.revision()?, StoreRevision(1));
        assert!(
            store
                .begin_read(
                    access.clone(),
                    SnapshotSelection::Latest,
                    CancellationToken::default(),
                )?
                .outbox()?
                .is_empty()
        );

        let receipt = service.tombstone_atom(
            &store,
            access.clone(),
            StoreRevision(1),
            key.clone(),
            original.atom_id.clone(),
            observed_at,
            message_id.clone(),
            CancellationToken::default(),
        )?;
        assert_eq!(receipt.revision, StoreRevision(2));
        assert!(!receipt.replayed);
        let expected_tombstone = LifecyclePlanner::tombstone(&original, observed_at)?;
        assert_eq!(receipt.tombstone_atom_id, expected_tombstone.atom_id);
        assert_eq!(receipt.tombstone_version_id, expected_tombstone.version_id);

        let read = store.begin_read(
            access.clone(),
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert!(read.get_active_atom_by_id(&original.atom_id)?.is_none());
        assert_eq!(
            read.get_atoms_by_id(std::slice::from_ref(&receipt.tombstone_atom_id))?,
            vec![Some(expected_tombstone)]
        );
        let outbox = read.outbox()?;
        assert_eq!(outbox.len(), 1);
        let outbox_item = outbox
            .first()
            .ok_or_else(|| std::io::Error::other("missing tombstone outbox item"))?;
        assert_eq!(outbox_item.causal_revision, StoreRevision(2));
        assert_eq!(outbox_item.message.message_id, message_id);
        assert_eq!(
            outbox_item.message.payload_digest,
            receipt.invalidation_digest
        );

        let replay = service.tombstone_atom(
            &store,
            access.clone(),
            StoreRevision(1),
            key.clone(),
            original.atom_id.clone(),
            observed_at,
            receipt.invalidation_message_id.clone(),
            CancellationToken::default(),
        )?;
        assert!(replay.replayed);
        assert_eq!(replay.revision, receipt.revision);
        assert_eq!(replay.tombstone_atom_id, receipt.tombstone_atom_id);
        assert_eq!(replay.tombstone_version_id, receipt.tombstone_version_id);
        assert_eq!(replay.invalidation_digest, receipt.invalidation_digest);

        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access.clone(),
                    StoreRevision(1),
                    key,
                    original.atom_id.clone(),
                    observed_at,
                    record(501)?,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::InvalidRecord)
        );
        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access.clone(),
                    StoreRevision(1),
                    IdempotencyKey::new("stale-key")?,
                    original.atom_id.clone(),
                    observed_at,
                    record(502)?,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::SourceChanged)
        );
        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access.clone(),
                    StoreRevision(2),
                    IdempotencyKey::new("already-gone")?,
                    original.atom_id.clone(),
                    observed_at,
                    record(503)?,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::NotFound)
        );
        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access_context(101)?,
                    StoreRevision(2),
                    IdempotencyKey::new("cross-tenant")?,
                    original.atom_id.clone(),
                    observed_at,
                    record(504)?,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::NotFound)
        );
        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access.clone(),
                    StoreRevision(2),
                    IdempotencyKey::new("missing-atom")?,
                    record(998)?,
                    observed_at,
                    record(506)?,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::NotFound)
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service
                .tombstone_atom(
                    &store,
                    access,
                    StoreRevision(2),
                    IdempotencyKey::new("cancelled")?,
                    record(999)?,
                    observed_at,
                    record(505)?,
                    cancellation,
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::Cancelled)
        );
        assert_eq!(store.revision()?, StoreRevision(2));
        Ok(())
    }

    #[test]
    fn sqlite_restart_preserves_tombstone_lookup_outbox_and_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("catalog.sqlite3");
        let access = access_context(100)?;
        let original = atom(access.tenant_id(), 1, 11, 1)?;
        let key = IdempotencyKey::new("sqlite-restart")?;
        let message_id = record(600)?;
        let observed_at = deleted_at()?;
        let receipt = {
            let store = SqliteStore::open(&path)?;
            seed(&store, &access, StoreRevision(0), vec![original.clone()])?;
            CatalogAtomService.tombstone_atom(
                &store,
                access.clone(),
                StoreRevision(1),
                key.clone(),
                original.atom_id.clone(),
                observed_at,
                message_id.clone(),
                CancellationToken::default(),
            )?
        };

        let reopened = SqliteStore::open(&path)?;
        assert_eq!(reopened.revision()?, StoreRevision(2));
        let read = reopened.begin_read(
            access.clone(),
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert_eq!(
            read.get_atoms_by_id(std::slice::from_ref(&receipt.tombstone_atom_id))?
                .first()
                .and_then(Option::as_ref)
                .map(|atom| &atom.version_id),
            Some(&receipt.tombstone_version_id)
        );
        assert!(read.get_active_atom_by_id(&original.atom_id)?.is_none());
        assert_eq!(read.outbox()?.len(), 1);
        drop(read);
        let replay = CatalogAtomService.tombstone_atom(
            &reopened,
            access,
            StoreRevision(1),
            key,
            original.atom_id,
            observed_at,
            message_id,
            CancellationToken::default(),
        )?;
        assert!(replay.replayed);
        assert_eq!(replay.revision, receipt.revision);
        assert_eq!(replay.tombstone_version_id, receipt.tombstone_version_id);
        Ok(())
    }

    #[test]
    fn duplicate_invalidation_identity_rolls_back_the_tombstone()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryStore::default();
        let access = access_context(100)?;
        let first = atom(access.tenant_id(), 1, 11, 1)?;
        let second = atom(access.tenant_id(), 2, 12, 2)?;
        seed(
            &store,
            &access,
            StoreRevision(0),
            vec![first.clone(), second.clone()],
        )?;
        let message_id = record(650)?;
        CatalogAtomService.tombstone_atom(
            &store,
            access.clone(),
            StoreRevision(1),
            IdempotencyKey::new("first-event")?,
            first.atom_id,
            deleted_at()?,
            message_id.clone(),
            CancellationToken::default(),
        )?;
        let second_tombstone = LifecyclePlanner::tombstone(&second, deleted_at()?)?;
        assert_eq!(
            CatalogAtomService
                .tombstone_atom(
                    &store,
                    access.clone(),
                    StoreRevision(2),
                    IdempotencyKey::new("duplicate-event")?,
                    second.atom_id.clone(),
                    deleted_at()?,
                    message_id,
                    CancellationToken::default(),
                )
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::InvalidRecord)
        );
        assert_eq!(store.revision()?, StoreRevision(2));
        let read = store.begin_read(
            access,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert_eq!(
            read.get_active_atom_by_id(&second.atom_id)?.as_ref(),
            Some(&second)
        );
        assert_eq!(
            read.get_atoms_by_id(std::slice::from_ref(&second_tombstone.atom_id))?,
            vec![None]
        );
        assert_eq!(read.outbox()?.len(), 1);
        Ok(())
    }

    #[test]
    fn concurrent_sqlite_retry_commits_one_logical_tombstone()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(SqliteStore::open(
            directory.path().join("concurrent.sqlite3"),
        )?);
        let access = access_context(100)?;
        let original = atom(access.tenant_id(), 1, 11, 1)?;
        seed(
            store.as_ref(),
            &access,
            StoreRevision(0),
            vec![original.clone()],
        )?;
        let key = IdempotencyKey::new("concurrent-retry")?;
        let message_id = record(700)?;
        let observed_at = deleted_at()?;
        let results = (0..8)
            .map(|_worker| {
                let store = Arc::clone(&store);
                let access = access.clone();
                let key = key.clone();
                let atom_id = original.atom_id.clone();
                let message_id = message_id.clone();
                std::thread::spawn(move || {
                    CatalogAtomService.tombstone_atom(
                        store.as_ref(),
                        access,
                        StoreRevision(1),
                        key,
                        atom_id,
                        observed_at,
                        message_id,
                        CancellationToken::default(),
                    )
                })
            })
            .collect::<Vec<_>>();
        let mut receipts = Vec::new();
        for result in results {
            receipts.push(
                result
                    .join()
                    .map_err(|_panic| std::io::Error::other("tombstone worker panicked"))??,
            );
        }
        assert_eq!(
            receipts.iter().filter(|receipt| !receipt.replayed).count(),
            1
        );
        let canonical = receipts
            .first()
            .ok_or_else(|| std::io::Error::other("missing concurrent tombstone receipt"))?;
        assert!(
            receipts
                .iter()
                .all(|receipt| receipt.revision == canonical.revision
                    && receipt.tombstone_version_id == canonical.tombstone_version_id
                    && receipt.invalidation_digest == canonical.invalidation_digest)
        );
        assert_eq!(store.revision()?, StoreRevision(2));
        let read = store.begin_read(
            access,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert_eq!(read.outbox()?.len(), 1);
        assert_eq!(
            read.get_atoms_by_id(std::slice::from_ref(&canonical.tombstone_atom_id))?
                .into_iter()
                .flatten()
                .count(),
            1
        );
        Ok(())
    }
}
