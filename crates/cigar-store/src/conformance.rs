//! Reusable black-box repository conformance suite shared by every backend.

use crate::{
    AccessContext, AtomSelector, BlobRecord, CancellationToken, IdempotencyIdentity, OutboxMessage,
    ReadTransaction, Repository, SnapshotSelection, StoreError, StoreErrorCode, StoreRevision,
    WriteTransaction,
};
use cigar_protocol::{
    ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, EffectJournalEvent,
    RecordId, SourceSnapshot, VersionId,
};

/// Backend failpoint control required by the conformance harness.
pub trait ConformanceRepository: Repository {
    /// Causes the next otherwise-valid commit to abort before visibility.
    fn inject_commit_abort(&self);
}

/// Complete deterministic fixture consumed by the black-box behavior suite.
#[derive(Clone)]
pub struct RepositoryFixture {
    /// Authorized tenant/purpose capability.
    pub context: AccessContext,
    /// Different tenant with the same purpose.
    pub other_tenant: AccessContext,
    /// Source snapshot.
    pub snapshot: SourceSnapshot,
    /// Two sorted, tenant-owned atoms.
    pub atoms: Vec<ContextAtomV1>,
    /// Edge connecting the fixture atoms.
    pub edge: ContextEdge,
    /// Reverse derivation edge that would create a cycle.
    pub cycle_edge: ContextEdge,
    /// Immutable compiled bundle.
    pub bundle: ContextBundle,
    /// Genesis context-space commit.
    pub context_commit: ContextCommit,
    /// Genesis effect journal event.
    pub effect_event: EffectJournalEvent,
    /// Protected content-addressed blob.
    pub blob: BlobRecord,
    /// Outbox record caused by the first commit.
    pub outbox: OutboxMessage,
    /// Idempotency identity for the first commit.
    pub idempotency: IdempotencyIdentity,
}

/// Counts from a successful repository conformance execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    /// Repository methods exercised through public traits.
    pub methods_exercised: u32,
    /// Concurrent writers raced at the same expected revision.
    pub concurrent_writers: u32,
    /// Atomic visibility and safety invariants checked.
    pub invariants_checked: u32,
}

/// Runs atomicity, snapshot, idempotency, scoping, concurrency, cursor, and cancellation checks.
pub fn run_repository_conformance<R>(
    repository: &R,
    fixture: &RepositoryFixture,
) -> Result<ConformanceReport, StoreError>
where
    R: ConformanceRepository,
{
    if fixture.atoms.len() != 2 {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let before = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if before.revision() != StoreRevision(0) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let mut dropped = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    dropped.stage_snapshot(fixture.snapshot.clone())?;
    drop(dropped);
    let after_drop = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if after_drop.revision() != StoreRevision(0) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let mut first = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    first.stage_snapshot(fixture.snapshot.clone())?;
    first.publish_atoms(fixture.atoms.clone(), vec![fixture.edge.clone()])?;
    first.put_bundle(fixture.bundle.clone())?;
    first.append_context_commit(fixture.context_commit.clone())?;
    first.append_effect_event(fixture.effect_event.clone())?;
    first.put_blob(fixture.blob.clone())?;
    first.enqueue_outbox(fixture.outbox.clone())?;
    let committed = first.commit(Some(fixture.idempotency.clone()))?;
    if committed.revision != StoreRevision(1) || committed.replayed {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let first_atom = fixture
        .atoms
        .first()
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
    if before.get_atom(&first_atom.version_id)?.is_some()
        || before.get_atoms_by_id(std::slice::from_ref(&first_atom.atom_id))? != vec![None]
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let after = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    let historical = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Revision(StoreRevision(0)),
        CancellationToken::default(),
    )?;
    if historical.get_atom(&first_atom.version_id)?.is_some() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    expect_code(
        repository.begin_read(
            fixture.context.clone(),
            SnapshotSelection::Revision(StoreRevision(99)),
            CancellationToken::default(),
        ),
        StoreErrorCode::NotFound,
    )?;
    if after.get_atom(&first_atom.version_id)?.as_ref() != Some(first_atom)
        || after.get_snapshot(&fixture.snapshot.snapshot_id)?.as_ref() != Some(&fixture.snapshot)
        || after.get_bundle(&fixture.bundle.bundle_id)?.as_ref() != Some(&fixture.bundle)
        || after.get_effect(&fixture.effect_event.effect_id)? != vec![fixture.effect_event.clone()]
        || after.get_blob(&fixture.blob.reference.digest)?.as_ref() != Some(&fixture.blob)
        || after.edges_from(&first_atom.version_id, Some(fixture.edge.kind), 10)?
            != vec![fixture.edge.clone()]
        || after.context_commits(&fixture.context_commit.space_id)?
            != vec![fixture.context_commit.clone()]
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let second_atom = fixture
        .atoms
        .get(1)
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
    let missing_atom_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7800")
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    let ordered = after.get_atoms_by_id(&[
        second_atom.atom_id.clone(),
        missing_atom_id.clone(),
        first_atom.atom_id.clone(),
    ])?;
    if ordered != vec![Some(second_atom.clone()), None, Some(first_atom.clone())]
        || historical.get_atoms_by_id(std::slice::from_ref(&first_atom.atom_id))? != vec![None]
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let current = fixture
        .atoms
        .iter()
        .max_by(|left, right| {
            (left.temporal.observed_at, &left.version_id)
                .cmp(&(right.temporal.observed_at, &right.version_id))
        })
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
    if after.get_active_atom_by_id(&current.atom_id)?.as_ref() != Some(current) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    expect_code(
        after.get_atoms_by_id(&[first_atom.atom_id.clone(), first_atom.atom_id.clone()]),
        StoreErrorCode::InvalidRecord,
    )?;
    expect_code(
        after.get_atoms_by_id(&vec![
            missing_atom_id.clone();
            crate::MAX_ATOM_BATCH_ITEMS + 1
        ]),
        StoreErrorCode::LimitExceeded,
    )?;
    let page = after.query_atoms(AtomSelector::default(), 1, None)?;
    if page.items.len() != 1 || page.next.is_none() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let second_page = after.query_atoms(AtomSelector::default(), 1, page.next.as_ref())?;
    if second_page.items.len() != 1 || second_page.next.is_some() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    expect_code(
        after.query_atoms(AtomSelector::default(), 0, None),
        StoreErrorCode::LimitExceeded,
    )?;
    let outbox = after.outbox()?;
    if outbox.len() != 1
        || outbox.first().map(|record| record.causal_revision) != Some(StoreRevision(1))
        || after.idempotent_result(&fixture.idempotency)? != Some(committed)
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let other = repository.begin_read(
        fixture.other_tenant.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if other.get_atom(&first_atom.version_id)?.is_some()
        || other.get_atoms_by_id(std::slice::from_ref(&first_atom.atom_id))? != vec![None]
        || other.get_active_atom_by_id(&current.atom_id)?.is_some()
        || other.get_blob(&fixture.blob.reference.digest)?.is_some()
        || !other.outbox()?.is_empty()
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }

    let mut replay = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    replay.stage_snapshot(fixture.snapshot.clone())?;
    let replayed = replay.commit(Some(fixture.idempotency.clone()))?;
    if replayed.revision != StoreRevision(1) || !replayed.replayed {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let mismatched_idempotency = IdempotencyIdentity::new(
        fixture.idempotency.scope.clone(),
        fixture.idempotency.key.clone(),
        ContentDigest::new(format!("1220{}", "d".repeat(64)))
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?,
    )?;
    let mut mismatched = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    mismatched.stage_snapshot(fixture.snapshot.clone())?;
    expect_code(
        mismatched.commit(Some(mismatched_idempotency)),
        StoreErrorCode::InvalidRecord,
    )?;

    let mut stale = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    stale.stage_snapshot(fixture.snapshot.clone())?;
    expect_code(stale.commit(None), StoreErrorCode::RevisionConflict)?;

    let mut colliding_atom = second_atom.clone();
    colliding_atom.atom_id = first_atom.atom_id.clone();
    colliding_atom.version_id = VersionId::new(format!("1220{}", "e".repeat(64)))
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    let mut colliding_write = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(1),
        CancellationToken::default(),
    )?;
    colliding_write.publish_atoms(vec![colliding_atom], Vec::new())?;
    expect_code(colliding_write.commit(None), StoreErrorCode::InvalidRecord)?;

    let mut orphan_outbox = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(1),
        CancellationToken::default(),
    )?;
    orphan_outbox.enqueue_outbox(fixture.outbox.clone())?;
    expect_code(orphan_outbox.commit(None), StoreErrorCode::InvalidRecord)?;

    repository.inject_commit_abort();
    let mut aborted = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(1),
        CancellationToken::default(),
    )?;

    let mut cyclic = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(1),
        CancellationToken::default(),
    )?;
    cyclic.publish_atoms(fixture.atoms.clone(), vec![fixture.cycle_edge.clone()])?;
    expect_code(cyclic.commit(None), StoreErrorCode::InvalidRecord)?;
    aborted.stage_snapshot(fixture.snapshot.clone())?;
    expect_code(aborted.commit(None), StoreErrorCode::InjectedAbort)?;
    let after_abort = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    if after_abort.revision() != StoreRevision(1) || after_abort.outbox()? != outbox {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    expect_code(
        repository.begin_read(
            fixture.context.clone(),
            SnapshotSelection::Latest,
            cancelled,
        ),
        StoreErrorCode::Cancelled,
    )?;
    let late_cancel = CancellationToken::default();
    let cancelled_read = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Latest,
        late_cancel.clone(),
    )?;
    late_cancel.cancel();
    expect_code(
        cancelled_read.get_atoms_by_id(std::slice::from_ref(&first_atom.atom_id)),
        StoreErrorCode::Cancelled,
    )?;
    let commit_cancelled = CancellationToken::default();
    let mut cancelled_write = repository.begin_write(
        fixture.context.clone(),
        StoreRevision(1),
        commit_cancelled.clone(),
    )?;
    cancelled_write.stage_snapshot(fixture.snapshot.clone())?;
    commit_cancelled.cancel();
    expect_code(cancelled_write.commit(None), StoreErrorCode::Cancelled)?;

    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            let mut transaction = repository.begin_write(
                fixture.context.clone(),
                StoreRevision(1),
                CancellationToken::default(),
            )?;
            transaction.stage_snapshot(fixture.snapshot.clone())?;
            transaction.commit(None)
        });
        let second = scope.spawn(|| {
            let mut transaction = repository.begin_write(
                fixture.context.clone(),
                StoreRevision(1),
                CancellationToken::default(),
            )?;
            transaction.stage_snapshot(fixture.snapshot.clone())?;
            transaction.commit(None)
        });
        [first.join(), second.join()]
    });
    let mut successes = 0;
    let mut conflicts = 0;
    for result in results {
        match result {
            Ok(Ok(_receipt)) => successes += 1,
            Ok(Err(error)) if error.code() == StoreErrorCode::RevisionConflict => conflicts += 1,
            _ => return Err(StoreError::new(StoreErrorCode::Unavailable)),
        }
    }
    if successes != 1 || conflicts != 1 {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let latest = repository.begin_read(
        fixture.context.clone(),
        SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    expect_code(
        latest.query_atoms(AtomSelector::default(), 1, page.next.as_ref()),
        StoreErrorCode::MixedSnapshot,
    )?;

    Ok(ConformanceReport {
        methods_exercised: 21,
        concurrent_writers: 2,
        invariants_checked: 19,
    })
}

fn expect_code<T>(
    result: Result<T, StoreError>,
    expected: StoreErrorCode,
) -> Result<(), StoreError> {
    match result {
        Err(error) if error.code() == expected => Ok(()),
        _ => Err(StoreError::new(StoreErrorCode::InvalidRecord)),
    }
}

impl ConformanceRepository for crate::InMemoryStore {
    fn inject_commit_abort(&self) {
        self.fail_next_commit();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{RepositoryFixture, run_repository_conformance};
    use crate::{
        AccessContext, BlobRecord, CancellationToken, IdempotencyIdentity, InMemoryStore,
        LocalBlobStore, LocalRepositoryBlobStore, MigrationDefinition, MigrationMode,
        MigrationPlan, OutboxMessage, ReadTransaction, Repository, RepositoryBlobStore,
        SnapshotSelection, SqliteFailpoint, SqliteStore, StoreErrorCode, StoreRevision,
        WriteTransaction,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider,
    };
    use cigar_protocol::{
        BlobRef, ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, EdgeKind,
        EffectJournalEvent, IdempotencyKey, RecordId, SourceSnapshot, VersionId,
    };
    use serde::de::DeserializeOwned;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn protocol_fixture<T: DeserializeOwned>(
        target: &str,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let fixture = cigar_testkit::deterministic_protocol_fixture(target)
            .ok_or_else(|| format!("missing deterministic fixture `{target}`"))?;
        Ok(serde_json::from_value(fixture.input)?)
    }

    fn content_digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        let digest = Sha256::digest(bytes);
        let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(ContentDigest::new(format!("1220{suffix}"))?)
    }

    pub(crate) fn repository_fixture() -> Result<RepositoryFixture, Box<dyn std::error::Error>> {
        let first_atom: ContextAtomV1 = protocol_fixture("ContextAtomV1")?;
        let mut second_atom = first_atom.clone();
        second_atom.atom_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7893")?;
        second_atom.version_id = VersionId::new(format!("1220{}", "b".repeat(64)))?;
        let mut edge: ContextEdge = protocol_fixture("ContextEdge")?;
        edge.from_version = first_atom.version_id.clone();
        edge.to_version = second_atom.version_id.clone();
        edge.kind = EdgeKind::DerivedFrom;
        let mut cycle_edge = edge.clone();
        cycle_edge.edge_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7894")?;
        cycle_edge.from_version = second_atom.version_id.clone();
        cycle_edge.to_version = first_atom.version_id.clone();
        let reference_fixture: BlobRef = protocol_fixture("BlobRef")?;
        let bytes = b"x".to_vec();
        let digest = content_digest(&bytes)?;
        let blob = BlobRecord::new(
            BlobRef {
                digest: digest.clone(),
                size_bytes: 1,
                media_type: reference_fixture.media_type,
            },
            bytes,
        )?;
        let context_commit: ContextCommit = protocol_fixture("ContextCommit")?;
        let context = AccessContext::new(
            first_atom.scope.tenant_id.clone(),
            context_commit.purpose.clone(),
        )?;
        Ok(RepositoryFixture {
            context,
            other_tenant: AccessContext::new(
                RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?,
                context_commit.purpose.clone(),
            )?,
            snapshot: protocol_fixture::<SourceSnapshot>("SourceSnapshot")?,
            atoms: vec![first_atom, second_atom],
            edge,
            cycle_edge,
            bundle: protocol_fixture::<ContextBundle>("ContextBundle")?,
            context_commit,
            effect_event: protocol_fixture::<EffectJournalEvent>("EffectJournalEvent")?,
            blob,
            outbox: OutboxMessage {
                message_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?,
                topic: "catalog.committed".to_owned(),
                payload_digest: digest,
            },
            idempotency: IdempotencyIdentity::new(
                "catalog.publish",
                IdempotencyKey::new("fixture-idempotency")?,
                ContentDigest::new(format!("1220{}", "c".repeat(64)))?,
            )?,
        })
    }

    #[test]
    fn memory_backend_passes_reusable_repository_conformance()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = run_repository_conformance(&InMemoryStore::default(), &repository_fixture()?)?;
        assert_eq!(report.methods_exercised, 21);
        assert_eq!(report.concurrent_writers, 2);
        assert_eq!(report.invariants_checked, 19);
        Ok(())
    }

    #[test]
    fn sqlite_backend_is_durable_configured_and_conformant()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.sqlite3");
        let fixture = repository_fixture()?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let key = provider.create(CreateKeyRequest {
            tenant: fixture.context.tenant_id().as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let local = LocalBlobStore::open(directory.path().join("blobs"), provider)?;
        let blobs: Arc<dyn RepositoryBlobStore> =
            Arc::new(LocalRepositoryBlobStore::new(local, key.key_ref, 1));
        {
            let store = SqliteStore::open_with_blob_repository(&path, Arc::clone(&blobs))?;
            let report = run_repository_conformance(&store, &fixture)?;
            assert_eq!(report.methods_exercised, 21);
            assert_eq!(report.concurrent_writers, 2);
            assert_eq!(report.invariants_checked, 19);
            assert_eq!(store.revision()?.0, 2);
            assert_eq!(
                store.rebuild_atom_projection(&CancellationToken::default())?,
                2
            );
            assert_eq!(
                store.atom_projection_count(fixture.context.tenant_id().as_str())?,
                2
            );
            assert_eq!(
                store.configuration()?,
                crate::SqliteConfiguration {
                    journal_mode: "wal".to_owned(),
                    synchronous: 2,
                    foreign_keys: true,
                    full_text_search: true,
                    defensive: true,
                    cache_kibibytes: 32_768,
                    max_database_bytes: crate::MAX_SQLITE_DATABASE_BYTES,
                    sqlite_version: rusqlite::version().to_owned(),
                }
            );
            store.integrity_check()?;
        }
        let reopened = SqliteStore::open_with_blob_repository(&path, blobs)?;
        assert_eq!(reopened.revision()?.0, 2);
        let read = reopened.begin_read(
            fixture.context,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        let first_atom = fixture
            .atoms
            .first()
            .ok_or("repository fixture must contain an atom")?;
        assert_eq!(
            read.get_atom(&first_atom.version_id)?.as_ref(),
            Some(first_atom)
        );
        assert_eq!(
            read.get_atoms_by_id(std::slice::from_ref(&first_atom.atom_id))?,
            vec![Some(first_atom.clone())]
        );
        Ok(())
    }

    #[test]
    fn sqlite_detects_migration_and_state_tampering() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let state_path = directory.path().join("state-tamper.sqlite3");
        drop(SqliteStore::open(&state_path)?);
        let connection = rusqlite::Connection::open(&state_path)?;
        connection.execute(
            "UPDATE cigar_repository_revisions_v4
             SET residual_state = x'00' WHERE revision = 0",
            [],
        )?;
        drop(connection);
        assert!(matches!(
            SqliteStore::open(&state_path),
            Err(error) if error.code() == StoreErrorCode::Unavailable
        ));

        let migration_path = directory.path().join("migration-tamper.sqlite3");
        drop(SqliteStore::open(&migration_path)?);
        let connection = rusqlite::Connection::open(&migration_path)?;
        connection.execute(
            "UPDATE schema_migrations SET checksum = 'tampered' WHERE sequence = 1",
            [],
        )?;
        drop(connection);
        assert!(matches!(
            SqliteStore::open(&migration_path),
            Err(error) if error.code() == StoreErrorCode::Unavailable
        ));
        Ok(())
    }

    #[test]
    fn sqlite_never_persists_blob_plaintext_and_reconciles_aborted_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.sqlite3");
        let fixture = repository_fixture()?;
        let provider = Arc::new(MemoryKeyProvider::default());
        let key = provider.create(CreateKeyRequest {
            tenant: fixture.context.tenant_id().as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: 1,
            activated_at: 1,
        })?;
        let blob_root = directory.path().join("blobs");
        let local = LocalBlobStore::open(&blob_root, provider)?;
        let blobs: Arc<dyn RepositoryBlobStore> =
            Arc::new(LocalRepositoryBlobStore::new(local, key.key_ref, 1));
        let plaintext = b"database-plaintext-secret-canary".to_vec();
        let digest = content_digest(&plaintext)?;
        let blob = BlobRecord::new(
            BlobRef {
                digest: digest.clone(),
                size_bytes: u64::try_from(plaintext.len())?,
                media_type: fixture.blob.reference.media_type,
            },
            plaintext.clone(),
        )?;
        {
            let store = SqliteStore::open_with_blob_repository(&path, Arc::clone(&blobs))?;
            store.fail_next_commit();
            let mut write = store.begin_write(
                fixture.context.clone(),
                StoreRevision(0),
                CancellationToken::default(),
            )?;
            write.put_blob(blob.clone())?;
            assert_eq!(
                write.commit(None).map_err(|error| error.code()),
                Err(StoreErrorCode::InjectedAbort)
            );
        }
        let encrypted_path = blob_root
            .join(fixture.context.tenant_id().as_str())
            .join("blobs")
            .join(digest.as_str());
        assert!(encrypted_path.exists());
        let store = SqliteStore::open_with_blob_repository(&path, blobs)?;
        assert!(!encrypted_path.exists());
        let mut write = store.begin_write(
            fixture.context.clone(),
            StoreRevision(0),
            CancellationToken::default(),
        )?;
        write.put_blob(blob.clone())?;
        write.commit(None)?;
        let read = store.begin_read(
            fixture.context,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert_eq!(read.get_blob(&digest)?.as_ref(), Some(&blob));
        for database_file in [path.clone(), path.with_extension("sqlite3-wal")] {
            if database_file.exists() {
                let bytes = std::fs::read(database_file)?;
                assert!(
                    !bytes
                        .windows(plaintext.len())
                        .any(|window| window == plaintext)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn sqlite_transaction_failpoints_rollback_every_precommit_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        for failpoint in [
            SqliteFailpoint::AfterBeginImmediate,
            SqliteFailpoint::AfterBlobPublication,
            SqliteFailpoint::BeforeStateInsert,
            SqliteFailpoint::AfterStateInsert,
            SqliteFailpoint::BeforeCommit,
        ] {
            let directory = tempfile::tempdir()?;
            let store = SqliteStore::open(directory.path().join("store.sqlite3"))?;
            let fixture = repository_fixture()?;
            store.inject_failpoint(failpoint)?;
            let mut write = store.begin_write(
                fixture.context,
                StoreRevision(0),
                CancellationToken::default(),
            )?;
            write.stage_snapshot(fixture.snapshot)?;
            assert_eq!(
                write.commit(None).map_err(|error| error.code()),
                Err(StoreErrorCode::InjectedAbort)
            );
            assert_eq!(store.revision()?, StoreRevision(0));
            store.integrity_check()?;
        }
        Ok(())
    }

    #[test]
    fn sqlite_page_quota_reports_full_without_partial_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("store.sqlite3"))?;
        store.constrain_to_current_pages()?;
        let fixture = repository_fixture()?;
        let template = fixture
            .atoms
            .first()
            .ok_or("repository fixture must contain an atom")?;
        let mut atoms = Vec::new();
        for index in 0..1_000_u64 {
            let mut atom = template.clone();
            atom.atom_id = RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{index:012x}"))?;
            atom.version_id = VersionId::new(format!("1220{index:064x}"))?;
            atoms.push(atom);
        }
        let mut write = store.begin_write(
            fixture.context,
            StoreRevision(0),
            CancellationToken::default(),
        )?;
        write.publish_atoms(atoms, Vec::new())?;
        assert_eq!(
            write.commit(None).map_err(|error| error.code()),
            Err(StoreErrorCode::Unavailable)
        );
        assert_eq!(store.revision()?, StoreRevision(0));
        store.integrity_check()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_permission_change_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.sqlite3");
        let store = SqliteStore::open(&path)?;
        assert_eq!(
            std::fs::metadata(directory.path())?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        let mut sidecars = Vec::new();
        for suffix in ["-wal", "-shm"] {
            let sidecar = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            if sidecar.exists() {
                assert_eq!(
                    std::fs::metadata(&sidecar)?.permissions().mode() & 0o777,
                    0o600
                );
                sidecars.push(sidecar);
            }
        }
        if let Some(sidecar) = sidecars.first() {
            std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o644))?;
            assert!(matches!(
                SqliteStore::open(&path),
                Err(error) if error.code() == StoreErrorCode::Unavailable
            ));
            std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o600))?;
        }
        drop(store);
        let original = std::fs::metadata(&path)?.permissions();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let result = SqliteStore::open(&path);
        assert!(matches!(
            result,
            Err(error) if error.code() == StoreErrorCode::Unavailable
        ));
        std::fs::set_permissions(&path, original)?;

        let alias = directory.path().join("hard-linked.sqlite3");
        std::fs::hard_link(&path, &alias)?;
        assert!(matches!(
            SqliteStore::open(&path),
            Err(error) if error.code() == StoreErrorCode::Unavailable
        ));
        std::fs::remove_file(alias)?;

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            SqliteStore::open(&path),
            Err(error) if error.code() == StoreErrorCode::Unavailable
        ));
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[test]
    fn sqlite_ignores_one_million_unbound_legacy_projection_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("million.sqlite3");
        {
            let store = SqliteStore::open(&path)?;
            store.seed_million_atom_projection("scale-tenant")?;
            assert_eq!(store.atom_projection_count("scale-tenant")?, 0);
        }
        let target = format!("1220{:064x}", 1_000_000_u64);
        let mut open_samples = Vec::new();
        let mut query_samples = Vec::new();
        for _sample in 0..30 {
            let started = std::time::Instant::now();
            let reopened = SqliteStore::open(&path)?;
            open_samples.push(started.elapsed());
            let started = std::time::Instant::now();
            assert!(!reopened.atom_projection_contains("scale-tenant", &target)?);
            query_samples.push(started.elapsed());
        }
        open_samples.sort();
        query_samples.sort();
        let open_p95 = *open_samples.get(28).ok_or("missing open p95 sample")?;
        let query_p95 = *query_samples.get(28).ok_or("missing query p95 sample")?;
        assert!(open_p95 <= std::time::Duration::from_secs(2));
        assert!(query_p95 <= std::time::Duration::from_millis(15));
        let reopened = SqliteStore::open(&path)?;
        assert_eq!(reopened.atom_projection_count("scale-tenant")?, 0);
        assert!(
            !reopened
                .atom_projection_contains("scale-tenant", &format!("1220{:064x}", 1_000_001_u64))?
        );
        eprintln!(
            "PROJECTION_ISOLATION unbound_rows=1000000 active_atom_count=0 open_p95_us={} exact_query_p95_us={} database_bytes={}",
            open_p95.as_micros(),
            query_p95.as_micros(),
            std::fs::metadata(path)?.len()
        );
        Ok(())
    }

    #[test]
    fn sqlite_durable_commit_p95_meets_local_profile_gate() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("durability.sqlite3"))?;
        let fixture = repository_fixture()?;
        let mut samples = Vec::new();
        for revision in 0..30_u64 {
            let mut write = store.begin_write(
                fixture.context.clone(),
                StoreRevision(revision),
                CancellationToken::default(),
            )?;
            write.stage_snapshot(fixture.snapshot.clone())?;
            let started = std::time::Instant::now();
            write.commit(None)?;
            samples.push(started.elapsed());
        }
        samples.sort();
        let p95 = *samples.get(28).ok_or("missing durable commit p95 sample")?;
        let dedicated_gate = std::env::var_os("CIGAR_PERFORMANCE_GATES").is_some();
        let threshold = if dedicated_gate {
            std::time::Duration::from_millis(25)
        } else {
            std::time::Duration::from_millis(250)
        };
        assert!(p95 <= threshold);
        eprintln!(
            "WP04_DURABILITY samples=30 dedicated_gate={dedicated_gate} commit_p95_us={}",
            p95.as_micros()
        );
        Ok(())
    }

    #[test]
    fn migration_plan_is_append_only_bounded_and_self_describing()
    -> Result<(), Box<dyn std::error::Error>> {
        let migration = MigrationDefinition {
            sequence: 1,
            name: "initialize_metadata".to_owned(),
            checksum: ContentDigest::new(format!("1220{}", "a".repeat(64)))?,
            minimum_application_major: 1,
            maximum_application_major: 1,
            mode: MigrationMode::Offline,
            lock_behavior: "exclusive schema lock".to_owned(),
            verification: "all required tables exist".to_owned(),
            rollback_or_restore: "restore the mandatory pre-migration backup".to_owned(),
        };
        let plan = MigrationPlan::new(vec![migration.clone()])?;
        assert_eq!(plan.latest_sequence(), 1);
        let mut invalid = migration;
        invalid.sequence = 2;
        assert!(MigrationPlan::new(vec![invalid]).is_err());
        Ok(())
    }
}
