//! Store-owned blob GC keeps reachability and physical deletion under one repository lock.

use cigar_crypto::MemoryKeyProvider;
use cigar_protocol::{BlobRef, ContentDigest, MediaType, RecordId};
use cigar_store::{
    AccessContext, BlobRecord, CancellationToken, GarbageCollectionPolicy,
    MultiTenantLocalRepositoryBlobStore, Repository, RepositoryBlobStore,
    RepositoryGarbageCollectionReport, SqliteStore, StoreError, StoreErrorCode, StoreRevision,
    WriteTransaction,
};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn blob(bytes: &[u8]) -> Result<BlobRecord, Box<dyn std::error::Error>> {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(BlobRecord::new(
        BlobRef {
            digest: ContentDigest::new(encoded)?,
            size_bytes: u64::try_from(bytes.len())?,
            media_type: MediaType::new("application/octet-stream")?,
        },
        bytes.to_vec(),
    )?)
}

#[test]
fn snapshot_consistent_gc_retains_live_blobs_and_deletes_only_unreferenced_files()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let provider = Arc::new(MemoryKeyProvider::default());
    let concrete = Arc::new(MultiTenantLocalRepositoryBlobStore::open(
        directory.path().join("blobs"),
        directory.path().join("blob-keys"),
        provider,
        1,
    )?);
    let repository: Arc<dyn RepositoryBlobStore> = concrete.clone();
    let store = SqliteStore::open_with_blob_repository(
        directory.path().join("metadata.sqlite3"),
        Arc::clone(&repository),
    )?;
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
    let live = blob(b"live encrypted payload")?;
    let orphan = blob(b"unreferenced encrypted payload")?;

    let mut transaction = store.begin_write(
        AccessContext::new(tenant.clone(), "store-owned-gc-test")?,
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    transaction.put_blob(live.clone())?;
    transaction.commit(None)?;
    let integrity = store.deep_integrity_check_with_blobs(repository.as_ref())?;
    assert_eq!(integrity.blob_reference_count, 1);
    assert_eq!(integrity.verified_blob_count, 1);
    repository.put(&tenant, &orphan)?;

    let policy = GarbageCollectionPolicy {
        retention_satisfied: true,
        legal_hold: false,
        backup_complete: true,
    };
    let planned = store.garbage_collect_blob_roots(policy, true, 10)?;
    assert_eq!(planned.deleted, 0);
    assert_eq!(planned.eligible.len(), 1);
    let candidate = planned.eligible.first().ok_or("missing GC candidate")?;
    assert_eq!(candidate.tenant_id, tenant);
    assert_eq!(candidate.digest, orphan.reference.digest);
    assert_eq!(
        repository.get(&tenant, &live.reference)?,
        Some(live.clone())
    );
    assert_eq!(
        repository.get(&tenant, &orphan.reference)?,
        Some(orphan.clone())
    );

    let deleted = store.garbage_collect_blob_roots(policy, false, 10)?;
    assert_eq!(deleted.eligible, planned.eligible);
    assert_eq!(deleted.deleted, 1);
    assert_eq!(repository.get(&tenant, &live.reference)?, Some(live));
    assert_eq!(repository.get(&tenant, &orphan.reference)?, None);

    let denied = store
        .garbage_collect_blob_roots(
            GarbageCollectionPolicy {
                retention_satisfied: true,
                legal_hold: true,
                backup_complete: true,
            },
            false,
            10,
        )
        .map_err(|error| error.code());
    assert_eq!(denied, Err(StoreErrorCode::Unavailable));
    Ok(())
}

#[test]
fn one_shot_offline_gc_preserves_candidates_until_the_locked_sweep()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("metadata.sqlite3");
    let provider = Arc::new(MemoryKeyProvider::default());
    let concrete = Arc::new(MultiTenantLocalRepositoryBlobStore::open(
        directory.path().join("blobs"),
        directory.path().join("blob-keys"),
        provider,
        1,
    )?);
    let repository: Arc<dyn RepositoryBlobStore> = concrete.clone();
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7892")?;
    let orphan = blob(b"offline candidate must survive startup")?;
    {
        let _store = SqliteStore::open_with_blob_repository(&database, Arc::clone(&repository))?;
        repository.put(&tenant, &orphan)?;
    }

    let report = SqliteStore::garbage_collect_at(
        &database,
        Arc::clone(&repository),
        GarbageCollectionPolicy {
            retention_satisfied: true,
            legal_hold: false,
            backup_complete: true,
        },
        true,
        10,
    )?;
    assert_eq!(report.deleted, 0);
    assert_eq!(report.eligible.len(), 1);
    let candidate = report.eligible.first().ok_or("missing GC candidate")?;
    assert_eq!(candidate.tenant_id, tenant);
    assert_eq!(candidate.digest, orphan.reference.digest);
    assert_eq!(repository.get(&tenant, &orphan.reference)?, Some(orphan));
    Ok(())
}

#[test]
fn one_shot_gc_refuses_to_create_a_missing_metadata_database()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let provider = Arc::new(MemoryKeyProvider::default());
    let repository: Arc<dyn RepositoryBlobStore> =
        Arc::new(MultiTenantLocalRepositoryBlobStore::open(
            directory.path().join("blobs"),
            directory.path().join("blob-keys"),
            provider,
            1,
        )?);
    let database = directory.path().join("does-not-exist.sqlite3");
    let error = SqliteStore::garbage_collect_at(
        &database,
        repository,
        GarbageCollectionPolicy {
            retention_satisfied: true,
            legal_hold: false,
            backup_complete: true,
        },
        true,
        10,
    )
    .map_err(|error| error.code());
    assert_eq!(error, Err(StoreErrorCode::Unavailable));
    assert!(!database.exists());
    Ok(())
}

#[derive(Default)]
struct BlockingGarbageCollector {
    entered: AtomicBool,
    release: AtomicBool,
    puts: AtomicUsize,
}

impl RepositoryBlobStore for BlockingGarbageCollector {
    fn put(&self, _tenant: &RecordId, _blob: &BlobRecord) -> Result<(), StoreError> {
        self.puts.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn get(
        &self,
        _tenant: &RecordId,
        _reference: &BlobRef,
    ) -> Result<Option<BlobRecord>, StoreError> {
        Ok(None)
    }

    fn readiness_probe(&self, _tenant: &RecordId, _blob: &BlobRecord) -> Result<(), StoreError> {
        Ok(())
    }

    fn reconcile(
        &self,
        _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    fn garbage_collect(
        &self,
        _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        _policy: GarbageCollectionPolicy,
        _dry_run: bool,
        _max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        self.entered.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(RepositoryGarbageCollectionReport::default())
    }
}

fn wait_for_flag(flag: &AtomicBool) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !flag.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            return Err(std::io::Error::other("timed out waiting for GC boundary").into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

#[test]
fn gc_holds_the_repository_writer_lock_across_physical_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let blobs = Arc::new(BlockingGarbageCollector::default());
    let repository: Arc<dyn RepositoryBlobStore> = blobs.clone();
    let database = directory.path().join("metadata.sqlite3");
    let store = Arc::new(SqliteStore::open_with_blob_repository(
        &database,
        Arc::clone(&repository),
    )?);
    // A distinct connection models another process; SQLite, rather than the in-process mutex,
    // must exclude this writer until physical selection completes.
    let writer_store = Arc::new(SqliteStore::open_with_blob_repository(
        &database, repository,
    )?);
    let policy = GarbageCollectionPolicy {
        retention_satisfied: true,
        legal_hold: false,
        backup_complete: true,
    };
    let gc_store = Arc::clone(&store);
    let gc = std::thread::spawn(move || {
        gc_store
            .garbage_collect_blob_roots(policy, true, 10)
            .map(|_report| ())
            .map_err(|error| error.to_string())
    });
    wait_for_flag(&blobs.entered)?;

    let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
    let (finished_sender, finished_receiver) = std::sync::mpsc::sync_channel(1);
    let commit_store = Arc::clone(&writer_store);
    let commit = std::thread::spawn(move || -> Result<(), String> {
        let _sent = started_sender.send(());
        let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")
            .map_err(|error| error.to_string())?;
        let mut transaction = commit_store
            .begin_write(
                AccessContext::new(tenant, "gc-lock-race").map_err(|error| error.to_string())?,
                StoreRevision(0),
                CancellationToken::default(),
            )
            .map_err(|error| error.to_string())?;
        transaction
            .put_blob(blob(b"published only after GC").map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        transaction
            .commit(None)
            .map_err(|error| error.to_string())?;
        let _sent = finished_sender.send(());
        Ok(())
    });
    started_receiver.recv_timeout(Duration::from_secs(5))?;
    assert!(
        finished_receiver
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
    assert_eq!(blobs.puts.load(Ordering::Acquire), 0);

    blobs.release.store(true, Ordering::Release);
    gc.join()
        .map_err(|_panic| std::io::Error::other("GC thread panicked"))?
        .map_err(std::io::Error::other)?;
    commit
        .join()
        .map_err(|_panic| std::io::Error::other("commit thread panicked"))?
        .map_err(std::io::Error::other)?;
    assert_eq!(blobs.puts.load(Ordering::Acquire), 1);
    Ok(())
}
