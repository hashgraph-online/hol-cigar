//! Store-owned blob GC keeps reachability and physical deletion under one repository lock.

use cigar_crypto::{CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider};
use cigar_protocol::{BlobRef, ContentDigest, MediaType, RecordId};
use cigar_store::{
    AccessContext, BlobRecord, CancellationToken, GarbageCollectionPlanErrorCode,
    GarbageCollectionPlanIdentity, GarbageCollectionPolicy, MultiTenantLocalRepositoryBlobStore,
    Repository, RepositoryBlobStore, RepositoryGarbageCollectionCandidate,
    RepositoryGarbageCollectionReport, SharedGarbageCollectionAuthorization, SqliteStore,
    StoreError, StoreErrorCode, StoreRevision, WriteTransaction, sign_garbage_collection_plan,
    verify_garbage_collection_plan_trusted,
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
fn snapshot_consistent_legacy_gc_preview_retains_live_blobs_and_cannot_bypass_signed_run()
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
    store.rebuild_atom_projection(&CancellationToken::default())?;
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

    assert_eq!(
        store
            .garbage_collect_blob_roots(policy, false, 10)
            .map_err(|error| error.code()),
        Err(StoreErrorCode::InvalidContext)
    );
    assert_eq!(repository.get(&tenant, &live.reference)?, Some(live));
    assert_eq!(repository.get(&tenant, &orphan.reference)?, Some(orphan));

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
    assert_eq!(denied, Err(StoreErrorCode::InvalidContext));
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

fn gc_policy() -> GarbageCollectionPolicy {
    GarbageCollectionPolicy {
        retention_satisfied: true,
        legal_hold: false,
        backup_complete: true,
    }
}

struct InterruptingGarbageCollector {
    inner: Arc<dyn RepositoryBlobStore>,
    interrupt_once: AtomicBool,
}

impl InterruptingGarbageCollector {
    fn new(inner: Arc<dyn RepositoryBlobStore>) -> Self {
        Self {
            inner,
            interrupt_once: AtomicBool::new(true),
        }
    }
}

impl RepositoryBlobStore for InterruptingGarbageCollector {
    fn put(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        self.inner.put(tenant, blob)
    }

    fn get(
        &self,
        tenant: &RecordId,
        reference: &BlobRef,
    ) -> Result<Option<BlobRecord>, StoreError> {
        self.inner.get(tenant, reference)
    }

    fn readiness_probe(&self, tenant: &RecordId, blob: &BlobRecord) -> Result<(), StoreError> {
        self.inner.readiness_probe(tenant, blob)
    }

    fn reconcile(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
    ) -> Result<(), StoreError> {
        self.inner.reconcile(live)
    }

    fn garbage_collect_candidates(
        &self,
        authorization: &SharedGarbageCollectionAuthorization,
        candidates: &[RepositoryGarbageCollectionCandidate],
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        if !dry_run
            && self.interrupt_once.swap(false, Ordering::AcqRel)
            && let Some(first) = candidates.first()
        {
            let report = self.inner.garbage_collect_candidates(
                authorization,
                std::slice::from_ref(first),
                policy,
                false,
                max_files,
            )?;
            return AccessContext::new(first.tenant_id.clone(), "").map(|_context| report);
        }
        self.inner
            .garbage_collect_candidates(authorization, candidates, policy, dry_run, max_files)
    }

    fn garbage_collect(
        &self,
        live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        self.inner.garbage_collect(live, policy, dry_run, max_files)
    }
}

#[test]
fn signed_exact_gc_plan_survives_restart_and_deletes_only_its_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("metadata.sqlite3");
    let provider = Arc::new(MemoryKeyProvider::default());
    let signing = provider.create(CreateKeyRequest {
        tenant: "gc-operator-tenant".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let concrete = Arc::new(MultiTenantLocalRepositoryBlobStore::open(
        directory.path().join("blobs"),
        directory.path().join("blob-keys"),
        Arc::clone(&provider),
        10,
    )?);
    let repository: Arc<dyn RepositoryBlobStore> = concrete.clone();
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7900")?;
    let live = blob(b"signed plan must preserve referenced content")?;
    let orphan = blob(b"signed restart-safe exact candidate")?;
    let store = SqliteStore::open_with_blob_repository(&database, Arc::clone(&repository))?;
    let mut write = store.begin_write(
        AccessContext::new(tenant.clone(), "signed-gc-live-root")?,
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    write.put_blob(live.clone())?;
    write.commit(None)?;
    repository.put(&tenant, &orphan)?;
    let plan = store.plan_garbage_collection_blob_roots(gc_policy(), 10, 10)?;
    assert_eq!(plan.repository_revision(), StoreRevision(1));
    assert_eq!(plan.candidates().len(), 1);
    let signed = sign_garbage_collection_plan(
        plan,
        provider.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signing.key_ref,
            tenant: "gc-operator-tenant",
            signer: "gc-operator",
        },
    )?;
    let persisted = serde_json::to_vec(&signed)?;
    assert!(
        !persisted
            .windows(b"null".len())
            .any(|window| window == b"null")
    );
    drop(store);
    let signed = serde_json::from_slice(&persisted)?;
    let verified =
        verify_garbage_collection_plan_trusted(signed, provider.as_ref(), 10, |identity| {
            identity.tenant == "gc-operator-tenant"
                && identity.signer == "gc-operator"
                && identity.signing_key == signing.key_ref
        })?;
    let report = SqliteStore::run_garbage_collection_plan_at(
        &database,
        Arc::clone(&repository),
        &verified,
        false,
    )?;
    assert_eq!(report.eligible, verified.plan().candidates());
    assert_eq!(report.deleted, 1);
    assert_eq!(repository.get(&tenant, &orphan.reference)?, None);
    assert_eq!(repository.get(&tenant, &live.reference)?, Some(live));
    Ok(())
}

#[test]
fn signed_gc_plan_resumes_after_partial_delete_and_retains_unplanned_orphans()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("metadata.sqlite3");
    let blob_root = directory.path().join("blobs");
    let provider = Arc::new(MemoryKeyProvider::default());
    let signing = provider.create(CreateKeyRequest {
        tenant: "gc-operator-tenant".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let concrete: Arc<dyn RepositoryBlobStore> =
        Arc::new(MultiTenantLocalRepositoryBlobStore::open(
            &blob_root,
            directory.path().join("blob-keys"),
            Arc::clone(&provider),
            10,
        )?);
    let repository: Arc<dyn RepositoryBlobStore> =
        Arc::new(InterruptingGarbageCollector::new(concrete));
    let store = SqliteStore::open_with_blob_repository(&database, Arc::clone(&repository))?;
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7902")?;
    let orphans = [
        blob(b"signed resumable candidate one")?,
        blob(b"signed resumable candidate two")?,
        blob(b"unplanned orphan must remain")?,
    ];
    for orphan in &orphans {
        repository.put(&tenant, orphan)?;
    }

    let plan = store.plan_garbage_collection_blob_roots(gc_policy(), 2, 10)?;
    assert_eq!(plan.candidates().len(), 2);
    let signed = sign_garbage_collection_plan(
        plan,
        provider.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signing.key_ref,
            tenant: "gc-operator-tenant",
            signer: "gc-operator",
        },
    )?;
    let verified =
        verify_garbage_collection_plan_trusted(signed, provider.as_ref(), 10, |_identity| true)?;
    let execution_directory = database
        .parent()
        .ok_or("missing database parent")?
        .join(".cigar-gc-executions");
    let preview = store.run_garbage_collection_plan(&verified, true)?;
    assert_eq!(preview.eligible, verified.plan().candidates());
    assert_eq!(preview.deleted, 0);
    assert!(!execution_directory.exists());
    assert_eq!(
        store
            .run_garbage_collection_plan(&verified, false)
            .map_err(|error| error.code()),
        Err(StoreErrorCode::InvalidContext)
    );
    let execution_markers =
        std::fs::read_dir(&execution_directory)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(execution_markers.len(), 1);
    let execution_marker = execution_markers
        .first()
        .ok_or("missing execution marker")?
        .path();
    let execution_marker_bytes = std::fs::read(&execution_marker)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&execution_directory)?
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            execution_markers
                .first()
                .ok_or("missing execution marker")?
                .metadata()?
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
    drop(store);

    std::fs::write(&execution_marker, b"corrupt execution marker")?;
    assert_eq!(
        SqliteStore::run_garbage_collection_plan_at(
            &database,
            Arc::clone(&repository),
            &verified,
            false,
        )
        .map_err(|error| error.code()),
        Err(StoreErrorCode::InvalidRecord)
    );
    std::fs::write(&execution_marker, execution_marker_bytes)?;

    let report = SqliteStore::run_garbage_collection_plan_at(
        &database,
        Arc::clone(&repository),
        &verified,
        false,
    )?;
    assert_eq!(report.eligible, verified.plan().candidates());
    assert_eq!(report.deleted, 1);
    for candidate in verified.plan().candidates() {
        let reference = orphans
            .iter()
            .find(|orphan| orphan.reference.digest == candidate.digest)
            .map(|orphan| &orphan.reference)
            .ok_or("signed candidate missing from fixture")?;
        assert_eq!(repository.get(&candidate.tenant_id, reference)?, None);
    }
    let retained = orphans
        .iter()
        .find(|orphan| {
            !verified
                .plan()
                .candidates()
                .iter()
                .any(|candidate| candidate.digest == orphan.reference.digest)
        })
        .ok_or("missing unplanned orphan")?;
    assert_eq!(
        repository.get(&tenant, &retained.reference)?,
        Some(retained.clone())
    );

    let repeated = SqliteStore::run_garbage_collection_plan_at(
        &database,
        Arc::clone(&repository),
        &verified,
        false,
    )?;
    assert_eq!(repeated.eligible, verified.plan().candidates());
    assert_eq!(repeated.deleted, 0);
    assert_eq!(
        repository.get(&tenant, &retained.reference)?,
        Some(retained.clone())
    );
    Ok(())
}

#[test]
fn exact_gc_run_rejects_same_revision_candidate_drift_and_newer_repository_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let provider = Arc::new(MemoryKeyProvider::default());
    let signing = provider.create(CreateKeyRequest {
        tenant: "gc-operator-tenant".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let blob_root = directory.path().join("blobs");
    let concrete = Arc::new(MultiTenantLocalRepositoryBlobStore::open(
        &blob_root,
        directory.path().join("blob-keys"),
        Arc::clone(&provider),
        10,
    )?);
    let repository: Arc<dyn RepositoryBlobStore> = concrete.clone();
    let store = SqliteStore::open_with_blob_repository(
        directory.path().join("metadata.sqlite3"),
        Arc::clone(&repository),
    )?;
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7901")?;
    let first = blob(b"candidate selected before drift")?;
    let substitute = blob(b"same-revision candidate-set substitution")?;
    repository.put(&tenant, &first)?;
    let plan = store.plan_garbage_collection_blob_roots(gc_policy(), 10, 10)?;
    let signed = sign_garbage_collection_plan(
        plan,
        provider.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signing.key_ref,
            tenant: "gc-operator-tenant",
            signer: "gc-operator",
        },
    )?;
    let verified =
        verify_garbage_collection_plan_trusted(signed, provider.as_ref(), 10, |_identity| true)?;
    repository.put(&tenant, &substitute)?;
    assert_eq!(store.revision()?, StoreRevision(0));
    assert_eq!(
        store
            .run_garbage_collection_plan(&verified, false)
            .map_err(|error| error.code()),
        Err(StoreErrorCode::RevisionConflict)
    );
    assert_eq!(
        repository.get(&tenant, &first.reference)?,
        Some(first.clone())
    );
    assert_eq!(
        repository.get(&tenant, &substitute.reference)?,
        Some(substitute.clone())
    );
    assert!(!directory.path().join(".cigar-gc-executions").exists());
    std::fs::remove_file(
        blob_root
            .join(tenant.as_str())
            .join("blobs")
            .join(first.reference.digest.as_str()),
    )?;
    assert_eq!(
        store
            .run_garbage_collection_plan(&verified, false)
            .map_err(|error| error.code()),
        Err(StoreErrorCode::RevisionConflict)
    );
    assert_eq!(repository.get(&tenant, &first.reference)?, None);
    assert_eq!(
        repository.get(&tenant, &substitute.reference)?,
        Some(substitute.clone())
    );
    repository.put(&tenant, &first)?;

    let plan = store.plan_garbage_collection_blob_roots(gc_policy(), 10, 11)?;
    let signed = sign_garbage_collection_plan(
        plan,
        provider.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signing.key_ref,
            tenant: "gc-operator-tenant",
            signer: "gc-operator",
        },
    )?;
    let verified =
        verify_garbage_collection_plan_trusted(signed, provider.as_ref(), 11, |_identity| true)?;
    let live = blob(b"metadata revision changes without changing old candidates")?;
    let mut write = store.begin_write(
        AccessContext::new(tenant.clone(), "stale-gc-plan")?,
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    write.put_blob(live)?;
    write.commit(None)?;
    assert_eq!(store.revision()?, StoreRevision(1));
    assert_eq!(
        store
            .run_garbage_collection_plan(&verified, false)
            .map_err(|error| error.code()),
        Err(StoreErrorCode::RevisionConflict)
    );
    assert_eq!(repository.get(&tenant, &first.reference)?, Some(first));
    assert_eq!(
        repository.get(&tenant, &substitute.reference)?,
        Some(substitute)
    );
    Ok(())
}

#[test]
fn signed_gc_plan_rejects_semantic_tampering_and_current_trust_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let provider = Arc::new(MemoryKeyProvider::default());
    let signing = provider.create(CreateKeyRequest {
        tenant: "gc-operator-tenant".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let concrete = Arc::new(MultiTenantLocalRepositoryBlobStore::open(
        directory.path().join("blobs"),
        directory.path().join("blob-keys"),
        Arc::clone(&provider),
        10,
    )?);
    let repository: Arc<dyn RepositoryBlobStore> = concrete;
    let store = SqliteStore::open_with_blob_repository(
        directory.path().join("metadata.sqlite3"),
        repository,
    )?;
    let plan = store.plan_garbage_collection_blob_roots(gc_policy(), 10, 10)?;
    let signed = sign_garbage_collection_plan(
        plan,
        provider.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signing.key_ref,
            tenant: "gc-operator-tenant",
            signer: "gc-operator",
        },
    )?;
    let wrong_provider = MemoryKeyProvider::default();
    assert_eq!(
        verify_garbage_collection_plan_trusted(signed.clone(), &wrong_provider, 10, |_identity| {
            true
        },)
        .err()
        .map(|error| error.code()),
        Some(GarbageCollectionPlanErrorCode::KeyUnavailable)
    );
    assert_eq!(
        verify_garbage_collection_plan_trusted(
            signed.clone(),
            provider.as_ref(),
            10,
            |_identity| false,
        )
        .err()
        .map(|error| error.code()),
        Some(GarbageCollectionPlanErrorCode::UntrustedSigner)
    );

    let mut tampered = serde_json::to_value(signed)?;
    let backup_complete = tampered
        .as_object_mut()
        .and_then(|document| document.get_mut("plan"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|plan| plan.get_mut("policy"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|policy| policy.get_mut("backup_complete"))
        .ok_or("missing signed policy field")?;
    *backup_complete = serde_json::Value::Bool(false);
    let tampered = serde_json::from_value(tampered)?;
    assert_eq!(
        verify_garbage_collection_plan_trusted(tampered, provider.as_ref(), 10, |_identity| true,)
            .err()
            .map(|error| error.code()),
        Some(GarbageCollectionPlanErrorCode::Corrupt)
    );

    let blocked = store.plan_garbage_collection_blob_roots(
        GarbageCollectionPolicy {
            retention_satisfied: true,
            legal_hold: true,
            backup_complete: true,
        },
        10,
        11,
    )?;
    let blocked = sign_garbage_collection_plan(
        blocked,
        provider.as_ref(),
        GarbageCollectionPlanIdentity {
            signing_key: &signing.key_ref,
            tenant: "gc-operator-tenant",
            signer: "gc-operator",
        },
    )?;
    let blocked =
        verify_garbage_collection_plan_trusted(blocked, provider.as_ref(), 11, |_identity| true)?;
    assert_eq!(
        store
            .run_garbage_collection_plan(&blocked, false)
            .map_err(|error| error.code()),
        Err(StoreErrorCode::InvalidContext)
    );
    assert_eq!(
        store.run_garbage_collection_plan(&blocked, true)?.deleted,
        0
    );
    Ok(())
}
