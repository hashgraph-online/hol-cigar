//! Durable SQLite repository with append-only, checksum-protected MVCC states.

use crate::memory::{
    CommittedState, InMemoryReadTransaction, StagedMutation, apply_mutation, blob_digest, validate,
};
use crate::service_repository::{
    EffectRecoveryPage, EffectRecoveryQuery, OutboxRecoveryPage, OutboxRecoveryQuery, ServiceBatch,
    ServiceBatchReceipt, ServiceError, ServiceErrorCode, ServiceListPage, ServiceListQuery,
    ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRepository, WorkerLocator,
    WorkerState, WorkerUpdate, apply_service_batch, apply_worker_update, check_cancellation,
    effect_recovery_from_state, map_store_error, outbox_recovery_from_state,
    service_get_from_state, service_list_from_state, validate_committed_service_state,
    worker_get_from_state,
};
use crate::{
    AccessContext, BlobRecord, CancellationToken, CommitReceipt, EffectRecordEnvelope,
    GarbageCollectionPolicy, IdempotencyIdentity, OutboxMessage, Repository,
    RepositoryGarbageCollectionReport, SnapshotSelection, StoreError, StoreErrorCode,
    StoreRevision, WriteTransaction,
};
use cigar_protocol::{
    AtomPayload, BlobRef, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge,
    EffectJournalEvent, EffectState, Lifecycle, RecordId, SourceSnapshot,
};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const INITIAL_MIGRATION: &str = include_str!("../migrations/sqlite/0001_initial.sql");
/// Maximum complete MVCC snapshots retained by the local profile.
pub const MAX_RETAINED_SQLITE_SNAPSHOTS: usize = 1_024;
/// Hard upper bound for the main local SQLite database file.
pub const MAX_SQLITE_DATABASE_BYTES: u64 = 4_294_967_296;

/// Runtime durability and feature settings observed from an open database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteConfiguration {
    /// Active SQLite journal mode.
    pub journal_mode: String,
    /// Active SQLite synchronous level (`2` is `FULL`).
    pub synchronous: i64,
    /// Whether SQLite foreign-key enforcement is enabled.
    pub foreign_keys: bool,
    /// Whether the atom full-text-search virtual table exists.
    pub full_text_search: bool,
    /// Whether SQLite defensive mode is active.
    pub defensive: bool,
    /// Bounded page-cache setting in kibibytes (negative SQLite `cache_size`).
    pub cache_kibibytes: i64,
    /// Hard database capacity configured through SQLite `max_page_count`.
    pub max_database_bytes: u64,
    /// Runtime SQLite library version.
    pub sqlite_version: String,
}

/// Content-free local storage measurements for capacity monitoring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteStorageStatistics {
    /// Current main database bytes (WAL and SHM are reported separately by operators).
    pub database_bytes: u64,
    /// Current allocated SQLite pages.
    pub page_count: u64,
    /// Configured hard maximum SQLite pages.
    pub max_page_count: u64,
    /// Number of retained complete MVCC snapshots.
    pub retained_snapshots: u64,
    /// Encoded bytes in the latest complete snapshot.
    pub latest_snapshot_bytes: u64,
}

/// Content-free result of a read-only semantic and projection integrity pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteDeepIntegrityReport {
    /// Latest checksum-protected repository revision inspected.
    pub revision: StoreRevision,
    /// Exact tenant partition count in the latest committed state.
    pub tenant_count: u64,
    /// Exact validated canonical atom count.
    pub atom_count: u64,
    /// Exact atom rows matched byte-for-byte in both SQL and FTS projections.
    pub projection_atom_count: u64,
    /// Exact validated legacy effect journal event count.
    pub effect_journal_event_count: u64,
    /// Exact digest-validated authenticated effect-envelope count.
    pub effect_record_count: u64,
    /// Effect envelopes whose semantic journal, tenant seal, and external checkpoint were verified.
    pub verified_effect_record_count: u64,
    /// Exact external encrypted-blob references in the latest committed state.
    pub blob_reference_count: u64,
    /// External blobs authenticated and decrypted against their exact metadata in this pass.
    pub verified_blob_count: u64,
    /// Effects whose latest legacy journal state is explicitly unknown.
    pub unknown_effect_count: u64,
}

type EffectRecordIntegrityVerifier<'a> = dyn FnMut(&RecordId, &EffectRecordEnvelope) -> bool + 'a;

/// Named one-shot SQLite durability and publication failure boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SqliteFailpoint {
    /// Immediately after acquiring the `BEGIN IMMEDIATE` writer transaction.
    AfterBeginImmediate,
    /// After encrypted blob publication but before metadata insertion.
    AfterBlobPublication,
    /// Immediately before appending the immutable state revision.
    BeforeStateInsert,
    /// After state insertion while rollback is still possible.
    AfterStateInsert,
    /// Immediately before the SQLite commit call.
    BeforeCommit,
    /// After SQLite commit and before publishing the durable revision anchor.
    BeforeRevisionAnchor,
    /// After atomically publishing the revision anchor.
    AfterRevisionAnchor,
}

/// Thread-safe durable repository backed by one SQLite WAL database.
pub struct SqliteStore {
    connection: Mutex<Connection>,
    database_path: PathBuf,
    fail_next_commit: AtomicBool,
    blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
    failpoints: Mutex<BTreeSet<SqliteFailpoint>>,
    revision_anchor: Option<PathBuf>,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteStore")
    }
}

impl SqliteStore {
    /// Opens or creates a database, verifies migrations, and initializes revision zero.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_internal(path.as_ref(), None)
    }

    /// Opens a database composed with durable encrypted blob persistence.
    pub fn open_with_blob_repository(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
    ) -> Result<Self, StoreError> {
        Self::open_internal(path.as_ref(), Some(blob_repository))
    }

    /// Opens an existing database only long enough to run one store-owned blob GC operation.
    ///
    /// Unlike normal startup, this entry point deliberately does not reconcile unreferenced
    /// objects before computing the GC plan. It cannot create a missing metadata database, and it
    /// does not expose a long-lived store whose startup reconciliation was skipped. The exact
    /// metadata mark set and physical sweep execute while an immediate SQLite transaction excludes
    /// writers in this and other processes.
    pub fn garbage_collect_at(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        let store = Self::open_internal_with_options(
            path.as_ref(),
            Some(blob_repository),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            false,
        )?;
        store.garbage_collect_blob_roots(policy, dry_run, max_files)
    }

    fn open_internal(
        path: &Path,
        blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
    ) -> Result<Self, StoreError> {
        Self::open_internal_with_options(
            path,
            blob_repository,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            true,
        )
    }

    fn open_internal_with_options(
        path: &Path,
        blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
        flags: rusqlite::OpenFlags,
        reconcile_blobs: bool,
    ) -> Result<Self, StoreError> {
        let secure_identity = prepare_secure_sqlite_path(
            path,
            flags.contains(rusqlite::OpenFlags::SQLITE_OPEN_CREATE),
        )?;
        let mut connection = Connection::open_with_flags(path, flags).map_err(unavailable)?;
        verify_secure_sqlite_path(path, secure_identity)?;
        configure(&connection)?;
        migrate(&mut connection)?;
        ensure_genesis(&connection)?;
        verify_secure_sqlite_path(path, secure_identity)?;
        let store = Self {
            connection: Mutex::new(connection),
            database_path: path.to_path_buf(),
            fail_next_commit: AtomicBool::new(false),
            blob_repository,
            failpoints: Mutex::new(BTreeSet::new()),
            revision_anchor: revision_anchor_path(path),
        };
        store.verify_or_advance_revision_anchor()?;
        if reconcile_blobs {
            store.reconcile_blobs()?;
        }
        Ok(store)
    }

    /// Arms a one-shot abort after validation and before durable publication.
    pub fn fail_next_commit(&self) {
        self.fail_next_commit.store(true, Ordering::Release);
    }

    /// Arms one named one-shot transaction failpoint.
    pub fn inject_failpoint(&self, failpoint: SqliteFailpoint) -> Result<(), StoreError> {
        self.failpoints
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
            .insert(failpoint);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn constrain_to_current_pages(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        let pages = connection
            .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "max_page_count", pages)
            .map_err(unavailable)
    }

    /// Returns the current durable revision.
    pub fn revision(&self) -> Result<StoreRevision, StoreError> {
        let connection = self.lock()?;
        Ok(load_state(&connection, SnapshotSelection::Latest)?.revision)
    }

    /// Proves whether the latest durable state contains no effect projection for any tenant.
    ///
    /// This global check exists for first-boot creation of a separate anti-rollback checkpoint;
    /// checking only currently configured tenants would miss records belonging to retired tenants.
    pub fn effect_store_is_empty(&self) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        let state = load_state(&connection, SnapshotSelection::Latest)?;
        Ok(state
            .tenants
            .values()
            .all(|tenant| tenant.effect_records.is_empty()))
    }

    /// Returns verified SQLite durability and indexing configuration.
    pub fn configuration(&self) -> Result<SqliteConfiguration, StoreError> {
        let connection = self.lock()?;
        let journal_mode = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .map_err(unavailable)?;
        let synchronous = connection
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let foreign_keys = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?
            == 1;
        let full_text_search = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'atom_fts')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?
            == 1;
        let defensive = connection
            .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
            .map_err(unavailable)?;
        let cache_size = connection
            .query_row("PRAGMA cache_size", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let page_size = connection
            .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let max_page_count = connection
            .query_row("PRAGMA max_page_count", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let max_database_bytes = u64::try_from(page_size)
            .ok()
            .and_then(|size| {
                u64::try_from(max_page_count)
                    .ok()
                    .and_then(|pages| size.checked_mul(pages))
            })
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        Ok(SqliteConfiguration {
            journal_mode,
            synchronous,
            foreign_keys,
            full_text_search,
            defensive,
            cache_kibibytes: cache_size.saturating_neg(),
            max_database_bytes,
            sqlite_version: rusqlite::version().to_owned(),
        })
    }

    /// Returns bounded, content-free local database capacity measurements.
    pub fn storage_statistics(&self) -> Result<SqliteStorageStatistics, StoreError> {
        let connection = self.lock()?;
        let page_count = connection
            .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let max_page_count = connection
            .query_row("PRAGMA max_page_count", [], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let retained_snapshots = connection
            .query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(unavailable)?;
        let latest_snapshot_bytes = connection
            .query_row(
                "SELECT length(state) FROM state_snapshots ORDER BY revision DESC LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?;
        Ok(SqliteStorageStatistics {
            database_bytes: fs::metadata(&self.database_path)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
                .len(),
            page_count: u64::try_from(page_count)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            max_page_count: u64::try_from(max_page_count)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            retained_snapshots: u64::try_from(retained_snapshots)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            latest_snapshot_bytes: u64::try_from(latest_snapshot_bytes)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
        })
    }

    /// Checks SQLite structure plus every stored state's digest and decodability.
    pub fn integrity_check(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        verify_connection(&connection)
    }

    /// Verifies every retained snapshot, the latest semantic graph, effect chains, and disposable
    /// atom/FTS projections without repairing or mutating any state.
    pub fn deep_integrity_check(&self) -> Result<SqliteDeepIntegrityReport, StoreError> {
        let connection = self.lock()?;
        verify_connection(&connection)?;
        verify_migration_connection(&connection)?;
        let state = load_state(&connection, SnapshotSelection::Latest)?;
        verify_latest_state_and_projections(&connection, &state)
    }

    /// Performs the complete semantic pass and then authenticates every exact external blob
    /// reachable from the inspected snapshot without invoking reconciliation or quarantine.
    pub fn deep_integrity_check_with_blobs(
        &self,
        repository: &dyn crate::RepositoryBlobStore,
    ) -> Result<SqliteDeepIntegrityReport, StoreError> {
        self.deep_integrity_check_external(repository, None)
    }

    /// Performs the complete semantic pass and authenticates every external blob and latest
    /// effect envelope without repairing either external store.
    pub fn deep_integrity_check_authenticated(
        &self,
        repository: &dyn crate::RepositoryBlobStore,
        mut verify_effect: impl FnMut(&RecordId, &EffectRecordEnvelope) -> bool,
    ) -> Result<SqliteDeepIntegrityReport, StoreError> {
        self.deep_integrity_check_external(repository, Some(&mut verify_effect))
    }

    fn deep_integrity_check_external(
        &self,
        repository: &dyn crate::RepositoryBlobStore,
        mut verify_effect: Option<&mut EffectRecordIntegrityVerifier<'_>>,
    ) -> Result<SqliteDeepIntegrityReport, StoreError> {
        let (state, mut report) = {
            let connection = self.lock()?;
            verify_connection(&connection)?;
            verify_migration_connection(&connection)?;
            let state = load_state(&connection, SnapshotSelection::Latest)?;
            let report = verify_latest_state_and_projections(&connection, &state)?;
            (state, report)
        };
        for (tenant_id, tenant) in state.tenants {
            for blob in tenant.blobs.values() {
                repository.verify_integrity(&tenant_id, &blob.reference)?;
                increment_integrity_count(&mut report.verified_blob_count)?;
            }
            if let Some(verifier) = verify_effect.as_deref_mut() {
                for envelope in tenant.effect_records.values() {
                    if !verifier(&tenant_id, envelope) {
                        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                    }
                    increment_integrity_count(&mut report.verified_effect_record_count)?;
                }
            }
        }
        if report.verified_blob_count != report.blob_reference_count {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        if verify_effect.is_some()
            && report.verified_effect_record_count != report.effect_record_count
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        Ok(report)
    }

    /// Verifies the installed migration ledger without applying or repairing migrations.
    pub fn verify_migration_level(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        verify_migration_connection(&connection)
    }

    /// Reconciles the configured blob repository against exact current metadata roots.
    pub fn reconcile_blob_roots(&self) -> Result<(), StoreError> {
        if self.blob_repository.is_none() {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        self.reconcile_blobs()
    }

    /// Plans or executes bounded blob GC using exact live roots from one locked latest snapshot.
    ///
    /// An immediate SQLite transaction remains held through physical selection/deletion. This
    /// prevents a concurrent writer in this or another process from publishing encrypted bytes
    /// before its metadata becomes visible to the mark set.
    pub fn garbage_collect_blob_roots(
        &self,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        let repository = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let state = load_state(&transaction, SnapshotSelection::Latest)?;
        let live = state
            .tenants
            .into_iter()
            .map(|(tenant, state)| {
                (
                    tenant.as_str().to_owned(),
                    state.blobs.into_keys().collect(),
                )
            })
            .collect();
        let report = repository.garbage_collect(&live, policy, dry_run, max_files)?;
        transaction.commit().map_err(unavailable)?;
        Ok(report)
    }

    /// Performs an exact encrypted write/read/delete probe through the configured blob adapter.
    pub fn blob_readiness_probe(
        &self,
        tenant: &cigar_protocol::RecordId,
        blob: &BlobRecord,
    ) -> Result<(), StoreError> {
        self.blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?
            .readiness_probe(tenant, blob)
    }

    /// Creates a transactionally consistent online backup of the main database.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), StoreError> {
        if destination.as_ref().exists() {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        self.lock()?
            .backup(rusqlite::MAIN_DB, destination, None)
            .map_err(unavailable)
    }

    /// Counts atom projection rows for one exact tenant using the covering primary index.
    pub fn atom_projection_count(&self, tenant: &str) -> Result<u64, StoreError> {
        validate_projection_selector(tenant)?;
        let count = self
            .lock()?
            .query_row(
                "SELECT COUNT(*) FROM atoms WHERE tenant_id = ?1",
                params![tenant],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?;
        u64::try_from(count).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }

    /// Performs one indexed exact-version existence query in the atom projection.
    pub fn atom_projection_contains(
        &self,
        tenant: &str,
        version: &str,
    ) -> Result<bool, StoreError> {
        validate_projection_selector(tenant)?;
        validate_projection_selector(version)?;
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM atoms WHERE tenant_id = ?1 AND version_id = ?2)",
                params![tenant, version],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value == 1)
            .map_err(unavailable)
    }

    /// Transactionally rebuilds the disposable atom and FTS projections from durable state.
    pub fn rebuild_atom_projection(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<u64, StoreError> {
        cancellation.check()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let state = load_state(&transaction, SnapshotSelection::Latest)?;
        transaction
            .execute_batch("DELETE FROM atom_fts; DELETE FROM atoms;")
            .map_err(unavailable)?;
        let mut inserted = 0_u64;
        {
            let mut atom_statement = transaction
                .prepare(
                    "INSERT INTO atoms
                     (tenant_id, version_id, lineage_id, lifecycle, exact_text, record)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(unavailable)?;
            for (tenant_id, tenant) in state.tenants {
                for atom in tenant.atoms.into_values() {
                    cancellation.check()?;
                    let record = encode_record(&atom)?;
                    let text = match &atom.payload {
                        AtomPayload::InlineText(text) => text.as_str(),
                        AtomPayload::Structured(_) | AtomPayload::Blob(_) => "",
                    };
                    atom_statement
                        .execute(params![
                            tenant_id.as_str(),
                            atom.version_id.as_str(),
                            atom.lineage_id.as_str(),
                            lifecycle_name(atom.lifecycle),
                            text,
                            record,
                        ])
                        .map_err(unavailable)?;
                    inserted = inserted
                        .checked_add(1)
                        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
                }
            }
        }
        cancellation.check()?;
        transaction.commit().map_err(unavailable)?;
        Ok(inserted)
    }

    #[cfg(test)]
    pub(crate) fn seed_million_atom_projection(&self, tenant: &str) -> Result<(), StoreError> {
        validate_projection_selector(tenant)?;
        self.lock()?
            .execute(
                "WITH RECURSIVE generated(value) AS (
                    VALUES(1)
                    UNION ALL
                    SELECT value + 1 FROM generated WHERE value < 1000000
                 )
                 INSERT INTO atoms (tenant_id, version_id, lineage_id, lifecycle, record)
                 SELECT ?1, printf('1220%064x', value), printf('lineage-%08x', value),
                        'active', x''
                 FROM generated",
                params![tenant],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }

    pub(crate) fn with_consistent_backup<T, E>(
        &self,
        destination: &Path,
        operation: impl FnOnce(StoreRevision) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        let mut connection = self.lock().map_err(E::from)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)
            .map_err(E::from)?;
        let revision = load_state(&transaction, SnapshotSelection::Latest)
            .map_err(E::from)?
            .revision;
        let source = Connection::open_with_flags(
            &self.database_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(unavailable)
        .map_err(E::from)?;
        source
            .busy_timeout(std::time::Duration::from_secs(30))
            .map_err(unavailable)
            .map_err(E::from)?;
        source
            .backup(rusqlite::MAIN_DB, destination, None)
            .map_err(unavailable)
            .map_err(E::from)?;
        let result = operation(revision)?;
        transaction.commit().map_err(unavailable).map_err(E::from)?;
        Ok(result)
    }

    fn reconcile_blobs(&self) -> Result<(), StoreError> {
        let Some(repository) = &self.blob_repository else {
            return Ok(());
        };
        let connection = self.lock()?;
        let state = load_state(&connection, SnapshotSelection::Latest)?;
        let live = state
            .tenants
            .into_iter()
            .map(|(tenant, state)| {
                (
                    tenant.as_str().to_owned(),
                    state.blobs.into_keys().collect(),
                )
            })
            .collect();
        repository.reconcile(&live)
    }

    fn verify_or_advance_revision_anchor(&self) -> Result<(), StoreError> {
        let Some(path) = &self.revision_anchor else {
            return Ok(());
        };
        let revision = self.revision()?;
        match read_revision_anchor(path)? {
            Some(anchored) if anchored > revision => {
                Err(StoreError::new(StoreErrorCode::Unavailable))
            }
            Some(anchored) if anchored == revision => Ok(()),
            _ => write_revision_anchor(path, revision),
        }
    }

    fn publish_revision_anchor(&self, revision: StoreRevision) -> Result<(), StoreError> {
        let Some(path) = &self.revision_anchor else {
            return Ok(());
        };
        self.trip(SqliteFailpoint::BeforeRevisionAnchor)?;
        write_revision_anchor(path, revision)?;
        self.trip(SqliteFailpoint::AfterRevisionAnchor)
    }

    fn trip(&self, failpoint: SqliteFailpoint) -> Result<(), StoreError> {
        if self
            .failpoints
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
            .remove(&failpoint)
        {
            Err(StoreError::new(StoreErrorCode::InjectedAbort))
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct SecureSqliteIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Clone, Copy)]
struct SecureSqliteIdentity;

#[cfg(unix)]
fn prepare_secure_sqlite_path(
    path: &Path,
    create: bool,
) -> Result<SecureSqliteIdentity, StoreError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let existing = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => None,
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    let mut parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != expected_uid
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    if parent_metadata.mode() & 0o7777 != 0o700 {
        if existing.is_some() {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        parent_metadata = fs::symlink_metadata(parent)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != expected_uid
            || parent_metadata.mode() & 0o7777 != 0o700
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
    }

    match existing {
        Some(_metadata) => secure_sqlite_file_identity(path, expected_uid),
        None => {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
            secure_sqlite_file_identity(path, expected_uid)
        }
    }
}

#[cfg(not(unix))]
fn prepare_secure_sqlite_path(
    _path: &Path,
    _create: bool,
) -> Result<SecureSqliteIdentity, StoreError> {
    Ok(SecureSqliteIdentity)
}

#[cfg(unix)]
fn verify_secure_sqlite_path(
    path: &Path,
    expected: SecureSqliteIdentity,
) -> Result<(), StoreError> {
    let expected_uid = rustix::process::geteuid().as_raw();
    if secure_sqlite_file_identity(path, expected_uid)? != expected {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        let sidecar = PathBuf::from(value);
        match fs::symlink_metadata(&sidecar) {
            Ok(_metadata) => {
                secure_sqlite_file_identity(&sidecar, expected_uid)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_secure_sqlite_path(
    _path: &Path,
    _expected: SecureSqliteIdentity,
) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn secure_sqlite_file_identity(
    path: &Path,
    expected_uid: u32,
) -> Result<SecureSqliteIdentity, StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(SecureSqliteIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) fn verify_sqlite_file(path: &Path) -> Result<(), StoreError> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    verify_connection(&connection)
}

/// Returns the exact external blob set reachable from the latest checksum-protected snapshot.
pub(crate) fn backup_blob_references(
    path: &Path,
) -> Result<BTreeMap<RecordId, Vec<BlobRef>>, StoreError> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    let state = load_state(&connection, SnapshotSelection::Latest)?;
    let mut result = BTreeMap::new();
    for (tenant, tenant_state) in state.tenants {
        let mut references = Vec::with_capacity(tenant_state.blobs.len());
        for (digest, blob) in tenant_state.blobs {
            if digest != blob.reference.digest || blob.bytes.is_some() {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            references.push(blob.reference);
        }
        if !references.is_empty() {
            result.insert(tenant, references);
        }
    }
    Ok(result)
}

fn verify_connection(connection: &Connection) -> Result<(), StoreError> {
    let status = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(unavailable)?;
    if status != "ok" {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let mut statement = connection
        .prepare("SELECT state, checksum FROM state_snapshots ORDER BY revision")
        .map_err(unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(unavailable)?;
    for row in rows {
        let (bytes, checksum) = row.map_err(unavailable)?;
        if state_checksum(&bytes) != checksum {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let state = decode_state(&bytes)?;
        validate_committed_service_state(&state)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    }
    Ok(())
}

fn verify_migration_connection(connection: &Connection) -> Result<(), StoreError> {
    let checksum = state_checksum(INITIAL_MIGRATION.as_bytes());
    let total = connection
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(unavailable)?;
    let matching = connection
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations
             WHERE sequence = 1 AND name = 'initial' AND checksum = ?1",
            params![checksum],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?;
    if total == 1 && matching == 1 {
        Ok(())
    } else {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

fn verify_latest_state_and_projections(
    connection: &Connection,
    state: &CommittedState,
) -> Result<SqliteDeepIntegrityReport, StoreError> {
    let tenant_count = u64::try_from(state.tenants.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let mut atom_count = 0_u64;
    let mut effect_journal_event_count = 0_u64;
    let mut effect_record_count = 0_u64;
    let mut blob_reference_count = 0_u64;
    let mut unknown_effect_count = 0_u64;

    for tenant in state.tenants.values() {
        for atom in tenant.atoms.values() {
            validate(atom)?;
            increment_integrity_count(&mut atom_count)?;
        }
        for edge in tenant.edges.values() {
            validate(edge)?;
            if !tenant.atoms.contains_key(&edge.from_version)
                || !tenant.atoms.contains_key(&edge.to_version)
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
        }
        for bundle in tenant.bundles.values() {
            validate(bundle)?;
        }
        for snapshot in tenant.snapshots.values() {
            validate(snapshot)?;
        }
        for (space_id, commits) in &tenant.context_commits {
            let mut previous = None;
            for (index, commit) in commits.iter().enumerate() {
                validate(commit)?;
                let expected_sequence = u64::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
                if commit.space_id != *space_id
                    || commit.sequence != expected_sequence
                    || commit.parent_commit_id.as_ref() != previous
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
                previous = Some(&commit.commit_id);
            }
        }
        for (effect_id, events) in &tenant.effects {
            verify_effect_journal(effect_id, events)?;
            effect_journal_event_count = effect_journal_event_count
                .checked_add(
                    u64::try_from(events.len())
                        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
                )
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            if events
                .last()
                .is_some_and(|event| event.to_state == EffectState::Unknown)
            {
                increment_integrity_count(&mut unknown_effect_count)?;
            }
        }
        for (effect_id, envelope) in &tenant.effect_records {
            if envelope.effect_id != *effect_id
                || state_checksum(envelope.bytes()) != envelope.record_digest.as_str()
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            if let Some(events) = tenant.effects.get(effect_id)
                && usize::try_from(envelope.effect_version).ok() != Some(events.len())
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            increment_integrity_count(&mut effect_record_count)?;
        }
        for (digest, blob) in &tenant.blobs {
            if blob.reference.digest != *digest
                || blob.bytes.as_ref().is_some_and(|bytes| {
                    state_checksum(bytes) != digest.as_str()
                        || u64::try_from(bytes.len()).ok() != Some(blob.reference.size_bytes)
                })
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            increment_integrity_count(&mut blob_reference_count)?;
        }
    }

    let projection_atom_count = verify_atom_projection(connection, state)?;
    if projection_atom_count != atom_count {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(SqliteDeepIntegrityReport {
        revision: state.revision,
        tenant_count,
        atom_count,
        projection_atom_count,
        effect_journal_event_count,
        effect_record_count,
        verified_effect_record_count: 0,
        blob_reference_count,
        verified_blob_count: 0,
        unknown_effect_count,
    })
}

fn verify_effect_journal(
    effect_id: &RecordId,
    events: &[EffectJournalEvent],
) -> Result<(), StoreError> {
    let mut previous: Option<&EffectJournalEvent> = None;
    for (index, event) in events.iter().enumerate() {
        validate(event)?;
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let expected_from = previous.map_or(EffectState::Prepared, |prior| prior.to_state);
        if event.effect_id != *effect_id
            || event.sequence != expected_sequence
            || event.expected_effect_version
                != u64::try_from(index)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            || event.from_state != expected_from
            || event.previous_event_digest.as_ref() != previous.map(|prior| &prior.event_digest)
            || previous.is_some_and(|prior| event.recorded_at < prior.recorded_at)
            || state_checksum(&journal_preimage(event)?) != event.event_digest.as_str()
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        previous = Some(event);
    }
    Ok(())
}

fn journal_preimage(event: &EffectJournalEvent) -> Result<Vec<u8>, StoreError> {
    let payload = serde_json::to_vec(&(
        &event.event_id,
        &event.effect_id,
        event.sequence,
        event.expected_effect_version,
        event.from_state,
        event.to_state,
        &event.actor_id,
        &event.payload_digest,
        event
            .previous_event_digest
            .as_ref()
            .map_or("", cigar_protocol::ContentDigest::as_str),
        event.recorded_at,
    ))
    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let mut preimage = b"CIGAR-EFFECT-KERNEL\0v1\0effect-journal-event\0".to_vec();
    preimage.extend_from_slice(&payload);
    Ok(preimage)
}

fn verify_atom_projection(
    connection: &Connection,
    state: &CommittedState,
) -> Result<u64, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, version_id, lineage_id, lifecycle, exact_text, record
             FROM atoms ORDER BY tenant_id, version_id",
        )
        .map_err(unavailable)?;
    let mut rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(unavailable)?;
    let mut count = 0_u64;
    for (tenant_id, tenant) in &state.tenants {
        for atom in tenant.atoms.values() {
            let row = rows
                .next()
                .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?
                .map_err(unavailable)?;
            let exact_text = match &atom.payload {
                AtomPayload::InlineText(text) => text.as_str(),
                AtomPayload::Structured(_) | AtomPayload::Blob(_) => "",
            };
            if row.0 != tenant_id.as_str()
                || row.1 != atom.version_id.as_str()
                || row.2 != atom.lineage_id.as_str()
                || row.3 != lifecycle_name(atom.lifecycle)
                || row.4 != exact_text
                || row.5 != encode_record(atom)?
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            increment_integrity_count(&mut count)?;
        }
    }
    if rows.next().is_some() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let mut fts_statement = connection
        .prepare(
            "SELECT tenant_id, version_id, exact_text FROM atom_fts ORDER BY tenant_id, version_id",
        )
        .map_err(unavailable)?;
    let mut fts_rows = fts_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(unavailable)?;
    for (tenant_id, tenant) in &state.tenants {
        for atom in tenant.atoms.values() {
            let row = fts_rows
                .next()
                .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?
                .map_err(unavailable)?;
            let exact_text = match &atom.payload {
                AtomPayload::InlineText(text) => text.as_str(),
                AtomPayload::Structured(_) | AtomPayload::Blob(_) => "",
            };
            if row.0 != tenant_id.as_str()
                || row.1 != atom.version_id.as_str()
                || row.2 != exact_text
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
        }
    }
    if fts_rows.next().is_some() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(count)
}

fn increment_integrity_count(value: &mut u64) -> Result<(), StoreError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    Ok(())
}

impl Repository for SqliteStore {
    type Read<'store>
        = InMemoryReadTransaction
    where
        Self: 'store;
    type Write<'store>
        = SqliteWriteTransaction<'store>
    where
        Self: 'store;

    fn begin_read(
        &self,
        context: AccessContext,
        selection: SnapshotSelection,
        cancellation: CancellationToken,
    ) -> Result<Self::Read<'_>, StoreError> {
        cancellation.check()?;
        let connection = self.lock()?;
        let state = load_state(&connection, selection)?;
        Ok(InMemoryReadTransaction {
            state: Arc::new(state),
            context,
            cancellation,
            blob_repository: self.blob_repository.clone(),
        })
    }

    fn begin_write(
        &self,
        context: AccessContext,
        expected_revision: StoreRevision,
        cancellation: CancellationToken,
    ) -> Result<Self::Write<'_>, StoreError> {
        cancellation.check()?;
        Ok(SqliteWriteTransaction {
            store: self,
            context,
            expected_revision,
            cancellation,
            staged: Vec::new(),
        })
    }
}

impl ServiceRepository for SqliteStore {
    fn service_get(
        &self,
        locator: &ServiceRecordLocator,
        selection: ServiceRecordSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<ServiceRecord>, ServiceError> {
        check_cancellation(cancellation)?;
        let connection = self.lock().map_err(map_store_error)?;
        let state = load_state(&connection, SnapshotSelection::Latest).map_err(map_store_error)?;
        service_get_from_state(&state, locator, selection)
    }

    fn service_list(
        &self,
        query: &ServiceListQuery,
        cancellation: &CancellationToken,
    ) -> Result<ServiceListPage, ServiceError> {
        check_cancellation(cancellation)?;
        let selection = query
            .revision()
            .map_or(SnapshotSelection::Latest, SnapshotSelection::Revision);
        let connection = self.lock().map_err(map_store_error)?;
        let state = load_state(&connection, selection).map_err(map_store_error)?;
        service_list_from_state(&state, query)
    }

    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError> {
        check_cancellation(cancellation)?;
        let mut connection = self.lock().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(service_unavailable)?;
        self.trip(SqliteFailpoint::AfterBeginImmediate)
            .map_err(map_store_error)?;
        let latest =
            load_state(&transaction, SnapshotSelection::Latest).map_err(map_store_error)?;
        let (next, receipt) = apply_service_batch(&latest, batch)?;
        if receipt.replayed {
            return Ok(receipt);
        }
        let next = next.ok_or_else(|| ServiceError::new(ServiceErrorCode::Unavailable))?;
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(ServiceErrorCode::InjectedAbort));
        }
        let bytes = encode_state(&next).map_err(map_store_error)?;
        let checksum = state_checksum(&bytes);
        let sqlite_revision = sqlite_revision(next.revision).map_err(map_store_error)?;
        self.trip(SqliteFailpoint::BeforeStateInsert)
            .map_err(map_store_error)?;
        transaction
            .execute(
                "INSERT INTO state_snapshots (revision, state, checksum) VALUES (?1, ?2, ?3)",
                params![sqlite_revision, bytes, checksum],
            )
            .map_err(service_unavailable)?;
        prune_state_snapshots(&transaction).map_err(map_store_error)?;
        self.trip(SqliteFailpoint::AfterStateInsert)
            .map_err(map_store_error)?;
        self.trip(SqliteFailpoint::BeforeCommit)
            .map_err(map_store_error)?;
        transaction.commit().map_err(service_unavailable)?;
        self.publish_revision_anchor(next.revision)
            .map_err(map_store_error)?;
        Ok(receipt)
    }

    fn effect_recovery(
        &self,
        query: &EffectRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<EffectRecoveryPage, ServiceError> {
        check_cancellation(cancellation)?;
        let selection = query
            .revision()
            .map_or(SnapshotSelection::Latest, SnapshotSelection::Revision);
        let connection = self.lock().map_err(map_store_error)?;
        let state = load_state(&connection, selection).map_err(map_store_error)?;
        effect_recovery_from_state(&state, query)
    }

    fn outbox_recovery(
        &self,
        query: &OutboxRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<OutboxRecoveryPage, ServiceError> {
        check_cancellation(cancellation)?;
        let selection = query
            .revision()
            .map_or(SnapshotSelection::Latest, SnapshotSelection::Revision);
        let connection = self.lock().map_err(map_store_error)?;
        let state = load_state(&connection, selection).map_err(map_store_error)?;
        outbox_recovery_from_state(&state, query)
    }

    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError> {
        check_cancellation(cancellation)?;
        let connection = self.lock().map_err(map_store_error)?;
        let state = load_state(&connection, SnapshotSelection::Latest).map_err(map_store_error)?;
        worker_get_from_state(&state, locator)
    }

    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError> {
        check_cancellation(cancellation)?;
        let mut connection = self.lock().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(service_unavailable)?;
        self.trip(SqliteFailpoint::AfterBeginImmediate)
            .map_err(map_store_error)?;
        let latest =
            load_state(&transaction, SnapshotSelection::Latest).map_err(map_store_error)?;
        let (next, state) = apply_worker_update(&latest, locator, update)?;
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(ServiceErrorCode::InjectedAbort));
        }
        let bytes = encode_state(&next).map_err(map_store_error)?;
        let checksum = state_checksum(&bytes);
        let sqlite_revision = sqlite_revision(next.revision).map_err(map_store_error)?;
        self.trip(SqliteFailpoint::BeforeStateInsert)
            .map_err(map_store_error)?;
        transaction
            .execute(
                "INSERT INTO state_snapshots (revision, state, checksum) VALUES (?1, ?2, ?3)",
                params![sqlite_revision, bytes, checksum],
            )
            .map_err(service_unavailable)?;
        prune_state_snapshots(&transaction).map_err(map_store_error)?;
        self.trip(SqliteFailpoint::AfterStateInsert)
            .map_err(map_store_error)?;
        self.trip(SqliteFailpoint::BeforeCommit)
            .map_err(map_store_error)?;
        transaction.commit().map_err(service_unavailable)?;
        self.publish_revision_anchor(next.revision)
            .map_err(map_store_error)?;
        Ok(state)
    }
}

/// Mutable SQLite transaction whose changes remain private until `commit`.
pub struct SqliteWriteTransaction<'store> {
    store: &'store SqliteStore,
    context: AccessContext,
    expected_revision: StoreRevision,
    cancellation: CancellationToken,
    staged: Vec<StagedMutation>,
}

impl fmt::Debug for SqliteWriteTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteWriteTransaction")
            .field("context", &self.context)
            .field("expected_revision", &self.expected_revision)
            .field("staged", &self.staged.len())
            .finish()
    }
}

impl SqliteWriteTransaction<'_> {
    fn stage(&mut self, mutation: StagedMutation) -> Result<(), StoreError> {
        self.cancellation.check()?;
        self.staged.push(mutation);
        Ok(())
    }
}

impl WriteTransaction for SqliteWriteTransaction<'_> {
    fn stage_snapshot(&mut self, snapshot: SourceSnapshot) -> Result<(), StoreError> {
        validate(&snapshot)?;
        self.stage(StagedMutation::Snapshot(snapshot))
    }

    fn publish_atoms(
        &mut self,
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
    ) -> Result<(), StoreError> {
        if atoms.is_empty() {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        for atom in &atoms {
            validate(atom)?;
            if &atom.scope.tenant_id != self.context.tenant_id() {
                return Err(StoreError::new(StoreErrorCode::InvalidContext));
            }
        }
        for edge in &edges {
            validate(edge)?;
        }
        self.stage(StagedMutation::Atoms(atoms, edges))
    }

    fn put_bundle(&mut self, bundle: ContextBundle) -> Result<(), StoreError> {
        validate(&bundle)?;
        self.stage(StagedMutation::Bundle(bundle))
    }

    fn append_context_commit(&mut self, commit: ContextCommit) -> Result<(), StoreError> {
        validate(&commit)?;
        if commit.purpose != self.context.purpose() {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        self.stage(StagedMutation::ContextCommit(commit))
    }

    fn append_effect_event(&mut self, event: EffectJournalEvent) -> Result<(), StoreError> {
        validate(&event)?;
        self.stage(StagedMutation::EffectEvent(event))
    }

    fn put_effect_record(&mut self, record: EffectRecordEnvelope) -> Result<(), StoreError> {
        self.stage(StagedMutation::EffectRecord(record))
    }

    fn put_blob(&mut self, blob: BlobRecord) -> Result<(), StoreError> {
        if blob_digest(blob.bytes()) != blob.reference.digest.as_str() {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        self.stage(StagedMutation::Blob(blob))
    }

    fn enqueue_outbox(&mut self, message: OutboxMessage) -> Result<(), StoreError> {
        message.validate()?;
        self.stage(StagedMutation::Outbox(message))
    }

    fn commit(self, idempotency: Option<IdempotencyIdentity>) -> Result<CommitReceipt, StoreError> {
        self.cancellation.check()?;
        validate_staged_shape(&self.staged)?;
        let mut connection = self.store.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        self.store.trip(SqliteFailpoint::AfterBeginImmediate)?;
        let latest = load_state(&transaction, SnapshotSelection::Latest)?;
        if let Some(identity) = &idempotency
            && let Some((digest, receipt)) =
                latest
                    .tenants
                    .get(self.context.tenant_id())
                    .and_then(|tenant| {
                        tenant
                            .idempotency
                            .get(&(identity.scope.clone(), identity.key.clone()))
                    })
        {
            if digest != &identity.request_digest {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            return Ok(CommitReceipt {
                revision: receipt.revision,
                replayed: true,
            });
        }
        if latest.revision != self.expected_revision {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
        let revision = StoreRevision(
            latest
                .revision
                .0
                .checked_add(1)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?,
        );
        let mut next = latest;
        next.revision = revision;
        let tenant = next
            .tenants
            .entry(self.context.tenant_id().clone())
            .or_default();
        if self
            .staged
            .iter()
            .any(|mutation| matches!(mutation, StagedMutation::Blob(_)))
        {
            let repository = self
                .store
                .blob_repository
                .as_ref()
                .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
            for mutation in &self.staged {
                if let StagedMutation::Blob(blob) = mutation {
                    repository.put(self.context.tenant_id(), blob)?;
                }
            }
        }
        self.store.trip(SqliteFailpoint::AfterBlobPublication)?;
        for mutation in self.staged {
            apply_mutation(tenant, mutation, revision)?;
        }
        for blob in tenant.blobs.values_mut() {
            blob.bytes = None;
        }
        let receipt = CommitReceipt {
            revision,
            replayed: false,
        };
        if let Some(identity) = idempotency {
            tenant.idempotency.insert(
                (identity.scope, identity.key),
                (identity.request_digest, receipt),
            );
        }
        self.cancellation.check()?;
        if self.store.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(StoreError::new(StoreErrorCode::InjectedAbort));
        }
        let bytes = encode_state(&next)?;
        let checksum = state_checksum(&bytes);
        let sqlite_revision = sqlite_revision(revision)?;
        self.store.trip(SqliteFailpoint::BeforeStateInsert)?;
        transaction
            .execute(
                "INSERT INTO state_snapshots (revision, state, checksum) VALUES (?1, ?2, ?3)",
                params![sqlite_revision, bytes, checksum],
            )
            .map_err(unavailable)?;
        prune_state_snapshots(&transaction)?;
        self.store.trip(SqliteFailpoint::AfterStateInsert)?;
        self.store.trip(SqliteFailpoint::BeforeCommit)?;
        transaction.commit().map_err(unavailable)?;
        self.store.publish_revision_anchor(revision)?;
        Ok(receipt)
    }
}

fn configure(connection: &Connection) -> Result<(), StoreError> {
    if rusqlite::version_number() < 3_045_000 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    connection
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA cache_size = -32768;
             PRAGMA wal_autocheckpoint = 1000;
             PRAGMA temp_store = MEMORY;
             PRAGMA trusted_schema = OFF;
             PRAGMA secure_delete = ON;",
        )
        .map_err(unavailable)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let has_fts5 = connection
        .query_row(
            "SELECT sqlite_compileoption_used('ENABLE_FTS5')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?
        == 1;
    if !has_fts5 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let page_size = connection
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let page_count = connection
        .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let page_size_u64 =
        u64::try_from(page_size).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if page_size_u64 == 0 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let maximum_pages = MAX_SQLITE_DATABASE_BYTES / page_size_u64;
    let maximum_pages_i64 = i64::try_from(maximum_pages)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if page_count > maximum_pages_i64 {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    connection
        .pragma_update(None, "max_page_count", maximum_pages_i64)
        .map_err(unavailable)?;
    let configured_maximum = connection
        .query_row("PRAGMA max_page_count", [], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    if configured_maximum != maximum_pages_i64 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

fn prune_state_snapshots(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let maximum = i64::try_from(MAX_RETAINED_SQLITE_SNAPSHOTS)
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    transaction
        .execute(
            "DELETE FROM state_snapshots
             WHERE revision NOT IN (
                 SELECT revision FROM state_snapshots ORDER BY revision DESC LIMIT ?1
             )",
            params![maximum],
        )
        .map(|_deleted| ())
        .map_err(unavailable)
}

fn validate_projection_selector(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        Err(StoreError::new(StoreErrorCode::InvalidContext))
    } else {
        Ok(())
    }
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                sequence INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                checksum TEXT NOT NULL,
                applied_at_unix_nanos TEXT NOT NULL
            ) STRICT;",
        )
        .map_err(unavailable)?;
    let checksum = state_checksum(INITIAL_MIGRATION.as_bytes());
    let stored = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE sequence = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(unavailable)?;
    if let Some(stored) = stored {
        return if stored == checksum {
            Ok(())
        } else {
            Err(StoreError::new(StoreErrorCode::Unavailable))
        };
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(unavailable)?;
    transaction
        .execute_batch(INITIAL_MIGRATION)
        .map_err(unavailable)?;
    let applied_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
        .as_nanos()
        .to_string();
    transaction
        .execute(
            "INSERT INTO schema_migrations (sequence, name, checksum, applied_at_unix_nanos)
             VALUES (1, 'initial', ?1, ?2)",
            params![checksum, applied_at],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)
}

fn ensure_genesis(connection: &Connection) -> Result<(), StoreError> {
    let exists = connection
        .query_row("SELECT EXISTS(SELECT 1 FROM state_snapshots)", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(unavailable)?
        == 1;
    if exists {
        return Ok(());
    }
    let bytes = encode_state(&CommittedState::default())?;
    let checksum = state_checksum(&bytes);
    connection
        .execute(
            "INSERT INTO state_snapshots (revision, state, checksum) VALUES (0, ?1, ?2)",
            params![bytes, checksum],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn load_state(
    connection: &Connection,
    selection: SnapshotSelection,
) -> Result<CommittedState, StoreError> {
    let row = match selection {
        SnapshotSelection::Latest => connection
            .query_row(
                "SELECT state, checksum FROM state_snapshots ORDER BY revision DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional(),
        SnapshotSelection::Revision(revision) => connection
            .query_row(
                "SELECT state, checksum FROM state_snapshots WHERE revision = ?1",
                params![sqlite_revision(revision)?],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional(),
    }
    .map_err(unavailable)?
    .ok_or_else(|| StoreError::new(StoreErrorCode::NotFound))?;
    if state_checksum(&row.0) != row.1 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    decode_state(&row.0)
}

fn encode_state(state: &CommittedState) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    Ok(bytes)
}

fn encode_record<T: serde::Serialize>(record: &T) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(record, &mut bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    Ok(bytes)
}

const fn lifecycle_name(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Active => "active",
        Lifecycle::Superseded => "superseded",
        Lifecycle::Tombstoned => "tombstoned",
        Lifecycle::Quarantined => "quarantined",
    }
}

fn decode_state(bytes: &[u8]) -> Result<CommittedState, StoreError> {
    let mut state: CommittedState = ciborium::de::from_reader(bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    state.ensure_atom_indexes()?;
    Ok(state)
}

fn state_checksum(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn sqlite_revision(revision: StoreRevision) -> Result<i64, StoreError> {
    i64::try_from(revision.0).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn validate_staged_shape(staged: &[StagedMutation]) -> Result<(), StoreError> {
    if staged.is_empty()
        || (staged
            .iter()
            .any(|mutation| matches!(mutation, StagedMutation::Outbox(_)))
            && !staged
                .iter()
                .any(|mutation| !matches!(mutation, StagedMutation::Outbox(_))))
    {
        Err(StoreError::new(StoreErrorCode::InvalidRecord))
    } else {
        Ok(())
    }
}

fn unavailable(_error: rusqlite::Error) -> StoreError {
    StoreError::new(StoreErrorCode::Unavailable)
}

fn service_unavailable(_error: rusqlite::Error) -> ServiceError {
    ServiceError::new(ServiceErrorCode::Unavailable)
}

fn revision_anchor_path(database: &Path) -> Option<PathBuf> {
    if database == Path::new(":memory:") {
        return None;
    }
    let mut value = database.as_os_str().to_os_string();
    value.push(".cigar-revision");
    Some(PathBuf::from(value))
}

fn read_revision_anchor(path: &Path) -> Result<Option<StoreRevision>, StoreError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    let length = file
        .metadata()
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
        .len();
    if length > 256 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(length).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let mut lines = value.lines();
    if lines.next() != Some("CIGAR-REVISION-v1") {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let revision_text = lines
        .next()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    let checksum = lines
        .next()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    if lines.next().is_some() || checksum != revision_anchor_checksum(revision_text) {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let revision = revision_text
        .parse::<u64>()
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    Ok(Some(StoreRevision(revision)))
}

fn write_revision_anchor(path: &Path, revision: StoreRevision) -> Result<(), StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    fs::create_dir_all(parent).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let revision_text = revision.0.to_string();
    let bytes = format!(
        "CIGAR-REVISION-v1\n{revision_text}\n{}\n",
        revision_anchor_checksum(&revision_text)
    );
    let mut temporary = tempfile::Builder::new()
        .prefix(".cigar-revision-")
        .tempfile_in(parent)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    temporary
        .write_all(bytes.as_bytes())
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    temporary
        .persist(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    sync_parent_directory(parent)
}

fn revision_anchor_checksum(revision: &str) -> String {
    let mut bytes = b"CIGAR-REVISION-ANCHOR\0v1\0".to_vec();
    bytes.extend_from_slice(revision.as_bytes());
    state_checksum(&bytes)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

impl crate::conformance::ConformanceRepository for SqliteStore {
    fn inject_commit_abort(&self) {
        self.fail_next_commit();
    }
}

#[cfg(test)]
mod backup_lock_tests {
    use super::SqliteStore;
    use crate::{StoreError, StoreErrorCode, StoreRevision};
    use rusqlite::Connection;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    fn wait(flag: &AtomicBool) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !flag.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("timed out waiting for backup boundary").into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    #[test]
    fn consistent_backup_excludes_an_independent_sqlite_writer_through_blob_copy_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("metadata.sqlite3");
        let backup = directory.path().join("backup.sqlite3");
        let store = Arc::new(SqliteStore::open(&database)?);
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let backup_store = Arc::clone(&store);
        let backup_entered = Arc::clone(&entered);
        let backup_release = Arc::clone(&release);
        let backup_thread = std::thread::spawn(move || -> Result<StoreRevision, String> {
            backup_store
                .with_consistent_backup(&backup, |revision| -> Result<StoreRevision, StoreError> {
                    backup_entered.store(true, Ordering::Release);
                    while !backup_release.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Ok(revision)
                })
                .map_err(|error| error.to_string())
        });
        wait(&entered)?;

        let writer_finished = Arc::new(AtomicBool::new(false));
        let writer_flag = Arc::clone(&writer_finished);
        let writer_database = database.clone();
        let writer = std::thread::spawn(move || -> Result<(), String> {
            let connection =
                Connection::open(writer_database).map_err(|error| error.to_string())?;
            connection
                .busy_timeout(Duration::from_secs(5))
                .map_err(|error| error.to_string())?;
            connection
                .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                .map_err(|error| error.to_string())?;
            writer_flag.store(true, Ordering::Release);
            Ok(())
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(!writer_finished.load(Ordering::Acquire));

        release.store(true, Ordering::Release);
        let revision = backup_thread
            .join()
            .map_err(|_panic| std::io::Error::other("backup thread panicked"))?
            .map_err(std::io::Error::other)?;
        writer
            .join()
            .map_err(|_panic| std::io::Error::other("writer thread panicked"))?
            .map_err(std::io::Error::other)?;
        assert_eq!(revision, StoreRevision(0));
        assert!(writer_finished.load(Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn deep_integrity_is_content_free_and_rejects_a_forged_projection_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("metadata.sqlite3");
        let store = SqliteStore::open(&database)?;
        let report = store.deep_integrity_check()?;
        assert_eq!(report.revision, StoreRevision(0));
        assert_eq!(report.tenant_count, 0);
        assert_eq!(report.atom_count, 0);
        assert_eq!(report.projection_atom_count, 0);
        assert_eq!(report.effect_journal_event_count, 0);
        assert_eq!(report.effect_record_count, 0);
        assert_eq!(report.verified_effect_record_count, 0);
        assert_eq!(report.blob_reference_count, 0);
        assert_eq!(report.verified_blob_count, 0);
        assert_eq!(report.unknown_effect_count, 0);
        drop(store);

        Connection::open(&database)?.execute(
            "INSERT INTO atoms
             (tenant_id, version_id, lineage_id, lifecycle, exact_text, record)
             VALUES ('forged-tenant', 'forged-version', 'forged-lineage', 'active', '', x'00')",
            [],
        )?;
        let reopened = SqliteStore::open(&database)?;
        let error = match reopened.deep_integrity_check() {
            Ok(_report) => return Err("forged projection unexpectedly passed".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), StoreErrorCode::InvalidRecord);
        Ok(())
    }
}
