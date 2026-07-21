//! Durable SQLite repository with append-only, checksum-protected MVCC states.

use crate::memory::{
    BlobState, CommittedState, InMemoryReadTransaction, StagedMutation, TenantState,
    apply_mutation, blob_digest, validate,
};
use crate::model::{MAX_ATOM_BATCH_ITEMS, MAX_QUERY_PAGE_ITEMS};
use crate::service_repository::{
    EffectRecoveryPage, EffectRecoveryQuery, OutboxRecoveryPage, OutboxRecoveryQuery, ServiceBatch,
    ServiceBatchReceipt, ServiceError, ServiceErrorCode, ServiceIdempotencyEntry, ServiceListPage,
    ServiceListQuery, ServiceRecord, ServiceRecordLocator, ServiceRecordSelection,
    ServiceRepository, WorkerLocator, WorkerState, WorkerUpdate, apply_service_batch,
    apply_worker_update, check_cancellation, effect_recovery_from_state, map_store_error,
    outbox_recovery_from_state, service_get_from_state, service_list_from_state,
    validate_committed_service_state, worker_get_from_state,
};
use crate::{
    AccessContext, AtomCursor, AtomPage, AtomSelector, BlobRecord, CancellationToken,
    CommitReceipt, EffectRecordEnvelope, GarbageCollectionPolicy, IdempotencyIdentity,
    OutboxMessage, OutboxRecord, ReadTransaction, Repository, RepositoryCommitBytes,
    RepositoryCommitDurations, RepositoryCommitKind, RepositoryCommitMetrics,
    RepositoryCommitMetricsObserver, RepositoryCommitOutcome, RepositoryGarbageCollectionCandidate,
    RepositoryGarbageCollectionReport, RepositoryRetentionCounts, RepositoryStartupMetrics,
    RepositoryStartupMetricsObserver, RepositoryStartupOutcome, RepositoryStartupStage,
    SnapshotSelection, StoreError, StoreErrorCode, StoreRevision, WriteTransaction,
};
use crate::{
    MAX_MIGRATION_ENTRIES, MigrationCompatibility, MigrationDefinition, MigrationLedgerEntry,
    MigrationMode, MigrationPlan,
};
use cigar_protocol::{
    AtomKind, AtomPayload, BlobRef, ContentDigest, ContextAtomV1, ContextBundle, ContextCommit,
    ContextEdge, ContextSpaceId, EdgeKind, EffectJournalEvent, EffectState, IdempotencyKey,
    Lifecycle, LineageId, RecordId, SourceSnapshot, VersionId,
};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INITIAL_MIGRATION: &str = include_str!("../migrations/sqlite/0001_initial.sql");
const COMPATIBILITY_LEDGER_MIGRATION: &str =
    include_str!("../migrations/sqlite/0002_compatibility_ledger.sql");
const GENERATION_BOUND_ATOM_PROJECTION_MIGRATION: &str =
    include_str!("../migrations/sqlite/0003_generation_bound_atom_projection.sql");
const NORMALIZED_AUTHORITATIVE_CATALOG_MIGRATION: &str =
    include_str!("../migrations/sqlite/0004_normalized_authoritative_catalog.sql");
const APPLICATION_MAJOR: u16 = 1;
const GC_EXECUTION_MARKER_SCHEMA: &str = "CIGAR-GC-EXECUTION-v1";
const GC_EXECUTION_DIRECTORY: &str = ".cigar-gc-executions";
const MAX_GC_EXECUTION_MARKER_BYTES: u64 = 512;

fn gc_candidate_preview_is_exact_or_resumable(
    preview: &[RepositoryGarbageCollectionCandidate],
    planned: &[RepositoryGarbageCollectionCandidate],
    execution_started: bool,
) -> bool {
    if preview.windows(2).any(|pair| {
        pair.first().zip(pair.get(1)).is_none_or(|(left, right)| {
            (&left.tenant_id, &left.digest) >= (&right.tenant_id, &right.digest)
        })
    }) {
        return false;
    }

    let mut preview_index = 0_usize;
    let mut planned_index = 0_usize;
    let mut matched = 0_usize;
    while let (Some(actual), Some(expected)) =
        (preview.get(preview_index), planned.get(planned_index))
    {
        match (&actual.tenant_id, &actual.digest).cmp(&(&expected.tenant_id, &expected.digest)) {
            std::cmp::Ordering::Less => preview_index = preview_index.saturating_add(1),
            std::cmp::Ordering::Equal => {
                matched = matched.saturating_add(1);
                preview_index = preview_index.saturating_add(1);
                planned_index = planned_index.saturating_add(1);
            }
            std::cmp::Ordering::Greater => planned_index = planned_index.saturating_add(1),
        }
    }
    let signed_candidate_missing = matched < planned.len();
    if execution_started && signed_candidate_missing {
        // A prior run may have terminated after deleting only a prefix/subset. Exact deletion below
        // still receives only the signed candidates, so unrelated newly visible orphans are retained.
        true
    } else {
        preview == planned
    }
}

#[derive(Clone, Copy)]
struct SqliteMigrationSource {
    name: &'static str,
    sql: &'static str,
    minimum_application_major: u16,
    maximum_application_major: u16,
    mode: MigrationMode,
}

const SQLITE_MIGRATIONS: &[SqliteMigrationSource] = &[
    SqliteMigrationSource {
        name: "initial",
        sql: INITIAL_MIGRATION,
        minimum_application_major: 1,
        maximum_application_major: 1,
        mode: MigrationMode::Offline,
    },
    SqliteMigrationSource {
        name: "compatibility_ledger",
        sql: COMPATIBILITY_LEDGER_MIGRATION,
        minimum_application_major: 1,
        maximum_application_major: 2,
        mode: MigrationMode::Online,
    },
    SqliteMigrationSource {
        name: "generation_bound_atom_projection",
        sql: GENERATION_BOUND_ATOM_PROJECTION_MIGRATION,
        minimum_application_major: 1,
        maximum_application_major: 1,
        mode: MigrationMode::Offline,
    },
    SqliteMigrationSource {
        name: "normalized_authoritative_catalog",
        sql: NORMALIZED_AUTHORITATIVE_CATALOG_MIGRATION,
        minimum_application_major: 1,
        maximum_application_major: 1,
        mode: MigrationMode::Offline,
    },
];

/// Named durable boundaries in the append-only SQLite migration transaction protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteMigrationFailpoint {
    /// After the migration ledger exists and before its retained prefix is inspected.
    AfterLedgerBootstrap,
    /// After the exclusive transaction for this sequence begins.
    AfterTransactionBegin(u32),
    /// After the sequence DDL executes while rollback remains possible.
    AfterMigrationSql(u32),
    /// Immediately before inserting the immutable migration ledger row.
    BeforeLedgerInsert(u32),
    /// After inserting the ledger row while rollback remains possible.
    AfterLedgerInsert(u32),
    /// Immediately before committing DDL and its ledger row together.
    BeforeCommit(u32),
    /// After commit, modeling an ambiguous migrator outcome recovered on restart.
    AfterCommit(u32),
}
/// Maximum complete MVCC snapshots retained by the local profile.
pub const MAX_RETAINED_SQLITE_SNAPSHOTS: usize = 1_024;
/// Hard upper bound for the main local SQLite database file.
pub const MAX_SQLITE_DATABASE_BYTES: u64 = 4_294_967_296;
/// Hard database bound for the explicit native Apple-silicon large-local profile.
pub const MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES: u64 = 68_719_476_736;
/// Required available filesystem capacity before the large-local profile can be selected.
pub const MIN_LARGE_LOCAL_AVAILABLE_BYTES: u64 = 322_122_547_200;
/// Free-space reserve maintained on every large-local reopen.
pub const MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES: u64 = 17_179_869_184;
/// Maximum authoritative atoms in the explicit large-local profile.
pub const MAX_LARGE_LOCAL_ATOMS: u64 = 1_250_000;
/// Maximum authoritative edges in the explicit large-local profile.
pub const MAX_LARGE_LOCAL_EDGES: u64 = 12_500_000;
/// Maximum logical bytes referenced by atom blob payloads in the large-local profile.
pub const MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES: u64 = 137_438_953_472;
const _: () = {
    assert!(MIN_LARGE_LOCAL_AVAILABLE_BYTES > MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES);
    assert!(MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES < MIN_LARGE_LOCAL_AVAILABLE_BYTES);
};
/// Complete atom projection generations retained after one atomic activation.
pub const MAX_RETAINED_SQLITE_PROJECTION_GENERATIONS: usize = 2;
/// Hard bound on logically present atom rows in one local projection generation.
pub const MAX_SQLITE_PROJECTION_ATOMS: u64 = 10_000_000;
const MAX_STORED_SQLITE_PROJECTION_GENERATIONS: u64 = 16;
const MAX_SQLITE_PROJECTION_RECORD_BYTES: usize = 16_777_216;
const MAX_SQLITE_PROJECTION_TEXT_BYTES: usize = 16_777_216;
const MAX_SQLITE_PROJECTION_SELECTOR_BYTES: usize = 512;
const MAX_SQLITE_CATALOG_RECORD_BYTES: usize = 16_777_216;
const MAX_SQLITE_CATALOG_TEXT_BYTES: usize = 16_777_216;
const STANDARD_MAX_CATALOG_ATOMS: u64 = MAX_SQLITE_PROJECTION_ATOMS;
const STANDARD_MAX_CATALOG_EDGES: u64 = 10_000_000;
const STANDARD_MAX_REFERENCED_BLOB_BYTES: u64 = MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES;
const STANDARD_WAL_LIMIT_BYTES: i64 = 268_435_456;
const LARGE_LOCAL_WAL_LIMIT_BYTES: i64 = 8_589_934_592;

/// Closed local SQLite capacity selection. Large-local is opt-in and macOS arm64 only.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqliteCapacityProfile {
    /// Existing bounded 4 GiB local behavior.
    #[default]
    Standard,
    /// Explicit high-capacity single-node profile for the local scale envelope.
    LargeLocal,
}

impl SqliteCapacityProfile {
    fn from_name(value: &str) -> Option<Self> {
        match value {
            "standard" => Some(Self::Standard),
            "large_local" => Some(Self::LargeLocal),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LargeLocal => "large_local",
        }
    }

    const fn database_bytes(self) -> u64 {
        match self {
            Self::Standard => MAX_SQLITE_DATABASE_BYTES,
            Self::LargeLocal => MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES,
        }
    }

    const fn maximum_atoms(self) -> u64 {
        match self {
            Self::Standard => STANDARD_MAX_CATALOG_ATOMS,
            Self::LargeLocal => MAX_LARGE_LOCAL_ATOMS,
        }
    }

    const fn maximum_edges(self) -> u64 {
        match self {
            Self::Standard => STANDARD_MAX_CATALOG_EDGES,
            Self::LargeLocal => MAX_LARGE_LOCAL_EDGES,
        }
    }

    const fn maximum_referenced_blob_bytes(self) -> u64 {
        match self {
            Self::Standard => STANDARD_MAX_REFERENCED_BLOB_BYTES,
            Self::LargeLocal => MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES,
        }
    }

    const fn wal_limit_bytes(self) -> i64 {
        match self {
            Self::Standard => STANDARD_WAL_LIMIT_BYTES,
            Self::LargeLocal => LARGE_LOCAL_WAL_LIMIT_BYTES,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogFreeStateV4 {
    format_version: u8,
    revision: StoreRevision,
    tenants: BTreeMap<RecordId, CatalogFreeTenantStateV4>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogFreeTenantStateV4 {
    bundles: BTreeMap<VersionId, ContextBundle>,
    snapshots: BTreeMap<RecordId, SourceSnapshot>,
    context_commits: BTreeMap<ContextSpaceId, Vec<ContextCommit>>,
    effects: BTreeMap<RecordId, Vec<EffectJournalEvent>>,
    effect_records: BTreeMap<RecordId, EffectRecordEnvelope>,
    blobs: BTreeMap<ContentDigest, BlobState>,
    outbox: Vec<OutboxRecord>,
    idempotency: BTreeMap<(String, IdempotencyKey), (ContentDigest, CommitReceipt)>,
    service_records: BTreeMap<(String, String), Vec<ServiceRecord>>,
    service_idempotency: BTreeMap<(String, IdempotencyKey), ServiceIdempotencyEntry>,
    worker_states: BTreeMap<String, WorkerState>,
}

impl From<CommittedState> for CatalogFreeStateV4 {
    fn from(state: CommittedState) -> Self {
        Self {
            format_version: 4,
            revision: state.revision,
            tenants: state
                .tenants
                .into_iter()
                .map(|(tenant, state)| (tenant, state.into()))
                .collect(),
        }
    }
}

impl CatalogFreeStateV4 {
    fn from_state(state: &CommittedState) -> Self {
        Self {
            format_version: 4,
            revision: state.revision,
            tenants: state
                .tenants
                .iter()
                .map(|(tenant, state)| {
                    (
                        tenant.clone(),
                        CatalogFreeTenantStateV4::from_tenant_state(state),
                    )
                })
                .collect(),
        }
    }
}

impl From<CatalogFreeStateV4> for CommittedState {
    fn from(state: CatalogFreeStateV4) -> Self {
        Self {
            revision: state.revision,
            tenants: state
                .tenants
                .into_iter()
                .map(|(tenant, state)| (tenant, state.into()))
                .collect(),
        }
    }
}

impl From<TenantState> for CatalogFreeTenantStateV4 {
    fn from(state: TenantState) -> Self {
        Self {
            bundles: state.bundles,
            snapshots: state.snapshots,
            context_commits: state.context_commits,
            effects: state.effects,
            effect_records: state.effect_records,
            blobs: state.blobs,
            outbox: state.outbox,
            idempotency: state.idempotency,
            service_records: state.service_records,
            service_idempotency: state.service_idempotency,
            worker_states: state.worker_states,
        }
    }
}

impl CatalogFreeTenantStateV4 {
    fn from_tenant_state(state: &TenantState) -> Self {
        Self {
            bundles: state.bundles.clone(),
            snapshots: state.snapshots.clone(),
            context_commits: state.context_commits.clone(),
            effects: state.effects.clone(),
            effect_records: state.effect_records.clone(),
            blobs: state.blobs.clone(),
            outbox: state.outbox.clone(),
            idempotency: state.idempotency.clone(),
            service_records: state.service_records.clone(),
            service_idempotency: state.service_idempotency.clone(),
            worker_states: state.worker_states.clone(),
        }
    }
}

impl From<CatalogFreeTenantStateV4> for TenantState {
    fn from(state: CatalogFreeTenantStateV4) -> Self {
        Self {
            atoms: BTreeMap::new(),
            atom_versions_by_id: BTreeMap::new(),
            current_versions_by_lineage: BTreeMap::new(),
            edges: BTreeMap::new(),
            bundles: state.bundles,
            snapshots: state.snapshots,
            context_commits: state.context_commits,
            effects: state.effects,
            effect_records: state.effect_records,
            blobs: state.blobs,
            outbox: state.outbox,
            idempotency: state.idempotency,
            service_records: state.service_records,
            service_idempotency: state.service_idempotency,
            worker_states: state.worker_states,
        }
    }
}

#[derive(Clone)]
struct CatalogRevisionMetadata {
    revision: StoreRevision,
    residual_checksum: ContentDigest,
    catalog_root: ContentDigest,
    semantic_root: ContentDigest,
    semantic_root_format: u8,
    atom_count: u64,
    edge_count: u64,
    referenced_blob_bytes: u64,
}

/// Verified active local atom/FTS projection binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteProjectionStatus {
    /// Monotonic generation selected by the singleton activation pointer.
    pub generation: u64,
    /// Authoritative repository revision through which this generation was built.
    pub source_revision: StoreRevision,
    /// Digest of the exact authoritative state snapshot used by the build.
    pub state_checksum: ContentDigest,
    /// Exact atom rows verified in both the SQL and FTS projections.
    pub atom_count: u64,
    /// Domain-separated digest of the ordered generation rows.
    pub projection_root: ContentDigest,
}

/// Named one-shot SQLite projection build and activation boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SqliteProjectionFailpoint {
    /// After acquiring the immediate writer transaction and authoritative snapshot.
    AfterBeginImmediate,
    /// After reserving the incomplete generation metadata row.
    AfterGenerationReserved,
    /// After all SQL and FTS rows plus final generation metadata are staged.
    AfterRowsBuilt,
    /// After rereading and verifying the staged generation against authoritative state.
    AfterGenerationVerified,
    /// Immediately before replacing the singleton activation pointer.
    BeforeActivation,
    /// After replacing activation while rollback remains possible.
    AfterActivation,
    /// Immediately before committing generation rows and activation together.
    BeforeCommit,
    /// After commit, modeling an ambiguous client outcome recovered on restart.
    AfterCommit,
}

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

/// Content-free identity and exact logical totals of the latest authoritative catalog revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteCatalogStatistics {
    /// Latest committed repository revision represented by these measurements.
    pub revision: StoreRevision,
    /// Digest of all normalized authoritative catalog buckets at this revision.
    pub catalog_root: ContentDigest,
    /// Content-free root of the complete authoritative semantic state.
    pub semantic_root: ContentDigest,
    /// Exact number of immutable authoritative atom rows visible at this revision.
    pub atom_count: u64,
    /// Exact number of immutable authoritative edge rows visible at this revision.
    pub edge_count: u64,
    /// Exact logical plaintext bytes referenced by authoritative blob atoms.
    pub referenced_blob_bytes: u64,
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
    secure_identity: SecureSqliteIdentity,
    _runtime_lock: Option<File>,
    capacity_profile: SqliteCapacityProfile,
    fail_next_commit: AtomicBool,
    blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
    failpoints: Mutex<BTreeSet<SqliteFailpoint>>,
    projection_failpoints: Mutex<BTreeSet<SqliteProjectionFailpoint>>,
    revision_anchor: Option<PathBuf>,
    commit_metrics_observer: Option<Arc<dyn RepositoryCommitMetricsObserver>>,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteStore")
    }
}

impl SqliteStore {
    /// Opens or creates a database, verifies migrations, and initializes revision zero.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_capacity_profile(path, SqliteCapacityProfile::Standard)
    }

    /// Opens or creates a database while reporting every content-free startup stage.
    pub fn open_with_startup_metrics(
        path: impl AsRef<Path>,
        observer: Arc<dyn RepositoryStartupMetricsObserver>,
    ) -> Result<Self, StoreError> {
        Self::open_internal(
            path.as_ref(),
            None,
            SqliteCapacityProfile::Standard,
            Some(observer),
        )
    }

    /// Opens with one explicit bounded local capacity profile.
    pub fn open_with_capacity_profile(
        path: impl AsRef<Path>,
        capacity_profile: SqliteCapacityProfile,
    ) -> Result<Self, StoreError> {
        Self::open_internal(path.as_ref(), None, capacity_profile, None)
    }

    /// Opens a database composed with durable encrypted blob persistence.
    pub fn open_with_blob_repository(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
    ) -> Result<Self, StoreError> {
        Self::open_with_blob_repository_and_capacity_profile(
            path,
            blob_repository,
            SqliteCapacityProfile::Standard,
        )
    }

    /// Opens with durable encrypted blobs and an explicit bounded capacity profile.
    pub fn open_with_blob_repository_and_capacity_profile(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        capacity_profile: SqliteCapacityProfile,
    ) -> Result<Self, StoreError> {
        Self::open_internal(path.as_ref(), Some(blob_repository), capacity_profile, None)
    }

    /// Opens with encrypted blobs, a bounded capacity profile, and startup-stage observations.
    pub fn open_with_blob_repository_capacity_and_startup_metrics(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        capacity_profile: SqliteCapacityProfile,
        observer: Arc<dyn RepositoryStartupMetricsObserver>,
    ) -> Result<Self, StoreError> {
        Self::open_internal(
            path.as_ref(),
            Some(blob_repository),
            capacity_profile,
            Some(observer),
        )
    }

    /// Opens an existing database only long enough to preview one store-owned blob GC operation.
    ///
    /// Unlike normal startup, this entry point deliberately does not reconcile unreferenced
    /// objects before computing the GC plan. It cannot create a missing metadata database, and it
    /// does not expose a long-lived store whose startup reconciliation was skipped. The exact
    /// metadata mark set is derived while an immediate SQLite transaction excludes writers in this
    /// and other processes. Destructive use fails closed; deletion requires a verified signed plan.
    pub fn garbage_collect_at(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        Self::garbage_collect_at_with_capacity_profile(
            path,
            blob_repository,
            policy,
            dry_run,
            max_files,
            SqliteCapacityProfile::Standard,
        )
    }

    /// Capacity-profile-aware form of [`Self::garbage_collect_at`].
    pub fn garbage_collect_at_with_capacity_profile(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
        capacity_profile: SqliteCapacityProfile,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        let store = Self::open_internal_with_options(
            path.as_ref(),
            Some(blob_repository),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            false,
            capacity_profile,
            None,
        )?;
        store.garbage_collect_blob_roots(policy, dry_run, max_files)
    }

    /// Opens an existing database without reconciliation and derives one revision-bound GC plan.
    pub fn plan_garbage_collection_at(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        policy: GarbageCollectionPolicy,
        max_files: usize,
        created_at_unix_nanos: i128,
    ) -> Result<crate::GarbageCollectionPlan, StoreError> {
        Self::plan_garbage_collection_at_with_capacity_profile(
            path,
            blob_repository,
            policy,
            max_files,
            created_at_unix_nanos,
            SqliteCapacityProfile::Standard,
        )
    }

    /// Capacity-profile-aware form of [`Self::plan_garbage_collection_at`].
    pub fn plan_garbage_collection_at_with_capacity_profile(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        policy: GarbageCollectionPolicy,
        max_files: usize,
        created_at_unix_nanos: i128,
        capacity_profile: SqliteCapacityProfile,
    ) -> Result<crate::GarbageCollectionPlan, StoreError> {
        let store = Self::open_internal_with_options(
            path.as_ref(),
            Some(blob_repository),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            false,
            capacity_profile,
            None,
        )?;
        store.plan_garbage_collection_blob_roots(policy, max_files, created_at_unix_nanos)
    }

    /// Opens an existing database without reconciliation and executes one verified exact plan.
    pub fn run_garbage_collection_plan_at(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        verified: &crate::VerifiedGarbageCollectionPlan,
        dry_run: bool,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        Self::run_garbage_collection_plan_at_with_capacity_profile(
            path,
            blob_repository,
            verified,
            dry_run,
            SqliteCapacityProfile::Standard,
        )
    }

    /// Capacity-profile-aware form of [`Self::run_garbage_collection_plan_at`].
    pub fn run_garbage_collection_plan_at_with_capacity_profile(
        path: impl AsRef<Path>,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
        verified: &crate::VerifiedGarbageCollectionPlan,
        dry_run: bool,
        capacity_profile: SqliteCapacityProfile,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        let store = Self::open_internal_with_options(
            path.as_ref(),
            Some(blob_repository),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            false,
            capacity_profile,
            None,
        )?;
        store.run_garbage_collection_plan(verified, dry_run)
    }

    fn open_internal(
        path: &Path,
        blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
        capacity_profile: SqliteCapacityProfile,
        startup_observer: Option<Arc<dyn RepositoryStartupMetricsObserver>>,
    ) -> Result<Self, StoreError> {
        Self::open_internal_with_options(
            path,
            blob_repository,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            true,
            capacity_profile,
            startup_observer,
        )
    }

    /// Qualification-only process abort at one exact SQLite migration boundary.
    ///
    /// This API is available only with `migration-fault-injection`; it never creates a database
    /// and aborts the process when the requested boundary is reached.
    #[cfg(feature = "migration-fault-injection")]
    pub fn migrate_with_process_abort(
        path: impl AsRef<Path>,
        boundary: SqliteMigrationFailpoint,
    ) -> Result<(), StoreError> {
        let path = path.as_ref();
        let secure_identity = prepare_secure_sqlite_path(path, false)?;
        let _runtime_lock = acquire_sqlite_runtime_shared_lock(path)?;
        let mut connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(unavailable)?;
        verify_secure_sqlite_path(path, secure_identity)?;
        configure(&connection, SqliteCapacityProfile::Standard)?;
        migrate_with_observer(&mut connection, |observed| {
            if observed == boundary {
                std::process::abort();
            }
            Ok(())
        })?;
        Err(StoreError::new(StoreErrorCode::InvalidContext))
    }

    fn open_internal_with_options(
        path: &Path,
        blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
        flags: rusqlite::OpenFlags,
        reconcile_blobs: bool,
        capacity_profile: SqliteCapacityProfile,
        startup_observer: Option<Arc<dyn RepositoryStartupMetricsObserver>>,
    ) -> Result<Self, StoreError> {
        let observer = startup_observer.as_ref();
        let (secure_identity, runtime_lock) =
            measure_startup_stage(observer, RepositoryStartupStage::PathConfiguration, || {
                preflight_capacity_profile(path, capacity_profile)?;
                let secure_identity = prepare_secure_sqlite_path(
                    path,
                    flags.contains(rusqlite::OpenFlags::SQLITE_OPEN_CREATE),
                )?;
                let runtime_lock = acquire_sqlite_runtime_shared_lock(path)?;
                Ok((secure_identity, runtime_lock))
            })?;
        let mut connection = measure_startup_stage(
            observer,
            RepositoryStartupStage::SqliteOpenConfigure,
            || {
                let connection = Connection::open_with_flags(path, flags).map_err(unavailable)?;
                verify_secure_sqlite_path(path, secure_identity)?;
                configure(&connection, capacity_profile)?;
                Ok(connection)
            },
        )?;
        measure_startup_stage(observer, RepositoryStartupStage::MigrationLedger, || {
            migrate(&mut connection)?;
            activate_normalized_catalog(&mut connection, capacity_profile)
        })?;
        // Startup authenticates and decodes the latest bounded catalog-free residual before any
        // caller can observe the repository. Catalog rows remain stream-verified by the explicit
        // integrity pass, so this check does not reintroduce whole-graph startup hydration.
        let _ = load_residual_state_for_startup(&connection, path, secure_identity, observer)?;
        let store = Self {
            connection: Mutex::new(connection),
            database_path: path.to_path_buf(),
            secure_identity,
            _runtime_lock: runtime_lock,
            capacity_profile,
            fail_next_commit: AtomicBool::new(false),
            blob_repository,
            failpoints: Mutex::new(BTreeSet::new()),
            projection_failpoints: Mutex::new(BTreeSet::new()),
            revision_anchor: revision_anchor_path(path),
            commit_metrics_observer: None,
        };
        measure_startup_stage(observer, RepositoryStartupStage::RevisionAnchor, || {
            store.verify_or_advance_revision_anchor()
        })?;
        measure_startup_stage(observer, RepositoryStartupStage::CatalogProjection, || {
            store.recover_atom_projection()
        })?;
        if reconcile_blobs {
            measure_startup_stage(observer, RepositoryStartupStage::BlobReconciliation, || {
                store.reconcile_blobs()
            })?;
        }
        Ok(store)
    }

    /// Attaches one content-free observer before the store is shared with runtime workers.
    ///
    /// The observer receives successful commits and idempotent replays only. It cannot change the
    /// repository result and must not perform repository I/O.
    #[must_use]
    pub fn with_commit_metrics_observer(
        mut self,
        observer: Arc<dyn RepositoryCommitMetricsObserver>,
    ) -> Self {
        self.commit_metrics_observer = Some(observer);
        self
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

    /// Arms one named one-shot atom/FTS generation build failpoint.
    pub fn inject_projection_failpoint(
        &self,
        failpoint: SqliteProjectionFailpoint,
    ) -> Result<(), StoreError> {
        self.projection_failpoints
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
        Ok(load_catalog_revision_metadata(&connection, SnapshotSelection::Latest)?.revision)
    }

    /// Returns the explicitly bound local capacity profile.
    #[must_use]
    pub const fn capacity_profile(&self) -> SqliteCapacityProfile {
        self.capacity_profile
    }

    /// Proves whether the latest durable state contains no effect projection for any tenant.
    ///
    /// This global check exists for first-boot creation of a separate anti-rollback checkpoint;
    /// checking only currently configured tenants would miss records belonging to retired tenants.
    pub fn effect_store_is_empty(&self) -> Result<bool, StoreError> {
        let connection = self.lock()?;
        let state = load_residual_state(&connection, SnapshotSelection::Latest)?;
        Ok(state
            .tenants
            .values()
            .all(|tenant| tenant.effect_records.is_empty()))
    }

    /// Reads every latest protected effect envelope from an immutable backup database.
    ///
    /// This global inventory exists only to bind the separately permissioned monotonic effect
    /// checkpoint into backup completeness. Callers must already possess local backup authority;
    /// record bytes remain protected and must not be emitted to diagnostics.
    pub fn backup_effect_record_inventory_at(
        path: impl AsRef<Path>,
    ) -> Result<Vec<(RecordId, EffectRecordEnvelope)>, StoreError> {
        let connection =
            Connection::open_with_flags(path.as_ref(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(unavailable)?;
        let state = load_residual_state(&connection, SnapshotSelection::Latest)?;
        let mut inventory = Vec::new();
        for (tenant_id, tenant) in state.tenants {
            inventory.extend(
                tenant
                    .effect_records
                    .into_values()
                    .map(|envelope| (tenant_id.clone(), envelope)),
            );
        }
        Ok(inventory)
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
            .query_row(
                "SELECT COUNT(*) FROM cigar_repository_revisions_v4",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?;
        let latest_snapshot_bytes = connection
            .query_row(
                "SELECT length(residual_state) FROM cigar_repository_revisions_v4
                 ORDER BY revision DESC LIMIT 1",
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

    /// Opens an existing v5 target read-only and returns authenticated content-free retention state.
    ///
    /// This does not activate, migrate, compact, pin, or otherwise mutate the target. Ordinary v4
    /// databases fail closed because they do not contain authenticated v5 authority.
    pub fn v5_retention_statistics_at(
        path: impl AsRef<Path>,
    ) -> Result<crate::SqliteRetentionStatisticsV5, StoreError> {
        let path = path.as_ref();
        let secure_identity = prepare_secure_sqlite_path(path, false)?;
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(unavailable)?;
        verify_secure_sqlite_path(path, secure_identity)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(unavailable)?;
        if !connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(unavailable)?
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        crate::sqlite_v5::retention_statistics_v5(&connection)
    }

    /// Authenticates only the latest v5 checkpoint and its bounded delta suffix for readiness.
    ///
    /// Historical retained payloads are deliberately not scanned by this path. Use the explicit
    /// deep-integrity workflow when every retained checkpoint and delta must be authenticated.
    pub fn v5_bounded_startup_at(
        path: impl AsRef<Path>,
    ) -> Result<crate::SqliteStartupVerificationV5, StoreError> {
        let path = path.as_ref();
        let secure_identity = prepare_secure_sqlite_path(path, false)?;
        let _runtime_lock = acquire_sqlite_runtime_shared_lock(path)?;
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(unavailable)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(30))
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(unavailable)?;
        connection
            .pragma_update(None, "query_only", true)
            .map_err(unavailable)?;
        if !connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(unavailable)?
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let report = crate::sqlite_v5::bounded_startup_verification_v5(&connection)?;
        verify_secure_sqlite_path(path, secure_identity)?;
        Ok(report)
    }

    /// Authenticates the bounded v5 head, repairs only the current projection/anchor when needed,
    /// and repeats the bounded verification before returning a readiness-safe report.
    pub fn v5_recover_bounded_startup_at(
        path: impl AsRef<Path>,
    ) -> Result<crate::SqliteStartupVerificationV5, StoreError> {
        let path = path.as_ref();
        let secure_identity = prepare_secure_sqlite_path(path, false)?;
        let _runtime_lock = acquire_sqlite_runtime_shared_lock(path)?;
        let mut connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(unavailable)?;
        let capacity_profile = connection
            .query_row(
                "SELECT capacity_profile FROM repository_authority_v5
                 WHERE singleton = 1 AND format_version = 5 AND activated = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(unavailable)
            .and_then(|value| {
                SqliteCapacityProfile::from_name(&value)
                    .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))
            })?;
        configure(&connection, capacity_profile)?;
        verify_secure_sqlite_path(path, secure_identity)?;
        let report = crate::sqlite_v5::recover_bounded_startup_v5(&mut connection)?;
        let anchor = revision_anchor_path(path)
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
        match read_revision_anchor(&anchor)? {
            Some(revision) if revision.0 > report.current_revision.0 => {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            Some(revision) if revision == report.current_revision => {}
            _ => write_revision_anchor(&anchor, report.current_revision)?,
        }
        verify_secure_sqlite_path(path, secure_identity)?;
        Ok(report)
    }

    /// Returns the checksum-protected roots and exact logical totals persisted for the latest
    /// authoritative catalog revision.
    pub fn catalog_statistics(&self) -> Result<SqliteCatalogStatistics, StoreError> {
        let connection = self.lock()?;
        let metadata = load_catalog_revision_metadata(&connection, SnapshotSelection::Latest)?;
        if !matches!(metadata.semantic_root_format, 1 | 4) {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        Ok(SqliteCatalogStatistics {
            revision: metadata.revision,
            catalog_root: metadata.catalog_root,
            semantic_root: metadata.semantic_root,
            atom_count: metadata.atom_count,
            edge_count: metadata.edge_count,
            referenced_blob_bytes: metadata.referenced_blob_bytes,
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
        let state = load_residual_state(&connection, SnapshotSelection::Latest)?;
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
            let state = load_residual_state(&connection, SnapshotSelection::Latest)?;
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

    /// Returns a content-free canonical root of the latest authoritative semantic state.
    ///
    /// Disposable SQL/FTS projections and migration metadata are deliberately excluded. The root
    /// is therefore stable across a schema-only migration when the decoded repository state is
    /// unchanged.
    pub fn semantic_root(&self) -> Result<ContentDigest, StoreError> {
        let connection = self.lock()?;
        let metadata = load_catalog_revision_metadata(&connection, SnapshotSelection::Latest)?;
        if !matches!(metadata.semantic_root_format, 1 | 4) {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        Ok(metadata.semantic_root)
    }

    /// Reconciles the configured blob repository against exact current metadata roots.
    pub fn reconcile_blob_roots(&self) -> Result<(), StoreError> {
        if self.blob_repository.is_none() {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        self.reconcile_blobs()
    }

    /// Previews bounded blob GC using exact live roots from one locked latest snapshot.
    ///
    /// An immediate SQLite transaction remains held through physical selection/deletion. This
    /// prevents a concurrent writer in this or another process from publishing encrypted bytes
    /// before its metadata becomes visible to the mark set. Destructive calls fail closed so the
    /// verified-plan APIs are the only public deletion route.
    pub fn garbage_collect_blob_roots(
        &self,
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_files: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        if !dry_run {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let repository = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let state = load_residual_state(&transaction, SnapshotSelection::Latest)?;
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
        let report = repository.garbage_collect(&live, policy, true, max_files)?;
        transaction.commit().map_err(unavailable)?;
        Ok(report)
    }

    /// Selects an exact ordered GC candidate set at one locked repository revision.
    ///
    /// Selection is always non-destructive. The caller must sign the returned plan before it can
    /// be presented to [`Self::run_garbage_collection_plan`].
    pub fn plan_garbage_collection_blob_roots(
        &self,
        policy: GarbageCollectionPolicy,
        max_files: usize,
        created_at_unix_nanos: i128,
    ) -> Result<crate::GarbageCollectionPlan, StoreError> {
        let repository = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let state = load_residual_state(&transaction, SnapshotSelection::Latest)?;
        let revision = state.revision;
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
        let selection_policy = GarbageCollectionPolicy {
            retention_satisfied: true,
            legal_hold: false,
            backup_complete: true,
        };
        let report = repository.garbage_collect(&live, selection_policy, true, max_files)?;
        if report.deleted != 0 {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        let plan = crate::GarbageCollectionPlan::new(
            revision,
            created_at_unix_nanos,
            policy,
            max_files,
            report.eligible,
        )?;
        transaction.commit().map_err(unavailable)?;
        Ok(plan)
    }

    /// Executes only the exact candidate set authenticated by a verified, current plan.
    ///
    /// The repository revision and a fresh deterministic physical candidate preview must both
    /// equal the signed plan while the same immediate transaction excludes metadata writers. A
    /// retry carrying the exact durable database-and-plan execution marker may instead observe
    /// signed candidates already absent after an interrupted prior run; exact deletion still
    /// receives only the signed set, so newly visible orphans are retained.
    pub fn run_garbage_collection_plan(
        &self,
        verified: &crate::VerifiedGarbageCollectionPlan,
        dry_run: bool,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        let repository = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        let plan = verified.plan();
        let policy = plan.policy();
        if !dry_run && (!policy.retention_satisfied || policy.legal_hold || !policy.backup_complete)
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let selection_policy = GarbageCollectionPolicy {
            retention_satisfied: true,
            legal_hold: false,
            backup_complete: true,
        };
        let max_files = plan.maximum_candidates();
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let state = load_residual_state(&transaction, SnapshotSelection::Latest)?;
        if state.revision != plan.repository_revision() {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
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
        let (execution_marker, execution_marker_bytes) =
            garbage_collection_execution_marker(&self.database_path, plan)?;
        let execution_started =
            garbage_collection_execution_marker_exists(&execution_marker, &execution_marker_bytes)?;
        let preview = repository.garbage_collect(&live, selection_policy, true, max_files)?;
        if preview.deleted != 0
            || !gc_candidate_preview_is_exact_or_resumable(
                &preview.eligible,
                plan.candidates(),
                execution_started,
            )
        {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
        if !dry_run && !execution_started {
            publish_garbage_collection_execution_marker(
                &execution_marker,
                &execution_marker_bytes,
            )?;
        }
        let report = repository.garbage_collect_candidates(
            &crate::SharedGarbageCollectionAuthorization::new(),
            plan.candidates(),
            if dry_run { selection_policy } else { policy },
            dry_run,
            max_files,
        )?;
        let candidate_count = u64::try_from(plan.candidates().len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        if report.eligible != plan.candidates()
            || (dry_run && report.deleted != 0)
            || report.deleted > candidate_count
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
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
        let connection = self.lock()?;
        let status = active_projection_status(&connection)?;
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM atom_projection_rows
                 WHERE generation = ?1 AND tenant_id = ?2",
                params![projection_generation_i64(status.generation)?, tenant],
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
        let connection = self.lock()?;
        let status = active_projection_status(&connection)?;
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM atom_projection_rows
                    WHERE generation = ?1 AND tenant_id = ?2 AND version_id = ?3
                 )",
                params![
                    projection_generation_i64(status.generation)?,
                    tenant,
                    version
                ],
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
        self.rebuild_atom_projection_generation(cancellation)
            .map(|status| status.atom_count)
    }

    /// Rebuilds, verifies, and atomically activates one immutable projection generation.
    pub fn rebuild_atom_projection_generation(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SqliteProjectionStatus, StoreError> {
        self.rebuild_atom_projection_internal(cancellation, None)
    }

    /// Returns the active generation after fully verifying SQL/FTS parity and state binding.
    pub fn projection_status(&self) -> Result<SqliteProjectionStatus, StoreError> {
        let connection = self.lock()?;
        let (metadata, state_checksum) = authoritative_projection_state(&connection)?;
        verify_active_projection(&connection, &metadata, &state_checksum)
    }

    /// Qualification-only process-abort injection at one exact projection boundary.
    #[cfg(feature = "projection-fault-injection")]
    pub fn rebuild_atom_projection_with_process_abort(
        &self,
        cancellation: &CancellationToken,
        boundary: SqliteProjectionFailpoint,
    ) -> Result<SqliteProjectionStatus, StoreError> {
        self.rebuild_atom_projection_internal(cancellation, Some(boundary))
    }

    fn rebuild_atom_projection_internal(
        &self,
        cancellation: &CancellationToken,
        process_abort: Option<SqliteProjectionFailpoint>,
    ) -> Result<SqliteProjectionStatus, StoreError> {
        cancellation.check()?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let (metadata, state_checksum) = authoritative_projection_state(&transaction)?;
        self.projection_boundary(
            SqliteProjectionFailpoint::AfterBeginImmediate,
            process_abort,
        )?;
        let stored_generations = transaction
            .query_row(
                "SELECT COUNT(*) FROM atom_projection_generations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?;
        if stored_generations < 0
            || u64::try_from(stored_generations)
                .ok()
                .is_none_or(|count| count > MAX_STORED_SQLITE_PROJECTION_GENERATIONS)
        {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let maximum_generation = transaction
            .query_row(
                "SELECT MAX(generation) FROM atom_projection_generations",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(unavailable)?
            .unwrap_or(0);
        let generation = u64::try_from(maximum_generation)
            .ok()
            .and_then(|generation| generation.checked_add(1))
            .filter(|generation| *generation <= i64::MAX as u64)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let generation_i64 = projection_generation_i64(generation)?;
        let revision_i64 = sqlite_revision(metadata.revision)?;
        let created_at = unix_nanos_text()?;
        transaction
            .execute(
                "INSERT INTO atom_projection_generations
                   (generation, source_revision, state_checksum, atom_count,
                    projection_root, complete, created_at_unix_nanos)
                 VALUES (?1, ?2, ?3, 0, ?4, 0, ?5)",
                params![
                    generation_i64,
                    revision_i64,
                    state_checksum.as_str(),
                    empty_projection_root(),
                    created_at
                ],
            )
            .map_err(unavailable)?;
        self.projection_boundary(
            SqliteProjectionFailpoint::AfterGenerationReserved,
            process_abort,
        )?;

        let mut root = projection_root_builder(generation, metadata.revision, &state_checksum)?;
        let mut atom_count = 0_u64;
        {
            let mut row_statement = transaction
                .prepare(
                    "INSERT INTO atom_projection_rows
                       (generation, tenant_id, version_id, lineage_id, lifecycle,
                        exact_text, record, record_checksum)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .map_err(unavailable)?;
            let mut fts_statement = transaction
                .prepare(
                    "INSERT INTO atom_projection_fts
                       (generation, tenant_id, version_id, exact_text)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(unavailable)?;
            let mut authoritative = transaction
                .prepare(
                    "SELECT tenant_id, record, record_checksum, exact_text
                     FROM cigar_catalog_atoms WHERE published_revision <= ?1
                     ORDER BY tenant_id, version_id",
                )
                .map_err(unavailable)?;
            let mut authoritative_rows = authoritative
                .query(params![revision_i64])
                .map_err(unavailable)?;
            while let Some(row) = authoritative_rows.next().map_err(unavailable)? {
                cancellation.check()?;
                let tenant_id = row.get::<_, String>(0).map_err(unavailable)?;
                let record = row.get::<_, Vec<u8>>(1).map_err(unavailable)?;
                let record_checksum = row.get::<_, String>(2).map_err(unavailable)?;
                let exact_text = row.get::<_, String>(3).map_err(unavailable)?;
                let atom = decode_catalog_atom(&record, &record_checksum)?;
                if atom.scope.tenant_id.as_str() != tenant_id
                    || projection_exact_text(&atom) != exact_text
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
                validate_projection_payload_bounds(&exact_text, &record)?;
                update_projection_root(
                    &mut root,
                    &tenant_id,
                    &atom,
                    &exact_text,
                    &record_checksum,
                )?;
                row_statement
                    .execute(params![
                        generation_i64,
                        tenant_id,
                        atom.version_id.as_str(),
                        atom.lineage_id.as_str(),
                        lifecycle_name(atom.lifecycle),
                        exact_text,
                        record,
                        record_checksum,
                    ])
                    .map_err(unavailable)?;
                fts_statement
                    .execute(params![
                        generation_i64,
                        atom.scope.tenant_id.as_str(),
                        atom.version_id.as_str(),
                        projection_exact_text(&atom),
                    ])
                    .map_err(unavailable)?;
                atom_count = atom_count
                    .checked_add(1)
                    .filter(|count| *count <= MAX_SQLITE_PROJECTION_ATOMS)
                    .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            }
        }
        let projection_root = finish_projection_root(root)?;
        transaction
            .execute(
                "UPDATE atom_projection_generations
                 SET atom_count = ?2, projection_root = ?3, complete = 1
                 WHERE generation = ?1 AND complete = 0",
                params![
                    generation_i64,
                    projection_count_i64(atom_count)?,
                    projection_root.as_str()
                ],
            )
            .map_err(unavailable)?;
        self.projection_boundary(SqliteProjectionFailpoint::AfterRowsBuilt, process_abort)?;
        let status = SqliteProjectionStatus {
            generation,
            source_revision: metadata.revision,
            state_checksum: state_checksum.clone(),
            atom_count,
            projection_root,
        };
        verify_projection_generation(&transaction, &metadata, &status)?;
        self.projection_boundary(
            SqliteProjectionFailpoint::AfterGenerationVerified,
            process_abort,
        )?;
        self.projection_boundary(SqliteProjectionFailpoint::BeforeActivation, process_abort)?;
        transaction
            .execute(
                "INSERT INTO atom_projection_activation
                   (singleton, generation, source_revision, state_checksum, activated_at_unix_nanos)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(singleton) DO UPDATE SET
                   generation = excluded.generation,
                   source_revision = excluded.source_revision,
                   state_checksum = excluded.state_checksum,
                   activated_at_unix_nanos = excluded.activated_at_unix_nanos",
                params![
                    generation_i64,
                    revision_i64,
                    state_checksum.as_str(),
                    unix_nanos_text()?
                ],
            )
            .map_err(unavailable)?;
        self.projection_boundary(SqliteProjectionFailpoint::AfterActivation, process_abort)?;
        prune_projection_generations(&transaction)?;
        self.projection_boundary(SqliteProjectionFailpoint::BeforeCommit, process_abort)?;
        cancellation.check()?;
        transaction.commit().map_err(unavailable)?;
        self.projection_boundary(SqliteProjectionFailpoint::AfterCommit, process_abort)?;
        Ok(status)
    }

    fn projection_boundary(
        &self,
        boundary: SqliteProjectionFailpoint,
        process_abort: Option<SqliteProjectionFailpoint>,
    ) -> Result<(), StoreError> {
        self.trip_projection(boundary)?;
        #[cfg(feature = "projection-fault-injection")]
        if process_abort == Some(boundary) {
            std::process::abort();
        }
        #[cfg(not(feature = "projection-fault-injection"))]
        let _unused = process_abort;
        Ok(())
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
        let revision = load_catalog_revision_metadata(&transaction, SnapshotSelection::Latest)
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
        let state = load_residual_state(&connection, SnapshotSelection::Latest)?;
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

    fn recover_atom_projection(&self) -> Result<(), StoreError> {
        let recovery_required = {
            let connection = self.lock()?;
            let (metadata, state_checksum) = authoritative_projection_state(&connection)?;
            match verify_active_projection(&connection, &metadata, &state_checksum) {
                Ok(_status) => false,
                Err(error) if error.code() == StoreErrorCode::LimitExceeded => return Err(error),
                Err(_error) => true,
            }
        };
        if recovery_required {
            self.rebuild_atom_projection_generation(&CancellationToken::default())?;
        }
        Ok(())
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

    fn observe_commit(&self, metrics: RepositoryCommitMetrics) {
        if let Some(observer) = &self.commit_metrics_observer {
            observer.observe_repository_commit(metrics);
        }
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

    fn trip_projection(&self, failpoint: SqliteProjectionFailpoint) -> Result<(), StoreError> {
        if self
            .projection_failpoints
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
pub(crate) struct SecureSqliteIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Clone, Copy)]
pub(crate) struct SecureSqliteIdentity;

#[cfg(unix)]
pub(crate) fn prepare_secure_sqlite_path(
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
pub(crate) fn prepare_secure_sqlite_path(
    _path: &Path,
    _create: bool,
) -> Result<SecureSqliteIdentity, StoreError> {
    Ok(SecureSqliteIdentity)
}

#[cfg(unix)]
pub(crate) fn verify_secure_sqlite_path(
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

#[cfg(test)]
pub(crate) fn verify_secure_sqlite_identity_for_test(path: &Path) -> Result<(), StoreError> {
    let identity = prepare_secure_sqlite_path(path, false)?;
    verify_secure_sqlite_path(path, identity)
}

#[cfg(not(unix))]
pub(crate) fn verify_secure_sqlite_path(
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

fn sqlite_runtime_lock_path(database: &Path) -> Option<PathBuf> {
    if database == Path::new(":memory:") {
        return None;
    }
    let mut value = database.as_os_str().to_os_string();
    value.push(".cigar-runtime.lock");
    Some(PathBuf::from(value))
}

#[cfg(unix)]
fn open_secure_sqlite_runtime_lock(database: &Path) -> Result<Option<File>, StoreError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let Some(path) = sqlite_runtime_lock_path(database) else {
        return Ok(None);
    };
    let descriptor = rustix::fs::open(
        &path,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let descriptor_metadata = descriptor
        .metadata()
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let path_metadata = fs::symlink_metadata(&path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    for metadata in [&descriptor_metadata, &path_metadata] {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
    }
    if descriptor_metadata.dev() != path_metadata.dev()
        || descriptor_metadata.ino() != path_metadata.ino()
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(Some(descriptor))
}

#[cfg(not(unix))]
fn open_secure_sqlite_runtime_lock(_database: &Path) -> Result<Option<File>, StoreError> {
    Ok(None)
}

pub(crate) fn acquire_sqlite_runtime_shared_lock(
    database: &Path,
) -> Result<Option<File>, StoreError> {
    let descriptor = open_secure_sqlite_runtime_lock(database)?;
    #[cfg(unix)]
    if let Some(file) = descriptor.as_ref() {
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockShared)
            .map_err(|_error| StoreError::new(StoreErrorCode::RevisionConflict))?;
    }
    Ok(descriptor)
}

#[cfg(unix)]
pub(crate) fn acquire_sqlite_runtime_exclusive_lock(database: &Path) -> Result<File, StoreError> {
    let descriptor = open_secure_sqlite_runtime_lock(database)?
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    rustix::fs::flock(
        &descriptor,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|_error| StoreError::new(StoreErrorCode::RevisionConflict))?;
    Ok(descriptor)
}

#[cfg(not(unix))]
pub(crate) fn acquire_sqlite_runtime_exclusive_lock(_database: &Path) -> Result<File, StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

pub(crate) fn verify_sqlite_file(path: &Path) -> Result<(), StoreError> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    verify_connection(&connection)
}

pub(crate) struct AuthenticatedV4MigrationDatabase {
    pub(crate) capacity_profile: String,
    pub(crate) first_revision: StoreRevision,
    pub(crate) latest_revision: StoreRevision,
    pub(crate) retained_revisions: u64,
    pub(crate) residual_checksum: ContentDigest,
    pub(crate) catalog_root: ContentDigest,
    pub(crate) semantic_root: ContentDigest,
    pub(crate) atom_count: u64,
    pub(crate) edge_count: u64,
    pub(crate) referenced_blob_bytes: u64,
}

pub(crate) struct AuthenticatedV4MigrationRevision {
    pub(crate) state: CommittedState,
    pub(crate) residual_checksum: ContentDigest,
    pub(crate) catalog_root: ContentDigest,
    pub(crate) semantic_root: ContentDigest,
    pub(crate) atom_count: u64,
    pub(crate) edge_count: u64,
    pub(crate) referenced_blob_bytes: u64,
}

pub(crate) fn for_each_authenticated_v4_migration_revision(
    path: &Path,
    mut consume: impl FnMut(AuthenticatedV4MigrationRevision) -> Result<(), StoreError>,
) -> Result<u64, StoreError> {
    let secure_identity = prepare_secure_sqlite_path(path, false)?;
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    connection
        .execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED;")
        .map_err(unavailable)?;
    verify_migration_connection(&connection)?;
    let revisions = {
        let mut statement = connection
            .prepare("SELECT revision FROM cigar_repository_revisions_v4 ORDER BY revision")
            .map_err(unavailable)?;
        let rows = statement
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let mut revisions = Vec::new();
        for row in rows {
            if revisions.len() >= MAX_RETAINED_SQLITE_SNAPSHOTS {
                return Err(StoreError::new(StoreErrorCode::LimitExceeded));
            }
            revisions.push(
                u64::try_from(row.map_err(unavailable)?)
                    .map(StoreRevision)
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?,
            );
        }
        revisions
    };
    if revisions.is_empty()
        || revisions.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_none_or(|(left, right)| left.0.checked_add(1) != Some(right.0))
        })
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    for revision in revisions.iter().copied() {
        let metadata =
            load_catalog_revision_metadata(&connection, SnapshotSelection::Revision(revision))?;
        let state = load_residual_state(&connection, SnapshotSelection::Revision(revision))?;
        let (catalog_root, atom_count, edge_count, referenced_blob_bytes) =
            calculate_catalog_snapshot(&connection, revision, true)?;
        if state.revision != revision
            || catalog_root != metadata.catalog_root
            || atom_count != metadata.atom_count
            || edge_count != metadata.edge_count
            || referenced_blob_bytes != metadata.referenced_blob_bytes
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        consume(AuthenticatedV4MigrationRevision {
            state,
            residual_checksum: metadata.residual_checksum,
            catalog_root: metadata.catalog_root,
            semantic_root: metadata.semantic_root,
            atom_count,
            edge_count,
            referenced_blob_bytes,
        })?;
    }
    verify_secure_sqlite_path(path, secure_identity)?;
    u64::try_from(revisions.len()).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

pub(crate) fn verify_migrated_v5_catalog_history(
    connection: &Connection,
) -> Result<u64, StoreError> {
    let (first, last) = connection
        .query_row(
            "SELECT MIN(revision), MAX(revision) FROM repository_revisions_v5",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .map_err(unavailable)?;
    let first = first
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))
        .and_then(|value| {
            u64::try_from(value)
                .map(StoreRevision)
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
        })?;
    let last = last
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))
        .and_then(|value| {
            u64::try_from(value)
                .map(StoreRevision)
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
        })?;
    verify_migrated_v5_catalog_history_range(connection, first, last)
}

pub(crate) fn verify_migrated_v5_catalog_history_range(
    connection: &Connection,
    first: StoreRevision,
    last: StoreRevision,
) -> Result<u64, StoreError> {
    let expected = last
        .0
        .checked_sub(first.0)
        .and_then(|distance| distance.checked_add(1))
        .filter(|count| *count <= crate::sqlite_v5::MAXIMUM_RETAINED_REVISIONS_V5)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let mut statement = connection
        .prepare(
            "SELECT revision, catalog_root, atom_count, edge_count, referenced_blob_bytes
             FROM repository_revisions_v5 WHERE revision BETWEEN ?1 AND ?2 ORDER BY revision",
        )
        .map_err(unavailable)?;
    let rows = statement
        .query_map(
            params![sqlite_revision(first)?, sqlite_revision(last)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let mut checked = 0_u64;
    for row in rows {
        checked = checked
            .checked_add(1)
            .filter(|count| *count <= expected)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let row = row.map_err(unavailable)?;
        let revision = u64::try_from(row.0)
            .map(StoreRevision)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
        let expected_revision = first
            .0
            .checked_add(checked.saturating_sub(1))
            .map(StoreRevision)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let expected_root = ContentDigest::new(row.1)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
        let expected_atoms = catalog_count_u64(row.2)?;
        let expected_edges = catalog_count_u64(row.3)?;
        let expected_blob_bytes = catalog_count_u64(row.4)?;
        let (root, atoms, edges, blob_bytes) =
            calculate_catalog_snapshot(connection, revision, true)?;
        if revision != expected_revision
            || root != expected_root
            || atoms != expected_atoms
            || edges != expected_edges
            || blob_bytes != expected_blob_bytes
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
    }
    if checked != expected {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(checked)
}

pub(crate) fn verify_migrated_v5_latest_state_and_projection(
    connection: &Connection,
    expected: &CommittedState,
) -> Result<SqliteDeepIntegrityReport, StoreError> {
    let compatibility = load_residual_state(connection, SnapshotSelection::Latest)?;
    if &compatibility != expected {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    verify_latest_state_and_projections(connection, expected)
}

pub(crate) fn authenticate_v4_migration_database(
    path: &Path,
    require_revision_anchor: bool,
) -> Result<AuthenticatedV4MigrationDatabase, StoreError> {
    let secure_identity = prepare_secure_sqlite_path(path, false)?;
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(30))
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    connection
        .execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED;")
        .map_err(unavailable)?;
    verify_migration_connection(&connection)?;
    verify_connection(&connection)?;
    verify_all_v4_migration_revision_roots(&connection)?;
    let latest = load_catalog_revision_metadata(&connection, SnapshotSelection::Latest)?;
    let (first, retained) = connection
        .query_row(
            "SELECT MIN(revision), COUNT(*) FROM cigar_repository_revisions_v4",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(unavailable)?;
    let first = first
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))
        .and_then(|revision| {
            u64::try_from(revision)
                .map(StoreRevision)
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
        })?;
    let retained =
        u64::try_from(retained).map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    let contiguous = latest
        .revision
        .0
        .checked_sub(first.0)
        .and_then(|distance| distance.checked_add(1));
    if retained == 0 || contiguous != Some(retained) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let capacity_profile = connection
        .query_row(
            "SELECT capacity_profile FROM cigar_catalog_authority
             WHERE singleton = 1 AND format_version = 4 AND activated = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(unavailable)?;
    if require_revision_anchor {
        let anchor_path = revision_anchor_path(path)
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
        if read_revision_anchor(&anchor_path)? != Some(latest.revision) {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
    }
    verify_secure_sqlite_path(path, secure_identity)?;
    Ok(AuthenticatedV4MigrationDatabase {
        capacity_profile,
        first_revision: first,
        latest_revision: latest.revision,
        retained_revisions: retained,
        residual_checksum: latest.residual_checksum,
        catalog_root: latest.catalog_root,
        semantic_root: latest.semantic_root,
        atom_count: latest.atom_count,
        edge_count: latest.edge_count,
        referenced_blob_bytes: latest.referenced_blob_bytes,
    })
}

fn verify_all_v4_migration_revision_roots(connection: &Connection) -> Result<(), StoreError> {
    let mut statement = connection
        .prepare("SELECT revision FROM cigar_repository_revisions_v4 ORDER BY revision")
        .map_err(unavailable)?;
    let rows = statement
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(unavailable)?;
    let mut checked = 0_usize;
    for row in rows {
        checked = checked
            .checked_add(1)
            .filter(|count| *count <= MAX_RETAINED_SQLITE_SNAPSHOTS)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let revision = u64::try_from(row.map_err(unavailable)?)
            .map(StoreRevision)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
        let metadata =
            load_catalog_revision_metadata(connection, SnapshotSelection::Revision(revision))?;
        let (catalog_root, atom_count, edge_count, referenced_blob_bytes) =
            calculate_catalog_snapshot(connection, revision, true)?;
        if catalog_root != metadata.catalog_root
            || atom_count != metadata.atom_count
            || edge_count != metadata.edge_count
            || referenced_blob_bytes != metadata.referenced_blob_bytes
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
    }
    if checked == 0 {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(())
}

/// Returns the exact external blob set reachable from the latest checksum-protected snapshot.
pub(crate) fn backup_blob_references(
    path: &Path,
) -> Result<BTreeMap<RecordId, Vec<BlobRef>>, StoreError> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(unavailable)?;
    let state = load_residual_state(&connection, SnapshotSelection::Latest)?;
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
    let authority = connection
        .query_row(
            "SELECT format_version, capacity_profile, activated
             FROM cigar_catalog_authority WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?;
    let capacity_profile = authority
        .as_ref()
        .and_then(|(format, profile, activated)| {
            (*format == 4 && *activated == 1)
                .then(|| SqliteCapacityProfile::from_name(profile))
                .flatten()
        })
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    if connection
        .query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(unavailable)?
        != 0
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let mut statement = connection
        .prepare(
            "SELECT revision, residual_state, residual_checksum
             FROM cigar_repository_revisions_v4 ORDER BY revision",
        )
        .map_err(unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(unavailable)?;
    let mut revisions = 0_usize;
    let mut latest = None;
    for row in rows {
        let (revision, bytes, checksum) = row.map_err(unavailable)?;
        revisions = revisions
            .checked_add(1)
            .filter(|count| *count <= MAX_RETAINED_SQLITE_SNAPSHOTS)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        if state_checksum(&bytes) != checksum {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let state = decode_catalog_free_state(&bytes)?;
        if sqlite_revision(state.revision)? != revision {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        validate_committed_service_state(&state)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        let metadata = load_catalog_revision_metadata(
            connection,
            SnapshotSelection::Revision(state.revision),
        )?;
        if metadata.residual_checksum.as_str() != checksum {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        latest = Some(metadata);
    }
    let latest = latest.ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    enforce_catalog_capacity(&latest, capacity_profile)?;
    let (root, atoms, edges, referenced_blob_bytes) =
        calculate_catalog_snapshot(connection, latest.revision, true)?;
    if root != latest.catalog_root
        || atoms != latest.atom_count
        || edges != latest.edge_count
        || referenced_blob_bytes != latest.referenced_blob_bytes
        || catalog_root_from_table(connection)? != root
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |_row| Ok(()))
        .optional()
        .map_err(unavailable)?;
    if foreign_key_violation.is_some() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    verify_catalog_lineage_heads(connection, latest.revision)?;
    Ok(())
}

fn verify_catalog_lineage_heads(
    connection: &Connection,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    let revision_i64 = sqlite_revision(revision)?;
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, lineage_id, record, record_checksum
             FROM cigar_catalog_atoms WHERE published_revision <= ?1
             ORDER BY tenant_id, lineage_id, version_id",
        )
        .map_err(unavailable)?;
    let mut rows = statement
        .query(params![revision_i64])
        .map_err(unavailable)?;
    let mut current: Option<(String, String, ContextAtomV1)> = None;
    let mut lineage_count = 0_u64;
    while let Some(row) = rows.next().map_err(unavailable)? {
        let tenant = row.get::<_, String>(0).map_err(unavailable)?;
        let lineage = row.get::<_, String>(1).map_err(unavailable)?;
        let record = row.get::<_, Vec<u8>>(2).map_err(unavailable)?;
        let checksum = row.get::<_, String>(3).map_err(unavailable)?;
        let atom = decode_catalog_atom(&record, &checksum)?;
        if atom.scope.tenant_id.as_str() != tenant || atom.lineage_id.as_str() != lineage {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        match current.as_mut() {
            Some((current_tenant, current_lineage, best))
                if current_tenant == &tenant && current_lineage == &lineage =>
            {
                if (atom.temporal.observed_at, &atom.version_id)
                    > (best.temporal.observed_at, &best.version_id)
                {
                    *best = atom;
                }
            }
            Some(_) => {
                let (current_tenant, current_lineage, best) = current
                    .replace((tenant, lineage, atom))
                    .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
                verify_catalog_lineage_head(
                    connection,
                    &current_tenant,
                    &current_lineage,
                    &best.version_id,
                    revision_i64,
                )?;
                lineage_count = lineage_count
                    .checked_add(1)
                    .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            }
            None => current = Some((tenant, lineage, atom)),
        }
    }
    if let Some((tenant, lineage, best)) = current {
        verify_catalog_lineage_head(
            connection,
            &tenant,
            &lineage,
            &best.version_id,
            revision_i64,
        )?;
        lineage_count = lineage_count
            .checked_add(1)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    }
    let visible_heads = connection
        .query_row(
            "SELECT COUNT(*) FROM cigar_catalog_lineage_heads
             WHERE valid_from_revision <= ?1
               AND (valid_to_revision IS NULL OR valid_to_revision > ?1)",
            params![revision_i64],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?;
    if catalog_count_u64(visible_heads)? != lineage_count {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(())
}

fn verify_catalog_lineage_head(
    connection: &Connection,
    tenant: &str,
    lineage: &str,
    version: &VersionId,
    revision: i64,
) -> Result<(), StoreError> {
    let stored = connection
        .query_row(
            "SELECT version_id FROM cigar_catalog_lineage_heads
             WHERE tenant_id = ?1 AND lineage_id = ?2
               AND valid_from_revision <= ?3
               AND (valid_to_revision IS NULL OR valid_to_revision > ?3)",
            params![tenant, lineage, revision],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(unavailable)?;
    if stored.as_deref() != Some(version.as_str()) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(())
}

fn verify_migration_connection(connection: &Connection) -> Result<(), StoreError> {
    let plan = sqlite_migration_plan()?;
    let installed = load_sqlite_migration_ledger(connection)?;
    match plan
        .check_installed(&installed, APPLICATION_MAJOR)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
    {
        MigrationCompatibility::Exact => Ok(()),
        MigrationCompatibility::UpgradeRequired { .. } => {
            Err(StoreError::new(StoreErrorCode::Unavailable))
        }
    }
}

pub(crate) fn sqlite_migration_plan() -> Result<MigrationPlan, StoreError> {
    SQLITE_MIGRATIONS
        .iter()
        .enumerate()
        .map(|(index, migration)| {
            let sequence = u32::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            let checksum = ContentDigest::new(state_checksum(migration.sql.as_bytes()))
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
            Ok(MigrationDefinition {
                sequence,
                name: migration.name.to_owned(),
                checksum,
                minimum_application_major: migration.minimum_application_major,
                maximum_application_major: migration.maximum_application_major,
                mode: migration.mode,
                lock_behavior: "one bounded exclusive SQLite schema transaction".to_owned(),
                verification: "contiguous immutable ledger and semantic-root equality".to_owned(),
                rollback_or_restore: "restore the verified pre-migration backup".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(MigrationPlan::new)
}

fn load_sqlite_migration_ledger(
    connection: &Connection,
) -> Result<Vec<MigrationLedgerEntry>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence,
                    CASE WHEN typeof(name) = 'text' AND length(CAST(name AS BLOB)) BETWEEN 1 AND 256
                         THEN name ELSE NULL END,
                    CASE WHEN typeof(checksum) = 'text' AND length(CAST(checksum AS BLOB)) = 68
                         THEN checksum ELSE NULL END,
                    minimum_application_major, maximum_application_major, online
             FROM schema_migrations
             ORDER BY sequence
             LIMIT ?1",
        )
        .map_err(unavailable)?;
    let limit = i64::try_from(MAX_MIGRATION_ENTRIES)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let rows = statement
        .query_map(params![limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(unavailable)?;
    let mut installed = Vec::new();
    for row in rows {
        let (sequence, name, checksum, minimum, maximum, online) = row.map_err(unavailable)?;
        installed.push(MigrationLedgerEntry {
            sequence: u32::try_from(sequence)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            name,
            checksum: ContentDigest::new(checksum)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            minimum_application_major: u16::try_from(minimum)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            maximum_application_major: u16::try_from(maximum)
                .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
            online: match online {
                0 => false,
                1 => true,
                _ => return Err(StoreError::new(StoreErrorCode::Unavailable)),
            },
        });
        if installed.len() > MAX_MIGRATION_ENTRIES {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
    }
    Ok(installed)
}

fn verify_latest_state_and_projections(
    connection: &Connection,
    state: &CommittedState,
) -> Result<SqliteDeepIntegrityReport, StoreError> {
    let catalog_metadata =
        load_catalog_revision_metadata(connection, SnapshotSelection::Revision(state.revision))?;
    let projection_checksum = catalog_metadata.catalog_root.clone();
    verify_state_and_projections(connection, state, &catalog_metadata, &projection_checksum)
}

pub(crate) fn verify_v5_latest_state_and_projection(
    connection: &Connection,
    state: &CommittedState,
    state_digest: &ContentDigest,
    catalog_root: &ContentDigest,
    semantic_root: &ContentDigest,
    totals: crate::revision_delta::RepositoryLogicalTotalsV5,
) -> Result<SqliteDeepIntegrityReport, StoreError> {
    let catalog_metadata = CatalogRevisionMetadata {
        revision: state.revision,
        residual_checksum: state_digest.clone(),
        catalog_root: catalog_root.clone(),
        semantic_root: semantic_root.clone(),
        semantic_root_format: 5,
        atom_count: totals.atom_count,
        edge_count: totals.edge_count,
        referenced_blob_bytes: totals.referenced_blob_bytes,
    };
    verify_state_and_projections(connection, state, &catalog_metadata, catalog_root)
}

pub(crate) fn recover_v5_latest_projection(
    connection: &mut Connection,
    state: &CommittedState,
    state_digest: &ContentDigest,
    catalog_root: &ContentDigest,
    semantic_root: &ContentDigest,
    totals: crate::revision_delta::RepositoryLogicalTotalsV5,
) -> Result<SqliteProjectionStatus, StoreError> {
    let metadata = CatalogRevisionMetadata {
        revision: state.revision,
        residual_checksum: state_digest.clone(),
        catalog_root: catalog_root.clone(),
        semantic_root: semantic_root.clone(),
        semantic_root_format: 5,
        atom_count: totals.atom_count,
        edge_count: totals.edge_count,
        referenced_blob_bytes: totals.referenced_blob_bytes,
    };
    match verify_active_projection(connection, &metadata, catalog_root) {
        Ok(status) => return Ok(status),
        Err(error) if error.code() == StoreErrorCode::LimitExceeded => return Err(error),
        Err(_error) => {}
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let stored_generations = transaction
        .query_row(
            "SELECT COUNT(*) FROM atom_projection_generations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?;
    if stored_generations < 0
        || u64::try_from(stored_generations)
            .ok()
            .is_none_or(|count| count > MAX_STORED_SQLITE_PROJECTION_GENERATIONS)
    {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let maximum_generation = transaction
        .query_row(
            "SELECT MAX(generation) FROM atom_projection_generations",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(unavailable)?
        .unwrap_or(0);
    let generation = u64::try_from(maximum_generation)
        .ok()
        .and_then(|value| value.checked_add(1))
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let generation_i64 = projection_generation_i64(generation)?;
    let revision_i64 = sqlite_revision(metadata.revision)?;
    transaction
        .execute(
            "INSERT INTO atom_projection_generations
               (generation, source_revision, state_checksum, atom_count,
                projection_root, complete, created_at_unix_nanos)
             VALUES (?1, ?2, ?3, 0, ?4, 0, ?5)",
            params![
                generation_i64,
                revision_i64,
                catalog_root.as_str(),
                empty_projection_root(),
                unix_nanos_text()?
            ],
        )
        .map_err(unavailable)?;
    let mut root = projection_root_builder(generation, metadata.revision, catalog_root)?;
    let mut atom_count = 0_u64;
    {
        let mut row_statement = transaction
            .prepare(
                "INSERT INTO atom_projection_rows
                   (generation, tenant_id, version_id, lineage_id, lifecycle,
                    exact_text, record, record_checksum)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(unavailable)?;
        let mut fts_statement = transaction
            .prepare(
                "INSERT INTO atom_projection_fts
                   (generation, tenant_id, version_id, exact_text)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(unavailable)?;
        let mut authoritative = transaction
            .prepare(
                "SELECT tenant_id, record, record_checksum, exact_text
                 FROM cigar_catalog_atoms WHERE published_revision <= ?1
                 ORDER BY tenant_id, version_id",
            )
            .map_err(unavailable)?;
        let mut rows = authoritative
            .query(params![revision_i64])
            .map_err(unavailable)?;
        while let Some(row) = rows.next().map_err(unavailable)? {
            let tenant_id = row.get::<_, String>(0).map_err(unavailable)?;
            let record = row.get::<_, Vec<u8>>(1).map_err(unavailable)?;
            let record_checksum = row.get::<_, String>(2).map_err(unavailable)?;
            let exact_text = row.get::<_, String>(3).map_err(unavailable)?;
            let atom = decode_catalog_atom(&record, &record_checksum)?;
            if atom.scope.tenant_id.as_str() != tenant_id
                || projection_exact_text(&atom) != exact_text
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            validate_projection_payload_bounds(&exact_text, &record)?;
            update_projection_root(&mut root, &tenant_id, &atom, &exact_text, &record_checksum)?;
            row_statement
                .execute(params![
                    generation_i64,
                    tenant_id,
                    atom.version_id.as_str(),
                    atom.lineage_id.as_str(),
                    lifecycle_name(atom.lifecycle),
                    exact_text,
                    record,
                    record_checksum,
                ])
                .map_err(unavailable)?;
            fts_statement
                .execute(params![
                    generation_i64,
                    atom.scope.tenant_id.as_str(),
                    atom.version_id.as_str(),
                    projection_exact_text(&atom),
                ])
                .map_err(unavailable)?;
            atom_count = atom_count
                .checked_add(1)
                .filter(|count| *count <= MAX_SQLITE_PROJECTION_ATOMS)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        }
    }
    let projection_root = finish_projection_root(root)?;
    transaction
        .execute(
            "UPDATE atom_projection_generations
             SET atom_count = ?2, projection_root = ?3, complete = 1
             WHERE generation = ?1 AND complete = 0",
            params![
                generation_i64,
                projection_count_i64(atom_count)?,
                projection_root.as_str()
            ],
        )
        .map_err(unavailable)?;
    let status = SqliteProjectionStatus {
        generation,
        source_revision: metadata.revision,
        state_checksum: catalog_root.clone(),
        atom_count,
        projection_root,
    };
    verify_projection_generation(&transaction, &metadata, &status)?;
    transaction
        .execute(
            "INSERT INTO atom_projection_activation
               (singleton, generation, source_revision, state_checksum, activated_at_unix_nanos)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
               generation = excluded.generation,
               source_revision = excluded.source_revision,
               state_checksum = excluded.state_checksum,
               activated_at_unix_nanos = excluded.activated_at_unix_nanos",
            params![
                generation_i64,
                revision_i64,
                catalog_root.as_str(),
                unix_nanos_text()?
            ],
        )
        .map_err(unavailable)?;
    prune_projection_generations(&transaction)?;
    transaction.commit().map_err(unavailable)?;
    verify_active_projection(connection, &metadata, catalog_root)
}

fn verify_state_and_projections(
    connection: &Connection,
    state: &CommittedState,
    catalog_metadata: &CatalogRevisionMetadata,
    projection_checksum: &ContentDigest,
) -> Result<SqliteDeepIntegrityReport, StoreError> {
    let tenant_count = u64::try_from(state.tenants.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let atom_count = catalog_metadata.atom_count;
    let mut effect_journal_event_count = 0_u64;
    let mut effect_record_count = 0_u64;
    let mut blob_reference_count = 0_u64;
    let mut unknown_effect_count = 0_u64;

    for tenant in state.tenants.values() {
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

    let projection_atom_count =
        verify_active_projection(connection, catalog_metadata, projection_checksum)?.atom_count;
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

fn authoritative_projection_state(
    connection: &Connection,
) -> Result<(CatalogRevisionMetadata, ContentDigest), StoreError> {
    let metadata = load_catalog_revision_metadata(connection, SnapshotSelection::Latest)?;
    if metadata.atom_count > MAX_SQLITE_PROJECTION_ATOMS {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let checksum = metadata.catalog_root.clone();
    Ok((metadata, checksum))
}

fn active_projection_status(connection: &Connection) -> Result<SqliteProjectionStatus, StoreError> {
    let (metadata, state_checksum) = authoritative_projection_state(connection)?;
    load_active_projection_status(connection, metadata.revision, &state_checksum)
}

fn load_active_projection_status(
    connection: &Connection,
    expected_revision: StoreRevision,
    expected_state_checksum: &ContentDigest,
) -> Result<SqliteProjectionStatus, StoreError> {
    let stored_generations = connection
        .query_row(
            "SELECT COUNT(*) FROM atom_projection_generations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?;
    if stored_generations <= 0 {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    if u64::try_from(stored_generations)
        .ok()
        .is_none_or(|count| count > MAX_STORED_SQLITE_PROJECTION_GENERATIONS)
    {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let row = connection
        .query_row(
            "SELECT a.generation, a.source_revision,
                    CASE WHEN typeof(a.state_checksum) = 'text'
                                   AND length(CAST(a.state_checksum AS BLOB)) = 68
                         THEN a.state_checksum ELSE NULL END,
                    g.atom_count,
                    CASE WHEN typeof(g.projection_root) = 'text'
                                   AND length(CAST(g.projection_root AS BLOB)) = 68
                         THEN g.projection_root ELSE NULL END,
                    g.complete,
                    g.source_revision,
                    CASE WHEN typeof(g.state_checksum) = 'text'
                                   AND length(CAST(g.state_checksum AS BLOB)) = 68
                         THEN g.state_checksum ELSE NULL END
             FROM atom_projection_activation AS a
             JOIN atom_projection_generations AS g ON g.generation = a.generation
             WHERE a.singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let generation =
        u64::try_from(row.0).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let source_revision = StoreRevision(
        u64::try_from(row.1).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
    );
    let state_checksum =
        ContentDigest::new(row.2).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let atom_count =
        u64::try_from(row.3).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let projection_root =
        ContentDigest::new(row.4).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let generation_source_revision = StoreRevision(
        u64::try_from(row.6).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
    );
    let generation_state_checksum =
        ContentDigest::new(row.7).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if generation == 0
        || row.5 != 1
        || atom_count > MAX_SQLITE_PROJECTION_ATOMS
        || source_revision > expected_revision
        || state_checksum != *expected_state_checksum
        || generation_source_revision != source_revision
        || generation_state_checksum != state_checksum
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(SqliteProjectionStatus {
        generation,
        source_revision,
        state_checksum,
        atom_count,
        projection_root,
    })
}

fn verify_active_projection(
    connection: &Connection,
    metadata: &CatalogRevisionMetadata,
    state_checksum: &ContentDigest,
) -> Result<SqliteProjectionStatus, StoreError> {
    let status = load_active_projection_status(connection, metadata.revision, state_checksum)?;
    verify_projection_generation(connection, metadata, &status)?;
    Ok(status)
}

fn verify_projection_generation(
    connection: &Connection,
    metadata: &CatalogRevisionMetadata,
    status: &SqliteProjectionStatus,
) -> Result<(), StoreError> {
    let generation = projection_generation_i64(status.generation)?;
    let mut statement = connection
        .prepare(
            "SELECT CASE WHEN typeof(tenant_id) = 'text'
                                   AND length(CAST(tenant_id AS BLOB)) <= ?2
                         THEN tenant_id ELSE NULL END,
                    CASE WHEN typeof(version_id) = 'text'
                                   AND length(CAST(version_id AS BLOB)) <= ?2
                         THEN version_id ELSE NULL END,
                    CASE WHEN typeof(lineage_id) = 'text'
                                   AND length(CAST(lineage_id AS BLOB)) <= ?2
                         THEN lineage_id ELSE NULL END,
                    CASE WHEN typeof(lifecycle) = 'text'
                                   AND length(CAST(lifecycle AS BLOB)) <= ?2
                         THEN lifecycle ELSE NULL END,
                    CASE WHEN typeof(exact_text) = 'text'
                                   AND length(CAST(exact_text AS BLOB)) <= ?3
                         THEN exact_text ELSE NULL END,
                    CASE WHEN typeof(record) = 'blob' AND length(record) <= ?4
                         THEN record ELSE NULL END,
                    CASE WHEN typeof(record_checksum) = 'text'
                                   AND length(CAST(record_checksum AS BLOB)) = 68
                         THEN record_checksum ELSE NULL END
             FROM atom_projection_rows
             WHERE generation = ?1
             ORDER BY tenant_id, version_id",
        )
        .map_err(unavailable)?;
    let mut rows = statement
        .query_map(
            params![
                generation,
                i64::try_from(MAX_SQLITE_PROJECTION_SELECTOR_BYTES)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
                i64::try_from(MAX_SQLITE_PROJECTION_TEXT_BYTES)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
                i64::try_from(MAX_SQLITE_PROJECTION_RECORD_BYTES)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let mut count = 0_u64;
    let mut root = projection_root_builder(
        status.generation,
        status.source_revision,
        &status.state_checksum,
    )?;
    let mut authoritative_statement = connection
        .prepare(
            "SELECT tenant_id, record, record_checksum, exact_text
             FROM cigar_catalog_atoms WHERE published_revision <= ?1
             ORDER BY tenant_id, version_id",
        )
        .map_err(unavailable)?;
    let authoritative_rows = authoritative_statement
        .query_map(params![sqlite_revision(status.source_revision)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(unavailable)?;
    for authoritative in authoritative_rows {
        let (tenant_id, record, record_checksum, exact_text) =
            authoritative.map_err(unavailable)?;
        let atom = decode_catalog_atom(&record, &record_checksum)?;
        let row = rows
            .next()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?
            .map_err(unavailable)?;
        if atom.scope.tenant_id.as_str() != tenant_id
            || projection_exact_text(&atom) != exact_text
            || row.0 != tenant_id
            || row.1 != atom.version_id.as_str()
            || row.2 != atom.lineage_id.as_str()
            || row.3 != lifecycle_name(atom.lifecycle)
            || row.4 != exact_text
            || row.5 != record
            || row.6 != record_checksum
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        update_projection_root(&mut root, &tenant_id, &atom, &exact_text, &record_checksum)?;
        count = count
            .checked_add(1)
            .filter(|count| *count <= MAX_SQLITE_PROJECTION_ATOMS)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    }
    if rows.next().is_some() || count != status.atom_count || count != metadata.atom_count {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    if finish_projection_root(root)? != status.projection_root {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }

    let mut fts_statement = connection
        .prepare(
            "SELECT CASE WHEN typeof(tenant_id) = 'text'
                                   AND length(CAST(tenant_id AS BLOB)) <= ?2
                         THEN tenant_id ELSE NULL END,
                    CASE WHEN typeof(version_id) = 'text'
                                   AND length(CAST(version_id AS BLOB)) <= ?2
                         THEN version_id ELSE NULL END,
                    CASE WHEN typeof(exact_text) = 'text'
                                   AND length(CAST(exact_text AS BLOB)) <= ?3
                         THEN exact_text ELSE NULL END
             FROM atom_projection_fts
             WHERE generation = ?1
             ORDER BY tenant_id, version_id",
        )
        .map_err(unavailable)?;
    let mut fts_rows = fts_statement
        .query_map(
            params![
                generation,
                i64::try_from(MAX_SQLITE_PROJECTION_SELECTOR_BYTES)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
                i64::try_from(MAX_SQLITE_PROJECTION_TEXT_BYTES)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let mut authoritative_fts_statement = connection
        .prepare(
            "SELECT tenant_id, version_id, exact_text
             FROM cigar_catalog_atoms WHERE published_revision <= ?1
             ORDER BY tenant_id, version_id",
        )
        .map_err(unavailable)?;
    let authoritative_fts_rows = authoritative_fts_statement
        .query_map(params![sqlite_revision(status.source_revision)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(unavailable)?;
    for authoritative in authoritative_fts_rows {
        let authoritative = authoritative.map_err(unavailable)?;
        let row = fts_rows
            .next()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?
            .map_err(unavailable)?;
        if row != authoritative {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
    }
    if fts_rows.next().is_some() {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(())
}

fn projection_root_builder(
    generation: u64,
    source_revision: StoreRevision,
    state_checksum: &ContentDigest,
) -> Result<Sha256, StoreError> {
    let mut root = Sha256::new();
    root.update(b"CIGAR-SQLITE-ATOM-PROJECTION\0v1\0");
    root.update(generation.to_be_bytes());
    root.update(source_revision.0.to_be_bytes());
    projection_root_field(&mut root, state_checksum.as_str().as_bytes())?;
    Ok(root)
}

fn update_projection_root(
    root: &mut Sha256,
    tenant_id: &str,
    atom: &ContextAtomV1,
    exact_text: &str,
    record_checksum: &str,
) -> Result<(), StoreError> {
    for field in [
        tenant_id,
        atom.version_id.as_str(),
        atom.lineage_id.as_str(),
        lifecycle_name(atom.lifecycle),
        exact_text,
        record_checksum,
    ] {
        projection_root_field(root, field.as_bytes())?;
    }
    Ok(())
}

fn projection_root_field(root: &mut Sha256, bytes: &[u8]) -> Result<(), StoreError> {
    root.update(
        u64::try_from(bytes.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    root.update(bytes);
    Ok(())
}

fn finish_projection_root(root: Sha256) -> Result<ContentDigest, StoreError> {
    let digest = root.finalize();
    let mut encoded = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    }
    ContentDigest::new(encoded).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

fn empty_projection_root() -> String {
    format!("1220{}", "0".repeat(64))
}

fn projection_exact_text(atom: &ContextAtomV1) -> &str {
    match &atom.payload {
        AtomPayload::InlineText(text) => text.as_str(),
        AtomPayload::Structured(_) | AtomPayload::Blob(_) => "",
    }
}

fn validate_projection_payload_bounds(exact_text: &str, record: &[u8]) -> Result<(), StoreError> {
    if exact_text.len() > MAX_SQLITE_PROJECTION_TEXT_BYTES
        || record.len() > MAX_SQLITE_PROJECTION_RECORD_BYTES
    {
        Err(StoreError::new(StoreErrorCode::LimitExceeded))
    } else {
        Ok(())
    }
}

fn projection_generation_i64(generation: u64) -> Result<i64, StoreError> {
    i64::try_from(generation).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn projection_count_i64(count: u64) -> Result<i64, StoreError> {
    i64::try_from(count).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn unix_nanos_text() -> Result<String, StoreError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
        .as_nanos()
        .to_string())
}

fn prune_projection_generations(connection: &Connection) -> Result<(), StoreError> {
    let retained = i64::try_from(MAX_RETAINED_SQLITE_PROJECTION_GENERATIONS)
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    connection
        .execute(
            "DELETE FROM atom_projection_fts
             WHERE CAST(generation AS INTEGER) NOT IN (
                SELECT generation FROM atom_projection_generations
                ORDER BY generation DESC LIMIT ?1
             )",
            params![retained],
        )
        .map_err(unavailable)?;
    connection
        .execute(
            "DELETE FROM atom_projection_rows
             WHERE generation NOT IN (
                SELECT generation FROM atom_projection_generations
                ORDER BY generation DESC LIMIT ?1
             )",
            params![retained],
        )
        .map_err(unavailable)?;
    connection
        .execute(
            "DELETE FROM atom_projection_generations
             WHERE generation NOT IN (
                SELECT generation FROM atom_projection_generations
                ORDER BY generation DESC LIMIT ?1
             )",
            params![retained],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn increment_integrity_count(value: &mut u64) -> Result<(), StoreError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    Ok(())
}

/// Snapshot-pinned SQLite read transaction. Residual state remains bounded while catalog reads
/// are served directly from normalized indexes on this transaction's independent connection.
pub struct SqliteReadTransaction {
    connection: Connection,
    residual: InMemoryReadTransaction,
    revision: StoreRevision,
}

impl fmt::Debug for SqliteReadTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteReadTransaction")
            .field("revision", &self.revision)
            .field("context", &self.residual.context)
            .finish()
    }
}

impl SqliteReadTransaction {
    pub(crate) fn from_v5_state(
        connection: Connection,
        state: CommittedState,
        context: AccessContext,
        cancellation: CancellationToken,
        blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
    ) -> Self {
        let revision = state.revision;
        Self {
            connection,
            residual: InMemoryReadTransaction {
                state: Arc::new(state),
                context,
                cancellation,
                blob_repository,
            },
            revision,
        }
    }

    fn check(&self) -> Result<(), StoreError> {
        self.residual.cancellation.check()
    }

    fn atom_by_column(
        &self,
        column: &str,
        value: &str,
    ) -> Result<Option<ContextAtomV1>, StoreError> {
        self.check()?;
        let sql = format!(
            "SELECT record, record_checksum FROM cigar_catalog_atoms
             WHERE tenant_id = ?1 AND {column} = ?2 AND published_revision <= ?3"
        );
        let row = self
            .connection
            .query_row(
                &sql,
                params![
                    self.residual.context.tenant_id().as_str(),
                    value,
                    sqlite_revision(self.revision)?
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(unavailable)?;
        row.map(|(record, checksum)| decode_catalog_atom(&record, &checksum))
            .transpose()
    }
}

impl ReadTransaction for SqliteReadTransaction {
    fn revision(&self) -> StoreRevision {
        self.revision
    }

    fn get_atom(&self, version: &VersionId) -> Result<Option<ContextAtomV1>, StoreError> {
        self.atom_by_column("version_id", version.as_str())
    }

    fn get_atoms_by_id(
        &self,
        atom_ids: &[RecordId],
    ) -> Result<Vec<Option<ContextAtomV1>>, StoreError> {
        self.check()?;
        if atom_ids.len() > MAX_ATOM_BATCH_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut seen = BTreeSet::new();
        let mut result = Vec::with_capacity(atom_ids.len());
        for atom_id in atom_ids {
            self.check()?;
            if !seen.insert(atom_id) {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            result.push(self.atom_by_column("atom_id", atom_id.as_str())?);
        }
        Ok(result)
    }

    fn get_active_atom_by_id(
        &self,
        atom_id: &RecordId,
    ) -> Result<Option<ContextAtomV1>, StoreError> {
        self.check()?;
        let revision = sqlite_revision(self.revision)?;
        let row = self
            .connection
            .query_row(
                "SELECT atom.record, atom.record_checksum
                 FROM cigar_catalog_atoms AS atom
                 JOIN cigar_catalog_lineage_heads AS head
                   ON head.tenant_id = atom.tenant_id
                  AND head.lineage_id = atom.lineage_id
                  AND head.version_id = atom.version_id
                 WHERE atom.tenant_id = ?1 AND atom.atom_id = ?2
                   AND atom.lifecycle = 'active'
                   AND atom.published_revision <= ?3
                   AND head.valid_from_revision <= ?3
                   AND (head.valid_to_revision IS NULL OR head.valid_to_revision > ?3)",
                params![
                    self.residual.context.tenant_id().as_str(),
                    atom_id.as_str(),
                    revision
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(unavailable)?;
        row.map(|(record, checksum)| decode_catalog_atom(&record, &checksum))
            .transpose()
    }

    fn query_atoms(
        &self,
        selector: AtomSelector,
        limit: usize,
        cursor: Option<&AtomCursor>,
    ) -> Result<AtomPage, StoreError> {
        self.check()?;
        if limit == 0 || limit > MAX_QUERY_PAGE_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        if cursor.is_some_and(|cursor| cursor.revision != self.revision) {
            return Err(StoreError::new(StoreErrorCode::MixedSnapshot));
        }
        let after = cursor.map_or("", |cursor| cursor.last_version.as_str());
        let fetch = i64::try_from(limit.saturating_add(1))
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let mut records = Vec::with_capacity(limit.saturating_add(1));
        if let Some(kind) = selector.kind {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT record, record_checksum FROM cigar_catalog_atoms
                     WHERE tenant_id = ?1 AND version_id > ?2 AND kind = ?3
                       AND published_revision <= ?4
                     ORDER BY version_id LIMIT ?5",
                )
                .map_err(unavailable)?;
            let rows = statement
                .query_map(
                    params![
                        self.residual.context.tenant_id().as_str(),
                        after,
                        atom_kind_name(kind),
                        sqlite_revision(self.revision)?,
                        fetch
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(unavailable)?;
            for row in rows {
                self.check()?;
                let (record, checksum) = row.map_err(unavailable)?;
                records.push(decode_catalog_atom(&record, &checksum)?);
            }
        } else {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT record, record_checksum FROM cigar_catalog_atoms
                     WHERE tenant_id = ?1 AND version_id > ?2 AND published_revision <= ?3
                     ORDER BY version_id LIMIT ?4",
                )
                .map_err(unavailable)?;
            let rows = statement
                .query_map(
                    params![
                        self.residual.context.tenant_id().as_str(),
                        after,
                        sqlite_revision(self.revision)?,
                        fetch
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(unavailable)?;
            for row in rows {
                self.check()?;
                let (record, checksum) = row.map_err(unavailable)?;
                records.push(decode_catalog_atom(&record, &checksum)?);
            }
        }
        let has_more = records.len() > limit;
        if has_more {
            records.truncate(limit);
        }
        let next = if has_more {
            records.last().map(|atom| AtomCursor {
                revision: self.revision,
                last_version: atom.version_id.clone(),
            })
        } else {
            None
        };
        Ok(AtomPage {
            items: records,
            next,
        })
    }

    fn edges_from(
        &self,
        version: &VersionId,
        kind: Option<EdgeKind>,
        limit: usize,
    ) -> Result<Vec<ContextEdge>, StoreError> {
        self.check()?;
        if limit == 0 || limit > MAX_QUERY_PAGE_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let limit = i64::try_from(limit)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let mut records = Vec::new();
        if let Some(kind) = kind {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT record, record_checksum FROM cigar_catalog_edges
                     WHERE tenant_id = ?1 AND from_version = ?2 AND kind = ?3
                       AND published_revision <= ?4
                     ORDER BY edge_id LIMIT ?5",
                )
                .map_err(unavailable)?;
            let rows = statement
                .query_map(
                    params![
                        self.residual.context.tenant_id().as_str(),
                        version.as_str(),
                        edge_kind_name(kind),
                        sqlite_revision(self.revision)?,
                        limit
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(unavailable)?;
            for row in rows {
                self.check()?;
                let (record, checksum) = row.map_err(unavailable)?;
                records.push(decode_catalog_edge(&record, &checksum)?);
            }
        } else {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT record, record_checksum FROM cigar_catalog_edges
                     WHERE tenant_id = ?1 AND from_version = ?2 AND published_revision <= ?3
                     ORDER BY edge_id LIMIT ?4",
                )
                .map_err(unavailable)?;
            let rows = statement
                .query_map(
                    params![
                        self.residual.context.tenant_id().as_str(),
                        version.as_str(),
                        sqlite_revision(self.revision)?,
                        limit
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(unavailable)?;
            for row in rows {
                self.check()?;
                let (record, checksum) = row.map_err(unavailable)?;
                records.push(decode_catalog_edge(&record, &checksum)?);
            }
        }
        Ok(records)
    }

    fn get_bundle(&self, bundle: &VersionId) -> Result<Option<ContextBundle>, StoreError> {
        self.residual.get_bundle(bundle)
    }

    fn get_snapshot(&self, snapshot: &RecordId) -> Result<Option<SourceSnapshot>, StoreError> {
        self.residual.get_snapshot(snapshot)
    }

    fn context_commits(&self, space: &ContextSpaceId) -> Result<Vec<ContextCommit>, StoreError> {
        self.residual.context_commits(space)
    }

    fn get_effect(&self, effect: &RecordId) -> Result<Vec<EffectJournalEvent>, StoreError> {
        self.residual.get_effect(effect)
    }

    fn get_effect_record(
        &self,
        effect: &RecordId,
    ) -> Result<Option<EffectRecordEnvelope>, StoreError> {
        self.residual.get_effect_record(effect)
    }

    fn get_blob(&self, digest: &ContentDigest) -> Result<Option<BlobRecord>, StoreError> {
        self.residual.get_blob(digest)
    }

    fn outbox(&self) -> Result<Vec<OutboxRecord>, StoreError> {
        self.residual.outbox()
    }

    fn idempotent_result(
        &self,
        identity: &IdempotencyIdentity,
    ) -> Result<Option<CommitReceipt>, StoreError> {
        self.residual.idempotent_result(identity)
    }
}

impl Repository for SqliteStore {
    type Read<'store>
        = SqliteReadTransaction
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
        verify_secure_sqlite_path(&self.database_path, self.secure_identity)?;
        let connection = Connection::open_with_flags(
            &self.database_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(unavailable)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(30))
            .map_err(unavailable)?;
        connection
            .execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED;")
            .map_err(unavailable)?;
        let state = load_residual_state(&connection, selection)?;
        let revision = state.revision;
        verify_secure_sqlite_path(&self.database_path, self.secure_identity)?;
        Ok(SqliteReadTransaction {
            connection,
            residual: InMemoryReadTransaction {
                state: Arc::new(state),
                context,
                cancellation,
                blob_repository: self.blob_repository.clone(),
            },
            revision,
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
        let state =
            load_residual_state(&connection, SnapshotSelection::Latest).map_err(map_store_error)?;
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
        let state = load_residual_state(&connection, selection).map_err(map_store_error)?;
        service_list_from_state(&state, query)
    }

    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError> {
        let total_started = Instant::now();
        check_cancellation(cancellation)?;
        let logical_changed = batch.logical_bytes();
        let lock_started = Instant::now();
        let mut connection = self.lock().map_err(map_store_error)?;
        let lock_wait = lock_started.elapsed();
        let before = sqlite_commit_footprint(&connection, &self.database_path);
        let transaction_started = Instant::now();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(service_unavailable)?;
        self.trip(SqliteFailpoint::AfterBeginImmediate)
            .map_err(map_store_error)?;
        let load_started = Instant::now();
        let (latest, residual_decode) =
            load_residual_state_profiled(&transaction, SnapshotSelection::Latest)
                .map_err(map_store_error)?;
        let repository_load = load_started.elapsed().saturating_sub(residual_decode);
        let revision_before = latest.revision;
        let staged_mutation_started = Instant::now();
        let (next, receipt) = apply_service_batch(&latest, batch)?;
        let staged_mutation = staged_mutation_started.elapsed();
        if receipt.replayed {
            drop(transaction);
            let sqlite_transaction = transaction_started.elapsed();
            let after = sqlite_commit_footprint(&connection, &self.database_path);
            drop(connection);
            self.observe_commit(RepositoryCommitMetrics {
                kind: RepositoryCommitKind::Service,
                outcome: RepositoryCommitOutcome::Replayed,
                revision_before,
                revision_after: revision_before,
                receipt_only: false,
                durations: RepositoryCommitDurations {
                    total: total_started.elapsed(),
                    lock_wait,
                    repository_load,
                    residual_decode,
                    staged_mutation,
                    sqlite_transaction,
                    ..RepositoryCommitDurations::default()
                },
                bytes: RepositoryCommitBytes {
                    database_before: before.database_bytes,
                    database_after: after.database_bytes,
                    wal_before: before.wal_bytes,
                    wal_after: after.wal_bytes,
                    ..RepositoryCommitBytes::default()
                },
                retained: after.retained,
            });
            return Ok(receipt);
        }
        let next = next.ok_or_else(|| ServiceError::new(ServiceErrorCode::Unavailable))?;
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(ServiceErrorCode::InjectedAbort));
        }
        self.trip(SqliteFailpoint::BeforeStateInsert)
            .map_err(map_store_error)?;
        let persisted = persist_normalized_revision(&transaction, &next, self.capacity_profile)
            .map_err(map_store_error)?;
        self.trip(SqliteFailpoint::AfterStateInsert)
            .map_err(map_store_error)?;
        self.trip(SqliteFailpoint::BeforeCommit)
            .map_err(map_store_error)?;
        let commit_started = Instant::now();
        transaction.commit().map_err(service_unavailable)?;
        let commit_fsync = commit_started.elapsed();
        let sqlite_transaction = transaction_started.elapsed();
        let after = sqlite_commit_footprint(&connection, &self.database_path);
        let anchor_started = Instant::now();
        self.publish_revision_anchor(next.revision)
            .map_err(map_store_error)?;
        let revision_anchor = anchor_started.elapsed();
        drop(connection);
        self.observe_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Service,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before,
            revision_after: next.revision,
            receipt_only: logical_changed == 0,
            durations: RepositoryCommitDurations {
                total: total_started.elapsed(),
                lock_wait,
                repository_load,
                residual_decode,
                staged_mutation,
                delta_encode: Duration::ZERO,
                full_encode: persisted.full_encode,
                catalog_root: persisted.catalog_root,
                sqlite_transaction,
                commit_fsync,
                revision_anchor,
            },
            bytes: commit_bytes(logical_changed, persisted, before, after),
            retained: after.retained,
        });
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
        let state = load_residual_state(&connection, selection).map_err(map_store_error)?;
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
        let state = load_residual_state(&connection, selection).map_err(map_store_error)?;
        outbox_recovery_from_state(&state, query)
    }

    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError> {
        check_cancellation(cancellation)?;
        let connection = self.lock().map_err(map_store_error)?;
        let state =
            load_residual_state(&connection, SnapshotSelection::Latest).map_err(map_store_error)?;
        worker_get_from_state(&state, locator)
    }

    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError> {
        let total_started = Instant::now();
        check_cancellation(cancellation)?;
        let logical_changed = update.logical_bytes(locator);
        let lock_started = Instant::now();
        let mut connection = self.lock().map_err(map_store_error)?;
        let lock_wait = lock_started.elapsed();
        let before = sqlite_commit_footprint(&connection, &self.database_path);
        let transaction_started = Instant::now();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(service_unavailable)?;
        self.trip(SqliteFailpoint::AfterBeginImmediate)
            .map_err(map_store_error)?;
        let load_started = Instant::now();
        let (latest, residual_decode) =
            load_residual_state_profiled(&transaction, SnapshotSelection::Latest)
                .map_err(map_store_error)?;
        let repository_load = load_started.elapsed().saturating_sub(residual_decode);
        let revision_before = latest.revision;
        let staged_mutation_started = Instant::now();
        let (next, state) = apply_worker_update(&latest, locator, update)?;
        let staged_mutation = staged_mutation_started.elapsed();
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(ServiceErrorCode::InjectedAbort));
        }
        self.trip(SqliteFailpoint::BeforeStateInsert)
            .map_err(map_store_error)?;
        let persisted = persist_normalized_revision(&transaction, &next, self.capacity_profile)
            .map_err(map_store_error)?;
        self.trip(SqliteFailpoint::AfterStateInsert)
            .map_err(map_store_error)?;
        self.trip(SqliteFailpoint::BeforeCommit)
            .map_err(map_store_error)?;
        let commit_started = Instant::now();
        transaction.commit().map_err(service_unavailable)?;
        let commit_fsync = commit_started.elapsed();
        let sqlite_transaction = transaction_started.elapsed();
        let after = sqlite_commit_footprint(&connection, &self.database_path);
        let anchor_started = Instant::now();
        self.publish_revision_anchor(next.revision)
            .map_err(map_store_error)?;
        let revision_anchor = anchor_started.elapsed();
        drop(connection);
        self.observe_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Worker,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before,
            revision_after: next.revision,
            receipt_only: logical_changed == 0,
            durations: RepositoryCommitDurations {
                total: total_started.elapsed(),
                lock_wait,
                repository_load,
                residual_decode,
                staged_mutation,
                delta_encode: Duration::ZERO,
                full_encode: persisted.full_encode,
                catalog_root: persisted.catalog_root,
                sqlite_transaction,
                commit_fsync,
                revision_anchor,
            },
            bytes: commit_bytes(logical_changed, persisted, before, after),
            retained: after.retained,
        });
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
        let total_started = Instant::now();
        self.cancellation.check()?;
        validate_staged_shape(&self.staged)?;
        let logical_changed = staged_logical_bytes(&self.staged)?;
        let lock_started = Instant::now();
        let mut connection = self.store.lock()?;
        let lock_wait = lock_started.elapsed();
        let before = sqlite_commit_footprint(&connection, &self.store.database_path);
        let transaction_started = Instant::now();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        self.store.trip(SqliteFailpoint::AfterBeginImmediate)?;
        let load_started = Instant::now();
        let (latest, residual_decode) =
            load_residual_state_profiled(&transaction, SnapshotSelection::Latest)?;
        let repository_load = load_started.elapsed().saturating_sub(residual_decode);
        let revision_before = latest.revision;
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
            let replayed = CommitReceipt {
                revision: receipt.revision,
                replayed: true,
            };
            drop(transaction);
            let sqlite_transaction = transaction_started.elapsed();
            let after = sqlite_commit_footprint(&connection, &self.store.database_path);
            drop(connection);
            self.store.observe_commit(RepositoryCommitMetrics {
                kind: RepositoryCommitKind::Repository,
                outcome: RepositoryCommitOutcome::Replayed,
                revision_before,
                revision_after: revision_before,
                receipt_only: false,
                durations: RepositoryCommitDurations {
                    total: total_started.elapsed(),
                    lock_wait,
                    repository_load,
                    residual_decode,
                    sqlite_transaction,
                    ..RepositoryCommitDurations::default()
                },
                bytes: RepositoryCommitBytes {
                    database_before: before.database_bytes,
                    database_after: after.database_bytes,
                    wal_before: before.wal_bytes,
                    wal_after: after.wal_bytes,
                    ..RepositoryCommitBytes::default()
                },
                retained: after.retained,
            });
            return Ok(replayed);
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
        let tenant_id = self.context.tenant_id().clone();
        next.tenants.entry(tenant_id.clone()).or_default();
        let staged_mutation_started = Instant::now();
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
        let mut touched_buckets = BTreeSet::new();
        for mutation in self.staged {
            match mutation {
                StagedMutation::Atoms(atoms, edges) => {
                    touched_buckets.extend(apply_catalog_batch(
                        &transaction,
                        &tenant_id,
                        atoms,
                        edges,
                        revision,
                        &self.cancellation,
                    )?);
                }
                mutation => {
                    let tenant = next
                        .tenants
                        .get_mut(&tenant_id)
                        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
                    apply_mutation(tenant, mutation, revision)?;
                }
            }
        }
        let tenant = next
            .tenants
            .get_mut(&tenant_id)
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
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
        let staged_mutation = staged_mutation_started.elapsed();
        self.cancellation.check()?;
        if self.store.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(StoreError::new(StoreErrorCode::InjectedAbort));
        }
        let catalog_bucket_started = Instant::now();
        for bucket in touched_buckets {
            persist_catalog_bucket(&transaction, bucket, revision)?;
        }
        let catalog_bucket = catalog_bucket_started.elapsed();
        self.store.trip(SqliteFailpoint::BeforeStateInsert)?;
        let persisted =
            persist_normalized_revision(&transaction, &next, self.store.capacity_profile)?;
        self.store.trip(SqliteFailpoint::AfterStateInsert)?;
        self.store.trip(SqliteFailpoint::BeforeCommit)?;
        let commit_started = Instant::now();
        transaction.commit().map_err(unavailable)?;
        let commit_fsync = commit_started.elapsed();
        let sqlite_transaction = transaction_started.elapsed();
        let after = sqlite_commit_footprint(&connection, &self.store.database_path);
        let anchor_started = Instant::now();
        self.store.publish_revision_anchor(revision)?;
        let revision_anchor = anchor_started.elapsed();
        drop(connection);
        self.store.observe_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Repository,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before,
            revision_after: revision,
            receipt_only: logical_changed == 0,
            durations: RepositoryCommitDurations {
                total: total_started.elapsed(),
                lock_wait,
                repository_load,
                residual_decode,
                staged_mutation,
                delta_encode: Duration::ZERO,
                full_encode: persisted.full_encode,
                catalog_root: catalog_bucket.saturating_add(persisted.catalog_root),
                sqlite_transaction,
                commit_fsync,
                revision_anchor,
            },
            bytes: commit_bytes(logical_changed, persisted, before, after),
            retained: after.retained,
        });
        Ok(receipt)
    }
}

pub(crate) fn apply_catalog_batch(
    connection: &Connection,
    tenant_id: &RecordId,
    atoms: Vec<ContextAtomV1>,
    edges: Vec<ContextEdge>,
    revision: StoreRevision,
    cancellation: &CancellationToken,
) -> Result<BTreeSet<u16>, StoreError> {
    let mut touched_buckets = BTreeSet::new();
    let mut touched_lineages = BTreeSet::new();
    for atom in atoms {
        cancellation.check()?;
        if &atom.scope.tenant_id != tenant_id {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        touched_lineages.insert(atom.lineage_id.clone());
        touched_buckets.insert(insert_catalog_atom(connection, tenant_id, &atom, revision)?);
    }
    for lineage_id in touched_lineages {
        cancellation.check()?;
        let current =
            current_catalog_lineage_version(connection, tenant_id, &lineage_id, revision)?
                .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
        sync_lineage_head(connection, tenant_id, &lineage_id, &current, revision)?;
    }
    for edge in edges {
        cancellation.check()?;
        if !catalog_atom_exists(connection, tenant_id, &edge.from_version, revision)?
            || !catalog_atom_exists(connection, tenant_id, &edge.to_version, revision)?
            || creates_catalog_derivation_cycle(
                connection,
                tenant_id,
                &edge,
                revision,
                cancellation,
            )?
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        touched_buckets.insert(insert_catalog_edge(connection, tenant_id, &edge, revision)?);
    }
    Ok(touched_buckets)
}

fn catalog_atom_exists(
    connection: &Connection,
    tenant_id: &RecordId,
    version_id: &VersionId,
    revision: StoreRevision,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM cigar_catalog_atoms
                 WHERE tenant_id = ?1 AND version_id = ?2 AND published_revision <= ?3
             )",
            params![
                tenant_id.as_str(),
                version_id.as_str(),
                sqlite_revision(revision)?
            ],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value == 1)
        .map_err(unavailable)
}

fn current_catalog_lineage_version(
    connection: &Connection,
    tenant_id: &RecordId,
    lineage_id: &LineageId,
    revision: StoreRevision,
) -> Result<Option<VersionId>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT record, record_checksum FROM cigar_catalog_atoms
             WHERE tenant_id = ?1 AND lineage_id = ?2 AND published_revision <= ?3
             ORDER BY version_id",
        )
        .map_err(unavailable)?;
    let rows = statement
        .query_map(
            params![
                tenant_id.as_str(),
                lineage_id.as_str(),
                sqlite_revision(revision)?
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(unavailable)?;
    let mut current: Option<ContextAtomV1> = None;
    for row in rows {
        let (record, checksum) = row.map_err(unavailable)?;
        let atom = decode_catalog_atom(&record, &checksum)?;
        if &atom.scope.tenant_id != tenant_id || &atom.lineage_id != lineage_id {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        if current.as_ref().is_none_or(|existing| {
            (atom.temporal.observed_at, &atom.version_id)
                > (existing.temporal.observed_at, &existing.version_id)
        }) {
            current = Some(atom);
        }
    }
    Ok(current.map(|atom| atom.version_id))
}

fn creates_catalog_derivation_cycle(
    connection: &Connection,
    tenant_id: &RecordId,
    candidate: &ContextEdge,
    revision: StoreRevision,
    cancellation: &CancellationToken,
) -> Result<bool, StoreError> {
    if candidate.kind != EdgeKind::DerivedFrom {
        return Ok(false);
    }
    let mut pending = vec![candidate.to_version.clone()];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        cancellation.check()?;
        if current == candidate.from_version {
            return Ok(true);
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        if visited.len() > 100_000 {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut statement = connection
            .prepare(
                "SELECT record, record_checksum FROM cigar_catalog_edges
                 WHERE tenant_id = ?1 AND from_version = ?2 AND kind = 'derived_from'
                   AND published_revision <= ?3
                 ORDER BY edge_id",
            )
            .map_err(unavailable)?;
        let rows = statement
            .query_map(
                params![
                    tenant_id.as_str(),
                    current.as_str(),
                    sqlite_revision(revision)?
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(unavailable)?;
        for row in rows {
            let (record, checksum) = row.map_err(unavailable)?;
            let edge = decode_catalog_edge(&record, &checksum)?;
            if edge.kind != EdgeKind::DerivedFrom || edge.from_version != current {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            pending.push(edge.to_version);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PersistNormalizedRevisionMeasurement {
    full_state_bytes: u64,
    full_encode: Duration,
    catalog_root: Duration,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SqliteCommitFootprint {
    database_bytes: Option<u64>,
    wal_bytes: Option<u64>,
    retained: RepositoryRetentionCounts,
}

fn persist_normalized_revision(
    connection: &Connection,
    state: &CommittedState,
    capacity_profile: SqliteCapacityProfile,
) -> Result<PersistNormalizedRevisionMeasurement, StoreError> {
    if state.tenants.values().any(|tenant| {
        !tenant.atoms.is_empty()
            || !tenant.atom_versions_by_id.is_empty()
            || !tenant.current_versions_by_lineage.is_empty()
            || !tenant.edges.is_empty()
    }) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let catalog_root_started = Instant::now();
    let catalog_root = catalog_root_from_table(connection)?;
    let (atom_count, edge_count, referenced_blob_bytes) = connection
        .query_row(
            "SELECT COALESCE(SUM(atom_count), 0), COALESCE(SUM(edge_count), 0),
                    COALESCE(SUM(referenced_blob_bytes), 0)
             FROM cigar_catalog_root_buckets",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(unavailable)?;
    let atom_count = catalog_count_u64(atom_count)?;
    let edge_count = catalog_count_u64(edge_count)?;
    let referenced_blob_bytes = catalog_count_u64(referenced_blob_bytes)?;
    let mut catalog_root_elapsed = catalog_root_started.elapsed();
    let full_encode_started = Instant::now();
    let residual_state = encode_catalog_free_state(state)?;
    let full_encode = full_encode_started.elapsed();
    let full_state_bytes = u64::try_from(residual_state.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let root_finalize_started = Instant::now();
    let residual_checksum = ContentDigest::new(state_checksum(&residual_state))
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let semantic_root = normalized_semantic_root(
        state.revision,
        &residual_checksum,
        &catalog_root,
        atom_count,
        edge_count,
        referenced_blob_bytes,
    )?;
    let metadata = CatalogRevisionMetadata {
        revision: state.revision,
        residual_checksum: residual_checksum.clone(),
        catalog_root: catalog_root.clone(),
        semantic_root: semantic_root.clone(),
        semantic_root_format: 4,
        atom_count,
        edge_count,
        referenced_blob_bytes,
    };
    enforce_catalog_capacity(&metadata, capacity_profile)?;
    catalog_root_elapsed = catalog_root_elapsed.saturating_add(root_finalize_started.elapsed());
    connection
        .execute(
            "INSERT INTO cigar_repository_revisions_v4
               (revision, residual_state, residual_checksum, catalog_root, semantic_root,
                semantic_root_format, atom_count, edge_count, referenced_blob_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, 4, ?6, ?7, ?8)",
            params![
                sqlite_revision(state.revision)?,
                residual_state,
                residual_checksum.as_str(),
                catalog_root.as_str(),
                semantic_root.as_str(),
                catalog_count_i64(atom_count)?,
                catalog_count_i64(edge_count)?,
                catalog_count_i64(referenced_blob_bytes)?,
            ],
        )
        .map_err(unavailable)?;
    prune_normalized_revisions(connection)?;
    Ok(PersistNormalizedRevisionMeasurement {
        full_state_bytes,
        full_encode,
        catalog_root: catalog_root_elapsed,
    })
}

fn prune_normalized_revisions(connection: &Connection) -> Result<(), StoreError> {
    let maximum = i64::try_from(MAX_RETAINED_SQLITE_SNAPSHOTS)
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    connection
        .execute(
            "DELETE FROM cigar_repository_revisions_v4
             WHERE revision NOT IN (
                 SELECT revision FROM cigar_repository_revisions_v4
                 ORDER BY revision DESC LIMIT ?1
             )",
            params![maximum],
        )
        .map(|_deleted| ())
        .map_err(unavailable)
}

fn sqlite_commit_footprint(connection: &Connection, path: &Path) -> SqliteCommitFootprint {
    let full_states = connection
        .query_row(
            "SELECT COUNT(*) FROM cigar_repository_revisions_v4",
            [],
            |row| row.get::<_, i64>(0),
        )
        .ok()
        .and_then(|count| u64::try_from(count).ok());
    SqliteCommitFootprint {
        database_bytes: sqlite_file_bytes(path),
        wal_bytes: sqlite_file_bytes(&sqlite_sidecar_path(path, "-wal")),
        retained: RepositoryRetentionCounts {
            full_states,
            checkpoints: Some(0),
            deltas: Some(0),
        },
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn sqlite_file_bytes(path: &Path) -> Option<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Some(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(0),
        Err(_error) => None,
    }
}

pub(crate) fn staged_logical_bytes(staged: &[StagedMutation]) -> Result<u64, StoreError> {
    staged.iter().try_fold(0_u64, |total, mutation| {
        let bytes = match mutation {
            StagedMutation::Snapshot(record) => encode_record(record)?,
            StagedMutation::Atoms(atoms, edges) => encode_record(&(atoms, edges))?,
            StagedMutation::Bundle(record) => encode_record(record)?,
            StagedMutation::ContextCommit(record) => encode_record(record)?,
            StagedMutation::EffectEvent(record) => encode_record(record)?,
            StagedMutation::EffectRecord(record) => encode_record(record)?,
            StagedMutation::Blob(record) => encode_record(&record.reference)?,
            StagedMutation::Outbox(record) => encode_record(record)?,
        };
        let bytes = u64::try_from(bytes.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        total
            .checked_add(bytes)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))
    })
}

fn commit_bytes(
    logical_changed: u64,
    persisted: PersistNormalizedRevisionMeasurement,
    before: SqliteCommitFootprint,
    after: SqliteCommitFootprint,
) -> RepositoryCommitBytes {
    RepositoryCommitBytes {
        logical_changed,
        encoded_delta: 0,
        checkpoint: 0,
        full_state: persisted.full_state_bytes,
        database_before: before.database_bytes,
        database_after: after.database_bytes,
        wal_before: before.wal_bytes,
        wal_after: after.wal_bytes,
    }
}

pub(crate) fn measure_startup_stage<T>(
    observer: Option<&Arc<dyn RepositoryStartupMetricsObserver>>,
    stage: RepositoryStartupStage,
    operation: impl FnOnce() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let started = Instant::now();
    let result = operation();
    if let Some(observer) = observer {
        observer.observe_repository_startup(RepositoryStartupMetrics {
            stage,
            outcome: if result.is_ok() {
                RepositoryStartupOutcome::Completed
            } else {
                RepositoryStartupOutcome::Failed
            },
            duration: started.elapsed(),
        });
    }
    result
}

pub(crate) fn preflight_capacity_profile(
    path: &Path,
    capacity_profile: SqliteCapacityProfile,
) -> Result<(), StoreError> {
    if capacity_profile == SqliteCapacityProfile::Standard {
        return Ok(());
    }
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    let available = available_filesystem_bytes(path)?;
    if available < MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    Ok(())
}

#[cfg(unix)]
fn available_filesystem_bytes(path: &Path) -> Result<u64, StoreError> {
    let mut current = if path.exists() {
        path
    } else {
        path.parent()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?
    };
    while !current.exists() {
        current = current
            .parent()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
    }
    let statistics = rustix::fs::statvfs(current)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    statistics
        .f_bavail
        .checked_mul(statistics.f_frsize)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))
}

#[cfg(not(unix))]
fn available_filesystem_bytes(_path: &Path) -> Result<u64, StoreError> {
    Err(StoreError::new(StoreErrorCode::InvalidContext))
}

pub(crate) fn configure(
    connection: &Connection,
    capacity_profile: SqliteCapacityProfile,
) -> Result<(), StoreError> {
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
    connection
        .pragma_update(
            None,
            "journal_size_limit",
            capacity_profile.wal_limit_bytes(),
        )
        .map_err(unavailable)?;
    if capacity_profile == SqliteCapacityProfile::LargeLocal {
        connection
            .pragma_update(None, "cache_size", -131_072_i64)
            .map_err(unavailable)?;
    }
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
    let maximum_pages = capacity_profile.database_bytes() / page_size_u64;
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

fn validate_projection_selector(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        Err(StoreError::new(StoreErrorCode::InvalidContext))
    } else {
        Ok(())
    }
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    migrate_with_observer(connection, |_boundary| Ok(()))
}

fn migrate_with_observer(
    connection: &mut Connection,
    mut observe: impl FnMut(SqliteMigrationFailpoint) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
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
    observe(SqliteMigrationFailpoint::AfterLedgerBootstrap)?;

    for (index, migration) in SQLITE_MIGRATIONS.iter().enumerate() {
        let sequence = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let sequence_i64 = i64::from(sequence);
        let checksum = state_checksum(migration.sql.as_bytes());
        let stored = connection
            .query_row(
                "SELECT name, checksum FROM schema_migrations WHERE sequence = ?1",
                params![sequence_i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(unavailable)?;
        if let Some((stored_name, stored_checksum)) = stored {
            if stored_name != migration.name || stored_checksum != checksum {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
            continue;
        }
        let later_rows = connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE sequence > ?1",
                params![sequence_i64],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?;
        if later_rows != 0 {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(unavailable)?;
        observe(SqliteMigrationFailpoint::AfterTransactionBegin(sequence))?;
        transaction
            .execute_batch(migration.sql)
            .map_err(unavailable)?;
        observe(SqliteMigrationFailpoint::AfterMigrationSql(sequence))?;
        observe(SqliteMigrationFailpoint::BeforeLedgerInsert(sequence))?;
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
            .as_nanos()
            .to_string();
        if sequence == 1 {
            transaction
                .execute(
                    "INSERT INTO schema_migrations
                       (sequence, name, checksum, applied_at_unix_nanos)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![sequence_i64, migration.name, checksum, applied_at],
                )
                .map_err(unavailable)?;
        } else {
            transaction
                .execute(
                    "INSERT INTO schema_migrations
                       (sequence, name, checksum, applied_at_unix_nanos,
                        minimum_application_major, maximum_application_major, online)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        sequence_i64,
                        migration.name,
                        checksum,
                        applied_at,
                        i64::from(migration.minimum_application_major),
                        i64::from(migration.maximum_application_major),
                        matches!(migration.mode, MigrationMode::Online),
                    ],
                )
                .map_err(unavailable)?;
        }
        observe(SqliteMigrationFailpoint::AfterLedgerInsert(sequence))?;
        observe(SqliteMigrationFailpoint::BeforeCommit(sequence))?;
        transaction.commit().map_err(unavailable)?;
        observe(SqliteMigrationFailpoint::AfterCommit(sequence))?;
    }
    verify_migration_connection(connection)
}

#[derive(Clone)]
struct CatalogBucketState {
    atom_count: u64,
    edge_count: u64,
    referenced_blob_bytes: u64,
    atom_root: ContentDigest,
    edge_root: ContentDigest,
}

fn activate_normalized_catalog(
    connection: &mut Connection,
    capacity_profile: SqliteCapacityProfile,
) -> Result<(), StoreError> {
    let installed = connection
        .query_row(
            "SELECT format_version, capacity_profile, activated
             FROM cigar_catalog_authority WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?;
    if let Some((format, profile, activated)) = installed {
        if format != 4 || activated != 1 || profile != capacity_profile.name() {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let legacy_rows = connection
            .query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(unavailable)?;
        let revision_rows = connection
            .query_row(
                "SELECT COUNT(*) FROM cigar_repository_revisions_v4",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(unavailable)?;
        if legacy_rows != 0 || revision_rows == 0 {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        return Ok(());
    }

    let staged_rows = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM cigar_repository_revisions_v4) +
                 (SELECT COUNT(*) FROM cigar_catalog_atoms) +
                 (SELECT COUNT(*) FROM cigar_catalog_edges) +
                 (SELECT COUNT(*) FROM cigar_catalog_lineage_heads) +
                 (SELECT COUNT(*) FROM cigar_catalog_root_buckets)",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unavailable)?;
    if staged_rows != 0 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    if capacity_profile == SqliteCapacityProfile::LargeLocal
        && available_filesystem_bytes(Path::new(connection.path().unwrap_or(".")))?
            < MIN_LARGE_LOCAL_AVAILABLE_BYTES
    {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let legacy_revisions = {
        let mut statement = transaction
            .prepare("SELECT revision FROM state_snapshots ORDER BY revision")
            .map_err(unavailable)?;
        let rows = statement
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let mut revisions = Vec::new();
        for row in rows {
            if revisions.len() >= MAX_RETAINED_SQLITE_SNAPSHOTS {
                return Err(StoreError::new(StoreErrorCode::LimitExceeded));
            }
            revisions.push(row.map_err(unavailable)?);
        }
        revisions
    };

    if legacy_revisions.is_empty() {
        let state = CommittedState::default();
        backfill_normalized_revision(
            &transaction,
            &state,
            &state_checksum(&encode_state(&state)?),
        )?;
    } else {
        for legacy_revision in legacy_revisions {
            let (bytes, checksum) = transaction
                .query_row(
                    "SELECT state, checksum FROM state_snapshots WHERE revision = ?1",
                    params![legacy_revision],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(unavailable)?;
            if state_checksum(&bytes) != checksum {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
            let state = decode_state(&bytes)?;
            if sqlite_revision(state.revision)? != legacy_revision {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            backfill_normalized_revision(&transaction, &state, &checksum)?;
        }
    }

    let latest = load_catalog_revision_metadata(&transaction, SnapshotSelection::Latest)?;
    enforce_catalog_capacity(&latest, capacity_profile)?;
    rebuild_all_catalog_buckets(&transaction, latest.revision)?;
    let persisted_root = catalog_root_from_table(&transaction)?;
    if persisted_root != latest.catalog_root {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    transaction
        .execute("DELETE FROM state_snapshots", [])
        .map_err(unavailable)?;
    transaction
        .execute(
            "INSERT INTO cigar_catalog_authority
               (singleton, format_version, capacity_profile, activated, activated_at_unix_nanos)
             VALUES (1, 4, ?1, 1, ?2)",
            params![capacity_profile.name(), unix_nanos_text()?],
        )
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)
}

fn backfill_normalized_revision(
    transaction: &rusqlite::Transaction<'_>,
    state: &CommittedState,
    legacy_semantic_root: &str,
) -> Result<(), StoreError> {
    let revision = state.revision;
    insert_catalog_from_state(transaction, state, revision)?;
    sync_lineage_heads_from_state(transaction, state, revision)?;
    let (catalog_root, atom_count, edge_count, referenced_blob_bytes) =
        calculate_catalog_snapshot(transaction, revision, true)?;
    let residual = encode_catalog_free_state(state)?;
    let residual_checksum = state_checksum(&residual);
    let semantic_root = ContentDigest::new(legacy_semantic_root.to_owned())
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    transaction
        .execute(
            "INSERT INTO cigar_repository_revisions_v4
               (revision, residual_state, residual_checksum, catalog_root, semantic_root,
                semantic_root_format, atom_count, edge_count, referenced_blob_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)",
            params![
                sqlite_revision(revision)?,
                residual,
                residual_checksum,
                catalog_root.as_str(),
                semantic_root.as_str(),
                catalog_count_i64(atom_count)?,
                catalog_count_i64(edge_count)?,
                catalog_count_i64(referenced_blob_bytes)?,
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn encode_catalog_free_state(state: &CommittedState) -> Result<Vec<u8>, StoreError> {
    encode_record(&CatalogFreeStateV4::from_state(state))
}

fn decode_catalog_free_state(bytes: &[u8]) -> Result<CommittedState, StoreError> {
    let residual: CatalogFreeStateV4 = ciborium::de::from_reader(bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if residual.format_version != 4 {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(residual.into())
}

fn load_catalog_revision_metadata(
    connection: &Connection,
    selection: SnapshotSelection,
) -> Result<CatalogRevisionMetadata, StoreError> {
    let query = match selection {
        SnapshotSelection::Latest => {
            "SELECT revision, residual_checksum, catalog_root, semantic_root,
                    semantic_root_format, atom_count, edge_count, referenced_blob_bytes
             FROM cigar_repository_revisions_v4 ORDER BY revision DESC LIMIT 1"
        }
        SnapshotSelection::Revision(_) => {
            "SELECT revision, residual_checksum, catalog_root, semantic_root,
                    semantic_root_format, atom_count, edge_count, referenced_blob_bytes
             FROM cigar_repository_revisions_v4 WHERE revision = ?1"
        }
    };
    let read = |row: &rusqlite::Row<'_>| -> rusqlite::Result<_> {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
        ))
    };
    let row = match selection {
        SnapshotSelection::Latest => connection.query_row(query, [], read).optional(),
        SnapshotSelection::Revision(revision) => connection
            .query_row(query, params![sqlite_revision(revision)?], read)
            .optional(),
    }
    .map_err(unavailable)?
    .ok_or_else(|| StoreError::new(StoreErrorCode::NotFound))?;
    let revision = StoreRevision(
        u64::try_from(row.0).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
    );
    let metadata = CatalogRevisionMetadata {
        revision,
        residual_checksum: ContentDigest::new(row.1)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
        catalog_root: ContentDigest::new(row.2)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
        semantic_root: ContentDigest::new(row.3)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
        semantic_root_format: u8::try_from(row.4)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
        atom_count: catalog_count_u64(row.5)?,
        edge_count: catalog_count_u64(row.6)?,
        referenced_blob_bytes: catalog_count_u64(row.7)?,
    };
    if metadata.semantic_root_format == 4
        && normalized_semantic_root(
            metadata.revision,
            &metadata.residual_checksum,
            &metadata.catalog_root,
            metadata.atom_count,
            metadata.edge_count,
            metadata.referenced_blob_bytes,
        )? != metadata.semantic_root
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(metadata)
}

fn load_residual_state(
    connection: &Connection,
    selection: SnapshotSelection,
) -> Result<CommittedState, StoreError> {
    load_residual_state_profiled(connection, selection).map(|(state, _decode)| state)
}

fn load_residual_state_for_startup(
    connection: &Connection,
    path: &Path,
    secure_identity: SecureSqliteIdentity,
    observer: Option<&Arc<dyn RepositoryStartupMetricsObserver>>,
) -> Result<CommittedState, StoreError> {
    let (metadata, bytes) = measure_startup_stage(
        observer,
        RepositoryStartupStage::LatestCheckpointRead,
        || {
            let metadata = load_catalog_revision_metadata(connection, SnapshotSelection::Latest)?;
            let bytes = connection
                .query_row(
                    "SELECT residual_state FROM cigar_repository_revisions_v4 WHERE revision = ?1",
                    params![sqlite_revision(metadata.revision)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(unavailable)?;
            Ok((metadata, bytes))
        },
    )?;
    measure_startup_stage(
        observer,
        RepositoryStartupStage::ChecksumVerification,
        || {
            if state_checksum(&bytes) != metadata.residual_checksum.as_str() {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
            verify_secure_sqlite_path(path, secure_identity)
        },
    )?;
    measure_startup_stage(observer, RepositoryStartupStage::DeltaReplay, || Ok(()))?;
    measure_startup_stage(observer, RepositoryStartupStage::ResidualDecode, || {
        let state = decode_catalog_free_state(&bytes)?;
        if state.revision != metadata.revision {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        Ok(state)
    })
}

fn load_residual_state_profiled(
    connection: &Connection,
    selection: SnapshotSelection,
) -> Result<(CommittedState, Duration), StoreError> {
    let metadata = load_catalog_revision_metadata(connection, selection)?;
    let bytes = connection
        .query_row(
            "SELECT residual_state FROM cigar_repository_revisions_v4 WHERE revision = ?1",
            params![sqlite_revision(metadata.revision)?],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(unavailable)?;
    if state_checksum(&bytes) != metadata.residual_checksum.as_str() {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let decode_started = Instant::now();
    let state = decode_catalog_free_state(&bytes)?;
    let decode_elapsed = decode_started.elapsed();
    if state.revision != metadata.revision {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok((state, decode_elapsed))
}

fn insert_catalog_from_state(
    connection: &Connection,
    state: &CommittedState,
    revision: StoreRevision,
) -> Result<BTreeSet<u16>, StoreError> {
    let mut buckets = BTreeSet::new();
    for (tenant_id, tenant) in &state.tenants {
        for atom in tenant.atoms.values() {
            buckets.insert(insert_catalog_atom(connection, tenant_id, atom, revision)?);
        }
        for edge in tenant.edges.values() {
            buckets.insert(insert_catalog_edge(connection, tenant_id, edge, revision)?);
        }
    }
    Ok(buckets)
}

fn insert_catalog_atom(
    connection: &Connection,
    tenant_id: &RecordId,
    atom: &ContextAtomV1,
    revision: StoreRevision,
) -> Result<u16, StoreError> {
    let record = encode_record(atom)?;
    let exact_text = catalog_exact_text(atom);
    validate_catalog_payload_bounds(exact_text, &record)?;
    let record_checksum = state_checksum(&record);
    let referenced_blob_bytes = atom_referenced_blob_bytes(atom);
    let bucket = catalog_root_bucket(
        b"CIGAR-CATALOG-ATOM-BUCKET-v1",
        tenant_id.as_str(),
        atom.version_id.as_str(),
    );
    connection
        .execute(
            "INSERT OR IGNORE INTO cigar_catalog_atoms
               (tenant_id, version_id, atom_id, lineage_id, kind, lifecycle,
                observed_at_unix_nanos, exact_text, referenced_blob_bytes, root_bucket,
                published_revision, record, record_checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                tenant_id.as_str(),
                atom.version_id.as_str(),
                atom.atom_id.as_str(),
                atom.lineage_id.as_str(),
                atom_kind_name(atom.kind),
                lifecycle_name(atom.lifecycle),
                atom.temporal.observed_at.unix_nanos().to_string(),
                exact_text,
                catalog_count_i64(referenced_blob_bytes)?,
                i64::from(bucket),
                sqlite_revision(revision)?,
                record,
                record_checksum,
            ],
        )
        .map_err(unavailable)?;
    let stored = connection
        .query_row(
            "SELECT atom_id, record_checksum, root_bucket, published_revision
             FROM cigar_catalog_atoms WHERE tenant_id = ?1 AND version_id = ?2",
            params![tenant_id.as_str(), atom.version_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
    if stored.0 != atom.atom_id.as_str()
        || stored.1 != state_checksum(&encode_record(atom)?)
        || stored.2 != i64::from(bucket)
        || stored.3 > sqlite_revision(revision)?
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(bucket)
}

fn insert_catalog_edge(
    connection: &Connection,
    tenant_id: &RecordId,
    edge: &ContextEdge,
    revision: StoreRevision,
) -> Result<u16, StoreError> {
    let record = encode_record(edge)?;
    if record.len() > MAX_SQLITE_CATALOG_RECORD_BYTES {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let record_checksum = state_checksum(&record);
    let bucket = catalog_root_bucket(
        b"CIGAR-CATALOG-EDGE-BUCKET-v1",
        tenant_id.as_str(),
        edge.edge_id.as_str(),
    );
    connection
        .execute(
            "INSERT OR IGNORE INTO cigar_catalog_edges
               (tenant_id, edge_id, from_version, to_version, kind, lifecycle, root_bucket,
                published_revision, record, record_checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                tenant_id.as_str(),
                edge.edge_id.as_str(),
                edge.from_version.as_str(),
                edge.to_version.as_str(),
                edge_kind_name(edge.kind),
                lifecycle_name(edge.lifecycle),
                i64::from(bucket),
                sqlite_revision(revision)?,
                record,
                record_checksum,
            ],
        )
        .map_err(unavailable)?;
    let stored = connection
        .query_row(
            "SELECT record_checksum, root_bucket, published_revision
             FROM cigar_catalog_edges WHERE tenant_id = ?1 AND edge_id = ?2",
            params![tenant_id.as_str(), edge.edge_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(unavailable)?
        .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
    if stored.0 != state_checksum(&encode_record(edge)?)
        || stored.1 != i64::from(bucket)
        || stored.2 > sqlite_revision(revision)?
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(bucket)
}

fn sync_lineage_heads_from_state(
    connection: &Connection,
    state: &CommittedState,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    for (tenant_id, tenant) in &state.tenants {
        for (lineage_id, version_id) in &tenant.current_versions_by_lineage {
            sync_lineage_head(connection, tenant_id, lineage_id, version_id, revision)?;
        }
    }
    Ok(())
}

fn sync_lineage_head(
    connection: &Connection,
    tenant_id: &RecordId,
    lineage_id: &LineageId,
    version_id: &VersionId,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    let current = connection
        .query_row(
            "SELECT valid_from_revision, version_id
             FROM cigar_catalog_lineage_heads
             WHERE tenant_id = ?1 AND lineage_id = ?2 AND valid_to_revision IS NULL",
            params![tenant_id.as_str(), lineage_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(unavailable)?;
    if current
        .as_ref()
        .is_some_and(|(_, current)| current == version_id.as_str())
    {
        return Ok(());
    }
    let revision_i64 = sqlite_revision(revision)?;
    if let Some((valid_from, _)) = current {
        if valid_from == revision_i64 {
            connection
                .execute(
                    "UPDATE cigar_catalog_lineage_heads SET version_id = ?3
                     WHERE tenant_id = ?1 AND lineage_id = ?2 AND valid_from_revision = ?4",
                    params![
                        tenant_id.as_str(),
                        lineage_id.as_str(),
                        version_id.as_str(),
                        valid_from
                    ],
                )
                .map_err(unavailable)?;
            return Ok(());
        }
        connection
            .execute(
                "UPDATE cigar_catalog_lineage_heads SET valid_to_revision = ?3
                 WHERE tenant_id = ?1 AND lineage_id = ?2 AND valid_to_revision IS NULL",
                params![tenant_id.as_str(), lineage_id.as_str(), revision_i64],
            )
            .map_err(unavailable)?;
    }
    connection
        .execute(
            "INSERT INTO cigar_catalog_lineage_heads
               (tenant_id, lineage_id, valid_from_revision, valid_to_revision, version_id)
             VALUES (?1, ?2, ?3, NULL, ?4)",
            params![
                tenant_id.as_str(),
                lineage_id.as_str(),
                revision_i64,
                version_id.as_str()
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

fn calculate_catalog_snapshot(
    connection: &Connection,
    revision: StoreRevision,
    verify_records: bool,
) -> Result<(ContentDigest, u64, u64, u64), StoreError> {
    let revision_i64 = sqlite_revision(revision)?;
    let buckets = {
        let mut statement = connection
            .prepare(
                "SELECT root_bucket FROM cigar_catalog_atoms WHERE published_revision <= ?1
                 UNION
                 SELECT root_bucket FROM cigar_catalog_edges WHERE published_revision <= ?1
                 ORDER BY root_bucket",
            )
            .map_err(unavailable)?;
        let rows = statement
            .query_map(params![revision_i64], |row| row.get::<_, i64>(0))
            .map_err(unavailable)?;
        let mut buckets = Vec::new();
        for row in rows {
            let bucket = row.map_err(unavailable)?;
            buckets.push(
                u16::try_from(bucket)
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?,
            );
        }
        buckets
    };
    let mut states = BTreeMap::new();
    let mut atom_count = 0_u64;
    let mut edge_count = 0_u64;
    let mut referenced_blob_bytes = 0_u64;
    for bucket in buckets {
        let state = compute_catalog_bucket(connection, bucket, revision, verify_records)?;
        atom_count = atom_count
            .checked_add(state.atom_count)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        edge_count = edge_count
            .checked_add(state.edge_count)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        referenced_blob_bytes = referenced_blob_bytes
            .checked_add(state.referenced_blob_bytes)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        states.insert(bucket, state);
    }
    Ok((
        catalog_root_from_bucket_states(&states)?,
        atom_count,
        edge_count,
        referenced_blob_bytes,
    ))
}

fn compute_catalog_bucket(
    connection: &Connection,
    bucket: u16,
    revision: StoreRevision,
    verify_records: bool,
) -> Result<CatalogBucketState, StoreError> {
    let mut atom_root = catalog_hash(b"CIGAR-CATALOG-ATOM-ROOT-v1");
    let mut edge_root = catalog_hash(b"CIGAR-CATALOG-EDGE-ROOT-v1");
    let mut atom_count = 0_u64;
    let mut edge_count = 0_u64;
    let mut referenced_blob_bytes = 0_u64;
    {
        let mut statement = connection
            .prepare(
                "SELECT tenant_id, version_id, atom_id, lineage_id, kind, lifecycle,
                        observed_at_unix_nanos, exact_text, referenced_blob_bytes,
                        published_revision, record, record_checksum
                 FROM cigar_catalog_atoms
                 WHERE root_bucket = ?1 AND published_revision <= ?2
                 ORDER BY tenant_id, version_id",
            )
            .map_err(unavailable)?;
        let mut rows = statement
            .query(params![i64::from(bucket), sqlite_revision(revision)?])
            .map_err(unavailable)?;
        while let Some(row) = rows.next().map_err(unavailable)? {
            let tenant = row.get::<_, String>(0).map_err(unavailable)?;
            let version = row.get::<_, String>(1).map_err(unavailable)?;
            let checksum = row.get::<_, String>(11).map_err(unavailable)?;
            if verify_records {
                let record = row.get::<_, Vec<u8>>(10).map_err(unavailable)?;
                if record.len() > MAX_SQLITE_CATALOG_RECORD_BYTES
                    || state_checksum(&record) != checksum
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
                let atom: ContextAtomV1 = decode_record(&record)?;
                let expected_bytes = atom_referenced_blob_bytes(&atom);
                if atom.scope.tenant_id.as_str() != tenant
                    || atom.version_id.as_str() != version
                    || atom.atom_id.as_str() != row.get::<_, String>(2).map_err(unavailable)?
                    || atom.lineage_id.as_str() != row.get::<_, String>(3).map_err(unavailable)?
                    || atom_kind_name(atom.kind) != row.get::<_, String>(4).map_err(unavailable)?
                    || lifecycle_name(atom.lifecycle)
                        != row.get::<_, String>(5).map_err(unavailable)?
                    || atom.temporal.observed_at.unix_nanos().to_string()
                        != row.get::<_, String>(6).map_err(unavailable)?
                    || catalog_exact_text(&atom) != row.get::<_, String>(7).map_err(unavailable)?
                    || catalog_count_u64(row.get::<_, i64>(8).map_err(unavailable)?)?
                        != expected_bytes
                    || catalog_root_bucket(b"CIGAR-CATALOG-ATOM-BUCKET-v1", &tenant, &version)
                        != bucket
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
            }
            catalog_hash_field(&mut atom_root, tenant.as_bytes())?;
            catalog_hash_field(&mut atom_root, version.as_bytes())?;
            catalog_hash_field(&mut atom_root, checksum.as_bytes())?;
            atom_count = atom_count
                .checked_add(1)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            referenced_blob_bytes = referenced_blob_bytes
                .checked_add(catalog_count_u64(
                    row.get::<_, i64>(8).map_err(unavailable)?,
                )?)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        }
    }
    {
        let mut statement = connection
            .prepare(
                "SELECT tenant_id, edge_id, from_version, to_version, kind, lifecycle,
                        published_revision, record, record_checksum
                 FROM cigar_catalog_edges
                 WHERE root_bucket = ?1 AND published_revision <= ?2
                 ORDER BY tenant_id, edge_id",
            )
            .map_err(unavailable)?;
        let mut rows = statement
            .query(params![i64::from(bucket), sqlite_revision(revision)?])
            .map_err(unavailable)?;
        while let Some(row) = rows.next().map_err(unavailable)? {
            let tenant = row.get::<_, String>(0).map_err(unavailable)?;
            let edge_id = row.get::<_, String>(1).map_err(unavailable)?;
            let checksum = row.get::<_, String>(8).map_err(unavailable)?;
            if verify_records {
                let record = row.get::<_, Vec<u8>>(7).map_err(unavailable)?;
                if record.len() > MAX_SQLITE_CATALOG_RECORD_BYTES
                    || state_checksum(&record) != checksum
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
                let edge: ContextEdge = decode_record(&record)?;
                if edge.edge_id.as_str() != edge_id
                    || edge.from_version.as_str() != row.get::<_, String>(2).map_err(unavailable)?
                    || edge.to_version.as_str() != row.get::<_, String>(3).map_err(unavailable)?
                    || edge_kind_name(edge.kind) != row.get::<_, String>(4).map_err(unavailable)?
                    || lifecycle_name(edge.lifecycle)
                        != row.get::<_, String>(5).map_err(unavailable)?
                    || catalog_root_bucket(b"CIGAR-CATALOG-EDGE-BUCKET-v1", &tenant, &edge_id)
                        != bucket
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
            }
            catalog_hash_field(&mut edge_root, tenant.as_bytes())?;
            catalog_hash_field(&mut edge_root, edge_id.as_bytes())?;
            catalog_hash_field(&mut edge_root, checksum.as_bytes())?;
            edge_count = edge_count
                .checked_add(1)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        }
    }
    Ok(CatalogBucketState {
        atom_count,
        edge_count,
        referenced_blob_bytes,
        atom_root: finish_catalog_hash(atom_root)?,
        edge_root: finish_catalog_hash(edge_root)?,
    })
}

fn rebuild_all_catalog_buckets(
    connection: &Connection,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    connection
        .execute("DELETE FROM cigar_catalog_root_buckets", [])
        .map_err(unavailable)?;
    let buckets = {
        let mut statement = connection
            .prepare(
                "SELECT root_bucket FROM cigar_catalog_atoms WHERE published_revision <= ?1
                 UNION
                 SELECT root_bucket FROM cigar_catalog_edges WHERE published_revision <= ?1
                 ORDER BY root_bucket",
            )
            .map_err(unavailable)?;
        let rows = statement
            .query_map(params![sqlite_revision(revision)?], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(unavailable)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(
                u16::try_from(row.map_err(unavailable)?)
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?,
            );
        }
        result
    };
    for bucket in buckets {
        persist_catalog_bucket(connection, bucket, revision)?;
    }
    Ok(())
}

pub(crate) fn persist_catalog_bucket(
    connection: &Connection,
    bucket: u16,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    let state = compute_catalog_bucket(connection, bucket, revision, false)?;
    if state.atom_count == 0 && state.edge_count == 0 {
        connection
            .execute(
                "DELETE FROM cigar_catalog_root_buckets WHERE root_bucket = ?1",
                params![i64::from(bucket)],
            )
            .map_err(unavailable)?;
        return Ok(());
    }
    connection
        .execute(
            "INSERT INTO cigar_catalog_root_buckets
               (root_bucket, atom_count, edge_count, referenced_blob_bytes, atom_root, edge_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(root_bucket) DO UPDATE SET
               atom_count = excluded.atom_count,
               edge_count = excluded.edge_count,
               referenced_blob_bytes = excluded.referenced_blob_bytes,
               atom_root = excluded.atom_root,
               edge_root = excluded.edge_root",
            params![
                i64::from(bucket),
                catalog_count_i64(state.atom_count)?,
                catalog_count_i64(state.edge_count)?,
                catalog_count_i64(state.referenced_blob_bytes)?,
                state.atom_root.as_str(),
                state.edge_root.as_str(),
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

pub(crate) fn catalog_root_from_table(
    connection: &Connection,
) -> Result<ContentDigest, StoreError> {
    let mut states = BTreeMap::new();
    let mut statement = connection
        .prepare(
            "SELECT root_bucket, atom_count, edge_count, referenced_blob_bytes,
                    atom_root, edge_root
             FROM cigar_catalog_root_buckets ORDER BY root_bucket",
        )
        .map_err(unavailable)?;
    let mut rows = statement.query([]).map_err(unavailable)?;
    while let Some(row) = rows.next().map_err(unavailable)? {
        let bucket = u16::try_from(row.get::<_, i64>(0).map_err(unavailable)?)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
        states.insert(
            bucket,
            CatalogBucketState {
                atom_count: catalog_count_u64(row.get::<_, i64>(1).map_err(unavailable)?)?,
                edge_count: catalog_count_u64(row.get::<_, i64>(2).map_err(unavailable)?)?,
                referenced_blob_bytes: catalog_count_u64(
                    row.get::<_, i64>(3).map_err(unavailable)?,
                )?,
                atom_root: ContentDigest::new(row.get::<_, String>(4).map_err(unavailable)?)
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?,
                edge_root: ContentDigest::new(row.get::<_, String>(5).map_err(unavailable)?)
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?,
            },
        );
    }
    catalog_root_from_bucket_states(&states)
}

fn catalog_root_from_bucket_states(
    states: &BTreeMap<u16, CatalogBucketState>,
) -> Result<ContentDigest, StoreError> {
    let mut root = catalog_hash(b"CIGAR-CATALOG-ROOT-v4");
    for (bucket, state) in states {
        root.update(bucket.to_be_bytes());
        root.update(state.atom_count.to_be_bytes());
        root.update(state.edge_count.to_be_bytes());
        root.update(state.referenced_blob_bytes.to_be_bytes());
        catalog_hash_field(&mut root, state.atom_root.as_str().as_bytes())?;
        catalog_hash_field(&mut root, state.edge_root.as_str().as_bytes())?;
    }
    finish_catalog_hash(root)
}

fn catalog_root_bucket(domain: &[u8], tenant: &str, identifier: &str) -> u16 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(tenant.len().to_be_bytes());
    hash.update(tenant.as_bytes());
    hash.update(identifier.len().to_be_bytes());
    hash.update(identifier.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let [first, second, ..] = digest;
    u16::from_be_bytes([first, second])
}

fn catalog_hash(domain: &[u8]) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash
}

fn catalog_hash_field(hash: &mut Sha256, bytes: &[u8]) -> Result<(), StoreError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    hash.update(length.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

fn finish_catalog_hash(hash: Sha256) -> Result<ContentDigest, StoreError> {
    let mut value = String::from("1220");
    for byte in hash.finalize() {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    ContentDigest::new(value).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

fn catalog_exact_text(atom: &ContextAtomV1) -> &str {
    match &atom.payload {
        AtomPayload::InlineText(value) => value,
        AtomPayload::Structured(_) | AtomPayload::Blob(_) => "",
    }
}

const fn atom_referenced_blob_bytes(atom: &ContextAtomV1) -> u64 {
    match &atom.payload {
        AtomPayload::Blob(reference) => reference.size_bytes,
        AtomPayload::InlineText(_) | AtomPayload::Structured(_) => 0,
    }
}

fn validate_catalog_payload_bounds(exact_text: &str, record: &[u8]) -> Result<(), StoreError> {
    if exact_text.len() > MAX_SQLITE_CATALOG_TEXT_BYTES
        || record.len() > MAX_SQLITE_CATALOG_RECORD_BYTES
    {
        Err(StoreError::new(StoreErrorCode::LimitExceeded))
    } else {
        Ok(())
    }
}

const fn atom_kind_name(kind: AtomKind) -> &'static str {
    match kind {
        AtomKind::Instruction => "instruction",
        AtomKind::SourceCode => "source_code",
        AtomKind::Documentation => "documentation",
        AtomKind::Decision => "decision",
        AtomKind::Conversation => "conversation",
        AtomKind::ToolResult => "tool_result",
        AtomKind::Schema => "schema",
        AtomKind::Policy => "policy",
        AtomKind::Test => "test",
        AtomKind::Artifact => "artifact",
    }
}

const fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::DependsOn => "depends_on",
        EdgeKind::Defines => "defines",
        EdgeKind::References => "references",
        EdgeKind::Supersedes => "supersedes",
        EdgeKind::Contradicts => "contradicts",
        EdgeKind::Supports => "supports",
        EdgeKind::DerivedFrom => "derived_from",
        EdgeKind::AppliesTo => "applies_to",
    }
}

fn catalog_count_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn catalog_count_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
}

fn enforce_catalog_capacity(
    metadata: &CatalogRevisionMetadata,
    profile: SqliteCapacityProfile,
) -> Result<(), StoreError> {
    if metadata.atom_count > profile.maximum_atoms()
        || metadata.edge_count > profile.maximum_edges()
        || metadata.referenced_blob_bytes > profile.maximum_referenced_blob_bytes()
    {
        Err(StoreError::new(StoreErrorCode::LimitExceeded))
    } else {
        Ok(())
    }
}

fn normalized_semantic_root(
    revision: StoreRevision,
    residual_checksum: &ContentDigest,
    catalog_root: &ContentDigest,
    atom_count: u64,
    edge_count: u64,
    referenced_blob_bytes: u64,
) -> Result<ContentDigest, StoreError> {
    let mut root = catalog_hash(b"CIGAR-SQLITE-SEMANTIC-ROOT-v4");
    root.update(revision.0.to_be_bytes());
    catalog_hash_field(&mut root, residual_checksum.as_str().as_bytes())?;
    catalog_hash_field(&mut root, catalog_root.as_str().as_bytes())?;
    root.update(atom_count.to_be_bytes());
    root.update(edge_count.to_be_bytes());
    root.update(referenced_blob_bytes.to_be_bytes());
    finish_catalog_hash(root)
}

fn decode_record<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    ciborium::de::from_reader(bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
}

fn decode_catalog_atom(record: &[u8], checksum: &str) -> Result<ContextAtomV1, StoreError> {
    if record.len() > MAX_SQLITE_CATALOG_RECORD_BYTES || state_checksum(record) != checksum {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    decode_record(record)
}

fn decode_catalog_edge(record: &[u8], checksum: &str) -> Result<ContextEdge, StoreError> {
    if record.len() > MAX_SQLITE_CATALOG_RECORD_BYTES || state_checksum(record) != checksum {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    decode_record(record)
}

#[cfg(test)]
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

fn garbage_collection_execution_digest(domain: &[u8], bytes: &[u8]) -> Result<String, StoreError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    let mut value = String::from("1220");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    }
    Ok(value)
}

fn garbage_collection_execution_marker(
    database: &Path,
    plan: &crate::GarbageCollectionPlan,
) -> Result<(PathBuf, Vec<u8>), StoreError> {
    let database = fs::canonicalize(database)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let parent = database
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    let database_digest = garbage_collection_execution_digest(
        b"CIGAR-GC-EXECUTION-DATABASE\0v1\0",
        database.as_os_str().as_encoded_bytes(),
    )?;
    let plan_bytes = serde_json::to_vec(plan)
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    let plan_digest =
        garbage_collection_execution_digest(b"CIGAR-GC-EXECUTION-PLAN\0v1\0", &plan_bytes)?;
    let directory = parent.join(GC_EXECUTION_DIRECTORY);
    let marker = directory.join(format!("{database_digest}-{plan_digest}.started"));
    let bytes =
        format!("{GC_EXECUTION_MARKER_SCHEMA}\n{database_digest}\n{plan_digest}\n").into_bytes();
    if u64::try_from(bytes.len()).map_or(true, |length| {
        length == 0 || length > MAX_GC_EXECUTION_MARKER_BYTES
    }) {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    Ok((marker, bytes))
}

fn garbage_collection_execution_marker_exists(
    marker: &Path,
    expected: &[u8],
) -> Result<bool, StoreError> {
    let file = match File::open(marker) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    let directory = marker
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    validate_garbage_collection_execution_directory(directory)?;
    validate_garbage_collection_execution_marker(marker, &file)?;
    let length = file
        .metadata()
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
        .len();
    if length == 0
        || length > MAX_GC_EXECUTION_MARKER_BYTES
        || usize::try_from(length).ok() != Some(expected.len())
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let mut actual = Vec::with_capacity(expected.len());
    file.take(MAX_GC_EXECUTION_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut actual)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if actual != expected {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(true)
}

fn publish_garbage_collection_execution_marker(
    marker: &Path,
    bytes: &[u8],
) -> Result<(), StoreError> {
    let directory = marker
        .parent()
        .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
    ensure_garbage_collection_execution_directory(directory)?;
    if garbage_collection_execution_marker_exists(marker, bytes)? {
        return Ok(());
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".cigar-gc-execution-")
        .tempfile_in(directory)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    }
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    match temporary.persist_noclobber(marker) {
        Ok(file) => {
            validate_garbage_collection_execution_marker(marker, &file)?;
            sync_parent_directory(directory)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            if garbage_collection_execution_marker_exists(marker, bytes)? {
                Ok(())
            } else {
                Err(StoreError::new(StoreErrorCode::InvalidRecord))
            }
        }
        Err(_error) => Err(StoreError::new(StoreErrorCode::Unavailable)),
    }
}

fn ensure_garbage_collection_execution_directory(path: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_error) => return Err(StoreError::new(StoreErrorCode::Unavailable)),
    };
    validate_garbage_collection_execution_directory(path)?;
    if created {
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        sync_parent_directory(parent)?;
    }
    Ok(())
}

fn validate_garbage_collection_execution_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
    }
    Ok(())
}

fn validate_garbage_collection_execution_marker(
    path: &Path,
    file: &File,
) -> Result<(), StoreError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let file_metadata = file
        .metadata()
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if path_metadata.uid() != rustix::process::geteuid().as_raw()
            || path_metadata.permissions().mode() & 0o7777 != 0o600
            || path_metadata.nlink() != 1
            || path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
    }
    Ok(())
}

fn sqlite_revision(revision: StoreRevision) -> Result<i64, StoreError> {
    i64::try_from(revision.0).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

pub(crate) fn validate_staged_shape(staged: &[StagedMutation]) -> Result<(), StoreError> {
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

pub(crate) fn read_revision_anchor(path: &Path) -> Result<Option<StoreRevision>, StoreError> {
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

pub(crate) fn write_revision_anchor(
    path: &Path,
    revision: StoreRevision,
) -> Result<(), StoreError> {
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
mod startup_metrics_tests {
    use super::SqliteStore;
    use crate::{
        RepositoryStartupMetrics, RepositoryStartupMetricsObserver, RepositoryStartupOutcome,
        RepositoryStartupStage,
    };
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CapturingStartupObserver {
        observations: Mutex<Vec<RepositoryStartupMetrics>>,
    }

    impl RepositoryStartupMetricsObserver for CapturingStartupObserver {
        fn observe_repository_startup(&self, metrics: RepositoryStartupMetrics) {
            if let Ok(mut observations) = self.observations.lock() {
                observations.push(metrics);
            }
        }
    }

    #[test]
    fn observed_sqlite_startup_reports_each_authenticated_stage_in_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let observer = Arc::new(CapturingStartupObserver::default());
        let observer_handle: Arc<dyn RepositoryStartupMetricsObserver> = observer.clone();
        let _store = SqliteStore::open_with_startup_metrics(
            directory.path().join("observed-startup.sqlite3"),
            observer_handle,
        )?;
        let observations = observer
            .observations
            .lock()
            .map_err(|_| std::io::Error::other("startup observer lock poisoned"))?;
        let stages = observations
            .iter()
            .map(|measurement| measurement.stage)
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            vec![
                RepositoryStartupStage::PathConfiguration,
                RepositoryStartupStage::SqliteOpenConfigure,
                RepositoryStartupStage::MigrationLedger,
                RepositoryStartupStage::LatestCheckpointRead,
                RepositoryStartupStage::ChecksumVerification,
                RepositoryStartupStage::DeltaReplay,
                RepositoryStartupStage::ResidualDecode,
                RepositoryStartupStage::RevisionAnchor,
                RepositoryStartupStage::CatalogProjection,
                RepositoryStartupStage::BlobReconciliation,
            ]
        );
        assert!(
            observations
                .iter()
                .all(|measurement| measurement.outcome == RepositoryStartupOutcome::Completed)
        );
        Ok(())
    }

    #[test]
    fn corrupt_latest_residual_reports_only_the_closed_checksum_stage_and_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("corrupt-startup.sqlite3");
        drop(SqliteStore::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute(
            "UPDATE cigar_repository_revisions_v4 SET residual_state = x'00' WHERE revision = 0",
            [],
        )?;
        drop(connection);

        let observer = Arc::new(CapturingStartupObserver::default());
        let observer_handle: Arc<dyn RepositoryStartupMetricsObserver> = observer.clone();
        assert!(SqliteStore::open_with_startup_metrics(&path, observer_handle).is_err());
        let observations = observer
            .observations
            .lock()
            .map_err(|_| std::io::Error::other("startup observer lock poisoned"))?;
        let failed = observations
            .iter()
            .filter(|measurement| measurement.outcome == RepositoryStartupOutcome::Failed)
            .collect::<Vec<_>>();
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed.first().map(|measurement| measurement.stage),
            Some(RepositoryStartupStage::ChecksumVerification)
        );
        Ok(())
    }
}

#[cfg(test)]
mod backup_lock_tests {
    use super::{SqliteStore, projection_generation_i64};
    use crate::{StoreError, StoreErrorCode, StoreRevision};
    use rusqlite::{Connection, params};
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
    fn deep_integrity_rejects_and_startup_recovers_a_forged_projection_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("metadata.sqlite3");
        let store = SqliteStore::open(&database)?;
        let initial_projection = store.projection_status()?;
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
        store.lock()?.execute(
            "INSERT INTO atom_projection_rows
             (generation, tenant_id, version_id, lineage_id, lifecycle,
              exact_text, record, record_checksum)
             VALUES (?1, 'forged-tenant', 'forged-version', 'forged-lineage',
                     'active', '', x'00', ?2)",
            params![
                projection_generation_i64(initial_projection.generation)?,
                format!("1220{}", "0".repeat(64))
            ],
        )?;
        let error = match store.deep_integrity_check() {
            Ok(_report) => return Err("forged projection unexpectedly passed".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), StoreErrorCode::InvalidRecord);
        drop(store);

        let reopened = SqliteStore::open(&database)?;
        let recovered_projection = reopened.projection_status()?;
        assert!(recovered_projection.generation > initial_projection.generation);
        assert_eq!(recovered_projection.atom_count, 0);
        assert_eq!(reopened.deep_integrity_check()?.projection_atom_count, 0);
        assert!(!reopened.atom_projection_contains("forged-tenant", "forged-version")?);
        Ok(())
    }
}

#[cfg(test)]
mod projection_generation_tests {
    use super::{
        MAX_SQLITE_PROJECTION_ATOMS, MAX_STORED_SQLITE_PROJECTION_GENERATIONS,
        SqliteProjectionFailpoint, SqliteStore, projection_generation_i64,
    };
    use crate::{
        AccessContext, CancellationToken, Repository, StoreErrorCode, StoreRevision,
        WriteTransaction,
    };
    use cigar_protocol::{ContextAtomV1, ContextBundle};
    use rusqlite::{Connection, params};
    use std::time::Duration;

    fn fixture_atom() -> Result<ContextAtomV1, Box<dyn std::error::Error>> {
        let fixture = cigar_testkit::deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing ContextAtomV1 fixture")?;
        Ok(serde_json::from_value(fixture.input)?)
    }

    fn required_error<T>(
        result: Result<T, crate::StoreError>,
        message: &'static str,
    ) -> Result<crate::StoreError, Box<dyn std::error::Error>> {
        match result {
            Err(error) => Ok(error),
            Ok(_value) => Err(message.into()),
        }
    }

    fn publish_fixture_atom(
        store: &SqliteStore,
    ) -> Result<ContextAtomV1, Box<dyn std::error::Error>> {
        let atom = fixture_atom()?;
        let context = AccessContext::new(atom.scope.tenant_id.clone(), "projection-test")?;
        let mut write =
            store.begin_write(context, StoreRevision(0), CancellationToken::default())?;
        write.publish_atoms(vec![atom.clone()], Vec::new())?;
        assert_eq!(write.commit(None)?.revision, StoreRevision(1));
        Ok(atom)
    }

    #[test]
    fn authoritative_commit_makes_old_projection_fail_closed_until_rebuild()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("stale.sqlite3"))?;
        let initial = store.projection_status()?;
        assert_eq!(initial.source_revision, StoreRevision(0));
        let atom = publish_fixture_atom(&store)?;

        let count_error = required_error(
            store.atom_projection_count(atom.scope.tenant_id.as_str()),
            "old generation served a newer authoritative revision",
        )?;
        assert_eq!(count_error.code(), StoreErrorCode::InvalidRecord);
        let contains_error = required_error(
            store.atom_projection_contains(atom.scope.tenant_id.as_str(), atom.version_id.as_str()),
            "old generation did not fail closed",
        )?;
        assert_eq!(contains_error.code(), StoreErrorCode::InvalidRecord);
        assert_eq!(
            required_error(store.projection_status(), "status was not stale")?.code(),
            StoreErrorCode::InvalidRecord
        );

        let rebuilt = store.rebuild_atom_projection_generation(&CancellationToken::default())?;
        assert!(rebuilt.generation > initial.generation);
        assert_eq!(rebuilt.source_revision, StoreRevision(1));
        assert_eq!(rebuilt.atom_count, 1);
        assert_eq!(
            store.atom_projection_count(atom.scope.tenant_id.as_str())?,
            1
        );
        assert!(
            store.atom_projection_contains(
                atom.scope.tenant_id.as_str(),
                atom.version_id.as_str()
            )?
        );
        Ok(())
    }

    #[test]
    fn non_catalog_revision_does_not_invalidate_an_unchanged_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("non-catalog.sqlite3"))?;
        let atom = publish_fixture_atom(&store)
            .map_err(|error| format!("publish fixture atom: {error}"))?;
        let projection = store
            .rebuild_atom_projection_generation(&CancellationToken::default())
            .map_err(|error| format!("rebuild projection: {error}"))?;
        assert_eq!(projection.source_revision, StoreRevision(1));
        let context = AccessContext::new(atom.scope.tenant_id.clone(), "projection-test")?;
        let bundle_fixture = cigar_testkit::deterministic_protocol_fixture("ContextBundle")
            .ok_or("missing ContextBundle fixture")?;
        let bundle: ContextBundle = serde_json::from_value(bundle_fixture.input)?;
        let mut write =
            store.begin_write(context, StoreRevision(1), CancellationToken::default())?;
        write.put_bundle(bundle)?;
        assert_eq!(
            write
                .commit(None)
                .map_err(|error| format!("bundle commit: {error}"))?
                .revision,
            StoreRevision(2)
        );

        let current = store
            .projection_status()
            .map_err(|error| format!("projection status: {error}"))?;
        assert_eq!(current, projection);
        let report = store
            .deep_integrity_check()
            .map_err(|error| format!("deep integrity: {error}"))?;
        assert_eq!(report.revision, StoreRevision(2));
        assert_eq!(report.atom_count, 1);
        assert_eq!(report.projection_atom_count, 1);
        Ok(())
    }

    #[test]
    fn every_in_process_projection_boundary_is_atomic_and_restart_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let boundaries = [
            SqliteProjectionFailpoint::AfterBeginImmediate,
            SqliteProjectionFailpoint::AfterGenerationReserved,
            SqliteProjectionFailpoint::AfterRowsBuilt,
            SqliteProjectionFailpoint::AfterGenerationVerified,
            SqliteProjectionFailpoint::BeforeActivation,
            SqliteProjectionFailpoint::AfterActivation,
            SqliteProjectionFailpoint::BeforeCommit,
            SqliteProjectionFailpoint::AfterCommit,
        ];
        for boundary in boundaries {
            let directory = tempfile::tempdir()?;
            let path = directory
                .path()
                .join(format!("failpoint-{boundary:?}.sqlite3"));
            let store = SqliteStore::open(&path)?;
            let before = store.projection_status()?;
            store.inject_projection_failpoint(boundary)?;
            let error = required_error(
                store.rebuild_atom_projection_generation(&CancellationToken::default()),
                "armed boundary did not interrupt the caller",
            )?;
            assert_eq!(error.code(), StoreErrorCode::InjectedAbort);
            drop(store);

            let reopened = SqliteStore::open(&path)?;
            let recovered = reopened.projection_status()?;
            if boundary == SqliteProjectionFailpoint::AfterCommit {
                assert!(recovered.generation > before.generation);
            } else {
                assert_eq!(recovered.generation, before.generation);
            }
            let stored = reopened.lock()?.query_row(
                "SELECT COUNT(*) FROM atom_projection_generations",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            assert!(stored >= 1);
            assert!(u64::try_from(stored)? <= 2);
        }
        Ok(())
    }

    #[test]
    fn startup_recovers_corrupt_rows_fts_and_generation_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        for corruption in ["row", "fts", "metadata"] {
            let directory = tempfile::tempdir()?;
            let path = directory
                .path()
                .join(format!("corrupt-{corruption}.sqlite3"));
            let store = SqliteStore::open(&path)?;
            let atom = publish_fixture_atom(&store)?;
            let before = store.rebuild_atom_projection_generation(&CancellationToken::default())?;
            let generation = projection_generation_i64(before.generation)?;
            match corruption {
                "row" => {
                    store.lock()?.execute(
                        "UPDATE atom_projection_rows
                         SET exact_text = exact_text || 'corrupt'
                         WHERE generation = ?1",
                        params![generation],
                    )?;
                }
                "fts" => {
                    store.lock()?.execute(
                        "DELETE FROM atom_projection_fts WHERE generation = ?1",
                        params![generation],
                    )?;
                }
                "metadata" => {
                    store.lock()?.execute(
                        "UPDATE atom_projection_generations
                         SET state_checksum = ?2 WHERE generation = ?1",
                        params![generation, format!("1220{}", "0".repeat(64))],
                    )?;
                }
                _ => unreachable!(),
            }
            assert!(store.projection_status().is_err());
            drop(store);

            let reopened = SqliteStore::open(&path)?;
            let recovered = reopened.projection_status()?;
            assert!(recovered.generation > before.generation);
            assert_eq!(recovered.source_revision, StoreRevision(1));
            assert_eq!(recovered.atom_count, 1);
            assert!(reopened.atom_projection_contains(
                atom.scope.tenant_id.as_str(),
                atom.version_id.as_str()
            )?);
        }
        Ok(())
    }

    #[test]
    fn startup_recovers_a_stale_activation_watermark() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("stale-watermark.sqlite3");
        let store = SqliteStore::open(&path)?;
        let before = store.projection_status()?;
        store.lock()?.execute(
            "UPDATE atom_projection_activation
             SET source_revision = source_revision + 1 WHERE singleton = 1",
            [],
        )?;
        assert_eq!(
            required_error(store.projection_status(), "watermark was not stale")?.code(),
            StoreErrorCode::InvalidRecord
        );
        drop(store);

        let reopened = SqliteStore::open(&path)?;
        let recovered = reopened.projection_status()?;
        assert!(recovered.generation > before.generation);
        assert_eq!(recovered.source_revision, StoreRevision(0));
        Ok(())
    }

    #[test]
    fn concurrent_reader_observes_one_complete_activation_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("concurrent-reader.sqlite3");
        let store = SqliteStore::open(&path)?;
        let before = store.projection_status()?;
        let reader = Connection::open(&path)?;
        reader.busy_timeout(Duration::from_secs(5))?;
        reader.execute_batch("BEGIN DEFERRED")?;
        let snapshot_generation = reader.query_row(
            "SELECT generation FROM atom_projection_activation WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(u64::try_from(snapshot_generation)?, before.generation);

        let after = store.rebuild_atom_projection_generation(&CancellationToken::default())?;
        assert!(after.generation > before.generation);
        let still_snapshot_generation = reader.query_row(
            "SELECT generation FROM atom_projection_activation WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(still_snapshot_generation, snapshot_generation);
        reader.execute_batch("COMMIT")?;
        let current_generation = reader.query_row(
            "SELECT generation FROM atom_projection_activation WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(u64::try_from(current_generation)?, after.generation);
        Ok(())
    }

    #[test]
    fn startup_bounds_generation_amplification_and_recovers_atom_count_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("generation-amplification.sqlite3");
        let store = SqliteStore::open(&path)?;
        let status = store.projection_status()?;
        let connection = store.lock()?;
        for generation in 2..=(MAX_STORED_SQLITE_PROJECTION_GENERATIONS + 1) {
            connection.execute(
                "INSERT INTO atom_projection_generations
                 (generation, source_revision, state_checksum, atom_count,
                  projection_root, complete, created_at_unix_nanos)
                 VALUES (?1, ?2, ?3, 0, ?4, 0, '0')",
                params![
                    projection_generation_i64(generation)?,
                    i64::try_from(status.source_revision.0)?,
                    status.state_checksum.as_str(),
                    format!("1220{}", "0".repeat(64))
                ],
            )?;
        }
        drop(connection);
        drop(store);
        let error = required_error(
            SqliteStore::open(&path),
            "generation amplification did not fail",
        )?;
        assert_eq!(error.code(), StoreErrorCode::LimitExceeded);

        let second_path = directory.path().join("atom-amplification.sqlite3");
        let second = SqliteStore::open(&second_path)?;
        let second_status = second.projection_status()?;
        second.lock()?.execute(
            "UPDATE atom_projection_generations
             SET atom_count = ?2 WHERE generation = ?1",
            params![
                projection_generation_i64(second_status.generation)?,
                i64::try_from(MAX_SQLITE_PROJECTION_ATOMS + 1)?
            ],
        )?;
        drop(second);
        let recovered = SqliteStore::open(&second_path)?;
        let recovered_status = recovered.projection_status()?;
        assert!(recovered_status.generation > second_status.generation);
        assert_eq!(recovered_status.atom_count, 0);
        Ok(())
    }
}

#[cfg(test)]
mod migration_tests {
    use super::{
        INITIAL_MIGRATION, MAX_LARGE_LOCAL_ATOMS, MAX_LARGE_LOCAL_EDGES,
        MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES, MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES,
        SQLITE_MIGRATIONS, SqliteCapacityProfile, SqliteMigrationFailpoint, SqliteStore,
        backfill_normalized_revision, configure, decode_state, ensure_genesis, migrate,
        migrate_with_observer, state_checksum, verify_migration_connection,
    };
    use crate::{StoreError, StoreErrorCode};
    use rusqlite::{Connection, params};
    use std::path::Path;

    fn retained_v1(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
            std::fs::set_permissions(
                path.parent().ok_or("retained fixture path has no parent")?,
                std::fs::Permissions::from_mode(0o700),
            )?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        let connection = Connection::open(path)?;
        configure(&connection, SqliteCapacityProfile::Standard)?;
        connection.execute_batch(INITIAL_MIGRATION)?;
        connection.execute(
            "INSERT INTO schema_migrations
               (sequence, name, checksum, applied_at_unix_nanos)
             VALUES (1, 'initial', ?1, '1700000000000000000')",
            params![state_checksum(INITIAL_MIGRATION.as_bytes())],
        )?;
        ensure_genesis(&connection)?;
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            for suffix in ["-wal", "-shm", "-journal"] {
                let sidecar = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
                if sidecar.exists() {
                    std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        Ok(())
    }

    fn migration_one_row(
        connection: &Connection,
    ) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        Ok(connection.query_row(
            "SELECT name, checksum, applied_at_unix_nanos
             FROM schema_migrations WHERE sequence = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    }

    #[test]
    fn capacity_profiles_are_closed_serializable_and_hard_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            serde_json::to_string(&SqliteCapacityProfile::Standard)?,
            "\"standard\""
        );
        assert_eq!(
            serde_json::from_str::<SqliteCapacityProfile>("\"large_local\"")?,
            SqliteCapacityProfile::LargeLocal
        );
        assert_eq!(
            SqliteCapacityProfile::LargeLocal.database_bytes(),
            MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES
        );
        assert_eq!(
            SqliteCapacityProfile::LargeLocal.maximum_atoms(),
            MAX_LARGE_LOCAL_ATOMS
        );
        assert_eq!(
            SqliteCapacityProfile::LargeLocal.maximum_edges(),
            MAX_LARGE_LOCAL_EDGES
        );
        assert_eq!(
            SqliteCapacityProfile::LargeLocal.maximum_referenced_blob_bytes(),
            MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES
        );
        Ok(())
    }

    #[test]
    fn catalog_statistics_expose_exact_content_free_genesis_roots_and_totals()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("catalog-statistics.sqlite3"))?;
        let statistics = store.catalog_statistics()?;
        assert_eq!(statistics.revision.0, 0);
        assert_eq!(statistics.atom_count, 0);
        assert_eq!(statistics.edge_count, 0);
        assert_eq!(statistics.referenced_blob_bytes, 0);
        assert_eq!(statistics.semantic_root, store.semantic_root()?);
        assert!(statistics.catalog_root.as_str().starts_with("1220"));
        assert_eq!(statistics.catalog_root.as_str().len(), 68);
        Ok(())
    }

    #[test]
    fn normalized_activation_rolls_back_as_one_unit_and_restarts_cleanly()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("activation-rollback.sqlite3");
        retained_v1(&path)?;
        let mut connection = Connection::open(&path)?;
        migrate(&mut connection)?;
        {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (bytes, checksum) = transaction.query_row(
                "SELECT state, checksum FROM state_snapshots WHERE revision = 0",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )?;
            let state = decode_state(&bytes)?;
            backfill_normalized_revision(&transaction, &state, &checksum)?;
            transaction.execute("DELETE FROM state_snapshots", [])?;
            // Dropping an uncommitted transaction models process loss before activation commit.
        }
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })?,
            1
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM cigar_repository_revisions_v4",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        drop(connection);

        let store = SqliteStore::open(&path)?;
        assert_eq!(store.revision()?.0, 0);
        drop(store);
        let connection = Connection::open(path)?;
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT format_version, capacity_profile, activated
                 FROM cigar_catalog_authority WHERE singleton = 1",
                [],
                |row| Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?
                )),
            )?,
            (4, "standard".to_owned(), 1)
        );
        Ok(())
    }

    #[test]
    fn retained_v1_upgrade_is_append_only_and_preserves_semantic_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("retained-v1.sqlite3");
        retained_v1(&path)?;
        let mut before = Connection::open(&path)?;
        let retained_row = migration_one_row(&before)?;
        let state_before: (Vec<u8>, String) = before.query_row(
            "SELECT state, checksum FROM state_snapshots WHERE revision = 0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        migrate(&mut before).map_err(|error| format!("retained-v1 migration failed: {error:?}"))?;
        verify_migration_connection(&before)
            .map_err(|error| format!("retained-v1 migration verification failed: {error:?}"))?;
        drop(before);

        let store = SqliteStore::open(&path)
            .map_err(|error| format!("retained-v1 open failed: {error:?}"))?;
        let semantic_root = store
            .semantic_root()
            .map_err(|error| format!("retained-v1 semantic root failed: {error:?}"))?;
        assert_eq!(semantic_root.as_str(), state_before.1);
        assert_eq!(state_checksum(&state_before.0), state_before.1);
        drop(store);

        let after = Connection::open(&path)?;
        assert_eq!(migration_one_row(&after)?, retained_row);
        assert_eq!(
            after.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })?,
            i64::try_from(SQLITE_MIGRATIONS.len())?
        );
        assert_eq!(
            after.query_row(
                "SELECT minimum_application_major, maximum_application_major, online
                 FROM schema_migrations WHERE sequence = 2",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?,
            (1, 2, 1)
        );
        assert_eq!(
            after.query_row(
                "SELECT minimum_application_major, maximum_application_major, online
                 FROM schema_migrations WHERE sequence = 3",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?,
            (1, 1, 0)
        );
        verify_migration_connection(&after)?;
        drop(after);
        SqliteStore::open(&path)?.integrity_check()?;
        Ok(())
    }

    #[test]
    fn retained_v1_upgrade_recovers_at_every_sqlite_migration_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut failpoints = vec![SqliteMigrationFailpoint::AfterLedgerBootstrap];
        for sequence in 2..=4 {
            failpoints.extend([
                SqliteMigrationFailpoint::AfterTransactionBegin(sequence),
                SqliteMigrationFailpoint::AfterMigrationSql(sequence),
                SqliteMigrationFailpoint::BeforeLedgerInsert(sequence),
                SqliteMigrationFailpoint::AfterLedgerInsert(sequence),
                SqliteMigrationFailpoint::BeforeCommit(sequence),
                SqliteMigrationFailpoint::AfterCommit(sequence),
            ]);
        }
        for failpoint in failpoints {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("interrupted.sqlite3");
            retained_v1(&path)?;
            let mut connection = Connection::open(&path)?;
            let state_before: String = connection.query_row(
                "SELECT checksum FROM state_snapshots WHERE revision = 0",
                [],
                |row| row.get(0),
            )?;
            let outcome = migrate_with_observer(&mut connection, |boundary| {
                if boundary == failpoint {
                    Err(StoreError::new(StoreErrorCode::InjectedAbort))
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                outcome.map_err(|error| error.code()),
                Err(StoreErrorCode::InjectedAbort)
            );
            migrate(&mut connection)
                .map_err(|error| format!("recovery after {failpoint:?} failed: {error:?}"))?;
            verify_migration_connection(&connection)
                .map_err(|error| format!("verification after {failpoint:?} failed: {error:?}"))?;
            assert_eq!(
                connection.query_row(
                    "SELECT checksum FROM state_snapshots WHERE revision = 0",
                    [],
                    |row| row.get::<_, String>(0),
                )?,
                state_before
            );
            assert_eq!(
                connection.query_row("PRAGMA integrity_check", [], |row| {
                    row.get::<_, String>(0)
                })?,
                "ok"
            );
            drop(connection);
            SqliteStore::open(&path)?.integrity_check()?;
        }
        Ok(())
    }

    #[test]
    fn unknown_future_and_unsupported_downgrade_are_blocked_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        for (minimum, maximum, online) in [(1_i64, 2_i64, 1_i64), (2, 2, 1), (1, 2, 0)] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("future.sqlite3");
            let root = SqliteStore::open(&path)?.semantic_root()?;
            let connection = Connection::open(&path)?;
            connection.execute(
                "INSERT INTO schema_migrations
                   (sequence, name, checksum, applied_at_unix_nanos,
                    minimum_application_major, maximum_application_major, online)
                 VALUES (5, 'future_expansion', ?1, '1700000000000000001', ?2, ?3, ?4)",
                params![format!("1220{}", "a".repeat(64)), minimum, maximum, online],
            )?;
            drop(connection);
            let reopened = SqliteStore::open(&path);
            assert!(matches!(
                reopened,
                Err(error) if error.code() == StoreErrorCode::Unavailable
            ));
            let connection = Connection::open(&path)?;
            assert_eq!(
                connection.query_row(
                    "SELECT semantic_root FROM cigar_repository_revisions_v4 WHERE revision = 0",
                    [],
                    |row| row.get::<_, String>(0),
                )?,
                root.as_str()
            );
        }
        Ok(())
    }

    #[test]
    fn oversized_migration_ledger_is_bounded_before_materialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("oversized.sqlite3");
        drop(SqliteStore::open(&path)?);
        let mut connection = Connection::open(&path)?;
        let transaction = connection.transaction()?;
        for sequence in 5_i64..=4_100_i64 {
            transaction.execute(
                "INSERT INTO schema_migrations
                   (sequence, name, checksum, applied_at_unix_nanos,
                    minimum_application_major, maximum_application_major, online)
                 VALUES (?1, ?2, ?3, '1700000000000000001', 1, 2, 1)",
                params![
                    sequence,
                    format!("future_{sequence:04}"),
                    format!("1220{sequence:064x}")
                ],
            )?;
        }
        transaction.commit()?;
        drop(connection);
        assert!(matches!(
            SqliteStore::open(&path),
            Err(error) if error.code() == StoreErrorCode::LimitExceeded
        ));
        Ok(())
    }
}
