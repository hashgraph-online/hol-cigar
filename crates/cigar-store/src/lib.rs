//! Transactional repository contracts and a hermetic in-memory behavioral oracle.

mod backup;
mod blob;
mod gc;
mod memory;
mod migration;
mod model;
mod object;
mod postgres;
mod service_repository;
mod sqlite;

pub use backup::{
    BACKUP_DATABASE_FILE, BACKUP_EFFECT_CHECKPOINT_FILE, BackupError, BackupErrorCode,
    BackupFailpoint, BackupFailpoints, BackupFile, BackupIdentity, BackupManifest,
    BackupSignatureIdentity, VerifiedBackup, create_backup, create_backup_with_effect_checkpoint,
    create_backup_with_failpoints, restore_backup, restore_backup_trusted,
    restore_backup_with_failpoints, verify_backup, verify_backup_trusted,
};
pub use blob::{
    BlobError, BlobErrorCode, BlobFailpoint, GarbageCollectionPolicy, GarbageCollectionReport,
    LocalBlobStore, LocalRepositoryBlobStore, MultiTenantLocalRepositoryBlobStore,
    ReconciliationReport, RepositoryBlobStore, RepositoryGarbageCollectionCandidate,
    RepositoryGarbageCollectionReport, SharedGarbageCollectionAuthorization,
};
pub use gc::{
    GarbageCollectionPlan, GarbageCollectionPlanError, GarbageCollectionPlanErrorCode,
    GarbageCollectionPlanIdentity, GarbageCollectionPlanSignatureIdentity,
    SignedGarbageCollectionPlan, VerifiedGarbageCollectionPlan, sign_garbage_collection_plan,
    verify_garbage_collection_plan_trusted,
};
pub use memory::{InMemoryReadTransaction, InMemoryStore, InMemoryWriteTransaction};
pub use migration::{
    MAX_MIGRATION_ENTRIES, MigrationCompatibility, MigrationCompatibilityError,
    MigrationDefinition, MigrationLedgerEntry, MigrationMode, MigrationPlan,
};
pub use model::{
    AccessContext, AtomCursor, AtomPage, AtomSelector, BlobRecord, CancellationToken,
    CommitReceipt, EffectRecordEnvelope, IdempotencyIdentity, MAX_ATOM_BATCH_ITEMS, OutboxMessage,
    OutboxRecord, ReadTransaction, Repository, SnapshotSelection, StoreError, StoreErrorCode,
    StoreRevision, WriteTransaction,
};
pub use object::{
    InMemoryObjectStorage, ObjectBackupEntry, ObjectBackupInventory, ObjectCopyEvidence,
    ObjectFailpoint, ObjectRepositoryBlobStore, ObjectRestoreReceipt, ObjectStorage,
    ObjectStorageError, ObjectStorageErrorCode, ObjectStorageIdentity, ObjectWriteOutcome,
    S3CompatibleObjectStorage, restore_object_backup_inventory,
};
#[cfg(any(test, feature = "migration-fault-injection"))]
pub use postgres::PostgresMigrationFailpoint;
pub use postgres::{
    MAX_RETAINED_POSTGRES_TENANT_SNAPSHOTS, MAX_RETAINED_POSTGRES_WAKEUPS_PER_TENANT,
    PostgresBackupInventory, PostgresBackupRestoreReceipt, PostgresBackupSignatureIdentity,
    PostgresBackupSnapshot, PostgresConfiguration, PostgresDatabaseBackupArtifact,
    PostgresDatabaseRestoreReceipt, PostgresFailpoint, PostgresMigrationBackupEntry,
    PostgresMigrationReceipt, PostgresReadConsistency, PostgresStore,
    PostgresTenantBackupInventory, PostgresWriteTransaction, SharedWakeup, SharedWakeupClaim,
    SignedPostgresBackupInventory, VerifiedPostgresDatabaseBackup, sign_postgres_backup_inventory,
    verify_postgres_backup_inventory, verify_postgres_backup_inventory_trusted,
    verify_postgres_database_backup,
};
pub use service_repository::{
    EffectRecoveryCursor, EffectRecoveryItem, EffectRecoveryPage, EffectRecoveryQuery,
    MAX_RETAINED_SERVICE_IDEMPOTENCY_ENTRIES, MAX_RETAINED_SERVICE_RECORD_KEYS,
    MAX_RETAINED_SERVICE_STATE_BYTES, MAX_RETAINED_SERVICE_VERSIONS_PER_KEY,
    MAX_RETAINED_SERVICE_VERSIONS_PER_TENANT, MAX_SERVICE_BATCH_BYTES, MAX_SERVICE_BATCH_RECORDS,
    MAX_SERVICE_KEY_BYTES, MAX_SERVICE_NAMESPACE_BYTES, MAX_SERVICE_PAGE_ITEMS,
    MAX_SERVICE_RECORD_BYTES, MAX_SERVICE_RESPONSE_BYTES, MAX_WORKER_CURSOR_BYTES,
    MAX_WORKER_SELECTOR_BYTES, OutboxRecoveryCursor, OutboxRecoveryPage, OutboxRecoveryQuery,
    ServiceBatch, ServiceBatchReceipt, ServiceError, ServiceErrorCode, ServiceExpectedVersion,
    ServiceIdempotency, ServiceListCursor, ServiceListPage, ServiceListQuery, ServiceListScope,
    ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordVersion,
    ServiceRecordWrite, ServiceRepository, ServiceResponse, WorkerLocator, WorkerState,
    WorkerUpdate,
};
#[cfg(any(test, feature = "migration-fault-injection"))]
pub use sqlite::SqliteMigrationFailpoint;
pub use sqlite::{
    MAX_LARGE_LOCAL_ATOMS, MAX_LARGE_LOCAL_EDGES, MAX_LARGE_LOCAL_REFERENCED_BLOB_BYTES,
    MAX_LARGE_LOCAL_SQLITE_DATABASE_BYTES, MAX_RETAINED_SQLITE_PROJECTION_GENERATIONS,
    MAX_RETAINED_SQLITE_SNAPSHOTS, MAX_SQLITE_DATABASE_BYTES, MAX_SQLITE_PROJECTION_ATOMS,
    MIN_LARGE_LOCAL_AVAILABLE_BYTES, MIN_LARGE_LOCAL_RUNTIME_RESERVE_BYTES, SqliteCapacityProfile,
    SqliteCatalogStatistics, SqliteConfiguration, SqliteDeepIntegrityReport, SqliteFailpoint,
    SqliteProjectionFailpoint, SqliteProjectionStatus, SqliteReadTransaction,
    SqliteStorageStatistics, SqliteStore, SqliteWriteTransaction,
};

/// Reusable black-box repository behavior suite.
pub mod conformance;
