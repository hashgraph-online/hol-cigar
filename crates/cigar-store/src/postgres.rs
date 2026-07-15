//! PostgreSQL shared profile with tenant-partitioned MVCC, RLS, and fenced workers.

use crate::memory::{
    CommittedState, InMemoryReadTransaction, StagedMutation, TenantState, apply_mutation,
    blob_digest, validate,
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
    GarbageCollectionPolicy, IdempotencyIdentity, ObjectBackupInventory, ObjectCopyEvidence,
    ObjectRestoreReceipt, OutboxMessage, Repository, RepositoryGarbageCollectionCandidate,
    RepositoryGarbageCollectionReport, SnapshotSelection, StoreError, StoreErrorCode,
    StoreRevision, WriteTransaction,
};
use cigar_crypto::{
    KeyAlgorithm, KeyProvider, KeyRef, SignatureEnvelope, SignatureRequest, SignatureVerification,
};
use cigar_protocol::{
    BlobRef, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, EffectJournalEvent,
    RecordId, SourceSnapshot, VersionId,
};
use fallible_iterator::FallibleIterator;
use postgres::config::{Host, SslMode};
use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::{GenericClient, IsolationLevel, Transaction};
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_postgres_rustls::MakeRustlsConnect;

#[derive(Clone, Copy)]
struct PostgresMigrationSource {
    name: &'static str,
    sql: &'static str,
    minimum_application_major: i32,
    maximum_application_major: i32,
    online: bool,
}

const MIGRATIONS: &[PostgresMigrationSource] = &[
    PostgresMigrationSource {
        name: "shared_metadata",
        sql: include_str!("../migrations/postgres/0001_shared_metadata.sql"),
        minimum_application_major: 1,
        maximum_application_major: 2,
        online: true,
    },
    PostgresMigrationSource {
        name: "object_outbox",
        sql: include_str!("../migrations/postgres/0002_object_outbox.sql"),
        minimum_application_major: 1,
        maximum_application_major: 2,
        online: true,
    },
    PostgresMigrationSource {
        name: "atom_projection",
        sql: include_str!("../migrations/postgres/0003_atom_projection.sql"),
        minimum_application_major: 1,
        maximum_application_major: 2,
        online: true,
    },
    PostgresMigrationSource {
        name: "gc_revision_guard",
        sql: include_str!("../migrations/postgres/0004_gc_revision_guard.sql"),
        minimum_application_major: 1,
        maximum_application_major: 2,
        online: true,
    },
];
const MIGRATION_LOCK_KEY: i64 = 4_843_415_282_449_238_323;
const BACKUP_GC_LOCK_KEY: i64 = 4_843_415_282_449_238_324;
const MAX_WAKEUP_CLAIMS: usize = 1_000;
/// Maximum full tenant snapshots retained by the shared profile.
pub const MAX_RETAINED_POSTGRES_TENANT_SNAPSHOTS: usize = 1_024;
/// Maximum unclaimed repository wakeups retained for one tenant.
pub const MAX_RETAINED_POSTGRES_WAKEUPS_PER_TENANT: usize = 4_096;
const MAX_ATOM_PROJECTION_RESTORE_ITEMS: usize = 10_000;
const MAX_ATOM_PROJECTION_RESTORE_BYTES: usize = 67_108_864;
const MAX_DATABASE_BACKUP_BYTES: u64 = 17_592_186_044_416;
const POSTGRES_BACKUP_FORMAT_VERSION: u8 = 2;
const POSTGRES_BACKUP_ARCHIVE_FORMAT: &str = "pg_dump-custom-v1";
const POSTGRES_BACKUP_SIGNATURE_PURPOSE: &str = "postgres-backup-inventory-v2";
const APPLICATION_MAJOR: i32 = 1;
const MAX_POSTGRES_CA_PEM_BYTES: usize = 2 * 1024 * 1024;
const MAX_POSTGRES_CA_CERTIFICATES: usize = 64;
const POSTGRES_FIXED_OPTIONS: &str = "-c search_path=public,pg_catalog,pg_temp";

#[derive(Clone, Eq, PartialEq)]
enum PostgresTrustRoots {
    WebPki,
    Explicit(Vec<Vec<u8>>),
}

/// Certificate-verified TLS identity and trust roots for PostgreSQL.
#[derive(Clone, Eq, PartialEq)]
struct PostgresTlsConfiguration {
    server_name: String,
    trust_roots: PostgresTrustRoots,
}

impl PostgresTlsConfiguration {
    fn webpki(server_name: String) -> Result<Self, StoreError> {
        validate_postgres_server_name(&server_name)?;
        Ok(Self {
            server_name,
            trust_roots: PostgresTrustRoots::WebPki,
        })
    }

    fn explicit(server_name: String, certificate_authority_pem: &[u8]) -> Result<Self, StoreError> {
        validate_postgres_server_name(&server_name)?;
        if certificate_authority_pem.is_empty()
            || certificate_authority_pem.len() > MAX_POSTGRES_CA_PEM_BYTES
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let certificates = CertificateDer::pem_slice_iter(certificate_authority_pem)
            .map(|certificate| {
                certificate
                    .map(|certificate| certificate.as_ref().to_vec())
                    .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() || certificates.len() > MAX_POSTGRES_CA_CERTIFICATES {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let configuration = Self {
            server_name,
            trust_roots: PostgresTrustRoots::Explicit(certificates),
        };
        configuration.connector()?;
        Ok(configuration)
    }

    fn connector(&self) -> Result<MakeRustlsConnect, StoreError> {
        let roots = match &self.trust_roots {
            PostgresTrustRoots::WebPki => RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            PostgresTrustRoots::Explicit(certificates) => {
                let mut roots = RootCertStore::empty();
                for certificate in certificates {
                    roots
                        .add(CertificateDer::from(certificate.clone()))
                        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?;
                }
                roots
            }
        };
        let configuration =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(MakeRustlsConnect::new(configuration))
    }
}

/// Bounded PostgreSQL pool and transaction timeout configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct PostgresConfiguration {
    database_url: String,
    tls: PostgresTlsConfiguration,
    /// Minimum warm connections retained by the pool.
    pub minimum_connections: u32,
    /// Hard connection-pool bound.
    pub maximum_connections: u32,
    /// Maximum time to acquire a connection.
    pub acquire_timeout: Duration,
    /// PostgreSQL statement timeout applied inside every transaction.
    pub statement_timeout: Duration,
    /// PostgreSQL lock timeout applied inside every transaction.
    pub lock_timeout: Duration,
    /// PostgreSQL idle-in-transaction timeout.
    pub idle_transaction_timeout: Duration,
    /// Hard wall-clock bound for one exported-snapshot backup transaction.
    pub backup_timeout: Duration,
}

impl PostgresConfiguration {
    /// Creates the production defaults for one explicit PostgreSQL connection URL.
    pub fn new(database_url: impl Into<String>) -> Result<Self, StoreError> {
        let database_url = database_url.into();
        let parsed = postgres::Config::from_str(&database_url)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?;
        let tls = PostgresTlsConfiguration::webpki(postgres_server_name(&parsed)?.to_owned())?;
        let configuration = Self {
            database_url,
            tls,
            minimum_connections: 2,
            maximum_connections: 32,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            lock_timeout: Duration::from_secs(5),
            idle_transaction_timeout: Duration::from_secs(30),
            backup_timeout: Duration::from_secs(4 * 60 * 60),
        };
        configuration.validate()?;
        Ok(configuration)
    }

    /// Creates production defaults with an explicit bounded PostgreSQL CA bundle.
    pub fn new_with_certificate_authority(
        database_url: impl Into<String>,
        server_name: impl Into<String>,
        certificate_authority_pem: &[u8],
    ) -> Result<Self, StoreError> {
        let mut configuration = Self::new(database_url)?;
        configuration.configure_certificate_authority(server_name, certificate_authority_pem)?;
        Ok(configuration)
    }

    /// Replaces public WebPKI roots with one bounded explicit PostgreSQL CA bundle.
    ///
    /// `server_name` must exactly match the single TCP `host` in `database_url`. A separate
    /// `hostaddr` may select the network address while preserving this certificate identity.
    pub fn configure_certificate_authority(
        &mut self,
        server_name: impl Into<String>,
        certificate_authority_pem: &[u8],
    ) -> Result<(), StoreError> {
        let tls =
            PostgresTlsConfiguration::explicit(server_name.into(), certificate_authority_pem)?;
        let parsed = postgres::Config::from_str(&self.database_url)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?;
        validate_postgres_tls_binding(&parsed, &tls)?;
        self.tls = tls;
        Ok(())
    }

    /// Validates all pool and timeout bounds without exposing the URL.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.database_url.is_empty()
            || self.database_url.len() > 8_192
            || self.minimum_connections == 0
            || self.maximum_connections < self.minimum_connections
            || self.maximum_connections > 256
            || self.acquire_timeout.is_zero()
            || self.acquire_timeout > Duration::from_secs(60)
            || self.statement_timeout.is_zero()
            || self.statement_timeout > Duration::from_secs(300)
            || self.lock_timeout.is_zero()
            || self.lock_timeout > self.statement_timeout
            || self.idle_transaction_timeout.is_zero()
            || self.idle_transaction_timeout > Duration::from_secs(300)
            || self.backup_timeout < Duration::from_secs(60)
            || self.backup_timeout > Duration::from_secs(24 * 60 * 60)
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let configuration = self.connection_configuration()?;
        validate_postgres_tls_binding(&configuration, &self.tls)?;
        self.tls.connector().map(|_connector| ())
    }

    fn connection_configuration(&self) -> Result<postgres::Config, StoreError> {
        let mut configuration = postgres::Config::from_str(&self.database_url)
            .map_err(|_error| StoreError::new(StoreErrorCode::InvalidContext))?;
        if configuration.get_options().is_some() {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        validate_postgres_tls_binding(&configuration, &self.tls)?;
        // Do not let a caller-controlled DSN or server-side role default redirect
        // unqualified protocol relations. Explicitly listing pg_temp last also prevents
        // temporary relations from shadowing the durable public-schema objects.
        configuration.options(POSTGRES_FIXED_OPTIONS);
        configuration.ssl_mode(SslMode::Require);
        Ok(configuration)
    }
}

fn postgres_server_name(configuration: &postgres::Config) -> Result<&str, StoreError> {
    match configuration.get_hosts() {
        [] => Ok("localhost"),
        [Host::Tcp(server_name)] if !server_name.is_empty() => Ok(server_name),
        _ => Err(StoreError::new(StoreErrorCode::InvalidContext)),
    }
}

fn validate_postgres_server_name(server_name: &str) -> Result<(), StoreError> {
    if server_name.is_empty()
        || server_name.len() > 253
        || !server_name.bytes().all(|byte| byte.is_ascii_graphic())
        || server_name.contains(['/', '\\', '@'])
        || ServerName::try_from(server_name.to_owned()).is_err()
    {
        Err(StoreError::new(StoreErrorCode::InvalidContext))
    } else {
        Ok(())
    }
}

fn validate_postgres_tls_binding(
    configuration: &postgres::Config,
    tls: &PostgresTlsConfiguration,
) -> Result<(), StoreError> {
    validate_postgres_server_name(&tls.server_name)?;
    if postgres_server_name(configuration)? != tls.server_name {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(())
}

impl fmt::Debug for PostgresConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresConfiguration")
            .field("database_url", &"[REDACTED]")
            .field("tls_server_name", &self.tls.server_name)
            .field(
                "tls_trust_roots",
                &match &self.tls.trust_roots {
                    PostgresTrustRoots::WebPki => "webpki",
                    PostgresTrustRoots::Explicit(_) => "explicit",
                },
            )
            .field("minimum_connections", &self.minimum_connections)
            .field("maximum_connections", &self.maximum_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("lock_timeout", &self.lock_timeout)
            .field("idle_transaction_timeout", &self.idle_transaction_timeout)
            .field("backup_timeout", &self.backup_timeout)
            .finish()
    }
}

/// Named one-shot shared-profile publication boundaries.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PostgresFailpoint {
    /// After the serializable transaction and global revision row lock are acquired.
    AfterRevisionLock,
    /// After object publication but before tenant metadata insertion.
    AfterBlobPublication,
    /// After all metadata rows are inserted but before commit.
    BeforeCommit,
}

/// One durable commit wakeup visible to shared workers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedWakeup {
    /// Tenant partition owning the event.
    pub tenant_id: RecordId,
    /// Causal repository revision.
    pub revision: StoreRevision,
    /// Stable bounded routing topic.
    pub topic: String,
}

/// Fenced claim over one shared wakeup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedWakeupClaim {
    /// Claimed wakeup.
    pub wakeup: SharedWakeup,
    /// Monotonic claim fence for this worker and item.
    pub fencing_token: u64,
    /// Exact bounded claim owner.
    pub owner: String,
}

/// Result of an owner-authorized append-only migration run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresMigrationReceipt {
    /// Latest installed migration sequence.
    pub latest_sequence: u32,
    /// Number of embedded migration checksums verified after installation.
    pub checksums_verified: u32,
}

/// One-shot PostgreSQL migration boundary available only to explicit qualification builds.
#[cfg(any(test, feature = "migration-fault-injection"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresMigrationFailpoint {
    /// After durable creation/verification of the migration-ledger table.
    AfterLedgerBootstrap,
    /// After acquiring the transaction-scoped migration advisory lock.
    AfterAdvisoryLock,
    /// After one missing migration's DDL executes inside the transaction.
    AfterMigrationSql(u32),
    /// After the matching immutable ledger row is inserted inside the transaction.
    AfterLedgerInsert(u32),
    /// Immediately before committing the serializable migration transaction.
    BeforeCommit,
    /// Immediately after commit, modeling an ambiguous client outcome recovered by verification.
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostgresMigrationBoundary {
    AfterLedgerBootstrap,
    AfterAdvisoryLock,
    AfterMigrationSql(u32),
    AfterLedgerInsert(u32),
    BeforeCommit,
    AfterCommit,
}

#[cfg(any(test, feature = "migration-fault-injection"))]
impl From<PostgresMigrationBoundary> for PostgresMigrationFailpoint {
    fn from(boundary: PostgresMigrationBoundary) -> Self {
        match boundary {
            PostgresMigrationBoundary::AfterLedgerBootstrap => Self::AfterLedgerBootstrap,
            PostgresMigrationBoundary::AfterAdvisoryLock => Self::AfterAdvisoryLock,
            PostgresMigrationBoundary::AfterMigrationSql(sequence) => {
                Self::AfterMigrationSql(sequence)
            }
            PostgresMigrationBoundary::AfterLedgerInsert(sequence) => {
                Self::AfterLedgerInsert(sequence)
            }
            PostgresMigrationBoundary::BeforeCommit => Self::BeforeCommit,
            PostgresMigrationBoundary::AfterCommit => Self::AfterCommit,
        }
    }
}

/// Read-routing guarantee for the shared transactional profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresReadConsistency {
    /// Every repository and service read uses the authoritative primary pool.
    PrimaryOnly,
}

/// One tenant partition bound into a consistent PostgreSQL backup inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresTenantBackupInventory {
    /// Exact tenant partition.
    pub tenant_id: RecordId,
    /// Latest tenant-state revision visible in the consistent snapshot, when any.
    pub state_revision: Option<StoreRevision>,
    /// Checksum of exact protected tenant-state bytes, when any.
    pub state_checksum: Option<String>,
    /// Exact number of retained tenant-state history rows.
    pub state_history_count: u64,
    /// Ordered root over every protected retained tenant-state row.
    pub state_history_root: String,
    /// Exact number of normalized immutable atom rows in the exported snapshot.
    pub atom_projection_count: u64,
    /// Ordered root over every normalized immutable atom row and protected record bytes.
    pub atom_projection_root: String,
    /// Exact number of wakeup, object-commit, and worker-claim rows.
    pub operational_row_count: u64,
    /// Ordered root over wakeup, object-commit, and worker-claim rows.
    pub operational_root: String,
}

/// One exact append-only migration row bound into a PostgreSQL backup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresMigrationBackupEntry {
    /// Contiguous one-based migration sequence.
    pub sequence: u32,
    /// Stable migration name.
    pub name: String,
    /// SHA-256 multihash of the exact migration source.
    pub checksum: String,
    /// Oldest compatible application major.
    pub minimum_application_major: i32,
    /// Newest compatible application major.
    pub maximum_application_major: i32,
    /// Whether the migration is declared rolling-compatible.
    pub online: bool,
    /// Exact durable migration application time in Unix microseconds.
    pub applied_at_unix_micros: i64,
}

/// Exact database-native archive produced from an exported PostgreSQL snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresDatabaseBackupArtifact {
    /// Exact supported archive encoding.
    pub archive_format: String,
    /// Exact archive byte length.
    pub archive_size_bytes: u64,
    /// SHA-256 multihash of the complete archive bytes.
    pub archive_checksum: String,
    /// Content-free SHA-256 multihash identifying the source database.
    pub source_database_identity: String,
    /// SHA-256 multihash of the exact `pg_export_snapshot` token used by `pg_dump`.
    pub exported_snapshot_checksum: String,
    /// SHA-256 multihash of `txid_current_snapshot()` in the exporting transaction.
    pub transaction_snapshot_checksum: String,
}

/// Opaque exact archive capability returned only after streaming size/checksum verification.
///
/// Reading this value streams the same verified bytes that must be supplied to `pg_restore`.
/// Activation refuses a capability that was not consumed completely.
pub struct VerifiedPostgresDatabaseBackup<R> {
    archive: R,
    artifact: PostgresDatabaseBackupArtifact,
    bytes_consumed: u64,
    consumption_digest: Sha256,
}

impl<R: Read> Read for VerifiedPostgresDatabaseBackup<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.archive.read(buffer)?;
        self.bytes_consumed = self
            .bytes_consumed
            .checked_add(u64::try_from(read).map_err(|_error| {
                std::io::Error::other("verified archive read length exceeds u64")
            })?)
            .ok_or_else(|| std::io::Error::other("verified archive read length overflow"))?;
        if self.bytes_consumed > self.artifact.archive_size_bytes {
            return Err(std::io::Error::other(
                "verified archive was consumed beyond its bound",
            ));
        }
        self.consumption_digest.update(
            buffer
                .get(..read)
                .ok_or_else(|| std::io::Error::other("verified archive read bound was invalid"))?,
        );
        Ok(read)
    }
}

/// Read-only capability passed to the database-native backup driver while its snapshot is open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresBackupSnapshot {
    /// Exact ephemeral snapshot token that must be supplied to `pg_dump --snapshot`.
    pub exported_snapshot: String,
    /// Signed-safe digest of the ephemeral exported snapshot token.
    pub exported_snapshot_checksum: String,
    /// Exact transaction snapshot observed by the exporting transaction.
    pub transaction_snapshot: String,
    /// Signed-safe digest of the transaction snapshot.
    pub transaction_snapshot_checksum: String,
    /// Identity derived from the exporting cluster system identifier and database OID.
    pub source_database_identity: String,
    /// Exact repository revision visible to the export.
    pub repository_revision: StoreRevision,
    /// Exact number of global revision-history rows visible to the export.
    pub revision_history_count: u64,
    /// Ordered root over the complete global revision history.
    pub revision_history_root: String,
    /// Complete append-only migration inventory visible to the export.
    pub migrations: Vec<PostgresMigrationBackupEntry>,
    /// Complete owner-authorized tenant inventory visible to the export.
    pub tenants: Vec<PostgresTenantBackupInventory>,
    /// Exact metadata-reachable live object set to copy into a backup namespace.
    pub live_objects: ObjectBackupInventory,
}

/// Evidence that an exact signed PostgreSQL archive was restored into a fresh database.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresDatabaseRestoreReceipt {
    /// Source database identity bound into the signed archive.
    source_database_identity: String,
    /// Content-free identity of the fresh restored database.
    destination_database_identity: String,
    /// Exact archive encoding consumed by restore.
    archive_format: String,
    /// Exact archive byte length consumed by restore.
    archive_size_bytes: u64,
    /// SHA-256 multihash of the exact archive bytes consumed by restore.
    archive_checksum: String,
    /// Repository revision observed after restore.
    repository_revision: StoreRevision,
    /// SHA-256 multihash of the complete restored migration inventory.
    migration_inventory_root: String,
    /// SHA-256 multihash of the complete restored tenant set.
    tenant_set_checksum: String,
}

/// Database and object receipts required before a restored backup can be activated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresBackupRestoreReceipt {
    /// Fresh database restore evidence.
    database: PostgresDatabaseRestoreReceipt,
    /// Fresh object namespace restore evidence.
    objects: ObjectRestoreReceipt,
}

/// CIGAR inventory accompanying a database-native PostgreSQL backup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresBackupInventory {
    /// Inventory format version, currently two.
    pub format_version: u8,
    /// Latest installed shared migration sequence.
    pub migration_sequence: u32,
    /// Exact consistent global repository revision.
    pub repository_revision: StoreRevision,
    /// Exact number of global revision-history rows.
    pub revision_history_count: u64,
    /// Ordered root over the complete global revision history.
    pub revision_history_root: String,
    /// Trusted backup operation time in Unix nanoseconds.
    pub created_at_unix_nanos: i128,
    /// Exact database-native archive captured from the exported snapshot.
    pub database: PostgresDatabaseBackupArtifact,
    /// Complete append-only migration inventory and checksums.
    pub migrations: Vec<PostgresMigrationBackupEntry>,
    /// SHA-256 multihash of the complete migration inventory.
    pub migration_inventory_root: String,
    /// SHA-256 multihash of the complete owner-authorized tenant set.
    pub tenant_set_checksum: String,
    /// Strictly sorted complete tenant inventory.
    pub tenants: Vec<PostgresTenantBackupInventory>,
    /// Exact encrypted object set in a self-contained backup namespace.
    pub objects: ObjectBackupInventory,
    /// Verified live-to-backup object copy receipt.
    pub object_copy_receipt: ObjectCopyEvidence,
    /// Domain-separated SHA-256 multihash over every preceding semantic field.
    pub canonical_root: String,
}

/// Purpose-bound signed PostgreSQL backup inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPostgresBackupInventory {
    /// Exact inventory that accompanied the database-native backup.
    pub inventory: PostgresBackupInventory,
    /// Opaque tenant-scoped signing key reference.
    pub signing_key: KeyRef,
    /// Exact tenant scope of the backup signing key.
    pub signing_tenant: String,
    /// Authenticated operator principal.
    pub signer: String,
    /// Signature time in Unix nanoseconds.
    pub signed_at_unix_nanos: i128,
    /// Exact Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

/// Persisted signer identity evaluated against current production trust during verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresBackupSignatureIdentity {
    /// Exact tenant scope of the signing key.
    pub signing_tenant: String,
    /// Authenticated operator principal embedded in the signature.
    pub signer: String,
    /// Opaque historical signing-key reference.
    pub signing_key: KeyRef,
    /// Trusted signature time in Unix nanoseconds.
    pub signed_at_unix_nanos: i128,
}

type Manager = PostgresConnectionManager<MakeRustlsConnect>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostgresAuthority {
    Runtime,
    Backup,
    GarbageCollection,
}

/// PostgreSQL repository whose stored state rows each contain exactly one tenant partition.
pub struct PostgresStore {
    pool: Pool<Manager>,
    configuration: PostgresConfiguration,
    authority: PostgresAuthority,
    blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
    fail_next_commit: AtomicBool,
    failpoints: Mutex<BTreeSet<PostgresFailpoint>>,
}

impl fmt::Debug for PostgresStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PostgresStore([REDACTED])")
    }
}

impl PostgresStore {
    /// Opens and verifies an already-migrated shared metadata repository.
    ///
    /// This path executes no DDL and works for a non-owner runtime role without `BYPASSRLS`.
    pub fn connect(configuration: PostgresConfiguration) -> Result<Self, StoreError> {
        Self::connect_internal(configuration, None, PostgresAuthority::Runtime)
    }

    /// Applies append-only migrations using an explicit owner/migrator connection.
    pub fn migrate(
        configuration: &PostgresConfiguration,
    ) -> Result<PostgresMigrationReceipt, StoreError> {
        configuration.validate()?;
        let postgres_configuration = configuration.connection_configuration()?;
        let tls_connector = configuration.tls.connector()?;
        let mut connection = postgres_configuration
            .connect(tls_connector)
            .map_err(postgres_error)?;
        migrate(&mut connection)?;
        verify_schema(&mut connection)?;
        verify_migrations(&mut connection)
    }

    /// Runs the real migrator with one injected boundary failure for external qualification.
    ///
    /// This API is absent from default builds. Qualification must use a disposable retained
    /// database and rerun the normal migrator plus semantic verification after every injected
    /// error, including the ambiguous `AfterCommit` outcome.
    #[cfg(feature = "migration-fault-injection")]
    pub fn migrate_with_failpoint(
        configuration: &PostgresConfiguration,
        failpoint: PostgresMigrationFailpoint,
    ) -> Result<PostgresMigrationReceipt, StoreError> {
        configuration.validate()?;
        let postgres_configuration = configuration.connection_configuration()?;
        let tls_connector = configuration.tls.connector()?;
        let mut connection = postgres_configuration
            .connect(tls_connector)
            .map_err(postgres_error)?;
        migrate_with_observer(&mut connection, |boundary| {
            if PostgresMigrationFailpoint::from(boundary) == failpoint {
                Err(StoreError::new(StoreErrorCode::InjectedAbort))
            } else {
                Ok(())
            }
        })?;
        verify_schema(&mut connection)?;
        verify_migrations(&mut connection)
    }

    /// Qualification-only process abort at one exact PostgreSQL migration boundary.
    ///
    /// This API is available only with `migration-fault-injection`. The caller must target a
    /// disposable database owned by the authenticated migrator role.
    #[cfg(feature = "migration-fault-injection")]
    pub fn migrate_with_process_abort(
        configuration: &PostgresConfiguration,
        failpoint: PostgresMigrationFailpoint,
    ) -> Result<PostgresMigrationReceipt, StoreError> {
        configuration.validate()?;
        let postgres_configuration = configuration.connection_configuration()?;
        let tls_connector = configuration.tls.connector()?;
        let mut connection = postgres_configuration
            .connect(tls_connector)
            .map_err(postgres_error)?;
        migrate_with_observer(&mut connection, |boundary| {
            if PostgresMigrationFailpoint::from(boundary) == failpoint {
                std::process::abort();
            }
            Ok(())
        })?;
        verify_schema(&mut connection)?;
        verify_migrations(&mut connection)
    }

    /// Explicit test/development convenience that migrates before opening the runtime pool.
    pub fn connect_and_migrate(configuration: PostgresConfiguration) -> Result<Self, StoreError> {
        Self::migrate(&configuration)?;
        Self::connect(configuration)
    }

    /// Opens the shared metadata repository with an encrypted object-CAS adapter.
    pub fn connect_with_blob_repository(
        configuration: PostgresConfiguration,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
    ) -> Result<Self, StoreError> {
        Self::connect_internal(
            configuration,
            Some(blob_repository),
            PostgresAuthority::Runtime,
        )
    }

    /// Opens a read-only cross-tenant backup/restore store under a dedicated backup principal.
    ///
    /// The connected role must be a non-superuser `BYPASSRLS` principal, must not own the
    /// database, must be able to call `pg_control_system()`, and must not be able to execute the
    /// repository GC revision guard. Runtime and GC principals fail closed at construction.
    pub fn connect_backup_with_blob_repository(
        configuration: PostgresConfiguration,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
    ) -> Result<Self, StoreError> {
        Self::connect_internal(
            configuration,
            Some(blob_repository),
            PostgresAuthority::Backup,
        )
    }

    /// Opens a cross-tenant physical-GC store under a dedicated GC principal.
    ///
    /// The connected role must be a non-superuser `BYPASSRLS` principal, must not own the
    /// database, must be able to execute only the repository GC revision guard, and must not be
    /// able to call `pg_control_system()`. Runtime and backup principals fail closed.
    pub fn connect_garbage_collection_with_blob_repository(
        configuration: PostgresConfiguration,
        blob_repository: Arc<dyn crate::RepositoryBlobStore>,
    ) -> Result<Self, StoreError> {
        Self::connect_internal(
            configuration,
            Some(blob_repository),
            PostgresAuthority::GarbageCollection,
        )
    }

    fn connect_internal(
        configuration: PostgresConfiguration,
        blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
        authority: PostgresAuthority,
    ) -> Result<Self, StoreError> {
        configuration.validate()?;
        let postgres_configuration = configuration.connection_configuration()?;
        let tls_connector = configuration.tls.connector()?;
        let manager = PostgresConnectionManager::new(postgres_configuration, tls_connector);
        let pool = Pool::builder()
            .min_idle(Some(configuration.minimum_connections))
            .max_size(configuration.maximum_connections)
            .connection_timeout(configuration.acquire_timeout)
            .build(manager)
            .map_err(pool_error)?;
        {
            let mut connection = pool.get().map_err(pool_error)?;
            verify_schema(&mut connection)?;
            verify_migrations(&mut *connection)?;
            verify_connection_authority(&mut *connection, authority)?;
        }
        Ok(Self {
            pool,
            configuration,
            authority,
            blob_repository,
            fail_next_commit: AtomicBool::new(false),
            failpoints: Mutex::new(BTreeSet::new()),
        })
    }

    /// Returns the current global MVCC revision.
    pub fn revision(&self) -> Result<StoreRevision, StoreError> {
        self.require_configured_authority(PostgresAuthority::Runtime)?;
        let mut connection = self.connection()?;
        verify_connection_authority(&mut *connection, PostgresAuthority::Runtime)?;
        current_revision(&mut *connection)
    }

    /// Returns the fixed read-routing policy; stale replicas are never used for semantic reads.
    #[must_use]
    pub const fn read_consistency(&self) -> PostgresReadConsistency {
        PostgresReadConsistency::PrimaryOnly
    }

    /// Verifies the complete embedded migration sequence without executing DDL.
    pub fn verify_migration_level(&self) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        verify_schema(&mut connection)?;
        verify_migrations(&mut *connection).map(|_receipt| ())
    }

    /// Counts normalized production atom rows visible to one tenant under forced RLS.
    pub fn atom_projection_count(&self, tenant: &RecordId) -> Result<u64, StoreError> {
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, tenant)?;
        let count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM cigar_atom_projection WHERE tenant_id = $1",
                &[&tenant.as_str()],
            )
            .map_err(postgres_error)?
            .get(0);
        transaction.commit().map_err(postgres_error)?;
        u64::try_from(count).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }

    /// Resolves and integrity-checks one exact atom directly from the normalized projection.
    pub fn atom_projection_get(
        &self,
        tenant: &RecordId,
        version: &VersionId,
    ) -> Result<Option<ContextAtomV1>, StoreError> {
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, tenant)?;
        let row = transaction
            .query_opt(
                "SELECT atom_id, lineage_id, record, record_checksum
                 FROM cigar_atom_projection
                 WHERE tenant_id = $1 AND version_id = $2",
                &[&tenant.as_str(), &version.as_str()],
            )
            .map_err(postgres_error)?;
        let atom = row
            .map(|row| decode_projection_row(tenant, version, &row))
            .transpose()?;
        transaction.commit().map_err(postgres_error)?;
        Ok(atom)
    }

    /// Restores one bounded, validated atom batch into the production projection.
    ///
    /// Every row is a real `ContextAtomV1`: it is tenant-checked, encoded, checksummed, inserted
    /// under forced RLS, and reread before the serializable transaction commits. Exact repeats are
    /// idempotent while any immutable identity collision fails closed.
    pub fn restore_atom_projection_batch(
        &self,
        tenant: &RecordId,
        published_revision: StoreRevision,
        atoms: &[ContextAtomV1],
    ) -> Result<u64, StoreError> {
        let records = prepare_projection_records(tenant, atoms)?;
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, tenant)?;
        ensure_repository_revision(&mut transaction, published_revision)?;
        let inserted =
            insert_projection_records(&mut transaction, tenant, published_revision, &records)?;
        verify_projection_records(&mut transaction, tenant, &records)?;
        transaction.commit().map_err(postgres_error)?;
        Ok(inserted)
    }

    /// Rebuilds missing normalized rows from the authoritative latest tenant snapshot.
    ///
    /// Separately restored immutable projection rows are retained. Existing rows must match the
    /// snapshot byte-for-byte, so rebuild cannot silently repair an identity or checksum conflict.
    pub fn rebuild_atom_projection(&self, tenant: &RecordId) -> Result<u64, StoreError> {
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, tenant)?;
        let revision = current_revision(&mut transaction)?;
        let state = load_state_at_revision(&mut transaction, tenant, revision)?;
        let atoms = state
            .tenants
            .get(tenant)
            .map(|state| state.atoms.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut rebuilt = 0_u64;
        for chunk in atoms.chunks(MAX_ATOM_PROJECTION_RESTORE_ITEMS) {
            let records = prepare_projection_records(tenant, chunk)?;
            rebuilt = rebuilt
                .checked_add(insert_projection_records(
                    &mut transaction,
                    tenant,
                    revision,
                    &records,
                )?)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            verify_projection_records(&mut transaction, tenant, &records)?;
        }
        transaction.commit().map_err(postgres_error)?;
        Ok(rebuilt)
    }

    /// Performs an encrypted object write/read/delete readiness proof.
    pub fn blob_readiness_probe(
        &self,
        tenant: &RecordId,
        blob: &BlobRecord,
    ) -> Result<(), StoreError> {
        self.require_configured_authority(PostgresAuthority::Runtime)?;
        self.blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?
            .readiness_probe(tenant, blob)
    }

    /// Verifies all live metadata roots and removes globally abandoned staging objects.
    pub fn reconcile_blob_roots(&self, tenants: &[RecordId]) -> Result<(), StoreError> {
        if tenants.is_empty()
            || tenants.len() > 65_536
            || tenants.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_some_and(|(left, right)| left >= right)
            })
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let mut live = BTreeMap::new();
        for tenant in tenants {
            let state = self.load_service_state(tenant, SnapshotSelection::Latest)?;
            let digests = state
                .tenants
                .get(tenant)
                .map(|state| state.blobs.keys().cloned().collect())
                .unwrap_or_default();
            live.insert(tenant.as_str().to_owned(), digests);
        }
        self.blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?
            .reconcile(&live)
    }

    /// Deletes a bounded exact zero-reference object set under writer and backup exclusion.
    ///
    /// This cross-tenant operation requires the dedicated backup/GC authority. Every retained
    /// tenant-state row is checked while the global revision row blocks new metadata commits. An
    /// exclusive advisory lock prevents overlap with exported-snapshot backup object copying.
    pub fn garbage_collect_blob_candidates(
        &self,
        candidates: &[RepositoryGarbageCollectionCandidate],
        policy: GarbageCollectionPolicy,
        dry_run: bool,
        max_objects: usize,
    ) -> Result<RepositoryGarbageCollectionReport, StoreError> {
        self.require_configured_authority(PostgresAuthority::GarbageCollection)?;
        if candidates.is_empty()
            || max_objects == 0
            || candidates.len() > max_objects
            || candidates.windows(2).any(|pair| {
                pair.first().zip(pair.get(1)).is_some_and(|(left, right)| {
                    (&left.tenant_id, &left.digest) >= (&right.tenant_id, &right.digest)
                })
            })
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let first = candidates
            .first()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .build_transaction()
            // The exclusive advisory lock can wait behind a backup that deliberately permits
            // metadata commits. READ COMMITTED gives the first post-lock reachability statement a
            // current snapshot; the global revision-row lock below then freezes all later metadata
            // publication through the physical deletion boundary.
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(postgres_error)?;
        configure_backup_transaction(&mut transaction, &self.configuration, &first.tenant_id)?;
        verify_connection_authority(&mut transaction, PostgresAuthority::GarbageCollection)?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&BACKUP_GC_LOCK_KEY])
            .map_err(postgres_error)?;
        let _revision_guard: i64 = transaction
            .query_one("SELECT public.cigar_gc_lock_repository_revision()", &[])
            .map_err(postgres_error)?
            .get(0);
        let mut by_tenant: BTreeMap<&RecordId, BTreeSet<&cigar_protocol::ContentDigest>> =
            BTreeMap::new();
        for candidate in candidates {
            by_tenant
                .entry(&candidate.tenant_id)
                .or_default()
                .insert(&candidate.digest);
        }
        for (tenant, digests) in by_tenant {
            transaction
                .query_one(
                    "SELECT set_config('cigar.tenant_id', $1, true)",
                    &[&tenant.as_str()],
                )
                .map_err(postgres_error)?;
            let tenant_value = tenant.as_str();
            let parameters: [&(dyn ToSql + Sync); 1] = [&tenant_value];
            let mut rows = transaction
                .query_raw(
                    "SELECT state FROM cigar_tenant_states
                     WHERE tenant_id = $1 ORDER BY revision",
                    parameters,
                )
                .map_err(postgres_error)?;
            while let Some(row) = rows.next().map_err(postgres_error)? {
                let bytes: Vec<u8> = row.get(0);
                let state: TenantState = decode(&bytes)?;
                if digests
                    .iter()
                    .any(|digest| state.blobs.contains_key(*digest))
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidContext));
                }
            }
        }
        let report = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?
            .garbage_collect_candidates(
                &crate::SharedGarbageCollectionAuthorization::new(),
                candidates,
                policy,
                dry_run,
                max_objects,
            )?;
        transaction.commit().map_err(postgres_error)?;
        Ok(report)
    }

    /// Captures a database-native archive and self-contained object copy under one exported
    /// owner-authorized PostgreSQL snapshot.
    ///
    /// The backup driver runs before the exporting transaction commits and must pass
    /// `snapshot.exported_snapshot` to `pg_dump --snapshot`. After it returns exact archive
    /// evidence, the store copies and verifies `snapshot.live_objects` into the distinct backup
    /// destination while the same snapshot and backup/GC exclusion lock remain active.
    pub fn capture_backup_inventory<F, E>(
        &self,
        tenants: &[RecordId],
        created_at_unix_nanos: i128,
        backup_destination: &dyn crate::ObjectStorage,
        capture: F,
    ) -> Result<PostgresBackupInventory, StoreError>
    where
        F: FnOnce(&PostgresBackupSnapshot) -> Result<PostgresDatabaseBackupArtifact, E>,
    {
        self.require_configured_authority(PostgresAuthority::Backup)?;
        validate_sorted_tenants(tenants)?;
        if created_at_unix_nanos <= 0 {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let first = tenants
            .first()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(postgres_error)?;
        configure_backup_transaction(&mut transaction, &self.configuration, first)?;
        verify_connection_authority(&mut transaction, PostgresAuthority::Backup)?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&BACKUP_GC_LOCK_KEY],
            )
            .map_err(postgres_error)?;
        let source_database_identity = database_identity(&mut transaction)?;
        let authoritative = authoritative_backup_tenants(&mut transaction)?;
        if authoritative != tenants {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        let exported: (String, String) = transaction
            .query_one(
                "SELECT pg_export_snapshot(), txid_current_snapshot()::text",
                &[],
            )
            .map_err(postgres_error)
            .map(|row| (row.get(0), row.get(1)))?;
        validate_snapshot_token(&exported.0)?;
        validate_transaction_snapshot(&exported.1)?;
        let state = load_backup_state(&mut transaction, tenants)?;
        let blob_repository = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        verify_backup_blob_references(blob_repository.as_ref(), &state.blob_references)?;
        let live_objects = blob_repository.backup_inventory(&state.live)?;
        live_objects.validate()?;
        let snapshot = PostgresBackupSnapshot {
            exported_snapshot_checksum: checksum_bytes(exported.0.as_bytes()),
            transaction_snapshot_checksum: checksum_bytes(exported.1.as_bytes()),
            exported_snapshot: exported.0,
            transaction_snapshot: exported.1,
            source_database_identity,
            repository_revision: state.repository_revision,
            revision_history_count: state.revision_history_count,
            revision_history_root: state.revision_history_root,
            migrations: state.migrations,
            tenants: state.tenants,
            live_objects,
        };
        let database =
            capture(&snapshot).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        let (objects, object_copy_receipt) =
            blob_repository.copy_backup_inventory(&state.live, backup_destination)?;
        validate_backup_artifacts(&snapshot, &database, &objects, &object_copy_receipt)?;
        transaction.commit().map_err(postgres_error)?;
        let migration_sequence = u32::try_from(snapshot.migrations.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let migration_inventory_root = migration_inventory_root(&snapshot.migrations)?;
        let mut inventory = PostgresBackupInventory {
            format_version: POSTGRES_BACKUP_FORMAT_VERSION,
            migration_sequence,
            repository_revision: snapshot.repository_revision,
            revision_history_count: snapshot.revision_history_count,
            revision_history_root: snapshot.revision_history_root,
            created_at_unix_nanos,
            database,
            migrations: snapshot.migrations,
            migration_inventory_root,
            tenant_set_checksum: tenant_set_checksum(tenants)?,
            tenants: snapshot.tenants,
            objects,
            object_copy_receipt: object_copy_receipt.evidence().clone(),
            canonical_root: String::new(),
        };
        inventory.canonical_root = backup_inventory_root(&inventory)?;
        validate_backup_inventory(&inventory)?;
        Ok(inventory)
    }

    /// Verifies and attests a restored database/object namespace under current signer trust.
    ///
    /// The archive capability must be produced by `verify_postgres_database_backup` and then read
    /// completely into the restore process. The object receipt must be returned by an exact copy
    /// from the signed backup namespace. Target database and object identities are derived from the
    /// connected stores and must differ from both live-source and backup identities.
    pub fn verify_restored_backup_trusted<P, F, R>(
        &self,
        signed: &SignedPostgresBackupInventory,
        archive: &VerifiedPostgresDatabaseBackup<R>,
        object_receipt: ObjectRestoreReceipt,
        provider: &P,
        now_unix_nanos: i128,
        trust: F,
    ) -> Result<PostgresBackupRestoreReceipt, StoreError>
    where
        P: KeyProvider,
        F: FnOnce(&PostgresBackupSignatureIdentity) -> bool,
    {
        self.require_configured_authority(PostgresAuthority::Backup)?;
        verify_postgres_backup_inventory_trusted(signed, provider, now_unix_nanos, trust)?;
        self.verify_restored_state(signed, archive, object_receipt)
    }

    fn verify_restored_state<R>(
        &self,
        signed: &SignedPostgresBackupInventory,
        archive: &VerifiedPostgresDatabaseBackup<R>,
        object_receipt: ObjectRestoreReceipt,
    ) -> Result<PostgresBackupRestoreReceipt, StoreError> {
        validate_backup_inventory(&signed.inventory)?;
        if archive.artifact != signed.inventory.database
            || archive.bytes_consumed != archive.artifact.archive_size_bytes
            || format!(
                "1220{}",
                hex_bytes(&archive.consumption_digest.clone().finalize())
            ) != archive.artifact.archive_checksum
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let expected_tenants: Vec<_> = signed
            .inventory
            .tenants
            .iter()
            .map(|entry| entry.tenant_id.clone())
            .collect();
        validate_sorted_tenants(&expected_tenants)?;
        let first = expected_tenants
            .first()
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidContext))?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(postgres_error)?;
        configure_backup_transaction(&mut transaction, &self.configuration, first)?;
        verify_connection_authority(&mut transaction, PostgresAuthority::Backup)?;
        let destination_database_identity = database_identity(&mut transaction)?;
        if destination_database_identity == signed.inventory.database.source_database_identity {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let authoritative = authoritative_backup_tenants(&mut transaction)?;
        if authoritative != expected_tenants {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let state = load_backup_state(&mut transaction, &expected_tenants)?;
        let blob_repository = self
            .blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        verify_backup_blob_references(blob_repository.as_ref(), &state.blob_references)?;
        let objects = blob_repository.backup_inventory(&state.live)?;
        objects.validate()?;
        transaction.commit().map_err(postgres_error)?;
        let expected_object_count = u64::try_from(signed.inventory.objects.entries.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        if state.repository_revision != signed.inventory.repository_revision
            || state.revision_history_count != signed.inventory.revision_history_count
            || state.revision_history_root != signed.inventory.revision_history_root
            || state.migrations != signed.inventory.migrations
            || state.tenants != signed.inventory.tenants
            || object_receipt.source() != &signed.inventory.objects.storage
            || object_receipt.destination() != &objects.storage
            || object_receipt.source() == object_receipt.destination()
            || objects.storage == signed.inventory.object_copy_receipt.source
            || objects.storage == signed.inventory.objects.storage
            || objects.entries != signed.inventory.objects.entries
            || object_receipt.object_count() != expected_object_count
            || object_receipt.ciphertext_bytes()
                != object_inventory_bytes(&signed.inventory.objects)?
            || object_receipt.inventory_root() != object_inventory_root(&signed.inventory.objects)?
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        Ok(PostgresBackupRestoreReceipt {
            database: PostgresDatabaseRestoreReceipt {
                source_database_identity: signed
                    .inventory
                    .database
                    .source_database_identity
                    .clone(),
                destination_database_identity,
                archive_format: archive.artifact.archive_format.clone(),
                archive_size_bytes: archive.artifact.archive_size_bytes,
                archive_checksum: archive.artifact.archive_checksum.clone(),
                repository_revision: state.repository_revision,
                migration_inventory_root: signed.inventory.migration_inventory_root.clone(),
                tenant_set_checksum: signed.inventory.tenant_set_checksum.clone(),
            },
            objects: object_receipt,
        })
    }

    /// Arms an otherwise-valid next commit to abort before visibility.
    pub fn fail_next_commit(&self) {
        self.fail_next_commit.store(true, Ordering::Release);
    }

    /// Arms one named one-shot transactional failure boundary.
    pub fn inject_failpoint(&self, failpoint: PostgresFailpoint) -> Result<(), StoreError> {
        self.failpoints
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?
            .insert(failpoint);
        Ok(())
    }

    /// Claims commit wakeups using row locks and `SKIP LOCKED` for horizontal workers.
    pub fn claim_wakeups(
        &self,
        tenant_id: &RecordId,
        worker: &str,
        owner: &str,
        now_unix_millis: i64,
        lease_millis: i64,
        limit: usize,
    ) -> Result<Vec<SharedWakeupClaim>, StoreError> {
        validate_worker_selector(worker)?;
        validate_worker_selector(owner)?;
        if now_unix_millis < 0
            || lease_millis <= 0
            || lease_millis > 300_000
            || limit == 0
            || limit > MAX_WAKEUP_CLAIMS
        {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, tenant_id)?;
        let limit = i64::try_from(limit)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let rows = transaction
            .query(
                "SELECT w.revision, w.topic
                 FROM cigar_shared_wakeups AS w
                 LEFT JOIN cigar_worker_claims AS c
                   ON c.tenant_id = w.tenant_id
                  AND c.worker = $2
                  AND c.item_key = (w.revision::text || ':' || w.topic)
                 WHERE w.tenant_id = $1
                   AND (c.item_key IS NULL OR c.lease_expires_at <=
                        to_timestamp(($3::bigint)::double precision / 1000.0))
                 ORDER BY w.revision, w.topic
                 FOR UPDATE OF w SKIP LOCKED
                 LIMIT $4",
                &[&tenant_id.as_str(), &worker, &now_unix_millis, &limit],
            )
            .map_err(postgres_error)?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let revision_i64: i64 = row.get(0);
            let revision = from_i64_revision(revision_i64)?;
            let topic: String = row.get(1);
            let item_key = format!("{revision_i64}:{topic}");
            let fencing_i64: i64 = transaction
                .query_one(
                    "INSERT INTO cigar_worker_claims
                       (tenant_id, worker, item_key, owner, fencing_token, lease_expires_at)
                     VALUES ($1, $2, $3, $4, 1,
                             to_timestamp((($5::bigint + $6::bigint))::double precision / 1000.0))
                     ON CONFLICT (tenant_id, worker, item_key) DO UPDATE SET
                       owner = EXCLUDED.owner,
                       fencing_token = cigar_worker_claims.fencing_token + 1,
                       lease_expires_at = EXCLUDED.lease_expires_at,
                       claimed_at = clock_timestamp()
                     WHERE cigar_worker_claims.lease_expires_at <=
                           to_timestamp(($5::bigint)::double precision / 1000.0)
                     RETURNING fencing_token",
                    &[
                        &tenant_id.as_str(),
                        &worker,
                        &item_key,
                        &owner,
                        &now_unix_millis,
                        &lease_millis,
                    ],
                )
                .map_err(postgres_error)?
                .get(0);
            claims.push(SharedWakeupClaim {
                wakeup: SharedWakeup {
                    tenant_id: tenant_id.clone(),
                    revision,
                    topic,
                },
                fencing_token: u64::try_from(fencing_i64)
                    .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?,
                owner: owner.to_owned(),
            });
        }
        transaction.commit().map_err(postgres_error)?;
        Ok(claims)
    }

    /// Acknowledges one exact fenced wakeup claim atomically.
    pub fn acknowledge_wakeup(
        &self,
        worker: &str,
        claim: &SharedWakeupClaim,
    ) -> Result<(), StoreError> {
        validate_worker_selector(worker)?;
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, &claim.wakeup.tenant_id)?;
        let revision = to_i64_revision(claim.wakeup.revision)?;
        let item_key = format!("{revision}:{}", claim.wakeup.topic);
        let fence = i64::try_from(claim.fencing_token)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let deleted = transaction
            .execute(
                "DELETE FROM cigar_worker_claims
                 WHERE tenant_id = $1 AND worker = $2 AND item_key = $3
                   AND owner = $4 AND fencing_token = $5",
                &[
                    &claim.wakeup.tenant_id.as_str(),
                    &worker,
                    &item_key,
                    &claim.owner,
                    &fence,
                ],
            )
            .map_err(postgres_error)?;
        if deleted != 1 {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
        transaction
            .execute(
                "DELETE FROM cigar_shared_wakeups
                 WHERE tenant_id = $1 AND revision = $2 AND topic = $3",
                &[
                    &claim.wakeup.tenant_id.as_str(),
                    &revision,
                    &claim.wakeup.topic,
                ],
            )
            .map_err(postgres_error)?;
        transaction.commit().map_err(postgres_error)
    }

    fn connection(&self) -> Result<PooledConnection<Manager>, StoreError> {
        self.pool.get().map_err(pool_error)
    }

    fn transaction<'connection>(
        &self,
        connection: &'connection mut PooledConnection<Manager>,
        tenant: &RecordId,
    ) -> Result<Transaction<'connection>, StoreError> {
        self.require_configured_authority(PostgresAuthority::Runtime)?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(postgres_error)?;
        configure_transaction(&mut transaction, &self.configuration, tenant)?;
        verify_connection_authority(&mut transaction, PostgresAuthority::Runtime)?;
        Ok(transaction)
    }

    fn require_configured_authority(&self, expected: PostgresAuthority) -> Result<(), StoreError> {
        if self.authority == expected {
            Ok(())
        } else {
            Err(StoreError::new(StoreErrorCode::Unavailable))
        }
    }

    fn trip(&self, failpoint: PostgresFailpoint) -> Result<(), StoreError> {
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

impl crate::conformance::ConformanceRepository for PostgresStore {
    fn inject_commit_abort(&self) {
        self.fail_next_commit();
    }
}

impl Repository for PostgresStore {
    type Read<'store>
        = InMemoryReadTransaction
    where
        Self: 'store;
    type Write<'store>
        = PostgresWriteTransaction<'store>
    where
        Self: 'store;

    fn begin_read(
        &self,
        context: AccessContext,
        selection: SnapshotSelection,
        cancellation: CancellationToken,
    ) -> Result<Self::Read<'_>, StoreError> {
        cancellation.check()?;
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, context.tenant_id())?;
        let state = load_state(&mut transaction, context.tenant_id(), selection)?;
        transaction.commit().map_err(postgres_error)?;
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
        Ok(PostgresWriteTransaction {
            store: self,
            context,
            expected_revision,
            cancellation,
            staged: Vec::new(),
        })
    }
}

impl ServiceRepository for PostgresStore {
    fn service_get(
        &self,
        locator: &ServiceRecordLocator,
        selection: ServiceRecordSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<ServiceRecord>, ServiceError> {
        check_cancellation(cancellation)?;
        let state = self
            .load_service_state(locator.tenant_id(), SnapshotSelection::Latest)
            .map_err(map_store_error)?;
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
        let state = self
            .load_service_state(query.tenant_id(), selection)
            .map_err(map_store_error)?;
        service_list_from_state(&state, query)
    }

    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError> {
        check_cancellation(cancellation)?;
        let tenant_id = batch.tenant_id().clone();
        let mut connection = self.connection().map_err(map_store_error)?;
        let mut transaction = self
            .transaction(&mut connection, &tenant_id)
            .map_err(map_store_error)?;
        let latest_revision = lock_revision(&mut transaction).map_err(map_store_error)?;
        let latest = load_state_at_revision(&mut transaction, &tenant_id, latest_revision)
            .map_err(map_store_error)?;
        let (next, receipt) = apply_service_batch(&latest, batch)?;
        if receipt.replayed {
            return Ok(receipt);
        }
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(ServiceErrorCode::InjectedAbort));
        }
        let next = next.ok_or_else(|| ServiceError::new(ServiceErrorCode::Unavailable))?;
        publish_state(&mut transaction, &tenant_id, &next).map_err(map_store_error)?;
        transaction.commit().map_err(service_postgres_error)?;
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
        let state = self
            .load_service_state(query.tenant_id(), selection)
            .map_err(map_store_error)?;
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
        let state = self
            .load_service_state(query.tenant_id(), selection)
            .map_err(map_store_error)?;
        outbox_recovery_from_state(&state, query)
    }

    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError> {
        check_cancellation(cancellation)?;
        let state = self
            .load_service_state(locator.tenant_id(), SnapshotSelection::Latest)
            .map_err(map_store_error)?;
        worker_get_from_state(&state, locator)
    }

    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError> {
        check_cancellation(cancellation)?;
        let mut connection = self.connection().map_err(map_store_error)?;
        let mut transaction = self
            .transaction(&mut connection, locator.tenant_id())
            .map_err(map_store_error)?;
        let latest_revision = lock_revision(&mut transaction).map_err(map_store_error)?;
        let latest = load_state_at_revision(&mut transaction, locator.tenant_id(), latest_revision)
            .map_err(map_store_error)?;
        let (next, state) = apply_worker_update(&latest, locator, update)?;
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(ServiceErrorCode::InjectedAbort));
        }
        publish_state(&mut transaction, locator.tenant_id(), &next).map_err(map_store_error)?;
        transaction.commit().map_err(service_postgres_error)?;
        Ok(state)
    }
}

impl PostgresStore {
    fn load_service_state(
        &self,
        tenant: &RecordId,
        selection: SnapshotSelection,
    ) -> Result<CommittedState, StoreError> {
        let mut connection = self.connection()?;
        let mut transaction = self.transaction(&mut connection, tenant)?;
        let state = load_state(&mut transaction, tenant, selection)?;
        transaction.commit().map_err(postgres_error)?;
        Ok(state)
    }
}

/// Mutable PostgreSQL transaction that stages domain mutations privately.
pub struct PostgresWriteTransaction<'store> {
    store: &'store PostgresStore,
    context: AccessContext,
    expected_revision: StoreRevision,
    cancellation: CancellationToken,
    staged: Vec<StagedMutation>,
}

impl fmt::Debug for PostgresWriteTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresWriteTransaction")
            .field("context", &self.context)
            .field("expected_revision", &self.expected_revision)
            .field("staged", &self.staged.len())
            .finish()
    }
}

impl PostgresWriteTransaction<'_> {
    fn stage(&mut self, mutation: StagedMutation) -> Result<(), StoreError> {
        self.cancellation.check()?;
        self.staged.push(mutation);
        Ok(())
    }
}

impl WriteTransaction for PostgresWriteTransaction<'_> {
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
        let mut projection_batches = Vec::new();
        for mutation in &self.staged {
            if let StagedMutation::Atoms(atoms, _edges) = mutation {
                for chunk in atoms.chunks(MAX_ATOM_PROJECTION_RESTORE_ITEMS) {
                    projection_batches
                        .push(prepare_projection_records(self.context.tenant_id(), chunk)?);
                }
            }
        }
        let mut connection = self.store.connection()?;
        let mut transaction = self
            .store
            .transaction(&mut connection, self.context.tenant_id())?;
        let latest_revision = lock_revision(&mut transaction)?;
        self.store.trip(PostgresFailpoint::AfterRevisionLock)?;
        let mut latest =
            load_state_at_revision(&mut transaction, self.context.tenant_id(), latest_revision)?;
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
        if latest_revision != self.expected_revision {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
        let revision = next_revision(latest_revision)?;
        latest.revision = revision;
        let tenant = latest
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
                    if repository
                        .get(self.context.tenant_id(), &blob.reference)?
                        .as_ref()
                        != Some(blob)
                    {
                        return Err(StoreError::new(StoreErrorCode::Unavailable));
                    }
                }
            }
        }
        self.store.trip(PostgresFailpoint::AfterBlobPublication)?;
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
        publish_state(&mut transaction, self.context.tenant_id(), &latest)?;
        for records in &projection_batches {
            insert_projection_records(
                &mut transaction,
                self.context.tenant_id(),
                revision,
                records,
            )?;
            verify_projection_records(&mut transaction, self.context.tenant_id(), records)?;
        }
        self.store.trip(PostgresFailpoint::BeforeCommit)?;
        transaction.commit().map_err(postgres_error)?;
        Ok(receipt)
    }
}

fn configure_transaction(
    transaction: &mut Transaction<'_>,
    configuration: &PostgresConfiguration,
    tenant: &RecordId,
) -> Result<(), StoreError> {
    let statement = timeout_value(configuration.statement_timeout)?;
    let lock = timeout_value(configuration.lock_timeout)?;
    let idle = timeout_value(configuration.idle_transaction_timeout)?;
    transaction
        .query_one(
            "SELECT set_config('statement_timeout', $1, true),
                    set_config('lock_timeout', $2, true),
                    set_config('idle_in_transaction_session_timeout', $3, true),
                    set_config('cigar.tenant_id', $4, true)",
            &[&statement, &lock, &idle, &tenant.as_str()],
        )
        .map(|_row| ())
        .map_err(postgres_error)
}

fn configure_backup_transaction(
    transaction: &mut Transaction<'_>,
    configuration: &PostgresConfiguration,
    tenant: &RecordId,
) -> Result<(), StoreError> {
    let statement = backup_timeout_value(configuration.backup_timeout)?;
    let lock = timeout_value(configuration.lock_timeout)?;
    let backup = backup_timeout_value(configuration.backup_timeout)?;
    transaction
        .query_one(
            "SELECT set_config('statement_timeout', $1, true),
                    set_config('lock_timeout', $2, true),
                    set_config('idle_in_transaction_session_timeout', '0', true),
                    set_config('transaction_timeout', $3, true),
                    set_config('cigar.tenant_id', $4, true)",
            &[&statement, &lock, &backup, &tenant.as_str()],
        )
        .map(|_row| ())
        .map_err(postgres_error)
}

/// Signs one exact database-native backup inventory with a tenant signing key.
pub fn sign_postgres_backup_inventory<P: KeyProvider>(
    inventory: PostgresBackupInventory,
    provider: &P,
    signing_key: &KeyRef,
    signing_tenant: &str,
    signer: &str,
    signed_at_unix_nanos: i128,
) -> Result<SignedPostgresBackupInventory, StoreError> {
    validate_backup_inventory(&inventory)?;
    if signing_tenant.is_empty()
        || signing_tenant.len() > 256
        || signing_tenant.bytes().any(|byte| byte.is_ascii_control())
        || signer.is_empty()
        || signer.len() > 256
        || signer.bytes().any(|byte| byte.is_ascii_control())
        || signed_at_unix_nanos != inventory.created_at_unix_nanos
    {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    let payload_digest = backup_inventory_digest(&inventory)?;
    let signature = provider
        .sign(SignatureRequest {
            key_ref: signing_key,
            tenant: signing_tenant,
            signer,
            purpose: POSTGRES_BACKUP_SIGNATURE_PURPOSE,
            payload_digest,
            signed_at: signed_at_unix_nanos,
            expires_at: None,
        })
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    Ok(SignedPostgresBackupInventory {
        inventory,
        signing_key: signature.key_ref,
        signing_tenant: signing_tenant.to_owned(),
        signer: signature.signer,
        signed_at_unix_nanos: signature.signed_at,
        signature: signature.signature.to_vec(),
    })
}

/// Streams and verifies the exact database-native archive bound into a signed inventory.
///
/// The archive is never buffered in full. Size overflow, truncation, extension, or checksum drift
/// fail before a restore receipt can be accepted.
pub fn verify_postgres_database_backup<R: Read + Seek>(
    artifact: &PostgresDatabaseBackupArtifact,
    mut archive: R,
) -> Result<VerifiedPostgresDatabaseBackup<R>, StoreError> {
    validate_database_artifact(artifact)?;
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    let mut digest = Sha256::new();
    let mut observed_size = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = archive
            .read(&mut buffer)
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        if read == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(
                u64::try_from(read)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
            )
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        if observed_size > artifact.archive_size_bytes || observed_size > MAX_DATABASE_BACKUP_BYTES
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        digest.update(
            buffer
                .get(..read)
                .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?,
        );
    }
    let checksum = format!("1220{}", hex_bytes(&digest.finalize()));
    if observed_size != artifact.archive_size_bytes || checksum != artifact.archive_checksum {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    Ok(VerifiedPostgresDatabaseBackup {
        archive,
        artifact: artifact.clone(),
        bytes_consumed: 0,
        consumption_digest: Sha256::new(),
    })
}

/// Verifies inventory structure, canonical root, purpose, identity, digest, and signature.
pub fn verify_postgres_backup_inventory<P: KeyProvider>(
    signed: &SignedPostgresBackupInventory,
    provider: &P,
    signing_tenant: &str,
    now_unix_nanos: i128,
) -> Result<(), StoreError> {
    verify_postgres_backup_inventory_trusted(signed, provider, now_unix_nanos, |identity| {
        identity.signing_tenant == signing_tenant
    })
}

/// Verifies one signed inventory and requires current authority to trust its persisted identity.
///
/// The key provider validates the historical signature at its exact signing time. The caller's
/// trust predicate separately enforces current principal/key revocation and operator policy.
pub fn verify_postgres_backup_inventory_trusted<P, F>(
    signed: &SignedPostgresBackupInventory,
    provider: &P,
    now_unix_nanos: i128,
    trust: F,
) -> Result<(), StoreError>
where
    P: KeyProvider,
    F: FnOnce(&PostgresBackupSignatureIdentity) -> bool,
{
    validate_backup_inventory(&signed.inventory)?;
    if signed.signing_tenant.is_empty()
        || signed.signing_tenant.len() > 256
        || signed
            .signing_tenant
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || signed.signer.is_empty()
        || signed.signer.len() > 256
        || signed.signature.len() != 64
        || signed.signed_at_unix_nanos > now_unix_nanos
        || signed.signed_at_unix_nanos != signed.inventory.created_at_unix_nanos
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    let identity = PostgresBackupSignatureIdentity {
        signing_tenant: signed.signing_tenant.clone(),
        signer: signed.signer.clone(),
        signing_key: signed.signing_key.clone(),
        signed_at_unix_nanos: signed.signed_at_unix_nanos,
    };
    let signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    let payload_digest = backup_inventory_digest(&signed.inventory)?;
    let envelope = SignatureEnvelope {
        algorithm: KeyAlgorithm::Ed25519,
        key_ref: signed.signing_key.clone(),
        signer: signed.signer.clone(),
        purpose: POSTGRES_BACKUP_SIGNATURE_PURPOSE.to_owned(),
        signed_at: signed.signed_at_unix_nanos,
        expires_at: None,
        payload_digest,
        signature,
    };
    provider
        .verify(
            &envelope,
            SignatureVerification {
                tenant: &signed.signing_tenant,
                signer: &signed.signer,
                purpose: POSTGRES_BACKUP_SIGNATURE_PURPOSE,
                payload_digest: &payload_digest,
                now: now_unix_nanos,
            },
        )
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    if !trust(&identity) {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

fn verify_connection_authority(
    connection: &mut impl GenericClient,
    expected: PostgresAuthority,
) -> Result<(), StoreError> {
    let row = connection
        .query_one(
            "SELECT session_user = current_user,
                    database_owner.rolname <> current_user,
                    authenticated_role.rolsuper,
                    authenticated_role.rolbypassrls,
                    authenticated_role.rolinherit,
                    authenticated_role.rolcreaterole,
                    authenticated_role.rolcreatedb,
                    authenticated_role.rolreplication,
                    authenticated_role.rolcanlogin,
                    NOT EXISTS (
                        SELECT 1
                        FROM pg_roles AS selectable_role
                        WHERE selectable_role.oid <> authenticated_role.oid
                          AND pg_has_role(
                              authenticated_role.oid,
                              selectable_role.oid,
                              'SET'
                          )
                    ),
                    has_function_privilege(
                        current_user,
                        'pg_catalog.pg_control_system()'::regprocedure,
                        'EXECUTE'
                    ),
                    has_function_privilege(
                        current_user,
                        'public.cigar_gc_lock_repository_revision()'::regprocedure,
                        'EXECUTE'
                    )
             FROM pg_roles AS authenticated_role
             JOIN pg_database AS database ON database.datname = current_database()
             JOIN pg_roles AS database_owner ON database_owner.oid = database.datdba
             WHERE authenticated_role.rolname = current_user",
            &[],
        )
        .map_err(postgres_error)?;
    let session_exact: bool = row.get(0);
    let not_owner: bool = row.get(1);
    let superuser: bool = row.get(2);
    let bypass_rls: bool = row.get(3);
    let inherits_roles: bool = row.get(4);
    let create_role: bool = row.get(5);
    let create_database: bool = row.get(6);
    let replication: bool = row.get(7);
    let can_login: bool = row.get(8);
    let no_set_memberships: bool = row.get(9);
    let control_system: bool = row.get(10);
    let gc_guard: bool = row.get(11);
    let exact = match expected {
        PostgresAuthority::Runtime => !bypass_rls && !control_system && !gc_guard,
        PostgresAuthority::Backup => bypass_rls && control_system && !gc_guard,
        PostgresAuthority::GarbageCollection => bypass_rls && !control_system && gc_guard,
    };
    if session_exact
        && not_owner
        && !superuser
        && !inherits_roles
        && !create_role
        && !create_database
        && !replication
        && can_login
        && no_set_memberships
        && exact
    {
        Ok(())
    } else {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

fn authoritative_backup_tenants(
    connection: &mut impl GenericClient,
) -> Result<Vec<RecordId>, StoreError> {
    let rows = connection
        .query(
            "SELECT tenant_id FROM (
                 SELECT tenant_id FROM cigar_tenant_states
                 UNION SELECT tenant_id FROM cigar_shared_wakeups
                 UNION SELECT tenant_id FROM cigar_object_commits
                 UNION SELECT tenant_id FROM cigar_worker_claims
                 UNION SELECT tenant_id FROM cigar_atom_projection
             ) AS tenant_catalog
             ORDER BY tenant_id",
            &[],
        )
        .map_err(postgres_error)?;
    if rows.len() > 65_536 {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    rows.into_iter()
        .map(|row| {
            RecordId::new(row.get::<_, String>(0))
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
        })
        .collect()
}

fn migration_backup_inventory(
    connection: &mut impl GenericClient,
) -> Result<Vec<PostgresMigrationBackupEntry>, StoreError> {
    let receipt = verify_migrations(connection)?;
    let rows = connection
        .query(
            "SELECT sequence, name, checksum, minimum_application_major,
                    maximum_application_major, online,
                    (extract(epoch FROM applied_at) * 1000000)::bigint
             FROM public.schema_migrations ORDER BY sequence",
            &[],
        )
        .map_err(postgres_error)?;
    if rows.len()
        != usize::try_from(receipt.latest_sequence)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let entries = rows
        .into_iter()
        .map(|row| {
            let sequence = u32::try_from(row.get::<_, i32>(0))
                .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
            Ok(PostgresMigrationBackupEntry {
                sequence,
                name: row.get(1),
                checksum: row.get(2),
                minimum_application_major: row.get(3),
                maximum_application_major: row.get(4),
                online: row.get(5),
                applied_at_unix_micros: row.get(6),
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    validate_migration_inventory(&entries)?;
    Ok(entries)
}

struct BackupState {
    repository_revision: StoreRevision,
    revision_history_count: u64,
    revision_history_root: String,
    migrations: Vec<PostgresMigrationBackupEntry>,
    tenants: Vec<PostgresTenantBackupInventory>,
    live: BTreeMap<String, BTreeSet<cigar_protocol::ContentDigest>>,
    blob_references: Vec<(RecordId, BlobRef)>,
}

fn load_backup_state(
    transaction: &mut Transaction<'_>,
    tenants: &[RecordId],
) -> Result<BackupState, StoreError> {
    let repository_revision = current_revision(transaction)?;
    let (revision_history_count, revision_history_root) =
        revision_history_root(transaction, repository_revision)?;
    let migrations = migration_backup_inventory(transaction)?;
    let revision = to_i64_revision(repository_revision)?;
    let mut inventory = Vec::with_capacity(tenants.len());
    let mut live = BTreeMap::new();
    let mut blob_references = Vec::new();
    for tenant in tenants {
        transaction
            .query_one(
                "SELECT set_config('cigar.tenant_id', $1, true)",
                &[&tenant.as_str()],
            )
            .map_err(postgres_error)?;
        let history = tenant_state_history(transaction, tenant, revision)?;
        let (atom_projection_count, atom_projection_root) =
            tenant_projection_root(transaction, tenant)?;
        let (operational_row_count, operational_root) =
            tenant_operational_root(transaction, tenant)?;
        blob_references.extend(
            history
                .references
                .iter()
                .cloned()
                .map(|reference| (tenant.clone(), reference)),
        );
        let digests = history
            .references
            .iter()
            .map(|reference| reference.digest.clone())
            .collect();
        live.insert(tenant.as_str().to_owned(), digests);
        inventory.push(PostgresTenantBackupInventory {
            tenant_id: tenant.clone(),
            state_revision: history.latest_revision,
            state_checksum: history.latest_checksum,
            state_history_count: history.count,
            state_history_root: history.root,
            atom_projection_count,
            atom_projection_root,
            operational_row_count,
            operational_root,
        });
    }
    blob_references
        .sort_by(|left, right| (&left.0, &left.1.digest).cmp(&(&right.0, &right.1.digest)));
    blob_references.dedup_by(|left, right| left.0 == right.0 && left.1.digest == right.1.digest);
    Ok(BackupState {
        repository_revision,
        revision_history_count,
        revision_history_root,
        migrations,
        tenants: inventory,
        live,
        blob_references,
    })
}

struct TenantStateHistory {
    latest_revision: Option<StoreRevision>,
    latest_checksum: Option<String>,
    count: u64,
    root: String,
    references: Vec<BlobRef>,
}

fn revision_history_root(
    transaction: &mut Transaction<'_>,
    current: StoreRevision,
) -> Result<(u64, String), StoreError> {
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-REVISION-HISTORY\0v1\0");
    let mut rows = transaction
        .query_raw(
            "SELECT revision,
                    (extract(epoch FROM committed_at) * 1000000)::bigint
             FROM cigar_repository_revisions ORDER BY revision",
            std::iter::empty::<&str>(),
        )
        .map_err(postgres_error)?;
    let mut count = 0_u64;
    let mut previous = None;
    while let Some(row) = rows.next().map_err(postgres_error)? {
        let revision = from_i64_revision(row.get(0))?;
        let committed_at_unix_micros: i64 = row.get(1);
        if revision.0 != count || previous.is_some_and(|value| value >= revision) {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        digest.update(revision.0.to_be_bytes());
        if committed_at_unix_micros < 0 {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        digest.update(committed_at_unix_micros.to_be_bytes());
        previous = Some(revision);
        count = count
            .checked_add(1)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    }
    if previous != Some(current)
        || count
            != current
                .0
                .checked_add(1)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok((count, format!("1220{}", hex_bytes(&digest.finalize()))))
}

fn tenant_state_history(
    transaction: &mut Transaction<'_>,
    tenant: &RecordId,
    maximum_revision: i64,
) -> Result<TenantStateHistory, StoreError> {
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-TENANT-STATE-HISTORY\0v1\0");
    digest_field(&mut digest, tenant.as_str().as_bytes())?;
    let tenant_value = tenant.as_str();
    let parameters: [&(dyn ToSql + Sync); 2] = [&tenant_value, &maximum_revision];
    let mut rows = transaction
        .query_raw(
            "SELECT revision, checksum, state FROM cigar_tenant_states
             WHERE tenant_id = $1 AND revision <= $2 ORDER BY revision",
            parameters,
        )
        .map_err(postgres_error)?;
    let mut latest_revision = None;
    let mut latest_checksum = None;
    let mut count = 0_u64;
    let mut references = BTreeMap::new();
    while let Some(row) = rows.next().map_err(postgres_error)? {
        let revision = from_i64_revision(row.get(0))?;
        let checksum: String = row.get(1);
        let bytes: Vec<u8> = row.get(2);
        if latest_revision.is_some_and(|previous| previous >= revision)
            || !valid_checksum(&checksum)
            || checksum_bytes(&bytes) != checksum
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let state: TenantState = decode(&bytes)?;
        for blob in state.blobs.values() {
            if let Some(previous) =
                references.insert(blob.reference.digest.clone(), blob.reference.clone())
                && previous != blob.reference
            {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
        }
        digest.update(revision.0.to_be_bytes());
        digest_field(&mut digest, checksum.as_bytes())?;
        digest_field(&mut digest, &bytes)?;
        latest_revision = Some(revision);
        latest_checksum = Some(checksum);
        count = count
            .checked_add(1)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    }
    Ok(TenantStateHistory {
        latest_revision,
        latest_checksum,
        count,
        root: format!("1220{}", hex_bytes(&digest.finalize())),
        references: references.into_values().collect(),
    })
}

fn tenant_projection_root(
    transaction: &mut Transaction<'_>,
    tenant: &RecordId,
) -> Result<(u64, String), StoreError> {
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-ATOM-PROJECTION\0v1\0");
    digest_field(&mut digest, tenant.as_str().as_bytes())?;
    let tenant_value = tenant.as_str();
    let parameters: [&(dyn ToSql + Sync); 1] = [&tenant_value];
    let mut rows = transaction
        .query_raw(
            "SELECT version_id, atom_id, lineage_id, record_checksum,
                    published_revision, record,
                    (extract(epoch FROM projected_at) * 1000000)::bigint
             FROM cigar_atom_projection WHERE tenant_id = $1 ORDER BY version_id",
            parameters,
        )
        .map_err(postgres_error)?;
    let mut count = 0_u64;
    let mut previous = None;
    while let Some(row) = rows.next().map_err(postgres_error)? {
        let version: String = row.get(0);
        let version_id = VersionId::new(version.clone())
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
        if previous
            .as_ref()
            .is_some_and(|value: &String| value >= &version)
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let atom_id: String = row.get(1);
        let lineage_id: String = row.get(2);
        let checksum: String = row.get(3);
        let published_revision = from_i64_revision(row.get(4))?;
        let record: Vec<u8> = row.get(5);
        let projected_at_unix_micros: i64 = row.get(6);
        if !valid_checksum(&checksum)
            || checksum_bytes(&record) != checksum
            || projected_at_unix_micros < 0
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let observed: ContextAtomV1 = decode(&record)?;
        if observed.scope.tenant_id != *tenant
            || observed.version_id != version_id
            || observed.atom_id.as_str() != atom_id
            || observed.lineage_id.as_str() != lineage_id
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        digest_field(&mut digest, version.as_bytes())?;
        digest_field(&mut digest, atom_id.as_bytes())?;
        digest_field(&mut digest, lineage_id.as_bytes())?;
        digest_field(&mut digest, checksum.as_bytes())?;
        digest.update(published_revision.0.to_be_bytes());
        digest_field(&mut digest, &record)?;
        digest.update(projected_at_unix_micros.to_be_bytes());
        previous = Some(version);
        count = count
            .checked_add(1)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    }
    Ok((count, format!("1220{}", hex_bytes(&digest.finalize()))))
}

fn tenant_operational_root(
    transaction: &mut Transaction<'_>,
    tenant: &RecordId,
) -> Result<(u64, String), StoreError> {
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-TENANT-OPERATIONAL\0v1\0");
    digest_field(&mut digest, tenant.as_str().as_bytes())?;
    let tenant_value = tenant.as_str();
    let parameters: [&(dyn ToSql + Sync); 1] = [&tenant_value];
    let mut rows = transaction
        .query_raw(
            "SELECT kind, value_a, value_b, value_c, number_a, number_b, number_c
             FROM (
               SELECT 1 AS kind, revision::text AS value_a, topic AS value_b,
                      ''::text AS value_c,
                      (extract(epoch FROM created_at) * 1000000)::bigint AS number_a,
                      0::bigint AS number_b, 0::bigint AS number_c
               FROM cigar_shared_wakeups WHERE tenant_id = $1
               UNION ALL
               SELECT 2, storage_key, digest, '', size_bytes,
                      (extract(epoch FROM committed_at) * 1000000)::bigint, 0::bigint
               FROM cigar_object_commits WHERE tenant_id = $1
               UNION ALL
               SELECT 3, worker, item_key, owner, fencing_token,
                      (extract(epoch FROM lease_expires_at) * 1000000)::bigint,
                      (extract(epoch FROM claimed_at) * 1000000)::bigint
               FROM cigar_worker_claims WHERE tenant_id = $1
             ) AS operational ORDER BY kind, value_a, value_b, value_c",
            parameters,
        )
        .map_err(postgres_error)?;
    let mut count = 0_u64;
    while let Some(row) = rows.next().map_err(postgres_error)? {
        let kind: i32 = row.get(0);
        let value_a: String = row.get(1);
        let value_b: String = row.get(2);
        let value_c: String = row.get(3);
        let number_a: i64 = row.get(4);
        let number_b: i64 = row.get(5);
        let number_c: i64 = row.get(6);
        if !(1..=3).contains(&kind) || number_a < 0 || number_b < 0 || number_c < 0 {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        digest.update(kind.to_be_bytes());
        digest_field(&mut digest, value_a.as_bytes())?;
        digest_field(&mut digest, value_b.as_bytes())?;
        digest_field(&mut digest, value_c.as_bytes())?;
        digest.update(number_a.to_be_bytes());
        digest.update(number_b.to_be_bytes());
        digest.update(number_c.to_be_bytes());
        count = count
            .checked_add(1)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    }
    Ok((count, format!("1220{}", hex_bytes(&digest.finalize()))))
}

fn digest_field(digest: &mut Sha256, bytes: &[u8]) -> Result<(), StoreError> {
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

fn database_identity(connection: &mut impl GenericClient) -> Result<String, StoreError> {
    let row = connection
        .query_one(
            "SELECT control.system_identifier::text, database.oid::text
             FROM pg_control_system() AS control
             CROSS JOIN pg_database AS database
             WHERE database.datname = current_database()",
            &[],
        )
        .map_err(postgres_error)?;
    let system_identifier: String = row.get(0);
    let database_oid: String = row.get(1);
    if system_identifier.is_empty()
        || system_identifier.len() > 32
        || !system_identifier.bytes().all(|byte| byte.is_ascii_digit())
        || database_oid.is_empty()
        || database_oid.len() > 16
        || !database_oid.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-DATABASE-IDENTITY\0v1\0");
    digest_field(&mut digest, system_identifier.as_bytes())?;
    digest_field(&mut digest, database_oid.as_bytes())?;
    Ok(format!("1220{}", hex_bytes(&digest.finalize())))
}

fn verify_backup_blob_references(
    repository: &dyn crate::RepositoryBlobStore,
    references: &[(RecordId, BlobRef)],
) -> Result<(), StoreError> {
    for (tenant, reference) in references {
        let observed = repository
            .get(tenant, reference)?
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        if observed.reference != *reference {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
    }
    Ok(())
}

fn validate_snapshot_token(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    } else {
        Ok(())
    }
}

fn validate_transaction_snapshot(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 8_192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b':' | b','))
    {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    } else {
        Ok(())
    }
}

fn validate_backup_artifacts(
    snapshot: &PostgresBackupSnapshot,
    database: &PostgresDatabaseBackupArtifact,
    objects: &ObjectBackupInventory,
    object_copy_receipt: &ObjectRestoreReceipt,
) -> Result<(), StoreError> {
    validate_database_artifact(database)?;
    snapshot.live_objects.validate()?;
    objects.validate()?;
    let expected_count = u64::try_from(snapshot.live_objects.entries.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let expected_bytes = object_inventory_bytes(&snapshot.live_objects)?;
    if database.exported_snapshot_checksum != snapshot.exported_snapshot_checksum
        || database.transaction_snapshot_checksum != snapshot.transaction_snapshot_checksum
        || database.source_database_identity != snapshot.source_database_identity
        || objects.storage == snapshot.live_objects.storage
        || objects.entries != snapshot.live_objects.entries
        || object_copy_receipt.source() != &snapshot.live_objects.storage
        || object_copy_receipt.destination() != &objects.storage
        || object_copy_receipt.source() == object_copy_receipt.destination()
        || object_copy_receipt.object_count() != expected_count
        || object_copy_receipt.ciphertext_bytes() != expected_bytes
        || object_copy_receipt.inventory_root() != object_inventory_root(&snapshot.live_objects)?
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

fn validate_database_artifact(artifact: &PostgresDatabaseBackupArtifact) -> Result<(), StoreError> {
    if artifact.archive_format != POSTGRES_BACKUP_ARCHIVE_FORMAT
        || artifact.archive_size_bytes == 0
        || artifact.archive_size_bytes > MAX_DATABASE_BACKUP_BYTES
        || !valid_checksum(&artifact.archive_checksum)
        || !valid_checksum(&artifact.source_database_identity)
        || !valid_checksum(&artifact.exported_snapshot_checksum)
        || !valid_checksum(&artifact.transaction_snapshot_checksum)
    {
        Err(StoreError::new(StoreErrorCode::InvalidRecord))
    } else {
        Ok(())
    }
}

fn validate_migration_inventory(
    migrations: &[PostgresMigrationBackupEntry],
) -> Result<(), StoreError> {
    if migrations.is_empty() || migrations.len() > 4_096 {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    for (index, migration) in migrations.iter().enumerate() {
        let expected = u32::try_from(index + 1)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        if migration.sequence != expected
            || migration.name.is_empty()
            || migration.name.len() > 256
            || migration.name.bytes().any(|byte| byte.is_ascii_control())
            || !valid_checksum(&migration.checksum)
            || migration.minimum_application_major <= 0
            || migration.minimum_application_major > APPLICATION_MAJOR
            || migration.maximum_application_major < APPLICATION_MAJOR
            || migration.applied_at_unix_micros < 0
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
    }
    Ok(())
}

fn validate_backup_inventory(inventory: &PostgresBackupInventory) -> Result<(), StoreError> {
    let tenants: Vec<_> = inventory
        .tenants
        .iter()
        .map(|entry| entry.tenant_id.clone())
        .collect();
    validate_sorted_tenants(&tenants)?;
    validate_database_artifact(&inventory.database)?;
    validate_migration_inventory(&inventory.migrations)?;
    inventory.objects.validate()?;
    let migration_sequence = u32::try_from(inventory.migrations.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let object_count = u64::try_from(inventory.objects.entries.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let expected_revision_history_count = inventory
        .repository_revision
        .0
        .checked_add(1)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
    if inventory.format_version != POSTGRES_BACKUP_FORMAT_VERSION
        || inventory.migration_sequence == 0
        || inventory.migration_sequence != migration_sequence
        || inventory.migration_inventory_root != migration_inventory_root(&inventory.migrations)?
        || inventory.revision_history_count != expected_revision_history_count
        || !valid_checksum(&inventory.revision_history_root)
        || inventory.created_at_unix_nanos <= 0
        || inventory.tenant_set_checksum != tenant_set_checksum(&tenants)?
        || inventory.object_copy_receipt.destination != inventory.objects.storage
        || inventory.object_copy_receipt.source == inventory.object_copy_receipt.destination
        || inventory.object_copy_receipt.object_count != object_count
        || inventory.object_copy_receipt.ciphertext_bytes
            != object_inventory_bytes(&inventory.objects)?
        || !valid_checksum(&inventory.object_copy_receipt.inventory_root)
        || inventory.tenants.iter().any(|entry| {
            let has_state = entry.state_revision.is_some();
            has_state != entry.state_checksum.is_some()
                || has_state != (entry.state_history_count > 0)
                || !valid_checksum(&entry.state_history_root)
                || !valid_checksum(&entry.atom_projection_root)
                || !valid_checksum(&entry.operational_root)
                || entry
                    .state_revision
                    .is_some_and(|revision| revision > inventory.repository_revision)
                || entry
                    .state_checksum
                    .as_ref()
                    .is_some_and(|checksum| !valid_checksum(checksum))
        })
        || backup_inventory_root(inventory)? != inventory.canonical_root
    {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(())
}

fn validate_sorted_tenants(tenants: &[RecordId]) -> Result<(), StoreError> {
    if tenants.is_empty()
        || tenants.len() > 65_536
        || tenants.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left >= right)
        })
    {
        Err(StoreError::new(StoreErrorCode::InvalidContext))
    } else {
        Ok(())
    }
}

fn valid_checksum(value: &str) -> bool {
    value.len() == 68
        && value.starts_with("1220")
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn tenant_set_checksum(tenants: &[RecordId]) -> Result<String, StoreError> {
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-BACKUP-TENANTS\0v1\0");
    digest.update(
        u64::try_from(tenants.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for tenant in tenants {
        digest.update(
            u64::try_from(tenant.as_str().len())
                .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
                .to_be_bytes(),
        );
        digest.update(tenant.as_str().as_bytes());
    }
    Ok(format!("1220{}", hex_bytes(&digest.finalize())))
}

fn migration_inventory_root(
    migrations: &[PostgresMigrationBackupEntry],
) -> Result<String, StoreError> {
    validate_migration_inventory(migrations)?;
    let bytes = encode(migrations)?;
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-BACKUP-MIGRATIONS\0v1\0");
    digest.update(bytes);
    Ok(format!("1220{}", hex_bytes(&digest.finalize())))
}

fn object_inventory_root(inventory: &ObjectBackupInventory) -> Result<String, StoreError> {
    inventory.validate()?;
    Ok(format!(
        "1220{}",
        hex_bytes(&Sha256::digest(encode(inventory)?))
    ))
}

fn object_inventory_bytes(inventory: &ObjectBackupInventory) -> Result<u64, StoreError> {
    inventory.entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.size_bytes)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))
    })
}

fn backup_inventory_root(inventory: &PostgresBackupInventory) -> Result<String, StoreError> {
    let semantic_fields = (
        inventory.format_version,
        inventory.migration_sequence,
        inventory.repository_revision,
        inventory.revision_history_count,
        &inventory.revision_history_root,
        inventory.created_at_unix_nanos,
        &inventory.database,
        &inventory.migrations,
        &inventory.migration_inventory_root,
        &inventory.tenant_set_checksum,
        &inventory.tenants,
        &inventory.objects,
        &inventory.object_copy_receipt,
    );
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-BACKUP-INVENTORY\0v2\0");
    digest.update(encode(&semantic_fields)?);
    Ok(format!("1220{}", hex_bytes(&digest.finalize())))
}

fn backup_inventory_digest(inventory: &PostgresBackupInventory) -> Result<[u8; 32], StoreError> {
    let bytes = encode(inventory)?;
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-POSTGRES-BACKUP-SIGNATURE\0v2\0");
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _result = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn timeout_value(duration: Duration) -> Result<String, StoreError> {
    let millis = duration.as_millis();
    if millis == 0 || millis > 300_000 {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(format!("{millis}ms"))
}

fn backup_timeout_value(duration: Duration) -> Result<String, StoreError> {
    let millis = duration.as_millis();
    if !(60_000..=86_400_000).contains(&millis) {
        return Err(StoreError::new(StoreErrorCode::InvalidContext));
    }
    Ok(format!("{millis}ms"))
}

fn lock_revision(client: &mut impl GenericClient) -> Result<StoreRevision, StoreError> {
    client
        .query_one(
            "SELECT revision FROM cigar_repository_revision WHERE singleton = true FOR UPDATE",
            &[],
        )
        .map_err(postgres_error)
        .and_then(|row| from_i64_revision(row.get(0)))
}

fn current_revision(client: &mut impl GenericClient) -> Result<StoreRevision, StoreError> {
    client
        .query_one(
            "SELECT revision FROM cigar_repository_revision WHERE singleton = true",
            &[],
        )
        .map_err(postgres_error)
        .and_then(|row| from_i64_revision(row.get(0)))
}

fn load_state(
    client: &mut impl GenericClient,
    tenant: &RecordId,
    selection: SnapshotSelection,
) -> Result<CommittedState, StoreError> {
    let revision = match selection {
        SnapshotSelection::Latest => current_revision(client)?,
        SnapshotSelection::Revision(revision) => {
            let current = current_revision(client)?;
            if current.0.saturating_sub(revision.0)
                >= u64::try_from(MAX_RETAINED_POSTGRES_TENANT_SNAPSHOTS)
                    .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
            {
                return Err(StoreError::new(StoreErrorCode::NotFound));
            }
            let revision_i64 = to_i64_revision(revision)?;
            if !client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM cigar_repository_revisions WHERE revision = $1)",
                    &[&revision_i64],
                )
                .map_err(postgres_error)?
                .get::<_, bool>(0)
            {
                return Err(StoreError::new(StoreErrorCode::NotFound));
            }
            revision
        }
    };
    load_state_at_revision(client, tenant, revision)
}

fn load_state_at_revision(
    client: &mut impl GenericClient,
    tenant: &RecordId,
    revision: StoreRevision,
) -> Result<CommittedState, StoreError> {
    let revision_i64 = to_i64_revision(revision)?;
    let row = client
        .query_opt(
            "SELECT state, checksum
             FROM cigar_tenant_states
             WHERE tenant_id = $1 AND revision <= $2
             ORDER BY revision DESC
             LIMIT 1",
            &[&tenant.as_str(), &revision_i64],
        )
        .map_err(postgres_error)?;
    let mut state = CommittedState {
        revision,
        tenants: BTreeMap::new(),
    };
    if let Some(row) = row {
        let bytes: Vec<u8> = row.get(0);
        let checksum: String = row.get(1);
        if checksum_bytes(&bytes) != checksum {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let tenant_state: TenantState = decode(&bytes)?;
        state.tenants.insert(tenant.clone(), tenant_state);
    }
    state.ensure_atom_indexes()?;
    validate_committed_service_state(&state)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))?;
    Ok(state)
}

struct AtomProjectionRecord {
    atom_id: String,
    lineage_id: String,
    version_id: String,
    record: Vec<u8>,
    checksum: String,
}

fn prepare_projection_records(
    tenant: &RecordId,
    atoms: &[ContextAtomV1],
) -> Result<Vec<AtomProjectionRecord>, StoreError> {
    if atoms.is_empty() || atoms.len() > MAX_ATOM_PROJECTION_RESTORE_ITEMS {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let mut atom_ids = BTreeSet::new();
    let mut version_ids = BTreeSet::new();
    let mut total_bytes = 0_usize;
    let mut records = Vec::with_capacity(atoms.len());
    for atom in atoms {
        validate(atom)?;
        if &atom.scope.tenant_id != tenant {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        if !atom_ids.insert(atom.atom_id.as_str()) || !version_ids.insert(atom.version_id.as_str())
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        let record = encode(atom)?;
        total_bytes = total_bytes
            .checked_add(record.len())
            .filter(|bytes| *bytes <= MAX_ATOM_PROJECTION_RESTORE_BYTES)
            .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
        records.push(AtomProjectionRecord {
            atom_id: atom.atom_id.as_str().to_owned(),
            lineage_id: atom.lineage_id.as_str().to_owned(),
            version_id: atom.version_id.as_str().to_owned(),
            checksum: checksum_bytes(&record),
            record,
        });
    }
    Ok(records)
}

fn ensure_repository_revision(
    client: &mut impl GenericClient,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    let revision = to_i64_revision(revision)?;
    let exists: bool = client
        .query_one(
            "SELECT EXISTS(
                 SELECT 1 FROM cigar_repository_revisions WHERE revision = $1
             )",
            &[&revision],
        )
        .map_err(postgres_error)?
        .get(0);
    if exists {
        Ok(())
    } else {
        Err(StoreError::new(StoreErrorCode::NotFound))
    }
}

fn insert_projection_records(
    transaction: &mut Transaction<'_>,
    tenant: &RecordId,
    revision: StoreRevision,
    records: &[AtomProjectionRecord],
) -> Result<u64, StoreError> {
    if records.is_empty() || records.len() > MAX_ATOM_PROJECTION_RESTORE_ITEMS {
        return Err(StoreError::new(StoreErrorCode::LimitExceeded));
    }
    let atom_ids = records
        .iter()
        .map(|record| record.atom_id.as_str())
        .collect::<Vec<_>>();
    let lineage_ids = records
        .iter()
        .map(|record| record.lineage_id.as_str())
        .collect::<Vec<_>>();
    let version_ids = records
        .iter()
        .map(|record| record.version_id.as_str())
        .collect::<Vec<_>>();
    let encoded = records
        .iter()
        .map(|record| record.record.as_slice())
        .collect::<Vec<_>>();
    let checksums = records
        .iter()
        .map(|record| record.checksum.as_str())
        .collect::<Vec<_>>();
    let revision = to_i64_revision(revision)?;
    transaction
        .execute(
            "INSERT INTO cigar_atom_projection
               (tenant_id, atom_id, lineage_id, version_id, record,
                record_checksum, published_revision)
             SELECT $1, restored.atom_id, restored.lineage_id, restored.version_id,
                    restored.record, restored.record_checksum, $7
             FROM unnest($2::text[], $3::text[], $4::text[], $5::bytea[], $6::text[])
                  AS restored(atom_id, lineage_id, version_id, record, record_checksum)
             ON CONFLICT DO NOTHING",
            &[
                &tenant.as_str(),
                &atom_ids,
                &lineage_ids,
                &version_ids,
                &encoded,
                &checksums,
                &revision,
            ],
        )
        .map_err(postgres_error)
}

fn verify_projection_records(
    transaction: &mut Transaction<'_>,
    tenant: &RecordId,
    records: &[AtomProjectionRecord],
) -> Result<(), StoreError> {
    let atom_ids = records
        .iter()
        .map(|record| record.atom_id.as_str())
        .collect::<Vec<_>>();
    let lineage_ids = records
        .iter()
        .map(|record| record.lineage_id.as_str())
        .collect::<Vec<_>>();
    let version_ids = records
        .iter()
        .map(|record| record.version_id.as_str())
        .collect::<Vec<_>>();
    let checksums = records
        .iter()
        .map(|record| record.checksum.as_str())
        .collect::<Vec<_>>();
    let sizes = records
        .iter()
        .map(|record| i64::try_from(record.record.len()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    let matched: i64 = transaction
        .query_one(
            "SELECT count(*)
             FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[])
                  AS expected(atom_id, lineage_id, version_id, record_checksum, record_size)
             JOIN cigar_atom_projection AS observed
               ON observed.tenant_id = $1
              AND observed.atom_id = expected.atom_id
              AND observed.lineage_id = expected.lineage_id
              AND observed.version_id = expected.version_id
              AND observed.record_checksum = expected.record_checksum
              AND octet_length(observed.record) = expected.record_size",
            &[
                &tenant.as_str(),
                &atom_ids,
                &lineage_ids,
                &version_ids,
                &checksums,
                &sizes,
            ],
        )
        .map_err(postgres_error)?
        .get(0);
    if usize::try_from(matched).ok() != Some(records.len()) {
        return Err(StoreError::new(StoreErrorCode::InvalidRecord));
    }
    Ok(())
}

fn decode_projection_row(
    tenant: &RecordId,
    version: &VersionId,
    row: &postgres::Row,
) -> Result<ContextAtomV1, StoreError> {
    let atom_id: String = row.get(0);
    let lineage_id: String = row.get(1);
    let record: Vec<u8> = row.get(2);
    let checksum: String = row.get(3);
    if !valid_checksum(&checksum) || checksum_bytes(&record) != checksum {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    let atom: ContextAtomV1 = decode(&record)?;
    validate(&atom)?;
    if &atom.scope.tenant_id != tenant
        || atom.version_id != *version
        || atom.atom_id.as_str() != atom_id
        || atom.lineage_id.as_str() != lineage_id
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(atom)
}

fn publish_state(
    transaction: &mut Transaction<'_>,
    tenant: &RecordId,
    state: &CommittedState,
) -> Result<(), StoreError> {
    let tenant_state = state.tenants.get(tenant).cloned().unwrap_or_default();
    let bytes = encode(&tenant_state)?;
    let checksum = checksum_bytes(&bytes);
    let revision = to_i64_revision(state.revision)?;
    transaction
        .execute(
            "INSERT INTO cigar_repository_revisions (revision) VALUES ($1)",
            &[&revision],
        )
        .map_err(postgres_error)?;
    transaction
        .execute(
            "INSERT INTO cigar_tenant_states (tenant_id, revision, state, checksum)
             VALUES ($1, $2, $3, $4)",
            &[&tenant.as_str(), &revision, &bytes, &checksum],
        )
        .map_err(postgres_error)?;
    transaction
        .execute(
            "UPDATE cigar_repository_revision SET revision = $1
             WHERE singleton = true",
            &[&revision],
        )
        .map_err(postgres_error)?;
    transaction
        .execute(
            "INSERT INTO cigar_shared_wakeups (tenant_id, revision, topic)
             VALUES ($1, $2, 'repository.commit')",
            &[&tenant.as_str(), &revision],
        )
        .map_err(postgres_error)?;
    let tenant_value = tenant.as_str();
    let snapshot_limit = i64::try_from(MAX_RETAINED_POSTGRES_TENANT_SNAPSHOTS)
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    transaction
        .execute(
            "DELETE FROM cigar_tenant_states
             WHERE tenant_id = $1
               AND revision NOT IN (
                   SELECT revision FROM cigar_tenant_states
                   WHERE tenant_id = $1
                   ORDER BY revision DESC
                   LIMIT $2
               )",
            &[&tenant_value, &snapshot_limit],
        )
        .map_err(postgres_error)?;
    let wakeup_limit = i64::try_from(MAX_RETAINED_POSTGRES_WAKEUPS_PER_TENANT)
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    transaction
        .execute(
            "DELETE FROM cigar_shared_wakeups
             WHERE tenant_id = $1
               AND (revision, topic) NOT IN (
                   SELECT revision, topic FROM cigar_shared_wakeups
                   WHERE tenant_id = $1
                   ORDER BY revision DESC, topic DESC
                   LIMIT $2
               )",
            &[&tenant_value, &wakeup_limit],
        )
        .map_err(postgres_error)?;
    transaction
        .query_one("SELECT pg_notify('cigar_events', '')", &[])
        .map(|_row| ())
        .map_err(postgres_error)
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

fn migrate(connection: &mut postgres::Client) -> Result<(), StoreError> {
    migrate_with_observer(connection, |_boundary| Ok(()))
}

fn migrate_with_observer(
    connection: &mut postgres::Client,
    mut observe: impl FnMut(PostgresMigrationBoundary) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    verify_migrator_authority(connection)?;
    connection
        .batch_execute(
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC;
             CREATE TABLE IF NOT EXISTS public.schema_migrations (
                sequence integer PRIMARY KEY,
                name text NOT NULL UNIQUE,
                checksum text NOT NULL,
                minimum_application_major integer NOT NULL,
                maximum_application_major integer NOT NULL,
                online boolean NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             )",
        )
        .map_err(postgres_error)?;
    observe(PostgresMigrationBoundary::AfterLedgerBootstrap)?;
    let mut transaction = connection
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .map_err(postgres_error)?;
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .map_err(postgres_error)?;
    observe(PostgresMigrationBoundary::AfterAdvisoryLock)?;
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        let sequence = i32::try_from(index + 1)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let checksum = checksum_bytes(migration.sql.as_bytes());
        let stored = transaction
            .query_opt(
                "SELECT name, checksum FROM public.schema_migrations WHERE sequence = $1",
                &[&sequence],
            )
            .map_err(postgres_error)?;
        if let Some(stored) = stored {
            if stored.get::<_, String>(0) != migration.name
                || stored.get::<_, String>(1) != checksum
            {
                return Err(StoreError::new(StoreErrorCode::Unavailable));
            }
            continue;
        }
        transaction
            .batch_execute(migration.sql)
            .map_err(postgres_error)?;
        observe(PostgresMigrationBoundary::AfterMigrationSql(
            u32::try_from(sequence)
                .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
        ))?;
        transaction
            .execute(
                "INSERT INTO public.schema_migrations
                   (sequence, name, checksum, minimum_application_major,
                    maximum_application_major, online)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &sequence,
                    &migration.name,
                    &checksum,
                    &migration.minimum_application_major,
                    &migration.maximum_application_major,
                    &migration.online,
                ],
            )
            .map_err(postgres_error)?;
        observe(PostgresMigrationBoundary::AfterLedgerInsert(
            u32::try_from(sequence)
                .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
        ))?;
    }
    observe(PostgresMigrationBoundary::BeforeCommit)?;
    transaction.commit().map_err(postgres_error)?;
    observe(PostgresMigrationBoundary::AfterCommit)
}

fn verify_migrator_authority(connection: &mut postgres::Client) -> Result<(), StoreError> {
    let owns_database: bool = connection
        .query_one(
            "SELECT owner.rolname = current_user AND session_user = current_user
             FROM pg_database AS database
             JOIN pg_roles AS owner ON owner.oid = database.datdba
             WHERE database.datname = current_database()",
            &[],
        )
        .map_err(postgres_error)?
        .get(0);
    if owns_database {
        Ok(())
    } else {
        Err(StoreError::new(StoreErrorCode::Unavailable))
    }
}

fn verify_schema(connection: &mut postgres::Client) -> Result<(), StoreError> {
    let count: i64 = connection
        .query_one(
            "SELECT count(*)
             FROM pg_class AS c
             JOIN pg_namespace AS n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public'
               AND c.relname IN ('cigar_tenant_states', 'cigar_shared_wakeups',
                                 'cigar_object_commits', 'cigar_worker_claims',
                                 'cigar_atom_projection')
               AND c.relrowsecurity AND c.relforcerowsecurity",
            &[],
        )
        .map_err(postgres_error)?
        .get(0);
    let projection_shape = connection
        .query_one(
            "SELECT
               (SELECT count(*) FROM pg_attribute
                WHERE attrelid = 'public.cigar_atom_projection'::regclass
                  AND attnum > 0 AND NOT attisdropped),
               count(*) FILTER (WHERE contype = 'p'),
               count(*) FILTER (WHERE contype = 'u'),
               count(*) FILTER (WHERE contype = 'f'),
               (SELECT count(*) FROM pg_policy
                WHERE polrelid = 'public.cigar_atom_projection'::regclass)
             FROM pg_constraint
             WHERE conrelid = 'public.cigar_atom_projection'::regclass",
            &[],
        )
        .map_err(postgres_error)?;
    let projection_shape: (i64, i64, i64, i64, i64) = (
        projection_shape.get(0),
        projection_shape.get(1),
        projection_shape.get(2),
        projection_shape.get(3),
        projection_shape.get(4),
    );
    let gc_guard = connection
        .query_one(
            "SELECT p.prosecdef,
                    p.provolatile = 'v',
                    p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[],
                    NOT EXISTS (
                        SELECT 1
                        FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) AS acl
                        WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                    )
             FROM pg_proc AS p
             JOIN pg_namespace AS n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'
               AND p.proname = 'cigar_gc_lock_repository_revision'
               AND pg_get_function_identity_arguments(p.oid) = ''",
            &[],
        )
        .map_err(postgres_error)?;
    let gc_guard: (bool, bool, bool, bool) = (
        gc_guard.get(0),
        gc_guard.get(1),
        gc_guard.get(2),
        gc_guard.get(3),
    );
    let revision = current_revision(connection)?;
    if count != 5
        || projection_shape != (8, 1, 1, 1, 1)
        || gc_guard != (true, true, true, true)
        || revision > StoreRevision(i64::MAX as u64)
    {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    Ok(())
}

fn verify_migrations(
    connection: &mut impl GenericClient,
) -> Result<PostgresMigrationReceipt, StoreError> {
    let rows = connection
        .query(
            "SELECT sequence, name, checksum,
                    minimum_application_major, maximum_application_major, online
             FROM public.schema_migrations
             ORDER BY sequence",
            &[],
        )
        .map_err(postgres_error)?;
    if rows.len() != MIGRATIONS.len() {
        return Err(StoreError::new(StoreErrorCode::Unavailable));
    }
    for (index, row) in rows.iter().enumerate() {
        let expected_sequence = i32::try_from(index + 1)
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
        let minimum: i32 = row.get(3);
        let maximum: i32 = row.get(4);
        let online: bool = row.get(5);
        if row.get::<_, i32>(0) != expected_sequence
            || minimum <= 0
            || minimum > APPLICATION_MAJOR
            || maximum < APPLICATION_MAJOR
            || row.get::<_, String>(1).is_empty()
            || row.get::<_, String>(1).len() > 256
            || row
                .get::<_, String>(1)
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !valid_checksum(&row.get::<_, String>(2))
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
        let Some(migration) = MIGRATIONS.get(index) else {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        };
        if row.get::<_, String>(1) != migration.name
            || row.get::<_, String>(2) != checksum_bytes(migration.sql.as_bytes())
            || minimum != migration.minimum_application_major
            || maximum != migration.maximum_application_major
            || online != migration.online
        {
            return Err(StoreError::new(StoreErrorCode::Unavailable));
        }
    }
    let latest = u32::try_from(rows.len())
        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?;
    Ok(PostgresMigrationReceipt {
        latest_sequence: latest,
        checksums_verified: u32::try_from(MIGRATIONS.len())
            .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?,
    })
}

fn encode<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))?;
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    ciborium::de::from_reader(bytes).map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

fn checksum_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut checksum = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        let _result = write!(&mut checksum, "{byte:02x}");
    }
    checksum
}

fn next_revision(current: StoreRevision) -> Result<StoreRevision, StoreError> {
    current
        .0
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .map(StoreRevision)
        .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn to_i64_revision(revision: StoreRevision) -> Result<i64, StoreError> {
    i64::try_from(revision.0).map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))
}

fn from_i64_revision(revision: i64) -> Result<StoreRevision, StoreError> {
    u64::try_from(revision)
        .map(StoreRevision)
        .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
}

fn validate_worker_selector(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Err(StoreError::new(StoreErrorCode::InvalidContext))
    } else {
        Ok(())
    }
}

fn postgres_error(error: postgres::Error) -> StoreError {
    let code = error.code();
    if code == Some(&SqlState::T_R_SERIALIZATION_FAILURE)
        || code == Some(&SqlState::T_R_DEADLOCK_DETECTED)
        || code == Some(&SqlState::LOCK_NOT_AVAILABLE)
    {
        StoreError::new(StoreErrorCode::RevisionConflict)
    } else {
        StoreError::new(StoreErrorCode::Unavailable)
    }
}

fn service_postgres_error(error: postgres::Error) -> ServiceError {
    map_store_error(postgres_error(error))
}

fn pool_error<E>(_error: E) -> StoreError {
    StoreError::new(StoreErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        MIGRATIONS, POSTGRES_BACKUP_ARCHIVE_FORMAT, POSTGRES_FIXED_OPTIONS, PostgresConfiguration,
        PostgresDatabaseBackupArtifact, PostgresMigrationBoundary, PostgresMigrationFailpoint,
        checksum_bytes, valid_checksum, verify_postgres_database_backup,
    };
    use postgres::config::SslMode;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use std::error::Error;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

    struct PostgresTlsFixture {
        ca_pem: String,
        untrusted_ca_pem: String,
        server_certificate_der: Vec<u8>,
        server_key_der: Vec<u8>,
    }

    enum FakePostgresTransport {
        Tls(Arc<ServerConfig>),
        PlaintextOnly,
    }

    #[derive(Debug)]
    struct FakePostgresObservation {
        request: [u8; 8],
        tls_handshake_succeeded: bool,
    }

    fn postgres_tls_fixture() -> Result<PostgresTlsFixture, Box<dyn Error>> {
        let mut ca_parameters = CertificateParams::new(Vec::<String>::new())?;
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = CertifiedIssuer::self_signed(ca_parameters, KeyPair::generate()?)?;

        let mut server_parameters =
            CertificateParams::new(vec!["postgres.test.invalid".to_owned()])?;
        server_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server_certificate = server_parameters.signed_by(&server_key, &ca)?;

        let mut untrusted_parameters = CertificateParams::new(Vec::<String>::new())?;
        untrusted_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        untrusted_parameters.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let untrusted_ca =
            CertifiedIssuer::self_signed(untrusted_parameters, KeyPair::generate()?)?;
        Ok(PostgresTlsFixture {
            ca_pem: ca.pem(),
            untrusted_ca_pem: untrusted_ca.pem(),
            server_certificate_der: server_certificate.der().to_vec(),
            server_key_der: server_key.serialize_der(),
        })
    }

    fn fake_tls_server_configuration(
        fixture: &PostgresTlsFixture,
    ) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
        let certificates = vec![CertificateDer::from(fixture.server_certificate_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.server_key_der.clone()));
        let configuration =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(certificates, key)?;
        Ok(Arc::new(configuration))
    }

    fn observe_fake_postgres_connection(
        listener: TcpListener,
        transport: FakePostgresTransport,
    ) -> Result<FakePostgresObservation, String> {
        let (mut stream, _peer) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| error.to_string())?;
        let mut request = [0_u8; 8];
        stream
            .read_exact(&mut request)
            .map_err(|error| error.to_string())?;
        match transport {
            FakePostgresTransport::PlaintextOnly => {
                stream.write_all(b"N").map_err(|error| error.to_string())?;
                Ok(FakePostgresObservation {
                    request,
                    tls_handshake_succeeded: false,
                })
            }
            FakePostgresTransport::Tls(configuration) => {
                stream.write_all(b"S").map_err(|error| error.to_string())?;
                let mut connection =
                    ServerConnection::new(configuration).map_err(|error| error.to_string())?;
                let succeeded =
                    connection.complete_io(&mut stream).is_ok() && !connection.is_handshaking();
                Ok(FakePostgresObservation {
                    request,
                    tls_handshake_succeeded: succeeded,
                })
            }
        }
    }

    fn connect_to_fake_postgres(
        server_name: &str,
        ca_pem: &[u8],
        url_ssl_mode: &str,
        transport: FakePostgresTransport,
    ) -> Result<(bool, FakePostgresObservation), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (sender, receiver) = mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let result = observe_fake_postgres_connection(listener, transport);
            let _sent = sender.send(result);
        });
        let url = format!(
            "host={server_name} hostaddr=127.0.0.1 port={port} user=cigar dbname=cigar \
             connect_timeout=1 sslmode={url_ssl_mode}"
        );
        let mut configuration = PostgresConfiguration::new(url)?;
        configuration.acquire_timeout = Duration::from_millis(250);
        configuration.configure_certificate_authority(server_name, ca_pem)?;
        let parsed = configuration.connection_configuration()?;
        let connected = parsed.connect(configuration.tls.connector()?).is_ok();
        let observation = receiver.recv_timeout(Duration::from_secs(3))??;
        server
            .join()
            .map_err(|_panic| "fake PostgreSQL server panicked")?;
        Ok((connected, observation))
    }

    fn artifact(bytes: &[u8]) -> Result<PostgresDatabaseBackupArtifact, Box<dyn Error>> {
        Ok(PostgresDatabaseBackupArtifact {
            archive_format: POSTGRES_BACKUP_ARCHIVE_FORMAT.to_owned(),
            archive_size_bytes: u64::try_from(bytes.len())?,
            archive_checksum: checksum_bytes(bytes),
            source_database_identity: checksum_bytes(b"source-database"),
            exported_snapshot_checksum: checksum_bytes(b"snapshot-token"),
            transaction_snapshot_checksum: checksum_bytes(b"1:2:"),
        })
    }

    #[test]
    fn postgres_migration_sources_are_contiguous_rolling_and_self_describing() {
        assert_eq!(MIGRATIONS.len(), 4);
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            let sequence = index + 1;
            let checksum = checksum_bytes(migration.sql.as_bytes());
            assert!(valid_checksum(&checksum));
            assert_eq!(migration.minimum_application_major, 1);
            assert_eq!(migration.maximum_application_major, 2);
            assert!(migration.online);
            assert!(migration.sql.contains(&format!(
                "-- sequence/name: {sequence} / {}",
                migration.name
            )));
            assert!(
                migration
                    .sql
                    .contains("-- application compatibility: major 1 through major 2")
            );
            assert!(migration.sql.contains("-- classification/lock: online /"));
            assert!(migration.sql.contains("-- verification:"));
            assert!(migration.sql.contains("-- rollback or restore:"));
            assert!(!migration.sql.lines().any(|line| {
                let statement = line.trim_start().to_ascii_uppercase();
                let first = statement
                    .split(|character: char| character.is_ascii_whitespace() || character == ';')
                    .next()
                    .unwrap_or_default();
                !statement.starts_with("--")
                    && ["BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE"].contains(&first)
            }));
        }
    }

    #[test]
    fn postgres_migration_failpoint_catalog_covers_every_durable_boundary() {
        let boundaries = [
            PostgresMigrationBoundary::AfterLedgerBootstrap,
            PostgresMigrationBoundary::AfterAdvisoryLock,
            PostgresMigrationBoundary::AfterMigrationSql(1),
            PostgresMigrationBoundary::AfterLedgerInsert(1),
            PostgresMigrationBoundary::BeforeCommit,
            PostgresMigrationBoundary::AfterCommit,
        ];
        let failpoints = boundaries.map(PostgresMigrationFailpoint::from);
        assert_eq!(failpoints.len(), 6);
        assert_eq!(
            failpoints,
            [
                PostgresMigrationFailpoint::AfterLedgerBootstrap,
                PostgresMigrationFailpoint::AfterAdvisoryLock,
                PostgresMigrationFailpoint::AfterMigrationSql(1),
                PostgresMigrationFailpoint::AfterLedgerInsert(1),
                PostgresMigrationFailpoint::BeforeCommit,
                PostgresMigrationFailpoint::AfterCommit,
            ]
        );
    }

    #[test]
    fn database_backup_verifier_streams_exact_bytes_and_rejects_drift() -> Result<(), Box<dyn Error>>
    {
        let bytes = b"PGDMP\0bounded-database-archive";
        let artifact = artifact(bytes)?;
        let mut verified = verify_postgres_database_backup(&artifact, Cursor::new(bytes.to_vec()))?;
        let mut replayed = Vec::new();
        verified.read_to_end(&mut replayed)?;
        assert_eq!(replayed, bytes);
        assert_eq!(verified.bytes_consumed, artifact.archive_size_bytes);
        let truncated = bytes
            .get(..bytes.len().saturating_sub(1))
            .ok_or("missing truncated archive fixture")?;
        assert!(
            verify_postgres_database_backup(&artifact, Cursor::new(truncated.to_vec())).is_err()
        );
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(verify_postgres_database_backup(&artifact, Cursor::new(extended)).is_err());
        let mut changed = bytes.to_vec();
        *changed
            .get_mut(5)
            .ok_or("missing changed archive fixture byte")? ^= 1;
        assert!(verify_postgres_database_backup(&artifact, Cursor::new(changed)).is_err());
        Ok(())
    }

    #[test]
    fn postgres_transport_forces_tls_and_binds_the_configured_host() -> Result<(), Box<dyn Error>> {
        let configuration = PostgresConfiguration::new(
            "host=postgres.example hostaddr=127.0.0.1 user=cigar dbname=cigar sslmode=disable",
        )?;
        let parsed = configuration.connection_configuration()?;
        assert_eq!(parsed.get_ssl_mode(), SslMode::Require);
        assert_eq!(parsed.get_options(), Some(POSTGRES_FIXED_OPTIONS));

        assert!(
            PostgresConfiguration::new(
                "host=postgres.example user=cigar dbname=cigar \
                 options='-c search_path=attacker'"
            )
            .is_err()
        );
        assert!(
            PostgresConfiguration::new(
                "postgresql://cigar@postgres.example/cigar?options=-csearch_path%3Dattacker"
            )
            .is_err()
        );

        let mut wrong_name = configuration.clone();
        wrong_name.tls.server_name = "attacker.example".to_owned();
        assert!(wrong_name.validate().is_err());
        assert!(
            PostgresConfiguration::new(
                "host=postgres.example,attacker.example user=cigar dbname=cigar"
            )
            .is_err()
        );
        #[cfg(unix)]
        assert!(PostgresConfiguration::new("host=/tmp user=cigar dbname=cigar").is_err());
        Ok(())
    }

    #[test]
    fn postgres_explicit_ca_input_is_bounded_and_strict() -> Result<(), Box<dyn Error>> {
        let mut configuration =
            PostgresConfiguration::new("host=postgres.example user=cigar dbname=cigar")?;
        assert!(
            configuration
                .configure_certificate_authority("postgres.example", b"")
                .is_err()
        );
        assert!(
            configuration
                .configure_certificate_authority(
                    "postgres.example",
                    b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
                )
                .is_err()
        );
        assert!(
            configuration
                .configure_certificate_authority(
                    "attacker.example",
                    b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn postgres_tls_rejects_wrong_ca_name_plaintext_and_downgrade() -> Result<(), Box<dyn Error>> {
        let fixture = postgres_tls_fixture()?;
        let (connected, observation) = connect_to_fake_postgres(
            "postgres.test.invalid",
            fixture.ca_pem.as_bytes(),
            "require",
            FakePostgresTransport::Tls(fake_tls_server_configuration(&fixture)?),
        )?;
        assert!(
            !connected,
            "the fake server never completes PostgreSQL auth"
        );
        assert_eq!(observation.request, POSTGRES_SSL_REQUEST);
        assert!(observation.tls_handshake_succeeded);

        let (connected, observation) = connect_to_fake_postgres(
            "postgres.test.invalid",
            fixture.untrusted_ca_pem.as_bytes(),
            "require",
            FakePostgresTransport::Tls(fake_tls_server_configuration(&fixture)?),
        )?;
        assert!(!connected);
        assert_eq!(observation.request, POSTGRES_SSL_REQUEST);
        assert!(!observation.tls_handshake_succeeded);

        let (connected, observation) = connect_to_fake_postgres(
            "wrong-name.test.invalid",
            fixture.ca_pem.as_bytes(),
            "require",
            FakePostgresTransport::Tls(fake_tls_server_configuration(&fixture)?),
        )?;
        assert!(!connected);
        assert_eq!(observation.request, POSTGRES_SSL_REQUEST);
        assert!(!observation.tls_handshake_succeeded);

        let (connected, observation) = connect_to_fake_postgres(
            "postgres.test.invalid",
            fixture.ca_pem.as_bytes(),
            "disable",
            FakePostgresTransport::PlaintextOnly,
        )?;
        assert!(!connected);
        assert_eq!(observation.request, POSTGRES_SSL_REQUEST);
        assert!(!observation.tls_handshake_succeeded);
        Ok(())
    }
}
