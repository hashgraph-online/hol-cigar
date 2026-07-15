//! Live PostgreSQL shared-profile conformance, RLS, wakeup, and contention tests.

use cigar_crypto::{
    CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, MemoryKeyProvider,
};
use cigar_protocol::{
    BlobRef, ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, EdgeKind,
    EffectJournalEvent, IdempotencyKey, RecordId, SourceSnapshot, VersionId,
};
use cigar_store::conformance::{RepositoryFixture, run_repository_conformance};
use cigar_store::{
    AccessContext, BlobRecord, CancellationToken, GarbageCollectionPolicy, IdempotencyIdentity,
    InMemoryObjectStorage, LocalBlobStore, LocalRepositoryBlobStore, ObjectFailpoint,
    ObjectRepositoryBlobStore, ObjectStorage, OutboxMessage, PostgresConfiguration,
    PostgresDatabaseBackupArtifact, PostgresStore, ReadTransaction, Repository,
    RepositoryBlobStore, RepositoryGarbageCollectionCandidate, S3CompatibleObjectStorage,
    ServiceBatch, ServiceErrorCode, ServiceExpectedVersion, ServiceIdempotency, ServiceListQuery,
    ServiceListScope, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite,
    ServiceRepository, ServiceResponse, SignedPostgresBackupInventory, SqliteStore, StoreErrorCode,
    StoreRevision, WriteTransaction, restore_object_backup_inventory,
    sign_postgres_backup_inventory, verify_postgres_backup_inventory,
    verify_postgres_backup_inventory_trusted, verify_postgres_database_backup,
};
use postgres::NoTls;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

fn live_postgres_configuration(
    database_url: String,
) -> Result<PostgresConfiguration, Box<dyn Error>> {
    let certificate_authority = std::fs::read(std::env::var("CIGAR_TEST_POSTGRES_CA_PATH")?)?;
    if certificate_authority.is_empty() || certificate_authority.len() > 2 * 1024 * 1024 {
        return Err("PostgreSQL qualification CA is empty or too large".into());
    }
    let server_name = std::env::var("CIGAR_TEST_POSTGRES_SERVER_NAME")?;
    Ok(PostgresConfiguration::new_with_certificate_authority(
        database_url,
        server_name,
        &certificate_authority,
    )?)
}

struct TestDatabase {
    admin_url: String,
    database: String,
    role: String,
    backup_role: String,
    garbage_collection_role: String,
    membership_role: String,
    owner_url: String,
    runtime_url: String,
    backup_url: String,
    garbage_collection_url: String,
}

impl TestDatabase {
    fn create(admin_url: String) -> Result<Self, Box<dyn Error>> {
        let suffix = NEXT_DATABASE.fetch_add(1, Ordering::AcqRel);
        let database = format!("cigar_wp18_{}_{suffix}", std::process::id());
        let role = format!("cigar_wp18_runtime_{}_{suffix}", std::process::id());
        let backup_role = format!("cigar_wp18_backup_{}_{suffix}", std::process::id());
        let garbage_collection_role = format!("cigar_wp18_gc_{}_{suffix}", std::process::id());
        let membership_role = format!("cigar_wp18_bridge_{}_{suffix}", std::process::id());
        let password = format!("wp18-runtime-{suffix}-only");
        let backup_password = format!("wp18-backup-{suffix}-only");
        let garbage_collection_password = format!("wp18-gc-{suffix}-only");
        let (prefix, _database_and_query) = admin_url
            .rsplit_once('/')
            .ok_or("PostgreSQL test URL must end in a database name")?;
        let owner_url = format!("{prefix}/{database}");
        let mut admin = postgres::Client::connect(&admin_url, NoTls)?;
        admin.batch_execute(&format!("CREATE DATABASE {database}"))?;
        let mut owner = postgres::Client::connect(&owner_url, NoTls)?;
        owner.batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}'
               NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
             CREATE ROLE {backup_role} LOGIN PASSWORD '{backup_password}'
               NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
             CREATE ROLE {garbage_collection_role} LOGIN PASSWORD '{garbage_collection_password}'
               NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
             CREATE ROLE {membership_role} NOLOGIN
               NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;"
        ))?;
        let runtime_url = format!("postgresql://{role}:{password}@127.0.0.1:55432/{database}");
        let backup_url =
            format!("postgresql://{backup_role}:{backup_password}@127.0.0.1:55432/{database}");
        let garbage_collection_url = format!(
            "postgresql://{garbage_collection_role}:{garbage_collection_password}@127.0.0.1:55432/{database}"
        );
        Ok(Self {
            admin_url,
            database,
            role,
            backup_role,
            garbage_collection_role,
            membership_role,
            owner_url,
            runtime_url,
            backup_url,
            garbage_collection_url,
        })
    }

    fn grant_runtime(&self) -> Result<(), Box<dyn Error>> {
        self.grant_runtime_at(&self.owner_url)
    }

    fn grant_backup(&self) -> Result<(), Box<dyn Error>> {
        self.grant_backup_at(&self.owner_url)
    }

    fn grant_garbage_collection(&self) -> Result<(), Box<dyn Error>> {
        self.grant_garbage_collection_at(&self.owner_url)
    }

    fn grant_runtime_at(&self, owner_url: &str) -> Result<(), Box<dyn Error>> {
        let mut owner = postgres::Client::connect(owner_url, NoTls)?;
        owner.batch_execute(&format!(
            "REVOKE CREATE ON SCHEMA public FROM {role};
             GRANT USAGE ON SCHEMA public TO {role};
             GRANT SELECT ON schema_migrations TO {role};
             GRANT SELECT, UPDATE ON cigar_repository_revision TO {role};
             GRANT SELECT, INSERT ON cigar_repository_revisions TO {role};
             GRANT SELECT, INSERT, UPDATE, DELETE ON cigar_tenant_states,
                 cigar_shared_wakeups, cigar_object_commits, cigar_worker_claims,
                 cigar_atom_projection TO {role};",
            role = self.role,
        ))?;
        Ok(())
    }

    fn grant_backup_at(&self, owner_url: &str) -> Result<(), Box<dyn Error>> {
        let mut owner = postgres::Client::connect(owner_url, NoTls)?;
        owner.batch_execute(&format!(
            "GRANT USAGE ON SCHEMA public TO {role};
             GRANT SELECT ON schema_migrations, cigar_repository_revision,
                 cigar_repository_revisions, cigar_tenant_states, cigar_shared_wakeups,
                 cigar_object_commits, cigar_worker_claims, cigar_atom_projection TO {role};
             REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision() FROM PUBLIC;
             REVOKE ALL ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {role};",
            role = self.backup_role,
        ))?;
        Ok(())
    }

    fn grant_garbage_collection_at(&self, owner_url: &str) -> Result<(), Box<dyn Error>> {
        let mut owner = postgres::Client::connect(owner_url, NoTls)?;
        owner.batch_execute(&format!(
            "GRANT USAGE ON SCHEMA public TO {role};
             GRANT SELECT ON schema_migrations, cigar_repository_revision,
                 cigar_repository_revisions, cigar_tenant_states, cigar_shared_wakeups,
                 cigar_object_commits, cigar_worker_claims, cigar_atom_projection TO {role};
             REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision() FROM PUBLIC;
             REVOKE ALL ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() TO {role};",
            role = self.garbage_collection_role,
        ))?;
        Ok(())
    }
}

struct ExtraDatabase {
    admin_url: String,
    database: String,
}

impl Drop for ExtraDatabase {
    fn drop(&mut self) {
        if let Ok(mut admin) = postgres::Client::connect(&self.admin_url, NoTls) {
            let _terminated = admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[&self.database],
            );
            let _dropped =
                admin.batch_execute(&format!("DROP DATABASE IF EXISTS {}", self.database));
        }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if let Ok(mut admin) = postgres::Client::connect(&self.admin_url, NoTls) {
            let _memberships = admin.batch_execute(&format!(
                "REVOKE {} FROM {};
                 REVOKE {} FROM {};",
                self.membership_role, self.role, self.backup_role, self.membership_role
            ));
            let _terminated = admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[&self.database],
            );
            let _dropped = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {};
                 DROP ROLE IF EXISTS {};
                 DROP ROLE IF EXISTS {};
                 DROP ROLE IF EXISTS {};
                 DROP ROLE IF EXISTS {};",
                self.database,
                self.role,
                self.backup_role,
                self.garbage_collection_role,
                self.membership_role
            ));
        }
    }
}

fn protocol_fixture<T: DeserializeOwned>(target: &str) -> Result<T, Box<dyn Error>> {
    let fixture = cigar_testkit::deterministic_protocol_fixture(target)
        .ok_or_else(|| format!("missing deterministic fixture `{target}`"))?;
    Ok(serde_json::from_value(fixture.input)?)
}

fn content_digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(ContentDigest::new(format!("1220{suffix}"))?)
}

fn repository_fixture() -> Result<RepositoryFixture, Box<dyn Error>> {
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

struct ObjectRepositoryFixture {
    storage: Arc<InMemoryObjectStorage>,
    repository: Arc<ObjectRepositoryBlobStore<MemoryKeyProvider, InMemoryObjectStorage>>,
    provider: Arc<MemoryKeyProvider>,
    key_ref: KeyRef,
}

fn object_repository(tenant: &RecordId) -> Result<ObjectRepositoryFixture, Box<dyn Error>> {
    let provider = Arc::new(MemoryKeyProvider::default());
    let key = provider.create(CreateKeyRequest {
        tenant: tenant.as_str().to_owned(),
        purpose: KeyPurpose::BlobEncryption,
        algorithm: KeyAlgorithm::XChaCha20Poly1305,
        created_at: 1,
        activated_at: 1,
    })?;
    let objects = Arc::new(InMemoryObjectStorage::default());
    let repository = Arc::new(ObjectRepositoryBlobStore::new(
        Arc::clone(&provider),
        Arc::clone(&objects),
        key.key_ref.clone(),
        1,
        [0x31; 32],
    ));
    Ok(ObjectRepositoryFixture {
        storage: objects,
        repository,
        provider,
        key_ref: key.key_ref,
    })
}

fn sqlite_repository(
    tenant: &RecordId,
    directory: &tempfile::TempDir,
) -> Result<SqliteStore, Box<dyn Error>> {
    let provider = Arc::new(MemoryKeyProvider::default());
    let key = provider.create(CreateKeyRequest {
        tenant: tenant.as_str().to_owned(),
        purpose: KeyPurpose::BlobEncryption,
        algorithm: KeyAlgorithm::XChaCha20Poly1305,
        created_at: 1,
        activated_at: 1,
    })?;
    let local = LocalBlobStore::open(directory.path().join("blobs"), provider)?;
    let blobs: Arc<dyn RepositoryBlobStore> =
        Arc::new(LocalRepositoryBlobStore::new(local, key.key_ref, 1));
    Ok(SqliteStore::open_with_blob_repository(
        directory.path().join("state.sqlite3"),
        blobs,
    )?)
}

fn container_archive_evidence(
    container: &str,
    dump_path: &str,
) -> Result<(u64, String), Box<dyn Error>> {
    let size = Command::new("docker")
        .args(["exec", container, "stat", "-c", "%s", dump_path])
        .output()?;
    if !size.status.success() {
        return Err("archive size command failed".into());
    }
    let size = std::str::from_utf8(&size.stdout)?.trim().parse::<u64>()?;
    let checksum = Command::new("docker")
        .args(["exec", container, "sha256sum", dump_path])
        .output()?;
    if !checksum.status.success() {
        return Err("archive checksum command failed".into());
    }
    let checksum = std::str::from_utf8(&checksum.stdout)?
        .split_whitespace()
        .next()
        .ok_or("archive checksum command returned no digest")?;
    if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("archive checksum command returned an invalid digest".into());
    }
    Ok((size, format!("1220{}", checksum.to_ascii_lowercase())))
}

#[allow(clippy::too_many_arguments)]
fn native_dump_restore_drill(
    database: &TestDatabase,
    source_objects: &ObjectRepositoryFixture,
    source_store: &Arc<PostgresStore>,
    tenants: &[RecordId],
    context: &AccessContext,
    concurrent_snapshot: SourceSnapshot,
    signing_provider: &MemoryKeyProvider,
    signing_key: &KeyRef,
    signing_tenant: &str,
) -> Result<SignedPostgresBackupInventory, Box<dyn Error>> {
    let container = match std::env::var("CIGAR_TEST_POSTGRES_CONTAINER") {
        Ok(value) => value,
        Err(_error) if std::env::var_os("CIGAR_REQUIRE_LIVE_SHARED_TESTS").is_none() => {
            return Err("native backup drill requires the live shared profile".into());
        }
        Err(_error) => {
            return Err("required PostgreSQL backup container was not configured".into());
        }
    };
    if container.is_empty()
        || !container
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("invalid PostgreSQL qualification container selector".into());
    }
    let migrator_user = std::env::var("CIGAR_TEST_POSTGRES_MIGRATOR_USER")?;
    let s3_endpoint = std::env::var("CIGAR_TEST_S3_ENDPOINT")?;
    let s3_bucket = std::env::var("CIGAR_TEST_S3_BUCKET")?;
    let s3_admin_access_key = std::env::var("CIGAR_TEST_S3_ADMIN_ACCESS_KEY")?;
    let s3_admin_secret_key = std::env::var("CIGAR_TEST_S3_ADMIN_SECRET_KEY")?;
    let s3_runtime_access_key = std::env::var("CIGAR_TEST_S3_ACCESS_KEY")?;
    let s3_runtime_secret_key = std::env::var("CIGAR_TEST_S3_SECRET_KEY")?;
    let target_name = format!("{}_restore", database.database);
    let dump_path = format!("/tmp/{}.dump", database.database);
    let backup_prefix = format!("cigar-v1/wp18-integrated-{}-backup/", std::process::id());
    let restored_prefix = format!("cigar-v1/wp18-integrated-{}-restore/", std::process::id());
    let backup_storage = Arc::new(S3CompatibleObjectStorage::new(
        &s3_endpoint,
        "us-east-1",
        &s3_bucket,
        &backup_prefix,
        &s3_admin_access_key,
        &s3_admin_secret_key,
        None,
        true,
    )?);
    let capture_repository: Arc<dyn RepositoryBlobStore> = source_objects.repository.clone();
    let capture_store = Arc::new(PostgresStore::connect_backup_with_blob_repository(
        live_postgres_configuration(database.backup_url.clone())?,
        Arc::clone(&capture_repository),
    )?);
    let garbage_collection_store = Arc::new(
        PostgresStore::connect_garbage_collection_with_blob_repository(
            live_postgres_configuration(database.garbage_collection_url.clone())?,
            Arc::clone(&capture_repository),
        )?,
    );
    assert!(
        PostgresStore::connect_with_blob_repository(
            live_postgres_configuration(database.backup_url.clone())?,
            Arc::clone(&capture_repository),
        )
        .is_err()
    );
    assert!(
        PostgresStore::connect_backup_with_blob_repository(
            live_postgres_configuration(database.garbage_collection_url.clone())?,
            Arc::clone(&capture_repository),
        )
        .is_err()
    );
    assert!(
        PostgresStore::connect_garbage_collection_with_blob_repository(
            live_postgres_configuration(database.backup_url.clone())?,
            capture_repository,
        )
        .is_err()
    );
    let mut owner = postgres::Client::connect(&database.owner_url, NoTls)?;
    owner.batch_execute(&format!(
        "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM {};",
        database.backup_role
    ))?;
    let revoked_backup_callback = AtomicBool::new(false);
    let revoked_backup = capture_store.capture_backup_inventory(
        tenants,
        2,
        backup_storage.as_ref(),
        |_| -> Result<PostgresDatabaseBackupArtifact, ()> {
            revoked_backup_callback.store(true, Ordering::Release);
            Err(())
        },
    );
    assert_eq!(
        revoked_backup.err().map(|error| error.code()),
        Some(StoreErrorCode::Unavailable)
    );
    assert!(!revoked_backup_callback.load(Ordering::Acquire));
    owner.batch_execute(&format!(
        "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {};",
        database.backup_role
    ))?;
    let omitted_callback = AtomicBool::new(false);
    if tenants.len() > 1 {
        let omitted_tenants = tenants
            .get(..tenants.len().saturating_sub(1))
            .ok_or("missing omitted tenant fixture")?;
        let omitted = capture_store.capture_backup_inventory(
            omitted_tenants,
            2,
            backup_storage.as_ref(),
            |_| {
                omitted_callback.store(true, Ordering::Release);
                Err(())
            },
        );
        assert_eq!(
            omitted.err().map(|error| error.code()),
            Some(StoreErrorCode::InvalidContext)
        );
        assert!(!omitted_callback.load(Ordering::Acquire));
    }
    let runtime_callback = AtomicBool::new(false);
    let unauthorized =
        source_store.capture_backup_inventory(tenants, 2, backup_storage.as_ref(), |_| {
            runtime_callback.store(true, Ordering::Release);
            Err(())
        });
    assert_eq!(
        unauthorized.err().map(|error| error.code()),
        Some(StoreErrorCode::Unavailable)
    );
    assert!(!runtime_callback.load(Ordering::Acquire));

    let orphan_bytes = b"wp18-backup-gc-exclusion-orphan".to_vec();
    let reference_fixture: BlobRef = protocol_fixture("BlobRef")?;
    let orphan_blob = BlobRecord::new(
        BlobRef {
            digest: content_digest(&orphan_bytes)?,
            size_bytes: u64::try_from(orphan_bytes.len())?,
            media_type: reference_fixture.media_type,
        },
        orphan_bytes,
    )?;
    source_objects
        .repository
        .put(context.tenant_id(), &orphan_blob)?;
    let gc_candidate = RepositoryGarbageCollectionCandidate {
        tenant_id: context.tenant_id().clone(),
        digest: orphan_blob.reference.digest.clone(),
    };
    owner.batch_execute(&format!(
        "REVOKE EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() FROM {};",
        database.garbage_collection_role
    ))?;
    assert_eq!(
        garbage_collection_store
            .garbage_collect_blob_candidates(
                std::slice::from_ref(&gc_candidate),
                GarbageCollectionPolicy {
                    retention_satisfied: true,
                    legal_hold: false,
                    backup_complete: true,
                },
                true,
                1,
            )
            .err()
            .map(|error| error.code()),
        Some(StoreErrorCode::Unavailable)
    );
    owner.batch_execute(&format!(
        "GRANT EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() TO {};",
        database.garbage_collection_role
    ))?;
    let gc_handle = Mutex::new(None);

    let inventory = capture_store.capture_backup_inventory(
        tenants,
        2,
        backup_storage.as_ref(),
        |snapshot| -> Result<PostgresDatabaseBackupArtifact, Box<dyn Error>> {
            let gc_store = Arc::clone(&garbage_collection_store);
            let candidate = gc_candidate.clone();
            let handle = std::thread::spawn(move || {
                gc_store
                    .garbage_collect_blob_candidates(
                        &[candidate],
                        GarbageCollectionPolicy {
                            retention_satisfied: true,
                            legal_hold: false,
                            backup_complete: true,
                        },
                        false,
                        1,
                    )
                    .map(|report| report.deleted)
                    .map_err(|error| error.code())
            });
            std::thread::sleep(Duration::from_millis(100));
            if handle.is_finished() {
                return Err("shared GC escaped the active backup exclusion lock".into());
            }
            *gc_handle
                .lock()
                .map_err(|_error| "backup GC handle mutex was poisoned")? = Some(handle);

            let mut write = source_store.begin_write(
                context.clone(),
                snapshot.repository_revision,
                CancellationToken::default(),
            )?;
            write.stage_snapshot(concurrent_snapshot)?;
            let concurrent = write.commit(None)?;
            if concurrent.revision.0 != snapshot.repository_revision.0.saturating_add(1)
                || concurrent.replayed
            {
                return Err("concurrent snapshot commit did not advance exactly once".into());
            }

            let dump = Command::new("docker")
                .args([
                    "exec",
                    &container,
                    "pg_dump",
                    "--format=custom",
                    "--no-owner",
                    "--no-acl",
                    "--snapshot",
                    &snapshot.exported_snapshot,
                    "--username",
                    &migrator_user,
                    "--dbname",
                    &database.database,
                    "--file",
                    &dump_path,
                ])
                .status()?;
            if !dump.success() {
                return Err("database-native backup failed".into());
            }
            let list = Command::new("docker")
                .args(["exec", &container, "pg_restore", "--list", &dump_path])
                .status()?;
            if !list.success() {
                return Err("database-native archive list verification failed".into());
            }
            let (archive_size_bytes, archive_checksum) =
                container_archive_evidence(&container, &dump_path)?;
            eprintln!("wp18: database-native archive captured from exported snapshot");
            Ok(PostgresDatabaseBackupArtifact {
                archive_format: "pg_dump-custom-v1".to_owned(),
                archive_size_bytes,
                archive_checksum,
                source_database_identity: snapshot.source_database_identity.clone(),
                exported_snapshot_checksum: snapshot.exported_snapshot_checksum.clone(),
                transaction_snapshot_checksum: snapshot.transaction_snapshot_checksum.clone(),
            })
        },
    )?;
    eprintln!("wp18: database and exact object backup capture committed");
    let handle = gc_handle
        .lock()
        .map_err(|_error| "backup GC handle mutex was poisoned")?
        .take()
        .ok_or("backup GC worker handle was not recorded")?;
    let gc_result = handle
        .join()
        .map_err(|_panic| "backup GC worker panicked")?;
    assert_eq!(gc_result, Ok(1));
    eprintln!("wp18: GC waited for backup exclusion and completed afterward");
    assert!(
        source_objects
            .repository
            .get(context.tenant_id(), &orphan_blob.reference)?
            .is_none()
    );
    assert_eq!(
        source_store.revision()?.0,
        inventory.repository_revision.0.saturating_add(1)
    );
    let signed = sign_postgres_backup_inventory(
        inventory,
        signing_provider,
        signing_key,
        signing_tenant,
        "backup-operator",
        2,
    )?;
    verify_postgres_backup_inventory(&signed, signing_provider, signing_tenant, 3)?;
    eprintln!("wp18: signed backup inventory verified");

    let archive_directory = tempfile::tempdir()?;
    let local_archive = archive_directory.path().join("database.dump");
    let copy = Command::new("docker")
        .args([
            "cp",
            &format!("{container}:{dump_path}"),
            local_archive.to_str().ok_or("invalid local archive path")?,
        ])
        .status()?;
    if !copy.success() {
        return Err("database-native archive copy failed".into());
    }
    let mut verified_archive =
        verify_postgres_database_backup(&signed.inventory.database, File::open(&local_archive)?)?;
    let tampered_archive = archive_directory.path().join("database-tampered.dump");
    std::fs::copy(&local_archive, &tampered_archive)?;
    OpenOptions::new()
        .append(true)
        .open(&tampered_archive)?
        .write_all(b"tamper")?;
    assert!(
        verify_postgres_database_backup(
            &signed.inventory.database,
            File::open(&tampered_archive)?,
        )
        .is_err()
    );
    let cleanup_source_archive = Command::new("docker")
        .args(["exec", &container, "rm", "-f", &dump_path])
        .status()?;
    if !cleanup_source_archive.success() {
        return Err("database-native source archive cleanup failed".into());
    }
    eprintln!("wp18: opaque database archive capability verified");

    let mut admin = postgres::Client::connect(&database.admin_url, NoTls)?;
    admin.batch_execute(&format!("CREATE DATABASE {target_name} TEMPLATE template0"))?;
    let target_guard = ExtraDatabase {
        admin_url: database.admin_url.clone(),
        database: target_name.clone(),
    };
    let mut restore = Command::new("docker")
        .args([
            "exec",
            "-i",
            &container,
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "--no-acl",
            "--username",
            &migrator_user,
            "--dbname",
            &target_name,
        ])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut restore_input = restore
        .stdin
        .take()
        .ok_or("database-native restore stdin was unavailable")?;
    std::io::copy(&mut verified_archive, &mut restore_input)?;
    drop(restore_input);
    if !restore.wait()?.success() {
        return Err("database-native restore failed".into());
    }
    eprintln!("wp18: exact verified archive streamed into fresh database");
    let (owner_prefix, _source) = database
        .owner_url
        .rsplit_once('/')
        .ok_or("invalid owner URL")?;
    let target_owner_url = format!("{owner_prefix}/{target_name}");
    database.grant_runtime_at(&target_owner_url)?;
    database.grant_backup_at(&target_owner_url)?;
    database.grant_garbage_collection_at(&target_owner_url)?;
    let (backup_prefix, _source) = database
        .backup_url
        .rsplit_once('/')
        .ok_or("invalid backup URL")?;
    let target_backup_url = format!("{backup_prefix}/{target_name}");

    for entry in &signed.inventory.objects.entries {
        source_objects.storage.delete(&entry.storage_key)?;
        assert!(source_objects.storage.get(&entry.storage_key).is_err());
    }
    let destination_storage = Arc::new(S3CompatibleObjectStorage::new(
        &s3_endpoint,
        "us-east-1",
        &s3_bucket,
        &restored_prefix,
        &s3_admin_access_key,
        &s3_admin_secret_key,
        None,
        true,
    )?);
    let destination_runtime_storage = Arc::new(S3CompatibleObjectStorage::new(
        &s3_endpoint,
        "us-east-1",
        &s3_bucket,
        &restored_prefix,
        &s3_runtime_access_key,
        &s3_runtime_secret_key,
        None,
        true,
    )?);
    let object_receipt = restore_object_backup_inventory(
        backup_storage.as_ref(),
        destination_storage.as_ref(),
        &signed.inventory.objects,
    )?;
    assert_eq!(
        object_receipt.object_count(),
        u64::try_from(signed.inventory.objects.entries.len())?
    );
    eprintln!("wp18: signed object backup restored into fresh namespace");
    let destination_repository: Arc<dyn RepositoryBlobStore> =
        Arc::new(ObjectRepositoryBlobStore::new(
            Arc::clone(&source_objects.provider),
            Arc::clone(&destination_runtime_storage),
            source_objects.key_ref.clone(),
            1,
            [0x31; 32],
        ));
    let restored = PostgresStore::connect_backup_with_blob_repository(
        live_postgres_configuration(target_backup_url.clone())?,
        Arc::clone(&destination_repository),
    )?;
    let restore_receipt = restored.verify_restored_backup_trusted(
        &signed,
        &verified_archive,
        object_receipt.clone(),
        signing_provider,
        3,
        |identity| {
            identity.signing_tenant == signing_tenant
                && identity.signer == "backup-operator"
                && identity.signing_key == signed.signing_key
        },
    )?;
    eprintln!("wp18: restored database and object roots activated under current trust");
    let receipt_json = serde_json::to_string(&restore_receipt)?;
    assert!(!receipt_json.contains(&database.database));

    let unavailable_provider = Arc::new(MemoryKeyProvider::default());
    let unavailable_repository: Arc<dyn RepositoryBlobStore> =
        Arc::new(ObjectRepositoryBlobStore::new(
            unavailable_provider,
            Arc::clone(&destination_runtime_storage),
            source_objects.key_ref.clone(),
            1,
            [0x31; 32],
        ));
    let unavailable_keys = PostgresStore::connect_backup_with_blob_repository(
        live_postgres_configuration(target_backup_url.clone())?,
        unavailable_repository,
    )?;
    assert!(
        unavailable_keys
            .verify_restored_backup_trusted(
                &signed,
                &verified_archive,
                object_receipt.clone(),
                signing_provider,
                3,
                |_identity| true,
            )
            .is_err()
    );
    drop(unavailable_keys);

    let mut target_owner = postgres::Client::connect(&target_owner_url, NoTls)?;
    let extra_tenant = "01890f47-8e7d-7b42-a1d5-3c4d5e6f7897";
    target_owner.execute(
        "INSERT INTO cigar_shared_wakeups (tenant_id, revision, topic)
         VALUES ($1, 0, 'backup-extra-tenant')",
        &[&extra_tenant],
    )?;
    assert!(
        restored
            .verify_restored_backup_trusted(
                &signed,
                &verified_archive,
                object_receipt.clone(),
                signing_provider,
                3,
                |_identity| true,
            )
            .is_err()
    );
    target_owner.execute(
        "DELETE FROM cigar_shared_wakeups WHERE tenant_id = $1",
        &[&extra_tenant],
    )?;

    let projection = target_owner.query_one(
        "SELECT tenant_id, version_id, record, record_checksum
         FROM cigar_atom_projection ORDER BY tenant_id, version_id LIMIT 1",
        &[],
    )?;
    let projection_tenant: String = projection.get(0);
    let projection_version: String = projection.get(1);
    let projection_record: Vec<u8> = projection.get(2);
    let projection_checksum: String = projection.get(3);
    let mut corrupted_projection = projection_record.clone();
    *corrupted_projection
        .get_mut(0)
        .ok_or("missing projection corruption byte")? ^= 0x01;
    let corrupted_checksum = content_digest(&corrupted_projection)?.as_str().to_owned();
    target_owner.execute(
        "UPDATE cigar_atom_projection SET record = $3, record_checksum = $4
         WHERE tenant_id = $1 AND version_id = $2",
        &[
            &projection_tenant,
            &projection_version,
            &corrupted_projection,
            &corrupted_checksum,
        ],
    )?;
    assert!(
        restored
            .verify_restored_backup_trusted(
                &signed,
                &verified_archive,
                object_receipt.clone(),
                signing_provider,
                3,
                |_identity| true,
            )
            .is_err()
    );
    target_owner.execute(
        "UPDATE cigar_atom_projection SET record = $3, record_checksum = $4
         WHERE tenant_id = $1 AND version_id = $2",
        &[
            &projection_tenant,
            &projection_version,
            &projection_record,
            &projection_checksum,
        ],
    )?;

    let history = target_owner.query_one(
        "SELECT tenant_id, revision, state, checksum FROM cigar_tenant_states
         ORDER BY tenant_id, revision LIMIT 1",
        &[],
    )?;
    let history_tenant: String = history.get(0);
    let history_revision: i64 = history.get(1);
    let history_state: Vec<u8> = history.get(2);
    let history_checksum: String = history.get(3);
    target_owner.execute(
        "DELETE FROM cigar_tenant_states WHERE tenant_id = $1 AND revision = $2",
        &[&history_tenant, &history_revision],
    )?;
    assert!(
        restored
            .verify_restored_backup_trusted(
                &signed,
                &verified_archive,
                object_receipt.clone(),
                signing_provider,
                3,
                |_identity| true,
            )
            .is_err()
    );
    target_owner.execute(
        "INSERT INTO cigar_tenant_states (tenant_id, revision, state, checksum)
         VALUES ($1, $2, $3, $4)",
        &[
            &history_tenant,
            &history_revision,
            &history_state,
            &history_checksum,
        ],
    )?;
    drop(restored);
    drop(target_owner);
    drop(target_guard);
    for key in destination_storage.list_namespace(10_000)? {
        destination_storage.delete(&key)?;
    }
    assert!(destination_storage.list_namespace(1)?.is_empty());
    for key in backup_storage.list_namespace(10_000)? {
        backup_storage.delete(&key)?;
    }
    assert!(backup_storage.list_namespace(1)?.is_empty());
    Ok(signed)
}

#[test]
fn postgres_shared_conformance_rls_wakeups_and_64_client_idempotency() -> Result<(), Box<dyn Error>>
{
    let admin_url = match std::env::var("CIGAR_TEST_POSTGRES_ADMIN_URL") {
        Ok(value) => value,
        Err(_error) if std::env::var_os("CIGAR_REQUIRE_LIVE_SHARED_TESTS").is_none() => {
            return Ok(());
        }
        Err(_error) => {
            return Err("required live PostgreSQL qualification was not configured".into());
        }
    };
    let database = TestDatabase::create(admin_url)?;
    eprintln!("wp18: database created");
    let owner_configuration = live_postgres_configuration(database.owner_url.clone())?;
    let migration = PostgresStore::migrate(&owner_configuration)?;
    eprintln!("wp18: migrations verified");
    assert_eq!(migration.latest_sequence, 4);
    assert_eq!(migration.checksums_verified, 4);
    database.grant_runtime()?;
    database.grant_backup()?;
    database.grant_garbage_collection()?;
    eprintln!("wp18: runtime grants installed");

    let fixture = repository_fixture()?;
    let mut runtime_configuration = live_postgres_configuration(database.runtime_url.clone())?;
    runtime_configuration.minimum_connections = 2;
    runtime_configuration.maximum_connections = 64;
    let object_fixture = object_repository(fixture.context.tenant_id())?;
    let blob_repository: Arc<dyn RepositoryBlobStore> = object_fixture.repository.clone();
    let postgres = Arc::new(PostgresStore::connect_with_blob_repository(
        runtime_configuration,
        Arc::clone(&blob_repository),
    )?);
    eprintln!("wp18: runtime store connected");
    let mut authority_owner = postgres::Client::connect(&database.owner_url, NoTls)?;
    authority_owner.batch_execute(&format!(
        "GRANT EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() TO {};",
        database.role
    ))?;
    assert_eq!(
        postgres.revision().err().map(|error| error.code()),
        Some(StoreErrorCode::Unavailable)
    );
    authority_owner.batch_execute(&format!(
        "REVOKE EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() FROM {};",
        database.role
    ))?;
    authority_owner.batch_execute(&format!(
        "GRANT {} TO {};
         GRANT {} TO {};",
        database.backup_role, database.membership_role, database.membership_role, database.role
    ))?;
    assert_eq!(
        postgres.revision().err().map(|error| error.code()),
        Some(StoreErrorCode::Unavailable)
    );
    authority_owner.batch_execute(&format!(
        "REVOKE {} FROM {};
         REVOKE {} FROM {};",
        database.membership_role, database.role, database.backup_role, database.membership_role
    ))?;
    let postgres_report = run_repository_conformance(postgres.as_ref(), &fixture)?;
    eprintln!("wp18: postgres conformance passed");

    let local_directory = tempfile::tempdir()?;
    let sqlite = sqlite_repository(fixture.context.tenant_id(), &local_directory)?;
    let sqlite_report = run_repository_conformance(&sqlite, &fixture)?;
    eprintln!("wp18: sqlite differential passed");
    assert_eq!(postgres_report, sqlite_report);

    let storm_revision = postgres.revision()?;
    let storm_barrier = Arc::new(Barrier::new(64));
    let mut storm_snapshots = Vec::new();
    for writer in 0..64_u64 {
        let mut snapshot = fixture.snapshot.clone();
        snapshot.snapshot_id = RecordId::new(format!("01890f47-8e7d-7b42-a1d3-{writer:012x}"))?;
        storm_snapshots.push(snapshot);
    }
    let storm_results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for snapshot in storm_snapshots {
            let store = Arc::clone(&postgres);
            let barrier = Arc::clone(&storm_barrier);
            let context = fixture.context.clone();
            handles.push(scope.spawn(move || {
                let mut write =
                    store.begin_write(context, storm_revision, CancellationToken::default())?;
                write.stage_snapshot(snapshot)?;
                barrier.wait();
                write.commit(None)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    let mut storm_commits = 0_u32;
    let mut storm_conflicts = 0_u32;
    for result in storm_results {
        match result.map_err(|_panic| "serialization-storm writer panicked")? {
            Ok(receipt) => {
                assert_eq!(receipt.revision, StoreRevision(storm_revision.0 + 1));
                assert!(!receipt.replayed);
                storm_commits += 1;
            }
            Err(error) if error.code() == StoreErrorCode::RevisionConflict => {
                storm_conflicts += 1;
            }
            Err(_error) => return Err("serialization storm returned an unexpected error".into()),
        }
    }
    assert_eq!(storm_commits, 1);
    assert_eq!(storm_conflicts, 63);
    assert_eq!(postgres.revision()?, StoreRevision(storm_revision.0 + 1));
    eprintln!("wp18: 64-writer serialization storm preserved one atomic winner");

    for (index, failpoint, expected_code) in [
        (
            0_u8,
            ObjectFailpoint::PartialUpload,
            StoreErrorCode::InjectedAbort,
        ),
        (
            1_u8,
            ObjectFailpoint::MissingObject,
            StoreErrorCode::NotFound,
        ),
        (
            2_u8,
            ObjectFailpoint::CredentialExpiry,
            StoreErrorCode::Unavailable,
        ),
    ] {
        let bytes = format!("wp18-object-publication-fault-{index}").into_bytes();
        let reference_fixture: BlobRef = protocol_fixture("BlobRef")?;
        let failed_blob = BlobRecord::new(
            BlobRef {
                digest: content_digest(&bytes)?,
                size_bytes: u64::try_from(bytes.len())?,
                media_type: reference_fixture.media_type,
            },
            bytes,
        )?;
        let before_failure = postgres.revision()?;
        object_fixture.storage.inject(failpoint)?;
        let mut write = postgres.begin_write(
            fixture.context.clone(),
            before_failure,
            CancellationToken::default(),
        )?;
        write.put_blob(failed_blob.clone())?;
        assert_eq!(
            write.commit(None).map_err(|error| error.code()),
            Err(expected_code)
        );
        assert_eq!(postgres.revision()?, before_failure);
        let read = postgres.begin_read(
            fixture.context.clone(),
            cigar_store::SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert!(read.get_blob(&failed_blob.reference.digest)?.is_none());
        drop(read);
        postgres.reconcile_blob_roots(std::slice::from_ref(fixture.context.tenant_id()))?;
    }
    eprintln!("wp18: object publication faults left no visible metadata roots");

    let mut runtime = postgres::Client::connect(&database.runtime_url, NoTls)?;
    let mut transaction = runtime.transaction()?;
    transaction.query_one(
        "SELECT set_config('cigar.tenant_id', $1, true)",
        &[&fixture.other_tenant.tenant_id().as_str()],
    )?;
    let hidden: i64 = transaction
        .query_one(
            "SELECT count(*) FROM cigar_tenant_states WHERE tenant_id = $1",
            &[&fixture.context.tenant_id().as_str()],
        )?
        .get(0);
    assert_eq!(hidden, 0);
    transaction.rollback()?;
    eprintln!("wp18: direct RLS isolation passed");

    let claims = postgres.claim_wakeups(
        fixture.context.tenant_id(),
        "outbox-v1",
        "worker-a",
        1_000,
        30_000,
        10,
    )?;
    eprintln!("wp18: wakeups claimed");
    assert!(!claims.is_empty());
    let first = claims.first().ok_or("missing wakeup claim")?;
    postgres.acknowledge_wakeup("outbox-v1", first)?;
    eprintln!("wp18: wakeup acknowledged");

    let tenant = fixture.context.tenant_id().clone();
    let record_bytes = b"exact-effect-intent".to_vec();
    let response = ServiceResponse::new(201, "application/cbor", b"created".to_vec())?;
    let write = ServiceRecordWrite::new(
        "effects",
        "shared-effect",
        ServiceExpectedVersion::Absent,
        record_bytes,
    )?;
    let batch = ServiceBatch::new(tenant.clone(), vec![write], response)?.with_idempotency(
        ServiceIdempotency::new(
            "effect.prepare",
            IdempotencyKey::new("shared-effect-idempotency")?,
            content_digest(b"same-normalized-request")?,
        )?,
    );
    let barrier = Arc::new(Barrier::new(64));
    let receipts = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _client in 0..64 {
            let store = Arc::clone(&postgres);
            let barrier = Arc::clone(&barrier);
            let batch = batch.clone();
            handles.push(scope.spawn(move || {
                barrier.wait();
                for _attempt in 0..128 {
                    match store.service_commit(batch.clone(), &CancellationToken::default()) {
                        Ok(receipt) => return Ok(receipt),
                        Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {}
                        Err(error) => return Err(error.code()),
                    }
                }
                Err(ServiceErrorCode::Unavailable)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    eprintln!("wp18: 64 clients joined");
    let mut committed_revision = None;
    for receipt in receipts {
        let receipt = receipt
            .map_err(|_panic| "64-client worker panicked")?
            .map_err(|_code| "64-client service commit failed")?;
        if let Some(revision) = committed_revision {
            assert_eq!(receipt.revision, revision);
        } else {
            committed_revision = Some(receipt.revision);
        }
    }
    let page = postgres.service_list(
        &ServiceListQuery::new(ServiceListScope::new(tenant, "effects", None)?, 100, None)?,
        &CancellationToken::default(),
    )?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items.first().map(|record| record.version()), Some(1));

    let mut other_snapshot = fixture.snapshot.clone();
    other_snapshot.snapshot_id = RecordId::new("01890f47-8e7d-7b42-a1d4-3c4d5e6f7896")?;
    let mut other_write = postgres.begin_write(
        fixture.other_tenant.clone(),
        postgres.revision()?,
        CancellationToken::default(),
    )?;
    other_write.stage_snapshot(other_snapshot)?;
    other_write.commit(None)?;

    let mut backup_tenants = vec![
        fixture.context.tenant_id().clone(),
        fixture.other_tenant.tenant_id().clone(),
    ];
    backup_tenants.sort();
    let signing_provider = MemoryKeyProvider::default();
    let signing = signing_provider.create(CreateKeyRequest {
        tenant: fixture.context.tenant_id().as_str().to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let mut concurrent_snapshot = fixture.snapshot.clone();
    concurrent_snapshot.snapshot_id = RecordId::new("01890f47-8e7d-7b42-a1d4-3c4d5e6f7895")?;
    let signed = native_dump_restore_drill(
        &database,
        &object_fixture,
        &postgres,
        &backup_tenants,
        &fixture.context,
        concurrent_snapshot,
        &signing_provider,
        &signing.key_ref,
        fixture.context.tenant_id().as_str(),
    )?;
    assert_eq!(signed.inventory.migration_sequence, 4);
    assert_eq!(signed.inventory.migrations.len(), 4);
    verify_postgres_backup_inventory(
        &signed,
        &signing_provider,
        fixture.context.tenant_id().as_str(),
        3,
    )?;
    verify_postgres_backup_inventory_trusted(&signed, &signing_provider, 3, |identity| {
        identity.signing_tenant == fixture.context.tenant_id().as_str()
            && identity.signer == "backup-operator"
            && identity.signing_key == signing.key_ref
    })?;
    assert!(
        verify_postgres_backup_inventory_trusted(&signed, &signing_provider, 3, |_identity| false,)
            .is_err()
    );
    let mut invalid_signature = signed.clone();
    *invalid_signature
        .signature
        .get_mut(0)
        .ok_or("missing backup signature byte")? ^= 0x01;
    let invalid_trust_called = AtomicBool::new(false);
    assert!(
        verify_postgres_backup_inventory_trusted(
            &invalid_signature,
            &signing_provider,
            3,
            |_identity| {
                invalid_trust_called.store(true, Ordering::Release);
                true
            },
        )
        .is_err()
    );
    assert!(!invalid_trust_called.load(Ordering::Acquire));
    let mut tampered = signed.clone();
    tampered.inventory.repository_revision.0 =
        tampered.inventory.repository_revision.0.saturating_add(1);
    assert!(
        verify_postgres_backup_inventory(
            &tampered,
            &signing_provider,
            fixture.context.tenant_id().as_str(),
            3,
        )
        .is_err()
    );
    let mut object_tampered = signed.clone();
    if let Some(entry) = object_tampered.inventory.objects.entries.first_mut() {
        entry.size_bytes = entry.size_bytes.saturating_add(1);
    }
    assert!(
        verify_postgres_backup_inventory_trusted(
            &object_tampered,
            &signing_provider,
            3,
            |_identity| true,
        )
        .is_err()
    );
    let mut tenant_tampered = signed.clone();
    tenant_tampered.signing_tenant = fixture.other_tenant.tenant_id().as_str().to_owned();
    assert!(
        verify_postgres_backup_inventory_trusted(
            &tenant_tampered,
            &signing_provider,
            3,
            |_identity| true,
        )
        .is_err()
    );

    let mut owner = postgres::Client::connect(&database.owner_url, NoTls)?;
    let adjacent = PostgresStore::connect_with_blob_repository(
        live_postgres_configuration(database.runtime_url.clone())?,
        object_repository(fixture.context.tenant_id())?.repository,
    )?;
    assert!(adjacent.verify_migration_level().is_ok());

    let rolling_old = ServiceBatch::new(
        fixture.context.tenant_id().clone(),
        vec![ServiceRecordWrite::new(
            "rolling-compatibility",
            "old-instance",
            ServiceExpectedVersion::Absent,
            b"old-instance-write".to_vec(),
        )?],
        ServiceResponse::new(200, "application/cbor", b"old-commit".to_vec())?,
    )?;
    postgres.service_commit(rolling_old, &CancellationToken::default())?;
    let old_locator = ServiceRecordLocator::new(
        fixture.context.tenant_id().clone(),
        "rolling-compatibility",
        "old-instance",
    )?;
    assert_eq!(
        adjacent
            .service_get(
                &old_locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )?
            .as_ref()
            .map(|record| record.bytes()),
        Some(b"old-instance-write".as_slice())
    );

    let rolling_new = ServiceBatch::new(
        fixture.context.tenant_id().clone(),
        vec![ServiceRecordWrite::new(
            "rolling-compatibility",
            "new-instance",
            ServiceExpectedVersion::Absent,
            b"new-instance-write".to_vec(),
        )?],
        ServiceResponse::new(200, "application/cbor", b"new-commit".to_vec())?,
    )?;
    adjacent.service_commit(rolling_new, &CancellationToken::default())?;
    let new_locator = ServiceRecordLocator::new(
        fixture.context.tenant_id().clone(),
        "rolling-compatibility",
        "new-instance",
    )?;
    assert_eq!(
        postgres
            .service_get(
                &new_locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )?
            .as_ref()
            .map(|record| record.bytes()),
        Some(b"new-instance-write".as_slice())
    );
    drop(adjacent);
    owner.execute(
        "INSERT INTO schema_migrations
           (sequence, name, checksum, minimum_application_major,
            maximum_application_major, online)
         VALUES (5, 'unknown_self_declared_online', $1, 1, 2, true)",
        &[&content_digest(b"unknown-self-declared-online")?.as_str()],
    )?;
    assert_eq!(
        PostgresStore::connect(live_postgres_configuration(database.runtime_url.clone())?)
            .err()
            .map(|error| error.code()),
        Some(StoreErrorCode::Unavailable)
    );

    drop(postgres);
    drop(runtime);
    Ok(())
}
