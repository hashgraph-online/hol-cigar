//! Live private-CA PostgreSQL migration, interruption, and mixed-version qualification.

#![cfg(all(feature = "migration-fault-injection", target_os = "macos"))]

use cigar_protocol::{RecordId, SourceSnapshot};
use cigar_store::{
    AccessContext, CancellationToken, PostgresConfiguration, PostgresMigrationFailpoint,
    PostgresStore, ReadTransaction, Repository, StoreError, StoreErrorCode, StoreRevision,
    WriteTransaction,
};
use postgres::config::SslMode;
use postgres::{Client, IsolationLevel, NoTls};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;

const ADMIN_URL: &str = "CIGAR_TEST_POSTGRES_TLS_ADMIN_URL";
const IP_ADMIN_URL: &str = "CIGAR_TEST_POSTGRES_TLS_IP_ADMIN_URL";
const SERVER_NAME: &str = "CIGAR_TEST_POSTGRES_TLS_SERVER_NAME";
const CA_PATH: &str = "CIGAR_TEST_POSTGRES_TLS_CA_PATH";
const WRONG_CA_PATH: &str = "CIGAR_TEST_POSTGRES_TLS_WRONG_CA_PATH";
const REQUIRE_LIVE: &str = "CIGAR_REQUIRE_LIVE_POSTGRES_MIGRATIONS";
const CHILD_URL: &str = "CIGAR_POSTGRES_MIGRATION_ABORT_URL";
const CHILD_BOUNDARY: &str = "CIGAR_POSTGRES_MIGRATION_ABORT_BOUNDARY";
const MAX_TEST_CA_BYTES: usize = 2 * 1024 * 1024;
const MACOS_SIGABRT: i32 = 6;

const MIGRATIONS: [(&str, &str); 4] = [
    (
        "shared_metadata",
        include_str!("../migrations/postgres/0001_shared_metadata.sql"),
    ),
    (
        "object_outbox",
        include_str!("../migrations/postgres/0002_object_outbox.sql"),
    ),
    (
        "atom_projection",
        include_str!("../migrations/postgres/0003_atom_projection.sql"),
    ),
    (
        "gc_revision_guard",
        include_str!("../migrations/postgres/0004_gc_revision_guard.sql"),
    ),
];

static NEXT_CLUSTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct LiveEnvironment {
    admin_url: String,
    ip_admin_url: String,
    server_name: String,
    certificate_authority: Vec<u8>,
    wrong_certificate_authority: Vec<u8>,
}

impl LiveEnvironment {
    fn load() -> Result<Option<Self>, Box<dyn Error>> {
        let admin_url = match std::env::var(ADMIN_URL) {
            Ok(value) => value,
            Err(_error) if std::env::var_os(REQUIRE_LIVE).is_none() => return Ok(None),
            Err(_error) => return Err("required live PostgreSQL admin URL is missing".into()),
        };
        let ip_admin_url = std::env::var(IP_ADMIN_URL)?;
        let server_name = std::env::var(SERVER_NAME)?;
        let certificate_authority = std::fs::read(std::env::var(CA_PATH)?)?;
        let wrong_certificate_authority = std::fs::read(std::env::var(WRONG_CA_PATH)?)?;
        if certificate_authority.is_empty()
            || certificate_authority.len() > MAX_TEST_CA_BYTES
            || wrong_certificate_authority.is_empty()
            || wrong_certificate_authority.len() > MAX_TEST_CA_BYTES
        {
            return Err("live PostgreSQL CA input exceeded its test bound".into());
        }
        Ok(Some(Self {
            admin_url,
            ip_admin_url,
            server_name,
            certificate_authority,
            wrong_certificate_authority,
        }))
    }

    fn store_configuration(&self, url: String) -> Result<PostgresConfiguration, StoreError> {
        let mut configuration = PostgresConfiguration::new_with_certificate_authority(
            url,
            self.server_name.clone(),
            &self.certificate_authority,
        )?;
        configuration.minimum_connections = 1;
        configuration.maximum_connections = 4;
        Ok(configuration)
    }
}

#[derive(Clone)]
struct DatabaseUrls {
    admin: String,
    migrator: String,
    runtime: String,
}

struct LiveCluster {
    environment: LiveEnvironment,
    suffix: String,
    migrator_role: String,
    migrator_password: String,
    runtime_role: String,
    runtime_password: String,
    databases: Vec<String>,
}

impl LiveCluster {
    fn create(environment: LiveEnvironment) -> Result<Self, Box<dyn Error>> {
        let ordinal = NEXT_CLUSTER.fetch_add(1, Ordering::AcqRel);
        let suffix = format!("{}_{}", std::process::id(), ordinal);
        let migrator_role = format!("cigar_migrator_{suffix}");
        let runtime_role = format!("cigar_runtime_{suffix}");
        let migrator_password = format!("migrator_{suffix}_7f3a");
        let runtime_password = format!("runtime_{suffix}_9c2d");
        let mut admin = connect_tls(&environment.admin_url, &environment.certificate_authority)?;
        admin.batch_execute(&format!(
            "CREATE ROLE {migrator_role} LOGIN PASSWORD '{migrator_password}'
                 NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
             CREATE ROLE {runtime_role} LOGIN PASSWORD '{runtime_password}'
                 NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;"
        ))?;
        Ok(Self {
            environment,
            suffix,
            migrator_role,
            migrator_password,
            runtime_role,
            runtime_password,
            databases: Vec::new(),
        })
    }

    fn create_database(&mut self, label: &str) -> Result<DatabaseUrls, Box<dyn Error>> {
        let database = format!("cigar_{}_{}_{}", label, self.suffix, self.databases.len());
        let mut admin = connect_tls(
            &self.environment.admin_url,
            &self.environment.certificate_authority,
        )?;
        admin.batch_execute(&format!(
            "CREATE DATABASE {database} OWNER {}",
            self.migrator_role
        ))?;
        self.databases.push(database.clone());
        admin.batch_execute(&format!(
            "REVOKE CREATE, TEMPORARY ON DATABASE {database} FROM PUBLIC"
        ))?;
        let migrator_url = rewrite_url(
            &self.environment.admin_url,
            &database,
            Some(&self.migrator_role),
            Some(&self.migrator_password),
        )?;
        connect_tls(&migrator_url, &self.environment.certificate_authority)?
            .batch_execute("GRANT CREATE ON SCHEMA public TO PUBLIC")?;
        Ok(DatabaseUrls {
            admin: rewrite_url(&self.environment.admin_url, &database, None, None)?,
            migrator: migrator_url,
            runtime: rewrite_url(
                &self.environment.admin_url,
                &database,
                Some(&self.runtime_role),
                Some(&self.runtime_password),
            )?,
        })
    }

    fn grant_runtime(&self, urls: &DatabaseUrls, prefix: u32) -> Result<(), Box<dyn Error>> {
        // Built-in catalog functions are owned by the bootstrap superuser, so the database
        // owner cannot revoke their default PUBLIC privilege. Use the disposable cluster's
        // administrator explicitly; otherwise the runtime-role authority check correctly
        // rejects a principal that can inspect cluster control data.
        connect_tls(&urls.admin, &self.environment.certificate_authority)?
            .batch_execute("REVOKE ALL ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC;")?;
        let mut migrator = connect_tls(&urls.migrator, &self.environment.certificate_authority)?;
        migrator.batch_execute(&format!(
            "REVOKE ALL ON SCHEMA public FROM PUBLIC;
             REVOKE CREATE ON SCHEMA public FROM {runtime};
             GRANT USAGE ON SCHEMA public TO {runtime};
             GRANT SELECT ON schema_migrations TO {runtime};
             GRANT SELECT, UPDATE ON cigar_repository_revision TO {runtime};
             GRANT SELECT, INSERT ON cigar_repository_revisions TO {runtime};
             GRANT SELECT, INSERT, UPDATE, DELETE ON cigar_tenant_states,
                 cigar_shared_wakeups TO {runtime};",
            runtime = self.runtime_role,
        ))?;
        if prefix >= 2 {
            migrator.batch_execute(&format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON cigar_object_commits,
                     cigar_worker_claims TO {runtime};",
                runtime = self.runtime_role,
            ))?;
        }
        if prefix >= 3 {
            migrator.batch_execute(&format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON cigar_atom_projection TO {runtime};",
                runtime = self.runtime_role,
            ))?;
        }
        if prefix >= 4 {
            migrator.batch_execute(
                "REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision() FROM PUBLIC;",
            )?;
        }
        Ok(())
    }
}

impl Drop for LiveCluster {
    fn drop(&mut self) {
        let Ok(mut admin) = connect_tls(
            &self.environment.admin_url,
            &self.environment.certificate_authority,
        ) else {
            return;
        };
        for database in self.databases.iter().rev() {
            let _terminated = admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[database],
            );
            let _dropped = admin.batch_execute(&format!("DROP DATABASE IF EXISTS {database}"));
        }
        let _dropped_roles = admin.batch_execute(&format!(
            "DROP ROLE IF EXISTS {};
             DROP ROLE IF EXISTS {};",
            self.runtime_role, self.migrator_role
        ));
    }
}

fn rewrite_url(
    base: &str,
    database: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let mut url = Url::parse(base)?;
    url.set_path(&format!("/{database}"));
    if let Some(username) = username {
        url.set_username(username)
            .map_err(|()| "PostgreSQL test username was invalid")?;
    }
    if let Some(password) = password {
        url.set_password(Some(password))
            .map_err(|()| "PostgreSQL test password was invalid")?;
    }
    Ok(url.into())
}

fn connect_tls(url: &str, certificate_authority: &[u8]) -> Result<Client, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    let certificates =
        CertificateDer::pem_slice_iter(certificate_authority).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err("PostgreSQL test CA contained no certificates".into());
    }
    for certificate in certificates {
        roots.add(certificate)?;
    }
    let tls = ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut configuration = postgres::Config::from_str(url)?;
    configuration.ssl_mode(SslMode::Require);
    Ok(configuration.connect(MakeRustlsConnect::new(tls))?)
}

fn checksum(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("1220{suffix}")
}

fn install_prefix(client: &mut Client, prefix: u32) -> Result<(), Box<dyn Error>> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS public.schema_migrations (
            sequence integer PRIMARY KEY,
            name text NOT NULL UNIQUE,
            checksum text NOT NULL,
            minimum_application_major integer NOT NULL,
            maximum_application_major integer NOT NULL,
            online boolean NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
         )",
    )?;
    for (index, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let sequence = u32::try_from(index)?.saturating_add(1);
        if sequence > prefix {
            break;
        }
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()?;
        transaction.batch_execute(sql)?;
        let sequence_i32 = i32::try_from(sequence)?;
        transaction.execute(
            "INSERT INTO public.schema_migrations
               (sequence, name, checksum, minimum_application_major,
                maximum_application_major, online)
             VALUES ($1, $2, $3, 1, 2, true)",
            &[&sequence_i32, name, &checksum(sql.as_bytes())],
        )?;
        transaction.commit()?;
    }
    Ok(())
}

fn relation_exists(client: &mut Client, name: &str) -> Result<bool, Box<dyn Error>> {
    Ok(client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("public.{name}")],
        )?
        .get(0))
}

fn assert_prefix(client: &mut Client, prefix: u32) -> Result<(), Box<dyn Error>> {
    let public_can_create: bool = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                FROM pg_namespace AS namespace,
                     LATERAL aclexplode(COALESCE(
                         namespace.nspacl,
                         acldefault('n', namespace.nspowner)
                     )) AS privilege
                WHERE namespace.nspname = 'public'
                  AND privilege.grantee = 0
                  AND privilege.privilege_type = 'CREATE'
             )",
            &[],
        )?
        .get(0);
    assert!(!public_can_create);
    let rows = client.query(
        "SELECT sequence, name, checksum, minimum_application_major,
                maximum_application_major, online
         FROM public.schema_migrations ORDER BY sequence",
        &[],
    )?;
    assert_eq!(rows.len(), usize::try_from(prefix)?);
    for (index, row) in rows.iter().enumerate() {
        let (name, sql) = MIGRATIONS
            .get(index)
            .ok_or("migration prefix exceeded embedded catalog")?;
        assert_eq!(
            row.get::<_, i32>(0),
            i32::try_from(index)?.saturating_add(1)
        );
        assert_eq!(row.get::<_, String>(1), *name);
        assert_eq!(row.get::<_, String>(2), checksum(sql.as_bytes()));
        assert_eq!(row.get::<_, i32>(3), 1);
        assert_eq!(row.get::<_, i32>(4), 2);
        assert!(row.get::<_, bool>(5));
    }
    assert_eq!(
        relation_exists(client, "cigar_repository_revision")?,
        prefix >= 1
    );
    assert_eq!(
        relation_exists(client, "cigar_object_commits")?,
        prefix >= 2
    );
    assert_eq!(
        relation_exists(client, "cigar_atom_projection")?,
        prefix >= 3
    );
    let function_exists: bool = client
        .query_one(
            "SELECT EXISTS(
                SELECT 1 FROM pg_proc AS procedure
                JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                WHERE namespace.nspname = 'public'
                  AND procedure.proname = 'cigar_gc_lock_repository_revision'
             )",
            &[],
        )?
        .get(0);
    assert_eq!(function_exists, prefix >= 4);
    Ok(())
}

fn root_field(root: &mut Sha256, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    root.update(u64::try_from(bytes.len())?.to_be_bytes());
    root.update(bytes);
    Ok(())
}

fn authoritative_state_root(client: &mut Client) -> Result<String, Box<dyn Error>> {
    let mut root = Sha256::new();
    root.update(b"CIGAR-POSTGRES-AUTHORITATIVE-STATE\0v1\0");
    let revision: i64 = client
        .query_one(
            "SELECT revision FROM cigar_repository_revision WHERE singleton = true",
            &[],
        )?
        .get(0);
    root.update(revision.to_be_bytes());
    for row in client.query(
        "SELECT revision FROM cigar_repository_revisions ORDER BY revision",
        &[],
    )? {
        root.update(row.get::<_, i64>(0).to_be_bytes());
    }
    for row in client.query(
        "SELECT tenant_id, revision, state, checksum
         FROM cigar_tenant_states ORDER BY tenant_id, revision",
        &[],
    )? {
        root_field(&mut root, row.get::<_, String>(0).as_bytes())?;
        root.update(row.get::<_, i64>(1).to_be_bytes());
        root_field(&mut root, &row.get::<_, Vec<u8>>(2))?;
        root_field(&mut root, row.get::<_, String>(3).as_bytes())?;
    }
    Ok(checksum(&root.finalize()))
}

fn seed_retained_state(
    client: &mut Client,
    tenant: &RecordId,
    state: &[u8],
    state_checksum: &str,
) -> Result<(), Box<dyn Error>> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()?;
    transaction.query_one(
        "SELECT set_config('cigar.tenant_id', $1, true)",
        &[&tenant.as_str()],
    )?;
    transaction.execute(
        "INSERT INTO public.cigar_repository_revisions (revision) VALUES (1)",
        &[],
    )?;
    transaction.execute(
        "INSERT INTO public.cigar_tenant_states (tenant_id, revision, state, checksum)
         VALUES ($1, 1, $2, $3)",
        &[&tenant.as_str(), &state, &state_checksum],
    )?;
    transaction.execute(
        "UPDATE public.cigar_repository_revision
         SET revision = 1 WHERE singleton = true",
        &[],
    )?;
    transaction.commit()?;
    Ok(())
}

fn boundary_name(boundary: PostgresMigrationFailpoint) -> String {
    match boundary {
        PostgresMigrationFailpoint::AfterLedgerBootstrap => "after-ledger-bootstrap".to_owned(),
        PostgresMigrationFailpoint::AfterAdvisoryLock => "after-advisory-lock".to_owned(),
        PostgresMigrationFailpoint::AfterMigrationSql(sequence) => {
            format!("after-migration-sql-{sequence}")
        }
        PostgresMigrationFailpoint::AfterLedgerInsert(sequence) => {
            format!("after-ledger-insert-{sequence}")
        }
        PostgresMigrationFailpoint::BeforeCommit => "before-commit".to_owned(),
        PostgresMigrationFailpoint::AfterCommit => "after-commit".to_owned(),
    }
}

fn parse_boundary(value: &str) -> Result<PostgresMigrationFailpoint, Box<dyn Error>> {
    match value {
        "after-ledger-bootstrap" => Ok(PostgresMigrationFailpoint::AfterLedgerBootstrap),
        "after-advisory-lock" => Ok(PostgresMigrationFailpoint::AfterAdvisoryLock),
        "before-commit" => Ok(PostgresMigrationFailpoint::BeforeCommit),
        "after-commit" => Ok(PostgresMigrationFailpoint::AfterCommit),
        _ => {
            if let Some(sequence) = value.strip_prefix("after-migration-sql-") {
                return Ok(PostgresMigrationFailpoint::AfterMigrationSql(
                    sequence.parse()?,
                ));
            }
            if let Some(sequence) = value.strip_prefix("after-ledger-insert-") {
                return Ok(PostgresMigrationFailpoint::AfterLedgerInsert(
                    sequence.parse()?,
                ));
            }
            Err(format!("unknown PostgreSQL migration boundary `{value}`").into())
        }
    }
}

fn required_store_error<T>(
    result: Result<T, StoreError>,
    message: &'static str,
) -> Result<StoreError, Box<dyn Error>> {
    match result {
        Err(error) => Ok(error),
        Ok(_value) => Err(message.into()),
    }
}

fn fixture_snapshot() -> Result<SourceSnapshot, Box<dyn Error>> {
    let fixture = cigar_testkit::deterministic_protocol_fixture("SourceSnapshot")
        .ok_or("missing SourceSnapshot fixture")?;
    Ok(serde_json::from_value(fixture.input)?)
}

#[test]
fn postgres_migration_abort_child() -> Result<(), Box<dyn Error>> {
    let Ok(url) = std::env::var(CHILD_URL) else {
        return Ok(());
    };
    let boundary = parse_boundary(&std::env::var(CHILD_BOUNDARY)?)?;
    let environment = LiveEnvironment::load()?.ok_or("live child environment was absent")?;
    let configuration = environment.store_configuration(url)?;
    let _never_returns = PostgresStore::migrate_with_process_abort(&configuration, boundary);
    Err("PostgreSQL process-abort boundary unexpectedly returned".into())
}

#[test]
fn private_ca_postgres_migrations_recover_and_preserve_mixed_writes() -> Result<(), Box<dyn Error>>
{
    let Some(environment) = LiveEnvironment::load()? else {
        return Ok(());
    };
    qualify_transport(&environment)
        .map_err(|error| format!("PostgreSQL transport qualification failed: {error}"))?;
    let mut cluster = LiveCluster::create(environment.clone())
        .map_err(|error| format!("PostgreSQL role fixture creation failed: {error}"))?;
    qualify_search_path_binding(&mut cluster, &environment)
        .map_err(|error| format!("PostgreSQL search-path qualification failed: {error}"))?;

    let baseline = cluster.create_database("baseline")?;
    let baseline_configuration = environment.store_configuration(baseline.migrator.clone())?;
    let baseline_receipt = PostgresStore::migrate(&baseline_configuration)
        .map_err(|error| format!("PostgreSQL baseline migration failed: {error:?}"))?;
    assert_eq!(baseline_receipt.latest_sequence, 4);
    assert_eq!(baseline_receipt.checksums_verified, 4);
    let empty_root = authoritative_state_root(&mut connect_tls(
        &baseline.admin,
        &environment.certificate_authority,
    )?)?;
    cluster.grant_runtime(&baseline, 4)?;
    let retained_tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7801")?;
    let retained_context = AccessContext::new(retained_tenant.clone(), "migration-retained-root")?;
    let retained_snapshot = fixture_snapshot()?;
    let baseline_store = PostgresStore::connect(
        environment
            .store_configuration(baseline.runtime.clone())
            .map_err(|error| {
                format!("PostgreSQL baseline runtime configuration failed: {error:?}")
            })?,
    )
    .map_err(|error| format!("PostgreSQL baseline runtime connection failed: {error:?}"))?;
    let mut baseline_write = baseline_store
        .begin_write(
            retained_context,
            StoreRevision(0),
            CancellationToken::default(),
        )
        .map_err(|error| format!("PostgreSQL baseline write failed to begin: {error:?}"))?;
    baseline_write.stage_snapshot(retained_snapshot)?;
    assert_eq!(
        baseline_write
            .commit(None)
            .map_err(|error| format!("PostgreSQL baseline write failed to commit: {error:?}"))?
            .revision,
        StoreRevision(1)
    );
    drop(baseline_store);
    let mut baseline_admin = connect_tls(&baseline.admin, &environment.certificate_authority)?;
    let retained_row = baseline_admin.query_one(
        "SELECT state, checksum FROM public.cigar_tenant_states
         WHERE tenant_id = $1 AND revision = 1",
        &[&retained_tenant.as_str()],
    )?;
    let retained_state: Vec<u8> = retained_row.get(0);
    let retained_checksum: String = retained_row.get(1);
    let retained_root = authoritative_state_root(&mut baseline_admin)?;
    assert_ne!(retained_root, empty_root);

    let mut cases = vec![
        (PostgresMigrationFailpoint::AfterLedgerBootstrap, 0, 0),
        (PostgresMigrationFailpoint::AfterAdvisoryLock, 0, 0),
    ];
    for sequence in 1..=4 {
        cases.extend([
            (
                PostgresMigrationFailpoint::AfterMigrationSql(sequence),
                sequence - 1,
                sequence - 1,
            ),
            (
                PostgresMigrationFailpoint::AfterLedgerInsert(sequence),
                sequence - 1,
                sequence - 1,
            ),
        ]);
    }
    cases.extend([
        (PostgresMigrationFailpoint::BeforeCommit, 3, 3),
        (PostgresMigrationFailpoint::AfterCommit, 3, 4),
    ]);
    let executable = std::env::current_exe()?;
    for (index, (boundary, start_prefix, interrupted_prefix)) in cases.into_iter().enumerate() {
        let urls = cluster.create_database(&format!("abort{index}"))?;
        if boundary != PostgresMigrationFailpoint::AfterLedgerBootstrap {
            let mut retained = connect_tls(&urls.migrator, &environment.certificate_authority)?;
            install_prefix(&mut retained, start_prefix)?;
            if start_prefix >= 1 {
                seed_retained_state(
                    &mut retained,
                    &retained_tenant,
                    &retained_state,
                    &retained_checksum,
                )?;
            }
        }
        let before_root = if start_prefix >= 1 {
            Some(authoritative_state_root(&mut connect_tls(
                &urls.admin,
                &environment.certificate_authority,
            )?)?)
        } else {
            None
        };
        let status = Command::new(&executable)
            .args(["--exact", "postgres_migration_abort_child", "--nocapture"])
            .env(CHILD_URL, &urls.migrator)
            .env(CHILD_BOUNDARY, boundary_name(boundary))
            .status()?;
        assert_eq!(status.signal(), Some(MACOS_SIGABRT));
        assert!(status.code().is_none());

        let mut interrupted = connect_tls(&urls.admin, &environment.certificate_authority)?;
        assert_prefix(&mut interrupted, interrupted_prefix)?;
        if let Some(ref before_root) = before_root {
            assert_eq!(
                authoritative_state_root(&mut interrupted)?.as_str(),
                before_root.as_str()
            );
        }
        drop(interrupted);

        let configuration = environment.store_configuration(urls.migrator.clone())?;
        let receipt = PostgresStore::migrate(&configuration)?;
        assert_eq!(receipt.latest_sequence, 4);
        assert_eq!(receipt.checksums_verified, 4);
        let mut recovered = connect_tls(&urls.admin, &environment.certificate_authority)?;
        assert_prefix(&mut recovered, 4)?;
        assert_eq!(
            authoritative_state_root(&mut recovered)?,
            before_root.unwrap_or_else(|| empty_root.clone())
        );
    }

    qualify_runtime_authority_and_tamper(&mut cluster, &environment)?;
    qualify_retained_writer_continuity(&mut cluster, &environment)?;
    Ok(())
}

fn qualify_transport(environment: &LiveEnvironment) -> Result<(), Box<dyn Error>> {
    let mut tls = connect_tls(&environment.admin_url, &environment.certificate_authority)?;
    let ssl: bool = tls
        .query_one(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )?
        .get(0);
    assert!(ssl);
    assert_eq!(tls.query_one("SHOW ssl", &[])?.get::<_, String>(0), "on");
    assert_eq!(
        tls.query_one(
            "SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )?
        .get::<_, String>(0),
        "TLSv1.3"
    );

    let mut plaintext_url = Url::parse(&environment.admin_url)?;
    plaintext_url.set_query(Some("sslmode=disable"));
    assert!(Client::connect(plaintext_url.as_str(), NoTls).is_err());
    assert!(
        connect_tls(
            &environment.admin_url,
            &environment.wrong_certificate_authority,
        )
        .is_err()
    );
    assert!(
        connect_tls(
            &environment.ip_admin_url,
            &environment.certificate_authority,
        )
        .is_err()
    );

    let wrong_ca = PostgresConfiguration::new_with_certificate_authority(
        environment.admin_url.clone(),
        environment.server_name.clone(),
        &environment.wrong_certificate_authority,
    )?;
    assert_eq!(
        required_store_error(
            PostgresStore::migrate(&wrong_ca),
            "wrong PostgreSQL CA was accepted",
        )?
        .code(),
        StoreErrorCode::Unavailable
    );
    let wrong_name = PostgresConfiguration::new_with_certificate_authority(
        environment.ip_admin_url.clone(),
        "127.0.0.1",
        &environment.certificate_authority,
    )?;
    assert_eq!(
        required_store_error(
            PostgresStore::migrate(&wrong_name),
            "wrong PostgreSQL certificate name was accepted",
        )?
        .code(),
        StoreErrorCode::Unavailable
    );
    Ok(())
}

fn qualify_search_path_binding(
    cluster: &mut LiveCluster,
    environment: &LiveEnvironment,
) -> Result<(), Box<dyn Error>> {
    let urls = cluster.create_database("searchpath")?;
    let mut owner = connect_tls(&urls.migrator, &environment.certificate_authority)?;
    owner.batch_execute(&format!(
        "CREATE SCHEMA attacker;
         CREATE TABLE attacker.schema_migrations (marker text PRIMARY KEY);
         INSERT INTO attacker.schema_migrations (marker) VALUES ('untouched');
         CREATE TABLE attacker.cigar_repository_revision (marker text PRIMARY KEY);
         INSERT INTO attacker.cigar_repository_revision (marker) VALUES ('untouched');
         ALTER ROLE {} IN DATABASE {} SET search_path = attacker;",
        cluster.migrator_role,
        Url::parse(&urls.migrator)?.path().trim_start_matches('/')
    ))?;
    drop(owner);

    let mut hostile_url = Url::parse(&urls.migrator)?;
    hostile_url
        .query_pairs_mut()
        .append_pair("options", "-c search_path=attacker");
    assert_eq!(
        required_store_error(
            environment.store_configuration(hostile_url.into()),
            "caller-controlled PostgreSQL options were accepted",
        )?
        .code(),
        StoreErrorCode::InvalidContext
    );

    let configuration = environment.store_configuration(urls.migrator.clone())?;
    PostgresStore::migrate(&configuration)?;
    let mut admin = connect_tls(&urls.admin, &environment.certificate_authority)?;
    assert_prefix(&mut admin, 4)?;
    let attacker_ledger_rows: i64 = admin
        .query_one("SELECT count(*) FROM attacker.schema_migrations", &[])?
        .get(0);
    let attacker_revision_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM attacker.cigar_repository_revision",
            &[],
        )?
        .get(0);
    assert_eq!(attacker_ledger_rows, 1);
    assert_eq!(attacker_revision_rows, 1);
    assert!(relation_exists(&mut admin, "schema_migrations")?);
    Ok(())
}

fn qualify_runtime_authority_and_tamper(
    cluster: &mut LiveCluster,
    environment: &LiveEnvironment,
) -> Result<(), Box<dyn Error>> {
    let urls = cluster.create_database("authority")?;
    let migrator_configuration = environment.store_configuration(urls.migrator.clone())?;
    PostgresStore::migrate(&migrator_configuration)?;
    cluster.grant_runtime(&urls, 4)?;
    let runtime_configuration = environment.store_configuration(urls.runtime.clone())?;
    let runtime = PostgresStore::connect(runtime_configuration.clone())?;
    assert_eq!(runtime.revision()?, StoreRevision(0));
    assert_eq!(
        required_store_error(
            PostgresStore::migrate(&runtime_configuration),
            "runtime role invoked the migrator",
        )?
        .code(),
        StoreErrorCode::Unavailable
    );
    let mut runtime_raw = connect_tls(&urls.runtime, &environment.certificate_authority)?;
    let identity = runtime_raw.query_one(
        "SELECT current_user, session_user,
                (SELECT count(*) FROM pg_auth_members AS membership
                 JOIN pg_roles AS member ON member.oid = membership.member
                 WHERE member.rolname = current_user),
                pg_has_role(current_user, $1, 'SET'),
                pg_has_role(current_user, $1, 'MEMBER'),
                pg_has_role(current_user, 'pg_database_owner', 'SET')",
        &[&cluster.migrator_role],
    )?;
    assert_eq!(identity.get::<_, String>(0), cluster.runtime_role);
    assert_eq!(identity.get::<_, String>(1), cluster.runtime_role);
    assert_ne!(identity.get::<_, String>(0), cluster.migrator_role);
    assert_eq!(identity.get::<_, i64>(2), 0);
    assert!(!identity.get::<_, bool>(3));
    assert!(!identity.get::<_, bool>(4));
    assert!(!identity.get::<_, bool>(5));
    let role_flags = runtime_raw.query_one(
        "SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
                rolreplication, rolbypassrls
         FROM pg_roles WHERE rolname = current_user",
        &[],
    )?;
    assert!(!role_flags.get::<_, bool>(0));
    assert!(!role_flags.get::<_, bool>(1));
    assert!(!role_flags.get::<_, bool>(2));
    assert!(!role_flags.get::<_, bool>(3));
    assert!(role_flags.get::<_, bool>(4));
    assert!(!role_flags.get::<_, bool>(5));
    assert!(!role_flags.get::<_, bool>(6));

    for forbidden in [
        format!("SET ROLE {}", cluster.migrator_role),
        "SET ROLE pg_database_owner".to_owned(),
        format!("SET SESSION AUTHORIZATION {}", cluster.migrator_role),
        "CREATE SCHEMA forbidden_runtime_schema".to_owned(),
        "CREATE TEMPORARY TABLE forbidden_runtime_temp(value integer)".to_owned(),
        "CREATE TABLE public.forbidden_runtime_table(value integer)".to_owned(),
        "ALTER SCHEMA public RENAME TO forbidden_runtime_public".to_owned(),
        "DROP SCHEMA public CASCADE".to_owned(),
        "ALTER TABLE public.cigar_repository_revision ADD COLUMN forbidden integer".to_owned(),
        "DROP TABLE public.cigar_shared_wakeups".to_owned(),
        "CREATE FUNCTION public.forbidden_runtime_function() RETURNS integer \
         LANGUAGE sql AS 'SELECT 1'"
            .to_owned(),
        "ALTER FUNCTION public.cigar_gc_lock_repository_revision() \
         RENAME TO forbidden_runtime_function"
            .to_owned(),
        "DROP FUNCTION public.cigar_gc_lock_repository_revision()".to_owned(),
    ] {
        assert!(
            runtime_raw.batch_execute(&forbidden).is_err(),
            "runtime role unexpectedly executed forbidden DDL"
        );
    }
    for forbidden in [
        "UPDATE public.schema_migrations SET name = 'forbidden' WHERE sequence = 1".to_owned(),
        "DELETE FROM public.schema_migrations WHERE sequence = 1".to_owned(),
    ] {
        assert!(
            runtime_raw.batch_execute(&forbidden).is_err(),
            "runtime role unexpectedly mutated the migration ledger"
        );
    }
    assert!(
        runtime_raw
            .execute(
                "INSERT INTO public.schema_migrations
               (sequence, name, checksum, minimum_application_major,
                maximum_application_major, online)
             VALUES (5, 'forbidden', $1, 1, 2, true)",
                &[&format!("1220{}", "f".repeat(64))],
            )
            .is_err()
    );
    assert_eq!(
        runtime_raw
            .query_one("SELECT current_user", &[])?
            .get::<_, String>(0),
        cluster.runtime_role
    );

    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7811")?;
    let context = AccessContext::new(tenant.clone(), "migration-runtime-authority")?;
    let snapshot = fixture_snapshot()?;
    let mut write = runtime.begin_write(
        context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    write.stage_snapshot(snapshot.clone())?;
    assert_eq!(write.commit(None)?.revision, StoreRevision(1));
    let read = runtime.begin_read(
        context,
        cigar_store::SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    assert_eq!(read.get_snapshot(&snapshot.snapshot_id)?, Some(snapshot));
    drop(read);
    assert_eq!(
        runtime_raw
            .query_one("SELECT count(*) FROM public.cigar_tenant_states", &[])?
            .get::<_, i64>(0),
        0
    );
    runtime_raw.query_one(
        "SELECT set_config('cigar.tenant_id', $1, false)",
        &[&tenant.as_str()],
    )?;
    assert_eq!(
        runtime_raw
            .query_one("SELECT count(*) FROM public.cigar_tenant_states", &[])?
            .get::<_, i64>(0),
        1
    );
    drop(runtime_raw);
    drop(runtime);

    let mut owner = connect_tls(&urls.migrator, &environment.certificate_authority)?;
    assert_prefix(&mut owner, 4)?;
    owner.execute(
        "UPDATE public.schema_migrations SET checksum = $1 WHERE sequence = 2",
        &[&format!("1220{}", "0".repeat(64))],
    )?;
    let mutated = ledger_identity(&mut owner)?;
    assert!(PostgresStore::migrate(&migrator_configuration).is_err());
    assert_eq!(ledger_identity(&mut owner)?, mutated);
    owner.execute(
        "UPDATE public.schema_migrations SET checksum = $1 WHERE sequence = 2",
        &[&checksum(
            MIGRATIONS.get(1).ok_or("missing migration 2")?.1.as_bytes(),
        )],
    )?;

    owner.execute(
        "INSERT INTO public.schema_migrations
           (sequence, name, checksum, minimum_application_major,
            maximum_application_major, online)
         VALUES (5, 'unknown_future', $1, 1, 2, true)",
        &[&format!("1220{}", "a".repeat(64))],
    )?;
    let unknown = ledger_identity(&mut owner)?;
    assert!(PostgresStore::migrate(&migrator_configuration).is_err());
    assert_eq!(ledger_identity(&mut owner)?, unknown);
    owner.execute(
        "DELETE FROM public.schema_migrations WHERE sequence = 5",
        &[],
    )?;

    owner.execute(
        "UPDATE public.schema_migrations
         SET minimum_application_major = 2, maximum_application_major = 2
         WHERE sequence = 4",
        &[],
    )?;
    let downgrade = ledger_identity(&mut owner)?;
    assert!(PostgresStore::migrate(&migrator_configuration).is_err());
    assert_eq!(ledger_identity(&mut owner)?, downgrade);
    owner.execute(
        "UPDATE public.schema_migrations
         SET minimum_application_major = 1, maximum_application_major = 2
         WHERE sequence = 4",
        &[],
    )?;
    assert_prefix(&mut owner, 4)?;
    PostgresStore::migrate(&migrator_configuration)?;
    Ok(())
}

fn ledger_identity(client: &mut Client) -> Result<String, Box<dyn Error>> {
    let mut root = Sha256::new();
    root.update(b"CIGAR-POSTGRES-MIGRATION-LEDGER\0v1\0");
    for row in client.query(
        "SELECT sequence, name, checksum, minimum_application_major,
                maximum_application_major, online
         FROM public.schema_migrations ORDER BY sequence",
        &[],
    )? {
        root.update(row.get::<_, i32>(0).to_be_bytes());
        root_field(&mut root, row.get::<_, String>(1).as_bytes())?;
        root_field(&mut root, row.get::<_, String>(2).as_bytes())?;
        root.update(row.get::<_, i32>(3).to_be_bytes());
        root.update(row.get::<_, i32>(4).to_be_bytes());
        root.update([u8::from(row.get::<_, bool>(5))]);
    }
    Ok(checksum(&root.finalize()))
}

fn qualify_retained_writer_continuity(
    cluster: &mut LiveCluster,
    environment: &LiveEnvironment,
) -> Result<(), Box<dyn Error>> {
    let tenant = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?;
    let context = AccessContext::new(tenant.clone(), "migration-mixed-version")?;
    let snapshot = fixture_snapshot()?;

    let source_urls = cluster.create_database("mixedsource")?;
    let source_migrator = environment.store_configuration(source_urls.migrator.clone())?;
    PostgresStore::migrate(&source_migrator)?;
    cluster.grant_runtime(&source_urls, 4)?;
    let source_store =
        PostgresStore::connect(environment.store_configuration(source_urls.runtime.clone())?)?;
    let mut source_write = source_store.begin_write(
        context.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    source_write.stage_snapshot(snapshot.clone())?;
    assert_eq!(source_write.commit(None)?.revision, StoreRevision(1));
    drop(source_store);
    let mut source_admin = connect_tls(&source_urls.admin, &environment.certificate_authority)?;
    let source_row = source_admin.query_one(
        "SELECT state, checksum FROM cigar_tenant_states
         WHERE tenant_id = $1 AND revision = 1",
        &[&tenant.as_str()],
    )?;
    let state: Vec<u8> = source_row.get(0);
    let state_checksum: String = source_row.get(1);
    let source_root = authoritative_state_root(&mut source_admin)?;

    let mixed_urls = cluster.create_database("mixedtarget")?;
    let mut mixed_migrator = connect_tls(&mixed_urls.migrator, &environment.certificate_authority)?;
    install_prefix(&mut mixed_migrator, 1)?;
    cluster.grant_runtime(&mixed_urls, 1)?;
    let mut retained_runtime =
        connect_tls(&mixed_urls.runtime, &environment.certificate_authority)?;
    let mixed_configuration = environment.store_configuration(mixed_urls.migrator.clone())?;
    PostgresStore::migrate(&mixed_configuration)?;
    cluster.grant_runtime(&mixed_urls, 4)?;

    let mut retained_write = retained_runtime
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()?;
    retained_write.query_one(
        "SELECT set_config('cigar.tenant_id', $1, true)",
        &[&tenant.as_str()],
    )?;
    retained_write.execute(
        "INSERT INTO cigar_repository_revisions (revision) VALUES (1)",
        &[],
    )?;
    retained_write.execute(
        "INSERT INTO cigar_tenant_states (tenant_id, revision, state, checksum)
         VALUES ($1, 1, $2, $3)",
        &[&tenant.as_str(), &state, &state_checksum],
    )?;
    retained_write.execute(
        "UPDATE cigar_repository_revision SET revision = 1 WHERE singleton = true",
        &[],
    )?;
    retained_write.commit()?;
    drop(retained_runtime);

    let mut mixed_admin = connect_tls(&mixed_urls.admin, &environment.certificate_authority)?;
    assert_eq!(authoritative_state_root(&mut mixed_admin)?, source_root);
    let mixed_store =
        PostgresStore::connect(environment.store_configuration(mixed_urls.runtime.clone())?)?;
    let read = mixed_store.begin_read(
        context.clone(),
        cigar_store::SnapshotSelection::Latest,
        CancellationToken::default(),
    )?;
    assert_eq!(read.revision(), StoreRevision(1));
    assert_eq!(
        read.get_snapshot(&snapshot.snapshot_id)?,
        Some(snapshot.clone())
    );
    drop(read);

    let mut next_snapshot = snapshot;
    next_snapshot.snapshot_id = RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7899")?;
    let mut next_write =
        mixed_store.begin_write(context, StoreRevision(1), CancellationToken::default())?;
    next_write.stage_snapshot(next_snapshot)?;
    assert_eq!(next_write.commit(None)?.revision, StoreRevision(2));
    assert_eq!(mixed_store.revision()?, StoreRevision(2));
    Ok(())
}
