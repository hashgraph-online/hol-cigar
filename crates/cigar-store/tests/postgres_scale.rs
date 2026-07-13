//! Live 10M-row qualification for the production PostgreSQL atom projection.

use cigar_protocol::{
    AtomPayload, ContentDigest, ContextAtomV1, LineageId, RecordId, Validate, VersionId,
};
use cigar_store::{
    AccessContext, CancellationToken, PostgresConfiguration, PostgresFailpoint, PostgresStore,
    Repository, StoreErrorCode, StoreRevision, WriteTransaction,
};
use postgres::NoTls;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TOTAL_ROWS: u64 = 10_000_000;
const RESTORE_BATCH_ROWS: u64 = 10_000;
const CURVE_TARGETS: [u64; 5] = [1_000, 10_000, 100_000, 1_000_000, TOTAL_ROWS];
const CURVE_QUERY_SAMPLES: usize = 25;
const FINAL_CORRECTNESS_SAMPLES: usize = 256;
const DATASET_ALGORITHM: &str = "cigar.wp18.atom-projection-scale.v1";

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

struct TestDatabase {
    admin_url: String,
    database: String,
    role: String,
    owner_url: String,
    runtime_url: String,
}

impl TestDatabase {
    fn create(admin_url: String) -> Result<Self, Box<dyn Error>> {
        let suffix = NEXT_DATABASE.fetch_add(1, Ordering::AcqRel);
        let database = format!("cigar_wp18_scale_{}_{suffix}", std::process::id());
        let role = format!("cigar_wp18_scale_runtime_{}_{suffix}", std::process::id());
        let password = format!("wp18-scale-runtime-{suffix}-only");
        let (prefix, _database_and_query) = admin_url
            .rsplit_once('/')
            .ok_or("PostgreSQL test URL must end in a database name")?;
        let authority = admin_url
            .strip_prefix("postgresql://")
            .and_then(|url| url.split('/').next())
            .and_then(|authority| authority.rsplit_once('@').map(|pair| pair.1))
            .ok_or("PostgreSQL test URL must contain an explicit authority")?;
        let owner_url = format!("{prefix}/{database}");
        let runtime_url = format!("postgresql://{role}:{password}@{authority}/{database}");
        let mut admin = postgres::Client::connect(&admin_url, NoTls)?;
        admin.batch_execute(&format!("CREATE DATABASE {database}"))?;
        let mut owner = postgres::Client::connect(&owner_url, NoTls)?;
        owner.batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}'
             NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
        ))?;
        Ok(Self {
            admin_url,
            database,
            role,
            owner_url,
            runtime_url,
        })
    }

    fn grant_runtime(&self) -> Result<(), Box<dyn Error>> {
        let mut owner = postgres::Client::connect(&self.owner_url, NoTls)?;
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
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if let Ok(mut admin) = postgres::Client::connect(&self.admin_url, NoTls) {
            let _terminated = admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[&self.database],
            );
            let _dropped = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {};
                 DROP ROLE IF EXISTS {};",
                self.database, self.role
            ));
        }
    }
}

#[derive(Serialize)]
struct LatencyDistribution {
    samples: usize,
    minimum_micros: u64,
    p50_micros: u64,
    p95_micros: u64,
    p99_micros: u64,
    maximum_micros: u64,
    mean_micros: u64,
}

#[derive(Serialize)]
struct DatabaseMetrics {
    database_size_bytes: u64,
    projection_total_bytes: u64,
    projection_heap_bytes: u64,
    projection_index_bytes: u64,
    estimated_live_rows: i64,
    estimated_dead_rows: i64,
    sequential_scans: i64,
    index_scans: i64,
    committed_transactions: i64,
    rolled_back_transactions: i64,
    blocks_read: i64,
    blocks_hit: i64,
    temporary_files: i64,
    temporary_bytes: i64,
    deadlocks: i64,
    conflicts: i64,
}

#[derive(Serialize)]
struct CurvePoint {
    target_rows: u64,
    added_rows: u64,
    interval_elapsed_millis: u64,
    cumulative_elapsed_millis: u64,
    interval_rows_per_second: u64,
    exact_count: u64,
    exact_count_elapsed_millis: u64,
    exact_query_latency: LatencyDistribution,
    database: DatabaseMetrics,
}

#[derive(Serialize)]
struct PostgresResources {
    version: String,
    shared_buffers: String,
    work_mem: String,
    maintenance_work_mem: String,
    effective_cache_size: String,
    max_connections: String,
    host_parallelism: usize,
}

#[derive(Serialize)]
struct DatasetReceipt {
    algorithm: &'static str,
    canonical_digest: String,
    source_digest: String,
    tenant_id: String,
    total_rows: u64,
    restore_batch_rows: u64,
}

#[derive(Serialize)]
struct FailureReceipt {
    unexpected_batch_failures: u64,
    unexpected_query_failures: u64,
    immutable_collision_rejected: bool,
    transaction_failpoint_rolled_back: bool,
}

#[derive(Serialize)]
struct ScaleReceipt {
    schema_version: &'static str,
    packet: &'static str,
    result: &'static str,
    started_at_unix_millis: u128,
    finished_at_unix_millis: u128,
    migration_sequence: u32,
    physical_row_count: u64,
    production_projection: bool,
    public_commit_atomic_projection: bool,
    public_rebuild_verified: bool,
    forced_rls_isolation_verified: bool,
    correctness_samples: usize,
    dataset: DatasetReceipt,
    failures: FailureReceipt,
    postgres: PostgresResources,
    curve: Vec<CurvePoint>,
}

fn unix_millis() -> Result<u128, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

fn multihash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("1220{suffix}")
}

fn template_atom() -> Result<ContextAtomV1, Box<dyn Error>> {
    let fixture = cigar_testkit::deterministic_protocol_fixture("ContextAtomV1")
        .ok_or("missing deterministic ContextAtomV1 fixture")?;
    Ok(serde_json::from_value(fixture.input)?)
}

fn scale_atom(
    template: &ContextAtomV1,
    tenant: &RecordId,
    index: u64,
) -> Result<ContextAtomV1, Box<dyn Error>> {
    let payload = format!("wp18-scale-record-{index:010}");
    let digest = multihash(payload.as_bytes());
    let mut atom = template.clone();
    atom.atom_id = RecordId::new(format!("018f0000-0000-7000-8000-{index:012x}"))?;
    atom.lineage_id = LineageId::new(format!("018f0001-0000-7000-8000-{index:012x}"))?;
    atom.version_id = VersionId::new(digest.clone())?;
    atom.content_digest = ContentDigest::new(digest.clone())?;
    atom.payload = AtomPayload::InlineText(payload);
    atom.source.revision = format!("wp18-scale-source-{index:010}");
    atom.source.snapshot_digest = ContentDigest::new(digest)?;
    atom.scope.tenant_id = tenant.clone();
    atom.validate()?;
    Ok(atom)
}

fn update_dataset_digest(digest: &mut Sha256, atom: &ContextAtomV1) {
    for value in [
        atom.atom_id.as_str(),
        atom.lineage_id.as_str(),
        atom.version_id.as_str(),
        atom.content_digest.as_str(),
        atom.source.revision.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    if let AtomPayload::InlineText(payload) = &atom.payload {
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload.as_bytes());
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn percentile(sorted: &[u64], numerator: usize, denominator: usize) -> u64 {
    let index = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted.get(index).copied().unwrap_or(u64::MAX)
}

fn latency_distribution(mut samples: Vec<u64>) -> LatencyDistribution {
    samples.sort_unstable();
    let sum = samples.iter().copied().map(u128::from).sum::<u128>();
    LatencyDistribution {
        samples: samples.len(),
        minimum_micros: samples.first().copied().unwrap_or(u64::MAX),
        p50_micros: percentile(&samples, 50, 100),
        p95_micros: percentile(&samples, 95, 100),
        p99_micros: percentile(&samples, 99, 100),
        maximum_micros: *samples.last().unwrap_or(&u64::MAX),
        mean_micros: u64::try_from(sum / samples.len() as u128).unwrap_or(u64::MAX),
    }
}

fn sample_indices(rows: u64, samples: usize) -> Vec<u64> {
    let mut indices = Vec::with_capacity(samples);
    for sample in 0..samples {
        let value = if sample == 0 {
            0
        } else if sample == 1 {
            rows - 1
        } else {
            (sample as u64)
                .wrapping_mul(11_400_714_819_323_198_485)
                .wrapping_add(7_919)
                % rows
        };
        indices.push(value);
    }
    indices
}

fn exact_query_distribution(
    store: &PostgresStore,
    template: &ContextAtomV1,
    tenant: &RecordId,
    rows: u64,
    samples: usize,
) -> Result<LatencyDistribution, Box<dyn Error>> {
    let mut latencies = Vec::with_capacity(samples);
    for index in sample_indices(rows, samples) {
        let expected = scale_atom(template, tenant, index)?;
        let started = Instant::now();
        let observed = store
            .atom_projection_get(tenant, &expected.version_id)?
            .ok_or("projected atom was absent")?;
        latencies.push(duration_micros(started.elapsed()));
        if observed != expected {
            return Err("projected atom did not match its generated semantic record".into());
        }
        observed.validate()?;
    }
    Ok(latency_distribution(latencies))
}

fn database_metrics(owner: &mut postgres::Client) -> Result<DatabaseMetrics, Box<dyn Error>> {
    let sizes = owner.query_one(
        "SELECT pg_database_size(current_database()),
                pg_total_relation_size('cigar_atom_projection'),
                pg_relation_size('cigar_atom_projection'),
                pg_indexes_size('cigar_atom_projection')",
        &[],
    )?;
    let table = owner.query_one(
        "SELECT n_live_tup, n_dead_tup, seq_scan, idx_scan
         FROM pg_stat_user_tables WHERE relname = 'cigar_atom_projection'",
        &[],
    )?;
    let database = owner.query_one(
        "SELECT xact_commit, xact_rollback, blks_read, blks_hit,
                temp_files, temp_bytes, deadlocks, conflicts
         FROM pg_stat_database WHERE datname = current_database()",
        &[],
    )?;
    let positive = |value: i64| u64::try_from(value).unwrap_or(0);
    Ok(DatabaseMetrics {
        database_size_bytes: positive(sizes.get(0)),
        projection_total_bytes: positive(sizes.get(1)),
        projection_heap_bytes: positive(sizes.get(2)),
        projection_index_bytes: positive(sizes.get(3)),
        estimated_live_rows: table.get(0),
        estimated_dead_rows: table.get(1),
        sequential_scans: table.get(2),
        index_scans: table.get(3),
        committed_transactions: database.get(0),
        rolled_back_transactions: database.get(1),
        blocks_read: database.get(2),
        blocks_hit: database.get(3),
        temporary_files: database.get(4),
        temporary_bytes: database.get(5),
        deadlocks: database.get(6),
        conflicts: database.get(7),
    })
}

fn postgres_resources(owner: &mut postgres::Client) -> Result<PostgresResources, Box<dyn Error>> {
    let row = owner.query_one(
        "SELECT version(), current_setting('shared_buffers'), current_setting('work_mem'),
                current_setting('maintenance_work_mem'), current_setting('effective_cache_size'),
                current_setting('max_connections')",
        &[],
    )?;
    Ok(PostgresResources {
        version: row.get(0),
        shared_buffers: row.get(1),
        work_mem: row.get(2),
        maintenance_work_mem: row.get(3),
        effective_cache_size: row.get(4),
        max_connections: row.get(5),
        host_parallelism: std::thread::available_parallelism()?.get(),
    })
}

fn write_receipt(path: &Path, receipt: &ScaleReceipt) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or("scale receipt path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let file = File::create(&temporary)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, receipt)?;
    let file = writer.into_inner()?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[test]
fn postgres_production_projection_physically_qualifies_ten_million_valid_atoms()
-> Result<(), Box<dyn Error>> {
    let required = std::env::var_os("CIGAR_REQUIRE_LIVE_SCALE_TESTS").is_some();
    if !required {
        return Ok(());
    }
    let admin_url = std::env::var("CIGAR_TEST_POSTGRES_ADMIN_URL")?;
    let receipt_path = PathBuf::from(std::env::var("CIGAR_SCALE_RECEIPT_PATH")?);
    let source_digest = std::env::var("CIGAR_SCALE_SOURCE_DIGEST")?;
    if source_digest.is_empty() || source_digest.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("scale source digest is invalid".into());
    }
    let _removed_stale_receipt = fs::remove_file(&receipt_path);
    let started_at_unix_millis = unix_millis()?;
    let qualification_started = Instant::now();

    let database = TestDatabase::create(admin_url)?;
    let mut owner_configuration = PostgresConfiguration::new(database.owner_url.clone())?;
    owner_configuration.statement_timeout = Duration::from_secs(300);
    owner_configuration.idle_transaction_timeout = Duration::from_secs(300);
    let migration = PostgresStore::migrate(&owner_configuration)?;
    if migration.latest_sequence != 4 || migration.checksums_verified != 4 {
        return Err("scale qualification did not install the exact migration level".into());
    }
    database.grant_runtime()?;

    let mut configuration = PostgresConfiguration::new(database.runtime_url.clone())?;
    configuration.minimum_connections = 1;
    configuration.maximum_connections = 4;
    configuration.statement_timeout = Duration::from_secs(300);
    configuration.idle_transaction_timeout = Duration::from_secs(300);
    let store = PostgresStore::connect(configuration)?;
    let tenant = RecordId::new("018f0002-0000-7000-8000-000000000001")?;
    let other_tenant = RecordId::new("018f0002-0000-7000-8000-000000000002")?;
    let access = AccessContext::new(tenant.clone(), "wp18-scale")?;
    let template = template_atom()?;
    let mut dataset_digest = Sha256::new();
    dataset_digest.update(DATASET_ALGORITHM.as_bytes());
    dataset_digest.update(TOTAL_ROWS.to_be_bytes());

    let first_atom = scale_atom(&template, &tenant, 0)?;
    update_dataset_digest(&mut dataset_digest, &first_atom);
    let mut write = store.begin_write(
        access.clone(),
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    write.publish_atoms(vec![first_atom.clone()], Vec::new())?;
    let first_receipt = write.commit(None)?;
    if first_receipt.revision != StoreRevision(1)
        || first_receipt.replayed
        || store.atom_projection_get(&tenant, &first_atom.version_id)? != Some(first_atom.clone())
    {
        return Err("ordinary public commit did not atomically maintain the projection".into());
    }

    let mut owner = postgres::Client::connect(&database.owner_url, NoTls)?;
    owner.batch_execute(&format!(
        "BEGIN;
         SET LOCAL cigar.tenant_id = '{}';
         DELETE FROM cigar_atom_projection WHERE tenant_id = '{}';
         COMMIT;",
        tenant.as_str(),
        tenant.as_str(),
    ))?;
    if store.atom_projection_count(&tenant)? != 0 || store.rebuild_atom_projection(&tenant)? != 1 {
        return Err("public atom projection rebuild did not restore the tenant snapshot".into());
    }

    let rollback_atom = scale_atom(&template, &tenant, TOTAL_ROWS)?;
    let mut rollback_write =
        store.begin_write(access, StoreRevision(1), CancellationToken::default())?;
    rollback_write.publish_atoms(vec![rollback_atom.clone()], Vec::new())?;
    store.inject_failpoint(PostgresFailpoint::BeforeCommit)?;
    if rollback_write.commit(None).map_err(|error| error.code())
        != Err(StoreErrorCode::InjectedAbort)
        || store
            .atom_projection_get(&tenant, &rollback_atom.version_id)?
            .is_some()
        || store.revision()? != StoreRevision(1)
    {
        return Err("projection publication escaped a rolled-back public transaction".into());
    }

    let mut curve = Vec::with_capacity(CURVE_TARGETS.len());
    let mut next_index = 1_u64;
    let mut prior_target = 1_u64;
    for target in CURVE_TARGETS {
        let interval_started = Instant::now();
        while next_index < target {
            let end = target.min(next_index + RESTORE_BATCH_ROWS);
            let mut atoms = Vec::with_capacity(usize::try_from(end - next_index)?);
            for index in next_index..end {
                let atom = scale_atom(&template, &tenant, index)?;
                update_dataset_digest(&mut dataset_digest, &atom);
                atoms.push(atom);
            }
            let inserted =
                store.restore_atom_projection_batch(&tenant, StoreRevision(1), atoms.as_slice())?;
            if inserted != end - next_index {
                return Err("fresh projection restore did not insert its exact batch".into());
            }
            next_index = end;
            if next_index.is_multiple_of(100_000) || next_index == target {
                eprintln!("wp18-scale: physically inserted {next_index}/{TOTAL_ROWS} atoms");
            }
        }
        let interval_elapsed = interval_started.elapsed();
        let count_started = Instant::now();
        let exact_count = store.atom_projection_count(&tenant)?;
        let count_elapsed = count_started.elapsed();
        if exact_count != target {
            return Err(format!("physical projection count {exact_count} != {target}").into());
        }
        let query_latency =
            exact_query_distribution(&store, &template, &tenant, target, CURVE_QUERY_SAMPLES)?;
        let interval_millis = duration_millis(interval_elapsed).max(1);
        let added_rows = target - prior_target;
        curve.push(CurvePoint {
            target_rows: target,
            added_rows,
            interval_elapsed_millis: interval_millis,
            cumulative_elapsed_millis: duration_millis(qualification_started.elapsed()),
            interval_rows_per_second: added_rows.saturating_mul(1_000) / interval_millis,
            exact_count,
            exact_count_elapsed_millis: duration_millis(count_elapsed),
            exact_query_latency: query_latency,
            database: database_metrics(&mut owner)?,
        });
        prior_target = target;
    }

    let repeat_start = TOTAL_ROWS - RESTORE_BATCH_ROWS;
    let repeat_batch = (repeat_start..TOTAL_ROWS)
        .map(|index| scale_atom(&template, &tenant, index))
        .collect::<Result<Vec<_>, _>>()?;
    if store.restore_atom_projection_batch(&tenant, StoreRevision(1), &repeat_batch)? != 0 {
        return Err("exact repeated projection restore was not idempotent".into());
    }
    let mut collision = scale_atom(&template, &tenant, TOTAL_ROWS - 1)?;
    collision.atom_id = RecordId::new("018f0000-0000-7000-8000-000000ffffff")?;
    if store
        .restore_atom_projection_batch(&tenant, StoreRevision(1), &[collision])
        .map_err(|error| error.code())
        != Err(StoreErrorCode::InvalidRecord)
    {
        return Err("immutable projection collision was not rejected".into());
    }
    if store.atom_projection_count(&other_tenant)? != 0 {
        return Err("forced RLS exposed the scale tenant through another tenant capability".into());
    }
    let final_distribution = exact_query_distribution(
        &store,
        &template,
        &tenant,
        TOTAL_ROWS,
        FINAL_CORRECTNESS_SAMPLES,
    )?;
    eprintln!(
        "wp18-scale: final {} correctness samples p95={}us p99={}us",
        final_distribution.samples, final_distribution.p95_micros, final_distribution.p99_micros,
    );
    let physical_row_count = store.atom_projection_count(&tenant)?;
    if physical_row_count != TOTAL_ROWS {
        return Err(
            "final production projection did not physically contain 10,000,000 rows".into(),
        );
    }
    owner.batch_execute("ANALYZE cigar_atom_projection")?;
    if let Some(final_point) = curve.last_mut() {
        final_point.database = database_metrics(&mut owner)?;
    }

    let canonical_digest = {
        let bytes = dataset_digest.finalize();
        format!(
            "1220{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    let receipt = ScaleReceipt {
        schema_version: "cigar.shared-scale-qualification.v1",
        packet: "WP18",
        result: "pass",
        started_at_unix_millis,
        finished_at_unix_millis: unix_millis()?,
        migration_sequence: migration.latest_sequence,
        physical_row_count,
        production_projection: true,
        public_commit_atomic_projection: true,
        public_rebuild_verified: true,
        forced_rls_isolation_verified: true,
        correctness_samples: FINAL_CORRECTNESS_SAMPLES,
        dataset: DatasetReceipt {
            algorithm: DATASET_ALGORITHM,
            canonical_digest,
            source_digest,
            tenant_id: tenant.as_str().to_owned(),
            total_rows: TOTAL_ROWS,
            restore_batch_rows: RESTORE_BATCH_ROWS,
        },
        failures: FailureReceipt {
            unexpected_batch_failures: 0,
            unexpected_query_failures: 0,
            immutable_collision_rejected: true,
            transaction_failpoint_rolled_back: true,
        },
        postgres: postgres_resources(&mut owner)?,
        curve,
    };
    write_receipt(&receipt_path, &receipt)?;
    eprintln!(
        "wp18-scale: qualified {physical_row_count} production rows; receipt={}",
        receipt_path.display()
    );
    Ok(())
}
