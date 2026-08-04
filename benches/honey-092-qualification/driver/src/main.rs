//! Small controlled v4/v5 comparison used by the Honey 0.9.2 correction gate.

use cigar_crypto::{CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider};
use cigar_protocol::RecordId;
use cigar_store::{
    CancellationToken, LocalBlobStore, LocalRepositoryBlobStore, RepositoryBlobStore,
    ServiceExpectedVersion, ServiceRepository, SqliteStore, WorkerLocator, WorkerState,
    WorkerUpdate,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "v5")]
use cigar_store::migrate_v5::{MigrationPathsV5, migrate_v4_to_v5, preflight_v4_to_v5_migration};
#[cfg(feature = "v5")]
use cigar_store::{
    BackupErrorCode, BackupIdentity, RepositoryStartupMetrics, RepositoryStartupMetricsObserver,
    SqliteCapacityProfile, SqliteV5Store, create_backup_with_effect_checkpoint,
};
#[cfg(feature = "v5")]
use std::sync::Mutex;
const TENANT_ID: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f78f1";
const STARTUP_REPETITIONS: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Format {
    V4,
    #[cfg(feature = "v5")]
    V5,
}

#[derive(Debug)]
struct Arguments {
    format: Format,
    root: PathBuf,
    initial_records: u64,
    mutations: u64,
}

#[derive(Serialize)]
struct MigrationObservation {
    duration_nanoseconds: u64,
    root_revision_exact: bool,
    retained_revisions: u64,
    source_database_bytes: u64,
    target_database_bytes: u64,
}

#[derive(Serialize)]
struct DriverResult {
    schema_version: &'static str,
    format: &'static str,
    initial_records: u64,
    mutations: u64,
    revision_before: u64,
    revision_after: u64,
    physical_before_bytes: u64,
    physical_after_bytes: u64,
    physical_growth_bytes: u64,
    mutation_latencies_nanoseconds: Vec<u64>,
    process_cold_startup_nanoseconds: Vec<u64>,
    process_cold_startup_stages_nanoseconds: BTreeMap<String, Vec<u64>>,
    migration: Option<MigrationObservation>,
}

#[cfg(feature = "v5")]
#[derive(Default)]
struct CapturingStartupObserver {
    observations: Mutex<Vec<RepositoryStartupMetrics>>,
}

#[cfg(feature = "v5")]
impl RepositoryStartupMetricsObserver for CapturingStartupObserver {
    fn observe_repository_startup(&self, metrics: RepositoryStartupMetrics) {
        if let Ok(mut observations) = self.observations.lock() {
            observations.push(metrics);
        }
    }
}

#[cfg(feature = "v5")]
fn collect_startup_stages(
    observer: &CapturingStartupObserver,
    stages: &mut BTreeMap<String, Vec<u64>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let observations = observer
        .observations
        .lock()
        .map_err(|_error| std::io::Error::other("startup observer lock poisoned"))?;
    for observation in observations.iter() {
        stages
            .entry(observation.stage.as_str().to_owned())
            .or_default()
            .push(nanos(observation.duration));
    }
    Ok(())
}

fn parse_u64(value: Option<String>) -> Result<u64, &'static str> {
    value
        .ok_or("missing argument value")?
        .parse::<u64>()
        .map_err(|_error| "invalid integer")
}

fn arguments() -> Result<Arguments, &'static str> {
    let mut values = env::args().skip(1);
    let mut format = None;
    let mut root = None;
    let mut initial_records = None;
    let mut mutations = None;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--format" => {
                format = Some(match values.next().as_deref() {
                    Some("v4") => Format::V4,
                    #[cfg(feature = "v5")]
                    Some("v5") => Format::V5,
                    _ => return Err("unsupported format"),
                });
            }
            "--root" => root = values.next().map(PathBuf::from),
            "--initial-records" => initial_records = Some(parse_u64(values.next())?),
            "--mutations" => mutations = Some(parse_u64(values.next())?),
            _ => return Err("unknown argument"),
        }
    }
    let result = Arguments {
        format: format.ok_or("format missing")?,
        root: root.ok_or("root missing")?,
        initial_records: initial_records.ok_or("initial records missing")?,
        mutations: mutations.ok_or("mutations missing")?,
    };
    if result.initial_records < 4
        || result.initial_records > 4_096
        || result.mutations == 0
        || result.mutations > 10_000
    {
        return Err("workload exceeds qualification bounds");
    }
    Ok(result)
}

fn nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn prepare_new_root(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "workload root already exists",
        )
        .into());
    }
    std::fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn locator(tenant: &RecordId, index: u64) -> Result<WorkerLocator, Box<dyn std::error::Error>> {
    Ok(WorkerLocator::new(
        tenant.clone(),
        format!("honey-092-qualification-{index:06}"),
    )?)
}

fn seed<R: ServiceRepository>(
    store: &R,
    initial_records: u64,
) -> Result<(RecordId, Vec<(WorkerLocator, WorkerState)>), Box<dyn std::error::Error>> {
    let tenant = RecordId::new(TENANT_ID)?;
    let mut states = Vec::with_capacity(usize::try_from(initial_records)?);
    for index in 0..initial_records {
        let worker = locator(&tenant, index)?;
        let state = store.worker_update(
            &worker,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "honey-092-qualification".to_owned(),
                now_unix_nanos: index.saturating_add(1),
                expires_at_unix_nanos: u64::MAX,
            },
            &CancellationToken::default(),
        )?;
        states.push((worker, state));
    }
    Ok((tenant, states))
}

fn mutate<R: ServiceRepository>(
    store: &R,
    states: &mut [(WorkerLocator, WorkerState)],
    mutations: u64,
    mutation_offset: u64,
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut latencies = Vec::with_capacity(usize::try_from(mutations)?);
    for mutation in 0..mutations {
        let sequence = mutation_offset
            .checked_add(mutation)
            .ok_or_else(|| std::io::Error::other("mutation sequence overflow"))?;
        let index = usize::try_from(sequence % 4)?;
        let (worker, state) = states
            .get_mut(index)
            .ok_or_else(|| std::io::Error::other("worker state missing"))?;
        let started = Instant::now();
        *state = store.worker_update(
            worker,
            WorkerUpdate::Checkpoint {
                expected: ServiceExpectedVersion::Version(state.version()),
                owner: "honey-092-qualification".to_owned(),
                fencing_token: state.fencing_token(),
                cursor: sequence.to_be_bytes().to_vec(),
                heartbeat_unix_nanos: sequence.saturating_add(1_000_000),
                expires_at_unix_nanos: u64::MAX,
            },
            &CancellationToken::default(),
        )?;
        latencies.push(nanos(started.elapsed()));
    }
    Ok(latencies)
}

fn physical_bytes(database: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    let mut total = 0_u64;
    let base = database.as_os_str();
    for suffix in ["", "-wal", "-shm", ".cigar-revision"] {
        let mut value = base.to_os_string();
        value.push(suffix);
        match std::fs::metadata(PathBuf::from(value)) {
            Ok(metadata) if metadata.is_file() => {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| std::io::Error::other("physical byte count overflow"))?;
            }
            Ok(_) => return Err(std::io::Error::other("unexpected non-file store member").into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(total)
}

fn local_blob_repository(
    root: &Path,
    tenant: &str,
) -> Result<Arc<dyn RepositoryBlobStore>, Box<dyn std::error::Error>> {
    let provider = Arc::new(MemoryKeyProvider::default());
    let wrapping = provider.create(CreateKeyRequest {
        tenant: tenant.to_owned(),
        purpose: KeyPurpose::BlobEncryption,
        algorithm: KeyAlgorithm::XChaCha20Poly1305,
        created_at: 1,
        activated_at: 1,
    })?;
    let local = LocalBlobStore::open(root, provider)?;
    Ok(Arc::new(LocalRepositoryBlobStore::new(
        local,
        wrapping.key_ref,
        1,
    )))
}

fn v4_startups(
    database: &Path,
    blobs: Arc<dyn RepositoryBlobStore>,
    states: &mut [(WorkerLocator, WorkerState)],
    mut expected_revision: u64,
    mutation_offset: u64,
) -> Result<(Vec<u64>, BTreeMap<String, Vec<u64>>), Box<dyn std::error::Error>> {
    let mut durations = Vec::with_capacity(STARTUP_REPETITIONS);
    for repetition in 0..STARTUP_REPETITIONS {
        let started = Instant::now();
        let store = SqliteStore::open_with_blob_repository(database, Arc::clone(&blobs))?;
        let elapsed = nanos(started.elapsed());
        if store.revision()?.0 != expected_revision {
            return Err(std::io::Error::other("v4 restart revision mismatch").into());
        }
        if repetition + 1 < STARTUP_REPETITIONS {
            let _tail_latency = mutate(
                &store,
                states,
                1,
                mutation_offset
                    .checked_add(u64::try_from(repetition)?)
                    .ok_or_else(|| std::io::Error::other("v4 startup sweep offset overflow"))?,
            )?;
            expected_revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("v4 startup sweep revision overflow"))?;
        }
        drop(store);
        durations.push(elapsed);
    }
    Ok((durations, BTreeMap::new()))
}

fn run_v4(arguments: &Arguments) -> Result<DriverResult, Box<dyn std::error::Error>> {
    let database = arguments.root.join("store.sqlite3");
    let blobs = local_blob_repository(&arguments.root.join("v4-blobs"), TENANT_ID)?;
    let store = SqliteStore::open_with_blob_repository(&database, Arc::clone(&blobs))?;
    let (_tenant, mut states) = seed(&store, arguments.initial_records)?;
    let revision_before = store.revision()?.0;
    drop(store);
    let physical_before_bytes = physical_bytes(&database)?;
    let store = SqliteStore::open_with_blob_repository(&database, Arc::clone(&blobs))?;
    let mutation_latencies_nanoseconds = mutate(&store, &mut states, arguments.mutations, 0)?;
    let revision_after = store.revision()?.0;
    drop(store);
    let physical_after_bytes = physical_bytes(&database)?;
    let (process_cold_startup_nanoseconds, process_cold_startup_stages_nanoseconds) =
        v4_startups(
            &database,
            blobs,
            &mut states,
            revision_after,
            arguments.mutations,
        )?;
    Ok(DriverResult {
        schema_version: "cigar.honey-092-system-comparison-driver.v1",
        format: "sqlite-v4-full-residual",
        initial_records: arguments.initial_records,
        mutations: arguments.mutations,
        revision_before,
        revision_after,
        physical_before_bytes,
        physical_after_bytes,
        physical_growth_bytes: physical_after_bytes.saturating_sub(physical_before_bytes),
        mutation_latencies_nanoseconds,
        process_cold_startup_nanoseconds,
        process_cold_startup_stages_nanoseconds,
        migration: None,
    })
}

#[cfg(feature = "v5")]
fn v5_startups(
    database: &Path,
    blobs: Arc<dyn RepositoryBlobStore>,
    states: &mut [(WorkerLocator, WorkerState)],
    mut expected_revision: u64,
    mutation_offset: u64,
) -> Result<(Vec<u64>, BTreeMap<String, Vec<u64>>), Box<dyn std::error::Error>> {
    let mut durations = Vec::with_capacity(STARTUP_REPETITIONS);
    let mut stages = BTreeMap::new();
    for repetition in 0..STARTUP_REPETITIONS {
        let observer = Arc::new(CapturingStartupObserver::default());
        let observer_handle: Arc<dyn RepositoryStartupMetricsObserver> = observer.clone();
        let started = Instant::now();
        let store = SqliteV5Store::open_with_blob_repository_capacity_and_startup_metrics(
            database,
            Arc::clone(&blobs),
            SqliteCapacityProfile::Standard,
            observer_handle,
        )?;
        let elapsed = nanos(started.elapsed());
        if store.revision()?.0 != expected_revision {
            return Err(std::io::Error::other("v5 restart revision mismatch").into());
        }
        if repetition + 1 < STARTUP_REPETITIONS {
            let _tail_latency = mutate(
                &store,
                states,
                1,
                mutation_offset
                    .checked_add(u64::try_from(repetition)?)
                    .ok_or_else(|| std::io::Error::other("v5 startup sweep offset overflow"))?,
            )?;
            expected_revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("v5 startup sweep revision overflow"))?;
        }
        drop(store);
        collect_startup_stages(&observer, &mut stages)?;
        durations.push(elapsed);
    }
    Ok((durations, stages))
}

#[cfg(feature = "v5")]
fn run_v5(arguments: &Arguments) -> Result<DriverResult, Box<dyn std::error::Error>> {
    let source = arguments.root.join("source-v4.sqlite3");
    let target = arguments.root.join("store-v5.sqlite3");
    let backup = arguments.root.join("verified-v4-backup");
    let blob_root = arguments.root.join("blobs");
    std::fs::create_dir(&blob_root)?;

    let provider = Arc::new(MemoryKeyProvider::default());
    let signing = provider.create(CreateKeyRequest {
        tenant: "honey-092-qualification".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: 1,
        activated_at: 1,
    })?;
    let source_store = SqliteStore::open(&source)?;
    let (tenant, mut states) = seed(&source_store, arguments.initial_records)?;
    let source_revision = source_store.revision()?;
    create_backup_with_effect_checkpoint(
        &source_store,
        &blob_root,
        &backup,
        provider.as_ref(),
        BackupIdentity {
            signing_key: &signing.key_ref,
            tenant: "honey-092-qualification",
            signer: "controlled-comparison",
            created_at_unix_nanos: 2,
        },
        |_database, checkpoint| {
            use std::io::Write as _;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(checkpoint)
                .map_err(|_error| BackupErrorCode::Unavailable)?;
            file.write_all(b"honey-092-controlled-effect-checkpoint")
                .map_err(|_error| BackupErrorCode::Unavailable)?;
            file.sync_all()
                .map_err(|_error| BackupErrorCode::Unavailable)
        },
    )?;
    drop(source_store);

    let migration_started = Instant::now();
    let migration_paths = MigrationPathsV5::resolve(&source, &backup, &target)
        .map_err(|error| std::io::Error::other(format!("migration paths: {error:?}")))?;
    let preflight =
        preflight_v4_to_v5_migration(migration_paths, provider.as_ref(), 3, |identity| {
            identity.tenant == "honey-092-qualification"
                && identity.signer == "controlled-comparison"
        })
        .map_err(|error| std::io::Error::other(format!("migration preflight: {error:?}")))?;
    let source_database_bytes = preflight.source_database_bytes();
    let migrated = migrate_v4_to_v5(preflight, 4)
        .map_err(|error| std::io::Error::other(format!("migration build: {error:?}")))?;
    let migration_duration = nanos(migration_started.elapsed());
    let migration = MigrationObservation {
        duration_nanoseconds: migration_duration,
        root_revision_exact: migrated.latest_revision == source_revision,
        retained_revisions: migrated.retained_revisions,
        source_database_bytes,
        target_database_bytes: migrated.target_database_bytes,
    };
    if !migration.root_revision_exact {
        return Err(std::io::Error::other("migration revision mismatch").into());
    }

    let wrapping = provider.create(CreateKeyRequest {
        tenant: tenant.as_str().to_owned(),
        purpose: KeyPurpose::BlobEncryption,
        algorithm: KeyAlgorithm::XChaCha20Poly1305,
        created_at: 5,
        activated_at: 5,
    })?;
    let local = LocalBlobStore::open(arguments.root.join("v5-blobs"), Arc::clone(&provider))
        .map_err(|error| std::io::Error::other(format!("blob store: {error:?}")))?;
    let blobs: Arc<dyn RepositoryBlobStore> =
        Arc::new(LocalRepositoryBlobStore::new(local, wrapping.key_ref, 5));
    let revision_before = migrated.latest_revision.0;
    let physical_before_bytes = physical_bytes(&target)?;
    let store = SqliteV5Store::open_with_blob_repository_and_capacity_profile(
        &target,
        Arc::clone(&blobs),
        SqliteCapacityProfile::Standard,
    )
    .map_err(|error| std::io::Error::other(format!("v5 open: {error:?}")))?;
    let mutation_latencies_nanoseconds = mutate(&store, &mut states, arguments.mutations, 0)
        .map_err(|error| std::io::Error::other(format!("v5 workload: {error:?}")))?;
    let revision_after = store.revision()?.0;
    drop(store);
    let physical_after_bytes = physical_bytes(&target)?;
    let (process_cold_startup_nanoseconds, process_cold_startup_stages_nanoseconds) =
        v5_startups(
            &target,
            blobs,
            &mut states,
            revision_after,
            arguments.mutations,
        )?;
    Ok(DriverResult {
        schema_version: "cigar.honey-092-system-comparison-driver.v1",
        format: "sqlite-v5-incremental",
        initial_records: arguments.initial_records,
        mutations: arguments.mutations,
        revision_before,
        revision_after,
        physical_before_bytes,
        physical_after_bytes,
        physical_growth_bytes: physical_after_bytes.saturating_sub(physical_before_bytes),
        mutation_latencies_nanoseconds,
        process_cold_startup_nanoseconds,
        process_cold_startup_stages_nanoseconds,
        migration: Some(migration),
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments().map_err(std::io::Error::other)?;
    prepare_new_root(&arguments.root)?;
    let result = match arguments.format {
        Format::V4 => run_v4(&arguments)?,
        #[cfg(feature = "v5")]
        Format::V5 => run_v5(&arguments)?,
    };
    if result.revision_after != result.revision_before.saturating_add(result.mutations) {
        return Err(std::io::Error::other("workload revision count mismatch").into());
    }
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("honey 0.9.2 system comparison driver failed: {error:?}");
        std::process::exit(2);
    }
}
