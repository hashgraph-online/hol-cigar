//! Content-free v4/v5 storage-efficiency workload driver.

use cigar_protocol::RecordId;
use cigar_store::{
    CancellationToken, RepositoryCommitMetrics, RepositoryCommitMetricsObserver,
    RepositoryStartupMetrics, RepositoryStartupMetricsObserver, ServiceExpectedVersion,
    ServiceRepository, SqliteStore, WorkerLocator, WorkerState, WorkerUpdate,
};
use serde::Serialize;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const TENANT_ID: &str = "01890f47-8e7d-7b42-a1d2-3c4d5e6f78f1";

#[derive(Default)]
struct Observer {
    commits: Mutex<Vec<RepositoryCommitMetrics>>,
    startup: Mutex<Vec<RepositoryStartupMetrics>>,
}

impl RepositoryCommitMetricsObserver for Observer {
    fn observe_repository_commit(&self, metrics: RepositoryCommitMetrics) {
        if let Ok(mut commits) = self.commits.lock() {
            commits.push(metrics);
        }
    }
}

impl RepositoryStartupMetricsObserver for Observer {
    fn observe_repository_startup(&self, metrics: RepositoryStartupMetrics) {
        if let Ok(mut startup) = self.startup.lock() {
            startup.push(metrics);
        }
    }
}

#[derive(Serialize)]
struct DurationObservation {
    total: u64,
    lock_wait: u64,
    repository_load: u64,
    residual_decode: u64,
    staged_mutation: u64,
    delta_encode: u64,
    full_encode: u64,
    catalog_root: u64,
    sqlite_transaction: u64,
    commit_fsync: u64,
    revision_anchor: u64,
}

#[derive(Serialize)]
struct ByteObservation {
    logical_changed: u64,
    encoded_delta: u64,
    checkpoint: u64,
    full_state: u64,
    database_before: Option<u64>,
    database_after: Option<u64>,
    wal_before: Option<u64>,
    wal_after: Option<u64>,
    durable_added: Option<u64>,
    write_amplification_millionths: Option<u64>,
}

#[derive(Serialize)]
struct CommitObservation {
    iteration: u64,
    operation: u64,
    kind: &'static str,
    outcome: &'static str,
    revision_before: u64,
    revision_after: u64,
    receipt_only: bool,
    durations_nanoseconds: DurationObservation,
    bytes: ByteObservation,
    retained_full_states: Option<u64>,
    retained_checkpoints: Option<u64>,
    retained_deltas: Option<u64>,
}

#[derive(Serialize)]
struct StartupObservation {
    stage: &'static str,
    outcome: &'static str,
    duration_nanoseconds: u64,
}

#[derive(Serialize)]
struct StorageObservation {
    revision: u64,
    retained_snapshots: u64,
    latest_snapshot_bytes: u64,
    database_bytes: u64,
    wal_bytes: u64,
}

#[derive(Serialize)]
struct DriverResult {
    schema_version: &'static str,
    persistence_format: &'static str,
    initial_records: u64,
    iterations: u64,
    mutations_per_iteration: u64,
    startup: Vec<StartupObservation>,
    storage_before: StorageObservation,
    storage_after: StorageObservation,
    commits: Vec<CommitObservation>,
}

struct Arguments {
    database: PathBuf,
    initial_records: u64,
    iterations: u64,
    mutations_per_iteration: u64,
}

fn parse_u64(value: Option<String>) -> Result<u64, &'static str> {
    value
        .ok_or("missing value")?
        .parse::<u64>()
        .map_err(|_error| "invalid integer")
}

fn arguments() -> Result<Arguments, &'static str> {
    let mut values = env::args().skip(1);
    let mut database = None;
    let mut initial_records = None;
    let mut iterations = None;
    let mut mutations = None;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--database" => database = values.next().map(PathBuf::from),
            "--initial-records" => initial_records = Some(parse_u64(values.next())?),
            "--iterations" => iterations = Some(parse_u64(values.next())?),
            "--mutations-per-iteration" => mutations = Some(parse_u64(values.next())?),
            _ => return Err("unknown argument"),
        }
    }
    let result = Arguments {
        database: database.ok_or("database missing")?,
        initial_records: initial_records.ok_or("initial records missing")?,
        iterations: iterations.ok_or("iterations missing")?,
        mutations_per_iteration: mutations.ok_or("mutations missing")?,
    };
    if result.initial_records == 0
        || result.iterations == 0
        || result.mutations_per_iteration == 0
        || result.mutations_per_iteration > result.initial_records
        || result.initial_records > 100_000
        || result.iterations > 100_000
        || result.mutations_per_iteration > 64
    {
        return Err("arguments exceed workload bounds");
    }
    Ok(result)
}

fn nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn storage(
    store: &SqliteStore,
    database: &std::path::Path,
) -> Result<StorageObservation, Box<dyn std::error::Error>> {
    let value = store.storage_statistics()?;
    let mut wal_name = database.as_os_str().to_os_string();
    wal_name.push("-wal");
    let wal_bytes = std::fs::metadata(PathBuf::from(wal_name))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    Ok(StorageObservation {
        revision: store.revision()?.0,
        retained_snapshots: value.retained_snapshots,
        latest_snapshot_bytes: value.latest_snapshot_bytes,
        database_bytes: value.database_bytes,
        wal_bytes,
    })
}

fn locator(tenant: &RecordId, index: u64) -> Result<WorkerLocator, Box<dyn std::error::Error>> {
    Ok(WorkerLocator::new(
        tenant.clone(),
        format!("honey-efficiency-{index:06}"),
    )?)
}

fn claim(
    store: &SqliteStore,
    locator: &WorkerLocator,
    now: u64,
) -> Result<WorkerState, Box<dyn std::error::Error>> {
    Ok(store.worker_update(
        locator,
        WorkerUpdate::Claim {
            expected: ServiceExpectedVersion::Absent,
            owner: "efficiency-driver".to_owned(),
            now_unix_nanos: now,
            expires_at_unix_nanos: u64::MAX,
        },
        &CancellationToken::default(),
    )?)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments().map_err(std::io::Error::other)?;
    let observer = Arc::new(Observer::default());
    let startup_observer: Arc<dyn RepositoryStartupMetricsObserver> = observer.clone();
    let commit_observer: Arc<dyn RepositoryCommitMetricsObserver> = observer.clone();
    let store = SqliteStore::open_with_startup_metrics(&arguments.database, startup_observer)?
        .with_commit_metrics_observer(commit_observer);
    let tenant = RecordId::new(TENANT_ID)?;
    let mut states = Vec::new();
    for index in 0..arguments.initial_records {
        let worker = locator(&tenant, index)?;
        let state = claim(&store, &worker, index.saturating_add(1))?;
        states.push((worker, state));
    }
    if let Ok(mut commits) = observer.commits.lock() {
        commits.clear();
    }
    let storage_before = storage(&store, &arguments.database)?;
    for iteration in 0..arguments.iterations {
        for operation in 0..arguments.mutations_per_iteration {
            let index = usize::try_from(operation)?;
            let (worker, state) = states
                .get_mut(index)
                .ok_or_else(|| std::io::Error::other("worker state missing"))?;
            *state = store.worker_update(
                worker,
                WorkerUpdate::Checkpoint {
                    expected: ServiceExpectedVersion::Version(state.version()),
                    owner: "efficiency-driver".to_owned(),
                    fencing_token: state.fencing_token(),
                    cursor: iteration.to_be_bytes().to_vec(),
                    heartbeat_unix_nanos: iteration.saturating_add(1_000_000),
                    expires_at_unix_nanos: u64::MAX,
                },
                &CancellationToken::default(),
            )?;
        }
    }
    let storage_after = storage(&store, &arguments.database)?;
    let commits = observer
        .commits
        .lock()
        .map_err(|_| std::io::Error::other("commit observer unavailable"))?
        .clone();
    let expected = arguments
        .iterations
        .checked_mul(arguments.mutations_per_iteration)
        .ok_or_else(|| std::io::Error::other("operation count overflow"))?;
    if u64::try_from(commits.len())? != expected {
        return Err(std::io::Error::other("commit observation count mismatch").into());
    }
    let observations = commits
        .into_iter()
        .enumerate()
        .map(|(index, metric)| {
            let index = u64::try_from(index).unwrap_or(u64::MAX);
            CommitObservation {
                iteration: index / arguments.mutations_per_iteration,
                operation: index % arguments.mutations_per_iteration,
                kind: metric.kind.as_str(),
                outcome: metric.outcome.as_str(),
                revision_before: metric.revision_before.0,
                revision_after: metric.revision_after.0,
                receipt_only: metric.receipt_only,
                durations_nanoseconds: DurationObservation {
                    total: nanos(metric.durations.total),
                    lock_wait: nanos(metric.durations.lock_wait),
                    repository_load: nanos(metric.durations.repository_load),
                    residual_decode: nanos(metric.durations.residual_decode),
                    staged_mutation: nanos(metric.durations.staged_mutation),
                    delta_encode: nanos(metric.durations.delta_encode),
                    full_encode: nanos(metric.durations.full_encode),
                    catalog_root: nanos(metric.durations.catalog_root),
                    sqlite_transaction: nanos(metric.durations.sqlite_transaction),
                    commit_fsync: nanos(metric.durations.commit_fsync),
                    revision_anchor: nanos(metric.durations.revision_anchor),
                },
                bytes: ByteObservation {
                    logical_changed: metric.bytes.logical_changed,
                    encoded_delta: metric.bytes.encoded_delta,
                    checkpoint: metric.bytes.checkpoint,
                    full_state: metric.bytes.full_state,
                    database_before: metric.bytes.database_before,
                    database_after: metric.bytes.database_after,
                    wal_before: metric.bytes.wal_before,
                    wal_after: metric.bytes.wal_after,
                    durable_added: metric.bytes.durable_bytes_added(),
                    write_amplification_millionths: metric.bytes.write_amplification_millionths(),
                },
                retained_full_states: metric.retained.full_states,
                retained_checkpoints: metric.retained.checkpoints,
                retained_deltas: metric.retained.deltas,
            }
        })
        .collect();
    let startup = observer
        .startup
        .lock()
        .map_err(|_| std::io::Error::other("startup observer unavailable"))?
        .iter()
        .map(|metric| StartupObservation {
            stage: metric.stage.as_str(),
            outcome: metric.outcome.as_str(),
            duration_nanoseconds: nanos(metric.duration),
        })
        .collect();
    let result = DriverResult {
        schema_version: "cigar.honey-efficiency-driver-result.v1",
        persistence_format: "sqlite-v4-full-residual",
        initial_records: arguments.initial_records,
        iterations: arguments.iterations,
        mutations_per_iteration: arguments.mutations_per_iteration,
        startup,
        storage_before,
        storage_after,
        commits: observations,
    };
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("honey efficiency driver failed");
        std::process::exit(2);
    }
}
