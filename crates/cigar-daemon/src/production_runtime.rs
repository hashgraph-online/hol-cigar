//! Repository-backed startup, readiness, worker supervision, and shutdown composition.

use crate::{
    BlockingPool, DaemonConfig, DaemonDependencies, DaemonTelemetry, DaemonWorkers, LifecycleError,
    LifecycleFuture, ProductionFacade, ReadinessGate, RuntimeClock, ShutdownHookFuture,
    ShutdownHooks, StartupAction, StartupCoordinator, StartupStep, WorkerJob, WorkerKind,
    WorkerReceivers, WorkerRuntime,
};
use cigar_api::CancellationToken as ApiCancellation;
use cigar_api::{ProbeObservation, ReadinessAggregator, ReadinessComponent, ReadinessProbe};
use cigar_protocol::{ErrorCode, RecordId};
use cigar_store::{
    CancellationToken as StoreCancellation, EffectRecoveryQuery, ServiceExpectedVersion,
    ServiceListQuery, ServiceListScope, ServiceRepository, WorkerLocator, WorkerState,
    WorkerUpdate,
};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

const HEALTH_NAMESPACE: &str = "daemon.health";
const WORKER_OWNER: &str = "cigard-runtime";
const WORKER_LEASE_NANOS: u64 = 60_000_000_000;
const MAX_WORKER_HEARTBEAT_AGE_NANOS: u64 = 30_000_000_000;
// Persist one worker heartbeat per tick instead of bursting every worker through the single
// SQLite writer. Nine worker kinds therefore complete a durable refresh cycle in 18 seconds,
// inside the 30-second health bound and three times inside the 60-second lease.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Stable failure while constructing concrete production dependencies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionRuntimeError {
    /// One mandatory component was missing or malformed.
    InvalidConfiguration,
    /// Construction requires an active Tokio runtime for supervised workers.
    RuntimeUnavailable,
}

impl fmt::Display for ProductionRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "production runtime configuration is incomplete",
            Self::RuntimeUnavailable => "production runtime requires an async executor",
        })
    }
}

impl std::error::Error for ProductionRuntimeError {}

/// Concrete subsystem checks called by startup, readiness, and supervised workers.
///
/// Implementations bind the daemon to the active migration manager, blob repository, policy
/// engine, journal recovery engine, mandatory index, and key provider. The daemon never replaces
/// an unavailable subsystem with a healthy default.
pub trait ProductionDependencyChecks: Send + Sync {
    /// Verifies that the installed migration level is exactly service-compatible.
    fn migration_level(&self) -> Result<(), LifecycleError>;
    /// Performs a bounded authenticated blob write/read/delete probe.
    fn blob_read_write(&self) -> Result<(), LifecycleError>;
    /// Resolves and validates the active immutable policy snapshot.
    fn policy_snapshot(&self) -> Result<(), LifecycleError>;
    /// Verifies the complete effect journal and legal transition projection.
    fn journal_integrity(&self) -> Result<(), LifecycleError>;
    /// Verifies mandatory index availability and its configured lag bound.
    fn mandatory_index(&self) -> Result<(), LifecycleError>;
    /// Resolves the active key provider without exporting key bytes.
    fn key_provider(&self) -> Result<(), LifecycleError>;
    /// Reconciles metadata roots with temporary and final blob objects.
    fn reconcile_orphan_blobs(&self) -> Result<(), LifecycleError>;
    /// Expires domain/effect/space renewable leases after their exact fence and time checks.
    fn cleanup_expired_leases(&self) -> Result<(), LifecycleError>;
    /// Verifies all durable worker and event cursors are authentic, scoped, and in range.
    fn verify_worker_cursors(&self) -> Result<(), LifecycleError>;
    /// Classifies dispatches lacking durable receipts without blindly retrying them.
    fn recover_unreceipted_dispatches(&self) -> Result<(), LifecycleError>;
    /// Persists domain worker cursors beyond the daemon wakeup cursors.
    fn checkpoint_workers(&self) -> Result<(), LifecycleError>;
    /// Releases domain renewable leases without changing effect truth.
    fn release_renewable_leases(&self) -> Result<(), LifecycleError>;
    /// Processes one durable wakeup. Failure closes readiness; the durable record remains truth.
    fn process_worker_job(&self, kind: WorkerKind, job: &WorkerJob) -> Result<(), LifecycleError>;
    /// Processes at most one item discovered from durable truth rather than an in-memory wakeup.
    ///
    /// Returns true only when one durable item completed or advanced. Implementations must bound
    /// every scan and fail closed on poison work rather than reporting progress or hot-looping.
    fn poll_durable_work(&self) -> Result<bool, LifecycleError>;
}

/// Injectable wall clock used only for leases and health observations, never semantic digests.
pub trait ProductionUnixClock: Send + Sync {
    /// Returns a positive Unix nanosecond observation.
    fn now_unix_nanos(&self) -> Result<u64, LifecycleError>;
}

/// System wall clock for production lease and heartbeat observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProductionUnixClock;

impl ProductionUnixClock for SystemProductionUnixClock {
    fn now_unix_nanos(&self) -> Result<u64, LifecycleError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| LifecycleError::action_failed())?;
        u64::try_from(elapsed.as_nanos()).map_err(|_error| LifecycleError::action_failed())
    }
}

struct RepositoryOperationalState {
    repository: Arc<dyn ServiceRepository>,
    system_tenant: RecordId,
    checks: Arc<dyn ProductionDependencyChecks>,
    workers: Arc<DaemonWorkers>,
    blocking_pool: Arc<BlockingPool>,
    clock: Arc<dyn ProductionUnixClock>,
    telemetry: Arc<DaemonTelemetry>,
    heartbeat_cursor: Mutex<usize>,
}

fn next_heartbeat_worker(cursor: &Mutex<usize>) -> Result<WorkerKind, LifecycleError> {
    let mut next = cursor
        .lock()
        .map_err(|_error| LifecycleError::action_failed())?;
    let kind = WorkerKind::ALL
        .get(*next)
        .copied()
        .ok_or_else(LifecycleError::action_failed)?;
    *next = (*next + 1) % WorkerKind::ALL.len();
    Ok(kind)
}

impl RepositoryOperationalState {
    fn observe_runtime(&self) -> Result<(), LifecycleError> {
        let queues = self
            .workers
            .runtime()
            .metrics()
            .map_err(|_error| LifecycleError::action_failed())?;
        self.telemetry
            .observe_runtime(&queues, self.blocking_pool.metrics());
        Ok(())
    }

    fn metadata_store(&self) -> Result<(), LifecycleError> {
        let scope = ServiceListScope::new(self.system_tenant.clone(), HEALTH_NAMESPACE, None)
            .map_err(|_error| LifecycleError::action_failed())?;
        self.repository
            .service_list(
                &ServiceListQuery::new(scope, 1, None)
                    .map_err(|_error| LifecycleError::action_failed())?,
                &StoreCancellation::default(),
            )
            .map(|_page| ())
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn journal_records(&self) -> Result<(), LifecycleError> {
        let mut cursor = None;
        loop {
            let query = EffectRecoveryQuery::new(self.system_tenant.clone(), 1_000, cursor)
                .map_err(|_error| LifecycleError::action_failed())?;
            let page = self
                .repository
                .effect_recovery(&query, &StoreCancellation::default())
                .map_err(|_error| LifecycleError::action_failed())?;
            cursor = page.next;
            if cursor.is_none() {
                return Ok(());
            }
        }
    }

    fn locator(&self, kind: WorkerKind) -> Result<WorkerLocator, LifecycleError> {
        WorkerLocator::new(
            self.system_tenant.clone(),
            format!("daemon.{}", kind.as_str()),
        )
        .map_err(|_error| LifecycleError::action_failed())
    }

    fn worker_state(&self, kind: WorkerKind) -> Result<Option<WorkerState>, LifecycleError> {
        self.repository
            .worker_get(&self.locator(kind)?, &StoreCancellation::default())
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn lease_expiry(now: u64) -> Result<u64, LifecycleError> {
        now.checked_add(WORKER_LEASE_NANOS)
            .ok_or_else(LifecycleError::action_failed)
    }

    fn cleanup_expired_leases(&self) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        for kind in WorkerKind::ALL {
            let Some(state) = self.worker_state(kind)? else {
                continue;
            };
            let Some(owner) = state.lease_owner() else {
                continue;
            };
            if state
                .lease_expires_at_unix_nanos()
                .is_some_and(|expiry| expiry <= now)
            {
                let locator = self.locator(kind)?;
                self.repository
                    .worker_update(
                        &locator,
                        WorkerUpdate::Release {
                            expected: ServiceExpectedVersion::Version(state.version()),
                            owner: owner.to_owned(),
                            fencing_token: state.fencing_token(),
                            heartbeat_unix_nanos: now.max(state.heartbeat_unix_nanos()),
                        },
                        &StoreCancellation::default(),
                    )
                    .map_err(|_error| LifecycleError::action_failed())?;
                self.telemetry.observe_worker_lease(kind, 0);
            }
        }
        Ok(())
    }

    fn ensure_worker_leases(&self) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        let expiry = Self::lease_expiry(now)?;
        for kind in WorkerKind::ALL {
            let locator = self.locator(kind)?;
            let current = self
                .repository
                .worker_get(&locator, &StoreCancellation::default())
                .map_err(|_error| LifecycleError::action_failed())?;
            match current {
                Some(state)
                    if state.lease_owner() == Some(WORKER_OWNER)
                        && state
                            .lease_expires_at_unix_nanos()
                            .is_some_and(|value| value > now) =>
                {
                    self.checkpoint_state(&locator, &state, state.cursor().to_vec(), now, expiry)?;
                }
                Some(state)
                    if state.lease_owner().is_none()
                        || state
                            .lease_expires_at_unix_nanos()
                            .is_some_and(|value| value <= now) =>
                {
                    self.repository
                        .worker_update(
                            &locator,
                            WorkerUpdate::Claim {
                                expected: ServiceExpectedVersion::Version(state.version()),
                                owner: WORKER_OWNER.to_owned(),
                                now_unix_nanos: now.max(state.heartbeat_unix_nanos()),
                                expires_at_unix_nanos: expiry
                                    .max(state.heartbeat_unix_nanos().saturating_add(1)),
                            },
                            &StoreCancellation::default(),
                        )
                        .map_err(|_error| LifecycleError::action_failed())?;
                }
                Some(_live_other_owner) => return Err(LifecycleError::action_failed()),
                None => {
                    self.repository
                        .worker_update(
                            &locator,
                            WorkerUpdate::Claim {
                                expected: ServiceExpectedVersion::Absent,
                                owner: WORKER_OWNER.to_owned(),
                                now_unix_nanos: now,
                                expires_at_unix_nanos: expiry,
                            },
                            &StoreCancellation::default(),
                        )
                        .map_err(|_error| LifecycleError::action_failed())?;
                }
            }
            self.telemetry
                .observe_worker_lease(kind, expiry.saturating_sub(now) / 1_000_000_000);
        }
        Ok(())
    }

    fn checkpoint_state(
        &self,
        locator: &WorkerLocator,
        state: &WorkerState,
        cursor: Vec<u8>,
        now: u64,
        expiry: u64,
    ) -> Result<(), LifecycleError> {
        self.repository
            .worker_update(
                locator,
                WorkerUpdate::Checkpoint {
                    expected: ServiceExpectedVersion::Version(state.version()),
                    owner: WORKER_OWNER.to_owned(),
                    fencing_token: state.fencing_token(),
                    cursor,
                    heartbeat_unix_nanos: now.max(state.heartbeat_unix_nanos()),
                    expires_at_unix_nanos: expiry
                        .max(state.heartbeat_unix_nanos().saturating_add(1)),
                },
                &StoreCancellation::default(),
            )
            .map(|_state| ())
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn checkpoint_all(&self) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        let expiry = Self::lease_expiry(now)?;
        for kind in WorkerKind::ALL {
            let locator = self.locator(kind)?;
            let state = self
                .repository
                .worker_get(&locator, &StoreCancellation::default())
                .map_err(|_error| LifecycleError::action_failed())?
                .ok_or_else(LifecycleError::action_failed)?;
            if state.lease_owner() != Some(WORKER_OWNER) {
                return Err(LifecycleError::action_failed());
            }
            self.checkpoint_state(&locator, &state, state.cursor().to_vec(), now, expiry)?;
            self.telemetry
                .observe_worker_lease(kind, expiry.saturating_sub(now) / 1_000_000_000);
        }
        self.observe_runtime()
    }

    fn checkpoint_heartbeat_slice(&self) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        let expiry = Self::lease_expiry(now)?;
        let kind = next_heartbeat_worker(&self.heartbeat_cursor)?;
        let locator = self.locator(kind)?;
        let state = self
            .repository
            .worker_get(&locator, &StoreCancellation::default())
            .map_err(|_error| LifecycleError::action_failed())?
            .ok_or_else(LifecycleError::action_failed)?;
        if state.lease_owner() != Some(WORKER_OWNER) {
            return Err(LifecycleError::action_failed());
        }
        self.checkpoint_state(&locator, &state, state.cursor().to_vec(), now, expiry)?;
        self.telemetry
            .observe_worker_lease(kind, expiry.saturating_sub(now) / 1_000_000_000);
        self.observe_runtime()
    }

    fn checkpoint_job(&self, kind: WorkerKind, job: &WorkerJob) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        let expiry = Self::lease_expiry(now)?;
        let locator = self.locator(kind)?;
        let state = self
            .repository
            .worker_get(&locator, &StoreCancellation::default())
            .map_err(|_error| LifecycleError::action_failed())?
            .ok_or_else(LifecycleError::action_failed)?;
        if state.lease_owner() != Some(WORKER_OWNER) {
            return Err(LifecycleError::action_failed());
        }
        self.checkpoint_state(
            &locator,
            &state,
            job.record_id.as_str().as_bytes().to_vec(),
            now,
            expiry,
        )?;
        self.telemetry
            .observe_worker_lease(kind, expiry.saturating_sub(now) / 1_000_000_000);
        self.observe_runtime()
    }

    fn release_all(&self) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        for kind in WorkerKind::ALL {
            let locator = self.locator(kind)?;
            let Some(state) = self
                .repository
                .worker_get(&locator, &StoreCancellation::default())
                .map_err(|_error| LifecycleError::action_failed())?
            else {
                continue;
            };
            if state.lease_owner() == Some(WORKER_OWNER) {
                self.repository
                    .worker_update(
                        &locator,
                        WorkerUpdate::Release {
                            expected: ServiceExpectedVersion::Version(state.version()),
                            owner: WORKER_OWNER.to_owned(),
                            fencing_token: state.fencing_token(),
                            heartbeat_unix_nanos: now.max(state.heartbeat_unix_nanos()),
                        },
                        &StoreCancellation::default(),
                    )
                    .map_err(|_error| LifecycleError::action_failed())?;
                self.telemetry.observe_worker_lease(kind, 0);
            }
        }
        Ok(())
    }

    fn workers_healthy(&self) -> Result<(), LifecycleError> {
        let now = self.clock.now_unix_nanos()?;
        let metrics = self
            .workers
            .runtime()
            .metrics()
            .map_err(|_error| LifecycleError::action_failed())?;
        if metrics.len() != WorkerKind::ALL.len() || metrics.iter().any(|metric| !metric.accepting)
        {
            return Err(LifecycleError::action_failed());
        }
        for kind in WorkerKind::ALL {
            let state = self
                .worker_state(kind)?
                .ok_or_else(LifecycleError::action_failed)?;
            let fresh = state.heartbeat_unix_nanos() <= now
                && now.saturating_sub(state.heartbeat_unix_nanos())
                    <= MAX_WORKER_HEARTBEAT_AGE_NANOS;
            let live = state.lease_owner() == Some(WORKER_OWNER)
                && state
                    .lease_expires_at_unix_nanos()
                    .is_some_and(|expiry| expiry > now);
            self.telemetry.observe_worker_lease(
                kind,
                state
                    .lease_expires_at_unix_nanos()
                    .unwrap_or(now)
                    .saturating_sub(now)
                    / 1_000_000_000,
            );
            if !fresh || !live {
                return Err(LifecycleError::action_failed());
            }
        }
        Ok(())
    }

    fn run_startup_step(&self, step: StartupStep) -> Result<(), LifecycleError> {
        match step {
            StartupStep::Migrations => {
                self.metadata_store()?;
                self.checks.migration_level()
            }
            StartupStep::JournalIntegrity => {
                self.journal_records()?;
                self.checks.journal_integrity()
            }
            StartupStep::OrphanBlobReconciliation => self.checks.reconcile_orphan_blobs(),
            StartupStep::ExpiredLeaseCleanup => self
                .cleanup_expired_leases()
                .and_then(|()| self.checks.cleanup_expired_leases()),
            StartupStep::WorkerCursorVerification => self
                .checks
                .verify_worker_cursors()
                .and_then(|()| self.ensure_worker_leases()),
            StartupStep::UnreceiptedDispatchRecovery => {
                self.checks.recover_unreceipted_dispatches()
            }
        }
    }
}

struct RepositoryStartupAction {
    step: StartupStep,
    state: Arc<RepositoryOperationalState>,
}

impl StartupAction for RepositoryStartupAction {
    fn step(&self) -> StartupStep {
        self.step
    }

    fn execute(&self) -> LifecycleFuture<'_> {
        let state = Arc::clone(&self.state);
        let pool = Arc::clone(&self.state.blocking_pool);
        let step = self.step;
        Box::pin(async move {
            pool.run(
                ApiCancellation::new(),
                tokio::time::Instant::now() + Duration::from_secs(30),
                move |_cancellation| state.run_startup_step(step),
            )
            .await
            .map_err(|_error| LifecycleError::action_failed())?
        })
    }
}

struct RepositoryReadinessProbe {
    component: ReadinessComponent,
    state: Arc<RepositoryOperationalState>,
}

impl ReadinessProbe for RepositoryReadinessProbe {
    fn component(&self) -> ReadinessComponent {
        self.component
    }

    fn check(&self) -> ProbeObservation {
        let result = match self.component {
            ReadinessComponent::MetadataStore => self.state.metadata_store(),
            ReadinessComponent::MigrationLevel => self.state.checks.migration_level(),
            ReadinessComponent::BlobReadWrite => self.state.checks.blob_read_write(),
            ReadinessComponent::PolicySnapshot => self.state.checks.policy_snapshot(),
            ReadinessComponent::JournalIntegrity => self
                .state
                .journal_records()
                .and_then(|()| self.state.checks.journal_integrity()),
            ReadinessComponent::MandatoryIndex => self.state.checks.mandatory_index(),
            ReadinessComponent::KeyProvider => self.state.checks.key_provider(),
            ReadinessComponent::WorkerHeartbeat => self.state.workers_healthy(),
        };
        if result.is_ok() {
            ProbeObservation::healthy()
        } else {
            ProbeObservation::unhealthy(ErrorCode::DependencyUnavailable)
        }
    }
}

struct RepositoryShutdownHooks {
    state: Arc<RepositoryOperationalState>,
    stop: Arc<AtomicBool>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl ShutdownHooks for RepositoryShutdownHooks {
    fn checkpoint_workers(&self) -> ShutdownHookFuture<'_> {
        Box::pin(async move {
            self.state.checkpoint_all()?;
            self.state.checks.checkpoint_workers()
        })
    }

    fn release_renewable_leases(&self) -> ShutdownHookFuture<'_> {
        Box::pin(async move {
            self.stop.store(true, Ordering::Release);
            let supervisor = self
                .supervisor
                .lock()
                .map_err(|_error| LifecycleError::action_failed())?
                .take();
            if let Some(supervisor) = supervisor {
                supervisor
                    .await
                    .map_err(|_error| LifecycleError::action_failed())?;
            }
            self.state.release_all()?;
            self.state.checks.release_renewable_leases()
        })
    }
}

fn spawn_worker_supervisor(
    mut receivers: WorkerReceivers,
    state: Arc<RepositoryOperationalState>,
    readiness: Arc<ReadinessGate>,
    stop: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, ProductionRuntimeError> {
    tokio::runtime::Handle::try_current()
        .map_err(|_error| ProductionRuntimeError::RuntimeUnavailable)?;
    Ok(tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut startup_completed = false;
        loop {
            if stop.load(Ordering::Acquire) {
                return;
            }
            if !state.workers.dispatch_claims_allowed() {
                match state.workers.runtime().metrics() {
                    Ok(metrics) if metrics.iter().all(|metric| !metric.accepting) => {
                        // Shutdown has closed every in-memory wakeup sender. Dropping the
                        // receivers below drains only latency hints; durable records remain the
                        // authoritative restart input. This also prevents a new blocking-pool
                        // admission from racing the later worker checkpoint.
                        return;
                    }
                    Ok(_still_accepting) => {}
                    Err(_error) => {
                        readiness.close();
                        return;
                    }
                }
            }
            if !startup_completed {
                startup_completed = readiness.is_open();
            }
            if !startup_completed {
                tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                continue;
            }
            match receivers.try_recv_any() {
                Ok(Some((kind, job))) => {
                    if matches!(kind, WorkerKind::Outbox | WorkerKind::Reconciliation)
                        && !state.workers.dispatch_claims_allowed()
                    {
                        continue;
                    }
                    let job_state = Arc::clone(&state);
                    let workers = Arc::clone(&state.workers);
                    let pool = Arc::clone(&state.blocking_pool);
                    let result = pool
                        .run(
                            ApiCancellation::new(),
                            tokio::time::Instant::now() + Duration::from_secs(30),
                            move |_cancellation| {
                                job_state.checks.process_worker_job(kind, &job)?;
                                job_state.checkpoint_job(kind, &job)
                            },
                        )
                        .await;
                    if !matches!(result, Ok(Ok(()))) {
                        workers.stop_dispatch_claims();
                        workers.runtime().stop_accepting();
                        readiness.close();
                        return;
                    }
                }
                Ok(None) => {
                    let poll_state = Arc::clone(&state);
                    let pool = Arc::clone(&state.blocking_pool);
                    let poll_result = pool
                        .run(
                            ApiCancellation::new(),
                            tokio::time::Instant::now() + Duration::from_secs(30),
                            move |_cancellation| poll_state.checks.poll_durable_work(),
                        )
                        .await;
                    match poll_result {
                        Ok(Ok(true)) => continue,
                        Ok(Ok(false)) => {}
                        Ok(Err(_error)) => {
                            state.workers.stop_dispatch_claims();
                            state.workers.runtime().stop_accepting();
                            readiness.close();
                            return;
                        }
                        Err(_error) => {
                            state.workers.stop_dispatch_claims();
                            state.workers.runtime().stop_accepting();
                            readiness.close();
                            return;
                        }
                    }
                    tokio::select! {
                        _ = heartbeat.tick() => {
                            let heartbeat_state = Arc::clone(&state);
                            let pool = Arc::clone(&state.blocking_pool);
                            let result = pool.run(
                                ApiCancellation::new(),
                                tokio::time::Instant::now() + Duration::from_secs(30),
                                move |_cancellation| heartbeat_state.checkpoint_heartbeat_slice(),
                            ).await;
                            if !matches!(result, Ok(Ok(()))) {
                                state.workers.stop_dispatch_claims();
                                state.workers.runtime().stop_accepting();
                                readiness.close();
                                return;
                            }
                        }
                        () = tokio::time::sleep(IDLE_POLL_INTERVAL) => {}
                    }
                }
                Err(_error) => {
                    state.workers.stop_dispatch_claims();
                    state.workers.runtime().stop_accepting();
                    readiness.close();
                    return;
                }
            }
        }
    }))
}

/// Runtime-owned dependencies made available while constructing the complete typed facade.
///
/// The startup coordinator and worker supervisor remain private until facade construction
/// succeeds, preventing a partially composed service from opening readiness or leaking tasks.
#[derive(Clone)]
pub struct RepositoryFacadeInputs {
    /// Complete structured dependency readiness probes.
    pub readiness: Arc<ReadinessAggregator>,
    /// Startup/shutdown admission gate shared with handlers.
    pub readiness_gate: Arc<ReadinessGate>,
    /// Bounded workers and effect-dispatch gate.
    pub workers: Arc<DaemonWorkers>,
    /// Admission- and execution-bounded blocking pool.
    pub blocking_pool: Arc<BlockingPool>,
    /// Content-safe process telemetry.
    pub telemetry: Arc<DaemonTelemetry>,
}

impl fmt::Debug for RepositoryFacadeInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryFacadeInputs")
            .field("readiness", &self.readiness)
            .field("readiness_gate", &self.readiness_gate)
            .field("workers", &self.workers)
            .field("blocking_pool", &self.blocking_pool)
            .field("telemetry", &self.telemetry)
            .finish()
    }
}

/// Builds the exact production lifecycle around a facade factory and durable store.
///
/// The factory resolves the otherwise cyclic dependency between typed operational/effect
/// handlers and the readiness, worker, blocking-pool, and telemetry state those handlers report.
#[allow(clippy::too_many_arguments)]
pub fn compose_repository_runtime_with_facade<F>(
    config: &DaemonConfig,
    repository: Arc<dyn ServiceRepository>,
    system_tenant: RecordId,
    checks: Arc<dyn ProductionDependencyChecks>,
    blocking_pool: Arc<BlockingPool>,
    queue_clock: Arc<dyn RuntimeClock>,
    unix_clock: Arc<dyn ProductionUnixClock>,
    telemetry: Arc<DaemonTelemetry>,
    facade_factory: F,
) -> Result<DaemonDependencies, ProductionRuntimeError>
where
    F: FnOnce(RepositoryFacadeInputs) -> Result<Arc<ProductionFacade>, ProductionRuntimeError>,
{
    let readiness_gate = Arc::new(ReadinessGate::default());
    let (runtime, receivers) = WorkerRuntime::new(&config.workers, queue_clock)
        .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?;
    let workers = Arc::new(DaemonWorkers::new(
        Arc::new(runtime),
        Arc::clone(&readiness_gate),
    ));
    let state = Arc::new(RepositoryOperationalState {
        repository,
        system_tenant,
        checks,
        workers: Arc::clone(&workers),
        blocking_pool: Arc::clone(&blocking_pool),
        clock: unix_clock,
        telemetry: Arc::clone(&telemetry),
        heartbeat_cursor: Mutex::new(0),
    });
    let startup_actions: Vec<Arc<dyn StartupAction>> = StartupStep::ALL
        .into_iter()
        .map(|step| {
            Arc::new(RepositoryStartupAction {
                step,
                state: Arc::clone(&state),
            }) as Arc<dyn StartupAction>
        })
        .collect();
    let startup_observer: Arc<dyn cigar_store::RepositoryStartupMetricsObserver> =
        telemetry.clone();
    let startup = StartupCoordinator::new_with_startup_metrics(
        startup_actions,
        Arc::clone(&readiness_gate),
        startup_observer,
    )
    .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?;
    let probes: Vec<Arc<dyn ReadinessProbe>> = [
        ReadinessComponent::MetadataStore,
        ReadinessComponent::MigrationLevel,
        ReadinessComponent::BlobReadWrite,
        ReadinessComponent::PolicySnapshot,
        ReadinessComponent::JournalIntegrity,
        ReadinessComponent::MandatoryIndex,
        ReadinessComponent::KeyProvider,
        ReadinessComponent::WorkerHeartbeat,
    ]
    .into_iter()
    .map(|component| {
        Arc::new(RepositoryReadinessProbe {
            component,
            state: Arc::clone(&state),
        }) as Arc<dyn ReadinessProbe>
    })
    .collect();
    let readiness = Arc::new(
        ReadinessAggregator::new(probes)
            .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?,
    );
    let facade = facade_factory(RepositoryFacadeInputs {
        readiness: Arc::clone(&readiness),
        readiness_gate: Arc::clone(&readiness_gate),
        workers: Arc::clone(&workers),
        blocking_pool: Arc::clone(&blocking_pool),
        telemetry: Arc::clone(&telemetry),
    })?;
    let stop = Arc::new(AtomicBool::new(false));
    let supervisor = spawn_worker_supervisor(
        receivers,
        Arc::clone(&state),
        Arc::clone(&readiness_gate),
        Arc::clone(&stop),
    )?;
    let hooks: Arc<dyn ShutdownHooks> = Arc::new(RepositoryShutdownHooks {
        state,
        stop,
        supervisor: Mutex::new(Some(supervisor)),
    });
    Ok(DaemonDependencies::production(
        facade,
        startup,
        readiness,
        readiness_gate,
        workers,
        blocking_pool,
        hooks,
        telemetry,
    ))
}

/// Builds the exact production lifecycle around an already complete governed facade and store.
#[allow(clippy::too_many_arguments)]
pub fn compose_repository_runtime(
    config: &DaemonConfig,
    facade: Arc<ProductionFacade>,
    repository: Arc<dyn ServiceRepository>,
    system_tenant: RecordId,
    checks: Arc<dyn ProductionDependencyChecks>,
    blocking_pool: Arc<BlockingPool>,
    queue_clock: Arc<dyn RuntimeClock>,
    unix_clock: Arc<dyn ProductionUnixClock>,
    telemetry: Arc<DaemonTelemetry>,
) -> Result<DaemonDependencies, ProductionRuntimeError> {
    compose_repository_runtime_with_facade(
        config,
        repository,
        system_tenant,
        checks,
        blocking_pool,
        queue_clock,
        unix_clock,
        telemetry,
        move |_inputs| Ok(facade),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        HEARTBEAT_INTERVAL, MAX_WORKER_HEARTBEAT_AGE_NANOS, ProductionDependencyChecks,
        ProductionUnixClock, SystemProductionUnixClock, WORKER_LEASE_NANOS,
        compose_repository_runtime, next_heartbeat_worker,
    };
    use crate::{
        BlockingPool, DaemonConfig, DaemonServer, DaemonTelemetry, DeploymentMode,
        DurableIdempotencyRepository, LifecycleError, LocalIdentity, ProductionFacade,
        QueueErrorCode, SystemRuntimeClock, WorkerCapacities, WorkerJob, WorkerKind,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use cigar_api::generated::{OPERATIONS, StreamKind};
    use cigar_api::{
        ApiError, CompleteServiceFacade, CompleteServiceFacadeBuilder, FacadeErrorFactory,
        FacadeEventStream, QuotaLimits, RequestContext, RequestEnvelope, ResponseEnvelope,
        ServiceFuture, StreamOperationHandler, TenantId, UnaryOperationHandler,
    };
    use cigar_protocol::{ErrorCode, RecordId};
    use cigar_store::{ServiceRepository, SqliteStore};
    use serde_json::json;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const SYSTEM_TENANT: &str = "01890f47-8e7d-7b42-a1d2-000000000001";
    const CORRELATION: &str = "01890f47-8e7d-7b42-a1d2-000000000002";

    #[test]
    fn durable_heartbeat_cadence_preserves_health_and_lease_headroom()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(2));
        let interval_nanos = u64::try_from(HEARTBEAT_INTERVAL.as_nanos())?;
        let cycle_nanos = interval_nanos.saturating_mul(WorkerKind::ALL.len() as u64);
        assert!(cycle_nanos <= MAX_WORKER_HEARTBEAT_AGE_NANOS);
        assert!(cycle_nanos.saturating_mul(3) <= WORKER_LEASE_NANOS);
        Ok(())
    }

    #[test]
    fn durable_heartbeat_round_robin_covers_every_worker_before_wrapping()
    -> Result<(), Box<dyn std::error::Error>> {
        let cursor = Mutex::new(0);
        let observed = (0..WorkerKind::ALL.len())
            .map(|_index| next_heartbeat_worker(&cursor))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(observed, WorkerKind::ALL);
        assert_eq!(next_heartbeat_worker(&cursor), Ok(WorkerKind::ALL[0]));
        Ok(())
    }

    struct Errors(RecordId);

    impl FacadeErrorFactory for Errors {
        fn public_error(&self, code: ErrorCode) -> ApiError {
            ApiError::new(code, self.0.clone())
        }
    }

    struct Unary {
        operation: &'static str,
        calls: Arc<AtomicUsize>,
        blocking_pool: Arc<BlockingPool>,
        correlation: RecordId,
    }

    impl UnaryOperationHandler for Unary {
        fn operation_id(&self) -> &'static str {
            self.operation
        }

        fn call<'a>(
            &'a self,
            _context: RequestContext,
            _request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
            let operation = self.operation;
            let calls = Arc::clone(&self.calls);
            let blocking_pool = Arc::clone(&self.blocking_pool);
            let correlation = self.correlation.clone();
            Box::pin(async move {
                let payload = blocking_pool
                    .run(
                        cigar_api::CancellationToken::new(),
                        tokio::time::Instant::now() + Duration::from_secs(1),
                        move |_cancellation| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            vec![0xa0]
                        },
                    )
                    .await
                    .map_err(|_error| ApiError::new(ErrorCode::RateLimited, correlation.clone()))?;
                ResponseEnvelope::new(operation, payload, None, None)
                    .map_err(|_error| ApiError::new(ErrorCode::Internal, correlation))
            })
        }
    }

    struct Events;

    impl StreamOperationHandler for Events {
        fn operation_id(&self) -> &'static str {
            "subscribeSpaceEvents"
        }

        fn subscribe<'a>(
            &'a self,
            _context: RequestContext,
            _request: RequestEnvelope,
        ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
            Box::pin(async {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                drop(sender);
                Ok(
                    Box::pin(tokio_stream::wrappers::ReceiverStream::new(receiver))
                        as FacadeEventStream,
                )
            })
        }
    }

    fn complete_facade(
        calls: Arc<AtomicUsize>,
        blocking_pool: Arc<BlockingPool>,
    ) -> Result<CompleteServiceFacade, Box<dyn Error>> {
        let mut builder =
            CompleteServiceFacadeBuilder::new(Arc::new(Errors(RecordId::new(CORRELATION)?)));
        for operation in OPERATIONS {
            match operation.stream_kind {
                StreamKind::Unary => {
                    builder.register_unary(Arc::new(Unary {
                        operation: operation.operation_id,
                        calls: Arc::clone(&calls),
                        blocking_pool: Arc::clone(&blocking_pool),
                        correlation: RecordId::new(CORRELATION)?,
                    }))?;
                }
                StreamKind::ServerStream => {
                    builder.register_stream(Arc::new(Events))?;
                }
            }
        }
        Ok(builder.build()?)
    }

    #[derive(Default)]
    struct Checks {
        healthy: AtomicBool,
        cursor_valid: AtomicBool,
        worker_poison: AtomicBool,
        block_compilation: AtomicBool,
        compilation_entered: AtomicBool,
        release_compilation: AtomicBool,
        processed: Mutex<Vec<WorkerKind>>,
        durable_polls: AtomicUsize,
        durable_progress_remaining: AtomicUsize,
        domain_cleanup: AtomicUsize,
        domain_checkpoint: AtomicUsize,
        domain_release: AtomicUsize,
    }

    impl Checks {
        fn new() -> Self {
            Self {
                healthy: AtomicBool::new(true),
                cursor_valid: AtomicBool::new(true),
                ..Self::default()
            }
        }

        fn check(&self) -> Result<(), LifecycleError> {
            if self.healthy.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(LifecycleError::action_failed())
            }
        }
    }

    impl ProductionDependencyChecks for Checks {
        fn migration_level(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn blob_read_write(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn policy_snapshot(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn journal_integrity(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn mandatory_index(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn key_provider(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn reconcile_orphan_blobs(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn cleanup_expired_leases(&self) -> Result<(), LifecycleError> {
            self.domain_cleanup.fetch_add(1, Ordering::SeqCst);
            self.check()
        }

        fn verify_worker_cursors(&self) -> Result<(), LifecycleError> {
            if self.cursor_valid.load(Ordering::Acquire) {
                self.check()
            } else {
                Err(LifecycleError::action_failed())
            }
        }

        fn recover_unreceipted_dispatches(&self) -> Result<(), LifecycleError> {
            self.check()
        }

        fn checkpoint_workers(&self) -> Result<(), LifecycleError> {
            self.domain_checkpoint.fetch_add(1, Ordering::SeqCst);
            self.check()
        }

        fn release_renewable_leases(&self) -> Result<(), LifecycleError> {
            self.domain_release.fetch_add(1, Ordering::SeqCst);
            self.check()
        }

        fn process_worker_job(
            &self,
            kind: WorkerKind,
            _job: &WorkerJob,
        ) -> Result<(), LifecycleError> {
            if kind == WorkerKind::Compilation && self.block_compilation.load(Ordering::Acquire) {
                self.compilation_entered.store(true, Ordering::Release);
                while !self.release_compilation.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }
            self.processed
                .lock()
                .map_err(|_error| LifecycleError::action_failed())?
                .push(kind);
            if self.worker_poison.load(Ordering::Acquire) {
                return Err(LifecycleError::action_failed());
            }
            self.check()
        }

        fn poll_durable_work(&self) -> Result<bool, LifecycleError> {
            self.check()?;
            self.durable_polls.fetch_add(1, Ordering::AcqRel);
            let mut remaining = self.durable_progress_remaining.load(Ordering::Acquire);
            loop {
                if remaining == 0 {
                    return Ok(false);
                }
                match self.durable_progress_remaining.compare_exchange_weak(
                    remaining,
                    remaining - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(true),
                    Err(observed) => remaining = observed,
                }
            }
        }
    }

    fn capacities() -> WorkerCapacities {
        WorkerCapacities {
            ingestion: 8,
            indexing: 8,
            invalidation: 8,
            compilation: 8,
            outbox: 8,
            reconciliation: 8,
            lease_cleanup: 8,
            backup: 2,
            garbage_collection: 4,
        }
    }

    fn config(root: &std::path::Path) -> Result<DaemonConfig, Box<dyn Error>> {
        let state = root.join("state");
        let runtime = root.join("runtime");
        std::fs::create_dir_all(&state)?;
        std::fs::create_dir_all(&runtime)?;
        let state = state.canonicalize()?;
        let runtime = runtime.canonicalize()?;
        Ok(DaemonConfig {
            mode: DeploymentMode::Local,
            intelligence_profile: crate::IntelligenceProfile::default(),
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
            state_directory: state.clone(),
            runtime_directory: runtime,
            unix_socket: None,
            windows_named_pipe: None,
            http_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            grpc_listen: None,
            local_token_file: Some(state.join("local.token")),
            tls: None,
            oidc: None,
            production: crate::ProductionPaths {
                project_directory: root.to_path_buf(),
                metadata_database: state.join("cigar.sqlite3"),
                active_store_descriptor: None,
                blob_directory: state.join("blobs"),
                blob_key_reference_directory: state.join("blob-keys"),
                keystore_file: state.join("keystore.cigar"),
                keystore_passphrase_file: root.join("keystore-passphrase"),
                cursor_signing_key_file: state.join("cursor.key"),
                effect_checkpoint_file: root.join("effect-checkpoints/checkpoints.json"),
                policy_profile_file: root.join("policy.json"),
                authority_file: root.join("authority.json"),
                source_registry_file: root.join("sources.json"),
                effect_registry_file: root.join("effects.json"),
            },
            local_vector: crate::LocalVectorSettings::default(),
            shared_storage: None,
            request_deadline_ms: 5_000,
            shutdown_deadline_ms: 5_000,
            max_request_bytes: 1024 * 1024,
            max_expansion_ratio: 8,
            workers: capacities(),
            resources: crate::ApplicationResourceLimits {
                global_request_concurrency: 64,
                per_tenant_request_concurrency: 16,
                blocking_active: 4,
                blocking_queued: 64,
                idempotency_wait_ms: 5_000,
            },
            telemetry: crate::TelemetrySettings {
                otlp_endpoint: None,
                otlp_ca_certificate_file: None,
                export_timeout_ms: 1_000,
                metric_interval_ms: 1_000,
            },
        })
    }

    struct Fixture {
        config: DaemonConfig,
        store: Arc<SqliteStore>,
        facade: Arc<ProductionFacade>,
        checks: Arc<Checks>,
        pool: Arc<BlockingPool>,
        calls: Arc<AtomicUsize>,
        dependencies: crate::DaemonDependencies,
    }

    fn fixture(root: &std::path::Path) -> Result<Fixture, Box<dyn Error>> {
        let config = config(root)?;
        let store = Arc::new(SqliteStore::open(config.state_directory.join("cigar.db"))?);
        let repository: Arc<dyn ServiceRepository> = store.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let pool = Arc::new(BlockingPool::new(4, 64)?);
        let idempotency = Arc::new(DurableIdempotencyRepository::new(
            Arc::clone(&repository),
            RecordId::new(SYSTEM_TENANT)?,
        ));
        let facade = Arc::new(ProductionFacade::new(
            complete_facade(Arc::clone(&calls), Arc::clone(&pool))?,
            idempotency,
            QuotaLimits::new(64, 64)?,
            Duration::from_secs(2),
        )?);
        let checks = Arc::new(Checks::new());
        let checks_object: Arc<dyn ProductionDependencyChecks> = checks.clone();
        let queue_clock: Arc<dyn crate::RuntimeClock> = Arc::new(SystemRuntimeClock::new());
        let unix_clock: Arc<dyn ProductionUnixClock> = Arc::new(SystemProductionUnixClock);
        let dependencies = compose_repository_runtime(
            &config,
            Arc::clone(&facade),
            repository,
            RecordId::new(SYSTEM_TENANT)?,
            checks_object,
            Arc::clone(&pool),
            queue_clock,
            unix_clock,
            Arc::new(DaemonTelemetry::local()),
        )?;
        Ok(Fixture {
            config,
            store,
            facade,
            checks,
            pool,
            calls,
            dependencies,
        })
    }

    fn worker_job() -> Result<WorkerJob, Box<dyn Error>> {
        Ok(WorkerJob {
            tenant: TenantId::new("tenant-a")?,
            record_id: RecordId::new("01890f47-8e7d-7b42-a1d2-000000000003")?,
            expected_revision: None,
        })
    }

    async fn raw_http(address: SocketAddr, request: String) -> Result<String, std::io::Error> {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        String::from_utf8(response).map_err(std::io::Error::other)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervised_workers_drain_on_shutdown_and_never_claim_outbox_after_gate()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let fixture = fixture(directory.path())?;
        fixture
            .checks
            .block_compilation
            .store(true, Ordering::Release);
        let workers = Arc::clone(&fixture.dependencies.workers);
        let readiness = Arc::clone(&fixture.dependencies.readiness_gate);
        let server = DaemonServer::local(
            fixture.config,
            fixture.dependencies,
            LocalIdentity::new("tenant-a", "principal-a")?,
        )?;
        let running = server.start().await?;
        workers.try_enqueue(WorkerKind::Compilation, worker_job()?)?;
        while !fixture.checks.compilation_entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        workers.try_enqueue(WorkerKind::Outbox, worker_job()?)?;
        let shutdown = tokio::spawn(async move { running.shutdown().await });
        while workers.dispatch_claims_allowed() {
            tokio::task::yield_now().await;
        }
        fixture
            .checks
            .release_compilation
            .store(true, Ordering::Release);
        let receipt = shutdown.await??;
        assert!(receipt.shutdown.failed.is_none());
        assert!(!readiness.is_open());
        let processed = fixture
            .checks
            .processed
            .lock()
            .map_err(|_error| "processed worker mutex poisoned")?
            .clone();
        assert_eq!(processed, vec![WorkerKind::Compilation]);
        assert_eq!(fixture.checks.domain_cleanup.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.checks.domain_checkpoint.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.checks.domain_release.load(Ordering::SeqCst), 1);
        assert!(fixture.pool.is_drained());
        assert!(!fixture.pool.metrics().accepting);
        assert!(fixture.pool.metrics().completion_count >= 7);
        assert!(fixture.store.integrity_check().is_ok());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn poison_worker_failure_closes_readiness_dispatch_and_every_queue()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let fixture = fixture(directory.path())?;
        let workers = Arc::clone(&fixture.dependencies.workers);
        let readiness = Arc::clone(&fixture.dependencies.readiness_gate);
        let server = DaemonServer::local(
            fixture.config,
            fixture.dependencies,
            LocalIdentity::new("tenant-a", "principal-a")?,
        )?;
        let running = server.start().await?;
        fixture.checks.worker_poison.store(true, Ordering::Release);
        workers.try_enqueue(WorkerKind::Compilation, worker_job()?)?;

        tokio::time::timeout(Duration::from_secs(5), async {
            while readiness.is_open() || workers.dispatch_claims_allowed() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(
            workers
                .runtime()
                .metrics()?
                .iter()
                .all(|metric| !metric.accepting)
        );
        assert_eq!(
            workers
                .try_enqueue(WorkerKind::Indexing, worker_job()?)
                .err()
                .map(|error| error.code()),
            Some(QueueErrorCode::NotAccepting)
        );
        assert_eq!(
            fixture
                .checks
                .processed
                .lock()
                .map_err(|_error| "processed worker mutex poisoned")?
                .as_slice(),
            &[WorkerKind::Compilation]
        );

        fixture.checks.worker_poison.store(false, Ordering::Release);
        let receipt = running.shutdown().await?;
        assert!(receipt.shutdown.failed.is_none());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_polls_durable_truth_immediately_after_startup_and_while_idle()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let fixture = fixture(directory.path())?;
        fixture
            .checks
            .durable_progress_remaining
            .store(1, Ordering::Release);
        let server = DaemonServer::local(
            fixture.config,
            fixture.dependencies,
            LocalIdentity::new("tenant-a", "principal-a")?,
        )?;
        let running = server.start().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.checks.durable_polls.load(Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            fixture
                .checks
                .durable_progress_remaining
                .load(Ordering::Acquire),
            0
        );
        assert!(running.shutdown().await?.shutdown.failed.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn invalid_durable_cursor_prevents_startup_and_readiness() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let fixture = fixture(directory.path())?;
        fixture.checks.cursor_valid.store(false, Ordering::Release);
        let readiness = Arc::clone(&fixture.dependencies.readiness_gate);
        let telemetry = Arc::clone(&fixture.dependencies.telemetry);
        let server = DaemonServer::local(
            fixture.config,
            fixture.dependencies,
            LocalIdentity::new("tenant-a", "principal-a")?,
        )?;
        let error = server
            .start()
            .await
            .err()
            .ok_or("startup unexpectedly succeeded")?;
        assert_eq!(error.code(), crate::DaemonErrorCode::StartupFailed);
        assert!(!readiness.is_open());
        let metrics = telemetry.render_openmetrics(&[]);
        assert!(metrics.contains("cigar_startup_stage_failures_total{stage=\"readiness_open\"} 1"));
        assert!(metrics.contains("cigar_startup_outcomes_total{outcome=\"failed\"} 1"));
        assert!(!metrics.contains("cursor_valid"));
        assert!(!metrics.contains(directory.path().to_string_lossy().as_ref()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn real_daemon_handles_32_mixed_clients_with_exact_replay_and_no_quota_leak()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let fixture = fixture(directory.path())?;
        let facade = Arc::clone(&fixture.facade);
        let server = DaemonServer::local(
            fixture.config.clone(),
            fixture.dependencies,
            LocalIdentity::new("tenant-a", "principal-a")?,
        )?;
        let running = server.start().await?;
        let address = running.addresses().http.ok_or("HTTP listener missing")?;
        let token_path = fixture
            .config
            .local_token_file
            .as_ref()
            .ok_or("token path missing")?;
        let token = std::fs::read_to_string(token_path)?;
        let mut clients = Vec::new();
        for index in 0..32_u32 {
            let token = token.clone();
            clients.push(tokio::spawn(async move {
                if index % 2 == 0 {
                    raw_http(
                        address,
                        format!(
                            "GET /v1/capabilities HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
                        ),
                    )
                    .await
                } else {
                    let body = serde_json::to_vec(&json!({
                        "operation_id": "createSpace",
                        "payload_cbor": URL_SAFE_NO_PAD.encode([0xa0]),
                        "idempotency_key": format!("load-{index}"),
                        "path_parameters": []
                    }))
                    .map_err(std::io::Error::other)?;
                    raw_http(
                        address,
                        format!(
                            "POST /v1/spaces HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: load-{index}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            String::from_utf8(body).map_err(std::io::Error::other)?,
                        ),
                    )
                    .await
                }
            }));
        }
        for (index, client) in clients.into_iter().enumerate() {
            let response = client.await??;
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "client {index}: {response}"
            );
        }
        // Both operational reads and domain mutations traverse the complete governed facade.
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 32);
        let before_replay = facade.quota_snapshot();
        assert_eq!(before_replay.global_in_use(), 0);
        assert_eq!(
            before_replay.admitted_total(),
            before_replay.released_total()
        );
        let replay_body = serde_json::to_vec(&json!({
            "operation_id": "createSpace",
            "payload_cbor": URL_SAFE_NO_PAD.encode([0xa0]),
            "idempotency_key": "load-1",
            "path_parameters": []
        }))?;
        let replay = raw_http(
            address,
            format!(
                "POST /v1/spaces HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: load-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                replay_body.len(),
                String::from_utf8(replay_body)?,
            ),
        )
        .await?;
        assert!(replay.starts_with("HTTP/1.1 200"));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 32);
        let shutdown = running.shutdown().await?;
        assert!(shutdown.shutdown.failed.is_none());
        let quotas = facade.quota_snapshot();
        assert_eq!(quotas.global_in_use(), 0);
        assert_eq!(quotas.admitted_total(), quotas.released_total());
        assert!(fixture.store.integrity_check().is_ok());
        Ok(())
    }

    #[test]
    fn production_composition_requires_an_async_runtime() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let config = config(directory.path())?;
        let store = Arc::new(SqliteStore::open(config.state_directory.join("cigar.db"))?);
        let repository: Arc<dyn ServiceRepository> = store;
        let pool = Arc::new(BlockingPool::new(1, 1)?);
        let facade = Arc::new(ProductionFacade::new(
            complete_facade(Arc::new(AtomicUsize::new(0)), Arc::clone(&pool))?,
            Arc::new(DurableIdempotencyRepository::new(
                Arc::clone(&repository),
                RecordId::new(SYSTEM_TENANT)?,
            )),
            QuotaLimits::new(1, 1)?,
            Duration::from_secs(1),
        )?);
        let checks: Arc<dyn ProductionDependencyChecks> = Arc::new(Checks::new());
        let queue_clock: Arc<dyn crate::RuntimeClock> = Arc::new(SystemRuntimeClock::new());
        let unix_clock: Arc<dyn ProductionUnixClock> = Arc::new(SystemProductionUnixClock);
        let result = compose_repository_runtime(
            &config,
            facade,
            repository,
            RecordId::new(SYSTEM_TENANT)?,
            checks,
            pool,
            queue_clock,
            unix_clock,
            Arc::new(DaemonTelemetry::local()),
        );
        assert!(matches!(
            result,
            Err(super::ProductionRuntimeError::RuntimeUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn queue_error_code_remains_content_free() {
        assert_eq!(format!("{:?}", QueueErrorCode::Full), "Full");
    }
}
