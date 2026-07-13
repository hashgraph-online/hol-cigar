//! Bounded wakeup queues for durable daemon workers.

use cigar_api::{CancellationToken, TenantId};
use cigar_protocol::{ExpectedRevision, RecordId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Every required bounded daemon worker family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkerKind {
    /// Source discovery and ingestion.
    Ingestion,
    /// Mandatory and optional index maintenance.
    Indexing,
    /// Dependency invalidation fan-out.
    Invalidation,
    /// Context compilation.
    Compilation,
    /// Durable outbox wakeups.
    Outbox,
    /// Unknown-effect reconciliation.
    Reconciliation,
    /// Expired lease cleanup.
    LeaseCleanup,
    /// Backup creation and verification.
    Backup,
    /// Blob and metadata garbage collection.
    GarbageCollection,
}

impl WorkerKind {
    /// Complete stable worker-family list.
    pub const ALL: [Self; 9] = [
        Self::Ingestion,
        Self::Indexing,
        Self::Invalidation,
        Self::Compilation,
        Self::Outbox,
        Self::Reconciliation,
        Self::LeaseCleanup,
        Self::Backup,
        Self::GarbageCollection,
    ];

    /// Stable metrics and diagnostics label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingestion => "ingestion",
            Self::Indexing => "indexing",
            Self::Invalidation => "invalidation",
            Self::Compilation => "compilation",
            Self::Outbox => "outbox",
            Self::Reconciliation => "reconciliation",
            Self::LeaseCleanup => "lease_cleanup",
            Self::Backup => "backup",
            Self::GarbageCollection => "garbage_collection",
        }
    }
}

/// Explicit full-queue behavior for every daemon wakeup queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverflowPolicy {
    /// Reject the new wakeup; the durable record remains discoverable by recovery scans.
    RejectNewest,
}

/// Durable-record reference placed on a worker wakeup queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerJob {
    /// Tenant scope used to reload and authorize durable work.
    pub tenant: TenantId,
    /// Durable record that remains authority if the wakeup is rejected or lost.
    pub record_id: RecordId,
    /// Optional optimistic revision observed by the enqueuer.
    pub expected_revision: Option<ExpectedRevision>,
}

/// Stable nonblocking enqueue failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueErrorCode {
    /// Graceful shutdown has stopped new work claims.
    NotAccepting,
    /// The bounded queue is at capacity.
    Full,
    /// The worker receiver has exited.
    Closed,
    /// Internal observation sequence space was exhausted.
    SequenceExhausted,
    /// Metrics state was poisoned by a panic and was discarded.
    MetricsUnavailable,
}

/// Content-free queue failure; the durable record remains authoritative.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct QueueError {
    code: QueueErrorCode,
}

impl QueueError {
    pub(crate) const fn new(code: QueueErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> QueueErrorCode {
        self.code
    }
}

impl fmt::Debug for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueueError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "bounded worker queue rejected wakeup: {:?}",
            self.code
        )
    }
}

impl std::error::Error for QueueError {}

/// Injected monotonic observation clock; values never enter semantic digests.
pub trait RuntimeClock: Send + Sync {
    /// Returns monotonic nanoseconds from an arbitrary stable origin.
    fn now_nanos(&self) -> u64;
}

/// Process-local monotonic observation clock.
#[derive(Debug)]
pub struct SystemRuntimeClock {
    origin: Instant,
}

impl SystemRuntimeClock {
    /// Starts a new process-local observation epoch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemRuntimeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeClock for SystemRuntimeClock {
    fn now_nanos(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Public bounded-queue metrics snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueMetricsSnapshot {
    /// Worker family.
    pub kind: WorkerKind,
    /// Configured hard capacity.
    pub capacity: usize,
    /// Current queued wakeups.
    pub depth: usize,
    /// Age of the oldest queued wakeup, if any.
    pub oldest_age_nanos: Option<u64>,
    /// Rejected enqueue attempts.
    pub rejection_count: u64,
    /// Explicit full-queue behavior.
    pub overflow_policy: OverflowPolicy,
    /// Whether new wakeups may still be accepted.
    pub accepting: bool,
}

struct QueueMetrics {
    depth: AtomicUsize,
    rejections: AtomicU64,
    next_sequence: AtomicU64,
    queued: Mutex<BTreeSet<(u64, u64)>>,
    clock: Arc<dyn RuntimeClock>,
}

impl QueueMetrics {
    fn reserve(&self) -> Result<(u64, u64), QueueError> {
        let mut current = self.next_sequence.load(Ordering::Relaxed);
        let sequence = loop {
            let next = current
                .checked_add(1)
                .ok_or_else(|| QueueError::new(QueueErrorCode::SequenceExhausted))?;
            match self.next_sequence.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(previous) => break previous,
                Err(observed) => current = observed,
            }
        };
        let enqueued_at = self.clock.now_nanos();
        self.queued
            .lock()
            .map_err(|_error| QueueError::new(QueueErrorCode::MetricsUnavailable))?
            .insert((enqueued_at, sequence));
        self.depth.fetch_add(1, Ordering::Release);
        Ok((enqueued_at, sequence))
    }

    fn remove(&self, enqueued_at: u64, sequence: u64) -> Result<(), QueueError> {
        let removed = self
            .queued
            .lock()
            .map_err(|_error| QueueError::new(QueueErrorCode::MetricsUnavailable))?
            .remove(&(enqueued_at, sequence));
        if removed {
            self.depth.fetch_sub(1, Ordering::AcqRel);
        }
        Ok(())
    }

    fn reject(&self, enqueued_at: u64, sequence: u64) -> Result<(), QueueError> {
        self.remove(enqueued_at, sequence)?;
        self.rejections.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn snapshot(
        &self,
        kind: WorkerKind,
        capacity: usize,
        accepting: bool,
    ) -> Result<QueueMetricsSnapshot, QueueError> {
        let now = self.clock.now_nanos();
        let oldest = self
            .queued
            .lock()
            .map_err(|_error| QueueError::new(QueueErrorCode::MetricsUnavailable))?
            .first()
            .map(|(enqueued_at, _sequence)| now.saturating_sub(*enqueued_at));
        Ok(QueueMetricsSnapshot {
            kind,
            capacity,
            depth: self.depth.load(Ordering::Acquire),
            oldest_age_nanos: oldest,
            rejection_count: self.rejections.load(Ordering::Relaxed),
            overflow_policy: OverflowPolicy::RejectNewest,
            accepting,
        })
    }
}

struct QueuedJob {
    job: WorkerJob,
    enqueued_at: u64,
    sequence: u64,
}

/// Cloneable nonblocking sender for one bounded worker queue.
#[derive(Clone)]
pub struct WorkerQueue {
    kind: WorkerKind,
    capacity: usize,
    sender: mpsc::Sender<QueuedJob>,
    metrics: Arc<QueueMetrics>,
    accepting: Arc<AtomicBool>,
}

impl WorkerQueue {
    /// Attempts one immediate wakeup without waiting for capacity.
    pub fn try_enqueue(&self, job: WorkerJob) -> Result<(), QueueError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(QueueError::new(QueueErrorCode::NotAccepting));
        }
        let (enqueued_at, sequence) = self.metrics.reserve()?;
        let queued = QueuedJob {
            job,
            enqueued_at,
            sequence,
        };
        match self.sender.try_send(queued) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_queued)) => {
                self.metrics.reject(enqueued_at, sequence)?;
                Err(QueueError::new(QueueErrorCode::Full))
            }
            Err(mpsc::error::TrySendError::Closed(_queued)) => {
                self.metrics.reject(enqueued_at, sequence)?;
                Err(QueueError::new(QueueErrorCode::Closed))
            }
        }
    }

    /// Returns current public queue metrics.
    pub fn metrics(&self) -> Result<QueueMetricsSnapshot, QueueError> {
        self.metrics.snapshot(
            self.kind,
            self.capacity,
            self.accepting.load(Ordering::Acquire),
        )
    }
}

impl fmt::Debug for WorkerQueue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerQueue")
            .field("kind", &self.kind)
            .field("capacity", &self.capacity)
            .field("accepting", &self.accepting.load(Ordering::Acquire))
            .finish()
    }
}

struct WorkerReceiver {
    receiver: mpsc::Receiver<QueuedJob>,
    metrics: Arc<QueueMetrics>,
}

impl WorkerReceiver {
    async fn recv(&mut self) -> Result<Option<WorkerJob>, QueueError> {
        let Some(queued) = self.receiver.recv().await else {
            return Ok(None);
        };
        self.metrics.remove(queued.enqueued_at, queued.sequence)?;
        Ok(Some(queued.job))
    }

    fn try_recv(&mut self) -> Result<Option<WorkerJob>, QueueError> {
        match self.receiver.try_recv() {
            Ok(queued) => {
                self.metrics.remove(queued.enqueued_at, queued.sequence)?;
                Ok(Some(queued.job))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(QueueError::new(QueueErrorCode::Closed))
            }
        }
    }

    fn close(&mut self) {
        self.receiver.close();
    }
}

impl Drop for WorkerReceiver {
    fn drop(&mut self) {
        while let Ok(queued) = self.receiver.try_recv() {
            let _ignored = self.metrics.remove(queued.enqueued_at, queued.sequence);
        }
    }
}

/// Receiving halves retained only by supervised worker tasks.
pub struct WorkerReceivers {
    receivers: BTreeMap<WorkerKind, WorkerReceiver>,
}

impl WorkerReceivers {
    /// Receives the next durable-record wakeup for one exact worker family.
    pub async fn recv(&mut self, kind: WorkerKind) -> Result<Option<WorkerJob>, QueueError> {
        self.receivers
            .get_mut(&kind)
            .ok_or_else(|| QueueError::new(QueueErrorCode::Closed))?
            .recv()
            .await
    }

    /// Polls all worker families once in stable order without waiting.
    pub(crate) fn try_recv_any(&mut self) -> Result<Option<(WorkerKind, WorkerJob)>, QueueError> {
        for kind in WorkerKind::ALL {
            let receiver = self
                .receivers
                .get_mut(&kind)
                .ok_or_else(|| QueueError::new(QueueErrorCode::Closed))?;
            if let Some(job) = receiver.try_recv()? {
                return Ok(Some((kind, job)));
            }
        }
        Ok(None)
    }

    /// Closes all receiving halves while retaining already queued wakeups for drain.
    pub fn begin_shutdown(&mut self) {
        for receiver in self.receivers.values_mut() {
            receiver.close();
        }
    }
}

impl fmt::Debug for WorkerReceivers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerReceivers")
            .field("receiver_count", &self.receivers.len())
            .finish()
    }
}

/// Sender registry and shutdown gate for all required bounded queues.
pub struct WorkerRuntime {
    queues: BTreeMap<WorkerKind, WorkerQueue>,
    accepting: Arc<AtomicBool>,
}

impl WorkerRuntime {
    /// Creates exactly nine queues from validated configured capacities.
    pub fn new(
        capacities: &crate::config::WorkerCapacities,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<(Self, WorkerReceivers), crate::config::ConfigError> {
        capacities.validate()?;
        let accepting = Arc::new(AtomicBool::new(true));
        let mut queues = BTreeMap::new();
        let mut receivers = BTreeMap::new();
        for kind in WorkerKind::ALL {
            let capacity = capacity_for(capacities, kind);
            let (sender, receiver) = mpsc::channel(capacity);
            let metrics = Arc::new(QueueMetrics {
                depth: AtomicUsize::new(0),
                rejections: AtomicU64::new(0),
                next_sequence: AtomicU64::new(0),
                queued: Mutex::new(BTreeSet::new()),
                clock: Arc::clone(&clock),
            });
            queues.insert(
                kind,
                WorkerQueue {
                    kind,
                    capacity,
                    sender,
                    metrics: Arc::clone(&metrics),
                    accepting: Arc::clone(&accepting),
                },
            );
            receivers.insert(kind, WorkerReceiver { receiver, metrics });
        }
        Ok((Self { queues, accepting }, WorkerReceivers { receivers }))
    }

    /// Returns a cloneable sender for one exact worker family.
    #[must_use]
    pub fn queue(&self, kind: WorkerKind) -> Option<WorkerQueue> {
        self.queues.get(&kind).cloned()
    }

    /// Atomically prevents all new wakeups before drain and lease release.
    pub fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    /// Returns a stable ordered snapshot for all nine queue metrics.
    pub fn metrics(&self) -> Result<Vec<QueueMetricsSnapshot>, QueueError> {
        self.queues.values().map(WorkerQueue::metrics).collect()
    }

    /// Returns true only when every queue has drained.
    pub fn is_drained(&self) -> Result<bool, QueueError> {
        Ok(self
            .metrics()?
            .into_iter()
            .all(|metrics| metrics.depth == 0))
    }
}

impl Drop for WorkerRuntime {
    fn drop(&mut self) {
        self.stop_accepting();
    }
}

impl fmt::Debug for WorkerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerRuntime")
            .field("queue_count", &self.queues.len())
            .field("accepting", &self.accepting.load(Ordering::Acquire))
            .finish()
    }
}

/// Stable failure from the bounded CPU/blocking execution pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockingPoolErrorCode {
    /// The configured active plus queued admission bound was exhausted.
    Exhausted,
    /// Graceful shutdown stopped new blocking work.
    NotAccepting,
    /// Cooperative cancellation was observed before completion.
    Cancelled,
    /// The caller's monotonic deadline elapsed before completion.
    DeadlineExceeded,
    /// The blocking task panicked or its runtime join failed.
    TaskFailed,
}

/// Content-free bounded blocking-pool error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlockingPoolError {
    code: BlockingPoolErrorCode,
}

impl BlockingPoolError {
    const fn new(code: BlockingPoolErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> BlockingPoolErrorCode {
        self.code
    }
}

impl fmt::Debug for BlockingPoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockingPoolError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BlockingPoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded blocking work failed: {:?}", self.code)
    }
}

impl std::error::Error for BlockingPoolError {}

/// Content-safe bounded CPU/blocking-pool metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockingPoolMetrics {
    /// Maximum simultaneously running jobs.
    pub active_capacity: usize,
    /// Maximum jobs admitted while awaiting an active permit.
    pub queue_capacity: usize,
    /// Jobs currently running on blocking threads.
    pub in_use: usize,
    /// Admitted jobs currently awaiting a blocking permit.
    pub queued: usize,
    /// Calls rejected because active plus queued capacity was exhausted.
    pub rejection_count: u64,
    /// Jobs whose blocking closures completed, including cooperative failures.
    pub completion_count: u64,
    /// Calls that observed cancellation before closure completion.
    pub cancellation_count: u64,
    /// Calls that observed deadline expiry before closure completion.
    pub deadline_count: u64,
    /// Whether new blocking work is accepted.
    pub accepting: bool,
}

struct BlockingPoolState {
    permits: Arc<Semaphore>,
    active_capacity: usize,
    queue_capacity: usize,
    admitted: AtomicUsize,
    in_use: AtomicUsize,
    queued: AtomicUsize,
    rejections: AtomicU64,
    completions: AtomicU64,
    cancellations: AtomicU64,
    deadlines: AtomicU64,
    accepting: AtomicBool,
}

/// Semaphore- and admission-bounded pool for parsing, tokenization, and other CPU/blocking work.
#[derive(Clone)]
pub struct BlockingPool {
    state: Arc<BlockingPoolState>,
}

impl BlockingPool {
    /// Creates a pool with independent hard bounds for running and waiting jobs.
    pub fn new(active_capacity: usize, queue_capacity: usize) -> Result<Self, BlockingPoolError> {
        if active_capacity == 0 || queue_capacity == 0 {
            return Err(BlockingPoolError::new(BlockingPoolErrorCode::Exhausted));
        }
        Ok(Self {
            state: Arc::new(BlockingPoolState {
                permits: Arc::new(Semaphore::new(active_capacity)),
                active_capacity,
                queue_capacity,
                admitted: AtomicUsize::new(0),
                in_use: AtomicUsize::new(0),
                queued: AtomicUsize::new(0),
                rejections: AtomicU64::new(0),
                completions: AtomicU64::new(0),
                cancellations: AtomicU64::new(0),
                deadlines: AtomicU64::new(0),
                accepting: AtomicBool::new(true),
            }),
        })
    }

    /// Runs one cooperative blocking closure within the active, queue, cancellation, and deadline
    /// bounds. Once dispatched, a non-cooperative closure remains charged to the pool until exit.
    pub async fn run<T, F>(
        &self,
        cancellation: CancellationToken,
        deadline: tokio::time::Instant,
        job: F,
    ) -> Result<T, BlockingPoolError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> T + Send + 'static,
    {
        self.run_with_cancel(cancellation, deadline, || {}, job)
            .await
    }

    /// Runs one cooperative blocking closure while continuously linking its own cancellation
    /// primitive to queue cancellation, request cancellation, deadline expiry, and future drop.
    pub async fn run_with_cancel<T, F, C>(
        &self,
        cancellation: CancellationToken,
        deadline: tokio::time::Instant,
        cancel_job: C,
        job: F,
    ) -> Result<T, BlockingPoolError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> T + Send + 'static,
        C: Fn() + Send + Sync + 'static,
    {
        let mut cancel_guard = BlockingJobCancelGuard::new(cancel_job);
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(BlockingPoolError::new(BlockingPoolErrorCode::NotAccepting));
        }
        let maximum_admitted = self
            .state
            .active_capacity
            .saturating_add(self.state.queue_capacity);
        let mut admitted = self.state.admitted.load(Ordering::Acquire);
        loop {
            if admitted >= maximum_admitted {
                self.state.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(BlockingPoolError::new(BlockingPoolErrorCode::Exhausted));
            }
            match self.state.admitted.compare_exchange_weak(
                admitted,
                admitted.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => admitted = observed,
            }
        }
        self.state.queued.fetch_add(1, Ordering::AcqRel);
        let admission = QueuedAdmission::new(Arc::clone(&self.state));
        let permit =
            acquire_blocking_permit(Arc::clone(&self.state.permits), &cancellation, deadline).await;
        let permit = match permit {
            Ok(permit) => permit,
            Err(error) => {
                match error.code() {
                    BlockingPoolErrorCode::Cancelled => {
                        self.state.cancellations.fetch_add(1, Ordering::Relaxed);
                    }
                    BlockingPoolErrorCode::DeadlineExceeded => {
                        self.state.deadlines.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                drop(admission);
                return Err(error);
            }
        };
        let running = admission.start(permit);
        let task_cancellation = cancellation.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            let result = job(task_cancellation);
            drop(running);
            result
        });
        loop {
            tokio::select! {
                result = &mut task => {
                    let result = result
                        .map_err(|_join_error| BlockingPoolError::new(BlockingPoolErrorCode::TaskFailed));
                    cancel_guard.disarm();
                    return result;
                }
                () = tokio::time::sleep_until(deadline) => {
                    cancellation.cancel();
                    self.state.deadlines.fetch_add(1, Ordering::Relaxed);
                    return Err(BlockingPoolError::new(BlockingPoolErrorCode::DeadlineExceeded));
                }
                () = tokio::time::sleep(Duration::from_millis(1)) => {
                    if cancellation.is_cancelled() {
                        self.state.cancellations.fetch_add(1, Ordering::Relaxed);
                        return Err(BlockingPoolError::new(BlockingPoolErrorCode::Cancelled));
                    }
                }
            }
        }
    }

    /// Stops new admissions. Running and already admitted closures retain their bounds.
    pub fn stop_accepting(&self) {
        self.state.accepting.store(false, Ordering::Release);
    }

    /// Returns true after every admitted closure or queued caller has exited.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.state.admitted.load(Ordering::Acquire) == 0
    }

    /// Returns a stable metrics snapshot without job or tenant data.
    #[must_use]
    pub fn metrics(&self) -> BlockingPoolMetrics {
        BlockingPoolMetrics {
            active_capacity: self.state.active_capacity,
            queue_capacity: self.state.queue_capacity,
            in_use: self.state.in_use.load(Ordering::Acquire),
            queued: self.state.queued.load(Ordering::Acquire),
            rejection_count: self.state.rejections.load(Ordering::Relaxed),
            completion_count: self.state.completions.load(Ordering::Relaxed),
            cancellation_count: self.state.cancellations.load(Ordering::Relaxed),
            deadline_count: self.state.deadlines.load(Ordering::Relaxed),
            accepting: self.state.accepting.load(Ordering::Acquire),
        }
    }
}

struct BlockingJobCancelGuard<C: Fn()> {
    cancel_job: Option<C>,
}

impl<C: Fn()> BlockingJobCancelGuard<C> {
    const fn new(cancel_job: C) -> Self {
        Self {
            cancel_job: Some(cancel_job),
        }
    }

    fn disarm(&mut self) {
        self.cancel_job = None;
    }
}

impl<C: Fn()> Drop for BlockingJobCancelGuard<C> {
    fn drop(&mut self) {
        if let Some(cancel_job) = self.cancel_job.take() {
            cancel_job();
        }
    }
}

impl fmt::Debug for BlockingPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockingPool")
            .field("metrics", &self.metrics())
            .finish()
    }
}

struct QueuedAdmission {
    state: Arc<BlockingPoolState>,
    queued: bool,
}

impl QueuedAdmission {
    const fn new(state: Arc<BlockingPoolState>) -> Self {
        Self {
            state,
            queued: true,
        }
    }

    fn start(mut self, permit: OwnedSemaphorePermit) -> RunningAdmission {
        self.state.queued.fetch_sub(1, Ordering::AcqRel);
        self.state.in_use.fetch_add(1, Ordering::AcqRel);
        self.queued = false;
        let state = Arc::clone(&self.state);
        drop(self);
        RunningAdmission {
            state,
            _permit: permit,
        }
    }
}

impl Drop for QueuedAdmission {
    fn drop(&mut self) {
        if self.queued {
            self.state.queued.fetch_sub(1, Ordering::AcqRel);
            self.state.admitted.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct RunningAdmission {
    state: Arc<BlockingPoolState>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for RunningAdmission {
    fn drop(&mut self) {
        self.state.in_use.fetch_sub(1, Ordering::AcqRel);
        self.state.admitted.fetch_sub(1, Ordering::AcqRel);
        self.state.completions.fetch_add(1, Ordering::Relaxed);
    }
}

async fn acquire_blocking_permit(
    semaphore: Arc<Semaphore>,
    cancellation: &CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<OwnedSemaphorePermit, BlockingPoolError> {
    loop {
        if cancellation.is_cancelled() {
            return Err(BlockingPoolError::new(BlockingPoolErrorCode::Cancelled));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(BlockingPoolError::new(
                BlockingPoolErrorCode::DeadlineExceeded,
            ));
        }
        match Arc::clone(&semaphore).try_acquire_owned() {
            Ok(permit) => return Ok(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(BlockingPoolError::new(BlockingPoolErrorCode::NotAccepting));
            }
        }
    }
}

const fn capacity_for(capacities: &crate::config::WorkerCapacities, kind: WorkerKind) -> usize {
    match kind {
        WorkerKind::Ingestion => capacities.ingestion,
        WorkerKind::Indexing => capacities.indexing,
        WorkerKind::Invalidation => capacities.invalidation,
        WorkerKind::Compilation => capacities.compilation,
        WorkerKind::Outbox => capacities.outbox,
        WorkerKind::Reconciliation => capacities.reconciliation,
        WorkerKind::LeaseCleanup => capacities.lease_cleanup,
        WorkerKind::Backup => capacities.backup,
        WorkerKind::GarbageCollection => capacities.garbage_collection,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BlockingPool, BlockingPoolErrorCode, QueueErrorCode, RuntimeClock, WorkerJob, WorkerKind,
        WorkerRuntime, WorkerRuntime as Runtime,
    };
    use crate::config::WorkerCapacities;
    use cigar_api::{CancellationToken, TenantId};
    use cigar_protocol::RecordId;
    use cigar_store::CancellationToken as StoreCancellationToken;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    #[derive(Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn advance(&self, nanos: u64) {
            self.0.fetch_add(nanos, Ordering::Relaxed);
        }
    }

    impl RuntimeClock for ManualClock {
        fn now_nanos(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn capacities(capacity: usize) -> WorkerCapacities {
        WorkerCapacities {
            ingestion: capacity,
            indexing: capacity,
            invalidation: capacity,
            compilation: capacity,
            outbox: capacity,
            reconciliation: capacity,
            lease_cleanup: capacity,
            backup: capacity,
            garbage_collection: capacity,
        }
    }

    fn job() -> Result<WorkerJob, Box<dyn std::error::Error>> {
        Ok(WorkerJob {
            tenant: TenantId::new("tenant-a")?,
            record_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            expected_revision: None,
        })
    }

    #[tokio::test]
    async fn all_nine_queues_are_bounded_and_publish_oldest_age()
    -> Result<(), Box<dyn std::error::Error>> {
        let clock = Arc::new(ManualClock::default());
        let (runtime, mut receivers) = Runtime::new(&capacities(1), clock.clone())?;
        assert_eq!(runtime.metrics()?.len(), WorkerKind::ALL.len());
        let queue = runtime
            .queue(WorkerKind::Outbox)
            .ok_or("outbox queue missing")?;
        queue.try_enqueue(job()?)?;
        clock.advance(50);
        assert_eq!(queue.metrics()?.oldest_age_nanos, Some(50));
        assert_eq!(
            queue.try_enqueue(job()?).err().map(|error| error.code()),
            Some(QueueErrorCode::Full)
        );
        assert_eq!(queue.metrics()?.rejection_count, 1);
        assert_eq!(receivers.recv(WorkerKind::Outbox).await?, Some(job()?));
        assert!(runtime.is_drained()?);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_exhaustion_never_exceeds_capacity() -> Result<(), Box<dyn std::error::Error>>
    {
        let (runtime, mut receivers) =
            WorkerRuntime::new(&capacities(4), Arc::new(ManualClock::default()))?;
        let queue = runtime
            .queue(WorkerKind::Compilation)
            .ok_or("compilation queue missing")?;
        let mut tasks = Vec::new();
        for _index in 0..32 {
            let queue = queue.clone();
            let wakeup = job()?;
            tasks.push(tokio::spawn(async move { queue.try_enqueue(wakeup) }));
        }
        let mut accepted = 0;
        for task in tasks {
            if task.await?.is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 4);
        assert_eq!(queue.metrics()?.depth, 4);
        assert_eq!(queue.metrics()?.rejection_count, 28);
        for _index in 0..4 {
            assert!(receivers.recv(WorkerKind::Compilation).await?.is_some());
        }
        assert!(runtime.is_drained()?);
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_rejects_new_claims_and_drains_existing_wakeups()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runtime, mut receivers) =
            WorkerRuntime::new(&capacities(2), Arc::new(ManualClock::default()))?;
        let queue = runtime
            .queue(WorkerKind::Reconciliation)
            .ok_or("reconciliation queue missing")?;
        queue.try_enqueue(job()?)?;
        runtime.stop_accepting();
        receivers.begin_shutdown();
        assert_eq!(
            queue.try_enqueue(job()?).err().map(|error| error.code()),
            Some(QueueErrorCode::NotAccepting)
        );
        assert!(receivers.recv(WorkerKind::Reconciliation).await?.is_some());
        assert!(receivers.recv(WorkerKind::Reconciliation).await?.is_none());
        assert!(runtime.is_drained()?);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn blocking_pool_bounds_active_and_queued_work_and_releases_after_cancel_and_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let pool = BlockingPool::new(1, 1)?;
        let release = Arc::new(AtomicBool::new(false));
        let first_pool = pool.clone();
        let first_release = Arc::clone(&release);
        let first = tokio::spawn(async move {
            first_pool
                .run(
                    CancellationToken::new(),
                    tokio::time::Instant::now() + Duration::from_secs(2),
                    move |_cancellation| {
                        while !first_release.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                        1_u8
                    },
                )
                .await
        });
        while pool.metrics().in_use != 1 {
            tokio::task::yield_now().await;
        }

        let queued_cancellation = CancellationToken::new();
        let second_pool = pool.clone();
        let second_token = queued_cancellation.clone();
        let second = tokio::spawn(async move {
            second_pool
                .run(
                    second_token,
                    tokio::time::Instant::now() + Duration::from_secs(2),
                    |_cancellation| 2_u8,
                )
                .await
        });
        while pool.metrics().queued != 1 {
            tokio::task::yield_now().await;
        }
        let exhausted = pool
            .run(
                CancellationToken::new(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                |_cancellation| 3_u8,
            )
            .await;
        assert_eq!(
            exhausted.err().map(|error| error.code()),
            Some(BlockingPoolErrorCode::Exhausted)
        );
        queued_cancellation.cancel();
        let second_result = second.await?;
        assert_eq!(
            second_result.err().map(|error| error.code()),
            Some(BlockingPoolErrorCode::Cancelled)
        );
        release.store(true, Ordering::Release);
        assert_eq!(first.await??, 1);

        let deadline = pool
            .run(
                CancellationToken::new(),
                tokio::time::Instant::now() + Duration::from_millis(10),
                |cancellation| {
                    while !cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    4_u8
                },
            )
            .await;
        assert_eq!(
            deadline.err().map(|error| error.code()),
            Some(BlockingPoolErrorCode::DeadlineExceeded)
        );
        for _attempt in 0..1_000 {
            if pool.is_drained() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let metrics = pool.metrics();
        assert_eq!(metrics.in_use, 0);
        assert_eq!(metrics.queued, 0);
        assert!(pool.is_drained());
        assert_eq!(metrics.rejection_count, 1);
        assert_eq!(metrics.cancellation_count, 1);
        assert_eq!(metrics.deadline_count, 1);
        assert_eq!(metrics.completion_count, 2);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_pool_links_request_cancellation_to_running_job_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let pool = BlockingPool::new(1, 1)?;
        let request_cancellation = CancellationToken::new();
        let store_cancellation = StoreCancellationToken::default();
        let observed_store = store_cancellation.clone();
        let cancel_store = {
            let store_cancellation = store_cancellation.clone();
            move || store_cancellation.cancel()
        };
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let running_pool = pool.clone();
        let running_request = request_cancellation.clone();
        let running = tokio::spawn(async move {
            running_pool
                .run_with_cancel(
                    running_request,
                    tokio::time::Instant::now() + Duration::from_secs(30),
                    cancel_store,
                    move |_cancellation| {
                        entered_tx.send(())?;
                        release_rx.recv()?;
                        Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                            store_cancellation.is_cancelled(),
                        )
                    },
                )
                .await
        });
        tokio::task::spawn_blocking(move || entered_rx.recv()).await??;
        request_cancellation.cancel();
        let result = running.await?;
        assert_eq!(
            result.err().map(|error| error.code()),
            Some(BlockingPoolErrorCode::Cancelled)
        );
        assert!(observed_store.is_cancelled());
        release_tx.send(())?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !pool.is_drained() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}
