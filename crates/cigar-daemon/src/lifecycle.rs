//! Ordered startup recovery and deadline-bounded graceful shutdown.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Boxed object-safe lifecycle action future.
pub type LifecycleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleError>> + Send + 'a>>;

/// Stable daemon lifecycle failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleErrorCode {
    /// A mandatory step was absent or duplicated.
    InvalidConfiguration,
    /// A mandatory action failed without exposing protected details.
    StepFailed,
    /// The overall startup or shutdown deadline elapsed.
    DeadlineExceeded,
}

/// Content-free daemon lifecycle failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LifecycleError {
    code: LifecycleErrorCode,
}

impl LifecycleError {
    /// Creates a safe failure for an injected action.
    #[must_use]
    pub const fn action_failed() -> Self {
        Self {
            code: LifecycleErrorCode::StepFailed,
        }
    }

    const fn new(code: LifecycleErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> LifecycleErrorCode {
        self.code
    }
}

impl fmt::Debug for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "daemon lifecycle failed: {:?}", self.code)
    }
}

impl std::error::Error for LifecycleError {}

/// Mandatory startup recovery step in exact execution order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StartupStep {
    /// Apply and verify supported metadata migrations.
    Migrations,
    /// Validate effect transition legality and journal hash chains.
    JournalIntegrity,
    /// Reconcile orphaned or missing blob projections.
    OrphanBlobReconciliation,
    /// Expire stale leases without reclaiming live fenced work.
    ExpiredLeaseCleanup,
    /// Verify every durable worker/event cursor is in range.
    WorkerCursorVerification,
    /// Classify dispatching effects without durable receipts as unknown.
    UnreceiptedDispatchRecovery,
}

impl StartupStep {
    /// Complete required startup sequence.
    pub const ALL: [Self; 6] = [
        Self::Migrations,
        Self::JournalIntegrity,
        Self::OrphanBlobReconciliation,
        Self::ExpiredLeaseCleanup,
        Self::WorkerCursorVerification,
        Self::UnreceiptedDispatchRecovery,
    ];

    /// Stable diagnostics label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Migrations => "migrations",
            Self::JournalIntegrity => "journal_integrity",
            Self::OrphanBlobReconciliation => "orphan_blob_reconciliation",
            Self::ExpiredLeaseCleanup => "expired_lease_cleanup",
            Self::WorkerCursorVerification => "worker_cursor_verification",
            Self::UnreceiptedDispatchRecovery => "unreceipted_dispatch_recovery",
        }
    }
}

/// Mandatory graceful-shutdown step in exact execution order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ShutdownStep {
    /// Stop accepting new HTTP, gRPC, and embedded requests.
    StopNewRequests,
    /// Prevent new effect dispatch claims before draining other work.
    PreventDispatchClaims,
    /// Drain bounded read and compile work.
    DrainReadsAndCompiles,
    /// Persist worker cursors and checkpoints.
    CheckpointWorkers,
    /// Release renewable leases without changing effect truth.
    ReleaseRenewableLeases,
    /// Flush content-safe telemetry within its remaining budget.
    FlushTelemetry,
}

impl ShutdownStep {
    /// Complete required shutdown sequence.
    pub const ALL: [Self; 6] = [
        Self::StopNewRequests,
        Self::PreventDispatchClaims,
        Self::DrainReadsAndCompiles,
        Self::CheckpointWorkers,
        Self::ReleaseRenewableLeases,
        Self::FlushTelemetry,
    ];

    /// Stable diagnostics label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewRequests => "stop_new_requests",
            Self::PreventDispatchClaims => "prevent_dispatch_claims",
            Self::DrainReadsAndCompiles => "drain_reads_and_compiles",
            Self::CheckpointWorkers => "checkpoint_workers",
            Self::ReleaseRenewableLeases => "release_renewable_leases",
            Self::FlushTelemetry => "flush_telemetry",
        }
    }
}

/// One object-safe startup recovery action.
pub trait StartupAction: Send + Sync {
    /// Exact step implemented by this action.
    fn step(&self) -> StartupStep;
    /// Runs the bounded idempotent recovery action.
    fn execute(&self) -> LifecycleFuture<'_>;
}

/// One object-safe graceful-shutdown action.
pub trait ShutdownAction: Send + Sync {
    /// Exact step implemented by this action.
    fn step(&self) -> ShutdownStep;
    /// Runs the bounded idempotent shutdown action.
    fn execute(&self) -> LifecycleFuture<'_>;
}

/// Atomic readiness gate opened only after every startup action succeeds.
#[derive(Debug, Default)]
pub struct ReadinessGate(AtomicBool);

impl ReadinessGate {
    /// Returns whether startup recovery completed successfully.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn open(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Closes readiness before shutdown or a newly detected critical failure.
    pub fn close(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Completed startup sequence safe for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupReceipt {
    /// All completed steps, always the full ordered set on success.
    pub completed: Vec<StartupStep>,
}

/// Completed or partial shutdown sequence safe for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReceipt {
    /// Successfully completed ordered steps.
    pub completed: Vec<ShutdownStep>,
    /// First step that failed or exceeded the deadline.
    pub failed: Option<ShutdownStep>,
    /// Stable failure category, if incomplete.
    pub error: Option<LifecycleErrorCode>,
}

/// Validated exact startup recovery coordinator.
pub struct StartupCoordinator {
    actions: BTreeMap<StartupStep, Arc<dyn StartupAction>>,
    readiness: Arc<ReadinessGate>,
}

impl StartupCoordinator {
    /// Requires exactly one action for every mandatory startup step.
    pub fn new(
        actions: Vec<Arc<dyn StartupAction>>,
        readiness: Arc<ReadinessGate>,
    ) -> Result<Self, LifecycleError> {
        let mut mapped = BTreeMap::new();
        for action in actions {
            if mapped.insert(action.step(), action).is_some() {
                return Err(LifecycleError::new(
                    LifecycleErrorCode::InvalidConfiguration,
                ));
            }
        }
        let configured: BTreeSet<_> = mapped.keys().copied().collect();
        let required: BTreeSet<_> = StartupStep::ALL.into_iter().collect();
        if configured != required {
            return Err(LifecycleError::new(
                LifecycleErrorCode::InvalidConfiguration,
            ));
        }
        Ok(Self {
            actions: mapped,
            readiness,
        })
    }

    /// Runs every startup action in semantic order within one overall deadline.
    pub async fn run(&self, deadline: Duration) -> Result<StartupReceipt, LifecycleError> {
        self.readiness.close();
        let started = Instant::now();
        let mut completed = Vec::with_capacity(StartupStep::ALL.len());
        for step in StartupStep::ALL {
            let remaining = remaining(deadline, started)?;
            let action = self
                .actions
                .get(&step)
                .ok_or_else(|| LifecycleError::new(LifecycleErrorCode::InvalidConfiguration))?;
            tokio::time::timeout(remaining, action.execute())
                .await
                .map_err(|_elapsed| LifecycleError::new(LifecycleErrorCode::DeadlineExceeded))??;
            completed.push(step);
        }
        self.readiness.open();
        Ok(StartupReceipt { completed })
    }
}

impl fmt::Debug for StartupCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupCoordinator")
            .field("action_count", &self.actions.len())
            .field("ready", &self.readiness.is_open())
            .finish()
    }
}

/// Validated exact graceful-shutdown coordinator.
pub struct ShutdownCoordinator {
    actions: BTreeMap<ShutdownStep, Arc<dyn ShutdownAction>>,
    readiness: Arc<ReadinessGate>,
}

impl ShutdownCoordinator {
    /// Requires exactly one action for every mandatory shutdown step.
    pub fn new(
        actions: Vec<Arc<dyn ShutdownAction>>,
        readiness: Arc<ReadinessGate>,
    ) -> Result<Self, LifecycleError> {
        let mut mapped = BTreeMap::new();
        for action in actions {
            if mapped.insert(action.step(), action).is_some() {
                return Err(LifecycleError::new(
                    LifecycleErrorCode::InvalidConfiguration,
                ));
            }
        }
        let configured: BTreeSet<_> = mapped.keys().copied().collect();
        let required: BTreeSet<_> = ShutdownStep::ALL.into_iter().collect();
        if configured != required {
            return Err(LifecycleError::new(
                LifecycleErrorCode::InvalidConfiguration,
            ));
        }
        Ok(Self {
            actions: mapped,
            readiness,
        })
    }

    /// Closes readiness and executes all steps, returning an exact partial receipt on failure.
    pub async fn run(&self, deadline: Duration) -> ShutdownReceipt {
        self.readiness.close();
        let started = Instant::now();
        let mut completed = Vec::with_capacity(ShutdownStep::ALL.len());
        for step in ShutdownStep::ALL {
            let remaining = match remaining(deadline, started) {
                Ok(remaining) => remaining,
                Err(error) => {
                    return ShutdownReceipt {
                        completed,
                        failed: Some(step),
                        error: Some(error.code()),
                    };
                }
            };
            let Some(action) = self.actions.get(&step) else {
                return ShutdownReceipt {
                    completed,
                    failed: Some(step),
                    error: Some(LifecycleErrorCode::InvalidConfiguration),
                };
            };
            match tokio::time::timeout(remaining, action.execute()).await {
                Ok(Ok(())) => completed.push(step),
                Ok(Err(error)) => {
                    return ShutdownReceipt {
                        completed,
                        failed: Some(step),
                        error: Some(error.code()),
                    };
                }
                Err(_elapsed) => {
                    return ShutdownReceipt {
                        completed,
                        failed: Some(step),
                        error: Some(LifecycleErrorCode::DeadlineExceeded),
                    };
                }
            }
        }
        ShutdownReceipt {
            completed,
            failed: None,
            error: None,
        }
    }
}

impl fmt::Debug for ShutdownCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShutdownCoordinator")
            .field("action_count", &self.actions.len())
            .finish()
    }
}

fn remaining(deadline: Duration, started: Instant) -> Result<Duration, LifecycleError> {
    deadline
        .checked_sub(started.elapsed())
        .ok_or_else(|| LifecycleError::new(LifecycleErrorCode::DeadlineExceeded))
}

#[cfg(test)]
mod tests {
    use super::{
        LifecycleError, LifecycleFuture, ReadinessGate, ShutdownAction, ShutdownCoordinator,
        ShutdownStep, StartupAction, StartupCoordinator, StartupStep,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct StartupRecorder {
        step: StartupStep,
        order: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl StartupAction for StartupRecorder {
        fn step(&self) -> StartupStep {
            self.step
        }

        fn execute(&self) -> LifecycleFuture<'_> {
            Box::pin(async move {
                self.order
                    .lock()
                    .map_err(|_error| LifecycleError::action_failed())?
                    .push(self.step.as_str());
                if self.fail {
                    Err(LifecycleError::action_failed())
                } else {
                    Ok(())
                }
            })
        }
    }

    struct ShutdownRecorder {
        step: ShutdownStep,
        order: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl ShutdownAction for ShutdownRecorder {
        fn step(&self) -> ShutdownStep {
            self.step
        }

        fn execute(&self) -> LifecycleFuture<'_> {
            Box::pin(async move {
                self.order
                    .lock()
                    .map_err(|_error| LifecycleError::action_failed())?
                    .push(self.step.as_str());
                if self.fail {
                    Err(LifecycleError::action_failed())
                } else {
                    Ok(())
                }
            })
        }
    }

    #[tokio::test]
    async fn startup_is_exactly_ordered_and_opens_readiness_last()
    -> Result<(), Box<dyn std::error::Error>> {
        let order = Arc::new(Mutex::new(Vec::new()));
        let actions: Vec<Arc<dyn StartupAction>> = StartupStep::ALL
            .into_iter()
            .rev()
            .map(|step| {
                Arc::new(StartupRecorder {
                    step,
                    order: Arc::clone(&order),
                    fail: false,
                }) as Arc<dyn StartupAction>
            })
            .collect();
        let readiness = Arc::new(ReadinessGate::default());
        let coordinator = StartupCoordinator::new(actions, Arc::clone(&readiness))?;
        let receipt = coordinator.run(Duration::from_secs(1)).await?;
        assert_eq!(receipt.completed, StartupStep::ALL);
        assert!(readiness.is_open());
        let observed = order
            .lock()
            .map_err(|_error| "startup order mutex poisoned")?
            .clone();
        let expected: Vec<_> = StartupStep::ALL
            .into_iter()
            .map(StartupStep::as_str)
            .collect();
        assert_eq!(observed, expected);
        Ok(())
    }

    #[tokio::test]
    async fn failed_startup_never_opens_readiness() -> Result<(), Box<dyn std::error::Error>> {
        let order = Arc::new(Mutex::new(Vec::new()));
        let actions: Vec<Arc<dyn StartupAction>> = StartupStep::ALL
            .into_iter()
            .map(|step| {
                Arc::new(StartupRecorder {
                    step,
                    order: Arc::clone(&order),
                    fail: step == StartupStep::JournalIntegrity,
                }) as Arc<dyn StartupAction>
            })
            .collect();
        let readiness = Arc::new(ReadinessGate::default());
        let coordinator = StartupCoordinator::new(actions, Arc::clone(&readiness))?;
        assert!(coordinator.run(Duration::from_secs(1)).await.is_err());
        assert!(!readiness.is_open());
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_closes_readiness_and_returns_exact_partial_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let order = Arc::new(Mutex::new(Vec::new()));
        let actions: Vec<Arc<dyn ShutdownAction>> = ShutdownStep::ALL
            .into_iter()
            .map(|step| {
                Arc::new(ShutdownRecorder {
                    step,
                    order: Arc::clone(&order),
                    fail: step == ShutdownStep::CheckpointWorkers,
                }) as Arc<dyn ShutdownAction>
            })
            .collect();
        let readiness = Arc::new(ReadinessGate::default());
        let coordinator = ShutdownCoordinator::new(actions, Arc::clone(&readiness))?;
        let receipt = coordinator.run(Duration::from_secs(1)).await;
        assert_eq!(receipt.failed, Some(ShutdownStep::CheckpointWorkers));
        assert_eq!(
            receipt.completed,
            vec![
                ShutdownStep::StopNewRequests,
                ShutdownStep::PreventDispatchClaims,
                ShutdownStep::DrainReadsAndCompiles,
            ]
        );
        assert!(!readiness.is_open());
        Ok(())
    }
}
