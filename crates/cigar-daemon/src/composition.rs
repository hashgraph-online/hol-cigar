//! Production composition inputs and real operational service facade.

use crate::{
    BlockingPool, DaemonConfig, DaemonFacadeErrorFactory, DaemonTelemetry, LifecycleError,
    LifecycleFuture, ProductionApplicationBuilder, ProductionFacade, QueueError, QueueErrorCode,
    ReadinessGate, ShutdownAction, ShutdownStep, StartupCoordinator, WorkerJob, WorkerKind,
    WorkerRuntime,
};
use cigar_api::{
    ApiError, EmptyRequest, FacadeErrorFactory, FacadeEventStream, HandlerRegistryError,
    ReadinessAggregator, RequestContext, RequestContextError, RequestEnvelope, ResponseEnvelope,
    ServiceFacade, ServiceFuture, TypedOperation, TypedRequest, TypedResponse, TypedUnaryService,
};
use cigar_api::{
    CapabilitiesResponse, ConfigurationResponse, DiagnosticCounter, DiagnosticsResponse,
    GetCapabilitiesOperation, GetConfigurationOperation, GetDiagnosticsOperation,
    GetLivenessOperation, GetMetricsOperation, GetReadinessOperation, GetVersionOperation,
    LivenessResponse, MetricsResponse, OperationPayload, PublicDeploymentMode, QueueDiagnostic,
    ReadinessResponse, VersionResponse, decode_operation_payload, decode_typed_request,
    encode_operation_payload,
};
use cigar_api::{MAX_EVENT_PAYLOAD_BYTES, MAX_OPERATION_PAYLOAD_BYTES};
use cigar_protocol::{BuildMetadata, ErrorCode, HealthStatus, UtcTimestamp};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Boxed future returned by durable shutdown hooks.
pub type ShutdownHookFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleError>> + Send + 'a>>;

/// Mandatory durable actions owned by the production service composition.
pub trait ShutdownHooks: Send + Sync {
    /// Persists durable worker cursors and checkpoints.
    fn checkpoint_workers(&self) -> ShutdownHookFuture<'_>;
    /// Releases renewable leases without changing effect truth.
    fn release_renewable_leases(&self) -> ShutdownHookFuture<'_>;
}

/// Worker controller that closes readiness when bounded queues become unavailable.
pub struct DaemonWorkers {
    runtime: Arc<WorkerRuntime>,
    readiness: Arc<ReadinessGate>,
    dispatch_claims: AtomicBool,
}

impl DaemonWorkers {
    /// Couples a validated worker runtime to the daemon readiness gate.
    #[must_use]
    pub const fn new(runtime: Arc<WorkerRuntime>, readiness: Arc<ReadinessGate>) -> Self {
        Self {
            runtime,
            readiness,
            dispatch_claims: AtomicBool::new(true),
        }
    }

    /// Enqueues one durable wakeup and fails readiness closed on exhaustion or worker loss.
    pub fn try_enqueue(&self, kind: WorkerKind, job: WorkerJob) -> Result<(), QueueError> {
        let result = self
            .runtime
            .queue(kind)
            .ok_or_else(|| QueueError::new(QueueErrorCode::Closed))
            .and_then(|queue| queue.try_enqueue(job));
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.code(),
                QueueErrorCode::Full
                    | QueueErrorCode::Closed
                    | QueueErrorCode::MetricsUnavailable
                    | QueueErrorCode::SequenceExhausted
            )
        }) {
            self.readiness.close();
        }
        result
    }

    /// Returns the underlying runtime used by shutdown and diagnostics.
    #[must_use]
    pub const fn runtime(&self) -> &Arc<WorkerRuntime> {
        &self.runtime
    }

    /// Prevents any new effect-dispatch claim while allowing already claimed non-dispatch work to
    /// drain. The durable outbox remains authoritative for skipped wakeups.
    pub fn stop_dispatch_claims(&self) {
        self.dispatch_claims.store(false, Ordering::Release);
    }

    /// Returns whether an outbox worker may begin a new dispatch claim.
    #[must_use]
    pub fn dispatch_claims_allowed(&self) -> bool {
        self.dispatch_claims.load(Ordering::Acquire)
    }
}

impl fmt::Debug for DaemonWorkers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonWorkers")
            .field("runtime", &self.runtime)
            .field("ready", &self.readiness.is_open())
            .finish()
    }
}

/// Exact dependencies required before the daemon can accept requests.
pub struct DaemonDependencies {
    /// Complete domain facade; no placeholder successes are installed.
    pub(crate) facade: Arc<dyn ServiceFacade>,
    /// Exact ordered recovery coordinator; readiness opens only after it succeeds.
    pub(crate) startup: StartupCoordinator,
    /// All eight mandatory dependency readiness probes.
    pub(crate) readiness: Arc<ReadinessAggregator>,
    /// Startup/shutdown request gate shared by lifecycle and worker supervision.
    pub(crate) readiness_gate: Arc<ReadinessGate>,
    /// Bounded worker runtime and readiness coupling.
    pub(crate) workers: Arc<DaemonWorkers>,
    /// Admission- and semaphore-bounded CPU/parsing execution pool.
    pub(crate) blocking_pool: Arc<BlockingPool>,
    /// Durable shutdown hooks implemented by concrete repositories/workers.
    pub(crate) shutdown_hooks: Arc<dyn ShutdownHooks>,
    /// Content-safe process telemetry with optional OTLP exporters.
    pub(crate) telemetry: Arc<DaemonTelemetry>,
}

impl DaemonDependencies {
    /// Creates production dependencies around a facade that is statically proven to contain all
    /// frozen operations and mandatory quota/idempotency governance.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn production(
        facade: Arc<ProductionFacade>,
        startup: StartupCoordinator,
        readiness: Arc<ReadinessAggregator>,
        readiness_gate: Arc<ReadinessGate>,
        workers: Arc<DaemonWorkers>,
        blocking_pool: Arc<BlockingPool>,
        shutdown_hooks: Arc<dyn ShutdownHooks>,
        telemetry: Arc<DaemonTelemetry>,
    ) -> Self {
        let facade: Arc<dyn ServiceFacade> = facade;
        Self {
            facade,
            startup,
            readiness,
            readiness_gate,
            workers,
            blocking_pool,
            shutdown_hooks,
            telemetry,
        }
    }
}

impl fmt::Debug for DaemonDependencies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonDependencies")
            .field("facade", &"[INJECTED COMPLETE FACADE]")
            .field("startup", &self.startup)
            .field("readiness", &self.readiness)
            .field("readiness_gate", &self.readiness_gate)
            .field("workers", &self.workers)
            .field("blocking_pool", &self.blocking_pool)
            .field("shutdown_hooks", &"[INJECTED]")
            .field("telemetry", &self.telemetry)
            .finish()
    }
}

/// Shared typed implementation of all seven daemon-owned operational methods.
pub struct OperationalHandlers {
    config: SafeConfiguration,
    readiness: Arc<ReadinessAggregator>,
    readiness_gate: Arc<ReadinessGate>,
    workers: Arc<DaemonWorkers>,
    blocking_pool: Option<Arc<BlockingPool>>,
    effects_enabled: bool,
    telemetry: Arc<DaemonTelemetry>,
    errors: Arc<dyn FacadeErrorFactory>,
}

impl OperationalHandlers {
    /// Creates operational handlers over the exact runtime state they report.
    #[must_use]
    pub fn new(
        config: &DaemonConfig,
        readiness: Arc<ReadinessAggregator>,
        readiness_gate: Arc<ReadinessGate>,
        workers: Arc<DaemonWorkers>,
        telemetry: Arc<DaemonTelemetry>,
        errors: Arc<dyn FacadeErrorFactory>,
    ) -> Self {
        Self {
            config: SafeConfiguration::from(config),
            readiness,
            readiness_gate,
            workers,
            blocking_pool: None,
            effects_enabled: false,
            telemetry,
            errors,
        }
    }

    /// Creates handlers with the exact production blocking pool they report.
    #[must_use]
    pub fn new_with_blocking_pool(
        config: &DaemonConfig,
        readiness: Arc<ReadinessAggregator>,
        readiness_gate: Arc<ReadinessGate>,
        workers: Arc<DaemonWorkers>,
        blocking_pool: Arc<BlockingPool>,
        telemetry: Arc<DaemonTelemetry>,
        errors: Arc<dyn FacadeErrorFactory>,
    ) -> Self {
        let mut handlers = Self::new(
            config,
            readiness,
            readiness_gate,
            workers,
            telemetry,
            errors,
        );
        handlers.blocking_pool = Some(blocking_pool);
        handlers
    }

    /// Selects the capability profile proven by the validated production effect registry.
    #[must_use]
    pub const fn with_effects_enabled(mut self, effects_enabled: bool) -> Self {
        self.effects_enabled = effects_enabled;
        self
    }

    fn error(&self, code: ErrorCode) -> ApiError {
        self.errors.public_error(code)
    }

    fn call_registered<O>(
        &self,
        context: RequestContext,
    ) -> Result<TypedResponse<O::Response>, ApiError>
    where
        O: TypedOperation<Request = EmptyRequest>,
    {
        let request = RequestEnvelope::new(
            O::OPERATION_ID,
            Vec::new(),
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .map_err(|_error| self.error(ErrorCode::Internal))?;
        let response = self
            .operational_response(&context, &request)?
            .ok_or_else(|| self.error(ErrorCode::Internal))?;
        let payload = decode_operation_payload::<O::Response>(
            response.payload_cbor(),
            MAX_OPERATION_PAYLOAD_BYTES,
        )
        .map_err(|_error| self.error(ErrorCode::Internal))?;
        Ok(TypedResponse {
            payload,
            semantic_etag: response.semantic_etag().map(str::to_owned),
            next_page_cursor: response.next_page_cursor().map(str::to_owned),
        })
    }

    fn operational_response(
        &self,
        context: &RequestContext,
        request: &RequestEnvelope,
    ) -> Result<Option<ResponseEnvelope>, ApiError> {
        let now = now_utc().map_err(|()| self.error(ErrorCode::Internal))?;
        context.check_active(now).map_err(|failure| {
            let code = match failure {
                RequestContextError::Cancelled | RequestContextError::DeadlineExceeded => {
                    ErrorCode::DeadlineExceeded
                }
                RequestContextError::InvalidDeadline | RequestContextError::InvalidField => {
                    ErrorCode::Internal
                }
            };
            self.error(code)
        })?;
        let operation = request.operation_id().as_str();
        match operation {
            "getLiveness" => {
                self.require_empty::<GetLivenessOperation>(request)?;
                self.typed_response(operation, LivenessResponse { live: true })
            }
            "getReadiness" => {
                self.require_empty::<GetReadinessOperation>(request)?;
                let report = self
                    .readiness
                    .report(now)
                    .map_err(|_error| self.error(ErrorCode::DependencyDegraded))?;
                let gate_open = self.readiness_gate.is_open();
                self.typed_response(
                    operation,
                    ReadinessResponse {
                        ready: gate_open && report.status == HealthStatus::Healthy,
                        gate_open,
                        dependency_report: report,
                    },
                )
            }
            "getVersion" => {
                self.require_empty::<GetVersionOperation>(request)?;
                let metadata = BuildMetadata::current(env!("CARGO_PKG_VERSION"));
                self.typed_response(
                    operation,
                    VersionResponse {
                        version: metadata.version.to_owned(),
                        source_revision: metadata.source_revision.to_owned(),
                        protocol_min: metadata.protocol_min.to_owned(),
                        protocol_max: metadata.protocol_max.to_owned(),
                        build_profile: metadata.build_profile.to_owned(),
                        enabled_features: Vec::new(),
                    },
                )
            }
            "getCapabilities" => {
                self.require_empty::<GetCapabilitiesOperation>(request)?;
                let max_payload_bytes = u32::try_from(MAX_OPERATION_PAYLOAD_BYTES)
                    .map_err(|_error| self.error(ErrorCode::Internal))?;
                let max_event_bytes = u32::try_from(MAX_EVENT_PAYLOAD_BYTES)
                    .map_err(|_error| self.error(ErrorCode::Internal))?;
                let profile = match self.config.mode {
                    crate::DeploymentMode::Local => "local",
                    crate::DeploymentMode::Shared => "shared",
                };
                let effects_profile = effect_capability_profile(self.effects_enabled);
                self.typed_response(
                    operation,
                    CapabilitiesResponse {
                        api_version: "v1".to_owned(),
                        protocol_version: cigar_protocol::PROTOCOL_MAX.to_owned(),
                        profiles: vec![effects_profile.to_owned(), profile.to_owned()],
                        extensions: Vec::new(),
                        max_payload_bytes,
                        max_event_bytes,
                        max_page_size: 1_000,
                    },
                )
            }
            "getConfiguration" => {
                self.require_empty::<GetConfigurationOperation>(request)?;
                self.typed_response(operation, self.configuration_response()?)
            }
            "getDiagnostics" => {
                self.require_empty::<GetDiagnosticsOperation>(request)?;
                let dependency_report = self
                    .readiness
                    .report(now)
                    .map_err(|_error| self.error(ErrorCode::DependencyDegraded))?;
                let ready = self.readiness_gate.is_open()
                    && dependency_report.status == HealthStatus::Healthy;
                let snapshots = self
                    .workers
                    .runtime()
                    .metrics()
                    .map_err(|_error| self.error(ErrorCode::DependencyDegraded))?;
                if let Some(blocking_pool) = &self.blocking_pool {
                    self.telemetry
                        .observe_runtime(&snapshots, blocking_pool.metrics());
                }
                let mut queues = snapshots
                    .iter()
                    .map(|queue| {
                        Ok(QueueDiagnostic {
                            name: queue.kind.as_str().to_owned(),
                            capacity: u32::try_from(queue.capacity)
                                .map_err(|_error| self.error(ErrorCode::Internal))?,
                            depth: u32::try_from(queue.depth)
                                .map_err(|_error| self.error(ErrorCode::Internal))?,
                            rejected: queue.rejection_count,
                            worker_healthy: queue.accepting && self.readiness_gate.is_open(),
                        })
                    })
                    .collect::<Result<Vec<_>, ApiError>>()?;
                queues.sort_by(|left, right| left.name.cmp(&right.name));
                let telemetry = self.telemetry.snapshot();
                let counters = vec![
                    DiagnosticCounter {
                        name: "authorized_requests".to_owned(),
                        value: telemetry.authorized_requests,
                    },
                    DiagnosticCounter {
                        name: "graceful_shutdowns".to_owned(),
                        value: telemetry.graceful_shutdowns,
                    },
                    DiagnosticCounter {
                        name: "listener_failures".to_owned(),
                        value: telemetry.listener_failures,
                    },
                    DiagnosticCounter {
                        name: "rejected_requests".to_owned(),
                        value: telemetry.rejected_requests,
                    },
                ];
                self.typed_response(
                    operation,
                    DiagnosticsResponse {
                        ready,
                        queues,
                        counters,
                    },
                )
            }
            "getMetrics" => {
                self.require_empty::<GetMetricsOperation>(request)?;
                let queues = self
                    .workers
                    .runtime()
                    .metrics()
                    .map_err(|_error| self.error(ErrorCode::DependencyDegraded))?;
                if let Some(blocking_pool) = &self.blocking_pool {
                    self.telemetry
                        .observe_runtime(&queues, blocking_pool.metrics());
                }
                self.typed_response(
                    operation,
                    MetricsResponse {
                        media_type: "application/openmetrics-text; version=1.0.0; charset=utf-8"
                            .to_owned(),
                        text: self.telemetry.render_openmetrics(&queues),
                    },
                )
            }
            _ => Ok(None),
        }
    }

    fn require_empty<O: cigar_api::TypedOperation>(
        &self,
        request: &RequestEnvelope,
    ) -> Result<(), ApiError> {
        decode_typed_request::<O>(request)
            .map(|_payload| ())
            .map_err(|_error| self.error(ErrorCode::InvalidArgument))
    }

    fn typed_response<T: OperationPayload>(
        &self,
        operation: &str,
        response: T,
    ) -> Result<Option<ResponseEnvelope>, ApiError> {
        let payload = encode_operation_payload(&response, MAX_OPERATION_PAYLOAD_BYTES)
            .map_err(|_error| self.error(ErrorCode::Internal))?;
        ResponseEnvelope::new(operation, payload, None, None)
            .map(Some)
            .map_err(|_error| self.error(ErrorCode::Internal))
    }

    fn configuration_response(&self) -> Result<ConfigurationResponse, ApiError> {
        Ok(ConfigurationResponse {
            mode: match self.config.mode {
                crate::DeploymentMode::Local => PublicDeploymentMode::Local,
                crate::DeploymentMode::Shared => PublicDeploymentMode::Shared,
            },
            local_ipc: self.config.local_ipc,
            http_enabled: self.config.http_listen.is_some(),
            grpc_enabled: self.config.grpc_listen.is_some(),
            max_request_bytes: u32::try_from(self.config.max_request_bytes)
                .map_err(|_error| self.error(ErrorCode::Internal))?,
            max_timeout_ms: self.config.request_deadline_ms,
        })
    }
}

macro_rules! impl_operational_unary {
    ($operation:ty) => {
        impl TypedUnaryService<$operation> for OperationalHandlers {
            fn call_typed<'a>(
                &'a self,
                context: RequestContext,
                _request: TypedRequest<EmptyRequest>,
            ) -> ServiceFuture<
                'a,
                Result<TypedResponse<<$operation as TypedOperation>::Response>, ApiError>,
            > {
                Box::pin(async move { self.call_registered::<$operation>(context) })
            }
        }
    };
}

impl_operational_unary!(GetLivenessOperation);
impl_operational_unary!(GetReadinessOperation);
impl_operational_unary!(GetVersionOperation);
impl_operational_unary!(GetCapabilitiesOperation);
impl_operational_unary!(GetConfigurationOperation);
impl_operational_unary!(GetDiagnosticsOperation);
impl_operational_unary!(GetMetricsOperation);

/// Registers the seven daemon-owned operational methods into the exact typed application.
pub fn register_operational_handlers(
    builder: &mut ProductionApplicationBuilder,
    handlers: Arc<OperationalHandlers>,
) -> Result<(), HandlerRegistryError> {
    builder.register_unary::<GetLivenessOperation, _>(Arc::clone(&handlers))?;
    builder.register_unary::<GetReadinessOperation, _>(Arc::clone(&handlers))?;
    builder.register_unary::<GetVersionOperation, _>(Arc::clone(&handlers))?;
    builder.register_unary::<GetCapabilitiesOperation, _>(Arc::clone(&handlers))?;
    builder.register_unary::<GetConfigurationOperation, _>(Arc::clone(&handlers))?;
    builder.register_unary::<GetDiagnosticsOperation, _>(Arc::clone(&handlers))?;
    builder.register_unary::<GetMetricsOperation, _>(handlers)?;
    Ok(())
}

/// Facade decorator preserving daemon-owned operational behavior around the complete registry.
pub struct OperationalFacade {
    delegate: Arc<dyn ServiceFacade>,
    handlers: Arc<OperationalHandlers>,
}

impl OperationalFacade {
    /// Wraps a complete domain facade with daemon-owned operational behavior.
    pub fn new(
        delegate: Arc<dyn ServiceFacade>,
        config: &DaemonConfig,
        readiness: Arc<ReadinessAggregator>,
        readiness_gate: Arc<ReadinessGate>,
        workers: Arc<DaemonWorkers>,
        telemetry: Arc<DaemonTelemetry>,
    ) -> Result<Self, cigar_protocol::ValidationErrors> {
        let errors: Arc<dyn FacadeErrorFactory> = Arc::new(DaemonFacadeErrorFactory::new()?);
        Ok(Self::with_handlers(
            delegate,
            Arc::new(OperationalHandlers::new(
                config,
                readiness,
                readiness_gate,
                workers,
                telemetry,
                errors,
            )),
        ))
    }

    /// Wraps a facade with the same operational handler instance registered for embedded mode.
    #[must_use]
    pub fn with_handlers(
        delegate: Arc<dyn ServiceFacade>,
        handlers: Arc<OperationalHandlers>,
    ) -> Self {
        Self { delegate, handlers }
    }

    /// Returns the exact typed operational handler state.
    #[must_use]
    pub const fn handlers(&self) -> &Arc<OperationalHandlers> {
        &self.handlers
    }
}

impl ServiceFacade for OperationalFacade {
    fn call<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<ResponseEnvelope, ApiError>> {
        Box::pin(async move {
            if let Some(response) = self.handlers.operational_response(&context, &request)? {
                Ok(response)
            } else {
                self.delegate.call(context, request).await
            }
        })
    }

    fn subscribe<'a>(
        &'a self,
        context: RequestContext,
        request: RequestEnvelope,
    ) -> ServiceFuture<'a, Result<FacadeEventStream, ApiError>> {
        self.delegate.subscribe(context, request)
    }
}

impl fmt::Debug for OperationalFacade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalFacade")
            .field("delegate", &"[INJECTED COMPLETE FACADE]")
            .field("handlers", &self.handlers)
            .finish()
    }
}

impl fmt::Debug for OperationalHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalHandlers")
            .field("config", &self.config)
            .field("ready", &self.readiness_gate.is_open())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct SafeConfiguration {
    mode: crate::DeploymentMode,
    http_listen: Option<std::net::SocketAddr>,
    grpc_listen: Option<std::net::SocketAddr>,
    local_ipc: bool,
    request_deadline_ms: u64,
    max_request_bytes: usize,
}

impl From<&DaemonConfig> for SafeConfiguration {
    fn from(config: &DaemonConfig) -> Self {
        Self {
            mode: config.mode,
            http_listen: config.http_listen,
            grpc_listen: config.grpc_listen,
            local_ipc: config.unix_socket.is_some() || config.windows_named_pipe.is_some(),
            request_deadline_ms: config.request_deadline_ms,
            max_request_bytes: config.max_request_bytes,
        }
    }
}

fn now_utc() -> Result<UtcTimestamp, ()> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| ())?;
    let nanos = i128::try_from(duration.as_nanos()).map_err(|_error| ())?;
    UtcTimestamp::from_unix_nanos(nanos).map_err(|_error| ())
}

const fn effect_capability_profile(effects_enabled: bool) -> &'static str {
    if effects_enabled {
        "effects-enabled"
    } else {
        "effects-disabled"
    }
}

pub(crate) struct RuntimeShutdownAction {
    pub step: ShutdownStep,
    pub readiness: Arc<ReadinessGate>,
    pub workers: Arc<DaemonWorkers>,
    pub blocking_pool: Arc<BlockingPool>,
    pub hooks: Arc<dyn ShutdownHooks>,
    pub telemetry: Arc<DaemonTelemetry>,
    pub listener_shutdown: tokio::sync::watch::Sender<bool>,
    pub telemetry_timeout: std::time::Duration,
}

impl ShutdownAction for RuntimeShutdownAction {
    fn step(&self) -> ShutdownStep {
        self.step
    }

    fn execute(&self) -> LifecycleFuture<'_> {
        Box::pin(async move {
            match self.step {
                ShutdownStep::StopNewRequests => {
                    self.readiness.close();
                    let _ignored = self.listener_shutdown.send(true);
                    Ok(())
                }
                ShutdownStep::PreventDispatchClaims => {
                    self.workers.stop_dispatch_claims();
                    self.workers.runtime().stop_accepting();
                    Ok(())
                }
                ShutdownStep::DrainReadsAndCompiles => loop {
                    if self
                        .workers
                        .runtime()
                        .is_drained()
                        .map_err(|_error| LifecycleError::action_failed())?
                        && self.blocking_pool.is_drained()
                    {
                        self.blocking_pool.stop_accepting();
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                },
                ShutdownStep::CheckpointWorkers => self.hooks.checkpoint_workers().await,
                ShutdownStep::ReleaseRenewableLeases => self.hooks.release_renewable_leases().await,
                ShutdownStep::FlushTelemetry => {
                    self.telemetry.record_graceful_shutdown();
                    self.telemetry
                        .shutdown_otlp(self.telemetry_timeout)
                        .map_err(|_error| LifecycleError::action_failed())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::effect_capability_profile;

    #[test]
    fn capability_profile_reflects_both_validated_effect_registry_states() {
        assert_eq!(effect_capability_profile(false), "effects-disabled");
        assert_eq!(effect_capability_profile(true), "effects-enabled");
    }
}
