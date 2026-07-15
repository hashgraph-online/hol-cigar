//! Content-safe aggregate daemon status and bounded reconnect monitor.

use crate::{
    DaemonGateway, DashboardMetrics, DashboardTargetConfig, GatewayComponentStatus,
    GatewayConfigurationObservation, GatewayDeploymentMode, GatewayDiagnosticsObservation,
    GatewayError, GatewayObservation, SafeEventAttribute, SafeEventAttributes, SafeEventBroker,
    SafeEventKind,
};
use cigar_sdk::ServerCompatibility;
use serde::Serialize;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

const STALE_AFTER: Duration = Duration::from_secs(10);
const UNREACHABLE_AFTER: Duration = Duration::from_secs(30);
const UNREACHABLE_FAILURES: u32 = 3;

/// Stable content-free status service failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    /// The current UTC observation time could not be represented.
    ClockUnavailable,
    /// The bounded content-safe event plane could not initialize or retain a transition.
    EventUnavailable,
}

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClockUnavailable => "dashboard status clock is unavailable",
            Self::EventUnavailable => "dashboard status event plane is unavailable",
        })
    }
}

impl std::error::Error for StatusError {}

/// Closed aggregate status ordered by dashboard precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateStatus {
    /// No valid compatible observation has completed.
    Starting,
    /// Every required typed observation is current and healthy.
    Healthy,
    /// A component is degraded or the last valid observation is stale.
    Degraded,
    /// Liveness, the readiness gate, or a required component is unhealthy.
    Unhealthy,
    /// Bounded failures or elapsed freshness make the target unreachable.
    Unreachable,
    /// SDK compatibility negotiation rejected the target.
    Incompatible,
}

impl AggregateStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unreachable => "unreachable",
            Self::Incompatible => "incompatible",
        }
    }
}

/// Closed component status exposed to the browser.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardComponentStatus {
    /// Component is operating normally.
    Healthy,
    /// Component is available with reduced guarantees.
    Degraded,
    /// Component is unavailable for required operations.
    Unhealthy,
    /// A future platform probe explicitly lacks support.
    Unsupported,
}

/// Public SDK-verified daemon build and protocol line.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardVersion {
    package: String,
    source_revision: String,
    protocol_min: String,
    protocol_max: String,
    api_version: String,
}

/// One current or retained content-safe readiness component.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardComponent {
    name: String,
    status: DashboardComponentStatus,
    reason: Option<String>,
    observed_at: String,
    latency_ms: u64,
    stale: bool,
}

/// Closed public deployment mode exposed by the redacted configuration endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardDeploymentMode {
    /// Permission-restricted local service.
    Local,
    /// TLS-authenticated shared service.
    Shared,
}

/// Latest SDK-validated redacted daemon configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfiguration {
    mode: DashboardDeploymentMode,
    local_ipc: bool,
    http_enabled: bool,
    grpc_enabled: bool,
    max_request_bytes: u32,
    max_timeout_ms: u64,
    observed_at: String,
    latency_ms: u64,
}

/// One closed worker heartbeat state from typed diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardWorkerHealth {
    worker: String,
    healthy: bool,
}

/// Latest cross-validated diagnostic and OpenMetrics snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardDiagnostics {
    ready: bool,
    workers: Vec<DashboardWorkerHealth>,
    metrics: DashboardMetrics,
    observed_at: String,
    latency_ms: u64,
    stale: bool,
}

/// Complete browser-safe aggregate status response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardStatus {
    schema_version: &'static str,
    aggregate: AggregateStatus,
    target_alias: String,
    observed_at: String,
    freshness_ms: u64,
    consecutive_failures: u32,
    control_enabled: bool,
    version: Option<DashboardVersion>,
    configuration: Option<DashboardConfiguration>,
    diagnostics: Option<DashboardDiagnostics>,
    components: Vec<DashboardComponent>,
}

impl DashboardStatus {
    /// Returns the current aggregate classification.
    #[must_use]
    pub const fn aggregate(&self) -> AggregateStatus {
        self.aggregate
    }

    /// Returns failures since the last valid observation.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

struct StatusState {
    snapshot: DashboardStatus,
    readiness_aggregate: AggregateStatus,
    last_valid: Option<Instant>,
}

/// Cloneable status snapshot broker used by the HTTP API and monitor task.
#[derive(Clone)]
pub struct StatusService {
    state: Arc<RwLock<StatusState>>,
    events: SafeEventBroker,
}

impl StatusService {
    /// Creates the explicit pre-observation `starting` status.
    pub fn new(target_alias: String, control_enabled: bool) -> Result<Self, StatusError> {
        let events = SafeEventBroker::new(128, 1024 * 1024, 64 * 1024, 16)
            .map_err(|_error| StatusError::EventUnavailable)?;
        Self::with_events(target_alias, control_enabled, events)
    }

    /// Creates a status service on an explicitly bounded shared event broker.
    pub fn with_events(
        target_alias: String,
        control_enabled: bool,
        events: SafeEventBroker,
    ) -> Result<Self, StatusError> {
        let service = Self {
            state: Arc::new(RwLock::new(StatusState {
                snapshot: DashboardStatus {
                    schema_version: "cigar.dashboard-status.v1",
                    aggregate: AggregateStatus::Starting,
                    target_alias,
                    observed_at: now_rfc3339()?,
                    freshness_ms: 0,
                    consecutive_failures: 0,
                    control_enabled,
                    version: None,
                    configuration: None,
                    diagnostics: None,
                    components: Vec::new(),
                },
                readiness_aggregate: AggregateStatus::Starting,
                last_valid: None,
            })),
            events,
        };
        service.publish_status_event("status.starting", AggregateStatus::Starting, 0, 0)?;
        Ok(service)
    }

    /// Returns a consistent immutable status snapshot.
    pub async fn snapshot(&self) -> DashboardStatus {
        self.state.read().await.snapshot.clone()
    }

    /// Returns the same bounded broker used for status transition delivery.
    #[must_use]
    pub fn event_broker(&self) -> SafeEventBroker {
        self.events.clone()
    }

    async fn record_success(
        &self,
        compatibility: &ServerCompatibility,
        observation: GatewayObservation,
    ) -> Result<(), StatusError> {
        let observed_at = now_rfc3339()?;
        let aggregate = classify_success(&observation);
        let components = observation
            .components
            .into_iter()
            .map(|component| DashboardComponent {
                name: component.name,
                status: match component.status {
                    GatewayComponentStatus::Healthy => DashboardComponentStatus::Healthy,
                    GatewayComponentStatus::Degraded => DashboardComponentStatus::Degraded,
                    GatewayComponentStatus::Unhealthy => DashboardComponentStatus::Unhealthy,
                },
                reason: component.reason,
                observed_at: observed_at.clone(),
                latency_ms: observation.latency_ms,
                stale: false,
            })
            .collect::<Vec<_>>();
        let mut state = self.state.write().await;
        let previous = state.snapshot.aggregate;
        state.readiness_aggregate = aggregate;
        state.snapshot.aggregate =
            aggregate_with_diagnostics(aggregate, state.snapshot.diagnostics.as_ref());
        state.snapshot.observed_at = observed_at;
        state.snapshot.freshness_ms = 0;
        state.snapshot.consecutive_failures = 0;
        state.snapshot.version = Some(DashboardVersion {
            package: compatibility.version.version.clone(),
            source_revision: compatibility.version.source_revision.clone(),
            protocol_min: compatibility.version.protocol_min.clone(),
            protocol_max: compatibility.version.protocol_max.clone(),
            api_version: compatibility.capabilities.api_version.clone(),
        });
        state.snapshot.components = components;
        state.last_valid = Some(Instant::now());
        let current = state.snapshot.aggregate;
        drop(state);
        if previous != current {
            self.publish_status_event(status_code(current), current, 0, 0)?;
        }
        Ok(())
    }

    async fn record_configuration(
        &self,
        observation: GatewayConfigurationObservation,
    ) -> Result<(), StatusError> {
        let configuration = DashboardConfiguration {
            mode: match observation.mode {
                GatewayDeploymentMode::Local => DashboardDeploymentMode::Local,
                GatewayDeploymentMode::Shared => DashboardDeploymentMode::Shared,
            },
            local_ipc: observation.local_ipc,
            http_enabled: observation.http_enabled,
            grpc_enabled: observation.grpc_enabled,
            max_request_bytes: observation.max_request_bytes,
            max_timeout_ms: observation.max_timeout_ms,
            observed_at: now_rfc3339()?,
            latency_ms: observation.latency_ms,
        };
        self.state.write().await.snapshot.configuration = Some(configuration);
        let mut attributes = SafeEventAttributes::new();
        attributes.insert(
            "configuration".to_owned(),
            SafeEventAttribute::Text("observed".to_owned()),
        );
        self.events
            .publish(
                SafeEventKind::Status,
                "status.configuration_observed",
                None,
                attributes,
            )
            .map_err(|_error| StatusError::EventUnavailable)?;
        Ok(())
    }

    async fn record_diagnostics(
        &self,
        observation: GatewayDiagnosticsObservation,
    ) -> Result<(), StatusError> {
        let unhealthy =
            !observation.ready || observation.workers.iter().any(|worker| !worker.healthy);
        let diagnostics = DashboardDiagnostics {
            ready: observation.ready,
            workers: observation
                .workers
                .into_iter()
                .map(|worker| DashboardWorkerHealth {
                    worker: worker.worker,
                    healthy: worker.healthy,
                })
                .collect(),
            metrics: observation.metrics,
            observed_at: now_rfc3339()?,
            latency_ms: observation.latency_ms,
            stale: false,
        };
        let mut state = self.state.write().await;
        let previous = state.snapshot.aggregate;
        state.snapshot.diagnostics = Some(diagnostics);
        if state.snapshot.consecutive_failures == 0 {
            state.snapshot.aggregate = if unhealthy {
                AggregateStatus::Unhealthy
            } else {
                state.readiness_aggregate
            };
        }
        let current = state.snapshot.aggregate;
        let failures = state.snapshot.consecutive_failures;
        let freshness = state.snapshot.freshness_ms;
        drop(state);
        if previous != current {
            self.publish_status_event(status_code(current), current, failures, freshness)?;
        }
        Ok(())
    }

    async fn record_diagnostics_failure(&self) -> Result<(), StatusError> {
        let mut state = self.state.write().await;
        let previous = state.snapshot.aggregate;
        if let Some(diagnostics) = &mut state.snapshot.diagnostics {
            diagnostics.stale = true;
        }
        if state.snapshot.aggregate == AggregateStatus::Healthy {
            state.snapshot.aggregate = AggregateStatus::Degraded;
        }
        let current = state.snapshot.aggregate;
        let failures = state.snapshot.consecutive_failures;
        let freshness = state.snapshot.freshness_ms;
        drop(state);
        if previous != current {
            self.publish_status_event(status_code(current), current, failures, freshness)?;
        } else {
            self.publish_status_event("status.diagnostics_stale", current, failures, freshness)?;
        }
        Ok(())
    }

    async fn record_failure(&self, error: GatewayError) -> Result<u32, StatusError> {
        let observed_at = now_rfc3339()?;
        let mut state = self.state.write().await;
        state.snapshot.consecutive_failures = state.snapshot.consecutive_failures.saturating_add(1);
        state.snapshot.observed_at = observed_at;
        let freshness = state
            .last_valid
            .map_or(Duration::ZERO, |instant| instant.elapsed());
        state.snapshot.freshness_ms = duration_millis(freshness);
        let incompatible = error == GatewayError::Incompatible;
        state.snapshot.aggregate = if incompatible {
            AggregateStatus::Incompatible
        } else if state.last_valid.is_none()
            || state.snapshot.consecutive_failures >= UNREACHABLE_FAILURES
            || freshness >= UNREACHABLE_AFTER
        {
            AggregateStatus::Unreachable
        } else if freshness >= STALE_AFTER {
            AggregateStatus::Degraded
        } else {
            state.snapshot.aggregate
        };
        let stale = freshness >= STALE_AFTER;
        for component in &mut state.snapshot.components {
            component.stale = stale;
        }
        let failures = state.snapshot.consecutive_failures;
        let aggregate = state.snapshot.aggregate;
        let freshness = state.snapshot.freshness_ms;
        drop(state);
        let mut attributes = status_attributes(aggregate, failures, freshness);
        attributes.insert(
            "failure".to_owned(),
            SafeEventAttribute::Text(gateway_error_name(error).to_owned()),
        );
        self.events
            .publish(
                SafeEventKind::Status,
                "status.probe_failed",
                None,
                attributes,
            )
            .map_err(|_error| StatusError::EventUnavailable)?;
        Ok(failures)
    }

    fn publish_status_event(
        &self,
        code: &'static str,
        aggregate: AggregateStatus,
        failures: u32,
        freshness_ms: u64,
    ) -> Result<(), StatusError> {
        self.events
            .publish(
                SafeEventKind::Status,
                code,
                None,
                status_attributes(aggregate, failures, freshness_ms),
            )
            .map(|_event| ())
            .map_err(|_error| StatusError::EventUnavailable)
    }
}

impl fmt::Debug for StatusService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StatusService([CONTENT-SAFE SNAPSHOT])")
    }
}

/// Owned cancellation and join handle for one bounded status monitor.
pub struct StatusMonitor {
    cancellation: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl StatusMonitor {
    /// Starts typed compatibility negotiation and bounded polling in the current Tokio runtime.
    #[must_use]
    pub fn start(service: StatusService, target: DashboardTargetConfig) -> Self {
        let (cancellation, receiver) = watch::channel(false);
        let task = tokio::spawn(run_monitor(service, target, receiver));
        Self {
            cancellation,
            task: Some(task),
        }
    }

    /// Cancels polling and waits for the monitor task to stop.
    pub async fn shutdown(mut self) {
        let _ignored = self.cancellation.send(true);
        if let Some(task) = self.task.take() {
            let _ignored = task.await;
        }
    }
}

impl fmt::Debug for StatusMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusMonitor")
            .field("running", &self.task.is_some())
            .finish()
    }
}

impl Drop for StatusMonitor {
    fn drop(&mut self) {
        let _ignored = self.cancellation.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run_monitor(
    service: StatusService,
    target: DashboardTargetConfig,
    mut cancellation: watch::Receiver<bool>,
) {
    let mut reconnect = Duration::from_secs(1);
    loop {
        if *cancellation.borrow() {
            return;
        }
        let gateway = match DaemonGateway::connect(&target).await {
            Ok(gateway) => gateway,
            Err(error) => {
                let _ignored = service.record_failure(error).await;
                if wait_or_cancel(reconnect, &mut cancellation).await {
                    return;
                }
                reconnect = reconnect.saturating_mul(2).min(Duration::from_secs(30));
                continue;
            }
        };
        reconnect = Duration::from_secs(1);
        let configuration = match gateway.observe_configuration().await {
            Ok(configuration) => configuration,
            Err(error) => {
                let _ignored = service.record_failure(error).await;
                if wait_or_cancel(reconnect, &mut cancellation).await {
                    return;
                }
                continue;
            }
        };
        let _ignored = service.record_configuration(configuration).await;
        let identity_deadline = Instant::now()
            .checked_add(Duration::from_millis(target.identity_interval_ms))
            .unwrap_or_else(Instant::now);
        let mut diagnostics_deadline = Instant::now();
        loop {
            match gateway.observe().await {
                Ok(observation) => {
                    let _ignored = service
                        .record_success(gateway.compatibility(), observation)
                        .await;
                }
                Err(error) => {
                    let failures = service.record_failure(error).await.unwrap_or(u32::MAX);
                    if failures >= UNREACHABLE_FAILURES {
                        break;
                    }
                }
            }
            if Instant::now() >= diagnostics_deadline {
                match gateway.observe_diagnostics().await {
                    Ok(observation) => {
                        let _ignored = service.record_diagnostics(observation).await;
                    }
                    Err(_error) => {
                        let _ignored = service.record_diagnostics_failure().await;
                    }
                }
                diagnostics_deadline = Instant::now()
                    .checked_add(Duration::from_millis(target.diagnostics_interval_ms))
                    .unwrap_or_else(Instant::now);
            }
            if Instant::now() >= identity_deadline
                || wait_or_cancel(
                    Duration::from_millis(target.status_interval_ms),
                    &mut cancellation,
                )
                .await
            {
                if *cancellation.borrow() {
                    return;
                }
                break;
            }
        }
    }
}

async fn wait_or_cancel(duration: Duration, cancellation: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        result = cancellation.changed() => result.is_err() || *cancellation.borrow(),
    }
}

fn classify_success(observation: &GatewayObservation) -> AggregateStatus {
    if !observation.live
        || !observation.gate_open
        || !observation.ready
        || observation
            .components
            .iter()
            .any(|component| component.status == GatewayComponentStatus::Unhealthy)
    {
        AggregateStatus::Unhealthy
    } else if observation
        .components
        .iter()
        .any(|component| component.status == GatewayComponentStatus::Degraded)
    {
        AggregateStatus::Degraded
    } else {
        AggregateStatus::Healthy
    }
}

fn aggregate_with_diagnostics(
    readiness: AggregateStatus,
    diagnostics: Option<&DashboardDiagnostics>,
) -> AggregateStatus {
    if readiness != AggregateStatus::Healthy {
        return readiness;
    }
    match diagnostics {
        Some(diagnostics) if diagnostics.stale => AggregateStatus::Degraded,
        Some(diagnostics)
            if !diagnostics.ready || diagnostics.workers.iter().any(|worker| !worker.healthy) =>
        {
            AggregateStatus::Unhealthy
        }
        _ => AggregateStatus::Healthy,
    }
}

fn status_attributes(
    aggregate: AggregateStatus,
    failures: u32,
    freshness_ms: u64,
) -> SafeEventAttributes {
    let mut attributes = SafeEventAttributes::new();
    attributes.insert(
        "aggregate".to_owned(),
        SafeEventAttribute::Text(aggregate.as_str().to_owned()),
    );
    attributes.insert(
        "consecutive_failures".to_owned(),
        SafeEventAttribute::Unsigned(u64::from(failures)),
    );
    attributes.insert(
        "freshness_ms".to_owned(),
        SafeEventAttribute::Unsigned(freshness_ms),
    );
    attributes
}

fn status_code(aggregate: AggregateStatus) -> &'static str {
    match aggregate {
        AggregateStatus::Starting => "status.starting",
        AggregateStatus::Healthy => "status.healthy",
        AggregateStatus::Degraded => "status.degraded",
        AggregateStatus::Unhealthy => "status.unhealthy",
        AggregateStatus::Unreachable => "status.unreachable",
        AggregateStatus::Incompatible => "status.incompatible",
    }
}

fn gateway_error_name(error: GatewayError) -> &'static str {
    match error {
        GatewayError::Incompatible => "incompatible",
        GatewayError::Unavailable => "unavailable",
        GatewayError::Protocol => "protocol",
    }
}

fn now_rfc3339() -> Result<String, StatusError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_error| StatusError::ClockUnavailable)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{AggregateStatus, DashboardComponentStatus, StatusService};
    use crate::{
        DashboardMetrics, DashboardQueueMetrics, GatewayComponent, GatewayComponentStatus,
        GatewayDiagnosticsObservation, GatewayError, GatewayObservation, GatewayWorkerHealth,
    };
    use cigar_sdk::ServerCompatibility;
    use cigar_sdk::api::{CapabilitiesResponse, VersionResponse};

    fn compatibility() -> ServerCompatibility {
        ServerCompatibility {
            version: VersionResponse {
                version: "0.1.0".to_owned(),
                source_revision: "revision-1".to_owned(),
                protocol_min: "1.0".to_owned(),
                protocol_max: "1.x".to_owned(),
                build_profile: "test".to_owned(),
                enabled_features: Vec::new(),
            },
            capabilities: CapabilitiesResponse {
                api_version: "v1".to_owned(),
                protocol_version: "1.x".to_owned(),
                profiles: vec!["local".to_owned()],
                extensions: Vec::new(),
                max_payload_bytes: 1024,
                max_event_bytes: 1024,
                max_page_size: 100,
            },
        }
    }

    fn observation(status: GatewayComponentStatus) -> GatewayObservation {
        GatewayObservation {
            live: true,
            gate_open: true,
            ready: status != GatewayComponentStatus::Unhealthy,
            components: vec![GatewayComponent {
                name: "metadata".to_owned(),
                status,
                reason: None,
            }],
            latency_ms: 12,
        }
    }

    #[tokio::test]
    async fn starting_success_and_degradation_are_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = StatusService::new("Local CIGAR".to_owned(), false)?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Starting
        );
        service
            .record_success(
                &compatibility(),
                observation(GatewayComponentStatus::Healthy),
            )
            .await?;
        let healthy = service.snapshot().await;
        assert_eq!(healthy.aggregate(), AggregateStatus::Healthy);
        assert_eq!(
            healthy.components.first().map(|component| component.status),
            Some(DashboardComponentStatus::Healthy)
        );

        service
            .record_success(
                &compatibility(),
                observation(GatewayComponentStatus::Degraded),
            )
            .await?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Degraded
        );
        Ok(())
    }

    #[tokio::test]
    async fn failures_and_incompatibility_follow_closed_precedence()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = StatusService::new("Local CIGAR".to_owned(), true)?;
        service
            .record_success(
                &compatibility(),
                observation(GatewayComponentStatus::Healthy),
            )
            .await?;
        assert_eq!(service.record_failure(GatewayError::Unavailable).await?, 1);
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Healthy
        );
        assert_eq!(service.record_failure(GatewayError::Unavailable).await?, 2);
        assert_eq!(service.record_failure(GatewayError::Unavailable).await?, 3);
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Unreachable
        );
        service.record_failure(GatewayError::Incompatible).await?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Incompatible
        );
        Ok(())
    }

    #[tokio::test]
    async fn diagnostics_are_cross_source_health_without_overwriting_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = StatusService::new("Local CIGAR".to_owned(), false)?;
        service
            .record_success(
                &compatibility(),
                observation(GatewayComponentStatus::Healthy),
            )
            .await?;
        service.record_diagnostics(diagnostics(false)).await?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Unhealthy
        );

        service
            .record_success(
                &compatibility(),
                observation(GatewayComponentStatus::Healthy),
            )
            .await?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Unhealthy
        );
        service.record_diagnostics(diagnostics(true)).await?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Healthy
        );
        service.record_diagnostics_failure().await?;
        assert_eq!(
            service.snapshot().await.aggregate(),
            AggregateStatus::Degraded
        );
        Ok(())
    }

    fn diagnostics(healthy: bool) -> GatewayDiagnosticsObservation {
        GatewayDiagnosticsObservation {
            ready: healthy,
            workers: vec![GatewayWorkerHealth {
                worker: "outbox".to_owned(),
                healthy,
            }],
            metrics: DashboardMetrics {
                authorized_requests_total: 3,
                rejected_requests_total: 0,
                listener_failures_total: 0,
                graceful_shutdowns_total: 0,
                queues: vec![DashboardQueueMetrics {
                    worker: "outbox".to_owned(),
                    depth: 1,
                    capacity: 8,
                    rejections_total: 0,
                    oldest_age_seconds: 1,
                }],
                semantic: Vec::new(),
                series_count: 8,
            },
            latency_ms: 4,
        }
    }
}
