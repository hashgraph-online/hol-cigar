//! Typed, proxy-free loopback daemon gateway built exclusively on `cigar-sdk`.

use crate::{DashboardMetrics, DashboardTargetConfig, MetricsError};
use cigar_sdk::api::EmptyRequest;
use cigar_sdk::protocol::HealthStatus;
use cigar_sdk::{
    AuthorizationProvider, AuthorizationValue, CallOptions, Client, ErrorKind, RemoteClientBuilder,
    SdkError, SdkFuture, ServerCompatibility,
};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read as _, Take};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: u64 = 8_192;

/// Stable content-free typed gateway failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    /// The server is reachable but not compatible with the frozen SDK line.
    Incompatible,
    /// No valid bounded transport response was available.
    Unavailable,
    /// The peer response disagreed with the frozen typed protocol.
    Protocol,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Incompatible => "dashboard target is incompatible",
            Self::Unavailable => "dashboard target is unavailable",
            Self::Protocol => "dashboard target response is invalid",
        })
    }
}

impl std::error::Error for GatewayError {}

/// One content-safe component observation returned by the typed gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayComponent {
    /// Stable component name from the validated readiness report.
    pub name: String,
    /// Closed readiness status.
    pub status: GatewayComponentStatus,
    /// Stable public CIGAR reason code, when present.
    pub reason: Option<String>,
}

/// Closed component status independent of protocol implementation types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayComponentStatus {
    /// Component is operating normally.
    Healthy,
    /// Component is available with reduced guarantees.
    Degraded,
    /// Component is unavailable for required operations.
    Unhealthy,
}

/// One complete valid liveness/readiness observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayObservation {
    /// True only for the validated liveness response.
    pub live: bool,
    /// True only while startup/shutdown admission is open.
    pub gate_open: bool,
    /// True only when the validated readiness response is ready.
    pub ready: bool,
    /// Typed readiness components in stable name order.
    pub components: Vec<GatewayComponent>,
    /// Complete probe wall duration in milliseconds.
    pub latency_ms: u64,
}

/// Closed public deployment mode from the typed configuration endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayDeploymentMode {
    /// Permission-restricted local service.
    Local,
    /// TLS-authenticated shared service.
    Shared,
}

/// One SDK-validated redacted daemon configuration observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfigurationObservation {
    /// Closed public daemon deployment mode.
    pub mode: GatewayDeploymentMode,
    /// Whether the daemon exposes its permission-restricted local IPC transport.
    pub local_ipc: bool,
    /// Whether the daemon HTTP transport is enabled.
    pub http_enabled: bool,
    /// Whether the daemon gRPC transport is enabled.
    pub grpc_enabled: bool,
    /// Maximum expanded daemon request bytes.
    pub max_request_bytes: u32,
    /// Maximum daemon request timeout in milliseconds.
    pub max_timeout_ms: u64,
    /// Complete typed configuration call duration in milliseconds.
    pub latency_ms: u64,
}

/// One closed daemon worker heartbeat observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayWorkerHealth {
    /// Closed stable worker-family name.
    pub worker: String,
    /// Whether the worker accepted work while its diagnostic was captured.
    pub healthy: bool,
}

/// Cross-validated typed diagnostics and closed OpenMetrics observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDiagnosticsObservation {
    /// Whether diagnostic request admission was open.
    pub ready: bool,
    /// Closed worker heartbeat states.
    pub workers: Vec<GatewayWorkerHealth>,
    /// Parsed metrics with no arbitrary labels or help text.
    pub metrics: DashboardMetrics,
    /// Complete parallel diagnostics and metrics call duration in milliseconds.
    pub latency_ms: u64,
}

/// Connected typed CIGAR daemon client and negotiated public compatibility.
pub struct DaemonGateway {
    client: Client,
    compatibility: ServerCompatibility,
    request_timeout: Duration,
}

impl DaemonGateway {
    /// Connects through `cigar-sdk`, explicitly permitting only configured loopback cleartext.
    pub async fn connect(config: &DashboardTargetConfig) -> Result<Self, GatewayError> {
        let authorization: Arc<dyn AuthorizationProvider> = Arc::new(
            RotatingFileAuthorization::new(config.bearer_token_file.clone()),
        );
        let builder = RemoteClientBuilder::new(&config.base_url)
            .map_err(map_sdk_error)?
            .allow_insecure_loopback(true)
            .authorization_provider(authorization)
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .map_err(map_sdk_error)?;
        let (client, compatibility) = builder.connect().await.map_err(map_sdk_error)?;
        Ok(Self {
            client,
            compatibility,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
        })
    }

    /// Returns the SDK-verified compatibility records.
    #[must_use]
    pub const fn compatibility(&self) -> &ServerCompatibility {
        &self.compatibility
    }

    /// Performs independent typed liveness and readiness calls with bounded deadlines.
    pub async fn observe(&self) -> Result<GatewayObservation, GatewayError> {
        let started = Instant::now();
        let liveness_options = CallOptions::read()
            .with_timeout(self.request_timeout)
            .map_err(map_sdk_error)?;
        let readiness_options = CallOptions::read()
            .with_timeout(self.request_timeout)
            .map_err(map_sdk_error)?;
        let (liveness, readiness) = tokio::join!(
            self.client.get_liveness(EmptyRequest {}, liveness_options),
            self.client
                .get_readiness(EmptyRequest {}, readiness_options)
        );
        let liveness = liveness.map_err(map_sdk_error)?.value;
        let readiness = readiness.map_err(map_sdk_error)?.value;
        let components = readiness
            .dependency_report
            .components
            .into_iter()
            .map(|component| {
                if !bounded_identifier(&component.name) {
                    return Err(GatewayError::Protocol);
                }
                Ok(GatewayComponent {
                    name: component.name,
                    status: match component.status {
                        HealthStatus::Healthy => GatewayComponentStatus::Healthy,
                        HealthStatus::Degraded => GatewayComponentStatus::Degraded,
                        HealthStatus::Unhealthy => GatewayComponentStatus::Unhealthy,
                    },
                    reason: component.reason.and_then(public_reason),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GatewayObservation {
            live: liveness.live,
            gate_open: readiness.gate_open,
            ready: readiness.ready,
            components,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Reads the SDK-validated redacted daemon configuration with a bounded deadline.
    pub async fn observe_configuration(
        &self,
    ) -> Result<GatewayConfigurationObservation, GatewayError> {
        let started = Instant::now();
        let options = CallOptions::read()
            .with_timeout(self.request_timeout)
            .map_err(map_sdk_error)?;
        let configuration = self
            .client
            .get_configuration(EmptyRequest {}, options)
            .await
            .map_err(map_sdk_error)?
            .value;
        Ok(GatewayConfigurationObservation {
            mode: match configuration.mode {
                cigar_sdk::api::PublicDeploymentMode::Local => GatewayDeploymentMode::Local,
                cigar_sdk::api::PublicDeploymentMode::Shared => GatewayDeploymentMode::Shared,
            },
            local_ipc: configuration.local_ipc,
            http_enabled: configuration.http_enabled,
            grpc_enabled: configuration.grpc_enabled,
            max_request_bytes: configuration.max_request_bytes,
            max_timeout_ms: configuration.max_timeout_ms,
            latency_ms: duration_millis(started.elapsed()),
        })
    }

    /// Reads and cross-validates typed diagnostics against closed OpenMetrics values.
    pub async fn observe_diagnostics(&self) -> Result<GatewayDiagnosticsObservation, GatewayError> {
        let started = Instant::now();
        let diagnostics_options = CallOptions::read()
            .with_timeout(self.request_timeout)
            .map_err(map_sdk_error)?;
        let metrics_options = CallOptions::read()
            .with_timeout(self.request_timeout)
            .map_err(map_sdk_error)?;
        let (diagnostics, metrics) = tokio::join!(
            self.client
                .get_diagnostics(EmptyRequest {}, diagnostics_options),
            self.client.get_metrics(EmptyRequest {}, metrics_options),
        );
        let diagnostics = diagnostics.map_err(map_sdk_error)?.value;
        let metrics_response = metrics.map_err(map_sdk_error)?.value;
        let metrics =
            DashboardMetrics::parse(metrics_response.text.as_bytes()).map_err(map_metrics_error)?;
        validate_counters(&diagnostics.counters, &metrics)?;
        if diagnostics.queues.len() != metrics.queues.len() {
            return Err(GatewayError::Protocol);
        }
        let workers = diagnostics
            .queues
            .into_iter()
            .map(|queue| {
                let metric = metrics
                    .queues
                    .iter()
                    .find(|metric| metric.worker == queue.name)
                    .ok_or(GatewayError::Protocol)?;
                if u64::from(queue.capacity) != metric.capacity
                    || u64::from(queue.depth) != metric.depth
                    || queue.rejected != metric.rejections_total
                {
                    return Err(GatewayError::Protocol);
                }
                Ok(GatewayWorkerHealth {
                    worker: queue.name,
                    healthy: queue.worker_healthy,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GatewayDiagnosticsObservation {
            ready: diagnostics.ready,
            workers,
            metrics,
            latency_ms: duration_millis(started.elapsed()),
        })
    }
}

impl fmt::Debug for DaemonGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonGateway")
            .field("compatibility", &self.compatibility)
            .field("request_timeout", &self.request_timeout)
            .field("authorization", &"[REDACTED ROTATING FILE]")
            .finish()
    }
}

fn public_reason(code: cigar_sdk::protocol::ErrorCode) -> Option<String> {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
}

fn map_sdk_error(error: SdkError) -> GatewayError {
    match error.kind() {
        ErrorKind::IncompatibleServer => GatewayError::Incompatible,
        ErrorKind::Protocol | ErrorKind::InvalidArgument | ErrorKind::InvalidConfiguration => {
            GatewayError::Protocol
        }
        ErrorKind::Cancelled
        | ErrorKind::DeadlineExceeded
        | ErrorKind::Transport
        | ErrorKind::Integrity
        | ErrorKind::Api => GatewayError::Unavailable,
    }
}

fn map_metrics_error(_error: MetricsError) -> GatewayError {
    GatewayError::Protocol
}

fn validate_counters(
    counters: &[cigar_sdk::api::DiagnosticCounter],
    metrics: &DashboardMetrics,
) -> Result<(), GatewayError> {
    if counters.len() != 4 {
        return Err(GatewayError::Protocol);
    }
    for counter in counters {
        let expected = match counter.name.as_str() {
            "authorized_requests" => metrics.authorized_requests_total,
            "rejected_requests" => metrics.rejected_requests_total,
            "listener_failures" => metrics.listener_failures_total,
            "graceful_shutdowns" => metrics.graceful_shutdowns_total,
            _ => return Err(GatewayError::Protocol),
        };
        if counter.value != expected {
            return Err(GatewayError::Protocol);
        }
    }
    Ok(())
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct RotatingFileAuthorization {
    path: PathBuf,
}

impl RotatingFileAuthorization {
    const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl AuthorizationProvider for RotatingFileAuthorization {
    fn authorization<'a>(&'a self) -> SdkFuture<'a, Result<Option<AuthorizationValue>, SdkError>> {
        Box::pin(async move {
            let path = self.path.clone();
            tokio::task::spawn_blocking(move || read_authorization(&path))
                .await
                .map_err(|_error| SdkError::transport())?
                .map(Some)
                .map_err(|_error| SdkError::transport())
        })
    }
}

impl fmt::Debug for RotatingFileAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotatingFileAuthorization")
            .field("path", &"[REDACTED]")
            .finish()
    }
}

fn read_authorization(path: &Path) -> Result<AuthorizationValue, GatewayError> {
    let before = fs::symlink_metadata(path).map_err(|_error| GatewayError::Unavailable)?;
    validate_credential_metadata(&before)?;
    let file = File::open(path).map_err(|_error| GatewayError::Unavailable)?;
    let opened = file
        .metadata()
        .map_err(|_error| GatewayError::Unavailable)?;
    validate_credential_metadata(&opened)?;
    if !same_file(&before, &opened) {
        return Err(GatewayError::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let mut bounded: Take<File> = file.take(MAX_CREDENTIAL_BYTES.saturating_add(1));
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_error| GatewayError::Unavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES as usize {
        return Err(GatewayError::Unavailable);
    }
    let after = fs::symlink_metadata(path).map_err(|_error| GatewayError::Unavailable)?;
    validate_credential_metadata(&after)?;
    if !same_file(&opened, &after) {
        return Err(GatewayError::Unavailable);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_error| GatewayError::Unavailable)?;
    let value = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let token = value.strip_prefix("Bearer ").unwrap_or(value);
    if token.is_empty()
        || token.len() > MAX_CREDENTIAL_BYTES as usize - "Bearer ".len()
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(GatewayError::Unavailable);
    }
    let authorization = if value.starts_with("Bearer ") {
        Zeroizing::new(value.to_owned())
    } else {
        Zeroizing::new(format!("Bearer {value}"))
    };
    AuthorizationValue::new(authorization.as_str().to_owned()).map_err(map_sdk_error)
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !value.ends_with(['.', '_', '-'])
}

fn validate_credential_metadata(metadata: &fs::Metadata) -> Result<(), GatewayError> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(GatewayError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::getuid().as_raw()
        {
            return Err(GatewayError::Unavailable);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(test)]
mod tests {
    use super::{GatewayError, read_authorization, validate_counters};
    use crate::DashboardMetrics;
    use cigar_sdk::api::DiagnosticCounter;
    use std::fs;

    #[test]
    fn owner_only_token_accepts_raw_or_bearer_text() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("daemon.token");
        fs::write(&path, "opaque-token\n")?;
        restrict(&path)?;
        let authorization = read_authorization(&path)?;
        assert!(!format!("{authorization:?}").contains("opaque-token"));
        fs::write(&path, "Bearer rotated-token\r\n")?;
        restrict(&path)?;
        read_authorization(&path)?;
        Ok(())
    }

    #[test]
    fn token_links_permissions_and_malformed_values_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("daemon.token");
        fs::write(&path, "not two tokens")?;
        restrict(&path)?;
        assert_eq!(
            read_authorization(&path).err(),
            Some(GatewayError::Unavailable)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};

            fs::write(&path, "valid-token")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
            assert_eq!(
                read_authorization(&path).err(),
                Some(GatewayError::Unavailable)
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            let link = directory.path().join("linked.token");
            symlink(&path, &link)?;
            assert_eq!(
                read_authorization(&link).err(),
                Some(GatewayError::Unavailable)
            );
        }
        Ok(())
    }

    #[test]
    fn typed_counters_must_exactly_match_closed_metrics() {
        let metrics = DashboardMetrics {
            authorized_requests_total: 9,
            rejected_requests_total: 2,
            listener_failures_total: 1,
            graceful_shutdowns_total: 0,
            queues: Vec::new(),
            series_count: 4,
        };
        let mut counters = vec![
            DiagnosticCounter {
                name: "authorized_requests".to_owned(),
                value: 9,
            },
            DiagnosticCounter {
                name: "graceful_shutdowns".to_owned(),
                value: 0,
            },
            DiagnosticCounter {
                name: "listener_failures".to_owned(),
                value: 1,
            },
            DiagnosticCounter {
                name: "rejected_requests".to_owned(),
                value: 2,
            },
        ];
        assert_eq!(validate_counters(&counters, &metrics), Ok(()));
        if let Some(counter) = counters.first_mut() {
            counter.value = 10;
        }
        assert_eq!(
            validate_counters(&counters, &metrics),
            Err(GatewayError::Protocol)
        );
    }

    fn restrict(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
