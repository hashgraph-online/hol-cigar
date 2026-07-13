//! Content-safe daemon telemetry and OpenMetrics exposition.

use crate::worker::QueueMetricsSnapshot;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, MeterProvider as _};
use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Validated OTLP export settings; credential headers remain collector-side configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpConfig {
    endpoint: String,
    export_timeout: Duration,
    metric_interval: Duration,
}

impl OtlpConfig {
    /// Creates bounded OTLP/gRPC export settings.
    pub fn new(
        endpoint: impl Into<String>,
        export_timeout: Duration,
        metric_interval: Duration,
    ) -> Result<Self, TelemetryError> {
        let endpoint = endpoint.into();
        let scheme_is_safe = endpoint.starts_with("https://")
            || endpoint.starts_with("http://127.0.0.1:")
            || endpoint.starts_with("http://[::1]:");
        if !scheme_is_safe
            || endpoint.len() > 2_048
            || endpoint.bytes().any(|byte| byte.is_ascii_control())
            || endpoint.contains('@')
            || export_timeout.is_zero()
            || export_timeout > Duration::from_secs(30)
            || metric_interval < Duration::from_secs(1)
            || metric_interval > Duration::from_secs(300)
        {
            return Err(TelemetryError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint,
            export_timeout,
            metric_interval,
        })
    }
}

/// Stable OTLP construction or shutdown failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryError {
    /// OTLP endpoint or bounded timing settings were invalid.
    InvalidConfiguration,
    /// The OTLP trace or metric pipeline could not be constructed.
    ExporterUnavailable,
    /// Bounded provider shutdown did not complete successfully.
    FlushFailed,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "telemetry configuration is invalid",
            Self::ExporterUnavailable => "OTLP exporter is unavailable",
            Self::FlushFailed => "OTLP telemetry flush failed",
        })
    }
}

impl std::error::Error for TelemetryError {}

struct OtelPipeline {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    tracer: SdkTracer,
    authorized: Counter<u64>,
    rejected: Counter<u64>,
    listener_failures: Counter<u64>,
    graceful_shutdowns: Counter<u64>,
}

impl OtelPipeline {
    fn new(config: &OtlpConfig) -> Result<Self, TelemetryError> {
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.clone())
            .with_timeout(config.export_timeout)
            .build()
            .map_err(|_error| TelemetryError::ExporterUnavailable)?;
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.clone())
            .with_timeout(config.export_timeout)
            .build()
            .map_err(|_error| TelemetryError::ExporterUnavailable)?;
        let resource = Resource::builder()
            .with_service_name("cigar-daemon")
            .build();
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter)
            .build();
        let reader = PeriodicReader::builder(metric_exporter)
            .with_interval(config.metric_interval)
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();
        let tracer = tracer_provider.tracer("cigar-daemon");
        let meter = meter_provider.meter("cigar-daemon");
        let authorized = meter
            .u64_counter("cigar.daemon.authorized_requests")
            .with_description("Authenticated requests accepted by daemon transports.")
            .build();
        let rejected = meter
            .u64_counter("cigar.daemon.rejected_requests")
            .with_description("Requests rejected before protected service dispatch.")
            .build();
        let listener_failures = meter
            .u64_counter("cigar.daemon.listener_failures")
            .with_description("Listener bind or unexpected-exit failures.")
            .build();
        let graceful_shutdowns = meter
            .u64_counter("cigar.daemon.graceful_shutdowns")
            .with_description("Completed bounded graceful shutdowns.")
            .build();
        Ok(Self {
            tracer_provider,
            meter_provider,
            tracer,
            authorized,
            rejected,
            listener_failures,
            graceful_shutdowns,
        })
    }

    fn request(&self, authorized: bool) {
        let outcome = if authorized { "authorized" } else { "rejected" };
        if authorized {
            self.authorized.add(1, &[]);
        } else {
            self.rejected.add(1, &[]);
        }
        let mut span = self.tracer.start("cigar.request.authority");
        span.set_attribute(KeyValue::new("cigar.auth.outcome", outcome));
        span.end();
    }

    fn listener_failure(&self) {
        self.listener_failures.add(1, &[]);
        let mut span = self.tracer.start("cigar.listener.failure");
        span.set_attribute(KeyValue::new("error.type", "listener_failure"));
        span.end();
    }

    fn graceful_shutdown(&self) {
        self.graceful_shutdowns.add(1, &[]);
    }

    fn shutdown(&self, timeout: Duration) -> Result<(), TelemetryError> {
        self.tracer_provider
            .shutdown_with_timeout(timeout)
            .map_err(|_error| TelemetryError::FlushFailed)?;
        self.meter_provider
            .shutdown_with_timeout(timeout)
            .map_err(|_error| TelemetryError::FlushFailed)
    }
}

/// Process-level counters that never contain tenant, principal, payload, or record data.
pub struct DaemonTelemetry {
    authorized_requests: AtomicU64,
    rejected_requests: AtomicU64,
    listener_failures: AtomicU64,
    graceful_shutdowns: AtomicU64,
    otel: Option<OtelPipeline>,
}

impl DaemonTelemetry {
    /// Creates process-local OpenMetrics telemetry without an outbound exporter.
    #[must_use]
    pub fn local() -> Self {
        Self {
            authorized_requests: AtomicU64::new(0),
            rejected_requests: AtomicU64::new(0),
            listener_failures: AtomicU64::new(0),
            graceful_shutdowns: AtomicU64::new(0),
            otel: None,
        }
    }

    /// Creates a real OTLP/gRPC trace and metric pipeline with bounded exporter timeouts.
    pub fn with_otlp(config: OtlpConfig) -> Result<Self, TelemetryError> {
        Ok(Self {
            otel: Some(OtelPipeline::new(&config)?),
            ..Self::local()
        })
    }

    /// Records one request that passed transport authentication.
    pub fn record_authorized_request(&self) {
        self.authorized_requests.fetch_add(1, Ordering::Relaxed);
        if let Some(otel) = &self.otel {
            otel.request(true);
        }
    }

    /// Records one request rejected before protected service dispatch.
    pub fn record_rejected_request(&self) {
        self.rejected_requests.fetch_add(1, Ordering::Relaxed);
        if let Some(otel) = &self.otel {
            otel.request(false);
        }
    }

    /// Records one listener that exited unexpectedly or failed to bind.
    pub fn record_listener_failure(&self) {
        self.listener_failures.fetch_add(1, Ordering::Relaxed);
        if let Some(otel) = &self.otel {
            otel.listener_failure();
        }
    }

    /// Records completion of one bounded graceful-shutdown sequence.
    pub fn record_graceful_shutdown(&self) {
        self.graceful_shutdowns.fetch_add(1, Ordering::Relaxed);
        if let Some(otel) = &self.otel {
            otel.graceful_shutdown();
        }
    }

    /// Flushes and shuts down configured OTLP providers within exporter-enforced bounds.
    pub fn shutdown_otlp(&self, timeout: Duration) -> Result<(), TelemetryError> {
        self.otel
            .as_ref()
            .map_or(Ok(()), |pipeline| pipeline.shutdown(timeout))
    }

    /// Returns a value-only snapshot suitable for diagnostics and health surfaces.
    #[must_use]
    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            authorized_requests: self.authorized_requests.load(Ordering::Relaxed),
            rejected_requests: self.rejected_requests.load(Ordering::Relaxed),
            listener_failures: self.listener_failures.load(Ordering::Relaxed),
            graceful_shutdowns: self.graceful_shutdowns.load(Ordering::Relaxed),
        }
    }

    /// Renders standards-compatible OpenMetrics text with only closed, content-safe labels.
    #[must_use]
    pub fn render_openmetrics(&self, queues: &[QueueMetricsSnapshot]) -> String {
        let snapshot = self.snapshot();
        let mut output = String::new();
        metric(
            &mut output,
            "cigar_daemon_authorized_requests_total",
            "Authenticated requests accepted by daemon transports.",
            "counter",
            snapshot.authorized_requests,
        );
        metric(
            &mut output,
            "cigar_daemon_rejected_requests_total",
            "Requests rejected before protected service dispatch.",
            "counter",
            snapshot.rejected_requests,
        );
        metric(
            &mut output,
            "cigar_daemon_listener_failures_total",
            "Listener bind or unexpected-exit failures.",
            "counter",
            snapshot.listener_failures,
        );
        metric(
            &mut output,
            "cigar_daemon_graceful_shutdowns_total",
            "Completed bounded graceful shutdowns.",
            "counter",
            snapshot.graceful_shutdowns,
        );
        output.push_str("# HELP cigar_worker_queue_depth Durable wakeups currently queued.\n");
        output.push_str("# TYPE cigar_worker_queue_depth gauge\n");
        output.push_str("# HELP cigar_worker_queue_capacity Configured hard queue capacity.\n");
        output.push_str("# TYPE cigar_worker_queue_capacity gauge\n");
        output.push_str("# HELP cigar_worker_queue_rejections_total Rejected bounded wakeups.\n");
        output.push_str("# TYPE cigar_worker_queue_rejections_total counter\n");
        output.push_str("# HELP cigar_worker_queue_oldest_age_seconds Age of the oldest wakeup.\n");
        output.push_str("# TYPE cigar_worker_queue_oldest_age_seconds gauge\n");
        for queue in queues {
            let kind = queue.kind.as_str();
            output.push_str(&format!(
                "cigar_worker_queue_depth{{worker=\"{kind}\"}} {}\n",
                queue.depth
            ));
            output.push_str(&format!(
                "cigar_worker_queue_capacity{{worker=\"{kind}\"}} {}\n",
                queue.capacity
            ));
            output.push_str(&format!(
                "cigar_worker_queue_rejections_total{{worker=\"{kind}\"}} {}\n",
                queue.rejection_count
            ));
            let oldest_seconds = queue.oldest_age_nanos.unwrap_or(0) / 1_000_000_000;
            output.push_str(&format!(
                "cigar_worker_queue_oldest_age_seconds{{worker=\"{kind}\"}} {oldest_seconds}\n"
            ));
        }
        output.push_str("# EOF\n");
        output
    }
}

impl Default for DaemonTelemetry {
    fn default() -> Self {
        Self::local()
    }
}

impl fmt::Debug for DaemonTelemetry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonTelemetry")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// Content-safe process telemetry values used by diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySnapshot {
    /// Requests admitted after transport authentication.
    pub authorized_requests: u64,
    /// Requests rejected before service dispatch.
    pub rejected_requests: u64,
    /// Listener bind or unexpected-exit failures.
    pub listener_failures: u64,
    /// Completed bounded graceful shutdowns.
    pub graceful_shutdowns: u64,
}

fn metric(output: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    output.push_str(&format!("# HELP {name} {help}\n"));
    output.push_str(&format!("# TYPE {name} {kind}\n"));
    output.push_str(&format!("{name} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::{DaemonTelemetry, OtlpConfig, TelemetryError};
    use crate::{OverflowPolicy, QueueMetricsSnapshot, WorkerKind};

    #[test]
    fn openmetrics_contains_only_closed_worker_labels_and_has_eof() {
        let telemetry = DaemonTelemetry::default();
        telemetry.record_authorized_request();
        telemetry.record_rejected_request();
        let output = telemetry.render_openmetrics(&[QueueMetricsSnapshot {
            kind: WorkerKind::Outbox,
            capacity: 8,
            depth: 2,
            oldest_age_nanos: Some(2_000_000_000),
            rejection_count: 1,
            overflow_policy: OverflowPolicy::RejectNewest,
            accepting: true,
        }]);
        assert!(output.contains("cigar_daemon_authorized_requests_total 1"));
        assert!(output.contains("worker=\"outbox\""));
        assert!(output.ends_with("# EOF\n"));
        assert!(!output.contains("tenant"));
        assert!(!output.contains("principal"));
    }

    #[test]
    fn otlp_configuration_rejects_unencrypted_remote_collectors() {
        assert_eq!(
            OtlpConfig::new(
                "http://collector.example:4317",
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(10),
            ),
            Err(TelemetryError::InvalidConfiguration)
        );
        assert!(
            OtlpConfig::new(
                "https://collector.example:4317",
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(10),
            )
            .is_ok()
        );
    }
}
