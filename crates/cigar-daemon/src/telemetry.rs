//! Content-safe daemon telemetry and OpenMetrics exposition.

use crate::worker::{BlockingPoolMetrics, QueueMetricsSnapshot, WorkerKind};
use cigar_api::{TransportMetricEvent, TransportMetricsObserver};
use cigar_observe::{DAEMON_METRICS, MetricKind, metric_definition};
use cigar_protocol::{EffectState, LaneKind};
use cigar_store::{
    RepositoryCommitKind, RepositoryCommitMetrics, RepositoryCommitMetricsObserver,
    RepositoryCommitOutcome, RepositoryStartupMetrics, RepositoryStartupMetricsObserver,
    RepositoryStartupOutcome, RepositoryStartupStage,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, MeterProvider as _};
use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
use opentelemetry_otlp::tonic_types::transport::{Certificate, ClientTlsConfig};
use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const MAX_OTLP_CA_BYTES: usize = 2 * 1024 * 1024;
const MAX_OTLP_CA_CERTIFICATES: usize = 128;
const EFFECT_STATE_COUNT: usize = 16;
const LANE_COUNT: usize = 5;
const COMPILE_PHASE_COUNT: usize = 7;
const COMPILE_CANDIDATE_STAGE_COUNT: usize = 5;
const COMPILE_RESULT_COUNT: usize = 7;
const CACHE_OBSERVATION_COUNT: usize = 32;
const REPOSITORY_COMMIT_KIND_COUNT: usize = 3;
const REPOSITORY_COMMIT_OUTCOME_COUNT: usize = 2;
const REPOSITORY_COMMIT_PHASE_COUNT: usize = 11;
const STARTUP_STAGE_COUNT: usize = 11;
const STARTUP_OUTCOME_COUNT: usize = 2;

#[derive(Clone, Eq, PartialEq)]
struct OtlpTlsConfig {
    server_name: String,
    ca_certificate_pem: Vec<u8>,
}

/// Validated OTLP export settings with no ambient credential or trust-root inputs.
#[derive(Clone, Eq, PartialEq)]
pub struct OtlpConfig {
    endpoint: String,
    export_timeout: Duration,
    metric_interval: Duration,
    tls: Option<OtlpTlsConfig>,
}

impl OtlpConfig {
    /// Creates bounded local-loopback OTLP/gRPC export settings without TLS.
    ///
    /// Remote HTTPS endpoints must use [`Self::new_with_ca_certificate`].
    pub fn new(
        endpoint: impl Into<String>,
        export_timeout: Duration,
        metric_interval: Duration,
    ) -> Result<Self, TelemetryError> {
        Self::new_internal(endpoint.into(), export_timeout, metric_interval, None)
    }

    /// Creates bounded HTTPS OTLP/gRPC export settings with an explicit CA bundle.
    pub fn new_with_ca_certificate(
        endpoint: impl Into<String>,
        export_timeout: Duration,
        metric_interval: Duration,
        ca_certificate_pem: Vec<u8>,
    ) -> Result<Self, TelemetryError> {
        Self::new_internal(
            endpoint.into(),
            export_timeout,
            metric_interval,
            Some(ca_certificate_pem),
        )
    }

    fn new_internal(
        endpoint: String,
        export_timeout: Duration,
        metric_interval: Duration,
        ca_certificate_pem: Option<Vec<u8>>,
    ) -> Result<Self, TelemetryError> {
        Self::validate_configuration_shape(
            &endpoint,
            export_timeout,
            metric_interval,
            ca_certificate_pem.is_some(),
        )?;
        let parsed = reqwest::Url::parse(&endpoint)
            .map_err(|_error| TelemetryError::InvalidConfiguration)?;
        let tls = match (parsed.scheme(), ca_certificate_pem) {
            ("https", Some(ca_certificate_pem)) => {
                validate_ca_certificate_bundle(&ca_certificate_pem)?;
                Some(OtlpTlsConfig {
                    server_name: parsed
                        .host_str()
                        .ok_or(TelemetryError::InvalidConfiguration)?
                        .to_owned(),
                    ca_certificate_pem,
                })
            }
            ("http", None) => None,
            _ => return Err(TelemetryError::InvalidConfiguration),
        };
        Ok(Self {
            endpoint,
            export_timeout,
            metric_interval,
            tls,
        })
    }

    pub(crate) fn validate_configuration_shape(
        endpoint: &str,
        export_timeout: Duration,
        metric_interval: Duration,
        has_explicit_ca: bool,
    ) -> Result<(), TelemetryError> {
        let parsed =
            reqwest::Url::parse(endpoint).map_err(|_error| TelemetryError::InvalidConfiguration)?;
        let endpoint_is_safe = {
            let url = &parsed;
            let root_path = url.path().is_empty() || url.path() == "/";
            let no_ambient_authority = url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none();
            let secure = url.scheme() == "https" && url.host_str().is_some();
            let loopback_http = url.scheme() == "http"
                && url.port().is_some()
                && url.host_str().is_some_and(|host| {
                    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
                });
            root_path
                && no_ambient_authority
                && !url.cannot_be_a_base()
                && (secure || loopback_http)
        };
        if !endpoint_is_safe
            || endpoint.len() > 2_048
            || endpoint.bytes().any(|byte| byte.is_ascii_control())
            || export_timeout.is_zero()
            || export_timeout > Duration::from_secs(30)
            || metric_interval < Duration::from_secs(1)
            || metric_interval > Duration::from_secs(300)
        {
            return Err(TelemetryError::InvalidConfiguration);
        }
        match (parsed.scheme(), has_explicit_ca) {
            ("https", true) | ("http", false) => Ok(()),
            _ => Err(TelemetryError::InvalidConfiguration),
        }
    }

    fn tonic_tls_config(&self) -> Option<ClientTlsConfig> {
        self.tls.as_ref().map(|tls| {
            ClientTlsConfig::new()
                .domain_name(tls.server_name.clone())
                .ca_certificate(Certificate::from_pem(tls.ca_certificate_pem.clone()))
        })
    }
}

impl fmt::Debug for OtlpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint)
            .field("export_timeout", &self.export_timeout)
            .field("metric_interval", &self.metric_interval)
            .field(
                "tls",
                &self
                    .tls
                    .as_ref()
                    .map(|tls| (&tls.server_name, "[EXPLICIT-CA]")),
            )
            .finish()
    }
}

fn validate_ca_certificate_bundle(bytes: &[u8]) -> Result<(), TelemetryError> {
    if bytes.is_empty()
        || bytes.len() > MAX_OTLP_CA_BYTES
        || bytes.contains(&0)
        || bytes
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY")
    {
        return Err(TelemetryError::InvalidConfiguration);
    }
    let certificates = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_error| TelemetryError::InvalidConfiguration)?;
    if certificates.is_empty() || certificates.len() > MAX_OTLP_CA_CERTIFICATES {
        return Err(TelemetryError::InvalidConfiguration);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_error| TelemetryError::InvalidConfiguration)?;
    }
    Ok(())
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
    counters: BTreeMap<&'static str, Counter<u64>>,
    gauges: BTreeMap<&'static str, Gauge<u64>>,
}

/// Removes every process-environment-derived OTLP metadata header before the request leaves the
/// daemon. The upstream tonic exporter merges `OTEL_EXPORTER_*_HEADERS` even when endpoint and
/// timeout settings are supplied programmatically; accepting those variables would create an
/// ambient credential and attacker-controlled telemetry-content path.
fn strip_ambient_otlp_metadata(
    mut request: tonic::Request<()>,
) -> Result<tonic::Request<()>, tonic::Status> {
    request.metadata_mut().clear();
    Ok(request)
}

impl OtelPipeline {
    fn new(config: &OtlpConfig) -> Result<Self, TelemetryError> {
        let mut span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.clone())
            .with_timeout(config.export_timeout)
            .with_interceptor(strip_ambient_otlp_metadata);
        if let Some(tls) = config.tonic_tls_config() {
            span_exporter = span_exporter.with_tls_config(tls);
        }
        let span_exporter = span_exporter
            .build()
            .map_err(|_error| TelemetryError::ExporterUnavailable)?;
        let mut metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.clone())
            .with_timeout(config.export_timeout)
            .with_interceptor(strip_ambient_otlp_metadata);
        if let Some(tls) = config.tonic_tls_config() {
            metric_exporter = metric_exporter.with_tls_config(tls);
        }
        let metric_exporter = metric_exporter
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
        let mut counters = BTreeMap::new();
        let mut gauges = BTreeMap::new();
        for definition in DAEMON_METRICS {
            match definition.kind {
                MetricKind::Counter => {
                    counters.insert(
                        definition.name,
                        meter
                            .u64_counter(definition.name)
                            .with_description(definition.help)
                            .build(),
                    );
                }
                MetricKind::Gauge => {
                    gauges.insert(
                        definition.name,
                        meter
                            .u64_gauge(definition.name)
                            .with_description(definition.help)
                            .build(),
                    );
                }
            }
        }
        Ok(Self {
            tracer_provider,
            meter_provider,
            tracer,
            counters,
            gauges,
        })
    }

    fn request(&self, authorized: bool) {
        let outcome = if authorized { "authorized" } else { "rejected" };
        if authorized {
            self.counter("cigar_daemon_authorized_requests_total", 1, None);
            self.counter("cigar_api_requests_total", 1, Some(("outcome", "accepted")));
        } else {
            self.counter("cigar_daemon_rejected_requests_total", 1, None);
            self.counter("cigar_api_requests_total", 1, Some(("outcome", "rejected")));
        }
        let mut span = self.tracer.start("cigar.request.authority");
        span.set_attribute(KeyValue::new("cigar.auth.outcome", outcome));
        span.end();
    }

    fn listener_failure(&self) {
        self.counter("cigar_daemon_listener_failures_total", 1, None);
        let mut span = self.tracer.start("cigar.listener.failure");
        span.set_attribute(KeyValue::new("error.type", "listener_failure"));
        span.end();
    }

    fn graceful_shutdown(&self) {
        self.counter("cigar_daemon_graceful_shutdowns_total", 1, None);
    }

    fn counter(&self, name: &'static str, value: u64, label: Option<(&'static str, &'static str)>) {
        debug_assert!(
            metric_definition(name).is_some_and(|definition| {
                definition.kind == MetricKind::Counter
                    && match (definition.label, label) {
                        (None, None) => true,
                        (Some(_), Some((key, value))) => definition.accepts_label(key, value),
                        _ => false,
                    }
            }),
            "OTLP counter must come from the closed metric schema"
        );
        let attributes =
            label.map_or_else(Vec::new, |(key, value)| vec![KeyValue::new(key, value)]);
        if let Some(counter) = self.counters.get(name) {
            counter.add(value, &attributes);
        }
    }

    fn gauge(&self, name: &'static str, value: u64, label: Option<(&'static str, &'static str)>) {
        debug_assert!(
            metric_definition(name).is_some_and(|definition| {
                definition.kind == MetricKind::Gauge
                    && match (definition.label, label) {
                        (None, None) => true,
                        (Some(_), Some((key, value))) => definition.accepts_label(key, value),
                        _ => false,
                    }
            }),
            "OTLP gauge must come from the closed metric schema"
        );
        let attributes =
            label.map_or_else(Vec::new, |(key, value)| vec![KeyValue::new(key, value)]);
        if let Some(gauge) = self.gauges.get(name) {
            gauge.record(value, &attributes);
        }
    }

    fn initialize_closed_series(&self) {
        for definition in DAEMON_METRICS {
            let labels: Vec<_> = definition.label.map_or_else(
                || vec![None],
                |domain| {
                    domain
                        .values
                        .iter()
                        .map(|value| Some((domain.key, *value)))
                        .collect()
                },
            );
            for label in labels {
                match definition.kind {
                    MetricKind::Counter => self.counter(definition.name, 0, label),
                    MetricKind::Gauge => self.gauge(definition.name, 0, label),
                }
            }
        }
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

/// Closed parser ownership stages accepted by ingestion telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserStage {
    /// Connector/source framing and metadata parsing.
    Source,
    /// Registered atomizer parsing.
    Atomizer,
    /// Tree-sitter or other registered code-intelligence parsing.
    CodeIntelligence,
}

impl ParserStage {
    const fn index(self) -> usize {
        match self {
            Self::Source => 0,
            Self::Atomizer => 1,
            Self::CodeIntelligence => 2,
        }
    }

    /// Stable bounded metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Atomizer => "atomizer",
            Self::CodeIntelligence => "code_intelligence",
        }
    }
}

/// Closed compiler phases matching the PRD trace tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompilePhase {
    /// Scope resolution.
    Scope,
    /// Candidate retrieval.
    Retrieve,
    /// Per-candidate authorization.
    Authorize,
    /// Dependency/conflict reconciliation.
    Reconcile,
    /// Representation transformation.
    Transform,
    /// Deterministic packing and sealing.
    Pack,
    /// Provider-ready materialization.
    Materialize,
}

impl CompilePhase {
    const fn index(self) -> usize {
        match self {
            Self::Scope => 0,
            Self::Retrieve => 1,
            Self::Authorize => 2,
            Self::Reconcile => 3,
            Self::Transform => 4,
            Self::Pack => 5,
            Self::Materialize => 6,
        }
    }

    /// Stable bounded metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scope => "scope",
            Self::Retrieve => "retrieve",
            Self::Authorize => "authorize",
            Self::Reconcile => "reconcile",
            Self::Transform => "transform",
            Self::Pack => "pack",
            Self::Materialize => "materialize",
        }
    }
}

/// Closed candidate-count checkpoint through retrieval and compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileCandidateStage {
    /// Raw bounded candidates returned across retrieval channels, including channel duplicates.
    BeforeGovernance,
    /// Unique candidates loaded and reauthorized against current governance.
    AfterGovernance,
    /// Unique logical candidates after deterministic lineage/logical coalescing.
    AfterLogicalCoalescing,
    /// Unique content keys after the content-equivalence checkpoint.
    AfterContentGrouping,
    /// Blocks retained by deterministic budget selection.
    AfterBudgetSelection,
}

impl CompileCandidateStage {
    const fn index(self) -> usize {
        match self {
            Self::BeforeGovernance => 0,
            Self::AfterGovernance => 1,
            Self::AfterLogicalCoalescing => 2,
            Self::AfterContentGrouping => 3,
            Self::AfterBudgetSelection => 4,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeGovernance => "before_governance",
            Self::AfterGovernance => "after_governance",
            Self::AfterLogicalCoalescing => "after_logical_coalescing",
            Self::AfterContentGrouping => "after_content_grouping",
            Self::AfterBudgetSelection => "after_budget_selection",
        }
    }
}

/// Content-free counts emitted once after a successful deterministic compilation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompileResultCounts {
    /// Selected context blocks.
    pub selected_blocks: u64,
    /// Unique selected normalized content keys.
    pub unique_content_keys: u64,
    /// Unique selected source versions.
    pub unique_source_versions: u64,
    /// Unique selected lineages.
    pub unique_lineages: u64,
    /// Candidates excluded by the deterministic budget.
    pub budget_displaced: u64,
    /// Candidates protected by an explicit mandatory flag or blocking requirement.
    pub mandatory_candidates: u64,
    /// Blocking contract requirements represented by selected candidates.
    pub blocking_requirements_satisfied: u64,
}

/// Closed governed cache layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheLayer {
    /// Authorized retrieval transcript.
    Retrieval,
    /// Deterministic context plan.
    Plan,
    /// Sealed context bundle.
    Bundle,
    /// Provider-ready materialization.
    Materialization,
}

impl CacheLayer {
    const fn index(self) -> usize {
        match self {
            Self::Retrieval => 0,
            Self::Plan => 1,
            Self::Bundle => 2,
            Self::Materialization => 3,
        }
    }
}

/// Closed cache hit, miss, or bypass reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheReason {
    /// A fully authenticated entry was reused.
    Hit,
    /// No entry existed for the exact key.
    AbsentEntry,
    /// Current policy or revocation state did not match.
    PolicyMismatch,
    /// Catalog or index watermark did not match.
    WatermarkMismatch,
    /// Tokenizer identity did not match.
    TokenizerMismatch,
    /// Materializer identity did not match.
    MaterializerMismatch,
    /// A semantic extension prevented safe reuse.
    UnknownSemanticExtension,
    /// This release has no cache implementation for the layer.
    NotConfigured,
}

impl CacheReason {
    const fn index(self) -> usize {
        match self {
            Self::Hit => 0,
            Self::AbsentEntry => 1,
            Self::PolicyMismatch => 2,
            Self::WatermarkMismatch => 3,
            Self::TokenizerMismatch => 4,
            Self::MaterializerMismatch => 5,
            Self::UnknownSemanticExtension => 6,
            Self::NotConfigured => 7,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::AbsentEntry => "absent_entry",
            Self::PolicyMismatch => "policy_mismatch",
            Self::WatermarkMismatch => "watermark_mismatch",
            Self::TokenizerMismatch => "tokenizer_mismatch",
            Self::MaterializerMismatch => "materializer_mismatch",
            Self::UnknownSemanticExtension => "unknown_semantic_extension",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// Closed handoff acceptance outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffAcceptanceOutcome {
    /// A recipient durably accepted the handoff.
    Accepted,
    /// Current authority rejected the attempted acceptance.
    Rejected,
    /// The handoff expired before acceptance.
    Expired,
}

impl HandoffAcceptanceOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Accepted => 0,
            Self::Rejected => 1,
            Self::Expired => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

/// Closed reconciliation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcome {
    /// Reconciliation established a terminal or retry-safe result.
    Resolved,
    /// The effect remains explicitly unknown.
    Unresolved,
    /// The bounded reconciliation operation failed.
    Failed,
}

impl ReconciliationOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Resolved => 0,
            Self::Unresolved => 1,
            Self::Failed => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
            Self::Failed => "failed",
        }
    }
}

/// Closed blob-integrity outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobIntegrityOutcome {
    /// The encrypted blob round-trip or integrity check passed.
    Verified,
    /// The expected blob was absent.
    Missing,
    /// Integrity or authenticated decryption failed.
    Corrupt,
}

impl BlobIntegrityOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Verified => 0,
            Self::Missing => 1,
            Self::Corrupt => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
        }
    }
}

/// Closed bounded-stream event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamBackpressureEvent {
    /// A bounded stream channel was opened.
    Opened,
    /// Producer progress awaited bounded consumer capacity.
    Blocked,
    /// Cancellation closed a bounded stream.
    Cancelled,
}

impl StreamBackpressureEvent {
    const fn index(self) -> usize {
        match self {
            Self::Opened => 0,
            Self::Blocked => 1,
            Self::Cancelled => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Blocked => "blocked",
            Self::Cancelled => "cancelled",
        }
    }
}

struct ProcessSampler {
    started: Instant,
    system: Mutex<System>,
    pid: Pid,
}

#[derive(Clone, Copy)]
struct ProcessSnapshot {
    uptime_seconds: u64,
    cpu_time_seconds: u64,
    resident_memory_bytes: u64,
    virtual_memory_bytes: u64,
    open_file_descriptors: u64,
}

impl ProcessSampler {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            system: Mutex::new(System::new()),
            pid: Pid::from_u32(std::process::id()),
        }
    }

    fn snapshot(&self) -> ProcessSnapshot {
        let fallback = ProcessSnapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            cpu_time_seconds: 0,
            resident_memory_bytes: 0,
            virtual_memory_bytes: 0,
            open_file_descriptors: 0,
        };
        let Ok(mut system) = self.system.lock() else {
            return fallback;
        };
        let pids = [self.pid];
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&pids),
            true,
            ProcessRefreshKind::everything(),
        );
        let Some(process) = system.process(self.pid) else {
            return fallback;
        };
        ProcessSnapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            cpu_time_seconds: process.accumulated_cpu_time() / 1_000,
            resident_memory_bytes: process.memory(),
            virtual_memory_bytes: process.virtual_memory(),
            open_file_descriptors: process
                .open_files()
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
        }
    }
}

/// Process-level counters that never contain tenant, principal, payload, or record data.
pub struct DaemonTelemetry {
    authorized_requests: AtomicU64,
    rejected_requests: AtomicU64,
    listener_failures: AtomicU64,
    graceful_shutdowns: AtomicU64,
    ingestion_atoms: [AtomicU64; 2],
    ingestion_bytes: AtomicU64,
    parser_failures: [AtomicU64; 3],
    quarantines: AtomicU64,
    index_lag_revisions: AtomicU64,
    invalidation_fanout: AtomicU64,
    invalidation_oldest_age_seconds: AtomicU64,
    candidates: AtomicU64,
    selected_blocks: AtomicU64,
    compile_candidate_stages: [AtomicU64; COMPILE_CANDIDATE_STAGE_COUNT],
    compile_results: [AtomicU64; COMPILE_RESULT_COUNT],
    lane_tokens: [AtomicU64; LANE_COUNT],
    compile_phase_duration_nanos: [AtomicU64; COMPILE_PHASE_COUNT],
    compile_phase_runs: [AtomicU64; COMPILE_PHASE_COUNT],
    compile_conflicts: AtomicU64,
    compile_stale: AtomicU64,
    cache_events: [AtomicU64; CACHE_OBSERVATION_COUNT],
    physical_tokens: AtomicU64,
    cache_tokens: [AtomicU64; 2],
    handoff_acceptance: [AtomicU64; 3],
    handoff_merge_conflicts: AtomicU64,
    effect_states: [AtomicU64; EFFECT_STATE_COUNT],
    effect_unknown_oldest_age_seconds: AtomicU64,
    effect_reconciliations: [AtomicU64; 3],
    worker_lease_remaining_seconds: [AtomicU64; 9],
    database_connections: [AtomicU64; 3],
    database_pool_waits: AtomicU64,
    startup_duration_nanos: AtomicU64,
    startup_stage_duration_nanos: [AtomicU64; STARTUP_STAGE_COUNT],
    startup_stage_runs: [AtomicU64; STARTUP_STAGE_COUNT],
    startup_stage_failures: [AtomicU64; STARTUP_STAGE_COUNT],
    startup_outcomes: [AtomicU64; STARTUP_OUTCOME_COUNT],
    repository_commit_kinds: [AtomicU64; REPOSITORY_COMMIT_KIND_COUNT],
    repository_commit_outcomes: [AtomicU64; REPOSITORY_COMMIT_OUTCOME_COUNT],
    repository_commit_duration_nanos: [AtomicU64; REPOSITORY_COMMIT_PHASE_COUNT],
    repository_commit_phase_runs: [AtomicU64; REPOSITORY_COMMIT_PHASE_COUNT],
    repository_logical_bytes: AtomicU64,
    repository_encoded_bytes: [AtomicU64; 3],
    repository_file_growth_bytes: [AtomicU64; 2],
    repository_file_bytes: [AtomicU64; 2],
    repository_retained_records: [AtomicU64; 3],
    repository_revision_delta: AtomicU64,
    repository_write_amplification_millionths: AtomicU64,
    repository_zero_logical_commits: AtomicU64,
    blob_integrity: [AtomicU64; 3],
    api_requests: [AtomicU64; 3],
    stream_backpressure: [AtomicU64; 3],
    blocking_jobs: [AtomicU64; 4],
    blocking_outcomes: [AtomicU64; 4],
    exported_queue_rejections: [AtomicU64; 9],
    exported_blocking_outcomes: [AtomicU64; 4],
    process: ProcessSampler,
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
            ingestion_atoms: std::array::from_fn(|_index| AtomicU64::new(0)),
            ingestion_bytes: AtomicU64::new(0),
            parser_failures: std::array::from_fn(|_index| AtomicU64::new(0)),
            quarantines: AtomicU64::new(0),
            index_lag_revisions: AtomicU64::new(0),
            invalidation_fanout: AtomicU64::new(0),
            invalidation_oldest_age_seconds: AtomicU64::new(0),
            candidates: AtomicU64::new(0),
            selected_blocks: AtomicU64::new(0),
            compile_candidate_stages: std::array::from_fn(|_index| AtomicU64::new(0)),
            compile_results: std::array::from_fn(|_index| AtomicU64::new(0)),
            lane_tokens: std::array::from_fn(|_index| AtomicU64::new(0)),
            compile_phase_duration_nanos: std::array::from_fn(|_index| AtomicU64::new(0)),
            compile_phase_runs: std::array::from_fn(|_index| AtomicU64::new(0)),
            compile_conflicts: AtomicU64::new(0),
            compile_stale: AtomicU64::new(0),
            cache_events: std::array::from_fn(|_index| AtomicU64::new(0)),
            physical_tokens: AtomicU64::new(0),
            cache_tokens: std::array::from_fn(|_index| AtomicU64::new(0)),
            handoff_acceptance: std::array::from_fn(|_index| AtomicU64::new(0)),
            handoff_merge_conflicts: AtomicU64::new(0),
            effect_states: std::array::from_fn(|_index| AtomicU64::new(0)),
            effect_unknown_oldest_age_seconds: AtomicU64::new(0),
            effect_reconciliations: std::array::from_fn(|_index| AtomicU64::new(0)),
            worker_lease_remaining_seconds: std::array::from_fn(|_index| AtomicU64::new(0)),
            database_connections: std::array::from_fn(|_index| AtomicU64::new(0)),
            database_pool_waits: AtomicU64::new(0),
            startup_duration_nanos: AtomicU64::new(0),
            startup_stage_duration_nanos: std::array::from_fn(|_index| AtomicU64::new(0)),
            startup_stage_runs: std::array::from_fn(|_index| AtomicU64::new(0)),
            startup_stage_failures: std::array::from_fn(|_index| AtomicU64::new(0)),
            startup_outcomes: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_commit_kinds: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_commit_outcomes: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_commit_duration_nanos: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_commit_phase_runs: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_logical_bytes: AtomicU64::new(0),
            repository_encoded_bytes: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_file_growth_bytes: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_file_bytes: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_retained_records: std::array::from_fn(|_index| AtomicU64::new(0)),
            repository_revision_delta: AtomicU64::new(0),
            repository_write_amplification_millionths: AtomicU64::new(0),
            repository_zero_logical_commits: AtomicU64::new(0),
            blob_integrity: std::array::from_fn(|_index| AtomicU64::new(0)),
            api_requests: std::array::from_fn(|_index| AtomicU64::new(0)),
            stream_backpressure: std::array::from_fn(|_index| AtomicU64::new(0)),
            blocking_jobs: std::array::from_fn(|_index| AtomicU64::new(0)),
            blocking_outcomes: std::array::from_fn(|_index| AtomicU64::new(0)),
            exported_queue_rejections: std::array::from_fn(|_index| AtomicU64::new(0)),
            exported_blocking_outcomes: std::array::from_fn(|_index| AtomicU64::new(0)),
            process: ProcessSampler::new(),
            otel: None,
        }
    }

    /// Creates a real OTLP/gRPC trace and metric pipeline with bounded exporter timeouts.
    pub fn with_otlp(config: OtlpConfig) -> Result<Self, TelemetryError> {
        let telemetry = Self {
            otel: Some(OtelPipeline::new(&config)?),
            ..Self::local()
        };
        if let Some(otel) = &telemetry.otel {
            otel.initialize_closed_series();
        }
        Ok(telemetry)
    }

    /// Records one request that passed transport authentication.
    pub fn record_authorized_request(&self) {
        atomic_saturating_add(&self.authorized_requests, 1);
        atomic_saturating_add(&self.api_requests[0], 1);
        if let Some(otel) = &self.otel {
            otel.request(true);
        }
    }

    /// Records one request rejected before protected service dispatch.
    pub fn record_rejected_request(&self) {
        atomic_saturating_add(&self.rejected_requests, 1);
        atomic_saturating_add(&self.api_requests[1], 1);
        if let Some(otel) = &self.otel {
            otel.request(false);
        }
    }

    /// Records one listener that exited unexpectedly or failed to bind.
    pub fn record_listener_failure(&self) {
        atomic_saturating_add(&self.listener_failures, 1);
        if let Some(otel) = &self.otel {
            otel.listener_failure();
        }
    }

    /// Records completion of one bounded graceful-shutdown sequence.
    pub fn record_graceful_shutdown(&self) {
        atomic_saturating_add(&self.graceful_shutdowns, 1);
        if let Some(otel) = &self.otel {
            otel.graceful_shutdown();
        }
    }

    /// Records one successful atomic ingestion publication without source identity or content.
    pub fn record_ingestion(&self, published_atoms: u64, tombstoned_atoms: u64, bytes: u64) {
        self.record_counter(
            &self.ingestion_atoms[0],
            "cigar_ingestion_atoms_total",
            published_atoms,
            Some(("outcome", "published")),
        );
        self.record_counter(
            &self.ingestion_atoms[1],
            "cigar_ingestion_atoms_total",
            tombstoned_atoms,
            Some(("outcome", "tombstoned")),
        );
        self.record_counter(
            &self.ingestion_bytes,
            "cigar_ingestion_bytes_total",
            bytes,
            None,
        );
    }

    /// Records one content-free parser failure at a compiled-in ownership stage.
    pub fn record_parser_failure(&self, stage: ParserStage) {
        self.record_closed_counter(
            &self.parser_failures,
            stage.index(),
            "cigar_ingestion_parser_failures_total",
            1,
            Some(("stage", stage.as_str())),
        );
    }

    /// Records source records quarantined before content can reach an index.
    pub fn record_quarantines(&self, count: u64) {
        self.record_counter(
            &self.quarantines,
            "cigar_ingestion_quarantines_total",
            count,
            None,
        );
    }

    /// Replaces the current mandatory-index revision lag observation.
    pub fn observe_index_lag(&self, revisions: u64) {
        self.observe_gauge(
            &self.index_lag_revisions,
            "cigar_index_lag_revisions",
            revisions,
            None,
        );
    }

    /// Records one bounded invalidation fan-out and current oldest pending age.
    pub fn record_invalidation(&self, fanout: u64, oldest_age_seconds: u64) {
        self.record_invalidation_fanout(fanout);
        self.observe_invalidation_age(oldest_age_seconds);
    }

    /// Records exact newly claimed catalog messages reached by invalidation processing.
    pub fn record_invalidation_fanout(&self, fanout: u64) {
        self.record_counter(
            &self.invalidation_fanout,
            "cigar_invalidation_fanout_total",
            fanout,
            None,
        );
    }

    /// Replaces the current oldest bounded invalidation-queue age.
    pub fn observe_invalidation_age(&self, oldest_age_seconds: u64) {
        self.observe_gauge(
            &self.invalidation_oldest_age_seconds,
            "cigar_invalidation_oldest_age_seconds",
            oldest_age_seconds,
            None,
        );
    }

    /// Records candidate and selected-block counts from one successful governed compilation.
    pub fn record_compile_selection(&self, candidates: u64, selected_blocks: u64) {
        self.record_counter(
            &self.candidates,
            "cigar_context_candidates_total",
            candidates,
            None,
        );
        self.record_counter(
            &self.selected_blocks,
            "cigar_context_selected_blocks_total",
            selected_blocks,
            None,
        );
    }

    /// Records candidate reduction checkpoints and content-free compile result counts.
    pub fn record_compile_measurements(
        &self,
        candidate_counts: [(CompileCandidateStage, u64); COMPILE_CANDIDATE_STAGE_COUNT],
        results: CompileResultCounts,
    ) {
        for (stage, count) in candidate_counts {
            self.record_closed_counter(
                &self.compile_candidate_stages,
                stage.index(),
                "cigar_context_candidate_stage_total",
                count,
                Some(("stage", stage.as_str())),
            );
        }
        for (index, (label, count)) in [
            ("selected_blocks", results.selected_blocks),
            ("unique_content_keys", results.unique_content_keys),
            ("unique_source_versions", results.unique_source_versions),
            ("unique_lineages", results.unique_lineages),
            ("budget_displaced", results.budget_displaced),
            ("mandatory_candidates", results.mandatory_candidates),
            (
                "blocking_requirements_satisfied",
                results.blocking_requirements_satisfied,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            self.record_closed_counter(
                &self.compile_results,
                index,
                "cigar_context_compile_results_total",
                count,
                Some(("kind", label)),
            );
        }
    }

    /// Records exact selected logical tokens for one standard context lane.
    pub fn record_lane_tokens(&self, lane: LaneKind, tokens: u64) {
        let (index, label) = lane_index_label(lane);
        self.record_closed_counter(
            &self.lane_tokens,
            index,
            "cigar_context_lane_tokens_total",
            tokens,
            Some(("lane", label)),
        );
    }

    /// Records monotonic elapsed time for one completed closed compiler phase.
    pub fn record_compile_phase(&self, phase: CompilePhase, elapsed: Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.record_closed_counter(
            &self.compile_phase_duration_nanos,
            phase.index(),
            "cigar_compile_phase_duration_nanoseconds_total",
            nanos,
            Some(("phase", phase.as_str())),
        );
        self.record_closed_counter(
            &self.compile_phase_runs,
            phase.index(),
            "cigar_compile_phase_runs_total",
            1,
            Some(("phase", phase.as_str())),
        );
    }

    /// Records typed compile conflicts.
    pub fn record_compile_conflicts(&self, count: u64) {
        self.record_counter(
            &self.compile_conflicts,
            "cigar_compile_conflicts_total",
            count,
            None,
        );
    }

    /// Records stale bundle or frozen-dependency observations.
    pub fn record_compile_stale(&self, count: u64) {
        self.record_counter(
            &self.compile_stale,
            "cigar_compile_stale_total",
            count,
            None,
        );
    }

    /// Records one governed cache observation in its fixed layer family.
    pub fn record_cache_observation(&self, layer: CacheLayer, reason: CacheReason) {
        let index = layer
            .index()
            .saturating_mul(8)
            .saturating_add(reason.index());
        let Some(local) = self.cache_events.get(index) else {
            return;
        };
        let name = match layer {
            CacheLayer::Retrieval => "cigar_retrieval_cache_events_total",
            CacheLayer::Plan => "cigar_plan_cache_events_total",
            CacheLayer::Bundle => "cigar_bundle_cache_events_total",
            CacheLayer::Materialization => "cigar_materialization_cache_events_total",
        };
        self.record_counter(local, name, 1, Some(("reason", reason.as_str())));
    }

    /// Records exact physical, provider cache-read, and provider cache-write tokens.
    pub fn record_materialization_tokens(&self, physical: u64, cache_read: u64, cache_write: u64) {
        self.record_counter(
            &self.physical_tokens,
            "cigar_context_physical_tokens_total",
            physical,
            None,
        );
        for ((local, value), label) in self
            .cache_tokens
            .iter()
            .zip([cache_read, cache_write])
            .zip(["read", "write"])
        {
            self.record_counter(
                local,
                "cigar_context_cache_tokens_total",
                value,
                Some(("kind", label)),
            );
        }
    }

    /// Records one closed handoff acceptance outcome.
    pub fn record_handoff_acceptance(&self, outcome: HandoffAcceptanceOutcome) {
        self.record_closed_counter(
            &self.handoff_acceptance,
            outcome.index(),
            "cigar_handoff_acceptance_total",
            1,
            Some(("outcome", outcome.as_str())),
        );
    }

    /// Records typed conflicts retained by a handoff merge.
    pub fn record_handoff_merge_conflicts(&self, count: u64) {
        self.record_counter(
            &self.handoff_merge_conflicts,
            "cigar_handoff_merge_conflicts_total",
            count,
            None,
        );
    }

    /// Records a durable effect projection observation by its closed protocol state.
    pub fn record_effect_state(&self, state: EffectState) {
        let (index, label) = effect_state_index_label(state);
        self.record_closed_counter(
            &self.effect_states,
            index,
            "cigar_effect_state_observations_total",
            1,
            Some(("state", label)),
        );
    }

    /// Updates the greatest currently observed unresolved-effect age.
    pub fn observe_unknown_effect_age(&self, age_seconds: u64) {
        self.effect_unknown_oldest_age_seconds
            .fetch_max(age_seconds, Ordering::Relaxed);
        if let Some(otel) = &self.otel {
            otel.gauge(
                "cigar_effect_unknown_oldest_age_seconds",
                self.effect_unknown_oldest_age_seconds
                    .load(Ordering::Relaxed),
                None,
            );
        }
    }

    /// Records one closed reconciliation result.
    pub fn record_reconciliation(&self, outcome: ReconciliationOutcome) {
        self.record_closed_counter(
            &self.effect_reconciliations,
            outcome.index(),
            "cigar_effect_reconciliations_total",
            1,
            Some(("outcome", outcome.as_str())),
        );
    }

    /// Records one content-free blob-integrity probe result.
    pub fn record_blob_integrity(&self, outcome: BlobIntegrityOutcome) {
        self.record_closed_counter(
            &self.blob_integrity,
            outcome.index(),
            "cigar_blob_integrity_total",
            1,
            Some(("outcome", outcome.as_str())),
        );
    }

    /// Records a governed API failure after authentication and admission.
    pub fn record_api_failure(&self) {
        self.record_counter(
            &self.api_requests[2],
            "cigar_api_requests_total",
            1,
            Some(("outcome", "failed")),
        );
    }

    /// Records one bounded stream event without operation or caller identity.
    pub fn record_stream_backpressure(&self, event: StreamBackpressureEvent) {
        self.record_closed_counter(
            &self.stream_backpressure,
            event.index(),
            "cigar_api_stream_backpressure_total",
            1,
            Some(("event", event.as_str())),
        );
    }

    /// Observes all process-owned queue and blocking-pool resource state.
    pub fn observe_runtime(&self, queues: &[QueueMetricsSnapshot], blocking: BlockingPoolMetrics) {
        for queue in queues {
            let index = worker_index(queue.kind);
            let label = queue.kind.as_str();
            let oldest_age_seconds = queue.oldest_age_nanos.unwrap_or(0) / 1_000_000_000;
            if queue.kind == WorkerKind::Invalidation {
                self.observe_invalidation_age(oldest_age_seconds);
            }
            let values = [
                ("cigar_worker_queue_depth", u64_from_usize(queue.depth)),
                (
                    "cigar_worker_queue_capacity",
                    u64_from_usize(queue.capacity),
                ),
                ("cigar_worker_queue_oldest_age_seconds", oldest_age_seconds),
            ];
            if let Some(otel) = &self.otel {
                for (name, value) in values {
                    otel.gauge(name, value, Some(("worker", label)));
                }
                if let Some(exported) = self.exported_queue_rejections.get(index) {
                    let previous = exported.swap(queue.rejection_count, Ordering::Relaxed);
                    otel.counter(
                        "cigar_worker_queue_rejections_total",
                        queue.rejection_count.saturating_sub(previous),
                        Some(("worker", label)),
                    );
                }
            }
        }
        let jobs = [
            u64_from_usize(blocking.in_use),
            u64_from_usize(blocking.queued),
            u64_from_usize(blocking.active_capacity),
            u64_from_usize(blocking.queue_capacity),
        ];
        let job_labels = ["active", "queued", "active_capacity", "queue_capacity"];
        for ((local, value), label) in self.blocking_jobs.iter().zip(jobs).zip(job_labels) {
            local.store(value, Ordering::Relaxed);
            if let Some(otel) = &self.otel {
                otel.gauge("cigar_blocking_pool_jobs", value, Some(("state", label)));
            }
        }
        let outcomes = [
            blocking.completion_count,
            blocking.rejection_count,
            blocking.cancellation_count,
            blocking.deadline_count,
        ];
        let outcome_labels = ["completed", "rejected", "cancelled", "deadline"];
        for (((local, exported), value), label) in self
            .blocking_outcomes
            .iter()
            .zip(&self.exported_blocking_outcomes)
            .zip(outcomes)
            .zip(outcome_labels)
        {
            local.store(value, Ordering::Relaxed);
            if let Some(otel) = &self.otel {
                let previous = exported.swap(value, Ordering::Relaxed);
                otel.counter(
                    "cigar_blocking_pool_outcomes_total",
                    value.saturating_sub(previous),
                    Some(("outcome", label)),
                );
            }
        }
        self.observe_process();
    }

    /// Replaces one worker's current remaining durable lease duration.
    pub fn observe_worker_lease(&self, kind: WorkerKind, remaining_seconds: u64) {
        self.observe_closed_gauge(
            &self.worker_lease_remaining_seconds,
            worker_index(kind),
            "cigar_worker_lease_remaining_seconds",
            remaining_seconds,
            Some(("worker", kind.as_str())),
        );
    }

    /// Replaces the closed database-pool connection observations.
    pub fn observe_database_pool(&self, active: u64, idle: u64, maximum: u64) {
        for ((local, value), label) in self
            .database_connections
            .iter()
            .zip([active, idle, maximum])
            .zip(["active", "idle", "maximum"])
        {
            self.observe_gauge(
                local,
                "cigar_database_pool_connections",
                value,
                Some(("state", label)),
            );
        }
    }

    /// Records database connection-pool waits.
    pub fn record_database_pool_waits(&self, count: u64) {
        self.record_counter(
            &self.database_pool_waits,
            "cigar_database_pool_waits_total",
            count,
            None,
        );
    }

    /// Records one content-free startup stage and terminal readiness/failure outcome.
    pub fn record_startup_stage(&self, metrics: RepositoryStartupMetrics) {
        let (index, label) = repository_startup_stage_index_label(metrics.stage);
        let duration = duration_nanoseconds(metrics.duration);
        self.record_counter(
            &self.startup_duration_nanos,
            "cigar_startup_duration_nanoseconds_total",
            duration,
            None,
        );
        self.record_closed_counter(
            &self.startup_stage_duration_nanos,
            index,
            "cigar_startup_stage_duration_nanoseconds_total",
            duration,
            Some(("stage", label)),
        );
        self.record_closed_counter(
            &self.startup_stage_runs,
            index,
            "cigar_startup_stage_runs_total",
            1,
            Some(("stage", label)),
        );
        match metrics.outcome {
            RepositoryStartupOutcome::Completed
                if metrics.stage == RepositoryStartupStage::ReadinessOpen =>
            {
                self.record_closed_counter(
                    &self.startup_outcomes,
                    0,
                    "cigar_startup_outcomes_total",
                    1,
                    Some(("outcome", "ready")),
                );
            }
            RepositoryStartupOutcome::Completed => {}
            RepositoryStartupOutcome::Failed => {
                self.record_closed_counter(
                    &self.startup_stage_failures,
                    index,
                    "cigar_startup_stage_failures_total",
                    1,
                    Some(("stage", label)),
                );
                self.record_closed_counter(
                    &self.startup_outcomes,
                    1,
                    "cigar_startup_outcomes_total",
                    1,
                    Some(("outcome", "failed")),
                );
            }
        }
    }

    /// Records one successful durable commit or idempotent replay using only closed numeric data.
    pub fn record_repository_commit(&self, metrics: RepositoryCommitMetrics) {
        let (kind_index, kind_label) = repository_commit_kind_index_label(metrics.kind);
        self.record_closed_counter(
            &self.repository_commit_kinds,
            kind_index,
            "cigar_repository_commit_kinds_total",
            1,
            Some(("kind", kind_label)),
        );
        let (outcome_index, outcome_label) = repository_commit_outcome_index_label(metrics.outcome);
        self.record_closed_counter(
            &self.repository_commit_outcomes,
            outcome_index,
            "cigar_repository_commit_outcomes_total",
            1,
            Some(("outcome", outcome_label)),
        );
        let committed = metrics.outcome == RepositoryCommitOutcome::Committed;
        let phases = [
            (metrics.durations.total, true),
            (metrics.durations.lock_wait, true),
            (metrics.durations.repository_load, true),
            (metrics.durations.residual_decode, true),
            (metrics.durations.staged_mutation, true),
            (
                metrics.durations.delta_encode,
                metrics.bytes.encoded_delta > 0,
            ),
            (
                metrics.durations.full_encode,
                metrics.bytes.checkpoint > 0 || metrics.bytes.full_state > 0,
            ),
            (metrics.durations.catalog_root, committed),
            (metrics.durations.sqlite_transaction, true),
            (metrics.durations.commit_fsync, committed),
            (metrics.durations.revision_anchor, committed),
        ];
        for (index, (duration, executed)) in phases.into_iter().enumerate() {
            if !executed {
                continue;
            }
            let Some(label) = cigar_observe::REPOSITORY_COMMIT_PHASE_VALUES.get(index) else {
                continue;
            };
            self.record_closed_counter(
                &self.repository_commit_duration_nanos,
                index,
                "cigar_repository_commit_duration_nanoseconds_total",
                duration_nanoseconds(duration),
                Some(("phase", label)),
            );
            self.record_closed_counter(
                &self.repository_commit_phase_runs,
                index,
                "cigar_repository_commit_phase_runs_total",
                1,
                Some(("phase", label)),
            );
        }
        self.record_counter(
            &self.repository_logical_bytes,
            "cigar_repository_logical_bytes_total",
            metrics.bytes.logical_changed,
            None,
        );
        for (index, (label, value)) in [
            ("delta", metrics.bytes.encoded_delta),
            ("checkpoint", metrics.bytes.checkpoint),
            ("full_state", metrics.bytes.full_state),
        ]
        .into_iter()
        .enumerate()
        {
            self.record_closed_counter(
                &self.repository_encoded_bytes,
                index,
                "cigar_repository_encoded_bytes_total",
                value,
                Some(("encoding", label)),
            );
        }
        for (index, (label, before, after)) in [
            (
                "database",
                metrics.bytes.database_before,
                metrics.bytes.database_after,
            ),
            ("wal", metrics.bytes.wal_before, metrics.bytes.wal_after),
        ]
        .into_iter()
        .enumerate()
        {
            if let (Some(before), Some(after)) = (before, after) {
                self.record_closed_counter(
                    &self.repository_file_growth_bytes,
                    index,
                    "cigar_repository_file_growth_bytes_total",
                    after.saturating_sub(before),
                    Some(("file", label)),
                );
                self.observe_closed_gauge(
                    &self.repository_file_bytes,
                    index,
                    "cigar_repository_file_bytes",
                    after,
                    Some(("file", label)),
                );
            }
        }
        for (index, (label, count)) in [
            ("full_state", metrics.retained.full_states),
            ("checkpoint", metrics.retained.checkpoints),
            ("delta", metrics.retained.deltas),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(count) = count {
                self.observe_closed_gauge(
                    &self.repository_retained_records,
                    index,
                    "cigar_repository_retained_records",
                    count,
                    Some(("record", label)),
                );
            }
        }
        self.record_counter(
            &self.repository_revision_delta,
            "cigar_repository_revision_delta_total",
            metrics.revision_delta(),
            None,
        );
        if let Some(ratio) = metrics.bytes.write_amplification_millionths() {
            self.observe_gauge(
                &self.repository_write_amplification_millionths,
                "cigar_repository_write_amplification_millionths",
                ratio,
                None,
            );
        }
        if metrics.receipt_only && metrics.outcome == RepositoryCommitOutcome::Committed {
            self.record_counter(
                &self.repository_zero_logical_commits,
                "cigar_repository_zero_logical_commits_total",
                1,
                None,
            );
        }
    }

    fn record_counter(
        &self,
        local: &AtomicU64,
        name: &'static str,
        value: u64,
        label: Option<(&'static str, &'static str)>,
    ) {
        atomic_saturating_add(local, value);
        if let Some(otel) = &self.otel {
            otel.counter(name, value, label);
        }
    }

    fn record_closed_counter(
        &self,
        locals: &[AtomicU64],
        index: usize,
        name: &'static str,
        value: u64,
        label: Option<(&'static str, &'static str)>,
    ) {
        if let Some(local) = locals.get(index) {
            self.record_counter(local, name, value, label);
        }
    }

    fn observe_gauge(
        &self,
        local: &AtomicU64,
        name: &'static str,
        value: u64,
        label: Option<(&'static str, &'static str)>,
    ) {
        local.store(value, Ordering::Relaxed);
        if let Some(otel) = &self.otel {
            otel.gauge(name, value, label);
        }
    }

    fn observe_closed_gauge(
        &self,
        locals: &[AtomicU64],
        index: usize,
        name: &'static str,
        value: u64,
        label: Option<(&'static str, &'static str)>,
    ) {
        if let Some(local) = locals.get(index) {
            self.observe_gauge(local, name, value, label);
        }
    }

    fn observe_process(&self) {
        let process = self.process.snapshot();
        if let Some(otel) = &self.otel {
            for (name, value) in [
                ("cigar_daemon_uptime_seconds", process.uptime_seconds),
                ("cigar_daemon_cpu_time_seconds", process.cpu_time_seconds),
                (
                    "cigar_daemon_resident_memory_bytes",
                    process.resident_memory_bytes,
                ),
                (
                    "cigar_daemon_virtual_memory_bytes",
                    process.virtual_memory_bytes,
                ),
                (
                    "cigar_daemon_open_file_descriptors",
                    process.open_file_descriptors,
                ),
            ] {
                otel.gauge(name, value, None);
            }
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
        let process = self.process.snapshot();
        if let Some(otel) = &self.otel {
            for (name, value) in process_values(process) {
                otel.gauge(name, value, None);
            }
        }
        let mut output = String::with_capacity(32 * 1024);
        for definition in DAEMON_METRICS {
            output.push_str("# HELP ");
            output.push_str(definition.name);
            output.push(' ');
            output.push_str(definition.help);
            output.push('\n');
            output.push_str("# TYPE ");
            output.push_str(definition.name);
            output.push(' ');
            output.push_str(definition.kind.as_str());
            output.push('\n');
            match definition.label {
                None => render_sample(
                    &mut output,
                    definition.name,
                    None,
                    self.metric_value(definition.name, None, queues, process),
                ),
                Some(domain) => {
                    for value in domain.values {
                        render_sample(
                            &mut output,
                            definition.name,
                            Some((domain.key, value)),
                            self.metric_value(definition.name, Some(value), queues, process),
                        );
                    }
                }
            }
        }
        output.push_str("# EOF\n");
        output
    }

    fn metric_value(
        &self,
        name: &str,
        label: Option<&str>,
        queues: &[QueueMetricsSnapshot],
        process: ProcessSnapshot,
    ) -> u64 {
        match name {
            "cigar_daemon_authorized_requests_total" => {
                self.authorized_requests.load(Ordering::Relaxed)
            }
            "cigar_daemon_rejected_requests_total" => {
                self.rejected_requests.load(Ordering::Relaxed)
            }
            "cigar_daemon_listener_failures_total" => {
                self.listener_failures.load(Ordering::Relaxed)
            }
            "cigar_daemon_graceful_shutdowns_total" => {
                self.graceful_shutdowns.load(Ordering::Relaxed)
            }
            "cigar_ingestion_atoms_total" => {
                indexed_value(&self.ingestion_atoms, label, &["published", "tombstoned"])
            }
            "cigar_ingestion_bytes_total" => self.ingestion_bytes.load(Ordering::Relaxed),
            "cigar_ingestion_parser_failures_total" => indexed_value(
                &self.parser_failures,
                label,
                &["source", "atomizer", "code_intelligence"],
            ),
            "cigar_ingestion_quarantines_total" => self.quarantines.load(Ordering::Relaxed),
            "cigar_index_lag_revisions" => self.index_lag_revisions.load(Ordering::Relaxed),
            "cigar_invalidation_fanout_total" => self.invalidation_fanout.load(Ordering::Relaxed),
            "cigar_invalidation_oldest_age_seconds" => {
                self.invalidation_oldest_age_seconds.load(Ordering::Relaxed)
            }
            "cigar_context_candidates_total" => self.candidates.load(Ordering::Relaxed),
            "cigar_context_selected_blocks_total" => self.selected_blocks.load(Ordering::Relaxed),
            "cigar_context_candidate_stage_total" => indexed_value(
                &self.compile_candidate_stages,
                label,
                cigar_observe::COMPILE_CANDIDATE_STAGE_VALUES,
            ),
            "cigar_context_compile_results_total" => indexed_value(
                &self.compile_results,
                label,
                cigar_observe::COMPILE_RESULT_VALUES,
            ),
            "cigar_context_lane_tokens_total" => indexed_value(
                &self.lane_tokens,
                label,
                &["rules", "task", "evidence", "history", "tools"],
            ),
            "cigar_compile_phase_duration_nanoseconds_total" => indexed_value(
                &self.compile_phase_duration_nanos,
                label,
                &[
                    "scope",
                    "retrieve",
                    "authorize",
                    "reconcile",
                    "transform",
                    "pack",
                    "materialize",
                ],
            ),
            "cigar_compile_phase_runs_total" => indexed_value(
                &self.compile_phase_runs,
                label,
                &[
                    "scope",
                    "retrieve",
                    "authorize",
                    "reconcile",
                    "transform",
                    "pack",
                    "materialize",
                ],
            ),
            "cigar_compile_conflicts_total" => self.compile_conflicts.load(Ordering::Relaxed),
            "cigar_compile_stale_total" => self.compile_stale.load(Ordering::Relaxed),
            "cigar_retrieval_cache_events_total" => {
                cache_value(&self.cache_events, CacheLayer::Retrieval, label)
            }
            "cigar_plan_cache_events_total" => {
                cache_value(&self.cache_events, CacheLayer::Plan, label)
            }
            "cigar_bundle_cache_events_total" => {
                cache_value(&self.cache_events, CacheLayer::Bundle, label)
            }
            "cigar_materialization_cache_events_total" => {
                cache_value(&self.cache_events, CacheLayer::Materialization, label)
            }
            "cigar_context_physical_tokens_total" => self.physical_tokens.load(Ordering::Relaxed),
            "cigar_context_cache_tokens_total" => {
                indexed_value(&self.cache_tokens, label, &["read", "write"])
            }
            "cigar_handoff_acceptance_total" => indexed_value(
                &self.handoff_acceptance,
                label,
                &["accepted", "rejected", "expired"],
            ),
            "cigar_handoff_merge_conflicts_total" => {
                self.handoff_merge_conflicts.load(Ordering::Relaxed)
            }
            "cigar_effect_state_observations_total" => indexed_value(
                &self.effect_states,
                label,
                cigar_observe::EFFECT_STATE_VALUES,
            ),
            "cigar_effect_unknown_oldest_age_seconds" => self
                .effect_unknown_oldest_age_seconds
                .load(Ordering::Relaxed),
            "cigar_effect_reconciliations_total" => indexed_value(
                &self.effect_reconciliations,
                label,
                &["resolved", "unresolved", "failed"],
            ),
            "cigar_worker_queue_depth" => {
                queue_value(queues, label, |queue| u64_from_usize(queue.depth))
            }
            "cigar_worker_queue_capacity" => {
                queue_value(queues, label, |queue| u64_from_usize(queue.capacity))
            }
            "cigar_worker_queue_rejections_total" => {
                queue_value(queues, label, |queue| queue.rejection_count)
            }
            "cigar_worker_queue_oldest_age_seconds" => queue_value(queues, label, |queue| {
                queue.oldest_age_nanos.unwrap_or(0) / 1_000_000_000
            }),
            "cigar_worker_lease_remaining_seconds" => indexed_value(
                &self.worker_lease_remaining_seconds,
                label,
                cigar_observe::WORKER_VALUES,
            ),
            "cigar_database_pool_connections" => indexed_value(
                &self.database_connections,
                label,
                &["active", "idle", "maximum"],
            ),
            "cigar_database_pool_waits_total" => self.database_pool_waits.load(Ordering::Relaxed),
            "cigar_startup_duration_nanoseconds_total" => {
                self.startup_duration_nanos.load(Ordering::Relaxed)
            }
            "cigar_startup_stage_duration_nanoseconds_total" => indexed_value(
                &self.startup_stage_duration_nanos,
                label,
                cigar_observe::STARTUP_STAGE_VALUES,
            ),
            "cigar_startup_stage_runs_total" => indexed_value(
                &self.startup_stage_runs,
                label,
                cigar_observe::STARTUP_STAGE_VALUES,
            ),
            "cigar_startup_stage_failures_total" => indexed_value(
                &self.startup_stage_failures,
                label,
                cigar_observe::STARTUP_STAGE_VALUES,
            ),
            "cigar_startup_outcomes_total" => indexed_value(
                &self.startup_outcomes,
                label,
                cigar_observe::STARTUP_OUTCOME_VALUES,
            ),
            "cigar_repository_commit_kinds_total" => indexed_value(
                &self.repository_commit_kinds,
                label,
                cigar_observe::REPOSITORY_COMMIT_KIND_VALUES,
            ),
            "cigar_repository_commit_outcomes_total" => indexed_value(
                &self.repository_commit_outcomes,
                label,
                cigar_observe::REPOSITORY_COMMIT_OUTCOME_VALUES,
            ),
            "cigar_repository_commit_duration_nanoseconds_total" => indexed_value(
                &self.repository_commit_duration_nanos,
                label,
                cigar_observe::REPOSITORY_COMMIT_PHASE_VALUES,
            ),
            "cigar_repository_commit_phase_runs_total" => indexed_value(
                &self.repository_commit_phase_runs,
                label,
                cigar_observe::REPOSITORY_COMMIT_PHASE_VALUES,
            ),
            "cigar_repository_logical_bytes_total" => {
                self.repository_logical_bytes.load(Ordering::Relaxed)
            }
            "cigar_repository_encoded_bytes_total" => indexed_value(
                &self.repository_encoded_bytes,
                label,
                &["delta", "checkpoint", "full_state"],
            ),
            "cigar_repository_file_growth_bytes_total" => indexed_value(
                &self.repository_file_growth_bytes,
                label,
                &["database", "wal"],
            ),
            "cigar_repository_file_bytes" => {
                indexed_value(&self.repository_file_bytes, label, &["database", "wal"])
            }
            "cigar_repository_retained_records" => indexed_value(
                &self.repository_retained_records,
                label,
                &["full_state", "checkpoint", "delta"],
            ),
            "cigar_repository_revision_delta_total" => {
                self.repository_revision_delta.load(Ordering::Relaxed)
            }
            "cigar_repository_write_amplification_millionths" => self
                .repository_write_amplification_millionths
                .load(Ordering::Relaxed),
            "cigar_repository_zero_logical_commits_total" => {
                self.repository_zero_logical_commits.load(Ordering::Relaxed)
            }
            "cigar_blob_integrity_total" => indexed_value(
                &self.blob_integrity,
                label,
                &["verified", "missing", "corrupt"],
            ),
            "cigar_api_requests_total" => indexed_value(
                &self.api_requests,
                label,
                &["accepted", "rejected", "failed"],
            ),
            "cigar_api_stream_backpressure_total" => indexed_value(
                &self.stream_backpressure,
                label,
                &["opened", "blocked", "cancelled"],
            ),
            "cigar_daemon_uptime_seconds" => process.uptime_seconds,
            "cigar_daemon_cpu_time_seconds" => process.cpu_time_seconds,
            "cigar_daemon_resident_memory_bytes" => process.resident_memory_bytes,
            "cigar_daemon_virtual_memory_bytes" => process.virtual_memory_bytes,
            "cigar_daemon_open_file_descriptors" => process.open_file_descriptors,
            "cigar_blocking_pool_jobs" => indexed_value(
                &self.blocking_jobs,
                label,
                &["active", "queued", "active_capacity", "queue_capacity"],
            ),
            "cigar_blocking_pool_outcomes_total" => indexed_value(
                &self.blocking_outcomes,
                label,
                &["completed", "rejected", "cancelled", "deadline"],
            ),
            _ => 0,
        }
    }
}

impl RepositoryCommitMetricsObserver for DaemonTelemetry {
    fn observe_repository_commit(&self, metrics: RepositoryCommitMetrics) {
        self.record_repository_commit(metrics);
    }
}

impl RepositoryStartupMetricsObserver for DaemonTelemetry {
    fn observe_repository_startup(&self, metrics: RepositoryStartupMetrics) {
        self.record_startup_stage(metrics);
    }
}

impl Default for DaemonTelemetry {
    fn default() -> Self {
        Self::local()
    }
}

impl TransportMetricsObserver for DaemonTelemetry {
    fn record_transport_metric(&self, event: TransportMetricEvent) {
        match event {
            TransportMetricEvent::ApiFailure => self.record_api_failure(),
            TransportMetricEvent::StreamOpened => {
                self.record_stream_backpressure(StreamBackpressureEvent::Opened);
            }
            TransportMetricEvent::StreamBlocked => {
                self.record_stream_backpressure(StreamBackpressureEvent::Blocked);
            }
            TransportMetricEvent::StreamCancelled => {
                self.record_stream_backpressure(StreamBackpressureEvent::Cancelled);
            }
        }
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

fn render_sample(output: &mut String, name: &str, label: Option<(&str, &str)>, value: u64) {
    output.push_str(name);
    if let Some((key, value)) = label {
        output.push('{');
        output.push_str(key);
        output.push_str("=\"");
        output.push_str(value);
        output.push_str("\"}");
    }
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn indexed_value<const N: usize>(
    values: &[AtomicU64; N],
    label: Option<&str>,
    labels: &[&str],
) -> u64 {
    label
        .and_then(|value| labels.iter().position(|candidate| *candidate == value))
        .and_then(|index| values.get(index))
        .map_or(0, |value| value.load(Ordering::Relaxed))
}

fn cache_value(
    values: &[AtomicU64; CACHE_OBSERVATION_COUNT],
    layer: CacheLayer,
    label: Option<&str>,
) -> u64 {
    label
        .and_then(|value| {
            cigar_observe::CACHE_REASON_VALUES
                .iter()
                .position(|candidate| *candidate == value)
        })
        .and_then(|reason| {
            layer
                .index()
                .checked_mul(cigar_observe::CACHE_REASON_VALUES.len())
                .and_then(|base| base.checked_add(reason))
        })
        .and_then(|index| values.get(index))
        .map_or(0, |value| value.load(Ordering::Relaxed))
}

fn queue_value(
    queues: &[QueueMetricsSnapshot],
    label: Option<&str>,
    value: impl Fn(&QueueMetricsSnapshot) -> u64,
) -> u64 {
    label
        .and_then(|label| queues.iter().find(|queue| queue.kind.as_str() == label))
        .map_or(0, value)
}

fn atomic_saturating_add(target: &AtomicU64, value: u64) {
    let mut current = target.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(value);
        match target.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn duration_nanoseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

const fn repository_startup_stage_index_label(
    stage: RepositoryStartupStage,
) -> (usize, &'static str) {
    match stage {
        RepositoryStartupStage::PathConfiguration => (0, "path_configuration"),
        RepositoryStartupStage::SqliteOpenConfigure => (1, "sqlite_open_configure"),
        RepositoryStartupStage::MigrationLedger => (2, "migration_ledger"),
        RepositoryStartupStage::LatestCheckpointRead => (3, "latest_checkpoint_read"),
        RepositoryStartupStage::ChecksumVerification => (4, "checksum_verification"),
        RepositoryStartupStage::DeltaReplay => (5, "delta_replay"),
        RepositoryStartupStage::ResidualDecode => (6, "residual_decode"),
        RepositoryStartupStage::CatalogProjection => (7, "catalog_projection"),
        RepositoryStartupStage::RevisionAnchor => (8, "revision_anchor"),
        RepositoryStartupStage::BlobReconciliation => (9, "blob_reconciliation"),
        RepositoryStartupStage::ReadinessOpen => (10, "readiness_open"),
    }
}

const fn repository_commit_kind_index_label(kind: RepositoryCommitKind) -> (usize, &'static str) {
    match kind {
        RepositoryCommitKind::Repository => (0, "repository"),
        RepositoryCommitKind::Service => (1, "service"),
        RepositoryCommitKind::Worker => (2, "worker"),
    }
}

const fn repository_commit_outcome_index_label(
    outcome: RepositoryCommitOutcome,
) -> (usize, &'static str) {
    match outcome {
        RepositoryCommitOutcome::Committed => (0, "committed"),
        RepositoryCommitOutcome::Replayed => (1, "replayed"),
    }
}

fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

const fn worker_index(kind: WorkerKind) -> usize {
    match kind {
        WorkerKind::Ingestion => 0,
        WorkerKind::Indexing => 1,
        WorkerKind::Invalidation => 2,
        WorkerKind::Compilation => 3,
        WorkerKind::Outbox => 4,
        WorkerKind::Reconciliation => 5,
        WorkerKind::LeaseCleanup => 6,
        WorkerKind::Backup => 7,
        WorkerKind::GarbageCollection => 8,
    }
}

const fn lane_index_label(lane: LaneKind) -> (usize, &'static str) {
    match lane {
        LaneKind::Rules => (0, "rules"),
        LaneKind::Task => (1, "task"),
        LaneKind::Evidence => (2, "evidence"),
        LaneKind::History => (3, "history"),
        LaneKind::Tools => (4, "tools"),
    }
}

const fn effect_state_index_label(state: EffectState) -> (usize, &'static str) {
    match state {
        EffectState::Prepared => (0, "prepared"),
        EffectState::PendingApproval => (1, "pending_approval"),
        EffectState::Authorized => (2, "authorized"),
        EffectState::Dispatching => (3, "dispatching"),
        EffectState::Succeeded => (4, "succeeded"),
        EffectState::Failed => (5, "failed"),
        EffectState::Unknown => (6, "unknown"),
        EffectState::AuthorizedForRetry => (7, "authorized_for_retry"),
        EffectState::ManualResolution => (8, "manual_resolution"),
        EffectState::Rejected => (9, "rejected"),
        EffectState::Expired => (10, "expired"),
        EffectState::Cancelled => (11, "cancelled"),
        EffectState::CompensationPending => (12, "compensation_pending"),
        EffectState::Compensating => (13, "compensating"),
        EffectState::Compensated => (14, "compensated"),
        EffectState::CompensationFailed => (15, "compensation_failed"),
    }
}

fn process_values(process: ProcessSnapshot) -> [(&'static str, u64); 5] {
    [
        ("cigar_daemon_uptime_seconds", process.uptime_seconds),
        ("cigar_daemon_cpu_time_seconds", process.cpu_time_seconds),
        (
            "cigar_daemon_resident_memory_bytes",
            process.resident_memory_bytes,
        ),
        (
            "cigar_daemon_virtual_memory_bytes",
            process.virtual_memory_bytes,
        ),
        (
            "cigar_daemon_open_file_descriptors",
            process.open_file_descriptors,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        BlobIntegrityOutcome, CacheLayer, CacheReason, CompileCandidateStage, CompilePhase,
        CompileResultCounts, DaemonTelemetry, HandoffAcceptanceOutcome, OtlpConfig, ParserStage,
        ReconciliationOutcome, TelemetryError, atomic_saturating_add, strip_ambient_otlp_metadata,
    };
    use crate::{BlockingPoolMetrics, OverflowPolicy, QueueMetricsSnapshot, WorkerKind};
    use cigar_api::{TransportMetricEvent, TransportMetricsObserver};
    use cigar_observe::{DAEMON_METRICS, maximum_daemon_series};
    use cigar_store::{
        RepositoryCommitBytes, RepositoryCommitDurations, RepositoryCommitKind,
        RepositoryCommitMetrics, RepositoryCommitOutcome, RepositoryRetentionCounts,
        RepositoryStartupMetrics, RepositoryStartupOutcome, RepositoryStartupStage, StoreRevision,
    };
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn atomic_accumulator_is_contention_safe_and_saturating() {
        const THREADS: u64 = 8;
        const INCREMENTS: u64 = 10_000;

        let value = Arc::new(AtomicU64::new(0));
        let mut workers = Vec::new();
        for _ in 0..THREADS {
            let value = Arc::clone(&value);
            workers.push(thread::spawn(move || {
                for _ in 0..INCREMENTS {
                    atomic_saturating_add(&value, 1);
                }
            }));
        }
        for worker in workers {
            assert!(worker.join().is_ok(), "telemetry accumulator worker joins");
        }
        assert_eq!(value.load(Ordering::Relaxed), THREADS * INCREMENTS);

        value.store(u64::MAX - 1, Ordering::Relaxed);
        atomic_saturating_add(&value, 8);
        assert_eq!(value.load(Ordering::Relaxed), u64::MAX);
        atomic_saturating_add(&value, 1);
        assert_eq!(value.load(Ordering::Relaxed), u64::MAX);
    }

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
    fn openmetrics_emits_the_exact_complete_closed_catalog() {
        let telemetry = DaemonTelemetry::default();
        telemetry.record_ingestion(2, 3, 5);
        telemetry.record_parser_failure(ParserStage::Source);
        telemetry.record_quarantines(7);
        telemetry.observe_index_lag(11);
        telemetry.record_invalidation(13, 17);
        telemetry.record_compile_selection(19, 23);
        telemetry.record_compile_measurements(
            [
                (CompileCandidateStage::BeforeGovernance, 101),
                (CompileCandidateStage::AfterGovernance, 83),
                (CompileCandidateStage::AfterLogicalCoalescing, 79),
                (CompileCandidateStage::AfterContentGrouping, 67),
                (CompileCandidateStage::AfterBudgetSelection, 23),
            ],
            CompileResultCounts {
                selected_blocks: 23,
                unique_content_keys: 21,
                unique_source_versions: 23,
                unique_lineages: 17,
                budget_displaced: 44,
                mandatory_candidates: 3,
                blocking_requirements_satisfied: 2,
            },
        );
        telemetry.record_compile_phase(CompilePhase::Pack, Duration::from_nanos(29));
        telemetry.record_compile_conflicts(31);
        telemetry.record_compile_stale(37);
        telemetry.record_cache_observation(CacheLayer::Materialization, CacheReason::Hit);
        telemetry.record_materialization_tokens(41, 43, 47);
        telemetry.record_handoff_acceptance(HandoffAcceptanceOutcome::Expired);
        telemetry.record_handoff_merge_conflicts(53);
        telemetry.observe_unknown_effect_age(59);
        telemetry.record_reconciliation(ReconciliationOutcome::Resolved);
        telemetry.record_blob_integrity(BlobIntegrityOutcome::Verified);
        telemetry.observe_database_pool(2, 3, 5);
        telemetry.record_database_pool_waits(61);
        telemetry.record_startup_stage(RepositoryStartupMetrics {
            stage: RepositoryStartupStage::MigrationLedger,
            outcome: RepositoryStartupOutcome::Completed,
            duration: Duration::from_nanos(43),
        });
        telemetry.record_startup_stage(RepositoryStartupMetrics {
            stage: RepositoryStartupStage::ReadinessOpen,
            outcome: RepositoryStartupOutcome::Completed,
            duration: Duration::from_nanos(47),
        });
        telemetry.record_repository_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Repository,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before: StoreRevision(4),
            revision_after: StoreRevision(5),
            receipt_only: false,
            durations: RepositoryCommitDurations {
                total: Duration::from_nanos(71),
                lock_wait: Duration::from_nanos(2),
                repository_load: Duration::from_nanos(3),
                residual_decode: Duration::from_nanos(5),
                staged_mutation: Duration::from_nanos(7),
                delta_encode: Duration::from_nanos(11),
                full_encode: Duration::from_nanos(13),
                catalog_root: Duration::from_nanos(17),
                sqlite_transaction: Duration::from_nanos(19),
                commit_fsync: Duration::from_nanos(23),
                revision_anchor: Duration::from_nanos(29),
            },
            bytes: RepositoryCommitBytes {
                logical_changed: 10,
                encoded_delta: 31,
                checkpoint: 37,
                full_state: 0,
                database_before: Some(100),
                database_after: Some(130),
                wal_before: Some(20),
                wal_after: Some(40),
            },
            retained: RepositoryRetentionCounts {
                full_states: Some(3),
                checkpoints: Some(2),
                deltas: Some(4),
            },
        });
        telemetry.record_transport_metric(TransportMetricEvent::ApiFailure);
        telemetry.record_transport_metric(TransportMetricEvent::StreamOpened);
        let queues = WorkerKind::ALL.map(|kind| QueueMetricsSnapshot {
            kind,
            capacity: 8,
            depth: usize::from(kind == WorkerKind::Invalidation),
            oldest_age_nanos: (kind == WorkerKind::Invalidation).then_some(67_000_000_000),
            rejection_count: 1,
            overflow_policy: OverflowPolicy::RejectNewest,
            accepting: true,
        });
        telemetry.observe_runtime(
            &queues,
            BlockingPoolMetrics {
                active_capacity: 4,
                queue_capacity: 8,
                in_use: 1,
                queued: 2,
                rejection_count: 3,
                completion_count: 5,
                cancellation_count: 7,
                deadline_count: 11,
                accepting: true,
            },
        );

        let output = telemetry.render_openmetrics(&queues);
        assert!(output.len() < 64 * 1024);
        let help_names = output
            .lines()
            .filter_map(|line| line.strip_prefix("# HELP "))
            .filter_map(|line| line.split_once(' ').map(|(name, _help)| name))
            .collect::<BTreeSet<_>>();
        let type_names = output
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .filter_map(|line| line.split_once(' ').map(|(name, _kind)| name))
            .collect::<BTreeSet<_>>();
        let expected_names = DAEMON_METRICS
            .iter()
            .map(|definition| definition.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(help_names, expected_names);
        assert_eq!(type_names, expected_names);
        assert_eq!(
            output.lines().filter(|line| !line.starts_with('#')).count(),
            maximum_daemon_series()
        );
        for definition in DAEMON_METRICS {
            assert!(output.contains(&format!(
                "# HELP {} {}\n# TYPE {} {}\n",
                definition.name,
                definition.help,
                definition.name,
                definition.kind.as_str()
            )));
        }
        for expected in [
            "cigar_ingestion_atoms_total{outcome=\"published\"} 2",
            "cigar_compile_phase_runs_total{phase=\"pack\"} 1",
            "cigar_context_candidate_stage_total{stage=\"after_content_grouping\"} 67",
            "cigar_context_compile_results_total{kind=\"budget_displaced\"} 44",
            "cigar_materialization_cache_events_total{reason=\"hit\"} 1",
            "cigar_handoff_acceptance_total{outcome=\"expired\"} 1",
            "cigar_api_requests_total{outcome=\"failed\"} 1",
            "cigar_api_stream_backpressure_total{event=\"opened\"} 1",
            "cigar_startup_duration_nanoseconds_total 90",
            "cigar_startup_stage_runs_total{stage=\"migration_ledger\"} 1",
            "cigar_startup_outcomes_total{outcome=\"ready\"} 1",
            "cigar_repository_commit_kinds_total{kind=\"repository\"} 1",
            "cigar_repository_commit_outcomes_total{outcome=\"committed\"} 1",
            "cigar_repository_commit_phase_runs_total{phase=\"delta_encode\"} 1",
            "cigar_repository_encoded_bytes_total{encoding=\"checkpoint\"} 37",
            "cigar_repository_file_growth_bytes_total{file=\"database\"} 30",
            "cigar_repository_retained_records{record=\"delta\"} 4",
            "cigar_repository_revision_delta_total 1",
            "cigar_repository_write_amplification_millionths 5000000",
            "cigar_invalidation_oldest_age_seconds 67",
            "cigar_blocking_pool_outcomes_total{outcome=\"deadline\"} 11",
        ] {
            assert!(
                output.lines().any(|line| line == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn otlp_configuration_requires_an_explicit_valid_ca_for_https()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new())?;
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate()?;
        let ca_pem = parameters.self_signed(&key)?.pem().into_bytes();
        assert_eq!(
            OtlpConfig::new(
                "http://collector.example:4317",
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(10),
            ),
            Err(TelemetryError::InvalidConfiguration)
        );
        assert!(
            OtlpConfig::new_with_ca_certificate(
                "https://collector.example:4317",
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(10),
                ca_pem.clone(),
            )
            .is_ok()
        );
        assert_eq!(
            OtlpConfig::new(
                "https://collector.example:4317",
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(10),
            ),
            Err(TelemetryError::InvalidConfiguration)
        );
        for invalid_ca in [
            Vec::new(),
            b"not a certificate".to_vec(),
            [
                b"-----BEGIN".as_slice(),
                b" PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n".as_slice(),
            ]
            .concat(),
        ] {
            assert_eq!(
                OtlpConfig::new_with_ca_certificate(
                    "https://collector.example:4317",
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(10),
                    invalid_ca,
                ),
                Err(TelemetryError::InvalidConfiguration)
            );
        }
        let configured = OtlpConfig::new_with_ca_certificate(
            "https://collector.example:4317",
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(10),
            ca_pem.clone(),
        )?;
        let debug = format!("{configured:?}");
        assert!(debug.contains("[EXPLICIT-CA]"));
        assert!(!debug.contains(std::str::from_utf8(&ca_pem)?));
        for invalid in [
            "https://user@collector.example:4317",
            "https://user:password@collector.example:4317",
            "https://collector.example:4317/path",
            "https://collector.example:4317?tenant=other",
            "https://collector.example:4317#fragment",
            "http://localhost",
        ] {
            assert_eq!(
                OtlpConfig::new(
                    invalid,
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(10),
                ),
                Err(TelemetryError::InvalidConfiguration),
                "endpoint {invalid:?} must fail closed"
            );
        }
        for allowed in [
            "http://localhost:4317",
            "http://127.0.0.1:4317",
            "http://[::1]:4317",
        ] {
            assert!(
                OtlpConfig::new(
                    allowed,
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(10),
                )
                .is_ok(),
                "endpoint {allowed:?} should pass"
            );
        }
        assert_eq!(
            OtlpConfig::new_with_ca_certificate(
                "http://127.0.0.1:4317",
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(10),
                ca_pem,
            ),
            Err(TelemetryError::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn telemetry_surfaces_drop_ambient_metadata_and_never_accept_content_canaries()
    -> Result<(), Box<dyn std::error::Error>> {
        const CANARIES: [&str; 7] = [
            "SOURCE-CONTENT-CANARY",
            "PROMPT-CANARY",
            "SECRET-CANARY",
            "/private/path/canary",
            "user-identity-canary@example.invalid",
            "effect-argument-canary",
            "attacker-high-cardinality-7f9d4c21",
        ];

        let mut request = tonic::Request::new(());
        for (index, canary) in CANARIES.iter().enumerate() {
            let key: tonic::metadata::MetadataKey<tonic::metadata::Ascii> =
                format!("x-canary-{index}").parse()?;
            let value: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = canary.parse()?;
            request.metadata_mut().insert(key, value);
        }
        let request = strip_ambient_otlp_metadata(request)?;
        assert!(request.metadata().is_empty());

        let telemetry = DaemonTelemetry::default();
        telemetry.record_authorized_request();
        telemetry.record_rejected_request();
        telemetry.record_listener_failure();
        telemetry.record_graceful_shutdown();
        telemetry.record_startup_stage(RepositoryStartupMetrics {
            stage: RepositoryStartupStage::ChecksumVerification,
            outcome: RepositoryStartupOutcome::Failed,
            duration: Duration::from_nanos(1),
        });
        telemetry.record_repository_commit(RepositoryCommitMetrics {
            kind: RepositoryCommitKind::Worker,
            outcome: RepositoryCommitOutcome::Committed,
            revision_before: StoreRevision(8),
            revision_after: StoreRevision(9),
            receipt_only: false,
            durations: RepositoryCommitDurations::default(),
            bytes: RepositoryCommitBytes {
                logical_changed: 1,
                full_state: 1,
                database_before: Some(1),
                database_after: Some(2),
                wal_before: Some(0),
                wal_after: Some(0),
                ..RepositoryCommitBytes::default()
            },
            retained: RepositoryRetentionCounts {
                full_states: Some(1),
                ..RepositoryRetentionCounts::default()
            },
        });
        let queues = WorkerKind::ALL.map(|kind| QueueMetricsSnapshot {
            kind,
            capacity: 8,
            depth: 2,
            oldest_age_nanos: Some(2_000_000_000),
            rejection_count: 1,
            overflow_policy: OverflowPolicy::RejectNewest,
            accepting: true,
        });
        let surfaces = [
            telemetry.render_openmetrics(&queues),
            serde_json::to_string(&telemetry.snapshot())?,
            format!("{telemetry:?}"),
        ]
        .join("\n");
        for canary in CANARIES {
            assert!(!surfaces.contains(canary));
        }
        for worker in WorkerKind::ALL {
            assert!(surfaces.contains(worker.as_str()));
        }
        assert!(!surfaces.contains("tenant"));
        assert!(!surfaces.contains("principal"));
        assert!(!surfaces.contains("record_id"));
        Ok(())
    }
}
