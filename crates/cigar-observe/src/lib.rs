//! Structured content-safe tracing, metrics, health, and diagnostics.

/// Stable OpenMetrics family kind supported by the CIGAR operator surface.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricKind {
    /// Monotonic process-lifetime counter.
    Counter,
    /// Current numeric observation.
    Gauge,
}

impl MetricKind {
    /// OpenMetrics metadata symbol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

/// One closed label dimension. Every value is compiled into the binary and no metric accepts a
/// second label, arbitrary text, tenant identity, path, record identity, or content-derived value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricLabelDomain {
    /// Stable label key.
    pub key: &'static str,
    /// Complete stable value vocabulary.
    pub values: &'static [&'static str],
}

/// One family in the complete daemon OpenMetrics/OTLP catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricDefinition {
    /// OpenMetrics family name.
    pub name: &'static str,
    /// Content-free HELP description.
    pub help: &'static str,
    /// Counter or gauge semantics.
    pub kind: MetricKind,
    /// Optional single closed label dimension.
    pub label: Option<MetricLabelDomain>,
}

impl MetricDefinition {
    const fn counter(
        name: &'static str,
        help: &'static str,
        label: Option<MetricLabelDomain>,
    ) -> Self {
        Self {
            name,
            help,
            kind: MetricKind::Counter,
            label,
        }
    }

    const fn gauge(
        name: &'static str,
        help: &'static str,
        label: Option<MetricLabelDomain>,
    ) -> Self {
        Self {
            name,
            help,
            kind: MetricKind::Gauge,
            label,
        }
    }

    /// Returns whether the exact closed label pair is valid for this family.
    #[must_use]
    pub fn accepts_label(self, key: &str, value: &str) -> bool {
        self.label
            .is_some_and(|domain| domain.key == key && domain.values.contains(&value))
    }
}

/// Stable worker families shared by queue and lease observations.
pub const WORKER_VALUES: &[&str] = &[
    "ingestion",
    "indexing",
    "invalidation",
    "compilation",
    "outbox",
    "reconciliation",
    "lease_cleanup",
    "backup",
    "garbage_collection",
];
/// Stable compiler lane vocabulary.
pub const LANE_VALUES: &[&str] = &["rules", "task", "evidence", "history", "tools"];
/// Stable trace-tree compiler phase vocabulary.
pub const COMPILE_PHASE_VALUES: &[&str] = &[
    "scope",
    "retrieve",
    "authorize",
    "reconcile",
    "transform",
    "pack",
    "materialize",
];
/// Stable repository commit path vocabulary.
pub const REPOSITORY_COMMIT_KIND_VALUES: &[&str] = &["repository", "service", "worker"];
/// Stable repository commit outcome vocabulary.
pub const REPOSITORY_COMMIT_OUTCOME_VALUES: &[&str] = &["committed", "replayed"];
/// Stable repository commit timing phases.
pub const REPOSITORY_COMMIT_PHASE_VALUES: &[&str] = &[
    "total",
    "lock_wait",
    "repository_load",
    "residual_decode",
    "staged_mutation",
    "delta_encode",
    "full_encode",
    "catalog_root",
    "sqlite_transaction",
    "commit_fsync",
    "revision_anchor",
];
/// Stable repository/readiness startup timing stages.
pub const STARTUP_STAGE_VALUES: &[&str] = &[
    "path_configuration",
    "sqlite_open_configure",
    "migration_ledger",
    "latest_checkpoint_read",
    "checksum_verification",
    "delta_replay",
    "residual_decode",
    "catalog_projection",
    "revision_anchor",
    "blob_reconciliation",
    "readiness_open",
];
/// Stable terminal startup outcomes.
pub const STARTUP_OUTCOME_VALUES: &[&str] = &["ready", "failed"];
/// Stable effect-state vocabulary, identical to `cigar_protocol::EffectState` serialization.
pub const EFFECT_STATE_VALUES: &[&str] = &[
    "prepared",
    "pending_approval",
    "authorized",
    "dispatching",
    "succeeded",
    "failed",
    "unknown",
    "authorized_for_retry",
    "manual_resolution",
    "rejected",
    "expired",
    "cancelled",
    "compensation_pending",
    "compensating",
    "compensated",
    "compensation_failed",
];

const ATOM_OUTCOMES: &[&str] = &["published", "tombstoned"];
const PARSER_STAGES: &[&str] = &["source", "atomizer", "code_intelligence"];
/// Closed candidate-count checkpoints through retrieval and compilation.
pub const COMPILE_CANDIDATE_STAGE_VALUES: &[&str] = &[
    "before_governance",
    "after_governance",
    "after_logical_coalescing",
    "after_content_grouping",
    "after_budget_selection",
];
/// Closed content-free result counts from one completed compilation.
pub const COMPILE_RESULT_VALUES: &[&str] = &[
    "selected_blocks",
    "unique_content_keys",
    "unique_source_versions",
    "unique_lineages",
    "budget_displaced",
    "mandatory_candidates",
    "blocking_requirements_satisfied",
];
/// Closed cache hit, miss, and bypass reason shared by four fixed layer-specific families.
pub const CACHE_REASON_VALUES: &[&str] = &[
    "hit",
    "absent_entry",
    "policy_mismatch",
    "watermark_mismatch",
    "tokenizer_mismatch",
    "materializer_mismatch",
    "unknown_semantic_extension",
    "not_configured",
];
const CACHE_TOKEN_KINDS: &[&str] = &["read", "write"];
const HANDOFF_OUTCOMES: &[&str] = &["accepted", "rejected", "expired"];
const RECONCILIATION_OUTCOMES: &[&str] = &["resolved", "unresolved", "failed"];
const DATABASE_STATES: &[&str] = &["active", "idle", "maximum"];
const INTEGRITY_OUTCOMES: &[&str] = &["verified", "missing", "corrupt"];
const API_OUTCOMES: &[&str] = &["accepted", "rejected", "failed"];
const STREAM_EVENTS: &[&str] = &["opened", "blocked", "cancelled"];
const BLOCKING_STATES: &[&str] = &["active", "queued", "active_capacity", "queue_capacity"];
const BLOCKING_OUTCOMES: &[&str] = &["completed", "rejected", "cancelled", "deadline"];
const REPOSITORY_ENCODING_VALUES: &[&str] = &["delta", "checkpoint", "full_state"];
const REPOSITORY_FILE_VALUES: &[&str] = &["database", "wal"];
const REPOSITORY_RETAINED_VALUES: &[&str] = &["full_state", "checkpoint", "delta"];

const fn label(key: &'static str, values: &'static [&'static str]) -> Option<MetricLabelDomain> {
    Some(MetricLabelDomain { key, values })
}

/// Complete closed daemon catalog required by PRD 23.2.
///
/// Demo and benchmark result metrics are deliberately not daemon process metrics: the benchmark
/// evidence assembler owns those signed result documents. All running-daemon families are here.
pub const DAEMON_METRICS: &[MetricDefinition] = &[
    MetricDefinition::counter(
        "cigar_daemon_authorized_requests_total",
        "Authenticated requests accepted by daemon transports.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_daemon_rejected_requests_total",
        "Requests rejected before protected service dispatch.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_daemon_listener_failures_total",
        "Listener bind or unexpected-exit failures.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_daemon_graceful_shutdowns_total",
        "Completed bounded graceful shutdowns.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_ingestion_atoms_total",
        "Atom versions published or tombstoned by atomic ingestion.",
        label("outcome", ATOM_OUTCOMES),
    ),
    MetricDefinition::counter(
        "cigar_ingestion_bytes_total",
        "Eligible source bytes processed by successful ingestion.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_ingestion_parser_failures_total",
        "Content-free parser failures at closed ingestion stages.",
        label("stage", PARSER_STAGES),
    ),
    MetricDefinition::counter(
        "cigar_ingestion_quarantines_total",
        "Source records quarantined before indexing.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_index_lag_revisions",
        "Current mandatory-index lag in catalog revisions.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_invalidation_fanout_total",
        "Catalog dependencies reached by invalidation processing.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_invalidation_oldest_age_seconds",
        "Age of the oldest pending invalidation.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_context_candidates_total",
        "Authorized candidates considered by compilation.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_context_selected_blocks_total",
        "Context blocks selected by compilation.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_context_candidate_stage_total",
        "Content-free candidate counts at closed retrieval and compilation checkpoints.",
        label("stage", COMPILE_CANDIDATE_STAGE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_context_compile_results_total",
        "Content-free selected, uniqueness, displacement, and requirement counts.",
        label("kind", COMPILE_RESULT_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_context_lane_tokens_total",
        "Selected logical tokens by standard context lane.",
        label("lane", LANE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_compile_phase_duration_nanoseconds_total",
        "Monotonic elapsed compilation time by closed phase.",
        label("phase", COMPILE_PHASE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_compile_phase_runs_total",
        "Completed compilation phases.",
        label("phase", COMPILE_PHASE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_compile_conflicts_total",
        "Typed compilation conflicts.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_compile_stale_total",
        "Stale bundle or dependency observations.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_retrieval_cache_events_total",
        "Governed retrieval-cache observations by closed reason.",
        label("reason", CACHE_REASON_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_plan_cache_events_total",
        "Governed plan-cache observations by closed reason.",
        label("reason", CACHE_REASON_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_bundle_cache_events_total",
        "Governed bundle-cache observations by closed reason.",
        label("reason", CACHE_REASON_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_materialization_cache_events_total",
        "Governed materialization-cache observations by closed reason.",
        label("reason", CACHE_REASON_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_context_physical_tokens_total",
        "Exact physical input tokens materialized.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_context_cache_tokens_total",
        "Provider cache-read and cache-write tokens.",
        label("kind", CACHE_TOKEN_KINDS),
    ),
    MetricDefinition::counter(
        "cigar_handoff_acceptance_total",
        "Handoff acceptance outcomes.",
        label("outcome", HANDOFF_OUTCOMES),
    ),
    MetricDefinition::counter(
        "cigar_handoff_merge_conflicts_total",
        "Typed conflicts retained by handoff merge.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_effect_state_observations_total",
        "Durable effect projections observed by closed state.",
        label("state", EFFECT_STATE_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_effect_unknown_oldest_age_seconds",
        "Greatest observed age of an unresolved unknown effect.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_effect_reconciliations_total",
        "Effect reconciliation outcomes.",
        label("outcome", RECONCILIATION_OUTCOMES),
    ),
    MetricDefinition::gauge(
        "cigar_worker_queue_depth",
        "Durable wakeups currently queued.",
        label("worker", WORKER_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_worker_queue_capacity",
        "Configured hard queue capacity.",
        label("worker", WORKER_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_worker_queue_rejections_total",
        "Rejected bounded wakeups.",
        label("worker", WORKER_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_worker_queue_oldest_age_seconds",
        "Age of the oldest wakeup.",
        label("worker", WORKER_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_worker_lease_remaining_seconds",
        "Remaining duration of each owned worker lease.",
        label("worker", WORKER_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_database_pool_connections",
        "Database connections by closed pool state.",
        label("state", DATABASE_STATES),
    ),
    MetricDefinition::counter(
        "cigar_database_pool_waits_total",
        "Database pool acquisition waits.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_startup_duration_nanoseconds_total",
        "Monotonic elapsed time across measured startup stages.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_startup_stage_duration_nanoseconds_total",
        "Monotonic elapsed startup time by closed stage.",
        label("stage", STARTUP_STAGE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_startup_stage_runs_total",
        "Completed or failed startup stage observations.",
        label("stage", STARTUP_STAGE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_startup_stage_failures_total",
        "Fail-closed startup observations by stable closed stage.",
        label("stage", STARTUP_STAGE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_startup_outcomes_total",
        "Terminal startup outcomes after readiness or a fail-closed stage.",
        label("outcome", STARTUP_OUTCOME_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_commit_kinds_total",
        "Durable repository observations by closed mutation path.",
        label("kind", REPOSITORY_COMMIT_KIND_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_commit_outcomes_total",
        "Durable repository observations by closed outcome.",
        label("outcome", REPOSITORY_COMMIT_OUTCOME_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_commit_duration_nanoseconds_total",
        "Monotonic elapsed repository commit time by closed phase.",
        label("phase", REPOSITORY_COMMIT_PHASE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_commit_phase_runs_total",
        "Observed repository commit phases.",
        label("phase", REPOSITORY_COMMIT_PHASE_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_logical_bytes_total",
        "Bounded logical mutation bytes observed by durable commits.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_repository_encoded_bytes_total",
        "Canonical repository bytes encoded by closed record class.",
        label("encoding", REPOSITORY_ENCODING_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_file_growth_bytes_total",
        "Positive physical repository-file growth by closed file class.",
        label("file", REPOSITORY_FILE_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_repository_file_bytes",
        "Last observed physical repository-file bytes by closed file class.",
        label("file", REPOSITORY_FILE_VALUES),
    ),
    MetricDefinition::gauge(
        "cigar_repository_retained_records",
        "Last observed retained revision records by closed class.",
        label("record", REPOSITORY_RETAINED_VALUES),
    ),
    MetricDefinition::counter(
        "cigar_repository_revision_delta_total",
        "Monotonic durable repository revisions added.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_repository_write_amplification_millionths",
        "Last available positive durable-byte to logical-byte ratio in millionths.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_repository_zero_logical_commits_total",
        "Committed receipt-only revisions with zero semantic mutation bytes.",
        None,
    ),
    MetricDefinition::counter(
        "cigar_blob_integrity_total",
        "Blob integrity probe outcomes.",
        label("outcome", INTEGRITY_OUTCOMES),
    ),
    MetricDefinition::counter(
        "cigar_api_requests_total",
        "Governed API admission and post-admission failure events.",
        label("outcome", API_OUTCOMES),
    ),
    MetricDefinition::counter(
        "cigar_api_stream_backpressure_total",
        "Bounded stream lifecycle and backpressure events.",
        label("event", STREAM_EVENTS),
    ),
    MetricDefinition::gauge(
        "cigar_daemon_uptime_seconds",
        "Monotonic daemon process uptime.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_daemon_cpu_time_seconds",
        "Accumulated daemon process CPU time.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_daemon_resident_memory_bytes",
        "Daemon resident memory bytes.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_daemon_open_file_descriptors",
        "Open daemon file descriptors.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_daemon_virtual_memory_bytes",
        "Daemon virtual memory bytes.",
        None,
    ),
    MetricDefinition::gauge(
        "cigar_blocking_pool_jobs",
        "Bounded blocking-pool jobs and capacities.",
        label("state", BLOCKING_STATES),
    ),
    MetricDefinition::counter(
        "cigar_blocking_pool_outcomes_total",
        "Bounded blocking-pool outcomes.",
        label("outcome", BLOCKING_OUTCOMES),
    ),
];

/// Looks up one exact family in the closed catalog.
#[must_use]
pub fn metric_definition(name: &str) -> Option<MetricDefinition> {
    DAEMON_METRICS
        .iter()
        .copied()
        .find(|metric| metric.name == name)
}

/// Exact maximum number of series produced when every closed label value is present once.
#[must_use]
pub fn maximum_daemon_series() -> usize {
    DAEMON_METRICS
        .iter()
        .map(|definition| definition.label.map_or(1, |label| label.values.len()))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{DAEMON_METRICS, maximum_daemon_series};
    use std::collections::BTreeSet;

    #[test]
    fn metric_catalog_is_unique_bounded_and_content_free() {
        assert_eq!(DAEMON_METRICS.len(), 65);
        assert_eq!(maximum_daemon_series(), 256);
        let names: BTreeSet<_> = DAEMON_METRICS.iter().map(|metric| metric.name).collect();
        assert_eq!(names.len(), DAEMON_METRICS.len());
        assert!(maximum_daemon_series() <= 256);
        for definition in DAEMON_METRICS {
            assert!(definition.name.starts_with("cigar_"));
            assert!(
                definition
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            );
            assert!(!definition.help.is_empty());
            if let Some(label) = definition.label {
                assert!(!label.values.is_empty());
                assert!(label.values.len() <= 16);
                let values: BTreeSet<_> = label.values.iter().copied().collect();
                assert_eq!(values.len(), label.values.len());
            }
        }
    }
}
