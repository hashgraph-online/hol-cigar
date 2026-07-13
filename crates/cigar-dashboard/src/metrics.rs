//! Bounded parser for the daemon's closed, content-safe OpenMetrics profile.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_METRICS_BYTES: usize = 1024 * 1024;
const MAX_METRICS_LINES: usize = 4_096;
const MAX_LINE_BYTES: usize = 1_024;
const MAX_HELP_BYTES: usize = 256;
const MAX_SERIES: usize = 64;

const AUTHORIZED_REQUESTS: &str = "cigar_daemon_authorized_requests_total";
const REJECTED_REQUESTS: &str = "cigar_daemon_rejected_requests_total";
const LISTENER_FAILURES: &str = "cigar_daemon_listener_failures_total";
const GRACEFUL_SHUTDOWNS: &str = "cigar_daemon_graceful_shutdowns_total";
const QUEUE_DEPTH: &str = "cigar_worker_queue_depth";
const QUEUE_CAPACITY: &str = "cigar_worker_queue_capacity";
const QUEUE_REJECTIONS: &str = "cigar_worker_queue_rejections_total";
const QUEUE_OLDEST_AGE: &str = "cigar_worker_queue_oldest_age_seconds";

const WORKERS: [&str; 9] = [
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

const DEFINITIONS: [MetricDefinition; 8] = [
    MetricDefinition::counter(AUTHORIZED_REQUESTS, false),
    MetricDefinition::counter(REJECTED_REQUESTS, false),
    MetricDefinition::counter(LISTENER_FAILURES, false),
    MetricDefinition::counter(GRACEFUL_SHUTDOWNS, false),
    MetricDefinition::gauge(QUEUE_DEPTH, true),
    MetricDefinition::gauge(QUEUE_CAPACITY, true),
    MetricDefinition::counter(QUEUE_REJECTIONS, true),
    MetricDefinition::gauge(QUEUE_OLDEST_AGE, true),
];

/// Stable content-free metric parsing failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricsError {
    /// The response, line count, line length, series count, or metadata exceeded its bound.
    LimitExceeded,
    /// The response was not strict UTF-8 OpenMetrics text in the supported profile.
    InvalidSyntax,
    /// A metric family, type, or label was outside the closed daemon profile.
    UnsupportedMetric,
    /// Required HELP/TYPE/EOF metadata was missing, duplicated, or inconsistent.
    InvalidMetadata,
    /// The same metric and closed label set appeared more than once.
    DuplicateSeries,
    /// A metric was not an unsigned finite integer in the current daemon contract.
    InvalidValue,
    /// Queue families were incomplete or violated depth/capacity invariants.
    InconsistentSnapshot,
}

impl fmt::Display for MetricsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "dashboard metrics limit was exceeded",
            Self::InvalidSyntax => "dashboard metrics syntax is invalid",
            Self::UnsupportedMetric => "dashboard metrics family or label is unsupported",
            Self::InvalidMetadata => "dashboard metrics metadata is invalid",
            Self::DuplicateSeries => "dashboard metrics contain a duplicate series",
            Self::InvalidValue => "dashboard metric value is invalid",
            Self::InconsistentSnapshot => "dashboard metrics snapshot is inconsistent",
        })
    }
}

impl std::error::Error for MetricsError {}

/// One content-safe daemon worker queue observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardQueueMetrics {
    /// Closed stable worker-family label.
    pub worker: String,
    /// Durable wakeups currently queued.
    pub depth: u64,
    /// Configured hard queue capacity.
    pub capacity: u64,
    /// Rejected bounded wakeups since process start.
    pub rejections_total: u64,
    /// Integer age of the oldest queued wakeup.
    pub oldest_age_seconds: u64,
}

/// Complete parsed daemon metrics snapshot with no arbitrary labels or text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardMetrics {
    /// Requests admitted after transport authentication.
    pub authorized_requests_total: u64,
    /// Requests rejected before protected dispatch.
    pub rejected_requests_total: u64,
    /// Listener bind or unexpected-exit failures.
    pub listener_failures_total: u64,
    /// Completed bounded graceful shutdowns.
    pub graceful_shutdowns_total: u64,
    /// Queue observations in the daemon's stable worker order.
    pub queues: Vec<DashboardQueueMetrics>,
    /// Exact number of accepted series.
    pub series_count: usize,
}

impl DashboardMetrics {
    /// Parses only the current closed daemon OpenMetrics profile.
    pub fn parse(bytes: &[u8]) -> Result<Self, MetricsError> {
        if bytes.is_empty() || bytes.len() > MAX_METRICS_BYTES {
            return Err(MetricsError::LimitExceeded);
        }
        let source = std::str::from_utf8(bytes).map_err(|_error| MetricsError::InvalidSyntax)?;
        if !source.ends_with('\n') || source.contains('\r') {
            return Err(MetricsError::InvalidSyntax);
        }

        let mut help = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        let mut samples = BTreeMap::new();
        let mut line_count = 0_usize;
        let mut saw_eof = false;

        for line in source.lines() {
            line_count = line_count
                .checked_add(1)
                .filter(|count| *count <= MAX_METRICS_LINES)
                .ok_or(MetricsError::LimitExceeded)?;
            if line.is_empty() || line.len() > MAX_LINE_BYTES || saw_eof {
                return Err(if line.len() > MAX_LINE_BYTES {
                    MetricsError::LimitExceeded
                } else {
                    MetricsError::InvalidSyntax
                });
            }
            if line == "# EOF" {
                saw_eof = true;
                continue;
            }
            if let Some(metadata) = line.strip_prefix("# HELP ") {
                parse_help(metadata, &mut help)?;
                continue;
            }
            if let Some(metadata) = line.strip_prefix("# TYPE ") {
                parse_type(metadata, &mut kinds)?;
                continue;
            }
            if line.starts_with('#') {
                return Err(MetricsError::InvalidMetadata);
            }
            parse_sample(line, &help, &kinds, &mut samples)?;
        }

        if !saw_eof || help.len() != DEFINITIONS.len() || kinds.len() != DEFINITIONS.len() {
            return Err(MetricsError::InvalidMetadata);
        }
        build_snapshot(samples)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MetricKind {
    Counter,
    Gauge,
}

impl MetricKind {
    fn parse(value: &str) -> Result<Self, MetricsError> {
        match value {
            "counter" => Ok(Self::Counter),
            "gauge" => Ok(Self::Gauge),
            _ => Err(MetricsError::UnsupportedMetric),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetricDefinition {
    name: &'static str,
    kind: MetricKind,
    worker_label: bool,
}

impl MetricDefinition {
    const fn counter(name: &'static str, worker_label: bool) -> Self {
        Self {
            name,
            kind: MetricKind::Counter,
            worker_label,
        }
    }

    const fn gauge(name: &'static str, worker_label: bool) -> Self {
        Self {
            name,
            kind: MetricKind::Gauge,
            worker_label,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SeriesKey {
    name: &'static str,
    worker: Option<&'static str>,
}

fn parse_help(metadata: &str, seen: &mut BTreeSet<&'static str>) -> Result<(), MetricsError> {
    let (name, description) = metadata
        .split_once(' ')
        .ok_or(MetricsError::InvalidMetadata)?;
    let definition = definition(name)?;
    if description.is_empty()
        || description.len() > MAX_HELP_BYTES
        || !description
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(if description.len() > MAX_HELP_BYTES {
            MetricsError::LimitExceeded
        } else {
            MetricsError::InvalidMetadata
        });
    }
    if !seen.insert(definition.name) {
        return Err(MetricsError::InvalidMetadata);
    }
    Ok(())
}

fn parse_type(metadata: &str, seen: &mut BTreeSet<&'static str>) -> Result<(), MetricsError> {
    let (name, kind) = metadata
        .split_once(' ')
        .ok_or(MetricsError::InvalidMetadata)?;
    if kind.contains(char::is_whitespace) {
        return Err(MetricsError::InvalidMetadata);
    }
    let definition = definition(name)?;
    if MetricKind::parse(kind)? != definition.kind || !seen.insert(definition.name) {
        return Err(MetricsError::InvalidMetadata);
    }
    Ok(())
}

fn parse_sample(
    line: &str,
    help: &BTreeSet<&'static str>,
    kinds: &BTreeSet<&'static str>,
    samples: &mut BTreeMap<SeriesKey, u64>,
) -> Result<(), MetricsError> {
    let (selector, value) = line.split_once(' ').ok_or(MetricsError::InvalidSyntax)?;
    if value.is_empty() || value.contains(char::is_whitespace) {
        return Err(MetricsError::InvalidValue);
    }
    let (definition, worker) = parse_selector(selector)?;
    if !help.contains(definition.name) || !kinds.contains(definition.name) {
        return Err(MetricsError::InvalidMetadata);
    }
    if value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MetricsError::InvalidValue);
    }
    let number = value
        .parse::<u64>()
        .map_err(|_error| MetricsError::InvalidValue)?;
    if samples.len() >= MAX_SERIES {
        return Err(MetricsError::LimitExceeded);
    }
    if samples
        .insert(
            SeriesKey {
                name: definition.name,
                worker,
            },
            number,
        )
        .is_some()
    {
        return Err(MetricsError::DuplicateSeries);
    }
    Ok(())
}

fn parse_selector(
    selector: &str,
) -> Result<(MetricDefinition, Option<&'static str>), MetricsError> {
    if let Some((name, labels)) = selector.split_once('{') {
        let definition = definition(name)?;
        if !definition.worker_label {
            return Err(MetricsError::UnsupportedMetric);
        }
        let labels = labels
            .strip_suffix('}')
            .ok_or(MetricsError::InvalidSyntax)?;
        if labels.contains('{') || labels.contains('}') {
            return Err(MetricsError::InvalidSyntax);
        }
        let worker = labels
            .strip_prefix("worker=\"")
            .and_then(|value| value.strip_suffix('"'))
            .and_then(worker)
            .ok_or(MetricsError::UnsupportedMetric)?;
        return Ok((definition, Some(worker)));
    }

    let definition = definition(selector)?;
    if definition.worker_label || selector.contains('}') {
        return Err(MetricsError::UnsupportedMetric);
    }
    Ok((definition, None))
}

fn definition(name: &str) -> Result<MetricDefinition, MetricsError> {
    DEFINITIONS
        .iter()
        .copied()
        .find(|definition| definition.name == name)
        .ok_or(MetricsError::UnsupportedMetric)
}

fn worker(value: &str) -> Option<&'static str> {
    WORKERS.iter().copied().find(|worker| *worker == value)
}

fn build_snapshot(samples: BTreeMap<SeriesKey, u64>) -> Result<DashboardMetrics, MetricsError> {
    let authorized_requests_total = process_sample(&samples, AUTHORIZED_REQUESTS)?;
    let rejected_requests_total = process_sample(&samples, REJECTED_REQUESTS)?;
    let listener_failures_total = process_sample(&samples, LISTENER_FAILURES)?;
    let graceful_shutdowns_total = process_sample(&samples, GRACEFUL_SHUTDOWNS)?;
    let mut queues = Vec::new();

    for worker in WORKERS {
        let depth = queue_sample(&samples, QUEUE_DEPTH, worker);
        let capacity = queue_sample(&samples, QUEUE_CAPACITY, worker);
        let rejections = queue_sample(&samples, QUEUE_REJECTIONS, worker);
        let oldest_age = queue_sample(&samples, QUEUE_OLDEST_AGE, worker);
        if depth.is_none() && capacity.is_none() && rejections.is_none() && oldest_age.is_none() {
            continue;
        }
        let (depth, capacity, rejections_total, oldest_age_seconds) =
            match (depth, capacity, rejections, oldest_age) {
                (Some(depth), Some(capacity), Some(rejections), Some(oldest_age)) => {
                    (depth, capacity, rejections, oldest_age)
                }
                _ => return Err(MetricsError::InconsistentSnapshot),
            };
        if depth > capacity {
            return Err(MetricsError::InconsistentSnapshot);
        }
        queues.push(DashboardQueueMetrics {
            worker: worker.to_owned(),
            depth,
            capacity,
            rejections_total,
            oldest_age_seconds,
        });
    }

    let expected_series = 4_usize
        .checked_add(
            queues
                .len()
                .checked_mul(4)
                .ok_or(MetricsError::LimitExceeded)?,
        )
        .ok_or(MetricsError::LimitExceeded)?;
    if samples.len() != expected_series {
        return Err(MetricsError::InconsistentSnapshot);
    }
    Ok(DashboardMetrics {
        authorized_requests_total,
        rejected_requests_total,
        listener_failures_total,
        graceful_shutdowns_total,
        queues,
        series_count: expected_series,
    })
}

fn process_sample(
    samples: &BTreeMap<SeriesKey, u64>,
    name: &'static str,
) -> Result<u64, MetricsError> {
    samples
        .get(&SeriesKey { name, worker: None })
        .copied()
        .ok_or(MetricsError::InconsistentSnapshot)
}

fn queue_sample(
    samples: &BTreeMap<SeriesKey, u64>,
    name: &'static str,
    worker: &'static str,
) -> Option<u64> {
    samples
        .get(&SeriesKey {
            name,
            worker: Some(worker),
        })
        .copied()
}

#[cfg(test)]
mod tests {
    use super::{DashboardMetrics, MetricsError};

    const VALID: &str = concat!(
        "# HELP cigar_daemon_authorized_requests_total Authenticated requests.\n",
        "# TYPE cigar_daemon_authorized_requests_total counter\n",
        "cigar_daemon_authorized_requests_total 7\n",
        "# HELP cigar_daemon_rejected_requests_total Rejected requests.\n",
        "# TYPE cigar_daemon_rejected_requests_total counter\n",
        "cigar_daemon_rejected_requests_total 2\n",
        "# HELP cigar_daemon_listener_failures_total Listener failures.\n",
        "# TYPE cigar_daemon_listener_failures_total counter\n",
        "cigar_daemon_listener_failures_total 0\n",
        "# HELP cigar_daemon_graceful_shutdowns_total Graceful shutdowns.\n",
        "# TYPE cigar_daemon_graceful_shutdowns_total counter\n",
        "cigar_daemon_graceful_shutdowns_total 1\n",
        "# HELP cigar_worker_queue_depth Queue depth.\n",
        "# TYPE cigar_worker_queue_depth gauge\n",
        "# HELP cigar_worker_queue_capacity Queue capacity.\n",
        "# TYPE cigar_worker_queue_capacity gauge\n",
        "# HELP cigar_worker_queue_rejections_total Queue rejections.\n",
        "# TYPE cigar_worker_queue_rejections_total counter\n",
        "# HELP cigar_worker_queue_oldest_age_seconds Oldest age.\n",
        "# TYPE cigar_worker_queue_oldest_age_seconds gauge\n",
        "cigar_worker_queue_depth{worker=\"outbox\"} 2\n",
        "cigar_worker_queue_capacity{worker=\"outbox\"} 8\n",
        "cigar_worker_queue_rejections_total{worker=\"outbox\"} 1\n",
        "cigar_worker_queue_oldest_age_seconds{worker=\"outbox\"} 3\n",
        "# EOF\n",
    );

    #[test]
    fn parses_closed_content_safe_snapshot() -> Result<(), Box<dyn std::error::Error>> {
        let metrics = DashboardMetrics::parse(VALID.as_bytes())?;
        assert_eq!(metrics.authorized_requests_total, 7);
        assert_eq!(metrics.series_count, 8);
        assert_eq!(metrics.queues.len(), 1);
        assert_eq!(
            metrics.queues.first().map(|queue| queue.worker.as_str()),
            Some("outbox")
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_series() {
        let duplicate = VALID.replace(
            "cigar_daemon_authorized_requests_total 7\n",
            concat!(
                "cigar_daemon_authorized_requests_total 7\n",
                "cigar_daemon_authorized_requests_total 8\n",
            ),
        );
        assert_eq!(
            DashboardMetrics::parse(duplicate.as_bytes()),
            Err(MetricsError::DuplicateSeries)
        );
    }

    #[test]
    fn rejects_unknown_family_and_worker_label() {
        let unknown_family = VALID.replace(
            "cigar_daemon_authorized_requests_total 7",
            "cigar_daemon_secret_value 7",
        );
        assert_eq!(
            DashboardMetrics::parse(unknown_family.as_bytes()),
            Err(MetricsError::UnsupportedMetric)
        );

        let unknown_worker = VALID.replace("worker=\"outbox\"", "worker=\"tenant-secret\"");
        assert_eq!(
            DashboardMetrics::parse(unknown_worker.as_bytes()),
            Err(MetricsError::UnsupportedMetric)
        );
    }

    #[test]
    fn rejects_nonfinite_fractional_and_signed_values() {
        for invalid in ["NaN", "+Inf", "-1", "1.5"] {
            let source = VALID.replace(
                "cigar_daemon_authorized_requests_total 7",
                &format!("cigar_daemon_authorized_requests_total {invalid}"),
            );
            assert_eq!(
                DashboardMetrics::parse(source.as_bytes()),
                Err(MetricsError::InvalidValue)
            );
        }
    }

    #[test]
    fn rejects_incomplete_queue_family_and_impossible_depth() {
        let incomplete = VALID.replace("cigar_worker_queue_capacity{worker=\"outbox\"} 8\n", "");
        assert_eq!(
            DashboardMetrics::parse(incomplete.as_bytes()),
            Err(MetricsError::InconsistentSnapshot)
        );

        let impossible = VALID.replace(
            "cigar_worker_queue_capacity{worker=\"outbox\"} 8",
            "cigar_worker_queue_capacity{worker=\"outbox\"} 1",
        );
        assert_eq!(
            DashboardMetrics::parse(impossible.as_bytes()),
            Err(MetricsError::InconsistentSnapshot)
        );
    }

    #[test]
    fn rejects_missing_eof_and_oversized_input() {
        let missing_eof = VALID.replace("# EOF\n", "");
        assert_eq!(
            DashboardMetrics::parse(missing_eof.as_bytes()),
            Err(MetricsError::InvalidMetadata)
        );
        let oversized = vec![b'x'; 1024 * 1024 + 1];
        assert_eq!(
            DashboardMetrics::parse(&oversized),
            Err(MetricsError::LimitExceeded)
        );
    }
}
