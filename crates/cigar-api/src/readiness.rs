//! Required dependency readiness aggregation.

use cigar_protocol::{
    ComponentHealth, ErrorCode, HealthReport, HealthStatus, SchemaVersion, UtcTimestamp, Validate,
};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

const REQUIRED_COMPONENTS: [ReadinessComponent; 8] = [
    ReadinessComponent::MetadataStore,
    ReadinessComponent::MigrationLevel,
    ReadinessComponent::BlobReadWrite,
    ReadinessComponent::PolicySnapshot,
    ReadinessComponent::JournalIntegrity,
    ReadinessComponent::MandatoryIndex,
    ReadinessComponent::KeyProvider,
    ReadinessComponent::WorkerHeartbeat,
];

/// One mandatory readiness dependency.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReadinessComponent {
    /// Metadata repository connectivity and transactional health.
    MetadataStore,
    /// Installed migration level matches the expected level.
    MigrationLevel,
    /// Blob store read/write integrity probe.
    BlobReadWrite,
    /// Current policy snapshot availability and validity.
    PolicySnapshot,
    /// Critical effect journal transition and chain integrity.
    JournalIntegrity,
    /// Mandatory index health and lag bound.
    MandatoryIndex,
    /// Current key-provider availability.
    KeyProvider,
    /// Critical worker heartbeat freshness.
    WorkerHeartbeat,
}

impl ReadinessComponent {
    /// Returns the stable public component name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataStore => "metadata_store",
            Self::MigrationLevel => "migration_level",
            Self::BlobReadWrite => "blob_read_write",
            Self::PolicySnapshot => "policy_snapshot",
            Self::JournalIntegrity => "journal_integrity",
            Self::MandatoryIndex => "mandatory_index",
            Self::KeyProvider => "key_provider",
            Self::WorkerHeartbeat => "worker_heartbeat",
        }
    }
}

/// Content-safe result of one readiness probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    status: HealthStatus,
    reason: Option<ErrorCode>,
}

impl ProbeObservation {
    /// Creates a healthy observation with no failure reason.
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            status: HealthStatus::Healthy,
            reason: None,
        }
    }

    /// Creates a degraded observation with a stable public reason code.
    #[must_use]
    pub const fn degraded(reason: ErrorCode) -> Self {
        Self {
            status: HealthStatus::Degraded,
            reason: Some(reason),
        }
    }

    /// Creates an unhealthy observation with a stable public reason code.
    #[must_use]
    pub const fn unhealthy(reason: ErrorCode) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            reason: Some(reason),
        }
    }
}

/// Object-safe health check for one required dependency.
pub trait ReadinessProbe: Send + Sync {
    /// Returns the one required component implemented by this probe.
    fn component(&self) -> ReadinessComponent;

    /// Performs a bounded check and returns only content-safe status metadata.
    fn check(&self) -> ProbeObservation;
}

/// Readiness aggregator configuration or report failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessError {
    /// A required probe is missing or duplicated.
    InvalidConfiguration,
    /// The resulting protocol report failed its own invariant checks.
    InvalidReport,
}

impl fmt::Display for ReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "readiness probes are incomplete or duplicated",
            Self::InvalidReport => "readiness report is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReadinessError {}

/// Aggregates exactly one probe for every mandatory readiness dependency.
pub struct ReadinessAggregator {
    probes: Vec<Arc<dyn ReadinessProbe>>,
}

impl ReadinessAggregator {
    /// Creates an aggregator only when all eight required probes appear exactly once.
    pub fn new(probes: Vec<Arc<dyn ReadinessProbe>>) -> Result<Self, ReadinessError> {
        let components: BTreeSet<_> = probes.iter().map(|probe| probe.component()).collect();
        let required: BTreeSet<_> = REQUIRED_COMPONENTS.into_iter().collect();
        if probes.len() != REQUIRED_COMPONENTS.len() || components != required {
            return Err(ReadinessError::InvalidConfiguration);
        }
        Ok(Self { probes })
    }

    /// Runs every required probe and returns a sorted, valid protocol health report.
    pub fn report(&self, observed_at: UtcTimestamp) -> Result<HealthReport, ReadinessError> {
        let mut components: Vec<_> = self
            .probes
            .iter()
            .map(|probe| {
                let observation = probe.check();
                ComponentHealth {
                    name: probe.component().as_str().to_owned(),
                    status: observation.status,
                    reason: observation.reason,
                }
            })
            .collect();
        components.sort_by(|left, right| left.name.cmp(&right.name));
        let status = components
            .iter()
            .map(|component| component.status)
            .max()
            .unwrap_or(HealthStatus::Healthy);
        let report = HealthReport {
            schema_version: SchemaVersion::new("cigar.health-report", 1)
                .map_err(|_error| ReadinessError::InvalidReport)?,
            status,
            components,
            observed_at,
        };
        report
            .validate()
            .map_err(|_error| ReadinessError::InvalidReport)?;
        Ok(report)
    }
}

impl fmt::Debug for ReadinessAggregator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadinessAggregator")
            .field("probe_count", &self.probes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProbeObservation, REQUIRED_COMPONENTS, ReadinessAggregator, ReadinessComponent,
        ReadinessError, ReadinessProbe,
    };
    use cigar_protocol::{ErrorCode, HealthStatus, UtcTimestamp, Validate};
    use std::sync::Arc;

    struct FixedProbe {
        component: ReadinessComponent,
        observation: ProbeObservation,
    }

    impl ReadinessProbe for FixedProbe {
        fn component(&self) -> ReadinessComponent {
            self.component
        }

        fn check(&self) -> ProbeObservation {
            self.observation
        }
    }

    fn probes(broken: Option<ReadinessComponent>) -> Vec<Arc<dyn ReadinessProbe>> {
        REQUIRED_COMPONENTS
            .into_iter()
            .map(|component| {
                let observation = if broken == Some(component) {
                    ProbeObservation::unhealthy(ErrorCode::DependencyDegraded)
                } else {
                    ProbeObservation::healthy()
                };
                Arc::new(FixedProbe {
                    component,
                    observation,
                }) as Arc<dyn ReadinessProbe>
            })
            .collect()
    }

    #[test]
    fn every_broken_dependency_makes_sorted_report_unhealthy()
    -> Result<(), Box<dyn std::error::Error>> {
        for broken in REQUIRED_COMPONENTS {
            let aggregator = ReadinessAggregator::new(probes(Some(broken)))?;
            let report = aggregator.report(UtcTimestamp::from_unix_nanos(10)?)?;
            assert_eq!(report.status, HealthStatus::Unhealthy, "{broken:?}");
            assert!(report.components.windows(2).all(|window| {
                match (window.first(), window.get(1)) {
                    (Some(left), Some(right)) => left.name < right.name,
                    _ => false,
                }
            }));
            assert!(report.validate().is_ok());
            let component = report
                .components
                .iter()
                .find(|component| component.name == broken.as_str())
                .ok_or("broken readiness component missing")?;
            assert_eq!(
                component.reason,
                Some(ErrorCode::DependencyDegraded),
                "{broken:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_or_duplicate_probe_fails_closed() {
        let mut missing = probes(None);
        missing.pop();
        assert!(matches!(
            ReadinessAggregator::new(missing),
            Err(ReadinessError::InvalidConfiguration)
        ));

        let duplicate: Vec<Arc<dyn ReadinessProbe>> = REQUIRED_COMPONENTS
            .into_iter()
            .map(|_component| {
                Arc::new(FixedProbe {
                    component: ReadinessComponent::MetadataStore,
                    observation: ProbeObservation::healthy(),
                }) as Arc<dyn ReadinessProbe>
            })
            .collect();
        assert!(matches!(
            ReadinessAggregator::new(duplicate),
            Err(ReadinessError::InvalidConfiguration)
        ));
    }
}
