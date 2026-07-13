//! Stable service errors, opaque pagination, health, and compatibility reports.

use crate::limits::{
    MAX_COMPATIBILITY_REASONS, MAX_HEALTH_COMPONENT_NAME_BYTES, MAX_HEALTH_COMPONENTS,
    MAX_PAGE_CURSOR_BYTES, MAX_PROBLEM_TEXT_BYTES, MAX_PROTOCOL_SELECTOR_BYTES,
    MAX_SCHEMA_COMPATIBILITY_ENTRIES, MAX_SCHEMA_FAMILY_BYTES,
};
use crate::primitive::base64url;
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{ExtensionMap, RecordId, SchemaVersion, UtcTimestamp, Validate};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Stable closed public error codes. Numeric and transport mappings are frozen in `spec/errors`.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u32)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Caller input is structurally invalid.
    InvalidArgument = 1000,
    /// A named resource limit was exceeded.
    LimitExceeded = 1001,
    /// Schema major or form is unsupported.
    UnsupportedSchema = 1002,
    /// Authenticated principal is unknown.
    UnknownPrincipal = 1100,
    /// Capability is malformed or insufficient.
    InvalidCapability = 1101,
    /// Capability is expired.
    CapabilityExpired = 1102,
    /// Source connector is unavailable.
    SourceUnavailable = 1200,
    /// Source snapshot is incomplete.
    SnapshotIncomplete = 1201,
    /// Integrity verification failed.
    IntegrityFailure = 1202,
    /// Index watermark is stale.
    IndexStale = 1300,
    /// Required index is unavailable.
    IndexUnavailable = 1301,
    /// Requested consistency could not be satisfied.
    ConsistencyUnsatisfied = 1302,
    /// Policy denied the operation.
    PolicyDenied = 1400,
    /// Processor constraints denied the operation.
    ProcessorDenied = 1401,
    /// Instruction authority was insufficient.
    InstructionAuthorityDenied = 1402,
    /// Required budget cannot be satisfied.
    BudgetUnsatisfiable = 1500,
    /// Required authorized context is missing.
    MissingRequiredContext = 1501,
    /// Critical semantic conflict remains unresolved.
    UnresolvedCriticalConflict = 1502,
    /// Delta base does not match provider-present state.
    DeltaBaseMismatch = 1600,
    /// Bundle was invalidated.
    BundleInvalidated = 1601,
    /// Optimistic revision does not match.
    RevisionConflict = 1700,
    /// Handoff expired.
    HandoffExpired = 1701,
    /// Handoff recipient does not match.
    HandoffRecipientMismatch = 1702,
    /// Effect requires approval.
    ApprovalRequired = 1800,
    /// Approval no longer binds current semantics or time.
    ApprovalStale = 1801,
    /// External effect outcome is unknown.
    EffectUnknown = 1802,
    /// Effect cannot be safely retried.
    UnsafeRetry = 1803,
    /// Replay lacks required dependencies.
    ReplayIncomplete = 1900,
    /// Named dependency is unavailable.
    DependencyUnavailable = 1901,
    /// Live operation requires explicit new authorization.
    LiveAuthorizationRequired = 1902,
    /// Request rate limit was reached.
    RateLimited = 2000,
    /// Request deadline elapsed.
    DeadlineExceeded = 2001,
    /// Dependency is degraded.
    DependencyDegraded = 2002,
    /// Internal error hidden behind a correlation ID.
    Internal = 2099,
}

impl ErrorCode {
    /// Stable numeric v1 code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        self as u32
    }

    /// Returns all stable public metadata for this code.
    #[must_use]
    pub const fn definition(self) -> &'static ErrorDefinition {
        error_definition(self)
    }

    /// Default HTTP status for this safe public error.
    #[must_use]
    pub const fn default_http_status(self) -> u16 {
        self.definition().http_status
    }

    /// Default retry guidance from the stable public error catalog.
    #[must_use]
    pub const fn default_retry_class(self) -> RetryClass {
        self.definition().retry
    }

    /// Canonical gRPC status spelling from the stable public error catalog.
    #[must_use]
    pub const fn grpc_status(self) -> &'static str {
        self.definition().grpc_status
    }
}

/// Stable retry guidance independent of transport.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// Repeating the same request is not expected to help.
    Never,
    /// Same semantic request is safe to repeat immediately.
    Safe,
    /// Retry only after bounded backoff.
    AfterBackoff,
    /// Retry only after current policy/capability authorization.
    AfterReauthorization,
    /// Retry only after reconciliation proves safety.
    AfterReconciliation,
}

/// Generated stable transport and remediation metadata for one public error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorDefinition {
    /// Stable symbolic and numeric error code.
    pub code: ErrorCode,
    /// Frozen symbolic spelling.
    pub symbol: &'static str,
    /// Default HTTP status.
    pub http_status: u16,
    /// Canonical gRPC status spelling.
    pub grpc_status: &'static str,
    /// Safe retry guidance.
    pub retry: RetryClass,
    /// Safe value-free message template.
    pub message: &'static str,
    /// Safe remediation template.
    pub remediation: &'static str,
    /// Whether safe details may disclose a record identity.
    pub disclose_identity: bool,
}

include!("generated/error_registry.rs");

/// Opaque bounded page cursor encoded as unpadded base64url in JSON.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PageCursor(Vec<u8>);

impl JsonSchema for PageCursor {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "PageCursor".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 2,
            "maxLength": 1366,
            "contentEncoding": "base64url",
            "description": "Unpadded base64url encoding of 1..=1024 opaque cursor bytes."
        })
    }
}

impl PageCursor {
    /// Creates a non-empty bounded opaque cursor.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ValidationErrors> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_PAGE_CURSOR_BYTES {
            let mut errors = ValidationErrors::new();
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/page_cursor",
                "page cursor must be non-empty and bounded",
            ));
            Err(errors)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns opaque cursor bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl Serialize for PageCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64url::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PageCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = base64url::deserialize(deserializer)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

/// Safe bounded RFC 9457-style problem record.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    /// Must be `cigar.problem.v1`.
    pub schema_version: SchemaVersion,
    /// Stable symbolic and numeric error code.
    pub code: ErrorCode,
    /// HTTP status mapped from the error catalog.
    pub http_status: u16,
    /// Stable retry guidance.
    pub retry: RetryClass,
    /// Safe bounded message with no protected identifiers.
    #[schemars(length(min = 1, max = MAX_PROBLEM_TEXT_BYTES))]
    pub message: String,
    /// Safe bounded remediation guidance.
    #[schemars(length(min = 1, max = MAX_PROBLEM_TEXT_BYTES))]
    pub remediation: String,
    /// Correlation identity for privileged internal logs.
    pub correlation_id: RecordId,
    /// Typed bounded safe details permitted by this error schema.
    pub details: ExtensionMap,
}

impl fmt::Debug for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Problem")
            .field("schema_version", &self.schema_version)
            .field("code", &self.code)
            .field("numeric_code", &self.code.numeric())
            .field("http_status", &self.http_status)
            .field("retry", &self.retry)
            .field("message_bytes", &self.message.len())
            .field("remediation_bytes", &self.remediation.len())
            .field("correlation_id", &self.correlation_id)
            .field("details", &self.details)
            .finish()
    }
}

impl Validate for Problem {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.problem", &mut errors);
        if self.http_status != self.code.default_http_status() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/http_status",
                "problem HTTP status disagrees with the stable error catalog",
            ));
        }
        if self.retry != self.code.default_retry_class() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/retry",
                "problem retry guidance disagrees with the stable error catalog",
            ));
        }
        for (path, value) in [
            ("/message", &self.message),
            ("/remediation", &self.remediation),
        ] {
            if value.is_empty() || value.len() > MAX_PROBLEM_TEXT_BYTES {
                errors.push(issue(
                    ValidationCode::LimitExceeded,
                    path,
                    "safe problem text must be non-empty and bounded",
                ));
            }
        }
        validate_extensions(&self.details, &mut errors);
        errors.into_result()
    }
}

/// Closed operational health status.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Component is operating normally.
    Healthy,
    /// Component is available with reduced guarantees or capacity.
    Degraded,
    /// Component is not available for required operations.
    Unhealthy,
}

/// Content-safe component health observation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentHealth {
    /// Stable component name.
    #[schemars(length(min = 1, max = MAX_HEALTH_COMPONENT_NAME_BYTES))]
    pub name: String,
    /// Current component status.
    pub status: HealthStatus,
    /// Stable reason code when not healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ErrorCode>,
}

/// Aggregate service health report.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReport {
    /// Must be `cigar.health-report.v1`.
    pub schema_version: SchemaVersion,
    /// Aggregate status equal to the worst component status.
    pub status: HealthStatus,
    /// Sorted unique component observations.
    #[schemars(length(max = MAX_HEALTH_COMPONENTS))]
    pub components: Vec<ComponentHealth>,
    /// Observation time.
    pub observed_at: UtcTimestamp,
}

impl Validate for HealthReport {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.health-report", &mut errors);
        if self.components.len() > MAX_HEALTH_COMPONENTS
            || !self
                .components
                .windows(2)
                .all(|window| match (window.first(), window.get(1)) {
                    (Some(first), Some(second)) => first.name < second.name,
                    _ => false,
                })
            || self.components.iter().any(|component| {
                component.name.is_empty() || component.name.len() > MAX_HEALTH_COMPONENT_NAME_BYTES
            })
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/components",
                "health components must be bounded, sorted, and uniquely named",
            ));
        }
        let expected = self
            .components
            .iter()
            .map(|component| component.status)
            .max()
            .unwrap_or(HealthStatus::Healthy);
        if expected != self.status {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/status",
                "aggregate health status disagrees with component status",
            ));
        }
        errors.into_result()
    }
}

/// Protocol and schema compatibility report.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityReport {
    /// Must be `cigar.compatibility-report.v1`.
    pub schema_version: SchemaVersion,
    /// Minimum accepted protocol version.
    #[schemars(length(min = 1, max = MAX_PROTOCOL_SELECTOR_BYTES))]
    pub protocol_min: String,
    /// Maximum accepted protocol line.
    #[schemars(length(min = 1, max = MAX_PROTOCOL_SELECTOR_BYTES))]
    pub protocol_max: String,
    /// Configured writer protocol version.
    #[schemars(length(min = 1, max = MAX_PROTOCOL_SELECTOR_BYTES))]
    pub writer_protocol: String,
    /// Maximum supported schema major by family.
    #[schemars(extend("maxProperties" = MAX_SCHEMA_COMPATIBILITY_ENTRIES))]
    pub schema_majors: BTreeMap<String, u16>,
    /// Whether the compared peer/artifact is compatible.
    pub compatible: bool,
    /// Sorted unique incompatibility reason codes.
    #[schemars(length(max = MAX_COMPATIBILITY_REASONS))]
    pub reasons: Vec<ErrorCode>,
}

impl Validate for CompatibilityReport {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.compatibility-report",
            &mut errors,
        );
        for (path, value) in [
            ("/protocol_min", &self.protocol_min),
            ("/protocol_max", &self.protocol_max),
            ("/writer_protocol", &self.writer_protocol),
        ] {
            if value.is_empty() || value.len() > MAX_PROTOCOL_SELECTOR_BYTES {
                errors.push(issue(
                    ValidationCode::LimitExceeded,
                    path,
                    "protocol version selector must be non-empty and bounded",
                ));
            }
        }
        if self.schema_majors.len() > MAX_SCHEMA_COMPATIBILITY_ENTRIES
            || self.schema_majors.iter().any(|(family, major)| {
                family.is_empty() || family.len() > MAX_SCHEMA_FAMILY_BYTES || *major == 0
            })
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/schema_majors",
                "schema family compatibility map is invalid or too large",
            ));
        }
        if self.reasons.len() > MAX_COMPATIBILITY_REASONS
            || !strictly_sorted_unique(&self.reasons)
            || self.compatible != self.reasons.is_empty()
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/reasons",
                "compatibility reasons must be bounded, sorted, and consistent",
            ));
        }
        errors.into_result()
    }
}

fn validate_version(version: &SchemaVersion, family: &str, errors: &mut ValidationErrors) {
    if let Err(found) = version.require_v1(family) {
        errors.merge(found);
    }
}

fn validate_extensions(extensions: &ExtensionMap, errors: &mut ValidationErrors) {
    if let Err(found) = extensions.validate_known(&BTreeSet::new()) {
        errors.merge(found);
    }
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|window| match (window.first(), window.get(1)) {
            (Some(first), Some(second)) => first < second,
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::{
        ComponentHealth, ERROR_REGISTRY, ErrorCode, HealthReport, HealthStatus, PageCursor,
        Problem, RetryClass,
    };
    use crate::{ExtensionMap, RecordId, UtcTimestamp, Validate};

    #[test]
    fn page_cursor_is_bounded_base64url_and_secret_safe() -> Result<(), Box<dyn std::error::Error>>
    {
        let cursor = PageCursor::new(vec![0xfb, 0xff, 0x61])?;
        let json = serde_json::to_string(&cursor)?;
        assert_eq!(json, "\"-_9h\"");
        assert!(!format!("{cursor:?}").contains("-_9h"));
        Ok(())
    }

    #[test]
    fn problem_status_must_match_stable_catalog() -> Result<(), Box<dyn std::error::Error>> {
        let problem = Problem {
            schema_version: "cigar.problem.v1".parse()?,
            code: ErrorCode::PolicyDenied,
            http_status: 500,
            retry: RetryClass::AfterReauthorization,
            message: "request denied".to_owned(),
            remediation: "request authorized scope".to_owned(),
            correlation_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            details: ExtensionMap::default(),
        };
        assert!(problem.validate().is_err());
        Ok(())
    }

    #[test]
    fn problem_retry_must_match_stable_catalog() -> Result<(), Box<dyn std::error::Error>> {
        let problem = Problem {
            schema_version: "cigar.problem.v1".parse()?,
            code: ErrorCode::PolicyDenied,
            http_status: ErrorCode::PolicyDenied.default_http_status(),
            retry: RetryClass::Never,
            message: "request denied".to_owned(),
            remediation: "request authorized scope".to_owned(),
            correlation_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            details: ExtensionMap::default(),
        };
        assert!(problem.validate().is_err());
        Ok(())
    }

    #[test]
    fn generated_error_registry_is_complete_and_self_consistent() {
        assert_eq!(ERROR_REGISTRY.len(), 34);
        let mut numeric_codes = std::collections::BTreeSet::new();
        let mut symbols = std::collections::BTreeSet::new();
        for definition in ERROR_REGISTRY {
            assert!(numeric_codes.insert(definition.code.numeric()));
            assert!(symbols.insert(definition.symbol));
            assert_eq!(definition.code.definition(), definition);
            assert_eq!(
                definition.code.default_http_status(),
                definition.http_status
            );
            assert_eq!(definition.code.default_retry_class(), definition.retry);
            assert_eq!(definition.code.grpc_status(), definition.grpc_status);
        }
    }

    #[test]
    fn aggregate_health_must_equal_worst_component() -> Result<(), Box<dyn std::error::Error>> {
        let report = HealthReport {
            schema_version: "cigar.health-report.v1".parse()?,
            status: HealthStatus::Healthy,
            components: vec![ComponentHealth {
                name: "storage".to_owned(),
                status: HealthStatus::Degraded,
                reason: Some(ErrorCode::DependencyDegraded),
            }],
            observed_at: UtcTimestamp::parse_rfc3339("2026-07-10T00:00:00Z")?,
        };
        assert!(report.validate().is_err());
        Ok(())
    }
}
