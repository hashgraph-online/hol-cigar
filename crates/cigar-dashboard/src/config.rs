//! Strict local-only dashboard configuration.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

const CONFIG_SCHEMA_VERSION: &str = "cigar.dashboard-config.v1";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_ALIAS_BYTES: usize = 64;

/// Stable content-free configuration failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardConfigErrorCode {
    /// TOML was malformed, duplicated, oversized, or contained unknown fields.
    InvalidSyntax,
    /// The configuration schema version is unsupported.
    UnsupportedSchema,
    /// A required path is relative, non-normalized, duplicated, or unsafe.
    InvalidPath,
    /// A listener or target is not an explicit numeric loopback address.
    UnsafeEndpoint,
    /// A numeric resource or timing limit is outside its closed bound.
    InvalidLimit,
    /// Control mode omitted its required isolated roots or registry.
    IncompleteControlConfiguration,
    /// A display-only value is malformed.
    InvalidDisplayValue,
    /// The configuration file could not be read safely.
    Unavailable,
}

/// Content-free dashboard configuration error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DashboardConfigError {
    code: DashboardConfigErrorCode,
}

impl DashboardConfigError {
    const fn new(code: DashboardConfigErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable public error category.
    #[must_use]
    pub const fn code(self) -> DashboardConfigErrorCode {
        self.code
    }
}

impl fmt::Debug for DashboardConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DashboardConfigError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for DashboardConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "dashboard configuration rejected: {:?}",
            self.code
        )
    }
}

impl std::error::Error for DashboardConfigError {}

/// Dashboard HTTP listener and bounded server settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardServerConfig {
    /// Numeric loopback listener address.
    pub listen: SocketAddr,
    /// Owner-protected runtime files and session state root.
    pub runtime_directory: PathBuf,
    /// Verified frontend asset root.
    pub asset_directory: PathBuf,
    /// Maximum complete sidecar request duration.
    pub request_timeout_ms: u64,
    /// Maximum graceful shutdown interval.
    pub shutdown_deadline_ms: u64,
    /// Maximum decoded sidecar request size.
    pub max_request_bytes: usize,
    /// Maximum safe event size.
    pub max_event_bytes: usize,
    /// Maximum concurrent browser SSE subscribers.
    pub max_sse_subscribers: usize,
}

/// Explicit local daemon target and probe settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardTargetConfig {
    /// Root HTTP URL for the loopback CIGAR daemon.
    pub base_url: String,
    /// Owner-protected daemon bearer token file.
    pub bearer_token_file: PathBuf,
    /// Maximum initial connection duration.
    pub connect_timeout_ms: u64,
    /// Maximum complete upstream request duration.
    pub request_timeout_ms: u64,
    /// Liveness/readiness observation interval.
    pub status_interval_ms: u64,
    /// Diagnostics/metrics observation interval.
    pub diagnostics_interval_ms: u64,
    /// Version/capability/configuration observation interval.
    pub identity_interval_ms: u64,
}

/// Reviewed test/soak control configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardControlConfig {
    /// Whether reviewed protocol/test controls are enabled.
    pub enabled: bool,
    /// Source checkout used only by workspace run profiles.
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
    /// Strict reviewed run-profile registry.
    #[serde(default)]
    pub profile_registry: Option<PathBuf>,
    /// External machine-readable evidence root.
    #[serde(default)]
    pub evidence_directory: Option<PathBuf>,
    /// Private isolated child-process sandbox root.
    #[serde(default)]
    pub sandbox_directory: Option<PathBuf>,
    /// Global hard bound on concurrently executing profiles.
    pub max_concurrent_runs: usize,
}

/// Dashboard-owned history retention settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardHistoryConfig {
    /// Separate dashboard SQLite file; never the daemon metadata database.
    pub database_file: PathBuf,
    /// Maximum retained terminal run count.
    pub max_runs: usize,
    /// Maximum safe event count retained for one run.
    pub max_events_per_run: usize,
    /// Maximum terminal-run retention age.
    pub max_age_days: u32,
    /// Maximum retained history and safe-event bytes.
    pub max_bytes: u64,
}

/// Non-sensitive user-facing labels.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardDisplayConfig {
    /// Short alias shown instead of exposing a raw endpoint.
    pub target_alias: String,
}

/// Complete validated dashboard configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    /// Must equal `cigar.dashboard-config.v1`.
    pub schema_version: String,
    /// Dashboard server settings.
    pub server: DashboardServerConfig,
    /// Local daemon target settings.
    pub target: DashboardTargetConfig,
    /// Reviewed control settings.
    pub control: DashboardControlConfig,
    /// Dashboard-only history settings.
    pub history: DashboardHistoryConfig,
    /// Non-sensitive display settings.
    pub display: DashboardDisplayConfig,
}

impl DashboardConfig {
    /// Reads, bounds, parses, and validates one dashboard TOML file.
    pub fn from_file(path: &Path) -> Result<Self, DashboardConfigError> {
        normalized_absolute(path)?;
        let metadata = fs::metadata(path)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::InvalidSyntax,
            ));
        }
        let bytes = fs::read(path)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        let source = std::str::from_utf8(&bytes)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::InvalidSyntax))?;
        Self::from_toml(source)
    }

    /// Parses strict TOML and validates every local-only and bounded-resource invariant.
    pub fn from_toml(source: &str) -> Result<Self, DashboardConfigError> {
        if source.is_empty()
            || source.len() > usize::try_from(MAX_CONFIG_BYTES).unwrap_or(usize::MAX)
        {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::InvalidSyntax,
            ));
        }
        let config: Self = toml::from_str(source)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::InvalidSyntax))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates all configuration invariants without accessing credentials or starting listeners.
    pub fn validate(&self) -> Result<(), DashboardConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::UnsupportedSchema,
            ));
        }
        validate_server(&self.server)?;
        validate_target(&self.target)?;
        validate_control(&self.control)?;
        validate_history(&self.history)?;
        validate_display(&self.display)?;
        validate_path_separation(self)?;
        Ok(())
    }
}

fn validate_server(config: &DashboardServerConfig) -> Result<(), DashboardConfigError> {
    if !config.listen.ip().is_loopback() || config.listen.port() == 0 {
        return Err(DashboardConfigError::new(
            DashboardConfigErrorCode::UnsafeEndpoint,
        ));
    }
    normalized_absolute(&config.runtime_directory)?;
    normalized_absolute(&config.asset_directory)?;
    let valid = (100..=300_000).contains(&config.request_timeout_ms)
        && (100..=300_000).contains(&config.shutdown_deadline_ms)
        && (1_024..=16_777_216).contains(&config.max_request_bytes)
        && (256..=1_048_576).contains(&config.max_event_bytes)
        && (1..=128).contains(&config.max_sse_subscribers);
    if valid {
        Ok(())
    } else {
        Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidLimit,
        ))
    }
}

fn validate_target(config: &DashboardTargetConfig) -> Result<(), DashboardConfigError> {
    normalized_absolute(&config.bearer_token_file)?;
    let url = reqwest::Url::parse(&config.base_url)
        .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::UnsafeEndpoint))?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    let safe = url.scheme() == "http"
        && loopback
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.port_or_known_default().is_some();
    if !safe {
        return Err(DashboardConfigError::new(
            DashboardConfigErrorCode::UnsafeEndpoint,
        ));
    }
    let valid = (100..=30_000).contains(&config.connect_timeout_ms)
        && (100..=300_000).contains(&config.request_timeout_ms)
        && (1_000..=60_000).contains(&config.status_interval_ms)
        && (1_000..=300_000).contains(&config.diagnostics_interval_ms)
        && (10_000..=3_600_000).contains(&config.identity_interval_ms);
    if valid {
        Ok(())
    } else {
        Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidLimit,
        ))
    }
}

fn validate_control(config: &DashboardControlConfig) -> Result<(), DashboardConfigError> {
    if !(1..=8).contains(&config.max_concurrent_runs) {
        return Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidLimit,
        ));
    }
    for path in [
        config.workspace_root.as_deref(),
        config.profile_registry.as_deref(),
        config.evidence_directory.as_deref(),
        config.sandbox_directory.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        normalized_absolute(path)?;
    }
    if config.enabled
        && (config.workspace_root.is_none()
            || config.profile_registry.is_none()
            || config.evidence_directory.is_none()
            || config.sandbox_directory.is_none())
    {
        return Err(DashboardConfigError::new(
            DashboardConfigErrorCode::IncompleteControlConfiguration,
        ));
    }
    if let (Some(workspace), Some(evidence), Some(sandbox)) = (
        config.workspace_root.as_deref(),
        config.evidence_directory.as_deref(),
        config.sandbox_directory.as_deref(),
    ) && (evidence.starts_with(workspace) || sandbox.starts_with(workspace))
    {
        return Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidPath,
        ));
    }
    Ok(())
}

fn validate_history(config: &DashboardHistoryConfig) -> Result<(), DashboardConfigError> {
    normalized_absolute(&config.database_file)?;
    let valid = (1..=100_000).contains(&config.max_runs)
        && (1..=100_000).contains(&config.max_events_per_run)
        && (1..=3_650).contains(&config.max_age_days)
        && (1_048_576..=107_374_182_400).contains(&config.max_bytes);
    if valid {
        Ok(())
    } else {
        Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidLimit,
        ))
    }
}

fn validate_display(config: &DashboardDisplayConfig) -> Result<(), DashboardConfigError> {
    let value = config.target_alias.as_bytes();
    if value.is_empty()
        || value.len() > MAX_ALIAS_BYTES
        || !value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' '))
    {
        Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidDisplayValue,
        ))
    } else {
        Ok(())
    }
}

fn validate_path_separation(config: &DashboardConfig) -> Result<(), DashboardConfigError> {
    let mut paths = BTreeSet::new();
    for path in [
        Some(config.server.runtime_directory.as_path()),
        Some(config.server.asset_directory.as_path()),
        Some(config.target.bearer_token_file.as_path()),
        Some(config.history.database_file.as_path()),
        config.control.workspace_root.as_deref(),
        config.control.profile_registry.as_deref(),
        config.control.evidence_directory.as_deref(),
        config.control.sandbox_directory.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !paths.insert(path) {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::InvalidPath,
            ));
        }
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> Result<(), DashboardConfigError> {
    if !path.is_absolute()
        || path.as_os_str().len() > MAX_PATH_BYTES
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        Err(DashboardConfigError::new(
            DashboardConfigErrorCode::InvalidPath,
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DashboardConfig, DashboardConfigErrorCode};

    const VALID: &str = include_str!("../../../tests/dashboard/fixtures/dashboard-valid.toml");
    const NON_LOOPBACK: &str =
        include_str!("../../../tests/dashboard/fixtures/dashboard-invalid-nonloopback.toml");

    #[test]
    fn valid_local_configuration_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let config = DashboardConfig::from_toml(VALID)?;
        assert!(config.server.listen.ip().is_loopback());
        assert!(!config.control.enabled);
        Ok(())
    }

    #[test]
    fn listener_and_target_must_be_numeric_loopback() {
        let error = DashboardConfig::from_toml(NON_LOOPBACK);
        assert_eq!(
            error.map_err(|failure| failure.code()),
            Err(DashboardConfigErrorCode::UnsafeEndpoint)
        );
    }

    #[test]
    fn unknown_fields_fail_strict_parsing() {
        let source = VALID.replace(
            "target_alias = \"Local CIGAR\"",
            "target_alias = \"Local CIGAR\"\nunknown = true",
        );
        let error = DashboardConfig::from_toml(&source);
        assert_eq!(
            error.map_err(|failure| failure.code()),
            Err(DashboardConfigErrorCode::InvalidSyntax)
        );
    }

    #[test]
    fn enabled_control_requires_every_isolated_root() {
        let source = VALID.replace("enabled = false", "enabled = true");
        let error = DashboardConfig::from_toml(&source);
        assert_eq!(
            error.map_err(|failure| failure.code()),
            Err(DashboardConfigErrorCode::IncompleteControlConfiguration)
        );
    }
}
