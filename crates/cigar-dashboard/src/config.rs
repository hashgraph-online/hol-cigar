//! Strict local-only dashboard configuration.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read as _;
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
        let before = fs::symlink_metadata(path)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.len() == 0
            || before.len() > MAX_CONFIG_BYTES
            || !safe_owned_regular(&before)
        {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::InvalidSyntax,
            ));
        }
        let mut file = File::open(path)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        let opened = file
            .metadata()
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        if !safe_owned_regular(&opened) || !same_file(&before, &opened) {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::InvalidPath,
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).map_err(|_error| {
            DashboardConfigError::new(DashboardConfigErrorCode::InvalidSyntax)
        })?);
        file.by_ref()
            .take(MAX_CONFIG_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        let opened_after = file
            .metadata()
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        let after = fs::symlink_metadata(path)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::Unavailable))?;
        if bytes.is_empty()
            || bytes.len() > usize::try_from(MAX_CONFIG_BYTES).unwrap_or(usize::MAX)
            || !same_file(&opened, &after)
            || !same_file(&opened, &opened_after)
        {
            return Err(DashboardConfigError::new(
                DashboardConfigErrorCode::InvalidPath,
            ));
        }
        let source = std::str::from_utf8(&bytes)
            .map_err(|_error| DashboardConfigError::new(DashboardConfigErrorCode::InvalidSyntax))?;
        let config = Self::from_toml(source)?;
        config.validate_filesystem()?;
        Ok(config)
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

    /// Verifies the configured local filesystem objects and their canonical separation.
    ///
    /// This read-only preflight is intentionally part of `from_file`, so `--check-config` cannot
    /// report success for a configuration that would later fail closed after binding a listener.
    fn validate_filesystem(&self) -> Result<(), DashboardConfigError> {
        let runtime =
            canonical_directory(&self.server.runtime_directory, DirectoryPolicy::Private)?;
        let assets = canonical_directory(&self.server.asset_directory, DirectoryPolicy::Ordinary)?;
        let token = canonical_regular_file(
            &self.target.bearer_token_file,
            RegularFilePolicy::OwnerPrivate,
        )?;
        let token_parent = self
            .target
            .bearer_token_file
            .parent()
            .ok_or_else(invalid_path)?;
        let _token_parent = canonical_directory(token_parent, DirectoryPolicy::NotPeerWritable)?;

        let history_parent = self
            .history
            .database_file
            .parent()
            .ok_or_else(invalid_path)?;
        let history_parent = canonical_directory(history_parent, DirectoryPolicy::Private)?;
        let history =
            canonical_optional_private_file(&self.history.database_file, &history_parent)?;

        let workspace = self
            .control
            .workspace_root
            .as_deref()
            .map(|path| canonical_directory(path, DirectoryPolicy::Ordinary))
            .transpose()?;
        let registry = self
            .control
            .profile_registry
            .as_deref()
            .map(|path| canonical_regular_file(path, RegularFilePolicy::ImmutableInput))
            .transpose()?;
        let evidence = self
            .control
            .evidence_directory
            .as_deref()
            .map(canonical_private_directory_or_missing)
            .transpose()?;
        let sandbox = self
            .control
            .sandbox_directory
            .as_deref()
            .map(canonical_private_directory_or_missing)
            .transpose()?;

        let directories = [
            Some(runtime.as_path()),
            Some(assets.as_path()),
            workspace.as_deref(),
            evidence.as_deref(),
            sandbox.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let mut unique_directories = BTreeSet::new();
        if directories
            .iter()
            .any(|path| !unique_directories.insert((*path).to_path_buf()))
        {
            return Err(invalid_path());
        }

        let mut unique_files = BTreeSet::new();
        for path in [
            Some(token.as_path()),
            Some(history.as_path()),
            registry.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !unique_files.insert(path.to_path_buf()) {
                return Err(invalid_path());
            }
        }

        if paths_overlap(&runtime, &assets)
            || history.starts_with(&runtime)
            || token.starts_with(&runtime)
            || evidence.as_ref().is_some_and(|root| {
                paths_overlap(root, &runtime)
                    || history.starts_with(root)
                    || token.starts_with(root)
            })
            || sandbox.as_ref().is_some_and(|root| {
                paths_overlap(root, &runtime)
                    || history.starts_with(root)
                    || token.starts_with(root)
            })
            || evidence
                .as_ref()
                .zip(sandbox.as_ref())
                .is_some_and(|(left, right)| paths_overlap(left, right))
            || workspace.as_ref().is_some_and(|source| {
                evidence
                    .as_ref()
                    .is_some_and(|root| paths_overlap(source, root))
                    || sandbox
                        .as_ref()
                        .is_some_and(|root| paths_overlap(source, root))
            })
        {
            return Err(invalid_path());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum DirectoryPolicy {
    Ordinary,
    NotPeerWritable,
    Private,
}

#[derive(Clone, Copy)]
enum RegularFilePolicy {
    ImmutableInput,
    OwnerPrivate,
}

fn invalid_path() -> DashboardConfigError {
    DashboardConfigError::new(DashboardConfigErrorCode::InvalidPath)
}

fn canonical_directory(
    path: &Path,
    policy: DirectoryPolicy,
) -> Result<PathBuf, DashboardConfigError> {
    let before = fs::symlink_metadata(path).map_err(|_error| invalid_path())?;
    if !directory_metadata_accepted(&before, policy) {
        return Err(invalid_path());
    }
    let canonical = path.canonicalize().map_err(|_error| invalid_path())?;
    let after = fs::symlink_metadata(path).map_err(|_error| invalid_path())?;
    let resolved = fs::symlink_metadata(&canonical).map_err(|_error| invalid_path())?;
    if !directory_metadata_accepted(&after, policy)
        || !directory_metadata_accepted(&resolved, policy)
        || !same_identity(&before, &after)
        || !same_identity(&before, &resolved)
    {
        return Err(invalid_path());
    }
    Ok(canonical)
}

fn canonical_regular_file(
    path: &Path,
    policy: RegularFilePolicy,
) -> Result<PathBuf, DashboardConfigError> {
    let before = fs::symlink_metadata(path).map_err(|_error| invalid_path())?;
    if !regular_metadata_accepted(&before, policy) {
        return Err(invalid_path());
    }
    let canonical = path.canonicalize().map_err(|_error| invalid_path())?;
    let after = fs::symlink_metadata(path).map_err(|_error| invalid_path())?;
    let resolved = fs::symlink_metadata(&canonical).map_err(|_error| invalid_path())?;
    if !regular_metadata_accepted(&after, policy)
        || !regular_metadata_accepted(&resolved, policy)
        || !same_identity(&before, &after)
        || !same_identity(&before, &resolved)
    {
        return Err(invalid_path());
    }
    Ok(canonical)
}

#[cfg(unix)]
fn directory_metadata_accepted(metadata: &fs::Metadata, policy: DirectoryPolicy) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let mode = metadata.mode() & 0o777;
    let owner = metadata.uid() == rustix::process::geteuid().as_raw();
    match policy {
        DirectoryPolicy::Ordinary => true,
        DirectoryPolicy::NotPeerWritable => mode & 0o022 == 0,
        DirectoryPolicy::Private => owner && mode == 0o700,
    }
}

#[cfg(not(unix))]
fn directory_metadata_accepted(_metadata: &fs::Metadata, _policy: DirectoryPolicy) -> bool {
    false
}

#[cfg(unix)]
fn regular_metadata_accepted(metadata: &fs::Metadata, policy: RegularFilePolicy) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.nlink() != 1
    {
        return false;
    }
    let owner = metadata.uid() == rustix::process::geteuid().as_raw();
    let mode = metadata.mode() & 0o777;
    match policy {
        RegularFilePolicy::ImmutableInput => mode & 0o022 == 0,
        RegularFilePolicy::OwnerPrivate => owner && mode & 0o077 == 0,
    }
}

#[cfg(not(unix))]
fn regular_metadata_accepted(_metadata: &fs::Metadata, _policy: RegularFilePolicy) -> bool {
    false
}

fn canonical_optional_private_file(
    path: &Path,
    canonical_parent: &Path,
) -> Result<PathBuf, DashboardConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !private_file_metadata_accepted(&metadata) {
                return Err(invalid_path());
            }
            let canonical = path.canonicalize().map_err(|_error| invalid_path())?;
            let after = fs::symlink_metadata(path).map_err(|_error| invalid_path())?;
            let resolved = fs::symlink_metadata(&canonical).map_err(|_error| invalid_path())?;
            if !private_file_metadata_accepted(&after)
                || !private_file_metadata_accepted(&resolved)
                || !same_identity(&metadata, &after)
                || !same_identity(&metadata, &resolved)
            {
                return Err(invalid_path());
            }
            Ok(canonical)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or_else(invalid_path)?;
            Ok(canonical_parent.join(name))
        }
        Err(_error) => Err(invalid_path()),
    }
}

#[cfg(unix)]
fn private_file_metadata_accepted(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.nlink() == 1
        && metadata.mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_file_metadata_accepted(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

fn canonical_private_directory_or_missing(path: &Path) -> Result<PathBuf, DashboardConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_metadata) => canonical_directory(path, DirectoryPolicy::Private),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(invalid_path)?;
            let parent = canonical_directory(parent, DirectoryPolicy::Private)?;
            let name = path.file_name().ok_or_else(invalid_path)?;
            Ok(parent.join(name))
        }
        Err(_error) => Err(invalid_path()),
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(unix)]
fn safe_owned_regular(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn safe_owned_regular(_metadata: &fs::Metadata) -> bool {
    false
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
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
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
    use std::fs;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};

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

        let duplicate = VALID.replace(
            "request_timeout_ms = 30000",
            "request_timeout_ms = 30000\nrequest_timeout_ms = 30001",
        );
        assert_eq!(
            DashboardConfig::from_toml(&duplicate).map_err(|failure| failure.code()),
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

    #[cfg(unix)]
    #[test]
    fn config_file_rejects_symlinks_hardlinks_and_writable_peers()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let source = directory.path().join("dashboard.toml");
        fs::write(&source, VALID)?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
        let linked = directory.path().join("linked.toml");
        fs::hard_link(&source, &linked)?;
        assert!(DashboardConfig::from_file(&source).is_err());
        fs::remove_file(&linked)?;

        let alias = directory.path().join("alias.toml");
        symlink(&source, &alias)?;
        assert!(DashboardConfig::from_file(&alias).is_err());

        fs::set_permissions(&source, fs::Permissions::from_mode(0o620))?;
        assert!(DashboardConfig::from_file(&source).is_err());
        Ok(())
    }

    #[test]
    fn endpoint_profile_rejects_dns_mapped_ipv6_credentials_and_url_suffixes() {
        for endpoint in [
            "http://localhost:7443/",
            "http://0.0.0.0:7443/",
            "http://[::ffff:127.0.0.1]:7443/",
            "https://127.0.0.1:7443/",
            "http://operator@127.0.0.1:7443/",
            "http://operator:secret@127.0.0.1:7443/",
            "http://127.0.0.1:7443/api",
            "http://127.0.0.1:7443/?debug=true",
            "http://127.0.0.1:7443/#secret",
        ] {
            let source = VALID.replace("http://127.0.0.1:7443/", endpoint);
            assert_eq!(
                DashboardConfig::from_toml(&source).map_err(|failure| failure.code()),
                Err(DashboardConfigErrorCode::UnsafeEndpoint),
                "endpoint unexpectedly accepted: {endpoint}"
            );
        }
    }

    #[test]
    fn relative_traversal_zero_excessive_and_overflow_values_fail_closed() {
        let relative = VALID.replace(
            "/tmp/cigar-dashboard/runtime",
            "relative/../dashboard/runtime",
        );
        assert_eq!(
            DashboardConfig::from_toml(&relative).map_err(|failure| failure.code()),
            Err(DashboardConfigErrorCode::InvalidPath)
        );

        for (accepted, rejected) in [
            ("max_sse_subscribers = 16", "max_sse_subscribers = 0"),
            ("max_concurrent_runs = 1", "max_concurrent_runs = 9"),
            ("max_age_days = 30", "max_age_days = 3651"),
            ("connect_timeout_ms = 2000", "connect_timeout_ms = 99"),
        ] {
            let source = VALID.replace(accepted, rejected);
            assert_eq!(
                DashboardConfig::from_toml(&source).map_err(|failure| failure.code()),
                Err(DashboardConfigErrorCode::InvalidLimit),
                "limit unexpectedly accepted: {rejected}"
            );
        }

        let overflow = VALID.replace("max_bytes = 1073741824", "max_bytes = 18446744073709551616");
        assert_eq!(
            DashboardConfig::from_toml(&overflow).map_err(|failure| failure.code()),
            Err(DashboardConfigErrorCode::InvalidSyntax)
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_configuration_preflight_accepts_a_separated_private_topology()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = FilesystemFixture::new(true)?;
        let config = DashboardConfig::from_file(&fixture.config_file)?;
        assert!(config.control.enabled);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_preflight_rejects_unsafe_token_and_state_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = FilesystemFixture::new(false)?;
        fs::set_permissions(&fixture.token_file, fs::Permissions::from_mode(0o640))?;
        assert_invalid_path(&fixture.config_file);

        let fixture = FilesystemFixture::new(false)?;
        fs::set_permissions(
            &fixture.history_directory,
            fs::Permissions::from_mode(0o770),
        )?;
        assert_invalid_path(&fixture.config_file);

        let fixture = FilesystemFixture::new(false)?;
        let second_link = fixture.root.path().join("token-hard-link");
        fs::hard_link(&fixture.token_file, second_link)?;
        assert_invalid_path(&fixture.config_file);

        let fixture = FilesystemFixture::new(false)?;
        let original_runtime = fixture.root.path().join("runtime-original");
        fs::rename(&fixture.runtime_directory, &original_runtime)?;
        std::os::unix::fs::symlink(&original_runtime, &fixture.runtime_directory)?;
        assert_invalid_path(&fixture.config_file);

        let fixture = FilesystemFixture::new(false)?;
        let nested_token = fixture.runtime_directory.join("daemon.token");
        fs::write(&nested_token, b"overlapping-token\n")?;
        fs::set_permissions(&nested_token, fs::Permissions::from_mode(0o600))?;
        fixture.replace_path(&fixture.token_file, &nested_token)?;
        assert_invalid_path(&fixture.config_file);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn canonical_aliases_and_evidence_inside_source_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let fixture = FilesystemFixture::new(false)?;
        let alias_parent = fixture.root.path().join("alias-parent");
        symlink(fixture.root.path(), &alias_parent)?;
        let aliased_assets = alias_parent.join("runtime");
        fixture.replace_path(&fixture.asset_directory, &aliased_assets)?;
        assert_invalid_path(&fixture.config_file);

        let fixture = FilesystemFixture::new(true)?;
        let workspace = fixture
            .workspace_directory
            .as_ref()
            .ok_or("missing workspace")?;
        let nested_evidence = workspace.join("evidence");
        fs::create_dir(&nested_evidence)?;
        fs::set_permissions(&nested_evidence, fs::Permissions::from_mode(0o700))?;
        let alias = fixture.root.path().join("source-alias");
        symlink(workspace, &alias)?;
        let hidden_nested_evidence = alias.join("evidence");
        fixture.replace_path(
            fixture
                .evidence_directory
                .as_ref()
                .ok_or("missing evidence")?,
            &hidden_nested_evidence,
        )?;
        assert_invalid_path(&fixture.config_file);
        Ok(())
    }

    #[cfg(unix)]
    fn assert_invalid_path(path: &Path) {
        assert_eq!(
            DashboardConfig::from_file(path).map_err(|failure| failure.code()),
            Err(DashboardConfigErrorCode::InvalidPath)
        );
    }

    #[cfg(unix)]
    struct FilesystemFixture {
        root: tempfile::TempDir,
        config_file: PathBuf,
        runtime_directory: PathBuf,
        asset_directory: PathBuf,
        token_file: PathBuf,
        history_directory: PathBuf,
        workspace_directory: Option<PathBuf>,
        evidence_directory: Option<PathBuf>,
    }

    #[cfg(unix)]
    impl FilesystemFixture {
        fn new(control_enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
            use std::os::unix::fs::PermissionsExt as _;

            let root = tempfile::tempdir()?;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
            let runtime_directory = root.path().join("runtime");
            let asset_directory = root.path().join("assets");
            let credential_directory = root.path().join("credentials");
            let history_directory = root.path().join("history");
            for directory in [
                &runtime_directory,
                &asset_directory,
                &credential_directory,
                &history_directory,
            ] {
                fs::create_dir(directory)?;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
            let token_file = credential_directory.join("cigard.token");
            fs::write(&token_file, b"local-dashboard-test-token\n")?;
            fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))?;
            let history_file = history_directory.join("history.sqlite3");

            let mut source = VALID
                .replace(
                    "/tmp/cigar-dashboard/runtime",
                    &path_text(&runtime_directory)?,
                )
                .replace("/tmp/cigar-dashboard/assets", &path_text(&asset_directory)?)
                .replace(
                    "/tmp/cigar-dashboard/cigard.token",
                    &path_text(&token_file)?,
                )
                .replace(
                    "/tmp/cigar-dashboard/history.sqlite3",
                    &path_text(&history_file)?,
                );

            let (workspace_directory, evidence_directory) = if control_enabled {
                let workspace = root.path().join("workspace");
                let evidence = root.path().join("evidence");
                let sandbox = root.path().join("sandbox");
                for directory in [&workspace, &evidence, &sandbox] {
                    fs::create_dir(directory)?;
                    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
                }
                let registry = root.path().join("profiles.json");
                fs::write(&registry, b"{}\n")?;
                fs::set_permissions(&registry, fs::Permissions::from_mode(0o600))?;
                source = source.replace(
                    "enabled = false\nmax_concurrent_runs = 1",
                    &format!(
                        "enabled = true\nworkspace_root = \"{}\"\nprofile_registry = \"{}\"\nevidence_directory = \"{}\"\nsandbox_directory = \"{}\"\nmax_concurrent_runs = 1",
                        path_text(&workspace)?,
                        path_text(&registry)?,
                        path_text(&evidence)?,
                        path_text(&sandbox)?,
                    ),
                );
                (Some(workspace), Some(evidence))
            } else {
                (None, None)
            };

            let config_file = root.path().join("dashboard.toml");
            fs::write(&config_file, source)?;
            fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                root,
                config_file,
                runtime_directory,
                asset_directory,
                token_file,
                history_directory,
                workspace_directory,
                evidence_directory,
            })
        }

        fn replace_path(&self, from: &Path, to: &Path) -> Result<(), Box<dyn std::error::Error>> {
            let source = fs::read_to_string(&self.config_file)?;
            let source = source.replace(&path_text(from)?, &path_text(to)?);
            fs::write(&self.config_file, source)?;
            Ok(())
        }
    }

    #[cfg(unix)]
    fn path_text(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let value = path.to_str().ok_or("test path is not UTF-8")?;
        if value.contains(['"', '\\']) {
            return Err("test path cannot be embedded in TOML".into());
        }
        Ok(value.to_owned())
    }
}
