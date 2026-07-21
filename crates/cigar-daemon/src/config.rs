//! Validated daemon configuration with fail-closed deployment profiles.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_QUEUE_CAPACITY: usize = 65_536;
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXPANSION_RATIO: u32 = 64;
const MAX_DEADLINE_MILLIS: u64 = 300_000;
const MAX_IDEMPOTENCY_WAIT_MILLIS: u64 = 120_000;
const MAX_BLOCKING_ACTIVE: usize = 4_096;
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_AUDIENCE_BYTES: usize = 256;
const MAX_OBJECT_ENDPOINT_BYTES: usize = 2_048;
const MAX_OBJECT_SELECTOR_BYTES: usize = 512;
const DEFAULT_LOCAL_VECTOR_DIMENSION: usize = 64;
const DEFAULT_LOCAL_VECTOR_MAXIMUM_ENTRIES: usize = 100_000;
const DEFAULT_LOCAL_VECTOR_MAXIMUM_NEIGHBORS: usize = 128;

/// Stable daemon configuration failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigErrorCode {
    /// TOML was malformed, duplicated, or contained unknown fields.
    InvalidSyntax,
    /// A configured numeric resource limit was zero or outside its bound.
    InvalidLimit,
    /// Local mode attempted a public bind or omitted fallback authentication.
    UnsafeLocalBind,
    /// Shared mode omitted mandatory TLS or OIDC verification settings.
    IncompleteSharedAuth,
    /// A configured path was not absolute.
    RelativePath,
    /// An OIDC issuer or audience was malformed.
    InvalidIdentityProvider,
    /// Mandatory production storage, policy, authority, or key paths were incomplete.
    IncompleteProductionInputs,
}

/// Content-free configuration error safe for startup diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConfigError {
    code: ConfigErrorCode,
}

impl ConfigError {
    const fn new(code: ConfigErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> ConfigErrorCode {
        self.code
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "daemon configuration rejected: {:?}", self.code)
    }
}

impl std::error::Error for ConfigError {}

/// Authentication and exposure profile selected for the daemon.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// Permission-restricted local IPC, or authenticated loopback fallback.
    Local,
    /// TLS and pinned OIDC identity for a shared deployment.
    Shared,
}

/// Exact bounded capacities for every required worker queue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCapacities {
    /// Source ingestion work.
    pub ingestion: usize,
    /// Mandatory and optional index maintenance.
    pub indexing: usize,
    /// Dependency invalidation fan-out.
    pub invalidation: usize,
    /// Context compilation work.
    pub compilation: usize,
    /// Durable outbox wakeups.
    pub outbox: usize,
    /// Unknown-effect reconciliation.
    pub reconciliation: usize,
    /// Expired lease cleanup.
    pub lease_cleanup: usize,
    /// Backup creation and verification.
    pub backup: usize,
    /// Blob and metadata garbage collection.
    pub garbage_collection: usize,
}

/// Explicit request-governance and bounded blocking-pool limits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationResourceLimits {
    /// Maximum concurrent admitted requests across every tenant.
    pub global_request_concurrency: u32,
    /// Maximum concurrent admitted requests for one authenticated tenant.
    pub per_tenant_request_concurrency: u32,
    /// Maximum closures simultaneously executing on blocking threads.
    pub blocking_active: usize,
    /// Maximum admitted closures waiting for a blocking-thread permit.
    pub blocking_queued: usize,
    /// Maximum duplicate mutation reservation wait.
    pub idempotency_wait_ms: u64,
}

impl ApplicationResourceLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.global_request_concurrency == 0
            || self.per_tenant_request_concurrency == 0
            || self.per_tenant_request_concurrency > self.global_request_concurrency
            || !(1..=MAX_BLOCKING_ACTIVE).contains(&self.blocking_active)
            || !(1..=MAX_QUEUE_CAPACITY).contains(&self.blocking_queued)
            || !(1..=MAX_IDEMPOTENCY_WAIT_MILLIS).contains(&self.idempotency_wait_ms)
        {
            Err(ConfigError::new(ConfigErrorCode::InvalidLimit))
        } else {
            Ok(())
        }
    }

    /// Returns the bounded idempotency reservation wait.
    #[must_use]
    pub const fn idempotency_wait(&self) -> Duration {
        Duration::from_millis(self.idempotency_wait_ms)
    }
}

/// Optional bounded OpenTelemetry export settings; `None` means explicit local-only telemetry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySettings {
    /// HTTPS or loopback OTLP/gRPC collector; omitted for no outbound exporter.
    pub otlp_endpoint: Option<String>,
    /// Explicit owner-controlled CA bundle required for every HTTPS collector.
    pub otlp_ca_certificate_file: Option<PathBuf>,
    /// Maximum one exporter operation duration.
    pub export_timeout_ms: u64,
    /// Periodic metric export interval.
    pub metric_interval_ms: u64,
}

impl TelemetrySettings {
    fn validate(&self) -> Result<(), ConfigError> {
        let export_timeout = Duration::from_millis(self.export_timeout_ms);
        let metric_interval = Duration::from_millis(self.metric_interval_ms);
        if export_timeout.is_zero()
            || export_timeout > Duration::from_secs(30)
            || metric_interval < Duration::from_secs(1)
            || metric_interval > Duration::from_secs(300)
        {
            return Err(ConfigError::new(ConfigErrorCode::InvalidLimit));
        }
        match (&self.otlp_endpoint, &self.otlp_ca_certificate_file) {
            (None, None) => {}
            (Some(endpoint), ca_certificate_file) => {
                if let Some(path) = ca_certificate_file {
                    normalized_absolute(path)?;
                }
                crate::OtlpConfig::validate_configuration_shape(
                    endpoint,
                    export_timeout,
                    metric_interval,
                    ca_certificate_file.is_some(),
                )
                .map_err(|_error| ConfigError::new(ConfigErrorCode::InvalidLimit))?;
            }
            (None, Some(_ca_certificate_file)) => {
                return Err(ConfigError::new(ConfigErrorCode::InvalidLimit));
            }
        }
        Ok(())
    }

    /// Returns validated OTLP settings using bytes read from the configured explicit CA file.
    ///
    /// Callers must use a descriptor-safe, bounded reader. `None` is required for loopback HTTP
    /// and for disabled export; HTTPS requires `Some` bytes from the exact configured file.
    pub fn otlp_config(
        &self,
        ca_certificate_pem: Option<Vec<u8>>,
    ) -> Result<Option<crate::OtlpConfig>, ConfigError> {
        self.validate()?;
        match (
            self.otlp_endpoint.as_ref(),
            self.otlp_ca_certificate_file.as_ref(),
            ca_certificate_pem,
        ) {
            (None, None, None) => Ok(None),
            (Some(endpoint), None, None) => crate::OtlpConfig::new(
                endpoint,
                Duration::from_millis(self.export_timeout_ms),
                Duration::from_millis(self.metric_interval_ms),
            )
            .map(Some)
            .map_err(|_error| ConfigError::new(ConfigErrorCode::InvalidLimit)),
            (Some(endpoint), Some(_path), Some(ca_certificate_pem)) => {
                crate::OtlpConfig::new_with_ca_certificate(
                    endpoint,
                    Duration::from_millis(self.export_timeout_ms),
                    Duration::from_millis(self.metric_interval_ms),
                    ca_certificate_pem,
                )
                .map(Some)
                .map_err(|_error| ConfigError::new(ConfigErrorCode::InvalidLimit))
            }
            _ => Err(ConfigError::new(ConfigErrorCode::InvalidLimit)),
        }
    }
}

impl WorkerCapacities {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let capacities = [
            self.ingestion,
            self.indexing,
            self.invalidation,
            self.compilation,
            self.outbox,
            self.reconciliation,
            self.lease_cleanup,
            self.backup,
            self.garbage_collection,
        ];
        if capacities
            .into_iter()
            .all(|capacity| (1..=MAX_QUEUE_CAPACITY).contains(&capacity))
        {
            Ok(())
        } else {
            Err(ConfigError::new(ConfigErrorCode::InvalidLimit))
        }
    }
}

/// File-backed TLS identity and optional service-client trust root.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    /// PEM certificate chain presented by the daemon.
    pub certificate_chain: PathBuf,
    /// PEM private key, read only at the TLS boundary.
    pub private_key: PathBuf,
    /// Optional PEM CA roots used to require and verify service mTLS.
    pub client_ca: Option<PathBuf>,
}

impl TlsFiles {
    fn validate(&self) -> Result<(), ConfigError> {
        absolute(&self.certificate_chain)?;
        absolute(&self.private_key)?;
        if let Some(client_ca) = &self.client_ca {
            absolute(client_ca)?;
        }
        Ok(())
    }
}

impl fmt::Debug for TlsFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsFiles")
            .field("certificate_chain", &"[CONFIGURED]")
            .field("private_key", &"[REDACTED]")
            .field(
                "client_ca",
                &self.client_ca.as_ref().map(|_| "[CONFIGURED]"),
            )
            .finish()
    }
}

/// Pinned OIDC JWT validation and bounded JWKS refresh settings.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSettings {
    /// Exact HTTPS issuer claim and discovery origin.
    pub issuer: String,
    /// Exact accepted audience.
    pub audience: String,
    /// Claim containing the CIGAR tenant selector.
    pub tenant_claim: String,
    /// Maximum cached-key age before a bounded refresh is required.
    pub jwks_max_age_seconds: u64,
    /// Maximum one-attempt JWKS refresh time.
    pub jwks_refresh_timeout_ms: u64,
    /// Maximum accepted temporal claim skew.
    pub clock_skew_seconds: u64,
    /// Maximum encoded bearer-token bytes.
    pub max_token_bytes: usize,
}

/// Explicit trusted files and roots required by the production application composer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionPaths {
    /// Canonical project root used to derive the local transport identity.
    pub project_directory: PathBuf,
    /// Durable SQLite metadata database.
    pub metadata_database: PathBuf,
    /// Owner-only active-store descriptor selecting an activated SQLite v5 target.
    #[serde(default)]
    pub active_store_descriptor: Option<PathBuf>,
    /// Encrypted content-addressed blob root.
    pub blob_directory: PathBuf,
    /// Non-secret per-tenant blob wrapping-key reference root.
    pub blob_key_reference_directory: PathBuf,
    /// Encrypted development keystore file.
    pub keystore_file: PathBuf,
    /// Permission-restricted handle containing the keystore passphrase.
    pub keystore_passphrase_file: PathBuf,
    /// Permission-restricted persistent HMAC key used for opaque cursors.
    pub cursor_signing_key_file: PathBuf,
    /// Separately mounted owner-only monotonic effect checkpoint file.
    pub effect_checkpoint_file: PathBuf,
    /// Strict JSON or TOML compiled policy profile.
    pub policy_profile_file: PathBuf,
    /// Strict JSON domain authority and revocation configuration.
    pub authority_file: PathBuf,
    /// Strict JSON registry of explicitly configured source connectors and atomizers.
    pub source_registry_file: PathBuf,
    /// Strict JSON effect connector and trusted argument-vault registry.
    pub effect_registry_file: PathBuf,
}

/// Disabled-by-default macOS local deterministic vector projection settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVectorSettings {
    /// Explicit opt-in. Absence of this section is always disabled.
    pub enabled: bool,
    /// Owner-private durable immutable-generation root, required only when enabled.
    pub root_directory: Option<PathBuf>,
    /// Exact bounded signed-integer feature dimension.
    pub dimension: usize,
    /// Maximum processor-approved document vectors in one generation.
    pub maximum_entries: usize,
    /// Maximum neighbors returned by one authorized vector stage.
    pub maximum_neighbors: usize,
}

impl Default for LocalVectorSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            root_directory: None,
            dimension: DEFAULT_LOCAL_VECTOR_DIMENSION,
            maximum_entries: DEFAULT_LOCAL_VECTOR_MAXIMUM_ENTRIES,
            maximum_neighbors: DEFAULT_LOCAL_VECTOR_MAXIMUM_NEIGHBORS,
        }
    }
}

impl LocalVectorSettings {
    fn validate(
        &self,
        mode: DeploymentMode,
        state_directory: &Path,
        production: &ProductionPaths,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return if self == &Self::default() {
                Ok(())
            } else {
                Err(ConfigError::new(
                    ConfigErrorCode::IncompleteProductionInputs,
                ))
            };
        }
        if mode != DeploymentMode::Local {
            return Err(ConfigError::new(
                ConfigErrorCode::IncompleteProductionInputs,
            ));
        }
        #[cfg(not(target_os = "macos"))]
        return Err(ConfigError::new(
            ConfigErrorCode::IncompleteProductionInputs,
        ));

        #[cfg(target_os = "macos")]
        {
            let root = self
                .root_directory
                .as_ref()
                .ok_or_else(|| ConfigError::new(ConfigErrorCode::IncompleteProductionInputs))?;
            normalized_absolute(root)?;
            if root == state_directory
                || !root.starts_with(state_directory)
                || root == &production.blob_directory
                || root == &production.blob_key_reference_directory
                || production.blob_directory.starts_with(root)
                || production.blob_key_reference_directory.starts_with(root)
                || !(8..=cigar_retrieval::MAX_VECTOR_DIMENSIONS).contains(&self.dimension)
                || !(1..=cigar_retrieval::MAX_LOCAL_VECTOR_ENTRIES).contains(&self.maximum_entries)
                || self.maximum_neighbors == 0
                || self.maximum_neighbors > self.maximum_entries
                || self.maximum_neighbors > cigar_retrieval::MAX_CANDIDATES
            {
                return Err(ConfigError::new(
                    ConfigErrorCode::IncompleteProductionInputs,
                ));
            }
            Ok(())
        }
    }
}

/// DDL-free runtime pool plus a separately mounted owner migration credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedPostgresSettings {
    /// Permission-restricted file containing the non-owner runtime PostgreSQL URL.
    pub runtime_url_file: PathBuf,
    /// Permission-restricted file containing the owner/migrator PostgreSQL URL.
    pub migrator_url_file: PathBuf,
    /// Exact DNS name or IP identity expected in the PostgreSQL server certificate.
    pub server_name: String,
    /// Bounded PEM CA bundle used only for PostgreSQL server authentication.
    pub ca_certificate_file: PathBuf,
    /// Minimum warm runtime connections.
    pub minimum_connections: u32,
    /// Hard runtime pool bound.
    pub maximum_connections: u32,
    /// Maximum pool acquisition time.
    pub acquire_timeout_ms: u64,
    /// Per-transaction PostgreSQL statement timeout.
    pub statement_timeout_ms: u64,
    /// Per-transaction PostgreSQL lock timeout.
    pub lock_timeout_ms: u64,
    /// Idle-in-transaction timeout.
    pub idle_transaction_timeout_ms: u64,
}

impl SharedPostgresSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        normalized_absolute(&self.runtime_url_file)?;
        normalized_absolute(&self.migrator_url_file)?;
        normalized_absolute(&self.ca_certificate_file)?;
        if self.runtime_url_file == self.migrator_url_file
            || self.ca_certificate_file == self.runtime_url_file
            || self.ca_certificate_file == self.migrator_url_file
            || self.server_name.is_empty()
            || self.server_name.len() > 253
            || !self.server_name.bytes().all(|byte| byte.is_ascii_graphic())
            || self.server_name.contains(['/', '\\', '@'])
            || self.minimum_connections == 0
            || self.maximum_connections < self.minimum_connections
            || self.maximum_connections > 256
            || !(1..=60_000).contains(&self.acquire_timeout_ms)
            || !(1..=300_000).contains(&self.statement_timeout_ms)
            || !(1..=self.statement_timeout_ms).contains(&self.lock_timeout_ms)
            || !(1..=300_000).contains(&self.idle_transaction_timeout_ms)
        {
            return Err(ConfigError::new(ConfigErrorCode::InvalidLimit));
        }
        Ok(())
    }
}

/// Explicit S3-compatible object-CAS endpoint and file-backed secret handles.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedObjectSettings {
    /// HTTPS endpoint; loopback HTTP is accepted only for development.
    pub endpoint: String,
    /// Exact signing region.
    pub region: String,
    /// Exact bucket name.
    pub bucket: String,
    /// Optional bounded key prefix.
    pub prefix: String,
    /// Enables path-style addressing for explicitly compatible providers.
    pub path_style: bool,
    /// Permission-restricted file containing the explicit access key.
    pub access_key_file: PathBuf,
    /// Permission-restricted file containing the explicit secret key.
    pub secret_key_file: PathBuf,
    /// Optional permission-restricted file containing a session token.
    pub security_token_file: Option<PathBuf>,
    /// Trusted JSON tenant-to-blob-wrapping-key-reference mapping.
    pub wrapping_keys_file: PathBuf,
    /// Permission-restricted file containing exactly 32 raw HMAC blinding-key bytes.
    pub blinding_key_file: PathBuf,
}

impl SharedObjectSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        for path in [
            &self.access_key_file,
            &self.secret_key_file,
            &self.wrapping_keys_file,
            &self.blinding_key_file,
        ] {
            normalized_absolute(path)?;
        }
        if let Some(token) = &self.security_token_file {
            normalized_absolute(token)?;
        }
        let endpoint_allowed = valid_shared_object_endpoint(&self.endpoint);
        let selectors_valid = !self.region.is_empty()
            && self.region.len() <= 128
            && !self.bucket.is_empty()
            && self.bucket.len() <= 63
            && self.prefix.len() <= MAX_OBJECT_SELECTOR_BYTES
            && !self.prefix.starts_with('/')
            && !self.prefix.contains("..");
        let mut files = BTreeSet::new();
        let distinct = [
            Some(&self.access_key_file),
            Some(&self.secret_key_file),
            self.security_token_file.as_ref(),
            Some(&self.wrapping_keys_file),
            Some(&self.blinding_key_file),
        ]
        .into_iter()
        .flatten()
        .all(|path| files.insert(path));
        if !endpoint_allowed
            || self.endpoint.len() > MAX_OBJECT_ENDPOINT_BYTES
            || !selectors_valid
            || !distinct
        {
            return Err(ConfigError::new(
                ConfigErrorCode::IncompleteProductionInputs,
            ));
        }
        Ok(())
    }
}

fn valid_shared_object_endpoint(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|endpoint| {
        let root_path = endpoint.path().is_empty() || endpoint.path() == "/";
        let no_ambient_authority = endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none();
        let secure = endpoint.scheme() == "https" && endpoint.host_str().is_some();
        let loopback_http = endpoint.scheme() == "http"
            && endpoint.port().is_some()
            && endpoint
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"));
        root_path
            && no_ambient_authority
            && !endpoint.cannot_be_a_base()
            && (secure || loopback_http)
    })
}

impl fmt::Debug for SharedObjectSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedObjectSettings")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("credentials", &"[REDACTED]")
            .field("wrapping_keys", &"[CONFIGURED]")
            .field("blinding_key", &"[REDACTED]")
            .finish()
    }
}

/// Shared PostgreSQL and object storage composition selected only in shared mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedStorageSettings {
    /// PostgreSQL connection pool and separate migration identity.
    pub postgres: SharedPostgresSettings,
    /// Encrypted S3-compatible object CAS.
    pub object: SharedObjectSettings,
}

impl SharedStorageSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        self.postgres.validate()?;
        self.object.validate()
    }
}

impl ProductionPaths {
    fn validate(&self, state_directory: &Path) -> Result<(), ConfigError> {
        let paths = [
            &self.project_directory,
            &self.metadata_database,
            &self.blob_directory,
            &self.blob_key_reference_directory,
            &self.keystore_file,
            &self.keystore_passphrase_file,
            &self.cursor_signing_key_file,
            &self.effect_checkpoint_file,
            &self.policy_profile_file,
            &self.authority_file,
            &self.source_registry_file,
            &self.effect_registry_file,
        ];
        for path in paths {
            normalized_absolute(path)?;
        }
        if let Some(descriptor) = &self.active_store_descriptor {
            normalized_absolute(descriptor)?;
            if descriptor == state_directory
                || !descriptor.starts_with(state_directory)
                || paths.contains(&descriptor)
                || descriptor.starts_with(&self.blob_directory)
                || descriptor.starts_with(&self.blob_key_reference_directory)
            {
                return Err(ConfigError::new(
                    ConfigErrorCode::IncompleteProductionInputs,
                ));
            }
        }
        for mutable in [
            &self.metadata_database,
            &self.blob_directory,
            &self.blob_key_reference_directory,
            &self.keystore_file,
            &self.cursor_signing_key_file,
        ] {
            if mutable == state_directory || !mutable.starts_with(state_directory) {
                return Err(ConfigError::new(
                    ConfigErrorCode::IncompleteProductionInputs,
                ));
            }
        }
        let unique: BTreeSet<&Path> = paths.into_iter().map(PathBuf::as_path).collect();
        if unique.len() != paths.len()
            || self.effect_checkpoint_file.starts_with(state_directory)
            || self
                .blob_directory
                .starts_with(&self.blob_key_reference_directory)
            || self
                .blob_key_reference_directory
                .starts_with(&self.blob_directory)
        {
            return Err(ConfigError::new(
                ConfigErrorCode::IncompleteProductionInputs,
            ));
        }
        Ok(())
    }
}

impl OidcSettings {
    fn validate(&self) -> Result<(), ConfigError> {
        let issuer_valid = valid_oidc_issuer(&self.issuer);
        let audience_valid = !self.audience.is_empty()
            && self.audience.len() <= MAX_AUDIENCE_BYTES
            && !self.audience.bytes().any(|byte| byte.is_ascii_control());
        let tenant_claim_valid = valid_claim_name(&self.tenant_claim);
        let bounds_valid = (1..=86_400).contains(&self.jwks_max_age_seconds)
            && (1..=30_000).contains(&self.jwks_refresh_timeout_ms)
            && self.clock_skew_seconds <= 300
            && (256..=65_536).contains(&self.max_token_bytes);
        if issuer_valid && audience_valid && tenant_claim_valid && bounds_valid {
            Ok(())
        } else {
            Err(ConfigError::new(ConfigErrorCode::InvalidIdentityProvider))
        }
    }
}

fn valid_oidc_issuer(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_ISSUER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    reqwest::Url::parse(value).is_ok_and(|issuer| {
        issuer.scheme() == "https"
            && issuer.host_str().is_some()
            && issuer.username().is_empty()
            && issuer.password().is_none()
            && issuer.query().is_none()
            && issuer.fragment().is_none()
            && !issuer.cannot_be_a_base()
    })
}

impl fmt::Debug for OidcSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcSettings")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("tenant_claim", &self.tenant_claim)
            .field("jwks_max_age_seconds", &self.jwks_max_age_seconds)
            .field("jwks_refresh_timeout_ms", &self.jwks_refresh_timeout_ms)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .field("max_token_bytes", &self.max_token_bytes)
            .finish()
    }
}

/// Complete validated daemon configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Local or shared security profile.
    pub mode: DeploymentMode,
    /// Explicit bounded SQLite capacity profile; `large_local` is macOS arm64 local-only.
    #[serde(default)]
    pub local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile,
    /// Durable metadata and blob state root.
    pub state_directory: PathBuf,
    /// Socket, token, and process-runtime root.
    pub runtime_directory: PathBuf,
    /// Preferred permission-restricted Unix socket in local mode.
    pub unix_socket: Option<PathBuf>,
    /// Permission-restricted Windows named pipe in the closed CIGAR namespace.
    pub windows_named_pipe: Option<String>,
    /// HTTP listen address.
    pub http_listen: Option<SocketAddr>,
    /// gRPC listen address.
    pub grpc_listen: Option<SocketAddr>,
    /// File-protected random bearer token required for loopback local TCP.
    pub local_token_file: Option<PathBuf>,
    /// Shared TLS identity; mandatory in shared mode.
    pub tls: Option<TlsFiles>,
    /// Pinned shared identity provider; mandatory in shared mode.
    pub oidc: Option<OidcSettings>,
    /// Mandatory trusted production application paths.
    pub production: ProductionPaths,
    /// Optional local deterministic vector projection; absent is disabled.
    #[serde(default)]
    pub local_vector: LocalVectorSettings,
    /// PostgreSQL/object profile; mandatory in shared mode and forbidden in local mode.
    #[serde(default)]
    pub shared_storage: Option<SharedStorageSettings>,
    /// Server-capped default request deadline.
    pub request_deadline_ms: u64,
    /// Maximum graceful-shutdown drain interval.
    pub shutdown_deadline_ms: u64,
    /// Maximum expanded request body.
    pub max_request_bytes: usize,
    /// Maximum expanded-to-compressed ratio.
    pub max_expansion_ratio: u32,
    /// Required bounded worker queues.
    pub workers: WorkerCapacities,
    /// Request quotas, blocking-pool admission, and durable idempotency wait bounds.
    pub resources: ApplicationResourceLimits,
    /// Explicit local-only or bounded OTLP telemetry profile.
    pub telemetry: TelemetrySettings,
}

impl DaemonConfig {
    /// Parses strict TOML and validates all exposure and resource invariants.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)
            .map_err(|_error| ConfigError::new(ConfigErrorCode::InvalidSyntax))?;
        config.validate()?;
        Ok(config)
    }

    /// Verifies deployment security and bounded-resource invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        normalized_absolute(&self.state_directory)?;
        normalized_absolute(&self.runtime_directory)?;
        self.production.validate(&self.state_directory)?;
        self.local_vector
            .validate(self.mode, &self.state_directory, &self.production)?;
        if let Some(socket) = &self.unix_socket {
            absolute(socket)?;
            if socket.parent() != Some(self.runtime_directory.as_path()) {
                return Err(ConfigError::new(ConfigErrorCode::UnsafeLocalBind));
            }
        }
        if self.unix_socket.is_some() && self.windows_named_pipe.is_some() {
            return Err(ConfigError::new(ConfigErrorCode::UnsafeLocalBind));
        }
        if self
            .windows_named_pipe
            .as_deref()
            .is_some_and(|name| !safe_windows_pipe_name(name))
        {
            return Err(ConfigError::new(ConfigErrorCode::UnsafeLocalBind));
        }
        if let Some(token_file) = &self.local_token_file {
            absolute(token_file)?;
        }
        let limits_valid = (1..=MAX_DEADLINE_MILLIS).contains(&self.request_deadline_ms)
            && (1..=MAX_DEADLINE_MILLIS).contains(&self.shutdown_deadline_ms)
            && (1..=MAX_REQUEST_BYTES).contains(&self.max_request_bytes)
            && (1..=MAX_EXPANSION_RATIO).contains(&self.max_expansion_ratio);
        if !limits_valid {
            return Err(ConfigError::new(ConfigErrorCode::InvalidLimit));
        }
        self.workers.validate()?;
        self.resources.validate()?;
        self.telemetry.validate()?;
        if self.http_listen.is_some() && self.http_listen == self.grpc_listen {
            return Err(ConfigError::new(ConfigErrorCode::InvalidLimit));
        }
        match self.mode {
            DeploymentMode::Local => self.validate_local(),
            DeploymentMode::Shared => self.validate_shared(),
        }
    }

    /// Returns the server-capped request deadline.
    #[must_use]
    pub const fn request_deadline(&self) -> Duration {
        Duration::from_millis(self.request_deadline_ms)
    }

    /// Returns the graceful-shutdown deadline.
    #[must_use]
    pub const fn shutdown_deadline(&self) -> Duration {
        Duration::from_millis(self.shutdown_deadline_ms)
    }

    fn validate_local(&self) -> Result<(), ConfigError> {
        if self.tls.is_some() || self.oidc.is_some() || self.shared_storage.is_some() {
            return Err(ConfigError::new(ConfigErrorCode::UnsafeLocalBind));
        }
        if self.local_sqlite_capacity_profile == cigar_store::SqliteCapacityProfile::LargeLocal
            && !cfg!(all(target_os = "macos", target_arch = "aarch64"))
        {
            return Err(ConfigError::new(
                ConfigErrorCode::IncompleteProductionInputs,
            ));
        }
        let tcp = [self.http_listen, self.grpc_listen];
        let has_tcp = tcp.into_iter().flatten().next().is_some();
        let tcp_safe = tcp
            .into_iter()
            .flatten()
            .all(|address| address.ip().is_loopback());
        let has_ipc = self.unix_socket.is_some() || self.windows_named_pipe.is_some();
        if !tcp_safe || (!has_ipc && !has_tcp) || (has_tcp && self.local_token_file.is_none()) {
            return Err(ConfigError::new(ConfigErrorCode::UnsafeLocalBind));
        }
        Ok(())
    }

    fn validate_shared(&self) -> Result<(), ConfigError> {
        if self.local_sqlite_capacity_profile != cigar_store::SqliteCapacityProfile::Standard
            || self.production.active_store_descriptor.is_some()
            || self.unix_socket.is_some()
            || self.windows_named_pipe.is_some()
            || self.local_token_file.is_some()
            || self.http_listen.is_none()
            || self.grpc_listen.is_none()
        {
            return Err(ConfigError::new(ConfigErrorCode::IncompleteSharedAuth));
        }
        let tls = self
            .tls
            .as_ref()
            .ok_or_else(|| ConfigError::new(ConfigErrorCode::IncompleteSharedAuth))?;
        tls.validate()?;
        self.oidc
            .as_ref()
            .ok_or_else(|| ConfigError::new(ConfigErrorCode::IncompleteSharedAuth))?
            .validate()?;
        self.shared_storage
            .as_ref()
            .ok_or_else(|| ConfigError::new(ConfigErrorCode::IncompleteProductionInputs))?
            .validate()
    }
}

fn safe_windows_pipe_name(value: &str) -> bool {
    let prefix = r"\\.\pipe\cigar-";
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 256
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn absolute(path: &Path) -> Result<(), ConfigError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ConfigError::new(ConfigErrorCode::RelativePath))
    }
}

fn normalized_absolute(path: &Path) -> Result<(), ConfigError> {
    use std::path::Component;

    absolute(path)?;
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        Err(ConfigError::new(ConfigErrorCode::RelativePath))
    } else {
        Ok(())
    }
}

fn valid_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{ConfigErrorCode, DaemonConfig};

    fn local_config(extra: &str) -> String {
        format!(
            r#"
mode = "local"
state_directory = "/tmp/cigar-state"
runtime_directory = "/tmp/cigar-run"
unix_socket = "/tmp/cigar-run/cigard.sock"
request_deadline_ms = 30000
shutdown_deadline_ms = 30000
max_request_bytes = 1048576
max_expansion_ratio = 16
{extra}

[workers]
ingestion = 4
indexing = 4
invalidation = 8
compilation = 2
outbox = 8
reconciliation = 4
lease_cleanup = 2
backup = 1
garbage_collection = 2

[production]
project_directory = "/tmp/cigar-project"
metadata_database = "/tmp/cigar-state/cigar.sqlite3"
blob_directory = "/tmp/cigar-state/blobs"
blob_key_reference_directory = "/tmp/cigar-state/blob-keys"
keystore_file = "/tmp/cigar-state/keystore.cigar"
keystore_passphrase_file = "/tmp/cigar-secrets/keystore-passphrase"
cursor_signing_key_file = "/tmp/cigar-state/cursor.key"
effect_checkpoint_file = "/tmp/cigar-effect-checkpoints/checkpoints.json"
policy_profile_file = "/tmp/cigar-config/policy.json"
authority_file = "/tmp/cigar-config/authority.json"
source_registry_file = "/tmp/cigar-config/sources.json"
effect_registry_file = "/tmp/cigar-config/effects.json"

[resources]
global_request_concurrency = 256
per_tenant_request_concurrency = 32
blocking_active = 4
blocking_queued = 64
idempotency_wait_ms = 30000

[telemetry]
export_timeout_ms = 5000
metric_interval_ms = 30000
"#
        )
    }

    fn shared_storage_config() -> &'static str {
        r#"
[shared_storage.postgres]
runtime_url_file = "/tmp/cigar-secrets/postgres-runtime-url"
migrator_url_file = "/tmp/cigar-secrets/postgres-migrator-url"
server_name = "postgres.cigar-dependencies.svc.cluster.local"
ca_certificate_file = "/tmp/cigar-secrets/postgres-ca.crt"
minimum_connections = 2
maximum_connections = 32
acquire_timeout_ms = 5000
statement_timeout_ms = 30000
lock_timeout_ms = 5000
idle_transaction_timeout_ms = 30000

[shared_storage.object]
endpoint = "https://objects.example"
region = "us-east-1"
bucket = "cigar-shared"
prefix = "production"
path_style = false
access_key_file = "/tmp/cigar-secrets/object-access-key"
secret_key_file = "/tmp/cigar-secrets/object-secret-key"
security_token_file = "/tmp/cigar-secrets/object-session-token"
wrapping_keys_file = "/tmp/cigar-config/object-wrapping-keys.json"
blinding_key_file = "/tmp/cigar-secrets/object-blinding-key"
        "#
    }

    fn shared_config() -> String {
        let extra = format!(
            r#"http_listen = "127.0.0.1:7443"
grpc_listen = "127.0.0.1:7444"

[tls]
certificate_chain = "/tmp/server.pem"
private_key = "/tmp/server.key"

[oidc]
issuer = "https://issuer.example"
audience = "cigar-api"
tenant_claim = "tenant"
jwks_max_age_seconds = 300
jwks_refresh_timeout_ms = 100
clock_skew_seconds = 30
max_token_bytes = 4096
{}"#,
            shared_storage_config()
        );
        local_config(&extra)
            .replace("mode = \"local\"", "mode = \"shared\"")
            .replace("unix_socket = \"/tmp/cigar-run/cigard.sock\"\n", "")
    }

    #[test]
    fn local_unix_profile_is_valid() -> Result<(), Box<dyn std::error::Error>> {
        let config = DaemonConfig::from_toml(&local_config(""))?;
        assert_eq!(config.workers.outbox, 8);
        assert_eq!(config.request_deadline().as_secs(), 30);
        assert!(!config.local_vector.enabled);
        assert_eq!(
            config.local_sqlite_capacity_profile,
            cigar_store::SqliteCapacityProfile::Standard
        );
        Ok(())
    }

    #[test]
    fn active_v5_descriptor_is_explicit_local_owner_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let local = local_config("").replace(
            "metadata_database = \"/tmp/cigar-state/cigar.sqlite3\"",
            "metadata_database = \"/tmp/cigar-state/cigar.sqlite3\"\nactive_store_descriptor = \"/tmp/cigar-state/active-store.json\"",
        );
        let config = DaemonConfig::from_toml(&local)?;
        assert_eq!(
            config.production.active_store_descriptor.as_deref(),
            Some(std::path::Path::new("/tmp/cigar-state/active-store.json"))
        );

        let outside = local.replace(
            "/tmp/cigar-state/active-store.json",
            "/tmp/cigar-config/active-store.json",
        );
        assert_eq!(
            DaemonConfig::from_toml(&outside)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::IncompleteProductionInputs)
        );

        let shared = shared_config().replace(
            "metadata_database = \"/tmp/cigar-state/cigar.sqlite3\"",
            "metadata_database = \"/tmp/cigar-state/cigar.sqlite3\"\nactive_store_descriptor = \"/tmp/cigar-state/active-store.json\"",
        );
        assert_eq!(
            DaemonConfig::from_toml(&shared)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::IncompleteSharedAuth)
        );
        Ok(())
    }

    #[test]
    fn large_local_sqlite_is_an_explicit_macos_arm64_only_profile() {
        let configured = DaemonConfig::from_toml(&local_config(
            "local_sqlite_capacity_profile = \"large_local\"",
        ));
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert!(matches!(
                configured,
                Ok(config)
                    if config.local_sqlite_capacity_profile
                        == cigar_store::SqliteCapacityProfile::LargeLocal
            ));
        } else {
            assert!(matches!(
                configured,
                Err(error) if error.code() == ConfigErrorCode::IncompleteProductionInputs
            ));
        }
    }

    #[test]
    fn local_vector_is_explicit_macos_only_bounded_and_shared_forbidden()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = r#"[local_vector]
enabled = true
root_directory = "/tmp/cigar-state/vectors"
dimension = 64
maximum_entries = 100000
maximum_neighbors = 128
"#;
        let enabled = DaemonConfig::from_toml(&local_config(table))?;
        assert!(enabled.local_vector.enabled);
        assert_eq!(enabled.local_vector.dimension, 64);

        for invalid in [
            local_config(table).replace(
                "root_directory = \"/tmp/cigar-state/vectors\"",
                "root_directory = \"/tmp/outside-vectors\"",
            ),
            local_config(table).replace("dimension = 64", "dimension = 0"),
            local_config(table).replace("maximum_neighbors = 128", "maximum_neighbors = 100001"),
            local_config(table).replace("enabled = true", "enabled = false"),
        ] {
            assert_eq!(
                DaemonConfig::from_toml(&invalid)
                    .err()
                    .map(|error| error.code()),
                Some(ConfigErrorCode::IncompleteProductionInputs)
            );
        }

        let shared = shared_config().replace("[workers]", &format!("{table}\n[workers]"));
        assert_eq!(
            DaemonConfig::from_toml(&shared)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::IncompleteProductionInputs)
        );
        Ok(())
    }

    #[test]
    fn effect_checkpoint_must_be_outside_mutable_state_directory() {
        let colocated = local_config("").replace(
            "effect_checkpoint_file = \"/tmp/cigar-effect-checkpoints/checkpoints.json\"",
            "effect_checkpoint_file = \"/tmp/cigar-state/effect-checkpoints.json\"",
        );
        assert_eq!(
            DaemonConfig::from_toml(&colocated)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::IncompleteProductionInputs)
        );
    }

    #[test]
    fn local_public_bind_fails_closed() {
        let error = DaemonConfig::from_toml(&local_config(
            "http_listen = \"0.0.0.0:7443\"\nlocal_token_file = \"/tmp/cigar-run/token\"",
        ));
        assert_eq!(
            error.err().map(|value| value.code()),
            Some(ConfigErrorCode::UnsafeLocalBind)
        );
    }

    #[test]
    fn loopback_tcp_requires_file_protected_token() {
        let error = DaemonConfig::from_toml(&local_config(
            "unix_socket = \"/tmp/duplicate.sock\"\nhttp_listen = \"127.0.0.1:7443\"",
        ));
        assert_eq!(
            error.err().map(|value| value.code()),
            Some(ConfigErrorCode::InvalidSyntax)
        );

        let no_socket = local_config("http_listen = \"127.0.0.1:7443\"")
            .replace("unix_socket = \"/tmp/cigar-run/cigard.sock\"\n", "");
        let error = DaemonConfig::from_toml(&no_socket);
        assert_eq!(
            error.err().map(|value| value.code()),
            Some(ConfigErrorCode::UnsafeLocalBind)
        );
    }

    #[test]
    fn windows_pipe_namespace_is_closed_and_exclusive_with_unix_socket() {
        let windows = local_config("").replace(
            "unix_socket = \"/tmp/cigar-run/cigard.sock\"",
            r#"windows_named_pipe = "\\\\.\\pipe\\cigar-local-v1""#,
        );
        assert!(DaemonConfig::from_toml(&windows).is_ok());

        for invalid in [
            windows.replace("cigar-local-v1", "other-local-v1"),
            windows.replace("cigar-local-v1", "cigar-local\\escape"),
            local_config("").replace(
                "request_deadline_ms = 30000",
                r#"windows_named_pipe = "\\\\.\\pipe\\cigar-local-v1"
request_deadline_ms = 30000"#,
            ),
        ] {
            assert_eq!(
                DaemonConfig::from_toml(&invalid)
                    .err()
                    .map(|error| error.code()),
                Some(ConfigErrorCode::UnsafeLocalBind)
            );
        }
    }

    #[test]
    fn shared_profile_requires_tls_and_oidc() {
        let shared =
            local_config("http_listen = \"127.0.0.1:7443\"\ngrpc_listen = \"127.0.0.1:7444\"")
                .replace("mode = \"local\"", "mode = \"shared\"")
                .replace("unix_socket = \"/tmp/cigar-run/cigard.sock\"\n", "");
        let error = DaemonConfig::from_toml(&shared);
        assert_eq!(
            error.err().map(|value| value.code()),
            Some(ConfigErrorCode::IncompleteSharedAuth)
        );
    }

    #[test]
    fn shared_oidc_issuer_rejects_ambient_authority_and_discovery_ambiguity() {
        let base = local_config(
            r#"http_listen = "127.0.0.1:7443"
grpc_listen = "127.0.0.1:7444"

[tls]
certificate_chain = "/tmp/server.pem"
private_key = "/tmp/server.key"

[oidc]
issuer = "https://issuer.example"
audience = "cigar-api"
tenant_claim = "tenant"
jwks_max_age_seconds = 300
jwks_refresh_timeout_ms = 100
clock_skew_seconds = 30
max_token_bytes = 4096"#,
        )
        .replace("mode = \"local\"", "mode = \"shared\"")
        .replace("unix_socket = \"/tmp/cigar-run/cigard.sock\"\n", "");
        for invalid in [
            "https://user@issuer.example",
            "https://issuer.example?tenant=other",
            "https://issuer.example#fragment",
        ] {
            let candidate = base.replace("https://issuer.example", invalid);
            assert_eq!(
                DaemonConfig::from_toml(&candidate)
                    .err()
                    .map(|error| error.code()),
                Some(ConfigErrorCode::InvalidIdentityProvider)
            );
        }
    }

    #[test]
    fn shared_profile_allows_tls_oidc_without_optional_service_mtls()
    -> Result<(), Box<dyn std::error::Error>> {
        let shared = shared_config();
        let config = DaemonConfig::from_toml(&shared)?;
        assert!(
            config
                .tls
                .as_ref()
                .is_some_and(|tls| tls.client_ca.is_none())
        );
        Ok(())
    }

    #[test]
    fn shared_object_endpoint_is_one_closed_origin_without_url_authority() {
        let base = shared_config();
        for invalid in [
            "https://user@objects.example",
            "https://user:password@objects.example",
            "https://objects.example/path",
            "https://objects.example?tenant=other",
            "https://objects.example#fragment",
            "http://objects.example:9000",
            "http://localhost",
        ] {
            let candidate = base.replace("https://objects.example", invalid);
            assert_eq!(
                DaemonConfig::from_toml(&candidate)
                    .err()
                    .map(|error| error.code()),
                Some(ConfigErrorCode::IncompleteProductionInputs),
                "endpoint {invalid:?} must fail closed"
            );
        }
        for allowed in [
            "https://objects.example",
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            let candidate = base.replace("https://objects.example", allowed);
            assert!(
                DaemonConfig::from_toml(&candidate).is_ok(),
                "endpoint {allowed:?} should satisfy the closed origin policy"
            );
        }
    }

    #[test]
    fn unknown_configuration_field_is_rejected() {
        let error = DaemonConfig::from_toml(&local_config("secret = \"must-not-be-ignored\""));
        assert_eq!(
            error.err().map(|value| value.code()),
            Some(ConfigErrorCode::InvalidSyntax)
        );
    }

    #[test]
    fn application_and_telemetry_resource_bounds_fail_closed() {
        for invalid in [
            local_config("").replace(
                "global_request_concurrency = 256",
                "global_request_concurrency = 0",
            ),
            local_config("").replace(
                "per_tenant_request_concurrency = 32",
                "per_tenant_request_concurrency = 257",
            ),
            local_config("").replace("blocking_active = 4", "blocking_active = 0"),
            local_config("").replace("blocking_queued = 64", "blocking_queued = 65537"),
            local_config("").replace(
                "idempotency_wait_ms = 30000",
                "idempotency_wait_ms = 120001",
            ),
            local_config("").replace("export_timeout_ms = 5000", "export_timeout_ms = 0"),
        ] {
            assert_eq!(
                DaemonConfig::from_toml(&invalid)
                    .err()
                    .map(|error| error.code()),
                Some(ConfigErrorCode::InvalidLimit)
            );
        }

        let unsafe_export = local_config("").replace(
            "[telemetry]",
            "[telemetry]\notlp_endpoint = \"http://collector.example:4317\"",
        );
        assert_eq!(
            DaemonConfig::from_toml(&unsafe_export)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::InvalidLimit)
        );

        let https_without_ca = local_config("").replace(
            "[telemetry]",
            "[telemetry]\notlp_endpoint = \"https://collector.example:4317\"",
        );
        assert_eq!(
            DaemonConfig::from_toml(&https_without_ca)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::InvalidLimit)
        );
        let https_with_ca = local_config("").replace(
            "[telemetry]",
            "[telemetry]\notlp_endpoint = \"https://collector.example:4317\"\notlp_ca_certificate_file = \"/tmp/collector-ca.pem\"",
        );
        assert!(DaemonConfig::from_toml(&https_with_ca).is_ok());
        let https_with_relative_ca =
            https_with_ca.replace("/tmp/collector-ca.pem", "relative/collector-ca.pem");
        assert_eq!(
            DaemonConfig::from_toml(&https_with_relative_ca)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::RelativePath)
        );
        let loopback_with_ca = local_config("").replace(
            "[telemetry]",
            "[telemetry]\notlp_endpoint = \"http://127.0.0.1:4317\"\notlp_ca_certificate_file = \"/tmp/collector-ca.pem\"",
        );
        assert_eq!(
            DaemonConfig::from_toml(&loopback_with_ca)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::InvalidLimit)
        );
        let ca_without_endpoint = local_config("").replace(
            "[telemetry]",
            "[telemetry]\notlp_ca_certificate_file = \"/tmp/collector-ca.pem\"",
        );
        assert_eq!(
            DaemonConfig::from_toml(&ca_without_endpoint)
                .err()
                .map(|error| error.code()),
            Some(ConfigErrorCode::InvalidLimit)
        );
    }
}
