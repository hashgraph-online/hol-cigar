//! Signed extension-manifest records and the stable capability-limited extension ABI.

use crate::limits::{
    EXTENSION_HANDLE_BYTES, EXTENSION_PUBLISHER_KEY_BYTES, EXTENSION_SIGNATURE_BYTES,
    MAX_EXTENSION_CONCURRENCY, MAX_EXTENSION_ENDPOINT_HOST_BYTES, MAX_EXTENSION_FUEL,
    MAX_EXTENSION_HANDLES, MAX_EXTENSION_HOST_CALLS, MAX_EXTENSION_HOST_SELECTOR_BYTES,
    MAX_EXTENSION_IO_BYTES, MAX_EXTENSION_KINDS, MAX_EXTENSION_MEMORY_BYTES,
    MAX_EXTENSION_NETWORK_ENDPOINTS, MAX_EXTENSION_PREOPENS, MAX_EXTENSION_PROCESSORS,
    MAX_EXTENSION_RANDOM_SEED_BYTES, MAX_EXTENSION_RECURSION_DEPTH, MAX_EXTENSION_RUNTIME_NANOS,
    MAX_EXTENSION_SANDBOX_PATH_BYTES,
};
use crate::primitive::base64url;
use crate::validation::{ValidationCode, ValidationErrors, issue};
use crate::{
    Classification, ContentDigest, DurationNanos, RecordId, SchemaVersion, UtcTimestamp, Validate,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;

const MAX_EXTENSION_ID_BYTES: usize = 128;
const ED25519_PUBLIC_KEY_BASE64URL_BYTES: usize = 43;
const ED25519_SIGNATURE_BASE64URL_BYTES: usize = 86;
const EXTENSION_HANDLE_BASE64URL_BYTES: usize = 43;
const MAX_EXTENSION_IO_BASE64URL_BYTES: usize = 89_478_486;
const MAX_EXTENSION_RANDOM_SEED_BASE64URL_BYTES: usize = 86;

/// Normalized reverse-domain-style extension or publisher identity.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExtensionId(String);

impl ExtensionId {
    /// Creates a bounded lowercase identifier made of dot-separated safe labels.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_EXTENSION_ID_BYTES
            && value.split('.').all(valid_identifier_label);
        if valid {
            Ok(Self(value))
        } else {
            Err(single_issue(
                ValidationCode::InvalidIdentity,
                "/extension_id",
                "extension identity must use normalized lowercase dot-separated labels",
            ))
        }
    }

    /// Returns the normalized identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl JsonSchema for ExtensionId {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "ExtensionId".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_EXTENSION_ID_BYTES,
            "pattern": "^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$"
        })
    }
}

impl fmt::Debug for ExtensionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ExtensionId").field(&self.0).finish()
    }
}

impl TryFrom<String> for ExtensionId {
    type Error = ValidationErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ExtensionId> for String {
    fn from(value: ExtensionId) -> Self {
        value.0
    }
}

fn valid_identifier_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// Closed v1 extension roles.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    /// Discovers or reads a governed source.
    SourceConnector,
    /// Converts source content into immutable atoms.
    Atomizer,
    /// Produces authorized retrieval candidates.
    Retriever,
    /// Produces one bounded ranking feature.
    RankingFeature,
    /// Produces an evidence-carrying representation transform.
    Transform,
    /// Verifies a summary against declared evidence.
    SummaryVerifier,
    /// Counts or encodes tokens under one fingerprint.
    Tokenizer,
    /// Renders a semantic bundle for a consumer.
    Materializer,
    /// Supplies a policy decision through the trusted policy boundary.
    PolicyProvider,
    /// Implements a storage backend behind trusted repository traits.
    StorageBackend,
    /// Performs one authorized effect connector operation.
    EffectConnector,
    /// Reconciles an ambiguous external effect.
    Reconciler,
}

/// Closed v1 extension execution environments.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRuntimeKind {
    /// Trusted extension linked into the host process.
    BuiltIn,
    /// Third-party WASI Preview 2 component.
    WasiPreview2,
    /// Third-party native executable in an operating-system sandbox.
    IsolatedSubprocess,
    /// Shared-profile remote gRPC implementation.
    RemoteGrpc,
}

/// Whether an extension promises deterministic semantic output.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionDeterminism {
    /// Identical declared inputs and host transcript produce identical semantic output.
    Deterministic,
    /// Output must be captured as an explicit observation.
    Nondeterministic,
}

/// Unambiguous integer semantic version used by extension compatibility ranges.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct ExtensionSemanticVersion {
    /// Semantic major version.
    pub major: u16,
    /// Semantic minor version.
    pub minor: u16,
    /// Semantic patch version.
    pub patch: u16,
}

impl ExtensionSemanticVersion {
    /// Creates one integer semantic version.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    const fn is_zero(self) -> bool {
        self.major == 0 && self.minor == 0 && self.patch == 0
    }
}

/// Inclusive protocol-ABI versions supported by an extension.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAbiVersionRange {
    /// Oldest supported ABI version.
    pub minimum: ExtensionSemanticVersion,
    /// Newest supported ABI version.
    pub maximum: ExtensionSemanticVersion,
}

impl ExtensionAbiVersionRange {
    fn validate_into(&self, errors: &mut ValidationErrors) {
        validate_version_range(self.minimum, self.maximum, "/protocol_abi", errors);
    }
}

/// Inclusive CIGAR application versions compatible with an extension.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CigarVersionRange {
    /// Oldest compatible CIGAR version.
    pub minimum: ExtensionSemanticVersion,
    /// Newest compatible CIGAR version.
    pub maximum: ExtensionSemanticVersion,
}

impl CigarVersionRange {
    fn validate_into(&self, errors: &mut ValidationErrors) {
        validate_version_range(
            self.minimum,
            self.maximum,
            "/compatible_cigar_versions",
            errors,
        );
    }
}

fn validate_version_range(
    minimum: ExtensionSemanticVersion,
    maximum: ExtensionSemanticVersion,
    path: &str,
    errors: &mut ValidationErrors,
) {
    if minimum.major == 0 || maximum.major == 0 || minimum > maximum {
        errors.push(issue(
            ValidationCode::InvalidValue,
            path,
            "version range must be ordered and use positive major versions",
        ));
    }
}

/// Opaque normalized package-relative path with no traversal or platform ambiguity.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SandboxPath(String);

impl SandboxPath {
    /// Creates an ASCII slash-separated path without empty, dot, or parent segments.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_EXTENSION_SANDBOX_PATH_BYTES
            && !value.starts_with('/')
            && !value.ends_with('/')
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.len() <= 255
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(single_issue(
                ValidationCode::InvalidValue,
                "/sandbox_path",
                "sandbox path must be normalized, relative, and traversal-free",
            ))
        }
    }

    /// Returns the normalized path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl JsonSchema for SandboxPath {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "SandboxPath".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_EXTENSION_SANDBOX_PATH_BYTES,
            "pattern": "^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
        })
    }
}

impl fmt::Debug for SandboxPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxPath")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl TryFrom<String> for SandboxPath {
    type Error = ValidationErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SandboxPath> for String {
    fn from(value: SandboxPath) -> Self {
        value.0
    }
}

/// Filesystem authority requested for one sandbox preopen.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SandboxAccess {
    /// Read-only package or operator-provided directory.
    ReadOnly,
    /// Explicit read/write directory.
    ReadWrite,
}

/// One normalized logical filesystem preopen.
#[derive(Clone, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPreopen {
    /// Guest-visible normalized relative path.
    pub path: SandboxPath,
    /// Maximum requested access.
    pub access: SandboxAccess,
}

impl fmt::Debug for SandboxPreopen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxPreopen")
            .field("path_bytes", &self.path.as_str().len())
            .field("access", &self.access)
            .finish()
    }
}

/// Network protocol permitted for a brokered endpoint.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTransport {
    /// HTTPS with authenticated TLS.
    Https,
    /// gRPC over authenticated TLS.
    GrpcTls,
    /// Other application protocol over authenticated TLS.
    TlsTcp,
}

/// Canonical lowercase DNS name or canonical textual IP address.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct NetworkHost(String);

impl NetworkHost {
    /// Creates a canonical exact host without URI syntax, wildcards, or a trailing dot.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        let canonical_ip = value
            .parse::<IpAddr>()
            .is_ok_and(|address| address.to_string() == value);
        let canonical_dns = !value.is_empty()
            && value.len() <= MAX_EXTENSION_ENDPOINT_HOST_BYTES
            && value.bytes().any(|byte| byte.is_ascii_lowercase())
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
            && value.split('.').all(valid_dns_label);
        if canonical_ip || canonical_dns {
            Ok(Self(value))
        } else {
            Err(single_issue(
                ValidationCode::InvalidValue,
                "/network_endpoint/host",
                "network host must be a canonical IP address or lowercase DNS name",
            ))
        }
    }

    /// Returns the canonical host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl JsonSchema for NetworkHost {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "NetworkHost".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_EXTENSION_ENDPOINT_HOST_BYTES,
            "description": "Canonical lowercase DNS name or canonical textual IP address; URI syntax and wildcards are forbidden."
        })
    }
}

impl fmt::Debug for NetworkHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkHost")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl TryFrom<String> for NetworkHost {
    type Error = ValidationErrors;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<NetworkHost> for String {
    fn from(value: NetworkHost) -> Self {
        value.0
    }
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// One exact brokered network allowlist entry.
#[derive(Clone, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    /// Authenticated transport.
    pub transport: NetworkTransport,
    /// Exact canonical destination host.
    pub host: NetworkHost,
    /// Nonzero destination port.
    pub port: u16,
}

impl NetworkEndpoint {
    /// Creates one normalized endpoint.
    pub fn new(
        transport: NetworkTransport,
        host: NetworkHost,
        port: u16,
    ) -> Result<Self, ValidationErrors> {
        if port == 0 {
            return Err(single_issue(
                ValidationCode::InvalidValue,
                "/network_endpoint/port",
                "network endpoint port must be nonzero",
            ));
        }
        Ok(Self {
            transport,
            host,
            port,
        })
    }
}

impl fmt::Debug for NetworkEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkEndpoint")
            .field("transport", &self.transport)
            .field("host_bytes", &self.host.as_str().len())
            .field("port", &self.port)
            .finish()
    }
}

/// Closed host authorities that an extension may request.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionHostCapability {
    /// Read content through an opaque source handle.
    SourceRead,
    /// Read content through an opaque blob handle.
    BlobRead,
    /// Advance a bounded host-owned iterator.
    BoundedIterator,
    /// Read an invocation-fixed deterministic clock.
    DeterministicClock,
    /// Read from an invocation-fixed deterministic random stream.
    DeterministicRandom,
    /// Emit bounded structured trace events.
    StructuredTracing,
    /// Observe invocation cancellation.
    Cancellation,
    /// Request brokered network I/O to an allowlisted endpoint.
    Network,
    /// Read through a declared filesystem preopen.
    FilesystemRead,
    /// Write through a declared filesystem preopen.
    FilesystemWrite,
    /// Forward an opaque secret handle to a final host-owned boundary.
    SecretHandle,
}

/// Backend-specific compute ceiling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionComputeBudget {
    /// Deterministic WASM fuel units.
    Fuel {
        /// Nonzero fuel ceiling.
        units: u64,
    },
    /// Native or remote CPU-time ceiling.
    CpuTime {
        /// Nonzero CPU duration.
        duration: DurationNanos,
    },
}

/// Complete bounded resource profile for one extension invocation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionLimits {
    /// Maximum guest memory bytes.
    pub max_memory_bytes: u64,
    /// Fuel or CPU-time ceiling.
    pub compute: ExtensionComputeBudget,
    /// Maximum elapsed wall time.
    pub wall_deadline: DurationNanos,
    /// Maximum exact input bytes.
    pub max_input_bytes: u64,
    /// Maximum exact output bytes.
    pub max_output_bytes: u64,
    /// Maximum simultaneous invocations.
    pub max_concurrency: u16,
    /// Maximum guest recursion depth.
    pub max_recursion_depth: u16,
    /// Maximum brokered calls during one invocation.
    pub max_host_calls: u32,
}

impl Validate for ExtensionLimits {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        self.validate_into(&mut errors);
        errors.into_result()
    }
}

impl ExtensionLimits {
    fn validate_into(&self, errors: &mut ValidationErrors) {
        if self.max_memory_bytes == 0 || self.max_memory_bytes > MAX_EXTENSION_MEMORY_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/max_memory_bytes",
                "extension memory limit must be nonzero and within the host maximum",
            ));
        }
        match self.compute {
            ExtensionComputeBudget::Fuel { units } if units == 0 || units > MAX_EXTENSION_FUEL => {
                errors.push(issue(
                    ValidationCode::LimitExceeded,
                    "/limits/compute/units",
                    "extension fuel limit must be nonzero and bounded",
                ));
            }
            ExtensionComputeBudget::CpuTime { duration }
                if duration.get() == 0 || duration.get() > MAX_EXTENSION_RUNTIME_NANOS =>
            {
                errors.push(issue(
                    ValidationCode::LimitExceeded,
                    "/limits/compute/duration",
                    "extension CPU-time limit must be nonzero and bounded",
                ));
            }
            ExtensionComputeBudget::Fuel { .. } | ExtensionComputeBudget::CpuTime { .. } => {}
        }
        if self.wall_deadline.get() == 0 || self.wall_deadline.get() > MAX_EXTENSION_RUNTIME_NANOS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/wall_deadline",
                "extension wall deadline must be nonzero and bounded",
            ));
        }
        let maximum_io = u64::try_from(MAX_EXTENSION_IO_BYTES).unwrap_or(u64::MAX);
        if self.max_input_bytes == 0 || self.max_input_bytes > maximum_io {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/max_input_bytes",
                "extension input limit must be nonzero and bounded",
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > maximum_io {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/max_output_bytes",
                "extension output limit must be nonzero and bounded",
            ));
        }
        if self.max_concurrency == 0 || self.max_concurrency > MAX_EXTENSION_CONCURRENCY {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/max_concurrency",
                "extension concurrency limit must be nonzero and bounded",
            ));
        }
        if self.max_recursion_depth == 0 || self.max_recursion_depth > MAX_EXTENSION_RECURSION_DEPTH
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/max_recursion_depth",
                "extension recursion limit must be nonzero and bounded",
            ));
        }
        if self.max_host_calls == 0 || self.max_host_calls > MAX_EXTENSION_HOST_CALLS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/limits/max_host_calls",
                "extension host-call limit must be nonzero and bounded",
            ));
        }
    }
}

/// Per-kind exact input and output schema bindings.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionSchemaBinding {
    /// Extension role whose wire schemas are bound.
    pub kind: ExtensionKind,
    /// Exact input schema digest.
    pub input_schema_digest: ContentDigest,
    /// Exact output schema digest.
    pub output_schema_digest: ContentDigest,
}

/// Signed extension package declaration. Cryptographic verification is a host responsibility.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionManifestV1 {
    /// Must be `cigar.extension-manifest.v1`.
    pub schema_version: SchemaVersion,
    /// Stable normalized extension identity.
    pub extension_id: ExtensionId,
    /// Declared extension package version.
    pub extension_version: ExtensionSemanticVersion,
    /// Execution environment required by this package.
    pub runtime: ExtensionRuntimeKind,
    /// Inclusive logical ABI compatibility range.
    pub protocol_abi: ExtensionAbiVersionRange,
    /// Digest of exact executable or component bytes.
    pub implementation_digest: ContentDigest,
    /// Digest of the exact containing package.
    pub package_digest: ContentDigest,
    /// Trusted publisher key selector.
    pub publisher_key_id: ExtensionId,
    /// Ed25519 public key asserted by the publisher.
    #[schemars(with = "String")]
    #[schemars(length(min = ED25519_PUBLIC_KEY_BASE64URL_BYTES, max = ED25519_PUBLIC_KEY_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub publisher_public_key: Vec<u8>,
    /// Ed25519 signature over the signature-excluded canonical manifest envelope.
    #[schemars(with = "String")]
    #[schemars(length(min = ED25519_SIGNATURE_BASE64URL_BYTES, max = ED25519_SIGNATURE_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub signature: Vec<u8>,
    /// Package-relative executable, component, export, or remote method selector.
    pub entry_point: SandboxPath,
    /// Sorted unique implemented extension roles.
    #[schemars(length(min = 1, max = MAX_EXTENSION_KINDS))]
    pub kinds: Vec<ExtensionKind>,
    /// Sorted one-to-one schema binding for every declared role.
    #[schemars(length(min = 1, max = MAX_EXTENSION_KINDS))]
    pub schema_bindings: Vec<ExtensionSchemaBinding>,
    /// Sorted unique source classifications this implementation can receive.
    #[schemars(length(max = 4))]
    pub source_classifications: Vec<Classification>,
    /// Sorted unique processor identities this implementation declares.
    #[schemars(length(max = MAX_EXTENSION_PROCESSORS), inner(length(min = 1, max = MAX_EXTENSION_HOST_SELECTOR_BYTES)))]
    pub processors: Vec<String>,
    /// Deterministic-output promise.
    pub determinism: ExtensionDeterminism,
    /// Sorted unique broker capabilities requested before activation.
    #[schemars(length(max = 32))]
    pub required_host_capabilities: Vec<ExtensionHostCapability>,
    /// Sorted unique exact brokered network endpoints.
    #[schemars(length(max = MAX_EXTENSION_NETWORK_ENDPOINTS))]
    pub network_allowlist: Vec<NetworkEndpoint>,
    /// Sorted unique logical filesystem preopens.
    #[schemars(length(max = MAX_EXTENSION_PREOPENS))]
    pub filesystem_preopens: Vec<SandboxPreopen>,
    /// Requested hard resource ceilings.
    pub limits: ExtensionLimits,
    /// Inclusive compatible CIGAR versions.
    pub compatible_cigar_versions: CigarVersionRange,
}

impl fmt::Debug for ExtensionManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionManifestV1")
            .field("schema_version", &self.schema_version)
            .field("extension_id", &self.extension_id)
            .field("extension_version", &self.extension_version)
            .field("runtime", &self.runtime)
            .field("protocol_abi", &self.protocol_abi)
            .field("implementation_digest", &self.implementation_digest)
            .field("package_digest", &self.package_digest)
            .field("publisher_key_id", &self.publisher_key_id)
            .field(
                "publisher_public_key_bytes",
                &self.publisher_public_key.len(),
            )
            .field("signature_bytes", &self.signature.len())
            .field("entry_point_bytes", &self.entry_point.as_str().len())
            .field("kind_count", &self.kinds.len())
            .field("schema_binding_count", &self.schema_bindings.len())
            .field("classification_count", &self.source_classifications.len())
            .field("processor_count", &self.processors.len())
            .field("determinism", &self.determinism)
            .field("capability_count", &self.required_host_capabilities.len())
            .field("network_endpoint_count", &self.network_allowlist.len())
            .field("preopen_count", &self.filesystem_preopens.len())
            .field("limits", &self.limits)
            .field("compatible_cigar_versions", &self.compatible_cigar_versions)
            .finish_non_exhaustive()
    }
}

impl Validate for ExtensionManifestV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.extension-manifest",
            &mut errors,
        );
        self.protocol_abi.validate_into(&mut errors);
        self.compatible_cigar_versions.validate_into(&mut errors);
        self.limits.validate_into(&mut errors);
        if self.extension_version.is_zero() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/extension_version",
                "extension version cannot be 0.0.0",
            ));
        }
        if self.publisher_public_key.len() != EXTENSION_PUBLISHER_KEY_BYTES {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/publisher_public_key",
                "publisher public key must contain exactly 32 bytes",
            ));
        }
        if self.signature.len() != EXTENSION_SIGNATURE_BYTES {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/signature",
                "extension signature must contain exactly 64 bytes",
            ));
        }
        if self.kinds.is_empty()
            || self.kinds.len() > MAX_EXTENSION_KINDS
            || !strictly_sorted_unique(&self.kinds)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/kinds",
                "extension kinds must be non-empty, bounded, sorted, and unique",
            ));
        }
        let binding_kinds: Vec<_> = self
            .schema_bindings
            .iter()
            .map(|value| value.kind)
            .collect();
        if self.schema_bindings.len() > MAX_EXTENSION_KINDS
            || !strictly_sorted_unique(&self.schema_bindings)
            || binding_kinds != self.kinds
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/schema_bindings",
                "schema bindings must be sorted and bind every declared kind exactly once",
            ));
        }
        if self.source_classifications.len() > 4
            || !strictly_sorted_unique(&self.source_classifications)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/source_classifications",
                "source classifications must be bounded, sorted, and unique",
            ));
        }
        if self.processors.len() > MAX_EXTENSION_PROCESSORS
            || !strictly_sorted_unique(&self.processors)
            || self.processors.iter().any(|value| !valid_selector(value))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/processors",
                "processor identities must be bounded, normalized, sorted, and unique",
            ));
        }
        if self.required_host_capabilities.len() > 32
            || !strictly_sorted_unique(&self.required_host_capabilities)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/required_host_capabilities",
                "host capabilities must be bounded, sorted, and unique",
            ));
        }
        self.validate_network(&mut errors);
        self.validate_preopens(&mut errors);
        errors.into_result()
    }
}

impl ExtensionManifestV1 {
    fn validate_network(&self, errors: &mut ValidationErrors) {
        if self.network_allowlist.len() > MAX_EXTENSION_NETWORK_ENDPOINTS
            || !strictly_sorted_unique(&self.network_allowlist)
            || self.network_allowlist.iter().any(|value| value.port == 0)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/network_allowlist",
                "network endpoints must be bounded, normalized, sorted, unique, and nonzero-port",
            ));
        }
        if !self.network_allowlist.is_empty()
            && self
                .required_host_capabilities
                .binary_search(&ExtensionHostCapability::Network)
                .is_err()
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/network_allowlist",
                "network endpoints require the brokered network capability",
            ));
        }
    }

    fn validate_preopens(&self, errors: &mut ValidationErrors) {
        let paths: Vec<_> = self
            .filesystem_preopens
            .iter()
            .map(|value| &value.path)
            .collect();
        if self.filesystem_preopens.len() > MAX_EXTENSION_PREOPENS
            || !strictly_sorted_unique(&self.filesystem_preopens)
            || !strictly_sorted_unique(&paths)
            || (self.runtime == ExtensionRuntimeKind::RemoteGrpc
                && !self.filesystem_preopens.is_empty())
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/filesystem_preopens",
                "preopens must be bounded, path-unique, sorted, and unavailable to remote extensions",
            ));
        }
        let has_read = self
            .required_host_capabilities
            .binary_search(&ExtensionHostCapability::FilesystemRead)
            .is_ok();
        let has_write = self
            .required_host_capabilities
            .binary_search(&ExtensionHostCapability::FilesystemWrite)
            .is_ok();
        if self
            .filesystem_preopens
            .iter()
            .any(|value| !has_read || (value.access == SandboxAccess::ReadWrite && !has_write))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/filesystem_preopens",
                "preopen access exceeds declared filesystem capabilities",
            ));
        }
    }
}

/// Opaque unguessable handle whose authority exists only in the trusted broker.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtensionHandle([u8; EXTENSION_HANDLE_BYTES]);

impl ExtensionHandle {
    /// Creates one exact 256-bit opaque handle.
    #[must_use]
    pub const fn new(bytes: [u8; EXTENSION_HANDLE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns opaque bytes for an IPC encoder, never for formatting.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EXTENSION_HANDLE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ExtensionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExtensionHandle([REDACTED])")
    }
}

impl Serialize for ExtensionHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        base64url::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for ExtensionHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = base64url::deserialize(deserializer)?;
        let bytes: [u8; EXTENSION_HANDLE_BYTES] = bytes
            .try_into()
            .map_err(|_error| serde::de::Error::custom("extension handle must contain 32 bytes"))?;
        Ok(Self(bytes))
    }
}

impl JsonSchema for ExtensionHandle {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "ExtensionHandle".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": EXTENSION_HANDLE_BASE64URL_BYTES,
            "maxLength": EXTENSION_HANDLE_BASE64URL_BYTES,
            "contentEncoding": "base64url"
        })
    }
}

/// Exact invocation delivered to one activated extension.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionInvocationV1 {
    /// Must be `cigar.extension-invocation.v1`.
    pub schema_version: SchemaVersion,
    /// Unique invocation identity.
    pub invocation_id: RecordId,
    /// Activated extension identity.
    pub extension_id: ExtensionId,
    /// Activated extension version.
    pub extension_version: ExtensionSemanticVersion,
    /// Exact activated signature-excluded manifest digest.
    pub manifest_digest: ContentDigest,
    /// Role invoked for this request.
    pub kind: ExtensionKind,
    /// Normalized operation selector.
    #[schemars(length(min = 1, max = MAX_EXTENSION_HOST_SELECTOR_BYTES))]
    pub operation: String,
    /// Exact input schema digest.
    pub input_schema_digest: ContentDigest,
    /// Digest of exact input bytes.
    pub input_digest: ContentDigest,
    /// Exact protected input bytes.
    #[schemars(with = "String")]
    #[schemars(length(max = MAX_EXTENSION_IO_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub input: Vec<u8>,
    /// Sorted effective broker capabilities for this invocation.
    #[schemars(length(max = 32))]
    pub authorized_capabilities: Vec<ExtensionHostCapability>,
    /// Sorted opaque handles scoped to this invocation.
    #[schemars(length(max = MAX_EXTENSION_HANDLES))]
    pub handles: Vec<ExtensionHandle>,
    /// Invocation-fixed clock, present exactly when clock capability is granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deterministic_clock: Option<UtcTimestamp>,
    /// Invocation-fixed seed, empty exactly when random capability is absent.
    #[schemars(with = "String")]
    #[schemars(length(max = MAX_EXTENSION_RANDOM_SEED_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub deterministic_random_seed: Vec<u8>,
    /// Effective hard limits after intersecting manifest and operator ceilings.
    pub effective_limits: ExtensionLimits,
    /// Invocation issuance time.
    pub issued_at: UtcTimestamp,
    /// Exclusive invocation wall deadline.
    pub deadline_at: UtcTimestamp,
}

impl fmt::Debug for ExtensionInvocationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionInvocationV1")
            .field("schema_version", &self.schema_version)
            .field("invocation_id", &self.invocation_id)
            .field("extension_id", &self.extension_id)
            .field("extension_version", &self.extension_version)
            .field("manifest_digest", &self.manifest_digest)
            .field("kind", &self.kind)
            .field("operation_bytes", &self.operation.len())
            .field("input_schema_digest", &self.input_schema_digest)
            .field("input_digest", &self.input_digest)
            .field("input_bytes", &self.input.len())
            .field("capability_count", &self.authorized_capabilities.len())
            .field("handle_count", &self.handles.len())
            .field(
                "has_deterministic_clock",
                &self.deterministic_clock.is_some(),
            )
            .field(
                "deterministic_random_seed_bytes",
                &self.deterministic_random_seed.len(),
            )
            .field("effective_limits", &self.effective_limits)
            .field("issued_at", &self.issued_at)
            .field("deadline_at", &self.deadline_at)
            .finish_non_exhaustive()
    }
}

impl Validate for ExtensionInvocationV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.extension-invocation",
            &mut errors,
        );
        self.effective_limits.validate_into(&mut errors);
        if self.extension_version.is_zero() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/extension_version",
                "extension version cannot be 0.0.0",
            ));
        }
        if !valid_selector(&self.operation) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/operation",
                "extension operation must be non-empty, bounded, and control-free",
            ));
        }
        if self.input.len() > MAX_EXTENSION_IO_BYTES
            || u64::try_from(self.input.len()).map_or(true, |length| {
                length > self.effective_limits.max_input_bytes
            })
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/input",
                "extension input exceeds the effective input limit",
            ));
        }
        if self.authorized_capabilities.len() > 32
            || !strictly_sorted_unique(&self.authorized_capabilities)
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/authorized_capabilities",
                "authorized capabilities must be bounded, sorted, and unique",
            ));
        }
        if self.handles.len() > MAX_EXTENSION_HANDLES || !strictly_sorted_unique(&self.handles) {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/handles",
                "extension handles must be bounded, sorted, and unique",
            ));
        }
        let has_clock = self
            .authorized_capabilities
            .binary_search(&ExtensionHostCapability::DeterministicClock)
            .is_ok();
        let has_random = self
            .authorized_capabilities
            .binary_search(&ExtensionHostCapability::DeterministicRandom)
            .is_ok();
        if has_clock != self.deterministic_clock.is_some() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/deterministic_clock",
                "deterministic clock value and capability must be present together",
            ));
        }
        if self.deterministic_random_seed.len() > MAX_EXTENSION_RANDOM_SEED_BYTES
            || has_random == self.deterministic_random_seed.is_empty()
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/deterministic_random_seed",
                "deterministic random seed must be bounded and capability-bound",
            ));
        }
        validate_deadline(
            self.issued_at,
            self.deadline_at,
            self.effective_limits.wall_deadline,
            "/deadline_at",
            &mut errors,
        );
        errors.into_result()
    }
}

/// Closed terminal extension outcomes.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionResponseOutcome {
    /// Extension returned a valid semantic output.
    Succeeded,
    /// Extension rejected the declared operation without executing it.
    Rejected,
    /// Extension failed or crashed before producing a valid output.
    Failed,
    /// Invocation observed cancellation.
    Cancelled,
}

/// Terminal extension response with protected bytes and no free-form error reflection.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionResponseV1 {
    /// Must be `cigar.extension-response.v1`.
    pub schema_version: SchemaVersion,
    /// Source invocation identity.
    pub invocation_id: RecordId,
    /// Terminal outcome.
    pub outcome: ExtensionResponseOutcome,
    /// Output schema for a successful response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_digest: Option<ContentDigest>,
    /// Digest of exact successful output bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<ContentDigest>,
    /// Exact protected successful output bytes.
    #[schemars(with = "String")]
    #[schemars(length(max = MAX_EXTENSION_IO_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub output: Vec<u8>,
    /// Number of completed broker calls.
    pub host_call_count: u32,
    /// Response completion time.
    pub completed_at: UtcTimestamp,
}

impl fmt::Debug for ExtensionResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionResponseV1")
            .field("schema_version", &self.schema_version)
            .field("invocation_id", &self.invocation_id)
            .field("outcome", &self.outcome)
            .field("output_schema_digest", &self.output_schema_digest)
            .field("output_digest", &self.output_digest)
            .field("output_bytes", &self.output.len())
            .field("host_call_count", &self.host_call_count)
            .field("completed_at", &self.completed_at)
            .finish_non_exhaustive()
    }
}

impl Validate for ExtensionResponseV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.extension-response",
            &mut errors,
        );
        let succeeded = self.outcome == ExtensionResponseOutcome::Succeeded;
        if succeeded != (self.output_schema_digest.is_some() && self.output_digest.is_some())
            || (!succeeded
                && (!self.output.is_empty()
                    || self.output_schema_digest.is_some()
                    || self.output_digest.is_some()))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/output",
                "only a successful response may carry output and must bind both output digests",
            ));
        }
        if self.output.len() > MAX_EXTENSION_IO_BYTES {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/output",
                "extension response exceeds the protocol output maximum",
            ));
        }
        if self.host_call_count > MAX_EXTENSION_HOST_CALLS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/host_call_count",
                "extension host-call count exceeds the protocol maximum",
            ));
        }
        errors.into_result()
    }
}

/// Closed broker call categories.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionHostCallKind {
    /// Read bytes from a source handle.
    ReadSource,
    /// Read bytes from a blob handle.
    ReadBlob,
    /// Advance a bounded iterator handle.
    IteratorNext,
    /// Read the deterministic clock.
    ClockNow,
    /// Read deterministic random bytes.
    RandomFill,
    /// Emit one structured trace record.
    Trace,
    /// Check whether the invocation was cancelled.
    CheckCancelled,
    /// Perform one brokered allowlisted network request.
    NetworkRequest,
    /// Read through a filesystem preopen handle.
    FileRead,
    /// Write through a filesystem preopen handle.
    FileWrite,
    /// Forward a secret handle at a final host-owned boundary.
    ResolveSecret,
}

impl ExtensionHostCallKind {
    /// Returns the exact capability required for this call.
    #[must_use]
    pub const fn required_capability(self) -> ExtensionHostCapability {
        match self {
            Self::ReadSource => ExtensionHostCapability::SourceRead,
            Self::ReadBlob => ExtensionHostCapability::BlobRead,
            Self::IteratorNext => ExtensionHostCapability::BoundedIterator,
            Self::ClockNow => ExtensionHostCapability::DeterministicClock,
            Self::RandomFill => ExtensionHostCapability::DeterministicRandom,
            Self::Trace => ExtensionHostCapability::StructuredTracing,
            Self::CheckCancelled => ExtensionHostCapability::Cancellation,
            Self::NetworkRequest => ExtensionHostCapability::Network,
            Self::FileRead => ExtensionHostCapability::FilesystemRead,
            Self::FileWrite => ExtensionHostCapability::FilesystemWrite,
            Self::ResolveSecret => ExtensionHostCapability::SecretHandle,
        }
    }

    const fn requires_handle(self) -> bool {
        matches!(
            self,
            Self::ReadSource
                | Self::ReadBlob
                | Self::IteratorNext
                | Self::NetworkRequest
                | Self::FileRead
                | Self::FileWrite
                | Self::ResolveSecret
        )
    }
}

/// Completed request/response transcript for one brokered host call.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionHostCallV1 {
    /// Must be `cigar.extension-host-call.v1`.
    pub schema_version: SchemaVersion,
    /// Unique host-call identity.
    pub call_id: RecordId,
    /// Owning invocation identity.
    pub invocation_id: RecordId,
    /// Contiguous one-based call ordinal.
    pub ordinal: u32,
    /// Closed call operation.
    pub kind: ExtensionHostCallKind,
    /// Capability presented for this call.
    pub capability: ExtensionHostCapability,
    /// Exact scoped handle for handle-requiring calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<ExtensionHandle>,
    /// Digest of exact protected request bytes.
    pub request_digest: ContentDigest,
    /// Exact protected request bytes.
    #[schemars(with = "String")]
    #[schemars(length(max = MAX_EXTENSION_IO_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub request: Vec<u8>,
    /// Digest of exact protected response bytes.
    pub response_digest: ContentDigest,
    /// Exact protected response bytes.
    #[schemars(with = "String")]
    #[schemars(length(max = MAX_EXTENSION_IO_BASE64URL_BYTES))]
    #[serde(with = "base64url")]
    pub response: Vec<u8>,
    /// Call start time.
    pub started_at: UtcTimestamp,
    /// Call completion time.
    pub completed_at: UtcTimestamp,
}

impl fmt::Debug for ExtensionHostCallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionHostCallV1")
            .field("schema_version", &self.schema_version)
            .field("call_id", &self.call_id)
            .field("invocation_id", &self.invocation_id)
            .field("ordinal", &self.ordinal)
            .field("kind", &self.kind)
            .field("capability", &self.capability)
            .field("has_handle", &self.handle.is_some())
            .field("request_digest", &self.request_digest)
            .field("request_bytes", &self.request.len())
            .field("response_digest", &self.response_digest)
            .field("response_bytes", &self.response.len())
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .finish_non_exhaustive()
    }
}

impl Validate for ExtensionHostCallV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.extension-host-call",
            &mut errors,
        );
        if self.call_id == self.invocation_id {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/call_id",
                "host-call and invocation identities must be distinct",
            ));
        }
        if self.ordinal == 0 || self.ordinal > MAX_EXTENSION_HOST_CALLS {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/ordinal",
                "host-call ordinal must be nonzero and bounded",
            ));
        }
        if self.capability != self.kind.required_capability() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/capability",
                "host-call capability does not match the closed operation",
            ));
        }
        if self.kind.requires_handle() != self.handle.is_some() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/handle",
                "host-call handle presence does not match the closed operation",
            ));
        }
        if self.request.len() > MAX_EXTENSION_IO_BYTES
            || self.response.len() > MAX_EXTENSION_IO_BYTES
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/request",
                "host-call request or response exceeds the protocol maximum",
            ));
        }
        if self.completed_at < self.started_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/completed_at",
                "host-call completion cannot precede its start",
            ));
        }
        errors.into_result()
    }
}

/// Closed reasons for cancelling one extension invocation.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCancelReason {
    /// Authenticated caller cancelled the operation.
    Caller,
    /// Effective wall deadline elapsed.
    Deadline,
    /// Host is shutting down.
    Shutdown,
    /// A hard resource ceiling was exceeded.
    ResourceLimit,
}

/// Idempotent cancellation message for one extension invocation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCancelV1 {
    /// Must be `cigar.extension-cancel.v1`.
    pub schema_version: SchemaVersion,
    /// Unique cancellation record identity.
    pub cancel_id: RecordId,
    /// Invocation being cancelled.
    pub invocation_id: RecordId,
    /// Safe closed cancellation reason.
    pub reason: ExtensionCancelReason,
    /// Cancellation request time.
    pub requested_at: UtcTimestamp,
}

impl Validate for ExtensionCancelV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(&self.schema_version, "cigar.extension-cancel", &mut errors);
        if self.cancel_id == self.invocation_id {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/cancel_id",
                "cancellation and invocation identities must be distinct",
            ));
        }
        errors.into_result()
    }
}

/// Replay dependency emitted for an extension invocation, especially nondeterministic output.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionObservationV1 {
    /// Must be `cigar.extension-observation.v1`.
    pub schema_version: SchemaVersion,
    /// Unique observation identity.
    pub observation_id: RecordId,
    /// Observed invocation identity.
    pub invocation_id: RecordId,
    /// Activated extension identity.
    pub extension_id: ExtensionId,
    /// Activated extension version.
    pub extension_version: ExtensionSemanticVersion,
    /// Exact activated manifest digest.
    pub manifest_digest: ContentDigest,
    /// Exact implementation digest.
    pub implementation_digest: ContentDigest,
    /// Exact containing package digest.
    pub package_digest: ContentDigest,
    /// Extension role invoked.
    pub kind: ExtensionKind,
    /// Declared determinism class.
    pub determinism: ExtensionDeterminism,
    /// Exact input digest.
    pub input_digest: ContentDigest,
    /// Exact effective execution limits.
    pub effective_limits: ExtensionLimits,
    /// Digest of the ordered completed host-call transcript.
    pub host_call_transcript_digest: ContentDigest,
    /// Number of calls in that transcript.
    pub host_call_count: u32,
    /// Terminal outcome.
    pub outcome: ExtensionResponseOutcome,
    /// Successful output schema digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_digest: Option<ContentDigest>,
    /// Successful output digest retained as a replay dependency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<ContentDigest>,
    /// Invocation start time.
    pub started_at: UtcTimestamp,
    /// Invocation completion time.
    pub completed_at: UtcTimestamp,
}

impl fmt::Debug for ExtensionObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionObservationV1")
            .field("schema_version", &self.schema_version)
            .field("observation_id", &self.observation_id)
            .field("invocation_id", &self.invocation_id)
            .field("extension_id", &self.extension_id)
            .field("extension_version", &self.extension_version)
            .field("manifest_digest", &self.manifest_digest)
            .field("implementation_digest", &self.implementation_digest)
            .field("package_digest", &self.package_digest)
            .field("kind", &self.kind)
            .field("determinism", &self.determinism)
            .field("input_digest", &self.input_digest)
            .field("effective_limits", &self.effective_limits)
            .field(
                "host_call_transcript_digest",
                &self.host_call_transcript_digest,
            )
            .field("host_call_count", &self.host_call_count)
            .field("outcome", &self.outcome)
            .field("output_schema_digest", &self.output_schema_digest)
            .field("output_digest", &self.output_digest)
            .field("started_at", &self.started_at)
            .field("completed_at", &self.completed_at)
            .finish_non_exhaustive()
    }
}

impl Validate for ExtensionObservationV1 {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        validate_version(
            &self.schema_version,
            "cigar.extension-observation",
            &mut errors,
        );
        self.effective_limits.validate_into(&mut errors);
        if self.observation_id == self.invocation_id {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/observation_id",
                "observation and invocation identities must be distinct",
            ));
        }
        if self.extension_version.is_zero() {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/extension_version",
                "extension version cannot be 0.0.0",
            ));
        }
        if self.host_call_count > self.effective_limits.max_host_calls
            || self.host_call_count > MAX_EXTENSION_HOST_CALLS
        {
            errors.push(issue(
                ValidationCode::LimitExceeded,
                "/host_call_count",
                "observed host-call count exceeds the effective limit",
            ));
        }
        let succeeded = self.outcome == ExtensionResponseOutcome::Succeeded;
        if succeeded != (self.output_schema_digest.is_some() && self.output_digest.is_some())
            || (!succeeded && (self.output_schema_digest.is_some() || self.output_digest.is_some()))
        {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/output_digest",
                "only successful observations carry both output digests",
            ));
        }
        if self.completed_at < self.started_at {
            errors.push(issue(
                ValidationCode::InvalidValue,
                "/completed_at",
                "extension observation completion cannot precede its start",
            ));
        }
        errors.into_result()
    }
}

fn validate_deadline(
    issued_at: UtcTimestamp,
    deadline_at: UtcTimestamp,
    maximum: DurationNanos,
    path: &str,
    errors: &mut ValidationErrors,
) {
    let elapsed = deadline_at
        .unix_nanos()
        .checked_sub(issued_at.unix_nanos())
        .and_then(|value| u64::try_from(value).ok());
    if elapsed.is_none_or(|value| value == 0 || value > maximum.get()) {
        errors.push(issue(
            ValidationCode::InvalidValue,
            path,
            "extension deadline must advance issuance and fit the effective wall limit",
        ));
    }
}

fn valid_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXTENSION_HOST_SELECTOR_BYTES
        && value == value.trim()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|window| match (window.first(), window.get(1)) {
            (Some(first), Some(second)) => first < second,
            _ => false,
        })
}

fn validate_version(version: &SchemaVersion, family: &str, errors: &mut ValidationErrors) {
    if let Err(found) = version.require_v1(family) {
        errors.merge(found);
    }
}

fn single_issue(code: ValidationCode, path: &str, message: &str) -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.push(issue(code, path, message));
    errors
}

#[cfg(test)]
mod tests {
    use super::{
        CigarVersionRange, ExtensionAbiVersionRange, ExtensionCancelReason, ExtensionCancelV1,
        ExtensionComputeBudget, ExtensionDeterminism, ExtensionHandle, ExtensionHostCallKind,
        ExtensionHostCallV1, ExtensionHostCapability, ExtensionId, ExtensionInvocationV1,
        ExtensionKind, ExtensionLimits, ExtensionManifestV1, ExtensionObservationV1,
        ExtensionResponseOutcome, ExtensionResponseV1, ExtensionRuntimeKind,
        ExtensionSchemaBinding, ExtensionSemanticVersion, NetworkEndpoint, NetworkHost,
        NetworkTransport, SandboxAccess, SandboxPath, SandboxPreopen,
    };
    use crate::{
        Classification, ContentDigest, DurationNanos, RecordId, SchemaVersion, UtcTimestamp,
        Validate,
    };

    fn digest(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn record(character: char) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f789{character}"
        ))?)
    }

    fn timestamp(second: u8) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
        Ok(UtcTimestamp::parse_rfc3339(&format!(
            "2026-07-11T12:00:{second:02}Z"
        ))?)
    }

    fn semantic_version() -> ExtensionSemanticVersion {
        ExtensionSemanticVersion::new(1, 2, 3)
    }

    fn limits() -> Result<ExtensionLimits, Box<dyn std::error::Error>> {
        Ok(ExtensionLimits {
            max_memory_bytes: 64 * 1_024 * 1_024,
            compute: ExtensionComputeBudget::Fuel { units: 1_000_000 },
            wall_deadline: DurationNanos::new(2_000_000_000)?,
            max_input_bytes: 4_096,
            max_output_bytes: 4_096,
            max_concurrency: 4,
            max_recursion_depth: 32,
            max_host_calls: 64,
        })
    }

    fn manifest() -> Result<ExtensionManifestV1, Box<dyn std::error::Error>> {
        let kinds = vec![ExtensionKind::SourceConnector, ExtensionKind::Transform];
        Ok(ExtensionManifestV1 {
            schema_version: SchemaVersion::new("cigar.extension-manifest", 1)?,
            extension_id: ExtensionId::new("dev.cigar.fixture")?,
            extension_version: semantic_version(),
            runtime: ExtensionRuntimeKind::WasiPreview2,
            protocol_abi: ExtensionAbiVersionRange {
                minimum: ExtensionSemanticVersion::new(1, 0, 0),
                maximum: ExtensionSemanticVersion::new(1, 1, 0),
            },
            implementation_digest: digest('1')?,
            package_digest: digest('2')?,
            publisher_key_id: ExtensionId::new("dev.cigar.publisher")?,
            publisher_public_key: vec![7; 32],
            signature: vec![8; 64],
            entry_point: SandboxPath::new("bin/extension.wasm")?,
            schema_bindings: vec![
                ExtensionSchemaBinding {
                    kind: ExtensionKind::SourceConnector,
                    input_schema_digest: digest('3')?,
                    output_schema_digest: digest('4')?,
                },
                ExtensionSchemaBinding {
                    kind: ExtensionKind::Transform,
                    input_schema_digest: digest('5')?,
                    output_schema_digest: digest('6')?,
                },
            ],
            kinds,
            source_classifications: vec![Classification::Public, Classification::Internal],
            processors: vec!["processor-a".to_owned(), "processor-b".to_owned()],
            determinism: ExtensionDeterminism::Deterministic,
            required_host_capabilities: vec![ExtensionHostCapability::Network],
            network_allowlist: vec![NetworkEndpoint::new(
                NetworkTransport::Https,
                NetworkHost::new("api.example.test")?,
                443,
            )?],
            filesystem_preopens: Vec::new(),
            limits: limits()?,
            compatible_cigar_versions: CigarVersionRange {
                minimum: ExtensionSemanticVersion::new(1, 0, 0),
                maximum: ExtensionSemanticVersion::new(1, 9, 0),
            },
        })
    }

    fn invocation() -> Result<ExtensionInvocationV1, Box<dyn std::error::Error>> {
        Ok(ExtensionInvocationV1 {
            schema_version: SchemaVersion::new("cigar.extension-invocation", 1)?,
            invocation_id: record('1')?,
            extension_id: ExtensionId::new("dev.cigar.fixture")?,
            extension_version: semantic_version(),
            manifest_digest: digest('7')?,
            kind: ExtensionKind::Transform,
            operation: "transform.summary".to_owned(),
            input_schema_digest: digest('8')?,
            input_digest: digest('9')?,
            input: b"protected-input-canary".to_vec(),
            authorized_capabilities: vec![
                ExtensionHostCapability::DeterministicClock,
                ExtensionHostCapability::DeterministicRandom,
            ],
            handles: vec![ExtensionHandle::new([1; 32]), ExtensionHandle::new([2; 32])],
            deterministic_clock: Some(timestamp(0)?),
            deterministic_random_seed: vec![3; 32],
            effective_limits: limits()?,
            issued_at: timestamp(0)?,
            deadline_at: timestamp(1)?,
        })
    }

    #[test]
    fn all_twelve_extension_kinds_have_frozen_wire_spellings()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (ExtensionKind::SourceConnector, "source_connector"),
            (ExtensionKind::Atomizer, "atomizer"),
            (ExtensionKind::Retriever, "retriever"),
            (ExtensionKind::RankingFeature, "ranking_feature"),
            (ExtensionKind::Transform, "transform"),
            (ExtensionKind::SummaryVerifier, "summary_verifier"),
            (ExtensionKind::Tokenizer, "tokenizer"),
            (ExtensionKind::Materializer, "materializer"),
            (ExtensionKind::PolicyProvider, "policy_provider"),
            (ExtensionKind::StorageBackend, "storage_backend"),
            (ExtensionKind::EffectConnector, "effect_connector"),
            (ExtensionKind::Reconciler, "reconciler"),
        ];
        assert_eq!(cases.len(), 12);
        for (kind, spelling) in cases {
            assert_eq!(serde_json::to_string(&kind)?, format!("\"{spelling}\""));
        }
        Ok(())
    }

    #[test]
    fn signed_manifest_is_bounded_cross_bound_and_debug_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = manifest()?;
        manifest.validate()?;
        let encoded = serde_json::to_vec(&manifest)?;
        let decoded: ExtensionManifestV1 = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, manifest);

        let rendered = format!("{manifest:?}");
        assert!(!rendered.contains("bin/extension.wasm"));
        assert!(!rendered.contains("api.example.test"));
        assert!(!rendered.contains("processor-a"));
        assert!(!rendered.contains("BwcHBwc"));
        assert!(!rendered.contains("CAgICAg"));
        assert!(rendered.contains("signature_bytes"));
        Ok(())
    }

    #[test]
    fn normalized_ids_paths_and_endpoints_reject_ambiguous_forms()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(ExtensionId::new("Dev.Cigar").is_err());
        assert!(ExtensionId::new("dev..cigar").is_err());
        assert!(ExtensionId::new("dev.cigar-").is_err());
        for path in ["../secret", "/absolute", "a//b", "a/./b", "a/../b", "a\\b"] {
            assert!(SandboxPath::new(path).is_err(), "accepted path {path}");
        }
        for host in [
            "HTTPS://example.test",
            "Example.test",
            "example.test.",
            "*.example.test",
            "https://example.test",
            "127.000.000.001",
        ] {
            assert!(NetworkHost::new(host).is_err(), "accepted host {host}");
        }
        assert!(NetworkHost::new("2001:db8::1").is_ok());
        assert!(
            NetworkEndpoint::new(
                NetworkTransport::Https,
                NetworkHost::new("example.test")?,
                0,
            )
            .is_err()
        );
        assert!(serde_json::from_str::<SandboxPath>("\"../secret\"").is_err());
        assert!(serde_json::from_str::<NetworkHost>("\"Example.test\"").is_err());
        Ok(())
    }

    #[test]
    fn manifest_rejects_signature_schema_capability_and_range_confusion()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut candidate = manifest()?;
        candidate.signature.pop();
        assert!(candidate.validate().is_err());

        let mut candidate = manifest()?;
        candidate.schema_bindings.swap(0, 1);
        assert!(candidate.validate().is_err());

        let mut candidate = manifest()?;
        candidate.required_host_capabilities.clear();
        assert!(candidate.validate().is_err());

        let mut candidate = manifest()?;
        candidate.protocol_abi.minimum = ExtensionSemanticVersion::new(2, 0, 0);
        assert!(candidate.validate().is_err());

        let mut candidate = manifest()?;
        candidate.required_host_capabilities = vec![ExtensionHostCapability::FilesystemRead];
        candidate.network_allowlist.clear();
        candidate.filesystem_preopens = vec![SandboxPreopen {
            path: SandboxPath::new("workspace/output")?,
            access: SandboxAccess::ReadWrite,
        }];
        assert!(candidate.validate().is_err());
        candidate
            .required_host_capabilities
            .push(ExtensionHostCapability::FilesystemWrite);
        assert!(candidate.validate().is_ok());

        candidate.runtime = ExtensionRuntimeKind::RemoteGrpc;
        assert!(candidate.validate().is_err());
        Ok(())
    }

    #[test]
    fn invocation_response_host_call_cancel_and_observation_bind_lifecycle()
    -> Result<(), Box<dyn std::error::Error>> {
        let invocation = invocation()?;
        invocation.validate()?;
        assert!(!format!("{invocation:?}").contains("protected-input-canary"));

        let mut candidate = invocation.clone();
        candidate.handles.push(ExtensionHandle::new([2; 32]));
        assert!(candidate.validate().is_err());
        let mut candidate = invocation.clone();
        candidate.deterministic_random_seed.clear();
        assert!(candidate.validate().is_err());
        let mut candidate = invocation.clone();
        candidate.deadline_at = timestamp(3)?;
        assert!(candidate.validate().is_err());
        let mut candidate = invocation;
        candidate.effective_limits.max_input_bytes = 1;
        assert!(candidate.validate().is_err());

        let response = ExtensionResponseV1 {
            schema_version: SchemaVersion::new("cigar.extension-response", 1)?,
            invocation_id: record('1')?,
            outcome: ExtensionResponseOutcome::Succeeded,
            output_schema_digest: Some(digest('a')?),
            output_digest: Some(digest('b')?),
            output: b"protected-output-canary".to_vec(),
            host_call_count: 1,
            completed_at: timestamp(1)?,
        };
        response.validate()?;
        assert!(!format!("{response:?}").contains("protected-output-canary"));
        let mut failed = response.clone();
        failed.outcome = ExtensionResponseOutcome::Failed;
        assert!(failed.validate().is_err());
        failed.output.clear();
        failed.output_schema_digest = None;
        failed.output_digest = None;
        assert!(failed.validate().is_ok());

        let host_call = ExtensionHostCallV1 {
            schema_version: SchemaVersion::new("cigar.extension-host-call", 1)?,
            call_id: record('2')?,
            invocation_id: record('1')?,
            ordinal: 1,
            kind: ExtensionHostCallKind::ReadBlob,
            capability: ExtensionHostCapability::BlobRead,
            handle: Some(ExtensionHandle::new([4; 32])),
            request_digest: digest('c')?,
            request: b"host-request-canary".to_vec(),
            response_digest: digest('d')?,
            response: b"host-response-canary".to_vec(),
            started_at: timestamp(0)?,
            completed_at: timestamp(1)?,
        };
        host_call.validate()?;
        let rendered = format!("{host_call:?}");
        assert!(!rendered.contains("host-request-canary"));
        assert!(!rendered.contains("host-response-canary"));
        let mut wrong_capability = host_call.clone();
        wrong_capability.capability = ExtensionHostCapability::SourceRead;
        assert!(wrong_capability.validate().is_err());
        let mut missing_handle = host_call;
        missing_handle.handle = None;
        assert!(missing_handle.validate().is_err());

        let cancel = ExtensionCancelV1 {
            schema_version: SchemaVersion::new("cigar.extension-cancel", 1)?,
            cancel_id: record('3')?,
            invocation_id: record('1')?,
            reason: ExtensionCancelReason::Deadline,
            requested_at: timestamp(1)?,
        };
        cancel.validate()?;
        let mut invalid_cancel = cancel;
        invalid_cancel.cancel_id = invalid_cancel.invocation_id.clone();
        assert!(invalid_cancel.validate().is_err());

        let observation = ExtensionObservationV1 {
            schema_version: SchemaVersion::new("cigar.extension-observation", 1)?,
            observation_id: record('4')?,
            invocation_id: record('1')?,
            extension_id: ExtensionId::new("dev.cigar.fixture")?,
            extension_version: semantic_version(),
            manifest_digest: digest('e')?,
            implementation_digest: digest('f')?,
            package_digest: digest('0')?,
            kind: ExtensionKind::Transform,
            determinism: ExtensionDeterminism::Nondeterministic,
            input_digest: digest('1')?,
            effective_limits: limits()?,
            host_call_transcript_digest: digest('2')?,
            host_call_count: 1,
            outcome: ExtensionResponseOutcome::Succeeded,
            output_schema_digest: Some(digest('3')?),
            output_digest: Some(digest('4')?),
            started_at: timestamp(0)?,
            completed_at: timestamp(1)?,
        };
        observation.validate()?;
        let mut invalid_observation = observation;
        invalid_observation.host_call_count = 65;
        assert!(invalid_observation.validate().is_err());
        Ok(())
    }

    #[test]
    fn records_deny_unknown_fields_and_limits_aggregate_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut encoded = serde_json::to_value(manifest()?)?;
        let Some(fields) = encoded.as_object_mut() else {
            return Err("manifest did not encode as an object".into());
        };
        fields.insert("ambient_environment".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<ExtensionManifestV1>(encoded).is_err());

        let mut invalid = limits()?;
        invalid.max_memory_bytes = 0;
        invalid.compute = ExtensionComputeBudget::Fuel { units: 0 };
        invalid.wall_deadline = DurationNanos::new(0)?;
        invalid.max_input_bytes = 0;
        invalid.max_output_bytes = 0;
        invalid.max_concurrency = 0;
        invalid.max_recursion_depth = 0;
        invalid.max_host_calls = 0;
        let Err(errors) = invalid.validate() else {
            return Err("zero resource profile unexpectedly validated".into());
        };
        assert_eq!(errors.len(), 8);
        Ok(())
    }
}
