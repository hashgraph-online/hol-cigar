//! Strict production effect connector registry and repository-backed argument vault.

use cigar_canon::parse_strict_json;
use cigar_effects::reference::{
    DemoDispatchMode, DemoIssueConnector, DemoIssueRequest, DemoIssueService,
    FilesystemEffectConnector, FilesystemWriteRequest, HttpTransport, IdempotentHttpConnector,
    IdempotentHttpRequest,
};
use cigar_effects::{EffectConnector, EffectError, EffectErrorCode};
use cigar_protocol::{EffectIntent, RecordId};
use cigar_store::{RepositoryBlobStore, StoreErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Component, PathBuf};
use std::sync::Arc;

const EFFECT_REGISTRY_SCHEMA: &str = "cigar.production-effect-registry.v1";
const MAX_EFFECT_CONNECTORS: usize = 256;
const REPOSITORY_ARGUMENT_VAULT: &str = "repository_blob_json.v1";

/// Exact media type required for versioned protected connector argument documents.
pub const PROTECTED_EFFECT_ARGUMENT_MEDIA_TYPE: &str =
    "application/vnd.cigar.effect-arguments+json";

/// Stable content-free effect registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionEffectRegistryError {
    /// The strict document or closed connector configuration was malformed.
    InvalidConfiguration,
    /// A configured reference connector could not be constructed safely.
    ConnectorUnavailable,
}

impl fmt::Display for ProductionEffectRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("production effect connector registry is unavailable")
    }
}

impl std::error::Error for ProductionEffectRegistryError {}

/// Stable content-free protected-argument resolution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectArgumentVaultError {
    /// The connector selector, document schema, normalized digest, or media type was invalid.
    InvalidArguments,
    /// The exact tenant-scoped protected blob was absent.
    NotFound,
    /// A configured size bound was exceeded.
    LimitExceeded,
    /// The authenticated blob repository or connector staging boundary was unavailable.
    Unavailable,
}

impl fmt::Display for EffectArgumentVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("protected effect arguments are unavailable")
    }
}

impl std::error::Error for EffectArgumentVaultError {}

/// Tenant-scoped vault used before preparation and again immediately before connector access.
pub trait EffectArgumentVault: Send + Sync {
    /// Authenticates, decodes, and validates a protected argument document without staging it.
    fn validate(
        &self,
        tenant: &RecordId,
        intent: &EffectIntent,
    ) -> Result<(), EffectArgumentVaultError>;

    /// Repeats validation and stages exact normalized arguments into the configured connector.
    fn stage(
        &self,
        tenant: &RecordId,
        intent: &EffectIntent,
    ) -> Result<(), EffectArgumentVaultError>;
}

/// Closed reference connector families that can be bound once a trusted argument vault exists.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionEffectConnectorKind {
    /// Hermetic demo issue service used only by explicitly selected deployments.
    DemoIssue,
    /// Atomic write connector confined to one canonical root.
    Filesystem,
    /// Same-key idempotent HTTPS connector pinned to one endpoint.
    IdempotentHttp,
}

/// One deterministic initial behavior for the hermetic demo connector.
///
/// This is deliberately unavailable to filesystem and HTTP connectors. It exists so an installed
/// local-development composition can prove unknown-outcome reconciliation without network access
/// or an unsafe second dispatch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevelopmentDemoDispatchMode {
    /// Commit and return the normal success observation.
    Normal,
    /// Commit once, lose the response, and require reconciliation.
    CommitThenLoseResponse,
    /// Prove that no request capable of committing reached the service.
    ProvenNotSent,
    /// Reject before committing.
    RejectBeforeCommit,
}

impl From<DevelopmentDemoDispatchMode> for DemoDispatchMode {
    fn from(value: DevelopmentDemoDispatchMode) -> Self {
        match value {
            DevelopmentDemoDispatchMode::Normal => Self::Normal,
            DevelopmentDemoDispatchMode::CommitThenLoseResponse => Self::CommitThenLoseResponse,
            DevelopmentDemoDispatchMode::ProvenNotSent => Self::ProvenNotSent,
            DevelopmentDemoDispatchMode::RejectBeforeCommit => Self::RejectBeforeCommit,
        }
    }
}

/// One immutable effect connector selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEffectConnectorConfiguration {
    /// Stable unique connector selector used by effect intents.
    pub name: String,
    /// Supported built-in connector implementation.
    pub kind: ProductionEffectConnectorKind,
    /// Existing canonical root, required only by `filesystem`.
    pub root_directory: Option<PathBuf>,
    /// Immutable HTTPS endpoint, required only by `idempotent_http`.
    pub endpoint: Option<String>,
    /// Explicit stock HTTPS and scoped-credential settings, required only by `idempotent_http`.
    pub https_transport: Option<ProductionHttpsEffectTransportConfiguration>,
    /// Mandatory opaque argument-vault provider selector for enabled connectors.
    pub argument_vault_provider: Option<String>,
    /// Optional one-shot initial mode, accepted only by the hermetic demo connector.
    pub development_demo_dispatch_mode: Option<DevelopmentDemoDispatchMode>,
}

/// Explicit, secret-safe configuration for the macOS stock HTTPS effect transport.
///
/// The credential bytes never appear here. `credential_handle` names the exact owner-private
/// credential document at `credential_file`; the transport revalidates that document's origin,
/// project, resource, validity window, and bearer token at every dispatch and lookup.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionHttpsEffectTransportConfiguration {
    /// Exact remote protocol contract implemented by the configured endpoint.
    pub provider_protocol: String,
    /// Opaque handle that must match the owner-private credential document.
    pub credential_handle: String,
    /// Absolute owner-private credential-document path.
    pub credential_file: PathBuf,
    /// Sorted unique public IP addresses dialed directly without ambient DNS.
    pub pinned_addresses: Vec<IpAddr>,
    /// Maximum TCP/TLS establishment time.
    pub connect_timeout_ms: u64,
    /// Maximum complete request and bounded-response time.
    pub request_timeout_ms: u64,
    /// Maximum accepted response bytes.
    pub maximum_response_bytes: usize,
}

impl fmt::Debug for ProductionHttpsEffectTransportConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionHttpsEffectTransportConfiguration")
            .field("provider_protocol", &self.provider_protocol)
            .field("credential_handle", &"[OPAQUE]")
            .field("credential_file", &"[OWNER-PRIVATE]")
            .field("pinned_address_count", &self.pinned_addresses.len())
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .finish()
    }
}

/// Constructs one endpoint-bound HTTPS transport for each configured HTTP connector.
///
/// A factory is injected only by the qualified local macOS bootstrap. Omitting it keeps live HTTP
/// effects unavailable even if a registry document attempts to configure one.
pub trait ProductionHttpTransportFactory: Send + Sync {
    /// Constructs a transport fixed to `endpoint` and the exact scoped credential settings.
    fn build(
        &self,
        endpoint: &str,
        configuration: ProductionHttpsEffectTransportConfiguration,
    ) -> Result<Arc<dyn HttpTransport>, ProductionEffectRegistryError>;
}

/// Explicit effect capability profile. Disabled effects are supported only when stated here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEffectRegistry {
    /// Must be `cigar.production-effect-registry.v1`.
    pub schema_version: String,
    /// Whether effect preparation/dispatch capabilities are enabled.
    pub effects_enabled: bool,
    /// Sorted unique immutable connector configurations.
    pub connectors: Vec<ProductionEffectConnectorConfiguration>,
}

impl ProductionEffectRegistry {
    /// Parses strict JSON and validates explicit disabled/enabled semantics.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProductionEffectRegistryError> {
        parse_strict_json(bytes)
            .map_err(|_error| ProductionEffectRegistryError::InvalidConfiguration)?;
        let registry: Self = serde_json::from_slice(bytes)
            .map_err(|_error| ProductionEffectRegistryError::InvalidConfiguration)?;
        registry.validate()?;
        Ok(registry)
    }

    fn validate(&self) -> Result<(), ProductionEffectRegistryError> {
        if self.schema_version != EFFECT_REGISTRY_SCHEMA
            || self.connectors.len() > MAX_EFFECT_CONNECTORS
            || self.connectors.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_some_and(|(a, b)| a.name >= b.name)
            })
            || self.connectors.iter().any(|connector| !connector.valid())
            || (!self.effects_enabled && !self.connectors.is_empty())
            || (self.effects_enabled && self.connectors.is_empty())
        {
            return Err(ProductionEffectRegistryError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Returns whether effect capability is explicitly disabled.
    #[must_use]
    pub const fn effects_disabled(&self) -> bool {
        !self.effects_enabled
    }

    /// Returns whether composition requires the explicitly qualified live HTTPS factory.
    #[must_use]
    pub(crate) fn requires_live_http(&self) -> bool {
        self.connectors
            .iter()
            .any(|connector| connector.kind == ProductionEffectConnectorKind::IdempotentHttp)
    }

    /// Returns whether a source-only local development fault was explicitly selected.
    #[must_use]
    pub(crate) fn has_development_demo_dispatch_mode(&self) -> bool {
        self.connectors
            .iter()
            .any(|connector| connector.development_demo_dispatch_mode.is_some())
    }

    /// Constructs the exact configured built-in connectors and their shared tenant-scoped vault.
    ///
    /// HTTP connectors require an explicitly injected bounded HTTPS transport. Disabled profiles
    /// construct an empty connector set and a vault that rejects every selector.
    pub fn compose(
        &self,
        blobs: Arc<dyn RepositoryBlobStore>,
        http_transports: Option<Arc<dyn ProductionHttpTransportFactory>>,
    ) -> Result<ProductionEffectComponents, ProductionEffectRegistryError> {
        self.validate()?;
        let mut connectors: Vec<Arc<dyn EffectConnector>> = Vec::new();
        let mut stagers = BTreeMap::new();
        let mut demo_services = BTreeMap::new();
        for configuration in &self.connectors {
            let stager = match configuration.kind {
                ProductionEffectConnectorKind::DemoIssue => {
                    let service = Arc::new(DemoIssueService::default());
                    if let Some(mode) = configuration.development_demo_dispatch_mode {
                        service
                            .set_next_mode(mode.into())
                            .map_err(map_connector_build_error)?;
                    }
                    let connector = Arc::new(
                        DemoIssueConnector::new(configuration.name.clone(), Arc::clone(&service))
                            .map_err(map_connector_build_error)?,
                    );
                    let exposed: Arc<dyn EffectConnector> = connector.clone();
                    connectors.push(exposed);
                    demo_services.insert(configuration.name.clone(), service);
                    ArgumentStager::Demo(connector)
                }
                ProductionEffectConnectorKind::Filesystem => {
                    let root = configuration
                        .root_directory
                        .as_ref()
                        .ok_or(ProductionEffectRegistryError::InvalidConfiguration)?;
                    let connector = Arc::new(
                        FilesystemEffectConnector::new(configuration.name.clone(), root)
                            .map_err(map_connector_build_error)?,
                    );
                    let exposed: Arc<dyn EffectConnector> = connector.clone();
                    connectors.push(exposed);
                    ArgumentStager::Filesystem(connector)
                }
                ProductionEffectConnectorKind::IdempotentHttp => {
                    let endpoint = configuration
                        .endpoint
                        .as_ref()
                        .ok_or(ProductionEffectRegistryError::InvalidConfiguration)?;
                    let transport_configuration = configuration
                        .https_transport
                        .clone()
                        .ok_or(ProductionEffectRegistryError::InvalidConfiguration)?;
                    let transport = http_transports
                        .as_ref()
                        .ok_or(ProductionEffectRegistryError::ConnectorUnavailable)?
                        .build(endpoint, transport_configuration)?;
                    let connector = Arc::new(
                        IdempotentHttpConnector::new(
                            configuration.name.clone(),
                            endpoint.clone(),
                            transport,
                        )
                        .map_err(map_connector_build_error)?,
                    );
                    let exposed: Arc<dyn EffectConnector> = connector.clone();
                    connectors.push(exposed);
                    ArgumentStager::Http(connector)
                }
            };
            if stagers.insert(configuration.name.clone(), stager).is_some() {
                return Err(ProductionEffectRegistryError::InvalidConfiguration);
            }
        }
        Ok(ProductionEffectComponents {
            connectors,
            vault: Arc::new(RepositoryEffectArgumentVault { blobs, stagers }),
            demo_services,
        })
    }
}

/// Composed connector/vault boundary retained for handler and worker construction.
pub struct ProductionEffectComponents {
    connectors: Vec<Arc<dyn EffectConnector>>,
    vault: Arc<RepositoryEffectArgumentVault>,
    demo_services: BTreeMap<String, Arc<DemoIssueService>>,
}

impl ProductionEffectComponents {
    /// Returns the immutable connector registry in configuration order.
    #[must_use]
    pub fn connectors(&self) -> Vec<Arc<dyn EffectConnector>> {
        self.connectors.clone()
    }

    /// Returns the same vault used by request handlers and durable workers.
    #[must_use]
    pub fn argument_vault(&self) -> Arc<dyn EffectArgumentVault> {
        self.vault.clone()
    }

    /// Returns a configured hermetic demo service for installed-artifact tests.
    #[must_use]
    pub fn demo_service(&self, connector: &str) -> Option<Arc<DemoIssueService>> {
        self.demo_services.get(connector).cloned()
    }
}

impl fmt::Debug for ProductionEffectComponents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionEffectComponents")
            .field("connector_count", &self.connectors.len())
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

enum ArgumentStager {
    Demo(Arc<DemoIssueConnector>),
    Filesystem(Arc<FilesystemEffectConnector>),
    Http(Arc<IdempotentHttpConnector>),
}

enum DecodedArguments {
    Demo(DemoIssueRequest),
    Filesystem(FilesystemWriteRequest),
    Http(IdempotentHttpRequest),
}

struct RepositoryEffectArgumentVault {
    blobs: Arc<dyn RepositoryBlobStore>,
    stagers: BTreeMap<String, ArgumentStager>,
}

impl RepositoryEffectArgumentVault {
    fn decode(
        &self,
        tenant: &RecordId,
        intent: &EffectIntent,
    ) -> Result<DecodedArguments, EffectArgumentVaultError> {
        let stager = self
            .stagers
            .get(&intent.connector)
            .ok_or(EffectArgumentVaultError::InvalidArguments)?;
        if intent.encrypted_arguments.media_type.as_str() != PROTECTED_EFFECT_ARGUMENT_MEDIA_TYPE {
            return Err(EffectArgumentVaultError::InvalidArguments);
        }
        let blob = self
            .blobs
            .get(tenant, &intent.encrypted_arguments)
            .map_err(map_blob_error)?
            .ok_or(EffectArgumentVaultError::NotFound)?;
        if blob.reference != intent.encrypted_arguments {
            return Err(EffectArgumentVaultError::InvalidArguments);
        }
        let decoded = match stager {
            ArgumentStager::Demo(_connector) => {
                DemoIssueRequest::decode_protected_document(blob.bytes())
                    .map(DecodedArguments::Demo)
            }
            ArgumentStager::Filesystem(_connector) => {
                FilesystemWriteRequest::decode_protected_document(blob.bytes())
                    .map(DecodedArguments::Filesystem)
            }
            ArgumentStager::Http(_connector) => {
                IdempotentHttpRequest::decode_protected_document(blob.bytes())
                    .map(DecodedArguments::Http)
            }
        }
        .map_err(map_argument_error)?;
        let digest = match &decoded {
            DecodedArguments::Demo(request) => request.arguments_digest(),
            DecodedArguments::Filesystem(request) => request.arguments_digest(),
            DecodedArguments::Http(request) => request.arguments_digest(),
        }
        .map_err(map_argument_error)?;
        if digest != intent.arguments_digest {
            return Err(EffectArgumentVaultError::InvalidArguments);
        }
        Ok(decoded)
    }
}

impl EffectArgumentVault for RepositoryEffectArgumentVault {
    fn validate(
        &self,
        tenant: &RecordId,
        intent: &EffectIntent,
    ) -> Result<(), EffectArgumentVaultError> {
        self.decode(tenant, intent).map(|_arguments| ())
    }

    fn stage(
        &self,
        tenant: &RecordId,
        intent: &EffectIntent,
    ) -> Result<(), EffectArgumentVaultError> {
        let decoded = self.decode(tenant, intent)?;
        let staged = match (
            self.stagers
                .get(&intent.connector)
                .ok_or(EffectArgumentVaultError::InvalidArguments)?,
            decoded,
        ) {
            (ArgumentStager::Demo(connector), DecodedArguments::Demo(request)) => {
                connector.stage_request(request)
            }
            (ArgumentStager::Filesystem(connector), DecodedArguments::Filesystem(request)) => {
                connector.stage_write(request)
            }
            (ArgumentStager::Http(connector), DecodedArguments::Http(request)) => {
                connector.stage_request(request)
            }
            _ => return Err(EffectArgumentVaultError::InvalidArguments),
        }
        .map_err(map_argument_error)?;
        if staged == intent.arguments_digest {
            Ok(())
        } else {
            Err(EffectArgumentVaultError::InvalidArguments)
        }
    }
}

impl fmt::Debug for RepositoryEffectArgumentVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryEffectArgumentVault")
            .field("connector_count", &self.stagers.len())
            .field("blobs", &"[TENANT-SCOPED ENCRYPTED REPOSITORY]")
            .finish()
    }
}

impl ProductionEffectConnectorConfiguration {
    fn valid(&self) -> bool {
        let selector_valid = !self.name.is_empty()
            && self.name.len() <= 256
            && self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        let vault_valid =
            self.argument_vault_provider.as_deref() == Some(REPOSITORY_ARGUMENT_VAULT);
        if !selector_valid || !vault_valid {
            return false;
        }
        match self.kind {
            ProductionEffectConnectorKind::DemoIssue => {
                self.root_directory.is_none()
                    && self.endpoint.is_none()
                    && self.https_transport.is_none()
            }
            ProductionEffectConnectorKind::Filesystem => {
                self.endpoint.is_none()
                    && self.https_transport.is_none()
                    && self.development_demo_dispatch_mode.is_none()
                    && self.root_directory.as_ref().is_some_and(|root| {
                        root.is_absolute()
                            && !root.components().any(|component| {
                                matches!(component, Component::CurDir | Component::ParentDir)
                            })
                    })
            }
            ProductionEffectConnectorKind::IdempotentHttp => {
                #[cfg(target_os = "macos")]
                {
                    self.root_directory.is_none()
                        && self.development_demo_dispatch_mode.is_none()
                        && self
                            .endpoint
                            .as_deref()
                            .zip(self.https_transport.as_ref())
                            .is_some_and(|(endpoint, transport)| {
                                transport.validate_for_endpoint(endpoint).is_ok()
                            })
                }
                #[cfg(not(target_os = "macos"))]
                {
                    false
                }
            }
        }
    }
}

fn map_connector_build_error(_error: EffectError) -> ProductionEffectRegistryError {
    ProductionEffectRegistryError::ConnectorUnavailable
}

fn map_blob_error(error: cigar_store::StoreError) -> EffectArgumentVaultError {
    match error.code() {
        StoreErrorCode::NotFound => EffectArgumentVaultError::NotFound,
        StoreErrorCode::InvalidContext | StoreErrorCode::InvalidRecord => {
            EffectArgumentVaultError::InvalidArguments
        }
        StoreErrorCode::LimitExceeded => EffectArgumentVaultError::LimitExceeded,
        StoreErrorCode::RevisionConflict
        | StoreErrorCode::MixedSnapshot
        | StoreErrorCode::Cancelled
        | StoreErrorCode::InjectedAbort
        | StoreErrorCode::Unavailable => EffectArgumentVaultError::Unavailable,
    }
}

fn map_argument_error(error: EffectError) -> EffectArgumentVaultError {
    match error.code() {
        EffectErrorCode::NotFound => EffectArgumentVaultError::NotFound,
        EffectErrorCode::LimitExceeded => EffectArgumentVaultError::LimitExceeded,
        EffectErrorCode::Unavailable | EffectErrorCode::Cancelled => {
            EffectArgumentVaultError::Unavailable
        }
        EffectErrorCode::InvalidInput
        | EffectErrorCode::Unauthorized
        | EffectErrorCode::RevisionConflict
        | EffectErrorCode::IdempotencyCollision
        | EffectErrorCode::InvalidTransition
        | EffectErrorCode::UnsafeRetry
        | EffectErrorCode::CorruptJournal
        | EffectErrorCode::Expired => EffectArgumentVaultError::InvalidArguments,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EFFECT_REGISTRY_SCHEMA, EffectArgumentVaultError, PROTECTED_EFFECT_ARGUMENT_MEDIA_TYPE,
        ProductionEffectRegistry, ProductionEffectRegistryError, ProductionHttpTransportFactory,
        ProductionHttpsEffectTransportConfiguration,
    };
    use cigar_effects::reference::{
        DemoIssueRequest, HttpLookupObservation, HttpResourceBindingRequest, HttpTransport,
        HttpTransportObservation, HttpTransportQuery, HttpTransportRequest, HttpTransportSecurity,
    };
    use cigar_effects::{EffectError, EffectErrorCode};
    use cigar_protocol::{
        BlobRef, Capability, ContentDigest, EffectIntent, ExtensionMap, IdempotencyKey, MediaType,
        RecordId, RetryPolicy, RiskLevel, SchemaVersion, UtcTimestamp, VersionId,
    };
    use cigar_store::{BlobRecord, RepositoryBlobStore, StoreError};
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    struct StaticBlobs {
        tenant: RecordId,
        blob: BlobRecord,
    }

    impl RepositoryBlobStore for StaticBlobs {
        fn put(&self, _tenant: &RecordId, _blob: &BlobRecord) -> Result<(), StoreError> {
            Ok(())
        }

        fn get(
            &self,
            tenant: &RecordId,
            reference: &BlobRef,
        ) -> Result<Option<BlobRecord>, StoreError> {
            Ok(
                (tenant == &self.tenant && reference == &self.blob.reference)
                    .then(|| self.blob.clone()),
            )
        }

        fn readiness_probe(
            &self,
            _tenant: &RecordId,
            _blob: &BlobRecord,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        fn reconcile(
            &self,
            _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct EmptyBlobs;

    impl RepositoryBlobStore for EmptyBlobs {
        fn put(&self, _tenant: &RecordId, _blob: &BlobRecord) -> Result<(), StoreError> {
            Ok(())
        }

        fn get(
            &self,
            _tenant: &RecordId,
            _reference: &BlobRef,
        ) -> Result<Option<BlobRecord>, StoreError> {
            Ok(None)
        }

        fn readiness_probe(
            &self,
            _tenant: &RecordId,
            _blob: &BlobRecord,
        ) -> Result<(), StoreError> {
            Ok(())
        }

        fn reconcile(
            &self,
            _live: &BTreeMap<String, BTreeSet<ContentDigest>>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct TestHttpTransport {
        endpoint: String,
    }

    impl HttpTransport for TestHttpTransport {
        fn security(&self) -> Result<HttpTransportSecurity, EffectError> {
            HttpTransportSecurity::new(
                self.endpoint.clone(),
                [Ipv4Addr::new(93, 184, 216, 34).into()],
                true,
                true,
                true,
            )
        }

        fn validate_resource_binding(
            &self,
            _request: &HttpResourceBindingRequest<'_>,
        ) -> Result<(), EffectError> {
            Ok(())
        }

        fn send(
            &self,
            _request: &HttpTransportRequest<'_>,
        ) -> Result<HttpTransportObservation, EffectError> {
            Err(EffectError::new(EffectErrorCode::Unavailable))
        }

        fn lookup(
            &self,
            _query: &HttpTransportQuery<'_>,
        ) -> Result<HttpLookupObservation, EffectError> {
            Err(EffectError::new(EffectErrorCode::Unavailable))
        }
    }

    #[derive(Default)]
    struct RecordingHttpFactory {
        builds: Mutex<Vec<(String, String)>>,
    }

    impl ProductionHttpTransportFactory for RecordingHttpFactory {
        fn build(
            &self,
            endpoint: &str,
            configuration: ProductionHttpsEffectTransportConfiguration,
        ) -> Result<Arc<dyn HttpTransport>, ProductionEffectRegistryError> {
            self.builds
                .lock()
                .map_err(|_error| ProductionEffectRegistryError::ConnectorUnavailable)?
                .push((endpoint.to_owned(), configuration.credential_handle));
            Ok(Arc::new(TestHttpTransport {
                endpoint: endpoint.to_owned(),
            }))
        }
    }

    fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        let hash = Sha256::digest(bytes);
        let mut encoded = String::from("1220");
        for byte in hash {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(ContentDigest::new(encoded)?)
    }

    fn intent(
        arguments: &DemoIssueRequest,
        reference: BlobRef,
    ) -> Result<EffectIntent, Box<dyn std::error::Error>> {
        Ok(EffectIntent {
            schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
            effect_id: record(10)?,
            connector: "issues".to_owned(),
            operation: "create_issue".to_owned(),
            arguments_digest: arguments.arguments_digest()?,
            encrypted_arguments: reference,
            target: arguments.project().to_owned(),
            preconditions: Vec::new(),
            result_schema_digest: digest(b"result-schema")?,
            risk: RiskLevel::Low,
            source_decision_id: VersionId::new(digest(b"decision")?.as_str())?,
            bundle_id: VersionId::new(digest(b"bundle")?.as_str())?,
            required_capability: Capability::ProposeEffect,
            idempotency_scope: "demo-issues".to_owned(),
            idempotency_key: IdempotencyKey::new("effect-key")?,
            retry_policy: RetryPolicy::Never,
            created_at: UtcTimestamp::parse_rfc3339("2026-07-12T00:00:00Z")?,
            expires_at: UtcTimestamp::parse_rfc3339("2026-07-12T00:05:00Z")?,
            compensation: None,
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn disabled_is_explicit_and_enabled_requires_the_closed_argument_vault()
    -> Result<(), Box<dyn std::error::Error>> {
        let disabled = format!(
            r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","effects_enabled":false,"connectors":[]}}"#
        );
        let registry = ProductionEffectRegistry::from_json(disabled.as_bytes())?;
        assert!(registry.effects_disabled());

        let enabled = format!(
            r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","effects_enabled":true,"connectors":[{{"name":"issues","kind":"demo_issue","argument_vault_provider":"repository_blob_json.v1"}}]}}"#
        );
        assert!(ProductionEffectRegistry::from_json(enabled.as_bytes()).is_ok());

        let development_fault = format!(
            r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","effects_enabled":true,"connectors":[{{"name":"issues","kind":"demo_issue","argument_vault_provider":"repository_blob_json.v1","development_demo_dispatch_mode":"commit_then_lose_response"}}]}}"#
        );
        let registry = ProductionEffectRegistry::from_json(development_fault.as_bytes())?;
        let components = registry.compose(Arc::new(EmptyBlobs), None)?;
        assert!(components.demo_service("issues").is_some());

        let unsupported = enabled.replace("repository_blob_json.v1", "ambient-memory.v1");
        assert_eq!(
            ProductionEffectRegistry::from_json(unsupported.as_bytes()),
            Err(ProductionEffectRegistryError::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn repository_vault_is_tenant_scoped_digest_bound_and_restart_stageable()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = record(1)?;
        let other_tenant = record(2)?;
        let arguments = DemoIssueRequest::new("project-a", "title", "body")?;
        let bytes = arguments.encode_protected_document()?;
        let reference = BlobRef {
            digest: digest(&bytes)?,
            size_bytes: u64::try_from(bytes.len())?,
            media_type: MediaType::new(PROTECTED_EFFECT_ARGUMENT_MEDIA_TYPE)?,
        };
        let blob = BlobRecord::new(reference.clone(), bytes)?;
        let blobs: Arc<dyn RepositoryBlobStore> = Arc::new(StaticBlobs {
            tenant: tenant.clone(),
            blob,
        });
        let registry = ProductionEffectRegistry::from_json(
            format!(
                r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","effects_enabled":true,"connectors":[{{"name":"issues","kind":"demo_issue","argument_vault_provider":"repository_blob_json.v1"}}]}}"#
            )
            .as_bytes(),
        )?;
        let components = registry.compose(blobs, None)?;
        let intent = intent(&arguments, reference)?;
        let vault = components.argument_vault();
        vault.validate(&tenant, &intent)?;
        vault.stage(&tenant, &intent)?;
        vault.stage(&tenant, &intent)?;
        assert_eq!(
            vault.validate(&other_tenant, &intent),
            Err(EffectArgumentVaultError::NotFound)
        );

        let mut drifted = intent;
        drifted.arguments_digest = digest(b"different-normalized-request")?;
        assert_eq!(
            vault.validate(&tenant, &drifted),
            Err(EffectArgumentVaultError::InvalidArguments)
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn http_connectors_require_explicit_settings_and_build_one_transport_per_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry_document = serde_json::json!({
            "schema_version": EFFECT_REGISTRY_SCHEMA,
            "effects_enabled": true,
            "connectors": [
                {
                    "name": "http-a",
                    "kind": "idempotent_http",
                    "endpoint": "https://a.example.invalid/v1/effects",
                    "https_transport": {
                        "provider_protocol": "cigar.idempotent-effect-http.v1",
                        "credential_handle": "credential-a",
                        "credential_file": "/private/tmp/cigar-effect-a.json",
                        "pinned_addresses": ["93.184.216.34"],
                        "connect_timeout_ms": 1_000,
                        "request_timeout_ms": 2_000,
                        "maximum_response_bytes": 16_384
                    },
                    "argument_vault_provider": "repository_blob_json.v1"
                },
                {
                    "name": "http-b",
                    "kind": "idempotent_http",
                    "endpoint": "https://b.example.invalid/v1/effects",
                    "https_transport": {
                        "provider_protocol": "cigar.idempotent-effect-http.v1",
                        "credential_handle": "credential-b",
                        "credential_file": "/private/tmp/cigar-effect-b.json",
                        "pinned_addresses": ["93.184.216.35"],
                        "connect_timeout_ms": 1_000,
                        "request_timeout_ms": 2_000,
                        "maximum_response_bytes": 16_384
                    },
                    "argument_vault_provider": "repository_blob_json.v1"
                }
            ]
        });
        let bytes = serde_json::to_vec(&registry_document)?;
        let registry = ProductionEffectRegistry::from_json(&bytes)?;
        assert!(registry.requires_live_http());
        let blobs: Arc<dyn RepositoryBlobStore> = Arc::new(EmptyBlobs);
        assert_eq!(
            registry.compose(Arc::clone(&blobs), None).err(),
            Some(ProductionEffectRegistryError::ConnectorUnavailable)
        );

        let recording = Arc::new(RecordingHttpFactory::default());
        let factory: Arc<dyn ProductionHttpTransportFactory> = recording.clone();
        let components = registry.compose(blobs, Some(factory))?;
        assert_eq!(components.connectors().len(), 2);
        let builds = recording
            .builds
            .lock()
            .map_err(|_error| "recording factory lock was poisoned")?;
        assert_eq!(
            builds.as_slice(),
            [
                (
                    "https://a.example.invalid/v1/effects".to_owned(),
                    "credential-a".to_owned()
                ),
                (
                    "https://b.example.invalid/v1/effects".to_owned(),
                    "credential-b".to_owned()
                )
            ]
        );

        let mut missing_transport = registry_document;
        missing_transport
            .get_mut("connectors")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|connectors| connectors.get_mut(0))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("connector must be an object")?
            .remove("https_transport");
        assert_eq!(
            ProductionEffectRegistry::from_json(&serde_json::to_vec(&missing_transport)?),
            Err(ProductionEffectRegistryError::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn omitted_unknown_and_disabled_nonempty_are_rejected() {
        for invalid in [
            format!(r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","connectors":[]}}"#),
            format!(
                r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","effects_enabled":false,"connectors":[],"unknown":true}}"#
            ),
            format!(
                r#"{{"schema_version":"{EFFECT_REGISTRY_SCHEMA}","effects_enabled":false,"connectors":[{{"name":"issues","kind":"demo_issue","argument_vault_provider":"vault.v1"}}]}}"#
            ),
        ] {
            assert_eq!(
                ProductionEffectRegistry::from_json(invalid.as_bytes()),
                Err(ProductionEffectRegistryError::InvalidConfiguration)
            );
        }
    }
}
