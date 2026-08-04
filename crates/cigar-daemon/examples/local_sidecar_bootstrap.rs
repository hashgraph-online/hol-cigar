//! Source-only bootstrap helper for CEDAR-managed local CIGAR sidecars.
//!
//! This example deliberately is not included in the published `cigar-daemon` crate. CEDAR invokes
//! it from an exact private shadow-CIGAR checkout to create an owner-private, loopback-only local
//! runtime. The shipped `cigard` command surface and public release authority remain unchanged.

#[path = "support/local_application.rs"]
mod local_application;

use cigar_crypto::{
    CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider as _, KeyPurpose,
    SecretBytes,
};
use cigar_daemon::{
    ApplicationResourceLimits, ConfiguredEffectAction, DaemonConfig, DeploymentMode,
    LocalBearerToken, LocalIdentity, ProductionAtomizationConfiguration,
    ProductionAuthorityConfiguration, ProductionEffectAuthorityRule, ProductionPaths,
    ProductionPrincipalAuthority, ProductionSourceConnectorConfiguration,
    ProductionSourceConnectorKind, ProductionSourceEntry, ProductionSourceRegistry,
    ProductionTenantAuthority, SourceConfiguration, SourceDiscoveryPolicyConfiguration,
    TelemetrySettings, WorkerCapacities,
};
use cigar_policy::PolicyProfile;
use cigar_protocol::{
    ApprovalKind, BuildMetadata, Capability, Classification, FixedPoint, GovernanceEnvelope,
    InstructionAuthority, MediaType, QualityEnvelope, RecordId, RiskLevel, SourceUri, UtcTimestamp,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroize as _;

const FIXED_TIME: &str = "2020-01-01T00:00:00Z";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapErrorCode {
    InvalidArguments,
    UnsafeRoot,
    RootExists,
    EntropyUnavailable,
    FilesystemUnavailable,
    CredentialUnavailable,
    IdentityUnavailable,
    KeyUnavailable,
    ConfigurationInvalid,
    SerializationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BootstrapError {
    code: BootstrapErrorCode,
}

impl BootstrapError {
    const fn new(code: BootstrapErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "local sidecar bootstrap rejected: {:?}",
            self.code
        )
    }
}

impl Error for BootstrapError {}

#[derive(Debug, Serialize)]
struct BootstrapReceipt {
    schema_version: &'static str,
    status: &'static str,
    root_handle: String,
    daemon_config_sha256: String,
    cli_config_sha256: String,
    http_endpoint: String,
    version: &'static str,
    source_revision: &'static str,
    context_abi: &'static str,
    authentication: &'static str,
    fixture_profile: &'static str,
    effects_enabled: bool,
    application_fixture_sha256: Option<String>,
    workflow_replays: Vec<WorkflowReplayReceipt>,
}

#[derive(Debug, Serialize)]
struct WorkflowReplayReceipt {
    workflow_family: &'static str,
    decision_id: String,
    bundle_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureProfile {
    GovernedContext,
    LocalApplication,
}

impl FixtureProfile {
    const fn name(self) -> &'static str {
        match self {
            Self::GovernedContext => "governed-context-v1",
            Self::LocalApplication => "humidor-local-application-v1",
        }
    }

    const fn effects_enabled(self) -> bool {
        matches!(self, Self::LocalApplication)
    }
}

fn main() {
    match parse_arguments()
        .and_then(|(root, listen, profile)| bootstrap_profile(&root, listen, profile))
    {
        Ok(receipt) => match serde_json::to_string(&receipt) {
            Ok(json) => println!("{json}"),
            Err(_error) => fail(BootstrapErrorCode::SerializationFailed),
        },
        Err(error) => fail(error.code),
    }
}

fn fail(code: BootstrapErrorCode) -> ! {
    let code = match code {
        BootstrapErrorCode::InvalidArguments => "invalid_arguments",
        BootstrapErrorCode::UnsafeRoot => "unsafe_root",
        BootstrapErrorCode::RootExists => "root_exists",
        BootstrapErrorCode::EntropyUnavailable => "entropy_unavailable",
        BootstrapErrorCode::FilesystemUnavailable => "filesystem_unavailable",
        BootstrapErrorCode::CredentialUnavailable => "credential_unavailable",
        BootstrapErrorCode::IdentityUnavailable => "identity_unavailable",
        BootstrapErrorCode::KeyUnavailable => "key_unavailable",
        BootstrapErrorCode::ConfigurationInvalid => "configuration_invalid",
        BootstrapErrorCode::SerializationFailed => "serialization_failed",
    };
    eprintln!(
        "{{\"schema_version\":\"cigar.local-sidecar-bootstrap-error.v1\",\"status\":\"error\",\"code\":\"{code}\"}}"
    );
    std::process::exit(1);
}

fn parse_arguments() -> Result<(PathBuf, SocketAddr, FixtureProfile), BootstrapError> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| BootstrapError::new(BootstrapErrorCode::InvalidArguments))?;
    let listen = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .ok_or_else(|| BootstrapError::new(BootstrapErrorCode::InvalidArguments))?;
    let profile = match arguments.next() {
        None => FixtureProfile::GovernedContext,
        Some(value) if value == "application" => FixtureProfile::LocalApplication,
        Some(_value) => return Err(BootstrapError::new(BootstrapErrorCode::InvalidArguments)),
    };
    if arguments.next().is_some() {
        return Err(BootstrapError::new(BootstrapErrorCode::InvalidArguments));
    }
    validate_root(&root)?;
    if !listen.ip().is_loopback() || listen.port() < 1_024 {
        return Err(BootstrapError::new(BootstrapErrorCode::InvalidArguments));
    }
    Ok((root, listen, profile))
}

fn validate_root(root: &Path) -> Result<(), BootstrapError> {
    if !root.is_absolute() || root.exists() {
        return Err(BootstrapError::new(if root.exists() {
            BootstrapErrorCode::RootExists
        } else {
            BootstrapErrorCode::UnsafeRoot
        }));
    }
    let parent = root
        .parent()
        .ok_or_else(|| BootstrapError::new(BootstrapErrorCode::UnsafeRoot))?;
    let name = root
        .file_name()
        .ok_or_else(|| BootstrapError::new(BootstrapErrorCode::UnsafeRoot))?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::UnsafeRoot))?;
    if canonical_parent != parent || canonical_parent.join(name) != root {
        return Err(BootstrapError::new(BootstrapErrorCode::UnsafeRoot));
    }
    Ok(())
}

#[cfg(test)]
fn bootstrap(root: &Path, listen: SocketAddr) -> Result<BootstrapReceipt, BootstrapError> {
    bootstrap_profile(root, listen, FixtureProfile::GovernedContext)
}

fn bootstrap_profile(
    root: &Path,
    listen: SocketAddr,
    profile: FixtureProfile,
) -> Result<BootstrapReceipt, BootstrapError> {
    validate_root(root)?;
    create_private_directory(root)?;
    let result = bootstrap_created_root(root, listen, profile);
    if result.is_err() {
        let _ignored = std::fs::remove_dir_all(root);
    }
    result
}

fn bootstrap_created_root(
    root: &Path,
    listen: SocketAddr,
    profile: FixtureProfile,
) -> Result<BootstrapReceipt, BootstrapError> {
    let state = root.join("state");
    let runtime = root.join("run");
    let project = root.join("project");
    let trusted = root.join("trusted");
    let secrets = root.join("secrets");
    let checkpoints = root.join("effect-checkpoints");
    let config_directory = root.join("config");
    for path in [
        &state,
        &runtime,
        &project,
        &trusted,
        &secrets,
        &checkpoints,
        &config_directory,
    ] {
        create_private_directory(path)?;
    }
    let project = project
        .canonicalize()
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::FilesystemUnavailable))?;
    restricted_write(
        &project.join("README.md"),
        b"# CEDAR local-sidecar fixture\n\nGoverned local context survives an exact CIGAR restart.\n",
    )?;

    let mut passphrase = [0_u8; 32];
    getrandom::fill(&mut passphrase)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::EntropyUnavailable))?;
    let passphrase_file = secrets.join("keystore-passphrase");
    restricted_write(&passphrase_file, &passphrase)?;

    let token_file = secrets.join("local-token");
    let token = LocalBearerToken::create_file(&token_file)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::CredentialUnavailable))?;
    drop(token);
    let mut encoded_token = std::fs::read_to_string(&token_file)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::CredentialUnavailable))?;
    let mut authorization = String::from("Bearer ");
    authorization.push_str(&encoded_token);
    encoded_token.zeroize();
    restricted_write(&secrets.join("sdk-authorization"), authorization.as_bytes())?;
    authorization.zeroize();

    let keystore_file = state.join("keystore.cigar");
    let keystore_result =
        EncryptedDevelopmentKeystore::open(&keystore_file, SecretBytes::new(passphrase.to_vec()));
    passphrase.fill(0);
    let keystore = Arc::new(
        keystore_result
            .map_err(|_error| BootstrapError::new(BootstrapErrorCode::KeyUnavailable))?,
    );
    let tenant = record(1)?;
    let project_id = record(2)?;
    let principal = record(3)?;
    let fixed_time = UtcTimestamp::parse_rfc3339(FIXED_TIME)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?;
    let signing = keystore
        .create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: fixed_time.unix_nanos(),
            activated_at: fixed_time.unix_nanos(),
        })
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::KeyUnavailable))?;
    let application_fixture = if profile == FixtureProfile::LocalApplication {
        Some(
            local_application::provision(
                root,
                Arc::clone(&keystore),
                tenant.clone(),
                record(5)?,
                project_id.clone(),
                principal.clone(),
                fixed_time.unix_nanos(),
            )
            .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?,
        )
    } else {
        None
    };
    drop(keystore);

    let local = LocalIdentity::from_project_root(&project)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::IdentityUnavailable))?;
    let authenticated = local.authenticated();
    let authority = ProductionAuthorityConfiguration {
        schema_version: "cigar.production-authority.v1".to_owned(),
        runtime_audience: "local-runtime-v1".to_owned(),
        decision_ttl_seconds: 60,
        tenants: vec![ProductionTenantAuthority {
            authenticated_tenant: authenticated.tenant().as_str().to_owned(),
            tenant_id: tenant,
            active: true,
            issuer_key_ref: signing.key_ref,
            project_ids: vec![project_id.clone()],
            principals: vec![ProductionPrincipalAuthority {
                authenticated_principal: authenticated.principal().as_str().to_owned(),
                principal_id: principal,
                grant_id: record(4)?,
                active: true,
                operator: true,
                not_before: fixed_time,
                expires_at: UtcTimestamp::parse_rfc3339("2099-01-01T00:00:00Z").map_err(
                    |_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid),
                )?,
                roles: vec!["developer".to_owned()],
                project_ids: vec![project_id],
                capabilities: if profile.effects_enabled() {
                    vec![
                        Capability::ReadContext,
                        Capability::CompileContext,
                        Capability::InvokeTool,
                        Capability::ProposeEffect,
                        Capability::ApproveEffect,
                        Capability::ReconcileEffect,
                    ]
                } else {
                    vec![Capability::ReadContext, Capability::CompileContext]
                },
                delegatable_capabilities: Vec::new(),
                purposes: if profile.effects_enabled() {
                    vec![
                        "authorizeEffect".to_owned(),
                        "catalog.read".to_owned(),
                        "dispatchEffect".to_owned(),
                        "getEffectStatus".to_owned(),
                        "prepareEffect".to_owned(),
                        "reconcileEffect".to_owned(),
                    ]
                } else {
                    vec!["catalog.read".to_owned()]
                },
                processors: if profile.effects_enabled() {
                    vec![
                        "cigar-reference".to_owned(),
                        "issues".to_owned(),
                        "local".to_owned(),
                    ]
                } else {
                    vec!["cigar-reference".to_owned(), "local".to_owned()]
                },
                catalog_purpose: "catalog.read".to_owned(),
                catalog_processor: "local".to_owned(),
                maximum_classification: Classification::Restricted,
                maximum_instruction_authority: InstructionAuthority::System,
                residency_allowed: true,
                egress_allowed: true,
                vector_allowed: false,
                handoff_target_allowed: false,
                effect_rules: if profile.effects_enabled() {
                    vec![ProductionEffectAuthorityRule {
                        connector: "issues".to_owned(),
                        operation: "create_issue".to_owned(),
                        target: "humidor-seeded".to_owned(),
                        required_capability: Capability::ProposeEffect,
                        maximum_risk: RiskLevel::Low,
                        allowed_actions: vec![
                            ConfiguredEffectAction::Prepare,
                            ConfiguredEffectAction::Authorize,
                            ConfiguredEffectAction::Dispatch,
                            ConfiguredEffectAction::Read,
                            ConfiguredEffectAction::Reconcile,
                        ],
                        allowed_approval_kinds: vec![ApprovalKind::Human],
                    }]
                } else {
                    Vec::new()
                },
            }],
            revoked_principal_ids: Vec::new(),
            revoked_key_refs: Vec::new(),
        }],
    };
    let authority_file = trusted.join("authority.json");
    restricted_write(&authority_file, &serialize(&authority)?)?;
    let policy_file = trusted.join("policy.json");
    restricted_write(
        &policy_file,
        &serialize(&PolicyProfile {
            schema_version: "cigar.policy-profile.v1".to_owned(),
            revision: 1,
            protected: true,
            rules: Vec::new(),
        })?,
    )?;
    let sources_file = trusted.join("sources.json");
    let source_id = record(5)?;
    let atomization = ProductionAtomizationConfiguration {
        project_ids: vec![record(2)?],
        governance: GovernanceEnvelope {
            classification: Classification::Internal,
            allowed_purposes: vec!["catalog.read".to_owned()],
            processor_constraints: Vec::new(),
            instruction_authority: InstructionAuthority::Data,
        },
        quality: QualityEnvelope {
            confidence: FixedPoint::new(FixedPoint::ONE)
                .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?,
            coverage: FixedPoint::new(FixedPoint::ONE)
                .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?,
            authority: 10,
        },
        lexical_enabled: true,
        embedding_eligible: false,
        atomizer_set: "required_v1".to_owned(),
    };
    let source = ProductionSourceEntry {
        tenant_id: record(1)?,
        source: SourceConfiguration {
            schema_version: "cigar.source-configuration.v1".to_owned(),
            source_id,
            root: SourceUri::new(canonical_file_uri(&project)?)
                .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?,
            connector_identity: "cigar.builtin.filesystem.v1".to_owned(),
            atomization_profile_digest: atomization
                .registry_digest(&record(1)?)
                .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?,
            discovery_policy: SourceDiscoveryPolicyConfiguration {
                max_items: 100,
                max_total_bytes: 1024 * 1024,
                max_record_bytes: 1024 * 1024,
                excluded_prefixes: Vec::new(),
                allowed_media_types: BTreeSet::from([MediaType::new("text/markdown").map_err(
                    |_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid),
                )?]),
                allow_user_broadening: false,
                follow_internal_symlinks: false,
                secret_patterns: Vec::new(),
            },
        },
        connector: ProductionSourceConnectorConfiguration {
            kind: ProductionSourceConnectorKind::Filesystem,
            root_directory: project.clone(),
        },
        atomization,
    };
    restricted_write(
        &sources_file,
        &serialize(&ProductionSourceRegistry {
            schema_version: "cigar.production-source-registry.v1".to_owned(),
            sources: vec![source],
        })?,
    )?;
    let effects_file = trusted.join("effects.json");
    restricted_write(
        &effects_file,
        if profile.effects_enabled() {
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":true,"connectors":[{"name":"issues","kind":"demo_issue","argument_vault_provider":"repository_blob_json.v1","development_demo_dispatch_mode":"commit_then_lose_response"}]}"#
        } else {
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":false,"connectors":[]}"#
        },
    )?;
    let (application_fixture_sha256, workflow_replays) = if let Some(fixture) = application_fixture
    {
        let bytes = serialize(&fixture)?;
        restricted_write(&trusted.join("application-fixture.json"), &bytes)?;
        (
            Some(format!("sha256:{}", sha256(&bytes))),
            fixture
                .workflow_replays
                .iter()
                .map(|replay| WorkflowReplayReceipt {
                    workflow_family: replay.workflow_family,
                    decision_id: replay.decision_id.as_str().to_owned(),
                    bundle_id: replay.bundle_id.as_str().to_owned(),
                })
                .collect(),
        )
    } else {
        (None, Vec::new())
    };

    let daemon = DaemonConfig {
        mode: DeploymentMode::Local,
        intelligence_profile: cigar_daemon::IntelligenceProfile::default(),
        local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
        state_directory: state.clone(),
        runtime_directory: runtime,
        unix_socket: None,
        windows_named_pipe: None,
        http_listen: Some(listen),
        grpc_listen: None,
        local_token_file: Some(token_file.clone()),
        tls: None,
        oidc: None,
        production: ProductionPaths {
            project_directory: project,
            metadata_database: state.join("cigar.sqlite3"),
            active_store_descriptor: None,
            blob_directory: state.join("blobs"),
            blob_key_reference_directory: state.join("blob-keys"),
            keystore_file,
            keystore_passphrase_file: passphrase_file,
            cursor_signing_key_file: state.join("cursor.key"),
            effect_checkpoint_file: checkpoints.join("checkpoints.json"),
            policy_profile_file: policy_file,
            authority_file,
            source_registry_file: sources_file,
            effect_registry_file: effects_file,
        },
        local_vector: cigar_daemon::LocalVectorSettings::default(),
        shared_storage: None,
        request_deadline_ms: 5_000,
        shutdown_deadline_ms: 5_000,
        max_request_bytes: 1024 * 1024,
        max_expansion_ratio: 8,
        workers: WorkerCapacities {
            ingestion: 4,
            indexing: 4,
            invalidation: 4,
            compilation: 4,
            outbox: 4,
            reconciliation: 4,
            lease_cleanup: 4,
            backup: 2,
            garbage_collection: 2,
        },
        resources: ApplicationResourceLimits {
            global_request_concurrency: 32,
            per_tenant_request_concurrency: 8,
            blocking_active: 4,
            blocking_queued: 16,
            idempotency_wait_ms: 1_000,
        },
        telemetry: TelemetrySettings {
            otlp_endpoint: None,
            otlp_ca_certificate_file: None,
            export_timeout_ms: 1_000,
            metric_interval_ms: 1_000,
        },
    };
    daemon
        .validate()
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))?;
    let daemon_bytes = toml::to_string(&daemon)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::SerializationFailed))?
        .into_bytes();
    let daemon_config = config_directory.join("cigard.toml");
    restricted_write(&daemon_config, &daemon_bytes)?;

    let cli_bytes = format!(
        concat!(
            "schema_version = 1\n",
            "target = \"local\"\n",
            "local_endpoint = \"http://{}\"\n",
            "authorization_file = {:?}\n",
            "project_state_directory = {:?}\n"
        ),
        listen,
        token_file,
        root.join("cli-state"),
    )
    .into_bytes();
    create_private_directory(&root.join("cli-state"))?;
    let cli_config = config_directory.join("cigar.toml");
    restricted_write(&cli_config, &cli_bytes)?;

    let metadata = BuildMetadata::current(env!("CARGO_PKG_VERSION"));
    Ok(BootstrapReceipt {
        schema_version: "cigar.local-sidecar-bootstrap.v1",
        status: "created",
        root_handle: format!("sha256:{}", sha256(root.as_os_str().as_encoded_bytes())),
        daemon_config_sha256: format!("sha256:{}", sha256(&daemon_bytes)),
        cli_config_sha256: format!("sha256:{}", sha256(&cli_bytes)),
        http_endpoint: format!("http://{listen}"),
        version: metadata.version,
        source_revision: metadata.source_revision,
        context_abi: metadata.context_abi,
        authentication: "owner_file_bearer",
        fixture_profile: profile.name(),
        effects_enabled: profile.effects_enabled(),
        application_fixture_sha256,
        workflow_replays,
    })
}

fn record(value: u64) -> Result<RecordId, BootstrapError> {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{value:012x}"))
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::ConfigurationInvalid))
}

fn canonical_file_uri(path: &Path) -> Result<String, BootstrapError> {
    let text = path
        .to_str()
        .ok_or_else(|| BootstrapError::new(BootstrapErrorCode::UnsafeRoot))?;
    let mut uri = String::from("file://");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut uri, "%{byte:02X}");
        }
    }
    Ok(uri)
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, BootstrapError> {
    serde_json::to_vec(value)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::SerializationFailed))
}

fn create_private_directory(path: &Path) -> Result<(), BootstrapError> {
    std::fs::create_dir(path)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::FilesystemUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_error| BootstrapError::new(BootstrapErrorCode::FilesystemUnavailable))?;
    }
    Ok(())
}

fn restricted_write(path: &Path, bytes: &[u8]) -> Result<(), BootstrapError> {
    std::fs::write(path, bytes)
        .map_err(|_error| BootstrapError::new(BootstrapErrorCode::FilesystemUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_error| BootstrapError::new(BootstrapErrorCode::FilesystemUnavailable))?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{BootstrapErrorCode, FixtureProfile, bootstrap, bootstrap_profile};
    use cigar_daemon::{DaemonConfig, ProductionEffectRegistry, ProductionSourceRegistry};
    use std::error::Error;
    use std::net::SocketAddr;

    #[test]
    fn creates_valid_owner_private_loopback_configuration() -> Result<(), Box<dyn Error>> {
        let parent = tempfile::tempdir()?;
        let root = parent.path().canonicalize()?.join("sidecar");
        let listen: SocketAddr = "127.0.0.1:47991".parse()?;
        let receipt = bootstrap(&root, listen)?;
        assert_eq!(receipt.status, "created");
        assert_eq!(receipt.http_endpoint, "http://127.0.0.1:47991");
        assert_eq!(receipt.fixture_profile, "governed-context-v1");
        assert!(!receipt.effects_enabled);
        let config_bytes = std::fs::read_to_string(root.join("config/cigard.toml"))?;
        let config = DaemonConfig::from_toml(&config_bytes)?;
        assert_eq!(config.http_listen, Some(listen));
        assert!(config.unix_socket.is_none());
        assert!(config.local_token_file.is_some());
        assert!(config.production.effect_checkpoint_file.starts_with(&root));
        assert!(
            !config
                .production
                .effect_checkpoint_file
                .starts_with(&config.state_directory)
        );
        let sources = std::fs::read(&config.production.source_registry_file)?;
        let registry =
            ProductionSourceRegistry::from_json(&sources, &config.production.project_directory)?;
        assert_eq!(registry.configured_tenants().len(), 1);
        assert!(
            config
                .production
                .project_directory
                .join("README.md")
                .is_file()
        );
        let authorization = std::fs::read_to_string(root.join("secrets/sdk-authorization"))?;
        assert!(authorization.starts_with("Bearer "));
        assert!(
            !authorization
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() && byte != b' ')
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&root)?.permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(root.join("secrets/local-token"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(root.join("secrets/sdk-authorization"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn existing_root_fails_without_mutation() -> Result<(), Box<dyn Error>> {
        let parent = tempfile::tempdir()?;
        let root = parent.path().canonicalize()?.join("sidecar");
        std::fs::create_dir(&root)?;
        let marker = root.join("marker");
        std::fs::write(&marker, b"preserve")?;
        let listen: SocketAddr = "127.0.0.1:47991".parse()?;
        let error = bootstrap(&root, listen).expect_err("existing root must fail");
        assert_eq!(error.code, BootstrapErrorCode::RootExists);
        assert_eq!(std::fs::read(marker)?, b"preserve");
        Ok(())
    }

    #[test]
    fn application_profile_seeds_effect_and_replay_boundaries() -> Result<(), Box<dyn Error>> {
        let parent = tempfile::tempdir()?;
        let root = parent.path().canonicalize()?.join("application-sidecar");
        let listen: SocketAddr = "127.0.0.1:47991".parse()?;
        let receipt = bootstrap_profile(&root, listen, FixtureProfile::LocalApplication)?;
        assert_eq!(receipt.fixture_profile, "humidor-local-application-v1");
        assert!(receipt.effects_enabled);
        assert!(receipt.application_fixture_sha256.is_some());
        assert_eq!(receipt.workflow_replays.len(), 6);
        assert_eq!(
            receipt
                .workflow_replays
                .iter()
                .map(|replay| replay.workflow_family)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            6
        );
        assert_eq!(
            receipt
                .workflow_replays
                .iter()
                .map(|replay| &replay.decision_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            6
        );
        let config =
            DaemonConfig::from_toml(&std::fs::read_to_string(root.join("config/cigard.toml"))?)?;
        let effects = ProductionEffectRegistry::from_json(&std::fs::read(
            config.production.effect_registry_file,
        )?)?;
        assert!(!effects.effects_disabled());
        let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(
            root.join("trusted/application-fixture.json"),
        )?)?;
        assert_eq!(
            fixture
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("cigar.local-application-fixture.v1")
        );
        assert_eq!(
            fixture.get("source_id").and_then(serde_json::Value::as_str),
            Some("01890f47-8e7d-7b42-a1d2-000000000005")
        );
        assert_eq!(
            fixture.get("query").and_then(serde_json::Value::as_str),
            Some("governed local context")
        );
        assert_eq!(
            fixture
                .get("workflow_replays")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(6)
        );
        Ok(())
    }
}
