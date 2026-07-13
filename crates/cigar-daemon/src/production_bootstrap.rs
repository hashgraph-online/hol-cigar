//! Fail-closed composition of the standalone production daemon.

use crate::{
    ApplicationIdGenerator, BlockingPool, CatalogContextApplication, DaemonConfig, DaemonError,
    DaemonErrorCode, DaemonFacadeErrorFactory, DaemonServer, DaemonTelemetry, DeploymentMode,
    DurableIdempotencyRepository, DurableLiveReplayAuthorizationRepository,
    EffectServiceDependencies, EffectServiceHandlers, EffectWorkerProcessor,
    EffectWorkerProcessorDependencies, LifecycleError, MonotonicApplicationIds,
    OperationalHandlers, PinnedContextTokenizerRegistry, ProductionDependencyChecks,
    ProductionDomainAuthority, ProductionEffectRecordAuthenticator, ProductionEffectRegistry,
    ProductionFacade, ProductionHandlerFamilies, ProductionKeyRequirement, ProductionRuntimeError,
    ProductionSourceRegistry, ProductionStore, ReplayLiveServices, ReplayLiveServicesError,
    ReplayLiveServicesFactory, ReplayServiceDependencies, ReplayServiceHandlers,
    RepositoryCatalogIndex, RepositoryProductionChecksDependencies,
    RepositoryProductionDependencyChecks, RepositorySpaceHandoffStateProvider,
    SpaceHandoffApplication, SystemAuthorityClock, SystemProductionUnixClock, SystemRuntimeClock,
    SystemSpaceHandoffValueSource, compose_complete_production_application,
    compose_repository_runtime_with_facade,
};
use cigar_api::{CursorCodec, CursorSigningKey, FacadeErrorFactory, QuotaLimits};
use cigar_canon::parse_strict_json;
use cigar_crypto::{
    EncryptedDevelopmentKeystore, ImmutableKeyProvider, KeyAlgorithm, KeyProvider, KeyPurpose,
    KeyRef, KeyStatus, SecretBytes,
};
use cigar_policy::{CompiledPolicyEngine, PolicyEngine};
use cigar_protocol::{RecordId, UtcTimestamp};
use cigar_replay::{
    LiveAuthorizationVerifier, LiveEffectDispatch, LiveEffectGate, LiveReplayAuthorization,
    LiveReplayInvocation, LiveReplayOutput, LiveReplayProvider, ReplayError, ReplayErrorCode,
};
use cigar_retrieval::{InMemoryIndexManager, IndexWorker, Retriever};
use cigar_store::{
    MultiTenantLocalRepositoryBlobStore, ObjectRepositoryBlobStore, PostgresConfiguration,
    PostgresStore, RepositoryBlobStore, S3CompatibleObjectStorage, ServiceRepository, SqliteStore,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const MAX_TRUSTED_FILE_BYTES: u64 = 1_048_576;
const MAX_PASSPHRASE_BYTES: u64 = 16_384;
const MAX_STORAGE_SECRET_BYTES: u64 = 16_384;
const MAX_POSTGRES_CA_BYTES: u64 = 2 * 1024 * 1024;
const CURSOR_KEY_BYTES: usize = 32;
const MAX_PRODUCTION_TENANTS: usize = 1_024;
const MAX_PRODUCTION_EFFECT_RECORDS: usize = 1_000_000;
const CURSOR_TTL: Duration = Duration::from_secs(15 * 60);
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Composes the exact standalone daemon from one validated production configuration.
///
/// Construction performs no listener bind. It does open and verify every durable/trusted
/// dependency, provisions configured sources, reconstructs the mandatory catalog index, and
/// installs a complete governed 45-operation facade. No in-memory healthy substitute is used for
/// a missing production dependency.
pub fn compose_production_server(config: DaemonConfig) -> Result<DaemonServer, DaemonError> {
    config.validate().map_err(|_error| bootstrap_failure())?;
    // Install the workspace-selected provider only when an embedding process has not already
    // selected one. This covers local OTLP/TLS clients as well as shared listener/JWKS paths.
    let _provider_result = rustls::crypto::ring::default_provider().install_default();
    prepare_directories(&config)?;

    let clock: Arc<dyn crate::AuthorityClock> = Arc::new(SystemAuthorityClock);
    let now = clock.now().map_err(|_error| bootstrap_failure())?;
    if config.mode == DeploymentMode::Shared {
        require_immutable_secret_file(&config.production.keystore_file, None)?;
        require_immutable_secret_file(
            &config.production.cursor_signing_key_file,
            Some(CURSOR_KEY_BYTES as u64),
        )?;
    }
    let passphrase = SecretBytes::new(read_restricted_file(
        &config.production.keystore_passphrase_file,
        MAX_PASSPHRASE_BYTES,
    )?);
    let keys = Arc::new(
        EncryptedDevelopmentKeystore::open(&config.production.keystore_file, passphrase)
            .map_err(|_error| bootstrap_failure())?,
    );
    let immutable_keys = Arc::new(ImmutableKeyProvider::new(Arc::clone(&keys)));
    let key_provider: Arc<dyn KeyProvider> = match config.mode {
        DeploymentMode::Local => keys.clone(),
        DeploymentMode::Shared => immutable_keys.clone(),
    };

    let policy = Arc::new(CompiledPolicyEngine::default());
    let policy_bytes = read_trusted_file(
        &config.production.policy_profile_file,
        MAX_TRUSTED_FILE_BYTES,
    )?;
    let expected_policy_snapshot = install_policy(
        &policy,
        &config.production.policy_profile_file,
        &policy_bytes,
        now,
    )?;

    let authority_bytes =
        read_trusted_file(&config.production.authority_file, MAX_TRUSTED_FILE_BYTES)?;
    let authority_configuration =
        crate::ProductionAuthorityConfiguration::from_json(&authority_bytes)
            .map_err(|_error| bootstrap_failure())?;
    let (system_tenant, recovery_actor, mut required_keys, active_tenants) =
        authority_bootstrap_metadata(&authority_configuration)?;
    let authority = Arc::new(
        ProductionDomainAuthority::new(
            authority_configuration,
            Arc::clone(&policy),
            Arc::clone(&key_provider),
            Arc::clone(&clock),
        )
        .map_err(|_error| bootstrap_failure())?,
    );

    let (blob_repository, store) = match config.mode {
        DeploymentMode::Local => {
            let blob_store = Arc::new(
                MultiTenantLocalRepositoryBlobStore::open(
                    &config.production.blob_directory,
                    &config.production.blob_key_reference_directory,
                    Arc::clone(&keys),
                    now.unix_nanos(),
                )
                .map_err(|_error| bootstrap_failure())?,
            );
            let blob_repository: Arc<dyn RepositoryBlobStore> = blob_store;
            let store = ProductionStore::local(
                SqliteStore::open_with_blob_repository(
                    &config.production.metadata_database,
                    Arc::clone(&blob_repository),
                )
                .map_err(|_error| bootstrap_failure())?,
            );
            (blob_repository, store)
        }
        DeploymentMode::Shared => compose_shared_store(
            &config,
            immutable_keys,
            now.unix_nanos(),
            &active_tenants,
            &mut required_keys,
        )?,
    };
    let store = Arc::new(store);
    let create_empty_effect_checkpoint = match config.mode {
        DeploymentMode::Local => effect_store_is_empty(&store)?,
        DeploymentMode::Shared => false,
    };
    let effect_signature_authority: Arc<dyn crate::EffectRecordSignatureAuthority> =
        authority.clone();
    let effect_record_authenticator: Arc<dyn cigar_effects::EffectRecordAuthenticator> = Arc::new(
        ProductionEffectRecordAuthenticator::open(
            effect_signature_authority,
            config.production.effect_checkpoint_file.clone(),
            create_empty_effect_checkpoint,
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    let effects_bytes = read_trusted_file(
        &config.production.effect_registry_file,
        MAX_TRUSTED_FILE_BYTES,
    )?;
    let effect_registry = ProductionEffectRegistry::from_json(&effects_bytes)
        .map_err(|_error| bootstrap_failure())?;
    let effect_components = effect_registry
        .compose(Arc::clone(&blob_repository), None)
        .map_err(|_error| bootstrap_failure())?;

    let service_repository: Arc<dyn ServiceRepository> = store.clone();

    let source_bytes = read_trusted_file(
        &config.production.source_registry_file,
        MAX_TRUSTED_FILE_BYTES,
    )?;
    let source_registry =
        ProductionSourceRegistry::from_json(&source_bytes, &config.production.project_directory)
            .map_err(|_error| bootstrap_failure())?;
    if source_registry
        .configured_tenants()
        .iter()
        .any(|tenant| active_tenants.binary_search(tenant).is_err())
    {
        return Err(bootstrap_failure());
    }

    let cursor_key = match config.mode {
        DeploymentMode::Local => {
            load_or_create_cursor_key(&config.production.cursor_signing_key_file)?
        }
        DeploymentMode::Shared => {
            load_existing_cursor_key(&config.production.cursor_signing_key_file)?
        }
    };
    let cursor = Arc::new(CursorCodec::new(cursor_key));
    let errors: Arc<dyn FacadeErrorFactory> =
        Arc::new(DaemonFacadeErrorFactory::new().map_err(|_error| bootstrap_failure())?);
    let ids: Arc<dyn ApplicationIdGenerator> = Arc::new(MonotonicApplicationIds::default());
    let blocking_pool = Arc::new(
        BlockingPool::new(
            config.resources.blocking_active,
            config.resources.blocking_queued,
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    let telemetry = Arc::new(
        match config
            .telemetry
            .otlp_config()
            .map_err(|_error| bootstrap_failure())?
        {
            Some(otlp) => DaemonTelemetry::with_otlp(otlp).map_err(|_error| bootstrap_failure())?,
            None => DaemonTelemetry::local(),
        },
    );

    let manager = Arc::new(InMemoryIndexManager::default());
    let index_worker = Arc::new(IndexWorker::default());
    let tenant_provider: Arc<dyn crate::ProductionTenantProvider> = authority.clone();
    let catalog_index = Arc::new(
        RepositoryCatalogIndex::new(
            Arc::clone(&store),
            Arc::clone(&tenant_provider),
            Arc::clone(&manager),
            Arc::clone(&index_worker),
            Arc::clone(&clock),
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    catalog_index
        .rebuild()
        .map_err(|_error| bootstrap_failure())?;

    let identities: Arc<dyn crate::DomainIdentityResolver> = authority.clone();
    let catalog_authorizer: Arc<dyn crate::CatalogContextAuthorizer> = authority.clone();
    let retriever: Arc<dyn Retriever> = manager.clone();
    let catalog = Arc::new(CatalogContextApplication::new(
        Arc::clone(&store),
        Arc::clone(&identities),
        catalog_authorizer,
        retriever,
        Arc::new(PinnedContextTokenizerRegistry::default()),
        Arc::clone(&blocking_pool),
        Arc::clone(&clock),
        Arc::clone(&errors),
    ));
    source_registry
        .provision(catalog.as_ref())
        .map_err(|_error| bootstrap_failure())?;

    let states = Arc::new(
        RepositorySpaceHandoffStateProvider::new_authenticated(
            Arc::clone(&service_repository),
            Arc::clone(&key_provider),
            authority.clone(),
            MAX_PRODUCTION_TENANTS,
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    let space_authorizer: Arc<dyn crate::SpaceHandoffAuthorizer> = authority.clone();
    let recipient_compiler: Arc<dyn crate::RecipientBundleCompiler> = catalog.clone();
    let handoff_references: Arc<dyn crate::HandoffReferenceResolver> = catalog.clone();
    let merge_planner: Arc<dyn crate::HandoffResultMergePlanner> = authority.clone();
    let spaces = Arc::new(
        SpaceHandoffApplication::new(
            states,
            Arc::clone(&identities),
            space_authorizer,
            recipient_compiler,
            merge_planner,
            handoff_references,
            Arc::new(SystemSpaceHandoffValueSource::new(Arc::clone(&clock))),
            cursor,
            Arc::clone(&errors),
            CURSOR_TTL,
            EVENT_POLL_INTERVAL,
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    let replay = Arc::new(ReplayServiceHandlers::new(ReplayServiceDependencies {
        repository: Arc::clone(&service_repository),
        identities: Arc::clone(&identities),
        live_authorizations: Arc::new(DurableLiveReplayAuthorizationRepository::new(Arc::clone(
            &service_repository,
        ))),
        live_services: Arc::new(RecordedOnlyReplayServices),
        clock: Arc::clone(&clock),
        ids: Arc::clone(&ids),
        blocking_pool: blocking_pool.as_ref().clone(),
        errors: Arc::clone(&errors),
    }));

    let deferred_checks = Arc::new(DeferredProductionChecks::default());
    let exposed_checks: Arc<dyn ProductionDependencyChecks> = deferred_checks.clone();
    let server_authority = Arc::clone(&authority);
    let runtime_config = config.clone();
    let facade_config = config.clone();
    let runtime = compose_repository_runtime_with_facade(
        &runtime_config,
        service_repository,
        system_tenant.clone(),
        exposed_checks,
        Arc::clone(&blocking_pool),
        Arc::new(SystemRuntimeClock::new()),
        Arc::new(SystemProductionUnixClock),
        Arc::clone(&telemetry),
        move |inputs| {
            let connectors = effect_components.connectors();
            let argument_vault = effect_components.argument_vault();
            let effect_policy: Arc<dyn crate::EffectPolicyEvaluator> = authority.clone();
            let effect_handlers = Arc::new(
                EffectServiceHandlers::new_with_authenticator(
                    EffectServiceDependencies {
                        repository: Arc::clone(&store),
                        identities,
                        policy: effect_policy,
                        clock: Arc::clone(&clock),
                        ids: Arc::clone(&ids),
                        dispatch_gate: inputs.workers.clone(),
                        dispatch_queue: inputs.workers.clone(),
                        argument_vault: Arc::clone(&argument_vault),
                        blocking_pool: inputs.blocking_pool.as_ref().clone(),
                        connectors: connectors.clone(),
                        errors: Arc::clone(&errors),
                    },
                    Arc::clone(&effect_record_authenticator),
                )
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?,
            );
            let worker_authority: Arc<dyn crate::EffectWorkerAuthority> = authority.clone();
            let effect_workers = Arc::new(
                EffectWorkerProcessor::new_with_authenticator(
                    EffectWorkerProcessorDependencies {
                        repository: Arc::clone(&store),
                        authority: worker_authority,
                        clock: Arc::clone(&clock),
                        ids: Arc::clone(&ids),
                        dispatch_gate: inputs.workers.clone(),
                        argument_vault,
                        connectors,
                    },
                    Arc::clone(&effect_record_authenticator),
                )
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?,
            );
            let policy_boundary: Arc<dyn PolicyEngine> = policy.clone();
            let index_target: Arc<dyn crate::ProductionIndexTarget> = catalog_index.clone();
            let maintenance: Arc<dyn crate::ProductionDomainMaintenance> = catalog_index.clone();
            let checks = Arc::new(
                RepositoryProductionDependencyChecks::new_with_effect_authenticator(
                    RepositoryProductionChecksDependencies {
                        store: Arc::clone(&store),
                        policy: policy_boundary,
                        expected_policy_snapshot,
                        index_worker,
                        index_manager: manager,
                        index_target,
                        max_index_lag_revisions: 0,
                        key_provider,
                        required_keys,
                        tenants: tenant_provider,
                        maintenance,
                        effect_workers,
                        clock: Arc::clone(&clock),
                        ids: Arc::clone(&ids),
                        system_tenant: system_tenant.clone(),
                        recovery_actor,
                        blob_probe_tenant: system_tenant.clone(),
                        max_tenants: MAX_PRODUCTION_TENANTS,
                        max_effect_records: MAX_PRODUCTION_EFFECT_RECORDS,
                    },
                    Arc::clone(&effect_record_authenticator),
                )
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?,
            );
            let checks: Arc<dyn ProductionDependencyChecks> = checks;
            deferred_checks
                .install(checks)
                .map_err(|()| ProductionRuntimeError::InvalidConfiguration)?;

            let operational = Arc::new(OperationalHandlers::new(
                &facade_config,
                inputs.readiness,
                inputs.readiness_gate,
                inputs.workers,
                inputs.telemetry,
                Arc::clone(&errors),
            ));
            let complete = compose_complete_production_application(
                Arc::clone(&errors),
                ProductionHandlerFamilies {
                    operational,
                    catalog_context: catalog,
                    space_handoff: spaces,
                    effects: effect_handlers,
                    replay,
                },
            )
            .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?;
            let quotas = QuotaLimits::new(
                facade_config.resources.global_request_concurrency,
                facade_config.resources.per_tenant_request_concurrency,
            )
            .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?;
            let idempotency = Arc::new(DurableIdempotencyRepository::new(
                Arc::clone(&store) as Arc<dyn ServiceRepository>,
                system_tenant,
            ));
            ProductionFacade::new(
                complete,
                idempotency,
                quotas,
                facade_config.resources.idempotency_wait(),
            )
            .map(Arc::new)
            .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)
        },
    )
    .map_err(|_error| bootstrap_failure())?;

    match config.mode {
        DeploymentMode::Local => {
            let local_identity =
                crate::LocalIdentity::from_project_root(&config.production.project_directory)
                    .map_err(|_error| bootstrap_failure())?;
            if server_authority
                .resolve_authenticated(&local_identity.authenticated())
                .map_err(|_error| bootstrap_failure())?
                .is_none()
            {
                return Err(bootstrap_failure());
            }
            DaemonServer::local(config, runtime, local_identity)
        }
        DeploymentMode::Shared => {
            let refresh =
                Arc::new(crate::HttpsJwksRefresh::new().map_err(|_error| {
                    DaemonError::new(DaemonErrorCode::SharedProviderUnavailable)
                })?);
            let operators: Arc<dyn crate::OperatorAuthorizer> = server_authority;
            DaemonServer::shared(config, runtime, refresh, operators)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectWrappingKeysFile {
    schema_version: String,
    keys: Vec<ObjectWrappingKeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectWrappingKeyEntry {
    tenant_id: RecordId,
    key_ref: KeyRef,
}

fn compose_shared_store(
    config: &DaemonConfig,
    keys: Arc<ImmutableKeyProvider<EncryptedDevelopmentKeystore>>,
    now_unix_nanos: i128,
    active_tenants: &[RecordId],
    required_keys: &mut Vec<ProductionKeyRequirement>,
) -> Result<(Arc<dyn RepositoryBlobStore>, ProductionStore), DaemonError> {
    let settings = config
        .shared_storage
        .as_ref()
        .ok_or_else(bootstrap_failure)?;
    let runtime_url = read_restricted_text(
        &settings.postgres.runtime_url_file,
        MAX_STORAGE_SECRET_BYTES,
    )?;
    let mut postgres =
        PostgresConfiguration::new(runtime_url).map_err(|_error| bootstrap_failure())?;
    let certificate_authority = read_restricted_file(
        &settings.postgres.ca_certificate_file,
        MAX_POSTGRES_CA_BYTES,
    )?;
    postgres
        .configure_certificate_authority(
            settings.postgres.server_name.clone(),
            &certificate_authority,
        )
        .map_err(|_error| bootstrap_failure())?;
    postgres.minimum_connections = settings.postgres.minimum_connections;
    postgres.maximum_connections = settings.postgres.maximum_connections;
    postgres.acquire_timeout = Duration::from_millis(settings.postgres.acquire_timeout_ms);
    postgres.statement_timeout = Duration::from_millis(settings.postgres.statement_timeout_ms);
    postgres.lock_timeout = Duration::from_millis(settings.postgres.lock_timeout_ms);
    postgres.idle_transaction_timeout =
        Duration::from_millis(settings.postgres.idle_transaction_timeout_ms);
    postgres.validate().map_err(|_error| bootstrap_failure())?;

    let access_key =
        read_restricted_text(&settings.object.access_key_file, MAX_STORAGE_SECRET_BYTES)?;
    let secret_key =
        read_restricted_text(&settings.object.secret_key_file, MAX_STORAGE_SECRET_BYTES)?;
    let security_token = settings
        .object
        .security_token_file
        .as_ref()
        .map(|path| read_restricted_text(path, MAX_STORAGE_SECRET_BYTES))
        .transpose()?;
    let blinding_bytes = read_restricted_file(&settings.object.blinding_key_file, 32)?;
    let blinding_key: [u8; 32] = blinding_bytes
        .try_into()
        .map_err(|_error| bootstrap_failure())?;

    let wrapping_bytes =
        read_trusted_file(&settings.object.wrapping_keys_file, MAX_TRUSTED_FILE_BYTES)?;
    parse_strict_json(&wrapping_bytes).map_err(|_error| bootstrap_failure())?;
    let wrapping_file: ObjectWrappingKeysFile =
        serde_json::from_slice(&wrapping_bytes).map_err(|_error| bootstrap_failure())?;
    if wrapping_file.schema_version != "cigar.object-wrapping-keys.v1"
        || wrapping_file.keys.len() != active_tenants.len()
        || wrapping_file
            .keys
            .iter()
            .map(|entry| &entry.tenant_id)
            .ne(active_tenants.iter())
    {
        return Err(bootstrap_failure());
    }
    let mut wrapping_keys = BTreeMap::new();
    for entry in wrapping_file.keys {
        let metadata = keys
            .resolve(
                &entry.key_ref,
                entry.tenant_id.as_str(),
                KeyPurpose::BlobEncryption,
                now_unix_nanos,
            )
            .map_err(|_error| bootstrap_failure())?;
        if metadata.key_ref != entry.key_ref
            || metadata.tenant != entry.tenant_id.as_str()
            || metadata.purpose != KeyPurpose::BlobEncryption
            || metadata.algorithm != KeyAlgorithm::XChaCha20Poly1305
            || metadata.status != KeyStatus::Active
            || wrapping_keys
                .insert(entry.tenant_id.clone(), entry.key_ref.clone())
                .is_some()
        {
            return Err(bootstrap_failure());
        }
        required_keys.push(ProductionKeyRequirement {
            key_ref: entry.key_ref,
            tenant: entry.tenant_id.as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
        });
    }
    let object_storage = Arc::new(
        S3CompatibleObjectStorage::new(
            &settings.object.endpoint,
            &settings.object.region,
            &settings.object.bucket,
            &settings.object.prefix,
            access_key,
            secret_key,
            security_token,
            settings.object.path_style,
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    let objects = Arc::new(
        ObjectRepositoryBlobStore::new_multi_tenant(
            keys,
            object_storage,
            wrapping_keys,
            now_unix_nanos,
            blinding_key,
        )
        .map_err(|_error| bootstrap_failure())?,
    );
    let blob_repository: Arc<dyn RepositoryBlobStore> = objects;
    let store = PostgresStore::connect_with_blob_repository(postgres, Arc::clone(&blob_repository))
        .map_err(|_error| bootstrap_failure())?;
    Ok((blob_repository, ProductionStore::shared(store)))
}

fn read_restricted_text(path: &Path, maximum: u64) -> Result<String, DaemonError> {
    let mut bytes = read_restricted_file(path, maximum)?;
    if bytes.last() == Some(&b'\n') {
        let _newline = bytes.pop();
    }
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(bootstrap_failure());
    }
    String::from_utf8(bytes).map_err(|_error| bootstrap_failure())
}

fn install_policy(
    policy: &CompiledPolicyEngine,
    path: &Path,
    bytes: &[u8],
    activated_at: UtcTimestamp,
) -> Result<cigar_policy::PolicySnapshot, DaemonError> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => {
            parse_strict_json(bytes).map_err(|_error| bootstrap_failure())?;
            policy
                .install_json(bytes, activated_at)
                .map_err(|_error| bootstrap_failure())
        }
        Some("toml") => {
            let text = std::str::from_utf8(bytes).map_err(|_error| bootstrap_failure())?;
            policy
                .install_toml(text, activated_at)
                .map_err(|_error| bootstrap_failure())
        }
        _ => Err(bootstrap_failure()),
    }
}

fn authority_bootstrap_metadata(
    configuration: &crate::ProductionAuthorityConfiguration,
) -> Result<
    (
        RecordId,
        RecordId,
        Vec<ProductionKeyRequirement>,
        Vec<RecordId>,
    ),
    DaemonError,
> {
    let mut active_tenants = Vec::new();
    let mut required_keys = Vec::new();
    let mut recovery_actor = None;
    for tenant in configuration.tenants.iter().filter(|tenant| tenant.active) {
        active_tenants.push(tenant.tenant_id.clone());
        required_keys.push(ProductionKeyRequirement {
            key_ref: tenant.issuer_key_ref.clone(),
            tenant: tenant.tenant_id.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
        });
        if recovery_actor.is_none() {
            recovery_actor = tenant
                .principals
                .iter()
                .find(|principal| principal.active)
                .map(|principal| principal.principal_id.clone());
        }
    }
    active_tenants.sort();
    required_keys.sort_by(|left, right| left.tenant.cmp(&right.tenant));
    let system_tenant = active_tenants
        .first()
        .cloned()
        .ok_or_else(bootstrap_failure)?;
    let recovery_actor = recovery_actor.ok_or_else(bootstrap_failure)?;
    Ok((system_tenant, recovery_actor, required_keys, active_tenants))
}

fn prepare_directories(config: &DaemonConfig) -> Result<(), DaemonError> {
    checked_restricted_directory(&config.state_directory)?;
    checked_directory(&config.runtime_directory, true)?;
    checked_directory(&config.production.project_directory, false)?;
    if config.mode == DeploymentMode::Local {
        checked_restricted_directory(&config.production.blob_directory)?;
        checked_restricted_directory(&config.production.blob_key_reference_directory)?;
        let parent = config
            .production
            .metadata_database
            .parent()
            .ok_or_else(bootstrap_failure)?;
        checked_restricted_directory(parent)?;
        checked_optional_restricted_file(&config.production.metadata_database)?;
    }
    for file in [
        &config.production.keystore_file,
        &config.production.cursor_signing_key_file,
    ] {
        let parent = file.parent().ok_or_else(bootstrap_failure)?;
        checked_restricted_directory(parent)?;
        checked_optional_restricted_file(file)?;
    }
    let checkpoint_parent = config
        .production
        .effect_checkpoint_file
        .parent()
        .ok_or_else(bootstrap_failure)?;
    checked_effect_checkpoint_directory(checkpoint_parent, config.mode == DeploymentMode::Local)?;
    checked_optional_restricted_file(&config.production.effect_checkpoint_file)?;
    Ok(())
}

fn checked_effect_checkpoint_directory(path: &Path, create: bool) -> Result<(), DaemonError> {
    #[cfg(windows)]
    {
        let result = if create {
            cigar_windows_ipc::create_or_validate_owner_only_directory(path)
        } else {
            cigar_windows_ipc::validate_owner_only_directory(path)
        };
        result.map_err(|_error| bootstrap_failure())
    }
    #[cfg(not(windows))]
    {
        if create {
            checked_restricted_directory(path)
        } else {
            require_restricted_directory(path)
        }
    }
}

fn effect_store_is_empty(store: &ProductionStore) -> Result<bool, DaemonError> {
    match store {
        ProductionStore::Local(store) => store
            .effect_store_is_empty()
            .map_err(|_error| bootstrap_failure()),
        ProductionStore::Shared(_store) => Err(bootstrap_failure()),
    }
}

fn checked_restricted_directory(path: &Path) -> Result<(), DaemonError> {
    checked_directory(path, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(bootstrap_failure());
        }
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_error| bootstrap_failure())?;
        }
        let restricted = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
        if restricted.file_type().is_symlink()
            || !restricted.is_dir()
            || restricted.uid() != rustix::process::geteuid().as_raw()
            || restricted.permissions().mode() & 0o7777 != 0o700
        {
            return Err(bootstrap_failure());
        }
    }
    Ok(())
}

fn require_restricted_directory(path: &Path) -> Result<(), DaemonError> {
    checked_directory(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(bootstrap_failure());
        }
    }
    Ok(())
}

fn checked_directory(path: &Path, create: bool) -> Result<(), DaemonError> {
    if create && !path.exists() {
        std::fs::create_dir_all(path).map_err(|_error| bootstrap_failure())?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(bootstrap_failure());
    }
    if std::fs::canonicalize(path).map_err(|_error| bootstrap_failure())? != path {
        return Err(bootstrap_failure());
    }
    Ok(())
}

fn checked_optional_restricted_file(path: &Path) -> Result<(), DaemonError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_error) => return Err(bootstrap_failure()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || std::fs::canonicalize(path).map_err(|_error| bootstrap_failure())? != path
    {
        return Err(bootstrap_failure());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(bootstrap_failure());
        }
    }
    Ok(())
}

fn read_trusted_file(path: &Path, maximum: u64) -> Result<Vec<u8>, DaemonError> {
    read_regular_file(path, maximum, false)
}

fn read_restricted_file(path: &Path, maximum: u64) -> Result<Vec<u8>, DaemonError> {
    read_regular_file(path, maximum, true)
}

fn read_regular_file(path: &Path, maximum: u64, restricted: bool) -> Result<Vec<u8>, DaemonError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
        || std::fs::canonicalize(path).map_err(|_error| bootstrap_failure())? != path
    {
        return Err(bootstrap_failure());
    }
    #[cfg(unix)]
    if restricted {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(bootstrap_failure());
        }
    }
    #[cfg(not(unix))]
    let _ = restricted;
    let file = File::open(path).map_err(|_error| bootstrap_failure())?;
    let capacity = usize::try_from(metadata.len()).map_err(|_error| bootstrap_failure())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| bootstrap_failure())?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(bootstrap_failure());
    }
    Ok(bytes)
}

fn require_immutable_secret_file(path: &Path, exact_size: Option<u64>) -> Result<(), DaemonError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || exact_size.is_some_and(|size| metadata.len() != size)
        || std::fs::canonicalize(path).map_err(|_error| bootstrap_failure())? != path
    {
        return Err(bootstrap_failure());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o400 {
            return Err(bootstrap_failure());
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Err(bootstrap_failure());
    }
    Ok(())
}

fn load_existing_cursor_key(path: &Path) -> Result<CursorSigningKey, DaemonError> {
    require_immutable_secret_file(path, Some(CURSOR_KEY_BYTES as u64))?;
    let bytes = read_restricted_file(path, CURSOR_KEY_BYTES as u64)?;
    CursorSigningKey::new(bytes).map_err(|_error| bootstrap_failure())
}

fn load_or_create_cursor_key(path: &Path) -> Result<CursorSigningKey, DaemonError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != CURSOR_KEY_BYTES as u64
            {
                return Err(bootstrap_failure());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(bootstrap_failure());
                }
            }
            let bytes = read_restricted_file(path, CURSOR_KEY_BYTES as u64)?;
            CursorSigningKey::new(bytes).map_err(|_error| bootstrap_failure())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = vec![0_u8; CURSOR_KEY_BYTES];
            getrandom::fill(&mut bytes).map_err(|_error| bootstrap_failure())?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|_error| bootstrap_failure())?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_error| bootstrap_failure())?;
            CursorSigningKey::new(bytes).map_err(|_error| bootstrap_failure())
        }
        Err(_error) => Err(bootstrap_failure()),
    }
}

#[derive(Default)]
struct DeferredProductionChecks {
    inner: OnceLock<Arc<dyn ProductionDependencyChecks>>,
}

impl DeferredProductionChecks {
    fn install(&self, checks: Arc<dyn ProductionDependencyChecks>) -> Result<(), ()> {
        self.inner.set(checks).map_err(|_checks| ())
    }

    fn current(&self) -> Result<&Arc<dyn ProductionDependencyChecks>, LifecycleError> {
        self.inner.get().ok_or_else(LifecycleError::action_failed)
    }
}

macro_rules! delegate_check {
    ($name:ident) => {
        fn $name(&self) -> Result<(), LifecycleError> {
            self.current()?.$name()
        }
    };
}

impl ProductionDependencyChecks for DeferredProductionChecks {
    delegate_check!(migration_level);
    delegate_check!(blob_read_write);
    delegate_check!(policy_snapshot);
    delegate_check!(journal_integrity);
    delegate_check!(mandatory_index);
    delegate_check!(key_provider);
    delegate_check!(reconcile_orphan_blobs);
    delegate_check!(cleanup_expired_leases);
    delegate_check!(verify_worker_cursors);
    delegate_check!(recover_unreceipted_dispatches);
    delegate_check!(checkpoint_workers);
    delegate_check!(release_renewable_leases);

    fn process_worker_job(
        &self,
        kind: crate::WorkerKind,
        job: &crate::WorkerJob,
    ) -> Result<(), LifecycleError> {
        self.current()?.process_worker_job(kind, job)
    }

    fn poll_durable_work(&self) -> Result<bool, LifecycleError> {
        self.current()?.poll_durable_work()
    }
}

struct RecordedOnlyReplayServices;

impl LiveAuthorizationVerifier for RecordedOnlyReplayServices {
    fn verify_current(
        &self,
        _authorization: &LiveReplayAuthorization,
    ) -> Result<UtcTimestamp, ReplayError> {
        Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid))
    }
}

impl LiveReplayProvider for RecordedOnlyReplayServices {
    fn execute(&self, _invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError> {
        Err(ReplayError::new(ReplayErrorCode::LiveProviderFailure))
    }
}

impl LiveEffectGate for RecordedOnlyReplayServices {
    fn authorize_and_dispatch(&self, _dispatch: &LiveEffectDispatch) -> Result<(), ReplayError> {
        Err(ReplayError::new(
            ReplayErrorCode::EffectAuthorizationInvalid,
        ))
    }
}

impl ReplayLiveServicesFactory for RecordedOnlyReplayServices {
    fn for_tenant(
        &self,
        _tenant_id: &RecordId,
    ) -> Result<ReplayLiveServices, ReplayLiveServicesError> {
        let services = Arc::new(Self);
        Ok(ReplayLiveServices {
            verifier: services.clone(),
            provider: services.clone(),
            effect_gate: services,
        })
    }
}

const fn bootstrap_failure() -> DaemonError {
    DaemonError::new(DaemonErrorCode::ProductionBootstrapFailed)
}

#[cfg(test)]
mod tests {
    use super::{
        CURSOR_KEY_BYTES, compose_production_server, load_existing_cursor_key,
        require_immutable_secret_file,
    };
    use crate::{
        ApplicationResourceLimits, DaemonConfig, DeploymentMode, LocalIdentity,
        ProductionAuthorityConfiguration, ProductionPaths, ProductionPrincipalAuthority,
        ProductionTenantAuthority, TelemetrySettings, WorkerCapacities,
        execute_process_command_until,
    };
    use cigar_crypto::{
        CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider, KeyPurpose,
        SecretBytes,
    };
    use cigar_policy::PolicyProfile;
    use cigar_protocol::{
        Capability, Classification, ContentDigest, InstructionAuthority, RecordId, UtcTimestamp,
    };
    use cigar_store::{
        AccessContext, CancellationToken, EffectRecordEnvelope, Repository, SqliteStore,
        StoreRevision, WriteTransaction,
    };
    use sha2::{Digest as _, Sha256};
    use std::error::Error;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct Fixture {
        _directory: TempDir,
        config: DaemonConfig,
    }

    fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
        let hash = Sha256::digest(bytes);
        let suffix: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(ContentDigest::new(format!("1220{suffix}"))?)
    }

    fn restricted_write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        std::fs::write(path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn fixture() -> Result<Fixture, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let root = std::fs::canonicalize(directory.path())?;
        let state = root.join("state");
        let runtime = root.join("run");
        let project = root.join("project");
        let trusted = root.join("trusted");
        let secrets = root.join("secrets");
        for path in [&state, &runtime, &project, &trusted, &secrets] {
            std::fs::create_dir_all(path)?;
        }
        let project = std::fs::canonicalize(project)?;

        let passphrase_file = secrets.join("keystore-passphrase");
        let passphrase = b"0123456789abcdef0123456789abcdef";
        restricted_write(&passphrase_file, passphrase)?;
        let keystore_file = state.join("keystore.cigar");
        let keystore = EncryptedDevelopmentKeystore::open(
            &keystore_file,
            SecretBytes::new(passphrase.to_vec()),
        )?;
        let tenant = record(1)?;
        let project_id = record(2)?;
        let principal = record(3)?;
        let signing = keystore.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?.unix_nanos(),
            activated_at: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?.unix_nanos(),
        })?;
        drop(keystore);

        let local = LocalIdentity::from_project_root(&project)?;
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
                    principal_id: principal.clone(),
                    grant_id: record(4)?,
                    active: true,
                    operator: true,
                    not_before: UtcTimestamp::parse_rfc3339("2020-01-01T00:00:00Z")?,
                    expires_at: UtcTimestamp::parse_rfc3339("2099-01-01T00:00:00Z")?,
                    roles: vec!["developer".to_owned()],
                    project_ids: vec![project_id],
                    capabilities: vec![Capability::ReadContext],
                    delegatable_capabilities: Vec::new(),
                    purposes: vec!["catalog.read".to_owned()],
                    processors: vec!["local".to_owned()],
                    catalog_purpose: "catalog.read".to_owned(),
                    catalog_processor: "local".to_owned(),
                    maximum_classification: Classification::Restricted,
                    maximum_instruction_authority: InstructionAuthority::System,
                    residency_allowed: true,
                    egress_allowed: false,
                    vector_allowed: false,
                    handoff_target_allowed: false,
                    effect_rules: Vec::new(),
                }],
                revoked_principal_ids: Vec::new(),
                revoked_key_refs: Vec::new(),
            }],
        };
        let authority_file = trusted.join("authority.json");
        std::fs::write(&authority_file, serde_json::to_vec(&authority)?)?;
        let policy_file = trusted.join("policy.json");
        std::fs::write(
            &policy_file,
            serde_json::to_vec(&PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            })?,
        )?;
        let sources_file = trusted.join("sources.json");
        std::fs::write(
            &sources_file,
            br#"{"schema_version":"cigar.production-source-registry.v1","sources":[]}"#,
        )?;
        let effects_file = trusted.join("effects.json");
        std::fs::write(
            &effects_file,
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":false,"connectors":[]}"#,
        )?;

        let config = DaemonConfig {
            mode: DeploymentMode::Local,
            state_directory: state.clone(),
            runtime_directory: runtime.clone(),
            unix_socket: Some(runtime.join("cigard.sock")),
            windows_named_pipe: None,
            http_listen: None,
            grpc_listen: None,
            local_token_file: None,
            tls: None,
            oidc: None,
            production: ProductionPaths {
                project_directory: project,
                metadata_database: state.join("cigar.sqlite3"),
                blob_directory: state.join("blobs"),
                blob_key_reference_directory: state.join("blob-keys"),
                keystore_file,
                keystore_passphrase_file: passphrase_file,
                cursor_signing_key_file: state.join("cursor.key"),
                effect_checkpoint_file: root.join("effect-checkpoints/checkpoints.json"),
                policy_profile_file: policy_file,
                authority_file,
                source_registry_file: sources_file,
                effect_registry_file: effects_file,
            },
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
                export_timeout_ms: 1_000,
                metric_interval_ms: 1_000,
            },
        };
        config.validate()?;
        Ok(Fixture {
            _directory: directory,
            config,
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_server_starts_shuts_down_and_restarts_without_rotating_durable_keys()
    -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let first = compose_production_server(fixture.config.clone())?;
        let running = first.start().await?;
        assert_eq!(
            running.addresses().local_ipc.as_deref(),
            fixture.config.unix_socket.as_deref()
        );
        let first_receipt = running.shutdown().await?;
        assert!(first_receipt.shutdown.failed.is_none());
        let cursor_key = std::fs::read(&fixture.config.production.cursor_signing_key_file)?;
        assert_eq!(cursor_key.len(), super::CURSOR_KEY_BYTES);
        assert!(fixture.config.production.metadata_database.is_file());

        let second = compose_production_server(fixture.config.clone())?;
        let running = second.start().await?;
        let second_receipt = running.shutdown().await?;
        assert!(second_receipt.shutdown.failed.is_none());
        assert_eq!(
            std::fs::read(&fixture.config.production.cursor_signing_key_file)?,
            cursor_key
        );
        Ok(())
    }

    #[test]
    fn local_bootstrap_refuses_to_create_checkpoint_for_nonempty_effect_store()
    -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let checkpoint = fixture.config.production.effect_checkpoint_file.clone();
        assert!(!checkpoint.exists());

        let store = SqliteStore::open(&fixture.config.production.metadata_database)?;
        let bytes = b"preexisting-effect-without-external-checkpoint".to_vec();
        let envelope = EffectRecordEnvelope::new(record(90)?, 0, digest(&bytes)?, bytes)?;
        let mut write = store.begin_write(
            AccessContext::new(record(91)?, "bootstrap-checkpoint-guard")?,
            StoreRevision(0),
            CancellationToken::default(),
        )?;
        write.put_effect_record(envelope)?;
        write.commit(None)?;
        drop(store);

        assert!(compose_production_server(fixture.config).is_err());
        assert!(!checkpoint.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn shared_key_and_cursor_mounts_must_be_preprovisioned_owner_read_only()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = fixture()?;
        assert!(
            require_immutable_secret_file(&fixture.config.production.keystore_file, None).is_err()
        );
        std::fs::set_permissions(
            &fixture.config.production.keystore_file,
            std::fs::Permissions::from_mode(0o400),
        )?;
        require_immutable_secret_file(&fixture.config.production.keystore_file, None)?;

        let cursor = &fixture.config.production.cursor_signing_key_file;
        restricted_write(cursor, &[0x5a; CURSOR_KEY_BYTES])?;
        assert!(load_existing_cursor_key(cursor).is_err());
        std::fs::set_permissions(cursor, std::fs::Permissions::from_mode(0o400))?;
        assert!(load_existing_cursor_key(cursor).is_ok());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_process_serve_path_runs_real_composition_and_graceful_shutdown()
    -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let config_file = fixture._directory.path().join("cigard.toml");
        std::fs::write(&config_file, toml::to_string(&fixture.config)?)?;
        let outcome = execute_process_command_until(
            &[
                OsString::from("serve"),
                OsString::from("--config"),
                config_file.into_os_string(),
            ],
            std::future::ready(()),
        )
        .await;
        assert_eq!(outcome.status, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, "{\"status\":\"stopped\"}\n");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn trusted_configuration_symlink_is_rejected_without_echoing_path()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let fixture = fixture()?;
        let original = fixture.config.production.source_registry_file.clone();
        let target = PathBuf::from(format!("{}.target", original.display()));
        std::fs::rename(&original, &target)?;
        symlink(&target, &original)?;
        let error = match compose_production_server(fixture.config) {
            Ok(_server) => return Err("trusted symlink unexpectedly composed".into()),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            crate::DaemonErrorCode::ProductionBootstrapFailed
        );
        assert!(
            !error
                .to_string()
                .contains(original.to_string_lossy().as_ref())
        );
        Ok(())
    }
}
