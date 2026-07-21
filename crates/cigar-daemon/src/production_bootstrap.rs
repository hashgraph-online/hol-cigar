//! Fail-closed composition of the standalone production daemon.

use crate::{
    ApplicationIdGenerator, BlockingPool, CatalogContextApplication, DaemonConfig, DaemonError,
    DaemonErrorCode, DaemonFacadeErrorFactory, DaemonServer, DaemonTelemetry, DeploymentMode,
    DurableIdempotencyRepository, DurableLiveReplayAuthorizationRepository,
    EffectServiceDependencies, EffectServiceHandlers, EffectWorkerProcessor,
    EffectWorkerProcessorDependencies, LifecycleError, LiveReplayAuthorizationRepository,
    MonotonicApplicationIds, OperationalHandlers, PinnedContextTokenizerRegistry,
    ProductionDependencyChecks, ProductionDomainAuthority, ProductionEffectRecordAuthenticator,
    ProductionEffectRegistry, ProductionFacade, ProductionHandlerFamilies,
    ProductionKeyRequirement, ProductionRuntimeError, ProductionSourceRegistry, ProductionStore,
    ReplayLiveServices, ReplayLiveServicesError, ReplayLiveServicesFactory,
    ReplayServiceDependencies, ReplayServiceHandlers, RepositoryCatalogIndex,
    RepositoryProductionChecksDependencies, RepositoryProductionDependencyChecks,
    RepositorySpaceHandoffStateProvider, SpaceHandoffApplication, SystemAuthorityClock,
    SystemProductionUnixClock, SystemRuntimeClock, SystemSpaceHandoffValueSource,
    compose_complete_production_application, compose_repository_runtime_with_facade,
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
use cigar_store::migrate_v5::read_active_store_descriptor_v1;
use cigar_store::{
    MultiTenantLocalRepositoryBlobStore, ObjectRepositoryBlobStore, PostgresConfiguration,
    PostgresStore, RepositoryBlobStore, S3CompatibleObjectStorage, ServiceRepository, SqliteStore,
    SqliteV5Store,
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
const MAX_OTLP_CA_BYTES: u64 = 2 * 1024 * 1024;
const MAX_KEYSTORE_BYTES: u64 = 16 * 1024 * 1024;
const CURSOR_KEY_BYTES: usize = 32;
const MAX_PRODUCTION_TENANTS: usize = 1_024;
const MAX_PRODUCTION_EFFECT_RECORDS: usize = 1_000_000;
const CURSOR_TTL: Duration = Duration::from_secs(15 * 60);
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Exact reviewed profile selected by the macOS production live-replay composition API.
pub const PRODUCTION_LIVE_REPLAY_PROFILE_V1: &str = "cigar.production-live-replay.tenant-bound.v1";

/// Explicit tenant-bound dependencies required to enable production live comparison.
///
/// The standalone `cigard` composition never constructs this profile and remains recorded-only.
/// An embedding application must inject a separately governed authorization repository plus a
/// tenant-scoped verifier/provider/effect-gate factory through
/// [`compose_production_server_with_live_replay`]. Keeping the fields private prevents a partial
/// profile from silently enabling only one live boundary.
pub struct ProductionLiveReplayProfile {
    authorizations: Arc<dyn LiveReplayAuthorizationRepository>,
    services: Arc<dyn ReplayLiveServicesFactory>,
}

impl ProductionLiveReplayProfile {
    /// Creates the reviewed v1 profile from explicit, application-owned security boundaries.
    #[must_use]
    pub fn tenant_bound_v1(
        authorizations: Arc<dyn LiveReplayAuthorizationRepository>,
        services: Arc<dyn ReplayLiveServicesFactory>,
    ) -> Self {
        Self {
            authorizations,
            services,
        }
    }

    /// Returns the exact security-profile identifier for audit and configuration receipts.
    #[must_use]
    pub const fn security_profile(&self) -> &'static str {
        PRODUCTION_LIVE_REPLAY_PROFILE_V1
    }
}

impl std::fmt::Debug for ProductionLiveReplayProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionLiveReplayProfile")
            .field("security_profile", &PRODUCTION_LIVE_REPLAY_PROFILE_V1)
            .field("authorizations", &"[INJECTED]")
            .field("services", &"[TENANT-BOUND]")
            .finish()
    }
}

struct ActiveTenantReplayLiveServices {
    active_tenants: Vec<RecordId>,
    inner: Arc<dyn ReplayLiveServicesFactory>,
}

impl ReplayLiveServicesFactory for ActiveTenantReplayLiveServices {
    fn for_tenant(
        &self,
        tenant_id: &RecordId,
    ) -> Result<ReplayLiveServices, ReplayLiveServicesError> {
        if self.active_tenants.binary_search(tenant_id).is_err() {
            return Err(ReplayLiveServicesError);
        }
        self.inner.for_tenant(tenant_id)
    }
}

fn production_http_transport_factory(
    mode: DeploymentMode,
    registry: &ProductionEffectRegistry,
    dispatch_gate: Arc<dyn crate::EffectDispatchGate>,
) -> Result<Option<Arc<dyn crate::ProductionHttpTransportFactory>>, ProductionRuntimeError> {
    if !registry.requires_live_http() {
        return Ok(None);
    }
    if mode != DeploymentMode::Local {
        return Err(ProductionRuntimeError::InvalidConfiguration);
    }
    #[cfg(target_os = "macos")]
    {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_error| ProductionRuntimeError::RuntimeUnavailable)?;
        Ok(Some(Arc::new(
            crate::StockHttpsEffectTransportFactory::new(runtime, dispatch_gate),
        )))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _dispatch_gate = dispatch_gate;
        Err(ProductionRuntimeError::InvalidConfiguration)
    }
}

/// Composes the exact standalone daemon from one validated production configuration.
///
/// Construction performs no listener bind. It does open and verify every durable/trusted
/// dependency, provisions configured sources, reconstructs the mandatory catalog index, and
/// installs a complete governed 45-operation facade. No in-memory healthy substitute is used for
/// a missing production dependency.
pub fn compose_production_server(config: DaemonConfig) -> Result<DaemonServer, DaemonError> {
    compose_production_server_internal(config, None)
}

/// Composes a local macOS production server with an explicitly injected live-replay profile.
///
/// This is the only stock production composition that can reach a live replay provider. The
/// caller owns provider qualification and authorization issuance. The replay engine still
/// requires one-use, current-policy authorization and accepts only new effect identities through
/// the independently injected effect gate. Shared and non-macOS profiles fail closed.
pub fn compose_production_server_with_live_replay(
    config: DaemonConfig,
    profile: ProductionLiveReplayProfile,
) -> Result<DaemonServer, DaemonError> {
    if config.mode != DeploymentMode::Local || !cfg!(target_os = "macos") {
        return Err(bootstrap_failure());
    }
    compose_production_server_internal(config, Some(profile))
}

fn compose_production_server_internal(
    config: DaemonConfig,
    live_replay_profile: Option<ProductionLiveReplayProfile>,
) -> Result<DaemonServer, DaemonError> {
    config.validate().map_err(|_error| bootstrap_failure())?;
    // Install the workspace-selected provider only when an embedding process has not already
    // selected one. This covers local OTLP/TLS clients as well as shared listener/JWKS paths.
    let _provider_result = rustls::crypto::ring::default_provider().install_default();
    prepare_directories(&config)?;

    let clock: Arc<dyn crate::AuthorityClock> = Arc::new(SystemAuthorityClock);
    let now = clock.now().map_err(|_error| bootstrap_failure())?;
    let passphrase = SecretBytes::new(read_restricted_file(
        &config.production.keystore_passphrase_file,
        MAX_PASSPHRASE_BYTES,
    )?);
    let keys = Arc::new(match config.mode {
        DeploymentMode::Local => {
            EncryptedDevelopmentKeystore::open(&config.production.keystore_file, passphrase)
                .map_err(|_error| bootstrap_failure())?
        }
        DeploymentMode::Shared => {
            let encoded =
                read_immutable_file(&config.production.keystore_file, MAX_KEYSTORE_BYTES, None)?;
            EncryptedDevelopmentKeystore::open_existing_bytes(
                &config.production.keystore_file,
                passphrase,
                &encoded,
            )
            .map_err(|_error| bootstrap_failure())?
        }
    });
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

    let otlp_ca = config
        .telemetry
        .otlp_ca_certificate_file
        .as_ref()
        .map(|path| read_trusted_file(path, MAX_OTLP_CA_BYTES))
        .transpose()?;
    let telemetry = Arc::new(
        match config
            .telemetry
            .otlp_config(otlp_ca)
            .map_err(|_error| bootstrap_failure())?
        {
            Some(otlp) => DaemonTelemetry::with_otlp(otlp).map_err(|_error| bootstrap_failure())?,
            None => DaemonTelemetry::local(),
        },
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
            let commit_observer: Arc<dyn cigar_store::RepositoryCommitMetricsObserver> =
                telemetry.clone();
            let startup_observer: Arc<dyn cigar_store::RepositoryStartupMetricsObserver> =
                telemetry.clone();
            let store =
                if let Some(descriptor_path) = config.production.active_store_descriptor.as_ref() {
                    let descriptor = read_active_store_descriptor_v1(descriptor_path)
                        .map_err(|_error| bootstrap_failure())?;
                    let database = Path::new(descriptor.database_path());
                    if database == config.state_directory
                        || !database.starts_with(&config.state_directory)
                    {
                        return Err(bootstrap_failure());
                    }
                    ProductionStore::local_v5(
                        SqliteV5Store::open_with_blob_repository_capacity_and_startup_metrics(
                            database,
                            Arc::clone(&blob_repository),
                            config.local_sqlite_capacity_profile,
                            startup_observer,
                        )
                        .map_err(|_error| bootstrap_failure())?
                        .with_commit_metrics_observer(commit_observer),
                    )
                } else {
                    ProductionStore::local(
                        SqliteStore::open_with_blob_repository_capacity_and_startup_metrics(
                            &config.production.metadata_database,
                            Arc::clone(&blob_repository),
                            config.local_sqlite_capacity_profile,
                            startup_observer,
                        )
                        .map_err(|_error| bootstrap_failure())?
                        .with_commit_metrics_observer(commit_observer),
                    )
                };
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
    #[cfg(target_os = "macos")]
    let local_vector = if config.local_vector.enabled {
        Some(Arc::new(
            crate::ProductionLocalVectorRuntime::new(&config.local_vector)
                .map_err(|_error| bootstrap_failure())?,
        ))
    } else {
        None
    };
    let manager = Arc::new(InMemoryIndexManager::default());
    let index_worker = Arc::new(IndexWorker::default());
    let tenant_provider: Arc<dyn crate::ProductionTenantProvider> = authority.clone();
    let catalog_index = RepositoryCatalogIndex::new(
        Arc::clone(&store),
        Arc::clone(&tenant_provider),
        Arc::clone(&manager),
        Arc::clone(&index_worker),
        Arc::clone(&clock),
    )
    .map_err(|_error| bootstrap_failure())?
    .with_telemetry(Arc::clone(&telemetry));
    #[cfg(target_os = "macos")]
    let catalog_index = if let Some(runtime) = &local_vector {
        catalog_index.with_local_vector_runtime(Arc::clone(runtime))
    } else {
        catalog_index
    };
    let catalog_index = Arc::new(catalog_index);
    catalog_index
        .rebuild()
        .map_err(|_error| bootstrap_failure())?;

    let identities: Arc<dyn crate::DomainIdentityResolver> = authority.clone();
    let catalog_authorizer: Arc<dyn crate::CatalogContextAuthorizer> = authority.clone();
    let retriever: Arc<dyn Retriever> = manager.clone();
    let tokenizer_registry = production_tokenizer_registry()?;
    let catalog = CatalogContextApplication::new(
        Arc::clone(&store),
        Arc::clone(&identities),
        catalog_authorizer,
        retriever,
        tokenizer_registry,
        Arc::clone(&blocking_pool),
        Arc::clone(&clock),
        Arc::clone(&errors),
    );
    #[cfg(target_os = "macos")]
    let catalog = if let Some(runtime) = &local_vector {
        catalog.with_query_vector_processor(runtime.query_processor())
    } else {
        catalog
    };
    let catalog = catalog.with_telemetry(Arc::clone(&telemetry));
    let catalog = Arc::new(catalog);
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
        .map_err(|_error| bootstrap_failure())?
        .with_telemetry(Arc::clone(&telemetry)),
    );
    let (live_authorizations, live_services): (
        Arc<dyn LiveReplayAuthorizationRepository>,
        Arc<dyn ReplayLiveServicesFactory>,
    ) = match live_replay_profile {
        Some(profile) => (
            profile.authorizations,
            Arc::new(ActiveTenantReplayLiveServices {
                active_tenants: active_tenants.clone(),
                inner: profile.services,
            }),
        ),
        None => (
            Arc::new(DurableLiveReplayAuthorizationRepository::new(Arc::clone(
                &service_repository,
            ))),
            Arc::new(RecordedOnlyReplayServices),
        ),
    };
    let replay = Arc::new(ReplayServiceHandlers::new(ReplayServiceDependencies {
        repository: Arc::clone(&service_repository),
        identities: Arc::clone(&identities),
        live_authorizations,
        live_services,
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
            let effects_enabled = effect_registry.effects_enabled;
            let dispatch_gate: Arc<dyn crate::EffectDispatchGate> = inputs.workers.clone();
            let http_transports = production_http_transport_factory(
                facade_config.mode,
                &effect_registry,
                dispatch_gate,
            )?;
            let effect_components = effect_registry
                .compose(Arc::clone(&blob_repository), http_transports)
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?;
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
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?
                .with_telemetry(Arc::clone(&inputs.telemetry)),
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
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?
                .with_telemetry(Arc::clone(&inputs.telemetry)),
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
                .map_err(|_error| ProductionRuntimeError::InvalidConfiguration)?
                .with_telemetry(Arc::clone(&inputs.telemetry)),
            );
            let checks: Arc<dyn ProductionDependencyChecks> = checks;
            deferred_checks
                .install(checks)
                .map_err(|()| ProductionRuntimeError::InvalidConfiguration)?;

            let operational = Arc::new(
                OperationalHandlers::new_with_blocking_pool(
                    &facade_config,
                    inputs.readiness,
                    inputs.readiness_gate,
                    inputs.workers,
                    Arc::clone(&inputs.blocking_pool),
                    inputs.telemetry,
                    Arc::clone(&errors),
                )
                .with_effects_enabled(effects_enabled),
            );
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
        #[cfg(target_os = "macos")]
        if config.local_vector.enabled {
            checked_restricted_directory(
                config
                    .local_vector
                    .root_directory
                    .as_deref()
                    .ok_or_else(bootstrap_failure)?,
            )?;
        }
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
        ProductionStore::LocalV5(store) => store
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
    read_regular_file(path, maximum, ProductionFilePolicy::Trusted, None)
}

fn read_restricted_file(path: &Path, maximum: u64) -> Result<Vec<u8>, DaemonError> {
    read_regular_file(path, maximum, ProductionFilePolicy::Restricted, None)
}

fn read_immutable_file(
    path: &Path,
    maximum: u64,
    exact_size: Option<u64>,
) -> Result<Vec<u8>, DaemonError> {
    read_regular_file(path, maximum, ProductionFilePolicy::Immutable, exact_size)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionFilePolicy {
    Trusted,
    Restricted,
    Immutable,
}

fn read_regular_file(
    path: &Path,
    maximum: u64,
    policy: ProductionFilePolicy,
    exact_size: Option<u64>,
) -> Result<Vec<u8>, DaemonError> {
    let link = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
    if link.file_type().is_symlink()
        || !link.is_file()
        || link.len() == 0
        || link.len() > maximum
        || exact_size.is_some_and(|size| link.len() != size)
        || std::fs::canonicalize(path).map_err(|_error| bootstrap_failure())? != path
    {
        return Err(bootstrap_failure());
    }
    let mut file = open_bounded_read(path).map_err(|_error| bootstrap_failure())?;
    let opened = file.metadata().map_err(|_error| bootstrap_failure())?;
    if !opened.is_file()
        || opened.len() == 0
        || opened.len() > maximum
        || exact_size.is_some_and(|size| opened.len() != size)
        || !same_regular_file(&link, &opened)
        || !safe_production_metadata(&opened, policy)
    {
        return Err(bootstrap_failure());
    }
    let capacity = usize::try_from(opened.len()).map_err(|_error| bootstrap_failure())?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_error| bootstrap_failure())?;
    let after_read = file.metadata().map_err(|_error| bootstrap_failure())?;
    let final_link = std::fs::symlink_metadata(path).map_err(|_error| bootstrap_failure())?;
    if final_link.file_type().is_symlink()
        || !same_regular_file(&opened, &after_read)
        || !same_regular_file(&after_read, &final_link)
        || !stable_regular_file(&opened, &after_read)
        || std::fs::canonicalize(path).map_err(|_error| bootstrap_failure())? != path
        || bytes.is_empty()
        || u64::try_from(bytes.len()).map_or(true, |length| {
            length > maximum
                || length != after_read.len()
                || exact_size.is_some_and(|size| length != size)
        })
    {
        return Err(bootstrap_failure());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_regular_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_regular_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

#[cfg(unix)]
fn stable_regular_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
}

#[cfg(not(unix))]
fn stable_regular_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn safe_production_metadata(metadata: &std::fs::Metadata, policy: ProductionFilePolicy) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let owner = metadata.uid();
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.nlink() != 1 {
            return false;
        }
        match policy {
            ProductionFilePolicy::Trusted => {
                (owner == 0 || owner == effective_uid) && metadata.mode() & 0o022 == 0
            }
            ProductionFilePolicy::Restricted => {
                owner == effective_uid && metadata.mode() & 0o077 == 0
            }
            ProductionFilePolicy::Immutable => {
                owner == effective_uid && metadata.mode() & 0o777 == 0o400
            }
        }
    }
    #[cfg(not(unix))]
    {
        match policy {
            ProductionFilePolicy::Immutable => metadata.permissions().readonly(),
            ProductionFilePolicy::Trusted | ProductionFilePolicy::Restricted => metadata.is_file(),
        }
    }
}

#[cfg(unix)]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::path::Component;

    let mut absolute = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if names.is_empty() && !absolute => absolute = true,
            Component::Normal(name) => names.push(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(invalid_read_path()),
        }
    }
    if !absolute {
        return Err(invalid_read_path());
    }
    let (file_name, ancestors) = names.split_last().ok_or_else(invalid_read_path)?;
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)?;
    validate_read_ancestor(&directory.metadata()?)?;
    for ancestor in ancestors {
        directory = openat(
            &directory,
            *ancestor,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)?;
        validate_read_ancestor(&directory.metadata()?)?;
    }
    openat(
        &directory,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(unix)]
fn validate_read_ancestor(metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = metadata.uid();
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_root = owner == 0 && mode & 0o1000 != 0;
    if metadata.is_dir()
        && (owner == 0 || owner == rustix::process::geteuid().as_raw())
        && (!writable_by_others || protected_sticky_root)
    {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe file ancestor",
        ))
    }
}

#[cfg(unix)]
fn invalid_read_path() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid file path")
}

#[cfg(not(unix))]
fn open_bounded_read(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn load_existing_cursor_key(path: &Path) -> Result<CursorSigningKey, DaemonError> {
    let bytes = read_immutable_file(path, CURSOR_KEY_BYTES as u64, Some(CURSOR_KEY_BYTES as u64))?;
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

fn production_tokenizer_registry() -> Result<Arc<PinnedContextTokenizerRegistry>, DaemonError> {
    Ok(Arc::new(
        PinnedContextTokenizerRegistry::with_reference_profiles()
            .map_err(|_error| bootstrap_failure())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveTenantReplayLiveServices, CURSOR_KEY_BYTES, MAX_KEYSTORE_BYTES,
        PRODUCTION_LIVE_REPLAY_PROFILE_V1, ProductionLiveReplayProfile, compose_production_server,
        load_existing_cursor_key, production_http_transport_factory, production_tokenizer_registry,
        read_immutable_file,
    };
    use crate::{
        ApplicationResourceLimits, DaemonConfig, DeploymentMode, LiveAuthorizationRepositoryError,
        LiveReplayAuthorizationRepository, LocalIdentity, ProductionAuthorityConfiguration,
        ProductionEffectRegistry, ProductionPaths, ProductionPrincipalAuthority,
        ProductionTenantAuthority, ReplayLiveServices, ReplayLiveServicesError,
        ReplayLiveServicesFactory, TelemetrySettings, WorkerCapacities,
        execute_process_command_until,
    };
    use cigar_compiler::ReferenceTokenizerProfile;
    use cigar_crypto::{
        CreateKeyRequest, EncryptedDevelopmentKeystore, KeyAlgorithm, KeyProvider, KeyPurpose,
        SecretBytes,
    };
    use cigar_policy::PolicyProfile;
    use cigar_protocol::{
        Capability, Classification, ContentDigest, InstructionAuthority, RecordId, UtcTimestamp,
    };
    use cigar_replay::LiveReplayAuthorization;
    use cigar_store::migrate_v5::{
        MigrationActivationPathsV5, MigrationPathsV5, MigrationReceiptIdentity,
        activate_v5_migration, migrate_v4_to_v5, preflight_v4_to_v5_migration,
        sign_migration_receipt_v1,
    };
    use cigar_store::{
        AccessContext, BackupErrorCode, BackupIdentity, CancellationToken, EffectRecordEnvelope,
        MultiTenantLocalRepositoryBlobStore, Repository, RepositoryBlobStore, ServiceBatch,
        ServiceExpectedVersion, ServiceRecordWrite, ServiceRepository, ServiceResponse,
        SqliteCapacityProfile, SqliteStore, SqliteV5Store, StoreRevision, WriteTransaction,
        create_backup_with_effect_checkpoint,
    };
    use sha2::{Digest as _, Sha256};
    use std::error::Error;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct Fixture {
        _directory: TempDir,
        config: DaemonConfig,
    }

    struct OpenDispatchGate;

    impl crate::EffectDispatchGate for OpenDispatchGate {
        fn dispatch_claims_allowed(&self) -> bool {
            true
        }
    }

    struct MissingLiveAuthorizations;

    impl LiveReplayAuthorizationRepository for MissingLiveAuthorizations {
        fn get(
            &self,
            _tenant_id: &RecordId,
            _authorization_id: &RecordId,
            _cancellation: &CancellationToken,
        ) -> Result<LiveReplayAuthorization, LiveAuthorizationRepositoryError> {
            Err(LiveAuthorizationRepositoryError::NotFound)
        }
    }

    #[derive(Default)]
    struct CountingLiveServices {
        calls: AtomicUsize,
    }

    impl ReplayLiveServicesFactory for CountingLiveServices {
        fn for_tenant(
            &self,
            _tenant_id: &RecordId,
        ) -> Result<ReplayLiveServices, ReplayLiveServicesError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ReplayLiveServicesError)
        }
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

    #[test]
    fn live_replay_profile_is_explicit_complete_and_active_tenant_scoped()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(80)?;
        let other_tenant = record(81)?;
        let concrete_services = Arc::new(CountingLiveServices::default());
        let services: Arc<dyn ReplayLiveServicesFactory> = concrete_services.clone();
        let authorizations: Arc<dyn LiveReplayAuthorizationRepository> =
            Arc::new(MissingLiveAuthorizations);
        let profile =
            ProductionLiveReplayProfile::tenant_bound_v1(authorizations, services.clone());
        assert_eq!(
            profile.security_profile(),
            PRODUCTION_LIVE_REPLAY_PROFILE_V1
        );
        let debug = format!("{profile:?}");
        assert!(debug.contains(PRODUCTION_LIVE_REPLAY_PROFILE_V1));
        assert!(!debug.contains("MissingLiveAuthorizations"));
        assert!(!debug.contains("CountingLiveServices"));

        let scoped = ActiveTenantReplayLiveServices {
            active_tenants: vec![tenant.clone()],
            inner: services,
        };
        assert!(scoped.for_tenant(&other_tenant).is_err());
        assert_eq!(concrete_services.calls.load(Ordering::SeqCst), 0);
        assert!(scoped.for_tenant(&tenant).is_err());
        assert_eq!(concrete_services.calls.load(Ordering::SeqCst), 1);
        Ok(())
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

    #[test]
    fn disabled_effects_do_not_construct_a_runtime_or_transport() -> Result<(), Box<dyn Error>> {
        let registry = ProductionEffectRegistry::from_json(
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":false,"connectors":[]}"#,
        )?;
        let gate: Arc<dyn crate::EffectDispatchGate> = Arc::new(OpenDispatchGate);
        assert!(
            production_http_transport_factory(DeploymentMode::Local, &registry, gate)?.is_none()
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_http_factory_is_local_macos_only_and_shared_fails_closed()
    -> Result<(), Box<dyn Error>> {
        let registry = ProductionEffectRegistry::from_json(
            br#"{"schema_version":"cigar.production-effect-registry.v1","effects_enabled":true,"connectors":[{"name":"http","kind":"idempotent_http","endpoint":"https://effects.example.invalid/v1/effects","https_transport":{"provider_protocol":"cigar.idempotent-effect-http.v1","credential_handle":"credential-a","credential_file":"/private/tmp/cigar-effect-credential.json","pinned_addresses":["93.184.216.34"],"connect_timeout_ms":1000,"request_timeout_ms":2000,"maximum_response_bytes":16384},"argument_vault_provider":"repository_blob_json.v1"}]}"#,
        )?;
        let local_gate: Arc<dyn crate::EffectDispatchGate> = Arc::new(OpenDispatchGate);
        assert!(
            production_http_transport_factory(DeploymentMode::Local, &registry, local_gate)?
                .is_some()
        );
        let shared_gate: Arc<dyn crate::EffectDispatchGate> = Arc::new(OpenDispatchGate);
        assert!(
            production_http_transport_factory(DeploymentMode::Shared, &registry, shared_gate)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn production_registry_contains_only_stable_reference_tokenizers_across_restarts()
    -> Result<(), Box<dyn Error>> {
        let first = production_tokenizer_registry()?;
        let restarted = production_tokenizer_registry()?;
        let materializer = ContentDigest::new(format!("1220{}", "aa".repeat(32)))?;
        for profile in ReferenceTokenizerProfile::ALL {
            let target = profile.target_profile(materializer.clone(), 4_096)?;
            let first_tokenizer =
                crate::ContextTokenizerRegistry::tokenizer(first.as_ref(), &target)
                    .ok_or("production reference tokenizer unavailable")?;
            let restarted_tokenizer =
                crate::ContextTokenizerRegistry::tokenizer(restarted.as_ref(), &target)
                    .ok_or("restarted reference tokenizer unavailable")?;
            assert_eq!(first_tokenizer.fingerprint(), &target.tokenizer_fingerprint);
            assert_eq!(
                restarted_tokenizer.fingerprint(),
                &target.tokenizer_fingerprint
            );
            assert_eq!(
                first_tokenizer.count_exact("CIGAR Δ".as_bytes())?,
                restarted_tokenizer.count_exact("CIGAR Δ".as_bytes())?
            );
        }
        let mut external =
            ReferenceTokenizerProfile::Utf8BytesV1.target_profile(materializer, 4_096)?;
        external.provider = "anthropic".to_owned();
        assert!(crate::ContextTokenizerRegistry::tokenizer(first.as_ref(), &external).is_none());
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
            local_sqlite_capacity_profile: cigar_store::SqliteCapacityProfile::Standard,
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
                active_store_descriptor: None,
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
            local_vector: crate::LocalVectorSettings::default(),
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

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn activated_v5_descriptor_drives_production_restarts_and_only_v5_writes()
    -> Result<(), Box<dyn Error>> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut fixture = fixture()?;
        let initialized = compose_production_server(fixture.config.clone())?
            .start()
            .await?;
        assert!(initialized.shutdown().await?.shutdown.failed.is_none());
        let source = fixture.config.production.metadata_database.clone();
        let target = fixture.config.state_directory.join("cigar-v5.sqlite3");
        let descriptor = fixture.config.state_directory.join("active-store.json");
        let backup = fixture.config.state_directory.join("verified-v4-backup");
        let passphrase = std::fs::read(&fixture.config.production.keystore_passphrase_file)?;
        let provider = Arc::new(EncryptedDevelopmentKeystore::open(
            &fixture.config.production.keystore_file,
            SecretBytes::new(passphrase.clone()),
        )?);
        let signing = provider.create(CreateKeyRequest {
            tenant: "migration-tenant".to_owned(),
            purpose: KeyPurpose::Signing,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: 1,
            activated_at: 1,
        })?;
        let checkpoint_bytes = std::fs::read(&fixture.config.production.effect_checkpoint_file)?;
        let source_store = SqliteStore::open(&source)?;
        create_backup_with_effect_checkpoint(
            &source_store,
            &fixture.config.production.blob_directory,
            &backup,
            provider.as_ref(),
            BackupIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
                created_at_unix_nanos: 2,
            },
            |_database, checkpoint| {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(checkpoint)
                    .map_err(|_error| BackupErrorCode::Unavailable)?;
                file.write_all(&checkpoint_bytes)
                    .map_err(|_error| BackupErrorCode::Unavailable)?;
                file.sync_all()
                    .map_err(|_error| BackupErrorCode::Unavailable)
            },
        )?;
        drop(source_store);
        let preflight = preflight_v4_to_v5_migration(
            MigrationPathsV5::resolve(&source, &backup, &target)?,
            provider.as_ref(),
            3,
            |_identity| true,
        )
        .map_err(|error| std::io::Error::other(format!("migration preflight: {error:?}")))?;
        let migrated = migrate_v4_to_v5(preflight, 4)
            .map_err(|error| std::io::Error::other(format!("migration build: {error:?}")))?;
        let migrated_head = migrated.latest_revision;
        let signed = sign_migration_receipt_v1(
            migrated.completed_receipt(),
            provider.as_ref(),
            MigrationReceiptIdentity {
                signing_key: &signing.key_ref,
                tenant: "migration-tenant",
                signer: "migration-operator",
            },
        )?;
        let mut receipt_value = target.as_os_str().to_os_string();
        receipt_value.push(".cigar-migration-receipt.json");
        let receipt = PathBuf::from(receipt_value);
        restricted_write(&receipt, &serde_json::to_vec(&signed)?)?;
        activate_v5_migration(
            MigrationActivationPathsV5::resolve(&source, &backup, &target, &receipt, &descriptor)?,
            provider.as_ref(),
            5,
            |_identity| true,
            |_identity| true,
        )
        .map_err(|error| std::io::Error::other(format!("migration activation: {error:?}")))?;

        let blob_store: Arc<dyn RepositoryBlobStore> =
            Arc::new(MultiTenantLocalRepositoryBlobStore::open(
                &fixture.config.production.blob_directory,
                &fixture.config.production.blob_key_reference_directory,
                Arc::clone(&provider),
                6,
            )?);
        let v5 = SqliteV5Store::open_with_blob_repository_and_capacity_profile(
            &target,
            Arc::clone(&blob_store),
            SqliteCapacityProfile::Standard,
        )
        .map_err(|error| std::io::Error::other(format!("first v5 runtime open: {error:?}")))?;
        let receipt = v5
            .service_commit(
                ServiceBatch::new(
                    record(1)?,
                    vec![ServiceRecordWrite::new(
                        "runtime",
                        "activated-v5",
                        ServiceExpectedVersion::Absent,
                        b"v5-only".to_vec(),
                    )?],
                    ServiceResponse::new(200, "application/json", b"ok".to_vec())?,
                )?,
                &CancellationToken::default(),
            )
            .map_err(|error| std::io::Error::other(format!("v5 service commit: {error:?}")))?;
        let v5_revision = StoreRevision(
            migrated_head
                .0
                .checked_add(1)
                .ok_or("test revision overflow")?,
        );
        assert_eq!(receipt.revision, v5_revision);
        drop(v5);

        fixture.config.production.active_store_descriptor = Some(descriptor);
        for _restart in 0..2 {
            let running = compose_production_server(fixture.config.clone())
                .map_err(|error| std::io::Error::other(format!("v5 daemon compose: {error:?}")))?
                .start()
                .await?;
            assert!(running.shutdown().await?.shutdown.failed.is_none());
        }
        assert_eq!(SqliteStore::open(&source)?.revision()?, migrated_head);
        let restarted_v5_revision = SqliteV5Store::open_with_blob_repository_and_capacity_profile(
            &target,
            blob_store,
            SqliteCapacityProfile::Standard,
        )?
        .revision()?;
        assert!(
            restarted_v5_revision.0 > v5_revision.0,
            "production restarts must advance the selected v5 delta chain"
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
            read_immutable_file(
                &fixture.config.production.keystore_file,
                MAX_KEYSTORE_BYTES,
                None
            )
            .is_err()
        );
        std::fs::set_permissions(
            &fixture.config.production.keystore_file,
            std::fs::Permissions::from_mode(0o400),
        )?;
        let _keystore = read_immutable_file(
            &fixture.config.production.keystore_file,
            MAX_KEYSTORE_BYTES,
            None,
        )?;

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
        // Strict configuration readers reject every symlinked ancestor. macOS exposes the
        // temporary root through `/var`, which is an alias of `/private/var`, so exercise the
        // documented physical-path contract here.
        let config_file = fixture
            ._directory
            .path()
            .canonicalize()?
            .join("cigard.toml");
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
