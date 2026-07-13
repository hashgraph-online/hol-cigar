//! Typed CatalogService and ContextService application adapters.
//!
//! This module is the authority boundary between caller-controlled API DTOs and the trusted
//! catalog, retrieval, compiler, policy, clock, and repository inputs required by WP04-WP08.

use crate::{
    AuthorityClock, BlockingPool, BlockingPoolErrorCode, DomainIdentityResolver,
    ProductionApplicationBuilder, ResolvedDomainIdentity,
};
use cigar_api::{
    ApiError, AtomBatchResponse, AtomIdRequest, AtomLookupResult, BatchAtomsOperation,
    BatchAtomsRequest, BundleIdRequest, CatalogQueryResponse, CompileContextBundleOperation,
    CompileContextBundleRequest, CompileContextDeltaOperation, CompileContextDeltaRequest,
    ContextDeltaResponse, ContextExplanationEntry, ContextExplanationResponse, ContextPlanResponse,
    CreateContextPlanOperation, CreateContextPlanRequest, DiscoverSourcesOperation,
    DiscoverSourcesRequest, DiscoveryPlanResponse, ExplainContextBundleOperation,
    ExplainContextBundleRequest, FacadeErrorFactory, GetContextBundleManifestOperation,
    GetContextBundleOperation, GetSourceStatusOperation, HandlerRegistryError,
    IngestCatalogOperation, IngestCatalogRequest, IngestionReceiptResponse, MaterializationProfile,
    MaterializationResponse, MaterializeContextBundleOperation, MaterializeContextBundleRequest,
    MutationReceipt, QueryCatalogOperation, QueryCatalogRequest, RevalidateContextBundleOperation,
    RevalidationResponse, SourceIdRequest, SourceStatus, SourceStatusResponse,
    TombstoneAtomOperation, TypedRequest, TypedResponse, TypedUnaryService,
};
use cigar_canon::parse_strict_json;
use cigar_catalog::{
    Atomizer, CatalogAtomService, CatalogError, CatalogErrorCode, ConnectorContext,
    DiscoveryDisposition, DiscoveryPlan, DiscoveryPolicy, DiscoveryRequest, IngestionRequest,
    IngestionService, SourceConnector, SourceHealthState,
};
use cigar_compiler::{
    BlockBodies, ByteTokenizer, CompilerCandidate, CompilerError, CompilerErrorCode,
    CompilerProfile, DeterministicCompiler, ExactTokenizer, FrozenInputs, MaterializationError,
    MaterializerProfile, RepresentationVariant, compiler_profile_digest, generate_delta,
    materialize,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    AtomKind, AtomPayload, CandidateDisposition, Capability, Classification, ContentDigest,
    ContextAtomV1, ContextBundle, ContextContract, ContextPlan, DispositionReason, EdgeKind,
    IdempotencyKey, InstructionAuthority, LaneKind, Lifecycle, MediaType, RecordId, RelativePath,
    SelectionManifest, SourceUri, UtcTimestamp, Validate, VersionId,
};
use cigar_retrieval::{
    AuthorizedPartition, CandidateFeatures, CandidateRef, QueryPlanner, RetrievalConsistency,
    RetrievalContext, RetrievalError, RetrievalErrorCode, Retriever, StagedRetrieval,
    StagedRetrievalResult,
};
use cigar_space::{RecipientBundleReceipt, ResultMergeKind};
use cigar_store::{
    AccessContext, AtomSelector, CancellationToken as StoreCancellationToken, IdempotencyIdentity,
    ReadTransaction, Repository, ServiceBatch, ServiceError, ServiceErrorCode,
    ServiceExpectedVersion, ServiceIdempotency, ServiceRecord, ServiceRecordLocator,
    ServiceRecordSelection, ServiceRecordWrite, ServiceRepository, ServiceResponse,
    SnapshotSelection, StoreError, StoreErrorCode, StoreRevision, WriteTransaction,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const SOURCE_CONFIG_NAMESPACE: &str = "catalog.source-config.v1";
const DISCOVERY_NAMESPACE: &str = "catalog.discovery-plan.v1";
const CONTEXT_PLAN_NAMESPACE: &str = "context.compile-plan.v1";
const CONTEXT_BUNDLE_INDEX_NAMESPACE: &str = "context.bundle-index.v1";
const MAX_COMPILE_CANDIDATES: usize = 10_000;
const MAX_DEPENDENCY_EDGES: usize = 1_000;
const MAX_CAS_RETRIES: usize = 16;

type SourceRuntimeKey = (RecordId, RecordId);
type SourceRuntimeRegistry = BTreeMap<SourceRuntimeKey, Arc<ConfiguredSourceRuntime>>;

/// Stable failure from the trusted catalog/context authorization provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogContextAuthorizationError {
    /// Current policy denied the request without disclosing protected resource existence.
    Denied,
    /// The returned authorization scope was malformed or internally inconsistent.
    InvalidDecision,
    /// Current policy state could not be evaluated safely.
    Unavailable,
}

impl fmt::Display for CatalogContextAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Denied => "catalog/context authorization denied",
            Self::InvalidDecision => "catalog/context authorization decision is invalid",
            Self::Unavailable => "catalog/context authorization is unavailable",
        })
    }
}

impl std::error::Error for CatalogContextAuthorizationError {}

/// Server-derived authorization partition used by catalog retrieval and context compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogContextAuthorization {
    /// Non-empty sorted project scope visible to the authenticated principal.
    pub project_ids: BTreeSet<RecordId>,
    /// Policy-normalized purpose used for repository and content gates.
    pub purpose: String,
    /// Approved local or external processor identifier.
    pub processor: String,
    /// Greatest information classification visible to this request.
    pub maximum_classification: Classification,
    /// Greatest instruction authority visible to this request.
    pub maximum_instruction_authority: InstructionAuthority,
    /// Immutable digest of the exact policy decision and its dependencies.
    pub policy_digest: ContentDigest,
    /// Whether the current policy permits partitioned vector retrieval.
    pub vector_allowed: bool,
}

impl CatalogContextAuthorization {
    fn validate(&self) -> Result<(), CatalogContextAuthorizationError> {
        if self.project_ids.is_empty()
            || self.project_ids.len() > 1_024
            || self.purpose.is_empty()
            || self.purpose.len() > 256
            || self.processor.is_empty()
            || self.processor.len() > 256
            || self
                .purpose
                .bytes()
                .chain(self.processor.bytes())
                .any(|byte| byte.is_ascii_control())
        {
            Err(CatalogContextAuthorizationError::InvalidDecision)
        } else {
            Ok(())
        }
    }
}

/// Trusted policy boundary that derives scope instead of accepting it from transport payloads.
pub trait CatalogContextAuthorizer: Send + Sync {
    /// Derives the complete catalog partition for one authenticated principal.
    fn authorize_catalog(
        &self,
        identity: &ResolvedDomainIdentity,
        observed_at: UtcTimestamp,
    ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError>;

    /// Validates caller-authored contract selectors and returns their server-authoritative scope.
    fn authorize_contract(
        &self,
        identity: &ResolvedDomainIdentity,
        contract: &ContextContract,
        observed_at: UtcTimestamp,
    ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError>;
}

/// Trusted registry for exact tokenizer implementations pinned by context contracts.
pub trait ContextTokenizerRegistry: Send + Sync {
    /// Resolves one exact tokenizer or returns `None` without falling back to an estimate.
    fn tokenizer(
        &self,
        fingerprint: &ContentDigest,
    ) -> Option<Arc<dyn ExactTokenizer + Send + Sync>>;
}

/// Thread-safe exact tokenizer registry for production composition and deterministic tests.
#[derive(Default)]
pub struct PinnedContextTokenizerRegistry {
    tokenizers: RwLock<BTreeMap<ContentDigest, Arc<dyn ExactTokenizer + Send + Sync>>>,
}

impl PinnedContextTokenizerRegistry {
    /// Registers one exact tokenizer under its own immutable fingerprint.
    pub fn register(
        &self,
        tokenizer: Arc<dyn ExactTokenizer + Send + Sync>,
    ) -> Result<(), CatalogContextAuthorizationError> {
        let fingerprint = tokenizer.fingerprint().clone();
        let mut tokenizers = self
            .tokenizers
            .write()
            .map_err(|_error| CatalogContextAuthorizationError::Unavailable)?;
        if tokenizers
            .get(&fingerprint)
            .is_some_and(|existing| !Arc::ptr_eq(existing, &tokenizer))
        {
            return Err(CatalogContextAuthorizationError::InvalidDecision);
        }
        tokenizers.insert(fingerprint, tokenizer);
        Ok(())
    }

    /// Registers the deterministic byte tokenizer for one pinned fingerprint.
    pub fn register_byte_tokenizer(
        &self,
        fingerprint: ContentDigest,
    ) -> Result<(), CatalogContextAuthorizationError> {
        self.register(Arc::new(ByteTokenizer::new(fingerprint)))
    }
}

impl ContextTokenizerRegistry for PinnedContextTokenizerRegistry {
    fn tokenizer(
        &self,
        fingerprint: &ContentDigest,
    ) -> Option<Arc<dyn ExactTokenizer + Send + Sync>> {
        self.tokenizers
            .read()
            .ok()
            .and_then(|tokenizers| tokenizers.get(fingerprint).cloned())
    }
}

/// Serializable trusted source discovery policy retained across daemon restarts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDiscoveryPolicyConfiguration {
    /// Maximum included entries.
    pub max_items: usize,
    /// Maximum included bytes across the complete plan.
    pub max_total_bytes: u64,
    /// Maximum bytes in one included record.
    pub max_record_bytes: u64,
    /// Non-bypassable excluded relative path prefixes.
    pub excluded_prefixes: Vec<RelativePath>,
    /// Exact allowed media types.
    pub allowed_media_types: BTreeSet<MediaType>,
    /// Whether policy permits an authorized ignore-only broadening.
    pub allow_user_broadening: bool,
    /// Whether in-root symlinks may be followed.
    pub follow_internal_symlinks: bool,
    /// Bounded organization secret patterns.
    pub secret_patterns: Vec<Vec<u8>>,
}

impl SourceDiscoveryPolicyConfiguration {
    fn policy(&self) -> Result<DiscoveryPolicy, CatalogError> {
        let policy = DiscoveryPolicy {
            max_items: self.max_items,
            max_total_bytes: self.max_total_bytes,
            max_record_bytes: self.max_record_bytes,
            excluded_prefixes: self.excluded_prefixes.clone(),
            allowed_media_types: self.allowed_media_types.clone(),
            allow_user_broadening: self.allow_user_broadening,
            follow_internal_symlinks: self.follow_internal_symlinks,
            secret_patterns: self.secret_patterns.clone(),
        };
        policy.validate()?;
        Ok(policy)
    }
}

/// Durable tenant-scoped source configuration supplied only by trusted composition code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfiguration {
    /// Must be `cigar.source-configuration.v1`.
    pub schema_version: String,
    /// Stable public source identity.
    pub source_id: RecordId,
    /// Server-authorized connector root.
    pub root: SourceUri,
    /// Stable configured connector implementation identity.
    pub connector_identity: String,
    /// Frozen discovery policy.
    pub discovery_policy: SourceDiscoveryPolicyConfiguration,
}

impl SourceConfiguration {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != "cigar.source-configuration.v1"
            || self.connector_identity.is_empty()
            || self.connector_identity.len() > 256
            || self
                .connector_identity
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        self.discovery_policy.policy().map(|_policy| ())
    }
}

/// Runtime connector and atomizers bound to one durable source configuration.
pub struct ConfiguredSourceRuntime {
    configuration: SourceConfiguration,
    connector: Arc<dyn SourceConnector>,
    atomizers: Vec<Arc<dyn Atomizer>>,
}

impl ConfiguredSourceRuntime {
    /// Creates a runtime after validating its durable configuration and atomizer registry.
    pub fn new(
        configuration: SourceConfiguration,
        connector: Arc<dyn SourceConnector>,
        atomizers: Vec<Arc<dyn Atomizer>>,
    ) -> Result<Self, CatalogError> {
        configuration.validate()?;
        if atomizers.is_empty() {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let mut identities = BTreeSet::new();
        for atomizer in &atomizers {
            let descriptor = atomizer.descriptor();
            if descriptor.id.is_empty()
                || descriptor.version.is_empty()
                || !identities.insert((descriptor.id, descriptor.version))
            {
                return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
            }
        }
        Ok(Self {
            configuration,
            connector,
            atomizers,
        })
    }

    /// Returns the trusted durable source configuration.
    #[must_use]
    pub const fn configuration(&self) -> &SourceConfiguration {
        &self.configuration
    }
}

impl fmt::Debug for ConfiguredSourceRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredSourceRuntime")
            .field("source_id", &self.configuration.source_id)
            .field("connector", &"[INJECTED]")
            .field("atomizer_count", &self.atomizers.len())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedDiscoveryPlan {
    schema_version: String,
    source_id: RecordId,
    configuration_digest: ContentDigest,
    include_paths: Vec<RelativePath>,
    included_count: u64,
    included_bytes: u64,
    plan_digest: ContentDigest,
    connector_watermark: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedCandidate {
    atom_id: RecordId,
    version_id: VersionId,
    content_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedCompileRecord {
    schema_version: String,
    tenant_id: RecordId,
    creator_id: RecordId,
    normalized_contract: ContextContract,
    plan: ContextPlan,
    manifest: SelectionManifest,
    bundle: ContextBundle,
    catalog_store_revision: StoreRevision,
    catalog_watermark: ContentDigest,
    policy_digest: ContentDigest,
    index_fingerprints: BTreeSet<ContentDigest>,
    retrieval_plan_digest: ContentDigest,
    compiler_profile_digest: ContentDigest,
    authorized_projects: Vec<RecordId>,
    processor: String,
    selected_candidates: BTreeMap<VersionId, RetainedCandidate>,
    block_sources: BTreeMap<VersionId, VersionId>,
    created_at: UtcTimestamp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedBundleIndex {
    schema_version: String,
    bundle_id: VersionId,
    plan_id: RecordId,
    manifest_id: VersionId,
}

struct VersionedRecord<T> {
    value: T,
    digest: ContentDigest,
}

/// Complete typed CatalogService and ContextService application implementation.
pub struct CatalogContextApplication<R>
where
    R: Repository + ServiceRepository,
{
    repository: Arc<R>,
    identities: Arc<dyn DomainIdentityResolver>,
    authorizer: Arc<dyn CatalogContextAuthorizer>,
    retriever: Arc<dyn Retriever>,
    tokenizers: Arc<dyn ContextTokenizerRegistry>,
    blocking_pool: Arc<BlockingPool>,
    clock: Arc<dyn AuthorityClock>,
    errors: Arc<dyn FacadeErrorFactory>,
    sources: Arc<RwLock<SourceRuntimeRegistry>>,
}

impl<R> Clone for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository,
{
    fn clone(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
            identities: Arc::clone(&self.identities),
            authorizer: Arc::clone(&self.authorizer),
            retriever: Arc::clone(&self.retriever),
            tokenizers: Arc::clone(&self.tokenizers),
            blocking_pool: Arc::clone(&self.blocking_pool),
            clock: Arc::clone(&self.clock),
            errors: Arc::clone(&self.errors),
            sources: Arc::clone(&self.sources),
        }
    }
}

impl<R> CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    /// Creates a fail-closed application over trusted runtime dependencies.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        identities: Arc<dyn DomainIdentityResolver>,
        authorizer: Arc<dyn CatalogContextAuthorizer>,
        retriever: Arc<dyn Retriever>,
        tokenizers: Arc<dyn ContextTokenizerRegistry>,
        blocking_pool: Arc<BlockingPool>,
        clock: Arc<dyn AuthorityClock>,
        errors: Arc<dyn FacadeErrorFactory>,
    ) -> Self {
        Self {
            repository,
            identities,
            authorizer,
            retriever,
            tokenizers,
            blocking_pool,
            clock,
            errors,
            sources: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Durably provisions or reattaches one tenant-scoped source runtime.
    pub fn provision_source(
        &self,
        tenant_id: RecordId,
        runtime: Arc<ConfiguredSourceRuntime>,
        cancellation: &StoreCancellationToken,
    ) -> Result<(), ApiError> {
        let result = self.provision_source_inner(&tenant_id, &runtime, cancellation);
        result.map_err(|code| self.errors.public_error(code))
    }

    fn provision_source_inner(
        &self,
        tenant_id: &RecordId,
        runtime: &Arc<ConfiguredSourceRuntime>,
        cancellation: &StoreCancellationToken,
    ) -> Result<(), cigar_protocol::ErrorCode> {
        runtime
            .configuration
            .validate()
            .map_err(map_catalog_error)?;
        let key = runtime.configuration.source_id.as_str();
        let locator = ServiceRecordLocator::new(tenant_id.clone(), SOURCE_CONFIG_NAMESPACE, key)
            .map_err(map_service_error)?;
        match self
            .repository
            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
            .map_err(map_service_error)?
        {
            Some(record) => {
                let retained: SourceConfiguration = decode_record(&record)?;
                if retained != runtime.configuration {
                    return Err(cigar_protocol::ErrorCode::IntegrityFailure);
                }
            }
            None => {
                let bytes = encode_record(&runtime.configuration)?;
                let write = ServiceRecordWrite::new(
                    SOURCE_CONFIG_NAMESPACE,
                    key,
                    ServiceExpectedVersion::Absent,
                    bytes,
                )
                .map_err(map_service_error)?;
                let response = ServiceResponse::new(204, "application/json", Vec::new())
                    .map_err(map_service_error)?;
                let batch = ServiceBatch::new(tenant_id.clone(), vec![write], response)
                    .map_err(map_service_error)?;
                match self.repository.service_commit(batch, cancellation) {
                    Ok(_receipt) => {}
                    Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                        let retained = self
                            .repository
                            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
                            .map_err(map_service_error)?
                            .ok_or(cigar_protocol::ErrorCode::DependencyUnavailable)?;
                        let retained: SourceConfiguration = decode_record(&retained)?;
                        if retained != runtime.configuration {
                            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
                        }
                    }
                    Err(error) => return Err(map_service_error(error)),
                }
            }
        }
        self.sources
            .write()
            .map_err(|_error| cigar_protocol::ErrorCode::DependencyUnavailable)?
            .insert(
                (tenant_id.clone(), runtime.configuration.source_id.clone()),
                Arc::clone(runtime),
            );
        Ok(())
    }

    async fn execute<T, F>(&self, context: cigar_api::RequestContext, job: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(
                Self,
                cigar_api::RequestContext,
                cigar_api::CancellationToken,
                Instant,
            ) -> Result<T, cigar_protocol::ErrorCode>
            + Send
            + 'static,
    {
        let now = self.clock.now().map_err(|_error| {
            self.errors
                .public_error(cigar_protocol::ErrorCode::Internal)
        })?;
        context.check_active(now).map_err(|_error| {
            self.errors
                .public_error(cigar_protocol::ErrorCode::DeadlineExceeded)
        })?;
        let remaining = context
            .deadline()
            .unix_nanos()
            .checked_sub(now.unix_nanos())
            .and_then(|nanos| u64::try_from(nanos).ok())
            .and_then(|nanos| Instant::now().checked_add(Duration::from_nanos(nanos)))
            .ok_or_else(|| {
                self.errors
                    .public_error(cigar_protocol::ErrorCode::DeadlineExceeded)
            })?;
        let tokio_deadline = tokio::time::Instant::from_std(remaining);
        let cancellation = context.cancellation().clone();
        let application = self.clone();
        let result = self
            .blocking_pool
            .run(cancellation, tokio_deadline, move |job_cancellation| {
                job(application, context, job_cancellation, remaining)
            })
            .await
            .map_err(|error| {
                let code = match error.code() {
                    BlockingPoolErrorCode::Cancelled | BlockingPoolErrorCode::DeadlineExceeded => {
                        cigar_protocol::ErrorCode::DeadlineExceeded
                    }
                    BlockingPoolErrorCode::Exhausted
                    | BlockingPoolErrorCode::NotAccepting
                    | BlockingPoolErrorCode::TaskFailed => {
                        cigar_protocol::ErrorCode::DependencyUnavailable
                    }
                };
                self.errors.public_error(code)
            })?;
        result.map_err(|code| self.errors.public_error(code))
    }

    fn begin_request(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
    ) -> Result<ApplicationRequest, cigar_protocol::ErrorCode> {
        let observed_at = self
            .clock
            .now()
            .map_err(|_error| cigar_protocol::ErrorCode::Internal)?;
        context
            .check_active(observed_at)
            .map_err(|_error| cigar_protocol::ErrorCode::DeadlineExceeded)?;
        if Instant::now() >= monotonic_deadline || cancellation.is_cancelled() {
            return Err(cigar_protocol::ErrorCode::DeadlineExceeded);
        }
        let identity = self
            .identities
            .resolve(context)
            .map_err(|error| match error.code() {
                crate::DomainIdentityErrorCode::Cancelled => {
                    cigar_protocol::ErrorCode::DeadlineExceeded
                }
                crate::DomainIdentityErrorCode::InvalidMapping => {
                    cigar_protocol::ErrorCode::UnknownPrincipal
                }
                crate::DomainIdentityErrorCode::Unavailable => {
                    cigar_protocol::ErrorCode::DependencyUnavailable
                }
            })?;
        let store_cancellation = StoreCancellationToken::default();
        if cancellation.is_cancelled() {
            store_cancellation.cancel();
            return Err(cigar_protocol::ErrorCode::DeadlineExceeded);
        }
        let bridge_stop = Arc::new(AtomicBool::new(false));
        let bridge_api = cancellation.clone();
        let bridge_store = store_cancellation.clone();
        let bridge_stop_worker = Arc::clone(&bridge_stop);
        let cancellation_bridge = std::thread::Builder::new()
            .name("cigar-request-cancellation".to_owned())
            .spawn(move || {
                while !bridge_stop_worker.load(Ordering::Acquire) {
                    if bridge_api.is_cancelled() {
                        bridge_store.cancel();
                        break;
                    }
                    std::thread::park_timeout(Duration::from_millis(1));
                }
            })
            .map_err(|_error| cigar_protocol::ErrorCode::DependencyUnavailable)?;
        Ok(ApplicationRequest {
            identity,
            observed_at,
            api_cancellation: cancellation.clone(),
            store_cancellation,
            monotonic_deadline,
            bridge_stop,
            cancellation_bridge: Some(cancellation_bridge),
        })
    }

    fn catalog_authorization(
        &self,
        request: &ApplicationRequest,
    ) -> Result<CatalogContextAuthorization, cigar_protocol::ErrorCode> {
        let authorization = self
            .authorizer
            .authorize_catalog(&request.identity, request.observed_at)
            .map_err(map_authorization_error)?;
        authorization.validate().map_err(map_authorization_error)?;
        Ok(authorization)
    }

    fn contract_authorization(
        &self,
        request: &ApplicationRequest,
        contract: &ContextContract,
    ) -> Result<CatalogContextAuthorization, cigar_protocol::ErrorCode> {
        let authorization = self
            .authorizer
            .authorize_contract(&request.identity, contract, request.observed_at)
            .map_err(map_authorization_error)?;
        authorization.validate().map_err(map_authorization_error)?;
        Ok(authorization)
    }

    fn source(
        &self,
        request: &ApplicationRequest,
        source_id: &RecordId,
    ) -> Result<LoadedSource, cigar_protocol::ErrorCode> {
        request.check()?;
        let locator = ServiceRecordLocator::new(
            request.identity.tenant_id.clone(),
            SOURCE_CONFIG_NAMESPACE,
            source_id.as_str(),
        )
        .map_err(map_service_error)?;
        let record = self
            .repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &request.store_cancellation,
            )
            .map_err(map_service_error)?
            .ok_or(cigar_protocol::ErrorCode::InvalidArgument)?;
        let configuration: SourceConfiguration = decode_record(&record)?;
        configuration.validate().map_err(map_catalog_error)?;
        if configuration.source_id != *source_id {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        let runtime = self
            .sources
            .read()
            .map_err(|_error| cigar_protocol::ErrorCode::DependencyUnavailable)?
            .get(&(request.identity.tenant_id.clone(), source_id.clone()))
            .cloned()
            .ok_or(cigar_protocol::ErrorCode::SourceUnavailable)?;
        if runtime.configuration != configuration {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        Ok(LoadedSource {
            runtime,
            configuration_digest: record.digest().clone(),
        })
    }

    fn discover_sources(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: TypedRequest<DiscoverSourcesRequest>,
    ) -> Result<DiscoveryPlanResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let _authorization = self.catalog_authorization(&state)?;
        let source = self.source(&state, &request.payload.source_id)?;
        let connector_context =
            ConnectorContext::new(state.store_cancellation.clone(), state.monotonic_deadline);
        let discovery = DiscoveryRequest {
            root: source.runtime.configuration.root.clone(),
            policy: source
                .runtime
                .configuration
                .discovery_policy
                .policy()
                .map_err(map_catalog_error)?,
            include_overrides: request.payload.include_paths.iter().cloned().collect(),
        };
        let plan = source
            .runtime
            .connector
            .discover(&discovery, &connector_context)
            .map_err(map_catalog_error)?;
        validate_discovery_plan(&plan, &source.runtime.configuration.root)?;
        let health = source.runtime.connector.health();
        let retained = RetainedDiscoveryPlan {
            schema_version: "cigar.retained-discovery-plan.v1".to_owned(),
            source_id: request.payload.source_id.clone(),
            configuration_digest: source.configuration_digest,
            include_paths: request.payload.include_paths,
            included_count: plan.included_count,
            included_bytes: plan.included_bytes,
            plan_digest: plan.plan_digest.clone(),
            connector_watermark: health.watermark.0,
        };
        if !request.metadata.dry_run() {
            self.persist_discovery(&state, &retained)?;
        }
        Ok(DiscoveryPlanResponse {
            source_id: retained.source_id,
            included_count: retained.included_count,
            included_bytes: retained.included_bytes,
            plan_digest: retained.plan_digest,
        })
    }

    fn persist_discovery(
        &self,
        request: &ApplicationRequest,
        plan: &RetainedDiscoveryPlan,
    ) -> Result<(), cigar_protocol::ErrorCode> {
        let locator = ServiceRecordLocator::new(
            request.identity.tenant_id.clone(),
            DISCOVERY_NAMESPACE,
            plan.source_id.as_str(),
        )
        .map_err(map_service_error)?;
        let bytes = encode_record(plan)?;
        for _attempt in 0..MAX_CAS_RETRIES {
            request.check()?;
            let retained = self
                .repository
                .service_get(
                    &locator,
                    ServiceRecordSelection::Latest,
                    &request.store_cancellation,
                )
                .map_err(map_service_error)?;
            let expected = retained
                .as_ref()
                .map_or(ServiceExpectedVersion::Absent, |record| {
                    ServiceExpectedVersion::Version(record.version())
                });
            let write = ServiceRecordWrite::new(
                DISCOVERY_NAMESPACE,
                plan.source_id.as_str(),
                expected,
                bytes.clone(),
            )
            .map_err(map_service_error)?;
            let response = ServiceResponse::new(200, "application/json", bytes.clone())
                .map_err(map_service_error)?;
            let batch =
                ServiceBatch::new(request.identity.tenant_id.clone(), vec![write], response)
                    .map_err(map_service_error)?;
            match self
                .repository
                .service_commit(batch, &request.store_cancellation)
            {
                Ok(_receipt) => return Ok(()),
                Err(error) if error.code() == ServiceErrorCode::RevisionConflict => continue,
                Err(error) => return Err(map_service_error(error)),
            }
        }
        Err(cigar_protocol::ErrorCode::DependencyUnavailable)
    }

    fn retained_discovery(
        &self,
        request: &ApplicationRequest,
        source_id: &RecordId,
    ) -> Result<RetainedDiscoveryPlan, cigar_protocol::ErrorCode> {
        let locator = ServiceRecordLocator::new(
            request.identity.tenant_id.clone(),
            DISCOVERY_NAMESPACE,
            source_id.as_str(),
        )
        .map_err(map_service_error)?;
        let record = self
            .repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &request.store_cancellation,
            )
            .map_err(map_service_error)?
            .ok_or(cigar_protocol::ErrorCode::InvalidArgument)?;
        let plan: RetainedDiscoveryPlan = decode_record(&record)?;
        if plan.schema_version != "cigar.retained-discovery-plan.v1" || plan.source_id != *source_id
        {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        Ok(plan)
    }

    fn ingest_catalog(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: TypedRequest<IngestCatalogRequest>,
    ) -> Result<IngestionReceiptResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let authorization = self.catalog_authorization(&state)?;
        let source = self.source(&state, &request.payload.source_id)?;
        let retained = self.retained_discovery(&state, &request.payload.source_id)?;
        if retained.plan_digest != request.payload.plan_digest
            || retained.configuration_digest != source.configuration_digest
        {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        let connector_context =
            ConnectorContext::new(state.store_cancellation.clone(), state.monotonic_deadline);
        let discovery_request = DiscoveryRequest {
            root: source.runtime.configuration.root.clone(),
            policy: source
                .runtime
                .configuration
                .discovery_policy
                .policy()
                .map_err(map_catalog_error)?,
            include_overrides: retained.include_paths.iter().cloned().collect(),
        };
        let current_plan = source
            .runtime
            .connector
            .discover(&discovery_request, &connector_context)
            .map_err(map_catalog_error)?;
        if current_plan.plan_digest != retained.plan_digest
            || current_plan.included_count != retained.included_count
            || current_plan.included_bytes != retained.included_bytes
        {
            return Err(cigar_protocol::ErrorCode::SnapshotIncomplete);
        }
        let access = AccessContext::new(state.identity.tenant_id.clone(), authorization.purpose)
            .map_err(map_store_error)?;
        let current_revision = self.current_revision(access.clone(), &state.store_cancellation)?;
        if request.metadata.dry_run() {
            let snapshot = source
                .runtime
                .connector
                .snapshot(None, &connector_context)
                .map_err(map_catalog_error)?;
            if !snapshot.snapshot.complete {
                return Err(cigar_protocol::ErrorCode::SnapshotIncomplete);
            }
            return Ok(IngestionReceiptResponse {
                revision: current_revision.0.max(1),
                snapshot_id: snapshot.snapshot.snapshot_id,
                published_atoms: 0,
                tombstoned_atoms: 0,
                publication_digest: retained.plan_digest,
            });
        }
        let key = parse_idempotency(request.metadata.idempotency_key())?;
        let atomizers: Vec<&dyn Atomizer> =
            source.runtime.atomizers.iter().map(AsRef::as_ref).collect();
        let receipt = IngestionService
            .ingest_discovered(
                self.repository.as_ref(),
                IngestionRequest {
                    access,
                    expected_revision: current_revision,
                    idempotency_key: key,
                },
                source.runtime.connector.as_ref(),
                &atomizers,
                &current_plan,
                &connector_context,
            )
            .map_err(map_catalog_error)?;
        Ok(IngestionReceiptResponse {
            revision: receipt.revision.0,
            snapshot_id: receipt.snapshot_id,
            published_atoms: receipt.published_atoms,
            tombstoned_atoms: receipt.tombstoned_atoms,
            publication_digest: receipt.publication_digest,
        })
    }

    fn source_status(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        source_id: RecordId,
    ) -> Result<SourceStatusResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let _authorization = self.catalog_authorization(&state)?;
        let source = self.source(&state, &source_id)?;
        let health = source.runtime.connector.health();
        let status = match health.state {
            SourceHealthState::Ready => SourceStatus::Ready,
            SourceHealthState::Degraded => SourceStatus::Degraded,
            SourceHealthState::Unavailable => SourceStatus::Unavailable,
        };
        Ok(SourceStatusResponse {
            source_id,
            status,
            watermark: health.watermark.0,
        })
    }

    fn query_catalog(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: QueryCatalogRequest,
    ) -> Result<CatalogQueryResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let authorization = self.catalog_authorization(&state)?;
        let access = AccessContext::new(
            state.identity.tenant_id.clone(),
            authorization.purpose.clone(),
        )
        .map_err(map_store_error)?;
        let revision = self.current_revision(access, &state.store_cancellation)?;
        let partition = authorized_partition(&state, &authorization)?;
        let plan = QueryPlanner::default()
            .plan(
                &request.requirements,
                &partition,
                revision,
                RetrievalConsistency::Strong,
                authorization.vector_allowed,
            )
            .map_err(map_retrieval_error)?;
        let result = StagedRetrieval
            .execute(
                &plan,
                self.retriever.as_ref(),
                &RetrievalContext {
                    cancellation: state.store_cancellation.clone(),
                    deadline: state.monotonic_deadline,
                },
            )
            .map_err(map_retrieval_error)?;
        let mut versions: BTreeSet<VersionId> = result
            .stages
            .iter()
            .flat_map(|stage| stage.batch.candidates.iter())
            .map(|candidate| candidate.version_id.clone())
            .collect();
        let maximum = usize::from(request.max_results);
        while versions.len() > maximum {
            let last = versions
                .last()
                .cloned()
                .ok_or(cigar_protocol::ErrorCode::Internal)?;
            versions.remove(&last);
        }
        let degraded = result
            .stages
            .iter()
            .any(|stage| stage.batch.disclosure.fallback_used);
        Ok(CatalogQueryResponse {
            version_ids: versions.into_iter().collect(),
            query_digest: result.plan_fingerprint,
            degraded,
        })
    }

    fn batch_atoms(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: BatchAtomsRequest,
    ) -> Result<AtomBatchResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let authorization = self.catalog_authorization(&state)?;
        let access = AccessContext::new(state.identity.tenant_id.clone(), authorization.purpose)
            .map_err(map_store_error)?;
        let batch = CatalogAtomService
            .batch_atoms(
                self.repository.as_ref(),
                access,
                SnapshotSelection::Latest,
                &request.atom_ids,
                state.store_cancellation.clone(),
            )
            .map_err(map_catalog_error)?;
        let results = request
            .atom_ids
            .into_iter()
            .zip(batch.atoms)
            .map(|(atom_id, atom)| match atom {
                Some(atom) => AtomLookupResult::Found {
                    atom: Box::new(atom),
                },
                None => AtomLookupResult::Missing { atom_id },
            })
            .collect();
        Ok(AtomBatchResponse { results })
    }

    fn tombstone_atom(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: TypedRequest<AtomIdRequest>,
    ) -> Result<MutationReceipt, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let authorization = self.catalog_authorization(&state)?;
        let access = AccessContext::new(state.identity.tenant_id.clone(), authorization.purpose)
            .map_err(map_store_error)?;
        let expected = parse_revision(request.metadata.expected_revision())?;
        if request.metadata.dry_run() {
            let batch = CatalogAtomService
                .batch_atoms(
                    self.repository.as_ref(),
                    access,
                    SnapshotSelection::Revision(expected),
                    std::slice::from_ref(&request.payload.atom_id),
                    state.store_cancellation.clone(),
                )
                .map_err(map_catalog_error)?;
            if batch.atoms.first().and_then(Option::as_ref).is_none() {
                return Err(cigar_protocol::ErrorCode::InvalidArgument);
            }
            return Ok(MutationReceipt {
                resource_id: request.payload.atom_id,
                revision: expected.0.max(1),
                replayed: false,
            });
        }
        let key = parse_idempotency(request.metadata.idempotency_key())?;
        let event_id = deterministic_record_id(&[
            b"CIGAR-CATALOG-TOMBSTONE-EVENT\0v1\0",
            state.identity.tenant_id.as_str().as_bytes(),
            request.payload.atom_id.as_str().as_bytes(),
            key.as_str().as_bytes(),
        ])?;
        let atom_id = request.payload.atom_id;
        let receipt = CatalogAtomService
            .tombstone_atom(
                self.repository.as_ref(),
                access,
                expected,
                key,
                atom_id.clone(),
                state.observed_at,
                event_id,
                state.store_cancellation.clone(),
            )
            .map_err(map_catalog_error)?;
        Ok(MutationReceipt {
            resource_id: atom_id,
            revision: receipt.revision.0,
            replayed: receipt.replayed,
        })
    }

    fn create_context_plan(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: TypedRequest<CreateContextPlanRequest>,
    ) -> Result<ContextPlanResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let authorization = self.contract_authorization(&state, &request.payload.contract)?;
        let mut contract = request.payload.contract;
        contract.principal_id = state.identity.principal_id.clone();
        contract.project_ids = authorization.project_ids.iter().cloned().collect();
        contract.purpose.clone_from(&authorization.purpose);
        contract
            .validate()
            .map_err(|_error| cigar_protocol::ErrorCode::InvalidArgument)?;
        let prepared = self.compile_context(&state, contract, &authorization)?;
        let response = ContextPlanResponse {
            plan: prepared.record.plan.clone(),
            bundle_id: prepared.record.bundle.bundle_id.clone(),
            manifest_digest: prepared.record.bundle.manifest_digest.clone(),
        };
        if !request.metadata.dry_run() {
            let idempotency = parse_idempotency(request.metadata.idempotency_key())?;
            self.persist_compile(&state, &prepared.record, &response, idempotency)?;
        }
        Ok(response)
    }

    fn compile_context(
        &self,
        request: &ApplicationRequest,
        contract: ContextContract,
        authorization: &CatalogContextAuthorization,
    ) -> Result<PreparedCompile, cigar_protocol::ErrorCode> {
        request.check()?;
        let access = AccessContext::new(
            request.identity.tenant_id.clone(),
            authorization.purpose.clone(),
        )
        .map_err(map_store_error)?;
        let read = self
            .repository
            .begin_read(
                access,
                SnapshotSelection::Latest,
                request.store_cancellation.clone(),
            )
            .map_err(map_store_error)?;
        let revision = read.revision();
        let partition = authorized_partition(request, authorization)?;
        let consistency = match contract.consistency {
            cigar_protocol::ConsistencyMode::Snapshot | cigar_protocol::ConsistencyMode::Strong => {
                RetrievalConsistency::Strong
            }
            cigar_protocol::ConsistencyMode::BoundedStaleness => {
                RetrievalConsistency::BoundedStale {
                    max_revision_lag: 0,
                }
            }
        };
        let retrieval_plan = QueryPlanner::default()
            .plan(
                &contract.requirements,
                &partition,
                revision,
                consistency,
                authorization.vector_allowed,
            )
            .map_err(map_retrieval_error)?;
        let retrieval = StagedRetrieval
            .execute(
                &retrieval_plan,
                self.retriever.as_ref(),
                &RetrievalContext {
                    cancellation: request.store_cancellation.clone(),
                    deadline: request.monotonic_deadline,
                },
            )
            .map_err(map_retrieval_error)?;
        let tokenizer = self
            .tokenizers
            .tokenizer(&contract.target.tokenizer_fingerprint)
            .ok_or(cigar_protocol::ErrorCode::DependencyUnavailable)?;
        let mut seeds = candidate_seeds(&retrieval);
        let mut atoms = BTreeMap::new();
        let mut dependencies = BTreeMap::<VersionId, BTreeSet<VersionId>>::new();
        let mut pending: VecDeque<VersionId> = seeds.keys().cloned().collect();
        while let Some(version_id) = pending.pop_front() {
            request.check()?;
            if atoms.contains_key(&version_id) {
                continue;
            }
            if atoms.len() >= MAX_COMPILE_CANDIDATES {
                return Err(cigar_protocol::ErrorCode::LimitExceeded);
            }
            let atom = read
                .get_atom(&version_id)
                .map_err(map_store_error)?
                .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
            let edges = read
                .edges_from(&version_id, Some(EdgeKind::DependsOn), MAX_DEPENDENCY_EDGES)
                .map_err(map_store_error)?;
            let mut atom_dependencies = BTreeSet::new();
            for edge in edges {
                if edge.lifecycle == Lifecycle::Active {
                    atom_dependencies.insert(edge.to_version.clone());
                    seeds.entry(edge.to_version.clone()).or_default();
                    pending.push_back(edge.to_version);
                }
            }
            dependencies.insert(version_id.clone(), atom_dependencies);
            atoms.insert(version_id, atom);
        }
        let catalog_watermark = catalog_watermark(&read)?;
        let retrieval_plan_digest = retained_retrieval_digest(&contract, &retrieval)?;
        let index_fingerprints = retained_index_fingerprints(&retrieval, &catalog_watermark)?;
        let profile = CompilerProfile::default();
        let profile_digest = compiler_profile_digest(&profile).map_err(map_compiler_error)?;
        let mut candidates = Vec::with_capacity(atoms.len());
        let mut bodies_by_version = BTreeMap::new();
        for (version_id, atom) in &atoms {
            request.check()?;
            let body = atom_body(&read, atom)?;
            let token_count = tokenizer
                .count_exact(&body)
                .map_err(map_materialization_error)?;
            if token_count == 0 {
                return Err(cigar_protocol::ErrorCode::IntegrityFailure);
            }
            bodies_by_version.insert(version_id.clone(), body);
            let seed = seeds
                .get(version_id)
                .ok_or(cigar_protocol::ErrorCode::Internal)?;
            let requirement_indices: BTreeSet<usize> = seed
                .requirement_indices
                .iter()
                .copied()
                .filter(|index| {
                    contract
                        .requirements
                        .get(*index)
                        .is_some_and(|requirement| requirement.semantic_type == atom.kind)
                })
                .collect();
            let (policy_outcome, pre_exclusion_reason) =
                atom_policy(atom, authorization, request.observed_at, &contract);
            let mut features = seed.candidate.as_ref().map_or_else(
                || dependency_features(atom, token_count),
                |candidate| candidate.features,
            );
            features.estimated_tokens = token_count;
            let representation =
                RepresentationVariant::exact(atom.content_digest.clone(), token_count)
                    .map_err(map_compiler_error)?;
            candidates.push(CompilerCandidate {
                version_id: version_id.clone(),
                logical_id: version_id.clone(),
                canonical_uri: atom.source.uri.clone(),
                lane: lane_for_kind(atom.kind),
                mandatory: false,
                requirement_indices,
                entity_coverage_bits: features.entity_coverage_bits,
                features,
                policy_outcome,
                pre_exclusion_reason,
                classification: atom.governance.classification,
                instruction_authority: atom.governance.instruction_authority,
                dependencies: dependencies.get(version_id).cloned().unwrap_or_default(),
                representations: vec![representation],
                claim: None,
                provenance_digest: digest_json(atom)?,
            });
        }
        let frozen = FrozenInputs {
            catalog_watermark: catalog_watermark.clone(),
            graph_revision: graph_digest(&dependencies)?,
            policy_digest: authorization.policy_digest.clone(),
            index_fingerprints: index_fingerprints.clone(),
            retrieval_plan_digest: retrieval_plan_digest.clone(),
            compiler_profile_digest: profile_digest.clone(),
            tokenizer_fingerprint: contract.target.tokenizer_fingerprint.clone(),
            materializer_fingerprint: contract.target.materializer_fingerprint.clone(),
        };
        let output = DeterministicCompiler
            .compile(cigar_compiler::CompileRequest {
                contract,
                frozen,
                profile,
                candidates,
            })
            .map_err(map_compiler_error)?;
        let selected_versions: BTreeSet<VersionId> = output
            .plan
            .dispositions
            .iter()
            .filter_map(|(version_id, disposition)| {
                matches!(disposition, CandidateDisposition::Selected { .. })
                    .then_some(version_id.clone())
            })
            .collect();
        let selected_candidates = selected_versions
            .iter()
            .map(|version_id| {
                let atom = atoms
                    .get(version_id)
                    .ok_or(cigar_protocol::ErrorCode::Internal)?;
                Ok((
                    version_id.clone(),
                    RetainedCandidate {
                        atom_id: atom.atom_id.clone(),
                        version_id: version_id.clone(),
                        content_digest: atom.content_digest.clone(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, cigar_protocol::ErrorCode>>()?;
        let mut block_sources = BTreeMap::new();
        for block in &output.bundle.blocks {
            let source = block
                .provenance
                .iter()
                .filter(|version_id| selected_versions.contains(*version_id))
                .filter(|version_id| {
                    atoms
                        .get(*version_id)
                        .is_some_and(|atom| atom.content_digest == block.content_digest)
                })
                .min()
                .cloned()
                .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
            let body = bodies_by_version
                .get(&source)
                .ok_or(cigar_protocol::ErrorCode::Internal)?;
            if tokenizer
                .count_exact(body)
                .map_err(map_materialization_error)?
                != block.token_count
            {
                return Err(cigar_protocol::ErrorCode::IntegrityFailure);
            }
            block_sources.insert(block.block_id.clone(), source);
        }
        let record = RetainedCompileRecord {
            schema_version: "cigar.retained-compile.v1".to_owned(),
            tenant_id: request.identity.tenant_id.clone(),
            creator_id: request.identity.principal_id.clone(),
            normalized_contract: output.normalized_contract,
            plan: output.plan,
            manifest: output.manifest,
            bundle: output.bundle,
            catalog_store_revision: revision,
            catalog_watermark,
            policy_digest: authorization.policy_digest.clone(),
            index_fingerprints,
            retrieval_plan_digest,
            compiler_profile_digest: profile_digest,
            authorized_projects: authorization.project_ids.iter().cloned().collect(),
            processor: authorization.processor.clone(),
            selected_candidates,
            block_sources,
            created_at: request.observed_at,
        };
        validate_compile_record(&record)?;
        Ok(PreparedCompile { record })
    }

    fn persist_compile(
        &self,
        request: &ApplicationRequest,
        record: &RetainedCompileRecord,
        response: &ContextPlanResponse,
        idempotency_key: IdempotencyKey,
    ) -> Result<(), cigar_protocol::ErrorCode> {
        validate_compile_record(record)?;
        let record_bytes = encode_record(record)?;
        let request_digest = digest_bytes(&record_bytes)?;
        let access = AccessContext::new(
            request.identity.tenant_id.clone(),
            record.normalized_contract.purpose.clone(),
        )
        .map_err(map_store_error)?;
        let mut bundle_persisted = false;
        for _attempt in 0..MAX_CAS_RETRIES {
            request.check()?;
            let read = self
                .repository
                .begin_read(
                    access.clone(),
                    SnapshotSelection::Latest,
                    request.store_cancellation.clone(),
                )
                .map_err(map_store_error)?;
            if let Some(existing) = read
                .get_bundle(&record.bundle.bundle_id)
                .map_err(map_store_error)?
            {
                if existing != record.bundle {
                    return Err(cigar_protocol::ErrorCode::IntegrityFailure);
                }
                bundle_persisted = true;
                break;
            }
            let revision = read.revision();
            drop(read);
            let mut write = self
                .repository
                .begin_write(access.clone(), revision, request.store_cancellation.clone())
                .map_err(map_store_error)?;
            write
                .put_bundle(record.bundle.clone())
                .map_err(map_store_error)?;
            let identity = IdempotencyIdentity::new(
                "context.bundle.v1",
                idempotency_key.clone(),
                request_digest.clone(),
            )
            .map_err(map_store_error)?;
            match write.commit(Some(identity)) {
                Ok(_receipt) => {
                    bundle_persisted = true;
                    break;
                }
                Err(error) if error.code() == StoreErrorCode::RevisionConflict => continue,
                Err(error) => return Err(map_store_error(error)),
            }
        }
        if !bundle_persisted {
            return Err(cigar_protocol::ErrorCode::DependencyUnavailable);
        }
        let index = RetainedBundleIndex {
            schema_version: "cigar.retained-bundle-index.v1".to_owned(),
            bundle_id: record.bundle.bundle_id.clone(),
            plan_id: record.plan.plan_id.clone(),
            manifest_id: record.manifest.manifest_id.clone(),
        };
        let index_bytes = encode_record(&index)?;
        let plan_locator = ServiceRecordLocator::new(
            request.identity.tenant_id.clone(),
            CONTEXT_PLAN_NAMESPACE,
            record.plan.plan_id.as_str(),
        )
        .map_err(map_service_error)?;
        if let Some(existing) = self
            .repository
            .service_get(
                &plan_locator,
                ServiceRecordSelection::Latest,
                &request.store_cancellation,
            )
            .map_err(map_service_error)?
        {
            let retained: RetainedCompileRecord = decode_record(&existing)?;
            return if retained == *record {
                Ok(())
            } else {
                Err(cigar_protocol::ErrorCode::IntegrityFailure)
            };
        }
        let plan_write = ServiceRecordWrite::new(
            CONTEXT_PLAN_NAMESPACE,
            record.plan.plan_id.as_str(),
            ServiceExpectedVersion::Absent,
            record_bytes,
        )
        .map_err(map_service_error)?;
        let index_write = ServiceRecordWrite::new(
            CONTEXT_BUNDLE_INDEX_NAMESPACE,
            record.bundle.bundle_id.as_str(),
            ServiceExpectedVersion::Absent,
            index_bytes,
        )
        .map_err(map_service_error)?;
        let response_bytes = encode_record(response)?;
        let response_record = ServiceResponse::new(200, "application/json", response_bytes)
            .map_err(map_service_error)?;
        let service_idempotency =
            ServiceIdempotency::new("context.create-plan.v1", idempotency_key, request_digest)
                .map_err(map_service_error)?;
        let batch = ServiceBatch::new(
            request.identity.tenant_id.clone(),
            vec![plan_write, index_write],
            response_record,
        )
        .map_err(map_service_error)?
        .with_idempotency(service_idempotency);
        match self
            .repository
            .service_commit(batch, &request.store_cancellation)
        {
            Ok(_receipt) => Ok(()),
            Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                let existing = self
                    .repository
                    .service_get(
                        &plan_locator,
                        ServiceRecordSelection::Latest,
                        &request.store_cancellation,
                    )
                    .map_err(map_service_error)?
                    .ok_or(cigar_protocol::ErrorCode::DependencyUnavailable)?;
                let retained: RetainedCompileRecord = decode_record(&existing)?;
                if retained == *record {
                    Ok(())
                } else {
                    Err(cigar_protocol::ErrorCode::IntegrityFailure)
                }
            }
            Err(error) => Err(map_service_error(error)),
        }
    }

    fn retained_plan(
        &self,
        request: &ApplicationRequest,
        plan_id: &RecordId,
    ) -> Result<VersionedRecord<RetainedCompileRecord>, cigar_protocol::ErrorCode> {
        let locator = ServiceRecordLocator::new(
            request.identity.tenant_id.clone(),
            CONTEXT_PLAN_NAMESPACE,
            plan_id.as_str(),
        )
        .map_err(map_service_error)?;
        let record = self
            .repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &request.store_cancellation,
            )
            .map_err(map_service_error)?
            .ok_or(cigar_protocol::ErrorCode::InvalidArgument)?;
        let value: RetainedCompileRecord = decode_record(&record)?;
        validate_compile_record(&value)?;
        if value.plan.plan_id != *plan_id || value.tenant_id != request.identity.tenant_id {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        Ok(VersionedRecord {
            value,
            digest: record.digest().clone(),
        })
    }

    fn retained_bundle(
        &self,
        request: &ApplicationRequest,
        bundle_id: &VersionId,
    ) -> Result<VersionedRecord<RetainedCompileRecord>, cigar_protocol::ErrorCode> {
        let locator = ServiceRecordLocator::new(
            request.identity.tenant_id.clone(),
            CONTEXT_BUNDLE_INDEX_NAMESPACE,
            bundle_id.as_str(),
        )
        .map_err(map_service_error)?;
        let index_record = self
            .repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &request.store_cancellation,
            )
            .map_err(map_service_error)?
            .ok_or(cigar_protocol::ErrorCode::InvalidArgument)?;
        let index: RetainedBundleIndex = decode_record(&index_record)?;
        if index.schema_version != "cigar.retained-bundle-index.v1" || index.bundle_id != *bundle_id
        {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        let retained = self.retained_plan(request, &index.plan_id)?;
        if retained.value.bundle.bundle_id != *bundle_id
            || retained.value.manifest.manifest_id != index.manifest_id
        {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        Ok(retained)
    }

    fn authorize_retained(
        &self,
        request: &ApplicationRequest,
        retained: &RetainedCompileRecord,
    ) -> Result<CatalogContextAuthorization, cigar_protocol::ErrorCode> {
        if retained.tenant_id != request.identity.tenant_id {
            return Err(cigar_protocol::ErrorCode::InvalidArgument);
        }
        let authorization = self
            .authorizer
            .authorize_contract(
                &request.identity,
                &retained.normalized_contract,
                request.observed_at,
            )
            .map_err(|_error| cigar_protocol::ErrorCode::InvalidArgument)?;
        authorization
            .validate()
            .map_err(|_error| cigar_protocol::ErrorCode::InvalidArgument)?;
        Ok(authorization)
    }

    fn stored_bundle(
        &self,
        request: &ApplicationRequest,
        retained: &RetainedCompileRecord,
        authorization: &CatalogContextAuthorization,
    ) -> Result<ContextBundle, cigar_protocol::ErrorCode> {
        let access = AccessContext::new(
            request.identity.tenant_id.clone(),
            authorization.purpose.clone(),
        )
        .map_err(map_store_error)?;
        let bundle = self
            .repository
            .begin_read(
                access,
                SnapshotSelection::Latest,
                request.store_cancellation.clone(),
            )
            .map_err(map_store_error)?
            .get_bundle(&retained.bundle.bundle_id)
            .map_err(map_store_error)?
            .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
        if bundle != retained.bundle {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        Ok(bundle)
    }

    fn compile_context_bundle(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: CompileContextBundleRequest,
    ) -> Result<(ContextBundle, String), cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_plan(&state, &request.plan_id)?;
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let bundle = self.stored_bundle(&state, &retained.value, &authorization)?;
        Ok((
            bundle,
            strong_etag(retained.value.bundle.bundle_id.as_str()),
        ))
    }

    fn compile_context_delta(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: CompileContextDeltaRequest,
    ) -> Result<ContextDeltaResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let base = self.retained_bundle(&state, &request.base_bundle_id)?;
        let target = self.retained_plan(&state, &request.target_plan_id)?;
        let base_authorization = self.authorize_retained(&state, &base.value)?;
        let target_authorization = self.authorize_retained(&state, &target.value)?;
        let base_bundle = self.stored_bundle(&state, &base.value, &base_authorization)?;
        let target_bundle = self.stored_bundle(&state, &target.value, &target_authorization)?;
        let sealed = generate_delta(&base_bundle, &target_bundle).map_err(map_delta_error)?;
        Ok(ContextDeltaResponse {
            delta: sealed.delta,
            delta_digest: sealed.delta_digest,
        })
    }

    fn get_context_bundle(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        bundle_id: VersionId,
    ) -> Result<(ContextBundle, String), cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_bundle(&state, &bundle_id)?;
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let bundle = self.stored_bundle(&state, &retained.value, &authorization)?;
        Ok((bundle, strong_etag(bundle_id.as_str())))
    }

    fn get_context_manifest(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        bundle_id: VersionId,
    ) -> Result<(SelectionManifest, String), cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_bundle(&state, &bundle_id)?;
        let _authorization = self.authorize_retained(&state, &retained.value)?;
        Ok((
            retained.value.manifest,
            strong_etag(retained.digest.as_str()),
        ))
    }

    fn explain_context_bundle(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: ExplainContextBundleRequest,
    ) -> Result<ContextExplanationResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_bundle(&state, &request.bundle_id)?;
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let requested: BTreeSet<VersionId> = request.version_ids.into_iter().collect();
        let access = AccessContext::new(
            state.identity.tenant_id.clone(),
            authorization.purpose.clone(),
        )
        .map_err(map_store_error)?;
        let read = self
            .repository
            .begin_read(
                access,
                SnapshotSelection::Latest,
                state.store_cancellation.clone(),
            )
            .map_err(map_store_error)?;
        let mut entries = Vec::new();
        for entry in &retained.value.manifest.entries {
            state.check()?;
            if !requested.is_empty() && !requested.contains(&entry.version_id) {
                continue;
            }
            let Some(atom) = read.get_atom(&entry.version_id).map_err(map_store_error)? else {
                continue;
            };
            if atom_visible(
                &atom,
                &authorization,
                state.observed_at,
                &retained.value.normalized_contract,
            ) {
                entries.push(ContextExplanationEntry {
                    version_id: entry.version_id.clone(),
                    disposition: entry.disposition.clone(),
                });
            }
        }
        Ok(ContextExplanationResponse { entries })
    }

    fn materialize_context_bundle(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: MaterializeContextBundleRequest,
    ) -> Result<MaterializationResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_bundle(&state, &request.bundle_id)?;
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let reasons = self.revalidation_reasons(&state, &retained.value, &authorization)?;
        if !reasons.is_empty() {
            return Err(cigar_protocol::ErrorCode::BundleInvalidated);
        }
        let bundle = self.stored_bundle(&state, &retained.value, &authorization)?;
        let tokenizer = self
            .tokenizers
            .tokenizer(
                &retained
                    .value
                    .normalized_contract
                    .target
                    .tokenizer_fingerprint,
            )
            .ok_or(cigar_protocol::ErrorCode::DependencyUnavailable)?;
        let access = AccessContext::new(state.identity.tenant_id.clone(), authorization.purpose)
            .map_err(map_store_error)?;
        let read = self
            .repository
            .begin_read(
                access,
                SnapshotSelection::Latest,
                state.store_cancellation.clone(),
            )
            .map_err(map_store_error)?;
        let mut bodies = BlockBodies::new();
        for block in &bundle.blocks {
            let source_version = retained
                .value
                .block_sources
                .get(&block.block_id)
                .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
            let atom = read
                .get_atom(source_version)
                .map_err(map_store_error)?
                .ok_or(cigar_protocol::ErrorCode::BundleInvalidated)?;
            bodies.insert(block.block_id.clone(), atom_body(&read, &atom)?);
        }
        let profile = match request.profile {
            MaterializationProfile::CanonicalJson => MaterializerProfile::Json,
            MaterializationProfile::ClaudePrompt => MaterializerProfile::ClaudePrompt,
        };
        let (materialized, accounting) = materialize(profile, &bundle, &bodies, tokenizer.as_ref())
            .map_err(map_materialization_error)?;
        if materialized.materializer_fingerprint
            != retained
                .value
                .normalized_contract
                .target
                .materializer_fingerprint
        {
            return Err(cigar_protocol::ErrorCode::BundleInvalidated);
        }
        Ok(MaterializationResponse {
            context: materialized,
            physical_input_tokens: accounting.physical_input_tokens,
        })
    }

    fn revalidate_context_bundle(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        bundle_id: VersionId,
    ) -> Result<RevalidationResponse, cigar_protocol::ErrorCode> {
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_bundle(&state, &bundle_id)?;
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let reasons = self.revalidation_reasons(&state, &retained.value, &authorization)?;
        Ok(RevalidationResponse {
            bundle_id,
            valid: reasons.is_empty(),
            reasons: reasons.into_iter().collect(),
        })
    }

    fn revalidation_reasons(
        &self,
        request: &ApplicationRequest,
        retained: &RetainedCompileRecord,
        authorization: &CatalogContextAuthorization,
    ) -> Result<BTreeSet<String>, cigar_protocol::ErrorCode> {
        let mut reasons = BTreeSet::new();
        if authorization.policy_digest != retained.policy_digest {
            reasons.insert("policy_changed".to_owned());
        }
        let authorized_projects: Vec<_> = authorization.project_ids.iter().cloned().collect();
        if authorized_projects != retained.authorized_projects
            || authorization.processor != retained.processor
            || authorization.purpose != retained.normalized_contract.purpose
        {
            reasons.insert("authorization_changed".to_owned());
        }
        if self
            .tokenizers
            .tokenizer(&retained.normalized_contract.target.tokenizer_fingerprint)
            .is_none()
        {
            reasons.insert("tokenizer_unavailable".to_owned());
        }
        let access = AccessContext::new(
            request.identity.tenant_id.clone(),
            authorization.purpose.clone(),
        )
        .map_err(map_store_error)?;
        let read = self
            .repository
            .begin_read(
                access,
                SnapshotSelection::Latest,
                request.store_cancellation.clone(),
            )
            .map_err(map_store_error)?;
        match read
            .get_bundle(&retained.bundle.bundle_id)
            .map_err(map_store_error)?
        {
            Some(bundle) if bundle == retained.bundle => {}
            Some(_bundle) => {
                reasons.insert("bundle_integrity_changed".to_owned());
            }
            None => {
                reasons.insert("bundle_missing".to_owned());
            }
        }
        for candidate in retained.selected_candidates.values() {
            request.check()?;
            let atom = read
                .get_atom(&candidate.version_id)
                .map_err(map_store_error)?;
            let active = read
                .get_active_atom_by_id(&candidate.atom_id)
                .map_err(map_store_error)?;
            match atom {
                Some(atom)
                    if atom.content_digest == candidate.content_digest
                        && atom_visible(
                            &atom,
                            authorization,
                            request.observed_at,
                            &retained.normalized_contract,
                        ) => {}
                Some(_atom) => {
                    reasons.insert("catalog_version_changed".to_owned());
                }
                None => {
                    reasons.insert("catalog_version_missing".to_owned());
                }
            }
            if active.as_ref().map(|atom| &atom.version_id) != Some(&candidate.version_id) {
                reasons.insert("catalog_version_inactive".to_owned());
            }
        }
        let current_catalog_watermark = catalog_watermark(&read)?;
        if current_catalog_watermark != retained.catalog_watermark {
            reasons.insert("catalog_watermark_changed".to_owned());
        }
        let partition = authorized_partition(request, authorization)?;
        let current_retrieval = QueryPlanner::default().plan(
            &retained.normalized_contract.requirements,
            &partition,
            retained.catalog_store_revision,
            RetrievalConsistency::Strong,
            authorization.vector_allowed,
        );
        match current_retrieval.and_then(|plan| {
            StagedRetrieval.execute(
                &plan,
                self.retriever.as_ref(),
                &RetrievalContext {
                    cancellation: request.store_cancellation.clone(),
                    deadline: request.monotonic_deadline,
                },
            )
        }) {
            Ok(result) => {
                if retained_retrieval_digest(&retained.normalized_contract, &result)?
                    != retained.retrieval_plan_digest
                {
                    reasons.insert("retrieval_plan_changed".to_owned());
                }
                if retained_index_fingerprints(&result, &retained.catalog_watermark)?
                    != retained.index_fingerprints
                {
                    reasons.insert("index_fingerprint_changed".to_owned());
                }
            }
            Err(_error) => {
                reasons.insert("retrieval_unavailable".to_owned());
            }
        }
        Ok(reasons)
    }

    fn current_revision(
        &self,
        access: AccessContext,
        cancellation: &StoreCancellationToken,
    ) -> Result<StoreRevision, cigar_protocol::ErrorCode> {
        self.repository
            .begin_read(access, SnapshotSelection::Latest, cancellation.clone())
            .map(|read| read.revision())
            .map_err(map_store_error)
    }
}

struct ApplicationRequest {
    identity: ResolvedDomainIdentity,
    observed_at: UtcTimestamp,
    api_cancellation: cigar_api::CancellationToken,
    store_cancellation: StoreCancellationToken,
    monotonic_deadline: Instant,
    bridge_stop: Arc<AtomicBool>,
    cancellation_bridge: Option<JoinHandle<()>>,
}

impl ApplicationRequest {
    fn check(&self) -> Result<(), cigar_protocol::ErrorCode> {
        if self.api_cancellation.is_cancelled() {
            self.store_cancellation.cancel();
        }
        if self.store_cancellation.is_cancelled() || Instant::now() >= self.monotonic_deadline {
            Err(cigar_protocol::ErrorCode::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

impl Drop for ApplicationRequest {
    fn drop(&mut self) {
        self.bridge_stop.store(true, Ordering::Release);
        if let Some(bridge) = self.cancellation_bridge.take() {
            bridge.thread().unpark();
            let _joined = bridge.join();
        }
    }
}

struct LoadedSource {
    runtime: Arc<ConfiguredSourceRuntime>,
    configuration_digest: ContentDigest,
}

impl<R> TypedUnaryService<DiscoverSourcesOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<DiscoverSourcesRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<DiscoveryPlanResponse>, ApiError>> {
        Box::pin(async move {
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.discover_sources(&context, &cancellation, deadline, request)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<IngestCatalogOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<IngestCatalogRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<IngestionReceiptResponse>, ApiError>>
    {
        Box::pin(async move {
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.ingest_catalog(&context, &cancellation, deadline, request)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<GetSourceStatusOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<SourceIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<SourceStatusResponse>, ApiError>> {
        Box::pin(async move {
            let source_id = request.payload.source_id;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.source_status(&context, &cancellation, deadline, source_id)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<QueryCatalogOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<QueryCatalogRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<CatalogQueryResponse>, ApiError>> {
        Box::pin(async move {
            let payload = request.payload;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.query_catalog(&context, &cancellation, deadline, payload)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<BatchAtomsOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<BatchAtomsRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<AtomBatchResponse>, ApiError>> {
        Box::pin(async move {
            let payload = request.payload;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.batch_atoms(&context, &cancellation, deadline, payload)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<TombstoneAtomOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<AtomIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<MutationReceipt>, ApiError>> {
        Box::pin(async move {
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.tombstone_atom(&context, &cancellation, deadline, request)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<CreateContextPlanOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<CreateContextPlanRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ContextPlanResponse>, ApiError>> {
        Box::pin(async move {
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.create_context_plan(&context, &cancellation, deadline, request)
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<CompileContextBundleOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<CompileContextBundleRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ContextBundle>, ApiError>> {
        Box::pin(async move {
            let payload = request.payload;
            let (bundle, etag) = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.compile_context_bundle(
                            &context,
                            &cancellation,
                            deadline,
                            payload,
                        )
                    },
                )
                .await?;
            Ok(TypedResponse {
                payload: bundle,
                semantic_etag: Some(etag),
                next_page_cursor: None,
            })
        })
    }
}

impl<R> TypedUnaryService<CompileContextDeltaOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<CompileContextDeltaRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ContextDeltaResponse>, ApiError>> {
        Box::pin(async move {
            let payload = request.payload;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.compile_context_delta(
                            &context,
                            &cancellation,
                            deadline,
                            payload,
                        )
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<GetContextBundleOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<BundleIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ContextBundle>, ApiError>> {
        Box::pin(async move {
            let bundle_id = request.payload.bundle_id;
            let (bundle, etag) = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.get_context_bundle(&context, &cancellation, deadline, bundle_id)
                    },
                )
                .await?;
            Ok(TypedResponse {
                payload: bundle,
                semantic_etag: Some(etag),
                next_page_cursor: None,
            })
        })
    }
}

impl<R> TypedUnaryService<GetContextBundleManifestOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<BundleIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<SelectionManifest>, ApiError>> {
        Box::pin(async move {
            let bundle_id = request.payload.bundle_id;
            let (manifest, etag) = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.get_context_manifest(
                            &context,
                            &cancellation,
                            deadline,
                            bundle_id,
                        )
                    },
                )
                .await?;
            Ok(TypedResponse {
                payload: manifest,
                semantic_etag: Some(etag),
                next_page_cursor: None,
            })
        })
    }
}

impl<R> TypedUnaryService<ExplainContextBundleOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<ExplainContextBundleRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<ContextExplanationResponse>, ApiError>>
    {
        Box::pin(async move {
            let payload = request.payload;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.explain_context_bundle(
                            &context,
                            &cancellation,
                            deadline,
                            payload,
                        )
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<MaterializeContextBundleOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<MaterializeContextBundleRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<MaterializationResponse>, ApiError>>
    {
        Box::pin(async move {
            let payload = request.payload;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.materialize_context_bundle(
                            &context,
                            &cancellation,
                            deadline,
                            payload,
                        )
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

impl<R> TypedUnaryService<RevalidateContextBundleOperation> for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn call_typed<'a>(
        &'a self,
        context: cigar_api::RequestContext,
        request: TypedRequest<BundleIdRequest>,
    ) -> cigar_api::ServiceFuture<'a, Result<TypedResponse<RevalidationResponse>, ApiError>> {
        Box::pin(async move {
            let bundle_id = request.payload.bundle_id;
            let response = self
                .execute(
                    context,
                    move |application, context, cancellation, deadline| {
                        application.revalidate_context_bundle(
                            &context,
                            &cancellation,
                            deadline,
                            bundle_id,
                        )
                    },
                )
                .await?;
            Ok(TypedResponse::new(response))
        })
    }
}

/// Registers all six CatalogService and eight ContextService typed handlers.
pub fn register_catalog_context_handlers<R>(
    builder: &mut ProductionApplicationBuilder,
    application: Arc<CatalogContextApplication<R>>,
) -> Result<(), HandlerRegistryError>
where
    R: Repository + ServiceRepository + 'static,
{
    builder.register_unary::<DiscoverSourcesOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<IngestCatalogOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<GetSourceStatusOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<QueryCatalogOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<BatchAtomsOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<TombstoneAtomOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<CreateContextPlanOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<CompileContextBundleOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<CompileContextDeltaOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<GetContextBundleOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<GetContextBundleManifestOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<ExplainContextBundleOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<MaterializeContextBundleOperation, _>(Arc::clone(&application))?;
    builder.register_unary::<RevalidateContextBundleOperation, _>(application)?;
    Ok(())
}

struct PreparedCompile {
    record: RetainedCompileRecord,
}

#[derive(Default)]
struct CandidateSeed {
    candidate: Option<CandidateRef>,
    requirement_indices: BTreeSet<usize>,
}

fn candidate_seeds(retrieval: &StagedRetrievalResult) -> BTreeMap<VersionId, CandidateSeed> {
    let mut seeds = BTreeMap::<VersionId, CandidateSeed>::new();
    for stage in &retrieval.stages {
        for candidate in &stage.batch.candidates {
            let seed = seeds.entry(candidate.version_id.clone()).or_default();
            seed.requirement_indices.insert(stage.requirement_index);
            let replace = seed
                .candidate
                .as_ref()
                .is_none_or(|current| candidate.total_score > current.total_score);
            if replace {
                seed.candidate = Some(candidate.clone());
            }
        }
    }
    seeds
}

fn authorized_partition(
    request: &ApplicationRequest,
    authorization: &CatalogContextAuthorization,
) -> Result<AuthorizedPartition, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-AUTHORIZED-PARTITION\0v1\0");
    hasher.update(request.identity.tenant_id.as_str().as_bytes());
    hasher.update(request.identity.principal_id.as_str().as_bytes());
    for project_id in &authorization.project_ids {
        hasher.update(project_id.as_str().as_bytes());
        hasher.update([0]);
    }
    hasher.update(authorization.purpose.as_bytes());
    hasher.update([0]);
    hasher.update(authorization.processor.as_bytes());
    hasher.update([0]);
    hasher.update(authorization.policy_digest.as_str().as_bytes());
    let partition = AuthorizedPartition {
        tenant_id: request.identity.tenant_id.clone(),
        project_ids: authorization.project_ids.clone(),
        purpose: authorization.purpose.clone(),
        processor: authorization.processor.clone(),
        maximum_classification: authorization.maximum_classification,
        maximum_instruction_authority: authorization.maximum_instruction_authority,
        valid_at: request.observed_at,
        observed_as_of: request.observed_at,
        vector_allowed: authorization.vector_allowed,
        partition_digest: digest_hasher(hasher)?,
    };
    partition.validate().map_err(map_retrieval_error)?;
    Ok(partition)
}

fn validate_discovery_plan(
    plan: &DiscoveryPlan,
    expected_root: &SourceUri,
) -> Result<(), cigar_protocol::ErrorCode> {
    if &plan.root != expected_root {
        return Err(cigar_protocol::ErrorCode::IntegrityFailure);
    }
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    let mut prior = None;
    for entry in &plan.entries {
        if prior
            .as_ref()
            .is_some_and(|path: &&RelativePath| *path >= &entry.record.relative_path)
        {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        prior = Some(&entry.record.relative_path);
        if entry.disposition == DiscoveryDisposition::Include {
            count = count
                .checked_add(1)
                .ok_or(cigar_protocol::ErrorCode::LimitExceeded)?;
            bytes = bytes
                .checked_add(entry.record.size_bytes)
                .ok_or(cigar_protocol::ErrorCode::LimitExceeded)?;
        }
    }
    if count != plan.included_count || bytes != plan.included_bytes {
        return Err(cigar_protocol::ErrorCode::IntegrityFailure);
    }
    Ok(())
}

fn catalog_watermark<T: ReadTransaction>(
    read: &T,
) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-CATALOG-CONTENT-WATERMARK\0v1\0");
    let mut cursor = None;
    let mut total = 0_usize;
    loop {
        let page = read
            .query_atoms(AtomSelector::default(), 1_000, cursor.as_ref())
            .map_err(map_store_error)?;
        total = total
            .checked_add(page.items.len())
            .ok_or(cigar_protocol::ErrorCode::LimitExceeded)?;
        if total > 100_000 {
            return Err(cigar_protocol::ErrorCode::LimitExceeded);
        }
        for atom in &page.items {
            hasher.update(atom.version_id.as_str().as_bytes());
            hasher.update(atom.content_digest.as_str().as_bytes());
            hasher.update([atom.lifecycle as u8]);
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    digest_hasher(hasher)
}

fn retained_retrieval_digest(
    contract: &ContextContract,
    retrieval: &StagedRetrievalResult,
) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-RETAINED-RETRIEVAL\0v1\0");
    let requirements = serde_json::to_vec(&contract.requirements)
        .map_err(|_error| cigar_protocol::ErrorCode::Internal)?;
    hasher.update(requirements);
    for stage in &retrieval.stages {
        let index = u64::try_from(stage.requirement_index)
            .map_err(|_error| cigar_protocol::ErrorCode::LimitExceeded)?;
        hasher.update(index.to_be_bytes());
        hasher.update(stage.query_fingerprint.as_str().as_bytes());
        hasher.update(stage.batch.disclosure.index_fingerprint.as_str().as_bytes());
        for candidate in &stage.batch.candidates {
            hasher.update(candidate.version_id.as_str().as_bytes());
        }
    }
    digest_hasher(hasher)
}

fn retained_index_fingerprints(
    retrieval: &StagedRetrievalResult,
    catalog_watermark: &ContentDigest,
) -> Result<BTreeSet<ContentDigest>, cigar_protocol::ErrorCode> {
    let mut values: BTreeSet<ContentDigest> = retrieval
        .stages
        .iter()
        .map(|stage| stage.batch.disclosure.index_fingerprint.clone())
        .collect();
    if values.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"CIGAR-EMPTY-RETRIEVAL-INDEX\0v1\0");
        hasher.update(catalog_watermark.as_str().as_bytes());
        values.insert(digest_hasher(hasher)?);
    }
    Ok(values)
}

fn graph_digest(
    dependencies: &BTreeMap<VersionId, BTreeSet<VersionId>>,
) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-CONTEXT-GRAPH-REVISION\0v1\0");
    for (source, targets) in dependencies {
        hasher.update(source.as_str().as_bytes());
        for target in targets {
            hasher.update(target.as_str().as_bytes());
        }
        hasher.update([0]);
    }
    digest_hasher(hasher)
}

fn atom_body<T: ReadTransaction>(
    read: &T,
    atom: &ContextAtomV1,
) -> Result<Vec<u8>, cigar_protocol::ErrorCode> {
    let body = match &atom.payload {
        AtomPayload::InlineText(text) => text.as_bytes().to_vec(),
        AtomPayload::Structured(value) => {
            serde_json::to_vec(value).map_err(|_error| cigar_protocol::ErrorCode::Internal)?
        }
        AtomPayload::Blob(reference) => read
            .get_blob(&reference.digest)
            .map_err(map_store_error)?
            .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?
            .bytes()
            .to_vec(),
    };
    if digest_bytes(&body)? != atom.content_digest {
        return Err(cigar_protocol::ErrorCode::IntegrityFailure);
    }
    Ok(body)
}

fn atom_visible(
    atom: &ContextAtomV1,
    authorization: &CatalogContextAuthorization,
    observed_at: UtcTimestamp,
    contract: &ContextContract,
) -> bool {
    let project_visible = atom
        .scope
        .project_ids
        .iter()
        .any(|project_id| authorization.project_ids.contains(project_id));
    let purpose_visible = atom
        .governance
        .allowed_purposes
        .binary_search(&authorization.purpose)
        .is_ok();
    let processor_visible = atom.governance.processor_constraints.is_empty()
        || atom
            .governance
            .processor_constraints
            .binary_search(&authorization.processor)
            .is_ok();
    let temporal = atom.temporal.valid_from <= observed_at
        && atom
            .temporal
            .valid_until
            .is_none_or(|valid_until| observed_at < valid_until)
        && atom.temporal.observed_at <= observed_at;
    let freshness = contract
        .requirements
        .iter()
        .filter(|requirement| requirement.semantic_type == atom.kind)
        .filter_map(|requirement| requirement.maximum_age)
        .all(|maximum_age| {
            observed_at
                .unix_nanos()
                .checked_sub(atom.temporal.observed_at.unix_nanos())
                .and_then(|age| u64::try_from(age).ok())
                .is_some_and(|age| age <= maximum_age.get())
        });
    project_visible
        && purpose_visible
        && processor_visible
        && temporal
        && freshness
        && atom.governance.classification <= authorization.maximum_classification
        && atom.governance.instruction_authority <= authorization.maximum_instruction_authority
        && atom.lifecycle == Lifecycle::Active
}

fn atom_policy(
    atom: &ContextAtomV1,
    authorization: &CatalogContextAuthorization,
    observed_at: UtcTimestamp,
    contract: &ContextContract,
) -> (PolicyOutcome, Option<DispositionReason>) {
    if atom.lifecycle != Lifecycle::Active {
        return (
            PolicyOutcome::Deny,
            Some(DispositionReason::LifecycleIneligible),
        );
    }
    if !atom
        .scope
        .project_ids
        .iter()
        .any(|project_id| authorization.project_ids.contains(project_id))
        || atom.governance.classification > authorization.maximum_classification
    {
        return (PolicyOutcome::Deny, Some(DispositionReason::ScopeDenied));
    }
    if atom
        .governance
        .allowed_purposes
        .binary_search(&authorization.purpose)
        .is_err()
    {
        return (PolicyOutcome::Deny, Some(DispositionReason::PurposeDenied));
    }
    if !atom.governance.processor_constraints.is_empty()
        && atom
            .governance
            .processor_constraints
            .binary_search(&authorization.processor)
            .is_err()
    {
        return (
            PolicyOutcome::Deny,
            Some(DispositionReason::ProcessorDenied),
        );
    }
    if atom.governance.instruction_authority > authorization.maximum_instruction_authority {
        return (
            PolicyOutcome::Deny,
            Some(DispositionReason::InstructionAuthorityDenied),
        );
    }
    if !atom_visible(atom, authorization, observed_at, contract) {
        return (
            PolicyOutcome::Deny,
            Some(DispositionReason::TemporalMismatch),
        );
    }
    let requirements: Vec<_> = contract
        .requirements
        .iter()
        .filter(|requirement| requirement.semantic_type == atom.kind)
        .collect();
    if !requirements.is_empty()
        && requirements.iter().all(|requirement| {
            atom.quality.authority < requirement.minimum_authority
                || atom.quality.coverage < requirement.minimum_coverage
        })
    {
        return (
            PolicyOutcome::Deny,
            Some(DispositionReason::TrustInsufficient),
        );
    }
    (PolicyOutcome::Allow, None)
}

fn dependency_features(atom: &ContextAtomV1, estimated_tokens: u32) -> CandidateFeatures {
    let coverage = u16::try_from(atom.quality.coverage.millionths() / 100).unwrap_or(10_000);
    let confidence = u16::try_from(atom.quality.confidence.millionths() / 100).unwrap_or(10_000);
    CandidateFeatures {
        requirement_match: 10_000,
        exact_match: 10_000,
        lexical_match: 0,
        semantic_match: 0,
        graph_proximity: 10_000,
        project_proximity: 10_000,
        task_proximity: 0,
        authority: atom.quality.authority.min(10_000),
        verification: confidence,
        freshness: 10_000,
        novelty: coverage,
        conflict_risk: 0,
        staleness: 0,
        estimated_tokens,
        requirement_coverage_bits: 0,
        entity_coverage_bits: 0,
    }
}

const fn lane_for_kind(kind: AtomKind) -> LaneKind {
    match kind {
        AtomKind::Instruction | AtomKind::Policy => LaneKind::Rules,
        AtomKind::Decision | AtomKind::Conversation => LaneKind::History,
        AtomKind::ToolResult | AtomKind::Schema => LaneKind::Tools,
        AtomKind::SourceCode | AtomKind::Documentation | AtomKind::Test | AtomKind::Artifact => {
            LaneKind::Evidence
        }
    }
}

fn validate_compile_record(
    record: &RetainedCompileRecord,
) -> Result<(), cigar_protocol::ErrorCode> {
    if record.schema_version != "cigar.retained-compile.v1"
        || record.creator_id != record.normalized_contract.principal_id
        || record.plan.catalog_watermark != record.catalog_watermark
        || record.plan.contract_digest != record.bundle.contract_digest
        || record.manifest.contract_digest != record.bundle.contract_digest
        || record.authorized_projects.is_empty()
        || !record
            .authorized_projects
            .windows(2)
            .all(|window| window.first() < window.get(1))
        || record.processor.is_empty()
        || record
            .selected_candidates
            .iter()
            .any(|(version_id, candidate)| {
                version_id != &candidate.version_id
                    || !record.manifest.entries.iter().any(|entry| {
                        &entry.version_id == version_id
                            && matches!(entry.disposition, CandidateDisposition::Selected { .. })
                    })
            })
    {
        return Err(cigar_protocol::ErrorCode::IntegrityFailure);
    }
    record
        .normalized_contract
        .validate()
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)?;
    record
        .plan
        .validate()
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)?;
    record
        .manifest
        .validate()
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)?;
    record
        .bundle
        .validate()
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)?;
    let manifest_digest = ContentDigest::new(record.manifest.manifest_id.as_str())
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)?;
    if manifest_digest != record.bundle.manifest_digest {
        return Err(cigar_protocol::ErrorCode::IntegrityFailure);
    }
    let block_ids: BTreeSet<_> = record
        .bundle
        .blocks
        .iter()
        .map(|block| &block.block_id)
        .collect();
    let retained_block_ids: BTreeSet<_> = record.block_sources.keys().collect();
    if block_ids != retained_block_ids
        || record
            .block_sources
            .values()
            .any(|version_id| !record.selected_candidates.contains_key(version_id))
    {
        return Err(cigar_protocol::ErrorCode::IntegrityFailure);
    }
    Ok(())
}

fn encode_record<T: Serialize>(value: &T) -> Result<Vec<u8>, cigar_protocol::ErrorCode> {
    let bytes = serde_json::to_vec(value).map_err(|_error| cigar_protocol::ErrorCode::Internal)?;
    parse_strict_json(&bytes).map_err(|_error| cigar_protocol::ErrorCode::Internal)?;
    Ok(bytes)
}

fn decode_record<T: DeserializeOwned>(
    record: &ServiceRecord,
) -> Result<T, cigar_protocol::ErrorCode> {
    parse_strict_json(record.bytes())
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)?;
    serde_json::from_slice(record.bytes())
        .map_err(|_error| cigar_protocol::ErrorCode::IntegrityFailure)
}

fn digest_json<T: Serialize>(value: &T) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let bytes = encode_record(value)?;
    digest_bytes(&bytes)
}

fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    digest_hasher(hasher)
}

fn digest_hasher(hasher: Sha256) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut encoded = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").map_err(|_error| cigar_protocol::ErrorCode::Internal)?;
    }
    ContentDigest::new(encoded).map_err(|_error| cigar_protocol::ErrorCode::Internal)
}

fn deterministic_record_id(parts: &[&[u8]]) -> Result<RecordId, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    RecordId::new(format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    ))
    .map_err(|_error| cigar_protocol::ErrorCode::Internal)
}

fn parse_revision(value: Option<&str>) -> Result<StoreRevision, cigar_protocol::ErrorCode> {
    let value = value.ok_or(cigar_protocol::ErrorCode::InvalidArgument)?;
    if value.starts_with("W/") {
        return Err(cigar_protocol::ErrorCode::InvalidArgument);
    }
    let value = match (value.strip_prefix('"'), value.strip_suffix('"')) {
        (Some(without_prefix), Some(_without_suffix)) => without_prefix
            .strip_suffix('"')
            .ok_or(cigar_protocol::ErrorCode::InvalidArgument)?,
        (None, None) => value,
        (Some(_), None) | (None, Some(_)) => {
            return Err(cigar_protocol::ErrorCode::InvalidArgument);
        }
    };
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(cigar_protocol::ErrorCode::InvalidArgument);
    }
    value
        .parse::<u64>()
        .map(StoreRevision)
        .map_err(|_error| cigar_protocol::ErrorCode::InvalidArgument)
}

fn parse_idempotency(value: Option<&str>) -> Result<IdempotencyKey, cigar_protocol::ErrorCode> {
    IdempotencyKey::new(value.ok_or(cigar_protocol::ErrorCode::InvalidArgument)?)
        .map_err(|_error| cigar_protocol::ErrorCode::InvalidArgument)
}

fn strong_etag(value: &str) -> String {
    format!("\"{value}\"")
}

const fn map_authorization_error(
    error: CatalogContextAuthorizationError,
) -> cigar_protocol::ErrorCode {
    match error {
        CatalogContextAuthorizationError::Denied => cigar_protocol::ErrorCode::PolicyDenied,
        CatalogContextAuthorizationError::InvalidDecision => {
            cigar_protocol::ErrorCode::IntegrityFailure
        }
        CatalogContextAuthorizationError::Unavailable => {
            cigar_protocol::ErrorCode::DependencyUnavailable
        }
    }
}

const fn map_catalog_error(error: CatalogError) -> cigar_protocol::ErrorCode {
    match error.code() {
        CatalogErrorCode::InvalidMetadata => cigar_protocol::ErrorCode::InvalidArgument,
        CatalogErrorCode::Denied => cigar_protocol::ErrorCode::PolicyDenied,
        CatalogErrorCode::NotFound => cigar_protocol::ErrorCode::InvalidArgument,
        CatalogErrorCode::SourceChanged => cigar_protocol::ErrorCode::RevisionConflict,
        CatalogErrorCode::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        CatalogErrorCode::Cancelled | CatalogErrorCode::DeadlineExceeded => {
            cigar_protocol::ErrorCode::DeadlineExceeded
        }
        CatalogErrorCode::Unavailable => cigar_protocol::ErrorCode::SourceUnavailable,
        CatalogErrorCode::InvalidRecord => cigar_protocol::ErrorCode::IntegrityFailure,
    }
}

const fn map_store_error(error: StoreError) -> cigar_protocol::ErrorCode {
    match error.code() {
        StoreErrorCode::InvalidContext => cigar_protocol::ErrorCode::PolicyDenied,
        StoreErrorCode::NotFound => cigar_protocol::ErrorCode::InvalidArgument,
        StoreErrorCode::RevisionConflict => cigar_protocol::ErrorCode::RevisionConflict,
        StoreErrorCode::InvalidRecord | StoreErrorCode::MixedSnapshot => {
            cigar_protocol::ErrorCode::IntegrityFailure
        }
        StoreErrorCode::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        StoreErrorCode::Cancelled => cigar_protocol::ErrorCode::DeadlineExceeded,
        StoreErrorCode::InjectedAbort | StoreErrorCode::Unavailable => {
            cigar_protocol::ErrorCode::DependencyUnavailable
        }
    }
}

const fn map_service_error(error: ServiceError) -> cigar_protocol::ErrorCode {
    match error.code() {
        ServiceErrorCode::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        ServiceErrorCode::NotFound => cigar_protocol::ErrorCode::InvalidArgument,
        ServiceErrorCode::RevisionConflict => cigar_protocol::ErrorCode::RevisionConflict,
        ServiceErrorCode::IdempotencyConflict => cigar_protocol::ErrorCode::IntegrityFailure,
        ServiceErrorCode::CursorScopeMismatch => cigar_protocol::ErrorCode::InvalidArgument,
        ServiceErrorCode::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        ServiceErrorCode::Cancelled => cigar_protocol::ErrorCode::DeadlineExceeded,
        ServiceErrorCode::InjectedAbort | ServiceErrorCode::Unavailable => {
            cigar_protocol::ErrorCode::DependencyUnavailable
        }
    }
}

const fn map_retrieval_error(error: RetrievalError) -> cigar_protocol::ErrorCode {
    match error.code() {
        RetrievalErrorCode::InvalidMetadata => cigar_protocol::ErrorCode::InvalidArgument,
        RetrievalErrorCode::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        RetrievalErrorCode::Denied => cigar_protocol::ErrorCode::PolicyDenied,
        RetrievalErrorCode::IndexUnavailable => cigar_protocol::ErrorCode::IndexUnavailable,
        RetrievalErrorCode::IndexStale => cigar_protocol::ErrorCode::IndexStale,
        RetrievalErrorCode::CorruptGeneration => cigar_protocol::ErrorCode::IntegrityFailure,
        RetrievalErrorCode::Cancelled | RetrievalErrorCode::DeadlineExceeded => {
            cigar_protocol::ErrorCode::DeadlineExceeded
        }
        RetrievalErrorCode::ChannelUnavailable => cigar_protocol::ErrorCode::DependencyUnavailable,
        RetrievalErrorCode::RequiredCandidateMissing => {
            cigar_protocol::ErrorCode::MissingRequiredContext
        }
    }
}

const fn map_compiler_error(error: CompilerError) -> cigar_protocol::ErrorCode {
    match error.code() {
        CompilerErrorCode::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        CompilerErrorCode::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        CompilerErrorCode::BudgetUnsatisfiable => cigar_protocol::ErrorCode::BudgetUnsatisfiable,
        CompilerErrorCode::RequiredMissing => cigar_protocol::ErrorCode::MissingRequiredContext,
        CompilerErrorCode::InvalidDependency | CompilerErrorCode::SealFailed => {
            cigar_protocol::ErrorCode::IntegrityFailure
        }
        CompilerErrorCode::UnresolvedCriticalConflict => {
            cigar_protocol::ErrorCode::UnresolvedCriticalConflict
        }
        CompilerErrorCode::PinMismatch => cigar_protocol::ErrorCode::BundleInvalidated,
        CompilerErrorCode::PolicyDenied => cigar_protocol::ErrorCode::PolicyDenied,
    }
}

const fn map_materialization_error(error: MaterializationError) -> cigar_protocol::ErrorCode {
    match error {
        MaterializationError::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        MaterializationError::ContentMismatch => cigar_protocol::ErrorCode::IntegrityFailure,
        MaterializationError::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        MaterializationError::Serialization => cigar_protocol::ErrorCode::Internal,
    }
}

const fn map_delta_error(error: cigar_compiler::DeltaError) -> cigar_protocol::ErrorCode {
    match error {
        cigar_compiler::DeltaError::WrongBase => cigar_protocol::ErrorCode::DeltaBaseMismatch,
        cigar_compiler::DeltaError::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        cigar_compiler::DeltaError::Tampered | cigar_compiler::DeltaError::TargetMismatch => {
            cigar_protocol::ErrorCode::IntegrityFailure
        }
        cigar_compiler::DeltaError::Digest => cigar_protocol::ErrorCode::Internal,
    }
}

impl<R> crate::RecipientBundleCompiler for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn compile_recipient_bundle(
        &self,
        request: crate::RecipientCompilationRequest,
        cancellation: &StoreCancellationToken,
    ) -> Result<RecipientBundleReceipt, crate::SpaceHandoffDependencyError> {
        if request.accepted.recipient_id != request.recipient_id
            || request.accepted.project_ids.is_empty()
            || !request.accepted.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::ReadContext | Capability::CompileContext
                )
            })
            || !request
                .accepted
                .project_ids
                .windows(2)
                .all(|window| window.first() < window.get(1))
        {
            return Err(crate::SpaceHandoffDependencyError::Invalid);
        }
        if cancellation.is_cancelled() {
            return Err(crate::SpaceHandoffDependencyError::Unavailable);
        }
        let locator = ServiceRecordLocator::new(
            request.tenant_id.clone(),
            CONTEXT_PLAN_NAMESPACE,
            request.target_plan_id.as_str(),
        )
        .map_err(|_error| crate::SpaceHandoffDependencyError::Invalid)?;
        let stored = self
            .repository
            .service_get(&locator, ServiceRecordSelection::Latest, cancellation)
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?
            .ok_or(crate::SpaceHandoffDependencyError::Denied)?;
        let target_plan_revision = stored.version();
        let target_plan_digest = stored.digest().clone();
        let retained: RetainedCompileRecord =
            decode_record(&stored).map_err(map_handoff_dependency_code)?;
        validate_compile_record(&retained).map_err(map_handoff_dependency_code)?;
        let accepted_projects: BTreeSet<_> = request.accepted.project_ids.iter().collect();
        let retained_projects: BTreeSet<_> = retained.authorized_projects.iter().collect();
        if retained.tenant_id != request.tenant_id
            || retained.plan.plan_id != request.target_plan_id
            || retained.normalized_contract.principal_id != request.recipient_id
            || retained.policy_digest != request.policy_digest
            || !retained_projects.is_subset(&accepted_projects)
            || retained.bundle.total_tokens > request.accepted.budget.total_input_tokens
            || retained.normalized_contract.budget.total_input_tokens
                > request.accepted.budget.total_input_tokens
        {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        let access = AccessContext::new(
            request.tenant_id.clone(),
            retained.normalized_contract.purpose.clone(),
        )
        .map_err(|_error| crate::SpaceHandoffDependencyError::Invalid)?;
        let read = self
            .repository
            .begin_read(access, SnapshotSelection::Latest, cancellation.clone())
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?;
        let persisted = read
            .get_bundle(&retained.bundle.bundle_id)
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?
            .ok_or(crate::SpaceHandoffDependencyError::Unavailable)?;
        if persisted != retained.bundle {
            return Err(crate::SpaceHandoffDependencyError::Unavailable);
        }
        let source = read
            .get_bundle(&request.source_bundle_id)
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?
            .ok_or(crate::SpaceHandoffDependencyError::Denied)?;
        if source.bundle_id != request.source_bundle_id {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        let accepted_references: BTreeSet<_> =
            accepted_handoff_reference_ids(&request.accepted.references)
                .into_iter()
                .cloned()
                .collect();
        let source_versions: BTreeSet<_> = source
            .blocks
            .iter()
            .flat_map(|block| block.provenance.iter().cloned())
            .collect();
        let allowed_versions: BTreeSet<_> = source_versions
            .union(&accepted_references)
            .cloned()
            .collect();
        if retained
            .block_sources
            .values()
            .any(|version| !allowed_versions.contains(version))
            || persisted
                .blocks
                .iter()
                .flat_map(|block| &block.provenance)
                .any(|version| !allowed_versions.contains(version))
        {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        let derivation_digest = recipient_derivation_digest(
            &request,
            target_plan_revision,
            &target_plan_digest,
            &persisted.bundle_id,
        )
        .map_err(map_handoff_dependency_code)?;
        Ok(RecipientBundleReceipt {
            bundle_id: persisted.bundle_id,
            source_bundle_id: request.source_bundle_id,
            target_plan_id: request.target_plan_id,
            target_plan_revision,
            target_plan_digest,
            derivation_digest,
        })
    }
}

impl<R> crate::HandoffReferenceResolver for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository + 'static,
{
    fn resolve_reference(
        &self,
        _context: &cigar_api::RequestContext,
        identity: &ResolvedDomainIdentity,
        authorization: &crate::CurrentSpaceHandoffAuthorization,
        project_id: &RecordId,
        version_id: &VersionId,
        expected_kind: ResultMergeKind,
        cancellation: &StoreCancellationToken,
    ) -> Result<crate::ResolvedHandoffReference, crate::SpaceHandoffDependencyError> {
        if cancellation.is_cancelled()
            || authorization.resource_project_id.as_ref() != Some(project_id)
            || !authorization.effective.project_ids.contains(project_id)
        {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        let observed_at = self
            .clock
            .now()
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?;
        let catalog = self
            .authorizer
            .authorize_catalog(identity, observed_at)
            .map_err(|error| match error {
                CatalogContextAuthorizationError::Denied => {
                    crate::SpaceHandoffDependencyError::Denied
                }
                CatalogContextAuthorizationError::InvalidDecision => {
                    crate::SpaceHandoffDependencyError::Invalid
                }
                CatalogContextAuthorizationError::Unavailable => {
                    crate::SpaceHandoffDependencyError::Unavailable
                }
            })?;
        if catalog.policy_digest != authorization.policy_digest
            || !catalog.project_ids.contains(project_id)
        {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        let access = AccessContext::new(identity.tenant_id.clone(), catalog.purpose.clone())
            .map_err(|_error| crate::SpaceHandoffDependencyError::Invalid)?;
        let atom = self
            .repository
            .begin_read(access, SnapshotSelection::Latest, cancellation.clone())
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?
            .get_atom(version_id)
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?
            .ok_or(crate::SpaceHandoffDependencyError::Denied)?;
        let required_kind = match expected_kind {
            ResultMergeKind::Decision => AtomKind::Decision,
            ResultMergeKind::Artifact => AtomKind::Artifact,
            ResultMergeKind::SourceChange => AtomKind::SourceCode,
        };
        if atom.validate().is_err()
            || &atom.version_id != version_id
            || atom.scope.tenant_id != identity.tenant_id
            || atom.kind != required_kind
            || atom.scope.project_ids.binary_search(project_id).is_err()
            || !atom_visible_for_reference(&atom, &catalog, observed_at)
        {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        Ok(crate::ResolvedHandoffReference {
            version_id: atom.version_id,
            kind: expected_kind,
            content_digest: atom.content_digest,
        })
    }
}

fn atom_visible_for_reference(
    atom: &ContextAtomV1,
    authorization: &CatalogContextAuthorization,
    observed_at: UtcTimestamp,
) -> bool {
    atom.lifecycle == Lifecycle::Active
        && atom
            .scope
            .project_ids
            .iter()
            .any(|project| authorization.project_ids.contains(project))
        && atom
            .governance
            .allowed_purposes
            .binary_search(&authorization.purpose)
            .is_ok()
        && (atom.governance.processor_constraints.is_empty()
            || atom
                .governance
                .processor_constraints
                .binary_search(&authorization.processor)
                .is_ok())
        && atom.governance.classification <= authorization.maximum_classification
        && atom.governance.instruction_authority <= authorization.maximum_instruction_authority
        && atom.temporal.valid_from <= observed_at
        && atom
            .temporal
            .valid_until
            .is_none_or(|valid_until| observed_at < valid_until)
        && atom.temporal.observed_at <= observed_at
}

fn accepted_handoff_reference_ids(
    references: &cigar_protocol::HandoffReferences,
) -> Vec<&VersionId> {
    references
        .sources
        .iter()
        .chain(&references.states)
        .chain(&references.decisions)
        .chain(&references.artifacts)
        .chain(&references.uncertainties)
        .chain(&references.effects)
        .collect()
}

fn recipient_derivation_digest(
    request: &crate::RecipientCompilationRequest,
    target_plan_revision: u64,
    target_plan_digest: &ContentDigest,
    bundle_id: &VersionId,
) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let value = (
        &request.handoff_id,
        &request.source_bundle_id,
        &request.target_plan_id,
        target_plan_revision,
        target_plan_digest,
        bundle_id,
        &request.accepted,
        &request.tenant_id,
        &request.recipient_id,
        &request.policy_digest,
    );
    let bytes = encode_record(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-HANDOFF-RECIPIENT-DERIVATION\0v1\0");
    hasher.update(bytes);
    digest_hasher(hasher)
}

const fn map_handoff_dependency_code(
    code: cigar_protocol::ErrorCode,
) -> crate::SpaceHandoffDependencyError {
    match code {
        cigar_protocol::ErrorCode::InvalidArgument
        | cigar_protocol::ErrorCode::LimitExceeded
        | cigar_protocol::ErrorCode::UnsupportedSchema => {
            crate::SpaceHandoffDependencyError::Invalid
        }
        cigar_protocol::ErrorCode::PolicyDenied
        | cigar_protocol::ErrorCode::ProcessorDenied
        | cigar_protocol::ErrorCode::InstructionAuthorityDenied
        | cigar_protocol::ErrorCode::UnknownPrincipal
        | cigar_protocol::ErrorCode::InvalidCapability
        | cigar_protocol::ErrorCode::CapabilityExpired => {
            crate::SpaceHandoffDependencyError::Denied
        }
        _ => crate::SpaceHandoffDependencyError::Unavailable,
    }
}

impl<R> fmt::Debug for CatalogContextApplication<R>
where
    R: Repository + ServiceRepository,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogContextApplication")
            .field("repository", &"[INJECTED]")
            .field("identity_resolver", &"[INJECTED]")
            .field("authorizer", &"[INJECTED]")
            .field("retriever", &"[INJECTED]")
            .field("tokenizers", &"[PINNED]")
            .field("source_runtimes", &"[TENANT-SCOPED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CatalogContextApplication, CatalogContextAuthorization, CatalogContextAuthorizationError,
        CatalogContextAuthorizer, ConfiguredSourceRuntime, ContextTokenizerRegistry,
        PinnedContextTokenizerRegistry, RetainedCompileRecord, SourceConfiguration,
        SourceDiscoveryPolicyConfiguration,
    };
    use crate::{
        AuthorityClock, AuthorityError, BlockingPool, DomainIdentityError, DomainIdentityResolver,
        ResolvedDomainIdentity,
    };
    use cigar_api::{
        AuthenticatedIdentity, BundleIdRequest, CancellationToken, CompileContextBundleOperation,
        CompileContextBundleRequest, CreateContextPlanOperation, CreateContextPlanRequest,
        DiscoverSourcesOperation, DiscoverSourcesRequest, FacadeErrorFactory,
        GetSourceStatusOperation, MAX_OPERATION_PAYLOAD_BYTES, MaterializationProfile,
        MaterializeContextBundleOperation, MaterializeContextBundleRequest, OperationId,
        PathParameter, PrincipalId, RequestContext, RequestEnvelope,
        RevalidateContextBundleOperation, SourceIdRequest, TenantId, TraceId, TypedUnaryAdapter,
        UnaryOperationHandler, decode_operation_payload, encode_operation_payload,
    };
    use cigar_catalog::{
        AtomizationOutput, AtomizationRequest, Atomizer, AtomizerDescriptor, AtomizerInvalidation,
        CatalogError, ConnectorContext, LocalFilesystemConnector,
    };
    use cigar_protocol::{
        AtomKind, AtomPayload, Budget, Classification, ContentDigest, ContextAtomV1, ContextBundle,
        ContextContract, ContextRequirement, ExtensionMap, FixedPoint, GovernanceEnvelope,
        InstructionAuthority, LaneKind, Lifecycle, MediaType, OperationClass, QualityEnvelope,
        RecordId, RequirementSelector, RetrievalEnvelope, SchemaVersion, ScopeEnvelope,
        SourceDescriptor, SourceUri, TargetProfile, TemporalEnvelope, UtcTimestamp, VersionId,
    };
    use cigar_retrieval::{InMemoryIndexManager, IndexBuild, RetrievalContext};
    use cigar_store::{
        AccessContext, CancellationToken as StoreCancellationToken, InMemoryStore, ReadTransaction,
        Repository, ServiceRecordLocator, ServiceRecordSelection, ServiceRepository,
        SnapshotSelection, StoreRevision, WriteTransaction,
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct Errors(RecordId);

    impl FacadeErrorFactory for Errors {
        fn public_error(&self, code: cigar_protocol::ErrorCode) -> cigar_api::ApiError {
            cigar_api::ApiError::new(code, self.0.clone())
        }
    }

    struct IdentityResolver(ResolvedDomainIdentity);

    impl DomainIdentityResolver for IdentityResolver {
        fn resolve(
            &self,
            _context: &RequestContext,
        ) -> Result<ResolvedDomainIdentity, DomainIdentityError> {
            Ok(self.0.clone())
        }
    }

    struct FixedAuthorizer(CatalogContextAuthorization);

    impl CatalogContextAuthorizer for FixedAuthorizer {
        fn authorize_catalog(
            &self,
            _identity: &ResolvedDomainIdentity,
            _observed_at: UtcTimestamp,
        ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
            Ok(self.0.clone())
        }

        fn authorize_contract(
            &self,
            _identity: &ResolvedDomainIdentity,
            contract: &ContextContract,
            _observed_at: UtcTimestamp,
        ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
            if contract
                .project_ids
                .iter()
                .all(|project_id| self.0.project_ids.contains(project_id))
            {
                Ok(self.0.clone())
            } else {
                Err(CatalogContextAuthorizationError::Denied)
            }
        }
    }

    struct FixedClock(UtcTimestamp);

    impl AuthorityClock for FixedClock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            Ok(self.0)
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            i64::try_from(self.0.unix_nanos() / 1_000_000_000)
                .map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    struct NoopAtomizer {
        media_type: MediaType,
    }

    impl Atomizer for NoopAtomizer {
        fn descriptor(&self) -> AtomizerDescriptor {
            AtomizerDescriptor {
                id: "test.noop".to_owned(),
                version: "1.0.0".to_owned(),
                media_types: BTreeSet::from([self.media_type.clone()]),
                max_input_bytes: 1_048_576,
                produced_kinds: BTreeSet::from([AtomKind::Documentation]),
                authority_ceiling: InstructionAuthority::Data,
                invalidation: AtomizerInvalidation {
                    source_bytes: true,
                    source_metadata: true,
                    adapter_version: true,
                },
            }
        }

        fn atomize(
            &self,
            _request: AtomizationRequest<'_>,
            context: &ConnectorContext,
        ) -> Result<AtomizationOutput, CatalogError> {
            context.check()?;
            Ok(AtomizationOutput {
                atoms: Vec::new(),
                edges: Vec::new(),
            })
        }
    }

    fn record(value: u64) -> Result<RecordId, cigar_protocol::ValidationErrors> {
        RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{value:012x}"))
    }

    fn version(value: u64) -> Result<VersionId, cigar_protocol::ValidationErrors> {
        VersionId::new(format!("1220{value:064x}"))
    }

    fn digest_bytes(bytes: &[u8]) -> Result<ContentDigest, cigar_protocol::ValidationErrors> {
        let hash = Sha256::digest(bytes);
        let mut encoded = String::from("1220");
        use std::fmt::Write as _;
        for byte in hash {
            write!(&mut encoded, "{byte:02x}").map_err(|_error| {
                let mut errors = cigar_protocol::ValidationErrors::new();
                errors.push(cigar_protocol::ValidationIssue {
                    code: cigar_protocol::ValidationCode::InvalidValue,
                    path: "/digest".to_owned(),
                    message: "digest formatting failed".to_owned(),
                });
                errors
            })?;
        }
        ContentDigest::new(encoded)
    }

    fn timestamp() -> Result<UtcTimestamp, cigar_protocol::ValidationErrors> {
        UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")
    }

    fn atom(
        tenant_id: &RecordId,
        project_id: &RecordId,
        body: &str,
    ) -> Result<ContextAtomV1, cigar_protocol::ValidationErrors> {
        Ok(ContextAtomV1 {
            schema_version: SchemaVersion::new("cigar.atom", 1)?,
            atom_id: record(10)?,
            lineage_id: cigar_protocol::LineageId::new("01890f47-8e7d-7b42-a1d2-000000000011")?,
            version_id: version(12)?,
            content_digest: digest_bytes(body.as_bytes())?,
            kind: AtomKind::Documentation,
            payload: AtomPayload::InlineText(body.to_owned()),
            source: SourceDescriptor {
                uri: SourceUri::new("file:///fixture/readme.md")?,
                relative_path: Some(cigar_protocol::RelativePath::new(b"readme.md".to_vec())?),
                revision: "revision-1".to_owned(),
                snapshot_digest: ContentDigest::new(format!("1220{}", "a".repeat(64)))?,
            },
            scope: ScopeEnvelope {
                tenant_id: tenant_id.clone(),
                project_ids: vec![project_id.clone()],
            },
            temporal: TemporalEnvelope {
                valid_from: UtcTimestamp::parse_rfc3339("2026-01-01T00:00:00Z")?,
                valid_until: None,
                observed_at: UtcTimestamp::parse_rfc3339("2026-07-01T00:00:00Z")?,
            },
            governance: GovernanceEnvelope {
                classification: Classification::Internal,
                allowed_purposes: vec!["coding".to_owned()],
                processor_constraints: Vec::new(),
                instruction_authority: InstructionAuthority::Data,
            },
            quality: QualityEnvelope {
                confidence: FixedPoint::new(FixedPoint::ONE)?,
                coverage: FixedPoint::new(FixedPoint::ONE)?,
                authority: 10,
            },
            retrieval: RetrievalEnvelope {
                exact_terms: vec!["readme".to_owned()],
                lexical_enabled: true,
                embedding_eligible: false,
            },
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        })
    }

    fn contract(
        caller_principal: RecordId,
        project_id: RecordId,
        version_id: VersionId,
        tokenizer: ContentDigest,
        materializer: ContentDigest,
    ) -> Result<ContextContract, cigar_protocol::ValidationErrors> {
        Ok(ContextContract {
            schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
            job_goal: "Answer from retained documentation".to_owned(),
            operation_class: OperationClass::Read,
            principal_id: caller_principal,
            purpose: "coding".to_owned(),
            context_space_id: None,
            project_ids: vec![project_id],
            target: TargetProfile {
                provider: "local".to_owned(),
                model_family: "byte-metered".to_owned(),
                tokenizer_fingerprint: tokenizer,
                materializer_fingerprint: materializer,
                max_context_tokens: 256,
            },
            budget: Budget {
                total_input_tokens: 128,
                output_reserve_tokens: 64,
                lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 128)]),
            },
            requirements: vec![ContextRequirement {
                semantic_type: AtomKind::Documentation,
                selector: RequirementSelector::Exact(version_id),
                minimum_authority: 1,
                maximum_age: None,
                minimum_coverage: FixedPoint::new(0)?,
                blocking: true,
            }],
            consistency: cigar_protocol::ConsistencyMode::Strong,
            maximum_staleness: None,
            extensions: ExtensionMap::default(),
        })
    }

    fn request_context(
        operation: &str,
        now: UtcTimestamp,
    ) -> Result<RequestContext, Box<dyn std::error::Error>> {
        let deadline = UtcTimestamp::from_unix_nanos(
            now.unix_nanos()
                .checked_add(60_000_000_000)
                .ok_or("deadline overflow")?,
        )?;
        Ok(RequestContext::new(
            AuthenticatedIdentity::from_verified_credentials(
                TenantId::new("tenant-authenticated")?,
                PrincipalId::new("principal-authenticated")?,
            ),
            OperationId::new(operation)?,
            deadline,
            TraceId::new("0123456789abcdef0123456789abcdef")?,
            CancellationToken::new(),
            now,
        )?)
    }

    struct Fixture {
        store: Arc<InMemoryStore>,
        application: Arc<CatalogContextApplication<InMemoryStore>>,
        errors: Arc<dyn FacadeErrorFactory>,
        tokenizer_registry: Arc<PinnedContextTokenizerRegistry>,
        retriever: Arc<InMemoryIndexManager>,
        identities: Arc<IdentityResolver>,
        authorizer: Arc<FixedAuthorizer>,
        clock: Arc<FixedClock>,
        contract: ContextContract,
        tenant_id: RecordId,
        principal_id: RecordId,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let tenant_id = record(1)?;
        let principal_id = record(2)?;
        let caller_principal = record(99)?;
        let project_id = record(3)?;
        let body = "retained documentation";
        let atom = atom(&tenant_id, &project_id, body)?;
        let tokenizer = ContentDigest::new(format!("1220{}", "b".repeat(64)))?;
        let materializer = digest_bytes(b"cigar.materializer.json.v1")?;
        let contract = contract(
            caller_principal,
            project_id.clone(),
            atom.version_id.clone(),
            tokenizer.clone(),
            materializer,
        )?;
        let store = Arc::new(InMemoryStore::default());
        let access = AccessContext::new(tenant_id.clone(), "coding")?;
        let mut write =
            store.begin_write(access, StoreRevision(0), StoreCancellationToken::default())?;
        write.publish_atoms(vec![atom.clone()], Vec::new())?;
        write.commit(None)?;
        let retriever = Arc::new(InMemoryIndexManager::default());
        let retrieval_context = RetrievalContext {
            cancellation: StoreCancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let descriptor = retriever.build_generation(
            IndexBuild {
                atoms: vec![atom],
                edges: Vec::new(),
                built_through_revision: StoreRevision(1),
                configuration_digest: ContentDigest::new(format!("1220{}", "c".repeat(64)))?,
                verified_at: timestamp()?,
                vector_fingerprint: None,
            },
            &retrieval_context,
        )?;
        retriever.activate(&descriptor.generation_id, None)?;
        let tokenizer_registry = Arc::new(PinnedContextTokenizerRegistry::default());
        tokenizer_registry.register_byte_tokenizer(tokenizer)?;
        let authorization = CatalogContextAuthorization {
            project_ids: BTreeSet::from([project_id]),
            purpose: "coding".to_owned(),
            processor: "local".to_owned(),
            maximum_classification: Classification::Internal,
            maximum_instruction_authority: InstructionAuthority::Project,
            policy_digest: ContentDigest::new(format!("1220{}", "d".repeat(64)))?,
            vector_allowed: false,
        };
        let identities = Arc::new(IdentityResolver(ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id: principal_id.clone(),
        }));
        let authorizer = Arc::new(FixedAuthorizer(authorization));
        let clock = Arc::new(FixedClock(timestamp()?));
        let errors: Arc<dyn FacadeErrorFactory> = Arc::new(Errors(record(50)?));
        let application = Arc::new(CatalogContextApplication::new(
            Arc::clone(&store),
            identities.clone(),
            authorizer.clone(),
            retriever.clone(),
            tokenizer_registry.clone(),
            Arc::new(BlockingPool::new(2, 2)?),
            clock.clone(),
            Arc::clone(&errors),
        ));
        Ok(Fixture {
            store,
            application,
            errors,
            tokenizer_registry,
            retriever,
            identities,
            authorizer,
            clock,
            contract,
            tenant_id,
            principal_id,
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dry_run_does_not_mutate_and_restart_serves_real_compile_artifacts() -> TestResult {
        let fixture = fixture()?;
        let request_payload = CreateContextPlanRequest {
            contract: fixture.contract.clone(),
        };
        let encoded = encode_operation_payload(&request_payload, MAX_OPERATION_PAYLOAD_BYTES)?;
        let adapter = TypedUnaryAdapter::<CreateContextPlanOperation, _>::new(
            Arc::clone(&fixture.application),
            Arc::clone(&fixture.errors),
        );
        let dry_request = RequestEnvelope::new_with_dry_run(
            "createContextPlan",
            encoded.clone(),
            true,
            Some("plan-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let dry_response = adapter
            .call(
                request_context("createContextPlan", fixture.clock.0)?,
                dry_request,
            )
            .await?;
        let dry_plan: cigar_api::ContextPlanResponse =
            decode_operation_payload(dry_response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(fixture.store.revision()?, StoreRevision(1));

        let actual_request = RequestEnvelope::new(
            "createContextPlan",
            encoded,
            Some("plan-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let actual_response = adapter
            .call(
                request_context("createContextPlan", fixture.clock.0)?,
                actual_request,
            )
            .await?;
        let actual_plan: cigar_api::ContextPlanResponse =
            decode_operation_payload(actual_response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(actual_plan, dry_plan);
        assert_eq!(fixture.store.revision()?, StoreRevision(3));
        let locator = ServiceRecordLocator::new(
            fixture.tenant_id.clone(),
            super::CONTEXT_PLAN_NAMESPACE,
            actual_plan.plan.plan_id.as_str(),
        )?;
        let retained = fixture
            .store
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &StoreCancellationToken::default(),
            )?
            .ok_or("missing retained plan")?;
        let retained: RetainedCompileRecord = super::decode_record(&retained)
            .map_err(|code| format!("retained decode failed: {code:?}"))?;
        assert_eq!(retained.creator_id, fixture.principal_id);
        assert_eq!(
            retained.normalized_contract.principal_id,
            fixture.principal_id
        );
        let access = AccessContext::new(fixture.tenant_id.clone(), "coding")?;
        assert_eq!(
            fixture
                .store
                .begin_read(
                    access,
                    SnapshotSelection::Latest,
                    StoreCancellationToken::default(),
                )?
                .get_bundle(&actual_plan.bundle_id)?,
            Some(retained.bundle.clone())
        );

        let restarted = Arc::new(CatalogContextApplication::new(
            Arc::clone(&fixture.store),
            fixture.identities,
            fixture.authorizer,
            fixture.retriever,
            fixture.tokenizer_registry as Arc<dyn ContextTokenizerRegistry>,
            Arc::new(BlockingPool::new(2, 2)?),
            fixture.clock.clone(),
            Arc::clone(&fixture.errors),
        ));
        let bundle_adapter = TypedUnaryAdapter::<CompileContextBundleOperation, _>::new(
            Arc::clone(&restarted),
            Arc::clone(&fixture.errors),
        );
        let bundle_request_payload = CompileContextBundleRequest {
            plan_id: actual_plan.plan.plan_id,
        };
        let bundle_request = RequestEnvelope::new(
            "compileContextBundle",
            encode_operation_payload(&bundle_request_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("bundle-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let bundle_response = bundle_adapter
            .call(
                request_context("compileContextBundle", fixture.clock.0)?,
                bundle_request,
            )
            .await?;
        let bundle: ContextBundle =
            decode_operation_payload(bundle_response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(bundle, retained.bundle);

        let materialize_adapter = TypedUnaryAdapter::<MaterializeContextBundleOperation, _>::new(
            Arc::clone(&restarted),
            Arc::clone(&fixture.errors),
        );
        let materialize_payload = MaterializeContextBundleRequest {
            bundle_id: bundle.bundle_id.clone(),
            profile: MaterializationProfile::CanonicalJson,
        };
        let materialize_request = RequestEnvelope::new(
            "materializeContextBundle",
            encode_operation_payload(&materialize_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("materialize-key".to_owned()),
            None,
            None,
            None,
            vec![PathParameter::new("bundle_id", bundle.bundle_id.as_str())?],
        )?;
        let materialized = materialize_adapter
            .call(
                request_context("materializeContextBundle", fixture.clock.0)?,
                materialize_request,
            )
            .await?;
        let materialized: cigar_api::MaterializationResponse =
            decode_operation_payload(materialized.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(materialized.context.bundle_id, bundle.bundle_id);
        assert_eq!(
            materialized.physical_input_tokens,
            materialized.context.token_count
        );

        let revalidate_adapter = TypedUnaryAdapter::<RevalidateContextBundleOperation, _>::new(
            restarted,
            Arc::clone(&fixture.errors),
        );
        let revalidate_payload = BundleIdRequest {
            bundle_id: bundle.bundle_id.clone(),
        };
        let revalidate_request = RequestEnvelope::new(
            "revalidateContextBundle",
            encode_operation_payload(&revalidate_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("revalidate-key".to_owned()),
            None,
            None,
            None,
            vec![PathParameter::new("bundle_id", bundle.bundle_id.as_str())?],
        )?;
        let revalidated = revalidate_adapter
            .call(
                request_context("revalidateContextBundle", fixture.clock.0)?,
                revalidate_request,
            )
            .await?;
        let revalidated: cigar_api::RevalidationResponse =
            decode_operation_payload(revalidated.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert!(revalidated.valid, "reasons: {:?}", revalidated.reasons);
        assert!(revalidated.reasons.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_configuration_and_discovery_are_tenant_durable_and_dry_run_safe() -> TestResult
    {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("README.md"), b"bounded documentation")?;
        let tenant_id = record(101)?;
        let principal_id = record(102)?;
        let project_id = record(103)?;
        let source_id = record(104)?;
        let root = SourceUri::new("file:///tenant-source")?;
        let media_type = MediaType::new("text/markdown")?;
        let connector = Arc::new(LocalFilesystemConnector::new(
            directory.path(),
            root.clone(),
        )?);
        let runtime = Arc::new(ConfiguredSourceRuntime::new(
            SourceConfiguration {
                schema_version: "cigar.source-configuration.v1".to_owned(),
                source_id: source_id.clone(),
                root,
                connector_identity: "local-filesystem.v1".to_owned(),
                discovery_policy: SourceDiscoveryPolicyConfiguration {
                    max_items: 100,
                    max_total_bytes: 1_048_576,
                    max_record_bytes: 1_048_576,
                    excluded_prefixes: Vec::new(),
                    allowed_media_types: BTreeSet::from([media_type.clone()]),
                    allow_user_broadening: false,
                    follow_internal_symlinks: false,
                    secret_patterns: Vec::new(),
                },
            },
            connector,
            vec![Arc::new(NoopAtomizer { media_type })],
        )?);
        let store = Arc::new(InMemoryStore::default());
        let authorization = CatalogContextAuthorization {
            project_ids: BTreeSet::from([project_id]),
            purpose: "coding".to_owned(),
            processor: "local".to_owned(),
            maximum_classification: Classification::Internal,
            maximum_instruction_authority: InstructionAuthority::Project,
            policy_digest: ContentDigest::new(format!("1220{}", "e".repeat(64)))?,
            vector_allowed: false,
        };
        let identities = Arc::new(IdentityResolver(ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id,
        }));
        let authorizer = Arc::new(FixedAuthorizer(authorization));
        let retriever = Arc::new(InMemoryIndexManager::default());
        let tokenizers = Arc::new(PinnedContextTokenizerRegistry::default());
        let clock = Arc::new(FixedClock(timestamp()?));
        let errors: Arc<dyn FacadeErrorFactory> = Arc::new(Errors(record(105)?));
        let application = Arc::new(CatalogContextApplication::new(
            Arc::clone(&store),
            identities.clone(),
            authorizer.clone(),
            retriever.clone(),
            tokenizers.clone(),
            Arc::new(BlockingPool::new(2, 2)?),
            clock.clone(),
            Arc::clone(&errors),
        ));
        application.provision_source(
            tenant_id.clone(),
            Arc::clone(&runtime),
            &StoreCancellationToken::default(),
        )?;
        assert_eq!(store.revision()?, StoreRevision(1));

        let restarted = Arc::new(CatalogContextApplication::new(
            Arc::clone(&store),
            identities,
            authorizer,
            retriever,
            tokenizers,
            Arc::new(BlockingPool::new(2, 2)?),
            clock.clone(),
            Arc::clone(&errors),
        ));
        restarted.provision_source(
            tenant_id.clone(),
            runtime,
            &StoreCancellationToken::default(),
        )?;
        assert_eq!(store.revision()?, StoreRevision(1));
        let adapter = TypedUnaryAdapter::<DiscoverSourcesOperation, _>::new(
            Arc::clone(&restarted),
            Arc::clone(&errors),
        );
        let payload = DiscoverSourcesRequest {
            source_id: source_id.clone(),
            include_paths: Vec::new(),
        };
        let encoded = encode_operation_payload(&payload, MAX_OPERATION_PAYLOAD_BYTES)?;
        let dry = RequestEnvelope::new_with_dry_run(
            "discoverSources",
            encoded.clone(),
            true,
            None,
            None,
            None,
            None,
            Vec::new(),
        )?;
        let dry_response = adapter
            .call(request_context("discoverSources", clock.0)?, dry)
            .await?;
        let dry_plan: cigar_api::DiscoveryPlanResponse =
            decode_operation_payload(dry_response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(dry_plan.included_count, 1);
        assert_eq!(store.revision()?, StoreRevision(1));

        let actual = RequestEnvelope::new(
            "discoverSources",
            encoded,
            None,
            None,
            None,
            None,
            Vec::new(),
        )?;
        let actual_response = adapter
            .call(request_context("discoverSources", clock.0)?, actual)
            .await?;
        let actual_plan: cigar_api::DiscoveryPlanResponse =
            decode_operation_payload(actual_response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(actual_plan, dry_plan);
        assert_eq!(store.revision()?, StoreRevision(2));
        let discovery_locator =
            ServiceRecordLocator::new(tenant_id, super::DISCOVERY_NAMESPACE, source_id.as_str())?;
        assert!(
            store
                .service_get(
                    &discovery_locator,
                    ServiceRecordSelection::Latest,
                    &StoreCancellationToken::default(),
                )?
                .is_some()
        );

        let status_adapter =
            TypedUnaryAdapter::<GetSourceStatusOperation, _>::new(restarted, Arc::clone(&errors));
        let status_payload = SourceIdRequest {
            source_id: source_id.clone(),
        };
        let status_request = RequestEnvelope::new(
            "getSourceStatus",
            encode_operation_payload(&status_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            None,
            None,
            None,
            None,
            vec![PathParameter::new("source_id", source_id.as_str())?],
        )?;
        let status = status_adapter
            .call(request_context("getSourceStatus", clock.0)?, status_request)
            .await?;
        let status: cigar_api::SourceStatusResponse =
            decode_operation_payload(status.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert_eq!(status.source_id, source_id);
        assert_eq!(status.status, cigar_api::SourceStatus::Ready);
        Ok(())
    }

    #[test]
    fn revision_parser_accepts_embedded_decimal_and_strong_if_match_only() {
        assert_eq!(super::parse_revision(Some("7")), Ok(StoreRevision(7)));
        assert_eq!(super::parse_revision(Some("\"7\"")), Ok(StoreRevision(7)));
        for invalid in ["W/\"7\"", "\"07\"", "07", "\"7", "7\"", "\"x\""] {
            assert_eq!(
                super::parse_revision(Some(invalid)),
                Err(cigar_protocol::ErrorCode::InvalidArgument)
            );
        }
    }
}
