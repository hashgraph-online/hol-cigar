//! Typed CatalogService and ContextService application adapters.
//!
//! This module is the authority boundary between caller-controlled API DTOs and the trusted
//! catalog, retrieval, compiler, policy, clock, and repository inputs required by WP04-WP08.

use crate::compiler_control_plane::{
    CompilerControlPlaneError, CompilerGovernance, DurableCompilerControlPlane,
    VerifiedTargetOverflow,
};
use crate::{
    AuthorityClock, BlockingPool, BlockingPoolErrorCode, CacheLayer as TelemetryCacheLayer,
    CacheReason, CompileCandidateStage, CompilePhase, CompileResultCounts, DaemonTelemetry,
    DomainIdentityResolver, ParserStage, ProductionApplicationBuilder, ResolvedDomainIdentity,
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
    IngestionService, SourceConnector, SourceHealthState, atomizer_registry_digest,
};
use cigar_compiler::{
    BlockBodies, ByteTokenizer, CacheKey, CacheLayer, CompilerCandidate, CompilerError,
    CompilerErrorCode, CompilerProfile, DeterministicCompiler, ExactTokenizer, FrozenInputs,
    MaterializationError, MaterializerProfile, ReferenceTokenizer, ReferenceTokenizerProfile,
    RepresentationVariant, apply_delta_verified, compiler_profile_digest, generate_delta,
    materialize,
};
use cigar_policy::{PolicyOutcome, RetrievalAuthorization, RetrievalResourceAuthorizationRequest};
use cigar_protocol::{
    AtomKind, AtomPayload, CandidateDisposition, Capability, Classification, ContentDigest,
    ContextAtomV1, ContextBundle, ContextContract, ContextPlan, DispositionReason, EdgeKind,
    IdempotencyKey, InstructionAuthority, LaneKind, Lifecycle, MediaType, RecordId, RelativePath,
    SelectionManifest, SourceUri, UtcTimestamp, Validate, VersionId,
};
use cigar_retrieval::{
    AuthorizedPartition, BoundedRetrievalResult, CandidateFeatures, CandidateRef, QueryPlanner,
    QueryPlannerProfile, QueryVectorProcessor, RequirementAwareCandidateReducer, RetrievalCapacity,
    RetrievalConsistency, RetrievalContext, RetrievalError, RetrievalErrorCode, RetrievalRequest,
    RetrievalStage, Retriever, StagedRetrieval, StagedRetrievalResult,
};
use cigar_space::{RecipientBundleReceipt, ResultMergeKind};
use cigar_store::{
    AccessContext, CancellationToken as StoreCancellationToken, IdempotencyIdentity,
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
const CATALOG_COMMITTED_TOPIC: &str = "catalog.committed";
const CATALOG_TOMBSTONED_TOPIC: &str = "catalog.atom-tombstoned";
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
#[derive(Clone, Eq, PartialEq)]
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
    /// Opaque live policy proof required before any retrieval index can be touched.
    pub retrieval_authorization: RetrievalAuthorization,
}

impl fmt::Debug for CatalogContextAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogContextAuthorization")
            .field("project_count", &self.project_ids.len())
            .field("purpose_bytes", &self.purpose.len())
            .field("processor_bytes", &self.processor.len())
            .field("maximum_classification", &self.maximum_classification)
            .field(
                "maximum_instruction_authority",
                &self.maximum_instruction_authority,
            )
            .field("vector_allowed", &self.vector_allowed)
            .finish_non_exhaustive()
    }
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
    /// Resolves one coherently bound target or returns `None` without falling back to an estimate.
    fn tokenizer(
        &self,
        target: &cigar_protocol::TargetProfile,
    ) -> Option<Arc<dyn ExactTokenizer + Send + Sync>>;
}

struct RegisteredTokenizer {
    provider: String,
    model_family: String,
    tokenizer: Arc<dyn ExactTokenizer + Send + Sync>,
}

/// Thread-safe exact tokenizer registry for production composition and deterministic tests.
#[derive(Default)]
pub struct PinnedContextTokenizerRegistry {
    tokenizers: RwLock<BTreeMap<ContentDigest, RegisteredTokenizer>>,
}

impl PinnedContextTokenizerRegistry {
    /// Creates the production registry containing every provider-neutral reference profile.
    pub fn with_reference_profiles() -> Result<Self, CatalogContextAuthorizationError> {
        let registry = Self::default();
        registry.register_reference_profiles()?;
        Ok(registry)
    }

    /// Registers every built-in provider-neutral reference profile exactly once.
    pub fn register_reference_profiles(&self) -> Result<(), CatalogContextAuthorizationError> {
        for profile in ReferenceTokenizerProfile::ALL {
            let tokenizer = ReferenceTokenizer::new(profile)
                .map_err(|_error| CatalogContextAuthorizationError::InvalidDecision)?;
            self.register_for_target(
                cigar_compiler::REFERENCE_TOKENIZER_PROVIDER,
                profile.identifier(),
                Arc::new(tokenizer),
            )?;
        }
        Ok(())
    }

    /// Registers one exact tokenizer under an immutable provider/model/fingerprint tuple.
    pub fn register_for_target(
        &self,
        provider: &str,
        model_family: &str,
        tokenizer: Arc<dyn ExactTokenizer + Send + Sync>,
    ) -> Result<(), CatalogContextAuthorizationError> {
        if !valid_target_binding(provider) || !valid_target_binding(model_family) {
            return Err(CatalogContextAuthorizationError::InvalidDecision);
        }
        let fingerprint = tokenizer.fingerprint().clone();
        let mut tokenizers = self
            .tokenizers
            .write()
            .map_err(|_error| CatalogContextAuthorizationError::Unavailable)?;
        if let Some(existing) = tokenizers.get(&fingerprint) {
            if existing.provider == provider
                && existing.model_family == model_family
                && Arc::ptr_eq(&existing.tokenizer, &tokenizer)
            {
                return Ok(());
            }
            return Err(CatalogContextAuthorizationError::InvalidDecision);
        }
        tokenizers.insert(
            fingerprint,
            RegisteredTokenizer {
                provider: provider.to_owned(),
                model_family: model_family.to_owned(),
                tokenizer,
            },
        );
        Ok(())
    }

    /// Registers the deterministic byte tokenizer for one pinned fingerprint.
    pub fn register_byte_tokenizer(
        &self,
        provider: &str,
        model_family: &str,
        fingerprint: ContentDigest,
    ) -> Result<(), CatalogContextAuthorizationError> {
        self.register_for_target(
            provider,
            model_family,
            Arc::new(ByteTokenizer::new(fingerprint)),
        )
    }
}

impl ContextTokenizerRegistry for PinnedContextTokenizerRegistry {
    fn tokenizer(
        &self,
        target: &cigar_protocol::TargetProfile,
    ) -> Option<Arc<dyn ExactTokenizer + Send + Sync>> {
        self.tokenizers
            .read()
            .ok()
            .and_then(|tokenizers| {
                tokenizers.get(&target.tokenizer_fingerprint).map(|entry| {
                    (entry.provider == target.provider && entry.model_family == target.model_family)
                        .then(|| Arc::clone(&entry.tokenizer))
                })
            })
            .flatten()
    }
}

fn valid_target_binding(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
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
    /// Digest of the exact ordered atomizer registry and each trusted configuration profile.
    pub atomization_profile_digest: ContentDigest,
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
        let connector_descriptor = connector.descriptor();
        if connector_descriptor.id != configuration.connector_identity
            || connector_descriptor.root != configuration.root
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let descriptors: Vec<_> = atomizers
            .iter()
            .map(|atomizer| atomizer.descriptor())
            .collect();
        if atomizer_registry_digest(&descriptors)? != configuration.atomization_profile_digest {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        for media_type in &configuration.discovery_policy.allowed_media_types {
            let maximum = descriptors
                .iter()
                .find(|descriptor| descriptor.media_types.contains(media_type))
                .and_then(|descriptor| u64::try_from(descriptor.max_input_bytes).ok())
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
            if configuration.discovery_policy.max_record_bytes > maximum {
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
    #[serde(default)]
    invalidation_candidates: BTreeMap<VersionId, RetainedCandidate>,
    block_sources: BTreeMap<VersionId, VersionId>,
    created_at: UtcTimestamp,
}

impl RetainedCompileRecord {
    fn effective_invalidation_candidates(&self) -> &BTreeMap<VersionId, RetainedCandidate> {
        if self.invalidation_candidates.is_empty() {
            &self.selected_candidates
        } else {
            &self.invalidation_candidates
        }
    }
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
    query_vector_processor: Option<Arc<dyn QueryVectorProcessor>>,
    tokenizers: Arc<dyn ContextTokenizerRegistry>,
    compiler_control_plane: Arc<DurableCompilerControlPlane>,
    compiler_profile: CompilerProfile,
    query_planner_profile: QueryPlannerProfile,
    blocking_pool: Arc<BlockingPool>,
    clock: Arc<dyn AuthorityClock>,
    errors: Arc<dyn FacadeErrorFactory>,
    sources: Arc<RwLock<SourceRuntimeRegistry>>,
    telemetry: Option<Arc<DaemonTelemetry>>,
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
            query_vector_processor: self.query_vector_processor.clone(),
            tokenizers: Arc::clone(&self.tokenizers),
            compiler_control_plane: Arc::clone(&self.compiler_control_plane),
            compiler_profile: self.compiler_profile.clone(),
            query_planner_profile: self.query_planner_profile,
            blocking_pool: Arc::clone(&self.blocking_pool),
            clock: Arc::clone(&self.clock),
            errors: Arc::clone(&self.errors),
            sources: Arc::clone(&self.sources),
            telemetry: self.telemetry.clone(),
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
        let compiler_repository: Arc<dyn ServiceRepository> = repository.clone();
        Self {
            repository,
            identities,
            authorizer,
            retriever,
            query_vector_processor: None,
            tokenizers,
            compiler_control_plane: Arc::new(DurableCompilerControlPlane::new(compiler_repository)),
            compiler_profile: CompilerProfile::default(),
            query_planner_profile: QueryPlannerProfile::default(),
            blocking_pool,
            clock,
            errors,
            sources: Arc::new(RwLock::new(BTreeMap::new())),
            telemetry: None,
        }
    }

    /// Attaches the process telemetry authority used by the production composition.
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Arc<DaemonTelemetry>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Installs the trusted query processor used only after live partition authorization.
    #[must_use]
    pub fn with_query_vector_processor(mut self, processor: Arc<dyn QueryVectorProcessor>) -> Self {
        self.query_vector_processor = Some(processor);
        self
    }

    /// Selects one matched, digest-bound runtime intelligence profile.
    #[must_use]
    pub fn with_intelligence_profile(
        mut self,
        compiler_profile: CompilerProfile,
        query_planner_profile: QueryPlannerProfile,
    ) -> Self {
        self.compiler_profile = compiler_profile;
        self.query_planner_profile = query_planner_profile;
        self
    }

    /// Selects a digest-bound compiler profile for benchmark-only experimental composition.
    #[cfg(any(test, feature = "experimental-profiles"))]
    #[must_use]
    pub fn with_benchmark_compiler_profile(mut self, profile: CompilerProfile) -> Self {
        self.compiler_profile = profile;
        self
    }

    /// Selects bounded graph/augmentation planning for benchmark-only composition.
    #[cfg(any(test, feature = "experimental-profiles"))]
    #[must_use]
    pub fn with_benchmark_query_planner_profile(mut self, profile: QueryPlannerProfile) -> Self {
        self.query_planner_profile = profile;
        self
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
        if let Some(telemetry) = &self.telemetry {
            let quarantines = plan
                .entries
                .iter()
                .filter(|entry| entry.disposition == DiscoveryDisposition::Quarantine)
                .count();
            telemetry.record_quarantines(u64::try_from(quarantines).unwrap_or(u64::MAX));
        }
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
        let access = AccessContext::new(state.identity.tenant_id.clone(), authorization.purpose)
            .map_err(map_store_error)?;
        let key = (!request.metadata.dry_run())
            .then(|| parse_idempotency(request.metadata.idempotency_key()))
            .transpose()?;
        let atomizers: Vec<&dyn Atomizer> =
            source.runtime.atomizers.iter().map(AsRef::as_ref).collect();
        for attempt in 0..MAX_CAS_RETRIES {
            state.check()?;
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
            let current_revision =
                self.current_revision(access.clone(), &state.store_cancellation)?;
            let Some(key) = key.as_ref() else {
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
            };
            match IngestionService.ingest_discovered(
                self.repository.as_ref(),
                IngestionRequest {
                    access: access.clone(),
                    expected_revision: current_revision,
                    idempotency_key: key.clone(),
                },
                source.runtime.connector.as_ref(),
                &atomizers,
                &current_plan,
                &connector_context,
            ) {
                Ok(receipt) => {
                    if let Some(telemetry) = &self.telemetry {
                        telemetry.record_ingestion(
                            receipt.published_atoms,
                            receipt.tombstoned_atoms,
                            retained.included_bytes,
                        );
                    }
                    return Ok(IngestionReceiptResponse {
                        revision: receipt.revision.0,
                        snapshot_id: receipt.snapshot_id,
                        published_atoms: receipt.published_atoms,
                        tombstoned_atoms: receipt.tombstoned_atoms,
                        publication_digest: receipt.publication_digest,
                    });
                }
                Err(error)
                    if error.code() == CatalogErrorCode::SourceChanged
                        && attempt + 1 < MAX_CAS_RETRIES =>
                {
                    continue;
                }
                Err(error) => {
                    if error.code() == CatalogErrorCode::InvalidRecord
                        && let Some(telemetry) = &self.telemetry
                    {
                        telemetry.record_parser_failure(ParserStage::Atomizer);
                    }
                    return Err(map_catalog_error(error));
                }
            }
        }
        Err(cigar_protocol::ErrorCode::RevisionConflict)
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
        let revision = self.current_catalog_revision(access, &state.store_cancellation)?;
        let partition = authorized_partition(&state, &authorization)?;
        let retrieval_profile = self.compiler_profile.retrieval_profile;
        let plan =
            QueryPlanner::new_with_retrieval_profile(self.query_planner_profile, retrieval_profile)
                .map_err(map_retrieval_error)?
                .plan_with_vector_processor(
                    &request.requirements,
                    &partition,
                    revision,
                    RetrievalConsistency::Strong,
                    authorization
                        .vector_allowed
                        .then_some(self.query_vector_processor.as_deref())
                        .flatten(),
                )
                .map_err(map_retrieval_error)?;
        let result = StagedRetrieval
            .execute_with_profile(
                &plan,
                self.retriever.as_ref(),
                &RetrievalContext {
                    cancellation: state.store_cancellation.clone(),
                    deadline: state.monotonic_deadline,
                },
                retrieval_profile,
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
        let (_revision, mut authorized) =
            self.authorized_atoms_by_id(&state, &authorization, &request.atom_ids)?;
        let results = request
            .atom_ids
            .into_iter()
            .map(|atom_id| match authorized.remove(&atom_id) {
                Some(atom) => AtomLookupResult::Found {
                    atom: Box::new(atom),
                },
                None => AtomLookupResult::Missing { atom_id },
            })
            .collect();
        Ok(AtomBatchResponse { results })
    }

    fn authorized_atoms_by_id(
        &self,
        request: &ApplicationRequest,
        authorization: &CatalogContextAuthorization,
        atom_ids: &[RecordId],
    ) -> Result<(StoreRevision, BTreeMap<RecordId, ContextAtomV1>), cigar_protocol::ErrorCode> {
        if atom_ids.is_empty() {
            return Err(cigar_protocol::ErrorCode::InvalidArgument);
        }
        let partition = authorized_partition(request, authorization)?;
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
        let revision = catalog_revision(&read)?;
        let selector_ids: BTreeSet<_> = atom_ids.iter().cloned().collect();
        if selector_ids.len() != atom_ids.len() {
            return Err(cigar_protocol::ErrorCode::InvalidArgument);
        }
        let exact = RetrievalRequest {
            stage: RetrievalStage::Exact,
            partition: partition.clone(),
            required_revision: revision,
            consistency: RetrievalConsistency::Strong,
            atom_kinds: BTreeSet::new(),
            exact_versions: BTreeSet::new(),
            atom_ids: selector_ids.clone(),
            lineage_ids: BTreeSet::new(),
            content_digests: BTreeSet::new(),
            canonical_uris: BTreeSet::new(),
            source_revisions: BTreeSet::new(),
            paths: BTreeSet::new(),
            terms: BTreeSet::new(),
            approved_vector: None,
            graph_roots: BTreeSet::new(),
            graph_depth: 0,
            limit: selector_ids.len(),
            allow_fallback: false,
        };
        let batch = self
            .retriever
            .retrieve(
                &exact,
                &RetrievalContext {
                    cancellation: request.store_cancellation.clone(),
                    deadline: request.monotonic_deadline,
                },
            )
            .map_err(map_retrieval_error)?;
        let mut atoms = BTreeMap::new();
        for candidate in batch.candidates {
            request.check()?;
            let atom = read
                .get_atom(&candidate.version_id)
                .map_err(map_store_error)?
                .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
            if !selector_ids.contains(&atom.atom_id) {
                return Err(cigar_protocol::ErrorCode::IntegrityFailure);
            }
            require_atom_authorized(&partition, &atom, false)?;
            if atoms.insert(atom.atom_id.clone(), atom).is_some() {
                return Err(cigar_protocol::ErrorCode::IntegrityFailure);
            }
        }
        partition.validate().map_err(map_retrieval_error)?;
        Ok((revision, atoms))
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
        let (authorized_revision, authorized) = self.authorized_atoms_by_id(
            &state,
            &authorization,
            std::slice::from_ref(&request.payload.atom_id),
        )?;
        if !authorized.contains_key(&request.payload.atom_id) {
            return Err(cigar_protocol::ErrorCode::InvalidArgument);
        }
        let access = AccessContext::new(state.identity.tenant_id.clone(), authorization.purpose)
            .map_err(map_store_error)?;
        let expected = parse_revision(request.metadata.expected_revision())?;
        if request.metadata.dry_run() {
            if authorized_revision != expected {
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
        let phase_started = Instant::now();
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
        let revision = catalog_revision(&read)?;
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
        let profile = self.compiler_profile.clone();
        let retrieval_capacity = RetrievalCapacity::new(
            contract.budget.lane_input_tokens.clone(),
            profile.maximum_items.clone(),
            profile.minimum_items.clone(),
        )
        .map_err(map_retrieval_error)?;
        self.record_compile_phase(CompilePhase::Scope, phase_started.elapsed());
        let phase_started = Instant::now();
        let retrieval_plan = QueryPlanner::new_with_retrieval_profile(
            self.query_planner_profile,
            profile.retrieval_profile,
        )
        .map_err(map_retrieval_error)?
        .plan_bounded_with_vector_processor(
            &contract.requirements,
            &retrieval_capacity,
            &partition,
            revision,
            consistency,
            authorization
                .vector_allowed
                .then_some(self.query_vector_processor.as_deref())
                .flatten(),
        )
        .map_err(map_retrieval_error)?;
        let retrieval_context = RetrievalContext {
            cancellation: request.store_cancellation.clone(),
            deadline: request.monotonic_deadline,
        };
        let retrieval = StagedRetrieval
            .execute_with_profile(
                &retrieval_plan,
                self.retriever.as_ref(),
                &retrieval_context,
                profile.retrieval_profile,
            )
            .map_err(map_retrieval_error)?;
        let bounded_retrieval = RequirementAwareCandidateReducer
            .reduce_with_profile(
                &retrieval_plan,
                &retrieval,
                &retrieval_context,
                profile.retrieval_profile,
            )
            .map_err(map_retrieval_error)?;
        let before_governance_count =
            u64::try_from(bounded_retrieval.counts.raw_stage_candidates).unwrap_or(u64::MAX);
        self.record_compile_phase(CompilePhase::Retrieve, phase_started.elapsed());
        let phase_started = Instant::now();
        let tokenizer = self
            .tokenizers
            .tokenizer(&contract.target)
            .ok_or(cigar_protocol::ErrorCode::DependencyUnavailable)?;
        let mut seeds = candidate_seeds(&bounded_retrieval);
        let mut index_authorized_versions: BTreeSet<_> = seeds.keys().cloned().collect();
        let mut atoms = BTreeMap::new();
        let mut dependencies = BTreeMap::<VersionId, BTreeSet<VersionId>>::new();
        let mut pending: VecDeque<VersionId> = seeds.keys().cloned().collect();
        while let Some(version_id) = pending.pop_front() {
            request.check()?;
            if atoms.contains_key(&version_id) {
                continue;
            }
            if atoms.len()
                >= retrieval_plan
                    .candidate_bounds
                    .profile
                    .absolute_compiler_candidates
                    .min(MAX_COMPILE_CANDIDATES)
            {
                return Err(cigar_protocol::ErrorCode::LimitExceeded);
            }
            if !index_authorized_versions.contains(&version_id) {
                return Err(cigar_protocol::ErrorCode::PolicyDenied);
            }
            let atom = read
                .get_atom(&version_id)
                .map_err(map_store_error)?
                .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
            require_atom_authorized(&partition, &atom, true)?;
            let edges = read
                .edges_from(&version_id, Some(EdgeKind::DependsOn), MAX_DEPENDENCY_EDGES)
                .map_err(map_store_error)?;
            let mut atom_dependencies = BTreeSet::new();
            for edge in edges {
                if edge.lifecycle == Lifecycle::Active {
                    if !index_authorized_versions.contains(&edge.to_version) {
                        require_index_authorized_version(
                            self.retriever.as_ref(),
                            &partition,
                            revision,
                            &edge.to_version,
                            request,
                        )?;
                        index_authorized_versions.insert(edge.to_version.clone());
                    }
                    atom_dependencies.insert(edge.to_version.clone());
                    seeds.entry(edge.to_version.clone()).or_default();
                    pending.push_back(edge.to_version);
                }
            }
            dependencies.insert(version_id.clone(), atom_dependencies);
            atoms.insert(version_id, atom);
        }
        self.record_compile_phase(CompilePhase::Authorize, phase_started.elapsed());
        let phase_started = Instant::now();
        let catalog_watermark = authorized_catalog_watermark(&retrieval, &atoms, &dependencies)?;
        let retrieval_plan_digest =
            retained_retrieval_digest(&contract, &retrieval, profile.retrieval_profile)?;
        let index_fingerprints = retained_index_fingerprints(&retrieval, &catalog_watermark)?;
        let profile = self.compiler_profile.clone();
        let profile_digest = compiler_profile_digest(&profile).map_err(map_compiler_error)?;
        self.record_compile_phase(CompilePhase::Reconcile, phase_started.elapsed());
        let phase_started = Instant::now();
        let mut candidates = Vec::with_capacity(atoms.len());
        let mut bodies_by_version = BTreeMap::new();
        for (version_id, atom) in &atoms {
            request.check()?;
            require_atom_authorized(&partition, atom, true)?;
            let body = atom_body(&read, atom)?;
            require_atom_authorized(&partition, atom, true)?;
            let token_count = tokenizer
                .count_exact(&body)
                .map_err(map_materialization_error)?;
            require_atom_authorized(&partition, atom, true)?;
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
                atom_compile_policy(atom, request.observed_at, &contract);
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
        self.record_compile_phase(CompilePhase::Transform, phase_started.elapsed());
        let blocking_requirement_indices = contract
            .requirements
            .iter()
            .enumerate()
            .filter_map(|(index, requirement)| requirement.blocking.then_some(index))
            .collect::<BTreeSet<_>>();
        let candidate_requirements = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.version_id.clone(),
                    candidate.requirement_indices.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mandatory_candidates = candidates
            .iter()
            .filter(|candidate| {
                candidate.mandatory
                    || candidate
                        .requirement_indices
                        .iter()
                        .any(|index| blocking_requirement_indices.contains(index))
            })
            .count();
        let logical_candidate_count = candidates
            .iter()
            .map(|candidate| &candidate.logical_id)
            .collect::<BTreeSet<_>>()
            .len();
        let compile_cache_reason = if contract.extensions.is_empty() {
            CacheReason::NotConfigured
        } else {
            CacheReason::UnknownSemanticExtension
        };
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
        let phase_started = Instant::now();
        let output = DeterministicCompiler
            .compile(cigar_compiler::CompileRequest {
                contract,
                frozen,
                profile,
                candidates,
            })
            .map_err(map_compiler_error)?;
        self.record_compile_phase(CompilePhase::Pack, phase_started.elapsed());
        let selected_versions: BTreeSet<VersionId> = output
            .plan
            .dispositions
            .iter()
            .filter_map(|(version_id, disposition)| {
                matches!(disposition, CandidateDisposition::Selected { .. })
                    .then_some(version_id.clone())
            })
            .collect();
        let represented_versions = output.invalidation.catalog_versions.clone();
        if let Some(telemetry) = &self.telemetry {
            telemetry.record_compile_selection(
                u64::try_from(output.plan.dispositions.len()).unwrap_or(u64::MAX),
                u64::try_from(output.bundle.blocks.len()).unwrap_or(u64::MAX),
            );
            let budget_displaced = output
                .plan
                .dispositions
                .iter()
                .filter(|(_version, disposition)| {
                    matches!(
                        disposition,
                        CandidateDisposition::Excluded {
                            reason: DispositionReason::BudgetDisplaced
                        }
                    )
                })
                .count();
            let unique_content_keys = output
                .bundle
                .blocks
                .iter()
                .map(|block| (block.representation, block.content_digest.clone()))
                .collect::<BTreeSet<_>>()
                .len();
            let unique_lineages = represented_versions
                .iter()
                .filter_map(|version| atoms.get(version))
                .map(|atom| &atom.lineage_id)
                .collect::<BTreeSet<_>>()
                .len();
            let blocking_requirements_satisfied = blocking_requirement_indices
                .iter()
                .filter(|index| {
                    represented_versions.iter().any(|version| {
                        candidate_requirements
                            .get(version)
                            .is_some_and(|requirements| requirements.contains(index))
                    })
                })
                .count();
            telemetry.record_compile_measurements(
                [
                    (
                        CompileCandidateStage::BeforeGovernance,
                        before_governance_count,
                    ),
                    (
                        CompileCandidateStage::AfterGovernance,
                        u64::try_from(bounded_retrieval.counts.after_version_coalescing)
                            .unwrap_or(u64::MAX),
                    ),
                    (
                        CompileCandidateStage::AfterLogicalCoalescing,
                        u64::try_from(logical_candidate_count).unwrap_or(u64::MAX),
                    ),
                    (
                        CompileCandidateStage::AfterContentGrouping,
                        u64::try_from(output.content_equivalence.len()).unwrap_or(u64::MAX),
                    ),
                    (
                        CompileCandidateStage::AfterBudgetSelection,
                        u64::try_from(output.bundle.blocks.len()).unwrap_or(u64::MAX),
                    ),
                ],
                CompileResultCounts {
                    selected_blocks: u64::try_from(output.bundle.blocks.len()).unwrap_or(u64::MAX),
                    unique_content_keys: u64::try_from(unique_content_keys).unwrap_or(u64::MAX),
                    unique_source_versions: u64::try_from(represented_versions.len())
                        .unwrap_or(u64::MAX),
                    unique_lineages: u64::try_from(unique_lineages).unwrap_or(u64::MAX),
                    budget_displaced: u64::try_from(budget_displaced).unwrap_or(u64::MAX),
                    mandatory_candidates: u64::try_from(mandatory_candidates).unwrap_or(u64::MAX),
                    blocking_requirements_satisfied: u64::try_from(blocking_requirements_satisfied)
                        .unwrap_or(u64::MAX),
                },
            );
            for layer in [
                TelemetryCacheLayer::Retrieval,
                TelemetryCacheLayer::Plan,
                TelemetryCacheLayer::Bundle,
            ] {
                telemetry.record_cache_observation(layer, compile_cache_reason);
            }
            for lane in [
                LaneKind::Rules,
                LaneKind::Task,
                LaneKind::Evidence,
                LaneKind::History,
                LaneKind::Tools,
            ] {
                let tokens = output
                    .bundle
                    .blocks
                    .iter()
                    .filter(|block| block.lane == lane)
                    .fold(0_u64, |total, block| {
                        total.saturating_add(u64::from(block.token_count))
                    });
                telemetry.record_lane_tokens(lane, tokens);
            }
            let conflicts = output
                .plan
                .dispositions
                .iter()
                .filter(|(_version, disposition)| {
                    matches!(
                        disposition,
                        CandidateDisposition::Excluded {
                            reason: DispositionReason::ConflictLost
                        }
                    )
                })
                .count();
            telemetry.record_compile_conflicts(u64::try_from(conflicts).unwrap_or(u64::MAX));
        }
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
        let invalidation_candidates = represented_versions
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
        for version_id in &represented_versions {
            let atom = atoms
                .get(version_id)
                .ok_or(cigar_protocol::ErrorCode::Internal)?;
            require_atom_authorized(&partition, atom, true)?;
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
            invalidation_candidates,
            block_sources,
            created_at: request.observed_at,
        };
        validate_compile_record(&record)?;
        Ok(PreparedCompile { record })
    }

    fn record_compile_phase(&self, phase: CompilePhase, elapsed: Duration) {
        if let Some(telemetry) = &self.telemetry {
            telemetry.record_compile_phase(phase, elapsed);
        }
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
        let partition = authorized_partition(request, authorization)?;
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
        require_selected_atoms_authorized(
            &read,
            retained,
            &partition,
            true,
            self.retriever.as_ref(),
            request,
        )?;
        let bundle = read
            .get_bundle(&retained.bundle.bundle_id)
            .map_err(map_store_error)?
            .ok_or(cigar_protocol::ErrorCode::IntegrityFailure)?;
        if bundle != retained.bundle {
            return Err(cigar_protocol::ErrorCode::IntegrityFailure);
        }
        require_selected_atoms_authorized(
            &read,
            retained,
            &partition,
            true,
            self.retriever.as_ref(),
            request,
        )?;
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
        let phase_started = Instant::now();
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let base = self.retained_bundle(&state, &request.base_bundle_id)?;
        let target = self.retained_plan(&state, &request.target_plan_id)?;
        let base_authorization = self.authorize_retained(&state, &base.value)?;
        let target_authorization = self.authorize_retained(&state, &target.value)?;
        let base_bundle = self.stored_bundle(&state, &base.value, &base_authorization)?;
        let target_bundle = self.stored_bundle(&state, &target.value, &target_authorization)?;
        let sealed = generate_delta(&base_bundle, &target_bundle).map_err(map_delta_error)?;
        apply_delta_verified(&base_bundle, &target_bundle, &sealed).map_err(map_delta_error)?;
        self.record_compile_phase(CompilePhase::Reconcile, phase_started.elapsed());
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
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let partition = authorized_partition(&state, &authorization)?;
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
        for entry in &retained.value.manifest.entries {
            state.check()?;
            require_index_authorized_version(
                self.retriever.as_ref(),
                &partition,
                retained.value.catalog_store_revision,
                &entry.version_id,
                &state,
            )?;
            let atom = read
                .get_atom(&entry.version_id)
                .map_err(map_store_error)?
                .ok_or(cigar_protocol::ErrorCode::PolicyDenied)?;
            require_atom_authorized(&partition, &atom, false)?;
        }
        partition.validate().map_err(map_retrieval_error)?;
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
        let partition = authorized_partition(&state, &authorization)?;
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
            match require_index_authorized_version(
                self.retriever.as_ref(),
                &partition,
                retained.value.catalog_store_revision,
                &entry.version_id,
                &state,
            ) {
                Ok(()) => {}
                Err(cigar_protocol::ErrorCode::PolicyDenied) => continue,
                Err(error) => return Err(error),
            }
            let Some(atom) = read.get_atom(&entry.version_id).map_err(map_store_error)? else {
                continue;
            };
            if atom_authorized(&partition, &atom, false)? {
                entries.push(ContextExplanationEntry {
                    version_id: entry.version_id.clone(),
                    disposition: entry.disposition.clone(),
                });
            }
        }
        partition.validate().map_err(map_retrieval_error)?;
        Ok(ContextExplanationResponse { entries })
    }

    fn materialize_context_bundle(
        &self,
        context: &cigar_api::RequestContext,
        cancellation: &cigar_api::CancellationToken,
        monotonic_deadline: Instant,
        request: MaterializeContextBundleRequest,
    ) -> Result<MaterializationResponse, cigar_protocol::ErrorCode> {
        let phase_started = Instant::now();
        let state = self.begin_request(context, cancellation, monotonic_deadline)?;
        let retained = self.retained_bundle(&state, &request.bundle_id)?;
        let authorization = self.authorize_retained(&state, &retained.value)?;
        let partition = authorized_partition(&state, &authorization)?;
        let governance = compiler_governance(&state, &authorization)?;
        let reasons = self.revalidation_reasons(&state, &retained.value, &authorization)?;
        if !reasons.is_empty() {
            return Err(cigar_protocol::ErrorCode::BundleInvalidated);
        }
        let bundle = self.stored_bundle(&state, &retained.value, &authorization)?;
        let tokenizer = self
            .tokenizers
            .tokenizer(&retained.value.normalized_contract.target)
            .ok_or(cigar_protocol::ErrorCode::DependencyUnavailable)?;
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
            require_atom_authorized(&partition, &atom, true)?;
            let body = atom_body(&read, &atom)?;
            require_atom_authorized(&partition, &atom, true)?;
            bodies.insert(block.block_id.clone(), body);
        }
        let profile = match request.profile {
            MaterializationProfile::CanonicalJson => MaterializerProfile::Json,
            MaterializationProfile::ClaudePrompt => MaterializerProfile::ClaudePrompt,
        };
        let cache_fingerprint = digest_json(&(
            "cigar.materialization-cache.v1",
            &bundle.bundle_id,
            &retained.value.normalized_contract.target,
            request.profile,
        ))?;
        let cache_key = CacheKey::new(
            CacheLayer::Materialization,
            state.identity.tenant_id.as_str(),
            partition.partition_digest().as_str(),
            cache_fingerprint,
        )
        .ok_or(cigar_protocol::ErrorCode::Internal)?;
        let cached_bytes = self
            .compiler_control_plane
            .cache_get(
                &cache_key,
                governance.policy_digest(),
                governance.revocation_epoch(),
                |candidate| candidate == &cache_key,
            )
            .ok()
            .flatten();
        let (cached, cache_miss_reason) = match cached_bytes {
            None => (None, CacheReason::AbsentEntry),
            Some(bytes) => match serde_json::from_slice::<MaterializationResponse>(&bytes) {
                Err(_error) => (None, CacheReason::AbsentEntry),
                Ok(response) if response.context.validate().is_err() => {
                    (None, CacheReason::UnknownSemanticExtension)
                }
                Ok(response) if response.context.bundle_id != bundle.bundle_id => {
                    (None, CacheReason::WatermarkMismatch)
                }
                Ok(response)
                    if response.context.tokenizer_fingerprint
                        != retained
                            .value
                            .normalized_contract
                            .target
                            .tokenizer_fingerprint =>
                {
                    (None, CacheReason::TokenizerMismatch)
                }
                Ok(response)
                    if response.context.materializer_fingerprint
                        != retained
                            .value
                            .normalized_contract
                            .target
                            .materializer_fingerprint =>
                {
                    (None, CacheReason::MaterializerMismatch)
                }
                Ok(response) if response.physical_input_tokens != response.context.token_count => {
                    (None, CacheReason::WatermarkMismatch)
                }
                Ok(response) => (Some(response), CacheReason::Hit),
            },
        };
        if let Some(response) = cached {
            require_selected_atoms_authorized(
                &read,
                &retained.value,
                &partition,
                true,
                self.retriever.as_ref(),
                &state,
            )?;
            if let Some(overflow) = VerifiedTargetOverflow::from_materialization(
                &response.context,
                &retained.value.normalized_contract.target,
            )
            .map_err(map_compiler_control_error)?
            {
                self.compiler_control_plane
                    .record_target_overflow(&governance, &overflow, &state.store_cancellation)
                    .map_err(map_compiler_control_error)?;
                return Err(cigar_protocol::ErrorCode::BudgetUnsatisfiable);
            }
            if let Some(telemetry) = &self.telemetry {
                telemetry.record_cache_observation(
                    TelemetryCacheLayer::Materialization,
                    CacheReason::Hit,
                );
                telemetry.record_materialization_tokens(
                    u64::from(response.physical_input_tokens),
                    0,
                    0,
                );
            }
            self.record_compile_phase(CompilePhase::Materialize, phase_started.elapsed());
            return Ok(response);
        }
        if let Some(telemetry) = &self.telemetry {
            telemetry
                .record_cache_observation(TelemetryCacheLayer::Materialization, cache_miss_reason);
        }
        let (materialized, accounting) = materialize(profile, &bundle, &bodies, tokenizer.as_ref())
            .map_err(map_materialization_error)?;
        require_selected_atoms_authorized(
            &read,
            &retained.value,
            &partition,
            true,
            self.retriever.as_ref(),
            &state,
        )?;
        if materialized.materializer_fingerprint
            != retained
                .value
                .normalized_contract
                .target
                .materializer_fingerprint
        {
            return Err(cigar_protocol::ErrorCode::BundleInvalidated);
        }
        if let Some(overflow) = VerifiedTargetOverflow::from_materialization(
            &materialized,
            &retained.value.normalized_contract.target,
        )
        .map_err(map_compiler_control_error)?
        {
            self.compiler_control_plane
                .record_target_overflow(&governance, &overflow, &state.store_cancellation)
                .map_err(map_compiler_control_error)?;
            return Err(cigar_protocol::ErrorCode::BudgetUnsatisfiable);
        }
        let response = MaterializationResponse {
            context: materialized,
            physical_input_tokens: accounting.physical_input_tokens,
        };
        if let Ok(bytes) = encode_record(&response) {
            let _cache_inserted = self.compiler_control_plane.cache_insert(
                cache_key,
                bytes,
                governance.policy_digest().clone(),
                governance.revocation_epoch(),
            );
        }
        if let Some(telemetry) = &self.telemetry {
            telemetry.record_materialization_tokens(
                u64::from(accounting.physical_input_tokens),
                u64::from(accounting.provider_cache_read_tokens),
                u64::from(accounting.provider_cache_write_tokens),
            );
        }
        self.record_compile_phase(CompilePhase::Materialize, phase_started.elapsed());
        Ok(response)
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
        if !reasons.is_empty()
            && let Some(telemetry) = &self.telemetry
        {
            telemetry.record_compile_stale(1);
        }
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
        let partition = authorized_partition(request, authorization)?;
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
            .tokenizer(&retained.normalized_contract.target)
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
        for candidate in retained.effective_invalidation_candidates().values() {
            request.check()?;
            match require_index_authorized_version(
                self.retriever.as_ref(),
                &partition,
                retained.catalog_store_revision,
                &candidate.version_id,
                request,
            ) {
                Ok(()) => {}
                Err(cigar_protocol::ErrorCode::PolicyDenied) => {
                    reasons.insert("authorization_changed".to_owned());
                    continue;
                }
                Err(cigar_protocol::ErrorCode::IndexUnavailable)
                | Err(cigar_protocol::ErrorCode::IndexStale)
                | Err(cigar_protocol::ErrorCode::DependencyUnavailable) => {
                    reasons.insert("retrieval_unavailable".to_owned());
                    continue;
                }
                Err(error) => return Err(error),
            }
            let atom = read
                .get_atom(&candidate.version_id)
                .map_err(map_store_error)?;
            match atom {
                Some(atom) if atom.content_digest == candidate.content_digest => {
                    if !atom_authorized(&partition, &atom, true)? {
                        reasons.insert("authorization_changed".to_owned());
                        continue;
                    }
                    let active = read
                        .get_active_atom_by_id(&candidate.atom_id)
                        .map_err(map_store_error)?;
                    if active.as_ref().map(|atom| &atom.version_id) != Some(&candidate.version_id) {
                        reasons.insert("catalog_version_inactive".to_owned());
                    }
                }
                Some(_atom) => {
                    reasons.insert("catalog_version_changed".to_owned());
                }
                None => {
                    reasons.insert("catalog_version_missing".to_owned());
                }
            }
        }
        let current_profile = self.compiler_profile.clone();
        let current_retrieval_profile = current_profile.retrieval_profile;
        let current_capacity = RetrievalCapacity::new(
            retained
                .normalized_contract
                .budget
                .lane_input_tokens
                .clone(),
            current_profile.maximum_items,
            current_profile.minimum_items,
        );
        let current_retrieval = current_capacity.and_then(|capacity| {
            QueryPlanner::new_with_retrieval_profile(
                self.query_planner_profile,
                current_retrieval_profile,
            )?
            .plan_bounded_with_vector_processor(
                &retained.normalized_contract.requirements,
                &capacity,
                &partition,
                retained.catalog_store_revision,
                RetrievalConsistency::Strong,
                authorization
                    .vector_allowed
                    .then_some(self.query_vector_processor.as_deref())
                    .flatten(),
            )
        });
        match current_retrieval.and_then(|plan| {
            StagedRetrieval.execute_with_profile(
                &plan,
                self.retriever.as_ref(),
                &RetrievalContext {
                    cancellation: request.store_cancellation.clone(),
                    deadline: request.monotonic_deadline,
                },
                current_retrieval_profile,
            )
        }) {
            Ok(result) => {
                if retained_retrieval_digest(
                    &retained.normalized_contract,
                    &result,
                    current_retrieval_profile,
                )? != retained.retrieval_plan_digest
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

    fn current_catalog_revision(
        &self,
        access: AccessContext,
        cancellation: &StoreCancellationToken,
    ) -> Result<StoreRevision, cigar_protocol::ErrorCode> {
        let read = self
            .repository
            .begin_read(access, SnapshotSelection::Latest, cancellation.clone())
            .map_err(map_store_error)?;
        catalog_revision(&read)
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

fn candidate_seeds(retrieval: &BoundedRetrievalResult) -> BTreeMap<VersionId, CandidateSeed> {
    let mut seeds = BTreeMap::<VersionId, CandidateSeed>::new();
    for bounded in &retrieval.candidates {
        seeds.insert(
            bounded.candidate.version_id.clone(),
            CandidateSeed {
                candidate: Some(bounded.candidate.clone()),
                requirement_indices: bounded.requirement_indices.clone(),
            },
        );
    }
    seeds
}

fn authorized_partition(
    request: &ApplicationRequest,
    authorization: &CatalogContextAuthorization,
) -> Result<AuthorizedPartition, cigar_protocol::ErrorCode> {
    authorized_partition_for_identity(&request.identity, request.observed_at, authorization)
}

fn compiler_governance(
    request: &ApplicationRequest,
    authorization: &CatalogContextAuthorization,
) -> Result<CompilerGovernance, cigar_protocol::ErrorCode> {
    let claims = authorization
        .retrieval_authorization
        .revalidate()
        .map_err(|_error| cigar_protocol::ErrorCode::PolicyDenied)?;
    if claims.tenant_id() != &request.identity.tenant_id
        || claims.principal_id() != &request.identity.principal_id
        || claims.policy_digest() != &authorization.policy_digest
    {
        return Err(cigar_protocol::ErrorCode::PolicyDenied);
    }
    Ok(CompilerGovernance::new(
        request.identity.tenant_id.clone(),
        claims.policy_digest().clone(),
        claims.revocation_epoch(),
        u64::try_from(request.observed_at.unix_nanos())
            .map_err(|_error| cigar_protocol::ErrorCode::Internal)?,
    ))
}

fn authorized_partition_for_identity(
    identity: &ResolvedDomainIdentity,
    observed_at: UtcTimestamp,
    authorization: &CatalogContextAuthorization,
) -> Result<AuthorizedPartition, cigar_protocol::ErrorCode> {
    let partition = AuthorizedPartition::from_policy_authorization(
        authorization.retrieval_authorization.clone(),
    )
    .map_err(map_retrieval_error)?;
    if partition.principal_id() != &identity.principal_id
        || partition.tenant_id() != &identity.tenant_id
        || partition.project_ids() != &authorization.project_ids
        || partition.purpose() != authorization.purpose.as_str()
        || partition.processor() != authorization.processor.as_str()
        || partition.maximum_classification() != authorization.maximum_classification
        || partition.maximum_instruction_authority() != authorization.maximum_instruction_authority
        || partition.valid_at() != observed_at
        || partition.observed_as_of() != observed_at
        || partition.claimed_policy_digest() != &authorization.policy_digest
        || authorization.vector_allowed && !partition.vector_allowed()
    {
        return Err(cigar_protocol::ErrorCode::PolicyDenied);
    }
    partition.validate().map_err(map_retrieval_error)?;
    Ok(partition)
}

fn require_index_authorized_version(
    retriever: &dyn Retriever,
    partition: &AuthorizedPartition,
    revision: StoreRevision,
    version_id: &VersionId,
    request: &ApplicationRequest,
) -> Result<(), cigar_protocol::ErrorCode> {
    request.check()?;
    let authorized = index_authorizes_version(
        retriever,
        partition,
        revision,
        version_id,
        request.store_cancellation.clone(),
        request.monotonic_deadline,
    )
    .map_err(map_retrieval_error)?;
    request.check()?;
    if authorized {
        Ok(())
    } else {
        Err(cigar_protocol::ErrorCode::PolicyDenied)
    }
}

fn index_authorizes_version(
    retriever: &dyn Retriever,
    partition: &AuthorizedPartition,
    revision: StoreRevision,
    version_id: &VersionId,
    cancellation: StoreCancellationToken,
    deadline: Instant,
) -> Result<bool, RetrievalError> {
    let exact = RetrievalRequest {
        stage: RetrievalStage::Exact,
        partition: partition.clone(),
        required_revision: revision,
        consistency: RetrievalConsistency::Strong,
        atom_kinds: BTreeSet::new(),
        exact_versions: BTreeSet::from([version_id.clone()]),
        atom_ids: BTreeSet::new(),
        lineage_ids: BTreeSet::new(),
        content_digests: BTreeSet::new(),
        canonical_uris: BTreeSet::new(),
        source_revisions: BTreeSet::new(),
        paths: BTreeSet::new(),
        terms: BTreeSet::new(),
        approved_vector: None,
        graph_roots: BTreeSet::new(),
        graph_depth: 0,
        limit: 1,
        allow_fallback: false,
    };
    let batch = retriever.retrieve(
        &exact,
        &RetrievalContext {
            cancellation,
            deadline,
        },
    )?;
    Ok(batch.candidates.len() == 1
        && batch
            .candidates
            .first()
            .is_some_and(|candidate| &candidate.version_id == version_id))
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

fn authorized_catalog_watermark(
    retrieval: &StagedRetrievalResult,
    atoms: &BTreeMap<VersionId, ContextAtomV1>,
    dependencies: &BTreeMap<VersionId, BTreeSet<VersionId>>,
) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-AUTHORIZED-CATALOG-CONTENT-WATERMARK\0v1\0");
    for stage in &retrieval.stages {
        hasher.update(stage.query_fingerprint.as_str().as_bytes());
        hasher.update(stage.batch.disclosure.index_fingerprint.as_str().as_bytes());
    }
    for (version_id, atom) in atoms {
        hasher.update(version_id.as_str().as_bytes());
        hasher.update(atom.content_digest.as_str().as_bytes());
        hasher.update([atom.lifecycle as u8]);
        if let Some(targets) = dependencies.get(version_id) {
            for target in targets {
                hasher.update(target.as_str().as_bytes());
            }
        }
        hasher.update([0]);
    }
    digest_hasher(hasher)
}

fn retained_retrieval_digest(
    contract: &ContextContract,
    retrieval: &StagedRetrievalResult,
    retrieval_profile: cigar_retrieval::RetrievalProfile,
) -> Result<ContentDigest, cigar_protocol::ErrorCode> {
    let mut hasher = Sha256::new();
    if retrieval_profile == cigar_retrieval::RetrievalProfile::BalancedV1 {
        hasher.update(b"CIGAR-RETAINED-RETRIEVAL\0v1\0");
    } else {
        hasher.update(b"CIGAR-RETAINED-RETRIEVAL\0v2\0");
        hasher.update(retrieval.plan_fingerprint.as_str().as_bytes());
        hasher.update(
            retrieval_profile
                .digest()
                .map_err(map_retrieval_error)?
                .as_str()
                .as_bytes(),
        );
    }
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

fn atom_authorized(
    partition: &AuthorizedPartition,
    atom: &ContextAtomV1,
    processor_required: bool,
) -> Result<bool, cigar_protocol::ErrorCode> {
    partition
        .authorize_resource(
            &RetrievalResourceAuthorizationRequest {
                input_digest: atom.content_digest.clone(),
                tenant_id: atom.scope.tenant_id.clone(),
                project_ids: atom.scope.project_ids.iter().cloned().collect(),
                allowed_purposes: atom.governance.allowed_purposes.iter().cloned().collect(),
                allowed_processors: atom
                    .governance
                    .processor_constraints
                    .iter()
                    .cloned()
                    .collect(),
                classification: atom.governance.classification,
                lifecycle: atom.lifecycle,
                integrity_verified: true,
                valid_from: atom.temporal.valid_from,
                valid_until: atom.temporal.valid_until,
                observed_at: atom.temporal.observed_at,
                instruction_authority: atom.governance.instruction_authority,
            },
            processor_required,
        )
        .map_err(map_retrieval_error)
}

fn require_atom_authorized(
    partition: &AuthorizedPartition,
    atom: &ContextAtomV1,
    processor_required: bool,
) -> Result<(), cigar_protocol::ErrorCode> {
    if atom_authorized(partition, atom, processor_required)? {
        Ok(())
    } else {
        Err(cigar_protocol::ErrorCode::PolicyDenied)
    }
}

fn require_selected_atoms_authorized<T: ReadTransaction>(
    read: &T,
    retained: &RetainedCompileRecord,
    partition: &AuthorizedPartition,
    processor_required: bool,
    retriever: &dyn Retriever,
    request: &ApplicationRequest,
) -> Result<(), cigar_protocol::ErrorCode> {
    for candidate in retained.effective_invalidation_candidates().values() {
        require_index_authorized_version(
            retriever,
            partition,
            retained.catalog_store_revision,
            &candidate.version_id,
            request,
        )?;
        let atom = read
            .get_atom(&candidate.version_id)
            .map_err(map_store_error)?
            .ok_or(cigar_protocol::ErrorCode::PolicyDenied)?;
        if atom.atom_id != candidate.atom_id || atom.content_digest != candidate.content_digest {
            return Err(cigar_protocol::ErrorCode::PolicyDenied);
        }
        require_atom_authorized(partition, &atom, processor_required)?;
    }
    partition.validate().map_err(map_retrieval_error)
}

fn atom_compile_policy(
    atom: &ContextAtomV1,
    observed_at: UtcTimestamp,
    contract: &ContextContract,
) -> (PolicyOutcome, Option<DispositionReason>) {
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
    if !freshness {
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
    let provenance_versions: BTreeSet<_> = record
        .bundle
        .blocks
        .iter()
        .flat_map(|block| block.provenance.iter().cloned())
        .collect();
    let invalidation_versions: BTreeSet<_> = record
        .effective_invalidation_candidates()
        .keys()
        .cloned()
        .collect();
    if block_ids != retained_block_ids
        || provenance_versions != invalidation_versions
        || record
            .effective_invalidation_candidates()
            .iter()
            .any(|(version_id, candidate)| version_id != &candidate.version_id)
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

fn catalog_revision(
    read: &impl ReadTransaction,
) -> Result<StoreRevision, cigar_protocol::ErrorCode> {
    Ok(read
        .outbox()
        .map_err(map_store_error)?
        .into_iter()
        .filter(|record| {
            matches!(
                record.message.topic.as_str(),
                CATALOG_COMMITTED_TOPIC | CATALOG_TOMBSTONED_TOPIC
            )
        })
        .map(|record| record.causal_revision)
        .max()
        .unwrap_or(StoreRevision(0)))
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

const fn map_compiler_control_error(error: CompilerControlPlaneError) -> cigar_protocol::ErrorCode {
    match error {
        CompilerControlPlaneError::Unauthorized => cigar_protocol::ErrorCode::PolicyDenied,
        CompilerControlPlaneError::InvalidInput => cigar_protocol::ErrorCode::InvalidArgument,
        CompilerControlPlaneError::Integrity => cigar_protocol::ErrorCode::IntegrityFailure,
        CompilerControlPlaneError::SequenceConflict => cigar_protocol::ErrorCode::RevisionConflict,
        CompilerControlPlaneError::LimitExceeded => cigar_protocol::ErrorCode::LimitExceeded,
        CompilerControlPlaneError::Unavailable => cigar_protocol::ErrorCode::DependencyUnavailable,
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
        context: &cigar_api::RequestContext,
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
        context
            .check_active(observed_at)
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?;
        let retrieval_deadline = context
            .deadline()
            .unix_nanos()
            .checked_sub(observed_at.unix_nanos())
            .and_then(|nanos| u64::try_from(nanos).ok())
            .and_then(|nanos| Instant::now().checked_add(Duration::from_nanos(nanos)))
            .ok_or(crate::SpaceHandoffDependencyError::Unavailable)?;
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
        let partition = authorized_partition_for_identity(identity, observed_at, &catalog)
            .map_err(map_handoff_protocol_error)?;
        let access = AccessContext::new(identity.tenant_id.clone(), catalog.purpose.clone())
            .map_err(|_error| crate::SpaceHandoffDependencyError::Invalid)?;
        let read = self
            .repository
            .begin_read(access, SnapshotSelection::Latest, cancellation.clone())
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?;
        let revision = catalog_revision(&read)
            .map_err(|_error| crate::SpaceHandoffDependencyError::Unavailable)?;
        let index_authorized = index_authorizes_version(
            self.retriever.as_ref(),
            &partition,
            revision,
            version_id,
            cancellation.clone(),
            retrieval_deadline,
        )
        .map_err(map_handoff_retrieval_error)?;
        if !index_authorized {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        let atom = read
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
            || !atom_authorized(&partition, &atom, false).map_err(map_handoff_protocol_error)?
        {
            return Err(crate::SpaceHandoffDependencyError::Denied);
        }
        partition.validate().map_err(map_handoff_retrieval_error)?;
        Ok(crate::ResolvedHandoffReference {
            version_id: atom.version_id,
            kind: expected_kind,
            content_digest: atom.content_digest,
        })
    }
}

const fn map_handoff_protocol_error(
    error: cigar_protocol::ErrorCode,
) -> crate::SpaceHandoffDependencyError {
    match error {
        cigar_protocol::ErrorCode::PolicyDenied | cigar_protocol::ErrorCode::UnknownPrincipal => {
            crate::SpaceHandoffDependencyError::Denied
        }
        cigar_protocol::ErrorCode::InvalidArgument
        | cigar_protocol::ErrorCode::IntegrityFailure => {
            crate::SpaceHandoffDependencyError::Invalid
        }
        _ => crate::SpaceHandoffDependencyError::Unavailable,
    }
}

const fn map_handoff_retrieval_error(error: RetrievalError) -> crate::SpaceHandoffDependencyError {
    match error.code() {
        RetrievalErrorCode::Denied => crate::SpaceHandoffDependencyError::Denied,
        RetrievalErrorCode::InvalidMetadata
        | RetrievalErrorCode::LimitExceeded
        | RetrievalErrorCode::CorruptGeneration
        | RetrievalErrorCode::RequiredCandidateMissing => {
            crate::SpaceHandoffDependencyError::Invalid
        }
        RetrievalErrorCode::IndexUnavailable
        | RetrievalErrorCode::IndexStale
        | RetrievalErrorCode::Cancelled
        | RetrievalErrorCode::DeadlineExceeded
        | RetrievalErrorCode::ChannelUnavailable => crate::SpaceHandoffDependencyError::Unavailable,
    }
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
        CatalogContextAuthorizer, CatalogErrorCode, ConfiguredSourceRuntime,
        ContextTokenizerRegistry, PinnedContextTokenizerRegistry, RetainedCompileRecord,
        SourceConfiguration, SourceDiscoveryPolicyConfiguration, catalog_revision,
    };
    use crate::{
        AuthorityClock, AuthorityError, BlockingPool, DomainIdentityError, DomainIdentityResolver,
        ResolvedDomainIdentity,
    };
    use cigar_api::{
        AuthenticatedIdentity, BundleIdRequest, CancellationToken, CompileContextBundleOperation,
        CompileContextBundleRequest, CreateContextPlanOperation, CreateContextPlanRequest,
        DiscoverSourcesOperation, DiscoverSourcesRequest, FacadeErrorFactory,
        GetSourceStatusOperation, IngestCatalogOperation, IngestCatalogRequest,
        MAX_OPERATION_PAYLOAD_BYTES, MaterializationProfile, MaterializeContextBundleOperation,
        MaterializeContextBundleRequest, OperationId, PathParameter, PrincipalId, RequestContext,
        RequestEnvelope, RevalidateContextBundleOperation, SourceIdRequest, TenantId, TraceId,
        TypedUnaryAdapter, UnaryOperationHandler, decode_operation_payload,
        encode_operation_payload,
    };
    use cigar_catalog::{
        Atomizer, FILESYSTEM_CONNECTOR_ID, LocalFilesystemConnector, atomizer_registry_digest,
    };
    use cigar_code_intel::{AtomizationProfile, BuiltinAtomizer, BuiltinAtomizerKind};
    use cigar_compiler::{
        ExactTokenizer, MaterializationError, ReferenceTokenizer, ReferenceTokenizerProfile,
    };
    use cigar_policy::{
        CapabilityContext, CompiledPolicyEngine, PolicyProfile, PolicyRequest, PolicyResource,
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
        AccessContext, CancellationToken as StoreCancellationToken, InMemoryStore, OutboxMessage,
        ReadTransaction, Repository, ServiceBatch, ServiceExpectedVersion, ServiceRecordLocator,
        ServiceRecordSelection, ServiceRecordWrite, ServiceRepository, ServiceResponse,
        SnapshotSelection, StoreRevision, WriteTransaction,
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct ConflictingTokenizer(ContentDigest);

    impl ExactTokenizer for ConflictingTokenizer {
        fn fingerprint(&self) -> &ContentDigest {
            &self.0
        }

        fn count_exact(&self, bytes: &[u8]) -> Result<u32, MaterializationError> {
            u32::try_from(bytes.len()).map_err(|_error| MaterializationError::LimitExceeded)
        }
    }

    struct CountingTokenizer {
        fingerprint: ContentDigest,
        calls: Arc<AtomicUsize>,
    }

    impl ExactTokenizer for CountingTokenizer {
        fn fingerprint(&self) -> &ContentDigest {
            &self.fingerprint
        }

        fn count_exact(&self, bytes: &[u8]) -> Result<u32, MaterializationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            u32::try_from(bytes.len()).map_err(|_error| MaterializationError::LimitExceeded)
        }
    }

    struct CountingStore {
        inner: InMemoryStore,
        denied_version: VersionId,
        denied_atom_reads: Arc<AtomicUsize>,
    }

    struct CountingRead {
        inner: cigar_store::InMemoryReadTransaction,
        denied_version: VersionId,
        denied_atom_reads: Arc<AtomicUsize>,
    }

    impl ReadTransaction for CountingRead {
        fn revision(&self) -> StoreRevision {
            self.inner.revision()
        }

        fn get_atom(
            &self,
            version: &VersionId,
        ) -> Result<Option<ContextAtomV1>, cigar_store::StoreError> {
            if version == &self.denied_version {
                self.denied_atom_reads.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.get_atom(version)
        }

        fn get_atoms_by_id(
            &self,
            atom_ids: &[RecordId],
        ) -> Result<Vec<Option<ContextAtomV1>>, cigar_store::StoreError> {
            self.inner.get_atoms_by_id(atom_ids)
        }

        fn get_active_atom_by_id(
            &self,
            atom_id: &RecordId,
        ) -> Result<Option<ContextAtomV1>, cigar_store::StoreError> {
            self.inner.get_active_atom_by_id(atom_id)
        }

        fn query_atoms(
            &self,
            selector: cigar_store::AtomSelector,
            limit: usize,
            cursor: Option<&cigar_store::AtomCursor>,
        ) -> Result<cigar_store::AtomPage, cigar_store::StoreError> {
            self.inner.query_atoms(selector, limit, cursor)
        }

        fn edges_from(
            &self,
            version: &VersionId,
            kind: Option<cigar_protocol::EdgeKind>,
            limit: usize,
        ) -> Result<Vec<cigar_protocol::ContextEdge>, cigar_store::StoreError> {
            self.inner.edges_from(version, kind, limit)
        }

        fn get_bundle(
            &self,
            bundle: &VersionId,
        ) -> Result<Option<ContextBundle>, cigar_store::StoreError> {
            self.inner.get_bundle(bundle)
        }

        fn get_snapshot(
            &self,
            snapshot: &RecordId,
        ) -> Result<Option<cigar_protocol::SourceSnapshot>, cigar_store::StoreError> {
            self.inner.get_snapshot(snapshot)
        }

        fn context_commits(
            &self,
            space: &cigar_protocol::ContextSpaceId,
        ) -> Result<Vec<cigar_protocol::ContextCommit>, cigar_store::StoreError> {
            self.inner.context_commits(space)
        }

        fn get_effect(
            &self,
            effect: &RecordId,
        ) -> Result<Vec<cigar_protocol::EffectJournalEvent>, cigar_store::StoreError> {
            self.inner.get_effect(effect)
        }

        fn get_effect_record(
            &self,
            effect: &RecordId,
        ) -> Result<Option<cigar_store::EffectRecordEnvelope>, cigar_store::StoreError> {
            self.inner.get_effect_record(effect)
        }

        fn get_blob(
            &self,
            digest: &ContentDigest,
        ) -> Result<Option<cigar_store::BlobRecord>, cigar_store::StoreError> {
            self.inner.get_blob(digest)
        }

        fn outbox(&self) -> Result<Vec<cigar_store::OutboxRecord>, cigar_store::StoreError> {
            self.inner.outbox()
        }

        fn idempotent_result(
            &self,
            identity: &cigar_store::IdempotencyIdentity,
        ) -> Result<Option<cigar_store::CommitReceipt>, cigar_store::StoreError> {
            self.inner.idempotent_result(identity)
        }
    }

    impl Repository for CountingStore {
        type Read<'store>
            = CountingRead
        where
            Self: 'store;
        type Write<'store>
            = cigar_store::InMemoryWriteTransaction<'store>
        where
            Self: 'store;

        fn begin_read(
            &self,
            context: AccessContext,
            selection: SnapshotSelection,
            cancellation: StoreCancellationToken,
        ) -> Result<Self::Read<'_>, cigar_store::StoreError> {
            Ok(CountingRead {
                inner: self.inner.begin_read(context, selection, cancellation)?,
                denied_version: self.denied_version.clone(),
                denied_atom_reads: Arc::clone(&self.denied_atom_reads),
            })
        }

        fn begin_write(
            &self,
            context: AccessContext,
            expected_revision: StoreRevision,
            cancellation: StoreCancellationToken,
        ) -> Result<Self::Write<'_>, cigar_store::StoreError> {
            self.inner
                .begin_write(context, expected_revision, cancellation)
        }
    }

    impl ServiceRepository for CountingStore {
        fn service_get(
            &self,
            locator: &ServiceRecordLocator,
            selection: ServiceRecordSelection,
            cancellation: &StoreCancellationToken,
        ) -> Result<Option<cigar_store::ServiceRecord>, cigar_store::ServiceError> {
            self.inner.service_get(locator, selection, cancellation)
        }

        fn service_list(
            &self,
            query: &cigar_store::ServiceListQuery,
            cancellation: &StoreCancellationToken,
        ) -> Result<cigar_store::ServiceListPage, cigar_store::ServiceError> {
            self.inner.service_list(query, cancellation)
        }

        fn service_commit(
            &self,
            batch: cigar_store::ServiceBatch,
            cancellation: &StoreCancellationToken,
        ) -> Result<cigar_store::ServiceBatchReceipt, cigar_store::ServiceError> {
            self.inner.service_commit(batch, cancellation)
        }

        fn effect_recovery(
            &self,
            query: &cigar_store::EffectRecoveryQuery,
            cancellation: &StoreCancellationToken,
        ) -> Result<cigar_store::EffectRecoveryPage, cigar_store::ServiceError> {
            self.inner.effect_recovery(query, cancellation)
        }

        fn outbox_recovery(
            &self,
            query: &cigar_store::OutboxRecoveryQuery,
            cancellation: &StoreCancellationToken,
        ) -> Result<cigar_store::OutboxRecoveryPage, cigar_store::ServiceError> {
            self.inner.outbox_recovery(query, cancellation)
        }

        fn worker_get(
            &self,
            locator: &cigar_store::WorkerLocator,
            cancellation: &StoreCancellationToken,
        ) -> Result<Option<cigar_store::WorkerState>, cigar_store::ServiceError> {
            self.inner.worker_get(locator, cancellation)
        }

        fn worker_update(
            &self,
            locator: &cigar_store::WorkerLocator,
            update: cigar_store::WorkerUpdate,
            cancellation: &StoreCancellationToken,
        ) -> Result<cigar_store::WorkerState, cigar_store::ServiceError> {
            self.inner.worker_update(locator, update, cancellation)
        }
    }

    #[test]
    fn tokenizer_registry_resolves_known_and_rejects_duplicate_conflicting_or_unknown_entries()
    -> TestResult {
        let registry = PinnedContextTokenizerRegistry::default();
        let profile = ReferenceTokenizerProfile::Utf8BytesV1;
        let target = profile.target_profile(
            ContentDigest::new(format!("1220{}", "aa".repeat(32)))?,
            4_096,
        )?;
        let tokenizer: Arc<dyn ExactTokenizer + Send + Sync> =
            Arc::new(ReferenceTokenizer::new(profile)?);
        let fingerprint = tokenizer.fingerprint().clone();
        registry.register_for_target(
            &target.provider,
            &target.model_family,
            Arc::clone(&tokenizer),
        )?;
        registry.register_for_target(
            &target.provider,
            &target.model_family,
            Arc::clone(&tokenizer),
        )?;
        assert!(registry.tokenizer(&target).is_some());

        assert_eq!(
            registry.register_for_target(
                &target.provider,
                &target.model_family,
                Arc::new(ReferenceTokenizer::new(profile)?),
            ),
            Err(CatalogContextAuthorizationError::InvalidDecision)
        );
        assert_eq!(
            registry.register_for_target(
                &target.provider,
                &target.model_family,
                Arc::new(ConflictingTokenizer(fingerprint.clone())),
            ),
            Err(CatalogContextAuthorizationError::InvalidDecision)
        );

        let mut external = target.clone();
        external.provider = "anthropic".to_owned();
        assert!(registry.tokenizer(&external).is_none());
        external.provider = "openai".to_owned();
        assert!(registry.tokenizer(&external).is_none());
        let mut cross_paired = target.clone();
        cross_paired.model_family = ReferenceTokenizerProfile::UnicodeScalarsV1
            .identifier()
            .to_owned();
        assert!(registry.tokenizer(&cross_paired).is_none());
        let mut unknown = target;
        unknown.tokenizer_fingerprint = ContentDigest::new(format!("1220{}", "ff".repeat(32)))?;
        assert!(registry.tokenizer(&unknown).is_none());
        Ok(())
    }

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

    struct FixedAuthorizer {
        authorization: CatalogContextAuthorization,
        _policy: Arc<CompiledPolicyEngine>,
    }

    impl CatalogContextAuthorizer for FixedAuthorizer {
        fn authorize_catalog(
            &self,
            _identity: &ResolvedDomainIdentity,
            _observed_at: UtcTimestamp,
        ) -> Result<CatalogContextAuthorization, CatalogContextAuthorizationError> {
            Ok(self.authorization.clone())
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
                .all(|project_id| self.authorization.project_ids.contains(project_id))
            {
                Ok(self.authorization.clone())
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

    fn fixed_authorizer(
        tenant_id: &RecordId,
        principal_id: &RecordId,
        project_id: &RecordId,
    ) -> Result<Arc<FixedAuthorizer>, Box<dyn std::error::Error>> {
        let policy = Arc::new(CompiledPolicyEngine::default());
        let observed_at = timestamp()?;
        let snapshot = policy.install(
            PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            },
            observed_at,
        )?;
        let expires_at = UtcTimestamp::from_unix_nanos(
            observed_at
                .unix_nanos()
                .checked_add(60_000_000_000)
                .ok_or("authorization timestamp overflow")?,
        )?;
        let projects = BTreeSet::from([project_id.clone()]);
        let processors = BTreeSet::from(["local".to_owned()]);
        let policy_request = PolicyRequest {
            resource: PolicyResource::Partition,
            input_digest: digest_bytes(b"catalog-context-test-authorization")?,
            principal_id: principal_id.clone(),
            principal_active: true,
            tenant_id: tenant_id.clone(),
            authenticated_tenant_id: tenant_id.clone(),
            project_id: Some(project_id.clone()),
            allowed_project_ids: projects.clone(),
            purpose: "coding".to_owned(),
            allowed_purposes: BTreeSet::from(["coding".to_owned()]),
            processor: Some("local".to_owned()),
            allowed_processors: processors.clone(),
            classification: Classification::Public,
            maximum_classification: Classification::Internal,
            residency_allowed: true,
            egress_allowed: true,
            lifecycle: Lifecycle::Active,
            integrity_verified: true,
            valid_at: observed_at,
            valid_from: observed_at,
            valid_until: Some(expires_at),
            observed_at,
            observed_as_of: observed_at,
            freshness_expires_at: None,
            instruction_authority: InstructionAuthority::Data,
            maximum_instruction_authority: InstructionAuthority::Project,
            excluded: false,
            modality_supported: true,
            capability: Some(CapabilityContext {
                subject_id: principal_id.clone(),
                grant_id: Some(record(900)?),
                capabilities: BTreeSet::from([cigar_protocol::Capability::CompileContext]),
                project_ids: projects.clone(),
                processors,
                expires_at,
            }),
            required_capability: Some(cigar_protocol::Capability::CompileContext),
            bound_policy_digest: None,
            effect_risk: None,
            effect_approved: false,
            effect_constraints_satisfied: true,
            fencing_required: false,
            fencing_verified: false,
            decision_expires_at: expires_at,
        };
        let retrieval_authorization = policy.authorize_retrieval_partition(&[policy_request])?;
        Ok(Arc::new(FixedAuthorizer {
            authorization: CatalogContextAuthorization {
                project_ids: projects,
                purpose: "coding".to_owned(),
                processor: "local".to_owned(),
                maximum_classification: Classification::Internal,
                maximum_instruction_authority: InstructionAuthority::Project,
                policy_digest: snapshot.policy_digest,
                vector_allowed: false,
                retrieval_authorization,
            },
            _policy: policy,
        }))
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
                max_context_tokens: 4_096,
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
                tenant_watermarks: [(tenant_id.clone(), StoreRevision(1))]
                    .into_iter()
                    .collect(),
                configuration_digest: ContentDigest::new(format!("1220{}", "c".repeat(64)))?,
                verified_at: timestamp()?,
                vector_binding: None,
            },
            &retrieval_context,
        )?;
        retriever.activate(&descriptor.generation_id, None)?;
        let tokenizer_registry = Arc::new(PinnedContextTokenizerRegistry::default());
        tokenizer_registry.register_byte_tokenizer("local", "byte-metered", tokenizer)?;
        let authorizer = fixed_authorizer(&tenant_id, &principal_id, &project_id)?;
        let identities = Arc::new(IdentityResolver(ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id: principal_id.clone(),
        }));
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

    #[test]
    fn catalog_revision_ignores_later_non_catalog_store_revisions() -> TestResult {
        let store = InMemoryStore::default();
        let tenant_id = record(301)?;
        let access = AccessContext::new(tenant_id.clone(), "coding")?;
        let mut catalog = store.begin_write(
            access.clone(),
            StoreRevision(0),
            StoreCancellationToken::default(),
        )?;
        catalog.publish_atoms(
            vec![atom(&tenant_id, &record(304)?, "catalog revision")?],
            Vec::new(),
        )?;
        catalog.enqueue_outbox(OutboxMessage {
            message_id: record(302)?,
            topic: "catalog.committed".to_owned(),
            payload_digest: digest_bytes(b"catalog revision")?,
        })?;
        assert_eq!(catalog.commit(None)?.revision, StoreRevision(1));

        let bytes = b"unrelated service state".to_vec();
        let service = ServiceBatch::new(
            tenant_id,
            vec![ServiceRecordWrite::new(
                "context.test-state.v1",
                record(303)?.as_str(),
                ServiceExpectedVersion::Absent,
                bytes.clone(),
            )?],
            ServiceResponse::new(200, "application/octet-stream", bytes)?,
        )?
        .with_expected_store_revision(StoreRevision(1));
        assert_eq!(
            store
                .service_commit(service, &StoreCancellationToken::default())?
                .revision,
            StoreRevision(2)
        );

        let read = store.begin_read(
            access,
            SnapshotSelection::Latest,
            StoreCancellationToken::default(),
        )?;
        assert_eq!(read.revision(), StoreRevision(2));
        assert_eq!(catalog_revision(&read), Ok(StoreRevision(1)));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn denied_dependency_is_rejected_before_full_atom_or_tokenizer_read() -> TestResult {
        let tenant_id = record(201)?;
        let principal_id = record(202)?;
        let project_id = record(203)?;
        let parent = atom(&tenant_id, &project_id, "authorized parent")?;
        let denied_body = "denied dependency payload canary";
        let mut denied = atom(&tenant_id, &project_id, denied_body)?;
        denied.atom_id = record(204)?;
        denied.lineage_id = cigar_protocol::LineageId::new("01890f47-8e7d-7b42-a1d2-000000000205")?;
        denied.version_id = version(206)?;
        denied.content_digest = digest_bytes(denied_body.as_bytes())?;
        denied.payload = AtomPayload::InlineText(denied_body.to_owned());
        denied.source.uri = SourceUri::new("file:///protected/denied-dependency.md")?;
        denied.governance.classification = Classification::Restricted;
        let dependency_edge = cigar_protocol::ContextEdge {
            schema_version: SchemaVersion::new("cigar.edge", 1)?,
            edge_id: record(207)?,
            from_version: parent.version_id.clone(),
            to_version: denied.version_id.clone(),
            kind: cigar_protocol::EdgeKind::DependsOn,
            provenance_digest: digest_bytes(b"dependency provenance")?,
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        };

        let denied_reads = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(CountingStore {
            inner: InMemoryStore::default(),
            denied_version: denied.version_id.clone(),
            denied_atom_reads: Arc::clone(&denied_reads),
        });
        let access = AccessContext::new(tenant_id.clone(), "coding")?;
        let mut write =
            store.begin_write(access, StoreRevision(0), StoreCancellationToken::default())?;
        write.publish_atoms(
            vec![parent.clone(), denied.clone()],
            vec![dependency_edge.clone()],
        )?;
        write.commit(None)?;

        let retriever = Arc::new(InMemoryIndexManager::default());
        let retrieval_context = RetrievalContext {
            cancellation: StoreCancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let descriptor = retriever.build_generation(
            IndexBuild {
                atoms: vec![parent.clone(), denied.clone()],
                edges: vec![dependency_edge],
                built_through_revision: StoreRevision(1),
                tenant_watermarks: [(tenant_id.clone(), StoreRevision(1))]
                    .into_iter()
                    .collect(),
                configuration_digest: digest_bytes(b"denied-dependency-index")?,
                verified_at: timestamp()?,
                vector_binding: None,
            },
            &retrieval_context,
        )?;
        retriever.activate(&descriptor.generation_id, None)?;

        let tokenizer_fingerprint = digest_bytes(b"counting-tokenizer")?;
        let tokenizer_calls = Arc::new(AtomicUsize::new(0));
        let tokenizers = Arc::new(PinnedContextTokenizerRegistry::default());
        tokenizers.register_for_target(
            "local",
            "byte-metered",
            Arc::new(CountingTokenizer {
                fingerprint: tokenizer_fingerprint.clone(),
                calls: Arc::clone(&tokenizer_calls),
            }),
        )?;
        let materializer = digest_bytes(b"cigar.materializer.json.v1")?;
        let compile_contract = contract(
            record(299)?,
            project_id.clone(),
            parent.version_id,
            tokenizer_fingerprint,
            materializer,
        )?;
        let authorizer = fixed_authorizer(&tenant_id, &principal_id, &project_id)?;
        let identities = Arc::new(IdentityResolver(ResolvedDomainIdentity {
            tenant_id,
            principal_id,
        }));
        let errors: Arc<dyn FacadeErrorFactory> = Arc::new(Errors(record(208)?));
        let clock = Arc::new(FixedClock(timestamp()?));
        let application = Arc::new(CatalogContextApplication::new(
            Arc::clone(&store),
            identities,
            authorizer,
            retriever,
            tokenizers,
            Arc::new(BlockingPool::new(2, 2)?),
            clock.clone(),
            Arc::clone(&errors),
        ));
        let adapter = TypedUnaryAdapter::<CreateContextPlanOperation, _>::new(application, errors);
        let request = RequestEnvelope::new(
            "createContextPlan",
            encode_operation_payload(
                &CreateContextPlanRequest {
                    contract: compile_contract,
                },
                MAX_OPERATION_PAYLOAD_BYTES,
            )?,
            Some("denied-dependency-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let error = adapter
            .call(request_context("createContextPlan", clock.0)?, request)
            .await
            .err()
            .ok_or("denied dependency unexpectedly succeeded")?;
        assert_eq!(error.code(), cigar_protocol::ErrorCode::PolicyDenied);
        assert_eq!(denied_reads.load(Ordering::SeqCst), 0);
        assert_eq!(tokenizer_calls.load(Ordering::SeqCst), 0);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(denied_body));
        assert!(!diagnostic.contains(denied.version_id.as_str()));
        assert!(!diagnostic.contains(denied.source.uri.as_str()));
        Ok(())
    }

    #[test]
    fn wildcard_record_governance_uses_the_opaque_policy_gate() -> TestResult {
        let tenant_id = record(220)?;
        let principal_id = record(221)?;
        let project_id = record(222)?;
        let authorizer = fixed_authorizer(&tenant_id, &principal_id, &project_id)?;
        let partition = cigar_retrieval::AuthorizedPartition::from_policy_authorization(
            authorizer.authorization.retrieval_authorization.clone(),
        )?;
        let mut wildcard = atom(&tenant_id, &project_id, "wildcard governed body")?;
        wildcard.governance.allowed_purposes = vec!["*".to_owned()];
        assert!(
            super::atom_authorized(&partition, &wildcard, true)
                .map_err(|error| format!("wildcard authorization failed: {error:?}"))?
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revocation_after_compile_hides_retained_bundle_and_materialization() -> TestResult {
        let fixture = fixture()?;
        let adapter = TypedUnaryAdapter::<CreateContextPlanOperation, _>::new(
            Arc::clone(&fixture.application),
            Arc::clone(&fixture.errors),
        );
        let request = RequestEnvelope::new(
            "createContextPlan",
            encode_operation_payload(
                &CreateContextPlanRequest {
                    contract: fixture.contract.clone(),
                },
                MAX_OPERATION_PAYLOAD_BYTES,
            )?,
            Some("revocation-plan-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let response = adapter
            .call(
                request_context("createContextPlan", fixture.clock.0)?,
                request,
            )
            .await?;
        let plan: cigar_api::ContextPlanResponse =
            decode_operation_payload(response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        let source_version = match &fixture
            .contract
            .requirements
            .first()
            .ok_or("fixture requirement missing")?
            .selector
        {
            RequirementSelector::Exact(version_id) => version_id.clone(),
            RequirementSelector::Query(_) => return Err("fixture selector changed".into()),
        };
        let read = fixture.store.begin_read(
            AccessContext::new(fixture.tenant_id.clone(), "coding")?,
            SnapshotSelection::Latest,
            StoreCancellationToken::default(),
        )?;
        let selected = read
            .get_atom(&source_version)?
            .ok_or("fixture atom missing")?;
        fixture.authorizer._policy.revoke_resource(
            selected.content_digest.clone(),
            UtcTimestamp::from_unix_nanos(
                fixture
                    .clock
                    .0
                    .unix_nanos()
                    .checked_add(1_000_000_000)
                    .ok_or("revocation time overflow")?,
            )?,
        )?;

        let bundle_adapter = TypedUnaryAdapter::<CompileContextBundleOperation, _>::new(
            Arc::clone(&fixture.application),
            Arc::clone(&fixture.errors),
        );
        let bundle_request = RequestEnvelope::new(
            "compileContextBundle",
            encode_operation_payload(
                &CompileContextBundleRequest {
                    plan_id: plan.plan.plan_id,
                },
                MAX_OPERATION_PAYLOAD_BYTES,
            )?,
            Some("revoked-bundle-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let bundle_error = bundle_adapter
            .call(
                request_context("compileContextBundle", fixture.clock.0)?,
                bundle_request,
            )
            .await
            .err()
            .ok_or("revoked bundle unexpectedly returned")?;
        assert_eq!(bundle_error.code(), cigar_protocol::ErrorCode::PolicyDenied);

        let bundle_id = plan.bundle_id;
        let materialize_adapter = TypedUnaryAdapter::<MaterializeContextBundleOperation, _>::new(
            fixture.application,
            Arc::clone(&fixture.errors),
        );
        let materialize_request = RequestEnvelope::new(
            "materializeContextBundle",
            encode_operation_payload(
                &MaterializeContextBundleRequest {
                    bundle_id: bundle_id.clone(),
                    profile: MaterializationProfile::CanonicalJson,
                },
                MAX_OPERATION_PAYLOAD_BYTES,
            )?,
            Some("revoked-materialize-key".to_owned()),
            None,
            None,
            None,
            vec![PathParameter::new("bundle_id", bundle_id.as_str())?],
        )?;
        let materialize_error = materialize_adapter
            .call(
                request_context("materializeContextBundle", fixture.clock.0)?,
                materialize_request,
            )
            .await
            .err()
            .ok_or("revoked body unexpectedly materialized")?;
        assert_eq!(materialize_error.code(), bundle_error.code());
        let diagnostic =
            format!("{bundle_error:?} {bundle_error} {materialize_error:?} {materialize_error}");
        assert!(!diagnostic.contains("retained documentation"));
        assert!(!diagnostic.contains(selected.content_digest.as_str()));
        assert!(!diagnostic.contains(selected.source.uri.as_str()));
        Ok(())
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
    async fn physical_target_overflow_is_publicly_rejected_and_restart_idempotent() -> TestResult {
        let mut fixture = fixture()?;
        fixture.contract.target.max_context_tokens = 256;
        let plan_adapter = TypedUnaryAdapter::<CreateContextPlanOperation, _>::new(
            Arc::clone(&fixture.application),
            Arc::clone(&fixture.errors),
        );
        let plan_request = RequestEnvelope::new(
            "createContextPlan",
            encode_operation_payload(
                &CreateContextPlanRequest {
                    contract: fixture.contract.clone(),
                },
                MAX_OPERATION_PAYLOAD_BYTES,
            )?,
            Some("overflow-plan-key".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let plan_response = plan_adapter
            .call(
                request_context("createContextPlan", fixture.clock.0)?,
                plan_request,
            )
            .await?;
        let plan: cigar_api::ContextPlanResponse =
            decode_operation_payload(plan_response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;

        let materialize_payload = MaterializeContextBundleRequest {
            bundle_id: plan.bundle_id.clone(),
            profile: MaterializationProfile::CanonicalJson,
        };
        let materialize_adapter = TypedUnaryAdapter::<MaterializeContextBundleOperation, _>::new(
            Arc::clone(&fixture.application),
            Arc::clone(&fixture.errors),
        );
        let materialize_request = RequestEnvelope::new(
            "materializeContextBundle",
            encode_operation_payload(&materialize_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("overflow-materialize-key".to_owned()),
            None,
            None,
            None,
            vec![PathParameter::new("bundle_id", plan.bundle_id.as_str())?],
        )?;
        let error = materialize_adapter
            .call(
                request_context("materializeContextBundle", fixture.clock.0)?,
                materialize_request,
            )
            .await
            .err()
            .ok_or("physical target overflow unexpectedly materialized")?;
        assert_eq!(error.code(), cigar_protocol::ErrorCode::BudgetUnsatisfiable);

        let locator = cigar_store::WorkerLocator::new(
            fixture.tenant_id.clone(),
            "context-target-overflow-v1",
        )?;
        let before_restart = fixture
            .store
            .worker_get(&locator, &StoreCancellationToken::default())?
            .ok_or("missing physical-overflow checkpoint")?;
        assert!(before_restart.lease_owner().is_none());
        let diagnostic: serde_json::Value = serde_json::from_slice(before_restart.cursor())?;
        let diagnostic = diagnostic
            .as_object()
            .ok_or("physical-overflow checkpoint was not an object")?;
        assert_eq!(
            diagnostic
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("cigar.target-overflow-repair.v1")
        );
        assert_eq!(
            diagnostic
                .get("bundle_id")
                .and_then(serde_json::Value::as_str),
            Some(plan.bundle_id.as_str())
        );
        assert_eq!(
            diagnostic
                .get("maximum_input_tokens")
                .and_then(serde_json::Value::as_u64),
            Some(256)
        );
        assert!(
            diagnostic
                .get("observed_tokens")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|observed| observed > 256)
        );
        assert!(
            !String::from_utf8_lossy(before_restart.cursor()).contains("retained documentation")
        );

        let restarted = Arc::new(CatalogContextApplication::new(
            Arc::clone(&fixture.store),
            fixture.identities.clone(),
            fixture.authorizer.clone(),
            fixture.retriever.clone(),
            fixture.tokenizer_registry.clone() as Arc<dyn ContextTokenizerRegistry>,
            Arc::new(BlockingPool::new(2, 2)?),
            fixture.clock.clone(),
            Arc::clone(&fixture.errors),
        ));
        let restarted_adapter = TypedUnaryAdapter::<MaterializeContextBundleOperation, _>::new(
            restarted,
            Arc::clone(&fixture.errors),
        );
        let retry_request = RequestEnvelope::new(
            "materializeContextBundle",
            encode_operation_payload(&materialize_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("overflow-materialize-restart-key".to_owned()),
            None,
            None,
            None,
            vec![PathParameter::new("bundle_id", plan.bundle_id.as_str())?],
        )?;
        let retry_error = restarted_adapter
            .call(
                request_context("materializeContextBundle", fixture.clock.0)?,
                retry_request,
            )
            .await
            .err()
            .ok_or("physical target overflow materialized after restart")?;
        assert_eq!(retry_error.code(), error.code());
        let after_restart = fixture
            .store
            .worker_get(&locator, &StoreCancellationToken::default())?
            .ok_or("physical-overflow checkpoint disappeared")?;
        assert_eq!(after_restart.version(), before_restart.version());
        assert_eq!(after_restart.cursor(), before_restart.cursor());
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
        let atomization_profile = AtomizationProfile {
            scope: ScopeEnvelope {
                tenant_id: tenant_id.clone(),
                project_ids: vec![project_id.clone()],
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
                authority: 1,
            },
            lexical_enabled: true,
            embedding_eligible: false,
        };
        let connector = Arc::new(LocalFilesystemConnector::new(
            directory.path(),
            root.clone(),
        )?);
        let atomizer = Arc::new(BuiltinAtomizer::new(
            BuiltinAtomizerKind::Markdown,
            atomization_profile.clone(),
        )?);
        let atomization_profile_digest = atomizer_registry_digest(&[atomizer.descriptor()])?;
        let source_configuration = SourceConfiguration {
            schema_version: "cigar.source-configuration.v1".to_owned(),
            source_id: source_id.clone(),
            root: root.clone(),
            connector_identity: FILESYSTEM_CONNECTOR_ID.to_owned(),
            atomization_profile_digest,
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
        };
        let mismatched_connector = Arc::new(LocalFilesystemConnector::new(
            directory.path(),
            SourceUri::new("file:///substituted-root")?,
        )?);
        assert_eq!(
            ConfiguredSourceRuntime::new(
                source_configuration.clone(),
                mismatched_connector,
                vec![atomizer.clone()],
            )
            .err()
            .map(|error| error.code()),
            Some(CatalogErrorCode::InvalidMetadata)
        );
        let mut substituted_profile = source_configuration.clone();
        substituted_profile.atomization_profile_digest =
            ContentDigest::new(format!("1220{}", "f".repeat(64)))?;
        assert_eq!(
            ConfiguredSourceRuntime::new(
                substituted_profile,
                connector.clone(),
                vec![atomizer.clone()],
            )
            .err()
            .map(|error| error.code()),
            Some(CatalogErrorCode::InvalidMetadata)
        );
        let json_atomizer = Arc::new(BuiltinAtomizer::new(
            BuiltinAtomizerKind::StructuredJson,
            atomization_profile,
        )?);
        let mut oversized_for_atomizer = source_configuration.clone();
        oversized_for_atomizer.discovery_policy.allowed_media_types =
            BTreeSet::from([MediaType::new("application/json")?]);
        oversized_for_atomizer.discovery_policy.max_record_bytes = 2_000_000;
        oversized_for_atomizer.discovery_policy.max_total_bytes = 2_000_000;
        oversized_for_atomizer.atomization_profile_digest =
            atomizer_registry_digest(&[json_atomizer.descriptor()])?;
        assert_eq!(
            ConfiguredSourceRuntime::new(
                oversized_for_atomizer,
                connector.clone(),
                vec![json_atomizer],
            )
            .err()
            .map(|error| error.code()),
            Some(CatalogErrorCode::InvalidMetadata)
        );
        let runtime = Arc::new(ConfiguredSourceRuntime::new(
            source_configuration,
            connector,
            vec![atomizer],
        )?);
        let store = Arc::new(InMemoryStore::default());
        let authorizer = fixed_authorizer(&tenant_id, &principal_id, &project_id)?;
        let identities = Arc::new(IdentityResolver(ResolvedDomainIdentity {
            tenant_id: tenant_id.clone(),
            principal_id: principal_id.clone(),
        }));
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

        let ingest_adapter = TypedUnaryAdapter::<IngestCatalogOperation, _>::new(
            Arc::clone(&restarted),
            Arc::clone(&errors),
        );
        let ingest_payload = IngestCatalogRequest {
            source_id: source_id.clone(),
            plan_digest: actual_plan.plan_digest.clone(),
        };
        std::fs::write(
            directory.path().join("README.md"),
            b"substituted documentation",
        )?;
        let substituted_request = RequestEnvelope::new(
            "ingestCatalog",
            encode_operation_payload(&ingest_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("catalog-substitution-fixture".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let substitution_error = ingest_adapter
            .call(
                request_context("ingestCatalog", clock.0)?,
                substituted_request,
            )
            .await
            .err()
            .ok_or("changed source crossed the accepted discovery boundary")?;
        assert_eq!(
            substitution_error.code(),
            cigar_protocol::ErrorCode::SnapshotIncomplete
        );
        assert_eq!(store.revision()?, StoreRevision(2));
        std::fs::write(directory.path().join("README.md"), b"bounded documentation")?;
        let ingest_request = RequestEnvelope::new(
            "ingestCatalog",
            encode_operation_payload(&ingest_payload, MAX_OPERATION_PAYLOAD_BYTES)?,
            Some("catalog-transaction-fixture-1".to_owned()),
            None,
            None,
            None,
            Vec::new(),
        )?;
        let ingestion = ingest_adapter
            .call(request_context("ingestCatalog", clock.0)?, ingest_request)
            .await?;
        let ingestion: cigar_api::IngestionReceiptResponse =
            decode_operation_payload(ingestion.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)?;
        assert!(ingestion.published_atoms > 0);
        assert_eq!(ingestion.tombstoned_atoms, 0);
        assert_eq!(ingestion.revision, 3);
        let catalog = store.begin_read(
            AccessContext::new(tenant_id.clone(), "coding")?,
            SnapshotSelection::Latest,
            StoreCancellationToken::default(),
        )?;
        assert!(
            catalog
                .outbox()?
                .iter()
                .any(|record| record.message.topic == "catalog.committed")
        );
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
