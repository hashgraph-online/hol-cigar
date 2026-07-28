//! Production catalog-to-materialization benchmark execution.

use crate::ConsumerError;
use crate::assignment::{Assignment, ExtractedFixture, IntelligenceProfile, multihash};
use crate::observation::{
    Artifact, EffectReplay, Observation, Pins, Resources, ToolObservation, body_prefix,
    canonical_json, core_artifacts, dispositions, normalized_duration, phase, selected_blocks,
};
use cigar_api::{
    AuthenticatedIdentity, BundleIdRequest, CancellationToken, CompileContextBundleOperation,
    CompileContextBundleRequest, CreateContextPlanOperation, CreateContextPlanRequest,
    DiscoverSourcesOperation, DiscoverSourcesRequest, ExplainContextBundleOperation,
    ExplainContextBundleRequest, FacadeErrorFactory, GetContextBundleManifestOperation,
    IngestCatalogOperation, IngestCatalogRequest, MAX_OPERATION_PAYLOAD_BYTES,
    MaterializationProfile, MaterializeContextBundleOperation, MaterializeContextBundleRequest,
    OperationId, OperationPayload, PrincipalId, RequestContext, RequestEnvelope, TenantId, TraceId,
    TypedOperation, TypedUnaryAdapter, TypedUnaryService, UnaryOperationHandler,
    decode_operation_payload, encode_operation_payload,
};
use cigar_catalog::{Atomizer, SourceConnector, atomizer_registry_digest};
use cigar_code_intel::{AtomizationProfile, BuiltinAtomizer};
use cigar_compiler::{CompilerProfile, ReferenceTokenizerProfile, compiler_profile_digest};
use cigar_daemon::{
    AuthorityClock, AuthorityError, BlockingPool, CatalogContextApplication,
    CatalogContextAuthorization, CatalogContextAuthorizationError, CatalogContextAuthorizer,
    ConfiguredSourceRuntime, DomainIdentityError, DomainIdentityResolver,
    PinnedContextTokenizerRegistry, ResolvedDomainIdentity, SourceConfiguration,
    SourceDiscoveryPolicyConfiguration,
};
use cigar_effects::run_fault_campaign;
use cigar_policy::{
    CapabilityContext, CompiledPolicyEngine, EffectiveCapabilities, PolicyProfile, PolicyRequest,
    PolicyResource,
};
use cigar_protocol::{
    Budget, Capability, Classification, ConsistencyMode, ContentDigest, ContextContract,
    ContextRequirement, CoordinationTopic, ExtensionMap, FixedPoint, GovernanceEnvelope,
    HandoffReferences, InstructionAuthority, LaneKind, OperationClass, QualityEnvelope,
    RecipientSelector, RecordId, RequirementSelector, SchemaVersion, ScopeEnvelope, SourceUri,
    UtcTimestamp, VersionId,
};
use cigar_replay::{ReplayDimensionDigests, compare_replay_dimensions};
use cigar_retrieval::{
    AuthorizedPartition, InMemoryIndexManager, IndexBuild, QueryPlannerProfile,
    RetrievalConsistency, RetrievalContext, RetrievalErrorCode, RetrievalProfile, RetrievalRequest,
    RetrievalStage, Retriever,
};
use cigar_space::{CreateHandoffRequest, HandoffService};
use cigar_store::{
    AccessContext, AtomSelector, CancellationToken as StoreCancellationToken, InMemoryStore,
    ReadTransaction, Repository, SnapshotSelection, StoreRevision,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Application = CatalogContextApplication<InMemoryStore>;

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
            .all(|project| self.authorization.project_ids.contains(project))
        {
            Ok(self.authorization.clone())
        } else {
            Err(CatalogContextAuthorizationError::Denied)
        }
    }
}

#[derive(Serialize)]
struct PlannerProfilePin {
    schema_version: &'static str,
    exact_cap: u64,
    metadata_cap: u64,
    lexical_cap: u64,
    vector_cap: u64,
    exact_timeout_ms: u64,
    metadata_timeout_ms: u64,
    lexical_timeout_ms: u64,
    vector_timeout_ms: u64,
}

#[derive(Serialize)]
struct ExperimentalPlannerProfilePin {
    schema_version: &'static str,
    base: PlannerProfilePin,
    exact_graph_depth: u16,
    graph_cap: u64,
    graph_timeout_ms: u64,
    augment_queries: bool,
    augment_cap: u64,
    augment_timeout_ms: u64,
}

#[derive(Serialize)]
struct MaterializationMetadata<'a> {
    schema_version: &'static str,
    bundle_id: &'a str,
    media_type: &'a str,
    content_digest: &'a str,
    byte_count: usize,
    physical_input_tokens: u32,
    tokenizer_fingerprint: &'a str,
    materializer_fingerprint: &'a str,
}

#[derive(Serialize)]
struct EffectCampaignArtifact {
    schema_version: &'static str,
    logical_effects: u64,
    possible_remote_commit_operations: u64,
    explicit_ambiguities: u64,
    duplicate_logical_effects: u64,
    blind_redispatches: u64,
}

/// Runs one assignment through the concrete production application.
pub async fn run(
    assignment: Assignment,
    assignment_bytes: &[u8],
) -> Result<Observation, ConsumerError> {
    let total_started = Instant::now();
    let assignment_digest = multihash(assignment_bytes)?;
    let mut phases = Vec::new();
    let mut tools = Vec::new();

    let fixture_started = Instant::now();
    let fixture = ExtractedFixture::from_assignment(&assignment)?;
    if multihash(fixture.archive_bytes())? != assignment.archive_digest {
        return Err(ConsumerError::new("archive_digest"));
    }
    phases.push(phase(
        assignment.consumer_mode,
        "fixture",
        elapsed_ms(fixture_started),
    ));

    let setup_started = Instant::now();
    let tenant_id = record(101)?;
    let principal_id = record(102)?;
    let caller_principal = record(103)?;
    let project_id = record(104)?;
    let source_id = record(105)?;
    let now = timestamp()?;
    let root = SourceUri::new("file:///benchmark-fixture")
        .map_err(|_error| ConsumerError::new("source_root"))?;
    let profile = AtomizationProfile {
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
            confidence: FixedPoint::new(FixedPoint::ONE)
                .map_err(|_error| ConsumerError::new("atomizer_profile"))?,
            coverage: FixedPoint::new(FixedPoint::ONE)
                .map_err(|_error| ConsumerError::new("atomizer_profile"))?,
            authority: 10,
        },
        lexical_enabled: true,
        embedding_eligible: false,
    };
    let mut atomizers: Vec<Arc<dyn Atomizer>> = BuiltinAtomizer::required_v1(profile)
        .map_err(|_error| ConsumerError::new("atomizer_profile"))?
        .into_iter()
        .map(|atomizer| Arc::new(atomizer) as Arc<dyn Atomizer>)
        .collect();
    atomizers.sort_by(|left, right| {
        let left = left.descriptor();
        let right = right.descriptor();
        (&left.id, &left.version).cmp(&(&right.id, &right.version))
    });
    let descriptors: Vec<_> = atomizers
        .iter()
        .map(|atomizer| atomizer.descriptor())
        .collect();
    let atomization_profile_digest = atomizer_registry_digest(&descriptors)
        .map_err(|_error| ConsumerError::new("atomizer_registry"))?;
    let connector: Arc<dyn SourceConnector> = Arc::new(fixture.connector(root.clone()));
    let runtime = Arc::new(
        ConfiguredSourceRuntime::new(
            SourceConfiguration {
                schema_version: "cigar.source-configuration.v1".to_owned(),
                source_id: source_id.clone(),
                root,
                connector_identity: "cigar.benchmark-fixture.v1".to_owned(),
                atomization_profile_digest,
                discovery_policy: SourceDiscoveryPolicyConfiguration {
                    max_items: 1_024,
                    max_total_bytes: 16 * 1024 * 1024,
                    max_record_bytes: 256 * 1024,
                    excluded_prefixes: assignment.exclusion_paths()?,
                    allowed_media_types: fixture.media_types().clone(),
                    allow_user_broadening: false,
                    follow_internal_symlinks: false,
                    secret_patterns: Vec::new(),
                },
            },
            connector,
            atomizers,
        )
        .map_err(|_error| ConsumerError::new("source_runtime"))?,
    );
    let store = Arc::new(InMemoryStore::default());
    let authorizer = fixed_authorizer(&tenant_id, &principal_id, &project_id, now)?;
    let policy_digest = authorizer.authorization.policy_digest.clone();
    let exact_authorization = authorizer.authorization.retrieval_authorization.clone();
    let identities = Arc::new(IdentityResolver(ResolvedDomainIdentity {
        tenant_id: tenant_id.clone(),
        principal_id: principal_id.clone(),
    }));
    let (retrieval_profile, compiler_profile) = match assignment
        .intelligence_profile
        .unwrap_or(IntelligenceProfile::BalancedV1)
    {
        IntelligenceProfile::BalancedV1 => {
            (RetrievalProfile::BalancedV1, CompilerProfile::default())
        }
        IntelligenceProfile::BalancedV2Candidate1 => (
            RetrievalProfile::BalancedV2Candidate,
            CompilerProfile::balanced_v2_candidate(),
        ),
    };
    let retriever = Arc::new(InMemoryIndexManager::with_experimental_profile(
        retrieval_profile,
    ));
    let tokenizer_registry = Arc::new(
        PinnedContextTokenizerRegistry::with_reference_profiles()
            .map_err(|_error| ConsumerError::new("tokenizer_registry"))?,
    );
    let clock = Arc::new(FixedClock(now));
    let errors: Arc<dyn FacadeErrorFactory> = Arc::new(Errors(record(106)?));
    let application = Arc::new(
        CatalogContextApplication::new(
            Arc::clone(&store),
            identities,
            authorizer,
            retriever.clone(),
            tokenizer_registry,
            Arc::new(
                BlockingPool::new(2, 2).map_err(|_error| ConsumerError::new("blocking_pool"))?,
            ),
            clock,
            Arc::clone(&errors),
        )
        .with_benchmark_compiler_profile(compiler_profile.clone())
        .with_benchmark_query_planner_profile(match retrieval_profile {
            RetrievalProfile::BalancedV1 => QueryPlannerProfile::default(),
            RetrievalProfile::BalancedV2Candidate => QueryPlannerProfile::balanced_v2_candidate(),
        }),
    );
    application
        .provision_source(
            tenant_id.clone(),
            runtime,
            &StoreCancellationToken::default(),
        )
        .map_err(|_error| ConsumerError::new("source_provision"))?;
    phases.push(phase(
        assignment.consumer_mode,
        "setup",
        elapsed_ms(setup_started),
    ));

    let ingest_started = Instant::now();
    let (discovery, observation) = call_operation::<DiscoverSourcesOperation>(
        &application,
        &errors,
        now,
        DiscoverSourcesRequest {
            source_id: source_id.clone(),
            include_paths: Vec::new(),
        },
        None,
    )
    .await?;
    tools.push(observation);
    let (ingestion, observation) = call_operation::<IngestCatalogOperation>(
        &application,
        &errors,
        now,
        IngestCatalogRequest {
            source_id,
            plan_digest: discovery.plan_digest,
        },
        Some("benchmark-ingest-v1"),
    )
    .await?;
    tools.push(observation);
    if ingestion.published_atoms == 0 || ingestion.tombstoned_atoms != 0 {
        return Err(ConsumerError::new("ingestion_empty"));
    }
    phases.push(phase(
        assignment.consumer_mode,
        "ingest",
        elapsed_ms(ingest_started),
    ));

    let index_started = Instant::now();
    let (atoms, edges, catalog_revision) = read_catalog(&store, &tenant_id)?;
    let graph_digest = multihash(&canonical_json(&edges)?)?;
    let retrieval_context = RetrievalContext {
        cancellation: StoreCancellationToken::default(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let descriptor = retriever
        .build_generation(
            IndexBuild {
                atoms,
                edges,
                built_through_revision: catalog_revision,
                tenant_watermarks: BTreeMap::from([(tenant_id.clone(), catalog_revision)]),
                configuration_digest: match retrieval_profile {
                    RetrievalProfile::BalancedV1 => multihash(b"cigar.benchmark-index.lexical.v1")?,
                    RetrievalProfile::BalancedV2Candidate => retrieval_profile
                        .digest()
                        .map_err(|_error| ConsumerError::new("retrieval_profile"))?,
                },
                verified_at: now,
                vector_binding: None,
            },
            &retrieval_context,
        )
        .map_err(|_error| ConsumerError::new("index_build"))?;
    let descriptor = retriever
        .activate(&descriptor.generation_id, None)
        .map_err(|_error| ConsumerError::new("index_activate"))?;
    phases.push(phase(
        assignment.consumer_mode,
        "index",
        elapsed_ms(index_started),
    ));

    let materializer = multihash(b"cigar.materializer.json.v1")?;
    let tokenizer_profile = ReferenceTokenizerProfile::Utf8BytesV1;
    let target = tokenizer_profile
        .target_profile(materializer.clone(), assignment.max_context_tokens)
        .map_err(|_error| ConsumerError::new("target_profile"))?;
    let compiler = compiler_profile_digest(&compiler_profile)
        .map_err(|_error| ConsumerError::new("compiler_profile"))?;
    let base_planner = PlannerProfilePin {
        schema_version: "cigar.query-planner-profile.v1",
        exact_cap: 16,
        metadata_cap: 256,
        lexical_cap: 256,
        vector_cap: 128,
        exact_timeout_ms: 250,
        metadata_timeout_ms: 500,
        lexical_timeout_ms: 750,
        vector_timeout_ms: 1_000,
    };
    let planner = match retrieval_profile {
        RetrievalProfile::BalancedV1 => multihash(&canonical_json(&base_planner)?)?,
        RetrievalProfile::BalancedV2Candidate => {
            multihash(&canonical_json(&ExperimentalPlannerProfilePin {
                schema_version: "cigar.query-planner-profile.v2-candidate.1",
                base: base_planner,
                exact_graph_depth: 2,
                graph_cap: 128,
                graph_timeout_ms: 750,
                augment_queries: false,
                augment_cap: 128,
                augment_timeout_ms: 500,
            })?)?
        }
    };
    let consumer = consumer_executable_digest()?;
    let contract = ContextContract {
        schema_version: SchemaVersion::new("cigar.context-contract", 1)
            .map_err(|_error| ConsumerError::new("contract"))?,
        job_goal: assignment.job_goal.clone(),
        operation_class: OperationClass::Read,
        principal_id: caller_principal,
        purpose: "coding".to_owned(),
        context_space_id: None,
        project_ids: vec![project_id.clone()],
        target: target.clone(),
        budget: Budget {
            total_input_tokens: assignment.token_budget,
            output_reserve_tokens: assignment.output_reserve_tokens,
            lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, assignment.token_budget)]),
        },
        requirements: vec![ContextRequirement {
            semantic_type: assignment.semantic_type.atom_kind(),
            selector: RequirementSelector::Query(assignment.query.clone()),
            minimum_authority: 1,
            maximum_age: None,
            minimum_coverage: FixedPoint::new(0)
                .map_err(|_error| ConsumerError::new("contract"))?,
            blocking: true,
        }],
        consistency: ConsistencyMode::Strong,
        maximum_staleness: None,
        extensions: ExtensionMap::default(),
    };

    let plan_started = Instant::now();
    let (plan_response, observation) = call_operation::<CreateContextPlanOperation>(
        &application,
        &errors,
        now,
        CreateContextPlanRequest { contract },
        Some("benchmark-plan-v1"),
    )
    .await?;
    tools.push(observation);
    phases.push(phase(
        assignment.consumer_mode,
        "plan",
        elapsed_ms(plan_started),
    ));

    let compile_started = Instant::now();
    let (bundle, observation) = call_operation::<CompileContextBundleOperation>(
        &application,
        &errors,
        now,
        CompileContextBundleRequest {
            plan_id: plan_response.plan.plan_id.clone(),
        },
        Some("benchmark-compile-v1"),
    )
    .await?;
    tools.push(observation);
    if bundle.bundle_id != plan_response.bundle_id
        || bundle.manifest_digest != plan_response.manifest_digest
    {
        return Err(ConsumerError::new("compile_binding"));
    }
    phases.push(phase(
        assignment.consumer_mode,
        "compile",
        elapsed_ms(compile_started),
    ));

    let explain_started = Instant::now();
    let (manifest, observation) = call_operation::<GetContextBundleManifestOperation>(
        &application,
        &errors,
        now,
        BundleIdRequest {
            bundle_id: bundle.bundle_id.clone(),
        },
        None,
    )
    .await?;
    tools.push(observation);
    verify_exact_manifest_entries(
        retriever.as_ref(),
        exact_authorization,
        catalog_revision,
        &manifest,
    )?;
    let (explanation, observation) = call_operation::<ExplainContextBundleOperation>(
        &application,
        &errors,
        now,
        ExplainContextBundleRequest {
            bundle_id: bundle.bundle_id.clone(),
            version_ids: Vec::new(),
        },
        Some("benchmark-explain-v1"),
    )
    .await?;
    tools.push(observation);
    phases.push(phase(
        assignment.consumer_mode,
        "explain",
        elapsed_ms(explain_started),
    ));

    let materialize_started = Instant::now();
    let (materialization, observation) = call_operation::<MaterializeContextBundleOperation>(
        &application,
        &errors,
        now,
        MaterializeContextBundleRequest {
            bundle_id: bundle.bundle_id.clone(),
            profile: MaterializationProfile::CanonicalJson,
        },
        Some("benchmark-materialize-v1"),
    )
    .await?;
    tools.push(observation);
    let output_digest = multihash(&materialization.context.bytes)?;
    phases.push(phase(
        assignment.consumer_mode,
        "materialize",
        elapsed_ms(materialize_started),
    ));

    let mut artifacts = core_artifacts(&plan_response.plan, &bundle, &manifest)?;
    artifacts.push(Artifact::canonical("explanation", &explanation)?);
    artifacts.push(Artifact::canonical(
        "materialization",
        &MaterializationMetadata {
            schema_version: "cigar.materialization-reference.v1",
            bundle_id: materialization.context.bundle_id.as_str(),
            media_type: materialization.context.media_type.as_str(),
            content_digest: output_digest.as_str(),
            byte_count: materialization.context.bytes.len(),
            physical_input_tokens: materialization.physical_input_tokens,
            tokenizer_fingerprint: materialization.context.tokenizer_fingerprint.as_str(),
            materializer_fingerprint: materialization.context.materializer_fingerprint.as_str(),
        },
    )?);

    let flow_started = Instant::now();
    let mut effect_replay = EffectReplay {
        handoffs: 0,
        effects: 0,
        unsafe_retries: 0,
        replay_dispatches: 0,
    };
    run_optional_flows(
        &assignment,
        &assignment_digest,
        &bundle,
        &output_digest,
        &consumer,
        &project_id,
        now,
        &mut artifacts,
        &mut effect_replay,
    )?;
    phases.push(phase(
        assignment.consumer_mode,
        "optional_flows",
        elapsed_ms(flow_started),
    ));

    let pins = Pins {
        catalog: ingestion.publication_digest,
        graph: graph_digest,
        index: descriptor.index_fingerprint,
        policy: policy_digest,
        planner,
        compiler,
        tokenizer: target.tokenizer_fingerprint,
        materializer,
        consumer,
        model: assignment.model.clone(),
        prompt: assignment.prompt_digest.clone(),
    };
    let mut body = body_prefix(&assignment, assignment_digest, pins);
    body.selected_blocks = selected_blocks(&bundle);
    body.dispositions = dispositions(&manifest);
    body.output_digest = output_digest;
    body.tool_observations = tools;
    body.phases = phases;
    body.artifacts = artifacts;
    body.resources = Resources {
        physical_input_tokens: materialization.physical_input_tokens,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        output_tokens: 0,
        latency_ms: normalized_duration(assignment.consumer_mode, elapsed_ms(total_started)),
        cpu_ms: 0,
        cpu_measured: false,
        peak_rss_bytes: 0,
        peak_rss_measured: false,
        cost_usd: 0,
    };
    body.effect_replay = effect_replay;
    Observation::seal(body)
}

async fn call_operation<O>(
    application: &Arc<Application>,
    errors: &Arc<dyn FacadeErrorFactory>,
    now: UtcTimestamp,
    payload: O::Request,
    idempotency_key: Option<&str>,
) -> Result<(O::Response, ToolObservation), ConsumerError>
where
    O: TypedOperation,
    Application: TypedUnaryService<O> + 'static,
{
    payload
        .validate_payload()
        .map_err(|_error| ConsumerError::new("operation_payload"))?;
    let request_bytes = canonical_json(&payload)?;
    let bindings = payload
        .path_bindings()
        .into_iter()
        .map(|(name, value)| {
            cigar_api::PathParameter::new(name, value)
                .map_err(|_error| ConsumerError::new("operation_path"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encoded = encode_operation_payload(&payload, MAX_OPERATION_PAYLOAD_BYTES)
        .map_err(|_error| ConsumerError::new("operation_encode"))?;
    let request = RequestEnvelope::new(
        O::OPERATION_ID,
        encoded,
        idempotency_key.map(str::to_owned),
        None,
        None,
        None,
        bindings,
    )
    .map_err(|_error| ConsumerError::new("operation_envelope"))?;
    let adapter = TypedUnaryAdapter::<O, _>::new(Arc::clone(application), Arc::clone(errors));
    let response = adapter
        .call(request_context(O::OPERATION_ID, now)?, request)
        .await
        .map_err(|error| ConsumerError::api(O::OPERATION_ID, error.code()))?;
    let payload: O::Response =
        decode_operation_payload(response.payload_cbor(), MAX_OPERATION_PAYLOAD_BYTES)
            .map_err(|_error| ConsumerError::new("operation_decode"))?;
    let response_bytes = canonical_json(&payload)?;
    Ok((
        payload,
        ToolObservation {
            tool: O::OPERATION_ID.to_owned(),
            request_digest: multihash(&request_bytes)?,
            response_digest: multihash(&response_bytes)?,
            exit_code: 0,
        },
    ))
}

fn read_catalog(
    store: &InMemoryStore,
    tenant_id: &RecordId,
) -> Result<
    (
        Vec<cigar_protocol::ContextAtomV1>,
        Vec<cigar_protocol::ContextEdge>,
        StoreRevision,
    ),
    ConsumerError,
> {
    let read = store
        .begin_read(
            AccessContext::new(tenant_id.clone(), "coding")
                .map_err(|_error| ConsumerError::new("catalog_access"))?,
            SnapshotSelection::Latest,
            StoreCancellationToken::default(),
        )
        .map_err(|_error| ConsumerError::new("catalog_read"))?;
    let revision = read.revision();
    let mut atoms = Vec::new();
    let mut cursor = None;
    loop {
        let page = read
            .query_atoms(AtomSelector::default(), 1_000, cursor.as_ref())
            .map_err(|_error| ConsumerError::new("catalog_query"))?;
        atoms.extend(page.items);
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    if atoms.is_empty() {
        return Err(ConsumerError::new("catalog_empty"));
    }
    let mut edges = Vec::new();
    for atom in &atoms {
        edges.extend(
            read.edges_from(&atom.version_id, None, 1_000)
                .map_err(|_error| ConsumerError::new("catalog_edges"))?,
        );
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    edges.dedup_by(|left, right| left.edge_id == right.edge_id);
    Ok((atoms, edges, revision))
}

fn verify_exact_manifest_entries(
    retriever: &dyn Retriever,
    authorization: cigar_policy::RetrievalAuthorization,
    revision: StoreRevision,
    manifest: &cigar_protocol::SelectionManifest,
) -> Result<(), ConsumerError> {
    let partition = AuthorizedPartition::from_policy_authorization(authorization)
        .map_err(|_error| ConsumerError::new("explain_partition"))?;
    for entry in &manifest.entries {
        let request = RetrievalRequest {
            stage: RetrievalStage::Exact,
            partition: partition.clone(),
            required_revision: revision,
            consistency: RetrievalConsistency::Strong,
            exact_versions: BTreeSet::from([entry.version_id.clone()]),
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
        let batch = retriever
            .retrieve(
                &request,
                &RetrievalContext {
                    cancellation: StoreCancellationToken::default(),
                    deadline: Instant::now() + Duration::from_secs(10),
                },
            )
            .map_err(|error| match error.code() {
                RetrievalErrorCode::InvalidMetadata => ConsumerError::new("explain_exact_invalid"),
                RetrievalErrorCode::LimitExceeded => ConsumerError::new("explain_exact_limit"),
                RetrievalErrorCode::Denied => ConsumerError::new("explain_exact_denied"),
                RetrievalErrorCode::IndexUnavailable => {
                    ConsumerError::new("explain_exact_unavailable")
                }
                RetrievalErrorCode::IndexStale => ConsumerError::new("explain_exact_stale"),
                RetrievalErrorCode::CorruptGeneration => {
                    ConsumerError::new("explain_exact_corrupt")
                }
                RetrievalErrorCode::Cancelled => ConsumerError::new("explain_exact_cancelled"),
                RetrievalErrorCode::DeadlineExceeded => {
                    ConsumerError::new("explain_exact_deadline")
                }
                RetrievalErrorCode::ChannelUnavailable => {
                    ConsumerError::new("explain_exact_channel")
                }
                RetrievalErrorCode::RequiredCandidateMissing => {
                    ConsumerError::new("explain_exact_missing")
                }
            })?;
        if batch.candidates.len() != 1
            || batch
                .candidates
                .first()
                .map(|candidate| &candidate.version_id)
                != Some(&entry.version_id)
        {
            return Err(ConsumerError::new("explain_exact_mismatch"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_optional_flows(
    assignment: &Assignment,
    assignment_digest: &ContentDigest,
    bundle: &cigar_protocol::ContextBundle,
    output_digest: &ContentDigest,
    consumer_digest: &ContentDigest,
    project_id: &RecordId,
    now: UtcTimestamp,
    artifacts: &mut Vec<Artifact>,
    facts: &mut EffectReplay,
) -> Result<(), ConsumerError> {
    if assignment.flows.handoff {
        let expires_at = UtcTimestamp::from_unix_nanos(
            now.unix_nanos()
                .checked_add(30_000_000_000)
                .ok_or_else(|| ConsumerError::new("handoff_time"))?,
        )
        .map_err(|_error| ConsumerError::new("handoff_time"))?;
        let authority_expires_at = UtcTimestamp::from_unix_nanos(
            now.unix_nanos()
                .checked_add(60_000_000_000)
                .ok_or_else(|| ConsumerError::new("handoff_time"))?,
        )
        .map_err(|_error| ConsumerError::new("handoff_time"))?;
        let source_versions: Vec<VersionId> = bundle
            .blocks
            .iter()
            .flat_map(|block| block.provenance.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let service = HandoffService::new(Arc::new(cigar_crypto::MemoryKeyProvider::default()));
        let preview = service
            .preview_creation(&CreateHandoffRequest {
                handoff_id: record(170)?,
                issuer_effective: EffectiveCapabilities {
                    tenant: "benchmark-tenant".to_owned(),
                    subject_id: record(171)?,
                    grant_id: record(172)?,
                    capabilities: BTreeSet::from([
                        Capability::CreateHandoff,
                        Capability::ReadContext,
                    ]),
                    project_ids: BTreeSet::from([project_id.clone()]),
                    processors: BTreeSet::from(["local".to_owned()]),
                    expires_at: authority_expires_at,
                },
                recipient: RecipientSelector::Principal(record(173)?),
                task: assignment.job_goal.clone(),
                acceptance_criteria: vec!["Use only typed references".to_owned()],
                requested_projects: BTreeSet::from([project_id.clone()]),
                requested_capabilities: BTreeSet::from([Capability::ReadContext]),
                policy_allowed_projects: BTreeSet::from([project_id.clone()]),
                policy_allowed_capabilities: BTreeSet::from([Capability::ReadContext]),
                budget: Budget {
                    total_input_tokens: assignment.token_budget,
                    output_reserve_tokens: assignment.output_reserve_tokens,
                    lane_input_tokens: BTreeMap::from([(
                        LaneKind::Evidence,
                        assignment.token_budget,
                    )]),
                },
                topics: BTreeSet::from([CoordinationTopic::BundleInvalidation]),
                references: HandoffReferences {
                    sources: source_versions,
                    states: Vec::new(),
                    decisions: Vec::new(),
                    artifacts: vec![bundle.bundle_id.clone()],
                    uncertainties: Vec::new(),
                    effects: Vec::new(),
                },
                bundle_id: bundle.bundle_id.clone(),
                audience: "cigarbench-recipient".to_owned(),
                created_at: now,
                expires_at,
                nonce: assignment_digest.as_str().as_bytes().to_vec(),
                reusable: false,
                issuer_key_ref: cigar_crypto::KeyRef::new("benchmark-handoff-key")
                    .map_err(|_error| ConsumerError::new("handoff_key"))?,
            })
            .map_err(|_error| ConsumerError::new("handoff_preview"))?;
        artifacts.push(Artifact::canonical("handoff", &preview)?);
        facts.handoffs = 1;
    }
    if assignment.flows.effect {
        let seed_text = assignment_digest
            .as_str()
            .get(4..20)
            .ok_or_else(|| ConsumerError::new("effect_seed"))?;
        let seed = u64::from_str_radix(seed_text, 16)
            .map_err(|_error| ConsumerError::new("effect_seed"))?;
        let report =
            run_fault_campaign(64, seed).map_err(|_error| ConsumerError::new("effect_campaign"))?;
        let artifact = EffectCampaignArtifact {
            schema_version: "cigar.effect-campaign-observation.v1",
            logical_effects: report.logical_effects(),
            possible_remote_commit_operations: report.possible_remote_commit_operations(),
            explicit_ambiguities: report.explicit_ambiguities(),
            duplicate_logical_effects: report.duplicate_logical_effects(),
            blind_redispatches: report.blind_redispatches(),
        };
        facts.effects = artifact.logical_effects;
        facts.unsafe_retries = artifact.blind_redispatches;
        artifacts.push(Artifact::canonical("effect", &artifact)?);
    }
    if assignment.flows.replay {
        let dimensions = ReplayDimensionDigests {
            semantic_context: Some(bundle.manifest_digest.clone()),
            materialization: Some(output_digest.clone()),
            components: Some(consumer_digest.clone()),
            output_claims: Some(output_digest.clone()),
            verification: Some(bundle.manifest_digest.clone()),
            effect_plan: Some(assignment_digest.clone()),
            observations: Some(assignment_digest.clone()),
        };
        let replay = compare_replay_dimensions(
            bundle.bundle_id.clone(),
            record(180)?,
            &dimensions,
            &dimensions,
        )
        .map_err(|_error| ConsumerError::new("replay_compare"))?;
        artifacts.push(Artifact::canonical("replay", &replay)?);
        facts.replay_dispatches = 1;
    }
    Ok(())
}

fn fixed_authorizer(
    tenant_id: &RecordId,
    principal_id: &RecordId,
    project_id: &RecordId,
    observed_at: UtcTimestamp,
) -> Result<Arc<FixedAuthorizer>, ConsumerError> {
    let policy = Arc::new(CompiledPolicyEngine::default());
    let snapshot = policy
        .install(
            PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            },
            observed_at,
        )
        .map_err(|_error| ConsumerError::new("policy_install"))?;
    let expires_at = UtcTimestamp::from_unix_nanos(
        observed_at
            .unix_nanos()
            .checked_add(60_000_000_000)
            .ok_or_else(|| ConsumerError::new("policy_time"))?,
    )
    .map_err(|_error| ConsumerError::new("policy_time"))?;
    let projects = BTreeSet::from([project_id.clone()]);
    let processors = BTreeSet::from(["local".to_owned()]);
    let policy_request = PolicyRequest {
        resource: PolicyResource::Partition,
        input_digest: multihash(b"cigar.benchmark.authorization.v1")?,
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
        lifecycle: cigar_protocol::Lifecycle::Active,
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
            grant_id: Some(record(190)?),
            capabilities: BTreeSet::from([Capability::CompileContext]),
            project_ids: projects.clone(),
            processors: processors.clone(),
            expires_at,
        }),
        required_capability: Some(Capability::CompileContext),
        bound_policy_digest: None,
        effect_risk: None,
        effect_approved: false,
        effect_constraints_satisfied: true,
        fencing_required: false,
        fencing_verified: false,
        decision_expires_at: expires_at,
    };
    let retrieval_authorization = policy
        .authorize_retrieval_partition(&[policy_request])
        .map_err(|_error| ConsumerError::new("policy_authorization"))?;
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

fn request_context(operation: &str, now: UtcTimestamp) -> Result<RequestContext, ConsumerError> {
    let deadline = UtcTimestamp::from_unix_nanos(
        now.unix_nanos()
            .checked_add(60_000_000_000)
            .ok_or_else(|| ConsumerError::new("request_deadline"))?,
    )
    .map_err(|_error| ConsumerError::new("request_deadline"))?;
    RequestContext::new(
        AuthenticatedIdentity::from_verified_credentials(
            TenantId::new("tenant-authenticated")
                .map_err(|_error| ConsumerError::new("request_identity"))?,
            PrincipalId::new("principal-authenticated")
                .map_err(|_error| ConsumerError::new("request_identity"))?,
        ),
        OperationId::new(operation).map_err(|_error| ConsumerError::new("request_operation"))?,
        deadline,
        TraceId::new("0123456789abcdef0123456789abcdef")
            .map_err(|_error| ConsumerError::new("request_trace"))?,
        CancellationToken::new(),
        now,
    )
    .map_err(|_error| ConsumerError::new("request_context"))
}

fn consumer_executable_digest() -> Result<ContentDigest, ConsumerError> {
    let executable =
        std::env::current_exe().map_err(|_error| ConsumerError::new("consumer_path"))?;
    let resolved = executable
        .canonicalize()
        .map_err(|_error| ConsumerError::new("consumer_path"))?;
    let metadata = std::fs::symlink_metadata(&resolved)
        .map_err(|_error| ConsumerError::new("consumer_path"))?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 * 1024 {
        return Err(ConsumerError::new("consumer_metadata"));
    }
    let mut bytes = Vec::new();
    File::open(resolved)
        .map_err(|_error| ConsumerError::new("consumer_open"))?
        .take(1024 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| ConsumerError::new("consumer_read"))?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 * 1024 {
        return Err(ConsumerError::new("consumer_metadata"));
    }
    multihash(&bytes)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn record(value: u64) -> Result<RecordId, ConsumerError> {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{value:012x}"))
        .map_err(|_error| ConsumerError::new("record_id"))
}

fn timestamp() -> Result<UtcTimestamp, ConsumerError> {
    UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")
        .map_err(|_error| ConsumerError::new("timestamp"))
}

#[cfg(test)]
mod tests {
    use cigar_api::generated::IdempotencyRequirement;
    use cigar_api::{ExplainContextBundleOperation, MaterializeContextBundleOperation};

    use super::*;

    #[test]
    fn mutation_shaped_read_flows_keep_required_idempotency_contracts() -> Result<(), ConsumerError>
    {
        for operation in [
            ExplainContextBundleOperation::OPERATION_ID,
            MaterializeContextBundleOperation::OPERATION_ID,
        ] {
            let contract = cigar_api::generated::operation_by_id(operation)
                .ok_or_else(|| ConsumerError::new("missing_test_contract"))?;
            assert_eq!(
                contract.idempotency_requirement,
                IdempotencyRequirement::Required
            );
        }
        let manifest =
            cigar_api::generated::operation_by_id(GetContextBundleManifestOperation::OPERATION_ID)
                .ok_or_else(|| ConsumerError::new("missing_test_contract"))?;
        assert_eq!(
            manifest.idempotency_requirement,
            IdempotencyRequirement::NotApplicable
        );
        Ok(())
    }
}
