//! FULL-200 qualification for every non-vector retrieval channel and selector boundary.

use cigar_policy::{
    CapabilityContext, CompiledPolicyEngine, PolicyProfile, PolicyRequest, PolicyResource,
};
use cigar_protocol::{
    AtomKind, AtomPayload, Capability, Classification, ContentDigest, ContextAtomV1, ContextEdge,
    ContextRequirement, InstructionAuthority, Lifecycle, LineageId, RecordId, RelativePath,
    SourceUri, UtcTimestamp, VersionId,
};
use cigar_retrieval::{
    AuthorizedPartition, InMemoryIndexManager, IndexBuild, MatchEvidence, QueryPlanner,
    RetrievalConsistency, RetrievalContext, RetrievalErrorCode, RetrievalRequest, RetrievalStage,
    Retriever, StagedRetrieval,
};
use cigar_store::{CancellationToken, StoreRevision};
use cigar_testkit::deterministic_protocol_fixture;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct AuthorizationFixture {
    partition: AuthorizedPartition,
    _engine: Arc<CompiledPolicyEngine>,
}

fn timestamp(value: &str) -> Result<UtcTimestamp, Box<dyn Error>> {
    Ok(UtcTimestamp::parse_rfc3339(value)?)
}

fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        format!("{value:02x}").repeat(32)
    ))?)
}

fn version(value: u8) -> Result<VersionId, Box<dyn Error>> {
    Ok(VersionId::new(digest(value)?.as_str())?)
}

fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
    ))?)
}

fn authorization(
    tenant_id: &RecordId,
    project_id: &RecordId,
) -> Result<AuthorizationFixture, Box<dyn Error>> {
    let engine = Arc::new(CompiledPolicyEngine::default());
    let now = timestamp("2026-07-10T00:00:05Z")?;
    let expires_at = timestamp("2026-07-10T00:01:05Z")?;
    engine.install(
        PolicyProfile {
            schema_version: "cigar.policy-profile.v1".to_owned(),
            revision: 1,
            protected: true,
            rules: Vec::new(),
        },
        now,
    )?;
    let principal_id = record(900)?;
    let project_ids = BTreeSet::from([project_id.clone()]);
    let allowed_processors = BTreeSet::from(["local".to_owned()]);
    let allowed_purposes = BTreeSet::from(["coding".to_owned()]);
    let capabilities = BTreeSet::from([Capability::ReadContext]);
    let authorization = engine.authorize_retrieval_partition(&[PolicyRequest {
        resource: PolicyResource::Partition,
        input_digest: digest(200)?,
        principal_id: principal_id.clone(),
        principal_active: true,
        tenant_id: tenant_id.clone(),
        authenticated_tenant_id: tenant_id.clone(),
        project_id: Some(project_id.clone()),
        allowed_project_ids: project_ids.clone(),
        purpose: "coding".to_owned(),
        allowed_purposes,
        processor: Some("local".to_owned()),
        allowed_processors: allowed_processors.clone(),
        classification: Classification::Public,
        maximum_classification: Classification::Internal,
        residency_allowed: true,
        egress_allowed: true,
        lifecycle: Lifecycle::Active,
        integrity_verified: true,
        valid_at: now,
        valid_from: now,
        valid_until: Some(expires_at),
        observed_at: now,
        observed_as_of: now,
        freshness_expires_at: None,
        instruction_authority: InstructionAuthority::Data,
        maximum_instruction_authority: InstructionAuthority::Data,
        excluded: false,
        modality_supported: true,
        capability: Some(CapabilityContext {
            subject_id: principal_id,
            grant_id: Some(record(901)?),
            capabilities: capabilities.clone(),
            project_ids,
            processors: allowed_processors,
            expires_at,
        }),
        required_capability: Some(Capability::ReadContext),
        bound_policy_digest: None,
        effect_risk: None,
        effect_approved: false,
        effect_constraints_satisfied: true,
        fencing_required: false,
        fencing_verified: false,
        decision_expires_at: expires_at,
    }])?;
    Ok(AuthorizationFixture {
        partition: AuthorizedPartition::from_policy_authorization(authorization)?,
        _engine: engine,
    })
}

fn atom(
    value: u8,
    tenant: &RecordId,
    project: &RecordId,
    path: &str,
    revision: &str,
    text: &str,
    terms: &[&str],
) -> Result<ContextAtomV1, Box<dyn Error>> {
    let fixture = deterministic_protocol_fixture("ContextAtomV1")
        .ok_or("missing deterministic ContextAtomV1 fixture")?;
    let mut atom: ContextAtomV1 = serde_json::from_value(fixture.input)?;
    atom.atom_id = record(u16::from(value) + 100)?;
    atom.lineage_id = LineageId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"))?;
    atom.version_id = version(value)?;
    atom.content_digest = digest(value.saturating_add(64))?;
    atom.payload = AtomPayload::InlineText(text.to_owned());
    atom.source.uri = SourceUri::new(format!("file:///qualified/{path}"))?;
    atom.source.relative_path = Some(RelativePath::new(path.as_bytes().to_vec())?);
    atom.source.revision = revision.to_owned();
    atom.scope.tenant_id = tenant.clone();
    atom.scope.project_ids = vec![project.clone()];
    atom.temporal.valid_from = timestamp("2026-07-10T00:00:00Z")?;
    atom.temporal.valid_until = None;
    atom.temporal.observed_at = timestamp("2026-07-10T00:00:01Z")?;
    atom.governance.allowed_purposes = vec!["coding".to_owned()];
    atom.governance.processor_constraints = vec!["local".to_owned()];
    atom.governance.classification = Classification::Internal;
    atom.governance.instruction_authority = InstructionAuthority::Data;
    atom.retrieval.lexical_enabled = true;
    atom.retrieval.exact_terms = terms.iter().map(|term| (*term).to_owned()).collect();
    atom.retrieval.exact_terms.sort();
    atom.retrieval.exact_terms.dedup();
    atom.lifecycle = Lifecycle::Active;
    Ok(atom)
}

fn edge(value: u16, from: &VersionId, to: &VersionId) -> Result<ContextEdge, Box<dyn Error>> {
    let fixture = deterministic_protocol_fixture("ContextEdge")
        .ok_or("missing deterministic ContextEdge fixture")?;
    let mut edge: ContextEdge = serde_json::from_value(fixture.input)?;
    edge.edge_id = record(value + 500)?;
    edge.from_version = from.clone();
    edge.to_version = to.clone();
    edge.lifecycle = Lifecycle::Active;
    Ok(edge)
}

fn context() -> RetrievalContext {
    RetrievalContext {
        cancellation: CancellationToken::default(),
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

fn request(stage: RetrievalStage, partition: &AuthorizedPartition) -> RetrievalRequest {
    RetrievalRequest {
        stage,
        partition: partition.clone(),
        required_revision: StoreRevision(17),
        consistency: RetrievalConsistency::Strong,
        atom_kinds: BTreeSet::new(),
        exact_versions: BTreeSet::new(),
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
        limit: 100,
        allow_fallback: false,
    }
}

fn build(atoms: Vec<ContextAtomV1>, edges: Vec<ContextEdge>) -> Result<IndexBuild, Box<dyn Error>> {
    let tenant_watermarks: BTreeMap<_, _> = atoms
        .iter()
        .map(|atom| (atom.scope.tenant_id.clone(), StoreRevision(17)))
        .collect();
    Ok(IndexBuild {
        atoms,
        edges,
        built_through_revision: StoreRevision(17),
        tenant_watermarks,
        configuration_digest: digest(240)?,
        verified_at: timestamp("2026-07-10T00:00:06Z")?,
        vector_binding: None,
    })
}

fn candidate_versions(
    manager: &InMemoryIndexManager,
    request: &RetrievalRequest,
) -> Result<BTreeSet<VersionId>, Box<dyn Error>> {
    Ok(manager
        .retrieve(request, &context())?
        .candidates
        .into_iter()
        .map(|candidate| candidate.version_id)
        .collect())
}

#[test]
fn exact_metadata_lexical_graph_temporal_authority_and_active_state_are_qualified()
-> Result<(), Box<dyn Error>> {
    let tenant = record(1)?;
    let project = record(2)?;
    let authority = authorization(&tenant, &project)?;
    let mut alpha = atom(
        1,
        &tenant,
        &project,
        "src/alpha.rs",
        "revision-alpha",
        "LexicalNeedle alpha implementation",
        &["symbol::alpha", "entity:customer"],
    )?;
    alpha.kind = AtomKind::SourceCode;
    let mut beta = atom(
        2,
        &tenant,
        &project,
        "docs/beta.md",
        "revision-beta",
        "connected beta documentation",
        &["symbol::beta", "entity:order"],
    )?;
    beta.kind = AtomKind::Documentation;
    let mut future = atom(
        3,
        &tenant,
        &project,
        "future.md",
        "revision-future",
        "LexicalNeedle future",
        &["symbol::future"],
    )?;
    future.temporal.valid_from = timestamp("2026-07-11T00:00:00Z")?;
    future.temporal.observed_at = timestamp("2026-07-11T00:00:01Z")?;
    let mut system = atom(
        4,
        &tenant,
        &project,
        "system.md",
        "revision-system",
        "LexicalNeedle system",
        &["symbol::system"],
    )?;
    system.governance.instruction_authority = InstructionAuthority::System;
    let mut tombstone = atom(
        5,
        &tenant,
        &project,
        "deleted.md",
        "revision-deleted",
        "LexicalNeedle deleted",
        &["symbol::deleted"],
    )?;
    tombstone.lifecycle = Lifecycle::Tombstoned;

    let graph_edge = edge(1, &alpha.version_id, &beta.version_id)?;
    let manager = InMemoryIndexManager::default();
    let generation = manager.build_generation(
        build(
            vec![alpha.clone(), beta.clone(), future, system, tombstone],
            vec![graph_edge],
        )?,
        &context(),
    )?;
    manager.activate(&generation.generation_id, None)?;

    let expected_alpha = BTreeSet::from([alpha.version_id.clone()]);
    let mut exact_requests = Vec::new();
    let mut by_version = request(RetrievalStage::Exact, &authority.partition);
    by_version.exact_versions.insert(alpha.version_id.clone());
    exact_requests.push(by_version);
    let mut by_atom = request(RetrievalStage::Exact, &authority.partition);
    by_atom.atom_ids.insert(alpha.atom_id.clone());
    exact_requests.push(by_atom);
    let mut by_lineage = request(RetrievalStage::Exact, &authority.partition);
    by_lineage.lineage_ids.insert(alpha.lineage_id.clone());
    exact_requests.push(by_lineage);
    let mut by_digest = request(RetrievalStage::Exact, &authority.partition);
    by_digest
        .content_digests
        .insert(alpha.content_digest.clone());
    exact_requests.push(by_digest);
    let mut by_uri = request(RetrievalStage::Exact, &authority.partition);
    by_uri.canonical_uris.insert(alpha.source.uri.clone());
    exact_requests.push(by_uri);
    let mut by_revision = request(RetrievalStage::Exact, &authority.partition);
    by_revision
        .source_revisions
        .insert(alpha.source.revision.clone());
    exact_requests.push(by_revision);
    for exact in &exact_requests {
        assert_eq!(candidate_versions(&manager, exact)?, expected_alpha);
    }

    let mut path = request(RetrievalStage::Metadata, &authority.partition);
    path.paths
        .insert(alpha.source.relative_path.clone().ok_or("missing path")?);
    assert_eq!(candidate_versions(&manager, &path)?, expected_alpha);

    for declared_term in ["symbol::alpha", "entity:customer"] {
        let mut metadata = request(RetrievalStage::Metadata, &authority.partition);
        metadata.terms.insert(declared_term.to_owned());
        let batch = manager.retrieve(&metadata, &context())?;
        assert_eq!(
            batch
                .candidates
                .iter()
                .map(|candidate| candidate.version_id.clone())
                .collect::<BTreeSet<_>>(),
            expected_alpha
        );
        assert!(
            batch
                .candidates
                .first()
                .ok_or("declared-term retrieval omitted its candidate")?
                .evidence
                .contains(&MatchEvidence::DeclaredTerm)
        );
    }

    let mut lexical = request(RetrievalStage::Lexical, &authority.partition);
    lexical.terms.insert("lexicalneedle".to_owned());
    assert_eq!(candidate_versions(&manager, &lexical)?, expected_alpha);

    let mut kind_scoped = request(RetrievalStage::Lexical, &authority.partition);
    kind_scoped.atom_kinds.insert(AtomKind::Documentation);
    kind_scoped.terms.insert("connected".to_owned());
    kind_scoped.terms.insert("lexicalneedle".to_owned());
    kind_scoped.limit = 1;
    assert_eq!(
        candidate_versions(&manager, &kind_scoped)?,
        BTreeSet::from([beta.version_id.clone()]),
        "semantic kind scope must be applied before channel ranking and caps"
    );

    let augment = request(RetrievalStage::Augment, &authority.partition);
    assert_eq!(
        candidate_versions(&manager, &augment)?,
        BTreeSet::from([alpha.version_id.clone(), beta.version_id.clone()]),
        "future, over-authority, and inactive records must not survive augmentation"
    );

    let mut graph = request(RetrievalStage::Graph, &authority.partition);
    graph.graph_roots.insert(alpha.version_id.clone());
    graph.graph_depth = 1;
    assert_eq!(
        candidate_versions(&manager, &graph)?,
        BTreeSet::from([alpha.version_id, beta.version_id])
    );
    Ok(())
}

#[test]
fn selector_shapes_and_blocking_absence_fail_instead_of_degrading() -> Result<(), Box<dyn Error>> {
    let tenant = record(10)?;
    let project = record(11)?;
    let authority = authorization(&tenant, &project)?;
    let invalid = [
        request(RetrievalStage::Exact, &authority.partition),
        request(RetrievalStage::Metadata, &authority.partition),
        request(RetrievalStage::Lexical, &authority.partition),
        request(RetrievalStage::Graph, &authority.partition),
    ];
    for request in invalid {
        assert_eq!(
            request.validate().map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );
    }

    let mut exact_with_query = request(RetrievalStage::Exact, &authority.partition);
    exact_with_query.exact_versions.insert(version(90)?);
    exact_with_query.terms.insert("wrong-channel".to_owned());
    assert_eq!(
        exact_with_query.validate().map_err(|error| error.code()),
        Err(RetrievalErrorCode::InvalidMetadata)
    );
    let mut graph_with_query = request(RetrievalStage::Graph, &authority.partition);
    graph_with_query.graph_roots.insert(version(90)?);
    graph_with_query.terms.insert("wrong-channel".to_owned());
    assert_eq!(
        graph_with_query.validate().map_err(|error| error.code()),
        Err(RetrievalErrorCode::InvalidMetadata)
    );
    let mut broad_augment = request(RetrievalStage::Augment, &authority.partition);
    broad_augment
        .paths
        .insert(RelativePath::new(b"secret".to_vec())?);
    assert_eq!(
        broad_augment.validate().map_err(|error| error.code()),
        Err(RetrievalErrorCode::InvalidMetadata)
    );

    let manager = InMemoryIndexManager::default();
    let unrelated = atom(
        10,
        &tenant,
        &project,
        "unrelated.md",
        "revision-unrelated",
        "unrelated",
        &["symbol::unrelated"],
    )?;
    let generation = manager.build_generation(build(vec![unrelated], Vec::new())?, &context())?;
    manager.activate(&generation.generation_id, None)?;
    let exact_requirement: ContextRequirement = serde_json::from_value(serde_json::json!({
        "semantic_type": "documentation",
        "selector": {"type": "exact", "value": version(91)?.as_str()},
        "minimum_authority": 1,
        "minimum_coverage": 0,
        "blocking": true
    }))?;
    let plan = QueryPlanner::default().plan(
        &[exact_requirement],
        &authority.partition,
        StoreRevision(17),
        RetrievalConsistency::Strong,
        false,
    )?;
    assert_eq!(
        StagedRetrieval
            .execute(&plan, &manager, &context())
            .map_err(|error| error.code()),
        Err(RetrievalErrorCode::RequiredCandidateMissing)
    );
    Ok(())
}

#[test]
fn non_vector_results_survive_input_order_and_generation_rebuild() -> Result<(), Box<dyn Error>> {
    let tenant = record(20)?;
    let project = record(21)?;
    let authority = authorization(&tenant, &project)?;
    let alpha = atom(
        20,
        &tenant,
        &project,
        "src/alpha.rs",
        "revision-alpha",
        "stable retrieval",
        &["symbol::stable"],
    )?;
    let beta = atom(
        21,
        &tenant,
        &project,
        "src/beta.rs",
        "revision-beta",
        "stable retrieval",
        &["entity:stable"],
    )?;
    let connection = edge(20, &alpha.version_id, &beta.version_id)?;

    let first = InMemoryIndexManager::default();
    let first_generation = first.build_generation(
        build(vec![alpha.clone(), beta.clone()], vec![connection.clone()])?,
        &context(),
    )?;
    first.activate(&first_generation.generation_id, None)?;

    let second = InMemoryIndexManager::default();
    let second_generation =
        second.build_generation(build(vec![beta, alpha], vec![connection])?, &context())?;
    second.activate(&second_generation.generation_id, None)?;
    assert_eq!(
        first_generation.semantic_root,
        second_generation.semantic_root
    );
    assert_eq!(
        first_generation.index_fingerprint,
        second_generation.index_fingerprint
    );

    let mut lexical = request(RetrievalStage::Lexical, &authority.partition);
    lexical.terms.insert("stable".to_owned());
    assert_eq!(
        first.retrieve(&lexical, &context())?,
        second.retrieve(&lexical, &context())?
    );
    Ok(())
}
