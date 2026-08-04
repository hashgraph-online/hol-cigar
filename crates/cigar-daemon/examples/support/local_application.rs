//! Source-only fixtures for the private HUMIDOR local-application composition.

use cigar_canon::{
    SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1, to_normalized_json,
};
use cigar_crypto::EncryptedDevelopmentKeystore;
use cigar_daemon::{DurableReplayArchive, PROTECTED_EFFECT_ARGUMENT_MEDIA_TYPE};
use cigar_effects::reference::DemoIssueRequest;
use cigar_protocol::{
    BlobRef, ContentDigest, ContextBundle, ContextPlan, DecisionOutcome, DecisionRecord,
    DependencyKind, ExtensionMap, LaneKind, MaterializedContext, MediaType, PlanLane, RecordId,
    ReplayMode, SchemaVersion, SelectionManifest, UsageRecord, UtcTimestamp, VersionId,
};
use cigar_replay::{
    DecisionArtifact, DecisionCapture, DecisionCaptureBuilder, DecisionDependency,
    DependencyCapture, DependencyRole, InvocationCapture, InvocationEnvelope, ReplayArchive,
};
use cigar_store::{
    AccessContext, BlobRecord, CancellationToken, MultiTenantLocalRepositoryBlobStore, Repository,
    RepositoryBlobStore, ServiceRepository, SqliteStore, StoreRevision, WriteTransaction,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

const WORKFLOW_FAMILIES: [&str; 6] = [
    "code_review",
    "customer_escalation",
    "employee_onboarding",
    "executive_briefing",
    "marketing_campaign",
    "product_requirements_document",
];
const REFERENCE_TOKENIZER_FINGERPRINT: &str =
    "1220704360550f3e648c66e8333d6f68beccead8c630c31b640385e72bcaf3266657";
const REFERENCE_MATERIALIZER_FINGERPRINT: &str =
    "122083981b61c83d6bc05a42d6144519b39976958fabc5bba2cb4d815e2d93b5cc20";

/// Content-safe fixture bindings consumed by HUMIDOR through an owner-private file.
#[derive(Debug, Serialize)]
pub struct ApplicationFixture {
    pub schema_version: &'static str,
    pub source_id: RecordId,
    pub project_id: RecordId,
    pub principal_id: RecordId,
    pub query: &'static str,
    pub tokenizer_fingerprint: ContentDigest,
    pub materializer_fingerprint: ContentDigest,
    pub connector: &'static str,
    pub operation: &'static str,
    pub target: &'static str,
    pub arguments_digest: ContentDigest,
    pub encrypted_arguments: BlobRef,
    pub result_schema_digest: ContentDigest,
    pub workflow_replays: Vec<WorkflowReplayFixture>,
}

/// Exact observational replay decision assigned to one seeded HUMIDOR workflow family.
#[derive(Debug, Serialize)]
pub struct WorkflowReplayFixture {
    pub workflow_family: &'static str,
    pub decision_id: VersionId,
    pub bundle_id: VersionId,
}

/// Seed exact protected effect arguments and six immutable observational replay decisions.
pub fn provision(
    root: &Path,
    keystore: Arc<EncryptedDevelopmentKeystore>,
    tenant: RecordId,
    source_id: RecordId,
    project_id: RecordId,
    principal_id: RecordId,
    semantic_time: i128,
) -> Result<ApplicationFixture, Box<dyn Error>> {
    let state = root.join("state");
    let blob_repository = Arc::new(MultiTenantLocalRepositoryBlobStore::open(
        state.join("blobs"),
        state.join("blob-keys"),
        keystore,
        semantic_time,
    )?);
    let exposed_blobs: Arc<dyn RepositoryBlobStore> = blob_repository;
    let store = Arc::new(SqliteStore::open_with_blob_repository(
        state.join("cigar.sqlite3"),
        Arc::clone(&exposed_blobs),
    )?);

    let arguments = DemoIssueRequest::new(
        "humidor-seeded",
        "Synthetic HUMIDOR workflow",
        "Local-only deterministic effect used for reconciliation qualification.",
    )?;
    let argument_bytes = arguments.encode_protected_document()?;
    let encrypted_arguments = BlobRef {
        digest: raw_digest(&argument_bytes)?,
        size_bytes: u64::try_from(argument_bytes.len())?,
        media_type: MediaType::new(PROTECTED_EFFECT_ARGUMENT_MEDIA_TYPE)?,
    };
    let blob = BlobRecord::new(encrypted_arguments.clone(), argument_bytes)?;
    let mut transaction = store.begin_write(
        AccessContext::new(tenant.clone(), "local-application-bootstrap")?,
        StoreRevision(0),
        CancellationToken::default(),
    )?;
    transaction.put_blob(blob)?;
    transaction.commit(None)?;

    let service_repository: Arc<dyn ServiceRepository> = store;
    let archive = DurableReplayArchive::new(service_repository, tenant);
    let mut workflow_replays = Vec::with_capacity(WORKFLOW_FAMILIES.len());
    for (index, family) in WORKFLOW_FAMILIES.into_iter().enumerate() {
        let capture = capture_fixture(family, u64::try_from(index)?)?;
        workflow_replays.push(WorkflowReplayFixture {
            workflow_family: family,
            decision_id: capture.archive.decision.decision_id.clone(),
            bundle_id: capture.archive.decision.bundle_id.clone(),
        });
        archive.put_capture(&capture)?;
    }

    Ok(ApplicationFixture {
        schema_version: "cigar.local-application-fixture.v1",
        source_id,
        project_id,
        principal_id,
        query: "governed local context",
        tokenizer_fingerprint: ContentDigest::new(REFERENCE_TOKENIZER_FINGERPRINT)?,
        materializer_fingerprint: ContentDigest::new(REFERENCE_MATERIALIZER_FINGERPRINT)?,
        connector: "issues",
        operation: "create_issue",
        target: "humidor-seeded",
        arguments_digest: arguments.arguments_digest()?,
        encrypted_arguments,
        result_schema_digest: raw_digest(b"cigar.demo-issue-result.v1")?,
        workflow_replays,
    })
}

fn capture_fixture(family: &str, index: u64) -> Result<DecisionCapture, Box<dyn Error>> {
    let task_bytes = format!("HUMIDOR seeded {family} workflow").into_bytes();
    let contract_digest = raw_digest(format!("contract:{family}").as_bytes())?;
    let catalog_watermark = raw_digest(b"local-application-catalog")?;
    let plan = ContextPlan {
        schema_version: SchemaVersion::new("cigar.context-plan", 1)?,
        plan_id: record(100 + index)?,
        contract_digest: contract_digest.clone(),
        catalog_watermark: catalog_watermark.clone(),
        total_input_tokens: 1,
        lanes: vec![PlanLane {
            kind: LaneKind::Evidence,
            budget_tokens: 1,
            candidate_versions: Vec::new(),
        }],
        dispositions: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    let placeholder = VersionId::new(raw_digest(b"self-id-placeholder")?.as_str())?;
    let mut manifest = SelectionManifest {
        schema_version: SchemaVersion::new("cigar.selection-manifest", 1)?,
        manifest_id: placeholder.clone(),
        contract_digest: contract_digest.clone(),
        entries: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    manifest.manifest_id = VersionId::new(semantic_multihash_v1(
        SemanticEnvelopeProfile::Manifest,
        &manifest,
    )?)?;
    let mut bundle = ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)?,
        bundle_id: placeholder.clone(),
        contract_digest,
        manifest_digest: ContentDigest::new(manifest.manifest_id.as_str())?,
        blocks: Vec::new(),
        total_tokens: 0,
        extensions: ExtensionMap::default(),
    };
    bundle.bundle_id = VersionId::new(semantic_multihash_v1(
        SemanticEnvelopeProfile::Bundle,
        &bundle,
    )?)?;

    let runtime = raw_digest(b"humidor-local-runtime")?;
    let consumer = raw_digest(b"humidor-deterministic-model")?;
    let adapter = raw_digest(b"humidor-cigar-adapter")?;
    let tokenizer = raw_digest(b"cigar-local-tokenizer")?;
    let materializer = raw_digest(b"cigar-local-materializer")?;
    let materialized_bytes = format!("provider-ready {family} context").into_bytes();
    let materialization_digest = raw_digest(&materialized_bytes)?;
    let materialization = MaterializedContext {
        schema_version: SchemaVersion::new("cigar.materialized-context", 1)?,
        bundle_id: bundle.bundle_id.clone(),
        media_type: MediaType::new("text/plain")?,
        bytes: materialized_bytes,
        token_count: 1,
        tokenizer_fingerprint: tokenizer,
        materializer_fingerprint: materializer,
    };
    let usage = UsageRecord {
        input_tokens: 1,
        output_tokens: 1,
        cached_input_tokens: 0,
        cost_micros: 0,
    };
    let invocation_bytes = format!("deterministic invocation for {family}").into_bytes();
    let parameter_bytes = b"{}".to_vec();
    let invocation = InvocationCapture::new(
        InvocationEnvelope {
            schema_version: SchemaVersion::new("cigar.invocation-envelope", 1)?,
            input_digest: raw_digest(&invocation_bytes)?,
            materialization_digest: materialization_digest.clone(),
            runtime_fingerprint: runtime.clone(),
            consumer_fingerprint: consumer.clone(),
            adapter_fingerprint: adapter,
            parameters_digest: raw_digest(&parameter_bytes)?,
            tool_schema_digests: Vec::new(),
            environment_digests: Vec::new(),
            effect_ids: Vec::new(),
            usage,
        },
        invocation_bytes,
        parameter_bytes,
    )?;
    let decision = DecisionRecord {
        schema_version: SchemaVersion::new("cigar.decision-record", 1)?,
        decision_id: placeholder,
        task_digest: raw_digest(&task_bytes)?,
        plan_id: plan.plan_id.clone(),
        plan_digest: raw_digest(&canonical_json(&plan)?)?,
        bundle_id: bundle.bundle_id.clone(),
        materialization_digest,
        runtime_fingerprint: runtime,
        consumer_fingerprint: consumer,
        output_artifacts: Vec::new(),
        asserted_claims: Vec::new(),
        evidence: Vec::new(),
        uncertainty: Vec::new(),
        verification_receipts: Vec::new(),
        effects: Vec::new(),
        usage,
        started_at: UtcTimestamp::parse_rfc3339("2026-07-30T00:00:00Z")?,
        completed_at: UtcTimestamp::parse_rfc3339("2026-07-30T00:00:01Z")?,
        outcome: DecisionOutcome::Succeeded,
        extensions: ExtensionMap::default(),
    };
    Ok(DecisionCaptureBuilder::new(
        decision,
        task_bytes,
        plan,
        manifest,
        bundle,
        materialization,
        invocation,
    )
    .with_dependency(component(
        DependencyRole::Consumer,
        DependencyKind::Consumer,
        b"humidor-deterministic-model",
    )?)
    .with_dependency(component(
        DependencyRole::Adapter,
        DependencyKind::Adapter,
        b"humidor-cigar-adapter",
    )?)
    .with_dependency(component(
        DependencyRole::Tokenizer,
        DependencyKind::Tokenizer,
        b"cigar-local-tokenizer",
    )?)
    .with_dependency(component(
        DependencyRole::Materializer,
        DependencyKind::Adapter,
        b"cigar-local-materializer",
    )?)
    .with_dependency(component(
        DependencyRole::Runtime,
        DependencyKind::Environment,
        b"humidor-local-runtime",
    )?)
    .with_dependency(evidence(
        DependencyRole::Policy,
        DependencyKind::Policy,
        b"local-application-policy",
        None,
    )?)
    .with_dependency(evidence(
        DependencyRole::Index,
        DependencyKind::Index,
        b"local-application-index",
        Some(catalog_watermark),
    )?)
    .seal()?)
}

fn component(
    role: DependencyRole,
    kind: DependencyKind,
    bytes: &[u8],
) -> Result<DependencyCapture, Box<dyn Error>> {
    let artifact =
        DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes.to_vec())?;
    Ok(DependencyCapture::new(
        DecisionDependency {
            kind,
            role,
            content_digest: artifact.content_digest.clone(),
            semantic_id: None,
            record_id: None,
            fingerprint: Some(artifact.content_digest.clone()),
            required_modes: modes(&[
                ReplayMode::EvidenceReproduction,
                ReplayMode::InvocationReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]),
        },
        artifact,
    )?)
}

fn evidence(
    role: DependencyRole,
    kind: DependencyKind,
    bytes: &[u8],
    fingerprint: Option<ContentDigest>,
) -> Result<DependencyCapture, Box<dyn Error>> {
    let artifact =
        DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes.to_vec())?;
    Ok(DependencyCapture::new(
        DecisionDependency {
            kind,
            role,
            content_digest: artifact.content_digest.clone(),
            semantic_id: None,
            record_id: None,
            fingerprint,
            required_modes: modes(&[
                ReplayMode::EvidenceReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]),
        },
        artifact,
    )?)
}

fn modes(values: &[ReplayMode]) -> BTreeSet<ReplayMode> {
    values.iter().copied().collect()
}

fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn raw_digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let mut encoded = String::from("1220");
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let json = serde_json::to_vec(value)?;
    Ok(to_normalized_json(&parse_strict_json(&json)?)?)
}
