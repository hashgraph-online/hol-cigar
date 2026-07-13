//! WP13 adversarial coverage for exact decision-capture provenance and typed artifacts.

use cigar_canon::{
    SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1, to_normalized_json,
};
use cigar_protocol::{
    BlobRef, CandidateDisposition, Capability, ContentDigest, ContextBlock, ContextBundle,
    ContextPlan, DecisionOutcome, DecisionRecord, DependencyKind, EffectIntent, ExtensionMap,
    FixedPoint, IdempotencyKey, LaneKind, ManifestEntry, MaterializedContext, MediaType, PlanLane,
    RecordId, ReplayMode, RepresentationKind, RetryPolicy, RiskLevel, SchemaVersion,
    SelectionManifest, UsageRecord, UtcTimestamp, VersionId,
};
use cigar_replay::{
    DecisionArtifact, DecisionCapture, DecisionCaptureBuilder, DecisionDependency,
    DependencyCapture, DependencyRole, InvocationCapture, InvocationEnvelope,
    ReplayFoundationError,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Default)]
enum SourceCase {
    #[default]
    Exact,
    Missing,
    SemanticMismatch,
}

#[derive(Clone, Copy, Default)]
enum IndexCase {
    #[default]
    Exact,
    Missing,
    WatermarkMismatch,
}

#[derive(Clone, Copy, Default)]
enum EffectCase {
    #[default]
    None,
    Exact,
    ArbitraryBytes,
    RecordIdMismatch,
    BundleMismatch,
}

#[derive(Clone, Copy, Default)]
enum OutputCase {
    #[default]
    None,
    Exact,
    SemanticMismatch,
}

#[derive(Clone, Copy, Default)]
enum ComponentCase {
    #[default]
    Absent,
    Exact,
    Empty,
    InvocationMismatch,
}

#[derive(Clone, Copy)]
struct Options {
    source: SourceCase,
    policy: bool,
    index: IndexCase,
    effect: EffectCase,
    output: OutputCase,
    tool: ComponentCase,
    environment: ComponentCase,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            source: SourceCase::Exact,
            policy: true,
            index: IndexCase::Exact,
            effect: EffectCase::None,
            output: OutputCase::None,
            tool: ComponentCase::Absent,
            environment: ComponentCase::Absent,
        }
    }
}

#[test]
fn selected_manifest_and_bundle_require_exact_source_semantics() -> TestResult {
    let valid = capture(Options::default())??;
    valid.validate()?;

    assert_rejected(capture(Options {
        source: SourceCase::Missing,
        ..Options::default()
    })?);
    assert_rejected(capture(Options {
        source: SourceCase::SemanticMismatch,
        ..Options::default()
    })?);
    Ok(())
}

#[test]
fn policy_and_index_are_mandatory_and_index_binds_catalog_watermark() -> TestResult {
    assert_rejected(capture(Options {
        policy: false,
        ..Options::default()
    })?);
    assert_rejected(capture(Options {
        index: IndexCase::Missing,
        ..Options::default()
    })?);
    assert_rejected(capture(Options {
        index: IndexCase::WatermarkMismatch,
        ..Options::default()
    })?);
    Ok(())
}

#[test]
fn effect_artifact_requires_canonical_intent_id_and_bundle_binding() -> TestResult {
    let valid = capture(Options {
        effect: EffectCase::Exact,
        ..Options::default()
    })??;
    valid.validate()?;

    for effect in [
        EffectCase::ArbitraryBytes,
        EffectCase::RecordIdMismatch,
        EffectCase::BundleMismatch,
    ] {
        assert_rejected(capture(Options {
            effect,
            ..Options::default()
        })?);
    }
    Ok(())
}

#[test]
fn output_artifact_semantic_id_is_its_exact_raw_multihash() -> TestResult {
    let valid = capture(Options {
        output: OutputCase::Exact,
        ..Options::default()
    })??;
    let output = dependency(&valid, DependencyRole::OutputArtifact)?;
    assert_eq!(
        output.semantic_id.as_ref().map(VersionId::as_str),
        Some(output.content_digest.as_str())
    );

    assert_rejected(capture(Options {
        output: OutputCase::SemanticMismatch,
        ..Options::default()
    })?);
    Ok(())
}

#[test]
fn tool_and_environment_artifacts_are_nonempty_and_fingerprint_bound() -> TestResult {
    let valid = capture(Options {
        tool: ComponentCase::Exact,
        environment: ComponentCase::Exact,
        ..Options::default()
    })??;
    valid.validate()?;

    for (tool, environment) in [
        (ComponentCase::Empty, ComponentCase::Exact),
        (ComponentCase::Exact, ComponentCase::Empty),
        (ComponentCase::InvocationMismatch, ComponentCase::Exact),
        (ComponentCase::Exact, ComponentCase::InvocationMismatch),
    ] {
        assert_rejected(capture(Options {
            tool,
            environment,
            ..Options::default()
        })?);
    }

    assert_component_fingerprint_mismatch_rejected(
        DependencyRole::ToolSchema,
        DependencyKind::ToolSchema,
    )?;
    assert_component_fingerprint_mismatch_rejected(
        DependencyRole::Environment,
        DependencyKind::Environment,
    )?;
    Ok(())
}

fn capture(options: Options) -> TestResult<Result<DecisionCapture, ReplayFoundationError>> {
    let task_bytes = b"capture integrity task".to_vec();
    let source_bytes = b"exact selected source bytes";
    let selected_source = version(b"selected source semantic version")?;
    let contract_digest = raw_digest(b"capture contract")?;
    let catalog_watermark = raw_digest(b"catalog watermark")?;
    let selected = CandidateDisposition::Selected {
        lane: LaneKind::Evidence,
        score: FixedPoint::new(900_000)?,
    };
    let plan = ContextPlan {
        schema_version: SchemaVersion::new("cigar.context-plan", 1)?,
        plan_id: record(1)?,
        contract_digest: contract_digest.clone(),
        catalog_watermark: catalog_watermark.clone(),
        total_input_tokens: 1,
        lanes: vec![PlanLane {
            kind: LaneKind::Evidence,
            budget_tokens: 1,
            candidate_versions: vec![selected_source.clone()],
        }],
        dispositions: vec![(selected_source.clone(), selected.clone())],
        extensions: ExtensionMap::default(),
    };
    let placeholder = version(b"placeholder")?;
    let mut manifest = SelectionManifest {
        schema_version: SchemaVersion::new("cigar.selection-manifest", 1)?,
        manifest_id: placeholder.clone(),
        contract_digest: contract_digest.clone(),
        entries: vec![ManifestEntry {
            version_id: selected_source.clone(),
            disposition: selected,
            reason_codes: Vec::new(),
            provenance_digest: raw_digest(b"source provenance")?,
        }],
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
        blocks: vec![ContextBlock {
            block_id: version(b"selected context block")?,
            lane: LaneKind::Evidence,
            representation: RepresentationKind::Exact,
            content_digest: raw_digest(source_bytes)?,
            token_count: 1,
            provenance: vec![selected_source.clone()],
            transform_receipt: None,
        }],
        total_tokens: 1,
        extensions: ExtensionMap::default(),
    };
    bundle.bundle_id = VersionId::new(semantic_multihash_v1(
        SemanticEnvelopeProfile::Bundle,
        &bundle,
    )?)?;

    let runtime = raw_digest(b"runtime implementation")?;
    let consumer = raw_digest(b"consumer implementation")?;
    let adapter = raw_digest(b"adapter implementation")?;
    let tokenizer = raw_digest(b"tokenizer implementation")?;
    let materializer = raw_digest(b"materializer implementation")?;
    let materialized_bytes = b"provider-ready context".to_vec();
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

    let tool = component_input(
        DependencyRole::ToolSchema,
        DependencyKind::ToolSchema,
        options.tool,
        b"tool schema",
        b"different tool schema",
    )?;
    let environment = component_input(
        DependencyRole::Environment,
        DependencyKind::Environment,
        options.environment,
        b"environment descriptor",
        b"different environment descriptor",
    )?;
    let tool_schema_digests = tool
        .as_ref()
        .map(|input| vec![input.invocation_fingerprint.clone()])
        .unwrap_or_default();
    let environment_digests = environment
        .as_ref()
        .map(|input| vec![input.invocation_fingerprint.clone()])
        .unwrap_or_default();

    let effect = effect_input(options.effect, &bundle.bundle_id)?;
    let effect_ids = effect
        .as_ref()
        .map(|input| vec![input.decision_id.clone()])
        .unwrap_or_default();
    let output = output_input(options.output)?;
    let output_artifacts = output
        .as_ref()
        .map(|input| vec![input.semantic_id.clone()])
        .unwrap_or_default();
    let usage = UsageRecord {
        input_tokens: 1,
        output_tokens: 1,
        cached_input_tokens: 0,
        cost_micros: 0,
    };
    let invocation_bytes = b"exact invocation input".to_vec();
    let parameter_bytes = b"{}".to_vec();
    let invocation = InvocationCapture::new(
        InvocationEnvelope {
            schema_version: SchemaVersion::new("cigar.invocation-envelope", 1)?,
            input_digest: raw_digest(&invocation_bytes)?,
            materialization_digest: materialization_digest.clone(),
            runtime_fingerprint: runtime.clone(),
            consumer_fingerprint: consumer.clone(),
            adapter_fingerprint: adapter.clone(),
            parameters_digest: raw_digest(&parameter_bytes)?,
            tool_schema_digests,
            environment_digests,
            effect_ids: effect_ids.clone(),
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
        output_artifacts,
        asserted_claims: Vec::new(),
        evidence: Vec::new(),
        uncertainty: Vec::new(),
        verification_receipts: Vec::new(),
        effects: effect_ids,
        usage,
        started_at: time(1)?,
        completed_at: time(2)?,
        outcome: DecisionOutcome::Succeeded,
        extensions: ExtensionMap::default(),
    };

    let mut builder = DecisionCaptureBuilder::new(
        decision,
        task_bytes,
        plan,
        manifest,
        bundle,
        materialization,
        invocation,
    );
    for dependency in [
        component(
            DependencyRole::Consumer,
            DependencyKind::Consumer,
            b"consumer implementation",
        )?,
        component(
            DependencyRole::Adapter,
            DependencyKind::Adapter,
            b"adapter implementation",
        )?,
        component(
            DependencyRole::Tokenizer,
            DependencyKind::Tokenizer,
            b"tokenizer implementation",
        )?,
        component(
            DependencyRole::Materializer,
            DependencyKind::Adapter,
            b"materializer implementation",
        )?,
        component(
            DependencyRole::Runtime,
            DependencyKind::Environment,
            b"runtime implementation",
        )?,
    ] {
        builder = builder.with_dependency(dependency);
    }
    if !matches!(options.source, SourceCase::Missing) {
        let semantic_id = if matches!(options.source, SourceCase::SemanticMismatch) {
            version(b"wrong source semantic version")?
        } else {
            selected_source
        };
        builder = builder.with_dependency(source_dependency(semantic_id, source_bytes)?);
    }
    if options.policy {
        builder = builder.with_dependency(snapshot_dependency(
            DependencyRole::Policy,
            DependencyKind::Policy,
            b"exact policy snapshot",
            None,
        )?);
    }
    if !matches!(options.index, IndexCase::Missing) {
        let fingerprint = if matches!(options.index, IndexCase::WatermarkMismatch) {
            raw_digest(b"wrong catalog watermark")?
        } else {
            catalog_watermark
        };
        builder = builder.with_dependency(snapshot_dependency(
            DependencyRole::Index,
            DependencyKind::Index,
            b"exact index generation",
            Some(fingerprint),
        )?);
    }
    if let Some(input) = tool {
        builder = builder.with_dependency(input.dependency);
    }
    if let Some(input) = environment {
        builder = builder.with_dependency(input.dependency);
    }
    if let Some(input) = effect {
        builder = builder.with_dependency(input.dependency);
    }
    if let Some(input) = output {
        builder = builder.with_dependency(input.dependency);
    }
    Ok(builder.seal())
}

struct ComponentInput {
    dependency: DependencyCapture,
    invocation_fingerprint: ContentDigest,
}

fn component_input(
    role: DependencyRole,
    kind: DependencyKind,
    case: ComponentCase,
    bytes: &[u8],
    mismatch_bytes: &[u8],
) -> TestResult<Option<ComponentInput>> {
    if matches!(case, ComponentCase::Absent) {
        return Ok(None);
    }
    let artifact_bytes = if matches!(case, ComponentCase::Empty) {
        Vec::new()
    } else {
        bytes.to_vec()
    };
    let dependency = component(role, kind, &artifact_bytes)?;
    let invocation_fingerprint = if matches!(case, ComponentCase::InvocationMismatch) {
        raw_digest(mismatch_bytes)?
    } else {
        dependency.dependency.content_digest.clone()
    };
    Ok(Some(ComponentInput {
        dependency,
        invocation_fingerprint,
    }))
}

struct EffectInput {
    dependency: DependencyCapture,
    decision_id: RecordId,
}

fn effect_input(case: EffectCase, bundle_id: &VersionId) -> TestResult<Option<EffectInput>> {
    if matches!(case, EffectCase::None) {
        return Ok(None);
    }
    let intent_id = record(20)?;
    let dependency_id = if matches!(case, EffectCase::RecordIdMismatch) {
        record(21)?
    } else {
        intent_id.clone()
    };
    let intent_bundle = if matches!(case, EffectCase::BundleMismatch) {
        version(b"wrong effect bundle")?
    } else {
        bundle_id.clone()
    };
    let bytes = if matches!(case, EffectCase::ArbitraryBytes) {
        canonical_json(&serde_json::json!({"not": "an effect intent"}))?
    } else {
        canonical_json(&effect_intent(intent_id, intent_bundle)?)?
    };
    let artifact = DecisionArtifact::new(MediaType::new("application/json")?, bytes)?;
    let dependency = DependencyCapture::new(
        DecisionDependency {
            kind: DependencyKind::Blob,
            role: DependencyRole::Effect,
            content_digest: artifact.content_digest.clone(),
            semantic_id: None,
            record_id: Some(dependency_id.clone()),
            fingerprint: None,
            required_modes: evidence_modes(),
        },
        artifact,
    )?;
    Ok(Some(EffectInput {
        dependency,
        decision_id: dependency_id,
    }))
}

struct OutputInput {
    dependency: DependencyCapture,
    semantic_id: VersionId,
}

fn output_input(case: OutputCase) -> TestResult<Option<OutputInput>> {
    if matches!(case, OutputCase::None) {
        return Ok(None);
    }
    let artifact = DecisionArtifact::new(
        MediaType::new("application/octet-stream")?,
        b"exact output artifact bytes".to_vec(),
    )?;
    let semantic_id = if matches!(case, OutputCase::SemanticMismatch) {
        version(b"unrelated output semantic id")?
    } else {
        VersionId::new(artifact.content_digest.as_str())?
    };
    let dependency = DependencyCapture::new(
        DecisionDependency {
            kind: DependencyKind::Blob,
            role: DependencyRole::OutputArtifact,
            content_digest: artifact.content_digest.clone(),
            semantic_id: Some(semantic_id.clone()),
            record_id: None,
            fingerprint: None,
            required_modes: evidence_modes(),
        },
        artifact,
    )?;
    Ok(Some(OutputInput {
        dependency,
        semantic_id,
    }))
}

fn component(
    role: DependencyRole,
    kind: DependencyKind,
    bytes: &[u8],
) -> TestResult<DependencyCapture> {
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
            required_modes: invocation_modes(),
        },
        artifact,
    )?)
}

fn source_dependency(semantic_id: VersionId, bytes: &[u8]) -> TestResult<DependencyCapture> {
    let artifact =
        DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes.to_vec())?;
    Ok(DependencyCapture::new(
        DecisionDependency {
            kind: DependencyKind::Source,
            role: DependencyRole::Source,
            content_digest: artifact.content_digest.clone(),
            semantic_id: Some(semantic_id),
            record_id: None,
            fingerprint: None,
            required_modes: evidence_modes(),
        },
        artifact,
    )?)
}

fn snapshot_dependency(
    role: DependencyRole,
    kind: DependencyKind,
    bytes: &[u8],
    fingerprint: Option<ContentDigest>,
) -> TestResult<DependencyCapture> {
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
            required_modes: evidence_modes(),
        },
        artifact,
    )?)
}

fn effect_intent(effect_id: RecordId, bundle_id: VersionId) -> TestResult<EffectIntent> {
    Ok(EffectIntent {
        schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
        effect_id,
        connector: "capture-test-connector".to_owned(),
        operation: "capture-test-operation".to_owned(),
        arguments_digest: raw_digest(b"effect arguments")?,
        encrypted_arguments: BlobRef {
            digest: raw_digest(b"encrypted arguments")?,
            size_bytes: 19,
            media_type: MediaType::new("application/octet-stream")?,
        },
        target: "capture-test-target".to_owned(),
        preconditions: Vec::new(),
        result_schema_digest: raw_digest(b"effect result schema")?,
        risk: RiskLevel::Low,
        source_decision_id: version(b"source decision before archive sealing")?,
        bundle_id,
        required_capability: Capability::InvokeTool,
        idempotency_scope: "capture-integrity".to_owned(),
        idempotency_key: IdempotencyKey::new("capture-integrity-effect")?,
        retry_policy: RetryPolicy::Never,
        created_at: time(1)?,
        expires_at: time(30)?,
        compensation: None,
        extensions: ExtensionMap::default(),
    })
}

fn assert_component_fingerprint_mismatch_rejected(
    role: DependencyRole,
    kind: DependencyKind,
) -> TestResult {
    let artifact = DecisionArtifact::new(
        MediaType::new("application/octet-stream")?,
        b"component implementation".to_vec(),
    )?;
    let result = DependencyCapture::new(
        DecisionDependency {
            kind,
            role,
            content_digest: artifact.content_digest.clone(),
            semantic_id: None,
            record_id: None,
            fingerprint: Some(raw_digest(b"different component")?),
            required_modes: invocation_modes(),
        },
        artifact,
    );
    assert_rejected(result);
    Ok(())
}

fn dependency(capture: &DecisionCapture, role: DependencyRole) -> TestResult<&DecisionDependency> {
    capture
        .archive
        .manifest
        .dependencies
        .iter()
        .find(|candidate| candidate.role == role)
        .ok_or_else(|| "capture dependency is absent".into())
}

fn assert_rejected<T>(result: Result<T, ReplayFoundationError>) {
    assert!(result.is_err(), "adversarial capture unexpectedly sealed");
}

fn canonical_json<T: Serialize>(value: &T) -> TestResult<Vec<u8>> {
    let serialized = serde_json::to_vec(value)?;
    Ok(to_normalized_json(&parse_strict_json(&serialized)?)?)
}

fn invocation_modes() -> BTreeSet<ReplayMode> {
    modes(&[
        ReplayMode::InvocationReproduction,
        ReplayMode::Observational,
        ReplayMode::LiveComparison,
    ])
}

fn evidence_modes() -> BTreeSet<ReplayMode> {
    modes(&[
        ReplayMode::EvidenceReproduction,
        ReplayMode::Observational,
        ReplayMode::LiveComparison,
    ])
}

fn modes(values: &[ReplayMode]) -> BTreeSet<ReplayMode> {
    values.iter().copied().collect()
}

fn raw_digest(bytes: &[u8]) -> TestResult<ContentDigest> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

fn version(bytes: &[u8]) -> TestResult<VersionId> {
    Ok(VersionId::new(raw_digest(bytes)?.as_str())?)
}

fn record(value: u64) -> TestResult<RecordId> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn time(second: u8) -> TestResult<UtcTimestamp> {
    let value = format!("2026-07-11T12:00:{second:02}Z");
    Ok(UtcTimestamp::parse_rfc3339(&value)?)
}
