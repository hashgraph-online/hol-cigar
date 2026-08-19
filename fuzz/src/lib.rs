//! Shared bounded entry points for the CIGAR release fuzz targets.

use cigar_canon::{
    from_deterministic_cbor, parse_strict_json, to_deterministic_cbor, to_normalized_json,
};
use cigar_catalog::{ProjectIdentity, ProjectIdentityInput};
use cigar_code_intel::{BuiltinLanguageAdapter, LanguageAdapter, ParseRequest};
use cigar_compiler::{
    BlockBodies, ByteTokenizer, CompileRequest, CompilerCandidate, CompilerProfile,
    DeterministicCompiler, FrozenInputs, MaterializerProfile, RepresentationVariant, apply_delta,
    compiler_profile_digest, generate_delta, materialize,
};
use cigar_daemon::fuzz_workflow_session_record;
use cigar_effects::{EffectCrashPoint, EffectFaultModel, FaultSnapshot};
use cigar_extension_host::FrameCodec;
use cigar_mcp::{
    Backend, BackendError, BackendRequest, BackendResponse, MAX_REQUEST_BYTES, Server,
};
use cigar_policy::{
    CapabilityContext, CompiledPolicyEngine, PolicyOutcome, PolicyProfile, PolicyRequest,
    PolicyResource,
};
use cigar_protocol::{
    AtomKind, Budget, Capability, Classification, CompatibilityReport, ConsistencyMode,
    ContextAtomV1, ContextBlock, ContextBundle, ContextContract, ContextDelta, ContextEdge,
    ContextPlan, ContextRequirement, DecisionRecord, EffectApproval, EffectAttempt, EffectIntent,
    EffectJournalEvent, EffectReceipt, ExtensionInvocationV1, ExtensionManifestV1, ExtensionMap,
    ExtensionResponseV1, FixedPoint, HandoffAcceptance, HandoffCapsule, HealthReport,
    InstructionAuthority, LaneKind, LineageId, MaterializedContext, OperationClass, Problem,
    ReconciliationReport, RecordId, RelativePath, ReplayDiff, ReplayExecution, ReplayRequest,
    RepresentationKind, RequirementSelector, SchemaVersion, SelectionManifest, SourceSnapshot,
    SourceUri, TargetProfile, UtcTimestamp, Validate, VerificationReceipt, VersionId,
};
use cigar_replay::{
    DecisionArchive, DecisionArchiveManifest, InvocationEnvelope, framed_observation_digest,
};
use cigar_retrieval::{
    AuthorizedPartition, CandidateBatch, CandidateFeatures, CandidateRankingDecision,
    CandidateRankingFactors, CandidateRef, CandidateSelectionBasis, ExecutedStage, MatchEvidence,
    QueryPlanner, QueryPlannerProfile, RequirementAwareCandidateReducer,
    RequirementRankingEvidence, RetrievalCapacity, RetrievalConsistency, RetrievalContext,
    RetrievalDisclosure, RetrievalProfile, StagedRetrievalResult,
};
use cigar_store::{CancellationToken, StoreRevision};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_FUZZ_INPUT: usize = 1_048_576;
const MAX_PARSER_INPUT: usize = 65_536;
const ERROR_REFLECTION_CANARY: &[u8] = b"CIGAR_WP19_ERROR_REFLECTION_CANARY";

/// Exercises strict JSON and deterministic CBOR as an idempotent, stable round trip.
pub fn canonical_json_cbor(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let Ok(node) = parse_strict_json(data) else {
        return;
    };
    let normalized = to_normalized_json(&node).expect("a parsed JSON node must normalize");
    let reparsed = parse_strict_json(&normalized).expect("normalized JSON must parse strictly");
    assert_eq!(node, reparsed);
    let cbor = to_deterministic_cbor(&node).expect("a parsed JSON node must encode as CBOR");
    let decoded = from_deterministic_cbor(&cbor).expect("deterministic CBOR must decode");
    assert_eq!(node, decoded);
    assert_eq!(
        cbor,
        to_deterministic_cbor(&decoded).expect("decoded CBOR must re-encode")
    );
}

/// Routes arbitrary strict JSON through representative records from every public domain family.
pub fn public_record_decoders(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_FUZZ_INPUT) else {
        return;
    };
    match selector % 24 {
        0 => strict_validate::<ContextAtomV1>(body),
        1 => strict_validate::<SourceSnapshot>(body),
        2 => strict_validate::<ContextContract>(body),
        3 => strict_validate::<ContextPlan>(body),
        4 => strict_validate::<ContextBundle>(body),
        5 => strict_validate::<SelectionManifest>(body),
        6 => strict_validate::<HandoffCapsule>(body),
        7 => strict_validate::<EffectIntent>(body),
        8 => strict_validate::<DecisionRecord>(body),
        9 => strict_validate::<ExtensionManifestV1>(body),
        10 => strict_validate::<Problem>(body),
        11 => strict_validate::<HealthReport>(body),
        12 => strict_validate::<ContextEdge>(body),
        13 => {
            let _decoded = strict_decode::<ContextRequirement>(body);
        }
        14 => strict_validate::<ContextDelta>(body),
        15 => strict_validate::<MaterializedContext>(body),
        16 => strict_validate::<ReplayExecution>(body),
        17 => strict_validate::<ReplayDiff>(body),
        18 => strict_validate::<VerificationReceipt>(body),
        19 => strict_validate::<EffectApproval>(body),
        20 => strict_validate::<EffectAttempt>(body),
        21 => strict_validate::<EffectReceipt>(body),
        22 => strict_validate::<ReconciliationReport>(body),
        _ => strict_validate::<CompatibilityReport>(body),
    }
}

/// Exercises v4 planning and post-governance reduction over byte-derived aliases and scores.
pub fn retrieval_plan_result_reduction(data: &[u8]) {
    let Some(data) = bounded(data, MAX_PARSER_INPUT) else {
        return;
    };
    if data.is_empty() {
        return;
    }
    let Ok((partition, _authority)) = fuzz_partition() else {
        return;
    };
    let requirement_count = usize::from(data[0] % 4) + 1;
    let requirements = (0..requirement_count)
        .map(|index| ContextRequirement {
            semantic_type: AtomKind::Documentation,
            selector: RequirementSelector::Query(format!("fuzz term {index}")),
            minimum_authority: 1,
            maximum_age: None,
            minimum_coverage: FixedPoint::new(0).expect("zero coverage is valid"),
            blocking: data.get(index + 1).copied().unwrap_or_default() & 1 != 0,
        })
        .collect::<Vec<_>>();
    let capacity = RetrievalCapacity::new(
        BTreeMap::from([(LaneKind::Evidence, 4_096)]),
        BTreeMap::from([(LaneKind::Evidence, 64)]),
        BTreeMap::from([(LaneKind::Evidence, 1)]),
    )
    .expect("fixed retrieval capacity is valid");
    let planner = QueryPlanner::new_with_retrieval_profile(
        QueryPlannerProfile::balanced_v4(),
        RetrievalProfile::BalancedV4,
    )
    .expect("fixed v4 planner is valid");
    let Ok(plan) = planner.plan_bounded_for_operation(
        &requirements,
        OperationClass::CodeChange,
        &capacity,
        &partition,
        StoreRevision(7),
        RetrievalConsistency::Strong,
    ) else {
        return;
    };
    let stages = plan
        .stages
        .iter()
        .enumerate()
        .map(|(index, planned)| {
            let seed = data.get(index + 1).copied().unwrap_or(index as u8);
            let identity = u64::from(seed % 16) + 1;
            let score = u16::from(seed).saturating_mul(37).min(10_000);
            let features = CandidateFeatures {
                requirement_match: score,
                lexical_match: score,
                project_proximity: 10_000,
                authority: 5_000,
                verification: 5_000,
                freshness: 10_000,
                estimated_tokens: u32::from(seed % 127) + 1,
                requirement_coverage_bits: 1_u64
                    .checked_shl(u32::try_from(planned.requirement_index % 64).unwrap_or_default())
                    .unwrap_or_default(),
                entity_coverage_bits: u64::from(seed),
                ..CandidateFeatures::default()
            };
            let candidate = CandidateRef {
                version_id: fixed_version(&identity.to_be_bytes()),
                lineage_id: fixed_lineage(u16::from(seed % 8) + 1),
                content_digest: fixed_digest(&[seed % 8]),
                atom_kind: AtomKind::Documentation,
                canonical_uri: SourceUri::new(format!("file:///fuzz/{}.md", seed % 8))
                    .expect("fixed source URI is valid"),
                relative_path: None,
                instruction_authority: InstructionAuthority::Data,
                classification: Classification::Internal,
                features,
                total_score: features
                    .score(RetrievalProfile::BalancedV4)
                    .expect("bounded features score"),
                evidence: BTreeSet::from([MatchEvidence::Lexical]),
            };
            ExecutedStage {
                requirement_index: planned.requirement_index,
                blocking: planned.blocking,
                stage: planned.request.stage,
                query_fingerprint: planned.query_fingerprint.clone(),
                batch: CandidateBatch {
                    candidates: vec![candidate],
                    disclosure: RetrievalDisclosure {
                        generation_id: fixed_record(900),
                        index_fingerprint: fixed_digest(b"fuzz-index"),
                        built_through_revision: StoreRevision(7),
                        actual_revision_lag: 0,
                        fallback_used: false,
                        last_verified_at: fixed_time(1_700_000_000_000_000_000),
                    },
                },
            }
        })
        .collect();
    let retrieval = StagedRetrievalResult {
        plan_fingerprint: plan.plan_fingerprint.clone(),
        stages,
    };
    let context = RetrievalContext {
        cancellation: CancellationToken::default(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let reducer = RequirementAwareCandidateReducer;
    let first =
        reducer.reduce_v4_for_operation(&plan, &retrieval, &context, OperationClass::CodeChange);
    let second =
        reducer.reduce_v4_for_operation(&plan, &retrieval, &context, OperationClass::CodeChange);
    assert_eq!(first, second, "retrieval reduction must be deterministic");
    if let Ok(output) = first {
        assert!(
            output
                .ranking_evidence
                .as_ref()
                .is_some_and(|evidence| evidence.validate().is_ok()),
            "v4 reduction emitted invalid ranking evidence"
        );
    }
}

/// Decodes a bounded seed, constructs valid v4 ranking evidence, then attacks validation fields.
pub fn ranking_evidence_decode_validate(data: &[u8]) {
    let Some((&mutation, scores)) = data.split_first() else {
        return;
    };
    let Some(scores) = bounded(scores, 256) else {
        return;
    };
    let decisions = scores
        .iter()
        .enumerate()
        .map(|(index, score)| {
            let base_score = i64::from(*score) * 1_000;
            CandidateRankingDecision {
                ordinal: index + 1,
                selected_version: fixed_version(&(index as u64).to_be_bytes()),
                basis: CandidateSelectionBasis::Score,
                newly_covered_requirements: 0,
                newly_covered_critical_requirements: 0,
                newly_covered_concepts: 0,
                source_diversity: false,
                section_diversity: false,
                kind_diversity: false,
                factors: CandidateRankingFactors {
                    base_score,
                    adjusted_score: base_score,
                    ..CandidateRankingFactors::default()
                },
                next_best_version: None,
                next_best_adjusted_score: None,
                uncovered_critical_after: 0,
            }
        })
        .collect();
    let Ok(valid) = RequirementRankingEvidence::new_v4(
        fixed_digest(b"ranking-plan"),
        BTreeSet::new(),
        BTreeSet::new(),
        decisions,
    ) else {
        return;
    };
    assert!(valid.validate().is_ok());
    let mut attacked = valid.clone();
    match mutation % 5 {
        0 => attacked.retrieval_profile_id.push_str("-substituted"),
        1 => attacked.retrieval_profile_digest = fixed_digest(b"wrong-profile"),
        2 => attacked.evidence_digest = fixed_digest(b"truncated-evidence"),
        3 if !attacked.decisions.is_empty() => attacked.decisions[0].ordinal += 1,
        _ if !attacked.decisions.is_empty() => {
            let selected = attacked.decisions[0].selected_version.clone();
            attacked.decisions[0].next_best_version = Some(selected);
            attacked.decisions[0].next_best_adjusted_score =
                Some(attacked.decisions[0].factors.adjusted_score);
        }
        _ => attacked.evidence_digest = fixed_digest(b"empty-evidence-tamper"),
    }
    assert!(
        attacked.validate().is_err(),
        "mutated ranking evidence must fail closed"
    );
}

/// Exercises v4 candidate packing with bounded aliases, costs, mandatory flags, and scores.
pub fn compiler_candidate_packing(data: &[u8]) {
    let Some(data) = bounded(data, 4_096) else {
        return;
    };
    if data.is_empty() {
        return;
    }
    let count = data.len().min(64);
    let candidates = data
        .iter()
        .take(count)
        .enumerate()
        .map(|(index, byte)| fuzz_compiler_candidate(index, *byte, false))
        .collect::<Vec<_>>();
    let request = fuzz_compile_request(candidates, u32::from(data[0]).saturating_mul(16) + 64);
    let first = DeterministicCompiler.compile(request.clone());
    let second = DeterministicCompiler.compile(request);
    assert_eq!(first, second, "v4 candidate packing must be deterministic");
}

/// Exercises cached dependency closure construction over byte-derived DAGs and explicit cycles.
pub fn dependency_closure(data: &[u8]) {
    let Some(data) = bounded(data, 4_096) else {
        return;
    };
    if data.is_empty() {
        return;
    }
    let count = data.len().min(32);
    let mut candidates = data
        .iter()
        .take(count)
        .enumerate()
        .map(|(index, byte)| fuzz_compiler_candidate(index, *byte, true))
        .collect::<Vec<_>>();
    for index in 1..candidates.len() {
        let selector = usize::from(data[index]);
        let dependency = selector % index;
        let dependency_version = candidates[dependency].version_id.clone();
        let preceding_version = candidates[index - 1].version_id.clone();
        candidates[index].dependencies.insert(dependency_version);
        if selector & 2 != 0 && index > 1 {
            candidates[index].dependencies.insert(preceding_version);
        }
    }
    if data[0] & 1 != 0 && candidates.len() > 1 {
        let last = candidates
            .last()
            .expect("non-empty candidate set")
            .version_id
            .clone();
        candidates[0].dependencies.insert(last);
    }
    let request = fuzz_compile_request(candidates, 4_096);
    let first = DeterministicCompiler.compile(request.clone());
    let second = DeterministicCompiler.compile(request);
    assert_eq!(first, second, "dependency closure must be deterministic");
}

/// Exercises strict workflow-session decoding and restored-state validation.
pub fn workflow_session_records(data: &[u8]) {
    fuzz_workflow_session_record(data);
}

/// Exercises URI/path validation and stable credential-free project identities.
pub fn identity_normalization(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let text = String::from_utf8_lossy(data);
    let _uri = SourceUri::new(text.as_ref());
    let _path = RelativePath::new(data.to_vec());
    let input = ProjectIdentityInput {
        tenant_id: fixed_record(1),
        git_remote: Some(text.into_owned()),
        root_lineage_id: fixed_record(2),
        disambiguator: "fuzz-worktree".to_owned(),
    };
    let first = ProjectIdentity::derive(input.clone());
    let second = ProjectIdentity::derive(input);
    assert_eq!(first, second);
    if let Ok(identity) = first
        && let Some(remote) = identity.normalized_remote()
    {
        assert!(!authority_contains_credentials(remote));
    }
}

/// Exercises bounded policy JSON/TOML parsing and atomic duplicate-revision rejection.
pub fn policy_parse_evaluate(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let activated_at = fixed_time(1_700_000_000_000_000_000);
    let json_engine = CompiledPolicyEngine::default();
    if json_engine.install_json(data, activated_at).is_ok() {
        assert!(json_engine.install_json(data, activated_at).is_err());
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let toml_engine = CompiledPolicyEngine::default();
        if toml_engine.install_toml(text, activated_at).is_ok() {
            assert!(toml_engine.install_toml(text, activated_at).is_err());
        }
    }
}

/// Exercises contract normalization and the deterministic compiler with an empty candidate set.
pub fn contract_compiler_candidates(data: &[u8]) {
    let Some(contract) = strict_decode::<ContextContract>(data) else {
        return;
    };
    if contract.validate().is_err() {
        return;
    }
    let profile = CompilerProfile::default();
    let Ok(profile_digest) = compiler_profile_digest(&profile) else {
        return;
    };
    let fixed = fixed_digest(b"compiler-fuzz-pin");
    let request = CompileRequest {
        frozen: FrozenInputs {
            catalog_watermark: fixed.clone(),
            graph_revision: fixed.clone(),
            policy_digest: fixed.clone(),
            index_fingerprints: BTreeSet::from([fixed.clone()]),
            retrieval_plan_digest: fixed,
            compiler_profile_digest: profile_digest,
            tokenizer_fingerprint: contract.target.tokenizer_fingerprint.clone(),
            materializer_fingerprint: contract.target.materializer_fingerprint.clone(),
        },
        contract,
        profile,
        candidates: Vec::new(),
        ranking_evidence: None,
    };
    let first = DeterministicCompiler.compile(request.clone());
    let second = DeterministicCompiler.compile(request);
    assert_eq!(first, second);
}

/// Builds valid arbitrary bundles and proves generated deltas reproduce the exact target.
pub fn delta_roundtrip(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let split = data.len() / 2;
    let shared = data.get(..split).unwrap_or_default();
    let added = data.get(split..).unwrap_or_default();
    let base = bundle_from_bodies(b"base", &[nonempty(shared)]);
    let target = bundle_from_bodies(b"target", &[nonempty(shared), nonempty(added)]);
    if let Ok(sealed) = generate_delta(&base, &target) {
        let applied = apply_delta(&base, &target, &sealed).expect("generated delta must apply");
        assert_eq!(applied, target);
        let mut tampered = sealed.clone();
        tampered.delta_digest = fixed_digest(b"tampered-delta");
        assert!(
            apply_delta(&base, &target, &tampered).is_err(),
            "a substituted delta digest must fail closed"
        );
        let wrong_base = bundle_from_bodies(b"wrong-base", &[nonempty(added)]);
        assert!(
            apply_delta(&wrong_base, &target, &sealed).is_err(),
            "a substituted delta base must fail closed"
        );
    }
}

/// Exercises manifest/delta/materialized decoders without reflecting protected input in errors.
pub fn manifest_explanation_redaction(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_FUZZ_INPUT) else {
        return;
    };
    match selector % 3 {
        0 => strict_validate_no_reflection::<SelectionManifest>(body),
        1 => strict_validate_no_reflection::<ContextDelta>(body),
        _ => strict_validate_no_reflection::<MaterializedContext>(body),
    }
}

/// Exercises handoff and acceptance decoding plus structural capability attenuation.
pub fn handoff_accept_merge(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let split = data.len() / 2;
    let capsule = data.get(..split).and_then(strict_decode::<HandoffCapsule>);
    let acceptance = data
        .get(split..)
        .and_then(strict_decode::<HandoffAcceptance>);
    if let Some(capsule) = capsule {
        let _capsule_validation = capsule.validate();
        if let Some(acceptance) = acceptance {
            let _acceptance_validation = acceptance.validate();
            let _attenuation = acceptance.validate_against(&capsule);
        }
    }
}

/// Exercises all materializers at arbitrary byte/token boundaries over valid exact bundles.
pub fn materializer_budget(data: &[u8]) {
    let Some(data) = bounded(data, MAX_PARSER_INPUT) else {
        return;
    };
    let body = nonempty(data);
    let bundle = bundle_from_bodies(b"materialize", &[body]);
    let block = bundle
        .blocks
        .first()
        .expect("generated bundle has one block");
    let mut bodies = BlockBodies::new();
    bodies.insert(block.block_id.clone(), body.to_vec());
    let tokenizer = ByteTokenizer::new(fixed_digest(b"byte-tokenizer"));
    for profile in [
        MaterializerProfile::Json,
        MaterializerProfile::Markdown,
        MaterializerProfile::FactSet,
        MaterializerProfile::ClaudePrompt,
        MaterializerProfile::McpResource,
    ] {
        if let Ok((rendered, accounting)) = materialize(profile, &bundle, &bodies, &tokenizer) {
            assert_eq!(rendered.token_count as usize, rendered.bytes.len());
            assert_eq!(accounting.physical_input_tokens, rendered.token_count);
            assert!(rendered.validate().is_ok());
        }
    }
}

/// Exercises every effect crash row, durable snapshot decoding, and damaged-journal input.
pub fn effect_journal_recovery(data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default() as usize;
    let point = EffectCrashPoint::ALL[selector % EffectCrashPoint::ALL.len()];
    let mut seed_bytes = [0_u8; 8];
    for (target, source) in seed_bytes.iter_mut().zip(data.iter().copied().skip(1)) {
        *target = source;
    }
    let seed = u64::from_le_bytes(seed_bytes);
    let snapshot = EffectFaultModel::inject(point, seed);
    let encoded = snapshot.to_json().expect("fault snapshot must serialize");
    let decoded = FaultSnapshot::from_json(&encoded).expect("fault snapshot must decode");
    decoded
        .recover()
        .verify()
        .expect("reference recovery invariants must hold");
    strict_validate::<EffectJournalEvent>(data);
    if let Ok(candidate) = FaultSnapshot::from_json(data) {
        let _verification = candidate.recover().verify();
    }
}

/// Exercises replay requests/records and bounded observation framing.
pub fn replay_envelopes(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    strict_validate::<ReplayRequest>(data);
    strict_validate::<DecisionRecord>(data);
    if let Some(value) = strict_decode::<InvocationEnvelope>(data) {
        let _validation = value.validate();
    }
    if let Some(value) = strict_decode::<DecisionArchiveManifest>(data) {
        let _validation = value.validate();
    }
    if let Some(value) = strict_decode::<DecisionArchive>(data) {
        let _validation = value.validate();
    }
    let midpoint = data.len() / 2;
    let observations = vec![
        data.get(..midpoint).unwrap_or_default().to_vec(),
        data.get(midpoint..).unwrap_or_default().to_vec(),
    ];
    let first = framed_observation_digest(&observations);
    let second = framed_observation_digest(&observations);
    assert_eq!(first, second);
}

fn fuzz_partition()
-> Result<(AuthorizedPartition, Arc<CompiledPolicyEngine>), Box<dyn std::error::Error>> {
    let engine = Arc::new(CompiledPolicyEngine::default());
    let now = fixed_time(1_700_000_000_000_000_000);
    let expires_at = fixed_time(1_700_000_060_000_000_000);
    engine.install(
        PolicyProfile {
            schema_version: "cigar.policy-profile.v1".to_owned(),
            revision: 1,
            protected: true,
            rules: Vec::new(),
        },
        now,
    )?;
    let tenant_id = fixed_record(1);
    let principal_id = fixed_record(2);
    let project_id = fixed_record(3);
    let project_ids = BTreeSet::from([project_id.clone()]);
    let capabilities = BTreeSet::from([Capability::ReadContext]);
    let processors = BTreeSet::from(["fuzz-local".to_owned()]);
    let purposes = BTreeSet::from(["fuzzing".to_owned()]);
    let request = PolicyRequest {
        resource: PolicyResource::Partition,
        input_digest: fixed_digest(b"fuzz-partition"),
        principal_id: principal_id.clone(),
        principal_active: true,
        tenant_id: tenant_id.clone(),
        authenticated_tenant_id: tenant_id,
        project_id: Some(project_id),
        allowed_project_ids: project_ids.clone(),
        purpose: "fuzzing".to_owned(),
        allowed_purposes: purposes,
        processor: Some("fuzz-local".to_owned()),
        allowed_processors: processors.clone(),
        classification: Classification::Public,
        maximum_classification: Classification::Internal,
        residency_allowed: true,
        egress_allowed: true,
        lifecycle: cigar_protocol::Lifecycle::Active,
        integrity_verified: true,
        valid_at: now,
        valid_from: now,
        valid_until: Some(expires_at),
        observed_at: now,
        observed_as_of: now,
        freshness_expires_at: None,
        instruction_authority: InstructionAuthority::Data,
        maximum_instruction_authority: InstructionAuthority::System,
        excluded: false,
        modality_supported: true,
        capability: Some(CapabilityContext {
            subject_id: principal_id,
            grant_id: Some(fixed_record(4)),
            capabilities,
            project_ids,
            processors,
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
    };
    let authorization = engine.authorize_retrieval_partition(&[request])?;
    let partition = AuthorizedPartition::from_policy_authorization(authorization)?;
    Ok((partition, engine))
}

fn fuzz_compile_request(candidates: Vec<CompilerCandidate>, budget: u32) -> CompileRequest {
    let budget = budget.max(1);
    let contract = ContextContract {
        schema_version: SchemaVersion::new("cigar.context-contract", 1)
            .expect("fixed contract schema is valid"),
        job_goal: "fuzz deterministic candidate packing".to_owned(),
        operation_class: OperationClass::Analysis,
        principal_id: fixed_record(10),
        purpose: "fuzzing".to_owned(),
        context_space_id: None,
        project_ids: vec![fixed_record(11)],
        target: TargetProfile {
            provider: "fuzz-provider".to_owned(),
            model_family: "fuzz-model".to_owned(),
            tokenizer_fingerprint: fixed_digest(b"fuzz-tokenizer"),
            materializer_fingerprint: fixed_digest(b"fuzz-materializer"),
            max_context_tokens: budget.saturating_add(1_024),
        },
        budget: Budget {
            total_input_tokens: budget,
            output_reserve_tokens: 1_024,
            lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, budget)]),
        },
        requirements: Vec::new(),
        consistency: ConsistencyMode::Strong,
        maximum_staleness: None,
        extensions: ExtensionMap::default(),
    };
    let mut profile = CompilerProfile::balanced_v4();
    profile.maximum_items.insert(LaneKind::Evidence, 64);
    let profile_digest =
        compiler_profile_digest(&profile).expect("fixed compiler profile must digest");
    let retrieval_plan_digest = fixed_digest(b"fuzz-retrieval-plan");
    let ranking_evidence = RequirementRankingEvidence::new_v4(
        retrieval_plan_digest.clone(),
        BTreeSet::new(),
        BTreeSet::new(),
        Vec::new(),
    )
    .expect("empty non-requirement ranking evidence is valid");
    CompileRequest {
        frozen: FrozenInputs {
            catalog_watermark: fixed_digest(b"fuzz-catalog"),
            graph_revision: fixed_digest(b"fuzz-graph"),
            policy_digest: fixed_digest(b"fuzz-policy"),
            index_fingerprints: BTreeSet::from([fixed_digest(b"fuzz-index")]),
            retrieval_plan_digest,
            compiler_profile_digest: profile_digest,
            tokenizer_fingerprint: contract.target.tokenizer_fingerprint.clone(),
            materializer_fingerprint: contract.target.materializer_fingerprint.clone(),
        },
        contract,
        profile,
        candidates,
        ranking_evidence: Some(ranking_evidence),
    }
}

fn fuzz_compiler_candidate(index: usize, byte: u8, dependency_mode: bool) -> CompilerCandidate {
    let group = if dependency_mode {
        index
    } else {
        usize::from(byte % 8)
    };
    let tokens = u32::from(byte % 63) + 1;
    let score = u16::from(byte).saturating_mul(37).min(10_000);
    CompilerCandidate {
        version_id: fixed_version(&(index as u64).to_be_bytes()),
        logical_id: fixed_version(&(group as u64).to_be_bytes()),
        lineage_id: fixed_lineage(u16::try_from(group % 65_535).unwrap_or_default()),
        canonical_uri: SourceUri::new(format!("file:///fuzz/{group}.md"))
            .expect("fixed compiler source URI is valid"),
        lane: LaneKind::Evidence,
        mandatory: byte & 1 != 0,
        requirement_indices: BTreeSet::new(),
        entity_coverage_bits: u64::from(byte),
        features: CandidateFeatures {
            requirement_match: score,
            lexical_match: score,
            project_proximity: 10_000,
            authority: 5_000,
            verification: 5_000,
            freshness: 10_000,
            estimated_tokens: tokens,
            entity_coverage_bits: u64::from(byte),
            ..CandidateFeatures::default()
        },
        policy_outcome: PolicyOutcome::Allow,
        pre_exclusion_reason: None,
        classification: Classification::Internal,
        instruction_authority: InstructionAuthority::Data,
        dependencies: BTreeSet::new(),
        representations: vec![
            RepresentationVariant::exact(fixed_digest(&(group as u64).to_le_bytes()), tokens)
                .expect("bounded exact representation is valid"),
        ],
        claim: None,
        provenance_digest: fixed_digest(&(index as u64).to_le_bytes()),
    }
}

/// Exercises strict extension manifests and canonical length-delimited ABI frames.
pub fn extension_frames(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_FUZZ_INPUT) else {
        return;
    };
    strict_validate::<ExtensionManifestV1>(body);
    let codec = FrameCodec::new(MAX_FUZZ_INPUT).expect("valid frame limit");
    if selector & 1 == 0 {
        let _invocation = codec.decode::<ExtensionInvocationV1>(body);
    } else {
        let _response = codec.decode::<ExtensionResponseV1>(body);
    }
}

/// Exercises strict MCP parsing/state transitions over a backend that cannot perform I/O.
pub fn mcp_messages(data: &[u8]) {
    let Some(data) = bounded(data, MAX_REQUEST_BYTES) else {
        return;
    };
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let mut server = Server::new(DenyBackend);
    if let Some(response) = server.process_line(line) {
        assert!(response.len() <= MAX_REQUEST_BYTES.saturating_mul(4));
        let _: serde_json::Value =
            serde_json::from_str(&response).expect("every MCP response must be valid JSON");
    }
}

/// Exercises every built-in Tree-sitter parser on bounded arbitrary source bytes.
pub fn builtin_source_parsers(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_PARSER_INPUT) else {
        return;
    };
    let adapters = BuiltinLanguageAdapter::required_v1();
    let adapter = &adapters[usize::from(selector) % adapters.len()];
    let extension = adapter
        .descriptor()
        .extensions
        .into_iter()
        .next()
        .unwrap_or_else(|| "txt".to_owned());
    let path = RelativePath::new(format!("fuzz.{extension}").into_bytes())
        .expect("fixed relative path must validate");
    let request = ParseRequest {
        path: &path,
        bytes: nonempty(body),
        previous: None,
    };
    let cancellation = CancellationToken::default();
    let first = adapter.parse(request, &cancellation);
    let second = adapter.parse(request, &cancellation);
    assert_eq!(first, second);
    if let Ok(parsed) = first {
        assert!(parsed.validate(nonempty(body).len()).is_ok());
    }
}

fn strict_validate<T>(data: &[u8])
where
    T: DeserializeOwned + Validate,
{
    if let Some(value) = strict_decode::<T>(data) {
        let _validation = value.validate();
    }
}

fn strict_validate_no_reflection<T>(data: &[u8])
where
    T: DeserializeOwned + Validate,
{
    if let Some(value) = strict_decode::<T>(data)
        && let Err(error) = value.validate()
    {
        let rendered = format!("{error:?}");
        if contains(data, ERROR_REFLECTION_CANARY) {
            assert!(
                !rendered
                    .as_bytes()
                    .windows(ERROR_REFLECTION_CANARY.len())
                    .any(|window| { window == ERROR_REFLECTION_CANARY })
            );
        }
    }
}

fn strict_decode<T: DeserializeOwned>(data: &[u8]) -> Option<T> {
    let data = bounded(data, MAX_FUZZ_INPUT)?;
    let node = parse_strict_json(data).ok()?;
    let normalized = to_normalized_json(&node).ok()?;
    serde_json::from_slice(&normalized).ok()
}

fn bounded(data: &[u8], maximum: usize) -> Option<&[u8]> {
    (data.len() <= maximum).then_some(data)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn authority_contains_credentials(remote: &str) -> bool {
    remote
        .split_once("://")
        .map(|(_scheme, remainder)| remainder.split('/').next().unwrap_or_default())
        .is_some_and(|authority| authority.contains('@'))
}

fn nonempty(data: &[u8]) -> &[u8] {
    if data.is_empty() { b"x" } else { data }
}

fn fixed_record(last: u16) -> RecordId {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f{last:04x}"))
        .expect("fixed UUIDv7-shaped record identifier")
}

fn fixed_lineage(last: u16) -> LineageId {
    LineageId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6e{last:04x}"))
        .expect("fixed UUIDv7-shaped lineage identifier")
}

fn fixed_time(nanos: i128) -> UtcTimestamp {
    UtcTimestamp::from_unix_nanos(nanos).expect("fixed timestamp")
}

fn fixed_digest(bytes: &[u8]) -> cigar_protocol::ContentDigest {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    cigar_protocol::ContentDigest::new(format!("1220{suffix}")).expect("SHA-256 multihash")
}

fn fixed_version(bytes: &[u8]) -> VersionId {
    VersionId::new(fixed_digest(bytes).as_str().to_owned()).expect("SHA-256 version identifier")
}

fn bundle_from_bodies(seed: &[u8], bodies: &[&[u8]]) -> ContextBundle {
    let mut unique = BTreeMap::<VersionId, ContextBlock>::new();
    for (index, body) in bodies.iter().enumerate() {
        let mut identity = Vec::from(*body);
        identity.extend_from_slice(&index.to_le_bytes());
        let block_id = fixed_version(&identity);
        unique.insert(
            block_id.clone(),
            ContextBlock {
                block_id,
                lane: LaneKind::Evidence,
                representation: RepresentationKind::Exact,
                content_digest: fixed_digest(body),
                token_count: u32::try_from(body.len()).expect("bounded fuzz body length"),
                provenance: vec![fixed_version(b"fuzz-provenance")],
                transform_receipt: None,
            },
        );
    }
    let blocks: Vec<_> = unique.into_values().collect();
    let total_tokens = blocks.iter().map(|block| block.token_count).sum();
    ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)
            .expect("fixed schema version"),
        bundle_id: fixed_version(seed),
        contract_digest: fixed_digest(b"fuzz-contract"),
        manifest_digest: fixed_digest(b"fuzz-manifest"),
        blocks,
        total_tokens,
        extensions: ExtensionMap::default(),
    }
}

#[derive(Clone, Copy, Debug)]
struct DenyBackend;

impl Backend for DenyBackend {
    fn call(&mut self, _request: BackendRequest<'_>) -> Result<BackendResponse, BackendError> {
        Err(BackendError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compiler_candidate_packing, delta_roundtrip, dependency_closure, mcp_messages,
        public_record_decoders, ranking_evidence_decode_validate, replay_envelopes,
        retrieval_plan_result_reduction, workflow_session_records,
    };

    #[test]
    fn h094_checked_in_security_seed_corpus_executes() {
        let retrieval = include_bytes!(
            "../corpus/retrieval_plan_result_reduction/four-requirement-alias-boundaries"
        );
        let ranking =
            include_bytes!("../corpus/ranking_evidence_decode_validate/runner-up-digest-tamper");
        let packing =
            include_bytes!("../corpus/compiler_candidate_packing/mandatory-alias-budget-edge");
        let closure = include_bytes!("../corpus/dependency_closure/cycle-and-diamond");
        let valid_session = include_bytes!("../corpus/workflow_session_records/valid-new-session");
        let invalid_session =
            include_bytes!("../corpus/workflow_session_records/impossible-effect-phase");
        let delta = include_bytes!("../corpus/delta_roundtrip/block-size-boundaries");
        let replay = include_bytes!("../corpus/replay_envelopes/unknown-field-invocation");
        let public = include_bytes!("../corpus/public_record_decoders/compatibility-unknown-field");

        assert_eq!(retrieval[0] % 4, 3, "seed must construct four requirements");
        assert_eq!(ranking[0] % 5, 2, "seed must attack the evidence digest");
        assert_eq!(closure[0] & 1, 1, "seed must close an explicit cycle");
        assert_eq!(delta.len(), 256, "seed must split at the 127/128 boundary");
        assert_eq!(public[0] % 24, 23, "seed must select compatibility records");

        retrieval_plan_result_reduction(retrieval);
        ranking_evidence_decode_validate(ranking);
        compiler_candidate_packing(packing);
        dependency_closure(closure);
        workflow_session_records(valid_session);
        workflow_session_records(invalid_session);
        delta_roundtrip(delta);
        replay_envelopes(replay);
        public_record_decoders(public);
        mcp_messages(include_bytes!(
            "../regressions/mcp_messages/backend-nonfinite-number.json"
        ));
        mcp_messages(include_bytes!(
            "../corpus/mcp_messages/out-of-range-numeric-id"
        ));
    }
}
