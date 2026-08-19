use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_compiler::{
    CompileRequest, CompilerCandidate, CompilerErrorCode, CompilerProfile, DeterministicCompiler,
    FrozenInputs, LossClass, RepresentationVariant, compiler_profile_digest,
};
use cigar_conformance::CaseOutcome;
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    AtomKind, Budget, Classification, ConsistencyMode, ContentDigest, ContextContract,
    ContextRequirement, ExtensionMap, FixedPoint, InstructionAuthority, LaneKind, OperationClass,
    RecordId, RepresentationKind, RequirementSelector, SchemaVersion, SourceUri, TargetProfile,
    Validate, VersionId,
};
use cigar_retrieval::CandidateFeatures;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "compiler_deterministic_bundle" => deterministic_bundle(input),
        "compiler_budget_rejection" => budget_rejection(input),
        _ => Err("unsupported compiler conformance operation".into()),
    }
}

fn deterministic_bundle(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "compiler-baseline-v1")?;
    let request = baseline_request()?;
    let first = DeterministicCompiler.compile(request.clone())?;
    let mut permuted = request;
    permuted.candidates.reverse();
    let second = DeterministicCompiler.compile(permuted)?;
    if first != second {
        return Err("production compiler changed output under candidate permutation".into());
    }
    first.plan.validate()?;
    first.manifest.validate()?;
    first.bundle.validate()?;
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.compiler-bundle.v1",
            &[
                first.plan.plan_id.as_str(),
                first.manifest.manifest_id.as_str(),
                first.bundle.bundle_id.as_str(),
                &first.bundle.total_tokens.to_string(),
                &first.normalized_contract.job_goal,
            ],
        ),
    ))
}

fn budget_rejection(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "compiler-mandatory-overflow-v1")?;
    let mut request = baseline_request()?;
    request
        .contract
        .budget
        .lane_input_tokens
        .insert(LaneKind::Rules, 250);
    request
        .contract
        .budget
        .lane_input_tokens
        .insert(LaneKind::Evidence, 500);
    request.contract.budget.total_input_tokens = 750;
    let error = DeterministicCompiler
        .compile(request)
        .err()
        .ok_or("production compiler accepted a mandatory overflow")?;
    if error.code() != CompilerErrorCode::BudgetUnsatisfiable
        || error.minimum_required_tokens() != Some(300)
    {
        return Err("production compiler returned the wrong budget lower bound".into());
    }
    Ok((
        CaseOutcome::Rejected,
        rejected_digest("compiler_budget_unsatisfiable_300"),
    ))
}

fn digest(value: u8) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        format!("{value:02x}").repeat(32)
    ))?)
}

fn version(value: u8) -> Result<VersionId, Box<dyn std::error::Error>> {
    Ok(VersionId::new(digest(value)?.as_str())?)
}

fn record(value: u16) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
    ))?)
}

fn contract(
    lane_budgets: BTreeMap<LaneKind, u32>,
    requirements: Vec<ContextRequirement>,
) -> Result<ContextContract, Box<dyn std::error::Error>> {
    let total_input_tokens = lane_budgets
        .values()
        .try_fold(0_u32, |total, value| total.checked_add(*value))
        .ok_or("budget overflow")?;
    Ok(ContextContract {
        schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
        job_goal: "  Implement   a verified change  ".to_owned(),
        operation_class: OperationClass::CodeChange,
        principal_id: record(1)?,
        purpose: "Coding".to_owned(),
        context_space_id: None,
        project_ids: vec![record(2)?],
        target: TargetProfile {
            provider: "Fixture".to_owned(),
            model_family: "Fixture Model".to_owned(),
            tokenizer_fingerprint: digest(240)?,
            materializer_fingerprint: digest(241)?,
            max_context_tokens: total_input_tokens + 1_000,
        },
        budget: Budget {
            total_input_tokens,
            output_reserve_tokens: 1_000,
            lane_input_tokens: lane_budgets,
        },
        requirements,
        consistency: ConsistencyMode::Strong,
        maximum_staleness: None,
        extensions: ExtensionMap::default(),
    })
}

fn requirement() -> Result<ContextRequirement, Box<dyn std::error::Error>> {
    Ok(ContextRequirement {
        semantic_type: AtomKind::Documentation,
        selector: RequirementSelector::Query("  current   policy ".to_owned()),
        minimum_authority: 1,
        maximum_age: None,
        minimum_coverage: FixedPoint::new(0)?,
        blocking: true,
    })
}

fn features(score: u16, tokens: u32) -> CandidateFeatures {
    CandidateFeatures {
        requirement_match: score,
        exact_match: score,
        lexical_match: score,
        semantic_match: 0,
        graph_proximity: 0,
        project_proximity: 10_000,
        task_proximity: 0,
        authority: 5_000,
        verification: 5_000,
        freshness: 10_000,
        novelty: 0,
        conflict_risk: 0,
        staleness: 0,
        estimated_tokens: tokens,
        requirement_coverage_bits: 0,
        entity_coverage_bits: 0,
    }
}

fn candidate(
    value: u8,
    lane: LaneKind,
    tokens: u32,
    score: u16,
) -> Result<CompilerCandidate, Box<dyn std::error::Error>> {
    Ok(CompilerCandidate {
        version_id: version(value)?,
        logical_id: version(value)?,
        lineage_id: cigar_protocol::LineageId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f{:04x}",
            u16::from(value)
        ))?,
        canonical_uri: SourceUri::new(format!("file:///fixture/{value:02x}.md"))?,
        lane,
        mandatory: false,
        requirement_indices: BTreeSet::new(),
        entity_coverage_bits: 0,
        features: features(score, tokens),
        policy_outcome: PolicyOutcome::Allow,
        pre_exclusion_reason: None,
        classification: Classification::Internal,
        instruction_authority: InstructionAuthority::Data,
        dependencies: BTreeSet::new(),
        representations: vec![RepresentationVariant {
            kind: RepresentationKind::Exact,
            content_digest: digest(value.saturating_add(64))?,
            token_count: tokens,
            loss: LossClass::Lossless,
            transform_receipt: None,
        }],
        claim: None,
        provenance_digest: digest(value.saturating_add(128))?,
    })
}

fn compile_request(
    contract: ContextContract,
    profile: CompilerProfile,
    candidates: Vec<CompilerCandidate>,
) -> Result<CompileRequest, Box<dyn std::error::Error>> {
    Ok(CompileRequest {
        frozen: FrozenInputs {
            catalog_watermark: digest(230)?,
            graph_revision: digest(231)?,
            policy_digest: digest(232)?,
            index_fingerprints: [digest(233)?].into_iter().collect(),
            retrieval_plan_digest: digest(234)?,
            compiler_profile_digest: compiler_profile_digest(&profile)?,
            tokenizer_fingerprint: contract.target.tokenizer_fingerprint.clone(),
            materializer_fingerprint: contract.target.materializer_fingerprint.clone(),
        },
        contract,
        profile,
        candidates,
        ranking_evidence: None,
    })
}

fn baseline_request() -> Result<CompileRequest, Box<dyn std::error::Error>> {
    let contract = contract(
        BTreeMap::from([(LaneKind::Rules, 500), (LaneKind::Evidence, 500)]),
        vec![requirement()?],
    )?;
    let mut governing = candidate(1, LaneKind::Rules, 200, 10_000)?;
    governing.requirement_indices.insert(0);
    let dependency = candidate(2, LaneKind::Rules, 100, 8_000)?;
    governing.dependencies.insert(dependency.version_id.clone());
    let evidence = candidate(3, LaneKind::Evidence, 300, 7_000)?;
    compile_request(
        contract,
        CompilerProfile::default(),
        vec![governing, dependency, evidence],
    )
}
