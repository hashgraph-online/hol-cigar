//! WP08 deterministic compiler, packing, provenance, and budget acceptance matrix.

use cigar_canon::{SemanticEnvelopeProfile, semantic_multihash_v1};
use cigar_compiler::{
    CandidateClaim, CompileRequest, CompilerCandidate, CompilerErrorCode, CompilerProfile,
    DeterministicCompiler, FrozenInputs, LossClass, PackingDecisionBasis, PackingStopReason,
    RepresentationVariant, compiler_profile_digest,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    AtomKind, Budget, CandidateDisposition, CanonicalValue, Classification, ConsistencyMode,
    ContentDigest, ContextContract, ContextRequirement, DispositionReason, ExtensionKey,
    ExtensionMap, FixedPoint, InstructionAuthority, LaneKind, LineageId, OperationClass, RecordId,
    RepresentationKind, RequirementSelector, SchemaVersion, SourceUri, TargetProfile, UtcTimestamp,
    Validate, VersionId,
};
use cigar_retrieval::{
    CandidateFeatures, CandidateRankingDecision, CandidateRankingFactors, CandidateSelectionBasis,
    QueryPlannerProfile, RequirementRankingEvidence, RetrievalProfile,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::process::Command;
use std::thread;

fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        format!("{value:02x}").repeat(32)
    ))?)
}

fn version(value: u8) -> Result<VersionId, Box<dyn Error>> {
    Ok(VersionId::new(digest(value)?.as_str())?)
}

fn digest_u64(value: u64) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!("1220{value:064x}"))?)
}

fn version_u64(value: u64) -> Result<VersionId, Box<dyn Error>> {
    Ok(VersionId::new(format!("1220{value:064x}"))?)
}

fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
    ))?)
}

fn lineage(value: u16) -> Result<LineageId, Box<dyn Error>> {
    Ok(LineageId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
    ))?)
}

fn time(value: &str) -> Result<UtcTimestamp, Box<dyn Error>> {
    Ok(UtcTimestamp::parse_rfc3339(value)?)
}

fn contract(
    lane_budgets: BTreeMap<LaneKind, u32>,
    requirements: Vec<ContextRequirement>,
) -> Result<ContextContract, Box<dyn Error>> {
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

fn requirement(blocking: bool, query: &str) -> Result<ContextRequirement, Box<dyn Error>> {
    Ok(ContextRequirement {
        semantic_type: AtomKind::Documentation,
        selector: RequirementSelector::Query(query.to_owned()),
        minimum_authority: 1,
        maximum_age: None,
        minimum_coverage: FixedPoint::new(0)?,
        blocking,
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
) -> Result<CompilerCandidate, Box<dyn Error>> {
    Ok(CompilerCandidate {
        version_id: version(value)?,
        logical_id: version(value)?,
        lineage_id: lineage(u16::from(value))?,
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

fn request(
    contract: ContextContract,
    profile: CompilerProfile,
    candidates: Vec<CompilerCandidate>,
) -> Result<CompileRequest, Box<dyn Error>> {
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

fn v4_ranking_evidence(
    candidates: &[CompilerCandidate],
    critical_requirements: BTreeSet<usize>,
) -> Result<RequirementRankingEvidence, Box<dyn Error>> {
    let selection = QueryPlannerProfile::balanced_v4().candidate_selection;
    let mut ranked = candidates
        .iter()
        .filter(|candidate| !candidate.requirement_indices.is_empty())
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| left.version_id.cmp(&right.version_id));
    let mut remaining = critical_requirements.len();
    let mut decisions = Vec::with_capacity(ranked.len());
    for (index, candidate) in ranked.into_iter().enumerate() {
        let newly_covered_critical_requirements = if index == 0 { remaining } else { 0 };
        remaining = remaining
            .checked_sub(newly_covered_critical_requirements)
            .ok_or("critical requirement underflow")?;
        let critical_requirement_gain = selection
            .critical_requirement_gain
            .checked_mul(i64::try_from(newly_covered_critical_requirements)?)
            .ok_or("critical gain overflow")?;
        let base_score = candidate.features.score(RetrievalProfile::BalancedV4)?;
        let adjusted_score = base_score
            .checked_add(critical_requirement_gain)
            .ok_or("adjusted score overflow")?;
        decisions.push(CandidateRankingDecision {
            ordinal: index.checked_add(1).ok_or("ordinal overflow")?,
            selected_version: candidate.version_id.clone(),
            basis: if newly_covered_critical_requirements > 0 {
                CandidateSelectionBasis::CriticalRequirement
            } else {
                CandidateSelectionBasis::Score
            },
            newly_covered_requirements: newly_covered_critical_requirements,
            newly_covered_critical_requirements,
            newly_covered_concepts: 0,
            source_diversity: false,
            section_diversity: false,
            kind_diversity: false,
            factors: CandidateRankingFactors {
                base_score,
                critical_requirement_gain,
                requirement_gain: 0,
                concept_gain: 0,
                diversity_gain: 0,
                generic_penalty: 0,
                redundancy_penalty: 0,
                similarity_penalty: 0,
                adjusted_score,
            },
            next_best_version: None,
            next_best_adjusted_score: None,
            uncovered_critical_after: remaining,
        });
    }
    Ok(RequirementRankingEvidence::new_v4(
        digest(234)?,
        critical_requirements,
        BTreeSet::new(),
        decisions,
    )?)
}

fn v4_request(
    contract: ContextContract,
    candidates: Vec<CompilerCandidate>,
) -> Result<CompileRequest, Box<dyn Error>> {
    let critical_requirements = contract
        .requirements
        .iter()
        .enumerate()
        .filter_map(|(index, requirement)| requirement.blocking.then_some(index))
        .collect();
    let ranking_evidence = v4_ranking_evidence(&candidates, critical_requirements)?;
    let mut request = request(contract, CompilerProfile::balanced_v4(), candidates)?;
    request.ranking_evidence = Some(ranking_evidence);
    Ok(request)
}

fn baseline_request() -> Result<CompileRequest, Box<dyn Error>> {
    let requirements = vec![requirement(true, "  current   policy ")?];
    let contract = contract(
        BTreeMap::from([(LaneKind::Rules, 500), (LaneKind::Evidence, 500)]),
        requirements,
    )?;
    let mut governing = candidate(1, LaneKind::Rules, 200, 10_000)?;
    governing.requirement_indices.insert(0);
    let mut dependency = candidate(2, LaneKind::Rules, 100, 8_000)?;
    dependency.mandatory = false;
    governing.dependencies.insert(dependency.version_id.clone());
    let evidence = candidate(3, LaneKind::Evidence, 300, 7_000)?;
    request(
        contract,
        CompilerProfile::default(),
        vec![governing, dependency, evidence],
    )
}

#[test]
fn golden_bundle_permutation_and_parallel_execution_are_identical() -> Result<(), Box<dyn Error>> {
    let input = baseline_request()?;
    let expected = DeterministicCompiler.compile(input.clone())?;
    assert_eq!(
        expected.plan.plan_id.as_str(),
        "89c22906-ee10-723b-9ce2-fa1b019c2f18"
    );
    assert_eq!(
        expected.manifest.manifest_id.as_str(),
        "122078ff8edd59dc1df3ae28f591de9058b9eaab4562d92fcc7529213822d2bfdad8"
    );
    assert_eq!(
        expected.bundle.bundle_id.as_str(),
        "12205febd5bb06ffbc44147cf0126543ded08d3b90c9169a16d992c3b14c59074e85"
    );
    expected.plan.validate()?;
    expected.manifest.validate()?;
    expected.bundle.validate()?;
    assert_eq!(
        expected.normalized_contract.job_goal,
        "Implement a verified change"
    );
    assert_eq!(expected.normalized_contract.purpose, "coding");
    assert_eq!(expected.bundle.blocks.len(), 3);
    assert_eq!(expected.bundle.total_tokens, 600);
    assert_eq!(expected.invalidation.catalog_versions.len(), 3);

    let mut permuted = input.clone();
    permuted.candidates.reverse();
    let reordered = DeterministicCompiler.compile(permuted)?;
    assert_eq!(reordered, expected);

    let mut handles = Vec::new();
    for _worker in 0..8 {
        let cloned = input.clone();
        handles.push(thread::spawn(move || DeterministicCompiler.compile(cloned)));
    }
    for handle in handles {
        let result = handle.join().map_err(|_| "compiler thread panicked")??;
        assert_eq!(result, expected);
    }
    Ok(())
}

#[test]
fn versioned_v2_profile_is_distinct_deterministic_and_ablatable() -> Result<(), Box<dyn Error>> {
    let v1 = DeterministicCompiler.compile(baseline_request()?)?;
    let mut input = baseline_request()?;
    input.profile = CompilerProfile::balanced_v2_candidate();
    input.frozen.compiler_profile_digest = compiler_profile_digest(&input.profile)?;
    let full = DeterministicCompiler.compile(input.clone())?;
    let replay = DeterministicCompiler.compile(input)?;
    assert_eq!(full, replay);
    assert_ne!(full.bundle.bundle_id, v1.bundle.bundle_id);
    assert_ne!(
        compiler_profile_digest(&CompilerProfile::default())?,
        compiler_profile_digest(&CompilerProfile::balanced_v2_candidate())?
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::default())?.as_str(),
        "122045f764c2c4b1a0ee6ecf6078050cfd939ff37c1b91edd8c4a38e8525e43cacb9"
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::balanced_v2_candidate())?.as_str(),
        "1220788e6159943dd2ddf35767d8935fdd8a7de5cb15c2242560ca7f551dc73437b2"
    );
    let h2 = CompilerProfile::balanced_v2_requirement_aware_candidate();
    let h1 = CompilerProfile::balanced_v2_candidate();
    assert_eq!(h2.local_swap_passes, h1.local_swap_passes);
    assert_eq!(h2.local_swap_alternatives, h1.local_swap_alternatives);
    assert_eq!(
        h2.requirement_coverage_weight,
        h1.requirement_coverage_weight
    );
    assert_eq!(h2.entity_coverage_weight, h1.entity_coverage_weight);
    assert_eq!(h2.loss_penalty, h1.loss_penalty);
    assert_eq!(h2.utility_density_ranking, h1.utility_density_ranking);
    assert_eq!(h2.minimum_lexical_match, h1.minimum_lexical_match);
    assert_eq!(
        h2.marginal_requirement_weight,
        h1.marginal_requirement_weight
    );
    assert_eq!(h2.marginal_entity_weight, h1.marginal_entity_weight);
    assert_eq!(h2.dependency_cost_penalty, h1.dependency_cost_penalty);
    assert_eq!(h2.diversity_weight, h1.diversity_weight);
    assert_eq!(h2.redundancy_penalty, h1.redundancy_penalty);
    assert_eq!(
        compiler_profile_digest(&h2)?.as_str(),
        "12204b4e01b01f305e7b00d7687965664a863b9ffa767f84272ee3826bc9ef57dbdb"
    );

    let mut ablation_ids = BTreeSet::new();
    for dimension in 0..8 {
        let mut profile = CompilerProfile::balanced_v2_candidate();
        match dimension {
            0 => profile.marginal_requirement_weight = 0,
            1 => profile.marginal_entity_weight = 0,
            2 => profile.dependency_cost_penalty = 0,
            3 => profile.diversity_weight = 0,
            4 => profile.redundancy_penalty = 0,
            5 => profile.utility_density_ranking = true,
            6 => profile.local_swap_passes = CompilerProfile::default().local_swap_passes,
            _ => profile.minimum_lexical_match = 0,
        }
        ablation_ids.insert(compiler_profile_digest(&profile)?);
    }
    assert_eq!(ablation_ids.len(), 8);
    assert!(!ablation_ids.contains(&compiler_profile_digest(
        &CompilerProfile::balanced_v2_candidate()
    )?));
    Ok(())
}

#[test]
fn balanced_v3_stops_redundant_optional_packing_after_coverage_saturates()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 100)]), Vec::new())?;
    let mut candidates = Vec::new();
    for value in 10..15_u8 {
        let mut item = candidate(value, LaneKind::Evidence, 20, 9_000)?;
        item.entity_coverage_bits = 1;
        item.features.entity_coverage_bits = 1;
        candidates.push(item);
    }
    let ranking = RequirementRankingEvidence::new(
        digest(234)?,
        BTreeSet::new(),
        BTreeSet::new(),
        Vec::new(),
    )?;

    let mut h2 = request(
        governed_contract.clone(),
        CompilerProfile::balanced_v2_requirement_aware_candidate(),
        candidates.clone(),
    )?;
    h2.ranking_evidence = Some(ranking.clone());
    let h2_output = DeterministicCompiler.compile(h2)?;

    let v3_profile = CompilerProfile::balanced_v3();
    let mut v3 = request(governed_contract, v3_profile.clone(), candidates)?;
    v3.ranking_evidence = Some(ranking);
    let v3_output = DeterministicCompiler.compile(v3)?;

    assert_eq!(h2_output.bundle.total_tokens, 100);
    assert_eq!(v3_output.bundle.total_tokens, 20);
    assert_eq!(v3_output.bundle.blocks.len(), 1);
    assert_ne!(
        compiler_profile_digest(&v3_profile)?,
        compiler_profile_digest(&CompilerProfile::balanced_v2_requirement_aware_candidate())?
    );
    assert_eq!(
        compiler_profile_digest(&v3_profile)?.as_str(),
        "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7"
    );
    Ok(())
}

#[test]
fn frozen_legacy_profile_snapshot_is_replayable() -> Result<(), Box<dyn Error>> {
    let v1_request = baseline_request()?;
    let v1 = DeterministicCompiler.compile(v1_request.clone())?;
    assert_eq!(DeterministicCompiler.compile(v1_request)?, v1);

    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 100)]), Vec::new())?;
    let mut candidates = Vec::new();
    for value in 10..15_u8 {
        let mut item = candidate(value, LaneKind::Evidence, 20, 9_000)?;
        item.entity_coverage_bits = 1;
        item.features.entity_coverage_bits = 1;
        candidates.push(item);
    }
    let ranking = RequirementRankingEvidence::new(
        digest(234)?,
        BTreeSet::new(),
        BTreeSet::new(),
        Vec::new(),
    )?;
    let mut v3_request = request(
        governed_contract,
        CompilerProfile::balanced_v3(),
        candidates,
    )?;
    v3_request.ranking_evidence = Some(ranking);
    let v3 = DeterministicCompiler.compile(v3_request.clone())?;
    assert_eq!(DeterministicCompiler.compile(v3_request.clone())?, v3);

    let mut invalid_v1 = baseline_request()?;
    invalid_v1.profile.minimum_lexical_match = 1;
    invalid_v1.frozen.compiler_profile_digest = compiler_profile_digest(&invalid_v1.profile)?;
    assert_eq!(
        DeterministicCompiler
            .compile(invalid_v1)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );
    let mut invalid_v3 = v3_request;
    invalid_v3.profile.sufficient_items_per_requirement = 0;
    invalid_v3.frozen.compiler_profile_digest = compiler_profile_digest(&invalid_v3.profile)?;
    assert_eq!(
        DeterministicCompiler
            .compile(invalid_v3)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );
    let mut pin_mismatch = baseline_request()?;
    pin_mismatch.frozen.compiler_profile_digest = digest(229)?;
    assert_eq!(
        DeterministicCompiler
            .compile(pin_mismatch)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::PinMismatch)
    );
    let missing_ranking = request(
        contract(BTreeMap::from([(LaneKind::Evidence, 100)]), Vec::new())?,
        CompilerProfile::balanced_v3(),
        Vec::new(),
    )?;
    assert_eq!(
        DeterministicCompiler
            .compile(missing_ranking)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );
    let mut unexpected_ranking = baseline_request()?;
    unexpected_ranking.ranking_evidence = Some(RequirementRankingEvidence::new(
        digest(234)?,
        BTreeSet::new(),
        BTreeSet::new(),
        Vec::new(),
    )?);
    assert_eq!(
        DeterministicCompiler
            .compile(unexpected_ranking)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );

    let selected = v3
        .bundle
        .blocks
        .iter()
        .map(|block| {
            block
                .provenance
                .first()
                .map(|version| version.as_str())
                .ok_or("legacy block provenance is empty")
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(",");
    assert_eq!(
        (
            RetrievalProfile::BalancedV1.identifier(),
            RetrievalProfile::BalancedV1.digest()?.as_str(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate.identifier(),
            RetrievalProfile::BalancedV2RequirementAwareCandidate
                .digest()?
                .as_str(),
            compiler_profile_digest(&CompilerProfile::default())?.as_str(),
            compiler_profile_digest(&CompilerProfile::balanced_v3())?.as_str(),
        ),
        (
            "cigar.retrieval-profile.balanced.v1",
            "1220c605f248bd6f9d7c476324630b0839fb4c7423009f47f3f13b8b1a62cfeb72ea",
            "cigar.retrieval-profile.balanced.v2-candidate.2",
            "12200a182e948a6f1db35e59b32a5ea9963807f26796303c65065385b84c33f1316a",
            "122045f764c2c4b1a0ee6ecf6078050cfd939ff37c1b91edd8c4a38e8525e43cacb9",
            "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7",
        )
    );
    assert_eq!(
        (
            v1.plan.plan_id.as_str(),
            v1.manifest.manifest_id.as_str(),
            v1.bundle.bundle_id.as_str(),
            v3.plan.plan_id.as_str(),
            v3.manifest.manifest_id.as_str(),
            v3.bundle.bundle_id.as_str(),
            selected.as_str(),
        ),
        (
            "89c22906-ee10-723b-9ce2-fa1b019c2f18",
            "122078ff8edd59dc1df3ae28f591de9058b9eaab4562d92fcc7529213822d2bfdad8",
            "12205febd5bb06ffbc44147cf0126543ded08d3b90c9169a16d992c3b14c59074e85",
            "83eda732-c46f-7e8a-b3c6-520ea67aa4cb",
            "12205569e9e015d51959c414f9ff47f91a763ccc727a84ef0ad4435cab70cef336df",
            "1220bd714d1809e35c467a71b3f6a80f647a15f48707fd9bda80c2739b4f7e4f04cc",
            "12200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        )
    );
    assert!(v1.packing_evidence.is_none());
    assert!(v3.packing_evidence.is_none());
    Ok(())
}

#[test]
fn balanced_v4_is_digest_bound_and_preserves_every_legacy_profile_digest()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::default())?.as_str(),
        "122045f764c2c4b1a0ee6ecf6078050cfd939ff37c1b91edd8c4a38e8525e43cacb9"
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::balanced_v2_candidate())?.as_str(),
        "1220788e6159943dd2ddf35767d8935fdd8a7de5cb15c2242560ca7f551dc73437b2"
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::balanced_v2_requirement_aware_candidate())?
            .as_str(),
        "12204b4e01b01f305e7b00d7687965664a863b9ffa767f84272ee3826bc9ef57dbdb"
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::balanced_v3())?.as_str(),
        "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7"
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::balanced_v4())?.as_str(),
        "1220d28b42286c3db066f73b70b670ee32b13311319fd512d682e9f843864749bcf2"
    );
    Ok(())
}

#[test]
fn balanced_v4_stops_cheap_low_quality_flood_and_seals_content_free_evidence()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 200)]), Vec::new())?;
    let mut useful = candidate(10, LaneKind::Evidence, 20, 9_000)?;
    useful.entity_coverage_bits = 1;
    useful.features.entity_coverage_bits = 1;
    let mut candidates = vec![useful.clone()];
    for value in 11..61_u8 {
        candidates.push(candidate(value, LaneKind::Evidence, 1, 8_000)?);
    }
    let output = DeterministicCompiler.compile(v4_request(governed_contract, candidates)?)?;
    assert_eq!(output.bundle.total_tokens, 20);
    assert_eq!(output.bundle.blocks.len(), 1);
    assert_eq!(
        output.bundle.blocks.first().ok_or("block")?.provenance,
        vec![useful.version_id]
    );
    let evidence = output.packing_evidence.as_ref().ok_or("packing evidence")?;
    evidence.validate()?;
    assert_eq!(
        evidence.stop_reason,
        PackingStopReason::NonPositiveMarginalUtility
    );
    assert_eq!(evidence.decisions.len(), 1);
    assert_eq!(
        evidence.decisions.first().ok_or("decision")?.basis,
        PackingDecisionBasis::MarginalUtility
    );
    let extensions = serde_json::to_value(&output.manifest.extensions)?;
    let sealed = extensions
        .get("cigar/packing-evidence.v1")
        .ok_or("sealed packing evidence")?;
    assert!(
        sealed
            .to_string()
            .contains(evidence.evidence_digest.as_str())
    );
    let mut corrupted = evidence.clone();
    corrupted
        .decisions
        .first_mut()
        .ok_or("decision")?
        .incremental_tokens ^= 1;
    assert_eq!(
        corrupted.validate().map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn balanced_v4_independent_blocking_fast_path_matches_general_packer() -> Result<(), Box<dyn Error>>
{
    let governed_contract = contract(
        BTreeMap::from([(LaneKind::Evidence, 400)]),
        vec![
            requirement(true, "first independent requirement")?,
            requirement(true, "second independent requirement")?,
        ],
    )?;
    let mut candidates = Vec::new();
    for requirement_index in 0..2_usize {
        for alternative in 0..4_u8 {
            let value = 70_u8
                .checked_add(u8::try_from(requirement_index)?.saturating_mul(4))
                .and_then(|value| value.checked_add(alternative))
                .ok_or("candidate value overflow")?;
            let tokens = 20_u32
                .checked_add(u32::from(alternative))
                .ok_or("candidate token overflow")?;
            let mut item = candidate(value, LaneKind::Evidence, tokens, 0)?;
            item.requirement_indices.insert(requirement_index);
            item.entity_coverage_bits = 1_u64
                .checked_shl(u32::try_from(requirement_index)?)
                .ok_or("entity bit overflow")?;
            item.features = CandidateFeatures {
                lexical_match: 8_000,
                estimated_tokens: tokens,
                requirement_coverage_bits: item.entity_coverage_bits,
                entity_coverage_bits: item.entity_coverage_bits,
                ..CandidateFeatures::default()
            };
            candidates.push(item);
        }
    }

    let fast = DeterministicCompiler
        .compile(v4_request(governed_contract.clone(), candidates.clone())?)?;
    assert_eq!(
        fast.ranking_evidence
            .as_ref()
            .ok_or("fast ranking evidence")?
            .decisions
            .len(),
        8
    );
    let fast_extensions = serde_json::to_value(&fast.manifest.extensions)?;
    assert!(
        fast_extensions
            .get("cigar/ranking-evidence.v1")
            .ok_or("sealed ranking evidence")?
            .to_string()
            .contains("digest-bound-output")
    );
    assert!(
        fast_extensions
            .get("cigar/ranking-decisions.v1/000")
            .is_none()
    );
    assert_eq!(
        semantic_multihash_v1(SemanticEnvelopeProfile::Manifest, &fast.manifest)?,
        fast.manifest.manifest_id.as_str()
    );
    assert_eq!(
        semantic_multihash_v1(SemanticEnvelopeProfile::Bundle, &fast.bundle)?,
        fast.bundle.bundle_id.as_str()
    );
    let mut fallback_profile = CompilerProfile::balanced_v4();
    fallback_profile
        .maximum_items
        .insert(LaneKind::Evidence, u16::MAX);
    let ranking_evidence = v4_ranking_evidence(&candidates, BTreeSet::from([0, 1]))?;
    let mut fallback_request = request(governed_contract, fallback_profile, candidates)?;
    fallback_request.ranking_evidence = Some(ranking_evidence);
    let general = DeterministicCompiler.compile(fallback_request)?;

    let fast_evidence = fast.packing_evidence.ok_or("fast packing evidence")?;
    let general_evidence = general.packing_evidence.ok_or("general packing evidence")?;
    assert_eq!(fast_evidence.decisions, general_evidence.decisions);
    assert_eq!(
        fast_evidence.dominance_decisions,
        general_evidence.dominance_decisions
    );
    assert_eq!(fast_evidence.stop_reason, general_evidence.stop_reason);
    assert_eq!(fast.content_equivalence, general.content_equivalence);
    assert_eq!(
        fast.bundle
            .blocks
            .iter()
            .map(|block| (&block.provenance, block.token_count))
            .collect::<Vec<_>>(),
        general
            .bundle
            .blocks
            .iter()
            .map(|block| (&block.provenance, block.token_count))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn balanced_v4_requirement_free_fast_path_matches_general_packer() -> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 96)]), Vec::new())?;
    let mut candidates = Vec::new();
    for index in 0..96_u8 {
        let value = index.checked_add(100).ok_or("candidate value overflow")?;
        let mut item = candidate(value, LaneKind::Evidence, 1, 8_000)?;
        item.entity_coverage_bits = 1_u64
            .checked_shl(u32::from(index % 64))
            .ok_or("entity bit overflow")?;
        item.features = features(8_000, 1);
        item.features.entity_coverage_bits = item.entity_coverage_bits;
        candidates.push(item);
    }

    let fast = DeterministicCompiler
        .compile(v4_request(governed_contract.clone(), candidates.clone())?)?;
    let mut fallback_profile = CompilerProfile::balanced_v4();
    fallback_profile
        .maximum_items
        .insert(LaneKind::Evidence, u16::MAX);
    let ranking_evidence = v4_ranking_evidence(&candidates, BTreeSet::new())?;
    let mut fallback_request = request(governed_contract, fallback_profile, candidates)?;
    fallback_request.ranking_evidence = Some(ranking_evidence);
    let general = DeterministicCompiler.compile(fallback_request)?;

    let fast_evidence = fast.packing_evidence.ok_or("fast packing evidence")?;
    let general_evidence = general.packing_evidence.ok_or("general packing evidence")?;
    assert!(!fast_evidence.decisions.is_empty());
    assert_eq!(fast_evidence.decisions, general_evidence.decisions);
    assert_eq!(
        fast_evidence.dominance_decisions,
        general_evidence.dominance_decisions
    );
    assert_eq!(fast_evidence.stop_reason, general_evidence.stop_reason);
    assert_eq!(fast.content_equivalence, general.content_equivalence);
    assert_eq!(
        fast.bundle
            .blocks
            .iter()
            .map(|block| (&block.provenance, block.token_count))
            .collect::<Vec<_>>(),
        general
            .bundle
            .blocks
            .iter()
            .map(|block| (&block.provenance, block.token_count))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn balanced_v4_reserves_exactly_one_independent_effect_corroborator() -> Result<(), Box<dyn Error>>
{
    let mut governed_contract = contract(
        BTreeMap::from([(LaneKind::Evidence, 100)]),
        vec![requirement(true, "authorize effect")?],
    )?;
    governed_contract.operation_class = OperationClass::ExternalMutation;
    let mut primary = candidate(20, LaneKind::Evidence, 20, 9_500)?;
    primary.requirement_indices.insert(0);
    let mut independent = candidate(21, LaneKind::Evidence, 20, 9_000)?;
    independent.requirement_indices.insert(0);
    let mut redundant = candidate(22, LaneKind::Evidence, 20, 8_500)?;
    redundant.requirement_indices.insert(0);
    redundant.canonical_uri = independent.canonical_uri.clone();
    redundant.lineage_id = independent.lineage_id.clone();

    let output = DeterministicCompiler.compile(v4_request(
        governed_contract,
        vec![primary.clone(), independent.clone(), redundant],
    )?)?;
    let selected = output
        .plan
        .lanes
        .iter()
        .flat_map(|lane| lane.candidate_versions.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        selected,
        BTreeSet::from([primary.version_id, independent.version_id])
    );
    let evidence = output.packing_evidence.ok_or("packing evidence")?;
    assert_eq!(evidence.decisions.len(), 2);
    assert_eq!(
        evidence.decisions.get(1).ok_or("corroboration")?.basis,
        PackingDecisionBasis::IndependentCorroboration
    );
    assert_eq!(
        evidence
            .decisions
            .get(1)
            .ok_or("corroboration")?
            .independently_corroborated_requirements,
        1
    );
    Ok(())
}

#[test]
fn balanced_v4_caches_shared_closures_and_rejects_a_giant_dependency() -> Result<(), Box<dyn Error>>
{
    let governed_contract = contract(
        BTreeMap::from([(LaneKind::Evidence, 30), (LaneKind::History, 15)]),
        vec![
            requirement(false, "first")?,
            requirement(false, "second")?,
            requirement(false, "giant")?,
        ],
    )?;
    let shared = candidate(30, LaneKind::History, 10, 8_000)?;
    let mut first = candidate(31, LaneKind::Evidence, 10, 9_000)?;
    first.requirement_indices.insert(0);
    first.dependencies.insert(shared.version_id.clone());
    let mut second = candidate(32, LaneKind::Evidence, 10, 8_900)?;
    second.requirement_indices.insert(1);
    second.dependencies.insert(shared.version_id.clone());
    let giant_dependency = candidate(33, LaneKind::History, 20, 9_500)?;
    let mut giant = candidate(34, LaneKind::Evidence, 5, 9_500)?;
    giant.requirement_indices.insert(2);
    giant
        .dependencies
        .insert(giant_dependency.version_id.clone());

    let output = DeterministicCompiler.compile(v4_request(
        governed_contract,
        vec![shared, first, second, giant_dependency, giant],
    )?)?;
    assert_eq!(output.bundle.total_tokens, 30);
    assert_eq!(output.bundle.blocks.len(), 3);
    assert_eq!(
        output
            .bundle
            .blocks
            .iter()
            .filter(|block| block.lane == LaneKind::History)
            .count(),
        1
    );
    assert_eq!(
        output
            .packing_evidence
            .ok_or("packing evidence")?
            .stop_reason,
        PackingStopReason::CapacitySaturated
    );
    Ok(())
}

#[test]
fn balanced_v4_dominance_and_permutation_are_semantically_metamorphic() -> Result<(), Box<dyn Error>>
{
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 50)]), Vec::new())?;
    let mut better = candidate(40, LaneKind::Evidence, 10, 9_500)?;
    better.entity_coverage_bits = 1;
    better.features.entity_coverage_bits = 1;
    let mut dominated = candidate(41, LaneKind::Evidence, 10, 8_000)?;
    dominated.entity_coverage_bits = 1;
    dominated.features.entity_coverage_bits = 1;
    dominated.canonical_uri = better.canonical_uri.clone();
    dominated.lineage_id = better.lineage_id.clone();
    dominated.provenance_digest = better.provenance_digest.clone();

    let baseline = DeterministicCompiler
        .compile(v4_request(governed_contract.clone(), vec![better.clone()])?)?;
    let with_dominated = DeterministicCompiler.compile(v4_request(
        governed_contract.clone(),
        vec![better.clone(), dominated.clone()],
    )?)?;
    assert_eq!(baseline.bundle.blocks, with_dominated.bundle.blocks);
    let dominance = with_dominated
        .packing_evidence
        .as_ref()
        .ok_or("packing evidence")?
        .dominance_decisions
        .first()
        .ok_or("dominance")?;
    assert_eq!(dominance.dominated_version, dominated.version_id);
    assert_eq!(
        dominance.reason,
        cigar_compiler::PackingDominanceReason::SameProvenanceNoWeakerValue
    );

    let mut permuted = v4_request(governed_contract, vec![dominated, better])?;
    permuted.candidates.reverse();
    let reordered = DeterministicCompiler.compile(permuted)?;
    assert_eq!(with_dominated, reordered);
    Ok(())
}

#[test]
fn balanced_v4_dominance_does_not_prune_distinct_governance_or_provenance()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 50)]), Vec::new())?;
    let mut better = candidate(42, LaneKind::Evidence, 10, 9_500)?;
    better.entity_coverage_bits = 1;
    better.features.entity_coverage_bits = 1;
    let mut distinct = candidate(43, LaneKind::Evidence, 10, 8_000)?;
    distinct.entity_coverage_bits = 1;
    distinct.features.entity_coverage_bits = 1;
    distinct.canonical_uri = better.canonical_uri.clone();
    distinct.lineage_id = better.lineage_id.clone();
    distinct.provenance_digest = better.provenance_digest.clone();

    let mut policy_better = better.clone();
    let mut policy_distinct = distinct.clone();
    let redacted = RepresentationVariant::redacted(digest(220)?, 10)?;
    policy_better.representations = vec![redacted.clone()];
    policy_distinct.representations = vec![redacted];
    policy_better.policy_outcome = PolicyOutcome::Redact;

    let mut classification_distinct = distinct.clone();
    classification_distinct.classification = Classification::Confidential;

    let mut authority_distinct = distinct.clone();
    authority_distinct.instruction_authority = InstructionAuthority::Advisory;

    let mut provenance_distinct = distinct;
    provenance_distinct.provenance_digest = digest(221)?;

    for candidates in [
        vec![policy_better, policy_distinct],
        vec![better.clone(), classification_distinct],
        vec![better.clone(), authority_distinct],
        vec![better, provenance_distinct],
    ] {
        let output =
            DeterministicCompiler.compile(v4_request(governed_contract.clone(), candidates)?)?;
        assert!(
            output
                .packing_evidence
                .ok_or("packing evidence")?
                .dominance_decisions
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn balanced_v4_exact_counts_and_closure_cache_invalidate_on_tokenizer_or_candidate_change()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 40)]), Vec::new())?;
    let mut exact = candidate(50, LaneKind::Evidence, 17, 9_000)?;
    exact.entity_coverage_bits = 1;
    exact.features.entity_coverage_bits = 1;
    let first = DeterministicCompiler
        .compile(v4_request(governed_contract.clone(), vec![exact.clone()])?)?;
    assert_eq!(first.bundle.total_tokens, 17);

    let mut changed_tokens = exact.clone();
    changed_tokens
        .representations
        .first_mut()
        .ok_or("representation")?
        .token_count = 18;
    let second = DeterministicCompiler
        .compile(v4_request(governed_contract.clone(), vec![changed_tokens])?)?;
    assert_eq!(second.bundle.total_tokens, 18);
    assert_ne!(
        first
            .packing_evidence
            .as_ref()
            .ok_or("first evidence")?
            .workspace_fingerprint,
        second
            .packing_evidence
            .as_ref()
            .ok_or("second evidence")?
            .workspace_fingerprint
    );

    let mut changed_tokenizer = governed_contract;
    changed_tokenizer.target.tokenizer_fingerprint = digest(77)?;
    let third = DeterministicCompiler.compile(v4_request(changed_tokenizer, vec![exact])?)?;
    assert_ne!(
        first
            .packing_evidence
            .ok_or("first evidence")?
            .workspace_fingerprint,
        third
            .packing_evidence
            .ok_or("third evidence")?
            .workspace_fingerprint
    );
    Ok(())
}

#[test]
fn balanced_v4_retains_all_mandatory_items_and_reports_exact_unsatisfiable_bound()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Rules, 40)]), Vec::new())?;
    let mut mandatory = Vec::new();
    for value in 60..64_u8 {
        let mut item = candidate(value, LaneKind::Rules, 10, 8_000)?;
        item.mandatory = true;
        mandatory.push(item);
    }
    let output =
        DeterministicCompiler.compile(v4_request(governed_contract.clone(), mandatory.clone())?)?;
    assert_eq!(output.bundle.blocks.len(), 4);
    assert!(
        output
            .packing_evidence
            .ok_or("packing evidence")?
            .decisions
            .iter()
            .all(|decision| decision.basis == PackingDecisionBasis::Mandatory)
    );

    let mut overflow = mandatory;
    let mut fifth = candidate(64, LaneKind::Rules, 10, 8_000)?;
    fifth.mandatory = true;
    overflow.push(fifth);
    let Err(error) = DeterministicCompiler.compile(v4_request(governed_contract, overflow)?) else {
        return Err("mandatory overflow unexpectedly compiled".into());
    };
    assert_eq!(error.code(), CompilerErrorCode::BudgetUnsatisfiable);
    assert_eq!(error.minimum_required_tokens(), Some(50));
    Ok(())
}

#[test]
fn balanced_v4_lane_bounds_budget_growth_and_denied_removal_preserve_authorized_selection()
-> Result<(), Box<dyn Error>> {
    let small_contract = contract(BTreeMap::from([(LaneKind::Evidence, 20)]), Vec::new())?;
    let mut mandatory = candidate(70, LaneKind::Evidence, 10, 8_000)?;
    mandatory.mandatory = true;
    let mut useful = candidate(71, LaneKind::Evidence, 10, 9_000)?;
    useful.entity_coverage_bits = 1;
    useful.features.entity_coverage_bits = 1;
    let mut denied = candidate(72, LaneKind::Evidence, 1, 10_000)?;
    denied.policy_outcome = PolicyOutcome::Deny;

    let mut bounded = v4_request(
        small_contract.clone(),
        vec![mandatory.clone(), useful.clone(), denied.clone()],
    )?;
    bounded.profile.minimum_items.insert(LaneKind::Evidence, 2);
    bounded.profile.maximum_items.insert(LaneKind::Evidence, 2);
    bounded.frozen.compiler_profile_digest = compiler_profile_digest(&bounded.profile)?;
    let with_denied = DeterministicCompiler.compile(bounded)?;
    assert_eq!(with_denied.bundle.blocks.len(), 2);

    let mut without_denied = v4_request(small_contract, vec![mandatory.clone(), useful.clone()])?;
    without_denied
        .profile
        .minimum_items
        .insert(LaneKind::Evidence, 2);
    without_denied
        .profile
        .maximum_items
        .insert(LaneKind::Evidence, 2);
    without_denied.frozen.compiler_profile_digest =
        compiler_profile_digest(&without_denied.profile)?;
    let authorized_only = DeterministicCompiler.compile(without_denied)?;
    assert_eq!(with_denied.bundle.blocks, authorized_only.bundle.blocks);

    let larger_contract = contract(BTreeMap::from([(LaneKind::Evidence, 40)]), Vec::new())?;
    let larger = DeterministicCompiler.compile(v4_request(
        larger_contract,
        vec![mandatory.clone(), useful],
    )?)?;
    assert!(
        larger
            .bundle
            .blocks
            .iter()
            .any(|block| { block.provenance.first() == Some(&mandatory.version_id) })
    );
    Ok(())
}

#[test]
fn balanced_v4_preserves_alias_conflict_and_dependency_safety_before_packing()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 40)]), Vec::new())?;
    let mut alias_a = candidate(80, LaneKind::Evidence, 10, 9_000)?;
    alias_a.entity_coverage_bits = 1;
    alias_a.features.entity_coverage_bits = 1;
    let mut alias_b = candidate(81, LaneKind::Evidence, 10, 8_500)?;
    alias_b.entity_coverage_bits = 1;
    alias_b.features.entity_coverage_bits = 1;
    alias_b.representations = alias_a.representations.clone();
    let aliased = DeterministicCompiler.compile(v4_request(
        governed_contract.clone(),
        vec![alias_a.clone(), alias_b.clone()],
    )?)?;
    assert_eq!(aliased.bundle.blocks.len(), 1);
    assert!(aliased.content_equivalence.iter().any(|class| {
        class.member_versions
            == BTreeSet::from([alias_a.version_id.clone(), alias_b.version_id.clone()])
    }));

    let mut older = candidate(82, LaneKind::Evidence, 10, 8_500)?;
    older.entity_coverage_bits = 1;
    older.features.entity_coverage_bits = 1;
    older.claim = Some(CandidateClaim {
        key: "network.mode".to_owned(),
        value_digest: digest(90)?,
        valid_at: time("2026-08-16T00:00:00Z")?,
        observed_at: time("2026-08-16T00:00:00Z")?,
        authority: 5,
        verified: true,
    });
    let mut newer = candidate(83, LaneKind::Evidence, 10, 8_500)?;
    newer.entity_coverage_bits = 1;
    newer.features.entity_coverage_bits = 1;
    newer.claim = Some(CandidateClaim {
        key: "network.mode".to_owned(),
        value_digest: digest(91)?,
        valid_at: time("2026-08-17T00:00:00Z")?,
        observed_at: time("2026-08-17T00:00:00Z")?,
        authority: 5,
        verified: true,
    });
    let reconciled = DeterministicCompiler.compile(v4_request(
        governed_contract.clone(),
        vec![older.clone(), newer.clone()],
    )?)?;
    let selected = reconciled
        .plan
        .lanes
        .iter()
        .flat_map(|lane| lane.candidate_versions.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(selected.contains(&newer.version_id));
    assert!(!selected.contains(&older.version_id));

    let mut cycle_a = candidate(84, LaneKind::Evidence, 10, 9_000)?;
    let mut cycle_b = candidate(85, LaneKind::Evidence, 10, 9_000)?;
    cycle_a.dependencies.insert(cycle_b.version_id.clone());
    cycle_b.dependencies.insert(cycle_a.version_id.clone());
    let Err(error) =
        DeterministicCompiler.compile(v4_request(governed_contract, vec![cycle_a, cycle_b])?)
    else {
        return Err("dependency cycle unexpectedly compiled".into());
    };
    assert_eq!(error.code(), CompilerErrorCode::InvalidDependency);
    Ok(())
}

#[test]
#[ignore = "explicit H094-300 compiler p95 diagnostic"]
fn benchmark_balanced_v4_packing_against_frozen_v3_path() -> Result<(), Box<dyn Error>> {
    for size in [128_usize, 512] {
        let governed_contract = contract(
            BTreeMap::from([(LaneKind::Evidence, u32::try_from(size)?)]),
            Vec::new(),
        )?;
        let mut candidates = Vec::with_capacity(size);
        for index in 0..size {
            let value = u64::try_from(index)?
                .checked_add(1)
                .ok_or("value overflow")?;
            let entity_bit = u32::try_from(index % 64)?;
            candidates.push(CompilerCandidate {
                version_id: version_u64(value)?,
                logical_id: version_u64(value)?,
                lineage_id: lineage(u16::try_from(value)?)?,
                canonical_uri: SourceUri::new(format!("file:///packing/{index:08x}.md"))?,
                lane: LaneKind::Evidence,
                mandatory: false,
                requirement_indices: BTreeSet::new(),
                entity_coverage_bits: 1_u64.checked_shl(entity_bit).ok_or("entity shift")?,
                features: features(8_000, 1),
                policy_outcome: PolicyOutcome::Allow,
                pre_exclusion_reason: None,
                classification: Classification::Internal,
                instruction_authority: InstructionAuthority::Data,
                dependencies: BTreeSet::new(),
                representations: vec![RepresentationVariant::exact(
                    digest_u64(value.checked_add(10_000).ok_or("digest overflow")?)?,
                    1,
                )?],
                claim: None,
                provenance_digest: digest_u64(
                    value.checked_add(20_000).ok_or("provenance overflow")?,
                )?,
            });
        }
        let mut v3 = request(
            governed_contract.clone(),
            CompilerProfile::balanced_v3(),
            candidates.clone(),
        )?;
        v3.ranking_evidence = Some(RequirementRankingEvidence::new(
            digest(234)?,
            BTreeSet::new(),
            BTreeSet::new(),
            Vec::new(),
        )?);
        let v4 = v4_request(governed_contract, candidates)?;
        let _v3_warm = DeterministicCompiler.compile(v3.clone())?;
        let _v4_warm = DeterministicCompiler.compile(v4.clone())?;
        let mut v3_samples = Vec::new();
        let mut v4_samples = Vec::new();
        for _sample in 0..40 {
            let started = std::time::Instant::now();
            let _output = DeterministicCompiler.compile(v3.clone())?;
            v3_samples.push(started.elapsed());
            let started = std::time::Instant::now();
            let _output = DeterministicCompiler.compile(v4.clone())?;
            v4_samples.push(started.elapsed());
        }
        v3_samples.sort();
        v4_samples.sort();
        let v3_p95 = *v3_samples.get(37).ok_or("v3 p95")?;
        let v4_p95 = *v4_samples.get(37).ok_or("v4 p95")?;
        println!(
            "H094_300_PACKING size={size} v3_p95_us={} v4_p95_us={} ratio_millionths={}",
            v3_p95.as_micros(),
            v4_p95.as_micros(),
            v4_p95
                .as_nanos()
                .checked_mul(1_000_000)
                .and_then(|value| value.checked_div(v3_p95.as_nanos().max(1)))
                .ok_or("ratio overflow")?
        );
    }
    Ok(())
}

#[test]
fn h2_ranking_evidence_is_required_validated_and_sealed_into_the_manifest()
-> Result<(), Box<dyn Error>> {
    let contract = contract(
        BTreeMap::from([(LaneKind::Evidence, 200)]),
        vec![requirement(true, "critical implementation")?],
    )?;
    let mut useful = candidate(42, LaneKind::Evidence, 200, 8_000)?;
    useful.requirement_indices.insert(0);
    useful.entity_coverage_bits = 0b111;
    useful.features.entity_coverage_bits = 0b111;
    let mut generic = candidate(43, LaneKind::Evidence, 200, 9_500)?;
    generic.requirement_indices.insert(0);
    generic.entity_coverage_bits = 0b001;
    generic.features.entity_coverage_bits = 0b001;
    let retrieval_profile = RetrievalProfile::BalancedV2RequirementAwareCandidate;
    let useful_base_score = useful.features.score(retrieval_profile)?;
    let generic_base_score = generic.features.score(retrieval_profile)?;
    assert!(generic_base_score > useful_base_score);
    let selection =
        QueryPlannerProfile::balanced_v2_requirement_aware_candidate().candidate_selection;
    let critical_requirement_gain = selection.critical_requirement_gain;
    let useful_concept_gain = selection
        .concept_gain
        .checked_mul(3)
        .ok_or("concept gain overflow")?;
    let diversity_gain = selection
        .source_diversity_gain
        .checked_add(selection.section_diversity_gain)
        .and_then(|value| value.checked_add(selection.kind_diversity_gain))
        .ok_or("diversity gain overflow")?;
    let useful_adjusted_score = useful_base_score
        .checked_add(critical_requirement_gain)
        .and_then(|value| value.checked_add(useful_concept_gain))
        .and_then(|value| value.checked_add(diversity_gain))
        .ok_or("ranking score overflow")?;
    let generic_initial_score = generic_base_score
        .checked_add(critical_requirement_gain)
        .and_then(|value| value.checked_add(selection.concept_gain))
        .and_then(|value| value.checked_add(diversity_gain))
        .and_then(|value| value.checked_sub(selection.generic_match_penalty))
        .ok_or("generic initial score overflow")?;
    assert!(useful_adjusted_score > generic_initial_score);
    let generic_diversity_gain = selection
        .source_diversity_gain
        .checked_add(selection.section_diversity_gain)
        .ok_or("generic diversity gain overflow")?;
    let generic_redundancy_penalty = selection
        .redundant_requirement_penalty
        .checked_add(selection.redundant_concept_penalty)
        .ok_or("generic redundancy penalty overflow")?;
    let generic_adjusted_score = generic_base_score
        .checked_add(generic_diversity_gain)
        .and_then(|value| value.checked_sub(selection.generic_match_penalty))
        .and_then(|value| value.checked_sub(generic_redundancy_penalty))
        .and_then(|value| value.checked_sub(selection.same_kind_penalty))
        .ok_or("generic adjusted score overflow")?;
    let evidence = RequirementRankingEvidence::new(
        digest(234)?,
        BTreeSet::from([0]),
        BTreeSet::new(),
        vec![
            CandidateRankingDecision {
                ordinal: 1,
                selected_version: useful.version_id.clone(),
                basis: CandidateSelectionBasis::CriticalRequirement,
                newly_covered_requirements: 1,
                newly_covered_critical_requirements: 1,
                newly_covered_concepts: 3,
                source_diversity: true,
                section_diversity: true,
                kind_diversity: true,
                factors: CandidateRankingFactors {
                    base_score: useful_base_score,
                    critical_requirement_gain,
                    requirement_gain: 0,
                    concept_gain: useful_concept_gain,
                    diversity_gain,
                    generic_penalty: 0,
                    redundancy_penalty: 0,
                    similarity_penalty: 0,
                    adjusted_score: useful_adjusted_score,
                },
                next_best_version: Some(generic.version_id.clone()),
                next_best_adjusted_score: Some(generic_initial_score),
                uncovered_critical_after: 0,
            },
            CandidateRankingDecision {
                ordinal: 2,
                selected_version: generic.version_id.clone(),
                basis: CandidateSelectionBasis::Protected,
                newly_covered_requirements: 0,
                newly_covered_critical_requirements: 0,
                newly_covered_concepts: 0,
                source_diversity: true,
                section_diversity: true,
                kind_diversity: false,
                factors: CandidateRankingFactors {
                    base_score: generic_base_score,
                    critical_requirement_gain: 0,
                    requirement_gain: 0,
                    concept_gain: 0,
                    diversity_gain: generic_diversity_gain,
                    generic_penalty: selection.generic_match_penalty,
                    redundancy_penalty: generic_redundancy_penalty,
                    similarity_penalty: selection.same_kind_penalty,
                    adjusted_score: generic_adjusted_score,
                },
                next_best_version: None,
                next_best_adjusted_score: None,
                uncovered_critical_after: 0,
            },
        ],
    )?;
    let profile = CompilerProfile::balanced_v2_requirement_aware_candidate();
    let mut missing = request(
        contract.clone(),
        profile.clone(),
        vec![useful.clone(), generic],
    )?;
    assert_eq!(
        DeterministicCompiler
            .compile(missing.clone())
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );

    missing.ranking_evidence = Some(evidence.clone());
    let output = DeterministicCompiler.compile(missing.clone())?;
    assert_eq!(output.ranking_evidence, Some(evidence.clone()));
    let selected = output
        .bundle
        .blocks
        .first()
        .ok_or("missing selected block")?;
    assert_eq!(selected.provenance, vec![useful.version_id]);
    let extensions = serde_json::to_value(&output.manifest.extensions)?;
    assert!(extensions.get("cigar/ranking-evidence.v1").is_some());
    assert!(extensions.get("cigar/ranking-decisions.v1/000").is_some());

    let mut corrupted = evidence;
    corrupted
        .decisions
        .first_mut()
        .ok_or("missing decision to corrupt")?
        .factors
        .adjusted_score ^= 1;
    missing.ranking_evidence = Some(corrupted);
    assert_eq!(
        DeterministicCompiler
            .compile(missing)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn content_equivalence_unions_obligations_provenance_citations_and_invalidation()
-> Result<(), Box<dyn Error>> {
    let requirements = vec![
        requirement(true, "first required source")?,
        requirement(true, "second required source")?,
    ];
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 30)]), requirements)?;
    let mut first = candidate(80, LaneKind::Evidence, 10, 7_000)?;
    let mut representative = candidate(81, LaneKind::Evidence, 10, 10_000)?;
    let mut first_dependency = candidate(82, LaneKind::Evidence, 5, 6_000)?;
    let mut second_dependency = candidate(83, LaneKind::Evidence, 5, 6_000)?;
    first.mandatory = true;
    first.requirement_indices.insert(0);
    representative.requirement_indices.insert(1);
    representative.representations = first.representations.clone();
    first
        .dependencies
        .insert(first_dependency.version_id.clone());
    representative
        .dependencies
        .insert(second_dependency.version_id.clone());
    first_dependency.entity_coverage_bits = 0b0001;
    second_dependency.entity_coverage_bits = 0b0010;
    let original = [
        first.clone(),
        representative.clone(),
        first_dependency.clone(),
        second_dependency.clone(),
    ];

    let mut expected = None;
    for first_index in 0..original.len() {
        for second_index in 0..original.len() {
            if second_index == first_index {
                continue;
            }
            for third_index in 0..original.len() {
                if third_index == first_index || third_index == second_index {
                    continue;
                }
                let fourth_index = (0..original.len())
                    .find(|index| {
                        *index != first_index && *index != second_index && *index != third_index
                    })
                    .ok_or("missing fourth permutation member")?;
                let candidates = [first_index, second_index, third_index, fourth_index]
                    .into_iter()
                    .map(|index| {
                        original
                            .get(index)
                            .cloned()
                            .ok_or("permutation index is outside the fixture")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let output = DeterministicCompiler.compile(request(
                    governed_contract.clone(),
                    CompilerProfile::default(),
                    candidates,
                )?)?;
                if let Some(prior) = &expected {
                    assert_eq!(&output, prior);
                } else {
                    expected = Some(output);
                }
            }
        }
    }
    let output = expected.ok_or("no content-equivalence permutation compiled")?;
    assert_eq!(output.bundle.blocks.len(), 3);
    assert_eq!(output.bundle.total_tokens, 20);
    assert_eq!(output.manifest.entries.len(), 4);
    let shared_digest = first
        .representations
        .first()
        .ok_or("missing shared representation")?
        .content_digest
        .clone();
    let shared_block = output
        .bundle
        .blocks
        .iter()
        .find(|block| block.content_digest == shared_digest)
        .ok_or("shared block was not selected")?;
    assert_eq!(
        shared_block.provenance,
        BTreeSet::from([
            first.version_id.clone(),
            representative.version_id.clone(),
            first_dependency.version_id.clone(),
            second_dependency.version_id.clone(),
        ])
        .into_iter()
        .collect::<Vec<_>>()
    );
    assert_eq!(
        output.invalidation.catalog_versions,
        shared_block.provenance.iter().cloned().collect()
    );
    assert!(matches!(
        output
            .plan
            .dispositions
            .iter()
            .find_map(
                |(version, disposition)| (version == &representative.version_id)
                    .then_some(disposition)
            ),
        Some(CandidateDisposition::Selected { .. })
    ));
    assert!(matches!(
        output
            .plan
            .dispositions
            .iter()
            .find_map(
                |(version, disposition)| (version == &first.version_id).then_some(disposition)
            ),
        Some(CandidateDisposition::Excluded {
            reason: DispositionReason::BudgetDisplaced
        })
    ));
    let class = output
        .content_equivalence
        .iter()
        .find(|class| class.member_versions.contains(&first.version_id))
        .ok_or("content-equivalence diagnostic is absent")?;
    assert_eq!(class.representative_version, representative.version_id);
    assert_eq!(
        class.member_versions,
        BTreeSet::from([first.version_id.clone(), representative.version_id.clone()])
    );
    assert_eq!(
        class.provenance_digests,
        BTreeSet::from([
            first.provenance_digest.clone(),
            representative.provenance_digest.clone(),
        ])
    );
    let first_citation = output
        .resolve_citation(&first.version_id)
        .ok_or("first merged citation did not resolve")?;
    let representative_citation = output
        .resolve_citation(&representative.version_id)
        .ok_or("representative citation did not resolve")?;
    assert_eq!(first_citation.source_version, first.version_id);
    assert_eq!(
        representative_citation.source_version,
        representative.version_id
    );
    assert_eq!(first_citation.block_id, shared_block.block_id);
    assert_eq!(representative_citation.block_id, shared_block.block_id);
    Ok(())
}

#[test]
fn content_equivalence_representative_uses_version_as_the_final_tie() -> Result<(), Box<dyn Error>>
{
    let tied_contract = contract(BTreeMap::from([(LaneKind::Evidence, 10)]), Vec::new())?;
    let first = candidate(84, LaneKind::Evidence, 10, 8_000)?;
    let mut second = candidate(85, LaneKind::Evidence, 10, 8_000)?;
    second.canonical_uri = first.canonical_uri.clone();
    second.representations = first.representations.clone();
    let output = DeterministicCompiler.compile(request(
        tied_contract,
        CompilerProfile::default(),
        vec![second, first.clone()],
    )?)?;
    let selected: BTreeSet<_> = output
        .plan
        .lanes
        .iter()
        .flat_map(|lane| lane.candidate_versions.iter().cloned())
        .collect();
    assert_eq!(selected, BTreeSet::from([first.version_id]));
    assert_eq!(output.bundle.blocks.len(), 1);
    assert_eq!(output.bundle.total_tokens, 10);
    Ok(())
}

#[test]
fn content_equivalence_keeps_loss_governance_claim_and_receipt_mismatches_separate()
-> Result<(), Box<dyn Error>> {
    let evidence_contract = contract(BTreeMap::from([(LaneKind::Evidence, 100)]), Vec::new())?;

    let mut lossless_left = candidate(86, LaneKind::Evidence, 10, 8_000)?;
    let mut lossless_right = candidate(87, LaneKind::Evidence, 10, 8_000)?;
    lossless_left
        .representations
        .push(RepresentationVariant::verified_summary(
            digest(190)?,
            5,
            digest(191)?,
        )?);
    lossless_right
        .representations
        .push(RepresentationVariant::verified_summary(
            digest(190)?,
            5,
            digest(191)?,
        )?);
    let loss_collision = DeterministicCompiler.compile(request(
        evidence_contract.clone(),
        CompilerProfile::default(),
        vec![lossless_left, lossless_right],
    )?)?;
    assert_eq!(loss_collision.bundle.blocks.len(), 2);

    let mut receipt_left = candidate(88, LaneKind::Evidence, 5, 8_000)?;
    let mut receipt_right = candidate(89, LaneKind::Evidence, 5, 8_000)?;
    receipt_left.representations = vec![RepresentationVariant::verified_summary(
        digest(192)?,
        5,
        digest(193)?,
    )?];
    receipt_right.representations = vec![RepresentationVariant::verified_summary(
        digest(192)?,
        5,
        digest(194)?,
    )?];
    let receipt_mismatch = DeterministicCompiler.compile(request(
        evidence_contract.clone(),
        CompilerProfile::default(),
        vec![receipt_left, receipt_right],
    )?)?;
    assert_eq!(receipt_mismatch.bundle.blocks.len(), 2);

    let mut claim_left = candidate(90, LaneKind::Evidence, 5, 8_000)?;
    let mut claim_right = candidate(91, LaneKind::Evidence, 5, 8_000)?;
    claim_right.representations = claim_left.representations.clone();
    claim_left.claim = Some(CandidateClaim {
        key: "evidence.mode".to_owned(),
        value_digest: digest(195)?,
        valid_at: time("2026-07-10T00:00:01Z")?,
        observed_at: time("2026-07-10T00:00:01Z")?,
        authority: 5,
        verified: true,
    });
    claim_right.claim = Some(CandidateClaim {
        valid_at: time("2026-07-10T00:00:02Z")?,
        ..claim_left
            .claim
            .clone()
            .ok_or("missing compatibility claim")?
    });
    let claim_mismatch = DeterministicCompiler.compile(request(
        evidence_contract.clone(),
        CompilerProfile::default(),
        vec![claim_left, claim_right],
    )?)?;
    assert_eq!(claim_mismatch.bundle.blocks.len(), 2);

    for mismatch in 0..4_u8 {
        let value = 102_u8
            .checked_add(mismatch.saturating_mul(2))
            .ok_or("governance fixture value overflow")?;
        let left = candidate(value, LaneKind::Evidence, 5, 8_000)?;
        let mut right = candidate(value.saturating_add(1), LaneKind::Evidence, 5, 8_000)?;
        right.representations = left.representations.clone();
        let mismatch_contract = match mismatch {
            0 => {
                right.lane = LaneKind::Rules;
                contract(
                    BTreeMap::from([(LaneKind::Evidence, 50), (LaneKind::Rules, 50)]),
                    Vec::new(),
                )?
            }
            1 => {
                right.policy_outcome = PolicyOutcome::Redact;
                evidence_contract.clone()
            }
            2 => {
                right.classification = Classification::Confidential;
                evidence_contract.clone()
            }
            3 => {
                right.instruction_authority = InstructionAuthority::Advisory;
                evidence_contract.clone()
            }
            _ => return Err("unreachable governance mismatch".into()),
        };
        let governance_mismatch = DeterministicCompiler.compile(request(
            mismatch_contract,
            CompilerProfile::default(),
            vec![left, right],
        )?)?;
        assert_eq!(governance_mismatch.bundle.blocks.len(), 2);
    }

    let mut redacted_left = candidate(94, LaneKind::Evidence, 5, 8_000)?;
    let mut redacted_right = candidate(95, LaneKind::Evidence, 5, 8_000)?;
    redacted_left.representations = vec![RepresentationVariant::redacted(digest(196)?, 5)?];
    redacted_right.representations = redacted_left.representations.clone();
    redacted_left.policy_outcome = PolicyOutcome::Redact;
    redacted_right.policy_outcome = PolicyOutcome::Redact;
    let distinct_disclosures = DeterministicCompiler.compile(request(
        evidence_contract,
        CompilerProfile::default(),
        vec![redacted_left, redacted_right],
    )?)?;
    assert_eq!(distinct_disclosures.bundle.blocks.len(), 2);
    Ok(())
}

#[test]
fn content_equivalence_falls_back_when_dependency_contraction_is_unsafe()
-> Result<(), Box<dyn Error>> {
    let governed_contract = contract(BTreeMap::from([(LaneKind::Evidence, 100)]), Vec::new())?;
    let mut first = candidate(96, LaneKind::Evidence, 10, 10_000)?;
    let mut second = candidate(97, LaneKind::Evidence, 10, 9_000)?;
    second.representations = first.representations.clone();
    first.dependencies.insert(second.version_id.clone());
    let direct = DeterministicCompiler.compile(request(
        governed_contract.clone(),
        CompilerProfile::default(),
        vec![first, second],
    )?)?;
    assert_eq!(direct.bundle.blocks.len(), 2);

    let mut first_a = candidate(98, LaneKind::Evidence, 10, 10_000)?;
    let mut first_b = candidate(99, LaneKind::Evidence, 10, 9_000)?;
    let second_a = candidate(100, LaneKind::Evidence, 10, 8_000)?;
    let mut second_b = candidate(101, LaneKind::Evidence, 10, 7_000)?;
    first_b.representations = first_a.representations.clone();
    second_b.representations = second_a.representations.clone();
    first_a.dependencies.insert(second_a.version_id.clone());
    second_b.dependencies.insert(first_b.version_id.clone());
    let contraction_cycle = DeterministicCompiler.compile(request(
        governed_contract,
        CompilerProfile::default(),
        vec![second_b, first_b, second_a, first_a],
    )?)?;
    assert_eq!(contraction_cycle.bundle.blocks.len(), 4);
    Ok(())
}

#[test]
fn mandatory_overflow_reports_exact_lower_bound_and_generated_budgets_hold()
-> Result<(), Box<dyn Error>> {
    let mut input = baseline_request()?;
    input
        .contract
        .budget
        .lane_input_tokens
        .insert(LaneKind::Rules, 250);
    input
        .contract
        .budget
        .lane_input_tokens
        .insert(LaneKind::Evidence, 500);
    input.contract.budget.total_input_tokens = 750;
    let error = DeterministicCompiler
        .compile(input)
        .err()
        .ok_or("mandatory overflow unexpectedly compiled")?;
    assert_eq!(error.code(), CompilerErrorCode::BudgetUnsatisfiable);
    assert_eq!(error.minimum_required_tokens(), Some(300));

    for budget in 300..=700_u32 {
        let mut generated = baseline_request()?;
        generated
            .contract
            .budget
            .lane_input_tokens
            .insert(LaneKind::Rules, budget);
        generated.contract.budget.total_input_tokens = budget + 500;
        generated.contract.target.max_context_tokens = budget + 1_500;
        let output = DeterministicCompiler.compile(generated)?;
        assert!(output.bundle.total_tokens <= output.plan.total_input_tokens);
    }
    Ok(())
}

#[test]
fn exact_component_pins_and_contract_fingerprint_are_semantic() -> Result<(), Box<dyn Error>> {
    let input = baseline_request()?;
    let first = DeterministicCompiler.compile(input.clone())?;
    let mut equivalent = input.clone();
    equivalent.contract.job_goal = "Implement  a verified   change".to_owned();
    let same = DeterministicCompiler.compile(equivalent)?;
    assert_eq!(same.plan.contract_digest, first.plan.contract_digest);

    let mut changed = input.clone();
    changed.contract.job_goal = "Implement a different verified change".to_owned();
    let different = DeterministicCompiler.compile(changed)?;
    assert_ne!(different.plan.contract_digest, first.plan.contract_digest);

    let mut extension_changed = input.clone();
    let mut extensions = BTreeMap::new();
    extensions.insert(
        ExtensionKey::new("downstream.example/correlation")?,
        CanonicalValue::Text("execution-2".to_owned()),
    );
    extension_changed.contract.extensions = ExtensionMap::new(extensions, &BTreeSet::new())?;
    let extension_different = DeterministicCompiler.compile(extension_changed)?;
    assert_ne!(
        extension_different.plan.contract_digest,
        first.plan.contract_digest
    );

    let mut mismatch = input;
    mismatch.frozen.tokenizer_fingerprint = digest(229)?;
    assert_eq!(
        DeterministicCompiler
            .compile(mismatch)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::PinMismatch)
    );
    Ok(())
}

#[test]
fn dependency_cycles_and_critical_conflicts_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut cycle = baseline_request()?;
    let first = cycle
        .candidates
        .first()
        .ok_or("missing first")?
        .version_id
        .clone();
    let second = cycle
        .candidates
        .get(1)
        .ok_or("missing second")?
        .version_id
        .clone();
    cycle
        .candidates
        .get_mut(1)
        .ok_or("missing second mutable")?
        .dependencies
        .insert(first);
    assert!(
        cycle
            .candidates
            .first()
            .ok_or("missing first")?
            .dependencies
            .contains(&second)
    );
    assert_eq!(
        DeterministicCompiler
            .compile(cycle)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidDependency)
    );

    let contract = contract(BTreeMap::from([(LaneKind::Rules, 1_000)]), Vec::new())?;
    let mut left = candidate(10, LaneKind::Rules, 100, 5_000)?;
    let mut right = candidate(11, LaneKind::Rules, 100, 5_000)?;
    left.claim = Some(CandidateClaim {
        key: "policy.mode".to_owned(),
        value_digest: digest(10)?,
        valid_at: time("2026-07-10T00:00:00Z")?,
        observed_at: time("2026-07-10T00:00:01Z")?,
        authority: 10,
        verified: true,
    });
    right.claim = Some(CandidateClaim {
        value_digest: digest(11)?,
        ..left.claim.clone().ok_or("missing left claim")?
    });
    let conflict = request(contract, CompilerProfile::default(), vec![left, right])?;
    assert_eq!(
        DeterministicCompiler
            .compile(conflict)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::UnresolvedCriticalConflict)
    );
    Ok(())
}

#[test]
fn brute_force_small_set_oracle_matches_independent_greedy_fixture() -> Result<(), Box<dyn Error>> {
    let contract = contract(BTreeMap::from([(LaneKind::Evidence, 500)]), Vec::new())?;
    let mut candidates = Vec::new();
    for (value, tokens, score) in [(20, 100, 9_000), (21, 200, 8_000), (22, 300, 7_000)] {
        candidates.push(candidate(value, LaneKind::Evidence, tokens, score)?);
    }
    let input = request(contract, CompilerProfile::default(), candidates.clone())?;
    let output = DeterministicCompiler.compile(input)?;
    let selected: BTreeSet<_> = output
        .bundle
        .blocks
        .iter()
        .map(|block| block.content_digest.clone())
        .collect();

    let mut oracle_tokens = 0_u32;
    let mut oracle_score = i64::MIN;
    for mask in 0..8_u8 {
        let mut tokens = 0_u32;
        let mut score = 0_i64;
        for (index, candidate) in candidates.iter().enumerate() {
            let bit = 1_u8.checked_shl(u32::try_from(index)?).unwrap_or_default();
            if mask & bit != 0 {
                tokens += candidate
                    .representations
                    .first()
                    .ok_or("missing representation")?
                    .token_count;
                score += candidate.features.balanced_score()?;
            }
        }
        if tokens <= 500 && score > oracle_score {
            oracle_score = score;
            oracle_tokens = tokens;
        }
    }
    assert_eq!(output.bundle.total_tokens, oracle_tokens);
    assert_eq!(selected.len(), output.bundle.blocks.len());
    Ok(())
}

#[test]
fn bounded_local_swap_replaces_one_item_with_two_better_alternatives() -> Result<(), Box<dyn Error>>
{
    let contract = contract(BTreeMap::from([(LaneKind::Evidence, 10)]), Vec::new())?;
    let first = candidate(30, LaneKind::Evidence, 6, 10_000)?;
    let second = candidate(31, LaneKind::Evidence, 5, 7_000)?;
    let third = candidate(32, LaneKind::Evidence, 5, 7_000)?;
    let profile = CompilerProfile {
        local_swap_passes: 2,
        local_swap_alternatives: 4,
        ..CompilerProfile::default()
    };
    let output = DeterministicCompiler.compile(request(
        contract,
        profile,
        vec![first.clone(), second.clone(), third.clone()],
    )?)?;
    let selected: BTreeSet<_> = output
        .plan
        .lanes
        .iter()
        .flat_map(|lane| lane.candidate_versions.iter().cloned())
        .collect();
    assert_eq!(
        selected,
        [second.version_id, third.version_id].into_iter().collect()
    );
    assert!(!selected.contains(&first.version_id));
    assert_eq!(output.bundle.total_tokens, 10);
    Ok(())
}

#[test]
fn every_disposition_reason_and_redacted_explanation_are_bounded() -> Result<(), Box<dyn Error>> {
    let contract = contract(BTreeMap::from([(LaneKind::Evidence, 500)]), Vec::new())?;
    let reasons = [
        DispositionReason::ScopeDenied,
        DispositionReason::PurposeDenied,
        DispositionReason::TemporalMismatch,
        DispositionReason::TrustInsufficient,
        DispositionReason::InstructionAuthorityDenied,
        DispositionReason::ProcessorDenied,
        DispositionReason::IntegrityFailed,
        DispositionReason::BudgetDisplaced,
        DispositionReason::LifecycleIneligible,
        DispositionReason::ConflictLost,
        DispositionReason::RequiredMissing,
    ];
    let mut candidates = Vec::new();
    for (index, reason) in reasons.into_iter().enumerate() {
        let value = u8::try_from(index + 40)?;
        let mut excluded = candidate(value, LaneKind::Evidence, 10, 1_000)?;
        excluded.pre_exclusion_reason = Some(reason);
        candidates.push(excluded);
    }
    let output = DeterministicCompiler.compile(request(
        contract,
        CompilerProfile::default(),
        candidates,
    )?)?;
    let found: BTreeSet<_> = output
        .manifest
        .entries
        .iter()
        .flat_map(|entry| entry.reason_codes.iter().copied())
        .collect();
    assert_eq!(found, reasons.into_iter().collect());
    let authorized = [version(40)?].into_iter().collect();
    let view = output.explain(&authorized);
    assert_eq!(view.entries.len(), 1);
    assert!(matches!(
        view.entries.first().map(|entry| &entry.disposition),
        Some(CandidateDisposition::Excluded { .. })
    ));
    assert!(!format!("{view:?}").contains(version(41)?.as_str()));
    Ok(())
}

#[test]
fn closure_and_local_repair_preserve_item_caps_and_blocking_roots() -> Result<(), Box<dyn Error>> {
    let blocking_contract = contract(
        BTreeMap::from([(LaneKind::Evidence, 10)]),
        vec![requirement(true, "required evidence")?],
    )?;
    let mut required = candidate(60, LaneKind::Evidence, 6, 10_000)?;
    required.requirement_indices.insert(0);
    let alternative_a = candidate(61, LaneKind::Evidence, 5, 7_000)?;
    let alternative_b = candidate(62, LaneKind::Evidence, 5, 7_000)?;
    let repaired = DeterministicCompiler.compile(request(
        blocking_contract,
        CompilerProfile {
            local_swap_passes: 2,
            local_swap_alternatives: 4,
            ..CompilerProfile::default()
        },
        vec![
            required.clone(),
            alternative_a.clone(),
            alternative_b.clone(),
        ],
    )?)?;
    let repaired_versions: BTreeSet<_> = repaired
        .bundle
        .blocks
        .iter()
        .flat_map(|block| block.provenance.iter().cloned())
        .collect();
    assert!(repaired_versions.contains(&required.version_id));
    assert!(!repaired_versions.contains(&alternative_a.version_id));
    assert!(!repaired_versions.contains(&alternative_b.version_id));

    let capped_contract = contract(BTreeMap::from([(LaneKind::Evidence, 10)]), Vec::new())?;
    let mut capped_primary = required;
    capped_primary.requirement_indices.clear();
    let capped = DeterministicCompiler.compile(request(
        capped_contract,
        CompilerProfile {
            maximum_items: BTreeMap::from([(LaneKind::Evidence, 1)]),
            local_swap_passes: 2,
            local_swap_alternatives: 4,
            ..CompilerProfile::default()
        },
        vec![capped_primary, alternative_a, alternative_b],
    )?)?;
    assert_eq!(capped.bundle.blocks.len(), 1);

    let dependency_contract = contract(
        BTreeMap::from([(LaneKind::Rules, 20), (LaneKind::Evidence, 20)]),
        Vec::new(),
    )?;
    let mut root = candidate(63, LaneKind::Evidence, 5, 10_000)?;
    root.mandatory = true;
    let dependency_a = candidate(64, LaneKind::Rules, 5, 8_000)?;
    let dependency_b = candidate(65, LaneKind::Rules, 5, 8_000)?;
    root.dependencies = BTreeSet::from([
        dependency_a.version_id.clone(),
        dependency_b.version_id.clone(),
    ]);
    let closure_error = DeterministicCompiler
        .compile(request(
            dependency_contract,
            CompilerProfile {
                maximum_items: BTreeMap::from([(LaneKind::Rules, 1)]),
                ..CompilerProfile::default()
            },
            vec![root, dependency_a, dependency_b],
        )?)
        .err()
        .ok_or("dependency closure exceeded its item cap without failing")?;
    assert_eq!(closure_error.code(), CompilerErrorCode::BudgetUnsatisfiable);

    let absent_lane_contract = contract(BTreeMap::from([(LaneKind::Evidence, 20)]), Vec::new())?;
    let absent_lane = DeterministicCompiler.compile(request(
        absent_lane_contract,
        CompilerProfile {
            minimum_items: BTreeMap::from([(LaneKind::Tools, 1)]),
            ..CompilerProfile::default()
        },
        vec![candidate(66, LaneKind::Evidence, 5, 5_000)?],
    )?)?;
    assert_eq!(absent_lane.bundle.blocks.len(), 1);
    Ok(())
}

#[test]
fn conflict_order_and_candidate_requirement_indices_fail_closed() -> Result<(), Box<dyn Error>> {
    let contract_with_requirement = contract(
        BTreeMap::from([(LaneKind::Evidence, 100)]),
        vec![requirement(false, "bounded")?],
    )?;
    let mut invalid_index = candidate(70, LaneKind::Evidence, 10, 5_000)?;
    invalid_index.requirement_indices.insert(1);
    assert_eq!(
        DeterministicCompiler
            .compile(request(
                contract_with_requirement,
                CompilerProfile::default(),
                vec![invalid_index],
            )?)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );

    let conflict_contract = contract(
        BTreeMap::from([(LaneKind::Rules, 100), (LaneKind::Evidence, 100)]),
        Vec::new(),
    )?;
    let mut evidence = candidate(71, LaneKind::Evidence, 10, 10_000)?;
    let mut rule = candidate(72, LaneKind::Rules, 10, 1_000)?;
    let rank = CandidateClaim {
        key: "policy.mode".to_owned(),
        value_digest: digest(71)?,
        valid_at: time("2026-07-10T00:00:02Z")?,
        observed_at: time("2026-07-10T00:00:03Z")?,
        authority: 10,
        verified: true,
    };
    evidence.claim = Some(rank.clone());
    rule.claim = Some(CandidateClaim {
        value_digest: digest(72)?,
        ..rank
    });
    assert_eq!(
        DeterministicCompiler
            .compile(request(
                conflict_contract,
                CompilerProfile::default(),
                vec![evidence, rule],
            )?)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::UnresolvedCriticalConflict)
    );

    let temporal_contract = contract(BTreeMap::from([(LaneKind::Evidence, 100)]), Vec::new())?;
    let mut older_high_authority = candidate(73, LaneKind::Evidence, 10, 8_000)?;
    older_high_authority.claim = Some(CandidateClaim {
        key: "fact.mode".to_owned(),
        value_digest: digest(73)?,
        valid_at: time("2026-07-10T00:00:01Z")?,
        observed_at: time("2026-07-10T00:00:01Z")?,
        authority: 100,
        verified: true,
    });
    let mut newer_lower_authority = candidate(74, LaneKind::Evidence, 10, 7_000)?;
    newer_lower_authority.claim = Some(CandidateClaim {
        key: "fact.mode".to_owned(),
        value_digest: digest(74)?,
        valid_at: time("2026-07-10T00:00:02Z")?,
        observed_at: time("2026-07-10T00:00:02Z")?,
        authority: 1,
        verified: false,
    });
    let temporal = DeterministicCompiler.compile(request(
        temporal_contract,
        CompilerProfile::default(),
        vec![older_high_authority.clone(), newer_lower_authority.clone()],
    )?)?;
    assert!(matches!(
        temporal
            .plan
            .dispositions
            .iter()
            .find_map(
                |(version, disposition)| (version == &older_high_authority.version_id)
                    .then_some(disposition)
            ),
        Some(CandidateDisposition::Excluded {
            reason: DispositionReason::ConflictLost
        })
    ));
    assert!(matches!(
        temporal
            .plan
            .dispositions
            .iter()
            .find_map(
                |(version, disposition)| (version == &newer_lower_authority.version_id)
                    .then_some(disposition)
            ),
        Some(CandidateDisposition::Selected { .. })
    ));
    Ok(())
}

#[test]
fn process_determinism_child() -> Result<(), Box<dyn Error>> {
    if std::env::var("CIGAR_COMPILER_PROCESS_CHILD")
        .ok()
        .as_deref()
        != Some("1")
    {
        return Ok(());
    }
    let mut input = baseline_request()?;
    let permutation = std::env::var("CIGAR_COMPILER_PERMUTATION")
        .map_err(|_| "compiler child permutation is absent")?
        .parse::<usize>()?;
    let orders = [
        [0_usize, 1_usize, 2_usize],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let order = orders
        .get(permutation)
        .ok_or("compiler child permutation is outside the closed matrix")?;
    let original = input.candidates;
    input.candidates = order
        .iter()
        .map(|index| {
            original
                .get(*index)
                .cloned()
                .ok_or("compiler child permutation is invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output = DeterministicCompiler.compile(input)?;
    println!(
        "CIGAR_COMPILER_IDENTITIES={}|{}|{}",
        output.plan.plan_id.as_str(),
        output.manifest.manifest_id.as_str(),
        output.bundle.bundle_id.as_str()
    );
    Ok(())
}

#[test]
fn semantic_identities_are_stable_across_process_locale_timezone_and_input_order()
-> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    let variants = [
        ("C", "UTC", "0"),
        ("en_US.UTF-8", "America/Denver", "1"),
        ("tr_TR.UTF-8", "Pacific/Kiritimati", "0"),
    ];
    let mut identities = BTreeSet::new();
    for repeat in 0..2_usize {
        for permutation in 0..6_usize {
            let (locale, timezone, seed) = variants
                .get((repeat + permutation) % variants.len())
                .ok_or("compiler process variant is absent")?;
            let output = Command::new(&executable)
                .args(["--exact", "process_determinism_child", "--nocapture"])
                .env("CIGAR_COMPILER_PROCESS_CHILD", "1")
                .env("CIGAR_COMPILER_PERMUTATION", permutation.to_string())
                .env("LC_ALL", locale)
                .env("TZ", timezone)
                .env("RUST_HASH_SEED", format!("qualification-{seed}-{repeat}"))
                .output()?;
            assert!(
                output.status.success(),
                "child compiler failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout)?;
            let identity = stdout
                .lines()
                .find_map(|line| line.strip_prefix("CIGAR_COMPILER_IDENTITIES="))
                .ok_or("child compiler omitted semantic identities")?;
            identities.insert(identity.to_owned());
        }
    }
    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities.into_iter().next().ok_or("missing identity")?,
        "89c22906-ee10-723b-9ce2-fa1b019c2f18|122078ff8edd59dc1df3ae28f591de9058b9eaab4562d92fcc7529213822d2bfdad8|12205febd5bb06ffbc44147cf0126543ded08d3b90c9169a16d992c3b14c59074e85"
    );
    Ok(())
}

#[test]
fn adversarial_feature_overflow_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut input = baseline_request()?;
    input
        .candidates
        .first_mut()
        .ok_or("missing candidate")?
        .features
        .exact_match = 10_001;
    assert_eq!(
        DeterministicCompiler
            .compile(input)
            .map_err(|error| error.code()),
        Err(CompilerErrorCode::InvalidInput)
    );
    Ok(())
}

#[test]
fn one_million_materialization_budget_arithmetic_has_no_overflow() -> Result<(), Box<dyn Error>> {
    if std::env::var("CIGAR_PERFORMANCE_GATES").ok().as_deref() != Some("1") {
        return Ok(());
    }
    let input = baseline_request()?;
    let output = DeterministicCompiler.compile(input)?;
    let started = std::time::Instant::now();
    let mut compliant = 0_u64;
    let mut checksum = 0_u64;
    for iteration in 0..1_000_000_u64 {
        let total = output
            .bundle
            .blocks
            .iter()
            .try_fold(0_u32, |sum, block| sum.checked_add(block.token_count))
            .ok_or("token overflow")?;
        if total == output.bundle.total_tokens && total <= output.plan.total_input_tokens {
            compliant += 1;
        }
        checksum ^= iteration.rotate_left(total % 63);
    }
    println!(
        "WP08_BUDGET_GATE materializations=1000000 compliant={compliant} elapsed_ms={} checksum={checksum}",
        started.elapsed().as_millis()
    );
    assert_eq!(compliant, 1_000_000);
    Ok(())
}

#[test]
fn projected_one_million_catalog_compile_latency_meets_local_targets() -> Result<(), Box<dyn Error>>
{
    if std::env::var("CIGAR_PERFORMANCE_GATES").ok().as_deref() != Some("1") {
        return Ok(());
    }
    let contract = contract(BTreeMap::from([(LaneKind::Evidence, 1_000)]), Vec::new())?;
    let mut candidates = Vec::new();
    for index in 0..1_000_u64 {
        candidates.push(CompilerCandidate {
            version_id: version_u64(index + 1)?,
            logical_id: version_u64(index + 1)?,
            lineage_id: lineage(u16::try_from(index + 1)?)?,
            canonical_uri: SourceUri::new(format!("file:///scale/{index:08x}.md"))?,
            lane: LaneKind::Evidence,
            mandatory: false,
            requirement_indices: BTreeSet::new(),
            entity_coverage_bits: index,
            features: features(5_000, 1),
            policy_outcome: PolicyOutcome::Allow,
            pre_exclusion_reason: None,
            classification: Classification::Internal,
            instruction_authority: InstructionAuthority::Data,
            dependencies: BTreeSet::new(),
            representations: vec![RepresentationVariant {
                kind: RepresentationKind::Exact,
                content_digest: digest_u64(index + 10_000)?,
                token_count: 1,
                loss: LossClass::Lossless,
                transform_receipt: None,
            }],
            claim: None,
            provenance_digest: digest_u64(index + 20_000)?,
        });
    }
    let input = request(contract, CompilerProfile::default(), candidates)?;
    let _warm = DeterministicCompiler.compile(input.clone())?;
    let mut samples = Vec::new();
    for _sample in 0..30 {
        let started = std::time::Instant::now();
        let output = DeterministicCompiler.compile(input.clone())?;
        assert_eq!(output.bundle.blocks.len(), 1_000);
        samples.push(started.elapsed());
    }
    samples.sort();
    let p50 = *samples.get(14).ok_or("missing p50")?;
    let p95 = *samples.get(28).ok_or("missing p95")?;
    let p99 = *samples.get(29).ok_or("missing p99")?;
    println!(
        "WP08_COMPILE source_catalog_atoms=1000000 projected_candidates=1000 samples=30 p50_ms={} p95_ms={} p99_ms={}",
        p50.as_millis(),
        p95.as_millis(),
        p99.as_millis()
    );
    assert!(p50 <= std::time::Duration::from_millis(75));
    assert!(p95 <= std::time::Duration::from_millis(250));
    assert!(p99 <= std::time::Duration::from_millis(750));
    Ok(())
}
