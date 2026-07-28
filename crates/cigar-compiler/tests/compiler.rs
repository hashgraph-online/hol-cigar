//! WP08 deterministic compiler, packing, provenance, and budget acceptance matrix.

use cigar_compiler::{
    CandidateClaim, CompileRequest, CompilerCandidate, CompilerErrorCode, CompilerProfile,
    DeterministicCompiler, FrozenInputs, LossClass, RepresentationVariant, compiler_profile_digest,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    AtomKind, Budget, CandidateDisposition, Classification, ConsistencyMode, ContentDigest,
    ContextContract, ContextRequirement, DispositionReason, ExtensionMap, FixedPoint,
    InstructionAuthority, LaneKind, OperationClass, RecordId, RepresentationKind,
    RequirementSelector, SchemaVersion, SourceUri, TargetProfile, UtcTimestamp, Validate,
    VersionId,
};
use cigar_retrieval::CandidateFeatures;
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
    })
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
        "1220e42df560c2b77e860952db51174f8fd995da09a7b37d231899ad173388943c8f"
    );
    assert_eq!(
        compiler_profile_digest(&CompilerProfile::balanced_v2_candidate())?.as_str(),
        "1220c363f1fc1b3afa384fbdae91cf16b8955d91362adcadf75fa8faf0e7e437cccf"
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
