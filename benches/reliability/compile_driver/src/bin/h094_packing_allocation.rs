//! Paired, bounded allocation qualification for the frozen v3 and candidate v4 packers.

use cigar_compiler::{
    CompileRequest, CompilerCandidate, CompilerProfile, DeterministicCompiler, FrozenInputs,
    RepresentationVariant, compiler_profile_digest,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    Budget, Classification, ConsistencyMode, ContentDigest, ContextContract, ExtensionMap,
    InstructionAuthority, LaneKind, LineageId, OperationClass, RecordId, SchemaVersion, SourceUri,
    TargetProfile, VersionId,
};
use cigar_retrieval::RequirementRankingEvidence;
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::hint::black_box;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const SCHEMA_VERSION: &str = "cigar.h094-packing-allocation-raw.v1";
const MEASUREMENT_METHOD: &str = "system-allocator-peak-live-above-precompiled-request-baseline-v1";
const CANDIDATE_COUNTS: [usize; 2] = [128, 512];
const WARMUPS: usize = 40;
const MEASURED_PAIRS: usize = 200;
const V3_ID: &str = "cigar.compiler-profile.balanced.v3";
const V3_DIGEST: &str = "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7";
const V4_ID: &str = "cigar.compiler-profile.balanced.v4";
const V4_DIGEST: &str = "1220d28b42286c3db066f73b70b670ee32b13311319fd512d682e9f843864749bcf2";

struct TrackingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL_ALLOCATOR: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates the exact allocation request to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_growth(layout.size(), true);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates the exact allocation request to the system allocator.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_growth(layout.size(), true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: The pointer and layout are the exact pair supplied by the caller.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Delegates the exact reallocation request to the system allocator.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            if new_size >= layout.size() {
                record_growth(new_size - layout.size(), true);
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        replacement
    }
}

fn atomic_max(target: &AtomicUsize, value: usize) {
    let mut current = target.load(Ordering::SeqCst);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn record_growth(bytes: usize, allocation_event: bool) {
    let live = LIVE_BYTES
        .fetch_add(bytes, Ordering::SeqCst)
        .saturating_add(bytes);
    if MEASURING.load(Ordering::SeqCst) {
        ALLOCATED_BYTES.fetch_add(bytes, Ordering::SeqCst);
        if allocation_event {
            ALLOCATION_COUNT.fetch_add(1, Ordering::SeqCst);
        }
        atomic_max(&PEAK_BYTES, live);
    }
}

#[derive(Clone, Copy)]
enum Treatment {
    BalancedV3,
    BalancedV4,
}

impl Treatment {
    fn label(self) -> &'static str {
        match self {
            Self::BalancedV3 => "balanced_v3",
            Self::BalancedV4 => "balanced_v4",
        }
    }

    fn profile(self) -> CompilerProfile {
        match self {
            Self::BalancedV3 => CompilerProfile::balanced_v3(),
            Self::BalancedV4 => CompilerProfile::balanced_v4(),
        }
    }
}

#[derive(Serialize)]
struct ProfileBinding {
    compiler_id: &'static str,
    compiler_digest: &'static str,
}

#[derive(Serialize)]
struct AllocationSample {
    peak_live_bytes: usize,
    allocated_bytes: usize,
    allocation_count: usize,
    selected_items: usize,
    bundle_id: String,
}

#[derive(Serialize)]
struct Pair {
    pair: usize,
    order: [&'static str; 2],
    balanced_v3: AllocationSample,
    balanced_v4: AllocationSample,
}

#[derive(Serialize)]
struct Cell {
    candidate_count: usize,
    pairs: Vec<Pair>,
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    measurement_method: &'static str,
    candidate_counts: [usize; 2],
    warmups_per_treatment_per_count: usize,
    measured_pairs_per_count: usize,
    profiles: BTreeMap<&'static str, ProfileBinding>,
    cells: Vec<Cell>,
}

fn digest(value: u64) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!("1220{value:064x}"))?)
}

fn version(value: u64) -> Result<VersionId, Box<dyn Error>> {
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

fn contract(candidate_count: usize) -> Result<ContextContract, Box<dyn Error>> {
    let budget = u32::try_from(candidate_count)?;
    Ok(ContextContract {
        schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
        job_goal: "Measure bounded compiler allocation behavior".to_owned(),
        operation_class: OperationClass::CodeChange,
        principal_id: record(1)?,
        purpose: "packing-allocation-qualification".to_owned(),
        context_space_id: None,
        project_ids: vec![record(2)?],
        target: TargetProfile {
            provider: "qualification".to_owned(),
            model_family: "deterministic".to_owned(),
            tokenizer_fingerprint: digest(900_001)?,
            materializer_fingerprint: digest(900_002)?,
            max_context_tokens: budget.checked_add(1_000).ok_or("budget overflow")?,
        },
        budget: Budget {
            total_input_tokens: budget,
            output_reserve_tokens: 1_000,
            lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, budget)]),
        },
        requirements: Vec::new(),
        consistency: ConsistencyMode::Strong,
        maximum_staleness: None,
        extensions: ExtensionMap::default(),
    })
}

fn candidate(index: usize) -> Result<CompilerCandidate, Box<dyn Error>> {
    let value = u64::try_from(index)?
        .checked_add(1)
        .ok_or("identity overflow")?;
    let entity_bit = u32::try_from(index % 64)?;
    let mut features = cigar_retrieval::CandidateFeatures {
        requirement_match: 8_000,
        exact_match: 8_000,
        lexical_match: 8_000,
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
        estimated_tokens: 1,
        requirement_coverage_bits: 0,
        entity_coverage_bits: 0,
    };
    features.entity_coverage_bits = 1_u64
        .checked_shl(entity_bit)
        .ok_or("entity coverage shift overflow")?;
    Ok(CompilerCandidate {
        version_id: version(value)?,
        logical_id: version(value)?,
        lineage_id: lineage(u16::try_from(value)?)?,
        canonical_uri: SourceUri::new(format!("file:///packing/{index:08x}.md"))?,
        lane: LaneKind::Evidence,
        mandatory: false,
        requirement_indices: BTreeSet::new(),
        entity_coverage_bits: features.entity_coverage_bits,
        features,
        policy_outcome: PolicyOutcome::Allow,
        pre_exclusion_reason: None,
        classification: Classification::Internal,
        instruction_authority: InstructionAuthority::Data,
        dependencies: BTreeSet::new(),
        representations: vec![RepresentationVariant::exact(
            digest(value.checked_add(10_000).ok_or("content digest overflow")?)?,
            1,
        )?],
        claim: None,
        provenance_digest: digest(
            value
                .checked_add(20_000)
                .ok_or("provenance digest overflow")?,
        )?,
    })
}

fn request(candidate_count: usize, treatment: Treatment) -> Result<CompileRequest, Box<dyn Error>> {
    let contract = contract(candidate_count)?;
    let candidates = (0..candidate_count)
        .map(candidate)
        .collect::<Result<Vec<_>, _>>()?;
    let profile = treatment.profile();
    let retrieval_plan_digest = digest(900_003)?;
    let ranking_evidence = match treatment {
        Treatment::BalancedV3 => RequirementRankingEvidence::new(
            retrieval_plan_digest.clone(),
            BTreeSet::new(),
            BTreeSet::new(),
            Vec::new(),
        )?,
        Treatment::BalancedV4 => RequirementRankingEvidence::new_v4(
            retrieval_plan_digest.clone(),
            BTreeSet::new(),
            BTreeSet::new(),
            Vec::new(),
        )?,
    };
    Ok(CompileRequest {
        frozen: FrozenInputs {
            catalog_watermark: digest(900_004)?,
            graph_revision: digest(900_005)?,
            policy_digest: digest(900_006)?,
            index_fingerprints: BTreeSet::from([digest(900_007)?]),
            retrieval_plan_digest,
            compiler_profile_digest: compiler_profile_digest(&profile)?,
            tokenizer_fingerprint: contract.target.tokenizer_fingerprint.clone(),
            materializer_fingerprint: contract.target.materializer_fingerprint.clone(),
        },
        contract,
        profile,
        candidates,
        ranking_evidence: Some(ranking_evidence),
    })
}

fn begin_measurement() -> Result<usize, Box<dyn Error>> {
    if MEASURING.swap(true, Ordering::SeqCst) {
        return Err("nested allocation measurement".into());
    }
    let baseline = LIVE_BYTES.load(Ordering::SeqCst);
    ALLOCATED_BYTES.store(0, Ordering::SeqCst);
    ALLOCATION_COUNT.store(0, Ordering::SeqCst);
    PEAK_BYTES.store(baseline, Ordering::SeqCst);
    Ok(baseline)
}

fn finish_measurement(baseline: usize) -> (usize, usize, usize) {
    MEASURING.store(false, Ordering::SeqCst);
    (
        PEAK_BYTES.load(Ordering::SeqCst).saturating_sub(baseline),
        ALLOCATED_BYTES.load(Ordering::SeqCst),
        ALLOCATION_COUNT.load(Ordering::SeqCst),
    )
}

fn measure(input: CompileRequest) -> Result<AllocationSample, Box<dyn Error>> {
    let baseline = begin_measurement()?;
    let compiled = DeterministicCompiler.compile(input);
    let (peak_live_bytes, allocated_bytes, allocation_count) = finish_measurement(baseline);
    let compiled = compiled?;
    black_box(&compiled);
    Ok(AllocationSample {
        peak_live_bytes,
        allocated_bytes,
        allocation_count,
        selected_items: compiled.bundle.blocks.len(),
        bundle_id: compiled.bundle.bundle_id.as_str().to_owned(),
    })
}

fn warm(template: &CompileRequest) -> Result<(), Box<dyn Error>> {
    for _ in 0..WARMUPS {
        black_box(DeterministicCompiler.compile(template.clone())?);
    }
    Ok(())
}

fn cell(candidate_count: usize) -> Result<Cell, Box<dyn Error>> {
    let v3 = request(candidate_count, Treatment::BalancedV3)?;
    let v4 = request(candidate_count, Treatment::BalancedV4)?;
    warm(&v3)?;
    warm(&v4)?;
    let mut pairs = Vec::with_capacity(MEASURED_PAIRS);
    for pair in 0..MEASURED_PAIRS {
        let v3_input = v3.clone();
        let v4_input = v4.clone();
        let (order, balanced_v3, balanced_v4) = if pair % 2 == 0 {
            (
                [Treatment::BalancedV3.label(), Treatment::BalancedV4.label()],
                measure(v3_input)?,
                measure(v4_input)?,
            )
        } else {
            let balanced_v4 = measure(v4_input)?;
            let balanced_v3 = measure(v3_input)?;
            (
                [Treatment::BalancedV4.label(), Treatment::BalancedV3.label()],
                balanced_v3,
                balanced_v4,
            )
        };
        pairs.push(Pair {
            pair,
            order,
            balanced_v3,
            balanced_v4,
        });
    }
    Ok(Cell {
        candidate_count,
        pairs,
    })
}

fn profile_bindings() -> Result<BTreeMap<&'static str, ProfileBinding>, Box<dyn Error>> {
    let observed_v3 = compiler_profile_digest(&CompilerProfile::balanced_v3())?;
    let observed_v4 = compiler_profile_digest(&CompilerProfile::balanced_v4())?;
    if observed_v3.as_str() != V3_DIGEST || observed_v4.as_str() != V4_DIGEST {
        return Err("compiler profile digest drift".into());
    }
    Ok(BTreeMap::from([
        (
            "balanced_v3",
            ProfileBinding {
                compiler_id: V3_ID,
                compiler_digest: V3_DIGEST,
            },
        ),
        (
            "balanced_v4",
            ProfileBinding {
                compiler_id: V4_ID,
                compiler_digest: V4_DIGEST,
            },
        ),
    ]))
}

fn execute() -> Result<Report, Box<dyn Error>> {
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        measurement_method: MEASUREMENT_METHOD,
        candidate_counts: CANDIDATE_COUNTS,
        warmups_per_treatment_per_count: WARMUPS,
        measured_pairs_per_count: MEASURED_PAIRS,
        profiles: profile_bindings()?,
        cells: CANDIDATE_COUNTS
            .into_iter()
            .map(cell)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn output_path() -> Result<PathBuf, Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let flag = arguments.next().ok_or("--output is required")?;
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("output is required")?;
    if flag != "--output" || arguments.next().is_some() || !output.is_absolute() {
        return Err("expected exactly --output <absolute-new-file>".into());
    }
    Ok(output)
}

fn write_new(path: &PathBuf, report: &Report) -> Result<(), Box<dyn Error>> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    serde_json::to_writer(&mut output, report)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(())
}

fn main() {
    let result = output_path().and_then(|path| write_new(&path, &execute()?));
    if let Err(error) = result {
        eprintln!("packing allocation qualification failed: {error}");
        std::process::exit(2);
    }
}
