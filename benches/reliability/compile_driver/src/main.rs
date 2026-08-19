//! Bounded full-bundle and delta compilation qualification driver.

use cigar_compiler::{
    CompileRequest, CompilerCandidate, CompilerProfile, DeterministicCompiler, FrozenInputs,
    LossClass, RepresentationVariant, apply_delta_verified, compiler_profile_digest,
    generate_delta,
};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{
    AtomKind, Budget, Classification, ConsistencyMode, ContentDigest, ContextBlock, ContextBundle,
    ContextContract, ContextRequirement, ExtensionMap, FixedPoint, InstructionAuthority, LaneKind,
    LineageId, OperationClass, RecordId, RepresentationKind, RequirementSelector, SchemaVersion,
    SourceUri, TargetProfile, VersionId,
};
use cigar_retrieval::{
    CandidateFeatures, CandidateRankingDecision, CandidateRankingFactors, CandidateSelectionBasis,
    QueryPlannerProfile, RequirementRankingEvidence, RetrievalProfile,
};
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::Instant;

const CONCURRENCY: [usize; 5] = [1, 2, 4, 8, 16];
const SCHEMA_VERSION: &str = "cigar.h094-compile-load-result.v1";
const ALLOCATION_WARMUP_ITERATIONS: usize = 128;
const ALLOCATION_MEASUREMENT_ITERATIONS: usize = 2_000;

struct TrackingAllocator;

static LIVE_ALLOCATION_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATION_BYTES: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL_ALLOCATOR: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates the exact allocation request to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates the exact allocation request to the system allocator.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_ALLOCATION_BYTES.fetch_sub(layout.size(), Ordering::AcqRel);
        LIVE_ALLOCATION_COUNT.fetch_sub(1, Ordering::AcqRel);
        // SAFETY: The pointer and layout are the exact pair supplied by the caller.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Delegates the exact reallocation request to the system allocator.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            if new_size >= layout.size() {
                let increase = new_size - layout.size();
                let live = LIVE_ALLOCATION_BYTES
                    .fetch_add(increase, Ordering::AcqRel)
                    .saturating_add(increase);
                atomic_max(&PEAK_ALLOCATION_BYTES, live);
            } else {
                LIVE_ALLOCATION_BYTES.fetch_sub(layout.size() - new_size, Ordering::AcqRel);
            }
        }
        replacement
    }
}

fn record_allocation(bytes: usize) {
    let live = LIVE_ALLOCATION_BYTES
        .fetch_add(bytes, Ordering::AcqRel)
        .saturating_add(bytes);
    LIVE_ALLOCATION_COUNT.fetch_add(1, Ordering::AcqRel);
    atomic_max(&PEAK_ALLOCATION_BYTES, live);
}

#[derive(Clone)]
struct Arguments {
    output: PathBuf,
    iterations: usize,
    queue_capacity: usize,
}

#[derive(Serialize)]
struct Cell {
    operation: &'static str,
    concurrency: usize,
    queue_capacity: usize,
    iterations: usize,
    wall_nanoseconds: u64,
    operation_nanoseconds_p50: u64,
    operation_nanoseconds_p95: u64,
    maximum_queue_depth: usize,
    rejected: usize,
    completed: usize,
    deterministic: bool,
}

#[derive(Serialize)]
struct AllocationProbe {
    warmup_iterations: usize,
    measurement_iterations: usize,
    operations_per_iteration: usize,
    live_bytes_before: usize,
    live_bytes_after: usize,
    live_allocations_before: usize,
    live_allocations_after: usize,
    peak_live_bytes: usize,
    zero_monotonic_growth: bool,
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    compiler_profile: &'static str,
    candidate_count: usize,
    requirement_count: usize,
    queue_capacity: usize,
    iterations_per_cell: usize,
    concurrency: [usize; 5],
    allocation_probe: AllocationProbe,
    cells: Vec<Cell>,
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut values = env::args_os().skip(1);
    let mut output = None;
    let mut iterations = None;
    let mut queue_capacity = None;
    while let Some(argument) = values.next() {
        match argument.to_str().ok_or("argument is not UTF-8")? {
            "--output" => output = values.next().map(PathBuf::from),
            "--iterations" => {
                iterations = values
                    .next()
                    .and_then(|value| value.to_str().and_then(|text| text.parse().ok()))
            }
            "--queue-capacity" => {
                queue_capacity = values
                    .next()
                    .and_then(|value| value.to_str().and_then(|text| text.parse().ok()))
            }
            _ => return Err("unknown argument".into()),
        }
    }
    let arguments = Arguments {
        output: output.ok_or("output is required")?,
        iterations: iterations.ok_or("iterations are required")?,
        queue_capacity: queue_capacity.ok_or("queue capacity is required")?,
    };
    if !arguments.output.is_absolute()
        || !(10..=10_000).contains(&arguments.iterations)
        || !(16..=1_024).contains(&arguments.queue_capacity)
        || arguments.queue_capacity < 16
    {
        return Err("arguments exceed registered bounds".into());
    }
    Ok(arguments)
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

fn requirement(index: usize) -> Result<ContextRequirement, Box<dyn Error>> {
    Ok(ContextRequirement {
        semantic_type: AtomKind::Documentation,
        selector: RequirementSelector::Query(format!("registered-requirement-{index}")),
        minimum_authority: 1,
        maximum_age: None,
        minimum_coverage: FixedPoint::new(0)?,
        blocking: true,
    })
}

fn contract() -> Result<ContextContract, Box<dyn Error>> {
    let requirements = (0..4).map(requirement).collect::<Result<Vec<_>, _>>()?;
    Ok(ContextContract {
        schema_version: SchemaVersion::new("cigar.context-contract", 1)?,
        job_goal: "Execute a bounded production workflow".to_owned(),
        operation_class: OperationClass::CodeChange,
        principal_id: record(1)?,
        purpose: "qualification".to_owned(),
        context_space_id: None,
        project_ids: vec![record(2)?],
        target: TargetProfile {
            provider: "qualification".to_owned(),
            model_family: "deterministic".to_owned(),
            tokenizer_fingerprint: digest(900_001)?,
            materializer_fingerprint: digest(900_002)?,
            max_context_tokens: 8_192,
        },
        budget: Budget {
            total_input_tokens: 4_096,
            output_reserve_tokens: 1_024,
            lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 4_096)]),
        },
        requirements,
        consistency: ConsistencyMode::Strong,
        maximum_staleness: None,
        extensions: ExtensionMap::default(),
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
        authority: 9_000,
        verification: 9_000,
        freshness: 10_000,
        novelty: 0,
        conflict_risk: 0,
        staleness: 0,
        estimated_tokens: tokens,
        requirement_coverage_bits: 0b1111,
        entity_coverage_bits: 0,
    }
}

fn candidate(index: usize) -> Result<CompilerCandidate, Box<dyn Error>> {
    let value = u64::try_from(index)?
        .checked_add(1)
        .ok_or("identity overflow")?;
    let score = 9_900_u16.saturating_sub(u16::try_from(index)?);
    Ok(CompilerCandidate {
        version_id: version(value)?,
        logical_id: version(value)?,
        lineage_id: lineage(u16::try_from(value)?)?,
        canonical_uri: SourceUri::new(format!("file:///qualification/{value:04}.md"))?,
        lane: LaneKind::Evidence,
        mandatory: false,
        requirement_indices: BTreeSet::from([0, 1, 2, 3]),
        entity_coverage_bits: 0,
        features: features(score, 24),
        policy_outcome: PolicyOutcome::Allow,
        pre_exclusion_reason: None,
        classification: Classification::Internal,
        instruction_authority: InstructionAuthority::Data,
        dependencies: BTreeSet::new(),
        representations: vec![RepresentationVariant {
            kind: RepresentationKind::Exact,
            content_digest: digest(100_000 + value)?,
            token_count: 24,
            loss: LossClass::Lossless,
            transform_receipt: None,
        }],
        claim: None,
        provenance_digest: digest(200_000 + value)?,
    })
}

fn compile_request() -> Result<CompileRequest, Box<dyn Error>> {
    let contract = contract()?;
    let candidates = (0..128).map(candidate).collect::<Result<Vec<_>, _>>()?;
    let profile = CompilerProfile::balanced_v4();
    let selection = QueryPlannerProfile::balanced_v4().candidate_selection;
    let mut decisions = Vec::with_capacity(candidates.len());
    for (index, item) in candidates.iter().enumerate() {
        let newly_covered = if index == 0 { 4 } else { 0 };
        let critical_gain = selection
            .critical_requirement_gain
            .checked_mul(i64::try_from(newly_covered)?)
            .ok_or("critical gain overflow")?;
        let base_score = item.features.score(RetrievalProfile::BalancedV4)?;
        decisions.push(CandidateRankingDecision {
            ordinal: index.checked_add(1).ok_or("ordinal overflow")?,
            selected_version: item.version_id.clone(),
            basis: if index == 0 {
                CandidateSelectionBasis::CriticalRequirement
            } else {
                CandidateSelectionBasis::Score
            },
            newly_covered_requirements: newly_covered,
            newly_covered_critical_requirements: newly_covered,
            newly_covered_concepts: 0,
            source_diversity: false,
            section_diversity: false,
            kind_diversity: false,
            factors: CandidateRankingFactors {
                base_score,
                critical_requirement_gain: critical_gain,
                requirement_gain: 0,
                concept_gain: 0,
                diversity_gain: 0,
                generic_penalty: 0,
                redundancy_penalty: 0,
                similarity_penalty: 0,
                adjusted_score: base_score
                    .checked_add(critical_gain)
                    .ok_or("adjusted score overflow")?,
            },
            next_best_version: None,
            next_best_adjusted_score: None,
            uncovered_critical_after: 0,
        });
    }
    let retrieval_plan_digest = digest(900_003)?;
    let ranking_evidence = RequirementRankingEvidence::new_v4(
        retrieval_plan_digest.clone(),
        BTreeSet::from([0, 1, 2, 3]),
        BTreeSet::new(),
        decisions,
    )?;
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

fn delta_bundles() -> Result<(ContextBundle, ContextBundle), Box<dyn Error>> {
    let mut blocks = Vec::new();
    for index in 0..64_u64 {
        blocks.push(ContextBlock {
            block_id: version(300_000 + index)?,
            lane: LaneKind::Evidence,
            representation: RepresentationKind::Exact,
            content_digest: digest(400_000 + index)?,
            token_count: 16,
            provenance: vec![version(500_000 + index)?],
            transform_receipt: None,
        });
    }
    let base = ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)?,
        bundle_id: version(600_001)?,
        contract_digest: digest(600_002)?,
        manifest_digest: digest(600_003)?,
        blocks: blocks.clone(),
        total_tokens: 1_024,
        extensions: ExtensionMap::default(),
    };
    let last = blocks.last_mut().ok_or("delta fixture is empty")?;
    last.block_id = version(600_004)?;
    last.content_digest = digest(600_005)?;
    last.provenance = vec![version(600_006)?];
    let target = ContextBundle {
        bundle_id: version(600_007)?,
        manifest_digest: digest(600_008)?,
        blocks,
        ..base.clone()
    };
    Ok((base, target))
}

enum Job {
    Full,
    Delta,
}

fn percentile(values: &mut [u64], numerator: usize, denominator: usize) -> u64 {
    values.sort_unstable();
    let index = values
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(values.len().saturating_sub(1));
    values.get(index).copied().unwrap_or(0)
}

fn atomic_max(target: &AtomicUsize, value: usize) {
    let mut current = target.load(Ordering::Relaxed);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn run_cell(
    operation: &'static str,
    concurrency: usize,
    queue_capacity: usize,
    iterations: usize,
    request: Arc<CompileRequest>,
    base: Arc<ContextBundle>,
    target: Arc<ContextBundle>,
) -> Result<Cell, Box<dyn Error>> {
    let (jobs_tx, jobs_rx) = mpsc::sync_channel(queue_capacity);
    let jobs_rx = Arc::new(Mutex::new(jobs_rx));
    let (results_tx, results_rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let queued = Arc::new(AtomicUsize::new(0));
    let maximum_queue_depth = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..concurrency {
        let jobs = Arc::clone(&jobs_rx);
        let results = results_tx.clone();
        let start = Arc::clone(&barrier);
        let request = Arc::clone(&request);
        let base = Arc::clone(&base);
        let target = Arc::clone(&target);
        let queued = Arc::clone(&queued);
        workers.push(thread::spawn(move || -> Result<(), String> {
            start.wait();
            loop {
                let job = jobs
                    .lock()
                    .map_err(|_| "job queue mutex poisoned".to_owned())?
                    .recv();
                let Ok(job) = job else { break };
                queued.fetch_sub(1, Ordering::AcqRel);
                let started = Instant::now();
                let identity = match job {
                    Job::Full => DeterministicCompiler
                        .compile((*request).clone())
                        .map_err(|error| error.to_string())?
                        .bundle
                        .bundle_id
                        .as_str()
                        .to_owned(),
                    Job::Delta => {
                        let delta =
                            generate_delta(&base, &target).map_err(|error| error.to_string())?;
                        apply_delta_verified(&base, &target, &delta)
                            .map_err(|error| error.to_string())?
                            .target_bundle_id()
                            .as_str()
                            .to_owned()
                    }
                };
                let elapsed = u64::try_from(started.elapsed().as_nanos())
                    .map_err(|_| "duration overflow".to_owned())?;
                results
                    .send((elapsed, identity))
                    .map_err(|_| "result receiver unavailable".to_owned())?;
            }
            Ok(())
        }));
    }
    drop(results_tx);
    barrier.wait();
    let wall_started = Instant::now();
    for _ in 0..iterations {
        let depth = queued.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        atomic_max(&maximum_queue_depth, depth.min(queue_capacity));
        let job = if operation == "full_bundle" {
            Job::Full
        } else {
            Job::Delta
        };
        if jobs_tx.send(job).is_err() {
            return Err("bounded job queue became unavailable".into());
        }
    }
    drop(jobs_tx);
    let mut durations = Vec::with_capacity(iterations);
    let mut identities = BTreeSet::new();
    for _ in 0..iterations {
        let (duration, identity) = results_rx.recv()?;
        durations.push(duration);
        identities.insert(identity);
    }
    let wall_nanoseconds = u64::try_from(wall_started.elapsed().as_nanos())?;
    for worker in workers {
        worker
            .join()
            .map_err(|_| "compile worker panicked")?
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
    }
    let mut p50_values = durations.clone();
    let p50 = percentile(&mut p50_values, 50, 100);
    let p95 = percentile(&mut durations, 95, 100);
    Ok(Cell {
        operation,
        concurrency,
        queue_capacity,
        iterations,
        wall_nanoseconds,
        operation_nanoseconds_p50: p50,
        operation_nanoseconds_p95: p95,
        maximum_queue_depth: maximum_queue_depth.load(Ordering::Acquire),
        rejected: 0,
        completed: iterations,
        deterministic: identities.len() == 1,
    })
}

fn run_allocation_iteration(
    request: &CompileRequest,
    base: &ContextBundle,
    target: &ContextBundle,
) -> Result<(), Box<dyn Error>> {
    let compiled = DeterministicCompiler.compile(request.clone())?;
    if compiled.bundle.blocks.is_empty() {
        return Err("allocation probe produced an empty full bundle".into());
    }
    let delta = generate_delta(base, target)?;
    let applied = apply_delta_verified(base, target, &delta)?;
    if applied.target_bundle_id() != &target.bundle_id {
        return Err("allocation probe delta identity changed".into());
    }
    Ok(())
}

fn allocation_probe(
    request: &CompileRequest,
    base: &ContextBundle,
    target: &ContextBundle,
) -> Result<AllocationProbe, Box<dyn Error>> {
    for _ in 0..ALLOCATION_WARMUP_ITERATIONS {
        run_allocation_iteration(request, base, target)?;
    }
    let live_bytes_before = LIVE_ALLOCATION_BYTES.load(Ordering::Acquire);
    let live_allocations_before = LIVE_ALLOCATION_COUNT.load(Ordering::Acquire);
    PEAK_ALLOCATION_BYTES.store(live_bytes_before, Ordering::Release);
    for _ in 0..ALLOCATION_MEASUREMENT_ITERATIONS {
        run_allocation_iteration(request, base, target)?;
    }
    let live_bytes_after = LIVE_ALLOCATION_BYTES.load(Ordering::Acquire);
    let live_allocations_after = LIVE_ALLOCATION_COUNT.load(Ordering::Acquire);
    let zero_monotonic_growth =
        live_bytes_after <= live_bytes_before && live_allocations_after <= live_allocations_before;
    Ok(AllocationProbe {
        warmup_iterations: ALLOCATION_WARMUP_ITERATIONS,
        measurement_iterations: ALLOCATION_MEASUREMENT_ITERATIONS,
        operations_per_iteration: 2,
        live_bytes_before,
        live_bytes_after,
        live_allocations_before,
        live_allocations_after,
        peak_live_bytes: PEAK_ALLOCATION_BYTES.load(Ordering::Acquire),
        zero_monotonic_growth,
    })
}

fn execute(arguments: &Arguments) -> Result<Report, Box<dyn Error>> {
    let request = Arc::new(compile_request()?);
    let (base, target) = delta_bundles()?;
    let base = Arc::new(base);
    let target = Arc::new(target);
    let allocation_probe = allocation_probe(&request, &base, &target)?;
    if !allocation_probe.zero_monotonic_growth {
        return Err("compile allocation probe observed monotonic live growth".into());
    }
    let mut cells = Vec::new();
    for operation in ["full_bundle", "delta"] {
        for concurrency in CONCURRENCY {
            cells.push(run_cell(
                operation,
                concurrency,
                arguments.queue_capacity,
                arguments.iterations,
                Arc::clone(&request),
                Arc::clone(&base),
                Arc::clone(&target),
            )?);
        }
    }
    if cells.iter().any(|cell| {
        !cell.deterministic
            || cell.completed != arguments.iterations
            || cell.rejected != 0
            || cell.maximum_queue_depth > arguments.queue_capacity
    }) {
        return Err("compile qualification invariant failed".into());
    }
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        compiler_profile: "cigar.compiler-profile.balanced.v4",
        candidate_count: 128,
        requirement_count: 4,
        queue_capacity: arguments.queue_capacity,
        iterations_per_cell: arguments.iterations,
        concurrency: CONCURRENCY,
        allocation_probe,
        cells,
    })
}

fn write_new(path: &PathBuf, value: &Report) -> Result<(), Box<dyn Error>> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(())
}

fn main() {
    let result = arguments().and_then(|arguments| {
        let report = execute(&arguments)?;
        write_new(&arguments.output, &report)?;
        Ok(())
    });
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
