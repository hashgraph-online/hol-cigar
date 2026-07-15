//! Production-linked bounded schedule models for the seven reviewed concurrency surfaces.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use cigar_api::TenantId;
use cigar_catalog::{
    ConnectorContext, DependencyInvalidator, InvalidationCause, InvalidationWorker,
};
use cigar_compiler::{CacheKey, CacheLayer, GovernedCache};
use cigar_daemon::{
    QueueErrorCode, RuntimeClock, WorkerCapacities, WorkerJob, WorkerKind, WorkerRuntime,
};
use cigar_protocol::{
    ContentDigest, ContextEdge, ContextSpaceId, CoordinationEvent, CoordinationEventKind, EdgeKind,
    ExpectedRevision, ExtensionMap, Lifecycle, Overlay, OverlayMutation, RecordId, SchemaVersion,
    UtcTimestamp, VersionId,
};
use cigar_space::{
    ContextSpaceService, CreateSpaceRequest, EventCursor, ProposedMutation, PublishOutcome,
    PublishRequest, ResourceKey, SpaceError, SpaceHierarchy,
};
use cigar_store::{
    CancellationToken, InMemoryStore, ServiceBatch, ServiceErrorCode, ServiceExpectedVersion,
    ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite, ServiceRepository,
    ServiceResponse, StoreRevision, WorkerLocator, WorkerUpdate,
};
use loom::model::Builder;
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{
    AtomicBool as StdAtomicBool, AtomicU64 as StdAtomicU64, AtomicUsize as StdAtomicUsize,
};
use std::sync::{Arc as StdArc, Barrier, Mutex as StdMutex};
use std::thread as std_thread;
use std::time::{Duration, Instant};

const MANIFEST_BYTES: &[u8] = include_bytes!("../model-refinement-v1.json");
const EXPECTED_SCHEMA: &str = "cigar.loom-production-refinement.v1";
const EXPECTED_MODEL_IDS: [&str; 7] = [
    "MODEL-CACHE-PUBLICATION",
    "MODEL-SNAPSHOT-VISIBILITY",
    "MODEL-CONTEXT-REVISION",
    "MODEL-OUTBOX-FENCING",
    "MODEL-SUBSCRIPTION-CURSOR",
    "MODEL-INVALIDATION-QUEUE",
    "MODEL-SHUTDOWN-GATE",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefinementManifest {
    schema_version: String,
    platform: PlatformBinding,
    loom: LoomBinding,
    evidence_class: String,
    direct_race_guard: DirectRaceGuard,
    models: Vec<ModelDescriptor>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformBinding {
    os: String,
    architecture: String,
    target: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoomBinding {
    crate_version: String,
    scheduler: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectRaceGuard {
    model_side_serialization: bool,
    snapshot_and_worker_iterations: u64,
    context_publication_iterations: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelDescriptor {
    id: String,
    test: String,
    production_bindings: Vec<ProductionBinding>,
    synchronization_refinement: String,
    configuration: ModelConfiguration,
    expected_schedules: usize,
    required_branches: Vec<String>,
    divergence_mutants: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionBinding {
    crate_name: String,
    source: String,
    symbols: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelConfiguration {
    max_threads: usize,
    max_branches: usize,
    max_permutations: Option<usize>,
    max_duration_seconds: Option<u64>,
    preemption_bound: Option<usize>,
    checkpointing: bool,
    expect_explicit_explore: bool,
    location_tracking: bool,
    logging: bool,
}

#[derive(Default)]
struct RunEvidence {
    schedules: StdAtomicUsize,
    branches: StdAtomicU64,
}

fn manifest() -> RefinementManifest {
    serde_json::from_slice(MANIFEST_BYTES).expect("model refinement manifest must be strict JSON")
}

fn descriptor(test: &str) -> ModelDescriptor {
    manifest()
        .models
        .into_iter()
        .find(|model| model.test == test)
        .expect("every model test must have one evidence descriptor")
}

fn observe_branch(evidence: &RunEvidence, branch: usize) {
    let mask = 1_u64
        .checked_shl(u32::try_from(branch).expect("branch index fits u32"))
        .expect("branch index is bounded by the manifest verifier");
    evidence
        .branches
        .fetch_or(mask, std::sync::atomic::Ordering::SeqCst);
}

fn run_model<F>(descriptor: ModelDescriptor, model: F)
where
    F: Fn(StdArc<RunEvidence>) + Send + Sync + 'static,
{
    let evidence = StdArc::new(RunEvidence::default());
    let execution_evidence = StdArc::clone(&evidence);
    let mut builder = Builder::new();
    builder.max_threads = descriptor.configuration.max_threads;
    builder.max_branches = descriptor.configuration.max_branches;
    builder.max_permutations = descriptor.configuration.max_permutations;
    builder.max_duration = descriptor
        .configuration
        .max_duration_seconds
        .map(Duration::from_secs);
    builder.preemption_bound = descriptor.configuration.preemption_bound;
    builder.checkpoint_file = None;
    builder.expect_explicit_explore = descriptor.configuration.expect_explicit_explore;
    builder.location = descriptor.configuration.location_tracking;
    builder.log = descriptor.configuration.logging;
    builder.check(move || {
        execution_evidence
            .schedules
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        model(StdArc::clone(&execution_evidence));
    });

    let schedules = evidence.schedules.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        schedules, descriptor.expected_schedules,
        "{} schedule count diverged from reviewed evidence",
        descriptor.id
    );
    let expected_branch_mask = 1_u64
        .checked_shl(
            u32::try_from(descriptor.required_branches.len()).expect("branch count fits u32"),
        )
        .expect("branch count is bounded by the manifest verifier")
        .saturating_sub(1);
    assert_eq!(
        evidence.branches.load(std::sync::atomic::Ordering::SeqCst),
        expected_branch_mask,
        "{} did not exercise every named branch",
        descriptor.id
    );
}

fn record(value: u64) -> RecordId {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{value:012x}"))
        .expect("model record ID is valid")
}

fn version(value: u64) -> VersionId {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    VersionId::new(encoded).expect("model version ID is valid")
}

fn content(value: u64) -> ContentDigest {
    ContentDigest::new(version(value).as_str()).expect("model content digest is valid")
}

fn timestamp(second: u8) -> UtcTimestamp {
    UtcTimestamp::parse_rfc3339(&format!("2026-07-14T12:00:{second:02}Z"))
        .expect("model timestamp is valid")
}

struct SpaceFixture {
    service: ContextSpaceService,
    space_id: ContextSpaceId,
    owner: RecordId,
    project: RecordId,
}

fn space_fixture() -> SpaceFixture {
    let service = ContextSpaceService::new();
    let space_id = ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")
        .expect("model space ID is valid");
    let owner = record(1);
    let project = record(2);
    let genesis = service
        .create_space(CreateSpaceRequest {
            space_id: space_id.clone(),
            hierarchy: SpaceHierarchy {
                tenant_id: record(3),
                workspace_id: record(4),
                active_project_id: project.clone(),
                branch_id: record(5),
                task_id: record(6),
                session_id: record(7),
            },
            author_id: owner.clone(),
            purpose: "loom production refinement genesis".to_owned(),
            policy_snapshot_digest: content(8),
            committed_at: timestamp(0),
            event_id: record(9),
        })
        .expect("production space genesis succeeds");
    assert_eq!(genesis.sequence, 1);
    SpaceFixture {
        service,
        space_id,
        owner,
        project,
    }
}

fn model_overlay(fixture: &SpaceFixture, id: u64, key: &str, value: u64) -> RecordId {
    let overlay = Overlay {
        schema_version: SchemaVersion::new("cigar.overlay", 1)
            .expect("model overlay schema is valid"),
        overlay_id: record(id),
        space_id: fixture.space_id.clone(),
        base_commit_id: fixture
            .service
            .head(&fixture.space_id)
            .expect("production head exists")
            .commit_id,
        owner_id: fixture.owner.clone(),
        created_at: timestamp(1),
        expires_at: timestamp(59),
        mutations: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    let overlay_id = overlay.overlay_id.clone();
    fixture
        .service
        .create_overlay(overlay)
        .expect("production overlay creation succeeds");
    fixture
        .service
        .propose(
            &fixture.space_id,
            &overlay_id,
            &fixture.owner,
            ProposedMutation {
                key: ResourceKey::new(key).expect("model resource key is valid"),
                mutation: OverlayMutation::Artifact(version(value)),
            },
        )
        .expect("production proposal succeeds");
    overlay_id
}

fn publish_request(owner: &RecordId, event: u64) -> PublishRequest {
    PublishRequest {
        expected_head: ExpectedRevision(1),
        actor_id: owner.clone(),
        purpose: "loom optimistic publication".to_owned(),
        policy_snapshot_digest: content(8),
        committed_at: timestamp(2),
        event_id: record(event),
    }
}

fn append_model_event(fixture: &SpaceFixture, event: u64, second: u8) {
    let expected = fixture
        .service
        .head(&fixture.space_id)
        .expect("production head exists")
        .sequence;
    fixture
        .service
        .append_events(
            &fixture.space_id,
            fixture.project.clone(),
            PublishRequest {
                expected_head: ExpectedRevision(expected),
                actor_id: fixture.owner.clone(),
                purpose: "loom subscription event".to_owned(),
                policy_snapshot_digest: content(8),
                committed_at: timestamp(second),
                event_id: record(event + 100),
            },
            vec![CoordinationEvent {
                event_id: record(event),
                kind: CoordinationEventKind::TaskCheckpointed,
                payload_digest: content(event),
            }],
        )
        .expect("production event append succeeds");
}

fn cache_observation_valid(observed: Option<&[u8]>) -> bool {
    observed.is_none_or(|bytes| bytes == b"complete-cache-entry")
}

fn snapshot_observation_valid(
    revision: Option<StoreRevision>,
    version: Option<u64>,
    bytes: Option<&[u8]>,
) -> bool {
    matches!(
        (revision, version, bytes),
        (None, None, None) | (Some(StoreRevision(1)), Some(1), Some(b"complete-snapshot"))
    )
}

const fn exclusive_winner_valid(winners: usize) -> bool {
    winners == 1
}

const fn cursor_transition_valid(before: EventCursor, after: EventCursor) -> bool {
    after.0 >= before.0
}

fn invalidation_observation_valid(invalidated: bool, cached: Option<u64>) -> bool {
    !(invalidated && cached.is_some())
}

const fn shutdown_observation_valid(observed_closed: bool, accepted: bool) -> bool {
    !(observed_closed && accepted)
}

#[test]
fn cache_publication_refines_production_governed_cache() {
    run_model(
        descriptor("cache_publication_refines_production_governed_cache"),
        |evidence| {
            let policy = content(10);
            let key = CacheKey::new(
                CacheLayer::Materialization,
                "tenant-a",
                "private",
                content(11),
            )
            .expect("model cache key is valid");
            let cache = Arc::new(Mutex::new(Some(
                GovernedCache::new(4, 1_024).expect("model cache bounds are valid"),
            )));

            let publisher_cache = Arc::clone(&cache);
            let publisher_key = key.clone();
            let publisher_policy = policy.clone();
            let publisher = thread::spawn(move || {
                thread::yield_now();
                let inserted = publisher_cache
                    .lock()
                    .expect("cache publication lock")
                    .as_mut()
                    .expect("production cache is initialized")
                    .insert(
                        publisher_key,
                        b"complete-cache-entry".to_vec(),
                        publisher_policy,
                        7,
                    );
                assert!(inserted);
            });
            let reader_cache = Arc::clone(&cache);
            let reader_key = key.clone();
            let reader_policy = policy.clone();
            let reader_evidence = StdArc::clone(&evidence);
            let reader = thread::spawn(move || {
                thread::yield_now();
                let observed = reader_cache
                    .lock()
                    .expect("cache observation lock")
                    .as_mut()
                    .and_then(|cache| cache.get(&reader_key, &reader_policy, 7, |_key| true));
                assert!(cache_observation_valid(observed.as_deref()));
                observe_branch(&reader_evidence, usize::from(observed.is_some()));
            });
            publisher.join().expect("publisher joins");
            reader.join().expect("reader joins");
            let final_value = cache
                .lock()
                .expect("final cache lock")
                .as_mut()
                .and_then(|cache| cache.get(&key, &policy, 7, |_key| true));
            assert_eq!(
                final_value.as_deref(),
                Some(b"complete-cache-entry".as_slice())
            );
        },
    );
}

#[test]
fn snapshot_visibility_refines_production_mvcc_store() {
    run_model(
        descriptor("snapshot_visibility_refines_production_mvcc_store"),
        |evidence| {
            let store = Arc::new(InMemoryStore::default());
            let tenant = record(20);
            let locator = ServiceRecordLocator::new(tenant.clone(), "loom", "snapshot")
                .expect("model service locator is valid");
            assert!(
                store
                    .service_get(
                        &locator,
                        ServiceRecordSelection::Latest,
                        &CancellationToken::default(),
                    )
                    .expect("production pre-publication read succeeds")
                    .is_none()
            );
            observe_branch(&evidence, 0);
            let writer_store = Arc::clone(&store);
            let writer = thread::spawn(move || {
                thread::yield_now();
                let write = ServiceRecordWrite::new(
                    "loom",
                    "snapshot",
                    ServiceExpectedVersion::Absent,
                    b"complete-snapshot".to_vec(),
                )
                .expect("model service write is valid");
                let response =
                    ServiceResponse::new(200, "application/octet-stream", b"ok".to_vec())
                        .expect("model service response is valid");
                let receipt = writer_store
                    .service_commit(
                        ServiceBatch::new(tenant, vec![write], response)
                            .expect("model service batch is valid"),
                        &CancellationToken::default(),
                    )
                    .expect("production MVCC publication succeeds");
                assert_eq!(receipt.revision, StoreRevision(1));
            });
            let reader_store = Arc::clone(&store);
            let reader_locator = locator.clone();
            let reader = thread::spawn(move || {
                thread::yield_now();
                let observed = reader_store
                    .service_get(
                        &reader_locator,
                        ServiceRecordSelection::Latest,
                        &CancellationToken::default(),
                    )
                    .expect("production snapshot read succeeds");
                assert!(snapshot_observation_valid(
                    observed.as_ref().map(|record| record.store_revision()),
                    observed.as_ref().map(|record| record.version()),
                    observed.as_ref().map(|record| record.bytes()),
                ));
            });
            writer.join().expect("snapshot writer joins");
            reader.join().expect("snapshot reader joins");
            let final_record = store
                .service_get(
                    &locator,
                    ServiceRecordSelection::Latest,
                    &CancellationToken::default(),
                )
                .expect("final production snapshot read succeeds")
                .expect("final production snapshot exists");
            assert!(snapshot_observation_valid(
                Some(final_record.store_revision()),
                Some(final_record.version()),
                Some(final_record.bytes()),
            ));
            observe_branch(&evidence, 1);
        },
    );
}

#[test]
fn context_revision_refines_production_space_publication() {
    run_model(
        descriptor("context_revision_refines_production_space_publication"),
        |evidence| {
            let fixture = space_fixture();
            let left_overlay = model_overlay(&fixture, 30, "artifact/left", 31);
            let right_overlay = model_overlay(&fixture, 32, "artifact/right", 33);
            let service = Arc::new(fixture.service);
            let winners = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for (overlay_id, event_id) in [(left_overlay, 34_u64), (right_overlay, 35)] {
                let service = Arc::clone(&service);
                let space_id = fixture.space_id.clone();
                let owner = fixture.owner.clone();
                let winners = Arc::clone(&winners);
                let thread_evidence = StdArc::clone(&evidence);
                handles.push(thread::spawn(move || {
                    thread::yield_now();
                    match service.publish(&space_id, &overlay_id, publish_request(&owner, event_id))
                    {
                        Ok(PublishOutcome::Published(commit)) => {
                            assert_eq!(commit.sequence, 2);
                            winners.fetch_add(1, Ordering::AcqRel);
                            observe_branch(&thread_evidence, 0);
                        }
                        Err(SpaceError::StaleRevision) => observe_branch(&thread_evidence, 1),
                        other => panic!("unexpected production publication outcome: {other:?}"),
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("context writer joins");
            }
            let winner_count = winners.load(Ordering::Acquire);
            assert!(exclusive_winner_valid(winner_count));
            assert_eq!(
                service
                    .head(&fixture.space_id)
                    .expect("production head remains readable")
                    .sequence,
                2
            );
        },
    );
}

#[test]
fn outbox_fencing_refines_production_worker_claim() {
    run_model(
        descriptor("outbox_fencing_refines_production_worker_claim"),
        |evidence| {
            let store = Arc::new(InMemoryStore::default());
            let locator = WorkerLocator::new(record(40), "outbox-indexer")
                .expect("model worker locator is valid");
            let winners = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for owner in ["daemon-a", "daemon-b"] {
                let store = Arc::clone(&store);
                let locator = locator.clone();
                let winners = Arc::clone(&winners);
                let thread_evidence = StdArc::clone(&evidence);
                handles.push(thread::spawn(move || {
                    thread::yield_now();
                    match store.worker_update(
                        &locator,
                        WorkerUpdate::Claim {
                            expected: ServiceExpectedVersion::Absent,
                            owner: owner.to_owned(),
                            now_unix_nanos: 10,
                            expires_at_unix_nanos: 100,
                        },
                        &CancellationToken::default(),
                    ) {
                        Ok(state) => {
                            assert_eq!((state.version(), state.fencing_token()), (1, 1));
                            winners.fetch_add(1, Ordering::AcqRel);
                            observe_branch(&thread_evidence, 0);
                        }
                        Err(error) => {
                            assert_eq!(error.code(), ServiceErrorCode::RevisionConflict);
                            observe_branch(&thread_evidence, 1);
                        }
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("outbox claimant joins");
            }
            assert!(exclusive_winner_valid(winners.load(Ordering::Acquire)));
            let retained = store
                .worker_get(&locator, &CancellationToken::default())
                .expect("production worker read succeeds")
                .expect("winning worker state exists");
            assert_eq!((retained.version(), retained.fencing_token()), (1, 1));
            assert!(retained.lease_owner().is_some());
        },
    );
}

#[test]
fn subscription_cursor_refines_production_event_pages() {
    run_model(
        descriptor("subscription_cursor_refines_production_event_pages"),
        |evidence| {
            let fixture = space_fixture();
            append_model_event(&fixture, 50, 2);
            append_model_event(&fixture, 51, 3);
            let service = Arc::new(fixture.service);
            let cursor = Arc::new(AtomicU64::new(0));
            let projects: BTreeSet<_> = [fixture.project].into_iter().collect();
            let mut handles = Vec::new();
            for (branch, after, limit) in
                [(0_usize, EventCursor(0), 1_usize), (1, EventCursor(1), 2)]
            {
                let service = Arc::clone(&service);
                let cursor = Arc::clone(&cursor);
                let space_id = fixture.space_id.clone();
                let projects = projects.clone();
                let thread_evidence = StdArc::clone(&evidence);
                handles.push(thread::spawn(move || {
                    thread::yield_now();
                    let page = service
                        .poll_events(&space_id, &projects, after, limit)
                        .expect("production event page succeeds");
                    let candidate = page.resume_cursor;
                    assert!(candidate.0 > after.0);
                    let mut current = cursor.load(Ordering::Acquire);
                    loop {
                        let next = EventCursor(current).advance_to(candidate).0;
                        match cursor.compare_exchange_weak(
                            current,
                            next,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => {
                                if current == 0 {
                                    observe_branch(&thread_evidence, branch);
                                }
                                assert!(cursor_transition_valid(
                                    EventCursor(current),
                                    EventCursor(next),
                                ));
                                break;
                            }
                            Err(observed) => current = observed,
                        }
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("subscription acknowledger joins");
            }
            assert_eq!(cursor.load(Ordering::Acquire), 3);
        },
    );
}

struct InvalidationModelState {
    batch: cigar_catalog::InvalidationBatch,
    cached: Option<u64>,
}

#[test]
fn invalidation_queue_refines_production_dependency_worker() {
    run_model(
        descriptor("invalidation_queue_refines_production_dependency_worker"),
        |evidence| {
            let root = version(60);
            let dependent = version(61);
            let edge = ContextEdge {
                schema_version: "cigar.edge.v1".parse().expect("model edge schema is valid"),
                edge_id: record(62),
                from_version: dependent,
                to_version: root.clone(),
                kind: EdgeKind::DerivedFrom,
                provenance_digest: content(63),
                lifecycle: Lifecycle::Active,
                superseded_by: None,
                extensions: ExtensionMap::default(),
            };
            let worker = Arc::new(
                DependencyInvalidator::new(&[edge]).expect("production dependency graph is valid"),
            );
            let state = Arc::new(Mutex::new(InvalidationModelState {
                batch: DependencyInvalidator::start(
                    root.clone(),
                    InvalidationCause::SourceChanged,
                    Some(root.clone()),
                    None,
                    StoreRevision(7),
                ),
                cached: Some(42),
            }));

            let invalidator_worker = Arc::clone(&worker);
            let invalidator_state = Arc::clone(&state);
            let invalidator_root = root.clone();
            let invalidator = thread::spawn(move || {
                thread::yield_now();
                let mut guarded = invalidator_state.lock().expect("invalidation state lock");
                guarded.batch = invalidator_worker
                    .process(
                        guarded.batch.clone(),
                        1,
                        &ConnectorContext::new(
                            CancellationToken::default(),
                            Instant::now() + Duration::from_secs(1),
                        ),
                    )
                    .expect("production invalidation step succeeds");
                if guarded.batch.invalidated.contains(&invalidator_root) {
                    guarded.cached = None;
                }
            });
            let reader_state = Arc::clone(&state);
            let reader_root = root.clone();
            let reader_evidence = StdArc::clone(&evidence);
            let reader = thread::spawn(move || {
                thread::yield_now();
                let guarded = reader_state.lock().expect("invalidation observation lock");
                let invalidated = guarded.batch.invalidated.contains(&reader_root);
                assert!(invalidation_observation_valid(invalidated, guarded.cached));
                observe_branch(&reader_evidence, usize::from(invalidated));
            });
            invalidator.join().expect("invalidator joins");
            reader.join().expect("invalidation reader joins");
            let final_state = state.lock().expect("final invalidation lock");
            assert!(final_state.batch.invalidated.contains(&root));
            assert!(final_state.cached.is_none());
        },
    );
}

#[derive(Debug, Default)]
struct FixedClock;

impl RuntimeClock for FixedClock {
    fn now_nanos(&self) -> u64 {
        1
    }
}

fn worker_capacities() -> WorkerCapacities {
    WorkerCapacities {
        ingestion: 1,
        indexing: 1,
        invalidation: 1,
        compilation: 1,
        outbox: 1,
        reconciliation: 1,
        lease_cleanup: 1,
        backup: 1,
        garbage_collection: 1,
    }
}

fn worker_job() -> WorkerJob {
    WorkerJob {
        tenant: TenantId::new("tenant-a").expect("model tenant is valid"),
        record_id: record(70),
        expected_revision: None,
    }
}

#[test]
fn shutdown_gate_refines_production_worker_admission() {
    run_model(
        descriptor("shutdown_gate_refines_production_worker_admission"),
        |evidence| {
            let (runtime, receivers) =
                WorkerRuntime::new(&worker_capacities(), StdArc::new(FixedClock))
                    .expect("production worker runtime is valid");
            let runtime = Arc::new(runtime);
            let queue = runtime
                .queue(WorkerKind::Outbox)
                .expect("production outbox queue exists");
            let closed = Arc::new(AtomicBool::new(false));
            let worker_closed = Arc::clone(&closed);
            let worker_evidence = StdArc::clone(&evidence);
            let worker = thread::spawn(move || {
                let observed_closed = worker_closed.load(Ordering::Acquire);
                let result = queue.try_enqueue(worker_job());
                let accepted = result.is_ok();
                assert!(shutdown_observation_valid(observed_closed, accepted));
                match result {
                    Ok(()) => observe_branch(&worker_evidence, 0),
                    Err(error) => {
                        assert_eq!(error.code(), QueueErrorCode::NotAccepting);
                        observe_branch(&worker_evidence, 1);
                    }
                }
            });
            let shutdown_runtime = Arc::clone(&runtime);
            let shutdown_closed = Arc::clone(&closed);
            let shutdown = thread::spawn(move || {
                shutdown_runtime.stop_accepting();
                shutdown_closed.store(true, Ordering::Release);
            });
            shutdown.join().expect("shutdown joins");
            worker.join().expect("worker joins");
            assert!(
                runtime
                    .metrics()
                    .expect("production queue metrics remain readable")
                    .iter()
                    .all(|metric| !metric.accepting)
            );
            drop(receivers);
        },
    );
}

#[test]
fn production_races_run_without_model_side_serialization() {
    let guard = manifest().direct_race_guard;
    assert!(!guard.model_side_serialization);
    for round in 0_u64..guard.snapshot_and_worker_iterations {
        let store = StdArc::new(InMemoryStore::default());
        let tenant = record(1_000 + round);
        let locator = ServiceRecordLocator::new(tenant.clone(), "loom", "snapshot")
            .expect("direct-race service locator is valid");
        let barrier = StdArc::new(Barrier::new(3));
        let writer_store = StdArc::clone(&store);
        let writer_barrier = StdArc::clone(&barrier);
        let writer = std_thread::spawn(move || {
            writer_barrier.wait();
            writer_store.service_commit(
                ServiceBatch::new(
                    tenant,
                    vec![
                        ServiceRecordWrite::new(
                            "loom",
                            "snapshot",
                            ServiceExpectedVersion::Absent,
                            b"complete-snapshot".to_vec(),
                        )
                        .expect("direct-race write is valid"),
                    ],
                    ServiceResponse::new(200, "application/octet-stream", b"ok".to_vec())
                        .expect("direct-race response is valid"),
                )
                .expect("direct-race batch is valid"),
                &CancellationToken::default(),
            )
        });
        let reader_store = StdArc::clone(&store);
        let reader_locator = locator.clone();
        let reader_barrier = StdArc::clone(&barrier);
        let reader = std_thread::spawn(move || {
            reader_barrier.wait();
            reader_store.service_get(
                &reader_locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )
        });
        barrier.wait();
        let receipt = writer
            .join()
            .expect("direct-race snapshot writer joins")
            .expect("direct-race snapshot publication succeeds");
        assert_eq!(receipt.revision, StoreRevision(1));
        let observed = reader
            .join()
            .expect("direct-race snapshot reader joins")
            .expect("direct-race snapshot read succeeds");
        assert!(snapshot_observation_valid(
            observed.as_ref().map(|record| record.store_revision()),
            observed.as_ref().map(|record| record.version()),
            observed.as_ref().map(|record| record.bytes()),
        ));

        let store = StdArc::new(InMemoryStore::default());
        let worker_locator = WorkerLocator::new(record(2_000 + round), "outbox-indexer")
            .expect("direct-race worker locator is valid");
        let barrier = StdArc::new(Barrier::new(3));
        let mut claimants = Vec::new();
        for owner in ["daemon-a", "daemon-b"] {
            let store = StdArc::clone(&store);
            let locator = worker_locator.clone();
            let barrier = StdArc::clone(&barrier);
            claimants.push(std_thread::spawn(move || {
                barrier.wait();
                store.worker_update(
                    &locator,
                    WorkerUpdate::Claim {
                        expected: ServiceExpectedVersion::Absent,
                        owner: owner.to_owned(),
                        now_unix_nanos: 10,
                        expires_at_unix_nanos: 100,
                    },
                    &CancellationToken::default(),
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = claimants
            .into_iter()
            .map(|claimant| claimant.join().expect("direct-race claimant joins"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    result
                        .as_ref()
                        .is_err_and(|error| error.code() == ServiceErrorCode::RevisionConflict)
                })
                .count(),
            1
        );
    }

    for round in 0_u64..guard.context_publication_iterations {
        let fixture = space_fixture();
        let left = model_overlay(&fixture, 3_000 + round * 4, "artifact/left", 3_001 + round);
        let right = model_overlay(&fixture, 3_002 + round * 4, "artifact/right", 3_003 + round);
        let service = StdArc::new(fixture.service);
        let barrier = StdArc::new(Barrier::new(3));
        let mut writers = Vec::new();
        for (overlay, event) in [(left, 4_000 + round * 2), (right, 4_001 + round * 2)] {
            let service = StdArc::clone(&service);
            let barrier = StdArc::clone(&barrier);
            let space_id = fixture.space_id.clone();
            let owner = fixture.owner.clone();
            writers.push(std_thread::spawn(move || {
                barrier.wait();
                service.publish(&space_id, &overlay, publish_request(&owner, event))
            }));
        }
        barrier.wait();
        let results: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().expect("direct-race context writer joins"))
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(PublishOutcome::Published(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(SpaceError::StaleRevision)))
                .count(),
            1
        );
    }
}

#[test]
fn production_tsan_surface_matrix_covers_remaining_paths() {
    let policy = content(5_000);
    let key = CacheKey::new(
        CacheLayer::Materialization,
        "tenant-a",
        "private",
        content(5_001),
    )
    .expect("native cache key is valid");
    let cache = StdArc::new(StdMutex::new(
        GovernedCache::new(4, 1_024).expect("native cache bounds are valid"),
    ));
    let barrier = StdArc::new(Barrier::new(3));
    let publisher_cache = StdArc::clone(&cache);
    let publisher_barrier = StdArc::clone(&barrier);
    let publisher_key = key.clone();
    let publisher_policy = policy.clone();
    let publisher = std_thread::spawn(move || {
        publisher_barrier.wait();
        publisher_cache
            .lock()
            .expect("native cache publication lock")
            .insert(
                publisher_key,
                b"complete-cache-entry".to_vec(),
                publisher_policy,
                7,
            )
    });
    let reader_cache = StdArc::clone(&cache);
    let reader_barrier = StdArc::clone(&barrier);
    let reader_key = key.clone();
    let reader_policy = policy.clone();
    let reader = std_thread::spawn(move || {
        reader_barrier.wait();
        reader_cache
            .lock()
            .expect("native cache observation lock")
            .get(&reader_key, &reader_policy, 7, |_key| true)
    });
    barrier.wait();
    assert!(publisher.join().expect("cache publisher joins"));
    let observed = reader.join().expect("cache reader joins");
    assert!(cache_observation_valid(observed.as_deref()));
    assert_eq!(
        cache
            .lock()
            .expect("final native cache lock")
            .get(&key, &policy, 7, |_key| true)
            .as_deref(),
        Some(b"complete-cache-entry".as_slice())
    );

    let fixture = space_fixture();
    append_model_event(&fixture, 5_100, 2);
    append_model_event(&fixture, 5_101, 3);
    let service = StdArc::new(fixture.service);
    let projects: BTreeSet<_> = [fixture.project].into_iter().collect();
    let cursor = StdArc::new(StdAtomicU64::new(0));
    let barrier = StdArc::new(Barrier::new(3));
    let mut readers = Vec::new();
    for (after, limit) in [(EventCursor(0), 1_usize), (EventCursor(1), 2_usize)] {
        let service = StdArc::clone(&service);
        let projects = projects.clone();
        let space_id = fixture.space_id.clone();
        let cursor = StdArc::clone(&cursor);
        let barrier = StdArc::clone(&barrier);
        readers.push(std_thread::spawn(move || {
            barrier.wait();
            let candidate = service
                .poll_events(&space_id, &projects, after, limit)
                .expect("native event page succeeds")
                .resume_cursor;
            let mut current = cursor.load(std::sync::atomic::Ordering::Acquire);
            loop {
                let next = EventCursor(current).advance_to(candidate).0;
                match cursor.compare_exchange_weak(
                    current,
                    next,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        }));
    }
    barrier.wait();
    for reader in readers {
        reader.join().expect("event reader joins");
    }
    assert_eq!(cursor.load(std::sync::atomic::Ordering::Acquire), 3);

    let root = version(5_200);
    let dependent = version(5_201);
    let worker = StdArc::new(
        DependencyInvalidator::new(&[ContextEdge {
            schema_version: "cigar.edge.v1"
                .parse()
                .expect("native edge schema is valid"),
            edge_id: record(5_202),
            from_version: dependent.clone(),
            to_version: root.clone(),
            kind: EdgeKind::DerivedFrom,
            provenance_digest: content(5_203),
            lifecycle: Lifecycle::Active,
            superseded_by: None,
            extensions: ExtensionMap::default(),
        }])
        .expect("native dependency graph is valid"),
    );
    let batch = DependencyInvalidator::start(
        root.clone(),
        InvalidationCause::SourceChanged,
        Some(root.clone()),
        None,
        StoreRevision(9),
    );
    let barrier = StdArc::new(Barrier::new(3));
    let mut invalidators = Vec::new();
    for _ in 0..2 {
        let worker = StdArc::clone(&worker);
        let batch = batch.clone();
        let root = root.clone();
        let dependent = dependent.clone();
        let barrier = StdArc::clone(&barrier);
        invalidators.push(std_thread::spawn(move || {
            barrier.wait();
            let completed = worker
                .process(
                    batch,
                    8,
                    &ConnectorContext::new(
                        CancellationToken::default(),
                        Instant::now() + Duration::from_secs(1),
                    ),
                )
                .expect("native invalidation completes");
            assert!(completed.invalidated.contains(&root));
            assert!(completed.invalidated.contains(&dependent));
        }));
    }
    barrier.wait();
    for invalidator in invalidators {
        invalidator.join().expect("invalidation worker joins");
    }

    let (runtime, receivers) = WorkerRuntime::new(&worker_capacities(), StdArc::new(FixedClock))
        .expect("native worker runtime is valid");
    let runtime = StdArc::new(runtime);
    let queue = runtime
        .queue(WorkerKind::Invalidation)
        .expect("native invalidation queue exists");
    let closed = StdArc::new(StdAtomicBool::new(false));
    let barrier = StdArc::new(Barrier::new(3));
    let admission_closed = StdArc::clone(&closed);
    let admission_barrier = StdArc::clone(&barrier);
    let admission = std_thread::spawn(move || {
        admission_barrier.wait();
        let observed_closed = admission_closed.load(std::sync::atomic::Ordering::Acquire);
        let accepted = queue.try_enqueue(worker_job()).is_ok();
        assert!(shutdown_observation_valid(observed_closed, accepted));
    });
    let shutdown_runtime = StdArc::clone(&runtime);
    let shutdown_closed = StdArc::clone(&closed);
    let shutdown_barrier = StdArc::clone(&barrier);
    let shutdown = std_thread::spawn(move || {
        shutdown_barrier.wait();
        shutdown_runtime.stop_accepting();
        shutdown_closed.store(true, std::sync::atomic::Ordering::Release);
    });
    barrier.wait();
    shutdown.join().expect("native shutdown joins");
    admission.join().expect("native admission joins");
    assert!(
        runtime
            .metrics()
            .expect("native queue metrics remain readable")
            .iter()
            .all(|metric| !metric.accepting)
    );
    drop(receivers);
}

#[test]
fn refinement_manifest_is_complete_and_source_bound() {
    let manifest = manifest();
    assert_eq!(manifest.schema_version, EXPECTED_SCHEMA);
    assert_eq!(manifest.platform.os, "macos");
    assert_eq!(manifest.platform.architecture, "aarch64");
    assert_eq!(manifest.platform.target, "aarch64-apple-darwin");
    assert_eq!(manifest.loom.crate_version, "0.7.2");
    assert_eq!(manifest.loom.scheduler, "loom::model::Builder");
    assert_eq!(manifest.evidence_class, "development_diagnostic");
    assert!(!manifest.direct_race_guard.model_side_serialization);
    assert_eq!(
        manifest.direct_race_guard.snapshot_and_worker_iterations,
        64
    );
    assert_eq!(
        manifest.direct_race_guard.context_publication_iterations,
        16
    );
    assert_eq!(std::env::consts::OS, manifest.platform.os);
    assert_eq!(std::env::consts::ARCH, manifest.platform.architecture);

    let ids: Vec<_> = manifest
        .models
        .iter()
        .map(|model| model.id.as_str())
        .collect();
    assert_eq!(ids, EXPECTED_MODEL_IDS);
    let mut tests = HashSet::new();
    let mut mutants = HashSet::new();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for model in &manifest.models {
        assert!(
            tests.insert(model.test.as_str()),
            "duplicate model test binding"
        );
        assert!(!model.synchronization_refinement.is_empty());
        assert_eq!(model.configuration.max_threads, 3);
        assert!(model.configuration.max_branches > 0);
        assert!(model.configuration.max_permutations.is_none());
        assert!(model.configuration.max_duration_seconds.is_none());
        assert!(model.configuration.preemption_bound.is_some());
        assert!(model.expected_schedules > 0);
        assert!(!model.configuration.checkpointing);
        assert!(!model.configuration.expect_explicit_explore);
        assert!(!model.configuration.location_tracking);
        assert!(!model.configuration.logging);
        assert!(model.required_branches.len() >= 2);
        assert!(model.required_branches.len() < 64);
        assert_eq!(
            model.required_branches.iter().collect::<HashSet<_>>().len(),
            model.required_branches.len(),
            "named branches must be unique"
        );
        assert!(!model.production_bindings.is_empty());
        assert!(!model.divergence_mutants.is_empty());
        for mutant in &model.divergence_mutants {
            assert!(
                mutants.insert(mutant.as_str()),
                "duplicate divergence mutant"
            );
        }
        for binding in &model.production_bindings {
            assert!(!binding.crate_name.is_empty());
            let source = fs::read_to_string(repository.join(&binding.source))
                .expect("bound production source must exist and be UTF-8");
            assert!(!binding.symbols.is_empty());
            for symbol in &binding.symbols {
                assert!(
                    source.contains(symbol),
                    "{} no longer contains bound symbol {symbol:?}",
                    binding.source
                );
            }
        }
    }
    assert_eq!(mutants.len(), 7);
}

#[test]
fn refinement_oracles_reject_one_divergence_per_model() {
    assert!(!cache_observation_valid(Some(b"partial-cache-entry")));
    assert!(!snapshot_observation_valid(
        Some(StoreRevision(1)),
        Some(1),
        Some(b"partial-snapshot"),
    ));
    assert!(!exclusive_winner_valid(2));
    assert!(!exclusive_winner_valid(0));
    assert!(!cursor_transition_valid(EventCursor(7), EventCursor(3)));
    assert!(!invalidation_observation_valid(true, Some(42)));
    assert!(!shutdown_observation_valid(true, true));
}
