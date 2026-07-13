//! WP13 acceptance coverage for exact, hermetic, and separately authorized replay modes.

use cigar_canon::{
    SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1, to_normalized_json,
};
use cigar_protocol::{
    BlobRef, CandidateDisposition, Capability, ContentDigest, ContextBlock, ContextBundle,
    ContextPlan, DecisionOutcome, DecisionRecord, DependencyKind, EffectIntent, ExtensionMap,
    FixedPoint, IdempotencyKey, LaneKind, ManifestEntry, MaterializedContext, MediaType, PlanLane,
    RecordId, ReplayMode, ReplayRequest, ReplayStatus, RepresentationKind, RetryPolicy, RiskLevel,
    SchemaVersion, SelectionManifest, UsageRecord, UtcTimestamp, VersionId,
};
use cigar_replay::{
    DecisionArchive, DecisionArtifact, DecisionCapture, DecisionCaptureBuilder, DecisionDependency,
    DependencyCapture, DependencyRole, InvocationCapture, InvocationEnvelope,
    LiveAuthorizationVerifier, LiveEffectDispatch, LiveEffectGate, LiveReplayAuthorization,
    LiveReplayInvocation, LiveReplayOutput, LiveReplayProvider, MAX_DECISION_ARTIFACT_BYTES,
    MissingDependencyReason, ObservationCapture, ObservationKind, RecordedObservation,
    ReplayArchive, ReplayContext, ReplayDimensionDigests, ReplayEngine, ReplayError,
    ReplayErrorCode, ReplayExternalCallCounters, ReplayFoundationError, ReplayFoundationErrorCode,
    component_dimension_digest, framed_observation_digest,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const EXACT_INVOCATION: &[u8] = b"exact retained invocation";
const RECORDED_RESPONSES: [&[u8]; 3] = [
    b"recorded consumer response",
    b"recorded tool response",
    b"recorded connector response",
];

struct Fixture {
    capture: DecisionCapture,
    old_effect_id: RecordId,
}

impl Fixture {
    fn decision_id(&self) -> VersionId {
        self.capture.archive.decision.decision_id.clone()
    }
}

#[derive(Clone)]
struct TestArchive {
    decision: DecisionArchive,
    artifacts: BTreeMap<ContentDigest, DecisionArtifact>,
}

impl TestArchive {
    fn complete(capture: &DecisionCapture) -> Self {
        Self {
            decision: capture.archive.clone(),
            artifacts: capture
                .artifacts
                .iter()
                .map(|artifact| (artifact.content_digest.clone(), artifact.clone()))
                .collect(),
        }
    }

    fn without_role(
        capture: &DecisionCapture,
        role: DependencyRole,
    ) -> TestResult<(Self, ContentDigest)> {
        let mut archive = Self::complete(capture);
        let digest = capture
            .archive
            .manifest
            .dependencies
            .iter()
            .find(|dependency| dependency.role == role)
            .map(|dependency| dependency.content_digest.clone())
            .ok_or_else(|| io::Error::other("fixture dependency role is absent"))?;
        if archive.artifacts.remove(&digest).is_none() {
            return Err(io::Error::other("fixture artifact is absent").into());
        }
        Ok((archive, digest))
    }

    fn replace(&mut self, lookup_digest: ContentDigest, artifact: DecisionArtifact) {
        self.artifacts.insert(lookup_digest, artifact);
    }
}

impl ReplayArchive for TestArchive {
    fn put_capture(&self, _capture: &DecisionCapture) -> Result<(), ReplayFoundationError> {
        Err(ReplayFoundationError::new(
            ReplayFoundationErrorCode::InvalidInput,
        ))
    }

    fn get_decision(
        &self,
        decision_id: &VersionId,
    ) -> Result<Option<DecisionArchive>, ReplayFoundationError> {
        Ok((decision_id == &self.decision.decision.decision_id).then(|| self.decision.clone()))
    }

    fn get_artifact(
        &self,
        content_digest: &ContentDigest,
    ) -> Result<Option<DecisionArtifact>, ReplayFoundationError> {
        Ok(self.artifacts.get(content_digest).cloned())
    }
}

#[derive(Default)]
struct PanicLiveBoundaries {
    verifier_calls: AtomicU64,
    provider_calls: AtomicU64,
    effect_calls: AtomicU64,
}

impl LiveAuthorizationVerifier for PanicLiveBoundaries {
    #[allow(clippy::panic)]
    fn verify_current(
        &self,
        _authorization: &LiveReplayAuthorization,
    ) -> Result<UtcTimestamp, ReplayError> {
        self.verifier_calls.fetch_add(1, Ordering::SeqCst);
        panic!("non-live replay crossed the live authorization boundary")
    }
}

impl LiveReplayProvider for PanicLiveBoundaries {
    #[allow(clippy::panic)]
    fn execute(&self, _invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError> {
        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        panic!("non-live replay crossed the live consumer/tool/connector boundary")
    }
}

impl LiveEffectGate for PanicLiveBoundaries {
    #[allow(clippy::panic)]
    fn authorize_and_dispatch(&self, _dispatch: &LiveEffectDispatch) -> Result<(), ReplayError> {
        self.effect_calls.fetch_add(1, Ordering::SeqCst);
        panic!("non-live replay crossed the effect-dispatch boundary")
    }
}

struct CurrentVerifier {
    expected_policy: ContentDigest,
    trusted_now: UtcTimestamp,
    calls: AtomicU64,
    accept: bool,
}

impl CurrentVerifier {
    fn accepting(expected_policy: ContentDigest, trusted_now: UtcTimestamp) -> Self {
        Self {
            expected_policy,
            trusted_now,
            calls: AtomicU64::new(0),
            accept: true,
        }
    }

    fn rejecting(expected_policy: ContentDigest, trusted_now: UtcTimestamp) -> Self {
        Self {
            expected_policy,
            trusted_now,
            calls: AtomicU64::new(0),
            accept: false,
        }
    }
}

impl LiveAuthorizationVerifier for CurrentVerifier {
    fn verify_current(
        &self,
        authorization: &LiveReplayAuthorization,
    ) -> Result<UtcTimestamp, ReplayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.accept && authorization.policy_snapshot_digest == self.expected_policy {
            Ok(self.trusted_now)
        } else {
            Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenInvocation {
    execution_id: RecordId,
    request_id: RecordId,
    source_decision_id: VersionId,
    input_digest: ContentDigest,
    exact_input: Vec<u8>,
    exact_parameters: Vec<u8>,
    exact_materialization: Vec<u8>,
    components: Vec<(DependencyRole, Vec<u8>)>,
}

struct RecordingProvider {
    calls: AtomicU64,
    effect_intents: Vec<RecordId>,
    observations: Vec<Vec<u8>>,
    invocations: Mutex<Vec<SeenInvocation>>,
}

impl RecordingProvider {
    fn new(effect_intents: Vec<RecordId>, observations: Vec<Vec<u8>>) -> Self {
        Self {
            calls: AtomicU64::new(0),
            effect_intents,
            observations,
            invocations: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> TestResult<Vec<SeenInvocation>> {
        self.invocations
            .lock()
            .map(|values| values.clone())
            .map_err(|_error| {
                io::Error::other("live provider observation lock was poisoned").into()
            })
    }
}

impl LiveReplayProvider for RecordingProvider {
    fn execute(&self, invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let seen = SeenInvocation {
            execution_id: invocation.execution_id.clone(),
            request_id: invocation.request_id.clone(),
            source_decision_id: invocation.source_decision_id.clone(),
            input_digest: invocation.input_digest.clone(),
            exact_input: invocation.exact_input().to_vec(),
            exact_parameters: invocation.exact_parameters().to_vec(),
            exact_materialization: invocation.reconstructed().exact_materialization().to_vec(),
            components: invocation
                .reconstructed()
                .components()
                .iter()
                .map(|component| (component.role, component.exact_bytes().to_vec()))
                .collect(),
        };
        self.invocations
            .lock()
            .map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))?
            .push(seen);
        LiveReplayOutput::new(
            ReplayDimensionDigests::default(),
            self.effect_intents.clone(),
            self.observations.clone(),
        )
    }
}

#[derive(Default)]
struct RecordingEffectGate {
    calls: AtomicU64,
    dispatches: Mutex<Vec<LiveEffectDispatch>>,
}

impl RecordingEffectGate {
    fn seen(&self) -> TestResult<Vec<LiveEffectDispatch>> {
        self.dispatches
            .lock()
            .map(|values| values.clone())
            .map_err(|_error| io::Error::other("effect-gate observation lock was poisoned").into())
    }
}

impl LiveEffectGate for RecordingEffectGate {
    fn authorize_and_dispatch(&self, dispatch: &LiveEffectDispatch) -> Result<(), ReplayError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.dispatches
            .lock()
            .map_err(|_error| ReplayError::new(ReplayErrorCode::Unavailable))?
            .push(dispatch.clone());
        Ok(())
    }
}

struct BlockingProvider {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    effect_intents: Vec<RecordId>,
}

impl LiveReplayProvider for BlockingProvider {
    fn execute(&self, _invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError> {
        self.entered.wait();
        self.release.wait();
        LiveReplayOutput::new(
            ReplayDimensionDigests::default(),
            self.effect_intents.clone(),
            vec![b"late provider output".to_vec()],
        )
    }
}

#[test]
fn cancellation_while_live_provider_is_blocked_quarantines_output_before_effect_dispatch()
-> TestResult {
    let fixture = fixture()?;
    let policy = raw_digest(b"cancellation policy")?;
    let fresh_effect = record(9_500)?;
    let request = live_request(
        fixture.decision_id(),
        9_501,
        false,
        vec![fresh_effect.clone()],
    )?;
    let authorization = authorization(&request, 9_501, policy.clone())?;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let provider = Arc::new(BlockingProvider {
        entered: entered.clone(),
        release: release.clone(),
        effect_intents: vec![fresh_effect],
    });
    let gate = Arc::new(RecordingEffectGate::default());
    let engine = Arc::new(ReplayEngine::with_live_services(
        Arc::new(TestArchive::complete(&fixture.capture)),
        Arc::new(CurrentVerifier::accepting(policy, time(12)?)),
        provider,
        gate.clone(),
    ));
    let cancelled = Arc::new(AtomicBool::new(false));
    let context = ReplayContext::new(
        Arc::new({
            let cancelled = cancelled.clone();
            move || cancelled.load(Ordering::Acquire)
        }),
        None,
    );
    let execution_id = record(9_502)?;
    let started_at = time(12)?;
    let completed_at = time(13)?;
    let worker = std::thread::spawn(move || {
        engine.replay_live_with_context(
            &request,
            &authorization,
            execution_id,
            started_at,
            completed_at,
            &context,
        )
    });
    entered.wait();
    cancelled.store(true, Ordering::Release);
    release.wait();
    let result = worker
        .join()
        .map_err(|_panic| io::Error::other("live replay worker panicked"))?;
    assert_eq!(
        result.err().map(ReplayError::code),
        Some(ReplayErrorCode::LiveProviderFailure)
    );
    assert_eq!(gate.calls.load(Ordering::SeqCst), 0);
    assert!(gate.seen()?.is_empty());
    Ok(())
}

#[test]
fn exact_non_live_modes_use_only_retained_bytes_and_recorded_boundaries() -> TestResult {
    let fixture = fixture()?;
    let archive = Arc::new(TestArchive::complete(&fixture.capture));
    let immutable_source = archive.decision.clone();
    let panic_boundaries = Arc::new(PanicLiveBoundaries::default());
    let engine = ReplayEngine::with_live_services(
        Arc::clone(&archive),
        panic_boundaries.clone(),
        panic_boundaries.clone(),
        panic_boundaries.clone(),
    );

    let evidence = engine.replay_non_live(
        &non_live_request(fixture.decision_id(), ReplayMode::EvidenceReproduction, 10)?,
        record(110)?,
        time(10)?,
        time(11)?,
    )?;
    assert_eq!(evidence.execution.status, ReplayStatus::Complete);
    assert!(evidence.execution.reconstructed_input_digest.is_none());
    assert!(evidence.execution.observation_digest.is_none());
    assert!(evidence.reconstructed_invocation().is_none());
    assert!(evidence.observations().is_empty());
    assert!(evidence.missing_dependencies.is_empty());

    let invocation = engine.replay_non_live(
        &non_live_request(
            fixture.decision_id(),
            ReplayMode::InvocationReproduction,
            11,
        )?,
        record(111)?,
        time(12)?,
        time(13)?,
    )?;
    assert_eq!(invocation.execution.status, ReplayStatus::Complete);
    assert_eq!(
        invocation.reconstructed_invocation(),
        Some(EXACT_INVOCATION)
    );
    assert_eq!(
        invocation.execution.reconstructed_input_digest,
        Some(raw_digest(EXACT_INVOCATION)?)
    );
    let reconstructed = invocation
        .invocation()
        .ok_or_else(|| io::Error::other("complete invocation reconstruction was absent"))?;
    assert_eq!(
        reconstructed.envelope,
        fixture.capture.archive.manifest.invocation
    );
    assert_eq!(reconstructed.exact_parameters(), b"{}");
    assert_eq!(
        reconstructed.exact_materialization(),
        b"provider-ready replay context"
    );
    for (role, expected_bytes) in [
        (
            DependencyRole::Runtime,
            b"runtime implementation".as_slice(),
        ),
        (
            DependencyRole::Consumer,
            b"consumer implementation".as_slice(),
        ),
        (
            DependencyRole::Adapter,
            b"adapter implementation".as_slice(),
        ),
        (
            DependencyRole::Tokenizer,
            b"tokenizer implementation".as_slice(),
        ),
        (
            DependencyRole::Materializer,
            b"materializer implementation".as_slice(),
        ),
        (
            DependencyRole::ToolSchema,
            b"tool schema implementation".as_slice(),
        ),
        (
            DependencyRole::Environment,
            b"environment implementation".as_slice(),
        ),
    ] {
        let component = reconstructed
            .components()
            .iter()
            .find(|component| component.role == role)
            .ok_or_else(|| io::Error::other("reconstructed component was absent"))?;
        assert_eq!(component.exact_bytes(), expected_bytes);
        assert_eq!(component.fingerprint, component.content_digest);
    }
    assert_eq!(reconstructed.components().len(), 7);
    let component_digest = component_dimension_digest(reconstructed.components())?;
    for (index, _component) in reconstructed.components().iter().enumerate() {
        let mut changed = reconstructed.components().to_vec();
        let candidate = changed
            .get_mut(index)
            .ok_or_else(|| io::Error::other("component test index was absent"))?;
        candidate.fingerprint = raw_digest(format!("changed component {index}").as_bytes())?;
        assert_ne!(component_dimension_digest(&changed)?, component_digest);
    }
    assert!(invocation.execution.observation_digest.is_none());
    assert!(invocation.observations().is_empty());

    let observational = engine.replay_non_live(
        &non_live_request(fixture.decision_id(), ReplayMode::Observational, 12)?,
        record(112)?,
        time(14)?,
        time(15)?,
    )?;
    let expected_observations = RECORDED_RESPONSES
        .iter()
        .map(|bytes| bytes.to_vec())
        .collect::<Vec<_>>();
    assert_eq!(observational.execution.status, ReplayStatus::Complete);
    assert_eq!(
        observational.reconstructed_invocation(),
        Some(EXACT_INVOCATION)
    );
    assert_eq!(observational.observations(), expected_observations);
    assert_eq!(
        observational.execution.observation_digest,
        Some(framed_observation_digest(&expected_observations)?)
    );
    assert!(!observational.execution.egress_permitted);
    assert!(!observational.execution.effect_dispatch_permitted);

    assert_eq!(panic_boundaries.verifier_calls.load(Ordering::SeqCst), 0);
    assert_eq!(panic_boundaries.provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(panic_boundaries.effect_calls.load(Ordering::SeqCst), 0);
    assert_eq!(engine.external_call_counters().live_authorization_checks, 0);
    assert_eq!(engine.external_call_counters().live_provider_calls, 0);
    assert_eq!(engine.external_call_counters().live_effect_dispatches, 0);
    assert_eq!(archive.decision, immutable_source);
    Ok(())
}

#[test]
fn missing_exact_source_and_consumer_are_detailed_and_never_substituted() -> TestResult {
    let fixture = fixture()?;
    let (without_source, source_digest) =
        TestArchive::without_role(&fixture.capture, DependencyRole::Source)?;
    let source_engine = ReplayEngine::new(Arc::new(without_source));
    let source_request =
        non_live_request(fixture.decision_id(), ReplayMode::EvidenceReproduction, 20)?;
    let inspection = source_engine.inspect_completeness(&source_request)?;
    assert_eq!(
        inspection.completeness.missing,
        vec![DependencyKind::Source]
    );
    assert_eq!(inspection.missing_dependencies.len(), 1);
    assert_eq!(
        source_engine.external_call_counters(),
        ReplayExternalCallCounters::default()
    );
    let source_result =
        source_engine.replay_non_live(&source_request, record(120)?, time(10)?, time(11)?)?;
    assert_eq!(source_result.execution.status, ReplayStatus::Incomplete);
    assert_eq!(
        source_result.execution.completeness.missing,
        vec![DependencyKind::Source]
    );
    assert_eq!(source_result.missing_dependencies.len(), 1);
    let source_row = source_result
        .missing_dependencies
        .first()
        .ok_or_else(|| io::Error::other("source missing row was absent"))?;
    assert_eq!(source_row.kind, DependencyKind::Source);
    assert_eq!(source_row.role, DependencyRole::Source);
    assert_eq!(source_row.content_digest, source_digest);
    assert_eq!(source_row.reason, MissingDependencyReason::Missing);
    assert!(source_result.reconstructed_invocation().is_none());

    for (role, kind, serial) in [
        (DependencyRole::Policy, DependencyKind::Policy, 122_u64),
        (DependencyRole::Index, DependencyKind::Index, 123_u64),
    ] {
        let (without_snapshot, expected_digest) =
            TestArchive::without_role(&fixture.capture, role)?;
        let snapshot_result = ReplayEngine::new(Arc::new(without_snapshot)).replay_non_live(
            &non_live_request(
                fixture.decision_id(),
                ReplayMode::EvidenceReproduction,
                serial,
            )?,
            record(serial.saturating_add(1_000))?,
            time(10)?,
            time(11)?,
        )?;
        assert_eq!(snapshot_result.execution.status, ReplayStatus::Incomplete);
        assert_eq!(snapshot_result.execution.completeness.missing, vec![kind]);
        let row = snapshot_result
            .missing_dependencies
            .first()
            .ok_or_else(|| io::Error::other("snapshot missing row was absent"))?;
        assert_eq!(row.role, role);
        assert_eq!(row.content_digest, expected_digest);
        assert_eq!(row.reason, MissingDependencyReason::Missing);
    }

    let (without_consumer, consumer_digest) =
        TestArchive::without_role(&fixture.capture, DependencyRole::Consumer)?;
    let consumer_engine = ReplayEngine::new(Arc::new(without_consumer));
    let consumer_result = consumer_engine.replay_non_live(
        &non_live_request(
            fixture.decision_id(),
            ReplayMode::InvocationReproduction,
            21,
        )?,
        record(121)?,
        time(12)?,
        time(13)?,
    )?;
    assert_eq!(consumer_result.execution.status, ReplayStatus::Incomplete);
    assert_eq!(
        consumer_result.execution.completeness.missing,
        vec![DependencyKind::Consumer]
    );
    assert_eq!(consumer_result.missing_dependencies.len(), 1);
    let consumer_row = consumer_result
        .missing_dependencies
        .first()
        .ok_or_else(|| io::Error::other("consumer missing row was absent"))?;
    assert_eq!(consumer_row.kind, DependencyKind::Consumer);
    assert_eq!(consumer_row.role, DependencyRole::Consumer);
    assert_eq!(consumer_row.content_digest, consumer_digest);
    assert_eq!(consumer_row.reason, MissingDependencyReason::Missing);
    assert!(consumer_result.reconstructed_invocation().is_none());
    Ok(())
}

#[test]
fn tampered_or_digest_substituted_invocation_is_integrity_failure() -> TestResult {
    let fixture = fixture()?;
    let invocation_digest = dependency_digest(&fixture.capture, DependencyRole::Invocation)?;
    let original = fixture
        .capture
        .artifacts
        .iter()
        .find(|artifact| artifact.content_digest == invocation_digest)
        .ok_or_else(|| io::Error::other("invocation artifact was absent"))?;

    let mut tampered_archive = TestArchive::complete(&fixture.capture);
    tampered_archive.replace(
        invocation_digest.clone(),
        alter_artifact(original, b"tampered invocation", false)?,
    );
    let tampered = ReplayEngine::new(Arc::new(tampered_archive)).replay_non_live(
        &non_live_request(
            fixture.decision_id(),
            ReplayMode::InvocationReproduction,
            30,
        )?,
        record(130)?,
        time(10)?,
        time(11)?,
    );
    let Err(tampered_error) = tampered else {
        return Err(io::Error::other("tampered invocation unexpectedly replayed").into());
    };
    assert_eq!(tampered_error.code(), ReplayErrorCode::ArchiveIntegrity);

    let mut substituted_archive = TestArchive::complete(&fixture.capture);
    substituted_archive.replace(
        invocation_digest,
        alter_artifact(original, b"new current invocation", true)?,
    );
    let substituted = ReplayEngine::new(Arc::new(substituted_archive)).replay_non_live(
        &non_live_request(
            fixture.decision_id(),
            ReplayMode::InvocationReproduction,
            31,
        )?,
        record(131)?,
        time(12)?,
        time(13)?,
    );
    let Err(substitution_error) = substituted else {
        return Err(io::Error::other("digest-substituted invocation unexpectedly replayed").into());
    };
    assert_eq!(substitution_error.code(), ReplayErrorCode::ArchiveIntegrity);
    Ok(())
}

#[test]
fn live_provider_runs_only_after_bound_current_authorization() -> TestResult {
    let fixture = fixture()?;
    let archive = Arc::new(TestArchive::complete(&fixture.capture));
    let policy = raw_digest(b"current live policy")?;
    let verifier = Arc::new(CurrentVerifier::rejecting(policy.clone(), time(10)?));
    let provider = Arc::new(RecordingProvider::new(Vec::new(), vec![b"live".to_vec()]));
    let gate = Arc::new(RecordingEffectGate::default());
    let engine =
        ReplayEngine::with_live_services(archive, verifier.clone(), provider.clone(), gate.clone());
    let request = live_request(fixture.decision_id(), 40, true, Vec::new())?;
    let mut wrong_principal = authorization(&request, 40, policy.clone())?;
    wrong_principal.requested_by = record(9_999)?;
    let wrong_result = engine.replay_live(
        &request,
        &wrong_principal,
        record(140)?,
        time(10)?,
        time(11)?,
    );
    let Err(wrong_error) = wrong_result else {
        return Err(io::Error::other("wrong-principal authorization was accepted").into());
    };
    assert_eq!(
        wrong_error.code(),
        ReplayErrorCode::LiveAuthorizationInvalid
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

    let current_rejected = engine.replay_live(
        &request,
        &authorization(&request, 41, policy.clone())?,
        record(141)?,
        time(12)?,
        time(13)?,
    );
    let Err(current_error) = current_rejected else {
        return Err(io::Error::other("current verifier denial was ignored").into());
    };
    assert_eq!(
        current_error.code(),
        ReplayErrorCode::LiveAuthorizationInvalid
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(gate.calls.load(Ordering::SeqCst), 0);

    let expired_verifier = Arc::new(CurrentVerifier::accepting(
        policy.clone(),
        UtcTimestamp::parse_rfc3339("2026-07-11T12:01:00Z")?,
    ));
    let expired_provider = Arc::new(RecordingProvider::new(Vec::new(), vec![b"live".to_vec()]));
    let expired_gate = Arc::new(RecordingEffectGate::default());
    let expired_engine = ReplayEngine::with_live_services(
        Arc::new(TestArchive::complete(&fixture.capture)),
        expired_verifier.clone(),
        expired_provider.clone(),
        expired_gate.clone(),
    );
    let expired_request = live_request(fixture.decision_id(), 42, true, Vec::new())?;
    let expired = expired_engine.replay_live(
        &expired_request,
        &authorization(&expired_request, 42, policy.clone())?,
        record(142)?,
        time(14)?,
        time(15)?,
    );
    let Err(expired_error) = expired else {
        return Err(
            io::Error::other("trusted time after authorization expiry was accepted").into(),
        );
    };
    assert_eq!(
        expired_error.code(),
        ReplayErrorCode::LiveAuthorizationInvalid
    );
    assert_eq!(expired_verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(expired_provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(expired_gate.calls.load(Ordering::SeqCst), 0);

    let early_verifier = Arc::new(CurrentVerifier::accepting(policy.clone(), time(10)?));
    let early_provider = Arc::new(RecordingProvider::new(Vec::new(), vec![b"live".to_vec()]));
    let early_gate = Arc::new(RecordingEffectGate::default());
    let early_engine = ReplayEngine::with_live_services(
        Arc::new(TestArchive::complete(&fixture.capture)),
        early_verifier.clone(),
        early_provider.clone(),
        early_gate.clone(),
    );
    let early_request = live_request(fixture.decision_id(), 43, true, Vec::new())?;
    let mut not_yet_valid = authorization(&early_request, 43, policy)?;
    not_yet_valid.not_before = time(20)?;
    let early = early_engine.replay_live(
        &early_request,
        &not_yet_valid,
        record(143)?,
        time(16)?,
        time(17)?,
    );
    let Err(early_error) = early else {
        return Err(
            io::Error::other("trusted time before authorization window was accepted").into(),
        );
    };
    assert_eq!(
        early_error.code(),
        ReplayErrorCode::LiveAuthorizationInvalid
    );
    assert_eq!(early_verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(early_provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(early_gate.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn oversized_live_observation_is_rejected_before_engine_execution() -> TestResult {
    let oversized = vec![0_u8; MAX_DECISION_ARTIFACT_BYTES.saturating_add(1)];
    let output = LiveReplayOutput::new(
        ReplayDimensionDigests::default(),
        Vec::new(),
        vec![oversized],
    );
    let Err(error) = output else {
        return Err(io::Error::other("oversized live observation was accepted").into());
    };
    assert_eq!(error.code(), ReplayErrorCode::LiveProviderFailure);
    Ok(())
}

#[test]
fn one_use_live_authorization_denies_concurrent_and_sequential_reuse() -> TestResult {
    let fixture = fixture()?;
    let archive = Arc::new(TestArchive::complete(&fixture.capture));
    let policy = raw_digest(b"concurrency policy")?;
    let verifier = Arc::new(CurrentVerifier::accepting(policy.clone(), time(10)?));
    let provider = Arc::new(RecordingProvider::new(Vec::new(), vec![b"live".to_vec()]));
    let gate = Arc::new(RecordingEffectGate::default());
    let engine = Arc::new(ReplayEngine::with_live_services(
        archive,
        verifier.clone(),
        provider.clone(),
        gate,
    ));
    let request = Arc::new(live_request(fixture.decision_id(), 50, true, Vec::new())?);
    let authorization = Arc::new(authorization(&request, 50, policy)?);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for execution_serial in [150_u64, 151] {
        let execution_id = record(execution_serial)?;
        let started_at = time(10)?;
        let completed_at = time(11)?;
        let worker_engine = Arc::clone(&engine);
        let worker_request = Arc::clone(&request);
        let worker_authorization = Arc::clone(&authorization);
        let worker_barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            worker_barrier.wait();
            worker_engine.replay_live(
                &worker_request,
                &worker_authorization,
                execution_id,
                started_at,
                completed_at,
            )
        }));
    }
    barrier.wait();

    let mut completed = 0_u64;
    let mut reused = 0_u64;
    for worker in workers {
        let outcome = worker
            .join()
            .map_err(|_panic| io::Error::other("live replay worker panicked"))?;
        match outcome {
            Ok(result) => {
                assert_eq!(result.execution.status, ReplayStatus::Complete);
                completed = completed.saturating_add(1);
            }
            Err(error) if error.code() == ReplayErrorCode::LiveAuthorizationReused => {
                reused = reused.saturating_add(1);
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "unexpected concurrent replay error: {:?}",
                    error.code()
                ))
                .into());
            }
        }
    }
    assert_eq!(completed, 1);
    assert_eq!(reused, 1);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

    let mut reused_digest = authorization.as_ref().clone();
    reused_digest.nonce = record(10_052)?;
    let sequential_reuse =
        engine.replay_live(&request, &reused_digest, record(152)?, time(12)?, time(13)?);
    let Err(reuse_error) = sequential_reuse else {
        return Err(io::Error::other("authorization was reusable after completion").into());
    };
    assert_eq!(reuse_error.code(), ReplayErrorCode::LiveAuthorizationReused);

    let second_request = live_request(fixture.decision_id(), 51, true, Vec::new())?;
    let mut reused_nonce =
        crate::authorization(&second_request, 51, raw_digest(b"concurrency policy")?)?;
    reused_nonce.nonce = authorization.nonce.clone();
    let nonce_reuse = engine.replay_live(
        &second_request,
        &reused_nonce,
        record(153)?,
        time(14)?,
        time(15)?,
    );
    let Err(nonce_error) = nonce_reuse else {
        return Err(io::Error::other("authorization nonce was reusable with a new digest").into());
    };
    assert_eq!(nonce_error.code(), ReplayErrorCode::LiveAuthorizationReused);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn live_effects_reject_old_ids_gate_fresh_ids_and_simulate_without_dispatch() -> TestResult {
    let fixture = fixture()?;
    let policy = raw_digest(b"effect policy")?;

    let old_verifier = Arc::new(CurrentVerifier::accepting(policy.clone(), time(10)?));
    let old_provider = Arc::new(RecordingProvider::new(
        vec![fixture.old_effect_id.clone()],
        vec![b"old effect live output".to_vec()],
    ));
    let old_gate = Arc::new(RecordingEffectGate::default());
    let old_engine = ReplayEngine::with_live_services(
        Arc::new(TestArchive::complete(&fixture.capture)),
        old_verifier.clone(),
        old_provider.clone(),
        old_gate.clone(),
    );
    let old_request = live_request(
        fixture.decision_id(),
        60,
        false,
        vec![fixture.old_effect_id.clone()],
    )?;
    let old_result = old_engine.replay_live(
        &old_request,
        &authorization(&old_request, 60, policy.clone())?,
        record(160)?,
        time(10)?,
        time(11)?,
    );
    let Err(old_error) = old_result else {
        return Err(io::Error::other("archived decision effect was redispatched").into());
    };
    assert_eq!(
        old_error.code(),
        ReplayErrorCode::EffectAuthorizationInvalid
    );
    assert_eq!(old_verifier.calls.load(Ordering::SeqCst), 0);
    assert_eq!(old_provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(old_gate.calls.load(Ordering::SeqCst), 0);

    let fresh_effect = record(70_001)?;
    let fresh_verifier = Arc::new(CurrentVerifier::accepting(policy.clone(), time(12)?));
    let fresh_provider = Arc::new(RecordingProvider::new(
        vec![fresh_effect.clone()],
        vec![b"fresh live observation".to_vec()],
    ));
    let fresh_gate = Arc::new(RecordingEffectGate::default());
    let fresh_archive = Arc::new(TestArchive::complete(&fixture.capture));
    let immutable_source = fresh_archive.decision.clone();
    let fresh_engine = ReplayEngine::with_live_services(
        Arc::clone(&fresh_archive),
        fresh_verifier.clone(),
        fresh_provider.clone(),
        fresh_gate.clone(),
    );
    let fresh_request = live_request(fixture.decision_id(), 61, false, vec![fresh_effect.clone()])?;
    let fresh_execution_id = record(161)?;
    let fresh_result = fresh_engine.replay_live(
        &fresh_request,
        &authorization(&fresh_request, 61, policy.clone())?,
        fresh_execution_id.clone(),
        time(12)?,
        time(13)?,
    )?;
    assert_eq!(fresh_result.execution.execution_id, fresh_execution_id);
    assert_eq!(fresh_result.execution.status, ReplayStatus::Complete);
    assert!(fresh_result.execution.egress_permitted);
    assert!(fresh_result.execution.effect_dispatch_permitted);
    assert_eq!(fresh_result.external_calls.live_authorization_checks, 1);
    assert_eq!(fresh_result.external_calls.live_provider_calls, 1);
    assert_eq!(fresh_result.external_calls.live_effect_dispatches, 1);
    let invocations = fresh_provider.seen()?;
    let invocation = invocations
        .first()
        .ok_or_else(|| io::Error::other("live invocation was not captured"))?;
    assert_eq!(invocation.execution_id, fresh_execution_id);
    assert_eq!(invocation.source_decision_id, fixture.decision_id());
    assert_eq!(invocation.exact_input, EXACT_INVOCATION);
    assert_eq!(invocation.exact_parameters, b"{}");
    assert_eq!(
        invocation.exact_materialization,
        b"provider-ready replay context"
    );
    assert_eq!(invocation.components.len(), 7);
    let dispatches = fresh_gate.seen()?;
    let dispatch = dispatches
        .first()
        .ok_or_else(|| io::Error::other("fresh effect dispatch was not captured"))?;
    assert_eq!(dispatch.execution_id, fresh_execution_id);
    assert_eq!(dispatch.source_decision_id, fixture.decision_id());
    assert_eq!(dispatch.effect_intents, vec![fresh_effect]);
    assert_eq!(fresh_archive.decision, immutable_source);

    let simulated_verifier = Arc::new(CurrentVerifier::accepting(policy.clone(), time(14)?));
    let simulated_provider = Arc::new(RecordingProvider::new(
        vec![fixture.old_effect_id.clone()],
        vec![b"simulated old effect observation".to_vec()],
    ));
    let simulated_gate = Arc::new(RecordingEffectGate::default());
    let simulated_engine = ReplayEngine::with_live_services(
        Arc::new(TestArchive::complete(&fixture.capture)),
        simulated_verifier,
        simulated_provider.clone(),
        simulated_gate.clone(),
    );
    let simulated_request = live_request(fixture.decision_id(), 62, true, Vec::new())?;
    let simulated = simulated_engine.replay_live(
        &simulated_request,
        &authorization(&simulated_request, 62, policy)?,
        record(162)?,
        time(14)?,
        time(15)?,
    )?;
    assert_eq!(simulated.execution.status, ReplayStatus::Complete);
    assert!(!simulated.execution.effect_dispatch_permitted);
    assert_eq!(simulated.external_calls.live_effect_dispatches, 0);
    assert_eq!(simulated_provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(simulated_gate.calls.load(Ordering::SeqCst), 0);
    assert!(simulated_gate.seen()?.is_empty());
    Ok(())
}

fn fixture() -> TestResult<Fixture> {
    let task_bytes = b"observable replay task".to_vec();
    let source_bytes = b"retained immutable source";
    let source_version = version(b"selected-source-v1")?;
    let contract_digest = raw_digest(b"replay contract")?;
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
            candidate_versions: vec![source_version.clone()],
        }],
        dispositions: vec![(source_version.clone(), selected.clone())],
        extensions: ExtensionMap::default(),
    };
    let placeholder = version(b"placeholder")?;
    let mut manifest = SelectionManifest {
        schema_version: SchemaVersion::new("cigar.selection-manifest", 1)?,
        manifest_id: placeholder.clone(),
        contract_digest: contract_digest.clone(),
        entries: vec![ManifestEntry {
            version_id: source_version.clone(),
            disposition: selected,
            reason_codes: Vec::new(),
            provenance_digest: raw_digest(b"selected source provenance")?,
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
            block_id: version(b"selected-context-block")?,
            lane: LaneKind::Evidence,
            representation: RepresentationKind::Exact,
            content_digest: raw_digest(source_bytes)?,
            token_count: 1,
            provenance: vec![source_version.clone()],
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
    let tool_schema = raw_digest(b"tool schema implementation")?;
    let environment = raw_digest(b"environment implementation")?;
    let materialized_bytes = b"provider-ready replay context".to_vec();
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
    let parameter_bytes = b"{}".to_vec();
    let old_effect_id = record(2_000)?;
    let old_effect_intent = effect_intent(old_effect_id.clone(), bundle.bundle_id.clone())?;
    let invocation = InvocationCapture::new(
        InvocationEnvelope {
            schema_version: SchemaVersion::new("cigar.invocation-envelope", 1)?,
            input_digest: raw_digest(EXACT_INVOCATION)?,
            materialization_digest: materialization_digest.clone(),
            runtime_fingerprint: runtime.clone(),
            consumer_fingerprint: consumer.clone(),
            adapter_fingerprint: adapter.clone(),
            parameters_digest: raw_digest(&parameter_bytes)?,
            tool_schema_digests: vec![tool_schema],
            environment_digests: vec![environment],
            effect_ids: vec![old_effect_id.clone()],
            usage,
        },
        EXACT_INVOCATION.to_vec(),
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
        consumer_fingerprint: consumer.clone(),
        output_artifacts: Vec::new(),
        asserted_claims: Vec::new(),
        evidence: Vec::new(),
        uncertainty: Vec::new(),
        verification_receipts: Vec::new(),
        effects: vec![old_effect_id.clone()],
        usage,
        started_at: time(1)?,
        completed_at: time(2)?,
        outcome: DecisionOutcome::Succeeded,
        extensions: ExtensionMap::default(),
    };

    let observation_kinds = [
        ObservationKind::Consumer,
        ObservationKind::Tool,
        ObservationKind::Connector,
    ];
    let provider_fingerprints = [
        consumer,
        raw_digest(b"tool provider implementation")?,
        raw_digest(b"connector provider implementation")?,
    ];
    let observations = observation_kinds
        .into_iter()
        .zip(provider_fingerprints)
        .zip(RECORDED_RESPONSES)
        .enumerate()
        .map(|(index, ((kind, fingerprint), response))| {
            let ordinal = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| io::Error::other("observation ordinal overflow"))?;
            Ok(ObservationCapture::new(
                RecordedObservation {
                    ordinal,
                    kind,
                    request_digest: raw_digest(format!("request-{ordinal}").as_bytes())?,
                    response_digest: raw_digest(response)?,
                    provider_fingerprint: fingerprint,
                    subject_id: None,
                },
                response.to_vec(),
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;

    let capture = DecisionCaptureBuilder::new(
        decision,
        task_bytes,
        plan,
        manifest,
        bundle,
        materialization,
        invocation,
    )
    .with_observations(observations)
    .with_dependency(component(
        DependencyRole::Consumer,
        DependencyKind::Consumer,
        b"consumer implementation",
    )?)
    .with_dependency(component(
        DependencyRole::Adapter,
        DependencyKind::Adapter,
        b"adapter implementation",
    )?)
    .with_dependency(component(
        DependencyRole::Tokenizer,
        DependencyKind::Tokenizer,
        b"tokenizer implementation",
    )?)
    .with_dependency(component(
        DependencyRole::Materializer,
        DependencyKind::Adapter,
        b"materializer implementation",
    )?)
    .with_dependency(component(
        DependencyRole::Runtime,
        DependencyKind::Environment,
        b"runtime implementation",
    )?)
    .with_dependency(component(
        DependencyRole::ToolSchema,
        DependencyKind::ToolSchema,
        b"tool schema implementation",
    )?)
    .with_dependency(component(
        DependencyRole::Environment,
        DependencyKind::Environment,
        b"environment implementation",
    )?)
    .with_dependency(source_dependency(source_version, source_bytes)?)
    .with_dependency(snapshot_dependency(
        DependencyRole::Policy,
        DependencyKind::Policy,
        b"retained decision policy snapshot",
        None,
    )?)
    .with_dependency(snapshot_dependency(
        DependencyRole::Index,
        DependencyKind::Index,
        b"retained decision index generation",
        Some(catalog_watermark),
    )?)
    .with_dependency(effect_dependency(&old_effect_intent)?)
    .seal()?;
    Ok(Fixture {
        capture,
        old_effect_id,
    })
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
            required_modes: modes(&[
                ReplayMode::InvocationReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]),
        },
        artifact,
    )?)
}

fn source_dependency(source_version: VersionId, bytes: &[u8]) -> TestResult<DependencyCapture> {
    let artifact =
        DecisionArtifact::new(MediaType::new("application/octet-stream")?, bytes.to_vec())?;
    Ok(DependencyCapture::new(
        DecisionDependency {
            kind: DependencyKind::Source,
            role: DependencyRole::Source,
            content_digest: artifact.content_digest.clone(),
            semantic_id: Some(source_version),
            record_id: None,
            fingerprint: None,
            required_modes: modes(&[
                ReplayMode::EvidenceReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]),
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
            required_modes: modes(&[
                ReplayMode::EvidenceReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]),
        },
        artifact,
    )?)
}

fn effect_dependency(intent: &EffectIntent) -> TestResult<DependencyCapture> {
    let artifact =
        DecisionArtifact::new(MediaType::new("application/json")?, canonical_json(intent)?)?;
    Ok(DependencyCapture::new(
        DecisionDependency {
            kind: DependencyKind::Blob,
            role: DependencyRole::Effect,
            content_digest: artifact.content_digest.clone(),
            semantic_id: None,
            record_id: Some(intent.effect_id.clone()),
            fingerprint: None,
            required_modes: modes(&[
                ReplayMode::EvidenceReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]),
        },
        artifact,
    )?)
}

fn effect_intent(effect_id: RecordId, bundle_id: VersionId) -> TestResult<EffectIntent> {
    Ok(EffectIntent {
        schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
        effect_id,
        connector: "recorded-test-connector".to_owned(),
        operation: "recorded-test-operation".to_owned(),
        arguments_digest: raw_digest(b"recorded effect arguments")?,
        encrypted_arguments: BlobRef {
            digest: raw_digest(b"encrypted effect argument blob")?,
            size_bytes: 32,
            media_type: MediaType::new("application/octet-stream")?,
        },
        target: "retained-test-target".to_owned(),
        preconditions: Vec::new(),
        result_schema_digest: raw_digest(b"recorded effect result schema")?,
        risk: RiskLevel::Low,
        source_decision_id: version(b"pre-archive source decision")?,
        bundle_id,
        required_capability: Capability::InvokeTool,
        idempotency_scope: "wp13-fixture".to_owned(),
        idempotency_key: IdempotencyKey::new("wp13-old-effect")?,
        retry_policy: RetryPolicy::Never,
        created_at: time(1)?,
        expires_at: time(50)?,
        compensation: None,
        extensions: ExtensionMap::default(),
    })
}

fn non_live_request(
    decision_id: VersionId,
    mode: ReplayMode,
    serial: u64,
) -> TestResult<ReplayRequest> {
    Ok(ReplayRequest {
        schema_version: SchemaVersion::new("cigar.replay-request", 1)?,
        request_id: record(serial)?,
        decision_id,
        mode,
        requested_by: record(900)?,
        live_authorization_digest: None,
        simulate_effects: true,
        authorized_effect_intents: Vec::new(),
    })
}

fn live_request(
    decision_id: VersionId,
    serial: u64,
    simulate_effects: bool,
    authorized_effect_intents: Vec<RecordId>,
) -> TestResult<ReplayRequest> {
    Ok(ReplayRequest {
        schema_version: SchemaVersion::new("cigar.replay-request", 1)?,
        request_id: record(serial)?,
        decision_id,
        mode: ReplayMode::LiveComparison,
        requested_by: record(901)?,
        live_authorization_digest: Some(raw_digest(format!("authorization-{serial}").as_bytes())?),
        simulate_effects,
        authorized_effect_intents,
    })
}

fn authorization(
    request: &ReplayRequest,
    serial: u64,
    policy_snapshot_digest: ContentDigest,
) -> TestResult<LiveReplayAuthorization> {
    Ok(LiveReplayAuthorization {
        schema_version: SchemaVersion::new("cigar.live-replay-authorization", 1)?,
        authorization_digest: request
            .live_authorization_digest
            .clone()
            .ok_or_else(|| io::Error::other("live request lacks authorization digest"))?,
        nonce: record(10_000 + serial)?,
        request_id: request.request_id.clone(),
        decision_id: request.decision_id.clone(),
        requested_by: request.requested_by.clone(),
        authorized_effect_intents: request.authorized_effect_intents.clone(),
        not_before: time(0)?,
        expires_at: time(59)?,
        policy_snapshot_digest,
    })
}

fn alter_artifact(
    original: &DecisionArtifact,
    replacement_bytes: &[u8],
    make_replacement_self_consistent: bool,
) -> TestResult<DecisionArtifact> {
    let mut encoded = serde_json::to_value(original)?;
    let object = encoded
        .as_object_mut()
        .ok_or_else(|| io::Error::other("artifact did not serialize as an object"))?;
    object.insert("bytes".to_owned(), serde_json::to_value(replacement_bytes)?);
    if make_replacement_self_consistent {
        object.insert(
            "content_digest".to_owned(),
            serde_json::to_value(raw_digest(replacement_bytes)?)?,
        );
    }
    Ok(serde_json::from_value(encoded)?)
}

fn dependency_digest(capture: &DecisionCapture, role: DependencyRole) -> TestResult<ContentDigest> {
    capture
        .archive
        .manifest
        .dependencies
        .iter()
        .find(|dependency| dependency.role == role)
        .map(|dependency| dependency.content_digest.clone())
        .ok_or_else(|| io::Error::other("dependency role was absent").into())
}

fn canonical_json<T: Serialize>(value: &T) -> TestResult<Vec<u8>> {
    let serialized = serde_json::to_vec(value)?;
    Ok(to_normalized_json(&parse_strict_json(&serialized)?)?)
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
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}
