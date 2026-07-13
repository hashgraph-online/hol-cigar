//! Process-boundary proof that non-live replay can run with operating-system egress denial.

use cigar_canon::{
    SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1, to_normalized_json,
};
use cigar_protocol::{
    ContentDigest, ContextBundle, ContextPlan, DecisionOutcome, DecisionRecord, DependencyKind,
    ExtensionMap, LaneKind, MaterializedContext, MediaType, PlanLane, RecordId, ReplayMode,
    ReplayRequest, ReplayStatus, SchemaVersion, SelectionManifest, UsageRecord, UtcTimestamp,
    VersionId,
};
use cigar_replay::{
    DecisionArtifact, DecisionCapture, DecisionCaptureBuilder, DecisionDependency,
    DependencyCapture, DependencyRole, InMemoryReplayArchive, InvocationCapture,
    InvocationEnvelope, LiveAuthorizationVerifier, LiveEffectDispatch, LiveEffectGate,
    LiveReplayAuthorization, LiveReplayInvocation, LiveReplayOutput, LiveReplayProvider,
    ObservationCapture, ObservationKind, RecordedObservation, ReplayArchive, ReplayEngine,
    ReplayError, ReplayErrorCode, ReplayExternalCallCounters,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fmt::Write as _;
#[cfg(target_os = "macos")]
use std::fs::{self, OpenOptions};
use std::io;
#[cfg(target_os = "macos")]
use std::io::Write as _;
#[cfg(target_os = "macos")]
use std::net::TcpListener;
use std::net::{SocketAddr, TcpStream};
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

const CHILD_PROTOCOL_ENV: &str = "CIGAR_REPLAY_NO_EGRESS_PROTOCOL";
const CHILD_COMMAND_ENV: &str = "CIGAR_REPLAY_NO_EGRESS_COMMAND";
const CHILD_ENDPOINT_ENV: &str = "CIGAR_REPLAY_NO_EGRESS_ENDPOINT";
const CHILD_PROTOCOL_V1: &str = "cigar.replay-no-egress.v1";
const CHILD_COMMAND_OBSERVATIONAL_REPLAY_V1: &str = "observational-replay.v1";
const CHILD_RESULT_SCHEMA: &str = "cigar.replay-no-egress-child-result.v1";
const EXACT_INVOCATION: &[u8] = b"exact no-egress invocation";
const RECORDED_CONNECTOR_RESPONSE: &[u8] = b"{\"connector\":\"recorded\",\"ok\":true}";
#[cfg(target_os = "macos")]
const TEST_NAME: &str = "os_level_no_egress_is_enforced";

/// A generated sandbox profile removed even when an assertion fails.
#[cfg(target_os = "macos")]
struct SandboxProfile {
    path: PathBuf,
}

#[cfg(target_os = "macos")]
impl SandboxProfile {
    fn deny_network() -> Result<Self, Box<dyn Error>> {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let path = env::temp_dir().join(format!(
            "cigar-replay-no-egress-{}-{}.sb",
            std::process::id(),
            since_epoch.as_nanos()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        file.write_all(b"(version 1)\n(allow default)\n(deny network*)\n")?;
        file.sync_all()?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "macos")]
impl Drop for SandboxProfile {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.path);
    }
}

#[test]
fn os_level_no_egress_is_enforced() -> Result<(), Box<dyn Error>> {
    match env::var(CHILD_COMMAND_ENV) {
        Ok(command) => run_child(&command),
        Err(env::VarError::NotPresent) => run_parent(),
        Err(env::VarError::NotUnicode(_value)) => {
            Err(io::Error::other("no-egress child command is not valid Unicode").into())
        }
    }
}

fn run_child(command: &str) -> Result<(), Box<dyn Error>> {
    let protocol = env::var(CHILD_PROTOCOL_ENV)?;
    if protocol != CHILD_PROTOCOL_V1 {
        return Err(io::Error::other("unsupported no-egress child protocol").into());
    }
    match command {
        CHILD_COMMAND_OBSERVATIONAL_REPLAY_V1 => child_observational_replay(),
        _ => Err(io::Error::other("unsupported no-egress child command").into()),
    }
}

fn child_observational_replay() -> Result<(), Box<dyn Error>> {
    let external_calls = run_recorded_connector_replay()?;
    let endpoint: SocketAddr = env::var(CHILD_ENDPOINT_ENV)?.parse()?;
    let raw_os_error = match TcpStream::connect_timeout(&endpoint, Duration::from_secs(1)) {
        Ok(_stream) => {
            return Err(io::Error::other(
                "sandboxed child unexpectedly reached the parent listener",
            )
            .into());
        }
        Err(error) => {
            let raw = error.raw_os_error().unwrap_or_default();
            if error.kind() != io::ErrorKind::PermissionDenied && raw != 1 {
                return Err(io::Error::other(format!(
                    "network probe was not denied with EPERM: kind={:?}, raw_os_error={raw}",
                    error.kind()
                ))
                .into());
            }
            raw
        }
    };
    println!(
        "{{\"schema\":\"{CHILD_RESULT_SCHEMA}\",\"replay_status\":\"complete\",\"network\":\"denied\",\"error_kind\":\"permission_denied\",\"raw_os_error\":{raw_os_error},\"live_authorization_checks\":{},\"live_provider_calls\":{},\"live_effect_dispatches\":{}}}",
        external_calls.live_authorization_checks,
        external_calls.live_provider_calls,
        external_calls.live_effect_dispatches,
    );
    Ok(())
}

struct ClosedLiveBoundaries;

impl LiveAuthorizationVerifier for ClosedLiveBoundaries {
    fn verify_current(
        &self,
        _authorization: &LiveReplayAuthorization,
    ) -> Result<UtcTimestamp, ReplayError> {
        Err(ReplayError::new(ReplayErrorCode::LiveAuthorizationInvalid))
    }
}

impl LiveReplayProvider for ClosedLiveBoundaries {
    fn execute(&self, invocation: &LiveReplayInvocation) -> Result<LiveReplayOutput, ReplayError> {
        assert!(
            invocation.exact_input().is_empty(),
            "observational replay crossed the live connector boundary"
        );
        Err(ReplayError::new(ReplayErrorCode::LiveProviderFailure))
    }
}

impl LiveEffectGate for ClosedLiveBoundaries {
    fn authorize_and_dispatch(&self, _dispatch: &LiveEffectDispatch) -> Result<(), ReplayError> {
        Err(ReplayError::new(
            ReplayErrorCode::EffectAuthorizationInvalid,
        ))
    }
}

fn run_recorded_connector_replay() -> Result<ReplayExternalCallCounters, Box<dyn Error>> {
    let capture = recorded_connector_capture()?;
    let decision_id = capture.archive.decision.decision_id.clone();
    let archive = Arc::new(InMemoryReplayArchive::default());
    archive.put_capture(&capture)?;

    let closed = Arc::new(ClosedLiveBoundaries);
    let verifier: Arc<dyn LiveAuthorizationVerifier> = closed.clone();
    let provider: Arc<dyn LiveReplayProvider> = closed.clone();
    let effect_gate: Arc<dyn LiveEffectGate> = closed;
    let engine = ReplayEngine::with_live_services(archive, verifier, provider, effect_gate);
    let request = ReplayRequest {
        schema_version: SchemaVersion::new("cigar.replay-request", 1)?,
        request_id: RecordId::new("01890f47-8e7d-7b42-a1d2-000000000101")?,
        decision_id,
        mode: ReplayMode::Observational,
        requested_by: RecordId::new("01890f47-8e7d-7b42-a1d2-000000000102")?,
        live_authorization_digest: None,
        simulate_effects: true,
        authorized_effect_intents: Vec::new(),
    };
    let result = engine.replay_non_live(
        &request,
        RecordId::new("01890f47-8e7d-7b42-a1d2-000000000103")?,
        UtcTimestamp::parse_rfc3339("2026-07-11T12:01:00Z")?,
        UtcTimestamp::parse_rfc3339("2026-07-11T12:01:01Z")?,
    )?;

    assert_eq!(result.execution.status, ReplayStatus::Complete);
    assert!(!result.execution.egress_permitted);
    assert!(!result.execution.effect_dispatch_permitted);
    assert!(result.execution.completeness.missing.is_empty());
    assert_eq!(result.reconstructed_invocation(), Some(EXACT_INVOCATION));
    assert_eq!(
        result.observations().first().map(Vec::as_slice),
        Some(RECORDED_CONNECTOR_RESPONSE)
    );
    assert_eq!(result.observations().len(), 1);
    assert_eq!(result.external_calls, ReplayExternalCallCounters::default());
    assert_eq!(
        engine.external_call_counters(),
        ReplayExternalCallCounters::default()
    );
    Ok(result.external_calls)
}

fn recorded_connector_capture() -> Result<DecisionCapture, Box<dyn Error>> {
    let task_bytes = b"prove replay under denied egress".to_vec();
    let contract_digest = raw_content_digest(b"no-egress contract")?;
    let plan = ContextPlan {
        schema_version: SchemaVersion::new("cigar.context-plan", 1)?,
        plan_id: RecordId::new("01890f47-8e7d-7b42-a1d2-000000000104")?,
        contract_digest: contract_digest.clone(),
        catalog_watermark: raw_content_digest(b"fixed catalog watermark")?,
        total_input_tokens: 1,
        lanes: vec![PlanLane {
            kind: LaneKind::Evidence,
            budget_tokens: 1,
            candidate_versions: Vec::new(),
        }],
        dispositions: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    let catalog_watermark = plan.catalog_watermark.clone();
    let placeholder = VersionId::new(format!("1220{}", "0".repeat(64)))?;
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

    let runtime = raw_content_digest(b"no-egress runtime")?;
    let consumer = raw_content_digest(b"no-egress consumer")?;
    let adapter = raw_content_digest(b"no-egress adapter")?;
    let tokenizer = raw_content_digest(b"no-egress tokenizer")?;
    let materializer = raw_content_digest(b"no-egress materializer")?;
    let materialized_bytes = b"provider-ready no-egress context".to_vec();
    let materialization_digest = raw_content_digest(&materialized_bytes)?;
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
    let invocation = InvocationCapture::new(
        InvocationEnvelope {
            schema_version: SchemaVersion::new("cigar.invocation-envelope", 1)?,
            input_digest: raw_content_digest(EXACT_INVOCATION)?,
            materialization_digest: materialization_digest.clone(),
            runtime_fingerprint: runtime.clone(),
            consumer_fingerprint: consumer.clone(),
            adapter_fingerprint: adapter.clone(),
            parameters_digest: raw_content_digest(&parameter_bytes)?,
            tool_schema_digests: Vec::new(),
            environment_digests: Vec::new(),
            effect_ids: Vec::new(),
            usage,
        },
        EXACT_INVOCATION.to_vec(),
        parameter_bytes,
    )?;
    let response_digest = raw_content_digest(RECORDED_CONNECTOR_RESPONSE)?;
    let observation = ObservationCapture::new(
        RecordedObservation {
            ordinal: 1,
            kind: ObservationKind::Connector,
            request_digest: raw_content_digest(b"GET recorded://fixture")?,
            response_digest,
            provider_fingerprint: raw_content_digest(b"recorded connector implementation")?,
            subject_id: None,
        },
        RECORDED_CONNECTOR_RESPONSE.to_vec(),
    );
    let decision = DecisionRecord {
        schema_version: SchemaVersion::new("cigar.decision-record", 1)?,
        decision_id: placeholder,
        task_digest: raw_content_digest(&task_bytes)?,
        plan_id: plan.plan_id.clone(),
        plan_digest: raw_content_digest(&canonical_record_bytes(&plan)?)?,
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
        started_at: UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")?,
        completed_at: UtcTimestamp::parse_rfc3339("2026-07-11T12:00:01Z")?,
        outcome: DecisionOutcome::Succeeded,
        extensions: ExtensionMap::default(),
    };

    let builder = DecisionCaptureBuilder::new(
        decision,
        task_bytes,
        plan,
        manifest,
        bundle,
        materialization,
        invocation,
    )
    .with_observations(vec![observation])
    .with_dependency(component(
        DependencyRole::Runtime,
        DependencyKind::Environment,
        b"no-egress runtime",
    )?)
    .with_dependency(component(
        DependencyRole::Consumer,
        DependencyKind::Consumer,
        b"no-egress consumer",
    )?)
    .with_dependency(component(
        DependencyRole::Adapter,
        DependencyKind::Adapter,
        b"no-egress adapter",
    )?)
    .with_dependency(component(
        DependencyRole::Tokenizer,
        DependencyKind::Tokenizer,
        b"no-egress tokenizer",
    )?)
    .with_dependency(component(
        DependencyRole::Materializer,
        DependencyKind::Adapter,
        b"no-egress materializer",
    )?)
    .with_dependency(snapshot_dependency(
        DependencyRole::Policy,
        DependencyKind::Policy,
        b"no-egress policy snapshot",
        None,
    )?)
    .with_dependency(snapshot_dependency(
        DependencyRole::Index,
        DependencyKind::Index,
        b"no-egress index generation",
        Some(catalog_watermark),
    )?);
    Ok(builder.seal()?)
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
            required_modes: all_replay_modes(),
        },
        artifact,
    )?)
}

fn snapshot_dependency(
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
            required_modes: [
                ReplayMode::EvidenceReproduction,
                ReplayMode::Observational,
                ReplayMode::LiveComparison,
            ]
            .into_iter()
            .collect(),
        },
        artifact,
    )?)
}

fn all_replay_modes() -> BTreeSet<ReplayMode> {
    [
        ReplayMode::EvidenceReproduction,
        ReplayMode::InvocationReproduction,
        ReplayMode::Observational,
        ReplayMode::LiveComparison,
    ]
    .into_iter()
    .collect()
}

fn canonical_record_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let json = serde_json::to_vec(value)?;
    let canonical = parse_strict_json(&json)?;
    Ok(to_normalized_json(&canonical)?)
}

fn raw_content_digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(ContentDigest::new(encoded)?)
}

#[cfg(target_os = "macos")]
fn run_parent() -> Result<(), Box<dyn Error>> {
    let sandbox = Path::new("/usr/bin/sandbox-exec");
    if !sandbox.is_file() {
        return Err(
            io::Error::other("macOS no-egress proof requires /usr/bin/sandbox-exec").into(),
        );
    }

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let profile = SandboxProfile::deny_network()?;
    let test_binary = env::current_exe()?;

    let output = Command::new(sandbox)
        .arg("-f")
        .arg(profile.path())
        .arg(test_binary)
        .arg("--exact")
        .arg(TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_PROTOCOL_ENV, CHILD_PROTOCOL_V1)
        .env(CHILD_COMMAND_ENV, CHILD_COMMAND_OBSERVATIONAL_REPLAY_V1)
        .env(CHILD_ENDPOINT_ENV, endpoint.to_string())
        .output()?;

    verify_child_output(&output)?;
    assert_no_connection_was_accepted(&listener)
}

#[cfg(not(target_os = "macos"))]
fn run_parent() -> Result<(), Box<dyn Error>> {
    Err(io::Error::other(format!(
        "WP13 OS no-egress proof is not implemented for host `{}`; refusing to skip",
        env::consts::OS
    ))
    .into())
}

#[cfg(target_os = "macos")]
fn verify_child_output(output: &Output) -> Result<(), Box<dyn Error>> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "sandboxed no-egress child failed: status={}; stdout={stdout:?}; stderr={stderr:?}",
            output.status
        ))
        .into());
    }
    if !stdout.contains(&format!("\"schema\":\"{CHILD_RESULT_SCHEMA}\""))
        || !stdout.contains("\"network\":\"denied\"")
        || !stdout.contains("\"error_kind\":\"permission_denied\"")
        || !stdout.contains("\"replay_status\":\"complete\"")
        || !stdout.contains("\"live_authorization_checks\":0")
        || !stdout.contains("\"live_provider_calls\":0")
        || !stdout.contains("\"live_effect_dispatches\":0")
    {
        return Err(io::Error::other(format!(
            "sandboxed child omitted its structured denial result: stdout={stdout:?}"
        ))
        .into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn assert_no_connection_was_accepted(listener: &TcpListener) -> Result<(), Box<dyn Error>> {
    match listener.accept() {
        Ok((_stream, peer)) => Err(io::Error::other(format!(
            "parent listener accepted a sandboxed connection from {peer}"
        ))
        .into()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
    }
}
