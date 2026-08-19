//! Content-safe raw observation records backed only by production facts.

use crate::ConsumerError;
use crate::assignment::{Assignment, ConsumerMode, SourceIdentity, Treatment, multihash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_canon::{parse_strict_json, to_normalized_json};
use cigar_protocol::{
    CandidateDisposition, ContentDigest, ContextBundle, ContextPlan, LaneKind, RepresentationKind,
    SelectionManifest,
};
use serde::Serialize;

/// One selected production bundle block.
#[derive(Clone, Debug, Serialize)]
pub struct SelectedBlock {
    /// Content-derived block identity.
    pub block_id: String,
    /// Destination lane.
    pub lane: String,
    /// Exact representation family.
    pub representation: String,
    /// Catalog semantic versions proving the block.
    pub provenance_ids: Vec<String>,
    /// Exact physical block tokens.
    pub tokens: u32,
    /// One-based final packing rank.
    pub rank: usize,
}

/// One disclosure-filtered candidate outcome.
#[derive(Clone, Debug, Serialize)]
pub struct Disposition {
    /// Authorized candidate semantic version.
    pub candidate_id: String,
    /// Stable final state and primary reason.
    pub reason: String,
}

/// One typed production call with exact request and response hashes.
#[derive(Clone, Debug, Serialize)]
pub struct ToolObservation {
    /// Frozen operation identifier.
    pub tool: String,
    /// Canonical typed request digest.
    pub request_digest: ContentDigest,
    /// Canonical typed response digest.
    pub response_digest: ContentDigest,
    /// Zero for a successfully decoded typed operation.
    pub exit_code: i32,
}

/// One measured production phase.
#[derive(Clone, Debug, Serialize)]
pub struct PhaseTiming {
    /// Stable phase identifier.
    pub phase: String,
    /// Wall duration in integer milliseconds, or zero in recorded mode.
    pub duration_ms: u64,
}

/// One retained, content-safe reproduction record.
#[derive(Clone, Debug, Serialize)]
pub struct Artifact {
    /// Closed artifact kind.
    pub kind: String,
    /// Digest of exact retained bytes.
    pub digest: ContentDigest,
    /// Exact retained byte count.
    pub bytes: usize,
    /// Exact retained bytes as unpadded base64url.
    pub retained_base64url: String,
}

impl Artifact {
    /// Retains canonical JSON for a content-safe semantic record.
    pub fn canonical<T: Serialize>(kind: &str, value: &T) -> Result<Self, ConsumerError> {
        let bytes = canonical_json(value)?;
        Self::exact(kind, bytes)
    }

    /// Retains already-canonical, content-safe bytes.
    pub fn exact(kind: &str, bytes: Vec<u8>) -> Result<Self, ConsumerError> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            return Err(ConsumerError::new("artifact_limit"));
        }
        Ok(Self {
            kind: kind.to_owned(),
            digest: multihash(&bytes)?,
            bytes: bytes.len(),
            retained_base64url: URL_SAFE_NO_PAD.encode(bytes),
        })
    }
}

/// Complete immutable semantic/configuration pins for one observation.
#[derive(Clone, Debug, Serialize)]
pub struct Pins {
    /// Ingestion publication digest.
    pub catalog: ContentDigest,
    /// Canonical catalog graph digest.
    pub graph: ContentDigest,
    /// Active retrieval-index fingerprint.
    pub index: ContentDigest,
    /// Installed policy snapshot digest.
    pub policy: ContentDigest,
    /// Exact default query-planner configuration digest.
    pub planner: ContentDigest,
    /// Exact compiler profile digest.
    pub compiler: ContentDigest,
    /// Exact tokenizer fingerprint.
    pub tokenizer: ContentDigest,
    /// Exact materializer fingerprint.
    pub materializer: ContentDigest,
    /// Exact benchmark consumer executable digest.
    pub consumer: ContentDigest,
    /// Pinned external or recorded consumer identity.
    pub model: String,
    /// Pinned prompt digest.
    pub prompt: ContentDigest,
}

/// Resource facts available without trusting a model.
#[derive(Clone, Debug, Serialize)]
pub struct Resources {
    /// Exact provider-ready input tokens.
    pub physical_input_tokens: u32,
    /// Cache reads reported by the consumer adapter.
    pub cache_read_tokens: u64,
    /// Cache writes reported by the consumer adapter.
    pub cache_write_tokens: u64,
    /// Output tokens reported by the consumer adapter.
    pub output_tokens: u64,
    /// End-to-end integer wall latency.
    pub latency_ms: u64,
    /// Process CPU time when measured.
    pub cpu_ms: u64,
    /// Whether CPU time was measured by this consumer.
    pub cpu_measured: bool,
    /// Peak resident set size when measured.
    pub peak_rss_bytes: u64,
    /// Whether peak RSS was measured by this consumer.
    pub peak_rss_measured: bool,
    /// Provider cost in USD; zero for the production-only deterministic consumer.
    pub cost_usd: u64,
}

/// Optional governed-flow facts.
#[derive(Clone, Debug, Serialize)]
pub struct EffectReplay {
    /// Handoff preview operations completed.
    pub handoffs: u64,
    /// Logical effects modeled through restart recovery.
    pub effects: u64,
    /// Unsafe blind redispatches observed.
    pub unsafe_retries: u64,
    /// Structured replay comparisons completed.
    pub replay_dispatches: u64,
}

/// Observation without its derived identity.
#[derive(Clone, Debug, Serialize)]
pub struct ObservationBody {
    /// Must be `cigar.benchmark-observation.v2`.
    pub schema_version: String,
    /// Parent refinement run.
    pub run_id: String,
    /// Paired comparison identity.
    pub pair_id: String,
    /// Benchmark task.
    pub task_id: String,
    /// Honey, champion, candidate, or explicit baseline.
    pub treatment: Treatment,
    /// Production or deterministic recorded mode.
    pub consumer_mode: ConsumerMode,
    /// Exact candidate source.
    pub source: SourceIdentity,
    /// Digest of exact assignment bytes.
    pub assignment_digest: ContentDigest,
    /// Digest of exact fixture archive bytes.
    pub archive_digest: ContentDigest,
    /// Immutable semantic/configuration pins.
    pub pins: Pins,
    /// Ordered packed blocks.
    pub selected_blocks: Vec<SelectedBlock>,
    /// Complete authorized candidate disposition table.
    pub dispositions: Vec<Disposition>,
    /// Exact consumer input digest.
    pub input_digest: ContentDigest,
    /// Exact provider-ready materialization digest.
    pub output_digest: ContentDigest,
    /// Typed production-call observations.
    pub tool_observations: Vec<ToolObservation>,
    /// Measured or normalized phase durations.
    pub phases: Vec<PhaseTiming>,
    /// Reproduction artifacts containing no source bodies.
    pub artifacts: Vec<Artifact>,
    /// Exact and explicitly unavailable resource facts.
    pub resources: Resources,
    /// Optional handoff/effect/replay facts.
    pub effect_replay: EffectReplay,
    /// Closed terminal state.
    pub status: String,
}

/// One self-identifying raw observation.
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    /// Must be `cigar.benchmark-observation.v2`.
    pub schema_version: String,
    /// Multihash over the canonical [`ObservationBody`].
    pub observation_id: ContentDigest,
    /// Parent refinement run.
    pub run_id: String,
    /// Paired comparison identity.
    pub pair_id: String,
    /// Benchmark task.
    pub task_id: String,
    /// Honey, champion, candidate, or explicit baseline.
    pub treatment: Treatment,
    /// Production or deterministic recorded mode.
    pub consumer_mode: ConsumerMode,
    /// Exact candidate source.
    pub source: SourceIdentity,
    /// Digest of exact assignment bytes.
    pub assignment_digest: ContentDigest,
    /// Digest of exact fixture archive bytes.
    pub archive_digest: ContentDigest,
    /// Immutable semantic/configuration pins.
    pub pins: Pins,
    /// Ordered packed blocks.
    pub selected_blocks: Vec<SelectedBlock>,
    /// Complete authorized candidate disposition table.
    pub dispositions: Vec<Disposition>,
    /// Exact consumer input digest.
    pub input_digest: ContentDigest,
    /// Exact provider-ready materialization digest.
    pub output_digest: ContentDigest,
    /// Typed production-call observations.
    pub tool_observations: Vec<ToolObservation>,
    /// Measured or normalized phase durations.
    pub phases: Vec<PhaseTiming>,
    /// Reproduction artifacts containing no source bodies.
    pub artifacts: Vec<Artifact>,
    /// Exact and explicitly unavailable resource facts.
    pub resources: Resources,
    /// Optional handoff/effect/replay facts.
    pub effect_replay: EffectReplay,
    /// Closed terminal state.
    pub status: String,
}

impl Observation {
    /// Seals a body under its exact canonical bytes.
    pub fn seal(body: ObservationBody) -> Result<Self, ConsumerError> {
        let observation_id = multihash(&canonical_json(&body)?)?;
        Ok(Self {
            schema_version: body.schema_version,
            observation_id,
            run_id: body.run_id,
            pair_id: body.pair_id,
            task_id: body.task_id,
            treatment: body.treatment,
            consumer_mode: body.consumer_mode,
            source: body.source,
            assignment_digest: body.assignment_digest,
            archive_digest: body.archive_digest,
            pins: body.pins,
            selected_blocks: body.selected_blocks,
            dispositions: body.dispositions,
            input_digest: body.input_digest,
            output_digest: body.output_digest,
            tool_observations: body.tool_observations,
            phases: body.phases,
            artifacts: body.artifacts,
            resources: body.resources,
            effect_replay: body.effect_replay,
            status: body.status,
        })
    }

    /// Returns one exact normalized JSON record.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConsumerError> {
        canonical_json(self)
    }
}

/// Converts production bundle facts into the raw observation representation.
pub fn selected_blocks(bundle: &ContextBundle) -> Vec<SelectedBlock> {
    bundle
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| SelectedBlock {
            block_id: block.block_id.as_str().to_owned(),
            lane: lane_name(block.lane).to_owned(),
            representation: representation_name(block.representation).to_owned(),
            provenance_ids: block
                .provenance
                .iter()
                .map(|version| version.as_str().to_owned())
                .collect(),
            tokens: block.token_count,
            rank: index.saturating_add(1),
        })
        .collect()
}

/// Converts the protected manifest into content-safe final dispositions.
pub fn dispositions(manifest: &SelectionManifest) -> Vec<Disposition> {
    manifest
        .entries
        .iter()
        .map(|entry| Disposition {
            candidate_id: entry.version_id.as_str().to_owned(),
            reason: disposition_name(&entry.disposition),
        })
        .collect()
}

/// Retains the exact plan, bundle, and manifest needed for semantic reproduction.
pub fn core_artifacts(
    plan: &ContextPlan,
    bundle: &ContextBundle,
    manifest: &SelectionManifest,
) -> Result<Vec<Artifact>, ConsumerError> {
    Ok(vec![
        Artifact::canonical("plan", plan)?,
        Artifact::canonical("bundle", bundle)?,
        Artifact::canonical("manifest", manifest)?,
    ])
}

/// Canonicalizes a serializable record using CIGAR's normalized strict JSON profile.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ConsumerError> {
    let serialized =
        serde_json::to_vec(value).map_err(|_error| ConsumerError::new("json_serialize"))?;
    let node =
        parse_strict_json(&serialized).map_err(|_error| ConsumerError::new("json_profile"))?;
    to_normalized_json(&node).map_err(|_error| ConsumerError::new("json_profile"))
}

fn lane_name(value: LaneKind) -> &'static str {
    match value {
        LaneKind::Rules => "rules",
        LaneKind::Task => "task",
        LaneKind::Evidence => "evidence",
        LaneKind::History => "history",
        LaneKind::Tools => "tools",
    }
}

fn representation_name(value: RepresentationKind) -> &'static str {
    match value {
        RepresentationKind::Exact => "exact",
        RepresentationKind::Extracted => "extracted",
        RepresentationKind::Summarized => "summarized",
        RepresentationKind::Redacted => "redacted",
    }
}

fn disposition_name(value: &CandidateDisposition) -> String {
    match value {
        CandidateDisposition::Selected { lane, .. } => {
            format!("selected:{}", lane_name(*lane))
        }
        CandidateDisposition::Excluded { reason } => {
            format!("excluded:{}", reason_name(*reason))
        }
        CandidateDisposition::Redacted { reason } => {
            format!("redacted:{}", reason_name(*reason))
        }
        CandidateDisposition::RequiredMissing => "required_missing".to_owned(),
    }
}

fn reason_name(value: cigar_protocol::DispositionReason) -> &'static str {
    use cigar_protocol::DispositionReason;
    match value {
        DispositionReason::ScopeDenied => "scope_denied",
        DispositionReason::PurposeDenied => "purpose_denied",
        DispositionReason::TemporalMismatch => "temporal_mismatch",
        DispositionReason::TrustInsufficient => "trust_insufficient",
        DispositionReason::InstructionAuthorityDenied => "instruction_authority_denied",
        DispositionReason::ProcessorDenied => "processor_denied",
        DispositionReason::IntegrityFailed => "integrity_failed",
        DispositionReason::BudgetDisplaced => "budget_displaced",
        DispositionReason::LifecycleIneligible => "lifecycle_ineligible",
        DispositionReason::ConflictLost => "conflict_lost",
        DispositionReason::RequiredMissing => "required_missing",
    }
}

/// Returns a normalized timing value for the selected mode.
#[must_use]
pub const fn normalized_duration(mode: ConsumerMode, measured_ms: u64) -> u64 {
    match mode {
        ConsumerMode::Production => measured_ms,
        ConsumerMode::Recorded => 0,
    }
}

/// Creates one stable phase record.
#[must_use]
pub fn phase(mode: ConsumerMode, name: &str, measured_ms: u64) -> PhaseTiming {
    PhaseTiming {
        phase: name.to_owned(),
        duration_ms: normalized_duration(mode, measured_ms),
    }
}

/// Convenience constructor for the assignment-derived body fields.
pub fn body_prefix(
    assignment: &Assignment,
    assignment_digest: ContentDigest,
    pins: Pins,
) -> ObservationBody {
    ObservationBody {
        schema_version: "cigar.benchmark-observation.v2".to_owned(),
        run_id: assignment.run_id.clone(),
        pair_id: assignment.pair_id.clone(),
        task_id: assignment.task_id.clone(),
        treatment: assignment.treatment,
        consumer_mode: assignment.consumer_mode,
        source: assignment.source.clone(),
        assignment_digest: assignment_digest.clone(),
        archive_digest: assignment.archive_digest.clone(),
        pins,
        selected_blocks: Vec::new(),
        dispositions: Vec::new(),
        input_digest: assignment_digest,
        output_digest: assignment.archive_digest.clone(),
        tool_observations: Vec::new(),
        phases: Vec::new(),
        artifacts: Vec::new(),
        resources: Resources {
            physical_input_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            output_tokens: 0,
            latency_ms: 0,
            cpu_ms: 0,
            cpu_measured: false,
            peak_rss_bytes: 0,
            peak_rss_measured: false,
            cost_usd: 0,
        },
        effect_replay: EffectReplay {
            handoffs: 0,
            effects: 0,
            unsafe_retries: 0,
            replay_dispatches: 0,
        },
        status: "completed".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_mode_removes_only_timing_variance() {
        assert_eq!(normalized_duration(ConsumerMode::Recorded, 42), 0);
        assert_eq!(normalized_duration(ConsumerMode::Production, 42), 42);
        assert_eq!(phase(ConsumerMode::Recorded, "compile", 42).duration_ms, 0);
        assert_eq!(
            phase(ConsumerMode::Production, "compile", 42).duration_ms,
            42
        );
    }

    #[test]
    fn retained_artifacts_bind_exact_canonical_bytes() -> Result<(), ConsumerError> {
        let artifact = Artifact::canonical("explanation", &serde_json::json!({"entries": []}))?;
        let expected = br#"{"entries":[]}"#;
        let expected_digest = multihash(expected)?;
        assert_eq!(artifact.bytes, expected.len());
        assert_eq!(artifact.digest, expected_digest);
        assert_eq!(artifact.retained_base64url, "eyJlbnRyaWVzIjpbXX0");
        Ok(())
    }
}
