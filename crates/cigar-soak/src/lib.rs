//! Deterministic CIGAR soak plan generation and offline receipt verification.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const PLAN_VERSION: &str = "cigar.soak-plan.v1";
const RESULT_VERSION: &str = "cigar.soak-result.v1";
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
const REQUIRED_PHASES: [&str; 14] = [
    "backup_verify",
    "compile",
    "context_switch",
    "delta",
    "discovery_ingestion",
    "effect",
    "fault_recovery",
    "gc_plan_execute",
    "handoff",
    "ordered_shutdown",
    "post_run_verify",
    "reconcile_compensate",
    "replay",
    "space_checkpoint_event",
];

/// Stable content-free soak tooling failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoakError {
    /// A document or output path was unavailable or unsafe.
    Unavailable,
    /// JSON was malformed, duplicated, unknown, or exceeded its bound.
    InvalidDocument,
    /// A plan was internally inconsistent or outside the reviewed profile.
    InvalidPlan,
    /// A result was incomplete or contradicted its plan or status.
    InvalidResult,
    /// Cryptographic source, binary, plan, or sample bindings disagreed.
    BindingMismatch,
    /// Operating-system randomness or time was unavailable.
    EntropyUnavailable,
    /// The isolated workload driver is not present in this build.
    DriverUnavailable,
}

impl fmt::Display for SoakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "soak input or output is unavailable",
            Self::InvalidDocument => "soak document is invalid",
            Self::InvalidPlan => "soak plan is invalid",
            Self::InvalidResult => "soak result is invalid",
            Self::BindingMismatch => "soak evidence binding does not match",
            Self::EntropyUnavailable => "soak entropy or time is unavailable",
            Self::DriverUnavailable => "soak workload driver is unavailable",
        })
    }
}

impl std::error::Error for SoakError {}

/// Closed reviewed soak profile vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SoakProfile {
    /// Two-minute harness and receipt smoke.
    #[serde(rename = "soak-smoke")]
    Smoke,
    /// Fifteen-minute local feedback run.
    #[serde(rename = "soak-developer")]
    Developer,
    /// One-hour development leak and fault signal.
    #[serde(rename = "soak-extended")]
    Extended,
    /// Exact installed-candidate 24-hour gate.
    #[serde(rename = "soak-rc-24h")]
    ReleaseCandidate24Hour,
}

impl SoakProfile {
    /// Resolves an exact reviewed profile ID.
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "soak-smoke" => Some(Self::Smoke),
            "soak-developer" => Some(Self::Developer),
            "soak-extended" => Some(Self::Extended),
            "soak-rc-24h" => Some(Self::ReleaseCandidate24Hour),
            _ => None,
        }
    }

    /// Returns the exact reviewed profile ID.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Smoke => "soak-smoke",
            Self::Developer => "soak-developer",
            Self::Extended => "soak-extended",
            Self::ReleaseCandidate24Hour => "soak-rc-24h",
        }
    }

    /// Returns the exact reviewed duration.
    #[must_use]
    pub const fn duration_seconds(self) -> u64 {
        match self {
            Self::Smoke => 120,
            Self::Developer => 900,
            Self::Extended => 3_600,
            Self::ReleaseCandidate24Hour => 86_400,
        }
    }

    fn sessions(self) -> Vec<u16> {
        match self {
            Self::Smoke => vec![1, 2],
            Self::Developer => vec![1, 2, 4, 8],
            Self::Extended => vec![1, 2, 4, 8, 16, 32],
            Self::ReleaseCandidate24Hour => vec![1, 2, 4, 8, 16, 32, 64],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FaultKind {
    Latency,
    Unavailable,
    StreamDisconnect,
    GracefulRestart,
    ProcessKill,
    IndexLag,
    ObjectFailure,
    KeyFailure,
    AmbiguousEffect,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SoakFault {
    id: String,
    kind: FaultKind,
    at_operation: u64,
    duration_ms: u64,
}

/// Strict deterministic soak plan document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoakPlan {
    schema_version: String,
    plan_id: String,
    profile_id: SoakProfile,
    seed: u64,
    duration_seconds: u64,
    session_schedule: Vec<u16>,
    workload_weights: BTreeMap<String, u16>,
    faults: Vec<SoakFault>,
    source_revision: String,
    daemon_digest: String,
    profile_digest: String,
}

impl SoakPlan {
    /// Returns the stable plan UUIDv7.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.plan_id
    }

    /// Returns the reviewed profile.
    #[must_use]
    pub const fn profile(&self) -> SoakProfile {
        self.profile_id
    }
}

/// Exact source, daemon, and registry bindings used when creating a plan.
#[derive(Clone, Debug)]
pub struct PlanBindings {
    source_revision: String,
    daemon_digest: String,
    profile_digest: String,
}

impl PlanBindings {
    /// Creates bindings; plan generation performs strict semantic validation.
    #[must_use]
    pub fn new(source_revision: String, daemon_digest: String, profile_digest: String) -> Self {
        Self {
            source_revision,
            daemon_digest,
            profile_digest,
        }
    }
}

/// Loaded strict plan with the SHA-256 of its exact input bytes.
#[derive(Clone, Debug)]
pub struct LoadedPlan {
    plan: SoakPlan,
    digest: [u8; 32],
}

impl LoadedPlan {
    /// Loads a strict bounded plan from an absolute regular file.
    pub fn load(path: &Path) -> Result<Self, SoakError> {
        let source = read_document(path)?;
        Self::from_json(&source)
    }

    /// Parses strict JSON, rejects duplicate fields, and validates plan semantics.
    pub fn from_json(source: &[u8]) -> Result<Self, SoakError> {
        validate_document_bytes(source)?;
        reject_duplicate_fields(source)?;
        let plan: SoakPlan =
            serde_json::from_slice(source).map_err(|_error| SoakError::InvalidDocument)?;
        validate_plan(&plan)?;
        Ok(Self {
            plan,
            digest: Sha256::digest(source).into(),
        })
    }

    /// Returns the validated plan.
    #[must_use]
    pub const fn plan(&self) -> &SoakPlan {
        &self.plan
    }

    /// Returns the exact plan file digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Generates a fully bound reviewed plan without starting any process.
pub fn generate_plan(
    profile: SoakProfile,
    seed: u64,
    bindings: PlanBindings,
) -> Result<SoakPlan, SoakError> {
    let plan = SoakPlan {
        schema_version: PLAN_VERSION.to_owned(),
        plan_id: uuid_v7()?,
        profile_id: profile,
        seed,
        duration_seconds: profile.duration_seconds(),
        session_schedule: profile.sessions(),
        workload_weights: default_workload_weights(),
        faults: profile_faults(profile),
        source_revision: bindings.source_revision,
        daemon_digest: bindings.daemon_digest,
        profile_digest: bindings.profile_digest,
    };
    validate_plan(&plan)?;
    Ok(plan)
}

/// Serializes a plan deterministically and creates a new absolute output file atomically enough
/// for qualification staging: existing paths are never replaced.
pub fn write_new_plan(path: &Path, plan: &SoakPlan) -> Result<(), SoakError> {
    validate_plan(plan)?;
    if !path.is_absolute() {
        return Err(SoakError::Unavailable);
    }
    let bytes = serde_json::to_vec_pretty(plan).map_err(|_error| SoakError::InvalidDocument)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_error| SoakError::Unavailable)?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_error| SoakError::Unavailable)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SoakStatus {
    Passed,
    Failed,
    Cancelled,
    TimedOut,
    InfrastructureFailed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvariantResult {
    id: String,
    status: InvariantStatus,
    observed: String,
    threshold: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InvariantStatus {
    Passed,
    Failed,
    Unsupported,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SoakResult {
    schema_version: String,
    result_id: String,
    plan_id: String,
    plan_digest: String,
    profile_id: SoakProfile,
    status: SoakStatus,
    started_at: String,
    finished_at: String,
    duration_seconds: u64,
    source_revision: String,
    daemon_digest: String,
    soak_binary_digest: String,
    completed_phases: Vec<String>,
    operation_counts: BTreeMap<String, u64>,
    session_operation_counts: BTreeMap<String, u64>,
    fault_counts: BTreeMap<String, u64>,
    sample_count: u64,
    warmup_sample_count: u64,
    invariants: Vec<InvariantResult>,
    samples_digest: String,
    #[serde(default)]
    failure_codes: Vec<String>,
}

/// Content-free successful verification summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedResult {
    result_id: String,
    status: &'static str,
    result_digest: [u8; 32],
}

impl VerifiedResult {
    /// Returns the verified result ID.
    #[must_use]
    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    /// Returns the verified terminal status.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the exact result file digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.result_digest
    }
}

/// Verifies one result against an exact loaded plan without network or process access.
pub fn verify_result(plan: &LoadedPlan, result_path: &Path) -> Result<VerifiedResult, SoakError> {
    let source = read_document(result_path)?;
    verify_result_json(plan, &source)
}

/// Verifies strict result bytes against an exact loaded plan.
pub fn verify_result_json(loaded: &LoadedPlan, source: &[u8]) -> Result<VerifiedResult, SoakError> {
    validate_document_bytes(source)?;
    reject_duplicate_fields(source)?;
    let result: SoakResult =
        serde_json::from_slice(source).map_err(|_error| SoakError::InvalidDocument)?;
    validate_result(loaded, &result)?;
    Ok(VerifiedResult {
        result_id: result.result_id,
        status: status_name(result.status),
        result_digest: Sha256::digest(source).into(),
    })
}

fn validate_plan(plan: &SoakPlan) -> Result<(), SoakError> {
    if plan.schema_version != PLAN_VERSION
        || !uuid_v7_is_valid(&plan.plan_id)
        || plan.duration_seconds != plan.profile_id.duration_seconds()
        || plan.session_schedule != plan.profile_id.sessions()
        || !bounded_text(&plan.source_revision, 128)
        || !sha256_is_valid(&plan.daemon_digest)
        || !sha256_is_valid(&plan.profile_digest)
        || plan.workload_weights.is_empty()
        || plan.workload_weights.len() > 32
        || plan
            .workload_weights
            .iter()
            .any(|(id, weight)| !bounded_identifier(id) || *weight == 0)
        || plan
            .workload_weights
            .values()
            .map(|value| u64::from(*value))
            .sum::<u64>()
            != 10_000
    {
        return Err(SoakError::InvalidPlan);
    }
    let mut prior_operation = 0_u64;
    let mut fault_ids = BTreeSet::new();
    for fault in &plan.faults {
        if !bounded_identifier(&fault.id)
            || !fault_ids.insert(fault.id.as_str())
            || fault.at_operation <= prior_operation
            || fault.duration_ms > 300_000
        {
            return Err(SoakError::InvalidPlan);
        }
        prior_operation = fault.at_operation;
    }
    Ok(())
}

fn validate_result(loaded: &LoadedPlan, result: &SoakResult) -> Result<(), SoakError> {
    let plan = loaded.plan();
    if result.schema_version != RESULT_VERSION
        || !uuid_v7_is_valid(&result.result_id)
        || result.plan_id != plan.plan_id
        || result.profile_id != plan.profile_id
        || result.source_revision != plan.source_revision
        || result.daemon_digest != plan.daemon_digest
        || !sha256_is_valid(&result.soak_binary_digest)
        || !sha256_is_valid(&result.samples_digest)
        || result.plan_digest != hex_digest(loaded.digest())
    {
        return Err(SoakError::BindingMismatch);
    }
    let started = OffsetDateTime::parse(&result.started_at, &Rfc3339)
        .map_err(|_error| SoakError::InvalidResult)?;
    let finished = OffsetDateTime::parse(&result.finished_at, &Rfc3339)
        .map_err(|_error| SoakError::InvalidResult)?;
    let elapsed = u64::try_from((finished - started).whole_seconds())
        .map_err(|_error| SoakError::InvalidResult)?;
    if elapsed != result.duration_seconds
        || result.duration_seconds > 604_800
        || result.sample_count < 3
        || result.warmup_sample_count == 0
        || result.warmup_sample_count.saturating_add(2) > result.sample_count
        || result.operation_counts.is_empty()
        || result.operation_counts.len() > 128
        || result.invariants.is_empty()
        || result.invariants.len() > 256
        || !exact_string_set(&result.completed_phases, &REQUIRED_PHASES)
        || !exact_session_counts(plan, &result.session_operation_counts)
        || !exact_fault_counts(plan, &result.fault_counts)
        || !valid_counts(&result.operation_counts)
        || !valid_counts(&result.session_operation_counts)
        || !valid_counts(&result.fault_counts)
        || !valid_invariants(&result.invariants)
        || !valid_failure_codes(&result.failure_codes)
    {
        return Err(SoakError::InvalidResult);
    }
    let all_invariants_pass = result
        .invariants
        .iter()
        .all(|invariant| invariant.status == InvariantStatus::Passed);
    let operation_total = result.operation_counts.values().copied().sum::<u64>();
    match result.status {
        SoakStatus::Passed
            if result.duration_seconds >= plan.duration_seconds
                && result.failure_codes.is_empty()
                && all_invariants_pass
                && operation_total > 0 => {}
        SoakStatus::Passed => return Err(SoakError::InvalidResult),
        _ if result.failure_codes.is_empty() => return Err(SoakError::InvalidResult),
        _ => {}
    }
    Ok(())
}

fn exact_session_counts(plan: &SoakPlan, counts: &BTreeMap<String, u64>) -> bool {
    let expected: BTreeSet<String> = plan.session_schedule.iter().map(u16::to_string).collect();
    counts.keys().cloned().collect::<BTreeSet<_>>() == expected
}

fn exact_fault_counts(plan: &SoakPlan, counts: &BTreeMap<String, u64>) -> bool {
    let expected: BTreeSet<&str> = plan.faults.iter().map(|fault| fault.id.as_str()).collect();
    counts.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected
}

fn exact_string_set(values: &[String], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && values.iter().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
}

fn valid_counts(counts: &BTreeMap<String, u64>) -> bool {
    counts
        .keys()
        .all(|id| bounded_identifier(id) || id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_invariants(invariants: &[InvariantResult]) -> bool {
    let mut prior: Option<&str> = None;
    invariants.iter().all(|invariant| {
        let valid = bounded_identifier(&invariant.id)
            && invariant.observed.len() <= 256
            && invariant.threshold.len() <= 256
            && prior.is_none_or(|value| value < invariant.id.as_str());
        prior = Some(invariant.id.as_str());
        valid
    })
}

fn valid_failure_codes(codes: &[String]) -> bool {
    if codes.len() > 256 {
        return false;
    }
    let mut prior: Option<&str> = None;
    codes.iter().all(|code| {
        let valid = bounded_identifier(code) && prior.is_none_or(|value| value < code.as_str());
        prior = Some(code.as_str());
        valid
    })
}

fn default_workload_weights() -> BTreeMap<String, u16> {
    BTreeMap::from([
        ("compile".to_owned(), 1_800),
        ("context".to_owned(), 1_800),
        ("effect".to_owned(), 1_400),
        ("handoff".to_owned(), 1_400),
        ("maintenance".to_owned(), 1_000),
        ("replay".to_owned(), 1_000),
        ("space".to_owned(), 1_600),
    ])
}

fn profile_faults(profile: SoakProfile) -> Vec<SoakFault> {
    let all = vec![
        SoakFault {
            id: "stream-disconnect-1".to_owned(),
            kind: FaultKind::StreamDisconnect,
            at_operation: 1_000,
            duration_ms: 500,
        },
        SoakFault {
            id: "dependency-latency-1".to_owned(),
            kind: FaultKind::Latency,
            at_operation: 5_000,
            duration_ms: 1_000,
        },
        SoakFault {
            id: "graceful-restart-1".to_owned(),
            kind: FaultKind::GracefulRestart,
            at_operation: 10_000,
            duration_ms: 5_000,
        },
        SoakFault {
            id: "ambiguous-effect-1".to_owned(),
            kind: FaultKind::AmbiguousEffect,
            at_operation: 25_000,
            duration_ms: 3_000,
        },
        SoakFault {
            id: "process-kill-1".to_owned(),
            kind: FaultKind::ProcessKill,
            at_operation: 50_000,
            duration_ms: 10_000,
        },
    ];
    let count = match profile {
        SoakProfile::Smoke => 0,
        SoakProfile::Developer => 1,
        SoakProfile::Extended => 3,
        SoakProfile::ReleaseCandidate24Hour => all.len(),
    };
    all.into_iter().take(count).collect()
}

fn status_name(status: SoakStatus) -> &'static str {
    match status {
        SoakStatus::Passed => "passed",
        SoakStatus::Failed => "failed",
        SoakStatus::Cancelled => "cancelled",
        SoakStatus::TimedOut => "timed_out",
        SoakStatus::InfrastructureFailed => "infrastructure_failed",
    }
}

fn read_document(path: &Path) -> Result<Vec<u8>, SoakError> {
    if !path.is_absolute() {
        return Err(SoakError::Unavailable);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_error| SoakError::Unavailable)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_DOCUMENT_BYTES
    {
        return Err(SoakError::Unavailable);
    }
    fs::read(path).map_err(|_error| SoakError::Unavailable)
}

fn validate_document_bytes(source: &[u8]) -> Result<(), SoakError> {
    if source.is_empty() || source.len() > MAX_DOCUMENT_BYTES as usize {
        Err(SoakError::InvalidDocument)
    } else {
        Ok(())
    }
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate object names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate object name"));
            }
            map.next_value::<UniqueJson>()?;
        }
        Ok(UniqueJson)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJson>()?.is_some() {}
        Ok(UniqueJson)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }
}

fn reject_duplicate_fields(source: &[u8]) -> Result<(), SoakError> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    UniqueJson::deserialize(&mut deserializer).map_err(|_error| SoakError::InvalidDocument)?;
    deserializer
        .end()
        .map_err(|_error| SoakError::InvalidDocument)
}

fn uuid_v7() -> Result<String, SoakError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| SoakError::EntropyUnavailable)?
        .as_millis();
    if timestamp >= (1_u128 << 48) {
        return Err(SoakError::EntropyUnavailable);
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_error| SoakError::EntropyUnavailable)?;
    let entropy = u128::from_be_bytes(random);
    let mut value = (timestamp << 80) | (entropy & ((1_u128 << 76) - 1));
    value = (value & !(0xf_u128 << 76)) | (0x7_u128 << 76);
    value = (value & !(0x3_u128 << 62)) | (0x2_u128 << 62);
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) & 0xffff_ffff,
        (value >> 80) & 0xffff,
        (value >> 64) & 0xffff,
        (value >> 48) & 0xffff,
        value & 0xffff_ffff_ffff
    ))
}

fn uuid_v7_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.get(8) == Some(&b'-')
        && bytes.get(13) == Some(&b'-')
        && bytes.get(14) == Some(&b'7')
        && bytes.get(18) == Some(&b'-')
        && bytes.get(23) == Some(&b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
        && bytes
            .get(19)
            .is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'))
        && !bytes.iter().any(u8::is_ascii_uppercase)
}

fn sha256_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex_digest(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    digest.iter().fold(
        String::with_capacity(digest.len() * 2),
        |mut output, byte| {
            if write!(output, "{byte:02x}").is_err() {
                return String::new();
            }
            output
        },
    )
}

fn bounded_identifier(value: &str) -> bool {
    bounded_text(value, 128)
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !value.ends_with(['.', '_', '-'])
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.contains(['\0', '\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::{
        LoadedPlan, PlanBindings, SoakError, SoakProfile, generate_plan, hex_digest,
        verify_result_json,
    };
    use serde_json::{Value, json};

    fn plan() -> Result<(LoadedPlan, Vec<u8>), Box<dyn std::error::Error>> {
        let plan = generate_plan(
            SoakProfile::Smoke,
            7,
            PlanBindings::new("revision-1".to_owned(), "a".repeat(64), "b".repeat(64)),
        )?;
        let source = serde_json::to_vec(&plan)?;
        Ok((LoadedPlan::from_json(&source)?, source))
    }

    fn passed_result(plan: &LoadedPlan) -> Value {
        json!({
            "schema_version": "cigar.soak-result.v1",
            "result_id": "018f0c96-2d8a-7f15-8c3d-16f8e8b72a44",
            "plan_id": plan.plan().plan_id,
            "plan_digest": hex_digest(plan.digest()),
            "profile_id": "soak-smoke",
            "status": "passed",
            "started_at": "2026-07-13T00:00:00Z",
            "finished_at": "2026-07-13T00:02:00Z",
            "duration_seconds": 120,
            "source_revision": "revision-1",
            "daemon_digest": "a".repeat(64),
            "soak_binary_digest": "c".repeat(64),
            "completed_phases": super::REQUIRED_PHASES,
            "operation_counts": {"compile": 100},
            "session_operation_counts": {"1": 50, "2": 50},
            "fault_counts": {},
            "sample_count": 12,
            "warmup_sample_count": 2,
            "invariants": [{
                "id": "canary-absence",
                "status": "passed",
                "observed": "0",
                "threshold": "0"
            }],
            "samples_digest": "d".repeat(64),
            "failure_codes": []
        })
    }

    #[test]
    fn reviewed_profiles_generate_strict_bound_plans() -> Result<(), Box<dyn std::error::Error>> {
        for profile in [
            SoakProfile::Smoke,
            SoakProfile::Developer,
            SoakProfile::Extended,
            SoakProfile::ReleaseCandidate24Hour,
        ] {
            let generated = generate_plan(
                profile,
                42,
                PlanBindings::new("revision-1".to_owned(), "a".repeat(64), "b".repeat(64)),
            )?;
            assert_eq!(generated.duration_seconds, profile.duration_seconds());
            LoadedPlan::from_json(&serde_json::to_vec(&generated)?)?;
        }
        Ok(())
    }

    #[test]
    fn complete_passing_result_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let (plan, _source) = plan()?;
        let verified = verify_result_json(&plan, &serde_json::to_vec(&passed_result(&plan))?)?;
        assert_eq!(verified.status(), "passed");
        Ok(())
    }

    #[test]
    fn duplicate_fields_and_plan_binding_mismatch_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (plan, source) = plan()?;
        let duplicate = String::from_utf8(source)?.replacen(
            "\"schema_version\":",
            "\"schema_version\":\"cigar.soak-plan.v1\",\"schema_version\":",
            1,
        );
        assert_eq!(
            LoadedPlan::from_json(duplicate.as_bytes()).err(),
            Some(SoakError::InvalidDocument)
        );

        let mut result = passed_result(&plan);
        result
            .as_object_mut()
            .ok_or("result object missing")?
            .insert("plan_digest".to_owned(), Value::from("0".repeat(64)));
        assert_eq!(
            verify_result_json(&plan, &serde_json::to_vec(&result)?).err(),
            Some(SoakError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn passing_status_rejects_missing_phase_or_failed_invariant()
    -> Result<(), Box<dyn std::error::Error>> {
        let (plan, _source) = plan()?;
        let mut result = passed_result(&plan);
        result
            .get_mut("completed_phases")
            .and_then(Value::as_array_mut)
            .ok_or("phases missing")?
            .pop();
        assert_eq!(
            verify_result_json(&plan, &serde_json::to_vec(&result)?).err(),
            Some(SoakError::InvalidResult)
        );

        let mut result = passed_result(&plan);
        let invariant = result
            .get_mut("invariants")
            .and_then(Value::as_array_mut)
            .and_then(|items| items.first_mut())
            .and_then(Value::as_object_mut)
            .ok_or("invariant missing")?;
        invariant.insert("status".to_owned(), Value::from("failed"));
        assert_eq!(
            verify_result_json(&plan, &serde_json::to_vec(&result)?).err(),
            Some(SoakError::InvalidResult)
        );
        Ok(())
    }
}
