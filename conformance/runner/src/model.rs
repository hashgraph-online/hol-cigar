//! Versioned public request, response, vector, and result records.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum accepted conformance result document size.
pub const MAX_RESULT_BYTES: u64 = 4 * 1024 * 1024;

/// Immutable limits declared by one vector set.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorLimits {
    /// Maximum cases in the set.
    pub max_cases: usize,
    /// Maximum serialized request size.
    pub max_request_bytes: usize,
    /// Maximum response body size.
    pub max_response_bytes: usize,
    /// Maximum adapter diagnostic size.
    pub max_diagnostic_bytes: usize,
    /// Maximum wall time for one case.
    pub max_case_timeout_ms: u64,
    /// Maximum sum of case timeouts.
    pub max_total_timeout_ms: u64,
    /// Maximum virtual memory for a local adapter.
    pub max_memory_bytes: u64,
    /// Maximum file size for a local adapter.
    pub max_file_bytes: u64,
    /// Maximum processes for a local adapter.
    pub max_processes: u64,
}

/// Expected public result of one case.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedResult {
    /// Expected success or governed rejection.
    pub outcome: CaseOutcome,
    /// Expected content- or error-bound public digest.
    pub public_digest: String,
}

/// One immutable conformance case.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorCase {
    /// Stable case identifier.
    pub id: String,
    /// Profile owning the case.
    pub profile: String,
    /// Whether the case is mandatory.
    pub required: bool,
    /// Closed adapter operation name.
    pub operation: String,
    /// Per-case wall timeout.
    pub timeout_ms: u64,
    /// Bounded operation-specific input.
    pub input: Value,
    /// Required public result.
    pub expected: ExpectedResult,
}

/// Checked-in vector-set document.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorManifest {
    /// Exact schema selector.
    pub schema_version: String,
    /// Immutable vector-set identifier.
    pub vector_set: String,
    /// Repository source vector used to derive this set.
    pub source_vector: String,
    /// Exact digest of the source vector at publication.
    pub source_vector_sha256: String,
    /// Profiles with executable required cases in this set.
    pub profiles: Vec<String>,
    /// Resource bounds.
    pub limits: VectorLimits,
    /// Ordered cases.
    pub cases: Vec<VectorCase>,
}

/// Fresh request sent to an implementation adapter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRequest {
    /// Exact protocol selector.
    pub schema_version: String,
    /// Stable case identifier.
    pub case_id: String,
    /// Profile owning the case.
    pub profile: String,
    /// Closed operation name.
    pub operation: String,
    /// Per-invocation digest challenge that prevents stale response replay.
    pub challenge: String,
    /// Operation input without expected output.
    pub input: Value,
}

/// Governed case outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    /// The operation completed successfully.
    Success,
    /// The operation failed closed with the expected public error.
    Rejected,
}

/// Response returned by an implementation adapter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResponse {
    /// Exact protocol selector.
    pub schema_version: String,
    /// Stable case identifier.
    pub case_id: String,
    /// Echo of the invocation challenge.
    pub challenge: String,
    /// Public outcome.
    pub outcome: CaseOutcome,
    /// Public digest or error digest.
    pub public_digest: String,
    /// Optional bounded, value-free diagnostic.
    pub diagnostic: Option<String>,
}

/// Public case status; required cases have no skipped state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Exact required result matched.
    Passed,
    /// The case failed or could not be safely completed.
    Failed,
}

/// One public case result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    /// Stable case identifier.
    pub case_id: String,
    /// Owning profile.
    pub profile: String,
    /// Whether the case was mandatory.
    pub required: bool,
    /// Pass or failure status.
    pub status: CaseStatus,
    /// Bounded wall duration in milliseconds.
    pub duration_ms: u64,
    /// Expected governed outcome.
    pub expected_outcome: CaseOutcome,
    /// Actual governed outcome, when a well-formed response was received.
    pub actual_outcome: Option<CaseOutcome>,
    /// Expected public digest.
    pub expected_public_digest: String,
    /// Actual public digest, when a well-formed response was received.
    pub actual_public_digest: Option<String>,
    /// Value-free public diagnostic category.
    pub redacted_diagnostic: Option<String>,
}

/// Overall public result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallResult {
    /// Every required case and integrity check passed.
    Passed,
    /// At least one case or integrity check failed.
    Failed,
}

/// Stable platform record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    /// Operating-system family.
    pub os: String,
    /// CPU architecture.
    pub architecture: String,
    /// Rust target family used by the runner.
    pub family: String,
}

/// Versioned public conformance result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceResult {
    /// Exact result schema selector.
    pub schema_version: String,
    /// Implementation name supplied by the qualifier.
    pub implementation: String,
    /// Digest of the implementation executable or declared remote build.
    pub build_digest: String,
    /// Profiles actually executed.
    pub claimed_profiles: Vec<String>,
    /// Digest of the runner executable.
    pub runner_digest: String,
    /// Immutable vector-set identifier.
    pub vector_set: String,
    /// Digest of every path and byte in the vector directory.
    pub vector_digest: String,
    /// Runner platform.
    pub platform: Platform,
    /// Effective isolation level.
    pub isolation: String,
    /// Whether the run meets release-grade local isolation requirements.
    pub release_qualified: bool,
    /// Ordered case results.
    pub cases: Vec<CaseResult>,
    /// Value-free integrity failure categories outside individual cases.
    pub integrity_errors: Vec<String>,
    /// Overall result.
    pub overall: OverallResult,
    /// Digest of this document with this field omitted.
    pub result_digest: String,
}

/// Machine-readable traceability validation result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceabilityResult {
    /// Exact schema selector.
    pub schema_version: String,
    /// Digest of `tests/invariants.yaml`.
    pub manifest_digest: String,
    /// Digest of the independent normative requirement registry.
    pub requirement_registry_digest: String,
    /// Number of mapped normative requirements.
    pub requirement_count: usize,
    /// Number of unique active tests.
    pub test_count: usize,
    /// Whether all checks passed.
    pub valid: bool,
}
