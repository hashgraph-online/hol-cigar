//! Standalone bounded CIGAR conformance runner, verifier, and traceability gate.

mod digest;
mod model;
mod prd_traceability;
mod traceability;
mod transport;
mod vectors;

pub use model::{
    AdapterRequest, AdapterResponse, CaseOutcome, CaseResult, CaseStatus, ConformanceResult,
    OverallResult, TraceabilityResult,
};
pub use traceability::validate_traceability;
pub use transport::{AdapterTarget, IsolationMode};

use digest::{
    hash_directory, hash_file, result_digest, sha256, snapshot_directory, valid_public_digest,
    valid_sha256,
};
use model::{MAX_RESULT_BYTES, Platform};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use transport::{invoke, isolation_claim};
use vectors::{
    load_vector_manifest_bytes, request_for_case, selected_cases, validate_fixture_manifest_bytes,
};

/// Exact result schema selector.
pub const RESULT_SCHEMA: &str = "cigar.conformance-result.v1";

/// Inputs for one complete profile run.
#[derive(Clone, Debug)]
pub struct RunConfiguration {
    /// Claimed profiles to execute.
    pub profiles: Vec<String>,
    /// Explicit implementation adapter.
    pub target: AdapterTarget,
    /// Safe implementation display name.
    pub implementation: String,
    /// Required for remote targets; local executable builds are hashed directly.
    pub remote_build_digest: Option<String>,
    /// Immutable vector directory.
    pub vectors: PathBuf,
    /// Requested local isolation.
    pub isolation: IsolationMode,
}

/// Runs every selected case and returns a self-bound result, including failures.
pub fn run_suite(configuration: &RunConfiguration) -> Result<ConformanceResult, String> {
    validate_implementation_name(&configuration.implementation)?;
    let vector_snapshot = snapshot_directory(&configuration.vectors)?;
    let vector_digest_before = vector_snapshot.digest.clone();
    let manifest = load_vector_manifest_bytes(vector_snapshot.file("core-v1.json")?)?;
    validate_fixture_manifest_bytes(vector_snapshot.file("fixture.toml")?, &manifest)?;
    let cases = selected_cases(&manifest, &configuration.profiles)?;
    let current_executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve runner executable: {error}"))?;
    let runner_digest = hash_file(&current_executable)?;
    let prepared_target = prepare_target(configuration)?;
    let build_digest = prepared_target.build_digest.clone();
    let (isolation, mut release_qualified) =
        isolation_claim(&prepared_target.target, configuration.isolation);

    let mut case_results = Vec::with_capacity(cases.len());
    for case in cases {
        let challenge = fresh_challenge(&case.id, &runner_digest, &vector_digest_before)?;
        let request = request_for_case(case, &challenge);
        let invocation = invoke(
            &prepared_target.target,
            &request,
            Duration::from_millis(case.timeout_ms),
            &manifest.limits,
            configuration.isolation,
        );
        let mut result = CaseResult {
            case_id: case.id.clone(),
            profile: case.profile.clone(),
            required: case.required,
            status: CaseStatus::Failed,
            duration_ms: invocation.duration_ms,
            expected_outcome: case.expected.outcome,
            actual_outcome: None,
            expected_public_digest: case.expected.public_digest.clone(),
            actual_public_digest: None,
            redacted_diagnostic: None,
        };
        match invocation.response {
            Ok(bytes) => match decode_adapter_response(&bytes, &manifest.limits) {
                Ok(response)
                    if response.case_id == case.id
                        && response.challenge == challenge
                        && response.outcome == case.expected.outcome
                        && response.public_digest == case.expected.public_digest =>
                {
                    result.status = CaseStatus::Passed;
                    result.actual_outcome = Some(response.outcome);
                    result.actual_public_digest = Some(response.public_digest);
                }
                Ok(response) => {
                    result.actual_outcome = Some(response.outcome);
                    if valid_public_digest(&response.public_digest) {
                        result.actual_public_digest = Some(response.public_digest);
                    }
                    result.redacted_diagnostic = Some(
                        if response.case_id != case.id || response.challenge != challenge {
                            "response_binding_mismatch".to_owned()
                        } else {
                            "public_result_mismatch".to_owned()
                        },
                    );
                }
                Err(category) => result.redacted_diagnostic = Some(category.to_owned()),
            },
            Err(failure) => {
                result.redacted_diagnostic = Some(failure.category().to_owned());
            }
        }
        case_results.push(result);
    }

    let mut integrity_errors = Vec::new();
    if case_results
        .iter()
        .any(|result| result.redacted_diagnostic.as_deref() == Some("isolation_unavailable"))
    {
        release_qualified = false;
    }
    match hash_directory(&configuration.vectors) {
        Ok(vector_digest_after) if vector_digest_after == vector_digest_before => {}
        Ok(_) | Err(_) => integrity_errors.push("vector_mutation".to_owned()),
    }
    let passed = integrity_errors.is_empty()
        && case_results
            .iter()
            .all(|result| result.status == CaseStatus::Passed);
    release_qualified &= passed;
    let mut result = ConformanceResult {
        schema_version: RESULT_SCHEMA.to_owned(),
        implementation: configuration.implementation.clone(),
        build_digest,
        claimed_profiles: configuration.profiles.clone(),
        runner_digest,
        vector_set: manifest.vector_set,
        vector_digest: vector_digest_before,
        platform: Platform {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            family: std::env::consts::FAMILY.to_owned(),
        },
        isolation: isolation.to_owned(),
        release_qualified,
        cases: case_results,
        integrity_errors,
        overall: if passed {
            OverallResult::Passed
        } else {
            OverallResult::Failed
        },
        result_digest: String::new(),
    };
    result.result_digest = result_digest(&result)?;
    Ok(result)
}

/// Verifies a passing result against this exact runner and vector tree.
pub fn verify_result(result: &ConformanceResult, vectors_root: &Path) -> Result<(), String> {
    validate_result_structure(result, vectors_root, true)?;
    if result.overall != OverallResult::Passed {
        return Err("conformance result is structurally valid but did not pass".to_owned());
    }
    Ok(())
}

/// Reads and verifies a bounded JSON result file.
pub fn verify_result_file(path: &Path, vectors_root: &Path) -> Result<ConformanceResult, String> {
    let bytes = read_bounded_regular_file(path, MAX_RESULT_BYTES)?;
    let result: ConformanceResult = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid conformance result JSON: {error}"))?;
    verify_result(&result, vectors_root)?;
    Ok(result)
}

pub(crate) fn verify_result_file_detached(
    path: &Path,
    vectors_root: &Path,
) -> Result<ConformanceResult, String> {
    let bytes = read_bounded_regular_file(path, MAX_RESULT_BYTES)?;
    let result: ConformanceResult = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid conformance result JSON: {error}"))?;
    validate_result_structure(&result, vectors_root, false)?;
    if result.overall != OverallResult::Passed {
        return Err("conformance result is structurally valid but did not pass".to_owned());
    }
    Ok(result)
}

/// Atomically writes a bounded pretty JSON artifact.
pub fn write_json_artifact(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot serialize JSON artifact: {error}"))?;
    if bytes.len() as u64 > MAX_RESULT_BYTES {
        return Err("JSON artifact exceeds the published size bound".to_owned());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create artifact directory: {error}"))?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err("artifact destination has an unsafe file type".to_owned());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create temporary artifact: {error}"))?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.write_all(b"\n"))
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("cannot write temporary artifact: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("cannot publish artifact: {}", error.error))?;
    sync_parent(parent)?;
    Ok(())
}

fn validate_result_structure(
    result: &ConformanceResult,
    vectors_root: &Path,
    require_current_runner: bool,
) -> Result<(), String> {
    if result.schema_version != RESULT_SCHEMA
        || !valid_implementation_name(&result.implementation)
        || !valid_sha256(&result.build_digest)
        || !valid_sha256(&result.runner_digest)
        || !valid_sha256(&result.vector_digest)
        || !valid_sha256(&result.result_digest)
        || result.platform.os.is_empty()
        || result.platform.os.len() > 64
        || result.platform.architecture.is_empty()
        || result.platform.architecture.len() > 64
        || result.platform.family.is_empty()
        || result.platform.family.len() > 64
    {
        return Err("invalid conformance result identity metadata".to_owned());
    }
    if result.result_digest != result_digest(result)? {
        return Err("conformance result self-digest mismatch".to_owned());
    }
    if require_current_runner {
        let current_executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve verifier executable: {error}"))?;
        if result.runner_digest != hash_file(&current_executable)? {
            return Err("result was produced by a different runner binary".to_owned());
        }
    }
    let snapshot = snapshot_directory(vectors_root)?;
    if result.vector_digest != snapshot.digest {
        return Err("result vector digest does not match the supplied archive".to_owned());
    }
    let manifest = load_vector_manifest_bytes(snapshot.file("core-v1.json")?)?;
    validate_fixture_manifest_bytes(snapshot.file("fixture.toml")?, &manifest)?;
    if result.vector_set != manifest.vector_set {
        return Err("result vector-set identity mismatch".to_owned());
    }
    let cases = selected_cases(&manifest, &result.claimed_profiles)?;
    if cases.len() != result.cases.len() {
        return Err("result omitted or added a required conformance case".to_owned());
    }
    for (expected, actual) in cases.into_iter().zip(&result.cases) {
        if actual.case_id != expected.id
            || actual.profile != expected.profile
            || actual.required != expected.required
            || actual.expected_outcome != expected.expected.outcome
            || actual.expected_public_digest != expected.expected.public_digest
            || actual.duration_ms > expected.timeout_ms.saturating_add(5000)
        {
            return Err(format!("result metadata mismatch for `{}`", expected.id));
        }
        let exact = actual.actual_outcome == Some(expected.expected.outcome)
            && actual.actual_public_digest.as_deref()
                == Some(expected.expected.public_digest.as_str());
        match actual.status {
            CaseStatus::Passed
                if exact
                    && actual.redacted_diagnostic.is_none()
                    && actual
                        .actual_public_digest
                        .as_deref()
                        .is_some_and(valid_public_digest) => {}
            CaseStatus::Failed
                if actual
                    .redacted_diagnostic
                    .as_deref()
                    .is_some_and(valid_diagnostic) => {}
            _ => {
                return Err(format!("invalid status proof for `{}`", expected.id));
            }
        }
    }
    if result.integrity_errors.len() > 8
        || result
            .integrity_errors
            .iter()
            .any(|error| error != "vector_mutation")
    {
        return Err("result contains an invalid integrity category".to_owned());
    }
    let all_passed = result.integrity_errors.is_empty()
        && result
            .cases
            .iter()
            .all(|case| case.status == CaseStatus::Passed);
    if (result.overall == OverallResult::Passed) != all_passed {
        return Err("overall result disagrees with required case evidence".to_owned());
    }
    let expected_release_qualified = result.overall == OverallResult::Passed
        && result.isolation == "strict_local"
        && !result
            .cases
            .iter()
            .any(|case| case.redacted_diagnostic.as_deref() == Some("isolation_unavailable"));
    if !matches!(
        result.isolation.as_str(),
        "strict_local" | "portable_local" | "remote_bounded"
    ) || result.release_qualified != expected_release_qualified
    {
        return Err("result contains an invalid isolation claim".to_owned());
    }
    Ok(())
}

struct PreparedTarget {
    target: AdapterTarget,
    build_digest: String,
    _temporary: Option<tempfile::TempDir>,
}

fn prepare_target(configuration: &RunConfiguration) -> Result<PreparedTarget, String> {
    match &configuration.target {
        AdapterTarget::Executable(path) | AdapterTarget::SdkAdapter(path) => {
            if configuration.remote_build_digest.is_some() {
                return Err("--build-digest is only valid for remote endpoints".to_owned());
            }
            let source = path
                .canonicalize()
                .map_err(|error| format!("cannot resolve implementation executable: {error}"))?;
            let metadata = fs::symlink_metadata(&source)
                .map_err(|error| format!("cannot inspect implementation executable: {error}"))?;
            if !metadata.file_type().is_file() || metadata.len() > 128 * 1024 * 1024 {
                return Err("implementation executable must be a bounded regular file".to_owned());
            }
            let file_name = source
                .file_name()
                .ok_or_else(|| "implementation executable has no file name".to_owned())?;
            let temporary = tempfile::Builder::new()
                .prefix("cigar-conformance-implementation-")
                .tempdir()
                .map_err(|error| format!("cannot create implementation snapshot: {error}"))?;
            let snapshot = temporary.path().join(file_name);
            fs::copy(&source, &snapshot)
                .map_err(|error| format!("cannot snapshot implementation executable: {error}"))?;
            let mut permissions = fs::metadata(&snapshot)
                .map_err(|error| format!("cannot inspect implementation snapshot: {error}"))?
                .permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&snapshot, permissions)
                .map_err(|error| format!("cannot protect implementation snapshot: {error}"))?;
            let build_digest = hash_file(&snapshot)?;
            let target = match &configuration.target {
                AdapterTarget::Executable(_) => AdapterTarget::Executable(snapshot),
                AdapterTarget::SdkAdapter(_) => AdapterTarget::SdkAdapter(snapshot),
                AdapterTarget::Http(_) | AdapterTarget::Unix(_) | AdapterTarget::Grpc(_) => {
                    return Err("local adapter target changed while preparing".to_owned());
                }
            };
            Ok(PreparedTarget {
                target,
                build_digest,
                _temporary: Some(temporary),
            })
        }
        AdapterTarget::Http(_) | AdapterTarget::Unix(_) | AdapterTarget::Grpc(_) => {
            let digest = configuration
                .remote_build_digest
                .as_deref()
                .ok_or_else(|| "remote endpoint requires --build-digest".to_owned())?;
            if !valid_sha256(digest) {
                return Err("remote build digest must be canonical SHA-256".to_owned());
            }
            Ok(PreparedTarget {
                target: configuration.target.clone(),
                build_digest: digest.to_owned(),
                _temporary: None,
            })
        }
    }
}

fn fresh_challenge(
    case_id: &str,
    runner_digest: &str,
    vector_digest: &str,
) -> Result<String, String> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| format!("cannot create conformance challenge: {error}"))?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"CIGAR-CONFORMANCE-CHALLENGE\0v1\0");
    frame(&mut bytes, case_id.as_bytes());
    frame(&mut bytes, runner_digest.as_bytes());
    frame(&mut bytes, vector_digest.as_bytes());
    frame(&mut bytes, &random);
    Ok(sha256(&bytes))
}

fn frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_adapter_response<'a>(
    bytes: &'a [u8],
    limits: &model::VectorLimits,
) -> Result<AdapterResponse, &'a str> {
    if bytes.len() > limits.max_response_bytes {
        return Err("output_limit");
    }
    let response: AdapterResponse =
        serde_json::from_slice(bytes).map_err(|_error| "malformed_response")?;
    if response.schema_version != "cigar.conformance.response.v1"
        || !valid_public_digest(&response.public_digest)
        || response.case_id.is_empty()
        || response.case_id.len() > 96
        || !valid_sha256(&response.challenge)
        || response.diagnostic.as_deref().is_some_and(|diagnostic| {
            diagnostic.len() > limits.max_diagnostic_bytes || !valid_diagnostic(diagnostic)
        })
    {
        return Err("malformed_response");
    }
    Ok(response)
}

fn valid_diagnostic(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn validate_implementation_name(value: &str) -> Result<(), String> {
    if valid_implementation_name(value) {
        Ok(())
    } else {
        Err("implementation name must be bounded printable ASCII".to_owned())
    }
}

fn valid_implementation_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

fn read_bounded_regular_file(path: &Path, bound: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect bounded file: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > bound {
        return Err("input must be a bounded regular file".to_owned());
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_error| "bounded input length overflow".to_owned())?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|file| file.take(bound.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read bounded file: {error}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err("bounded input changed while being read".to_owned());
    }
    Ok(bytes)
}

fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync artifact directory: {error}"))
}

/// Returns whether every claimed profile appears exactly once.
#[doc(hidden)]
#[must_use]
pub fn profiles_are_unique(profiles: &[String]) -> bool {
    profiles.iter().collect::<BTreeSet<_>>().len() == profiles.len()
}
