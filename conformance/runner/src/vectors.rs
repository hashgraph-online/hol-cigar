//! Immutable conformance vector loading and validation.

use crate::digest::valid_public_digest;
use crate::model::{AdapterRequest, VectorCase, VectorManifest};
use std::collections::{BTreeMap, BTreeSet};

const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const PROFILE_REGISTRY: &[&str] = &[
    "cigar-core-v1",
    "cigar-catalog-v1",
    "cigar-compiler-v1",
    "cigar-handoff-v1",
    "cigar-effect-v1",
    "cigar-replay-v1",
    "cigar-service-v1",
    "cigar-runtime-claude-code-v1",
];
const OPERATIONS: &[&str] = &[
    "canonicalize_json",
    "reject_json",
    "reject_cbor",
    "unsupported_domain",
    "public_error",
    "differential_records",
    "catalog_project_invalidation",
    "catalog_cycle_rejection",
    "compiler_deterministic_bundle",
    "compiler_budget_rejection",
    "handoff_signed_attenuation",
    "handoff_expiry_rejection",
    "effect_durable_dispatch",
    "effect_idempotency_collision",
    "replay_recorded_provider",
    "replay_request_mismatch",
    "service_cursor_roundtrip",
    "service_cursor_tamper",
    "claude_mcp_initialize",
    "claude_mcp_preinit_rejection",
];

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    fixture_id: String,
    semantic_version: String,
    source_revision: String,
    expected_snapshot_digest: String,
    fixed_time: String,
    id_seed: String,
    random_seed: u64,
    locale: String,
    timezone: String,
    unicode_form: String,
    permitted_atoms: Vec<String>,
    prohibited_atoms: Vec<String>,
    mandatory_atoms: Vec<String>,
    stale_atoms: Vec<String>,
    contradicted_atoms: Vec<String>,
    secret_canaries: Vec<String>,
    expected_reason_codes: Vec<String>,
    expected_external_calls: Vec<String>,
    minimum_implementation: String,
    compatibility_behavior: String,
    fingerprints: BTreeMap<String, String>,
    expected_digests: BTreeMap<String, String>,
    expected_tokens_by_materializer: BTreeMap<String, u64>,
}

/// Loads and validates a manifest from an already digest-bound vector snapshot.
pub fn load_vector_manifest_bytes(source: &[u8]) -> Result<VectorManifest, String> {
    if source.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("vector manifest exceeds the published size bound".to_owned());
    }
    let manifest: VectorManifest = serde_json::from_slice(source)
        .map_err(|error| format!("invalid vector manifest JSON: {error}"))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Validates the deterministic fixture metadata bound into the vector snapshot.
pub fn validate_fixture_manifest_bytes(
    source: &[u8],
    vectors: &VectorManifest,
) -> Result<(), String> {
    if source.len() > 64 * 1024 {
        return Err("fixture manifest exceeds the published size bound".to_owned());
    }
    let text = std::str::from_utf8(source)
        .map_err(|_error| "fixture manifest must be UTF-8".to_owned())?;
    let fixture: FixtureManifest =
        toml::from_str(text).map_err(|error| format!("invalid fixture manifest TOML: {error}"))?;
    if fixture.fixture_id != "cigar-v1-conformance"
        || fixture.semantic_version != "1.0.0"
        || fixture.source_revision != vectors.vector_set
        || fixture.expected_snapshot_digest != format!("sha256:{}", vectors.source_vector_sha256)
        || fixture.fixed_time != "2026-07-10T00:00:00Z"
        || !valid_name(&fixture.id_seed, 128)
        || fixture.random_seed == 0
        || fixture.locale != "C"
        || fixture.timezone != "UTC"
        || fixture.unicode_form != "NFC"
        || !fixture.expected_external_calls.is_empty()
        || fixture.minimum_implementation != "0.1.0"
        || fixture.compatibility_behavior.is_empty()
        || fixture.compatibility_behavior.len() > 512
    {
        return Err("fixture manifest identity or deterministic settings are invalid".to_owned());
    }
    for values in [
        &fixture.permitted_atoms,
        &fixture.prohibited_atoms,
        &fixture.mandatory_atoms,
        &fixture.stale_atoms,
        &fixture.contradicted_atoms,
        &fixture.secret_canaries,
        &fixture.expected_reason_codes,
    ] {
        if values.is_empty()
            || values.len() > 256
            || values.iter().any(|value| !valid_name(value, 128))
            || values.iter().collect::<BTreeSet<_>>().len() != values.len()
        {
            return Err("fixture manifest contains an invalid semantic set".to_owned());
        }
    }
    let required_fingerprints = BTreeSet::from([
        "schema",
        "tokenizer",
        "policy",
        "parser",
        "index",
        "compiler",
        "transform",
        "materializer",
    ]);
    if fixture
        .fingerprints
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != required_fingerprints
        || fixture
            .fingerprints
            .values()
            .any(|digest| !crate::digest::valid_sha256(digest))
    {
        return Err("fixture manifest fingerprint set is incomplete".to_owned());
    }
    let required_digests = BTreeSet::from([
        "bundle", "manifest", "delta", "handoff", "decision", "journal",
    ]);
    if fixture
        .expected_digests
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != required_digests
        || fixture
            .expected_digests
            .values()
            .any(|digest| !valid_public_digest(digest))
    {
        return Err("fixture manifest expected digest set is incomplete".to_owned());
    }
    let required_materializers = BTreeSet::from(["json", "markdown", "claude_mcp", "fact_set"]);
    if fixture
        .expected_tokens_by_materializer
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != required_materializers
        || fixture
            .expected_tokens_by_materializer
            .values()
            .any(|tokens| *tokens == 0 || *tokens > 1_000_000)
    {
        return Err("fixture manifest token expectations are incomplete".to_owned());
    }
    Ok(())
}

/// Validates closed selectors, uniqueness, bounds, and required-case coverage.
pub fn validate_manifest(manifest: &VectorManifest) -> Result<(), String> {
    if manifest.schema_version != "cigar.conformance.vectors.v1"
        || !valid_name(&manifest.vector_set, 128)
        || !valid_relative_path(&manifest.source_vector)
        || manifest.source_vector_sha256.len() != 64
        || !manifest
            .source_vector_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid vector manifest identity metadata".to_owned());
    }
    let limits = &manifest.limits;
    if limits.max_cases == 0
        || limits.max_cases > 10_000
        || manifest.cases.is_empty()
        || manifest.cases.len() > limits.max_cases
        || limits.max_request_bytes == 0
        || limits.max_request_bytes > 4 * 1024 * 1024
        || limits.max_response_bytes == 0
        || limits.max_response_bytes > 1024 * 1024
        || limits.max_diagnostic_bytes > 4096
        || limits.max_case_timeout_ms == 0
        || limits.max_case_timeout_ms > 60_000
        || limits.max_total_timeout_ms == 0
        || limits.max_total_timeout_ms > 3_600_000
        || limits.max_memory_bytes < 32 * 1024 * 1024
        || limits.max_memory_bytes > 4 * 1024 * 1024 * 1024
        || limits.max_file_bytes == 0
        || limits.max_file_bytes > 64 * 1024 * 1024
        || limits.max_processes == 0
        || limits.max_processes > 256
    {
        return Err("invalid vector resource limits".to_owned());
    }

    let registry: BTreeSet<&str> = PROFILE_REGISTRY.iter().copied().collect();
    let mut profiles = BTreeSet::new();
    for profile in &manifest.profiles {
        if !registry.contains(profile.as_str()) || !profiles.insert(profile.as_str()) {
            return Err(format!("unknown or duplicate profile `{profile}`"));
        }
    }
    if profiles.is_empty() {
        return Err("vector set must expose at least one profile".to_owned());
    }

    let operations: BTreeSet<&str> = OPERATIONS.iter().copied().collect();
    let mut case_ids = BTreeSet::new();
    let mut required_by_profile = BTreeMap::<&str, usize>::new();
    let mut timeout_sum = 0_u64;
    for case in &manifest.cases {
        if !valid_case_id(&case.id)
            || !case_ids.insert(case.id.as_str())
            || !profiles.contains(case.profile.as_str())
            || !operations.contains(case.operation.as_str())
            || case.timeout_ms == 0
            || case.timeout_ms > limits.max_case_timeout_ms
            || !valid_public_digest(&case.expected.public_digest)
        {
            return Err(format!("invalid conformance case `{}`", case.id));
        }
        timeout_sum = timeout_sum
            .checked_add(case.timeout_ms)
            .ok_or_else(|| "case timeout sum overflowed".to_owned())?;
        if case.required {
            let count = required_by_profile.entry(&case.profile).or_default();
            *count = count.saturating_add(1);
        }
        let challenge = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let request = request_for_case(case, challenge);
        let size = serde_json::to_vec(&request)
            .map_err(|error| format!("cannot size conformance case: {error}"))?
            .len();
        if size > limits.max_request_bytes {
            return Err(format!(
                "conformance case `{}` exceeds request bound",
                case.id
            ));
        }
    }
    if timeout_sum > limits.max_total_timeout_ms {
        return Err("case timeout sum exceeds vector-set bound".to_owned());
    }
    for profile in profiles {
        if required_by_profile
            .get(profile)
            .copied()
            .unwrap_or_default()
            == 0
        {
            return Err(format!("profile `{profile}` has no required cases"));
        }
    }
    Ok(())
}

/// Selects every case for the claimed profiles in manifest order.
pub fn selected_cases<'a>(
    manifest: &'a VectorManifest,
    claimed_profiles: &[String],
) -> Result<Vec<&'a VectorCase>, String> {
    if claimed_profiles.is_empty() {
        return Err("at least one --profile is required".to_owned());
    }
    let available: BTreeSet<&str> = manifest.profiles.iter().map(String::as_str).collect();
    let mut claimed = BTreeSet::new();
    for profile in claimed_profiles {
        if !available.contains(profile.as_str()) {
            return Err(format!(
                "profile `{profile}` has no executable required vector set"
            ));
        }
        if !claimed.insert(profile.as_str()) {
            return Err(format!("profile `{profile}` was claimed more than once"));
        }
    }
    let cases: Vec<_> = manifest
        .cases
        .iter()
        .filter(|case| claimed.contains(case.profile.as_str()))
        .collect();
    if cases.is_empty() {
        return Err("claimed profiles selected no cases".to_owned());
    }
    Ok(cases)
}

/// Builds a request without exposing its expected answer.
#[must_use]
pub fn request_for_case(case: &VectorCase, challenge: &str) -> AdapterRequest {
    AdapterRequest {
        schema_version: "cigar.conformance.request.v1".to_owned(),
        case_id: case.id.clone(),
        profile: case.profile.clone(),
        operation: case.operation.clone(),
        challenge: challenge.to_owned(),
        input: case.input.clone(),
    }
}

fn valid_case_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && value.split(['/', '\\']).all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}
