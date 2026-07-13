//! Independent Rust and SDK reproduction of the retained replay vector.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FIXTURE_BYTES: usize = 1_048_576;
const MAX_RETAINED_BYTES: usize = 1_048_576;
const MAX_ENCODED_RETAINED_BYTES: usize = 1_398_104;
const MAX_ARTIFACTS: usize = 64;
const MAX_OBSERVATIONS: usize = 1_024;
const DEPENDENCY_ORDER: [&str; 11] = [
    "source",
    "blob",
    "policy",
    "index",
    "manifest",
    "bundle",
    "tokenizer",
    "adapter",
    "consumer",
    "tool_schema",
    "environment",
];
const EXPECTED_STABLE_OUTPUT: &str = concat!(
    "{\"schema_version\":\"cigar.replay-reproduction-result.v1\",",
    "\"bundle_digest_multihash\":\"1220aaac06a3388202a1de76e7681595326f93cf694741d54b5b5658cd4e5721200e\",",
    "\"invocation_digest_multihash\":\"1220427dbdc6bd7bae9a33dd4e9230fa4d55a566b903c953982dfce9b7aa490de82c\",",
    "\"observation_digest_multihash\":\"12208d4c87c7ff3cc4b832eb8ecb94a1182ac92fcb509a70c50efc614e8bbc574607\",",
    "\"complete\":true,\"missing_dependencies\":[],",
    "\"missing_artifact_probe\":{\"complete\":false,\"missing_dependencies\":[\"source\"]},",
    "\"tampered_artifact_probe\":{\"accepted\":false,\"missing_dependencies\":[\"consumer\"]},",
    "\"empty_recorded_response_probe\":{\"accepted\":true,",
    "\"digest_multihash\":\"1220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}}\n"
);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayVector {
    schema_version: String,
    digest_algorithm: String,
    observation_framing: String,
    retained: RetainedBytes,
    required_dependencies: Vec<String>,
    retained_artifacts: Vec<RetainedArtifact>,
    missing_artifact_probe: MissingArtifactProbe,
    tampered_artifact_probe: TamperedArtifactProbe,
    empty_recorded_response_probe: EmptyRecordedResponseProbe,
    expected: ExpectedResult,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedBytes {
    bundle_bytes_base64url: String,
    invocation_bytes_base64url: String,
    recorded_observation_bytes_base64url: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedArtifact {
    kind: String,
    bytes_base64url: String,
    digest_multihash: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MissingArtifactProbe {
    kind: String,
    expected_complete: bool,
    expected_missing_dependencies: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TamperedArtifactProbe {
    kind: String,
    replacement_bytes_base64url: String,
    expected_accepted: bool,
    expected_missing_dependencies: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRecordedResponseProbe {
    bytes_base64url: String,
    digest_multihash: String,
    expected_accepted: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedResult {
    bundle_digest_multihash: String,
    invocation_digest_multihash: String,
    observation_digest_multihash: String,
    complete: bool,
    missing_dependencies: Vec<String>,
}

#[derive(Serialize)]
struct ReproductionResult<'a> {
    schema_version: &'static str,
    bundle_digest_multihash: &'a str,
    invocation_digest_multihash: &'a str,
    observation_digest_multihash: &'a str,
    complete: bool,
    missing_dependencies: &'a [String],
    missing_artifact_probe: CompletenessProbe<'a>,
    tampered_artifact_probe: TamperProbe<'a>,
    empty_recorded_response_probe: EmptyResponseProbe<'a>,
}

#[derive(Serialize)]
struct CompletenessProbe<'a> {
    complete: bool,
    missing_dependencies: &'a [String],
}

#[derive(Serialize)]
struct TamperProbe<'a> {
    accepted: bool,
    missing_dependencies: &'a [String],
}

#[derive(Serialize)]
struct EmptyResponseProbe<'a> {
    accepted: bool,
    digest_multihash: &'a str,
}

struct ArtifactVerification {
    verified_bytes: BTreeMap<String, Vec<u8>>,
    missing: Vec<String>,
}

#[test]
fn rust_and_every_sdk_reproduce_exact_replay_vector() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let fixture_path = root.join("schemas/vectors/replay-v1.json");
    let fixture = load_fixture(&fixture_path)?;
    let rust_output = reproduce(&fixture)?;
    if rust_output != EXPECTED_STABLE_OUTPUT {
        return Err(invalid(format!(
            "Rust replay output differs from the stable vector: {rust_output:?}"
        )));
    }

    let node = node_command(&root, &fixture_path).output()?;
    require_identical("TypeScript", &node, rust_output.as_bytes())?;

    let python = python_command(&root, &fixture_path).output()?;
    require_identical("Python", &python, rust_output.as_bytes())?;

    let go = go_command(&root, &fixture_path).output()?;
    require_identical("Go", &go, rust_output.as_bytes())?;
    Ok(())
}

#[test]
fn duplicate_json_keys_are_rejected_by_every_sdk() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let fixture_path = root.join("schemas/vectors/replay-v1.json");
    let source = std::fs::read_to_string(&fixture_path)?;
    let duplicate = source.replacen(
        "\"schema_version\":",
        "\"schema_version\":\"forged\",\"schema_version\":",
        1,
    );
    if duplicate == source {
        return Err(invalid("failed to construct duplicate-key replay probe"));
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let probe_path = std::env::temp_dir().join(format!(
        "cigar-replay-duplicate-{}-{nonce}.json",
        std::process::id()
    ));
    std::fs::write(&probe_path, duplicate)?;

    let rust_accepted = load_fixture(&probe_path).is_ok();
    let node = node_command(&root, &probe_path).output()?;
    let python = python_command(&root, &probe_path).output()?;
    let go = go_command(&root, &probe_path).output()?;
    std::fs::remove_file(&probe_path)?;

    if rust_accepted {
        return Err(invalid("Rust accepted a duplicate JSON object key"));
    }
    require_rejected("TypeScript", &node)?;
    require_rejected("Python", &python)?;
    require_rejected("Go", &go)?;
    Ok(())
}

fn node_command(root: &Path, fixture: &Path) -> Command {
    let mut command = Command::new("node");
    command
        .arg(root.join("sdk/typescript/src/verify-replay.ts"))
        .arg(fixture)
        .current_dir(root);
    command
}

fn python_command(root: &Path, fixture: &Path) -> Command {
    let mut command = Command::new("python3");
    command
        .arg("-m")
        .arg("cigar_sdk.verify_replay")
        .arg(fixture)
        .env("PYTHONPATH", root.join("sdk/python/src"))
        .current_dir(root);
    command
}

fn go_command(root: &Path, fixture: &Path) -> Command {
    let mut command = Command::new("go");
    command
        .arg("-C")
        .arg(root.join("sdk/go"))
        .arg("run")
        .arg("./cmd/cigar-verify-replay")
        .arg(fixture)
        .current_dir(root);
    command
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .to_path_buf()
}

fn load_fixture(path: &Path) -> Result<ReplayVector, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut source = Vec::new();
    file.take(u64::try_from(MAX_FIXTURE_BYTES)?.saturating_add(1))
        .read_to_end(&mut source)?;
    if source.is_empty() || source.len() > MAX_FIXTURE_BYTES {
        return Err(invalid("replay fixture is empty or exceeds its bound"));
    }

    let mut duplicate_parser = serde_json::Deserializer::from_slice(&source);
    RejectDuplicateKeys::deserialize(&mut duplicate_parser)?;
    duplicate_parser.end()?;
    serde_json::from_slice(&source).map_err(Into::into)
}

fn reproduce(fixture: &ReplayVector) -> Result<String, Box<dyn Error>> {
    if fixture.schema_version != "cigar.replay-vector.v1"
        || fixture.digest_algorithm != "sha256-multihash-raw-v1"
        || fixture.observation_framing != "u32be-length-prefixed-v1"
    {
        return Err(invalid("replay fixture declares an unsupported profile"));
    }
    if !fixture
        .required_dependencies
        .iter()
        .map(String::as_str)
        .eq(DEPENDENCY_ORDER)
    {
        return Err(invalid("required dependency order differs"));
    }

    let bundle = decode_base64url(&fixture.retained.bundle_bytes_base64url, false)?;
    let invocation = decode_base64url(&fixture.retained.invocation_bytes_base64url, false)?;
    if fixture
        .retained
        .recorded_observation_bytes_base64url
        .is_empty()
        || fixture.retained.recorded_observation_bytes_base64url.len() > MAX_OBSERVATIONS
    {
        return Err(invalid(
            "recorded observations must be non-empty and bounded",
        ));
    }
    let observations = fixture
        .retained
        .recorded_observation_bytes_base64url
        .iter()
        .map(|encoded| decode_base64url(encoded, true))
        .collect::<Result<Vec<_>, _>>()?;

    let bundle_digest = multihash(&bundle)?;
    let invocation_digest = multihash(&invocation)?;
    let observation_digest = observation_multihash(&observations)?;
    for digest in [
        &fixture.expected.bundle_digest_multihash,
        &fixture.expected.invocation_digest_multihash,
        &fixture.expected.observation_digest_multihash,
    ] {
        verify_multihash(digest)?;
    }
    if bundle_digest != fixture.expected.bundle_digest_multihash
        || invocation_digest != fixture.expected.invocation_digest_multihash
        || observation_digest != fixture.expected.observation_digest_multihash
    {
        return Err(invalid("retained replay digest mismatch"));
    }

    let artifacts = verify_artifacts(&fixture.required_dependencies, &fixture.retained_artifacts)?;
    let complete = artifacts.missing.is_empty();
    if complete != fixture.expected.complete
        || artifacts.missing != fixture.expected.missing_dependencies
    {
        return Err(invalid("artifact-derived replay completeness differs"));
    }
    let artifact_bundle = artifacts
        .verified_bytes
        .get("bundle")
        .ok_or_else(|| invalid("verified bundle artifact is missing"))?;
    if artifact_bundle != &bundle {
        return Err(invalid(
            "retained bundle and bundle dependency artifact differ",
        ));
    }

    let missing_probe = &fixture.missing_artifact_probe;
    if !fixture.required_dependencies.contains(&missing_probe.kind) {
        return Err(invalid(
            "missing artifact probe names an unknown dependency",
        ));
    }
    let without_artifact = fixture
        .retained_artifacts
        .iter()
        .filter(|artifact| artifact.kind != missing_probe.kind)
        .cloned()
        .collect::<Vec<_>>();
    let missing_verification = verify_artifacts(&fixture.required_dependencies, &without_artifact)?;
    let missing_complete = missing_verification.missing.is_empty();
    if missing_complete != missing_probe.expected_complete
        || missing_verification.missing != missing_probe.expected_missing_dependencies
    {
        return Err(invalid("missing artifact probe differs"));
    }

    let tamper_probe = &fixture.tampered_artifact_probe;
    if !fixture.required_dependencies.contains(&tamper_probe.kind) {
        return Err(invalid(
            "tampered artifact probe names an unknown dependency",
        ));
    }
    let mut tampered_artifacts = fixture.retained_artifacts.clone();
    let mut replacement_count = 0_u8;
    for artifact in &mut tampered_artifacts {
        if artifact.kind == tamper_probe.kind {
            artifact.bytes_base64url = tamper_probe.replacement_bytes_base64url.clone();
            replacement_count = replacement_count.saturating_add(1);
        }
    }
    if replacement_count != 1 {
        return Err(invalid(
            "tampered artifact probe must identify exactly one artifact",
        ));
    }
    let tampered_verification =
        verify_artifacts(&fixture.required_dependencies, &tampered_artifacts)?;
    let tamper_accepted = tampered_verification.missing.is_empty();
    if tamper_accepted != tamper_probe.expected_accepted
        || tampered_verification.missing != tamper_probe.expected_missing_dependencies
    {
        return Err(invalid("tampered artifact probe differs"));
    }

    let empty_probe = &fixture.empty_recorded_response_probe;
    let empty_response = decode_base64url(&empty_probe.bytes_base64url, true)?;
    verify_multihash(&empty_probe.digest_multihash)?;
    let empty_digest = multihash(&empty_response)?;
    let empty_accepted = empty_response.is_empty() && empty_digest == empty_probe.digest_multihash;
    if empty_accepted != empty_probe.expected_accepted {
        return Err(invalid("empty recorded response probe differs"));
    }

    let result = ReproductionResult {
        schema_version: "cigar.replay-reproduction-result.v1",
        bundle_digest_multihash: &bundle_digest,
        invocation_digest_multihash: &invocation_digest,
        observation_digest_multihash: &observation_digest,
        complete,
        missing_dependencies: &artifacts.missing,
        missing_artifact_probe: CompletenessProbe {
            complete: missing_complete,
            missing_dependencies: &missing_verification.missing,
        },
        tampered_artifact_probe: TamperProbe {
            accepted: tamper_accepted,
            missing_dependencies: &tampered_verification.missing,
        },
        empty_recorded_response_probe: EmptyResponseProbe {
            accepted: empty_accepted,
            digest_multihash: &empty_digest,
        },
    };
    let mut encoded = serde_json::to_string(&result)?;
    encoded.push('\n');
    Ok(encoded)
}

fn verify_artifacts(
    required: &[String],
    artifacts: &[RetainedArtifact],
) -> Result<ArtifactVerification, Box<dyn Error>> {
    if artifacts.len() > MAX_ARTIFACTS {
        return Err(invalid("retained artifact table exceeds its bound"));
    }
    let mut seen = BTreeSet::new();
    let mut verified_bytes = BTreeMap::new();
    for artifact in artifacts {
        if !required.contains(&artifact.kind) || !seen.insert(artifact.kind.clone()) {
            return Err(invalid("retained artifact kind is unknown or duplicated"));
        }
        verify_multihash(&artifact.digest_multihash)?;
        let bytes = decode_base64url(&artifact.bytes_base64url, false)?;
        if multihash(&bytes)? == artifact.digest_multihash {
            verified_bytes.insert(artifact.kind.clone(), bytes);
        }
    }
    let missing = required
        .iter()
        .filter(|kind| !verified_bytes.contains_key(*kind))
        .cloned()
        .collect();
    Ok(ArtifactVerification {
        verified_bytes,
        missing,
    })
}

fn decode_base64url(input: &str, allow_empty: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    if input.is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(invalid("retained bytes must not be empty"))
        };
    }
    if input.len() > MAX_ENCODED_RETAINED_BYTES || input.len() % 4 == 1 {
        return Err(invalid("retained bytes are invalid or unbounded base64url"));
    }
    let mut output = Vec::with_capacity(input.len().saturating_mul(3) / 4);
    for chunk in input.as_bytes().chunks(4) {
        let values = chunk
            .iter()
            .copied()
            .map(base64_value)
            .collect::<Result<Vec<_>, _>>()?;
        match values.as_slice() {
            [a, b, c, d] => {
                output.push((a << 2) | (b >> 4));
                output.push(((b & 0x0f) << 4) | (c >> 2));
                output.push(((c & 0x03) << 6) | d);
            }
            [a, b, c] if c & 0x03 == 0 => {
                output.push((a << 2) | (b >> 4));
                output.push(((b & 0x0f) << 4) | (c >> 2));
            }
            [a, b] if b & 0x0f == 0 => output.push((a << 2) | (b >> 4)),
            _ => return Err(invalid("retained bytes use non-canonical base64url")),
        }
    }
    if output.len() > MAX_RETAINED_BYTES {
        return Err(invalid("decoded retained bytes exceed their bound"));
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, Box<dyn Error>> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(invalid("retained bytes contain a non-base64url character")),
    }
}

fn multihash(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn observation_multihash(observations: &[Vec<u8>]) -> Result<String, Box<dyn Error>> {
    let mut hash = Sha256::new();
    for observation in observations {
        let length = u32::try_from(observation.len())?;
        hash.update(length.to_be_bytes());
        hash.update(observation);
    }
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash.finalize() {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn verify_multihash(value: &str) -> Result<(), Box<dyn Error>> {
    if value.len() != 68
        || !value.starts_with("1220")
        || !value
            .bytes()
            .skip(4)
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(
            "expected digest is not a lowercase SHA-256 multihash",
        ));
    }
    Ok(())
}

fn require_identical(
    runtime: &str,
    output: &Output,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    if !output.status.success() {
        return Err(invalid(format!(
            "{runtime} replay verifier failed: status={}; stdout={:?}; stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    if output.stdout != expected {
        return Err(invalid(format!(
            "{runtime} replay output differs: {:?}",
            String::from_utf8_lossy(&output.stdout)
        )));
    }
    Ok(())
}

fn require_rejected(runtime: &str, output: &Output) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        return Err(invalid(format!(
            "{runtime} accepted a duplicate JSON object key"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

struct RejectDuplicateKeys;

impl<'de> Deserialize<'de> for RejectDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = RejectDuplicateKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RejectDuplicateKeys)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<RejectDuplicateKeys>()?.is_some() {}
        Ok(RejectDuplicateKeys)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<RejectDuplicateKeys>()?;
        }
        Ok(RejectDuplicateKeys)
    }
}
