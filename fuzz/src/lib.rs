//! Shared bounded entry points for the CIGAR release fuzz targets.

use cigar_canon::{
    from_deterministic_cbor, parse_strict_json, to_deterministic_cbor, to_normalized_json,
};
use cigar_catalog::{ProjectIdentity, ProjectIdentityInput};
use cigar_code_intel::{BuiltinLanguageAdapter, LanguageAdapter, ParseRequest};
use cigar_compiler::{
    BlockBodies, ByteTokenizer, CompileRequest, CompilerProfile, DeterministicCompiler,
    FrozenInputs, MaterializerProfile, apply_delta, compiler_profile_digest, generate_delta,
    materialize,
};
use cigar_effects::{EffectCrashPoint, EffectFaultModel, FaultSnapshot};
use cigar_extension_host::FrameCodec;
use cigar_mcp::{
    Backend, BackendError, BackendRequest, BackendResponse, MAX_REQUEST_BYTES, Server,
};
use cigar_policy::CompiledPolicyEngine;
use cigar_protocol::{
    ContextAtomV1, ContextBlock, ContextBundle, ContextContract, ContextDelta, ContextPlan,
    DecisionRecord, EffectIntent, EffectJournalEvent, ExtensionInvocationV1, ExtensionManifestV1,
    ExtensionMap, ExtensionResponseV1, HandoffAcceptance, HandoffCapsule, HealthReport, LaneKind,
    MaterializedContext, Problem, RecordId, RelativePath, ReplayRequest, RepresentationKind,
    SchemaVersion, SelectionManifest, SourceSnapshot, SourceUri, UtcTimestamp, Validate, VersionId,
};
use cigar_replay::framed_observation_digest;
use cigar_store::CancellationToken;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FUZZ_INPUT: usize = 1_048_576;
const MAX_PARSER_INPUT: usize = 65_536;
const ERROR_REFLECTION_CANARY: &[u8] = b"CIGAR_WP19_ERROR_REFLECTION_CANARY";

/// Exercises strict JSON and deterministic CBOR as an idempotent, stable round trip.
pub fn canonical_json_cbor(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let Ok(node) = parse_strict_json(data) else {
        return;
    };
    let normalized = to_normalized_json(&node).expect("a parsed JSON node must normalize");
    let reparsed = parse_strict_json(&normalized).expect("normalized JSON must parse strictly");
    assert_eq!(node, reparsed);
    let cbor = to_deterministic_cbor(&node).expect("a parsed JSON node must encode as CBOR");
    let decoded = from_deterministic_cbor(&cbor).expect("deterministic CBOR must decode");
    assert_eq!(node, decoded);
    assert_eq!(
        cbor,
        to_deterministic_cbor(&decoded).expect("decoded CBOR must re-encode")
    );
}

/// Routes arbitrary strict JSON through representative records from every public domain family.
pub fn public_record_decoders(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_FUZZ_INPUT) else {
        return;
    };
    match selector % 12 {
        0 => strict_validate::<ContextAtomV1>(body),
        1 => strict_validate::<SourceSnapshot>(body),
        2 => strict_validate::<ContextContract>(body),
        3 => strict_validate::<ContextPlan>(body),
        4 => strict_validate::<ContextBundle>(body),
        5 => strict_validate::<SelectionManifest>(body),
        6 => strict_validate::<HandoffCapsule>(body),
        7 => strict_validate::<EffectIntent>(body),
        8 => strict_validate::<DecisionRecord>(body),
        9 => strict_validate::<ExtensionManifestV1>(body),
        10 => strict_validate::<Problem>(body),
        _ => strict_validate::<HealthReport>(body),
    }
}

/// Exercises URI/path validation and stable credential-free project identities.
pub fn identity_normalization(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let text = String::from_utf8_lossy(data);
    let _uri = SourceUri::new(text.as_ref());
    let _path = RelativePath::new(data.to_vec());
    let input = ProjectIdentityInput {
        tenant_id: fixed_record(1),
        git_remote: Some(text.into_owned()),
        root_lineage_id: fixed_record(2),
        disambiguator: "fuzz-worktree".to_owned(),
    };
    let first = ProjectIdentity::derive(input.clone());
    let second = ProjectIdentity::derive(input);
    assert_eq!(first, second);
    if let Ok(identity) = first {
        if let Some(remote) = identity.normalized_remote() {
            assert!(!authority_contains_credentials(remote));
        }
    }
}

/// Exercises bounded policy JSON/TOML parsing and atomic duplicate-revision rejection.
pub fn policy_parse_evaluate(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let activated_at = fixed_time(1_700_000_000_000_000_000);
    let json_engine = CompiledPolicyEngine::default();
    if json_engine.install_json(data, activated_at).is_ok() {
        assert!(json_engine.install_json(data, activated_at).is_err());
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let toml_engine = CompiledPolicyEngine::default();
        if toml_engine.install_toml(text, activated_at).is_ok() {
            assert!(toml_engine.install_toml(text, activated_at).is_err());
        }
    }
}

/// Exercises contract normalization and the deterministic compiler with an empty candidate set.
pub fn contract_compiler_candidates(data: &[u8]) {
    let Some(contract) = strict_decode::<ContextContract>(data) else {
        return;
    };
    if contract.validate().is_err() {
        return;
    }
    let profile = CompilerProfile::default();
    let Ok(profile_digest) = compiler_profile_digest(&profile) else {
        return;
    };
    let fixed = fixed_digest(b"compiler-fuzz-pin");
    let request = CompileRequest {
        frozen: FrozenInputs {
            catalog_watermark: fixed.clone(),
            graph_revision: fixed.clone(),
            policy_digest: fixed.clone(),
            index_fingerprints: BTreeSet::from([fixed.clone()]),
            retrieval_plan_digest: fixed,
            compiler_profile_digest: profile_digest,
            tokenizer_fingerprint: contract.target.tokenizer_fingerprint.clone(),
            materializer_fingerprint: contract.target.materializer_fingerprint.clone(),
        },
        contract,
        profile,
        candidates: Vec::new(),
    };
    let first = DeterministicCompiler.compile(request.clone());
    let second = DeterministicCompiler.compile(request);
    assert_eq!(first, second);
}

/// Builds valid arbitrary bundles and proves generated deltas reproduce the exact target.
pub fn delta_roundtrip(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let split = data.len() / 2;
    let shared = data.get(..split).unwrap_or_default();
    let added = data.get(split..).unwrap_or_default();
    let base = bundle_from_bodies(b"base", &[nonempty(shared)]);
    let target = bundle_from_bodies(b"target", &[nonempty(shared), nonempty(added)]);
    if let Ok(sealed) = generate_delta(&base, &target) {
        let applied = apply_delta(&base, &target, &sealed).expect("generated delta must apply");
        assert_eq!(applied, target);
    }
}

/// Exercises manifest/delta/materialized decoders without reflecting protected input in errors.
pub fn manifest_explanation_redaction(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_FUZZ_INPUT) else {
        return;
    };
    match selector % 3 {
        0 => strict_validate_no_reflection::<SelectionManifest>(body),
        1 => strict_validate_no_reflection::<ContextDelta>(body),
        _ => strict_validate_no_reflection::<MaterializedContext>(body),
    }
}

/// Exercises handoff and acceptance decoding plus structural capability attenuation.
pub fn handoff_accept_merge(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    let split = data.len() / 2;
    let capsule = data
        .get(..split)
        .and_then(strict_decode::<HandoffCapsule>);
    let acceptance = data
        .get(split..)
        .and_then(strict_decode::<HandoffAcceptance>);
    if let Some(capsule) = capsule {
        let _capsule_validation = capsule.validate();
        if let Some(acceptance) = acceptance {
            let _acceptance_validation = acceptance.validate();
            let _attenuation = acceptance.validate_against(&capsule);
        }
    }
}

/// Exercises all materializers at arbitrary byte/token boundaries over valid exact bundles.
pub fn materializer_budget(data: &[u8]) {
    let Some(data) = bounded(data, MAX_PARSER_INPUT) else {
        return;
    };
    let body = nonempty(data);
    let bundle = bundle_from_bodies(b"materialize", &[body]);
    let block = bundle.blocks.first().expect("generated bundle has one block");
    let mut bodies = BlockBodies::new();
    bodies.insert(block.block_id.clone(), body.to_vec());
    let tokenizer = ByteTokenizer::new(fixed_digest(b"byte-tokenizer"));
    for profile in [
        MaterializerProfile::Json,
        MaterializerProfile::Markdown,
        MaterializerProfile::FactSet,
        MaterializerProfile::ClaudePrompt,
        MaterializerProfile::McpResource,
    ] {
        if let Ok((rendered, accounting)) = materialize(profile, &bundle, &bodies, &tokenizer) {
            assert_eq!(rendered.token_count as usize, rendered.bytes.len());
            assert_eq!(accounting.physical_input_tokens, rendered.token_count);
            assert!(rendered.validate().is_ok());
        }
    }
}

/// Exercises every effect crash row, durable snapshot decoding, and damaged-journal input.
pub fn effect_journal_recovery(data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default() as usize;
    let point = EffectCrashPoint::ALL[selector % EffectCrashPoint::ALL.len()];
    let mut seed_bytes = [0_u8; 8];
    for (target, source) in seed_bytes.iter_mut().zip(data.iter().copied().skip(1)) {
        *target = source;
    }
    let seed = u64::from_le_bytes(seed_bytes);
    let snapshot = EffectFaultModel::inject(point, seed);
    let encoded = snapshot.to_json().expect("fault snapshot must serialize");
    let decoded = FaultSnapshot::from_json(&encoded).expect("fault snapshot must decode");
    decoded
        .recover()
        .verify()
        .expect("reference recovery invariants must hold");
    strict_validate::<EffectJournalEvent>(data);
    if let Ok(candidate) = FaultSnapshot::from_json(data) {
        let _verification = candidate.recover().verify();
    }
}

/// Exercises replay requests/records and bounded observation framing.
pub fn replay_envelopes(data: &[u8]) {
    let Some(data) = bounded(data, MAX_FUZZ_INPUT) else {
        return;
    };
    strict_validate::<ReplayRequest>(data);
    strict_validate::<DecisionRecord>(data);
    let midpoint = data.len() / 2;
    let observations = vec![
        data.get(..midpoint).unwrap_or_default().to_vec(),
        data.get(midpoint..).unwrap_or_default().to_vec(),
    ];
    let first = framed_observation_digest(&observations);
    let second = framed_observation_digest(&observations);
    assert_eq!(first, second);
}

/// Exercises strict extension manifests and canonical length-delimited ABI frames.
pub fn extension_frames(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_FUZZ_INPUT) else {
        return;
    };
    strict_validate::<ExtensionManifestV1>(body);
    let codec = FrameCodec::new(MAX_FUZZ_INPUT).expect("valid frame limit");
    if selector & 1 == 0 {
        let _invocation = codec.decode::<ExtensionInvocationV1>(body);
    } else {
        let _response = codec.decode::<ExtensionResponseV1>(body);
    }
}

/// Exercises strict MCP parsing/state transitions over a backend that cannot perform I/O.
pub fn mcp_messages(data: &[u8]) {
    let Some(data) = bounded(data, MAX_REQUEST_BYTES) else {
        return;
    };
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let mut server = Server::new(DenyBackend);
    if let Some(response) = server.process_line(line) {
        assert!(response.len() <= MAX_REQUEST_BYTES.saturating_mul(4));
        let _: serde_json::Value = serde_json::from_str(&response)
            .expect("every MCP response must be valid JSON");
    }
}

/// Exercises every built-in Tree-sitter parser on bounded arbitrary source bytes.
pub fn builtin_source_parsers(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Some(body) = bounded(body, MAX_PARSER_INPUT) else {
        return;
    };
    let adapters = BuiltinLanguageAdapter::required_v1();
    let adapter = &adapters[usize::from(selector) % adapters.len()];
    let extension = adapter
        .descriptor()
        .extensions
        .into_iter()
        .next()
        .unwrap_or_else(|| "txt".to_owned());
    let path = RelativePath::new(format!("fuzz.{extension}").into_bytes())
        .expect("fixed relative path must validate");
    let request = ParseRequest {
        path: &path,
        bytes: nonempty(body),
        previous: None,
    };
    let cancellation = CancellationToken::default();
    let first = adapter.parse(request, &cancellation);
    let second = adapter.parse(request, &cancellation);
    assert_eq!(first, second);
    if let Ok(parsed) = first {
        assert!(parsed.validate(nonempty(body).len()).is_ok());
    }
}

fn strict_validate<T>(data: &[u8])
where
    T: DeserializeOwned + Validate,
{
    if let Some(value) = strict_decode::<T>(data) {
        let _validation = value.validate();
    }
}

fn strict_validate_no_reflection<T>(data: &[u8])
where
    T: DeserializeOwned + Validate,
{
    if let Some(value) = strict_decode::<T>(data)
        && let Err(error) = value.validate()
    {
        let rendered = format!("{error:?}");
        if contains(data, ERROR_REFLECTION_CANARY) {
            assert!(!rendered.as_bytes().windows(ERROR_REFLECTION_CANARY.len()).any(|window| {
                window == ERROR_REFLECTION_CANARY
            }));
        }
    }
}

fn strict_decode<T: DeserializeOwned>(data: &[u8]) -> Option<T> {
    let data = bounded(data, MAX_FUZZ_INPUT)?;
    let node = parse_strict_json(data).ok()?;
    let normalized = to_normalized_json(&node).ok()?;
    serde_json::from_slice(&normalized).ok()
}

fn bounded(data: &[u8], maximum: usize) -> Option<&[u8]> {
    (data.len() <= maximum).then_some(data)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn authority_contains_credentials(remote: &str) -> bool {
    remote
        .split_once("://")
        .map(|(_scheme, remainder)| remainder.split('/').next().unwrap_or_default())
        .is_some_and(|authority| authority.contains('@'))
}

fn nonempty(data: &[u8]) -> &[u8] {
    if data.is_empty() { b"x" } else { data }
}

fn fixed_record(last: u16) -> RecordId {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f{last:04x}"))
        .expect("fixed UUIDv7-shaped record identifier")
}

fn fixed_time(nanos: i128) -> UtcTimestamp {
    UtcTimestamp::from_unix_nanos(nanos).expect("fixed timestamp")
}

fn fixed_digest(bytes: &[u8]) -> cigar_protocol::ContentDigest {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    cigar_protocol::ContentDigest::new(format!("1220{suffix}"))
        .expect("SHA-256 multihash")
}

fn fixed_version(bytes: &[u8]) -> VersionId {
    VersionId::new(fixed_digest(bytes).as_str().to_owned()).expect("SHA-256 version identifier")
}

fn bundle_from_bodies(seed: &[u8], bodies: &[&[u8]]) -> ContextBundle {
    let mut unique = BTreeMap::<VersionId, ContextBlock>::new();
    for (index, body) in bodies.iter().enumerate() {
        let mut identity = Vec::from(*body);
        identity.extend_from_slice(&index.to_le_bytes());
        let block_id = fixed_version(&identity);
        unique.insert(
            block_id.clone(),
            ContextBlock {
                block_id,
                lane: LaneKind::Evidence,
                representation: RepresentationKind::Exact,
                content_digest: fixed_digest(body),
                token_count: u32::try_from(body.len()).expect("bounded fuzz body length"),
                provenance: vec![fixed_version(b"fuzz-provenance")],
                transform_receipt: None,
            },
        );
    }
    let blocks: Vec<_> = unique.into_values().collect();
    let total_tokens = blocks.iter().map(|block| block.token_count).sum();
    ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)
            .expect("fixed schema version"),
        bundle_id: fixed_version(seed),
        contract_digest: fixed_digest(b"fuzz-contract"),
        manifest_digest: fixed_digest(b"fuzz-manifest"),
        blocks,
        total_tokens,
        extensions: ExtensionMap::default(),
    }
}

#[derive(Clone, Copy, Debug)]
struct DenyBackend;

impl Backend for DenyBackend {
    fn call(&mut self, _request: BackendRequest<'_>) -> Result<BackendResponse, BackendError> {
        Err(BackendError::Unavailable)
    }
}
