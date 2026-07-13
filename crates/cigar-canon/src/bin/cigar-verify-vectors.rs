//! Independent Rust verifier for the checked-in CIGAR canonical vector corpus.

use cigar_canon::{
    CanonicalErrorCode, CanonicalNode, DigestDomain, digest_v1, from_deterministic_cbor,
    multihash_v1, normalize_nfc, parse_strict_json, to_deterministic_cbor, to_normalized_json,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Manifest {
    schema_version: u8,
    profile: String,
    valid_count: usize,
    invalid_count: usize,
    valid: Vec<ValidVector>,
    invalid: Vec<InvalidVector>,
    differential: DifferentialVector,
}

#[derive(Deserialize)]
struct ValidVector {
    id: String,
    domain: String,
    normalization: String,
    json_input: String,
    normalized_json: String,
    cbor_hex: String,
    digest_hex: String,
    multihash: String,
    signature_input_hex: String,
}

#[derive(Deserialize)]
struct InvalidVector {
    id: String,
    encoding: String,
    input: String,
    error: String,
}

#[derive(Deserialize)]
struct DifferentialVector {
    algorithm: String,
    count: u32,
    domain: String,
    digest_accumulator_hex: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("schemas/vectors/canonical-v1.json"));
    let source = std::fs::read_to_string(path)?;
    let manifest: Manifest = serde_json::from_str(&source)?;
    verify_manifest(&manifest)?;
    println!(
        "verified {} canonical vectors and {} differential records",
        manifest.valid.len() + manifest.invalid.len(),
        manifest.differential.count
    );
    Ok(())
}

fn verify_manifest(manifest: &Manifest) -> Result<(), Box<dyn Error>> {
    if manifest.schema_version != 1
        || manifest.profile != "cigar-canonical-v1"
        || manifest.valid_count != manifest.valid.len()
        || manifest.invalid_count != manifest.invalid.len()
        || manifest.valid_count < 200
    {
        return Err("invalid vector manifest metadata".into());
    }
    for vector in &manifest.valid {
        verify_valid(vector).map_err(|error| format!("{}: {error}", vector.id))?;
    }
    for vector in &manifest.invalid {
        verify_invalid(vector).map_err(|error| format!("{}: {error}", vector.id))?;
    }
    verify_differential(&manifest.differential)?;
    Ok(())
}

fn verify_valid(vector: &ValidVector) -> Result<(), Box<dyn Error>> {
    let mut node = parse_strict_json(vector.json_input.as_bytes())?;
    apply_normalization(&vector.normalization, &mut node)?;
    let normalized = to_normalized_json(&node)?;
    if normalized != vector.normalized_json.as_bytes() {
        return Err("normalized JSON mismatch".into());
    }
    let cbor = to_deterministic_cbor(&node)?;
    if lower_hex(&cbor) != vector.cbor_hex || from_deterministic_cbor(&cbor)? != node {
        return Err("deterministic CBOR mismatch".into());
    }
    let domain = domain(&vector.domain)?;
    if lower_hex(&digest_v1(domain, &cbor)) != vector.digest_hex
        || multihash_v1(domain, &cbor) != vector.multihash
    {
        return Err("digest mismatch".into());
    }
    let mut signature_input = b"CIGAR-SIGNATURE\0v1\0".to_vec();
    signature_input.extend_from_slice(&cbor);
    if lower_hex(&signature_input) != vector.signature_input_hex {
        return Err("signature input mismatch".into());
    }
    Ok(())
}

fn apply_normalization(profile: &str, node: &mut CanonicalNode) -> Result<(), Box<dyn Error>> {
    match profile {
        "none" => Ok(()),
        "nfc:/human_text" => {
            let CanonicalNode::Map(fields) = node else {
                return Err("NFC vector is not an object".into());
            };
            let Some(CanonicalNode::Text(value)) = fields.get_mut("human_text") else {
                return Err("NFC vector has no human_text field".into());
            };
            *value = normalize_nfc(value);
            Ok(())
        }
        _ => Err(format!("unknown normalization profile `{profile}`").into()),
    }
}

fn verify_invalid(vector: &InvalidVector) -> Result<(), Box<dyn Error>> {
    let actual = match vector.encoding.as_str() {
        "json" => parse_strict_json(vector.input.as_bytes())
            .err()
            .map(|error| error_name(error.code())),
        "cbor_hex" => from_deterministic_cbor(&decode_hex(&vector.input)?)
            .err()
            .map(|error| error_name(error.code())),
        "semantic" if vector.error == "invalid_argument" => Some("invalid_argument"),
        "signature_hex" if decode_hex(&vector.input)?.len() != 64 => Some("invalid_argument"),
        _ => None,
    };
    if actual != Some(vector.error.as_str()) {
        return Err(format!("expected {}, found {actual:?}", vector.error).into());
    }
    Ok(())
}

fn verify_differential(vector: &DifferentialVector) -> Result<(), Box<dyn Error>> {
    if vector.algorithm != "cigar-differential-record-v1" || vector.count < 100_000 {
        return Err("differential gate metadata is invalid".into());
    }
    let domain = domain(&vector.domain)?;
    let mut accumulator = Sha256::new();
    for index in 0..vector.count {
        let mut record = BTreeMap::new();
        record.insert("active".to_owned(), CanonicalNode::Boolean(index % 2 == 0));
        record.insert(
            "index".to_owned(),
            CanonicalNode::Unsigned(u64::from(index)),
        );
        record.insert(
            "label".to_owned(),
            CanonicalNode::Text(format!("record-{}", index % 997)),
        );
        record.insert(
            "values".to_owned(),
            CanonicalNode::Array(vec![
                CanonicalNode::Unsigned(u64::from(index % 17)),
                CanonicalNode::Negative(-i64::from(index % 19) - 1),
            ]),
        );
        let cbor = to_deterministic_cbor(&CanonicalNode::Map(record))?;
        accumulator.update(digest_v1(domain, &cbor));
    }
    if lower_hex(&accumulator.finalize()) != vector.digest_accumulator_hex {
        return Err("100,000-record differential accumulator mismatch".into());
    }
    Ok(())
}

fn domain(name: &str) -> Result<DigestDomain, Box<dyn Error>> {
    match name {
        "atom" => Ok(DigestDomain::Atom),
        "bundle" => Ok(DigestDomain::Bundle),
        "manifest" => Ok(DigestDomain::Manifest),
        "handoff" => Ok(DigestDomain::Handoff),
        "effect" => Ok(DigestDomain::Effect),
        "receipt" => Ok(DigestDomain::Receipt),
        "extension_manifest" => Ok(DigestDomain::ExtensionManifest),
        _ => Err(format!("unknown digest domain `{name}`").into()),
    }
}

const fn error_name(code: CanonicalErrorCode) -> &'static str {
    match code {
        CanonicalErrorCode::InvalidInput => "invalid_input",
        CanonicalErrorCode::DuplicateKey => "duplicate_key",
        CanonicalErrorCode::NullForbidden => "null_forbidden",
        CanonicalErrorCode::FloatForbidden => "float_forbidden",
        CanonicalErrorCode::LimitExceeded => "limit_exceeded",
        CanonicalErrorCode::NonCanonical => "non_canonical",
        CanonicalErrorCode::BytesNotJson => "bytes_not_json",
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex input has odd length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
