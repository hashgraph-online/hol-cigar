//! Shared canonical protocol-vector qualification.

use cigar_canon::{
    CanonicalNode, DigestDomain, digest_v1, from_deterministic_cbor, multihash_v1, normalize_nfc,
    parse_strict_json, to_deterministic_cbor, to_normalized_json,
};
use serde::Deserialize;

const VECTORS: &[u8] = include_bytes!("../../../schemas/vectors/canonical-v1.json");

#[derive(Deserialize)]
struct VectorDocument {
    valid_count: usize,
    invalid_count: usize,
    valid: Vec<ValidVector>,
    invalid: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct ValidVector {
    domain: String,
    normalization: String,
    json_input: String,
    normalized_json: String,
    cbor_hex: String,
    digest_hex: String,
    multihash: String,
}

#[derive(Deserialize)]
struct InvalidVector {
    encoding: String,
    input: String,
}

#[test]
fn all_canonical_vectors_match_the_frozen_rust_codec() -> Result<(), Box<dyn std::error::Error>> {
    cigar_canon::parse_strict_json(VECTORS)?;
    let document: VectorDocument = serde_json::from_slice(VECTORS)?;
    assert_eq!(document.valid.len(), document.valid_count);
    assert_eq!(document.invalid.len(), document.invalid_count);
    for vector in document.valid {
        let mut node = parse_strict_json(vector.json_input.as_bytes())?;
        apply_normalization(&mut node, &vector.normalization)?;
        assert_eq!(
            to_normalized_json(&node)?,
            vector.normalized_json.as_bytes()
        );
        let cbor = to_deterministic_cbor(&node)?;
        assert_eq!(hex(&cbor), vector.cbor_hex);
        let domain = domain(&vector.domain)?;
        assert_eq!(hex(&digest_v1(domain, &cbor)), vector.digest_hex);
        assert_eq!(multihash_v1(domain, &cbor), vector.multihash);
    }
    for vector in document.invalid {
        match vector.encoding.as_str() {
            "json" => assert!(parse_strict_json(vector.input.as_bytes()).is_err()),
            "cbor_hex" => assert!(from_deterministic_cbor(&decode_hex(&vector.input)?).is_err()),
            "semantic" | "signature_hex" => {}
            _ => return Err("unknown invalid-vector encoding".into()),
        }
    }
    Ok(())
}

fn apply_normalization(
    node: &mut CanonicalNode,
    normalization: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match normalization {
        "none" => Ok(()),
        "nfc:/human_text" => {
            let CanonicalNode::Map(fields) = node else {
                return Err("NFC vector was not a map".into());
            };
            let Some(CanonicalNode::Text(text)) = fields.get_mut("human_text") else {
                return Err("NFC vector lacked human_text".into());
            };
            *text = normalize_nfc(text);
            Ok(())
        }
        _ => Err("unknown normalization profile".into()),
    }
}

fn domain(value: &str) -> Result<DigestDomain, Box<dyn std::error::Error>> {
    Ok(match value {
        "atom" => DigestDomain::Atom,
        "bundle" => DigestDomain::Bundle,
        "manifest" => DigestDomain::Manifest,
        "handoff" => DigestDomain::Handoff,
        "effect" => DigestDomain::Effect,
        "receipt" => DigestDomain::Receipt,
        "extension_manifest" => DigestDomain::ExtensionManifest,
        _ => return Err("unknown digest domain".into()),
    })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd hex input".into());
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

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _result = write!(&mut output, "{byte:02x}");
    }
    output
}
