//! Exact-content and extension-manifest digest helpers.

use crate::error::{ExtensionHostError, ExtensionHostErrorCode, error};
use cigar_canon::{
    SemanticEnvelopeProfile, parse_strict_json, semantic_multihash_v1, semantic_signing_bytes_v1,
    to_deterministic_cbor,
};
use cigar_protocol::{ContentDigest, ExtensionManifestV1};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub(crate) fn raw_content_digest(bytes: &[u8]) -> Result<ContentDigest, ExtensionHostError> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
    }
    ContentDigest::new(encoded).map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))
}

pub(crate) fn canonical_record_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ExtensionHostError> {
    let json = serde_json::to_vec(value)
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    let node = parse_strict_json(&json)
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))?;
    to_deterministic_cbor(&node).map_err(|_error| error(ExtensionHostErrorCode::InvalidResponse))
}

pub(crate) fn canonical_record_digest<T: Serialize>(
    value: &T,
) -> Result<ContentDigest, ExtensionHostError> {
    raw_content_digest(&canonical_record_bytes(value)?)
}

pub(crate) fn manifest_signing_bytes(
    manifest: &ExtensionManifestV1,
) -> Result<Vec<u8>, ExtensionHostError> {
    semantic_signing_bytes_v1(SemanticEnvelopeProfile::ExtensionManifest, manifest)
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))
}

pub(crate) fn manifest_digest(
    manifest: &ExtensionManifestV1,
) -> Result<ContentDigest, ExtensionHostError> {
    let encoded = semantic_multihash_v1(SemanticEnvelopeProfile::ExtensionManifest, manifest)
        .map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))?;
    ContentDigest::new(encoded).map_err(|_error| error(ExtensionHostErrorCode::InvalidInput))
}
