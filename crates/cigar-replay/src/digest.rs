//! Strict deterministic encoding and exact-content digest helpers.

use crate::contract::{DecisionArchive, ReplayFoundationError, ReplayFoundationErrorCode};
use cigar_canon::{CanonicalNode, parse_strict_json, to_deterministic_cbor, to_normalized_json};
use cigar_protocol::{ContentDigest, VersionId};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Serializes one record through the strict canonical JSON semantic model.
pub(crate) fn canonical_record_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ReplayFoundationError> {
    let json = serde_json::to_vec(value).map_err(|_error| unavailable())?;
    let node = parse_strict_json(&json).map_err(|_error| invalid())?;
    to_normalized_json(&node).map_err(|_error| invalid())
}

/// Computes the raw SHA-256 multihash of exact bytes without inventing a semantic domain.
pub(crate) fn raw_content_digest(bytes: &[u8]) -> Result<ContentDigest, ReplayFoundationError> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}").map_err(|_error| unavailable())?;
    }
    ContentDigest::new(encoded).map_err(|_error| invalid())
}

/// Derives the decision root from deterministic archive bytes with only its self-ID excluded.
pub(crate) fn archive_version_id(
    archive: &DecisionArchive,
) -> Result<VersionId, ReplayFoundationError> {
    let bytes = archive_root_bytes(archive)?;
    VersionId::new(raw_content_digest(&bytes)?.as_str()).map_err(|_error| invalid())
}

fn archive_root_bytes(archive: &DecisionArchive) -> Result<Vec<u8>, ReplayFoundationError> {
    let json = serde_json::to_vec(archive).map_err(|_error| unavailable())?;
    let mut root = parse_strict_json(&json).map_err(|_error| invalid())?;
    let CanonicalNode::Map(fields) = &mut root else {
        return Err(invalid());
    };
    let Some(CanonicalNode::Map(decision)) = fields.get_mut("decision") else {
        return Err(invalid());
    };
    if decision.remove("decision_id").is_none() {
        return Err(invalid());
    }
    to_deterministic_cbor(&root).map_err(|_error| invalid())
}

fn invalid() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::InvalidInput)
}

fn unavailable() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{canonical_record_bytes, raw_content_digest};

    #[test]
    fn canonical_record_encoding_is_order_independent() -> Result<(), Box<dyn std::error::Error>> {
        let first = serde_json::json!({"z": 1, "a": [true, 2]});
        let second = serde_json::json!({"a": [true, 2], "z": 1});
        let first_bytes = canonical_record_bytes(&first)?;
        let second_bytes = canonical_record_bytes(&second)?;
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(
            raw_content_digest(&first_bytes)?,
            raw_content_digest(&second_bytes)?
        );
        Ok(())
    }

    #[test]
    fn raw_digest_changes_with_exact_bytes() -> Result<(), Box<dyn std::error::Error>> {
        assert_ne!(raw_content_digest(b"a")?, raw_content_digest(b"b")?);
        Ok(())
    }
}
