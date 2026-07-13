use crate::{EffectError, EffectErrorCode};
use cigar_protocol::{ContentDigest, EffectIntent};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub(crate) const MAX_REFERENCE_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_REFERENCE_TEXT_BYTES: usize = 65_536;

pub(crate) fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<ContentDigest, EffectError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-REFERENCE-CONNECTOR\0v1\0");
    update_part(&mut hasher, domain)?;
    for part in parts {
        update_part(&mut hasher, part)?;
    }
    encode_digest(hasher.finalize().into())
}

pub(crate) fn stable_evidence(
    domain: &[u8],
    intent: &EffectIntent,
) -> Result<ContentDigest, EffectError> {
    digest_parts(
        domain,
        &[
            intent.effect_id.as_str().as_bytes(),
            intent.arguments_digest.as_str().as_bytes(),
        ],
    )
}

pub(crate) fn validate_selector(value: &str) -> Result<(), EffectError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        Err(EffectError::new(EffectErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_bounded_text(value: &str, maximum: usize) -> Result<(), EffectError> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        Err(EffectError::new(EffectErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn update_part(hasher: &mut Sha256, part: &[u8]) -> Result<(), EffectError> {
    let length = u64::try_from(part.len())
        .map_err(|_error| EffectError::new(EffectErrorCode::LimitExceeded))?;
    hasher.update(length.to_be_bytes());
    hasher.update(part);
    Ok(())
}

fn encode_digest(digest: [u8; 32]) -> Result<ContentDigest, EffectError> {
    let mut encoded = String::from("1220");
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
    }
    ContentDigest::new(encoded).map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))
}
