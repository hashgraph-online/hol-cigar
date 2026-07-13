//! Exact structural redaction with derived digest and policy lineage.

use crate::{PolicyError, PolicyErrorCode};
use cigar_canon::{CanonicalNode, to_deterministic_cbor};
use cigar_protocol::ContentDigest;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Structurally redacted value with exact derivation lineage.
#[derive(Clone, Eq, PartialEq)]
pub struct RedactedValue {
    /// Redacted canonical semantic value.
    pub value: CanonicalNode,
    /// Digest of the derived redacted representation.
    pub derived_digest: ContentDigest,
    /// Digest of the exact input representation.
    pub source_digest: ContentDigest,
    /// Policy snapshot that required the transform.
    pub policy_digest: ContentDigest,
    /// Exact paths transformed.
    pub redacted_paths: BTreeSet<String>,
}

impl fmt::Debug for RedactedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedValue")
            .field("derived_digest", &self.derived_digest)
            .field("source_digest", &self.source_digest)
            .field("policy_digest", &self.policy_digest)
            .field("redacted_path_count", &self.redacted_paths.len())
            .finish_non_exhaustive()
    }
}

/// Stateless exact JSON-pointer structural redactor.
#[derive(Clone, Copy, Debug, Default)]
pub struct StructuralRedactor;

impl StructuralRedactor {
    /// Replaces selected fields without string searching or serialization round trips.
    pub fn redact(
        &self,
        value: &CanonicalNode,
        redaction_paths: &BTreeSet<String>,
        required_paths: &BTreeSet<String>,
        source_digest: ContentDigest,
        policy_digest: ContentDigest,
    ) -> Result<RedactedValue, PolicyError> {
        if redaction_paths.len() > crate::MAX_POLICY_SELECTORS
            || required_paths.len() > crate::MAX_POLICY_SELECTORS
        {
            return Err(PolicyError::new(PolicyErrorCode::LimitExceeded));
        }
        for redacted in redaction_paths {
            if required_paths
                .iter()
                .any(|required| pointers_overlap(redacted, required))
            {
                return Err(PolicyError::new(PolicyErrorCode::RequiredField));
            }
        }
        let mut output = value.clone();
        for path in redaction_paths {
            let segments = parse_pointer(path)?;
            redact_at(&mut output, &segments)?;
        }
        let canonical = to_deterministic_cbor(&output)
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
        let derived_digest =
            redaction_digest(&canonical, &source_digest, &policy_digest, redaction_paths)?;
        Ok(RedactedValue {
            value: output,
            derived_digest,
            source_digest,
            policy_digest,
            redacted_paths: redaction_paths.clone(),
        })
    }
}

fn pointers_overlap(left: &str, right: &str) -> bool {
    left == right
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn parse_pointer(pointer: &str) -> Result<Vec<String>, PolicyError> {
    if pointer.is_empty()
        || pointer.len() > crate::MAX_POLICY_TEXT_BYTES
        || !pointer.starts_with('/')
        || pointer.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
    }
    pointer
        .split('/')
        .skip(1)
        .map(|segment| {
            let mut decoded = String::new();
            let mut characters = segment.chars();
            while let Some(character) = characters.next() {
                if character == '~' {
                    match characters.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        Some(_) | None => {
                            return Err(PolicyError::new(PolicyErrorCode::InvalidInput));
                        }
                    }
                } else {
                    decoded.push(character);
                }
            }
            if decoded.is_empty() {
                Err(PolicyError::new(PolicyErrorCode::InvalidInput))
            } else {
                Ok(decoded)
            }
        })
        .collect()
}

fn redact_at(value: &mut CanonicalNode, segments: &[String]) -> Result<(), PolicyError> {
    let (first, rest) = segments
        .split_first()
        .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?;
    match value {
        CanonicalNode::Map(fields) => {
            let child = fields
                .get_mut(first)
                .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?;
            if rest.is_empty() {
                *child = CanonicalNode::Text("[REDACTED]".to_owned());
                Ok(())
            } else {
                redact_at(child, rest)
            }
        }
        CanonicalNode::Array(values) => {
            let index = first
                .parse::<usize>()
                .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
            let child = values
                .get_mut(index)
                .ok_or_else(|| PolicyError::new(PolicyErrorCode::InvalidInput))?;
            if rest.is_empty() {
                *child = CanonicalNode::Text("[REDACTED]".to_owned());
                Ok(())
            } else {
                redact_at(child, rest)
            }
        }
        CanonicalNode::Boolean(_)
        | CanonicalNode::Unsigned(_)
        | CanonicalNode::Negative(_)
        | CanonicalNode::Bytes(_)
        | CanonicalNode::Text(_) => Err(PolicyError::new(PolicyErrorCode::InvalidInput)),
    }
}

fn redaction_digest(
    canonical: &[u8],
    source: &ContentDigest,
    policy: &ContentDigest,
    paths: &BTreeSet<String>,
) -> Result<ContentDigest, PolicyError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-REDACTION\0v1\0");
    hasher.update(source.as_str());
    hasher.update(policy.as_str());
    for path in paths {
        hasher.update(path.as_bytes());
        hasher.update([0]);
    }
    hasher.update(canonical);
    let mut value = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))?;
    }
    ContentDigest::new(value).map_err(|_error| PolicyError::new(PolicyErrorCode::InvalidInput))
}
