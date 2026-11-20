//! A local context graph for applications that own and authorize their input documents.
//!
//! This library performs no network access or filesystem discovery. Each graph belongs to one
//! application-defined privacy domain. Filter authorized node IDs on every request when a graph
//! contains documents with differing access rules. Relevance and graph edges never grant access.

#![doc = include_str!("../README.md")]

mod answer;
#[cfg(feature = "broker")]
pub mod broker;
mod chunking;
mod explain;
mod graph;
mod prompt;
mod select;
mod snapshot;
mod tokenizer;
mod views;
#[cfg(feature = "bpe")]
#[path = "worker/mod.rs"]
pub mod worker;

pub use answer::{
    AnswerAssessment, AnswerClaim, AnswerDecision, AnswerDraft, AnswerPolicy, ClaimAssessment,
    ClaimIssue, ClaimReview, ClaimVerdict,
};
pub use explain::{SelectionExplanation, SelectionSignal, SelectionStep};
pub use graph::{ContextGraph, Document, EdgeKind, GraphLimits, SourceUpdate};
pub use prompt::ContextPrompt;
pub use select::{ContextRequest, ExcerptMode, SelectionStats};
pub use snapshot::{Citation, ContextDelta, ContextSnapshot, EvidenceBlock};
#[cfg(feature = "bpe")]
pub use tokenizer::O200kTokenizer;
pub use tokenizer::{
    CachedTokenCounter, TokenCacheLimits, TokenCacheStats, TokenCounter, Utf8ByteCounter,
};
pub use views::{
    ContextView, ContextViewAssessment, ContextViewHandle, ContextViewSpec, ContextViews,
};

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Stable error categories; errors never include document text, source paths, or queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextError {
    /// Input is empty, malformed, or uses invalid options.
    InvalidInput,
    /// A graph, query, traversal, or output limit was exceeded.
    LimitExceeded,
    /// A requested node or required dependency is absent or unauthorized.
    RequiredUnavailable,
    /// The exact required evidence cannot fit the requested token budget.
    BudgetUnsatisfiable,
    /// A tokenizer could not count the supplied text.
    Tokenizer,
    /// A serialized snapshot or delta failed integrity validation.
    Integrity,
    /// A delta belongs to a different base, privacy domain, policy, or tokenizer.
    BaseMismatch,
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "context graph error: {self:?}")
    }
}

impl std::error::Error for ContextError {}

pub(crate) fn digest<T: serde::Serialize>(domain: &str, value: &T) -> Result<String, ContextError> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    // Preserve the exact serde_json byte stream without retaining a second
    // serialized copy of source text alongside the graph/snapshot/rendering.
    serde_json::to_writer(HashWriter(&mut hash), value).map_err(|_| ContextError::Integrity)?;
    let mut output = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(&mut output, "{byte:02x}").map_err(|_| ContextError::Integrity)?;
    }
    Ok(output)
}

struct HashWriter<'a>(&'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    fn legacy_digest<T: serde::Serialize>(
        domain: &str,
        value: &T,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut hash = Sha256::new();
        hash.update(domain.as_bytes());
        hash.update([0]);
        hash.update(serde_json::to_vec(value)?);
        Ok(hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    #[test]
    fn streamed_commitments_preserve_legacy_bytes_and_domain_separation()
    -> Result<(), Box<dyn std::error::Error>> {
        for index in 0..256_u64 {
            let value = serde_json::json!({
                "record": [index, u64::MAX - index],
                "text": format!("café 🦀 \"quote\"\\slash\n\t\0 {index}"),
                "nested": {"empty": [], "optional": null, "boolean": index % 2 == 0},
            });
            for domain in ["cigar.document.v1", "cigar.context-snapshot.v1", ""] {
                assert_eq!(digest(domain, &value)?, legacy_digest(domain, &value)?);
            }
        }
        let large = "source \"quoted\" café 🦀\n".repeat(65_536);
        assert_eq!(digest("large", &large)?, legacy_digest("large", &large)?);
        assert_ne!(digest("a", &"bc")?, digest("ab", &"c")?);
        Ok(())
    }

    #[test]
    fn serialization_failure_still_returns_content_free_integrity_error() {
        struct Invalid;
        impl serde::Serialize for Invalid {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(
                    "caller-controlled failure detail",
                ))
            }
        }
        assert_eq!(digest("failure", &Invalid), Err(ContextError::Integrity));
    }
}
