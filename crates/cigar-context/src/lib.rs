//! A local context graph for applications that own and authorize their input documents.
//!
//! This library performs no network access or filesystem discovery. Each graph belongs to one
//! application-defined privacy domain. Filter authorized node IDs on every request when a graph
//! contains documents with differing access rules. Relevance and graph edges never grant access.

#![doc = include_str!("../README.md")]

mod answer;
mod graph;
mod prompt;
mod select;
mod snapshot;
mod tokenizer;

pub use answer::{
    AnswerAssessment, AnswerClaim, AnswerDecision, AnswerDraft, AnswerPolicy, ClaimAssessment,
    ClaimIssue, ClaimReview, ClaimVerdict,
};
pub use graph::{ContextGraph, Document, EdgeKind, GraphLimits, SourceUpdate};
pub use prompt::ContextPrompt;
pub use select::{ContextRequest, ExcerptMode, SelectionStats};
pub use snapshot::{Citation, ContextDelta, ContextSnapshot, EvidenceBlock};
#[cfg(feature = "bpe")]
pub use tokenizer::O200kTokenizer;
pub use tokenizer::{
    CachedTokenCounter, TokenCacheLimits, TokenCacheStats, TokenCounter, Utf8ByteCounter,
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
    let bytes = serde_json::to_vec(value).map_err(|_| ContextError::Integrity)?;
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(bytes);
    let mut output = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(&mut output, "{byte:02x}").map_err(|_| ContextError::Integrity)?;
    }
    Ok(output)
}
