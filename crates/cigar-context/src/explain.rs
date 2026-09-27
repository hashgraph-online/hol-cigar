//! Opt-in, current-state selection traces. These are not semantic truth assessments.

use crate::{ContextError, ContextRequest, ContextSnapshot, TokenCounter, digest};
use serde::Serialize;

/// Signals used by the deterministic selector for an admitted root.
/// They describe retrieval, not support for a claim or permission to execute a tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionSignal {
    /// Explicitly required by the context request.
    Required,
    /// At least one indexed query term matched this root.
    LexicalMatch,
    /// A matched identifier was recognized as a declaration by the lexical index.
    DeclarationMatch,
    /// This root was admitted from the caller's ranked semantic IDs.
    SemanticCandidate,
    /// This root was admitted by bounded graph expansion.
    GraphExpansion,
}

/// One successful selection step, in the order it happened. Only selected IDs appear.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SelectionStep {
    /// Root whose complete hard closure was considered at this step.
    pub root_id: String,
    /// Previously unselected IDs added by this step, including required counterevidence.
    /// Sorted by ID; coalesced equal-text documents retain distinct IDs here.
    pub added_ids: Vec<String>,
    /// Retrieval signals, not calibrated confidence or a semantic justification.
    pub signals: Vec<SelectionSignal>,
}

impl std::fmt::Debug for SelectionStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionStep")
            .field("added_documents", &self.added_ids.len())
            .finish_non_exhaustive()
    }
}

/// Reconstructed selection trace after current evidence and authority validation.
/// Contains selected IDs, so keep it within the same disclosure boundary as its context.
/// No query/source text, rejected IDs, similarity scores or truth probabilities are returned.
/// This record is neither a signed receipt nor a replacement for answer review.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SelectionExplanation {
    /// Independently versioned explanation shape; the snapshot ABI is unchanged.
    pub schema: &'static str,
    /// Exact original snapshot being explained.
    pub snapshot_id: String,
    /// Domain-separated commitment to the caller's exact context request.
    pub request_id: String,
    /// Current revision at validation. Out-of-scope writes may preserve a view's evidence.
    pub checked_graph_revision: u64,
    /// Exact algorithm/vocabulary identity used for context-text token accounting.
    pub tokenizer: String,
    /// Successful selection steps only. Unselected evidence is not disclosed.
    pub steps: Vec<SelectionStep>,
}

impl std::fmt::Debug for SelectionExplanation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionExplanation")
            .field("steps", &self.steps.len())
            .finish_non_exhaustive()
    }
}

impl SelectionExplanation {
    pub(crate) fn new(
        snapshot: &ContextSnapshot,
        request: &ContextRequest,
        checked_graph_revision: u64,
        tokenizer: &impl TokenCounter,
        steps: Vec<SelectionStep>,
    ) -> Result<Self, ContextError> {
        Ok(Self {
            schema: "cigar.context-selection-explanation.v1",
            snapshot_id: snapshot.id().to_owned(),
            request_id: digest("cigar.context-explanation-request.v1", request)?,
            checked_graph_revision,
            tokenizer: tokenizer.identity().to_owned(),
            steps,
        })
    }
}
