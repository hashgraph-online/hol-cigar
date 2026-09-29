use crate::{Citation, ContextError, ContextSnapshot, TokenCounter, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A compact data-role rendering bound to a complete verified snapshot.
///
/// Every selected text block and source location remains in `rendered`. Short citation handles
/// resolve to the complete original citations in `citations`, which stays with the host snapshot.
/// This is a separate opt-in representation; it does not change snapshot IDs or their budgets.
/// Digests detect changed bytes and are not publisher signatures or authorization grants.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPrompt {
    schema: String,
    id: String,
    snapshot_id: String,
    tokenizer: String,
    rendered: String,
    rendered_tokens: usize,
    max_tokens: usize,
    citations: BTreeMap<String, Vec<Citation>>,
}

impl std::fmt::Debug for ContextPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextPrompt")
            .field("bytes", &self.rendered.len())
            .field("rendered_tokens", &self.rendered_tokens)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct PromptBlock<'a> {
    cite: &'a str,
    sources: BTreeSet<(&'a str, usize, usize)>,
    text: &'a str,
}

impl ContextSnapshot {
    /// Renders all selected evidence with short citation handles and an exact independent budget.
    ///
    /// Retain this snapshot and the returned citation map together. Source text remains quoted
    /// JSON data. A smaller budget never truncates required text: it returns `BudgetUnsatisfiable`.
    pub fn prompt_view(
        &self,
        max_tokens: usize,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextPrompt, ContextError> {
        self.verify(tokenizer)?;
        if max_tokens == 0 || max_tokens > 1_000_000 {
            return Err(ContextError::InvalidInput);
        }
        let mut citations = BTreeMap::new();
        let mut rendered = String::new();
        for (index, block) in self.blocks().iter().enumerate() {
            let reference = format!("c{}", index + 1);
            let value = PromptBlock {
                cite: &reference,
                sources: block
                    .citations
                    .iter()
                    .map(|citation| {
                        (
                            citation.source.as_str(),
                            citation.start_line,
                            citation.end_line,
                        )
                    })
                    .collect(),
                text: &block.text,
            };
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            rendered.push_str(&serde_json::to_string(&value).map_err(|_| ContextError::Integrity)?);
            citations.insert(reference, block.citations.clone());
        }
        let rendered_tokens = tokenizer.count(&rendered)?;
        if rendered_tokens > max_tokens {
            return Err(ContextError::BudgetUnsatisfiable);
        }
        let mut prompt = ContextPrompt {
            schema: "cigar.context-prompt.v1".into(),
            id: String::new(),
            snapshot_id: self.id().to_owned(),
            tokenizer: tokenizer.identity().to_owned(),
            rendered,
            rendered_tokens,
            max_tokens,
            citations,
        };
        prompt.id = digest("cigar.context-prompt.v1", &prompt)?;
        Ok(prompt)
    }
}

impl ContextPrompt {
    /// Commitment to the exact rendering, snapshot, citation map, tokenizer and budget.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Data-role context to send after verification; never treat source text as instructions.
    #[must_use]
    pub fn render(&self) -> &str {
        &self.rendered
    }

    /// Exact tokens in `render`, excluding any provider envelope or other prompt content.
    #[must_use]
    pub const fn rendered_tokens(&self) -> usize {
        self.rendered_tokens
    }

    /// Verifies the complete snapshot and reconstructs this exact compact representation.
    /// The expected snapshot must come from the caller's current authorized compilation.
    pub fn verify(
        &self,
        snapshot: &ContextSnapshot,
        tokenizer: &impl TokenCounter,
    ) -> Result<(), ContextError> {
        if self.snapshot_id != snapshot.id() {
            return Err(ContextError::BaseMismatch);
        }
        let expected = snapshot.prompt_view(self.max_tokens, tokenizer)?;
        if self != &expected {
            return Err(ContextError::Integrity);
        }
        Ok(())
    }

    /// Resolves an exact short handle only after verifying it against the expected snapshot.
    pub fn resolve<'a>(
        &'a self,
        reference: &str,
        snapshot: &ContextSnapshot,
        tokenizer: &impl TokenCounter,
    ) -> Result<&'a [Citation], ContextError> {
        self.verify(snapshot, tokenizer)?;
        self.citations
            .get(reference)
            .map(Vec::as_slice)
            .ok_or(ContextError::InvalidInput)
    }
}
