use crate::{ContextError, SelectionStats, TokenCounter, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Exact source location and commitment for a retained excerpt.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    /// Stable source node identity.
    pub node_id: String,
    /// Caller-provided source locator.
    pub source: String,
    /// Digest of the complete original document, including identity and locator.
    pub document_digest: String,
    /// One-based first source line, inclusive.
    pub start_line: usize,
    /// One-based last source line, inclusive.
    pub end_line: usize,
}

/// One physical context block, possibly shared by several exact-text source aliases.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBlock {
    /// Exact full text or explicitly marked extractive windows.
    pub text: String,
    /// Sorted source citations, retaining every selected alias.
    pub citations: Vec<Citation>,
}

impl std::fmt::Debug for EvidenceBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceBlock")
            .field("bytes", &self.text.len())
            .field("citations", &self.citations.len())
            .finish_non_exhaustive()
    }
}

impl EvidenceBlock {
    pub(crate) fn new(text: String, mut citations: Vec<Citation>) -> Result<Self, ContextError> {
        citations.sort();
        citations.dedup();
        let block = Self { text, citations };
        block.validate()?;
        Ok(block)
    }

    /// Identity binds both text and all source citations.
    pub fn id(&self) -> Result<String, ContextError> {
        digest("cigar.evidence-block.v1", self)
    }

    fn validate(&self) -> Result<(), ContextError> {
        if self.text.is_empty()
            || self.text.len() > 1_048_576
            || self.citations.is_empty()
            || self.citations.len() > 4096
            || self.citations.windows(2).any(|w| w.first() >= w.get(1))
            || self.citations.iter().any(|c| {
                !crate::graph::valid_id(&c.node_id)
                    || c.source.is_empty()
                    || c.source.len() > 2048
                    || c.source.chars().any(char::is_control)
                    || !valid_digest(&c.document_digest)
                    || c.start_line == 0
                    || c.end_line < c.start_line
            })
        {
            return Err(ContextError::Integrity);
        }
        Ok(())
    }
}

/// A complete ordered context and its integrity commitment. Digests are not signatures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSnapshot {
    id: String,
    domain: String,
    policy_revision: String,
    tokenizer: String,
    graph_revision: u64,
    blocks: Vec<EvidenceBlock>,
    stats: SelectionStats,
}

impl ContextSnapshot {
    pub(crate) fn seal(
        domain: &str,
        policy: &str,
        tokenizer: &str,
        revision: u64,
        blocks: Vec<EvidenceBlock>,
        stats: SelectionStats,
    ) -> Result<Self, ContextError> {
        let mut value = Self {
            id: String::new(),
            domain: domain.to_owned(),
            policy_revision: policy.to_owned(),
            tokenizer: tokenizer.to_owned(),
            graph_revision: revision,
            blocks,
            stats,
        };
        value.id = value.commitment()?;
        Ok(value)
    }

    fn commitment(&self) -> Result<String, ContextError> {
        digest(
            "cigar.context-snapshot.v1",
            &(
                &self.domain,
                &self.policy_revision,
                &self.tokenizer,
                self.graph_revision,
                &self.blocks,
                &self.stats,
            ),
        )
    }

    /// Complete snapshot identity, suitable for exact delta base matching.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Selected physical evidence, including citations.
    #[must_use]
    pub fn blocks(&self) -> &[EvidenceBlock] {
        &self.blocks
    }

    /// Content-free query measurements.
    #[must_use]
    pub const fn stats(&self) -> &SelectionStats {
        &self.stats
    }

    /// Render source citations and content as ordinary quoted JSON data, one block per line.
    /// The application must place this text in its data/context role, never an instruction role.
    #[must_use]
    pub fn render(&self) -> String {
        render(&self.blocks)
    }

    /// Recomputes integrity, bounds, and exact final token count after loading or receiving data.
    pub fn verify(&self, tokenizer: &impl TokenCounter) -> Result<(), ContextError> {
        if self.domain.is_empty()
            || self.domain.len() > 256
            || self.policy_revision.is_empty()
            || self.policy_revision.len() > 256
            || self.tokenizer != tokenizer.identity()
            || !valid_digest(&self.id)
            || self.blocks.len() > 4096
            || self.blocks.iter().map(|b| b.text.len()).sum::<usize>() > 16_777_216
        {
            return Err(ContextError::Integrity);
        }
        for block in &self.blocks {
            block.validate()?;
        }
        let mut ids = BTreeSet::new();
        for block in &self.blocks {
            if !ids.insert(block.id()?) {
                return Err(ContextError::Integrity);
            }
        }
        let sources = self
            .blocks
            .iter()
            .flat_map(|b| b.citations.iter().map(|c| &c.node_id))
            .collect::<BTreeSet<_>>();
        let tokens = tokenizer.count(&self.render())?;
        if self.commitment()? != self.id
            || self.stats.selected_blocks != self.blocks.len()
            || self.stats.selected_sources != sources.len()
            || self.stats.rendered_tokens != tokens
            || tokens > self.stats.available_tokens
        {
            return Err(ContextError::Integrity);
        }
        Ok(())
    }

    /// Builds a delta for a receiver that retains the exact base. Policy changes require full refresh.
    pub fn delta_from(
        &self,
        base: &Self,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextDelta, ContextError> {
        self.verify(tokenizer)?;
        base.verify(tokenizer)?;
        if self.domain != base.domain
            || self.policy_revision != base.policy_revision
            || self.tokenizer != base.tokenizer
        {
            return Err(ContextError::BaseMismatch);
        }
        let prior = base
            .blocks
            .iter()
            .map(EvidenceBlock::id)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut order = Vec::new();
        let mut added = Vec::new();
        for block in &self.blocks {
            let id = block.id()?;
            if !prior.contains(&id) {
                added.push(block.clone());
            }
            order.push(id);
        }
        Ok(ContextDelta {
            base_id: base.id.clone(),
            target_id: self.id.clone(),
            graph_revision: self.graph_revision,
            stats: self.stats.clone(),
            order,
            added,
        })
    }
}

/// A verified transport delta. It saves network/storage bytes, not stateless model prompt tokens.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextDelta {
    base_id: String,
    target_id: String,
    graph_revision: u64,
    stats: SelectionStats,
    order: Vec<String>,
    added: Vec<EvidenceBlock>,
}

impl ContextDelta {
    /// Number of blocks whose complete bytes must be transported.
    #[must_use]
    pub fn added_blocks(&self) -> usize {
        self.added.len()
    }

    /// Reconstructs and verifies a complete snapshot; omission in `order` withdraws old content.
    pub fn apply(
        &self,
        base: &ContextSnapshot,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextSnapshot, ContextError> {
        base.verify(tokenizer)?;
        if self.base_id != base.id {
            return Err(ContextError::BaseMismatch);
        }
        if self.order.len() > 4096
            || self.added.len() > self.order.len()
            || self.order.iter().collect::<BTreeSet<_>>().len() != self.order.len()
        {
            return Err(ContextError::Integrity);
        }
        let mut values = base
            .blocks
            .iter()
            .map(|block| block.id().map(|id| (id, block.clone())))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for block in &self.added {
            block.validate()?;
            let id = block.id()?;
            if !self.order.contains(&id) || values.insert(id, block.clone()).is_some() {
                return Err(ContextError::Integrity);
            }
        }
        let blocks = self
            .order
            .iter()
            .map(|id| values.remove(id).ok_or(ContextError::Integrity))
            .collect::<Result<Vec<_>, _>>()?;
        let candidate = ContextSnapshot::seal(
            &base.domain,
            &base.policy_revision,
            &base.tokenizer,
            self.graph_revision,
            blocks,
            self.stats.clone(),
        )?;
        if candidate.id != self.target_id {
            return Err(ContextError::Integrity);
        }
        candidate.verify(tokenizer)?;
        Ok(candidate)
    }
}

#[derive(Serialize)]
struct Rendered<'a> {
    sources: Vec<(&'a str, &'a str, usize, usize)>,
    text: &'a str,
}

pub(crate) fn render(blocks: &[EvidenceBlock]) -> String {
    blocks
        .iter()
        .map(|block| {
            let rendered = Rendered {
                sources: block
                    .citations
                    .iter()
                    .map(|c| {
                        (
                            c.node_id.as_str(),
                            c.source.as_str(),
                            c.start_line,
                            c.end_line,
                        )
                    })
                    .collect(),
                text: &block.text,
            };
            // Serializing strings, vectors, and integers to an owned string is infallible.
            serde_json::to_string(&rendered).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
