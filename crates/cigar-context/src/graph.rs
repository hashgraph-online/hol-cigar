use crate::{ContextError, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A source document. IDs and graph relations are application metadata, never inferred authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// Stable, application-assigned ID, at most 128 printable ASCII characters.
    pub id: String,
    /// Source locator retained in citations; not opened by this library.
    pub source: String,
    /// Exact UTF-8 source text.
    pub text: String,
    /// One-based offset in the original source, for application-provided fragments.
    #[serde(default = "first_line")]
    pub start_line: usize,
}

const fn first_line() -> usize {
    1
}

impl Document {
    /// Constructs an input document. The graph validates bounds before indexing.
    pub fn new(id: impl Into<String>, source: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            source: source.into(),
            text: text.into(),
            start_line: 1,
        }
    }

    /// Splits explicit text into overlapping line chunks, preserving original line numbers and
    /// UTF-8/line terminators. This is not an AST parser: choose complete symbols yourself when
    /// syntax must remain intact. At most 4096 chunks and 16 MiB of input are accepted.
    /// Replace/withdraw obsolete chunk IDs after source edits; this method does not mutate a graph.
    pub fn chunks(
        &self,
        max_lines: usize,
        overlap_lines: usize,
    ) -> Result<Vec<Self>, ContextError> {
        if max_lines == 0
            || overlap_lines >= max_lines
            || !valid_id(&self.id)
            || self.id.len() > 100
            || self.start_line == 0
            || self.text.trim().is_empty()
        {
            return Err(ContextError::InvalidInput);
        }
        if self.text.len() > 16_777_216 {
            return Err(ContextError::LimitExceeded);
        }
        let lines = self.text.split_inclusive('\n').collect::<Vec<_>>();
        let mut chunks = Vec::new();
        let mut start = 0;
        while start < lines.len() {
            let end = start.saturating_add(max_lines).min(lines.len());
            let text = lines
                .get(start..end)
                .ok_or(ContextError::Integrity)?
                .concat();
            if !text.trim().is_empty() {
                if chunks.len() >= 4096 {
                    return Err(ContextError::LimitExceeded);
                }
                let start_line = self
                    .start_line
                    .checked_add(start)
                    .ok_or(ContextError::LimitExceeded)?;
                chunks.push(Self {
                    id: format!("{}:L{start_line}", self.id),
                    source: self.source.clone(),
                    text,
                    start_line,
                });
            }
            if end == lines.len() {
                break;
            }
            start = end - overlap_lines;
        }
        Ok(chunks)
    }
}

impl std::fmt::Debug for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Document")
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

/// Semantics of a directed relation from one document to another.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Selecting the source requires the target's complete text and its hard closure.
    Requires,
    /// Selecting either side includes the other's complete text, preserving counterevidence.
    Contradicts,
    /// The target is supporting evidence, considered during bounded graph expansion.
    Supports,
    /// The target is a related lead, with a smaller expansion score.
    Related,
}

/// Memory and ingestion limits enforced before graph mutation.
#[derive(Clone, Copy, Debug)]
pub struct GraphLimits {
    /// Maximum live documents.
    pub max_documents: usize,
    /// Maximum UTF-8 bytes per document.
    pub max_document_bytes: usize,
    /// Maximum total live text bytes.
    pub max_total_bytes: usize,
    /// Maximum outgoing edges per document.
    pub max_edges_per_document: usize,
    /// Maximum retained directed edges, including edges to withdrawn sources.
    pub max_edges: usize,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_documents: 100_000,
            max_document_bytes: 262_144,
            max_total_bytes: 256 * 1024 * 1024,
            max_edges_per_document: 128,
            max_edges: 1_000_000,
        }
    }
}

pub(crate) struct IndexedDocument {
    pub document: Document,
    pub terms: BTreeMap<String, IndexedTerm>,
    pub digest: String,
    pub text_digest: String,
    pub declarations: BTreeSet<String>,
}

pub(crate) struct IndexedTerm {
    pub count: u8,
    // None encodes the common line-zero occurrence (or no text occurrence when !in_text).
    // Box only exceptional positions so every short-document term stays small and allocation-free.
    positions: Option<Box<LinePosting>>,
    in_text: bool,
    pub in_source: bool,
}

enum LinePosting {
    Single(usize),
    Multiple(Vec<usize>),
}

impl LinePosting {
    fn lines(&self) -> impl Iterator<Item = usize> + '_ {
        let (single, multiple) = match self {
            Self::Single(line) => (Some(*line), &[][..]),
            Self::Multiple(lines) => (None, lines.as_slice()),
        };
        single.into_iter().chain(multiple.iter().copied())
    }

    fn intersects(&self, start: usize, end: usize) -> bool {
        match self {
            Self::Single(line) => *line >= start && *line <= end,
            Self::Multiple(lines) => {
                let index = lines.partition_point(|line| *line < start);
                lines.get(index).is_some_and(|line| *line <= end)
            }
        }
    }
}

impl IndexedTerm {
    fn new() -> Self {
        Self {
            count: 0,
            positions: None,
            in_text: false,
            in_source: false,
        }
    }

    pub fn lines(&self) -> impl Iterator<Item = usize> + '_ {
        (self.in_text && self.positions.is_none())
            .then_some(0)
            .into_iter()
            .chain(self.positions.iter().flat_map(|posting| posting.lines()))
    }

    pub fn intersects(&self, start: usize, end: usize) -> bool {
        self.positions
            .as_ref()
            .map_or(self.in_text && start == 0, |posting| {
                posting.intersects(start, end)
            })
    }

    fn add_line(&mut self, line: usize) {
        match self.positions.as_deref_mut() {
            Some(LinePosting::Multiple(lines)) => lines.push(line),
            Some(posting @ LinePosting::Single(_)) => {
                if let LinePosting::Single(first) = posting {
                    *posting = LinePosting::Multiple(vec![*first, line]);
                }
            }
            None if self.in_text => {
                self.positions = Some(Box::new(LinePosting::Multiple(vec![0, line])))
            }
            None if line > 0 => self.positions = Some(Box::new(LinePosting::Single(line))),
            None => {}
        }
        self.in_text = true;
    }
}

/// Result of one atomic source replacement. An identical replacement does not advance revision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceUpdate {
    /// New node IDs.
    pub inserted: usize,
    /// Existing node IDs whose document changed.
    pub replaced: usize,
    /// Obsolete node IDs withdrawn from this source.
    pub removed: usize,
    /// Identical documents retained.
    pub unchanged: usize,
    /// Graph revision after this transaction.
    pub revision: u64,
}

/// An incrementally updated in-memory graph belonging to one caller-controlled privacy domain.
pub struct ContextGraph {
    pub(crate) domain: String,
    pub(crate) limits: GraphLimits,
    pub(crate) documents: BTreeMap<String, IndexedDocument>,
    // Store the saturated frequency beside each ID, avoiding random document lookups per term.
    pub(crate) postings: BTreeMap<String, BTreeMap<Arc<str>, u8>>,
    pub(crate) edges: BTreeMap<String, BTreeSet<(EdgeKind, String)>>,
    pub(crate) revision: u64,
    sources: BTreeMap<String, BTreeSet<String>>,
    bytes: usize,
    edge_count: usize,
}

impl ContextGraph {
    /// Creates an empty graph. The domain must identify the application's privacy boundary.
    pub fn new(domain: impl Into<String>, limits: GraphLimits) -> Result<Self, ContextError> {
        let domain = domain.into();
        if domain.is_empty()
            || domain.len() > 256
            || limits.max_documents == 0
            || limits.max_document_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_edges_per_document == 0
            || limits.max_edges == 0
        {
            return Err(ContextError::InvalidInput);
        }
        Ok(Self {
            domain,
            limits,
            documents: BTreeMap::new(),
            postings: BTreeMap::new(),
            edges: BTreeMap::new(),
            revision: 0,
            sources: BTreeMap::new(),
            bytes: 0,
            edge_count: 0,
        })
    }

    /// Number of live source documents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether the graph has no live documents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Current local mutation sequence. Identical upserts do not advance it.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Inserts or replaces one source and updates only its term postings. Returns whether changed.
    pub fn upsert(&mut self, document: Document) -> Result<bool, ContextError> {
        if !valid_id(&document.id)
            || document.source.is_empty()
            || document.source.len() > 2048
            || document.source.chars().any(char::is_control)
            || document.text.trim().is_empty()
            || document.start_line == 0
        {
            return Err(ContextError::InvalidInput);
        }
        let old = self.documents.get(&document.id);
        if old.is_some_and(|value| value.document == document) {
            return Ok(false);
        }
        let bytes = self
            .bytes
            .saturating_sub(old.map_or(0, |v| v.document.text.len()))
            .checked_add(document.text.len())
            .ok_or(ContextError::LimitExceeded)?;
        if document.text.len() > self.limits.max_document_bytes
            || bytes > self.limits.max_total_bytes
            || (old.is_none() && self.len() >= self.limits.max_documents)
        {
            return Err(ContextError::LimitExceeded);
        }
        if document
            .start_line
            .checked_add(document.text.lines().count().saturating_sub(1))
            .is_none()
        {
            return Err(ContextError::LimitExceeded);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        let content_digest = digest("cigar.document.v1", &document)?;
        let text_digest = digest("cigar.document-text.v1", &document.text)?;
        let declarations = declarations(&document.text);
        let mut terms = BTreeMap::<String, IndexedTerm>::new();
        for (line, text) in document.text.lines().enumerate() {
            for (term, count) in term_counts(text) {
                let value = terms.entry(term).or_insert_with(IndexedTerm::new);
                value.count = (usize::from(value.count) + count.min(3)).min(3) as u8;
                value.add_line(line);
            }
        }
        for (term, count) in term_counts(&document.source) {
            let value = terms.entry(term).or_insert_with(IndexedTerm::new);
            value.count = (usize::from(value.count) + count.min(3)).min(3) as u8;
            value.in_source = true;
        }
        self.unindex(&document.id);
        self.sources
            .entry(document.source.clone())
            .or_default()
            .insert(document.id.clone());
        let posting_id: Arc<str> = Arc::from(document.id.as_str());
        for (term, value) in &terms {
            self.postings
                .entry(term.clone())
                .or_default()
                .insert(Arc::clone(&posting_id), value.count);
        }
        self.documents.insert(
            document.id.clone(),
            IndexedDocument {
                document,
                terms,
                digest: content_digest,
                text_digest,
                declarations,
            },
        );
        self.bytes = bytes;
        self.revision = revision;
        Ok(true)
    }

    /// Atomically replaces all documents with this exact source locator, withdrawing obsolete IDs.
    /// Empty input withdraws the source. Every input must use this locator and a distinct ID; IDs
    /// owned by another source are rejected. Validation/indexing completes before live mutation.
    /// Existing edges remain, so references to withdrawn chunks continue to fail closed. This is
    /// not automatic edge migration: callers repair semantic relations explicitly.
    pub fn replace_source(
        &mut self,
        source: &str,
        documents: Vec<Document>,
    ) -> Result<SourceUpdate, ContextError> {
        if source.is_empty() || source.len() > 2048 || source.chars().any(char::is_control) {
            return Err(ContextError::InvalidInput);
        }
        if documents.len() > self.limits.max_documents {
            return Err(ContextError::LimitExceeded);
        }
        let mut staged = Self::new(self.domain.clone(), self.limits)?;
        let mut result = SourceUpdate::default();
        for document in documents {
            if document.source != source || staged.documents.contains_key(&document.id) {
                return Err(ContextError::InvalidInput);
            }
            match self.documents.get(&document.id) {
                Some(old) if old.document.source != source => {
                    return Err(ContextError::InvalidInput);
                }
                Some(old) if old.document == document => result.unchanged += 1,
                Some(_) => result.replaced += 1,
                None => result.inserted += 1,
            }
            staged.upsert(document)?;
        }
        let old_ids = self.sources.get(source).cloned().unwrap_or_default();
        result.removed = old_ids
            .iter()
            .filter(|id| !staged.documents.contains_key(*id))
            .count();
        if result.inserted + result.replaced + result.removed == 0 {
            result.revision = self.revision;
            return Ok(result);
        }
        let removed_bytes = old_ids
            .iter()
            .filter_map(|id| self.documents.get(id))
            .map(|node| node.document.text.len())
            .sum::<usize>();
        let bytes = self
            .bytes
            .checked_sub(removed_bytes)
            .and_then(|v| v.checked_add(staged.bytes))
            .ok_or(ContextError::LimitExceeded)?;
        let count = self.len() - old_ids.len() + staged.len();
        if bytes > self.limits.max_total_bytes || count > self.limits.max_documents {
            return Err(ContextError::LimitExceeded);
        }
        result.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        // No fallible operations after this point. The temporary index bounds staging work and
        // leaves the live graph unchanged on all validation/limit failures.
        for id in old_ids {
            self.unindex(&id);
            self.documents.remove(&id);
        }
        for (term, entries) in staged.postings {
            self.postings.entry(term).or_default().extend(entries);
        }
        self.sources.extend(staged.sources);
        self.documents.extend(staged.documents);
        self.bytes = bytes;
        self.revision = result.revision;
        Ok(result)
    }

    /// Withdraws a document. Incoming hard edges remain so dependents fail closed until repaired.
    pub fn remove(&mut self, id: &str) -> Result<bool, ContextError> {
        let Some(value) = self.documents.get(id) else {
            return Ok(false);
        };
        let bytes = self.bytes.saturating_sub(value.document.text.len());
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        self.unindex(id);
        self.documents.remove(id);
        self.bytes = bytes;
        self.revision = revision;
        Ok(true)
    }

    /// Adds a typed edge. Both endpoints must exist. Contradiction links are symmetric and atomic.
    pub fn link(&mut self, from: &str, to: &str, kind: EdgeKind) -> Result<bool, ContextError> {
        if from == to || !self.documents.contains_key(from) || !self.documents.contains_key(to) {
            return Err(ContextError::InvalidInput);
        }
        let mut additions = vec![(from, to)];
        if kind == EdgeKind::Contradicts {
            additions.push((to, from));
        }
        let changed = additions.iter().any(|(a, b)| {
            !self
                .edges
                .get(*a)
                .is_some_and(|edges| edges.contains(&(kind, (*b).to_owned())))
        });
        if !changed {
            return Ok(false);
        }
        let added_count = additions
            .iter()
            .filter(|(a, b)| {
                !self
                    .edges
                    .get(*a)
                    .is_some_and(|edges| edges.contains(&(kind, (*b).to_owned())))
            })
            .count();
        let edge_count = self
            .edge_count
            .checked_add(added_count)
            .ok_or(ContextError::LimitExceeded)?;
        if edge_count > self.limits.max_edges {
            return Err(ContextError::LimitExceeded);
        }
        for (a, b) in &additions {
            if self.edges.get(*a).is_some_and(|edges| {
                edges.len() >= self.limits.max_edges_per_document
                    && !edges.contains(&(kind, (*b).to_owned()))
            }) {
                return Err(ContextError::LimitExceeded);
            }
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        for (a, b) in additions {
            self.edges
                .entry(a.to_owned())
                .or_default()
                .insert((kind, b.to_owned()));
        }
        self.edge_count = edge_count;
        self.revision = revision;
        Ok(true)
    }

    /// Explicitly removes an edge, including both directions of a contradiction.
    pub fn unlink(&mut self, from: &str, to: &str, kind: EdgeKind) -> Result<bool, ContextError> {
        let present = self
            .edges
            .get(from)
            .is_some_and(|e| e.contains(&(kind, to.to_owned())));
        if !present {
            return Ok(false);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        if let Some(edges) = self.edges.get_mut(from) {
            if edges.remove(&(kind, to.to_owned())) {
                self.edge_count -= 1;
            }
            if edges.is_empty() {
                self.edges.remove(from);
            }
        }
        if kind == EdgeKind::Contradicts
            && let Some(edges) = self.edges.get_mut(to)
        {
            if edges.remove(&(kind, from.to_owned())) {
                self.edge_count -= 1;
            }
            if edges.is_empty() {
                self.edges.remove(to);
            }
        }
        self.revision = revision;
        Ok(true)
    }

    fn unindex(&mut self, id: &str) {
        if let Some(old) = self.documents.get(id) {
            if let Some(ids) = self.sources.get_mut(&old.document.source) {
                ids.remove(id);
                if ids.is_empty() {
                    self.sources.remove(&old.document.source);
                }
            }
            for term in old.terms.keys() {
                if let Some(ids) = self.postings.get_mut(term) {
                    ids.remove(id);
                    if ids.is_empty() {
                        self.postings.remove(term);
                    }
                }
            }
        }
    }
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_graphic())
}

// Lexical relevance, not a parser or authority assertion. Prefer named declarations over
// mentions. Applications requiring exact syntax should supply AST-aware chunks.
fn declarations(text: &str) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for line in text.lines() {
        let tokens = line
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .filter(|word| !word.is_empty())
            .take(8)
            .collect::<Vec<_>>();
        for pair in tokens.windows(2) {
            if pair.first().is_some_and(|word| {
                [
                    "fn",
                    "def",
                    "function",
                    "class",
                    "struct",
                    "enum",
                    "trait",
                    "interface",
                ]
                .contains(word)
            }) && let Some(name) = pair.get(1)
            {
                result.insert(name.to_lowercase());
            }
        }
    }
    result
}

pub(crate) fn term_counts(text: &str) -> BTreeMap<String, usize> {
    let mut terms = BTreeMap::new();
    // Keep complete technical identifiers as well as their searchable components. Splitting
    // resolve_reference_tokenizer_target into only common words destroys its strongest signal.
    for token in text.split(|ch: char| !ch.is_alphanumeric() && ch != '_') {
        let camel = token
            .chars()
            .zip(token.chars().skip(1))
            .any(|(a, b)| a.is_lowercase() && b.is_uppercase());
        if token.len() >= 2 && (token.contains('_') || camel) {
            *terms.entry(token.to_lowercase()).or_default() += 1;
        }
    }
    let mut split = String::with_capacity(text.len());
    let mut previous_lower = false;
    for ch in text.chars() {
        if previous_lower && ch.is_uppercase() {
            split.push(' ');
        }
        split.push(ch);
        previous_lower = ch.is_lowercase();
    }
    for term in split.split(|ch: char| !ch.is_alphanumeric()) {
        if term.len() >= 2 {
            *terms.entry(term.to_lowercase()).or_default() += 1;
        }
    }
    terms
}
