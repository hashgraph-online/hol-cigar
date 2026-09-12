use crate::graph::term_counts;
use crate::{
    Citation, ContextError, ContextGraph, ContextSnapshot, EdgeKind, EvidenceBlock, TokenCounter,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// Source representation for optional query matches. Hard dependencies always use complete text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcerptMode {
    /// Include complete source documents.
    #[default]
    Full,
    /// Include matching line windows with neighboring lines and explicit source ranges.
    QueryWindows,
}

/// A bounded query against one local graph. Authorization is supplied by the owning application.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextRequest {
    /// Natural-language query or code identifiers.
    pub query: String,
    /// Maximum context-text tokens, before subtracting `reserve_tokens`.
    pub max_tokens: usize,
    /// Caller allowance for system prompt, history, output, and provider framing.
    pub reserve_tokens: usize,
    /// Exact IDs that must appear, with their complete hard closure.
    pub required: BTreeSet<String>,
    /// Authorized IDs for this call; `None` means all documents in this caller-owned local graph.
    pub allowed: Option<BTreeSet<String>>,
    /// Optional ranked IDs from an application-supplied semantic retriever. Every ID is still
    /// filtered by `allowed`. Rank, not an incompatible model similarity scale, supplies the gain.
    pub semantic_candidates: Vec<String>,
    /// Application policy revision; changing it invalidates delta reuse.
    pub policy_revision: String,
    /// Maximum candidate roots retained after lexical lookup and graph expansion.
    pub max_candidates: usize,
    /// Maximum physical evidence blocks in the output, including hard closure.
    pub max_blocks: usize,
    /// Maximum optional graph-expansion depth. Hard closure is never silently truncated.
    pub graph_depth: usize,
    /// Number of distinct source witnesses sought for each query term, between one and four.
    pub evidence_per_term: usize,
    /// Representation mode for optional roots.
    pub excerpt_mode: ExcerptMode,
}

impl Default for ContextRequest {
    fn default() -> Self {
        Self {
            query: String::new(),
            max_tokens: 4096,
            reserve_tokens: 0,
            required: BTreeSet::new(),
            allowed: None,
            semantic_candidates: Vec::new(),
            policy_revision: "local-owner.v1".to_owned(),
            max_candidates: 256,
            max_blocks: 16,
            graph_depth: 2,
            evidence_per_term: 1,
            excerpt_mode: ExcerptMode::Full,
        }
    }
}

/// Content-free statistics. Coverage counts describe lexical query concepts, not answer quality.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionStats {
    /// Live documents at query time.
    pub documents: usize,
    /// Authorized documents matching at least one indexed term.
    pub lexical_matches: usize,
    /// Roots considered after bounded expansion.
    pub candidates: usize,
    /// Physical blocks in the result.
    pub selected_blocks: usize,
    /// Sources represented by selected blocks, including exact-text aliases.
    pub selected_sources: usize,
    /// Distinct non-stopword query terms.
    pub query_terms: usize,
    /// Query terms covered by at least one selected source's indexed text or locator.
    pub covered_terms: usize,
    /// Final exact rendered-text token count, including citations.
    pub rendered_tokens: usize,
    /// Available context-text budget after the caller reserve.
    pub available_tokens: usize,
    /// Optional roots refused because their hard closure was unavailable or unauthorized.
    pub unavailable_roots: usize,
    /// Optional roots refused because their hard closure exceeded the candidate bound.
    pub limit_rejected_roots: usize,
    /// Optional roots refused because their complete representation did not fit the budget.
    pub budget_rejected_roots: usize,
}

struct Root<'a> {
    id: &'a str,
    score: u64,
    depth: usize,
    semantic: bool,
    declarations: usize,
}

#[derive(Default)]
struct Witnesses {
    sources: BTreeSet<String>,
    content: BTreeSet<String>,
}

impl ContextGraph {
    fn scored_roots<'a>(
        &'a self,
        request: &ContextRequest,
        terms: &BTreeSet<String>,
        total: usize,
    ) -> (BTreeMap<String, u64>, Vec<Root<'a>>, usize) {
        let allowed = |id: &str| request.allowed.as_ref().is_none_or(|ids| ids.contains(id));
        let work = terms
            .iter()
            .filter_map(|term| self.postings.get(term))
            .fold(0_usize, |count, posting| {
                count.saturating_add(posting.len())
            });
        let dense = self.slots.len() > 512 && work > self.slots.len() / 4;
        let authorization = (dense && request.allowed.is_some()).then(|| {
            let mut slots = vec![false; self.slots.len()];
            if let Some(ids) = &request.allowed {
                for node in ids.iter().filter_map(|id| self.documents.get(id)) {
                    if let Some(entry) = slots.get_mut(node.slot) {
                        *entry = true;
                    }
                }
            }
            slots
        });
        let slot_allowed = |slot: usize| {
            authorization
                .as_ref()
                .is_none_or(|slots| slots.get(slot).copied().unwrap_or(false))
        };
        let mut weights = BTreeMap::new();
        let mut sparse = HashMap::<&str, u64>::new();
        let mut scores = if dense {
            vec![0_u64; self.slots.len()]
        } else {
            Vec::new()
        };
        let mut touched = Vec::new();
        for term in terms {
            let Some(posting) = self.postings.get(term) else {
                continue;
            };
            let frequency = if request.allowed.is_none() {
                posting.len()
            } else if dense {
                posting
                    .values()
                    .filter(|entry| slot_allowed(entry.slot))
                    .count()
            } else {
                posting.keys().filter(|id| allowed(id)).count()
            };
            // Preserve the integer score and authorized corpus statistics exactly.
            let weight = 1000 + (1000 * total as u64 / (frequency as u64 + 1)).min(100_000);
            weights.insert(term.clone(), weight);
            if dense {
                for entry in posting.values().filter(|entry| slot_allowed(entry.slot)) {
                    if let Some(score) = scores.get_mut(entry.slot) {
                        if *score == 0 {
                            touched.push(entry.slot);
                        }
                        *score += weight * (3 + u64::from(entry.count));
                    }
                }
            } else {
                for (id, entry) in posting.iter().filter(|(id, _)| allowed(id)) {
                    *sparse.entry(id).or_default() += weight * (3 + u64::from(entry.count));
                }
            }
        }
        let lexical_matches = if dense { touched.len() } else { sparse.len() };
        for (rank, id) in request.semantic_candidates.iter().enumerate() {
            let Some(node) = self.documents.get(id) else {
                continue;
            };
            if dense {
                if slot_allowed(node.slot)
                    && let Some(score) = scores.get_mut(node.slot)
                {
                    if *score == 0 {
                        touched.push(node.slot);
                    }
                    *score += 600_000 / (60 + rank as u64);
                }
            } else if allowed(id) {
                *sparse.entry(id).or_default() += 600_000 / (60 + rank as u64);
            }
        }
        let semantic = request
            .semantic_candidates
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let root = |node: &'a crate::graph::IndexedDocument, score| Root {
            declarations: node.declarations.intersection(terms).count(),
            semantic: semantic.contains(node.document.id.as_str()),
            id: node.document.id.as_str(),
            score,
            depth: 0,
        };
        let roots = if dense {
            touched
                .into_iter()
                .filter_map(|slot| {
                    self.slots
                        .get(slot)
                        .and_then(Option::as_deref)
                        .zip(scores.get(slot))
                        .map(|(node, score)| root(node, *score))
                })
                .collect()
        } else {
            sparse
                .into_iter()
                .filter_map(|(id, score)| self.documents.get(id).map(|node| root(node, score)))
                .collect()
        };
        (weights, roots, lexical_matches)
    }

    /// Retrieves, expands, selects, cites, and seals a context snapshot using exact final counts.
    /// Every selected hard dependency and counterclaim must be authorized and fit in full.
    pub fn compile(
        &self,
        request: &ContextRequest,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextSnapshot, ContextError> {
        validate(request, tokenizer)?;
        let available = request.max_tokens - request.reserve_tokens;
        let terms = query_terms(&request.query);
        if terms.len() > 64 {
            return Err(ContextError::LimitExceeded);
        }
        let allowed = |id: &str| request.allowed.as_ref().is_none_or(|ids| ids.contains(id));
        let total = request.allowed.as_ref().map_or(self.len(), |ids| {
            ids.iter()
                .filter(|id| self.documents.contains_key(*id))
                .count()
        });
        let (weights, mut roots, lexical_matches) = self.scored_roots(request, &terms, total);
        let rank = |a: &Root<'_>, b: &Root<'_>| {
            b.declarations
                .cmp(&a.declarations)
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| a.id.cmp(b.id))
        };
        let seed_limit = if request.graph_depth == 0 {
            request.max_candidates
        } else {
            request.max_candidates.div_ceil(2)
        };
        // Select exactly the same total-order prefix without sorting every matching document.
        // Hash iteration order cannot affect the result: document IDs break every score tie.
        if roots.len() > seed_limit {
            roots.select_nth_unstable_by(seed_limit, rank);
            roots.truncate(seed_limit);
        }
        roots.sort_by(rank);
        let mut seen = roots.iter().map(|r| r.id).collect::<BTreeSet<_>>();
        let mut queue = roots
            .iter()
            .map(|r| (r.id, r.score, 0))
            .collect::<VecDeque<_>>();
        // Reserve space for graph leads without evicting stronger lexical matches. The queue
        // has a fixed bound even for cyclic, dense, or adversarial graphs.
        while let Some((id, score, depth)) = queue.pop_front() {
            if depth >= request.graph_depth || roots.len() >= request.max_candidates {
                continue;
            }
            if let Some(edges) = self.edges.get(id) {
                for (kind, target) in edges {
                    if roots.len() >= request.max_candidates {
                        break;
                    }
                    if !allowed(target)
                        || !self.documents.contains_key(target)
                        || !seen.insert(target.as_str())
                    {
                        continue;
                    }
                    let divisor = if *kind == EdgeKind::Related { 4 } else { 2 };
                    let next = score / divisor;
                    roots.push(Root {
                        declarations: self
                            .documents
                            .get(target)
                            .map_or(0, |node| node.declarations.intersection(&terms).count()),
                        id: target,
                        score: next,
                        depth: depth + 1,
                        semantic: false,
                    });
                    queue.push_back((target, next, depth + 1));
                }
            }
        }
        let mut selected = BTreeSet::new();
        let mut blocks = Vec::new();
        let mut coverage = BTreeMap::<String, Witnesses>::new();
        for id in &request.required {
            let closure = self.hard_closure(id, request)?;
            if selected.union(&closure).count() > request.max_candidates {
                return Err(ContextError::LimitExceeded);
            }
            let additions = self.blocks_for(&closure, &selected, &terms, None)?;
            append_coalesced(&mut blocks, additions);
            selected.extend(closure);
            if blocks.len() > request.max_blocks {
                return Err(ContextError::BudgetUnsatisfiable);
            }
        }
        if blocks.len() > request.max_blocks
            || tokenizer.count(&crate::snapshot::render(&blocks))? > available
        {
            return Err(ContextError::BudgetUnsatisfiable);
        }
        self.add_coverage(&blocks, &terms, &mut coverage);
        let mut unavailable = 0;
        let mut limit_rejected = 0;
        let mut budget_rejected = 0;
        let hard_nodes = self
            .edges
            .iter()
            .filter(|_| request.excerpt_mode == ExcerptMode::QueryWindows)
            .filter(|(id, _)| allowed(id))
            .flat_map(|(from, edges)| {
                edges
                    .iter()
                    .filter(|(kind, _)| matches!(kind, EdgeKind::Requires | EdgeKind::Contradicts))
                    .flat_map(move |(_, to)| [from.clone(), to.clone()])
            })
            .chain(request.required.iter().cloned())
            .collect::<BTreeSet<_>>();
        // Build and tokenize root closures once. Coverage changes only utility, not source bytes.
        let mut prepared = Vec::new();
        for root in roots {
            if selected.contains(root.id) {
                continue;
            }
            match self.hard_closure(root.id, request) {
                Ok(closure) => {
                    let excerpt_root = (request.excerpt_mode == ExcerptMode::QueryWindows
                        && closure.len() == 1
                        && !hard_nodes.contains(root.id))
                    .then_some(root.id);
                    let values =
                        self.blocks_for(&closure, &BTreeSet::new(), &terms, excerpt_root)?;
                    let cost = tokenizer.count(&crate::snapshot::render(&values))?.max(1);
                    let retained = if excerpt_root.is_none() {
                        closure
                            .iter()
                            .filter_map(|id| {
                                self.documents.get(id).map(|node| {
                                    (
                                        id.clone(),
                                        terms
                                            .iter()
                                            .filter(|term| node.terms.contains_key(*term))
                                            .cloned()
                                            .collect::<BTreeSet<_>>(),
                                    )
                                })
                            })
                            .collect()
                    } else {
                        self.retained_terms(&values, &terms)
                    };
                    prepared.push((root, closure, values, cost, retained));
                }
                Err(ContextError::RequiredUnavailable) => unavailable += 1,
                Err(ContextError::LimitExceeded) => limit_rejected += 1,
                Err(error) => return Err(error),
            }
        }
        let candidate_count = prepared.len() + unavailable + limit_rejected;
        while !prepared.is_empty() && blocks.len() < request.max_blocks {
            let retained_selected = self.retained_terms(&blocks, &terms);
            let covered_declarations = selected
                .iter()
                .filter_map(|id| self.documents.get(id).map(|node| (id, node)))
                .flat_map(|(id, node)| {
                    node.declarations
                        .intersection(&terms)
                        .filter(|term| {
                            retained_selected
                                .get(id)
                                .is_some_and(|words| words.contains(*term))
                        })
                        .cloned()
                })
                .collect::<BTreeSet<_>>();
            let mut best = None;
            for (index, (root, closure, _, cost, retained)) in prepared.iter().enumerate() {
                if closure.is_subset(&selected) {
                    continue;
                }
                let mut gain = 0_u64;
                let mut new_declaration = false;
                for id in closure {
                    if let Some(node) = self.documents.get(id) {
                        for term in node.declarations.intersection(&terms) {
                            if !covered_declarations.contains(term)
                                && retained.get(id).is_some_and(|words| words.contains(term))
                            {
                                new_declaration = true;
                                gain += weights.get(term).copied().unwrap_or(1000) * 20;
                            }
                        }
                    }
                }
                for (term, weight) in &weights {
                    let witnessed = coverage.get(term).map_or(0, |v| v.sources.len());
                    if witnessed >= request.evidence_per_term {
                        continue;
                    }
                    if closure.iter().any(|id| {
                        self.documents.get(id).is_some_and(|node| {
                            retained.get(id).is_some_and(|terms| terms.contains(term))
                                && !coverage.get(term).is_some_and(|v| {
                                    v.sources.contains(&node.document.source)
                                        || v.content.contains(&node.text_digest)
                                })
                        })
                    }) {
                        gain += weight * 10 / (witnessed as u64 + 1);
                    }
                }
                // Explicit supporting leads can add evidence without repeating the query words.
                if root.depth > 0 || root.semantic {
                    gain += root.score / 2;
                }
                if gain == 0 {
                    continue;
                }
                let value = gain + root.score / 16;
                if best.is_none_or(
                    |(_, best_value, best_cost, best_declaration): (usize, u64, usize, bool)| {
                        (new_declaration && !best_declaration)
                            || (new_declaration == best_declaration
                                && u128::from(value) * best_cost as u128
                                    > u128::from(best_value) * *cost as u128)
                    },
                ) {
                    best = Some((index, value, *cost, new_declaration));
                }
            }
            let Some((index, _, _, _)) = best else {
                break;
            };
            let (_, closure, additions, _, _) = prepared.remove(index);
            let mut proposed = blocks.clone();
            append_coalesced(
                &mut proposed,
                additions
                    .into_iter()
                    .filter(|block| {
                        !block
                            .citations
                            .iter()
                            .all(|citation| selected.contains(&citation.node_id))
                    })
                    .collect(),
            );
            if proposed.len() > request.max_blocks
                || tokenizer.count(&crate::snapshot::render(&proposed))? > available
            {
                budget_rejected += 1;
                continue;
            }
            blocks = proposed;
            selected.extend(closure);
            self.add_coverage(&blocks, &terms, &mut coverage);
        }
        let tokens = tokenizer.count(&crate::snapshot::render(&blocks))?;
        let stats = SelectionStats {
            documents: total,
            lexical_matches,
            candidates: candidate_count,
            selected_blocks: blocks.len(),
            selected_sources: selected.len(),
            query_terms: terms.len(),
            covered_terms: coverage.len(),
            rendered_tokens: tokens,
            available_tokens: available,
            unavailable_roots: unavailable,
            limit_rejected_roots: limit_rejected,
            budget_rejected_roots: budget_rejected,
        };
        let snapshot = ContextSnapshot::seal(
            &self.domain,
            &request.policy_revision,
            tokenizer.identity(),
            self.revision,
            blocks,
            stats,
        )?;
        snapshot.verify(tokenizer)?;
        Ok(snapshot)
    }

    fn hard_closure(
        &self,
        root: &str,
        request: &ContextRequest,
    ) -> Result<BTreeSet<String>, ContextError> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![root.to_owned()];
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if seen.len() > request.max_candidates {
                return Err(ContextError::LimitExceeded);
            }
            if !self.documents.contains_key(&id)
                || request
                    .allowed
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(&id))
            {
                return Err(ContextError::RequiredUnavailable);
            }
            if let Some(edges) = self.edges.get(&id) {
                for (kind, target) in edges {
                    if matches!(kind, EdgeKind::Requires | EdgeKind::Contradicts) {
                        pending.push(target.clone());
                    }
                }
            }
        }
        Ok(seen)
    }

    fn add_coverage(
        &self,
        blocks: &[EvidenceBlock],
        terms: &BTreeSet<String>,
        coverage: &mut BTreeMap<String, Witnesses>,
    ) {
        for (id, retained) in self.retained_terms(blocks, terms) {
            if let Some(node) = self.documents.get(&id) {
                for term in terms {
                    if retained.contains(term) {
                        let witnesses = coverage.entry(term.clone()).or_default();
                        if !witnesses.sources.contains(&node.document.source)
                            && !witnesses.content.contains(&node.text_digest)
                        {
                            witnesses.sources.insert(node.document.source.clone());
                            witnesses.content.insert(node.text_digest.clone());
                        }
                    }
                }
            }
        }
    }

    fn blocks_for(
        &self,
        ids: &BTreeSet<String>,
        selected: &BTreeSet<String>,
        terms: &BTreeSet<String>,
        excerpt_root: Option<&str>,
    ) -> Result<Vec<EvidenceBlock>, ContextError> {
        let mut blocks = Vec::new();
        for id in ids.difference(selected) {
            let node = self
                .documents
                .get(id)
                .ok_or(ContextError::RequiredUnavailable)?;
            let text = &node.document.text;
            if excerpt_root != Some(id.as_str()) {
                blocks.push(EvidenceBlock::new(
                    text.clone(),
                    vec![Citation {
                        node_id: id.clone(),
                        source: node.document.source.clone(),
                        document_digest: node.digest.clone(),
                        start_line: node.document.start_line,
                        end_line: node.document.start_line + text.lines().count() - 1,
                    }],
                )?);
                continue;
            }
            let lines = text.lines().collect::<Vec<_>>();
            let matching_lines = terms
                .iter()
                .filter_map(|term| node.terms.get(term))
                .flat_map(|value| value.lines())
                .collect::<BTreeSet<_>>();
            let ranges = windows(lines.len(), matching_lines);
            let mut excerpts = Vec::new();
            let mut citations = Vec::new();
            for (start, end) in ranges {
                let content = lines
                    .get(start..end)
                    .ok_or(ContextError::Integrity)?
                    .join("\n");
                excerpts.push(content);
                citations.push(Citation {
                    node_id: id.clone(),
                    source: node.document.source.clone(),
                    document_digest: node.digest.clone(),
                    start_line: node.document.start_line + start,
                    end_line: node.document.start_line + (end - 1),
                });
            }
            let body = excerpts.join("\n[… omitted …]\n");
            blocks.push(EvidenceBlock::new(body, citations)?);
        }
        Ok(blocks)
    }

    // All blocks here were constructed from this graph. Query-term line postings let us compute
    // precisely the old retained-text coverage without repeatedly analyzing each candidate body.
    fn retained_terms(
        &self,
        blocks: &[EvidenceBlock],
        terms: &BTreeSet<String>,
    ) -> BTreeMap<String, BTreeSet<String>> {
        let mut retained = BTreeMap::new();
        for block in blocks {
            for citation in &block.citations {
                let Some(node) = self.documents.get(&citation.node_id) else {
                    continue;
                };
                let words = retained
                    .entry(citation.node_id.clone())
                    .or_insert_with(BTreeSet::new);
                for term in terms {
                    if node.terms.get(term).is_some_and(|value| {
                        value.in_source || {
                            let start = citation.start_line - node.document.start_line;
                            let end = citation.end_line - node.document.start_line;
                            value.intersects(start, end)
                        }
                    }) || (term == "omitted" && block.text.contains("\n[… omitted …]\n"))
                    {
                        words.insert(term.clone());
                    }
                }
            }
        }
        retained
    }
}

fn append_coalesced(blocks: &mut Vec<EvidenceBlock>, additions: Vec<EvidenceBlock>) {
    for block in additions {
        if let Some(existing) = blocks
            .iter_mut()
            .find(|existing| existing.text == block.text)
        {
            existing.citations.extend(block.citations);
            existing.citations.sort();
            existing.citations.dedup();
        } else {
            blocks.push(block);
        }
    }
}

fn windows(line_count: usize, matching_lines: BTreeSet<usize>) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for index in matching_lines {
        let start = index.saturating_sub(1);
        let end = index.saturating_add(2).min(line_count);
        if let Some(last) = ranges.last_mut()
            && start <= last.1
        {
            last.1 = end;
            continue;
        }
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        ranges.push((0, line_count));
    }
    ranges
}

fn query_terms(text: &str) -> BTreeSet<String> {
    const STOP: &[&str] = &[
        "the", "and", "for", "with", "from", "that", "this", "what", "which", "how", "does", "are",
        "was", "were", "into", "can", "should", "please", "about", "then", "than",
    ];
    term_counts(text)
        .into_keys()
        .filter(|term| !STOP.contains(&term.as_str()))
        .collect()
}

fn validate(request: &ContextRequest, tokenizer: &impl TokenCounter) -> Result<(), ContextError> {
    if request.query.trim().is_empty() && request.required.is_empty()
        || request.query.len() > 8192
        || request.max_tokens <= request.reserve_tokens
        || request.max_tokens > 16_777_216
        || !(1..=4096).contains(&request.max_candidates)
        || request.max_blocks == 0
        || request.max_blocks > request.max_candidates
        || request.required.len() > request.max_candidates
        || request.semantic_candidates.len() > request.max_candidates
        || request
            .semantic_candidates
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.semantic_candidates.len()
        || request.graph_depth > 8
        || !(1..=4).contains(&request.evidence_per_term)
        || request.policy_revision.is_empty()
        || request.policy_revision.len() > 256
        || tokenizer.identity().is_empty()
        || tokenizer.identity().len() > 256
    {
        return Err(ContextError::InvalidInput);
    }
    Ok(())
}
