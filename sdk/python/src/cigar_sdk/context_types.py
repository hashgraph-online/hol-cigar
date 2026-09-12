"""Typed wire values for the local Rust graph (separate from the frozen remote ABI)."""

from typing import Literal, NotRequired, TypedDict

LocalEdgeKind = Literal["requires", "contradicts", "supports", "related"]


class LocalDocument(TypedDict):
    id: str
    source: str
    text: str
    start_line: NotRequired[int]


class LocalContextLimits(TypedDict, total=False):
    max_documents: int
    max_document_bytes: int
    max_total_bytes: int
    max_edges_per_document: int
    max_edges: int
    cache_entries: int
    cache_text_bytes: int


class LocalContextRequest(TypedDict, total=False):
    query: str
    max_tokens: int
    reserve_tokens: int
    required: list[str]
    allowed: list[str] | None
    semantic_candidates: list[str]
    policy_revision: str
    max_candidates: int
    max_blocks: int
    graph_depth: int
    evidence_per_term: int
    excerpt_mode: Literal["full", "query_windows"]


class LocalCitation(TypedDict):
    node_id: str
    source: str
    document_digest: str
    start_line: int
    end_line: int


class LocalContextPrompt(TypedDict):
    schema: Literal["cigar.context-prompt.v1"]
    id: str
    snapshot_id: str
    tokenizer: str
    rendered: str
    rendered_tokens: int
    max_tokens: int
    citations: dict[str, list[LocalCitation]]


class LocalEvidenceBlock(TypedDict):
    text: str
    citations: list[LocalCitation]


class LocalSelectionStats(TypedDict):
    documents: int
    lexical_matches: int
    candidates: int
    selected_blocks: int
    selected_sources: int
    query_terms: int
    covered_terms: int
    rendered_tokens: int
    available_tokens: int
    unavailable_roots: int
    limit_rejected_roots: int
    budget_rejected_roots: int


class LocalContextSnapshot(TypedDict):
    id: str
    domain: str
    policy_revision: str
    tokenizer: str
    graph_revision: int
    blocks: list[LocalEvidenceBlock]
    stats: LocalSelectionStats


class LocalContextResult(TypedDict):
    snapshot: LocalContextSnapshot
    rendered: str


class LocalContextDelta(TypedDict):
    base_id: str
    target_id: str
    graph_revision: int
    stats: LocalSelectionStats
    order: list[str]
    added: list[LocalEvidenceBlock]


class LocalSourceUpdate(TypedDict):
    inserted: int
    replaced: int
    removed: int
    unchanged: int
    revision: int


class LocalTokenCacheStats(TypedDict):
    hits: int
    misses: int
    entries: int
    text_bytes: int


class LocalGraphStats(TypedDict):
    documents: int
    revision: int
    cache: LocalTokenCacheStats
