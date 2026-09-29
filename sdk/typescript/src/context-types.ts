/** Local graph wire values; these do not replace the frozen remote Context ABI. */
export type LocalEdgeKind = "requires" | "contradicts" | "supports" | "related";
export type LocalAnswerClaim = Readonly<{text: string; citations: readonly string[]; confidence_bps: number | null}>;
export type LocalAnswerDraft = Readonly<{snapshot_id: string; claims: readonly LocalAnswerClaim[]; abstain?: boolean}>;
/** Host-trusted judgment, supplied separately from untrusted model output. */
export type LocalClaimReview = Readonly<{
  claim_key: string; verdict: "supported" | "unsupported" | "contradicted" | "unknown";
  reviewed_counterevidence?: readonly string[];
}>;
export type LocalAnswerPolicy = Readonly<{min_sources?: number; high_confidence_bps?: number}>;
export type LocalClaimAssessment = Readonly<{
  claim_key: string; independent_sources: number;
  issues: readonly ("uncited" | "invalid_citation" | "insufficient_sources" | "unreviewed" |
    "unsupported" | "contradicted" | "unknown" | "unreviewed_counterevidence")[];
}>;
export type LocalAnswerAssessment = Readonly<{
  snapshot_id: string; draft_id: string; decision: "release" | "abstain";
  claims: readonly LocalClaimAssessment[]; confident_failures: number; missing_confidence: number;
}>;
export type LocalDocument = Readonly<{id: string; source: string; text: string; start_line?: number}>;
export type LocalContextLimits = Readonly<{
  max_documents?: number; max_document_bytes?: number; max_total_bytes?: number;
  max_edges_per_document?: number; max_edges?: number; cache_entries?: number; cache_text_bytes?: number;
}>;
export type LocalContextRequest = Readonly<{
  query?: string; max_tokens?: number; reserve_tokens?: number; required?: readonly string[];
  allowed?: readonly string[] | null; semantic_candidates?: readonly string[]; policy_revision?: string;
  max_candidates?: number; max_blocks?: number; graph_depth?: number; evidence_per_term?: number;
  excerpt_mode?: "full" | "query_windows";
}>;
export type LocalCitation = Readonly<{
  node_id: string; source: string; document_digest: string; start_line: number; end_line: number;
}>;
export type LocalEvidenceBlock = Readonly<{text: string; citations: readonly LocalCitation[]}>;
export type LocalSelectionStats = Readonly<{
  documents: number; lexical_matches: number; candidates: number; selected_blocks: number;
  selected_sources: number; query_terms: number; covered_terms: number; rendered_tokens: number;
  available_tokens: number; unavailable_roots: number; limit_rejected_roots: number; budget_rejected_roots: number;
}>;
export type LocalContextSnapshot = Readonly<{
  id: string; domain: string; policy_revision: string; tokenizer: string; graph_revision: number;
  blocks: readonly LocalEvidenceBlock[]; stats: LocalSelectionStats;
}>;
export type LocalContextResult = Readonly<{snapshot: LocalContextSnapshot; rendered: string}>;
export type LocalSelectionSignal = "required" | "lexical_match" | "declaration_match" |
  "semantic_candidate" | "graph_expansion";
export type LocalSelectionStep = Readonly<{
  root_id: string; added_ids: readonly string[]; signals: readonly LocalSelectionSignal[];
}>;
/** Current selection trace, not truth confidence or execution authority. Contains selected IDs. */
export type LocalSelectionExplanation = Readonly<{
  schema: "cigar.context-selection-explanation.v1";
  snapshot_id: string; request_id: string; checked_graph_revision: number; tokenizer: string;
  steps: readonly LocalSelectionStep[];
}>;
export type LocalContextPrompt = Readonly<{
  schema: "cigar.context-prompt.v1"; id: string; snapshot_id: string; tokenizer: string;
  rendered: string; rendered_tokens: number; max_tokens: number;
  citations: Readonly<Record<string, readonly LocalCitation[]>>;
}>;
export type LocalContextDelta = Readonly<{
  base_id: string; target_id: string; graph_revision: number; stats: LocalSelectionStats;
  order: readonly string[]; added: readonly LocalEvidenceBlock[];
}>;
export type LocalSourceUpdate = Readonly<{
  inserted: number; replaced: number; removed: number; unchanged: number; revision: number;
}>;
export type LocalGraphStats = Readonly<{
  documents: number; revision: number;
  cache: Readonly<{hits: number; misses: number; entries: number; text_bytes: number}>;
}>;

/** Host-owned source scope. Keep definition and root graph access outside agent control. */
export type LocalViewSpec = Readonly<{
  id: string; allowed_sources: readonly string[]; writable_sources?: readonly string[]; policy_revision: string;
}>;
/** Session-local routing identity, not a bearer credential or signed capability. */
export type LocalViewHandle = Readonly<{id: string; generation: number}>;
export type LocalViewContext = Readonly<{
  id: string; view: LocalViewHandle; request: LocalContextRequest; scope_id: string; snapshot: LocalContextSnapshot;
}>;
export type LocalViewResult = Readonly<{context: LocalViewContext; rendered: string}>;
export type LocalViewAssessment = Readonly<{
  context_id: string; checked_graph_revision: number; assessment: LocalAnswerAssessment;
}>;
