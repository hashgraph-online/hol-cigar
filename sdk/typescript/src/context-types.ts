/** Local graph wire values; these do not replace the frozen remote Context ABI. */
export type LocalEdgeKind = "requires" | "contradicts" | "supports" | "related";
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
