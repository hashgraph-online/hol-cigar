import { WorkerChannel } from "./local-worker.js";
import { LocalContextError, LOCAL_CONTEXT_PROTOCOL, LOCAL_CONTEXT_CORE_VERSION } from "./local-runtime.js";
export { LocalContextError, LOCAL_CONTEXT_PROTOCOL, LOCAL_CONTEXT_CORE_VERSION,
  getLocalContextCapabilities } from "./local-runtime.js";
export type { LocalContextCapabilities, LocalWorkerCapabilities } from "./local-runtime.js";
import type { LocalWorkerCapabilities } from "./local-runtime.js";
import type {
  LocalAnswerAssessment, LocalAnswerDraft, LocalAnswerPolicy, LocalClaimReview,
  LocalCitation, LocalContextDelta, LocalContextLimits, LocalContextPrompt, LocalContextRequest, LocalContextResult, LocalContextSnapshot,
  LocalDocument, LocalEdgeKind, LocalGraphStats, LocalSelectionExplanation, LocalSourceUpdate,
  LocalViewSpec, LocalViewHandle, LocalViewContext, LocalViewResult, LocalViewAssessment,
} from "./context-types.js";

const MAX_FRAME = 32 * 1024 * 1024;
const MAX_RESPONSE = 64 * 1024 * 1024;
const CORE_ERRORS = new Set(["InvalidInput", "LimitExceeded", "RequiredUnavailable", "BudgetUnsatisfiable",
  "Tokenizer", "Integrity", "BaseMismatch"]);

export type LocalContextOptions = Readonly<{
  /** Explicit trusted executable; never searched in PATH or downloaded. */
  workerPath?: string;
  limits?: LocalContextLimits;
  /** Active exchange deadline, including pipe writes. Queue capacity is separately bounded. */
  timeoutMs?: number;
  /** Includes the active request; bounded to 1..128. Default 32. */
  maxPending?: number;
}>;

/** One persistent Rust graph/cache per privacy domain. Use await using or close().
 * No automatic retry/restart: transport failure makes mutation outcome uncertain.
 * Calls are serialized, with bounded pending count and exact-input byte limits.
 */
export class LocalContextGraph implements AsyncDisposable {
  private readonly channel: WorkerChannel;
  private supportsViews = false;
  private workerFeatures: readonly string[] = [];

  private constructor(options: LocalContextOptions) {
    this.channel = new WorkerChannel(options, [], (text, id) => {
      const reply = JSON.parse(text) as {id: number; ok: boolean; result?: unknown; error?: string};
      if (!reply || reply.id !== id || typeof reply.ok !== "boolean" ||
          (reply.ok ? !("result" in reply) : !CORE_ERRORS.has(reply.error ?? ""))) throw new Error();
      return reply.ok ? {ok: true, result: reply.result} : {ok: false, error: new LocalContextError(reply.error!)};
    });
  }

  private call<T>(command: Record<string, unknown>): Promise<T> { return this.channel.call<T>(command); }

  static async create(domain: string, options: LocalContextOptions = {}): Promise<LocalContextGraph> {
    const graph = new LocalContextGraph(options);
    try {
      const hello = await graph.call<Record<string, unknown>>({op: "init", domain, limits: options.limits ?? {}});
      if (!hello || hello.protocol !== LOCAL_CONTEXT_PROTOCOL || hello.core_version !== LOCAL_CONTEXT_CORE_VERSION ||
          hello.max_frame_bytes !== MAX_FRAME || hello.max_response_bytes !== MAX_RESPONSE) {
        throw new LocalContextError("IncompatibleWorker");
      }
      const capabilities: unknown = hello.capabilities ?? [];
      if (!Array.isArray(capabilities) || capabilities.some((value: unknown) => typeof value !== "string")) {
        throw new LocalContextError("IncompatibleWorker");
      }
      graph.supportsViews = capabilities.includes("context_views.v1");
      graph.workerFeatures = [...new Set(capabilities as string[])].sort();
      return graph;
    } catch (error) { await graph.close(); throw error; }
  }

  upsert(document: LocalDocument): Promise<boolean> { return this.call({op: "upsert", document}); }
  /** Negotiated features of this live worker; not a release qualification claim. */
  capabilities(): LocalWorkerCapabilities {
    if (this.channel.closed) throw new LocalContextError("Closed");
    return {
      schema: "cigar.local-worker-capabilities.v1",
      protocol: LOCAL_CONTEXT_PROTOCOL,
      core_version: LOCAL_CONTEXT_CORE_VERSION,
      features: [...this.workerFeatures],
      max_frame_bytes: MAX_FRAME,
      max_response_bytes: MAX_RESPONSE,
      execution: "isolated-process-serialized",
      authority: "trusted-host",
      requires_hol_services: false,
    };
  }
  private viewCall<T>(command: Record<string, unknown>): Promise<T> {
    if (!this.supportsViews) return Promise.reject(new LocalContextError("IncompatibleWorker"));
    if (command.op === "explain_view" && !this.workerFeatures.includes("selection_explanation.v1")) {
      return Promise.reject(new LocalContextError("IncompatibleWorker"));
    }
    return this.call(command);
  }
  /** Define/replace a host-owned source scope. Replacing revokes its old handles.
   * This is logical partitioning in a trusted application, not a sandbox or service capability. */
  async createView(spec: LocalViewSpec): Promise<LocalContextView> {
    const handle = await this.viewCall<LocalViewHandle>({op: "define_view", spec});
    return new LocalContextView(handle, <T>(command: Record<string, unknown>) => this.viewCall<T>(command));
  }
  /** Revoke view access without deleting shared documents. */
  revokeView(viewId: string): Promise<boolean> { return this.viewCall({op: "revoke_view", view_id: viewId}); }
  /** Atomic; [] withdraws a source. Hard edges remain and fail closed until explicitly repaired. */
  replaceSource(source: string, documents: readonly LocalDocument[]): Promise<LocalSourceUpdate> {
    return this.call({op: "replace_source", source, documents});
  }
  remove(nodeId: string): Promise<boolean> { return this.call({op: "remove", node_id: nodeId}); }
  link(from: string, to: string, kind: LocalEdgeKind): Promise<boolean> { return this.call({op: "link", from, to, kind}); }
  unlink(from: string, to: string, kind: LocalEdgeKind): Promise<boolean> { return this.call({op: "unlink", from, to, kind}); }
  /** Rust-rendered context is ordinary data, not an instruction or authorization grant. */
  compile(request: LocalContextRequest): Promise<LocalContextResult> { return this.call({op: "compile", request}); }
  /** Recompile an exact current snapshot; retrieval signals are not truth probabilities. */
  explain(request: LocalContextRequest, snapshot: LocalContextSnapshot): Promise<LocalSelectionExplanation> {
    if (!this.workerFeatures.includes("selection_explanation.v1")) {
      return Promise.reject(new LocalContextError("IncompatibleWorker"));
    }
    return this.call({op: "explain", request, snapshot});
  }
  chunks(document: LocalDocument, maxLines: number, overlapLines = 0): Promise<LocalDocument[]> {
    return this.call({op: "chunks", document, max_lines: maxLines, overlap_lines: overlapLines});
  }
  verify(snapshot: LocalContextSnapshot): Promise<LocalContextResult> { return this.call({op: "verify", snapshot}); }
  /** Compact data-role rendering bound to the complete snapshot and retained citation map. */
  promptView(snapshot: LocalContextSnapshot, maxTokens: number): Promise<LocalContextPrompt> {
    return this.call({op: "prompt_view", snapshot, max_tokens: maxTokens});
  }

  /** Bind claims to a snapshot for a trusted reviewer; this performs no factual judgment. */
  reviewKeys(draft: LocalAnswerDraft): Promise<readonly string[]> {
    return this.call({op: "review_keys", draft});
  }

  /** Recompile current authorized context. Reviews/policy must stay outside model control.
   * Only display assessed claims on release; confidence never grants release permission. */
  checkAnswer(request: LocalContextRequest, draft: LocalAnswerDraft,
    reviews: readonly LocalClaimReview[], policy: LocalAnswerPolicy = {}): Promise<LocalAnswerAssessment> {
    return this.call({op: "check_answer", request, draft, reviews, policy});
  }
  verifyPrompt(prompt: LocalContextPrompt, snapshot: LocalContextSnapshot): Promise<LocalContextPrompt> {
    return this.call({op: "verify_prompt", prompt, snapshot});
  }
  resolveCitation(reference: string, prompt: LocalContextPrompt, snapshot: LocalContextSnapshot): Promise<readonly LocalCitation[]> {
    return this.call({op: "resolve_citation", reference, prompt, snapshot});
  }
  delta(base: LocalContextSnapshot, target: LocalContextSnapshot): Promise<LocalContextDelta> {
    return this.call({op: "delta", base, target});
  }
  applyDelta(base: LocalContextSnapshot, delta: LocalContextDelta): Promise<LocalContextResult> {
    return this.call({op: "apply_delta", base, delta});
  }
  stats(): Promise<LocalGraphStats> { return this.call({op: "stats"}); }
  clearCache(): Promise<null> { return this.call({op: "clear_cache"}); }
  async close(): Promise<void> { await this.channel.close(); }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
}

/** One scoped facade sharing the owner's worker, index and bounded call queue.
 * Keep root access, worker pipes and review authority outside untrusted agent control.
 * Worker failure closes every view; this facade does not retry or restart mutations. */
export class LocalContextView {
  readonly #handle: LocalViewHandle;
  readonly #call: <T>(command: Record<string, unknown>) => Promise<T>;
  constructor(handle: LocalViewHandle, call: <T>(command: Record<string, unknown>) => Promise<T>) {
    this.#handle = Object.freeze({...handle});
    this.#call = call;
  }
  /** Request access may narrow, but never widen, the host-defined view. */
  compile(request: LocalContextRequest): Promise<LocalViewResult> {
    return this.#call({op: "compile_view", view: this.#handle, request});
  }
  /** Revalidate this whole view, then explain only selected evidence. */
  explain(context: LocalViewContext): Promise<LocalSelectionExplanation> {
    return this.#call({op: "explain_view", view: this.#handle, context});
  }
  replaceSource(source: string, documents: readonly LocalDocument[]): Promise<LocalSourceUpdate> {
    return this.#call({op: "replace_view_source", view: this.#handle, source, documents});
  }
  /** Draft snapshot_id is context.snapshot.id; existing review identities remain unchanged. */
  reviewKeys(draft: LocalAnswerDraft): Promise<readonly string[]> { return this.#call({op: "review_keys", draft}); }
  /** Freshly recompile and recheck the whole readable scope. Unrelated outside writes are allowed;
   * any authorized source/edge change invalidates. This grants no external effect authority. */
  checkAnswer(context: LocalViewContext, draft: LocalAnswerDraft, reviews: readonly LocalClaimReview[],
    policy: LocalAnswerPolicy = {}): Promise<LocalViewAssessment> {
    return this.#call({op: "check_view_answer", view: this.#handle, context, draft, reviews, policy});
  }
}
