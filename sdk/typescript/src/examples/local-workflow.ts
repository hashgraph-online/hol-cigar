/** Offline integration example. The fixture reviewer is not a general factuality judge. */
import assert from "node:assert/strict";
import { LocalContextGraph, LocalContextError } from "../context-api.js";
import type { LocalAnswerDraft, LocalClaimReview, LocalContextOptions } from "../context-api.js";

const INITIAL_POLICY = "Retry at most three times and preserve the operation ID.";
const UPDATED_POLICY = "Retry at most once and preserve the operation ID.";
const POLICY_ID = "retry.policy";

// These verdicts come from the example's separately authored, known fixture facts.
// For arbitrary documents, replace this with your authenticated semantic reviewer.
// Never let the answer generator supply its own verdict, policy or authorized IDs.
async function reviewFixture(graph: LocalContextGraph, draft: LocalAnswerDraft,
  knownPolicy: string): Promise<LocalClaimReview[]> {
  const keys = await graph.reviewKeys(draft);
  return draft.claims.map((claim, index) => ({
    claim_key: keys[index]!,
    verdict: claim.citations.length !== 1 || claim.citations[0] !== POLICY_ID ? "unknown" :
      claim.text === knownPolicy ? "supported" : claim.text === "Retry thirty times." ? "contradicted" : "unknown",
  }));
}

/** In a service, retain this graph across requests within one privacy domain. */
export async function runLocalWorkflow(options: LocalContextOptions = {}) {
  const graph = await LocalContextGraph.create("local-workflow-example", options);
  try {
    // The application reads approved files and supplies text. A source locator is not opened.
    await graph.replaceSource("src/retry.ts", [{id: "retry.impl", source: "src/retry.ts",
      text: "export const retryLimit = 3; // Preserve the operation ID."}]);
    await graph.replaceSource("docs/retry.md", [{id: POLICY_ID, source: "docs/retry.md", text: INITIAL_POLICY}]);
    await graph.link("retry.impl", POLICY_ID, "requires");
    const request = {query: "retry", required: ["retry.impl"], allowed: ["retry.impl", POLICY_ID],
      policy_revision: "example-access-v1", max_tokens: 1024, reserve_tokens: 128};
    const compiled = await graph.compile(request);
    assert.ok(compiled.snapshot.stats.rendered_tokens <= 896);
    assert.deepEqual(await graph.verify(compiled.snapshot), compiled);

    const hits = (await graph.stats()).cache.hits;
    assert.deepEqual(await graph.compile(request), compiled);
    assert.ok((await graph.stats()).cache.hits > hits);
    const prompt = await graph.promptView(compiled.snapshot, 896);
    await graph.verifyPrompt(prompt, compiled.snapshot);
    const handle = Object.keys(prompt.citations).find(key => prompt.citations[key]!.some(c => c.node_id === POLICY_ID));
    assert.ok(handle);
    const citations = await graph.resolveCitation(handle, prompt, compiled.snapshot);
    const nodeIds = [...new Set(citations.map(citation => citation.node_id))];

    // A real generator receives prompt.rendered as data. This offline demo authors its draft.
    const draft: LocalAnswerDraft = {snapshot_id: compiled.snapshot.id,
      claims: [{text: INITIAL_POLICY, citations: nodeIds, confidence_bps: 9900}]};
    const reviews = await reviewFixture(graph, draft, INITIAL_POLICY);
    const assessment = await graph.checkAnswer(request, draft, reviews);
    assert.equal(assessment.decision, "release");
    // Display only these assessed claims after release, never extra unreviewed prose.
    const releasedClaims = assessment.decision === "release" ? draft.claims.map(claim => claim.text) : [];
    assert.equal((await graph.checkAnswer(request, draft, [])).decision, "abstain");
    const wrong: LocalAnswerDraft = {...draft,
      claims: [{text: "Retry thirty times.", citations: nodeIds, confidence_bps: 9900}]};
    assert.equal((await graph.checkAnswer(request, wrong,
      await reviewFixture(graph, wrong, INITIAL_POLICY))).decision, "abstain");

    await graph.replaceSource("docs/retry.md", [{id: POLICY_ID, source: "docs/retry.md", text: UPDATED_POLICY}]);
    await graph.replaceSource("src/retry.ts", [{id: "retry.impl", source: "src/retry.ts",
      text: "export const retryLimit = 1; // Preserve the operation ID."}]);
    await assert.rejects(graph.checkAnswer(request, draft, reviews),
      error => error instanceof LocalContextError && error.code === "BaseMismatch");
    const refreshed = await graph.compile(request);
    const delta = await graph.delta(compiled.snapshot, refreshed.snapshot);
    assert.deepEqual(await graph.applyDelta(compiled.snapshot, delta), refreshed);
    const freshDraft: LocalAnswerDraft = {snapshot_id: refreshed.snapshot.id,
      claims: [{text: UPDATED_POLICY, citations: [POLICY_ID], confidence_bps: 9900}]};
    assert.equal((await graph.checkAnswer(request, freshDraft,
      await reviewFixture(graph, freshDraft, UPDATED_POLICY))).decision, "release");
    await assert.rejects(graph.compile({...request, allowed: ["retry.impl"]}),
      error => error instanceof LocalContextError && error.code === "RequiredUnavailable");

    return {schema: "cigar.local-workflow-example.v1", status: "passed", reviewer: "scripted-fixture",
      requires_hol_services: false, selected_sources: compiled.snapshot.stats.selected_sources,
      rendered_tokens: compiled.snapshot.stats.rendered_tokens, prompt_tokens: prompt.rendered_tokens,
      released_claims: releasedClaims, refreshed_claims: freshDraft.claims.map(claim => claim.text),
      checks: ["authorized-dependencies", "exact-budget", "snapshot-integrity", "cache-reuse", "compact-citations",
        "supported-release", "missing-review-abstention", "confident-error-abstention", "stale-review-rejection",
        "source-refresh", "delta-roundtrip", "fresh-review", "authorization-rejection"]};
  } finally {
    await graph.close();
  }
}
