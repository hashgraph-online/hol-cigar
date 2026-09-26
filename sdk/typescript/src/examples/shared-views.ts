/** Five concurrent scripted agents using one local worker; no model or network calls. */
import { LocalContextGraph, type LocalContextView } from "../context.js";
import type { LocalAnswerDraft, LocalClaimReview } from "../context-types.js";

function ensure(value: boolean): void {
  if (!value) throw new Error("shared-view example invariant failed");
}

export async function runSharedViews(options: {workerPath?: string; rounds?: number} = {}) {
  const rounds = options.rounds ?? 10;
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > 1000) throw new Error("Use 1..1000 rounds.");
  const graph = await LocalContextGraph.create("five-agent-example", options);
  try {
    await graph.upsert({id: "policy", source: "shared", text: "Release only independently reviewed claims."});
    const views: LocalContextView[] = [];
    for (let index = 0; index < 5; index++) {
      const name = `agent-${index}`;
      await graph.upsert({id: name, source: name, text: `${name} completed revision 0.`});
      await graph.link(name, "policy", "requires");
      views.push(await graph.createView({id: name, allowed_sources: [name, "shared"],
        writable_sources: [name], policy_revision: "host-policy-1"}));
    }
    const counts = await Promise.all(views.map(async (view, index) => {
      const name = `agent-${index}`;
      for (let revision = 1; revision <= rounds; revision++) {
        const knownFact = `${name} completed revision ${revision}.`;
        await view.replaceSource(name, [{id: name, source: name, text: knownFact}]);
        const {context, rendered} = await view.compile({required: [name], max_tokens: 512});
        const ids = new Set(context.snapshot.blocks.flatMap(b => b.citations.map(c => c.node_id)));
        ensure(ids.size === 2 && ids.has(name) && ids.has("policy") && rendered.includes(knownFact));
        ensure(context.snapshot.stats.rendered_tokens <= 512);
        const draft: LocalAnswerDraft = {snapshot_id: context.snapshot.id,
          claims: [{text: knownFact, citations: [name], confidence_bps: 9900}]};
        // Host-side fixture oracle. A real application supplies an authenticated semantic reviewer.
        const keys = await view.reviewKeys(draft);
        const reviews: LocalClaimReview[] = keys.map((key, i) => ({claim_key: key,
          verdict: draft.claims[i]?.text === knownFact ? "supported" : "unknown"}));
        ensure((await view.checkAnswer(context, draft, reviews)).assessment.decision === "release");
        ensure((await view.checkAnswer(context, draft, [])).assessment.decision === "abstain");
      }
      return rounds;
    }));
    ensure((await graph.stats()).documents === 6);
    const released = counts.reduce((a, b) => a + b, 0);
    return {schema: "cigar.shared-views-example.v1", status: "passed", agents: 5, workers: 1,
      indexed_documents: 6, released, missing_review_abstentions: released,
      reviewer: "scripted-fixture", requires_hol_services: false};
  } finally {
    await graph.close();
  }
}
