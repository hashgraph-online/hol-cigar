import assert from "node:assert/strict";
import { test } from "node:test";
import { LocalContextError, LocalContextGraph } from "../context-api.js";
import type { LocalViewContext, LocalContextView } from "../context-api.js";

const options = () => process.env.CIGAR_TEST_WORKER ? {workerPath: process.env.CIGAR_TEST_WORKER} : {};
const code = (expected: string) => (error: unknown) => error instanceof LocalContextError && error.code === expected;

async function seed(graph: LocalContextGraph) {
  await graph.upsert({id: "policy", source: "shared", text: "Only release independently reviewed claims."});
  return Promise.all(Array.from({length: 5}, async (_, i) => {
    const id = `agent-${i}`;
    await graph.upsert({id, source: id, text: `${id} task revision 0.`});
    await graph.link(id, "policy", "requires");
    return graph.createView({id, allowed_sources: [id, "shared"], writable_sources: [id], policy_revision: "host-policy-1"});
  }));
}

async function reviewed(view: LocalContextView, context: LocalViewContext, agent: string, text = "A task is assigned.") {
  const draft = {snapshot_id: context.snapshot.id, claims: [{text, citations: [agent], confidence_bps: 9999}]};
  const reviews = (await view.reviewKeys(draft)).map(claim_key => ({claim_key, verdict: "supported" as const}));
  return {draft, reviews};
}

test("five agents share one graph/index with independently valid reviews during concurrent writes", async () => {
  await using graph = await LocalContextGraph.create("five-agent-alpha", options());
  const views = await seed(graph);
  const completed = await Promise.all(views.map(async (view, i) => {
    const id = `agent-${i}`;
    for (let revision = 0; revision < 25; revision++) {
      const text = `${id} task revision ${revision}.`;
      await view.replaceSource(id, [{id, source: id, text}]);
      const result = await view.compile({required: [id], query: "task", max_tokens: 1024});
      assert.deepEqual(new Set(result.context.snapshot.blocks.flatMap(b => b.citations.map(c => c.node_id))), new Set([id, "policy"]));
      assert.ok(result.rendered.includes(text));
      assert.equal(result.context.snapshot.stats.documents, 2);
      const {draft, reviews} = await reviewed(view, result.context, id, text);
      const checked = await view.checkAnswer(result.context, draft, reviews);
      assert.equal(checked.assessment.decision, "release");
      assert.equal(checked.context_id, result.context.id);
      assert.equal((await graph.verify(result.context.snapshot)).rendered, result.rendered);
    }
    return 25;
  }));
  assert.equal(completed.reduce((a, b) => a + b), 125);
  assert.equal((await graph.stats()).documents, 6);
});

test("outside writes preserve scoped reviews while legacy snapshot checks and inside freshness remain strict", async () => {
  await using graph = await LocalContextGraph.create("five-agent-alpha", options());
  const views = await seed(graph);
  const view = views[0]!;
  const {context} = await view.compile({required: ["agent-0"]});
  const {draft, reviews} = await reviewed(view, context, "agent-0");
  const request = {required: ["agent-0"], allowed: ["agent-0", "policy"]};
  const legacy = await graph.compile(request);
  await views[4]!.replaceSource("agent-4", [{id: "agent-4", source: "agent-4", text: "Other work changed."}]);
  assert.equal((await view.checkAnswer(context, draft, reviews)).assessment.decision, "release");
  await assert.rejects(graph.checkAnswer(request, {snapshot_id: legacy.snapshot.id, claims: [], abstain: true}, []), code("BaseMismatch"));
  await graph.upsert({id: "new", source: "shared", text: "New authorized evidence."});
  await assert.rejects(view.checkAnswer(context, draft, reviews), code("BaseMismatch"));
});

test("view write limits, revocation, tamper rejection and trusted review gates", async () => {
  await using graph = await LocalContextGraph.create("five-agent-alpha", options());
  const views = await seed(graph);
  const view = views[0]!;
  const {context} = await view.compile({required: ["agent-0"]});
  const {draft, reviews} = await reviewed(view, context, "agent-0");
  const revision = (await graph.stats()).revision;
  await assert.rejects(view.compile({required: ["agent-4"], allowed: ["agent-4"]}), code("RequiredUnavailable"));
  await assert.rejects(view.replaceSource("shared", []), code("RequiredUnavailable"));
  await assert.rejects(view.replaceSource("agent-0", [{id: "policy", source: "agent-0", text: "Collision"}]), code("RequiredUnavailable"));
  assert.equal((await graph.stats()).revision, revision);
  await assert.rejects(view.checkAnswer({...context, scope_id: "0".repeat(64)}, draft, reviews), code("Integrity"));
  assert.equal((await view.checkAnswer(context, draft, [])).assessment.decision, "abstain");
  assert.equal((await view.checkAnswer(context, draft, [{claim_key: reviews[0]!.claim_key, verdict: "contradicted"}])).assessment.decision, "abstain");
  assert.equal(await graph.revokeView("agent-0"), true);
  await assert.rejects(view.compile({required: ["agent-0"]}), code("RequiredUnavailable"));
  const replacement = await graph.createView({id: "agent-0", allowed_sources: ["agent-0", "shared"], policy_revision: "2"});
  await assert.rejects(replacement.checkAnswer(context, draft, reviews), code("BaseMismatch"));
  await graph.close();
  await assert.rejects(views[1]!.compile({query: "task"}), code("Closed"));
});
