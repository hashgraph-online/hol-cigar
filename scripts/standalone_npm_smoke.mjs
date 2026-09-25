// Copy this file into an empty npm consumer project and run:
// node standalone_npm_smoke.mjs 0.11.0
// No service URL, credentials, provider, or workerPath is supplied.
import assert from "node:assert/strict";

const version = process.argv[2];
assert.ok(["0.9.4", "0.10.0-beta.1", "0.11.0"].includes(version), "supply the installed version");
const checks = [];
const pass = (name) => checks.push(name);

if (version === "0.9.4") {
  await assert.rejects(import("@hol-org/cigar/context"), {code: "ERR_PACKAGE_PATH_NOT_EXPORTED"});
  console.log(JSON.stringify({version, platform: process.platform, arch: process.arch,
    node: process.version, local_graph_available: false,
    observed_error: "ERR_PACKAGE_PATH_NOT_EXPORTED"}));
} else {
  const {LocalContextGraph, LocalContextError, LOCAL_CONTEXT_CORE_VERSION} =
    await import("@hol-org/cigar/context");
  assert.equal(LOCAL_CONTEXT_CORE_VERSION, version);
  const code = (expected) => (error) => error instanceof LocalContextError && error.code === expected;
  const graph = await LocalContextGraph.create("npm-standalone-smoke");
  pass("bundled worker initializes without configuration");
  const features = {compact_prompt: typeof graph.promptView === "function",
    answer_review: typeof graph.checkAnswer === "function"};
  const implementation = {id: "retry.impl", source: "src/retry.ts",
    text: "export const retryLimit = 3; // retries preserve the operation ID"};
  const contract = {id: "retry.contract", source: "docs/retry.md",
    text: "Retry at most three times and preserve the operation ID."};
  const request = {query: "retry", required: [implementation.id],
    allowed: [implementation.id, contract.id], max_tokens: 1024, reserve_tokens: 128};
  let result;
  try {
    if (version === "0.11.0") assert.deepEqual(features, {compact_prompt: true, answer_review: true});
    await graph.replaceSource(implementation.source, [implementation]);
    await graph.replaceSource(contract.source, [contract]);
    await graph.upsert({id: "private", source: "private.txt", text: "Private retry policy."});
    await graph.link(implementation.id, contract.id, "requires");
    result = await graph.compile(request);
    assert.deepEqual(new Set(result.snapshot.blocks.flatMap(block => block.citations.map(c => c.node_id))),
      new Set([implementation.id, contract.id]));
    assert.ok(result.snapshot.stats.rendered_tokens <= 896);
    assert.ok(result.snapshot.blocks.some(block => block.text === contract.text));
    pass("ingestion, hard dependencies, scope filtering and exact token budget");
    await assert.rejects(graph.compile({...request, allowed: [implementation.id]}), code("RequiredUnavailable"));
    await assert.rejects(graph.compile({...request, allowed: []}), code("RequiredUnavailable"));
    pass("unauthorized hard dependencies fail closed");
    assert.deepEqual(await graph.verify(result.snapshot), result);
    pass("snapshot verification");
    const before = await graph.stats();
    assert.deepEqual(await graph.compile(request), result);
    assert.ok((await graph.stats()).cache.hits > before.cache.hits);
    pass("persistent graph reuses the exact-token cache");
    await graph.replaceSource(contract.source, [contract]);
    assert.equal((await graph.stats()).revision, before.revision);
    pass("unchanged source refresh preserves graph revision");
    const chunks = await graph.chunks({id: "lines", source: "lines.txt",
      text: "first\nsecond\nthird\nfourth", start_line: 11}, 2);
    assert.deepEqual(chunks.map(chunk => chunk.start_line), [11, 13]);
    pass("chunk citations preserve source lines");
    if (features.compact_prompt) {
      const prompt = await graph.promptView(result.snapshot, 1024);
      assert.deepEqual(await graph.verifyPrompt(prompt, result.snapshot), prompt);
      for (const [handle, citations] of Object.entries(prompt.citations)) {
        assert.deepEqual(await graph.resolveCitation(handle, prompt, result.snapshot), citations);
      }
      pass("compact prompt and citation resolution");
    }
    let draft;
    let reviews;
    if (features.answer_review) {
      draft = {snapshot_id: result.snapshot.id,
        claims: [{text: contract.text, citations: [contract.id], confidence_bps: 9900}]};
      const [key] = await graph.reviewKeys(draft);
      // A manually reviewed, verbatim fixture. This is not a general semantic reviewer.
      reviews = [{claim_key: key, verdict: "supported"}];
      assert.equal((await graph.checkAnswer(request, draft, reviews)).decision, "release");
      assert.equal((await graph.checkAnswer(request, draft, [])).decision, "abstain");
      assert.equal((await graph.checkAnswer(request, draft, reviews, {min_sources: 2})).decision, "abstain");
      const incorrect = {snapshot_id: result.snapshot.id,
        claims: [{text: "Retry thirty times.", citations: [contract.id], confidence_bps: 9900}]};
      const [incorrectKey] = await graph.reviewKeys(incorrect);
      const assessment = await graph.checkAnswer(request, incorrect,
        [{claim_key: incorrectKey, verdict: "contradicted"}]);
      assert.equal(assessment.decision, "abstain");
      assert.equal(assessment.confident_failures, 1);
      pass("trusted review gates release, missing review, corroboration and confident error");
    }
    await graph.replaceSource(contract.source, [{...contract, text: "Retry at most once."}]);
    const next = await graph.compile(request);
    assert.notEqual(next.snapshot.id, result.snapshot.id);
    assert.ok(next.snapshot.blocks.some(block => block.text === "Retry at most once."));
    const delta = await graph.delta(result.snapshot, next.snapshot);
    assert.deepEqual(await graph.applyDelta(result.snapshot, delta), next);
    pass("atomic source edit and verified delta round trip");
    if (features.answer_review) {
      await assert.rejects(graph.checkAnswer(request, draft, reviews), code("BaseMismatch"));
      pass("source changes invalidate the old answer review");
    }
    const tampered = structuredClone(next.snapshot);
    tampered.blocks[0].text = "Tampered evidence";
    await assert.rejects(graph.verify(tampered), code("Integrity"));
    pass("altered evidence is rejected");
    await assert.rejects(graph.compile({...request, max_tokens: 1, reserve_tokens: 0}), code("BudgetUnsatisfiable"));
    pass("insufficient budgets fail without dropping required evidence");
    await graph.replaceSource(contract.source, []);
    await assert.rejects(graph.compile(request), code("RequiredUnavailable"));
    pass("source withdrawal invalidates dependent context");
    await graph.unlink(implementation.id, contract.id, "requires");
    assert.equal((await graph.compile(request)).snapshot.stats.selected_sources, 1);
    pass("explicit graph repair restores availability");
    assert.equal(await graph.remove("private"), true);
    await graph.clearCache();
    assert.deepEqual((await graph.stats()).cache, {hits: 0, misses: 0, entries: 0, text_bytes: 0});
    pass("explicit document removal and cache clearing");
  } finally {
    await graph.close();
  }
  await assert.rejects(graph.stats(), code("Closed"));
  pass("worker cleanup");
  console.log(JSON.stringify({version, platform: process.platform, arch: process.arch,
    node: process.version, local_graph_available: true, features,
    rendered_tokens: result.snapshot.stats.rendered_tokens, checks_passed: checks.length, checks}));
}
