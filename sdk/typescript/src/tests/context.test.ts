import assert from "node:assert/strict";
import { test } from "node:test";
import { LocalContextError, LocalContextGraph } from "../context-api.js";
import type { LocalContextOptions, LocalContextRequest } from "../context-api.js";

const options = (extra: LocalContextOptions = {}): LocalContextOptions => ({
  ...(process.env.CIGAR_TEST_WORKER ? {workerPath: process.env.CIGAR_TEST_WORKER} : {}), ...extra,
});
const code = (expected: string) => (error: unknown) => error instanceof LocalContextError && error.code === expected;

test("compact prompt preserves source and verifies citation resolution", async () => {
  await using graph = await LocalContextGraph.create("sdk-test", options());
  const text = "Require the same identity on retry. Reject a mismatched signature. café 🦀";
  await graph.upsert({id: `source:${"a".repeat(100)}`, source: "contract.rs", text});
  const {snapshot} = await graph.compile({query: "retry", max_tokens: 512});
  const prompt = await graph.promptView(snapshot, 512);
  assert.deepEqual(await graph.verifyPrompt(prompt, snapshot), prompt);
  assert.equal(JSON.parse(prompt.rendered).text, text);
  assert.deepEqual(await graph.resolveCitation("c1", prompt, snapshot), snapshot.blocks[0]?.citations);
  await assert.rejects(graph.verifyPrompt({...prompt, rendered: "tampered"}, snapshot), code("Integrity"));
  await assert.rejects(graph.promptView(snapshot, 1), code("BudgetUnsatisfiable"));
});

test("local incremental cache and exact Rust rendering", async () => {
  await using graph = await LocalContextGraph.create("sdk-test", options());
  const doc = {id: "a", source: "src/a.rs", text: "fn authorize_user() { /* café 🦀 */ }\n"};
  assert.equal(await graph.upsert(doc), true);
  assert.equal(await graph.upsert(doc), false);
  assert.equal((await graph.stats()).revision, 1);
  const request = {query: "authorizeUser", max_tokens: 256, reserve_tokens: 32};
  const result = await graph.compile(request);
  assert.match(result.rendered, /authorize_user/);
  assert.ok(result.snapshot.stats.rendered_tokens <= 224);
  assert.deepEqual(await graph.verify(result.snapshot), result);
  const before = (await graph.stats()).cache.hits;
  assert.deepEqual(await graph.compile(request), result);
  assert.ok((await graph.stats()).cache.hits > before);
  await graph.clearCache();
  assert.deepEqual((await graph.stats()).cache, {hits: 0, misses: 0, entries: 0, text_bytes: 0});
});

test("atomic source replacement preserves hard dependency authorization", async () => {
  await using graph = await LocalContextGraph.create("sdk-test", options({limits: {max_documents: 2}}));
  const a = {id: "a", source: "a", text: "alpha"};
  await graph.upsert(a);
  await graph.upsert({id: "b", source: "b", text: "beta"});
  await graph.link("a", "b", "requires");
  const before = await graph.stats();
  await assert.rejects(graph.replaceSource("a", [{...a, text: "changed"}, {...a, id: "b"}]), code("InvalidInput"));
  assert.deepEqual(await graph.stats(), before);
  await assert.rejects(graph.compile({required: ["a"], allowed: ["a"]}), code("RequiredUnavailable"));
  await graph.replaceSource("b", []);
  await assert.rejects(graph.compile({required: ["a"]}), code("RequiredUnavailable"));
  await graph.unlink("a", "b", "requires");
  assert.equal((await graph.compile({required: ["a"]})).snapshot.stats.selected_sources, 1);
});

test("chunks, exact-base deltas, tamper rejection, and unsatisfiable budget", async () => {
  await using graph = await LocalContextGraph.create("sdk-test", options());
  const chunks = await graph.chunks({id: "a", source: "a", text: "α\r\nβ\nγ", start_line: 4}, 2, 1);
  assert.deepEqual(chunks.map(c => c.start_line), [4, 5]);
  await graph.replaceSource("a", chunks);
  const base = (await graph.compile({required: [chunks[0]!.id]})).snapshot;
  await graph.replaceSource("a", [{id: "a", source: "a", text: "replacement"}]);
  const target = await graph.compile({required: ["a"]});
  const delta = await graph.delta(base, target.snapshot);
  assert.deepEqual(await graph.applyDelta(base, delta), target);
  const tampered = {...target.snapshot, blocks: [{...target.snapshot.blocks[0]!, text: "tampered"}]};
  await assert.rejects(graph.verify(tampered), code("Integrity"));
  await assert.rejects(graph.applyDelta(target.snapshot, delta), code("BaseMismatch"));
  await assert.rejects(graph.compile({required: ["a"], max_tokens: 1}), code("BudgetUnsatisfiable"));
});

test("queued calls are serialized, bounded, and reject after close", async () => {
  const graph = await LocalContextGraph.create("sdk-test", options({maxPending: 4}));
  try {
    const pending = Array.from({length: 4}, (_, i) => graph.upsert({id: `${i}`, source: "a", text: "alpha"}));
    await assert.rejects(graph.stats(), code("Busy"));
    assert.deepEqual(await Promise.all(pending), [true, true, true, true]);
    assert.equal((await graph.stats()).documents, 4);
  } finally { await graph.close(); }
  await graph.close();
  await assert.rejects(graph.stats(), code("Closed"));
});

test("invalid options and unsafe integers fail before transmission", async () => {
  for (const timeoutMs of [0, -1, NaN, Infinity]) {
    await assert.rejects(LocalContextGraph.create("test", options({timeoutMs})), code("InvalidInput"));
  }
  await assert.rejects(LocalContextGraph.create("test", {workerPath: "relative-path"}), code("WorkerUnavailable"));
  await using graph = await LocalContextGraph.create("sdk-test", options());
  await assert.rejects(graph.compile({max_tokens: Number.MAX_SAFE_INTEGER + 1}), code("InvalidInput"));
  assert.equal((await graph.stats()).documents, 0);
});

test("invalid frames close transport without reflecting content", async () => {
  await using graph = await LocalContextGraph.create("sdk-test", options());
  await assert.rejects(graph.compile({secret_query_typo: "PRIVATE"} as LocalContextRequest), code("Transport"));
  await assert.rejects(graph.stats(), code("Closed"));
});

test("cache can be disabled", async () => {
  await using graph = await LocalContextGraph.create("sdk-test", options({limits: {cache_entries: 0}}));
  await graph.upsert({id: "a", source: "a", text: "alpha"});
  await graph.compile({query: "alpha"});
  assert.equal((await graph.stats()).cache.entries, 0);
});

test("deadline closes the graph and rejects queued mutations", {
  skip: !process.env.CIGAR_TEST_STALLED_WORKER,
}, async () => {
  const graph = await LocalContextGraph.create("test", {workerPath: process.env.CIGAR_TEST_STALLED_WORKER!, timeoutMs: 2_000});
  const start = performance.now();
  const pending = graph.upsert({id: "a", source: "a", text: "x".repeat(1_000_000)});
  const queued = graph.stats();
  await Promise.all([assert.rejects(pending, code("Timeout")), assert.rejects(queued, code("Closed"))]);
  await graph.close();
  assert.ok(performance.now() - start < 5_000);
});
