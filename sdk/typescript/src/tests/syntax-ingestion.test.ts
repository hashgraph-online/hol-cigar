import assert from "node:assert/strict";
import test from "node:test";
import { LocalBrokerError, LocalContextBroker, LocalContextClient, LocalContextError, LocalContextGraph } from "../context-api.js";

const options = () => process.env.CIGAR_TEST_WORKER ? {workerPath:process.env.CIGAR_TEST_WORKER} : {};
const code = (expected: string) => (error: unknown): boolean => error instanceof LocalContextError && error.code === expected;

test("parser-owned boundaries retain exact UTF8, CRLF and absolute citation lines",async()=>{
  await using graph = await LocalContextGraph.create("syntax",options());
  const document = {id:"code",source:"source.ts",text:"// café 🦀\r\nfunction a() {\r\n  return 1;\r\n}\r\n\r\nfunction b() {}\n",start_line:40};
  const chunks = await graph.chunksAtLines(document,[45]);
  assert.equal(chunks.map(chunk=>chunk.text).join(""),document.text);
  assert.deepEqual(chunks.map(chunk=>chunk.id),["code:L40","code:L45"]);
  assert.deepEqual(chunks.map(chunk=>chunk.start_line),[40,45]);
  assert.equal(chunks[1]!.text,"function b() {}\n");
  assert.equal((await graph.stats()).documents,0);
  await graph.replaceSource(document.source,chunks);
  await graph.replaceSource(document.source,await graph.chunksAtLines({...document,text:"const x = 1;\n"},[]));
  assert.equal((await graph.stats()).documents,1);
  await assert.rejects(graph.compile({required:[chunks[1]!.id]}),code("RequiredUnavailable"));
});

test("invalid or lossy line boundaries cannot produce chunks or mutate the graph",async()=>{
  await using graph = await LocalContextGraph.create("syntax",options());
  const before = await graph.stats();
  for (const starts of [[0],[1],[4],[3,2],[3,3],[2,3],[Number.MAX_SAFE_INTEGER+1],[1.5]]) {
    await assert.rejects(graph.chunksAtLines({id:"a",source:"s",text:"first\n\nthird\n"},starts),code("InvalidInput"));
    assert.deepEqual(await graph.stats(),before);
  }
  (graph as unknown as {workerFeatures: string[]}).workerFeatures=[];
  await assert.rejects(graph.chunksAtLines({id:"a",source:"s",text:"first"},[]),code("IncompatibleWorker"));
});

test("broker boundary preprocessing is host-only and grants no evidence authority",async()=>{
  await using broker = await LocalContextBroker.create("syntax",options());
  const document = {id:"code",source:"code",text:"first\nsecond\n"};
  const revision = await broker.sourceRevision("code");
  const chunks = await broker.chunksAtLines(document,[2]);
  assert.deepEqual(chunks.map(chunk=>chunk.id),["code:L1","code:L2"]);
  assert.deepEqual(await broker.sourceRevision("code"),revision);
  const client = new LocalContextClient(await broker.grant({id:"a",allowed_sources:["code"],policy_revision:"1"}));
  assert.deepEqual((await client.compile({query:"first"})).context.snapshot.blocks,[]);
  assert.equal("chunksAtLines" in client,false);
  const hello = broker.capabilities();
  broker.capabilities=()=>({...hello,capabilities:hello.capabilities.filter(value=>value!=="document_boundaries.v1")});
  await assert.rejects(broker.chunksAtLines(document,[2]),(error:unknown)=>error instanceof LocalBrokerError && error.code==="IncompatibleWorker");
});
