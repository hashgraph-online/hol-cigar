import assert from "node:assert/strict";
import test from "node:test";
import { LocalBrokerError, LocalContextBroker, LocalContextClient, LocalContextError, LocalContextGraph } from "../context-api.js";
import type { LocalBrokerSourceProvenance } from "../context-api.js";

const options = () => process.env.CIGAR_TEST_WORKER ? {workerPath:process.env.CIGAR_TEST_WORKER} : {};
const code = (expected: string) => (error: unknown): boolean => error instanceof LocalContextError && error.code === expected;

test("selection trace observes actual root closure and exact tokenizer without changing output",async()=>{
  await using graph = await LocalContextGraph.create("explanation",options());
  await graph.upsert({id:"root",source:"code",text:"pub fn authorize_user() {}\n"});
  await graph.upsert({id:"dependency",source:"rules",text:"Require permission."});
  await graph.upsert({id:"semantic",source:"notes",text:"Independent retrieval lead."});
  await graph.upsert({id:"HIDDEN_ID",source:"hidden",text:"authorize_user PRIVATE_TEXT"});
  await graph.link("root","dependency","requires");
  const request = {query:"authorize_user",max_tokens:1024,allowed:["root","dependency","semantic"],semantic_candidates:["semantic","HIDDEN_ID"]};
  const result = await graph.compile(request);
  const trace = await graph.explain(request,result.snapshot);
  assert.equal(trace.schema,"cigar.context-selection-explanation.v1");
  assert.equal(trace.snapshot_id,result.snapshot.id);
  assert.equal(trace.tokenizer,result.snapshot.tokenizer);
  assert.equal(trace.checked_graph_revision,result.snapshot.graph_revision);
  assert.equal(trace.request_id.length,64);
  const rows = new Map(trace.steps.map(step=>[step.root_id,step]));
  assert.deepEqual(rows.get("root")!.added_ids,["dependency","root"]);
  assert.deepEqual(rows.get("root")!.signals,["lexical_match","declaration_match"]);
  assert.deepEqual(rows.get("semantic")!.signals,["semantic_candidate"]);
  for (const value of ["HIDDEN_ID","PRIVATE_TEXT","authorize_user","Require permission."]) assert.equal(JSON.stringify(trace).includes(value),false);
  assert.deepEqual(await graph.compile(request),result);
  assert.deepEqual(await graph.explain(request,result.snapshot),trace);
});

test("root explanation refuses changed content, request scope and graph state",async()=>{
  await using graph = await LocalContextGraph.create("explanation",options());
  await graph.upsert({id:"fact",source:"docs",text:"evidence"});
  const request = {required:["fact"]};
  const result = await graph.compile(request);
  const forged = {...result.snapshot,blocks:result.snapshot.blocks.map(block=>({...block,text:"FORGED"}))};
  await assert.rejects(graph.explain(request,forged),code("BaseMismatch"));
  await assert.rejects(graph.explain({query:"evidence",allowed:[]},result.snapshot),code("BaseMismatch"));
  await graph.upsert({id:"unrelated",source:"other",text:"different"});
  await assert.rejects(graph.explain(request,result.snapshot),code("BaseMismatch"));
});

test("view explanation checks whole scope and retains original snapshot after unrelated changes",async()=>{
  await using graph = await LocalContextGraph.create("explanation",options());
  await graph.upsert({id:"fact",source:"docs",text:"evidence"});
  const a = await graph.createView({id:"a",allowed_sources:["docs"],policy_revision:"1"});
  const b = await graph.createView({id:"b",allowed_sources:["docs"],policy_revision:"1"});
  const result = await a.compile({required:["fact"]});
  const before = await a.explain(result.context);
  assert.deepEqual(before.steps,[{root_id:"fact",added_ids:["fact"],signals:["required"]}]);
  await assert.rejects(b.explain(result.context),code("BaseMismatch"));
  await graph.upsert({id:"secret",source:"other",text:"PRIVATE_OTHER"});
  const after = await a.explain(result.context);
  assert.equal(after.snapshot_id,before.snapshot_id);
  assert.deepEqual(after.steps,before.steps);
  assert.ok(after.checked_graph_revision > before.checked_graph_revision);
  await graph.upsert({id:"new",source:"docs",text:"Unselected new evidence."});
  await assert.rejects(a.explain(result.context),code("BaseMismatch"));
  await graph.revokeView("a");
  await assert.rejects(a.explain(result.context),code("RequiredUnavailable"));
});

test("explanation requires explicit capability without dispatching to an older worker",async()=>{
  await using graph = await LocalContextGraph.create("explanation",options());
  const view = await graph.createView({id:"a",allowed_sources:[],policy_revision:"1"});
  const result = await view.compile({query:"absent"});
  // Simulate a valid older hello at the capability boundary. No worker command is changed.
  (graph as unknown as {workerFeatures: string[]}).workerFeatures = ["context_views.v1"];
  await assert.rejects(graph.explain({query:"absent"},result.context.snapshot),code("IncompatibleWorker"));
  await assert.rejects(view.explain(result.context),code("IncompatibleWorker"));
});

for (const change of ["metadata","revocation","forgotten_ticket"]) {
  test(`broker explanation preserves current ticket authority after ${change}`,async()=>{
    await using broker = await LocalContextBroker.create("broker-explain",options());
    const documents = [{id:"fact",source:"docs",text:"evidence"}];
    const provenance: LocalBrokerSourceProvenance = {authority:"fixture-host",upstream_revision:"1",observed_at_ms:1,valid_until_ms:null,origin:"host",derived_from:[]};
    await broker.replaceSource("docs",await broker.sourceRevision("docs"),documents,provenance);
    const a = new LocalContextClient(await broker.grant({id:"a",allowed_sources:["docs"],policy_revision:"1"}));
    const b = new LocalContextClient(await broker.grant({id:"b",allowed_sources:["docs"],policy_revision:"1"}));
    const context = await a.compile({required:["fact"]});
    assert.equal((await a.explain(context.ticket)).snapshot_id,context.context.snapshot.id);
    await assert.rejects(b.explain(context.ticket),code("AccessDenied"));
    if (change==="metadata") await broker.replaceSource("docs",await broker.sourceRevision("docs"),documents,{...provenance,upstream_revision:"2"});
    else if (change==="revocation") await broker.revoke("a");
    else await a.forgetTicket(context.ticket);
    await assert.rejects(a.explain(context.ticket),(error:unknown)=>error instanceof LocalBrokerError);
  });
}
