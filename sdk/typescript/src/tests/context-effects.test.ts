import assert from "node:assert/strict";
import { inspect } from "node:util";
import test from "node:test";
import {
  CigarClient, ContextEffectDispatchUncertain, EffectStatusResponse, LocalBrokerError,
  LocalContextBroker, LocalContextClient, ValidationError, decodeOperationPayload, dispatchContextEffect, encodeOperationPayload,
} from "../index.js";
import type { LocalBrokerExecutionReview, LocalBrokerSourceProvenance } from "../index.js";

const EFFECT = "01900000-0000-7000-8000-000000000001";
const INTENT = "1220" + "a".repeat(64);
const VERSION = (1n << 53n) + 7n;
const provenance: LocalBrokerSourceProvenance = {
  authority:"host", upstream_revision:"v1", observed_at_ms:1, valid_until_ms:null, origin:"host", derived_from:[],
};
const options = () => process.env.CIGAR_TEST_WORKER ? {workerPath:process.env.CIGAR_TEST_WORKER} : {};
async function fixture(broker: LocalContextBroker) {
  await broker.replaceSource("docs", await broker.sourceRevision("docs"), [{id:"fact",source:"docs",text:"Retry at most three times."}], provenance);
  const agent = new LocalContextClient(await broker.grant({id:"agent", allowed_sources:["docs"], policy_revision:"one"}));
  const context = await agent.compile({query:"retry",required:["fact"]});
  const submission = await agent.submitAnswer(context.ticket, {snapshot_id:context.context.snapshot.id,
    claims:[{text:"Retry at most three times.",citations:["fact"],confidence_bps:9900}]});
  const review: LocalBrokerExecutionReview = {authority_revision:"reviewer-one",policy:{},
    reviews:(await broker.submission(context.ticket)).review_keys.map(claim_key=>({claim_key,verdict:"supported"}))};
  const binding = await broker.bindExecution(context.ticket,submission,EFFECT,INTENT,review);
  return {binding,review};
}
class EffectWire {
  before: EffectStatusResponse = {effect_id:EFFECT,intent_digest:INTENT,state:"authorized",effect_version:VERSION,attempt_count:2,reconciliation_count:1};
  after: EffectStatusResponse = {...this.before,state:"dispatching",effect_version:VERSION+1n,attempt_count:3};
  requests: Array<{url:string;init:RequestInit}> = [];
  onGet: () => void | Promise<void> = () => {};
  getError = false;
  dispatchError = false;
  replyOperation = "dispatchEffect";
  client(): CigarClient {
    return new CigarClient({baseUrl:"http://127.0.0.1:1234",allowInsecureLoopback:true,trustCustomFetch:true,maxAttempts:8,
      fetch:async(input,init={})=>{
        this.requests.push({url:String(input),init});
        const get = init.method === "GET";
        if (get) await this.onGet();
        if (get ? this.getError : this.dispatchError) throw new Error("PRIVATE_EFFECT_ARGUMENTS");
        return new Response(JSON.stringify({operation_id:get?"getEffectStatus":this.replyOperation,
          payload_cbor:Buffer.from(encodeOperationPayload(get?this.before:this.after)).toString("base64url")}),
        {status:200,headers:{"content-type":"application/json"}});
      }});
  }
}

test("checked adapter uses generated operations, exact u64 revision and the existing key once",async()=>{
  await using broker = await LocalContextBroker.create("node-effect",options());
  const {binding,review} = await fixture(broker), wire = new EffectWire();
  const calls: number[] = [];
  const resolve = ()=>{calls.push(wire.requests.length);return review;};
  const result = await dispatchContextEffect(broker,wire.client(),binding,resolve,{idempotencyKey:"existing-key"});
  assert.deepEqual(calls,[1]);
  assert.deepEqual(result.handoff.binding,binding);
  assert.equal(result.response.payload.state,"dispatching");
  assert.deepEqual(wire.requests.map(r=>r.init.method),["GET","POST"]);
  const {url,init} = wire.requests[1]!;
  assert.ok(url.endsWith(`/v1/effects/${EFFECT}:dispatch`));
  const headers = new Headers(init.headers), body = JSON.parse(String(init.body));
  assert.equal(headers.get("if-match"),VERSION.toString());
  assert.equal(headers.get("idempotency-key"),"existing-key");
  assert.equal(body.expected_revision,VERSION.toString());
  assert.deepEqual(decodeOperationPayload(Buffer.from(body.payload_cbor,"base64url")),{effect_id:EFFECT});
  assert.ok(!inspect(result).includes(EFFECT));
  assert.ok(!String(result).includes(INTENT));
  const changed = structuredClone(result.handoff) as {binding:{effect_id:string}};
  changed.binding.effect_id="changed";
  assert.deepEqual(result.handoff.binding,binding);
  await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,resolve,{idempotencyKey:"existing-key"}),
    (error:unknown)=>error instanceof LocalBrokerError && error.code==="Conflict");
  assert.equal(wire.requests.filter(r=>r.init.method==="POST").length,1);
});

for (const state of ["prepared","pending_approval","dispatching","unknown","succeeded","failed","cancelled"] as const) {
  test(`adapter refuses ${state} before consuming context`,async()=>{
    await using broker = await LocalContextBroker.create("node-effect",options());
    const {binding,review} = await fixture(broker), wire = new EffectWire();
    wire.before={...wire.before,state};
    await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"same-key"}),ValidationError);
    assert.equal(wire.requests.length,1);
    assert.deepEqual((await broker.takeExecutionHandoff(binding,review)).binding,binding);
  });
}
for (const state of ["dispatching","unknown","succeeded","failed","authorized_for_retry"] as const) {
  test(`adapter preserves authority outcome ${state} without retries`,async()=>{
    await using broker = await LocalContextBroker.create("node-effect",options());
    const {binding,review} = await fixture(broker), wire = new EffectWire();
    wire.before={...wire.before,state:"authorized_for_retry"};wire.after={...wire.after,state};
    const result = await dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"original-key"});
    assert.equal(result.response.payload.state,state);assert.equal(wire.requests.length,2);
  });
}
for (const change of ["effect","intent","revision","counter","read_failure"]) {
  test(`preflight ${change} failure preserves the unconsumed binding`,async()=>{
    await using broker = await LocalContextBroker.create("node-effect",options());
    const {binding,review} = await fixture(broker), wire = new EffectWire();
    if (change==="effect") wire.before={...wire.before,effect_id:"01900000-0000-7000-8000-000000000002"};
    else if (change==="intent") wire.before={...wire.before,intent_digest:"1220"+"b".repeat(64)};
    else if (change==="revision") wire.before={...wire.before,effect_version:(1n<<64n)-1n};
    else if (change==="counter") wire.before={...wire.before,attempt_count:2**32};
    else wire.getError=true;
    await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"same-key"}));
    assert.equal(wire.requests.length,1);
    assert.deepEqual((await broker.takeExecutionHandoff(binding,review)).binding,binding);
  });
}
for (const change of ["source","reviewer","policy","resolver_failure"]) {
  test(`current ${change} is resolved after status and checked before dispatch`,async()=>{
    await using broker = await LocalContextBroker.create("node-effect",options());
    const {binding,review} = await fixture(broker), wire = new EffectWire();
    const resolve = async()=>{
      assert.equal(wire.requests.length,1);
      if (change==="source") await broker.replaceSource("docs",await broker.sourceRevision("docs"),[{id:"fact",source:"docs",text:"changed"}],provenance);
      else if (change==="reviewer") return {...review,authority_revision:"revoked"};
      else if (change==="policy") return {...review,policy:{min_sources:2}};
      else throw new Error("review unavailable");
      return review;
    };
    await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,resolve,{idempotencyKey:"same-key"}));
    assert.equal(wire.requests.length,1);
  });
}
for (const change of ["lost_reply","operation","effect","intent","version","attempt","reconciliation","state","malformed"]) {
  test(`post-consumption ${change} failure never repeats a send`,async()=>{
    await using broker = await LocalContextBroker.create("node-effect",options());
    const {binding,review} = await fixture(broker), wire = new EffectWire();
    if (change==="lost_reply") wire.dispatchError=true;
    else if (change==="operation") wire.replyOperation="getEffectStatus";
    else if (change==="effect") wire.after={...wire.after,effect_id:"01900000-0000-7000-8000-000000000002"};
    else if (change==="intent") wire.after={...wire.after,intent_digest:"1220"+"b".repeat(64)};
    else if (change==="version") wire.after={...wire.after,effect_version:VERSION};
    else if (change==="attempt") wire.after={...wire.after,attempt_count:1};
    else if (change==="reconciliation") wire.after={...wire.after,reconciliation_count:0};
    else if (change==="state") wire.after={...wire.after,state:"authorized"};
    else wire.after={...wire.after,state:"PRIVATE_EFFECT_ARGUMENTS" as EffectStatusResponse["state"]};
    await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"same-key"}),(error:unknown)=>{
      assert.ok(error instanceof ContextEffectDispatchUncertain);
      assert.deepEqual(error.handoff.binding,binding);
      assert.ok(!inspect(error).includes("PRIVATE_EFFECT_ARGUMENTS"));
      const copy = structuredClone(error.handoff) as {binding:{effect_id:string}};
      copy.binding.effect_id="changed";assert.deepEqual(error.handoff.binding,binding);return true;
    });
    assert.equal(wire.requests.length,2);
    await assert.rejects(broker.takeExecutionHandoff(binding,review),(error:unknown)=>error instanceof LocalBrokerError&&error.code==="Conflict");
  });
}
test("bad local inputs perform no effect I/O; caller mutation cannot retarget a pending adapter",async()=>{
  await using broker = await LocalContextBroker.create("node-effect",options());
  const {binding,review} = await fixture(broker), wire = new EffectWire();
  for (const timeoutMs of [0,NaN,Infinity,300001]) {
    await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"same-key",timeoutMs}),ValidationError);
  }
  await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"\n"}),ValidationError);
  await assert.rejects(dispatchContextEffect(broker,wire.client(),{...binding,effect_id:"bad"},()=>review,{idempotencyKey:"same-key"}),ValidationError);
  await assert.rejects(dispatchContextEffect(broker,wire.client(),{...binding,intent_digest:"bad"},()=>review,{idempotencyKey:"same-key"}),ValidationError);
  assert.equal(wire.requests.length,0);
  const supplied = structuredClone(binding) as typeof binding & {effect_id:string};
  wire.onGet = ()=>{supplied.effect_id="changed";};
  const result = await dispatchContextEffect(broker,wire.client(),supplied,()=>review,{idempotencyKey:"same-key"});
  assert.deepEqual(result.handoff.binding,binding);assert.equal(result.response.payload.effect_id,EFFECT);
});
test("a malformed consumed handoff cannot reach the effect client",async()=>{
  await using broker = await LocalContextBroker.create("node-effect",options());
  const {binding,review} = await fixture(broker), wire = new EffectWire();
  const take = broker.takeExecutionHandoff.bind(broker);
  broker.takeExecutionHandoff = async(...args)=>{
    const value=await take(...args);return {...value,checked:{...value.checked,assessment:{...value.checked.assessment,decision:"abstain"}}};
  };
  await assert.rejects(dispatchContextEffect(broker,wire.client(),binding,()=>review,{idempotencyKey:"same-key"}),ContextEffectDispatchUncertain);
  assert.equal(wire.requests.length,1);
});
