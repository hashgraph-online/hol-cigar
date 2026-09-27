/** Local Rust Honey HTTP integration driver. No provider, connector or service discovery. */
import assert from "node:assert/strict";
import { createInterface } from "node:readline";
import { CigarClient, ContextEffectDispatchUncertain, LocalBrokerError, LocalContextBroker, LocalContextClient,
  ValidationError, dispatchContextEffect } from "../index.js";
import type { LocalBrokerExecutionReview, LocalBrokerSourceProvenance } from "../index.js";

const lines = createInterface({input:process.stdin,terminal:false});
const input = lines[Symbol.asyncIterator]();
async function read(): Promise<Record<string,string>> {
  const value=await input.next();
  assert.ok(!value.done && Buffer.byteLength(value.value)<=32768);
  return JSON.parse(value.value) as Record<string,string>;
}
const emit = (value:object)=>process.stdout.write(JSON.stringify(value)+"\n");
try {
  const config=await read();
  const client=new CigarClient({baseUrl:config["base_url"]!,bearerToken:"context-effect-sdk-fixture",allowInsecureLoopback:true,maxAttempts:8});
  const provenance:LocalBrokerSourceProvenance={authority:"host",upstream_revision:"one",observed_at_ms:1,valid_until_ms:null,origin:"host",derived_from:[]};
  await using broker=await LocalContextBroker.create("honey-sdk",{workerPath:process.env.CIGAR_TEST_WORKER!});
  await broker.replaceSource("docs",await broker.sourceRevision("docs"),[{id:"fact",source:"docs",text:"The approved operation is send."}],provenance);
  const agent=new LocalContextClient(await broker.grant({id:"agent",allowed_sources:["docs"],policy_revision:"host-one"}));
  const context=await agent.compile({query:"send",required:["fact"]});
  const submission=await agent.submitAnswer(context.ticket,{snapshot_id:context.context.snapshot.id,
    claims:[{text:"The approved operation is send.",citations:["fact"],confidence_bps:9900}]});
  const review:LocalBrokerExecutionReview={authority_revision:"trusted-reviewer-one",policy:{},
    reviews:(await broker.submission(context.ticket)).review_keys.map(claim_key=>({claim_key,verdict:"supported"}))};
  const intent=config["scenario"]==="intent_substitution"?"1220"+"f".repeat(64):config["intent_digest"]!;
  const binding=await broker.bindExecution(context.ticket,submission,config["effect_id"]!,intent,review);
  const resolveReview=async()=>{
    if(config["scenario"]==="stale_context") await broker.replaceSource("docs",await broker.sourceRevision("docs"),
      [{id:"fact",source:"docs",text:"The operation is withdrawn."}],{...provenance,upstream_revision:"two"});
    return review;
  };
  let outcome:string;
  try {
    const result=await dispatchContextEffect(broker,client,binding,resolveReview,{idempotencyKey:"existing-sdk-dispatch",timeoutMs:10_000});
    assert.equal(result.response.payload.state,"dispatching");assert.deepEqual(result.handoff.binding,binding);outcome="dispatched";
  } catch(error) {
    if(error instanceof ContextEffectDispatchUncertain) {
      assert.equal(config["scenario"],"lost_ack");assert.deepEqual(error.handoff.binding,binding);outcome="uncertain";
    } else {
      assert.ok(error instanceof LocalBrokerError || error instanceof ValidationError);
      assert.ok(["stale_context","intent_substitution"].includes(config["scenario"]!));outcome="refused";
    }
  }
  emit({phase:"dispatch",outcome,effect_id:config["effect_id"]});
  let closed=false;
  for(let index=0;index<3;index++) {
    const command=await read();
    if(command["action"]==="close") {closed=true;break;}
    assert.equal(command["action"],"observe");
    const status=(await client.getEffectStatus({payload:{effect_id:config["effect_id"]!}},{timeoutMs:10_000,maxAttempts:1})).payload;
    assert.equal(status.effect_id,config["effect_id"]);assert.equal(status.intent_digest,config["intent_digest"]);
    emit({phase:"observed",state:status.state,version:status.effect_version.toString(),attempts:status.attempt_count,reconciliations:status.reconciliation_count});
  }
  assert.ok(closed);
} finally {lines.close();}
