import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { createServer } from "node:net";
import { once } from "node:events";
import { inspect } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { LocalBrokerConnection, LocalBrokerError, LocalContextBroker, LocalContextClient } from "../context-api.js";
import type { LocalAnswerDraft, LocalBrokerContext, LocalBrokerExecutionReview, LocalBrokerSourceProvenance } from "../context-api.js";

const options = () => process.env.CIGAR_TEST_WORKER ? {workerPath:process.env.CIGAR_TEST_WORKER} : {};
const provenance = (origin: "host" | "reviewed_proposal" = "host"): LocalBrokerSourceProvenance => ({
  authority:"fixture-host", upstream_revision:"v1", observed_at_ms:1, valid_until_ms:null, origin, derived_from:[],
});
const code = (expected: string) => (error: unknown): boolean => error instanceof LocalBrokerError && error.code === expected;
const ingest = async (broker: LocalContextBroker, source: string, id: string, text: string) =>
  broker.replaceSource(source, await broker.sourceRevision(source), [{id, source, text}], provenance());

async function executionFixture(broker: LocalContextBroker) {
  await ingest(broker,"docs","fact","Retry at most three times.");
  const client = new LocalContextClient(await broker.grant({id:"execution-agent",allowed_sources:["docs"],policy_revision:"one"}));
  const context = await client.compile({query:"retry",required:["fact"]});
  const draft: LocalAnswerDraft = {snapshot_id:context.context.snapshot.id,
    claims:[{text:"Retry at most three times.",citations:["fact"],confidence_bps:9900}]};
  const submission = await client.submitAnswer(context.ticket,draft);
  const review: LocalBrokerExecutionReview = {authority_revision:"reviewer-policy-one",policy:{},
    reviews:(await broker.submission(context.ticket)).review_keys.map(claim_key=>({claim_key,verdict:"supported"}))};
  return {client,context,draft,submission,review};
}

test("execution handoff binds the exact intent and permits only one local take",async()=>{
  await using broker = await LocalContextBroker.create("node-handoff",options());
  const {client,context,submission,review} = await executionFixture(broker);
  assert.equal("bindExecution" in client,false);
  assert.equal("takeExecutionHandoff" in client,false);
  const binding = await broker.bindExecution(context.ticket,submission,"prepared-effect","1220"+"a".repeat(64),review);
  await assert.rejects(broker.takeExecutionHandoff({...binding,intent_digest:"1220"+"b".repeat(64)},review),code("Stale"));
  await ingest(broker,"unrelated","private","Unrelated private update.");
  const results = await Promise.allSettled([broker.takeExecutionHandoff(binding,review),broker.takeExecutionHandoff(binding,review)]);
  const accepted = results.filter(value=>value.status==="fulfilled");
  const denied = results.filter(value=>value.status==="rejected");
  assert.equal(accepted.length,1); assert.equal(denied.length,1);
  assert.deepEqual(accepted[0]!.value.binding,binding);
  assert.equal(accepted[0]!.value.checked.assessment.decision,"release");
  assert.ok(code("Conflict")(denied[0]!.reason));
});

for (const change of ["source","metadata","submission","revoke","reviewer","policy","verdict"]) {
  test(`execution handoff rejects changed ${change}`,async()=>{
    await using broker = await LocalContextBroker.create("node-handoff-stale",options());
    const {client,context,draft,submission,review} = await executionFixture(broker);
    const binding = await broker.bindExecution(context.ticket,submission,"prepared-effect","1220"+"a".repeat(64),review);
    let current = review;
    if (change==="source") await ingest(broker,"docs","fact","Changed retry rule.");
    else if (change==="metadata") await broker.replaceSource("docs",await broker.sourceRevision("docs"),
      [{id:"fact",source:"docs",text:"Retry at most three times."}],{...provenance(),upstream_revision:"two"});
    else if (change==="submission") await client.submitAnswer(context.ticket,draft);
    else if (change==="revoke") await broker.revoke("execution-agent");
    else if (change==="reviewer") current={...review,authority_revision:"reviewer-revoked"};
    else if (change==="policy") current={...review,policy:{min_sources:2}};
    else current={...review,reviews:review.reviews.map(value=>({...value,verdict:"unknown"}))};
    await assert.rejects(broker.takeExecutionHandoff(binding,current),(error:unknown)=>error instanceof LocalBrokerError);
  });
}

test("execution handoff requires review and refuses workers without its advertised feature",async()=>{
  await using broker = await LocalContextBroker.create("node-handoff-feature",options());
  const {context,submission,review} = await executionFixture(broker);
  await assert.rejects(broker.bindExecution(context.ticket,submission,"prepared-effect","1220"+"a".repeat(64),{...review,reviews:[]}),code("AccessDenied"));
  const binding = await broker.bindExecution(context.ticket,submission,"prepared-effect","1220"+"a".repeat(64),review);
  const capabilities = broker.capabilities.bind(broker);
  const hello = capabilities();
  broker.capabilities = ()=>({...hello,capabilities:hello.capabilities.filter(value=>value!=="execution_handoff.v1")});
  await assert.rejects(broker.bindExecution(context.ticket,submission,"prepared-effect","1220"+"a".repeat(64),review),code("IncompatibleWorker"));
  await assert.rejects(broker.takeExecutionHandoff(binding,review),code("IncompatibleWorker"));
  broker.capabilities=capabilities;
  assert.equal((await broker.takeExecutionHandoff(binding,review)).checked.assessment.decision,"release");
});

for (const agents of [1,5,12]) test(`${agents} independent Node agents share scopes and preserve unaffected work`, {timeout:30_000}, async () => {
  await using broker = await LocalContextBroker.create("node-broker", options());
  await ingest(broker,"shared","common","common evidence");
  const grants: LocalBrokerConnection[] = [];
  for (let i=0;i<agents;i++) {
    await ingest(broker,`private-${i}`,`doc-${i}`,`PRIVATE_AGENT_${i}_ evidence`);
    grants.push(await broker.grant({id:`agent-${i}`,allowed_sources:["shared",`private-${i}`],policy_revision:"host-1"}));
  }
  const results = await Promise.all(grants.map(async (grant,i) => {
    const child = spawn(process.execPath,[fileURLToPath(new URL("./broker-agent.js",import.meta.url))],{stdio:["pipe","pipe","pipe"]});
    const output: Buffer[] = [], errors: Buffer[] = [];
    child.stdout.on("data",(value:Buffer)=>output.push(value));
    child.stderr.on("data",(value:Buffer)=>errors.push(value));
    const done = once(child,"close");
    child.stdin.end(JSON.stringify({connection:grant.export(),request:{query:"evidence",required:["common",`doc-${i}`]}}));
    const timer = setTimeout(()=>child.kill("SIGKILL"),20_000);
    try { assert.equal((await done)[0],0,Buffer.concat(errors).toString()); }
    finally { clearTimeout(timer); child.kill("SIGKILL"); }
    return JSON.parse(Buffer.concat(output).toString()) as LocalBrokerContext;
  }));
  for (let i=0;i<agents;i++) {
    const result = results[i]!;
    assert.equal(result.context.snapshot.stats.documents,2);
    assert.ok(result.rendered.includes(`PRIVATE_AGENT_${i}_`));
    for (let j=0;j<agents;j++) if (i!==j) assert.ok(!result.rendered.includes(`PRIVATE_AGENT_${j}_`));
  }
  await ingest(broker,"private-0","doc-0","changed evidence");
  for (let i=0;i<agents;i++) {
    const client = new LocalContextClient(grants[i]!);
    if (i===0) await assert.rejects(client.revalidate(results[i]!.ticket),code("Stale"));
    else {
      await client.revalidate(results[i]!.ticket);
      await assert.rejects(client.revalidate(results[0]!.ticket),code("AccessDenied"));
    }
  }
});

test("proposal admission, CAS and exact host review work through the Node API",async()=>{
  await using broker = await LocalContextBroker.create("node-review",options());
  const a = new LocalContextClient(await broker.grant({id:"a",allowed_sources:["docs"],writable_sources:["docs"],policy_revision:"host-1"}));
  const b = new LocalContextClient(await broker.grant({id:"b",allowed_sources:["docs"],writable_sources:["docs"],policy_revision:"host-1"}));
  const revision = await a.sourceRevision("docs");
  assert.equal(revision.version,"0");
  const pa = await a.proposeSource("a-1","docs",revision,[{id:"fact",source:"docs",text:"Retry three times."}]);
  const pb = await b.proposeSource("b-1","docs",revision,[{id:"other",source:"docs",text:"Retry four times."}]);
  assert.equal((await a.compile({query:"retry"})).context.snapshot.blocks.length,0);
  assert.equal((await broker.proposal(pa.proposal_id)).documents[0]!.id,"fact");
  await broker.admitProposal(pa.proposal_id,provenance("reviewed_proposal"));
  await assert.rejects(broker.admitProposal(pb.proposal_id,provenance("reviewed_proposal")),code("Conflict"));
  assert.equal((await a.proposalStatus("a-1")).outcome.status,"admitted");
  await broker.rejectProposal(pb.proposal_id);
  await b.forgetProposal("b-1");
  const context = await a.compile({query:"retry",required:["fact"]});
  const draft: LocalAnswerDraft = {snapshot_id:context.context.snapshot.id,
    claims:[{text:"Retry three times.",citations:["fact"],confidence_bps:9900}]};
  const id = await a.submitAnswer(context.ticket,draft);
  const submission = await broker.submission(context.ticket);
  assert.equal(submission.submission_id,id);
  const reviews = submission.review_keys.map(claim_key=>({claim_key,verdict:"supported" as const}));
  assert.equal((await broker.checkAnswer(context.ticket,id,[])).assessment.decision,"abstain");
  assert.equal((await broker.checkAnswer(context.ticket,id,reviews)).assessment.decision,"release");
  assert.equal((await a.citations(context.ticket,"fact"))[0]!.source,"docs");
  assert.equal("checkAnswer" in a,false);
  await a.forgetTicket(context.ticket);
  await assert.rejects(a.revalidate(context.ticket),code("AccessDenied"));
});

test("connection serialization is redacted and routing accepts only literal loopback",()=>{
  const connection = new LocalBrokerConnection(1234,"e".repeat(64),"a".repeat(64));
  for (const text of [inspect(connection),String(connection),JSON.stringify(connection)]) assert.ok(!text.includes("a".repeat(64)));
  assert.deepEqual(LocalBrokerConnection.fromConfig(connection.export()).export(),connection.export());
  assert.throws(()=>LocalBrokerConnection.fromConfig({...connection.export(),host:"localhost" as "127.0.0.1"}),code("InvalidInput"));
});

test("an impersonating broker receives no credential secret or context",{timeout:10_000},async()=>{
  const observed: Buffer[] = [];
  let hello: Record<string,string> | undefined;
  const server = createServer(socket=>{
    let incoming = Buffer.alloc(0), sent = false;
    socket.on("error",()=>undefined);
    socket.on("data",(data:Buffer)=>{
      if (sent) { observed.push(data); return; }
      incoming = Buffer.concat([incoming,data]);
      if (incoming.length<4 || incoming.length<4+incoming.readUInt32BE()) return;
      hello = JSON.parse(incoming.subarray(4).toString()) as Record<string,string>;
      const response = Buffer.from(JSON.stringify({protocol:hello.protocol,epoch:hello.epoch,grant_id:hello.grant_id,
        client_nonce:hello.nonce,server_nonce:"b".repeat(64),proof:"0".repeat(64)}));
      const prefix=Buffer.alloc(4);prefix.writeUInt32BE(response.length);sent=true;
      socket.write(Buffer.concat([prefix,response]));
    });
  });
  server.listen(0,"127.0.0.1"); await once(server,"listening");
  const address=server.address(); assert.ok(address && typeof address!=="string");
  try {
    const client = new LocalContextClient(new LocalBrokerConnection(address.port,"e".repeat(64),"a".repeat(64)));
    await assert.rejects(client.compile({query:"PRIVATE_CONTEXT_CANARY"}),error=>error instanceof LocalBrokerError && error.code==="Authentication" && error.dispatched===false);
  } finally { server.close(); await once(server,"close"); }
  assert.ok(hello && !JSON.stringify(hello).includes("a".repeat(64)) && !JSON.stringify(hello).includes("PRIVATE_CONTEXT_CANARY"));
  assert.equal(Buffer.concat(observed).length,0);
});

for (const failure of ["lost", "oversized", "duplicate", "partial-prefix", "unsafe-timing", "fragmented-success"] as const)
test(`authenticated ${failure} response preserves outcome and never retries`,{timeout:10_000},async()=>{
  let connections = 0, commands = 0;
  const server = createServer(socket=>{
    connections++;
    let incoming = Buffer.alloc(0), stage = 0, transcript = "";
    socket.on("error",()=>undefined);
    const send = (text: string) => {
      const data = Buffer.from(text), prefix = Buffer.alloc(4);
      prefix.writeUInt32BE(data.length);
      const frame=Buffer.concat([prefix,data]);
      socket.write(frame.subarray(0,1));
      setImmediate(()=>{
        socket.write(frame.subarray(1,6));
        setImmediate(()=>socket.write(frame.subarray(6)));
      });
    };
    socket.on("data",(data:Buffer)=>{
      incoming = Buffer.concat([incoming,data]);
      while (incoming.length >= 4 && incoming.length >= 4 + incoming.readUInt32BE()) {
        const length = incoming.readUInt32BE();
        const frame = JSON.parse(incoming.subarray(4,4+length).toString()) as Record<string,unknown>;
        incoming = incoming.subarray(4+length);
        if (stage === 0) {
          transcript = `${frame.epoch}${frame.grant_id}${frame.nonce}${"b".repeat(64)}`;
          const proof = createHmac("sha256",Buffer.from("a".repeat(64),"hex"))
            .update("cigar.broker-server-proof.v1\0"+transcript).digest("hex");
          send(JSON.stringify({protocol:frame.protocol,epoch:frame.epoch,grant_id:frame.grant_id,
            client_nonce:frame.nonce,server_nonce:"b".repeat(64),proof}));
        } else if (stage === 1) {
          assert.equal(frame.proof,createHmac("sha256",Buffer.from("a".repeat(64),"hex"))
            .update("cigar.broker-client-proof.v1\0"+transcript).digest("hex"));
        } else {
          commands++;
          assert.equal((frame.command as Record<string,unknown>).op,failure === "fragmented-success" ? "source_revision" : "propose_source");
          if (failure === "lost") socket.end();
          else if (failure === "oversized") {
            const prefix=Buffer.alloc(4);prefix.writeUInt32BE(8*1024*1024+1);socket.write(prefix);
          } else if (failure === "partial-prefix") socket.write(Buffer.from([0]));
          else if (failure === "fragmented-success") send(JSON.stringify({protocol:"cigar.context-broker.v1",id:1,
            outcome:{status:"ok",result:{epoch:"e".repeat(64),version:"0"}},timing:{queue_us:0,service_us:0}}));
          else send('{"protocol":"cigar.context-broker.v1","id":1,'+
            (failure === "duplicate" ? '"id":1,' : '')+
            '"outcome":{"status":"ok","result":null},"timing":{"queue_us":'+
            (failure === "unsafe-timing" ? '9007199254740993' : '0')+',"service_us":0}}');
        }
        stage++;
      }
    });
  });
  server.listen(0,"127.0.0.1"); await once(server,"listening");
  const address=server.address(); assert.ok(address && typeof address!=="string");
  try {
    const client = new LocalContextClient(new LocalBrokerConnection(address.port,"e".repeat(64),"a".repeat(64)),{timeoutMs:300});
    if (failure === "fragmented-success") assert.deepEqual(await client.sourceRevision("docs"),{epoch:"e".repeat(64),version:"0"});
    else await assert.rejects(client.proposeSource("once","docs",{epoch:"e".repeat(64),version:"0"},[]),
        error=>error instanceof LocalBrokerError && error.dispatched===null &&
          error.code===(failure === "partial-prefix" ? "Timeout" : "Transport"));
  } finally { const closed=once(server,"close");server.close();await closed; }
  assert.equal(connections,1);assert.equal(commands,1);
});

test("incomplete authentication obeys the total deadline and local concurrency bound",{timeout:10_000},async()=>{
  let connections=0;
  const server=createServer(socket=>{connections++;socket.on("data",()=>undefined);socket.on("error",()=>undefined);});
  server.listen(0,"127.0.0.1");await once(server,"listening");
  const address=server.address();assert.ok(address && typeof address!=="string");
  try {
    const client=new LocalContextClient(new LocalBrokerConnection(address.port,"e".repeat(64),"a".repeat(64)),{timeoutMs:100,maxPending:1});
    const pending=assert.rejects(client.sourceRevision("docs"),
      error=>error instanceof LocalBrokerError && error.code==="Timeout" && error.dispatched===false);
    await assert.rejects(client.sourceRevision("docs"),code("Busy"));
    await pending;
  } finally {const closed=once(server,"close");server.close();await closed;}
  assert.equal(connections,1);
});
