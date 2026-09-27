import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { LocalBrokerError, LocalContextBroker, LocalContextClient } from "../context-api.js";
import type { LocalBrokerOptions, LocalBrokerSourceProvenance } from "../context-api.js";

const provenance: LocalBrokerSourceProvenance = {authority:"host",upstream_revision:"one",
  observed_at_ms:1,valid_until_ms:null,origin:"host",derived_from:[]};
const options = (directory: string): LocalBrokerOptions => ({
  ...(process.env.CIGAR_TEST_WORKER ? {workerPath: process.env.CIGAR_TEST_WORKER} : {}),storage:{directory},
});
const code = (wanted: string) => (error: unknown) => error instanceof LocalBrokerError && error.code === wanted;
const grant = (broker: LocalContextBroker) => broker.grant({id:"agent",allowed_sources:["docs"],policy_revision:"same"});
const ingest = async (broker: LocalContextBroker, text: string) => broker.replaceSource("docs",
  await broker.sourceRevision("docs"),[{id:"fact",source:"docs",text}],provenance);

test("Node broker restores evidence and withdrawal while rejecting pre-restart context and CAS", {
  skip:process.platform === "win32" ? "persistent directory protection is not implemented for Windows" : false,
  timeout:30_000,
}, async()=>{
  const directory = await mkdtemp(join(tmpdir(),"cigar-broker-store-"));
  try {
    await using original = await LocalContextBroker.create("node-durable",options(directory));
    assert.deepEqual(original.capabilities().storage,{mode:"sqlite-checkpoint.v1",restored:false});
    const old = (await ingest(original,"durable evidence")).revision;
    const client = new LocalContextClient(await grant(original));
    const result = await client.compile({query:"evidence",required:["fact"]});
    await assert.rejects(LocalContextBroker.create("node-durable",options(directory)),code("Unavailable"));
    await original.close();
    await using restored = await LocalContextBroker.create("node-durable",options(directory));
    assert.equal(restored.capabilities().storage?.restored,true);
    const current = await restored.sourceRevision("docs");
    assert.equal(current.version,old.version);
    assert.notEqual(current.epoch,old.epoch);
    await assert.rejects(restored.replaceSource("docs",old,[],provenance),code("Conflict"));
    const fresh = new LocalContextClient(await grant(restored));
    await assert.rejects(fresh.revalidate(result.ticket),code("AccessDenied"));
    assert.match((await fresh.compile({query:"evidence"})).rendered,/durable evidence/u);
    await restored.replaceSource("docs",current,[],provenance);
    await restored.close();
    await using withdrawn = await LocalContextBroker.create("node-durable",options(directory));
    assert.equal((await withdrawn.sourceRevision("docs")).version,"2");
    const reader = new LocalContextClient(await grant(withdrawn));
    assert.doesNotMatch((await reader.compile({query:"evidence"})).rendered,/durable evidence/u);
  } finally { await rm(directory,{recursive:true}); }
});

test("Node durability failure closes the broker without a false failure receipt or retry", {
  skip:process.platform === "win32" ? "persistent directory protection is not implemented for Windows" : false,
  timeout:30_000,
},async()=>{
  const directory = await mkdtemp(join(tmpdir(),"cigar-broker-store-"));
  const opts: LocalBrokerOptions = {...options(directory),storage:{directory,max_checkpoint_bytes:4096}};
  try {
    await using original = await LocalContextBroker.create("node-durable",opts);
    await ingest(original,"original evidence");
    await assert.rejects(ingest(original,"large evidence".repeat(1000)),(error:unknown)=>
      error instanceof LocalBrokerError && error.code === "Transport" && error.dispatched === null);
    await assert.rejects(original.sourceRevision("docs"),code("Closed"));
    await using restored = await LocalContextBroker.create("node-durable",opts);
    assert.equal((await restored.sourceRevision("docs")).version,"1");
    assert.match((await new LocalContextClient(await grant(restored)).compile({query:"evidence"})).rendered,/original evidence/u);
  } finally { await rm(directory,{recursive:true}); }
});
