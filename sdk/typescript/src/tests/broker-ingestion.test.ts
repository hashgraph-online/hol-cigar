import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { LocalBrokerError, LocalContextBroker, LocalContextClient } from "../context-api.js";
import type { LocalBrokerOptions, LocalBrokerSourceProvenance, LocalDocument } from "../context-api.js";

const provenance: LocalBrokerSourceProvenance = {authority:"host",upstream_revision:"one",
  observed_at_ms:1,valid_until_ms:null,origin:"host",derived_from:[]};
const options = (): LocalBrokerOptions => process.env.CIGAR_TEST_WORKER ? {workerPath:process.env.CIGAR_TEST_WORKER} : {};
const code = (wanted: string) => (error: unknown) => error instanceof LocalBrokerError && error.code === wanted;
const document = (id="fact",text="new evidence"): LocalDocument => ({id,source:"docs",text});
const reader = async (broker: LocalContextBroker) => new LocalContextClient(await broker.grant({
  id:"reader",allowed_sources:["docs"],policy_revision:"one"}));
const seed = async (broker: LocalContextBroker) => (await broker.replaceSource("docs",
  await broker.sourceRevision("docs"),[document("fact","old evidence")],provenance)).revision;

test("async batch input has one visibility point and preserves noop replacement and withdrawal",async()=>{
  await using broker = await LocalContextBroker.create("batch-sdk",options());
  const before = await seed(broker);
  const client = await reader(broker);
  const previous = await client.compile({query:"evidence",required:["fact"]});
  const documents = [document(),document("extra","additional evidence")];
  async function* batches() {
    for (const value of documents) {
      assert.deepEqual(await broker.sourceRevision("docs"),before);
      await client.revalidate(previous.ticket);
      const context = await client.compile({query:"evidence",required:["fact"]});
      assert.match(context.rendered,/old evidence/u);
      assert.doesNotMatch(context.rendered,/new evidence/u);
      await client.forgetTicket(context.ticket);
      yield [value];
    }
    assert.deepEqual(await broker.sourceRevision("docs"),before);
    await client.revalidate(previous.ticket);
  }
  const receipt = await broker.replaceSourceBatches("docs",before,batches(),provenance);
  assert.deepEqual(receipt,{revision:{...before,version:"2"},inserted:1,replaced:1,removed:0,unchanged:0});
  await assert.rejects(client.revalidate(previous.ticket),code("Stale"));
  const after = await client.compile({query:"evidence",required:["fact","extra"]});
  assert.match(after.rendered,/new evidence/u);
  assert.match(after.rendered,/additional evidence/u);
  const ordinary = await broker.replaceSource("docs",receipt.revision,documents,provenance);
  assert.deepEqual(ordinary.revision,receipt.revision);
  assert.equal(ordinary.unchanged,2);
  await client.revalidate(after.ticket);
  const withdrawal = await broker.replaceSourceBatches("docs",receipt.revision,[],provenance);
  assert.equal(withdrawal.removed,2);
  assert.equal(withdrawal.revision.version,"3");
  assert.deepEqual((await client.compile({query:"evidence"})).context.snapshot.blocks,[]);
});

test("low level batch handles are host-only, consumed, and harmless to abort twice",async()=>{
  await using broker = await LocalContextBroker.create("batch-sdk",options());
  const before = await seed(broker), client = await reader(broker);
  for (const name of ["beginSourceReplace","appendSourceDocuments","commitSourceReplace","abortSourceReplace"])
    assert.equal(name in client,false);
  const transaction = await broker.beginSourceReplace("docs",before,provenance);
  assert.equal(transaction.epoch,before.epoch);
  assert.equal(await broker.appendSourceDocuments(transaction,[document()]),1);
  assert.equal(await broker.appendSourceDocuments(transaction,[document("extra")]),2);
  assert.deepEqual(await broker.sourceRevision("docs"),before);
  assert.equal(await broker.abortSourceReplace({...transaction,epoch:"0".repeat(64)}),false);
  assert.equal(await broker.abortSourceReplace(transaction),true);
  assert.equal(await broker.abortSourceReplace(transaction),false);
  await assert.rejects(broker.commitSourceReplace(transaction),code("Stale"));
  const next = await broker.beginSourceReplace("docs",before,provenance);
  await broker.appendSourceDocuments(next,[document()]);
  await broker.commitSourceReplace(next);
  await assert.rejects(broker.commitSourceReplace(next),code("Stale"));
});

test("invalid later batches release all staging slots and leave old evidence intact",async()=>{
  await using broker = await LocalContextBroker.create("batch-sdk",options());
  const before = await seed(broker), client = await reader(broker);
  for (const bad of [[],[document()],[{...document("second"),source:"wrong"}]]) {
    for (let repeat=0;repeat<5;repeat++) {
      // Five attempts would exhaust the four slots if the convenience API leaked staging.
      await assert.rejects(broker.replaceSourceBatches("docs",before,[[document()],bad],provenance),code("InvalidInput"));
      assert.deepEqual(await broker.sourceRevision("docs"),before);
    }
  }
  assert.match((await client.compile({query:"evidence"})).rendered,/old evidence/u);
});

test("sync and async generator failures preserve the original error even if abort fails",async()=>{
  await using broker = await LocalContextBroker.create("batch-sdk",options());
  const before = await seed(broker), failure = new Error("caller-owned input failure");
  function* sync() { yield [document()]; throw failure; }
  async function* asynchronous() { yield [document()]; throw failure; }
  for (const generate of [sync,asynchronous]) for (let repeat=0;repeat<5;repeat++) {
    await assert.rejects(broker.replaceSourceBatches("docs",before,generate(),provenance),error=>error===failure);
  }
  broker.abortSourceReplace=async()=>{throw new LocalBrokerError("Closed");};
  await assert.rejects(broker.replaceSourceBatches("docs",before,asynchronous(),provenance),error=>error===failure);
  assert.deepEqual(await broker.sourceRevision("docs"),before);
});

test("batch commit rechecks source CAS without retrying or publishing stale generator output",async()=>{
  await using broker = await LocalContextBroker.create("batch-sdk",options());
  const before = await seed(broker);
  async function* batches() {
    yield [document()];
    await broker.replaceSource("docs",before,[document("fact","concurrent evidence")],provenance);
  }
  const commit = broker.commitSourceReplace.bind(broker);
  let calls=0;
  broker.commitSourceReplace=async transaction=>{calls++; return commit(transaction);};
  await assert.rejects(broker.replaceSourceBatches("docs",before,batches(),provenance),error=>
    error instanceof LocalBrokerError && error.code==="Conflict" && error.dispatched===true);
  assert.equal(calls,1);
  assert.equal((await broker.sourceRevision("docs")).version,"2");
  assert.match((await (await reader(broker)).compile({query:"evidence"})).rendered,/concurrent evidence/u);
});

test("batch capabilities are required before consuming input or dispatching a host command",async()=>{
  await using broker = await LocalContextBroker.create("batch-sdk",options());
  const before = await broker.sourceRevision("docs"), hello = broker.capabilities();
  broker.capabilities=()=>({...hello,capabilities:hello.capabilities.filter(value=>value!=="source_batches.v1")});
  const transaction = {epoch:before.epoch,id:"a".repeat(64)};
  const batches: Iterable<LocalDocument[]> = {[Symbol.iterator](){throw new Error("input must not be consumed");}};
  for (const action of [
    ()=>broker.beginSourceReplace("docs",before,provenance),
    ()=>broker.appendSourceDocuments(transaction,[document()]),
    ()=>broker.commitSourceReplace(transaction),
    ()=>broker.abortSourceReplace(transaction),
    ()=>broker.replaceSourceBatches("docs",before,batches,provenance),
  ]) await assert.rejects(action,error=>error instanceof LocalBrokerError && error.code==="IncompatibleWorker" && error.dispatched===false);
});

test("restart discards staging and retains only a committed replacement",{timeout:30_000},async()=>{
  const directory = await mkdtemp(join(tmpdir(),"cigar-batches-"));
  const opts: LocalBrokerOptions = {...options(),storage:{directory:join(directory,"store"),create_directory:true}};
  try {
    await using original = await LocalContextBroker.create("batch-sdk",opts);
    const before = await seed(original);
    const transaction = await original.beginSourceReplace("docs",before,provenance);
    const database = join(directory,"store","broker.sqlite3"), saved = await readFile(database);
    await original.appendSourceDocuments(transaction,[document("fact","UNCOMMITTED_PRIVATE_INPUT")]);
    assert.deepEqual(await readFile(database),saved);
    await original.close();
    await using restored = await LocalContextBroker.create("batch-sdk",opts);
    const current = await restored.sourceRevision("docs");
    assert.equal(current.version,before.version);
    await assert.rejects(restored.commitSourceReplace(transaction),code("Stale"));
    assert.match((await (await reader(restored)).compile({query:"evidence"})).rendered,/old evidence/u);
    const receipt = await restored.replaceSourceBatches("docs",current,[[document()]],provenance);
    await restored.close();
    await using committed = await LocalContextBroker.create("batch-sdk",opts);
    assert.equal((await committed.sourceRevision("docs")).version,receipt.revision.version);
    assert.match((await (await reader(committed)).compile({query:"evidence"})).rendered,/new evidence/u);
  } finally { await rm(directory,{recursive:true}); }
});

test("durable batch failure closes owner with unknown outcome without retry or cleanup masking",{timeout:30_000},async()=>{
  const directory = await mkdtemp(join(tmpdir(),"cigar-batches-"));
  const opts: LocalBrokerOptions = {...options(),storage:{
    directory:join(directory,"store"),create_directory:true,max_checkpoint_bytes:4096}};
  try {
    await using original = await LocalContextBroker.create("batch-sdk",opts);
    const before = await seed(original);
    const commit = original.commitSourceReplace.bind(original);
    let calls=0;
    original.commitSourceReplace=async transaction=>{calls++; return commit(transaction);};
    await assert.rejects(original.replaceSourceBatches("docs",before,[[document("fact","large evidence ".repeat(1000))]],provenance),
      error=>error instanceof LocalBrokerError && error.code==="Transport" && error.dispatched===null);
    assert.equal(calls,1);
    assert.throws(()=>original.capabilities(),code("Closed"));
    await using restored = await LocalContextBroker.create("batch-sdk",opts);
    assert.equal((await restored.sourceRevision("docs")).version,before.version);
    assert.match((await (await reader(restored)).compile({query:"evidence"})).rendered,/old evidence/u);
  } finally { await rm(directory,{recursive:true}); }
});
