// Offline large-source contract probe against an explicitly supplied compiled SDK and worker.
// This validates a frame boundary and recovery; elapsed time is not a comparative performance claim.
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {createReadStream} from "node:fs";
import {mkdtemp, readdir, readFile, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {dirname, isAbsolute, join, relative} from "node:path";
import {createInterface} from "node:readline";
import {pathToFileURL} from "node:url";

const [sdkFile, worker, corpus] = process.argv.slice(2);
assert.equal(process.argv.length,5);
assert([sdkFile,worker,corpus].every(value=>isAbsolute(value)));
const {LocalContextBroker,LocalContextClient,LocalBrokerError} = await import(pathToFileURL(sdkFile).href);
const sha = bytes=>createHash("sha256").update(bytes).digest("hex");
async function fileHash(path) {
  const digest = createHash("sha256");
  for await (const part of createReadStream(path)) digest.update(part);
  return digest.digest("hex");
}
async function sdkHash() {
  const root=dirname(sdkFile), files=[];
  async function collect(directory) {
    for (const entry of await readdir(directory,{withFileTypes:true})) {
      if (entry.name==="tests") continue;
      const path=join(directory,entry.name);
      if (entry.isDirectory()) await collect(path);
      else if (entry.isFile()) files.push([relative(root,path),sha(await readFile(path))]);
      else throw new Error("unexpected SDK input type");
    }
  }
  await collect(root);
  return sha(JSON.stringify(files.sort((a,b)=>a[0].localeCompare(b[0],"en"))));
}
async function* documents() {
  const stream=createReadStream(corpus);
  const reader=createInterface({input:stream,crlfDelay:Infinity});
  try { for await (const line of reader) yield JSON.parse(line); }
  finally { reader.close(); stream.destroy(); }
}
const provenance={authority:"fixture-host",upstream_revision:"one",observed_at_ms:1,
  valid_until_ms:null,origin:"host",derived_from:[]};
const code=expected=>error=>error instanceof LocalBrokerError && error.code===expected;
const grant=async host=>new LocalContextClient(await host.grant({id:"reader",allowed_sources:["docs"],policy_revision:"one"},
  {limits:{max_tokens:100000}}));
const initial={worker_sha256:await fileHash(worker),corpus_sha256:await fileHash(corpus),sdk_dist_sha256:await sdkHash()};
const rows=[];
for (const mode of ["memory","sqlite"]) {
  const directory=await mkdtemp(join(tmpdir(),"cigar-node-large-source-"));
  const options={workerPath:worker,timeoutMs:120_000,
    graph:{max_documents:10000,max_document_bytes:256*1024,max_total_bytes:64*1024*1024},
    retention:{max_retained_bytes:64*1024*1024},
    ...(mode==="sqlite"?{storage:{directory:join(directory,"store"),create_directory:true,
      max_checkpoint_bytes:64*1024*1024,max_database_bytes:256*1024*1024}}:{})};
  try {
    await using host=await LocalContextBroker.create("node-ingestion-probe",options);
    const before=(await host.replaceSource("docs",await host.sourceRevision("docs"),[
      {id:"obsolete",source:"docs",text:"Old evidence remains until commit."}],provenance)).revision;
    const client=await grant(host), old=await client.compile({query:"evidence",required:["obsolete"]});
    let all=[];
    for await (const document of documents()) all.push(document);
    const textBytes=all.reduce((sum,document)=>sum+Buffer.byteLength(document.text),0), count=all.length;
    assert(textBytes>32*1024*1024);
    await assert.rejects(host.replaceSource("docs",before,all,provenance),error=>
      error instanceof LocalBrokerError && error.code==="LimitExceeded" && error.dispatched===false);
    all=null;
    assert.deepEqual(await host.sourceRevision("docs"),before);
    let batches=0;
    async function* input() {
      let batch=[];
      for await (const document of documents()) {
        batch.push(document);
        if (batch.length===4) {
          assert.deepEqual(await host.sourceRevision("docs"),before);
          await client.revalidate(old.ticket);
          batches++;
          yield batch;
          batch=[];
        }
      }
      if (batch.length) { batches++; yield batch; }
      assert.deepEqual(await host.sourceRevision("docs"),before);
      await client.revalidate(old.ticket);
    }
    const receipt=await host.replaceSourceBatches("docs",before,input(),provenance,{leaseMs:120_000});
    assert.deepEqual(receipt,{revision:{...before,version:"2"},inserted:count,replaced:0,removed:1,unchanged:0});
    await assert.rejects(client.revalidate(old.ticket),code("Stale"));
    async function verify(reader) {
      const result=await reader.compile({query:"retry policy",required:["probe"],max_tokens:512});
      assert.match(result.rendered,/Retry policy: stop after three attempts\./u);
      assert.equal(result.context.snapshot.stats.documents,count);
      assert(result.context.snapshot.stats.rendered_tokens<=512);
      assert.deepEqual([...new Set(result.context.snapshot.blocks.flatMap(block=>block.citations.map(value=>value.node_id)))],["probe"]);
      return sha(result.rendered);
    }
    const rendered=await verify(client);
    async function verifyEveryDocument(reader) {
      let checked=0;
      for await (const document of documents()) {
        const context=await reader.compile({query:"evidence",required:[document.id],allowed:[document.id],max_tokens:100000});
        assert.equal(context.context.snapshot.blocks.length,1);
        assert.equal(context.context.snapshot.blocks[0].text,document.text);
        assert.equal(context.context.snapshot.blocks[0].citations[0].node_id,document.id);
        assert.equal(context.context.snapshot.blocks[0].citations[0].source,document.source);
        await reader.forgetTicket(context.ticket);
        checked++;
      }
      assert.equal(checked,count);
      return checked;
    }
    const checkedDocuments=await verifyEveryDocument(client);
    await host.close();
    if (mode==="sqlite") {
      await using restored=await LocalContextBroker.create("node-ingestion-probe",options);
      const current=await restored.sourceRevision("docs");
      assert.equal(current.version,receipt.revision.version);
      assert.notEqual(current.epoch,receipt.revision.epoch);
      const restoredClient=await grant(restored);
      assert.equal(await verify(restoredClient),rendered);
      assert.equal(await verifyEveryDocument(restoredClient),count);
    }
    rows.push({status:"ok",mode,documents:count,text_bytes:textBytes,batches,
      whole_frame:"rejected_before_dispatch",batched:"committed",rendered_sha256:rendered,
      exact_document_round_trips:checkedDocuments,restored:mode==="sqlite"});
  } finally { await rm(directory,{recursive:true}); }
}
assert.deepEqual(initial,{worker_sha256:await fileHash(worker),corpus_sha256:await fileHash(corpus),sdk_dist_sha256:await sdkHash()});
console.log(JSON.stringify({schema:"cigar.node-large-ingestion.v1",node:process.version,model_mode:"none",
  harness_sha256:await fileHash(process.argv[1]),...initial,rows}));
