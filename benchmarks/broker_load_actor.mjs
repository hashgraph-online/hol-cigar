// Independent Node consumer. Grant material enters only through private stdin.
import {createHash} from "node:crypto";
import {isAbsolute} from "node:path";
import {pathToFileURL} from "node:url";

const [sdkFile]=process.argv.slice(2);
if (!sdkFile || !isAbsolute(sdkFile) || process.argv.length!==3) throw new Error("explicit compiled SDK required");
const {LocalBrokerConnection,LocalBrokerError,LocalContextClient}=await import(pathToFileURL(sdkFile).href);
const hash=text=>createHash("sha256").update(text).digest("hex");
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

async function* commands() {
  process.stdin.setEncoding("utf8");
  let pending="";
  for await (const part of process.stdin) {
    pending+=part;
    if (Buffer.byteLength(pending)>4*1024*1024) throw new Error("private control frame bound");
    let end;
    while ((end=pending.indexOf("\n"))!==-1) {
      const value=JSON.parse(pending.slice(0,end));
      pending=pending.slice(end+1);
      if (!value || typeof value!=="object" || Array.isArray(value)) throw new Error("invalid private envelope");
      yield value;
    }
  }
  if (pending) throw new Error("truncated private control frame");
}
async function emit(value) {
  const text=JSON.stringify(value)+"\n";
  if (Buffer.byteLength(text)>16*1024*1024) throw new Error("observation response bound");
  await new Promise((resolve,reject)=>process.stdout.write(text,error=>error?reject(error):resolve()));
}
function checkContext(result,expected,count,budget) {
  const snapshot=result.context.snapshot,selected=new Set();
  for (const block of snapshot.blocks) for (const citation of block.citations) {
    const document=expected.get(citation.node_id);
    if (!document || selected.has(citation.node_id) || block.text!==document.text || citation.source!==document.source)
      throw new Error("unexpected selected evidence");
    selected.add(citation.node_id);
  }
  if (selected.size!==expected.size || snapshot.stats.documents!==count || snapshot.stats.rendered_tokens>budget)
    throw new Error("scope or budget mismatch");
  return hash(result.rendered);
}
async function observed(operation) {
  const start=performance.now();
  let result=null,status;
  try { result=await operation(); status={status:"ok"}; }
  catch (error) {
    status=error instanceof LocalBrokerError?{status:"error",code:error.code,dispatched:error.dispatched}:
      {status:"harness_error",kind:error?.constructor?.name??"Unknown"};
  }
  return [result,{...status,elapsed_ms:performance.now()-start,timing:null}];
}
class Actor {
  constructor(config) {
    this.timeout=config.call_timeout_ms;
    this.client=this.connect(config.connection);
    this.request=config.request;
    this.expected=new Map(config.required_documents.map(document=>[document.id,document]));
    this.count=config.scope_documents;
    this.retained=new Map();
    this.contexts=new Map();
  }
  connect(config) {return new LocalContextClient(LocalBrokerConnection.fromConfig(config),{timeoutMs:this.timeout,maxPending:4});}
  async compile() {
    const context=await this.client.compile(this.request);
    try {return [context,checkContext(context,this.expected,this.count,this.request.max_tokens)];}
    catch(error) {await this.client.forgetTicket(context.ticket); throw error;}
  }
  async measure(command) {
    if (!(command.duration_ms>=100 && command.duration_ms<=30000) || ![1,4].includes(command.parallelism) ||
        !Number.isInteger(command.max_cycles) || command.max_cycles<1 || command.max_cycles>10000)
      throw new Error("unregistered load bounds");
    const delay=command.start_at_ms-Date.now();
    if (!(delay>0 && delay<=5000)) throw new Error("start deadline missed");
    const start=performance.now()+delay,deadline=start+command.duration_ms;
    const samples=[],starts=[];
    let sequence=0;
    async function lane(actor,laneId) {
      await sleep(Math.max(0,start-performance.now()));
      starts.push(Date.now());
      while (performance.now()<deadline) {
        if (sequence>=command.max_cycles) return;
        const index=sequence++;
        const [value,compile]=await observed(()=>actor.compile());
        let forget=null,rendered_sha256=null;
        if (value!==null) {
          const [context,digest]=value;
          rendered_sha256=digest;
          [,forget]=await observed(()=>actor.client.forgetTicket(context.ticket));
        }
        samples.push({sequence:index,lane:laneId,compile,forget,rendered_sha256});
      }
    }
    await Promise.all(Array.from({length:command.parallelism},(_,id)=>lane(this,id)));
    return {status:"ok",kind:"measure",samples:samples.sort((a,b)=>a.sequence-b.sequence),actual_start_ms:Math.min(...starts),
      finish_ms:Date.now(),monotonic_window_ms:performance.now()-start,capped:sequence>=command.max_cycles,duration_ms:command.duration_ms,native_timing:"unavailable",attempted:sequence};
  }
  async command(command) {
    switch(command.op) {
      case "verify_documents": {
        const documents=command.documents,digests=[];
        if(!Array.isArray(documents) || !documents.length || documents.length>4096) throw new Error("unregistered verification size");
        for(let offset=0;offset<documents.length;offset+=16) {
          const batch=documents.slice(offset,offset+16),request={query:"evidence",required:batch.map(value=>value.id),max_tokens:16384,max_blocks:batch.length};
          const context=await this.client.compile(request);
          try {digests.push(checkContext(context,new Map(batch.map(value=>[value.id,value])),command.scope_documents,request.max_tokens));}
          finally {await this.client.forgetTicket(context.ticket);}
        }
        return {status:"ok",documents:documents.length,batch_digests:digests};
      }
      case "measure": return this.measure(command);
      case "warmup": {
        for(let i=0;i<command.cycles;i++) {const [context]=await this.compile(); await this.client.forgetTicket(context.ticket);}
        return {status:"ok"};
      }
      case "retain": {
        const [context,digest]=await this.compile();
        this.retained.set(command.slot,context.ticket);
        this.contexts.set(command.slot,context);
        return {status:"ok",rendered_sha256:digest,private_ticket:context.ticket};
      }
      case "revalidate": return (await observed(()=>this.client.revalidate(this.retained.get(command.slot))))[1];
      case "foreign_ticket": return (await observed(()=>this.client.revalidate(command.private_ticket)))[1];
      case "compile_probe": {
        const [digest,outcome]=await observed(async()=>{
          const context=await this.client.compile(command.request);
          try {return command.required_documents?
            checkContext(context,new Map(command.required_documents.map(document=>[document.id,document])),command.scope_documents,command.request.max_tokens):
            hash(context.rendered);}
          finally {await this.client.forgetTicket(context.ticket);}
        });
        return {...outcome,rendered_sha256:digest};
      }
      case "submit": {
        const context=this.contexts.get(command.slot),document=this.expected.values().next().value;
        const draft={snapshot_id:context.context.snapshot.id,claims:[{text:document.text,citations:[document.id],confidence_bps:9900}]};
        const [submission_id,outcome]=await observed(()=>this.client.submitAnswer(context.ticket,draft));
        return {...outcome,submission_id};
      }
      case "configure": {
        this.client=this.connect(command.connection);
        this.expected=new Map(command.required_documents.map(document=>[document.id,document]));
        this.count=command.scope_documents;
        if(command.request) this.request=command.request;
        return {status:"ok"};
      }
      case "proposal": {
        const [proposal,outcome]=await observed(()=>this.client.proposeSource(command.request_key,command.source,command.expected,command.documents));
        return {...outcome,proposal};
      }
      case "proposal_status": {
        const [proposal,outcome]=await observed(()=>this.client.proposalStatus(command.request_key));
        return {...outcome,proposal};
      }
      case "forget": {
        await this.client.forgetTicket(this.retained.get(command.slot));
        this.retained.delete(command.slot);
        this.contexts.delete(command.slot);
        return {status:"ok"};
      }
      case "forget_proposal": return (await observed(()=>this.client.forgetProposal(command.request_key)))[1];
      default: throw new Error("unknown private control operation");
    }
  }
}

try {
  const input=commands(),first=await input.next();
  if (!first.done) {
    const actor=new Actor(first.value);
    await emit({status:"ready",pid:process.pid,runtime:"node",version:process.version});
    for await (const command of input) {
      if(command.op==="close") {await emit({status:"closed"}); break;}
      let response;
      try {response=await actor.command(command);}
      catch(error) {response={status:"harness_error",kind:error?.constructor?.name??"Unknown"};}
      await emit(response);
    }
  }
} catch(error) {
  await emit({status:"harness_error",kind:error?.constructor?.name??"Unknown"});
  process.exitCode=1;
}
