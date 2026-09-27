import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import { Socket } from "node:net";
import { inspect } from "node:util";
import { LOCAL_CONTEXT_CORE_VERSION, LocalContextError } from "./local-runtime.js";
import { WorkerChannel } from "./local-worker.js";
import type { WorkerReply } from "./local-worker.js";
import { assertUniqueJsonKeys } from "./strict-json.js";
import type {
  LocalAnswerDraft, LocalAnswerPolicy, LocalCitation, LocalClaimReview, LocalContextRequest,
  LocalDocument, LocalEdgeKind, LocalViewAssessment, LocalViewSpec,
} from "./context-types.js";
import type {
  LocalBrokerAgentLimits, LocalBrokerAgentQueueLimits, LocalBrokerCapabilities, LocalBrokerConnectionConfig,
  LocalBrokerContext, LocalBrokerOptions, LocalBrokerProposal, LocalBrokerProposalStatus,
  LocalBrokerSourceProvenance, LocalBrokerSourceReceipt, LocalBrokerSourceRevision, LocalBrokerSubmission,
} from "./broker-types.js";

const PROTOCOL = "cigar.context-broker.v1";
const MAX_FRAME = 2 * 1024 * 1024, MAX_RESPONSE = 8 * 1024 * 1024, MAX_HANDSHAKE = 1024;
const ERRORS = new Set(["AccessDenied", "Stale", "Conflict", "Quota", "InvalidInput", "Unavailable",
  "LimitExceeded", "RequiredUnavailable", "BudgetUnsatisfiable", "Tokenizer", "Integrity", "BaseMismatch",
  "Expired", "Cancelled", "Closed"]);

/** null means a sent operation's outcome is unknown. false proves no dispatch;
 * true accompanies a known server failure. No error triggers an automatic retry. */
export class LocalBrokerError extends LocalContextError {
  readonly dispatched: boolean | null;
  constructor(code: string, dispatched: boolean | null = false) {
    super(code); this.name = "LocalBrokerError"; this.dispatched = dispatched;
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key));
}
function hex(value: unknown): value is string { return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value); }
function parse(text: string): unknown {
  assertUniqueJsonKeys(text);
  return JSON.parse(text, (_key, value: unknown) => {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error();
    return value;
  }) as unknown;
}
function decode(bytes: Buffer): unknown { return parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes)); }
function reply(text: string, id: number): WorkerReply {
  const value = parse(text);
  if (!record(value) || !keys(value, ["protocol", "id", "outcome", "timing"]) ||
      value.protocol !== PROTOCOL || value.id !== id || !record(value.timing) ||
      !keys(value.timing, ["queue_us", "service_us"]) ||
      Object.values(value.timing).some(n => typeof n !== "number" || !Number.isSafeInteger(n) || n < 0)) throw new Error();
  const outcome = value.outcome;
  if (!record(outcome)) throw new Error();
  if (outcome.status === "ok" && keys(outcome, ["status", "result"])) return {ok: true, result: outcome.result};
  if (!keys(outcome, ["status", "error", "dispatched"]) || outcome.status !== "error" ||
      typeof outcome.error !== "string" || !ERRORS.has(outcome.error) || typeof outcome.dispatched !== "boolean") throw new Error();
  return {ok: false, error: new LocalBrokerError(outcome.error, outcome.dispatched)};
}

/** One host-issued grant. Inspection/JSON are redacted; export() deliberately exposes protected-IPC material. */
export class LocalBrokerConnection {
  readonly #secret: string;
  constructor(readonly port: number, readonly epoch: string, secret: string) {
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !hex(epoch) || !hex(secret)) throw new LocalBrokerError("InvalidInput");
    this.#secret = secret;
    Object.freeze(this);
  }
  [inspect.custom](): string { return "LocalBrokerConnection(<redacted>)"; }
  toJSON(): string { return "LocalBrokerConnection(<redacted>)"; }
  toString(): string { return "LocalBrokerConnection(<redacted>)"; }
  /** Sensitive copy for protected IPC to one agent. Never log the returned object. */
  export(): LocalBrokerConnectionConfig {
    return {schema: "cigar.broker-client.v1", host: "127.0.0.1", port: this.port, epoch: this.epoch, secret: this.#secret};
  }
  static fromConfig(config: LocalBrokerConnectionConfig): LocalBrokerConnection {
    if (!record(config) || !keys(config, ["schema", "host", "port", "epoch", "secret"]) ||
        config.schema !== "cigar.broker-client.v1" || config.host !== "127.0.0.1") throw new LocalBrokerError("InvalidInput");
    return new LocalBrokerConnection(config.port, config.epoch, config.secret);
  }
}

/** Trusted owner of one shared graph. Keep this object and worker pipes outside agent control.
 * Host transport uncertainty closes the worker without automatic restart or retry. */
export class LocalContextBroker implements AsyncDisposable {
  readonly #channel: WorkerChannel;
  #hello: LocalBrokerCapabilities | undefined;
  private constructor(options: LocalBrokerOptions) { this.#channel = new WorkerChannel(options, ["--broker"], reply); }

  static async create(domain: string, options: LocalBrokerOptions = {}): Promise<LocalContextBroker> {
    let broker: LocalContextBroker;
    try { broker = new LocalContextBroker(options); }
    catch (error) { throw asBrokerError(error, false); }
    try {
      const hello = await broker.call<unknown>({op: "init", domain, graph: options.graph ?? {},
        retention: options.retention ?? {}, queues: options.queues ?? {}, transport: options.transport ?? {},
        ...(options.storage === undefined ? {} : {storage: options.storage})});
      if (!record(hello) || hello.protocol !== PROTOCOL || hello.core_version !== LOCAL_CONTEXT_CORE_VERSION ||
          hello.host !== "127.0.0.1" || typeof hello.port !== "number" || !Number.isInteger(hello.port) ||
          hello.port < 1 || hello.port > 65535 || !hex(hello.epoch) || hello.max_frame_bytes !== MAX_FRAME ||
          hello.max_response_bytes !== MAX_RESPONSE || hello.host_max_frame_bytes !== 32 * 1024 * 1024 ||
          hello.host_max_response_bytes !== 64 * 1024 * 1024 || hello.requires_hol_services !== false ||
          hello.execution !== "single-owner-fair-dispatch" || !Array.isArray(hello.capabilities) ||
          hello.capabilities.some((v: unknown) => typeof v !== "string") || !hello.capabilities.includes("mutual_grant_proof.v1")) {
        throw new LocalBrokerError("IncompatibleWorker", null);
      }
      broker.#hello = structuredClone(hello) as LocalBrokerCapabilities;
      if (options.storage !== undefined && (!record(hello.storage) || !keys(hello.storage, ["mode", "restored"]) ||
          hello.storage.mode !== "sqlite-checkpoint.v1" || typeof hello.storage.restored !== "boolean")) {
        throw new LocalBrokerError("IncompatibleWorker", null);
      }
      return broker;
    } catch (error) { await broker.close(); throw error; }
  }

  private async call<T>(command: Record<string, unknown>): Promise<T> {
    try { return await this.#channel.call<T>(command); }
    catch (error) {
      const uncertain = error instanceof LocalContextError && ["Transport", "Timeout"].includes(error.code);
      throw asBrokerError(error, uncertain ? null : false);
    }
  }
  capabilities(): LocalBrokerCapabilities {
    if (this.#channel.closed || !this.#hello) throw new LocalBrokerError("Closed");
    return structuredClone(this.#hello);
  }
  async grant(view: LocalViewSpec, options: Readonly<{
    limits?: LocalBrokerAgentLimits; queue?: LocalBrokerAgentQueueLimits; leaseMs?: number;
  }> = {}): Promise<LocalBrokerConnection> {
    const value = await this.call<unknown>({op: "grant", spec: {view, limits: options.limits ?? {}, lease_ms: options.leaseMs ?? 300_000},
      queue: options.queue ?? {}});
    try {
      const hello = this.#hello;
      if (!hello || !record(value) || !keys(value, ["epoch", "secret"]) || value.epoch !== hello.epoch || !hex(value.secret)) throw new Error();
      return new LocalBrokerConnection(hello.port, hello.epoch, value.secret);
    } catch { await this.close(); throw new LocalBrokerError("Transport", null); }
  }
  revoke(agent: string): Promise<boolean> { return this.call({op: "revoke", agent}); }
  sourceRevision(source: string): Promise<LocalBrokerSourceRevision> { return this.call({op: "source_revision", source}); }
  replaceSource(source: string, expected: LocalBrokerSourceRevision, documents: readonly LocalDocument[],
    provenance: LocalBrokerSourceProvenance): Promise<LocalBrokerSourceReceipt> {
    return this.call({op: "replace_source", source, expected, documents, provenance});
  }
  provenance(source: string): Promise<LocalBrokerSourceProvenance | null> { return this.call({op: "provenance", source}); }
  setEdge(from: string, to: string, kind: LocalEdgeKind, present: boolean,
    expected: Readonly<Record<string, LocalBrokerSourceRevision>>): Promise<Record<string, LocalBrokerSourceRevision>> {
    return this.call({op: "set_edge", from, to, kind, present, expected});
  }
  proposal(proposalId: string): Promise<LocalBrokerProposal> { return this.call({op: "proposal", proposal_id: proposalId}); }
  admitProposal(proposalId: string, provenance: LocalBrokerSourceProvenance): Promise<LocalBrokerSourceReceipt> {
    return this.call({op: "admit_proposal", proposal_id: proposalId, provenance});
  }
  async rejectProposal(proposalId: string): Promise<void> { await this.call({op: "reject_proposal", proposal_id: proposalId}); }
  submission(ticket: string): Promise<LocalBrokerSubmission> { return this.call({op: "submission", ticket}); }
  checkAnswer(ticket: string, submissionId: string, reviews: readonly LocalClaimReview[], policy: LocalAnswerPolicy = {}): Promise<LocalViewAssessment> {
    return this.call({op: "check_answer", ticket, submission_id: submissionId, reviews, policy});
  }
  async close(): Promise<void> { await this.#channel.close(); }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
}

function asBrokerError(error: unknown, dispatched: boolean | null): LocalBrokerError {
  if (error instanceof LocalBrokerError) return error;
  return new LocalBrokerError(error instanceof LocalContextError ? error.code : "Transport", dispatched);
}

/** Restricted agent facade. Owns no worker or persistent socket. Each operation authenticates
 * both peers before command transfer and uses one total deadline; no automatic retries. */
export class LocalContextClient {
  readonly #connection: LocalBrokerConnectionConfig;
  readonly #timeoutMs: number;
  readonly #waitMs: number;
  readonly #maxPending: number;
  #pending = 0;
  constructor(connection: LocalBrokerConnection, options: Readonly<{
    timeoutMs?: number; queueTimeoutMs?: number; maxPending?: number;
  }> = {}) {
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#waitMs = options.queueTimeoutMs ?? 30_000;
    this.#maxPending = options.maxPending ?? 4;
    if (!(connection instanceof LocalBrokerConnection) || !Number.isFinite(this.#timeoutMs) ||
        this.#timeoutMs <= 0 || this.#timeoutMs > 300_000 || !Number.isInteger(this.#waitMs) ||
        this.#waitMs < 1 || this.#waitMs > 86_400_000 || !Number.isInteger(this.#maxPending) ||
        this.#maxPending < 1 || this.#maxPending > 128) throw new LocalBrokerError("InvalidInput");
    this.#connection = connection.export();
  }

  private async call<T>(command: Record<string, unknown>): Promise<T> {
    if (this.#pending >= this.#maxPending) throw new LocalBrokerError("Busy");
    this.#pending++;
    const deadline = performance.now() + this.#timeoutMs;
    let sent = false;
    let timedOut = false;
    let socket: Socket | undefined;
    let timer: NodeJS.Timeout | undefined;
    try {
      let frame: Buffer;
      try {
        frame = Buffer.from(JSON.stringify({protocol: PROTOCOL, id: 1, wait_ms: this.#waitMs, command}, (_key, value: unknown) => {
          if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error();
          return value;
        }), "utf8");
      } catch { throw new LocalBrokerError("InvalidInput"); }
      if (frame.length > MAX_FRAME) throw new LocalBrokerError("LimitExceeded");
      const remaining = deadline - performance.now();
      if (remaining <= 0) throw new LocalBrokerError("Timeout");
      socket = new Socket();
      const peer = socket;
      // Keep an error handler installed between individual reads/writes. Each awaiting operation
      // also handles its own error; the outer catch exposes only a content-free SDK error.
      peer.on("error", () => undefined);
      peer.setNoDelay(true);
      timer = setTimeout(() => { timedOut = true; peer.destroy(new LocalBrokerError("Timeout", sent ? null : false)); }, remaining);
      const connected = once(peer, "connect");
      peer.connect({host: "127.0.0.1", port: this.#connection.port, family: 4});
      await connected;
      await this.authenticate(peer);
      sent = true;
      await writeFrame(peer, frame);
      const bytes = await readFrame(peer, MAX_RESPONSE);
      const result = reply(new TextDecoder("utf-8", {fatal: true}).decode(bytes), 1);
      if (!result.ok) throw result.error;
      return result.result as T;
    } catch (error) {
      if (timedOut) throw new LocalBrokerError("Timeout", sent ? null : false);
      throw asBrokerError(error, sent ? null : false);
    }
    finally { if (timer) clearTimeout(timer); socket?.destroy(); this.#pending--; }
  }

  private async authenticate(socket: Socket): Promise<void> {
    const config = this.#connection;
    const grant = createHash("sha256").update("cigar.broker-grant-id.v1\0" + config.epoch + config.secret).digest("hex");
    const nonce = randomBytes(32).toString("hex");
    await writeFrame(socket, Buffer.from(JSON.stringify({protocol: PROTOCOL, epoch: config.epoch, grant_id: grant, nonce})));
    const server = decode(await readFrame(socket, MAX_HANDSHAKE));
    if (!record(server) || !keys(server, ["protocol", "epoch", "grant_id", "client_nonce", "server_nonce", "proof"]) ||
        server.protocol !== PROTOCOL || server.epoch !== config.epoch || server.grant_id !== grant ||
        server.client_nonce !== nonce || !hex(server.server_nonce) || !hex(server.proof)) throw new LocalBrokerError("Authentication");
    const transcript = config.epoch + grant + nonce + server.server_nonce;
    const key = Buffer.from(config.secret, "hex");
    const expected = createHmac("sha256", key).update("cigar.broker-server-proof.v1\0" + transcript).digest();
    if (!timingSafeEqual(expected, Buffer.from(server.proof, "hex"))) throw new LocalBrokerError("Authentication");
    const proof = createHmac("sha256", key).update("cigar.broker-client-proof.v1\0" + transcript).digest("hex");
    await writeFrame(socket, Buffer.from(JSON.stringify({protocol: PROTOCOL, proof})));
  }

  compile(request: LocalContextRequest): Promise<LocalBrokerContext> { return this.call({op: "compile", request}); }
  async revalidate(ticket: string): Promise<void> { await this.call({op: "revalidate", ticket}); }
  citations(ticket: string, nodeId: string): Promise<readonly LocalCitation[]> { return this.call({op: "citations", ticket, node_id: nodeId}); }
  sourceRevision(source: string): Promise<LocalBrokerSourceRevision> { return this.call({op: "source_revision", source}); }
  proposeSource(requestKey: string, source: string, expected: LocalBrokerSourceRevision,
    documents: readonly LocalDocument[]): Promise<LocalBrokerProposalStatus> {
    return this.call({op: "propose_source", request_key: requestKey, source, expected, documents});
  }
  proposalStatus(requestKey: string): Promise<LocalBrokerProposalStatus> { return this.call({op: "proposal_status", request_key: requestKey}); }
  async forgetProposal(requestKey: string): Promise<void> { await this.call({op: "forget_proposal", request_key: requestKey}); }
  async forgetTicket(ticket: string): Promise<void> { await this.call({op: "forget_ticket", ticket}); }
  async submitAnswer(ticket: string, draft: LocalAnswerDraft): Promise<string> {
    return (await this.call<{submission_id: string}>({op: "submit_answer", ticket, draft})).submission_id;
  }
}

async function writeFrame(socket: Socket, bytes: Buffer): Promise<void> {
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
  await new Promise<void>((resolve, reject) => socket.write(Buffer.concat([prefix, bytes]), error => error ? reject(error) : resolve()));
}
async function readFrame(socket: Socket, limit: number): Promise<Buffer> {
  const length = (await readExact(socket, 4)).readUInt32BE();
  if (length < 1 || length > limit) throw new Error();
  return readExact(socket, length);
}
async function readExact(socket: Socket, length: number): Promise<Buffer> {
  const result = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    // Consume partial data before waiting again. Re-registering `readable` while
    // a short prefix remains buffered can spin on nextTick and starve deadlines.
    const available = Math.min(length - offset, socket.readableLength);
    if (available > 0) {
      const bytes: unknown = socket.read(available);
      if (!Buffer.isBuffer(bytes) || bytes.length !== available) throw new Error();
      bytes.copy(result, offset);
      offset += bytes.length;
      continue;
    }
    if (socket.destroyed || socket.readableEnded) throw new Error();
    await new Promise<void>((resolve, reject) => {
      const clean = (): void => { socket.off("readable", ready); socket.off("end", closed); socket.off("close", closed); socket.off("error", failed); };
      const ready = (): void => { clean(); resolve(); };
      const closed = (): void => { clean(); reject(new Error()); };
      const failed = (error: Error): void => { clean(); reject(error); };
      socket.once("readable", ready); socket.once("end", closed); socket.once("close", closed); socket.once("error", failed);
    });
  }
  return result;
}
