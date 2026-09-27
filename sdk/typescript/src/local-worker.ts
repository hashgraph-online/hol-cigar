import { spawn } from "node:child_process";
import type { ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { LocalContextError, resolveLocalWorker } from "./local-runtime.js";

/** Internal lifecycle shared by the local graph and private broker host. */
export type WorkerOptions = Readonly<{workerPath?: string; timeoutMs?: number; maxPending?: number}>;
export type WorkerReply = {ok: true; result: unknown} | {ok: false; error: Error};
const MAX_FRAME = 32 * 1024 * 1024;
const MAX_RESPONSE = 64 * 1024 * 1024;
type Pending = {id: number; resolve: (value: unknown) => void; reject: (error: Error) => void; timer: NodeJS.Timeout};

export class WorkerChannel implements AsyncDisposable {
  private readonly child: ChildProcessByStdio<Writable, Readable, null>;
  private readonly exited: Promise<void>;
  private readonly timeoutMs: number;
  private readonly maxPending: number;
  closed = false;
  private sequence = 0;
  private queued = 0;
  private queuedBytes = 0;
  private tail: Promise<unknown> = Promise.resolve();
  private pending: Pending | undefined;
  private fragments: Buffer[] = [];
  private received = 0;

  constructor(options: WorkerOptions, arguments_: readonly string[], private readonly decode: (text: string, id: number) => WorkerReply) {
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxPending = options.maxPending ?? 32;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0 || this.timeoutMs > 2_147_483_647 ||
        !Number.isInteger(this.maxPending) || this.maxPending < 1 || this.maxPending > 128) {
      throw new LocalContextError("InvalidInput");
    }
    const binary = resolveLocalWorker(options.workerPath);
    this.child = spawn(binary, [...arguments_], {stdio: ["pipe", "pipe", "ignore"], shell: false, windowsHide: true});
    this.exited = new Promise((resolve) => { this.child.once("close", resolve); });
    this.child.on("error", () => this.fail("WorkerUnavailable"));
    this.child.on("exit", () => this.fail("Transport"));
    this.child.stdin.on("error", () => this.fail("Transport"));
    this.child.stdout.on("error", () => this.fail("Transport"));
    this.child.stdout.on("data", (data: Buffer) => this.receive(data));
  }

  private fail(code: string): void {
    this.closed = true;
    const pending = this.pending;
    this.pending = undefined;
    if (pending) { clearTimeout(pending.timer); pending.reject(new LocalContextError(code)); }
    this.fragments = [];
    this.received = 0;
    this.child.kill("SIGKILL");
  }

  private receive(data: Buffer): void {
    if (this.closed) return;
    if (!this.pending) { this.fail("Transport"); return; }
    this.received += data.length;
    if (this.received > MAX_RESPONSE) { this.fail("Transport"); return; }
    this.fragments.push(data);
    const newline = data.indexOf(10);
    if (newline < 0) return;
    if (newline !== data.length - 1) { this.fail("Transport"); return; }
    const pending = this.pending;
    let reply: WorkerReply;
    try {
      const text = new TextDecoder("utf-8", {fatal: true}).decode(Buffer.concat(this.fragments, this.received));
      reply = this.decode(text, pending.id);
    } catch { this.fail("Transport"); return; }
    this.pending = undefined;
    clearTimeout(pending.timer);
    this.fragments = [];
    this.received = 0;
    if (reply.ok) pending.resolve(reply.result);
    else pending.reject(reply.error);
  }

  async call<T>(command: Record<string, unknown>): Promise<T> {
    if (this.closed) throw new LocalContextError("Closed");
    if (this.queued >= this.maxPending) throw new LocalContextError("Busy");
    this.sequence = this.sequence % 4_294_967_295 + 1;
    const id = this.sequence;
    let frame: Buffer;
    try {
      frame = Buffer.from(JSON.stringify({id, command}, (_key, value: unknown) => {
        if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error();
        return value;
      }) + "\n", "utf8");
    } catch { throw new LocalContextError("InvalidInput"); }
    if (frame.length > MAX_FRAME) throw new LocalContextError("LimitExceeded");
    if (this.queuedBytes + frame.length > MAX_FRAME * 2) throw new LocalContextError("Busy");
    this.queued++;
    this.queuedBytes += frame.length;
    const result = this.tail.then(() => new Promise<unknown>((resolve, reject) => {
      if (this.closed) { reject(new LocalContextError("Closed")); return; }
      const timer = setTimeout(() => this.fail("Timeout"), this.timeoutMs);
      this.pending = {id, resolve, reject, timer};
      // One bounded frame in flight. No write until the previous response has completed.
      this.child.stdin.write(frame, (error) => { if (error) this.fail("Transport"); });
    }));
    this.tail = result.catch(() => undefined);
    try { return await result as T; }
    finally { this.queued--; this.queuedBytes -= frame.length; }
  }

  async close(): Promise<void> { this.fail("Closed"); await this.exited; }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
}
