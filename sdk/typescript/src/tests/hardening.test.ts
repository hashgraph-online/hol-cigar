import assert from "node:assert/strict";
import { test } from "node:test";

import * as sdk from "../index.js";

const local = { allowInsecureLoopback: true, trustCustomFetch: true } as const;
const uuid = "01900000-0000-7000-8000-000000000001";
const digest = `1220${"1".repeat(64)}`;

test("all 70 payload models and their nested schemas are immutable", () => {
  assert.equal(sdk.PAYLOAD_TYPES.length, 70);
  for (const name of sdk.PAYLOAD_TYPES) {
    const model = (sdk as unknown as Record<string, unknown>)[name] as sdk.PayloadModel<unknown>;
    assert.equal(typeof model.create, "function");
    assert.equal(Object.isFrozen(model.schema), true);
  }
  const properties = sdk.ContextBundle.schema["properties"] as Record<string, unknown>;
  assert.equal(Object.isFrozen(properties), true);
  assert.throws(() => {
    properties["bundle_id"] = {};
  }, TypeError);
});

test("pattern properties and nested bigint JSON values validate", () => {
  const bundle = sdk.ContextBundle.create({
    schema_version: "cigar.context-bundle.v1",
    bundle_id: digest,
    contract_digest: digest,
    manifest_digest: digest,
    blocks: [],
    total_tokens: 0,
    extensions: {
      "valid.key": { type: "integer", value: -1n },
    },
  });
  assert.equal((bundle.extensions["valid.key"] as sdk.JsonObject)["value"], -1n);
  assert.throws(() => sdk.ContextBundle.create({ ...bundle, extensions: { "INVALID KEY": { type: "text", value: "x" } } }));
});

test("optional nullable schema artifacts are omission-only", () => {
  const omitted = sdk.AuthorizeEffectRequest.create({ effect_id: uuid });
  assert.equal(omitted.approval, undefined);
  assert.throws(() => sdk.AuthorizeEffectRequest.create({ effect_id: uuid, approval: null } as never), sdk.ValidationError);
});

test("problem details are deeply copied and frozen", () => {
  const details = { nested: [{ value: "before" }] };
  const error = new sdk.CigarApiError(503, {
    schema_version: "cigar.problem.v1",
    code: "INDEX_UNAVAILABLE",
    http_status: 503,
    retry: "after_backoff",
    message: "message",
    remediation: "remediation",
    correlation_id: "01900000-0000-7000-8000-000000000001",
    details,
  });
  details.nested[0]!.value = "after";
  assert.equal(((error.details["nested"] as readonly sdk.JsonObject[])[0] as sdk.JsonObject)["value"], "before");
  assert.equal(Object.isFrozen(error.details["nested"]), true);
  assert.throws(() => {
    ((error.details["nested"] as sdk.JsonObject[])[0] as Record<string, unknown>)["value"] = "tampered";
  }, TypeError);
});

test("deadline, redirect, and response byte bounds fail closed", async () => {
  assert.throws(() => new sdk.CigarClient({
    baseUrl: "http://localhost",
    allowInsecureLoopback: true,
    fetch: async () => new Response(),
  }), sdk.ValidationError);

  let calls = 0;
  const deadlineClient = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    maxAttempts: 8,
    fetch: async (_input, init) => {
      calls += 1;
      assert.equal(init?.redirect, "error");
      return new Response("", {
        status: 503,
        headers: {
          "content-type": "application/problem+json",
          "content-length": "65537",
        },
      });
    },
  });
  const started = Date.now();
  await assert.rejects(
    deadlineClient.getVersion({ payload: {} }, { timeoutMs: 50 }),
    sdk.CigarTimeoutError,
  );
  assert.equal(calls, 1);
  assert.ok(Date.now() - started < 150);

  const oversized = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    maxAttempts: 1,
    fetch: async () => new Response("", {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "999999999" },
    }),
  });
  await assert.rejects(oversized.getVersion({ payload: {} }), sdk.TransportError);

  const duplicate = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    maxAttempts: 1,
    fetch: async () => new Response(
      '{"operation_id":"getVersion","operation_id":"getVersion","payload_cbor":"oA"}',
      { headers: { "content-type": "application/json" } },
    ),
  });
  await assert.rejects(duplicate.getVersion({ payload: {} }), sdk.TransportError);

  const provider = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    bearerToken: async () => await new Promise<string>(() => undefined),
    fetch: async () => { throw new Error("network must not be reached"); },
  });
  const providerStarted = Date.now();
  await assert.rejects(provider.getVersion({ payload: {} }, { timeoutMs: 20 }), sdk.CigarTimeoutError);
  assert.ok(Date.now() - providerStarted < 120);
});

test("SSE reconnects after a body read failure without duplicate delivery", async () => {
  const eventPayload = Buffer.from(sdk.encodeOperationPayload({
    space_id: uuid,
    project_id: uuid,
    event: { event_id: uuid, kind: "context_committed", payload_digest: digest },
  })).toString("base64url");
  const frame = (id: string): string =>
    `id: ${id}\ndata: {"operation_id":"subscribeSpaceEvents","event_id":"${id}","payload_cbor":"${eventPayload}"}\n\n`;
  let calls = 0;
  const resumes: (string | null)[] = [];
  const client = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async (_input, init) => {
      calls += 1;
      resumes.push(new Headers(init?.headers).get("last-event-id"));
      if (calls === 1) {
        let delivered = false;
        return new Response(new ReadableStream<Uint8Array>({
          pull(controller) {
            if (!delivered) {
              delivered = true;
              controller.enqueue(new TextEncoder().encode(frame("event-1")));
            } else {
              controller.error(new Error("connection reset"));
            }
          },
        }), { headers: { "content-type": "text/event-stream" } });
      }
      return new Response(frame("event-1") + frame("event-2"), {
        headers: { "content-type": "text/event-stream" },
      });
    },
  });
  const stream = client.subscribeSpaceEvents(
    { payload: { space_id: uuid } },
    { maxAttempts: 2 },
  );
  const ids: string[] = [];
  for await (const event of stream) ids.push(event.eventId);
  assert.deepEqual(ids, ["event-1", "event-2"]);
  assert.deepEqual(resumes, [null, "event-1"]);
});

test("closing an SSE iterator aborts its active body read", async () => {
  let observedAbort = false;
  const client = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async (_input, init) => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        init?.signal?.addEventListener("abort", () => {
          observedAbort = true;
          controller.error(init.signal?.reason);
        }, { once: true });
      },
    }), { headers: { "content-type": "text/event-stream" } }),
  });
  const stream = client.subscribeSpaceEvents({ payload: { space_id: uuid } }, { timeoutMs: 1_000 });
  const iterator = stream[Symbol.asyncIterator]();
  const pending = iterator.next();
  await new Promise<void>((resolve) => setImmediate(resolve));
  stream.close();
  assert.deepEqual(await pending, { done: true, value: undefined });
  assert.equal(observedAbort, true);
});

test("an external abort cancels a unary call without retry", async () => {
  let calls = 0;
  const client = new sdk.CigarClient({
    baseUrl: "http://localhost",
    ...local,
    maxAttempts: 8,
    fetch: async (_input, init) => await new Promise<Response>((_resolve, reject) => {
      calls += 1;
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    }),
  });
  const controller = new AbortController();
  const pending = client.getVersion({ payload: {} }, { signal: controller.signal });
  await new Promise<void>((resolve) => setImmediate(resolve));
  controller.abort(new DOMException("cancelled", "AbortError"));
  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(calls, 1);
});

test("canonical codecs reject excessive nesting and forged collection lengths", () => {
  let value: unknown = "leaf";
  for (let index = 0; index < 66; index += 1) value = [value];
  assert.throws(() => sdk.encodeOperationPayload(value), sdk.ValidationError);
  assert.throws(
    () => sdk.decodeOperationPayload(Uint8Array.of(0x9a, 0x00, 0x01, 0x86, 0xa1)),
    sdk.ValidationError,
  );
});
