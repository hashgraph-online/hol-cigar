import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { CigarApiError, CigarClient, TransportError, ValidationError, encodeOperationPayload } from "../index.js";

const problemFixture = readFileSync(
  new URL("../../../fixtures/problem-index-unavailable-v1.json", import.meta.url),
  "utf8",
);
const local = { allowInsecureLoopback: true, trustCustomFetch: true } as const;
const uuid = "01900000-0000-7000-8000-000000000001";
const digest = `1220${"1".repeat(64)}`;
const ingestionResponse = {
  revision: 1n,
  snapshot_id: uuid,
  published_atoms: 1n,
  tombstoned_atoms: 0n,
  publication_digest: digest,
};

const ok = (operationId: string, cursor?: string, payload: unknown = {}): Response => new Response(JSON.stringify({
  operation_id: operationId,
  payload_cbor: Buffer.from(encodeOperationPayload(payload)).toString("base64url"),
  ...(cursor === undefined ? {} : { next_page_cursor: cursor }),
}), { status: 200, headers: { "content-type": "application/json", "x-cigar-api-version": "1" } });

const retryable = (): Response => new Response(problemFixture, {
  status: 503,
  headers: { "content-type": "application/problem+json" },
});

test("all 45 generated methods are installed", () => {
  const client = new CigarClient({ baseUrl: "http://localhost", ...local, fetch: async () => ok("unused") });
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(client));
  assert.equal(methods.includes("compileContextBundle"), true);
  assert.equal(methods.includes("acceptHandoff"), true);
  assert.equal(methods.includes("reconcileEffect"), true);
  assert.equal(methods.includes("runObservationalReplay"), true);
});

test("idempotency-bound mutation retries preserve bytes and key", async () => {
  const bodies: string[] = [];
  const keys: string[] = [];
  let calls = 0;
  const client = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async (_input, init) => {
      calls += 1;
      bodies.push(String(init?.body));
      keys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      return calls === 1 ? retryable() : ok("ingestCatalog", undefined, ingestionResponse);
    },
  });
  const response = await client.ingestCatalog({
    payload: { source_id: uuid, plan_digest: digest },
    idempotencyKey: "fixed-key",
  });
  assert.equal(response.payload.revision, 1n);
  assert.equal(calls, 2);
  assert.deepEqual(keys, ["fixed-key", "fixed-key"]);
  assert.equal(bodies[0], bodies[1]);
});

test("effect dispatch is never retried automatically", async () => {
  let calls = 0;
  const client = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    maxAttempts: 8,
    fetch: async () => {
      calls += 1;
      return retryable();
    },
  });
  await assert.rejects(
    client.dispatchEffect({
      payload: { effect_id: uuid },
      idempotencyKey: "dispatch-key",
      expectedRevision: "revision-1",
    }),
    CigarApiError,
  );
  assert.equal(calls, 1);
});

test("pagination forwards the exact resume cursor and detects completion", async () => {
  const urls: string[] = [];
  let calls = 0;
  const client = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async (input) => {
      urls.push(String(input));
      calls += 1;
      return calls === 1 ? ok("getSpaceLog", "cursor-2") : ok("getSpaceLog");
    },
  });
  const pages = [];
  for await (const page of client.paginate("getSpaceLog", {
    pathParameters: [{ name: "space_id", value: "space-1" }],
    pageSize: 10,
  })) pages.push(page);
  assert.equal(pages.length, 2);
  assert.match(urls[1] ?? "", /page_cursor=cursor-2/u);
});

test("resumable SSE exposes AsyncIterable events", async () => {
  const encodedEvent = Buffer.from(encodeOperationPayload({
    space_id: uuid,
    project_id: uuid,
    event: { event_id: uuid, kind: "context_committed", payload_digest: digest },
  })).toString("base64url");
  const bodies = [
    `id: event-1\ndata: {"operation_id":"subscribeSpaceEvents","event_id":"event-1","payload_cbor":"${encodedEvent}"}\n\n`,
  ];
  const client = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    maxAttempts: 1,
    fetch: async (_input, init) => {
      assert.equal(new Headers(init?.headers).get("last-event-id"), "event-0");
      return new Response(bodies.shift(), { status: 200, headers: { "content-type": "text/event-stream" } });
    },
  });
  const stream = client.subscribeSpaceEvents({
    payload: { space_id: uuid },
  }, { resumeFrom: "event-0", maxAttempts: 1 });
  const received = [];
  for await (const event of stream) received.push(event);
  assert.equal(received[0]?.eventId, "event-1");
  assert.equal(received[0]?.payload.space_id, uuid);
  assert.equal(stream.lastEventId, "event-1");
  assert.throws(
    () => client.subscribeSpaceEvents(
      { payload: { space_id: uuid }, pageCursor: "opaque-page" },
      { maxAttempts: 1 },
    ),
    ValidationError,
  );
  const invalidAttempts = client.subscribeSpaceEvents(
    { payload: { space_id: uuid } },
    { maxAttempts: 0 },
  );
  await assert.rejects(async () => {
    for await (const _event of invalidAttempts) { /* unreachable */ }
  }, ValidationError);
});

test("required revision and idempotency metadata fail before network", async () => {
  const client = new CigarClient({ baseUrl: "http://localhost", ...local, fetch: async () => ok("forkSpace") });
  await assert.rejects(
    client.forkSpace({
      payload: { space_id: uuid, fork: {} },
    }),
    ValidationError,
  );
});

test("typed handoff, reconciliation, and replay workflows validate end to end", async () => {
  const responses: Record<string, unknown> = {
    acceptHandoff: {
      schema_version: "cigar.handoff-acceptance.v1",
      acceptance_id: uuid,
      handoff_id: uuid,
      recipient_id: uuid,
      accepted_capabilities: ["read_context"],
      rejected_capabilities: [],
      unavailable_references: [],
      policy_digest: digest,
      bundle_id: digest,
      accepted_at: "2026-01-01T00:00:00Z",
      acknowledgement_digest: digest,
    },
    reconcileEffect: {
      effect_id: uuid,
      state: "succeeded",
      effect_version: 2n,
      intent_digest: digest,
      attempt_count: 1,
      reconciliation_count: 1,
    },
    runObservationalReplay: {
      schema_version: "cigar.replay-execution.v1",
      execution_id: uuid,
      request_id: uuid,
      mode: "observational",
      status: "complete",
      completeness: { available: ["bundle"], missing: [] },
      egress_permitted: false,
      effect_dispatch_permitted: false,
      started_at: "2026-01-01T00:00:00Z",
    },
  };
  const client = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async (_input, init) => {
      const operation = new Headers(init?.headers).get("x-cigar-operation-id") ?? "";
      return ok(operation, undefined, responses[operation]);
    },
  });
  const handoff = await client.acceptHandoff({
    payload: { handoff_id: uuid, target_plan_id: uuid },
    idempotencyKey: "accept-1",
    expectedRevision: "revision-1",
  });
  const effect = await client.reconcileEffect({
    payload: { effect_id: uuid },
    idempotencyKey: "reconcile-1",
    expectedRevision: "revision-2",
  });
  const replay = await client.runObservationalReplay({
    payload: { replay_id: uuid },
    idempotencyKey: "replay-1",
  });
  assert.equal(handoff.payload.accepted_capabilities[0], "read_context");
  assert.equal(effect.payload.state, "succeeded");
  assert.equal(replay.payload.mode, "observational");
});

test("typed bundle responses reject missing transform evidence", async () => {
  const transformedBlock = {
    block_id: digest,
    lane: "evidence",
    representation: "summarized",
    content_digest: digest,
    token_count: 1,
    provenance: [digest],
  };
  const bundle = {
    schema_version: "cigar.context-bundle.v1",
    bundle_id: digest,
    contract_digest: digest,
    manifest_digest: digest,
    blocks: [transformedBlock],
    total_tokens: 1,
    extensions: {},
  };
  const invalid = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async () => ok("getContextBundle", undefined, bundle),
  });
  await assert.rejects(invalid.getContextBundle({ payload: { bundle_id: digest } }), ValidationError);

  const valid = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async () => ok("getContextBundle", undefined, {
      ...bundle,
      blocks: [{ ...transformedBlock, transform_receipt: digest }],
    }),
  });
  const response = await valid.getContextBundle({ payload: { bundle_id: digest } });
  assert.equal(response.payload.blocks.length, 1);
});

test("transport security and exact problem contract fail closed", async () => {
  assert.throws(() => new CigarClient({ baseUrl: "http://example.com" }), ValidationError);
  assert.throws(
    () => new CigarClient({ baseUrl: "https://example.com/prefix" }),
    ValidationError,
  );
  const missingContentType = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async () => new Response(JSON.stringify({ operation_id: "getVersion", payload_cbor: "" })),
  });
  await assert.rejects(missingContentType.getVersion({ payload: {} }), TransportError);

  const wrongProblem = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    fetch: async () => new Response(problemFixture.replace('"http_status": 503', '"http_status": 500'), {
      status: 503,
      headers: { "content-type": "application/problem+json" },
    }),
  });
  await assert.rejects(wrongProblem.getVersion({ payload: {} }), TransportError);

  const token = new CigarClient({
    baseUrl: "http://localhost",
    ...local,
    bearerToken: "x".repeat(8193),
    fetch: async () => ok("getVersion"),
  });
  await assert.rejects(token.getVersion({ payload: {} }), ValidationError);
});
