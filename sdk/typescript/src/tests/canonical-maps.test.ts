import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  CigarClient, ContextBundle, CreateContextPlanRequest, EmptyRequest, TransportError, ValidationError,
  decodeOperationPayload, deterministicCbor, encodeOperationPayload,
} from "../index.js";

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/semantic-boundaries-v1.json", import.meta.url), "utf8")) as {
  operation_map: Record<string, unknown>;
};
const digest = `1220${"1".repeat(64)}`;
const uuid = "01900000-0000-7000-8000-000000000001";
const bundle = {
  schema_version: "cigar.context-bundle.v1", bundle_id: digest, contract_digest: digest, manifest_digest: digest,
  blocks: [], total_tokens: 0, extensions: { example: { type: "object", value: fixture.operation_map } },
};
const bundleInput = bundle as unknown as Parameters<typeof ContextBundle.create>[0];

test("operation CBOR preserves every own special key and ordinary object behavior", () => {
  const input = { nested: [fixture.operation_map], ordinary: true, omitted: undefined };
  const expected = { nested: [fixture.operation_map], ordinary: true };
  const encoded = encodeOperationPayload(input);
  assert.deepEqual(encoded, deterministicCbor(expected as never));
  const decoded = decodeOperationPayload(encoded) as typeof expected;
  assert.deepEqual(decoded, expected);
  assert.equal(Object.getPrototypeOf(decoded), Object.prototype);
  assert.equal(Object.getPrototypeOf(decoded.nested[0]), Object.prototype);
  assert.deepEqual(Object.keys(decoded.nested[0] ?? {}).sort(), Object.keys(fixture.operation_map).sort());
  const changed = { nested: [{ ...fixture.operation_map, ["__proto__"]: { type: "text", value: "changed" } }], ordinary: true };
  assert.notDeepEqual(encodeOperationPayload(changed), encoded);
  assert.throws(() => encodeOperationPayload([undefined]), ValidationError);
  assert.throws(() => encodeOperationPayload(JSON.parse('{"é":1,"e\\u0301":2}')), ValidationError);
  assert.throws(() => decodeOperationPayload(Uint8Array.from([0xa2, 0x61, 0x61, 1, 0x61, 0x61, 2])), ValidationError);
});

test("nominal models validate special-name values through the declared schema", () => {
  const model = ContextBundle.create(bundleInput);
  assert.deepEqual(decodeOperationPayload(encodeOperationPayload(model)), bundle);
  for (const key of Object.keys(fixture.operation_map)) {
    const invalid = { ...bundle, extensions: { example: { type: "object", value: { [key]: "not a canonical value" } } } };
    assert.throws(() => ContextBundle.create(invalid as unknown as typeof bundleInput), ValidationError);
    assert.throws(() => EmptyRequest.create({ [key]: true }), ValidationError);
  }
});

test("typed request and response paths preserve special-name extension members", async () => {
  const request = CreateContextPlanRequest.create({ contract: {
    schema_version: "cigar.context-contract.v1", job_goal: "inspect evidence", operation_class: "analysis",
    principal_id: uuid, purpose: "test", project_ids: [uuid],
    target: { provider: "offline", model_family: "fixture", tokenizer_fingerprint: digest, materializer_fingerprint: digest, max_context_tokens: 256 },
    budget: { total_input_tokens: 128, output_reserve_tokens: 64, lane_input_tokens: { evidence: 128 } },
    requirements: [], consistency: "snapshot", extensions: bundleInput.extensions,
  } });
  let transmitted: Uint8Array | undefined;
  const sender = new CigarClient({
    baseUrl: "http://localhost", allowInsecureLoopback: true, trustCustomFetch: true, maxAttempts: 1,
    fetch: async (_url, init) => {
      const envelope = JSON.parse(String(init?.body)) as { payload_cbor: string };
      transmitted = Buffer.from(envelope.payload_cbor, "base64url");
      throw new Error("fixture ends after request capture");
    },
  });
  await assert.rejects(sender.createContextPlan({ payload: request, idempotencyKey: "canonical-map-test" }), TransportError);
  assert.ok(transmitted);
  assert.deepEqual(Buffer.from(transmitted), Buffer.from(deterministicCbor(request as never)));

  const receiver = new CigarClient({
    baseUrl: "http://localhost", allowInsecureLoopback: true, trustCustomFetch: true,
    fetch: async () => new Response(JSON.stringify({
      operation_id: "getContextBundle", payload_cbor: Buffer.from(deterministicCbor(bundle as never)).toString("base64url"),
    }), { status: 200, headers: { "content-type": "application/json", "x-cigar-api-version": "1" } }),
  });
  const result = await receiver.getContextBundle({ payload: { bundle_id: digest } });
  assert.deepEqual(decodeOperationPayload(encodeOperationPayload(result.payload)), bundle);
});
