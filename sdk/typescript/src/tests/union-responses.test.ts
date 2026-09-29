import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import type { PayloadModel } from "../index.js";

// Run these same positive assertions against an installed release when comparing
// a regression baseline with the source candidate. No server or provider is used.
const sdk = await import(
  process.env["CIGAR_TEST_SDK_MODULE"] ?? new URL("../index.js", import.meta.url).href
) as typeof import("../index.js");

interface Vector {
  name: string;
  response_type: string;
  payload_cbor: string;
  integers?: Array<{ path: Array<string | number>; decimal: string; typescript_type: "bigint" | "number" }>;
}
const fixture = JSON.parse(readFileSync(
  new URL("../../fixtures/union-responses-v1.json", import.meta.url), "utf8",
)) as { uuid: string; valid: Vector[]; invalid: Vector[] };
const bytes = (vector: Vector): Uint8Array => Uint8Array.from(Buffer.from(vector.payload_cbor, "base64url"));
const model = (vector: Vector): PayloadModel<unknown> =>
  (sdk as unknown as Record<string, PayloadModel<unknown>>)[vector.response_type]!;

function checkValue(vector: Vector, value: unknown): void {
  assert.deepEqual(sdk.encodeOperationPayload(value), bytes(vector), "canonical response bytes must be preserved");
  assert.equal(Object.isFrozen(value), true);
  for (const expected of vector.integers ?? []) {
    let actual = value;
    for (const key of expected.path) actual = (actual as Record<string | number, unknown>)[key];
    assert.equal(typeof actual, expected.typescript_type, expected.path.join("/"));
    assert.equal(String(actual), expected.decimal, expected.path.join("/"));
  }
}

test("shared canonical CBOR response variants decode with exact integer types", async (t) => {
  for (const vector of fixture.valid) {
    await t.test(vector.name, () => {
      const decoded = sdk.decodeOperationPayload(bytes(vector));
      checkValue(vector, model(vector).create(decoded));
      assert.deepEqual(sdk.encodeOperationPayload(decoded), bytes(vector), "coercion must not mutate its input");
    });
  }
});

test("shared malformed CBOR response variants remain rejected", async (t) => {
  for (const vector of fixture.invalid) {
    await t.test(vector.name, () => {
      assert.throws(() => model(vector).create(sdk.decodeOperationPayload(bytes(vector))), sdk.ValidationError);
    });
  }
});

test("publishSpace accepts each valid response and does not retry a completed mutation", async (t) => {
  for (const vector of fixture.valid.filter((item) => item.response_type === "SpacePublishResponse")) {
    await t.test(vector.name, async () => {
      let calls = 0;
      const client = new sdk.CigarClient({
        baseUrl: "http://localhost", allowInsecureLoopback: true, trustCustomFetch: true,
        fetch: async (url, init) => {
          calls += 1;
          assert.equal(String(url), `http://localhost/v1/spaces/${fixture.uuid}:publish`);
          assert.equal(init?.method, "POST");
          assert.equal(new Headers(init?.headers).get("idempotency-key"), "union-response-regression");
          return new Response(JSON.stringify({ operation_id: "publishSpace", payload_cbor: vector.payload_cbor }), {
            status: 200, headers: { "content-type": "application/json", "x-cigar-api-version": "1" },
          });
        },
      });
      const response = await client.publishSpace({
        payload: { space_id: fixture.uuid, overlay_id: fixture.uuid, purpose: "Offline response decoding regression" },
        idempotencyKey: "union-response-regression", expectedRevision: "revision-1",
      });
      assert.equal(calls, 1);
      assert.equal(response.operationId, "publishSpace");
      assert.deepEqual(response.payloadCbor, bytes(vector));
      checkValue(vector, response.payload);
    });
  }
});

test("publishSpace rejects malformed responses without retrying a completed mutation", async (t) => {
  for (const vector of fixture.invalid) {
    await t.test(vector.name, async () => {
      let calls = 0;
      const client = new sdk.CigarClient({
        baseUrl: "http://localhost", allowInsecureLoopback: true, trustCustomFetch: true,
        fetch: async () => {
          calls += 1;
          return new Response(JSON.stringify({ operation_id: "publishSpace", payload_cbor: vector.payload_cbor }), {
            status: 200, headers: { "content-type": "application/json", "x-cigar-api-version": "1" },
          });
        },
      });
      await assert.rejects(client.publishSpace({
        payload: { space_id: fixture.uuid, overlay_id: fixture.uuid, purpose: "Offline response decoding regression" },
        idempotencyKey: "union-response-regression", expectedRevision: "revision-1",
      }), sdk.ValidationError);
      assert.equal(calls, 1);
    });
  }
});

test("union coercion rejects lossy integers and bounds recursive extension values", () => {
  const vector = fixture.valid.find((item) => item.name === "published-one")!;
  for (const sequence of [Number.MAX_SAFE_INTEGER + 1, 1.5, NaN, Infinity]) {
    const value = sdk.decodeOperationPayload(bytes(vector)) as { commit: Record<string, unknown> };
    value.commit["sequence"] = sequence;
    assert.throws(() => model(vector).create(value), sdk.ValidationError);
  }
  const value = sdk.decodeOperationPayload(bytes(vector)) as { commit: Record<string, unknown> };
  let nested: unknown = { type: "integer", value: 1 };
  for (let index = 0; index < 70; index += 1) nested = { type: "array", value: [nested] };
  value.commit["extensions"] = { nested };
  assert.throws(() => model(vector).create(value), sdk.ValidationError);
});
