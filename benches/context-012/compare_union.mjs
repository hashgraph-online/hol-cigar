// Compare the unchanged response corpus against an actual installed npm package.
// Custom fetch supplies local fixtures; this performs no network or server action.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const [modulePath, outputPath] = process.argv.slice(2);
assert.ok(modulePath && outputPath, "usage: node compare_union.mjs INSTALLED_MODULE OUTPUT");
const sdk = await import(pathToFileURL(modulePath).href);
const fixtureBytes = readFileSync(new URL("../../sdk/fixtures/union-responses-v1.json", import.meta.url));
const fixture = JSON.parse(fixtureBytes);
const outcomes = [];
for (const [family, vectors] of [["valid", fixture.valid], ["invalid", fixture.invalid]]) {
  for (const vector of vectors) {
    const bytes = Uint8Array.from(Buffer.from(vector.payload_cbor, "base64url"));
    let decoded = false;
    let error = null;
    try {
      const raw = sdk.decodeOperationPayload(bytes);
      const value = sdk[vector.response_type].create(raw);
      assert.deepEqual(sdk.encodeOperationPayload(value), bytes);
      assert.deepEqual(sdk.encodeOperationPayload(raw), bytes);
      assert.equal(Object.isFrozen(value), true);
      for (const item of vector.integers ?? []) {
        let integer = value;
        for (const key of item.path) integer = integer[key];
        assert.equal(typeof integer, item.typescript_type);
        assert.equal(String(integer), item.decimal);
      }
      decoded = true;
    } catch (failure) {
      if (!(failure instanceof sdk.ValidationError)) throw failure;
      error = failure.message;
    }
    const row = { family, name: vector.name, response_type: vector.response_type, decoded, error };
    if (vector.response_type === "SpacePublishResponse") {
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
      try {
        const response = await client.publishSpace({
          payload: { space_id: fixture.uuid, overlay_id: fixture.uuid, purpose: "Offline regression comparison" },
          idempotencyKey: "union-response-comparison", expectedRevision: "revision-1",
        });
        assert.deepEqual(response.payloadCbor, bytes);
        row.publish_decoded = true;
      } catch (failure) {
        if (!(failure instanceof sdk.ValidationError)) throw failure;
        row.publish_decoded = false;
      }
      assert.equal(calls, 1, "completed mutations must never be retried on decode failure");
      row.fetch_calls = calls;
    }
    outcomes.push(row);
  }
}
const packageJson = JSON.parse(readFileSync(new URL("../package.json", pathToFileURL(modulePath))));
const result = {
  schema: "cigar.installed-union-comparison.v1", version: packageJson.version,
  installed_module: modulePath, fixture_sha256: createHash("sha256").update(fixtureBytes).digest("hex"),
  harness_sha256: createHash("sha256").update(readFileSync(fileURLToPath(import.meta.url))).digest("hex"),
  provider_calls: 0, server_calls: 0,
  valid_decoded: outcomes.filter(row => row.family === "valid" && row.decoded).length,
  valid_total: fixture.valid.length,
  malformed_rejected: outcomes.filter(row => row.family === "invalid" && !row.decoded).length,
  malformed_total: fixture.invalid.length,
  publish_decoded: outcomes.filter(row => row.family === "valid" && row.publish_decoded).length,
  publish_total: outcomes.filter(row => row.family === "valid" && row.response_type === "SpacePublishResponse").length,
  outcomes,
};
writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify({ version: result.version, valid: `${result.valid_decoded}/${result.valid_total}`,
  publish: `${result.publish_decoded}/${result.publish_total}`, rejected: `${result.malformed_rejected}/${result.malformed_total}` }));
