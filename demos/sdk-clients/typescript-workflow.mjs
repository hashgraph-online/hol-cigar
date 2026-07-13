#!/usr/bin/env node
// Exercise the public TypeScript SDK against the shared recorded workflow.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
  CigarClient,
  bundleId,
  deterministicCbor,
  encodeOperationPayload,
  verifyBundle,
} from "../../sdk/typescript/dist/index.js";

const fixtureUrl = new URL("./workflow-fixture-v1.json", import.meta.url);
const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
if (fixture.schema_version !== "cigar.sdk-recorded-workflow.v1") {
  throw new Error("workflow fixture schema is unsupported");
}
const operations = new Map(fixture.operations.map((operation) => [operation.operation_id, operation]));
if (operations.size !== fixture.expected_operations.length) {
  throw new Error("workflow operation inventory is duplicated or incomplete");
}

for (const operation of fixture.operations) {
  const encodedRequest = Buffer.from(encodeOperationPayload(operation.request)).toString("base64url");
  const encodedResponse = Buffer.from(encodeOperationPayload(operation.response)).toString("base64url");
  if (encodedRequest !== operation.request_cbor_base64url || encodedResponse !== operation.response_cbor_base64url) {
    throw new Error("workflow fixture contains non-canonical operation CBOR");
  }
}
const contract = operations.get("createContextPlan").request.contract;
const contractDigest = `1220${createHash("sha256")
  .update(Buffer.from("CIGAR-CONTEXT-CONTRACT\0v1\0"))
  .update(deterministicCbor(contract))
  .digest("hex")}`;
if (contractDigest !== fixture.expected_contract_digest) {
  throw new Error("workflow contract digest differs from its canonical request");
}

let position = 0;
const expectedPaths = new Map([
  ["discoverSources", "/v1/sources:discover"],
  ["ingestCatalog", "/v1/catalog:ingest"],
  ["createContextPlan", "/v1/context/plans"],
  ["compileContextBundle", "/v1/context/bundles:compile"],
]);

const recordedFetch = async (input, init = {}) => {
  const operation = fixture.operations[position];
  if (operation === undefined) throw new Error("SDK issued an unexpected extra operation");
  position += 1;
  const operationId = operation.operation_id;
  const headers = new Headers(init.headers);
  if (headers.get("x-cigar-operation-id") !== operationId) {
    throw new Error("SDK operation header differs from the recorded operation");
  }
  const url = input instanceof URL ? input : new URL(typeof input === "string" ? input : input.url);
  const expectedPath = operationId === "getContextBundleManifest"
    ? `/v1/context/bundles/${operation.path_parameters[0].value}/manifest`
    : expectedPaths.get(operationId);
  const expectedMethod = operationId === "getContextBundleManifest" ? "GET" : "POST";
  if (init.method !== expectedMethod || url.pathname !== expectedPath || url.search !== "") {
    throw new Error("SDK method or bound operation path differs from the fixture");
  }
  if (headers.get("idempotency-key") !== operation.idempotency_key) {
    throw new Error("SDK idempotency key differs from the recorded request");
  }
  if (expectedMethod === "GET") {
    if (init.body !== undefined) throw new Error("SDK emitted a body for a GET operation");
  } else {
    if (typeof init.body !== "string") throw new Error("SDK emitted a non-text request wrapper");
    const wire = JSON.parse(init.body);
    if (
      wire.operation_id !== operationId
      || wire.payload_cbor !== operation.request_cbor_base64url
      || JSON.stringify(wire.path_parameters) !== JSON.stringify(operation.path_parameters)
      || (wire.idempotency_key ?? null) !== operation.idempotency_key
    ) {
      throw new Error("SDK wire request differs from the recorded typed request");
    }
  }
  const response = JSON.stringify({
    operation_id: operationId,
    payload_cbor: operation.response_cbor_base64url,
  });
  return new Response(response, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(response)),
      "x-cigar-api-version": "1",
    },
  });
};

const client = new CigarClient({
  baseUrl: "http://127.0.0.1:1",
  allowInsecureLoopback: true,
  fetch: recordedFetch,
  trustCustomFetch: true,
  maxAttempts: 1,
});

const discovered = await client.discoverSources({ payload: operations.get("discoverSources").request });
const ingested = await client.ingestCatalog({
  payload: operations.get("ingestCatalog").request,
  idempotencyKey: operations.get("ingestCatalog").idempotency_key,
});
const planned = await client.createContextPlan({
  payload: operations.get("createContextPlan").request,
  idempotencyKey: operations.get("createContextPlan").idempotency_key,
});
const compiled = await client.compileContextBundle({
  payload: operations.get("compileContextBundle").request,
  idempotencyKey: operations.get("compileContextBundle").idempotency_key,
});
const manifest = await client.getContextBundleManifest({
  payload: operations.get("getContextBundleManifest").request,
});

if (position !== fixture.operations.length) throw new Error("SDK did not execute every workflow operation");
if (
  discovered.payload.source_id !== operations.get("discoverSources").request.source_id
  || ingested.payload.snapshot_id !== operations.get("ingestCatalog").response.snapshot_id
  || planned.payload.bundle_id !== fixture.expected_bundle_id
) {
  throw new Error("workflow response chain differs from the fixture");
}
verifyBundle(compiled.payload);
if (bundleId(compiled.payload) !== fixture.expected_bundle_id) {
  throw new Error("compiled bundle identity verification failed");
}
const manifestFields = { ...manifest.payload };
delete manifestFields.manifest_id;
const manifestHash = createHash("sha256")
  .update(Buffer.from("CIGAR-MANIFEST\0v1\0"))
  .update(deterministicCbor([3, manifestFields]))
  .digest("hex");
const computedManifestId = `1220${manifestHash}`;
if (computedManifestId !== fixture.expected_manifest_id) {
  throw new Error("selection manifest identity verification failed");
}
if (
  compiled.payload.manifest_digest !== manifest.payload.manifest_id
  || compiled.payload.contract_digest !== manifest.payload.contract_digest
  || compiled.payload.contract_digest !== fixture.expected_contract_digest
) {
  throw new Error("compiled bundle and manifest are not bound to the same contract");
}

console.log(fixture.expected_bundle_id);
