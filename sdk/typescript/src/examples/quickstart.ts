import { readFile } from "node:fs/promises";

import {
  CigarClient,
  bundleId,
  createIdempotencyKey,
  verifyBundle,
  type SemanticContextBundle,
} from "../index.js";

interface Fixture {
  readonly schema_version: string;
  readonly bundle: SemanticContextBundle;
  readonly expected_bundle_id: string;
}

const fixtureUrl = new URL("../../fixtures/semantic-bundle-v1.json", import.meta.url);
const fixture = JSON.parse(await readFile(fixtureUrl, "utf8")) as Fixture;
if (fixture.schema_version !== "cigar.sdk-semantic-bundle-fixture.v1") throw new Error("unsupported fixture");
verifyBundle(fixture.bundle);
const identity = bundleId(fixture.bundle);
if (identity !== fixture.expected_bundle_id) throw new Error("shared semantic bundle identity differs");

const baseUrl = process.env.CIGAR_URL;
if (baseUrl !== undefined) {
  const planId = process.env.CIGAR_PLAN_ID;
  if (planId === undefined) throw new Error("CIGAR_PLAN_ID is required with CIGAR_URL");
  const client = new CigarClient({
    baseUrl,
    allowInsecureLoopback: baseUrl.startsWith("http://"),
    ...(process.env.CIGAR_TOKEN === undefined ? {} : { bearerToken: process.env.CIGAR_TOKEN }),
  });
  await client.negotiate({ timeoutMs: 5_000 });
  const compiled = await client.compileContextBundle({
    payload: { plan_id: planId },
    idempotencyKey: createIdempotencyKey("quickstart"),
  });
  if (compiled.payload.bundle_id !== identity) throw new Error("daemon bundle identity differs from the shared fixture");
  const manifest = await client.getContextBundleManifest({ payload: { bundle_id: compiled.payload.bundle_id } });
  console.error(`verified daemon manifest ${manifest.payload.manifest_id}`);
}

console.log(identity);
