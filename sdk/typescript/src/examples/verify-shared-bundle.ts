import { readFile } from "node:fs/promises";

import { bundleId, verifyBundle, type SemanticContextBundle } from "../index.js";

interface Fixture {
  readonly schema_version: string;
  readonly bundle: SemanticContextBundle;
  readonly expected_bundle_id: string;
}

const defaultFixture = new URL("../../fixtures/semantic-bundle-v1.json", import.meta.url);
const source = await readFile(process.argv[2] ?? defaultFixture, "utf8");
const fixture = JSON.parse(source) as Fixture;
if (fixture.schema_version !== "cigar.sdk-semantic-bundle-fixture.v1") throw new Error("unsupported fixture");
verifyBundle(fixture.bundle);
const computed = bundleId(fixture.bundle);
if (computed !== fixture.expected_bundle_id) throw new Error("shared semantic bundle identity differs");
console.log(computed);
