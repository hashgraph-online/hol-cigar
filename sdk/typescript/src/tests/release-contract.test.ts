import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { file_context_abi } from "../generated/context_abi_pb.js";
import { CONTEXT_ABI } from "../index.js";

type ReleaseMetadata = Readonly<{
  schema_version: string;
  name: string;
  version: string;
  context_abi: string;
}>;

test("release metadata and generated descriptor bind the exported Context ABI", () => {
  const release = JSON.parse(
    readFileSync(new URL("../release.json", import.meta.url), "utf8"),
  ) as ReleaseMetadata;
  assert.equal(release.schema_version, "cigar.sdk-release.v1");
  assert.equal(release.name, "@cigar/sdk");
  assert.equal(release.version, "0.1.0");
  assert.equal(release.context_abi, CONTEXT_ABI);
  assert.equal(file_context_abi.proto.package, CONTEXT_ABI);
});
