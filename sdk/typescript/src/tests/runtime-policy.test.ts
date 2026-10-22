import assert from "node:assert/strict";
import test from "node:test";
import { CompatibilityError } from "../errors.js";
import { requirePatchedNodeFetch } from "../runtime-policy.js";
import { CigarClient } from "../client.js";

test("native fetch rejects vulnerable, unsupported and prerelease runtimes", () => {
  for (const version of ["24.10.0", "24.19.0", "24.22.0", "22.23.4", "26.12.1", "24.22.1-rc.1", "invalid"]) {
    assert.throws(() => requirePatchedNodeFetch(version), CompatibilityError, version);
  }
});

test("native fetch accepts the security patch and later supported releases", () => {
  for (const version of ["24.22.1", "24.22.2", "24.23.0"]) {
    assert.doesNotThrow(() => requirePatchedNodeFetch(version), version);
  }
});

test("client enforces the native runtime boundary while preserving trusted custom fetch", () => {
  const original = Object.getOwnPropertyDescriptor(process.versions, "node");
  assert.ok(original);
  Object.defineProperty(process.versions, "node", { ...original, value: "24.22.0" });
  try {
    const options = { baseUrl: "http://127.0.0.1", allowInsecureLoopback: true };
    assert.throws(() => new CigarClient(options), CompatibilityError);
    assert.doesNotThrow(() => new CigarClient({ ...options, fetch: globalThis.fetch, trustCustomFetch: true }));
  } finally {
    Object.defineProperty(process.versions, "node", original);
  }
});
