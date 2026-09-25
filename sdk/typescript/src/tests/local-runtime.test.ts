import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { getLocalContextCapabilities } from "../context-api.js";
import { NATIVE_PLATFORMS } from "../native-platforms.js";
import { runLocalWorkflow } from "../examples/local-workflow.js";

async function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "cigar-local-runtime-")));
  mkdirSync(join(root, "dist"));
  writeFileSync(join(root, "package.json"), '{"type":"module"}');
  for (const name of ["local-runtime.js", "native-platforms.js"]) {
    copyFileSync(new URL(`../${name}`, import.meta.url), join(root, "dist", name));
  }
  const runtime = await import(pathToFileURL(join(root, "dist/local-runtime.js")).href) as typeof import("../local-runtime.js");
  return {root, runtime, close: () => rmSync(root, {recursive: true, force: true})};
}

test("every advertised platform selects its own worker and rejects a wrong target or altered bytes", async () => {
  const sample = await fixture();
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const archDescriptor = Object.getOwnPropertyDescriptor(process, "arch")!;
  const getReport = process.report.getReport;
  try {
    for (const [id, metadata] of Object.entries(NATIVE_PLATFORMS)) {
      const [platform, arch, libc] = id.split("-");
      Object.defineProperty(process, "platform", {...platformDescriptor, value: platform});
      Object.defineProperty(process, "arch", {...archDescriptor, value: arch});
      process.report.getReport = (() => ({header: libc === "gnu" ? {glibcVersionRuntime: "2.28"} : {}})) as typeof getReport;
      assert.equal(sample.runtime.localPlatform(), id);
      const directory = join(sample.root, "native", id);
      mkdirSync(directory, {recursive: true});
      const bytes = Buffer.from(`fixture bytes for ${id}`);
      const manifest = {protocol: "cigar.context-worker.v1", core_version: "0.12.0",
        target: metadata.target, sha256: createHash("sha256").update(bytes).digest("hex")};
      writeFileSync(join(directory, metadata.executable), bytes);
      writeFileSync(join(directory, "manifest.json"), JSON.stringify(manifest));
      assert.equal(sample.runtime.getLocalContextCapabilities().worker_available, true);
      assert.equal(sample.runtime.resolveLocalWorker(), join(directory, metadata.executable));
      writeFileSync(join(directory, "manifest.json"), JSON.stringify({...manifest, target: "wrong-target"}));
      assert.equal(sample.runtime.getLocalContextCapabilities().error_code, "WorkerIntegrity");
      writeFileSync(join(directory, "manifest.json"), JSON.stringify(manifest));
      writeFileSync(join(directory, metadata.executable), "altered");
      assert.equal(sample.runtime.getLocalContextCapabilities().error_code, "WorkerIntegrity");
    }
  } finally {
    Object.defineProperty(process, "platform", platformDescriptor);
    Object.defineProperty(process, "arch", archDescriptor);
    process.report.getReport = getReport;
    sample.close();
  }
});

test("missing and unsupported workers produce guidance without caller paths or credentials", async () => {
  const sample = await fixture();
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  try {
    const missing = sample.runtime.getLocalContextCapabilities();
    assert.equal(missing.worker_available, false);
    assert.equal(missing.error_code, "WorkerUnavailable");
    assert.match(missing.guidance, /HOL services and API keys are not required/);
    const privatePath = join(sample.root, "PRIVATE_USER_PATH");
    const explicit = sample.runtime.getLocalContextCapabilities({workerPath: privatePath});
    assert.equal(explicit.worker_source, "explicit");
    assert.equal(JSON.stringify(explicit).includes(privatePath), false);
    Object.defineProperty(process, "platform", {...descriptor, value: "freebsd"});
    assert.equal(sample.runtime.getLocalContextCapabilities().error_code, "UnsupportedPlatform");
    assert.equal(sample.runtime.getLocalContextCapabilities().requires_hol_services, false);
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    sample.close();
  }
});

test("doctor distinguishes capability inspection from a verified compile and reports missing workers", () => {
  const cli = fileURLToPath(new URL("../local-cli.js", import.meta.url));
  const missing = spawnSync(process.execPath, [cli, "doctor", "--json", "--worker", "relative-private-path"],
    {encoding: "utf8", timeout: 15_000});
  assert.equal(missing.status, 1, missing.stderr);
  const failure = JSON.parse(missing.stdout);
  assert.equal(failure.error_code, "WorkerUnavailable");
  assert.equal(failure.compile_verified, false);
  assert.equal(missing.stdout.includes("relative-private-path"), false);
  const workerPath = process.env.CIGAR_TEST_WORKER;
  const result = spawnSync(process.execPath, [cli, "doctor", "--json",
    ...(workerPath ? ["--worker", workerPath] : [])], {encoding: "utf8", timeout: 15_000});
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "ready");
  assert.equal(report.compile_verified, true);
  assert.equal(report.capabilities.requires_hol_services, false);
  assert.ok(report.rendered_tokens <= 256);
});

test("the packaged workflow exercises reviewed release, abstention and source refresh", async () => {
  const workerPath = process.env.CIGAR_TEST_WORKER;
  assert.equal(getLocalContextCapabilities(workerPath ? {workerPath} : {}).worker_available, true);
  const report = await runLocalWorkflow(workerPath ? {workerPath} : {});
  assert.equal(report.status, "passed");
  assert.equal(report.reviewer, "scripted-fixture");
  assert.ok(report.checks.includes("confident-error-abstention"));
  assert.ok(report.checks.includes("stale-review-rejection"));
  assert.notDeepEqual(report.released_claims, report.refreshed_claims);
  const cli = fileURLToPath(new URL("../local-cli.js", import.meta.url));
  const result = spawnSync(process.execPath, [cli, "demo", "--json",
    ...(workerPath ? ["--worker", workerPath] : [])], {encoding: "utf8", timeout: 15_000});
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), report);
});

test("package declares a standalone CLI and an importable complete example", () => {
  const metadata = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(metadata.bin["cigar-context"], "./dist/local-cli.js");
  assert.equal(metadata.exports["./examples/local-workflow"].import, "./dist/examples/local-workflow.js");
  assert.equal(metadata.scripts.postinstall, undefined);
});
