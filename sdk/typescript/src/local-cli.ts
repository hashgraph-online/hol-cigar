#!/usr/bin/env node
import assert from "node:assert/strict";
import { LocalContextGraph, LocalContextError, getLocalContextCapabilities } from "./context-api.js";
import { runLocalWorkflow } from "./examples/local-workflow.js";

const args = process.argv.slice(2);
const usage = "Usage: cigar-context <doctor|demo> [--json] [--worker /absolute/trusted/worker]\n" +
  "Runs locally. No HOL service, account, API key or model provider is required.";
const command = args.shift();
let json = false;
let workerPath: string | undefined;
let invalid = false;
while (args.length) {
  const argument = args.shift();
  if (argument === "--json" && !json) json = true;
  else if (argument === "--worker" && workerPath === undefined && args.length) workerPath = args.shift();
  else invalid = true;
}
if (command === "--help" || command === "-h" || !command) {
  console.log(usage);
} else if (invalid || !["doctor", "demo"].includes(command)) {
  console.error(usage);
  process.exitCode = 2;
} else {
  const options = {...(workerPath === undefined ? {} : {workerPath}), timeoutMs: 5_000};
  const capabilities = getLocalContextCapabilities(options);
  try {
    if (command === "demo") {
      const report = await runLocalWorkflow(options);
      console.log(JSON.stringify(report, null, json ? undefined : 2));
    } else {
      const graph = await LocalContextGraph.create("cigar-doctor", options);
      let tokens: number;
      try {
        await graph.upsert({id: "doctor", source: "cigar:doctor", text: "Local context compilation works."});
        const compiled = await graph.compile({required: ["doctor"], allowed: ["doctor"], max_tokens: 256});
        assert.deepEqual(await graph.verify(compiled.snapshot), compiled);
        assert.ok(compiled.snapshot.stats.rendered_tokens <= 256);
        tokens = compiled.snapshot.stats.rendered_tokens;
      } finally { await graph.close(); }
      const report = {schema: "cigar.local-diagnostics.v1", status: "ready", capabilities,
        compile_verified: true, rendered_tokens: tokens};
      console.log(json ? JSON.stringify(report) :
        `CIGAR ${capabilities.package_version}: ready on ${capabilities.platform} (${capabilities.runtime}).\n` +
        `Local compilation and snapshot verification passed (${tokens} tokens).\n` +
        "No HOL service, account or API key is required.");
    }
  } catch (error) {
    const code = error instanceof LocalContextError ? error.code : "Internal";
    const guidance = error instanceof LocalContextError ? error.message : "The local diagnostic failed unexpectedly.";
    const report = {schema: "cigar.local-diagnostics.v1", status: "error", capabilities,
      compile_verified: false, error_code: code, guidance};
    console.log(json ? JSON.stringify(report) :
      `CIGAR ${capabilities.package_version}: ${code} on ${capabilities.platform}.\n${guidance}`);
    process.exitCode = 1;
  }
}
