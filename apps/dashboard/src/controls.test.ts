import test from "node:test";
import assert from "node:assert/strict";

import {
  cancellableRunId,
  cancellationPath,
  profileControlPresentation,
} from "../public/controls.20260714.js";

const runId = "01981f9e-8377-7a22-8f01-0123456789ab";

test("only the exact available state plus explicit control enables launch", () => {
  assert.deepEqual(profileControlPresentation("available", true), {
    enabled: true,
    label: "Launch reviewed profile",
    state: "available",
  });
  assert.equal(profileControlPresentation("available", false).enabled, false);
  assert.equal(profileControlPresentation("tool_missing", true).enabled, false);
  assert.equal(profileControlPresentation("unknown", true).enabled, false);
});

test("cancellation accepts only canonical UUIDv7 active runs", () => {
  assert.equal(cancellableRunId({ run_id: runId, state: "running" }), runId);
  assert.equal(cancellableRunId({ run_id: runId, state: "cancelling" }), null);
  assert.equal(cancellableRunId({ run_id: "../../escape", state: "running" }), null);
  assert.equal(cancellationPath(runId), `/api/v1/runs/${runId}:cancel`);
  assert.equal(cancellationPath("id;touch /tmp/no"), null);
});
