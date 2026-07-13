import assert from "node:assert/strict";
import test from "node:test";

import { classifyAggregateStatus, classifyFreshness, type StatusEvidence } from "./status.ts";

const healthy: StatusEvidence = {
  hasValidObservation: true,
  compatibility: "compatible",
  reachable: true,
  live: true,
  gateOpen: true,
  readiness: "healthy",
  freshnessMs: 100,
  consecutiveFailures: 0,
};

test("healthy requires compatible fresh liveness and readiness", () => {
  assert.equal(classifyAggregateStatus(healthy), "healthy");
  assert.equal(classifyFreshness(healthy), "fresh");
});

test("incompatibility has precedence over reachability", () => {
  assert.equal(
    classifyAggregateStatus({
      ...healthy,
      compatibility: "incompatible",
      reachable: false,
      consecutiveFailures: 3,
    }),
    "incompatible",
  );
});

test("three failures or thirty seconds makes the status unreachable", () => {
  assert.equal(classifyAggregateStatus({ ...healthy, consecutiveFailures: 3 }), "unreachable");
  assert.equal(classifyAggregateStatus({ ...healthy, freshnessMs: 30_000 }), "unreachable");
});

test("a valid closed readiness gate is unhealthy rather than unreachable", () => {
  assert.equal(classifyAggregateStatus({ ...healthy, gateOpen: false }), "unhealthy");
});

test("a stale otherwise healthy observation is degraded", () => {
  const evidence = { ...healthy, freshnessMs: 10_000 };
  assert.equal(classifyFreshness(evidence), "stale");
  assert.equal(classifyAggregateStatus(evidence), "degraded");
});

test("missing observations and compatibility negotiation remain starting", () => {
  assert.equal(
    classifyAggregateStatus({
      ...healthy,
      hasValidObservation: false,
      compatibility: "unknown",
    }),
    "starting",
  );
});
