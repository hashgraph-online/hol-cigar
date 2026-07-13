import test from "node:test";
import assert from "node:assert/strict";

import {
  enabledTransports,
  formatByteLimit,
  freshnessPresentation,
  isAggregateStatus,
  isComponentStatus,
} from "../public/health-details.20260713.js";

test("freshness thresholds are exact and do not invent aggregate health", () => {
  assert.deepEqual(freshnessPresentation(0), { className: "fresh", label: "Fresh" });
  assert.deepEqual(freshnessPresentation(9_999), { className: "fresh", label: "Fresh" });
  assert.deepEqual(freshnessPresentation(10_000), { className: "stale", label: "Stale" });
  assert.deepEqual(freshnessPresentation(30_000), { className: "stale", label: "Stale" });
  assert.deepEqual(freshnessPresentation(30_001), {
    className: "expired",
    label: "Expired observation",
  });
});

test("invalid freshness values fail to an explicit unknown state", () => {
  assert.deepEqual(freshnessPresentation(-1), {
    className: "unknown",
    label: "Unknown freshness",
  });
  assert.equal(freshnessPresentation(1.5).className, "unknown");
  assert.equal(freshnessPresentation(Number.MAX_VALUE).className, "unknown");
});

test("aggregate and component states are closed allowlists", () => {
  assert.equal(isAggregateStatus("healthy"), true);
  assert.equal(isAggregateStatus("stale"), true);
  assert.equal(isAggregateStatus("passing"), false);
  assert.equal(isComponentStatus("degraded"), true);
  assert.equal(isComponentStatus("stale"), false);
});

test("configuration summaries expose only closed transport and bounded byte facts", () => {
  assert.deepEqual(
    enabledTransports({ local_ipc: true, http_enabled: false, grpc_enabled: true }),
    ["Local IPC", "gRPC"],
  );
  assert.deepEqual(enabledTransports(null), []);
  assert.equal(formatByteLimit(1024), "1 KiB");
  assert.equal(formatByteLimit(2 * 1024 * 1024), "2 MiB");
  assert.equal(formatByteLimit(17), "17 bytes");
  assert.equal(formatByteLimit(-1), "Unavailable");
});
