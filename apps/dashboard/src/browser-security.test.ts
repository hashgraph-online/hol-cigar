import assert from "node:assert/strict";
import test from "node:test";

import {
  isSidecarApiPath,
  openSidecarEventStream,
  sidecarFetch,
} from "../public/browser-security.20260714.js";

const cancelPath = "/api/v1/runs/01890f47-3c91-7b5a-8b55-55f4fe74527a:cancel";

test("the browser network boundary accepts only closed same-origin sidecar paths", () => {
  for (const path of [
    "/api/v1/bootstrap",
    "/api/v1/evidence",
    "/api/v1/events",
    "/api/v1/protocol",
    "/api/v1/run-profiles",
    "/api/v1/runs",
    "/api/v1/session:csrf",
    "/api/v1/session:exchange",
    "/api/v1/status",
    cancelPath,
  ]) assert.equal(isSidecarApiPath(path), true, path);

  for (const path of [
    "",
    "/",
    " /api/v1/status",
    "/api/v1/status?target=http://host",
    "/api/v1/status#fragment",
    "/api/v1/status/",
    "/api/v1/%2e%2e/status",
    "//attacker.invalid/api/v1/status",
    "https://attacker.invalid/api/v1/status",
    "\\\\attacker.invalid\\api\\v1\\status",
    "/api/v1/runs/01890f47-3c91-6b5a-8b55-55f4fe74527a:cancel",
    "/api/v1/runs/01890f47-3c91-7b5a-7b55-55f4fe74527a:cancel",
  ]) assert.equal(isSidecarApiPath(path), false, path);
  assert.equal(isSidecarApiPath(null), false);
});

test("sidecarFetch rejects an unreviewed path before invoking the transport", { concurrency: false }, () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => { calls += 1; }) as typeof globalThis.fetch;
  try {
    assert.throws(() => sidecarFetch("https://attacker.invalid/"), /reviewed same-origin/);
    assert.throws(() => sidecarFetch("/api/v1/status", null), /options must be an object/);
    assert.throws(() => sidecarFetch("/api/v1/status", []), /options must be an object/);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = original;
  }
});

test("sidecarFetch overrides redirect, credential, and referrer weakening", { concurrency: false }, async () => {
  const original = globalThis.fetch;
  let capturedPath = null;
  let capturedOptions = null;
  const sentinel = Object.freeze({ ok: true });
  globalThis.fetch = (async (path, options) => {
    capturedPath = path;
    capturedOptions = options;
    return sentinel;
  }) as typeof globalThis.fetch;
  try {
    const result = await sidecarFetch(cancelPath, {
      body: "{}",
      credentials: "include",
      method: "POST",
      redirect: "follow",
      referrerPolicy: "unsafe-url",
    });
    assert.equal(result, sentinel);
    assert.equal(capturedPath, cancelPath);
    assert.deepEqual(capturedOptions, {
      body: "{}",
      credentials: "same-origin",
      method: "POST",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    assert.equal(Object.isFrozen(capturedOptions), true);
  } finally {
    globalThis.fetch = original;
  }
});

test("the event stream constructor receives only the fixed same-origin route", { concurrency: false }, () => {
  const original = globalThis.EventSource;
  const calls = [];
  class EventSourceProbe {
    constructor(path, options) {
      calls.push({ options, path });
    }
  }
  globalThis.EventSource = EventSourceProbe as typeof globalThis.EventSource;
  try {
    assert.ok(openSidecarEventStream() instanceof EventSourceProbe);
    assert.deepEqual(calls, [{ options: { withCredentials: true }, path: "/api/v1/events" }]);
  } finally {
    globalThis.EventSource = original;
  }
});

test("the event stream remains unavailable when the browser primitive is absent", { concurrency: false }, () => {
  const original = globalThis.EventSource;
  globalThis.EventSource = undefined as typeof globalThis.EventSource;
  try {
    assert.equal(openSidecarEventStream(), null);
  } finally {
    globalThis.EventSource = original;
  }
});
