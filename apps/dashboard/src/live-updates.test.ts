import test from "node:test";
import assert from "node:assert/strict";

import {
  liveUpdatePresentation,
  shouldRefreshAutomatically,
} from "../public/live-updates.20260713.js";

test("automatic refresh requires an unpaused visible document", () => {
  assert.equal(shouldRefreshAutomatically(false, "visible"), true);
  assert.equal(shouldRefreshAutomatically(true, "visible"), false);
  assert.equal(shouldRefreshAutomatically(false, "hidden"), false);
  assert.equal(shouldRefreshAutomatically(false, "prerender"), false);
});

test("unknown pause state fails closed", () => {
  assert.equal(shouldRefreshAutomatically(undefined, "visible"), false);
  assert.equal(shouldRefreshAutomatically("false", "visible"), false);
  assert.equal(shouldRefreshAutomatically(0, "visible"), false);
});

test("live-update control always carries semantic text and state", () => {
  assert.deepEqual(liveUpdatePresentation(false), {
    icon: "Ⅱ",
    label: "Pause live updates",
    state: "live",
  });
  assert.deepEqual(liveUpdatePresentation(true), {
    icon: "▶",
    label: "Resume live updates",
    state: "paused",
  });
  assert.equal(liveUpdatePresentation(undefined).state, "paused");
});
