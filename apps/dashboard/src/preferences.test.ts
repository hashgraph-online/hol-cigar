import test from "node:test";
import assert from "node:assert/strict";

import {
  densityPresentation,
  motionPresentation,
  nextTheme,
  nextDensity,
  nextMotion,
  normalizeDensity,
  normalizeMotion,
  normalizeTheme,
  themePresentation,
} from "../public/preferences.20260713.js";

test("theme values are a closed allowlist", () => {
  assert.equal(normalizeTheme("system"), "system");
  assert.equal(normalizeTheme("light"), "light");
  assert.equal(normalizeTheme("dark"), "dark");
});

test("unknown and non-string theme values fail to system", () => {
  assert.equal(normalizeTheme("sepia"), "system");
  assert.equal(normalizeTheme(null), "system");
  assert.equal(normalizeTheme({ theme: "dark" }), "system");
});

test("theme cycling is deterministic", () => {
  assert.equal(nextTheme("system"), "light");
  assert.equal(nextTheme("light"), "dark");
  assert.equal(nextTheme("dark"), "system");
  assert.equal(nextTheme("invalid"), "light");
});

test("theme presentation is semantic text plus a bounded icon", () => {
  assert.deepEqual(themePresentation("system"), { icon: "◐", label: "System" });
  assert.deepEqual(themePresentation("light"), { icon: "☀", label: "Light" });
  assert.deepEqual(themePresentation("dark"), { icon: "☾", label: "Dark" });
});

test("density values cycle through a closed compactness policy", () => {
  assert.equal(normalizeDensity("comfortable"), "comfortable");
  assert.equal(normalizeDensity("compact"), "compact");
  assert.equal(normalizeDensity("dense"), "comfortable");
  assert.equal(nextDensity("comfortable"), "compact");
  assert.equal(nextDensity("compact"), "comfortable");
  assert.deepEqual(densityPresentation("compact"), { icon: "≡", label: "Compact" });
});

test("motion values cycle through system standard and reduced", () => {
  assert.equal(normalizeMotion("system"), "system");
  assert.equal(normalizeMotion("standard"), "standard");
  assert.equal(normalizeMotion("reduced"), "reduced");
  assert.equal(normalizeMotion("animated"), "system");
  assert.equal(nextMotion("system"), "standard");
  assert.equal(nextMotion("standard"), "reduced");
  assert.equal(nextMotion("reduced"), "system");
});

test("motion presentation never relies on its icon alone", () => {
  assert.deepEqual(motionPresentation("system"), { icon: "◌", label: "System" });
  assert.deepEqual(motionPresentation("standard"), { icon: "◆", label: "Standard" });
  assert.deepEqual(motionPresentation("reduced"), { icon: "—", label: "Reduced" });
});
