const THEMES = Object.freeze(["system", "light", "dark"]);
const DENSITIES = Object.freeze(["comfortable", "compact"]);
const MOTION_MODES = Object.freeze(["system", "standard", "reduced"]);

export function normalizeTheme(value) {
  return THEMES.includes(value) ? value : "system";
}

export function nextTheme(value) {
  const theme = normalizeTheme(value);
  const position = THEMES.indexOf(theme);
  return THEMES[(position + 1) % THEMES.length];
}

export function themePresentation(value) {
  const theme = normalizeTheme(value);
  if (theme === "light") return Object.freeze({ icon: "☀", label: "Light" });
  if (theme === "dark") return Object.freeze({ icon: "☾", label: "Dark" });
  return Object.freeze({ icon: "◐", label: "System" });
}

export function normalizeDensity(value) {
  return DENSITIES.includes(value) ? value : "comfortable";
}

export function nextDensity(value) {
  const density = normalizeDensity(value);
  const position = DENSITIES.indexOf(density);
  return DENSITIES[(position + 1) % DENSITIES.length];
}

export function densityPresentation(value) {
  const density = normalizeDensity(value);
  return density === "compact"
    ? Object.freeze({ icon: "≡", label: "Compact" })
    : Object.freeze({ icon: "▦", label: "Comfortable" });
}

export function normalizeMotion(value) {
  return MOTION_MODES.includes(value) ? value : "system";
}

export function nextMotion(value) {
  const motion = normalizeMotion(value);
  const position = MOTION_MODES.indexOf(motion);
  return MOTION_MODES[(position + 1) % MOTION_MODES.length];
}

export function motionPresentation(value) {
  const motion = normalizeMotion(value);
  if (motion === "standard") return Object.freeze({ icon: "◆", label: "Standard" });
  if (motion === "reduced") return Object.freeze({ icon: "—", label: "Reduced" });
  return Object.freeze({ icon: "◌", label: "System" });
}
