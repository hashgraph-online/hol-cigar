export function shouldRefreshAutomatically(paused, visibilityState) {
  return paused === false && visibilityState === "visible";
}

export function liveUpdatePresentation(paused) {
  if (paused !== false) {
    return Object.freeze({
      icon: "▶",
      label: "Resume live updates",
      state: "paused",
    });
  }
  return Object.freeze({
    icon: "Ⅱ",
    label: "Pause live updates",
    state: "live",
  });
}
