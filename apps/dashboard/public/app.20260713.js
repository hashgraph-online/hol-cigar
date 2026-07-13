import {
  densityPresentation,
  motionPresentation,
  nextDensity,
  nextMotion,
  nextTheme,
  normalizeDensity,
  normalizeMotion,
  normalizeTheme,
  themePresentation,
} from "./preferences.20260713.js";
import {
  liveUpdatePresentation,
  shouldRefreshAutomatically,
} from "./live-updates.20260713.js";
import {
  enabledTransports,
  formatByteLimit,
  freshnessPresentation,
  isAggregateStatus,
  isComponentStatus,
} from "./health-details.20260713.js";

const $ = (id) => document.getElementById(id);
const THEME_STORAGE_KEY = "cigar.dashboard.theme.v1";
const DENSITY_STORAGE_KEY = "cigar.dashboard.density.v1";
const MOTION_STORAGE_KEY = "cigar.dashboard.motion.v1";

function readTheme() {
  try {
    return normalizeTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return "system";
  }
}

function storeTheme(theme) {
  try {
    if (theme === "system") {
      window.localStorage.removeItem(THEME_STORAGE_KEY);
    } else {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    }
  } catch {
    // Storage can be disabled; the in-memory display preference still applies.
  }
}

function readDensity() {
  try {
    return normalizeDensity(window.localStorage.getItem(DENSITY_STORAGE_KEY));
  } catch {
    return "comfortable";
  }
}

function storeDensity(density) {
  try {
    if (density === "comfortable") {
      window.localStorage.removeItem(DENSITY_STORAGE_KEY);
    } else {
      window.localStorage.setItem(DENSITY_STORAGE_KEY, density);
    }
  } catch {
    // Storage can be disabled; the in-memory display preference still applies.
  }
}

function readMotion() {
  try {
    return normalizeMotion(window.localStorage.getItem(MOTION_STORAGE_KEY));
  } catch {
    return "system";
  }
}

function storeMotion(motion) {
  try {
    if (motion === "system") {
      window.localStorage.removeItem(MOTION_STORAGE_KEY);
    } else {
      window.localStorage.setItem(MOTION_STORAGE_KEY, motion);
    }
  } catch {
    // Storage can be disabled; the in-memory display preference still applies.
  }
}

function applyTheme(value) {
  const theme = normalizeTheme(value);
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
  const button = $("theme-toggle");
  if (button) {
    const presentation = themePresentation(theme);
    button.textContent = `${presentation.icon} ${presentation.label}`;
    button.setAttribute("aria-label", `Color theme: ${presentation.label}. Activate to change theme.`);
    button.title = `Color theme: ${presentation.label}`;
    button.dataset.theme = theme;
  }
  return theme;
}

function applyDensity(value) {
  const density = normalizeDensity(value);
  document.documentElement.dataset.density = density;
  const button = $("density-toggle");
  if (button) {
    const presentation = densityPresentation(density);
    button.textContent = `${presentation.icon} ${presentation.label}`;
    button.setAttribute("aria-label", `Layout density: ${presentation.label}. Activate to change density.`);
    button.title = `Layout density: ${presentation.label}`;
    button.dataset.density = density;
  }
  return density;
}

function applyMotion(value) {
  const motion = normalizeMotion(value);
  if (motion === "system") {
    delete document.documentElement.dataset.motion;
  } else {
    document.documentElement.dataset.motion = motion;
  }
  const button = $("motion-toggle");
  if (button) {
    const presentation = motionPresentation(motion);
    button.textContent = `${presentation.icon} ${presentation.label}`;
    button.setAttribute("aria-label", `Motion preference: ${presentation.label}. Activate to change motion.`);
    button.title = `Motion preference: ${presentation.label}`;
    button.dataset.motion = motion;
  }
  return motion;
}

let selectedTheme = applyTheme(readTheme());
let selectedDensity = applyDensity(readDensity());
let selectedMotion = applyMotion(readMotion());
let updatesPaused = false;

function showToast(message) {
  const toast = $("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.hidden = false;
  window.setTimeout(() => { toast.hidden = true; }, 4000);
}

function setStatus(status, label, detail) {
  const pill = $("global-status");
  pill.className = `status-pill ${status}`;
  pill.querySelector("span").textContent = label;
  $("operational-state").textContent = label;
  $("operational-detail").textContent = detail;
}

function title(value) {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function setExactTime(id, value) {
  const node = $(id);
  if (typeof value === "string" && value.length > 0 && value.length <= 64) {
    node.textContent = value;
    node.dateTime = value;
  } else {
    node.textContent = "Unavailable";
    node.removeAttribute("datetime");
  }
}

function renderHealthDetails(value) {
  const freshness = freshnessPresentation(value.freshness_ms);
  const freshnessBadge = $("freshness-badge");
  freshnessBadge.textContent = freshness.label;
  freshnessBadge.className = `mini-badge freshness-${freshness.className}`;
  $("health-target").textContent = value.target_alias;
  $("health-aggregate").textContent = title(value.aggregate);
  $("health-failures").textContent = String(value.consecutive_failures);
  $("health-age").textContent = `${freshness.label} · ${value.freshness_ms} ms`;
  setExactTime("health-observed-at", value.observed_at);

  const configuration = value.configuration;
  if (configuration) {
    $("health-mode").textContent = configuration.mode === "local"
      ? "Local"
      : configuration.mode === "shared"
        ? "Shared"
        : "Unavailable";
    const transports = enabledTransports(configuration);
    $("health-transports").textContent = transports.length ? transports.join(", ") : "None enabled";
    $("health-limits").textContent = `${formatByteLimit(configuration.max_request_bytes)} request · ${configuration.max_timeout_ms} ms timeout`;
    setExactTime("configuration-observed-at", configuration.observed_at);
  } else {
    $("health-mode").textContent = "Unavailable";
    $("health-transports").textContent = "Awaiting typed configuration";
    $("health-limits").textContent = "Unavailable";
    setExactTime("configuration-observed-at", null);
  }

  const diagnostics = value.diagnostics;
  if (diagnostics) {
    $("diagnostics-state").textContent = diagnostics.stale ? "Stale" : diagnostics.ready ? "Ready" : "Not ready";
    $("diagnostics-latency").textContent = `${diagnostics.latency_ms} ms`;
    setExactTime("diagnostics-observed-at", diagnostics.observed_at);
  } else {
    $("diagnostics-state").textContent = "Awaiting observation";
    $("diagnostics-latency").textContent = "Unavailable";
    setExactTime("diagnostics-observed-at", null);
  }

  const staleSources = [];
  if (freshness.className === "stale" || freshness.className === "expired") {
    staleSources.push("Aggregate status");
  }
  if (diagnostics?.stale) staleSources.push("Diagnostics and metrics");
  for (const component of value.components) {
    if (component.stale) staleSources.push(title(component.name));
  }
  $("stale-sources").textContent = staleSources.length ? staleSources.join(", ") : "None";

  const componentRows = value.components.map((component) => {
    if (
      !isComponentStatus(component.status)
      || typeof component.name !== "string"
      || typeof component.observed_at !== "string"
      || !Number.isSafeInteger(component.latency_ms)
      || typeof component.stale !== "boolean"
      || (component.reason !== null && typeof component.reason !== "string")
    ) {
      throw new Error("Status response contained an invalid component state.");
    }
    const row = element("div", "", "health-component");
    row.setAttribute("role", "listitem");
    const state = element("span", title(component.status), `component-state ${component.status}`);
    const reason = element("code", component.reason || "no-public-reason");
    const observation = element("span", `${component.observed_at} · ${component.latency_ms} ms`);
    row.append(element("strong", title(component.name)), state, reason, observation);
    return row;
  });
  if (!componentRows.length) {
    componentRows.push(element("p", "No readiness component observation is available.", "empty-copy"));
  }
  $("health-components").replaceChildren(...componentRows);
}

function renderDaemonStatus(value) {
  if (
    value?.schema_version !== "cigar.dashboard-status.v1"
    || !isAggregateStatus(value.aggregate)
    || !Array.isArray(value.components)
    || !Number.isSafeInteger(value.freshness_ms)
    || !Number.isSafeInteger(value.consecutive_failures)
    || value.consecutive_failures < 0
  ) {
    throw new Error("Status response returned an incompatible response.");
  }
  renderHealthDetails(value);
  const label = title(value.aggregate);
  const freshness = value.freshness_ms === 0 ? "fresh" : `${Math.round(value.freshness_ms / 1000)}s old`;
  const detail = value.version
    ? `Protocol ${value.version.protocol_min}–${value.version.protocol_max} · API ${value.version.api_version} · ${freshness}`
    : `No valid compatibility observation · failures ${value.consecutive_failures}`;
  setStatus(value.aggregate, label, detail);
  $("readiness-badge").textContent = label;
  $("readiness-badge").className = value.aggregate === "healthy" ? "mini-badge" : "mini-badge neutral";
  $("readiness-count").textContent = String(value.components.length);
  $("readiness-detail").textContent = value.version
    ? `Daemon ${value.version.package} · source ${value.version.source_revision}`
    : "Compatibility negotiation has not produced a valid typed observation.";
  const dots = $("component-dots");
  dots.replaceChildren(...value.components.map((component) => {
    const dot = document.createElement("i");
    dot.className = component.status;
    dot.title = `${component.name}: ${component.status}${component.reason ? ` (${component.reason})` : ""}`;
    return dot;
  }));
  dots.setAttribute(
    "aria-label",
    value.components.length
      ? value.components.map((component) => `${component.name} ${component.status}`).join(", ")
      : "No readiness component observation",
  );

  const diagnostics = value.diagnostics;
  const queueDots = $("queue-dots");
  if (!diagnostics) {
    $("queue-badge").textContent = "Awaiting observation";
    $("queue-badge").className = "mini-badge neutral";
    $("queue-utilization").textContent = "—";
    $("queue-detail").textContent = "Typed diagnostics and closed metrics have not been observed.";
    queueDots.replaceChildren();
    queueDots.setAttribute("aria-label", "No worker queue observation");
    return;
  }
  const health = new Map(diagnostics.workers.map((worker) => [worker.worker, worker.healthy]));
  const depth = diagnostics.metrics.queues.reduce((total, queue) => total + queue.depth, 0);
  const capacity = diagnostics.metrics.queues.reduce((total, queue) => total + queue.capacity, 0);
  const utilization = capacity === 0 ? 0 : Math.round((depth / capacity) * 100);
  const unhealthy = diagnostics.workers.filter((worker) => !worker.healthy).length;
  $("queue-badge").textContent = diagnostics.stale
    ? "Stale"
    : unhealthy
      ? `${unhealthy} unhealthy`
      : "Healthy";
  $("queue-badge").className = unhealthy || diagnostics.stale ? "mini-badge neutral" : "mini-badge";
  $("queue-utilization").textContent = `${utilization}%`;
  $("queue-detail").textContent = `${depth} of ${capacity} slots · ${diagnostics.metrics.rejected_requests_total} rejected requests · ${diagnostics.latency_ms} ms probe`;
  const queueNodes = diagnostics.metrics.queues.map((queue) => {
    const dot = document.createElement("i");
    const ratio = queue.capacity === 0 ? 0 : queue.depth / queue.capacity;
    dot.className = !health.get(queue.worker) ? "unhealthy" : ratio >= 0.8 ? "degraded" : "healthy";
    dot.title = `${title(queue.worker)}: ${queue.depth}/${queue.capacity}, ${queue.rejections_total} rejected`;
    return dot;
  });
  queueDots.replaceChildren(...queueNodes);
  queueDots.setAttribute(
    "aria-label",
    diagnostics.metrics.queues.length
      ? diagnostics.metrics.queues.map((queue) => `${title(queue.worker)} ${queue.depth} of ${queue.capacity}`).join(", ")
      : "No worker queues reported",
  );
}

function duration(seconds) {
  if (seconds >= 3600) return `${Math.round(seconds / 3600)} hr`;
  if (seconds >= 60) return `${Math.round(seconds / 60)} min`;
  return `${seconds} sec`;
}

function element(name, text, className) {
  const node = document.createElement(name);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function renderProfiles(value) {
  const grid = $("profile-grid");
  const cards = value.profiles.map((profile) => {
    const card = element("article", "", `profile-card${profile.kind === "soak" ? " accent" : ""}`);
    if (profile.id === "soak-smoke") card.id = "soak";
    const heading = element("div", "");
    heading.append(
      element("span", title(profile.kind), "profile-kind"),
      element(
        "span",
        profile.availability_state === "available" ? "Available" : "Unavailable",
        `mini-badge${profile.availability_state === "available" ? "" : " neutral"}`,
      ),
    );
    const facts = document.createElement("dl");
    for (const [label, fact] of [
      ["Expected", duration(profile.expected_duration_seconds)],
      ["Network", title(profile.network_mode)],
    ]) {
      const row = document.createElement("div");
      row.append(element("dt", label), element("dd", fact));
      facts.append(row);
    }
    const button = element(
      "button",
      profile.availability_state === "available" && value.control_enabled
        ? "Launch contract pending"
        : profile.availability_state === "command_not_implemented"
          ? "Supervisor not implemented"
          : "Control disabled",
    );
    button.type = "button";
    button.disabled = true;
    card.append(
      heading,
      element("h3", profile.title),
      element("p", profile.description),
      facts,
      button,
    );
    return card;
  });
  if (cards.length) {
    grid.replaceChildren(...cards);
  } else {
    const empty = element("article", "", "profile-card");
    empty.append(
      element("span", "Observer mode", "profile-kind"),
      element("h3", "No run registry configured"),
      element("p", "Add an absolute reviewed registry path to expose disabled profile metadata."),
    );
    grid.replaceChildren(empty);
  }
}

function renderRuns(value) {
  if (value?.schema_version !== "cigar.dashboard-runs.v1" || !Array.isArray(value.runs)) {
    throw new Error("Run history returned an incompatible response.");
  }
  const latest = value.runs[0];
  if (!latest) {
    $("verification-state").textContent = "Not run";
    $("verification-detail").textContent = "No persisted dashboard run";
    return;
  }
  const labels = {
    queued: "Queued",
    preparing: "Preparing",
    running: "Running",
    cancelling: "Cancelling",
    cancelled: "Cancelled",
    passed: "Passed",
    failed: "Failed",
    timed_out: "Timed out",
    lost: "Lost",
  };
  const label = labels[latest.state];
  if (!label || typeof latest.profile_id !== "string") {
    throw new Error("Run history contained an invalid state.");
  }
  $("verification-state").textContent = label;
  $("verification-detail").textContent = `${latest.profile_id} · dashboard run history`;
}

function renderEvidence(value) {
  if (value?.schema_version !== "cigar.dashboard-evidence-index.v1" || !Array.isArray(value.evidence)) {
    throw new Error("Evidence history returned an incompatible response.");
  }
  const latest = value.evidence[0];
  if (latest?.category === "release-qualifying" && latest.status === "valid") {
    $("release-state").textContent = "Qualified";
    $("release-detail").textContent = `${latest.schema_id} · independently verified descriptor`;
    return;
  }
  $("release-state").textContent = "Not qualified";
  if (!latest) {
    $("release-detail").textContent = "No release-qualifying descriptor";
  } else if (latest.status !== "valid") {
    $("release-detail").textContent = `Latest descriptor ${title(latest.status)}`;
  } else {
    $("release-detail").textContent = `${title(latest.category)} evidence is not release-qualifying`;
  }
}

async function exchangeBootstrap() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const secret = fragment.get("bootstrap");
  if (!secret) return;
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  const response = await fetch("/api/v1/session:exchange", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bootstrap_secret: secret }),
  });
  if (!response.ok) throw new Error("The one-time dashboard link was rejected.");
  await response.json();
}

let refreshInFlight = false;
let refreshQueued = false;
let eventStream = null;

function connectEventStream() {
  if (
    eventStream
    || typeof EventSource === "undefined"
    || !shouldRefreshAutomatically(updatesPaused, document.visibilityState)
  ) return;
  const source = new EventSource("/api/v1/events", { withCredentials: true });
  source.addEventListener("status", () => refresh());
  source.addEventListener("run", () => refresh());
  source.addEventListener("evidence", () => refresh());
  source.addEventListener("open", () => {
    if (eventStream !== source || !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    $("session-state").textContent = "Authenticated local session · live updates";
  });
  source.addEventListener("error", () => {
    if (eventStream !== source || !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    $("session-state").textContent = "Authenticated local session · reconnecting updates";
  });
  eventStream = source;
}

function disconnectEventStream() {
  eventStream?.close();
  eventStream = null;
}

function applyLiveUpdateState(paused) {
  updatesPaused = paused === true;
  const button = $("live-updates-toggle");
  if (button) {
    const presentation = liveUpdatePresentation(updatesPaused);
    button.textContent = presentation.icon;
    button.setAttribute("aria-label", presentation.label);
    button.title = presentation.label;
    button.dataset.state = presentation.state;
    button.setAttribute("aria-pressed", String(updatesPaused));
  }
  const sessionState = $("session-state");
  if (updatesPaused) {
    refreshQueued = false;
    disconnectEventStream();
    if (sessionState?.textContent.startsWith("Authenticated local session")) {
      sessionState.textContent = "Authenticated local session · updates paused";
    }
  } else if (document.visibilityState !== "visible") {
    disconnectEventStream();
    if (sessionState?.textContent.startsWith("Authenticated local session")) {
      sessionState.textContent = "Authenticated local session · background updates suspended";
    }
  } else {
    if (sessionState?.textContent.startsWith("Authenticated local session")) {
      sessionState.textContent = "Authenticated local session · resynchronizing";
    }
    refresh(true);
  }
}

async function refresh(manual = false) {
  if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
  if (refreshInFlight) {
    if (manual) refreshQueued = true;
    return;
  }
  refreshInFlight = true;
  if ($("session-state").textContent === "No browser session") {
    setStatus("starting", "Connecting", "Checking the authenticated sidecar session");
  }
  try {
    await exchangeBootstrap();
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    const response = await fetch("/api/v1/bootstrap", { credentials: "same-origin", cache: "no-store" });
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    if (response.status === 401) {
      disconnectEventStream();
      setStatus("unreachable", "Session required", "Open the one-time URL printed by cigar-dashboard");
      $("session-state").textContent = "Authentication required";
      return;
    }
    if (!response.ok) throw new Error("Sidecar bootstrap is unavailable.");
    const value = await response.json();
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    connectEventStream();
    $("target-alias").textContent = value.target_alias;
    $("sidecar-version").textContent = `v${value.sidecar_version}`;
    $("sidecar-detail").textContent = `${value.asset_count} verified assets · ${Math.round(value.max_request_bytes / 1024)} KiB request cap`;
    $("sidecar-badge").textContent = "Online";
    $("control-badge").textContent = value.control_enabled ? "Configured" : "Disabled";
    $("session-state").textContent = updatesPaused
      ? "Authenticated local session · updates paused"
      : document.visibilityState === "visible"
        ? "Authenticated local session"
        : "Authenticated local session · background updates suspended";
    const [statusResponse, profilesResponse, runsResponse, evidenceResponse] = await Promise.all([
      fetch("/api/v1/status", { credentials: "same-origin", cache: "no-store" }),
      fetch("/api/v1/run-profiles", { credentials: "same-origin", cache: "no-store" }),
      fetch("/api/v1/runs", { credentials: "same-origin", cache: "no-store" }),
      fetch("/api/v1/evidence", { credentials: "same-origin", cache: "no-store" }),
    ]);
    if (!statusResponse.ok) throw new Error("Typed daemon status is unavailable.");
    if (!profilesResponse.ok) throw new Error("Reviewed run profiles are unavailable.");
    if (!runsResponse.ok) throw new Error("Dashboard run history is unavailable.");
    if (!evidenceResponse.ok) throw new Error("Dashboard evidence history is unavailable.");
    const [status, profiles, runs, evidence] = await Promise.all([
      statusResponse.json(),
      profilesResponse.json(),
      runsResponse.json(),
      evidenceResponse.json(),
    ]);
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    renderDaemonStatus(status);
    renderProfiles(profiles);
    renderRuns(runs);
    renderEvidence(evidence);
  } catch (error) {
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    setStatus("unreachable", "Sidecar unavailable", "The local dashboard sidecar did not return a valid response");
    $("session-state").textContent = "Connection failed";
    showToast(error instanceof Error ? error.message : "Dashboard refresh failed.");
  } finally {
    refreshInFlight = false;
    if (refreshQueued) {
      refreshQueued = false;
      refresh(true);
    }
  }
}

$("refresh")?.addEventListener("click", () => refresh(true));
$("health-reconnect")?.addEventListener("click", () => refresh(true));
$("live-updates-toggle")?.addEventListener("click", () => {
  applyLiveUpdateState(!updatesPaused);
});
$("theme-toggle")?.addEventListener("click", () => {
  selectedTheme = applyTheme(nextTheme(selectedTheme));
  storeTheme(selectedTheme);
});
$("density-toggle")?.addEventListener("click", () => {
  selectedDensity = applyDensity(nextDensity(selectedDensity));
  storeDensity(selectedDensity);
});
$("motion-toggle")?.addEventListener("click", () => {
  selectedMotion = applyMotion(nextMotion(selectedMotion));
  storeMotion(selectedMotion);
});
$("display-menu")?.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    event.currentTarget.removeAttribute("open");
    event.currentTarget.querySelector("summary")?.focus();
  }
});
window.addEventListener("storage", (event) => {
  if (event.key === THEME_STORAGE_KEY || event.key === null) {
    selectedTheme = applyTheme(event.newValue);
  }
  if (event.key === DENSITY_STORAGE_KEY || event.key === null) {
    selectedDensity = applyDensity(event.newValue);
  }
  if (event.key === MOTION_STORAGE_KEY || event.key === null) {
    selectedMotion = applyMotion(event.newValue);
  }
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") {
    disconnectEventStream();
    const sessionState = $("session-state");
    if (!updatesPaused && sessionState?.textContent.startsWith("Authenticated local session")) {
      sessionState.textContent = "Authenticated local session · background updates suspended";
    }
  } else if (!updatesPaused) {
    refresh(true);
  }
});
refresh();
window.setInterval(() => {
  refresh();
}, 2000);
