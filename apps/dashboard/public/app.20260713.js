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
import {
  filterProtocolOperations,
  normalizeProtocolCatalog,
} from "./protocol-catalog.20260713.js";
import {
  cancellableRunId,
  cancellationPath,
  profileControlPresentation,
} from "./controls.20260714.js";
import {
  openSidecarEventStream,
  sidecarFetch,
} from "./browser-security.20260714.js";

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
let csrfToken = null;
let activeRunId = null;

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
    const control = profileControlPresentation(profile.availability_state, value.control_enabled);
    const button = element("button", control.label);
    button.type = "button";
    button.disabled = !control.enabled;
    if (!button.disabled) {
      button.addEventListener("click", () => startProfile(profile));
    }
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

let protocolCatalog = null;

function renderProtocol(value, query = "") {
  protocolCatalog = normalizeProtocolCatalog(value);
  const operations = filterProtocolOperations(protocolCatalog, query);
  $("protocol-count").textContent = `${operations.length} of ${protocolCatalog.operation_count} operations`;
  $("protocol-badge").textContent = `${protocolCatalog.service_count} services · ${protocolCatalog.operation_count} operations`;
  const serviceCounts = protocolCatalog.services.map((service) => {
    const item = element("span", `${service.name.replace(/Service$/, "")} · ${service.operations.length}`);
    item.setAttribute("role", "listitem");
    return item;
  });
  $("protocol-services").replaceChildren(...serviceCounts);
  const rows = operations.map((operation) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    identity.append(element("strong", operation.operation_id), element("small", operation.rpc));
    const route = document.createElement("td");
    route.append(element("span", operation.http_method, `method method-${operation.http_method.toLowerCase()}`), element("code", operation.http_path));
    const contract = document.createElement("td");
    const badges = [
      operation.auth,
      operation.mutation ? "mutation" : "read",
      operation.stream === "server_stream" ? "stream" : "unary",
      operation.idempotency === "required" ? "idempotent" : null,
      operation.revision === "required" ? "revisioned" : null,
    ].filter(Boolean);
    contract.append(...badges.map((badge) => element("span", title(badge), "contract-badge")));
    row.append(identity, route, contract);
    return row;
  });
  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = element("td", "No generated operation matches this search.", "empty-copy");
    cell.colSpan = 3;
    row.append(cell);
    rows.push(row);
  }
  $("protocol-operations").replaceChildren(...rows);
}

function renderRuns(value) {
  if (value?.schema_version !== "cigar.dashboard-runs.v1" || !Array.isArray(value.runs)) {
    throw new Error("Run history returned an incompatible response.");
  }
  const latest = value.runs[0];
  if (!latest) {
    activeRunId = null;
    $("cancel-run").hidden = true;
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
  activeRunId = cancellableRunId(latest);
  $("cancel-run").hidden = activeRunId === null || latest.state === "cancelling";
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
  const response = await sidecarFetch("/api/v1/session:exchange", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bootstrap_secret: secret }),
  });
  if (!response.ok) throw new Error("The one-time dashboard link was rejected.");
  const value = await response.json();
  csrfToken = value.csrf_token;
}

async function ensureCsrfToken() {
  if (typeof csrfToken === "string" && csrfToken.length > 0) return csrfToken;
  const response = await sidecarFetch("/api/v1/session:csrf", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) throw new Error("The local control proof could not be refreshed.");
  const value = await response.json();
  if (value?.schema_version !== "cigar.dashboard-session.v1" || typeof value.csrf_token !== "string") {
    throw new Error("The local control proof was invalid.");
  }
  csrfToken = value.csrf_token;
  return csrfToken;
}

async function startProfile(profile) {
  if (profile.availability_state !== "available") return;
  const accepted = window.confirm(
    `Launch reviewed profile “${profile.id}”?\n\nThe executable and arguments are fixed by the verified registry. Ordinary output is never shown in the browser.`,
  );
  if (!accepted) return;
  try {
    const csrf = await ensureCsrfToken();
    const response = await sidecarFetch("/api/v1/runs", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "content-type": "application/json",
        "x-cigar-csrf": csrf,
      },
      body: JSON.stringify({ profile_id: profile.id }),
    });
    if (!response.ok) throw new Error("The reviewed profile was not started.");
    const run = await response.json();
    activeRunId = run.run_id;
    showToast(`Started ${profile.id}.`);
    await refresh(true);
  } catch (error) {
    showToast(error instanceof Error ? error.message : "The reviewed profile was not started.");
  }
}

async function cancelActiveRun() {
  if (typeof activeRunId !== "string") return;
  const path = cancellationPath(activeRunId);
  if (path === null) return;
  try {
    const csrf = await ensureCsrfToken();
    const response = await sidecarFetch(path, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "x-cigar-csrf": csrf },
    });
    if (!response.ok) throw new Error("The reviewed run could not be cancelled.");
    showToast("Cancellation requested; the process group is settling.");
    await refresh(true);
  } catch (error) {
    showToast(error instanceof Error ? error.message : "The reviewed run could not be cancelled.");
  }
}

let refreshInFlight = false;
let refreshQueued = false;
let eventStream = null;

function connectEventStream() {
  if (
    eventStream
    || !shouldRefreshAutomatically(updatesPaused, document.visibilityState)
  ) return;
  const source = openSidecarEventStream();
  if (source === null) return;
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
    const response = await sidecarFetch("/api/v1/bootstrap", { cache: "no-store" });
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
    const [statusResponse, protocolResponse, profilesResponse, runsResponse, evidenceResponse] = await Promise.all([
      sidecarFetch("/api/v1/status", { cache: "no-store" }),
      sidecarFetch("/api/v1/protocol", { cache: "no-store" }),
      sidecarFetch("/api/v1/run-profiles", { cache: "no-store" }),
      sidecarFetch("/api/v1/runs", { cache: "no-store" }),
      sidecarFetch("/api/v1/evidence", { cache: "no-store" }),
    ]);
    if (!statusResponse.ok) throw new Error("Typed daemon status is unavailable.");
    if (!protocolResponse.ok) throw new Error("Generated protocol catalog is unavailable.");
    if (!profilesResponse.ok) throw new Error("Reviewed run profiles are unavailable.");
    if (!runsResponse.ok) throw new Error("Dashboard run history is unavailable.");
    if (!evidenceResponse.ok) throw new Error("Dashboard evidence history is unavailable.");
    const [status, protocol, profiles, runs, evidence] = await Promise.all([
      statusResponse.json(),
      protocolResponse.json(),
      profilesResponse.json(),
      runsResponse.json(),
      evidenceResponse.json(),
    ]);
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    renderDaemonStatus(status);
    renderProtocol(protocol, $("protocol-search")?.value || "");
    renderProfiles(profiles);
    renderRuns(runs);
    renderEvidence(evidence);
  } catch (error) {
    if (!manual && !shouldRefreshAutomatically(updatesPaused, document.visibilityState)) return;
    setStatus("unreachable", "Sidecar unavailable", "The local dashboard sidecar did not return a valid response");
    $("sidecar-badge").textContent = "Unreachable";
    $("session-state").textContent = "Connection failed";
    $("health-details")?.setAttribute("open", "");
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
$("cancel-run")?.addEventListener("click", cancelActiveRun);
$("protocol-search")?.addEventListener("input", (event) => {
  if (protocolCatalog) renderProtocol(protocolCatalog, event.currentTarget.value);
});
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
document.addEventListener("keydown", (event) => {
  const menu = $("display-menu");
  if (event.key === "Escape" && menu?.hasAttribute("open")) {
    event.preventDefault();
    menu.removeAttribute("open");
    menu.querySelector("summary")?.focus();
  }
}, true);
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
