const FIXED_API_PATHS = Object.freeze(new Set([
  "/api/v1/bootstrap",
  "/api/v1/evidence",
  "/api/v1/events",
  "/api/v1/protocol",
  "/api/v1/run-profiles",
  "/api/v1/runs",
  "/api/v1/session:csrf",
  "/api/v1/session:exchange",
  "/api/v1/status",
]));
const CANCEL_PATH = /^\/api\/v1\/runs\/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:cancel$/;
const EVENTS_PATH = "/api/v1/events";

export function isSidecarApiPath(path) {
  return typeof path === "string"
    && (FIXED_API_PATHS.has(path) || CANCEL_PATH.test(path));
}

export function sidecarFetch(path, options = {}) {
  if (!isSidecarApiPath(path)) {
    throw new TypeError("dashboard network access is limited to reviewed same-origin sidecar routes");
  }
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("dashboard request options must be an object");
  }
  return globalThis.fetch(path, Object.freeze({
    ...options,
    credentials: "same-origin",
    redirect: "error",
    referrerPolicy: "no-referrer",
  }));
}

export function openSidecarEventStream() {
  if (typeof globalThis.EventSource !== "function") return null;
  return new globalThis.EventSource(EVENTS_PATH, { withCredentials: true });
}
