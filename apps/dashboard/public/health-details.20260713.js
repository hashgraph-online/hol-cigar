const AGGREGATES = Object.freeze([
  "starting",
  "healthy",
  "degraded",
  "unhealthy",
  "stale",
  "unreachable",
  "incompatible",
]);
const COMPONENT_STATES = Object.freeze(["healthy", "degraded", "unhealthy"]);

export function isAggregateStatus(value) {
  return AGGREGATES.includes(value);
}

export function isComponentStatus(value) {
  return COMPONENT_STATES.includes(value);
}

export function freshnessPresentation(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    return Object.freeze({ className: "unknown", label: "Unknown freshness" });
  }
  if (value < 10_000) {
    return Object.freeze({ className: "fresh", label: "Fresh" });
  }
  if (value <= 30_000) {
    return Object.freeze({ className: "stale", label: "Stale" });
  }
  return Object.freeze({ className: "expired", label: "Expired observation" });
}

export function enabledTransports(configuration) {
  if (!configuration || typeof configuration !== "object") return Object.freeze([]);
  const transports = [];
  if (configuration.local_ipc === true) transports.push("Local IPC");
  if (configuration.http_enabled === true) transports.push("HTTP");
  if (configuration.grpc_enabled === true) transports.push("gRPC");
  return Object.freeze(transports);
}

export function formatByteLimit(value) {
  if (!Number.isSafeInteger(value) || value < 0) return "Unavailable";
  if (value >= 1024 * 1024 && value % (1024 * 1024) === 0) {
    return `${value / (1024 * 1024)} MiB`;
  }
  if (value >= 1024 && value % 1024 === 0) return `${value / 1024} KiB`;
  return `${value} bytes`;
}
