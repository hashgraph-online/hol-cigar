export type AggregateStatus =
  | "starting"
  | "healthy"
  | "degraded"
  | "unhealthy"
  | "unreachable"
  | "incompatible";

export type CompatibilityState = "unknown" | "compatible" | "incompatible";
export type ReadinessState = "healthy" | "degraded" | "unhealthy";
export type FreshnessState = "waiting" | "fresh" | "stale" | "unreachable";

export interface StatusEvidence {
  readonly hasValidObservation: boolean;
  readonly compatibility: CompatibilityState;
  readonly reachable: boolean;
  readonly live: boolean;
  readonly gateOpen: boolean;
  readonly readiness: ReadinessState;
  readonly freshnessMs: number;
  readonly consecutiveFailures: number;
}

const STALE_AFTER_MS = 10_000;
const UNREACHABLE_AFTER_MS = 30_000;
const UNREACHABLE_AFTER_FAILURES = 3;

export function classifyFreshness(evidence: StatusEvidence): FreshnessState {
  if (!evidence.hasValidObservation) return "waiting";
  if (
    !evidence.reachable ||
    evidence.consecutiveFailures >= UNREACHABLE_AFTER_FAILURES ||
    evidence.freshnessMs >= UNREACHABLE_AFTER_MS
  ) {
    return "unreachable";
  }
  if (evidence.freshnessMs >= STALE_AFTER_MS) return "stale";
  return "fresh";
}

export function classifyAggregateStatus(evidence: StatusEvidence): AggregateStatus {
  if (evidence.compatibility === "incompatible") return "incompatible";
  if (!evidence.hasValidObservation || evidence.compatibility === "unknown") return "starting";
  const freshness = classifyFreshness(evidence);
  if (freshness === "unreachable") return "unreachable";
  if (!evidence.live || !evidence.gateOpen || evidence.readiness === "unhealthy") {
    return "unhealthy";
  }
  if (evidence.readiness === "degraded" || freshness === "stale") return "degraded";
  return "healthy";
}
