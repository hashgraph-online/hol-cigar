const AVAILABILITY = new Set([
  "available",
  "control_disabled",
  "tool_missing",
  "platform_unsupported",
  "source_checkout_required",
  "dependency_cache_missing",
  "credential_missing",
  "command_not_implemented",
]);
const ACTIVE_STATES = new Set(["queued", "preparing", "running", "cancelling"]);
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function profileControlPresentation(state, controlEnabled) {
  const safeState = AVAILABILITY.has(state) ? state : "command_not_implemented";
  const enabled = controlEnabled === true && safeState === "available";
  const label = enabled
    ? "Launch reviewed profile"
    : safeState.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
  return { enabled, label, state: safeState };
}

export function cancellableRunId(run) {
  if (
    run === null
    || typeof run !== "object"
    || !ACTIVE_STATES.has(run.state)
    || run.state === "cancelling"
    || typeof run.run_id !== "string"
    || !RUN_ID.test(run.run_id)
  ) return null;
  return run.run_id;
}

export function cancellationPath(runId) {
  return typeof runId === "string" && RUN_ID.test(runId)
    ? `/api/v1/runs/${runId}:cancel`
    : null;
}
