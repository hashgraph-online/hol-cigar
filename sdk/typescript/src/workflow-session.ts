/** Identity-only state tracking for deterministic workflow context cycles. */

import { CigarError } from "./errors.js";

export const MAX_WORKFLOW_DELTA_CHAIN_LENGTH = 8;
export const MAX_WORKFLOW_REPLAY_CYCLES = 64;

export const WORKFLOW_CONTEXT_PHASES = [
  "new", "plan_created", "target_bundle_loaded", "delta_compiled", "bundle_ready", "materialized",
  "model_invocation_pending", "model_result_recorded", "effect_prepared", "observation_recorded",
  "effect_authorization_revalidated", "effect_authorized", "effect_revalidated", "effect_dispatching",
  "effect_ambiguous", "effect_settled", "checkpointed", "finished", "replay_verified", "quarantined",
] as const;
export type WorkflowContextPhase = typeof WORKFLOW_CONTEXT_PHASES[number];

export const WORKFLOW_RESUME_ACTIONS = [
  "create_context_plan", "compile_context_bundle", "compile_context_delta", "apply_context_delta",
  "materialize_context_bundle", "begin_model_invocation", "resume_model_invocation",
  "prepare_effect_or_ingest_observation", "ingest_observation", "authorize_effect_or_checkpoint",
  "revalidate_context_bundle", "dispatch_effect", "observe_effect", "reconcile_effect", "checkpoint",
  "materialize_or_finish", "replay", "complete",
] as const;
export type WorkflowResumeAction = typeof WORKFLOW_RESUME_ACTIONS[number];

export const WORKFLOW_SESSION_ERROR_CODES = [
  "invalid_transition", "invalid_event", "identity_mismatch", "invalidated", "limit_exceeded",
] as const;
export type WorkflowSessionErrorCode = typeof WORKFLOW_SESSION_ERROR_CODES[number];

export const WORKFLOW_SESSION_EVENT_NAMES = [
  "plan_created", "bundle_compiled", "delta_compiled", "delta_applied", "materialized",
  "model_invocation_started", "model_result_recorded", "effect_prepared", "observation_recorded",
  "effect_authorized", "effect_revalidated", "effect_dispatched", "effect_observed", "cycle_checkpointed",
  "finished", "replay_verified", "context_quarantined",
] as const;

export const WORKFLOW_QUARANTINE_REASONS = ["cancelled", "revoked", "invalidated"] as const;
export type WorkflowQuarantineReason = typeof WORKFLOW_QUARANTINE_REASONS[number];

const ACTION_OPERATIONS = {
  create_context_plan: "createContextPlan",
  compile_context_bundle: "compileContextBundle",
  compile_context_delta: "compileContextDelta",
  apply_context_delta: null,
  materialize_context_bundle: "materializeContextBundle",
  begin_model_invocation: null,
  resume_model_invocation: null,
  prepare_effect_or_ingest_observation: null,
  ingest_observation: "ingestCatalog",
  authorize_effect_or_checkpoint: "authorizeEffect",
  revalidate_context_bundle: "revalidateContextBundle",
  dispatch_effect: "dispatchEffect",
  observe_effect: "getEffectStatus",
  reconcile_effect: "reconcileEffect",
  checkpoint: null,
  materialize_or_finish: null,
  replay: "createReplay",
  complete: null,
} as const satisfies Readonly<Record<WorkflowResumeAction, string | null>>;

export function workflowOperationId(action: WorkflowResumeAction): string | null {
  return ACTION_OPERATIONS[action];
}

export class WorkflowSessionError extends CigarError {
  readonly code: WorkflowSessionErrorCode;

  constructor(code: WorkflowSessionErrorCode) {
    super(`workflow context transition failed: ${code}`);
    this.code = code;
  }
}

type ContextIdentity = Readonly<{ planId: string; bundleId: string; contractDigest: string }>;
type DeltaIdentity = Readonly<{ baseBundleId: string; targetBundleId: string; deltaDigest: string }>;
export type WorkflowEffectState =
  | "prepared" | "authorized" | "dispatching" | "unknown" | "authorized_for_retry"
  | "succeeded" | "failed" | "manual_resolution" | "rejected" | "expired" | "cancelled"
  | "compensated" | "compensation_failed";
type EffectIdentity = Readonly<{
  effectId: string;
  intentDigest: string;
  effectVersion: bigint;
  state: WorkflowEffectState;
  attemptCount: number;
  reconciliationCount: number;
}>;

export type WorkflowReplayDiffStatus = "equal" | "different";
export type WorkflowDeltaReplayIdentity = Readonly<{
  baseBundleId: string;
  targetBundleId: string;
  deltaDigest: string;
}>;
export type WorkflowEffectReplayIdentity = Readonly<EffectIdentity>;
export type WorkflowContextCycleIdentity = Readonly<{
  planId: string;
  bundleId: string;
  contractDigest: string;
  selectedDelta?: WorkflowDeltaReplayIdentity;
  materializedBundleId: string;
  tokenizerFingerprint: string;
  materializerFingerprint: string;
  physicalInputTokens: number;
  invocationId: string;
  requestDigest: string;
  idempotencyKeyDigest: string;
  modelResultDigest: string;
  effect?: WorkflowEffectReplayIdentity;
  outcomeDigest: string;
  outcomeRevision: bigint;
}>;
export type WorkflowContextReplayIdentity = Readonly<{
  cycles: readonly WorkflowContextCycleIdentity[];
}>;
export type WorkflowContextReplayComparison = Readonly<{
  bundleDeltaSelection: WorkflowReplayDiffStatus;
  materialization: WorkflowReplayDiffStatus;
  modelResultIdentity: WorkflowReplayDiffStatus;
  toolEffectDecisions: WorkflowReplayDiffStatus;
  outcome: WorkflowReplayDiffStatus;
  exactMatch: boolean;
}>;

type MaterializationIdentity = Readonly<{
  bundleId: string;
  tokenizerFingerprint: string;
  materializerFingerprint: string;
  physicalInputTokens: number;
}>;
type InvocationIdentity = Readonly<{
  invocationId: string;
  requestDigest: string;
  idempotencyKeyDigest: string;
}>;

const DIGEST = /^1220[0-9a-f]{64}$/;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TERMINAL_EFFECT_STATES: ReadonlySet<WorkflowEffectState> = new Set([
  "succeeded", "failed", "manual_resolution", "rejected", "expired", "cancelled", "compensated",
  "compensation_failed",
]);

/** Mutable, content-safe helper for one context lifecycle. Successful boundaries advance it atomically. */
export class WorkflowContextSession {
  #phase: WorkflowContextPhase = "new";
  #completedTurns = 0;
  #deltaChainLength = 0;
  #activeContext: ContextIdentity | undefined;
  #pendingContext: ContextIdentity | undefined;
  #pendingDelta: DeltaIdentity | undefined;
  #selectedDelta: DeltaIdentity | undefined;
  #materialization: MaterializationIdentity | undefined;
  #invocation: InvocationIdentity | undefined;
  #modelResultDigest: string | undefined;
  #observationDigest: string | undefined;
  #observationRevision: bigint | undefined;
  #effect: EffectIdentity | undefined;
  #completedCycles: WorkflowContextCycleIdentity[] = [];
  #replayVerified = false;
  #quarantineReason: WorkflowQuarantineReason | undefined;

  get phase(): WorkflowContextPhase { return this.#phase; }
  get completedTurns(): number { return this.#completedTurns; }
  get deltaChainLength(): number { return this.#deltaChainLength; }
  get activeBundleId(): string | undefined { return this.#activeContext?.bundleId; }

  replayIdentity(): WorkflowContextReplayIdentity {
    this.#requirePhase("finished", "replay_verified");
    if (this.#completedCycles.length === 0) fail("invalid_transition");
    return cloneReplayIdentity({ cycles: this.#completedCycles });
  }

  compareReplay(candidate: WorkflowContextReplayIdentity): WorkflowContextReplayComparison {
    const baseline = this.replayIdentity();
    validateReplayIdentity(candidate);
    return compareWorkflowReplay(baseline, candidate);
  }

  get resumeAction(): WorkflowResumeAction {
    switch (this.#phase) {
      case "new": case "observation_recorded": return "create_context_plan";
      case "plan_created": return "compile_context_bundle";
      case "target_bundle_loaded": return "compile_context_delta";
      case "delta_compiled": return "apply_context_delta";
      case "bundle_ready":
        if (this.#modelResultDigest === undefined) return "materialize_context_bundle";
        return this.#effect === undefined ? "checkpoint" : "revalidate_context_bundle";
      case "materialized": return "begin_model_invocation";
      case "model_invocation_pending": return "resume_model_invocation";
      case "model_result_recorded": return "prepare_effect_or_ingest_observation";
      case "effect_prepared": return "ingest_observation";
      case "effect_authorization_revalidated": return "authorize_effect_or_checkpoint";
      case "effect_authorized": return "revalidate_context_bundle";
      case "effect_revalidated": return "dispatch_effect";
      case "effect_dispatching": return "observe_effect";
      case "effect_ambiguous": return "reconcile_effect";
      case "effect_settled": return "checkpoint";
      case "checkpointed": return "materialize_or_finish";
      case "finished": return "replay";
      case "replay_verified": case "quarantined": return "complete";
    }
  }

  toString(): string {
    return `WorkflowContextSession(phase=${this.#phase}, completedTurns=${this.#completedTurns}, `
      + `deltaChainLength=${this.#deltaChainLength}, hasActiveContext=${this.#activeContext !== undefined}, `
      + `hasPendingContext=${this.#pendingContext !== undefined}, hasPendingDelta=${this.#pendingDelta !== undefined}, `
      + `hasSelectedDelta=${this.#selectedDelta !== undefined}, hasInvocation=${this.#invocation !== undefined}, `
      + `hasProviderIdempotencyKey=${this.#invocation !== undefined}, `
      + `hasModelResult=${this.#modelResultDigest !== undefined}, `
      + `hasObservation=${this.#observationDigest !== undefined}, effectState=${this.#effect?.state ?? "none"}, `
      + `completedCycleCount=${this.#completedCycles.length}, `
      + `quarantineReason=${this.#quarantineReason ?? "none"})`;
  }

  recordPlanCreated(planId: string, bundleId: string, contractDigest: string): void {
    this.#requirePhase("new", "observation_recorded");
    record(planId); digest(bundleId); digest(contractDigest);
    this.#pendingContext = { planId, bundleId, contractDigest };
    this.#pendingDelta = undefined;
    this.#phase = "plan_created";
  }

  recordBundleCompiled(bundleId: string, contractDigest: string): void {
    this.#requirePhase("plan_created");
    digest(bundleId); digest(contractDigest);
    const pending = this.#pendingContext;
    if (pending === undefined) fail("invalid_transition");
    if (pending.bundleId !== bundleId || pending.contractDigest !== contractDigest) fail("identity_mismatch");
    if (this.#activeContext === undefined || this.#activeContext.bundleId === bundleId) {
      this.#activeContext = pending;
      this.#pendingContext = undefined;
      this.#selectedDelta = undefined;
      if (this.#deltaChainLength >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH) this.#deltaChainLength = 0;
      this.#phase = "bundle_ready";
    } else if (this.#deltaChainLength >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH) {
      this.#activeContext = pending;
      this.#pendingContext = undefined;
      this.#selectedDelta = undefined;
      this.#deltaChainLength = 0;
      this.#phase = "bundle_ready";
    } else {
      this.#phase = "target_bundle_loaded";
    }
  }

  recordDeltaCompiled(baseBundleId: string, targetBundleId: string, deltaDigest: string): void {
    this.#requirePhase("target_bundle_loaded");
    if (this.#deltaChainLength >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH) fail("limit_exceeded");
    digest(baseBundleId); digest(targetBundleId); digest(deltaDigest);
    if (this.#activeContext === undefined || this.#pendingContext === undefined) fail("invalid_transition");
    if (this.#activeContext.bundleId !== baseBundleId || this.#pendingContext.bundleId !== targetBundleId) {
      fail("identity_mismatch");
    }
    this.#pendingDelta = { baseBundleId, targetBundleId, deltaDigest };
    this.#phase = "delta_compiled";
  }

  recordDeltaApplied(baseBundleId: string, targetBundleId: string, deltaDigest: string): void {
    this.#requirePhase("delta_compiled");
    digest(baseBundleId); digest(targetBundleId); digest(deltaDigest);
    const pending = this.#pendingDelta;
    if (pending === undefined) fail("invalid_transition");
    if (pending.baseBundleId !== baseBundleId || pending.targetBundleId !== targetBundleId
      || pending.deltaDigest !== deltaDigest) fail("identity_mismatch");
    if (this.#deltaChainLength >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH) fail("limit_exceeded");
    this.#deltaChainLength += 1;
    this.#selectedDelta = pending;
    this.#activeContext = this.#pendingContext;
    this.#pendingContext = undefined;
    this.#pendingDelta = undefined;
    this.#phase = "bundle_ready";
  }

  recordMaterialized(
    bundleId: string,
    tokenizerFingerprint: string,
    materializerFingerprint: string,
    physicalInputTokens: number,
  ): void {
    this.#requirePhase("bundle_ready", "checkpointed");
    digest(bundleId); digest(tokenizerFingerprint); digest(materializerFingerprint);
    if (this.#modelResultDigest !== undefined || !positiveInteger(physicalInputTokens, 0xffff_ffff)) {
      fail("invalid_event");
    }
    if (this.activeBundleId !== bundleId) fail("identity_mismatch");
    this.#materialization = {
      bundleId, tokenizerFingerprint, materializerFingerprint, physicalInputTokens,
    };
    this.#phase = "materialized";
  }

  beginModelInvocation(invocationId: string, requestDigest: string, idempotencyKeyDigest: string): void {
    this.#requirePhase("materialized");
    record(invocationId); digest(requestDigest); digest(idempotencyKeyDigest);
    this.#invocation = { invocationId, requestDigest, idempotencyKeyDigest };
    this.#phase = "model_invocation_pending";
  }

  recordModelResult(invocationId: string, resultDigest: string): void {
    this.#requirePhase("model_invocation_pending");
    record(invocationId); digest(resultDigest);
    if (this.#invocation?.invocationId !== invocationId) fail("identity_mismatch");
    this.#modelResultDigest = resultDigest;
    this.#phase = "model_result_recorded";
  }

  recordEffectPrepared(
    effectId: string,
    intentDigest: string,
    effectVersion: bigint,
    state: WorkflowEffectState = "prepared",
    attemptCount = 0,
    reconciliationCount = 0,
  ): void {
    this.#requirePhase("model_result_recorded");
    record(effectId); digest(intentDigest); positiveBigint(effectVersion);
    if (this.#effect !== undefined || state !== "prepared" || !count(attemptCount)
      || !count(reconciliationCount) || attemptCount !== 0 || reconciliationCount !== 0) fail("invalid_event");
    this.#effect = { effectId, intentDigest, effectVersion, state, attemptCount, reconciliationCount };
    this.#phase = "effect_prepared";
  }

  recordObservation(publicationDigest: string, revision: bigint): void {
    this.#requirePhase("model_result_recorded", "effect_prepared");
    digest(publicationDigest); positiveBigint(revision);
    this.#observationDigest = publicationDigest;
    this.#observationRevision = revision;
    this.#phase = "observation_recorded";
  }

  recordEffectAuthorized(
    effectId: string,
    intentDigest: string,
    effectVersion: bigint,
    state: WorkflowEffectState = "authorized",
    attemptCount = 0,
    reconciliationCount = 0,
  ): void {
    this.#requirePhase("effect_authorization_revalidated");
    if (this.#modelResultDigest === undefined || state !== "authorized") fail("invalid_event");
    if (this.#effect === undefined || attemptCount !== this.#effect.attemptCount
      || reconciliationCount !== this.#effect.reconciliationCount) fail("invalid_event");
    this.#updateEffect(effectId, intentDigest, effectVersion, state, attemptCount, reconciliationCount, true);
    this.#phase = "effect_authorized";
  }

  recordEffectRevalidated(bundleId: string, valid: boolean): void {
    const beforeAuthorization = this.#phase === "bundle_ready"
      && this.#modelResultDigest !== undefined && this.#effect?.state === "prepared";
    if (!beforeAuthorization && this.#phase !== "effect_authorized") fail("invalid_transition");
    digest(bundleId);
    if (typeof valid !== "boolean") fail("invalid_event");
    if (this.activeBundleId !== bundleId) fail("identity_mismatch");
    if (!valid) {
      this.#enterQuarantine("invalidated");
    } else {
      this.#phase = beforeAuthorization ? "effect_authorization_revalidated" : "effect_revalidated";
    }
  }

  quarantineContext(bundleId: string, reason: WorkflowQuarantineReason): void {
    digest(bundleId);
    if (!(WORKFLOW_QUARANTINE_REASONS as readonly string[]).includes(reason)) fail("invalid_event");
    if (["new", "finished", "replay_verified", "quarantined"].includes(this.#phase)) {
      fail("invalid_transition");
    }
    if (this.activeBundleId !== bundleId) fail("identity_mismatch");
    this.#enterQuarantine(reason);
  }

  recordEffectDispatched(
    effectId: string,
    intentDigest: string,
    effectVersion: bigint,
    state: WorkflowEffectState,
    attemptCount: number,
    reconciliationCount: number,
  ): void {
    this.#requirePhase("effect_revalidated");
    if (state !== "dispatching" && state !== "unknown" && !TERMINAL_EFFECT_STATES.has(state)) {
      fail("invalid_event");
    }
    if (this.#effect === undefined || attemptCount !== this.#effect.attemptCount + 1
      || reconciliationCount !== this.#effect.reconciliationCount) fail("invalid_event");
    this.#updateEffect(effectId, intentDigest, effectVersion, state, attemptCount, reconciliationCount, true);
    this.#phase = effectPhase(state);
  }

  recordEffectObserved(
    effectId: string,
    intentDigest: string,
    effectVersion: bigint,
    state: WorkflowEffectState,
    attemptCount: number,
    reconciliationCount: number,
  ): void {
    const allowed = this.#phase === "effect_dispatching"
      ? state === "dispatching" || state === "unknown" || TERMINAL_EFFECT_STATES.has(state)
      : this.#phase === "effect_ambiguous"
        && (state === "unknown" || state === "authorized_for_retry" || TERMINAL_EFFECT_STATES.has(state));
    if (!allowed) fail("invalid_transition");
    if (this.#effect === undefined || attemptCount < this.#effect.attemptCount
      || reconciliationCount < this.#effect.reconciliationCount
      || state === "authorized_for_retry" && (attemptCount !== this.#effect.attemptCount
        || reconciliationCount <= this.#effect.reconciliationCount)) fail("invalid_event");
    this.#updateEffect(effectId, intentDigest, effectVersion, state, attemptCount, reconciliationCount, false);
    this.#phase = effectPhase(state);
  }

  checkpointCycle(): void {
    const effectComplete = this.#effect === undefined
      ? this.#phase === "bundle_ready"
      : this.#phase === "effect_settled" && TERMINAL_EFFECT_STATES.has(this.#effect.state);
    if (!effectComplete || this.#modelResultDigest === undefined || this.#observationDigest === undefined) {
      fail("invalid_transition");
    }
    if (this.#completedCycles.length >= MAX_WORKFLOW_REPLAY_CYCLES || this.#completedTurns >= 0xffff_ffff) {
      fail("limit_exceeded");
    }
    const selected = this.#activeContext;
    const materialization = this.#materialization;
    const invocation = this.#invocation;
    const outcomeRevision = this.#observationRevision;
    if (selected === undefined || materialization === undefined || invocation === undefined
      || outcomeRevision === undefined) fail("invalid_transition");
    this.#completedCycles.push({
      planId: selected.planId,
      bundleId: selected.bundleId,
      contractDigest: selected.contractDigest,
      ...(this.#selectedDelta === undefined ? {} : { selectedDelta: { ...this.#selectedDelta } }),
      materializedBundleId: materialization.bundleId,
      tokenizerFingerprint: materialization.tokenizerFingerprint,
      materializerFingerprint: materialization.materializerFingerprint,
      physicalInputTokens: materialization.physicalInputTokens,
      invocationId: invocation.invocationId,
      requestDigest: invocation.requestDigest,
      idempotencyKeyDigest: invocation.idempotencyKeyDigest,
      modelResultDigest: this.#modelResultDigest,
      ...(this.#effect === undefined ? {} : { effect: { ...this.#effect } }),
      outcomeDigest: this.#observationDigest,
      outcomeRevision,
    });
    this.#completedTurns += 1;
    this.#pendingContext = undefined;
    this.#pendingDelta = undefined;
    this.#selectedDelta = undefined;
    this.#materialization = undefined;
    this.#invocation = undefined;
    this.#modelResultDigest = undefined;
    this.#observationDigest = undefined;
    this.#observationRevision = undefined;
    this.#effect = undefined;
    this.#phase = "checkpointed";
  }

  finish(): void {
    this.#requirePhase("checkpointed");
    if (this.#completedTurns === 0) fail("invalid_transition");
    this.#phase = "finished";
  }

  recordReplayVerified(
    decisionId: string,
    executionId: string,
    candidate: WorkflowContextReplayIdentity,
  ): WorkflowContextReplayComparison {
    this.#requirePhase("finished");
    digest(decisionId); record(executionId);
    const comparison = this.compareReplay(candidate);
    if (!comparison.exactMatch) fail("identity_mismatch");
    this.#replayVerified = true;
    this.#phase = "replay_verified";
    return comparison;
  }

  #requirePhase(...allowed: readonly WorkflowContextPhase[]): void {
    if (!allowed.includes(this.#phase)) fail("invalid_transition");
  }

  #updateEffect(
    effectId: string,
    intentDigest: string,
    effectVersion: bigint,
    state: WorkflowEffectState,
    attemptCount: number,
    reconciliationCount: number,
    requireNewVersion: boolean,
  ): void {
    record(effectId); digest(intentDigest); positiveBigint(effectVersion);
    if (!count(attemptCount) || !count(reconciliationCount)
      || !effectCountsValid(state, attemptCount, reconciliationCount)) fail("invalid_event");
    const current = this.#effect;
    if (current === undefined) fail("invalid_transition");
    const versionValid = effectVersion > current.effectVersion
      || (!requireNewVersion && effectVersion === current.effectVersion && state === current.state);
    if (effectId !== current.effectId || intentDigest !== current.intentDigest || !versionValid) {
      fail("identity_mismatch");
    }
    this.#effect = { effectId, intentDigest, effectVersion, state, attemptCount, reconciliationCount };
  }

  #enterQuarantine(reason: WorkflowQuarantineReason): void {
    this.#pendingContext = undefined;
    this.#pendingDelta = undefined;
    this.#selectedDelta = undefined;
    this.#materialization = undefined;
    this.#invocation = undefined;
    this.#modelResultDigest = undefined;
    this.#observationDigest = undefined;
    this.#observationRevision = undefined;
    this.#effect = undefined;
    this.#replayVerified = false;
    this.#quarantineReason = reason;
    this.#phase = "quarantined";
  }
}

function cloneReplayIdentity(identity: WorkflowContextReplayIdentity): WorkflowContextReplayIdentity {
  return {
    cycles: identity.cycles.map((cycle) => ({
      ...cycle,
      ...(cycle.selectedDelta === undefined ? {} : { selectedDelta: { ...cycle.selectedDelta } }),
      ...(cycle.effect === undefined ? {} : { effect: { ...cycle.effect } }),
    })),
  };
}

function validateReplayIdentity(identity: WorkflowContextReplayIdentity): void {
  if (typeof identity !== "object" || identity === null || !Array.isArray(identity.cycles)
    || identity.cycles.length === 0 || identity.cycles.length > MAX_WORKFLOW_REPLAY_CYCLES) {
    fail("invalid_event");
  }
  for (const cycle of identity.cycles) {
    record(cycle.planId); digest(cycle.bundleId); digest(cycle.contractDigest);
    digest(cycle.materializedBundleId); digest(cycle.tokenizerFingerprint);
    digest(cycle.materializerFingerprint); record(cycle.invocationId); digest(cycle.requestDigest);
    digest(cycle.idempotencyKeyDigest); digest(cycle.modelResultDigest); digest(cycle.outcomeDigest);
    if (!positiveInteger(cycle.physicalInputTokens, 0xffff_ffff)) fail("invalid_event");
    positiveBigint(cycle.outcomeRevision);
    if (cycle.selectedDelta !== undefined) {
      digest(cycle.selectedDelta.baseBundleId); digest(cycle.selectedDelta.targetBundleId);
      digest(cycle.selectedDelta.deltaDigest);
      if (cycle.selectedDelta.targetBundleId !== cycle.bundleId
        || cycle.selectedDelta.baseBundleId !== cycle.materializedBundleId
        || cycle.selectedDelta.baseBundleId === cycle.selectedDelta.targetBundleId) {
        fail("identity_mismatch");
      }
    }
    if (cycle.effect !== undefined) {
      record(cycle.effect.effectId); digest(cycle.effect.intentDigest);
      positiveBigint(cycle.effect.effectVersion);
      if (!TERMINAL_EFFECT_STATES.has(cycle.effect.state) || !count(cycle.effect.attemptCount)
        || !count(cycle.effect.reconciliationCount)
        || !effectCountsValid(
          cycle.effect.state, cycle.effect.attemptCount, cycle.effect.reconciliationCount,
        )) fail("invalid_event");
    }
  }
}

function compareWorkflowReplay(
  baseline: WorkflowContextReplayIdentity,
  candidate: WorkflowContextReplayIdentity,
): WorkflowContextReplayComparison {
  const sameLength = baseline.cycles.length === candidate.cycles.length;
  const pairs = baseline.cycles.map((cycle, index) => [cycle, candidate.cycles[index]!] as const);
  const bundleDeltaSelection = comparisonStatus(sameLength && pairs.every(([left, right]) =>
    left.planId === right.planId && left.bundleId === right.bundleId
    && left.contractDigest === right.contractDigest && equalDelta(left.selectedDelta, right.selectedDelta)));
  const materialization = comparisonStatus(sameLength && pairs.every(([left, right]) =>
    left.materializedBundleId === right.materializedBundleId
    && left.tokenizerFingerprint === right.tokenizerFingerprint
    && left.materializerFingerprint === right.materializerFingerprint
    && left.physicalInputTokens === right.physicalInputTokens));
  const modelResultIdentity = comparisonStatus(sameLength && pairs.every(([left, right]) =>
    left.invocationId === right.invocationId && left.requestDigest === right.requestDigest
    && left.idempotencyKeyDigest === right.idempotencyKeyDigest
    && left.modelResultDigest === right.modelResultDigest));
  const toolEffectDecisions = comparisonStatus(sameLength && pairs.every(([left, right]) =>
    equalEffect(left.effect, right.effect)));
  const outcome = comparisonStatus(sameLength && pairs.every(([left, right]) =>
    left.outcomeDigest === right.outcomeDigest && left.outcomeRevision === right.outcomeRevision));
  return {
    bundleDeltaSelection,
    materialization,
    modelResultIdentity,
    toolEffectDecisions,
    outcome,
    exactMatch: [bundleDeltaSelection, materialization, modelResultIdentity, toolEffectDecisions, outcome]
      .every((status) => status === "equal"),
  };
}

function comparisonStatus(equal: boolean): WorkflowReplayDiffStatus {
  return equal ? "equal" : "different";
}

function equalDelta(
  left: WorkflowDeltaReplayIdentity | undefined,
  right: WorkflowDeltaReplayIdentity | undefined,
): boolean {
  return left === undefined || right === undefined
    ? left === right
    : left.baseBundleId === right.baseBundleId && left.targetBundleId === right.targetBundleId
      && left.deltaDigest === right.deltaDigest;
}

function equalEffect(
  left: WorkflowEffectReplayIdentity | undefined,
  right: WorkflowEffectReplayIdentity | undefined,
): boolean {
  return left === undefined || right === undefined
    ? left === right
    : left.effectId === right.effectId && left.intentDigest === right.intentDigest
      && left.effectVersion === right.effectVersion && left.state === right.state
      && left.attemptCount === right.attemptCount && left.reconciliationCount === right.reconciliationCount;
}

function fail(code: WorkflowSessionErrorCode): never { throw new WorkflowSessionError(code); }
function digest(value: string): void { if (!DIGEST.test(value)) fail("invalid_event"); }
function record(value: string): void { if (!UUID_V7.test(value)) fail("invalid_event"); }
function positiveBigint(value: bigint): void {
  if (typeof value !== "bigint" || value <= 0n || value > 0xffff_ffff_ffff_ffffn) fail("invalid_event");
}
function positiveInteger(value: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= maximum;
}
function count(value: number): boolean { return Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff; }
function effectCountsValid(state: WorkflowEffectState, attempts: number, reconciliations: number): boolean {
  if (reconciliations !== 0 && attempts === 0) return false;
  if (["prepared", "authorized", "rejected"].includes(state)) {
    return attempts === 0 && reconciliations === 0;
  }
  if ([
    "dispatching", "succeeded", "failed", "unknown", "compensated", "compensation_failed",
  ].includes(state)) return attempts !== 0;
  if (state === "authorized_for_retry" || state === "manual_resolution") {
    return attempts !== 0 && reconciliations !== 0;
  }
  return state === "expired" || state === "cancelled";
}
function effectPhase(state: WorkflowEffectState): WorkflowContextPhase {
  if (state === "dispatching") return "effect_dispatching";
  if (state === "unknown") return "effect_ambiguous";
  if (state === "authorized_for_retry") return "effect_authorized";
  if (TERMINAL_EFFECT_STATES.has(state)) return "effect_settled";
  return fail("invalid_event");
}
