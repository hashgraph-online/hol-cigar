import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  MAX_WORKFLOW_DELTA_CHAIN_LENGTH,
  MAX_WORKFLOW_REPLAY_CYCLES,
  WORKFLOW_CONTEXT_PHASES,
  WORKFLOW_QUARANTINE_REASONS,
  WORKFLOW_RESUME_ACTIONS,
  WORKFLOW_SESSION_ERROR_CODES,
  WORKFLOW_SESSION_EVENT_NAMES,
  WorkflowContextSession,
  WorkflowSessionError,
  workflowOperationId,
} from "../index.js";

const digests = Object.fromEntries(
  [..."0123456789abcdef"].map((character) => [character, `1220${character.repeat(64)}`]),
) as Readonly<Record<string, string>>;
const digest = (character: string): string => digests[character]!;
const record = (suffix: number): string => `01890f47-8e7d-7b42-a1d2-3c4d5e6f78${suffix.toString(16).padStart(2, "0")}`;

function initialCycle(session: WorkflowContextSession): void {
  session.recordPlanCreated(record(1), digest("a"), digest("1"));
  session.recordBundleCompiled(digest("a"), digest("1"));
  session.recordMaterialized(digest("a"), digest("2"), digest("3"), 10);
  session.beginModelInvocation(record(2), digest("4"), digest("8"));
  session.recordModelResult(record(2), digest("5"));
}

function advanceTarget(session: WorkflowContextSession): void {
  session.recordObservation(digest("6"), 1n);
  session.recordPlanCreated(record(3), digest("b"), digest("7"));
  session.recordBundleCompiled(digest("b"), digest("7"));
  session.recordDeltaCompiled(digest("a"), digest("b"), digest("8"));
  session.recordDeltaApplied(digest("a"), digest("b"), digest("8"));
}

test("shared workflow contract inventory is exact", () => {
  const contract = JSON.parse(
    readFileSync(new URL("../../../workflow-context-session.v1.json", import.meta.url), "utf8"),
  ) as {
    schema_version: string;
    maximum_delta_chain_length: number;
    maximum_replay_cycles: number;
    phases: string[];
    error_codes: string[];
    resume_actions: { action: string; operation_id: string | null }[];
    events: string[];
    quarantine_reasons: string[];
    retry_fences: {
      provider_invocation: string;
      effect_retry: string;
    };
    replay_comparison_dimensions: string[];
    replay_verification: string;
    telemetry: {
      maximum_added_series: number;
      label_policy: string;
      families: string[];
    };
  };
  assert.equal(contract.schema_version, "cigar.sdk-workflow-context-session.v1");
  assert.equal(contract.maximum_delta_chain_length, MAX_WORKFLOW_DELTA_CHAIN_LENGTH);
  assert.equal(contract.maximum_replay_cycles, MAX_WORKFLOW_REPLAY_CYCLES);
  assert.deepEqual(contract.phases, WORKFLOW_CONTEXT_PHASES);
  assert.deepEqual(contract.error_codes, WORKFLOW_SESSION_ERROR_CODES);
  assert.deepEqual(contract.resume_actions, WORKFLOW_RESUME_ACTIONS.map((action) => ({
    action,
    operation_id: workflowOperationId(action),
  })));
  assert.deepEqual(contract.events, WORKFLOW_SESSION_EVENT_NAMES);
  assert.deepEqual(contract.quarantine_reasons, WORKFLOW_QUARANTINE_REASONS);
  assert.deepEqual(contract.retry_fences, {
    provider_invocation: "durable_invocation_and_idempotency_key_digest_required_before_call",
    effect_retry: "durable_reconciliation_count_must_advance_before_authorized_for_retry",
  });
  assert.deepEqual(contract.replay_comparison_dimensions, [
    "bundle_delta_selection",
    "materialization",
    "model_result_identity",
    "tool_effect_decisions",
    "outcome",
  ]);
  assert.equal(contract.replay_verification, "all_exact_identity_dimensions_must_equal");
  assert.deepEqual(contract.telemetry, {
    maximum_added_series: 17,
    label_policy: "single_closed_static_dimension_no_identifiers_or_content",
    families: [
      "cigar_workflow_context_cycles_total",
      "cigar_workflow_context_selections_total",
      "cigar_workflow_context_delta_blocks_total",
      "cigar_workflow_context_recoveries_total",
      "cigar_workflow_context_replay_dimensions_total",
      "cigar_workflow_context_replay_verifications_total",
    ],
  });
});

test("no-effect cycle reaches verified replay", () => {
  const session = new WorkflowContextSession();
  initialCycle(session);
  advanceTarget(session);
  assert.equal(session.activeBundleId, digest("b"));
  assert.equal(session.deltaChainLength, 1);
  assert.equal(session.resumeAction, "checkpoint");
  session.checkpointCycle();
  session.finish();
  const baseline = session.replayIdentity();
  const exact = session.compareReplay(baseline);
  assert.equal(exact.exactMatch, true);
  const incoherent = {
    cycles: baseline.cycles.map((cycle, index) => index === 0
      ? { ...cycle, selectedDelta: { ...cycle.selectedDelta!, baseBundleId: digest("c") } }
      : cycle),
  };
  assert.throws(
    () => session.compareReplay(incoherent),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "identity_mismatch",
  );
  const impossibleEffect = {
    cycles: baseline.cycles.map((cycle, index) => index === 0 ? {
      ...cycle,
      effect: {
        effectId: record(8), intentDigest: digest("9"), effectVersion: 3n,
        state: "succeeded" as const, attemptCount: 0, reconciliationCount: 0,
      },
    } : cycle),
  };
  assert.throws(
    () => session.compareReplay(impossibleEffect),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "invalid_event",
  );
  const changed = {
    cycles: baseline.cycles.map((cycle, index) =>
      index === 0 ? { ...cycle, outcomeDigest: digest("d") } : cycle),
  };
  const comparison = session.compareReplay(changed);
  assert.equal(comparison.outcome, "different");
  assert.equal(comparison.bundleDeltaSelection, "equal");
  assert.throws(
    () => session.recordReplayVerified(digest("c"), record(4), changed),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "identity_mismatch",
  );
  assert.equal(session.phase, "finished");
  session.recordReplayVerified(digest("c"), record(4), baseline);
  assert.equal(session.completedTurns, 1);
  assert.equal(session.phase, "replay_verified");
  assert.equal(session.resumeAction, "complete");
});

test("delta chain bound forces a full-bundle checkpoint", () => {
  const session = new WorkflowContextSession();
  initialCycle(session);
  let base = "a";
  [..."bcdef123"].forEach((target, index) => {
    session.recordObservation(digest("6"), BigInt(index + 1));
    session.recordPlanCreated(record(index + 3), digest(target), digest("7"));
    session.recordBundleCompiled(digest(target), digest("7"));
    session.recordDeltaCompiled(digest(base), digest(target), digest("8"));
    session.recordDeltaApplied(digest(base), digest(target), digest("8"));
    base = target;
    if (index + 1 < MAX_WORKFLOW_DELTA_CHAIN_LENGTH) {
      session.checkpointCycle();
      session.recordMaterialized(digest(base), digest("2"), digest("3"), 10);
      session.beginModelInvocation(record(index + 20), digest("4"), digest("8"));
      session.recordModelResult(record(index + 20), digest("5"));
    }
  });
  assert.equal(session.deltaChainLength, MAX_WORKFLOW_DELTA_CHAIN_LENGTH);

  session.checkpointCycle();
  session.recordMaterialized(digest(base), digest("2"), digest("3"), 10);
  session.beginModelInvocation(record(40), digest("4"), digest("8"));
  session.recordModelResult(record(40), digest("5"));
  session.recordObservation(digest("6"), 9n);
  session.recordPlanCreated(record(41), digest("4"), digest("7"));
  session.recordBundleCompiled(digest("4"), digest("7"));
  assert.equal(session.phase, "bundle_ready");
  assert.equal(session.activeBundleId, digest("4"));
  assert.equal(session.deltaChainLength, 0);
  assert.equal(session.resumeAction, "checkpoint");
});

test("ambiguous effect retry requires another revalidation", () => {
  const session = new WorkflowContextSession();
  const effectId = record(8);
  initialCycle(session);
  session.recordEffectPrepared(effectId, digest("9"), 1n);
  advanceTarget(session);
  assert.equal(session.resumeAction, "revalidate_context_bundle");
  session.recordEffectRevalidated(digest("b"), true);
  assert.equal(session.phase, "effect_authorization_revalidated");
  session.recordEffectAuthorized(effectId, digest("9"), 2n);
  session.recordEffectRevalidated(digest("b"), true);
  session.recordEffectDispatched(effectId, digest("9"), 3n, "unknown", 1, 0);
  assert.throws(
    () => session.recordEffectObserved(effectId, digest("9"), 4n, "authorized_for_retry", 1, 0),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "invalid_event",
  );
  session.recordEffectObserved(effectId, digest("9"), 4n, "authorized_for_retry", 1, 1);
  assert.throws(
    () => session.recordEffectDispatched(effectId, digest("9"), 5n, "succeeded", 2, 1),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "invalid_transition",
  );
  assert.equal(session.phase, "effect_authorized");
  session.recordEffectRevalidated(digest("b"), true);
  session.recordEffectDispatched(effectId, digest("9"), 5n, "succeeded", 2, 1);
  session.checkpointCycle();
});

test("cancellation quarantines a late provider result", () => {
  const session = new WorkflowContextSession();
  session.recordPlanCreated(record(1), digest("a"), digest("1"));
  session.recordBundleCompiled(digest("a"), digest("1"));
  session.recordMaterialized(digest("a"), digest("2"), digest("3"), 10);
  session.beginModelInvocation(record(2), digest("4"), digest("8"));
  session.quarantineContext(digest("a"), "cancelled");
  assert.throws(
    () => session.recordModelResult(record(2), digest("5")),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "invalid_transition",
  );
  assert.equal(session.phase, "quarantined");
  assert.equal(session.resumeAction, "complete");
});

test("failed transition is atomic and content-free", () => {
  const session = new WorkflowContextSession();
  assert.throws(
    () => session.recordBundleCompiled(digest("a"), digest("1")),
    (error: unknown) => error instanceof WorkflowSessionError && error.code === "invalid_transition",
  );
  assert.equal(session.phase, "new");
  assert.equal(session.toString().includes(digest("a")), false);
});
