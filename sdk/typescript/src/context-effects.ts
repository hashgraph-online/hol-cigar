/** Opt-in bridge to existing CIGAR effects. Does not discover services, approve or retry. */
import type { LocalContextBroker } from "./broker.js";
import type { LocalBrokerExecutionBinding, LocalBrokerExecutionHandoff, LocalBrokerExecutionReview } from "./broker-types.js";
import { CigarError, ValidationError } from "./errors.js";
import { EffectIdRequest, EffectStatusResponse } from "./generated/models.js";
import { validateIdempotencyKey } from "./idempotency.js";
import type { CallOptions, TypedOperationRequest, TypedOperationResponse } from "./types.js";

const FIELDS = ["schema", "id", "epoch", "ticket", "submission_id", "context_id", "snapshot_id",
  "source_authority_digest", "review_digest", "effect_id", "intent_digest"] as const;
const READY = new Set(["authorized", "authorized_for_retry"]);
const NOT_DISPATCHED = new Set(["prepared", "pending_approval", "authorized"]);

/** The two existing generated operations used here. CigarClient implements this port. */
export interface ContextEffectClient {
  getEffectStatus(request: TypedOperationRequest<EffectIdRequest>, options?: CallOptions): Promise<TypedOperationResponse<EffectStatusResponse>>;
  dispatchEffect(request: TypedOperationRequest<EffectIdRequest>, options?: CallOptions): Promise<TypedOperationResponse<EffectStatusResponse>>;
}

/** A consumed context check and authority response; the response may still be dispatching. */
export class ContextEffectDispatch {
  readonly #handoff: LocalBrokerExecutionHandoff;
  readonly #response: TypedOperationResponse<EffectStatusResponse>;
  constructor(handoff: LocalBrokerExecutionHandoff, response: TypedOperationResponse<EffectStatusResponse>) {
    this.#handoff = structuredClone(handoff);
    this.#response = structuredClone(response);
  }
  get handoff(): LocalBrokerExecutionHandoff { return structuredClone(this.#handoff); }
  get response(): TypedOperationResponse<EffectStatusResponse> { return structuredClone(this.#response); }
  toString(): string { return `ContextEffectDispatch(state=${this.#response.payload.state})`; }
}

/** No valid dispatch response after consumption. Observe/reconcile the same effect, never blindly resend. */
export class ContextEffectDispatchUncertain extends CigarError {
  readonly #handoff: LocalBrokerExecutionHandoff;
  constructor(handoff: LocalBrokerExecutionHandoff) {
    super("context effect dispatch outcome is uncertain; observe the existing effect");
    this.#handoff = structuredClone(handoff);
  }
  get handoff(): LocalBrokerExecutionHandoff { return structuredClone(this.#handoff); }
}

function status(response: TypedOperationResponse<EffectStatusResponse>, operation: string,
  binding: LocalBrokerExecutionBinding): Readonly<EffectStatusResponse> {
  const value = EffectStatusResponse.create(response.payload);
  if (response.operationId !== operation || value.effect_id !== binding.effect_id || value.intent_digest !== binding.intent_digest
    || value.effect_version < 0n || value.effect_version >= 1n << 64n
    || value.attempt_count < 0 || value.attempt_count >= 2 ** 32
    || value.reconciliation_count < 0 || value.reconciliation_count >= 2 ** 32) {
    throw new ValidationError("effect response does not match the bound intent");
  }
  return value;
}

/**
 * Read the current effect, resolve current host review, consume context, then dispatch once.
 * Each HTTP leg has its own bounded timeout; the broker and host resolver keep their deadlines.
 * Context is checked at handoff time, without locking a remote worker's later execution.
 * Honey remains responsible for current authorization, exact version and intent preconditions.
 */
export async function dispatchContextEffect(
  broker: LocalContextBroker,
  client: ContextEffectClient,
  binding: LocalBrokerExecutionBinding,
  resolveReview: () => LocalBrokerExecutionReview | Promise<LocalBrokerExecutionReview>,
  options: Readonly<{idempotencyKey: string; timeoutMs?: number}>,
): Promise<ContextEffectDispatch> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (typeof binding !== "object" || binding === null || Array.isArray(binding)
    || Object.keys(binding).length !== FIELDS.length
    || FIELDS.some(key => !Object.hasOwn(binding, key) || typeof binding[key] !== "string" || Buffer.byteLength(binding[key]) > 256)
    || binding.schema !== "cigar.context-execution-binding.v1" || !/^1220[0-9a-f]{64}$/u.test(binding.intent_digest)
    || typeof resolveReview !== "function" || typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs)
    || timeoutMs <= 0 || timeoutMs > 300_000 || typeof options.idempotencyKey !== "string") {
    throw new ValidationError("invalid context effect dispatch input");
  }
  const exact = structuredClone(binding);
  const payload = EffectIdRequest.create({effect_id: exact.effect_id});
  const idempotencyKey = validateIdempotencyKey(options.idempotencyKey);
  const callOptions: CallOptions = {timeoutMs, maxAttempts: 1};
  const before = status(await client.getEffectStatus({payload}, callOptions), "getEffectStatus", exact);
  if (!READY.has(before.state) || before.effect_version === (1n << 64n) - 1n) {
    throw new ValidationError("bound effect is not dispatchable");
  }

  // Caller mutations across either await cannot retarget the checked intent. Resolve the trusted
  // review after the remote read; no callback or extra read occurs between take and dispatch.
  const handoff = await broker.takeExecutionHandoff(exact, await resolveReview());
  try {
    if (FIELDS.some(key => handoff.binding[key] !== exact[key])
      || handoff.checked.context_id !== exact.context_id || handoff.checked.assessment.snapshot_id !== exact.snapshot_id
      || handoff.checked.assessment.decision !== "release") {
      throw new ValidationError("context handoff does not match the bound intent");
    }
    const response = await client.dispatchEffect({payload, idempotencyKey, expectedRevision: before.effect_version.toString()}, callOptions);
    const after = status(response, "dispatchEffect", exact);
    if (after.effect_version <= before.effect_version || after.attempt_count < before.attempt_count
      || after.reconciliation_count < before.reconciliation_count || NOT_DISPATCHED.has(after.state)) {
      throw new ValidationError("effect dispatch did not return a valid advancement");
    }
    return new ContextEffectDispatch(handoff, response);
  } catch {
    // No retry and no leaked remote error content. The consumed identity must be reconciled.
    throw new ContextEffectDispatchUncertain(handoff);
  }
}
