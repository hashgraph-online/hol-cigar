"""Identity-only state tracking for deterministic workflow context cycles."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Never

from cigar_sdk.errors import CigarError

_DIGEST: Final = re.compile(r"^1220[0-9a-f]{64}$")
_UUID_V7: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
MAX_WORKFLOW_DELTA_CHAIN_LENGTH: Final = 8
MAX_WORKFLOW_REPLAY_CYCLES: Final = 64
_TERMINAL_EFFECT_STATES: Final = frozenset(
    {
        "succeeded",
        "failed",
        "manual_resolution",
        "rejected",
        "expired",
        "cancelled",
        "compensated",
        "compensation_failed",
    }
)

WORKFLOW_SESSION_EVENT_NAMES: Final = (
    "plan_created",
    "bundle_compiled",
    "delta_compiled",
    "delta_applied",
    "materialized",
    "model_invocation_started",
    "model_result_recorded",
    "effect_prepared",
    "observation_recorded",
    "effect_authorized",
    "effect_revalidated",
    "effect_dispatched",
    "effect_observed",
    "cycle_checkpointed",
    "finished",
    "replay_verified",
    "context_quarantined",
)


class WorkflowContextPhase(StrEnum):
    """Closed context-cycle phase shared by all CIGAR SDKs."""

    NEW = "new"
    PLAN_CREATED = "plan_created"
    TARGET_BUNDLE_LOADED = "target_bundle_loaded"
    DELTA_COMPILED = "delta_compiled"
    BUNDLE_READY = "bundle_ready"
    MATERIALIZED = "materialized"
    MODEL_INVOCATION_PENDING = "model_invocation_pending"
    MODEL_RESULT_RECORDED = "model_result_recorded"
    EFFECT_PREPARED = "effect_prepared"
    OBSERVATION_RECORDED = "observation_recorded"
    EFFECT_AUTHORIZATION_REVALIDATED = "effect_authorization_revalidated"
    EFFECT_AUTHORIZED = "effect_authorized"
    EFFECT_REVALIDATED = "effect_revalidated"
    EFFECT_DISPATCHING = "effect_dispatching"
    EFFECT_AMBIGUOUS = "effect_ambiguous"
    EFFECT_SETTLED = "effect_settled"
    CHECKPOINTED = "checkpointed"
    FINISHED = "finished"
    REPLAY_VERIFIED = "replay_verified"
    QUARANTINED = "quarantined"


class WorkflowQuarantineReason(StrEnum):
    """Closed reason that in-flight results are no longer authoritative."""

    CANCELLED = "cancelled"
    REVOKED = "revoked"
    INVALIDATED = "invalidated"


class WorkflowResumeAction(StrEnum):
    """Exact action a recovered caller must resume."""

    CREATE_CONTEXT_PLAN = "create_context_plan"
    COMPILE_CONTEXT_BUNDLE = "compile_context_bundle"
    COMPILE_CONTEXT_DELTA = "compile_context_delta"
    APPLY_CONTEXT_DELTA = "apply_context_delta"
    MATERIALIZE_CONTEXT_BUNDLE = "materialize_context_bundle"
    BEGIN_MODEL_INVOCATION = "begin_model_invocation"
    RESUME_MODEL_INVOCATION = "resume_model_invocation"
    PREPARE_EFFECT_OR_INGEST_OBSERVATION = "prepare_effect_or_ingest_observation"
    INGEST_OBSERVATION = "ingest_observation"
    AUTHORIZE_EFFECT_OR_CHECKPOINT = "authorize_effect_or_checkpoint"
    REVALIDATE_CONTEXT_BUNDLE = "revalidate_context_bundle"
    DISPATCH_EFFECT = "dispatch_effect"
    OBSERVE_EFFECT = "observe_effect"
    RECONCILE_EFFECT = "reconcile_effect"
    CHECKPOINT = "checkpoint"
    MATERIALIZE_OR_FINISH = "materialize_or_finish"
    REPLAY = "replay"
    COMPLETE = "complete"

    @property
    def operation_id(self) -> str | None:
        """Existing v1 operation implementing this action, if it is remote."""
        return _ACTION_OPERATIONS[self]


_ACTION_OPERATIONS: Final[dict[WorkflowResumeAction, str | None]] = {
    WorkflowResumeAction.CREATE_CONTEXT_PLAN: "createContextPlan",
    WorkflowResumeAction.COMPILE_CONTEXT_BUNDLE: "compileContextBundle",
    WorkflowResumeAction.COMPILE_CONTEXT_DELTA: "compileContextDelta",
    WorkflowResumeAction.APPLY_CONTEXT_DELTA: None,
    WorkflowResumeAction.MATERIALIZE_CONTEXT_BUNDLE: "materializeContextBundle",
    WorkflowResumeAction.BEGIN_MODEL_INVOCATION: None,
    WorkflowResumeAction.RESUME_MODEL_INVOCATION: None,
    WorkflowResumeAction.PREPARE_EFFECT_OR_INGEST_OBSERVATION: None,
    WorkflowResumeAction.INGEST_OBSERVATION: "ingestCatalog",
    WorkflowResumeAction.AUTHORIZE_EFFECT_OR_CHECKPOINT: "authorizeEffect",
    WorkflowResumeAction.REVALIDATE_CONTEXT_BUNDLE: "revalidateContextBundle",
    WorkflowResumeAction.DISPATCH_EFFECT: "dispatchEffect",
    WorkflowResumeAction.OBSERVE_EFFECT: "getEffectStatus",
    WorkflowResumeAction.RECONCILE_EFFECT: "reconcileEffect",
    WorkflowResumeAction.CHECKPOINT: None,
    WorkflowResumeAction.MATERIALIZE_OR_FINISH: None,
    WorkflowResumeAction.REPLAY: "createReplay",
    WorkflowResumeAction.COMPLETE: None,
}


class WorkflowSessionErrorCode(StrEnum):
    """Stable local workflow-state failure category."""

    INVALID_TRANSITION = "invalid_transition"
    INVALID_EVENT = "invalid_event"
    IDENTITY_MISMATCH = "identity_mismatch"
    INVALIDATED = "invalidated"
    LIMIT_EXCEEDED = "limit_exceeded"


class WorkflowSessionError(CigarError):
    """Content-safe local workflow state-machine failure."""

    def __init__(self, code: WorkflowSessionErrorCode) -> None:
        super().__init__(f"workflow context transition failed: {code.value}")
        self.code = code

    def __repr__(self) -> str:
        return f"WorkflowSessionError(code={self.code.value!r})"


class WorkflowReplayDiffStatus(StrEnum):
    """Exact status for one context-cycle replay dimension."""

    EQUAL = "equal"
    DIFFERENT = "different"


@dataclass(frozen=True, slots=True)
class WorkflowDeltaReplayIdentity:
    base_bundle_id: str
    target_bundle_id: str
    delta_digest: str


@dataclass(frozen=True, slots=True)
class WorkflowEffectReplayIdentity:
    effect_id: str
    intent_digest: str
    effect_version: int
    state: str
    attempt_count: int
    reconciliation_count: int


@dataclass(frozen=True, slots=True)
class WorkflowContextCycleIdentity:
    plan_id: str
    bundle_id: str
    contract_digest: str
    selected_delta: WorkflowDeltaReplayIdentity | None
    materialized_bundle_id: str
    tokenizer_fingerprint: str
    materializer_fingerprint: str
    physical_input_tokens: int
    invocation_id: str
    request_digest: str
    idempotency_key_digest: str
    model_result_digest: str
    effect: WorkflowEffectReplayIdentity | None
    outcome_digest: str
    outcome_revision: int


@dataclass(frozen=True, slots=True)
class WorkflowContextReplayIdentity:
    cycles: tuple[WorkflowContextCycleIdentity, ...]


@dataclass(frozen=True, slots=True)
class WorkflowContextReplayComparison:
    bundle_delta_selection: WorkflowReplayDiffStatus
    materialization: WorkflowReplayDiffStatus
    model_result_identity: WorkflowReplayDiffStatus
    tool_effect_decisions: WorkflowReplayDiffStatus
    outcome: WorkflowReplayDiffStatus
    exact_match: bool


class WorkflowContextSession:
    """Copy-free, identity-only helper for one deterministic context lifecycle."""

    def __init__(self) -> None:
        self._phase = WorkflowContextPhase.NEW
        self._completed_turns = 0
        self._delta_chain_length = 0
        self._active_context: tuple[str, str, str] | None = None
        self._pending_context: tuple[str, str, str] | None = None
        self._pending_delta: tuple[str, str, str] | None = None
        self._selected_delta: tuple[str, str, str] | None = None
        self._materialization: tuple[str, str, str, int] | None = None
        self._invocation: tuple[str, str, str] | None = None
        self._model_result_digest: str | None = None
        self._observation_digest: str | None = None
        self._observation_revision: int | None = None
        self._effect: tuple[str, str, int, str, int, int] | None = None
        self._completed_cycles: list[WorkflowContextCycleIdentity] = []
        self._replay_verified = False
        self._quarantine_reason: WorkflowQuarantineReason | None = None

    def __repr__(self) -> str:
        effect_state = self._effect[3] if self._effect is not None else None
        return (
            "WorkflowContextSession("
            f"phase={self._phase.value!r}, completed_turns={self._completed_turns}, "
            f"delta_chain_length={self._delta_chain_length}, has_active_context={self._active_context is not None}, "
            f"has_pending_context={self._pending_context is not None}, "
            f"has_pending_delta={self._pending_delta is not None}, "
            f"has_selected_delta={self._selected_delta is not None}, has_invocation={self._invocation is not None}, "
            f"has_provider_idempotency_key={self._invocation is not None}, "
            f"has_model_result={self._model_result_digest is not None}, "
            f"has_observation={self._observation_digest is not None}, effect_state={effect_state!r}, "
            f"completed_cycle_count={len(self._completed_cycles)}, "
            f"quarantine_reason={self._quarantine_reason!r})"
        )

    @property
    def phase(self) -> WorkflowContextPhase:
        return self._phase

    @property
    def completed_turns(self) -> int:
        return self._completed_turns

    @property
    def delta_chain_length(self) -> int:
        return self._delta_chain_length

    @property
    def active_bundle_id(self) -> str | None:
        return self._active_context[1] if self._active_context is not None else None

    def replay_identity(self) -> WorkflowContextReplayIdentity:
        """Return the exact bounded transcript after workflow completion."""
        self._require_phase(WorkflowContextPhase.FINISHED, WorkflowContextPhase.REPLAY_VERIFIED)
        if not self._completed_cycles:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        return WorkflowContextReplayIdentity(tuple(self._completed_cycles))

    def compare_replay(self, candidate: WorkflowContextReplayIdentity) -> WorkflowContextReplayComparison:
        """Compare a candidate transcript without accepting mismatched replay state."""
        baseline = self.replay_identity()
        _validate_replay_identity(candidate)
        return _compare_workflow_replay(baseline, candidate)

    @property
    def resume_action(self) -> WorkflowResumeAction:
        if self._phase in {WorkflowContextPhase.NEW, WorkflowContextPhase.OBSERVATION_RECORDED}:
            return WorkflowResumeAction.CREATE_CONTEXT_PLAN
        if self._phase is WorkflowContextPhase.PLAN_CREATED:
            return WorkflowResumeAction.COMPILE_CONTEXT_BUNDLE
        if self._phase is WorkflowContextPhase.TARGET_BUNDLE_LOADED:
            return WorkflowResumeAction.COMPILE_CONTEXT_DELTA
        if self._phase is WorkflowContextPhase.DELTA_COMPILED:
            return WorkflowResumeAction.APPLY_CONTEXT_DELTA
        if self._phase is WorkflowContextPhase.BUNDLE_READY:
            if self._model_result_digest is None:
                return WorkflowResumeAction.MATERIALIZE_CONTEXT_BUNDLE
            return (
                WorkflowResumeAction.REVALIDATE_CONTEXT_BUNDLE
                if self._effect is not None
                else WorkflowResumeAction.CHECKPOINT
            )
        if self._phase is WorkflowContextPhase.MATERIALIZED:
            return WorkflowResumeAction.BEGIN_MODEL_INVOCATION
        if self._phase is WorkflowContextPhase.MODEL_INVOCATION_PENDING:
            return WorkflowResumeAction.RESUME_MODEL_INVOCATION
        if self._phase is WorkflowContextPhase.MODEL_RESULT_RECORDED:
            return WorkflowResumeAction.PREPARE_EFFECT_OR_INGEST_OBSERVATION
        if self._phase is WorkflowContextPhase.EFFECT_PREPARED:
            return WorkflowResumeAction.INGEST_OBSERVATION
        if self._phase is WorkflowContextPhase.EFFECT_AUTHORIZATION_REVALIDATED:
            return WorkflowResumeAction.AUTHORIZE_EFFECT_OR_CHECKPOINT
        if self._phase is WorkflowContextPhase.EFFECT_AUTHORIZED:
            return WorkflowResumeAction.REVALIDATE_CONTEXT_BUNDLE
        if self._phase is WorkflowContextPhase.EFFECT_REVALIDATED:
            return WorkflowResumeAction.DISPATCH_EFFECT
        if self._phase is WorkflowContextPhase.EFFECT_DISPATCHING:
            return WorkflowResumeAction.OBSERVE_EFFECT
        if self._phase is WorkflowContextPhase.EFFECT_AMBIGUOUS:
            return WorkflowResumeAction.RECONCILE_EFFECT
        if self._phase is WorkflowContextPhase.EFFECT_SETTLED:
            return WorkflowResumeAction.CHECKPOINT
        if self._phase is WorkflowContextPhase.CHECKPOINTED:
            return WorkflowResumeAction.MATERIALIZE_OR_FINISH
        if self._phase is WorkflowContextPhase.FINISHED:
            return WorkflowResumeAction.REPLAY
        return WorkflowResumeAction.COMPLETE

    def record_plan_created(self, plan_id: str, bundle_id: str, contract_digest: str) -> None:
        self._require_phase(WorkflowContextPhase.NEW, WorkflowContextPhase.OBSERVATION_RECORDED)
        _record(plan_id)
        _digest(bundle_id)
        _digest(contract_digest)
        self._pending_context = (plan_id, bundle_id, contract_digest)
        self._pending_delta = None
        self._phase = WorkflowContextPhase.PLAN_CREATED

    def record_bundle_compiled(self, bundle_id: str, contract_digest: str) -> None:
        self._require_phase(WorkflowContextPhase.PLAN_CREATED)
        _digest(bundle_id)
        _digest(contract_digest)
        if self._pending_context is None:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if self._pending_context[1:] != (bundle_id, contract_digest):
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        if self._active_context is None or self._active_context[1] == bundle_id:
            self._active_context = self._pending_context
            self._pending_context = None
            self._selected_delta = None
            if self._delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH:
                self._delta_chain_length = 0
            self._phase = WorkflowContextPhase.BUNDLE_READY
        elif self._delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH:
            self._active_context = self._pending_context
            self._pending_context = None
            self._selected_delta = None
            self._delta_chain_length = 0
            self._phase = WorkflowContextPhase.BUNDLE_READY
        else:
            self._phase = WorkflowContextPhase.TARGET_BUNDLE_LOADED

    def record_delta_compiled(self, base_bundle_id: str, target_bundle_id: str, delta_digest: str) -> None:
        self._require_phase(WorkflowContextPhase.TARGET_BUNDLE_LOADED)
        if self._delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH:
            self._fail(WorkflowSessionErrorCode.LIMIT_EXCEEDED)
        _digest(base_bundle_id)
        _digest(target_bundle_id)
        _digest(delta_digest)
        if self._active_context is None or self._pending_context is None:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if self._active_context[1] != base_bundle_id or self._pending_context[1] != target_bundle_id:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        self._pending_delta = (base_bundle_id, target_bundle_id, delta_digest)
        self._phase = WorkflowContextPhase.DELTA_COMPILED

    def record_delta_applied(self, base_bundle_id: str, target_bundle_id: str, delta_digest: str) -> None:
        self._require_phase(WorkflowContextPhase.DELTA_COMPILED)
        _digest(base_bundle_id)
        _digest(target_bundle_id)
        _digest(delta_digest)
        if self._pending_delta is None:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if self._pending_delta != (base_bundle_id, target_bundle_id, delta_digest):
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        if self._delta_chain_length >= MAX_WORKFLOW_DELTA_CHAIN_LENGTH:
            self._fail(WorkflowSessionErrorCode.LIMIT_EXCEEDED)
        self._delta_chain_length += 1
        self._selected_delta = self._pending_delta
        self._active_context = self._pending_context
        self._pending_context = None
        self._pending_delta = None
        self._phase = WorkflowContextPhase.BUNDLE_READY

    def record_materialized(
        self,
        bundle_id: str,
        tokenizer_fingerprint: str,
        materializer_fingerprint: str,
        physical_input_tokens: int,
    ) -> None:
        self._require_phase(WorkflowContextPhase.BUNDLE_READY, WorkflowContextPhase.CHECKPOINTED)
        _digest(bundle_id)
        _digest(tokenizer_fingerprint)
        _digest(materializer_fingerprint)
        if self._model_result_digest is not None or not _bounded_positive(physical_input_tokens, 0xFFFF_FFFF):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        if self.active_bundle_id != bundle_id:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        self._materialization = (
            bundle_id,
            tokenizer_fingerprint,
            materializer_fingerprint,
            physical_input_tokens,
        )
        self._phase = WorkflowContextPhase.MATERIALIZED

    def begin_model_invocation(self, invocation_id: str, request_digest: str, idempotency_key_digest: str) -> None:
        self._require_phase(WorkflowContextPhase.MATERIALIZED)
        _record(invocation_id)
        _digest(request_digest)
        _digest(idempotency_key_digest)
        self._invocation = (invocation_id, request_digest, idempotency_key_digest)
        self._phase = WorkflowContextPhase.MODEL_INVOCATION_PENDING

    def record_model_result(self, invocation_id: str, result_digest: str) -> None:
        self._require_phase(WorkflowContextPhase.MODEL_INVOCATION_PENDING)
        _record(invocation_id)
        _digest(result_digest)
        if self._invocation is None or self._invocation[0] != invocation_id:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        self._model_result_digest = result_digest
        self._phase = WorkflowContextPhase.MODEL_RESULT_RECORDED

    def record_effect_prepared(
        self,
        effect_id: str,
        intent_digest: str,
        effect_version: int,
        state: str = "prepared",
        attempt_count: int = 0,
        reconciliation_count: int = 0,
    ) -> None:
        self._require_phase(WorkflowContextPhase.MODEL_RESULT_RECORDED)
        _record(effect_id)
        _digest(intent_digest)
        if (
            self._effect is not None
            or not _bounded_positive(effect_version, 0xFFFF_FFFF_FFFF_FFFF)
            or state != "prepared"
            or not _bounded_count(attempt_count)
            or not _bounded_count(reconciliation_count)
            or attempt_count != 0
            or reconciliation_count != 0
        ):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        self._effect = (effect_id, intent_digest, effect_version, state, attempt_count, reconciliation_count)
        self._phase = WorkflowContextPhase.EFFECT_PREPARED

    def record_observation(self, publication_digest: str, revision: int) -> None:
        self._require_phase(WorkflowContextPhase.MODEL_RESULT_RECORDED, WorkflowContextPhase.EFFECT_PREPARED)
        _digest(publication_digest)
        if not _bounded_positive(revision, 0xFFFF_FFFF_FFFF_FFFF):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        self._observation_digest = publication_digest
        self._observation_revision = revision
        self._phase = WorkflowContextPhase.OBSERVATION_RECORDED

    def record_effect_authorized(
        self,
        effect_id: str,
        intent_digest: str,
        effect_version: int,
        state: str = "authorized",
        attempt_count: int = 0,
        reconciliation_count: int = 0,
    ) -> None:
        self._require_phase(WorkflowContextPhase.EFFECT_AUTHORIZATION_REVALIDATED)
        if self._model_result_digest is None or state != "authorized":
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        if self._effect is None or (attempt_count, reconciliation_count) != self._effect[4:]:
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        self._update_effect(
            effect_id,
            intent_digest,
            effect_version,
            state,
            attempt_count,
            reconciliation_count,
            require_new_version=True,
        )
        self._phase = WorkflowContextPhase.EFFECT_AUTHORIZED

    def record_effect_revalidated(self, bundle_id: str, *, valid: bool) -> None:
        before_authorization = (
            self._phase is WorkflowContextPhase.BUNDLE_READY
            and self._model_result_digest is not None
            and self._effect is not None
            and self._effect[3] == "prepared"
        )
        if not before_authorization and self._phase is not WorkflowContextPhase.EFFECT_AUTHORIZED:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        _digest(bundle_id)
        if not isinstance(valid, bool):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        if self.active_bundle_id != bundle_id:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        if not valid:
            self._enter_quarantine(WorkflowQuarantineReason.INVALIDATED)
        else:
            self._phase = (
                WorkflowContextPhase.EFFECT_AUTHORIZATION_REVALIDATED
                if before_authorization
                else WorkflowContextPhase.EFFECT_REVALIDATED
            )

    def quarantine_context(self, bundle_id: str, reason: WorkflowQuarantineReason) -> None:
        """Terminally fence an exact active context after cancellation or revocation."""
        _digest(bundle_id)
        if not isinstance(reason, WorkflowQuarantineReason):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        if self._phase in {
            WorkflowContextPhase.NEW,
            WorkflowContextPhase.FINISHED,
            WorkflowContextPhase.REPLAY_VERIFIED,
            WorkflowContextPhase.QUARANTINED,
        }:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if self.active_bundle_id != bundle_id:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        self._enter_quarantine(reason)

    def record_effect_dispatched(
        self,
        effect_id: str,
        intent_digest: str,
        effect_version: int,
        state: str,
        attempt_count: int,
        reconciliation_count: int,
    ) -> None:
        self._require_phase(WorkflowContextPhase.EFFECT_REVALIDATED)
        if state not in {"dispatching", "unknown"} | _TERMINAL_EFFECT_STATES:
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        if self._effect is None or attempt_count != self._effect[4] + 1 or reconciliation_count != self._effect[5]:
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        self._update_effect(
            effect_id,
            intent_digest,
            effect_version,
            state,
            attempt_count,
            reconciliation_count,
            require_new_version=True,
        )
        self._phase = _effect_phase(state)

    def record_effect_observed(
        self,
        effect_id: str,
        intent_digest: str,
        effect_version: int,
        state: str,
        attempt_count: int,
        reconciliation_count: int,
    ) -> None:
        if self._phase is WorkflowContextPhase.EFFECT_DISPATCHING:
            allowed = {"dispatching", "unknown"} | _TERMINAL_EFFECT_STATES
        elif self._phase is WorkflowContextPhase.EFFECT_AMBIGUOUS:
            allowed = {"unknown", "authorized_for_retry"} | _TERMINAL_EFFECT_STATES
        else:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if state not in allowed:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if self._effect is None:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if (
            attempt_count < self._effect[4]
            or reconciliation_count < self._effect[5]
            or (
                state == "authorized_for_retry"
                and (attempt_count != self._effect[4] or reconciliation_count <= self._effect[5])
            )
        ):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        self._update_effect(
            effect_id,
            intent_digest,
            effect_version,
            state,
            attempt_count,
            reconciliation_count,
            require_new_version=False,
        )
        self._phase = _effect_phase(state)

    def checkpoint_cycle(self) -> None:
        effect_complete = (
            self._phase is WorkflowContextPhase.BUNDLE_READY
            if self._effect is None
            else self._phase is WorkflowContextPhase.EFFECT_SETTLED and self._effect[3] in _TERMINAL_EFFECT_STATES
        )
        if not effect_complete or self._model_result_digest is None or self._observation_digest is None:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        if len(self._completed_cycles) >= MAX_WORKFLOW_REPLAY_CYCLES or self._completed_turns >= 0xFFFF_FFFF:
            self._fail(WorkflowSessionErrorCode.LIMIT_EXCEEDED)
        if (
            self._active_context is None
            or self._materialization is None
            or self._invocation is None
            or self._observation_revision is None
        ):
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        plan_id, bundle_id, contract_digest = self._active_context
        materialized_bundle_id, tokenizer_fingerprint, materializer_fingerprint, physical_input_tokens = (
            self._materialization
        )
        invocation_id, request_digest, idempotency_key_digest = self._invocation
        selected_delta = (
            WorkflowDeltaReplayIdentity(*self._selected_delta) if self._selected_delta is not None else None
        )
        effect = WorkflowEffectReplayIdentity(*self._effect) if self._effect is not None else None
        self._completed_cycles.append(
            WorkflowContextCycleIdentity(
                plan_id=plan_id,
                bundle_id=bundle_id,
                contract_digest=contract_digest,
                selected_delta=selected_delta,
                materialized_bundle_id=materialized_bundle_id,
                tokenizer_fingerprint=tokenizer_fingerprint,
                materializer_fingerprint=materializer_fingerprint,
                physical_input_tokens=physical_input_tokens,
                invocation_id=invocation_id,
                request_digest=request_digest,
                idempotency_key_digest=idempotency_key_digest,
                model_result_digest=self._model_result_digest,
                effect=effect,
                outcome_digest=self._observation_digest,
                outcome_revision=self._observation_revision,
            )
        )
        self._completed_turns += 1
        self._pending_context = None
        self._pending_delta = None
        self._selected_delta = None
        self._materialization = None
        self._invocation = None
        self._model_result_digest = None
        self._observation_digest = None
        self._observation_revision = None
        self._effect = None
        self._phase = WorkflowContextPhase.CHECKPOINTED

    def finish(self) -> None:
        self._require_phase(WorkflowContextPhase.CHECKPOINTED)
        if self._completed_turns == 0:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        self._phase = WorkflowContextPhase.FINISHED

    def record_replay_verified(
        self,
        decision_id: str,
        execution_id: str,
        candidate: WorkflowContextReplayIdentity,
    ) -> WorkflowContextReplayComparison:
        self._require_phase(WorkflowContextPhase.FINISHED)
        _digest(decision_id)
        _record(execution_id)
        comparison = self.compare_replay(candidate)
        if not comparison.exact_match:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        self._replay_verified = True
        self._phase = WorkflowContextPhase.REPLAY_VERIFIED
        return comparison

    def _require_phase(self, *allowed: WorkflowContextPhase) -> None:
        if self._phase not in allowed:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)

    def _update_effect(
        self,
        effect_id: str,
        intent_digest: str,
        effect_version: int,
        state: str,
        attempt_count: int,
        reconciliation_count: int,
        *,
        require_new_version: bool,
    ) -> None:
        _record(effect_id)
        _digest(intent_digest)
        if (
            not _bounded_positive(effect_version, 0xFFFF_FFFF_FFFF_FFFF)
            or not _bounded_count(attempt_count)
            or not _bounded_count(reconciliation_count)
            or not _effect_counts_valid(state, attempt_count, reconciliation_count)
        ):
            self._fail(WorkflowSessionErrorCode.INVALID_EVENT)
        if self._effect is None:
            self._fail(WorkflowSessionErrorCode.INVALID_TRANSITION)
        current_id, current_intent, current_version, current_state, _, _ = self._effect
        version_valid = effect_version > current_version or (
            not require_new_version and effect_version == current_version and state == current_state
        )
        if effect_id != current_id or intent_digest != current_intent or not version_valid:
            self._fail(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        self._effect = (effect_id, intent_digest, effect_version, state, attempt_count, reconciliation_count)

    def _enter_quarantine(self, reason: WorkflowQuarantineReason) -> None:
        self._pending_context = None
        self._pending_delta = None
        self._selected_delta = None
        self._materialization = None
        self._invocation = None
        self._model_result_digest = None
        self._observation_digest = None
        self._observation_revision = None
        self._effect = None
        self._replay_verified = False
        self._quarantine_reason = reason
        self._phase = WorkflowContextPhase.QUARANTINED

    @staticmethod
    def _fail(code: WorkflowSessionErrorCode) -> Never:
        raise WorkflowSessionError(code)


def _digest(value: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WorkflowSessionError(WorkflowSessionErrorCode.INVALID_EVENT)


def _record(value: str) -> None:
    if not isinstance(value, str) or _UUID_V7.fullmatch(value) is None:
        raise WorkflowSessionError(WorkflowSessionErrorCode.INVALID_EVENT)


def _bounded_positive(value: int, maximum: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 0 < value <= maximum


def _bounded_count(value: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 0 <= value <= 0xFFFF_FFFF


def _validate_replay_identity(identity: WorkflowContextReplayIdentity) -> None:
    if (
        not isinstance(identity, WorkflowContextReplayIdentity)
        or not identity.cycles
        or len(identity.cycles) > MAX_WORKFLOW_REPLAY_CYCLES
    ):
        raise WorkflowSessionError(WorkflowSessionErrorCode.INVALID_EVENT)
    for cycle in identity.cycles:
        _record(cycle.plan_id)
        _digest(cycle.bundle_id)
        _digest(cycle.contract_digest)
        _digest(cycle.materialized_bundle_id)
        _digest(cycle.tokenizer_fingerprint)
        _digest(cycle.materializer_fingerprint)
        _record(cycle.invocation_id)
        _digest(cycle.request_digest)
        _digest(cycle.idempotency_key_digest)
        _digest(cycle.model_result_digest)
        _digest(cycle.outcome_digest)
        if not _bounded_positive(cycle.physical_input_tokens, 0xFFFF_FFFF) or not _bounded_positive(
            cycle.outcome_revision, 0xFFFF_FFFF_FFFF_FFFF
        ):
            raise WorkflowSessionError(WorkflowSessionErrorCode.INVALID_EVENT)
        if cycle.selected_delta is not None:
            _digest(cycle.selected_delta.base_bundle_id)
            _digest(cycle.selected_delta.target_bundle_id)
            _digest(cycle.selected_delta.delta_digest)
            if (
                cycle.selected_delta.target_bundle_id != cycle.bundle_id
                or cycle.selected_delta.base_bundle_id != cycle.materialized_bundle_id
                or cycle.selected_delta.base_bundle_id == cycle.selected_delta.target_bundle_id
            ):
                raise WorkflowSessionError(WorkflowSessionErrorCode.IDENTITY_MISMATCH)
        if cycle.effect is not None:
            _record(cycle.effect.effect_id)
            _digest(cycle.effect.intent_digest)
            if (
                not _bounded_positive(cycle.effect.effect_version, 0xFFFF_FFFF_FFFF_FFFF)
                or cycle.effect.state not in _TERMINAL_EFFECT_STATES
                or not _bounded_count(cycle.effect.attempt_count)
                or not _bounded_count(cycle.effect.reconciliation_count)
                or not _effect_counts_valid(
                    cycle.effect.state,
                    cycle.effect.attempt_count,
                    cycle.effect.reconciliation_count,
                )
            ):
                raise WorkflowSessionError(WorkflowSessionErrorCode.INVALID_EVENT)


def _compare_workflow_replay(
    baseline: WorkflowContextReplayIdentity,
    candidate: WorkflowContextReplayIdentity,
) -> WorkflowContextReplayComparison:
    same_length = len(baseline.cycles) == len(candidate.cycles)
    pairs = tuple(zip(baseline.cycles, candidate.cycles, strict=False))
    selection = _comparison_status(
        same_length
        and all(
            (left.plan_id, left.bundle_id, left.contract_digest, left.selected_delta)
            == (right.plan_id, right.bundle_id, right.contract_digest, right.selected_delta)
            for left, right in pairs
        )
    )
    materialization = _comparison_status(
        same_length
        and all(
            (
                left.materialized_bundle_id,
                left.tokenizer_fingerprint,
                left.materializer_fingerprint,
                left.physical_input_tokens,
            )
            == (
                right.materialized_bundle_id,
                right.tokenizer_fingerprint,
                right.materializer_fingerprint,
                right.physical_input_tokens,
            )
            for left, right in pairs
        )
    )
    model_result = _comparison_status(
        same_length
        and all(
            (left.invocation_id, left.request_digest, left.idempotency_key_digest, left.model_result_digest)
            == (right.invocation_id, right.request_digest, right.idempotency_key_digest, right.model_result_digest)
            for left, right in pairs
        )
    )
    effect = _comparison_status(same_length and all(left.effect == right.effect for left, right in pairs))
    outcome = _comparison_status(
        same_length
        and all(
            (left.outcome_digest, left.outcome_revision) == (right.outcome_digest, right.outcome_revision)
            for left, right in pairs
        )
    )
    statuses = (selection, materialization, model_result, effect, outcome)
    return WorkflowContextReplayComparison(
        bundle_delta_selection=selection,
        materialization=materialization,
        model_result_identity=model_result,
        tool_effect_decisions=effect,
        outcome=outcome,
        exact_match=all(status is WorkflowReplayDiffStatus.EQUAL for status in statuses),
    )


def _comparison_status(equal: bool) -> WorkflowReplayDiffStatus:
    return WorkflowReplayDiffStatus.EQUAL if equal else WorkflowReplayDiffStatus.DIFFERENT


def _effect_phase(state: str) -> WorkflowContextPhase:
    if state == "dispatching":
        return WorkflowContextPhase.EFFECT_DISPATCHING
    if state == "unknown":
        return WorkflowContextPhase.EFFECT_AMBIGUOUS
    if state == "authorized_for_retry":
        return WorkflowContextPhase.EFFECT_AUTHORIZED
    if state in _TERMINAL_EFFECT_STATES:
        return WorkflowContextPhase.EFFECT_SETTLED
    raise WorkflowSessionError(WorkflowSessionErrorCode.INVALID_EVENT)


def _effect_counts_valid(state: str, attempts: int, reconciliations: int) -> bool:
    if reconciliations != 0 and attempts == 0:
        return False
    if state in {"prepared", "authorized", "rejected"}:
        return attempts == 0 and reconciliations == 0
    if state in {
        "dispatching",
        "succeeded",
        "failed",
        "unknown",
        "compensated",
        "compensation_failed",
    }:
        return attempts != 0
    if state in {"authorized_for_retry", "manual_resolution"}:
        return attempts != 0 and reconciliations != 0
    return state in {"expired", "cancelled"}
