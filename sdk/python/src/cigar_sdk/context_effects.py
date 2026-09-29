"""Opt-in bridge from local reviewed context to the existing CIGAR effect authority.

No credentials, services, approvals, effect IDs or retry attempts are created here.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from typing import Protocol

from cigar_sdk.broker import LocalContextBroker
from cigar_sdk.broker_types import LocalBrokerExecutionBinding, LocalBrokerExecutionHandoff, LocalBrokerExecutionReview
from cigar_sdk.errors import CigarError, ValidationError
from cigar_sdk.generated.models import EffectIdRequest, EffectStatusResponse
from cigar_sdk.idempotency import validate_idempotency_key
from cigar_sdk.models_runtime import payload_value
from cigar_sdk.types import CallOptions, TypedOperationRequest, TypedOperationResponse

_BINDING_FIELDS = frozenset(
    {
        "schema",
        "id",
        "epoch",
        "ticket",
        "submission_id",
        "context_id",
        "snapshot_id",
        "source_authority_digest",
        "review_digest",
        "effect_id",
        "intent_digest",
    }
)
_DIGEST = re.compile(r"1220[0-9a-f]{64}")
_READY = frozenset({"authorized", "authorized_for_retry"})
_NOT_DISPATCHED = frozenset({"prepared", "pending_approval", "authorized"})


class ContextEffectClient(Protocol):
    """The two existing generated operations used by this adapter. CigarClient implements it."""

    def get_effect_status(
        self, request: TypedOperationRequest[EffectIdRequest], *, options: CallOptions | None = None
    ) -> TypedOperationResponse[EffectStatusResponse]: ...

    def dispatch_effect(
        self, request: TypedOperationRequest[EffectIdRequest], *, options: CallOptions | None = None
    ) -> TypedOperationResponse[EffectStatusResponse]: ...


class ContextEffectDispatch:
    """A consumed context check and the effect authority's response, not proof of tool success."""

    def __init__(
        self, handoff: LocalBrokerExecutionHandoff, response: TypedOperationResponse[EffectStatusResponse]
    ) -> None:
        self._handoff = copy.deepcopy(handoff)
        self._response = response

    @property
    def handoff(self) -> LocalBrokerExecutionHandoff:
        return copy.deepcopy(self._handoff)

    @property
    def response(self) -> TypedOperationResponse[EffectStatusResponse]:
        return self._response

    def __repr__(self) -> str:
        return f"ContextEffectDispatch(state={self._response.payload.state!r})"


class ContextEffectDispatchUncertain(CigarError):
    """A handoff was consumed but no valid dispatch response was obtained. Observe the same effect.

    Do not retry this adapter or prepare a replacement intent to resolve uncertainty. Use the
    existing effect status/reconciliation workflow. Handoff access is explicit and copy-safe.
    """

    def __init__(self, handoff: LocalBrokerExecutionHandoff) -> None:
        super().__init__("context effect dispatch outcome is uncertain; observe the existing effect")
        self._handoff = copy.deepcopy(handoff)

    @property
    def handoff(self) -> LocalBrokerExecutionHandoff:
        return copy.deepcopy(self._handoff)


def _status(
    response: TypedOperationResponse[EffectStatusResponse], operation: str, binding: LocalBrokerExecutionBinding
) -> EffectStatusResponse:
    status = response.payload
    payload_value(status)  # Enforce the same generated record contract for injected effect ports.
    if (
        response.operation_id != operation
        or status.effect_id != binding["effect_id"]
        or status.intent_digest != binding["intent_digest"]
        or not 0 <= status.effect_version < 1 << 64
        or not 0 <= status.attempt_count < 1 << 32
        or not 0 <= status.reconciliation_count < 1 << 32
    ):
        raise ValidationError("effect response does not match the bound intent")
    return status


def dispatch_context_effect(
    broker: LocalContextBroker,
    client: ContextEffectClient,
    binding: LocalBrokerExecutionBinding,
    resolve_review: Callable[[], LocalBrokerExecutionReview],
    *,
    idempotency_key: str,
    timeout: float = 30.0,
) -> ContextEffectDispatch:
    """Check current effect identity, consume current reviewed context, then dispatch once.

    The host supplies an explicitly configured client and a resolver for current trusted review
    authority. The existing effect must already be authorized (or explicitly authorized for retry
    by reconciliation). Each HTTP operation has its own bounded timeout and one attempt. Native
    context and caller-owned review resolution retain their own deadlines.

    The context check is at handoff time: it cannot lock context across remote worker execution.
    Honey still checks its current authorization, exact effect version and intent preconditions.
    """
    if (
        not isinstance(binding, dict)
        or set(binding) != _BINDING_FIELDS
        or any(not isinstance(value, str) or len(value.encode()) > 256 for value in binding.values())
        or binding["schema"] != "cigar.context-execution-binding.v1"
        or _DIGEST.fullmatch(binding["intent_digest"]) is None
        or not callable(resolve_review)
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= 300
        or not isinstance(idempotency_key, str)
    ):
        raise ValidationError("invalid context effect dispatch input")
    exact = copy.deepcopy(binding)
    payload = EffectIdRequest(effect_id=exact["effect_id"])
    payload_value(payload)
    validate_idempotency_key(idempotency_key)
    options = CallOptions(timeout=timeout, max_attempts=1)
    before = _status(
        client.get_effect_status(TypedOperationRequest(payload), options=options), "getEffectStatus", exact
    )
    if before.state not in _READY or before.effect_version == (1 << 64) - 1:
        raise ValidationError("bound effect is not dispatchable")

    # Resolve after the remote read, then check and consume in the native authority. No cached
    # agent approval, callback, status polling or unrelated work occurs between take and dispatch.
    handoff = broker.take_execution_handoff(exact, resolve_review())
    try:
        if (
            handoff["binding"] != exact
            or handoff["checked"]["context_id"] != exact["context_id"]
            or handoff["checked"]["assessment"]["snapshot_id"] != exact["snapshot_id"]
            or handoff["checked"]["assessment"]["decision"] != "release"
        ):
            raise ValidationError("context handoff does not match the bound intent")
        response = client.dispatch_effect(
            TypedOperationRequest(
                payload, idempotency_key=idempotency_key, expected_revision=str(before.effect_version)
            ),
            options=options,
        )
        after = _status(response, "dispatchEffect", exact)
        if (
            after.effect_version <= before.effect_version
            or after.attempt_count < before.attempt_count
            or after.reconciliation_count < before.reconciliation_count
            or after.state in _NOT_DISPATCHED
        ):
            raise ValidationError("effect dispatch did not return a valid advancement")
    except Exception:
        # An HTTP error, timeout, malformed response or injected-port failure cannot make this
        # consumed handoff reusable. Preserve the identity without surfacing remote content.
        raise ContextEffectDispatchUncertain(handoff) from None
    return ContextEffectDispatch(handoff, response)
