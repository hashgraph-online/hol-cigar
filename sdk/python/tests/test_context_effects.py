"""Real context authority and generated HTTP client; deterministic effect-wire fault fixtures."""

from __future__ import annotations

import base64
import json
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest
from test_broker import broker as broker
from test_broker import execution_fixture, ingest

from cigar_sdk import (
    CigarClient,
    ContextEffectDispatchUncertain,
    LocalBrokerError,
    TransportError,
    ValidationError,
    dispatch_context_effect,
)
from cigar_sdk.digest import _deterministic_cbor
from cigar_sdk.models_runtime import decode_operation_payload
from cigar_sdk.transport import HttpResponse

EFFECT = "01900000-0000-7000-8000-000000000001"
INTENT = "1220" + "a" * 64
VERSION = (1 << 53) + 7


class EffectWire:
    def __init__(self):
        self.before = {
            "effect_id": EFFECT,
            "intent_digest": INTENT,
            "state": "authorized",
            "effect_version": VERSION,
            "attempt_count": 2,
            "reconciliation_count": 1,
        }
        self.after = dict(self.before, state="dispatching", effect_version=VERSION + 1, attempt_count=3)
        self.get_error = None
        self.dispatch_error = None
        self.on_get = lambda: None
        self.requests = []
        self.reply_operation = "dispatchEffect"

    def request(self, method, url, headers, body, timeout):
        self.requests.append((method, url, dict(headers), body, timeout))
        if method == "GET":
            self.on_get()
            if self.get_error:
                raise self.get_error
            operation, value = "getEffectStatus", self.before
        else:
            if self.dispatch_error:
                raise self.dispatch_error
            operation, value = self.reply_operation, self.after
        payload = base64.urlsafe_b64encode(_deterministic_cbor(value)).rstrip(b"=").decode()
        return HttpResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(
                {
                    "operation_id": operation,
                    "payload_cbor": payload,
                }
            ).encode(),
        )

    def stream(self, *args):
        raise AssertionError("not an effect stream")

    def client(self):
        return CigarClient(
            "http://127.0.0.1:1234",
            allow_insecure_loopback=True,
            transport=self,
            trust_custom_transport=True,
            max_attempts=8,
        )


@pytest.fixture
def bound(broker):
    _, context, _, submission, review = execution_fixture(broker)
    return broker.bind_execution(context["ticket"], submission, EFFECT, INTENT, review), review


def test_exact_generated_dispatch_preserves_revision_key_and_consumed_identity(broker, bound):
    binding, review = bound
    wire = EffectWire()
    calls = []

    def resolve():
        calls.append(len(wire.requests))
        return review

    result = dispatch_context_effect(broker, wire.client(), binding, resolve, idempotency_key="existing-dispatch-key")
    assert calls == [1]
    assert result.response.payload.state == "dispatching"
    assert result.handoff["binding"] == binding
    assert result.handoff["checked"]["assessment"]["decision"] == "release"
    assert [r[0] for r in wire.requests] == ["GET", "POST"]
    _, url, headers, body, _ = wire.requests[1]
    request = json.loads(body)
    assert url.endswith(f"/v1/effects/{EFFECT}:dispatch")
    assert headers["if-match"] == str(VERSION)
    assert headers["idempotency-key"] == "existing-dispatch-key"
    assert request["expected_revision"] == str(VERSION)
    assert decode_operation_payload(base64.urlsafe_b64decode(request["payload_cbor"] + "==")) == {"effect_id": EFFECT}
    assert EFFECT not in repr(result) and INTENT not in repr(result)
    changed = result.handoff
    changed["binding"]["effect_id"] = "changed"
    assert result.handoff["binding"] == binding
    with pytest.raises(LocalBrokerError, match="Conflict"):
        dispatch_context_effect(broker, wire.client(), binding, resolve, idempotency_key="existing-dispatch-key")
    assert len([r for r in wire.requests if r[0] == "POST"]) == 1


@pytest.mark.parametrize(
    "state", ["prepared", "pending_approval", "dispatching", "unknown", "succeeded", "failed", "cancelled"]
)
def test_non_dispatchable_effect_does_not_consume_context_or_send(broker, bound, state):
    binding, review = bound
    wire = EffectWire()
    wire.before["state"] = state
    with pytest.raises(ValidationError, match="not dispatchable"):
        dispatch_context_effect(broker, wire.client(), binding, lambda: review, idempotency_key="same-key")
    assert len(wire.requests) == 1
    assert broker.take_execution_handoff(binding, review)["binding"] == binding


@pytest.mark.parametrize("state", ["dispatching", "unknown", "succeeded", "failed", "authorized_for_retry"])
def test_authority_outcomes_are_preserved_without_automatic_reconciliation_or_retry(broker, bound, state):
    binding, review = bound
    wire = EffectWire()
    wire.before["state"] = "authorized_for_retry"
    wire.after["state"] = state
    result = dispatch_context_effect(broker, wire.client(), binding, lambda: review, idempotency_key="original-key")
    assert result.response.payload.state == state
    assert len(wire.requests) == 2


@pytest.mark.parametrize("change", ["intent", "effect", "revision_overflow", "counter_overflow", "read_failure"])
def test_preflight_failures_retain_unconsumed_context(broker, bound, change):
    binding, review = bound
    wire = EffectWire()
    if change == "intent":
        wire.before["intent_digest"] = "1220" + "b" * 64
    elif change == "effect":
        wire.before["effect_id"] = "01900000-0000-7000-8000-000000000002"
    elif change == "revision_overflow":
        wire.before["effect_version"] = (1 << 64) - 1
    elif change == "counter_overflow":
        wire.before["attempt_count"] = 1 << 32
    else:
        wire.get_error = TransportError("private read diagnostic")
    with pytest.raises((ValidationError, TransportError)):
        dispatch_context_effect(broker, wire.client(), binding, lambda: review, idempotency_key="same-key")
    assert len(wire.requests) == 1
    assert broker.take_execution_handoff(binding, review)["binding"] == binding


@pytest.mark.parametrize("change", ["source", "reviewer", "policy", "resolver_failure"])
def test_current_review_is_resolved_after_remote_read_and_revalidated_before_dispatch(broker, bound, change):
    binding, review = bound
    wire = EffectWire()

    def resolve():
        assert len(wire.requests) == 1
        if change == "source":
            ingest(broker, "docs", "fact", "Changed source after effect read.")
        elif change == "reviewer":
            review["authority_revision"] = "revoked"
        elif change == "policy":
            review["policy"] = {"min_sources": 2}
        else:
            raise RuntimeError("review authority unavailable")
        return review

    with pytest.raises((LocalBrokerError, RuntimeError)):
        dispatch_context_effect(broker, wire.client(), binding, resolve, idempotency_key="same-key")
    assert len(wire.requests) == 1


@pytest.mark.parametrize(
    "change",
    ["lost_reply", "operation", "effect", "intent", "version", "attempt", "reconciliation", "state", "malformed"],
)
def test_every_post_consumption_failure_retains_identity_and_never_retries(broker, bound, change):
    binding, review = bound
    wire = EffectWire()
    if change == "lost_reply":
        wire.dispatch_error = TransportError("PRIVATE_EFFECT_ARGUMENTS")
    elif change == "operation":
        wire.reply_operation = "getEffectStatus"
    elif change == "effect":
        wire.after["effect_id"] = "01900000-0000-7000-8000-000000000002"
    elif change == "intent":
        wire.after["intent_digest"] = "1220" + "b" * 64
    elif change == "version":
        wire.after["effect_version"] = VERSION
    elif change == "attempt":
        wire.after["attempt_count"] = 1
    elif change == "reconciliation":
        wire.after["reconciliation_count"] = 0
    elif change == "state":
        wire.after["state"] = "authorized"
    else:
        wire.after["state"] = "PRIVATE_EFFECT_ARGUMENTS"
    with pytest.raises(ContextEffectDispatchUncertain) as caught:
        dispatch_context_effect(broker, wire.client(), binding, lambda: review, idempotency_key="same-key")
    assert len(wire.requests) == 2
    assert caught.value.handoff["binding"] == binding
    assert "PRIVATE_EFFECT_ARGUMENTS" not in str(caught.value) + repr(caught.value)
    caught.value.handoff["binding"]["effect_id"] = "changed"
    assert caught.value.handoff["binding"] == binding
    with pytest.raises(LocalBrokerError, match="Conflict"):
        broker.take_execution_handoff(binding, review)


@pytest.mark.parametrize("change", ["timeout", "nan", "bool", "key", "extra", "effect", "digest", "resolver"])
def test_invalid_inputs_fail_before_remote_read_or_context_consumption(broker, bound, change):
    binding, review = bound
    supplied = deepcopy(binding)
    wire = EffectWire()
    arguments = {"idempotency_key": "same-key", "timeout": 30}

    def resolver():
        return review

    if change == "timeout":
        arguments["timeout"] = 301
    elif change == "nan":
        arguments["timeout"] = float("nan")
    elif change == "bool":
        arguments["timeout"] = True
    elif change == "key":
        arguments["idempotency_key"] = "\n"
    elif change == "extra":
        supplied["agent_approval"] = "true"
    elif change == "effect":
        supplied["effect_id"] = "not-a-honey-effect"
    elif change == "digest":
        supplied["intent_digest"] = "bad"
    else:
        resolver = None
    with pytest.raises(ValidationError):
        dispatch_context_effect(broker, wire.client(), supplied, resolver, **arguments)
    assert wire.requests == []
    assert broker.take_execution_handoff(binding, review)["binding"] == binding


def test_caller_cannot_retarget_binding_during_read_and_bad_handoff_never_dispatches(broker, bound):
    binding, review = bound
    wire = EffectWire()
    original = deepcopy(binding)
    wire.on_get = lambda: binding.update(effect_id="changed-during-read")
    result = dispatch_context_effect(broker, wire.client(), binding, lambda: review, idempotency_key="same-key")
    assert result.handoff["binding"] == original
    assert result.response.payload.effect_id == EFFECT


def test_invalid_handoff_or_injected_port_cannot_bypass_identity_check(broker, bound):
    binding, review = bound
    wire = EffectWire()
    client = wire.client()
    real_take = broker.take_execution_handoff

    def malformed(*args):
        result = real_take(*args)
        result["checked"]["assessment"]["decision"] = "abstain"
        return result

    with patch.object(broker, "take_execution_handoff", side_effect=malformed):
        with pytest.raises(ContextEffectDispatchUncertain):
            dispatch_context_effect(broker, client, binding, lambda: review, idempotency_key="same-key")
    assert len(wire.requests) == 1


def test_injected_port_operation_identity_is_checked_before_take(broker, bound):
    binding, review = bound
    wire = EffectWire()
    client = wire.client()
    original = client.get_effect_status
    with patch.object(
        client,
        "get_effect_status",
        side_effect=lambda *a, **kw: replace(
            original(*a, **kw),
            operation_id="dispatchEffect",
        ),
    ):
        with pytest.raises(ValidationError, match="bound intent"):
            dispatch_context_effect(broker, client, binding, lambda: review, idempotency_key="same-key")
    assert broker.take_execution_handoff(binding, review)["binding"] == binding
