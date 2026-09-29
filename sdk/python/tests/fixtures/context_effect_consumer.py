"""Bounded local integration driver for the Rust Honey HTTP fixture; never a model call."""

import json
import os
import sys

from cigar_sdk import (
    CallOptions,
    CigarClient,
    ContextEffectDispatchUncertain,
    LocalBrokerError,
    LocalContextBroker,
    LocalContextClient,
    TypedOperationRequest,
    ValidationError,
    dispatch_context_effect,
    models,
)


def read():
    line = sys.stdin.readline(32769)
    if not line.endswith("\n") or len(line) > 32768:
        raise ValueError("invalid integration driver frame")
    return json.loads(line)


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main():
    config = read()
    client = CigarClient(
        config["base_url"], bearer_token="context-effect-sdk-fixture", allow_insecure_loopback=True, max_attempts=8
    )
    provenance = {
        "authority": "host",
        "upstream_revision": "one",
        "observed_at_ms": 1,
        "valid_until_ms": None,
        "origin": "host",
        "derived_from": [],
    }
    with LocalContextBroker("honey-sdk", worker_path=os.environ["CIGAR_TEST_WORKER"]) as broker:
        broker.replace_source(
            "docs",
            broker.source_revision("docs"),
            [
                {"id": "fact", "source": "docs", "text": "The approved operation is send."},
            ],
            provenance,
        )
        agent = LocalContextClient(
            broker.grant(
                {
                    "id": "agent",
                    "allowed_sources": ["docs"],
                    "policy_revision": "host-one",
                }
            )
        )
        context = agent.compile({"query": "send", "required": ["fact"]})
        submission = agent.submit_answer(
            context["ticket"],
            {
                "snapshot_id": context["context"]["snapshot"]["id"],
                "claims": [{"text": "The approved operation is send.", "citations": ["fact"], "confidence_bps": 9900}],
            },
        )
        review = {
            "authority_revision": "trusted-reviewer-one",
            "policy": {},
            "reviews": [
                {"claim_key": key, "verdict": "supported"}
                for key in broker.submission(context["ticket"])["review_keys"]
            ],
        }
        intent = "1220" + "f" * 64 if config["scenario"] == "intent_substitution" else config["intent_digest"]
        binding = broker.bind_execution(context["ticket"], submission, config["effect_id"], intent, review)

        def resolve_review():
            if config["scenario"] == "stale_context":
                broker.replace_source(
                    "docs",
                    broker.source_revision("docs"),
                    [
                        {"id": "fact", "source": "docs", "text": "The operation is withdrawn."},
                    ],
                    dict(provenance, upstream_revision="two"),
                )
            return review

        try:
            result = dispatch_context_effect(
                broker, client, binding, resolve_review, idempotency_key="existing-sdk-dispatch", timeout=10
            )
            assert result.response.payload.state == "dispatching"
            assert result.handoff["binding"] == binding
            outcome = "dispatched"
        except ContextEffectDispatchUncertain as error:
            assert config["scenario"] == "lost_ack"
            assert error.handoff["binding"] == binding
            outcome = "uncertain"
        except LocalBrokerError, ValidationError:
            assert config["scenario"] in {"stale_context", "intent_substitution"}
            outcome = "refused"
        emit({"phase": "dispatch", "outcome": outcome, "effect_id": config["effect_id"]})
        for _ in range(3):
            command = read()
            if command["action"] == "close":
                return
            assert command["action"] == "observe"
            status = client.get_effect_status(
                TypedOperationRequest(models.EffectIdRequest(effect_id=config["effect_id"])),
                options=CallOptions(timeout=10, max_attempts=1),
            ).payload
            assert status.effect_id == config["effect_id"] and status.intent_digest == config["intent_digest"]
            emit(
                {
                    "phase": "observed",
                    "state": status.state,
                    "version": str(status.effect_version),
                    "attempts": status.attempt_count,
                    "reconciliations": status.reconciliation_count,
                }
            )
    raise AssertionError("integration driver did not receive close")


if __name__ == "__main__":
    main()
