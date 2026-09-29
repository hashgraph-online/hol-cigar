"""Resume a complete effect workflow; rejected events cannot advance its state."""

from __future__ import annotations

import pytest
from test_workflow_session import _DIGESTS as D
from test_workflow_session import _record

from cigar_sdk import WorkflowContextSession, WorkflowSessionError


def steps():
    return [
        (
            "record_plan_created",
            {"plan_id": _record(1), "bundle_id": D["a"], "contract_digest": D["1"]},
            "compile_context_bundle",
        ),
        ("record_bundle_compiled", {"bundle_id": D["a"], "contract_digest": D["1"]}, "materialize_context_bundle"),
        (
            "record_materialized",
            {
                "bundle_id": D["a"],
                "tokenizer_fingerprint": D["2"],
                "materializer_fingerprint": D["3"],
                "physical_input_tokens": 10,
            },
            "begin_model_invocation",
        ),
        (
            "begin_model_invocation",
            {"invocation_id": _record(2), "request_digest": D["4"], "idempotency_key_digest": D["8"]},
            "resume_model_invocation",
        ),
        (
            "record_model_result",
            {"invocation_id": _record(2), "result_digest": D["5"]},
            "prepare_effect_or_ingest_observation",
        ),
        (
            "record_effect_prepared",
            {"effect_id": _record(8), "intent_digest": D["9"], "effect_version": 1},
            "ingest_observation",
        ),
        ("record_observation", {"publication_digest": D["6"], "revision": 1}, "create_context_plan"),
        (
            "record_plan_created",
            {"plan_id": _record(3), "bundle_id": D["b"], "contract_digest": D["7"]},
            "compile_context_bundle",
        ),
        ("record_bundle_compiled", {"bundle_id": D["b"], "contract_digest": D["7"]}, "compile_context_delta"),
        (
            "record_delta_compiled",
            {"base_bundle_id": D["a"], "target_bundle_id": D["b"], "delta_digest": D["8"]},
            "apply_context_delta",
        ),
        (
            "record_delta_applied",
            {"base_bundle_id": D["a"], "target_bundle_id": D["b"], "delta_digest": D["8"]},
            "revalidate_context_bundle",
        ),
        ("record_effect_revalidated", {"bundle_id": D["b"], "valid": True}, "authorize_effect_or_checkpoint"),
        (
            "record_effect_authorized",
            {"effect_id": _record(8), "intent_digest": D["9"], "effect_version": 2},
            "revalidate_context_bundle",
        ),
        ("record_effect_revalidated", {"bundle_id": D["b"], "valid": True}, "dispatch_effect"),
        (
            "record_effect_dispatched",
            {
                "effect_id": _record(8),
                "intent_digest": D["9"],
                "effect_version": 3,
                "state": "dispatching",
                "attempt_count": 1,
                "reconciliation_count": 0,
            },
            "observe_effect",
        ),
        (
            "record_effect_observed",
            {
                "effect_id": _record(8),
                "intent_digest": D["9"],
                "effect_version": 4,
                "state": "succeeded",
                "attempt_count": 1,
                "reconciliation_count": 0,
            },
            "checkpoint",
        ),
        ("checkpoint_cycle", {}, "materialize_or_finish"),
        ("finish", {}, "replay"),
    ]


@pytest.mark.parametrize(
    "position,field,value",
    [
        (0, "plan_id", "PRIVATE_INVALID"),
        (0, "bundle_id", "PRIVATE_INVALID"),
        (1, "bundle_id", D["f"]),
        (1, "contract_digest", D["f"]),
        (2, "bundle_id", D["f"]),
        (2, "physical_input_tokens", 0),
        (2, "physical_input_tokens", True),
        (4, "invocation_id", _record(99)),
        (5, "effect_version", 0),
        (5, "state", "authorized"),
        (5, "attempt_count", 1),
        (5, "reconciliation_count", 1),
        (6, "revision", 0),
        (9, "base_bundle_id", D["f"]),
        (9, "target_bundle_id", D["f"]),
        (10, "delta_digest", D["f"]),
        (11, "bundle_id", D["f"]),
        (11, "valid", 1),
        (12, "state", "prepared"),
        (12, "attempt_count", 1),
        (12, "effect_version", 1),
        (12, "effect_id", _record(99)),
        (12, "intent_digest", D["f"]),
        (14, "state", "prepared"),
        (14, "attempt_count", 0),
        (14, "reconciliation_count", 1),
        (15, "state", "authorized"),
        (15, "attempt_count", 0),
        (15, "effect_version", 2),
    ],
)
def test_rejected_event_preserves_recovery_and_can_be_followed_by_valid_event(position, field, value):
    session = WorkflowContextSession()
    assert session.active_bundle_id is None
    assert session.resume_action.value == "create_context_plan"
    for index, (name, arguments, expected_resume) in enumerate(steps()):
        if index == position:
            before = (session.phase, session.resume_action, session.active_bundle_id, session.completed_turns)
            with pytest.raises(WorkflowSessionError) as raised:
                getattr(session, name)(**{**arguments, field: value})
            assert "PRIVATE_INVALID" not in str(raised.value)
            assert (session.phase, session.resume_action, session.active_bundle_id, session.completed_turns) == before
        getattr(session, name)(**arguments)
        assert session.resume_action.value == expected_resume
    identity = session.replay_identity()
    assert session.compare_replay(identity).exact_match
    session.record_replay_verified(D["c"], _record(4), identity)
    assert session.resume_action.value == "complete"
