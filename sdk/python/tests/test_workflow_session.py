from __future__ import annotations

import json
from dataclasses import replace
from importlib import resources

import pytest

from cigar_sdk import (
    MAX_WORKFLOW_DELTA_CHAIN_LENGTH,
    MAX_WORKFLOW_REPLAY_CYCLES,
    WORKFLOW_SESSION_EVENT_NAMES,
    WorkflowContextPhase,
    WorkflowContextSession,
    WorkflowEffectReplayIdentity,
    WorkflowQuarantineReason,
    WorkflowReplayDiffStatus,
    WorkflowResumeAction,
    WorkflowSessionError,
    WorkflowSessionErrorCode,
)

_DIGESTS = {character: "1220" + character * 64 for character in "0123456789abcdef"}


def _record(suffix: int) -> str:
    return f"01890f47-8e7d-7b42-a1d2-3c4d5e6f78{suffix:02x}"


def _initial_cycle(session: WorkflowContextSession) -> None:
    session.record_plan_created(_record(1), _DIGESTS["a"], _DIGESTS["1"])
    session.record_bundle_compiled(_DIGESTS["a"], _DIGESTS["1"])
    session.record_materialized(_DIGESTS["a"], _DIGESTS["2"], _DIGESTS["3"], 10)
    session.begin_model_invocation(_record(2), _DIGESTS["4"], _DIGESTS["8"])
    session.record_model_result(_record(2), _DIGESTS["5"])


def _advance_target(session: WorkflowContextSession) -> None:
    session.record_observation(_DIGESTS["6"], 1)
    session.record_plan_created(_record(3), _DIGESTS["b"], _DIGESTS["7"])
    session.record_bundle_compiled(_DIGESTS["b"], _DIGESTS["7"])
    session.record_delta_compiled(_DIGESTS["a"], _DIGESTS["b"], _DIGESTS["8"])
    session.record_delta_applied(_DIGESTS["a"], _DIGESTS["b"], _DIGESTS["8"])


def test_shared_contract_inventory_is_exact() -> None:
    contract = json.loads(
        resources.files("cigar_sdk").joinpath("workflow-context-session.v1.json").read_text(encoding="utf-8")
    )
    assert contract["schema_version"] == "cigar.sdk-workflow-context-session.v1"
    assert contract["maximum_delta_chain_length"] == MAX_WORKFLOW_DELTA_CHAIN_LENGTH
    assert contract["maximum_replay_cycles"] == MAX_WORKFLOW_REPLAY_CYCLES
    assert contract["phases"] == [phase.value for phase in WorkflowContextPhase]
    assert contract["error_codes"] == [code.value for code in WorkflowSessionErrorCode]
    assert contract["resume_actions"] == [
        {"action": action.value, "operation_id": action.operation_id} for action in WorkflowResumeAction
    ]
    assert contract["events"] == list(WORKFLOW_SESSION_EVENT_NAMES)
    assert contract["quarantine_reasons"] == [reason.value for reason in WorkflowQuarantineReason]
    assert contract["retry_fences"] == {
        "provider_invocation": "durable_invocation_and_idempotency_key_digest_required_before_call",
        "effect_retry": "durable_reconciliation_count_must_advance_before_authorized_for_retry",
    }
    assert contract["replay_comparison_dimensions"] == [
        "bundle_delta_selection",
        "materialization",
        "model_result_identity",
        "tool_effect_decisions",
        "outcome",
    ]
    assert contract["replay_verification"] == "all_exact_identity_dimensions_must_equal"
    assert contract["telemetry"] == {
        "maximum_added_series": 17,
        "label_policy": "single_closed_static_dimension_no_identifiers_or_content",
        "families": [
            "cigar_workflow_context_cycles_total",
            "cigar_workflow_context_selections_total",
            "cigar_workflow_context_delta_blocks_total",
            "cigar_workflow_context_recoveries_total",
            "cigar_workflow_context_replay_dimensions_total",
            "cigar_workflow_context_replay_verifications_total",
        ],
    }


def test_no_effect_cycle_reaches_verified_replay() -> None:
    session = WorkflowContextSession()
    _initial_cycle(session)
    _advance_target(session)
    assert session.active_bundle_id == _DIGESTS["b"]
    assert session.delta_chain_length == 1
    assert session.resume_action.value == WorkflowResumeAction.CHECKPOINT.value
    session.checkpoint_cycle()
    session.finish()
    baseline = session.replay_identity()
    exact = session.compare_replay(baseline)
    assert exact.exact_match
    delta = baseline.cycles[0].selected_delta
    assert delta is not None
    incoherent_delta = replace(delta, base_bundle_id=_DIGESTS["c"])
    incoherent_cycle = replace(baseline.cycles[0], selected_delta=incoherent_delta)
    with pytest.raises(WorkflowSessionError) as incoherent:
        session.compare_replay(replace(baseline, cycles=(incoherent_cycle,)))
    assert incoherent.value.code is WorkflowSessionErrorCode.IDENTITY_MISMATCH
    impossible_effect = WorkflowEffectReplayIdentity(
        effect_id=_record(8),
        intent_digest=_DIGESTS["9"],
        effect_version=3,
        state="succeeded",
        attempt_count=0,
        reconciliation_count=0,
    )
    impossible_cycle = replace(baseline.cycles[0], effect=impossible_effect)
    with pytest.raises(WorkflowSessionError) as impossible:
        session.compare_replay(replace(baseline, cycles=(impossible_cycle,)))
    assert impossible.value.code is WorkflowSessionErrorCode.INVALID_EVENT
    changed_cycle = replace(baseline.cycles[0], outcome_digest=_DIGESTS["d"])
    changed = replace(baseline, cycles=(changed_cycle,))
    comparison = session.compare_replay(changed)
    assert comparison.outcome is WorkflowReplayDiffStatus.DIFFERENT
    assert comparison.bundle_delta_selection is WorkflowReplayDiffStatus.EQUAL
    with pytest.raises(WorkflowSessionError) as mismatch:
        session.record_replay_verified(_DIGESTS["c"], _record(4), changed)
    assert mismatch.value.code is WorkflowSessionErrorCode.IDENTITY_MISMATCH
    assert session.phase.value == WorkflowContextPhase.FINISHED.value
    session.record_replay_verified(_DIGESTS["c"], _record(4), baseline)
    assert session.completed_turns == 1
    assert session.phase is WorkflowContextPhase.REPLAY_VERIFIED
    assert session.resume_action is WorkflowResumeAction.COMPLETE


def test_delta_chain_bound_forces_full_bundle_checkpoint() -> None:
    session = WorkflowContextSession()
    _initial_cycle(session)
    base = "a"
    for index, target in enumerate("bcdef123"):
        session.record_observation(_DIGESTS["6"], index + 1)
        session.record_plan_created(_record(index + 3), _DIGESTS[target], _DIGESTS["7"])
        session.record_bundle_compiled(_DIGESTS[target], _DIGESTS["7"])
        session.record_delta_compiled(_DIGESTS[base], _DIGESTS[target], _DIGESTS["8"])
        session.record_delta_applied(_DIGESTS[base], _DIGESTS[target], _DIGESTS["8"])
        base = target
        if index + 1 < MAX_WORKFLOW_DELTA_CHAIN_LENGTH:
            session.checkpoint_cycle()
            session.record_materialized(_DIGESTS[base], _DIGESTS["2"], _DIGESTS["3"], 10)
            session.begin_model_invocation(_record(index + 20), _DIGESTS["4"], _DIGESTS["8"])
            session.record_model_result(_record(index + 20), _DIGESTS["5"])
    assert session.delta_chain_length == MAX_WORKFLOW_DELTA_CHAIN_LENGTH

    session.checkpoint_cycle()
    session.record_materialized(_DIGESTS[base], _DIGESTS["2"], _DIGESTS["3"], 10)
    session.begin_model_invocation(_record(40), _DIGESTS["4"], _DIGESTS["8"])
    session.record_model_result(_record(40), _DIGESTS["5"])
    session.record_observation(_DIGESTS["6"], 9)
    session.record_plan_created(_record(41), _DIGESTS["4"], _DIGESTS["7"])
    session.record_bundle_compiled(_DIGESTS["4"], _DIGESTS["7"])
    assert session.phase is WorkflowContextPhase.BUNDLE_READY
    assert session.active_bundle_id == _DIGESTS["4"]
    assert session.delta_chain_length == 0
    assert session.resume_action is WorkflowResumeAction.CHECKPOINT


def test_ambiguous_effect_retry_requires_another_revalidation() -> None:
    session = WorkflowContextSession()
    effect_id = _record(8)
    _initial_cycle(session)
    session.record_effect_prepared(effect_id, _DIGESTS["9"], 1)
    _advance_target(session)
    assert session.resume_action is WorkflowResumeAction.REVALIDATE_CONTEXT_BUNDLE
    session.record_effect_revalidated(_DIGESTS["b"], valid=True)
    assert session.phase.value == WorkflowContextPhase.EFFECT_AUTHORIZATION_REVALIDATED.value
    session.record_effect_authorized(effect_id, _DIGESTS["9"], 2)
    session.record_effect_revalidated(_DIGESTS["b"], valid=True)
    session.record_effect_dispatched(effect_id, _DIGESTS["9"], 3, "unknown", 1, 0)
    with pytest.raises(WorkflowSessionError) as missing_reconciliation:
        session.record_effect_observed(effect_id, _DIGESTS["9"], 4, "authorized_for_retry", 1, 0)
    assert missing_reconciliation.value.code is WorkflowSessionErrorCode.INVALID_EVENT
    session.record_effect_observed(effect_id, _DIGESTS["9"], 4, "authorized_for_retry", 1, 1)
    with pytest.raises(WorkflowSessionError) as captured:
        session.record_effect_dispatched(effect_id, _DIGESTS["9"], 5, "succeeded", 2, 1)
    assert captured.value.code is WorkflowSessionErrorCode.INVALID_TRANSITION
    assert session.phase is WorkflowContextPhase.EFFECT_AUTHORIZED
    session.record_effect_revalidated(_DIGESTS["b"], valid=True)
    session.record_effect_dispatched(effect_id, _DIGESTS["9"], 5, "succeeded", 2, 1)
    session.checkpoint_cycle()


def test_cancellation_quarantines_a_late_provider_result() -> None:
    session = WorkflowContextSession()
    session.record_plan_created(_record(1), _DIGESTS["a"], _DIGESTS["1"])
    session.record_bundle_compiled(_DIGESTS["a"], _DIGESTS["1"])
    session.record_materialized(_DIGESTS["a"], _DIGESTS["2"], _DIGESTS["3"], 10)
    session.begin_model_invocation(_record(2), _DIGESTS["4"], _DIGESTS["8"])
    session.quarantine_context(_DIGESTS["a"], WorkflowQuarantineReason.CANCELLED)
    with pytest.raises(WorkflowSessionError) as captured:
        session.record_model_result(_record(2), _DIGESTS["5"])
    assert captured.value.code is WorkflowSessionErrorCode.INVALID_TRANSITION
    assert session.phase is WorkflowContextPhase.QUARANTINED
    assert session.resume_action is WorkflowResumeAction.COMPLETE


def test_failed_transition_is_atomic_and_content_free() -> None:
    session = WorkflowContextSession()
    with pytest.raises(WorkflowSessionError) as captured:
        session.record_bundle_compiled(_DIGESTS["a"], _DIGESTS["1"])
    assert captured.value.code is WorkflowSessionErrorCode.INVALID_TRANSITION
    assert session.phase is WorkflowContextPhase.NEW
    assert _DIGESTS["a"] not in repr(session)
