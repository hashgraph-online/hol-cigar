#!/usr/bin/env python3
"""Run resumable, quota-governed CIGAR refinement iterations."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import errno
import os
from pathlib import Path
import re
import stat
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement import config
from tools.refinement.adapters import (
    AdapterError,
    BaseAdapter,
    PatchJsonAdapter,
    ProviderFailure,
    RecordedAdapter,
    SubprocessJsonlAdapter,
)
from tools.refinement.api_agent import hosted_adapter
from tools.refinement.canonical import (
    canonical_bytes,
    identity,
    load_file,
    safe_relative_path,
    secure_read,
)
from tools.refinement.commands import (
    CommandError,
    CommandRegistry,
    default_registry,
    run_named,
)
from tools.refinement.experiment import ExperimentError, schedule, validate_signal
from tools.refinement.ledger import Ledger, LedgerError
from tools.refinement.local_agent import local_adapter
from tools.refinement.loop_state import LoopState, LoopStateError
from tools.refinement.proposal import ProposalController, ProposalError
from tools.refinement.quota import QuotaError, QuotaLedger
from tools.refinement.schema import SchemaRegistry
from tools.refinement.trials import TrialError, TrialStore
from tools.refinement.workspace import (
    DiffPolicy,
    WorkspaceError,
    commit_candidate,
    inspect_worktree,
    plan_worktree,
    repository_identity,
    validate_diff,
    worktree_snapshot,
)

DECISIONS = frozenset(
    {
        "nominate",
        "reject_gate",
        "reject_leakage",
        "reject_incorrect",
        "reject_metric_gaming",
        "reject_test_weakening",
        "reject_evaluator_edit",
        "reject_invalid",
    }
)
MODES = {"suggest": 0, "patch": 1, "pr": 2}
SENSITIVE_CONTENT = (
    re.compile(rb"-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----"),
    re.compile(rb"AKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,255}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,255}"),
    re.compile(rb"CIGAR_CORPUS_(?:SHADOW|SEALED|PROMOTION|HOLDOUT)_[A-Z0-9]{16,}"),
)


class LoopError(RuntimeError):
    """A loop request is unsafe, ambiguous, exhausted, or cannot be resumed."""


class LoopFault(RuntimeError):
    """A controlled qualification fault injected after an immutable phase."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class PauseRequested(LoopError):
    """The configured external pause marker is present."""


class Evaluator(Protocol):
    evaluator_id: str

    def evaluate(
        self,
        *,
        worktree: Path,
        packet: dict[str, Any],
        diff: dict[str, Any],
        gates: dict[str, Any],
    ) -> dict[str, Any]: ...


AdapterFactory = Callable[[dict[str, Any]], BaseAdapter]
FaultHook = Callable[[str, int, str | None], None]


def _absolute(path: Path, label: str, *, must_exist: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise LoopError(f"{label} must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise LoopError(f"{label} cannot be resolved") from error
    if resolved != path:
        raise LoopError(f"{label} must not contain aliases")
    return path


def _private_directory(path: Path, label: str) -> Path:
    path = _absolute(path, label, must_exist=True)
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise LoopError(f"{label} must be an owner-private 0700 directory")
    return path


def _private_descendant(root: Path, *segments: str) -> Path:
    current = root
    for segment in segments:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", segment) is None:
            raise LoopError("private state path segment is invalid")
        current = current / segment
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = current.stat(follow_symlinks=False)
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise LoopError("private state directory metadata is unsafe")
    return current


def _reservation_id(run_id: str, trial_id: str) -> str:
    digest = identity({"run_id": run_id, "trial_id": trial_id})
    return f"quota-{digest[4:]}"


def _seal_evaluation(
    *,
    evaluator_id: str,
    trial_id: str,
    decision: str,
    failure_category: str | None,
    reasons: list[str],
    diff_snapshot_id: str,
    gate_id: str,
    metrics: list[dict[str, Any]],
    hard_invariants: list[dict[str, str]],
) -> dict[str, Any]:
    body = {
        "schema_version": "cigar.refinement-loop-evaluation.v1",
        "evaluation_id": "",
        "evaluator_id": evaluator_id,
        "trial_id": trial_id,
        "decision": decision,
        "failure_category": failure_category,
        "reasons": reasons,
        "diff_snapshot_id": diff_snapshot_id,
        "gate_id": gate_id,
        "metrics": metrics,
        "hard_invariants": hard_invariants,
    }
    unsigned = dict(body)
    unsigned.pop("evaluation_id")
    body["evaluation_id"] = identity(unsigned)
    SchemaRegistry(ROOT / "schemas" / "refinement").validate(
        "loop-evaluation-v1.schema.json", body
    )
    return body


def _sensitive_paths(worktree: Path, diff: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    for relative in diff["paths"]:
        path = worktree / safe_relative_path(relative)
        if not path.exists():
            continue
        payload = secure_read(path.absolute(), maximum_bytes=16 * 1024 * 1024)
        if any(pattern.search(payload) is not None for pattern in SENSITIVE_CONTENT):
            findings.append(relative)
    return findings


class GateOnlyEvaluator:
    """Development evaluator: hard gates and content scan nominate, never promote."""

    evaluator_id = "gate-only-development-v1"

    def evaluate(
        self,
        *,
        worktree: Path,
        packet: dict[str, Any],
        diff: dict[str, Any],
        gates: dict[str, Any],
    ) -> dict[str, Any]:
        if any(row["status"] != "passed" for row in gates["gates"]):
            return _seal_evaluation(
                evaluator_id=self.evaluator_id,
                trial_id=packet["_trial_id"],
                decision="reject_gate",
                failure_category="focused_gate_failed",
                reasons=["At least one controller-owned named gate failed."],
                diff_snapshot_id=diff["snapshot"]["snapshot_id"],
                gate_id=gates["gate_id"],
                metrics=[],
                hard_invariants=[
                    {"name": "named_gates", "status": "failed"},
                    {"name": "sensitive_content", "status": "not_evaluated"},
                ],
            )
        findings = _sensitive_paths(worktree, diff)
        if findings:
            return _seal_evaluation(
                evaluator_id=self.evaluator_id,
                trial_id=packet["_trial_id"],
                decision="reject_leakage",
                failure_category="sensitive_content_detected",
                reasons=[
                    "Changed candidate content matched a prohibited credential/canary class."
                ],
                diff_snapshot_id=diff["snapshot"]["snapshot_id"],
                gate_id=gates["gate_id"],
                metrics=[],
                hard_invariants=[
                    {"name": "named_gates", "status": "passed"},
                    {"name": "sensitive_content", "status": "failed"},
                ],
            )
        return _seal_evaluation(
            evaluator_id=self.evaluator_id,
            trial_id=packet["_trial_id"],
            decision="nominate",
            failure_category=None,
            reasons=[
                "Diff policy, named gates, and sensitive-content scan passed; "
                "candidate still requires independent benchmark and shadow evaluation."
            ],
            diff_snapshot_id=diff["snapshot"]["snapshot_id"],
            gate_id=gates["gate_id"],
            metrics=[],
            hard_invariants=[
                {"name": "named_gates", "status": "passed"},
                {"name": "sensitive_content", "status": "passed"},
            ],
        )


def _validate_evaluation(
    evaluation: dict[str, Any],
    *,
    trial_id: str,
    diff: dict[str, Any],
    gates: dict[str, Any],
) -> None:
    try:
        SchemaRegistry(ROOT / "schemas" / "refinement").validate(
            "loop-evaluation-v1.schema.json", evaluation
        )
    except ValueError as error:
        raise LoopError("loop evaluator returned a malformed record") from error
    unsigned = dict(evaluation)
    claimed = unsigned.pop("evaluation_id")
    if (
        identity(unsigned) != claimed
        or evaluation["decision"] not in DECISIONS
        or evaluation["trial_id"] != trial_id
        or evaluation["diff_snapshot_id"] != diff["snapshot"]["snapshot_id"]
        or evaluation["gate_id"] != gates["gate_id"]
    ):
        raise LoopError("loop evaluation does not bind the exact trial")
    rejected = evaluation["decision"] != "nominate"
    if rejected != (evaluation["failure_category"] is not None):
        raise LoopError("loop evaluation failure category is inconsistent")


def _usage_request(packet: dict[str, Any]) -> dict[str, int]:
    try:
        microusd = int(Decimal(str(packet["budgets"]["cost_usd"])) * Decimal(1_000_000))
    except (InvalidOperation, ValueError) as error:
        raise LoopError("task packet cost cannot be represented exactly") from error
    return {
        "input_tokens": packet["budgets"]["input_tokens"],
        "output_tokens": packet["budgets"]["output_tokens"],
        "cost_microusd": microusd,
        "compute_milliseconds": packet["budgets"]["wall_seconds"] * 1000,
    }


def _safe_gate_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: result[key]
        for key in (
            "command_id",
            "command_sha256",
            "exit_code",
            "timed_out",
            "output_overflow",
            "stdout_bytes",
            "stdout_sha256",
            "stderr_bytes",
            "stderr_sha256",
            "duration_seconds",
            "duration_sha256",
            "status",
        )
    }


class LoopController:
    """Advance one run through immutable boundaries and resume after interruptions."""

    def __init__(
        self,
        *,
        repository: Path,
        loaded_config: dict[str, Any],
        run_id: str,
        state: LoopState,
        trials: TrialStore,
        worktree_root: Path,
        command_state_root: Path,
        ledger: Ledger,
        quota: QuotaLedger,
        utc_day: str,
        signals: list[dict[str, Any]],
        history: list[dict[str, Any]],
        trial_class: str,
        adapter_profile: str,
        adapter_factory: AdapterFactory,
        evaluator: Evaluator,
        mode: str,
        maximum_iterations: int,
        maximum_estimated_cost: float,
        pause_file: Path,
        no_promotion: bool,
        registry: CommandRegistry | None = None,
        fault_hook: FaultHook | None = None,
    ) -> None:
        self.repository = repository.resolve(strict=True)
        self.config = loaded_config
        self.run_id = run_id
        self.state = state
        self.trials = trials
        self.worktree_root = _private_directory(worktree_root, "worktree root")
        self.command_state_root = _private_directory(
            command_state_root, "command state root"
        )
        self.ledger = ledger
        self.quota = quota
        self.utc_day = utc_day
        self.signals = signals
        self.history = history
        self.trial_class = trial_class
        self.adapter_profile = adapter_profile
        self.adapter_factory = adapter_factory
        self.evaluator = evaluator
        self.mode = mode
        self.maximum_iterations = maximum_iterations
        self.maximum_estimated_cost = maximum_estimated_cost
        self.pause_file = pause_file
        self.no_promotion = no_promotion
        self.registry = registry or default_registry()
        self.fault_hook = fault_hook
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", run_id) is None
            or mode not in MODES
            or MODES[mode] > MODES[loaded_config["mode"]]
            or not 1 <= maximum_iterations <= loaded_config["limits"]["max_iterations"]
            or maximum_estimated_cost < 0
            or maximum_estimated_cost > loaded_config["limits"]["max_cost_usd"]
            or not no_promotion
        ):
            raise LoopError("loop run authority exceeds its configuration")
        if not pause_file.is_absolute() or pause_file.is_symlink():
            raise LoopError("pause file must be an absolute non-symlink path")
        for signal in signals:
            validate_signal(signal)

    def _fault(self, phase: str, iteration: int, trial_id: str | None) -> None:
        if self.fault_hook is not None:
            self.fault_hook(phase, iteration, trial_id)

    def _validate_packet_authority(self, packet: dict[str, Any]) -> None:
        budgets = packet["budgets"]
        limits = self.config["limits"]
        comparisons = (
            ("input_tokens", "max_input_tokens"),
            ("output_tokens", "max_output_tokens"),
            ("wall_seconds", "max_wall_seconds"),
            ("files", "max_files_changed"),
            ("lines", "max_lines_changed"),
            ("cost_usd", "max_cost_usd"),
        )
        if any(
            budgets[packet_key] > limits[limit_key]
            for packet_key, limit_key in comparisons
        ):
            raise LoopError("scheduled task packet exceeds the run configuration")
        if budgets["cost_usd"] > self.maximum_estimated_cost:
            raise LoopError("scheduled task packet exceeds the operator cost ceiling")

    def _paused(self) -> bool:
        if not self.pause_file.exists():
            return False
        metadata = self.pause_file.stat(follow_symlinks=False)
        if (
            self.pause_file.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise LoopError("pause marker metadata is unsafe")
        return True

    def _check_pause(
        self, events: list[dict[str, Any]], iteration: int, trial_id: str | None
    ) -> None:
        if not self._paused():
            return
        effective = LoopState.effective_phase(events)
        if effective == "terminal":
            return
        self.state.append(
            run_id=self.run_id,
            iteration=iteration,
            phase="paused",
            resume_phase=effective,
            trial_id=trial_id,
            champion_revision=events[0]["champion_revision"],
            champion_tree=events[0]["champion_tree"],
            artifact_ids=[],
            status="operator_pause",
            failure_category="operator_pause",
        )
        raise PauseRequested("operator pause marker is present")

    def _phase_artifact(
        self, events: list[dict[str, Any]], phase: str, iteration: int
    ) -> Any:
        for event in reversed(events):
            if event["phase"] == phase and event["iteration"] == iteration:
                if len(event["artifact_ids"]) != 1:
                    raise LoopError("loop phase has an ambiguous artifact inventory")
                return self.state.artifact(event["artifact_ids"][0])
        raise LoopError(f"loop phase artifact is missing: {phase}")

    def _ensure_ledger(
        self,
        *,
        event_type: str,
        iteration_id: str,
        source_revision: str,
        source_tree: str,
        artifact_ids: list[str],
        decision: str | None,
    ) -> dict[str, Any]:
        matches = [
            entry
            for entry in self.ledger.replay()
            if entry["event_type"] == event_type
            and entry["iteration_id"] == iteration_id
        ]
        expected = {
            "source_revision": source_revision,
            "source_tree": source_tree,
            "artifact_ids": sorted(set(artifact_ids)),
            "evidence_class": self.config["evidence"]["class"],
            "decision": decision,
        }
        if len(matches) > 1:
            raise LoopError("ledger has duplicate phase events for one trial")
        if matches:
            entry = matches[0]
            if any(
                (sorted(entry[key]) if key == "artifact_ids" else entry[key]) != value
                for key, value in expected.items()
            ):
                raise LoopError("existing ledger phase differs from resumed state")
            return entry
        return self.ledger.append(
            event_type=event_type,
            iteration_id=iteration_id,
            source_revision=source_revision,
            source_tree=source_tree,
            artifact_ids=expected["artifact_ids"],
            evidence_class=self.config["evidence"]["class"],
            decision=decision,
        )

    def _settle_proposal(
        self,
        *,
        reservation_id: str,
        actual: dict[str, int],
    ) -> None:
        reservation = self.quota.reservation(reservation_id)
        if reservation is None:
            raise LoopError("proposal quota reservation is missing")
        if reservation["kind"] == "reserved":
            self.quota.finish(reservation_id, actual=actual)
            return
        if reservation["kind"] != "settled" or reservation["actual"] != actual:
            raise LoopError("proposal quota settlement differs from its checkpoint")

    def _reconcile_terminal(
        self,
        *,
        events: list[dict[str, Any]],
        iteration: int,
    ) -> None:
        terminal = self._phase_artifact(events, "terminal", iteration)
        trial_id = terminal["trial_id"]
        terminal_id = identity(terminal)
        early_rejection_id = terminal.get("early_rejection_id")
        if early_rejection_id is not None:
            self._ensure_ledger(
                event_type="proposal_finished",
                iteration_id=trial_id,
                source_revision=events[0]["champion_revision"],
                source_tree=events[0]["champion_tree"],
                artifact_ids=[early_rejection_id],
                decision="denied",
            )
            self._ensure_ledger(
                event_type="trial_rejected",
                iteration_id=trial_id,
                source_revision=events[0]["champion_revision"],
                source_tree=events[0]["champion_tree"],
                artifact_ids=[early_rejection_id, terminal_id],
                decision="reject_invalid",
            )
            return
        evaluation = self._phase_artifact(events, "evaluated", iteration)
        candidate = terminal["candidate"]
        source_revision = (
            candidate["revision"]
            if candidate is not None
            else events[0]["champion_revision"]
        )
        source_tree = (
            candidate["tree"] if candidate is not None else events[0]["champion_tree"]
        )
        artifact_ids = [evaluation["evaluation_id"], terminal_id]
        if candidate is not None:
            artifact_ids.append(identity(candidate))
        review_payload = terminal["review_payload"]
        if review_payload is not None:
            artifact_ids.append(review_payload["payload_id"])
        self._ensure_ledger(
            event_type=(
                "trial_nominated"
                if evaluation["decision"] == "nominate"
                else "trial_rejected"
            ),
            iteration_id=trial_id,
            source_revision=source_revision,
            source_tree=source_tree,
            artifact_ids=artifact_ids,
            decision=evaluation["decision"],
        )

    def _recover_proposed(
        self,
        *,
        events: list[dict[str, Any]],
        iteration: int,
        trial_id: str,
        packet: dict[str, Any],
        trial_state: dict[str, Any],
    ) -> bool:
        matches = self.state.unreferenced_artifacts(
            schema_version="cigar.refinement-loop-proposed.v1",
            trial_id=trial_id,
        )
        if len(matches) > 1:
            raise LoopError("multiple unreferenced proposal checkpoints exist")
        if not matches:
            return False
        artifact_id, proposed = matches[0]
        expected_reservation = _reservation_id(self.run_id, trial_id)
        if (
            set(proposed)
            != {
                "schema_version",
                "trial_id",
                "outcome",
                "diff",
                "reservation_id",
                "settled_usage",
            }
            or proposed["reservation_id"] != expected_reservation
        ):
            raise LoopError("unreferenced proposal checkpoint is malformed")
        outcome = proposed["outcome"]
        unsigned_outcome = dict(outcome)
        claimed_outcome = unsigned_outcome.pop("outcome_id", None)
        usage = outcome.get("usage")
        if (
            claimed_outcome != identity(unsigned_outcome)
            or not isinstance(usage, dict)
            or usage.get("usage_id") != outcome.get("usage_id")
        ):
            raise LoopError("unreferenced proposal outcome identity is invalid")
        worktree = Path(trial_state["worktree"]["worktree_path"])
        current_diff = validate_diff(
            worktree,
            DiffPolicy(
                allowed_paths=tuple(packet["allowed_paths"]),
                forbidden_paths=tuple(packet["forbidden_paths"]),
                maximum_files=min(
                    packet["budgets"]["files"],
                    self.config["limits"]["max_files_changed"],
                ),
                maximum_lines=min(
                    packet["budgets"]["lines"],
                    self.config["limits"]["max_lines_changed"],
                ),
            ),
        )
        if current_diff != proposed["diff"] or current_diff["changed_files"] == 0:
            raise LoopError("unreferenced proposal differs from the candidate worktree")
        self.state.append(
            run_id=self.run_id,
            iteration=iteration,
            phase="proposed",
            trial_id=trial_id,
            champion_revision=events[0]["champion_revision"],
            champion_tree=events[0]["champion_tree"],
            artifact_ids=[artifact_id],
            reservation_id=expected_reservation,
            status="proposed",
        )
        return True

    def _recover_terminal(
        self,
        *,
        events: list[dict[str, Any]],
        iteration: int,
        trial_id: str,
        evaluation: dict[str, Any],
        trial_state: dict[str, Any],
    ) -> bool:
        matches = self.state.unreferenced_artifacts(
            schema_version="cigar.refinement-loop-terminal.v1",
            trial_id=trial_id,
        )
        if len(matches) > 1:
            raise LoopError("multiple unreferenced terminal checkpoints exist")
        if not matches:
            return False
        artifact_id, terminal = matches[0]
        if (
            set(terminal)
            != {
                "schema_version",
                "trial_id",
                "decision",
                "mode",
                "candidate",
                "review_payload",
                "no_promotion",
            }
            or terminal["decision"] != evaluation["decision"]
            or terminal["mode"] != self.mode
            or terminal["no_promotion"] is not True
        ):
            raise LoopError("unreferenced terminal checkpoint is malformed")
        candidate = terminal["candidate"]
        if candidate is not None:
            worktree = Path(trial_state["worktree"]["worktree_path"])
            actual = repository_identity(worktree, require_clean=True)
            if (
                actual["revision"] != candidate["revision"]
                or actual["tree"] != candidate["tree"]
                or actual["branch"] != candidate["branch"]
                or candidate["parent_revision"] != events[0]["champion_revision"]
            ):
                raise LoopError("recovered candidate commit identity changed")
        review_payload = terminal["review_payload"]
        if review_payload is not None:
            unsigned_review = dict(review_payload)
            claimed_review = unsigned_review.pop("payload_id", None)
            if (
                claimed_review != identity(unsigned_review)
                or review_payload["merge_authority"] is not False
                or review_payload["publication_authority"] is not False
            ):
                raise LoopError("recovered review payload is unsafe")
        self.state.append(
            run_id=self.run_id,
            iteration=iteration,
            phase="terminal",
            trial_id=trial_id,
            champion_revision=events[0]["champion_revision"],
            champion_tree=events[0]["champion_tree"],
            artifact_ids=[artifact_id],
            status=evaluation["decision"],
            failure_category=evaluation["failure_category"],
            candidate_revision=(
                candidate["revision"] if candidate is not None else None
            ),
            candidate_tree=candidate["tree"] if candidate is not None else None,
        )
        return True

    def _interrupt(
        self,
        error: BaseException,
        events: list[dict[str, Any]],
        iteration: int,
        trial_id: str | None,
    ) -> dict[str, Any]:
        effective = LoopState.effective_phase(events)
        if effective is None:
            raise error
        if isinstance(error, LoopFault):
            category = error.category
        elif isinstance(error, ProviderFailure):
            category = "provider_outage"
        elif isinstance(error, QuotaError):
            category = "budget_exhausted"
        elif isinstance(error, LoopError) and "budget exhausted" in str(error):
            category = "budget_exhausted"
        elif isinstance(error, OSError) and error.errno == errno.ENOSPC:
            category = "disk_pressure"
        elif isinstance(error, (LoopStateError, LedgerError)):
            category = "evidence_publication_interruption"
        else:
            category = "controller_interruption"
        error_record = {
            "schema_version": "cigar.refinement-loop-interruption.v1",
            "category": category,
            "exception": type(error).__name__,
            "resume_phase": effective,
        }
        artifact_id = self.state.write_artifact(error_record)
        event = self.state.append(
            run_id=self.run_id,
            iteration=iteration,
            phase="interrupted",
            resume_phase=effective,
            trial_id=trial_id,
            champion_revision=events[0]["champion_revision"],
            champion_tree=events[0]["champion_tree"],
            artifact_ids=[artifact_id],
            status="resumable",
            failure_category=category,
        )
        return {
            "schema_version": "cigar.refinement-loop-result.v1",
            "run_id": self.run_id,
            "status": "interrupted",
            "failure_category": category,
            "resume_phase": effective,
            "event_id": event["event_id"],
        }

    def _early_reject(
        self,
        *,
        error: BaseException,
        events: list[dict[str, Any]],
        iteration: int,
        trial_id: str,
        reservation_id: str,
        requested: dict[str, int],
        failure_category: str | None = None,
    ) -> dict[str, Any]:
        message = str(error)
        category = failure_category or (
            "forbidden_control_surface"
            if any(
                token in message
                for token in (
                    "outside allowed",
                    "forbidden",
                    "not allowlisted",
                    "arbitrary",
                )
            )
            else "invalid_model_action"
        )
        reservation = self.quota.reservation(reservation_id)
        if reservation is not None and reservation["kind"] == "reserved":
            self.quota.finish(reservation_id, actual=requested)
        rejection = {
            "schema_version": "cigar.refinement-early-rejection.v1",
            "trial_id": trial_id,
            "decision": "reject_invalid",
            "failure_category": category,
            "exception": type(error).__name__,
            "candidate_committed": False,
            "champion_changed": False,
        }
        rejection_id = self.state.write_artifact(rejection)
        terminal_record = {
            "schema_version": "cigar.refinement-loop-terminal.v1",
            "trial_id": trial_id,
            "decision": "reject_invalid",
            "mode": self.mode,
            "candidate": None,
            "review_payload": None,
            "no_promotion": True,
            "early_rejection_id": rejection_id,
        }
        terminal_id = self.state.write_artifact(terminal_record)
        event = self.state.append(
            run_id=self.run_id,
            iteration=iteration,
            phase="terminal",
            trial_id=trial_id,
            champion_revision=events[0]["champion_revision"],
            champion_tree=events[0]["champion_tree"],
            artifact_ids=[terminal_id],
            reservation_id=reservation_id,
            status="reject_invalid",
            failure_category=category,
        )
        self._ensure_ledger(
            event_type="proposal_finished",
            iteration_id=trial_id,
            source_revision=events[0]["champion_revision"],
            source_tree=events[0]["champion_tree"],
            artifact_ids=[rejection_id],
            decision="denied",
        )
        self._ensure_ledger(
            event_type="trial_rejected",
            iteration_id=trial_id,
            source_revision=events[0]["champion_revision"],
            source_tree=events[0]["champion_tree"],
            artifact_ids=[rejection_id, identity(terminal_record)],
            decision="reject_invalid",
        )
        return event

    def _contract_body(
        self,
        champion: dict[str, str],
        *,
        started_at_utc: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": "cigar.refinement-loop-contract.v1",
            "run_id": self.run_id,
            "started_at_utc": started_at_utc,
            "champion": {
                "revision": champion["revision"],
                "tree": champion["tree"],
            },
            "config_profile": self.config["profile_id"],
            "config_id": identity(self.config),
            "operations_policy_id": self.quota.policy["policy_id"],
            "utc_day": self.utc_day,
            "evidence_class": self.config["evidence"]["class"],
            "adapter_profile": self.adapter_profile,
            "evaluator_id": self.evaluator.evaluator_id,
            "mode": self.mode,
            "maximum_iterations": self.maximum_iterations,
            "maximum_estimated_cost": self.maximum_estimated_cost,
            "signal_ids": sorted(signal["signal_id"] for signal in self.signals),
            "history_ids": sorted(identity(item) for item in self.history),
            "no_promotion": True,
        }

    def _start(self) -> list[dict[str, Any]]:
        events = self.state.replay()
        champion = repository_identity(self.repository, require_clean=True)
        if events:
            if (
                events[0]["champion_revision"] != champion["revision"]
                or events[0]["champion_tree"] != champion["tree"]
            ):
                raise LoopError("champion changed while the loop run was resumable")
            if len(events[0]["artifact_ids"]) != 1:
                raise LoopError("loop start contract inventory is ambiguous")
            contract = self.state.artifact(events[0]["artifact_ids"][0])
            if not isinstance(contract, dict):
                raise LoopError("loop start contract is malformed")
            started_at = contract.get("started_at_utc")
            if not isinstance(started_at, str):
                raise LoopError("loop start time is missing")
            expected = self._contract_body(
                {
                    "revision": champion["revision"],
                    "tree": champion["tree"],
                },
                started_at_utc=started_at,
            )
            expected["contract_id"] = identity(expected)
            if contract != expected:
                raise LoopError("resumed loop authority differs from its contract")
            return events
        started_at = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        contract_body = self._contract_body(
            {
                "revision": champion["revision"],
                "tree": champion["tree"],
            },
            started_at_utc=started_at,
        )
        contract = {**contract_body, "contract_id": identity(contract_body)}
        artifact_id = self.state.write_artifact(contract)
        self.state.append(
            run_id=self.run_id,
            iteration=0,
            phase="started",
            trial_id=None,
            champion_revision=champion["revision"],
            champion_tree=champion["tree"],
            artifact_ids=[artifact_id],
            status="running",
        )
        return self.state.replay()

    def run(self) -> dict[str, Any]:
        with self.state.exclusive():
            return self._run_exclusive()

    def _run_exclusive(self) -> dict[str, Any]:
        events = self._start()
        contract = self.state.artifact(events[0]["artifact_ids"][0])
        try:
            started_at = datetime.fromisoformat(
                contract["started_at_utc"].replace("Z", "+00:00")
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise LoopError("loop start time is malformed") from error
        if started_at.tzinfo is None:
            raise LoopError("loop start time lacks a timezone")
        iteration = events[-1]["iteration"]
        trial_id = events[-1]["trial_id"]
        try:
            while True:
                events = self.state.replay()
                effective = LoopState.effective_phase(events)
                completed = sum(event["phase"] == "terminal" for event in events)
                elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
                if elapsed < -300:
                    raise LoopError("loop start time is implausibly in the future")
                if elapsed >= self.config["limits"]["max_wall_seconds"]:
                    raise LoopError("loop wall-time budget exhausted")
                if effective == "terminal" and completed >= self.maximum_iterations:
                    self._reconcile_terminal(
                        events=events,
                        iteration=events[-1]["iteration"],
                    )
                    terminal = self._phase_artifact(
                        events,
                        "terminal",
                        events[-1]["iteration"],
                    )
                    candidate = terminal["candidate"]
                    return {
                        "schema_version": "cigar.refinement-loop-result.v1",
                        "run_id": self.run_id,
                        "status": "completed",
                        "iterations": completed,
                        "event_id": events[-1]["event_id"],
                        "last_trial_id": terminal["trial_id"],
                        "last_decision": terminal["decision"],
                        "candidate_revision": (
                            candidate["revision"] if candidate is not None else None
                        ),
                        "no_promotion": True,
                    }
                iteration = (
                    events[-1]["iteration"] + 1
                    if effective == "terminal"
                    else events[-1]["iteration"]
                )
                trial_id = None if effective in {"started", "terminal"} else trial_id
                self._check_pause(events, iteration, trial_id)

                if effective in {"started", "terminal"}:
                    champion = {
                        "revision": events[0]["champion_revision"],
                        "tree": events[0]["champion_tree"],
                    }
                    try:
                        scheduling, packet = schedule(
                            signals=self.signals,
                            history=self.history,
                            ledger_entries=self.ledger.replay(),
                            champion=champion,
                            trial_class=self.trial_class,
                            maximum_estimated_cost=self.maximum_estimated_cost,
                            families_path=self.repository
                            / self.config["paths"]["intervention_families"],
                        )
                    except ExperimentError as error:
                        if "no eligible opportunity" not in str(error):
                            raise
                        return {
                            "schema_version": "cigar.refinement-loop-result.v1",
                            "run_id": self.run_id,
                            "status": "exhausted",
                            "iterations": completed,
                            "event_id": events[-1]["event_id"],
                            "no_promotion": True,
                        }
                    trial_id = scheduling["selected_trial_id"]
                    scheduled_artifact = {
                        "schema_version": "cigar.refinement-loop-scheduled.v1",
                        "schedule": scheduling,
                        "packet": packet,
                    }
                    artifact_id = self.state.write_artifact(scheduled_artifact)
                    self.state.append(
                        run_id=self.run_id,
                        iteration=iteration,
                        phase="scheduled",
                        trial_id=trial_id,
                        champion_revision=champion["revision"],
                        champion_tree=champion["tree"],
                        artifact_ids=[artifact_id],
                        status="scheduled",
                    )
                    self._fault("scheduled", iteration, trial_id)
                    events = self.state.replay()
                    effective = "scheduled"

                scheduled = self._phase_artifact(events, "scheduled", iteration)
                scheduling = scheduled["schedule"]
                packet = scheduled["packet"]
                trial_id = scheduling["selected_trial_id"]
                self._validate_packet_authority(packet)

                if effective == "scheduled":
                    self._ensure_ledger(
                        event_type="trial_created",
                        iteration_id=trial_id,
                        source_revision=events[0]["champion_revision"],
                        source_tree=events[0]["champion_tree"],
                        artifact_ids=[
                            scheduling["decision_id"],
                            packet["packet_id"],
                        ],
                        decision="scheduled",
                    )
                    states = self.trials.load(trial_id)
                    intent = (
                        states[0]["worktree"]
                        if states
                        else plan_worktree(
                            self.repository,
                            self.worktree_root,
                            trial_id=trial_id,
                            champion_ref=events[0]["champion_revision"],
                        )
                    )
                    trial_state = self.trials.create_or_resume(
                        champion_repository=self.repository,
                        intent=intent,
                        hypothesis=packet["hypothesis"],
                        allowed_paths=packet["allowed_paths"],
                        forbidden_paths=packet["forbidden_paths"],
                        maximum_files=min(
                            packet["budgets"]["files"],
                            self.config["limits"]["max_files_changed"],
                        ),
                        maximum_lines=min(
                            packet["budgets"]["lines"],
                            self.config["limits"]["max_lines_changed"],
                        ),
                        evidence_class=self.config["evidence"]["class"],
                    )
                    artifact_id = self.state.write_artifact(trial_state)
                    self.state.append(
                        run_id=self.run_id,
                        iteration=iteration,
                        phase="materialized",
                        trial_id=trial_id,
                        champion_revision=events[0]["champion_revision"],
                        champion_tree=events[0]["champion_tree"],
                        artifact_ids=[artifact_id],
                        status="materialized",
                    )
                    self._fault("materialized", iteration, trial_id)
                    events = self.state.replay()
                    effective = "materialized"

                trial_state = self._phase_artifact(events, "materialized", iteration)
                worktree = Path(trial_state["worktree"]["worktree_path"])

                if effective == "materialized":
                    if self._recover_proposed(
                        events=events,
                        iteration=iteration,
                        trial_id=trial_id,
                        packet=packet,
                        trial_state=trial_state,
                    ):
                        events = self.state.replay()
                        effective = "proposed"
                    inspection = inspect_worktree(
                        self.repository, trial_state["worktree"]
                    )
                    if effective == "materialized" and (
                        not inspection["resumable"] or not inspection["clean"]
                    ):
                        reservation_id = _reservation_id(self.run_id, trial_id)
                        self._early_reject(
                            error=LoopError(
                                "proposal mutation has no published checkpoint"
                            ),
                            events=events,
                            iteration=iteration,
                            trial_id=trial_id,
                            reservation_id=reservation_id,
                            requested=_usage_request(packet),
                            failure_category="evidence_publication_interruption",
                        )
                        continue
                    if effective == "materialized" and not inspection["clean"]:
                        raise LoopError(
                            "pre-proposal worktree is not clean and exactly resumable"
                        )
                    if effective == "materialized":
                        self._check_pause(events, iteration, trial_id)
                if effective == "materialized":
                    adapter = self.adapter_factory(packet)
                    reservation_id = _reservation_id(self.run_id, trial_id)
                    requested = _usage_request(packet)
                    reservation = self.quota.reservation(reservation_id)
                    if reservation is None:
                        self.quota.reserve(
                            utc_day=self.utc_day,
                            provider_id=adapter.adapter_id,
                            reservation_id=reservation_id,
                            requested=requested,
                        )
                    elif reservation["kind"] != "reserved":
                        raise LoopError(
                            "proposal quota reservation is already terminal"
                        )
                    command_root = _private_descendant(
                        self.command_state_root,
                        self.run_id,
                        trial_id,
                        "proposal",
                    )
                    started = time.monotonic()
                    controller = ProposalController(
                        worktree=worktree,
                        task_packet=packet,
                        adapter=adapter,
                        registry=self.registry,
                        command_state=command_root,
                        maximum_repairs=self.config["proposal"]["maximum_repairs"],
                    )
                    try:
                        outcome = controller.run()
                    except ProviderFailure:
                        raise
                    except (AdapterError, ProposalError) as error:
                        self._early_reject(
                            error=error,
                            events=events,
                            iteration=iteration,
                            trial_id=trial_id,
                            reservation_id=reservation_id,
                            requested=requested,
                        )
                        continue
                    usage = outcome["usage"]
                    actual = {
                        "input_tokens": min(
                            usage["input_tokens"], requested["input_tokens"]
                        ),
                        "output_tokens": min(
                            usage["output_tokens"], requested["output_tokens"]
                        ),
                        "cost_microusd": requested["cost_microusd"],
                        "compute_milliseconds": min(
                            int((time.monotonic() - started) * 1000),
                            requested["compute_milliseconds"],
                        ),
                    }
                    diff = validate_diff(
                        worktree,
                        DiffPolicy(
                            allowed_paths=tuple(packet["allowed_paths"]),
                            forbidden_paths=tuple(packet["forbidden_paths"]),
                            maximum_files=min(
                                packet["budgets"]["files"],
                                self.config["limits"]["max_files_changed"],
                            ),
                            maximum_lines=min(
                                packet["budgets"]["lines"],
                                self.config["limits"]["max_lines_changed"],
                            ),
                        ),
                    )
                    if diff["changed_files"] == 0:
                        raise LoopError("proposal completed without a candidate diff")
                    proposed = {
                        "schema_version": "cigar.refinement-loop-proposed.v1",
                        "trial_id": trial_id,
                        "outcome": outcome,
                        "diff": diff,
                        "reservation_id": reservation_id,
                        "settled_usage": actual,
                    }
                    artifact_id = self.state.write_artifact(proposed)
                    self.state.append(
                        run_id=self.run_id,
                        iteration=iteration,
                        phase="proposed",
                        trial_id=trial_id,
                        champion_revision=events[0]["champion_revision"],
                        champion_tree=events[0]["champion_tree"],
                        artifact_ids=[artifact_id],
                        reservation_id=reservation_id,
                        status="proposed",
                    )
                    self._fault("proposed", iteration, trial_id)
                    events = self.state.replay()
                    effective = "proposed"

                proposed = self._phase_artifact(events, "proposed", iteration)
                diff = proposed["diff"]
                self._settle_proposal(
                    reservation_id=proposed["reservation_id"],
                    actual=proposed["settled_usage"],
                )
                self._ensure_ledger(
                    event_type="proposal_finished",
                    iteration_id=trial_id,
                    source_revision=events[0]["champion_revision"],
                    source_tree=events[0]["champion_tree"],
                    artifact_ids=[
                        proposed["outcome"]["outcome_id"],
                        diff["snapshot"]["snapshot_id"],
                        proposed["outcome"]["usage"]["usage_id"],
                    ],
                    decision=proposed["outcome"]["terminal_kind"],
                )

                if effective == "proposed":
                    self._check_pause(events, iteration, trial_id)
                    gate_results: list[dict[str, Any]] = []
                    before = worktree_snapshot(worktree)
                    for gate in packet["named_gates"]:
                        command_state = _private_descendant(
                            self.command_state_root,
                            self.run_id,
                            trial_id,
                            f"gate-{gate}",
                        )
                        gate_results.append(
                            {
                                "gate": gate,
                                **_safe_gate_result(
                                    run_named(
                                        self.registry,
                                        gate,
                                        cwd=worktree,
                                        state=command_state,
                                    )
                                ),
                            }
                        )
                    after = worktree_snapshot(worktree)
                    if after["snapshot_id"] != before["snapshot_id"]:
                        raise LoopError("named gates changed the candidate source")
                    gate_body = {
                        "schema_version": "cigar.refinement-loop-gates.v1",
                        "trial_id": trial_id,
                        "before_snapshot_id": before["snapshot_id"],
                        "after_snapshot_id": after["snapshot_id"],
                        "gates": gate_results,
                    }
                    gates = {**gate_body, "gate_id": identity(gate_body)}
                    artifact_id = self.state.write_artifact(gates)
                    self.state.append(
                        run_id=self.run_id,
                        iteration=iteration,
                        phase="gated",
                        trial_id=trial_id,
                        champion_revision=events[0]["champion_revision"],
                        champion_tree=events[0]["champion_tree"],
                        artifact_ids=[artifact_id],
                        status=(
                            "passed"
                            if all(row["status"] == "passed" for row in gate_results)
                            else "failed"
                        ),
                    )
                    self._fault("gated", iteration, trial_id)
                    events = self.state.replay()
                    effective = "gated"

                gates = self._phase_artifact(events, "gated", iteration)
                gate_decision = (
                    "passed"
                    if all(row["status"] == "passed" for row in gates["gates"])
                    else "failed"
                )
                self._ensure_ledger(
                    event_type="gate_finished",
                    iteration_id=trial_id,
                    source_revision=events[0]["champion_revision"],
                    source_tree=events[0]["champion_tree"],
                    artifact_ids=[gates["gate_id"]],
                    decision=gate_decision,
                )

                if effective == "gated":
                    self._check_pause(events, iteration, trial_id)
                    evaluation = self.evaluator.evaluate(
                        worktree=worktree,
                        packet={**packet, "_trial_id": trial_id},
                        diff=diff,
                        gates=gates,
                    )
                    _validate_evaluation(
                        evaluation,
                        trial_id=trial_id,
                        diff=diff,
                        gates=gates,
                    )
                    artifact_id = self.state.write_artifact(evaluation)
                    self.state.append(
                        run_id=self.run_id,
                        iteration=iteration,
                        phase="evaluated",
                        trial_id=trial_id,
                        champion_revision=events[0]["champion_revision"],
                        champion_tree=events[0]["champion_tree"],
                        artifact_ids=[artifact_id],
                        status=evaluation["decision"],
                        failure_category=evaluation["failure_category"],
                    )
                    self._fault("evaluated", iteration, trial_id)
                    events = self.state.replay()
                    effective = "evaluated"

                evaluation = self._phase_artifact(events, "evaluated", iteration)
                self._ensure_ledger(
                    event_type="evaluation_finished",
                    iteration_id=trial_id,
                    source_revision=events[0]["champion_revision"],
                    source_tree=events[0]["champion_tree"],
                    artifact_ids=[evaluation["evaluation_id"]],
                    decision=evaluation["decision"],
                )

                if effective == "evaluated":
                    if self._recover_terminal(
                        events=events,
                        iteration=iteration,
                        trial_id=trial_id,
                        evaluation=evaluation,
                        trial_state=trial_state,
                    ):
                        continue
                    self._fault("before_terminal", iteration, trial_id)
                    candidate: dict[str, Any] | None = None
                    review_payload: dict[str, Any] | None = None
                    if evaluation["decision"] == "nominate" and self.mode != "suggest":
                        candidate = commit_candidate(
                            self.repository,
                            trial_state["worktree"],
                            diff,
                            packet_id=packet["packet_id"],
                        )
                        if self.mode == "pr":
                            review_body = {
                                "schema_version": "cigar.refinement-pr-payload.v1",
                                "operation": "create-review-request-only",
                                "trial_id": trial_id,
                                "base_revision": events[0]["champion_revision"],
                                "candidate_revision": candidate["revision"],
                                "candidate_tree": candidate["tree"],
                                "branch": candidate["branch"],
                                "evaluation_id": evaluation["evaluation_id"],
                                "merge_authority": False,
                                "publication_authority": False,
                            }
                            review_payload = {
                                **review_body,
                                "payload_id": identity(review_body),
                            }
                    terminal_record = {
                        "schema_version": "cigar.refinement-loop-terminal.v1",
                        "trial_id": trial_id,
                        "decision": evaluation["decision"],
                        "mode": self.mode,
                        "candidate": candidate,
                        "review_payload": review_payload,
                        "no_promotion": True,
                    }
                    artifact_id = self.state.write_artifact(terminal_record)
                    source_revision = (
                        candidate["revision"]
                        if candidate is not None
                        else events[0]["champion_revision"]
                    )
                    source_tree = (
                        candidate["tree"]
                        if candidate is not None
                        else events[0]["champion_tree"]
                    )
                    terminal_event = self.state.append(
                        run_id=self.run_id,
                        iteration=iteration,
                        phase="terminal",
                        trial_id=trial_id,
                        champion_revision=events[0]["champion_revision"],
                        champion_tree=events[0]["champion_tree"],
                        artifact_ids=[artifact_id],
                        status=evaluation["decision"],
                        failure_category=evaluation["failure_category"],
                        candidate_revision=(
                            candidate["revision"] if candidate is not None else None
                        ),
                        candidate_tree=(
                            candidate["tree"] if candidate is not None else None
                        ),
                    )
                    domain_ids = [
                        evaluation["evaluation_id"],
                        identity(terminal_record),
                    ]
                    if candidate is not None:
                        domain_ids.append(identity(candidate))
                    if review_payload is not None:
                        domain_ids.append(review_payload["payload_id"])
                    self._ensure_ledger(
                        event_type=(
                            "trial_nominated"
                            if evaluation["decision"] == "nominate"
                            else "trial_rejected"
                        ),
                        iteration_id=trial_id,
                        source_revision=source_revision,
                        source_tree=source_tree,
                        artifact_ids=domain_ids,
                        decision=evaluation["decision"],
                    )
                    self._fault("terminal", iteration, trial_id)
                    events = self.state.replay()
                    effective = "terminal"
                    if (
                        sum(event["phase"] == "terminal" for event in events)
                        >= self.maximum_iterations
                    ):
                        return {
                            "schema_version": "cigar.refinement-loop-result.v1",
                            "run_id": self.run_id,
                            "status": "completed",
                            "iterations": sum(
                                event["phase"] == "terminal" for event in events
                            ),
                            "event_id": terminal_event["event_id"],
                            "last_trial_id": trial_id,
                            "last_decision": evaluation["decision"],
                            "candidate_revision": (
                                candidate["revision"] if candidate is not None else None
                            ),
                            "no_promotion": True,
                        }
        except PauseRequested:
            latest = self.state.replay()[-1]
            return {
                "schema_version": "cigar.refinement-loop-result.v1",
                "run_id": self.run_id,
                "status": "paused",
                "resume_phase": latest["resume_phase"],
                "event_id": latest["event_id"],
                "no_promotion": True,
            }
        except (
            AdapterError,
            CommandError,
            ExperimentError,
            LedgerError,
            LoopError,
            LoopFault,
            LoopStateError,
            OSError,
            ProposalError,
            QuotaError,
            TrialError,
            WorkspaceError,
        ) as error:
            return self._interrupt(
                error,
                self.state.replay(),
                iteration,
                trial_id,
            )


def load_adapter_profile(path: Path, profile_id: str) -> dict[str, Any]:
    value = load_file(path)
    SchemaRegistry(ROOT / "schemas" / "refinement").validate(
        "adapter-profiles-v1.schema.json", value
    )
    profiles = [
        profile for profile in value["profiles"] if profile["profile_id"] == profile_id
    ]
    if len(profiles) != 1:
        raise LoopError("proposal adapter profile is missing or duplicated")
    return profiles[0]


def adapter_factory_from_profile(
    profile: dict[str, Any],
    *,
    maximum_turns: int,
    recorded_actions: Path | None = None,
    subprocess_executable: Path | None = None,
    patch_response: Path | None = None,
) -> AdapterFactory:
    adapter_id = profile["adapter"]

    def build(_packet: dict[str, Any]) -> BaseAdapter:
        if adapter_id == "openai-responses-tools-v1":
            return hosted_adapter(
                model=profile["model"],
                credential_handle=profile["credential_handle"],
                maximum_turns=maximum_turns,
            )
        if adapter_id == "openai-compatible-tools-v1":
            return local_adapter(
                endpoint=profile["endpoint"],
                model=profile["model"],
                maximum_turns=maximum_turns,
            )
        if adapter_id == "recorded-proposal-v1":
            if recorded_actions is None:
                raise LoopError("recorded adapter requires --recorded-actions")
            actions = load_file(recorded_actions)
            if not isinstance(actions, list):
                raise LoopError("recorded action stream is not an array")
            return RecordedAdapter(actions, maximum_turns=maximum_turns)
        if adapter_id == "subprocess-jsonl-v1":
            if subprocess_executable is None:
                raise LoopError("subprocess adapter requires --subprocess-executable")
            return SubprocessJsonlAdapter(
                subprocess_executable,
                tuple(profile["arguments"]),
                maximum_turns=maximum_turns,
                timeout_seconds=profile["timeout_seconds"],
            )
        if adapter_id == "patch-json-v1":
            if patch_response is None:
                raise LoopError("patch adapter requires --patch-response")
            payload = secure_read(patch_response)
            return PatchJsonAdapter(
                lambda _packet: payload,
                maximum_turns=min(maximum_turns, 2),
            )
        raise LoopError("proposal adapter profile is unsupported")

    return build


def _load_signals(path: Path) -> list[dict[str, Any]]:
    value = load_file(path)
    try:
        SchemaRegistry(ROOT / "schemas" / "refinement").validate(
            "opportunities-v1.schema.json", value
        )
    except ValueError as error:
        raise LoopError("opportunity registry fails its schema") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "registry_id", "signals"}
        or value["schema_version"] != "cigar.refinement-opportunities.v1"
        or not isinstance(value["signals"], list)
    ):
        raise LoopError("opportunity registry is malformed")
    unsigned = dict(value)
    unsigned.pop("registry_id")
    if value["registry_id"] != identity(unsigned):
        raise LoopError("opportunity registry identity is invalid")
    for signal in value["signals"]:
        validate_signal(signal)
    return value["signals"]


def _load_history(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    value = load_file(path)
    try:
        SchemaRegistry(ROOT / "schemas" / "refinement").validate(
            "trial-history-set-v1.schema.json", value
        )
    except ValueError as error:
        raise LoopError("trial-history registry fails its schema") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "registry_id", "history"}
        or value["schema_version"] != "cigar.refinement-trial-history-set.v1"
        or not isinstance(value["history"], list)
    ):
        raise LoopError("trial-history registry is malformed")
    unsigned = dict(value)
    unsigned.pop("registry_id")
    if value["registry_id"] != identity(unsigned):
        raise LoopError("trial-history registry identity is invalid")
    registry = SchemaRegistry(ROOT / "schemas" / "refinement")
    for row in value["history"]:
        registry.validate("trial-history-v1.schema.json", row)
    return value["history"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--loop-state-root", type=Path, required=True)
    parser.add_argument("--trial-state-root", type=Path, required=True)
    parser.add_argument("--worktree-root", type=Path, required=True)
    parser.add_argument("--command-state-root", type=Path, required=True)
    parser.add_argument("--ledger-root", type=Path, required=True)
    parser.add_argument("--quota-root", type=Path, required=True)
    parser.add_argument("--operations-policy", type=Path, required=True)
    parser.add_argument("--signals", type=Path, required=True)
    parser.add_argument("--history", type=Path)
    parser.add_argument(
        "--trial-class", choices=("product", "infrastructure"), default="product"
    )
    parser.add_argument("--adapter-profile", required=True)
    parser.add_argument("--recorded-actions", type=Path)
    parser.add_argument("--subprocess-executable", type=Path)
    parser.add_argument("--patch-response", type=Path)
    parser.add_argument("--mode", choices=("suggest", "patch", "pr"), required=True)
    parser.add_argument("--max-iterations", type=int, required=True)
    parser.add_argument("--maximum-estimated-cost", type=float, required=True)
    parser.add_argument("--pause-file", type=Path, required=True)
    parser.add_argument("--utc-day")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--no-promotion", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository = _absolute(arguments.repository, "repository", must_exist=True)
        config_path = _absolute(arguments.config, "config", must_exist=True)
        loaded = config.load(config_path)
        profile_path = (repository / loaded["paths"]["proposal_profiles"]).resolve(
            strict=True
        )
        profile = load_adapter_profile(profile_path, arguments.adapter_profile)
        if arguments.offline and profile["adapter"] == "openai-responses-tools-v1":
            raise LoopError("offline mode forbids the hosted adapter")
        signals = _load_signals(
            _absolute(arguments.signals, "signals", must_exist=True)
        )
        history = _load_history(
            _absolute(arguments.history, "history", must_exist=True)
            if arguments.history is not None
            else None
        )
        if arguments.dry_run:
            champion = repository_identity(repository, require_clean=True)
            decision, packet = schedule(
                signals=signals,
                history=history,
                ledger_entries=Ledger(
                    _absolute(arguments.ledger_root, "ledger root", must_exist=True),
                    repository_root=repository,
                ).replay(),
                champion={
                    "revision": champion["revision"],
                    "tree": champion["tree"],
                },
                trial_class=arguments.trial_class,
                maximum_estimated_cost=arguments.maximum_estimated_cost,
                families_path=repository / loaded["paths"]["intervention_families"],
            )
            result = {
                "schema_version": "cigar.refinement-loop-dry-run.v1",
                "status": "planned",
                "run_id": arguments.run_id,
                "schedule_decision_id": decision["decision_id"],
                "trial_id": decision["selected_trial_id"],
                "packet_id": packet["packet_id"],
                "credentials_resolved": False,
                "state_mutated": False,
            }
        else:
            utc_day = arguments.utc_day or datetime.now(timezone.utc).date().isoformat()
            factory = adapter_factory_from_profile(
                profile,
                maximum_turns=loaded["proposal"]["maximum_turns"],
                recorded_actions=(
                    _absolute(
                        arguments.recorded_actions,
                        "recorded actions",
                        must_exist=True,
                    )
                    if arguments.recorded_actions is not None
                    else None
                ),
                subprocess_executable=(
                    _absolute(
                        arguments.subprocess_executable,
                        "subprocess executable",
                        must_exist=True,
                    )
                    if arguments.subprocess_executable is not None
                    else None
                ),
                patch_response=(
                    _absolute(
                        arguments.patch_response,
                        "patch response",
                        must_exist=True,
                    )
                    if arguments.patch_response is not None
                    else None
                ),
            )
            result = LoopController(
                repository=repository,
                loaded_config=loaded,
                run_id=arguments.run_id,
                state=LoopState(
                    _absolute(
                        arguments.loop_state_root,
                        "loop state root",
                        must_exist=False,
                    ),
                    repository_root=repository,
                ),
                trials=TrialStore(
                    _absolute(
                        arguments.trial_state_root,
                        "trial state root",
                        must_exist=False,
                    ),
                    repository_root=repository,
                ),
                worktree_root=_private_directory(
                    arguments.worktree_root, "worktree root"
                ),
                command_state_root=_private_directory(
                    arguments.command_state_root, "command state root"
                ),
                ledger=Ledger(
                    _absolute(arguments.ledger_root, "ledger root", must_exist=True),
                    repository_root=repository,
                ),
                quota=QuotaLedger(
                    _absolute(arguments.quota_root, "quota root", must_exist=False),
                    repository_root=repository,
                    policy_path=_absolute(
                        arguments.operations_policy,
                        "operations policy",
                        must_exist=True,
                    ),
                ),
                utc_day=utc_day,
                signals=signals,
                history=history,
                trial_class=arguments.trial_class,
                adapter_profile=arguments.adapter_profile,
                adapter_factory=factory,
                evaluator=GateOnlyEvaluator(),
                mode=arguments.mode,
                maximum_iterations=arguments.max_iterations,
                maximum_estimated_cost=arguments.maximum_estimated_cost,
                pause_file=arguments.pause_file,
                no_promotion=arguments.no_promotion,
            ).run()
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0 if result["status"] in {"planned", "completed", "exhausted"} else 3
    except (
        AdapterError,
        CommandError,
        ExperimentError,
        LedgerError,
        LoopError,
        LoopStateError,
        OSError,
        ProposalError,
        QuotaError,
        TrialError,
        ValueError,
        WorkspaceError,
        config.ConfigError,
    ) as error:
        print(f"refinement loop: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
