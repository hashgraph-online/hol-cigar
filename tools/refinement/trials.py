"""Immutable trial-state snapshots and crash reconciliation."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from .canonical import identity, loads, safe_relative_path
from .workspace import (
    TRIAL_ID,
    DiffPolicy,
    WorkspaceError,
    inspect_worktree,
    materialize_worktree,
    validate_worktree_record,
)

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError

STATE_NAME = re.compile(r"^states/([0-9]{20})\.json$")
PHASES = {"intent", "created", "resumable", "rejected", "cleaning", "cleaned"}
EVIDENCE_CLASSES = {"diagnostic", "development", "shadow", "promotion", "release"}


class TrialError(RuntimeError):
    """Trial state is malformed, corrupt, ambiguous, or unsafe."""


def _validate_private_directory(path: Path) -> None:
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise TrialError("trial state root must be an owner-private real directory")


def _discover(trial_root: Path) -> set[str]:
    states = trial_root / "states"
    if not states.exists():
        return set()
    _validate_private_directory(states)
    result: set[str] = set()
    with os.scandir(states) as iterator:
        for item in iterator:
            relative = f"states/{item.name}"
            if STATE_NAME.fullmatch(relative) is None:
                raise TrialError("trial state contains an unexpected filename")
            metadata = item.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or item.is_symlink()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise TrialError("trial snapshot is not an immutable regular file")
            result.add(relative)
    return result


def _unsigned(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("state_id", None)
    return result


def _validate_state(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "state_id",
        "sequence",
        "previous_state_id",
        "phase",
        "trial_id",
        "hypothesis",
        "worktree",
        "allowed_paths",
        "forbidden_paths",
        "maximum_files",
        "maximum_lines",
        "evidence_class",
        "reason",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise TrialError("trial snapshot fields are not closed")
    if value["schema_version"] != "cigar.refinement-controller-state.v1":
        raise TrialError("trial snapshot schema is unsupported")
    if (
        isinstance(value["sequence"], bool)
        or not isinstance(value["sequence"], int)
        or value["sequence"] < 0
        or value["sequence"] > 1_000_000
    ):
        raise TrialError("trial snapshot sequence is invalid")
    if value["phase"] not in PHASES or value["evidence_class"] not in EVIDENCE_CLASSES:
        raise TrialError("trial phase or evidence class is invalid")
    if (
        not isinstance(value["hypothesis"], str)
        or not 1 <= len(value["hypothesis"]) <= 4096
        or not isinstance(value["reason"], (str, type(None)))
        or (isinstance(value["reason"], str) and not 1 <= len(value["reason"]) <= 4096)
    ):
        raise TrialError("trial text is invalid")
    for name in ("allowed_paths", "forbidden_paths"):
        paths = value[name]
        if (
            not isinstance(paths, list)
            or len(paths) > 1024
            or any(not isinstance(path, str) for path in paths)
        ):
            raise TrialError("trial path inventory is invalid")
        try:
            canonical_paths = [safe_relative_path(path) for path in paths]
        except ValueError as error:
            raise TrialError("trial path inventory contains an unsafe path") from error
        if len(canonical_paths) != len(set(canonical_paths)):
            raise TrialError("trial path inventory contains duplicates")
    policy = DiffPolicy(
        allowed_paths=tuple(value["allowed_paths"]),
        forbidden_paths=tuple(value["forbidden_paths"]),
        maximum_files=value["maximum_files"],
        maximum_lines=value["maximum_lines"],
    )
    try:
        policy.validate()
    except WorkspaceError as error:
        raise TrialError("trial diff policy is invalid") from error
    try:
        validate_worktree_record(value["worktree"])
    except WorkspaceError as error:
        raise TrialError("trial worktree intent is invalid") from error
    if value["worktree"]["trial_id"] != value["trial_id"]:
        raise TrialError("trial snapshot and worktree IDs differ")
    reason_required = value["phase"] in {"rejected", "cleaning", "cleaned"}
    if reason_required != (value["reason"] is not None):
        raise TrialError("trial snapshot reason does not match its phase")
    if value["state_id"] != identity(_unsigned(value)):
        raise TrialError("trial snapshot identity does not match its content")
    return value


def _validate_transition(previous: list[dict[str, Any]], value: dict[str, Any]) -> None:
    if not previous:
        if value["phase"] != "intent":
            raise TrialError("the first trial snapshot must be intent")
        return
    first = previous[0]
    for field in (
        "trial_id",
        "hypothesis",
        "worktree",
        "allowed_paths",
        "forbidden_paths",
        "maximum_files",
        "maximum_lines",
        "evidence_class",
    ):
        if value[field] != first[field]:
            raise TrialError("trial authority fields cannot change across snapshots")
    transitions = {
        "intent": {"created", "resumable", "rejected"},
        "created": {"cleaning"},
        "resumable": {"cleaning"},
        "cleaning": {"cleaned"},
        "rejected": set(),
        "cleaned": set(),
    }
    if value["phase"] not in transitions[previous[-1]["phase"]]:
        raise TrialError("trial snapshot phase transition is invalid")


class TrialStore:
    def __init__(self, state_root: Path, *, repository_root: Path) -> None:
        if not state_root.is_absolute() or not repository_root.is_absolute():
            raise TrialError("trial and repository roots must be absolute")
        self.state_root = state_root
        self.repository_root = repository_root.resolve(strict=True)
        try:
            with EvidenceWorkspace.create(
                state_root, repository_root=self.repository_root
            ):
                pass
        except EvidenceWorkspaceError as error:
            raise TrialError("trial state root is unsafe") from error

    def trial_root(self, trial_id: str) -> Path:
        try:
            safe_relative_path(trial_id)
        except ValueError as error:
            raise TrialError("trial ID is unsafe") from error
        if TRIAL_ID.fullmatch(trial_id) is None:
            raise TrialError("trial ID is invalid")
        return self.state_root / trial_id

    def load(self, trial_id: str) -> list[dict[str, Any]]:
        root = self.trial_root(trial_id)
        if not root.exists():
            return []
        try:
            with EvidenceWorkspace.create(
                root, repository_root=self.repository_root
            ) as workspace:
                paths = _discover(workspace.root)
                payloads = workspace.read_files(paths, strict_read_only=True)
        except EvidenceWorkspaceError as error:
            raise TrialError("trial evidence workspace is unsafe") from error
        ordered = sorted(payloads)
        expected = [f"states/{index:020d}.json" for index in range(len(ordered))]
        if ordered != expected:
            raise TrialError("trial snapshot sequence is not contiguous")
        previous: str | None = None
        result: list[dict[str, Any]] = []
        for sequence, path in enumerate(ordered):
            value = _validate_state(loads(payloads[path]))
            if value["sequence"] != sequence or value["previous_state_id"] != previous:
                raise TrialError("trial snapshot chain is broken")
            if value["trial_id"] != trial_id:
                raise TrialError("trial snapshot belongs to another trial")
            previous = value["state_id"]
            result.append(value)
        return result

    def append(
        self,
        *,
        phase: str,
        trial_id: str,
        hypothesis: str,
        worktree: dict[str, Any],
        allowed_paths: list[str],
        forbidden_paths: list[str],
        maximum_files: int,
        maximum_lines: int,
        evidence_class: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        previous = self.load(trial_id)
        sequence = len(previous)
        value: dict[str, Any] = {
            "schema_version": "cigar.refinement-controller-state.v1",
            "state_id": "",
            "sequence": sequence,
            "previous_state_id": previous[-1]["state_id"] if previous else None,
            "phase": phase,
            "trial_id": trial_id,
            "hypothesis": hypothesis,
            "worktree": worktree,
            "allowed_paths": allowed_paths,
            "forbidden_paths": forbidden_paths,
            "maximum_files": maximum_files,
            "maximum_lines": maximum_lines,
            "evidence_class": evidence_class,
            "reason": reason,
        }
        value["state_id"] = identity(_unsigned(value))
        _validate_state(value)
        _validate_transition(previous, value)
        root = self.trial_root(trial_id)
        try:
            with EvidenceWorkspace.create(
                root, repository_root=self.repository_root
            ) as workspace:
                before = _discover(workspace.root)
                expected_before = {
                    f"states/{index:020d}.json" for index in range(sequence)
                }
                if before != expected_before:
                    raise TrialError("trial state changed between load and append")
                workspace.write_json(f"states/{sequence:020d}.json", value)
                workspace.read_files(
                    expected_before | {f"states/{sequence:020d}.json"},
                    strict_read_only=True,
                )
        except EvidenceWorkspaceError as error:
            raise TrialError("trial snapshot publication failed") from error
        replayed = self.load(trial_id)
        if replayed[-1] != value:
            raise TrialError("trial snapshot did not replay exactly")
        return value

    def create_or_resume(
        self,
        *,
        champion_repository: Path,
        intent: dict[str, Any],
        hypothesis: str,
        allowed_paths: list[str],
        forbidden_paths: list[str],
        maximum_files: int,
        maximum_lines: int,
        evidence_class: str,
    ) -> dict[str, Any]:
        try:
            intent = validate_worktree_record(
                intent, champion_repository=champion_repository
            )
        except WorkspaceError as error:
            raise TrialError("trial worktree intent is invalid") from error
        trial_id = intent["trial_id"]
        states = self.load(trial_id)
        if not states:
            self.append(
                phase="intent",
                trial_id=trial_id,
                hypothesis=hypothesis,
                worktree=intent,
                allowed_paths=allowed_paths,
                forbidden_paths=forbidden_paths,
                maximum_files=maximum_files,
                maximum_lines=maximum_lines,
                evidence_class=evidence_class,
            )
            states = self.load(trial_id)
        initial = states[0]
        expected = {
            "hypothesis": hypothesis,
            "worktree": intent,
            "allowed_paths": allowed_paths,
            "forbidden_paths": forbidden_paths,
            "maximum_files": maximum_files,
            "maximum_lines": maximum_lines,
            "evidence_class": evidence_class,
        }
        if any(initial[key] != value for key, value in expected.items()):
            raise TrialError("existing trial intent differs from the requested trial")
        latest = states[-1]
        if latest["phase"] in {"created", "resumable"}:
            inspection = inspect_worktree(champion_repository, intent)
            if not inspection["resumable"]:
                raise TrialError("recorded trial is no longer resumable")
            return latest
        if latest["phase"] != "intent":
            raise TrialError("trial is already terminal")
        inspection = inspect_worktree(champion_repository, intent)
        if inspection["status"] == "missing":
            try:
                materialize_worktree(champion_repository, intent)
            except WorkspaceError as error:
                self.append(
                    phase="rejected",
                    trial_id=trial_id,
                    hypothesis=hypothesis,
                    worktree=intent,
                    allowed_paths=allowed_paths,
                    forbidden_paths=forbidden_paths,
                    maximum_files=maximum_files,
                    maximum_lines=maximum_lines,
                    evidence_class=evidence_class,
                    reason="worktree_materialization_failed",
                )
                raise TrialError("trial worktree could not be materialized") from error
            phase = "created"
        elif inspection["resumable"]:
            phase = "resumable"
        else:
            raise TrialError("crashed trial worktree state is ambiguous")
        return self.append(
            phase=phase,
            trial_id=trial_id,
            hypothesis=hypothesis,
            worktree=intent,
            allowed_paths=allowed_paths,
            forbidden_paths=forbidden_paths,
            maximum_files=maximum_files,
            maximum_lines=maximum_lines,
            evidence_class=evidence_class,
        )
