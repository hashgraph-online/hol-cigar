"""Immutable content-addressed state for resumable refinement-loop runs."""

from __future__ import annotations

# ruff: noqa: E402

import os
import re
import stat
import sys
import fcntl
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .canonical import identity, loads, secure_read
from .schema import SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError

EVENT_SCHEMA = "loop-event-v1.schema.json"
EVENT_NAME = re.compile(r"^events/([0-9]{20})\.json$")
ARTIFACT_NAME = re.compile(r"^artifacts/(1220[0-9a-f]{64})\.json$")
PHASES = (
    "started",
    "scheduled",
    "materialized",
    "proposed",
    "gated",
    "evaluated",
    "terminal",
)
TRANSITIONS = {
    "started": {"scheduled"},
    "scheduled": {"materialized"},
    "materialized": {"proposed", "terminal"},
    "proposed": {"gated"},
    "gated": {"evaluated"},
    "evaluated": {"terminal"},
    "terminal": {"scheduled"},
}


class LoopStateError(RuntimeError):
    """A loop event/artifact inventory is corrupt, ambiguous, or not append-only."""


def _without_id(event: dict[str, Any]) -> dict[str, Any]:
    result = dict(event)
    result.pop("event_id", None)
    return result


class LoopState:
    """One external run journal containing immutable events and aggregate artifacts."""

    def __init__(self, root: Path, *, repository_root: Path) -> None:
        if not root.is_absolute() or not repository_root.is_absolute():
            raise LoopStateError("loop state and repository roots must be absolute")
        self.root = root
        self.repository_root = repository_root.resolve(strict=True)
        if (
            root == self.repository_root
            or self.repository_root in root.parents
            or root in self.repository_root.parents
        ):
            raise LoopStateError("loop state must be external to the repository")
        self.registry = SchemaRegistry(self.repository_root / "schemas" / "refinement")
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ):
                pass
        except EvidenceWorkspaceError as error:
            raise LoopStateError("loop state workspace is unsafe") from error

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        """Hold the single-controller lease for this run without following links."""

        path = self.root / ".controller.lock"
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise LoopStateError("controller lock metadata is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LoopStateError(
                    "another controller already holds this run"
                ) from error
            yield
        except OSError as error:
            raise LoopStateError("controller lock cannot be acquired") from error
        finally:
            if descriptor >= 0:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def _inventory(self) -> tuple[list[str], list[str]]:
        events: list[str] = []
        artifacts: list[str] = []
        for directory_name, pattern, selected in (
            ("events", EVENT_NAME, events),
            ("artifacts", ARTIFACT_NAME, artifacts),
        ):
            directory = self.root / directory_name
            if not directory.exists():
                continue
            metadata = directory.stat(follow_symlinks=False)
            if (
                directory.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise LoopStateError("loop state directory metadata is unsafe")
            try:
                iterator = os.scandir(directory)
            except OSError as error:
                raise LoopStateError("loop state cannot be enumerated") from error
            with iterator:
                for item in iterator:
                    relative = f"{directory_name}/{item.name}"
                    metadata = item.stat(follow_symlinks=False)
                    if (
                        pattern.fullmatch(relative) is None
                        or item.is_symlink()
                        or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != 0o400
                    ):
                        raise LoopStateError("loop state contains an unsafe entry")
                    selected.append(relative)
        events.sort()
        artifacts.sort()
        expected = [f"events/{index:020d}.json" for index in range(len(events))]
        if events != expected:
            raise LoopStateError("loop event sequence is not contiguous")
        return events, artifacts

    def _payloads(self) -> dict[str, bytes]:
        before_events, before_artifacts = self._inventory()
        names = before_events + before_artifacts
        try:
            payloads = {name: secure_read(self.root / name) for name in names}
        except (OSError, ValueError) as error:
            raise LoopStateError("loop state cannot be read safely") from error
        if self._inventory() != (before_events, before_artifacts):
            raise LoopStateError("loop state changed during replay")
        return payloads

    def replay(self) -> list[dict[str, Any]]:
        payloads = self._payloads()
        event_names = sorted(name for name in payloads if name.startswith("events/"))
        previous: str | None = None
        result: list[dict[str, Any]] = []
        for sequence, name in enumerate(event_names):
            value = loads(payloads[name])
            if not isinstance(value, dict):
                raise LoopStateError("loop event is not an object")
            try:
                self.registry.validate(EVENT_SCHEMA, value)
            except ValueError as error:
                raise LoopStateError("loop event fails its schema") from error
            if (
                value["sequence"] != sequence
                or value["previous_event_id"] != previous
                or value["event_id"] != identity(_without_id(value))
            ):
                raise LoopStateError("loop event chain or identity is invalid")
            if result:
                first = result[0]
                for field in ("run_id", "champion_revision", "champion_tree"):
                    if value[field] != first[field]:
                        raise LoopStateError("loop run authority changed across events")
                previous_phase = result[-1]["phase"]
                effective = (
                    result[-1]["resume_phase"]
                    if previous_phase in {"interrupted", "paused"}
                    else previous_phase
                )
                if value["phase"] in {"interrupted", "paused"}:
                    if value["resume_phase"] != effective:
                        raise LoopStateError(
                            "loop interruption resume phase is invalid"
                        )
                elif value["phase"] not in TRANSITIONS[effective]:
                    raise LoopStateError("loop phase transition is invalid")
                if effective == "terminal" and value["phase"] == "scheduled":
                    if value["iteration"] != result[-1]["iteration"] + 1:
                        raise LoopStateError("loop iteration did not advance exactly")
                elif value["iteration"] != result[-1]["iteration"]:
                    raise LoopStateError("loop iteration changed within a trial")
            elif value["phase"] != "started":
                raise LoopStateError("first loop event must be started")
            previous = value["event_id"]
            result.append(value)
        artifact_names = sorted(
            name for name in payloads if name.startswith("artifacts/")
        )
        for name in artifact_names:
            value = loads(payloads[name])
            if identity(value) != ARTIFACT_NAME.fullmatch(name).group(1):  # type: ignore[union-attr]
                raise LoopStateError("loop artifact identity is invalid")
        referenced = {
            artifact_id for event in result for artifact_id in event["artifact_ids"]
        }
        available = {
            ARTIFACT_NAME.fullmatch(name).group(1)  # type: ignore[union-attr]
            for name in artifact_names
        }
        if not referenced.issubset(available):
            raise LoopStateError("loop event references a missing artifact")
        return result

    def artifact(self, artifact_id: str) -> Any:
        if re.fullmatch(r"1220[0-9a-f]{64}", artifact_id) is None:
            raise LoopStateError("loop artifact ID is invalid")
        payloads = self._payloads()
        name = f"artifacts/{artifact_id}.json"
        if name not in payloads:
            raise LoopStateError("loop artifact does not exist")
        value = loads(payloads[name])
        if identity(value) != artifact_id:
            raise LoopStateError("loop artifact content identity is invalid")
        return value

    def unreferenced_artifacts(
        self,
        *,
        schema_version: str,
        trial_id: str,
    ) -> list[tuple[str, Any]]:
        if (
            re.fullmatch(r"cigar\.[a-z0-9.-]{1,127}", schema_version) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", trial_id) is None
        ):
            raise LoopStateError("artifact recovery selector is invalid")
        events = self.replay()
        referenced = {
            artifact_id for event in events for artifact_id in event["artifact_ids"]
        }
        _, artifact_names = self._inventory()
        matches: list[tuple[str, Any]] = []
        for name in artifact_names:
            match = ARTIFACT_NAME.fullmatch(name)
            if match is None:
                raise LoopStateError("loop artifact inventory is invalid")
            artifact_id = match.group(1)
            if artifact_id in referenced:
                continue
            value = self.artifact(artifact_id)
            if (
                isinstance(value, dict)
                and value.get("schema_version") == schema_version
                and value.get("trial_id") == trial_id
            ):
                matches.append((artifact_id, value))
        return matches

    def write_artifact(self, value: Any) -> str:
        artifact_id = identity(value)
        relative = f"artifacts/{artifact_id}.json"
        events, artifacts = self._inventory()
        if relative in artifacts:
            if self.artifact(artifact_id) != value:
                raise LoopStateError("existing loop artifact differs")
            return artifact_id
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                if self._inventory() != (events, artifacts):
                    raise LoopStateError("loop state changed before artifact write")
                workspace.write_json(relative, value)
        except EvidenceWorkspaceError as error:
            raise LoopStateError("loop artifact publication failed") from error
        if self.artifact(artifact_id) != value:
            raise LoopStateError("loop artifact did not replay exactly")
        return artifact_id

    def append(
        self,
        *,
        run_id: str,
        iteration: int,
        phase: str,
        trial_id: str | None,
        champion_revision: str,
        champion_tree: str,
        artifact_ids: list[str],
        reservation_id: str | None = None,
        resume_phase: str | None = None,
        status: str | None = None,
        failure_category: str | None = None,
        candidate_revision: str | None = None,
        candidate_tree: str | None = None,
    ) -> dict[str, Any]:
        events = self.replay()
        body = {
            "schema_version": "cigar.refinement-loop-event.v1",
            "event_id": "",
            "sequence": len(events),
            "previous_event_id": events[-1]["event_id"] if events else None,
            "run_id": run_id,
            "iteration": iteration,
            "phase": phase,
            "resume_phase": resume_phase,
            "trial_id": trial_id,
            "champion_revision": champion_revision,
            "champion_tree": champion_tree,
            "artifact_ids": sorted(set(artifact_ids)),
            "reservation_id": reservation_id,
            "status": status,
            "failure_category": failure_category,
            "candidate_revision": candidate_revision,
            "candidate_tree": candidate_tree,
        }
        body["event_id"] = identity(_without_id(body))
        try:
            self.registry.validate(EVENT_SCHEMA, body)
        except ValueError as error:
            raise LoopStateError("loop event is malformed") from error
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                before_events, before_artifacts = self._inventory()
                if len(before_events) != len(events):
                    raise LoopStateError("loop events changed before append")
                if not set(body["artifact_ids"]).issubset(
                    {
                        ARTIFACT_NAME.fullmatch(name).group(1)  # type: ignore[union-attr]
                        for name in before_artifacts
                    }
                ):
                    raise LoopStateError("loop event cites an unavailable artifact")
                workspace.write_json(f"events/{len(events):020d}.json", body)
        except EvidenceWorkspaceError as error:
            raise LoopStateError("loop event publication failed") from error
        replayed = self.replay()
        if replayed[-1] != body:
            raise LoopStateError("loop event did not replay exactly")
        return body

    @staticmethod
    def latest_artifact_id(events: list[dict[str, Any]], phase: str) -> str:
        for event in reversed(events):
            if event["phase"] == phase and event["artifact_ids"]:
                return event["artifact_ids"][-1]
        raise LoopStateError(f"loop phase has no artifact: {phase}")

    @staticmethod
    def effective_phase(events: list[dict[str, Any]]) -> str | None:
        if not events:
            return None
        latest = events[-1]
        return (
            latest["resume_phase"]
            if latest["phase"] in {"interrupted", "paused"}
            else latest["phase"]
        )
