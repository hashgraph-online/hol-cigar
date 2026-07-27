"""Append-only, hash-chained refinement ledger in a protected external workspace."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, identity, loads
from .schema import SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
)

ENTRY_NAME = re.compile(r"^entries/([0-9]{20})\.json$")
SCHEMA_FILE = "ledger-v1.schema.json"
EVENT_TYPES = {
    "baseline_captured",
    "trial_created",
    "proposal_finished",
    "gate_finished",
    "evaluation_finished",
    "trial_rejected",
    "trial_promoted",
    "controller_stopped",
}


class LedgerError(RuntimeError):
    """Ledger state is missing, ambiguous, corrupt, or not append-only."""


def _discover(root: Path) -> set[str]:
    try:
        root_metadata = root.stat(follow_symlinks=False)
    except OSError as error:
        raise LedgerError("ledger root cannot be inspected") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise LedgerError("ledger root must be an owner-private directory")
    entries = root / "entries"
    if not entries.exists():
        return set()
    entry_metadata = entries.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(entry_metadata.st_mode)
        or entries.is_symlink()
        or stat.S_IMODE(entry_metadata.st_mode) != 0o700
    ):
        raise LedgerError("ledger entries path is not an owner-private directory")
    result: set[str] = set()
    try:
        iterator = os.scandir(entries)
    except OSError as error:
        raise LedgerError("ledger entries cannot be enumerated") from error
    with iterator:
        for item in iterator:
            relative = f"entries/{item.name}"
            if ENTRY_NAME.fullmatch(relative) is None:
                raise LedgerError("ledger contains an unexpected entry name")
            metadata = item.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or item.is_symlink()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise LedgerError("ledger entry is not an immutable regular file")
            result.add(relative)
    return result


def _entry_without_id(entry: dict[str, Any]) -> dict[str, Any]:
    result = dict(entry)
    result.pop("entry_id", None)
    return result


class Ledger:
    def __init__(
        self,
        root: Path,
        *,
        repository_root: Path,
        schema_root: Path | None = None,
    ) -> None:
        if not root.is_absolute() or not repository_root.is_absolute():
            raise LedgerError("ledger and repository roots must be absolute")
        self.root = root
        self.repository_root = repository_root.resolve(strict=True)
        selected_schema_root = (
            schema_root or self.repository_root / "schemas/refinement"
        )
        self.registry = SchemaRegistry(selected_schema_root)

    def replay(self) -> list[dict[str, Any]]:
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                paths = _discover(workspace.root)
                payloads = workspace.read_files(paths, strict_read_only=True)
        except EvidenceWorkspaceError as error:
            raise LedgerError("ledger workspace is unsafe") from error
        ordered = sorted(payloads)
        expected_names = [f"entries/{index:020d}.json" for index in range(len(ordered))]
        if ordered != expected_names:
            raise LedgerError("ledger sequence is not contiguous")
        previous: str | None = None
        result: list[dict[str, Any]] = []
        for index, name in enumerate(ordered):
            value = loads(payloads[name])
            if not isinstance(value, dict):
                raise LedgerError("ledger entry is not an object")
            try:
                self.registry.validate(SCHEMA_FILE, value)
            except ValueError as error:
                raise LedgerError("ledger entry fails its schema") from error
            if value["sequence"] != index or value["previous_entry_id"] != previous:
                raise LedgerError("ledger sequence or previous-entry link is invalid")
            expected_id = identity(_entry_without_id(value))
            if value["entry_id"] != expected_id:
                raise LedgerError("ledger entry identity does not match its content")
            previous = value["entry_id"]
            result.append(value)
        return result

    def append(
        self,
        *,
        event_type: str,
        iteration_id: str,
        source_revision: str,
        source_tree: str,
        artifact_ids: list[str],
        evidence_class: str,
        decision: str | None = None,
    ) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise LedgerError("ledger event type is unsupported")
        entries = self.replay()
        sequence = len(entries)
        entry: dict[str, Any] = {
            "schema_version": "cigar.refinement-ledger-entry.v1",
            "entry_id": "",
            "sequence": sequence,
            "previous_entry_id": entries[-1]["entry_id"] if entries else None,
            "event_type": event_type,
            "iteration_id": iteration_id,
            "source_revision": source_revision,
            "source_tree": source_tree,
            "artifact_ids": artifact_ids,
            "evidence_class": evidence_class,
            "decision": decision,
        }
        entry["entry_id"] = identity(_entry_without_id(entry))
        try:
            self.registry.validate(SCHEMA_FILE, entry)
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                before = _discover(workspace.root)
                expected_before = {
                    f"entries/{index:020d}.json" for index in range(sequence)
                }
                if before != expected_before:
                    raise LedgerError("ledger changed between replay and append")
                workspace.write_json(f"entries/{sequence:020d}.json", entry)
                expected_after = expected_before | {f"entries/{sequence:020d}.json"}
                workspace.read_files(expected_after, strict_read_only=True)
        except (EvidenceWorkspaceError, ValueError) as error:
            raise LedgerError("ledger entry publication failed") from error
        replayed = self.replay()
        if len(replayed) != sequence + 1 or replayed[-1] != entry:
            raise LedgerError("published ledger entry did not replay exactly")
        return entry


def entry_payload_digest(entry: dict[str, Any]) -> str:
    return identity(_entry_without_id(entry))


def canonical_entry_bytes(entry: dict[str, Any]) -> bytes:
    return canonical_bytes(entry)
