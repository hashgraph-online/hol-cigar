#!/usr/bin/env python3
"""Run a resumable no-promotion controller soak against an unchanged champion."""

from __future__ import annotations

# ruff: noqa: E402

import argparse
import fcntl
import os
import re
import stat
import sys
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import canonical_bytes, identity, loads, secure_read
from tools.refinement.commands import (
    CommandError,
    CommandRegistry,
    default_registry,
    run_named,
)
from tools.refinement.ledger import Ledger, LedgerError
from tools.refinement.workspace import WorkspaceError, repository_identity

RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import EvidenceLimits, EvidenceWorkspace, EvidenceWorkspaceError

EVENT = re.compile(r"^events/([0-9]{20})\.json$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
COMMAND_ID = "refinement-loop-smoke"
SOAK_EVIDENCE_LIMITS = EvidenceLimits(
    max_files=100_000,
    max_directories=16_384,
)


class SoakError(RuntimeError):
    """A soak contract, journal, command, or source invariant failed."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise SoakError("soak timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise SoakError("soak timestamp lacks a timezone")
    return parsed


def _absolute(path: Path, label: str, *, must_exist: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise SoakError(f"{label} must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise SoakError(f"{label} cannot be resolved") from error
    if resolved != path:
        raise SoakError(f"{label} must not contain aliases")
    return path


def _private_directory(path: Path, label: str) -> Path:
    path = _absolute(path, label, must_exist=True)
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SoakError(f"{label} must be owner-private 0700")
    return path


def _without_id(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    return result


class SoakJournal:
    def __init__(self, root: Path, *, repository: Path) -> None:
        self.root = root
        self.repository = repository
        try:
            with EvidenceWorkspace.create(
                root,
                repository_root=repository,
                limits=SOAK_EVIDENCE_LIMITS,
            ):
                pass
        except EvidenceWorkspaceError as error:
            raise SoakError("soak evidence root is unsafe") from error
        commands = root / "commands"
        try:
            commands.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _private_directory(commands, "soak command root")

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        descriptor = -1
        try:
            descriptor = os.open(
                self.root / ".soak.lock",
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise SoakError("soak lock metadata is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise SoakError("another supervisor holds the soak lease") from error
            yield
        except OSError as error:
            raise SoakError("soak lease cannot be acquired") from error
        finally:
            if descriptor >= 0:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def _event_names(self) -> list[str]:
        directory = self.root / "events"
        if not directory.exists():
            return []
        _private_directory(directory, "soak event root")
        names: list[str] = []
        with os.scandir(directory) as iterator:
            for item in iterator:
                relative = f"events/{item.name}"
                metadata = item.stat(follow_symlinks=False)
                if (
                    EVENT.fullmatch(relative) is None
                    or item.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o400
                ):
                    raise SoakError("soak event inventory is unsafe")
                names.append(relative)
        names.sort()
        expected = [f"events/{index:020d}.json" for index in range(len(names))]
        if names != expected:
            raise SoakError("soak event sequence is not contiguous")
        return names

    def replay(self) -> list[dict[str, Any]]:
        names = self._event_names()
        payloads = {name: secure_read(self.root / name) for name in names}
        if names != self._event_names():
            raise SoakError("soak journal changed during replay")
        events: list[dict[str, Any]] = []
        previous: str | None = None
        for sequence, name in enumerate(names):
            value = loads(payloads[name])
            required = {
                "schema_version",
                "event_id",
                "sequence",
                "previous_event_id",
                "run_id",
                "cycle",
                "command_id",
                "command_receipt_id",
                "source",
                "ledger_head",
                "status",
            }
            if (
                not isinstance(value, dict)
                or set(value) != required
                or value["schema_version"] != "cigar.refinement-soak-event.v1"
                or value["sequence"] != sequence
                or value["cycle"] != sequence
                or value["previous_event_id"] != previous
                or value["event_id"] != identity(_without_id(value, "event_id"))
                or value["status"] != "passed"
                or value["command_id"] != COMMAND_ID
                or re.fullmatch(r"1220[0-9a-f]{64}", value["command_receipt_id"])
                is None
            ):
                raise SoakError("soak event chain is invalid")
            if events and (
                value["run_id"] != events[0]["run_id"]
                or value["source"] != events[0]["source"]
                or value["ledger_head"] != events[0]["ledger_head"]
            ):
                raise SoakError("soak invariant changed between cycles")
            previous = value["event_id"]
            events.append(value)
        return events

    def contract(self, expected: dict[str, Any]) -> dict[str, Any]:
        path = self.root / "contract.json"
        if path.exists():
            value = loads(secure_read(path))
            if value != expected:
                raise SoakError("resumed soak authority differs from its contract")
            return value
        try:
            with EvidenceWorkspace.create(
                self.root,
                repository_root=self.repository,
                limits=SOAK_EVIDENCE_LIMITS,
            ) as workspace:
                workspace.write_json("contract.json", expected)
        except EvidenceWorkspaceError as error:
            raise SoakError("soak contract publication failed") from error
        value = loads(secure_read(path))
        if value != expected:
            raise SoakError("soak contract did not replay exactly")
        return value

    def append(self, value: dict[str, Any]) -> dict[str, Any]:
        events = self.replay()
        body = {
            **value,
            "event_id": "",
            "sequence": len(events),
            "previous_event_id": events[-1]["event_id"] if events else None,
            "cycle": len(events),
        }
        body["event_id"] = identity(_without_id(body, "event_id"))
        try:
            with EvidenceWorkspace.create(
                self.root,
                repository_root=self.repository,
                limits=SOAK_EVIDENCE_LIMITS,
            ) as workspace:
                if len(self._event_names()) != len(events):
                    raise SoakError("soak journal changed before append")
                workspace.write_json(f"events/{len(events):020d}.json", body)
        except EvidenceWorkspaceError as error:
            raise SoakError("soak event publication failed") from error
        if self.replay()[-1] != body:
            raise SoakError("soak event did not replay exactly")
        return body


def _ledger_head(ledger: Ledger) -> str | None:
    entries = ledger.replay()
    return entries[-1]["entry_id"] if entries else None


def run_soak(
    *,
    repository: Path,
    state_root: Path,
    ledger_root: Path,
    run_id: str,
    duration_seconds: int,
    interval_seconds: int,
    pause_file: Path,
    no_promotion: bool,
    registry: CommandRegistry | None = None,
) -> dict[str, Any]:
    if (
        RUN_ID.fullmatch(run_id) is None
        or isinstance(duration_seconds, bool)
        or not 1 <= duration_seconds <= 172800
        or isinstance(interval_seconds, bool)
        or not 0 <= interval_seconds <= 3600
        or not no_promotion
    ):
        raise SoakError("soak authority is invalid")
    repository = _absolute(repository, "repository", must_exist=True)
    ledger_root = _private_directory(ledger_root, "ledger root")
    if not pause_file.is_absolute() or pause_file.is_symlink():
        raise SoakError("pause file must be an absolute non-symlink path")
    source = repository_identity(repository, require_clean=True)
    selected_registry = registry or default_registry()
    if COMMAND_ID not in selected_registry.identifiers:
        raise SoakError("soak command is absent from the named registry")
    ledger = Ledger(ledger_root, repository_root=repository)
    ledger_head = _ledger_head(ledger)
    journal = SoakJournal(state_root, repository=repository)
    with journal.exclusive():
        contract_path = journal.root / "contract.json"
        if contract_path.exists():
            existing = loads(secure_read(contract_path))
            started_at_utc = existing.get("started_at_utc")
            if not isinstance(started_at_utc, str):
                raise SoakError("soak contract start time is malformed")
        else:
            started_at_utc = _timestamp(_utc_now())
        body = {
            "schema_version": "cigar.refinement-soak-contract.v1",
            "run_id": run_id,
            "started_at_utc": started_at_utc,
            "duration_seconds": duration_seconds,
            "interval_seconds": interval_seconds,
            "command_id": COMMAND_ID,
            "source": {
                "revision": source["revision"],
                "tree": source["tree"],
            },
            "ledger_head": ledger_head,
            "no_promotion": True,
        }
        contract = {**body, "contract_id": identity(body)}
        journal.contract(contract)
        started = _parse_timestamp(started_at_utc)
        while (_utc_now() - started).total_seconds() < duration_seconds:
            if pause_file.exists():
                return {
                    "schema_version": "cigar.refinement-soak-result.v1",
                    "run_id": run_id,
                    "status": "paused",
                    "cycles": len(journal.replay()),
                    "qualified_24h": False,
                    "no_promotion": True,
                }
            cycle = len(journal.replay())
            command_state = journal.root / "commands" / f"{cycle:020d}"
            result = run_named(
                selected_registry,
                COMMAND_ID,
                cwd=repository,
                state=command_state,
            )
            if result["status"] != "passed":
                raise SoakError("controller smoke command failed")
            if (
                repository_identity(repository, require_clean=True) != source
                or _ledger_head(ledger) != ledger_head
            ):
                raise SoakError("soak changed the champion or authoritative ledger")
            journal.append(
                {
                    "schema_version": "cigar.refinement-soak-event.v1",
                    "run_id": run_id,
                    "command_id": COMMAND_ID,
                    "command_receipt_id": identity(result),
                    "source": {
                        "revision": source["revision"],
                        "tree": source["tree"],
                    },
                    "ledger_head": ledger_head,
                    "status": "passed",
                }
            )
            remaining = duration_seconds - (_utc_now() - started).total_seconds()
            if interval_seconds and remaining > 0:
                time.sleep(min(interval_seconds, remaining))
        events = journal.replay()
        report_body = {
            "schema_version": "cigar.refinement-soak-result.v1",
            "run_id": run_id,
            "status": "passed",
            "duration_seconds": duration_seconds,
            "cycles": len(events),
            "first_event_id": events[0]["event_id"] if events else None,
            "last_event_id": events[-1]["event_id"] if events else None,
            "source": {
                "revision": source["revision"],
                "tree": source["tree"],
            },
            "ledger_head": ledger_head,
            "qualified_24h": duration_seconds >= 86400,
            "no_promotion": True,
        }
        return {**report_body, "report_id": identity(report_body)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--ledger-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=int, default=30)
    parser.add_argument("--pause-file", type=Path, required=True)
    parser.add_argument("--no-promotion", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = run_soak(
            repository=arguments.repository,
            state_root=_absolute(arguments.state_root, "state root", must_exist=False),
            ledger_root=arguments.ledger_root,
            run_id=arguments.run_id,
            duration_seconds=arguments.duration_seconds,
            interval_seconds=arguments.interval_seconds,
            pause_file=arguments.pause_file,
            no_promotion=arguments.no_promotion,
        )
        sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
        return 0 if result["status"] == "passed" else 3
    except (
        CommandError,
        EvidenceWorkspaceError,
        LedgerError,
        OSError,
        SoakError,
        ValueError,
        WorkspaceError,
    ) as error:
        print(f"refinement soak: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
