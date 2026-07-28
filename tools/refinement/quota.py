"""Append-only reservations enforcing provider and global refinement ceilings."""

from __future__ import annotations

# ruff: noqa: E402

import fcntl
import os
import re
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .canonical import identity, load_file, loads, secure_read
from .schema import SchemaRegistry

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError

EVENT_SCHEMA = "quota-event-v1.schema.json"
POLICY_SCHEMA = "operations-policy-v1.schema.json"
ENTRY = re.compile(r"^entries/([0-9]{20})\.json$")
UTC_DAY = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
RESERVATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RESOURCE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cost_microusd",
    "compute_milliseconds",
)


class QuotaError(RuntimeError):
    """Quota state or a requested reservation is unsafe, corrupt, or exhausted."""


def _without_id(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("event_id", None)
    return result


def _resources(
    *,
    input_tokens: int,
    output_tokens: int,
    cost_microusd: int,
    compute_milliseconds: int,
) -> dict[str, int]:
    result = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_microusd": cost_microusd,
        "compute_milliseconds": compute_milliseconds,
    }
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in result.values()
    ):
        raise QuotaError("quota resources must be non-negative integers")
    return result


def load_policy(path: Path, schema_root: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink():
        raise QuotaError("operations policy must be an absolute real file")
    try:
        value = load_file(path)
        SchemaRegistry(schema_root).validate(POLICY_SCHEMA, value)
    except (OSError, ValueError) as error:
        raise QuotaError("operations policy is malformed") from error
    if not isinstance(value, dict):
        raise QuotaError("operations policy is not an object")
    unsigned = dict(value)
    unsigned.pop("policy_id")
    if value["policy_id"] != identity(unsigned):
        raise QuotaError("operations policy identity is invalid")
    providers = [row["provider_id"] for row in value["providers"]]
    if providers != sorted(set(providers)):
        raise QuotaError("operations providers must be unique and sorted")
    return value


class QuotaLedger:
    """Hash-chained reservation/settlement ledger with a process-safe append lock."""

    def __init__(
        self,
        root: Path,
        *,
        repository_root: Path,
        policy_path: Path,
        schema_root: Path | None = None,
    ) -> None:
        if not root.is_absolute() or not repository_root.is_absolute():
            raise QuotaError("quota and repository roots must be absolute")
        self.root = root
        self.repository_root = repository_root.resolve(strict=True)
        if (
            self.root == self.repository_root
            or self.repository_root in self.root.parents
            or self.root in self.repository_root.parents
        ):
            raise QuotaError("quota state must be external to the repository")
        self.schema_root = (
            schema_root or self.repository_root / "schemas" / "refinement"
        ).resolve(strict=True)
        self.registry = SchemaRegistry(self.schema_root)
        self.policy = load_policy(policy_path, self.schema_root)
        self.providers = {row["provider_id"]: row for row in self.policy["providers"]}

    def _inventory(self) -> list[str]:
        if not self.root.exists():
            return []
        try:
            metadata = self.root.stat(follow_symlinks=False)
        except OSError as error:
            raise QuotaError("quota root cannot be inspected") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or self.root.is_symlink()
        ):
            raise QuotaError("quota root must be an owner-private directory")
        entries = self.root / "entries"
        if not entries.exists():
            return []
        entry_metadata = entries.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(entry_metadata.st_mode)
            or stat.S_IMODE(entry_metadata.st_mode) != 0o700
            or entries.is_symlink()
        ):
            raise QuotaError("quota entries directory is unsafe")
        names: list[str] = []
        try:
            iterator = os.scandir(entries)
        except OSError as error:
            raise QuotaError("quota entries cannot be enumerated") from error
        with iterator:
            for item in iterator:
                relative = f"entries/{item.name}"
                metadata = item.stat(follow_symlinks=False)
                if (
                    ENTRY.fullmatch(relative) is None
                    or not stat.S_ISREG(metadata.st_mode)
                    or item.is_symlink()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o400
                ):
                    raise QuotaError("quota ledger contains an unsafe entry")
                names.append(relative)
        names.sort()
        expected = [f"entries/{index:020d}.json" for index in range(len(names))]
        if names != expected:
            raise QuotaError("quota ledger sequence is not contiguous")
        return names

    @contextmanager
    def _lock(self) -> Iterator[None]:
        try:
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ):
                pass
        except EvidenceWorkspaceError as error:
            raise QuotaError("quota workspace is unsafe") from error
        path = self.root / ".quota.lock"
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise QuotaError("quota lock metadata is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError as error:
            raise QuotaError("quota lock cannot be acquired") from error
        finally:
            if "descriptor" in locals():
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def replay(self) -> list[dict[str, Any]]:
        names = self._inventory()
        if not names:
            return []
        try:
            payloads = {name: secure_read(self.root / name) for name in names}
            if self._inventory() != names:
                raise QuotaError("quota ledger changed during replay")
        except (OSError, ValueError) as error:
            raise QuotaError("quota workspace cannot be replayed") from error
        result: list[dict[str, Any]] = []
        previous: str | None = None
        reservations: dict[str, dict[str, Any]] = {}
        for sequence, name in enumerate(names):
            value = loads(payloads[name])
            if not isinstance(value, dict):
                raise QuotaError("quota event is not an object")
            try:
                self.registry.validate(EVENT_SCHEMA, value)
            except ValueError as error:
                raise QuotaError("quota event fails its schema") from error
            if (
                value["sequence"] != sequence
                or value["previous_event_id"] != previous
                or value["policy_id"] != self.policy["policy_id"]
                or value["event_id"] != identity(_without_id(value))
            ):
                raise QuotaError("quota event chain or identity is invalid")
            reservation_id = value["reservation_id"]
            prior = reservations.get(reservation_id)
            if value["kind"] == "reserved":
                if prior is not None or value["actual"] is not None:
                    raise QuotaError("quota reservation lifecycle is invalid")
                reservations[reservation_id] = value
            else:
                if (
                    prior is None
                    or prior["kind"] != "reserved"
                    or value["provider_id"] != prior["provider_id"]
                    or value["utc_day"] != prior["utc_day"]
                    or value["requested"] != prior["requested"]
                ):
                    raise QuotaError(
                        "quota terminal event does not bind its reservation"
                    )
                if value["kind"] == "settled":
                    if value["actual"] is None or any(
                        value["actual"][key] > value["requested"][key]
                        for key in RESOURCE_KEYS
                    ):
                        raise QuotaError("quota settlement exceeds its reservation")
                elif value["actual"] != {key: 0 for key in RESOURCE_KEYS}:
                    raise QuotaError("quota cancellation must settle zero resources")
                reservations[reservation_id] = value
            previous = value["event_id"]
            result.append(value)
        return result

    @staticmethod
    def _active(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        active: dict[str, dict[str, Any]] = {}
        for event in events:
            active[event["reservation_id"]] = event
        return active

    def usage(self, utc_day: str) -> dict[str, Any]:
        if UTC_DAY.fullmatch(utc_day) is None:
            raise QuotaError("UTC day must use YYYY-MM-DD")
        current = self._active(self.replay())
        by_provider: dict[str, dict[str, int]] = {
            provider: {
                **{key: 0 for key in RESOURCE_KEYS},
                "active_reservations": 0,
            }
            for provider in self.providers
        }
        global_usage = {
            "compute_milliseconds": 0,
            "active_reservations": 0,
        }
        for event in current.values():
            row = by_provider[event["provider_id"]]
            if event["kind"] == "reserved":
                row["active_reservations"] += 1
                global_usage["active_reservations"] += 1
            if event["utc_day"] != utc_day:
                continue
            resources = (
                event["requested"] if event["kind"] == "reserved" else event["actual"]
            )
            assert resources is not None
            for key in RESOURCE_KEYS:
                row[key] += resources[key]
            global_usage["compute_milliseconds"] += resources["compute_milliseconds"]
        return {
            "schema_version": "cigar.refinement-quota-usage.v1",
            "policy_id": self.policy["policy_id"],
            "utc_day": utc_day,
            "providers": [
                {"provider_id": provider, **by_provider[provider]}
                for provider in sorted(by_provider)
            ],
            "global": global_usage,
        }

    def _append(self, body: dict[str, Any]) -> dict[str, Any]:
        events = self.replay()
        event = {
            "schema_version": "cigar.refinement-quota-event.v1",
            "event_id": "",
            "sequence": len(events),
            "previous_event_id": events[-1]["event_id"] if events else None,
            "policy_id": self.policy["policy_id"],
            **body,
        }
        event["event_id"] = identity(_without_id(event))
        try:
            self.registry.validate(EVENT_SCHEMA, event)
            with EvidenceWorkspace.create(
                self.root, repository_root=self.repository_root
            ) as workspace:
                expected = {
                    f"entries/{index:020d}.json" for index in range(len(events))
                }
                if set(self._inventory()) != expected:
                    raise QuotaError("quota ledger changed during append")
                workspace.write_json(f"entries/{len(events):020d}.json", event)
        except (EvidenceWorkspaceError, ValueError) as error:
            raise QuotaError("quota event publication failed") from error
        if self.replay()[-1] != event:
            raise QuotaError("quota event did not replay exactly")
        return event

    def reserve(
        self,
        *,
        utc_day: str,
        provider_id: str,
        reservation_id: str,
        requested: dict[str, int],
    ) -> dict[str, Any]:
        if (
            UTC_DAY.fullmatch(utc_day) is None
            or RESERVATION.fullmatch(reservation_id) is None
            or provider_id not in self.providers
            or set(requested) != set(RESOURCE_KEYS)
        ):
            raise QuotaError("quota reservation identity or provider is invalid")
        requested = _resources(**requested)
        with self._lock():
            if reservation_id in self._active(self.replay()):
                raise QuotaError("quota reservation ID already exists")
            usage = self.usage(utc_day)
            row = next(
                item
                for item in usage["providers"]
                if item["provider_id"] == provider_id
            )
            limits = self.providers[provider_id]
            mappings = {
                "input_tokens": "max_input_tokens_per_day",
                "output_tokens": "max_output_tokens_per_day",
                "cost_microusd": "max_cost_microusd_per_day",
            }
            for resource, limit in mappings.items():
                if row[resource] + requested[resource] > limits[limit]:
                    raise QuotaError(f"provider daily {resource} ceiling exhausted")
            if row["active_reservations"] + 1 > limits["max_concurrent_reservations"]:
                raise QuotaError("provider concurrency ceiling exhausted")
            global_limits = self.policy["global"]
            if (
                usage["global"]["compute_milliseconds"]
                + requested["compute_milliseconds"]
                > global_limits["max_compute_milliseconds_per_day"]
            ):
                raise QuotaError("global daily compute ceiling exhausted")
            if (
                usage["global"]["active_reservations"] + 1
                > global_limits["max_concurrent_reservations"]
            ):
                raise QuotaError("global concurrency ceiling exhausted")
            return self._append(
                {
                    "kind": "reserved",
                    "reservation_id": reservation_id,
                    "utc_day": utc_day,
                    "provider_id": provider_id,
                    "requested": requested,
                    "actual": None,
                }
            )

    def finish(
        self,
        reservation_id: str,
        *,
        actual: dict[str, int] | None,
        cancelled: bool = False,
    ) -> dict[str, Any]:
        if RESERVATION.fullmatch(reservation_id) is None:
            raise QuotaError("quota reservation ID is invalid")
        with self._lock():
            current = self._active(self.replay()).get(reservation_id)
            if current is None or current["kind"] != "reserved":
                raise QuotaError("quota reservation is not active")
            if cancelled:
                selected = {key: 0 for key in RESOURCE_KEYS}
                kind = "cancelled"
            else:
                if actual is None or set(actual) != set(RESOURCE_KEYS):
                    raise QuotaError("quota settlement resources are incomplete")
                selected = _resources(**actual)
                kind = "settled"
            return self._append(
                {
                    "kind": kind,
                    "reservation_id": reservation_id,
                    "utc_day": current["utc_day"],
                    "provider_id": current["provider_id"],
                    "requested": current["requested"],
                    "actual": selected,
                }
            )
