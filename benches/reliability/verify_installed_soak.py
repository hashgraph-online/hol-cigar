#!/usr/bin/env python3
"""Independently verify installed-soak cycles and content-free time-series evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Never

CONFIGURATION = Path(__file__).with_name("soak-configuration.v1.json")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
KINDS = ("installed", "scale", "maintenance", "compile", "liveness")
SAMPLE_KEYS = {
    "schema_version", "sequence", "elapsed_nanoseconds", "unix_seconds",
    "coordinator_rss_bytes", "active_process_group_rss_bytes", "disk_available_bytes",
    "active_job", "completed_cycles", "operation_counts",
}


class VerificationError(RuntimeError):
    """Installed soak evidence is incomplete, inconsistent, or changed."""


def fail(message: str) -> Never:
    raise VerificationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("soak evidence contains a duplicate JSON field")
        result[key] = value
    return result


def reject_nonfinite(_value: str) -> Never:
    fail("soak evidence contains a non-finite JSON number")


def decode_json(payload: bytes) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("soak evidence contains invalid JSON") from error


def load(path: Path, maximum: int = 64 * 1024 * 1024) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError("soak evidence is unavailable") from error
    value = decode_json(payload)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not payload or len(payload) > maximum or not isinstance(value, dict):
        fail("soak evidence is invalid or unbounded")
    return value


def verify_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise VerificationError("private soak directory is unavailable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved != path
    ):
        fail("soak evidence directories must be canonical and owner-private")


def verify_file(binding: Any, maximum: int = 1024**3) -> Path:
    if (
        not isinstance(binding, dict)
        or set(binding) != {"path", "bytes", "sha256"}
        or not isinstance(binding["path"], str)
        or not isinstance(binding["bytes"], int)
        or isinstance(binding["bytes"], bool)
        or binding["bytes"] <= 0
        or binding["bytes"] > maximum
        or not isinstance(binding["sha256"], str)
        or SHA256.fullmatch(binding["sha256"]) is None
    ):
        fail("soak file binding is invalid")
    path = Path(binding["path"])
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError("bound soak file is unavailable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not payload
        or len(payload) > maximum
        or len(payload) != binding["bytes"]
        or hashlib.sha256(payload).hexdigest() != binding["sha256"]
    ):
        fail("bound soak file changed")
    return path


def slope_bytes_per_hour(samples: list[tuple[int, int]]) -> int:
    if len(samples) < 2:
        fail("insufficient post-warmup memory samples")
    origin = samples[0][0]
    xs = [(elapsed - origin) / 3_600_000_000_000 for elapsed, _rss in samples]
    ys = [rss for _elapsed, rss in samples]
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    denominator = sum((value - x_mean) ** 2 for value in xs)
    if denominator == 0:
        fail("memory sample times are degenerate")
    return round(sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys, strict=True)) / denominator)


def valid_counts(value: Any, expected_keys: set[str] | None = None) -> bool:
    return (
        isinstance(value, dict)
        and (expected_keys is None or set(value) == expected_keys)
        and all(
            isinstance(key, str)
            and re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", key) is not None
            and isinstance(count, int)
            and not isinstance(count, bool)
            and count >= 0
            for key, count in value.items()
        )
    )


def verify_cycles(root: Path) -> tuple[int, str, dict[str, int], dict[str, int]]:
    verify_private_directory(root)
    try:
        directories = sorted(root.iterdir())
    except OSError as error:
        raise VerificationError("soak cycle directory is unavailable") from error
    if not directories or len(directories) > 100_000:
        fail("soak cycle count is invalid")
    hasher = hashlib.sha256(b"CIGAR-H094-SOAK-CYCLES\0")
    operations: dict[str, int] = {}
    completed = {kind: 0 for kind in KINDS}
    for sequence, directory in enumerate(directories, start=1):
        verify_private_directory(directory)
        prefix = f"{sequence:08d}-"
        if not directory.name.startswith(prefix):
            fail("soak cycle sequence is discontinuous")
        path = directory / "cycle-receipt.json"
        receipt = load(path, 16 * 1024 * 1024)
        expected = {"schema_version", "status", "sequence", "kind", "duration_nanoseconds", "operations", "commands", "receipt_id"}
        if set(receipt) != expected:
            fail("soak cycle receipt fields are invalid")
        receipt_id = receipt.pop("receipt_id")
        kind = receipt["kind"]
        if (
            receipt_id != hashlib.sha256(canonical(receipt)).hexdigest()
            or receipt["schema_version"] != "cigar.h094-installed-soak-cycle.v1"
            or receipt["status"] != "passed"
            or receipt["sequence"] != sequence
            or kind not in KINDS
            or directory.name != f"{sequence:08d}-{kind}"
            or not isinstance(receipt["duration_nanoseconds"], int)
            or isinstance(receipt["duration_nanoseconds"], bool)
            or receipt["duration_nanoseconds"] <= 0
            or not valid_counts(receipt["operations"])
            or not isinstance(receipt["commands"], list)
        ):
            fail("soak cycle receipt identity or status is invalid")
        for command in receipt["commands"]:
            if (
                not isinstance(command, dict)
                or set(command) != {
                    "command_id", "duration_nanoseconds", "exit_code", "stdout_bytes",
                    "stdout_sha256", "stderr_bytes", "stderr_sha256",
                }
                or SHA256.fullmatch(command["command_id"]) is None
                or command["exit_code"] != 0
                or not isinstance(command["duration_nanoseconds"], int)
                or command["duration_nanoseconds"] <= 0
                or not 0 <= command["stdout_bytes"] <= 8 * 1024 * 1024
                or not 0 <= command["stderr_bytes"] <= 8 * 1024 * 1024
                or SHA256.fullmatch(command["stdout_sha256"]) is None
                or SHA256.fullmatch(command["stderr_sha256"]) is None
            ):
                fail("soak command receipt is invalid")
        for operation, count in receipt["operations"].items():
            if count <= 0:
                fail("soak cycle claimed a zero-count operation")
            operations[operation] = operations.get(operation, 0) + count
        completed[kind] += 1
        payload = path.read_bytes()
        hasher.update(canonical({"path": str(path.resolve()), "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}))
    return len(directories), hasher.hexdigest(), operations, completed


def verify_samples(
    path: Path,
    profile: dict[str, Any],
    operations: dict[str, int],
    completed: dict[str, int],
    forbidden: set[str],
) -> tuple[int, int, int, int]:
    try:
        metadata = path.lstat()
        stream = path.open("rb")
    except OSError as error:
        raise VerificationError("soak samples are unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > 64 * 1024 * 1024:
        fail("soak samples are invalid or unbounded")
    count = 0
    warmup = 0
    first_elapsed: int | None = None
    prior_elapsed: int | None = None
    maximum_gap = 0
    post_warmup: list[tuple[int, int]] = []
    prior_operations = {key: 0 for key in operations}
    prior_completed = {kind: 0 for kind in KINDS}
    with stream:
        for line in stream:
            if len(line) > 16 * 1024:
                fail("one content-free soak sample exceeded its bound")
            try:
                sample = decode_json(line)
            except VerificationError as error:
                raise VerificationError("one soak sample is invalid JSON") from error
            if not isinstance(sample, dict) or set(sample) != SAMPLE_KEYS or forbidden.intersection(sample):
                fail("one soak sample has non-content-free or unknown fields")
            elapsed = sample["elapsed_nanoseconds"]
            rss = sample["coordinator_rss_bytes"]
            if (
                sample["schema_version"] != "cigar.h094-installed-soak-sample.v1"
                or sample["sequence"] != count
                or not isinstance(elapsed, int)
                or isinstance(elapsed, bool)
                or elapsed < 0
                or not isinstance(sample["unix_seconds"], int)
                or any(
                    not isinstance(sample[name], int) or isinstance(sample[name], bool) or sample[name] < 0
                    for name in ("coordinator_rss_bytes", "active_process_group_rss_bytes", "disk_available_bytes")
                )
                or sample["active_job"] not in (*KINDS, None)
                or not valid_counts(sample["completed_cycles"], set(KINDS))
                or not valid_counts(sample["operation_counts"], set(operations))
            ):
                fail("one soak sample value is invalid")
            if prior_elapsed is not None:
                if elapsed <= prior_elapsed:
                    fail("soak sample monotonic time did not advance")
                maximum_gap = max(maximum_gap, elapsed - prior_elapsed)
            else:
                first_elapsed = elapsed
            if any(sample["operation_counts"][key] < prior_operations[key] for key in operations) or any(sample["completed_cycles"][key] < prior_completed[key] for key in KINDS):
                fail("soak cumulative counters regressed")
            prior_operations = sample["operation_counts"]
            prior_completed = sample["completed_cycles"]
            prior_elapsed = elapsed
            count += 1
            if elapsed <= profile["warmup_seconds"] * 1_000_000_000:
                warmup += 1
            else:
                post_warmup.append((elapsed, rss))
    if (
        count < 3
        or first_elapsed is None
        or first_elapsed > profile["sample_interval_seconds"] * 1_000_000_000
        or prior_elapsed is None
        or prior_elapsed < profile["duration_seconds"] * 1_000_000_000
        or maximum_gap > profile["maximum_sample_gap_seconds"] * 1_000_000_000
        or prior_operations != operations
        or prior_completed != completed
    ):
        fail("soak sample series is incomplete or exceeds its gap bound")
    return count, warmup, maximum_gap, slope_bytes_per_hour(post_warmup)


def verify(report_path: Path) -> str:
    try:
        report_path = report_path.resolve(strict=True)
    except OSError as error:
        raise VerificationError("installed soak report is unavailable") from error
    verify_private_directory(report_path.parent)
    report = load(report_path)
    required = {
        "schema_version", "status", "profile_id", "source_revision", "configuration", "artifacts",
        "plan", "result", "samples", "cycle_receipt_count", "cycle_receipts_root",
        "duration_seconds", "sample_count", "warmup_sample_count", "maximum_sample_gap_nanoseconds",
        "coordinator_rss_slope_bytes_per_hour", "completed_cycles", "operation_counts",
        "all_required_operations_exercised", "all_artifacts_immutable", "rust_result_verified", "report_id",
    }
    if set(report) != required:
        fail("installed soak report fields are invalid")
    report_id = report.pop("report_id")
    if not isinstance(report_id, str) or SHA256.fullmatch(report_id) is None or report_id != hashlib.sha256(canonical(report)).hexdigest():
        fail("installed soak report identity disagrees")
    if (
        report["schema_version"] != "cigar.h094-installed-soak-report.v1"
        or report["status"] != "passed"
        or report["profile_id"] not in {"soak-smoke", "soak-rc-24h"}
        or SOURCE.fullmatch(report["source_revision"]) is None
        or report["all_required_operations_exercised"] is not True
        or report["all_artifacts_immutable"] is not True
        or report["rust_result_verified"] is not True
    ):
        fail("installed soak report did not pass the RC contract")
    configuration_path = verify_file(report["configuration"])
    if configuration_path != CONFIGURATION.resolve(strict=True):
        fail("installed soak used an unexpected configuration")
    configuration = load(configuration_path)
    profile = configuration["profiles"][report["profile_id"]]
    artifacts = report["artifacts"]
    expected_artifacts = {
        "cigar", "cigard", "install_qualifier", "soak_binary", "compile_driver", "scale_driver",
        "effects_test", "daemon_test", "gc_test", "runner",
    }
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        fail("installed soak artifact inventory is incomplete")
    artifact_paths = {name: verify_file(binding) for name, binding in artifacts.items()}
    plan_path = verify_file(report["plan"])
    result_path = verify_file(report["result"])
    samples_path = verify_file(report["samples"], 64 * 1024 * 1024)
    plan = load(plan_path)
    result = load(result_path)
    if (
        plan.get("profile_id") != report["profile_id"]
        or plan.get("duration_seconds") != profile["duration_seconds"]
        or result.get("status") != "passed"
        or result.get("source_revision") != report["source_revision"]
        or result.get("samples_digest") != report["samples"]["sha256"]
        or result.get("plan_digest") != report["plan"]["sha256"]
    ):
        fail("Rust soak plan/result binding disagrees")
    cycle_count, cycle_root, operations, completed = verify_cycles(report_path.parent / "cycles")
    if (
        cycle_count != report["cycle_receipt_count"]
        or cycle_root != report["cycle_receipts_root"]
        or operations != report["operation_counts"]
        or completed != report["completed_cycles"]
        or any(operations.get(name, 0) <= 0 for name in configuration["required_operations"])
        or any(completed.get(kind, 0) <= 0 for kind in KINDS)
    ):
        fail("independently aggregated soak cycles disagree")
    sample_count, warmup, maximum_gap, slope = verify_samples(
        samples_path,
        profile,
        operations,
        completed,
        set(configuration["content_forbidden_keys"]),
    )
    if (
        sample_count != report["sample_count"]
        or warmup != report["warmup_sample_count"]
        or maximum_gap != report["maximum_sample_gap_nanoseconds"]
        or slope != report["coordinator_rss_slope_bytes_per_hour"]
        or slope > profile["maximum_coordinator_rss_slope_bytes_per_hour"]
        or report["duration_seconds"] < profile["duration_seconds"]
        or result.get("operation_counts") != operations
        or result.get("sample_count") != sample_count
        or result.get("warmup_sample_count") != warmup
    ):
        fail("independently verified soak metrics disagree")
    try:
        verified = subprocess.run(
            [str(artifact_paths["soak_binary"]), "verify", "--plan", str(plan_path), "--result", str(result_path)],
            env={"HOME": os.environ.get("HOME", ""), "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationError("bound Rust soak verifier could not execute") from error
    if verified.returncode != 0 or len(verified.stdout) > 1024 * 1024 or len(verified.stderr) > 1024 * 1024:
        fail("bound Rust soak verifier rejected the result")
    return report_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report_id = verify(arguments.report)
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"installed soak evidence verified: {report_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
