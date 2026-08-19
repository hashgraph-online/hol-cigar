#!/usr/bin/env python3
"""Run and verify content-free Honey storage-efficiency baselines."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
sys.path.insert(0, os.fspath(RELEASE_SCRIPTS))

from evidence_workspace import (  # noqa: E402
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    canonical_json_bytes,
)

SCHEMA_VERSION = "cigar.honey-efficiency-evidence.v1"
PROFILE_SCHEMA_VERSION = "cigar.honey-efficiency-profiles.v1"
DRIVER_SCHEMA_VERSION = "cigar.honey-efficiency-driver-result.v1"
PERSISTENCE_FORMAT = "sqlite-v4-full-residual"
EVIDENCE_FILES = frozenset(
    {"baseline-manifest.json", "raw-observations.json", "summary.json"}
)
MAX_DRIVER_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_VERIFIED_COPY_BYTES = 64 * 1024 * 1024 * 1024
SOURCE_INPUTS = (
    "Cargo.lock",
    "benches/honey-efficiency/driver/Cargo.lock",
    "benches/honey-efficiency/driver/Cargo.toml",
    "benches/honey-efficiency/driver/src/main.rs",
    "benches/honey-efficiency/honey_efficiency.py",
    "benches/honey-efficiency/profiles.v1.json",
    "benches/honey-efficiency/tests/test_honey_efficiency.py",
    "crates/cigar-daemon/src/catalog_context_application.rs",
    "crates/cigar-daemon/src/lifecycle.rs",
    "crates/cigar-daemon/src/production_bootstrap.rs",
    "crates/cigar-daemon/src/production_runtime.rs",
    "crates/cigar-daemon/src/telemetry.rs",
    "crates/cigar-observe/src/lib.rs",
    "crates/cigar-store/src/lib.rs",
    "crates/cigar-store/src/metrics.rs",
    "crates/cigar-store/src/service_repository.rs",
    "crates/cigar-store/src/sqlite.rs",
)


class HarnessError(RuntimeError):
    """A fail-closed harness invariant was not satisfied."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path, *, maximum: int = MAX_VERIFIED_COPY_BYTES) -> tuple[str, int]:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise HarnessError("input must be an owned bounded regular file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise HarnessError("input exceeds the bounded file limit")
            digest.update(chunk)
        after = os.fstat(source.fileno())
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise HarnessError("input changed while it was being authenticated")
    return digest.hexdigest(), size


def load_profiles(path: Path) -> dict[str, dict[str, int | str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError("cannot read the workload profile") from error
    if not isinstance(value, dict) or set(value) != {"schema_version", "profiles"}:
        raise HarnessError("profile document has an unexpected shape")
    if value["schema_version"] != PROFILE_SCHEMA_VERSION:
        raise HarnessError("profile schema version is unsupported")
    profiles = value["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != {
        "small",
        "threshold",
        "hiero-shaped",
    }:
        raise HarnessError("the required workload profiles are not frozen")
    validated: dict[str, dict[str, int | str]] = {}
    for name, profile in profiles.items():
        if not isinstance(profile, dict) or set(profile) != {
            "initial_records",
            "iterations",
            "mutations_per_iteration",
            "shape",
        }:
            raise HarnessError("profile fields are not closed")
        initial = profile["initial_records"]
        iterations = profile["iterations"]
        mutations = profile["mutations_per_iteration"]
        shape = profile["shape"]
        if (
            isinstance(initial, bool)
            or not isinstance(initial, int)
            or not 1 <= initial <= 100_000
            or isinstance(iterations, bool)
            or not isinstance(iterations, int)
            or not 1 <= iterations <= 100_000
            or isinstance(mutations, bool)
            or not isinstance(mutations, int)
            or not 1 <= mutations <= min(initial, 64)
            or not isinstance(shape, str)
            or not shape
            or len(shape) > 160
        ):
            raise HarnessError("profile exceeds deterministic workload bounds")
        validated[name] = dict(profile)
    return validated


def command_output(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def source_binding(driver: Path, profile_path: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for relative in SOURCE_INPUTS:
        path = REPOSITORY_ROOT / relative
        digest, size = sha256_file(path, maximum=512 * 1024 * 1024)
        files.append({"bytes": size, "path": relative, "sha256": digest})
    driver_digest, driver_bytes = sha256_file(driver, maximum=512 * 1024 * 1024)
    profile_digest, profile_bytes = sha256_file(profile_path)
    worktree_digest = sha256_bytes(canonical_json_bytes(files))
    try:
        base_commit = command_output(["git", "rev-parse", "HEAD"])
        base_tree = command_output(["git", "rev-parse", "HEAD^{tree}"])
        tracked_status = command_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=no"]
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HarnessError("cannot bind the benchmark to the source repository") from error
    return {
        "base_commit": base_commit,
        "base_tree": base_tree,
        "binding_kind": "worktree-source-set-v1",
        "candidate_bound": False,
        "candidate_bound_compatible": True,
        "driver": {"bytes": driver_bytes, "sha256": driver_digest},
        "profile_document": {"bytes": profile_bytes, "sha256": profile_digest},
        "tracked_worktree_dirty": bool(tracked_status),
        "worktree_source_files": files,
        "worktree_source_sha256": worktree_digest,
    }


def build_driver(manifest: Path) -> Path:
    try:
        subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                os.fspath(manifest),
                "--release",
                "--locked",
                "--offline",
            ],
            cwd=REPOSITORY_ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1800,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HarnessError("the efficiency driver build failed") from error
    return manifest.parent / "target" / "release" / "cigar-honey-efficiency-driver"


def copy_verified_database(source: Path, target: Path, expected_sha256: str) -> dict[str, Any]:
    if (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise HarnessError("verified-copy SHA-256 must be lowercase hexadecimal")
    digest, size = sha256_file(source)
    if digest != expected_sha256:
        raise HarnessError("verified-copy digest does not match its authorization")
    free = shutil.disk_usage(target.parent).free
    if free < size + max(size // 5, 512 * 1024 * 1024):
        raise HarnessError("insufficient free space for a verified-copy workload")
    shutil.copyfile(source, target, follow_symlinks=False)
    copied_digest, copied_size = sha256_file(target)
    if copied_digest != digest or copied_size != size:
        raise HarnessError("verified-copy scratch authentication failed")
    return {"bytes": size, "kind": "verified-copy", "sha256": digest}


def run_driver(
    driver: Path,
    database: Path,
    profile: Mapping[str, int | str],
    timeout_seconds: int,
) -> dict[str, Any]:
    arguments = [
        os.fspath(driver),
        "--database",
        os.fspath(database),
        "--initial-records",
        str(profile["initial_records"]),
        "--iterations",
        str(profile["iterations"]),
        "--mutations-per-iteration",
        str(profile["mutations_per_iteration"]),
    ]
    try:
        completed = subprocess.run(
            arguments,
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HarnessError("the bounded efficiency workload failed") from error
    if completed.stderr or len(completed.stdout) > MAX_DRIVER_OUTPUT_BYTES:
        raise HarnessError("driver output violated its content-free output contract")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError("driver output is not valid JSON") from error
    if not isinstance(result, dict):
        raise HarnessError("driver output has an unexpected shape")
    return result


def nearest_rank(values: Iterable[int], numerator: int, denominator: int) -> int:
    ordered = sorted(values)
    if not ordered:
        raise HarnessError("cannot summarize an empty measurement cohort")
    rank = max(1, (len(ordered) * numerator + denominator - 1) // denominator)
    return ordered[min(rank, len(ordered)) - 1]


def integer_ols_slope_millionths(values: list[int]) -> int:
    if len(values) < 2:
        return 0
    count = len(values)
    sum_x = count * (count - 1) // 2
    sum_x_squared = count * (count - 1) * (2 * count - 1) // 6
    sum_y = sum(values)
    sum_xy = sum(index * value for index, value in enumerate(values))
    numerator = count * sum_xy - sum_x * sum_y
    denominator = count * sum_x_squared - sum_x * sum_x
    return (numerator * 1_000_000) // denominator


def distribution(values: list[int]) -> dict[str, int]:
    if not values or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
        raise HarnessError("measurement distribution is invalid")
    return {
        "count": len(values),
        "maximum": max(values),
        "mean": sum(values) // len(values),
        "p50": nearest_rank(values, 50, 100),
        "p95": nearest_rank(values, 95, 100),
    }


def validate_driver_result(
    result: Mapping[str, Any], profile: Mapping[str, int | str]
) -> list[Mapping[str, Any]]:
    expected_root = {
        "schema_version",
        "persistence_format",
        "initial_records",
        "iterations",
        "mutations_per_iteration",
        "startup",
        "storage_before",
        "storage_after",
        "commits",
    }
    if set(result) != expected_root:
        raise HarnessError("driver result fields are not closed")
    if (
        result["schema_version"] != DRIVER_SCHEMA_VERSION
        or result["persistence_format"] != PERSISTENCE_FORMAT
        or result["initial_records"] != profile["initial_records"]
        or result["iterations"] != profile["iterations"]
        or result["mutations_per_iteration"] != profile["mutations_per_iteration"]
    ):
        raise HarnessError("driver result is not bound to the selected workload")
    commits = result["commits"]
    expected_count = int(profile["iterations"]) * int(profile["mutations_per_iteration"])
    if not isinstance(commits, list) or len(commits) != expected_count:
        raise HarnessError("driver returned an incomplete commit cohort")
    for index, commit in enumerate(commits):
        if not isinstance(commit, dict):
            raise HarnessError("commit observation has an unexpected shape")
        if (
            commit.get("iteration") != index // int(profile["mutations_per_iteration"])
            or commit.get("operation") != index % int(profile["mutations_per_iteration"])
            or commit.get("kind") != "worker"
            or commit.get("outcome") != "committed"
            or commit.get("receipt_only") is not False
            or commit.get("revision_after") != commit.get("revision_before") + 1
        ):
            raise HarnessError("commit observation violates the serial workload contract")
        byte_values = commit.get("bytes")
        if (
            not isinstance(byte_values, dict)
            or byte_values.get("full_state", 0) <= 0
            or byte_values.get("encoded_delta") != 0
            or byte_values.get("checkpoint") != 0
        ):
            raise HarnessError("baseline did not reproduce v4 full-snapshot persistence")
    return commits


def summarize(
    driver_result: Mapping[str, Any],
    profile_name: str,
    profile: Mapping[str, int | str],
    input_binding: Mapping[str, Any],
    source: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    commits = validate_driver_result(driver_result, profile)
    raw = {
        "driver_result": driver_result,
        "input": dict(input_binding),
        "profile": {
            "id": profile_name,
            "initial_records": profile["initial_records"],
            "iterations": profile["iterations"],
            "mutations_per_iteration": profile["mutations_per_iteration"],
        },
        "schema_version": SCHEMA_VERSION,
        "source": dict(source),
    }
    raw_digest = sha256_bytes(canonical_json_bytes(raw))
    phases = tuple(commits[0]["durations_nanoseconds"])
    if phases != (
        "total",
        "lock_wait",
        "repository_load",
        "residual_decode",
        "staged_mutation",
        "delta_encode",
        "full_encode",
        "catalog_root",
        "sqlite_transaction",
        "commit_fsync",
        "revision_anchor",
    ):
        raise HarnessError("commit timing phase domain changed")
    stage_distributions = {
        phase: distribution([commit["durations_nanoseconds"][phase] for commit in commits])
        for phase in phases
    }
    startup = driver_result["startup"]
    if not isinstance(startup, list) or not startup:
        raise HarnessError("startup observations are empty")
    startup_stages: dict[str, dict[str, int | str]] = {}
    for item in startup:
        if (
            not isinstance(item, dict)
            or set(item) != {"stage", "outcome", "duration_nanoseconds"}
            or item["outcome"] != "completed"
            or not isinstance(item["duration_nanoseconds"], int)
            or item["duration_nanoseconds"] < 0
            or item["stage"] in startup_stages
        ):
            raise HarnessError("startup observation is invalid")
        startup_stages[item["stage"]] = {
            "duration_nanoseconds": item["duration_nanoseconds"],
            "outcome": item["outcome"],
        }
    full_state = [commit["bytes"]["full_state"] for commit in commits]
    logical = [commit["bytes"]["logical_changed"] for commit in commits]
    durable = [commit["bytes"]["durable_added"] or 0 for commit in commits]
    amplification = [
        commit["bytes"]["write_amplification_millionths"] or 0 for commit in commits
    ]
    storage_before = driver_result["storage_before"]
    storage_after = driver_result["storage_after"]
    summary = {
        "baseline_behavior": {
            "encoded_delta_bytes": 0,
            "full_snapshot_encoded_each_commit": True,
            "persistence_format": PERSISTENCE_FORMAT,
            "snapshot_bytes_ols_slope_per_operation_millionths": integer_ols_slope_millionths(full_state),
        },
        "bytes": {
            "durable_added": distribution(durable),
            "full_state": distribution(full_state),
            "logical_changed": distribution(logical),
            "write_amplification_millionths": distribution(amplification),
        },
        "commit_count": len(commits),
        "input": dict(input_binding),
        "outcome": "pass",
        "profile": raw["profile"],
        "raw_observations_sha256": raw_digest,
        "schema_version": SCHEMA_VERSION,
        "source_binding": {
            "base_commit": source["base_commit"],
            "candidate_bound": source["candidate_bound"],
            "candidate_bound_compatible": source["candidate_bound_compatible"],
            "worktree_source_sha256": source["worktree_source_sha256"],
        },
        "startup_stages": startup_stages,
        "storage": {
            "database_growth_bytes": max(0, storage_after["database_bytes"] - storage_before["database_bytes"]),
            "latest_snapshot_growth_bytes": max(0, storage_after["latest_snapshot_bytes"] - storage_before["latest_snapshot_bytes"]),
            "retained_snapshots_after": storage_after["retained_snapshots"],
            "retained_snapshots_before": storage_before["retained_snapshots"],
            "revision_delta": storage_after["revision"] - storage_before["revision"],
            "wal_growth_bytes": max(0, storage_after["wal_bytes"] - storage_before["wal_bytes"]),
        },
        "timings_nanoseconds": stage_distributions,
        "total_latency_ols_slope_per_operation_millionths": integer_ols_slope_millionths(
            [commit["durations_nanoseconds"]["total"] for commit in commits]
        ),
    }
    if summary["storage"]["revision_delta"] != len(commits):
        raise HarnessError("storage revision delta does not match the commit cohort")
    return raw, summary


def execute(args: argparse.Namespace) -> dict[str, Any]:
    profile_path = (REPOSITORY_ROOT / "benches/honey-efficiency/profiles.v1.json").resolve()
    profiles = load_profiles(profile_path)
    profile = profiles[args.profile]
    manifest = REPOSITORY_ROOT / "benches/honey-efficiency/driver/Cargo.toml"
    driver = Path(args.driver).resolve() if args.driver else build_driver(manifest)
    if not driver.is_file():
        raise HarnessError("the selected driver does not exist")
    output = Path(args.output)
    if not output.is_absolute() or output.resolve(strict=False) != output:
        raise HarnessError("evidence output must be a canonical absolute path")
    timeouts = {"small": 300, "threshold": 1800, "hiero-shaped": 14_400}
    with tempfile.TemporaryDirectory(prefix="cigar-honey-efficiency-") as temporary:
        scratch = Path(temporary)
        os.chmod(scratch, 0o700)
        database = scratch / "workload.sqlite3"
        if args.verified_copy:
            input_binding = copy_verified_database(
                Path(args.verified_copy).resolve(strict=True),
                database,
                args.verified_copy_sha256,
            )
        else:
            input_binding = {"kind": "generated", "seed": 0}
        result = run_driver(driver, database, profile, timeouts[args.profile])
    source = source_binding(driver, profile_path)
    raw, summary = summarize(result, args.profile, profile, input_binding, source)
    limits = EvidenceLimits(max_json_bytes=MAX_DRIVER_OUTPUT_BYTES)
    with EvidenceWorkspace.create(output, repository_root=REPOSITORY_ROOT, limits=limits) as workspace:
        raw_attachment = workspace.write_json("raw-observations.json", raw)
        if raw_attachment.sha256 != summary["raw_observations_sha256"]:
            raise HarnessError("raw observation publication changed canonical bytes")
        summary_attachment = workspace.write_json("summary.json", summary)
        baseline_manifest = {
            "artifacts": [raw_attachment.as_dict(), summary_attachment.as_dict()],
            "candidate_bound": False,
            "candidate_bound_compatible": True,
            "outcome": "pass",
            "persistence_format": PERSISTENCE_FORMAT,
            "profile_id": args.profile,
            "schema_version": SCHEMA_VERSION,
            "source": source,
        }
        manifest_attachment = workspace.write_json(
            "baseline-manifest.json", baseline_manifest
        )
    return {
        "evidence_root": os.fspath(output),
        "manifest": manifest_attachment.as_dict(),
        "raw_observations": raw_attachment.as_dict(),
        "summary": summary_attachment.as_dict(),
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.output)
    limits = EvidenceLimits(max_json_bytes=MAX_DRIVER_OUTPUT_BYTES)
    with EvidenceWorkspace.create(root, repository_root=REPOSITORY_ROOT, limits=limits) as workspace:
        payloads = workspace.read_files(set(EVIDENCE_FILES))
    try:
        documents = {name: json.loads(payload) for name, payload in payloads.items()}
    except (UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError("evidence contains invalid JSON") from error
    raw = documents["raw-observations.json"]
    summary = documents["summary.json"]
    manifest = documents["baseline-manifest.json"]
    if (
        raw.get("schema_version") != SCHEMA_VERSION
        or summary.get("schema_version") != SCHEMA_VERSION
        or manifest.get("schema_version") != SCHEMA_VERSION
        or summary.get("outcome") != "pass"
        or manifest.get("outcome") != "pass"
    ):
        raise HarnessError("evidence outcome or schema is invalid")
    raw_digest = sha256_bytes(payloads["raw-observations.json"])
    summary_digest = sha256_bytes(payloads["summary.json"])
    attachments = {
        item["path"]: (item["sha256"], item["bytes"])
        for item in manifest.get("artifacts", [])
        if isinstance(item, dict) and set(item) == {"path", "sha256", "bytes"}
    }
    if (
        summary.get("raw_observations_sha256") != raw_digest
        or attachments
        != {
            "raw-observations.json": (raw_digest, len(payloads["raw-observations.json"])),
            "summary.json": (summary_digest, len(payloads["summary.json"])),
        }
    ):
        raise HarnessError("evidence content binding is invalid")
    return {
        "manifest_sha256": sha256_bytes(payloads["baseline-manifest.json"]),
        "outcome": "pass",
        "profile_id": manifest["profile_id"],
        "raw_observations_sha256": raw_digest,
        "summary_sha256": summary_digest,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="run a bounded v4 baseline")
    run.add_argument("--profile", choices=("small", "threshold", "hiero-shaped"), required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--driver")
    run.add_argument("--verified-copy")
    run.add_argument("--verified-copy-sha256")
    run.set_defaults(handler=execute)
    check = subcommands.add_parser("verify", help="verify a baseline evidence directory")
    check.add_argument("--output", required=True)
    check.set_defaults(handler=verify)
    return result


def main() -> int:
    args = parser().parse_args()
    if bool(getattr(args, "verified_copy", None)) != bool(
        getattr(args, "verified_copy_sha256", None)
    ):
        print("honey efficiency harness failed: verified copy and digest must be supplied together", file=sys.stderr)
        return 2
    try:
        value = args.handler(args)
        sys.stdout.buffer.write(canonical_json_bytes(value))
    except (HarnessError, EvidenceWorkspaceError, OSError, ValueError) as error:
        print(f"honey efficiency harness failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
