#!/usr/bin/env python3
"""Run source-bound H094-600 retained-record lifecycle qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Never

ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION = Path(__file__).with_name("configuration.v1.json")
SCHEMA_VERSION = "cigar.h094-retained-record-result.v1"
MAX_OUTPUT_BYTES = 1024 * 1024


class ReliabilityError(RuntimeError):
    """One qualification invariant failed closed."""


def fail(message: str) -> Never:
    raise ReliabilityError(message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ReliabilityError("value is not canonical JSON") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fingerprint(path: Path) -> dict[str, Any]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            fail("bound input is not a regular file")
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ReliabilityError("bound input is unavailable") from error
    if len(payload) == 0 or len(payload) > 1024**3:
        fail("bound input exceeds its byte bound")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        fail("bound input changed while read")
    return {"path": str(path), "bytes": len(payload), "sha256": sha256_bytes(payload)}


def load_configuration() -> dict[str, Any]:
    try:
        value = json.loads(CONFIGURATION.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReliabilityError("reliability configuration is unavailable") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version")
        != "cigar.h094-reliability-configuration.v1"
        or value.get("retained_record_counts") != [8, 128, 4096, 100000, 1000000]
    ):
        fail("reliability configuration is invalid")
    return value


def private_directory(path: Path, *, create: bool) -> None:
    try:
        if create:
            path.mkdir(mode=0o700)
        metadata = path.lstat()
    except OSError as error:
        raise ReliabilityError("private directory is unavailable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or path.resolve(strict=True) != path
    ):
        fail("qualification directories must be canonical and owner-private")


def write_new(path: Path, value: Any, mode: int) -> None:
    payload = canonical(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ReliabilityError("qualification evidence publication failed") from error


def run(command: list[str], *, timeout: int = 86400) -> None:
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReliabilityError("qualification subprocess failed") from error
    if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
        fail("qualification subprocess output exceeded its bound")
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReliabilityError(f"qualification subprocess rejected the run: {message}")


def git_value(*arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReliabilityError("Git source binding failed") from error
    value = result.stdout.decode("ascii", errors="strict").strip()
    if not value or len(value) > 128:
        fail("Git source binding is invalid")
    return value


def profile(record_count: int) -> dict[str, Any]:
    if record_count not in {8, 128, 4096, 100000, 1000000}:
        fail("retained-record count is not registered")
    large_local = record_count == 1_000_000
    return {
        "schema_version": "cigar.local-scale-profile.v1",
        "id": "scaled_fixture",
        "platform": "aarch64-apple-darwin",
        "capacity_profile": "large_local" if large_local else "standard",
        "atoms": record_count,
        "edges": record_count,
        "blob_objects": 1,
        "blob_bytes_each": 8,
        "referenced_blob_bytes": 8,
        "atom_batch_size": min(record_count, 1000),
        "edge_batch_size": min(record_count, 10000),
        "maximum_database_bytes": 68719476736 if large_local else 4294967296,
        "minimum_initial_available_bytes": 1,
        "minimum_runtime_reserve_bytes": 1,
        "maximum_atoms": 1250000,
        "maximum_edges": 12500000,
        "maximum_referenced_blob_bytes": 137438953472,
    }


def execute(driver: Path, candidate: Path, output: Path) -> dict[str, Any]:
    configuration = load_configuration()
    private_directory(output, create=True)
    driver = driver.resolve(strict=True)
    candidate = candidate.resolve(strict=True)
    source_revision = git_value("rev-parse", "--verify", "HEAD")
    tree = git_value("rev-parse", "--verify", "HEAD^{tree}")
    source_tree_sha256 = sha256_bytes(tree.encode("ascii"))
    observations: list[dict[str, Any]] = []
    for record_count in configuration["retained_record_counts"]:
        case = output / f"records-{record_count}"
        case.mkdir(mode=0o700)
        evidence = case / "evidence"
        workspace = case / "workspace"
        repository = case / "repository"
        for directory in (evidence, workspace, repository):
            directory.mkdir(mode=0o700)
        profile_path = evidence / "profile.json"
        binding_path = evidence / "binding.json"
        result_path = evidence / "result.json"
        write_new(profile_path, profile(record_count), 0o600)
        run(
            [
                str(driver),
                "prepare-fixture",
                "--profile",
                str(profile_path),
                "--candidate",
                str(candidate),
                "--repository-root",
                str(repository),
                "--source-revision",
                source_revision,
                "--source-tree-sha256",
                source_tree_sha256,
                "--run-id",
                f"h094-600-retained-{record_count}",
                "--output",
                str(binding_path),
            ]
        )
        wall_started = time.monotonic_ns()
        run(
            [
                str(driver),
                "fixture-run",
                "--profile",
                str(profile_path),
                "--binding",
                str(binding_path),
                "--workspace",
                str(workspace),
                "--output",
                str(result_path),
            ]
        )
        wall_nanoseconds = time.monotonic_ns() - wall_started
        run(
            [
                str(driver),
                "verify",
                "--profile",
                str(profile_path),
                "--binding",
                str(binding_path),
                "--receipt",
                str(result_path),
            ]
        )
        receipt = json.loads(result_path.read_text(encoding="utf-8"))
        observations.append(
            {
                "record_count": record_count,
                "wall_nanoseconds": wall_nanoseconds,
                "database_bytes": receipt["storage"]["database_bytes"],
                "lifecycle": receipt["lifecycle"],
                "catalog_root_equal_after_restart": (
                    receipt["roots"]["semantic_before_reopen"]
                    == receipt["roots"]["semantic_after_reopen"]
                    == receipt["roots"]["semantic_after_restore"]
                ),
                "profile": fingerprint(profile_path),
                "binding": fingerprint(binding_path),
                "driver_receipt": fingerprint(result_path),
                "driver_receipt_id": receipt["receipt_id"],
            }
        )
    body = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "source_revision": source_revision,
        "source_tree_sha256": source_tree_sha256,
        "configuration": fingerprint(CONFIGURATION),
        "driver": fingerprint(driver),
        "candidate": fingerprint(candidate),
        "record_counts": configuration["retained_record_counts"],
        "observations": observations,
        "all_lifecycle_phases_measured": True,
        "all_roots_exact_after_restart_and_restore": all(
            item["catalog_root_equal_after_restart"] for item in observations
        ),
    }
    report = {**body, "report_id": sha256_bytes(canonical(body))}
    write_new(output / "retained-record-report.json", report, 0o400)
    return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        arguments = parse_arguments()
        report = execute(arguments.driver, arguments.candidate, arguments.out)
    except ReliabilityError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"retained-record qualification passed: {report['report_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
