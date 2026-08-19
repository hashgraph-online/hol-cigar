#!/usr/bin/env python3
"""Independent read-only verifier for H094-600 retained-record evidence."""

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

COUNTS = [8, 128, 4096, 100000, 1000000]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MULTIHASH = re.compile(r"^1220[0-9a-f]{64}$")
LIFECYCLE = {
    "cold_start_nanoseconds",
    "steady_state_nanoseconds",
    "restart_nanoseconds",
    "warm_start_nanoseconds",
}


class VerificationError(RuntimeError):
    """Evidence is incomplete, inconsistent, or unbound."""


def fail(message: str) -> Never:
    raise VerificationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def rust_struct_json(value: Any) -> bytes:
    """Reproduce serde's declared struct-field order for Rust receipt identities."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def bounded_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError("evidence input is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not payload
        or len(payload) > 1024 * 1024
    ):
        fail("evidence input is not a bounded regular file")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("evidence JSON is invalid") from error
    if not isinstance(value, dict):
        fail("evidence root must be an object")
    return value, payload


def verify_fingerprint(value: Any) -> Path:
    if not isinstance(value, dict) or set(value) != {"path", "bytes", "sha256"}:
        fail("file fingerprint is invalid")
    path = Path(value["path"])
    try:
        payload = path.read_bytes()
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError("bound file is unavailable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or value["bytes"] != len(payload)
        or value["sha256"] != hashlib.sha256(payload).hexdigest()
    ):
        fail("file fingerprint binding disagrees")
    return path


def verify_driver_receipt(receipt: dict[str, Any], count: int) -> None:
    if receipt.get("schema_version") != "cigar.local-scale-result.v1":
        fail("driver receipt schema is invalid")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or MULTIHASH.fullmatch(receipt_id) is None:
        fail("driver receipt identity is invalid")
    body = dict(receipt)
    body.pop("receipt_id")
    if receipt_id != "1220" + hashlib.sha256(rust_struct_json(body)).hexdigest():
        fail("driver receipt identity disagrees")
    if (
        receipt.get("result") != "fixture-passed"
        or receipt.get("release_scale_qualified") is not False
        or receipt.get("targets", {}).get("atoms") != count
        or receipt.get("observed") != receipt.get("targets")
        or set(receipt.get("lifecycle", {})) != LIFECYCLE
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in receipt["lifecycle"].values()
        )
    ):
        fail("driver receipt lifecycle or retained-record observation is invalid")
    roots = receipt.get("roots", {})
    if not (
        roots.get("semantic_before_reopen")
        == roots.get("semantic_after_reopen")
        == roots.get("semantic_after_restore")
    ):
        fail("restart or restore changed the semantic root")


def verify(report_path: Path, driver: Path) -> str:
    report, _ = bounded_json(report_path)
    expected_keys = {
        "schema_version",
        "status",
        "source_revision",
        "source_tree_sha256",
        "configuration",
        "driver",
        "candidate",
        "record_counts",
        "observations",
        "all_lifecycle_phases_measured",
        "all_roots_exact_after_restart_and_restore",
        "report_id",
    }
    if set(report) != expected_keys:
        fail("retained-record report fields are invalid")
    report_id = report.pop("report_id")
    if not isinstance(report_id, str) or report_id != hashlib.sha256(canonical(report)).hexdigest():
        fail("retained-record report identity disagrees")
    if (
        report["schema_version"] != "cigar.h094-retained-record-result.v1"
        or report["status"] != "passed"
        or report["record_counts"] != COUNTS
        or report["all_lifecycle_phases_measured"] is not True
        or report["all_roots_exact_after_restart_and_restore"] is not True
        or not isinstance(report["source_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", report["source_revision"]) is None
        or not isinstance(report["source_tree_sha256"], str)
        or SHA256.fullmatch(report["source_tree_sha256"]) is None
    ):
        fail("retained-record report status or binding is invalid")
    bound_driver = verify_fingerprint(report["driver"])
    if bound_driver != driver.resolve(strict=True):
        fail("independent verifier driver differs from report")
    verify_fingerprint(report["candidate"])
    verify_fingerprint(report["configuration"])
    observations = report["observations"]
    if not isinstance(observations, list) or [item.get("record_count") for item in observations] != COUNTS:
        fail("retained-record observations are incomplete or reordered")
    for observation in observations:
        if set(observation) != {
            "record_count",
            "wall_nanoseconds",
            "database_bytes",
            "lifecycle",
            "catalog_root_equal_after_restart",
            "profile",
            "binding",
            "driver_receipt",
            "driver_receipt_id",
        }:
            fail("retained-record observation fields are invalid")
        count = observation["record_count"]
        if (
            isinstance(observation["wall_nanoseconds"], bool)
            or observation["wall_nanoseconds"] <= 0
            or isinstance(observation["database_bytes"], bool)
            or observation["database_bytes"] <= 0
            or set(observation["lifecycle"]) != LIFECYCLE
            or observation["catalog_root_equal_after_restart"] is not True
        ):
            fail("retained-record measurement is invalid")
        profile = verify_fingerprint(observation["profile"])
        binding = verify_fingerprint(observation["binding"])
        receipt_path = verify_fingerprint(observation["driver_receipt"])
        receipt, _ = bounded_json(receipt_path)
        verify_driver_receipt(receipt, count)
        if observation["driver_receipt_id"] != receipt["receipt_id"]:
            fail("nested driver receipt identity disagrees")
        try:
            result = subprocess.run(
                [
                    str(bound_driver),
                    "verify",
                    "--profile",
                    str(profile),
                    "--binding",
                    str(binding),
                    "--receipt",
                    str(receipt_path),
                ],
                env={"HOME": os.environ.get("HOME", ""), "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
                check=False,
                capture_output=True,
                timeout=900,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise VerificationError("bound Rust verifier could not execute") from error
        if result.returncode != 0 or len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
            fail("bound Rust verifier rejected nested evidence")
    return report_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report_id = verify(arguments.report, arguments.driver)
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"retained-record evidence verified: {report_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
