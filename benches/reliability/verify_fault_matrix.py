#!/usr/bin/env python3
"""Independently verify a content-free H094-600 fault-matrix receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Never

ROOT = Path(__file__).resolve().parents[2]
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    """Fault evidence is incomplete, changed, or internally inconsistent."""


def fail(message: str) -> Never:
    raise VerificationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def load(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("fault evidence is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not payload or len(payload) > 4 * 1024 * 1024 or not isinstance(value, dict):
        fail("fault evidence is invalid or unbounded")
    return value


def verify_file(binding: Any) -> Path:
    if not isinstance(binding, dict) or set(binding) != {"path", "bytes", "sha256"}:
        fail("file binding is invalid")
    path = Path(binding["path"])
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError("bound file is unavailable") from error
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or len(payload) != binding["bytes"]
        or hashlib.sha256(payload).hexdigest() != binding["sha256"]
    ):
        fail("bound file changed")
    return path


def git_bytes(*arguments: str) -> bytes:
    try:
        return subprocess.run(["git", *arguments], cwd=ROOT, check=True, capture_output=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationError("source binding cannot be recomputed") from error


def verify(report_path: Path) -> str:
    report = load(report_path)
    required = {
        "schema_version", "status", "source", "configuration", "manifest", "runner", "cargo",
        "required_fault_count", "case_count", "all_cases_passed", "results", "report_id",
    }
    if set(report) != required:
        fail("fault report fields are invalid")
    report_id = report.pop("report_id")
    if not isinstance(report_id, str) or SHA256.fullmatch(report_id) is None or report_id != hashlib.sha256(canonical(report)).hexdigest():
        fail("fault report identity disagrees")
    if report["schema_version"] != "cigar.h094-fault-matrix-result.v1" or report["status"] != "passed" or report["all_cases_passed"] is not True:
        fail("fault report did not pass")
    configuration_path = verify_file(report["configuration"])
    manifest_path = verify_file(report["manifest"])
    verify_file(report["runner"])
    verify_file(report["cargo"])
    configuration = load(configuration_path)
    manifest = load(manifest_path)
    cases = manifest.get("cases")
    required_faults = configuration.get("required_faults")
    if not isinstance(cases, list) or not isinstance(required_faults, list):
        fail("bound fault authority is invalid")
    expected_faults = [fault for case in cases for fault in case.get("faults", [])]
    if sorted(expected_faults) != sorted(required_faults) or len(expected_faults) != len(set(expected_faults)):
        fail("bound manifest fault coverage is not exact")
    if report["required_fault_count"] != len(required_faults) or report["case_count"] != len(cases):
        fail("fault report counts disagree")
    source = report["source"]
    if not isinstance(source, dict) or set(source) != {"revision", "diff_sha256", "status_sha256"}:
        fail("source binding fields are invalid")
    if re.fullmatch(r"[0-9a-f]{40,64}", source["revision"]) is None:
        fail("bound source revision is invalid")
    try:
        subprocess.run(
            ["git", "cat-file", "-e", f"{source['revision']}^{{commit}}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationError("bound source revision is unavailable") from error
    clean_digest = hashlib.sha256(b"").hexdigest()
    if source["diff_sha256"] != clean_digest or source["status_sha256"] != clean_digest:
        fail("fault campaign did not execute from a clean source revision")
    results = report["results"]
    if not isinstance(results, list) or len(results) != len(cases):
        fail("fault results are incomplete")
    exact_result_keys = {
        "case_id", "faults", "package", "test", "injection_mode", "expected", "command",
        "duration_nanoseconds", "exit_code", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256",
    }
    for case, result in zip(cases, results, strict=True):
        command = ["cargo", "test", "--offline", "-p", case["package"], case["test"], "--", "--exact"]
        if (
            not isinstance(result, dict)
            or set(result) != exact_result_keys
            or any(result[key] != case[key] for key in ("case_id", "faults", "package", "test", "injection_mode", "expected"))
            or result["command"] != command
            or result["exit_code"] != 0
            or isinstance(result["duration_nanoseconds"], bool)
            or result["duration_nanoseconds"] <= 0
            or not 0 <= result["stdout_bytes"] <= 4 * 1024 * 1024
            or not 0 <= result["stderr_bytes"] <= 4 * 1024 * 1024
            or SHA256.fullmatch(result["stdout_sha256"]) is None
            or SHA256.fullmatch(result["stderr_sha256"]) is None
        ):
            fail("fault case receipt is invalid")
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
    print(f"fault matrix evidence verified: {report_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
