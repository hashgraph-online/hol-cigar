#!/usr/bin/env python3
"""Execute the preregistered H094-600 production fault matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Never

ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION = Path(__file__).with_name("configuration.v1.json")
MANIFEST = Path(__file__).with_name("fault-matrix.v1.json")
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
TEST_NAME = re.compile(r"^[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*$")


class FaultMatrixError(RuntimeError):
    """Fault qualification did not prove the registered contract."""


def fail(message: str) -> Never:
    raise FaultMatrixError(message)


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
        raise FaultMatrixError("value is not canonical JSON") from error


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_object(path: Path, maximum: int = 1024 * 1024) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FaultMatrixError("fault-matrix input is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not payload
        or len(payload) > maximum
        or not isinstance(value, dict)
    ):
        fail("fault-matrix input is invalid or unbounded")
    return value


def fingerprint(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    payload = path.read_bytes()
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not payload:
        fail("bound input is not a non-empty regular file")
    return {"path": str(path), "bytes": len(payload), "sha256": sha256(payload)}


def git_bytes(*arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments], cwd=ROOT, check=True, capture_output=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FaultMatrixError("Git source binding failed") from error
    return result.stdout


def validate_manifest(manifest: dict[str, Any], configuration: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {"schema_version", "cases"} or manifest["schema_version"] != "cigar.h094-fault-matrix.v1":
        fail("fault manifest authority is invalid")
    cases = manifest["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > 64:
        fail("fault manifest case count is invalid")
    seen_cases: set[str] = set()
    observed_faults: list[str] = []
    exact_keys = {"case_id", "faults", "package", "test", "injection_mode", "expected"}
    for case in cases:
        if not isinstance(case, dict) or set(case) != exact_keys:
            fail("fault case fields are invalid")
        case_id = case["case_id"]
        faults = case["faults"]
        if (
            not isinstance(case_id, str)
            or IDENTIFIER.fullmatch(case_id) is None
            or case_id in seen_cases
            or not isinstance(faults, list)
            or not faults
            or len(faults) > 8
            or any(not isinstance(fault, str) or IDENTIFIER.fullmatch(fault) is None for fault in faults)
            or not isinstance(case["package"], str)
            or IDENTIFIER.fullmatch(case["package"]) is None
            or not isinstance(case["test"], str)
            or TEST_NAME.fullmatch(case["test"]) is None
            or not isinstance(case["injection_mode"], str)
            or IDENTIFIER.fullmatch(case["injection_mode"]) is None
            or case["expected"] not in {"exact_recovery", "fail_closed", "deterministic_degradation"}
        ):
            fail("fault case value is invalid")
        seen_cases.add(case_id)
        observed_faults.extend(faults)
    required = configuration.get("required_faults")
    if not isinstance(required, list) or sorted(observed_faults) != sorted(required) or len(set(observed_faults)) != len(observed_faults):
        fail("fault manifest does not cover every registered fault exactly once")
    return cases


def source_binding() -> dict[str, str]:
    revision = git_bytes("rev-parse", "--verify", "HEAD").decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", revision) is None:
        fail("source revision is invalid")
    return {
        "revision": revision,
        "diff_sha256": sha256(git_bytes("diff", "--binary", "HEAD")),
        "status_sha256": sha256(git_bytes("status", "--porcelain=v1", "--untracked-files=all")),
    }


def command_environment() -> dict[str, str]:
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        "RUST_BACKTRACE": "0",
    }
    for name in ("CARGO_HOME", "RUSTUP_HOME", "TMPDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def execute(output: Path) -> dict[str, Any]:
    if not output.is_absolute() or output.exists():
        fail("fault evidence output must be a new absolute directory")
    output.mkdir(mode=0o700)
    configuration = load_object(CONFIGURATION)
    manifest = load_object(MANIFEST)
    cases = validate_manifest(manifest, configuration)
    environment = command_environment()
    results = []
    for case in cases:
        command = [
            "cargo", "test", "--offline", "-p", case["package"], case["test"],
            "--", "--exact",
        ]
        started = time.monotonic_ns()
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                timeout=1800,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise FaultMatrixError(f"fault case {case['case_id']} did not execute") from error
        duration = time.monotonic_ns() - started
        stdout = completed.stdout
        stderr = completed.stderr
        if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
            fail(f"fault case {case['case_id']} output exceeded its bound")
        if completed.returncode != 0 or b"1 passed; 0 failed" not in stdout:
            fail(f"fault case {case['case_id']} failed")
        results.append(
            {
                "case_id": case["case_id"],
                "faults": case["faults"],
                "package": case["package"],
                "test": case["test"],
                "injection_mode": case["injection_mode"],
                "expected": case["expected"],
                "command": command,
                "duration_nanoseconds": duration,
                "exit_code": completed.returncode,
                "stdout_bytes": len(stdout),
                "stdout_sha256": sha256(stdout),
                "stderr_bytes": len(stderr),
                "stderr_sha256": sha256(stderr),
            }
        )
    body = {
        "schema_version": "cigar.h094-fault-matrix-result.v1",
        "status": "passed",
        "source": source_binding(),
        "configuration": fingerprint(CONFIGURATION),
        "manifest": fingerprint(MANIFEST),
        "runner": fingerprint(Path(__file__)),
        "cargo": fingerprint(Path(subprocess.run(["which", "cargo"], check=True, capture_output=True, env=environment).stdout.decode().strip())),
        "required_fault_count": len(configuration["required_faults"]),
        "case_count": len(cases),
        "all_cases_passed": True,
        "results": results,
    }
    report = {**body, "report_id": sha256(canonical(body))}
    payload = canonical(report) + b"\n"
    descriptor = os.open(
        output / "fault-matrix-report.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = execute(arguments.out)
    except (FaultMatrixError, subprocess.SubprocessError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"fault matrix passed: {report['report_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
