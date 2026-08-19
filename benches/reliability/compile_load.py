#!/usr/bin/env python3
"""Bind and run the release-mode bounded compiler load driver."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Never

ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION = Path(__file__).with_name("configuration.v1.json")


class CompileLoadError(RuntimeError):
    """The compile-load qualification failed closed."""


def fail(message: str) -> Never:
    raise CompileLoadError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def fingerprint(path: Path) -> dict[str, Any]:
    try:
        path = path.resolve(strict=True)
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise CompileLoadError("bound file is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not payload or len(payload) > 1024**3:
        fail("bound file is not a bounded regular file")
    return {"path": str(path), "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CompileLoadError("JSON input is unavailable") from error
    if not isinstance(value, dict) or not payload or len(payload) > 16 * 1024 * 1024:
        fail("JSON input is invalid or unbounded")
    return value


def validate_raw(value: dict[str, Any], configuration: dict[str, Any]) -> None:
    if set(value) != {
        "schema_version", "compiler_profile", "candidate_count", "requirement_count",
        "queue_capacity", "iterations_per_cell", "concurrency", "allocation_probe", "cells",
    }:
        fail("compile driver fields are invalid")
    concurrency = configuration["compile_concurrency"]
    if (
        value["schema_version"] != "cigar.h094-compile-load-result.v1"
        or value["compiler_profile"] != "cigar.compiler-profile.balanced.v4"
        or value["candidate_count"] != 128
        or value["requirement_count"] != 4
        or value["queue_capacity"] != configuration["compile_queue_capacity"]
        or value["iterations_per_cell"] != configuration["compile_iterations_per_cell"]
        or value["concurrency"] != concurrency
    ):
        fail("compile driver authority differs from the registered configuration")
    probe = value["allocation_probe"]
    if (
        not isinstance(probe, dict)
        or set(probe) != {
            "warmup_iterations", "measurement_iterations", "operations_per_iteration",
            "live_bytes_before", "live_bytes_after", "live_allocations_before",
            "live_allocations_after", "peak_live_bytes", "zero_monotonic_growth",
        }
        or probe["warmup_iterations"] != 128
        or probe["measurement_iterations"] != 2_000
        or probe["operations_per_iteration"] != 2
        or probe["zero_monotonic_growth"] is not True
        or any(
            isinstance(probe[key], bool) or not isinstance(probe[key], int) or probe[key] < 0
            for key in (
                "live_bytes_before", "live_bytes_after", "live_allocations_before",
                "live_allocations_after", "peak_live_bytes",
            )
        )
        or probe["live_bytes_after"] > probe["live_bytes_before"]
        or probe["live_allocations_after"] > probe["live_allocations_before"]
        or probe["peak_live_bytes"] < max(probe["live_bytes_before"], probe["live_bytes_after"])
    ):
        fail("compile allocation probe observed live growth or invalid accounting")
    expected = [(operation, workers) for operation in ("full_bundle", "delta") for workers in concurrency]
    cells = value["cells"]
    if not isinstance(cells, list) or [(cell.get("operation"), cell.get("concurrency")) for cell in cells] != expected:
        fail("compile driver cells are incomplete or reordered")
    exact_keys = {
        "operation", "concurrency", "queue_capacity", "iterations", "wall_nanoseconds",
        "operation_nanoseconds_p50", "operation_nanoseconds_p95", "maximum_queue_depth",
        "rejected", "completed", "deterministic",
    }
    for cell in cells:
        numeric = ("wall_nanoseconds", "operation_nanoseconds_p50", "operation_nanoseconds_p95")
        if (
            set(cell) != exact_keys
            or cell["queue_capacity"] != configuration["compile_queue_capacity"]
            or cell["iterations"] != configuration["compile_iterations_per_cell"]
            or cell["completed"] != cell["iterations"]
            or cell["rejected"] != 0
            or cell["deterministic"] is not True
            or not 0 <= cell["maximum_queue_depth"] <= cell["queue_capacity"]
            or any(isinstance(cell[key], bool) or not isinstance(cell[key], int) or cell[key] <= 0 for key in numeric)
            or cell["operation_nanoseconds_p50"] > cell["operation_nanoseconds_p95"]
        ):
            fail("compile driver cell invariant failed")


def write_new(path: Path, value: Any, mode: int) -> None:
    payload = canonical(value) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise CompileLoadError("compile evidence publication failed") from error


def execute(driver: Path, candidate: Path, output: Path) -> dict[str, Any]:
    configuration = load_json(CONFIGURATION)
    if output.exists() or not output.is_absolute():
        fail("output must be a new absolute directory")
    output.mkdir(mode=0o700)
    driver_binding = fingerprint(driver)
    candidate_binding = fingerprint(candidate)
    raw_path = output / "compile-load.raw.json"
    try:
        source_revision = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, check=True, capture_output=True, timeout=30
        ).stdout.decode("ascii").strip()
        result = subprocess.run(
            [
                str(driver_binding["path"]), "--output", str(raw_path), "--iterations",
                str(configuration["compile_iterations_per_cell"]), "--queue-capacity",
                str(configuration["compile_queue_capacity"]),
            ],
            cwd=ROOT,
            env={"HOME": os.environ.get("HOME", ""), "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
            check=False,
            capture_output=True,
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CompileLoadError("compile driver could not execute") from error
    if result.returncode != 0 or len(result.stdout) > 1024**2 or len(result.stderr) > 1024**2:
        fail("compile driver rejected the registered run")
    raw = load_json(raw_path)
    validate_raw(raw, configuration)
    body = {
        "schema_version": "cigar.h094-bound-compile-load-result.v1",
        "status": "passed",
        "source_revision": source_revision,
        "configuration": fingerprint(CONFIGURATION),
        "driver": driver_binding,
        "candidate": candidate_binding,
        "raw": fingerprint(raw_path),
        "queue_capacity_fixed": True,
        "all_cells_deterministic": True,
        "allocation_probe": raw["allocation_probe"],
        "cells": raw["cells"],
    }
    report = {**body, "report_id": hashlib.sha256(canonical(body)).hexdigest()}
    write_new(output / "compile-load-report.json", report, 0o400)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = execute(arguments.driver, arguments.candidate, arguments.out)
    except CompileLoadError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"compile-load qualification passed: {report['report_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
