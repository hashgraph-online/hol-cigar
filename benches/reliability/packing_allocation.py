#!/usr/bin/env python3
"""Run and bind the pre-registered H094-G07 packing-allocation qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Never


ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts/release"
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError  # noqa: E402


CONFIGURATION = Path(__file__).with_name("packing-allocation-configuration.v1.json")
DRIVER_SOURCE = (
    Path(__file__).with_name("compile_driver") / "src/bin/h094_packing_allocation.rs"
)
DRIVER_LOCK = Path(__file__).with_name("compile_driver") / "Cargo.lock"
RAW_NAME = "packing-allocation.raw.json"
REPORT_NAME = "packing-allocation-report.json"
MAX_JSON_BYTES = 16 * 1024 * 1024
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
BUNDLE_ID = re.compile(r"1220[0-9a-f]{64}")


class PackingAllocationError(RuntimeError):
    """The bounded packing-allocation qualification failed closed."""


def fail(message: str) -> Never:
    raise PackingAllocationError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def load_object(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PackingAllocationError("JSON input is unavailable") from error
    if not payload or len(payload) > MAX_JSON_BYTES or not isinstance(value, dict):
        fail("JSON input is empty, oversized, or not an object")
    return value


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def file_binding(path: Path, *, relative: bool) -> dict[str, Any]:
    try:
        original_metadata = path.lstat()
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
        payload = resolved.read_bytes()
    except OSError as error:
        raise PackingAllocationError("bound file is unavailable") from error
    if (
        stat.S_ISLNK(original_metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not payload
        or len(payload) > 1024**3
    ):
        fail("bound file is not a bounded regular file")
    if relative:
        try:
            name = resolved.relative_to(ROOT).as_posix()
        except ValueError as error:
            raise PackingAllocationError(
                "repository binding escapes the source root"
            ) from error
    else:
        name = resolved.name
    return {"path": name, "bytes": len(payload), "sha256": sha256_bytes(payload)}


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} fields are invalid")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} is not a bounded integer")
    return value


def load_configuration() -> dict[str, Any]:
    value = load_object(CONFIGURATION)
    _exact_keys(
        value,
        {
            "schema_version",
            "candidate_counts",
            "warmups_per_treatment_per_count",
            "measured_pairs_per_count",
            "treatment_order",
            "measurement_method",
            "bootstrap",
            "profiles",
            "thresholds",
            "fixture",
            "content_free",
        },
        "packing-allocation configuration",
    )
    bootstrap = _exact_keys(
        value["bootstrap"],
        {"algorithm", "resamples", "confidence_level_millionths", "seed_sha256"},
        "bootstrap configuration",
    )
    thresholds = _exact_keys(
        value["thresholds"],
        {
            "minimum_peak_live_reduction_millionths",
            "maximum_balanced_v4_peak_live_bytes",
            "maximum_balanced_v4_allocated_bytes_ratio_millionths",
            "maximum_balanced_v4_allocation_count_ratio_millionths",
        },
        "allocation thresholds",
    )
    absolute = _exact_keys(
        thresholds["maximum_balanced_v4_peak_live_bytes"],
        {"128", "512"},
        "absolute allocation thresholds",
    )
    profiles = _exact_keys(
        value["profiles"], {"balanced_v3", "balanced_v4"}, "profiles"
    )
    for label, expected_id, expected_digest in (
        (
            "balanced_v3",
            "cigar.compiler-profile.balanced.v3",
            "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7",
        ),
        (
            "balanced_v4",
            "cigar.compiler-profile.balanced.v4",
            "1220d28b42286c3db066f73b70b670ee32b13311319fd512d682e9f843864749bcf2",
        ),
    ):
        profile = _exact_keys(
            profiles[label], {"compiler_id", "compiler_digest"}, f"{label} profile"
        )
        if profile != {"compiler_id": expected_id, "compiler_digest": expected_digest}:
            fail(f"{label} profile binding drifted")
    fixture = _exact_keys(
        value["fixture"],
        {
            "lane",
            "token_count_per_candidate",
            "requirement_count",
            "entity_cycle",
            "mandatory_candidates",
            "dependencies",
            "policy_outcome",
        },
        "allocation fixture",
    )
    if (
        value["schema_version"] != "cigar.h094-packing-allocation-configuration.v1"
        or value["candidate_counts"] != [128, 512]
        or value["warmups_per_treatment_per_count"] != 40
        or value["measured_pairs_per_count"] != 200
        or value["treatment_order"] != "pair-parity-alternating-v1"
        or value["measurement_method"]
        != "system-allocator-peak-live-above-precompiled-request-baseline-v1"
        or bootstrap["algorithm"] != "paired-sha256-counter-bootstrap-v1"
        or bootstrap["resamples"] != 10_000
        or bootstrap["confidence_level_millionths"] != 950_000
        or not isinstance(bootstrap["seed_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", bootstrap["seed_sha256"]) is None
        or thresholds["minimum_peak_live_reduction_millionths"] != 400_000
        or thresholds["maximum_balanced_v4_allocated_bytes_ratio_millionths"]
        != 1_000_000
        or thresholds["maximum_balanced_v4_allocation_count_ratio_millionths"]
        != 1_000_000
        or absolute != {"128": 4_194_304, "512": 16_777_216}
        or fixture
        != {
            "lane": "evidence",
            "token_count_per_candidate": 1,
            "requirement_count": 0,
            "entity_cycle": 64,
            "mandatory_candidates": 0,
            "dependencies": 0,
            "policy_outcome": "allow",
        }
        or value["content_free"] is not True
    ):
        fail("packing-allocation configuration drifted")
    return value


def validate_raw(value: dict[str, Any], configuration: dict[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "measurement_method",
            "candidate_counts",
            "warmups_per_treatment_per_count",
            "measured_pairs_per_count",
            "profiles",
            "cells",
        },
        "packing-allocation raw result",
    )
    if (
        value["schema_version"] != "cigar.h094-packing-allocation-raw.v1"
        or value["measurement_method"] != configuration["measurement_method"]
        or value["candidate_counts"] != configuration["candidate_counts"]
        or value["warmups_per_treatment_per_count"]
        != configuration["warmups_per_treatment_per_count"]
        or value["measured_pairs_per_count"]
        != configuration["measured_pairs_per_count"]
        or value["profiles"] != configuration["profiles"]
    ):
        fail("packing-allocation driver authority drifted")
    cells = value["cells"]
    if (
        not isinstance(cells, list)
        or [cell.get("candidate_count") for cell in cells]
        != configuration["candidate_counts"]
    ):
        fail("packing-allocation cells are missing or reordered")
    sample_keys = {
        "peak_live_bytes",
        "allocated_bytes",
        "allocation_count",
        "selected_items",
        "bundle_id",
    }
    for cell in cells:
        _exact_keys(cell, {"candidate_count", "pairs"}, "allocation cell")
        candidate_count = _integer(
            cell["candidate_count"], "candidate count", minimum=1
        )
        pairs = cell["pairs"]
        if (
            not isinstance(pairs, list)
            or len(pairs) != configuration["measured_pairs_per_count"]
        ):
            fail("allocation cell pair count drifted")
        identities: dict[str, set[str]] = {"balanced_v3": set(), "balanced_v4": set()}
        selected_counts: dict[str, set[int]] = {
            "balanced_v3": set(),
            "balanced_v4": set(),
        }
        for index, pair in enumerate(pairs):
            _exact_keys(
                pair,
                {"pair", "order", "balanced_v3", "balanced_v4"},
                "allocation pair",
            )
            expected_order = (
                ["balanced_v3", "balanced_v4"]
                if index % 2 == 0
                else ["balanced_v4", "balanced_v3"]
            )
            if pair["pair"] != index or pair["order"] != expected_order:
                fail("allocation pair identity or treatment order drifted")
            for treatment in ("balanced_v3", "balanced_v4"):
                sample = _exact_keys(pair[treatment], sample_keys, "allocation sample")
                for metric in (
                    "peak_live_bytes",
                    "allocated_bytes",
                    "allocation_count",
                    "selected_items",
                ):
                    minimum = 0 if metric == "selected_items" else 1
                    _integer(sample[metric], f"{treatment} {metric}", minimum=minimum)
                if sample["selected_items"] > candidate_count:
                    fail(
                        "allocation sample selected-item count exceeds "
                        "the candidate bound"
                    )
                if (
                    not isinstance(sample["bundle_id"], str)
                    or BUNDLE_ID.fullmatch(sample["bundle_id"]) is None
                ):
                    fail("allocation sample bundle identity is malformed")
                identities[treatment].add(sample["bundle_id"])
                selected_counts[treatment].add(sample["selected_items"])
        if any(
            len(values) != 1
            for values in (*identities.values(), *selected_counts.values())
        ):
            fail("allocation samples are semantically nondeterministic")


def percentile(values: list[int], numerator: int, denominator: int) -> int:
    ordered = sorted(values)
    index = max(0, (len(ordered) * numerator + denominator - 1) // denominator - 1)
    return ordered[min(index, len(ordered) - 1)]


def metric_summary(values: list[int]) -> dict[str, int]:
    if not values:
        fail("cannot summarize an empty metric")
    p50 = percentile(values, 50, 100)
    deviations = [abs(value - p50) for value in values]
    return {
        "count": len(values),
        "minimum": min(values),
        "maximum": max(values),
        "mean_millionths": sum(values) * 1_000_000 // len(values),
        "p50": p50,
        "p95": percentile(values, 95, 100),
        "p99": percentile(values, 99, 100),
        "median_absolute_deviation": percentile(deviations, 50, 100),
    }


def ratio_millionths(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        fail("allocation ratio denominator is not positive")
    return numerator * 1_000_000 // denominator


def reduction_millionths(baseline: list[int], candidate: list[int]) -> int:
    return ratio_millionths(sum(baseline) - sum(candidate), sum(baseline))


def _bootstrap_indices(seed: bytes, resample: int, length: int) -> list[int]:
    indices: list[int] = []
    counter = 0
    while len(indices) < length:
        block = hashlib.sha256(
            b"CIGAR-H094-G07-BOOTSTRAP\0v1\0"
            + seed
            + resample.to_bytes(8, "big")
            + counter.to_bytes(8, "big")
        ).digest()
        for offset in range(0, len(block), 8):
            indices.append(int.from_bytes(block[offset : offset + 8], "big") % length)
            if len(indices) == length:
                break
        counter += 1
    return indices


def bootstrap_interval(
    baseline: list[int], candidate: list[int], configuration: dict[str, Any]
) -> list[int]:
    if len(baseline) != len(candidate) or not baseline:
        fail("paired bootstrap inputs are invalid")
    seed = bytes.fromhex(configuration["bootstrap"]["seed_sha256"])
    results = []
    for resample in range(configuration["bootstrap"]["resamples"]):
        indices = _bootstrap_indices(seed, resample, len(baseline))
        results.append(
            reduction_millionths(
                [baseline[index] for index in indices],
                [candidate[index] for index in indices],
            )
        )
    return [percentile(results, 25, 1000), percentile(results, 975, 1000)]


def evaluate(value: dict[str, Any], configuration: dict[str, Any]) -> dict[str, Any]:
    validate_raw(value, configuration)
    cells = []
    overall = True
    thresholds = configuration["thresholds"]
    for cell in value["cells"]:
        treatments: dict[str, dict[str, Any]] = {}
        series: dict[str, dict[str, list[int]]] = {}
        for treatment in ("balanced_v3", "balanced_v4"):
            metrics = {
                metric: [pair[treatment][metric] for pair in cell["pairs"]]
                for metric in ("peak_live_bytes", "allocated_bytes", "allocation_count")
            }
            series[treatment] = metrics
            treatments[treatment] = {
                metric: metric_summary(values) for metric, values in metrics.items()
            }
            treatments[treatment]["selected_items"] = cell["pairs"][0][treatment][
                "selected_items"
            ]
            treatments[treatment]["bundle_id"] = cell["pairs"][0][treatment][
                "bundle_id"
            ]
        v3 = series["balanced_v3"]
        v4 = series["balanced_v4"]
        peak_reduction = reduction_millionths(
            v3["peak_live_bytes"], v4["peak_live_bytes"]
        )
        peak_interval = bootstrap_interval(
            v3["peak_live_bytes"], v4["peak_live_bytes"], configuration
        )
        allocated_ratio = ratio_millionths(
            sum(v4["allocated_bytes"]), sum(v3["allocated_bytes"])
        )
        count_ratio = ratio_millionths(
            sum(v4["allocation_count"]), sum(v3["allocation_count"])
        )
        maximum_peak = thresholds["maximum_balanced_v4_peak_live_bytes"][
            str(cell["candidate_count"])
        ]
        gates = {
            "peak_reduction": peak_interval[0]
            >= thresholds["minimum_peak_live_reduction_millionths"],
            "absolute_peak_bound": max(v4["peak_live_bytes"]) <= maximum_peak,
            "allocated_bytes_nonregression": allocated_ratio
            <= thresholds["maximum_balanced_v4_allocated_bytes_ratio_millionths"],
            "allocation_count_nonregression": count_ratio
            <= thresholds["maximum_balanced_v4_allocation_count_ratio_millionths"],
        }
        passed = all(gates.values())
        overall = overall and passed
        cells.append(
            {
                "candidate_count": cell["candidate_count"],
                "status": "passed" if passed else "failed",
                "treatments": treatments,
                "comparison": {
                    "peak_live_reduction_millionths": peak_reduction,
                    "peak_live_reduction_95pct_bootstrap_interval_millionths": (
                        peak_interval
                    ),
                    "allocated_bytes_ratio_millionths": allocated_ratio,
                    "allocation_count_ratio_millionths": count_ratio,
                },
                "gates": gates,
            }
        )
    return {
        "status": "passed" if overall else "failed",
        "cells": cells,
    }


def clean_source_snapshot() -> dict[str, Any]:
    def git(*arguments: str) -> bytes:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=ROOT,
                check=False,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise PackingAllocationError(
                "Git source identity is unavailable"
            ) from error
        if result.returncode != 0 or len(result.stdout) > 32 * 1024 * 1024:
            fail("Git source identity command failed")
        return result.stdout

    try:
        revision = git("rev-parse", "--verify", "HEAD").strip().decode("ascii")
        tree = git("rev-parse", "--verify", "HEAD^{tree}").strip().decode("ascii")
    except UnicodeError as error:
        raise PackingAllocationError("Git source identity is not ASCII") from error
    if OBJECT_ID.fullmatch(revision) is None or OBJECT_ID.fullmatch(tree) is None:
        fail("Git source identity is malformed")
    if git("status", "--porcelain=v1", "-z", "--untracked-files=all"):
        fail("packing-allocation qualification requires a clean committed source")
    return {"revision": revision, "tree": tree, "clean": True}


def execute(driver: Path, output: Path) -> dict[str, Any]:
    configuration = load_configuration()
    source_before = clean_source_snapshot()
    if not output.is_absolute() or output.exists():
        fail("evidence output must be a new absolute directory")
    driver_binding = file_binding(driver, relative=False)
    with tempfile.TemporaryDirectory(prefix="cigar-h094-g07-") as temporary:
        raw_path = Path(temporary).resolve() / RAW_NAME
        try:
            result = subprocess.run(
                [str(driver.resolve(strict=True)), "--output", str(raw_path)],
                cwd=ROOT,
                env={
                    "HOME": os.environ.get("HOME", ""),
                    "LC_ALL": "C",
                    "PATH": os.environ.get("PATH", ""),
                },
                check=False,
                capture_output=True,
                timeout=600,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise PackingAllocationError(
                "packing-allocation driver could not execute"
            ) from error
        if (
            result.returncode != 0
            or result.stdout
            or len(result.stderr) > 1024 * 1024
            or not raw_path.is_file()
        ):
            fail("packing-allocation driver rejected the registered run")
        raw = load_object(raw_path)
    source_after = clean_source_snapshot()
    if source_after != source_before:
        fail("source identity changed during packing-allocation qualification")
    evaluation = evaluate(raw, configuration)
    raw_payload = canonical(raw) + b"\n"
    bindings = {
        "configuration": file_binding(CONFIGURATION, relative=True),
        "driver_source": file_binding(DRIVER_SOURCE, relative=True),
        "driver_lock": file_binding(DRIVER_LOCK, relative=True),
        "driver_binary": driver_binding,
        "raw": {
            "path": RAW_NAME,
            "bytes": len(raw_payload),
            "sha256": sha256_bytes(raw_payload),
        },
    }
    body = {
        "schema_version": "cigar.h094-packing-allocation-report.v1",
        "status": evaluation["status"],
        "source": source_before,
        "bindings": bindings,
        "configuration_id": configuration["schema_version"],
        "evaluation": evaluation,
    }
    report = {**body, "report_id": sha256_bytes(canonical(body))}
    workspace = EvidenceWorkspace.create(output, repository_root=ROOT)
    try:
        workspace.write_json(RAW_NAME, raw)
        workspace.write_json(REPORT_NAME, report)
    finally:
        workspace.close()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = execute(arguments.driver, arguments.out)
    except (EvidenceWorkspaceError, PackingAllocationError) as error:
        print(f"packing-allocation qualification failed: {error}", file=sys.stderr)
        return 2
    print(f"packing-allocation qualification {report['status']}: {report['report_id']}")
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
