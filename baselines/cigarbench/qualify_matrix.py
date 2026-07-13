#!/usr/bin/env python3
"""Replay and qualify the complete CIGARBench baseline/ablation matrix."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Never, Sequence

ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / "benches" / "cigarbench" / "cigarbench.py"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_REPORTS = 32


class MatrixError(Exception):
    """A content-free qualification-matrix failure."""


def fail(message: str) -> Never:
    raise MatrixError(message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise MatrixError("matrix value is not canonical JSON") from error


def load_analyzer() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "cigarbench_matrix_analyzer", ANALYZER
    )
    if specification is None or specification.loader is None:
        fail("canonical analyzer is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def comparator_inventory(manifest: dict[str, Any], analyzer: ModuleType) -> set[str]:
    validated = analyzer.validate_baseline_manifest(manifest)
    return analyzer.declared_comparator_ids(validated)


def validate_matrix_reports(
    reports: dict[str, dict[str, Any]], expected: set[str]
) -> dict[str, Any]:
    if not reports or len(reports) > MAX_REPORTS or set(reports) != expected:
        fail("qualification matrix comparator inventory is incomplete")
    shared_manifest_bindings: set[bytes] = set()
    seed_commitments: set[str] = set()
    pin_sets: set[bytes] = set()
    input_digests: set[str] = set()
    report_digests: set[str] = set()
    for comparator_id, report in reports.items():
        comparison = report.get("comparison")
        qualification = report.get("qualification")
        manifests = report.get("input_manifests")
        if (
            not IDENTIFIER.fullmatch(comparator_id)
            or not isinstance(comparison, dict)
            or comparison.get("comparator_id") != comparator_id
            or comparison.get("evidence_class") != "qualification"
            or not isinstance(comparison.get("pins"), dict)
        ):
            fail("qualification report comparator binding is invalid")
        if (
            report.get("decision") != "pass"
            or not isinstance(qualification, dict)
            or qualification.get("eligible") is not True
            or qualification.get("evaluator_attestation", {}).get("verified")
            is not True
            or report.get("bootstrap_repetitions", 0) < 10_000
        ):
            fail("one comparator lacks passing qualification evidence")
        if not isinstance(manifests, dict) or set(manifests) != {
            "plan",
            "datasets",
            "baselines",
            "canaries",
            "environment",
        }:
            fail("qualification report input bindings are invalid")
        shared_manifest_bindings.add(
            canonical(
                {
                    key: manifests[key]
                    for key in ("datasets", "baselines", "canaries", "environment")
                }
            )
        )
        seed = report.get("seed_commitment")
        input_digest = report.get("input_digest")
        report_digest = report.get("report_digest")
        if not all(
            isinstance(value, str) and re.fullmatch(r"1220[0-9a-f]{64}", value)
            for value in (seed, input_digest, report_digest)
        ):
            fail("qualification report digest binding is invalid")
        seed_commitments.add(seed)
        input_digests.add(input_digest)
        report_digests.add(report_digest)
        pin_sets.add(canonical(comparison["pins"]))
    if (
        len(shared_manifest_bindings) != 1
        or len(seed_commitments) != 1
        or len(pin_sets) != 1
        or len(input_digests) != len(expected)
        or len(report_digests) != len(expected)
    ):
        fail("qualification matrix is not one equally pinned paired experiment")
    return {
        "schema_version": "cigar.benchmark-matrix-report.v1",
        "status": "pass",
        "comparators": sorted(expected),
        "shared_seed_commitment": next(iter(seed_commitments)),
        "shared_input_manifests": json.loads(next(iter(shared_manifest_bindings))),
        "reports": {
            comparator_id: reports[comparator_id]["report_digest"]
            for comparator_id in sorted(reports)
        },
    }


def qualify(args: argparse.Namespace) -> int:
    analyzer = load_analyzer()
    manifest = analyzer.load_json(args.baselines)
    expected = comparator_inventory(manifest, analyzer)
    root = args.evidence_root.resolve()
    if args.evidence_root.is_symlink() or not root.is_dir():
        fail("matrix evidence root must be a regular directory")
    actual_directories = {
        path.name for path in root.iterdir() if path.is_dir() and not path.is_symlink()
    }
    if actual_directories != expected:
        fail("matrix evidence directories do not match the comparator inventory")
    reports: dict[str, dict[str, Any]] = {}
    for comparator_id in sorted(expected):
        directory = root / comparator_id
        paths = {
            "events": directory / "events.jsonl",
            "plan": directory / "plan.json",
            "report": directory / "report.json",
        }
        replay_args = argparse.Namespace(
            **paths,
            datasets=args.datasets,
            baselines=args.baselines,
            canaries=args.canaries,
            environment=args.environment,
            seed_file=args.seed_file,
            attestation_key_file=args.attestation_key_file,
        )
        analyzer.replay_report(replay_args)
        report = analyzer.load_json(paths["report"])
        if report.get("comparison", {}).get("comparator_id") != comparator_id:
            fail("matrix directory and comparator report disagree")
        reports[comparator_id] = report
    result = validate_matrix_reports(reports, expected)
    result["matrix_digest"] = analyzer.sha256_multihash(canonical(result))
    analyzer.write_json(args.output, result)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evidence-root", type=Path, required=True)
    result.add_argument("--datasets", type=Path, required=True)
    result.add_argument("--baselines", type=Path, required=True)
    result.add_argument("--canaries", type=Path, required=True)
    result.add_argument("--environment", type=Path, required=True)
    result.add_argument("--seed-file", type=Path, required=True)
    result.add_argument("--attestation-key-file", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return qualify(parser().parse_args(argv))
    except MatrixError as error:
        print(f"cigarbench-matrix: {error}", file=sys.stderr)
        return 2
    except (OSError, AttributeError, TypeError, ValueError):
        print("cigarbench-matrix: local evidence operation failed", file=sys.stderr)
        return 2
    except Exception as error:
        analyzer = sys.modules.get("cigarbench_matrix_analyzer")
        if analyzer is not None and isinstance(error, analyzer.BenchError):
            print(f"cigarbench-matrix: {error}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    raise SystemExit(main())
