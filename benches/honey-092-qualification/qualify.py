#!/usr/bin/env python3
"""Run the focused Honey 0.9.2 correction comparison and emit one disposition."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
DRIVER_SOURCE = Path(__file__).resolve().parent / "driver" / "src" / "main.rs"
PUBLISHED_COMMIT = "ee9b52b69f4245c27b46da6ef2fc4a070430caed"
SCHEMA_VERSION = "cigar.honey-092-focused-qualification.v1"
MUTATION_COUNTS = (100, 1_000)
INITIAL_RECORDS = 128
STARTUP_REPETITIONS = 40
MINIMUM_STORAGE_IMPROVEMENT_PPM = 100_000
MAXIMUM_STORAGE_REGRESSION_PPM = 50_000
MAXIMUM_LATENCY_REGRESSION_PPM = 200_000
MAXIMUM_CONTEXT_TOKEN_REGRESSION_PPM = 100_000


class QualificationError(RuntimeError):
    """A closed qualification input or execution invariant failed."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def command(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout: int,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(arguments),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise QualificationError("bounded command execution failed") from error


def git_identity(root: Path, *, expected_commit: str | None = None) -> dict[str, Any]:
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise QualificationError("source root must be canonical and absolute")
    values: dict[str, bytes] = {}
    for name, arguments in (
        ("commit", ["git", "rev-parse", "--verify", "HEAD^{commit}"]),
        ("tree", ["git", "rev-parse", "--verify", "HEAD^{tree}"]),
        ("status", ["git", "status", "--porcelain=v1", "--untracked-files=all"]),
    ):
        result = command(arguments, cwd=root, timeout=60)
        if result.returncode != 0 or len(result.stdout) > 32 * 1024 * 1024:
            raise QualificationError("cannot authenticate source identity")
        values[name] = result.stdout.strip()
    commit_id = values["commit"].decode("ascii")
    tree_id = values["tree"].decode("ascii")
    if values["status"]:
        raise QualificationError("qualification requires a clean exact source")
    if expected_commit is not None and commit_id != expected_commit:
        raise QualificationError("published source commit drifted")
    return {"commit": commit_id, "tree": tree_id, "clean": True}


def _manifest(source: Path, *, enable_v5: bool) -> str:
    dependencies = [
        f'cigar-crypto = {{ path = "{source / "crates/cigar-crypto"}" }}',
        f'cigar-protocol = {{ path = "{source / "crates/cigar-protocol"}" }}',
        f'cigar-store = {{ path = "{source / "crates/cigar-store"}" }}',
        'serde = { version = "=1.0.228", features = ["derive"] }',
        'serde_json = "=1.0.150"',
    ]
    return "\n".join(
        [
            "[package]",
            'name = "honey-092-system-driver"',
            'version = "0.1.0"',
            'edition = "2024"',
            "publish = false",
            "",
            "[workspace]",
            "",
            "[features]",
            "default = []",
            "v5 = []",
            "",
            "[dependencies]",
            *dependencies,
            "",
            "[profile.release]",
            'opt-level = 3',
            'debug = false',
            'incremental = false',
        ]
    ) + "\n"


def build_driver(source: Path, scratch: Path, *, enable_v5: bool) -> dict[str, Any]:
    project = scratch / ("candidate-driver" if enable_v5 else "published-driver")
    (project / "src").mkdir(parents=True)
    shutil.copyfile(DRIVER_SOURCE, project / "src/main.rs")
    (project / "Cargo.toml").write_text(
        _manifest(source, enable_v5=enable_v5), encoding="utf-8"
    )
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = os.fspath(project / "target")
    arguments = [
        "cargo",
        "build",
        "--manifest-path",
        os.fspath(project / "Cargo.toml"),
        "--release",
        "--offline",
    ]
    if enable_v5:
        arguments.extend(["--features", "v5"])
    started = time.monotonic_ns()
    result = command(arguments, cwd=source, timeout=1_800, environment=environment)
    duration = time.monotonic_ns() - started
    if result.returncode != 0:
        raise QualificationError("comparison driver build failed")
    executable = project / "target/release/honey-092-system-driver"
    if not executable.is_file():
        raise QualificationError("comparison driver executable is missing")
    return {
        "path": executable,
        "sha256": sha256_file(executable),
        "bytes": executable.stat().st_size,
        "build_duration_nanoseconds": duration,
    }


def run_driver(
    executable: Path,
    scratch: Path,
    *,
    label: str,
    format_name: str,
    mutations: int,
) -> dict[str, Any]:
    workload_root = scratch / f"{label}-{mutations}"
    result = command(
        [
            os.fspath(executable),
            "--format",
            format_name,
            "--root",
            os.fspath(workload_root),
            "--initial-records",
            str(INITIAL_RECORDS),
            "--mutations",
            str(mutations),
        ],
        cwd=ROOT,
        timeout=1_800,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > 16 * 1024 * 1024:
        diagnostic = result.stderr.decode("utf-8", "replace")[-2_048:].strip()
        raise QualificationError(
            f"comparison workload failed for {label} (exit {result.returncode}): {diagnostic}"
        )
    try:
        value = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError("comparison driver emitted invalid JSON") from error
    validate_driver_result(value, format_name=format_name, mutations=mutations)
    return value


def _positive_series(value: Any, count: int, label: str) -> list[int]:
    if (
        not isinstance(value, list)
        or len(value) != count
        or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in value)
    ):
        raise QualificationError(f"{label} is invalid")
    return value


def validate_driver_result(value: Any, *, format_name: str, mutations: int) -> None:
    expected = {
        "schema_version",
        "format",
        "initial_records",
        "mutations",
        "revision_before",
        "revision_after",
        "physical_before_bytes",
        "physical_after_bytes",
        "physical_growth_bytes",
        "mutation_latencies_nanoseconds",
        "process_cold_startup_nanoseconds",
        "process_cold_startup_stages_nanoseconds",
        "migration",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise QualificationError("comparison driver result shape drifted")
    expected_format = (
        "sqlite-v4-full-residual" if format_name == "v4" else "sqlite-v5-incremental"
    )
    if (
        value["schema_version"] != "cigar.honey-092-system-comparison-driver.v1"
        or value["format"] != expected_format
        or value["initial_records"] != INITIAL_RECORDS
        or value["mutations"] != mutations
        or value["revision_after"] - value["revision_before"] != mutations
        or value["physical_after_bytes"] < value["physical_before_bytes"]
        or value["physical_growth_bytes"]
        != value["physical_after_bytes"] - value["physical_before_bytes"]
    ):
        raise QualificationError("comparison driver result identity drifted")
    _positive_series(value["mutation_latencies_nanoseconds"], mutations, "mutation latency")
    _positive_series(
        value["process_cold_startup_nanoseconds"], STARTUP_REPETITIONS, "startup latency"
    )
    startup_stages = value["process_cold_startup_stages_nanoseconds"]
    if not isinstance(startup_stages, dict) or (format_name == "v5" and not startup_stages):
        raise QualificationError("startup stage evidence is incomplete")
    if format_name == "v4" and startup_stages:
        raise QualificationError("published driver unexpectedly emitted unavailable stage evidence")
    for stage, durations in startup_stages.items():
        if not isinstance(stage, str) or not stage:
            raise QualificationError("startup stage identity is invalid")
        _positive_series(durations, STARTUP_REPETITIONS, f"startup stage {stage}")
    migration = value["migration"]
    if format_name == "v4":
        if migration is not None:
            raise QualificationError("v4 result unexpectedly contains migration evidence")
    elif (
        not isinstance(migration, dict)
        or migration.get("root_revision_exact") is not True
        or migration.get("retained_revisions", 0) < 1
        or migration.get("duration_nanoseconds", 0) <= 0
    ):
        raise QualificationError("v5 migration evidence is incomplete")


def percentile(values: Sequence[int], numerator: int, denominator: int) -> int:
    ordered = sorted(values)
    rank = max(1, (len(ordered) * numerator + denominator - 1) // denominator)
    return ordered[min(rank, len(ordered)) - 1]


def distribution(values: Sequence[int]) -> dict[str, int]:
    return {
        "count": len(values),
        "minimum": min(values),
        "p50": percentile(values, 50, 100),
        "p95": percentile(values, 95, 100),
        "maximum": max(values),
    }


def ratio_ppm(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise QualificationError("comparison denominator is zero")
    return (numerator * 1_000_000) // denominator


def summarize_system_pair(
    published: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    published_mutation = distribution(published["mutation_latencies_nanoseconds"])
    candidate_mutation = distribution(candidate["mutation_latencies_nanoseconds"])
    published_startup = distribution(published["process_cold_startup_nanoseconds"])
    candidate_startup = distribution(candidate["process_cold_startup_nanoseconds"])
    published_startup_stages = {
        stage: distribution(durations)
        for stage, durations in published["process_cold_startup_stages_nanoseconds"].items()
    }
    candidate_startup_stages = {
        stage: distribution(durations)
        for stage, durations in candidate["process_cold_startup_stages_nanoseconds"].items()
    }
    storage_ratio = ratio_ppm(
        candidate["physical_growth_bytes"], published["physical_growth_bytes"]
    )
    mutation_ratio = ratio_ppm(candidate_mutation["p50"], published_mutation["p50"])
    mutation_p95_ratio = ratio_ppm(candidate_mutation["p95"], published_mutation["p95"])
    startup_ratio = ratio_ppm(candidate_startup["p50"], published_startup["p50"])
    startup_p95_ratio = ratio_ppm(candidate_startup["p95"], published_startup["p95"])
    checks = {
        "storage_materially_improved": storage_ratio
        <= 1_000_000 - MINIMUM_STORAGE_IMPROVEMENT_PPM,
        "storage_not_degraded": storage_ratio
        <= 1_000_000 + MAXIMUM_STORAGE_REGRESSION_PPM,
        "mutation_latency_not_materially_degraded": mutation_ratio
        <= 1_000_000 + MAXIMUM_LATENCY_REGRESSION_PPM,
        "mutation_latency_p95_not_materially_degraded": mutation_p95_ratio
        <= 1_000_000 + MAXIMUM_LATENCY_REGRESSION_PPM,
        "startup_not_materially_degraded": startup_ratio
        <= 1_000_000 + MAXIMUM_LATENCY_REGRESSION_PPM,
        "startup_p95_not_materially_degraded": startup_p95_ratio
        <= 1_000_000 + MAXIMUM_LATENCY_REGRESSION_PPM,
        "migration_root_revision_exact": candidate["migration"]["root_revision_exact"] is True,
    }
    return {
        "mutations": candidate["mutations"],
        "published": {
            "physical_growth_bytes": published["physical_growth_bytes"],
            "mutation_latency_nanoseconds": published_mutation,
            "process_cold_startup_nanoseconds": published_startup,
            "process_cold_startup_stages_nanoseconds": published_startup_stages,
        },
        "candidate": {
            "physical_growth_bytes": candidate["physical_growth_bytes"],
            "mutation_latency_nanoseconds": candidate_mutation,
            "process_cold_startup_nanoseconds": candidate_startup,
            "process_cold_startup_stages_nanoseconds": candidate_startup_stages,
            "migration": candidate["migration"],
        },
        "ratios_millionths": {
            "storage_growth": storage_ratio,
            "mutation_latency_p50": mutation_ratio,
            "mutation_latency_p95": mutation_p95_ratio,
            "process_cold_startup_p50": startup_ratio,
            "process_cold_startup_p95": startup_p95_ratio,
        },
        "checks": checks,
        "status": "pass" if all(checks.values()) else "fail",
    }


def run_candidate_test(candidate: Path, identifier: str, arguments: Sequence[str]) -> dict[str, Any]:
    started = time.monotonic_ns()
    result = command(arguments, cwd=candidate, timeout=1_800)
    return {
        "id": identifier,
        "status": "pass" if result.returncode == 0 else "fail",
        "returncode": result.returncode,
        "duration_nanoseconds": time.monotonic_ns() - started,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def validate_hiero(path: Path, candidate_commit: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError("Hiero disposition is unreadable") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "hiero.cigar-092-three-way-disposition.v1"
        or value.get("candidate", {}).get("source_revision") != candidate_commit
        or value.get("cohort", {}).get("request_count") != 25
        or value.get("cohort", {}).get("workflow_count") != 5
    ):
        raise QualificationError("Hiero disposition is not bound to this 25-case candidate")
    treatments = value.get("treatments", {})
    published = treatments.get("published_0_9_1")
    candidate = treatments.get("candidate_0_9_2_balanced_v1")
    if not isinstance(published, dict) or not isinstance(candidate, dict):
        raise QualificationError("Hiero treatment evidence is incomplete")
    candidate_overall = candidate.get("overall", {})
    published_overall = published.get("overall", {})
    candidate_metrics = candidate_overall.get("metrics", {})
    published_metrics = published_overall.get("metrics", {})
    workflow_checks: dict[str, Any] = {}
    for workflow in value["cohort"].get("workflows", []):
        before = published.get("by_workflow", {}).get(workflow, {})
        after = candidate.get("by_workflow", {}).get(workflow, {})
        before_metrics = before.get("metrics", {})
        after_metrics = after.get("metrics", {})
        checks = {
            "completed": after.get("complete_pair_count") == 5,
            "citations_not_lower": after_metrics.get("citation_resolvability_rate", -1)
            >= before_metrics.get("citation_resolvability_rate", 2),
            "coverage_not_lower": after_metrics.get("required_source_coverage", -1)
            >= before_metrics.get("required_source_coverage", 2),
            "evidence_not_lower": after_metrics.get("evidence_count", -1)
            >= before_metrics.get("evidence_count", 2),
        }
        workflow_checks[workflow] = {
            "checks": checks,
            "status": "pass" if all(checks.values()) else "fail",
        }
    token_ratio = ratio_ppm(
        round(float(candidate_metrics.get("estimated_tokens", 0)) * 100_000),
        round(float(published_metrics.get("estimated_tokens", 0)) * 100_000),
    )
    checks = {
        "all_25_complete": candidate_overall.get("complete_pair_count") == 25,
        "all_workflows_non_degraded": all(
            item["status"] == "pass" for item in workflow_checks.values()
        ),
        "token_use_not_materially_degraded": token_ratio
        <= 1_000_000 + MAXIMUM_CONTEXT_TOKEN_REGRESSION_PPM,
        "quality_not_lower": candidate_metrics.get("quality_index", -1)
        >= published_metrics.get("quality_index", 2),
    }
    return {
        "path": os.fspath(path),
        "sha256": sha256_file(path),
        "token_ratio_millionths": token_ratio,
        "workflow_checks": workflow_checks,
        "checks": checks,
        "status": "pass" if all(checks.values()) else "fail",
    }


def create_output(path: Path, report: Mapping[str, Any]) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise QualificationError("output must be an absolute create-new path")
    path.mkdir(mode=0o700, parents=False)
    payload = canonical(report)
    target = path / "honey-092-focused-qualification.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def execute(arguments: argparse.Namespace) -> dict[str, Any]:
    candidate = arguments.candidate_source.resolve(strict=True)
    published = arguments.published_source.resolve(strict=True)
    candidate_identity = git_identity(candidate)
    published_identity = git_identity(published, expected_commit=PUBLISHED_COMMIT)
    with tempfile.TemporaryDirectory(prefix="cigar-honey-092-focused-") as temporary:
        scratch = Path(temporary).resolve(strict=True)
        os.chmod(scratch, 0o700)
        published_driver = build_driver(published, scratch, enable_v5=False)
        candidate_driver = build_driver(candidate, scratch, enable_v5=True)
        raw: dict[str, dict[str, Any]] = {"published": {}, "candidate": {}}
        for mutations in MUTATION_COUNTS:
            order = ("published", "candidate") if mutations == 100 else ("candidate", "published")
            for treatment in order:
                if treatment == "published":
                    raw[treatment][str(mutations)] = run_driver(
                        published_driver["path"],
                        scratch,
                        label="published",
                        format_name="v4",
                        mutations=mutations,
                    )
                else:
                    raw[treatment][str(mutations)] = run_driver(
                        candidate_driver["path"],
                        scratch,
                        label="candidate",
                        format_name="v5",
                        mutations=mutations,
                    )
        drivers = {
            "published": {key: value for key, value in published_driver.items() if key != "path"},
            "candidate": {key: value for key, value in candidate_driver.items() if key != "path"},
        }

    system_pairs = [
        summarize_system_pair(raw["published"][str(count)], raw["candidate"][str(count)])
        for count in MUTATION_COUNTS
    ]
    candidate_tests = [
        run_candidate_test(
            candidate,
            "balanced-v1-only-release-profile",
            ["cargo", "test", "-p", "cigar-daemon", "config::tests"],
        ),
        run_candidate_test(
            candidate,
            "crash-boundary-recovery",
            [
                "cargo",
                "test",
                "-p",
                "cigar-store",
                "sqlite_v5::tests::process_kill_matrix_recovers_only_prior_or_complete_revisions",
                "--",
                "--test-threads=1",
            ],
        ),
        run_candidate_test(
            candidate,
            "v4-to-v5-migration",
            [
                "cargo",
                "test",
                "-p",
                "cigar-store",
                "migrate_v5::tests::preflight_reverifies_backup_freezes_source_and_rejects_head_drift",
                "--",
                "--test-threads=1",
            ],
        ),
        run_candidate_test(
            candidate,
            "backup-restore",
            [
                "cargo",
                "test",
                "-p",
                "cigar-store",
                "backup::tests::signed_backup_verifies_restores_empty_and_preserves_root",
                "--",
                "--test-threads=1",
            ],
        ),
        run_candidate_test(
            candidate,
            "semantic-request-reuse",
            ["cargo", "test", "-p", "cigar-sdk", "--test", "semantic_reuse"],
        ),
    ]
    hiero = validate_hiero(arguments.hiero_disposition.resolve(strict=True), candidate_identity["commit"])
    acceptance = {
        "all_25_hiero_cases_complete": hiero["checks"]["all_25_complete"],
        "no_workflow_loses_citations_coverage_or_evidence": hiero["checks"][
            "all_workflows_non_degraded"
        ],
        "token_use_not_materially_regressed": hiero["checks"][
            "token_use_not_materially_degraded"
        ],
        "important_system_metric_materially_improved": any(
            pair["checks"]["storage_materially_improved"] for pair in system_pairs
        ),
        "no_system_metric_materially_degraded": all(
            pair["checks"]["storage_not_degraded"]
            and pair["checks"]["mutation_latency_not_materially_degraded"]
            and pair["checks"]["mutation_latency_p95_not_materially_degraded"]
            and pair["checks"]["startup_not_materially_degraded"]
            and pair["checks"]["startup_p95_not_materially_degraded"]
            for pair in system_pairs
        ),
        "migration_and_recovery_correct": all(
            item["status"] == "pass"
            for item in candidate_tests
            if item["id"] in {"crash-boundary-recovery", "v4-to-v5-migration", "backup-restore"}
        )
        and all(pair["checks"]["migration_root_revision_exact"] for pair in system_pairs),
    }
    accepted = all(acceptance.values())
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "scope": "local developer-preview correction gate; no publication authority",
        "authority": {"public_pr": False, "publish": False, "release": False, "tag": False},
        "sources": {"published_honey": published_identity, "candidate": candidate_identity},
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "thresholds": {
            "minimum_storage_improvement_millionths": MINIMUM_STORAGE_IMPROVEMENT_PPM,
            "maximum_storage_regression_millionths": MAXIMUM_STORAGE_REGRESSION_PPM,
            "maximum_latency_regression_millionths": MAXIMUM_LATENCY_REGRESSION_PPM,
            "maximum_context_token_regression_millionths": MAXIMUM_CONTEXT_TOKEN_REGRESSION_PPM,
        },
        "drivers": drivers,
        "system_comparison": system_pairs,
        "candidate_correctness": candidate_tests,
        "hiero_context": hiero,
        "acceptance": acceptance,
        "disposition": "accept-0.9.2" if accepted else "reject-0.9.2",
    }
    report["proof_id"] = f"sha256:{hashlib.sha256(canonical(report)).hexdigest()}"
    create_output(arguments.output, report)
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--candidate-source", type=Path, default=ROOT)
    result.add_argument("--published-source", type=Path, required=True)
    result.add_argument("--hiero-disposition", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        report = execute(arguments)
    except (QualificationError, OSError, ValueError) as error:
        print(f"Honey 0.9.2 focused qualification failed: {error}", file=os.sys.stderr)
        return 2
    print(
        json.dumps(
            {"disposition": report["disposition"], "proof_id": report["proof_id"]},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if report["disposition"] == "accept-0.9.2" else 2


if __name__ == "__main__":
    raise SystemExit(main())
