#!/usr/bin/env python3
"""Produce one closed Honey 0.9.3 efficiency/reliability qualification report."""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

import honey_efficiency_contract as contract
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    reject_evidence_directory,
    repo_root,
)


RAW_SCHEMA_VERSION = "cigar.honey-efficiency-raw-observations.v1"
REPORT_NAME = "honey-efficiency-reliability-report.json"
BOOTSTRAP_REPETITIONS = 10_000
BOOTSTRAP_BLOCK_LENGTH = 10
RAW_ROOT_FIELDS = {
    "schema_version",
    "run_id",
    "generated_at",
    "source",
    "candidate",
    "fixtures",
    "environment",
    "execution",
    "stages",
    "latency",
    "storage",
    "startup",
    "workflows",
    "validation",
    "compatibility",
}
WORKFLOW_FIELDS = {
    "id",
    "requests",
    "completed",
    "selected",
    "duplicate_selected",
    "budget_displaced",
    "citation_total",
    "citation_resolved",
    "required_source_total",
    "required_source_resolved",
    "local_lineages",
    "cigar_lineages",
}
VALIDATION_NAMES = (
    "required",
    "policy",
    "security",
    "provenance",
    "tokenizer",
    "materializer",
    "budget",
)


class EfficiencyQualificationError(contract.EfficiencyContractError):
    """The raw observations or create-new output violated the qualification contract."""


def _strict_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    try:
        return contract._keys(value, expected, label)
    except contract.EfficiencyContractError as error:
        raise EfficiencyQualificationError(str(error)) from error


def _bounded_integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    try:
        return contract._integer(value, minimum, maximum, label)
    except contract.EfficiencyContractError as error:
        raise EfficiencyQualificationError(str(error)) from error


def _bounded_sequence(value: Any, minimum: int, maximum: int, label: str) -> list[Any]:
    try:
        return contract._sequence(value, minimum, maximum, label)
    except contract.EfficiencyContractError as error:
        raise EfficiencyQualificationError(str(error)) from error


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EfficiencyQualificationError(f"{label} is not boolean")
    return value


def _positive_series(value: Any, count: int, label: str) -> list[int]:
    series = _bounded_sequence(value, count, count, label)
    return [
        _bounded_integer(item, 1, 86_400_000_000_000, f"{label} item")
        for item in series
    ]


def _ceil_fraction(value: Fraction) -> int:
    return value.numerator // value.denominator + (value.numerator % value.denominator != 0)


def _ols_slope(values: Sequence[int]) -> Fraction:
    count = len(values)
    if count < 2:
        raise EfficiencyQualificationError("OLS requires at least two observations")
    sum_x = count * (count - 1) // 2
    sum_x_squared = count * (count - 1) * (2 * count - 1) // 6
    denominator = count * sum_x_squared - sum_x * sum_x
    numerator = count * sum(index * value for index, value in enumerate(values))
    numerator -= sum_x * sum(values)
    if denominator <= 0:
        raise EfficiencyQualificationError("OLS denominator is invalid")
    return Fraction(numerator, denominator)


def _deterministic_index(seed: str, repetition: int, block: int, maximum: int) -> int:
    if maximum < 1:
        raise EfficiencyQualificationError("bootstrap start range is empty")
    material = (
        b"CIGAR-HONEY-MOVING-BLOCK-BOOTSTRAP\x00v1\x00"
        + bytes.fromhex(seed)
        + repetition.to_bytes(8, "big")
        + block.to_bytes(8, "big")
    )
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") % maximum


def moving_block_bootstrap_interval(
    values: Sequence[int], *, seed: str, repetitions: int, block_length: int
) -> tuple[int, int]:
    """Returns a deterministic nearest-rank two-sided 95% OLS-slope interval."""

    if (
        len(values) < 2
        or repetitions != BOOTSTRAP_REPETITIONS
        or block_length != BOOTSTRAP_BLOCK_LENGTH
        or block_length > len(values)
    ):
        raise EfficiencyQualificationError("bootstrap configuration drifted")
    try:
        contract._sha256(seed, "bootstrap seed", nonzero=True)
    except contract.EfficiencyContractError as error:
        raise EfficiencyQualificationError(str(error)) from error
    block_count = math.ceil(len(values) / block_length)
    maximum_start = len(values) - block_length + 1
    slopes: list[Fraction] = []
    for repetition in range(repetitions):
        sample: list[int] = []
        for block in range(block_count):
            start = _deterministic_index(seed, repetition, block, maximum_start)
            sample.extend(values[start : start + block_length])
        slopes.append(_ols_slope(sample[: len(values)]))
    slopes.sort()
    lower_rank = math.ceil(repetitions * 25 / 1_000) - 1
    upper_rank = math.ceil(repetitions * 975 / 1_000) - 1
    return _ceil_fraction(slopes[lower_rank]), _ceil_fraction(slopes[upper_rank])


def _nearest_rank(values: Sequence[int], numerator: int, denominator: int) -> int:
    if not values or numerator < 1 or numerator > denominator or denominator < 1:
        raise EfficiencyQualificationError("nearest-rank input is invalid")
    ordered = sorted(values)
    rank = math.ceil(len(ordered) * numerator / denominator)
    return ordered[rank - 1]


def _ratio_millionths(numerator: int, denominator: int, label: str) -> int:
    if denominator <= 0:
        raise EfficiencyQualificationError(f"{label} denominator is zero")
    return (numerator * 1_000_000 + denominator - 1) // denominator


def _stage_metric(identifier: str, observations: Sequence[int]) -> dict[str, Any]:
    ordered = sorted(observations)
    return {
        "id": identifier,
        "samples": len(ordered),
        "unit": "nanoseconds",
        "minimum": ordered[0],
        "maximum": ordered[-1],
        "mean": sum(ordered) // len(ordered),
        "p50": _nearest_rank(ordered, 50, 100),
        "p95": _nearest_rank(ordered, 95, 100),
    }


def _workflow_status(workflow: Mapping[str, Any]) -> str:
    selected = workflow["selected"]
    citations = workflow["citation_total"]
    required = workflow["required_source_total"]
    if selected <= 0 or citations <= 0 or required <= 0:
        return "fail"
    passed = (
        workflow["completed"] == workflow["requests"]
        and _ratio_millionths(
            workflow["duplicate_selected"], selected, "workflow duplicates"
        )
        <= 50_000
        and _ratio_millionths(
            workflow["budget_displaced"], selected, "workflow displacement"
        )
        < 10_000_000
        and _ratio_millionths(
            workflow["citation_resolved"], citations, "workflow citations"
        )
        >= 990_000
        and _ratio_millionths(
            workflow["required_source_resolved"], required, "workflow required sources"
        )
        == 1_000_000
        and workflow["cigar_lineages"] - workflow["local_lineages"] >= 0
    )
    return "pass" if passed else "fail"


def validate_raw_observations(document: Any) -> Mapping[str, Any]:
    """Validates the closed raw attachment before any statistic is derived."""

    root = _strict_keys(document, RAW_ROOT_FIELDS, "raw observations")
    if root["schema_version"] != RAW_SCHEMA_VERSION:
        raise EfficiencyQualificationError("raw observation schema drifted")
    contract._identifier(root["run_id"], "raw run ID")
    if (
        not isinstance(root["generated_at"], str)
        or contract.TIMESTAMP.fullmatch(root["generated_at"]) is None
    ):
        raise EfficiencyQualificationError("raw timestamp is invalid")
    source = _strict_keys(root["source"], {"commit", "tree", "clean"}, "raw source")
    for field in ("commit", "tree"):
        if (
            not isinstance(source[field], str)
            or contract.GIT_OBJECT.fullmatch(source[field]) is None
        ):
            raise EfficiencyQualificationError("raw source identity is invalid")
    if source["clean"] is not True:
        raise EfficiencyQualificationError("raw source is not clean")
    candidate = _strict_keys(
        root["candidate"],
        {"manifest_sha256", "installed_runtime_sha256"},
        "raw candidate",
    )
    contract._sha256(candidate["manifest_sha256"], "raw candidate manifest", nonzero=True)
    contract._sha256(
        candidate["installed_runtime_sha256"], "raw installed runtime", nonzero=True
    )
    fixtures = _strict_keys(root["fixtures"], {"manifest_sha256", "entries"}, "raw fixtures")
    if fixtures["manifest_sha256"] != contract.FIXTURE_SHA256:
        raise EfficiencyQualificationError("raw fixture authority drifted")
    entries = _bounded_sequence(fixtures["entries"], 3, 4, "raw fixture entries")
    if len({entry.get("id") for entry in entries if isinstance(entry, dict)}) != len(entries):
        raise EfficiencyQualificationError("raw fixtures are duplicated")
    environment = _strict_keys(
        root["environment"],
        {
            "host_os",
            "os_version",
            "kernel",
            "architecture",
            "cpu_model",
            "filesystem",
            "power_source",
            "low_power_mode",
            "thermal_state",
            "network_used",
            "tools",
        },
        "raw environment",
    )
    if len(_bounded_sequence(environment["tools"], 4, 32, "raw tools")) < 4:
        raise EfficiencyQualificationError("raw tool inventory is incomplete")
    fixtures_document, fixture_payload = contract.load_json(repo_root() / contract.FIXTURE_PATH)
    fixture_manifest = contract.validate_fixture_manifest(fixtures_document, fixture_payload)
    if root["execution"] != contract._expected_execution(fixture_manifest):
        raise EfficiencyQualificationError("raw execution conditions drifted")
    stages = _bounded_sequence(root["stages"], 1, 256, "raw stages")
    stage_ids: set[str] = set()
    for stage in stages:
        row = _strict_keys(stage, {"id", "observations_ns"}, "raw stage")
        identifier = contract._identifier(row["id"], "raw stage ID")
        if identifier in stage_ids:
            raise EfficiencyQualificationError("raw stage is duplicated")
        stage_ids.add(identifier)
        _positive_series(row["observations_ns"], 100, "raw stage observations")
    latency = _strict_keys(
        root["latency"],
        {
            "serial_request_latencies_ns",
            "compile_latencies_ns",
            "paired_local_compile_latencies_ns",
            "bootstrap_seed",
            "bootstrap_repetitions",
            "bootstrap_block_length",
        },
        "raw latency",
    )
    for field in (
        "serial_request_latencies_ns",
        "compile_latencies_ns",
        "paired_local_compile_latencies_ns",
    ):
        _positive_series(latency[field], 100, field)
    contract._sha256(latency["bootstrap_seed"], "bootstrap seed", nonzero=True)
    if (
        latency["bootstrap_repetitions"] != BOOTSTRAP_REPETITIONS
        or latency["bootstrap_block_length"] != BOOTSTRAP_BLOCK_LENGTH
    ):
        raise EfficiencyQualificationError("raw bootstrap configuration drifted")
    storage = _strict_keys(
        root["storage"],
        {
            "incremental_storage_format",
            "migration_root_revision_exact",
            "failpoint_recovery_exact",
            "physical_initial_bytes",
            "physical_final_bytes",
            "completed_compilations",
            "serial_mutations_completed",
            "retained_checkpoints",
            "retained_deltas",
            "readiness_suffix_deltas",
            "readiness_suffix_bytes",
            "mixed_workers_completed",
            "mixed_mutations_per_worker_completed",
            "backup_restore_downgrade_passed",
            "compaction_pin_drift_passed",
            "deep_integrity_passed",
        },
        "raw storage",
    )
    for field in (
        "incremental_storage_format",
        "migration_root_revision_exact",
        "failpoint_recovery_exact",
        "backup_restore_downgrade_passed",
        "compaction_pin_drift_passed",
        "deep_integrity_passed",
    ):
        _boolean(storage[field], f"raw storage {field}")
    for field in (
        "physical_initial_bytes",
        "physical_final_bytes",
        "completed_compilations",
        "serial_mutations_completed",
        "retained_checkpoints",
        "retained_deltas",
        "readiness_suffix_deltas",
        "readiness_suffix_bytes",
        "mixed_workers_completed",
        "mixed_mutations_per_worker_completed",
    ):
        _bounded_integer(storage[field], 0, 68_719_476_736, f"raw storage {field}")
    if storage["completed_compilations"] < 1:
        raise EfficiencyQualificationError("raw compilation cohort is empty")
    if (
        storage["mixed_workers_completed"] != 4
        or storage["mixed_mutations_per_worker_completed"] != 2_500
    ):
        raise EfficiencyQualificationError("raw mixed-concurrency cohort is incomplete")
    startup = _strict_keys(
        root["startup"],
        {"clean_readiness_ns", "crash_recovery_readiness_ns"},
        "raw startup",
    )
    for field in ("clean_readiness_ns", "crash_recovery_readiness_ns"):
        _bounded_integer(startup[field], 1, 300_000_000_000, f"raw startup {field}")
    workflows = _bounded_sequence(root["workflows"], 5, 5, "raw workflows")
    workflow_ids: set[str] = set()
    for workflow in workflows:
        row = _strict_keys(workflow, WORKFLOW_FIELDS, "raw workflow")
        identifier = contract._identifier(row["id"], "raw workflow ID")
        if identifier in workflow_ids or row["requests"] != 20:
            raise EfficiencyQualificationError("raw workflow identity or size drifted")
        workflow_ids.add(identifier)
        for field in WORKFLOW_FIELDS - {"id"}:
            _bounded_integer(row[field], 0, 18_446_744_073_709_551_615, field)
    validation = _strict_keys(root["validation"], set(VALIDATION_NAMES), "raw validation")
    for name in VALIDATION_NAMES:
        _boolean(validation[name], f"raw validation {name}")
    compatibility = _strict_keys(
        root["compatibility"],
        {
            "v1_operation_count",
            "v1_nominal_payload_count",
            "granular_v1_clients_compatible",
            "future_operations_added_to_v1",
            "legacy_mandatory_gates_passed",
        },
        "raw compatibility",
    )
    _bounded_integer(compatibility["v1_operation_count"], 0, 1_000, "v1 operation count")
    _bounded_integer(
        compatibility["v1_nominal_payload_count"], 0, 1_000, "v1 payload count"
    )
    for field in (
        "granular_v1_clients_compatible",
        "future_operations_added_to_v1",
        "legacy_mandatory_gates_passed",
    ):
        _boolean(compatibility[field], field)
    return root


def _gate_measurements(raw: Mapping[str, Any]) -> dict[str, dict[str, bool | int]]:
    latency = raw["latency"]
    serial = latency["serial_request_latencies_ns"]
    slope = _ceil_fraction(_ols_slope(serial))
    _bootstrap_lower, bootstrap_upper = moving_block_bootstrap_interval(
        serial,
        seed=latency["bootstrap_seed"],
        repetitions=latency["bootstrap_repetitions"],
        block_length=latency["bootstrap_block_length"],
    )
    compile_p95 = _nearest_rank(latency["compile_latencies_ns"], 95, 100)
    local_p95 = _nearest_rank(latency["paired_local_compile_latencies_ns"], 95, 100)
    storage = raw["storage"]
    physical_growth = max(
        0, storage["physical_final_bytes"] - storage["physical_initial_bytes"]
    )
    growth_per_compilation = (
        physical_growth + storage["completed_compilations"] - 1
    ) // storage["completed_compilations"]
    workflows = raw["workflows"]
    totals = {
        field: sum(workflow[field] for workflow in workflows)
        for field in WORKFLOW_FIELDS - {"id", "requests"}
    }
    lineage_deltas = [
        workflow["cigar_lineages"] - workflow["local_lineages"]
        for workflow in workflows
    ]
    validation = raw["validation"]
    compatibility = raw["compatibility"]
    startup = raw["startup"]
    return {
        "H91-G001": {"incremental_storage_format": storage["incremental_storage_format"]},
        "H91-G002": {"migration_root_revision_exact": storage["migration_root_revision_exact"]},
        "H91-G003": {"failpoint_recovery_exact": storage["failpoint_recovery_exact"]},
        "H91-G004": {"physical_growth_bytes_per_compilation": growth_per_compilation},
        "H91-G005": {
            "serial_latency_slope_ns_per_request": slope,
            "serial_latency_bootstrap_upper_ns_per_request": bootstrap_upper,
        },
        "H91-G006": {
            "compile_p95_ns": compile_p95,
            "compile_p95_vs_paired_local_millionths": _ratio_millionths(
                compile_p95, local_p95, "paired compile p95"
            ),
        },
        "H91-G007": {
            "clean_readiness_ns": startup["clean_readiness_ns"],
            "crash_recovery_readiness_ns": startup["crash_recovery_readiness_ns"],
        },
        "H91-G008": {
            "serial_mutations_completed": storage["serial_mutations_completed"],
            "retained_chain_payloads": storage["retained_checkpoints"]
            + storage["retained_deltas"],
            "maximum_checkpoint_suffix_deltas": storage["readiness_suffix_deltas"],
            "maximum_checkpoint_suffix_bytes": storage["readiness_suffix_bytes"],
        },
        "H91-G009": {"completed_requests": totals["completed"]},
        "H91-G010": {
            "duplicate_selected_percent_millionths": _ratio_millionths(
                totals["duplicate_selected"], totals["selected"], "selected duplicates"
            )
        },
        "H91-G011": {
            "aggregate_lineage_delta": sum(lineage_deltas),
            "minimum_workflow_lineage_delta": min(lineage_deltas),
        },
        "H91-G012": {
            "budget_displaced_selected_ratio_millionths": _ratio_millionths(
                totals["budget_displaced"], totals["selected"], "budget displacement"
            )
        },
        "H91-G013": {
            "citation_resolvability_millionths": _ratio_millionths(
                totals["citation_resolved"], totals["citation_total"], "citations"
            )
        },
        "H91-G014": {
            "required_source_coverage_millionths": _ratio_millionths(
                totals["required_source_resolved"],
                totals["required_source_total"],
                "required sources",
            )
        },
        "H91-G015": {
            f"{name}_validation_fail_closed": validation[name] for name in VALIDATION_NAMES
        },
        "H91-G016": {
            "backup_restore_downgrade_passed": storage[
                "backup_restore_downgrade_passed"
            ]
        },
        "H91-G017": {"compaction_pin_drift_passed": storage["compaction_pin_drift_passed"]},
        "H91-G018": {"deep_integrity_passed": storage["deep_integrity_passed"]},
        "H91-G019": {
            "v1_operation_count": compatibility["v1_operation_count"],
            "v1_nominal_payload_count": compatibility["v1_nominal_payload_count"],
        },
        "H91-G020": {
            "granular_v1_clients_compatible": compatibility[
                "granular_v1_clients_compatible"
            ],
            "future_operations_added_to_v1": compatibility["future_operations_added_to_v1"],
        },
        "H91-G021": {
            "prerelease": True,
            "supported": False,
            "production_qualified": False,
        },
        "H91-G022": {
            "legacy_mandatory_gates_passed": compatibility[
                "legacy_mandatory_gates_passed"
            ]
        },
    }


def build_report(
    raw: Mapping[str, Any], raw_payload: bytes, profile: Mapping[str, Any]
) -> dict[str, Any]:
    """Derives all report statistics and closed statuses from authenticated raw observations."""

    measurements = _gate_measurements(raw)
    expected_release_gates = {
        row["id"]: row["release_gate_id"] for row in profile["required_gates"]
    }
    raw_sha256 = hashlib.sha256(raw_payload).hexdigest()
    gates: list[dict[str, Any]] = []
    for gate_id in contract.GATE_IDS[:-1]:
        thresholds = [
            {"name": name, "operator": operator, "value": value, "unit": unit}
            for name, operator, value, unit in contract.EXPECTED_GATE_THRESHOLDS[gate_id]
        ]
        gate_measurements = [
            {"name": name, "value": measurements[gate_id][name], "unit": unit}
            for name, _operator, _value, unit in contract.EXPECTED_GATE_THRESHOLDS[gate_id]
        ]
        passed = all(
            contract._threshold_passed(
                threshold["operator"], threshold["value"], gate_measurements[index]["value"]
            )
            for index, threshold in enumerate(thresholds)
        )
        evidence = canonical_json_bytes({"gate_id": gate_id, "raw_sha256": raw_sha256})
        gates.append(
            {
                "gate_id": gate_id,
                "release_gate_id": expected_release_gates[gate_id],
                "status": "pass" if passed else "fail",
                "thresholds": thresholds,
                "measurements": gate_measurements,
                "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            }
        )
    workflows = []
    for raw_workflow in raw["workflows"]:
        workflow = dict(raw_workflow)
        workflow["lineage_delta"] = (
            workflow["cigar_lineages"] - workflow["local_lineages"]
        )
        workflow["status"] = _workflow_status(raw_workflow)
        workflows.append(workflow)
    closure_measurements = {
        "gates_001_through_022_passed": all(
            gate["status"] == "pass" for gate in gates
        ),
        "workflows_passed": all(workflow["status"] == "pass" for workflow in workflows),
    }
    closure_thresholds = [
        {"name": name, "operator": operator, "value": value, "unit": unit}
        for name, operator, value, unit in contract.EXPECTED_GATE_THRESHOLDS["H91-G023"]
    ]
    gates.append(
        {
            "gate_id": "H91-G023",
            "release_gate_id": expected_release_gates["H91-G023"],
            "status": "pass"
            if all(closure_measurements.values())
            else "fail",
            "thresholds": closure_thresholds,
            "measurements": [
                {"name": name, "value": closure_measurements[name], "unit": unit}
                for name, _operator, _value, unit in contract.EXPECTED_GATE_THRESHOLDS[
                    "H91-G023"
                ]
            ],
            "evidence_sha256": hashlib.sha256(
                canonical_json_bytes(
                    {"gate_id": "H91-G023", "raw_sha256": raw_sha256}
                )
            ).hexdigest(),
        }
    )
    stage_metrics = [
        _stage_metric(stage["id"], stage["observations_ns"])
        for stage in raw["stages"]
    ]
    overall = "pass" if all(gate["status"] == "pass" for gate in gates) else "fail"
    return {
        "schema_version": contract.REPORT_SCHEMA_VERSION,
        "report_id": raw["run_id"],
        "generated_at": raw["generated_at"],
        "authorities": {
            "qualification_profile_sha256": contract.PROFILE_SHA256,
            "report_schema_sha256": contract.REPORT_SCHEMA_SHA256,
        },
        "product": {
            "version": "0.9.3",
            "release_state": "developer-preview",
            "context_abi": "cigar.context.v1",
            "target_triple": "aarch64-apple-darwin",
            "prerelease": True,
            "supported": False,
            "production_qualified": False,
        },
        "source": dict(raw["source"]),
        "candidate": dict(raw["candidate"]),
        "fixtures": {
            "manifest_sha256": raw["fixtures"]["manifest_sha256"],
            "entries": [dict(entry) for entry in raw["fixtures"]["entries"]],
        },
        "raw_observations": {
            "attachment_id": "honey-efficiency-raw-observations",
            "sha256": raw_sha256,
            "bytes": len(raw_payload),
        },
        "environment": dict(raw["environment"]),
        "execution": dict(raw["execution"]),
        "stage_metrics": stage_metrics,
        "gate_results": gates,
        "workflows": workflows,
        "overall_status": overall,
        "fail_closed": True,
    }


def _regular_file_payload(path: Path, label: str, maximum: int) -> bytes:
    if not path.is_absolute():
        raise EfficiencyQualificationError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise EfficiencyQualificationError(f"{label} is unavailable") from error
    if resolved != path or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EfficiencyQualificationError(f"{label} must be a canonical regular file")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise EfficiencyQualificationError(f"{label} size is outside its bound")
    try:
        with path.open("rb") as source:
            payload = source.read(maximum + 1)
            opened = os.fstat(source.fileno())
    except OSError as error:
        raise EfficiencyQualificationError(f"{label} cannot be read") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(payload) > maximum or any(
        getattr(metadata, field) != getattr(opened, field) for field in stable
    ):
        raise EfficiencyQualificationError(f"{label} changed during read")
    return payload


def _git_identity(root: Path) -> tuple[str, str]:
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise EfficiencyQualificationError("source root must be canonical and absolute")
    commands = (
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        ("rev-parse", "--verify", "HEAD^{commit}"),
        ("rev-parse", "--verify", "HEAD^{tree}"),
    )
    outputs = []
    for arguments in commands:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if result.returncode != 0 or len(result.stdout) > 32 * 1024 * 1024:
            raise EfficiencyQualificationError("cannot authenticate source identity")
        outputs.append(result.stdout)
    if outputs[0]:
        raise EfficiencyQualificationError("qualification requires a clean exact source tree")
    return outputs[1].decode().strip(), outputs[2].decode().strip()


def _create_private_output(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise EfficiencyQualificationError("output directory must be an absolute new child")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise EfficiencyQualificationError("output parent is unavailable") from error
    if parent != path.parent or path.exists() or path.is_symlink():
        raise EfficiencyQualificationError("output directory already exists or is unsafe")
    path.mkdir(mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise EfficiencyQualificationError("output directory is not owner-private")


def produce(
    *,
    root: Path,
    raw_path: Path,
    candidate_manifest_path: Path,
    installed_runtime_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Authenticates exact inputs and writes a create-new owner-private report bundle."""

    if output.exists() or output.is_symlink():
        raise EfficiencyQualificationError("output directory already exists")
    contract.validate_authorities(root)
    raw_payload = _regular_file_payload(raw_path, "raw observations", 1_073_741_824)
    try:
        raw_document = json.loads(
            raw_payload,
            object_pairs_hook=contract._object,
            parse_constant=contract._reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EfficiencyQualificationError("raw observations are not strict JSON") from error
    raw = validate_raw_observations(raw_document)
    manifest_payload = _regular_file_payload(
        candidate_manifest_path, "candidate manifest", 64 * 1024 * 1024
    )
    runtime_payload = _regular_file_payload(
        installed_runtime_path, "installed runtime", 4 * 1024 * 1024 * 1024
    )
    if hashlib.sha256(manifest_payload).hexdigest() != raw["candidate"]["manifest_sha256"]:
        raise EfficiencyQualificationError("candidate manifest binding is stale")
    if hashlib.sha256(runtime_payload).hexdigest() != raw["candidate"]["installed_runtime_sha256"]:
        raise EfficiencyQualificationError("installed runtime binding is stale")
    commit, tree = _git_identity(root)
    if raw["source"] != {"commit": commit, "tree": tree, "clean": True}:
        raise EfficiencyQualificationError("raw source binding is stale")
    profile, profile_payload = contract.load_json(root / contract.PROFILE_PATH)
    contract.validate_qualification_profile(profile, profile_payload)
    fixture_manifest, fixture_payload = contract.load_json(root / contract.FIXTURE_PATH)
    contract.validate_fixture_manifest(fixture_manifest, fixture_payload)
    report = build_report(raw, raw_payload, profile)
    contract.validate_report(report, fixture_manifest, profile)
    _create_private_output(output)
    try:
        report_target = output / REPORT_NAME
        report_payload = canonical_json_bytes(report)
        with report_target.open("xb") as destination:
            os.fchmod(destination.fileno(), 0o600)
            destination.write(report_payload)
            destination.flush()
            os.fsync(destination.fileno())
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        contract.validate_raw_attachment(report, raw_path)
        validated_report, _payload = contract.load_json(report_target)
        contract.validate_report(validated_report, fixture_manifest, profile)
    except Exception:
        shutil.rmtree(output)
        raise
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="reserved common selector; use the explicit create-new --output path",
    )
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--raw-observations", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--installed-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        reject_evidence_directory(
            arguments.evidence_dir, "Honey efficiency qualification"
        )
        report = produce(
            root=arguments.root.resolve(strict=True),
            raw_path=arguments.raw_observations,
            candidate_manifest_path=arguments.candidate_manifest,
            installed_runtime_path=arguments.installed_runtime,
            output=arguments.output,
        )
        print(
            json.dumps(
                {"overall_status": report["overall_status"], "status": "produced"},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if report["overall_status"] == "pass" else 2
    except (
        EfficiencyQualificationError,
        contract.EfficiencyContractError,
        OSError,
        ReleaseError,
    ) as error:
        print(f"Honey efficiency qualification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
