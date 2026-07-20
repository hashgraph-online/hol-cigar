#!/usr/bin/env python3
"""Validate frozen Honey 0.9.1 efficiency inputs and qualification reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    reject_evidence_directory,
    repo_root,
)


REPORT_SCHEMA_VERSION = "cigar.honey-efficiency-reliability-qualification.v1"
FIXTURE_SCHEMA_VERSION = "cigar.honey-efficiency-qualification-fixtures.v1"
VERIFIED_COPY_SCHEMA_VERSION = "cigar.honey-verified-copy-input.v1"
QUALIFICATION_PROFILE_VERSION = "cigar.honey-efficiency-qualification-profile.v1"
REPORT_SCHEMA_ID = (
    "https://cigar.invalid/schemas/"
    "honey-efficiency-reliability-qualification.v1.schema.json"
)
FIXTURE_PATH = Path("benches/honey-efficiency/qualification-fixtures.v1.json")
VERIFIED_COPY_PATH = Path("packaging/honey/verified-copy-input.v1.json")
PROFILE_PATH = Path("packaging/honey/efficiency-qualification-profile.v1.json")
REPORT_SCHEMA_PATH = Path(
    "packaging/honey/schemas/"
    "honey-efficiency-reliability-qualification.v1.schema.json"
)
FIXTURE_SHA256 = "3d8337c5fa20ad035983a3d3fc8b15026e9b5dec203550078d4ea5b0da917a86"
VERIFIED_COPY_SHA256 = "e8b59c505e71a02d78d14884ee4402c95932f5ab1225a6aec4f14f99d13ebc23"
PROFILE_SHA256 = "eda075ae461d2f31f446eb13f9ecca027df048f6640769c5d5f56c1528f7b8a8"
REPORT_SCHEMA_SHA256 = "e1920d7d85944321a53e42cd2eb2e4af75d5b79c814f9d9fa1b8534d9710c38d"
MAX_JSON_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
GENERATED_FIXTURE_IDS = (
    "H91-FIXTURE-SMALL-GENERATED",
    "H91-FIXTURE-BOUNDARY-GENERATED",
    "H91-FIXTURE-HIERO-SHAPED-GENERATED",
)
VERIFIED_COPY_ID = "H91-WORKLOAD-VERIFIED-COPY"
REQUIRED_GENERATED_GATES = (
    "H91-G001",
    "H91-G002",
    "H91-G003",
    "H91-G016",
    "H91-G018",
)
GATE_IDS = tuple(f"H91-G{index:03d}" for index in range(1, 24))
AUTHENTICATED_INPUT_IDS = (
    "H91-INPUT-EFFICIENCY-HANDOFF",
    "H91-INPUT-090-HANDOFF-ZIP",
    "H91-INPUT-QUALIFICATION-FIXTURES",
    "H91-INPUT-VERIFIED-COPY-DESCRIPTOR",
    "H91-INPUT-QUALIFICATION-REPORT-SCHEMA",
    "H91-INPUT-PAIRED-RAW-BENCHMARK",
)
HISTORICAL_HANDOFF_INPUT = {
    "id": "H91-INPUT-090-HANDOFF-ZIP",
    "external": True,
    "artifact_name": "cigar-honey-0.9.0-honey.1-developer-handoff.zip",
    "bytes": 116_927_188,
    "sha256": "53f484ae7e2be6a51a0dd613731986bfda926688b0dcff21462a2bdb8da7f421",
}
ROOT_FIELDS = {
    "schema_version",
    "report_id",
    "generated_at",
    "authorities",
    "product",
    "source",
    "candidate",
    "fixtures",
    "raw_observations",
    "environment",
    "execution",
    "stage_metrics",
    "gate_results",
    "workflows",
    "overall_status",
    "fail_closed",
}
MEASUREMENT_UNITS = {
    "boolean",
    "bytes",
    "count",
    "millionths",
    "nanoseconds",
    "nanoseconds_per_request",
    "percent_millionths",
    "ratio_millionths",
    "revisions",
}
THRESHOLD_OPERATORS = {"eq", "ge", "gt", "le", "lt"}
EXPECTED_GATE_THRESHOLDS: dict[str, tuple[tuple[str, str, bool | int, str], ...]] = {
    "H91-G001": (("incremental_storage_format", "eq", True, "boolean"),),
    "H91-G002": (("migration_root_revision_exact", "eq", True, "boolean"),),
    "H91-G003": (("failpoint_recovery_exact", "eq", True, "boolean"),),
    "H91-G004": (
        ("physical_growth_bytes_per_compilation", "lt", 1_048_576, "bytes"),
    ),
    "H91-G005": (
        ("serial_latency_slope_ns_per_request", "le", 10_000_000, "nanoseconds_per_request"),
        (
            "serial_latency_bootstrap_upper_ns_per_request",
            "le",
            10_000_000,
            "nanoseconds_per_request",
        ),
    ),
    "H91-G006": (
        ("compile_p95_ns", "lt", 10_000_000_000, "nanoseconds"),
        ("compile_p95_vs_paired_local_millionths", "le", 2_000_000, "ratio_millionths"),
    ),
    "H91-G007": (
        ("clean_readiness_ns", "le", 30_000_000_000, "nanoseconds"),
        ("crash_recovery_readiness_ns", "le", 30_000_000_000, "nanoseconds"),
    ),
    "H91-G008": (
        ("serial_mutations_completed", "eq", 10_000, "count"),
        ("retained_chain_payloads", "eq", 10_001, "count"),
        ("maximum_checkpoint_suffix_deltas", "le", 256, "count"),
        ("maximum_checkpoint_suffix_bytes", "le", 268_435_456, "bytes"),
    ),
    "H91-G009": (("completed_requests", "eq", 100, "count"),),
    "H91-G010": (("duplicate_selected_percent_millionths", "le", 50_000, "percent_millionths"),),
    "H91-G011": (
        ("aggregate_lineage_delta", "ge", 0, "count"),
        ("minimum_workflow_lineage_delta", "ge", 0, "count"),
    ),
    "H91-G012": (("budget_displaced_selected_ratio_millionths", "lt", 10_000_000, "ratio_millionths"),),
    "H91-G013": (("citation_resolvability_millionths", "ge", 990_000, "millionths"),),
    "H91-G014": (("required_source_coverage_millionths", "eq", 1_000_000, "millionths"),),
    "H91-G015": tuple(
        (f"{name}_validation_fail_closed", "eq", True, "boolean")
        for name in (
            "required",
            "policy",
            "security",
            "provenance",
            "tokenizer",
            "materializer",
            "budget",
        )
    ),
    "H91-G016": (("backup_restore_downgrade_passed", "eq", True, "boolean"),),
    "H91-G017": (("compaction_pin_drift_passed", "eq", True, "boolean"),),
    "H91-G018": (("deep_integrity_passed", "eq", True, "boolean"),),
    "H91-G019": (
        ("v1_operation_count", "eq", 45, "count"),
        ("v1_nominal_payload_count", "eq", 70, "count"),
    ),
    "H91-G020": (
        ("granular_v1_clients_compatible", "eq", True, "boolean"),
        ("future_operations_added_to_v1", "eq", False, "boolean"),
    ),
    "H91-G021": (
        ("prerelease", "eq", True, "boolean"),
        ("supported", "eq", False, "boolean"),
        ("production_qualified", "eq", False, "boolean"),
    ),
    "H91-G022": (("legacy_mandatory_gates_passed", "eq", True, "boolean"),),
    "H91-G023": (
        ("gates_001_through_022_passed", "eq", True, "boolean"),
        ("workflows_passed", "eq", True, "boolean"),
    ),
}


class EfficiencyContractError(RuntimeError):
    """A frozen qualification input or report violated its closed contract."""


def _reject_constant(value: str) -> None:
    raise EfficiencyContractError(f"non-finite JSON number is forbidden: {value}")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EfficiencyContractError("duplicate JSON key is forbidden")
        result[key] = value
    return result


def _read_regular(path: Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise EfficiencyContractError("cannot inspect required input") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise EfficiencyContractError("input must be a bounded regular file")
    try:
        with path.open("rb") as source:
            payload = source.read(maximum + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise EfficiencyContractError("cannot read required input") from error
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(payload) > maximum or any(
        getattr(before, field) != getattr(after, field) for field in stable
    ):
        raise EfficiencyContractError("input changed or exceeded its bound")
    return payload


def load_json(path: Path, maximum: int = MAX_JSON_BYTES) -> tuple[Any, bytes]:
    """Loads strict JSON from one stable bounded regular file."""

    payload = _read_regular(path, maximum)
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EfficiencyContractError("input is not strict JSON") from error
    return value, payload


def _keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise EfficiencyContractError(f"{label} fields are not closed")
    return value


def _sequence(value: Any, minimum: int, maximum: int, label: str) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise EfficiencyContractError(f"{label} has an invalid count")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EfficiencyContractError(f"{label} is outside its integer bound")
    return value


def _sha256(value: Any, label: str, *, nonzero: bool = False) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise EfficiencyContractError(f"{label} is not a lowercase SHA-256")
    if nonzero and value == "0" * 64:
        raise EfficiencyContractError(f"{label} cannot be the zero placeholder")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise EfficiencyContractError(f"{label} is not a bounded identifier")
    return value


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fixture_digest(document: Mapping[str, Any], fixture: Mapping[str, Any]) -> str:
    binding = {
        "digest_domain": document["digest_domain"],
        "generator_id": document["generator_id"],
        "id": fixture["id"],
        "seed": fixture["seed"],
        "generator_inputs": fixture["generator_inputs"],
    }
    return _digest(canonical_json_bytes(binding))


def validate_fixture_manifest(document: Any, payload: bytes) -> Mapping[str, Any]:
    """Validates the reviewed generated-workload manifest and every fixture digest."""

    if _digest(payload) != FIXTURE_SHA256:
        raise EfficiencyContractError("frozen fixture manifest digest drifted")
    root = _keys(
        document,
        {
            "schema_version",
            "generator_id",
            "digest_domain",
            "workload_order",
            "fixtures",
            "execution",
            "environment",
        },
        "fixture manifest",
    )
    if (
        root["schema_version"] != FIXTURE_SCHEMA_VERSION
        or root["generator_id"] != "cigar.honey.synthetic-qualification-generator.v1"
        or root["digest_domain"] != "cigar.honey.efficiency-fixture.v1"
        or root["workload_order"] != list(GENERATED_FIXTURE_IDS)
    ):
        raise EfficiencyContractError("fixture identity or order drifted")
    fixtures = _sequence(root["fixtures"], 3, 3, "generated fixtures")
    observed_ids: list[str] = []
    for fixture in fixtures:
        row = _keys(
            fixture,
            {"id", "seed", "generator_inputs", "fixture_sha256"},
            "generated fixture",
        )
        observed_ids.append(_identifier(row["id"], "fixture ID"))
        _sha256(row["seed"], "fixture seed", nonzero=True)
        _sha256(row["fixture_sha256"], "fixture digest", nonzero=True)
        if not isinstance(row["generator_inputs"], dict) or not row["generator_inputs"]:
            raise EfficiencyContractError("fixture generator inputs are empty")
        if row["fixture_sha256"] != _fixture_digest(root, row):
            raise EfficiencyContractError("generated fixture digest is stale")
    if observed_ids != list(GENERATED_FIXTURE_IDS):
        raise EfficiencyContractError("generated fixture inventory drifted")
    execution = _keys(
        root["execution"],
        {
            "capacity_profile",
            "warmup_requests",
            "serial_request_count",
            "serial_repetitions",
            "serial_mutation_count",
            "mixed_concurrency",
            "retention_policy",
        },
        "fixture execution",
    )
    if (
        execution["capacity_profile"] != "standard"
        or execution["warmup_requests"] != 5
        or execution["serial_request_count"] != 100
        or execution["serial_repetitions"] != 1
        or execution["serial_mutation_count"] != 10_000
        or execution["mixed_concurrency"]
        != {"workers": 4, "mutations_per_worker": 2_500}
    ):
        raise EfficiencyContractError("frozen execution conditions drifted")
    retention = execution["retention_policy"]
    expected_retention = {
        "maximum_delta_operations": 4_096,
        "maximum_delta_bytes": 67_108_864,
        "maximum_checkpoint_bytes": 268_435_456,
        "maximum_deltas_since_checkpoint": 256,
        "maximum_accumulated_delta_bytes": 268_435_456,
        "maximum_retained_revisions": 100_000,
        "maximum_retained_age_nanos": 2_592_000_000_000_000,
        "maximum_physical_retained_bytes": 3_221_225_472,
        "minimum_reconstructable_revisions": 256,
        "minimum_verified_replay_revisions": 256,
    }
    if retention != expected_retention:
        raise EfficiencyContractError("frozen retention policy drifted")
    if root["environment"] != {
        "target_triple": "aarch64-apple-darwin",
        "host_os": "macos",
        "cpu_model": "Apple M3 Ultra",
        "filesystem": "apfs",
        "power_source": "ac",
        "low_power_mode": False,
        "thermal_state": "nominal",
        "network_required": False,
    }:
        raise EfficiencyContractError("frozen environment conditions drifted")
    return root


def validate_verified_copy_descriptor(
    document: Any, payload: bytes | None = None
) -> Mapping[str, Any]:
    """Validates an unbound template or content-free externally bound verified-copy descriptor."""

    root = _keys(
        document,
        {
            "schema_version",
            "input_id",
            "status",
            "content_free",
            "executable",
            "binding",
            "required_generated_gates",
        },
        "verified-copy descriptor",
    )
    if (
        root["schema_version"] != VERIFIED_COPY_SCHEMA_VERSION
        or root["input_id"] != VERIFIED_COPY_ID
        or root["content_free"] is not True
        or root["required_generated_gates"] != list(REQUIRED_GENERATED_GATES)
    ):
        raise EfficiencyContractError("verified-copy descriptor authority drifted")
    if root["status"] == "unbound":
        if root["executable"] is not False or root["binding"] is not None:
            raise EfficiencyContractError("unbound verified copy became executable")
        if payload is not None and _digest(payload) != VERIFIED_COPY_SHA256:
            raise EfficiencyContractError("verified-copy template digest drifted")
    elif root["status"] == "bound":
        if root["executable"] is not True:
            raise EfficiencyContractError("bound verified copy is not executable")
        binding = _keys(
            root["binding"],
            {
                "store_identity_sha256",
                "store_sha256",
                "bytes",
                "source_revision",
                "copy_receipt_sha256",
            },
            "verified-copy binding",
        )
        for field in ("store_identity_sha256", "store_sha256", "copy_receipt_sha256"):
            _sha256(binding[field], field, nonzero=True)
        _integer(binding["bytes"], 1, 68_719_476_736, "verified-copy bytes")
        _integer(binding["source_revision"], 1, 18_446_744_073_709_551_615, "source revision")
    else:
        raise EfficiencyContractError("verified-copy descriptor status is not closed")
    return root


def validate_qualification_profile(document: Any, payload: bytes) -> Mapping[str, Any]:
    """Validates the frozen gate inventory and developer-preview claims."""

    if _digest(payload) != PROFILE_SHA256:
        raise EfficiencyContractError("qualification profile digest drifted")
    root = _keys(
        document,
        {
            "schema_version",
            "profile_id",
            "product_version",
            "release_state",
            "context_abi",
            "fail_closed",
            "claims",
            "authenticated_inputs",
            "findings",
            "required_gates",
            "input_policy",
        },
        "qualification profile",
    )
    if (
        root["schema_version"] != QUALIFICATION_PROFILE_VERSION
        or root["product_version"] != "0.9.1-honey.1"
        or root["release_state"] != "developer-preview"
        or root["context_abi"] != "cigar.context.v1"
        or root["fail_closed"] is not True
        or root["claims"]
        != {"prerelease": True, "supported": False, "production_qualified": False}
    ):
        raise EfficiencyContractError("qualification profile identity or claims drifted")
    inputs = _sequence(root["authenticated_inputs"], 6, 6, "authenticated inputs")
    if [row.get("id") for row in inputs if isinstance(row, dict)] != list(
        AUTHENTICATED_INPUT_IDS
    ):
        raise EfficiencyContractError("authenticated input inventory drifted")
    historical = _keys(
        inputs[1],
        {"id", "external", "artifact_name", "bytes", "sha256"},
        "historical handoff input",
    )
    if historical != HISTORICAL_HANDOFF_INPUT:
        raise EfficiencyContractError("historical handoff external binding drifted")
    paired = _keys(
        inputs[5], {"id", "external", "sha256"}, "paired benchmark input"
    )
    if paired["external"] is not True:
        raise EfficiencyContractError("paired benchmark input is not external")
    _sha256(paired["sha256"], "paired benchmark digest", nonzero=True)
    gates = _sequence(root["required_gates"], 23, 23, "qualification gates")
    if [row.get("id") for row in gates if isinstance(row, dict)] != list(GATE_IDS):
        raise EfficiencyContractError("qualification gate inventory drifted")
    for row in gates:
        _keys(row, {"id", "release_gate_id", "criterion"}, "qualification gate")
        _identifier(row["release_gate_id"], "release gate ID")
        if not isinstance(row["criterion"], str) or not 1 <= len(row["criterion"]) <= 1024:
            raise EfficiencyContractError("qualification criterion is invalid")
    return root


def validate_report_schema(document: Any, payload: bytes) -> Mapping[str, Any]:
    """Authenticates the exact strict report JSON Schema."""

    if _digest(payload) != REPORT_SCHEMA_SHA256:
        raise EfficiencyContractError("qualification report schema digest drifted")
    root = _keys(
        document,
        {"$schema", "$id", "title", "type", "additionalProperties", "required", "properties", "$defs"},
        "qualification report schema",
    )
    if (
        root["$schema"] != "https://json-schema.org/draft/2020-12/schema"
        or root["$id"] != REPORT_SCHEMA_ID
        or root["type"] != "object"
        or root["additionalProperties"] is not False
        or set(root["required"]) != ROOT_FIELDS
        or set(root["properties"]) != ROOT_FIELDS
    ):
        raise EfficiencyContractError("qualification report schema is not closed")
    return root


def _validate_scalar(value: Any, label: str) -> bool | int:
    if isinstance(value, bool):
        return value
    return _integer(value, -9_223_372_036_854_775_808, 18_446_744_073_709_551_615, label)


def _threshold_passed(operator: str, expected: bool | int, observed: bool | int) -> bool:
    if type(expected) is not type(observed):
        return False
    if operator == "eq":
        return observed == expected
    if isinstance(expected, bool) or isinstance(observed, bool):
        return False
    if operator == "ge":
        return observed >= expected
    if operator == "gt":
        return observed > expected
    if operator == "le":
        return observed <= expected
    if operator == "lt":
        return observed < expected
    return False


def _expected_execution(fixture_manifest: Mapping[str, Any]) -> dict[str, Any]:
    execution = fixture_manifest["execution"]
    concurrency = execution["mixed_concurrency"]
    return {
        "capacity_profile": execution["capacity_profile"],
        "workload_order": list(fixture_manifest["workload_order"]),
        "warmup_requests": execution["warmup_requests"],
        "serial_request_count": execution["serial_request_count"],
        "serial_repetitions": execution["serial_repetitions"],
        "serial_mutation_count": execution["serial_mutation_count"],
        "mixed_concurrency_workers": concurrency["workers"],
        "mixed_concurrency_mutations_per_worker": concurrency["mutations_per_worker"],
        "retention_policy": dict(execution["retention_policy"]),
    }


def validate_report(
    document: Any,
    fixture_manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Validates one candidate-bound report and recomputes every closed status."""

    root = _keys(document, ROOT_FIELDS, "qualification report")
    if (
        root["schema_version"] != REPORT_SCHEMA_VERSION
        or root["fail_closed"] is not True
        or _identifier(root["report_id"], "report ID") != root["report_id"]
        or not isinstance(root["generated_at"], str)
        or TIMESTAMP.fullmatch(root["generated_at"]) is None
    ):
        raise EfficiencyContractError("qualification report identity is invalid")
    if root["product"] != {
        "version": "0.9.1-honey.1",
        "release_state": "developer-preview",
        "context_abi": "cigar.context.v1",
        "target_triple": "aarch64-apple-darwin",
        "prerelease": True,
        "supported": False,
        "production_qualified": False,
    }:
        raise EfficiencyContractError("qualification report product claims drifted")
    if root["authorities"] != {
        "qualification_profile_sha256": PROFILE_SHA256,
        "report_schema_sha256": REPORT_SCHEMA_SHA256,
    }:
        raise EfficiencyContractError("qualification report authority binding drifted")
    source = _keys(root["source"], {"commit", "tree", "clean"}, "report source")
    if (
        not isinstance(source["commit"], str)
        or GIT_OBJECT.fullmatch(source["commit"]) is None
        or not isinstance(source["tree"], str)
        or GIT_OBJECT.fullmatch(source["tree"]) is None
        or source["clean"] is not True
    ):
        raise EfficiencyContractError("report source is not a clean exact revision")
    candidate = _keys(
        root["candidate"],
        {"manifest_sha256", "installed_runtime_sha256"},
        "report candidate",
    )
    _sha256(candidate["manifest_sha256"], "candidate manifest", nonzero=True)
    _sha256(candidate["installed_runtime_sha256"], "installed runtime", nonzero=True)
    fixtures = _keys(root["fixtures"], {"manifest_sha256", "entries"}, "report fixtures")
    if fixtures["manifest_sha256"] != FIXTURE_SHA256:
        raise EfficiencyContractError("report fixture manifest binding drifted")
    entries = _sequence(fixtures["entries"], 3, 4, "report fixture entries")
    expected_fixture_digests = {
        row["id"]: row["fixture_sha256"] for row in fixture_manifest["fixtures"]
    }
    generated_ids: list[str] = []
    observed_ids: set[str] = set()
    for entry in entries:
        row = _keys(entry, {"id", "sha256", "kind"}, "report fixture entry")
        identifier = _identifier(row["id"], "report fixture ID")
        if identifier in observed_ids:
            raise EfficiencyContractError("report repeats a fixture")
        observed_ids.add(identifier)
        _sha256(row["sha256"], "report fixture digest", nonzero=True)
        if row["kind"] == "generated":
            generated_ids.append(identifier)
            if expected_fixture_digests.get(identifier) != row["sha256"]:
                raise EfficiencyContractError("report generated fixture binding drifted")
        elif row["kind"] == "verified-copy":
            if identifier != VERIFIED_COPY_ID:
                raise EfficiencyContractError("verified-copy fixture ID drifted")
        else:
            raise EfficiencyContractError("report fixture kind is not closed")
    if generated_ids != list(GENERATED_FIXTURE_IDS):
        raise EfficiencyContractError("report omitted or reordered generated fixtures")
    raw = _keys(
        root["raw_observations"],
        {"attachment_id", "sha256", "bytes"},
        "raw observation binding",
    )
    _identifier(raw["attachment_id"], "raw observation attachment ID")
    _sha256(raw["sha256"], "raw observation digest", nonzero=True)
    _integer(raw["bytes"], 1, 1_073_741_824, "raw observation bytes")
    environment = _keys(
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
        "report environment",
    )
    frozen_environment = fixture_manifest["environment"]
    for field, expected in (
        ("host_os", frozen_environment["host_os"]),
        ("architecture", "arm64"),
        ("cpu_model", frozen_environment["cpu_model"]),
        ("filesystem", frozen_environment["filesystem"]),
        ("power_source", frozen_environment["power_source"]),
        ("low_power_mode", frozen_environment["low_power_mode"]),
        ("thermal_state", frozen_environment["thermal_state"]),
        ("network_used", frozen_environment["network_required"]),
    ):
        if environment[field] != expected:
            raise EfficiencyContractError("report environment violates frozen conditions")
    for field in ("os_version", "kernel"):
        if not isinstance(environment[field], str) or not 1 <= len(environment[field]) <= 128:
            raise EfficiencyContractError("report environment identity is invalid")
    tools = _sequence(environment["tools"], 4, 32, "report tools")
    tool_ids: set[str] = set()
    for tool in tools:
        row = _keys(tool, {"id", "version"}, "report tool")
        identifier = _identifier(row["id"], "tool ID")
        if identifier in tool_ids:
            raise EfficiencyContractError("report repeats a tool identity")
        tool_ids.add(identifier)
        if not isinstance(row["version"], str) or not 1 <= len(row["version"]) <= 256:
            raise EfficiencyContractError("report tool version is invalid")
    if root["execution"] != _expected_execution(fixture_manifest):
        raise EfficiencyContractError("report execution conditions drifted")
    stage_metrics = _sequence(root["stage_metrics"], 1, 256, "stage metrics")
    stage_ids: set[str] = set()
    for stage in stage_metrics:
        row = _keys(
            stage,
            {"id", "samples", "unit", "minimum", "maximum", "mean", "p50", "p95"},
            "stage metric",
        )
        identifier = _identifier(row["id"], "stage metric ID")
        if identifier in stage_ids or row["unit"] not in {"bytes", "count", "nanoseconds"}:
            raise EfficiencyContractError("stage metric identity or unit is invalid")
        stage_ids.add(identifier)
        _integer(row["samples"], 1, 1_000_000, "stage samples")
        for field in ("minimum", "maximum", "mean", "p50", "p95"):
            _integer(row[field], 0, 18_446_744_073_709_551_615, f"stage {field}")
        if not row["minimum"] <= row["p50"] <= row["p95"] <= row["maximum"]:
            raise EfficiencyContractError("stage metric quantiles are inconsistent")
    gate_results = _sequence(root["gate_results"], 23, 23, "gate results")
    expected_release_gates = {
        row["id"]: row["release_gate_id"] for row in profile["required_gates"]
    }
    gate_statuses: list[str] = []
    for index, gate in enumerate(gate_results):
        row = _keys(
            gate,
            {
                "gate_id",
                "release_gate_id",
                "status",
                "thresholds",
                "measurements",
                "evidence_sha256",
            },
            "gate result",
        )
        gate_id = row["gate_id"]
        if gate_id != GATE_IDS[index] or row["release_gate_id"] != expected_release_gates[gate_id]:
            raise EfficiencyContractError("gate result inventory or release binding drifted")
        _sha256(row["evidence_sha256"], "gate evidence", nonzero=True)
        measurements: dict[str, tuple[bool | int, str]] = {}
        for measurement in _sequence(row["measurements"], 1, 64, "gate measurements"):
            item = _keys(measurement, {"name", "value", "unit"}, "gate measurement")
            name = _identifier(item["name"], "measurement name")
            if name in measurements or item["unit"] not in MEASUREMENT_UNITS:
                raise EfficiencyContractError("gate measurement identity or unit is invalid")
            measurements[name] = (_validate_scalar(item["value"], "measurement"), item["unit"])
        passed = True
        threshold_names: set[str] = set()
        thresholds = _sequence(row["thresholds"], 1, 32, "gate thresholds")
        observed_threshold_policy = tuple(
            (
                threshold.get("name"),
                threshold.get("operator"),
                threshold.get("value"),
                threshold.get("unit"),
            )
            if isinstance(threshold, dict)
            else (None, None, None, None)
            for threshold in thresholds
        )
        if observed_threshold_policy != EXPECTED_GATE_THRESHOLDS[gate_id]:
            raise EfficiencyContractError("gate threshold policy drifted or weakened")
        for threshold in thresholds:
            item = _keys(
                threshold,
                {"name", "operator", "value", "unit"},
                "gate threshold",
            )
            name = _identifier(item["name"], "threshold name")
            expected = _validate_scalar(item["value"], "threshold")
            if (
                name in threshold_names
                or item["operator"] not in THRESHOLD_OPERATORS
                or item["unit"] not in MEASUREMENT_UNITS
                or name not in measurements
                or measurements[name][1] != item["unit"]
            ):
                raise EfficiencyContractError("gate threshold cannot be evaluated exactly")
            threshold_names.add(name)
            passed = passed and _threshold_passed(
                item["operator"], expected, measurements[name][0]
            )
        expected_status = "pass" if passed else "fail"
        if row["status"] != expected_status:
            raise EfficiencyContractError("gate status disagrees with measured thresholds")
        gate_statuses.append(row["status"])
    workflows = _sequence(root["workflows"], 5, 5, "workflow results")
    workflow_statuses: list[str] = []
    workflow_ids: set[str] = set()
    completed_total = 0
    for workflow in workflows:
        row = _keys(
            workflow,
            {
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
                "lineage_delta",
                "status",
            },
            "workflow result",
        )
        identifier = _identifier(row["id"], "workflow ID")
        if identifier in workflow_ids or row["requests"] != 20:
            raise EfficiencyContractError("workflow identity or request count drifted")
        workflow_ids.add(identifier)
        for field in (
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
        ):
            _integer(row[field], 0, 18_446_744_073_709_551_615, f"workflow {field}")
        if (
            row["completed"] > 20
            or row["duplicate_selected"] > row["selected"]
            or row["citation_resolved"] > row["citation_total"]
            or row["required_source_resolved"] > row["required_source_total"]
            or row["lineage_delta"] != row["cigar_lineages"] - row["local_lineages"]
            or row["status"] not in {"pass", "fail"}
        ):
            raise EfficiencyContractError("workflow metrics are inconsistent")
        completed_total += row["completed"]
        workflow_statuses.append(row["status"])
    all_pass = all(status == "pass" for status in gate_statuses + workflow_statuses)
    expected_overall = "pass" if all_pass else "fail"
    if root["overall_status"] != expected_overall:
        raise EfficiencyContractError("overall status disagrees with mandatory results")
    if root["overall_status"] == "pass" and completed_total != 100:
        raise EfficiencyContractError("passing report does not contain 100 completions")
    return root


def validate_raw_attachment(report: Mapping[str, Any], path: Path) -> None:
    """Authenticates the separately retained raw-observation attachment."""

    expected = report["raw_observations"]
    payload = _read_regular(path, 1_073_741_824)
    if len(payload) != expected["bytes"] or _digest(payload) != expected["sha256"]:
        raise EfficiencyContractError("raw observation attachment binding failed")


def validate_authorities(root: Path) -> dict[str, str]:
    """Validates all frozen H91-610 authority inputs."""

    fixtures, fixture_payload = load_json(root / FIXTURE_PATH)
    descriptor, descriptor_payload = load_json(root / VERIFIED_COPY_PATH)
    profile, profile_payload = load_json(root / PROFILE_PATH)
    schema, schema_payload = load_json(root / REPORT_SCHEMA_PATH)
    validate_fixture_manifest(fixtures, fixture_payload)
    validate_verified_copy_descriptor(descriptor, descriptor_payload)
    validate_qualification_profile(profile, profile_payload)
    validate_report_schema(schema, schema_payload)
    return {
        "fixture_sha256": _digest(fixture_payload),
        "profile_sha256": _digest(profile_payload),
        "report_schema_sha256": _digest(schema_payload),
        "verified_copy_descriptor_sha256": _digest(descriptor_payload),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="reserved common selector; this validator emits no evidence",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    authority = subcommands.add_parser("check-authority")
    authority.add_argument("--root", type=Path, default=repo_root())
    report = subcommands.add_parser("validate-report")
    report.add_argument("--root", type=Path, default=repo_root())
    report.add_argument("--report", type=Path, required=True)
    report.add_argument("--raw-observations", type=Path, required=True)
    return parser


def main() -> int:
    """Runs the non-mutating authority or report validator."""

    arguments = _parser().parse_args()
    try:
        reject_evidence_directory(
            arguments.evidence_dir, "Honey efficiency contract validation"
        )
        root = arguments.root.resolve(strict=True)
        bindings = validate_authorities(root)
        if arguments.command == "validate-report":
            fixtures, fixture_payload = load_json(root / FIXTURE_PATH)
            profile, profile_payload = load_json(root / PROFILE_PATH)
            validate_fixture_manifest(fixtures, fixture_payload)
            validate_qualification_profile(profile, profile_payload)
            report, _report_payload = load_json(arguments.report.resolve(strict=True))
            validated = validate_report(report, fixtures, profile)
            validate_raw_attachment(validated, arguments.raw_observations.resolve(strict=True))
        print(json.dumps({"status": "pass", **bindings}, sort_keys=True, separators=(",", ":")))
        return 0
    except (EfficiencyContractError, OSError, ReleaseError) as error:
        print(f"Honey efficiency contract failed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
