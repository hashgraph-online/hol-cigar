#!/usr/bin/env python3
"""Fail-closed CIGAR section 22 performance evidence validator.

This module deliberately has no third-party dependencies.  It validates a
digest-bound run manifest and an append-only JSONL sample stream, produces a
deterministic report, and compares a candidate with a like-for-like baseline.
It does not collect samples and it does not manufacture release evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import random
import re
import statistics
import sys
from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Never

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from cigarbench import EvidenceExecution, EvidenceWorkspaceError  # noqa: E402


RUN_SCHEMA = "cigar.performance-run.v1"
SAMPLE_SCHEMA = "cigar.performance-sample.v1"
REPORT_SCHEMA = "cigar.performance-report.v1"
ATTESTATION_SCHEMA = "cigar.performance-attestation.v1"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_SAMPLE_BYTES = 128 * 1024
MAX_SAMPLES = 1_000_000
MAX_CASES = 10_000
MIN_POST_WARM_SAMPLES = 30
MIN_CALIBRATION_SAMPLES = 30
MAX_HOST_CV_PERCENT = 5.0
MIN_BOOTSTRAP_REPETITIONS = 10_000
MAX_BOOTSTRAP_REPETITIONS = 1_000_000
WARN_REGRESSION_PERCENT = 5.0
P95_REGRESSION_PERCENT = 10.0
THROUGHPUT_REGRESSION_PERCENT = 15.0
RSS_REGRESSION_PERCENT = 15.0
IDLE_RSS_LIMIT_BYTES = 300 * 1024 * 1024
# Section 22 says "negligible CPU" but supplies no number.  This conservative,
# versioned harness interpretation is intentionally explicit in every report.
IDLE_CPU_LIMIT_PERCENT = 1.0

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^1220[0-9a-f]{64}$")

OPERATIONS = {
    "warm_semantic_bundle_cache_hit",
    "delta_compile",
    "full_deterministic_compile",
    "claude_prompt_hook",
    "mcp_summary_retrieval",
    "daemon_ready",
    "durable_journal_prepare",
    "local_event_propagation",
    "same_region_shared_event",
    "one_file_incremental_reindex",
    "ingestion",
    "local_active_sessions",
    "local_scale",
    "shared_scale",
    "idle_daemon",
    "hard_budget",
}

LATENCY_GATES: dict[str, tuple[tuple[str, float, float], ...]] = {
    "warm_semantic_bundle_cache_hit": (("p95", 0.95, 15.0),),
    "delta_compile": (("p95", 0.95, 50.0),),
    "full_deterministic_compile": (
        ("p50", 0.50, 75.0),
        ("p95", 0.95, 250.0),
        ("p99", 0.99, 750.0),
    ),
    "claude_prompt_hook": (("p95", 0.95, 150.0), ("p99", 0.99, 1000.0)),
    "mcp_summary_retrieval": (("p95", 0.95, 250.0),),
    "daemon_ready": (("p95", 0.95, 2000.0),),
    "durable_journal_prepare": (("p95", 0.95, 25.0),),
    "local_event_propagation": (("p95", 0.95, 100.0),),
    "same_region_shared_event": (("p95", 0.95, 1000.0),),
    "one_file_incremental_reindex": (("p95", 0.95, 500.0),),
}

RUN_KEYS = {
    "schema_version",
    "run_id",
    "evidence_class",
    "bindings",
    "environment",
    "environment_digest",
    "daemon",
    "configuration",
    "collection",
    "cases",
}
BINDING_KEYS = {"build_digest", "dataset_digest"}
ENVIRONMENT_KEYS = {
    "cpu",
    "physical_cores",
    "logical_cores",
    "memory_bytes",
    "os",
    "kernel",
    "filesystem",
    "storage",
    "power_mode",
    "compiler_flags",
    "background_load",
    "runner_id",
    "dedicated_pinned_runner",
}
DAEMON_KEYS = {
    "kind",
    "artifact_digest",
    "installation_receipt_digest",
    "version",
}
CONFIGURATION_KEYS = {"tokenizer", "policy"}
COLLECTION_KEYS = {
    "clock",
    "warmup_samples_per_case",
    "post_warm_samples_per_case",
    "host_calibration_ms",
}
CASE_KEYS = {"case_id", "case_digest", "operation", "work_unit", "load"}
LOAD_KEYS = {
    "atoms",
    "edges",
    "candidates",
    "referenced_blob_bytes",
    "clients",
    "cache_state",
    "index_state",
    "retrieval_modes",
    "consistency",
    "store",
    "bundle_tokens",
    "generative_transform",
    "embedding",
    "durability_profile",
    "region",
    "memory_mapped_indexes_excluded",
    "generated_materializations",
}
SAMPLE_KEYS = {
    "schema_version",
    "sample_id",
    "sequence",
    "previous_sample_id",
    "run_id",
    "manifest_digest",
    "environment_digest",
    "build_digest",
    "dataset_digest",
    "daemon_artifact_digest",
    "case_id",
    "case_digest",
    "sample_index",
    "phase",
    "metrics",
}
METRIC_KEYS = {
    "latency_ms",
    "elapsed_ms",
    "work_units",
    "allocations_count",
    "allocation_bytes",
    "cpu_percent",
    "rss_bytes",
    "disk_amplification",
    "database_bytes",
    "index_bytes",
    "lock_time_ms",
    "queue_depth",
    "cache_hit_rate",
    "invalidation_lag_ms",
    "failed_operations",
    "total_operations",
    "critical_recall",
    "leakage_count",
    "correctness_loss",
    "correctness_degradation",
    "materializations_attempted",
    "materializations_within_budget",
    "external_latency_ms",
}
EXTERNAL_LATENCY_KEYS = {"model", "embedding", "network_source", "connector"}
REPORT_KEYS = {
    "schema_version",
    "report_id",
    "report_type",
    "decision",
    "reasons",
    "thresholds",
    "candidate",
    "baseline",
    "comparisons",
}
ATTESTATION_KEYS = {
    "schema_version",
    "key_id",
    "role",
    "algorithm",
    "manifest_digest",
    "sample_stream_digest",
    "terminal_sample_id",
    "sample_count",
    "tag",
}
HMAC_TAG = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_DISTRIBUTIONS = (
    "latency_ms",
    "throughput_per_second",
    "allocations_count",
    "allocation_bytes",
    "cpu_percent",
    "rss_bytes",
    "disk_amplification",
    "database_bytes",
    "index_bytes",
    "lock_time_ms",
    "queue_depth",
    "cache_hit_rate",
    "invalidation_lag_ms",
    "failure_rate",
    "critical_recall",
    "leakage_count",
    "external_model_latency_ms",
    "external_embedding_latency_ms",
    "external_network_source_latency_ms",
    "external_connector_latency_ms",
)


class PerformanceError(Exception):
    """A performance evidence validation failure."""


def fail(message: str) -> Never:
    raise PerformanceError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON contains a duplicate object key")
        result[key] = value
    return result


def reject_constant(_: str) -> Never:
    fail("JSON contains a non-finite number")


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PerformanceError("value is not canonical JSON") from error


def sha256_multihash(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def file_multihash(path: Path, maximum: int = MAX_JSON_BYTES) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        fail("input must be a bounded regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "1220" + digest.hexdigest()


def parse_json_bytes(payload: bytes) -> Any:
    try:
        return json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PerformanceError("input is not strict UTF-8 JSON") from error


def load_json(path: Path, maximum: int = MAX_JSON_BYTES) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        fail("input must be a bounded regular non-symlink file")
    return parse_json_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    payload = canonical_bytes(value) + b"\n"
    if len(payload) > MAX_JSON_BYTES:
        fail("report exceeds the byte limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields do not match the v1 schema")
    return value


def bounded_string(value: Any, label: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        fail(f"{label} is not a bounded non-empty string")
    return value


def identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        fail(f"{label} is not a bounded identifier")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{label} is not a sha256 multihash")
    return value


def integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} is not an integer in range")
    return value


def number(value: Any, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        fail(f"{label} is outside its numeric bounds")
    return result


def ratio(value: Any, label: str) -> float:
    result = number(value, label)
    if result > 1.0:
        fail(f"{label} is outside [0,1]")
    return result


def boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        fail(f"{label} must be boolean")
    return value


def validate_environment(value: Any) -> dict[str, Any]:
    environment = exact_object(value, ENVIRONMENT_KEYS, "environment")
    for key in (
        "cpu",
        "os",
        "kernel",
        "filesystem",
        "storage",
        "power_mode",
        "background_load",
    ):
        bounded_string(environment[key], f"environment {key}")
    identifier(environment["runner_id"], "runner id")
    integer(environment["physical_cores"], "physical cores", 1)
    logical = integer(environment["logical_cores"], "logical cores", 1)
    if logical < environment["physical_cores"]:
        fail("logical cores cannot be below physical cores")
    integer(environment["memory_bytes"], "memory bytes", 1)
    flags = environment["compiler_flags"]
    if not isinstance(flags, list) or len(flags) > 256:
        fail("compiler flags must be a bounded array")
    for flag in flags:
        bounded_string(flag, "compiler flag", 512)
    boolean(environment["dedicated_pinned_runner"], "dedicated pinned runner")
    return environment


def case_without_digest(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "case_digest"}


def validate_load(value: Any) -> dict[str, Any]:
    load = exact_object(value, LOAD_KEYS, "load profile")
    for key in (
        "atoms",
        "edges",
        "candidates",
        "referenced_blob_bytes",
        "clients",
        "bundle_tokens",
        "generated_materializations",
    ):
        integer(load[key], f"load {key}")
    if load["clients"] < 1:
        fail("load clients must be positive")
    for key in ("cache_state", "index_state", "durability_profile"):
        identifier(load[key], f"load {key}")
    if load["cache_state"] not in {"cold", "warm"}:
        fail("cache state is not supported by v1")
    if load["consistency"] not in {"strong", "bounded_stale"}:
        fail("consistency is not supported by v1")
    if load["store"] not in {"local", "shared"}:
        fail("store is not supported by v1")
    if load["embedding"] not in {"none", "local", "remote"}:
        fail("embedding mode is not supported by v1")
    if load["region"] not in {"local", "same_region", "cross_region"}:
        fail("region is not supported by v1")
    modes = load["retrieval_modes"]
    allowed_modes = {"exact", "lexical", "graph", "vector"}
    if (
        not isinstance(modes, list)
        or not modes
        or len(modes) != len(set(modes))
        or set(modes) - allowed_modes
        or modes != sorted(modes)
    ):
        fail("retrieval modes must be a sorted non-empty v1 subset")
    boolean(load["generative_transform"], "generative transform")
    boolean(
        load["memory_mapped_indexes_excluded"],
        "memory-mapped indexes excluded",
    )
    return load


def validate_case(value: Any) -> dict[str, Any]:
    case = exact_object(value, CASE_KEYS, "case")
    identifier(case["case_id"], "case id")
    digest(case["case_digest"], "case digest")
    if case["operation"] not in OPERATIONS:
        fail("case operation is not a v1 operation")
    identifier(case["work_unit"], "work unit")
    validate_load(case["load"])
    expected = sha256_multihash(canonical_bytes(case_without_digest(case)))
    if case["case_digest"] != expected:
        fail("case digest does not match the case definition")
    return case


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = exact_object(value, RUN_KEYS, "performance run")
    if manifest["schema_version"] != RUN_SCHEMA:
        fail("performance run schema version is not supported")
    identifier(manifest["run_id"], "run id")
    if manifest["evidence_class"] not in {
        "qualification",
        "development",
        "harness_smoke",
    }:
        fail("evidence class is not supported")
    bindings = exact_object(manifest["bindings"], BINDING_KEYS, "bindings")
    digest(bindings["build_digest"], "build digest")
    digest(bindings["dataset_digest"], "dataset digest")
    environment = validate_environment(manifest["environment"])
    digest(manifest["environment_digest"], "environment digest")
    expected_environment = sha256_multihash(canonical_bytes(environment))
    if manifest["environment_digest"] != expected_environment:
        fail("environment digest does not match the environment capture")
    daemon = exact_object(manifest["daemon"], DAEMON_KEYS, "daemon")
    if daemon["kind"] != "installed_cigard":
        fail("performance samples must target an installed cigard")
    digest(daemon["artifact_digest"], "daemon artifact digest")
    digest(daemon["installation_receipt_digest"], "installation receipt digest")
    bounded_string(daemon["version"], "daemon version", 128)
    configuration = exact_object(
        manifest["configuration"], CONFIGURATION_KEYS, "configuration"
    )
    identifier(configuration["tokenizer"], "tokenizer")
    identifier(configuration["policy"], "policy")
    collection = exact_object(manifest["collection"], COLLECTION_KEYS, "collection")
    identifier(collection["clock"], "measurement clock")
    integer(collection["warmup_samples_per_case"], "warm-up sample count")
    integer(collection["post_warm_samples_per_case"], "post-warm sample count", 1)
    calibration = collection["host_calibration_ms"]
    if not isinstance(calibration, list) or len(calibration) > 100_000:
        fail("host calibration must be a bounded array")
    for value_ in calibration:
        if number(value_, "host calibration measurement") <= 0.0:
            fail("host calibration measurements must be positive")
    cases = manifest["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > MAX_CASES:
        fail("cases must be a bounded non-empty array")
    seen: set[str] = set()
    for case in cases:
        validated = validate_case(case)
        if validated["case_id"] in seen:
            fail("case ids must be unique")
        seen.add(validated["case_id"])
    return manifest


def manifest_digest(manifest: dict[str, Any]) -> str:
    return sha256_multihash(canonical_bytes(manifest))


def validate_metrics(value: Any, logical_cores: int) -> dict[str, Any]:
    metrics = exact_object(value, METRIC_KEYS, "sample metrics")
    for key in ("latency_ms", "elapsed_ms"):
        if number(metrics[key], f"metric {key}") <= 0.0:
            fail(f"metric {key} must be positive")
    if number(metrics["work_units"], "metric work_units") <= 0.0:
        fail("metric work_units must be positive")
    for key in (
        "allocations_count",
        "allocation_bytes",
        "rss_bytes",
        "database_bytes",
        "index_bytes",
        "failed_operations",
        "leakage_count",
        "materializations_attempted",
        "materializations_within_budget",
    ):
        integer(metrics[key], f"metric {key}")
    integer(metrics["total_operations"], "metric total_operations", 1)
    if metrics["failed_operations"] > metrics["total_operations"]:
        fail("failed operations exceed total operations")
    if (
        metrics["materializations_within_budget"]
        > metrics["materializations_attempted"]
    ):
        fail("within-budget materializations exceed attempts")
    for key in (
        "disk_amplification",
        "lock_time_ms",
        "queue_depth",
        "invalidation_lag_ms",
    ):
        number(metrics[key], f"metric {key}")
    cpu = number(metrics["cpu_percent"], "metric cpu_percent")
    if cpu > logical_cores * 100.0:
        fail("CPU percentage exceeds the recorded host capacity")
    ratio(metrics["cache_hit_rate"], "metric cache_hit_rate")
    ratio(metrics["critical_recall"], "metric critical_recall")
    boolean(metrics["correctness_loss"], "metric correctness_loss")
    boolean(metrics["correctness_degradation"], "metric correctness_degradation")
    external = exact_object(
        metrics["external_latency_ms"],
        EXTERNAL_LATENCY_KEYS,
        "external latency metrics",
    )
    for key in EXTERNAL_LATENCY_KEYS:
        number(external[key], f"external latency {key}")
    return metrics


def sample_without_id(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "sample_id"}


def sample_with_id(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("sample_id", None)
    return {
        **result,
        "sample_id": sha256_multihash(canonical_bytes(result)),
    }


def validate_sample(
    value: Any,
    manifest: dict[str, Any],
    expected_manifest_digest: str,
    cases: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    sample = exact_object(value, SAMPLE_KEYS, "sample")
    if sample["schema_version"] != SAMPLE_SCHEMA:
        fail("sample schema version is not supported")
    digest(sample["sample_id"], "sample id")
    integer(sample["sequence"], "sample sequence")
    if sample["previous_sample_id"] is not None:
        digest(sample["previous_sample_id"], "previous sample id")
    if sample["run_id"] != manifest["run_id"]:
        fail("sample run binding does not match the manifest")
    expected_bindings = {
        "manifest_digest": expected_manifest_digest,
        "environment_digest": manifest["environment_digest"],
        "build_digest": manifest["bindings"]["build_digest"],
        "dataset_digest": manifest["bindings"]["dataset_digest"],
        "daemon_artifact_digest": manifest["daemon"]["artifact_digest"],
    }
    for key, expected in expected_bindings.items():
        digest(sample[key], key.replace("_", " "))
        if sample[key] != expected:
            fail("sample digest binding does not match the manifest")
    identifier(sample["case_id"], "sample case id")
    if sample["case_id"] not in cases:
        fail("sample refers to an unknown case")
    digest(sample["case_digest"], "sample case digest")
    if sample["case_digest"] != cases[sample["case_id"]]["case_digest"]:
        fail("sample case binding does not match the manifest")
    integer(sample["sample_index"], "sample index")
    if sample["phase"] not in {"warmup", "post_warm"}:
        fail("sample phase is not supported")
    validate_metrics(sample["metrics"], manifest["environment"]["logical_cores"])
    expected_id = sha256_multihash(canonical_bytes(sample_without_id(sample)))
    if sample["sample_id"] != expected_id:
        fail("sample identity does not match its content")
    return sample


def load_samples(path: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        fail("samples must be a bounded regular non-symlink file")
    expected_manifest_digest = manifest_digest(manifest)
    cases = {case["case_id"]: case for case in manifest["cases"]}
    result: list[dict[str, Any]] = []
    previous: str | None = None
    per_group: dict[tuple[str, str], list[int]] = defaultdict(list)
    with path.open("rb") as stream:
        for sequence, line in enumerate(stream):
            if sequence >= MAX_SAMPLES:
                fail("sample count exceeds the v1 limit")
            if len(line) > MAX_SAMPLE_BYTES:
                fail("sample line exceeds the v1 byte limit")
            if not line.strip():
                fail("sample stream contains an empty line")
            sample = validate_sample(
                parse_json_bytes(line), manifest, expected_manifest_digest, cases
            )
            if sample["sequence"] != sequence:
                fail("sample sequence is not contiguous")
            if sample["previous_sample_id"] != previous:
                fail("sample hash chain is not contiguous")
            previous = sample["sample_id"]
            per_group[(sample["case_id"], sample["phase"])].append(
                sample["sample_index"]
            )
            result.append(sample)
    if not result:
        fail("sample stream is empty")
    warmups = manifest["collection"]["warmup_samples_per_case"]
    post_warm = manifest["collection"]["post_warm_samples_per_case"]
    for case_id in cases:
        for phase, count in (("warmup", warmups), ("post_warm", post_warm)):
            indexes = per_group.get((case_id, phase), [])
            if indexes != list(range(count)):
                fail("sample indexes do not match the manifest collection plan")
    expected_count = len(cases) * (warmups + post_warm)
    if len(result) != expected_count:
        fail("sample count does not match the manifest collection plan")
    return result


def read_attestation_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        fail("attestation key must be a bounded regular non-symlink file")
    key = path.read_bytes()
    if len(key) < 32:
        fail("attestation key must contain at least 32 bytes")
    return key


def attestation_without_tag(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "tag"}


def attestation_payload(
    manifest: dict[str, Any],
    samples: Sequence[dict[str, Any]],
    samples_digest: str,
    key_id: str,
) -> dict[str, Any]:
    identifier(key_id, "attestation key id")
    digest(samples_digest, "sample stream digest")
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "key_id": key_id,
        "role": "independent_performance_evaluator",
        "algorithm": "hmac-sha256",
        "manifest_digest": manifest_digest(manifest),
        "sample_stream_digest": samples_digest,
        "terminal_sample_id": samples[-1]["sample_id"],
        "sample_count": len(samples),
    }


def create_attestation(
    manifest: dict[str, Any],
    samples: Sequence[dict[str, Any]],
    samples_digest: str,
    key_id: str,
    key: bytes,
) -> dict[str, Any]:
    if len(key) < 32:
        fail("attestation key must contain at least 32 bytes")
    payload = attestation_payload(manifest, samples, samples_digest, key_id)
    return {
        **payload,
        "tag": hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest(),
    }


def verify_attestation(
    value: Any,
    manifest: dict[str, Any],
    samples: Sequence[dict[str, Any]],
    samples_digest: str,
    key: bytes,
) -> dict[str, Any]:
    attestation = exact_object(value, ATTESTATION_KEYS, "performance attestation")
    if attestation["schema_version"] != ATTESTATION_SCHEMA:
        fail("performance attestation schema version is not supported")
    identifier(attestation["key_id"], "attestation key id")
    if attestation["role"] != "independent_performance_evaluator":
        fail("performance attestation role is not independent evaluator")
    if attestation["algorithm"] != "hmac-sha256":
        fail("performance attestation algorithm is not supported")
    digest(attestation["manifest_digest"], "attested manifest digest")
    digest(attestation["sample_stream_digest"], "attested sample stream digest")
    digest(attestation["terminal_sample_id"], "attested terminal sample id")
    integer(attestation["sample_count"], "attested sample count", 1)
    if not isinstance(attestation["tag"], str) or not HMAC_TAG.fullmatch(
        attestation["tag"]
    ):
        fail("performance attestation tag is malformed")
    expected_payload = attestation_payload(
        manifest,
        samples,
        samples_digest,
        attestation["key_id"],
    )
    if canonical_bytes(attestation_without_tag(attestation)) != canonical_bytes(
        expected_payload
    ):
        fail("performance attestation bindings do not match the raw evidence")
    expected_tag = hmac.new(
        key, canonical_bytes(expected_payload), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(attestation["tag"], expected_tag):
        fail("performance attestation authentication failed")
    return {
        "verified": True,
        "schema_version": ATTESTATION_SCHEMA,
        "key_id": attestation["key_id"],
        "role": attestation["role"],
        "algorithm": attestation["algorithm"],
        "attestation_digest": sha256_multihash(canonical_bytes(attestation)),
    }


def missing_attestation() -> dict[str, Any]:
    return {
        "verified": False,
        "schema_version": ATTESTATION_SCHEMA,
        "key_id": None,
        "role": "independent_performance_evaluator",
        "algorithm": "hmac-sha256",
        "attestation_digest": None,
    }


def nearest_rank(values: Iterable[float], quantile: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        fail("cannot summarize an empty distribution")
    if not 0.0 <= quantile <= 1.0:
        fail("quantile is outside [0,1]")
    if quantile == 0.0:
        return ordered[0]
    return ordered[math.ceil(quantile * len(ordered)) - 1]


def clean_float(value: float) -> float:
    if not math.isfinite(value):
        fail("computed statistic is non-finite")
    # Stable reports matter more than exposing platform-specific final bits.
    return round(value, 12)


def distribution(values: Iterable[float]) -> dict[str, Any]:
    materialized = [float(value) for value in values]
    if not materialized:
        fail("cannot summarize an empty distribution")
    return {
        "count": len(materialized),
        "minimum": clean_float(min(materialized)),
        "p25": clean_float(nearest_rank(materialized, 0.25)),
        "p50": clean_float(nearest_rank(materialized, 0.50)),
        "p75": clean_float(nearest_rank(materialized, 0.75)),
        "p90": clean_float(nearest_rank(materialized, 0.90)),
        "p95": clean_float(nearest_rank(materialized, 0.95)),
        "p99": clean_float(nearest_rank(materialized, 0.99)),
        "maximum": clean_float(max(materialized)),
        "mean": clean_float(statistics.fmean(materialized)),
        "sample_standard_deviation": clean_float(
            statistics.stdev(materialized) if len(materialized) > 1 else 0.0
        ),
    }


def metric_value(metrics: dict[str, Any], name: str) -> float:
    if name == "throughput_per_second":
        return float(metrics["work_units"]) * 1000.0 / float(metrics["elapsed_ms"])
    if name == "failure_rate":
        return float(metrics["failed_operations"]) / float(metrics["total_operations"])
    if name.startswith("external_") and name.endswith("_latency_ms"):
        external_name = name[len("external_") : -len("_latency_ms")]
        return float(metrics["external_latency_ms"][external_name])
    return float(metrics[name])


def case_distributions(samples: Sequence[dict[str, Any]]) -> dict[str, Any]:
    post_warm = [sample for sample in samples if sample["phase"] == "post_warm"]
    result = {
        name: distribution(
            metric_value(sample["metrics"], name) for sample in post_warm
        )
        for name in REQUIRED_DISTRIBUTIONS
    }
    if set(result) != set(REQUIRED_DISTRIBUTIONS):
        fail("internal error: required distributions were not emitted")
    return result


def host_variance(collection: dict[str, Any]) -> dict[str, Any]:
    values = [float(value) for value in collection["host_calibration_ms"]]
    cv = 0.0
    if len(values) > 1:
        mean = statistics.fmean(values)
        cv = statistics.stdev(values) / mean * 100.0
    eligible = len(values) >= MIN_CALIBRATION_SAMPLES and cv < MAX_HOST_CV_PERCENT
    return {
        "method": "sample_coefficient_of_variation_percent",
        "sample_count": len(values),
        "value_percent": clean_float(cv),
        "required_sample_count": MIN_CALIBRATION_SAMPLES,
        "exclusive_limit_percent": MAX_HOST_CV_PERCENT,
        "status": "pass" if eligible else "insufficient_evidence",
    }


def profile_violations(case: dict[str, Any]) -> list[str]:
    operation = case["operation"]
    load = case["load"]
    violations: list[str] = []

    expected_units = {
        "ingestion": "atoms",
        "local_active_sessions": "sessions",
        "hard_budget": "materializations",
    }
    expected_unit = expected_units.get(operation, "operations")
    if case["work_unit"] != expected_unit:
        violations.append("wrong_work_unit")

    if operation == "warm_semantic_bundle_cache_hit":
        if load["atoms"] < 1_000_000:
            violations.append("fewer_than_1m_atoms")
        if load["cache_state"] != "warm":
            violations.append("cache_not_warm")
    elif operation == "delta_compile":
        if not 5_500 <= load["bundle_tokens"] <= 6_500:
            violations.append("not_representative_6k_token_bundle")
    elif operation == "full_deterministic_compile":
        if load["atoms"] < 1_000_000:
            violations.append("fewer_than_1m_atoms")
        if load["edges"] < 10_000_000:
            violations.append("fewer_than_10m_edges")
        if load["generative_transform"]:
            violations.append("generative_transform_enabled")
    elif operation == "claude_prompt_hook":
        if load["cache_state"] != "warm":
            violations.append("cache_not_warm")
        if load["store"] != "local" or load["region"] != "local":
            violations.append("not_local_sidecar")
    elif operation == "mcp_summary_retrieval":
        if load["store"] != "local" or load["region"] != "local":
            violations.append("not_local_sidecar")
    elif operation == "daemon_ready":
        if load["atoms"] < 1_000_000:
            violations.append("fewer_than_1m_atoms")
    elif operation == "durable_journal_prepare":
        if load["durability_profile"] != "sqlite":
            violations.append("not_sqlite_durability_profile")
    elif operation == "local_event_propagation":
        if load["clients"] < 32:
            violations.append("fewer_than_32_attached_sessions")
        if load["store"] != "local":
            violations.append("not_local_store")
    elif operation == "same_region_shared_event":
        if load["store"] != "shared" or load["region"] != "same_region":
            violations.append("not_same_region_shared_store")
        if load["durability_profile"] != "postgresql_object":
            violations.append("not_postgresql_object_profile")
    elif operation == "one_file_incremental_reindex":
        if load["embedding"] == "remote":
            violations.append("remote_embedding_enabled")
    elif operation == "ingestion":
        if load["atoms"] < 1 or load["atoms"] > 1_000:
            violations.append("not_small_source_atoms")
        if load["embedding"] != "none":
            violations.append("embedding_enabled")
    elif operation == "local_active_sessions":
        if load["clients"] < 32:
            violations.append("fewer_than_32_sessions")
        if load["store"] != "local":
            violations.append("not_local_store")
    elif operation == "local_scale":
        if load["atoms"] < 1_000_000:
            violations.append("fewer_than_1m_atoms")
        if load["edges"] < 10_000_000:
            violations.append("fewer_than_10m_edges")
        if load["referenced_blob_bytes"] < 100 * 1024**3:
            violations.append("fewer_than_100_gib_referenced_blobs")
        if load["store"] != "local":
            violations.append("not_local_store")
    elif operation == "shared_scale":
        if load["store"] != "shared":
            violations.append("not_shared_store")
    elif operation == "idle_daemon":
        if not load["memory_mapped_indexes_excluded"]:
            violations.append("memory_mapped_indexes_not_excluded")
    elif operation == "hard_budget":
        if load["generated_materializations"] < 1_000_000:
            violations.append("fewer_than_1m_generated_materializations")
    return violations


def load_matrix(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    gib = 1024**3
    required: dict[str, Any] = {
        "atoms": [1_000, 10_000, 100_000, 1_000_000, 10_000_000],
        "candidate_boundaries": [10, 10_000],
        "referenced_blob_boundaries_bytes": [gib, 100 * gib],
        "clients": [1, 8, 32, 64, 128],
        "cache_states": ["cold", "warm"],
        "retrieval_modes": ["exact", "graph", "lexical", "vector"],
        "retrieval_combination": True,
        "consistency": ["bounded_stale", "strong"],
        "stores": ["local", "shared"],
    }
    loads = [case["load"] for case in cases]
    observed: dict[str, Any] = {
        "atoms": sorted({load["atoms"] for load in loads}),
        "candidates": sorted({load["candidates"] for load in loads}),
        "referenced_blob_bytes": sorted(
            {load["referenced_blob_bytes"] for load in loads}
        ),
        "clients": sorted({load["clients"] for load in loads}),
        "cache_states": sorted({load["cache_state"] for load in loads}),
        "retrieval_modes": sorted(
            {mode for load in loads for mode in load["retrieval_modes"]}
        ),
        "retrieval_combinations": sorted(
            {"+".join(load["retrieval_modes"]) for load in loads}
        ),
        "consistency": sorted({load["consistency"] for load in loads}),
        "stores": sorted({load["store"] for load in loads}),
    }
    missing: dict[str, Any] = {}
    set_checks = {
        "atoms": (required["atoms"], observed["atoms"]),
        "candidate_boundaries": (
            required["candidate_boundaries"],
            observed["candidates"],
        ),
        "referenced_blob_boundaries_bytes": (
            required["referenced_blob_boundaries_bytes"],
            observed["referenced_blob_bytes"],
        ),
        "clients": (required["clients"], observed["clients"]),
        "cache_states": (required["cache_states"], observed["cache_states"]),
        "retrieval_modes": (
            required["retrieval_modes"],
            observed["retrieval_modes"],
        ),
        "consistency": (required["consistency"], observed["consistency"]),
        "stores": (required["stores"], observed["stores"]),
    }
    for name, (needed, present) in set_checks.items():
        absent = sorted(set(needed) - set(present))
        if absent:
            missing[name] = absent
    if not any(len(load["retrieval_modes"]) > 1 for load in loads):
        missing["retrieval_combination"] = True
    return {
        "coverage_model": "required_axis_values_not_cartesian_product",
        "required": required,
        "observed": observed,
        "missing": missing,
        "complete": not missing,
    }


def samples_by_case(
    samples: Sequence[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        result[sample["case_id"]].append(sample)
    return result


def slo_for_case(
    case: dict[str, Any], samples: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    violations = profile_violations(case)
    if violations:
        return {
            "status": "not_evaluable",
            "checks": [],
            "profile_violations": violations,
        }
    post_warm = [sample for sample in samples if sample["phase"] == "post_warm"]
    metrics = [sample["metrics"] for sample in post_warm]
    operation = case["operation"]
    checks: list[dict[str, Any]] = []
    if operation in LATENCY_GATES:
        latencies = [float(metric["latency_ms"]) for metric in metrics]
        for statistic, quantile, limit in LATENCY_GATES[operation]:
            observed = nearest_rank(latencies, quantile)
            checks.append(
                {
                    "metric": "latency_ms",
                    "statistic": statistic,
                    "observed": clean_float(observed),
                    "comparison": "at_most",
                    "threshold": limit,
                    "status": "pass" if observed <= limit else "fail",
                }
            )
    elif operation == "ingestion":
        throughputs = [
            metric_value(metric, "throughput_per_second") for metric in metrics
        ]
        observed = min(throughputs)
        checks.append(
            {
                "metric": "throughput_per_second",
                "statistic": "minimum",
                "observed": clean_float(observed),
                "comparison": "at_least",
                "threshold": 250.0,
                "status": "pass" if observed >= 250.0 else "fail",
            }
        )
    elif operation in {"local_active_sessions", "local_scale", "shared_scale"}:
        loss = any(
            metric["correctness_loss"] or metric["correctness_degradation"]
            for metric in metrics
        )
        checks.append(
            {
                "metric": "correctness",
                "statistic": "any_loss_or_degradation",
                "observed": loss,
                "comparison": "equals",
                "threshold": False,
                "status": "fail" if loss else "pass",
            }
        )
    elif operation == "idle_daemon":
        rss = max(float(metric["rss_bytes"]) for metric in metrics)
        cpu = max(float(metric["cpu_percent"]) for metric in metrics)
        checks.extend(
            [
                {
                    "metric": "rss_bytes",
                    "statistic": "maximum",
                    "observed": clean_float(rss),
                    "comparison": "under",
                    "threshold": IDLE_RSS_LIMIT_BYTES,
                    "status": "pass" if rss < IDLE_RSS_LIMIT_BYTES else "fail",
                },
                {
                    "metric": "cpu_percent",
                    "statistic": "maximum",
                    "observed": clean_float(cpu),
                    "comparison": "at_most",
                    "threshold": IDLE_CPU_LIMIT_PERCENT,
                    "status": "pass" if cpu <= IDLE_CPU_LIMIT_PERCENT else "fail",
                    "note": "versioned harness interpretation of negligible CPU",
                },
            ]
        )
    elif operation == "hard_budget":
        attempted = sum(metric["materializations_attempted"] for metric in metrics)
        within = sum(metric["materializations_within_budget"] for metric in metrics)
        compliance = within / attempted if attempted else 0.0
        checks.extend(
            [
                {
                    "metric": "materializations_attempted",
                    "statistic": "sum",
                    "observed": attempted,
                    "comparison": "at_least",
                    "threshold": 1_000_000,
                    "status": "pass" if attempted >= 1_000_000 else "fail",
                },
                {
                    "metric": "budget_compliance",
                    "statistic": "aggregate_ratio",
                    "observed": clean_float(compliance),
                    "comparison": "at_least",
                    "threshold": 0.9999,
                    "status": "pass" if compliance >= 0.9999 else "fail",
                },
            ]
        )
    status = "fail" if any(check["status"] == "fail" for check in checks) else "pass"
    return {"status": status, "checks": checks, "profile_violations": []}


def quality_summary(samples: Sequence[dict[str, Any]]) -> dict[str, Any]:
    metrics = [
        sample["metrics"] for sample in samples if sample["phase"] == "post_warm"
    ]
    return {
        "minimum_critical_recall": clean_float(
            min(float(metric["critical_recall"]) for metric in metrics)
        ),
        "mean_critical_recall": clean_float(
            statistics.fmean(float(metric["critical_recall"]) for metric in metrics)
        ),
        "leakage_count": sum(metric["leakage_count"] for metric in metrics),
        "correctness_loss_samples": sum(
            bool(metric["correctness_loss"]) for metric in metrics
        ),
        "correctness_degradation_samples": sum(
            bool(metric["correctness_degradation"]) for metric in metrics
        ),
        "failed_operations": sum(metric["failed_operations"] for metric in metrics),
        "total_operations": sum(metric["total_operations"] for metric in metrics),
    }


def qualification(
    manifest: dict[str, Any],
    variance: dict[str, Any],
    matrix: dict[str, Any],
    case_results: Sequence[dict[str, Any]],
    attestation: dict[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    if manifest["evidence_class"] != "qualification":
        reasons.append("non_qualification_evidence")
    if manifest["evidence_class"] == "harness_smoke":
        reasons.append("smoke_evidence_never_qualifies")
    if not attestation["verified"]:
        reasons.append("missing_or_unverified_independent_attestation")
    if not manifest["environment"]["dedicated_pinned_runner"]:
        reasons.append("runner_is_not_dedicated_and_pinned")
    if manifest["collection"]["clock"] != "monotonic":
        reasons.append("measurement_clock_is_not_monotonic")
    if manifest["collection"]["warmup_samples_per_case"] < 1:
        reasons.append("no_warmup_samples")
    if manifest["collection"]["post_warm_samples_per_case"] < MIN_POST_WARM_SAMPLES:
        reasons.append("fewer_than_30_post_warm_samples_per_case")
    if variance["sample_count"] < MIN_CALIBRATION_SAMPLES:
        reasons.append("fewer_than_30_host_calibration_samples")
    if variance["value_percent"] >= MAX_HOST_CV_PERCENT:
        reasons.append("host_variance_is_not_below_5_percent")
    operations = {case["operation"] for case in manifest["cases"]}
    for operation in sorted(OPERATIONS - operations):
        reasons.append(f"missing_operation:{operation}")
    for result in case_results:
        if result["slo"]["status"] == "not_evaluable":
            reasons.append(f"profile_mismatch:{result['case_id']}")
    if not matrix["complete"]:
        reasons.append("load_matrix_axis_coverage_incomplete")
    shared_atoms = {
        case["load"]["atoms"]
        for case in manifest["cases"]
        if case["operation"] == "shared_scale"
    }
    required_curve = {1_000, 10_000, 100_000, 1_000_000, 10_000_000}
    if not required_curve.issubset(shared_atoms):
        reasons.append("shared_scale_curve_incomplete")
    return {
        "eligible": not reasons,
        "reasons": sorted(set(reasons)),
        "requirements": {
            "evidence_class": "qualification",
            "installed_daemon_kind": "installed_cigard",
            "verified_independent_attestation": True,
            "dedicated_pinned_runner": True,
            "minimum_warmup_samples_per_case": 1,
            "minimum_post_warm_samples_per_case": MIN_POST_WARM_SAMPLES,
            "minimum_host_calibration_samples": MIN_CALIBRATION_SAMPLES,
            "exclusive_host_cv_limit_percent": MAX_HOST_CV_PERCENT,
            "required_operations": sorted(OPERATIONS),
            "complete_load_matrix_axis_coverage": True,
            "shared_scale_curve_atoms": sorted(required_curve),
        },
    }


def evaluate_run(
    manifest: dict[str, Any],
    samples: Sequence[dict[str, Any]],
    samples_digest: str,
    attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attestation_result = attestation or missing_attestation()
    grouped = samples_by_case(samples)
    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        values = grouped[case["case_id"]]
        slo = slo_for_case(case, values)
        case_results.append(
            {
                "case_id": case["case_id"],
                "case_digest": case["case_digest"],
                "operation": case["operation"],
                "work_unit": case["work_unit"],
                "load": case["load"],
                "warmup_samples": sum(sample["phase"] == "warmup" for sample in values),
                "post_warm_samples": sum(
                    sample["phase"] == "post_warm" for sample in values
                ),
                "distributions": case_distributions(values),
                "slo": slo,
            }
        )
    variance = host_variance(manifest["collection"])
    matrix = load_matrix(manifest["cases"])
    eligible = qualification(
        manifest, variance, matrix, case_results, attestation_result
    )
    quality = quality_summary(samples)
    slo_failures = sorted(
        result["case_id"]
        for result in case_results
        if result["slo"]["status"] == "fail"
    )
    quality_failure = (
        quality["correctness_loss_samples"] > 0
        or quality["correctness_degradation_samples"] > 0
    )
    if slo_failures or quality_failure:
        decision = "fail"
    elif eligible["eligible"]:
        decision = "pass"
    else:
        decision = "insufficient_evidence"
    terminal_sample_id = samples[-1]["sample_id"]
    return {
        "decision": decision,
        "run_metadata": manifest,
        "source": {
            "manifest_digest": manifest_digest(manifest),
            "sample_stream_digest": samples_digest,
            "sample_count": len(samples),
            "terminal_sample_id": terminal_sample_id,
        },
        "host_variance": variance,
        "attestation": attestation_result,
        "load_matrix": matrix,
        "quality": quality,
        "slo_summary": {
            "status": "fail" if slo_failures else "pass",
            "failing_cases": slo_failures,
            "not_evaluable_cases": sorted(
                result["case_id"]
                for result in case_results
                if result["slo"]["status"] == "not_evaluable"
            ),
            "local_scale_requires_all_run_slos": True,
        },
        "qualification": eligible,
        "case_results": case_results,
    }


def report_thresholds(bootstrap_repetitions: int | None) -> dict[str, Any]:
    return {
        "minimum_post_warm_samples_per_case": MIN_POST_WARM_SAMPLES,
        "exclusive_host_cv_limit_percent": MAX_HOST_CV_PERCENT,
        "p95_regression_block_percent": P95_REGRESSION_PERCENT,
        "throughput_regression_block_percent": THROUGHPUT_REGRESSION_PERCENT,
        "rss_regression_block_percent": RSS_REGRESSION_PERCENT,
        "regression_warn_percent": WARN_REGRESSION_PERCENT,
        "idle_rss_under_bytes": IDLE_RSS_LIMIT_BYTES,
        "idle_cpu_at_most_percent": IDLE_CPU_LIMIT_PERCENT,
        "bootstrap_repetitions": bootstrap_repetitions,
    }


def report_without_id(report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if key != "report_id"}


def with_report_id(value: dict[str, Any]) -> dict[str, Any]:
    body = dict(value)
    body.pop("report_id", None)
    return {
        **body,
        "report_id": sha256_multihash(canonical_bytes(body)),
    }


def validate_report(value: Any) -> dict[str, Any]:
    report = exact_object(value, REPORT_KEYS, "performance report")
    if report["schema_version"] != REPORT_SCHEMA:
        fail("performance report schema version is not supported")
    digest(report["report_id"], "report id")
    expected = sha256_multihash(canonical_bytes(report_without_id(report)))
    if report["report_id"] != expected:
        fail("performance report identity does not match its content")
    if report["report_type"] not in {"validation", "comparison"}:
        fail("performance report type is not supported")
    if report["decision"] not in {"pass", "fail", "insufficient_evidence"}:
        fail("performance report decision is not supported")
    return report


def validation_report(
    manifest: dict[str, Any],
    samples: Sequence[dict[str, Any]],
    samples_digest: str,
    attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    candidate = evaluate_run(manifest, samples, samples_digest, attestation)
    reasons: list[str] = []
    if candidate["decision"] == "fail":
        reasons.extend(
            f"slo_failure:{case}" for case in candidate["slo_summary"]["failing_cases"]
        )
        if candidate["quality"]["correctness_loss_samples"]:
            reasons.append("correctness_loss_observed")
        if candidate["quality"]["correctness_degradation_samples"]:
            reasons.append("correctness_degradation_observed")
    elif candidate["decision"] == "insufficient_evidence":
        reasons.extend(candidate["qualification"]["reasons"])
    return with_report_id(
        {
            "schema_version": REPORT_SCHEMA,
            "report_type": "validation",
            "decision": candidate["decision"],
            "reasons": sorted(set(reasons)),
            "thresholds": report_thresholds(None),
            "candidate": candidate,
            "baseline": None,
            "comparisons": {"cases": [], "quality": []},
        }
    )


def assert_comparable(candidate: dict[str, Any], baseline: dict[str, Any]) -> None:
    distinct_bindings = (
        ("run id", candidate["run_id"], baseline["run_id"]),
        (
            "build digest",
            candidate["bindings"]["build_digest"],
            baseline["bindings"]["build_digest"],
        ),
        (
            "installed artifact digest",
            candidate["daemon"]["artifact_digest"],
            baseline["daemon"]["artifact_digest"],
        ),
        (
            "installation receipt digest",
            candidate["daemon"]["installation_receipt_digest"],
            baseline["daemon"]["installation_receipt_digest"],
        ),
    )
    for label, candidate_value, baseline_value in distinct_bindings:
        if candidate_value == baseline_value:
            fail(f"candidate and baseline must have distinct {label}")
    if (
        candidate["bindings"]["dataset_digest"]
        != baseline["bindings"]["dataset_digest"]
    ):
        fail("candidate and baseline dataset digests differ")
    if candidate["environment_digest"] != baseline["environment_digest"]:
        fail("candidate and baseline environment digests differ")
    if canonical_bytes(candidate["configuration"]) != canonical_bytes(
        baseline["configuration"]
    ):
        fail("candidate and baseline tokenizer or policy differs")
    candidate_cases = {
        case["case_id"]: case["case_digest"] for case in candidate["cases"]
    }
    baseline_cases = {
        case["case_id"]: case["case_digest"] for case in baseline["cases"]
    }
    if candidate_cases != baseline_cases:
        fail("candidate and baseline workload case digests differ")
    for key in ("warmup_samples_per_case", "post_warm_samples_per_case"):
        if candidate["collection"][key] != baseline["collection"][key]:
            fail("candidate and baseline sample plans differ")


def bootstrap_p95_regression(
    candidate: Sequence[float],
    baseline: Sequence[float],
    repetitions: int,
    seed_material: bytes,
) -> dict[str, Any]:
    if len(candidate) != len(baseline) or not candidate:
        fail("paired bootstrap requires equal non-empty sample arrays")
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")
    generator = random.Random(seed)
    changes: list[float] = []
    length = len(candidate)
    for _ in range(repetitions):
        indexes = [generator.randrange(length) for _ in range(length)]
        candidate_p95 = nearest_rank((candidate[index] for index in indexes), 0.95)
        baseline_p95 = nearest_rank((baseline[index] for index in indexes), 0.95)
        if baseline_p95 <= 0.0:
            fail("baseline p95 must be positive")
        changes.append((candidate_p95 / baseline_p95 - 1.0) * 100.0)
    point = (nearest_rank(candidate, 0.95) / nearest_rank(baseline, 0.95) - 1.0) * 100.0
    return {
        "point_percent": clean_float(point),
        "ci95_percent": [
            clean_float(nearest_rank(changes, 0.025)),
            clean_float(nearest_rank(changes, 0.975)),
        ],
        "method": "paired_sample_index_bootstrap_nearest_rank",
        "repetitions": repetitions,
    }


def comparison_status(value: float, block: float) -> str:
    if value > block:
        return "fail"
    if value > WARN_REGRESSION_PERCENT:
        return "warn"
    return "pass"


def compare_case(
    case_id: str,
    candidate: Sequence[dict[str, Any]],
    baseline: Sequence[dict[str, Any]],
    repetitions: int,
    seed_material: bytes,
) -> dict[str, Any]:
    candidate_metrics = [
        sample["metrics"] for sample in candidate if sample["phase"] == "post_warm"
    ]
    baseline_metrics = [
        sample["metrics"] for sample in baseline if sample["phase"] == "post_warm"
    ]
    if len(candidate_metrics) != len(baseline_metrics):
        fail("candidate and baseline post-warm sample counts differ")
    p95 = bootstrap_p95_regression(
        [float(metric["latency_ms"]) for metric in candidate_metrics],
        [float(metric["latency_ms"]) for metric in baseline_metrics],
        repetitions,
        seed_material,
    )
    # The PRD's statistical-significance qualifier applies specifically to p95.
    p95_status = (
        "fail"
        if p95["ci95_percent"][0] > P95_REGRESSION_PERCENT
        else ("warn" if p95["point_percent"] > WARN_REGRESSION_PERCENT else "pass")
    )
    candidate_throughput = nearest_rank(
        (metric_value(metric, "throughput_per_second") for metric in candidate_metrics),
        0.50,
    )
    baseline_throughput = nearest_rank(
        (metric_value(metric, "throughput_per_second") for metric in baseline_metrics),
        0.50,
    )
    throughput_change = (
        (baseline_throughput - candidate_throughput) / baseline_throughput * 100.0
    )
    candidate_rss = nearest_rank(
        (float(metric["rss_bytes"]) for metric in candidate_metrics), 0.95
    )
    baseline_rss = nearest_rank(
        (float(metric["rss_bytes"]) for metric in baseline_metrics), 0.95
    )
    if baseline_rss <= 0.0:
        fail("baseline RSS p95 must be positive")
    rss_change = (candidate_rss / baseline_rss - 1.0) * 100.0
    throughput = {
        "statistic": "p50",
        "baseline": clean_float(baseline_throughput),
        "candidate": clean_float(candidate_throughput),
        "regression_percent": clean_float(throughput_change),
        "block_over_percent": THROUGHPUT_REGRESSION_PERCENT,
        "status": comparison_status(throughput_change, THROUGHPUT_REGRESSION_PERCENT),
    }
    rss = {
        "statistic": "p95",
        "baseline": clean_float(baseline_rss),
        "candidate": clean_float(candidate_rss),
        "regression_percent": clean_float(rss_change),
        "block_over_percent": RSS_REGRESSION_PERCENT,
        "status": comparison_status(rss_change, RSS_REGRESSION_PERCENT),
    }
    statuses = [p95_status, throughput["status"], rss["status"]]
    status = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "pass"
    return {
        "case_id": case_id,
        "status": status,
        "p95_latency": {
            **p95,
            "statistically_significant_block_over_percent": P95_REGRESSION_PERCENT,
            "status": p95_status,
        },
        "throughput": throughput,
        "rss": rss,
    }


def quality_comparisons(
    candidate: dict[str, Any], baseline: dict[str, Any]
) -> list[dict[str, Any]]:
    checks = [
        {
            "metric": "minimum_critical_recall",
            "baseline": baseline["minimum_critical_recall"],
            "candidate": candidate["minimum_critical_recall"],
            "comparison": "candidate_at_least_baseline",
            "status": (
                "pass"
                if candidate["minimum_critical_recall"]
                >= baseline["minimum_critical_recall"]
                else "fail"
            ),
        },
        {
            "metric": "leakage_count",
            "baseline": baseline["leakage_count"],
            "candidate": candidate["leakage_count"],
            "comparison": "candidate_at_most_baseline",
            "status": (
                "pass"
                if candidate["leakage_count"] <= baseline["leakage_count"]
                else "fail"
            ),
        },
        {
            "metric": "correctness_loss_samples",
            "baseline": baseline["correctness_loss_samples"],
            "candidate": candidate["correctness_loss_samples"],
            "comparison": "candidate_equals_zero",
            "status": (
                "pass" if candidate["correctness_loss_samples"] == 0 else "fail"
            ),
        },
        {
            "metric": "correctness_degradation_samples",
            "baseline": baseline["correctness_degradation_samples"],
            "candidate": candidate["correctness_degradation_samples"],
            "comparison": "candidate_equals_zero",
            "status": (
                "pass" if candidate["correctness_degradation_samples"] == 0 else "fail"
            ),
        },
    ]
    return checks


def comparison_report(
    candidate_manifest: dict[str, Any],
    candidate_samples: Sequence[dict[str, Any]],
    candidate_samples_digest: str,
    baseline_manifest: dict[str, Any],
    baseline_samples: Sequence[dict[str, Any]],
    baseline_samples_digest: str,
    bootstrap_repetitions: int = MIN_BOOTSTRAP_REPETITIONS,
    candidate_attestation: dict[str, Any] | None = None,
    baseline_attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    integer(bootstrap_repetitions, "bootstrap repetitions", 1)
    if bootstrap_repetitions > MAX_BOOTSTRAP_REPETITIONS:
        fail("bootstrap repetitions exceed the bounded evaluator limit")
    if candidate_samples_digest == baseline_samples_digest:
        fail("candidate and baseline must have distinct sample streams")
    if (
        candidate_attestation is not None
        and baseline_attestation is not None
        and candidate_attestation.get("verified") is True
        and baseline_attestation.get("verified") is True
        and candidate_attestation.get("attestation_digest")
        == baseline_attestation.get("attestation_digest")
    ):
        fail("candidate and baseline must have distinct attestations")
    assert_comparable(candidate_manifest, baseline_manifest)
    candidate = evaluate_run(
        candidate_manifest,
        candidate_samples,
        candidate_samples_digest,
        candidate_attestation,
    )
    baseline = evaluate_run(
        baseline_manifest,
        baseline_samples,
        baseline_samples_digest,
        baseline_attestation,
    )
    candidate_grouped = samples_by_case(candidate_samples)
    baseline_grouped = samples_by_case(baseline_samples)
    seed_prefix = canonical_bytes(
        {
            "candidate": candidate_samples_digest,
            "baseline": baseline_samples_digest,
            "repetitions": bootstrap_repetitions,
        }
    )
    case_comparisons = [
        compare_case(
            case["case_id"],
            candidate_grouped[case["case_id"]],
            baseline_grouped[case["case_id"]],
            bootstrap_repetitions,
            seed_prefix + case["case_id"].encode("utf-8"),
        )
        for case in candidate_manifest["cases"]
    ]
    quality = quality_comparisons(candidate["quality"], baseline["quality"])
    reasons: list[str] = []
    if bootstrap_repetitions < MIN_BOOTSTRAP_REPETITIONS:
        reasons.append("fewer_than_10000_bootstrap_repetitions")
    if not candidate["qualification"]["eligible"]:
        reasons.extend(
            f"candidate:{reason}" for reason in candidate["qualification"]["reasons"]
        )
    if not baseline["qualification"]["eligible"]:
        reasons.extend(
            f"baseline:{reason}" for reason in baseline["qualification"]["reasons"]
        )
    if baseline["decision"] != "pass":
        reasons.append("baseline_did_not_pass_qualification_gates")
    failing_regressions = [
        comparison["case_id"]
        for comparison in case_comparisons
        if comparison["status"] == "fail"
    ]
    failing_quality = [
        check["metric"] for check in quality if check["status"] == "fail"
    ]
    hard_failure = (
        candidate["decision"] == "fail"
        or bool(failing_regressions)
        or bool(failing_quality)
    )
    if candidate["decision"] == "fail":
        reasons.append("candidate_slo_or_correctness_failure")
    reasons.extend(f"regression_failure:{case}" for case in failing_regressions)
    reasons.extend(f"quality_regression:{metric}" for metric in failing_quality)
    if hard_failure:
        decision = "fail"
    elif reasons:
        decision = "insufficient_evidence"
    else:
        decision = "pass"
    return with_report_id(
        {
            "schema_version": REPORT_SCHEMA,
            "report_type": "comparison",
            "decision": decision,
            "reasons": sorted(set(reasons)),
            "thresholds": report_thresholds(bootstrap_repetitions),
            "candidate": candidate,
            "baseline": baseline,
            "comparisons": {"cases": case_comparisons, "quality": quality},
        }
    )


def load_evidence(
    manifest_path: Path, samples_path: Path
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    manifest = validate_manifest(load_json(manifest_path))
    samples = load_samples(samples_path, manifest)
    return manifest, samples, file_multihash(samples_path)


def load_verified_attestation(
    attestation_path: Path | None,
    key_path: Path | None,
    manifest: dict[str, Any],
    samples: Sequence[dict[str, Any]],
    samples_digest: str,
) -> dict[str, Any]:
    if (attestation_path is None) != (key_path is None):
        fail("attestation and attestation key must be supplied together")
    if attestation_path is None or key_path is None:
        return missing_attestation()
    return verify_attestation(
        load_json(attestation_path),
        manifest,
        samples,
        samples_digest,
        read_attestation_key(key_path),
    )


def command_attest(arguments: argparse.Namespace) -> dict[str, Any]:
    manifest, samples, samples_digest = load_evidence(
        arguments.manifest, arguments.samples
    )
    attestation = create_attestation(
        manifest,
        samples,
        samples_digest,
        arguments.key_id,
        read_attestation_key(arguments.key_file),
    )
    write_json(arguments.output, attestation)
    return attestation


def command_validate(arguments: argparse.Namespace) -> dict[str, Any]:
    manifest, samples, samples_digest = load_evidence(
        arguments.manifest, arguments.samples
    )
    attestation = load_verified_attestation(
        arguments.attestation,
        arguments.attestation_key_file,
        manifest,
        samples,
        samples_digest,
    )
    report = validation_report(manifest, samples, samples_digest, attestation)
    write_json(arguments.output, report)
    if arguments.require_qualification and report["decision"] != "pass":
        fail("performance qualification did not pass")
    return report


def command_compare(arguments: argparse.Namespace) -> dict[str, Any]:
    candidate_manifest, candidate_samples, candidate_digest = load_evidence(
        arguments.candidate_manifest, arguments.candidate_samples
    )
    baseline_manifest, baseline_samples, baseline_digest = load_evidence(
        arguments.baseline_manifest, arguments.baseline_samples
    )
    candidate_attestation = load_verified_attestation(
        arguments.candidate_attestation,
        arguments.candidate_attestation_key_file,
        candidate_manifest,
        candidate_samples,
        candidate_digest,
    )
    baseline_attestation = load_verified_attestation(
        arguments.baseline_attestation,
        arguments.baseline_attestation_key_file,
        baseline_manifest,
        baseline_samples,
        baseline_digest,
    )
    report = comparison_report(
        candidate_manifest,
        candidate_samples,
        candidate_digest,
        baseline_manifest,
        baseline_samples,
        baseline_digest,
        arguments.bootstrap_repetitions,
        candidate_attestation,
        baseline_attestation,
    )
    write_json(arguments.output, report)
    if arguments.require_qualification and report["decision"] != "pass":
        fail("performance comparison did not pass")
    return report


def command_replay(arguments: argparse.Namespace) -> None:
    recorded = validate_report(load_json(arguments.report))
    candidate_manifest, candidate_samples, candidate_digest = load_evidence(
        arguments.candidate_manifest, arguments.candidate_samples
    )
    candidate_attestation = load_verified_attestation(
        arguments.candidate_attestation,
        arguments.candidate_attestation_key_file,
        candidate_manifest,
        candidate_samples,
        candidate_digest,
    )
    if recorded["report_type"] == "validation":
        if (
            arguments.baseline_manifest is not None
            or arguments.baseline_samples is not None
        ):
            fail("validation replay does not accept baseline evidence")
        reproduced = validation_report(
            candidate_manifest,
            candidate_samples,
            candidate_digest,
            candidate_attestation,
        )
    else:
        if arguments.baseline_manifest is None or arguments.baseline_samples is None:
            fail("comparison replay requires baseline evidence")
        baseline_manifest, baseline_samples, baseline_digest = load_evidence(
            arguments.baseline_manifest, arguments.baseline_samples
        )
        baseline_attestation = load_verified_attestation(
            arguments.baseline_attestation,
            arguments.baseline_attestation_key_file,
            baseline_manifest,
            baseline_samples,
            baseline_digest,
        )
        repetitions = recorded["thresholds"]["bootstrap_repetitions"]
        reproduced = comparison_report(
            candidate_manifest,
            candidate_samples,
            candidate_digest,
            baseline_manifest,
            baseline_samples,
            baseline_digest,
            repetitions,
            candidate_attestation,
            baseline_attestation,
        )
    if canonical_bytes(recorded) != canonical_bytes(reproduced):
        fail("performance report does not reproduce from raw evidence")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Validate digest-bound CIGAR section 22 performance evidence"
    )
    result.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external evidence workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    subcommands = result.add_subparsers(dest="command", required=True)

    attest = subcommands.add_parser(
        "attest", help="authenticate a validated raw performance stream"
    )
    attest.add_argument("--manifest", type=Path, required=True)
    attest.add_argument("--samples", type=Path, required=True)
    attest.add_argument("--key-file", type=Path, required=True)
    attest.add_argument("--key-id", required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.set_defaults(function=command_attest)

    validate = subcommands.add_parser("validate", help="validate one performance run")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--samples", type=Path, required=True)
    validate.add_argument("--attestation", type=Path)
    validate.add_argument("--attestation-key-file", type=Path)
    validate.add_argument("--output", type=Path, required=True)
    validate.add_argument("--require-qualification", action="store_true")
    validate.set_defaults(function=command_validate)

    compare = subcommands.add_parser("compare", help="compare candidate and baseline")
    compare.add_argument("--candidate-manifest", type=Path, required=True)
    compare.add_argument("--candidate-samples", type=Path, required=True)
    compare.add_argument("--baseline-manifest", type=Path, required=True)
    compare.add_argument("--baseline-samples", type=Path, required=True)
    compare.add_argument("--candidate-attestation", type=Path)
    compare.add_argument("--candidate-attestation-key-file", type=Path)
    compare.add_argument("--baseline-attestation", type=Path)
    compare.add_argument("--baseline-attestation-key-file", type=Path)
    compare.add_argument(
        "--bootstrap-repetitions", type=int, default=MIN_BOOTSTRAP_REPETITIONS
    )
    compare.add_argument("--output", type=Path, required=True)
    compare.add_argument("--require-qualification", action="store_true")
    compare.set_defaults(function=command_compare)

    replay = subcommands.add_parser("replay", help="reproduce and verify a report")
    replay.add_argument("--report", type=Path, required=True)
    replay.add_argument("--candidate-manifest", type=Path, required=True)
    replay.add_argument("--candidate-samples", type=Path, required=True)
    replay.add_argument("--candidate-attestation", type=Path)
    replay.add_argument("--candidate-attestation-key-file", type=Path)
    replay.add_argument("--baseline-manifest", type=Path)
    replay.add_argument("--baseline-samples", type=Path)
    replay.add_argument("--baseline-attestation", type=Path)
    replay.add_argument("--baseline-attestation-key-file", type=Path)
    replay.set_defaults(function=command_replay)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    evidence: EvidenceExecution | None = None
    try:
        evidence = EvidenceExecution.open(arguments)
        arguments.function(arguments)
        evidence.publish(f"performance-{arguments.command}")
        return 0
    except PerformanceError as error:
        print(f"performance evidence error: {error}", file=sys.stderr)
        return 2
    except (EvidenceWorkspaceError, OSError):
        print(
            "performance evidence error: operating system operation failed",
            file=sys.stderr,
        )
        return 2
    finally:
        if evidence is not None:
            evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
