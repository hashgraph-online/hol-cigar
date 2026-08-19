#!/usr/bin/env python3
"""Build and independently verify content-free three-way workflow evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Never

SCHEMA_VERSION = "cigar.workflow-efficacy.evidence-manifest.v1"
RAW_SCHEMA = "cigar.workflow-efficacy.raw-observations.v1"
ENVIRONMENT_SCHEMA = "cigar.workflow-efficacy.environment-receipt.v1"
AGGREGATE_SCHEMA = "cigar.workflow-efficacy.aggregate-report.v1"
CLAIM_SCHEMA = "cigar.workflow-efficacy.claim-ledger.v1"
TREATMENT_IDS = (
    "honey-0.9.2-balanced-v1",
    "honey-0.9.3-balanced-v3",
    "honey-0.9.4-balanced-v4",
)
BASELINE_COMMITS = {
    "honey-0.9.2-balanced-v1": "35538959bce7497311906e4d370334a87abd362b",
    "honey-0.9.3-balanced-v3": "a049fbc8ed81c9adc6b1a066ca053c5befc2578a",
}
ATTACHMENTS = {
    "configuration": "configuration.json",
    "raw_observations": "raw-observations.json",
    "environment_receipt": "environment-receipt.json",
    "aggregate_report": "aggregate-report.json",
    "claim_ledger": "claim-ledger.json",
}
MAX_FILE_BYTES = 1024 * 1024 * 1024


class EvidenceError(RuntimeError):
    """A stable, content-free evidence validation failure."""


def fail(message: str) -> Never:
    raise EvidenceError(message)


def canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EvidenceError("evidence is not canonical JSON") from error


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bounded_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        status = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_size <= 0
        or status.st_size > MAX_FILE_BYTES
    ):
        fail(f"{label} is not one bounded regular file")
    return status


def strict_json(
    path: Path, label: str, *, require_canonical: bool = True
) -> dict[str, Any]:
    bounded_regular_file(path, label)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                fail(f"{label} contains a duplicate key")
            output[key] = value
        return output

    payload = path.read_bytes()
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        fail(f"{label} root is not an object")
    if require_canonical and payload != canonical(value):
        fail(f"{label} is not encoded canonically")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has missing or unexpected fields")
    return value


def exact_list(value: Any, length: int | None, label: str) -> list[Any]:
    if not isinstance(value, list) or (length is not None and len(value) != length):
        fail(f"{label} is not the expected list")
    return value


def text(value: Any, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        fail(f"{label} is not bounded text")
    return value


def sha256(value: Any, label: str) -> str:
    value = text(value, label, maximum=64)
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        fail(f"{label} is not a SHA-256 digest")
    return value


def git_object(value: Any, label: str) -> str:
    value = text(value, label, maximum=40)
    if len(value) != 40 or any(
        character not in "0123456789abcdef" for character in value
    ):
        fail(f"{label} is not an immutable Git object")
    return value


def integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        fail(f"{label} is not a bounded integer")
    return value


def metric_number(value: Any, label: str) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        fail(f"{label} is not a finite numeric metric")
    if value < 0 or abs(value) > 2**63 - 1:
        fail(f"{label} is outside the metric domain")
    return float(value)


def safe_file_name(value: Any, label: str) -> str:
    value = text(value, label, maximum=128)
    path = PurePosixPath(value)
    if path.is_absolute() or len(path.parts) != 1 or path.name != value:
        fail(f"{label} is not a safe evidence file name")
    return value


def file_digest(path: Path) -> str:
    bounded_regular_file(path, path.name)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_evidence_directory(path: Path, *, must_exist: bool = True) -> Path:
    path = path.resolve(strict=must_exist)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        fail("evidence directory is unavailable")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        fail("evidence directory must be owner-only")
    return path


def configuration(path: Path) -> tuple[dict[str, Any], str]:
    value = strict_json(path, "configuration", require_canonical=False)
    exact_keys(
        value,
        {
            "schema_version",
            "configuration_id",
            "scenario",
            "treatments",
            "workflows",
            "cohorts",
            "ordering",
            "metrics",
            "bootstrap",
            "environment_tolerance",
            "content_policy",
        },
        "configuration",
    )
    if value["schema_version"] != "cigar.workflow-efficacy.configuration.v1":
        fail("configuration schema version is unsupported")
    text(value["configuration_id"], "configuration ID", maximum=128)
    text(value["scenario"], "scenario", maximum=128)

    treatments = exact_list(value["treatments"], 3, "configured treatments")
    expected_treatments: list[str] = []
    for index, treatment in enumerate(treatments):
        exact_keys(
            treatment,
            {
                "id",
                "product_version",
                "retrieval_profile",
                "compiler_profile",
                "runner_feature",
            },
            f"configured treatment {index}",
        )
        treatment_id = text(treatment["id"], "configured treatment ID", maximum=128)
        expected_treatments.append(treatment_id)
        if treatment["runner_feature"] is not None:
            text(treatment["runner_feature"], "runner feature", maximum=64)
    if tuple(expected_treatments) != TREATMENT_IDS:
        fail("configuration does not declare the exact three treatments")
    if len({item["product_version"] for item in treatments}) != 3:
        fail("configured treatment versions are not unique")

    workflows = exact_list(value["workflows"], 5, "configured workflows")
    if len(set(workflows)) != 5:
        fail("configured workflows are not unique")
    for workflow in workflows:
        text(workflow, "workflow ID", maximum=64)

    cohorts = exact_keys(value["cohorts"], {"historical", "rc"}, "configured cohorts")
    for cohort_id, minimum in (("historical", 20), ("rc", 50)):
        cohort = exact_keys(
            cohorts[cohort_id],
            {
                "measured_trials_per_workflow",
                "warmups_per_workflow",
                "randomize_block_order",
            },
            f"{cohort_id} cohort",
        )
        trials = integer(
            cohort["measured_trials_per_workflow"], "measured trials", minimum=1
        )
        warmups = integer(cohort["warmups_per_workflow"], "warmups", minimum=0)
        if trials < minimum or (cohort_id == "rc" and warmups < 10):
            fail(f"{cohort_id} cohort is below its registered minimum")
        if cohort_id == "historical" and (trials != 20 or warmups != 5):
            fail("historical cohort must remain the frozen five-by-20 design")
        if not isinstance(cohort["randomize_block_order"], bool):
            fail("cohort randomization selector is not Boolean")

    ordering = exact_keys(
        value["ordering"],
        {
            "algorithm",
            "randomization_algorithm",
            "latin_square",
            "historical_row_rule",
            "rc_row_rule",
        },
        "ordering configuration",
    )
    if ordering["algorithm"] != "balanced-cyclic-latin-square-v1":
        fail("ordering algorithm is unsupported")
    if ordering["randomization_algorithm"] != "sha256-counter-fisher-yates-v1":
        fail("randomization algorithm is unsupported")
    square = exact_list(ordering["latin_square"], 3, "Latin square")
    for row in square:
        if set(exact_list(row, 3, "Latin-square row")) != set(TREATMENT_IDS):
            fail("Latin-square row does not contain every treatment exactly once")
    for position in range(3):
        if {row[position] for row in square} != set(TREATMENT_IDS):
            fail("Latin square is not position-balanced")

    metrics = value["metrics"]
    if not isinstance(metrics, dict) or not metrics:
        fail("metric registry is empty")
    for metric, direction in metrics.items():
        text(metric, "metric ID", maximum=128)
        if direction not in {"higher", "lower", "diagnostic"}:
            fail("metric direction is unsupported")
    for required in (
        "completed",
        "blocking_requirement_coverage",
        "gold_source_coverage",
        "citation_resolvability_rate",
        "exact_tokens",
        "estimated_tokens",
        "wall_time_ns",
        "planner_latency_ns",
        "reducer_latency_ns",
        "compiler_latency_ns",
        "materializer_latency_ns",
        "total_latency_ns",
    ):
        if required not in metrics:
            fail("metric registry omits a required measurement")

    bootstrap = exact_keys(
        value["bootstrap"],
        {"algorithm", "resamples", "confidence_level", "metrics"},
        "bootstrap configuration",
    )
    if bootstrap["algorithm"] != "paired-sha256-counter-bootstrap-v1":
        fail("bootstrap algorithm is unsupported")
    integer(bootstrap["resamples"], "bootstrap resamples", minimum=1, maximum=100000)
    if bootstrap["confidence_level"] != 0.95:
        fail("bootstrap confidence level must be 0.95")
    bootstrap_metrics = exact_list(bootstrap["metrics"], None, "bootstrap metrics")
    if not bootstrap_metrics or not set(bootstrap_metrics) <= set(metrics):
        fail("bootstrap metric registry is invalid")

    policy = exact_keys(
        value["content_policy"],
        {
            "raw_evidence_location",
            "repository_evidence",
            "forbidden_observation_fields",
        },
        "content policy",
    )
    if policy["raw_evidence_location"] != "external-owner-only":
        fail("raw evidence location policy is unsafe")
    exact_list(policy["forbidden_observation_fields"], None, "forbidden fields")
    return value, file_digest(path)


def deterministic_u64(seed: bytes, counter: int) -> int:
    digest = hashlib.sha256(seed + counter.to_bytes(16, "big")).digest()
    return int.from_bytes(digest[:8], "big")


def shuffled(values: list[Any], seed: str, namespace: str) -> list[Any]:
    output = list(values)
    key = hashlib.sha256(f"{seed}\x00{namespace}".encode()).digest()
    for counter, index in enumerate(range(len(output) - 1, 0, -1)):
        selected = deterministic_u64(key, counter) % (index + 1)
        output[index], output[selected] = output[selected], output[index]
    return output


def pair_key(pair: dict[str, Any]) -> tuple[str, str, int, int]:
    return (pair["workflow"], pair["scenario"], pair["trial"], pair["turn"])


def validate_pair(pair: Any, config: dict[str, Any], label: str) -> dict[str, Any]:
    pair = exact_keys(pair, {"workflow", "scenario", "trial", "turn"}, label)
    if (
        pair["workflow"] not in config["workflows"]
        or pair["scenario"] != config["scenario"]
    ):
        fail(f"{label} names an unregistered workflow or scenario")
    integer(pair["trial"], f"{label} trial", maximum=1000000)
    integer(pair["turn"], f"{label} turn", maximum=10000)
    return pair


def expected_blocks(
    config: dict[str, Any], cohort_id: str, seed: str
) -> list[tuple[str, dict[str, Any]]]:
    cohort = config["cohorts"][cohort_id]
    output: list[tuple[str, dict[str, Any]]] = []
    for phase, count in (
        ("warmup", cohort["warmups_per_workflow"]),
        ("measured", cohort["measured_trials_per_workflow"]),
    ):
        phase_blocks = [
            (
                phase,
                {
                    "workflow": workflow,
                    "scenario": config["scenario"],
                    "trial": trial,
                    "turn": 0,
                },
            )
            for workflow in config["workflows"]
            for trial in range(count)
        ]
        if cohort["randomize_block_order"]:
            phase_blocks = shuffled(phase_blocks, seed, phase)
        output.extend(phase_blocks)
    return output


def latin_row(
    config: dict[str, Any], cohort_id: str, seed: str, pair: dict[str, Any]
) -> list[str]:
    if cohort_id == "historical":
        workflow_ordinal = config["workflows"].index(pair["workflow"])
        row = (workflow_ordinal + pair["trial"]) % 3
    else:
        identity = "\x00".join(
            (
                seed,
                pair["workflow"],
                pair["scenario"],
                str(pair["trial"]),
                str(pair["turn"]),
            )
        ).encode()
        row = int.from_bytes(hashlib.sha256(identity).digest()[:8], "big") % 3
    return config["ordering"]["latin_square"][row]


def validate_treatment_binding(
    binding: Any,
    configured: dict[str, Any],
    environment_digest: str,
    configuration_digest: str,
) -> dict[str, Any]:
    binding = exact_keys(
        binding,
        {
            "id",
            "product_version",
            "retrieval_profile",
            "compiler_profile",
            "source",
            "runner",
        },
        "treatment binding",
    )
    for field in ("id", "product_version", "retrieval_profile", "compiler_profile"):
        if binding[field] != configured[field]:
            fail("treatment binding does not match the registered configuration")
    source = exact_keys(
        binding["source"],
        {
            "root",
            "commit",
            "tree",
            "product_version",
            "context_abi",
            "worktree_dirty",
            "source_set_sha256",
            "source_files",
        },
        "source binding",
    )
    text(source["root"], "source root", maximum=4096)
    commit = git_object(source["commit"], "source commit")
    git_object(source["tree"], "source tree")
    if (
        source["product_version"] != configured["product_version"]
        or source["worktree_dirty"] is not False
    ):
        fail("source binding has version drift or a dirty worktree")
    sha256(source["source_set_sha256"], "source-set digest")
    files = exact_list(source["source_files"], None, "source files")
    if not files:
        fail("source binding has no files")
    seen_files: set[str] = set()
    observed_files: list[str] = []
    for item in files:
        item = exact_keys(item, {"path", "bytes", "sha256"}, "source file")
        relative = (
            safe_file_name(item["path"], "source file path")
            if "/" not in str(item["path"])
            else text(item["path"], "source file path", maximum=512)
        )
        if (
            relative in seen_files
            or relative.startswith("/")
            or ".." in PurePosixPath(relative).parts
        ):
            fail("source file path is duplicate or unsafe")
        seen_files.add(relative)
        observed_files.append(relative)
        integer(item["bytes"], "source file bytes", minimum=1, maximum=MAX_FILE_BYTES)
        sha256(item["sha256"], "source file digest")
    if observed_files != sorted(observed_files):
        fail("source-file inventory is not canonically ordered")
    if source["source_set_sha256"] != digest_bytes(canonical(files)):
        fail("source-set digest does not bind the declared source files")
    if commit != BASELINE_COMMITS.get(binding["id"], commit):
        fail("historical baseline commit drifted")

    runner = exact_keys(
        binding["runner"],
        {
            "binary_sha256",
            "generated_manifest_sha256",
            "lockfile_sha256",
            "runner_source_sha256",
            "manifest_template_sha256",
            "harness_sha256",
            "fixture_sha256",
            "source_set_sha256",
            "environment_receipt_sha256",
            "host_sha256",
            "toolchain_sha256",
            "configuration_sha256",
            "build_profile",
        },
        "runner binding",
    )
    for field in (
        "binary_sha256",
        "generated_manifest_sha256",
        "lockfile_sha256",
        "runner_source_sha256",
        "manifest_template_sha256",
        "harness_sha256",
        "fixture_sha256",
        "source_set_sha256",
    ):
        sha256(runner[field], f"runner {field}")
    if runner["source_set_sha256"] != source["source_set_sha256"]:
        fail("runner is not bound to the treatment source set")
    if runner["environment_receipt_sha256"] != environment_digest:
        fail("runner is not bound to the environment receipt")
    if runner["configuration_sha256"] != configuration_digest:
        fail("runner is not bound to the registered configuration")
    if runner["build_profile"] != "release-locked-offline":
        fail("runner was not built with the qualifying profile")
    return binding


def validate_environment(value: dict[str, Any]) -> tuple[str, str]:
    exact_keys(
        value,
        {"schema_version", "observed_at", "host", "toolchain", "power"},
        "environment receipt",
    )
    if value["schema_version"] != ENVIRONMENT_SCHEMA:
        fail("environment receipt schema is unsupported")
    text(value["observed_at"], "environment observation time", maximum=64)
    for field in ("host", "toolchain", "power"):
        if not isinstance(value[field], dict) or not value[field]:
            fail(f"environment {field} receipt is empty")
    return digest_bytes(canonical(value["host"])), digest_bytes(
        canonical(value["toolchain"])
    )


def validate_raw(
    value: dict[str, Any],
    config: dict[str, Any],
    configuration_digest: str,
    environment_digest: str,
    host_digest: str,
    toolchain_digest: str,
) -> dict[str, Any]:
    exact_keys(
        value,
        {
            "schema_version",
            "configuration_sha256",
            "cohort",
            "seed_commitment",
            "treatments",
            "order_blocks",
            "observations",
        },
        "raw observations",
    )
    if (
        value["schema_version"] != RAW_SCHEMA
        or value["configuration_sha256"] != configuration_digest
    ):
        fail("raw observations have schema or configuration drift")
    cohort_id = value["cohort"]
    if cohort_id not in config["cohorts"]:
        fail("raw observations name an unsupported cohort")
    seed = sha256(value["seed_commitment"], "seed commitment")

    bindings = exact_list(value["treatments"], 3, "treatment bindings")
    configured = {item["id"]: item for item in config["treatments"]}
    actual_ids: list[str] = []
    commits: set[str] = set()
    trees: set[str] = set()
    for binding in bindings:
        treatment_id = binding.get("id") if isinstance(binding, dict) else None
        if treatment_id not in configured:
            fail("raw observations contain an unknown treatment")
        validate_treatment_binding(
            binding,
            configured[treatment_id],
            environment_digest,
            configuration_digest,
        )
        if binding["runner"]["host_sha256"] != host_digest:
            fail("runner is not bound to the host receipt")
        if binding["runner"]["toolchain_sha256"] != toolchain_digest:
            fail("runner is not bound to the toolchain receipt")
        actual_ids.append(treatment_id)
        commits.add(binding["source"]["commit"])
        trees.add(binding["source"]["tree"])
    if tuple(actual_ids) != TREATMENT_IDS or len(commits) != 3 or len(trees) != 3:
        fail("treatments are duplicated, reordered, or source-reused")

    expected = expected_blocks(config, cohort_id, seed)
    blocks = exact_list(value["order_blocks"], len(expected), "order blocks")
    measured_orders: dict[tuple[str, str, int, int], list[str]] = {}
    for index, (block, (expected_phase, expected_pair)) in enumerate(
        zip(blocks, expected, strict=True)
    ):
        block = exact_keys(block, {"phase", "pairing", "order"}, f"order block {index}")
        pair = validate_pair(block["pairing"], config, f"order block {index} pairing")
        if block["phase"] != expected_phase or pair != expected_pair:
            fail("order blocks do not follow the pre-registered block order")
        order = exact_list(block["order"], 3, f"order block {index} treatment order")
        if order != latin_row(config, cohort_id, seed, pair):
            fail("order block does not follow the pre-registered Latin square")
        if expected_phase == "measured":
            key = pair_key(pair)
            if key in measured_orders:
                fail("measured pair identity is duplicated")
            measured_orders[key] = order

    expected_observations = (
        len(config["workflows"])
        * config["cohorts"][cohort_id]["measured_trials_per_workflow"]
        * 3
    )
    observations = exact_list(
        value["observations"], expected_observations, "observations"
    )
    metric_ids = set(config["metrics"])
    pair_treatments: dict[tuple[str, str, int, int], set[str]] = {}
    for index, observation in enumerate(observations):
        observation = exact_keys(
            observation,
            {"pairing", "treatment_id", "order_position", "metrics"},
            f"observation {index}",
        )
        pair = validate_pair(
            observation["pairing"], config, f"observation {index} pairing"
        )
        key = pair_key(pair)
        order = measured_orders.get(key)
        if order is None:
            fail("observation has no registered measured order block")
        treatment_id = observation["treatment_id"]
        if treatment_id not in TREATMENT_IDS:
            fail("observation treatment is unknown")
        position = integer(observation["order_position"], "order position", maximum=2)
        if order[position] != treatment_id:
            fail("observation treatment order is inconsistent")
        present = pair_treatments.setdefault(key, set())
        if treatment_id in present:
            fail("pair contains a duplicate treatment observation")
        present.add(treatment_id)
        metrics = exact_keys(
            observation["metrics"], metric_ids, f"observation {index} metrics"
        )
        for metric, metric_value in metrics.items():
            metric_number(metric_value, f"observation {index} metric {metric}")
    if set(pair_treatments) != set(measured_orders) or any(
        values != set(TREATMENT_IDS) for values in pair_treatments.values()
    ):
        fail("paired observations are incomplete")
    return value


def percentile(values: list[float], probability: float) -> float:
    if not values:
        fail("cannot summarize an empty metric")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def summary(values: list[float]) -> dict[str, float | int]:
    mean = math.fsum(values) / len(values)
    median = percentile(values, 0.5)
    deviations = [abs(value - median) for value in values]
    return {
        "count": len(values),
        "min": min(values),
        "mean": mean,
        "p50": median,
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
        "median_absolute_deviation": percentile(deviations, 0.5),
    }


def bootstrap_intervals(
    deltas: dict[str, list[float]],
    config: dict[str, Any],
    seed_namespace: str,
) -> dict[str, list[float]]:
    metrics = config["bootstrap"]["metrics"]
    count = len(next(iter(deltas.values())))
    if count == 0 or any(len(deltas[metric]) != count for metric in metrics):
        fail("bootstrap inputs are unpaired")
    estimates = {metric: [] for metric in metrics}
    seed = hashlib.sha256(seed_namespace.encode()).digest()
    counter = 0
    for _ in range(config["bootstrap"]["resamples"]):
        totals = {metric: 0.0 for metric in metrics}
        for _ in range(count):
            selected = deterministic_u64(seed, counter) % count
            counter += 1
            for metric in metrics:
                totals[metric] += deltas[metric][selected]
        for metric in metrics:
            estimates[metric].append(totals[metric] / count)
    return {
        metric: [percentile(values, 0.025), percentile(values, 0.975)]
        for metric, values in estimates.items()
    }


def aggregate_scope(
    observations: list[dict[str, Any]],
    config: dict[str, Any],
    configuration_digest: str,
    scope_id: str,
) -> dict[str, Any]:
    metric_ids = list(config["metrics"])
    by_treatment: dict[str, dict[tuple[str, str, int, int], dict[str, float]]] = {
        treatment: {} for treatment in TREATMENT_IDS
    }
    for observation in observations:
        treatment = observation["treatment_id"]
        key = pair_key(observation["pairing"])
        by_treatment[treatment][key] = {
            metric: metric_number(value, metric)
            for metric, value in observation["metrics"].items()
        }
    pair_sets = [set(values) for values in by_treatment.values()]
    if not pair_sets or any(values != pair_sets[0] for values in pair_sets[1:]):
        fail("aggregate scope contains unpaired treatment data")
    keys = sorted(pair_sets[0])
    treatment_reports: dict[str, Any] = {}
    for treatment in TREATMENT_IDS:
        treatment_reports[treatment] = {
            "observation_count": len(keys),
            "metrics": {
                metric: summary([by_treatment[treatment][key][metric] for key in keys])
                for metric in metric_ids
            },
        }

    candidate = TREATMENT_IDS[2]
    comparisons: dict[str, Any] = {}
    for baseline in TREATMENT_IDS[:2]:
        comparison_id = f"{candidate}__vs__{baseline}"
        deltas = {
            metric: [
                by_treatment[candidate][key][metric]
                - by_treatment[baseline][key][metric]
                for key in keys
            ]
            for metric in metric_ids
        }
        intervals = bootstrap_intervals(
            deltas,
            config,
            f"{configuration_digest}\x00{scope_id}\x00{comparison_id}",
        )
        metric_reports: dict[str, Any] = {}
        for metric in metric_ids:
            baseline_mean = treatment_reports[baseline]["metrics"][metric]["mean"]
            candidate_mean = treatment_reports[candidate]["metrics"][metric]["mean"]
            direction = config["metrics"][metric]
            if baseline_mean == 0 or direction == "diagnostic":
                improvement = None
            elif direction == "lower":
                improvement = (
                    (baseline_mean - candidate_mean) * 100.0 / abs(baseline_mean)
                )
            else:
                improvement = (
                    (candidate_mean - baseline_mean) * 100.0 / abs(baseline_mean)
                )
            metric_report: dict[str, Any] = {
                "candidate_minus_baseline_mean": math.fsum(deltas[metric]) / len(keys),
                "relative_improvement_percent": improvement,
            }
            if metric in intervals:
                metric_report["paired_mean_delta_95pct_bootstrap_ci"] = intervals[
                    metric
                ]
            metric_reports[metric] = metric_report
        comparisons[comparison_id] = {
            "pair_count": len(keys),
            "metrics": metric_reports,
        }
    return {"treatments": treatment_reports, "comparisons": comparisons}


def compute_aggregate(
    raw: dict[str, Any],
    config: dict[str, Any],
    configuration_digest: str,
    raw_digest: str,
) -> dict[str, Any]:
    observations = raw["observations"]
    by_workflow = {
        workflow: aggregate_scope(
            [item for item in observations if item["pairing"]["workflow"] == workflow],
            config,
            configuration_digest,
            f"workflow:{workflow}",
        )
        for workflow in config["workflows"]
    }
    return {
        "schema_version": AGGREGATE_SCHEMA,
        "configuration_sha256": configuration_digest,
        "raw_observations_sha256": raw_digest,
        "cohort": raw["cohort"],
        "overall": aggregate_scope(
            observations, config, configuration_digest, "overall"
        ),
        "by_workflow": by_workflow,
    }


def claim(claim_id: str, passed: bool, actual: Any, rule: str) -> dict[str, Any]:
    return {
        "claim_id": claim_id,
        "status": "pass" if passed else "fail",
        "actual": actual,
        "rule": rule,
    }


def compute_claim_ledger(
    aggregate: dict[str, Any], configuration_digest: str, aggregate_digest: str
) -> dict[str, Any]:
    candidate = TREATMENT_IDS[2]
    baseline_092, baseline_093 = TREATMENT_IDS[:2]
    overall = aggregate["overall"]["treatments"]
    candidate_metrics = overall[candidate]["metrics"]
    claims = [
        claim(
            "H094-G03-valid-completion",
            candidate_metrics["completed"]["min"] == 1.0,
            candidate_metrics["completed"]["min"],
            "candidate minimum == 1",
        ),
        claim(
            "H094-G03-blocking-coverage",
            candidate_metrics["blocking_requirement_coverage"]["min"] == 1.0,
            candidate_metrics["blocking_requirement_coverage"]["min"],
            "candidate minimum == 1",
        ),
        claim(
            "H094-G03-gold-coverage",
            candidate_metrics["gold_source_coverage"]["min"] == 1.0,
            candidate_metrics["gold_source_coverage"]["min"],
            "candidate minimum == 1",
        ),
        claim(
            "H094-G03-citation-resolution",
            candidate_metrics["citation_resolvability_rate"]["min"] == 1.0,
            candidate_metrics["citation_resolvability_rate"]["min"],
            "candidate minimum == 1",
        ),
        claim(
            "H094-G04-exact-token-mean",
            candidate_metrics["exact_tokens"]["mean"] <= 1050.0,
            candidate_metrics["exact_tokens"]["mean"],
            "candidate mean <= 1050",
        ),
        claim(
            "H094-G05-useful-precision",
            candidate_metrics["useful_selection_precision"]["mean"] >= 0.60,
            candidate_metrics["useful_selection_precision"]["mean"],
            "candidate mean >= 0.60",
        ),
        claim(
            "H094-G05-semantic-duplicates",
            candidate_metrics["semantic_duplicate_rate"]["mean"] <= 0.01,
            candidate_metrics["semantic_duplicate_rate"]["mean"],
            "candidate mean <= 0.01",
        ),
        claim(
            "H094-G08-context-cycles",
            candidate_metrics["context_cycles"]["min"] == 3.0,
            candidate_metrics["context_cycles"]["min"],
            "candidate minimum == 3",
        ),
        claim(
            "H094-G08-two-deltas",
            candidate_metrics["delta_count"]["min"] >= 2.0,
            candidate_metrics["delta_count"]["min"],
            "candidate minimum >= 2",
        ),
        claim(
            "H094-G08-delta-reuse",
            candidate_metrics["delta_reuse_rate"]["mean"] >= 0.70,
            candidate_metrics["delta_reuse_rate"]["mean"],
            "candidate mean >= 0.70",
        ),
        claim(
            "H094-G08-materialization",
            candidate_metrics["materialization_count"]["min"] >= 3.0,
            candidate_metrics["materialization_count"]["min"],
            "candidate minimum >= 3",
        ),
        claim(
            "H094-G08-revalidation",
            candidate_metrics["revalidation_count"]["min"] >= 1.0,
            candidate_metrics["revalidation_count"]["min"],
            "candidate minimum >= 1",
        ),
        claim(
            "H094-G08-exactly-once-effect",
            candidate_metrics["effect_count"]["min"] == 1.0
            and candidate_metrics["effect_count"]["max"] == 1.0,
            candidate_metrics["effect_count"]["mean"],
            "candidate minimum and maximum == 1",
        ),
        claim(
            "H094-G08-checkpoint-per-cycle",
            candidate_metrics["checkpoint_count"]["min"] >= 3.0,
            candidate_metrics["checkpoint_count"]["min"],
            "candidate minimum >= 3",
        ),
        claim(
            "H094-G08-replay",
            candidate_metrics["replay_verified"]["min"] == 1.0,
            candidate_metrics["replay_verified"]["min"],
            "candidate minimum == 1",
        ),
        claim(
            "H094-G08-negative-cases",
            candidate_metrics["negative_cases_passed"]["min"] == 9.0,
            candidate_metrics["negative_cases_passed"]["min"],
            "candidate minimum == 9",
        ),
        claim(
            "H094-G08-fail-closed",
            candidate_metrics["fail_closed"]["min"] == 1.0,
            candidate_metrics["fail_closed"]["min"],
            "candidate minimum == 1",
        ),
        claim(
            "H094-G16-embedded-mode",
            candidate_metrics["embedded_mode_exercised"]["mean"] == 0.5,
            candidate_metrics["embedded_mode_exercised"]["mean"],
            "candidate mean == 0.5 under trial-mod-2 schedule",
        ),
        claim(
            "H094-G16-sidecar-mode",
            candidate_metrics["sidecar_mode_exercised"]["mean"] == 0.5,
            candidate_metrics["sidecar_mode_exercised"]["mean"],
            "candidate mean == 0.5 under trial-mod-2 schedule",
        ),
    ]
    for workflow, report in aggregate["by_workflow"].items():
        treatments = report["treatments"]
        candidate_values = treatments[candidate]["metrics"]
        v3_values = treatments[baseline_093]["metrics"]
        claims.extend(
            [
                claim(
                    f"H094-G04-{workflow}-token-nonregression",
                    candidate_values["exact_tokens"]["mean"]
                    <= v3_values["exact_tokens"]["mean"] * 1.02,
                    candidate_values["exact_tokens"]["mean"],
                    "candidate mean <= 1.02 * 0.9.3 mean",
                ),
                claim(
                    f"H094-G06-{workflow}-reducer-p50",
                    candidate_values["reducer_latency_ns"]["p50"]
                    <= v3_values["reducer_latency_ns"]["p50"],
                    candidate_values["reducer_latency_ns"]["p50"],
                    "candidate p50 <= 0.9.3 p50",
                ),
                claim(
                    f"H094-G06-{workflow}-reducer-p95",
                    candidate_values["reducer_latency_ns"]["p95"]
                    <= v3_values["reducer_latency_ns"]["p95"],
                    candidate_values["reducer_latency_ns"]["p95"],
                    "candidate p95 <= 0.9.3 p95",
                ),
                claim(
                    f"H094-G06-{workflow}-compiler-p95",
                    candidate_values["compiler_latency_ns"]["p95"]
                    <= v3_values["compiler_latency_ns"]["p95"] * 1.05,
                    candidate_values["compiler_latency_ns"]["p95"],
                    "candidate p95 <= 1.05 * 0.9.3 p95",
                ),
            ]
        )
        if workflow in {"solo", "json-rpc", "evm-tx-liveness"}:
            claims.append(
                claim(
                    f"H094-G06-{workflow}-small-workflow-p95",
                    candidate_values["reducer_latency_ns"]["p95"]
                    <= v3_values["reducer_latency_ns"]["p95"] * 0.70,
                    candidate_values["reducer_latency_ns"]["p95"],
                    "candidate p95 <= 0.70 * 0.9.3 p95",
                )
            )
    claims.extend(
        [
            claim(
                "H094-G06-aggregate-total-p50-v3",
                candidate_metrics["total_latency_ns"]["p50"]
                <= overall[baseline_093]["metrics"]["total_latency_ns"]["p50"] * 0.80,
                candidate_metrics["total_latency_ns"]["p50"],
                "candidate p50 <= 0.80 * 0.9.3 p50",
            ),
            claim(
                "H094-G06-aggregate-total-p50-v1",
                candidate_metrics["total_latency_ns"]["p50"]
                <= overall[baseline_092]["metrics"]["total_latency_ns"]["p50"] * 0.50,
                candidate_metrics["total_latency_ns"]["p50"],
                "candidate p50 <= 0.50 * 0.9.2 p50",
            ),
            {
                "claim_id": "H094-G07-128-512-allocation",
                "status": "not_evaluated",
                "actual": None,
                "rule": "requires dedicated 128- and 512-candidate cohorts",
            },
        ]
    )
    evaluated = [item for item in claims if item["status"] != "not_evaluated"]
    return {
        "schema_version": CLAIM_SCHEMA,
        "configuration_sha256": configuration_digest,
        "aggregate_report_sha256": aggregate_digest,
        "cohort": aggregate["cohort"],
        "overall_status": "pass"
        if all(item["status"] == "pass" for item in evaluated)
        else "fail",
        "claims": claims,
    }


def exclusive_write(path: Path, value: dict[str, Any]) -> None:
    payload = canonical(value)
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
    except OSError as error:
        raise EvidenceError(f"refusing to replace {path.name}") from error
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def attachment(path: Path) -> dict[str, Any]:
    status = bounded_regular_file(path, path.name)
    return {"file": path.name, "bytes": status.st_size, "sha256": file_digest(path)}


def manifest_value(
    directory: Path, config: dict[str, Any], cohort: str
) -> dict[str, Any]:
    attachments = {
        name: attachment(directory / file_name)
        for name, file_name in ATTACHMENTS.items()
    }
    evidence_id = digest_bytes(canonical(attachments))
    return {
        "schema_version": SCHEMA_VERSION,
        "configuration_id": config["configuration_id"],
        "cohort": cohort,
        "evidence_id": evidence_id,
        "attachments": attachments,
    }


def build(directory: Path) -> dict[str, Any]:
    directory = validate_evidence_directory(directory)
    config, config_digest = configuration(directory / ATTACHMENTS["configuration"])
    environment_path = directory / ATTACHMENTS["environment_receipt"]
    environment = strict_json(environment_path, "environment receipt")
    host_digest, toolchain_digest = validate_environment(environment)
    environment_digest = file_digest(environment_path)
    raw_path = directory / ATTACHMENTS["raw_observations"]
    raw = strict_json(raw_path, "raw observations")
    validate_raw(
        raw,
        config,
        config_digest,
        environment_digest,
        host_digest,
        toolchain_digest,
    )
    raw_digest = file_digest(raw_path)
    aggregate = compute_aggregate(raw, config, config_digest, raw_digest)
    aggregate_path = directory / ATTACHMENTS["aggregate_report"]
    exclusive_write(aggregate_path, aggregate)
    ledger = compute_claim_ledger(aggregate, config_digest, file_digest(aggregate_path))
    ledger_path = directory / ATTACHMENTS["claim_ledger"]
    exclusive_write(ledger_path, ledger)
    manifest = manifest_value(directory, config, raw["cohort"])
    exclusive_write(directory / "evidence-manifest.json", manifest)
    return manifest


def verify_manifest(value: dict[str, Any], directory: Path) -> dict[str, Path]:
    exact_keys(
        value,
        {"schema_version", "configuration_id", "cohort", "evidence_id", "attachments"},
        "evidence manifest",
    )
    if value["schema_version"] != SCHEMA_VERSION or value["cohort"] not in {
        "historical",
        "rc",
    }:
        fail("evidence manifest schema or cohort is unsupported")
    sha256(value["evidence_id"], "evidence ID")
    attachments = exact_keys(
        value["attachments"], set(ATTACHMENTS), "manifest attachments"
    )
    paths: dict[str, Path] = {}
    canonical_attachments: dict[str, Any] = {}
    for name, expected_file in ATTACHMENTS.items():
        item = exact_keys(
            attachments[name], {"file", "bytes", "sha256"}, f"{name} attachment"
        )
        if safe_file_name(item["file"], f"{name} file") != expected_file:
            fail("manifest attachment uses an unexpected file name")
        path = directory / expected_file
        status = bounded_regular_file(path, f"{name} attachment")
        if (
            integer(item["bytes"], f"{name} bytes", minimum=1, maximum=MAX_FILE_BYTES)
            != status.st_size
        ):
            fail("manifest attachment byte length drifted")
        if sha256(item["sha256"], f"{name} digest") != file_digest(path):
            fail("manifest attachment digest drifted")
        canonical_attachments[name] = item
        paths[name] = path
    if value["evidence_id"] != digest_bytes(canonical(canonical_attachments)):
        fail("evidence identity drifted")
    return paths


def verify(directory: Path) -> dict[str, Any]:
    directory = validate_evidence_directory(directory)
    manifest = strict_json(directory / "evidence-manifest.json", "evidence manifest")
    paths = verify_manifest(manifest, directory)
    config, config_digest = configuration(paths["configuration"])
    if manifest["configuration_id"] != config["configuration_id"]:
        fail("manifest configuration identity drifted")
    environment = strict_json(paths["environment_receipt"], "environment receipt")
    host_digest, toolchain_digest = validate_environment(environment)
    raw = strict_json(paths["raw_observations"], "raw observations")
    validate_raw(
        raw,
        config,
        config_digest,
        file_digest(paths["environment_receipt"]),
        host_digest,
        toolchain_digest,
    )
    if raw["cohort"] != manifest["cohort"]:
        fail("manifest cohort drifted")
    expected_aggregate = compute_aggregate(
        raw, config, config_digest, file_digest(paths["raw_observations"])
    )
    actual_aggregate = strict_json(paths["aggregate_report"], "aggregate report")
    if actual_aggregate != expected_aggregate:
        fail("aggregate report does not recompute from raw observations")
    expected_ledger = compute_claim_ledger(
        expected_aggregate, config_digest, file_digest(paths["aggregate_report"])
    )
    actual_ledger = strict_json(paths["claim_ledger"], "claim ledger")
    if actual_ledger != expected_ledger:
        fail("claim ledger does not recompute from the aggregate report")
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    for command in ("build", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--evidence-dir", required=True, type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        result = (
            build(arguments.evidence_dir)
            if arguments.command == "build"
            else verify(arguments.evidence_dir)
        )
    except EvidenceError as error:
        print(f"workflow evidence rejected: {error}")
        return 1
    print(
        json.dumps(
            {"evidence_id": result["evidence_id"], "status": "verified"}, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
