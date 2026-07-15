#!/usr/bin/env python3
"""CIGARBench v1: deterministic plans, raw evidence, comparison, and replay.

The module intentionally uses only the Python standard library so an installed
release can reproduce reports without downloading analysis dependencies.  Smoke
fixtures exercise the harness but are permanently ineligible for release claims.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never

HARNESS_ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = HARNESS_ROOT / "scripts" / "release"
if str(RELEASE_TOOLS) not in sys.path:
    sys.path.insert(0, str(RELEASE_TOOLS))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    digest_secure_file,
    safe_relative_path as safe_evidence_path,
)

SCHEMA = "cigar.benchmark-event.v1"
PLAN_SCHEMA = "cigar.benchmark-plan.v1"
REPORT_SCHEMA = "cigar.benchmark-report.v1"
ENVIRONMENT_SCHEMA = "cigar.benchmark-environment.v1"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_EVENTS = 1_000_000
MAX_ASSIGNMENTS = 50_000
MAX_CONSUMER_OUTPUT = 64 * 1024
MAX_CONSUMER_ARTIFACT = 2 * 1024 * 1024 * 1024
PROTECTED_STRATA = {"PolicyBoundary", "EffectCrash", "MultiProject-Switch"}
REQUIRED_STRATA = {
    "LongRepo-Change",
    "MultiProject-Switch",
    "Agent-Handoff",
    "Temporal-Truth",
    "Needle-and-Distractor",
    "PolicyBoundary",
    "EffectCrash",
    "CrossRuntime-Replay",
    "CatalogMutation",
}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MULTIHASH = re.compile(r"^1220[0-9a-f]{64}$")
TREATMENTS = ("baseline", "cigar")
METRIC_KEYS = {
    "physical_input_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "verified_success",
    "critical_recall",
    "context_precision",
    "prohibited_context_rate",
    "context_caused_harm",
    "stale_harm",
    "rework_count",
    "latency_ms",
    "intervention_count",
    "cost",
    "unauthorized_context_count",
    "calibration_variance",
}
PIN_KEYS = {
    "model",
    "runtime",
    "tools",
    "repository",
    "output_budget",
    "sampling",
    "tokenizer",
    "source",
    "adapter",
    "compiler",
    "consumer_artifact",
}
ASSIGNMENT_KEYS = {
    "run_id",
    "pair_id",
    "dataset_id",
    "task_id",
    "stratum",
    "baseline_id",
    "sample_index",
    "evidence_class",
    "pins",
    "environment_digest",
    "treatment",
    "order",
}


class BenchError(Exception):
    """A content-free benchmark validation failure."""


def fail(message: str) -> Never:
    raise BenchError(message)


def selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment and Path(argument) != Path(environment):
        fail("--evidence-dir conflicts with CIGAR_EVIDENCE_DIR")
    selected = argument if argument is not None else environment
    if selected is None or os.fspath(selected) == "":
        return None
    path = Path(selected)
    if not path.is_absolute():
        fail("benchmark evidence directory must be absolute")
    return path


class EvidenceExecution:
    """Stage one command output before create-new external publication."""

    def __init__(
        self,
        workspace: EvidenceWorkspace | None,
        relative_output: str | None,
        temporary: tempfile.TemporaryDirectory[str] | None,
    ) -> None:
        self.workspace = workspace
        self.relative_output = relative_output
        self.temporary = temporary

    @classmethod
    def open(cls, arguments: argparse.Namespace) -> EvidenceExecution:
        selected = selected_evidence_directory(arguments)
        if selected is None:
            return cls(None, None, None)
        workspace = EvidenceWorkspace.create(selected, repository_root=HARNESS_ROOT)
        temporary: tempfile.TemporaryDirectory[str] | None = None
        try:
            relative_output: str | None = None
            output = getattr(arguments, "output", None)
            if output is not None:
                try:
                    relative_output = "/".join(safe_evidence_path(os.fspath(output)))
                except EvidenceWorkspaceError as error:
                    raise BenchError(
                        "benchmark evidence output path is unsafe"
                    ) from error
                temporary = tempfile.TemporaryDirectory(prefix="cigarbench-evidence-")
                staging_root = Path(temporary.name).resolve(strict=True)
                # Raw benchmark attachments are unpublished and must remain owner-private.
                os.chmod(staging_root, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                staged = staging_root / "output"
                arguments.output = staged
            return cls(workspace, relative_output, temporary)
        except BaseException:
            if temporary is not None:
                temporary.cleanup()
            workspace.close()
            raise

    def publish(self, command: str) -> None:
        if self.workspace is None:
            return
        attachment: dict[str, object] | None = None
        if self.relative_output is not None:
            if self.temporary is None:
                fail("benchmark evidence staging is unavailable")
            staged = Path(self.temporary.name).resolve(strict=True) / "output"
            expected = digest_secure_file(staged, max_bytes=MAX_INPUT_BYTES)
            published = self.workspace.attach_file(
                staged,
                self.relative_output,
                expected_sha256=expected.sha256,
                expected_bytes=expected.bytes,
            )
            attachment = published.as_dict()
            receipt_path = f"{self.relative_output}.receipt.json"
        else:
            receipt_path = f"cigarbench/{command}.receipt.json"
        tool = digest_secure_file(
            Path(__file__).resolve(strict=True), max_bytes=MAX_INPUT_BYTES
        )
        self.workspace.write_json(
            receipt_path,
            {
                "schema_version": "cigar.benchmark-evidence-publication.v1",
                "command": command,
                "status": "passed",
                "qualifying_evidence": False,
                "source_descriptor_bound": False,
                "tool": {
                    "sha256": tool.sha256,
                    "bytes": tool.bytes,
                },
                "output": attachment,
            },
        )

    def close(self) -> None:
        if self.workspace is not None:
            self.workspace.close()
        if self.temporary is not None:
            self.temporary.cleanup()


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON contains a duplicate object key")
        result[key] = value
    return result


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
        raise BenchError("value is not canonical JSON") from error


def sha256_multihash(value: bytes) -> str:
    return "1220" + hashlib.sha256(value).hexdigest()


def file_multihash(path: Path, maximum: int = MAX_INPUT_BYTES) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        fail("artifact must be a bounded regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "1220" + digest.hexdigest()


def load_json(path: Path, maximum: int = MAX_INPUT_BYTES) -> Any:
    if path.is_symlink() or not path.is_file():
        fail("input must be a regular non-symlink file")
    size = path.stat().st_size
    if size > maximum:
        fail("input exceeds the byte limit")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchError("input is not strict UTF-8 JSON") from error


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(value) + b"\n"
    if len(payload) > MAX_INPUT_BYTES:
        fail("JSON output exceeds the byte limit")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
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


def identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        fail(f"{label} is not a bounded identifier")
    return value


def finite_number(value: Any, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} is not numeric")
    number = float(value)
    if not math.isfinite(number) or number < minimum:
        fail(f"{label} is outside its numeric bounds")
    return number


def ratio(value: Any, label: str) -> float:
    number = finite_number(value, label)
    if number > 1.0:
        fail(f"{label} is outside [0,1]")
    return number


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields do not match the v1 schema")
    return value


def validate_metrics(value: Any) -> dict[str, Any]:
    metrics = exact_keys(value, METRIC_KEYS, "metrics")
    for key in (
        "physical_input_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "rework_count",
        "intervention_count",
        "unauthorized_context_count",
    ):
        number = metrics[key]
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            fail(f"metric {key} must be a non-negative integer")
    for key in ("verified_success", "context_caused_harm"):
        if not isinstance(metrics[key], bool):
            fail(f"metric {key} must be boolean")
    for key in (
        "critical_recall",
        "context_precision",
        "prohibited_context_rate",
        "stale_harm",
        "calibration_variance",
    ):
        ratio(metrics[key], f"metric {key}")
    finite_number(metrics["latency_ms"], "metric latency_ms")
    finite_number(metrics["cost"], "metric cost")
    prohibited = float(metrics["prohibited_context_rate"])
    unauthorized = int(metrics["unauthorized_context_count"])
    if (prohibited == 0.0) != (unauthorized == 0):
        fail("prohibited-context rate and unauthorized count are inconsistent")
    if float(metrics["stale_harm"]) > 0.0 and not metrics["context_caused_harm"]:
        fail("stale harm must be included in context-caused harm")
    return metrics


def validate_pins(value: Any) -> dict[str, Any]:
    pins = exact_keys(value, PIN_KEYS, "pins")
    for key in PIN_KEYS - {"output_budget"}:
        identifier(pins[key], f"pin {key}")
    budget = pins["output_budget"]
    if isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0:
        fail("pin output_budget must be a positive integer")
    if not isinstance(pins["consumer_artifact"], str) or not MULTIHASH.fullmatch(
        pins["consumer_artifact"]
    ):
        fail("consumer artifact pin must be a sha256 multihash")
    return pins


EVENT_KEYS = {
    "schema_version",
    "event_id",
    "run_id",
    "pair_id",
    "dataset_id",
    "task_id",
    "stratum",
    "treatment",
    "baseline_id",
    "order",
    "sample_index",
    "warmup",
    "evidence_class",
    "pins",
    "metrics",
    "environment_digest",
    "assignment_digest",
    "seed_commitment",
    "attestation",
}


def validate_event(value: Any) -> dict[str, Any]:
    event = exact_keys(value, EVENT_KEYS, "event")
    if event["schema_version"] != SCHEMA:
        fail("event schema version is unsupported")
    for key in ("run_id", "pair_id", "dataset_id", "task_id", "stratum", "baseline_id"):
        identifier(event[key], key)
    if event["treatment"] not in TREATMENTS:
        fail("event treatment is unsupported")
    if event["order"] not in (1, 2):
        fail("event order must be one or two")
    if (
        isinstance(event["sample_index"], bool)
        or not isinstance(event["sample_index"], int)
        or event["sample_index"] < 0
    ):
        fail("sample index must be a non-negative integer")
    if not isinstance(event["warmup"], bool):
        fail("warmup must be boolean")
    if event["evidence_class"] not in ("harness_smoke", "qualification"):
        fail("evidence class is unsupported")
    validate_pins(event["pins"])
    validate_metrics(event["metrics"])
    for key in (
        "event_id",
        "environment_digest",
        "assignment_digest",
        "seed_commitment",
    ):
        if not isinstance(event[key], str) or not MULTIHASH.fullmatch(event[key]):
            fail(f"{key} is not a sha256 multihash")
    attestation = event["attestation"]
    if attestation is not None:
        attestation = exact_keys(attestation, {"key_id", "mac"}, "event attestation")
        identifier(attestation["key_id"], "attestation key id")
        if not isinstance(attestation["mac"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", attestation["mac"]
        ):
            fail("event attestation MAC is invalid")
    preimage = dict(event)
    supplied = preimage.pop("event_id")
    if sha256_multihash(canonical_bytes(preimage)) != supplied:
        fail("event identity does not match its canonical fields")
    return event


def event_with_id(value: dict[str, Any]) -> dict[str, Any]:
    event = dict(value)
    event.pop("event_id", None)
    event["event_id"] = sha256_multihash(canonical_bytes(event))
    return validate_event(event)


def load_events(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        fail("raw event input is not a bounded regular file")
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    with path.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            if len(raw) > MAX_EVENT_BYTES:
                fail("raw event exceeds the per-event byte limit")
            if len(events) >= MAX_EVENTS:
                fail("raw event count exceeds the limit")
            try:
                value = json.loads(raw, object_pairs_hook=reject_duplicates)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BenchError(
                    f"raw event line {line_number} is invalid JSON"
                ) from error
            event = validate_event(value)
            if event["event_id"] in seen:
                fail("raw events contain a duplicate identity")
            seen.add(event["event_id"])
            events.append(event)
    if not events:
        fail("raw event stream is empty")
    return events


def write_events(path: Path, events: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            total = 0
            count = 0
            for event in events:
                payload = canonical_bytes(event) + b"\n"
                if len(payload) > MAX_EVENT_BYTES:
                    fail("raw event exceeds the per-event byte limit")
                total += len(payload)
                count += 1
                if total > MAX_INPUT_BYTES or count > MAX_EVENTS:
                    fail("raw event output exceeds the aggregate limit")
                stream.write(payload)
            if count == 0:
                fail("raw event output cannot be empty")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Pair:
    baseline: dict[str, Any]
    cigar: dict[str, Any]


def paired(events: Sequence[dict[str, Any]]) -> list[Pair]:
    groups: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for event in events:
        if event["warmup"]:
            continue
        treatments = groups[event["pair_id"]]
        if event["treatment"] in treatments:
            fail("one pair contains a duplicate treatment")
        treatments[event["treatment"]] = event
    result: list[Pair] = []
    for pair_id in sorted(groups):
        group = groups[pair_id]
        if set(group) != set(TREATMENTS):
            fail("one post-warm pair is incomplete")
        baseline, cigar = group["baseline"], group["cigar"]
        for key in (
            "run_id",
            "pair_id",
            "dataset_id",
            "task_id",
            "stratum",
            "baseline_id",
            "sample_index",
            "evidence_class",
            "pins",
            "environment_digest",
            "assignment_digest",
            "seed_commitment",
        ):
            if baseline[key] != cigar[key]:
                fail(f"paired events disagree on {key}")
        if baseline["order"] == cigar["order"]:
            fail("paired treatments have the same execution order")
        result.append(Pair(baseline, cigar))
    if not result:
        fail("raw events contain no post-warm pairs")
    return result


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        fail("cannot summarize an empty sample")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def mean(values: Sequence[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def token_reduction(pair: Pair) -> float:
    baseline = float(pair.baseline["metrics"]["physical_input_tokens"])
    cigar = float(pair.cigar["metrics"]["physical_input_tokens"])
    if baseline <= 0.0:
        fail("baseline physical input tokens must be positive")
    return 100.0 * (baseline - cigar) / baseline


def success_cost_improvement(sample: Sequence[Pair]) -> float:
    baseline_successes = sum(
        pair.baseline["metrics"]["verified_success"] for pair in sample
    )
    cigar_successes = sum(pair.cigar["metrics"]["verified_success"] for pair in sample)
    if baseline_successes == 0 or cigar_successes == 0:
        return float("nan")
    baseline = (
        sum(float(pair.baseline["metrics"]["cost"]) for pair in sample)
        / baseline_successes
    )
    cigar = (
        sum(float(pair.cigar["metrics"]["cost"]) for pair in sample) / cigar_successes
    )
    if baseline <= 0:
        return float("nan")
    return 100.0 * (baseline - cigar) / baseline


def bootstrap_interval(
    sample: Sequence[Pair],
    statistic: Callable[[Sequence[Pair]], float],
    repetitions: int,
    rng: random.Random,
) -> list[float] | None:
    clusters_by_stratum: dict[str, dict[tuple[str, str], list[Pair]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for pair in sample:
        event = pair.baseline
        clusters_by_stratum[event["stratum"]][
            (event["dataset_id"], event["task_id"])
        ].append(pair)
    # Repetitions of one task are correlated measurements, not independent jobs.
    # Resample whole task clusters and preserve each stratum's task count.
    if not clusters_by_stratum or any(
        len(clusters) < 2 for clusters in clusters_by_stratum.values()
    ):
        return None
    values: list[float] = []
    for _ in range(repetitions):
        resampled: list[Pair] = []
        for stratum in sorted(clusters_by_stratum):
            clusters = [
                clusters_by_stratum[stratum][key]
                for key in sorted(clusters_by_stratum[stratum])
            ]
            for _cluster in clusters:
                resampled.extend(clusters[rng.randrange(len(clusters))])
        value = statistic(resampled)
        if math.isfinite(value):
            values.append(value)
    if len(values) < max(2, repetitions // 2):
        return None
    return [round(percentile(values, 0.025), 6), round(percentile(values, 0.975), 6)]


def rounded(value: float) -> float:
    return round(value, 6)


def distribution(values: Sequence[float]) -> dict[str, float | int]:
    if not values:
        fail("cannot summarize an empty metric distribution")
    return {
        "count": len(values),
        "minimum": rounded(min(values)),
        "p25": rounded(percentile(values, 0.25)),
        "p50": rounded(percentile(values, 0.50)),
        "p75": rounded(percentile(values, 0.75)),
        "p95": rounded(percentile(values, 0.95)),
        "p99": rounded(percentile(values, 0.99)),
        "maximum": rounded(max(values)),
        "mean": rounded(mean(values)),
    }


def wilson_binary_interval(successes: int, count: int) -> list[float]:
    if count <= 0 or successes < 0 or successes > count:
        fail("binary outcome sample is invalid")
    z = 1.959963984540054
    probability = successes / count
    denominator = 1.0 + z * z / count
    center = (probability + z * z / (2.0 * count)) / denominator
    radius = (
        z
        * math.sqrt(
            probability * (1.0 - probability) / count + z * z / (4.0 * count * count)
        )
        / denominator
    )
    return [
        rounded(100.0 * max(0.0, center - radius)),
        rounded(100.0 * min(1.0, center + radius)),
    ]


def treatment_values(sample: Sequence[Pair], treatment: str, key: str) -> list[float]:
    return [float(getattr(pair, treatment)["metrics"][key]) for pair in sample]


def cost_per_success(sample: Sequence[Pair], treatment: str) -> float | None:
    successes = sum(
        bool(getattr(pair, treatment)["metrics"]["verified_success"]) for pair in sample
    )
    if successes == 0:
        return None
    return rounded(sum(treatment_values(sample, treatment, "cost")) / successes)


def metric_summary(
    sample: Sequence[Pair], repetitions: int, rng: random.Random
) -> dict[str, Any]:
    reductions = [token_reduction(pair) for pair in sample]

    def median_reduction(values: Sequence[Pair]) -> float:
        return statistics.median(token_reduction(pair) for pair in values)

    def quarter_reduction(values: Sequence[Pair]) -> float:
        return percentile([token_reduction(pair) for pair in values], 0.25)

    def success_delta(values: Sequence[Pair]) -> float:
        baseline = mean(
            [float(pair.baseline["metrics"]["verified_success"]) for pair in values]
        )
        cigar = mean(
            [float(pair.cigar["metrics"]["verified_success"]) for pair in values]
        )
        return 100.0 * (cigar - baseline)

    def cigar_average(key: str) -> Callable[[Sequence[Pair]], float]:
        return lambda values: 100.0 * mean(
            [float(pair.cigar["metrics"][key]) for pair in values]
        )

    costs = success_cost_improvement(sample)
    baseline_success = 100.0 * mean(
        treatment_values(sample, "baseline", "verified_success")
    )
    cigar_success = 100.0 * mean(treatment_values(sample, "cigar", "verified_success"))
    task_clusters: dict[tuple[str, str, str], list[Pair]] = defaultdict(list)
    for pair in sample:
        event = pair.baseline
        task_clusters[(event["stratum"], event["dataset_id"], event["task_id"])].append(
            pair
        )
    cigar_harm_count = sum(
        any(bool(pair.cigar["metrics"]["context_caused_harm"]) for pair in values)
        for values in task_clusters.values()
    )
    return {
        "pair_count": len(sample),
        "physical_input_tokens": {
            "baseline": distribution(
                treatment_values(sample, "baseline", "physical_input_tokens")
            ),
            "cigar": distribution(
                treatment_values(sample, "cigar", "physical_input_tokens")
            ),
        },
        "cache_read_tokens": {
            "baseline": distribution(
                treatment_values(sample, "baseline", "cache_read_tokens")
            ),
            "cigar": distribution(
                treatment_values(sample, "cigar", "cache_read_tokens")
            ),
        },
        "cache_write_tokens": {
            "baseline": distribution(
                treatment_values(sample, "baseline", "cache_write_tokens")
            ),
            "cigar": distribution(
                treatment_values(sample, "cigar", "cache_write_tokens")
            ),
        },
        "physical_input_reduction_percent": {
            "median": rounded(statistics.median(reductions)),
            "median_ci95": bootstrap_interval(
                sample, median_reduction, repetitions, rng
            ),
            "p25": rounded(percentile(reductions, 0.25)),
            "p25_ci95": bootstrap_interval(sample, quarter_reduction, repetitions, rng),
        },
        "verified_success_delta_percentage_points": {
            "value": rounded(success_delta(sample)),
            "ci95": bootstrap_interval(sample, success_delta, repetitions, rng),
        },
        "verified_success_percent": {
            "baseline": rounded(baseline_success),
            "cigar": rounded(cigar_success),
        },
        "critical_recall_percent": {
            "baseline": rounded(
                100.0 * mean(treatment_values(sample, "baseline", "critical_recall"))
            ),
            "value": rounded(cigar_average("critical_recall")(sample)),
            "ci95": bootstrap_interval(
                sample, cigar_average("critical_recall"), repetitions, rng
            ),
        },
        "context_precision_percent": {
            "baseline": rounded(
                100.0 * mean(treatment_values(sample, "baseline", "context_precision"))
            ),
            "value": rounded(cigar_average("context_precision")(sample)),
            "ci95": bootstrap_interval(
                sample, cigar_average("context_precision"), repetitions, rng
            ),
        },
        "prohibited_context_percent": {
            "baseline": rounded(
                100.0
                * mean(treatment_values(sample, "baseline", "prohibited_context_rate"))
            ),
            "value": rounded(cigar_average("prohibited_context_rate")(sample)),
            "ci95": bootstrap_interval(
                sample, cigar_average("prohibited_context_rate"), repetitions, rng
            ),
        },
        "context_caused_harm_percent": {
            "baseline": rounded(
                100.0
                * mean(treatment_values(sample, "baseline", "context_caused_harm"))
            ),
            "value": rounded(cigar_average("context_caused_harm")(sample)),
            "ci95": wilson_binary_interval(cigar_harm_count, len(task_clusters)),
        },
        "stale_harm_percent": {
            "baseline": rounded(
                100.0 * mean(treatment_values(sample, "baseline", "stale_harm"))
            ),
            "value": rounded(cigar_average("stale_harm")(sample)),
            "ci95": bootstrap_interval(
                sample, cigar_average("stale_harm"), repetitions, rng
            ),
        },
        "unauthorized_context_count": sum(
            int(pair.cigar["metrics"]["unauthorized_context_count"]) for pair in sample
        ),
        "cost_per_verified_success_improvement_percent": {
            "value": rounded(costs) if math.isfinite(costs) else None,
            "ci95": bootstrap_interval(
                sample, success_cost_improvement, repetitions, rng
            ),
        },
        "cost_per_verified_success": {
            "baseline": cost_per_success(sample, "baseline"),
            "cigar": cost_per_success(sample, "cigar"),
        },
        "cost": {
            "baseline": distribution(treatment_values(sample, "baseline", "cost")),
            "cigar": distribution(treatment_values(sample, "cigar", "cost")),
        },
        "latency_ms": {
            "baseline": distribution(
                treatment_values(sample, "baseline", "latency_ms")
            ),
            "cigar": distribution(treatment_values(sample, "cigar", "latency_ms")),
        },
        "rework_count": {
            "baseline": distribution(
                treatment_values(sample, "baseline", "rework_count")
            ),
            "cigar": distribution(treatment_values(sample, "cigar", "rework_count")),
        },
        "intervention_count": {
            "baseline": distribution(
                treatment_values(sample, "baseline", "intervention_count")
            ),
            "cigar": distribution(
                treatment_values(sample, "cigar", "intervention_count")
            ),
        },
    }


def gate_status(condition: bool, eligible: bool) -> str:
    if not eligible:
        return "insufficient_evidence"
    return "pass" if condition else "fail"


def gates(
    summary: dict[str, Any], eligible: bool, strong_baseline: bool
) -> dict[str, str]:
    token = summary["physical_input_reduction_percent"]
    success_metric = summary["verified_success_delta_percentage_points"]
    cost_metric = summary["cost_per_verified_success_improvement_percent"]
    cost = cost_metric["value"]
    recall = summary["critical_recall_percent"]
    precision = summary["context_precision_percent"]
    harm = summary["context_caused_harm_percent"]
    prohibited = summary["prohibited_context_percent"]
    stale_harm = summary["stale_harm_percent"]
    median_lower = token["median_ci95"][0] if token["median_ci95"] else float("-inf")
    p25_lower = token["p25_ci95"][0] if token["p25_ci95"] else float("-inf")
    success_lower = (
        success_metric["ci95"][0] if success_metric["ci95"] else float("-inf")
    )
    cost_lower = cost_metric["ci95"][0] if cost_metric["ci95"] else float("-inf")
    recall_lower = recall["ci95"][0] if recall["ci95"] else float("-inf")
    precision_lower = precision["ci95"][0] if precision["ci95"] else float("-inf")
    harm_upper = harm["ci95"][1] if harm["ci95"] else float("inf")
    stale_harm_upper = stale_harm["ci95"][1] if stale_harm["ci95"] else float("inf")
    result = {
        "median_physical_input_reduction": gate_status(median_lower >= 40.0, eligible),
        "p25_physical_input_reduction": gate_status(p25_lower >= 25.0, eligible),
        "cost_per_verified_success": gate_status(
            cost is not None and cost_lower >= 10.0, eligible
        ),
        "task_success_noninferiority": gate_status(success_lower >= -2.0, eligible),
        "critical_context_recall": gate_status(recall_lower >= 99.0, eligible),
        "selected_context_precision": gate_status(precision_lower >= 90.0, eligible),
        "context_caused_harm": gate_status(harm_upper < 1.0, eligible),
        "stale_context_harm": gate_status(stale_harm_upper < 1.0, eligible),
        "prohibited_context": gate_status(prohibited["value"] == 0.0, eligible),
        "unauthorized_context": gate_status(
            summary["unauthorized_context_count"] == 0, eligible
        ),
    }
    if strong_baseline:
        strong = (
            median_lower >= 30.0 and success_lower >= -1.0
        ) or success_lower >= 5.0
        result["strong_baseline_advantage"] = gate_status(strong, eligible)
    else:
        result["strong_baseline_advantage"] = "not_applicable"
    return result


def seed_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        fail("seed must be a bounded regular file")
    value = path.read_bytes()
    if len(value) < 32:
        fail("seed must contain at least 32 bytes")
    return value


def attestation_key_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        fail("attestation key must be a bounded regular file")
    value = path.read_bytes()
    if len(value) < 32:
        fail("attestation key must contain at least 32 bytes")
    return value


def attestation_preimage(event: dict[str, Any]) -> bytes:
    value = dict(event)
    value.pop("event_id", None)
    attestation = value.pop("attestation", None)
    if not isinstance(attestation, dict):
        fail("attestation preimage requires an evaluator key identity")
    return b"CIGARBENCH\x00v1\x00independent-verification\x00" + canonical_bytes(
        {"key_id": attestation.get("key_id"), "event": value}
    )


def attest_events(args: argparse.Namespace) -> int:
    plan, datasets, _baselines, _canaries, _environment, _digests = (
        validated_input_bundle(args)
    )
    events = load_events(args.events)
    bind_events_to_plan(events, plan)
    if any(event["evidence_class"] != "qualification" for event in events):
        fail("only qualification-class events may receive an attestation")
    seed = seed_bytes(args.seed_file)
    if sha256_multihash(seed) != plan["seed_commitment"]:
        fail("attestation seed does not match the committed benchmark plan")
    verify_seeded_assignments(plan, datasets, seed)
    key = attestation_key_bytes(args.key_file)
    if key == seed:
        fail("attestation and assignment seed material must be independently held")
    key_id = identifier(args.key_id, "attestation key id")
    attested: list[dict[str, Any]] = []
    for event in events:
        value = dict(event)
        value.pop("event_id")
        value["attestation"] = {"key_id": key_id, "mac": "0" * 64}
        value["attestation"]["mac"] = hmac.new(
            key, attestation_preimage(value), hashlib.sha256
        ).hexdigest()
        attested.append(event_with_id(value))
    write_events(args.output, attested)
    return 0


def verify_attestations(
    events: Sequence[dict[str, Any]], key_path: Path | None
) -> tuple[bool, str | None]:
    if key_path is None:
        return False, None
    key = attestation_key_bytes(key_path)
    key_ids: set[str] = set()
    for event in events:
        attestation = event["attestation"]
        if attestation is None:
            return False, None
        expected = hmac.new(
            key, attestation_preimage(event), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(attestation["mac"], expected):
            fail("qualification event attestation is invalid")
        key_ids.add(attestation["key_id"])
    if len(key_ids) != 1:
        fail("qualification events use more than one attestation key")
    return True, next(iter(key_ids))


def deterministic_rng(seed: bytes, domain: bytes) -> random.Random:
    digest = hashlib.sha256(b"CIGARBENCH\x00v1\x00" + domain + b"\x00" + seed).digest()
    return random.Random(int.from_bytes(digest, "big"))


def seeded_baseline_orders(
    datasets: dict[str, Any], replicates: int, seed: bytes
) -> dict[tuple[str, int], int]:
    if replicates <= 0 or replicates > 100_000:
        fail("replicate count is outside bounds")
    rng = deterministic_rng(seed, b"assignment")
    datasets_by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dataset in datasets["datasets"]:
        datasets_by_stratum[dataset["stratum"]].append(dataset)
    result: dict[tuple[str, int], int] = {}
    for stratum in sorted(datasets_by_stratum):
        slots = [
            (dataset["dataset_id"], sample_index)
            for dataset in sorted(
                datasets_by_stratum[stratum], key=lambda item: item["dataset_id"]
            )
            for sample_index in range(replicates)
        ]
        orders = [1 if index % 2 == 0 else 2 for index in range(len(slots))]
        rng.shuffle(orders)
        result.update(zip(slots, orders, strict=True))
    return result


def verify_seeded_assignments(
    plan: dict[str, Any], datasets: dict[str, Any], seed: bytes
) -> int:
    baseline_by_dataset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    observed: dict[tuple[str, int, str], dict[str, Any]] = {}
    for assignment in plan["assignments"]:
        identity = (
            assignment["dataset_id"],
            assignment["sample_index"],
            assignment["treatment"],
        )
        if identity in observed:
            fail("plan repeats a seeded assignment identity")
        observed[identity] = assignment
        if assignment["treatment"] == "baseline":
            baseline_by_dataset[assignment["dataset_id"]].append(assignment)
    dataset_ids = {dataset["dataset_id"] for dataset in datasets["datasets"]}
    counts = {
        dataset_id: len(baseline_by_dataset[dataset_id]) for dataset_id in dataset_ids
    }
    if 0 in counts.values() or len(set(counts.values())) != 1:
        fail("plan does not use one balanced replicate count for every dataset")
    replicates = next(iter(counts.values()))
    expected_orders = seeded_baseline_orders(datasets, replicates, seed)
    expected_identities = {
        (dataset_id, sample_index, treatment)
        for dataset_id in dataset_ids
        for sample_index in range(replicates)
        for treatment in TREATMENTS
    }
    if set(observed) != expected_identities:
        fail("plan assignments do not match the seeded dataset inventory")
    for (dataset_id, sample_index, treatment), assignment in observed.items():
        baseline_order = expected_orders[(dataset_id, sample_index)]
        expected_order = (
            baseline_order if treatment == "baseline" else 3 - baseline_order
        )
        if (
            assignment["pair_id"] != f"{dataset_id}:{sample_index:05d}"
            or assignment["order"] != expected_order
        ):
            fail("plan treatment order does not reproduce from the hidden seed")
    return replicates


def validated_input_bundle(
    args: argparse.Namespace,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, str],
]:
    plan = validate_plan(load_json(args.plan))
    datasets = validate_dataset_manifest(load_json(args.datasets))
    baselines = validate_baseline_manifest(load_json(args.baselines))
    canaries = validate_canary_registry(load_json(args.canaries))
    environment = validate_environment(load_json(args.environment))
    validate_dataset_artifacts(datasets, args.datasets, canaries)
    digests = {
        "plan": plan["assignment_digest"],
        "datasets": sha256_multihash(canonical_bytes(datasets)),
        "baselines": sha256_multihash(canonical_bytes(baselines)),
        "canaries": sha256_multihash(canonical_bytes(canaries)),
        "environment": environment["environment_digest"],
    }
    if plan["dataset_manifest_digest"] != digests["datasets"]:
        fail("plan is not bound to the supplied dataset manifest")
    if plan["baseline_manifest_digest"] != digests["baselines"]:
        fail("plan is not bound to the supplied baseline manifest")
    if plan["canary_registry_digest"] != digests["canaries"]:
        fail("plan is not bound to the supplied canary registry")
    if environment["dataset_digest"] != digests["datasets"]:
        fail("environment is not bound to the supplied dataset manifest")
    if {assignment["environment_digest"] for assignment in plan["assignments"]} != {
        digests["environment"]
    }:
        fail("plan is not bound to the supplied environment capture")
    dataset_by_id = {dataset["dataset_id"]: dataset for dataset in datasets["datasets"]}
    baseline_ids = declared_comparator_ids(baselines)
    for assignment in plan["assignments"]:
        dataset = dataset_by_id.get(assignment["dataset_id"])
        if dataset is None or (assignment["task_id"], assignment["stratum"]) != (
            dataset["task_id"],
            dataset["stratum"],
        ):
            fail("plan assignment disagrees with the dataset manifest")
        if assignment["baseline_id"] not in baseline_ids:
            fail("plan assignment uses an undeclared baseline")
    return plan, datasets, baselines, canaries, environment, digests


def bind_events_to_plan(events: Sequence[dict[str, Any]], plan: dict[str, Any]) -> None:
    if any(event["warmup"] for event in events):
        fail("raw event stream contains an assignment not represented by the plan")
    planned = {
        (assignment["pair_id"], assignment["treatment"]): assignment
        for assignment in plan["assignments"]
    }
    observed: set[tuple[str, str]] = set()
    for event in events:
        identity = (event["pair_id"], event["treatment"])
        assignment = planned.get(identity)
        projection = {key: event[key] for key in ASSIGNMENT_KEYS}
        if assignment is None or canonical_bytes(projection) != canonical_bytes(
            assignment
        ):
            fail("raw event stream does not match the committed benchmark plan")
        if event["assignment_digest"] != plan["assignment_digest"]:
            fail("raw event assignment commitment does not match the plan")
        observed.add(identity)
    if observed != set(planned):
        fail("raw event stream does not contain every planned assignment")


def compare(args: argparse.Namespace) -> int:
    if (
        isinstance(args.bootstrap_repetitions, bool)
        or not isinstance(args.bootstrap_repetitions, int)
        or not (100 <= args.bootstrap_repetitions <= 1_000_000)
    ):
        fail("bootstrap repetition count is outside bounds")
    plan, datasets, _baselines, _canaries, _environment, input_digests = (
        validated_input_bundle(args)
    )
    events = load_events(args.events)
    bind_events_to_plan(events, plan)
    pairs = paired(events)
    seed = seed_bytes(args.seed_file)
    seed_commitment = sha256_multihash(seed)
    if plan["seed_commitment"] != seed_commitment:
        fail("hidden seed does not match the committed benchmark plan")
    replicate_count = verify_seeded_assignments(plan, datasets, seed)
    event_seed_commitments = {pair.baseline["seed_commitment"] for pair in pairs}
    if event_seed_commitments != {seed_commitment}:
        fail("hidden seed does not match the raw event commitment")
    for key in (
        "run_id",
        "baseline_id",
        "pins",
        "environment_digest",
        "assignment_digest",
    ):
        if len({canonical_bytes(pair.baseline[key]) for pair in pairs}) != 1:
            fail(f"raw events pool more than one pinned {key}")
    evidence_classes = {pair.baseline["evidence_class"] for pair in pairs}
    strata: dict[str, list[Pair]] = defaultdict(list)
    for pair in pairs:
        strata[pair.baseline["stratum"]].append(pair)
    expected = REQUIRED_STRATA
    order_balanced = all(
        abs(
            sum(pair.baseline["order"] == 1 for pair in values)
            - sum(pair.baseline["order"] == 2 for pair in values)
        )
        <= 1
        for values in strata.values()
    )
    minimum_count = min(map(len, strata.values()))
    independent_task_counts = {
        stratum: len(
            {(pair.baseline["dataset_id"], pair.baseline["task_id"]) for pair in values}
        )
        for stratum, values in strata.items()
    }
    minimum_task_count = min(independent_task_counts.values())
    maximum_variance = max(
        float(event["metrics"]["calibration_variance"])
        for pair in pairs
        for event in (pair.baseline, pair.cigar)
    )
    eligibility_reasons: list[str] = []
    attested, attestation_key_id = verify_attestations(
        events, getattr(args, "attestation_key_file", None)
    )
    if getattr(args, "attestation_key_file", None) is not None and (
        attestation_key_bytes(args.attestation_key_file) == seed
    ):
        fail("attestation and assignment seed material must be independently held")
    if evidence_classes != {"qualification"}:
        eligibility_reasons.append("non_qualification_evidence")
    elif not attested:
        eligibility_reasons.append("missing_independent_evaluator_attestation")
    if set(strata) != expected:
        eligibility_reasons.append("strata_incomplete")
    if minimum_count < 30:
        eligibility_reasons.append("fewer_than_30_post_warm_pairs_per_stratum")
    if minimum_task_count < 30:
        eligibility_reasons.append("fewer_than_30_independent_tasks_per_stratum")
    if maximum_variance >= 0.05:
        eligibility_reasons.append("calibrated_host_variance_not_below_5_percent")
    if not order_balanced:
        eligibility_reasons.append("treatment_order_not_balanced")
    if args.bootstrap_repetitions < 10_000:
        eligibility_reasons.append("fewer_than_10000_bootstrap_repetitions")
    eligible = not eligibility_reasons
    all_rng = deterministic_rng(seed, b"global-bootstrap")
    global_summary = metric_summary(pairs, args.bootstrap_repetitions, all_rng)
    baseline_ids = {pair.baseline["baseline_id"] for pair in pairs}
    if len(baseline_ids) != 1:
        fail("raw events pool more than one comparator")
    strong = bool(
        baseline_ids
        & {
            "transcript-summary",
            "lexical-top-k-rag",
            "semantic-top-k-rag",
            "native-memory",
        }
    )
    global_gates = gates(global_summary, eligible, strong)
    per_stratum: dict[str, Any] = {}
    for stratum in sorted(strata):
        values = strata[stratum]
        stratum_eligible = eligible and len(values) >= 30
        summary = metric_summary(
            values,
            args.bootstrap_repetitions,
            deterministic_rng(seed, stratum.encode("utf-8")),
        )
        per_stratum[stratum] = {
            "metrics": summary,
            "gates": gates(summary, stratum_eligible, strong),
        }
    statuses = list(global_gates.values())
    for stratum in PROTECTED_STRATA:
        if stratum in per_stratum:
            statuses.extend(per_stratum[stratum]["gates"].values())
    if "fail" in statuses:
        decision = "fail"
    elif "insufficient_evidence" in statuses:
        decision = "insufficient_evidence"
    else:
        decision = "pass"
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "input_digest": file_multihash(args.events),
        "input_manifests": input_digests,
        "seed_commitment": seed_commitment,
        "bootstrap_repetitions": args.bootstrap_repetitions,
        "comparison": {
            "comparator_id": next(iter(baseline_ids)),
            "pins": pairs[0].baseline["pins"],
            "evidence_class": pairs[0].baseline["evidence_class"],
        },
        "qualification": {
            "eligible": eligible,
            "reasons": sorted(eligibility_reasons),
            "minimum_post_warm_pairs_per_stratum": minimum_count,
            "replicates_per_task": replicate_count,
            "minimum_independent_tasks_per_stratum": minimum_task_count,
            "independent_tasks_per_stratum": dict(
                sorted(independent_task_counts.items())
            ),
            "maximum_calibrated_host_variance": rounded(maximum_variance),
            "order_balanced": order_balanced,
            "strata": sorted(strata),
            "evaluator_attestation": {
                "verified": attested,
                "key_id": attestation_key_id,
            },
        },
        "global": {"metrics": global_summary, "gates": global_gates},
        "per_stratum": per_stratum,
        "decision": decision,
    }
    report["report_digest"] = sha256_multihash(canonical_bytes(report))
    write_json(args.output, report)
    if args.require_qualification and decision != "pass":
        return 2
    return 0


def validate_dataset_manifest(value: Any) -> dict[str, Any]:
    manifest = exact_keys(value, {"schema_version", "datasets"}, "dataset manifest")
    if manifest["schema_version"] != "cigar.benchmark-datasets.v1" or not isinstance(
        manifest["datasets"], list
    ):
        fail("dataset manifest schema is unsupported")
    if not (len(REQUIRED_STRATA) <= len(manifest["datasets"]) <= 10_000):
        fail("dataset manifest entry count is outside bounds")
    seen: set[str] = set()
    seen_tasks: set[tuple[str, str]] = set()
    for dataset in manifest["datasets"]:
        entry = exact_keys(
            dataset,
            {
                "dataset_id",
                "version",
                "stratum",
                "task_id",
                "fixture",
                "fixture_digest",
                "license",
                "canary_ids",
            },
            "dataset entry",
        )
        dataset_id = identifier(entry["dataset_id"], "dataset id")
        if dataset_id in seen:
            fail("dataset ids are not unique")
        seen.add(dataset_id)
        for key in ("version", "stratum", "task_id", "license"):
            identifier(entry[key], key)
        task_identity = (entry["stratum"], entry["task_id"])
        if task_identity in seen_tasks:
            fail("dataset task identities are not unique within a stratum")
        seen_tasks.add(task_identity)
        if (
            not isinstance(entry["fixture"], str)
            or Path(entry["fixture"]).is_absolute()
            or ".." in Path(entry["fixture"]).parts
        ):
            fail("dataset fixture path is unsafe")
        if not isinstance(entry["fixture_digest"], str) or not MULTIHASH.fullmatch(
            entry["fixture_digest"]
        ):
            fail("dataset fixture digest is invalid")
        if not isinstance(entry["canary_ids"], list) or not all(
            isinstance(value, str) and IDENTIFIER.fullmatch(value)
            for value in entry["canary_ids"]
        ):
            fail("dataset canary ids are invalid")
    if {entry["stratum"] for entry in manifest["datasets"]} != REQUIRED_STRATA:
        fail("dataset manifest does not contain the exact v1 stratum inventory")
    return manifest


def validate_baseline_manifest(value: Any) -> dict[str, Any]:
    manifest = exact_keys(
        value, {"schema_version", "baselines", "ablations"}, "baseline manifest"
    )
    if manifest["schema_version"] != "cigar.benchmark-baselines.v1":
        fail("baseline manifest schema is unsupported")
    if not isinstance(manifest["baselines"], list) or not isinstance(
        manifest["ablations"], list
    ):
        fail("baseline manifest collections are invalid")
    seen: set[str] = set()
    for baseline in manifest["baselines"]:
        entry = exact_keys(
            baseline, {"baseline_id", "class", "description"}, "baseline entry"
        )
        baseline_id = identifier(entry["baseline_id"], "baseline id")
        if baseline_id in seen:
            fail("baseline ids are not unique")
        seen.add(baseline_id)
        identifier(entry["class"], "baseline class")
        if not isinstance(entry["description"], str) or not (
            1 <= len(entry["description"]) <= 256
        ):
            fail("baseline description is outside bounds")
    if not all(
        isinstance(value, str) and IDENTIFIER.fullmatch(value)
        for value in manifest["ablations"]
    ):
        fail("baseline ablation identifiers are invalid")
    required_ablations = {
        "cigar-without-temporal",
        "cigar-without-policy-filter",
        "cigar-without-graph",
        "cigar-without-delta",
        "cigar-without-handoff-packaging",
    }
    if set(manifest["ablations"]) != required_ablations or len(
        manifest["ablations"]
    ) != len(required_ablations):
        fail("baseline manifest does not contain the exact v1 ablation inventory")
    required = {
        "full-transcript-project",
        "fixed-window",
        "native-memory",
        "transcript-summary",
        "lexical-top-k-rag",
        "semantic-top-k-rag",
        "human-oracle",
    }
    if seen != required:
        fail("baseline manifest does not contain the exact v1 baseline inventory")
    return manifest


def declared_comparator_ids(manifest: dict[str, Any]) -> set[str]:
    return {entry["baseline_id"] for entry in manifest["baselines"]} | set(
        manifest["ablations"]
    )


def validate_canary_registry(value: Any) -> dict[str, Any]:
    registry = exact_keys(value, {"schema_version", "canaries"}, "canary registry")
    if registry["schema_version"] != "cigar.canary-registry.v1" or not isinstance(
        registry["canaries"], list
    ):
        fail("canary registry schema is unsupported")
    seen: set[str] = set()
    for canary in registry["canaries"]:
        entry = exact_keys(canary, {"id", "value"}, "canary entry")
        canary_id = identifier(entry["id"], "canary id")
        if canary_id in seen:
            fail("canary ids are not unique")
        seen.add(canary_id)
        if not isinstance(entry["value"], str) or not (
            16 <= len(entry["value"].encode("utf-8")) <= 1024
        ):
            fail("canary value is outside bounds")
    return registry


def validate_dataset_artifacts(
    manifest: dict[str, Any], manifest_path: Path, canary_registry: dict[str, Any]
) -> None:
    canary_values = {
        entry["id"]: entry["value"] for entry in canary_registry["canaries"]
    }
    fixture_root = manifest_path.resolve().parent
    for dataset in manifest["datasets"]:
        fixture_path = (fixture_root / dataset["fixture"]).resolve()
        if (
            fixture_path.parent != fixture_root
            or fixture_path.is_symlink()
            or not fixture_path.is_file()
        ):
            fail("dataset fixture does not resolve to a regular manifest sibling")
        payload = fixture_path.read_bytes()
        if (
            len(payload) > MAX_INPUT_BYTES
            or sha256_multihash(payload) != dataset["fixture_digest"]
        ):
            fail("dataset fixture digest does not match the manifest")
        fixture = load_json(fixture_path)
        fixture = exact_keys(
            fixture,
            {
                "schema_version",
                "dataset_id",
                "fixed_seed",
                "source_revision",
                "task",
                "critical_context",
                "prohibited_context",
                "expected_outcome",
                "canary",
            },
            "dataset fixture",
        )
        if (
            fixture["schema_version"] != "cigar.benchmark-fixture.v1"
            or fixture["dataset_id"] != dataset["dataset_id"]
        ):
            fail("dataset fixture identity does not match the manifest")
        identifier(fixture["dataset_id"], "fixture dataset id")
        identifier(fixture["source_revision"], "fixture source revision")
        if isinstance(fixture["fixed_seed"], bool) or not isinstance(
            fixture["fixed_seed"], int
        ):
            fail("dataset fixture seed is invalid")
        if not isinstance(fixture["task"], str) or not (
            1 <= len(fixture["task"].encode("utf-8")) <= 4096
        ):
            fail("dataset fixture task is outside bounds")
        for key in ("critical_context", "prohibited_context", "expected_outcome"):
            items = fixture[key]
            if (
                not isinstance(items, list)
                or not (1 <= len(items) <= 1024)
                or not all(
                    isinstance(item, str) and 1 <= len(item.encode("utf-8")) <= 1024
                    for item in items
                )
                or len(items) != len(set(items))
            ):
                fail("dataset fixture reference collection is invalid")
        if set(fixture["critical_context"]) & set(fixture["prohibited_context"]):
            fail("dataset fixture critical and prohibited context overlap")
        if any(canary_id not in canary_values for canary_id in dataset["canary_ids"]):
            fail("dataset refers to an unregistered canary")
        if (
            len(dataset["canary_ids"]) != 1
            or fixture.get("canary") != canary_values[dataset["canary_ids"][0]]
        ):
            fail("dataset fixture canary does not match its registry entry")


ENVIRONMENT_KEYS = {
    "schema_version",
    "cpu",
    "memory_bytes",
    "os",
    "filesystem",
    "storage",
    "power_mode",
    "background_load",
    "toolchains",
    "compiler_flags",
    "build_digest",
    "dataset_digest",
    "dataset_shape",
    "index_state",
    "tokenizer",
    "policy",
    "warmup_runs",
    "concurrency",
    "external_latency_included",
    "environment_digest",
}


def validate_environment(value: Any) -> dict[str, Any]:
    environment = exact_keys(value, ENVIRONMENT_KEYS, "environment capture")
    if environment["schema_version"] != ENVIRONMENT_SCHEMA:
        fail("environment capture schema is unsupported")
    environment_digest = environment["environment_digest"]
    if not isinstance(environment_digest, str) or not MULTIHASH.fullmatch(
        environment_digest
    ):
        fail("environment capture digest is invalid")
    unsigned = dict(environment)
    unsigned.pop("environment_digest")
    if sha256_multihash(canonical_bytes(unsigned)) != environment_digest:
        fail("environment capture digest does not match its fields")
    for key in ("build_digest", "dataset_digest"):
        if not isinstance(environment[key], str) or not MULTIHASH.fullmatch(
            environment[key]
        ):
            fail("environment artifact digest is invalid")
    cpu = exact_keys(
        environment["cpu"], {"logical_cores", "machine", "processor"}, "environment CPU"
    )
    if (
        isinstance(cpu["logical_cores"], bool)
        or not isinstance(cpu["logical_cores"], int)
        or cpu["logical_cores"] <= 0
    ):
        fail("environment logical core count is invalid")
    memory = environment["memory_bytes"]
    if memory is not None and (
        isinstance(memory, bool) or not isinstance(memory, int) or memory <= 0
    ):
        fail("environment memory size is invalid")
    operating_system = exact_keys(
        environment["os"], {"system", "release", "version"}, "environment OS"
    )
    toolchains = exact_keys(
        environment["toolchains"],
        {"python", "rustc", "cargo"},
        "environment toolchains",
    )
    compiler_flags = exact_keys(
        environment["compiler_flags"],
        {"RUSTFLAGS", "CFLAGS", "CXXFLAGS"},
        "environment compiler flags",
    )
    for value in [
        cpu["machine"],
        cpu["processor"],
        *operating_system.values(),
        *toolchains.values(),
        *compiler_flags.values(),
    ]:
        if not isinstance(value, str) or len(value.encode("utf-8")) > 8192:
            fail("environment string field is outside bounds")
    for key in (
        "filesystem",
        "storage",
        "power_mode",
        "background_load",
        "index_state",
        "tokenizer",
        "policy",
    ):
        value = environment[key]
        if not isinstance(value, str) or not (1 <= len(value.encode("utf-8")) <= 128):
            fail("environment label is outside bounds")
    shape = exact_keys(
        environment["dataset_shape"],
        {"atoms", "edges", "blob_bytes"},
        "environment dataset shape",
    )
    for value in shape.values():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            fail("environment dataset shape is invalid")
    for key, allow_zero in (("warmup_runs", True), ("concurrency", False)):
        value = environment[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < int(not allow_zero)
        ):
            fail("environment run configuration is invalid")
    if not isinstance(environment["external_latency_included"], bool):
        fail("environment latency classification is invalid")
    return environment


def make_plan(args: argparse.Namespace) -> int:
    manifest = validate_dataset_manifest(load_json(args.datasets))
    baselines = validate_baseline_manifest(load_json(args.baselines))
    canary_registry = validate_canary_registry(load_json(args.canaries))
    validate_dataset_artifacts(manifest, args.datasets, canary_registry)
    seed = seed_bytes(args.seed_file)
    pins = validate_pins(load_json(args.pins))
    environment = validate_environment(load_json(args.environment))
    environment_digest = environment["environment_digest"]
    dataset_manifest_digest = sha256_multihash(canonical_bytes(manifest))
    if environment["dataset_digest"] != dataset_manifest_digest:
        fail("environment is not bound to the supplied dataset manifest")
    if args.baseline_id not in declared_comparator_ids(baselines):
        fail("selected comparator is absent from the baseline manifest")
    if len(manifest["datasets"]) * args.replicates * len(TREATMENTS) > MAX_ASSIGNMENTS:
        fail("requested plan exceeds the assignment limit")
    assignments: list[dict[str, Any]] = []
    run_id = identifier(args.run_id, "run id")
    baseline_orders = seeded_baseline_orders(manifest, args.replicates, seed)
    for dataset in sorted(manifest["datasets"], key=lambda item: item["dataset_id"]):
        for sample_index in range(args.replicates):
            baseline_order = baseline_orders[(dataset["dataset_id"], sample_index)]
            pair_id = f"{dataset['dataset_id']}:{sample_index:05d}"
            base = {
                "run_id": run_id,
                "pair_id": pair_id,
                "dataset_id": dataset["dataset_id"],
                "task_id": dataset["task_id"],
                "stratum": dataset["stratum"],
                "baseline_id": args.baseline_id,
                "sample_index": sample_index,
                "evidence_class": args.evidence_class,
                "pins": pins,
                "environment_digest": environment_digest,
            }
            assignments.extend(
                [
                    {**base, "treatment": "baseline", "order": baseline_order},
                    {**base, "treatment": "cigar", "order": 3 - baseline_order},
                ]
            )
    assignments.sort(
        key=lambda value: (value["dataset_id"], value["sample_index"], value["order"])
    )
    plan: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA,
        "seed_commitment": sha256_multihash(seed),
        "dataset_manifest_digest": dataset_manifest_digest,
        "baseline_manifest_digest": sha256_multihash(canonical_bytes(baselines)),
        "canary_registry_digest": sha256_multihash(canonical_bytes(canary_registry)),
        "assignments": assignments,
    }
    plan["assignment_digest"] = sha256_multihash(canonical_bytes(plan))
    write_json(args.output, plan)
    return 0


def validate_plan(value: Any) -> dict[str, Any]:
    plan = exact_keys(
        value,
        {
            "schema_version",
            "seed_commitment",
            "dataset_manifest_digest",
            "baseline_manifest_digest",
            "canary_registry_digest",
            "assignments",
            "assignment_digest",
        },
        "plan",
    )
    if plan["schema_version"] != PLAN_SCHEMA or not isinstance(
        plan["assignments"], list
    ):
        fail("benchmark plan schema is unsupported")
    supplied = plan["assignment_digest"]
    unsigned = dict(plan)
    unsigned.pop("assignment_digest")
    if (
        not isinstance(supplied, str)
        or sha256_multihash(canonical_bytes(unsigned)) != supplied
    ):
        fail("benchmark assignment digest is invalid")
    if not plan["assignments"] or len(plan["assignments"]) > MAX_ASSIGNMENTS:
        fail("benchmark assignment count is outside bounds")
    if not isinstance(plan["seed_commitment"], str) or not MULTIHASH.fullmatch(
        plan["seed_commitment"]
    ):
        fail("benchmark seed commitment is invalid")
    if not isinstance(plan["dataset_manifest_digest"], str) or not MULTIHASH.fullmatch(
        plan["dataset_manifest_digest"]
    ):
        fail("benchmark dataset digest is invalid")
    if not isinstance(plan["baseline_manifest_digest"], str) or not MULTIHASH.fullmatch(
        plan["baseline_manifest_digest"]
    ):
        fail("benchmark baseline digest is invalid")
    if not isinstance(plan["canary_registry_digest"], str) or not MULTIHASH.fullmatch(
        plan["canary_registry_digest"]
    ):
        fail("benchmark canary registry digest is invalid")
    seen: set[tuple[str, str]] = set()
    pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for assignment in plan["assignments"]:
        entry = exact_keys(assignment, ASSIGNMENT_KEYS, "assignment")
        for key in (
            "run_id",
            "pair_id",
            "dataset_id",
            "task_id",
            "stratum",
            "baseline_id",
        ):
            identifier(entry[key], f"assignment {key}")
        if entry["treatment"] not in TREATMENTS or entry["order"] not in (1, 2):
            fail("assignment treatment or order is invalid")
        if entry["evidence_class"] not in ("harness_smoke", "qualification"):
            fail("assignment evidence class is invalid")
        if (
            isinstance(entry["sample_index"], bool)
            or not isinstance(entry["sample_index"], int)
            or entry["sample_index"] < 0
        ):
            fail("assignment sample index is invalid")
        validate_pins(entry["pins"])
        if not isinstance(entry["environment_digest"], str) or not MULTIHASH.fullmatch(
            entry["environment_digest"]
        ):
            fail("assignment environment digest is invalid")
        identity = (entry["pair_id"], entry["treatment"])
        if identity in seen:
            fail("plan repeats one pair treatment")
        seen.add(identity)
        pairs[entry["pair_id"]].append(entry)
    for values in pairs.values():
        if len(values) != 2 or {entry["treatment"] for entry in values} != set(
            TREATMENTS
        ):
            fail("benchmark plan contains an incomplete pair")
        if {entry["order"] for entry in values} != {1, 2}:
            fail("benchmark plan pair does not counterbalance order")
        baseline = next(entry for entry in values if entry["treatment"] == "baseline")
        cigar = next(entry for entry in values if entry["treatment"] == "cigar")
        for key in ASSIGNMENT_KEYS - {"treatment", "order"}:
            if baseline[key] != cigar[key]:
                fail(f"benchmark plan pair disagrees on {key}")
    return plan


def clean_consumer_environment(home: Path) -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "HOME": str(home),
            "TMPDIR": str(home / "tmp"),
            "CARGO_NET_OFFLINE": "true",
            "UV_OFFLINE": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
        }
    )
    return environment


def consumer_metrics(
    command: Sequence[str],
    assignment: dict[str, Any],
    timeout: float,
    canaries: Sequence[tuple[str, bytes]] = (),
) -> dict[str, Any]:
    with (
        tempfile.TemporaryDirectory(prefix="cigarbench-consumer-") as home_name,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        home = Path(home_name)
        (home / "tmp").mkdir(mode=0o700)
        try:
            completed = subprocess.run(
                command,
                input=canonical_bytes(assignment) + b"\n",
                cwd=home,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
                env=clean_consumer_environment(home),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BenchError("benchmark consumer could not complete") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if stdout.tell() > MAX_CONSUMER_OUTPUT or stderr.tell() > MAX_CONSUMER_OUTPUT:
            fail("benchmark consumer output exceeds the byte limit")
        stdout.seek(0)
        stderr.seek(0)
        payload = stdout.read()
        stderr_payload = stderr.read()
        for canary_id, canary in canaries:
            if canary in payload or canary in stderr_payload:
                fail(f"registered benchmark canary {canary_id} reached consumer output")
        scanned = 0
        for path in sorted(home.rglob("*")):
            if path.is_symlink():
                fail("benchmark consumer created an unsafe temporary artifact")
            if path.is_dir():
                continue
            if not path.is_file():
                fail("benchmark consumer created an unsafe temporary artifact")
            scanned += path.stat().st_size
            if scanned > MAX_INPUT_BYTES:
                fail("benchmark consumer temporary artifacts exceed the byte limit")
            overlap = (
                max((len(canary) for _canary_id, canary in canaries), default=1) - 1
            )
            tail = b""
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    value = tail + chunk
                    for canary_id, canary in canaries:
                        if canary in value:
                            fail(
                                f"registered benchmark canary {canary_id} reached a temporary artifact"
                            )
                    tail = value[-overlap:] if overlap else b""
        if completed.returncode != 0:
            fail("benchmark consumer returned a non-zero status")
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchError(
            "benchmark consumer did not return strict JSON metrics"
        ) from error
    return validate_metrics(value)


def execute_plan(args: argparse.Namespace) -> int:
    plan = validate_plan(load_json(args.plan))
    canary_registry = validate_canary_registry(load_json(args.canaries))
    if (
        sha256_multihash(canonical_bytes(canary_registry))
        != plan["canary_registry_digest"]
    ):
        fail("execution canary registry does not match the committed plan")
    canary_values = [
        (entry["id"], entry["value"].encode("utf-8"))
        for entry in canary_registry["canaries"]
    ]
    if not args.consumer:
        fail("an explicit consumer command is required")
    timeout = finite_number(args.timeout, "consumer timeout")
    if timeout <= 0.0 or timeout > 86_400.0:
        fail("consumer timeout is outside bounds")
    consumer_digest = file_multihash(args.consumer_artifact, MAX_CONSUMER_ARTIFACT)
    if {
        assignment["pins"]["consumer_artifact"] for assignment in plan["assignments"]
    } != {consumer_digest}:
        fail("consumer artifact does not match the committed plan pin")
    artifact = args.consumer_artifact.resolve()
    executable_name = shutil.which(args.consumer[0]) or args.consumer[0]
    executable = Path(executable_name)
    direct = (
        executable.exists()
        and executable.is_file()
        and not executable.is_symlink()
        and executable.resolve() == artifact
    )
    interpreted = (
        executable.exists()
        and executable.resolve() == Path(sys.executable).resolve()
        and len(args.consumer) >= 2
        and Path(args.consumer[1]).exists()
        and not Path(args.consumer[1]).is_symlink()
        and Path(args.consumer[1]).resolve() == artifact
    )
    if not direct and not interpreted:
        fail("consumer artifact is not the executed program")
    consumer_command = list(args.consumer)
    if direct:
        consumer_command[0] = str(artifact)
    else:
        consumer_command[0] = str(executable.resolve())
        consumer_command[1] = str(artifact)
    events: list[dict[str, Any]] = []
    for assignment in plan["assignments"]:
        metrics = consumer_metrics(consumer_command, assignment, timeout, canary_values)
        event = event_with_id(
            {
                "schema_version": SCHEMA,
                **assignment,
                "warmup": False,
                "metrics": metrics,
                "assignment_digest": plan["assignment_digest"],
                "seed_commitment": plan["seed_commitment"],
                "attestation": None,
            }
        )
        events.append(event)
    write_events(args.output, events)
    return 0


def capture_command(command: list[str]) -> str:
    environment = dict(os.environ)
    environment.pop("CIGAR_EVIDENCE_DIR", None)
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"
        output.seek(0)
        return (
            output.read(8193).decode("utf-8", errors="replace")[:8192].strip()
            or "unavailable"
        )


def capture_environment(args: argparse.Namespace) -> int:
    for value, label in (
        (args.build_digest, "build"),
        (args.dataset_digest, "dataset"),
    ):
        if not MULTIHASH.fullmatch(value):
            fail(f"{label} digest is not a sha256 multihash")
    for value, label in (
        (args.atoms, "atom count"),
        (args.edges, "edge count"),
        (args.blob_bytes, "blob bytes"),
        (args.warmup_runs, "warmup runs"),
        (args.concurrency, "concurrency"),
    ):
        if value < 0 or (label == "concurrency" and value == 0):
            fail(f"{label} is outside bounds")
    for value in (
        args.filesystem,
        args.storage,
        args.power_mode,
        args.background_load,
        args.index_state,
        args.tokenizer,
        args.policy,
    ):
        if not isinstance(value, str) or not (1 <= len(value) <= 128):
            fail("environment label is outside bounds")
    compiler_flags = {
        key: os.environ.get(key, "") for key in ("RUSTFLAGS", "CFLAGS", "CXXFLAGS")
    }
    if any(len(value.encode("utf-8")) > 8192 for value in compiler_flags.values()):
        fail("compiler flags exceed the environment capture bound")
    environment: dict[str, Any] = {
        "schema_version": ENVIRONMENT_SCHEMA,
        "cpu": {
            "logical_cores": os.cpu_count() or 1,
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "memory_bytes": None,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
        },
        "filesystem": args.filesystem,
        "storage": args.storage,
        "power_mode": args.power_mode,
        "background_load": args.background_load,
        "toolchains": {
            "python": platform.python_version(),
            "rustc": capture_command(["rustc", "-vV"]),
            "cargo": capture_command(["cargo", "--version"]),
        },
        "compiler_flags": compiler_flags,
        "build_digest": args.build_digest,
        "dataset_digest": args.dataset_digest,
        "dataset_shape": {
            "atoms": args.atoms,
            "edges": args.edges,
            "blob_bytes": args.blob_bytes,
        },
        "index_state": args.index_state,
        "tokenizer": args.tokenizer,
        "policy": args.policy,
        "warmup_runs": args.warmup_runs,
        "concurrency": args.concurrency,
        "external_latency_included": False,
    }
    if hasattr(os, "sysconf"):
        try:
            environment["memory_bytes"] = int(
                os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
            )
        except (OSError, ValueError):
            pass
    environment["environment_digest"] = sha256_multihash(canonical_bytes(environment))
    validate_environment(environment)
    write_json(args.output, environment)
    return 0


def print_manifest_digest(args: argparse.Namespace) -> int:
    validators = {
        "datasets": validate_dataset_manifest,
        "baselines": validate_baseline_manifest,
        "canaries": validate_canary_registry,
    }
    value = validators[args.kind](load_json(args.input))
    print(sha256_multihash(canonical_bytes(value)))
    return 0


def replay_report(args: argparse.Namespace) -> int:
    expected = load_json(args.report)
    expected = exact_keys(
        expected,
        {
            "schema_version",
            "input_digest",
            "input_manifests",
            "seed_commitment",
            "bootstrap_repetitions",
            "comparison",
            "qualification",
            "global",
            "per_stratum",
            "decision",
            "report_digest",
        },
        "benchmark report",
    )
    if expected["schema_version"] != REPORT_SCHEMA:
        fail("benchmark report schema is unsupported")
    repetitions = expected["bootstrap_repetitions"]
    if (
        isinstance(repetitions, bool)
        or not isinstance(repetitions, int)
        or not (100 <= repetitions <= 1_000_000)
    ):
        fail("benchmark report bootstrap count is invalid")
    unsigned = dict(expected)
    supplied_digest = unsigned.pop("report_digest")
    if (
        not isinstance(supplied_digest, str)
        or sha256_multihash(canonical_bytes(unsigned)) != supplied_digest
    ):
        fail("benchmark report digest is invalid")
    with tempfile.TemporaryDirectory(prefix="cigarbench-replay-") as directory:
        temporary = Path(directory) / "report.json"
        replay_args = argparse.Namespace(
            events=args.events,
            plan=args.plan,
            datasets=args.datasets,
            baselines=args.baselines,
            canaries=args.canaries,
            environment=args.environment,
            seed_file=args.seed_file,
            attestation_key_file=args.attestation_key_file,
            bootstrap_repetitions=repetitions,
            output=temporary,
            require_qualification=False,
        )
        compare(replay_args)
        actual = load_json(temporary)
    if canonical_bytes(actual) != canonical_bytes(expected):
        fail("report does not reproduce exactly from raw events")
    return 0


def scan_canaries(args: argparse.Namespace) -> int:
    registry = load_json(args.registry, 1024 * 1024)
    if not isinstance(registry, dict) or set(registry) != {
        "schema_version",
        "canaries",
    }:
        fail("canary registry schema is invalid")
    if registry["schema_version"] != "cigar.canary-registry.v1" or not isinstance(
        registry["canaries"], list
    ):
        fail("canary registry version is unsupported")
    needles: list[tuple[str, bytes]] = []
    for item in registry["canaries"]:
        if not isinstance(item, dict) or set(item) != {"id", "value"}:
            fail("canary registry entry is invalid")
        canary_id = identifier(item["id"], "canary id")
        if not isinstance(item["value"], str) or not (
            16 <= len(item["value"].encode("utf-8")) <= 1024
        ):
            fail("canary value is outside bounds")
        needles.append((canary_id, item["value"].encode("utf-8")))
    scanned = 0
    file_count = 0
    overlap = max((len(needle) for _canary_id, needle in needles), default=1) - 1
    for target in args.target:
        paths = [target]
        if target.is_dir():
            paths = sorted(
                path
                for path in target.rglob("*")
                if path.is_file() or path.is_symlink()
            )
        for path in paths:
            if path.is_symlink() or not path.is_file():
                fail("canary scan target contains an unsafe file")
            file_count += 1
            if file_count > 100_000:
                fail("canary scan file count exceeds the limit")
            size = path.stat().st_size
            scanned += size
            if scanned > args.maximum_bytes:
                fail("canary scan exceeds the aggregate byte limit")
            tail = b""
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    payload = tail + chunk
                    for canary_id, needle in needles:
                        if needle in payload:
                            fail(f"registered canary {canary_id} was detected")
                    tail = payload[-overlap:] if overlap else b""
    return 0


def guard_profiles(args: argparse.Namespace) -> int:
    repository = args.repository.resolve()
    benches = (repository / "benches").resolve()
    for candidate in benches.rglob("*"):
        if (
            candidate.is_file()
            and candidate.name in {"config", "config.toml"}
            and candidate.parent.name == ".cargo"
        ):
            fail("benchmark-local Cargo configuration can affect default profiles")
    manifest = (repository / "Cargo.toml").read_text(encoding="utf-8")
    section = ""
    for raw in manifest.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
        if (
            any(
                section == profile or section.startswith(profile + ".")
                for profile in ("profile.dev", "profile.release", "profile.test")
            )
            and "cigarbench" in line.lower()
        ):
            fail("benchmark configuration leaked into a default Cargo profile")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external evidence workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    commands = result.add_subparsers(dest="command", required=True)

    manifest_digest = commands.add_parser(
        "manifest-digest", help="print a validated canonical manifest digest"
    )
    manifest_digest.add_argument(
        "--kind", choices=("datasets", "baselines", "canaries"), required=True
    )
    manifest_digest.add_argument("--input", type=Path, required=True)
    manifest_digest.set_defaults(function=print_manifest_digest)

    environment = commands.add_parser(
        "environment", help="capture a benchmark environment"
    )
    environment.add_argument("--output", type=Path, required=True)
    environment.add_argument("--build-digest", required=True)
    environment.add_argument("--dataset-digest", required=True)
    environment.add_argument("--filesystem", default="unknown")
    environment.add_argument("--storage", default="unknown")
    environment.add_argument("--power-mode", default="unknown")
    environment.add_argument("--background-load", default="controlled")
    environment.add_argument("--atoms", type=int, default=0)
    environment.add_argument("--edges", type=int, default=0)
    environment.add_argument("--blob-bytes", type=int, default=0)
    environment.add_argument("--index-state", default="cold")
    environment.add_argument("--tokenizer", default="cigar-byte-v1")
    environment.add_argument("--policy", default="cigar-policy-v1")
    environment.add_argument("--warmup-runs", type=int, default=1)
    environment.add_argument("--concurrency", type=int, default=1)
    environment.set_defaults(function=capture_environment)

    plan = commands.add_parser(
        "plan", help="create a paired randomized hidden-seed plan"
    )
    plan.add_argument("--datasets", type=Path, required=True)
    plan.add_argument("--baselines", type=Path, required=True)
    plan.add_argument("--canaries", type=Path, required=True)
    plan.add_argument("--pins", type=Path, required=True)
    plan.add_argument("--environment", type=Path, required=True)
    plan.add_argument("--seed-file", type=Path, required=True)
    plan.add_argument("--run-id", required=True)
    plan.add_argument("--baseline-id", required=True)
    plan.add_argument("--replicates", type=int, required=True)
    plan.add_argument(
        "--evidence-class", choices=("harness_smoke", "qualification"), required=True
    )
    plan.add_argument("--output", type=Path, required=True)
    plan.set_defaults(function=make_plan)

    execute = commands.add_parser(
        "execute", help="execute a plan through an installed consumer"
    )
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument("--canaries", type=Path, required=True)
    execute.add_argument("--consumer-artifact", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--timeout", type=float, default=300.0)
    execute.add_argument("consumer", nargs=argparse.REMAINDER)
    execute.set_defaults(function=execute_plan)

    comparison = commands.add_parser("compare", help="compare paired raw events")
    comparison.add_argument("--events", type=Path, required=True)
    comparison.add_argument("--plan", type=Path, required=True)
    comparison.add_argument("--datasets", type=Path, required=True)
    comparison.add_argument("--baselines", type=Path, required=True)
    comparison.add_argument("--canaries", type=Path, required=True)
    comparison.add_argument("--environment", type=Path, required=True)
    comparison.add_argument("--seed-file", type=Path, required=True)
    comparison.add_argument("--attestation-key-file", type=Path)
    comparison.add_argument("--bootstrap-repetitions", type=int, default=10_000)
    comparison.add_argument("--output", type=Path, required=True)
    comparison.add_argument("--require-qualification", action="store_true")
    comparison.set_defaults(function=compare)

    replay = commands.add_parser("replay", help="reproduce a report byte-for-byte")
    replay.add_argument("--events", type=Path, required=True)
    replay.add_argument("--report", type=Path, required=True)
    replay.add_argument("--plan", type=Path, required=True)
    replay.add_argument("--datasets", type=Path, required=True)
    replay.add_argument("--baselines", type=Path, required=True)
    replay.add_argument("--canaries", type=Path, required=True)
    replay.add_argument("--environment", type=Path, required=True)
    replay.add_argument("--seed-file", type=Path, required=True)
    replay.add_argument("--attestation-key-file", type=Path)
    replay.set_defaults(function=replay_report)

    attest = commands.add_parser(
        "attest", help="bind independently evaluated qualification events"
    )
    attest.add_argument("--events", type=Path, required=True)
    attest.add_argument("--plan", type=Path, required=True)
    attest.add_argument("--datasets", type=Path, required=True)
    attest.add_argument("--baselines", type=Path, required=True)
    attest.add_argument("--canaries", type=Path, required=True)
    attest.add_argument("--environment", type=Path, required=True)
    attest.add_argument("--seed-file", type=Path, required=True)
    attest.add_argument("--key-file", type=Path, required=True)
    attest.add_argument("--key-id", required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.set_defaults(function=attest_events)

    canary = commands.add_parser(
        "canary-scan", help="scan evidence for registered canaries"
    )
    canary.add_argument("--registry", type=Path, required=True)
    canary.add_argument("--maximum-bytes", type=int, default=1024 * 1024 * 1024)
    canary.add_argument("target", type=Path, nargs="+")
    canary.set_defaults(function=scan_canaries)

    guard = commands.add_parser(
        "guard-profile", help="verify benchmark settings cannot affect normal builds"
    )
    guard.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[2]
    )
    guard.set_defaults(function=guard_profiles)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if (
        getattr(args, "bootstrap_repetitions", 100) < 100
        or getattr(args, "bootstrap_repetitions", 100) > 1_000_000
    ):
        print(
            "cigarbench: bootstrap repetition count is outside bounds", file=sys.stderr
        )
        return 2
    evidence: EvidenceExecution | None = None
    try:
        evidence = EvidenceExecution.open(args)
        status = int(args.function(args))
        if status == 0:
            evidence.publish(args.command)
        return status
    except BenchError as error:
        print(f"cigarbench: {error}", file=sys.stderr)
        return 2
    except (EvidenceWorkspaceError, OSError):
        print("cigarbench: local artifact operation failed", file=sys.stderr)
        return 2
    finally:
        if evidence is not None:
            evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
