"""Offline evidence envelope and paired analysis for context SDK evaluations.

No provider calls, executable loading, or unverified summary import. Artifacts
are regular files inside the explicitly supplied evidence directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path


IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_OBSERVATIONS = 1_000_000
CLASSES = {
    "invariant",
    "evidence-retention",
    "task-outcome",
    "answer-replay",
    "model-output",
    "performance",
}
ROLES = {
    "plan",
    "tasks",
    "observations",
    "corpus",
    "oracle",
    "harness",
    "evaluator",
    "package",
    "worker",
    "source",
    "model",
}
RATIO_UNITS = {"ratio", "tokens-per-fact", "tokens-per-task", "operations-per-second"}


class EvaluationError(ValueError):
    """An incomplete or inconsistent evidence set cannot support a comparison."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvaluationError(message)


def record(value: object, keys: set[str], label: str) -> dict:
    require(type(value) is dict and set(value) == keys, f"invalid {label} fields")
    return value


def identifier(value: object) -> bool:
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None


def number(value: object) -> bool:
    return type(value) in (int, float) and 0 <= value <= 10**15 and math.isfinite(value)


def member(value: object, options: set[str]) -> bool:
    return type(value) is str and value in options


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def decode(data: bytes) -> object:
    require(len(data) <= MAX_JSON_BYTES, "JSON byte limit exceeded")
    try:
        return json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=lambda _: invalid_constant(),
            parse_float=finite_float,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise EvaluationError("invalid evidence JSON") from error


def invalid_constant() -> None:
    raise EvaluationError("non-finite JSON number")


def finite_float(value: str) -> float:
    result = float(value)
    require(math.isfinite(result), "non-finite JSON number")
    return result


def encoded(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def artifact_path(root: Path, name: object) -> Path:
    require(type(name) is str and 0 < len(name) <= 512, "invalid artifact path")
    pieces = name.split("/")
    require(
        all(
            part and part not in {".", ".."} and "\\" not in part and ":" not in part
            for part in pieces
        ),
        "artifact path must remain inside evidence directory",
    )
    path = root
    for part in pieces:
        path = path / part
        require(not path.is_symlink(), "artifact symlinks are not allowed")
    require(
        path.is_file() and path.resolve().is_relative_to(root),
        "artifact is not a contained regular file",
    )
    return path


def verify_artifacts(root: Path, values: object) -> dict[str, tuple[dict, Path]]:
    require(
        type(values) is list and 6 <= len(values) <= 256, "invalid artifact inventory"
    )
    artifacts = {}
    paths = set()
    for value in values:
        item = record(value, {"id", "role", "path", "sha256", "bytes"}, "artifact")
        require(
            identifier(item["id"]) and item["id"] not in artifacts,
            "duplicate or invalid artifact identity",
        )
        require(member(item["role"], ROLES), "invalid artifact role")
        require(
            type(item["sha256"]) is str
            and DIGEST.fullmatch(item["sha256"]) is not None,
            "invalid artifact digest",
        )
        require(
            type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_ARTIFACT_BYTES,
            "invalid artifact size",
        )
        path = artifact_path(root, item["path"])
        require(path not in paths, "duplicate artifact path")
        paths.add(path)
        before = path.stat()
        require(before.st_size == item["bytes"], "artifact size mismatch")
        require(file_digest(path) == item["sha256"], "artifact digest mismatch")
        after = path.stat()
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "artifact changed during verification",
        )
        artifacts[item["id"]] = (item, path)
    return artifacts


def input_artifact(artifacts: dict, name: object, role: str) -> Path:
    require(
        type(name) is str and name in artifacts and artifacts[name][0]["role"] == role,
        f"missing {role} artifact binding",
    )
    path = artifacts[name][1]
    require(path.stat().st_size <= MAX_JSON_BYTES, "input byte limit exceeded")
    return path


def validate_plan(value: object, artifacts: dict) -> dict:
    plan = record(
        value,
        {
            "schema",
            "id",
            "evidence_class",
            "oracle_kind",
            "model_mode",
            "cluster_unit",
            "seed",
            "baseline",
            "candidate",
            "cohorts",
            "treatments",
            "metrics",
            "inputs",
            "conditions",
        },
        "plan",
    )
    require(
        plan["schema"] == "cigar.context-evaluation-plan.v1" and identifier(plan["id"]),
        "invalid plan identity",
    )
    require(member(plan["evidence_class"], CLASSES), "invalid evidence class")
    require(
        member(
            plan["oracle_kind"], {"authored", "executable", "independently-adjudicated"}
        ),
        "invalid oracle origin",
    )
    require(
        member(plan["model_mode"], {"none", "recorded", "local"}),
        "provider execution is outside this evaluation contract",
    )
    require(
        member(plan["cluster_unit"], {"task-cluster", "process-cohort"}),
        "invalid sampling unit",
    )
    require(
        type(plan["seed"]) is int and 0 <= plan["seed"] < 2**32,
        "invalid resampling seed",
    )
    if plan["evidence_class"] == "model-output":
        require(
            plan["oracle_kind"] == "independently-adjudicated"
            and plan["model_mode"] != "none",
            "model-output claims require independent labels and identified model outputs",
        )
        require(
            any(item[0]["role"] == "model" for item in artifacts.values()),
            "missing model identity artifact",
        )
    if plan["evidence_class"] == "answer-replay":
        require(
            plan["model_mode"] == "recorded",
            "answer replay must identify recorded outputs",
        )
    require(
        type(plan["conditions"]) is dict and bool(plan["conditions"]),
        "study conditions must be explicit",
    )
    inputs = record(plan["inputs"], {"corpus", "oracle", "harness"}, "plan inputs")
    for role, binding in inputs.items():
        input_artifact(artifacts, binding, role)
    cohorts = plan["cohorts"]
    require(
        type(cohorts) is list
        and 1 <= len(cohorts) <= 1000
        and all(identifier(c) for c in cohorts)
        and len(set(cohorts)) == len(cohorts),
        "invalid cohorts",
    )
    treatments = plan["treatments"]
    require(
        type(treatments) is list and 2 <= len(treatments) <= 16, "invalid treatments"
    )
    treatment_ids = set()
    for value in treatments:
        item = record(
            value,
            {"id", "version", "source_commit", "artifacts", "settings"},
            "treatment",
        )
        require(
            identifier(item["id"]) and item["id"] not in treatment_ids,
            "duplicate treatment",
        )
        treatment_ids.add(item["id"])
        require(
            type(item["version"]) is str and 0 < len(item["version"]) <= 64,
            "invalid treatment version",
        )
        require(
            type(item["source_commit"]) is str
            and COMMIT.fullmatch(item["source_commit"]),
            "invalid source commit",
        )
        bindings = item["artifacts"]
        require(
            type(bindings) is list
            and bindings
            and all(type(b) is str and b in artifacts for b in bindings),
            "missing treatment artifact",
        )
        require(len(set(bindings)) == len(bindings), "duplicate treatment artifact")
        require(
            any(
                artifacts[b][0]["role"] in {"package", "worker", "source"}
                for b in bindings
            ),
            "treatment lacks executable or source identity",
        )
        require(type(item["settings"]) is dict, "treatment settings must be explicit")
    require(
        member(plan["baseline"], treatment_ids)
        and member(plan["candidate"], treatment_ids)
        and plan["baseline"] != plan["candidate"],
        "invalid paired treatment identities",
    )
    metrics = plan["metrics"]
    require(type(metrics) is list and 1 <= len(metrics) <= 128, "invalid metrics")
    metric_ids = set()
    for value in metrics:
        item = record(value, {"id", "unit", "aggregation", "direction"}, "metric")
        require(
            identifier(item["id"]) and item["id"] not in metric_ids, "duplicate metric"
        )
        metric_ids.add(item["id"])
        require(
            member(
                item["aggregation"],
                {"mean", "median", "p95", "p99", "max", "sum", "ratio"},
            ),
            "invalid aggregation",
        )
        require(
            member(
                item["unit"], {"milliseconds", "bytes", "tokens", "count"} | RATIO_UNITS
            ),
            "invalid metric unit",
        )
        require(
            (item["aggregation"] == "ratio") == (item["unit"] in RATIO_UNITS),
            "ratio unit/aggregation mismatch",
        )
        require(
            member(item["direction"], {"higher", "lower", "descriptive"}),
            "invalid metric direction",
        )
    return plan


def validate_tasks(value: object, metric_ids: set[str]) -> dict:
    document = record(value, {"schema", "tasks"}, "task inventory")
    require(
        document["schema"] == "cigar.context-evaluation-tasks.v1", "invalid task schema"
    )
    require(
        type(document["tasks"]) is list and 1 <= len(document["tasks"]) <= 100_000,
        "invalid tasks",
    )
    tasks = {}
    for value in document["tasks"]:
        item = record(
            value,
            {"id", "sha256", "definition", "cluster", "stratum", "metrics"},
            "task",
        )
        require(identifier(item["id"]) and item["id"] not in tasks, "duplicate task")
        require(
            type(item["sha256"]) is str and DIGEST.fullmatch(item["sha256"]),
            "invalid task digest",
        )
        require(
            type(item["definition"]) is dict and bool(item["definition"]),
            "missing task definition",
        )
        require(
            hashlib.sha256(encoded(item["definition"])).hexdigest() == item["sha256"],
            "task digest mismatch",
        )
        require(
            identifier(item["cluster"]) and identifier(item["stratum"]),
            "invalid task cluster or stratum",
        )
        require(
            type(item["metrics"]) is list
            and item["metrics"]
            and all(type(m) is str and m in metric_ids for m in item["metrics"])
            and len(set(item["metrics"])) == len(item["metrics"]),
            "invalid task metrics",
        )
        tasks[item["id"]] = item
    require(
        set().union(*(set(task["metrics"]) for task in tasks.values())) == metric_ids,
        "unassigned metric",
    )
    return tasks


def read_observations(path: Path, plan: dict, tasks: dict) -> list[dict]:
    metrics = {item["id"]: item for item in plan["metrics"]}
    treatments = {item["id"] for item in plan["treatments"]}
    cohorts = set(plan["cohorts"])
    seen = set()
    exposures = defaultdict(set)
    rows = []
    for line in path.read_bytes().splitlines():
        require(
            line.strip() and len(rows) < MAX_OBSERVATIONS, "invalid observation stream"
        )
        row = record(
            decode(line),
            {
                "schema",
                "task",
                "treatment",
                "cohort",
                "replicate",
                "metric",
                "status",
                "value",
                "numerator",
                "denominator",
            },
            "observation",
        )
        require(
            row["schema"] == "cigar.context-observation.v1",
            "invalid observation schema",
        )
        require(type(row["task"]) is str and row["task"] in tasks, "unknown task")
        require(
            type(row["metric"]) is str
            and row["metric"] in tasks[row["task"]]["metrics"],
            "unknown task metric",
        )
        require(
            type(row["treatment"]) is str and row["treatment"] in treatments,
            "unknown treatment",
        )
        require(
            type(row["cohort"]) is str and row["cohort"] in cohorts, "unknown cohort"
        )
        require(
            type(row["replicate"]) is int and 0 <= row["replicate"] < MAX_OBSERVATIONS,
            "invalid replicate",
        )
        key = (
            row["task"],
            row["metric"],
            row["cohort"],
            row["replicate"],
            row["treatment"],
        )
        require(key not in seen, "duplicate observation")
        seen.add(key)
        exposures[(row["task"], row["metric"], row["cohort"], row["treatment"])].add(
            row["replicate"]
        )
        require(
            member(row["status"], {"ok", "unsupported", "failed"}),
            "invalid observation status",
        )
        if row["status"] != "ok":
            require(
                all(row[key] is None for key in ("value", "numerator", "denominator")),
                "unsuccessful observations cannot supply measurements",
            )
        elif metrics[row["metric"]]["aggregation"] == "ratio":
            require(
                row["value"] is None
                and number(row["numerator"])
                and number(row["denominator"])
                and (
                    metrics[row["metric"]]["unit"] != "ratio"
                    or row["numerator"] <= row["denominator"]
                ),
                "invalid ratio observation",
            )
        else:
            require(
                number(row["value"])
                and row["numerator"] is None
                and row["denominator"] is None,
                "invalid sample observation",
            )
        rows.append(row)
    for task in tasks.values():
        for metric in task["metrics"]:
            for cohort in cohorts:
                sets = [
                    exposures[(task["id"], metric, cohort, treatment)]
                    for treatment in treatments
                ]
                require(
                    sets[0] and all(item == sets[0] for item in sets),
                    "missing or unpaired observations; record unsupported/failed outcomes explicitly",
                )
    return rows


def quantile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percentile) - 1)]


def reduce_rows(rows: list[dict], aggregation: str) -> float | None:
    if any(row["status"] != "ok" for row in rows):
        return None
    if aggregation == "ratio":
        denominator = sum(row["denominator"] for row in rows)
        return (
            sum(row["numerator"] for row in rows) / denominator if denominator else None
        )
    values = [row["value"] for row in rows]
    if not values:
        return None
    if aggregation == "median":
        return statistics.median(values)
    if aggregation == "max":
        return max(values)
    if aggregation in {"p95", "p99"}:
        return quantile(values, 0.95 if aggregation == "p95" else 0.99)
    return sum(values) if aggregation == "sum" else statistics.mean(values)


def confidence_interval(values: list[float], seed: int) -> list[float] | None:
    # Small cohorts remain descriptive; repeats never increase cluster count.
    if len(values) < 8:
        return None
    rng = random.Random(seed)
    means = [statistics.mean(rng.choices(values, k=len(values))) for _ in range(2000)]
    return [quantile(means, 0.025), quantile(means, 0.975)]


def summarize(plan: dict, tasks: dict, rows: list[dict]) -> dict:
    result = {}
    for metric in plan["metrics"]:
        selected = [row for row in rows if row["metric"] == metric["id"]]
        if not selected:
            continue
        groups = defaultdict(list)
        for row in selected:
            cluster = (
                row["cohort"]
                if plan["cluster_unit"] == "process-cohort"
                else tasks[row["task"]]["cluster"]
            )
            groups[(row["treatment"], cluster)].append(row)
        values = {
            key: reduce_rows(group, metric["aggregation"])
            for key, group in groups.items()
        }
        by_treatment = {}
        for treatment in plan["treatments"]:
            group = [row for row in selected if row["treatment"] == treatment["id"]]
            counts = Counter(row["status"] for row in group)
            by_treatment[treatment["id"]] = {
                "observations": len(group),
                "status_counts": {
                    status: counts[status] for status in ("ok", "unsupported", "failed")
                },
                "value": reduce_rows(group, metric["aggregation"]),
                "clusters": sum(key[0] == treatment["id"] for key in groups),
            }
        baseline, candidate = plan["baseline"], plan["candidate"]
        clusters = sorted(key[1] for key in groups if key[0] == baseline)
        complete = all(
            values[(baseline, c)] is not None and values[(candidate, c)] is not None
            for c in clusters
        )
        differences = (
            [values[(candidate, c)] - values[(baseline, c)] for c in clusters]
            if complete
            else []
        )
        relative = (
            [(values[(candidate, c)] / values[(baseline, c)]) - 1 for c in clusters]
            if complete and all(values[(baseline, c)] != 0 for c in clusters)
            else []
        )
        result[metric["id"]] = {
            "unit": metric["unit"],
            "aggregation": metric["aggregation"],
            "direction": metric["direction"],
            "treatments": by_treatment,
            "paired": {
                "status": "complete" if complete else "incomplete",
                "cluster_unit": plan["cluster_unit"],
                "clusters": len(clusters),
                "mean_difference": statistics.mean(differences)
                if differences
                else None,
                "difference_ci95": confidence_interval(differences, plan["seed"]),
                "mean_relative_change": statistics.mean(relative) if relative else None,
                "relative_change_ci95": confidence_interval(relative, plan["seed"]),
            },
        }
    return result


def evaluate(directory: Path) -> dict:
    root = directory.resolve(strict=True)
    manifest_path = artifact_path(root, "manifest.json")
    require(
        manifest_path.stat().st_size <= MAX_JSON_BYTES, "manifest byte limit exceeded"
    )
    manifest_bytes = manifest_path.read_bytes()
    manifest = record(
        decode(manifest_bytes),
        {"schema", "plan", "tasks", "observations", "evaluator", "artifacts"},
        "manifest",
    )
    require(
        manifest["schema"] == "cigar.context-evaluation-manifest.v1",
        "invalid manifest schema",
    )
    artifacts = verify_artifacts(root, manifest["artifacts"])
    input_artifact(artifacts, manifest["evaluator"], "evaluator")
    evaluator_digest = artifacts[manifest["evaluator"]][0]["sha256"]
    require(
        evaluator_digest == file_digest(Path(__file__)),
        "use the evaluator version bound to this evidence",
    )
    plan = validate_plan(
        decode(input_artifact(artifacts, manifest["plan"], "plan").read_bytes()),
        artifacts,
    )
    tasks = validate_tasks(
        decode(input_artifact(artifacts, manifest["tasks"], "tasks").read_bytes()),
        {metric["id"] for metric in plan["metrics"]},
    )
    require(
        sum(len(task["metrics"]) for task in tasks.values())
        * len(plan["cohorts"])
        * len(plan["treatments"])
        <= MAX_OBSERVATIONS,
        "planned exposure count exceeds observation limit",
    )
    strata = sorted({task["stratum"] for task in tasks.values()})
    require(len(strata) <= 128, "stratum limit exceeded")
    rows = read_observations(
        input_artifact(artifacts, manifest["observations"], "observations"), plan, tasks
    )
    metrics = summarize(plan, tasks, rows)
    # Recheck bytes after analysis; callers must keep the directory immutable for
    # the duration of verification. This is an integrity check, not a signature.
    verify_artifacts(root, manifest["artifacts"])
    require(
        evaluator_digest == file_digest(Path(__file__)),
        "evaluator changed during verification",
    )
    return {
        "schema": "cigar.context-evaluation-result.v1",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "evaluator_sha256": evaluator_digest,
        "study_id": plan["id"],
        "evidence_class": plan["evidence_class"],
        "oracle_kind": plan["oracle_kind"],
        "model_mode": plan["model_mode"],
        "baseline": plan["baseline"],
        "candidate": plan["candidate"],
        "tasks": len(tasks),
        "observations": len(rows),
        "metrics": metrics,
        "strata": {
            stratum: summarize(
                plan,
                tasks,
                [row for row in rows if tasks[row["task"]]["stratum"] == stratum],
            )
            for stratum in strata
        },
        "limitations": [
            "Digests commit to supplied bytes; they do not authenticate the producer or establish oracle independence.",
            "Declared evidence class and sampling independence require study review.",
            "Paired intervals resample whole declared clusters, never repeated calls; fewer than eight clusters are descriptive.",
            "Unsupported, failed or zero-denominator pairs make the paired result incomplete; none are silently dropped.",
            "Performance and authored replay cannot establish model-output accuracy or hallucination prevalence.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory",
        type=Path,
        help="directory containing manifest.json and its bound artifacts",
    )
    parser.add_argument(
        "--output", type=Path, help="new result file; existing files are never replaced"
    )
    args = parser.parse_args()
    try:
        result = evaluate(args.directory)
        payload = encoded(result)
        if args.output:
            with args.output.open("xb") as stream:
                stream.write(payload)
        else:
            print(payload.decode(), end="")
    except (EvaluationError, OSError) as error:
        raise SystemExit(f"context evaluation failed: {error}") from error


if __name__ == "__main__":
    main()
