"""Bind shared_views raw measurements to exact wheels and recompute performance.

This does not establish efficacy or independent-process broker qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import shutil
import zipfile
from email.parser import BytesParser
from pathlib import Path

from evaluation import EvaluationError, decode, encoded, evaluate, file_digest, require
import evaluation


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "benchmarks/shared_views.py"
SPEC = importlib.util.spec_from_file_location("shared_views", HARNESS)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def wheel_identity(path: Path) -> tuple[str, str, set[str]]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(
            len(names) == len(set(names)) and len(names) <= 10_000,
            "invalid wheel inventory",
        )
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "missing wheel metadata")
        require(
            sum(info.file_size for info in archive.infolist()) <= 1024**3,
            "wheel expansion limit exceeded",
        )
        fields = BytesParser().parsebytes(archive.read(metadata[0]))
        require(fields.get("Name") == "hol-cigar", "unexpected wheel distribution")
        version = fields.get("Version")
        require(type(version) is str, "missing wheel version")
        sources = MODULE.package_source_identity(
            (name.removeprefix("cigar_sdk/"), archive.read(name))
            for name in names
            if name.startswith("cigar_sdk/")
            and not name.endswith("/")
            and "/_native/" not in name
        )
        workers = {
            hashlib.sha256(archive.read(name)).hexdigest()
            for name in names
            if name.startswith("cigar_sdk/_native/")
            and name.rsplit("/", 1)[-1]
            in {"cigar-context-worker", "cigar-context-worker.exe"}
        }
        require(bool(workers), "comparison requires a native wheel")
        return version, sources, workers


def import_study(
    raw_path: Path,
    baseline: str,
    candidate: str,
    baseline_wheel: Path,
    candidate_wheel: Path,
    baseline_commit: str,
    candidate_commit: str,
    output: Path,
) -> dict:
    require(
        raw_path.stat().st_size <= 64 * 1024 * 1024, "raw study byte limit exceeded"
    )
    raw_bytes = raw_path.read_bytes()
    raw = decode(raw_bytes)
    require(
        type(raw) is dict and raw.get("schema") == "cigar.shared-views-comparison.v1",
        "unexpected shared-view study",
    )
    require(
        raw.get("harness_sha256") == file_digest(HARNESS),
        "raw observations do not bind this harness",
    )
    require(
        type(raw.get("agents")) is int
        and raw.get("agents") in (1, 5, 12)
        and raw.get("reviewer") == "scripted-fixture",
        "unexpected study conditions",
    )
    require(
        type(raw.get("cohorts")) is int and 1 <= raw["cohorts"] <= 1000,
        "invalid cohort count",
    )
    require(
        all(
            type(raw.get(key)) is int and raw[key] > 0
            for key in ("rounds_per_cohort", "documents_per_source")
        ),
        "invalid corpus parameters",
    )
    require(
        type(raw.get("samples")) is list and baseline != candidate,
        "missing paired samples",
    )
    require(
        all(
            type(row) is dict
            and type(row.get("variant")) is str
            and type(row.get("cohort")) is int
            and type(row.get("python")) is str
            and type(row.get("protobuf")) is str
            for row in raw["samples"]
        ),
        "invalid raw sample identities",
    )
    selected = [
        row for row in raw["samples"] if row.get("variant") in {baseline, candidate}
    ]
    require(len(selected) == raw["cohorts"] * 2, "incomplete paired cohorts")
    expected = {
        (label, cohort)
        for label in (baseline, candidate)
        for cohort in range(raw["cohorts"])
    }
    require(
        {(row["variant"], row["cohort"]) for row in selected} == expected,
        "duplicate or missing cohort",
    )
    require(
        len({(row["python"], row["protobuf"]) for row in selected}) == 1,
        "runtime mismatch",
    )
    identities = {
        baseline: wheel_identity(baseline_wheel),
        candidate: wheel_identity(candidate_wheel),
    }
    for row in selected:
        version, sources, workers = identities[row["variant"]]
        require(
            row.get("version") == version and row.get("sdk_source_sha256") == sources,
            "measured SDK sources do not match the supplied wheel",
        )
        require(
            row.get("worker_sha256") in workers,
            "measured worker does not match the supplied wheel",
        )
        require(
            type(row.get("raw_timing_ms")) is dict
            and type(row.get("raw_host_and_worker_rss_bytes")) is list,
            "summary-only studies cannot be imported",
        )
    require(not output.exists(), "output directory already exists")

    common = {
        "agents": raw["agents"],
        "rounds": raw["rounds_per_cohort"],
        "documents_per_source": raw["documents_per_source"],
        "max_tokens": 2048,
        "reserve_tokens": 128,
        "corpus_generator_sha256": raw["harness_sha256"],
        "agent_execution": "one-host-scoped-clients",
        "reviewer": "scripted-fixture",
    }
    metrics, tasks, observations = [], [], []

    def add(task_id, unit, aggregation, read_values):
        metric_id = f"{task_id}-{aggregation}"
        metrics.append(
            {
                "id": metric_id,
                "unit": unit,
                "aggregation": aggregation,
                "direction": "lower",
            }
        )
        definition = {"family": "shared-views-v1", "operation": task_id, **common}
        existing = next((task for task in tasks if task["id"] == task_id), None)
        if existing:
            existing["metrics"].append(metric_id)
        else:
            tasks.append(
                {
                    "id": task_id,
                    "definition": definition,
                    "sha256": hashlib.sha256(encoded(definition)).hexdigest(),
                    "cluster": "authored-shared-views",
                    "stratum": "shared-views",
                    "metrics": [metric_id],
                }
            )
        for sample in selected:
            values = read_values(sample)
            require(
                type(values) is list and bool(values), "missing raw measurement series"
            )
            for replicate, value in enumerate(values):
                observations.append(
                    {
                        "schema": "cigar.context-observation.v1",
                        "task": task_id,
                        "treatment": "baseline"
                        if sample["variant"] == baseline
                        else "candidate",
                        "cohort": f"session-{sample['cohort']}",
                        "replicate": replicate,
                        "metric": metric_id,
                        "status": "ok",
                        "value": value,
                        "numerator": None,
                        "denominator": None,
                    }
                )

    for operation in ("compile", "verify", "review", "replace"):
        if operation == "replace" and all(
            sample["mode"] == "legacy" for sample in selected
        ):
            continue
        for aggregation in ("median", "p95", "p99"):
            add(
                operation,
                "milliseconds",
                aggregation,
                lambda sample, op=operation: sample["raw_timing_ms"].get(op),
            )
    add("startup", "milliseconds", "median", lambda sample: [sample["startup_ms"]])
    add("ingestion", "milliseconds", "median", lambda sample: [sample["setup_ms"]])
    add("worker-rss", "bytes", "max", lambda sample: sample.get("raw_worker_rss_bytes"))
    add(
        "host-worker-rss",
        "bytes",
        "max",
        lambda sample: sample["raw_host_and_worker_rss_bytes"],
    )
    plan = {
        "schema": "cigar.context-evaluation-plan.v1",
        "id": f"shared-views-{raw['agents']}-performance",
        "evidence_class": "performance",
        "oracle_kind": "authored",
        "model_mode": "none",
        "cluster_unit": "process-cohort",
        "seed": 1400,
        "baseline": "baseline",
        "candidate": "candidate",
        "cohorts": [f"session-{i}" for i in range(raw["cohorts"])],
        "inputs": {"corpus": "corpus", "oracle": "oracle", "harness": "harness"},
        "conditions": {
            **common,
            "host": raw["host"],
            "python": selected[0]["python"],
            "protobuf": selected[0]["protobuf"],
            "method": raw["method"],
            "plan_origin": "imported-existing-study; not prospectively preregistered",
        },
        "treatments": [
            {
                "id": treatment,
                "version": identities[label][0],
                "source_commit": commit,
                "artifacts": [f"{treatment}-wheel"],
                "settings": {
                    "label": label,
                    "mode": next(
                        row["mode"] for row in selected if row["variant"] == label
                    ),
                },
            }
            for treatment, label, commit in (
                ("baseline", baseline, baseline_commit),
                ("candidate", candidate, candidate_commit),
            )
        ],
        "metrics": metrics,
    }
    output.mkdir(mode=0o700)
    artifacts = []

    def artifact(name, role, path):
        artifacts.append(
            {
                "id": name,
                "role": role,
                "path": path.name,
                "sha256": file_digest(path),
                "bytes": path.stat().st_size,
            }
        )

    for treatment, wheel in (
        ("baseline", baseline_wheel),
        ("candidate", candidate_wheel),
    ):
        target = output / f"{treatment}.whl"
        shutil.copyfile(wheel, target)
        artifact(f"{treatment}-wheel", "package", target)
    documents = {
        "evaluator": ("evaluator", Path(evaluation.__file__).read_bytes()),
        "plan": ("plan", encoded(plan)),
        "tasks": (
            "tasks",
            encoded({"schema": "cigar.context-evaluation-tasks.v1", "tasks": tasks}),
        ),
        "observations": (
            "observations",
            b"".join(encoded(row) for row in observations),
        ),
        "corpus": ("corpus", encoded(common)),
        "oracle": (
            "oracle",
            encoded(
                {
                    "kind": "authored",
                    "enforcement_only": True,
                    "definition": "The bound harness asserts scope, budgets, exact source revisions and supplied verdicts.",
                }
            ),
        ),
        "harness": ("harness", HARNESS.read_bytes()),
        "raw-study": ("source", raw_bytes),
    }
    for name, (role, data) in documents.items():
        path = output / f"{name}.data"
        with path.open("xb") as stream:
            stream.write(data)
        artifact(name, role, path)
    manifest = {
        "schema": "cigar.context-evaluation-manifest.v1",
        "plan": "plan",
        "tasks": "tasks",
        "observations": "observations",
        "evaluator": "evaluator",
        "artifacts": artifacts,
    }
    with (output / "manifest.json").open("xb") as stream:
        stream.write(encoded(manifest))
    result = evaluate(output)
    with (output / "result.json").open("xb") as stream:
        stream.write(encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("raw", "baseline-wheel", "candidate-wheel", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("baseline", "candidate", "baseline-commit", "candidate-commit"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        report = import_study(
            args.raw,
            args.baseline,
            args.candidate,
            args.baseline_wheel,
            args.candidate_wheel,
            args.baseline_commit,
            args.candidate_commit,
            args.output,
        )
    except (EvaluationError, OSError, KeyError, TypeError, zipfile.BadZipFile) as error:
        raise SystemExit(f"shared-view import failed: {error}") from error
    print(
        encoded(
            {
                "study": report["study_id"],
                "tasks": report["tasks"],
                "observations": report["observations"],
            }
        ).decode(),
        end="",
    )


if __name__ == "__main__":
    main()
