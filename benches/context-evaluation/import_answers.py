"""Bind recorded displayed answers and independent annotations to the offline evidence contract.

Only the repository's metric code is loaded. Study artifacts are data, never executable code.
Coverage attestations and oracle independence still require human study review.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import shutil
from pathlib import Path

import evaluation
from evaluation import (
    MAX_JSON_BYTES,
    MAX_OBSERVATIONS,
    EvaluationError,
    artifact_path,
    decode,
    encoded,
    evaluate,
    file_digest,
    identifier,
    input_artifact,
    record,
    require,
    validate_plan,
    validate_tasks,
    verify_artifacts,
)


METRIC_SOURCE = Path(__file__).resolve().parents[1] / "answer-quality/metrics.py"
METRIC_SHA256 = file_digest(METRIC_SOURCE)
SPEC = importlib.util.spec_from_file_location("answer_metric_rules", METRIC_SOURCE)
assert SPEC is not None and SPEC.loader is not None
ANSWER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANSWER)

RATIOS = {
    "factual-precision": "higher",
    "known-error-rate": "lower",
    "unverified-rate": "lower",
    "annotation-coverage": "higher",
    "confident-error-all-claims": "lower",
    "confident-error-confident-claims": "lower",
    "confident-error-episodes": "lower",
    "confident-unknown-claims": "lower",
    "confidence-coverage": "descriptive",
    "brier": "lower",
    "citation-precision": "higher",
    "citation-completeness": "higher",
    "answer-coverage": "descriptive",
    "correct-answer-yield": "higher",
    "answerable-success": "higher",
    "answerable-refusal": "lower",
    "unanswerable-abstention": "higher",
    "useful-fact-recall": "higher",
    "tokens-per-useful-fact": "lower",
}
METRICS = [
    {
        "id": name,
        "unit": "tokens-per-fact" if name == "tokens-per-useful-fact" else "ratio",
        "aggregation": "ratio",
        "direction": direction,
    }
    for name, direction in RATIOS.items()
] + [
    {
        "id": "context-tokens",
        "unit": "tokens",
        "aggregation": "sum",
        "direction": "descriptive",
    },
    {
        "id": "latency-median",
        "unit": "milliseconds",
        "aggregation": "median",
        "direction": "lower",
    },
    {
        "id": "latency-p95",
        "unit": "milliseconds",
        "aggregation": "p95",
        "direction": "lower",
    },
]
ANNOTATION_KEYS = {
    "episode_id",
    "treatment",
    "stratum",
    "answerable",
    "abstained",
    "gold_facts",
    "context_tokens",
    "latency_ms",
    "claims",
}
CLAIM_KEYS = {"id", "fact_id", "label", "confidence", "citation_labels"}


def measurements(row: dict) -> dict:
    """Additive numerators/denominators; never average per-answer percentages."""
    claims = row["claims"]
    total = len(claims)
    supported = sum(claim["label"] == "supported" for claim in claims)
    errors = sum(claim["label"] in {"unsupported", "contradicted"} for claim in claims)
    unknown = sum(claim["label"] == "unknown" for claim in claims)
    confident = [
        claim
        for claim in claims
        if claim["confidence"] is not None and claim["confidence"] >= 0.8
    ]
    confident_errors = sum(
        claim["label"] in {"unsupported", "contradicted"} for claim in confident
    )
    calibrated = [
        claim
        for claim in claims
        if claim["confidence"] is not None and claim["label"] != "unknown"
    ]
    citations = [label for claim in claims for label in claim["citation_labels"]]
    useful = len(ANSWER.useful_facts(row))
    correct = int(ANSWER.correct_answer(row))
    answerable = int(row["answerable"])
    return {
        "factual-precision": (supported, total),
        "known-error-rate": (errors, total - unknown),
        "unverified-rate": (total - supported, total),
        "annotation-coverage": (total - unknown, total),
        "confident-error-all-claims": (confident_errors, total),
        "confident-error-confident-claims": (confident_errors, len(confident)),
        "confident-error-episodes": (int(ANSWER.confident_error_episode(row)), 1),
        "confident-unknown-claims": (
            sum(claim["label"] == "unknown" for claim in confident),
            len(confident),
        ),
        "confidence-coverage": (
            sum(claim["confidence"] is not None for claim in claims),
            total,
        ),
        "brier": (
            sum(
                (claim["confidence"] - int(claim["label"] == "supported")) ** 2
                for claim in calibrated
            ),
            len(calibrated),
        ),
        "citation-precision": (citations.count("supported"), len(citations)),
        "citation-completeness": (
            sum("supported" in claim["citation_labels"] for claim in claims),
            total,
        ),
        "answer-coverage": (int(not row["abstained"]), 1),
        "correct-answer-yield": (correct, 1),
        "answerable-success": (correct, answerable),
        "answerable-refusal": (int(row["abstained"] and row["answerable"]), answerable),
        "unanswerable-abstention": (
            int(row["abstained"] and not row["answerable"]),
            1 - answerable,
        ),
        "useful-fact-recall": (useful, len(row["gold_facts"])),
        "tokens-per-useful-fact": (row["context_tokens"], useful),
        "context-tokens": row["context_tokens"],
        "latency-median": row["latency_ms"],
        "latency-p95": row["latency_ms"],
    }


def bound_bytes(artifacts: dict, name: str, role: str) -> bytes:
    path = input_artifact(artifacts, name, role)
    payload = path.read_bytes()
    item = artifacts[name][0]
    require(
        len(payload) == item["bytes"]
        and hashlib.sha256(payload).hexdigest() == item["sha256"],
        "parsed artifact changed",
    )
    return payload


def displayed_answers(payload: bytes) -> dict[str, str]:
    document = record(decode(payload), {"schema", "answers"}, "displayed answers")
    require(
        document["schema"] == "cigar.displayed-answers.v1",
        "invalid displayed-answer schema",
    )
    require(
        type(document["answers"]) is list
        and len(document["answers"]) <= MAX_OBSERVATIONS,
        "invalid displayed answers",
    )
    answers = {}
    for value in document["answers"]:
        item = record(value, {"id", "text"}, "displayed answer")
        require(
            identifier(item["id"]) and item["id"] not in answers,
            "duplicate or invalid displayed-answer identity",
        )
        require(type(item["text"]) is str, "displayed answer must retain text")
        # Reject unpaired surrogates; source hashing and character spans require valid UTF-8.
        try:
            item["text"].encode("utf-8")
        except UnicodeError as error:
            raise EvaluationError("invalid displayed-answer Unicode") from error
        answers[item["id"]] = item["text"]
    return answers


def annotated_row(row: dict, task: dict, text: str) -> dict:
    annotation = record(row["annotation"], ANNOTATION_KEYS, "answer annotation")
    require(type(annotation["claims"]) is list, "missing claim inventory")
    for claim in annotation["claims"]:
        record(claim, CLAIM_KEYS, "atomic claim")
    try:
        ANSWER.validate([annotation])
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        raise EvaluationError("invalid answer annotation") from error
    require(
        annotation["episode_id"] == task["id"]
        and annotation["treatment"] == row["treatment"]
        and annotation["stratum"] == task["stratum"]
        and annotation["answerable"] == task["definition"]["answerable"]
        and annotation["gold_facts"] == task["definition"]["gold_facts"],
        "annotation task/gold/stratum drift",
    )
    coverage = record(
        row["coverage"], {"reviewed_entire_display", "spans"}, "annotation coverage"
    )
    spans = coverage["spans"]
    require(
        coverage["reviewed_entire_display"] is True
        and type(spans) is dict
        and set(spans) == {claim["id"] for claim in annotation["claims"]},
        "every displayed claim needs an explicit full-display review and source span",
    )
    for ranges in spans.values():
        require(type(ranges) is list and 1 <= len(ranges) <= 128, "missing claim spans")
        for span in ranges:
            require(
                type(span) is list
                and len(span) == 2
                and all(type(index) is int for index in span)
                and 0 <= span[0] < span[1] <= len(text)
                and bool(text[span[0] : span[1]].strip()),
                "claim span does not select displayed text",
            )
    return annotation


def observations(
    payload: bytes, plan: dict, tasks: dict, answers: dict, artifacts: dict
) -> list[dict]:
    treatments = {item["id"]: item for item in plan["treatments"]}
    result, seen_outputs, seen_rows = [], set(), set()
    for line in payload.splitlines():
        require(
            line.strip() and len(result) + len(METRICS) <= MAX_OBSERVATIONS,
            "invalid or oversized answer record stream",
        )
        row = record(
            decode(line),
            {
                "schema",
                "task",
                "treatment",
                "cohort",
                "replicate",
                "status",
                "identity",
                "output",
                "coverage",
                "annotation",
            },
            "answer record",
        )
        require(
            row["schema"] == "cigar.annotated-answer-observation.v1",
            "invalid answer record schema",
        )
        require(
            type(row["task"]) is str and row["task"] in tasks, "unknown answer task"
        )
        require(
            type(row["treatment"]) is str and row["treatment"] in treatments,
            "unknown answer treatment",
        )
        require(
            type(row["cohort"]) is str and row["cohort"] in plan["cohorts"],
            "unknown answer cohort",
        )
        require(
            type(row["replicate"]) is int and 0 <= row["replicate"] < MAX_OBSERVATIONS,
            "invalid answer replicate",
        )
        require(
            type(row["status"]) is str
            and row["status"] in {"ok", "unsupported", "failed"},
            "invalid answer outcome",
        )
        key = (row["task"], row["treatment"], row["cohort"], row["replicate"])
        require(key not in seen_rows, "duplicate answer record")
        seen_rows.add(key)
        treatment = treatments[row["treatment"]]
        identity = record(
            row["identity"],
            {"version", "source_commit", "artifacts", "harness_sha256"},
            "measured identity",
        )
        require(
            all(
                identity[field] == treatment[field]
                for field in ("version", "source_commit", "artifacts")
            )
            and identity["harness_sha256"]
            == artifacts[plan["inputs"]["harness"]][0]["sha256"],
            "recorded source/package/worker/harness identity drift",
        )
        text = None
        if row["output"] is not None:
            output = record(row["output"], {"id", "sha256"}, "answer output binding")
            require(
                type(output["id"]) is str
                and output["id"] in answers
                and output["id"] not in seen_outputs,
                "missing or reused displayed answer",
            )
            text = answers[output["id"]]
            require(
                hashlib.sha256(text.encode()).hexdigest() == output["sha256"],
                "displayed-answer digest mismatch",
            )
            seen_outputs.add(output["id"])
        values = {}
        if row["status"] == "ok":
            require(
                text is not None,
                "successful observations require the full displayed answer",
            )
            values = measurements(annotated_row(row, tasks[row["task"]], text))
        else:
            require(
                row["annotation"] is None and row["coverage"] is None,
                "failed/unsupported outcomes cannot acquire successful annotations",
            )
        for metric in METRICS:
            value = values.get(metric["id"])
            result.append(
                {
                    "schema": "cigar.context-observation.v1",
                    **{
                        field: row[field]
                        for field in (
                            "task",
                            "treatment",
                            "cohort",
                            "replicate",
                            "status",
                        )
                    },
                    "metric": metric["id"],
                    "value": value if metric["aggregation"] != "ratio" else None,
                    "numerator": value[0]
                    if value is not None and metric["aggregation"] == "ratio"
                    else None,
                    "denominator": value[1]
                    if value is not None and metric["aggregation"] == "ratio"
                    else None,
                }
            )
    require(
        set(answers) == seen_outputs,
        "unaccounted displayed answers must not be dropped",
    )
    return result


def import_study(directory: Path, output: Path) -> dict:
    root = directory.resolve(strict=True)
    index_path = artifact_path(root, "study.json")
    require(
        index_path.stat().st_size <= MAX_JSON_BYTES, "study index byte limit exceeded"
    )
    index = index_path.read_bytes()
    study = record(
        decode(index),
        {
            "schema",
            "id",
            "evidence_class",
            "oracle_kind",
            "model_mode",
            "seed",
            "baseline",
            "candidate",
            "cohorts",
            "conditions",
            "treatments",
            "tasks",
            "inputs",
            "artifacts",
        },
        "annotated-answer study",
    )
    require(
        study["schema"] == "cigar.annotated-answer-study.v1",
        "invalid answer study schema",
    )
    require(
        study["evidence_class"] in ("invariant", "answer-replay", "model-output"),
        "not an answer study evidence class",
    )
    require(
        study["model_mode"] in ("none", "recorded"),
        "this adapter only imports retained offline observations",
    )
    require(
        study["evidence_class"] == "invariant"
        or study["oracle_kind"] == "independently-adjudicated",
        "answer efficacy requires independent annotations",
    )
    artifacts = verify_artifacts(root, study["artifacts"])
    require(
        len(artifacts) <= 240 and all(len(name) <= 120 for name in artifacts),
        "answer artifact inventory limit exceeded",
    )
    require(
        all(item[0]["path"] != "study.json" for item in artifacts.values()),
        "index cannot also be an input artifact",
    )
    inputs = record(
        study["inputs"],
        {"corpus", "oracle", "harness", "records", "outputs"},
        "answer inputs",
    )
    plan = {
        key: value
        for key, value in study.items()
        if key not in {"schema", "inputs", "artifacts", "tasks"}
    }
    plan.update(
        schema="cigar.context-evaluation-plan.v1",
        cluster_unit="task-cluster",
        metrics=METRICS,
        inputs={key: inputs[key] for key in ("corpus", "oracle", "harness")},
    )
    validate_plan(plan, artifacts)
    if plan["evidence_class"] != "invariant":
        require(
            all(
                any(artifacts[name][0]["role"] == "model" for name in item["artifacts"])
                for item in plan["treatments"]
            ),
            "each answer treatment must identify its recorded model",
        )
    require(type(study["tasks"]) is list, "missing answer tasks")
    tasks = []
    for value in study["tasks"]:
        task = record(
            value, {"id", "definition", "sha256", "cluster", "stratum"}, "answer task"
        )
        definition = task["definition"]
        require(
            type(definition) is dict
            and type(definition.get("answerable")) is bool
            and type(definition.get("gold_facts")) is list,
            "answer task must bind answerability and gold facts",
        )
        facts = definition["gold_facts"]
        require(
            all(type(fact) is str and fact for fact in facts)
            and len(facts) == len(set(facts))
            and (not definition["answerable"] or bool(facts)),
            "invalid gold fact inventory",
        )
        tasks.append({**task, "metrics": [metric["id"] for metric in METRICS]})
    task_document = {"schema": "cigar.context-evaluation-tasks.v1", "tasks": tasks}
    task_map = validate_tasks(task_document, {metric["id"] for metric in METRICS})
    require(
        sum(len(task["metrics"]) for task in tasks)
        * len(plan["cohorts"])
        * len(plan["treatments"])
        <= MAX_OBSERVATIONS,
        "planned answer exposure limit exceeded",
    )
    answers = displayed_answers(bound_bytes(artifacts, inputs["outputs"], "source"))
    rows = observations(
        bound_bytes(artifacts, inputs["records"], "observations"),
        plan,
        task_map,
        answers,
        artifacts,
    )
    # All input bindings survive intact under raw/, which is itself a reusable importer input.
    plan["inputs"] = {key: f"raw-{value}" for key, value in plan["inputs"].items()}
    plan["treatments"] = [
        {**item, "artifacts": [f"raw-{name}" for name in item["artifacts"]]}
        for item in plan["treatments"]
    ]
    plan["conditions"] = {
        **plan["conditions"],
        "answer_import": {
            "method": "retained outputs and annotations; no generation or semantic judging",
            "plan_origin": "imported supplied study; prospective registration not established by importer",
            "confidence_threshold": 0.8,
            "coverage": "explicit full-display review with Unicode character spans; completeness requires oracle review",
            "binding": "hashes identify supplied artifacts; execution identity and independence require producer review",
            "ece": "not an additive metric; use retained answer metrics separately, not averages of episode ECE",
        },
    }
    require(not output.exists(), "output directory already exists")
    output.mkdir(mode=0o700)
    (output / "raw").mkdir(mode=0o700)
    inventory = []
    for name, (item, path) in artifacts.items():
        relative = "raw/" + item["path"]
        target = output / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("rb") as source, target.open("xb") as destination:
            shutil.copyfileobj(source, destination, 1024 * 1024)
        inventory.append({**item, "id": f"raw-{name}", "path": relative})
    documents = {
        "original-study": ("source", "raw/study.json", index),
        "plan": ("plan", "plan.json", encoded(plan)),
        "tasks": ("tasks", "tasks.json", encoded(task_document)),
        "observations": (
            "observations",
            "observations.jsonl",
            b"".join(encoded(row) for row in rows),
        ),
        "answer-importer": (
            "harness",
            "answer-importer.py",
            Path(__file__).read_bytes(),
        ),
        "answer-metric-rules": (
            "harness",
            "answer-metric-rules.py",
            METRIC_SOURCE.read_bytes(),
        ),
        "evaluator": (
            "evaluator",
            "evaluator.py",
            Path(evaluation.__file__).read_bytes(),
        ),
    }
    for name, (role, relative, payload) in documents.items():
        with (output / relative).open("xb") as stream:
            stream.write(payload)
        inventory.append(
            {
                "id": name,
                "role": role,
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    # Rechecking original inputs and copied bytes prevents a changed archive from receiving a new identity.
    verify_artifacts(root, study["artifacts"])
    require(index_path.read_bytes() == index, "answer study index changed")
    require(
        file_digest(METRIC_SOURCE) == METRIC_SHA256,
        "answer metric rules changed during import",
    )
    manifest = {
        "schema": "cigar.context-evaluation-manifest.v1",
        "plan": "plan",
        "tasks": "tasks",
        "observations": "observations",
        "evaluator": "evaluator",
        "artifacts": inventory,
    }
    with (output / "manifest.json").open("xb") as stream:
        stream.write(encoded(manifest))
    report = evaluate(output)
    with (output / "result.json").open("xb") as stream:
        stream.write(encoded(report))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory",
        type=Path,
        help="directory with study.json and bound input artifacts",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new evidence directory"
    )
    arguments = parser.parse_args()
    try:
        report = import_study(arguments.directory, arguments.output)
    except (EvaluationError, OSError, UnicodeError) as error:
        raise SystemExit(f"answer import failed: {error}") from error
    print(
        encoded(
            {
                "study": report["study_id"],
                "evidence_class": report["evidence_class"],
                "tasks": report["tasks"],
                "observations": report["observations"],
            }
        ).decode(),
        end="",
    )


if __name__ == "__main__":
    main()
