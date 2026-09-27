"""Import retained Hiero campaigns without treating process exit as task truth.

Optional terminal results are recomputed from a bound readback and an explicit
field oracle. No measured code, oracle code, command or model is executed here.
Artifact provenance and the independence of a readback still need human review.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

import evaluation
from evaluation import (
    COMMIT,
    MAX_JSON_BYTES,
    MAX_OBSERVATIONS,
    EvaluationError,
    artifact_path,
    decode,
    encoded,
    evaluate,
    identifier,
    input_artifact,
    member,
    number,
    record,
    require,
    validate_plan,
    validate_tasks,
    verify_artifacts,
)


METRICS = [
    {"id": name, "unit": unit, "aggregation": aggregation, "direction": direction}
    for name, unit, aggregation, direction in (
        ("process-exit-success", "ratio", "ratio", "descriptive"),
        ("campaign-complete", "ratio", "ratio", "higher"),
        ("retained-iterations", "ratio", "ratio", "descriptive"),
        ("declared-context-quality-pass", "ratio", "ratio", "descriptive"),
        ("declared-target-executions", "count", "sum", "descriptive"),
        ("declared-synthetic-self-tests", "count", "sum", "descriptive"),
        ("declared-context-tokens", "tokens", "sum", "descriptive"),
        ("campaign-wall-ms", "milliseconds", "median", "descriptive"),
        ("terminal-contract-success", "ratio", "ratio", "higher"),
        ("terminal-check-pass", "ratio", "ratio", "higher"),
    )
]


def bound_bytes(artifacts: dict, name: object, role: str) -> bytes:
    path = input_artifact(artifacts, name, role)
    payload = path.read_bytes()
    item = artifacts[name][0]
    require(
        len(payload) == item["bytes"]
        and hashlib.sha256(payload).hexdigest() == item["sha256"],
        "parsed Hiero artifact changed",
    )
    return payload


def bound_json(artifacts: dict, name: object, role: str) -> object:
    return decode(bound_bytes(artifacts, name, role))


def command_option(command: object, option: str) -> str:
    require(
        type(command) is list
        and all(type(part) is str for part in command)
        and command.count(option) == 1,
        "missing or ambiguous campaign command option",
    )
    index = command.index(option) + 1
    require(index < len(command), "campaign command option has no value")
    return command[index]


def task_oracles(payload: bytes, tasks: dict) -> dict:
    document = record(decode(payload), {"schema", "tasks"}, "Hiero task oracle")
    require(
        document["schema"] == "hiero.context-task-oracles.v1"
        and type(document["tasks"]) is list,
        "invalid Hiero oracle schema",
    )
    result = {}
    for value in document["tasks"]:
        item = record(value, {"task", "task_sha256", "mode", "checks"}, "task oracle")
        require(
            member(item["task"], set(tasks)) and item["task"] not in result,
            "missing or duplicated oracle task",
        )
        require(
            item["task_sha256"] == tasks[item["task"]]["sha256"]
            and member(item["mode"], {"unavailable", "terminal-readback"})
            and type(item["checks"]) is list
            and len(item["checks"]) <= 128,
            "invalid oracle definition binding",
        )
        require(
            bool(item["checks"]) == (item["mode"] == "terminal-readback"),
            "unavailable or empty oracle cannot establish task success",
        )
        seen = set()
        for raw in item["checks"]:
            check = record(raw, {"id", "path", "equals"}, "terminal field check")
            require(
                identifier(check["id"]) and check["id"] not in seen,
                "duplicate or invalid terminal check",
            )
            seen.add(check["id"])
            require(
                type(check["path"]) is list
                and 1 <= len(check["path"]) <= 32
                and all(
                    (type(part) is str and 0 < len(part) <= 256)
                    or (type(part) is int and 0 <= part <= 100_000)
                    for part in check["path"]
                ),
                "invalid terminal field path",
            )
        result[item["task"]] = item
    require(
        set(result) == set(tasks), "every task needs an explicit oracle disposition"
    )
    return result


def field_matches(state: dict, check: dict) -> bool:
    value = state
    for part in check["path"]:
        if type(part) is str and type(value) is dict and part in value:
            value = value[part]
        elif type(part) is int and type(value) is list and part < len(value):
            value = value[part]
        else:
            return False
    # Python equality would otherwise identify True with 1 and 1.0 with 1.
    return encoded(value) == encoded(check["equals"])


def terminal_values(row: dict, task: dict, oracle: dict, inputs: dict, artifacts: dict):
    if row["terminal"] is None:
        return {}
    require(
        oracle["mode"] == "terminal-readback" and inputs["terminal_reader"] is not None,
        "terminal readback lacks an oracle and reader identity",
    )
    reader = input_artifact(artifacts, inputs["terminal_reader"], "harness")
    require(reader.is_file(), "missing terminal reader")
    terminal = record(
        bound_json(artifacts, row["terminal"], "source"),
        {
            "schema",
            "campaign_id",
            "task",
            "task_sha256",
            "treatment",
            "cohort",
            "replicate",
            "target_revision",
            "execution_sha256",
            "oracle_sha256",
            "reader_sha256",
            "mode",
            "complete",
            "state",
        },
        "Hiero terminal readback",
    )
    require(
        terminal["schema"] == "hiero.context-terminal-readback.v1"
        and type(terminal["replicate"]) is int
        and all(
            terminal[key] == row[key]
            for key in ("campaign_id", "task", "treatment", "cohort", "replicate")
        )
        and terminal["task_sha256"] == task["sha256"]
        and terminal["target_revision"] == task["definition"]["target_revision"]
        and terminal["execution_sha256"] == artifacts[row["execution"]][0]["sha256"]
        and terminal["oracle_sha256"] == artifacts[inputs["oracle"]][0]["sha256"]
        and terminal["reader_sha256"]
        == artifacts[inputs["terminal_reader"]][0]["sha256"],
        "terminal result belongs to different execution, task, oracle or reader",
    )
    require(
        member(terminal["mode"], {"target", "synthetic"})
        and type(terminal["complete"]) is bool
        and type(terminal["state"]) is dict,
        "invalid terminal readback disposition",
    )
    if not terminal["complete"] or terminal["mode"] != "target":
        return {}
    passed = sum(field_matches(terminal["state"], check) for check in oracle["checks"])
    return {
        "terminal-contract-success": (int(passed == len(oracle["checks"])), 1),
        "terminal-check-pass": (passed, len(oracle["checks"])),
    }


def campaign_values(row: dict, task: dict, treatment: dict, artifacts: dict):
    execution = bound_json(artifacts, row["execution"], "source")
    require(type(execution) is dict, "invalid original execution receipt")
    definition = task["definition"]
    requested = definition["requested_iterations"]
    worker_digests = {
        artifacts[name][0]["sha256"]
        for name in treatment["artifacts"]
        if artifacts[name][0]["role"] == "worker"
    }
    require(
        execution.get("workflow") == definition["workflow"]
        and execution.get("cigar_version") == treatment["version"]
        and type(execution.get("compiler_binary_sha256")) is str
        and execution["compiler_binary_sha256"] in worker_digests
        and type(execution.get("requested_iterations")) is int
        and execution["requested_iterations"] == requested
        and execution.get("compiler_mode") == "required"
        and execution.get("ai_provider") == "mock"
        and execution.get("live_ai") is False,
        "Hiero execution identity or offline mode mismatch",
    )
    command = execution.get("command")
    require(
        command_option(command, "--campaign-id") == row["campaign_id"]
        and command_option(command, "--ref") == definition["target_revision"]
        and command_option(command, "--max-iterations") == str(requested),
        "Hiero command does not bind the planned campaign",
    )
    require(
        (command_option(command, "--ai-provider") == "mock")
        if definition["ai_mode"] == "mock"
        else "--ai-provider" not in command,
        "Hiero command conflicts with the declared offline AI mode",
    )
    require(
        type(execution.get("exit_code")) is int
        and -255 <= execution["exit_code"] <= 255
        and number(execution.get("seconds"))
        and type(execution.get("iteration_files")) is int
        and execution["iteration_files"] == len(row["iterations"]),
        "invalid process outcome or lost iteration receipts",
    )
    iterations = [bound_json(artifacts, name, "source") for name in row["iterations"]]
    require(
        len(iterations) <= requested
        and all(
            type(item) is dict and type(item.get("iteration")) is int
            for item in iterations
        )
        and [item["iteration"] for item in iterations]
        == list(range(1, len(iterations) + 1)),
        "missing, duplicated or reordered iteration receipts",
    )
    completed = execution.get("completed_iterations")
    require(
        completed is None
        or (type(completed) is int and 0 <= completed <= len(iterations)),
        "invalid declared campaign completion",
    )
    values = {
        "process-exit-success": (int(execution["exit_code"] == 0), 1),
        "retained-iterations": (len(iterations), requested),
        "campaign-wall-ms": execution["seconds"] * 1000,
    }
    if execution["exit_code"] != 0 or completed is not None:
        values["campaign-complete"] = (
            int(execution["exit_code"] == 0 and completed == requested),
            1,
        )
    quality = [item.get("context_quality_status") for item in iterations]
    require(
        all(
            value is None or member(value, {"passed", "failed", "blocked"})
            for value in quality
        ),
        "unknown context-quality disposition",
    )
    if quality and all(value is not None for value in quality):
        values["declared-context-quality-pass"] = (
            quality.count("passed"),
            len(quality),
        )
    for metric, field in (
        ("declared-target-executions", "target_executing_validation_count"),
        ("declared-synthetic-self-tests", "synthetic_harness_self_test_count"),
        ("declared-context-tokens", "token_budget_used"),
    ):
        samples = [item.get(field) for item in iterations]
        require(
            all(
                value is None or (type(value) is int and 0 <= value <= 10**9)
                for value in samples
            ),
            "invalid declared iteration count",
        )
        if samples and all(value is not None for value in samples):
            values[metric] = sum(samples)
    return values


def observations(
    payload: bytes,
    plan: dict,
    tasks: dict,
    oracles: dict,
    inputs: dict,
    artifacts: dict,
):
    treatments = {item["id"]: item for item in plan["treatments"]}
    results, seen, campaign_ids, consumed = [], set(), set(), set()
    for line in payload.splitlines():
        require(
            line.strip() and len(results) + len(METRICS) <= MAX_OBSERVATIONS,
            "invalid Hiero stream size",
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
                "campaign_id",
                "execution",
                "iterations",
                "terminal",
            },
            "Hiero campaign observation",
        )
        require(
            row["schema"] == "cigar.hiero-campaign-observation.v1"
            and member(row["task"], set(tasks))
            and member(row["treatment"], set(treatments))
            and member(row["cohort"], set(plan["cohorts"]))
            and type(row["replicate"]) is int
            and 0 <= row["replicate"] < MAX_OBSERVATIONS
            and member(row["status"], {"ok", "failed", "unsupported"})
            and identifier(row["campaign_id"]),
            "invalid campaign identity or observation status",
        )
        key = tuple(row[name] for name in ("task", "treatment", "cohort", "replicate"))
        require(
            key not in seen and row["campaign_id"] not in campaign_ids,
            "duplicate campaign",
        )
        seen.add(key)
        campaign_ids.add(row["campaign_id"])
        treatment = treatments[row["treatment"]]
        identity = record(
            row["identity"],
            {"version", "source_commit", "artifacts", "harness_sha256"},
            "Hiero measured identity",
        )
        require(
            all(
                identity[name] == treatment[name]
                for name in ("version", "source_commit", "artifacts")
            )
            and identity["harness_sha256"] == artifacts[inputs["harness"]][0]["sha256"],
            "Hiero source, worker or producer identity drift",
        )
        require(
            type(row["iterations"]) is list and len(row["iterations"]) <= 50,
            "invalid iteration inventory",
        )
        values = {}
        if row["status"] == "ok":
            references = [row["execution"], *row["iterations"]]
            if row["terminal"] is not None:
                references.append(row["terminal"])
            require(
                all(type(name) is str and name in artifacts for name in references)
                and len(references) == len(set(references))
                and not consumed.intersection(references),
                "missing or reused original campaign receipt",
            )
            consumed.update(references)
            values = campaign_values(row, tasks[row["task"]], treatment, artifacts)
            values.update(
                terminal_values(
                    row, tasks[row["task"]], oracles[row["task"]], inputs, artifacts
                )
            )
        else:
            require(
                row["execution"] is None
                and row["terminal"] is None
                and row["iterations"] == [],
                "unobserved attempts cannot conceal supplied campaign receipts",
            )
        for metric in METRICS:
            value = values.get(metric["id"])
            status = (
                row["status"]
                if row["status"] != "ok"
                else "ok"
                if value is not None
                else "unsupported"
            )
            ratio = metric["aggregation"] == "ratio"
            results.append(
                {
                    "schema": "cigar.context-observation.v1",
                    **{
                        name: row[name]
                        for name in ("task", "treatment", "cohort", "replicate")
                    },
                    "metric": metric["id"],
                    "status": status,
                    "value": value if not ratio else None,
                    "numerator": value[0] if value is not None and ratio else None,
                    "denominator": value[1] if value is not None and ratio else None,
                }
            )
    require(
        consumed == set(inputs["campaign_receipts"]),
        "unaccounted or omitted campaign receipts",
    )
    return results


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
            "cluster_unit",
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
        "Hiero study",
    )
    require(
        study["schema"] == "cigar.hiero-study.v1"
        and member(
            study["evidence_class"], {"invariant", "task-outcome", "performance"}
        )
        and study["model_mode"] == "none",
        "this Hiero adapter imports offline mock campaigns only",
    )
    artifacts = verify_artifacts(root, study["artifacts"])
    require(
        len(artifacts) <= 240 and all(len(name) <= 120 for name in artifacts),
        "Hiero artifact inventory limit exceeded",
    )
    require(
        all(item[0]["path"] != "study.json" for item in artifacts.values()),
        "study index is not an input artifact",
    )
    inputs = record(
        study["inputs"],
        {
            "corpus",
            "oracle",
            "harness",
            "records",
            "terminal_reader",
            "campaign_receipts",
        },
        "Hiero inputs",
    )
    receipts = inputs["campaign_receipts"]
    require(
        type(receipts) is list
        and all(
            type(name) is str
            and name in artifacts
            and artifacts[name][0]["role"] == "source"
            for name in receipts
        )
        and len(receipts) == len(set(receipts)),
        "invalid original campaign receipt inventory",
    )
    if inputs["terminal_reader"] is not None:
        input_artifact(artifacts, inputs["terminal_reader"], "harness")
    plan = {
        key: value
        for key, value in study.items()
        if key not in {"schema", "inputs", "artifacts", "tasks"}
    }
    plan.update(
        schema="cigar.context-evaluation-plan.v1",
        metrics=METRICS,
        inputs={key: inputs[key] for key in ("corpus", "oracle", "harness")},
    )
    validate_plan(plan, artifacts)
    require(type(study["tasks"]) is list, "missing Hiero task inventory")
    tasks = []
    for value in study["tasks"]:
        task = record(
            value, {"id", "definition", "sha256", "cluster", "stratum"}, "Hiero task"
        )
        definition = task["definition"]
        require(
            type(definition) is dict
            and identifier(definition.get("workflow"))
            and member(definition.get("ai_mode"), {"mock", "not-used"})
            and type(definition.get("target_revision")) is str
            and COMMIT.fullmatch(definition["target_revision"])
            and type(definition.get("requested_iterations")) is int
            and 1 <= definition["requested_iterations"] <= 50,
            "Hiero task must bind workflow, AI mode, target commit and iteration budget",
        )
        tasks.append({**task, "metrics": [metric["id"] for metric in METRICS]})
    task_document = {"schema": "cigar.context-evaluation-tasks.v1", "tasks": tasks}
    task_map = validate_tasks(task_document, {metric["id"] for metric in METRICS})
    oracles = task_oracles(bound_bytes(artifacts, inputs["oracle"], "oracle"), task_map)
    if study["evidence_class"] == "task-outcome":
        require(
            study["oracle_kind"] in ("executable", "independently-adjudicated")
            and inputs["terminal_reader"] is not None
            and all(item["mode"] == "terminal-readback" for item in oracles.values()),
            "task-outcome evidence requires bound terminal oracles and a reader",
        )
    rows = observations(
        bound_bytes(artifacts, inputs["records"], "observations"),
        plan,
        task_map,
        oracles,
        inputs,
        artifacts,
    )
    plan["inputs"] = {key: f"raw-{value}" for key, value in plan["inputs"].items()}
    plan["treatments"] = [
        {**item, "artifacts": [f"raw-{name}" for name in item["artifacts"]]}
        for item in plan["treatments"]
    ]
    plan["conditions"] = {
        **plan["conditions"],
        "hiero_import": {
            "plan_origin": "supplied retained study; importer does not establish prospective registration",
            "process_success": "exit zero and declared campaign completion do not establish task truth",
            "terminal_contract": "exact typed JSON fields from a bound target readback; missing, partial and synthetic readbacks remain unavailable",
            "independence": "producer execution, target provenance and reader independence require external review; hashes do not authenticate them",
            "declared_metrics": "Hiero quality/count/token fields are producer declarations, not independent findings or exact provider tokens",
            "model": "deterministic mock campaigns; no model or hallucination-prevalence conclusion",
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
        "hiero-importer": ("harness", "hiero-importer.py", Path(__file__).read_bytes()),
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
    verify_artifacts(root, study["artifacts"])
    require(index_path.read_bytes() == index, "Hiero study index changed")
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
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = import_study(args.directory, args.output)
    except (EvaluationError, OSError, UnicodeError) as error:
        raise SystemExit(f"Hiero import failed: {error}") from error
    print(
        encoded(
            {
                key: report[key]
                for key in ("study_id", "evidence_class", "tasks", "observations")
            }
        ).decode(),
        end="",
    )


if __name__ == "__main__":
    main()
