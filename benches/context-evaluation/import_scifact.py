"""Score sealed SciFact predictions against independent original annotations.

This reads no model output and makes no hallucination/task-success claim. Gold
annotations are loaded only after the complete prediction inventory is verified.
Full-abstract ingestion makes complete rationale coverage track paper retrieval;
it is not evidence that a sentence selector or reasoning model understood a claim.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
from pathlib import Path
import shutil
import zipfile

import evaluation
from evaluation import artifact_path, decode, encoded, evaluate, file_digest, require

HARNESS = Path(__file__).resolve().parents[2] / "benchmarks/scifact.py"
SPEC = importlib.util.spec_from_file_location("scifact_harness", HARNESS)
assert SPEC is not None and SPEC.loader is not None
HARNESS_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS_MODULE)
CONFIG = HARNESS_MODULE.CONFIG
lines = HARNESS_MODULE.json_lines

METRICS = [
    {"id": name, "unit": "ratio", "aggregation": "ratio", "direction": direction}
    for name, direction in (
        ("evidence-recall", "higher"),
        ("evidence-precision", "higher"),
        ("claim-evidence-hit", "higher"),
        ("complete-rationale-coverage", "higher"),
        ("citation-text-fidelity", "higher"),
        ("budget-violation", "lower"),
        ("operation-failure", "lower"),
    )
] + [
    {"id": name, "unit": unit, "aggregation": "median", "direction": direction}
    for name, unit, direction in (
        ("rendered-tokens", "tokens", "descriptive"),
        ("selected-papers", "count", "descriptive"),
        ("query-latency", "milliseconds", "descriptive"),
        ("packing-calls", "count", "descriptive"),
    )
]


def gold_labels(
    corpus: dict[str, dict], queries: list[dict], oracle: list[dict]
) -> tuple[dict, dict]:
    gold, parent, papers = {}, {}, {}
    query_by_id = {row["id"]: row["query"] for row in queries}
    require(len(query_by_id) == len(queries), "duplicate query ID")

    def root(value):
        while parent[value] != value:
            value = parent[value]
        return value

    for row in oracle:
        require(
            set(row) == {"id", "claim", "evidence", "cited_doc_ids"},
            "invalid oracle fields",
        )
        claim_id = f"claim-{row['id']}"
        require(
            claim_id not in gold and query_by_id.get(claim_id) == row["claim"],
            "oracle/query identity mismatch",
        )
        require(type(row["evidence"]) is dict, "invalid evidence annotations")
        parent[claim_id] = claim_id
        rationale_count, labels = 0, set()
        by_paper = {}
        for paper, rationales in row["evidence"].items():
            require(
                paper in corpus and type(rationales) is list and bool(rationales),
                "invalid annotated paper",
            )
            by_paper[paper] = []
            for rationale in rationales:
                require(
                    set(rationale) == {"sentences", "label"}
                    and rationale["label"] in {"SUPPORT", "CONTRADICT"},
                    "invalid rationale label",
                )
                indexes = rationale["sentences"]
                require(
                    type(indexes) is list
                    and bool(indexes)
                    and len(set(indexes)) == len(indexes),
                    "invalid rationale sentence inventory",
                )
                require(
                    all(
                        type(index) is int
                        and 0 <= index < len(corpus[paper]["abstract"])
                        for index in indexes
                    ),
                    "rationale sentence outside original abstract",
                )
                by_paper[paper].append(indexes)
                rationale_count += 1
                labels.add(rationale["label"])
            if paper in papers:
                left, right = root(claim_id), root(papers[paper])
                parent[max(left, right)] = min(left, right)
            papers[paper] = claim_id
        stratum = (
            "no-annotated-evidence"
            if not labels
            else "support"
            if labels == {"SUPPORT"}
            else "contradiction"
            if labels == {"CONTRADICT"}
            else "mixed"
        )
        gold[claim_id] = {
            "papers": by_paper,
            "rationales": rationale_count,
            "stratum": stratum,
        }
    require(set(gold) == set(query_by_id), "incomplete oracle inventory")
    return gold, {claim: root(claim) for claim in parent}


def score_row(row: dict, gold: dict, documents: dict, budget: int) -> tuple[dict, dict]:
    require(
        set(row)
        == {
            "id",
            "status",
            "error",
            "ranked_ids",
            "result",
            "ranking_ms",
            "compile_ms",
            "compile_calls",
        },
        "invalid prediction fields",
    )
    require(row["status"] in {"ok", "failed"}, "invalid prediction status")
    for key in ("ranking_ms", "compile_ms", "compile_calls"):
        require(evaluation.number(row[key]), "invalid prediction timing/call count")
    if row["status"] == "failed":
        require(
            type(row["error"]) is str and row["result"] is None,
            "invalid failed prediction",
        )
        return {"operation-failure": (1, 1)}, {}
    require(
        row["error"] is None and type(row["result"]) is dict,
        "invalid successful prediction",
    )
    result = row["result"]
    snapshot = result["snapshot"]
    require(
        type(snapshot["blocks"]) is list and type(result["rendered"]) is str,
        "invalid snapshot result",
    )
    selected, faithful_papers, citations = set(), set(), 0
    for block in snapshot["blocks"]:
        require(
            type(block["text"]) is str
            and type(block["citations"]) is list
            and bool(block["citations"]),
            "invalid evidence block",
        )
        for citation in block["citations"]:
            paper = citation["node_id"]
            require(
                paper in documents and paper not in selected,
                "unknown or repeated selected paper",
            )
            selected.add(paper)
            document = documents[paper]
            citations += 1
            if (
                block["text"] == document["text"]
                and citation["source"] == document["source"]
                and citation["start_line"] == 1
                and citation["end_line"]
                == len(document["text"].removesuffix("\n").split("\n"))
            ):
                faithful_papers.add(paper)
    hits = faithful_papers & gold["papers"].keys()
    tokens = snapshot["stats"]["rendered_tokens"]
    require(
        type(tokens) is int
        and tokens >= 0
        and snapshot["stats"]["selected_blocks"] == len(snapshot["blocks"]),
        "invalid token/block inventory",
    )
    ratios = {
        "evidence-recall": (len(hits), len(gold["papers"])),
        "evidence-precision": (len(hits), len(selected)),
        "claim-evidence-hit": (int(bool(hits)), int(bool(gold["papers"]))),
        "complete-rationale-coverage": (
            sum(len(gold["papers"][paper]) for paper in hits),
            gold["rationales"],
        ),
        "citation-text-fidelity": (len(faithful_papers), citations),
        "budget-violation": (int(tokens > budget), 1),
        "operation-failure": (0, 1),
    }
    values = {
        "rendered-tokens": tokens,
        "selected-papers": len(selected),
        "query-latency": row["ranking_ms"] + row["compile_ms"],
        "packing-calls": row["compile_calls"],
    }
    return ratios, values


def verify_predictions(root: Path, registration: dict, seal: dict) -> dict:
    require(
        registration["schema"] == "cigar.scifact-study.v1"
        and registration["configuration"] == CONFIG,
        "invalid study registration",
    )
    require(
        seal["schema"] == "cigar.scifact-prediction-seal.v1"
        and seal["registration_sha256"] == file_digest(root / "registration.json"),
        "invalid prediction seal",
    )
    require(
        registration["harness_sha256"] == file_digest(HARNESS)
        and registration["scorer_sha256"] == file_digest(Path(__file__)),
        "evaluation source changed after registration",
    )
    treatments = {row["id"]: row for row in registration["treatments"]}
    require(
        len(treatments) == 5 and len(treatments) == len(registration["treatments"]),
        "incomplete treatment inventory",
    )
    expected = {(name, budget) for name in treatments for budget in CONFIG["budgets"]}
    require(
        type(seal["cells"]) is list and len(seal["cells"]) == len(expected),
        "incomplete prediction seal",
    )
    outputs = {}
    metadata = decode(artifact_path(root, "data/inputs.json").read_bytes())
    require(metadata["configuration"] == CONFIG, "dataset configuration mismatch")
    for cell in seal["cells"]:
        key = (cell["treatment"], cell["budget"])
        require(
            key in expected and key not in outputs,
            "duplicate or unknown prediction cell",
        )
        path = artifact_path(root, cell["summary_path"])
        require(
            file_digest(path) == cell["summary_sha256"], "prediction summary changed"
        )
        summary = decode(path.read_bytes())
        require(
            summary["schema"] == "cigar.scifact-predictions.v1"
            and summary["budget"] == key[1],
            "prediction configuration mismatch",
        )
        treatment = treatments[key[0]]
        require(
            summary["mode"] == treatment["settings"]["mode"]
            and summary["identity"] == treatment["settings"]["identity"],
            "prediction treatment mismatch",
        )
        require(
            summary["inputs_sha256"] == file_digest(root / "data/inputs.json"),
            "prediction input mismatch",
        )
        prediction_path = path.parent / "predictions.jsonl"
        require(
            not prediction_path.is_symlink()
            and file_digest(prediction_path) == summary["predictions_sha256"],
            "predictions changed after sealing",
        )
        rows = lines(prediction_path.read_bytes())
        require(
            summary["queries"] == len(rows) == metadata["queries"]
            and summary["failures"] == sum(row["status"] == "failed" for row in rows),
            "prediction count mismatch",
        )
        require(
            len({row["id"] for row in rows}) == len(rows), "duplicate prediction ID"
        )
        outputs[key] = {
            "summary": summary,
            "rows": {row["id"]: row for row in rows},
            "summary_path": path,
            "prediction_path": prediction_path,
        }
    require(set(outputs) == expected, "missing prediction cell")
    require(
        len(
            {
                (row["summary"]["python"], row["summary"]["protobuf"])
                for row in outputs.values()
            }
        )
        == 1,
        "Python/protobuf runtime mismatch",
    )
    return outputs


def verify_runtime_artifacts(root: Path, registration: dict) -> None:
    root = root.resolve()
    artifacts = {}
    for item in registration["artifacts"]:
        require(item["id"] not in artifacts, "duplicate frozen artifact")
        path = artifact_path(root, item["path"])
        require(
            file_digest(path) == item["sha256"]
            and path.stat().st_size == item["bytes"],
            "frozen runtime artifact changed",
        )
        artifacts[item["id"]] = (item, path)
    for treatment in registration["treatments"]:
        identity = treatment["settings"]["identity"]
        require(
            treatment["source_commit"] == identity["source_commit"]
            and treatment["version"] == identity["version"],
            "runtime version/commit mismatch",
        )
        package_sources, worker_hashes, recipe_hashes = set(), set(), set()
        for name in treatment["artifacts"]:
            require(name in artifacts, "missing runtime artifact")
            item, path = artifacts[name]
            if item["role"] == "worker":
                worker_hashes.add(item["sha256"])
            elif item["role"] == "harness":
                recipe_hashes.add(item["sha256"])
            elif item["role"] == "package":
                with zipfile.ZipFile(path) as archive:
                    names = archive.namelist()
                    require(
                        len(names) == len(set(names))
                        and len(names) <= 10_000
                        and sum(info.file_size for info in archive.infolist())
                        <= 1024**3,
                        "invalid package inventory",
                    )
                    sources = []
                    for name in names:
                        if not name.startswith("cigar_sdk/") or name.endswith("/"):
                            continue
                        relative = name.removeprefix("cigar_sdk/")
                        parts = relative.split("/")
                        if "_native" in parts:
                            if parts[-1] in {
                                "cigar-context-worker",
                                "cigar-context-worker.exe",
                            }:
                                worker_hashes.add(
                                    hashlib.sha256(archive.read(name)).hexdigest()
                                )
                        elif "__pycache__" not in parts and not name.endswith(".pyc"):
                            sources.append(
                                [
                                    relative,
                                    hashlib.sha256(archive.read(name)).hexdigest(),
                                ]
                            )
                    # Matches the measured SDK file inventory, not archive metadata.
                    import json

                    package_sources.add(
                        hashlib.sha256(
                            json.dumps(sorted(sources), separators=(",", ":")).encode()
                        ).hexdigest()
                    )
        require(
            identity["sdk_source_sha256"] in package_sources
            and identity["worker_sha256"] in worker_hashes,
            "measured runtime does not match frozen package/worker",
        )
        if treatment["settings"]["mode"] != "default":
            require(
                identity["recipe_sha256"] in recipe_hashes,
                "ranked treatment lacks exact adapter source",
            )


def import_study(
    root: Path, baseline: str, candidate: str, budget: int, output: Path
) -> dict:
    root = root.resolve()
    require(not output.exists(), "comparison destination already exists")
    registration = decode((root / "registration.json").read_bytes())
    seal = decode((root / "predictions-frozen.json").read_bytes())
    outputs = verify_predictions(root, registration, seal)
    verify_runtime_artifacts(root, registration)
    require(
        (baseline, budget) in outputs
        and (candidate, budget) in outputs
        and baseline != candidate,
        "unknown comparison",
    )
    data = root / "data"
    metadata = decode((data / "inputs.json").read_bytes())
    # No annotations are inspected until every treatment's predictions are sealed.
    for name, expected in metadata["files"].items():
        require(
            file_digest(artifact_path(root, "data/" + name)) == expected,
            "dataset identity changed",
        )
    documents = {row["id"]: row for row in lines((data / "corpus.jsonl").read_bytes())}
    originals = {
        str(row["doc_id"]): row
        for row in lines((data / "original-corpus.jsonl").read_bytes())
    }
    queries = lines((data / "queries.jsonl").read_bytes())
    gold, clusters = gold_labels(
        originals, queries, lines((data / "oracle.jsonl").read_bytes())
    )
    query_ids = {row["id"] for row in queries}
    require(
        all(set(value["rows"]) == query_ids for value in outputs.values()),
        "prediction/query inventory mismatch",
    )
    tasks, observations = [], []
    for query in queries:
        claim = query["id"]
        definition = {
            "family": "scifact-development-abstract-retrieval",
            "query": query["query"],
            "budget": budget,
            "corpus_sha256": metadata["files"]["corpus.jsonl"],
            "oracle_sha256": metadata["files"]["oracle.jsonl"],
        }
        tasks.append(
            {
                "id": claim,
                "definition": definition,
                "sha256": hashlib.sha256(encoded(definition)).hexdigest(),
                "cluster": clusters[claim],
                "stratum": gold[claim]["stratum"],
                "metrics": [metric["id"] for metric in METRICS],
            }
        )
        for treatment in (baseline, candidate):
            row = outputs[(treatment, budget)]["rows"][claim]
            ratios, values = score_row(row, gold[claim], documents, budget)
            for metric in METRICS:
                name = metric["id"]
                ok = name in ratios or name in values
                numerator, denominator = ratios.get(name, (None, None))
                observations.append(
                    {
                        "schema": "cigar.context-observation.v1",
                        "task": claim,
                        "treatment": treatment,
                        "cohort": "held-out-development",
                        "replicate": 0,
                        "metric": name,
                        "status": "ok" if ok else "failed",
                        "value": values.get(name),
                        "numerator": numerator,
                        "denominator": denominator,
                    }
                )
    treatments = [
        row for row in registration["treatments"] if row["id"] in {baseline, candidate}
    ]
    plan = {
        "schema": "cigar.context-evaluation-plan.v1",
        "id": f"scifact-{baseline}-{candidate}-{budget}",
        "evidence_class": "evidence-retention",
        "oracle_kind": "independently-adjudicated",
        "model_mode": "none",
        "cluster_unit": "task-cluster",
        "seed": CONFIG["seed"],
        "baseline": baseline,
        "candidate": candidate,
        "cohorts": ["held-out-development"],
        "treatments": treatments,
        "metrics": METRICS,
        "inputs": {"corpus": "corpus", "oracle": "oracle", "harness": "harness"},
        "conditions": {
            "configuration": CONFIG,
            "budget": budget,
            "strata": dict(Counter(row["stratum"] for row in gold.values())),
            "claim_clusters": len(set(clusters.values())),
            "timings": "informational sequential process runs, not a paired performance study",
            "rationale_limit": "full abstracts make rationale coverage dependent on paper retrieval",
            "no_evidence": "no annotated evidence is not a negative correctness judgment on every paper",
        },
    }
    output.mkdir(mode=0o700)
    artifacts = []

    def add(name, role, payload=None, source=None):
        target = output / (name + ".data")
        if source is not None:
            shutil.copyfile(source, target)
        else:
            target.write_bytes(payload)
        artifacts.append(
            {
                "id": name,
                "role": role,
                "path": target.name,
                "sha256": file_digest(target),
                "bytes": target.stat().st_size,
            }
        )

    selected_artifacts = set().union(*(set(row["artifacts"]) for row in treatments))
    for item in registration["artifacts"]:
        path = artifact_path(root, item["path"])
        require(
            file_digest(path) == item["sha256"]
            and path.stat().st_size == item["bytes"],
            "frozen runtime artifact changed",
        )
        if item["id"] in selected_artifacts:
            add(item["id"], item["role"], source=path)
    require(
        selected_artifacts <= {row["id"] for row in artifacts},
        "missing treatment artifact",
    )
    for name, role, path in (
        ("corpus", "corpus", data / "corpus.jsonl"),
        ("original-corpus", "source", data / "original-corpus.jsonl"),
        ("oracle", "oracle", data / "oracle.jsonl"),
        ("harness", "harness", HARNESS),
        ("scorer", "source", Path(__file__)),
        ("registration", "source", root / "registration.json"),
        ("prediction-seal", "source", root / "predictions-frozen.json"),
        ("evaluator", "evaluator", Path(evaluation.__file__)),
    ):
        add(name, role, source=path)
    for treatment in (baseline, candidate):
        add(
            treatment + "-predictions",
            "source",
            source=outputs[(treatment, budget)]["prediction_path"],
        )
        add(
            treatment + "-summary",
            "source",
            source=outputs[(treatment, budget)]["summary_path"],
        )
    add("plan", "plan", payload=encoded(plan))
    add(
        "tasks",
        "tasks",
        payload=encoded(
            {"schema": "cigar.context-evaluation-tasks.v1", "tasks": tasks}
        ),
    )
    add(
        "observations",
        "observations",
        payload=b"".join(encoded(row) for row in observations),
    )
    manifest = {
        "schema": "cigar.context-evaluation-manifest.v1",
        "plan": "plan",
        "tasks": "tasks",
        "observations": "observations",
        "evaluator": "evaluator",
        "artifacts": artifacts,
    }
    (output / "manifest.json").write_bytes(encoded(manifest))
    result = evaluate(output)
    (output / "result.json").write_bytes(encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--budget", type=int, required=True)
    args = parser.parse_args()
    result = import_study(
        args.study, args.baseline, args.candidate, args.budget, args.output
    )
    print(
        encoded(
            {
                "study": result["study_id"],
                "tasks": result["tasks"],
                "observations": result["observations"],
            }
        ).decode(),
        end="",
    )


if __name__ == "__main__":
    main()
