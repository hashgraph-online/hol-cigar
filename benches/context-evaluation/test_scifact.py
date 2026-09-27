"""Independent annotations are scored without treating citations as gold."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from evaluation import EvaluationError, encoded, file_digest
import import_scifact as importer
from import_scifact import gold_labels, import_study, score_row


def inputs():
    corpus = {"7": {"abstract": ["One.", "Two."]}, "8": {"abstract": ["Other."]}}
    queries = [
        {"id": "claim-1", "query": "Claim one"},
        {"id": "claim-2", "query": "Claim two"},
        {"id": "claim-3", "query": "Unknown"},
    ]
    oracle = [
        {
            "id": 1,
            "claim": "Claim one",
            "evidence": {"7": [{"label": "SUPPORT", "sentences": [0, 1]}]},
            "cited_doc_ids": [7, 8],
        },
        {
            "id": 2,
            "claim": "Claim two",
            "evidence": {"7": [{"label": "CONTRADICT", "sentences": [1]}]},
            "cited_doc_ids": [7],
        },
        {"id": 3, "claim": "Unknown", "evidence": {}, "cited_doc_ids": [8]},
    ]
    return corpus, queries, oracle


def prediction():
    return {
        "id": "claim-1",
        "status": "ok",
        "error": None,
        "ranked_ids": ["7"],
        "result": {
            "snapshot": {
                "blocks": [
                    {
                        "text": "Title\nOne.\nTwo.",
                        "citations": [
                            {
                                "node_id": "7",
                                "source": "scifact",
                                "start_line": 1,
                                "end_line": 3,
                            }
                        ],
                    }
                ],
                "stats": {"selected_blocks": 1, "rendered_tokens": 12},
            },
            "rendered": "rendered",
        },
        "ranking_ms": 2.5,
        "compile_ms": 3.5,
        "compile_calls": 1,
    }


DOCS = {"7": {"source": "scifact", "text": "Title\nOne.\nTwo."}}


def complete_study(root):
    corpus, queries, oracle = inputs()
    data = root / "data"
    data.mkdir()
    documents = [
        {"id": "7", "source": "scifact", "text": DOCS["7"]["text"], "start_line": 1},
        {"id": "8", "source": "scifact", "text": "Title\nOther.", "start_line": 1},
    ]
    original = [
        {"doc_id": int(paper), "title": "Title", **value, "structured": False}
        for paper, value in corpus.items()
    ]
    files = {}
    for name, values in (
        ("corpus.jsonl", documents),
        ("queries.jsonl", queries),
        ("original-corpus.jsonl", original),
        ("oracle.jsonl", oracle),
    ):
        path = data / name
        path.write_bytes(b"".join(encoded(row) for row in values))
        files[name] = file_digest(path)
    (data / "inputs.json").write_bytes(
        encoded(
            {
                "configuration": importer.CONFIG,
                "queries": 3,
                "documents": 2,
                "files": files,
            }
        )
    )
    package = root / "package.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("cigar_sdk/__init__.py", b"fixture")
    (root / "worker").write_bytes(b"worker-fixture-not-executed")
    (root / "adapter.py").write_bytes(b"adapter-fixture-not-executed")
    artifacts = [
        {
            "id": name,
            "role": role,
            "path": path,
            "sha256": file_digest(root / path),
            "bytes": (root / path).stat().st_size,
        }
        for name, role, path in (
            ("package", "package", "package.zip"),
            ("worker", "worker", "worker"),
            ("adapter", "harness", "adapter.py"),
        )
    ]
    identity = {
        "version": "test-fixture",
        "source_commit": "a" * 40,
        "sdk_source_sha256": hashlib.sha256(
            json.dumps(
                [["__init__.py", hashlib.sha256(b"fixture").hexdigest()]],
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "worker_sha256": file_digest(root / "worker"),
        "recipe_sha256": file_digest(root / "adapter.py"),
        "harness_sha256": file_digest(importer.HARNESS),
    }
    names = {
        "v012-default": "default",
        "v014-default": "default",
        "v012-ranked": "ranked",
        "v014-ranked": "ranked",
        "v012-flat": "flat",
    }
    treatments = [
        {
            "id": name,
            "version": identity["version"],
            "source_commit": identity["source_commit"],
            "artifacts": ["package", "worker", "adapter"],
            "settings": {"mode": mode, "identity": identity},
        }
        for name, mode in names.items()
    ]
    registration = {
        "schema": "cigar.scifact-study.v1",
        "configuration": importer.CONFIG,
        "harness_sha256": file_digest(importer.HARNESS),
        "scorer_sha256": file_digest(Path(importer.__file__)),
        "treatments": treatments,
        "artifacts": artifacts,
    }
    (root / "registration.json").write_bytes(encoded(registration))
    cells = []
    for name, mode in names.items():
        for budget in importer.CONFIG["budgets"]:
            directory = root / f"{name}-{budget}"
            directory.mkdir()
            rows = []
            for query in queries:
                row = prediction()
                row["id"] = query["id"]
                rows.append(row)
            (directory / "predictions.jsonl").write_bytes(
                b"".join(encoded(row) for row in rows)
            )
            summary = {
                "schema": "cigar.scifact-predictions.v1",
                "budget": budget,
                "mode": mode,
                "identity": identity,
                "inputs_sha256": file_digest(data / "inputs.json"),
                "predictions_sha256": file_digest(directory / "predictions.jsonl"),
                "queries": 3,
                "failures": 0,
                "python": "test-runtime",
                "protobuf": "test-protobuf",
            }
            path = directory / "summary.json"
            path.write_bytes(encoded(summary))
            cells.append(
                {
                    "treatment": name,
                    "budget": budget,
                    "summary_path": path.relative_to(root).as_posix(),
                    "summary_sha256": file_digest(path),
                }
            )
    (root / "predictions-frozen.json").write_bytes(
        encoded(
            {
                "schema": "cigar.scifact-prediction-seal.v1",
                "registration_sha256": file_digest(root / "registration.json"),
                "cells": cells,
            }
        )
    )


class SciFactScoringTests(unittest.TestCase):
    def test_complete_bound_study_exports_common_contract_and_rejects_prediction_tamper(
        self,
    ):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            complete_study(root)
            result = import_study(
                root, "v012-default", "v014-default", 512, root / "comparison"
            )
            self.assertEqual(result["tasks"], 3)
            self.assertEqual(result["observations"], 66)
            (root / "v014-default-512/predictions.jsonl").write_bytes(b"changed")
            with self.assertRaises(EvaluationError):
                import_study(
                    root, "v012-default", "v014-default", 512, root / "bad-comparison"
                )

    def test_dropped_treatment_rejected_before_gold_read(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            complete_study(root)
            path = root / "predictions-frozen.json"
            seal = json.loads(path.read_bytes())
            seal["cells"].pop()
            path.write_bytes(encoded(seal))
            (root / "data/oracle.jsonl").unlink()
            with self.assertRaisesRegex(EvaluationError, "incomplete prediction seal"):
                import_study(
                    root, "v012-default", "v014-default", 512, root / "comparison"
                )

    def test_runtime_artifact_must_match_observed_sdk_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            complete_study(root)
            registration = json.loads((root / "registration.json").read_bytes())
            registration["treatments"][0]["settings"]["identity"][
                "sdk_source_sha256"
            ] = "0" * 64
            with self.assertRaisesRegex(EvaluationError, "measured runtime"):
                importer.verify_runtime_artifacts(root, registration)

    def test_independent_evidence_not_cited_ids_and_shared_paper_clusters(self):
        gold, clusters = gold_labels(*inputs())
        self.assertEqual(set(gold["claim-1"]["papers"]), {"7"})
        self.assertEqual(gold["claim-3"]["papers"], {})
        self.assertEqual(gold["claim-1"]["stratum"], "support")
        self.assertEqual(gold["claim-2"]["stratum"], "contradiction")
        self.assertEqual(gold["claim-3"]["stratum"], "no-annotated-evidence")
        self.assertEqual(clusters["claim-1"], clusters["claim-2"])
        self.assertNotEqual(clusters["claim-1"], clusters["claim-3"])

    def test_missing_or_duplicate_oracle_and_invalid_rationale_rejected(self):
        for mutation in ("missing", "duplicate", "invalid-index", "query-drift"):
            corpus, queries, oracle = inputs()
            if mutation == "missing":
                oracle.pop()
            elif mutation == "duplicate":
                oracle.append(copy.deepcopy(oracle[0]))
            elif mutation == "invalid-index":
                oracle[0]["evidence"]["7"][0]["sentences"] = [2]
            else:
                oracle[0]["claim"] = "changed"
            with self.subTest(mutation=mutation), self.assertRaises(EvaluationError):
                gold_labels(corpus, queries, oracle)

    def test_hand_scored_full_abstract_and_equal_budget(self):
        gold, _ = gold_labels(*inputs())
        ratios, values = score_row(prediction(), gold["claim-1"], DOCS, 12)
        for metric in (
            "evidence-recall",
            "evidence-precision",
            "claim-evidence-hit",
            "complete-rationale-coverage",
            "citation-text-fidelity",
        ):
            self.assertEqual(ratios[metric], (1, 1))
        self.assertEqual(ratios["budget-violation"], (0, 1))
        self.assertEqual(values["query-latency"], 6)
        self.assertEqual(
            score_row(prediction(), gold["claim-1"], DOCS, 11)[0]["budget-violation"],
            (1, 1),
        )

    def test_wrong_text_cannot_receive_retrieval_or_rationale_credit(self):
        gold, _ = gold_labels(*inputs())
        row = prediction()
        row["result"]["snapshot"]["blocks"][0]["text"] = "fabricated"
        ratios, _ = score_row(row, gold["claim-1"], DOCS, 12)
        self.assertEqual(ratios["evidence-recall"], (0, 1))
        self.assertEqual(ratios["complete-rationale-coverage"], (0, 1))
        self.assertEqual(ratios["citation-text-fidelity"], (0, 1))

    def test_no_gold_and_empty_selection_preserve_zero_denominators(self):
        gold, _ = gold_labels(*inputs())
        row = prediction()
        ratios, _ = score_row(row, gold["claim-3"], DOCS, 12)
        self.assertEqual(ratios["evidence-recall"], (0, 0))
        self.assertEqual(ratios["evidence-precision"], (0, 1))
        row["result"]["snapshot"]["blocks"] = []
        row["result"]["snapshot"]["stats"]["selected_blocks"] = 0
        ratios, _ = score_row(row, gold["claim-1"], DOCS, 12)
        self.assertEqual(ratios["evidence-recall"], (0, 1))
        self.assertEqual(ratios["evidence-precision"], (0, 0))

    def test_failed_prediction_is_retained_without_invented_measurements(self):
        gold, _ = gold_labels(*inputs())
        row = prediction()
        row.update(status="failed", error="Transport", result=None)
        self.assertEqual(
            score_row(row, gold["claim-1"], DOCS, 12),
            ({"operation-failure": (1, 1)}, {}),
        )


if __name__ == "__main__":
    unittest.main()
