"""Authored unit fixtures for answer binding, denominators and cluster preservation.

These synthetic artifacts do not constitute a real model study or release evidence.
"""

from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from evaluation import EvaluationError, decode, encoded, evaluate
from import_answers import ANSWER, import_study


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture():
    definition = {
        "prompt": "What is the retry limit?",
        "answerable": True,
        "gold_facts": ["retry-limit"],
    }
    study = {
        "schema": "cigar.annotated-answer-study.v1",
        "id": "answer-import-unit-only",
        "evidence_class": "invariant",
        "oracle_kind": "authored",
        "model_mode": "none",
        "seed": 1400,
        "baseline": "baseline",
        "candidate": "candidate",
        "cohorts": ["session-0"],
        "conditions": {
            "synthetic_unit_fixture": True,
            "not_release_evidence": True,
            "token_budget": 256,
        },
        "treatments": [
            {
                "id": name,
                "version": version,
                "source_commit": commit * 40,
                "artifacts": [f"{name}-package", f"{name}-worker"],
                "settings": {"reviewer": "unit-fixture"},
            }
            for name, version, commit in [
                ("baseline", "0.12.0", "a"),
                ("candidate", "0.14.0", "b"),
            ]
        ],
        "tasks": [
            {
                "id": "retry",
                "definition": definition,
                "sha256": sha(encoded(definition)),
                "cluster": "repository-one",
                "stratum": "numeric",
            }
        ],
        "inputs": {
            "corpus": "corpus",
            "oracle": "oracle",
            "harness": "harness",
            "records": "records",
            "outputs": "outputs",
        },
        "artifacts": [],
    }
    files = {
        "corpus": ("corpus", b"Authored example: retry at most three times.\n"),
        "oracle": (
            "oracle",
            b"Authored unit annotations, not independent model judgments.\n",
        ),
        "harness": ("harness", b"Nonexecutable unit fixture producer.\n"),
        "baseline-package": ("package", b"fake baseline package\n"),
        "candidate-package": ("package", b"fake candidate package\n"),
        "baseline-worker": ("worker", b"fake baseline worker\n"),
        "candidate-worker": ("worker", b"fake candidate worker\n"),
    }
    answers, rows = [], []
    for treatment in study["treatments"]:
        name = treatment["id"]
        text = (
            "Retry three times. Then delete the account."
            if name == "baseline"
            else "Retry three times."
        )
        claims = [
            {
                "id": "limit",
                "fact_id": "retry-limit",
                "label": "supported",
                "confidence": 0.9,
                "citation_labels": ["supported"],
            }
        ]
        spans = {"limit": [[0, 18]]}
        if name == "baseline":
            claims.append(
                {
                    "id": "extra",
                    "fact_id": None,
                    "label": "unsupported",
                    "confidence": 0.8,
                    "citation_labels": ["unsupported"],
                }
            )
            spans["extra"] = [[19, len(text)]]
        answers.append({"id": name, "text": text})
        rows.append(
            {
                "schema": "cigar.annotated-answer-observation.v1",
                "task": "retry",
                "treatment": name,
                "cohort": "session-0",
                "replicate": 0,
                "status": "ok",
                "identity": {
                    **{
                        key: treatment[key]
                        for key in ("version", "source_commit", "artifacts")
                    },
                    "harness_sha256": sha(files["harness"][1]),
                },
                "output": {"id": name, "sha256": sha(text.encode())},
                "coverage": {"reviewed_entire_display": True, "spans": spans},
                "annotation": {
                    "episode_id": "retry",
                    "treatment": name,
                    "stratum": "numeric",
                    "answerable": True,
                    "abstained": False,
                    "gold_facts": ["retry-limit"],
                    "context_tokens": 100,
                    "latency_ms": 4 if name == "baseline" else 3,
                    "claims": claims,
                },
            }
        )
    return study, files, answers, rows


def seal(root, study, files, answers, rows):
    files = {
        **files,
        "outputs": (
            "source",
            encoded({"schema": "cigar.displayed-answers.v1", "answers": answers}),
        ),
        "records": ("observations", b"".join(encoded(row) for row in rows)),
    }
    inventory = []
    for name, (role, payload) in files.items():
        path = f"{name}.data"
        (root / path).write_bytes(payload)
        inventory.append(
            {
                "id": name,
                "role": role,
                "path": path,
                "sha256": sha(payload),
                "bytes": len(payload),
            }
        )
    study = {**study, "artifacts": inventory}
    (root / "study.json").write_bytes(encoded(study))


class AnswerImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-answer-import-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "input"
        self.source.mkdir()
        self.study, self.files, self.answers, self.rows = fixture()
        self.attempt = 0

    def imported(self):
        seal(self.source, self.study, self.files, self.answers, self.rows)
        self.attempt += 1
        self.output = self.root / f"result-{self.attempt}"
        return import_study(self.source, self.output)

    def value(self, report, name, treatment="baseline"):
        return report["metrics"][name]["treatments"][treatment]["value"]

    def test_hand_calculated_answers_bind_and_recompute_from_retained_originals(self):
        report = self.imported()
        self.assertEqual(report, evaluate(self.output))
        self.assertEqual(report["evidence_class"], "invariant")
        self.assertEqual(report["observations"], 44)
        self.assertEqual(self.value(report, "factual-precision"), 0.5)
        self.assertEqual(self.value(report, "confident-error-confident-claims"), 0.5)
        self.assertEqual(self.value(report, "confident-error-episodes"), 1)
        self.assertAlmostEqual(self.value(report, "brier"), 0.325)
        self.assertEqual(self.value(report, "citation-precision"), 0.5)
        self.assertEqual(self.value(report, "useful-fact-recall"), 1)
        self.assertEqual(self.value(report, "tokens-per-useful-fact"), 100)
        self.assertEqual(self.value(report, "correct-answer-yield"), 0)
        self.assertEqual(self.value(report, "correct-answer-yield", "candidate"), 1)
        self.assertEqual(self.value(report, "latency-p95", "candidate"), 3)
        paired = report["metrics"]["correct-answer-yield"]["paired"]
        self.assertEqual(paired["clusters"], 1)
        self.assertEqual(paired["mean_difference"], 1)
        self.assertIsNone(paired["difference_ci95"])
        original = self.output
        self.assertEqual(report, import_study(original / "raw", self.root / "reimport"))
        with self.assertRaisesRegex(EvaluationError, "already exists"):
            import_study(self.source, original)
        manifest = decode((original / "manifest.json").read_bytes())
        artifacts = {item["id"]: item for item in manifest["artifacts"]}
        self.assertEqual(
            artifacts["raw-oracle"]["sha256"], sha(self.files["oracle"][1])
        )
        self.assertIn("answer-metric-rules", artifacts)
        (original / "raw/candidate-package.data").write_bytes(b"changed artifact")
        with self.assertRaises(EvaluationError):
            evaluate(original)

    def test_existing_metric_semantics_match_for_unknown_and_repeated_useful_facts(
        self,
    ):
        base = self.rows[0]
        base["annotation"]["claims"][1]["label"] = "unknown"
        base["annotation"]["claims"][0]["confidence"] = None
        extra = copy.deepcopy(base["annotation"]["claims"][0]) | {"id": "repeat"}
        base["annotation"]["claims"].append(extra)
        base["coverage"]["spans"]["repeat"] = [[0, 18]]
        report = self.imported()
        legacy = ANSWER.evaluate([row["annotation"] for row in self.rows])[
            "treatments"
        ]["baseline"]
        for new, old in {
            "factual-precision": "factual_precision",
            "known-error-rate": "known_error_rate",
            "annotation-coverage": "annotation_coverage",
            "confidence-coverage": "confidence_coverage",
            "unverified-rate": "unverified_rate",
            "confident-error-all-claims": "confident_error_rate_all_claims",
            "confident-error-confident-claims": "confident_error_rate_confident_claims",
            "useful-fact-recall": "useful_fact_recall",
            "tokens-per-useful-fact": "context_tokens_per_supported_useful_fact",
            "brier": "brier",
            "citation-completeness": "citation_completeness",
        }.items():
            self.assertEqual(self.value(report, new), legacy[old])
        self.assertIsNone(self.value(report, "brier"))
        self.assertEqual(self.value(report, "confident-unknown-claims"), 1)
        self.assertEqual(self.value(report, "useful-fact-recall"), 1)

    def test_refusing_everything_retains_cost_without_perfect_accuracy(self):
        for row, answer in zip(self.rows, self.answers, strict=True):
            row["annotation"].update(abstained=True, claims=[])
            row["coverage"]["spans"] = {}
            answer["text"] = "I cannot answer from the supplied evidence."
            row["output"]["sha256"] = sha(answer["text"].encode())
        report = self.imported()
        for name in (
            "factual-precision",
            "brier",
            "citation-precision",
            "tokens-per-useful-fact",
        ):
            self.assertIsNone(self.value(report, name))
        self.assertEqual(self.value(report, "answerable-refusal"), 1)
        self.assertEqual(self.value(report, "correct-answer-yield"), 0)
        rows = [
            decode(line)
            for line in (self.output / "observations.jsonl").read_bytes().splitlines()
        ]
        cost = next(row for row in rows if row["metric"] == "tokens-per-useful-fact")
        self.assertEqual((cost["numerator"], cost["denominator"]), (100, 0))

    def test_failed_and_unsupported_runs_are_retained_as_incomplete_pairs(self):
        for status in ("failed", "unsupported"):
            with self.subTest(status=status):
                self.rows[1].update(status=status, annotation=None, coverage=None)
                report = self.imported()
                metric = report["metrics"]["correct-answer-yield"]
                self.assertIsNone(metric["treatments"]["candidate"]["value"])
                self.assertEqual(
                    metric["treatments"]["candidate"]["status_counts"][status], 1
                )
                self.assertEqual(metric["paired"]["status"], "incomplete")
                self.assertIsNone(metric["paired"]["mean_difference"])

    def test_unanswerable_abstention_has_no_invented_gold_or_precision(self):
        definition = self.study["tasks"][0]["definition"]
        definition.update(answerable=False, gold_facts=[])
        self.study["tasks"][0]["sha256"] = sha(encoded(definition))
        for row, answer in zip(self.rows, self.answers, strict=True):
            row["annotation"].update(
                answerable=False, gold_facts=[], abstained=True, claims=[]
            )
            row["coverage"]["spans"] = {}
            answer["text"] = "Insufficient evidence."
            row["output"]["sha256"] = sha(answer["text"].encode())
        report = self.imported()
        self.assertEqual(self.value(report, "unanswerable-abstention"), 1)
        self.assertEqual(self.value(report, "correct-answer-yield"), 0)
        for name in (
            "factual-precision",
            "useful-fact-recall",
            "answerable-success",
            "answerable-refusal",
        ):
            self.assertIsNone(self.value(report, name))

    def test_strata_cannot_hide_extra_unsupported_claims_and_pooled_denominators(self):
        task = copy.deepcopy(self.study["tasks"][0])
        task.update(
            id="authorization", cluster="repository-two", stratum="authorization"
        )
        task["definition"]["prompt"] = "What is the retry limit under this authority?"
        task["sha256"] = sha(encoded(task["definition"]))
        self.study["tasks"].append(task)
        extra = copy.deepcopy(self.rows)
        # Reversed outcomes in a second independent task; 1/2 and 1/1 claim
        # precision pool as 2/3, not the mean of per-answer rates (3/4).
        annotations = [copy.deepcopy(row["annotation"]) for row in self.rows[::-1]]
        coverages = [copy.deepcopy(row["coverage"]) for row in self.rows[::-1]]
        texts = [answer["text"] for answer in self.answers[::-1]]
        for row, annotation, coverage, text in zip(
            extra, annotations, coverages, texts, strict=True
        ):
            name = row["treatment"]
            annotation.update(
                episode_id=task["id"], treatment=name, stratum=task["stratum"]
            )
            identity = name + "-authorization"
            row.update(
                task=task["id"],
                annotation=annotation,
                coverage=coverage,
                output={"id": identity, "sha256": sha(text.encode())},
            )
            self.answers.append({"id": identity, "text": text})
        self.rows += extra
        report = self.imported()
        self.assertAlmostEqual(self.value(report, "factual-precision"), 2 / 3)
        self.assertAlmostEqual(
            self.value(report, "factual-precision", "candidate"), 2 / 3
        )
        self.assertEqual(
            report["strata"]["numeric"]["correct-answer-yield"]["paired"][
                "mean_difference"
            ],
            1,
        )
        self.assertEqual(
            report["strata"]["authorization"]["correct-answer-yield"]["paired"][
                "mean_difference"
            ],
            -1,
        )
        self.assertEqual(
            report["metrics"]["correct-answer-yield"]["paired"]["clusters"], 2
        )

    def test_repetitions_do_not_create_independent_task_clusters(self):
        original_rows, original_answers = (
            copy.deepcopy(self.rows),
            copy.deepcopy(self.answers),
        )
        for replicate in range(1, 9):
            for row, answer in zip(original_rows, original_answers, strict=True):
                new = copy.deepcopy(row)
                output_id = f"{answer['id']}-{replicate}"
                new.update(
                    replicate=replicate, output={**row["output"], "id": output_id}
                )
                self.rows.append(new)
                self.answers.append({**answer, "id": output_id})
        report = self.imported()
        paired = report["metrics"]["correct-answer-yield"]["paired"]
        self.assertEqual(paired["clusters"], 1)
        self.assertIsNone(paired["difference_ci95"])

    def test_answer_gold_identity_and_display_coverage_cannot_drift(self):
        original = copy.deepcopy(self.rows)
        mutations = [
            lambda r: r[0]["identity"].update(version="invented-version"),
            lambda r: r[0]["identity"].update(source_commit="f" * 40),
            lambda r: r[0]["identity"].update(artifacts=["candidate-worker"]),
            lambda r: r[0]["identity"].update(harness_sha256="0" * 64),
            lambda r: r[0]["annotation"].update(gold_facts=["other"]),
            lambda r: r[0]["annotation"].update(stratum="easier"),
            lambda r: r[0]["coverage"].update(reviewed_entire_display=False),
            lambda r: r[0]["coverage"]["spans"].pop("extra"),
            lambda r: r[0]["coverage"]["spans"].update(extra=[[19, 999]]),
            lambda r: r[0]["coverage"]["spans"].update(extra=[[True, 3]]),
            lambda r: r[0]["output"].update(sha256="0" * 64),
            lambda r: r[0].update(output=None),
            lambda r: r[0]["annotation"].update(unknown_extra=1),
            lambda r: r[0]["annotation"]["claims"][0].pop("confidence"),
            lambda r: r[0]["annotation"]["claims"][0].update(label="auto-approved"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.rows = copy.deepcopy(original)
                mutate(self.rows)
                with self.assertRaises(EvaluationError):
                    self.imported()

    def test_missing_duplicate_or_unaccounted_runs_cannot_disappear(self):
        originals = copy.deepcopy(self.rows)
        for rows in ([originals[0]], originals + [originals[0]]):
            self.rows = rows
            with self.assertRaises(EvaluationError):
                self.imported()
        self.rows = originals
        self.answers.append({"id": "extra", "text": "Unreported failure."})
        with self.assertRaisesRegex(EvaluationError, "unaccounted"):
            self.imported()

    def test_explicit_failed_row_may_have_no_display_but_cannot_supply_annotations(
        self,
    ):
        self.rows[1].update(status="failed", output=None)
        self.answers.pop()
        with self.assertRaisesRegex(EvaluationError, "annotations"):
            self.imported()
        self.rows[1].update(annotation=None, coverage=None)
        report = self.imported()
        self.assertEqual(report["observations"], 44)

    def test_authored_fixtures_cannot_be_promoted_to_model_efficacy(self):
        for evidence_class in ("answer-replay", "model-output"):
            self.study.update(evidence_class=evidence_class, model_mode="recorded")
            with self.assertRaisesRegex(EvaluationError, "independent annotations"):
                self.imported()
        self.study.update(oracle_kind="independently-adjudicated")
        with self.assertRaisesRegex(EvaluationError, "model identity"):
            self.imported()
        self.files["model"] = ("model", b"Unit-test model identity only.\n")
        with self.assertRaisesRegex(EvaluationError, "each answer treatment"):
            self.imported()
        for treatment, row in zip(self.study["treatments"], self.rows, strict=True):
            treatment["artifacts"].append("model")
            row["identity"]["artifacts"] = treatment["artifacts"].copy()
        report = self.imported()
        self.assertEqual(report["model_mode"], "recorded")
        self.assertIn("independence", " ".join(report["limitations"]))
        self.study["model_mode"] = "provider"
        with self.assertRaises(EvaluationError):
            self.imported()

    def test_input_artifact_and_json_tampering_fail_before_a_success_report(self):
        seal(self.source, self.study, self.files, self.answers, self.rows)
        (self.source / "baseline-worker.data").write_bytes(b"a substituted worker")
        with self.assertRaises(EvaluationError):
            import_study(self.source, self.root / "tampered")
        self.assertFalse((self.root / "tampered/result.json").exists())
        (self.source / "study.json").write_bytes(b'{"schema":"one","schema":"two"}')
        with self.assertRaises(EvaluationError):
            import_study(self.source, self.root / "ambiguous")


if __name__ == "__main__":
    unittest.main()
