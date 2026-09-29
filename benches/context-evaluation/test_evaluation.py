"""Adversarial evidence validation and statistical-unit regression tests."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evaluation import EvaluationError, decode, encoded, evaluate, validate_plan


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def fixture():
    plan = {
        "schema": "cigar.context-evaluation-plan.v1",
        "id": "unit-test-only",
        "evidence_class": "performance",
        "oracle_kind": "authored",
        "model_mode": "none",
        "cluster_unit": "process-cohort",
        "seed": 1400,
        "baseline": "baseline",
        "candidate": "candidate",
        "cohorts": [f"session-{i}" for i in range(8)],
        "inputs": {"corpus": "corpus", "oracle": "oracle", "harness": "harness"},
        "conditions": {
            "unit_test_fixture": True,
            "not_release_evidence": True,
            "token_budget": 256,
        },
        "treatments": [
            {
                "id": name,
                "version": version,
                "source_commit": commit * 40,
                "artifacts": ["worker"],
                "settings": {"mode": "shared"},
            }
            for name, version, commit in [
                ("baseline", "0.12.0", "a"),
                ("candidate", "0.14.0", "b"),
            ]
        ],
        "metrics": [
            {
                "id": "compile",
                "unit": "milliseconds",
                "aggregation": "median",
                "direction": "lower",
            },
            {
                "id": "evidence-recall",
                "unit": "ratio",
                "aggregation": "ratio",
                "direction": "higher",
            },
        ],
    }
    definition = {"query": "retry limit", "required": ["contract"], "max_tokens": 256}
    tasks = {
        "schema": "cigar.context-evaluation-tasks.v1",
        "tasks": [
            {
                "id": "retry",
                "sha256": digest(definition),
                "definition": definition,
                "cluster": "repository-a",
                "stratum": "numeric",
                "metrics": ["compile", "evidence-recall"],
            }
        ],
    }
    rows = []
    for cohort in plan["cohorts"]:
        for treatment in ("baseline", "candidate"):
            for metric in ("compile", "evidence-recall"):
                rows.append(
                    {
                        "schema": "cigar.context-observation.v1",
                        "task": "retry",
                        "treatment": treatment,
                        "cohort": cohort,
                        "replicate": 0,
                        "metric": metric,
                        "status": "ok",
                        "value": (10 if treatment == "baseline" else 8)
                        if metric == "compile"
                        else None,
                        "numerator": 1 if metric == "evidence-recall" else None,
                        "denominator": 2 if metric == "evidence-recall" else None,
                    }
                )
    return plan, tasks, rows


def seal(root, plan, tasks, rows):
    files = {
        "evaluator": (
            "evaluator",
            Path(__file__).with_name("evaluation.py").read_bytes(),
        ),
        "plan": ("plan", encoded(plan)),
        "tasks": ("tasks", encoded(tasks)),
        "observations": ("observations", b"".join(encoded(row) for row in rows)),
        "corpus": ("corpus", b"unit test document\n"),
        "oracle": ("oracle", b"unit test oracle\n"),
        "harness": ("harness", b"unit test harness; not executable evidence\n"),
        "worker": ("worker", b"unit test binary identity; not executable\n"),
    }
    artifacts = []
    for name, (role, payload) in files.items():
        path = f"{name}.data"
        (root / path).write_bytes(payload)
        artifacts.append(
            {
                "id": name,
                "role": role,
                "path": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    manifest = {
        "schema": "cigar.context-evaluation-manifest.v1",
        "plan": "plan",
        "tasks": "tasks",
        "observations": "observations",
        "evaluator": "evaluator",
        "artifacts": artifacts,
    }
    (root / "manifest.json").write_bytes(encoded(manifest))
    return manifest


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="context-evaluation-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.plan, self.tasks, self.rows = fixture()

    def result(self):
        seal(self.root, self.plan, self.tasks, self.rows)
        return evaluate(self.root)

    def test_metrics_are_recomputed_and_hashes_identify_exact_inputs(self):
        first = self.result()
        self.assertEqual(first, evaluate(self.root))
        self.assertEqual(
            first["manifest_sha256"],
            hashlib.sha256((self.root / "manifest.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(first["observations"], 32)
        compile_metric = first["metrics"]["compile"]
        self.assertEqual(compile_metric["treatments"]["baseline"]["value"], 10)
        self.assertEqual(compile_metric["treatments"]["candidate"]["value"], 8)
        self.assertEqual(compile_metric["paired"]["clusters"], 8)
        self.assertEqual(compile_metric["paired"]["difference_ci95"], [-2, -2])
        self.assertAlmostEqual(compile_metric["paired"]["mean_relative_change"], -0.2)
        self.assertEqual(
            first["metrics"]["evidence-recall"]["treatments"]["candidate"]["value"], 0.5
        )

    def test_repetition_does_not_inflate_independent_task_clusters(self):
        self.plan["cluster_unit"] = "task-cluster"
        self.rows += [
            {**row, "replicate": i} for i in range(1, 100) for row in list(self.rows)
        ]
        paired = self.result()["metrics"]["compile"]["paired"]
        self.assertEqual(paired["clusters"], 1)
        self.assertIsNone(paired["difference_ci95"])
        self.assertEqual(paired["mean_difference"], -2)

    def test_cluster_weight_is_not_proportional_to_repeated_call_count(self):
        first_cohort = []
        for row in self.rows:
            if row["cohort"] == "session-0" and row["metric"] == "compile":
                if row["treatment"] == "candidate":
                    row["value"] = 110
                first_cohort.append(row)
        self.rows += [
            {**row, "replicate": i} for i in range(1, 100) for row in first_cohort
        ]
        paired = self.result()["metrics"]["compile"]["paired"]
        self.assertEqual(paired["clusters"], 8)
        self.assertEqual(paired["mean_difference"], (100 - 2 * 7) / 8)

    def test_stratum_results_keep_regressions_visible(self):
        task = copy.deepcopy(self.tasks["tasks"][0])
        task.update(id="temporal", cluster="repository-b", stratum="temporal")
        task["definition"]["query"] = "current retry limit"
        task["sha256"] = digest(task["definition"])
        self.tasks["tasks"].append(task)
        other = [{**row, "task": "temporal"} for row in self.rows]
        for row in other:
            if row["metric"] == "compile" and row["treatment"] == "candidate":
                row["value"] = 100
        self.rows += other
        strata = self.result()["strata"]
        self.assertEqual(strata["numeric"]["compile"]["paired"]["mean_difference"], -2)
        self.assertEqual(strata["temporal"]["compile"]["paired"]["mean_difference"], 90)

    def test_a_changed_evaluator_cannot_reinterpret_bound_evidence(self):
        manifest = seal(self.root, self.plan, self.tasks, self.rows)
        artifact = next(
            item for item in manifest["artifacts"] if item["id"] == "evaluator"
        )
        payload = (
            self.root / artifact["path"]
        ).read_bytes() + b"\n# another evaluator revision\n"
        (self.root / artifact["path"]).write_bytes(payload)
        artifact.update(sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))
        (self.root / "manifest.json").write_bytes(encoded(manifest))
        with self.assertRaisesRegex(EvaluationError, "evaluator version"):
            evaluate(self.root)

    def test_zero_denominator_is_unknown_and_zero_baseline_has_no_relative_effect(self):
        for row in self.rows:
            if row["metric"] == "evidence-recall":
                row["numerator"] = row["denominator"] = 0
            elif row["treatment"] == "baseline":
                row["value"] = 0
        result = self.result()
        self.assertIsNone(
            result["metrics"]["evidence-recall"]["treatments"]["baseline"]["value"]
        )
        self.assertEqual(
            result["metrics"]["evidence-recall"]["paired"]["status"], "incomplete"
        )
        self.assertIsNone(
            result["metrics"]["compile"]["paired"]["mean_relative_change"]
        )
        self.assertEqual(result["metrics"]["compile"]["paired"]["mean_difference"], 8)

    def test_rates_use_denominators_instead_of_mean_of_percentages(self):
        for row in self.rows:
            if row["metric"] == "evidence-recall":
                row["numerator"] = 1
                row["denominator"] = 1 if row["cohort"] == "session-0" else 9
        value = self.result()["metrics"]["evidence-recall"]["treatments"]["baseline"][
            "value"
        ]
        self.assertEqual(value, 8 / 64)

    def test_token_efficiency_uses_total_cost_per_fact_without_bounding_it_to_one(self):
        self.plan["metrics"][1]["unit"] = "tokens-per-fact"
        for row in self.rows:
            if row["metric"] == "evidence-recall":
                row["numerator"] = 256
                row["denominator"] = 2
        metric = self.result()["metrics"]["evidence-recall"]
        self.assertEqual(metric["unit"], "tokens-per-fact")
        self.assertEqual(metric["treatments"]["baseline"]["value"], 128)
        for row in self.rows:
            if row["metric"] == "evidence-recall":
                row["denominator"] = 0
        unavailable = self.result()["metrics"]["evidence-recall"]
        self.assertIsNone(unavailable["treatments"]["baseline"]["value"])
        self.assertEqual(unavailable["paired"]["status"], "incomplete")

    def test_an_unsupported_or_failed_measurement_cannot_disappear_from_comparison(
        self,
    ):
        for status in ("unsupported", "failed"):
            with self.subTest(status=status):
                row = self.rows[0]
                row.update(status=status, value=None, numerator=None, denominator=None)
                metric = self.result()["metrics"]["compile"]
                self.assertEqual(
                    metric["treatments"]["baseline"]["status_counts"][status], 1
                )
                self.assertIsNone(metric["treatments"]["baseline"]["value"])
                self.assertEqual(metric["paired"]["status"], "incomplete")
                self.assertIsNone(metric["paired"]["difference_ci95"])

    def test_missing_unpaired_and_duplicate_rows_are_rejected(self):
        mutations = [
            lambda rows: rows[1:],
            lambda rows: rows + [rows[0]],
            lambda rows: [{**rows[0], "replicate": 7}, *rows[1:]],
        ]
        for change in mutations:
            with self.subTest(change=change):
                seal(self.root, self.plan, self.tasks, change(self.rows))
                with self.assertRaises(EvaluationError):
                    evaluate(self.root)

    def test_task_and_artifact_hash_changes_are_not_relabelled_as_valid_evidence(self):
        self.tasks["tasks"][0]["definition"]["max_tokens"] = 1024
        with self.assertRaisesRegex(EvaluationError, "task digest"):
            self.result()
        self.tasks["tasks"][0]["sha256"] = digest(self.tasks["tasks"][0]["definition"])
        self.result()
        path = self.root / "worker.data"
        path.write_bytes(b"X" * path.stat().st_size)
        with self.assertRaisesRegex(EvaluationError, "artifact digest"):
            evaluate(self.root)

    def test_artifact_paths_cannot_escape_the_directory(self):
        for path in (
            "../outside",
            "/absolute",
            "C:\\outside",
            "directory/../worker.data",
        ):
            with self.subTest(path=path):
                manifest = seal(self.root, self.plan, self.tasks, self.rows)
                manifest["artifacts"][-1]["path"] = path
                (self.root / "manifest.json").write_bytes(encoded(manifest))
                with self.assertRaises(EvaluationError):
                    evaluate(self.root)

    def test_symlink_artifacts_and_manifest_are_rejected(self):
        manifest = seal(self.root, self.plan, self.tasks, self.rows)
        link = self.root / "linked-worker.data"
        link.symlink_to(self.root / "worker.data")
        manifest["artifacts"][-1]["path"] = link.name
        (self.root / "manifest.json").write_bytes(encoded(manifest))
        with self.assertRaisesRegex(EvaluationError, "symlink"):
            evaluate(self.root)
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "manifest.json").symlink_to(self.root / "manifest.json")
        with self.assertRaisesRegex(EvaluationError, "symlink"):
            evaluate(nested)

    def test_replay_and_model_accuracy_labels_require_distinct_evidence(self):
        self.plan["evidence_class"] = "model-output"
        with self.assertRaisesRegex(EvaluationError, "independent"):
            self.result()
        self.plan["oracle_kind"] = "independently-adjudicated"
        self.plan["model_mode"] = "recorded"
        with self.assertRaisesRegex(EvaluationError, "model identity"):
            self.result()
        self.plan["evidence_class"] = "answer-replay"
        self.assertEqual(self.result()["evidence_class"], "answer-replay")
        self.plan["model_mode"] = "provider"
        with self.assertRaises(EvaluationError):
            self.result()

    def test_booleans_nonfinite_values_duplicate_json_members_and_extra_fields_fail(
        self,
    ):
        for value in (True, -1, 10**100):
            with self.subTest(value=value):
                self.rows[0]["value"] = value
                with self.assertRaises(EvaluationError):
                    self.result()
        for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            with self.subTest(payload=payload), self.assertRaises(EvaluationError):
                decode(payload)
        self.rows[0]["value"] = 1
        self.rows[0]["ignored_failure"] = True
        with self.assertRaises(EvaluationError):
            self.result()

    def test_reducer_and_evidence_identity_fields_fail_closed_for_wrong_types(self):
        for field in (
            "evidence_class",
            "oracle_kind",
            "model_mode",
            "cluster_unit",
            "baseline",
            "candidate",
        ):
            for value in ([], {}, 4, True, None):
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(EvaluationError),
                ):
                    plan = copy.deepcopy(self.plan)
                    plan[field] = value
                    validate_plan(plan, {})

    def test_metrics_are_kept_separate_from_any_precomputed_summary(self):
        manifest = seal(self.root, self.plan, self.tasks, self.rows)
        manifest["summary"] = {"all_tests_passed": True, "speedup": 100}
        (self.root / "manifest.json").write_bytes(json.dumps(manifest).encode())
        with self.assertRaisesRegex(EvaluationError, "manifest fields"):
            evaluate(self.root)


if __name__ == "__main__":
    unittest.main()
