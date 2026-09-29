"""Authored contract fixtures, never independent task efficacy or release evidence."""

from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from evaluation import EvaluationError, decode, encoded, evaluate
from import_hiero import field_matches, import_study


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def fixture(ai_mode="mock"):
    definition = {
        "workflow": "evm-tx-liveness",
        "ai_mode": ai_mode,
        "target_revision": "c" * 40,
        "requested_iterations": 2,
        "goal": "one durable accepted operation",
    }
    task = {
        "id": "ledger",
        "definition": definition,
        "sha256": sha(encoded(definition)),
        "cluster": "repository-one",
        "stratum": "effect",
    }
    study = {
        "schema": "cigar.hiero-study.v1",
        "id": "hiero-import-unit-only",
        "evidence_class": "invariant",
        "oracle_kind": "authored",
        "model_mode": "none",
        "cluster_unit": "task-cluster",
        "seed": 14,
        "baseline": "baseline",
        "candidate": "candidate",
        "cohorts": ["pair-1"],
        "conditions": {"unit_fixture": True, "no_independent_task_claim": True},
        "treatments": [
            {
                "id": name,
                "version": version,
                "source_commit": letter * 40,
                "artifacts": [f"{name}-worker"],
                "settings": {"compiler": "required", "ai": "mock"},
            }
            for name, version, letter in (
                ("baseline", "0.12.0", "a"),
                ("candidate", "0.14.0", "b"),
            )
        ],
        "tasks": [task],
        "inputs": {
            "corpus": "corpus",
            "oracle": "oracle",
            "harness": "harness",
            "records": "records",
            "terminal_reader": "reader",
            "campaign_receipts": [],
        },
        "artifacts": [],
    }
    oracle = {
        "schema": "hiero.context-task-oracles.v1",
        "tasks": [
            {
                "task": "ledger",
                "task_sha256": task["sha256"],
                "mode": "terminal-readback",
                "checks": [
                    {"id": "state", "path": ["effect_state"], "equals": "applied"},
                    {"id": "count", "path": ["send_count"], "equals": 1},
                ],
            }
        ],
    }
    files = {
        "corpus": ("corpus", b"Authored ledger fixture, not target execution.\n"),
        "oracle": ("oracle", encoded(oracle)),
        "harness": ("harness", b"Retained producer identity, never loaded.\n"),
        "reader": ("harness", b"Retained reader identity, never loaded.\n"),
    }
    rows = []
    for treatment in study["treatments"]:
        name = treatment["id"]
        files[f"{name}-worker"] = ("worker", f"fake {name} worker\n".encode())
        execution = {
            "workflow": definition["workflow"],
            "requested_iterations": 2,
            "command": [
                "python",
                "-m",
                "fake_hiero_campaign",
                "--campaign-id",
                name,
                "--ref",
                definition["target_revision"],
                "--max-iterations",
                "2",
                "--ai-provider",
                "mock",
            ],
            "ai_provider": "mock",
            "live_ai": False,
            "compiler_mode": "required",
            "cigar_version": treatment["version"],
            "compiler_binary_sha256": sha(files[f"{name}-worker"][1]),
            "exit_code": 0,
            "seconds": 2 if name == "baseline" else 3,
            "completed_iterations": 2,
            "iteration_files": 2,
        }
        files[f"{name}-execution"] = ("source", encoded(execution))
        if ai_mode == "not-used":
            execution["command"] = execution["command"][:-2]
            files[f"{name}-execution"] = ("source", encoded(execution))
        iterations = []
        for index in (1, 2):
            key = f"{name}-iteration-{index}"
            iterations.append(key)
            files[key] = (
                "source",
                encoded(
                    {
                        "iteration": index,
                        "context_quality_status": "passed",
                        "target_executing_validation_count": 0,
                        "synthetic_harness_self_test_count": 2,
                        "oracle_validated_count": 999,
                        "token_budget_used": index * 100,
                    }
                ),
            )
        terminal = {
            "schema": "hiero.context-terminal-readback.v1",
            "campaign_id": name,
            "task": "ledger",
            "task_sha256": task["sha256"],
            "treatment": name,
            "cohort": "pair-1",
            "replicate": 0,
            "target_revision": definition["target_revision"],
            "execution_sha256": sha(files[f"{name}-execution"][1]),
            "oracle_sha256": sha(files["oracle"][1]),
            "reader_sha256": sha(files["reader"][1]),
            "mode": "target",
            "complete": True,
            "state": {
                "effect_state": "failed" if name == "baseline" else "applied",
                "send_count": 1,
            },
        }
        files[f"{name}-terminal"] = ("source", encoded(terminal))
        study["inputs"]["campaign_receipts"].extend(
            [f"{name}-execution", *iterations, f"{name}-terminal"]
        )
        rows.append(
            {
                "schema": "cigar.hiero-campaign-observation.v1",
                "task": "ledger",
                "treatment": name,
                "cohort": "pair-1",
                "replicate": 0,
                "status": "ok",
                "identity": {
                    **{
                        key: treatment[key]
                        for key in ("version", "source_commit", "artifacts")
                    },
                    "harness_sha256": sha(files["harness"][1]),
                },
                "campaign_id": name,
                "execution": f"{name}-execution",
                "iterations": iterations,
                "terminal": f"{name}-terminal",
            }
        )
    return study, files, rows


def seal(directory, study, files, rows):
    files = {
        **files,
        "records": ("observations", b"".join(encoded(row) for row in rows)),
    }
    inventory = []
    for name, (role, payload) in files.items():
        path = f"{name}.data"
        (directory / path).write_bytes(payload)
        inventory.append(
            {
                "id": name,
                "role": role,
                "path": path,
                "sha256": sha(payload),
                "bytes": len(payload),
            }
        )
    (directory / "study.json").write_bytes(encoded({**study, "artifacts": inventory}))


class HieroImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-hiero-import-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "input"
        self.source.mkdir()
        self.study, self.files, self.rows = fixture()
        self.attempt = 0

    def imported(self):
        seal(self.source, self.study, self.files, self.rows)
        self.attempt += 1
        self.output = self.root / f"result-{self.attempt}"
        return import_study(self.source, self.output)

    def value(self, report, metric, treatment="baseline"):
        return report["metrics"][metric]["treatments"][treatment]["value"]

    def change(self, name, **updates):
        role, payload = self.files[name]
        self.files[name] = (role, encoded({**decode(payload), **updates}))

    def test_exit_and_synthetic_oracle_counts_cannot_replace_terminal_truth(self):
        report = self.imported()
        self.assertEqual(self.value(report, "process-exit-success"), 1)
        self.assertEqual(self.value(report, "campaign-complete"), 1)
        self.assertEqual(self.value(report, "declared-context-quality-pass"), 1)
        self.assertEqual(self.value(report, "declared-synthetic-self-tests"), 4)
        self.assertEqual(self.value(report, "declared-target-executions"), 0)
        self.assertEqual(self.value(report, "declared-context-tokens"), 300)
        self.assertEqual(self.value(report, "terminal-contract-success"), 0)
        self.assertEqual(
            self.value(report, "terminal-contract-success", "candidate"), 1
        )
        self.assertEqual(self.value(report, "terminal-check-pass"), 0.5)
        self.assertEqual(self.value(report, "campaign-wall-ms"), 2000)
        paired = report["metrics"]["terminal-contract-success"]["paired"]
        self.assertEqual(paired["clusters"], 1)
        self.assertIsNone(paired["difference_ci95"])
        self.assertEqual(evaluate(self.output), report)
        self.assertEqual(
            import_study(self.output / "raw", self.root / "reimport"), report
        )
        with self.assertRaisesRegex(EvaluationError, "already exists"):
            import_study(self.source, self.output)

    def test_synthetic_or_partial_readback_is_unavailable_not_perfect(self):
        for updates in ({"mode": "synthetic"}, {"mode": "target", "complete": False}):
            with self.subTest(updates=updates):
                self.change("candidate-terminal", **updates)
                report = self.imported()
                self.assertIsNone(
                    self.value(report, "terminal-contract-success", "candidate")
                )
                self.assertEqual(
                    report["metrics"]["terminal-check-pass"]["paired"]["status"],
                    "incomplete",
                )

    def test_missing_terminal_oracle_does_not_become_a_zero_or_success(self):
        for row in self.rows:
            self.study["inputs"]["campaign_receipts"].remove(row["terminal"])
            del self.files[row["terminal"]]
            row["terminal"] = None
        self.study["inputs"]["terminal_reader"] = None
        oracle = decode(self.files["oracle"][1])
        oracle["tasks"][0].update(mode="unavailable", checks=[])
        self.files["oracle"] = ("oracle", encoded(oracle))
        report = self.imported()
        self.assertIsNone(self.value(report, "terminal-contract-success"))
        self.assertEqual(self.value(report, "campaign-complete"), 1)
        self.study.update(evidence_class="task-outcome", oracle_kind="executable")
        with self.assertRaisesRegex(EvaluationError, "requires bound terminal"):
            self.imported()

    def test_process_failure_can_coexist_with_a_confirmed_target_outcome(self):
        self.change("candidate-execution", exit_code=124, completed_iterations=None)
        self.change(
            "candidate-terminal",
            execution_sha256=sha(self.files["candidate-execution"][1]),
        )
        report = self.imported()
        self.assertEqual(self.value(report, "process-exit-success", "candidate"), 0)
        self.assertEqual(self.value(report, "campaign-complete", "candidate"), 0)
        self.assertEqual(
            self.value(report, "terminal-contract-success", "candidate"), 1
        )

    def test_failed_observation_keeps_an_incomplete_pair(self):
        row = self.rows[1]
        for name in [row["execution"], *row["iterations"], row["terminal"]]:
            self.study["inputs"]["campaign_receipts"].remove(name)
            del self.files[name]
        row.update(status="failed", execution=None, iterations=[], terminal=None)
        report = self.imported()
        for metric in report["metrics"].values():
            self.assertIsNone(metric["treatments"]["candidate"]["value"])
            self.assertEqual(metric["paired"]["status"], "incomplete")

    def test_missing_declared_fields_remain_unknown(self):
        for name in self.rows[0]["iterations"]:
            self.change(
                name,
                token_budget_used=None,
                target_executing_validation_count=None,
                context_quality_status=None,
            )
        report = self.imported()
        for name in (
            "declared-context-tokens",
            "declared-target-executions",
            "declared-context-quality-pass",
        ):
            self.assertIsNone(self.value(report, name))

    def test_explicit_no_ai_workflow_does_not_invent_a_provider_option(self):
        self.study, self.files, self.rows = fixture("not-used")
        self.assertEqual(self.value(self.imported(), "campaign-complete"), 1)
        execution = decode(self.files["baseline-execution"][1])
        execution["command"] += ["--ai-provider", "mock"]
        self.change("baseline-execution", command=execution["command"])
        with self.assertRaises(EvaluationError):
            self.imported()

    def test_terminal_binding_rejects_every_cross_campaign_substitution(self):
        original = copy.deepcopy(self.files)
        for field, value in (
            ("campaign_id", "another"),
            ("task", "another"),
            ("task_sha256", "0" * 64),
            ("treatment", "candidate"),
            ("cohort", "pair-2"),
            ("replicate", False),
            ("target_revision", "d" * 40),
            ("execution_sha256", "0" * 64),
            ("oracle_sha256", "0" * 64),
            ("reader_sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                self.files = copy.deepcopy(original)
                self.change("baseline-terminal", **{field: value})
                with self.assertRaises(EvaluationError):
                    self.imported()

    def test_original_worker_command_and_offline_identity_are_bound(self):
        original = copy.deepcopy(self.files)
        changes = (
            {"cigar_version": "fake"},
            {"compiler_binary_sha256": "0" * 64},
            {"workflow": "wrong"},
            {"requested_iterations": True},
            {"live_ai": True},
            {"ai_provider": "provider"},
            {"compiler_mode": "optional"},
            {"command": ["--campaign-id", "baseline"]},
            {"exit_code": True},
            {"seconds": -1},
            {"iteration_files": 1},
            {"completed_iterations": 3},
        )
        for change in changes:
            with self.subTest(change=change):
                self.files = copy.deepcopy(original)
                self.change("baseline-execution", **change)
                with self.assertRaises(EvaluationError):
                    self.imported()
        self.files = original
        self.rows[0]["identity"]["source_commit"] = "f" * 40
        with self.assertRaises(EvaluationError):
            self.imported()

    def test_lost_duplicated_reused_and_unaccounted_receipts_are_rejected(self):
        original = copy.deepcopy(self.rows)
        for mutation in (
            lambda rows: rows[0]["iterations"].pop(),
            lambda rows: rows[0]["iterations"].reverse(),
            lambda rows: rows[0]["iterations"].__setitem__(1, rows[0]["iterations"][0]),
            lambda rows: rows[1].update(terminal=rows[0]["terminal"]),
            lambda rows: rows[0].update(terminal=None),
        ):
            self.rows = copy.deepcopy(original)
            mutation(self.rows)
            with self.assertRaises(EvaluationError):
                self.imported()
        self.rows = original + [original[0]]
        with self.assertRaises(EvaluationError):
            self.imported()

    def test_task_oracle_changes_and_empty_checks_are_rejected(self):
        original = copy.deepcopy(self.files)
        for change in ({"checks": []}, {"task_sha256": "0" * 64}, {"task": "other"}):
            self.files = copy.deepcopy(original)
            oracle = decode(self.files["oracle"][1])
            oracle["tasks"][0].update(change)
            self.files["oracle"] = ("oracle", encoded(oracle))
            with self.assertRaises(EvaluationError):
                self.imported()

    def test_field_oracle_uses_exact_json_types_and_real_paths(self):
        self.assertTrue(
            field_matches(
                {"a": [None, {"b": False}]}, {"path": ["a", 1, "b"], "equals": False}
            )
        )
        for expected in (0, 0.0, "false", None):
            self.assertFalse(
                field_matches({"a": False}, {"path": ["a"], "equals": expected})
            )
        self.assertFalse(
            field_matches({"a": {}}, {"path": ["a", "missing"], "equals": None})
        )
        self.assertFalse(field_matches({"a": []}, {"path": ["a", 0], "equals": None}))

    def test_mutated_original_bytes_and_duplicate_json_do_not_import(self):
        seal(self.source, self.study, self.files, self.rows)
        (self.source / "baseline-worker.data").write_bytes(b"tampered")
        with self.assertRaises(EvaluationError):
            import_study(self.source, self.root / "bad-hash")
        self.files["baseline-execution"] = ("source", b'{"exit_code":0,"exit_code":1}')
        with self.assertRaises(EvaluationError):
            self.imported()


if __name__ == "__main__":
    unittest.main()
