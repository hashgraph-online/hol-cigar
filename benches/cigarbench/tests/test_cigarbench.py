from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "benches" / "cigarbench" / "cigarbench.py"
SPEC = importlib.util.spec_from_file_location("cigarbench", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cigarbench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cigarbench
SPEC.loader.exec_module(cigarbench)


class CigarBenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.temp = Path(self.directory.name)
        self.datasets = ROOT / "benches" / "cigarbench" / "datasets" / "manifest.json"
        self.baselines = ROOT / "baselines" / "cigarbench" / "manifest.json"
        self.canaries = ROOT / "benches" / "cigarbench" / "canaries.json"
        self.pins = (
            ROOT / "benches" / "cigarbench" / "pins" / "deterministic-consumer-v1.json"
        )
        self.environment = (
            ROOT / "benches" / "cigarbench" / "fixtures" / "smoke-environment.json"
        )
        self.public_seed = (
            ROOT / "benches" / "cigarbench" / "fixtures" / "public-smoke-seed.txt"
        )
        self.consumer = (
            ROOT / "benches" / "cigarbench" / "fixtures" / "recorded_consumer.py"
        )
        self.strata = [
            entry["stratum"]
            for entry in json.loads(self.datasets.read_text())["datasets"]
        ]

    def tearDown(self) -> None:
        self.directory.cleanup()

    def make_plan(
        self,
        seed: Path | None = None,
        replicates: int = 2,
        evidence_class: str = "harness_smoke",
    ) -> Path:
        output = self.temp / (
            f"plan-{seed.name if seed else 'public'}-{evidence_class}.json"
        )
        status = cigarbench.main(
            [
                "plan",
                "--datasets",
                str(self.datasets),
                "--baselines",
                str(self.baselines),
                "--canaries",
                str(self.canaries),
                "--pins",
                str(self.pins),
                "--environment",
                str(self.environment),
                "--seed-file",
                str(seed or self.public_seed),
                "--run-id",
                "smoke-run-v1",
                "--baseline-id",
                "full-transcript-project",
                "--replicates",
                str(replicates),
                "--evidence-class",
                evidence_class,
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 0)
        return output

    def test_hidden_seed_is_committed_not_disclosed_and_assignment_is_balanced(
        self,
    ) -> None:
        first_seed = self.temp / "first.seed"
        second_seed = self.temp / "second.seed"
        first_seed.write_bytes(b"a" * 32)
        second_seed.write_bytes(b"b" * 32)
        first = json.loads(self.make_plan(first_seed, 5).read_text())
        second = json.loads(self.make_plan(second_seed, 5).read_text())
        self.assertNotEqual(first["seed_commitment"], second["seed_commitment"])
        self.assertNotIn((b"a" * 32).decode(), json.dumps(first))
        self.assertNotEqual(first["assignment_digest"], second["assignment_digest"])
        by_stratum: dict[str, list[dict[str, object]]] = {}
        for assignment in first["assignments"]:
            if assignment["treatment"] == "baseline":
                by_stratum.setdefault(str(assignment["stratum"]), []).append(assignment)
        self.assertEqual(set(by_stratum), set(self.strata))
        for values in by_stratum.values():
            first_count = sum(value["order"] == 1 for value in values)
            self.assertLessEqual(abs(first_count - (len(values) - first_count)), 1)

    def test_paired_smoke_report_reproduces_and_cannot_claim_qualification(
        self,
    ) -> None:
        plan = self.make_plan()
        events = self.temp / "events.jsonl"
        self.assertEqual(
            cigarbench.main(
                [
                    "execute",
                    "--plan",
                    str(plan),
                    "--canaries",
                    str(self.canaries),
                    "--consumer-artifact",
                    str(self.consumer),
                    "--output",
                    str(events),
                    sys.executable,
                    str(self.consumer),
                ]
            ),
            0,
        )
        report = self.temp / "report.json"
        arguments = [
            "compare",
            "--events",
            str(events),
            "--plan",
            str(plan),
            "--datasets",
            str(self.datasets),
            "--baselines",
            str(self.baselines),
            "--canaries",
            str(self.canaries),
            "--environment",
            str(self.environment),
            "--seed-file",
            str(self.public_seed),
            "--bootstrap-repetitions",
            "200",
            "--output",
            str(report),
        ]
        self.assertEqual(cigarbench.main(arguments), 0)
        value = json.loads(report.read_text())
        self.assertEqual(value["decision"], "insufficient_evidence")
        self.assertFalse(value["qualification"]["eligible"])
        self.assertIn("non_qualification_evidence", value["qualification"]["reasons"])
        self.assertIn(
            "fewer_than_30_post_warm_pairs_per_stratum",
            value["qualification"]["reasons"],
        )
        self.assertIn(
            "fewer_than_30_independent_tasks_per_stratum",
            value["qualification"]["reasons"],
        )
        self.assertEqual(
            cigarbench.main(
                [
                    "replay",
                    "--events",
                    str(events),
                    "--report",
                    str(report),
                    "--plan",
                    str(plan),
                    "--datasets",
                    str(self.datasets),
                    "--baselines",
                    str(self.baselines),
                    "--canaries",
                    str(self.canaries),
                    "--environment",
                    str(self.environment),
                    "--seed-file",
                    str(self.public_seed),
                ]
            ),
            0,
        )
        wrong_seed = self.temp / "wrong.seed"
        wrong_seed.write_bytes(b"not the committed hidden seed value" * 2)
        with self.assertRaisesRegex(cigarbench.BenchError, "commit"):
            cigarbench.compare(
                type(
                    "Args",
                    (),
                    {
                        "events": events,
                        "plan": plan,
                        "datasets": self.datasets,
                        "baselines": self.baselines,
                        "canaries": self.canaries,
                        "environment": self.environment,
                        "seed_file": wrong_seed,
                        "attestation_key_file": None,
                        "bootstrap_repetitions": 200,
                        "output": self.temp / "wrong.json",
                        "require_qualification": False,
                    },
                )()
            )

    def test_release_gates_use_conservative_confidence_bounds(self) -> None:
        summary = {
            "physical_input_reduction_percent": {
                "median": 45.0,
                "median_ci95": [40.1, 48.0],
                "p25": 30.0,
                "p25_ci95": [25.1, 35.0],
            },
            "verified_success_delta_percentage_points": {
                "value": 0.0,
                "ci95": [-1.9, 1.0],
            },
            "cost_per_verified_success_improvement_percent": {
                "value": 15.0,
                "ci95": [10.1, 20.0],
            },
            "critical_recall_percent": {"value": 99.5, "ci95": [99.1, 100.0]},
            "context_precision_percent": {"value": 93.0, "ci95": [90.1, 95.0]},
            "context_caused_harm_percent": {"value": 0.0, "ci95": [0.0, 0.9]},
            "stale_harm_percent": {"value": 0.0, "ci95": [0.0, 0.9]},
            "prohibited_context_percent": {"value": 0.0, "ci95": [0.0, 0.0]},
            "unauthorized_context_count": 0,
        }
        self.assertNotIn("fail", cigarbench.gates(summary, True, False).values())
        summary["physical_input_reduction_percent"]["median_ci95"][0] = 39.9
        self.assertEqual(
            cigarbench.gates(summary, True, False)["median_physical_input_reduction"],
            "fail",
        )

    def test_tampered_event_and_incomplete_pair_fail_closed(self) -> None:
        plan = self.make_plan(replicates=1)
        events = self.temp / "events.jsonl"
        self.assertEqual(
            cigarbench.main(
                [
                    "execute",
                    "--plan",
                    str(plan),
                    "--canaries",
                    str(self.canaries),
                    "--consumer-artifact",
                    str(self.consumer),
                    "--output",
                    str(events),
                    sys.executable,
                    str(self.consumer),
                ]
            ),
            0,
        )
        lines = events.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["metrics"]["physical_input_tokens"] += 1
        lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        invalid = self.temp / "tampered.jsonl"
        invalid.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(cigarbench.BenchError, "identity"):
            cigarbench.load_events(invalid)
        incomplete = self.temp / "incomplete.jsonl"
        incomplete.write_text(events.read_text().splitlines()[0] + "\n")
        with self.assertRaisesRegex(cigarbench.BenchError, "incomplete"):
            cigarbench.paired(cigarbench.load_events(incomplete))

    def test_plan_binding_rejects_self_consistent_but_fabricated_event(self) -> None:
        plan = self.make_plan(replicates=1)
        events = self.temp / "bound-events.jsonl"
        self.assertEqual(
            cigarbench.main(
                [
                    "execute",
                    "--plan",
                    str(plan),
                    "--canaries",
                    str(self.canaries),
                    "--consumer-artifact",
                    str(self.consumer),
                    "--output",
                    str(events),
                    sys.executable,
                    str(self.consumer),
                ]
            ),
            0,
        )
        values = cigarbench.load_events(events)
        pair_id = values[0]["pair_id"]
        fabricated = []
        for event in values:
            value = dict(event)
            if value["pair_id"] == pair_id:
                value["task_id"] = "fabricated-task"
                value.pop("event_id")
                value = cigarbench.event_with_id(value)
            fabricated.append(value)
        with self.assertRaisesRegex(cigarbench.BenchError, "committed benchmark plan"):
            cigarbench.bind_events_to_plan(
                fabricated, cigarbench.validate_plan(cigarbench.load_json(plan))
            )
        rewritten_plan = cigarbench.load_json(plan)
        first_pair = rewritten_plan["assignments"][0]["pair_id"]
        for assignment in rewritten_plan["assignments"]:
            if assignment["pair_id"] == first_pair:
                assignment["order"] = 3 - assignment["order"]
        rewritten_plan.pop("assignment_digest")
        rewritten_plan["assignment_digest"] = cigarbench.sha256_multihash(
            cigarbench.canonical_bytes(rewritten_plan)
        )
        rewritten_plan = cigarbench.validate_plan(rewritten_plan)
        with self.assertRaisesRegex(cigarbench.BenchError, "hidden seed"):
            cigarbench.verify_seeded_assignments(
                rewritten_plan,
                cigarbench.validate_dataset_manifest(
                    cigarbench.load_json(self.datasets)
                ),
                cigarbench.seed_bytes(self.public_seed),
            )

    def test_evaluator_attestation_is_verified_but_repetition_is_not_independence(
        self,
    ) -> None:
        plan = self.make_plan(replicates=30, evidence_class="qualification")
        events = self.temp / "qualification-events.jsonl"
        self.assertEqual(
            cigarbench.main(
                [
                    "execute",
                    "--plan",
                    str(plan),
                    "--canaries",
                    str(self.canaries),
                    "--consumer-artifact",
                    str(self.consumer),
                    "--output",
                    str(events),
                    sys.executable,
                    str(self.consumer),
                ]
            ),
            0,
        )
        key = self.temp / "evaluator.key"
        key.write_bytes(b"independently-held-evaluator-key-0001")
        attested = self.temp / "attested.jsonl"
        self.assertEqual(
            cigarbench.main(
                [
                    "attest",
                    "--events",
                    str(events),
                    "--plan",
                    str(plan),
                    "--datasets",
                    str(self.datasets),
                    "--baselines",
                    str(self.baselines),
                    "--canaries",
                    str(self.canaries),
                    "--environment",
                    str(self.environment),
                    "--seed-file",
                    str(self.public_seed),
                    "--key-file",
                    str(key),
                    "--key-id",
                    "evaluator-v1",
                    "--output",
                    str(attested),
                ]
            ),
            0,
        )
        report = self.temp / "qualification-report.json"
        self.assertEqual(
            cigarbench.main(
                [
                    "compare",
                    "--events",
                    str(attested),
                    "--plan",
                    str(plan),
                    "--datasets",
                    str(self.datasets),
                    "--baselines",
                    str(self.baselines),
                    "--canaries",
                    str(self.canaries),
                    "--environment",
                    str(self.environment),
                    "--seed-file",
                    str(self.public_seed),
                    "--attestation-key-file",
                    str(key),
                    "--bootstrap-repetitions",
                    "200",
                    "--output",
                    str(report),
                ]
            ),
            0,
        )
        value = json.loads(report.read_text())
        self.assertTrue(value["qualification"]["evaluator_attestation"]["verified"])
        self.assertEqual(
            value["qualification"]["minimum_post_warm_pairs_per_stratum"], 30
        )
        self.assertEqual(
            value["qualification"]["minimum_independent_tasks_per_stratum"], 1
        )
        self.assertIn(
            "fewer_than_30_independent_tasks_per_stratum",
            value["qualification"]["reasons"],
        )
        tampered_events = cigarbench.load_events(attested)
        first = dict(tampered_events[0])
        first.pop("event_id")
        first["attestation"] = dict(first["attestation"])
        first["attestation"]["key_id"] = "substituted-evaluator"
        tampered_events[0] = cigarbench.event_with_id(first)
        with self.assertRaisesRegex(cigarbench.BenchError, "attestation"):
            cigarbench.verify_attestations(tampered_events, key)

    def test_canary_scan_reports_only_identifier_and_profile_guard_passes(self) -> None:
        safe = self.temp / "safe.json"
        safe.write_text('{"status":"content-free"}\n')
        registry = ROOT / "benches" / "cigarbench" / "canaries.json"
        self.assertEqual(
            cigarbench.main(["canary-scan", "--registry", str(registry), str(safe)]), 0
        )
        leaked = self.temp / "leaked.txt"
        leaked.write_text("BENCH_CANARY_POLICY_C28617")
        with self.assertRaises(cigarbench.BenchError) as failure:
            cigarbench.scan_canaries(
                type(
                    "Args",
                    (),
                    {"registry": registry, "target": [leaked], "maximum_bytes": 1024},
                )()
            )
        self.assertIn("policy", str(failure.exception))
        self.assertNotIn("BENCH_CANARY", str(failure.exception))
        self.assertEqual(
            cigarbench.main(["guard-profile", "--repository", str(ROOT)]), 0
        )

    def test_consumer_protocol_rejects_non_json_and_nonzero_processes(self) -> None:
        assignment = cigarbench.validate_plan(cigarbench.load_json(self.make_plan()))[
            "assignments"
        ][0]
        with self.assertRaises(cigarbench.BenchError):
            cigarbench.consumer_metrics(
                [sys.executable, "-c", "print('not json')"], assignment, 2.0
            )
        with self.assertRaises(cigarbench.BenchError):
            cigarbench.consumer_metrics(
                [sys.executable, "-c", "raise SystemExit(3)"], assignment, 2.0
            )
        metrics = cigarbench.consumer_metrics(
            [sys.executable, str(self.consumer)], assignment, 2.0
        )
        secret = "BENCH_CANARY_POLICY_C28617"
        leaking_consumer = self.temp / "leaking-consumer.py"
        leaking_consumer.write_text(
            "import json,os,sys\n"
            "from pathlib import Path\n"
            "json.load(sys.stdin)\n"
            f"Path(os.environ['HOME'], 'leak').write_text({secret!r})\n"
            f"sys.stdout.write({json.dumps(metrics)!r})\n"
        )
        with self.assertRaises(cigarbench.BenchError) as failure:
            cigarbench.consumer_metrics(
                [sys.executable, str(leaking_consumer)],
                assignment,
                2.0,
                [("policy", secret.encode())],
            )
        self.assertNotIn(secret, str(failure.exception))

    def test_cli_subprocess_has_content_free_failure(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "compare",
                "--events",
                str(self.temp / "missing"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(str(self.temp), completed.stderr.decode())


if __name__ == "__main__":
    unittest.main()
