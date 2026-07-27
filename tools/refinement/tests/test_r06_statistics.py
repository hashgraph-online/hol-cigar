from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from typing import Callable

from tools.refinement import canonical
from tools.refinement.corpus import STRATA
from tools.refinement.promotion import ParetoArchive, PromotionError, decide
from tools.refinement.promotion import replay as replay_decision
from tools.refinement.schema import SchemaRegistry
from tools.refinement.statistics import (
    REQUIRED_METRICS,
    compare,
    comparison_from_paths,
    load_policy,
    replay as replay_comparison,
)

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas/refinement"
POLICY_PATH = ROOT / "refinement/policy/promotion-v1.json"
HONEY_PATH = ROOT / "refinement/baselines/honey-anchor.v1.json"
MH = "1220" + "a" * 64

RATIO_METRICS = {
    "abstention_correctness",
    "citation_precision",
    "citation_recall",
    "conflict_correctness",
    "critical_context_recall",
    "evidence_item_precision",
    "evidence_sufficiency",
    "evidence_token_precision",
    "human_agreement",
    "selected_provenance_coverage",
    "temporal_correctness",
    "unsupported_claim_rate",
}
UNITS = {
    "verified_task_success": "boolean",
    "first_useful_evidence_rank": "rank",
    "physical_input_tokens": "tokens",
    "cache_read_tokens": "tokens",
    "cache_write_tokens": "tokens",
    "output_tokens": "tokens",
    "prohibited_materialized_tokens": "tokens",
    "latency_ms": "milliseconds",
    "cpu_ms": "milliseconds",
    "peak_rss_bytes": "bytes",
    "cost_usd": "usd",
}


def base_values(role: str) -> dict[str, float]:
    values = {name: 0.0 for name in REQUIRED_METRICS}
    values.update(
        {
            "verified_task_success": {
                "champion": 0.8,
                "candidate": 0.82,
                "honey": 0.75,
            }[role],
            "critical_context_recall": {
                "champion": 0.995,
                "candidate": 0.995,
                "honey": 0.99,
            }[role],
            "evidence_token_precision": {
                "champion": 0.92,
                "candidate": 0.92,
                "honey": 0.90,
            }[role],
            "evidence_item_precision": 0.9,
            "citation_recall": 0.9,
            "citation_precision": 0.9,
            "unsupported_claim_rate": 0.05,
            "temporal_correctness": 1.0,
            "conflict_correctness": 1.0,
            "abstention_correctness": 1.0,
            "evidence_sufficiency": 0.9,
            "first_useful_evidence_rank": 2.0,
            "selected_provenance_coverage": 1.0,
            "physical_input_tokens": 100.0,
            "cache_read_tokens": 10.0,
            "cache_write_tokens": 5.0,
            "output_tokens": 10.0,
            "latency_ms": 100.0,
            "cpu_ms": 50.0,
            "peak_rss_bytes": 100.0,
            "cost_usd": 1.0,
            "human_agreement": 1.0,
        }
    )
    return values


def metric_rows(values: dict[str, float]) -> list[dict[str, object]]:
    rows = []
    for name in sorted(REQUIRED_METRICS):
        value = values[name]
        unit = "ratio" if name in RATIO_METRICS else UNITS.get(name, "count")
        rows.append(
            {
                "name": name,
                "numerator": value,
                "denominator": 1,
                "value": value,
                "unit": unit,
                "applicable": True,
            }
        )
    return rows


Mutator = Callable[[str, str, str, int, int, float], float]


class StatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = SchemaRegistry(SCHEMAS)
        cls.policy, cls.policy_digest = load_policy(POLICY_PATH, cls.registry)
        cls.honey_bytes = HONEY_PATH.read_bytes()
        cls.honey = canonical.loads(cls.honey_bytes)

    def sample(
        self,
        *,
        evidence_class: str = "development",
        tasks: int = 2,
        seeds: int = 1,
        repetitions: int = 1000,
        confidence: int = 95,
        mutate: Mutator | None = None,
        candidate_revision: str = "c" * 40,
    ) -> dict[str, object]:
        pairs = []
        for stratum in STRATA:
            slug = stratum.lower().replace("-", "")
            for task_index in range(tasks):
                for seed in range(seeds):
                    treatments = {}
                    for role in ("champion", "candidate", "honey"):
                        values = base_values(role)
                        if mutate is not None:
                            values = {
                                name: mutate(
                                    role,
                                    name,
                                    stratum,
                                    task_index,
                                    seed,
                                    value,
                                )
                                for name, value in values.items()
                            }
                        treatments[role] = {
                            "evaluation_digest": canonical.identity(
                                {
                                    "role": role,
                                    "stratum": stratum,
                                    "task": task_index,
                                    "seed": seed,
                                    "candidate": candidate_revision,
                                }
                            ),
                            "metrics": metric_rows(values),
                        }
                    pairs.append(
                        {
                            "pair_id": f"pair-{slug}-{task_index:03d}-{seed:02d}",
                            "task_id": f"task-{slug}-{task_index:03d}",
                            "task_lineage_id": f"lineage-{slug}-{task_index:03d}",
                            "stratum": stratum,
                            "seed_index": seed,
                            **treatments,
                        }
                    )
        pairs.sort(key=lambda item: item["pair_id"])
        checks0 = [
            {
                "check_id": check,
                "passed": True,
                "attachment_digest": canonical.identity({"tier": 0, "check": check}),
            }
            for check in self.policy["tier0_checks"]
        ]
        checks1 = [
            {
                "check_id": check,
                "passed": True,
                "attachment_digest": canonical.identity({"tier": 1, "check": check}),
            }
            for check in self.policy["tier1_external_checks"]
        ]
        body = {
            "schema_version": "cigar.comparison-input.v1",
            "trial_id": f"trial-{candidate_revision[:8]}",
            "evidence_class": evidence_class,
            "champion_source": {"revision": "b" * 40, "tree": "1" * 40},
            "candidate_source": {"revision": candidate_revision, "tree": "2" * 40},
            "honey_source": {
                "revision": self.honey["source"]["release_commit"],
                "tree": self.honey["source"]["tree"],
            },
            "dataset_epoch": MH,
            "policy_digest": self.policy_digest,
            "bootstrap_repetitions": repetitions,
            "confidence_percent": confidence,
            "assignment_seed_digests": [
                canonical.identity({"seed": index}) for index in range(seeds)
            ],
            "tier0_checks": checks0,
            "tier1_checks": checks1,
            "pairs": pairs,
        }
        return {**body, "input_id": canonical.identity(body)}

    def run_comparison(self, value: dict[str, object]) -> dict[str, object]:
        payload = canonical.canonical_bytes(value)
        self.registry.validate("comparison-input-v1.schema.json", value)
        return compare(
            input_value=value,
            input_digest=canonical.multihash_bytes(payload),
            policy=self.policy,
            policy_digest=self.policy_digest,
            honey_anchor=self.honey,
            honey_anchor_bytes=self.honey_bytes,
            registry=self.registry,
        )

    def test_meaningful_paired_improvement_passes_holm_honey_and_replay(self) -> None:
        comparison = self.run_comparison(self.sample())
        metrics = {item["name"]: item for item in comparison["metrics"]}
        self.assertEqual(comparison["verdict"], "eligible")
        self.assertIn("verified_task_success", comparison["meaningful_improvements"])
        self.assertTrue(metrics["verified_task_success"]["holm_passed"])
        self.assertTrue(metrics["verified_task_success"]["seed_consistent"])
        self.assertTrue(metrics["verified_task_success"]["noninferior_honey"])
        self.assertEqual(len(comparison["metrics"]), len(REQUIRED_METRICS))
        decision = decide(comparison, self.registry)
        self.assertEqual(decision["decision"], "promote")
        self.assertEqual(decide(comparison, self.registry), decision)

    def test_faster_but_less_correct_and_leakier_fails(self) -> None:
        def mutate(role, name, _stratum, _task, _seed, value):
            if role == "candidate" and name == "verified_task_success":
                return 0.7
            if role == "candidate" and name == "authorization_violations":
                return 1
            if role == "candidate" and name in {"latency_ms", "physical_input_tokens"}:
                return 70
            return value

        comparison = self.run_comparison(self.sample(mutate=mutate))
        self.assertEqual(comparison["verdict"], "ineligible")
        self.assertIn("hard-invariant", comparison["reasons"])
        self.assertEqual(
            decide(comparison, self.registry)["decision"],
            "reject_hard_invariant",
        )

    def test_average_improvement_cannot_hide_protected_stratum_failure(self) -> None:
        def mutate(role, name, stratum, _task, _seed, value):
            if role == "candidate" and name == "verified_task_success":
                return 0.7 if stratum == "PolicyBoundary" else 0.84
            return value

        comparison = self.run_comparison(self.sample(mutate=mutate))
        protected = {item["stratum"]: item for item in comparison["protected_strata"]}
        self.assertEqual(protected["PolicyBoundary"]["status"], "failed")
        self.assertIn("protected-stratum", comparison["reasons"])
        self.assertEqual(
            decide(comparison, self.registry)["decision"], "reject_inferior"
        )

    def test_statistically_noisy_point_improvement_fails(self) -> None:
        def mutate(role, name, _stratum, task, _seed, value):
            if role == "candidate" and name == "verified_task_success":
                return 0.84 if task == 0 else 0.78
            return value

        comparison = self.run_comparison(self.sample(mutate=mutate))
        metric = next(
            item
            for item in comparison["metrics"]
            if item["name"] == "verified_task_success"
        )
        self.assertGreaterEqual(metric["benefit"], 0.009)
        self.assertFalse(metric["meaningful"])
        self.assertEqual(
            decide(comparison, self.registry)["decision"],
            "reject_no_meaningful_improvement",
        )

    def test_seed_direction_inconsistency_fails_as_overfit(self) -> None:
        def mutate(role, name, _stratum, _task, seed, value):
            if role == "candidate" and name == "verified_task_success":
                return 0.83 if seed == 0 else 0.79
            return value

        comparison = self.run_comparison(
            self.sample(seeds=2, mutate=mutate)
        )
        self.assertIn("seed-inconsistent", comparison["reasons"])
        self.assertEqual(
            decide(comparison, self.registry)["decision"],
            "reject_overfit_or_inconsistent",
        )

    def test_exact_noninferiority_slo_meaningful_and_performance_boundaries(self) -> None:
        def at_boundary(role, name, _stratum, _task, _seed, value):
            if role in {"champion", "candidate", "honey"} and name == "critical_context_recall":
                return 0.99
            if role == "candidate" and name == "verified_task_success":
                return 0.78
            if role == "candidate" and name == "latency_ms":
                return 110
            return value

        comparison = self.run_comparison(self.sample(mutate=at_boundary))
        metrics = {item["name"]: item for item in comparison["metrics"]}
        performance = {item["name"]: item for item in comparison["performance"]}
        self.assertTrue(metrics["verified_task_success"]["noninferior_champion"])
        self.assertTrue(metrics["critical_context_recall"]["absolute_slo_passed"])
        self.assertTrue(performance["latency_ms"]["noninferior"])

        def below(role, name, stratum, task, seed, value):
            value = at_boundary(role, name, stratum, task, seed, value)
            if role == "candidate" and name == "critical_context_recall":
                return 0.989999
            if role == "candidate" and name == "verified_task_success":
                return 0.779999
            if role == "candidate" and name == "latency_ms":
                return 110.0001
            return value

        failed = self.run_comparison(self.sample(mutate=below))
        metrics = {item["name"]: item for item in failed["metrics"]}
        performance = {item["name"]: item for item in failed["performance"]}
        self.assertFalse(metrics["verified_task_success"]["noninferior_champion"])
        self.assertFalse(metrics["critical_context_recall"]["absolute_slo_passed"])
        self.assertFalse(performance["latency_ms"]["noninferior"])

        def meaningful_exact(role, name, _stratum, _task, _seed, value):
            if role == "candidate" and name == "verified_task_success":
                return 0.81
            return value

        exact = self.run_comparison(self.sample(mutate=meaningful_exact))
        success = next(
            item
            for item in exact["metrics"]
            if item["name"] == "verified_task_success"
        )
        self.assertTrue(success["meaningful"])
        self.assertEqual(success["lower"], 0.01)

    def test_shadow_requires_99_percent_two_seeds_and_thirty_tasks(self) -> None:
        comparison = self.run_comparison(
            self.sample(
                evidence_class="shadow",
                tasks=30,
                seeds=2,
                repetitions=10_000,
                confidence=99,
            )
        )
        self.assertEqual(comparison["verdict"], "eligible")
        self.assertEqual(comparison["confidence_percent"], 99)
        self.assertEqual(comparison["assignment_seeds"], 2)
        self.assertEqual(comparison["bootstrap_repetitions"], 10_000)

    def test_tier0_sample_shortage_is_invalid_not_inferior(self) -> None:
        value = self.sample(
            evidence_class="shadow",
            tasks=2,
            seeds=1,
            repetitions=1000,
            confidence=95,
        )
        comparison = self.run_comparison(value)
        self.assertEqual(comparison["verdict"], "invalid")
        self.assertEqual(
            decide(comparison, self.registry)["decision"],
            "reject_invalid_evidence",
        )

    def test_nonpromoted_candidates_form_append_only_pareto_history(self) -> None:
        def no_gain(role, name, _stratum, _task, _seed, value):
            if role == "candidate" and name == "verified_task_success":
                return 0.8
            return value

        first = self.run_comparison(
            self.sample(mutate=no_gain, candidate_revision="d" * 40)
        )
        first_decision = decide(first, self.registry)
        self.assertEqual(
            first_decision["decision"], "reject_no_meaningful_improvement"
        )
        with tempfile.TemporaryDirectory() as raw:
            archive_root = Path(raw).resolve(strict=True) / "pareto"
            archive = ParetoArchive(archive_root, ROOT, SCHEMAS)
            record = archive.append(first, first_decision)
            self.assertEqual(record["frontier_after"], [first["comparison_id"]])
            self.assertEqual(archive.replay(), [record])

            def worse(role, name, _stratum, _task, _seed, value):
                if role == "candidate" and name == "verified_task_success":
                    return 0.79
                return value

            second = self.run_comparison(
                self.sample(mutate=worse, candidate_revision="f" * 40)
            )
            second_decision = decide(second, self.registry)
            second_record = archive.append(second, second_decision)
            self.assertEqual(second_record["dominated_by"], [first["comparison_id"]])
            self.assertEqual(second_record["frontier_after"], [first["comparison_id"]])
            self.assertEqual(len(archive.replay()), 2)
            with self.assertRaisesRegex(PromotionError, "already present"):
                archive.append(first, first_decision)
            with self.assertRaisesRegex(PromotionError, "not eligible"):
                archive.append(
                    self.run_comparison(self.sample(candidate_revision="e" * 40)),
                    decide(
                        self.run_comparison(
                            self.sample(candidate_revision="e" * 40)
                        ),
                        self.registry,
                    ),
                )

    def test_comparison_and_decision_replay_exactly_from_raw_attachment(self) -> None:
        value = self.sample()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(strict=True)
            input_path = root / "input.json"
            comparison_path = root / "comparison.json"
            decision_path = root / "decision.json"
            input_path.write_bytes(canonical.canonical_bytes(value))
            comparison = comparison_from_paths(
                input_path,
                POLICY_PATH,
                HONEY_PATH,
                SCHEMAS,
            )
            comparison_path.write_bytes(canonical.canonical_bytes(comparison))
            self.assertEqual(
                replay_comparison(
                    comparison_path,
                    input_path=input_path,
                    policy_path=POLICY_PATH,
                    honey_anchor_path=HONEY_PATH,
                    schemas=SCHEMAS,
                ),
                comparison,
            )
            decision = decide(comparison, self.registry)
            decision_path.write_bytes(canonical.canonical_bytes(decision))
            self.assertEqual(
                replay_decision(decision_path, comparison_path, SCHEMAS),
                decision,
            )


if __name__ == "__main__":
    unittest.main()
