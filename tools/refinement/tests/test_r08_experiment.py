from __future__ import annotations

# ruff: noqa: E402

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.canonical import identity, load_file
from tools.refinement.experiment import (
    ExperimentError,
    deduplicate_patches,
    hypothesis_fingerprint,
    load_families,
    make_signal,
    patch_fingerprints,
    schedule,
)
from tools.refinement.schema import SchemaRegistry

CHAMPION = {"revision": "a" * 40, "tree": "b" * 40}


def commitment(value: str) -> str:
    return identity({"commitment": value})


def signal(
    name: str,
    *,
    kind: str = "kpi_cluster",
    visibility: str = "public",
    summary: str | None = "Exact symbol evidence ranks after distractors.",
    owner: str | None = "lexical-scoring",
    metric: str = "critical_recall",
    magnitude: float = 0.4,
    cost: float = 5,
) -> dict[str, object]:
    return make_signal(
        source_kind=kind,
        visibility=visibility,
        summary=summary,
        source_commitment=commitment(name),
        owner_hint=owner,
        metric=metric,
        magnitude=magnitude,
        estimated_cost=cost,
        strata=["Needle-and-Distractor"],
        reproducible=True,
    )


def history(
    *,
    trial_id: str,
    family: str,
    fingerprint: str | None = None,
    outcome: str = "rejected",
    failure: str | None = "no-signal",
    effect: float = -0.1,
    cost: float = 10,
) -> dict[str, object]:
    return {
        "schema_version": "cigar.refinement-trial-history.v1",
        "trial_id": trial_id,
        "family_id": family,
        "hypothesis_fingerprint": fingerprint or commitment(trial_id),
        "patch_fingerprint": None,
        "outcome": outcome,
        "failure_category": failure,
        "primary_effect": effect,
        "evaluation_cost": cost,
        "model_dependent": False,
        "affected_strata": ["Needle-and-Distractor"],
    }


class ExperimentSchedulerTests(unittest.TestCase):
    def test_registry_is_schema_valid_and_separates_trial_classes(self) -> None:
        families = load_families()
        self.assertEqual(len(families), 8)
        product = [item for item in families if item["trial_class"] == "product"]
        infrastructure = [
            item for item in families if item["trial_class"] == "infrastructure"
        ]
        self.assertEqual(len(product), 7)
        self.assertEqual(len(infrastructure), 1)
        for family in product:
            self.assertIn("refinement", family["forbidden_paths"])
            self.assertFalse(
                any(path.startswith("refinement") for path in family["allowed_paths"])
            )
        self.assertIn("crates", infrastructure[0]["forbidden_paths"])
        registry = SchemaRegistry(ROOT / "schemas/refinement")
        registry.validate(
            "intervention-families-v1.schema.json",
            load_file(
                (ROOT / "refinement/profiles/intervention-families.v1.json").resolve()
            ),
        )

    def test_all_five_signal_sources_map_to_owner_paths(self) -> None:
        cases = [
            signal("kpi", kind="kpi_cluster"),
            signal(
                "profile",
                kind="profiler",
                owner="packing-dependency-closure",
                metric="latency_p95",
            ),
            signal("mutation", kind="mutation_survivor"),
            signal("test", kind="test_failure"),
            signal("issue", kind="issue"),
        ]
        decisions = []
        for item in cases:
            decision, packet = schedule(
                signals=[item],
                history=[],
                ledger_entries=[],
                champion=CHAMPION,
                trial_class="product",
                maximum_estimated_cost=100,
            )
            decisions.append(decision["selected_family_id"])
            self.assertTrue(packet["allowed_paths"])
        self.assertEqual(
            decisions,
            [
                "lexical-ranking",
                "packing-dependency",
                "lexical-ranking",
                "lexical-ranking",
                "lexical-ranking",
            ],
        )

    def test_hidden_signal_is_aggregate_only_and_packet_has_no_canary(self) -> None:
        with self.assertRaisesRegex(ExperimentError, "aggregate-only"):
            signal(
                "hidden-bad",
                visibility="aggregate_hidden",
                summary="SEALED-CANARY task 4 failed",
                owner=None,
            )
        hidden = signal(
            "hidden-good",
            visibility="aggregate_hidden",
            summary=None,
            owner=None,
        )
        decision, packet = schedule(
            signals=[hidden],
            history=[],
            ledger_entries=[],
            champion=CHAMPION,
            trial_class="product",
            maximum_estimated_cost=100,
        )
        serialized = json.dumps({"decision": decision, "packet": packet})
        self.assertNotIn("SEALED-CANARY", serialized)
        self.assertNotIn("task 4", serialized)
        self.assertIn(hidden["source_commitment"], packet["failure_cluster"])

    def test_exact_hypothesis_is_deduplicated_and_family_failures_downrank(
        self,
    ) -> None:
        lexical = signal("lexical", magnitude=0.6)
        packing = signal(
            "packing",
            owner="packing-dependency-closure",
            metric="evidence_token_precision",
            magnitude=0.4,
        )
        base_decision, _ = schedule(
            signals=[lexical, packing],
            history=[],
            ledger_entries=[],
            champion=CHAMPION,
            trial_class="product",
            maximum_estimated_cost=100,
        )
        self.assertEqual(base_decision["selected_family_id"], "lexical-ranking")
        failures = [
            history(trial_id=f"prior-{index}", family="lexical-ranking")
            for index in range(8)
        ]
        penalized, _ = schedule(
            signals=[lexical, packing],
            history=failures,
            ledger_entries=[],
            champion=CHAMPION,
            trial_class="product",
            maximum_estimated_cost=100,
        )
        self.assertEqual(penalized["selected_family_id"], "packing-dependency")
        family = next(
            item for item in load_families() if item["family_id"] == "lexical-ranking"
        )
        intervention = family["intervention_template"].format(metric=lexical["metric"])
        duplicate = hypothesis_fingerprint(
            "lexical-ranking", lexical["metric"], intervention, "product"
        )
        exact = history(
            trial_id="exact-prior",
            family="lexical-ranking",
            fingerprint=duplicate,
        )
        decision, _ = schedule(
            signals=[lexical, packing],
            history=[exact],
            ledger_entries=[],
            champion=CHAMPION,
            trial_class="product",
            maximum_estimated_cost=100,
        )
        self.assertTrue(
            any("duplicate-hypothesis" in reason for reason in decision["excluded"])
        )

    def test_patch_exact_and_near_duplicate_fingerprints_are_blocked(self) -> None:
        first = (
            b"diff --git a/a b/a\nindex 111..222 100644\n--- a/a\n+++ b/a\n"
            b"@@ -1 +1 @@\n-old\n+new\n"
        )
        near = first.replace(b"index 111..222", b"index aaa..bbb").replace(
            b"@@ -1 +1 @@", b"@@ -8 +8 @@"
        )
        other = first.replace(b"+new", b"+other")
        exact, semantic = patch_fingerprints(first)
        self.assertNotEqual(exact, semantic)
        accepted = deduplicate_patches([first, near, other], set())
        self.assertEqual(accepted, [first, other])
        self.assertEqual(deduplicate_patches([first], {semantic}), [])

    def test_budget_and_ledger_resume_select_the_next_packet(self) -> None:
        first = signal("first", magnitude=0.7, cost=5)
        second = signal(
            "second",
            owner="packing-dependency-closure",
            metric="evidence_token_precision",
            magnitude=0.5,
            cost=5,
        )
        over = signal("over", magnitude=1, cost=500)
        selected, packet = schedule(
            signals=[first, second, over],
            history=[],
            ledger_entries=[],
            champion=CHAMPION,
            trial_class="product",
            maximum_estimated_cost=10,
        )
        self.assertIn("over-budget", " ".join(selected["excluded"]))
        unsigned = dict(packet)
        claimed = unsigned.pop("packet_id")
        self.assertEqual(identity(unsigned), claimed)
        ledger = [
            {
                "event_type": "trial_rejected",
                "iteration_id": selected["selected_trial_id"],
            }
        ]
        resumed, resumed_packet = schedule(
            signals=[first, second, over],
            history=[],
            ledger_entries=ledger,
            champion=CHAMPION,
            trial_class="product",
            maximum_estimated_cost=10,
        )
        self.assertNotEqual(resumed["selected_trial_id"], selected["selected_trial_id"])
        self.assertNotEqual(resumed_packet["packet_id"], packet["packet_id"])
        self.assertIn("completed-ledger-trial", " ".join(resumed["excluded"]))

    def test_infrastructure_packet_cannot_edit_product_code(self) -> None:
        infrastructure = signal(
            "harness",
            kind="test_failure",
            owner="benchmark-evaluator-infrastructure",
            metric="harness_validity",
        )
        decision, packet = schedule(
            signals=[infrastructure],
            history=[],
            ledger_entries=[],
            champion=CHAMPION,
            trial_class="infrastructure",
            maximum_estimated_cost=100,
        )
        self.assertEqual(decision["selected_family_id"], "benchmark-infrastructure")
        self.assertIn("crates", packet["forbidden_paths"])
        self.assertTrue(
            all(not path.startswith("crates/") for path in packet["allowed_paths"])
        )
        with self.assertRaisesRegex(ExperimentError, "no eligible"):
            schedule(
                signals=[infrastructure],
                history=[],
                ledger_entries=[],
                champion=CHAMPION,
                trial_class="product",
                maximum_estimated_cost=100,
            )


if __name__ == "__main__":
    unittest.main()
