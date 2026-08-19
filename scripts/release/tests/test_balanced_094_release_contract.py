#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "packaging/honey/balanced-0.9.4-release-contract.v1.json"
RELEASE_NOTES = ROOT / "RELEASE_NOTES_HONEY_v0.9.4.md"


class Balanced094ReleaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(CONTRACT.read_bytes())
        cls.release_notes = RELEASE_NOTES.read_text(encoding="utf-8")

    def test_release_and_comparator_identities_are_exact(self) -> None:
        self.assertEqual(self.document["release"]["version"], "0.9.4")
        self.assertFalse(self.document["release"]["production_qualified"])
        comparators = {
            item["version"]: item for item in self.document["comparators"]
        }
        self.assertEqual(set(comparators), {"0.9.2", "0.9.3"})
        self.assertEqual(
            comparators["0.9.2"]["commit"],
            "35538959bce7497311906e4d370334a87abd362b",
        )
        self.assertEqual(
            comparators["0.9.2"]["tree"],
            "1157c5fb32b7faed65a8db5ae1e44505636b872f",
        )
        self.assertEqual(
            comparators["0.9.3"]["commit"],
            "a049fbc8ed81c9adc6b1a066ca053c5befc2578a",
        )
        self.assertEqual(
            comparators["0.9.3"]["tree"],
            "7179f2d0b78c8af314aebc8c86d62a0b6067e6ec",
        )

    def test_candidate_remains_unbound_and_v4_remains_opt_in(self) -> None:
        candidate = self.document["candidate"]
        self.assertEqual(candidate["final_source_binding"], "required-after-freeze")
        self.assertFalse(candidate["final_source_bound"])
        self.assertEqual(
            candidate["default_profile_during_qualification"], "balanced_v3"
        )
        self.assertEqual(candidate["qualification_profile"], "balanced_v4")
        self.assertEqual(candidate["release_profiles"], ["balanced_v4"])
        self.assertEqual(candidate["replay_profiles"], ["balanced_v1", "balanced_v3"])
        self.assertEqual(candidate["context_abi"], "cigar.context.v1")
        self.assertEqual(candidate["storage_format"], "sqlite-v5")
        self.assertEqual(candidate["public_operations"], 45)
        self.assertEqual(candidate["nominal_payload_types"], 70)

    def test_all_profile_identities_and_digests_are_pinned(self) -> None:
        profiles = self.document["profile_bindings"]
        self.assertEqual(set(profiles), {"balanced_v1", "balanced_v3", "balanced_v4"})
        self.assertEqual(
            profiles["balanced_v1"]["retrieval_digest"],
            "1220c605f248bd6f9d7c476324630b0839fb4c7423009f47f3f13b8b1a62cfeb72ea",
        )
        self.assertEqual(
            profiles["balanced_v3"]["compiler_digest"],
            "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7",
        )
        self.assertEqual(
            profiles["balanced_v4"]["retrieval_digest"],
            "1220f5e7f91cefdaea9b0748999b173fa38e005a350a6f533396e281d1c342c2d910",
        )
        self.assertEqual(
            profiles["balanced_v4"]["compiler_digest"],
            "1220d28b42286c3db066f73b70b670ee32b13311319fd512d682e9f843864749bcf2",
        )
        self.assertTrue(profiles["balanced_v1"]["immutable"])
        self.assertTrue(profiles["balanced_v3"]["immutable"])
        self.assertFalse(profiles["balanced_v4"]["repair_enabled"])

    def test_thresholds_and_observed_results_are_bounded(self) -> None:
        thresholds = self.document["thresholds"]
        context = thresholds["context_correctness_and_efficiency"]
        self.assertEqual(context["maximum_mean_exact_tokens"], 1050)
        self.assertEqual(
            context["minimum_useful_selection_precision_millionths"], 600_000
        )
        speed = thresholds["retrieval_compiler_speed"]
        self.assertEqual(
            speed["minimum_small_workflow_reducer_p95_improvement_millionths"],
            300_000,
        )
        self.assertEqual(
            speed[
                "minimum_request_allocation_reduction_at_128_and_512_candidates_millionths"
            ],
            400_000,
        )
        workflow = thresholds["actual_workflow"]
        self.assertEqual(workflow["minimum_delta_reuse_rate_millionths"], 700_000)
        self.assertEqual(workflow["required_negative_case_count"], 9)

        context_result = self.document["retained_results"][
            "source_linked_context_diagnostic"
        ]
        self.assertLessEqual(
            context_result["candidate_mean_exact_tokens"],
            context["maximum_mean_exact_tokens"],
        )
        self.assertEqual(context_result["treatment_observations"], 300)
        workflow_result = self.document["retained_results"][
            "deterministic_workflow_rc_diagnostic"
        ]
        self.assertEqual(workflow_result["candidate_observations"], 250)
        self.assertEqual(workflow_result["total_observations"], 750)
        self.assertGreaterEqual(
            workflow_result["candidate_mean_delta_reuse_millionths"],
            workflow["minimum_delta_reuse_rate_millionths"],
        )
        self.assertEqual(workflow_result["passed_claims"], 44)
        self.assertEqual(
            workflow_result["not_evaluated_claims"],
            ["H094-G07-128-512-allocation"],
        )
        allocation = self.document["retained_results"][
            "packing_allocation_source_qualification"
        ]
        self.assertEqual(allocation["status"], "pass-source-diagnostic-not-final-rc")
        self.assertTrue(allocation["final_rc_rerun_required"])
        self.assertEqual(allocation["candidate_counts"], [128, 512])
        self.assertEqual(allocation["measured_pairs_per_count"], 200)
        self.assertEqual(allocation["bootstrap_resamples"], 10_000)
        self.assertEqual(
            allocation["minimum_peak_live_reduction_millionths"],
            speed[
                "minimum_request_allocation_reduction_at_128_and_512_candidates_millionths"
            ],
        )
        for cell in allocation["cells"]:
            self.assertEqual(cell["status"], "passed")
            self.assertGreaterEqual(
                cell["peak_live_reduction_95pct_bootstrap_interval_millionths"][0],
                allocation["minimum_peak_live_reduction_millionths"],
            )
            self.assertLessEqual(cell["allocated_bytes_ratio_millionths"], 1_000_000)
            self.assertLessEqual(cell["allocation_count_ratio_millionths"], 1_000_000)

    def test_mandatory_gate_partition_is_exact_and_soak_is_last(self) -> None:
        gates = self.document["gate_results"]
        gate_ids = [gate["id"] for gate in gates]
        self.assertEqual(len(gate_ids), len(set(gate_ids)))
        self.assertEqual(set(gate_ids), set(self.document["mandatory_gates"]))
        statuses = {gate["id"]: gate["status"] for gate in gates}
        required_deferred = {
            "final-clean-source-binding",
            "manual-security-review",
            "installed-three-way-context-and-workflows",
            "upgrade-from-0.9.2-and-0.9.3",
            "binary-rollback-on-separately-restored-state",
            "clean-artifact-installs",
            "dependency-security-scanners",
            "fuzz-mutation-and-sanitizers",
            "checksums-sbom-provenance-and-license-bindings",
            "two-builder-reproducibility",
            "independent-evidence-recomputation",
            "signing-and-notarization",
            "release-owner-authorization",
        }
        self.assertTrue(
            all(statuses[gate_id] == "deferred" for gate_id in required_deferred)
        )
        self.assertEqual(
            statuses["dedicated-128-512-allocation-threshold"],
            "pass-source-qualification",
        )
        self.assertEqual(statuses["installed-runtime-soak-24h"], "deferred-last")
        self.assertFalse(
            self.document["known_limits"]["soak_may_run_before_other_candidate_gates"]
        )

    def test_release_authority_remains_closed(self) -> None:
        self.assertFalse(any(self.document["authority"].values()))
        self.assertFalse(
            self.document["known_limits"][
                "candidate_may_be_promoted_before_all_mandatory_gates_pass"
            ]
        )
        self.assertFalse(
            self.document["known_limits"]["source_tests_are_installed_artifact_tests"]
        )
        self.assertFalse(
            self.document["known_limits"][
                "retained_manual_review_covers_final_unbound_source"
            ]
        )
        self.assertFalse(
            self.document["retained_results"]["deterministic_workflow_rc_diagnostic"][
                "live_provider_campaign_executed"
            ]
        )

    def test_release_notes_keep_source_claims_bounded_by_retained_evidence(self) -> None:
        allocation = self.document["retained_results"][
            "packing_allocation_source_qualification"
        ]
        reductions = [
            cell["peak_live_reduction_millionths"] / 10_000
            for cell in allocation["cells"]
        ]
        self.assertIn(f"{reductions[0]:.3f}% and {reductions[1]:.3f}%", self.release_notes)
        self.assertIn(
            "This is source qualification\nfor commit `1d7bf983`, not final installed-RC evidence",
            self.release_notes,
        )
        self.assertIn("unpublished and unsupported", self.release_notes)
        self.assertIn("24-hour soak remains deliberately last", self.release_notes)
        for prohibited in ("production ready", "production-ready", "production qualified"):
            self.assertNotIn(prohibited, self.release_notes.lower())


if __name__ == "__main__":
    unittest.main()
