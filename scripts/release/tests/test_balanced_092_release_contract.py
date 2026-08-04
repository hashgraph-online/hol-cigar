#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "packaging/honey/balanced-0.9.2-release-contract.v1.json"


class Balanced092ReleaseContractTests(unittest.TestCase):
    def test_contract_freezes_published_0_9_1_as_the_only_baseline(self) -> None:
        document = json.loads(CONTRACT.read_bytes())
        baseline = document["published_baseline"]
        self.assertEqual(baseline["version"], "0.9.1")
        self.assertEqual(baseline["git_tag"], "hol-cigar-v0.9.1-pypi.2")
        self.assertEqual(
            baseline["commit"], "ee9b52b69f4245c27b46da6ef2fc4a070430caed"
        )
        self.assertEqual(
            baseline["tree"], "7c36625bfa09417150f3b0ec6dafc7161105234f"
        )
        self.assertEqual(
            baseline["roles"], ["sole-comparator", "rollback-reference"]
        )
        self.assertEqual(
            [item["sha256"] for item in baseline["python_artifacts"]],
            [
                "4b2f9299aa5fddbd848d0ec95c488eb5d0b3904c6718e6dec0537e7f37edbe75",
                "20bef5e8c08c68b301ed6e400b25f472541f013b10d7e34b499db18f7b1ed125",
            ],
        )

    def test_contract_is_balanced_only_and_excludes_h1_from_every_role(self) -> None:
        document = json.loads(CONTRACT.read_bytes())
        candidate = document["candidate"]
        self.assertEqual(candidate["release_profiles"], ["balanced_v1"])
        self.assertEqual(candidate["default_profile"], "balanced_v1")
        self.assertEqual(
            candidate["capability_identifiers"], ["intelligence-balanced-v1"]
        )
        excluded = document["excluded_experiment"]
        self.assertEqual(excluded["id"], "h1")
        self.assertEqual(excluded["disposition"], "terminal-failure")
        self.assertEqual(excluded["historical_evidence_use"], "audit-only")
        for field in (
            "runtime_selectable",
            "release_candidate",
            "comparator",
            "fallback",
            "qualification_input",
            "release_claim_source",
            "may_be_relabeled_balanced",
        ):
            self.assertFalse(excluded[field])

    def test_contract_binds_frozen_inputs_and_fail_closed_thresholds(self) -> None:
        document = json.loads(CONTRACT.read_bytes())
        for binding in document["frozen_inputs"].values():
            payload = ROOT / binding["path"]
            self.assertTrue(payload.is_file())
            self.assertEqual(hashlib.sha256(payload.read_bytes()).hexdigest(), binding["sha256"])
        cohort = document["comparison_cohort"]
        self.assertEqual(cohort["requests"], 100)
        self.assertEqual(cohort["requests_per_workflow"], 20)
        self.assertEqual(len(cohort["workflows"]), 5)
        self.assertTrue(cohort["authenticated_governed_lineage_counts_required"])
        self.assertTrue(cohort["source_diversity_is_not_lineage_proxy"])
        self.assertFalse(cohort["cross_arm_cache_reuse"])
        storage_policy = document["storage_policy"]
        self.assertEqual(storage_policy["checkpoint_cadence_matrix"], [4, 16, 64, 128, 256])
        self.assertEqual(
            storage_policy["release_default_maximum_deltas_since_checkpoint"], 4
        )
        self.assertEqual(storage_policy["protocol_maximum_deltas_since_checkpoint"], 256)
        self.assertEqual(storage_policy["focused_startup_repetitions"], 40)
        self.assertFalse(storage_policy["thresholds_modified_after_observation"])
        thresholds = document["thresholds"]
        self.assertEqual(thresholds["maximum_security_policy_violations"], 0)
        self.assertEqual(thresholds["maximum_duplicate_selected_content"], 0)
        self.assertEqual(thresholds["maximum_latency_regression_millionths"], 200000)
        self.assertEqual(thresholds["minimum_storage_improvement_millionths"], 100000)
        self.assertEqual(thresholds["maximum_growth_bytes_per_compilation"], 1048575)
        self.assertEqual(thresholds["minimum_meaningful_improvements"], 1)
        self.assertFalse(any(document["authority"].values()))


if __name__ == "__main__":
    unittest.main()
