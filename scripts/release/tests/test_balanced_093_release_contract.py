#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "packaging/honey/balanced-0.9.3-release-contract.v1.json"


class Balanced093ReleaseContractTests(unittest.TestCase):
    def test_profile_and_version_are_exact(self) -> None:
        document = json.loads(CONTRACT.read_bytes())
        self.assertEqual(document["release"]["version"], "0.9.3")
        self.assertEqual(document["previous_candidate"]["version"], "0.9.2")
        self.assertEqual(document["candidate"]["default_profile"], "balanced_v3")
        self.assertEqual(document["candidate"]["release_profiles"], ["balanced_v3"])
        self.assertEqual(document["candidate"]["replay_profiles"], ["balanced_v1"])
        self.assertEqual(
            document["profile_bindings"]["balanced_v3"]["compiler_digest"],
            "12201c2f4519471391ad623c662f7bcce02b8f2c82ef79db844c9d20905a0ca22cb7",
        )

    def test_improvements_are_bounded_and_efficacy_fails_closed(self) -> None:
        improvements = json.loads(CONTRACT.read_bytes())["improvements"]
        token = improvements["token_reduction"]
        self.assertEqual(token["redundant_fixture_baseline_tokens"], 100)
        self.assertEqual(token["redundant_fixture_candidate_tokens"], 20)
        self.assertEqual(token["fixture_reduction_millionths"], 800_000)
        self.assertFalse(token["generalized_claim"])

        efficacy = improvements["completion_efficacy"]
        self.assertTrue(efficacy["blocking_candidates_protected"])
        self.assertTrue(efficacy["uncovered_blocking_requirement_fails_closed"])
        self.assertFalse(efficacy["live_provider_completion_claim"])

        speed = improvements["speed"]
        self.assertEqual(speed["bounded_similarity_work_before"], "cubic")
        self.assertEqual(speed["bounded_similarity_work_after"], "quadratic")
        self.assertTrue(speed["removed_inner_selected_candidate_scan"])
        self.assertEqual(speed["operation_count_fixture_candidates"], 128)
        self.assertEqual(speed["prior_similarity_evaluations"], 349_504)
        self.assertEqual(speed["candidate_similarity_updates"], 8_128)
        self.assertEqual(speed["similarity_work_reduction_millionths"], 976_744)

    def test_release_authority_remains_closed(self) -> None:
        document = json.loads(CONTRACT.read_bytes())
        self.assertFalse(any(document["authority"].values()))
        self.assertIn("critical-requirement-recall", document["mandatory_gates"])
        self.assertIn("latency-nonregression", document["mandatory_gates"])


if __name__ == "__main__":
    unittest.main()
