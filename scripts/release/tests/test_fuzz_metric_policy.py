#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
RELEASE = REPOSITORY / "scripts" / "release"
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from assemble_evidence import _enforce_metric_gates  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


class FuzzMetricPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        requirements = json.loads(
            (REPOSITORY / "packaging" / "release-requirements.v1.json").read_text()
        )
        cls.requirements = {
            "metric_gates": [
                gate
                for gate in requirements["metric_gates"]
                if gate["category"] == "fuzz"
            ]
        }
        cls.target_names = sorted(
            gate["name"]
            for gate in cls.requirements["metric_gates"]
            if gate["name"].startswith("fuzz.target_seconds.")
        )
        cls.passing_receipt = {
            "category": "fuzz",
            "metrics": {
                **{name: 604_800 for name in cls.target_names},
                "fuzz.total_seconds": 8_467_200,
                "fuzz.unresolved_defect_count": 0,
            },
        }

    def test_policy_names_exact_fourteen_targets_and_reconciled_aggregate(self) -> None:
        self.assertEqual(len(self.target_names), 14)
        observed = _enforce_metric_gates(
            [deepcopy(self.passing_receipt)], self.requirements
        )
        self.assertEqual(observed["fuzz:fuzz.total_seconds"], 8_467_200)
        self.assertEqual(
            {name.removeprefix("fuzz.target_seconds.") for name in self.target_names},
            {
                "builtin_source_parsers",
                "canonical_json_cbor",
                "contract_compiler_candidates",
                "delta_roundtrip",
                "effect_journal_recovery",
                "extension_frames",
                "handoff_accept_merge",
                "identity_normalization",
                "manifest_explanation_redaction",
                "materializer_budget",
                "mcp_messages",
                "policy_parse_evaluate",
                "public_record_decoders",
                "replay_envelopes",
            },
        )

    def test_aggregate_only_or_duplicate_summary_cannot_pass(self) -> None:
        aggregate_only = deepcopy(self.passing_receipt)
        aggregate_only["metrics"] = {
            "fuzz.total_seconds": 8_467_200,
            "fuzz.unresolved_defect_count": 0,
        }
        with self.assertRaisesRegex(ReleaseError, "target inventory"):
            _enforce_metric_gates([aggregate_only], self.requirements)
        with self.assertRaisesRegex(ReleaseError, "exactly one"):
            _enforce_metric_gates(
                [deepcopy(self.passing_receipt), deepcopy(self.passing_receipt)],
                self.requirements,
            )

    def test_each_target_is_independently_mandatory_and_cannot_be_under_time(
        self,
    ) -> None:
        for name in self.target_names:
            with self.subTest(name=name):
                missing = deepcopy(self.passing_receipt)
                del missing["metrics"][name]
                with self.assertRaisesRegex(ReleaseError, "target inventory"):
                    _enforce_metric_gates([missing], self.requirements)

                under = deepcopy(self.passing_receipt)
                under["metrics"][name] -= 1
                under["metrics"]["fuzz.total_seconds"] -= 1
                with self.assertRaisesRegex(ReleaseError, "expected gte 604800"):
                    _enforce_metric_gates([under], self.requirements)

    def test_aggregate_must_equal_targets_and_defects_must_be_zero(self) -> None:
        mismatched = deepcopy(self.passing_receipt)
        mismatched["metrics"]["fuzz.total_seconds"] += 1
        with self.assertRaisesRegex(ReleaseError, "does not reconcile"):
            _enforce_metric_gates([mismatched], self.requirements)

        defective = deepcopy(self.passing_receipt)
        defective["metrics"]["fuzz.unresolved_defect_count"] = 1
        with self.assertRaisesRegex(ReleaseError, "expected lte 0"):
            _enforce_metric_gates([defective], self.requirements)

    def test_fractional_or_unexpected_target_metrics_fail_closed(self) -> None:
        fractional = deepcopy(self.passing_receipt)
        fractional["metrics"][self.target_names[0]] = 604_800.5
        fractional["metrics"]["fuzz.total_seconds"] = 8_467_200.5
        with self.assertRaisesRegex(ReleaseError, "nonnegative integer"):
            _enforce_metric_gates([fractional], self.requirements)

        unexpected = deepcopy(self.passing_receipt)
        unexpected["metrics"]["fuzz.target_seconds.not_governed"] = 604_800
        with self.assertRaisesRegex(ReleaseError, "target inventory"):
            _enforce_metric_gates([unexpected], self.requirements)


if __name__ == "__main__":
    unittest.main()
