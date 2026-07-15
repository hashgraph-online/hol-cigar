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


class MutationMetricPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        requirements = json.loads(
            (REPOSITORY / "packaging" / "release-requirements.v1.json").read_text()
        )
        cls.requirements = {
            "metric_gates": [
                gate
                for gate in requirements["metric_gates"]
                if gate["category"] == "mutation"
            ]
        }
        cls.passing_receipt = {
            "category": "mutation",
            "metrics": {
                "mutation.score_percent": 90.0,
                "mutation.duration_seconds": 14_400,
                "mutation.production_package_fraction": 1.0,
                "mutation.timeout_count": 0,
                "mutation.critical_viable_survivor_count": 0,
            },
        }

    def test_exact_release_boundaries_pass(self) -> None:
        observed = _enforce_metric_gates(
            [deepcopy(self.passing_receipt)], self.requirements
        )
        self.assertEqual(
            set(observed),
            {f"mutation:{name}" for name in self.passing_receipt["metrics"]},
        )

    def test_every_release_mutation_metric_is_mandatory(self) -> None:
        for name in self.passing_receipt["metrics"]:
            with self.subTest(name=name):
                receipt = deepcopy(self.passing_receipt)
                del receipt["metrics"][name]
                with self.assertRaisesRegex(ReleaseError, "governed inventory"):
                    _enforce_metric_gates([receipt], self.requirements)

    def test_campaign_cannot_be_assembled_from_duplicate_or_partial_receipts(
        self,
    ) -> None:
        with self.assertRaisesRegex(ReleaseError, "exactly one complete campaign"):
            _enforce_metric_gates(
                [deepcopy(self.passing_receipt), deepcopy(self.passing_receipt)],
                self.requirements,
            )
        unexpected = deepcopy(self.passing_receipt)
        unexpected["metrics"]["mutation.synthetic"] = 1
        with self.assertRaisesRegex(ReleaseError, "governed inventory"):
            _enforce_metric_gates([unexpected], self.requirements)

    def test_integer_campaign_metrics_reject_boolean_and_fractional_values(
        self,
    ) -> None:
        for name, value in (
            ("mutation.duration_seconds", 14_400.0),
            ("mutation.timeout_count", False),
            ("mutation.critical_viable_survivor_count", False),
        ):
            receipt = deepcopy(self.passing_receipt)
            receipt["metrics"][name] = value
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ReleaseError, "invalid numeric types"),
            ):
                _enforce_metric_gates([receipt], self.requirements)

    def test_representative_or_incomplete_campaign_cannot_pass(self) -> None:
        inadequate = {
            "mutation.score_percent": 89.999,
            "mutation.duration_seconds": 14_399,
            "mutation.production_package_fraction": 0.999,
            "mutation.timeout_count": 1,
            "mutation.critical_viable_survivor_count": 1,
        }
        for name, value in inadequate.items():
            with self.subTest(name=name, value=value):
                receipt = deepcopy(self.passing_receipt)
                receipt["metrics"][name] = value
                with self.assertRaisesRegex(ReleaseError, "expected"):
                    _enforce_metric_gates([receipt], self.requirements)


if __name__ == "__main__":
    unittest.main()
