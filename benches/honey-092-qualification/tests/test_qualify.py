from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "qualify.py"
SPEC = importlib.util.spec_from_file_location("honey_092_qualify", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
qualify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify)


def result(*, growth: int, mutation: int, startup: int, v5: bool) -> dict:
    return {
        "schema_version": "cigar.honey-092-system-comparison-driver.v1",
        "format": "sqlite-v5-incremental" if v5 else "sqlite-v4-full-residual",
        "initial_records": 128,
        "mutations": 100,
        "revision_before": 128,
        "revision_after": 228,
        "physical_before_bytes": 1_000,
        "physical_after_bytes": 1_000 + growth,
        "physical_growth_bytes": growth,
        "mutation_latencies_nanoseconds": [mutation] * 100,
        "process_cold_startup_nanoseconds": [startup] * qualify.STARTUP_REPETITIONS,
        "process_cold_startup_stages_nanoseconds": {
            "readiness_open": [startup] * qualify.STARTUP_REPETITIONS
        },
        "migration": (
            {
                "duration_nanoseconds": 1,
                "root_revision_exact": True,
                "retained_revisions": 129,
                "source_database_bytes": 1,
                "target_database_bytes": 1,
            }
            if v5
            else None
        ),
    }


class FocusedQualificationTests(unittest.TestCase):
    def test_system_pair_accepts_material_storage_gain_without_latency_loss(self) -> None:
        comparison = qualify.summarize_system_pair(
            result(growth=1_000, mutation=100, startup=100, v5=False),
            result(growth=500, mutation=110, startup=110, v5=True),
        )
        self.assertEqual(comparison["status"], "pass")
        self.assertTrue(comparison["checks"]["storage_materially_improved"])

    def test_system_pair_rejects_hidden_startup_regression(self) -> None:
        comparison = qualify.summarize_system_pair(
            result(growth=1_000, mutation=100, startup=100, v5=False),
            result(growth=500, mutation=100, startup=121, v5=True),
        )
        self.assertEqual(comparison["status"], "fail")
        self.assertFalse(comparison["checks"]["startup_not_materially_degraded"])

    def test_driver_result_requires_exact_mutation_and_migration_evidence(self) -> None:
        value = result(growth=500, mutation=100, startup=100, v5=True)
        qualify.validate_driver_result(value, format_name="v5", mutations=100)
        value["migration"]["root_revision_exact"] = False
        with self.assertRaises(qualify.QualificationError):
            qualify.validate_driver_result(value, format_name="v5", mutations=100)


if __name__ == "__main__":
    unittest.main()
