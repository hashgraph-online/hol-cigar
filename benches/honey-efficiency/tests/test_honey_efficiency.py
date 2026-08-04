from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "honey_efficiency.py"
SPEC = importlib.util.spec_from_file_location("honey_efficiency", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


def commit(index: int) -> dict[str, object]:
    return {
        "iteration": index // 2,
        "operation": index % 2,
        "kind": "worker",
        "outcome": "committed",
        "revision_before": 2 + index,
        "revision_after": 3 + index,
        "receipt_only": False,
        "durations_nanoseconds": {
            "total": 100 + index,
            "lock_wait": 1,
            "repository_load": 2,
            "residual_decode": 3,
            "staged_mutation": 4,
            "delta_encode": 0,
            "full_encode": 5,
            "catalog_root": 6,
            "sqlite_transaction": 7,
            "commit_fsync": 8,
            "revision_anchor": 9,
        },
        "bytes": {
            "logical_changed": 10,
            "encoded_delta": 0,
            "checkpoint": 0,
            "full_state": 1000 + 100 * index,
            "database_before": 4096,
            "database_after": 8192,
            "wal_before": 0,
            "wal_after": 4096,
            "durable_added": 8192,
            "write_amplification_millionths": 819_200_000,
        },
        "retained_full_states": 3 + index,
        "retained_checkpoints": 0,
        "retained_deltas": 0,
    }


class HoneyEfficiencyTests(unittest.TestCase):
    def test_frozen_profiles_are_bounded(self) -> None:
        profiles = harness.load_profiles(
            harness.REPOSITORY_ROOT / "benches/honey-efficiency/profiles.v1.json"
        )
        self.assertEqual(set(profiles), {"small", "threshold", "hiero-shaped"})
        self.assertEqual(profiles["hiero-shaped"]["iterations"], 100)

    def test_integer_ols_is_exact_and_signed(self) -> None:
        self.assertEqual(harness.integer_ols_slope_millionths([2, 4, 6]), 2_000_000)
        self.assertEqual(harness.integer_ols_slope_millionths([6, 4, 2]), -2_000_000)

    def test_summary_reproduces_full_snapshot_behavior(self) -> None:
        profile = {
            "initial_records": 2,
            "iterations": 2,
            "mutations_per_iteration": 2,
            "shape": "test",
        }
        driver = {
            "schema_version": harness.DRIVER_SCHEMA_VERSION,
            "persistence_format": harness.PERSISTENCE_FORMAT,
            "initial_records": 2,
            "iterations": 2,
            "mutations_per_iteration": 2,
            "startup": [
                {
                    "stage": "sqlite_open_configure",
                    "outcome": "completed",
                    "duration_nanoseconds": 50,
                }
            ],
            "storage_before": {
                "revision": 2,
                "retained_snapshots": 3,
                "latest_snapshot_bytes": 900,
                "database_bytes": 4096,
                "wal_bytes": 0,
            },
            "storage_after": {
                "revision": 6,
                "retained_snapshots": 7,
                "latest_snapshot_bytes": 1300,
                "database_bytes": 8192,
                "wal_bytes": 4096,
            },
            "commits": [commit(index) for index in range(4)],
        }
        source = {
            "base_commit": "0" * 40,
            "candidate_bound": False,
            "candidate_bound_compatible": True,
            "worktree_source_sha256": "1" * 64,
        }
        raw, summary = harness.summarize(
            driver,
            "small",
            profile,
            {"kind": "generated", "seed": 0},
            source,
        )
        self.assertEqual(summary["outcome"], "pass")
        self.assertTrue(summary["baseline_behavior"]["full_snapshot_encoded_each_commit"])
        self.assertEqual(
            summary["raw_observations_sha256"],
            hashlib.sha256(harness.canonical_json_bytes(raw)).hexdigest(),
        )
        self.assertEqual(summary["storage"]["revision_delta"], 4)
        self.assertEqual(
            summary["baseline_behavior"][
                "snapshot_bytes_ols_slope_per_operation_millionths"
            ],
            100_000_000,
        )

    def test_verified_copy_requires_and_preserves_exact_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            target = root / "target.sqlite3"
            source.write_bytes(b"verified-copy")
            digest = hashlib.sha256(b"verified-copy").hexdigest()
            binding = harness.copy_verified_database(source, target, digest)
            self.assertEqual(binding, {"bytes": 13, "kind": "verified-copy", "sha256": digest})
            self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_report_serialization_contains_no_path_or_content_field(self) -> None:
        profile = {
            "initial_records": 1,
            "iterations": 1,
            "mutations_per_iteration": 1,
            "shape": "test",
        }
        one = commit(0)
        one["operation"] = 0
        driver = {
            "schema_version": harness.DRIVER_SCHEMA_VERSION,
            "persistence_format": harness.PERSISTENCE_FORMAT,
            "initial_records": 1,
            "iterations": 1,
            "mutations_per_iteration": 1,
            "startup": [
                {
                    "stage": "sqlite_open_configure",
                    "outcome": "completed",
                    "duration_nanoseconds": 1,
                }
            ],
            "storage_before": {
                "revision": 2,
                "retained_snapshots": 3,
                "latest_snapshot_bytes": 900,
                "database_bytes": 4096,
                "wal_bytes": 0,
            },
            "storage_after": {
                "revision": 3,
                "retained_snapshots": 4,
                "latest_snapshot_bytes": 1000,
                "database_bytes": 8192,
                "wal_bytes": 4096,
            },
            "commits": [one],
        }
        raw, summary = harness.summarize(
            driver,
            "small",
            profile,
            {"kind": "generated", "seed": 0},
            {
                "base_commit": "0" * 40,
                "candidate_bound": False,
                "candidate_bound_compatible": True,
                "worktree_source_sha256": "1" * 64,
            },
        )
        encoded = json.dumps({"raw": raw, "summary": summary}, sort_keys=True)
        self.assertNotIn("private_path", encoded)
        self.assertNotIn("source_content", encoded)
        self.assertNotIn("prompt", encoded)


if __name__ == "__main__":
    unittest.main()
