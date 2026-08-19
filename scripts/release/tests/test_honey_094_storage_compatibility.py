from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

FROZEN_093 = "a049fbc8ed81c9adc6b1a066ca053c5befc2578a"

SQLITE_MIGRATION_SHA256 = {
    "crates/cigar-store/migrations/sqlite/0001_initial.sql": (
        "5d461110aeed4c43c7f0668599ac7070fdee6d8b349dc2b2815de4ca84f0efe1"
    ),
    "crates/cigar-store/migrations/sqlite/0002_compatibility_ledger.sql": (
        "4cddd01548672b49f04ad24d3e091a3c12be5620048fb8c056543caf6953f0c6"
    ),
    "crates/cigar-store/migrations/sqlite/0003_generation_bound_atom_projection.sql": (
        "59c68cc76fe17fae0e211f53f2081072b63bbf692fd67747a4eb8c412d68c71b"
    ),
    "crates/cigar-store/migrations/sqlite/0004_normalized_authoritative_catalog.sql": (
        "da0c9facf2c1ec0d3a800474b3ad9379897401d689fbe947f2b6f443cae1e729"
    ),
    "crates/cigar-store/migrations/sqlite/0005_incremental_repository_state.sql": (
        "4600a510c1fb75dc47e26eb8f3faeb2197150455c216e612cef40b67fd16aff2"
    ),
}

FROZEN_V5_SOURCE_SHA256 = {
    "crates/cigar-store/src/migrate_v5.rs": (
        "cb42720e7b56bc1bb2834a1c6fc2fa402db1a3b3d42cee6795be8c59d3b603f1"
    ),
    "crates/cigar-store/src/revision_delta.rs": (
        "6aa5dfd1427571fdce4dc2317aea5a909c82b00fc1e18b849aeb2b6941eb3bff"
    ),
    "crates/cigar-store/src/service_repository.rs": (
        "b8d780c5e18076b72fc2e77d2e92fcad47bfe8510addeff38978c7c78ea3981d"
    ),
    "crates/cigar-store/src/sqlite_v5.rs": (
        "4ae54e9f05d2f827e4e775233f88d3e6ac3fa04a45e9771804b47bf99b10c075"
    ),
}


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


class Honey094StorageCompatibilityTests(unittest.TestCase):
    def test_sqlite_migration_inventory_and_v5_core_match_frozen_093(self) -> None:
        migrations = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "crates/cigar-store/migrations/sqlite").glob("*.sql")
        }
        self.assertEqual(migrations, set(SQLITE_MIGRATION_SHA256))
        self.assertEqual(
            {relative: sha256(relative) for relative in SQLITE_MIGRATION_SHA256},
            SQLITE_MIGRATION_SHA256,
            f"SQLite migration drifted from frozen 0.9.3 {FROZEN_093}",
        )
        self.assertEqual(
            {relative: sha256(relative) for relative in FROZEN_V5_SOURCE_SHA256},
            FROZEN_V5_SOURCE_SHA256,
            f"v5 persistence core drifted from frozen 0.9.3 {FROZEN_093}",
        )

    def test_workflow_checkpoint_reuses_the_existing_v5_service_record_path(self) -> None:
        workflow = (ROOT / "crates/cigar-daemon/src/workflow_context_store.rs").read_text(
            encoding="utf-8"
        )
        sqlite_v5 = (ROOT / "crates/cigar-store/src/sqlite_v5.rs").read_text(
            encoding="utf-8"
        )
        revision_delta = (
            ROOT / "crates/cigar-store/src/revision_delta.rs"
        ).read_text(encoding="utf-8")

        for required in (
            'const SESSION_NAMESPACE: &str = "context.workflow-session.v1";',
            'const SESSION_SCHEMA: &str = "cigar.workflow-context-checkpoint.v1";',
            "repository: Arc<dyn ServiceRepository>",
            "ServiceRecordWrite::new(",
            "ServiceExpectedVersion::Absent",
            "ServiceExpectedVersion::Version(",
        ):
            self.assertIn(required, workflow)
        for forbidden in (
            "rusqlite",
            "CREATE TABLE",
            "ALTER TABLE",
            "schema_migrations",
            "repository_authority_v5",
            "format_version",
        ):
            self.assertNotIn(forbidden, workflow)

        self.assertIn("impl ServiceRepository for SqliteV5Store", sqlite_v5)
        self.assertIn("repository_delta_from_service_v5", sqlite_v5)
        self.assertIn("Self::ApplyServiceBatch", revision_delta)
        self.assertIn('"apply_service_batch"', revision_delta)


if __name__ == "__main__":
    unittest.main()
