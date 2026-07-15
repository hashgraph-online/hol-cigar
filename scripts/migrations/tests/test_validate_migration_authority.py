from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.migrations.validate_migration_authority import AuthorityError, validate


REPOSITORY = Path(__file__).resolve().parents[3]


class MigrationAuthorityTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "migrations").mkdir()
        shutil.copy2(REPOSITORY / "migrations" / "authority-v1.json", root / "migrations")
        for backend in ("sqlite", "postgres"):
            shutil.copytree(REPOSITORY / "migrations" / backend, root / "migrations" / backend)
            destination = root / "crates" / "cigar-store" / "migrations" / backend
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                REPOSITORY / "crates" / "cigar-store" / "migrations" / backend,
                destination,
            )
        return temporary, root

    def mutate(self, root: Path, operation) -> None:
        path = root / "migrations" / "authority-v1.json"
        authority = json.loads(path.read_text(encoding="utf-8"))
        operation(authority)
        path.write_text(json.dumps(authority), encoding="utf-8")

    def test_repository_authority_is_closed_and_complete(self) -> None:
        self.assertEqual(
            validate(REPOSITORY),
            {"backends": 2, "migrations": 8, "retained_fixtures": 5},
        )

    def test_source_edit_is_rejected_by_digest(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        path = root / "migrations" / "sqlite" / "0001_initial.sql"
        path.write_text(path.read_text(encoding="utf-8") + "\n-- rewritten\n", encoding="utf-8")
        with self.assertRaises(AuthorityError):
            validate(root)

    def test_missing_or_unlisted_migration_is_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        (root / "migrations" / "sqlite" / "0003_unlisted.sql").write_text(
            "-- unlisted\n", encoding="utf-8"
        )
        with self.assertRaises(AuthorityError):
            validate(root)

    def test_sequence_gap_and_reordering_are_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.mutate(root, lambda value: value["backends"][1]["migrations"].reverse())
        with self.assertRaises(AuthorityError):
            validate(root)

    def test_unknown_field_and_duplicate_json_field_are_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.mutate(root, lambda value: value.update({"unreviewed": True}))
        with self.assertRaises(AuthorityError):
            validate(root)

        shutil.copy2(
            REPOSITORY / "migrations" / "authority-v1.json",
            root / "migrations" / "authority-v1.json",
        )
        path = root / "migrations" / "authority-v1.json"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("{", '{"schema_version":"duplicate",', 1), encoding="utf-8")
        with self.assertRaises(AuthorityError):
            validate(root)

    def test_symlinked_source_and_path_escape_are_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        source = root / "migrations" / "sqlite" / "0002_compatibility_ledger.sql"
        target = root / "outside.sql"
        target.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(target)
        with self.assertRaises(AuthorityError):
            validate(root)

        source.unlink()
        shutil.copy2(
            REPOSITORY / "migrations" / "sqlite" / "0002_compatibility_ledger.sql", source
        )
        self.mutate(
            root,
            lambda value: value["backends"][0]["migrations"][1].update(
                {"source": "../outside.sql"}
            ),
        )
        with self.assertRaises(AuthorityError):
            validate(root)

    def test_transaction_control_and_mirror_drift_are_rejected(self) -> None:
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        mirror = (
            root
            / "crates"
            / "cigar-store"
            / "migrations"
            / "postgres"
            / "0004_gc_revision_guard.sql"
        )
        mirror.write_text(mirror.read_text(encoding="utf-8") + "\nCOMMIT;\n", encoding="utf-8")
        with self.assertRaises(AuthorityError):
            validate(root)


if __name__ == "__main__":
    unittest.main()
