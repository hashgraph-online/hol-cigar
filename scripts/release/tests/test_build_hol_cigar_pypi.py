#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_hol_cigar_pypi as builder  # noqa: E402


class HolCigarPypiBuilderTests(unittest.TestCase):
    def test_authority_is_versioned_attributed_and_explicitly_not_production(self) -> None:
        profile = builder.validate_authority()
        self.assertEqual(profile["distribution"], "hol-cigar")
        self.assertEqual(profile["version"], "0.9.1")
        self.assertEqual(profile["protocol_home"], "https://hol.org")
        self.assertEqual(profile["release_state"], "developer-preview")
        self.assertFalse(profile["supported"])
        self.assertFalse(profile["production_qualified"])
        self.assertEqual(
            profile["mandatory_gates"],
            list(builder.MANDATORY_GATES),
        )
        self.assertEqual(
            profile["deferred_full_release_gates"],
            list(builder.DEFERRED_GATES),
        )

    def test_staging_reuses_sdk_source_but_overlays_pypi_release_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hol-cigar-stage-test-") as temporary:
            destination = Path(temporary) / "source"
            builder.stage(builder.ROOT, destination)
            release = json.loads(
                (
                    destination
                    / "src"
                    / "cigar_sdk"
                    / "release.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(release["name"], "hol-cigar")
            self.assertEqual(release["version"], "0.9.1")
            self.assertEqual(release["release_state"], "developer-preview")
            self.assertEqual(release["protocol_home"], "https://hol.org")
            self.assertTrue((destination / "src" / "cigar_sdk" / "client.py").is_file())
            contract = (
                destination / "tests" / "test_release_contract.py"
            ).read_text(encoding="utf-8")
            self.assertIn('metadata.version("hol-cigar")', contract)
            self.assertNotIn('metadata.version("cigar-sdk")', contract)

    def test_authority_rejects_missing_hol_attribution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hol-cigar-authority-test-") as temporary:
            fixture = Path(temporary)
            (fixture / "packaging").mkdir()
            shutil.copytree(
                builder.PACKAGE_ROOT,
                fixture / "packaging" / "pypi",
            )
            readme = fixture / "packaging" / "pypi" / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8").replace(
                    "developed by\n[HOL](https://hol.org)",
                    "developed by its contributors",
                ),
                encoding="utf-8",
            )
            notice = fixture / "packaging" / "pypi" / "NOTICE"
            notice.write_text(
                notice.read_text(encoding="utf-8").replace(
                    "developed by HOL (https://hol.org)",
                    "developed by its contributors",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(builder.PackageError, "attribution"):
                builder.validate_authority(fixture)

    def test_archive_path_validation_fails_closed(self) -> None:
        for value in ("../escape", "/absolute", "a/./b", r"a\b"):
            with self.subTest(value=value):
                with self.assertRaises(builder.PackageError):
                    builder._safe_archive_path(value)


if __name__ == "__main__":
    unittest.main()
