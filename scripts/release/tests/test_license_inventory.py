#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / "scripts/release"
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import generate_license_inventory as license_inventory  # noqa: E402
from generate_sbom import _cargo_components, _workspace_package_names  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


DIAGNOSTIC_REGRESSION_PURLS = {
    "pkg:cargo/block_on_proc@0.2.0",
    "pkg:cargo/castaway@0.2.4",
    "pkg:cargo/cfg_aliases@0.2.1",
    "pkg:cargo/compact_str@0.7.1",
    "pkg:cargo/core-foundation@0.9.4",
    "pkg:cargo/foreign-types-shared@0.1.1",
    "pkg:cargo/foreign-types@0.3.2",
    "pkg:cargo/hyper-tls@0.6.0",
    "pkg:cargo/lru-slab@0.1.2",
    "pkg:cargo/minidom@0.16.0",
}


def external_locked_cargo_purls(root: Path) -> set[str]:
    workspace_names = _workspace_package_names(root)
    return {
        component["purl"]
        for component in _cargo_components(root)
        if not (
            component["ecosystem"] == "generic" and component["name"] in workspace_names
        )
    }


class CargoLicenseClosureTests(unittest.TestCase):
    def test_cargo_metadata_uses_all_features_and_rejects_partial_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text(
                """version = 4

[[package]]
name = "present"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "feature-only"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
""",
                encoding="utf-8",
            )
            metadata = {
                "packages": [
                    {
                        "name": "present",
                        "version": "1.0.0",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "manifest_path": str(root / "present/Cargo.toml"),
                        "license": "MIT",
                    }
                ]
            }
            completed = subprocess.CompletedProcess(
                args=["cargo", "metadata"],
                returncode=0,
                stdout=json.dumps(metadata).encode("utf-8"),
                stderr=b"",
            )
            with mock.patch.object(
                license_inventory, "run_bounded", return_value=completed
            ) as run:
                with self.assertRaisesRegex(
                    ReleaseError,
                    r"cargo metadata --all-features differs from Cargo\.lock; "
                    r"missing_count=1",
                ):
                    license_inventory._cargo(root)
            command = run.call_args.args[0]
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            self.assertIn("--all-features", command)

    def test_generated_cargo_inventory_matches_the_complete_lock_closure(self) -> None:
        generated = {entry["purl"] for entry in license_inventory._cargo(ROOT)}
        expected = external_locked_cargo_purls(ROOT)
        self.assertEqual(generated, expected)
        self.assertLessEqual(DIAGNOSTIC_REGRESSION_PURLS, generated)

    def test_committed_inventory_contains_the_complete_cargo_lock_closure(self) -> None:
        inventory = json.loads(
            (ROOT / "packaging/licenses/third-party-inventory.v1.json").read_text(
                encoding="utf-8"
            )
        )
        by_purl = {entry["purl"]: entry for entry in inventory["components"]}
        committed = {
            entry["purl"]
            for entry in inventory["components"]
            if entry["ecosystem"] in {"cargo", "generic"}
        }
        expected = external_locked_cargo_purls(ROOT)
        self.assertEqual(committed, expected)
        self.assertLessEqual(DIAGNOSTIC_REGRESSION_PURLS, committed)
        for purl in DIAGNOSTIC_REGRESSION_PURLS:
            self.assertNotEqual(by_purl[purl]["license_expression"], "NOASSERTION")
            self.assertEqual(by_purl[purl]["policy_status"], "accepted-by-policy")


if __name__ == "__main__":
    unittest.main()
