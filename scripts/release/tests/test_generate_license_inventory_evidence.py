#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import generate_license_inventory as inventory  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class LicenseInventoryEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-license-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.input = self.base / "input.lock"
        self.input.write_text("locked\n", encoding="utf-8")
        os.chmod(self.input, 0o600)

    def arguments(
        self,
        *,
        out: Path,
        evidence_dir: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.repository,
            out=out,
            evidence_dir=evidence_dir,
            require_complete=False,
        )

    def open_output(
        self,
        *,
        out: Path,
        evidence_dir: Path | None = None,
        environment: str = "",
        inputs: list[Path] | None = None,
    ) -> inventory.LicenseInventoryOutput:
        arguments = self.arguments(out=out, evidence_dir=evidence_dir)
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": environment},
            clear=False,
        ):
            return inventory.LicenseInventoryOutput.open(
                arguments,
                self.repository,
                inputs if inputs is not None else [self.input],
            )

    def test_external_output_is_canonical_owner_only_and_create_new(self) -> None:
        evidence = self.base / "evidence"
        output = self.open_output(
            out=Path("supply-chain/licenses.json"), evidence_dir=evidence
        )
        self.addCleanup(output.close)
        document = {"z": 1, "components": [], "status": "review-required"}

        output.publish(document)

        destination = evidence / "supply-chain/licenses.json"
        self.assertEqual(
            destination.read_bytes(),
            b'{"components":[],"status":"review-required","z":1}\n',
        )
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        self.assertEqual(destination.stat().st_nlink, 1)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
            output.publish({"status": "replacement"})

    def test_environment_selection_and_conflicts_are_strict(self) -> None:
        evidence = self.base / "environment-evidence"
        output = self.open_output(out=Path("licenses.json"), environment=str(evidence))
        self.addCleanup(output.close)
        output.publish({"status": "selected-from-environment"})
        self.assertTrue((evidence / "licenses.json").is_file())

        arguments = self.arguments(
            out=Path("licenses.json"), evidence_dir=self.base / "argument"
        )
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "different")},
            clear=False,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                inventory.selected_evidence_directory(arguments)

        arguments.evidence_dir = Path("relative")
        with mock.patch.dict(os.environ, {"CIGAR_EVIDENCE_DIR": ""}, clear=False):
            with self.assertRaisesRegex(ReleaseError, "absolute"):
                inventory.selected_evidence_directory(arguments)

    def test_direct_development_output_and_input_alias_rejection(self) -> None:
        direct = self.base / "development" / "licenses.json"
        output = self.open_output(out=direct)
        output.publish({"status": "first"})
        output.publish({"status": "second"})
        output.close()
        self.assertEqual(
            json.loads(direct.read_text(encoding="utf-8")), {"status": "second"}
        )
        self.assertEqual(stat.S_IMODE(direct.stat().st_mode), 0o644)

        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            self.open_output(out=self.input, inputs=[self.input])

        evidence = self.base / "alias-evidence"
        evidence.mkdir(mode=0o700)
        aliased_input = evidence / "licenses.json"
        aliased_input.write_text("{}\n", encoding="utf-8")
        os.chmod(aliased_input, 0o600)
        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            self.open_output(
                out=Path("licenses.json"),
                evidence_dir=evidence,
                inputs=[aliased_input],
            )

    def test_selected_output_rejects_escape_absolute_and_internal_root(self) -> None:
        evidence = self.base / "unsafe-path-evidence"
        for output in (
            Path("../escape.json"),
            Path("nested/../../escape.json"),
            self.base / "absolute.json",
            Path("nested\\licenses.json"),
        ):
            with self.subTest(output=output):
                with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
                    self.open_output(out=output, evidence_dir=evidence)
        self.assertFalse(evidence.exists())

        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.open_output(
                out=Path("licenses.json"),
                evidence_dir=self.repository / "evidence",
            )

    def test_workspace_rejects_links_modes_collisions_and_rebinding(self) -> None:
        target = self.base / "target"
        target.mkdir(mode=0o700)
        linked = self.base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.open_output(out=Path("licenses.json"), evidence_dir=linked)

        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self.open_output(out=Path("licenses.json"), evidence_dir=insecure)

        hardlinks = self.base / "hardlinks"
        hardlinks.mkdir(mode=0o700)
        first = hardlinks / "first.json"
        second = hardlinks / "second.json"
        first.write_text("{}\n", encoding="utf-8")
        os.chmod(first, 0o400)
        os.link(first, second)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "hardlinked"):
            self.open_output(out=Path("licenses.json"), evidence_dir=hardlinks)

        collision = self.base / "collision"
        collision.mkdir(mode=0o700)
        existing = collision / "Licenses.json"
        existing.write_text("{}\n", encoding="utf-8")
        os.chmod(existing, 0o400)
        output = self.open_output(out=Path("licenses.json"), evidence_dir=collision)
        self.addCleanup(output.close)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            output.publish({"status": "unsafe"})

        rebound = self.base / "rebound"
        output = self.open_output(out=Path("licenses.json"), evidence_dir=rebound)
        self.addCleanup(output.close)
        displaced = self.base / "displaced"
        rebound.rename(displaced)
        rebound.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            output.publish({"status": "unsafe"})
        self.assertFalse((displaced / "licenses.json").exists())
        self.assertFalse((rebound / "licenses.json").exists())

    def test_cargo_metadata_child_does_not_inherit_evidence_selector(self) -> None:
        cargo_root = self.base / "cargo"
        cargo_root.mkdir()
        (cargo_root / "Cargo.lock").write_text(
            """version = 4

[[package]]
name = "dependency"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
""",
            encoding="utf-8",
        )
        metadata = {
            "packages": [
                {
                    "name": "dependency",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "manifest_path": str(cargo_root / "dependency/Cargo.toml"),
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
        with (
            mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": str(self.base / "parent-evidence")},
                clear=False,
            ),
            mock.patch.object(inventory, "run_bounded", return_value=completed) as run,
        ):
            self.assertEqual(len(inventory._cargo(cargo_root)), 1)

        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("CIGAR_EVIDENCE_DIR", child_environment)
        self.assertEqual(run.call_args.args[0][0:2], ["cargo", "metadata"])


if __name__ == "__main__":
    unittest.main()
