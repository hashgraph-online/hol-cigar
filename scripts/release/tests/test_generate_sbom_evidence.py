#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import generate_sbom  # noqa: E402
import verify_release  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class SbomEvidenceTests(unittest.TestCase):
    def arguments(
        self, *, out: Path, evidence_dir: Path | None = None
    ) -> SimpleNamespace:
        return SimpleNamespace(out=out, evidence_dir=evidence_dir)

    def publish_fixture(self, output: generate_sbom.SbomOutput) -> None:
        output.publish("sbom.spdx.json", {"format": "spdx"})
        output.publish("sbom.cyclonedx.json", {"format": "cyclonedx"})
        output.publish("sbom-artifacts.json", {"artifacts": []})

    def test_legacy_development_directory_remains_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            destination = base / "development-sbom"
            with mock.patch.dict(os.environ, {}, clear=True):
                output = generate_sbom.SbomOutput.open(
                    self.arguments(out=destination), root
                )
            try:
                self.publish_fixture(output)
            finally:
                output.close()
            self.assertEqual(
                json.loads((destination / "sbom.spdx.json").read_bytes()),
                {"format": "spdx"},
            )
            self.assertEqual(
                stat.S_IMODE((destination / "sbom.spdx.json").stat().st_mode),
                0o644,
            )

    def test_external_documents_are_canonical_owner_only_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            evidence = base / "evidence"
            arguments = self.arguments(
                out=Path("supply-chain/sbom"), evidence_dir=evidence
            )
            output = generate_sbom.SbomOutput.open(arguments, root)
            try:
                self.publish_fixture(output)
            finally:
                output.close()

            destination = evidence / "supply-chain/sbom/sbom.spdx.json"
            self.assertEqual(destination.read_bytes(), b'{"format":"spdx"}\n')
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
            self.assertEqual(destination.stat().st_nlink, 1)

            output = generate_sbom.SbomOutput.open(arguments, root)
            try:
                with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
                    self.publish_fixture(output)
            finally:
                output.close()

    def test_environment_selection_conflict_and_relative_root_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            arguments = self.arguments(out=Path("sbom"), evidence_dir=base / "argument")
            with mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": str(base / "environment")},
                clear=True,
            ):
                with self.assertRaisesRegex(ReleaseError, "conflicts"):
                    generate_sbom.selected_evidence_directory(arguments)

            arguments.evidence_dir = Path("relative")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "absolute path"):
                    generate_sbom.selected_evidence_directory(arguments)

    def test_external_output_rejects_escape_and_internal_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            evidence = base / "evidence"

            for unsafe in (Path("../escape"), base / "absolute"):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaisesRegex(ReleaseError, "evidence path"):
                        generate_sbom.SbomOutput.open(
                            self.arguments(out=unsafe, evidence_dir=evidence), root
                        )

            with self.assertRaisesRegex(ReleaseError, "outside"):
                generate_sbom.SbomOutput.open(
                    self.arguments(out=Path("sbom"), evidence_dir=root / "evidence"),
                    root,
                )

    def test_legacy_directory_must_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            destination = base / "sbom"
            destination.mkdir()
            (destination / "existing").write_bytes(b"keep")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "must be empty"):
                    generate_sbom.SbomOutput.open(self.arguments(out=destination), root)

    def test_generated_documents_match_release_verifier_contract(self) -> None:
        root = RELEASE.parents[1]
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            artifact = base / "fixture-artifact.tar.gz"
            artifact.write_bytes(b"non-release SBOM contract fixture")
            destination = base / "sbom"
            arguments = SimpleNamespace(
                root=root,
                artifact=[artifact],
                out=destination,
                evidence_dir=None,
                source_date_epoch="1700000000",
                require_reviewed_licenses=True,
            )
            with (
                mock.patch.object(
                    generate_sbom, "parse_arguments", return_value=arguments
                ),
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                self.assertEqual(generate_sbom.main(), 0)
            validated = verify_release._validate_sboms(  # noqa: SLF001
                destination,
                {"fixture": artifact},
                "0.9.4",
            )
            self.assertEqual(len(validated), 3)


if __name__ == "__main__":
    unittest.main()
