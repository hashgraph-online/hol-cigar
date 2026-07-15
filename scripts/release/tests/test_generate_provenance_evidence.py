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

import generate_provenance  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class ProvenanceEvidenceTests(unittest.TestCase):
    def arguments(
        self, *, out: Path, evidence_dir: Path | None = None
    ) -> SimpleNamespace:
        return SimpleNamespace(out=out, evidence_dir=evidence_dir)

    def test_legacy_development_output_remains_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            artifact = base / "artifact"
            artifact.write_bytes(b"artifact")
            destination = base / "development/provenance.json"
            output = generate_provenance.ProvenanceOutput.open(
                self.arguments(out=destination), root, [artifact]
            )
            try:
                output.publish({"z": 2, "a": 1})
            finally:
                output.close()
            self.assertEqual(json.loads(destination.read_bytes()), {"a": 1, "z": 2})
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)

    def test_external_output_is_canonical_owner_only_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            artifact = base / "artifact"
            artifact.write_bytes(b"artifact")
            evidence = base / "evidence"
            arguments = self.arguments(
                out=Path("supply-chain/provenance.json"), evidence_dir=evidence
            )
            output = generate_provenance.ProvenanceOutput.open(
                arguments, root, [artifact]
            )
            try:
                output.publish({"z": 2, "a": 1})
            finally:
                output.close()

            destination = evidence / "supply-chain/provenance.json"
            self.assertEqual(destination.read_bytes(), b'{"a":1,"z":2}\n')
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
            self.assertEqual(destination.stat().st_nlink, 1)

            output = generate_provenance.ProvenanceOutput.open(
                arguments, root, [artifact]
            )
            try:
                with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
                    output.publish({"replacement": True})
            finally:
                output.close()

    def test_environment_selection_conflict_and_relative_root_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            arguments = self.arguments(
                out=Path("provenance.json"), evidence_dir=base / "argument"
            )
            with mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": str(base / "environment")},
                clear=True,
            ):
                with self.assertRaisesRegex(ReleaseError, "conflicts"):
                    generate_provenance.selected_evidence_directory(arguments)

            arguments.evidence_dir = Path("relative")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "absolute path"):
                    generate_provenance.selected_evidence_directory(arguments)

    def test_external_output_rejects_escape_internal_root_and_input_alias(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            artifact = base / "artifact"
            artifact.write_bytes(b"artifact")
            evidence = base / "evidence"

            for unsafe in (Path("../escape.json"), base / "absolute.json"):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaisesRegex(ReleaseError, "evidence path"):
                        generate_provenance.ProvenanceOutput.open(
                            self.arguments(out=unsafe, evidence_dir=evidence),
                            root,
                            [artifact],
                        )

            with self.assertRaisesRegex(ReleaseError, "outside"):
                generate_provenance.ProvenanceOutput.open(
                    self.arguments(
                        out=Path("provenance.json"), evidence_dir=root / "evidence"
                    ),
                    root,
                    [artifact],
                )

            alias_root = base / "alias-evidence"
            alias_root.mkdir(mode=0o700)
            aliased_input = alias_root / "provenance.json"
            aliased_input.write_bytes(b"input")
            os.chmod(aliased_input, 0o600)
            with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
                generate_provenance.ProvenanceOutput.open(
                    self.arguments(
                        out=Path("provenance.json"), evidence_dir=alias_root
                    ),
                    root,
                    [aliased_input],
                )


if __name__ == "__main__":
    unittest.main()
