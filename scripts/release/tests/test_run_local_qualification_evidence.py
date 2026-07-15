#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import run_local_qualification  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402
from signatures import _write_new_private_json  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class LocalQualificationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-local-qualification-evidence-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)

    def arguments(
        self,
        *,
        output: Path,
        evidence_dir: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.repository,
            source_date_epoch="1700000000",
            out=output,
            evidence_dir=evidence_dir,
        )

    def open_output(
        self,
        *,
        output: Path,
        evidence_dir: Path | None = None,
        environment: str = "",
    ) -> run_local_qualification._ReportOutput:
        arguments = self.arguments(output=output, evidence_dir=evidence_dir)
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": environment}, clear=False
        ):
            return run_local_qualification._ReportOutput.open(
                arguments,
                repository_root=self.repository,
            )

    def test_selected_workspace_publishes_canonical_owner_only_create_new_report(
        self,
    ) -> None:
        evidence = self.base / "evidence"
        output = self.open_output(
            output=Path("qualification/result.json"), evidence_dir=evidence
        )
        self.addCleanup(output.close)
        report = {"z": 1, "release_ready": False, "status": "passed-local-scope"}

        output.publish(report)

        destination = evidence / "qualification/result.json"
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), report)
        self.assertEqual(
            destination.read_bytes(),
            b'{"release_ready":false,"status":"passed-local-scope","z":1}\n',
        )
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        self.assertEqual(destination.stat().st_nlink, 1)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
            output.publish({"release_ready": True})

    def test_environment_selection_conflict_and_path_contract(self) -> None:
        evidence = self.base / "environment"
        selected = self.open_output(
            output=Path("report.json"), environment=str(evidence)
        )
        selected.close()

        arguments = self.arguments(
            output=Path("report.json"), evidence_dir=self.base / "argument"
        )
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "other")},
            clear=False,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                run_local_qualification._ReportOutput.open(
                    arguments,
                    repository_root=self.repository,
                )

        for unsafe in (
            Path("../escape.json"),
            Path("nested/../../escape.json"),
            self.base / "absolute.json",
            Path("nested\\report.json"),
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
                    self.open_output(output=unsafe, evidence_dir=self.base / "paths")
        with self.assertRaisesRegex(ReleaseError, "must be absolute"):
            self.open_output(output=Path("report.json"))

    def test_absolute_legacy_form_still_uses_a_secure_external_workspace(self) -> None:
        evidence = self.base / "absolute-evidence"
        destination = evidence / "report.json"
        output = self.open_output(output=destination)
        self.addCleanup(output.close)
        output.publish({"release_ready": False})

        self.assertTrue(destination.is_file())
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)

        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self.open_output(output=insecure / "report.json")

    def test_repository_links_collisions_and_rebound_paths_fail_closed(self) -> None:
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.open_output(
                output=Path("report.json"),
                evidence_dir=self.repository / "evidence",
            )

        target = self.base / "linked-target"
        target.mkdir(mode=0o700)
        linked = self.base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.open_output(output=Path("report.json"), evidence_dir=linked)

        collision = self.base / "collision"
        collision.mkdir(mode=0o700)
        existing = collision / "Report.json"
        existing.write_text("{}\n", encoding="utf-8")
        os.chmod(existing, 0o400)
        collision_output = self.open_output(
            output=Path("report.json"), evidence_dir=collision
        )
        self.addCleanup(collision_output.close)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            collision_output.publish({"release_ready": False})

        rebound = self.base / "rebound"
        rebound_output = self.open_output(
            output=Path("report.json"), evidence_dir=rebound
        )
        self.addCleanup(rebound_output.close)
        displaced = self.base / "displaced"
        rebound.rename(displaced)
        rebound.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            rebound_output.publish({"release_ready": False})
        self.assertFalse((displaced / "report.json").exists())
        self.assertFalse((rebound / "report.json").exists())

    def test_signature_scratch_is_canonical_private_external_and_accepted(self) -> None:
        with run_local_qualification._private_scratch_directory(
            self.repository
        ) as scratch:
            self.assertEqual(scratch, scratch.resolve(strict=True))
            self.assertNotIn(self.repository, scratch.parents)
            self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
            signature_directory = scratch / "ephemeral-key"
            signature_directory.mkdir(mode=0o700)
            envelope = signature_directory / "selftest.sig.json"
            _write_new_private_json(envelope, {"selftest": True})
            self.assertEqual(envelope.read_bytes(), b'{"selftest":true}\n')
            self.assertEqual(stat.S_IMODE(envelope.stat().st_mode), 0o400)

    def test_child_commands_cannot_inherit_parent_evidence_workspace(self) -> None:
        parent = self.base / "parent-evidence"
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(parent)}, clear=False
        ):
            environment = run_local_qualification._qualification_environment(
                1_700_000_000
            )
        self.assertNotIn("CIGAR_EVIDENCE_DIR", environment)
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "1700000000")
        self.assertEqual(environment["TZ"], "UTC")

    def test_installation_matrix_routes_receipt_to_selected_external_workspace(
        self,
    ) -> None:
        matrix = json.loads(
            (RELEASE.parents[1] / "tests/installation/matrix-v1.json").read_text(
                encoding="utf-8"
            )
        )
        case = next(
            entry for entry in matrix["cases"] if entry["id"] == "INSTALL-WP21-001"
        )
        command = case["command"]
        output = command[command.index("--out") + 1]
        self.assertEqual(output, "wp21-local-readiness.json")
        self.assertFalse(Path(output).is_absolute())
        self.assertEqual(case["required_environment"], ["CIGAR_EVIDENCE_DIR"])


if __name__ == "__main__":
    unittest.main()
