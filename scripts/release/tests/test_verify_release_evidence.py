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

import verify_release  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class VerifyReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-verify-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.dist = self.base / "dist"
        self.dist.mkdir(mode=0o700)
        trust = self.base / "trust"
        trust.mkdir(mode=0o700)
        self.trust_policy = trust / "policy.json"
        self.trust_policy.write_text("{}\n", encoding="utf-8")
        os.chmod(self.trust_policy, 0o600)

    def arguments(
        self,
        *,
        report: Path | None,
        evidence_dir: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            directory=self.dist,
            root=self.repository,
            trust_policy=self.trust_policy,
            verification_time=1_700_000_000,
            report=report,
            evidence_dir=evidence_dir,
        )

    def open_output(
        self,
        *,
        report: Path | None,
        evidence_dir: Path | None = None,
        environment: str = "",
    ) -> verify_release._ReportOutput | None:
        arguments = self.arguments(report=report, evidence_dir=evidence_dir)
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": environment}, clear=False
        ):
            return verify_release._ReportOutput.open(
                arguments,
                repository_root=self.repository,
                dist=self.dist,
            )

    def test_selected_workspace_publishes_relative_create_new_report(self) -> None:
        evidence = self.base / "evidence"
        output = self.open_output(
            report=Path("verification/report.json"), evidence_dir=evidence
        )
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        report = {
            "schema_version": "cigar.release-verification.v1",
            "status": "passed",
        }
        output.publish(report)
        published = evidence / "verification/report.json"
        self.assertEqual(json.loads(published.read_text(encoding="utf-8")), report)
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(published.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(published.stat().st_mode), 0o400)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
            output.publish(report)

    def test_environment_selection_and_conflict_rejection(self) -> None:
        evidence = self.base / "environment-evidence"
        output = self.open_output(report=Path("report.json"), environment=str(evidence))
        self.assertIsNotNone(output)
        assert output is not None
        output.close()

        arguments = self.arguments(
            report=Path("report.json"), evidence_dir=self.base / "argument"
        )
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "environment")},
            clear=False,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                verify_release._ReportOutput.open(
                    arguments,
                    repository_root=self.repository,
                    dist=self.dist,
                )

    def test_report_path_contract_rejects_escape_and_ambiguous_forms(self) -> None:
        evidence = self.base / "path-evidence"
        for report in (
            Path("../escape.json"),
            Path("nested/../../escape.json"),
            Path("/absolute/report.json"),
            Path("nested\\report.json"),
        ):
            with self.subTest(report=report):
                with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
                    self.open_output(report=report, evidence_dir=evidence)
        with self.assertRaisesRegex(ReleaseError, "must be absolute"):
            self.open_output(report=Path("relative-report.json"))

    def test_legacy_absolute_report_requires_secure_external_parent(self) -> None:
        evidence = self.base / "legacy-evidence"
        evidence.mkdir(mode=0o700)
        report = evidence / "report.json"
        output = self.open_output(report=report)
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        output.publish({"status": "passed"})
        self.assertTrue(report.is_file())
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o400)

        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self.open_output(report=insecure / "report.json")

    def test_repository_dist_links_and_distinct_trust_policy_are_rejected(self) -> None:
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.open_output(
                report=Path("report.json"),
                evidence_dir=self.repository / "evidence",
            )

        dist_evidence = self.dist / "evidence"
        with self.assertRaisesRegex(ReleaseError, "verified directory"):
            self.open_output(report=Path("report.json"), evidence_dir=dist_evidence)
        self.assertFalse(dist_evidence.exists())

        linked_target = self.base / "linked-target"
        linked_target.mkdir(mode=0o700)
        linked = self.base / "linked-evidence"
        linked.symlink_to(linked_target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.open_output(report=Path("report.json"), evidence_dir=linked)

        trust_workspace = self.trust_policy.parent
        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            self.open_output(
                report=Path(self.trust_policy.name), evidence_dir=trust_workspace
            )

    def test_workspace_rejects_nested_link_collision_and_rebound(self) -> None:
        linked_evidence = self.base / "nested-link-evidence"
        linked_evidence.mkdir(mode=0o700)
        (linked_evidence / "redirect").symlink_to(
            self.repository, target_is_directory=True
        )
        with self.assertRaisesRegex(EvidenceWorkspaceError, "not a regular file"):
            self.open_output(report=Path("report.json"), evidence_dir=linked_evidence)

        collision = self.base / "collision-evidence"
        collision.mkdir(mode=0o700)
        existing = collision / "Report.json"
        existing.write_text("{}\n", encoding="utf-8")
        os.chmod(existing, 0o400)
        output = self.open_output(report=Path("report.json"), evidence_dir=collision)
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            output.publish({"status": "passed"})

        rebound = self.base / "rebound-evidence"
        output = self.open_output(report=Path("report.json"), evidence_dir=rebound)
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        displaced = self.base / "displaced-evidence"
        rebound.rename(displaced)
        rebound.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            output.publish({"status": "passed"})
        self.assertFalse((displaced / "report.json").exists())
        self.assertFalse((rebound / "report.json").exists())

    def test_no_report_preserves_stdout_only_path_and_ignores_environment(self) -> None:
        arguments = self.arguments(report=None)
        with (
            mock.patch.object(
                verify_release, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(
                verify_release, "_run_verification", return_value=0
            ) as verification,
            mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": str(self.base / "unused")},
                clear=False,
            ),
        ):
            self.assertEqual(verify_release.main(), 0)
        verification.assert_called_once_with(arguments, None)
        self.assertFalse((self.base / "unused").exists())

        arguments = self.arguments(
            report=None, evidence_dir=self.base / "explicit-unused"
        )
        with (
            mock.patch.object(
                verify_release, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(
                verify_release, "_run_verification", return_value=0
            ) as verification,
            mock.patch.dict(os.environ, {"CIGAR_EVIDENCE_DIR": ""}, clear=False),
        ):
            self.assertEqual(verify_release.main(), 0)
        verification.assert_called_once_with(arguments, None)
        self.assertFalse((self.base / "explicit-unused").exists())

        conflicting = self.arguments(
            report=None, evidence_dir=self.base / "argument-unused"
        )
        with (
            mock.patch.object(
                verify_release, "parse_arguments", return_value=conflicting
            ),
            mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": str(self.base / "environment-unused")},
                clear=False,
            ),
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                verify_release.main()


if __name__ == "__main__":
    unittest.main()
