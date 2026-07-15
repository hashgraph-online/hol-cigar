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

import check_docs  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class DocumentationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-docs-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        (self.repository / "docs").mkdir(parents=True, mode=0o700)
        for name in ("site-manifest.v1.json", "commands.v1.json"):
            path = self.repository / "docs" / name
            path.write_text("{}\n", encoding="utf-8")
            os.chmod(path, 0o600)

    def arguments(
        self,
        *,
        report: Path | None,
        evidence_dir: Path | None = None,
        variables: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.repository,
            execute=[],
            execute_local=False,
            variables=variables,
            report=report,
            evidence_dir=evidence_dir,
        )

    def open_output(
        self,
        *,
        report: Path | None,
        evidence_dir: Path | None = None,
        variables: Path | None = None,
        environment: str = "",
    ) -> check_docs._ReportOutput | None:
        arguments = self.arguments(
            report=report,
            evidence_dir=evidence_dir,
            variables=variables,
        )
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": environment}, clear=False
        ):
            return check_docs._ReportOutput.open(
                arguments,
                repository_root=self.repository,
            )

    def test_selected_report_is_canonical_owner_only_and_create_new(self) -> None:
        evidence = self.base / "evidence"
        output = self.open_output(
            report=Path("docs/result.json"), evidence_dir=evidence
        )
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        report = {"z": 1, "status": "passed", "failed_commands": 0}

        output.publish(report)

        destination = evidence / "docs/result.json"
        self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), report)
        self.assertEqual(
            destination.read_bytes(),
            b'{"failed_commands":0,"status":"passed","z":1}\n',
        )
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        self.assertEqual(destination.stat().st_nlink, 1)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
            output.publish({"status": "replaced"})

    def test_no_report_stdout_mode_and_legacy_direct_development_output(self) -> None:
        unused = self.base / "unused"
        output = self.open_output(report=None)
        self.assertIsNone(output)
        self.assertFalse(unused.exists())

        direct = self.base / "development" / "docs.json"
        output = self.open_output(report=direct)
        self.assertIsNotNone(output)
        assert output is not None
        output.publish({"status": "first"})
        output.publish({"status": "second"})
        output.close()
        self.assertEqual(
            json.loads(direct.read_text(encoding="utf-8")), {"status": "second"}
        )
        self.assertEqual(stat.S_IMODE(direct.stat().st_mode), 0o644)

        with self.assertRaisesRegex(ReleaseError, "requires a safe relative"):
            self.open_output(report=None, evidence_dir=unused)
        self.assertFalse(unused.exists())

    def test_environment_selection_and_conflict_are_strict(self) -> None:
        evidence = self.base / "environment"
        output = self.open_output(report=Path("docs.json"), environment=str(evidence))
        self.assertIsNotNone(output)
        assert output is not None
        output.close()

        arguments = self.arguments(
            report=Path("docs.json"), evidence_dir=self.base / "argument"
        )
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "other")},
            clear=False,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                check_docs._ReportOutput.open(
                    arguments,
                    repository_root=self.repository,
                )

    def test_selected_report_rejects_escape_absolute_and_input_alias(self) -> None:
        evidence = self.base / "paths"
        for report in (
            Path("../escape.json"),
            Path("nested/../../escape.json"),
            self.base / "absolute.json",
            Path("nested\\report.json"),
        ):
            with self.subTest(report=report):
                with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
                    self.open_output(report=report, evidence_dir=evidence)
        self.assertFalse(evidence.exists())

        site_manifest = self.repository / "docs/site-manifest.v1.json"
        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            self.open_output(report=site_manifest)

        alias_root = self.base / "alias"
        alias_root.mkdir(mode=0o700)
        variables = alias_root / "variables.json"
        variables.write_text("{}\n", encoding="utf-8")
        os.chmod(variables, 0o600)
        with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
            self.open_output(
                report=Path("variables.json"),
                evidence_dir=alias_root,
                variables=variables,
            )

    def test_workspace_rejects_internal_links_modes_collisions_and_rebound(
        self,
    ) -> None:
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.open_output(
                report=Path("report.json"),
                evidence_dir=self.repository / "evidence",
            )

        target = self.base / "target"
        target.mkdir(mode=0o700)
        linked = self.base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.open_output(report=Path("report.json"), evidence_dir=linked)

        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self.open_output(report=Path("report.json"), evidence_dir=insecure)

        hardlinks = self.base / "hardlinks"
        hardlinks.mkdir(mode=0o700)
        first = hardlinks / "first.json"
        second = hardlinks / "second.json"
        first.write_text("{}\n", encoding="utf-8")
        os.chmod(first, 0o400)
        os.link(first, second)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "hardlinked"):
            self.open_output(report=Path("report.json"), evidence_dir=hardlinks)

        collision = self.base / "collision"
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

        rebound = self.base / "rebound"
        output = self.open_output(report=Path("report.json"), evidence_dir=rebound)
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        displaced = self.base / "displaced"
        rebound.rename(displaced)
        rebound.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            output.publish({"status": "passed"})
        self.assertFalse((displaced / "report.json").exists())
        self.assertFalse((rebound / "report.json").exists())

    def test_executed_commands_never_inherit_parent_evidence_selector(self) -> None:
        parent = self.base / "parent-evidence"
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(parent)}, clear=False
        ):
            environment = check_docs._documentation_environment()
        self.assertNotIn("CIGAR_EVIDENCE_DIR", environment)
        self.assertEqual(environment["TZ"], "UTC")
        self.assertEqual(environment["LC_ALL"], "C")


if __name__ == "__main__":
    unittest.main()
