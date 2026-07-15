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

import check_reproducibility  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class ReproducibilityEvidenceTests(unittest.TestCase):
    def arguments(
        self,
        *,
        root: Path,
        report: Path | None,
        evidence_dir: Path | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            root=root,
            source_date_epoch="1",
            report=report,
            evidence_dir=evidence_dir,
            require_committed_clean=False,
        )

    @staticmethod
    def manifest() -> dict[str, object]:
        return {
            "source": {"revision": "a" * 40, "tree": "b" * 40},
            "artifacts": [
                {"id": "source", "sha256": "c" * 64, "bytes": 17},
                {"id": "docs", "sha256": "d" * 64, "bytes": 23},
            ],
        }

    def run_main(self, arguments: SimpleNamespace) -> int:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                check_reproducibility, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(
                check_reproducibility,
                "_build",
                side_effect=[self.manifest(), self.manifest()],
            ),
        ):
            return check_reproducibility.main()

    def test_development_report_behavior_remains_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            report = root / "development" / "report.json"
            self.assertEqual(self.run_main(self.arguments(root=root, report=report)), 0)
            document = json.loads(report.read_bytes())
            self.assertEqual(document["status"], "passed")
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o644)

    def test_external_report_is_canonical_owner_only_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root = base / "source"
            root.mkdir()
            evidence = base / "evidence"
            arguments = self.arguments(
                root=root,
                report=Path("reports/reproducibility.json"),
                evidence_dir=evidence,
            )
            self.assertEqual(self.run_main(arguments), 0)
            report = evidence / "reports/reproducibility.json"
            self.assertEqual(json.loads(report.read_bytes())["status"], "passed")
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o400)
            self.assertEqual(report.stat().st_nlink, 1)

            with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
                self.run_main(arguments)

    def test_selector_conflict_and_relative_root_fail_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            arguments = self.arguments(
                root=base,
                report=Path("report.json"),
                evidence_dir=base / "argument",
            )
            with mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": str(base / "environment")},
                clear=True,
            ):
                with self.assertRaisesRegex(ReleaseError, "conflicts"):
                    check_reproducibility.selected_evidence_directory(arguments)

            arguments.evidence_dir = Path("relative")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "absolute path"):
                    check_reproducibility.selected_evidence_directory(arguments)

    def test_workspace_requires_safe_relative_report_outside_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            source = base / "source"
            source.mkdir()
            evidence = base / "evidence"

            missing = self.arguments(root=source, report=None, evidence_dir=evidence)
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "requires a relative"):
                    check_reproducibility.open_report_workspace(missing, source)

            for unsafe in (Path("../escape.json"), base / "absolute.json"):
                with self.subTest(unsafe=unsafe):
                    arguments = self.arguments(
                        root=source, report=unsafe, evidence_dir=evidence
                    )
                    with mock.patch.dict(os.environ, {}, clear=True):
                        with self.assertRaisesRegex(ReleaseError, "evidence path"):
                            check_reproducibility.open_report_workspace(
                                arguments, source
                            )

            internal = self.arguments(
                root=source,
                report=Path("report.json"),
                evidence_dir=source / "evidence",
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "outside"):
                    check_reproducibility.open_report_workspace(internal, source)


if __name__ == "__main__":
    unittest.main()
