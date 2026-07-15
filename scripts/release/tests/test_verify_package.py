#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import verify_package  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class VerifyPackageEvidenceTests(unittest.TestCase):
    def arguments(
        self,
        *,
        archive: Path,
        contract: Path,
        report: Path | None,
        evidence_dir: Path | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            archive=archive,
            contract=contract,
            expected_version=None,
            expected_abi=None,
            source_date_epoch=None,
            report=report,
            evidence_dir=evidence_dir,
        )

    def inputs(self, base: Path) -> tuple[Path, Path]:
        archive = base / "artifact.tar"
        contract = base / "contract.json"
        archive.write_bytes(b"archive")
        contract.write_text("{}", encoding="utf-8")
        return archive, contract

    def run_main(self, arguments: SimpleNamespace, report: dict[str, object]) -> str:
        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                verify_package, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(verify_package, "verify", return_value=report),
            redirect_stdout(output),
        ):
            self.assertEqual(verify_package.main(), 0)
        return output.getvalue()

    def test_development_report_behavior_is_unchanged_without_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, contract = self.inputs(base)
            destination = base / "development" / "report.json"
            arguments = self.arguments(
                archive=archive, contract=contract, report=destination
            )
            report = {"schema_version": "test.v1", "status": "passed"}

            stdout = self.run_main(arguments, report)

            self.assertEqual(json.loads(destination.read_bytes()), report)
            self.assertEqual(
                stdout, verify_package.canonical_json_bytes(report).decode()
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)

    def test_external_report_is_canonical_owner_only_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, contract = self.inputs(base)
            evidence = base / "evidence"
            arguments = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("reports/package.json"),
                evidence_dir=evidence,
            )
            first_report = {"z": 1, "a": [True, None]}

            self.run_main(arguments, first_report)

            destination = evidence / "reports" / "package.json"
            self.assertEqual(destination.read_bytes(), b'{"a":[true,null],"z":1}\n')
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
            self.assertEqual(destination.stat().st_nlink, 1)

            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(
                    verify_package, "parse_arguments", return_value=arguments
                ),
                mock.patch.object(
                    verify_package, "verify", return_value={"replaced": True}
                ),
                self.assertRaisesRegex(ReleaseError, "overwrite"),
            ):
                verify_package.main()
            self.assertEqual(destination.read_bytes(), b'{"a":[true,null],"z":1}\n')

    def test_environment_selection_and_conflict_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, contract = self.inputs(base)
            environment = base / "environment"
            arguments = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("report.json"),
            )
            with mock.patch.dict(
                os.environ, {"CIGAR_EVIDENCE_DIR": str(environment)}, clear=True
            ):
                self.assertEqual(
                    verify_package.selected_evidence_directory(arguments), environment
                )

            arguments.evidence_dir = base / "argument"
            with mock.patch.dict(
                os.environ, {"CIGAR_EVIDENCE_DIR": str(environment)}, clear=True
            ):
                with self.assertRaisesRegex(ReleaseError, "conflicts"):
                    verify_package.selected_evidence_directory(arguments)

            arguments.evidence_dir = Path("relative")
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "absolute path"):
                    verify_package.selected_evidence_directory(arguments)

    def test_workspace_requires_report_and_safe_relative_destination(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, contract = self.inputs(base)
            evidence = base / "evidence"
            missing = self.arguments(
                archive=archive,
                contract=contract,
                report=None,
                evidence_dir=evidence,
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "requires a relative"):
                    verify_package.open_report_workspace(missing)
            self.assertFalse(evidence.exists())

            for unsafe in (Path("../escaped.json"), base / "absolute.json"):
                with self.subTest(unsafe=unsafe):
                    arguments = self.arguments(
                        archive=archive,
                        contract=contract,
                        report=unsafe,
                        evidence_dir=evidence,
                    )
                    with mock.patch.dict(os.environ, {}, clear=True):
                        with self.assertRaisesRegex(ReleaseError, "evidence path"):
                            verify_package.open_report_workspace(arguments)
                    self.assertFalse(evidence.exists())

    def test_workspace_rejects_internal_symlink_and_non_private_roots(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, contract = self.inputs(base)

            internal = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("report.json"),
                evidence_dir=verify_package.REPOSITORY_ROOT / "reports" / "package",
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "outside"):
                    verify_package.open_report_workspace(internal)

            target = base / "target"
            target.mkdir(mode=0o700)
            alias = base / "alias"
            alias.symlink_to(target, target_is_directory=True)
            symlinked = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("report.json"),
                evidence_dir=alias,
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "unsafe"):
                    verify_package.open_report_workspace(symlinked)

            public = base / "public"
            public.mkdir(mode=0o755)
            os.chmod(public, 0o755)
            public_arguments = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("report.json"),
                evidence_dir=public,
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "0700"):
                    verify_package.open_report_workspace(public_arguments)

    def test_workspace_rejects_case_collision_and_preserves_distinct_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, contract = self.inputs(base)
            evidence = base / "evidence"
            first = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("Result.json"),
                evidence_dir=evidence,
            )
            self.run_main(first, {"first": True})

            collision = self.arguments(
                archive=archive,
                contract=contract,
                report=Path("result.json"),
                evidence_dir=evidence,
            )
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(
                    verify_package, "parse_arguments", return_value=collision
                ),
                mock.patch.object(
                    verify_package, "verify", return_value={"second": True}
                ),
                self.assertRaisesRegex(ReleaseError, "collision"),
            ):
                verify_package.main()

            distinct_evidence = base / "distinct"
            distinct_evidence.mkdir(mode=0o700)
            archive_report = distinct_evidence / "archive.tar"
            archive_report.write_bytes(b"archive")
            os.chmod(archive_report, 0o400)
            distinct = self.arguments(
                archive=archive_report,
                contract=contract,
                report=Path("archive.tar"),
                evidence_dir=distinct_evidence,
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
                    verify_package.open_report_workspace(distinct)


if __name__ == "__main__":
    unittest.main()
