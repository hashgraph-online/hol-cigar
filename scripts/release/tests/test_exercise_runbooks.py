#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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

import exercise_runbooks  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class ExerciseRunbooksEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-runbook-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self._write_fixture()

    def _write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def _write_fixture(self) -> None:
        exercises = []
        for identifier in sorted(exercise_runbooks._REQUIRED_EXERCISES):
            document = f"docs/{identifier}.md"
            term = f"required-{identifier}"
            path = self.repository / document
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# {identifier}\n\n{term}\n", encoding="utf-8")
            exercises.append(
                {
                    "id": identifier,
                    "document": document,
                    "required_terms": [term],
                }
            )
        self._write_json(
            self.repository / "packaging/operation-exercises.v1.json",
            {
                "schema_version": "cigar.operation-exercises.v1",
                "exercises": exercises,
            },
        )
        self._write_json(
            self.repository / "packaging/artifact-matrix.v1.json",
            {
                "schema_version": "cigar.artifact-matrix.v1",
                "release_state": "release",
                "product_version": "1.0.0",
                "context_abi": "cigar.context.v1",
                "artifacts": [
                    {
                        "id": "source",
                        "filename": "source.tar.gz",
                        "contract": "contracts/source.v1.json",
                        "required_for_release": True,
                    }
                ],
            },
        )
        candidate = self.repository / "candidate"
        candidate.mkdir(mode=0o700)
        artifact = candidate / "source.tar.gz"
        artifact.write_bytes(b"exact candidate artifact\n")
        self.candidate_manifest = candidate / "release-build.json"
        self._write_json(
            self.candidate_manifest,
            {
                "schema_version": "cigar.release-build.v1",
                "product_version": "1.0.0",
                "context_abi": "cigar.context.v1",
                "source_date_epoch": 1_700_000_000,
                "source": {
                    "revision": "a" * 40,
                    "tree_sha256": "b" * 64,
                    "committed": True,
                    "clean": True,
                },
                "artifacts": [
                    {
                        "id": "source",
                        "path": artifact.name,
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "bytes": artifact.stat().st_size,
                        "contract": "packaging/contracts/source.v1.json",
                    }
                ],
            },
        )

    def _run_main(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> int:
        argv = ["exercise_runbooks.py", "--root", str(self.repository), *arguments]
        selected_environment = {
            "CIGAR_EVIDENCE_DIR": "",
            "CIGAR_OPERATION_SANDBOX_ENFORCED": "",
            **(environment or {}),
        }
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.dict(os.environ, selected_environment, clear=False),
        ):
            return exercise_runbooks.main()

    def test_candidate_static_evidence_uses_environment_workspace(self) -> None:
        evidence = self.base / "candidate-evidence"
        result = self._run_main(
            "--mode",
            "static",
            "--candidate-manifest",
            str(self.candidate_manifest),
            environment={"CIGAR_EVIDENCE_DIR": str(evidence)},
        )
        self.assertEqual(result, 0)
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        outputs = sorted(path for path in evidence.iterdir() if path.is_file())
        self.assertEqual(len(outputs), 9)
        self.assertTrue(
            all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in outputs)
        )
        summary = json.loads((evidence / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exercise_count"], 8)
        self.assertEqual(summary["source_revision"], "a" * 40)
        self.assertEqual(summary["artifact_ids"], ["source"])
        self.assertEqual(len(summary["receipts"]), 8)
        for reference in summary["receipts"]:
            receipt = evidence / reference["path"]
            self.assertEqual(reference["bytes"], receipt.stat().st_size)
            self.assertEqual(
                reference["sha256"], hashlib.sha256(receipt.read_bytes()).hexdigest()
            )

    def test_development_static_keeps_legacy_out_behavior(self) -> None:
        output = self.repository / "development-evidence"
        result = self._run_main("--mode", "static", "--out", str(output))
        self.assertEqual(result, 0)
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["artifact_ids"], ["runbook-documentation"])
        self.assertTrue(summary["source_revision"].startswith("development:"))

    def test_output_sources_must_not_conflict(self) -> None:
        first = self.base / "first"
        second = self.base / "second"
        arguments = argparse.Namespace(evidence_dir=first, out=second)
        with mock.patch.dict(os.environ, {"CIGAR_EVIDENCE_DIR": ""}, clear=False):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                exercise_runbooks._selected_evidence_directory(arguments)

        arguments = argparse.Namespace(evidence_dir=first, out=None)
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(second)}, clear=False
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                exercise_runbooks._selected_evidence_directory(arguments)

        arguments = argparse.Namespace(evidence_dir=first, out=first)
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(first)}, clear=False
        ):
            self.assertEqual(
                exercise_runbooks._selected_evidence_directory(arguments), first
            )

    def test_secure_output_rejects_relative_internal_insecure_and_symlink_roots(
        self,
    ) -> None:
        with self.assertRaisesRegex(EvidenceWorkspaceError, "absolute"):
            exercise_runbooks._EvidenceOutput.open(
                Path("relative"), repository_root=self.repository, secure=True
            )
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            exercise_runbooks._EvidenceOutput.open(
                self.repository / "evidence",
                repository_root=self.repository,
                secure=True,
            )

        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            exercise_runbooks._EvidenceOutput.open(
                insecure, repository_root=self.repository, secure=True
            )

        target = self.base / "target"
        target.mkdir(mode=0o700)
        alias = self.base / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            exercise_runbooks._EvidenceOutput.open(
                alias, repository_root=self.repository, secure=True
            )

        nested = self.base / "nested-symlink-output"
        output = exercise_runbooks._EvidenceOutput.open(
            nested, repository_root=self.repository, secure=True
        )
        self.addCleanup(output.close)
        (nested / "redirect").symlink_to(self.repository, target_is_directory=True)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "not a regular file"):
            output.write_json("safe.json", {"status": "unsafe"})
        self.assertFalse((self.repository / "safe.json").exists())

    def test_secure_output_rejects_overwrite_escape_collision_and_rebound(self) -> None:
        evidence = self.base / "secure-output"
        output = exercise_runbooks._EvidenceOutput.open(
            evidence, repository_root=self.repository, secure=True
        )
        self.addCleanup(output.close)
        output.write_json("receipt.json", {"status": "passed"})
        with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
            output.write_json("receipt.json", {"status": "changed"})
        with self.assertRaises(EvidenceWorkspaceError):
            output.write_json("../escape.json", {"status": "unsafe"})
        output.write_json("Case/one.json", {"status": "passed"})
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            output.write_json("case/two.json", {"status": "unsafe"})

        displaced = self.base / "displaced"
        evidence.rename(displaced)
        evidence.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            output.write_json("after-rebound.json", {"status": "unsafe"})
        self.assertFalse((displaced / "after-rebound.json").exists())
        self.assertFalse((evidence / "after-rebound.json").exists())

    def test_secure_output_requires_an_empty_create_new_workspace(self) -> None:
        evidence = self.base / "existing"
        evidence.mkdir(mode=0o700)
        existing = evidence / "summary.json"
        existing.write_text("{}\n", encoding="utf-8")
        os.chmod(existing, 0o400)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "inventory mismatch"):
            exercise_runbooks._EvidenceOutput.open(
                evidence, repository_root=self.repository, secure=True
            )


if __name__ == "__main__":
    unittest.main()
