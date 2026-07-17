#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
ROOT = RELEASE.parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import assemble_evidence  # noqa: E402
import beta_artifacts  # noqa: E402
import beta_release  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes  # noqa: E402
import selftest_release_verifier  # noqa: E402
import signatures  # noqa: E402


class SourceOnlyEntrypointTests(unittest.TestCase):
    def test_every_release_entrypoint_declares_the_common_selector(self) -> None:
        entrypoints = []
        missing = []
        for path in sorted(RELEASE.glob("*.py"), key=lambda item: item.name):
            source = path.read_text(encoding="utf-8")
            if "__main__" not in source:
                continue
            entrypoints.append(path.name)
            if "--evidence-dir" not in source:
                missing.append(path.name)
        self.assertEqual(len(entrypoints), 44)
        self.assertEqual(missing, [])

    def test_source_mutators_and_stdout_only_checks_reject_evidence(self) -> None:
        evidence = "/tmp/cigar-inapplicable-evidence"
        commands = (
            ("beta_profile.py", "check", "--root", str(ROOT)),
            (
                "development_macos_profile.py",
                "check",
                "--root",
                str(ROOT),
            ),
            (
                "generate_beta_licenses.py",
                "--root",
                str(ROOT),
                "--crate-cache",
                "/tmp/not-opened-crate-cache",
                "--rustc",
                "/tmp/not-opened-rustc",
            ),
            ("validate_metadata.py", "--root", str(ROOT)),
            (
                "development_protocol_baseline.py",
                "check",
                "--root",
                str(ROOT),
            ),
            ("product_version.py", "check", "--root", str(ROOT)),
            ("post_beta_profile.py", "check", "--root", str(ROOT)),
        )
        environment = os.environ.copy()
        environment.pop("CIGAR_EVIDENCE_DIR", None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for command in commands:
            with self.subTest(script=command[0]):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(RELEASE / command[0]),
                        *command[1:],
                        "--evidence-dir",
                        evidence,
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("inapplicable", result.stderr)


class BetaOrchestrationSelectorTests(unittest.TestCase):
    def test_beta_artifact_producers_select_one_external_workspace(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            selected = beta_artifacts._selected_output(
                argparse.Namespace(
                    evidence_dir=Path("/tmp/cigar-beta-candidate"),
                    out=None,
                ),
                "beta candidate build",
            )
            self.assertEqual(selected, Path("/tmp/cigar-beta-candidate"))
            with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "both"):
                beta_artifacts._selected_output(
                    argparse.Namespace(
                        evidence_dir=Path("/tmp/cigar-beta-candidate"),
                        out=Path("/tmp/legacy-candidate"),
                    ),
                    "beta candidate build",
                )
            with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "requires"):
                beta_artifacts._selected_output(
                    argparse.Namespace(evidence_dir=None, out=None),
                    "beta candidate build",
                )

    def test_beta_release_plan_and_inventory_have_unambiguous_outputs(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            plan = beta_release._selected_output(
                argparse.Namespace(
                    action="plan",
                    evidence_dir=Path("/tmp/cigar-beta-release-plan"),
                    out=None,
                )
            )
            self.assertEqual(
                plan,
                Path("/tmp/cigar-beta-release-plan/release-evidence.json"),
            )
            assembled = beta_release._selected_output(
                argparse.Namespace(
                    action="assemble",
                    evidence_dir=Path("/tmp/cigar-beta-release"),
                    out=None,
                )
            )
            self.assertEqual(assembled, Path("/tmp/cigar-beta-release"))
            with self.assertRaisesRegex(beta_release.BetaReleaseError, "both"):
                beta_release._selected_output(
                    argparse.Namespace(
                        action="assemble",
                        evidence_dir=Path("/tmp/cigar-beta-release"),
                        out=Path("/tmp/legacy-release"),
                    )
                )


class AssembleEvidenceOutputTests(unittest.TestCase):
    def test_external_output_is_canonical_private_and_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            evidence = base / "evidence"
            arguments = argparse.Namespace(
                evidence_dir=evidence,
                out="nested/release-evidence.json",
            )
            document = {"status": "passed", "metrics": {"count": 1}}
            assemble_evidence._publish_assembled(
                arguments,
                root=repository,
                dist=repository / "dist",
                occupied_paths=set(),
                document=document,
            )
            output = evidence / "nested/release-evidence.json"
            self.assertEqual(output.read_bytes(), canonical_json_bytes(document))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
            with self.assertRaisesRegex(ReleaseError, "overwrite"):
                assemble_evidence._publish_assembled(
                    arguments,
                    root=repository,
                    dist=repository / "dist",
                    occupied_paths=set(),
                    document=document,
                )

    def test_internal_root_and_path_escape_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            with self.assertRaisesRegex(ReleaseError, "outside"):
                assemble_evidence._publish_assembled(
                    argparse.Namespace(
                        evidence_dir=repository / "evidence",
                        out="release-evidence.json",
                    ),
                    root=repository,
                    dist=repository / "dist",
                    occupied_paths=set(),
                    document={"status": "passed"},
                )
            with self.assertRaisesRegex(ReleaseError, "unsafe|path"):
                assemble_evidence._publish_assembled(
                    argparse.Namespace(
                        evidence_dir=base / "external",
                        out="../escape.json",
                    ),
                    root=repository,
                    dist=repository / "dist",
                    occupied_paths=set(),
                    document={"status": "passed"},
                )


class SignatureEvidenceOutputTests(unittest.TestCase):
    @staticmethod
    def _arguments(base: Path, repository: Path, evidence: Path) -> argparse.Namespace:
        inputs = base / "inputs"
        inputs.mkdir(mode=0o700)
        payload = inputs / "payload.bin"
        private_key = inputs / "private.pem"
        public_key = inputs / "public.pem"
        for path, content in (
            (payload, b"payload\n"),
            (private_key, b"private\n"),
            (public_key, b"public\n"),
        ):
            path.write_bytes(content)
            path.chmod(0o600)
        return argparse.Namespace(
            root=repository,
            evidence_dir=evidence,
            out=Path("signatures/envelope.json"),
            payload=payload,
            private_key=private_key,
            public_key=public_key,
            signer_principal="cigar:test",
            purpose="release-evidence",
            signed_at=1_700_000_000,
            expires_at=None,
            openssl=None,
            openssl_sha256="0" * 64,
        )

    def test_signature_is_staged_and_published_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            evidence = base / "evidence"
            arguments = self._arguments(base, repository, evidence)
            envelope = {
                "schema_version": "cigar.test-signature-envelope.v1",
                "signature": "test",
            }

            def fake_sign(
                _payload: Path,
                _private_key: Path,
                _public_key: Path,
                output: Path,
                **_keywords: object,
            ) -> None:
                signatures._write_new_private_json(output, envelope)

            with mock.patch.object(signatures, "sign", side_effect=fake_sign):
                observed = signatures._sign_to_evidence_workspace(
                    arguments,
                    evidence,
                )
            output = evidence / "signatures/envelope.json"
            self.assertEqual(observed, canonical_json_bytes(envelope))
            self.assertEqual(output.read_bytes(), observed)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
            with (
                mock.patch.object(signatures, "sign", side_effect=fake_sign),
                self.assertRaisesRegex(ReleaseError, "overwrite"),
            ):
                signatures._sign_to_evidence_workspace(arguments, evidence)

    def test_signature_escape_and_repository_local_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            arguments = self._arguments(base, repository, base / "evidence")
            arguments.out = Path("../escape.json")
            with self.assertRaisesRegex(ReleaseError, "unsafe|path"):
                signatures._sign_to_evidence_workspace(arguments, base / "evidence")
            arguments.out = Path("envelope.json")
            with self.assertRaisesRegex(ReleaseError, "outside"):
                signatures._sign_to_evidence_workspace(
                    arguments,
                    repository / "evidence",
                )


class SelftestEvidenceOutputTests(unittest.TestCase):
    def test_main_publishes_an_external_report_without_running_children(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(strict=True)
            repository = base / "repository"
            repository.mkdir(mode=0o700)
            evidence = base / "evidence"
            arguments = argparse.Namespace(
                evidence_dir=evidence,
                report=Path("selftest/result.json"),
            )
            result = {
                "schema_version": "cigar.release-verifier-selftest-result.v1",
                "status": "passed",
                "release_ready": False,
                "checks": [],
            }
            with (
                mock.patch.object(
                    selftest_release_verifier,
                    "parse_arguments",
                    return_value=arguments,
                ),
                mock.patch.object(
                    selftest_release_verifier,
                    "repo_root",
                    return_value=repository,
                ),
                mock.patch.object(
                    selftest_release_verifier,
                    "_execute_selftest",
                    return_value=result,
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(selftest_release_verifier.main(), 0)
            output = evidence / "selftest/result.json"
            self.assertEqual(output.read_bytes(), canonical_json_bytes(result))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)

    def test_child_commands_do_not_inherit_parent_selector(self) -> None:
        captured: dict[str, str] = {}

        def fake_run(
            arguments: list[str],
            **keywords: object,
        ) -> subprocess.CompletedProcess[bytes]:
            del arguments
            environment = keywords["env"]
            assert isinstance(environment, dict)
            captured.update(environment)
            return subprocess.CompletedProcess(["fixture"], 0, b"", b"")

        with (
            mock.patch.dict(
                os.environ,
                {"CIGAR_EVIDENCE_DIR": "/tmp/parent", "KEEP": "yes"},
                clear=True,
            ),
            mock.patch.object(
                selftest_release_verifier,
                "run_bounded",
                side_effect=fake_run,
            ),
        ):
            selftest_release_verifier._run(["fixture"], ROOT)
        self.assertNotIn("CIGAR_EVIDENCE_DIR", captured)
        self.assertEqual(captured["KEEP"], "yes")


if __name__ == "__main__":
    unittest.main()
