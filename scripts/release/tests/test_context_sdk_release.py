from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import context_sdk_beta as release  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


class StableReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cigar-stable-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.profile = release.STABLE
        self.commit = "1" * 40
        for name in self.profile.payloads:
            (self.directory / name).write_text(name)
        self.document = {
            "schema": self.profile.schema,
            "release": self.profile.version,
            "source_commit": self.commit,
            "payloads": release.inventory(self.directory, self.profile.payloads),
        }
        self.save()

    def save(self):
        (self.directory / self.profile.manifest).write_text(json.dumps(self.document))
        (self.directory / "SHA256SUMS").write_text(
            "".join(
                f"{row['sha256']}  {row['file']}\n"
                for row in release.inventory(
                    self.directory, self.profile.payloads | {self.profile.manifest}
                )
            )
        )

    def verify(self, signed=False):
        return release.verify(self.directory, self.commit, signed, profile=self.profile)

    def test_unsigned_candidate_checks_exact_bytes_without_claiming_signatures(self):
        with mock.patch.object(release.subprocess, "run") as runner:
            self.assertEqual(self.verify(), self.document)
            runner.assert_not_called()

    def test_stable_identity_cannot_be_relabelled_or_verified_as_beta(self):
        with self.assertRaises(ReleaseError):
            release.verify(self.directory, self.commit, False)
        for key, value in (
            ("release", "0.10.0-beta.1"),
            ("schema", release.BETA.schema),
            ("source_commit", "2" * 40),
        ):
            with self.subTest(field=key):
                original = self.document[key]
                self.document[key] = value
                self.save()
                with self.assertRaises(ReleaseError):
                    self.verify()
                self.document[key] = original

    def test_tampered_or_added_payload_is_rejected(self):
        (self.directory / "RELEASE_NOTES.md").write_text("substitution")
        with self.assertRaisesRegex(ReleaseError, "payload mismatch"):
            self.verify()
        (self.directory / "unexpected.txt").write_text("unexpected")
        with self.assertRaisesRegex(ReleaseError, "unexpected"):
            self.verify()

    def test_signatures_bind_every_payload_to_stable_workflow_tag_and_commit(self):
        (self.directory / release.BUNDLE).write_text("synthetic test fixture")
        with mock.patch.object(release.subprocess, "run") as runner:
            self.verify(True)
            self.assertEqual(runner.call_count, len(self.profile.signed_files))
            for call in runner.call_args_list:
                argv = call.args[0]
                for flag, expected in (
                    ("--signer-workflow", self.profile.workflow),
                    ("--source-ref", "refs/tags/v0.10.1"),
                    ("--source-digest", self.commit),
                    ("--signer-digest", self.commit),
                ):
                    self.assertEqual(argv[argv.index(flag) + 1], expected)
                self.assertIn("--deny-self-hosted-runners", argv)

    def test_stable_requires_two_independent_qualified_builds(self):
        with self.assertRaisesRegex(ReleaseError, "distinct"):
            release.assemble(
                self.directory,
                self.directory,
                self.directory / "out",
                self.commit,
                "1",
                self.profile,
            )

    def test_stable_archives_have_genuine_stable_identities(self):
        self.assertEqual(
            release.handoff.artifact_names("0.10.1"),
            {
                "cigar-context-0.10.1.crate",
                "hol-org-cigar-0.10.1.tgz",
                "hol_cigar-0.10.1.tar.gz",
                "hol_cigar-0.10.1-py3-none-macosx_11_0_arm64.whl",
            },
        )
        for version in ("0.10.2", "0.10.1-beta.1", "0.10.1+substitution", "../0.10.1"):
            with self.subTest(version=version), self.assertRaises(ReleaseError):
                release.handoff.artifact_names(version)

    def test_stable_workflow_builds_on_branch_and_publishes_only_exact_tag(self):
        source = (
            release.ROOT / ".github/workflows/context-sdk-release.yml"
        ).read_text()
        self.assertIn("branches: [codex/cigar-0.10.1]", source)
        self.assertIn("builder: [first, second]", source)
        self.assertIn("github.ref == 'refs/tags/v0.10.1'", source)
        self.assertIn("--verify-attestations", source)
        self.assertNotIn("--prerelease", source)

    def test_stable_entrypoint_rejects_inapplicable_evidence_before_reading_inputs(
        self,
    ):
        env = os.environ.copy()
        env.pop("CIGAR_EVIDENCE_DIR", None)
        result = subprocess.run(
            [
                sys.executable,
                str(release.ROOT / "scripts/release/context_sdk_release.py"),
                "verify",
                "--directory",
                str(self.directory / "not-opened"),
                "--commit",
                self.commit,
                "--evidence-dir",
                str(self.directory / "inapplicable"),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inapplicable", result.stderr)
