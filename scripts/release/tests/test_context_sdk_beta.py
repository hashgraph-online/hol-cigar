from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

RELEASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE))
import context_sdk_beta as beta  # noqa: E402
from release_lib import ReleaseError  # noqa: E402

COMMIT = "1" * 40


class BetaPublicBytesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cigar-beta-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        for name in beta.PAYLOADS:
            (self.directory / name).write_text(name)
        self.document = {
            "schema": "cigar.context-sdk-beta.v1",
            "release": beta.VERSION,
            "source_commit": COMMIT,
            "payloads": beta.inventory(self.directory, beta.PAYLOADS),
        }
        self.save()

    def save(self):
        (self.directory / beta.MANIFEST).write_text(json.dumps(self.document))
        sums = "".join(
            f"{r['sha256']}  {r['file']}\n"
            for r in beta.inventory(self.directory, beta.PAYLOADS | {beta.MANIFEST})
        )
        (self.directory / "SHA256SUMS").write_text(sums)

    def test_exact_unsigned_bytes_are_not_described_as_signed(self):
        with mock.patch.object(beta.subprocess, "run") as runner:
            self.assertEqual(beta.verify(self.directory, COMMIT, False), self.document)
            runner.assert_not_called()

    def test_tampering_is_rejected(self):
        (self.directory / "RELEASE_NOTES.md").write_text("substitution")
        with self.assertRaisesRegex(ReleaseError, "payload mismatch"):
            beta.verify(self.directory, COMMIT, False)

    def test_missing_file_is_rejected(self):
        (self.directory / "sbom.cdx.json").unlink()
        with self.assertRaisesRegex(ReleaseError, "missing"):
            beta.verify(self.directory, COMMIT, False)

    def test_extra_file_is_rejected(self):
        (self.directory / "unexpected").write_text("extra")
        with self.assertRaisesRegex(ReleaseError, "unexpected"):
            beta.verify(self.directory, COMMIT, False)

    def test_symlink_is_rejected(self):
        selected = self.directory / "RELEASE_NOTES.md"
        selected.unlink()
        selected.symlink_to(self.directory / "sbom.cdx.json")
        with self.assertRaisesRegex(ReleaseError, "symlink"):
            beta.verify(self.directory, COMMIT, False)

    def test_wrong_release_and_source_are_rejected(self):
        for key, value in (
            ("release", "0.10.0"),
            ("source_commit", "2" * 40),
            ("schema", "anything"),
        ):
            with self.subTest(key=key):
                previous = self.document[key]
                self.document[key] = value
                self.save()
                with self.assertRaises(ReleaseError):
                    beta.verify(self.directory, COMMIT, False)
                self.document[key] = previous

    def test_approved_manifest_pin_is_enforced(self):
        with self.assertRaisesRegex(ReleaseError, "approved manifest"):
            beta.verify(self.directory, COMMIT, False, "0" * 64)

    def test_checksums_cannot_omit_or_add_payloads(self):
        (self.directory / "SHA256SUMS").write_text("")
        with self.assertRaisesRegex(ReleaseError, "checksum inventory"):
            beta.verify(self.directory, COMMIT, False)

    def test_signatures_required_for_every_payload_with_exact_identity(self):
        (self.directory / beta.BUNDLE).write_text(
            "synthetic non-cryptographic test bundle"
        )
        with mock.patch.object(beta.subprocess, "run") as runner:
            beta.verify(self.directory, COMMIT, True)
            self.assertEqual(runner.call_count, len(beta.SIGNED_FILES))
            for call in runner.call_args_list:
                args = call.args[0]
                for flag, expected in (
                    ("--repo", beta.REPO),
                    ("--signer-workflow", beta.WORKFLOW),
                    ("--source-ref", "refs/tags/" + beta.TAG),
                    ("--source-digest", COMMIT),
                    ("--signer-digest", COMMIT),
                ):
                    self.assertEqual(args[args.index(flag) + 1], expected)
                self.assertIn("--deny-self-hosted-runners", args)
                self.assertTrue(call.kwargs["check"])

    def test_unsigned_inventory_cannot_pass_signed_mode(self):
        with self.assertRaises(ReleaseError):
            beta.verify(self.directory, COMMIT, True)

    def test_signature_failure_propagates(self):
        (self.directory / beta.BUNDLE).write_text("bad bundle")
        with mock.patch.object(
            beta.subprocess,
            "run",
            side_effect=beta.subprocess.CalledProcessError(1, "gh"),
        ):
            with self.assertRaises(beta.subprocess.CalledProcessError):
                beta.verify(self.directory, COMMIT, True)

    def test_same_build_cannot_supply_both_independent_inputs(self):
        with self.assertRaisesRegex(ReleaseError, "distinct"):
            beta.assemble(
                self.directory, self.directory, self.directory / "out", COMMIT, "1"
            )

    def test_independent_mismatches_fail_before_assembly(self):
        report = {
            "source_binding": {"commit": COMMIT},
            "artifacts": [{"sha256": "1"}],
            "worker": {"sha256": "1"},
        }
        for key in report:
            different = copy.deepcopy(report)
            different[key] = {"changed": True}
            with (
                self.subTest(key=key),
                mock.patch.object(
                    beta, "validate_build", side_effect=[report, different]
                ),
            ):
                with self.assertRaisesRegex(ReleaseError, "independent"):
                    beta.assemble(
                        self.directory / "one",
                        self.directory / "two",
                        self.directory / "out",
                        COMMIT,
                        "1",
                    )

    def test_genuine_beta_core_archive_identity(self):
        self.assertIn("cigar-context-0.10.0-beta.1.crate", beta.PAYLOADS)
        self.assertNotIn("cigar-context-0.10.0.crate", beta.PAYLOADS)


if __name__ == "__main__":
    unittest.main()
