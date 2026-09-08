from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import context_sdk_inputs as inputs  # noqa: E402
import product_version  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cigar-source-binding-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "Cargo.toml").write_text("fixture source\n")
        self.status = b""
        self.commit = b"1" * 40
        self.names = b"Cargo.toml\0"
        self.patch = mock.patch.object(inputs, "_git", side_effect=self.git)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.paths = mock.patch.object(inputs, "EXACT_INPUTS", ("Cargo.toml",))
        self.paths.start()
        self.addCleanup(self.paths.stop)

    def git(self, root, *args):
        if args[0] == "status":
            return self.status
        if args[0] == "ls-files":
            return self.names
        if args[0] == "show":
            return b"1788739200"
        return self.commit

    def test_clean_revision_and_source_hash_are_bound(self):
        first = inputs.capture(self.root)
        self.assertTrue(first["clean"])
        self.assertEqual(first["commit"], "1" * 40)
        self.assertEqual(first["source_date_epoch"], 1788739200)
        inputs.require_unchanged(self.root, first)
        (self.root / "Cargo.toml").write_text("changed source\n")
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            inputs.require_unchanged(self.root, first)

    def test_commit_change_is_rejected_even_with_identical_source(self):
        first = inputs.capture(self.root)
        self.commit = b"2" * 40
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            inputs.require_unchanged(self.root, first)

    def test_dirty_checkout_requires_explicit_diagnostic_opt_in(self):
        self.status = b" M Cargo.toml\n"
        with self.assertRaisesRegex(ReleaseError, "clean checkout"):
            inputs.capture(self.root)
        self.assertFalse(inputs.capture(self.root, allow_dirty=True)["clean"])

    def test_missing_tracked_input_fails(self):
        self.names = b""
        with self.assertRaisesRegex(ReleaseError, "missing a tracked"):
            inputs.capture(self.root)

    def test_legacy_version_generator_cannot_partially_overwrite_sdk_release(self):
        (self.root / "sdk").mkdir()
        (self.root / "sdk/local-context-release.v1.json").write_text("{}")
        with mock.patch.object(product_version, "_update_toml_manifests") as mutation:
            with self.assertRaisesRegex(
                product_version.VersionError, "No files changed"
            ):
                product_version.generate(self.root)
            mutation.assert_not_called()
        self.assertEqual((self.root / "Cargo.toml").read_text(), "fixture source\n")

    def test_environment_and_generated_files_are_not_opened(self):
        self.names += (
            b"sdk/python/.env\0sdk/python/.venv/hidden.py\0sdk/python/private.pem\0"
        )
        self.assertEqual(set(inputs.capture(self.root)["files"]), {"Cargo.toml"})


class DiagnosticEntrypointTests(unittest.TestCase):
    COMMANDS = (
        (
            "prepare_context_sdk_rc.py",
            "--output",
            "/tmp/not-created",
            "--cargo",
            "/unused/cargo",
            "--pnpm",
            "/unused/pnpm",
            "--npm",
            "/unused/npm",
            "--uv",
            "/unused/uv",
            "--target-dir",
            "/tmp/not-created-target",
        ),
        (
            "qualify_context_sdk_rc.py",
            "--release",
            "/unused/release",
            "--output",
            "/tmp/not-created",
            "--baseline",
            "/unused/baseline",
            "--uv",
            "/unused/uv",
            "--pnpm",
            "/unused/pnpm",
            "--npm",
            "/unused/npm",
            "--cli",
            "/unused/cli",
        ),
        (
            "finalize_context_sdk_rc.py",
            "--release",
            "/unused/release",
            "--qualification",
            "/unused/qualification",
            "--artifacts",
            "/tmp/not-created",
            "--evidence",
            "/tmp/not-created-evidence",
            "--uv",
            "/unused/uv",
            "--actionlint",
            "/unused/actionlint",
        ),
    )

    def test_diagnostic_producers_reject_release_evidence_selector(self):
        for command in self.COMMANDS:
            for via_environment in (False, True):
                with self.subTest(command=command[0], environment=via_environment):
                    environment = os.environ.copy()
                    environment.pop("CIGAR_EVIDENCE_DIR", None)
                    extra = ["--evidence-dir", "/tmp/not-created-evidence"]
                    if via_environment:
                        environment["CIGAR_EVIDENCE_DIR"] = extra[1]
                        extra = []
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(RELEASE / command[0]),
                            *command[1:],
                            *extra,
                        ],
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("inapplicable", result.stderr)

    def test_optimized_python_cannot_disable_qualification(self):
        for command in self.COMMANDS:
            with self.subTest(command=command[0]):
                result = subprocess.run(
                    [sys.executable, "-O", str(RELEASE / command[0]), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("assertions enabled", result.stderr)
