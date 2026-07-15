from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools" / "quality" / "ci_workflow_receipt.py"
SPEC = importlib.util.spec_from_file_location("ci_workflow_receipt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ci_receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_receipt)


REVISION = "1" * 40
TREE = "2" * 40


def source_identity() -> dict[str, object]:
    return {
        "revision": REVISION,
        "tree": TREE,
        "committed": True,
        "clean": True,
        "status": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
    }


class MacosCiWorkflowReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-ci-receipt-test-")
        self.root = Path(self.temporary.name).resolve(strict=True)
        os.chmod(self.root, 0o700)
        self.attachment = self.root / "underlying.json"
        self.attachment.write_bytes(b'{"status":"passed"}\n')
        os.chmod(self.attachment, 0o400)
        self.output = self.root / "workflow-receipt.json"

    def tearDown(self) -> None:
        for path in self.root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                path.chmod(0o600)
        self.temporary.cleanup()

    def arguments(self, **changes: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "output": self.output,
            "lane": "effect-rc",
            "event_sha": REVISION,
            "repository": "owner/repository",
            "run_id": "1234",
            "run_attempt": "2",
            "job": "effect-rc",
            "command": "cargo nextest run --locked --offline",
            "attachment": [f"effect-receipt={self.attachment}"],
        }
        values.update(changes)
        return argparse.Namespace(**values)

    @staticmethod
    def native_platform() -> dict[str, str]:
        return {
            "system": "Darwin",
            "machine": "arm64",
            "target": "aarch64-apple-darwin",
        }

    def publish(self, **changes: object) -> None:
        with (
            mock.patch.object(
                ci_receipt, "source_identity", return_value=source_identity()
            ),
            mock.patch.object(
                ci_receipt, "_platform", return_value=self.native_platform()
            ),
        ):
            ci_receipt.publish(self.arguments(**changes))

    def test_publish_is_content_free_source_bound_and_create_new(self) -> None:
        self.publish()
        document = ci_receipt._strict_json(
            self.output.read_bytes(), "test workflow receipt"
        )
        validated = ci_receipt.validate_document(document)
        self.assertEqual(validated["source"], source_identity())
        self.assertEqual(
            validated["builder"]["identity"],
            "github-actions://owner/repository/actions/runs/1234/attempts/2/jobs/effect-rc",
        )
        self.assertEqual(
            validated["attachments"],
            [
                {
                    "id": "effect-receipt",
                    "bytes": self.attachment.stat().st_size,
                    "sha256": hashlib.sha256(self.attachment.read_bytes()).hexdigest(),
                }
            ],
        )
        self.assertNotIn(str(self.attachment), self.output.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o400)
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "create-new"):
            self.publish()

    def test_verify_reopens_source_command_and_attachments(self) -> None:
        self.publish()
        arguments = argparse.Namespace(
            receipt=self.output,
            event_sha=REVISION,
            repository="owner/repository",
            run_id="1234",
            run_attempt="2",
            job="effect-rc",
            command="cargo nextest run --locked --offline",
            attachment=[f"effect-receipt={self.attachment}"],
        )
        with (
            mock.patch.object(
                ci_receipt, "source_identity", return_value=source_identity()
            ),
            mock.patch.object(
                ci_receipt, "_platform", return_value=self.native_platform()
            ),
        ):
            ci_receipt.verify(arguments)
        arguments.command = "substituted command"
        with (
            mock.patch.object(
                ci_receipt, "source_identity", return_value=source_identity()
            ),
            mock.patch.object(
                ci_receipt, "_platform", return_value=self.native_platform()
            ),
            self.assertRaisesRegex(ci_receipt.ReceiptError, "command binding"),
        ):
            ci_receipt.verify(arguments)

    def test_verify_rejects_another_builder_or_platform(self) -> None:
        self.publish()
        arguments = argparse.Namespace(
            receipt=self.output,
            event_sha=REVISION,
            repository="owner/repository",
            run_id="1234",
            run_attempt="3",
            job="effect-rc",
            command="cargo nextest run --locked --offline",
            attachment=[f"effect-receipt={self.attachment}"],
        )
        with (
            mock.patch.object(
                ci_receipt, "source_identity", return_value=source_identity()
            ),
            mock.patch.object(
                ci_receipt, "_platform", return_value=self.native_platform()
            ),
            self.assertRaisesRegex(ci_receipt.ReceiptError, "builder binding"),
        ):
            ci_receipt.verify(arguments)
        arguments.run_attempt = "2"
        with (
            mock.patch.object(
                ci_receipt,
                "_platform",
                side_effect=ci_receipt.ReceiptError("not native"),
            ),
            self.assertRaisesRegex(ci_receipt.ReceiptError, "not native"),
        ):
            ci_receipt.verify(arguments)

    def test_tampered_receipt_id_and_claims_fail(self) -> None:
        self.publish()
        document = ci_receipt._strict_json(self.output.read_bytes(), "receipt")
        for mutate in (
            lambda value: value.__setitem__("receipt_id", "f" * 64),
            lambda value: value["claims"].__setitem__("fuzz_executed", True),
            lambda value: value["source"].__setitem__("clean", False),
            lambda value: value["builder"].__setitem__("run_attempt", 9),
        ):
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(document)
                mutate(changed)
                with self.assertRaises(ci_receipt.ReceiptError):
                    ci_receipt.validate_document(changed)

        changed = copy.deepcopy(document)
        changed["created_utc"] = "2026-99-99T99:99:99Z"
        body = {key: value for key, value in changed.items() if key != "receipt_id"}
        changed["receipt_id"] = ci_receipt.sha256_bytes(
            ci_receipt.canonical_bytes(body)
        )
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "identity or claims"):
            ci_receipt.validate_document(changed)

    def test_unsafe_attachment_forms_fail_closed(self) -> None:
        second = self.root / "second.json"
        second.write_bytes(b"{}\n")
        os.chmod(second, 0o400)
        cases = (
            [f"duplicate={self.attachment}", f"duplicate={second}"],
            [f"UPPERCASE={self.attachment}"],
            [f"missing={self.root / 'missing.json'}"],
        )
        for attachments in cases:
            with (
                self.subTest(attachments=attachments),
                self.assertRaises(ci_receipt.ReceiptError),
            ):
                self.publish(attachment=attachments)

        alias = self.root / "alias.json"
        alias.symlink_to(self.attachment)
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "protected"):
            self.publish(attachment=[f"alias={alias}"])

        os.chmod(second, 0o666)
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "protected"):
            self.publish(attachment=[f"writable={second}"])

    def test_hardlinked_or_aliased_attachments_fail(self) -> None:
        alias = self.root / "hardlink.json"
        os.link(self.attachment, alias)
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "single-link"):
            self.publish(
                attachment=[
                    f"first={self.attachment}",
                    f"second={alias}",
                ]
            )

    def test_builder_and_lane_are_closed_world(self) -> None:
        for changes in (
            {"lane": "fuzz"},
            {"repository": "not-a-repository"},
            {"run_id": "0"},
            {"run_attempt": "not-a-number"},
            {"job": "unsafe/job"},
            {"command": ""},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(ci_receipt.ReceiptError),
            ):
                self.publish(**changes)

    def test_source_identity_requires_exact_clean_event_revision(self) -> None:
        clean_status = b""
        outputs = {
            ("rev-parse", "--verify", "HEAD"): (REVISION + "\n").encode(),
            ("rev-parse", "--verify", "HEAD^{tree}"): (TREE + "\n").encode(),
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"): clean_status,
        }
        with mock.patch.object(
            ci_receipt,
            "_git",
            side_effect=lambda arguments, _maximum: outputs[tuple(arguments)],
        ):
            self.assertEqual(ci_receipt.source_identity(REVISION), source_identity())
            with self.assertRaisesRegex(ci_receipt.ReceiptError, "exact clean"):
                ci_receipt.source_identity("3" * 40)
        outputs[("status", "--porcelain=v1", "-z", "--untracked-files=all")] = (
            b" M Cargo.toml\0"
        )
        with (
            mock.patch.object(
                ci_receipt,
                "_git",
                side_effect=lambda arguments, _maximum: outputs[tuple(arguments)],
            ),
            self.assertRaisesRegex(ci_receipt.ReceiptError, "exact clean"),
        ):
            ci_receipt.source_identity(REVISION)

    def test_platform_scope_is_native_apple_silicon_only(self) -> None:
        with mock.patch.object(ci_receipt.sys, "platform", "linux"):
            with self.assertRaisesRegex(ci_receipt.ReceiptError, "Apple-silicon"):
                ci_receipt._platform()
        with (
            mock.patch.object(ci_receipt.sys, "platform", "darwin"),
            mock.patch.object(ci_receipt.platform, "machine", return_value="x86_64"),
            self.assertRaisesRegex(ci_receipt.ReceiptError, "Apple-silicon"),
        ):
            ci_receipt._platform()

    def test_output_directory_must_be_external_canonical_and_private(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "mode 0700"):
            self.publish(output=unsafe / "receipt.json")
        repository_directory = ROOT / ".ci-workflow-receipt-test"
        repository_directory.mkdir(mode=0o700)
        self.addCleanup(repository_directory.rmdir)
        repository_output = repository_directory / "receipt.json"
        with self.assertRaisesRegex(ci_receipt.ReceiptError, "outside"):
            self.publish(output=repository_output)
        self.assertFalse(repository_output.exists())


if __name__ == "__main__":
    unittest.main()
