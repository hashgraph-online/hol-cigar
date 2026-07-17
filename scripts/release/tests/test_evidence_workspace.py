#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from evidence_workspace import (  # noqa: E402
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    canonical_json_bytes,
    digest_secure_file,
    safe_relative_path,
    validate_metrics,
)


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class EvidenceWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)

    def workspace(
        self, name: str = "evidence", *, limits: EvidenceLimits | None = None
    ) -> EvidenceWorkspace:
        return EvidenceWorkspace.create(
            self.base / name,
            repository_root=self.repository,
            limits=limits,
        )

    def test_private_external_create_new_canonical_json(self) -> None:
        with self.workspace() as workspace:
            attachment = workspace.write_json(
                "receipts/result.json", {"z": 1, "a": [True, None]}
            )
            output = workspace.root / attachment.path
            self.assertEqual(output.read_bytes(), b'{"a":[true,null],"z":1}\n')
            self.assertEqual(stat.S_IMODE(workspace.root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
            self.assertEqual(output.stat().st_nlink, 1)
            self.assertEqual(attachment.bytes, output.stat().st_size)
            with self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"):
                workspace.write_json("receipts/result.json", {"different": True})

    def test_descriptor_relative_exact_snapshot_reads_stable_bytes(self) -> None:
        with self.workspace() as workspace:
            workspace.write_json("one.json", {"value": 1})
            workspace.write_json("nested/two.json", {"value": 2})
            payloads = workspace.read_files(
                {"one.json", "nested/two.json"}, strict_read_only=True
            )
            self.assertEqual(payloads["one.json"], b'{"value":1}\n')
            self.assertEqual(payloads["nested/two.json"], b'{"value":2}\n')
            with self.assertRaisesRegex(
                EvidenceWorkspaceError, "snapshot inventory mismatch"
            ):
                workspace.read_files({"one.json"}, strict_read_only=True)

    def test_internal_relative_noncanonical_and_insecure_roots_are_rejected(
        self,
    ) -> None:
        internal = self.repository / "evidence"
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            EvidenceWorkspace.create(internal, repository_root=self.repository)
        self.assertFalse(internal.exists(), "repo-internal output was created")
        with self.assertRaisesRegex(EvidenceWorkspaceError, "absolute"):
            EvidenceWorkspace.create(Path("relative"), repository_root=self.repository)
        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        os.chmod(insecure, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            EvidenceWorkspace.create(insecure, repository_root=self.repository)

    def test_symlink_root_and_workspace_entries_are_rejected(self) -> None:
        target = self.base / "target"
        target.mkdir(mode=0o700)
        alias = self.base / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            EvidenceWorkspace.create(alias, repository_root=self.repository)
        with self.workspace() as workspace:
            (workspace.root / "redirect").symlink_to(self.repository)
            with self.assertRaisesRegex(EvidenceWorkspaceError, "not a regular file"):
                workspace.write_json("safe.json", {"safe": True})

    def test_open_workspace_rejects_root_path_replacement(self) -> None:
        workspace = self.workspace()
        self.addCleanup(workspace.close)
        displaced = self.base / "displaced"
        workspace.root.rename(displaced)
        workspace.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            workspace.write_json("receipt.json", {"safe": True})
        self.assertFalse((displaced / "receipt.json").exists())
        self.assertFalse((workspace.root / "receipt.json").exists())

    def test_path_escape_case_and_unicode_aliases_are_rejected(self) -> None:
        with self.workspace() as workspace:
            workspace.write_json("Case/receipt.json", {"ok": True})
            with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
                workspace.write_json("case/other.json", {"ok": True})
            decomposed = unicodedata.normalize("NFD", "café")
            self.assertNotEqual(decomposed, "café")
            with self.assertRaisesRegex(EvidenceWorkspaceError, "NFC"):
                workspace.write_json(f"{decomposed}.json", {"ok": True})
            for unsafe in ("../escape.json", "a/../../escape", "/absolute", "a\\b"):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaises(EvidenceWorkspaceError):
                        workspace.write_json(unsafe, {"ok": True})

    def test_unrelated_noncanonical_parent_entry_cannot_redirect_workspace(
        self,
    ) -> None:
        unrelated = self.base / unicodedata.normalize("NFD", "unrelated-é")
        unrelated.mkdir(mode=0o700)
        with self.workspace() as workspace:
            workspace.write_json("receipt.json", {"safe": True})
            self.assertTrue((workspace.root / "receipt.json").is_file())

    def test_attachments_reject_symlink_hardlink_writable_and_nonregular_sources(
        self,
    ) -> None:
        source = self.base / "source.bin"
        source.write_bytes(b"reviewed bytes")
        os.chmod(source, 0o600)
        with self.workspace() as workspace:
            copied = workspace.attach_file(
                source,
                "attachments/source.bin",
                expected_sha256=hashlib.sha256(b"reviewed bytes").hexdigest(),
                expected_bytes=len(b"reviewed bytes"),
            )
            self.assertEqual(
                (workspace.root / copied.path).read_bytes(), b"reviewed bytes"
            )

        alias = self.base / "source-link.bin"
        alias.symlink_to(source)
        with self.workspace("symlink-evidence") as workspace:
            with self.assertRaises(EvidenceWorkspaceError):
                workspace.attach_file(alias, "attachment.bin")

        hardlink = self.base / "source-hardlink.bin"
        os.link(source, hardlink)
        with self.workspace("hardlink-evidence") as workspace:
            with self.assertRaisesRegex(EvidenceWorkspaceError, "hardlinked"):
                workspace.attach_file(source, "attachment.bin")
        hardlink.unlink()

        os.chmod(source, 0o622)
        with self.workspace("writable-evidence") as workspace:
            with self.assertRaisesRegex(EvidenceWorkspaceError, "group/world writable"):
                workspace.attach_file(source, "attachment.bin")

        fifo = self.base / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.workspace("fifo-evidence") as workspace:
            with self.assertRaisesRegex(EvidenceWorkspaceError, "not regular"):
                workspace.attach_file(fifo, "attachment.bin")

    def test_attachment_content_binding_rejects_substitution_before_publish(
        self,
    ) -> None:
        source = self.base / "bound-source.bin"
        reviewed = b"reviewed-content"
        source.write_bytes(reviewed)
        os.chmod(source, 0o600)
        expected_sha256 = hashlib.sha256(reviewed).hexdigest()
        expected_bytes = len(reviewed)

        source.write_bytes(b"substitute-bytes")
        with self.workspace("substitution-evidence") as workspace:
            with self.assertRaisesRegex(EvidenceWorkspaceError, "validated content"):
                workspace.attach_file(
                    source,
                    "attachment.bin",
                    expected_sha256=expected_sha256,
                    expected_bytes=expected_bytes,
                )
            self.assertFalse((workspace.root / "attachment.bin").exists())

            with self.assertRaisesRegex(
                EvidenceWorkspaceError, "lowercase hexadecimal"
            ):
                workspace.attach_file(
                    source,
                    "invalid-digest.bin",
                    expected_sha256="A" * 64,
                )
            self.assertFalse((workspace.root / "invalid-digest.bin").exists())

    def test_existing_hardlinks_and_quota_overflow_are_rejected(self) -> None:
        root = self.base / "hardlinked-workspace"
        root.mkdir(mode=0o700)
        first = root / "one"
        first.write_bytes(b"x")
        os.chmod(first, 0o600)
        os.link(first, root / "two")
        with self.assertRaisesRegex(EvidenceWorkspaceError, "hardlinked"):
            EvidenceWorkspace.create(root, repository_root=self.repository)

        limits = EvidenceLimits(
            max_files=1,
            max_directories=8,
            max_file_bytes=128,
            max_total_bytes=128,
            max_json_bytes=128,
            max_path_depth=4,
        )
        with self.workspace("bounded", limits=limits) as workspace:
            workspace.write_json("one.json", {"value": "small"})
            with self.assertRaisesRegex(EvidenceWorkspaceError, "file-count"):
                workspace.write_json("two.json", {"value": "small"})

    def test_large_release_artifact_limit_requires_explicit_opt_in(self) -> None:
        default_limits = EvidenceLimits()
        self.assertEqual(default_limits.max_file_bytes, 64 * 1024 * 1024)

        release_limits = EvidenceLimits(max_file_bytes=512 * 1024 * 1024)
        release_limits.validate()
        self.assertEqual(release_limits.max_file_bytes, 512 * 1024 * 1024)

    def test_finite_json_metrics_and_secure_digests(self) -> None:
        for value in (math.inf, -math.inf, math.nan):
            with self.subTest(value=value):
                with self.assertRaisesRegex(EvidenceWorkspaceError, "non-finite"):
                    canonical_json_bytes({"value": value})
        validate_metrics({"count": 1, "ratio": 0.5})
        with self.assertRaisesRegex(EvidenceWorkspaceError, "not finite"):
            validate_metrics({"ratio": math.nan})
        with self.assertRaisesRegex(EvidenceWorkspaceError, "integer or float"):
            validate_metrics({"result": True})
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            validate_metrics({"Count": 1, "count": 2})

        source = self.base / "digest.bin"
        source.write_bytes(b"digest input")
        os.chmod(source, 0o600)
        record = digest_secure_file(source)
        self.assertEqual(record.path, "digest.bin")
        self.assertEqual(record.bytes, len(b"digest input"))
        self.assertEqual(len(record.sha256), 64)

    def test_schema_is_strict_json_and_path_validator_is_canonical(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[3]
            / "packaging/schemas/source-descriptor.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(safe_relative_path("a/b.json"), ("a", "b.json"))


if __name__ == "__main__":
    unittest.main()
