from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "crates/xtask/tool_authority.py"
SPEC = importlib.util.spec_from_file_location("xtask_tool_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def clean_source() -> dict[str, object]:
    return {
        "kind": "git",
        "revision": "1" * 40,
        "tree": "2" * 40,
        "committed": True,
        "clean": True,
        "status_entry_count": 0,
        "status_sha256": hashlib.sha256(b"").hexdigest(),
    }


class ToolAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-tool-authority-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name).resolve(strict=True)
        os.chmod(self.root, 0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _reviewed_document(self, command_id: str = "format-check") -> Path:
        tools: dict[str, object] = {}
        for name in sorted(MODULE.ROUTE_TOOLS[command_id]):
            path = self.root / f"tool-{name}"
            path.write_bytes(f"#!/bin/sh\n# {name}\nexit 0\n".encode())
            os.chmod(path, 0o700)
            tools[name] = {
                "path": os.fspath(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        reviewed = self.root / "reviewed.json"
        reviewed.write_bytes(
            MODULE.canonical_json_bytes(
                {"schema_version": MODULE.REVIEW_SCHEMA, "tools": tools}
            )
        )
        os.chmod(reviewed, 0o600)
        return reviewed

    def _environment(self) -> list[str]:
        values = []
        for name in sorted(MODULE.ENVIRONMENT):
            path = self.root / f"environment-{name.lower()}"
            path.mkdir(mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
            values.append(f"{name}={path}")
        return values

    def test_draft_and_validate_require_external_reviewed_digests(self) -> None:
        reviewed = self._reviewed_document()
        output = self.root / "authority.json"
        source = clean_source()
        with mock.patch.object(MODULE, "source_binding", return_value=source):
            result = MODULE.draft(
                argparse.Namespace(
                    reviewed_tools=reviewed,
                    command_id="format-check",
                    environment=self._environment(),
                    output=output,
                )
            )
            verified = MODULE.validate(
                argparse.Namespace(authority=output, expected_sha256=result["sha256"])
            )
        self.assertEqual(result, verified)
        self.assertEqual(result["tool_count"], len(MODULE.ROUTE_TOOLS["format-check"]))
        self.assertEqual(stat_mode(output), 0o400)
        for expected in (None, "0" * 64):
            with (
                self.subTest(expected=expected),
                self.assertRaises(MODULE.ToolAuthorityError),
            ):
                MODULE.validate(
                    argparse.Namespace(authority=output, expected_sha256=expected)
                )

        reviewed.chmod(0o600)
        document = MODULE.load_json_bytes(reviewed.read_bytes(), "reviewed")
        first = sorted(MODULE.ROUTE_TOOLS["format-check"])[0]
        document["tools"][first]["sha256"] = "0" * 64
        reviewed.write_bytes(MODULE.canonical_json_bytes(document))
        with (
            mock.patch.object(MODULE, "source_binding", return_value=source),
            self.assertRaises(MODULE.ToolAuthorityError),
        ):
            MODULE.draft(
                argparse.Namespace(
                    reviewed_tools=reviewed,
                    command_id="format-check",
                    environment=self._environment(),
                    output=self.root / "must-not-exist.json",
                )
            )

    def test_reviewed_tool_and_environment_inventories_are_exact(self) -> None:
        reviewed = MODULE.load_json_bytes(
            self._reviewed_document().read_bytes(), "reviewed"
        )
        expected = MODULE.ROUTE_TOOLS["format-check"]
        reviewed["tools"].pop(sorted(expected)[0])
        with self.assertRaises(MODULE.ToolAuthorityError):
            MODULE._validate_tools(reviewed["tools"], expected)
        environment = self._environment()
        with self.assertRaises(MODULE.ToolAuthorityError):
            MODULE._parse_environment(environment[:-1])

        with self.assertRaises(MODULE.ToolAuthorityError):
            MODULE.draft(
                argparse.Namespace(
                    reviewed_tools=self._reviewed_document(),
                    command_id="lint",
                    environment=self._environment(),
                    output=self.root / "wrong-route.json",
                )
            )

    def test_reviewed_tool_rejects_relative_symlink_and_named_replacement(self) -> None:
        reviewed = MODULE.load_json_bytes(
            self._reviewed_document().read_bytes(), "reviewed"
        )
        name = sorted(MODULE.ROUTE_TOOLS["format-check"])[0]
        entry = reviewed["tools"][name]
        path = Path(entry["path"])

        relative = dict(entry)
        relative["path"] = os.path.relpath(path, ROOT)
        with self.assertRaisesRegex(MODULE.ToolAuthorityError, "absolute"):
            MODULE._reviewed_tool(relative, name)

        alias = self.root / "tool-alias"
        alias.symlink_to(path)
        symlinked = dict(entry)
        symlinked["path"] = os.fspath(alias)
        with self.assertRaisesRegex(MODULE.ToolAuthorityError, "aliases|symlinks"):
            MODULE._reviewed_tool(symlinked, name)

        replacement = self.root / "tool-replacement"
        replacement.write_bytes(path.read_bytes())
        os.chmod(replacement, 0o700)
        real_read = os.read
        swapped = False

        def replace_named_file(descriptor: int, maximum: int) -> bytes:
            nonlocal swapped
            payload = real_read(descriptor, maximum)
            if not swapped:
                os.replace(replacement, path)
                swapped = True
            return payload

        with (
            mock.patch.object(MODULE.os, "read", side_effect=replace_named_file),
            self.assertRaisesRegex(MODULE.ToolAuthorityError, "changed|substituted"),
        ):
            MODULE._reviewed_tool(entry, name)

    def test_protected_document_rejects_named_replacement_during_read(self) -> None:
        reviewed = self._reviewed_document()
        replacement = self.root / "reviewed-replacement.json"
        replacement.write_bytes(reviewed.read_bytes())
        os.chmod(replacement, 0o600)
        real_read = os.read
        swapped = False

        def replace_named_file(descriptor: int, maximum: int) -> bytes:
            nonlocal swapped
            payload = real_read(descriptor, maximum)
            if payload and not swapped:
                os.replace(replacement, reviewed)
                swapped = True
            return payload

        with (
            mock.patch.object(MODULE.os, "read", side_effect=replace_named_file),
            self.assertRaisesRegex(MODULE.ToolAuthorityError, "changed"),
        ):
            MODULE._protected_document(reviewed, "reviewed tools")

    def test_user_owned_group_writable_ancestor_is_rejected(self) -> None:
        hostile_parent = self.root / "group-writable"
        hostile_parent.mkdir(mode=0o700)
        os.chmod(hostile_parent, 0o770)
        reviewed = hostile_parent / "reviewed.json"
        reviewed.write_bytes(MODULE.canonical_json_bytes({"ignored": True}))
        os.chmod(reviewed, 0o600)

        with self.assertRaisesRegex(
            MODULE.ToolAuthorityError, "unprotected path ancestor"
        ):
            MODULE._protected_document(reviewed, "reviewed tools")


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
