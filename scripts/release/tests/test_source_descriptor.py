#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from source_descriptor import (  # noqa: E402
    SourceDescriptorError,
    build_source_descriptor,
    validate_source_descriptor,
)


@unittest.skipUnless(os.name == "posix", "secure source binding requires POSIX")
class SourceDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = (Path(self.temporary.name) / "repository").resolve()
        self.root.mkdir(mode=0o700)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Evidence Test")
        self.git("config", "user.email", "evidence@example.invalid")
        (self.root / "policy.json").write_text('{"policy":true}\n', encoding="utf-8")
        (self.root / "tool.py").write_text("print('tool')\n", encoding="utf-8")
        self.git("add", "policy.json", "tool.py")
        self.git("commit", "--quiet", "-m", "fixture")

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
                "TZ": "UTC",
            },
        )
        return result.stdout.decode("ascii", errors="strict").strip()

    def build(self, *, require_clean: bool = True) -> dict[str, object]:
        return build_source_descriptor(
            repository_root=self.root,
            generated_at="2026-07-13T12:00:00Z",
            source_archive={
                "name": "cigar-source.tar.gz",
                "sha256": "a" * 64,
                "bytes": 1234,
            },
            policy_inputs=["policy.json"],
            tool_inputs=["tool.py"],
            require_clean=require_clean,
        )

    def test_descriptor_binds_full_commit_tree_archive_policy_and_tool(self) -> None:
        descriptor = self.build()
        git = descriptor["git"]
        self.assertEqual(git["revision"], self.git("rev-parse", "HEAD^{commit}"))
        self.assertEqual(git["tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertTrue(git["committed"])
        self.assertTrue(git["clean"])
        self.assertEqual(git["status_entry_count"], 0)
        self.assertEqual(git["status_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(descriptor["source_archive"]["sha256"], "a" * 64)
        self.assertEqual(descriptor["policy_inputs"][0]["path"], "policy.json")
        self.assertEqual(descriptor["tool_inputs"][0]["path"], "tool.py")
        self.assertEqual(descriptor["generated_at"], "2026-07-13T12:00:00Z")

    def test_dirty_source_fails_closed_or_is_content_free_when_allowed(self) -> None:
        (self.root / "private-name-with-token-SECRET").write_text(
            "secret payload", encoding="utf-8"
        )
        with self.assertRaisesRegex(SourceDescriptorError, "clean"):
            self.build()
        descriptor = self.build(require_clean=False)
        self.assertFalse(descriptor["git"]["clean"])
        self.assertEqual(descriptor["git"]["status_entry_count"], 1)
        serialized = json.dumps(descriptor, sort_keys=True)
        self.assertNotIn("private-name", serialized)
        self.assertNotIn("secret payload", serialized)

    def test_ambient_secrets_are_never_forwarded_or_serialized(self) -> None:
        captured: list[dict[str, str]] = []
        from source_descriptor import run_bounded as real_run_bounded

        def recording_run(*args: object, **kwargs: object) -> object:
            captured.append(dict(kwargs["env"]))
            return real_run_bounded(*args, **kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {"AWS_SECRET_ACCESS_KEY": "do-not-capture", "TOKEN": "also-secret"},
            ),
            mock.patch("source_descriptor.run_bounded", side_effect=recording_run),
        ):
            descriptor = self.build()
        self.assertTrue(captured)
        for environment in captured:
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
            self.assertNotIn("TOKEN", environment)
        serialized = json.dumps(descriptor, sort_keys=True)
        self.assertNotIn("do-not-capture", serialized)
        self.assertNotIn("also-secret", serialized)

    def test_invalid_timestamp_archive_and_input_aliases_are_rejected(self) -> None:
        with self.assertRaisesRegex(SourceDescriptorError, "generated_at"):
            build_source_descriptor(
                repository_root=self.root,
                generated_at="now",
                source_archive={
                    "name": "source.tar",
                    "sha256": "a" * 64,
                    "bytes": 1,
                },
                policy_inputs=["policy.json"],
                tool_inputs=["tool.py"],
            )
        with self.assertRaisesRegex(SourceDescriptorError, "SHA-256"):
            build_source_descriptor(
                repository_root=self.root,
                generated_at="2026-07-13T12:00:00Z",
                source_archive={"name": "source.tar", "sha256": "bad", "bytes": 1},
                policy_inputs=["policy.json"],
                tool_inputs=["tool.py"],
            )
        with self.assertRaisesRegex(SourceDescriptorError, "duplicate portable"):
            build_source_descriptor(
                repository_root=self.root,
                generated_at="2026-07-13T12:00:00Z",
                source_archive={
                    "name": "source.tar",
                    "sha256": "a" * 64,
                    "bytes": 1,
                },
                policy_inputs=["policy.json", "Policy.json"],
                tool_inputs=["tool.py"],
            )

    def test_descriptor_is_deterministic_for_unchanged_inputs(self) -> None:
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)

    def test_validator_rejects_substitution_and_contradictory_source_state(
        self,
    ) -> None:
        descriptor = self.build()
        validate_source_descriptor(descriptor)
        descriptor["git"]["clean"] = False
        with self.assertRaisesRegex(SourceDescriptorError, "contradicts"):
            validate_source_descriptor(descriptor)
        descriptor = self.build()
        descriptor["tool_inputs"][0]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(SourceDescriptorError, "SHA-256"):
            validate_source_descriptor(descriptor)

    def test_gitignored_uncommitted_inputs_are_rejected(self) -> None:
        (self.root / ".gitignore").write_text("ignored-policy.json\n", encoding="utf-8")
        self.git("add", ".gitignore")
        self.git("commit", "--quiet", "-m", "ignore fixture")
        (self.root / "ignored-policy.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(SourceDescriptorError, "not committed"):
            build_source_descriptor(
                repository_root=self.root,
                generated_at="2026-07-13T12:00:00Z",
                source_archive={
                    "name": "source.tar",
                    "sha256": "a" * 64,
                    "bytes": 1,
                },
                policy_inputs=["ignored-policy.json"],
                tool_inputs=["tool.py"],
            )

    def test_git_replacement_objects_are_rejected(self) -> None:
        original = self.git("rev-parse", "HEAD")
        (self.root / "policy.json").write_text(
            '{"policy":"replacement"}\n', encoding="utf-8"
        )
        self.git("add", "policy.json")
        self.git("commit", "--quiet", "-m", "replacement fixture")
        replacement = self.git("rev-parse", "HEAD")
        self.git("reset", "--hard", "--quiet", original)
        self.git("replace", original, replacement)
        self.git("reset", "--hard", "--quiet", "HEAD")
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaisesRegex(SourceDescriptorError, "replacement refs"):
            self.build()


if __name__ == "__main__":
    unittest.main()
