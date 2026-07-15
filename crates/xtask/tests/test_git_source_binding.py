from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
XTASK = ROOT / "crates" / "xtask"
if str(XTASK) not in sys.path:
    sys.path.insert(0, str(XTASK))

import command_plane_evidence as evidence  # noqa: E402


class GitSourceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.repository_number = 0

    @staticmethod
    def _git(repository: Path, *arguments: str) -> bytes:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return result.stdout

    def _repository(self) -> Path:
        self.repository_number += 1
        repository = self.parent / f"repository-{self.repository_number}"
        repository.mkdir()
        self._git(repository, "init", "--quiet")
        self._git(repository, "config", "user.email", "qualification@example.invalid")
        self._git(repository, "config", "user.name", "Qualification Test")
        (repository / "tracked.txt").write_bytes(b"committed source\n")
        self._git(repository, "add", "tracked.txt")
        self._git(repository, "commit", "--quiet", "-m", "initial")
        return repository.resolve(strict=True)

    def test_clean_regular_checkout_has_content_free_clean_binding(self) -> None:
        repository = self._repository()
        index_before = (repository / ".git" / "index").read_bytes()

        binding = evidence.source_binding(repository)

        self.assertTrue(binding["clean"])
        self.assertEqual(binding["status_entry_count"], 0)
        self.assertEqual(
            binding["status_sha256"], evidence.hashlib.sha256(b"").hexdigest()
        )
        self.assertEqual((repository / ".git" / "index").read_bytes(), index_before)

    def test_explicit_false_cache_configuration_remains_compatible(self) -> None:
        repository = self._repository()
        for key in (
            "core.fsmonitor",
            "core.ignoreStat",
            "core.untrackedCache",
            "core.sparseCheckout",
            "core.sparseCheckoutCone",
            "extensions.worktreeConfig",
            "index.sparse",
        ):
            self._git(repository, "config", "--local", key, "false")

        self.assertTrue(evidence.source_binding(repository)["clean"])

    def test_assume_unchanged_cannot_hide_modified_tracked_content(self) -> None:
        repository = self._repository()
        self._git(repository, "update-index", "--assume-unchanged", "tracked.txt")
        (repository / "tracked.txt").write_bytes(b"malicious source\n")
        self.assertEqual(
            self._git(
                repository,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ),
            b"",
        )

        with self.assertRaisesRegex(evidence.CommandPlaneError, "assume-unchanged"):
            evidence.source_binding(repository)

    def test_skip_worktree_cannot_hide_modified_tracked_content(self) -> None:
        repository = self._repository()
        self._git(repository, "update-index", "--skip-worktree", "tracked.txt")
        (repository / "tracked.txt").write_bytes(b"malicious source\n")
        self.assertEqual(
            self._git(
                repository,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ),
            b"",
        )

        with self.assertRaisesRegex(
            evidence.CommandPlaneError, "skip-worktree or fsmonitor-valid"
        ):
            evidence.source_binding(repository)

    def test_fsmonitor_valid_index_extension_is_rejected_without_active_config(
        self,
    ) -> None:
        repository = self._repository()
        self._git(repository, "config", "core.fsmonitor", "true")
        self._git(repository, "update-index", "--fsmonitor-valid", "tracked.txt")
        self._git(repository, "config", "--unset", "core.fsmonitor")

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "unsupported cached or sparse extension",
        ):
            evidence.source_binding(repository)

    def test_untracked_cache_index_extension_is_rejected_without_active_config(
        self,
    ) -> None:
        repository = self._repository()
        self._git(repository, "config", "core.untrackedCache", "true")
        self._git(repository, "status", "--porcelain")
        self._git(repository, "config", "--unset", "core.untrackedCache")

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "unsupported cached or sparse extension",
        ):
            evidence.source_binding(repository)

    def test_unsafe_local_cache_and_sparse_configuration_fails_closed(self) -> None:
        for key, value in (
            ("core.fsmonitor", "true"),
            ("core.ignoreStat", "true"),
            ("core.untrackedCache", "true"),
            ("core.sparseCheckout", "true"),
            ("extensions.worktreeConfig", "true"),
            ("index.sparse", "true"),
        ):
            with self.subTest(key=key):
                repository = self._repository()
                self._git(repository, "config", "--local", key, value)
                (repository / "tracked.txt").write_bytes(b"malicious source\n")

                with self.assertRaisesRegex(
                    evidence.CommandPlaneError,
                    "unsupported cached source state",
                ):
                    evidence.source_binding(repository)

    def test_direct_tracked_comparison_rejects_a_false_clean_status(self) -> None:
        repository = self._repository()
        (repository / "tracked.txt").write_bytes(b"malicious source\n")

        with (
            mock.patch.object(
                evidence,
                "_status_state",
                return_value=(b"", 0, evidence.hashlib.sha256(b"").digest()),
            ),
            self.assertRaisesRegex(
                evidence.CommandPlaneError,
                "reported clean while tracked HEAD, index, or worktree state differed",
            ),
        ):
            evidence.source_binding(repository)

    def test_staged_regular_content_remains_a_supported_dirty_binding(self) -> None:
        repository = self._repository()
        (repository / "tracked.txt").write_bytes(b"staged source\n")
        self._git(repository, "add", "tracked.txt")

        binding = evidence.source_binding(repository)

        self.assertFalse(binding["clean"])
        self.assertEqual(binding["status_entry_count"], 1)

    def test_exact_protected_root_target_is_the_only_ignored_exception(self) -> None:
        repository = self._repository()
        (repository / ".gitignore").write_bytes(b"/target/\n")
        self._git(repository, "add", ".gitignore")
        self._git(repository, "commit", "--quiet", "-m", "cargo outputs")
        target = repository / "target"
        target.mkdir(mode=0o755)
        (target / "built-xtask").write_bytes(b"generated executable\n")

        binding = evidence.source_binding(repository)

        self.assertTrue(binding["clean"])
        self.assertEqual(binding["status_entry_count"], 0)

    def test_unprotected_root_target_is_rejected(self) -> None:
        repository = self._repository()
        (repository / ".gitignore").write_bytes(b"/target/\n")
        self._git(repository, "add", ".gitignore")
        self._git(repository, "commit", "--quiet", "-m", "cargo outputs")
        target = repository / "target"
        target.mkdir(mode=0o755)
        target.chmod(0o777)

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "owner-owned protected real directory",
        ):
            evidence.source_binding(repository)

    def test_real_cargo_xtask_can_bind_a_clean_checkout_with_its_target(self) -> None:
        repository = self._repository()
        (repository / "tracked.txt").unlink()
        (repository / ".cargo").mkdir()
        (repository / ".cargo" / "config.toml").write_text(
            '[alias]\nxtask = "run --quiet --package xtask --"\n',
            encoding="utf-8",
        )
        (repository / ".gitignore").write_text("/target/\n", encoding="utf-8")
        (repository / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["xtask"]\nresolver = "2"\n',
            encoding="utf-8",
        )
        crate = repository / "xtask"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(
            '[package]\nname = "xtask"\nversion = "0.0.0"\nedition = "2024"\n',
            encoding="utf-8",
        )
        (crate / "src" / "main.rs").write_text(
            """use std::env;
use std::process::{exit, Command};

fn main() {
    let module = env::var("CIGAR_TEST_EVIDENCE_MODULE").unwrap();
    let script = "import json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import command_plane_evidence as e; print(json.dumps(e.source_binding(Path.cwd().resolve(strict=True)),sort_keys=True))";
    let status = Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(script)
        .arg(module)
        .status()
        .unwrap();
    if !status.success() {
        exit(1);
    }
}
""",
            encoding="utf-8",
        )
        subprocess.run(
            ["cargo", "generate-lockfile", "--offline"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        self._git(repository, "add", "--all")
        self._git(repository, "commit", "--quiet", "-m", "minimal cargo xtask")
        environment = dict(os.environ)
        environment["CARGO_NET_OFFLINE"] = "true"
        environment["CARGO_TARGET_DIR"] = os.fspath(repository / "target")
        environment["CIGAR_TEST_EVIDENCE_MODULE"] = os.fspath(XTASK)
        for key in ("RUSTC_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            environment.pop(key, None)

        result = subprocess.run(
            ["cargo", "xtask"],
            cwd=repository,
            check=True,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )

        binding = json.loads(result.stdout)
        self.assertTrue(binding["clean"])
        self.assertEqual(binding["status_entry_count"], 0)
        self.assertTrue((repository / "target").is_dir())

    def test_hardlinked_tracked_source_is_rejected(self) -> None:
        repository = self._repository()
        os.link(repository / "tracked.txt", repository / "second-link.txt")

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "single-link exact 0644 or 0755",
        ):
            evidence.source_binding(repository)

    def test_group_only_execute_cannot_satisfy_an_executable_index_entry(self) -> None:
        repository = self._repository()
        tracked = repository / "tracked.txt"
        tracked.chmod(0o755)
        self._git(repository, "add", "tracked.txt")
        self._git(repository, "commit", "--quiet", "-m", "executable source")
        self._git(repository, "config", "core.fileMode", "false")
        tracked.chmod(0o654)

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "exact 0644 or 0755",
        ):
            evidence.source_binding(repository)

    def test_group_writable_tracked_parent_directory_is_rejected(self) -> None:
        repository = self._repository()
        nested = repository / "nested"
        nested.mkdir(mode=0o755)
        (nested / "source.txt").write_bytes(b"nested source\n")
        self._git(repository, "add", "nested/source.txt")
        self._git(repository, "commit", "--quiet", "-m", "nested source")
        nested.chmod(0o775)

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "source directories must be owner-owned protected real directories",
        ):
            evidence.source_binding(repository)

    def test_local_filemode_setting_cannot_hide_a_mode_change(self) -> None:
        repository = self._repository()
        self._git(repository, "config", "core.fileMode", "false")
        (repository / "tracked.txt").chmod(0o755)
        self.assertEqual(
            self._git(
                repository,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ),
            b"",
        )

        binding = evidence.source_binding(repository)

        self.assertFalse(binding["clean"])
        self.assertEqual(binding["status_entry_count"], 1)

    def test_tracked_gitignore_cannot_hide_ignored_untracked_content(self) -> None:
        repository = self._repository()
        (repository / ".gitignore").write_bytes(b"ignored-source.py\n")
        self._git(repository, "add", ".gitignore")
        self._git(repository, "commit", "--quiet", "-m", "ignore policy")
        (repository / "ignored-source.py").write_bytes(b"executed = True\n")
        self.assertEqual(
            self._git(
                repository,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ),
            b"",
        )

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "ignored untracked content outside the protected Cargo target root",
        ):
            evidence.source_binding(repository)

    def test_effective_local_info_exclude_is_rejected(self) -> None:
        repository = self._repository()
        info_exclude = repository / ".git" / "info" / "exclude"
        info_exclude.write_bytes(b"local-hidden.py\n")
        (repository / "local-hidden.py").write_bytes(b"executed = True\n")

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "effective local Git info attributes or excludes",
        ):
            evidence.source_binding(repository)

    def test_effective_local_info_attributes_is_rejected(self) -> None:
        repository = self._repository()
        (repository / ".git" / "info" / "attributes").write_bytes(
            b"*.txt filter=local-driver\n"
        )

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "effective local Git info attributes or excludes",
        ):
            evidence.source_binding(repository)

    def test_control_file_named_identity_must_still_match_after_read(self) -> None:
        repository = self._repository()
        control = repository / ".git" / "index"
        original = control.lstat()
        changed = mock.Mock()
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        ):
            setattr(changed, field, getattr(original, field))
        changed.st_ino += 1

        with (
            mock.patch.object(Path, "lstat", side_effect=(original, changed)),
            self.assertRaisesRegex(
                evidence.CommandPlaneError,
                "changed while it was inspected",
            ),
        ):
            evidence._read_git_control_file(
                control,
                maximum=evidence._MAXIMUM_GIT_CONTROL_BYTES,
                required=True,
            )

    def test_local_filter_configuration_is_rejected_before_status(self) -> None:
        repository = self._repository()
        self._git(repository, "config", "filter.local.clean", "malicious-filter")

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "alter source discovery or filtering",
        ):
            evidence.source_binding(repository)

    def test_tracked_symlinks_are_explicitly_unsupported(self) -> None:
        repository = self._repository()
        (repository / "link.txt").symlink_to("tracked.txt")
        self._git(repository, "add", "link.txt")
        self._git(repository, "commit", "--quiet", "-m", "tracked link")

        with self.assertRaisesRegex(
            evidence.CommandPlaneError,
            "tracked symlinks, submodules, and non-regular entries",
        ):
            evidence.source_binding(repository)


if __name__ == "__main__":
    unittest.main()
