from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refinement.commands import (
    CommandError,
    CommandRegistry,
    CommandSpec,
    run_named,
    sanitized_environment,
)
from tools.refinement.refine import main as refine_main
from tools.refinement.trials import TrialError, TrialStore
from tools.refinement.workspace import (
    DiffPolicy,
    WorkspaceError,
    clean_worktree,
    cleanup_preview,
    inspect_worktree,
    materialize_worktree,
    plan_worktree,
    repository_identity,
    resolve_commit,
    validate_diff,
    validate_worktree_record,
    worktree_snapshot,
)


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class RepositoryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.repository = self.root / "champion"
        self.repository.mkdir()
        git(self.repository, "init", "-b", "main")
        git(self.repository, "config", "user.name", "CIGAR Test")
        git(self.repository, "config", "user.email", "cigar@example.invalid")
        (self.repository / "src").mkdir()
        (self.repository / "src/data.txt").write_text("champion\n", encoding="utf-8")
        (self.repository / "README.md").write_text("champion\n", encoding="utf-8")
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-m", "champion")
        self.worktrees = self.root / "worktrees"
        self.worktrees.mkdir()
        self.state = self.root / "state"
        self.command_state = self.root / "command-state"
        self.before = repository_identity(self.repository, require_clean=True)

    def tearDown(self) -> None:
        after = repository_identity(self.repository, require_clean=True)
        self.assertEqual(after, self.before, "the champion checkout changed")
        self.temporary.cleanup()

    def intent(self, trial_id: str = "trial-1") -> dict[str, object]:
        return plan_worktree(
            self.repository,
            self.worktrees,
            trial_id=trial_id,
            champion_ref="HEAD",
        )

    def store(self) -> TrialStore:
        return TrialStore(self.state, repository_root=self.repository)

    def create_trial(
        self, trial_id: str = "trial-1"
    ) -> tuple[TrialStore, dict[str, object], dict[str, object]]:
        store = self.store()
        intent = self.intent(trial_id)
        state = store.create_or_resume(
            champion_repository=self.repository,
            intent=intent,
            hypothesis="Improve exact evidence retrieval.",
            allowed_paths=["src"],
            forbidden_paths=["src/secret"],
            maximum_files=4,
            maximum_lines=20,
            evidence_class="development",
        )
        return store, intent, state

    def test_exact_worktree_lifecycle_and_cleanup_preview(self) -> None:
        store, intent, created = self.create_trial()
        self.assertEqual(created["phase"], "created")
        self.assertEqual(len(store.load("trial-1")), 2)
        inspection = inspect_worktree(self.repository, intent)
        self.assertTrue(inspection["resumable"])
        self.assertEqual(inspection["revision"], self.before["revision"])
        self.assertEqual(inspection["tree"], self.before["tree"])
        self.assertEqual(inspection["branch"], "refine/trial-trial-1")

        preview = cleanup_preview(self.repository, intent)
        self.assertTrue(preview["executable"])
        self.assertEqual(preview["actions"], ["git-worktree-remove", "retain-branch"])
        cleaned = clean_worktree(self.repository, intent)
        self.assertEqual(cleaned["status"], "cleaned")
        self.assertFalse(Path(intent["worktree_path"]).exists())
        self.assertEqual(
            git(
                self.repository,
                "show-ref",
                "--verify",
                "refs/heads/refine/trial-trial-1",
            ).split()[0],
            self.before["revision"],
        )

    def test_detached_identity_is_explicitly_read_only(self) -> None:
        git(self.repository, "checkout", "--detach", self.before["revision"])
        try:
            with self.assertRaisesRegex(WorkspaceError, "malformed or detached"):
                repository_identity(self.repository, require_clean=True)
            detached = repository_identity(
                self.repository,
                require_clean=True,
                allow_detached=True,
            )
            self.assertEqual(detached["revision"], self.before["revision"])
            self.assertEqual(detached["tree"], self.before["tree"])
            self.assertIsNone(detached["branch"])
        finally:
            git(self.repository, "checkout", "main")

    def test_intent_only_restart_materializes_one_exact_trial(self) -> None:
        store = self.store()
        intent = self.intent()
        store.append(
            phase="intent",
            trial_id="trial-1",
            hypothesis="Recover.",
            worktree=intent,
            allowed_paths=["src"],
            forbidden_paths=[],
            maximum_files=2,
            maximum_lines=10,
            evidence_class="development",
        )
        resumed = store.create_or_resume(
            champion_repository=self.repository,
            intent=intent,
            hypothesis="Recover.",
            allowed_paths=["src"],
            forbidden_paths=[],
            maximum_files=2,
            maximum_lines=10,
            evidence_class="development",
        )
        self.assertEqual(resumed["phase"], "created")
        self.assertEqual(len(store.load("trial-1")), 2)

    def test_materialized_restart_is_reconciled_as_resumable(self) -> None:
        store = self.store()
        intent = self.intent()
        store.append(
            phase="intent",
            trial_id="trial-1",
            hypothesis="Recover materialized work.",
            worktree=intent,
            allowed_paths=["src"],
            forbidden_paths=[],
            maximum_files=2,
            maximum_lines=10,
            evidence_class="development",
        )
        materialize_worktree(self.repository, intent)
        resumed = store.create_or_resume(
            champion_repository=self.repository,
            intent=intent,
            hypothesis="Recover materialized work.",
            allowed_paths=["src"],
            forbidden_paths=[],
            maximum_files=2,
            maximum_lines=10,
            evidence_class="development",
        )
        self.assertEqual(resumed["phase"], "resumable")
        self.assertEqual(len(store.load("trial-1")), 2)

    def test_cleanup_restart_reconciles_a_missing_exact_worktree(self) -> None:
        store, intent, latest = self.create_trial()
        cleaning = store.append(
            phase="cleaning",
            trial_id=latest["trial_id"],
            hypothesis=latest["hypothesis"],
            worktree=latest["worktree"],
            allowed_paths=latest["allowed_paths"],
            forbidden_paths=latest["forbidden_paths"],
            maximum_files=latest["maximum_files"],
            maximum_lines=latest["maximum_lines"],
            evidence_class=latest["evidence_class"],
            reason="operator_requested_clean_worktree",
        )
        self.assertEqual(cleaning["phase"], "cleaning")
        clean_worktree(self.repository, intent)
        common = [
            "--repository",
            str(self.repository),
            "--config",
            str((ROOT / "refinement/config/fast-v1.toml").resolve(strict=True)),
            "--state-root",
            str(self.state),
            "--worktree-root",
            str(self.worktrees),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                refine_main(
                    [
                        "trial",
                        "clean",
                        *common,
                        "--trial-id",
                        "trial-1",
                        "--execute",
                    ]
                ),
                0,
            )
        self.assertEqual(store.load("trial-1")[-1]["phase"], "cleaned")

    def test_trial_state_rejects_illegal_transitions_and_id_mismatch(self) -> None:
        store = self.store()
        intent = self.intent()
        common = {
            "hypothesis": "Strict transitions.",
            "allowed_paths": ["src"],
            "forbidden_paths": [],
            "maximum_files": 2,
            "maximum_lines": 10,
            "evidence_class": "development",
        }
        with self.assertRaisesRegex(TrialError, "first trial snapshot"):
            store.append(
                phase="created",
                trial_id="trial-1",
                worktree=intent,
                **common,
            )
        mismatch = {
            **intent,
            "trial_id": "other",
            "branch": "refine/trial-other",
            "worktree_path": str(self.worktrees / "other"),
        }
        with self.assertRaisesRegex(TrialError, "IDs differ"):
            store.append(
                phase="intent",
                trial_id="trial-1",
                worktree=mismatch,
                **common,
            )
        store.append(
            phase="intent",
            trial_id="trial-1",
            worktree=intent,
            **common,
        )
        with self.assertRaisesRegex(TrialError, "transition"):
            store.append(
                phase="intent",
                trial_id="trial-1",
                worktree=intent,
                **common,
            )

    def test_ambiguous_restart_is_rejected_without_new_state(self) -> None:
        store = self.store()
        intent = self.intent()
        store.append(
            phase="intent",
            trial_id="trial-1",
            hypothesis="Reject ambiguity.",
            worktree=intent,
            allowed_paths=["src"],
            forbidden_paths=[],
            maximum_files=2,
            maximum_lines=10,
            evidence_class="development",
        )
        git(
            self.repository,
            "worktree",
            "add",
            "-b",
            "wrong-branch",
            intent["worktree_path"],
            "HEAD",
        )
        with self.assertRaisesRegex(TrialError, "ambiguous"):
            store.create_or_resume(
                champion_repository=self.repository,
                intent=intent,
                hypothesis="Reject ambiguity.",
                allowed_paths=["src"],
                forbidden_paths=[],
                maximum_files=2,
                maximum_lines=10,
                evidence_class="development",
            )
        self.assertEqual(len(store.load("trial-1")), 1)

    def test_committed_candidate_cannot_hide_its_diff(self) -> None:
        _, intent, _ = self.create_trial()
        worktree = Path(intent["worktree_path"])
        (worktree / "src/data.txt").write_text("hidden candidate\n", encoding="utf-8")
        git(worktree, "add", "src/data.txt")
        git(worktree, "commit", "-m", "candidate must remain uncommitted")
        inspection = inspect_worktree(self.repository, intent)
        self.assertEqual(inspection["status"], "invalid")
        self.assertFalse(inspection["resumable"])

    def test_worktree_record_rejects_paths_aliases_and_injection(self) -> None:
        intent = self.intent()
        mutations = [
            {**intent, "trial_id": "../escape"},
            {**intent, "branch": "refine/trial-trial-1; touch owned"},
            {**intent, "champion_revision": "HEAD"},
            {**intent, "champion_tree": "b" * 39},
            {**intent, "git_common_dir": str(self.root)},
            {
                **intent,
                "worktree_path": str(self.worktrees / ".." / "worktrees" / "trial-1"),
            },
            {**intent, "unexpected": "field"},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(WorkspaceError):
                validate_worktree_record(mutation, champion_repository=self.repository)

        alias = self.root / "worktrees-alias"
        alias.symlink_to(self.worktrees, target_is_directory=True)
        with self.assertRaisesRegex(WorkspaceError, "absolute real|aliases|symlinks"):
            plan_worktree(
                self.repository,
                alias,
                trial_id="alias-trial",
                champion_ref="HEAD",
            )
        for reference in ("--help", "../main", "main..other", "main@{1}", "a//b"):
            with self.subTest(reference=reference), self.assertRaises(WorkspaceError):
                resolve_commit(self.repository, reference)

    def test_diff_policy_accepts_bounded_allowed_change(self) -> None:
        _, intent, _ = self.create_trial()
        worktree = Path(intent["worktree_path"])
        before = worktree_snapshot(worktree)
        (worktree / "src/data.txt").write_text("candidate\n", encoding="utf-8")
        result = validate_diff(
            worktree,
            DiffPolicy(("src",), ("src/secret",), maximum_files=2, maximum_lines=4),
        )
        after = worktree_snapshot(worktree)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["paths"], ["src/data.txt"])
        self.assertNotEqual(before["snapshot_id"], after["snapshot_id"])

    def test_diff_and_snapshot_reject_a_symlinked_worktree_alias(self) -> None:
        _, intent, _ = self.create_trial()
        worktree = Path(intent["worktree_path"])
        alias = self.root / "trial-alias"
        alias.symlink_to(worktree, target_is_directory=True)
        policy = DiffPolicy(("src",), (), maximum_files=2, maximum_lines=4)
        with self.assertRaises(WorkspaceError):
            validate_diff(alias, policy)
        with self.assertRaises(WorkspaceError):
            worktree_snapshot(alias)

    def test_diff_policy_rejects_forbidden_outside_budget_link_and_binary(self) -> None:
        cases = ("forbidden", "outside", "files", "lines", "link", "binary")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                trial_id = f"diff-{index}"
                _, intent, _ = self.create_trial(trial_id)
                worktree = Path(intent["worktree_path"])
                policy = DiffPolicy(
                    ("src",),
                    ("src/secret",),
                    maximum_files=1,
                    maximum_lines=2,
                )
                if case == "forbidden":
                    (worktree / "src/secret").write_text("x\n", encoding="utf-8")
                elif case == "outside":
                    (worktree / "outside.txt").write_text("x\n", encoding="utf-8")
                elif case == "files":
                    (worktree / "src/a.txt").write_text("x\n", encoding="utf-8")
                    (worktree / "src/b.txt").write_text("x\n", encoding="utf-8")
                elif case == "lines":
                    (worktree / "src/data.txt").write_text(
                        "one\ntwo\nthree\n", encoding="utf-8"
                    )
                elif case == "link":
                    (worktree / "src/link").symlink_to("data.txt")
                else:
                    (worktree / "src/data.txt").write_bytes(b"\x00binary")
                with self.assertRaises(WorkspaceError):
                    validate_diff(worktree, policy)

    def test_cli_doctor_create_inspect_preview_and_clean(self) -> None:
        common = [
            "--repository",
            str(self.repository),
            "--config",
            str((ROOT / "refinement/config/fast-v1.toml").resolve(strict=True)),
            "--state-root",
            str(self.state),
            "--worktree-root",
            str(self.worktrees),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(refine_main(["doctor", *common]), 0)
        doctor = json.loads(output.getvalue())
        self.assertEqual(doctor["status"], "passed")
        self.assertFalse(doctor["credentials_resolved"])

        create = [
            "trial",
            "create",
            *common,
            "--trial-id",
            "cli-trial",
            "--hypothesis",
            "Exercise the CLI.",
            "--allowed-path",
            "src",
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(refine_main(create), 0)
            self.assertEqual(
                refine_main(["trial", "inspect", *common, "--trial-id", "cli-trial"]),
                0,
            )
            self.assertEqual(
                refine_main(["trial", "clean", *common, "--trial-id", "cli-trial"]),
                0,
            )
            self.assertTrue((self.worktrees / "cli-trial").exists())
            self.assertEqual(
                refine_main(
                    [
                        "trial",
                        "clean",
                        *common,
                        "--trial-id",
                        "cli-trial",
                        "--execute",
                    ]
                ),
                0,
            )
        self.assertFalse((self.worktrees / "cli-trial").exists())
        self.assertEqual(self.store().load("cli-trial")[-1]["phase"], "cleaned")


class CommandControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()
        self.counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_code(
        self,
        code: str,
        *,
        timeout: int = 10,
        stdout_limit: int = 64 * 1024,
        stderr_limit: int = 64 * 1024,
        arguments: tuple[str, ...] = (),
        memory: int | None = None,
    ) -> dict[str, object]:
        self.counter += 1
        identifier = f"test-{self.counter}"
        registry = CommandRegistry(
            (
                CommandSpec(
                    identifier,
                    (sys.executable, "-c", code, *arguments),
                    timeout,
                    stdout_limit,
                    stderr_limit,
                    memory,
                ),
            )
        )
        state = self.root / f"state-{self.counter}"
        return run_named(registry, identifier, cwd=self.cwd, state=state)

    def test_named_registry_rejects_unknown_and_duplicate_commands(self) -> None:
        spec = CommandSpec("known", (sys.executable, "-c", "pass"), 2)
        registry = CommandRegistry((spec,))
        with self.assertRaisesRegex(CommandError, "named registry"):
            registry.get("echo unsafe")
        with self.assertRaisesRegex(CommandError, "duplicate"):
            CommandRegistry((spec, spec))
        with self.assertRaises(CommandError):
            CommandSpec("boolean-time", (sys.executable, "-c", "pass"), True).validate()
        with self.assertRaises(CommandError):
            CommandSpec(
                "boolean-output",
                (sys.executable, "-c", "pass"),
                2,
                maximum_stdout_bytes=True,
            ).validate()

    def test_bounded_launcher_parses_with_python_3_12(self) -> None:
        source = (ROOT / "tools/refinement/exec_bounded.py").read_text(encoding="utf-8")
        ast.parse(source, feature_version=(3, 12))

    def test_shell_free_launcher_supports_a_target_without_arguments(self) -> None:
        registry = CommandRegistry((CommandSpec("no-arguments", (sys.executable,), 2),))
        result = run_named(
            registry,
            "no-arguments",
            cwd=self.cwd,
            state=self.root / "no-arguments-state",
        )
        self.assertEqual(result["status"], "passed")

    def test_environment_is_sanitized_without_credentials_or_proxies(self) -> None:
        names = [
            "CIGAR_PROPOSAL_API_KEY",
            "OPENAI_API_KEY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "AWS_SECRET_ACCESS_KEY",
        ]
        previous = {name: os.environ.get(name) for name in names}
        try:
            for name in names:
                os.environ[name] = "must-not-leak"
            code = f"import os,sys;sys.exit(any(os.environ.get(n) for n in {names!r}))"
            result = self.run_code(code)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["exit_code"], 0)
        self.assertNotIn("OPENAI_API_KEY", result["environment_keys"])

    def test_shell_metacharacters_are_passed_as_data(self) -> None:
        marker = self.root / "shell-owned"
        hostile = f"; touch {marker}"
        code = "import sys; raise SystemExit(sys.argv[1] != " + repr(hostile) + ")"
        result = self.run_code(code, arguments=(hostile,))
        self.assertEqual(result["status"], "passed")
        self.assertFalse(marker.exists())

    def test_command_hashes_executable_arguments_environment_outputs_and_duration(
        self,
    ) -> None:
        result = self.run_code(
            "import sys; sys.stdout.write('out'); sys.stderr.write('err')"
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"out").hexdigest())
        self.assertEqual(result["stderr_sha256"], hashlib.sha256(b"err").hexdigest())
        for key in (
            "result_id",
            "command_sha256",
            "executable_sha256",
            "environment_sha256",
            "duration_sha256",
        ):
            self.assertRegex(str(result[key]), r"^(1220)?[0-9a-f]{64}$")
        self.assertGreaterEqual(result["duration_seconds"], 0)

    def test_timeout_kills_the_process_group(self) -> None:
        started = time.monotonic()
        result = self.run_code("import time; time.sleep(30)", timeout=1)
        self.assertLess(time.monotonic() - started, 8)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["status"], "failed")

    def test_output_flood_is_bounded_and_killed(self) -> None:
        result = self.run_code(
            "import os; os.write(1, b'x' * 1048576)",
            stdout_limit=1024,
        )
        self.assertTrue(result["output_overflow"])
        self.assertLessEqual(result["stdout_bytes"], 1024)
        self.assertEqual(result["status"], "failed")

    @unittest.skipUnless(hasattr(os, "fork"), "process-group test requires POSIX fork")
    def test_child_leak_is_detected_and_killed(self) -> None:
        code = "import os,time;pid=os.fork();time.sleep(30) if pid == 0 else None"
        started = time.monotonic()
        result = self.run_code(code, timeout=5)
        self.assertLess(time.monotonic() - started, 8)
        self.assertTrue(result["descendant_cleanup_required"])
        self.assertEqual(result["status"], "failed")

    def test_nonzero_exit_is_a_failed_result(self) -> None:
        result = self.run_code("raise SystemExit(17)")
        self.assertEqual(result["exit_code"], 17)
        self.assertEqual(result["status"], "failed")

    def test_state_and_cwd_symlinks_and_unsafe_modes_are_rejected(self) -> None:
        real_state = self.root / "real-state"
        real_state.mkdir(mode=0o700)
        alias_state = self.root / "alias-state"
        alias_state.symlink_to(real_state, target_is_directory=True)
        with self.assertRaises(CommandError):
            sanitized_environment(alias_state)

        unsafe_state = self.root / "unsafe-state"
        unsafe_state.mkdir(mode=0o755)
        with self.assertRaises(CommandError):
            sanitized_environment(unsafe_state)
        self.assertEqual(
            stat.S_IMODE(unsafe_state.stat().st_mode),
            0o755,
            "validation must not silently repair hostile permissions",
        )

        alias_cwd = self.root / "alias-cwd"
        alias_cwd.symlink_to(self.cwd, target_is_directory=True)
        registry = CommandRegistry(
            (CommandSpec("test", (sys.executable, "-c", "pass"), 2),)
        )
        with self.assertRaises(CommandError):
            run_named(
                registry,
                "test",
                cwd=alias_cwd,
                state=self.root / "unused-state",
            )

    def test_memory_limit_reporting_matches_platform_support(self) -> None:
        result = self.run_code("pass", memory=64 * 1024 * 1024)
        self.assertEqual(
            result["memory_limit_enforced"], sys.platform.startswith("linux")
        )


if __name__ == "__main__":
    unittest.main()
