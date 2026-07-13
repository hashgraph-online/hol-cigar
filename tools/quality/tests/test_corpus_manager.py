from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "corpus_manager", ROOT / "tools" / "quality" / "corpus_manager.py"
)
assert SPEC is not None and SPEC.loader is not None
corpus_manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus_manager)


class CorpusManagerTests(unittest.TestCase):
    def test_campaign_policy_is_complete_and_regression_is_pinned(self) -> None:
        policy, targets = corpus_manager.load_policy()
        self.assertEqual(len(targets), 14)
        fixtures = policy["targets"]["mcp_messages"]["named_fixtures"]
        regression = next(
            fixture
            for fixture in fixtures
            if fixture["name"] == "out-of-range-numeric-id"
        )
        self.assertEqual(regression["classification"], "minimized-regression")
        self.assertEqual(regression["sha1"], "8990a2f1ca2774f3cea4ad12624eac0acf7bfd31")
        entries = corpus_manager.collect_entries("mcp_messages", policy)
        actual = next(entry for entry in entries if entry["name"] == regression["name"])
        self.assertEqual(actual["classification"], "minimized-regression")
        self.assertEqual(actual["sha256"], regression["sha256"])

    def test_output_inside_repository_is_rejected(self) -> None:
        with self.assertRaises(corpus_manager.CorpusFailure):
            corpus_manager.external_new_path(
                ROOT / ".forbidden-corpus-report", directory=False
            )

    def test_minimizer_input_is_content_deduplicated(self) -> None:
        body = b"same input"
        entry = {
            "path": "fuzz/corpus/example/a",
            "name": "a",
            "present": True,
            "tracked": True,
            "classification": "reusable-corpus",
            "sha1": corpus_manager.digest(body, "sha1"),
            "sha256": corpus_manager.digest(body, "sha256"),
            "size": len(body),
            "_body": body,
        }
        duplicate = dict(entry, path="fuzz/corpus/example/b", name="b")
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw).resolve() / "input"
            corpus_manager.create_minimizer_input(output, [entry, duplicate], 1024)
            files = list(output.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), body)

    def test_deterministic_output_preserves_named_fixture(self) -> None:
        fixture_body = b"required regression"
        other_body = b"coverage input"
        fixture = {
            "name": "named-regression",
            "classification": "minimized-regression",
            "sha1": corpus_manager.digest(fixture_body, "sha1"),
            "sha256": corpus_manager.digest(fixture_body, "sha256"),
        }
        policy = {
            "limits": {
                "maximum_files_per_target": 4,
                "maximum_input_bytes": 1024,
                "maximum_total_bytes_per_target": 4096,
            },
            "targets": {"example": {"named_fixtures": [fixture]}},
        }
        entries = [
            {
                "path": "fuzz/corpus/example/named-regression",
                "name": "named-regression",
                "present": True,
                "tracked": True,
                "classification": "minimized-regression",
                "sha1": fixture["sha1"],
                "sha256": fixture["sha256"],
                "size": len(fixture_body),
                "_body": fixture_body,
            },
            {
                "path": "fuzz/corpus/example/other",
                "name": "other",
                "present": True,
                "tracked": True,
                "classification": "reusable-corpus",
                "sha1": corpus_manager.digest(other_body, "sha1"),
                "sha256": corpus_manager.digest(other_body, "sha256"),
                "size": len(other_body),
                "_body": other_body,
            },
        ]
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            minimized = base / "minimized"
            minimized.mkdir()
            (minimized / "engine-name").write_bytes(other_body)
            output = base / "output"
            state, mapping = corpus_manager.emit_deterministic_corpus(
                "example", minimized, output, entries, policy
            )
            self.assertEqual((output / "named-regression").read_bytes(), fixture_body)
            self.assertTrue(
                (output / corpus_manager.digest(other_body, "sha1")).is_file()
            )
            self.assertEqual(state["file_count"], 2)
            self.assertEqual(mapping[0]["new_names"], ["named-regression"])
            foreign = base / "foreign"
            foreign.mkdir()
            (foreign / "engine-name").write_bytes(b"not a source input")
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.emit_deterministic_corpus(
                    "example", foreign, base / "foreign-output", entries, policy
                )

    def test_reconcile_copies_verifies_then_restores_and_unlinks(self) -> None:
        transient_body = b"new fuzzer growth"
        tracked_body = b"tracked corpus input"
        transient = {
            "path": "fuzz/corpus/example/"
            + corpus_manager.digest(transient_body, "sha1"),
            "name": corpus_manager.digest(transient_body, "sha1"),
            "present": True,
            "tracked": False,
            "base_classification": "transient-corpus",
            "classification": "transient-corpus",
            "sha1": corpus_manager.digest(transient_body, "sha1"),
            "sha256": corpus_manager.digest(transient_body, "sha256"),
            "size": len(transient_body),
            "_body": transient_body,
        }
        restoration = {
            "path": "fuzz/corpus/example/"
            + corpus_manager.digest(tracked_body, "sha1"),
            "name": corpus_manager.digest(tracked_body, "sha1"),
            "present": False,
            "tracked": True,
            "base_classification": "tracked-deletion-recovered-from-index",
            "classification": "tracked-deletion-recovered-from-index",
            "sha1": corpus_manager.digest(tracked_body, "sha1"),
            "sha256": corpus_manager.digest(tracked_body, "sha256"),
            "size": len(tracked_body),
            "_body": tracked_body,
        }
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            source_root = base / "source"
            source = source_root / transient["path"]
            source.parent.mkdir(parents=True)
            source.write_bytes(transient_body)
            quarantine = base / "quarantine"
            quarantine.mkdir()
            actions = corpus_manager.prepare_quarantine(
                [transient], quarantine, source_root=source_root
            )
            self.assertTrue(actions[0]["copy_verified"])
            saved = quarantine / actions[0]["quarantine_path"]
            self.assertEqual(saved.read_bytes(), transient_body)
            mutations = corpus_manager.apply_reconciliation(
                [transient], [restoration], source_root=source_root
            )
            self.assertFalse(source.exists())
            self.assertEqual(
                (source_root / restoration["path"]).read_bytes(), tracked_body
            )
            self.assertEqual(len(mutations), 2)

    def test_reconcile_refuses_changed_transient_before_unlink(self) -> None:
        expected = b"inventoried"
        changed = b"changed concurrently"
        entry = {
            "path": "fuzz/corpus/example/transient",
            "name": "transient",
            "present": True,
            "tracked": False,
            "base_classification": "transient-corpus",
            "classification": "transient-corpus",
            "sha1": corpus_manager.digest(expected, "sha1"),
            "sha256": corpus_manager.digest(expected, "sha256"),
            "size": len(expected),
            "_body": expected,
        }
        with tempfile.TemporaryDirectory() as raw:
            source_root = Path(raw).resolve() / "source"
            source = source_root / entry["path"]
            source.parent.mkdir(parents=True)
            source.write_bytes(changed)
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.apply_reconciliation(
                    [entry], [], source_root=source_root
                )
            self.assertEqual(source.read_bytes(), changed)

    def test_atomic_reconcile_never_unlinks_a_racing_replacement(self) -> None:
        expected = b"inventoried transient"
        replacement = b"replacement created after atomic move"
        entry = {
            "path": "fuzz/corpus/example/transient",
            "name": "transient",
            "present": True,
            "tracked": False,
            "base_classification": "transient-corpus",
            "classification": "transient-corpus",
            "sha1": corpus_manager.digest(expected, "sha1"),
            "sha256": corpus_manager.digest(expected, "sha256"),
            "size": len(expected),
            "_body": expected,
        }
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw).resolve() / "source" / entry["path"]
            source.parent.mkdir(parents=True)
            source.write_bytes(expected)

            def replace_after_move(original: Path, _holding: Path) -> None:
                original.write_bytes(replacement)

            corpus_manager.atomic_remove_verified_transient(
                source, entry, post_move_hook=replace_after_move
            )
            self.assertEqual(source.read_bytes(), replacement)

    def test_private_mkdir_rejects_symlink_components_and_uses_0700(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            nested = base / "a" / "b" / "c"
            corpus_manager.private_mkdir(nested, exist_ok=False)
            for directory in (base / "a", base / "a" / "b", nested):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.private_mkdir(link / "child", exist_ok=False)

    def test_artifact_scan_finds_root_unknown_and_nested_entries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            artifact_root = Path(raw).resolve() / "artifacts"
            artifact_root.mkdir()
            target = artifact_root / "known"
            target.mkdir()
            (target / "crash-direct").write_bytes(b"direct")
            nested = target / "nested"
            nested.mkdir()
            (nested / "crash-nested").write_bytes(b"nested")
            (artifact_root / "crash-root").write_bytes(b"root")
            unknown = artifact_root / "unknown"
            unknown.mkdir()
            (unknown / "crash-unknown").write_bytes(b"unknown")
            with mock.patch.object(corpus_manager, "ARTIFACT_ROOT", artifact_root):
                by_target, unexpected = corpus_manager.scan_artifacts(
                    ["known"], ["crash-"]
                )
            self.assertEqual(len(by_target["known"]), 1)
            self.assertGreaterEqual(len(unexpected), 5)
            self.assertTrue(
                any(item["path"].endswith("crash-root") for item in unexpected)
            )

    def test_deleted_named_fixture_is_a_recoverable_deletion_not_healthy(self) -> None:
        body = b"pinned regression"
        fixture = {
            "name": "named-regression",
            "classification": "minimized-regression",
            "sha1": corpus_manager.digest(body, "sha1"),
            "sha256": corpus_manager.digest(body, "sha256"),
        }
        policy = {"targets": {"example": {"named_fixtures": [fixture]}}}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            corpus_root = root / "fuzz" / "corpus"
            (corpus_root / "example").mkdir(parents=True)
            relative = "fuzz/corpus/example/named-regression"
            with (
                mock.patch.object(corpus_manager, "ROOT", root),
                mock.patch.object(corpus_manager, "CORPUS_ROOT", corpus_root),
                mock.patch.object(
                    corpus_manager,
                    "git_paths",
                    side_effect=[{relative}, set()],
                ),
                mock.patch.object(corpus_manager, "index_body", return_value=body),
            ):
                entries = corpus_manager.collect_entries("example", policy)
            self.assertEqual(
                entries[0]["base_classification"],
                "named-fixture-deletion-recovered-from-index",
            )

    def test_execution_source_state_rejects_mutation_and_extra_entries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            mirror = Path(raw).resolve() / "execution-source"
            (mirror / "fuzz").mkdir(parents=True, mode=0o700)
            (mirror / "crates" / "example").mkdir(parents=True, mode=0o700)
            files = {
                "fuzz/Cargo.toml": (b"[workspace]\n", "100644"),
                "crates/example/build.rs": (b"fn main() {}\n", "100755"),
            }
            entries = []
            for relative, (body, git_mode) in files.items():
                path = mirror / relative
                path.write_bytes(body)
                entries.append(
                    {
                        "path": relative,
                        "git_mode": git_mode,
                        "git_oid": corpus_manager.digest(body, "sha1"),
                        "size": len(body),
                        "sha256": corpus_manager.digest(body, "sha256"),
                    }
                )
            corpus_manager.harden_execution_source(mirror, entries)
            expected = corpus_manager.expected_execution_source_state(
                corpus_manager.tracked_source_digest(entries), set()
            )
            self.assertEqual(
                corpus_manager.execution_source_state(
                    mirror, entries, expected_artifact_targets=set()
                ),
                expected,
            )
            cargo_toml = mirror / "fuzz" / "Cargo.toml"
            cargo_toml.chmod(0o600)
            cargo_toml.write_bytes(b"substituted\n")
            cargo_toml.chmod(0o400)
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.execution_source_state(
                    mirror, entries, expected_artifact_targets=set()
                )
            cargo_toml.chmod(0o600)
            cargo_toml.write_bytes(files["fuzz/Cargo.toml"][0])
            cargo_toml.chmod(0o400)
            extra = mirror / "fuzz" / "unexpected.tmp"
            extra.write_bytes(b"unexpected")
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.execution_source_state(
                    mirror, entries, expected_artifact_targets=set()
                )
            extra.unlink()
            unexpected_directory = mirror / "fuzz" / "unexpected-directory"
            unexpected_directory.mkdir(mode=0o700)
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.execution_source_state(
                    mirror, entries, expected_artifact_targets=set()
                )
            unexpected_directory.rmdir()
            symlink = mirror / "fuzz" / "unexpected-symlink"
            symlink.symlink_to(cargo_toml)
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.execution_source_state(
                    mirror, entries, expected_artifact_targets=set()
                )
            symlink.unlink()
            artifact_target = mirror / "fuzz" / "artifacts" / "example"
            artifact_target.mkdir(mode=0o700)
            (artifact_target / "crash-deadbeef").write_bytes(b"crash")
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.execution_source_state(
                    mirror, entries, expected_artifact_targets={"example"}
                )

    def test_execution_source_checkout_uses_only_index_and_hardens_modes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            source_root = base / "candidate"
            source_root.mkdir()
            subprocess.run(["git", "init", "--quiet"], cwd=source_root, check=True)
            tracked = source_root / "fuzz" / "Cargo.toml"
            executable = source_root / "scripts" / "check"
            tracked.parent.mkdir()
            executable.parent.mkdir()
            tracked.write_text("[workspace]\n", encoding="utf-8")
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            subprocess.run(
                ["git", "add", "fuzz/Cargo.toml", "scripts/check"],
                cwd=source_root,
                check=True,
            )
            (source_root / "untracked-secret").write_text(
                "must not be mirrored", encoding="utf-8"
            )
            output_root = base / "output"
            output_root.mkdir(mode=0o700)
            preflight = output_root / "preflight"
            preflight.mkdir(mode=0o700)
            home = base / "home"
            temporary = base / "tmp"
            home.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            environment = corpus_manager.sanitized_environment(
                private_home=home,
                private_tmp=temporary,
                ambient={"PATH": os.environ.get("PATH", "")},
            )
            with mock.patch.object(corpus_manager, "ROOT", source_root):
                entries = corpus_manager.tracked_index_entries()
                mirror, state, checkout = corpus_manager.create_execution_source_mirror(
                    output_root, entries, environment
                )
            self.assertFalse((mirror / "untracked-secret").exists())
            self.assertEqual(
                (mirror / "fuzz" / "Cargo.toml").stat().st_mode & 0o777, 0o400
            )
            self.assertEqual(
                (mirror / "scripts" / "check").stat().st_mode & 0o777, 0o500
            )
            self.assertEqual(
                state["tracked_source"], corpus_manager.tracked_source_digest(entries)
            )
            self.assertEqual(checkout["exit_code"], 0)
            corpus_manager.remove_owned_scratch_tree(mirror, label="test-mirror")

    def test_read_only_candidate_and_index_mode_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / "candidate"
            source = root / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            body = b"pub fn value() -> u8 { 1 }\n"
            source.write_bytes(body)
            source.chmod(0o444)
            source.parent.chmod(0o555)
            root.chmod(0o555)
            entry = {
                "path": "src/lib.rs",
                "git_mode": "100644",
                "git_oid": corpus_manager.digest(body, "sha1"),
                "size": len(body),
                "sha256": corpus_manager.digest(body, "sha256"),
            }

            def fake_git(*arguments: str) -> bytes:
                if arguments[0] == "status":
                    return b""
                if arguments[-1] == "HEAD":
                    return b"a" * 40 + b"\n"
                if arguments[-1] == "HEAD^{tree}":
                    return b"b" * 40 + b"\n"
                raise AssertionError(arguments)

            with (
                mock.patch.object(corpus_manager, "ROOT", root),
                mock.patch.object(corpus_manager, "git_bytes", side_effect=fake_git),
            ):
                state = corpus_manager.candidate_checkout_state(
                    [entry], require_read_only=True
                )
                self.assertEqual(state["tracked_source"]["file_count"], 1)
                source.chmod(0o644)
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.candidate_checkout_state(
                        [entry], require_read_only=True
                    )
                source.chmod(0o444)
                source.parent.chmod(0o755)
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.candidate_checkout_state(
                        [entry], require_read_only=True
                    )
                source.parent.chmod(0o555)
                mismatched = dict(entry, sha256="0" * 64)
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.candidate_checkout_state(
                        [mismatched], require_read_only=True
                    )
            source.parent.chmod(0o755)
            root.chmod(0o755)

        unsafe_index = b"120000 " + b"c" * 40 + b" 0\tlink\0"
        with mock.patch.object(corpus_manager, "git_bytes", return_value=unsafe_index):
            with self.assertRaises(corpus_manager.CorpusFailure):
                corpus_manager.tracked_index_entries()

    def test_success_scratch_cleanup_removes_only_owned_exact_roots(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output_root = Path(raw).resolve() / "stage"
            output_root.mkdir(mode=0o700)
            for name in (
                "build-target",
                "cargo-wrapper",
                "execution-source",
                "work",
            ):
                directory = output_root / name
                directory.mkdir(mode=0o700)
                child = directory / "nested"
                child.mkdir(mode=0o700)
                file = child / "file"
                file.write_bytes(b"scratch")
                file.chmod(0o400)
                child.chmod(0o500)
                directory.chmod(0o500)
            retained = output_root / "preflight"
            retained.mkdir(mode=0o700)
            removed = corpus_manager.remove_success_scratch(output_root)
            self.assertEqual(
                removed,
                ["build-target", "cargo-wrapper", "execution-source", "work"],
            )
            self.assertTrue(retained.is_dir())
            for name in removed:
                self.assertFalse((output_root / name).exists())

    def test_staged_verifier_detects_substitution(self) -> None:
        policy, _ = corpus_manager.load_policy()
        entries = corpus_manager.collect_entries("mcp_messages", policy)
        with tempfile.TemporaryDirectory() as raw:
            output_root = Path(raw).resolve() / "staged"
            corpus_manager.private_mkdir(output_root, exist_ok=False)
            minimized = output_root / "work" / "mcp_messages"
            corpus_manager.private_mkdir(minimized, exist_ok=False)
            seed = entries[0]["_body"]
            corpus_manager.write_new_bytes(
                minimized / corpus_manager.digest(seed, "sha1"), seed
            )
            state, mapping = corpus_manager.emit_deterministic_corpus(
                "mcp_messages",
                minimized,
                output_root / "corpus" / "mcp_messages",
                entries,
                policy,
            )
            repeat_state, _ = corpus_manager.emit_deterministic_corpus(
                "mcp_messages",
                minimized,
                output_root / "equivalence" / "mcp_messages",
                entries,
                policy,
            )
            for run in ("primary", "repeat"):
                corpus_manager.private_mkdir(
                    output_root / "artifacts" / "mcp_messages" / run,
                    exist_ok=False,
                )
            build_target = output_root / "build-target"
            corpus_manager.private_mkdir(build_target, exist_ok=False)
            wrapper_directory = output_root / "cargo-wrapper"
            corpus_manager.private_mkdir(wrapper_directory, exist_ok=False)
            real_cargo = corpus_manager.shutil.which("cargo")
            self.assertIsNotNone(real_cargo)
            wrapper = wrapper_directory / "cargo"
            corpus_manager.write_new_bytes(
                wrapper,
                corpus_manager.cargo_wrapper_source(
                    real_cargo=real_cargo, python=corpus_manager.sys.executable
                ),
                mode=0o700,
            )
            source_binding = corpus_manager.source_binding_document()
            cargo_fuzz_execution = corpus_manager.cargo_fuzz_execution_record(
                wrapper, source_binding
            )
            tracked_source = {
                "algorithm": "sha256-path-git-mode-oid-content-size-v1",
                "digest": "1" * 64,
                "file_count": 1,
                "total_bytes": 1,
            }
            candidate_state = {
                "schema_version": "cigar.read-only-candidate.v1",
                "git_head": source_binding["git_head"],
                "git_tree": "2" * 40,
                "git_status": {
                    "algorithm": "sha256-git-porcelain-v1-z",
                    "digest": corpus_manager.digest(b"", "sha256"),
                    "entry_count": 0,
                    "dirty": False,
                },
                "tracked_source": tracked_source,
                "root_mode": "0555",
                "tracked_files_read_only": True,
                "tracked_directories_read_only": True,
            }
            _, campaign_targets = corpus_manager.load_policy()
            source_snapshots = {
                target: corpus_manager.corpus_state(
                    corpus_manager.collect_entries(target, policy), present_only=True
                )
                for target in campaign_targets
            }
            seed_value = policy[
                "deterministic_minimization_seed_base"
            ] + campaign_targets.index("mcp_messages")
            enforcement = corpus_manager.execution_enforcement()
            log_directory = output_root / "logs" / "mcp_messages"
            corpus_manager.private_mkdir(log_directory, exist_ok=False)
            campaign_document = json.loads(
                corpus_manager.CAMPAIGN_PATH.read_text(encoding="utf-8")
            )

            def engine_for(label: str) -> dict[str, object]:
                log_path = log_directory / f"{label}.log"
                corpus_manager.write_new_bytes(log_path, b"")
                return {
                    "target": "mcp_messages",
                    "command": corpus_manager.redacted_command(
                        [
                            str(corpus_manager.direct_cargo_fuzz_binary()),
                            "cmin",
                            "--sanitizer",
                            "address",
                            "--target-dir",
                            str(output_root / "build-target"),
                            "--fuzz-dir",
                            str(output_root / "execution-source" / "fuzz"),
                            "mcp_messages",
                            str(output_root / "work" / "mcp_messages" / label),
                            "--",
                            (
                                "-dict="
                                f"{output_root / 'execution-source' / 'fuzz' / 'dictionaries' / 'cigar.dict'}"
                            ),
                            f"-timeout={campaign_document['timeout_seconds']}",
                            f"-rss_limit_mb={campaign_document['rss_limit_mib']}",
                            f"-max_len={campaign_document['maximum_input_bytes']}",
                            (
                                "-artifact_prefix="
                                f"{output_root / 'artifacts' / 'mcp_messages' / label}{os.sep}"
                            ),
                            f"-seed={seed_value}",
                        ]
                    ),
                    "exit_code": 0,
                    "artifact_count": 0,
                    "deterministic_seed": seed_value,
                    "dependency_mode": "locked-offline-cargo-wrapper",
                    "cargo_fuzz_invocation": corpus_manager.DIRECT_CARGO_FUZZ_MODE,
                    "target_dir": corpus_manager.external_path_binding(
                        output_root / "build-target"
                    ),
                    "timed_out": False,
                    "output_overflow": False,
                    "descendant_cleanup_required": False,
                    "captured_output_bytes": 0,
                    "maximum_output_bytes": policy["maximum_subprocess_output_bytes"],
                    "execution_enforcement": enforcement,
                    "execution_source_after": (
                        corpus_manager.expected_execution_source_state(
                            tracked_source, {"mcp_messages"}
                        )
                    ),
                    "read_only_candidate_unchanged": True,
                    "private_log": {
                        "name": log_path.name,
                        "sha256": corpus_manager.digest_file(log_path),
                        "size": 0,
                        "mode": "0600",
                    },
                }

            preflight_directory = output_root / "preflight"
            corpus_manager.private_mkdir(preflight_directory, exist_ok=False)
            preflight_log = preflight_directory / "cargo-metadata.log"
            corpus_manager.write_new_bytes(preflight_log, b"")
            checkout_log = preflight_directory / "source-checkout.log"
            corpus_manager.write_new_bytes(checkout_log, b"")
            engine = engine_for("primary")
            repeat_engine = engine_for("repeat")
            checkout_preflight = {
                "command": "git checkout-index --all --prefix=<external-execution-source>",
                "exit_code": 0,
                "timed_out": False,
                "output_overflow": False,
                "descendant_cleanup_required": False,
                "captured_output_bytes": 0,
                "maximum_output_bytes": 1024 * 1024,
                "execution_enforcement": enforcement,
                "private_log": {
                    "name": checkout_log.name,
                    "sha256": corpus_manager.digest_file(checkout_log),
                    "size": 0,
                    "mode": "0600",
                },
            }
            report = {
                "schema_version": "cigar.fuzz-corpus-minimization.v1",
                "created_at": corpus_manager.utc_now(),
                "source_working_corpus_unchanged": True,
                "all_fourteen_targets_snapshotted": True,
                "source_corpus_before": source_snapshots,
                "source_corpus_after": source_snapshots,
                "dependency_mode": "locked-offline-cargo-wrapper",
                "cargo_fuzz_execution": cargo_fuzz_execution,
                "read_only_candidate": {
                    "before": candidate_state,
                    "after": candidate_state,
                    "unchanged": True,
                },
                "execution_source": {
                    "construction": "git-checkout-index-closed-regular-file-set",
                    "checkout_preflight": checkout_preflight,
                    "before": corpus_manager.expected_execution_source_state(
                        tracked_source, set()
                    ),
                    "after": corpus_manager.expected_execution_source_state(
                        tracked_source, {"mcp_messages"}
                    ),
                    "tracked_source_unchanged": True,
                    "candidate_tracked_source_equal": True,
                    "compiled_only_from_execution_source": True,
                },
                "success_scratch_cleanup": {
                    "removed": [
                        "build-target",
                        "cargo-wrapper",
                        "execution-source",
                        "work",
                    ],
                    "completed": True,
                },
                "execution_enforcement": enforcement,
                "environment_policy": {
                    "ambient_environment": "strict-reviewed-allowlist",
                    "credentials_proxies_cloud_ci_variables_inherited": False,
                    "private_home_and_tmp": True,
                },
                "metadata_preflight": {
                    "command": corpus_manager.redacted_command(
                        [
                            "cargo",
                            "metadata",
                            "--manifest-path",
                            str(
                                output_root / "execution-source" / "fuzz" / "Cargo.toml"
                            ),
                            "--no-deps",
                            "--format-version",
                            "1",
                        ]
                    ),
                    "exit_code": 0,
                    "timed_out": False,
                    "output_overflow": False,
                    "descendant_cleanup_required": False,
                    "captured_output_bytes": 0,
                    "maximum_output_bytes": 1024 * 1024,
                    "execution_enforcement": enforcement,
                    "private_log": {
                        "name": preflight_log.name,
                        "sha256": corpus_manager.digest_file(preflight_log),
                        "size": 0,
                        "mode": "0600",
                    },
                },
                "source_revision": corpus_manager.git_bytes("rev-parse", "HEAD")
                .decode()
                .strip(),
                "source_binding": source_binding,
                "policy": {
                    "path": "fuzz/corpus-policy.v1.json",
                    "sha256": corpus_manager.digest(
                        corpus_manager.POLICY_PATH.read_bytes(), "sha256"
                    ),
                },
                "campaign": {
                    "path": "fuzz/campaign-v1.json",
                    "sha256": corpus_manager.digest(
                        corpus_manager.CAMPAIGN_PATH.read_bytes(), "sha256"
                    ),
                },
                "targets": [
                    {
                        "target": "mcp_messages",
                        "input": corpus_manager.corpus_state(
                            entries, present_only=False
                        ),
                        "output": state,
                        "repeat_output": repeat_state,
                        "engine": engine,
                        "repeat_engine": repeat_engine,
                        "deterministic_equivalence_proved": True,
                        "old_to_new": mapping,
                    }
                ],
            }
            corpus_manager.shutil.rmtree(output_root / "work")
            corpus_manager.shutil.rmtree(build_target)
            corpus_manager.shutil.rmtree(wrapper_directory)
            corpus_manager.write_new_json(
                output_root / "minimization-report.json", report
            )
            with (
                mock.patch.object(
                    corpus_manager, "tracked_index_entries", return_value=[{}]
                ),
                mock.patch.object(
                    corpus_manager,
                    "candidate_checkout_state",
                    return_value=candidate_state,
                ),
            ):
                verified = corpus_manager.verify_minimized_output(
                    output_root, require_all_targets=False
                )
                self.assertEqual(verified["status"], "passed")
                unexpected = output_root / "unexpected-scratch"
                unexpected.mkdir(mode=0o700)
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.verify_minimized_output(
                        output_root, require_all_targets=False
                    )
                unexpected.rmdir()
                report_path = output_root / "minimization-report.json"
                report["unexpected_field"] = True
                report_path.write_text(
                    json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.verify_minimized_output(
                        output_root, require_all_targets=False
                    )
                report.pop("unexpected_field")
                report["targets"][0]["old_to_new"][0]["retained"] = not report[
                    "targets"
                ][0]["old_to_new"][0]["retained"]
                report_path.write_text(
                    json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.verify_minimized_output(
                        output_root, require_all_targets=False
                    )
                report["targets"][0]["old_to_new"][0]["retained"] = not report[
                    "targets"
                ][0]["old_to_new"][0]["retained"]
                report_path.write_text(
                    json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                regression = (
                    output_root / "corpus" / "mcp_messages" / "out-of-range-numeric-id"
                )
                regression.chmod(0o644)
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.verify_minimized_output(
                        output_root, require_all_targets=False
                    )
                regression.chmod(0o600)
                regression.write_bytes(b"substituted")
                with self.assertRaises(corpus_manager.CorpusFailure):
                    corpus_manager.verify_minimized_output(
                        output_root, require_all_targets=False
                    )


if __name__ == "__main__":
    unittest.main()
