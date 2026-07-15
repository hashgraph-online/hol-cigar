from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "historical_crashes", ROOT / "tools" / "quality" / "historical_crashes.py"
)
assert SPEC is not None and SPEC.loader is not None
historical_crashes = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = historical_crashes
SPEC.loader.exec_module(historical_crashes)


class HistoricalCrashTests(unittest.TestCase):
    def _write(self, root: Path, relative: str, body: bytes) -> None:
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)

    def _binding(self, root: Path, relative: str) -> dict[str, object]:
        body = (root / relative).read_bytes()
        return {
            "path": relative,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body),
        }

    def _fixture(self, root: Path, relative: str) -> dict[str, object]:
        body = (root / relative).read_bytes()
        return {
            "path": relative,
            "encoding": "base64",
            "bytes": historical_crashes.base64.b64encode(body).decode("ascii"),
            "size": len(body),
            "sha1": hashlib.sha1(body, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    def _workspace(self, raw: str) -> tuple[Path, Path, dict[str, object]]:
        root = Path(raw).resolve() / "source"
        root.mkdir(mode=0o700)
        for directory in (
            "fuzz/artifacts",
            "fuzz/corpus/mcp_messages",
            "fuzz/regressions/mcp_messages",
        ):
            (root / directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._write(
            root,
            "fuzz/campaign-v1.json",
            (ROOT / "fuzz/campaign-v1.json").read_bytes(),
        )
        self._write(
            root,
            "fuzz/corpus-policy.v1.json",
            (ROOT / "fuzz/corpus-policy.v1.json").read_bytes(),
        )
        self._write(
            root,
            "fuzz/corpus/mcp_messages/out-of-range-numeric-id",
            (ROOT / "fuzz/corpus/mcp_messages/out-of-range-numeric-id").read_bytes(),
        )
        self._write(
            root,
            "fuzz/regressions/mcp_messages/backend-nonfinite-number.json",
            (
                ROOT / "fuzz/regressions/mcp_messages/backend-nonfinite-number.json"
            ).read_bytes(),
        )
        for relative in sorted(historical_crashes.REQUIRED_SOURCE_BINDINGS):
            self._write(root, relative, f"bound source: {relative}\n".encode())

        manifest = deepcopy(
            json.loads((ROOT / "fuzz/historical-crashes.v1.json").read_bytes())
        )
        manifest["campaign"] = self._binding(root, "fuzz/campaign-v1.json")
        manifest["corpus_policy"] = self._binding(root, "fuzz/corpus-policy.v1.json")
        manifest["source_bindings"] = [
            self._binding(root, relative)
            for relative in sorted(historical_crashes.REQUIRED_SOURCE_BINDINGS)
        ]
        for regression in manifest["regressions"]:
            regression["fixture"] = self._fixture(root, regression["fixture"]["path"])
        manifest_path = root / "fuzz/historical-crashes.v1.json"
        self._write(
            root,
            "fuzz/historical-crashes.v1.json",
            historical_crashes._canonical_json(manifest),
        )
        return root, manifest_path, manifest

    def _rewrite_manifest(
        self, root: Path, manifest: dict[str, object], *, canonical: bool = True
    ) -> None:
        if canonical:
            body = historical_crashes._canonical_json(manifest)
        else:
            body = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
        (root / "fuzz/historical-crashes.v1.json").write_bytes(body)

    def test_checked_in_manifest_is_closed_and_source_bound(self) -> None:
        manifest = historical_crashes.validate_manifest()
        self.assertEqual(manifest.document["supported_target"], "aarch64-apple-darwin")
        self.assertEqual(
            [entry["id"] for entry in manifest.document["regressions"]],
            [
                "mcp-nonfinite-backend-number",
                "mcp-out-of-range-numeric-id",
            ],
        )
        for regression in manifest.document["regressions"]:
            self.assertEqual(
                regression["test_command"],
                historical_crashes._expected_command(regression["test_selector"]),
            )

    def test_cargo_resolution_and_compiled_mcp_library_are_source_bound(self) -> None:
        required = {
            ".cargo/config.toml",
            "Cargo.toml",
            "rust-toolchain.toml",
            "crates/cigar-mcp/src/backend.rs",
            "crates/cigar-mcp/src/generated/operation_mappings.rs",
            "crates/cigar-mcp/src/lib.rs",
        }
        self.assertTrue(required <= historical_crashes.REQUIRED_SOURCE_BINDINGS)
        for relative in sorted(required):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                root, manifest_path, _manifest = self._workspace(raw)
                path = root / relative
                path.write_bytes(path.read_bytes() + b"unbound substitution\n")
                with self.assertRaises(historical_crashes.HistoricalCrashError):
                    historical_crashes.validate_manifest(
                        root=root, manifest_path=manifest_path
                    )

    def test_missing_extra_tampered_duplicate_and_unmapped_fixtures_fail(self) -> None:
        mutations = ("missing", "extra", "tampered", "duplicate", "unmapped")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root, manifest_path, manifest = self._workspace(raw)
                backend = (
                    root / "fuzz/regressions/mcp_messages/backend-nonfinite-number.json"
                )
                if mutation == "missing":
                    backend.unlink()
                elif mutation == "extra":
                    self._write(
                        root,
                        "fuzz/regressions/mcp_messages/unmapped.json",
                        b"{}\n",
                    )
                elif mutation == "tampered":
                    backend.write_bytes(b'{"substituted":true}\n')
                elif mutation == "duplicate":
                    manifest["regressions"].append(deepcopy(manifest["regressions"][0]))
                    self._rewrite_manifest(root, manifest)
                else:
                    self._write(
                        root,
                        "fuzz/artifacts/mcp_messages/crash-unmapped",
                        b"fault\n",
                    )
                with self.assertRaises(historical_crashes.HistoricalCrashError):
                    historical_crashes.validate_manifest(
                        root=root, manifest_path=manifest_path
                    )

    def test_policy_added_regression_without_mapping_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, manifest_path, manifest = self._workspace(raw)
            body = b"new historical input\n"
            self._write(
                root,
                "fuzz/corpus/mcp_messages/unmapped-policy-regression",
                body,
            )
            policy_path = root / "fuzz/corpus-policy.v1.json"
            policy = json.loads(policy_path.read_bytes())
            policy["targets"]["mcp_messages"]["named_fixtures"].append(
                {
                    "classification": "minimized-regression",
                    "name": "unmapped-policy-regression",
                    "sha1": hashlib.sha1(body, usedforsecurity=False).hexdigest(),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            manifest["corpus_policy"] = self._binding(
                root, "fuzz/corpus-policy.v1.json"
            )
            self._rewrite_manifest(root, manifest)
            with self.assertRaisesRegex(
                historical_crashes.HistoricalCrashError, "inventory is not closed"
            ):
                historical_crashes.validate_manifest(
                    root=root, manifest_path=manifest_path
                )

    def test_symlink_hardlink_fifo_and_case_alias_fixtures_fail_closed(self) -> None:
        for mutation in ("symlink", "hardlink", "fifo", "alias"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root, manifest_path, _manifest = self._workspace(raw)
                backend = (
                    root / "fuzz/regressions/mcp_messages/backend-nonfinite-number.json"
                )
                if mutation == "symlink":
                    preserved = backend.with_suffix(".preserved")
                    backend.rename(preserved)
                    backend.symlink_to(preserved.name)
                elif mutation == "hardlink":
                    preserved = root / "hardlinked-source"
                    backend.rename(preserved)
                    os.link(preserved, backend)
                elif mutation == "fifo":
                    backend.unlink()
                    os.mkfifo(backend, 0o600)
                else:
                    alias = backend.with_name(backend.name.upper())
                    try:
                        descriptor = os.open(
                            alias,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                        )
                    except FileExistsError:
                        backend.rename(alias)
                    else:
                        os.write(descriptor, b"alias\n")
                        os.close(descriptor)
                with self.assertRaises(historical_crashes.HistoricalCrashError):
                    historical_crashes.validate_manifest(
                        root=root, manifest_path=manifest_path
                    )

    def test_manifest_shape_source_digest_and_command_weakening_fail(self) -> None:
        mutations = ("noncanonical", "unknown", "source", "command", "selector")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root, manifest_path, manifest = self._workspace(raw)
                if mutation == "noncanonical":
                    self._rewrite_manifest(root, manifest, canonical=False)
                elif mutation == "unknown":
                    manifest["unexpected"] = True
                    self._rewrite_manifest(root, manifest)
                elif mutation == "source":
                    manifest["source_bindings"].pop()
                    self._rewrite_manifest(root, manifest)
                elif mutation == "command":
                    manifest["regressions"][0]["test_command"].remove("--offline")
                    self._rewrite_manifest(root, manifest)
                else:
                    manifest["regressions"][0]["test_selector"] = "test(server)"
                    self._rewrite_manifest(root, manifest)
                with self.assertRaises(historical_crashes.HistoricalCrashError):
                    historical_crashes.validate_manifest(
                        root=root, manifest_path=manifest_path
                    )

    def test_runner_uses_only_exact_commands_and_revalidates_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root, manifest_path, manifest = self._workspace(raw)
            observed_commands: list[list[str]] = []

            def passed(command: list[str], **_kwargs: object) -> dict[str, object]:
                observed_commands.append(command)
                return {
                    "exit_code": 0,
                    "timed_out": False,
                    "output_overflow": False,
                    "descendant_cleanup_required": False,
                    "captured_output_bytes": 10,
                    "log_sha256": "0" * 64,
                }

            with (
                mock.patch.object(historical_crashes, "_native_macos"),
                mock.patch.object(
                    historical_crashes, "run_bounded", side_effect=passed
                ),
            ):
                result = historical_crashes.run_regressions(
                    root=root, manifest_path=manifest_path
                )
            self.assertEqual(result["status"], "passed")
            self.assertFalse(result["release_eligible"])
            self.assertEqual(
                observed_commands,
                [entry["test_command"] for entry in manifest["regressions"]],
            )
            for command in observed_commands:
                self.assertIn("--offline", command)
                self.assertEqual(command[-2], "-E")
                self.assertTrue(command[-1].startswith("test(="))

    def test_runner_rejects_failed_or_source_mutating_test(self) -> None:
        for mutation in ("failed", "source-mutating"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root, manifest_path, _manifest = self._workspace(raw)
                calls = 0

                def result(*_args: object, **_kwargs: object) -> dict[str, object]:
                    nonlocal calls
                    calls += 1
                    if mutation == "source-mutating":
                        source = root / "crates/cigar-mcp/src/server.rs"
                        source.write_bytes(source.read_bytes() + b"changed\n")
                    return {
                        "exit_code": 1 if mutation == "failed" else 0,
                        "timed_out": False,
                        "output_overflow": False,
                        "descendant_cleanup_required": False,
                        "captured_output_bytes": 0,
                        "log_sha256": "0" * 64,
                    }

                with (
                    mock.patch.object(historical_crashes, "_native_macos"),
                    mock.patch.object(
                        historical_crashes, "run_bounded", side_effect=result
                    ),
                    self.assertRaises(historical_crashes.HistoricalCrashError),
                ):
                    historical_crashes.run_regressions(
                        root=root, manifest_path=manifest_path
                    )
                self.assertGreaterEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
