#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_claude_code_plugin as builder  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class ClaudeCodePluginBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-plugin-builder-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.root = builder.REPOSITORY_ROOT
        self.source = {
            "revision": "a" * 40,
            "tree_sha256": "b" * 64,
            "committed": True,
            "clean": False,
        }
        self.host = {
            "platform": "macos",
            "architecture": "arm64",
            "target_triple": builder.TARGET_TRIPLE,
            "macos_version": "15.6",
        }

    def arguments(self, evidence: Path | None) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.root,
            evidence_dir=evidence,
            source_date_epoch="1700000000",
            cargo=None,
            rustc=None,
            runtime_archive=None,
        )

    @staticmethod
    def macho(marker: bytes) -> bytes:
        return (
            struct.pack(
                "<IIIIIIII",
                0xFEEDFACF,
                0x0100000C,
                0,
                2,
                0,
                0,
                0,
                0,
            )
            + marker
        )

    def hook(self, *, probe: dict[str, object] | None = None) -> builder.BuiltHook:
        return builder.BuiltHook(
            executable=self.macho(b"cigar-claude-hook-development-runtime"),
            mcp_executable=self.macho(b"cigar-mcp-development-runtime"),
            schema_probe=probe
            or {
                "schema_version": "cigar.claude-hook-event.v1",
                "ok": True,
                "maximum_input_bytes": 65_536,
                "model_calls": 0,
                "effect_precheck": "fail_closed",
            },
            tools=(
                {
                    "name": "cargo",
                    "version": "cargo test",
                    "sha256": "c" * 64,
                    "bytes": 1,
                },
                {
                    "name": "rustc",
                    "version": "rustc test",
                    "sha256": "d" * 64,
                    "bytes": 1,
                },
            ),
        )

    def fake_builder(
        self,
        _configuration: builder.BuildConfiguration,
        _source: dict[str, object],
        _epoch: int,
        _scratch: Path,
        _arguments: argparse.Namespace,
    ) -> builder.BuiltHook:
        return self.hook()

    @staticmethod
    def fake_validator(
        _configuration: builder.BuildConfiguration, _scratch: Path
    ) -> dict[str, object]:
        return {
            "validator": "adapters/claude-code/tests/validate_package.py",
            "status": "passed",
        }

    def produce(
        self,
        evidence: Path,
        hook_builder: builder.HookBuilder | None = None,
        *,
        source_side_effect: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        source_patch = (
            mock.patch.object(
                builder, "_source_identity", side_effect=source_side_effect
            )
            if source_side_effect is not None
            else mock.patch.object(
                builder, "_source_identity", return_value=self.source
            )
        )
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(builder, "_require_host", return_value=self.host),
            source_patch,
        ):
            return builder.produce(
                self.arguments(evidence),
                hook_builder=hook_builder or self.fake_builder,
                source_validator=self.fake_validator,
            )

    def test_configuration_binds_exact_honey_authorities_and_source_package(
        self,
    ) -> None:
        configuration = builder._load_configuration(self.root)
        self.assertEqual(configuration.version, "0.9.2")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(
            configuration.filename,
            "cigar-claude-code-0.9.2.tar.gz",
        )
        self.assertEqual(
            set(configuration.authority), set(builder.HONEY_AUTHORITY_PATHS)
        )
        self.assertEqual(
            configuration.receipt_filename,
            "claude-code-plugin-build-receipt.json",
        )
        self.assertTrue(configuration.honey)
        self.assertEqual(
            builder._runtime_artifact_id(configuration),
            builder.HONEY_RUNTIME_ARTIFACT_ID,
        )
        self.assertEqual(
            builder._runtime_artifact_id(mock.Mock(honey=False)),
            builder.DEVELOPMENT_RUNTIME_ARTIFACT_ID,
        )
        self.assertEqual(
            set(configuration.assets),
            set(builder.SOURCE_RELEASE_PATHS) | {"LICENSE", "NOTICE"},
        )
        compatibility = json.loads(configuration.assets["compatibility.json"])
        self.assertEqual(compatibility["context_abi"], "cigar.context.v1")

    def test_fake_build_is_deterministic_contract_valid_and_unclaimed(self) -> None:
        first_root = self.base / "first"
        second_root = self.base / "second"
        first = self.produce(first_root)
        second = self.produce(second_root)

        filename = "cigar-claude-code-0.9.2.tar.gz"
        first_archive = first_root / filename
        second_archive = second_root / filename
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first["archive"], second["archive"])
        self.assertEqual(first["status"], "built-unqualified")
        self.assertEqual(
            first["claims"],
            {
                "development_build": True,
                "installed_compatibility": False,
                "distribution_signed": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        )
        self.assertEqual(stat.S_IMODE(first_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(first_archive.stat().st_mode), 0o400)
        receipt_path = first_root / "claude-code-plugin-build-receipt.json"
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o400)
        self.assertEqual(json.loads(receipt_path.read_bytes()), first)

        with tarfile.open(first_archive, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers()}
            expected = set(builder.SOURCE_RELEASE_PATHS) | {
                "RELEASE-METADATA.json",
                "LICENSE",
                "NOTICE",
                "SHA256SUMS",
                "bin/cigar-claude-hook",
                "bin/cigar-mcp",
            }
            self.assertEqual(set(members), expected)
            self.assertNotIn("package-manifest.json", members)
            self.assertFalse(any(name.startswith("tests/") for name in members))
            self.assertTrue(
                all(member.uid == 0 and member.gid == 0 for member in members.values())
            )
            self.assertTrue(
                all(member.mtime == 1_700_000_000 for member in members.values())
            )
            self.assertEqual(members["bin/cigar-claude-hook"].mode, 0o755)
            self.assertEqual(members["bin/cigar-mcp"].mode, 0o755)
            self.assertEqual(members["compatibility.json"].mode, 0o644)
            metadata_handle = archive.extractfile("RELEASE-METADATA.json")
            self.assertIsNotNone(metadata_handle)
            assert metadata_handle is not None
            metadata = json.loads(metadata_handle.read())
            self.assertEqual(metadata["artifact_id"], builder.ARTIFACT_ID)
            self.assertFalse(metadata["source"]["clean"])
            readme_handle = archive.extractfile("README.md")
            self.assertIsNotNone(readme_handle)
            assert readme_handle is not None
            readme = readme_handle.read().decode("utf-8")
            self.assertIn("unpublished, unsupported development package", readme)
            self.assertIn("define a future qualification scope only", readme)
            self.assertNotIn("This package is qualified", readme)
            self.assertNotIn("runs signed CIGAR executables", readme)

    def test_stale_probe_wrong_architecture_and_source_change_fail_closed(self) -> None:
        def stale(
            _configuration: builder.BuildConfiguration,
            _source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltHook:
            return self.hook(
                probe={
                    "schema_version": "cigar.claude-hook-event.v0",
                    "ok": True,
                    "maximum_input_bytes": 65_536,
                    "model_calls": 0,
                    "effect_precheck": "fail_closed",
                }
            )

        stale_root = self.base / "stale"
        with self.assertRaisesRegex(ReleaseError, "probe is stale"):
            self.produce(stale_root, stale)
        self.assertEqual(list(stale_root.iterdir()), [])

        invalid = self.hook()
        invalid = builder.BuiltHook(
            executable=b"not-a-mach-o-binary" * 2,
            mcp_executable=invalid.mcp_executable,
            schema_probe=invalid.schema_probe,
            tools=invalid.tools,
        )
        with self.assertRaisesRegex(ReleaseError, "thin arm64"):
            builder._validate_hook(invalid)

        changed = {**self.source, "tree_sha256": "e" * 64}
        changed_root = self.base / "changed"
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(
                changed_root,
                source_side_effect=[self.source, changed],
            )
        self.assertEqual(list(changed_root.iterdir()), [])

    def test_same_length_substitution_after_verification_cannot_publish(self) -> None:
        evidence = self.base / "mutated-archive"
        original_attach = builder.EvidenceWorkspace.attach_file
        observed_binding: dict[str, object] = {}

        def substitute_before_copy(
            workspace: builder.EvidenceWorkspace,
            source: Path,
            relative: str,
            *,
            read_only: bool = True,
            expected_sha256: str | None = None,
            expected_bytes: int | None = None,
        ) -> object:
            observed_binding.update(
                {"sha256": expected_sha256, "bytes": expected_bytes}
            )
            payload = bytearray(source.read_bytes())
            payload[-1] ^= 1
            with source.open("r+b") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return original_attach(
                workspace,
                source,
                relative,
                read_only=read_only,
                expected_sha256=expected_sha256,
                expected_bytes=expected_bytes,
            )

        with (
            mock.patch.object(
                builder.EvidenceWorkspace,
                "attach_file",
                new=substitute_before_copy,
            ),
            self.assertRaisesRegex(
                EvidenceWorkspaceError, "SHA-256 differs from validated content"
            ),
        ):
            self.produce(evidence)

        self.assertRegex(str(observed_binding["sha256"]), r"^[0-9a-f]{64}$")
        self.assertGreater(int(observed_binding["bytes"]), 0)
        self.assertEqual(list(evidence.iterdir()), [])

    def test_verifier_same_length_substitution_cannot_reach_publication(self) -> None:
        evidence = self.base / "verifier-substitution"
        real_verify = builder.verify_package

        def substitute_after_verify(*args: object, **kwargs: object) -> object:
            result = real_verify(*args, **kwargs)
            archive = Path(args[0])
            payload = bytearray(archive.read_bytes())
            payload[len(payload) // 2] ^= 1
            with archive.open("r+b") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            return result

        with (
            mock.patch.object(
                builder, "verify_package", side_effect=substitute_after_verify
            ),
            self.assertRaisesRegex(ReleaseError, "changed during package verification"),
        ):
            self.produce(evidence)
        self.assertEqual(list(evidence.iterdir()), [])

    def test_output_selection_rejects_unsafe_paths_conflicts_and_reuse(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "is required"):
                builder._selected_evidence_directory(self.arguments(None))
            with self.assertRaisesRegex(ReleaseError, "absolute path"):
                builder._selected_evidence_directory(
                    self.arguments(Path("relative-output"))
                )

        conflicting = self.arguments(self.base / "argument")
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "environment")},
            clear=True,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                builder._selected_evidence_directory(conflicting)

        evidence = self.base / "once"
        self.produce(evidence)
        attempted = mock.Mock(side_effect=AssertionError("builder must not run"))
        with self.assertRaisesRegex(EvidenceWorkspaceError, "inventory mismatch"):
            self.produce(evidence, attempted)
        attempted.assert_not_called()

    def test_external_workspace_rejects_repository_symlink_and_public_roots(
        self,
    ) -> None:
        internal = self.root / "reports" / "plugin-development"
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.produce(internal)
        self.assertFalse(internal.exists())

        target = self.base / "target"
        target.mkdir(mode=0o700)
        linked = self.base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.produce(linked)

        public = self.base / "public"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
            self.produce(public)

    def test_source_manifest_rejects_same_length_asset_substitution(self) -> None:
        adapter = self.base / "adapter"
        adapter.mkdir(mode=0o700)
        asset = adapter / "README.md"
        asset.write_bytes(b"reviewed\n")
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        manifest = {
            "schema_version": "cigar.claude-code-package.v1",
            "files": [
                {
                    "path": "README.md",
                    "sha256": digest,
                    "bytes": len(asset.read_bytes()),
                }
            ],
        }
        (adapter / "package-manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8"
        )
        with mock.patch.object(
            builder, "SOURCE_RELEASE_PATHS", frozenset({"README.md"})
        ):
            self.assertEqual(
                builder._manifest_assets(adapter), {"README.md": b"reviewed\n"}
            )
            asset.write_bytes(b"replaced\n")
            self.assertEqual(asset.stat().st_size, len(b"reviewed\n"))
            with self.assertRaisesRegex(ReleaseError, "binding differs"):
                builder._manifest_assets(adapter)

    def test_stable_input_reader_rejects_links_and_writable_files(self) -> None:
        writable = self.base / "writable"
        writable.write_bytes(b"payload")
        os.chmod(writable, 0o666)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            builder._read_stable_file(writable, 1024, "writable input")

        safe = self.base / "safe"
        safe.write_bytes(b"payload")
        os.chmod(safe, 0o600)
        linked = self.base / "input-link"
        linked.symlink_to(safe)
        with self.assertRaisesRegex(ReleaseError, "securely read"):
            builder._read_stable_file(linked, 1024, "linked input")

        hardlink = self.base / "hardlink"
        os.link(safe, hardlink)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            builder._read_stable_file(safe, 1024, "hardlinked input")

    def test_source_validator_and_child_environment_are_hermetic(self) -> None:
        configuration = builder._load_configuration(self.root)
        scratch = self.base / "validator-scratch"
        scratch.mkdir(mode=0o700)
        self.assertEqual(
            builder._default_source_validator(configuration, scratch),
            {
                "validator": "adapters/claude-code/tests/validate_package.py",
                "status": "passed",
            },
        )

        cargo_value = shutil.which("cargo")
        rustc_value = shutil.which("rustc")
        self.assertIsNotNone(cargo_value)
        self.assertIsNotNone(rustc_value)
        assert cargo_value is not None and rustc_value is not None
        build_scratch = self.base / "build-scratch"
        build_scratch.mkdir(mode=0o700)
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(self.base / "parent")}, clear=False
        ):
            environment = builder._cargo_environment(
                configuration,
                1_700_000_000,
                build_scratch,
                Path(cargo_value),
                Path(rustc_value),
            )
        self.assertNotIn("CIGAR_EVIDENCE_DIR", environment)
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(build_scratch / "target"))
        remap_flags = environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        self.assertEqual(len(remap_flags), len(set(remap_flags)))
        for destination in (
            "/usr/src/cigar",
            "/usr/src/cigar-plugin-build",
            "/usr/src/cargo-home",
            "/usr/src/rustup-home",
            "/usr/src/owner-home",
        ):
            self.assertTrue(
                any(flag.endswith(f"={destination}") for flag in remap_flags),
                destination,
            )

    def test_default_builder_reuses_exact_verified_runtime_hook_bytes(self) -> None:
        configuration = builder._load_configuration(self.root)
        scratch = self.base / "runtime-build-scratch"
        scratch.mkdir(mode=0o700)
        hook = (
            b"#!/bin/sh\nset -eu\nprintf '%s\\n' "
            b'\'{"schema_version":"cigar.claude-hook-event.v1","ok":true,'
            b'"maximum_input_bytes":65536,"model_calls":0,'
            b'"effect_precheck":"fail_closed"}\'\n'
        )
        mcp = b"#!/bin/sh\nset -eu\nprintf '%s\\n' '{\"ok\":true}'\n"
        runtime = self.base / "runtime.tar.gz"
        with tarfile.open(runtime, "w:gz") as archive:
            member = tarfile.TarInfo("bin/cigar-claude-hook")
            member.size = len(hook)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(hook))
            member = tarfile.TarInfo("bin/cigar-mcp")
            member.size = len(mcp)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(mcp))
        os.chmod(runtime, 0o600)
        arguments = self.arguments(self.base / "unused")
        arguments.runtime_archive = runtime
        verification = {
            "schema_version": "cigar.package-verification.v1",
            "status": "passed",
            "file_count": 2,
            "expanded_bytes": len(hook) + len(mcp),
            "metadata": {
                "artifact_id": builder.HONEY_RUNTIME_ARTIFACT_ID,
                "product_version": configuration.version,
                "context_abi": configuration.context_abi,
                "source_date_epoch": 1_700_000_000,
                "source": dict(self.source),
            },
        }
        with mock.patch.object(builder, "verify_package", return_value=verification):
            built = builder._default_hook_builder(
                configuration,
                self.source,
                1_700_000_000,
                scratch,
                arguments,
            )
        self.assertEqual(built.executable, hook)
        self.assertEqual(built.mcp_executable, mcp)
        self.assertEqual(
            built.runtime_binding["hook"],
            {"sha256": hashlib.sha256(hook).hexdigest(), "bytes": len(hook)},
        )
        self.assertEqual(
            built.runtime_binding["artifact_id"],
            builder.HONEY_RUNTIME_ARTIFACT_ID,
        )
        self.assertFalse(built.runtime_binding["distribution_signature_qualified"])

    def test_host_rejects_non_native_platforms(self) -> None:
        with (
            mock.patch.object(builder.sys, "platform", "linux"),
            mock.patch.object(builder.platform, "machine", return_value="aarch64"),
            self.assertRaisesRegex(ReleaseError, "Apple-silicon macOS"),
        ):
            builder._require_host()


if __name__ == "__main__":
    unittest.main()
