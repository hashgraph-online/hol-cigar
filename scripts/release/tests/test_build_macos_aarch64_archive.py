#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_macos_aarch64_archive as builder  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class MacosAarch64ArchiveBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-macos-builder-")
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

    def arguments(self, evidence: Path | None) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.root,
            evidence_dir=evidence,
            source_date_epoch="1700000000",
            cargo=None,
            rustc=None,
            protoc=None,
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

    def runtime(
        self,
        configuration: builder.BuildConfiguration,
        source: dict[str, object],
        *,
        version: str | None = None,
        source_revision: str | None = None,
    ) -> builder.BuiltRuntime:
        document = {
            "version": version or configuration.version,
            "source_revision": source_revision or str(source["revision"]),
            "context_abi": configuration.context_abi,
            "protocol_min": "1.0",
            "protocol_max": "1.x",
            "build_profile": "release",
            "enabled_features": [],
        }
        generated = {
            path: configuration.assets[path]
            for path in (
                "share/man/man1/cigar.1",
                "completions/cigar.bash",
                "completions/_cigar",
                "completions/cigar.fish",
            )
        }
        return builder.BuiltRuntime(
            cigar=self.macho(b"cigar-development-runtime"),
            cigard=self.macho(b"cigard-development-runtime"),
            cigar_mcp=self.macho(b"cigar-mcp-development-runtime"),
            cigar_claude_hook=self.macho(b"cigar-claude-hook-development-runtime"),
            cigar_version=dict(document),
            cigard_version=dict(document),
            cigar_mcp_probe={
                "status": "ok",
                "protocol_version": "2025-06-18",
                "build": dict(document),
            },
            cigar_claude_hook_probe={
                "schema_version": "cigar.claude-hook-event.v1",
                "ok": True,
                "maximum_input_bytes": 65_536,
                "model_calls": 0,
                "effect_precheck": "fail_closed",
            },
            generated_assets=generated,
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
        configuration: builder.BuildConfiguration,
        source: dict[str, object],
        _epoch: int,
        _scratch: Path,
        _arguments: argparse.Namespace,
    ) -> builder.BuiltRuntime:
        return self.runtime(configuration, source)

    def produce(
        self,
        evidence: Path,
        runtime_builder: builder.RuntimeBuilder | None = None,
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
        with mock.patch.dict(os.environ, {}, clear=True), source_patch:
            return builder.produce(
                self.arguments(evidence),
                runtime_builder=runtime_builder or self.fake_builder,
            )

    def test_configuration_is_bound_to_development_authorities(self) -> None:
        configuration = builder._load_configuration(self.root)
        self.assertEqual(configuration.version, "1.0.0-dev.1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(
            configuration.filename,
            "cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz",
        )
        self.assertEqual(set(configuration.authority), set(builder.AUTHORITY_PATHS))
        self.assertEqual(set(configuration.assets), set(builder.ASSET_PATHS))
        self.assertLessEqual(
            {
                "scripts/release/build_macos_aarch64_archive.py",
                "scripts/release/evidence_workspace.py",
                "scripts/release/release_lib.py",
                "scripts/release/verify_package.py",
                "conformance/runner/**",
                "sdk/rust/**",
                "spec/api/**",
            },
            set(builder.SOURCE_INCLUDES),
        )

    def test_native_build_command_selects_only_the_full_runtime_profile(self) -> None:
        command = builder._runtime_build_command(Path("/private/tooling/cargo"))
        self.assertEqual(command[0:2], ["/private/tooling/cargo", "build"])
        self.assertEqual(command.count("--no-default-features"), 1)
        self.assertEqual(command[command.index("--features") + 1], "full")
        self.assertNotIn("beta-embedded", command)
        self.assertEqual(
            [
                command[index + 1]
                for index, value in enumerate(command)
                if value == "-p"
            ],
            ["cigar-cli", "cigar-daemon", "cigar-mcp", "cigar-claude-hook"],
        )

    def test_runtime_builds_from_a_private_exact_source_snapshot(self) -> None:
        original_spec = (self.root / "spec/api/operations-v1.md").read_bytes()

        def inspect_snapshot(
            configuration: builder.BuildConfiguration,
            source: dict[str, object],
            _epoch: int,
            scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltRuntime:
            self.assertEqual(configuration.root, scratch / "source")
            self.assertNotEqual(configuration.root, self.root)
            self.assertFalse((configuration.root / ".git").exists())
            self.assertEqual(
                (configuration.root / "spec/api/operations-v1.md").read_bytes(),
                original_spec,
            )
            self.assertEqual(
                stat.S_IMODE(configuration.root.stat().st_mode),
                0o700,
            )
            return self.runtime(configuration, source)

        receipt = self.produce(self.base / "snapshot-build", inspect_snapshot)
        self.assertEqual(receipt["source"], self.source)

    def test_source_snapshot_recheck_and_destination_escape_fail_closed(self) -> None:
        root = self.base / "source-recheck"
        root.mkdir(mode=0o700)
        source = root / "input.rs"
        source.write_bytes(b"fn original() {}\n")
        snapshot = (builder.SourceInput("input.rs", source.read_bytes(), 0o644),)
        source.write_bytes(b"fn modified() {}\n")
        with self.assertRaisesRegex(ReleaseError, "changed after"):
            builder._verify_source_snapshot(root, snapshot)

        destination = self.base / "escaped-snapshot"
        malicious = (builder.SourceInput("../outside", b"payload", 0o644),)
        with self.assertRaises(ReleaseError):
            builder._write_source_snapshot(malicious, destination)
        self.assertFalse((self.base / "outside").exists())

    def test_fake_native_build_is_deterministic_contract_valid_and_unclaimed(
        self,
    ) -> None:
        first_root = self.base / "first"
        second_root = self.base / "second"
        first = self.produce(first_root)
        second = self.produce(second_root)

        filename = "cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz"
        first_archive = first_root / filename
        second_archive = second_root / filename
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first["archive"], second["archive"])
        self.assertEqual(first["status"], "built-unqualified")
        self.assertEqual(first["runtime_profile"], builder.RUNTIME_PROFILE)
        self.assertEqual(
            set(first["runtime_payload"]),
            {"cigar", "cigard", "cigar-mcp", "cigar-claude-hook"},
        )
        self.assertEqual(
            {record["path"] for record in first["runtime_payload"].values()},
            {
                "bin/cigar",
                "bin/cigard",
                "bin/cigar-mcp",
                "bin/cigar-claude-hook",
            },
        )
        self.assertEqual(
            first["claims"],
            {
                "development_build": True,
                "distribution_signed": False,
                "notarized": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        )
        self.assertEqual(
            first["build_environment"],
            {
                "cargo_network_offline": True,
                "network_enforcement": "darwin-sandbox-exec-deny-network-v1",
                "sandbox_launcher": "/usr/bin/sandbox-exec",
                "sandbox_policy": "(version 1)(allow default)(deny network*)",
            },
        )
        self.assertEqual(stat.S_IMODE(first_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(first_archive.stat().st_mode), 0o400)
        self.assertEqual(
            stat.S_IMODE((first_root / builder.BUILD_RECEIPT).stat().st_mode), 0o400
        )
        self.assertEqual(
            json.loads((first_root / builder.BUILD_RECEIPT).read_bytes()), first
        )

        with tarfile.open(first_archive, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers()}
            expected = {
                "RELEASE-METADATA.json",
                "LICENSE",
                "NOTICE",
                "SHA256SUMS",
                "bin/cigar",
                "bin/cigard",
                "bin/cigar-mcp",
                "bin/cigar-claude-hook",
                "share/man/man1/cigar.1",
                "completions/cigar.bash",
                "completions/_cigar",
                "completions/cigar.fish",
            }
            self.assertEqual(set(members), expected)
            self.assertTrue(
                all(member.uid == 0 and member.gid == 0 for member in members.values())
            )
            self.assertTrue(
                all(member.mtime == 1_700_000_000 for member in members.values())
            )
            self.assertEqual(members["bin/cigar"].mode, 0o755)
            self.assertEqual(members["bin/cigard"].mode, 0o755)
            self.assertEqual(members["bin/cigar-mcp"].mode, 0o755)
            self.assertEqual(members["bin/cigar-claude-hook"].mode, 0o755)
            self.assertEqual(members["LICENSE"].mode, 0o644)
            metadata_handle = archive.extractfile("RELEASE-METADATA.json")
            self.assertIsNotNone(metadata_handle)
            assert metadata_handle is not None
            metadata = json.loads(metadata_handle.read())
            self.assertEqual(metadata["artifact_id"], builder.ARTIFACT_ID)
            self.assertFalse(metadata["source"]["clean"])

    def test_stale_runtime_wrong_architecture_and_source_change_fail_closed(
        self,
    ) -> None:
        def stale(
            configuration: builder.BuildConfiguration,
            source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltRuntime:
            return self.runtime(configuration, source, version="9.9.9")

        stale_root = self.base / "stale"
        with self.assertRaisesRegex(ReleaseError, "stale or malformed"):
            self.produce(stale_root, stale)
        self.assertEqual(list(stale_root.iterdir()), [])

        configuration = builder._load_configuration(self.root)
        beta_profile = self.runtime(configuration, self.source)
        beta_profile.cigar_version["enabled_features"] = ["beta-embedded"]
        with self.assertRaisesRegex(ReleaseError, "stale or malformed"):
            builder._validate_runtime(beta_profile, configuration, self.source)

        invalid = self.runtime(configuration, self.source)
        invalid = builder.BuiltRuntime(
            cigar=b"not-a-mach-o-binary" * 2,
            cigard=invalid.cigard,
            cigar_mcp=invalid.cigar_mcp,
            cigar_claude_hook=invalid.cigar_claude_hook,
            cigar_version=invalid.cigar_version,
            cigard_version=invalid.cigard_version,
            cigar_mcp_probe=invalid.cigar_mcp_probe,
            cigar_claude_hook_probe=invalid.cigar_claude_hook_probe,
            generated_assets=invalid.generated_assets,
            tools=invalid.tools,
        )
        with self.assertRaisesRegex(ReleaseError, "thin arm64"):
            builder._validate_runtime(invalid, configuration, self.source)

        changed = {**self.source, "tree_sha256": "e" * 64}
        changed_root = self.base / "changed"
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(
                changed_root,
                source_side_effect=[self.source, changed],
            )
        self.assertEqual(list(changed_root.iterdir()), [])

    def test_staged_archive_mutation_after_verification_cannot_publish(self) -> None:
        evidence = self.base / "mutated-archive"
        original_attach = builder.EvidenceWorkspace.attach_file
        observed_binding: dict[str, object] = {}

        def mutate_before_copy(
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
            with source.open("ab") as handle:
                handle.write(b"post-verification mutation")
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
                new=mutate_before_copy,
            ),
            self.assertRaisesRegex(
                EvidenceWorkspaceError, "differs from validated content"
            ),
        ):
            self.produce(evidence)

        self.assertRegex(str(observed_binding["sha256"]), r"^[0-9a-f]{64}$")
        self.assertGreater(int(observed_binding["bytes"]), 0)
        self.assertEqual(list(evidence.iterdir()), [])

    def test_output_selection_rejects_missing_relative_conflict_and_reuse(self) -> None:
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
        internal = self.root / "reports" / "native-development"
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

    def test_host_and_child_environment_are_native_and_do_not_share_evidence(
        self,
    ) -> None:
        with (
            mock.patch.object(builder.sys, "platform", "linux"),
            mock.patch.object(builder.platform, "machine", return_value="aarch64"),
            self.assertRaisesRegex(ReleaseError, "Apple-silicon macOS"),
        ):
            builder._require_host()

        configuration = builder._load_configuration(self.root)
        cargo = Path(shutil_which("cargo"))
        rustc = Path(shutil_which("rustc"))
        protoc = Path(shutil_which("protoc"))
        scratch = self.base / "scratch"
        scratch.mkdir(mode=0o700)
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(self.base / "parent")}, clear=False
        ):
            environment = builder._cargo_environment(
                configuration,
                self.source,
                1_700_000_000,
                scratch,
                cargo,
                rustc,
                protoc,
            )
        self.assertNotIn("CIGAR_EVIDENCE_DIR", environment)
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(scratch / "target"))
        remap_flags = environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        self.assertEqual(len(remap_flags), len(set(remap_flags)))
        self.assertTrue(
            remap_flags[0].startswith(f"--remap-path-prefix={configuration.root}=")
        )
        for destination in (
            "/usr/src/cigar",
            "/usr/src/cigar-build",
            "/usr/src/cargo-home",
            "/usr/src/rustup-home",
            "/usr/src/owner-home",
        ):
            self.assertTrue(
                any(flag.endswith(f"={destination}") for flag in remap_flags),
                destination,
            )

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_build_subprocesses_are_wrapped_in_the_fixed_no_egress_sandbox(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"ok\n", stderr=b""
        )
        with mock.patch.object(builder, "run_bounded", return_value=completed) as run:
            output = builder._run_checked(
                ["/private/tmp/cargo", "build"],
                cwd=self.base,
                environment={"PATH": "/usr/bin:/bin"},
                timeout=30,
                label="sandbox wrapping probe",
            )
        self.assertEqual(output, b"ok\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/sandbox-exec",
                "-p",
                "(version 1)(allow default)(deny network*)",
                "/private/tmp/cargo",
                "build",
            ],
        )

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_build_sandbox_actually_denies_socket_connect(self) -> None:
        probe = """import socket, sys
try:
    client = socket.socket()
    client.connect(("127.0.0.1", 9))
except PermissionError:
    raise SystemExit(0)
except OSError:
    raise SystemExit(3)
raise SystemExit(4)
"""
        output = builder._run_checked(
            ["/usr/bin/python3", "-c", probe],
            cwd=self.base,
            environment={"PATH": "/usr/bin:/bin", "HOME": str(self.base)},
            timeout=30,
            label="network denial probe",
        )
        self.assertEqual(output, b"")


def shutil_which(name: str) -> str:
    import shutil

    value = shutil.which(name)
    if value is None:
        raise AssertionError(f"{name} is unavailable")
    return value


if __name__ == "__main__":
    unittest.main()
