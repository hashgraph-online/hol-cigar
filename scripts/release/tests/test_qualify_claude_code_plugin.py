#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
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

import qualify_claude_code_plugin as qualifier  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure qualification requires POSIX")
class ClaudePluginInstalledQualifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-claude-qualifier-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)

    def arguments(self, evidence: Path | None) -> argparse.Namespace:
        return argparse.Namespace(evidence_dir=evidence)

    def archive(self, name: str, members: list[tuple[str, bytes, str]]) -> Path:
        path = self.base / name
        with tarfile.open(path, "w:gz") as archive:
            for member_name, payload, kind in members:
                member = tarfile.TarInfo(member_name)
                member.size = len(payload)
                member.mode = 0o755 if member_name.startswith("bin/") else 0o644
                if kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "target"
                    member.size = 0
                    archive.addfile(member)
                else:
                    archive.addfile(member, io.BytesIO(payload))
        os.chmod(path, 0o600)
        return path

    def directory(self, relative: str) -> Path:
        path = self.base / relative
        path.mkdir(mode=0o700, parents=True)
        for parent in [path, *path.parents]:
            if parent == self.base.parent:
                break
            if parent.is_relative_to(self.base):
                os.chmod(parent, 0o700)
        return path

    @staticmethod
    def plugin_files() -> dict[str, bytes]:
        return {
            ".claude-plugin/plugin.json": qualifier.canonical_json_bytes(
                {"name": "cigar", "version": "0.9.0-honey.1"}
            ),
            ".mcp.json": qualifier.canonical_json_bytes(
                {
                    "mcpServers": {
                        "cigar": {
                            "command": "${CLAUDE_PLUGIN_ROOT}/bin/cigar-mcp",
                            "args": ["serve"],
                            "env": {
                                "CIGAR_CLAUDE_PLUGIN_ROOT": "${CLAUDE_PLUGIN_ROOT}",
                                "CIGAR_CLAUDE_PLUGIN_DATA": "${CLAUDE_PLUGIN_DATA}",
                            },
                        }
                    }
                }
            ),
            "compatibility.json": qualifier.canonical_json_bytes(
                {
                    "schema_version": "cigar.claude-code-compatibility.v1",
                    "context_abi": "cigar.context.v1",
                    "claude_code": {
                        "minimum_inclusive": "2.1.207",
                        "maximum_exclusive": "2.1.208",
                    },
                    "platforms": ["macos-aarch64", "macos-arm64"],
                    "public_surfaces_only": True,
                }
            ),
            "hooks/hooks.json": qualifier.canonical_json_bytes(
                qualifier._expected_hooks()
            ),
        }

    def materialize(self, root: Path, files: dict[str, bytes]) -> None:
        for relative, payload in sorted(files.items()):
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            for parent in target.parents:
                if parent == root.parent:
                    break
                os.chmod(parent, 0o700)
            qualifier._write_new(target, payload, 0o400, relative)

    def test_evidence_selection_requires_one_absolute_location(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "is required"):
                qualifier._selected_evidence_directory(self.arguments(None))
            with self.assertRaisesRegex(ReleaseError, "absolute"):
                qualifier._selected_evidence_directory(self.arguments(Path("relative")))
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "environment")},
            clear=True,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                qualifier._selected_evidence_directory(
                    self.arguments(self.base / "argument")
                )

    def test_independent_digest_authority_is_exact_lowercase_sha256(self) -> None:
        digest = "a" * 64
        self.assertEqual(qualifier._expected_sha256(digest, "archive"), digest)
        for value in (None, "A" * 64, "a" * 63, "g" * 64):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ReleaseError, "lowercase SHA-256"):
                    qualifier._expected_sha256(value, "archive")

    def test_product_authority_selects_distinct_bounded_runtime_identities(
        self,
    ) -> None:
        honey = json.loads(
            (
                qualifier.REPOSITORY_ROOT / "packaging/product-version.v1.json"
            ).read_bytes()
        )
        selected = qualifier._qualification_product(honey)
        self.assertTrue(selected.honey)
        self.assertEqual(selected.version, "0.9.0-honey.1")
        self.assertEqual(
            selected.runtime_artifact_id, qualifier.HONEY_RUNTIME_ARTIFACT_ID
        )

        development = {
            "schema_version": "cigar.product-version.v1",
            "release_state": "development",
            "channel": "development",
            "published": False,
            "supported": False,
            "version": "1.0.0-dev.1",
            "context_abi": "cigar.context.v1",
        }
        selected = qualifier._qualification_product(development)
        self.assertFalse(selected.honey)
        self.assertEqual(
            selected.runtime_artifact_id,
            qualifier.DEVELOPMENT_RUNTIME_ARTIFACT_ID,
        )

        stale_honey = {**honey, "tag": "v0.9.0-honey.2"}
        with self.assertRaisesRegex(ReleaseError, "development or Honey"):
            qualifier._qualification_product(stale_honey)

    def test_honey_runtime_plugin_pair_reaches_lifecycle_metadata_gate(self) -> None:
        product = qualifier._qualification_product(
            json.loads(
                (
                    qualifier.REPOSITORY_ROOT / "packaging/product-version.v1.json"
                ).read_bytes()
            )
        )
        source = {
            "revision": "a" * 40,
            "tree_sha256": "b" * 64,
            "committed": True,
            "clean": True,
        }

        def verification(artifact_id: str) -> dict[str, object]:
            return {
                "metadata": {
                    "artifact_id": artifact_id,
                    "product_version": product.version,
                    "context_abi": product.context_abi,
                    "source_date_epoch": 1_700_000_000,
                    "source": dict(source),
                    "input_tree_sha256": "c" * 64,
                    "input_file_count": 12,
                }
            }

        runtime, plugin = qualifier._archive_metadata_pair(
            verification(qualifier.HONEY_RUNTIME_ARTIFACT_ID),
            verification(qualifier.PLUGIN_ARTIFACT_ID),
            product,
            1_700_000_000,
        )
        self.assertEqual(runtime["artifact_id"], qualifier.HONEY_RUNTIME_ARTIFACT_ID)
        self.assertEqual(plugin["artifact_id"], qualifier.PLUGIN_ARTIFACT_ID)

        with self.assertRaisesRegex(ReleaseError, qualifier.HONEY_RUNTIME_ARTIFACT_ID):
            qualifier._archive_metadata_pair(
                verification(qualifier.DEVELOPMENT_RUNTIME_ARTIFACT_ID),
                verification(qualifier.PLUGIN_ARTIFACT_ID),
                product,
                1_700_000_000,
            )

    def test_secure_reader_rejects_symlink_hardlink_and_writable_input(self) -> None:
        safe = self.base / "safe"
        safe.write_bytes(b"payload")
        os.chmod(safe, 0o600)
        resolved, payload = qualifier._secure_regular(safe, 1024, "safe")
        self.assertEqual(resolved, safe)
        self.assertEqual(payload, b"payload")

        linked = self.base / "linked"
        linked.symlink_to(safe)
        with self.assertRaisesRegex(ReleaseError, "symbolic link"):
            qualifier._secure_regular(linked, 1024, "linked")

        hardlink = self.base / "hardlink"
        os.link(safe, hardlink)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            qualifier._secure_regular(safe, 1024, "hardlinked")

        writable = self.base / "writable"
        writable.write_bytes(b"payload")
        os.chmod(writable, 0o666)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            qualifier._secure_regular(writable, 1024, "writable")

    def test_extractor_preserves_exact_bytes_and_private_modes(self) -> None:
        archive = self.archive(
            "valid.tar.gz",
            [("bin/tool", b"executable", "file"), ("README.md", b"text\n", "file")],
        )
        destination = self.base / "out"
        files = qualifier._extract_verified(archive.read_bytes(), destination)
        self.assertEqual(files, {"bin/tool": b"executable", "README.md": b"text\n"})
        self.assertEqual(stat.S_IMODE((destination / "bin/tool").stat().st_mode), 0o500)
        self.assertEqual(
            stat.S_IMODE((destination / "README.md").stat().st_mode), 0o400
        )

    def test_extractor_rejects_links_and_unsafe_paths(self) -> None:
        linked = self.archive("linked.tar.gz", [("link", b"", "symlink")])
        with self.assertRaisesRegex(ReleaseError, "regular file"):
            qualifier._extract_verified(linked.read_bytes(), self.base / "linked-out")

        escaped = self.archive("escaped.tar.gz", [("../escape", b"bad", "file")])
        with self.assertRaises(ReleaseError):
            qualifier._extract_verified(escaped.read_bytes(), self.base / "escaped-out")
        self.assertFalse((self.base / "escape").exists())

    def test_metadata_requires_exact_artifact_and_source_binding(self) -> None:
        document = {
            "metadata": {
                "artifact_id": qualifier.PLUGIN_ARTIFACT_ID,
                "product_version": "0.9.0-honey.1",
                "context_abi": "cigar.context.v1",
                "source_date_epoch": 1_700_000_000,
                "source": {
                    "revision": "a" * 40,
                    "tree_sha256": "b" * 64,
                    "committed": True,
                    "clean": False,
                },
                "input_tree_sha256": "c" * 64,
                "input_file_count": 12,
            }
        }
        self.assertEqual(
            qualifier._metadata(
                document,
                qualifier.PLUGIN_ARTIFACT_ID,
                "0.9.0-honey.1",
                "cigar.context.v1",
                1_700_000_000,
            ),
            document["metadata"],
        )
        changed = json.loads(json.dumps(document))
        changed["metadata"]["source"]["committed"] = False
        with self.assertRaisesRegex(ReleaseError, "source-bound"):
            qualifier._metadata(
                changed,
                qualifier.PLUGIN_ARTIFACT_ID,
                "0.9.0-honey.1",
                "cigar.context.v1",
                1_700_000_000,
            )

    def test_fixture_host_protocol_is_exact_private_and_preserves_unrelated_state(
        self,
    ) -> None:
        fixture_root = self.directory("fixture")
        helpers, protocol = qualifier._stage_fixture_helpers(
            self.directory("fixture/bin")
        )
        self.assertEqual(protocol["schema_version"], qualifier.FIXTURE_PROTOCOL_SCHEMA)
        self.assertEqual(
            protocol["helper"], qualifier._identity(qualifier.FIXTURE_HELPER)
        )
        self.assertNotIn(b"/bin/bash", qualifier.FIXTURE_HELPER)
        self.assertNotIn(b"#!/bin/sh", qualifier.FIXTURE_HELPER)

        files = self.plugin_files()
        plugin = self.directory("plugin")
        self.materialize(plugin, files)
        public = qualifier._validate_plugin_authority(
            files, "0.9.0-honey.1", "cigar.context.v1"
        )
        authority_payload = qualifier.canonical_json_bytes(
            {
                "schema_version": qualifier.FIXTURE_PROTOCOL_SCHEMA,
                "claude_version": qualifier.CLAUDE_VERSION,
                "product_version": "0.9.0-honey.1",
                "context_abi": "cigar.context.v1",
                "public_files": public["public_files"],
            }
        )
        authority = qualifier._write_new(
            fixture_root / "authority.json", authority_payload, 0o400, "authority"
        )
        host_state = self.directory("host-state")
        preserved = self.directory("host-state/preserved")
        qualifier._write_new(
            preserved / "settings.json", b'{"unrelated":true}\n', 0o600, "preserved"
        )
        before_public, before = qualifier._preservation_snapshot({"host": preserved})
        environment = {
            "CIGAR_QUALIFICATION_HOST_STATE": str(host_state),
            "CIGAR_QUALIFICATION_PLUGIN_AUTHORITY": str(authority),
            "HOME": str(self.directory("home")),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }

        def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [str(helpers["claude-fixed-host"]), *arguments],
                env=environment,
                cwd=self.base,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
                check=False,
            )

        version = run("--version")
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertIn(b"2.1.207", version.stdout)
        self.assertEqual(
            run("plugin", "validate", str(plugin), "--strict").returncode, 0
        )
        marketplace = self.directory("marketplace")
        installed = self.directory("marketplace/plugins/cigar")
        self.materialize(installed, files)
        self.assertEqual(
            run("plugin", "marketplace", "add", str(marketplace)).returncode, 0
        )
        self.assertEqual(
            run("plugin", "install", "cigar@cigar-local", "--scope", "user").returncode,
            0,
        )
        self.assertNotEqual(
            run(
                "plugin", "install", "cigar@cigar-local", "--scope", "project"
            ).returncode,
            0,
        )
        self.assertEqual(
            run(
                "plugin", "uninstall", "cigar@cigar-local", "--scope", "user"
            ).returncode,
            0,
        )
        self.assertEqual(
            run("plugin", "marketplace", "remove", "cigar-local").returncode, 0
        )
        managed = json.loads((host_state / "managed.json").read_bytes())
        self.assertEqual(
            managed,
            {
                "schema_version": qualifier.FIXTURE_PROTOCOL_SCHEMA,
                "marketplace": None,
                "installed": False,
            },
        )
        after_public, after = qualifier._preservation_snapshot({"host": preserved})
        self.assertEqual(after_public, before_public)
        self.assertEqual(after, before)
        self.assertNotIn("CIGAR_QUALIFICATION_EVENT_LOG", environment)

    def test_daemon_fixture_accepts_only_two_frozen_status_argv_forms(self) -> None:
        helpers, _protocol = qualifier._stage_fixture_helpers(self.directory("helpers"))
        environment = {
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        daemon = str(helpers["cigar-fixed-daemon"])
        for arguments in [
            ["status", "--output", "json", "--deadline", "1s"],
            [
                "status",
                "--yes",
                "--non-interactive",
                "--output",
                "json",
                "--deadline",
                "2s",
            ],
        ]:
            result = subprocess.run(
                [daemon, *arguments],
                env=environment,
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        rejected = subprocess.run(
            [daemon, "status", "--output", "json"],
            env=environment,
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertNotIn("CIGAR_QUALIFICATION_EVENT_LOG", environment)

    def test_cli_envelope_rejects_non_result_output(self) -> None:
        self.assertEqual(
            qualifier._load_cli_result(b'{"result":{"installed":true}}', "cli"),
            {"installed": True},
        )
        with self.assertRaisesRegex(ReleaseError, "unexpected JSON envelope"):
            qualifier._load_cli_result(b'{"status":"ok"}', "cli")

    def test_plugin_authority_rejects_version_abi_mcp_and_hook_drift(self) -> None:
        files = self.plugin_files()
        authority = qualifier._validate_plugin_authority(
            files, "0.9.0-honey.1", "cigar.context.v1"
        )
        self.assertEqual(authority["registered_hook_count"], 18)
        self.assertEqual(authority["mcp_tool_count"], 10)
        self.assertEqual(authority["mcp_resource_family_count"], 8)
        for relative, replacement, message in [
            (
                ".claude-plugin/plugin.json",
                qualifier.canonical_json_bytes(
                    {"name": "cigar", "version": "1.0.0-dev.2"}
                ),
                "public configuration",
            ),
            (
                "compatibility.json",
                qualifier.canonical_json_bytes(
                    {
                        "schema_version": "cigar.claude-code-compatibility.v1",
                        "context_abi": "cigar.context.v2",
                        "claude_code": {
                            "minimum_inclusive": "2.1.207",
                            "maximum_exclusive": "2.1.208",
                        },
                        "platforms": ["macos-aarch64", "macos-arm64"],
                        "public_surfaces_only": True,
                    }
                ),
                "public configuration",
            ),
            (".mcp.json", b'{"mcpServers":{}}\n', "public configuration"),
            ("hooks/hooks.json", b'{"hooks":{}}\n', "public configuration"),
        ]:
            changed = {**files, relative: replacement}
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(ReleaseError, message):
                    qualifier._validate_plugin_authority(
                        changed, "0.9.0-honey.1", "cigar.context.v1"
                    )

    def test_installed_manifest_binds_exact_private_tree_and_rejects_links(
        self,
    ) -> None:
        root = self.directory("installed")
        payloads = {
            ".claude-plugin/plugin.json": b'{"name":"cigar"}\n',
            ".mcp.json": b'{"mcpServers":{}}\n',
        }
        manifest = {
            "schema_version": "cigar.claude-code-package.v1",
            "files": [
                {
                    "path": relative,
                    "sha256": qualifier.sha256_bytes(payload),
                    "bytes": len(payload),
                }
                for relative, payload in sorted(payloads.items())
            ],
        }
        self.materialize(
            root,
            {
                **payloads,
                "package-manifest.json": qualifier.canonical_json_bytes(manifest),
            },
        )
        identity, observed = qualifier._installed_manifest_identity(root)
        self.assertEqual(identity["manifest_entry_count"], 2)
        self.assertEqual(set(observed), {*payloads, "package-manifest.json"})

        extra = root / "extra"
        qualifier._write_new(extra, b"unexpected\n", 0o400, "extra")
        with self.assertRaisesRegex(ReleaseError, "exact staged tree"):
            qualifier._installed_manifest_identity(root)

        extra.unlink()
        hardlink = root / "hardlink"
        os.link(root / ".mcp.json", hardlink)
        with self.assertRaisesRegex(ReleaseError, "hard-linked"):
            qualifier._installed_manifest_identity(root)

    def test_partial_and_malformed_private_plugin_clones_attempt_self_authorization(
        self,
    ) -> None:
        source = self.directory("source")
        files = {
            "package-manifest.json": b'{"schema_version":"fixture"}\n',
            "hooks/hooks.json": b'{"hooks":{}}\n',
            ".mcp.json": b'{"mcpServers":{}}\n',
        }
        self.materialize(source, files)
        partial = qualifier._clone_plugin_source(
            self.base / "partial",
            files,
            omitted={"hooks/hooks.json"},
            rewrite_manifest=True,
        )
        malformed = qualifier._clone_plugin_source(
            self.base / "malformed",
            files,
            replacements={".mcp.json": b'{"mcpServers":'},
            rewrite_manifest=True,
        )
        self.assertFalse((partial / "hooks/hooks.json").exists())
        self.assertEqual((malformed / ".mcp.json").read_bytes(), b'{"mcpServers":')
        for root in (partial, malformed):
            identity, payloads = qualifier._installed_manifest_identity(root)
            self.assertEqual(identity["manifest_entry_count"], len(payloads) - 1)
            self.assertNotEqual(
                payloads["package-manifest.json"], files["package-manifest.json"]
            )
            public, _records, _payloads = qualifier._tree_snapshot(
                root, "hostile clone"
            )
            self.assertGreater(public["file_count"], 0)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_preservation_snapshot_detects_content_mode_link_and_path_changes(
        self,
    ) -> None:
        root = self.directory("preserved")
        path = qualifier._write_new(root / "config", b"exact\n", 0o600, "config")
        public, details = qualifier._preservation_snapshot({"config": root})
        same_public, same_details = qualifier._preservation_snapshot({"config": root})
        self.assertEqual(same_public, public)
        self.assertEqual(same_details, details)

        os.chmod(path, 0o400)
        changed_public, changed_details = qualifier._preservation_snapshot(
            {"config": root}
        )
        self.assertNotEqual(changed_public, public)
        self.assertNotEqual(changed_details, details)

        os.chmod(path, 0o600)
        hardlink = root / "alias"
        os.link(path, hardlink)
        with self.assertRaisesRegex(ReleaseError, "hard-linked"):
            qualifier._preservation_snapshot({"config": root})

    def test_thin_arm64_macho_identity_rejects_scripts_fat_and_wrong_cpu(self) -> None:
        valid = (
            struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
            + b"payload"
        )
        qualifier._require_thin_arm64_macho(valid, "valid")
        for payload in [
            b"#!/bin/sh\n",
            struct.pack(">I", 0xCAFEBABE) + b"x" * 40,
            struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 0, 2, 0, 0, 0, 0),
        ]:
            with self.assertRaisesRegex(ReleaseError, "thin arm64"):
                qualifier._require_thin_arm64_macho(payload, "invalid")

    def test_bounded_runner_always_wraps_sandbox_without_a_shell_and_checks_canaries(
        self,
    ) -> None:
        tool = qualifier._write_new(
            self.base / "tool", b"#!/bin/sh\nexit 0\n", 0o500, "tool"
        )
        identity = qualifier._identity(tool.read_bytes())
        environment = {
            "HOME": str(self.base),
            "CIGAR_HOME": str(self.base),
            "CIGAR_QUALIFICATION_MARKETPLACE_ROOT": str(
                self.base / "claude-code/marketplace-test"
            ),
            "TMPDIR": str(self.base),
            "CIGAR_QUALIFICATION_HOST_STATE": str(self.base),
            "CIGAR_QUALIFICATION_EXECUTION_IDENTITIES": json.dumps(
                {str(tool): identity}
            ),
        }
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"ok\n", stderr=b""
        )
        with mock.patch.object(
            qualifier, "run_bounded", return_value=completed
        ) as bounded:
            result = qualifier._run(
                [str(tool), "arg"],
                cwd=self.base,
                environment=environment,
                label="tool",
                input_payload=b"input",
                forbidden_output=(b"canary",),
            )
        self.assertEqual(result, b"ok\n")
        invocation = bounded.call_args.args[0]
        self.assertEqual(invocation[:2], ["/usr/bin/sandbox-exec", "-p"])
        self.assertEqual(invocation[-2:], [str(tool), "arg"])
        policy = invocation[2]
        self.assertIn("(deny default)", policy)
        self.assertNotIn("(allow default)", policy)
        self.assertIn(f'(literal "{tool}")', policy)
        self.assertNotIn("{32}", policy)
        self.assertIn("cigar-plugin-validation-" + "[0-9a-f]" * 32, policy)
        self.assertIn(
            str(self.base / "claude-code/marketplace-test/plugins/cigar/bin/cigar-mcp"),
            policy,
        )
        self.assertNotIn("network", policy)
        self.assertEqual(bounded.call_args.kwargs["input_payload"], b"input")

        leaked = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"secret-canary", stderr=b""
        )
        with mock.patch.object(qualifier, "run_bounded", return_value=leaked):
            with self.assertRaisesRegex(ReleaseError, "content canary"):
                qualifier._run(
                    [str(tool)],
                    cwd=self.base,
                    environment=environment,
                    label="leak",
                    forbidden_output=(b"secret-canary",),
                )

    def test_expected_failure_requires_an_ordinary_nonzero_exit(self) -> None:
        tool = qualifier._write_new(
            self.base / "negative-tool", b"#!/bin/sh\nexit 2\n", 0o500, "tool"
        )
        environment = {
            "HOME": str(self.base),
            "CIGAR_HOME": str(self.base),
            "CIGAR_QUALIFICATION_MARKETPLACE_ROOT": str(
                self.base / "claude-code/marketplace-test"
            ),
            "TMPDIR": str(self.base),
            "CIGAR_QUALIFICATION_HOST_STATE": str(self.base),
            "CIGAR_QUALIFICATION_EXECUTION_IDENTITIES": json.dumps(
                {str(tool): qualifier._identity(tool.read_bytes())}
            ),
        }
        for returncode, accepted in [(2, True), (0, False), (-9, False)]:
            completed = subprocess.CompletedProcess(
                args=[], returncode=returncode, stdout=b"", stderr=b""
            )
            with self.subTest(returncode=returncode):
                with mock.patch.object(
                    qualifier, "run_bounded", return_value=completed
                ):
                    if accepted:
                        self.assertEqual(
                            qualifier._run_failure(
                                [str(tool)],
                                cwd=self.base,
                                environment=environment,
                                label="negative",
                            ),
                            b"",
                        )
                    else:
                        with self.assertRaises(ReleaseError):
                            qualifier._run_failure(
                                [str(tool)],
                                cwd=self.base,
                                environment=environment,
                                label="negative",
                            )

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS Seatbelt")
    def test_deny_default_seatbelt_blocks_provider_read_external_write_and_network(
        self,
    ) -> None:
        workspace = self.directory("seatbelt/workspace")
        home = self.directory("seatbelt/home")
        cigar_home = self.directory("seatbelt/cigar")
        temporary = self.directory("seatbelt/tmp")
        host_state = self.directory("seatbelt/host")
        provider = self.directory("seatbelt/provider") / "canary"
        provider.write_bytes(b"provider secret\n")
        outside = self.base / "seatbelt/outside-write"
        environment = {
            "HOME": str(home),
            "CIGAR_HOME": str(cigar_home),
            "CIGAR_QUALIFICATION_MARKETPLACE_ROOT": str(
                cigar_home / "claude-code/marketplace-test"
            ),
            "TMPDIR": str(temporary),
            "CIGAR_QUALIFICATION_HOST_STATE": str(host_state),
            "PROVIDER_CANARY": str(provider),
            "OUTSIDE_WRITE": str(outside),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        script = """
import os
import socket
import sys
denied = 0
try:
    open(os.environ["PROVIDER_CANARY"], "rb").read()
except PermissionError:
    denied += 1
try:
    open(os.environ["OUTSIDE_WRITE"], "wb").write(b"unexpected")
except PermissionError:
    denied += 1
probe = socket.socket()
try:
    probe.bind(("127.0.0.1", 0))
except PermissionError:
    denied += 1
sys.exit(0 if denied == 3 else 9)
"""
        command = [str(qualifier.SYSTEM_PYTHON), "-c", script]
        policy = qualifier._sandbox_policy(command, workspace, environment)
        result = subprocess.run(
            [str(qualifier.MACOS_SANDBOX_EXEC), "-p", policy, *command],
            cwd=workspace,
            env=environment,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(outside.exists())

    def test_qualifier_source_has_no_shell_or_workspace_test_execution(self) -> None:
        source = Path(qualifier.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"/bin/bash"', source)
        self.assertNotIn("run-fixture-demo.sh", source)
        self.assertNotIn("public-surface-smoke.sh", source)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
