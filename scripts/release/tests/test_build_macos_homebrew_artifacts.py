#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_macos_aarch64_archive as native  # noqa: E402
import build_macos_homebrew_artifacts as homebrew  # noqa: E402
import verify_macos_homebrew_artifacts as verifier  # noqa: E402
from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure evidence workspaces require POSIX")
class MacosHomebrewArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-homebrew-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.root = homebrew.REPOSITORY_ROOT
        self.epoch = 1_700_000_000
        self.source = {
            "revision": "a" * 40,
            "tree_sha256": "b" * 64,
            "committed": True,
            "clean": False,
        }

    @staticmethod
    def _host() -> dict[str, str]:
        return {
            "platform": "macos",
            "architecture": "arm64",
            "target_triple": homebrew.TARGET_TRIPLE,
            "macos_version": "15.6",
        }

    def test_independent_verifier_publishes_create_new_external_report(self) -> None:
        evidence = self.base / "verification-evidence"
        arguments = argparse.Namespace(
            evidence_dir=evidence,
            report=Path("homebrew/result.json"),
            root=self.root,
        )
        result = {"schema_version": verifier.VERIFICATION_SCHEMA, "status": "pass"}
        verifier._publish_report(arguments, result)
        report = evidence / "homebrew/result.json"
        self.assertEqual(report.read_bytes(), canonical_json_bytes(result))
        self.assertEqual(report.stat().st_mode & 0o777, 0o400)
        with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
            verifier._publish_report(arguments, result)

    @staticmethod
    def _macho(marker: bytes) -> bytes:
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

    def _runtime(
        self,
        configuration: native.BuildConfiguration,
        source: dict[str, object],
        _epoch: int,
        _scratch: Path,
        _arguments: argparse.Namespace,
    ) -> native.BuiltRuntime:
        version = {
            "version": configuration.version,
            "source_revision": source["revision"],
            "context_abi": configuration.context_abi,
            "protocol_min": "1.0",
            "protocol_max": "1.x",
            "build_profile": "release",
            "enabled_features": [],
        }
        return native.BuiltRuntime(
            cigar=self._macho(b"cigar-homebrew-test"),
            cigard=self._macho(b"cigard-homebrew-test"),
            cigar_mcp=self._macho(b"cigar-mcp-homebrew-test"),
            cigar_claude_hook=self._macho(b"cigar-claude-hook-homebrew-test"),
            cigar_version=dict(version),
            cigard_version=dict(version),
            cigar_mcp_probe={
                "status": "ok",
                "protocol_version": "2025-06-18",
                "build": dict(version),
            },
            cigar_claude_hook_probe={
                "schema_version": "cigar.claude-hook-event.v1",
                "ok": True,
                "maximum_input_bytes": 65_536,
                "model_calls": 0,
                "effect_precheck": "fail_closed",
            },
            generated_assets={
                path: configuration.assets[path]
                for path in (
                    "share/man/man1/cigar.1",
                    "completions/cigar.bash",
                    "completions/_cigar",
                    "completions/cigar.fish",
                )
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

    def _native_inputs(self) -> tuple[Path, Path]:
        output = self.base / "native"
        arguments = argparse.Namespace(
            root=self.root,
            evidence_dir=output,
            source_date_epoch=str(self.epoch),
            cargo=None,
            rustc=None,
            protoc=None,
        )
        with (
            mock.patch.object(native, "_require_host", return_value=self._host()),
            mock.patch.object(native, "_source_identity", return_value=self.source),
        ):
            native.produce(arguments, runtime_builder=self._runtime)
        return (
            output / "cigar-1.0.0-dev.1-aarch64-apple-darwin.tar.gz",
            output / native.BUILD_RECEIPT,
        )

    def _arguments(
        self, output: Path, native_archive: Path, native_receipt: Path
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.root,
            native_archive=native_archive,
            native_build_receipt=native_receipt,
            evidence_dir=output,
            source_date_epoch=str(self.epoch),
        )

    def _produce(
        self, output: Path, native_archive: Path, native_receipt: Path
    ) -> dict[str, object]:
        with mock.patch.object(homebrew, "_require_host", return_value=self._host()):
            return homebrew.produce(
                self._arguments(output, native_archive, native_receipt)
            )

    def _verify(
        self, output: Path, native_archive: Path, native_receipt: Path
    ) -> dict[str, object]:
        return verifier.verify(
            self.root,
            native_archive,
            native_receipt,
            output / "cigar--1.0.0-dev.1.arm64_sequoia.bottle.tar.gz",
            output / "cigar-1.0.0-dev.1-homebrew-tap.tar.gz",
            output / homebrew.BUILD_RECEIPT,
            self.epoch,
        )

    def test_configuration_is_exact_and_remains_unclaimed(self) -> None:
        configuration = homebrew._load_configuration(self.root)
        self.assertEqual(configuration.version, "1.0.0-dev.1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(
            configuration.bottle_filename,
            "cigar--1.0.0-dev.1.arm64_sequoia.bottle.tar.gz",
        )
        self.assertEqual(
            configuration.tap_filename,
            "cigar-1.0.0-dev.1-homebrew-tap.tar.gz",
        )
        profile = json.loads(
            (
                self.root / "packaging/development/local-macos-aarch64.v1.json"
            ).read_bytes()
        )
        selected = {row["id"]: row for row in profile["selected_artifacts"]}
        for identifier in (
            homebrew.FORMULA_ARTIFACT_ID,
            homebrew.BOTTLE_ARTIFACT_ID,
        ):
            self.assertFalse(selected[identifier]["built"])
            self.assertFalse(selected[identifier]["qualified"])
        self.assertFalse(profile["published"])
        self.assertFalse(profile["supported"])
        self.assertLessEqual(
            {
                "adapters/claude-code/package-manifest.json",
                "packaging/local-archives.v1.json",
                "scripts/release/build_macos_aarch64_archive.py",
                "scripts/release/build_macos_homebrew_artifacts.py",
                "scripts/release/verify_macos_homebrew_artifacts.py",
                "scripts/release/evidence_workspace.py",
                "scripts/release/release_lib.py",
                "scripts/release/verify_package.py",
            },
            set(homebrew.AUTHORITY_PATHS),
        )
        self.assertLessEqual(set(native.AUTHORITY_PATHS), set(homebrew.AUTHORITY_PATHS))

    def test_pair_is_deterministic_contract_valid_and_digest_bound(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        first_root = self.base / "first"
        second_root = self.base / "second"
        first = self._produce(first_root, native_archive, native_receipt)
        second = self._produce(second_root, native_archive, native_receipt)

        bottle_name = "cigar--1.0.0-dev.1.arm64_sequoia.bottle.tar.gz"
        tap_name = "cigar-1.0.0-dev.1-homebrew-tap.tar.gz"
        self.assertEqual(
            (first_root / bottle_name).read_bytes(),
            (second_root / bottle_name).read_bytes(),
        )
        self.assertEqual(
            (first_root / tap_name).read_bytes(),
            (second_root / tap_name).read_bytes(),
        )
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "built-unqualified")
        self.assertEqual(
            first["claims"],
            {
                "development_build": True,
                "release_built": False,
                "distribution_signed": False,
                "notarized": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        )
        self.assertEqual(
            first["external_requirements"],
            {
                "native_code_signing": "not-evidenced",
                "notarization": "not-evidenced",
                "artifact_signatures": "not-evidenced",
                "installed_byte_qualification": "not-evidenced",
                "homebrew_publication": "not-performed",
            },
        )
        self.assertEqual(
            set(first["input_native_archive"]["runtime_payload"]),
            {"cigar", "cigard", "cigar-mcp", "cigar-claude-hook"},
        )
        self.assertEqual(
            first["bottle_binding"]["installed_runtime_members"],
            [
                "bin/cigar",
                "bin/cigard",
                "bin/cigar-mcp",
                "bin/cigar-claude-hook",
            ],
        )
        self.assertEqual(stat.S_IMODE(first_root.stat().st_mode), 0o700)
        self.assertTrue(
            all(
                stat.S_IMODE(path.stat().st_mode) == 0o400
                for path in first_root.iterdir()
            )
        )

        with tarfile.open(first_root / bottle_name, "r:gz") as bottle:
            members = {member.name: member for member in bottle.getmembers()}
            prefix = "cigar/1.0.0-dev.1"
            self.assertEqual(
                set(members),
                {
                    f"{prefix}/.brew/cigar.rb",
                    f"{prefix}/INSTALL_RECEIPT.json",
                    f"{prefix}/bin/cigar",
                    f"{prefix}/bin/cigard",
                    f"{prefix}/bin/cigar-mcp",
                    f"{prefix}/bin/cigar-claude-hook",
                    f"{prefix}/etc/bash_completion.d/cigar",
                    f"{prefix}/share/doc/cigar/LICENSE",
                    f"{prefix}/share/doc/cigar/NOTICE",
                    f"{prefix}/sbom.spdx.json",
                    f"{prefix}/share/fish/vendor_completions.d/cigar.fish",
                    f"{prefix}/share/man/man1/cigar.1",
                    f"{prefix}/share/zsh/site-functions/_cigar",
                },
            )
            self.assertTrue(
                all(
                    member.isfile()
                    and member.uid == 0
                    and member.gid == 0
                    and member.mtime == self.epoch
                    for member in members.values()
                )
            )
            embedded_handle = bottle.extractfile(f"{prefix}/.brew/cigar.rb")
            receipt_handle = bottle.extractfile(f"{prefix}/INSTALL_RECEIPT.json")
            sbom_handle = bottle.extractfile(f"{prefix}/sbom.spdx.json")
            self.assertIsNotNone(embedded_handle)
            self.assertIsNotNone(receipt_handle)
            self.assertIsNotNone(sbom_handle)
            assert embedded_handle is not None
            embedded_formula = embedded_handle.read()
            self.assertNotIn(b"bottle do", embedded_formula)
            self.assertFalse(
                any(name.endswith(native_archive.name) for name in members)
            )
            assert receipt_handle is not None and sbom_handle is not None
            install_receipt = json.loads(receipt_handle.read())
            sbom = json.loads(sbom_handle.read())
            self.assertTrue(install_receipt["built_as_bottle"])
            self.assertFalse(install_receipt["poured_from_bottle"])
            self.assertFalse(install_receipt["loaded_from_api"])
            self.assertEqual(install_receipt["arch"], "arm64")
            self.assertEqual(
                install_receipt["source"]["versions"]["stable"], "1.0.0-dev.1"
            )
            self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
            self.assertEqual(sbom["documentDescribes"], ["SPDXRef-Archive-cigar-src"])
            self.assertEqual(
                sbom["packages"][0]["checksums"][0]["checksumValue"],
                first["input_native_archive"]["sha256"],
            )
            self.assertEqual(members[f"{prefix}/bin/cigar-mcp"].mode, 0o755)
            self.assertEqual(members[f"{prefix}/bin/cigar-claude-hook"].mode, 0o755)

        with tarfile.open(first_root / tap_name, "r:gz") as tap:
            formula_handle = tap.extractfile("Formula/cigar.rb")
            metadata_handle = tap.extractfile("HOMEBREW-TAP-METADATA.json")
            self.assertIsNotNone(formula_handle)
            self.assertIsNotNone(metadata_handle)
            assert formula_handle is not None and metadata_handle is not None
            formula = formula_handle.read()
            metadata = json.loads(metadata_handle.read())
        bottle_record = next(
            row
            for row in first["artifacts"]
            if row["artifact_id"] == homebrew.BOTTLE_ARTIFACT_ID
        )
        bottle_digest = bottle_record["sha256"]
        self.assertEqual(metadata["bottle"]["sha256"], bottle_digest)
        self.assertEqual(metadata["bottle"]["tag"], "arm64_sequoia")
        self.assertEqual(metadata["bottle"]["rebuild"], 0)
        self.assertEqual(
            metadata["source_archive"]["runtime_members"],
            [
                "bin/cigar",
                "bin/cigard",
                "bin/cigar-mcp",
                "bin/cigar-claude-hook",
            ],
        )
        self.assertIn(f'arm64_sequoia: "{bottle_digest}"'.encode(), formula)
        self.assertIn(b"cellar: :any_skip_relocation", formula)
        self.assertIn(b"downloads.cigar.invalid/development", formula)
        self.assertIn(b'"bin/cigar-mcp"', formula)
        self.assertIn(b'"bin/cigar-claude-hook"', formula)
        self.assertIn(b"cigar-mcp schema-noop", formula)
        self.assertIn(b"cigar-claude-hook schema-noop", formula)
        self.assertNotIn(b"http://", formula)

        ruby = shutil.which("ruby")
        if ruby is not None:
            syntax = subprocess.run(
                [ruby, "-c"],
                input=formula,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=10,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stdout.decode())

        brew = shutil.which("brew")
        if brew is not None:
            environment = dict(os.environ)
            environment.update(
                {
                    "HOMEBREW_NO_AUTO_UPDATE": "1",
                    "HOMEBREW_NO_INSTALL_FROM_API": "1",
                }
            )
            parser = subprocess.run(
                [
                    brew,
                    "ruby",
                    "-e",
                    (
                        'require "utils/bottles"; '
                        "bottle=Pathname(ARGV.fetch(0)); "
                        "receipt=Utils::Bottles.receipt_path(bottle); "
                        'raise "missing receipt" unless receipt; '
                        "tab=Tab.from_file_content("
                        "Utils::Bottles.file_from_bottle(bottle, receipt), receipt); "
                        'raise "wrong arch" unless tab.arch.to_s == "arm64"; '
                        'raise "not bottle" unless tab.built_as_bottle; '
                        'raise "wrong version" unless '
                        "Utils::Bottles.resolve_version(bottle).to_s == "
                        '"1.0.0-dev.1"; '
                        "Utils::Bottles.formula_contents(bottle)"
                    ),
                    str(first_root / bottle_name),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=30,
            )
            self.assertEqual(parser.returncode, 0, parser.stdout.decode())

    def test_independent_verifier_reconstructs_the_exact_unqualified_pair(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        output = self.base / "verified-output"
        produced = self._produce(output, native_archive, native_receipt)

        report = self._verify(output, native_archive, native_receipt)

        self.assertEqual(
            report["schema_version"],
            "cigar.development-homebrew-verification.v1",
        )
        self.assertEqual(report["status"], "verified-built-unqualified")
        self.assertEqual(report["source"], self.source)
        self.assertEqual(report["artifacts"], produced["artifacts"])
        self.assertEqual(report["claims"], produced["claims"])
        self.assertFalse(report["claims"]["qualified"])
        self.assertFalse(report["claims"]["release"])

    def test_verifier_rejects_same_length_bottle_mutation(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        output = self.base / "mutated-bottle-output"
        self._produce(output, native_archive, native_receipt)
        bottle = output / "cigar--1.0.0-dev.1.arm64_sequoia.bottle.tar.gz"
        payload = bytearray(bottle.read_bytes())
        payload[-1] ^= 1
        os.chmod(bottle, 0o600)
        bottle.write_bytes(payload)
        os.chmod(bottle, 0o400)

        with self.assertRaises(ReleaseError):
            self._verify(output, native_archive, native_receipt)

    def test_pinned_sequoia_host_is_required_before_production_and_verification(
        self,
    ) -> None:
        native_archive, native_receipt = self._native_inputs()
        rejected = self.base / "wrong-host-output"
        wrong_host = {
            "platform": "macos",
            "architecture": "arm64",
            "target_triple": homebrew.TARGET_TRIPLE,
            "macos_version": "16.0",
        }
        with (
            mock.patch.object(homebrew, "_require_host", return_value=wrong_host),
            self.assertRaisesRegex(ReleaseError, "pinned Apple-silicon macOS 15.6"),
        ):
            homebrew.produce(self._arguments(rejected, native_archive, native_receipt))
        self.assertFalse(rejected.exists())

        output = self.base / "wrong-host-receipt-output"
        self._produce(output, native_archive, native_receipt)
        receipt = output / homebrew.BUILD_RECEIPT
        document = json.loads(receipt.read_bytes())
        document["host"] = wrong_host
        os.chmod(receipt, 0o600)
        receipt.write_bytes(canonical_json_bytes(document))
        os.chmod(receipt, 0o400)
        with self.assertRaisesRegex(ReleaseError, "pinned Apple-silicon macOS 15.6"):
            self._verify(output, native_archive, native_receipt)

        document["host"] = self._host()
        document["claims"]["qualified"] = True
        os.chmod(receipt, 0o600)
        receipt.write_bytes(canonical_json_bytes(document))
        os.chmod(receipt, 0o400)
        with self.assertRaisesRegex(ReleaseError, "overclaims"):
            self._verify(output, native_archive, native_receipt)

    def test_overclaiming_native_receipt_is_rejected_before_output(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        document = json.loads(native_receipt.read_bytes())
        document["claims"]["distribution_signed"] = True
        replacement_root = self.base / "overclaim-input"
        replacement_root.mkdir(mode=0o700)
        replacement = replacement_root / native.BUILD_RECEIPT
        replacement.write_bytes(canonical_json_bytes(document))
        os.chmod(replacement, 0o600)
        output = self.base / "overclaim-output"
        arguments = self._arguments(output, native_archive, replacement)
        with (
            mock.patch.object(homebrew, "_require_host", return_value=self._host()),
            self.assertRaisesRegex(ReleaseError, "stale or overclaims"),
        ):
            homebrew.produce(arguments)
        self.assertFalse(output.exists())

    def test_narrow_beta_native_receipt_is_rejected_before_output(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        document = json.loads(native_receipt.read_bytes())
        document["runtime_profile"] = "cigar.beta.embedded-local.v1"
        replacement_root = self.base / "beta-profile-input"
        replacement_root.mkdir(mode=0o700)
        replacement = replacement_root / native.BUILD_RECEIPT
        replacement.write_bytes(canonical_json_bytes(document))
        os.chmod(replacement, 0o600)
        output = self.base / "beta-profile-output"
        with (
            mock.patch.object(homebrew, "_require_host", return_value=self._host()),
            self.assertRaisesRegex(ReleaseError, "stale or overclaims"),
        ):
            homebrew.produce(self._arguments(output, native_archive, replacement))
        self.assertFalse(output.exists())

    def test_stale_native_authority_receipt_is_rejected_before_output(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        document = json.loads(native_receipt.read_bytes())
        authority_path = "packaging/product-version.v1.json"
        document["authority"][authority_path]["sha256"] = "0" * 64
        replacement_root = self.base / "stale-authority-input"
        replacement_root.mkdir(mode=0o700)
        replacement = replacement_root / native.BUILD_RECEIPT
        replacement.write_bytes(canonical_json_bytes(document))
        os.chmod(replacement, 0o600)
        output = self.base / "stale-authority-output"
        with (
            mock.patch.object(homebrew, "_require_host", return_value=self._host()),
            self.assertRaisesRegex(ReleaseError, "stale or overclaims"),
        ):
            homebrew.produce(self._arguments(output, native_archive, replacement))
        self.assertFalse(output.exists())

    def test_same_length_prepublication_mutation_publishes_nothing(self) -> None:
        native_archive, native_receipt = self._native_inputs()
        output = self.base / "mutation-output"
        original = EvidenceWorkspace.attach_file

        def mutate_then_attach(
            workspace: EvidenceWorkspace,
            source: Path,
            relative: str,
            *,
            read_only: bool = True,
            expected_sha256: str | None = None,
            expected_bytes: int | None = None,
        ):
            if relative.endswith(".bottle.tar.gz"):
                payload = bytearray(source.read_bytes())
                payload[-1] ^= 1
                source.write_bytes(payload)
                os.chmod(source, 0o600)
            return original(
                workspace,
                source,
                relative,
                read_only=read_only,
                expected_sha256=expected_sha256,
                expected_bytes=expected_bytes,
            )

        with (
            mock.patch.object(homebrew, "_require_host", return_value=self._host()),
            mock.patch.object(EvidenceWorkspace, "attach_file", new=mutate_then_attach),
            self.assertRaisesRegex(
                EvidenceWorkspaceError,
                "SHA-256 differs from validated content",
            ),
        ):
            homebrew.produce(self._arguments(output, native_archive, native_receipt))
        self.assertTrue(output.is_dir())
        self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
