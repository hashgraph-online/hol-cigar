#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_go_sdk as builder  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


HONEY_SELECTED = (
    json.loads(
        (builder.REPOSITORY_ROOT / "packaging/product-version.v1.json").read_text(
            encoding="utf-8"
        )
    ).get("channel")
    == "honey"
)


@unittest.skipIf(HONEY_SELECTED, "Go SDK is explicitly deferred by the Honey profile")
@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class GoSdkBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-go-sdk-builder-")
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
            go=None,
            dependency_proxy=None,
        )

    @staticmethod
    def validation(*, module_version: str = "v1.0.0-dev.1") -> dict[str, object]:
        return {
            "schema_version": "cigar.go-sdk-build-validation.v1",
            "status": "passed",
            "offline": True,
            "fresh_module_cache": True,
            "module_path": builder.MODULE_PATH,
            "module_version": module_version,
            "module_sum": "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "go_mod_sum": "h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "packages": list(builder.EXPECTED_PACKAGES),
            "checks": {
                "go-mod-download": "passed",
                "go-mod-verify": "passed",
                "go-list": "passed",
                "go-vet": "passed",
                "go-test": "passed",
                "semantic-bundle": "passed",
            },
            "semantic_bundle_identity": builder.EXPECTED_QUICKSTART_IDENTITY,
            "tool": {
                "name": "go",
                "version": "go version go1.26.6 darwin/arm64",
                "sha256": "c" * 64,
                "bytes": 1,
            },
        }

    @classmethod
    def fake_validator(
        cls,
        _configuration: builder.BuildConfiguration,
        _archive: Path,
        _epoch: int,
        scratch: Path,
        _arguments: argparse.Namespace,
    ) -> dict[str, object]:
        if stat.S_IMODE(scratch.stat().st_mode) != 0o700:
            raise AssertionError("Go SDK scratch workspace is not owner-only")
        return cls.validation()

    def produce(
        self,
        evidence: Path,
        validator: builder.GoValidator | None = None,
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
                go_validator=validator or self.fake_validator,
            )

    def test_configuration_binds_exact_authorities_contract_and_module(self) -> None:
        configuration = builder._load_configuration(self.root)
        self.assertEqual(configuration.product_version, "1.0.0-dev.1")
        self.assertEqual(configuration.module_version, "v1.0.0-dev.1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(configuration.module_path, builder.MODULE_PATH)
        self.assertEqual(
            configuration.module_prefix,
            "github.com/CIGAR/cigar/sdk/go@v1.0.0-dev.1/",
        )
        self.assertEqual(configuration.filename, "cigar-go-sdk-1.0.0-dev.1.zip")
        self.assertEqual(set(configuration.authority), set(builder.AUTHORITY_PATHS))
        self.assertEqual(set(configuration.assets), set(builder.SOURCE_RELEASE_PATHS))
        release = json.loads(configuration.assets["release.json"])
        self.assertEqual(release["name"], builder.MODULE_PATH)
        self.assertEqual(release["version"], "1.0.0-dev.1")
        self.assertEqual(release["context_abi"], "cigar.context.v1")

    def test_fake_build_is_deterministic_contract_valid_and_unclaimed(self) -> None:
        first_root = self.base / "first"
        second_root = self.base / "second"
        first = self.produce(first_root)
        second = self.produce(second_root)

        filename = "cigar-go-sdk-1.0.0-dev.1.zip"
        first_archive = first_root / filename
        second_archive = second_root / filename
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first["archive"], second["archive"])
        self.assertEqual(first["status"], "built-unqualified")
        self.assertEqual(first["payload_file_count"], len(builder.SOURCE_RELEASE_PATHS))
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
        receipt_path = first_root / builder.BUILD_RECEIPT
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o400)
        self.assertEqual(json.loads(receipt_path.read_bytes()), first)

        with zipfile.ZipFile(first_archive) as archive:
            members = archive.infolist()
            expected = {
                f"github.com/CIGAR/cigar/sdk/go@v1.0.0-dev.1/{relative}"
                for relative in builder.SOURCE_RELEASE_PATHS
            }
            self.assertEqual({member.filename for member in members}, expected)
            self.assertFalse(any(member.is_dir() for member in members))
            self.assertFalse(any("!c!i!g!a!r" in member.filename for member in members))
            expected_time = time.gmtime(1_700_000_000)[:6]
            self.assertTrue(
                all(member.date_time == expected_time for member in members)
            )
            self.assertTrue(
                all(
                    (member.external_attr >> 16) & 0o7777 == 0o644 for member in members
                )
            )
            release = json.loads(
                archive.read("github.com/CIGAR/cigar/sdk/go@v1.0.0-dev.1/release.json")
            )
            self.assertEqual(release["version"], "1.0.0-dev.1")
        self.assertEqual(first["package_verification"]["status"], "passed")
        self.assertEqual(first["go_validation"]["offline"], True)
        self.assertEqual(first["go_validation"]["fresh_module_cache"], True)

    def test_go_proxy_escaping_is_separate_from_archive_prefix(self) -> None:
        self.assertEqual(
            builder._escape_proxy_path(builder.MODULE_PATH),
            "github.com/!c!i!g!a!r/cigar/sdk/go",
        )
        configuration = builder._load_configuration(self.root)
        self.assertEqual(
            configuration.module_prefix,
            f"{builder.MODULE_PATH}@{configuration.module_version}/",
        )

    def test_default_validator_round_trips_through_fresh_offline_cache(self) -> None:
        configuration = builder._load_configuration(self.root)
        scratch = self.base / "real-validator"
        scratch.mkdir(mode=0o700)
        archive = scratch / configuration.filename
        builder._write_archive(
            archive,
            builder._package_entries(configuration),
            1_700_000_000,
        )
        try:
            result = builder._default_go_validator(
                configuration,
                archive,
                1_700_000_000,
                scratch,
                self.arguments(None),
            )
        except ReleaseError as error:
            self.assertRegex(str(error), r"requires Go >=1\.26\.5")
            return
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["packages"], list(builder.EXPECTED_PACKAGES))
        self.assertTrue(result["offline"])
        self.assertTrue(result["fresh_module_cache"])
        self.assertEqual(
            result["semantic_bundle_identity"],
            builder.EXPECTED_QUICKSTART_IDENTITY,
        )
        self.assertRegex(str(result["module_sum"]), r"^h1:[A-Za-z0-9+/=]+$")

    def test_source_and_validation_changes_fail_closed(self) -> None:
        changed = {**self.source, "tree_sha256": "e" * 64}
        evidence = self.base / "changed"
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(
                evidence,
                source_side_effect=[self.source, changed],
            )
        self.assertEqual(list(evidence.iterdir()), [])

        def wrong_version(
            _configuration: builder.BuildConfiguration,
            _archive: Path,
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> dict[str, object]:
            return self.validation(module_version="v1.0.0-other.1")

        wrong = self.base / "wrong-version"
        with self.assertRaisesRegex(ReleaseError, "different module version"):
            self.produce(wrong, wrong_version)
        self.assertEqual(list(wrong.iterdir()), [])

    def test_same_length_substitution_after_validation_cannot_publish(self) -> None:
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

    def test_validator_archive_mutation_is_detected_before_publication(self) -> None:
        def mutating_validator(
            _configuration: builder.BuildConfiguration,
            archive: Path,
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> dict[str, object]:
            payload = bytearray(archive.read_bytes())
            payload[len(payload) // 2] ^= 1
            archive.write_bytes(payload)
            return self.validation()

        evidence = self.base / "validator-mutation"
        with self.assertRaisesRegex(ReleaseError, "changed during verification"):
            self.produce(evidence, mutating_validator)
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
        attempted = mock.Mock(side_effect=AssertionError("validator must not run"))
        with self.assertRaisesRegex(EvidenceWorkspaceError, "inventory mismatch"):
            self.produce(evidence, attempted)
        attempted.assert_not_called()

    def test_external_workspace_and_stable_input_guards(self) -> None:
        internal = self.root / "reports" / "go-sdk-development"
        with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
            self.produce(internal)
        self.assertFalse(internal.exists())

        target = self.base / "target"
        target.mkdir(mode=0o700)
        linked = self.base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(EvidenceWorkspaceError):
            self.produce(linked)

        writable = self.base / "writable"
        writable.write_bytes(b"payload")
        os.chmod(writable, 0o666)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            builder._read_stable_file(writable, 1024, "writable input")

        safe = self.base / "safe"
        safe.write_bytes(b"payload")
        os.chmod(safe, 0o600)
        input_link = self.base / "input-link"
        input_link.symlink_to(safe)
        with self.assertRaisesRegex(ReleaseError, "securely read"):
            builder._read_stable_file(input_link, 1024, "linked input")
        hardlink = self.base / "hardlink"
        os.link(safe, hardlink)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            builder._read_stable_file(safe, 1024, "hardlinked input")

    def test_source_inventory_and_zip_epoch_fail_closed(self) -> None:
        module = self.base / "module"
        module.mkdir(mode=0o700)
        (module / "go.mod").write_bytes(b"module example.test/module\n")
        (module / "unexpected.go").write_bytes(b"package module\n")
        with (
            mock.patch.object(builder, "SOURCE_RELEASE_PATHS", frozenset({"go.mod"})),
            self.assertRaisesRegex(ReleaseError, "unexpected=.*unexpected.go"),
        ):
            builder._module_assets(module)
        with self.assertRaisesRegex(ReleaseError, "ZIP range"):
            builder._zip_datetime(builder.MINIMUM_ZIP_EPOCH - 1)
        with self.assertRaisesRegex(ReleaseError, "ZIP range"):
            builder._zip_datetime(builder.MAXIMUM_ZIP_EPOCH + 2)

    def test_host_rejects_non_native_platforms(self) -> None:
        with (
            mock.patch.object(builder.sys, "platform", "linux"),
            mock.patch.object(builder.platform, "machine", return_value="aarch64"),
            self.assertRaisesRegex(ReleaseError, "Apple-silicon macOS"),
        ):
            builder._require_host()

    def test_go_toolchain_floor_rejects_vulnerable_patch_versions(self) -> None:
        with self.assertRaisesRegex(ReleaseError, r"requires Go >=1\.26\.6"):
            builder._require_supported_go_toolchain("go version go1.26.5 darwin/arm64")
        self.assertEqual(
            builder._require_supported_go_toolchain("go version go1.26.6 darwin/arm64"),
            (1, 26, 6),
        )
        self.assertEqual(
            builder._require_supported_go_toolchain("go version go1.27.0 darwin/arm64"),
            (1, 27, 0),
        )
        with self.assertRaisesRegex(ReleaseError, "native macOS arm64"):
            builder._require_supported_go_toolchain("go version go1.26.6 linux/arm64")


if __name__ == "__main__":
    unittest.main()
