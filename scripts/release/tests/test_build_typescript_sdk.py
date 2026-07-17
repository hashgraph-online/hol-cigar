#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_typescript_sdk as builder  # noqa: E402
from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class TypeScriptSdkBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-typescript-builder-")
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
        self.dependencies = {
            "schema_version": "cigar.npm-build-dependencies.v1",
            "packages": [
                {"name": spec.name, "version": spec.version}
                for spec in builder.DEPENDENCY_SPECS
            ],
            "file_count": 5,
            "bytes": 100,
            "tree_sha256": "c" * 64,
        }

    def arguments(self, evidence: Path | None) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.root,
            evidence_dir=evidence,
            source_date_epoch="1700000000",
            node=None,
            pnpm=None,
            npm=None,
        )

    def entries(
        self,
        configuration: builder.BuildConfiguration,
        *,
        omit: str | None = None,
        extra: builder.PackageEntry | None = None,
        wrong_release: bool = False,
    ) -> tuple[builder.PackageEntry, ...]:
        result: list[builder.PackageEntry] = []
        source_bindings = {
            "package/package.json": configuration.sdk_sources["package.json"],
            "package/README.md": configuration.sdk_sources["README.md"],
            "package/LICENSE": configuration.sdk_sources["LICENSE"],
            "package/NOTICE": configuration.sdk_sources["NOTICE"],
            "package/fixtures/semantic-bundle-v1.json": configuration.sdk_sources[
                "fixtures/semantic-bundle-v1.json"
            ],
            "package/dist/release.json": (
                canonical_json_bytes(
                    {
                        "schema_version": "cigar.sdk-release.v1",
                        "name": "@cigar/sdk",
                        "version": "9.9.9",
                        "context_abi": configuration.context_abi,
                    }
                )
                if wrong_release
                else configuration.sdk_sources["release.json"]
            ),
        }
        source_map = canonical_json_bytes(
            {
                "version": 3,
                "file": "module.js",
                "sources": ["../src/module.ts"],
                "sourcesContent": ["export {};\n"],
                "names": [],
                "mappings": "",
            }
        )
        for path in sorted(
            builder.EXPECTED_PACKAGE_PATHS, key=lambda value: value.encode("utf-8")
        ):
            if path == omit:
                continue
            if path in source_bindings:
                payload = source_bindings[path]
            elif path.endswith(".map"):
                payload = source_map
            elif path.endswith(".d.ts"):
                payload = b"export {};\n"
            elif path.endswith(".js"):
                payload = b"export {};\n"
            else:
                raise AssertionError(f"unhandled fake package path: {path}")
            result.append(builder.PackageEntry(path, payload))
        if extra is not None:
            result.append(extra)
        return tuple(result)

    def package(
        self,
        configuration: builder.BuildConfiguration,
        **entry_options: object,
    ) -> builder.BuiltPackage:
        entries = self.entries(configuration, **entry_options)
        return builder.BuiltPackage(
            entries=entries,
            tools=(
                {
                    "name": "node",
                    "version": "v24.10.0",
                    "sha256": "d" * 64,
                    "bytes": 1,
                },
                {
                    "name": "pnpm",
                    "version": "10.34.5",
                    "sha256": "e" * 64,
                    "bytes": 1,
                },
            ),
            dependency_snapshot=self.dependencies,
            lock_validation={
                "package_manager": "pnpm@10.34.5",
                "mode": "offline-frozen-lockfile-only",
                "scripts": False,
                "status": "passed",
            },
            npm_pack={
                "package_manager": "npm@11.6.0",
                "ignore_scripts": True,
                "raw_file_count": len(entries),
                "status": "passed",
            },
            smoke_probe={
                "command": "node dist/examples/quickstart.js",
                "identity": builder.EXPECTED_QUICKSTART_IDENTITY,
                "status": "passed",
            },
            clean_install_validation={
                "schema_version": "cigar.typescript-sdk-clean-install.v1",
                "status": "passed-semantic-workflow",
                "offline": True,
                "scripts": False,
                "dependency_mode": "local-reviewed-package-archive",
                "package": f"@cigar/sdk@{configuration.version}",
                "package_payload_tree_sha256": builder._payload_tree(entries),
                "dependency": {
                    "name": "@bufbuild/protobuf",
                    "version": "2.12.1",
                    "sha256": "f" * 64,
                    "bytes": 1,
                },
                "semantic_bundle_identity": builder.EXPECTED_QUICKSTART_IDENTITY,
                "checks": {
                    "materialized-package": "passed",
                    "public-import": "passed",
                    "release-assets": "passed",
                    "semantic-workflow": "passed",
                },
            },
        )

    def fake_builder(
        self,
        configuration: builder.BuildConfiguration,
        _source: dict[str, object],
        _epoch: int,
        scratch: Path,
        _arguments: argparse.Namespace,
    ) -> builder.BuiltPackage:
        self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
        return self.package(configuration)

    def produce(
        self,
        evidence: Path,
        package_builder: builder.PackageBuilder | None = None,
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
            source_patch,
            mock.patch.object(
                builder, "_dependency_identity", return_value=self.dependencies
            ),
            mock.patch.object(
                builder,
                "_require_host",
                return_value={
                    "platform": "macos",
                    "architecture": "arm64",
                    "target_triple": builder.TARGET_TRIPLE,
                    "macos_version": "15.0",
                },
            ),
        ):
            return builder.produce(
                self.arguments(evidence),
                package_builder=package_builder or self.fake_builder,
            )

    def test_configuration_binds_honey_authorities_and_exact_inventory(
        self,
    ) -> None:
        configuration = builder._load_configuration(self.root)
        self.assertEqual(configuration.version, "0.9.0-honey.1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(configuration.filename, "cigar-sdk-0.9.0-honey.1.tgz")
        self.assertEqual(
            set(configuration.authority), set(builder.HONEY_AUTHORITY_PATHS)
        )
        self.assertEqual(
            configuration.receipt_filename, "typescript-sdk-build-receipt.json"
        )
        self.assertEqual(
            set(configuration.sdk_sources), set(builder.SDK_BUILD_SOURCE_PATHS)
        )
        self.assertEqual(len(builder.EXPECTED_PACKAGE_PATHS), 74)

    def test_configuration_requires_the_exact_matrix_producer_binding(self) -> None:
        load_json = builder.load_json

        def without_producer(path: Path) -> object:
            value = load_json(path)
            if path.name != "artifact-matrix.v1.json":
                return value
            copied = json.loads(json.dumps(value))
            row = next(
                artifact
                for artifact in copied["artifacts"]
                if artifact["id"] == builder.ARTIFACT_ID
            )
            row.pop("producer")
            return copied

        with mock.patch.object(builder, "load_json", side_effect=without_producer):
            with self.assertRaisesRegex(ReleaseError, "artifact row"):
                builder._load_configuration(self.root)

    def test_fake_build_is_deterministic_contract_valid_and_unclaimed(self) -> None:
        first_root = self.base / "first"
        second_root = self.base / "second"
        first = self.produce(first_root)
        second = self.produce(second_root)

        filename = "cigar-sdk-0.9.0-honey.1.tgz"
        first_archive = first_root / filename
        second_archive = second_root / filename
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first["archive"], second["archive"])
        self.assertEqual(first["status"], "built-unqualified")
        self.assertEqual(first["payload_file_count"], 74)
        self.assertEqual(
            first["claims"],
            {
                "development_build": True,
                "registry_signature": False,
                "distribution_signed": False,
                "installed_compatibility": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        )
        self.assertEqual(stat.S_IMODE(first_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(first_archive.stat().st_mode), 0o400)
        self.assertEqual(
            stat.S_IMODE(
                (first_root / "typescript-sdk-build-receipt.json").stat().st_mode
            ),
            0o400,
        )
        self.assertEqual(
            json.loads((first_root / "typescript-sdk-build-receipt.json").read_bytes()),
            first,
        )

        with tarfile.open(first_archive, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(
                {member.name for member in members}, builder.EXPECTED_PACKAGE_PATHS
            )
            self.assertTrue(all(member.isfile() for member in members))
            self.assertTrue(all(member.mode == 0o644 for member in members))
            self.assertTrue(
                all(member.uid == 0 and member.gid == 0 for member in members)
            )
            self.assertTrue(all(member.mtime == 1_700_000_000 for member in members))

    def test_missing_extra_stale_and_noncanonical_payloads_fail_closed(self) -> None:
        configuration = builder._load_configuration(self.root)
        invalid = (
            self.package(configuration, omit="package/dist/index.js"),
            self.package(
                configuration,
                extra=builder.PackageEntry(
                    "package/dist/undeclared.js", b"export {};\n"
                ),
            ),
            self.package(configuration, wrong_release=True),
        )
        for index, package in enumerate(invalid):
            with self.subTest(index=index):
                evidence = self.base / f"invalid-{index}"

                def bad_builder(
                    _configuration: builder.BuildConfiguration,
                    _source: dict[str, object],
                    _epoch: int,
                    _scratch: Path,
                    _arguments: argparse.Namespace,
                    selected: builder.BuiltPackage = package,
                ) -> builder.BuiltPackage:
                    return selected

                with self.assertRaises(ReleaseError):
                    self.produce(evidence, bad_builder)
                self.assertEqual(list(evidence.iterdir()), [])

    def test_source_and_dependency_changes_fail_before_publication(self) -> None:
        changed_source = {**self.source, "tree_sha256": "f" * 64}
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(
                self.base / "source-changed",
                source_side_effect=[self.source, changed_source],
            )
        self.assertEqual(list((self.base / "source-changed").iterdir()), [])

        calls = 0

        def dependency_change(_root: Path) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return (
                self.dependencies
                if calls == 1
                else {
                    **self.dependencies,
                    "tree_sha256": "9" * 64,
                }
            )

        evidence = self.base / "dependency-changed"
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(builder, "_source_identity", return_value=self.source),
            mock.patch.object(
                builder, "_dependency_identity", side_effect=dependency_change
            ),
            mock.patch.object(
                builder,
                "_require_host",
                return_value={
                    "platform": "macos",
                    "architecture": "arm64",
                    "target_triple": builder.TARGET_TRIPLE,
                    "macos_version": "15.0",
                },
            ),
        ):
            with self.assertRaisesRegex(ReleaseError, "dependencies changed"):
                builder.produce(
                    self.arguments(evidence), package_builder=self.fake_builder
                )
        self.assertEqual(list(evidence.iterdir()), [])

    def test_attachment_substitution_is_rejected_without_publishing_archive(
        self,
    ) -> None:
        evidence = self.base / "substitution"
        attach = EvidenceWorkspace.attach_file

        def substitute(
            workspace: EvidenceWorkspace,
            source: Path,
            relative: str,
            **kwargs: object,
        ) -> object:
            source.write_bytes(b"substituted archive")
            return attach(workspace, source, relative, **kwargs)

        with mock.patch.object(EvidenceWorkspace, "attach_file", new=substitute):
            with self.assertRaisesRegex(
                EvidenceWorkspaceError, "differs from validated content"
            ):
                self.produce(evidence)
        self.assertEqual(list(evidence.iterdir()), [])

    def test_output_selection_requires_absolute_external_empty_workspace(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "is required"):
                builder._selected_evidence_directory(self.arguments(None))
            with self.assertRaisesRegex(ReleaseError, "absolute"):
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

        occupied = self.base / "occupied"
        occupied.mkdir(mode=0o700)
        marker = occupied / "marker"
        marker.write_text("owned\n", encoding="utf-8")
        os.chmod(marker, 0o400)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "inventory mismatch"):
            self.produce(occupied)
        self.assertEqual(marker.read_text(encoding="utf-8"), "owned\n")

    def test_raw_npm_pack_rejects_nonregular_and_unreviewed_members(self) -> None:
        raw = self.base / "raw.tgz"
        with tarfile.open(raw, "w:gz") as archive:
            directory = tarfile.TarInfo("package/dist")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
        os.chmod(raw, 0o600)
        with self.assertRaisesRegex(ReleaseError, "member is unsafe"):
            builder._read_npm_pack(raw)

        extra = self.base / "extra.tgz"
        with tarfile.open(extra, "w:gz") as archive:
            payload = b"unexpected\n"
            member = tarfile.TarInfo("package/unreviewed.txt")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(ReleaseError, "exact reviewed"):
            builder._read_npm_pack(extra)

    def test_installed_build_dependency_snapshot_is_exact_and_bounded(self) -> None:
        snapshot = builder._dependency_identity(self.root)
        self.assertEqual(snapshot["schema_version"], "cigar.npm-build-dependencies.v1")
        self.assertEqual(
            snapshot["packages"],
            [
                {"name": spec.name, "version": spec.version}
                for spec in builder.DEPENDENCY_SPECS
            ],
        )
        self.assertGreater(snapshot["file_count"], 100)
        self.assertGreater(snapshot["bytes"], 1_000_000)
        self.assertRegex(str(snapshot["tree_sha256"]), r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
