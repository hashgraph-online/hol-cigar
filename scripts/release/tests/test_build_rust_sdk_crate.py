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

import build_rust_sdk_crate as builder  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class RustSdkCrateBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-rust-sdk-builder-")
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
            cargo_local_registry=None,
            protoc=None,
            cargo_cache=None,
        )

    def normalized_manifest(self, configuration: builder.BuildConfiguration) -> bytes:
        return (
            "[package]\n"
            'name = "cigar-sdk"\n'
            f'version = "{configuration.version}"\n'
            'edition = "2024"\n'
            'rust-version = "1.92"\n'
            'publish = ["crates-io"]\n\n'
            "[dependencies.cigar-api]\n"
            f'version = "={configuration.version}"\n\n'
            "[dependencies.cigar-canon]\n"
            f'version = "={configuration.version}"\n\n'
            "[dependencies.cigar-daemon]\n"
            f'version = "={configuration.version}"\noptional = true\n\n'
            "[dependencies.cigar-protocol]\n"
            f'version = "={configuration.version}"\n'
        ).encode("utf-8")

    def packaged_lock(self, configuration: builder.BuildConfiguration) -> bytes:
        lines = ["version = 4", ""]
        for specification in builder.PACKAGE_SPECS:
            version = builder._package_version(specification, configuration.version)
            lines.extend(
                [
                    "[[package]]",
                    f'name = "{specification.name}"',
                    f'version = "{version}"',
                    "",
                ]
            )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def entries(
        self,
        configuration: builder.BuildConfiguration,
        *,
        source: dict[str, object] | None = None,
        omit: str | None = None,
        extra: builder.CrateEntry | None = None,
        changed_source: str | None = None,
    ) -> tuple[builder.CrateEntry, ...]:
        selected_source = source or self.source
        generated = {
            f"{configuration.crate_root}/Cargo.toml": self.normalized_manifest(
                configuration
            ),
            f"{configuration.crate_root}/Cargo.toml.orig": configuration.sdk_sources[
                "Cargo.toml"
            ],
            f"{configuration.crate_root}/Cargo.lock": self.packaged_lock(configuration),
            f"{configuration.crate_root}/.cargo_vcs_info.json": canonical_json_bytes(
                builder._expected_vcs_document(selected_source)
            ),
        }
        for relative, payload in configuration.sdk_sources.items():
            if relative == "Cargo.toml":
                continue
            generated[f"{configuration.crate_root}/{relative}"] = (
                b"changed\n" if relative == changed_source else payload
            )
        result = [
            builder.CrateEntry(path, payload)
            for path, payload in sorted(generated.items())
            if path != omit
        ]
        if extra is not None:
            result.append(extra)
        return tuple(sorted(result, key=lambda entry: entry.path.encode("utf-8")))

    def fake_built(
        self,
        configuration: builder.BuildConfiguration,
        *,
        source: dict[str, object] | None = None,
        omit: str | None = None,
        extra: builder.CrateEntry | None = None,
        changed_source: str | None = None,
    ) -> builder.BuiltCrate:
        entries = self.entries(
            configuration,
            source=source,
            omit=omit,
            extra=extra,
            changed_source=changed_source,
        )
        records = tuple(
            {
                "name": specification.name,
                "version": builder._package_version(
                    specification, configuration.version
                ),
                "sha256": f"{index + 1:064x}",
                "bytes": index + 1,
            }
            for index, specification in enumerate(builder.PACKAGE_SPECS)
        )
        return builder.BuiltCrate(
            entries=entries,
            raw_cargo_package_sha256="c" * 64,
            raw_cargo_package_bytes=123,
            package_chain=records,
            dependency_registry={
                "schema_version": "cigar.cargo-dependency-registry-snapshot.v1",
                "source": "workspace-Cargo.lock-and-owner-cache",
                "offline": True,
                "file_count": 500,
                "bytes": 1000,
                "tree_sha256": "d" * 64,
            },
            tools=(
                {
                    "name": "cargo",
                    "version": "cargo 1.92.0 (fixture)",
                    "sha256": "e" * 64,
                    "bytes": 1,
                },
            ),
            validation={
                "schema_version": "cigar.rust-sdk-crate-build-validation.v1",
                "status": "passed-local-registry",
                "offline": True,
                "external_publish_performed": False,
                "artifact_under_test": "canonical-cargo-generated-crate",
                "checks": {
                    "cargo-package-chain": "passed",
                    "extracted-library-tests-no-default-features": "passed",
                    "extracted-quickstart-no-default-features": "passed",
                    "local-registry-default-feature-consumer": "passed",
                },
                "quickstart_identity": builder.EXPECTED_QUICKSTART_IDENTITY,
                "workspace_integration_tests": {
                    "executed": False,
                    "reason": "not packaged; repository integration tests depend on external shared schemas and fixtures",
                },
            },
        )

    def fake_builder(
        self,
        configuration: builder.BuildConfiguration,
        source: dict[str, object],
        _epoch: int,
        scratch: Path,
        _arguments: argparse.Namespace,
    ) -> builder.BuiltCrate:
        self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
        return self.fake_built(configuration, source=source)

    def produce(
        self,
        evidence: Path,
        crate_builder: builder.CrateBuilder | None = None,
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
                crate_builder=crate_builder or self.fake_builder,
            )

    def test_configuration_binds_authorities_and_packaged_quickstart(self) -> None:
        configuration = builder._load_configuration(self.root)
        self.assertEqual(configuration.version, "1.0.0-dev.1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(configuration.filename, "cigar-sdk-1.0.0-dev.1.crate")
        self.assertEqual(set(configuration.authority), set(builder.AUTHORITY_PATHS))
        self.assertIn("examples/quickstart.rs", configuration.sdk_sources)
        self.assertIn("fixtures/semantic-bundle-v1.json", configuration.sdk_sources)

    def test_repeated_builds_are_byte_identical(self) -> None:
        first = self.base / "first"
        second = self.base / "second"
        first_receipt = self.produce(first)
        second_receipt = self.produce(second)
        first_archive = first / "cigar-sdk-1.0.0-dev.1.crate"
        second_archive = second / "cigar-sdk-1.0.0-dev.1.crate"
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(
            first_receipt["archive"]["sha256"], second_receipt["archive"]["sha256"]
        )

    def test_receipt_keeps_unpublished_chain_and_release_claims_false(self) -> None:
        evidence = self.base / "evidence"
        receipt = self.produce(evidence)
        self.assertEqual(receipt["status"], "built-unqualified")
        self.assertEqual(
            receipt["unpublished_dependency_chain"]["package_count"],
            len(builder.PACKAGE_SPECS) - 1,
        )
        self.assertTrue(
            receipt["unpublished_dependency_chain"][
                "resolved_only_from_private_local_registry"
            ]
        )
        self.assertFalse(
            receipt["unpublished_dependency_chain"]["crates_io_resolution_verified"]
        )
        claims = receipt["claims"]
        for name in (
            "registry_signature",
            "distribution_signed",
            "signed",
            "installable",
            "installed_compatibility",
            "clean_install_from_crates_io",
            "crates_io_dependency_resolution",
            "crates_io_published",
            "published",
            "qualified",
            "supported",
            "release",
        ):
            self.assertFalse(claims[name], name)
        self.assertEqual(
            stat.S_IMODE((evidence / builder.BUILD_RECEIPT).stat().st_mode), 0o400
        )
        self.assertEqual(
            stat.S_IMODE((evidence / receipt["archive"]["path"]).stat().st_mode),
            0o400,
        )

    def test_archive_contract_and_canonical_metadata_are_verified(self) -> None:
        evidence = self.base / "evidence"
        receipt = self.produce(evidence)
        self.assertEqual(receipt["package_verification"]["status"], "passed")
        archive = evidence / receipt["archive"]["path"]
        with tarfile.open(archive, mode="r:gz") as package:
            members = package.getmembers()
        self.assertTrue(members)
        self.assertTrue(all(member.isfile() for member in members))
        self.assertTrue(all(member.mtime == 1700000000 for member in members))
        self.assertTrue(all(member.mode == 0o644 for member in members))
        self.assertTrue(all(member.uid == 0 and member.gid == 0 for member in members))

    def test_source_change_during_build_is_rejected(self) -> None:
        changed = dict(self.source)
        changed["tree_sha256"] = "f" * 64
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(
                self.base / "evidence",
                source_side_effect=[self.source, changed],
            )

    def test_missing_package_member_is_rejected(self) -> None:
        def incomplete(
            configuration: builder.BuildConfiguration,
            source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltCrate:
            return self.fake_built(
                configuration,
                source=source,
                omit=f"{configuration.crate_root}/src/lib.rs",
            )

        with self.assertRaisesRegex(ReleaseError, "inventory differs"):
            self.produce(self.base / "evidence", crate_builder=incomplete)

    def test_unreviewed_package_member_is_rejected(self) -> None:
        def extra(
            configuration: builder.BuildConfiguration,
            source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltCrate:
            return self.fake_built(
                configuration,
                source=source,
                extra=builder.CrateEntry(
                    f"{configuration.crate_root}/tests/not-reviewed.rs", b"x\n"
                ),
            )

        with self.assertRaisesRegex(ReleaseError, "inventory differs"):
            self.produce(self.base / "evidence", crate_builder=extra)

    def test_changed_packaged_source_is_rejected(self) -> None:
        def changed(
            configuration: builder.BuildConfiguration,
            source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltCrate:
            return self.fake_built(
                configuration, source=source, changed_source="README.md"
            )

        with self.assertRaisesRegex(ReleaseError, "source differs"):
            self.produce(self.base / "evidence", crate_builder=changed)

    def test_vcs_metadata_must_bind_source_revision_and_dirty_state(self) -> None:
        wrong = dict(self.source)
        wrong["revision"] = "9" * 40

        def wrong_vcs(
            configuration: builder.BuildConfiguration,
            _source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltCrate:
            return self.fake_built(configuration, source=wrong)

        with self.assertRaisesRegex(ReleaseError, "VCS metadata"):
            self.produce(self.base / "evidence", crate_builder=wrong_vcs)

    def test_clean_vcs_metadata_omits_dirty_field_like_cargo(self) -> None:
        clean = dict(self.source)
        clean["clean"] = True
        self.assertEqual(
            builder._expected_vcs_document(clean),
            {"git": {"sha1": clean["revision"]}, "path_in_vcs": builder.SDK_RELATIVE},
        )

    def test_output_workspace_must_be_external_and_empty(self) -> None:
        with self.assertRaises(EvidenceWorkspaceError):
            self.produce(self.root / "target/rust-sdk-evidence")
        occupied = self.base / "occupied"
        occupied.mkdir(mode=0o700)
        (occupied / "existing").write_text("x", encoding="utf-8")
        with self.assertRaises(EvidenceWorkspaceError):
            self.produce(occupied)

    def test_canonical_writer_refuses_existing_target(self) -> None:
        destination = self.base / "existing.crate"
        destination.write_bytes(b"occupied")
        configuration = builder._load_configuration(self.root)
        entries = self.entries(configuration)
        with self.assertRaisesRegex(ReleaseError, "refusing to overwrite"):
            builder._write_canonical_crate(destination, entries, 1700000000)

    def test_normalized_manifest_with_path_dependency_is_rejected(self) -> None:
        normalized = (
            '[package]\nname = "cigar-sdk"\nversion = "1.0.0-dev.1"\n'
            'publish = ["crates-io"]\n\n[dependencies.cigar-api]\n'
            'version = "=1.0.0-dev.1"\npath = "../../crates/cigar-api"\n'
        ).encode("utf-8")
        archive = self.base / "bad.crate"
        with tarfile.open(archive, mode="w:gz") as package:
            member = tarfile.TarInfo("cigar-sdk-1.0.0-dev.1/Cargo.toml")
            member.size = len(normalized)
            package.addfile(member, io.BytesIO(normalized))
        with self.assertRaisesRegex(ReleaseError, "normalized dependency"):
            builder._normalized_manifest(archive, "cigar-sdk", "1.0.0-dev.1")

    def test_receipt_is_canonical_json(self) -> None:
        evidence = self.base / "evidence"
        receipt = self.produce(evidence)
        payload = (evidence / builder.BUILD_RECEIPT).read_bytes()
        self.assertEqual(payload, canonical_json_bytes(receipt))
        self.assertEqual(json.loads(payload), receipt)


if __name__ == "__main__":
    unittest.main()
