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
from dataclasses import replace
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
            honey_local_registry_kit=True,
        )

    def honey_configuration(self) -> builder.BuildConfiguration:
        return builder._load_configuration(self.root, honey_local_registry_kit=True)

    def write_honey_fixture_kit(
        self,
        destination: Path,
        configuration: builder.BuildConfiguration | None = None,
    ) -> dict[str, object]:
        configuration = configuration or self.honey_configuration()
        registry = destination.parent / f"{destination.stem}-registry"
        index = registry / "index/ci/ga"
        index.mkdir(parents=True, mode=0o700)
        crate_payload = b"fixture Cargo package\n"
        (registry / f"cigar-sdk-{configuration.version}.crate").write_bytes(
            crate_payload
        )
        (index / "cigar-sdk").write_bytes(b'{"fixture":true}\n')
        consumer = destination.parent / f"{destination.stem}-consumer"
        consumer.mkdir(mode=0o700)
        (consumer / "Cargo.lock").write_bytes(b"version = 4\n")
        return builder._write_honey_kit(
            destination,
            configuration=configuration,
            source=self.source,
            epoch=1700000000,
            registry=registry,
            consumer=consumer,
            package_chain=(
                {
                    "name": "cigar-sdk",
                    "version": configuration.version,
                    "sha256": "a" * 64,
                    "bytes": len(crate_payload),
                },
            ),
            registry_identity=builder._registry_identity(registry),
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
        built = self.fake_built(configuration, source=source)
        kit_path = scratch / configuration.filename
        construction = self.write_honey_fixture_kit(kit_path, configuration)
        qualification = {
            "schema_version": "cigar.honey-rust-sdk-kit-validation.v1",
            "status": "passed",
            "offline": True,
            "network_proxy": "deny-loopback",
            "cargo_check": "passed",
            "cargo_test": "passed",
            "semantic_workflow": "passed",
            "semantic_bundle_identity": builder.EXPECTED_QUICKSTART_IDENTITY,
            "archive_file_count": construction["file_count"],
        }
        return replace(
            built,
            kit_path=kit_path,
            kit_validation={
                "construction": construction,
                "qualification": qualification,
            },
        )

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
        configuration = builder._load_configuration(
            self.root, honey_local_registry_kit=True
        )
        self.assertEqual(configuration.version, "0.9.4")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(
            configuration.filename,
            "cigar-rust-sdk-0.9.4-local-registry.tar.gz",
        )
        self.assertEqual(
            set(configuration.authority), set(builder.HONEY_AUTHORITY_PATHS)
        )
        self.assertEqual(
            configuration.receipt_filename,
            "rust-sdk-local-registry-build-receipt.json",
        )
        self.assertIn("examples/quickstart.rs", configuration.sdk_sources)
        self.assertIn("fixtures/semantic-bundle-v1.json", configuration.sdk_sources)
        self.assertIn("src/semantic_reuse.rs", configuration.sdk_sources)

    def test_honey_output_workspace_accepts_the_contracted_kit_bound(self) -> None:
        captured: dict[str, object] = {}
        real_create = builder.EvidenceWorkspace.create

        def capture_create(*args: object, **kwargs: object) -> object:
            captured["limits"] = kwargs.get("limits")
            return real_create(*args, **kwargs)

        with mock.patch.object(
            builder.EvidenceWorkspace, "create", side_effect=capture_create
        ):
            self.produce(self.base / "bounded-kit")

        limits = captured["limits"]
        self.assertIsInstance(limits, builder.EvidenceLimits)
        self.assertEqual(limits.max_file_bytes, builder.MAX_KIT_ARCHIVE_BYTES)
        self.assertGreater(limits.max_total_bytes, limits.max_file_bytes)

    def test_repeated_builds_are_byte_identical(self) -> None:
        first = self.base / "first"
        second = self.base / "second"
        first_receipt = self.produce(first)
        second_receipt = self.produce(second)
        filename = "cigar-rust-sdk-0.9.4-local-registry.tar.gz"
        first_archive = first / filename
        second_archive = second / filename
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(
            first_receipt["archive"]["sha256"], second_receipt["archive"]["sha256"]
        )

    def test_receipt_keeps_unpublished_chain_and_release_claims_false(self) -> None:
        evidence = self.base / "evidence"
        receipt = self.produce(evidence)
        self.assertEqual(receipt["status"], "honey-built-unqualified")
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
            "notarized",
            "published",
            "supported",
            "production_qualified",
            "release",
        ):
            self.assertFalse(claims[name], name)
        for name in (
            "developer_preview",
            "cargo_package_generated",
            "package_contract_verified",
            "self_contained_local_registry",
            "offline_consumer_check",
            "offline_consumer_test",
            "semantic_workflow_verified",
        ):
            self.assertTrue(claims[name], name)
        self.assertEqual(
            stat.S_IMODE((evidence / builder.HONEY_BUILD_RECEIPT).stat().st_mode),
            0o400,
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
        configuration = builder._load_configuration(
            self.root, honey_local_registry_kit=True
        )
        entries = self.entries(configuration)
        with self.assertRaisesRegex(ReleaseError, "refusing to overwrite"):
            builder._write_canonical_crate(destination, entries, 1700000000)

    def test_normalized_manifest_with_path_dependency_is_rejected(self) -> None:
        normalized = (
            '[package]\nname = "cigar-sdk"\nversion = "0.9.4"\n'
            'publish = ["crates-io"]\n\n[dependencies.cigar-api]\n'
            'version = "=0.9.4"\npath = "../../crates/cigar-api"\n'
        ).encode("utf-8")
        archive = self.base / "bad.crate"
        with tarfile.open(archive, mode="w:gz") as package:
            member = tarfile.TarInfo("cigar-sdk-0.9.4/Cargo.toml")
            member.size = len(normalized)
            package.addfile(member, io.BytesIO(normalized))
        with self.assertRaisesRegex(ReleaseError, "normalized dependency"):
            builder._normalized_manifest(archive, "cigar-sdk", "0.9.4")

    def test_honey_local_registry_kit_is_deterministic_and_checksum_bound(self) -> None:
        first = self.base / "first-kit.tar.gz"
        second = self.base / "second-kit.tar.gz"
        first_construction = self.write_honey_fixture_kit(first)
        second_construction = self.write_honey_fixture_kit(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_construction, second_construction)

        payloads = builder._extract_honey_kit(
            first, self.base / "kit-extracted", 1700000000
        )
        expected_support = {
            ".cargo/config.toml",
            "README.md",
            "LICENSE",
            "NOTICE",
            "RELEASE-METADATA.json",
            "SHA256SUMS",
            "examples/agent_a_coordinator.rs",
            "examples/consumer/Cargo.toml",
            "examples/consumer/Cargo.lock",
            "examples/consumer/src/main.rs",
            "examples/consumer/fixtures/semantic-bundle-v1.json",
        }
        self.assertTrue(expected_support.issubset(payloads))
        self.assertTrue(
            any(
                name.startswith("registry/") and name.endswith(".crate")
                for name in payloads
            )
        )
        metadata = json.loads(payloads["RELEASE-METADATA.json"])
        configuration = self.honey_configuration()
        self.assertEqual(metadata["schema_version"], "cigar.release-metadata.v1")
        self.assertEqual(metadata["artifact_id"], builder.HONEY_ARTIFACT_ID)
        self.assertEqual(metadata["product_version"], configuration.version)
        self.assertEqual(metadata["context_abi"], configuration.context_abi)
        self.assertEqual(metadata["source"], self.source)
        self.assertEqual(metadata["source_date_epoch"], 1700000000)
        self.assertEqual(metadata["input_file_count"], len(payloads) - 1)
        self.assertEqual(metadata["contract"], configuration.contract_relative)
        self.assertEqual(
            metadata["contract_sha256"],
            configuration.authority[configuration.contract_relative]["sha256"],
        )
        self.assertNotIn("offline", metadata)
        self.assertNotIn("production_qualified", metadata)

    def test_honey_local_registry_kit_rejects_checksum_tampering(self) -> None:
        original = self.base / "original-kit.tar.gz"
        self.write_honey_fixture_kit(original)
        entries: list[builder.CrateEntry] = []
        with tarfile.open(original, mode="r:gz") as archive:
            for member in archive:
                handle = archive.extractfile(member)
                self.assertIsNotNone(handle)
                payload = handle.read() if handle is not None else b""
                if member.name == "SHA256SUMS":
                    lines = payload.splitlines()
                    prefix = b"0" if lines[0][:1] != b"0" else b"1"
                    lines[0] = prefix + lines[0][1:]
                    payload = b"\n".join(lines) + b"\n"
                entries.append(builder.CrateEntry(member.name, payload))
        tampered = self.base / "tampered-kit.tar.gz"
        builder._write_canonical_crate(tampered, tuple(entries), 1700000000)
        with self.assertRaisesRegex(ReleaseError, "checksum"):
            builder._extract_honey_kit(
                tampered, self.base / "tampered-extracted", 1700000000
            )

    def test_receipt_is_canonical_json(self) -> None:
        evidence = self.base / "evidence"
        receipt = self.produce(evidence)
        payload = (evidence / builder.HONEY_BUILD_RECEIPT).read_bytes()
        self.assertEqual(payload, canonical_json_bytes(receipt))
        self.assertEqual(json.loads(payload), receipt)


if __name__ == "__main__":
    unittest.main()
