#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import io
import json
import os
import shutil
import struct
import sys
import tarfile
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
ROOT = RELEASE.parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import beta_artifacts  # noqa: E402
import beta_profile  # noqa: E402
from release_lib import (  # noqa: E402
    expand_files,
    normalized_mode,
    process_failure_summary,
    sha256_bytes,
    sha256_file,
)


def synthetic_elf() -> bytes:
    payload = bytearray(768)
    payload[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        payload,
        16,
        3,
        62,
        1,
        0x400100,
        64,
        0,
        0,
        64,
        56,
        5,
        64,
        0,
        0,
    )
    struct.pack_into("<IIQQQQQQ", payload, 64, 1, 5, 0, 0x400000, 0, 768, 768, 4096)
    interpreter = b"/lib64/ld-linux-x86-64.so.2\0"
    struct.pack_into(
        "<IIQQQQQQ",
        payload,
        120,
        3,
        4,
        384,
        0x400180,
        0,
        len(interpreter),
        len(interpreter),
        1,
    )
    struct.pack_into("<IIQQQQQQ", payload, 176, 2, 6, 448, 0x4001C0, 0, 80, 80, 8)
    struct.pack_into("<IIQQQQQQ", payload, 232, 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    struct.pack_into(
        "<IIQQQQQQ", payload, 288, 0x6474E552, 4, 448, 0x4001C0, 0, 80, 80, 16
    )
    payload[384 : 384 + len(interpreter)] = interpreter
    string_table = b"\0libc.so.6\0"
    struct.pack_into("<QQ", payload, 448, 5, 0x400230)
    struct.pack_into("<QQ", payload, 464, 10, len(string_table))
    struct.pack_into("<QQ", payload, 480, 1, 1)
    struct.pack_into("<QQ", payload, 496, 24, 0)
    struct.pack_into("<QQ", payload, 512, 0, 0)
    payload[560 : 560 + len(string_table)] = string_table
    return bytes(payload)


def custom_archive(
    path: Path,
    epoch: int,
    entries: list[tuple[str, bytes, int, bytes | None]],
) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for name, payload, mode, kind in entries:
                    information = tarfile.TarInfo(name)
                    information.mode = mode
                    information.mtime = epoch
                    information.uid = 0
                    information.gid = 0
                    information.uname = ""
                    information.gname = ""
                    if kind is not None:
                        information.type = kind
                        information.linkname = "target"
                        information.size = 0
                        archive.addfile(information)
                    else:
                        information.size = len(payload)
                        archive.addfile(information, io.BytesIO(payload))


@unittest.skipUnless(os.name == "posix", "beta evidence requires POSIX")
class BetaArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.snapshot = beta_artifacts.GitSnapshot(
            revision="1" * 40,
            tree="2" * 40,
            source_date_epoch=1_700_000_000,
            generated_at="2023-11-14T22:13:20Z",
        )

    def input_records(self, paths: tuple[str, ...]) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        for relative in paths:
            path = ROOT / relative
            records.append(
                {
                    "path": relative,
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                }
            )
        records.sort(key=lambda record: str(record["path"]).encode("utf-8"))
        return records

    def assert_release_verification_schema(self, document: dict[str, object]) -> None:
        schema = json.loads(
            (
                ROOT / "packaging/beta/schemas/beta-release-verification.v1.schema.json"
            ).read_text()
        )
        self.assertEqual(set(document), set(schema["required"]))
        for key, rule in schema["properties"].items():
            if "const" in rule:
                self.assertEqual(document[key], rule["const"])
        self.assertRegex(
            str(document["source_revision"]),
            schema["properties"]["source_revision"]["pattern"],
        )
        self.assertIsInstance(document["manifest"], dict)
        self.assertEqual(len(document["artifacts"]), 6)
        checks = document["checks"]
        self.assertIsInstance(checks, dict)
        checks_schema = schema["properties"]["checks"]
        self.assertEqual(set(checks), set(checks_schema["required"]))
        for key, rule in checks_schema["properties"].items():
            if "const" in rule:
                self.assertEqual(checks[key], rule["const"])
            elif rule.get("type") == "boolean":
                self.assertIs(type(checks[key]), bool)

    def pinned_cargo_graph(
        self,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        resolution = json.loads(
            (ROOT / "packaging/beta/cargo-resolution.v1.json").read_text()
        )
        inventory = json.loads(
            (ROOT / "packaging/licenses/beta-third-party-inventory.v1.json").read_text()
        )
        license_by_purl = {
            record["purl"]: record["license_expression"]
            for record in inventory["components"]
        }
        package_by_purl = {
            f"pkg:cargo/{record['name']}@{record['version']}": record
            for record in resolution["external_packages"]
        }
        components: list[dict[str, object]] = []
        for record in resolution["resolution"]:
            purl = record["ref"]
            name, version = purl.removeprefix("pkg:cargo/").rsplit("@", 1)
            component: dict[str, object] = {
                "type": "application" if name == "cigar-cli" else "library",
                "name": name,
                "version": version,
                "purl": purl,
                "bom-ref": purl,
                "licenses": [
                    {
                        "expression": (
                            "Apache-2.0"
                            if record["source"] == "workspace"
                            else license_by_purl[purl]
                        )
                    }
                ],
            }
            if purl in package_by_purl:
                component["hashes"] = [
                    {
                        "alg": "SHA-256",
                        "content": package_by_purl[purl]["checksum"],
                    }
                ]
            components.append(component)
        components.sort(key=lambda item: (str(item["name"]), str(item["version"])))
        return components, [dict(record) for record in resolution["dependencies"]]

    def rust_material(self) -> dict[str, object]:
        manifest = json.loads(
            (
                ROOT / "packaging/licenses/beta-third-party-license-manifest.v1.json"
            ).read_text()
        )
        notice = manifest["rust_standard_library"]
        digest = "e" * 64
        return {
            "uri": (
                f"urn:cigar:rust-target-libdir:{beta_profile.TARGET_TRIPLE}:{digest}"
            ),
            "name": "rust-target-libdir",
            "digest": {"sha256": digest},
            "annotations": {
                "bytes": 1,
                "fileCount": 1,
                "noticeBytes": notice["bytes"],
                "noticeSha256": notice["sha256"],
                "rustcCommit": "ded5c06cf21d2b93bffd5d884aa6e96934ee4234",
                "target": beta_profile.TARGET_TRIPLE,
                "toolchainVersion": beta_profile.RUST_TOOLCHAIN_VERSION,
            },
        }

    def qualified_host(self) -> dict[str, str]:
        return {
            "system": "linux",
            "machine": "x86_64",
            "distribution": beta_profile.QUALIFIED_DISTRIBUTION,
            "distribution_version": beta_profile.QUALIFIED_DISTRIBUTION_VERSION,
            "libc": "glibc",
            "libc_version": beta_profile.MINIMUM_GLIBC_VERSION,
            "glibc_identity": f"glibc {beta_profile.MINIMUM_GLIBC_VERSION}",
            "runtime_baseline": beta_profile.RUNTIME_BASELINE,
            "target": beta_profile.TARGET_TRIPLE,
        }

    def synthetic_binary_build(self) -> beta_artifacts.BinaryBuild:
        cargo_components, cargo_dependencies = self.pinned_cargo_graph()
        rust_material = self.rust_material()
        components, dependencies = beta_artifacts._augment_native_resolution(
            cargo_components,
            cargo_dependencies,
            beta_artifacts.elf_needed_libraries(synthetic_elf()),
            beta_artifacts._rust_standard_library_component(rust_material),
        )
        rustc_version = (
            "rustc 1.92.0 (ded5c06cf 2025-12-08)\n"
            "binary: rustc\n"
            "commit-hash: ded5c06cf21d2b93bffd5d884aa6e96934ee4234\n"
            "commit-date: 2025-12-08\n"
            "host: x86_64-unknown-linux-gnu\n"
            "release: 1.92.0\n"
            "LLVM version: 21.1.3"
        )
        tools = tuple(
            {
                "name": name,
                "sha256": character * 64,
                "bytes": 1,
                "version": rustc_version if name == "rustc" else f"{name} fixture",
            }
            for name, character in (
                ("cargo", "a"),
                ("git", "b"),
                ("linker", "c"),
                ("python", "d"),
                ("python-gzip", "e"),
                ("python-tarfile", "f"),
                ("python-zlib", "1"),
                ("rustc", "2"),
            )
        )
        dependency_materials = tuple(
            {
                "uri": beta_artifacts._purl(package["name"], package["version"]),
                "name": f"{package['name']}-{package['version']}.crate",
                "digest": {"sha256": package["checksum"]},
                "annotations": {
                    "archiveBytes": 1,
                    "source": package["source"],
                    "sourceTreeSha256": "3" * 64,
                },
            }
            for package in beta_artifacts._pinned_vendor_crates(ROOT)
        )
        help_digest = sha256_file(ROOT / "crates/cigar-cli/assets/cigar-help-beta.txt")
        return beta_artifacts.BinaryBuild(
            synthetic_elf(),
            beta_artifacts.expected_version_document(self.snapshot),
            help_digest,
            tuple(components),
            tuple(dependencies),
            tools,
            dependency_materials,
            (rust_material,),
        )

    def fixture_committed(
        self, matrix: dict[str, object]
    ) -> dict[str, beta_artifacts.CommittedEntry]:
        paths = {"LICENSE", "NOTICE"}
        for matrix_entry in matrix["artifacts"][:5]:
            policy = beta_artifacts._contract_policy(ROOT, matrix_entry)
            paths.update(policy["required"])
        paths.update(beta_profile.BETA_PROJECTION_REMAP)
        paths.discard("RELEASE-METADATA.json")
        committed = {}
        for name in paths:
            source = ROOT / name
            payload = (
                source.read_bytes()
                if source.is_file() and not source.is_symlink()
                else f"reviewed fixture for {name}\n".encode()
            )
            committed[name] = beta_artifacts.CommittedEntry(
                name, payload, normalized_mode(name)
            )
        for source, destination in beta_profile.BETA_PROJECTION_REMAP.items():
            committed[destination] = beta_artifacts.CommittedEntry(
                destination,
                committed[source].payload,
                committed[source].mode,
            )
        help_path = "crates/cigar-cli/assets/cigar-help-beta.txt"
        committed[help_path] = beta_artifacts.CommittedEntry(
            help_path, (ROOT / help_path).read_bytes(), 0o644
        )
        return committed

    def workspace_projection_inputs(
        self,
    ) -> dict[str, beta_artifacts.CommittedEntry]:
        committed: dict[str, beta_artifacts.CommittedEntry] = {}
        selected = expand_files(
            ROOT,
            [
                *beta_profile.BETA_PROJECTION_INCLUDE,
                *beta_profile.BETA_PROJECTION_REMAP,
            ],
            [],
        )
        for relative, path in selected:
            committed[relative] = beta_artifacts.CommittedEntry(
                relative, path.read_bytes(), normalized_mode(relative)
            )
        return committed

    def freeze_source(self, name: str = "source-freeze") -> Path:
        output = self.base / name
        committed = self.workspace_projection_inputs()
        with (
            mock.patch.object(
                beta_artifacts,
                "inspect_clean_snapshot",
                return_value=self.snapshot,
            ) as freeze_snapshot_gate,
            mock.patch.object(
                beta_artifacts,
                "read_committed_tree",
                return_value=committed,
            ),
            mock.patch.object(
                beta_artifacts,
                "require_declared_host",
                side_effect=AssertionError(
                    "source freeze attempted native qualification"
                ),
            ),
        ):
            report = beta_artifacts.freeze_beta_source(
                root=ROOT,
                output=output,
                git_path=Path(sys.executable),
            )
        self.assertEqual(report["status"], "passed")
        self.assertGreaterEqual(freeze_snapshot_gate.call_count, 3)
        self.assertFalse(report["checks"]["native_host_qualification_performed"])
        return output

    def build_candidate(self) -> Path:
        candidate = self.base / "candidate"
        candidate.mkdir(mode=0o700)
        matrix = beta_profile.expected_artifact_matrix()
        self.committed = self.fixture_committed(matrix)
        artifacts: list[dict[str, object]] = []
        archive_manifest = beta_profile.expected_source_archives()

        for declaration, matrix_entry in zip(
            archive_manifest["archives"], matrix["artifacts"][:5], strict=True
        ):
            policy = beta_artifacts._contract_policy(ROOT, matrix_entry)
            entries = beta_artifacts._select_entries(
                self.committed,
                declaration["include"],
                archive_manifest["always_exclude"],
                str(matrix_entry["id"]),
            )
            metadata = beta_artifacts._metadata(
                artifact_id=str(matrix_entry["id"]),
                contract_path=str(matrix_entry["contract"]),
                contract_sha256=sha256_file(policy["path"]),
                snapshot=self.snapshot,
                payload=entries,
                build=beta_artifacts._source_build_record(),
            )
            relative = f"artifacts/{matrix_entry['filename']}"
            archive = candidate / relative
            beta_artifacts.write_deterministic_archive(
                archive, entries, metadata, self.snapshot.source_date_epoch
            )
            artifacts.append(
                beta_artifacts._artifact_record(
                    archive,
                    str(matrix_entry["id"]),
                    relative,
                    str(matrix_entry["contract"]),
                )
            )

        source_record = artifacts[0]
        source_descriptor = {
            "schema_version": "cigar.source-descriptor.v1",
            "generated_at": self.snapshot.generated_at,
            "git": {
                "revision": self.snapshot.revision,
                "tree": self.snapshot.tree,
                "committed": True,
                "clean": True,
                "status_entry_count": 0,
                "status_sha256": sha256_bytes(b""),
            },
            "source_archive": {
                "name": Path(str(source_record["path"])).name,
                "sha256": source_record["sha256"],
                "bytes": source_record["bytes"],
            },
            "policy_inputs": self.input_records(beta_artifacts.SOURCE_POLICY_INPUTS),
            "tool_inputs": self.input_records(beta_artifacts.SOURCE_TOOL_INPUTS),
        }
        source_descriptor_path = candidate / beta_artifacts.SOURCE_DESCRIPTOR_PATH
        beta_artifacts._write_private_json(source_descriptor_path, source_descriptor)
        source_descriptor_reference = beta_artifacts._file_reference(
            source_descriptor_path, beta_artifacts.SOURCE_DESCRIPTOR_PATH
        )

        matrix_entry = matrix["artifacts"][5]
        binary_payload = synthetic_elf()
        base_entries = [
            beta_artifacts.CommittedEntry(
                "LICENSE", self.committed["LICENSE"].payload, 0o644
            ),
            beta_artifacts.CommittedEntry(
                "NOTICE", self.committed["NOTICE"].payload, 0o644
            ),
            beta_artifacts.CommittedEntry("bin/cigar", binary_payload, 0o755),
        ]
        binary_entries = [
            *base_entries,
            beta_artifacts.CommittedEntry(
                "SHA256SUMS", beta_artifacts._internal_checksums(base_entries), 0o644
            ),
        ]
        help_digest = sha256_file(ROOT / "crates/cigar-cli/assets/cigar-help-beta.txt")
        binary_build = beta_artifacts._binary_build_record(
            beta_artifacts.expected_version_document(self.snapshot), help_digest
        )
        policy = beta_artifacts._contract_policy(ROOT, matrix_entry)
        metadata = beta_artifacts._metadata(
            artifact_id=str(matrix_entry["id"]),
            contract_path=str(matrix_entry["contract"]),
            contract_sha256=sha256_file(policy["path"]),
            snapshot=self.snapshot,
            payload=binary_entries,
            build=binary_build,
        )
        relative = f"artifacts/{matrix_entry['filename']}"
        binary_archive = candidate / relative
        beta_artifacts.write_deterministic_archive(
            binary_archive,
            binary_entries,
            metadata,
            self.snapshot.source_date_epoch,
        )
        artifacts.append(
            beta_artifacts._artifact_record(
                binary_archive,
                str(matrix_entry["id"]),
                relative,
                str(matrix_entry["contract"]),
            )
        )

        checksums_payload = "".join(
            f"{record['sha256']}  {record['path']}\n"
            for record in sorted(
                artifacts, key=lambda record: str(record["path"]).encode("utf-8")
            )
        ).encode("ascii")
        checksums_path = candidate / beta_artifacts.CHECKSUM_PATH
        beta_artifacts._write_private(checksums_path, checksums_payload)
        checksums_reference = beta_artifacts._file_reference(
            checksums_path, beta_artifacts.CHECKSUM_PATH
        )

        cargo_components, cargo_dependencies = self.pinned_cargo_graph()
        rust_material = self.rust_material()
        components, dependencies = beta_artifacts._augment_native_resolution(
            cargo_components,
            cargo_dependencies,
            beta_artifacts.elf_needed_libraries(binary_payload),
            beta_artifacts._rust_standard_library_component(rust_material),
        )
        self.cargo_components = cargo_components
        self.cargo_dependencies = cargo_dependencies
        artifact_payloads = {
            str(record["path"]): (candidate / str(record["path"])).read_bytes()
            for record in artifacts
        }
        member_bindings = beta_artifacts._archive_member_bindings(
            root=ROOT,
            snapshot=self.snapshot,
            artifacts=artifacts,
            artifact_payloads=artifact_payloads,
        )
        sbom = beta_artifacts.build_beta_sbom(
            snapshot=self.snapshot,
            artifacts=artifacts,
            components=components,
            dependencies=dependencies,
            member_bindings=member_bindings,
        )
        sbom_path = candidate / beta_artifacts.SBOM_PATH
        beta_artifacts._write_private_json(sbom_path, sbom)
        sbom_reference = beta_artifacts._file_reference(
            sbom_path, beta_artifacts.SBOM_PATH
        )
        spdx = beta_artifacts.build_beta_spdx(
            snapshot=self.snapshot,
            artifacts=artifacts,
            components=components,
            dependencies=dependencies,
            member_bindings=member_bindings,
        )
        spdx_path = candidate / beta_artifacts.SPDX_PATH
        beta_artifacts._write_private_json(spdx_path, spdx)
        spdx_reference = beta_artifacts._file_reference(
            spdx_path, beta_artifacts.SPDX_PATH
        )
        self.artifacts = artifacts
        self.components = components
        self.dependencies = dependencies
        self.member_bindings = member_bindings
        self.sbom = sbom
        self.spdx = spdx

        rustc_version = (
            "rustc 1.92.0 (ded5c06cf 2025-12-08)\n"
            "binary: rustc\n"
            "commit-hash: ded5c06cf21d2b93bffd5d884aa6e96934ee4234\n"
            "commit-date: 2025-12-08\n"
            "host: x86_64-unknown-linux-gnu\n"
            "release: 1.92.0\n"
            "LLVM version: 21.1.3"
        )
        tools = [
            {
                "name": name,
                "sha256": character * 64,
                "bytes": 1,
                "version": rustc_version if name == "rustc" else f"{name} fixture",
            }
            for name, character in (
                ("cargo", "a"),
                ("git", "b"),
                ("linker", "c"),
                ("python", "d"),
                ("python-gzip", "e"),
                ("python-tarfile", "f"),
                ("python-zlib", "1"),
                ("rustc", "2"),
            )
        ]
        dependency_materials = [
            {
                "uri": beta_artifacts._purl(package["name"], package["version"]),
                "name": f"{package['name']}-{package['version']}.crate",
                "digest": {"sha256": package["checksum"]},
                "annotations": {
                    "archiveBytes": 1,
                    "source": package["source"],
                    "sourceTreeSha256": "3" * 64,
                },
            }
            for package in beta_artifacts._pinned_vendor_crates(ROOT)
        ]
        provenance = beta_artifacts.build_beta_provenance(
            snapshot=self.snapshot,
            artifacts=artifacts,
            source_descriptor=source_descriptor,
            source_descriptor_reference=source_descriptor_reference,
            tools=tools,
            dependency_materials=dependency_materials,
            toolchain_materials=[rust_material],
            host=self.qualified_host(),
            builder_id="test://reviewed-linux-builder",
            started_on="2023-11-14T22:13:20Z",
            finished_on="2023-11-14T22:13:21Z",
        )
        provenance_path = candidate / beta_artifacts.PROVENANCE_PATH
        beta_artifacts._write_private_json(provenance_path, provenance)
        provenance_reference = beta_artifacts._file_reference(
            provenance_path, beta_artifacts.PROVENANCE_PATH
        )

        manifest = beta_artifacts._build_manifest_document(
            snapshot=self.snapshot,
            artifacts=artifacts,
            source_descriptor_reference=source_descriptor_reference,
            checksums_reference=checksums_reference,
            sbom_reference=sbom_reference,
            spdx_reference=spdx_reference,
            provenance_reference=provenance_reference,
            binary_build=binary_build,
        )
        beta_artifacts._write_private_json(
            candidate / beta_artifacts.BUILD_MANIFEST_PATH, manifest
        )
        verification = beta_artifacts.verify_beta_candidate(
            root=ROOT,
            candidate=candidate,
            strict_read_only=False,
            execute_binary=False,
            snapshot_override=self.snapshot,
            committed_override=self.committed,
            resolution_override=(self.cargo_components, self.cargo_dependencies),
            require_recorded_verification=False,
        )
        verification["checks"]["binary_executed"] = True
        beta_artifacts._write_private_json(
            candidate / beta_artifacts.VERIFICATION_PATH, verification
        )
        return candidate

    def test_projected_source_release_tool_imports_are_self_contained(self) -> None:
        committed: dict[str, beta_artifacts.CommittedEntry] = {}
        selected = expand_files(
            ROOT,
            [
                *beta_profile.BETA_PROJECTION_INCLUDE,
                *beta_profile.BETA_PROJECTION_REMAP,
            ],
            [],
        )
        for relative, path in selected:
            committed[relative] = beta_artifacts.CommittedEntry(
                relative, path.read_bytes(), normalized_mode(relative)
            )

        projected = beta_artifacts._project_beta_source(committed)
        stage = self.base / "projected-source"
        beta_artifacts._materialize_committed_tree(stage, projected)
        home = self.base / "projected-home"
        home.mkdir(mode=0o700)
        result = beta_artifacts.run_bounded(
            [sys.executable, "scripts/release/beta_artifacts.py", "--help"],
            cwd=stage,
            env={
                "HOME": str(home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
            timeout=30,
            max_stdout=256 * 1024,
            max_stderr=256 * 1024,
        )
        self.assertEqual(
            result.returncode,
            0,
            process_failure_summary(result, "projected beta tool import"),
        )

    def test_source_freeze_is_deterministic_host_independent_and_cli_verifiable(
        self,
    ) -> None:
        first = self.freeze_source("first-freeze")
        second = self.freeze_source("second-freeze")
        for relative in beta_artifacts.SOURCE_FREEZE_PATHS:
            first_path = first / relative
            second_path = second / relative
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            self.assertEqual(first_path.stat().st_mode & 0o777, 0o400)
        self.assertEqual(
            {
                path.relative_to(first).as_posix()
                for path in first.rglob("*")
                if path.is_file()
            },
            set(beta_artifacts.SOURCE_FREEZE_PATHS),
        )
        committed = self.workspace_projection_inputs()
        with (
            mock.patch.object(
                beta_artifacts,
                "require_declared_host",
                side_effect=AssertionError(
                    "source verification attempted native qualification"
                ),
            ),
            mock.patch.object(
                beta_artifacts,
                "inspect_clean_snapshot",
                return_value=self.snapshot,
            ),
            mock.patch.object(
                beta_artifacts,
                "read_committed_tree",
                return_value=committed,
            ),
        ):
            report = beta_artifacts.verify_beta_source_freeze(
                root=ROOT,
                source_freeze=first,
                git_path=Path(sys.executable),
            )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["source"], self.snapshot.source_identity())
        self.assertTrue(report["checks"]["git_projection_recomputed"])

        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "beta_artifacts.py",
                    "verify-source",
                    "--root",
                    str(ROOT),
                    "--source-freeze",
                    str(first),
                    "--git",
                    sys.executable,
                ],
            ),
            mock.patch.object(sys, "stdout", stdout),
            mock.patch.object(
                beta_artifacts,
                "inspect_clean_snapshot",
                return_value=self.snapshot,
            ),
            mock.patch.object(
                beta_artifacts,
                "read_committed_tree",
                return_value=committed,
            ),
        ):
            self.assertEqual(beta_artifacts.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "passed")

    def test_source_freeze_rejects_alias_nesting_omission_and_substitution(
        self,
    ) -> None:
        original = self.freeze_source()
        alias = self.base / "freeze-alias"
        alias.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "aliases"):
            beta_artifacts.verify_beta_source_freeze(
                root=ROOT,
                source_freeze=alias,
                git_path=Path(sys.executable),
            )
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "nested"):
            beta_artifacts._require_disjoint_external_paths(
                original,
                original / "candidate",
                "source freeze",
                "candidate",
            )
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "outside"):
            beta_artifacts._require_new_external_output(
                ROOT, ROOT / "nested-source-freeze", "source freeze"
            )

        omitted = self.base / "omitted-freeze"
        shutil.copytree(original, omitted)
        (omitted / beta_artifacts.SOURCE_DESCRIPTOR_PATH).unlink()
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "inventory"):
            beta_artifacts.verify_beta_source_freeze(
                root=ROOT,
                source_freeze=omitted,
                git_path=Path(sys.executable),
            )

        substituted = self.base / "substituted-freeze"
        shutil.copytree(original, substituted)
        archive = substituted / beta_artifacts.SOURCE_ARCHIVE_PATH
        os.chmod(archive, 0o600)
        archive.write_bytes(archive.read_bytes() + b"substitution")
        os.chmod(archive, 0o400)
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "binding"):
            beta_artifacts.verify_beta_source_freeze(
                root=ROOT,
                source_freeze=substituted,
                git_path=Path(sys.executable),
            )

        invalid_identity = self.base / "invalid-identity-freeze"
        shutil.copytree(original, invalid_identity)
        descriptor_path = invalid_identity / beta_artifacts.SOURCE_DESCRIPTOR_PATH
        descriptor = json.loads(descriptor_path.read_bytes())
        descriptor["git"]["revision"] = "0" * 40
        os.chmod(descriptor_path, 0o600)
        descriptor_path.write_bytes(beta_artifacts.canonical_json_bytes(descriptor))
        os.chmod(descriptor_path, 0o400)
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "Git identity"):
            beta_artifacts.verify_beta_source_freeze(
                root=ROOT,
                source_freeze=invalid_identity,
                git_path=Path(sys.executable),
            )

        home = self.base / "negative-cli-home"
        home.mkdir(mode=0o700)
        result = beta_artifacts.run_bounded(
            [
                sys.executable,
                "scripts/release/beta_artifacts.py",
                "verify-source",
                "--root",
                str(ROOT),
                "--source-freeze",
                str(omitted),
                "--git",
                sys.executable,
            ],
            cwd=ROOT,
            env={
                "HOME": str(home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
            timeout=60,
            max_stdout=256 * 1024,
            max_stderr=256 * 1024,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"source freeze workspace is unsafe", result.stderr)

    def test_native_build_consumes_freeze_and_preserves_frozen_bytes(self) -> None:
        source_freeze = self.freeze_source()
        output = self.base / "candidate-from-freeze"
        frozen_archive = (
            source_freeze / beta_artifacts.SOURCE_ARCHIVE_PATH
        ).read_bytes()
        frozen_descriptor = (
            source_freeze / beta_artifacts.SOURCE_DESCRIPTOR_PATH
        ).read_bytes()
        binary = self.synthetic_binary_build()
        committed = self.workspace_projection_inputs()
        observed_source: list[Path] = []

        def builder(
            source: Path,
            _staging: Path,
            snapshot: beta_artifacts.GitSnapshot,
            expected_help: bytes,
        ) -> beta_artifacts.BinaryBuild:
            self.assertNotEqual(source, ROOT)
            self.assertEqual(snapshot, self.snapshot)
            self.assertEqual(source.stat().st_mode & 0o777, 0o555)
            self.assertEqual(
                (source / "crates/cigar-cli/assets/cigar-help-beta.txt").read_bytes(),
                expected_help,
            )
            observed_source.append(source)
            return binary

        with (
            mock.patch.object(
                beta_artifacts,
                "require_declared_host",
                return_value=self.qualified_host(),
            ) as host_gate,
            mock.patch.object(
                beta_artifacts,
                "inspect_clean_snapshot",
                return_value=self.snapshot,
            ) as snapshot_gate,
            mock.patch.object(
                beta_artifacts,
                "read_committed_tree",
                return_value=committed,
            ),
            mock.patch.object(
                beta_artifacts,
                "_run_beta_binary",
                return_value=(
                    beta_artifacts.expected_version_document(self.snapshot),
                    binary.help_sha256,
                ),
            ),
        ):
            report = beta_artifacts.build_beta_candidate(
                root=ROOT,
                output=output,
                source_freeze=source_freeze,
                builder_id="test://source-freeze-builder",
                git_path=Path(sys.executable),
                binary_builder=builder,
            )
        host_gate.assert_called()
        self.assertGreaterEqual(snapshot_gate.call_count, 3)
        self.assertTrue(observed_source)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            (output / beta_artifacts.SOURCE_ARCHIVE_PATH).read_bytes(),
            frozen_archive,
        )
        self.assertEqual(
            (output / beta_artifacts.SOURCE_DESCRIPTOR_PATH).read_bytes(),
            frozen_descriptor,
        )

        mismatched = beta_artifacts.GitSnapshot(
            revision="3" * 40,
            tree=self.snapshot.tree,
            source_date_epoch=self.snapshot.source_date_epoch,
            generated_at=self.snapshot.generated_at,
        )
        rejected_output = self.base / "mismatched-candidate"
        with (
            mock.patch.object(
                beta_artifacts,
                "require_declared_host",
                return_value=self.qualified_host(),
            ),
            mock.patch.object(
                beta_artifacts,
                "inspect_clean_snapshot",
                return_value=mismatched,
            ),
        ):
            with self.assertRaisesRegex(
                beta_artifacts.BetaArtifactError, "checkout identity"
            ):
                beta_artifacts.build_beta_candidate(
                    root=ROOT,
                    output=rejected_output,
                    source_freeze=source_freeze,
                    builder_id="test://mismatched-builder",
                    git_path=Path(sys.executable),
                    binary_builder=builder,
                )
        self.assertFalse(rejected_output.exists())

    def test_version_identity_is_exact_and_fail_closed(self) -> None:
        expected = beta_artifacts.expected_version_document(self.snapshot)
        self.assertEqual(set(expected), beta_artifacts.EXPECTED_VERSION_KEYS)
        self.assertEqual(
            beta_artifacts.validate_version_document(expected, self.snapshot), expected
        )
        for mutation in (
            {**expected, "production_ready": True},
            {**expected, "enabled_features": ["full"]},
            {**expected, "source_revision": "3" * 40},
            {**expected, "unexpected": "field"},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(beta_artifacts.BetaArtifactError):
                    beta_artifacts.validate_version_document(mutation, self.snapshot)

    def test_declared_host_requires_two_exact_glibc_identities(self) -> None:
        observed = self.qualified_host()
        observed.pop("runtime_baseline")
        observed.pop("target")
        with mock.patch.object(beta_artifacts, "_host_platform", return_value=observed):
            self.assertEqual(
                beta_artifacts.require_declared_host(), self.qualified_host()
            )

        for field, value in (
            ("libc", "libc"),
            ("libc_version", "2.38"),
            ("glibc_identity", "glibc 2.38"),
            ("glibc_identity", ""),
        ):
            substituted = {**observed, field: value}
            with (
                self.subTest(field=field, value=value),
                mock.patch.object(
                    beta_artifacts, "_host_platform", return_value=substituted
                ),
            ):
                with self.assertRaisesRegex(
                    beta_artifacts.BetaArtifactError, "exact|qualified|baseline"
                ):
                    beta_artifacts.require_declared_host()

    def test_elf_validation_rejects_wrong_platform_and_incomplete_headers(self) -> None:
        beta_artifacts.validate_elf_linux_x86_64(synthetic_elf())
        for mutation in (
            b"MZ" + synthetic_elf()[2:],
            synthetic_elf()[:18] + struct.pack("<H", 183) + synthetic_elf()[20:],
            synthetic_elf()[:24] + b"\0" * 8 + synthetic_elf()[32:],
            synthetic_elf()[:120] + struct.pack("<I", 0) + synthetic_elf()[124:],
        ):
            with self.assertRaises(beta_artifacts.BetaArtifactError):
                beta_artifacts.validate_elf_linux_x86_64(mutation)

    def test_cargo_closure_requires_only_beta_feature_and_excludes_subsystems(
        self,
    ) -> None:
        root_id = "path+file:///src/cigar-cli#0.1.0"
        canon_id = "path+file:///src/cigar-canon#0.1.0"
        dependency_id = "registry+https://example.invalid#indexed@1.0.0"
        document = {
            "workspace_members": [root_id, canon_id],
            "packages": [
                {
                    "id": root_id,
                    "name": "cigar-cli",
                    "version": "0.1.0",
                    "license": "Apache-2.0",
                    "source": None,
                    "manifest_path": str(
                        (ROOT / "crates/cigar-cli/Cargo.toml").resolve()
                    ),
                },
                {
                    "id": canon_id,
                    "name": "cigar-canon",
                    "version": "0.1.0",
                    "license": "Apache-2.0",
                    "source": None,
                    "manifest_path": str(
                        (ROOT / "crates/cigar-canon/Cargo.toml").resolve()
                    ),
                },
                {
                    "id": dependency_id,
                    "name": "serde",
                    "version": "1.0.0",
                    "license": "MIT OR Apache-2.0",
                    "source": "registry+https://example.invalid/index",
                    "checksum": "a" * 64,
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": root_id,
                        "features": ["beta-embedded"],
                        "deps": [
                            {
                                "pkg": canon_id,
                                "dep_kinds": [{"kind": None, "target": None}],
                            },
                            {
                                "pkg": dependency_id,
                                "dep_kinds": [{"kind": None, "target": None}],
                            },
                        ],
                    },
                    {"id": canon_id, "features": [], "deps": []},
                    {"id": dependency_id, "features": [], "deps": []},
                ]
            },
        }
        components, dependencies = beta_artifacts._cargo_components(
            document, root=ROOT, enforce_pinned=False
        )
        self.assertEqual(
            [component["name"] for component in components],
            ["cigar-canon", "cigar-cli", "serde"],
        )
        self.assertEqual(len(dependencies), 3)

        wrong_feature = copy.deepcopy(document)
        wrong_feature["resolve"]["nodes"][0]["features"] = ["full"]
        with self.assertRaisesRegex(
            beta_artifacts.BetaArtifactError, "only beta-embedded"
        ):
            beta_artifacts._cargo_components(
                wrong_feature, root=ROOT, enforce_pinned=False
            )

        forbidden = copy.deepcopy(document)
        forbidden_id = "path+file:///src/cigar-daemon#0.1.0"
        forbidden["packages"].append(
            {
                "id": forbidden_id,
                "name": "cigar-daemon",
                "version": "0.1.0",
                "license": "Apache-2.0",
            }
        )
        forbidden["resolve"]["nodes"][0]["deps"].append(
            {
                "pkg": forbidden_id,
                "dep_kinds": [{"kind": "dev", "target": None}],
            }
        )
        forbidden["resolve"]["nodes"].append(
            {"id": forbidden_id, "features": [], "deps": []}
        )
        dev_components, _ = beta_artifacts._cargo_components(
            forbidden, root=ROOT, enforce_pinned=False
        )
        self.assertNotIn(
            "cigar-daemon", [component["name"] for component in dev_components]
        )
        forbidden["resolve"]["nodes"][0]["deps"][-1]["dep_kinds"] = [
            {"kind": None, "target": None}
        ]
        with self.assertRaisesRegex(
            beta_artifacts.BetaArtifactError, "excluded packages"
        ):
            beta_artifacts._cargo_components(forbidden, root=ROOT, enforce_pinned=False)

    def test_deterministic_archive_is_byte_identical_and_create_new(self) -> None:
        entries = [beta_artifacts.CommittedEntry("NOTICE", b"deterministic\n", 0o644)]
        metadata = beta_artifacts._metadata(
            artifact_id="source",
            contract_path="packaging/beta/contracts/source-archive.v1.json",
            contract_sha256="a" * 64,
            snapshot=self.snapshot,
            payload=entries,
            build=beta_artifacts._source_build_record(),
        )
        first = self.base / "one.tar.gz"
        second = self.base / "two.tar.gz"
        beta_artifacts.write_deterministic_archive(
            first, entries, metadata, self.snapshot.source_date_epoch
        )
        beta_artifacts.write_deterministic_archive(
            second, entries, metadata, self.snapshot.source_date_epoch
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())
        before = first.read_bytes()
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "overwrite"):
            beta_artifacts.write_deterministic_archive(
                first, entries, metadata, self.snapshot.source_date_epoch
            )
        self.assertEqual(first.read_bytes(), before)

        policy = beta_artifacts._contract_policy(
            ROOT, beta_profile.expected_artifact_matrix()["artifacts"][0]
        )
        beta_artifacts._read_canonical_tar(
            before,
            epoch=self.snapshot.source_date_epoch,
            policy=policy,
            retained=["RELEASE-METADATA.json"],
        )
        raw_tar = bytearray(gzip.decompress(before))
        raw_tar[-1] = 1
        post_end = io.BytesIO()
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=post_end,
            mtime=self.snapshot.source_date_epoch,
        ) as compressed:
            compressed.write(raw_tar)
        corrupted_footer = bytearray(before)
        corrupted_footer[-8] ^= 1
        mutations = {
            "appended": before + b"trailing",
            "concatenated": before + before,
            "truncated": before[:-8],
            "bad-footer": bytes(corrupted_footer),
            "nonzero-post-end": post_end.getvalue(),
        }
        for name, mutation in mutations.items():
            with self.subTest(noncanonical_archive=name):
                with self.assertRaisesRegex(
                    beta_artifacts.BetaArtifactError,
                    "canonical|inspect|trailing|concatenated|truncated|ambiguous|invalid",
                ):
                    beta_artifacts._read_canonical_tar(
                        mutation,
                        epoch=self.snapshot.source_date_epoch,
                        policy=policy,
                        retained=["RELEASE-METADATA.json"],
                    )

    def test_tar_structure_rejects_traversal_links_modes_and_unicode(self) -> None:
        unsafe_cases = (
            ("traversal", [("../escape", b"x", 0o644, None)]),
            ("symlink", [("link", b"", 0o644, tarfile.SYMTYPE)]),
            ("mode", [("file", b"x", 0o666, None)]),
            (
                "unicode",
                [(unicodedata.normalize("NFD", "café"), b"x", 0o644, None)],
            ),
        )
        for name, entries in unsafe_cases:
            with self.subTest(name=name):
                archive = self.base / f"{name}.tar.gz"
                custom_archive(archive, self.snapshot.source_date_epoch, list(entries))
                with self.assertRaises(beta_artifacts.ReleaseError):
                    beta_artifacts._read_canonical_tar(
                        archive.read_bytes(),
                        epoch=self.snapshot.source_date_epoch,
                        policy={
                            "max_entries": 16,
                            "max_member_bytes": 1024,
                            "max_total_bytes": 4096,
                            "content_scan_exemptions": [],
                        },
                        retained=[],
                    )
        bomb = io.BytesIO()
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=bomb,
            mtime=self.snapshot.source_date_epoch,
        ) as compressed:
            compressed.write(b"\0" * (2 * 1024 * 1024))
        with self.assertRaisesRegex(
            beta_artifacts.BetaArtifactError, "expansion limit"
        ):
            beta_artifacts._read_canonical_tar(
                bomb.getvalue(),
                epoch=self.snapshot.source_date_epoch,
                policy={
                    "max_entries": 1,
                    "max_member_bytes": 1024,
                    "max_total_bytes": 1024,
                    "content_scan_exemptions": [],
                },
                retained=[],
            )

    def test_crlf_and_committed_source_substitution_are_rejected(self) -> None:
        matrix_entry = beta_profile.expected_artifact_matrix()["artifacts"][0]
        policy = beta_artifacts._contract_policy(ROOT, matrix_entry)
        crlf_entry = beta_artifacts.CommittedEntry(
            "NOTICE", b"not canonical\r\n", 0o644
        )
        metadata = beta_artifacts._metadata(
            artifact_id="source",
            contract_path=str(matrix_entry["contract"]),
            contract_sha256=sha256_file(policy["path"]),
            snapshot=self.snapshot,
            payload=[crlf_entry],
            build=beta_artifacts._source_build_record(),
        )
        archive = self.base / "crlf.tar.gz"
        beta_artifacts.write_deterministic_archive(
            archive, [crlf_entry], metadata, self.snapshot.source_date_epoch
        )
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "non-LF"):
            beta_artifacts.verify_beta_archive(
                root=ROOT,
                archive_payload=archive.read_bytes(),
                archive_name=archive.name,
                matrix_entry=matrix_entry,
                source_descriptor={
                    "git": {
                        "revision": self.snapshot.revision,
                        "tree": self.snapshot.tree,
                    }
                },
                snapshot=self.snapshot,
                committed={"NOTICE": crlf_entry},
                execute_binary=False,
            )

        attributes = {
            "NOTICE": {
                "sha256": sha256_bytes(b"substituted\n"),
                "size": len(b"reviewed\n"),
                "mode": 0o644,
            }
        }
        with mock.patch.object(
            beta_profile,
            "expected_source_archives",
            return_value={
                "archives": [{"id": "source", "include": ["NOTICE"]}],
                "always_exclude": [],
            },
        ):
            with self.assertRaisesRegex(
                beta_artifacts.BetaArtifactError, "substituted committed"
            ):
                beta_artifacts._validate_committed_payload(
                    matrix_entry=matrix_entry,
                    attributes=attributes,
                    committed={
                        "NOTICE": beta_artifacts.CommittedEntry(
                            "NOTICE", b"reviewed\n", 0o644
                        )
                    },
                )

    def test_default_offline_verification_never_executes_candidate(self) -> None:
        candidate = self.build_candidate()
        with mock.patch.object(
            beta_artifacts,
            "_run_beta_binary",
            side_effect=AssertionError("unsigned binary execution attempted"),
        ) as runner:
            report = beta_artifacts.verify_beta_candidate(
                root=ROOT,
                candidate=candidate,
                strict_read_only=False,
                snapshot_override=self.snapshot,
                committed_override=self.committed,
                resolution_override=(self.cargo_components, self.cargo_dependencies),
            )
        runner.assert_not_called()
        self.assertFalse(report["checks"]["binary_executed"])
        recorded = json.loads(
            (candidate / beta_artifacts.VERIFICATION_PATH).read_text()
        )
        self.assertTrue(recorded["checks"]["binary_executed"])
        self.assert_release_verification_schema(recorded)
        self.assert_release_verification_schema(report)

    def test_spdx_and_cyclonedx_member_component_parity_is_exact(self) -> None:
        self.build_candidate()
        beta_artifacts._validate_spdx(
            document=self.spdx,
            snapshot=self.snapshot,
            artifacts=self.artifacts,
            components=self.components,
            dependencies=self.dependencies,
            member_bindings=self.member_bindings,
        )
        substituted = copy.deepcopy(self.spdx)
        substituted["files"][0]["checksums"][0]["checksumValue"] = "f" * 64
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "SPDX"):
            beta_artifacts._validate_spdx(
                document=substituted,
                snapshot=self.snapshot,
                artifacts=self.artifacts,
                components=self.components,
                dependencies=self.dependencies,
                member_bindings=self.member_bindings,
            )
        omitted_components = [
            component
            for component in self.components
            if component["name"] != "libc.so.6"
        ]
        omitted_refs = {component["bom-ref"] for component in omitted_components}
        omitted_dependencies = [
            {
                "ref": edge["ref"],
                "dependsOn": [
                    reference
                    for reference in edge["dependsOn"]
                    if reference in omitted_refs
                ],
            }
            for edge in self.dependencies
            if edge["ref"] in omitted_refs
        ]
        self_consistent_omission = beta_artifacts.build_beta_sbom(
            snapshot=self.snapshot,
            artifacts=self.artifacts,
            components=omitted_components,
            dependencies=omitted_dependencies,
            member_bindings=self.member_bindings,
        )
        with self.assertRaisesRegex(
            beta_artifacts.BetaArtifactError, "resolved component closure"
        ):
            beta_artifacts._validate_sbom(
                document=self_consistent_omission,
                snapshot=self.snapshot,
                artifacts=self.artifacts,
                member_bindings=self.member_bindings,
                expected_components=self.components,
                expected_dependencies=self.dependencies,
            )

    def test_rustup_home_is_preserved_without_exported_environment(self) -> None:
        cargo_home = self.base / ".cargo"
        rustup_home = self.base / ".rustup"
        target = self.base / "target"
        cargo_home.mkdir(mode=0o700)
        rustup_home.mkdir()
        target.mkdir()
        executable = Path(sys.executable).resolve()
        with (
            mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)}, clear=True),
            mock.patch.object(beta_artifacts.Path, "home", return_value=self.base),
        ):
            environment = beta_artifacts._cargo_environment(
                root=ROOT,
                target_directory=target,
                snapshot=self.snapshot,
                cargo=executable,
                rustc=executable,
                linker=executable,
                cargo_home=cargo_home,
            )
        self.assertEqual(environment["RUSTUP_HOME"], str(rustup_home))

    def test_rustup_proxy_invocation_name_is_preserved_in_private_stage(self) -> None:
        backing = self.base / "rustup"
        backing.write_bytes(Path(sys.executable).read_bytes())
        os.chmod(backing, 0o500)
        proxy = self.base / "cargo"
        proxy.symlink_to(backing)
        selected = beta_artifacts._secure_executable(proxy, "cargo")
        self.assertEqual(selected, proxy)
        staged = beta_artifacts._stage_executable(
            selected, "cargo", self.base / "staged-tools"
        )
        self.assertEqual(staged.name, "cargo")
        self.assertFalse(staged.is_symlink())
        self.assertEqual(staged.read_bytes(), backing.read_bytes())

    def test_complete_candidate_chain_and_substitution_rejection(self) -> None:
        candidate = self.build_candidate()
        verification = beta_artifacts.verify_beta_candidate(
            root=ROOT,
            candidate=candidate,
            strict_read_only=False,
            execute_binary=False,
            snapshot_override=self.snapshot,
            committed_override=self.committed,
            resolution_override=(self.cargo_components, self.cargo_dependencies),
        )
        self.assertEqual(verification["status"], "passed")
        self.assertFalse(verification["checks"]["binary_executed"])
        self.assertFalse(verification["checks"]["signed"])

        extra = candidate / "extra.txt"
        beta_artifacts._write_private(extra, b"substitution\n")
        with self.assertRaisesRegex(
            beta_artifacts.BetaArtifactError, "inventory mismatch"
        ):
            beta_artifacts.verify_beta_candidate(
                root=ROOT,
                candidate=candidate,
                strict_read_only=False,
                execute_binary=False,
                snapshot_override=self.snapshot,
                committed_override=self.committed,
                resolution_override=(self.cargo_components, self.cargo_dependencies),
            )
        extra.unlink()

        manifest_path = candidate / beta_artifacts.BUILD_MANIFEST_PATH
        canonical_manifest = manifest_path.read_bytes()
        manifest = json.loads(canonical_manifest)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "not canonical"):
            beta_artifacts.verify_beta_candidate(
                root=ROOT,
                candidate=candidate,
                strict_read_only=False,
                execute_binary=False,
                snapshot_override=self.snapshot,
                committed_override=self.committed,
                resolution_override=(self.cargo_components, self.cargo_dependencies),
            )
        manifest_path.write_bytes(canonical_manifest)

        artifact_path = candidate / str(manifest["artifacts"][0]["path"])
        with artifact_path.open("ab") as handle:
            handle.write(b"substitution")
        with self.assertRaisesRegex(beta_artifacts.BetaArtifactError, "byte binding"):
            beta_artifacts.verify_beta_candidate(
                root=ROOT,
                candidate=candidate,
                strict_read_only=False,
                execute_binary=False,
                snapshot_override=self.snapshot,
                committed_override=self.committed,
                resolution_override=(self.cargo_components, self.cargo_dependencies),
            )


if __name__ == "__main__":
    unittest.main()
