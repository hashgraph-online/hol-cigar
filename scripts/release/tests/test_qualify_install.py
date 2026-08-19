#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import qualify_install  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class InstallQualificationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-install-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.archive = self.base / "candidate.tar"
        self.contract = self.base / "contract.json"
        self.runtime_build_receipt = self.base / "runtime-build-receipt.json"
        self.tool_archive = self.base / "qualification-tool.tar"
        self.tool_contract = self.base / "qualification-tool-contract.json"
        self.tool_build_receipt = self.base / "tool-build-receipt.json"
        self.driver = self.base / "driver"
        self.archive.write_bytes(b"candidate")
        self.contract.write_text("{}\n", encoding="utf-8")
        self.runtime_build_receipt.write_text("{}\n", encoding="utf-8")
        self.tool_archive.write_bytes(b"qualification-tool")
        self.tool_contract.write_text("{}\n", encoding="utf-8")
        self.tool_build_receipt.write_text("{}\n", encoding="utf-8")
        self.driver.write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(self.driver, 0o700)

    def macos_system_tool_environment(self) -> dict[str, str]:
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.base)}
        command_line_tools = Path("/Library/Developer/CommandLineTools")
        if command_line_tools.is_dir():
            environment["DEVELOPER_DIR"] = str(command_line_tools)
        return environment

    def arguments(
        self,
        *,
        report: Path | None,
        evidence_dir: Path | None = None,
        archive: Path | None = None,
        contract: Path | None = None,
        runtime_build_receipt: Path | None = None,
        tool_archive: Path | None = None,
        tool_contract: Path | None = None,
        tool_build_receipt: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            archive=archive or self.archive,
            contract=contract or self.contract,
            runtime_build_receipt=(runtime_build_receipt or self.runtime_build_receipt),
            qualification_tool_archive=tool_archive or self.tool_archive,
            qualification_tool_contract=tool_contract or self.tool_contract,
            qualification_tool_build_receipt=(
                tool_build_receipt or self.tool_build_receipt
            ),
            expected_artifact_id=qualify_install.RUNTIME_ARTIFACT_ID,
            expected_target="aarch64-apple-darwin",
            expected_version=qualify_install.DEFAULT_PRODUCT_VERSION,
            expected_abi="cigar.context.v1",
            report=report,
            evidence_dir=evidence_dir,
        )

    def run_main(
        self,
        arguments: argparse.Namespace,
        report: dict[str, object],
        *,
        environment: dict[str, str] | None = None,
    ) -> str:
        stdout = io.StringIO()
        with (
            mock.patch.dict(os.environ, environment or {}, clear=True),
            mock.patch.object(
                qualify_install, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(qualify_install, "_qualify", return_value=report),
            redirect_stdout(stdout),
        ):
            self.assertEqual(qualify_install.main(), 0)
        return stdout.getvalue()

    @staticmethod
    def source_identity() -> dict[str, object]:
        return {
            "revision": "d" * 40,
            "tree_sha256": "e" * 64,
            "committed": True,
            "clean": True,
        }

    @staticmethod
    def build_tools() -> list[dict[str, object]]:
        return [
            {
                "name": name,
                "version": f"{name} 1.0",
                "sha256": character * 64,
                "bytes": index + 1,
            }
            for index, (name, character) in enumerate(
                (("cargo", "1"), ("protoc", "2"), ("rustc", "3"))
            )
        ]

    @staticmethod
    def installed_workflow(
        artifact_id: str,
        artifact_sha256: str,
        source_revision: str,
        *,
        executable_sha256: str = "f" * 64,
    ) -> dict[str, object]:
        workflow: dict[str, object] = {
            "profile": qualify_install.INSTALLED_WORKFLOW_PROFILE,
            "full_surface_sha256": "1" * 64,
            "semantic_identity_sha256": "2" * 64,
            "cigar_sha256": executable_sha256,
            "cigard_sha256": executable_sha256,
            "binding_sha256": "0" * 64,
            "no_egress_enforcement": qualify_install.MACOS_NO_EGRESS_ENFORCEMENT,
        }
        workflow["binding_sha256"] = qualify_install._installed_workflow_binding(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            source_revision=source_revision,
            workflow=workflow,
        )
        return workflow

    def runtime_receipt(
        self,
        *,
        archive_sha256: str = "a" * 64,
        archive_bytes: int = 42,
        contract_sha256: str = "b" * 64,
        contract_bytes: int = 43,
    ) -> dict[str, object]:
        contract_path = "packaging/contracts/macos-runtime-archive.v1.json"
        authority = {
            path: {"sha256": "c" * 64, "bytes": 1}
            for path in qualify_install.RUNTIME_RECEIPT_AUTHORITY_PATHS
        }
        authority[contract_path] = {
            "sha256": contract_sha256,
            "bytes": contract_bytes,
        }
        return {
            "schema_version": qualify_install.RUNTIME_BUILD_RECEIPT_SCHEMA,
            "status": "built-unqualified",
            "artifact_id": qualify_install.RUNTIME_ARTIFACT_ID,
            "target": qualify_install.MACOS_TARGET,
            "product_version": qualify_install.DEFAULT_PRODUCT_VERSION,
            "context_abi": "cigar.context.v1",
            "runtime_profile": qualify_install.RUNTIME_PROFILE,
            "source_date_epoch": 1_700_000_000,
            "source": self.source_identity(),
            "host": {
                "platform": "macos",
                "architecture": "arm64",
                "target_triple": qualify_install.MACOS_TARGET,
                "macos_version": "15.0",
            },
            "archive": {
                "path": "candidate.tar.gz",
                "sha256": archive_sha256,
                "bytes": archive_bytes,
            },
            "contract": {"path": contract_path, "sha256": contract_sha256},
            "authority": authority,
            "build_tools": self.build_tools(),
            "build_environment": {
                "cargo_network_offline": True,
                "network_enforcement": "darwin-sandbox-exec-deny-network-v1",
                "sandbox_launcher": "/usr/bin/sandbox-exec",
                "sandbox_policy": "(version 1)(allow default)(deny network*)",
            },
            "runtime_payload": {
                name: {"path": f"bin/{name}", "sha256": "f" * 64, "bytes": 32}
                for name in qualify_install.REQUIRED_INSTALLED_BINARIES
            },
            "payload_file_count": 11,
            "package_verification": {
                "schema_version": "cigar.package-verification.v1",
                "status": "passed",
                "file_count": 12,
                "expanded_bytes": 1024,
            },
            "claims": {
                "development_build": False,
                "developer_preview_build": True,
                "distribution_signed": False,
                "notarized": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        }

    def tool_receipt(
        self,
        *,
        archive_sha256: str = "a" * 64,
        archive_bytes: int = 42,
        contract_sha256: str = "b" * 64,
        contract_bytes: int = 43,
    ) -> dict[str, object]:
        contract_path = "packaging/contracts/macos-conformance-runner.v1.json"
        authority = {
            path: {"sha256": "c" * 64, "bytes": 1}
            for path in qualify_install.QUALIFICATION_TOOL_RECEIPT_AUTHORITY_PATHS
        }
        authority[contract_path] = {
            "sha256": contract_sha256,
            "bytes": contract_bytes,
        }
        return {
            "schema_version": qualify_install.QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA,
            "status": "built-unqualified",
            "artifact_id": qualify_install.QUALIFICATION_TOOL_ARTIFACT_ID,
            "target": qualify_install.MACOS_TARGET,
            "product_version": qualify_install.DEFAULT_PRODUCT_VERSION,
            "context_abi": "cigar.context.v1",
            "source_date_epoch": 1_700_000_000,
            "source": self.source_identity(),
            "host": {
                "platform": "macos",
                "architecture": "arm64",
                "target_triple": qualify_install.MACOS_TARGET,
                "macos_version": "15.0",
            },
            "archive": {
                "path": "tool.tar.gz",
                "sha256": archive_sha256,
                "bytes": archive_bytes,
            },
            "install_target": "bin/cigar-conformance",
            "contract": {"path": contract_path, "sha256": contract_sha256},
            "authority": authority,
            "build_tools": self.build_tools(),
            "build_environment": {
                "network_enforcement": "darwin-sandbox-exec-deny-network-v1",
                "sandbox_launcher": "/usr/bin/sandbox-exec",
                "sandbox_policy": "(version 1)(allow default)(deny network*)",
            },
            "invocation_probes": [
                {
                    "command": "bin/cigar-conformance --help",
                    "status": "passed",
                    "scope": "invocation-only",
                    "qualifying_evidence": False,
                },
                {
                    "command": "bin/cigar-install-qualifier --help",
                    "status": "passed",
                    "scope": "invocation-only",
                    "qualifying_evidence": False,
                },
            ],
            "payload": {
                path: {"sha256": "f" * 64, "bytes": 32, "mode": "0755"}
                for path in (
                    "bin/cigar-conformance",
                    "bin/cigar-install-qualifier",
                )
            },
            "package_verification": {
                "schema_version": "cigar.package-verification.v1",
                "status": "passed",
                "file_count": 20,
                "expanded_bytes": 2048,
            },
            "claims": {
                "development_build": False,
                "developer_preview_build": True,
                "candidate": False,
                "distribution_signed": False,
                "notarized": False,
                "installed_qualified": False,
                "conformance_qualified": False,
                "benchmark_efficacy": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        }

    def test_candidate_report_is_external_canonical_owner_only_and_create_new(
        self,
    ) -> None:
        evidence = self.base / "evidence"
        arguments = self.arguments(
            report=Path("install/result.json"), evidence_dir=evidence
        )
        report = {"z": 1, "a": [True, None], "status": "passed"}

        stdout = self.run_main(arguments, report)

        destination = evidence / "install" / "result.json"
        self.assertEqual(
            destination.read_bytes(), b'{"a":[true,null],"status":"passed","z":1}\n'
        )
        self.assertEqual(json.loads(stdout), report)
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        self.assertEqual(destination.stat().st_nlink, 1)

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                qualify_install, "parse_arguments", return_value=arguments
            ),
            mock.patch.object(
                qualify_install, "_qualify", return_value={"replaced": True}
            ),
            self.assertRaisesRegex(EvidenceWorkspaceError, "overwrite"),
        ):
            qualify_install.main()
        self.assertEqual(
            destination.read_bytes(), b'{"a":[true,null],"status":"passed","z":1}\n'
        )

    def test_stdout_only_development_path_does_not_create_ambient_workspace(
        self,
    ) -> None:
        unused = self.base / "unused"
        arguments = self.arguments(report=None)
        report = {"status": "passed"}

        stdout = self.run_main(
            arguments,
            report,
            environment={"CIGAR_EVIDENCE_DIR": str(unused)},
        )

        self.assertEqual(json.loads(stdout), report)
        self.assertFalse(unused.exists())

        explicit = self.arguments(report=None, evidence_dir=self.base / "explicit")
        self.run_main(explicit, report)
        self.assertFalse((self.base / "explicit").exists())

    def test_report_requires_workspace_and_selection_rejects_conflict(self) -> None:
        without_workspace = self.arguments(report=Path("report.json"))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "requires --evidence-dir"):
                qualify_install._ReportOutput.open(without_workspace)

        conflicting = self.arguments(
            report=Path("report.json"), evidence_dir=self.base / "argument"
        )
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "environment")},
            clear=True,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                qualify_install._ReportOutput.open(conflicting)

        relative = self.arguments(report=None, evidence_dir=Path("relative-evidence"))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "absolute path"):
                qualify_install._ReportOutput.open(relative)

    def test_report_rejects_escape_absolute_and_all_input_aliases(self) -> None:
        evidence = self.base / "paths"
        for report in (
            Path("../escaped.json"),
            Path("nested/../../escaped.json"),
            self.base / "absolute.json",
            Path("nested\\report.json"),
        ):
            with self.subTest(report=report):
                arguments = self.arguments(report=report, evidence_dir=evidence)
                with mock.patch.dict(os.environ, {}, clear=True):
                    with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
                        qualify_install._ReportOutput.open(arguments)
        self.assertFalse(evidence.exists())

        alias_root = self.base / "aliases"
        alias_root.mkdir(mode=0o700)
        for name in (
            "archive",
            "contract",
            "runtime_build_receipt",
            "tool_archive",
            "tool_contract",
            "tool_build_receipt",
        ):
            aliased = alias_root / f"{name}.json"
            aliased.write_bytes(b"input")
            os.chmod(aliased, 0o400)
            inputs = {
                "archive": self.archive,
                "contract": self.contract,
                "runtime_build_receipt": self.runtime_build_receipt,
                "tool_archive": self.tool_archive,
                "tool_contract": self.tool_contract,
                "tool_build_receipt": self.tool_build_receipt,
            }
            inputs[name] = aliased
            arguments = self.arguments(
                report=Path(aliased.name),
                evidence_dir=alias_root,
                archive=inputs["archive"],
                contract=inputs["contract"],
                runtime_build_receipt=inputs["runtime_build_receipt"],
                tool_archive=inputs["tool_archive"],
                tool_contract=inputs["tool_contract"],
                tool_build_receipt=inputs["tool_build_receipt"],
            )
            with self.subTest(input=name), mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ReleaseError, "must not replace an input"):
                    qualify_install._ReportOutput.open(arguments)

    def test_workspace_rejects_repository_links_collisions_modes_and_rebound(
        self,
    ) -> None:
        internal = self.arguments(
            report=Path("report.json"),
            evidence_dir=qualify_install.REPOSITORY_ROOT / "reports" / "install",
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(EvidenceWorkspaceError, "outside"):
                qualify_install._ReportOutput.open(internal)

        target = self.base / "target"
        target.mkdir(mode=0o700)
        alias = self.base / "linked"
        alias.symlink_to(target, target_is_directory=True)
        linked = self.arguments(report=Path("report.json"), evidence_dir=alias)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(EvidenceWorkspaceError):
                qualify_install._ReportOutput.open(linked)

        public = self.base / "public"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        insecure = self.arguments(report=Path("report.json"), evidence_dir=public)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(EvidenceWorkspaceError, "0700"):
                qualify_install._ReportOutput.open(insecure)

        collision_root = self.base / "collision"
        collision_root.mkdir(mode=0o700)
        existing = collision_root / "Result.json"
        existing.write_text("{}\n", encoding="utf-8")
        os.chmod(existing, 0o400)
        collision_arguments = self.arguments(
            report=Path("result.json"), evidence_dir=collision_root
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            output = qualify_install._ReportOutput.open(collision_arguments)
        self.assertIsNotNone(output)
        assert output is not None
        self.addCleanup(output.close)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "collision"):
            output.publish({"status": "passed"})

        rebound_root = self.base / "rebound"
        rebound_arguments = self.arguments(
            report=Path("report.json"), evidence_dir=rebound_root
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            rebound = qualify_install._ReportOutput.open(rebound_arguments)
        self.assertIsNotNone(rebound)
        assert rebound is not None
        self.addCleanup(rebound.close)
        displaced = self.base / "displaced"
        rebound_root.rename(displaced)
        rebound_root.mkdir(mode=0o700)
        with self.assertRaisesRegex(EvidenceWorkspaceError, "no longer names"):
            rebound.publish({"status": "passed"})
        self.assertFalse((displaced / "report.json").exists())
        self.assertFalse((rebound_root / "report.json").exists())

    def test_child_environment_never_inherits_parent_evidence_workspace(self) -> None:
        ambient = self.base / "parent-evidence"
        install = self.base / "install"
        isolated = self.base / "isolated"
        with mock.patch.dict(
            os.environ, {"CIGAR_EVIDENCE_DIR": str(ambient)}, clear=False
        ):
            environment = qualify_install._qualification_environment(install, isolated)
        self.assertNotIn("CIGAR_EVIDENCE_DIR", environment)
        self.assertEqual(environment["CIGAR_NO_EGRESS_ENFORCED"], "1")
        self.assertEqual(environment["PATH"], str(install / "bin"))

    def test_secure_input_staging_rejects_links_and_insecure_or_nonexecuting_files(
        self,
    ) -> None:
        destination_root = self.base / "staged"
        destination_root.mkdir(mode=0o700)

        linked = self.base / "linked-driver"
        linked.symlink_to(self.driver)
        with self.assertRaisesRegex(ReleaseError, "securely stage"):
            qualify_install._stage_secure_input(
                linked,
                destination_root / "linked",
                1024,
                "linked driver",
                executable=True,
            )

        hardlink = self.base / "hardlinked-driver"
        os.link(self.driver, hardlink)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            qualify_install._stage_secure_input(
                self.driver,
                destination_root / "hardlink",
                1024,
                "hardlinked driver",
                executable=True,
            )
        hardlink.unlink()

        os.chmod(self.driver, 0o600)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            qualify_install._stage_secure_input(
                self.driver,
                destination_root / "nonexecuting",
                1024,
                "nonexecuting driver",
                executable=True,
            )

        os.chmod(self.driver, 0o722)
        with self.assertRaisesRegex(ReleaseError, "owner-controlled"):
            qualify_install._stage_secure_input(
                self.driver,
                destination_root / "writable",
                1024,
                "writable driver",
                executable=True,
            )

    def test_secure_input_staging_binds_exact_bytes_and_private_mode(self) -> None:
        source = self.base / "secure-input"
        source.write_bytes(b"exact-input")
        os.chmod(source, 0o700)
        destination = self.base / "staged-input"
        digest, size = qualify_install._stage_secure_input(
            source,
            destination,
            1024,
            "secure input",
            executable=True,
        )
        self.assertEqual(
            digest,
            "00e516abfd60d0cb0354695ab452c47172fd780314fe5d7b7514e998820dbf63",
        )
        self.assertEqual(size, len(b"exact-input"))
        self.assertEqual(destination.read_bytes(), b"exact-input")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o500)

    def test_macos_runtime_contract_requires_both_production_sidecars(self) -> None:
        contract = (
            qualify_install.REPOSITORY_ROOT
            / "packaging/contracts/macos-runtime-archive.v1.json"
        )
        self.assertEqual(
            qualify_install._required_binary_names(contract),
            ("cigar", "cigard", "cigar-mcp", "cigar-claude-hook"),
        )

    def test_honey_documented_qualifier_command_uses_runtime_profile_id(self) -> None:
        root = qualify_install.REPOSITORY_ROOT
        commands = json.loads((root / "docs/commands.v1.json").read_bytes())
        command = next(
            row for row in commands["commands"] if row.get("id") == "install-archive"
        )
        index = command["argv"].index("--expected-artifact-id")
        self.assertEqual(
            command["argv"][index + 1], qualify_install.RUNTIME_ARTIFACT_ID
        )
        guide = (root / "docs/guides/install.md").read_text(encoding="utf-8")
        self.assertIn(
            f"--expected-artifact-id {qualify_install.RUNTIME_ARTIFACT_ID}", guide
        )

    def test_official_build_receipts_require_exact_source_archive_and_contract_bindings(
        self,
    ) -> None:
        runtime = self.runtime_receipt()
        parsed_runtime = qualify_install._validate_runtime_build_receipt(
            json.dumps(runtime).encode(),
            archive_name="candidate.tar.gz",
            archive_sha256="a" * 64,
            archive_bytes=42,
            contract_sha256="b" * 64,
            contract_bytes=43,
            product_version=qualify_install.DEFAULT_PRODUCT_VERSION,
            context_abi="cigar.context.v1",
            source=self.source_identity(),
        )
        self.assertEqual(parsed_runtime, runtime)

        tool = self.tool_receipt()
        parsed_tool = qualify_install._validate_qualification_tool_build_receipt(
            json.dumps(tool).encode(),
            archive_name="tool.tar.gz",
            archive_sha256="a" * 64,
            archive_bytes=42,
            contract_sha256="b" * 64,
            contract_bytes=43,
            product_version=qualify_install.DEFAULT_PRODUCT_VERSION,
            context_abi="cigar.context.v1",
            source=self.source_identity(),
        )
        self.assertEqual(parsed_tool, tool)
        self.assertEqual(
            qualify_install._validate_same_source_identity(
                self.source_identity(), self.source_identity()
            ),
            (self.source_identity(), self.source_identity()),
        )
        qualify_install._validate_shared_build_authority(runtime, tool)

        same_revision_different_tree = {
            **self.source_identity(),
            "tree_sha256": "9" * 64,
        }
        self.assertEqual(
            qualify_install._validate_same_source_identity(
                self.source_identity(), same_revision_different_tree
            ),
            (self.source_identity(), same_revision_different_tree),
        )
        different_revision = {
            **same_revision_different_tree,
            "revision": "8" * 40,
        }
        with self.assertRaisesRegex(ReleaseError, "one clean committed revision"):
            qualify_install._validate_same_source_identity(
                self.source_identity(), different_revision
            )

        for path in qualify_install.SHARED_BUILD_AUTHORITY_PATHS:
            for field, replacement in (("sha256", "9" * 64), ("bytes", 99)):
                mismatched_tool = self.tool_receipt()
                mismatched_tool["authority"] = {
                    **mismatched_tool["authority"],
                    path: {
                        **mismatched_tool["authority"][path],
                        field: replacement,
                    },
                }
                with (
                    self.subTest(path=path, field=field),
                    self.assertRaisesRegex(ReleaseError, "build receipts disagree"),
                ):
                    qualify_install._validate_shared_build_authority(
                        runtime, mismatched_tool
                    )

        missing_path = qualify_install.SHARED_BUILD_AUTHORITY_PATHS[0]
        missing_runtime = self.runtime_receipt()
        missing_tool = self.tool_receipt()
        del missing_runtime["authority"][missing_path]
        del missing_tool["authority"][missing_path]
        with self.assertRaisesRegex(ReleaseError, "build receipts disagree"):
            qualify_install._validate_shared_build_authority(
                missing_runtime, missing_tool
            )

        runtime_mutations = {
            "schema": {**runtime, "schema_version": "caller.receipt.v1"},
            "target": {**runtime, "target": "x86_64-apple-darwin"},
            "runtime-profile": {
                **runtime,
                "runtime_profile": "cigar.beta.embedded-local.v1",
            },
            "archive": {
                **runtime,
                "archive": {**runtime["archive"], "sha256": "9" * 64},
            },
            "source": {
                **runtime,
                "source": {**runtime["source"], "revision": "9" * 40},
            },
            "contract": {
                **runtime,
                "contract": {**runtime["contract"], "sha256": "9" * 64},
            },
        }
        for name, mutated in runtime_mutations.items():
            with self.subTest(runtime=name), self.assertRaises(ReleaseError):
                qualify_install._validate_runtime_build_receipt(
                    json.dumps(mutated).encode(),
                    archive_name="candidate.tar.gz",
                    archive_sha256="a" * 64,
                    archive_bytes=42,
                    contract_sha256="b" * 64,
                    contract_bytes=43,
                    product_version=qualify_install.DEFAULT_PRODUCT_VERSION,
                    context_abi="cigar.context.v1",
                    source=self.source_identity(),
                )

        wrong_tool = {
            **tool,
            "install_target": "bin/caller-selected-driver",
        }
        with self.assertRaisesRegex(ReleaseError, "identity is not exact"):
            qualify_install._validate_qualification_tool_build_receipt(
                json.dumps(wrong_tool).encode(),
                archive_name="tool.tar.gz",
                archive_sha256="a" * 64,
                archive_bytes=42,
                contract_sha256="b" * 64,
                contract_bytes=43,
                product_version=qualify_install.DEFAULT_PRODUCT_VERSION,
                context_abi="cigar.context.v1",
                source=self.source_identity(),
            )

    def test_extracted_runtime_and_tool_executables_must_be_thin_arm64_macho(
        self,
    ) -> None:
        valid = struct.pack("<IIII", 0xFEEDFACF, 0x0100000C, 0, 2) + b"\0" * 16
        executable = self.base / "arm64-tool"
        executable.write_bytes(valid)
        os.chmod(executable, 0o700)
        digest, byte_count = qualify_install._inspect_macho_arm64_executable(
            executable, "arm64 tool"
        )
        self.assertEqual(digest, __import__("hashlib").sha256(valid).hexdigest())
        self.assertEqual(byte_count, 32)

        payloads = {
            "script": b"#!/bin/sh\n" + b"x" * 32,
            "fat": struct.pack(">I", 0xCAFEBABE) + b"\0" * 32,
            "x86_64": struct.pack("<IIII", 0xFEEDFACF, 0x01000007, 3, 2) + b"\0" * 16,
            "arm64-dylib": struct.pack("<IIII", 0xFEEDFACF, 0x0100000C, 0, 6)
            + b"\0" * 16,
        }
        for name, payload in payloads.items():
            candidate = self.base / name
            candidate.write_bytes(payload)
            os.chmod(candidate, 0o700)
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ReleaseError, "thin arm64"),
            ):
                qualify_install._inspect_macho_arm64_executable(candidate, name)

    def test_macos_admin_group_membership_includes_primary_and_supplementary_gids(
        self,
    ) -> None:
        admin = SimpleNamespace(gr_gid=80)
        cases = (
            (80, 501, [], True),
            (501, 80, [], True),
            (501, 501, [20, 80], True),
            (501, 501, [20, 12], False),
        )
        for real_gid, effective_gid, supplementary, expected in cases:
            with (
                self.subTest(
                    real_gid=real_gid,
                    effective_gid=effective_gid,
                    supplementary=supplementary,
                ),
                mock.patch.object(
                    qualify_install.platform, "system", return_value="Darwin"
                ),
                mock.patch.object(qualify_install.os, "getuid", return_value=501),
                mock.patch.object(qualify_install.os, "geteuid", return_value=501),
                mock.patch.object(qualify_install.os, "getgid", return_value=real_gid),
                mock.patch.object(
                    qualify_install.os, "getegid", return_value=effective_gid
                ),
                mock.patch.object(
                    qualify_install.os, "getgroups", return_value=supplementary
                ),
                mock.patch.object(qualify_install.grp, "getgrnam", return_value=admin),
            ):
                self.assertEqual(qualify_install._is_administrator(), expected)

        with (
            mock.patch.object(qualify_install.os, "getuid", return_value=501),
            mock.patch.object(qualify_install.os, "geteuid", return_value=0),
            mock.patch.object(qualify_install.grp, "getgrnam") as lookup,
        ):
            self.assertTrue(qualify_install._is_administrator())
            lookup.assert_not_called()

        with (
            mock.patch.object(qualify_install.os, "getuid", return_value=0),
            mock.patch.object(qualify_install.os, "geteuid", return_value=501),
            mock.patch.object(qualify_install.grp, "getgrnam") as lookup,
        ):
            self.assertTrue(qualify_install._is_administrator())
            lookup.assert_not_called()

        with (
            mock.patch.object(
                qualify_install.platform, "system", return_value="Darwin"
            ),
            mock.patch.object(qualify_install.os, "getuid", return_value=501),
            mock.patch.object(qualify_install.os, "geteuid", return_value=501),
            mock.patch.object(qualify_install.grp, "getgrnam", side_effect=KeyError),
            self.assertRaisesRegex(ReleaseError, "cannot resolve.*admin group"),
        ):
            qualify_install._is_administrator()

    @unittest.skipUnless(sys.platform == "darwin", "requires canonical /private/tmp")
    def test_short_private_outer_root_bounds_all_driver_socket_paths(self) -> None:
        with qualify_install._qualification_directory() as base:
            temporary = base / "tmp"
            temporary.mkdir(mode=0o700)
            paths = qualify_install._driver_socket_paths(temporary)
            self.assertEqual(len(paths), 3)
            self.assertEqual(
                {path.parent.name for path in paths},
                {"cigar-q-governed", "cigar-q-contracts", "cigar-q-upgrade"},
            )
            self.assertTrue(
                all(
                    len(os.fsencode(path))
                    <= qualify_install.MAX_MACOS_SOCKET_PATH_BYTES
                    for path in paths
                )
            )
            self.assertTrue(str(base).startswith("/private/tmp/cigar-q-"))

            overlong = base / ("nested-" * 12)
            overlong.mkdir(mode=0o700)
            with self.assertRaisesRegex(ReleaseError, "exceeds 96 bytes"):
                qualify_install._driver_socket_paths(overlong)

    def test_driver_receipt_requires_exact_artifact_bound_workflow_inventory(
        self,
    ) -> None:
        artifact_id = qualify_install.RUNTIME_ARTIFACT_ID
        artifact_sha256 = "a" * 64
        version = qualify_install.DEFAULT_PRODUCT_VERSION
        abi = "cigar.context.v1"
        source_revision = "d" * 40
        receipt = {
            "schema_version": "cigar.installed-driver.v1",
            "status": "passed",
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_sha256,
            "product_version": version,
            "context_abi": abi,
            "source_revision": source_revision,
            "runtime_profile": qualify_install.RUNTIME_PROFILE,
            "installed_workflow": self.installed_workflow(
                artifact_id, artifact_sha256, source_revision
            ),
            "process_enforcement": qualify_install.MACOS_PROCESS_ENFORCEMENT,
            "checks": [
                {"id": identifier, "status": "passed"}
                for identifier in sorted(qualify_install.REQUIRED_DRIVER_CHECKS)
            ],
        }
        parsed, checks = qualify_install._validate_driver_receipt(
            json.dumps(receipt).encode("utf-8"),
            artifact_id,
            artifact_sha256,
            version,
            abi,
            source_revision,
        )
        self.assertEqual(parsed, receipt)
        self.assertEqual(set(checks), qualify_install.REQUIRED_DRIVER_CHECKS)
        self.assertLessEqual(
            {
                "backup-restore",
                "upgrade",
                "daemon-lifecycle",
                "version-binding",
                "effect-reconcile-cli-contract",
                "handoff-preview-cli-contract",
                "replay-cli-contract",
                "materialize",
                "delta",
                "permission-denial",
                "no-egress",
                "full-surface",
            },
            set(checks),
        )

        for missing in qualify_install.REQUIRED_DRIVER_CHECKS:
            with self.subTest(missing=missing):
                incomplete = dict(receipt)
                incomplete["checks"] = [
                    check for check in receipt["checks"] if check["id"] != missing
                ]
                with self.assertRaisesRegex(ReleaseError, "inventory is not exact"):
                    qualify_install._validate_driver_receipt(
                        json.dumps(incomplete).encode("utf-8"),
                        artifact_id,
                        artifact_sha256,
                        version,
                        abi,
                        source_revision,
                    )

        expanded = dict(receipt)
        expanded["checks"] = [
            *receipt["checks"],
            {"id": "unreviewed-claim", "status": "passed"},
        ]
        with self.assertRaisesRegex(ReleaseError, "unexpected=.*unreviewed-claim"):
            qualify_install._validate_driver_receipt(
                json.dumps(expanded).encode("utf-8"),
                artifact_id,
                artifact_sha256,
                version,
                abi,
                source_revision,
            )

    def test_installed_workflow_binding_is_cross_language_stable(self) -> None:
        workflow = {
            "profile": qualify_install.INSTALLED_WORKFLOW_PROFILE,
            "full_surface_sha256": "1" * 64,
            "semantic_identity_sha256": "2" * 64,
            "cigar_sha256": "3" * 64,
            "cigard_sha256": "4" * 64,
            "binding_sha256": "0" * 64,
            "no_egress_enforcement": qualify_install.MACOS_NO_EGRESS_ENFORCEMENT,
        }
        self.assertEqual(
            qualify_install._installed_workflow_binding(
                artifact_id=qualify_install.RUNTIME_ARTIFACT_ID,
                artifact_sha256="a" * 64,
                source_revision="b" * 40,
                workflow=workflow,
            ),
            "212cf7301b171d084f40fa0873126a53924e91747e4e4d11eef2ac567b2f6b01",
        )

    def test_driver_receipt_rejects_stale_duplicate_and_nonpassing_claims(self) -> None:
        base = {
            "schema_version": "cigar.installed-driver.v1",
            "status": "passed",
            "artifact_id": qualify_install.RUNTIME_ARTIFACT_ID,
            "artifact_sha256": "b" * 64,
            "product_version": qualify_install.DEFAULT_PRODUCT_VERSION,
            "context_abi": "cigar.context.v1",
            "source_revision": "d" * 40,
            "runtime_profile": qualify_install.RUNTIME_PROFILE,
            "installed_workflow": self.installed_workflow(
                qualify_install.RUNTIME_ARTIFACT_ID, "b" * 64, "d" * 40
            ),
            "process_enforcement": qualify_install.MACOS_PROCESS_ENFORCEMENT,
            "checks": [
                {"id": identifier, "status": "passed"}
                for identifier in sorted(qualify_install.REQUIRED_DRIVER_CHECKS)
            ],
        }

        stale = dict(base)
        stale["artifact_sha256"] = "c" * 64
        with self.assertRaisesRegex(ReleaseError, "stale or bound"):
            qualify_install._validate_driver_receipt(
                json.dumps(stale).encode("utf-8"),
                base["artifact_id"],
                base["artifact_sha256"],
                base["product_version"],
                base["context_abi"],
                base["source_revision"],
            )

        narrow_runtime = {**base, "runtime_profile": "cigar.beta.embedded-local.v1"}
        with self.assertRaisesRegex(ReleaseError, "stale or bound"):
            qualify_install._validate_driver_receipt(
                json.dumps(narrow_runtime).encode("utf-8"),
                base["artifact_id"],
                base["artifact_sha256"],
                base["product_version"],
                base["context_abi"],
                base["source_revision"],
            )

        for field, value in (
            ("profile", "cigar.beta.embedded-local.v1"),
            ("full_surface_sha256", "c" * 64),
            ("semantic_identity_sha256", "not-a-digest"),
            ("cigar_sha256", "c" * 64),
            ("no_egress_enforcement", "caller-attestation"),
            ("binding_sha256", "0" * 64),
        ):
            with self.subTest(workflow_field=field):
                malformed = dict(base)
                malformed["installed_workflow"] = {
                    **base["installed_workflow"],
                    field: value,
                }
                with self.assertRaisesRegex(ReleaseError, "workflow binding"):
                    qualify_install._validate_driver_receipt(
                        json.dumps(malformed).encode("utf-8"),
                        base["artifact_id"],
                        base["artifact_sha256"],
                        base["product_version"],
                        base["context_abi"],
                        base["source_revision"],
                    )

        duplicate = dict(base)
        duplicate["checks"] = [*base["checks"], base["checks"][0]]
        with self.assertRaisesRegex(ReleaseError, "duplicate"):
            qualify_install._validate_driver_receipt(
                json.dumps(duplicate).encode("utf-8"),
                base["artifact_id"],
                base["artifact_sha256"],
                base["product_version"],
                base["context_abi"],
                base["source_revision"],
            )

        failed = dict(base)
        failed["checks"] = [dict(check) for check in base["checks"]]
        failed["checks"][0]["status"] = "failed"
        with self.assertRaisesRegex(ReleaseError, "non-passing"):
            qualify_install._validate_driver_receipt(
                json.dumps(failed).encode("utf-8"),
                base["artifact_id"],
                base["artifact_sha256"],
                base["product_version"],
                base["context_abi"],
                base["source_revision"],
            )

    def test_install_report_requires_exact_macos_provenance_and_inventory(self) -> None:
        digest = "a" * 64
        source_revision = "b" * 40
        report = {
            "schema_version": "cigar.install-qualification.v1",
            "status": "passed",
            "artifact_id": qualify_install.RUNTIME_ARTIFACT_ID,
            "artifact_sha256": digest,
            "artifact_bytes": 42,
            "product_version": qualify_install.DEFAULT_PRODUCT_VERSION,
            "context_abi": "cigar.context.v1",
            "source_revision": source_revision,
            "target": qualify_install.MACOS_TARGET,
            "runtime_build_receipt": {
                "schema_version": qualify_install.RUNTIME_BUILD_RECEIPT_SCHEMA,
                "status": "built-unqualified",
                "sha256": digest,
                "bytes": 41,
            },
            "qualification_tool": {
                "artifact_id": qualify_install.QUALIFICATION_TOOL_ARTIFACT_ID,
                "archive_sha256": digest,
                "archive_bytes": 43,
                "contract_id": qualify_install.QUALIFICATION_TOOL_CONTRACT_ID,
                "contract_sha256": digest,
                "source_revision": source_revision,
                "build_receipt_schema_version": (
                    qualify_install.QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA
                ),
                "build_receipt_status": "built-unqualified",
                "build_receipt_sha256": digest,
                "build_receipt_bytes": 44,
                "runner_path": "bin/cigar-conformance",
                "runner_sha256": digest,
                "driver_path": "bin/cigar-install-qualifier",
                "driver_sha256": digest,
            },
            "build_receipt_authentication": (
                qualify_install.BUILD_RECEIPT_AUTHENTICATION
            ),
            "driver_receipt_sha256": digest,
            "installed_binary_sha256": {
                name: digest for name in qualify_install.REQUIRED_INSTALLED_BINARIES
            },
            "installed_workflow": self.installed_workflow(
                qualify_install.RUNTIME_ARTIFACT_ID,
                digest,
                source_revision,
                executable_sha256=digest,
            ),
            "unprivileged": True,
            "non_admin": True,
            "no_compiler_path": True,
            "no_egress": True,
            "no_egress_enforcement": qualify_install.MACOS_NO_EGRESS_ENFORCEMENT,
            "process_enforcement": qualify_install.MACOS_PROCESS_ENFORCEMENT,
            "path_cases": list(qualify_install.REQUIRED_PATH_CASES),
            "checks": list(qualify_install.REQUIRED_QUALIFICATION_CHECKS),
            "uninstalled": True,
            "state_retained": True,
            "package_contract_sha256": digest,
        }
        qualify_install._validate_report(report)

        mutations = {
            "foreign-target": {**report, "target": "x86_64-unknown-linux-gnu"},
            "external-attestation": {
                **report,
                "no_egress_enforcement": "external-runner-attestation-v1",
            },
            "missing-check": {**report, "checks": report["checks"][:-1]},
            "admin": {**report, "non_admin": False},
            "authenticated-overclaim": {
                **report,
                "build_receipt_authentication": "authenticated",
            },
            "unknown-field": {**report, "claim": True},
            "narrow-workflow": {
                **report,
                "installed_workflow": {
                    **report["installed_workflow"],
                    "profile": "cigar.beta.embedded-local.v1",
                },
            },
        }
        for name, candidate in mutations.items():
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                qualify_install._validate_report(candidate)

        wrong_source = dict(report)
        wrong_source["qualification_tool"] = {
            **report["qualification_tool"],
            "source_revision": "c" * 40,
        }
        with self.assertRaisesRegex(ReleaseError, "tool provenance"):
            qualify_install._validate_report(wrong_source)

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_installed_commands_are_wrapped_in_the_fixed_no_egress_sandbox(
        self,
    ) -> None:
        completed = __import__("subprocess").CompletedProcess(
            args=[], returncode=0, stdout=b"ok\n", stderr=b""
        )
        with mock.patch.object(
            qualify_install, "run_bounded", return_value=completed
        ) as run:
            result = qualify_install._run(
                ["/private/tmp/cigar", "version"],
                self.base,
                {"PATH": "/usr/bin:/bin"},
            )
        self.assertEqual(result.stdout, b"ok\n")
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/sandbox-exec",
                "-p",
                (
                    "(version 1)(allow default)(deny network*)(deny mach-lookup)"
                    "(deny file-write*)(deny process-fork)(deny signal)"
                    f"(allow file-write* (subpath {json.dumps(str(self.base))}))"
                    "(allow network-bind network-inbound network-outbound "
                    f"(subpath {json.dumps(str(self.base))}))"
                ),
                "/private/tmp/cigar",
                "version",
            ],
        )
        self.assertEqual(
            qualify_install._no_egress_enforcement("aarch64-apple-darwin"),
            "darwin-seatbelt-deny-network-mach-confine-writes-protect-candidate-workspace-unix-v1",
        )

    def test_python_never_seatbelt_wraps_the_verified_rust_driver(self) -> None:
        completed = __import__("subprocess").CompletedProcess(
            args=[], returncode=0, stdout=b"{}\n", stderr=b""
        )
        driver_command = ["/private/tmp/cigar-install-qualifier", "--help"]
        with mock.patch.object(
            qualify_install, "run_bounded", return_value=completed
        ) as run:
            qualify_install._run_qualification_driver(
                driver_command,
                self.base,
                {"PATH": "/private/tmp/tool/bin"},
            )
        self.assertEqual(run.call_args.args[0], driver_command)
        self.assertNotIn("/usr/bin/sandbox-exec", run.call_args.args[0])

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_direct_probe_seatbelt_denies_signals_and_cfprefsd_writes(self) -> None:
        subprocess_module = __import__("subprocess")
        helper = subprocess_module.Popen(["/bin/sleep", "30"])
        self.addCleanup(helper.kill)
        signal_probe = """import os, signal, sys
try:
    os.kill(int(sys.argv[1]), signal.SIGTERM)
except PermissionError:
    raise SystemExit(0)
raise SystemExit(4)
"""
        qualify_install._run(
            ["/usr/bin/python3", "-c", signal_probe, str(helper.pid)],
            self.base,
            self.macos_system_tool_environment(),
        )
        self.assertIsNone(helper.poll())
        helper.terminate()
        helper.wait(timeout=5)

        domain = f"dev.cigar.qualifier.{os.getpid()}.{self.base.name}"
        environment = self.macos_system_tool_environment()
        try:
            with self.assertRaises(ReleaseError):
                qualify_install._run(
                    ["/usr/bin/defaults", "write", domain, "probe", "escaped"],
                    self.base,
                    environment,
                )
            observed = subprocess_module.run(
                ["/usr/bin/defaults", "read", domain, "probe"],
                env=environment,
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(observed.stdout.strip(), b"escaped")
        finally:
            subprocess_module.run(
                ["/usr/bin/defaults", "delete", domain],
                env=environment,
                check=False,
                capture_output=True,
            )

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_fixed_macos_sandbox_denies_ip_and_allows_only_workspace_unix_ipc(
        self,
    ) -> None:
        environment = self.macos_system_tool_environment()
        inside = self.base / "candidate.sock"
        outside = self.base.parent / f"{self.base.name}-outside.sock"
        self.addCleanup(outside.unlink, missing_ok=True)
        probe = """import socket, sys
inside, outside = sys.argv[1:]
server = socket.socket(socket.AF_UNIX)
server.bind(inside)
client = socket.socket()
try:
    client.connect(("127.0.0.1", 9))
except PermissionError:
    pass
except OSError:
    raise SystemExit(3)
else:
    raise SystemExit(4)
escaped = socket.socket(socket.AF_UNIX)
try:
    escaped.bind(outside)
except PermissionError:
    raise SystemExit(0)
except OSError:
    raise SystemExit(5)
raise SystemExit(6)
"""
        result = qualify_install._run(
            ["/usr/bin/python3", "-c", probe, str(inside), str(outside)],
            self.base,
            environment,
        )
        self.assertEqual(result.returncode, 0)

        echo = qualify_install._run(
            ["/bin/echo", "bounded-stdout"],
            self.base,
            environment,
        )
        self.assertEqual(echo.stdout, b"bounded-stdout\n")

        with self.assertRaisesRegex(ReleaseError, "installed command exited 128"):
            qualify_install._run(
                ["/bin/sh", "-c", 'sleep 1 & child=$!; wait "$child"'],
                self.base,
                environment,
            )

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_fixed_macos_sandbox_makes_candidate_tree_immutable(self) -> None:
        environment = self.macos_system_tool_environment()
        protected = self.base / "candidate"
        protected.mkdir(mode=0o700)
        binary = protected / "cigar"
        binary.write_bytes(b"candidate-bytes")
        os.chmod(binary, 0o700)
        writable = self.base / "workspace-output"
        outside = self.base.parent / f"{self.base.name}-outside-write"
        self.addCleanup(outside.unlink, missing_ok=True)
        probe = """from pathlib import Path
import sys
protected, writable, outside = map(Path, sys.argv[1:])
try:
    protected.write_bytes(b\"mutated\")
except PermissionError:
    pass
else:
    raise SystemExit(4)
writable.write_bytes(b\"allowed\")
try:
    outside.write_bytes(b\"escaped\")
except PermissionError:
    pass
else:
    raise SystemExit(5)
"""
        qualify_install._run(
            [
                "/usr/bin/python3",
                "-c",
                probe,
                str(binary),
                str(writable),
                str(outside),
            ],
            self.base,
            environment,
            protected_roots=(protected,),
        )
        self.assertEqual(binary.read_bytes(), b"candidate-bytes")
        self.assertEqual(writable.read_bytes(), b"allowed")
        self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
