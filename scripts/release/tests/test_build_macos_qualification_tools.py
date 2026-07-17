#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
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

import build_macos_qualification_tools as builder  # noqa: E402
from release_lib import ReleaseError, load_json, sha256_bytes  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure workspace requires POSIX")
class MacosQualificationToolBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-tool-builder-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.root = builder.REPOSITORY_ROOT
        self.source = {
            "revision": "a" * 40,
            "tree_sha256": "b" * 64,
            "committed": True,
            "clean": True,
        }
        self.host = {
            "platform": "macos",
            "architecture": "arm64",
            "target_triple": builder.TARGET_TRIPLE,
            "macos_version": "15.6",
        }
        self.cargo = Path(shutil.which("cargo") or "/missing/cargo")
        self.rustc = Path(shutil.which("rustc") or "/missing/rustc")
        self.protoc = Path(shutil.which("protoc") or "/missing/protoc")

    def arguments(self, selector: str, evidence: Path) -> argparse.Namespace:
        return argparse.Namespace(
            tool=selector,
            root=self.root,
            evidence_dir=evidence,
            source_date_epoch="1700000000",
            cargo=self.cargo,
            rustc=self.rustc,
            protoc=self.protoc,
            python=Path(sys.executable),
        )

    def configuration(self, selector: str) -> builder.BuildConfiguration:
        spec = builder.SPECS[selector]
        assets: dict[str, bytes] = {}
        source_assets = (
            builder.CONFORMANCE_ASSETS
            if selector == "conformance"
            else builder.BENCHMARK_ASSETS
        )
        for destination, relative in source_assets.items():
            assets[destination] = self.root.joinpath(*relative.split("/")).read_bytes()
        for name in ("LICENSE", "NOTICE"):
            assets[name] = (self.root / name).read_bytes()
        authority: dict[str, dict[str, object]] = {}
        for relative in builder._authority_paths(spec):
            payload = self.root.joinpath(*relative.split("/")).read_bytes()
            authority[relative] = {
                "sha256": sha256_bytes(payload),
                "bytes": len(payload),
            }
        return builder.BuildConfiguration(
            root=self.root,
            spec=spec,
            version="0.9.0-honey.1",
            context_abi="cigar.context.v1",
            filename=spec.filename_template.format(version="0.9.0-honey.1"),
            contract_path=self.root.joinpath(*spec.contract_relative.split("/")),
            authority=authority,
            assets=assets,
            honey=True,
        )

    @staticmethod
    def macho(marker: bytes = b"cigar-conformance-development") -> bytes:
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

    def fake_conformance(
        self,
        configuration: builder.BuildConfiguration,
        _source: dict[str, object],
        _epoch: int,
        _scratch: Path,
        _arguments: argparse.Namespace,
    ) -> builder.BuiltTool:
        entries = (
            builder.PackageEntry("README.md", builder.CONFORMANCE_README, 0o644),
            builder.PackageEntry("LICENSE", configuration.assets["LICENSE"], 0o644),
            builder.PackageEntry("NOTICE", configuration.assets["NOTICE"], 0o644),
            builder.PackageEntry("bin/cigar-conformance", self.macho(), 0o755),
            builder.PackageEntry(
                "bin/cigar-install-qualifier",
                self.macho(b"cigar-install-qualifier-development"),
                0o755,
            ),
            *(
                builder.PackageEntry(path, payload, 0o644)
                for path, payload in sorted(configuration.assets.items())
                if path not in {"LICENSE", "NOTICE"}
            ),
        )
        return builder.BuiltTool(
            entries=entries,
            tools=(
                {
                    "name": "cargo",
                    "version": "cargo test",
                    "sha256": "c" * 64,
                    "bytes": 1,
                },
            ),
            invocation_probes=(
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
            ),
        )

    def produce(
        self,
        selector: str,
        evidence: Path,
        *,
        tool_builder: builder.ToolBuilder | None = None,
        source_side_effect: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        configuration = self.configuration(selector)
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
            mock.patch.object(
                builder, "_load_configuration", return_value=configuration
            ),
            mock.patch.object(
                builder, "_authority_digests", return_value=configuration.authority
            ),
            mock.patch.object(builder, "_require_host", return_value=self.host),
            source_patch,
        ):
            return builder.produce(
                self.arguments(selector, evidence), tool_builder=tool_builder
            )

    def test_matrix_contract_and_profile_projection_are_exact(self) -> None:
        matrix = load_json(self.root / "packaging/artifact-matrix.v1.json")
        rows = {row["id"]: row for row in matrix["artifacts"]}
        self.assertEqual(len(rows), 22)
        for spec in builder.SPECS.values():
            with self.subTest(spec=spec.selector):
                self.assertEqual(
                    rows[spec.artifact_id],
                    builder._matrix_row(spec, "0.9.0-honey.1"),
                )
                contract = load_json(
                    self.root.joinpath(*spec.contract_relative.split("/"))
                )
                expected = builder._expected_archive_paths(spec)
                self.assertEqual(set(contract["allow"]), expected)
                self.assertEqual(set(contract["required"]), expected)
        import development_macos_profile as profile

        honey = load_json(self.root / "packaging/honey/artifact-matrix.v1.json")
        selected_internal = [
            row
            for row in honey["internal_inputs"]
            if row.get("id") == builder.HONEY_INTERNAL_INPUT_ID
        ]
        self.assertEqual(
            selected_internal,
            [
                builder._honey_internal_input(
                    builder.SPECS["conformance"], "0.9.0-honey.1"
                )
            ],
        )

        selected = dict(profile.SELECTED)
        self.assertEqual(len(selected), 17)
        self.assertEqual(
            selected["cigar-conformance-macos-aarch64"],
            "qualification-conformance",
        )
        self.assertEqual(
            selected["cigarbench-macos-aarch64"], "qualification-benchmark"
        )
        producer_sources = {
            "scripts/release/build_macos_qualification_tools.py",
            "scripts/release/evidence_workspace.py",
            "scripts/release/release_lib.py",
            "scripts/release/verify_package.py",
        }
        for spec in builder.SPECS.values():
            self.assertLessEqual(producer_sources, set(spec.source_includes))
        self.assertEqual(profile.MISSING, ())

    def test_configuration_loader_binds_rows_profile_contracts_and_assets(self) -> None:
        staged = self.base / "configuration-repository"
        required = {
            "packaging/product-version.v1.json",
            "packaging/honey/capability-profile.v1.json",
            "packaging/honey/artifact-matrix.v1.json",
            "packaging/honey/release-requirements.v1.json",
            "LICENSE",
            "NOTICE",
            builder.SPECS["conformance"].contract_relative,
            *builder.CONFORMANCE_ASSETS.values(),
        }
        for relative in required:
            destination = staged.joinpath(*relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.root.joinpath(*relative.split("/")), destination)
        spec = builder.SPECS["conformance"]
        configuration = builder._load_configuration(staged, spec)
        self.assertEqual(configuration.version, "0.9.0-honey.1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertTrue(configuration.honey)
        self.assertEqual(
            configuration.filename,
            spec.filename_template.format(version="0.9.0-honey.1"),
        )
        self.assertEqual(
            set(configuration.authority),
            set(builder._authority_paths(spec, honey=True)),
        )
        with self.assertRaisesRegex(ReleaseError, "only the bounded conformance"):
            builder._load_configuration(staged, builder.SPECS["cigarbench"])

    def test_conformance_fake_build_is_deterministic_exact_and_unclaimed(self) -> None:
        first_root = self.base / "conformance-first"
        second_root = self.base / "conformance-second"
        first = self.produce(
            "conformance", first_root, tool_builder=self.fake_conformance
        )
        second = self.produce(
            "conformance", second_root, tool_builder=self.fake_conformance
        )
        name = "cigar-conformance-0.9.0-honey.1-aarch64-apple-darwin.tar.gz"
        self.assertEqual(
            (first_root / name).read_bytes(), (second_root / name).read_bytes()
        )
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "built-unqualified")
        self.assertEqual(first["claims"], self.expected_claims())
        self.assertEqual(first["build_environment"], self.expected_build_environment())
        self.assertFalse(first["invocation_probes"][0]["qualifying_evidence"])
        self.assertEqual(stat.S_IMODE((first_root / name).stat().st_mode), 0o400)
        receipt = first_root / builder.SPECS["conformance"].receipt_name
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o400)
        self.assertEqual(json.loads(receipt.read_bytes()), first)
        with tarfile.open(first_root / name, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers()}
            self.assertEqual(
                set(members),
                builder._expected_archive_paths(builder.SPECS["conformance"]),
            )
            self.assertEqual(members["bin/cigar-conformance"].mode, 0o755)
            self.assertEqual(
                members["bin/cigar-install-qualifier"].mode,
                0o755,
            )
            self.assertEqual(len(first["invocation_probes"]), 2)
            self.assertTrue(
                all(member.uid == 0 and member.gid == 0 for member in members.values())
            )
            self.assertTrue(
                all(member.mtime == 1_700_000_000 for member in members.values())
            )

    @unittest.skipUnless(sys.platform == "darwin", "requires native macOS toolchain")
    def test_cigarbench_direct_launchers_reject_hostile_python_and_cwd_injection(
        self,
    ) -> None:
        first_root = self.base / "bench-first"
        second_root = self.base / "bench-second"
        first = self.produce("cigarbench", first_root)
        second = self.produce("cigarbench", second_root)
        name = "cigarbench-0.9.0-honey.1-aarch64-apple-darwin.tar.gz"
        self.assertEqual(
            (first_root / name).read_bytes(), (second_root / name).read_bytes()
        )
        self.assertEqual(first, second)
        self.assertEqual(first["claims"], self.expected_claims())
        self.assertEqual(first["build_environment"], self.expected_build_environment())
        self.assertFalse(first["claims"]["benchmark_efficacy"])
        self.assertEqual(len(first["invocation_probes"]), 4)
        self.assertTrue(
            all(
                probe["scope"] == "invocation-only"
                for probe in first["invocation_probes"]
            )
        )
        self.assertTrue(
            all(
                probe["direct_installed_launcher"]
                for probe in first["invocation_probes"]
            )
        )
        python_probes = [
            probe
            for probe in first["invocation_probes"]
            if probe["command"] != "bin/cigarbench-local-scale --help"
        ]
        self.assertEqual(len(python_probes), 3)
        self.assertTrue(
            all(
                probe["python_injection_resistance"] == "passed"
                for probe in python_probes
            )
        )
        native_probe = next(
            probe
            for probe in first["invocation_probes"]
            if probe["command"] == "bin/cigarbench-local-scale --help"
        )
        self.assertEqual(
            native_probe["python_injection_resistance"],
            "not-applicable-native-binary",
        )
        self.assertEqual(
            first["build_tools"][0]["invocation_path"], "/opt/homebrew/bin/python3"
        )
        self.assertEqual(first["build_tools"][0]["isolated_flags"], ["-B", "-I", "-S"])
        with tarfile.open(first_root / name, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers()}
            self.assertEqual(
                set(members),
                builder._expected_archive_paths(builder.SPECS["cigarbench"]),
            )
            for launcher in (
                "bin/cigarbench",
                "bin/cigarbench-performance",
                "bin/cigarbench-matrix",
            ):
                self.assertEqual(members[launcher].mode, 0o755)
                handle = archive.extractfile(launcher)
                self.assertIsNotNone(handle)
                assert handle is not None
                payload = handle.read()
                self.assertTrue(payload.startswith(b"#!/bin/sh\n"))
                self.assertIn(b"exec /opt/homebrew/bin/python3 -B -I -S", payload)
                self.assertNotIn(b"/usr/bin/env python", payload)
            native = members["bin/cigarbench-local-scale"]
            self.assertEqual(native.mode, 0o755)
            handle = archive.extractfile(native)
            self.assertIsNotNone(handle)
            assert handle is not None
            builder._validate_macho_arm64(handle.read(), "cigarbench-local-scale")
            self.assertFalse(any("reports/" in name for name in members))
            self.assertFalse(any("fixtures/" in name for name in members))
            self.assertFalse(any("tests/" in name for name in members))
            self.assertFalse(any("dashboard" in name for name in members))

    def test_bad_native_runner_source_change_and_nonempty_output_fail_closed(
        self,
    ) -> None:
        configuration = self.configuration("conformance")

        def bad_runner(
            _configuration: builder.BuildConfiguration,
            _source: dict[str, object],
            _epoch: int,
            _scratch: Path,
            _arguments: argparse.Namespace,
        ) -> builder.BuiltTool:
            built = self.fake_conformance(
                configuration, self.source, 1_700_000_000, self.base, _arguments
            )
            entries = tuple(
                builder.PackageEntry(entry.path, b"not-macho", entry.mode)
                if entry.path == "bin/cigar-conformance"
                else entry
                for entry in built.entries
            )
            return builder.BuiltTool(entries, built.tools, built.invocation_probes)

        with self.assertRaisesRegex(ReleaseError, "bounded executable|thin arm64"):
            self.produce(
                "conformance", self.base / "bad-runner", tool_builder=bad_runner
            )

        changed = dict(self.source)
        changed["tree_sha256"] = "d" * 64
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(
                "conformance",
                self.base / "source-change",
                tool_builder=self.fake_conformance,
                source_side_effect=[self.source, changed],
            )

        occupied = self.base / "occupied"
        occupied.mkdir(mode=0o700)
        (occupied / "unexpected").write_text("occupied", encoding="utf-8")
        with self.assertRaises(Exception):
            self.produce("conformance", occupied, tool_builder=self.fake_conformance)

    def test_honey_tool_build_rejects_dirty_source_before_building(self) -> None:
        dirty = {**self.source, "clean": False}
        attempted = mock.Mock(side_effect=AssertionError("builder must not run"))
        evidence = self.base / "dirty-source"
        with self.assertRaisesRegex(ReleaseError, "Honey requires a clean tree"):
            self.produce(
                "conformance",
                evidence,
                tool_builder=attempted,
                source_side_effect=[dirty],
            )
        attempted.assert_not_called()
        self.assertFalse(evidence.exists())

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_tool_subprocesses_are_wrapped_in_the_fixed_no_egress_sandbox(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"ok\n", stderr=b""
        )
        with mock.patch.object(builder, "run_bounded", return_value=completed) as run:
            output = builder._run_checked(
                ["/private/tmp/cigarbench", "--help"],
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
                "/private/tmp/cigarbench",
                "--help",
            ],
        )

    @unittest.skipUnless(
        sys.platform == "darwin", "requires the macOS Seatbelt launcher"
    )
    def test_tool_sandbox_actually_denies_socket_connect(self) -> None:
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

    @staticmethod
    def expected_build_environment() -> dict[str, object]:
        return {
            "network_enforcement": "darwin-sandbox-exec-deny-network-v1",
            "sandbox_launcher": "/usr/bin/sandbox-exec",
            "sandbox_policy": "(version 1)(allow default)(deny network*)",
        }

    @staticmethod
    def expected_claims() -> dict[str, bool]:
        return {
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
        }


if __name__ == "__main__":
    unittest.main()
