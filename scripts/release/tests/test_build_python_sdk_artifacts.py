#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import build_python_sdk_artifacts as builder  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError  # noqa: E402
from release_lib import ReleaseError  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure evidence workspaces require POSIX")
class PythonSdkArtifactBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("uv") is None or sys.version_info[:2] != (3, 14):
            raise unittest.SkipTest(
                "the focused package build needs uv and Python 3.14"
            )
        cls.class_temporary = tempfile.TemporaryDirectory(
            prefix="cigar-python-builder-class-"
        )
        cls.class_base = Path(cls.class_temporary.name).resolve()
        os.chmod(cls.class_base, 0o700)
        cls.configuration = builder._load_configuration(builder.REPOSITORY_ROOT)
        cls.source = {
            "revision": "a" * 40,
            "tree_sha256": "b" * 64,
            "committed": True,
            "clean": False,
        }
        scratch = cls.class_base / "offline-build"
        scratch.mkdir(mode=0o700)
        built = builder._default_package_builder(
            cls.configuration,
            cls.source,
            1_700_000_000,
            scratch,
            cls._arguments(cls.class_base / "unused"),
        )
        cls.sdist_bytes = built.sdist.read_bytes()
        cls.wheel_bytes = built.wheel.read_bytes()
        cls.tools = built.tools
        cls.build_policy = built.build_policy
        cls.clean_install_validation = built.clean_install_validation

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cigar-python-builder-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.root = builder.REPOSITORY_ROOT
        self.host = {
            "platform": "macos",
            "architecture": "arm64",
            "target_triple": builder.TARGET_TRIPLE,
            "macos_version": "15.6",
        }

    @staticmethod
    def _arguments(evidence: Path) -> argparse.Namespace:
        return argparse.Namespace(
            root=builder.REPOSITORY_ROOT,
            evidence_dir=evidence,
            source_date_epoch="1700000000",
            uv=None,
            python=None,
            uv_cache_dir=None,
        )

    def fake_builder(
        self,
        configuration: builder.BuildConfiguration,
        _source: dict[str, object],
        _epoch: int,
        scratch: Path,
        _arguments: argparse.Namespace,
    ) -> builder.BuiltPackages:
        self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
        sdist = scratch / configuration.sdist_filename
        wheel = scratch / configuration.wheel_filename
        sdist.write_bytes(self.sdist_bytes)
        wheel.write_bytes(self.wheel_bytes)
        os.chmod(sdist, 0o600)
        os.chmod(wheel, 0o600)
        return builder.BuiltPackages(
            sdist=sdist,
            wheel=wheel,
            tools=self.tools,
            build_policy=self.build_policy,
            clean_install_validation=self.clean_install_validation,
        )

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
            mock.patch.object(builder, "_require_host", return_value=self.host),
            source_patch,
        ):
            return builder.produce(
                self._arguments(evidence),
                package_builder=package_builder or self.fake_builder,
            )

    def test_configuration_binds_versions_locks_contracts_and_exact_sources(
        self,
    ) -> None:
        configuration = builder._load_configuration(self.root)
        self.assertEqual(configuration.version, "0.9.0-honey.1")
        self.assertEqual(configuration.python_version, "0.9.0.dev1")
        self.assertEqual(configuration.context_abi, "cigar.context.v1")
        self.assertEqual(
            configuration.sdist_filename,
            "cigar_sdk-0.9.0.dev1.tar.gz",
        )
        self.assertEqual(
            configuration.wheel_filename,
            "cigar_sdk-0.9.0.dev1-py3-none-any.whl",
        )
        self.assertEqual(
            set(configuration.authority), set(builder.HONEY_AUTHORITY_PATHS)
        )
        self.assertEqual(
            configuration.receipt_filename, "python-sdk-build-receipt.json"
        )
        self.assertEqual(
            configuration.lock_summary,
            {
                "format_version": 1,
                "revision": 3,
                "requires_python": "==3.14.*",
                "runtime_dependency": "protobuf==6.33.5",
                "development_dependencies": [
                    "mypy==1.19.1",
                    "pytest==9.0.2",
                    "ruff==0.14.10",
                ],
                "build_backend": "hatchling==1.28.0",
            },
        )
        self.assertIn(
            "src/cigar_sdk/fixtures/problem-index-unavailable-v1.json",
            configuration.source_assets,
        )
        self.assertNotIn("uv.lock", configuration.source_assets)
        self.assertFalse(
            any(path.startswith("examples/") for path in configuration.source_assets)
        )
        self.assertFalse(
            any("__pycache__" in path for path in configuration.source_assets)
        )

    def test_pair_is_deterministic_contract_valid_owner_only_and_unclaimed(
        self,
    ) -> None:
        first_root = self.base / "first"
        second_root = self.base / "second"
        first = self.produce(first_root)
        second = self.produce(second_root)

        filenames = {
            "cigar_sdk-0.9.0.dev1.tar.gz",
            "cigar_sdk-0.9.0.dev1-py3-none-any.whl",
            "python-sdk-build-receipt.json",
        }
        self.assertEqual(first, second)
        for filename in filenames:
            self.assertEqual(
                (first_root / filename).read_bytes(),
                (second_root / filename).read_bytes(),
            )
            self.assertEqual(
                stat.S_IMODE((first_root / filename).stat().st_mode), 0o400
            )
        self.assertEqual(stat.S_IMODE(first_root.stat().st_mode), 0o700)
        self.assertEqual(first["status"], "built-unqualified")
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
        self.assertEqual(
            first["external_requirements"],
            {
                "twine_check": "not-performed",
                "clean_sdist_install": "passed-offline-with-runtime-dependencies",
                "clean_wheel_install": "passed-offline-with-runtime-dependencies",
                "wheel_interpreter_matrix": "native-cpython-3.14-passed",
                "artifact_signatures": "not-evidenced",
                "pypi_publication": "not-performed",
            },
        )
        self.assertTrue(first["package_validation"]["core_metadata_identical"])
        self.assertEqual(
            json.loads((first_root / "python-sdk-build-receipt.json").read_bytes()),
            first,
        )

    def test_sdist_tests_and_fixtures_are_self_contained(self) -> None:
        prefix = "cigar_sdk-0.9.0.dev1"
        with tarfile.open(fileobj=io.BytesIO(self.sdist_bytes), mode="r:gz") as archive:
            members = {
                member.name: archive.extractfile(member).read()
                for member in archive.getmembers()
                if member.isfile() and archive.extractfile(member) is not None
            }
        for fixture in (
            "problem-index-unavailable-v1.json",
            "semantic-bundle-v1.json",
        ):
            packaged = members[f"{prefix}/src/cigar_sdk/fixtures/{fixture}"]
            self.assertEqual(
                packaged, (self.root / "sdk/fixtures" / fixture).read_bytes()
            )
        test_payloads = [
            payload
            for name, payload in members.items()
            if name.startswith(f"{prefix}/tests/") and name.endswith(".py")
        ]
        self.assertEqual(len(test_payloads), 5)
        self.assertTrue(
            all(
                b"importlib" in payload or b"resources" not in payload
                for payload in test_payloads
            )
        )
        self.assertTrue(all(b"parents[2]" not in payload for payload in test_payloads))
        self.assertTrue(
            all(b"sdk/fixtures" not in payload for payload in test_payloads)
        )

    def test_wheel_record_and_exact_inventory_reject_tampering(self) -> None:
        wheel = self.base / "valid.whl"
        wheel.write_bytes(self.wheel_bytes)
        os.chmod(wheel, 0o600)
        payloads, _ = builder._read_wheel(wheel, self.configuration, 1_700_000_000)
        record = "cigar_sdk-0.9.0.dev1.dist-info/RECORD"
        tampered = dict(payloads)
        tampered["cigar_sdk/client.py"] += b"\n"
        with self.assertRaisesRegex(ReleaseError, "RECORD binding differs"):
            builder._validate_wheel_record(tampered, record)

        extra = self.base / "extra.whl"
        extra.write_bytes(self.wheel_bytes)
        os.chmod(extra, 0o600)
        with zipfile.ZipFile(extra, mode="a") as archive:
            archive.writestr("cigar_sdk/unexpected.py", b"unexpected\n")
        with self.assertRaisesRegex(ReleaseError, "Python wheel"):
            builder._read_wheel(extra, self.configuration, 1_700_000_000)

    def test_stale_matrix_row_and_package_fixture_fail_closed(self) -> None:
        real_load = builder.load_json

        def missing_producer(path: Path) -> object:
            document = real_load(path)
            if path.name == "artifact-matrix.v1.json":
                document = copy.deepcopy(document)
                for row in document["artifacts"]:
                    if row.get("id") == builder.SDIST_ARTIFACT_ID:
                        row.pop("producer")
            return document

        with mock.patch.object(builder, "load_json", side_effect=missing_producer):
            with self.assertRaisesRegex(ReleaseError, "artifact row is incomplete"):
                builder._load_configuration(self.root)

        original = builder._read_stable_file

        def stale_fixture(path: Path, maximum: int, label: str) -> bytes:
            payload = original(path, maximum, label)
            if label == "sdk/fixtures/problem-index-unavailable-v1.json":
                return payload.replace(b"INDEX_UNAVAILABLE", b"INDEX_DIFFERENTXX")
            return payload

        with mock.patch.object(builder, "_read_stable_file", side_effect=stale_fixture):
            with self.assertRaisesRegex(
                ReleaseError, "packaged Python SDK fixture is stale"
            ):
                builder._source_assets(self.root)

    def test_source_change_and_incomplete_build_policy_publish_nothing(self) -> None:
        changed = {**self.source, "tree_sha256": "c" * 64}
        changed_root = self.base / "changed"
        with self.assertRaisesRegex(ReleaseError, "source changed"):
            self.produce(changed_root, source_side_effect=[self.source, changed])
        self.assertEqual(list(changed_root.iterdir()), [])

        def incomplete_policy(
            configuration: builder.BuildConfiguration,
            source: dict[str, object],
            epoch: int,
            scratch: Path,
            arguments: argparse.Namespace,
        ) -> builder.BuiltPackages:
            built = self.fake_builder(configuration, source, epoch, scratch, arguments)
            return builder.BuiltPackages(
                sdist=built.sdist,
                wheel=built.wheel,
                tools=built.tools,
                build_policy={**built.build_policy, "network": "unknown"},
                clean_install_validation=built.clean_install_validation,
            )

        policy_root = self.base / "policy"
        with self.assertRaisesRegex(ReleaseError, "build policy is incomplete"):
            self.produce(policy_root, incomplete_policy)
        self.assertEqual(list(policy_root.iterdir()), [])

    def test_same_length_substitution_after_verification_cannot_publish(self) -> None:
        evidence = self.base / "substitution"
        original_attach = builder.EvidenceWorkspace.attach_file
        observed: dict[str, object] = {}

        def substitute_before_attach(
            workspace: builder.EvidenceWorkspace,
            source: Path,
            relative: str,
            *,
            read_only: bool = True,
            expected_sha256: str | None = None,
            expected_bytes: int | None = None,
        ) -> object:
            if relative.endswith(".tar.gz"):
                observed.update({"sha256": expected_sha256, "bytes": expected_bytes})
                payload = bytearray(source.read_bytes())
                payload[-1] ^= 1
                source.write_bytes(payload)
            return original_attach(
                workspace,
                source,
                relative,
                read_only=read_only,
                expected_sha256=expected_sha256,
                expected_bytes=expected_bytes,
            )

        with mock.patch.object(
            builder.EvidenceWorkspace,
            "attach_file",
            new=substitute_before_attach,
        ):
            with self.assertRaises(EvidenceWorkspaceError):
                self.produce(evidence)
        self.assertRegex(str(observed["sha256"]), r"^[0-9a-f]{64}$")
        self.assertGreater(observed["bytes"], 0)
        self.assertEqual(list(evidence.iterdir()), [])

    def test_output_selection_and_nonempty_workspace_fail_closed(self) -> None:
        arguments = self._arguments(Path("relative"))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "absolute"):
                builder._selected_evidence_directory(arguments)

        arguments.evidence_dir = self.base / "argument"
        with mock.patch.dict(
            os.environ,
            {"CIGAR_EVIDENCE_DIR": str(self.base / "environment")},
            clear=True,
        ):
            with self.assertRaisesRegex(ReleaseError, "conflicts"):
                builder._selected_evidence_directory(arguments)

        nonempty = self.base / "nonempty"
        nonempty.mkdir(mode=0o700)
        (nonempty / "sentinel").write_text("occupied\n", encoding="utf-8")
        os.chmod(nonempty / "sentinel", 0o600)
        with self.assertRaises(EvidenceWorkspaceError):
            self.produce(nonempty)
        self.assertEqual(
            [path.name for path in nonempty.iterdir()],
            ["sentinel"],
        )


if __name__ == "__main__":
    unittest.main()
