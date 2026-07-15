from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
sys.path.insert(0, str(RELEASE_SCRIPTS))

import assemble_honey_release as honey  # noqa: E402
import build_archives  # noqa: E402
import build_claude_code_plugin  # noqa: E402
import build_macos_aarch64_archive  # noqa: E402
import build_python_sdk_artifacts  # noqa: E402
import build_rust_sdk_crate  # noqa: E402
import build_typescript_sdk  # noqa: E402


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class HoneyConfigurationTests(unittest.TestCase):
    @staticmethod
    def _authority(
        configuration: honey.Configuration, required: tuple[str, ...]
    ) -> dict[str, dict[str, object]]:
        return {
            relative: {
                "sha256": honey.sha256_file(configuration.root / relative),
                "bytes": (configuration.root / relative).stat().st_size,
            }
            for relative in required
        }

    def _root(self, directory: Path) -> Path:
        root = directory / "repo"
        (root / "packaging" / "honey").mkdir(parents=True)
        _write_json(
            root / honey.PRODUCT_PATH,
            {
                "schema_version": "cigar.product-version.v1",
                "product": "cigar",
                "version": honey.EXPECTED_VERSION,
                "target_release_version": "0.9.0",
                "context_abi": honey.EXPECTED_ABI,
                "release_state": honey.EXPECTED_STATE,
                "channel": "honey",
                "prerelease": True,
                "published": False,
                "supported": False,
                "tag": f"v{honey.EXPECTED_VERSION}",
            },
        )
        _write_json(
            root / honey.PROFILE_PATH,
            {
                "schema_version": "cigar.honey.capability-profile.v1",
                "profile_id": "cigar.honey.local.macos-aarch64.v1",
                "identity": {
                    "product_version": honey.EXPECTED_VERSION,
                    "context_abi": honey.EXPECTED_ABI,
                    "release_state": honey.EXPECTED_STATE,
                    "channel": "honey",
                    "prerelease": True,
                    "published": False,
                    "supported": False,
                    "production_qualified": False,
                },
            },
        )
        _write_json(
            root / honey.REQUIREMENTS_PATH,
            {
                "schema_version": "cigar.honey.release-requirements.v1",
                "profile_id": "cigar.honey.local.macos-aarch64.v1",
                "evidence_class": honey.EXPECTED_STATE,
                "fail_closed": True,
                "machine_claims": {
                    "prerelease": True,
                    "production_qualified": False,
                    "supported": False,
                },
            },
        )
        artifacts = []
        for index in range(11):
            artifacts.append(
                {
                    "id": f"payload-{index:02d}",
                    "kind": "release-notes" if index == 10 else "payload-archive",
                    "filename": (
                        "RELEASE_NOTES_HONEY_v0.9.md"
                        if index == 10
                        else f"payload-{index:02d}.tar.gz"
                    ),
                    "contract": None,
                    "producer": ["fixture"],
                    "workspace": "source-metadata",
                    "public_attachment": True,
                    "required": True,
                    "receipt": {
                        "required": False,
                        "schema_version": None,
                        "filename": None,
                    },
                    "qualification_gate_ids": ["fixture"],
                    "sha256_required": True,
                }
            )
        artifacts.extend(
            [
                {
                    "id": "release-manifest",
                    "kind": "release-manifest",
                    "filename": honey.MANIFEST_NAME,
                    "contract": None,
                    "producer": ["assembler"],
                    "workspace": "assembly",
                    "generated_by_assembler": True,
                    "public_attachment": True,
                    "required": True,
                    "receipt": {
                        "required": False,
                        "schema_version": None,
                        "filename": None,
                    },
                    "qualification_gate_ids": ["offline-verification"],
                    "sha256_required": True,
                },
                {
                    "id": "checksums",
                    "kind": "checksum-manifest",
                    "filename": honey.CHECKSUM_NAME,
                    "contract": None,
                    "producer": ["assembler"],
                    "workspace": "assembly",
                    "generated_by_assembler": True,
                    "public_attachment": True,
                    "required": True,
                    "receipt": {
                        "required": False,
                        "schema_version": None,
                        "filename": None,
                    },
                    "qualification_gate_ids": ["offline-verification"],
                    "sha256_required": False,
                },
            ]
        )
        _write_json(
            root / honey.MATRIX_PATH,
            {
                "schema_version": "cigar.honey.artifact-matrix.v1",
                "profile_id": "cigar.honey.local.macos-aarch64.v1",
                "product_version": honey.EXPECTED_VERSION,
                "context_abi": honey.EXPECTED_ABI,
                "release_state": honey.EXPECTED_STATE,
                "artifacts": artifacts,
                "internal_inputs": [],
                "fail_closed": True,
            },
        )
        return root

    def test_loads_exact_thirteen_attachment_honey_projection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            configuration = honey._load_configuration(self._root(Path(raw)))
        self.assertEqual(configuration.version, "0.9.0-honey.1")
        self.assertEqual(len(configuration.artifacts), 13)
        self.assertEqual(
            {spec.filename for spec in configuration.artifacts if spec.generated},
            {honey.MANIFEST_NAME, honey.CHECKSUM_NAME},
        )

    def test_portable_filename_collision_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = self._root(Path(raw))
            matrix_path = root / honey.MATRIX_PATH
            matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
            matrix["artifacts"][1]["filename"] = "PAYLOAD-00.TAR.GZ"
            _write_json(matrix_path, matrix)
            with self.assertRaisesRegex(honey.HoneyAssemblyError, "duplicated"):
                honey._load_configuration(root)

    def test_checksum_manifest_is_sorted_and_excludes_itself(self) -> None:
        manifest = b'{"schema_version":"fixture"}\n'
        payload = honey._checksum_payload({"z": b"last", "a": b"first"}, manifest)
        lines = payload.decode("ascii").splitlines()
        self.assertEqual(
            [line.split("  ", 1)[1] for line in lines], ["a", honey.MANIFEST_NAME, "z"]
        )
        self.assertNotIn(honey.CHECKSUM_NAME, payload.decode("ascii"))

    def test_workspace_parser_requires_key_and_canonical_absolute_path(self) -> None:
        self.assertEqual(
            honey._parse_workspace("python=/private/tmp/python")[0], "python"
        )
        with self.assertRaises(argparse.ArgumentTypeError):
            honey._parse_workspace("python=relative")
        with self.assertRaises(argparse.ArgumentTypeError):
            honey._parse_workspace("missing-separator")

    def test_receipt_authority_policies_match_every_selected_producer(self) -> None:
        configuration = honey._load_configuration(REPOSITORY_ROOT)
        receipt_specs = {
            spec.identifier: spec
            for spec in configuration.artifacts
            if spec.receipt_required
        }
        self.assertEqual(set(honey.RECEIPT_AUTHORITY_PATHS), set(receipt_specs))
        portable_contracts = {
            spec.contract
            for spec in receipt_specs.values()
            if spec.workspace == "portable"
        }
        self.assertEqual(
            set(honey.PORTABLE_AUTHORITY_PATHS),
            {*build_archives.HONEY_AUTHORITY_PATHS, *portable_contracts},
        )
        for identifiers, expected in (
            (
                {"macos-runtime-aarch64"},
                set(build_macos_aarch64_archive.AUTHORITY_PATHS),
            ),
            ({"typescript-sdk"}, set(build_typescript_sdk.HONEY_AUTHORITY_PATHS)),
            (
                {"python-sdk-wheel", "python-sdk-sdist"},
                set(build_python_sdk_artifacts.HONEY_AUTHORITY_PATHS),
            ),
            (
                {"rust-sdk-local-registry"},
                set(build_rust_sdk_crate.HONEY_AUTHORITY_PATHS),
            ),
            (
                {"claude-code-plugin"},
                set(build_claude_code_plugin.HONEY_AUTHORITY_PATHS),
            ),
        ):
            for identifier in identifiers:
                self.assertEqual(
                    set(honey.RECEIPT_AUTHORITY_PATHS[identifier]), expected
                )
        self.assertEqual(
            set(honey.RECEIPT_AUTHORITY_PATHS["honey-demos"]),
            {
                *honey.COMMON_HONEY_AUTHORITY_PATHS,
                "packaging/honey/contracts/demos-archive.v1.json",
            },
        )

    def test_nonportable_receipts_require_exact_authority_inventory(self) -> None:
        configuration = honey._load_configuration(REPOSITORY_ROOT)
        state = honey.RepositoryState("a" * 40, True, "b" * 64)
        source = {
            "revision": state.revision,
            "tree_sha256": "c" * 64,
            "committed": True,
            "clean": True,
        }
        specs = [
            spec
            for spec in configuration.artifacts
            if spec.receipt_required and spec.workspace != "portable"
        ]
        for spec in specs:
            with self.subTest(spec=spec.identifier):
                artifact = f"{spec.identifier} payload".encode()
                receipt = {
                    "schema_version": spec.receipt_schema,
                    "status": "built-unqualified",
                    "product_version": configuration.version,
                    "context_abi": configuration.context_abi,
                    "source_date_epoch": 1,
                    "source": source,
                    "archive": {
                        "path": spec.filename,
                        "sha256": honey.sha256_bytes(artifact),
                        "bytes": len(artifact),
                    },
                    "authority": self._authority(
                        configuration, honey.RECEIPT_AUTHORITY_PATHS[spec.identifier]
                    ),
                }
                observed_source, observed_schema = honey._validate_receipt(
                    honey.canonical_json_bytes(receipt),
                    spec,
                    artifact,
                    configuration,
                    state,
                    1,
                )
                self.assertEqual(observed_source, source)
                self.assertEqual(observed_schema, spec.receipt_schema)

                del receipt["authority"]
                with self.assertRaisesRegex(
                    honey.HoneyAssemblyError, "authority inventory is not exact"
                ):
                    honey._validate_receipt(
                        honey.canonical_json_bytes(receipt),
                        spec,
                        artifact,
                        configuration,
                        state,
                        1,
                    )

    def test_portable_receipt_requires_one_exact_shared_authority_map(self) -> None:
        configuration = honey._load_configuration(REPOSITORY_ROOT)
        specs = tuple(
            spec for spec in configuration.artifacts if spec.workspace == "portable"
        )
        state = honey.RepositoryState("a" * 40, True, "b" * 64)
        source = {
            "revision": state.revision,
            "tree_sha256": "c" * 64,
            "committed": True,
            "clean": True,
        }
        artifacts = {
            spec.identifier: f"{spec.identifier} payload".encode() for spec in specs
        }
        receipt = {
            "schema_version": "cigar.local-archive-build.v1",
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": 1,
            "source": source,
            "artifacts": [
                {
                    "id": spec.identifier,
                    "path": spec.filename,
                    "sha256": honey.sha256_bytes(artifacts[spec.identifier]),
                    "bytes": len(artifacts[spec.identifier]),
                }
                for spec in specs
            ],
            "authority": self._authority(configuration, honey.PORTABLE_AUTHORITY_PATHS),
        }
        self.assertEqual(
            honey._parse_portable_manifest(
                honey.canonical_json_bytes(receipt),
                specs,
                artifacts,
                configuration,
                state,
                1,
            ),
            source,
        )
        del receipt["authority"][honey.REQUIREMENTS_PATH]
        with self.assertRaisesRegex(
            honey.HoneyAssemblyError, "authority inventory is not exact"
        ):
            honey._parse_portable_manifest(
                honey.canonical_json_bytes(receipt),
                specs,
                artifacts,
                configuration,
                state,
                1,
            )


if __name__ == "__main__":
    unittest.main()
