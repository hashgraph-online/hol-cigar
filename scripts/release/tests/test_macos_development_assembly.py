from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest


import sys


RELEASE = Path(__file__).resolve().parents[1]
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

import assemble_macos_development_artifacts as assembler  # noqa: E402
from evidence_workspace import EvidenceWorkspaceError, digest_secure_file  # noqa: E402
from release_lib import ReleaseError, canonical_json_bytes, sha256_bytes  # noqa: E402
import verify_macos_development_assembly as verifier  # noqa: E402


@unittest.skipUnless(os.name == "posix", "secure evidence workspaces require POSIX")
class MacosDevelopmentAssemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cigar-assembly-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        os.chmod(self.base, 0o700)
        self.root = assembler.REPOSITORY_ROOT
        self.configuration = assembler.load_configuration(self.root)
        self.epoch = 1_700_000_000
        self.state = assembler.RepositoryState(
            revision="a" * 40,
            status_sha256="b" * 64,
            clean=False,
        )
        self.source = {
            "revision": self.state.revision,
            "tree_sha256": "c" * 64,
            "committed": True,
            "clean": self.state.clean,
        }

    def _write(self, directory: Path, name: str, payload: bytes) -> Path:
        path = directory / name
        path.write_bytes(payload)
        os.chmod(path, 0o400)
        return path

    def test_independent_verifier_publishes_create_new_external_report(self) -> None:
        evidence = self.base / "verification-evidence"
        arguments = argparse.Namespace(
            evidence_dir=evidence,
            report=Path("assembly/result.json"),
            root=self.root,
        )
        result = {"schema_version": verifier.VERIFICATION_SCHEMA, "status": "pass"}
        verifier._publish_report(arguments, result)
        report = evidence / "assembly/result.json"
        self.assertEqual(report.read_bytes(), canonical_json_bytes(result))
        self.assertEqual(report.stat().st_mode & 0o777, 0o400)
        with self.assertRaises((EvidenceWorkspaceError, ReleaseError)):
            verifier._publish_report(arguments, result)

    def _write_json(self, directory: Path, name: str, value: object) -> Path:
        return self._write(directory, name, canonical_json_bytes(value))

    def _authority(
        self, specs: tuple[assembler.ArtifactSpec, ...]
    ) -> dict[str, dict[str, object]]:
        relatives = {
            "packaging/product-version.v1.json",
            "packaging/artifact-matrix.v1.json",
            "packaging/development/local-macos-aarch64.v1.json",
            *(f"packaging/{spec.contract}" for spec in specs),
        }
        result: dict[str, dict[str, object]] = {}
        for relative in sorted(relatives):
            digest = digest_secure_file(self.root / relative)
            result[relative] = {"sha256": digest.sha256, "bytes": digest.bytes}
        return result

    @staticmethod
    def _claims() -> dict[str, bool]:
        return {
            "development_build": True,
            "distribution_signed": False,
            "qualified": False,
            "published": False,
            "supported": False,
            "release": False,
        }

    def _contract(self, spec: assembler.ArtifactSpec) -> dict[str, object]:
        relative = f"packaging/{spec.contract}"
        digest = digest_secure_file(self.root / relative)
        return {"path": relative, "sha256": digest.sha256}

    def _common_receipt(
        self, spec: assembler.ArtifactSpec, payload: bytes
    ) -> dict[str, object]:
        receipt: dict[str, object] = {
            "schema_version": spec.receipt_schema,
            "status": "built-unqualified",
            "artifact_id": spec.identifier,
            "target": spec.target,
            "product_version": self.configuration.version,
            "context_abi": self.configuration.context_abi,
            "source_date_epoch": self.epoch,
            "source": self.source,
            "host": self.configuration.host,
            "archive": {
                "path": assembler._filename(spec, self.configuration.version),
                "sha256": sha256_bytes(payload),
                "bytes": len(payload),
            },
            "contract": self._contract(spec),
            "authority": self._authority((spec,)),
            "claims": self._claims(),
        }
        if spec.workspace in {"typescript", "rust"}:
            receipt["producer_declared_in_artifact_matrix"] = True
        return receipt

    def _fixtures(self, name: str = "inputs") -> dict[str, Path]:
        root = self.base / name
        root.mkdir(mode=0o700)
        directories: dict[str, Path] = {}
        specs_by_workspace = {
            key: tuple(
                spec for spec in self.configuration.specs if spec.workspace == key
            )
            for key in assembler.WORKSPACE_ARGUMENTS
        }
        payloads = {
            spec.identifier: f"artifact:{spec.identifier}\n".encode("ascii")
            for spec in self.configuration.specs
        }
        for key in assembler.WORKSPACE_ARGUMENTS:
            directory = root / key
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
            directories[key] = directory

        portable_specs = specs_by_workspace["portable"]
        portable_records = []
        portable_checksums: dict[str, bytes] = {}
        for spec in portable_specs:
            filename = assembler._filename(spec, self.configuration.version)
            payload = payloads[spec.identifier]
            self._write(directories["portable"], filename, payload)
            portable_checksums[filename] = payload
            portable_records.append(
                {
                    "id": spec.identifier,
                    "path": filename,
                    "sha256": sha256_bytes(payload),
                    "bytes": len(payload),
                    "contract": f"packaging/{spec.contract}",
                }
            )
        self._write_json(
            directories["portable"],
            "build-manifest.json",
            {
                "schema_version": assembler.BUILD_SCHEMA,
                "product_version": self.configuration.version,
                "context_abi": self.configuration.context_abi,
                "source_date_epoch": self.epoch,
                "source": self.source,
                "artifacts": sorted(portable_records, key=lambda item: item["id"]),
            },
        )
        self._write(
            directories["portable"],
            "SHA256SUMS",
            "".join(
                f"{sha256_bytes(payload)}  {filename}\n"
                for filename, payload in sorted(portable_checksums.items())
            ).encode("ascii"),
        )

        for key in (
            "native",
            "conformance_tool",
            "cigarbench_tool",
            "typescript",
            "rust",
            "go",
            "claude",
        ):
            spec = specs_by_workspace[key][0]
            payload = payloads[spec.identifier]
            self._write(
                directories[key],
                assembler._filename(spec, self.configuration.version),
                payload,
            )
            self._write_json(
                directories[key], spec.receipt, self._common_receipt(spec, payload)
            )

        python_specs = specs_by_workspace["python"]
        python_payloads = {
            spec.identifier: payloads[spec.identifier] for spec in python_specs
        }
        for spec in python_specs:
            self._write(
                directories["python"],
                assembler._filename(spec, self.configuration.version),
                python_payloads[spec.identifier],
            )
        by_id = {spec.identifier: spec for spec in python_specs}
        python_ids = ["python-sdk-sdist", "python-sdk-wheel"]
        self._write_json(
            directories["python"],
            python_specs[0].receipt,
            {
                "schema_version": python_specs[0].receipt_schema,
                "status": "built-unqualified",
                "artifact_ids": python_ids,
                "target": python_specs[0].target,
                "product_version": self.configuration.version,
                "python_distribution_version": assembler._python_version(
                    self.configuration.version
                ),
                "context_abi": self.configuration.context_abi,
                "source_date_epoch": self.epoch,
                "source": self.source,
                "host": self.configuration.host,
                "artifacts": {
                    "sdist": {
                        "path": assembler._filename(
                            by_id[python_ids[0]], self.configuration.version
                        ),
                        "sha256": sha256_bytes(python_payloads[python_ids[0]]),
                        "bytes": len(python_payloads[python_ids[0]]),
                    },
                    "wheel": {
                        "path": assembler._filename(
                            by_id[python_ids[1]], self.configuration.version
                        ),
                        "sha256": sha256_bytes(python_payloads[python_ids[1]]),
                        "bytes": len(python_payloads[python_ids[1]]),
                    },
                },
                "contracts": {
                    identifier: self._contract(by_id[identifier])
                    for identifier in python_ids
                },
                "authority": self._authority(python_specs),
                "claims": self._claims(),
            },
        )

        homebrew_specs = specs_by_workspace["homebrew"]
        homebrew_payloads = {
            spec.identifier: payloads[spec.identifier] for spec in homebrew_specs
        }
        for spec in homebrew_specs:
            self._write(
                directories["homebrew"],
                assembler._filename(spec, self.configuration.version),
                homebrew_payloads[spec.identifier],
            )
        native_spec = specs_by_workspace["native"][0]
        native_payload = payloads[native_spec.identifier]
        native_receipt_payload = (
            directories["native"] / native_spec.receipt
        ).read_bytes()
        summaries = {
            identifier: {
                "schema_version": "cigar.package-verification.v1",
                "status": "passed",
                "file_count": 1,
                "expanded_bytes": 1,
            }
            for identifier in (
                "macos-homebrew-formula-arm64",
                "macos-installer-arm64",
            )
        }
        by_homebrew_id = {spec.identifier: spec for spec in homebrew_specs}
        self._write_json(
            directories["homebrew"],
            homebrew_specs[0].receipt,
            {
                "schema_version": homebrew_specs[0].receipt_schema,
                "status": "built-unqualified",
                "product_version": self.configuration.version,
                "context_abi": self.configuration.context_abi,
                "target": assembler.TARGET_TRIPLE,
                "source_date_epoch": self.epoch,
                "source": self.source,
                "host": self.configuration.host,
                "input_native_archive": {
                    "artifact_id": native_spec.identifier,
                    "path": assembler._filename(
                        native_spec, self.configuration.version
                    ),
                    "sha256": sha256_bytes(native_payload),
                    "bytes": len(native_payload),
                    "build_receipt": {
                        "filename": native_spec.receipt,
                        "sha256": sha256_bytes(native_receipt_payload),
                        "bytes": len(native_receipt_payload),
                    },
                },
                "artifacts": [
                    {
                        "artifact_id": identifier,
                        "kind": by_homebrew_id[identifier].kind,
                        "path": assembler._filename(
                            by_homebrew_id[identifier], self.configuration.version
                        ),
                        "sha256": sha256_bytes(homebrew_payloads[identifier]),
                        "bytes": len(homebrew_payloads[identifier]),
                        "contract": self._contract(by_homebrew_id[identifier]),
                        "package_verification": summaries[identifier],
                    }
                    for identifier in (
                        "macos-homebrew-formula-arm64",
                        "macos-installer-arm64",
                    )
                ],
                "authority": self._authority(homebrew_specs),
                "external_requirements": {
                    "native_code_signing": "not-evidenced",
                    "notarization": "not-evidenced",
                    "artifact_signatures": "not-evidenced",
                    "installed_byte_qualification": "not-evidenced",
                    "homebrew_publication": "not-performed",
                },
                "claims": {
                    **self._claims(),
                    "release_built": False,
                    "notarized": False,
                },
            },
        )
        return directories

    def _arguments(
        self, directories: dict[str, Path], output: Path
    ) -> argparse.Namespace:
        return argparse.Namespace(
            root=self.root,
            portable_workspace=directories["portable"],
            native_workspace=directories["native"],
            conformance_workspace=directories["conformance_tool"],
            cigarbench_workspace=directories["cigarbench_tool"],
            homebrew_workspace=directories["homebrew"],
            typescript_workspace=directories["typescript"],
            rust_workspace=directories["rust"],
            python_workspace=directories["python"],
            go_workspace=directories["go"],
            claude_workspace=directories["claude"],
            evidence_dir=output,
            source_date_epoch=str(self.epoch),
        )

    @staticmethod
    def _accept_package(*_arguments: object) -> dict[str, object]:
        return {"metadata": None}

    @staticmethod
    def _accept_homebrew(*_arguments: object) -> None:
        return None

    def _assemble(self, arguments: argparse.Namespace) -> dict[str, object]:
        return assembler.assemble(
            arguments,
            package_verifier=self._accept_package,
            homebrew_verifier=self._accept_homebrew,
            repository_state=self.state,
        )

    def _verify(self, output: Path) -> dict[str, object]:
        return verifier.verify(
            self.root,
            output,
            package_verifier=self._accept_package,
            repository_state=self.state,
        )

    @staticmethod
    def _replace(path: Path, payload: bytes) -> None:
        os.chmod(path, 0o600)
        path.write_bytes(payload)
        os.chmod(path, 0o400)

    def _replace_json(self, path: Path, mutate: object) -> None:
        document = json.loads(path.read_bytes())
        mutate(document)
        self._replace(path, canonical_json_bytes(document))

    def test_complete_assembly_is_deterministic_and_explicitly_unqualified(
        self,
    ) -> None:
        directories = self._fixtures()
        first = self.base / "assembled-first"
        second = self.base / "assembled-second"
        first_manifest = self._assemble(self._arguments(directories, first))
        second_manifest = self._assemble(self._arguments(directories, second))
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_manifest["schema_version"], assembler.BUILD_SCHEMA)
        self.assertEqual(len(first_manifest["artifacts"]), 17)
        self.assertEqual(
            {record["id"] for record in first_manifest["artifacts"]},
            {spec.identifier for spec in self.configuration.specs},
        )
        for name in sorted(path.name for path in first.iterdir()):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        result = self._verify(first)
        self.assertEqual(result["status"], "verified-development-only")
        self.assertFalse(result["release_eligible"])
        self.assertEqual(result["artifact_count"], 17)

    def test_missing_extra_and_case_colliding_input_files_fail_closed(self) -> None:
        cases = ("missing", "extra", "collision")
        for case in cases:
            with self.subTest(case=case):
                directories = self._fixtures(f"inputs-{case}")
                portable = directories["portable"]
                if case == "missing":
                    (portable / "SHA256SUMS").unlink()
                elif case == "extra":
                    self._write(portable, "unselected.bin", b"unselected\n")
                else:
                    try:
                        self._write(portable, "BUILD-MANIFEST.JSON", b"{}\n")
                    except OSError:
                        # The default macOS filesystem rejects this alias before the
                        # workspace scanner can.  Preserve an explicit assertion that
                        # both spellings map to the verifier's same portable identity.
                        self.assertEqual(
                            assembler._portable_key("BUILD-MANIFEST.JSON"),
                            assembler._portable_key("build-manifest.json"),
                        )
                        continue
                output = self.base / f"assembled-{case}"
                with self.assertRaises(
                    (ReleaseError, assembler.EvidenceWorkspaceError)
                ):
                    self._assemble(self._arguments(directories, output))
                self.assertFalse(output.exists())

    def test_receipt_id_contract_revision_and_claim_mutations_are_rejected(
        self,
    ) -> None:
        cases = ("id", "contract", "revision", "claim")
        for case in cases:
            with self.subTest(case=case):
                directories = self._fixtures(f"receipt-{case}")
                native_spec = next(
                    spec
                    for spec in self.configuration.specs
                    if spec.workspace == "native"
                )
                path = directories["native"] / native_spec.receipt

                def mutate(document: dict[str, object]) -> None:
                    if case == "id":
                        document["artifact_id"] = "source"
                    elif case == "contract":
                        document["contract"] = {
                            "path": "packaging/contracts/docs-archive.v1.json",
                            "sha256": "d" * 64,
                        }
                    elif case == "revision":
                        document["source"]["revision"] = "e" * 40  # type: ignore[index]
                    else:
                        document["claims"]["qualified"] = True  # type: ignore[index]

                self._replace_json(path, mutate)
                with self.assertRaises(ReleaseError):
                    self._assemble(
                        self._arguments(directories, self.base / f"bad-{case}")
                    )

    def test_workspace_alias_and_noncanonical_traversal_are_rejected(self) -> None:
        directories = self._fixtures()
        aliased = self._arguments(directories, self.base / "alias-output")
        aliased.rust_workspace = aliased.typescript_workspace
        with self.assertRaises(ReleaseError):
            self._assemble(aliased)

        traversed = self._arguments(directories, self.base / "traversal-output")
        traversed.go_workspace = Path(
            f"{directories['go'].parent}/../{directories['go'].parent.name}/go"
        )
        with self.assertRaises(ReleaseError):
            self._assemble(traversed)

    def test_symlink_hardlink_and_fifo_inputs_are_rejected(self) -> None:
        for case in ("symlink", "hardlink", "fifo"):
            with self.subTest(case=case):
                directories = self._fixtures(f"unsafe-{case}")
                spec = next(
                    item for item in self.configuration.specs if item.workspace == "go"
                )
                path = directories["go"] / assembler._filename(
                    spec, self.configuration.version
                )
                path.unlink()
                source = self.base / f"unsafe-source-{case}"
                source.write_bytes(b"unsafe\n")
                os.chmod(source, 0o400)
                if case == "symlink":
                    path.symlink_to(source)
                elif case == "hardlink":
                    os.link(source, path)
                else:
                    os.mkfifo(path, 0o400)
                with self.assertRaises(
                    (ReleaseError, assembler.EvidenceWorkspaceError)
                ):
                    self._assemble(
                        self._arguments(directories, self.base / f"unsafe-out-{case}")
                    )

    def test_input_mutation_during_contract_validation_is_detected(self) -> None:
        directories = self._fixtures()
        spec = next(item for item in self.configuration.specs if item.workspace == "go")
        path = directories["go"] / assembler._filename(spec, self.configuration.version)
        mutated = False

        def mutate_once(*_arguments: object) -> dict[str, object]:
            nonlocal mutated
            if not mutated:
                mutated = True
                self._replace(path, b"post-snapshot mutation\n")
            return {"metadata": None}

        with self.assertRaises(ReleaseError):
            assembler.assemble(
                self._arguments(directories, self.base / "mutated-input-output"),
                package_verifier=mutate_once,
                homebrew_verifier=self._accept_homebrew,
                repository_state=self.state,
            )

    def test_output_mutation_and_unreferenced_file_are_rejected(self) -> None:
        directories = self._fixtures()
        output = self.base / "assembled"
        self._assemble(self._arguments(directories, output))
        source_spec = next(
            spec for spec in self.configuration.specs if spec.identifier == "source"
        )
        source_path = output / assembler._filename(
            source_spec, self.configuration.version
        )
        original = source_path.read_bytes()
        self._replace(source_path, b"post-manifest mutation\n")
        with self.assertRaises(ReleaseError):
            self._verify(output)
        self._replace(source_path, original)
        self._write(output, "unreferenced.txt", b"unreferenced\n")
        with self.assertRaises(verifier.EvidenceWorkspaceError):
            self._verify(output)

    def test_nonempty_output_is_rejected_before_authoritative_manifests(self) -> None:
        directories = self._fixtures()
        output = self.base / "nonempty-output"
        output.mkdir(mode=0o700)
        os.chmod(output, 0o700)
        self._write(output, "existing", b"existing\n")
        with self.assertRaises(assembler.EvidenceWorkspaceError):
            self._assemble(self._arguments(directories, output))
        self.assertFalse((output / assembler.BUILD_MANIFEST).exists())
        self.assertFalse((output / assembler.CHECKSUM_MANIFEST).exists())


if __name__ == "__main__":
    unittest.main()
