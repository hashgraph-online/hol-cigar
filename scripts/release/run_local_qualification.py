#!/usr/bin/env python3
"""Run the complete locally testable WP21 qualification and emit one content-free receipt."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from exercise_runbooks import _source as operation_source
from qualify_install import (
    INSTALLED_WORKFLOW_PROFILE,
    MACOS_NO_EGRESS_ENFORCEMENT,
    MACOS_PROCESS_ENFORCEMENT,
    REQUIRED_DRIVER_CHECKS,
    RUNTIME_PROFILE,
    _installed_workflow_binding,
    _validate_driver_receipt as validate_installed_driver_receipt,
)
from product_version import python_distribution_version
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    process_failure_summary,
    repo_root,
    require_source_date_epoch,
    run_bounded,
    validate_qualification_policy,
    validate_release_policy_documents,
    write_json,
)
from signatures import sign, verify as verify_signature
from verify_package import verify as verify_package


PRODUCT_VERSION = "1.0.0-dev.1"
PYTHON_DISTRIBUTION_VERSION = python_distribution_version(PRODUCT_VERSION)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external evidence workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    return parser.parse_args()


def _selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment:
        if os.fspath(argument) != os.fspath(Path(environment)):
            raise ReleaseError(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; "
                "provide one evidence directory"
            )
    if argument is not None:
        return argument
    if environment:
        return Path(environment)
    return None


class _ReportOutput:
    """Pinned create-new destination for the local qualification receipt."""

    def __init__(self, workspace: EvidenceWorkspace, relative: str) -> None:
        self.workspace = workspace
        self.relative = relative

    @classmethod
    def open(
        cls,
        arguments: argparse.Namespace,
        *,
        repository_root: Path,
    ) -> _ReportOutput:
        evidence_root = _selected_evidence_directory(arguments)
        requested = arguments.out
        if evidence_root is not None:
            if requested.is_absolute():
                raise ReleaseError(
                    "--out must be relative when an evidence directory is selected"
                )
            parts = safe_evidence_path(os.fspath(requested))
        else:
            if not requested.is_absolute():
                raise ReleaseError(
                    "--out must be absolute unless --evidence-dir or "
                    "CIGAR_EVIDENCE_DIR is selected"
                )
            evidence_root = requested.parent
            parts = safe_evidence_path(requested.name)
        workspace = EvidenceWorkspace.create(
            evidence_root,
            repository_root=repository_root,
        )
        return cls(workspace, "/".join(parts))

    def publish(self, report: dict[str, Any]) -> None:
        self.workspace.write_json(self.relative, report)

    def close(self) -> None:
        self.workspace.close()


def _is_same_or_beneath(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


@contextmanager
def _private_scratch_directory(repository_root: Path) -> Iterator[Path]:
    """Yield one canonical private scratch root outside the source repository."""

    with tempfile.TemporaryDirectory(prefix="cigar-wp21-local-") as raw:
        scratch = Path(raw).resolve(strict=True)
        repository = repository_root.resolve(strict=True)
        # Qualification scratch holds installed candidate bytes and must remain owner-private.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            scratch,
            0o700,
        )
        metadata = scratch.stat(follow_symlinks=False)
        if (
            scratch != scratch.resolve(strict=True)
            or _is_same_or_beneath(scratch, repository)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ReleaseError(
                "local qualification scratch directory is not canonical, "
                "private, owner-controlled, and external"
            )
        yield scratch


def _run(
    root: Path,
    arguments: list[str],
    environment: dict[str, str] | None = None,
    expected: int = 0,
) -> subprocess.CompletedProcess[str]:
    raw = run_bounded(
        arguments,
        cwd=root,
        env=environment,
        timeout=600,
        max_stdout=32 * 1024 * 1024,
        max_stderr=32 * 1024 * 1024,
    )
    if raw.returncode != expected:
        command_label = Path(arguments[1] if len(arguments) > 1 else arguments[0]).name
        raise ReleaseError(
            f"{command_label}: {process_failure_summary(raw, 'local qualification command')}"
        )
    result = subprocess.CompletedProcess(
        raw.args,
        raw.returncode,
        raw.stdout.decode("utf-8", errors="replace"),
        raw.stderr.decode("utf-8", errors="replace"),
    )
    return result


def _qualification_environment(epoch: int) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("CIGAR_EVIDENCE_DIR", None)
    environment.update(
        {
            "SOURCE_DATE_EPOCH": str(epoch),
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONHASHSEED": "0",
            "NO_COLOR": "1",
        }
    )
    return environment


def _expect_failure(callable_value: Any, label: str) -> None:
    try:
        callable_value()
    except ReleaseError:
        return
    raise ReleaseError(f"negative test unexpectedly passed: {label}")


def _oci_descriptor(payload: bytes, media_type: str) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "size": len(payload),
    }


def _write_oci_fixture(
    path: Path,
    epoch: int,
    runtime_user: str,
    *,
    wrong_diff_id: bool = False,
    secret_layer: bool = False,
) -> None:
    layer_tar = io.BytesIO()
    with tarfile.open(
        fileobj=layer_tar, mode="w", format=tarfile.PAX_FORMAT
    ) as layer_archive:
        layer_payload = (
            b"-----BEGIN " + b"PRIVATE KEY-----\n"
            if secret_layer
            else b"synthetic cigar executable\n"
        )
        layer_member = tarfile.TarInfo("usr/bin/cigar")
        layer_member.size = len(layer_payload)
        layer_member.mode = 0o755
        layer_member.mtime = epoch
        layer_member.uid = 0
        layer_member.gid = 0
        layer_member.uname = ""
        layer_member.gname = ""
        layer_archive.addfile(layer_member, io.BytesIO(layer_payload))
    uncompressed_layer = layer_tar.getvalue()
    compressed_layer = gzip.compress(uncompressed_layer, compresslevel=9, mtime=0)
    layer = _oci_descriptor(
        compressed_layer, "application/vnd.oci.image.layer.v1.tar+gzip"
    )
    blobs: dict[str, bytes] = {
        f"blobs/sha256/{layer['digest'].removeprefix('sha256:')}": compressed_layer,
    }
    manifest_descriptors: list[dict[str, Any]] = []
    for architecture in ("amd64", "arm64"):
        config_payload = canonical_json_bytes(
            {
                "architecture": architecture,
                "config": {"Cmd": ["/usr/bin/cigar"], "User": runtime_user},
                "os": "linux",
                "rootfs": {
                    "diff_ids": [
                        f"sha256:{'f' * 64 if wrong_diff_id else hashlib.sha256(uncompressed_layer).hexdigest()}"
                    ],
                    "type": "layers",
                },
            }
        )
        config = _oci_descriptor(
            config_payload, "application/vnd.oci.image.config.v1+json"
        )
        blobs[f"blobs/sha256/{config['digest'].removeprefix('sha256:')}"] = (
            config_payload
        )
        manifest_payload = canonical_json_bytes(
            {
                "config": config,
                "layers": [layer],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2,
            }
        )
        manifest = _oci_descriptor(
            manifest_payload, "application/vnd.oci.image.manifest.v1+json"
        )
        manifest["annotations"] = {
            "dev.cigar.context-abi": "cigar.context.v1",
            "org.opencontainers.image.version": PRODUCT_VERSION,
        }
        manifest["platform"] = {"architecture": architecture, "os": "linux"}
        blobs[f"blobs/sha256/{manifest['digest'].removeprefix('sha256:')}"] = (
            manifest_payload
        )
        manifest_descriptors.append(manifest)
    files = {
        "index.json": canonical_json_bytes(
            {
                "manifests": manifest_descriptors,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        ),
        "oci-layout": canonical_json_bytes({"imageLayoutVersion": "1.0.0"}),
        **blobs,
    }
    with tarfile.open(path, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o644
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            archive.addfile(member, io.BytesIO(payload))


def _qualify(
    arguments: argparse.Namespace,
    *,
    root: Path,
    report_output: _ReportOutput,
) -> int:
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    environment = _qualification_environment(epoch)
    python = sys.executable
    checks: list[dict[str, Any]] = []

    with _private_scratch_directory(root) as temporary:
        _run(root, [python, "scripts/release/validate_metadata.py"], environment)
        matrix = load_json(root / "packaging/artifact-matrix.v1.json")
        requirements = load_json(root / "packaging/release-requirements.v1.json")
        gaps = load_json(root / "packaging/qualification-gaps.v1.json")
        validate_release_policy_documents(matrix, requirements, gaps)
        qualification_policy = load_json(
            root / "packaging/qualification-category-map.v1.json"
        )
        validate_qualification_policy(qualification_policy)
        weakened_requirements = load_json(
            root / "packaging/release-requirements.v1.json"
        )
        weakened_requirements["required_evidence_categories"].remove("security")
        _expect_failure(
            lambda: validate_release_policy_documents(
                matrix, weakened_requirements, gaps
            ),
            "weakened release policy",
        )
        weakened_qualification_policy = load_json(
            root / "packaging/qualification-category-map.v1.json"
        )
        weakened_qualification_policy["universal_requirements"].clear()
        _expect_failure(
            lambda: validate_qualification_policy(weakened_qualification_policy),
            "weakened artifact qualification policy",
        )
        checks.append(
            {
                "id": "metadata",
                "status": "passed",
                "detail": "artifact matrix, contracts, versions, ABI, schemas, gaps, and pinned anti-weakening release and artifact-qualification policies are valid",
            }
        )

        docs_report = temporary / "docs.json"
        _run(
            root,
            [
                python,
                "scripts/release/check_docs.py",
                "--execute-local",
                "--report",
                str(docs_report),
            ],
            environment,
        )
        docs = load_json(docs_report)
        checks.append(
            {
                "id": "docs",
                "status": "passed",
                "detail": f"{docs['pages']} pages, {docs['links']} links, {docs['executed_commands']} local command steps",
            }
        )

        operations = temporary / "operations"
        _run(
            root,
            [
                python,
                "scripts/release/exercise_runbooks.py",
                "--mode",
                "static",
                "--source-date-epoch",
                str(epoch),
                "--out",
                str(operations),
            ],
            environment,
        )
        checks.append(
            {
                "id": "runbooks-static",
                "status": "passed",
                "detail": "all eight required runbooks contain bounded preconditions, recovery, stop conditions, and evidence rules",
            }
        )

        operation_root = temporary / "operation-build-fixture"
        (operation_root / "packaging").mkdir(parents=True)
        candidate_artifact = operation_root / "candidate.tar.gz"
        candidate_artifact.write_bytes(b"candidate artifact\n")
        candidate_record = {
            "bytes": candidate_artifact.stat().st_size,
            "contract": "packaging/contracts/source.v1.json",
            "id": "source",
            "path": candidate_artifact.name,
            "sha256": hashlib.sha256(candidate_artifact.read_bytes()).hexdigest(),
        }
        write_json(
            operation_root / "packaging/artifact-matrix.v1.json",
            {
                "artifacts": [
                    {
                        "contract": "contracts/source.v1.json",
                        "filename": candidate_artifact.name,
                        "id": "source",
                        "required_for_release": True,
                    }
                ],
                "context_abi": "cigar.context.v1",
                "product_version": PRODUCT_VERSION,
                "release_state": "release",
                "schema_version": "cigar.artifact-matrix.v1",
            },
        )
        operation_build = operation_root / "build-manifest.json"
        write_json(
            operation_build,
            {
                "artifacts": [candidate_record],
                "context_abi": "cigar.context.v1",
                "product_version": PRODUCT_VERSION,
                "schema_version": "cigar.release-build.v1",
                "source": {
                    "clean": True,
                    "committed": True,
                    "revision": "b" * 40,
                    "tree_sha256": "c" * 64,
                },
                "source_date_epoch": epoch,
            },
        )
        operation_arguments = argparse.Namespace(
            candidate_manifest=operation_build,
            mode="live",
            source_date_epoch=0,
        )
        operation_identity = operation_source(
            operation_arguments,
            operation_root,
            operation_root / "packaging/operation-exercises.v1.json",
        )
        if operation_identity != ("b" * 40, epoch, ["source"]):
            raise ReleaseError(
                "operation candidate build binding returned an unexpected identity"
            )
        candidate_artifact.write_bytes(b"mutated candidate artifact\n")
        _expect_failure(
            lambda: operation_source(
                operation_arguments,
                operation_root,
                operation_root / "packaging/operation-exercises.v1.json",
            ),
            "operation candidate artifact mutation",
        )

        installed_checks = sorted(REQUIRED_DRIVER_CHECKS)
        installed_workflow: dict[str, object] = {
            "profile": INSTALLED_WORKFLOW_PROFILE,
            "full_surface_sha256": "1" * 64,
            "semantic_identity_sha256": "2" * 64,
            "cigar_sha256": "3" * 64,
            "cigard_sha256": "4" * 64,
            "binding_sha256": "0" * 64,
            "no_egress_enforcement": MACOS_NO_EGRESS_ENFORCEMENT,
        }
        installed_workflow["binding_sha256"] = _installed_workflow_binding(
            artifact_id="source",
            artifact_sha256="d" * 64,
            source_revision="b" * 40,
            workflow=installed_workflow,
        )
        installed_driver_receipt = {
            "artifact_id": "source",
            "artifact_sha256": "d" * 64,
            "checks": [
                {"id": identifier, "status": "passed"}
                for identifier in installed_checks
            ],
            "context_abi": "cigar.context.v1",
            "source_revision": "b" * 40,
            "runtime_profile": RUNTIME_PROFILE,
            "installed_workflow": installed_workflow,
            "process_enforcement": MACOS_PROCESS_ENFORCEMENT,
            "product_version": PRODUCT_VERSION,
            "schema_version": "cigar.installed-driver.v1",
            "status": "passed",
        }
        validate_installed_driver_receipt(
            canonical_json_bytes(installed_driver_receipt),
            "source",
            "d" * 64,
            PRODUCT_VERSION,
            "cigar.context.v1",
            "b" * 40,
        )
        stale_installed_receipt = {
            **installed_driver_receipt,
            "artifact_sha256": "e" * 64,
        }
        _expect_failure(
            lambda: validate_installed_driver_receipt(
                canonical_json_bytes(stale_installed_receipt),
                "source",
                "d" * 64,
                PRODUCT_VERSION,
                "cigar.context.v1",
                "b" * 40,
            ),
            "installed driver stale artifact binding",
        )
        checks.append(
            {
                "id": "candidate-driver-bindings",
                "status": "passed",
                "detail": "operation build manifests and installed-driver receipts bind exact candidate identities; mutated or stale artifact bindings failed",
            }
        )

        generated_inventory = temporary / "third-party-inventory.json"
        _run(
            root,
            [
                python,
                "scripts/release/generate_license_inventory.py",
                "--out",
                str(generated_inventory),
            ],
            environment,
        )
        if (
            generated_inventory.read_bytes()
            != (root / "packaging/licenses/third-party-inventory.v1.json").read_bytes()
        ):
            raise ReleaseError("committed third-party license inventory is stale")
        inventory = load_json(generated_inventory)
        checks.append(
            {
                "id": "license-inventory",
                "status": "passed",
                "detail": f"{inventory['component_count']} components inventoried; {inventory['review_required_count']} explicitly remain review-required",
            }
        )

        distribution = temporary / "dist"
        _run(
            root,
            [
                python,
                "scripts/release/build_archives.py",
                "--out",
                str(distribution),
                "--source-date-epoch",
                str(epoch),
            ],
            environment,
        )
        build = load_json(distribution / "build-manifest.json")
        checks.append(
            {
                "id": "deterministic-archives",
                "status": "passed",
                "detail": f"{len(build['artifacts'])} source-derived archives built and contract-verified",
            }
        )

        reproducibility = temporary / "reproducibility.json"
        _run(
            root,
            [
                python,
                "scripts/release/check_reproducibility.py",
                "--source-date-epoch",
                str(epoch),
                "--report",
                str(reproducibility),
            ],
            environment,
        )
        checks.append(
            {
                "id": "reproducibility",
                "status": "passed",
                "detail": "two isolated homes produced identical SHA-256 payloads for all local archives",
            }
        )

        source_record = next(
            record for record in build["artifacts"] if record["id"] == "source"
        )
        source_archive = distribution / source_record["path"]
        sbom_directory = temporary / "sbom"
        _run(
            root,
            [
                python,
                "scripts/release/generate_sbom.py",
                "--artifact",
                str(source_archive),
                "--out",
                str(sbom_directory),
                "--source-date-epoch",
                str(epoch),
            ],
            environment,
        )
        sbom_binding = load_json(sbom_directory / "sbom-artifacts.json")
        checks.append(
            {
                "id": "sbom",
                "status": "passed",
                "detail": f"SPDX 2.3 and CycloneDX 1.6 generated for {sbom_binding['component_count']} locked components",
            }
        )

        provenance = temporary / "provenance.json"
        _run(
            root,
            [
                python,
                "scripts/release/generate_provenance.py",
                "--artifact",
                str(source_archive),
                "--source-archive",
                str(source_archive),
                "--source-revision",
                build["source"]["revision"],
                "--builder-id",
                "cigar-local-qualification",
                "--workflow-id",
                "cigar.local.wp21-qualification.v1",
                "--network-mode",
                "unspecified",
                "--command",
                "python3 scripts/release/build_archives.py",
                "--source-date-epoch",
                str(epoch),
                "--out",
                str(provenance),
            ],
            environment,
        )
        checks.append(
            {
                "id": "provenance",
                "status": "passed",
                "detail": "deterministic in-toto/SLSA statement binds artifact, source archive, locks, builder, and command",
            }
        )

        key_directory = temporary / "ephemeral-key"
        key_directory.mkdir(mode=0o700)
        private_key = key_directory / "private.pem"
        public_key = key_directory / "public.pem"
        _run(
            root,
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            environment,
        )
        os.chmod(private_key, 0o600)
        _run(
            root,
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            environment,
        )
        _expect_failure(
            lambda: sign(
                source_archive,
                private_key,
                public_key,
                source_archive,
                signer_principal="cigar:local-qualification",
                purpose="release-artifact",
                signed_at=epoch,
                expires_at=epoch + 3600,
            ),
            "signature output aliases payload",
        )
        envelope = key_directory / "source.sig.json"
        sign(
            source_archive,
            private_key,
            public_key,
            envelope,
            signer_principal="cigar:local-qualification",
            purpose="release-artifact",
            signed_at=epoch,
            expires_at=epoch + 3600,
        )
        verify_signature(
            envelope,
            source_archive,
            public_key,
            expected_purpose="release-artifact",
            expected_signer="cigar:local-qualification",
            verification_time=epoch,
        )
        corrupted = load_json(envelope)
        signature = bytearray(
            base64.b64decode(corrupted["signature_base64"], validate=True)
        )
        signature[0] ^= 1
        corrupted["signature_base64"] = base64.b64encode(signature).decode("ascii")
        corrupted_path = key_directory / "corrupted.sig.json"
        write_json(corrupted_path, corrupted)
        _expect_failure(
            lambda: verify_signature(
                corrupted_path,
                source_archive,
                public_key,
                expected_purpose="release-artifact",
                expected_signer="cigar:local-qualification",
                verification_time=epoch,
            ),
            "corrupted signature",
        )
        repurposed = load_json(envelope)
        repurposed["purpose"] = "release-sbom"
        repurposed_path = key_directory / "repurposed.sig.json"
        write_json(repurposed_path, repurposed)
        _expect_failure(
            lambda: verify_signature(
                repurposed_path,
                source_archive,
                public_key,
                expected_purpose="release-sbom",
                expected_signer="cigar:local-qualification",
                verification_time=epoch,
            ),
            "repurposed envelope",
        )
        _expect_failure(
            lambda: verify_signature(
                envelope,
                source_archive,
                public_key,
                expected_purpose="release-artifact",
                expected_signer="cigar:local-qualification",
                verification_time=epoch + 3600,
            ),
            "expired signature",
        )
        swapped_directory = temporary / "swapped"
        swapped_directory.mkdir()
        swapped = swapped_directory / source_archive.name
        swapped.write_bytes(b"different artifact bytes\n")
        _expect_failure(
            lambda: verify_signature(
                envelope,
                swapped,
                public_key,
                expected_purpose="release-artifact",
                expected_signer="cigar:local-qualification",
                verification_time=epoch,
            ),
            "swapped artifact",
        )
        checks.append(
            {
                "id": "signatures",
                "status": "passed",
                "detail": "domain-separated Ed25519 verification passed; output alias, corrupted, repurposed, expired, and same-name swapped payload cases failed",
            }
        )

        oci_contract = root / "packaging/contracts/oci-image.v1.json"
        oci_fixture = temporary / "oci-image.tar"
        _write_oci_fixture(oci_fixture, epoch, "10001:10001")
        oci_report = verify_package(
            oci_fixture,
            oci_contract,
            PRODUCT_VERSION,
            "cigar.context.v1",
            epoch,
        )
        expected_oci = {
            "layers": 1,
            "non_root": True,
            "platforms": ["linux/amd64", "linux/arm64"],
            "referenced_blobs": 5,
        }
        if oci_report.get("oci") != expected_oci:
            raise ReleaseError(
                "OCI package verifier returned an unexpected structural summary"
            )
        root_oci_fixture = temporary / "root-oci-image.tar"
        _write_oci_fixture(root_oci_fixture, epoch, "10001:0")
        _expect_failure(
            lambda: verify_package(
                root_oci_fixture,
                oci_contract,
                PRODUCT_VERSION,
                "cigar.context.v1",
                epoch,
            ),
            "OCI image with root group",
        )
        wrong_diff_oci_fixture = temporary / "wrong-diff-id-oci-image.tar"
        _write_oci_fixture(
            wrong_diff_oci_fixture,
            epoch,
            "10001:10001",
            wrong_diff_id=True,
        )
        _expect_failure(
            lambda: verify_package(
                wrong_diff_oci_fixture,
                oci_contract,
                PRODUCT_VERSION,
                "cigar.context.v1",
                epoch,
            ),
            "OCI image with a stale config diff ID",
        )
        secret_oci_fixture = temporary / "secret-layer-oci-image.tar"
        _write_oci_fixture(
            secret_oci_fixture,
            epoch,
            "10001:10001",
            secret_layer=True,
        )
        _expect_failure(
            lambda: verify_package(
                secret_oci_fixture,
                oci_contract,
                PRODUCT_VERSION,
                "cigar.context.v1",
                epoch,
            ),
            "OCI image containing private key material",
        )
        checks.append(
            {
                "id": "oci-contract",
                "status": "passed",
                "detail": "an exact dual-platform OCI layout passed descriptor, layer-tar, diff-ID, content, version, ABI, and non-root checks; root-group, stale-diff-ID, and secret-layer images failed",
            }
        )

        checksum_contract_path = temporary / "checksum-contract.json"
        write_json(
            checksum_contract_path,
            {
                "allow": ["SHA256SUMS", "payload.bin"],
                "checksum_manifest": {
                    "path": "SHA256SUMS",
                    "scope": "all-payload-files",
                },
                "content_scan": True,
                "content_scan_exemptions": [],
                "deny": [],
                "formats": ["tar.gz"],
                "id": "selftest-checksum-v1",
                "line_endings": "lf",
                "max_entries": 8,
                "max_member_bytes": 1024,
                "max_total_bytes": 4096,
                "modes": ["0644"],
                "required": ["SHA256SUMS", "payload.bin"],
                "schema_version": "cigar.package-contract.v1",
                "symlinks": "forbid",
            },
        )
        checksum_payload = b"synthetic package payload\n"
        checksum_line = (
            f"{hashlib.sha256(checksum_payload).hexdigest()}  payload.bin\n".encode(
                "ascii"
            )
        )

        def write_checksum_fixture(path: Path, manifest_payload: bytes) -> None:
            with tarfile.open(path, "w:gz") as archive:
                for name, payload in (
                    ("payload.bin", checksum_payload),
                    ("SHA256SUMS", manifest_payload),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    member.mode = 0o644
                    member.mtime = epoch
                    member.uid = 0
                    member.gid = 0
                    archive.addfile(member, io.BytesIO(payload))

        checksum_fixture = temporary / "checksum-package.tar.gz"
        write_checksum_fixture(checksum_fixture, checksum_line)
        verify_package(checksum_fixture, checksum_contract_path, None, None, epoch)
        bad_checksum_fixture = temporary / "bad-checksum-package.tar.gz"
        write_checksum_fixture(
            bad_checksum_fixture, f"{'0' * 64}  payload.bin\n".encode("ascii")
        )
        _expect_failure(
            lambda: verify_package(
                bad_checksum_fixture, checksum_contract_path, None, None, epoch
            ),
            "stale internal checksum manifest",
        )

        python_sdist_contract = root / "packaging/contracts/python-sdist.v1.json"

        def write_python_sdist_fixture(path: Path, gitignore_payload: bytes) -> None:
            prefix = f"cigar_sdk-{PYTHON_DISTRIBUTION_VERSION}/"
            release_payload = canonical_json_bytes(
                {
                    "schema_version": "cigar.sdk-release.v1",
                    "name": "cigar-sdk",
                    "version": PRODUCT_VERSION,
                    "context_abi": "cigar.context.v1",
                }
            )
            members = {
                ".gitignore": gitignore_payload,
                "LICENSE": b"synthetic Apache-2.0 license fixture\n",
                "NOTICE": b"synthetic CIGAR notice fixture\n",
                "PKG-INFO": (
                    f"Metadata-Version: 2.4\nName: cigar-sdk\nVersion: {PYTHON_DISTRIBUTION_VERSION}\n".encode()
                ),
                "README.md": b"# Synthetic CIGAR SDK sdist fixture\n",
                "pyproject.toml": (
                    f'[project]\nname = "cigar-sdk"\nversion = "{PYTHON_DISTRIBUTION_VERSION}"\n'.encode()
                ),
                "src/cigar_sdk/__init__.py": b'CONTEXT_ABI = "cigar.context.v1"\n',
                "src/cigar_sdk/release.json": release_payload,
            }
            with tarfile.open(path, "w:gz") as archive:
                for relative, payload in sorted(members.items()):
                    member = tarfile.TarInfo(prefix + relative)
                    member.size = len(payload)
                    member.mode = 0o644
                    member.mtime = epoch
                    member.uid = 0
                    member.gid = 0
                    archive.addfile(member, io.BytesIO(payload))

        safe_python_sdist = temporary / "safe-python-sdist.tar.gz"
        write_python_sdist_fixture(safe_python_sdist, b"dist/\n__pycache__/\n")
        verify_package(
            safe_python_sdist,
            python_sdist_contract,
            PRODUCT_VERSION,
            "cigar.context.v1",
            epoch,
        )
        secret_python_sdist = temporary / "secret-python-sdist.tar.gz"
        write_python_sdist_fixture(
            secret_python_sdist,
            b"dist/\n# gh" + b"p_0123456789abcdefghijklmnop\n",
        )
        _expect_failure(
            lambda: verify_package(
                secret_python_sdist,
                python_sdist_contract,
                PRODUCT_VERSION,
                "cigar.context.v1",
                epoch,
            ),
            "Hatchling sdist .gitignore containing a credential",
        )

        malicious = temporary / "traversal.tar.gz"
        with tarfile.open(malicious, "w:gz") as archive:
            payload = b"escape"
            member = tarfile.TarInfo("../escape")
            member.size = len(payload)
            member.mode = 0o644
            member.mtime = epoch
            archive.addfile(member, io.BytesIO(payload))
        _expect_failure(
            lambda: verify_package(
                malicious,
                root / "packaging/contracts/license-archive.v1.json",
                PRODUCT_VERSION,
                "cigar.context.v1",
                epoch,
            ),
            "archive traversal",
        )
        entry_bomb = temporary / "entry-bomb.tar.gz"
        with tarfile.open(entry_bomb, "w:gz") as archive:
            for name in ("one", "two"):
                member = tarfile.TarInfo(name)
                member.size = 0
                member.mode = 0o644
                member.mtime = epoch
                archive.addfile(member, io.BytesIO())
        bounded_contract = load_json(
            root / "packaging/contracts/license-archive.v1.json"
        )
        bounded_contract["max_entries"] = 1
        bounded_contract_path = temporary / "bounded-contract.json"
        write_json(bounded_contract_path, bounded_contract)
        _expect_failure(
            lambda: verify_package(
                entry_bomb,
                bounded_contract_path,
                PRODUCT_VERSION,
                "cigar.context.v1",
                epoch,
            ),
            "archive entry-count bomb",
        )
        broad_contract = load_json(root / "packaging/contracts/license-archive.v1.json")
        broad_contract["id"] = "selftest-broad-v1"
        broad_contract["allow"] = ["**"]
        broad_contract["required"] = []
        broad_contract_path = temporary / "broad-contract.json"
        write_json(broad_contract_path, broad_contract)
        root_secret = temporary / "root-secret.tar.gz"
        with tarfile.open(root_secret, "w:gz") as archive:
            payload = b"synthetic configuration\n"
            member = tarfile.TarInfo(".env")
            member.size = len(payload)
            member.mode = 0o644
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            archive.addfile(member, io.BytesIO(payload))
        _expect_failure(
            lambda: verify_package(
                root_secret,
                broad_contract_path,
                None,
                None,
                epoch,
            ),
            "root-level deny pattern",
        )
        case_collision = temporary / "case-collision.tar.gz"
        with tarfile.open(case_collision, "w:gz") as archive:
            for name in ("Payload.txt", "payload.txt"):
                payload = b"synthetic payload\n"
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = 0o644
                member.mtime = epoch
                member.uid = 0
                member.gid = 0
                archive.addfile(member, io.BytesIO(payload))
        _expect_failure(
            lambda: verify_package(
                case_collision,
                broad_contract_path,
                None,
                None,
                epoch,
            ),
            "case-insensitive archive collision",
        )
        checks.append(
            {
                "id": "negative-package",
                "status": "passed",
                "detail": "the required Hatchling .gitignore passed only with safe scanned bytes; credential-bearing .gitignore, stale internal checksums, traversal, entry-count bomb, root-level double-star deny match, and case-insensitive collision were rejected before extraction",
            }
        )

        _run(
            root, [python, "scripts/release/selftest_release_verifier.py"], environment
        )
        checks.append(
            {
                "id": "release-verifier-selftest",
                "status": "passed",
                "detail": "a minimal committed, fully signed fixture passed and rejected a mismatched build contract, artifact or raw-report tampering, and an unreferenced payload",
            }
        )

        release_gate = _run(
            root,
            [python, "scripts/release/validate_metadata.py", "--release"],
            environment,
            expected=1,
        )
        expected_release_gate_reasons = (
            "artifact matrix remains in development state",
            "release qualification gaps remain open",
        )
        if not any(
            reason in release_gate.stderr for reason in expected_release_gate_reasons
        ):
            raise ReleaseError(
                "production metadata gate failed for an unexpected reason"
            )
        checks.append(
            {
                "id": "production-gate",
                "status": "passed",
                "detail": "production gate rejected the development workspace with no bypass",
            }
        )

    gaps_document = load_json(root / "packaging/qualification-gaps.v1.json")
    blocking_gaps = sorted(
        entry["id"]
        for entry in gaps_document["gaps"]
        if entry.get("release_blocking") is True
    )
    report = {
        "schema_version": "cigar.wp21-local-qualification.v1",
        "scope": "locally-testable-packaging-documentation-operations",
        "status": "passed-local-scope",
        "release_ready": False,
        "source_date_epoch": epoch,
        "source": build["source"],
        "checks": checks,
        "release_blocking_gaps": blocking_gaps,
    }
    report_output.publish(report)
    print(
        f"WP21 local qualification passed {len(checks)} checks; {len(blocking_gaps)} release-blocking gaps remain"
    )
    return 0


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve(strict=True)
    report_output = _ReportOutput.open(arguments, repository_root=root)
    try:
        return _qualify(arguments, root=root, report_output=report_output)
    finally:
        report_output.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        OSError,
        subprocess.TimeoutExpired,
        ReleaseError,
    ) as error:
        raise SystemExit(f"WP21 local qualification failed: {error}") from error
