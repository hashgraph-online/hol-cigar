#!/usr/bin/env python3
"""Independently reconstruct an Apple-silicon development artifact assembly."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

from assemble_macos_development_artifacts import (
    BUILD_MANIFEST,
    BUILD_SCHEMA,
    CHECKSUM_MANIFEST,
    MAX_OUTPUT_TOTAL_BYTES,
    REPOSITORY_ROOT,
    ArtifactSpec,
    RepositoryState,
    _filename,
    load_configuration,
)
from evidence_workspace import (
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    resolve_beneath,
    run_bounded,
    selected_evidence_directory,
    sha256_bytes,
)
from verify_package import verify as verify_package


VERIFICATION_SCHEMA = "cigar.development-macos-assembly-verification.v1"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external private evidence workspace (or CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="safe relative create-new verification report path",
    )
    return parser.parse_args()


def _publish_report(arguments: argparse.Namespace, result: dict[str, Any]) -> None:
    selected = selected_evidence_directory(arguments.evidence_dir)
    if selected is None:
        if arguments.report is not None:
            raise ReleaseError("--report requires an external evidence directory")
        return
    if arguments.report is None:
        raise ReleaseError("--evidence-dir requires a safe relative --report path")
    try:
        relative = "/".join(safe_evidence_path(os.fspath(arguments.report)))
        workspace = EvidenceWorkspace.create(
            selected, repository_root=arguments.root.resolve(strict=True)
        )
    except EvidenceWorkspaceError as error:
        raise ReleaseError(
            f"cannot open assembly verification evidence: {error}"
        ) from error
    try:
        workspace.read_files(set())
        workspace.write_json(relative, result)
        workspace.read_files({relative})
    finally:
        workspace.close()


def _repository_state(root: Path) -> RepositoryState:
    revision = run_bounded(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        timeout=60,
        max_stdout=1024,
        max_stderr=1024 * 1024,
    )
    status = run_bounded(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        timeout=60,
        max_stdout=32 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if revision.returncode != 0 or status.returncode != 0:
        raise ReleaseError("cannot bind verification to the repository source state")
    value = revision.stdout.decode("ascii", errors="strict").strip()
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
        raise ReleaseError("repository HEAD is not a canonical lowercase revision")
    return RepositoryState(
        revision=value,
        status_sha256=sha256_bytes(status.stdout),
        clean=not bool(status.stdout.strip()),
    )


def _external_distribution(path: Path, root: Path) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise ReleaseError("assembled distribution must be an absolute canonical path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot inspect assembled distribution: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseError("assembled distribution must already exist as a directory")
    try:
        inside = os.path.commonpath((os.fspath(path), os.fspath(root))) == os.fspath(
            root
        )
    except ValueError:
        inside = False
    if inside:
        raise ReleaseError(
            "assembled distribution must be outside the source repository"
        )
    return path


def _stage_and_verify(
    payload: bytes,
    spec: ArtifactSpec,
    version: str,
    context_abi: str,
    epoch: int,
    source: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="cigar-development-assembly-reverify-"
    ) as raw:
        directory = Path(raw).resolve(strict=True)
        # Reverification inputs remain unpublished until every binding passes.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            directory, 0o700
        )
        archive = directory / _filename(spec, version)
        descriptor = os.open(
            archive,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            offset = 0
            while offset < len(view):
                count = os.write(descriptor, view[offset:])
                if count <= 0:
                    raise ReleaseError(
                        "short write while staging independent verification"
                    )
                offset += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        expected_version = (
            None if spec.identifier == "macos-installer-arm64" else version
        )
        expected_abi = (
            None if spec.identifier == "macos-installer-arm64" else context_abi
        )
        result = verify_package(
            archive,
            resolve_beneath(root, f"packaging/{spec.contract}"),
            expected_version,
            expected_abi,
            epoch,
        )
    metadata = result.get("metadata")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or metadata.get("artifact_id") != spec.identifier
        or metadata.get("product_version") != version
        or metadata.get("context_abi") != context_abi
        or metadata.get("source_date_epoch") != epoch
        or metadata.get("source") != source
    ):
        raise ReleaseError(
            f"assembled package metadata binding is stale: {spec.identifier}"
        )
    return result


def _checksum_bytes(
    specs: tuple[ArtifactSpec, ...], payloads: dict[str, bytes], version: str
) -> bytes:
    records = sorted(
        (_filename(spec, version), sha256_bytes(payloads[spec.identifier]))
        for spec in specs
    )
    return "".join(f"{digest}  {path}\n" for path, digest in records).encode("ascii")


def verify(
    root: Path,
    dist: Path,
    *,
    package_verifier: Any = _stage_and_verify,
    repository_state: RepositoryState | None = None,
) -> dict[str, Any]:
    configuration = load_configuration(root)
    selected_dist = _external_distribution(dist, configuration.root)
    names = {_filename(spec, configuration.version) for spec in configuration.specs}
    names.update({BUILD_MANIFEST, CHECKSUM_MANIFEST})
    limits = EvidenceLimits(
        max_files=64,
        max_directories=8,
        max_file_bytes=64 * 1024 * 1024,
        max_total_bytes=MAX_OUTPUT_TOTAL_BYTES,
        max_json_bytes=16 * 1024 * 1024,
        max_path_depth=4,
    )
    workspace = EvidenceWorkspace.create(
        selected_dist, repository_root=configuration.root, limits=limits
    )
    try:
        snapshot = workspace.read_files(names, strict_read_only=True)
        manifest_payload = snapshot[BUILD_MANIFEST]
        manifest = load_json_bytes(manifest_payload, BUILD_MANIFEST)
        if (
            not isinstance(manifest, dict)
            or manifest_payload != canonical_json_bytes(manifest)
            or set(manifest)
            != {
                "schema_version",
                "product_version",
                "context_abi",
                "source_date_epoch",
                "source",
                "artifacts",
            }
            or manifest.get("schema_version") != BUILD_SCHEMA
            or manifest.get("product_version") != configuration.version
            or manifest.get("context_abi") != configuration.context_abi
            or not isinstance(manifest.get("source_date_epoch"), int)
            or isinstance(manifest.get("source_date_epoch"), bool)
            or not 0 <= manifest["source_date_epoch"] <= 4_294_967_295
        ):
            raise ReleaseError("assembled build manifest is noncanonical or malformed")
        state = repository_state or _repository_state(configuration.root)
        source = manifest.get("source")
        if (
            not isinstance(source, dict)
            or set(source) != {"revision", "tree_sha256", "committed", "clean"}
            or source.get("revision") != state.revision
            or re.fullmatch(r"[0-9a-f]{64}", str(source.get("tree_sha256"))) is None
            or source.get("committed") is not True
            or source.get("clean") is not state.clean
        ):
            raise ReleaseError("assembled source binding is stale")
        records = manifest.get("artifacts")
        if not isinstance(records, list) or not all(
            isinstance(record, dict) for record in records
        ):
            raise ReleaseError("assembled artifact inventory is malformed")
        expected_ids = {spec.identifier for spec in configuration.specs}
        by_id: dict[str, dict[str, Any]] = {}
        for record in records:
            if set(record) != {"id", "path", "sha256", "bytes", "contract"}:
                raise ReleaseError("assembled artifact record has an unexpected shape")
            identifier = record.get("id")
            if not isinstance(identifier, str) or identifier in by_id:
                raise ReleaseError("assembled artifact IDs are invalid or duplicated")
            by_id[identifier] = record
        if set(by_id) != expected_ids or [record["id"] for record in records] != sorted(
            expected_ids
        ):
            raise ReleaseError("assembled artifact IDs are missing, extra, or unsorted")
        artifact_payloads: dict[str, bytes] = {}
        reconstructed_records: list[dict[str, Any]] = []
        for spec in sorted(configuration.specs, key=lambda item: item.identifier):
            filename = _filename(spec, configuration.version)
            payload = snapshot[filename]
            artifact_payloads[spec.identifier] = payload
            expected_record = {
                "id": spec.identifier,
                "path": filename,
                "sha256": sha256_bytes(payload),
                "bytes": len(payload),
                "contract": f"packaging/{spec.contract}",
            }
            if by_id[spec.identifier] != expected_record:
                raise ReleaseError(
                    f"assembled artifact digest/path/contract changed: {spec.identifier}"
                )
            reconstructed_records.append(expected_record)
            package_verifier(
                payload,
                spec,
                configuration.version,
                configuration.context_abi,
                manifest["source_date_epoch"],
                source,
                configuration.root,
            )
        reconstructed = {
            "schema_version": BUILD_SCHEMA,
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": manifest["source_date_epoch"],
            "source": source,
            "artifacts": reconstructed_records,
        }
        if canonical_json_bytes(reconstructed) != manifest_payload:
            raise ReleaseError(
                "release-build.json is not the exact reconstructed manifest"
            )
        expected_checksums = _checksum_bytes(
            configuration.specs, artifact_payloads, configuration.version
        )
        if snapshot[CHECKSUM_MANIFEST] != expected_checksums:
            raise ReleaseError(
                "SHA256SUMS is stale, ambiguous, or references extra files"
            )
        repeated = workspace.read_files(names, strict_read_only=True)
        if repeated != snapshot:
            raise ReleaseError("assembled artifact bytes changed during verification")
    finally:
        workspace.close()
    current = repository_state or _repository_state(configuration.root)
    if current != state:
        raise ReleaseError("repository state changed during independent verification")
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "status": "verified-development-only",
        "profile_id": "cigar.development.local.macos-aarch64.v1",
        "product_version": configuration.version,
        "context_abi": configuration.context_abi,
        "source_date_epoch": manifest["source_date_epoch"],
        "source": source,
        "artifact_count": len(configuration.specs),
        "artifact_ids": sorted(expected_ids),
        "build_manifest_sha256": sha256_bytes(manifest_payload),
        "checksums_sha256": sha256_bytes(expected_checksums),
        "release_eligible": False,
        "external_requirements": {
            "clean_candidate_build": "not-evidenced",
            "artifact_signatures": "not-evidenced",
            "native_code_signing": "not-evidenced",
            "notarization": "not-evidenced",
            "installed_byte_qualification": "not-evidenced",
            "publication": "not-performed",
        },
    }


def main() -> int:
    arguments = parse_arguments()
    result = verify(arguments.root, arguments.dist)
    _publish_report(arguments, result)
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        OSError,
        ReleaseError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(
            f"macOS development assembly verification failed: {error}"
        ) from error
