#!/usr/bin/env python3
"""Offline verification for an assembled CIGAR Honey developer preview."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Mapping

from assemble_honey_release import (
    CHECKSUM_NAME,
    EXPECTED_ABI,
    EXPECTED_ARTIFACT_COUNT,
    EXPECTED_STATE,
    EXPECTED_TARGET,
    EXPECTED_VERSION,
    MANIFEST_NAME,
    MANIFEST_SCHEMA,
    MATRIX_PATH,
    PROFILE_PATH,
    REQUIREMENTS_PATH,
    REPOSITORY_ROOT,
    HoneyAssemblyError,
    _checksum_payload,
    _load_configuration,
)
from evidence_workspace import EvidenceLimits, EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    reject_evidence_directory,
    sha256_bytes,
)
from verify_package import verify as verify_package


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024


class HoneyVerificationError(ReleaseError):
    """The downloaded Honey candidate is incomplete or untrustworthy."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
            "public candidate verification emits only a stdout result"
        ),
    )
    return parser.parse_args()


def _canonical_document(payload: bytes, label: str) -> dict[str, Any]:
    document = load_json_bytes(payload, label)
    if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
        raise HoneyVerificationError(f"{label} is not canonical JSON")
    return document


def _validate_source(source: object) -> Mapping[str, Any]:
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or _REVISION.fullmatch(str(source.get("revision"))) is None
        or _SHA256.fullmatch(str(source.get("tree_sha256"))) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        raise HoneyVerificationError("Honey manifest source is invalid or unclean")
    return source


def _validate_receipt_reference(reference: object, *, required: bool) -> None:
    if not required:
        if reference is not None:
            raise HoneyVerificationError(
                "receipt-free artifact has a receipt reference"
            )
        return
    if (
        not isinstance(reference, dict)
        or set(reference) != {"path", "schema_version", "sha256", "bytes"}
        or not isinstance(reference.get("path"), str)
        or not isinstance(reference.get("schema_version"), str)
        or _SHA256.fullmatch(str(reference.get("sha256"))) is None
        or isinstance(reference.get("bytes"), bool)
        or not isinstance(reference.get("bytes"), int)
        or reference["bytes"] <= 0
    ):
        raise HoneyVerificationError("artifact producer receipt reference is invalid")


def _validate_release_notes(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise HoneyVerificationError("Honey release notes are not UTF-8") from error
    if (
        not text.endswith("\n")
        or "\r" in text
        or EXPECTED_VERSION not in text
        or "developer preview" not in text.casefold()
    ):
        raise HoneyVerificationError("Honey release notes omit identity or limitations")


def verify(candidate: Path, root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    configuration = _load_configuration(root)
    if not candidate.is_absolute() or Path(os.path.normpath(candidate)) != candidate:
        raise HoneyVerificationError("candidate path must be absolute and canonical")
    if candidate.is_symlink() or not candidate.is_dir():
        raise HoneyVerificationError(
            "candidate must be an existing non-symlink directory"
        )
    expected_inventory = {spec.filename for spec in configuration.artifacts}
    workspace = EvidenceWorkspace.create(
        candidate,
        repository_root=configuration.root,
        limits=EvidenceLimits(
            max_files=EXPECTED_ARTIFACT_COUNT + 4,
            max_directories=2,
            max_file_bytes=MAX_FILE_BYTES,
            max_total_bytes=MAX_TOTAL_BYTES,
            max_json_bytes=MAX_JSON_BYTES,
            max_path_depth=2,
        ),
    )
    try:
        snapshot = workspace.read_files(expected_inventory, strict_read_only=True)
    finally:
        workspace.close()

    manifest_payload = snapshot[MANIFEST_NAME]
    manifest = _canonical_document(manifest_payload, MANIFEST_NAME)
    if set(manifest) != {
        "schema_version",
        "product_version",
        "context_abi",
        "profile_id",
        "channel",
        "release_state",
        "target",
        "source_date_epoch",
        "source",
        "authority",
        "artifacts",
        "evidence",
        "claims",
    }:
        raise HoneyVerificationError("Honey manifest has an unexpected key inventory")
    epoch = manifest.get("source_date_epoch")
    if (
        manifest.get("schema_version") != MANIFEST_SCHEMA
        or manifest.get("product_version") != EXPECTED_VERSION
        or manifest.get("context_abi") != EXPECTED_ABI
        or manifest.get("profile_id") != configuration.profile_id
        or manifest.get("channel") != "honey"
        or manifest.get("release_state") != EXPECTED_STATE
        or manifest.get("target") != EXPECTED_TARGET
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 0
        or epoch > 4_294_967_295
    ):
        raise HoneyVerificationError("Honey manifest identity is stale")
    source = _validate_source(manifest.get("source"))
    if manifest.get("authority") != {
        PROFILE_PATH: configuration.profile_digest,
        MATRIX_PATH: configuration.matrix_digest,
        REQUIREMENTS_PATH: configuration.requirements_digest,
    }:
        raise HoneyVerificationError("Honey manifest authority digest changed")
    if manifest.get("claims") != {
        "developer_preview": True,
        "prerelease": True,
        "published": False,
        "supported": False,
        "production_qualified": False,
        "signed": False,
        "notarized": False,
    }:
        raise HoneyVerificationError(
            "Honey manifest contains a forbidden release claim"
        )
    if manifest.get("evidence") != {
        "status": "not-evaluated",
        "public_attachment": False,
        "required_internal_inputs": [
            {"id": identifier, "status": "not-evaluated"}
            for identifier in configuration.internal_input_ids
        ],
    }:
        raise HoneyVerificationError(
            "Honey public manifest overclaims or changes private evidence requirements"
        )

    payload_specs = tuple(
        spec for spec in configuration.artifacts if not spec.generated
    )
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or len(rows) != len(payload_specs):
        raise HoneyVerificationError("Honey manifest artifact count is incomplete")
    observed_ids: set[str] = set()
    observed_paths: set[str] = set()
    for spec, row in zip(payload_specs, rows, strict=True):
        if not isinstance(row, dict) or set(row) != {
            "id",
            "kind",
            "path",
            "sha256",
            "bytes",
            "contract",
            "producer_receipt",
            "status",
        }:
            raise HoneyVerificationError("Honey artifact manifest row is malformed")
        payload = snapshot[spec.filename]
        if (
            row.get("id") != spec.identifier
            or row.get("kind") != spec.kind
            or row.get("path") != spec.filename
            or row.get("sha256") != sha256_bytes(payload)
            or row.get("bytes") != len(payload)
            or row.get("contract") != spec.contract
            or row.get("status") != "honey-built-unqualified"
            or spec.identifier in observed_ids
            or spec.filename in observed_paths
        ):
            raise HoneyVerificationError(
                f"Honey artifact binding changed: {spec.identifier}"
            )
        _validate_receipt_reference(
            row.get("producer_receipt"), required=spec.receipt_required
        )
        if spec.contract is not None:
            with tempfile.TemporaryDirectory(
                prefix="cigar-honey-offline-verify-"
            ) as raw:
                archive = Path(raw) / spec.filename
                archive.write_bytes(payload)
                result = verify_package(
                    archive,
                    configuration.root / spec.contract,
                    configuration.version,
                    configuration.context_abi,
                    epoch,
                )
            if result.get("status") != "passed":
                raise HoneyVerificationError(
                    f"Honey package verification failed: {spec.identifier}"
                )
        if spec.workspace == "source-metadata" and spec.kind == "release-notes":
            _validate_release_notes(payload)
        observed_ids.add(spec.identifier)
        observed_paths.add(spec.filename)

    payloads = {spec.filename: snapshot[spec.filename] for spec in payload_specs}
    expected_checksums = _checksum_payload(payloads, manifest_payload)
    if snapshot[CHECKSUM_NAME] != expected_checksums:
        raise HoneyVerificationError(
            "Honey SHA256SUMS is stale, incomplete, duplicated, or unsorted"
        )
    # This verifier intentionally proves only the public attachment inventory,
    # hashes, package contracts, and bounded developer-preview claims. Producer
    # receipts and installed-gate evidence are private release inputs, so a
    # candidate-only invocation must never promote these bytes to a qualified
    # developer preview by itself.
    result = {
        "schema_version": "cigar.honey.verification-result.v1",
        "status": "passed-artifact-integrity",
        "qualification_status": "not-evaluated",
        "product_version": configuration.version,
        "context_abi": configuration.context_abi,
        "profile_id": configuration.profile_id,
        "source": dict(source),
        "artifact_count": len(configuration.artifacts),
        "payload_artifact_count": len(payload_specs),
        "manifest_sha256": sha256_bytes(manifest_payload),
        "checksum_manifest_sha256": sha256_bytes(snapshot[CHECKSUM_NAME]),
        "claims": manifest["claims"],
    }
    return result


def main() -> int:
    arguments = parse_arguments()
    reject_evidence_directory(arguments.evidence_dir, "Honey public verification")
    result = verify(arguments.candidate, arguments.root)
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        HoneyAssemblyError,
        HoneyVerificationError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"Honey verification failed: {error}") from error
