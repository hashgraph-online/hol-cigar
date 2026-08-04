#!/usr/bin/env python3
"""Generate and validate the bounded local macOS aarch64 development projection."""

from __future__ import annotations

import argparse
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    reject_evidence_directory,
    repo_root,
    sha256_bytes,
    sha256_file,
    write_json,
)


PROFILE_ID = "cigar.development.local.macos-aarch64.v1"
PROFILE_PATH = "packaging/development/local-macos-aarch64.v1.json"
SCHEMA_PATH = "packaging/development/schemas/local-macos-aarch64.v1.schema.json"
SCHEMA_SHA256 = "846ba53f97fc703e23583e34cfb12ae8a333805be78e98ace13c383cfcb84ff7"
PROFILE_SHA256 = "d5353cc006548ebe90da600fb468be03d8028e108867f5fc11c262af5766ba20"
PRODUCT_VERSION_PATH = "packaging/product-version.v1.json"
PRODUCT_VERSION_SHA256 = (
    "5769db6058cc7198d8d840003244893e495446ba58218c3cb3602a382af24839"
)
ARTIFACT_MATRIX_PATH = "packaging/artifact-matrix.v1.json"
ARTIFACT_ID_INVENTORY_SHA256 = (
    "b5f25d88f278943ff7f3fe9cea42d335df272913afa4538d1acb30071ecec1c7"
)

SELECTED = (
    ("source", "portable"),
    ("docs", "portable"),
    ("schemas", "portable"),
    ("conformance", "portable"),
    ("benchmarks", "portable"),
    ("licenses", "portable"),
    ("cli-daemon-macos-aarch64", "native-runtime"),
    ("cigar-conformance-macos-aarch64", "qualification-conformance"),
    ("cigarbench-macos-aarch64", "qualification-benchmark"),
    ("macos-homebrew-formula-arm64", "installer-metadata"),
    ("macos-installer-arm64", "installer-native"),
    ("typescript-sdk", "sdk-typescript"),
    ("rust-sdk-crate", "sdk-rust"),
    ("python-sdk-sdist", "sdk-python"),
    ("python-sdk-wheel", "sdk-python"),
    ("go-sdk", "sdk-go"),
    ("claude-code-plugin", "adapter"),
)
DEFERRED = (
    (
        "cli-daemon-linux-x86_64-gnu",
        "Linux x86_64 requires a separate native qualification profile.",
    ),
    (
        "cli-daemon-linux-aarch64-gnu",
        "Linux aarch64 requires a separate native qualification profile.",
    ),
    (
        "cli-daemon-macos-x86_64",
        "Intel macOS requires a separate native qualification profile.",
    ),
    (
        "cli-daemon-windows-x86_64",
        "Windows requires native ACL, signing, and installed qualification in a separate profile.",
    ),
    (
        "shared-oci",
        "The Linux multiarchitecture OCI index requires a separate container profile.",
    ),
)
MISSING: tuple[tuple[str, str], ...] = ()


def expected_profile() -> dict[str, Any]:
    return {
        "schema_version": "cigar.development-artifact-profile.v1",
        "profile_id": PROFILE_ID,
        "product": "cigar",
        "version_binding": {
            "path": PRODUCT_VERSION_PATH,
            "sha256": PRODUCT_VERSION_SHA256,
            "version": "0.9.2",
            "target_release_version": "0.9.2",
        },
        "artifact_matrix": {
            "path": ARTIFACT_MATRIX_PATH,
            "schema_version": "cigar.artifact-matrix.v1",
            "artifact_id_inventory_sha256": ARTIFACT_ID_INVENTORY_SHA256,
        },
        "target": {
            "host_os": "macos",
            "host_arch": "arm64",
            "target_triple": "aarch64-apple-darwin",
        },
        "deployment_modes": ["embedded", "local-sidecar"],
        "release_state": "development",
        "published": False,
        "supported": False,
        "observed_host": {
            "status": "observation-only",
            "os": "macos",
            "version": "15.6",
            "build": "24G84",
            "architecture": "arm64",
            "minimum_support_claim": False,
        },
        "selected_artifacts": [
            {
                "id": identifier,
                "selection_group": group,
                "status": "planned",
                "built": False,
                "qualified": False,
            }
            for identifier, group in SELECTED
        ],
        "deferred_artifacts": [
            {
                "id": identifier,
                "status": "deferred-separate-profile",
                "reason": reason,
            }
            for identifier, reason in DEFERRED
        ],
        "missing_artifacts": [
            {"id": identifier, "status": "missing", "reason": reason}
            for identifier, reason in MISSING
        ],
        "qualification_obligations": {
            "fuzz_accumulation": {
                "requirement": "mandatory",
                "current_run": "deferred",
                "qualifying_evidence": False,
            },
            "soak": {
                "requirement": "mandatory",
                "current_run": "deferred",
                "qualifying_evidence": False,
            },
            "signing": {
                "requirement": "mandatory",
                "execution_boundary": "external",
                "evidence_status": "not-evidenced",
            },
            "notarization": {
                "requirement": "mandatory",
                "execution_boundary": "external",
                "evidence_status": "not-evidenced",
            },
        },
        "fail_closed": True,
    }


def _repository_path(root: Path, relative: str) -> Path:
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise ReleaseError(f"unsafe development-profile path: {relative!r}")
    current = root
    for part in parsed.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ReleaseError(
                f"cannot inspect development-profile path: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseError("development-profile parent must be a real directory")
    return root.joinpath(*parsed.parts)


def _regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{label} must be a regular file")
    if metadata.st_nlink != 1:
        raise ReleaseError(f"{label} must not be hard-linked")


def _load_canonical(path: Path, label: str) -> Any:
    _regular_file(path, label)
    document = load_json(path)
    if path.read_bytes() != canonical_json_bytes(document):
        raise ReleaseError(f"{label} is not canonical JSON")
    return document


def _validate_sources(root: Path) -> tuple[str, ...]:
    version_path = _repository_path(root, PRODUCT_VERSION_PATH)
    _regular_file(version_path, PRODUCT_VERSION_PATH)
    if sha256_file(version_path) != PRODUCT_VERSION_SHA256:
        raise ReleaseError("development product-version digest drifted")
    version = load_json(version_path)
    if not isinstance(version, dict) or any(
        version.get(key) != value
        for key, value in {
            "schema_version": "cigar.product-version.v1",
            "product": "cigar",
            "version": "0.9.2",
            "target_release_version": "0.9.2",
            "release_state": "developer-preview",
            "published": False,
            "supported": False,
        }.items()
    ):
        raise ReleaseError("development product-version binding is invalid")

    matrix_path = _repository_path(root, ARTIFACT_MATRIX_PATH)
    _regular_file(matrix_path, ARTIFACT_MATRIX_PATH)
    matrix = load_json(matrix_path)
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("product_version") != "0.9.2"
        or matrix.get("release_state") != "development"
        or not isinstance(matrix.get("artifacts"), list)
    ):
        raise ReleaseError("development artifact matrix binding is invalid")
    identifiers = tuple(
        entry.get("id") for entry in matrix["artifacts"] if isinstance(entry, dict)
    )
    if (
        len(identifiers) != 22
        or len(identifiers) != len(matrix["artifacts"])
        or not all(
            isinstance(identifier, str) and identifier for identifier in identifiers
        )
        or len(set(identifiers)) != len(identifiers)
        or sha256_bytes(canonical_json_bytes(list(identifiers)))
        != ARTIFACT_ID_INVENTORY_SHA256
    ):
        raise ReleaseError("development artifact ID inventory drifted")
    return identifiers


def _validate_document(document: Any, matrix_ids: tuple[str, ...]) -> None:
    expected = expected_profile()
    if not isinstance(document, dict) or set(document) != set(expected):
        raise ReleaseError("development profile has missing or unexpected fields")
    if document != expected:
        raise ReleaseError(
            "development profile differs from its fail-closed projection"
        )
    selected = tuple(entry["id"] for entry in document["selected_artifacts"])
    deferred = tuple(entry["id"] for entry in document["deferred_artifacts"])
    if (
        selected != tuple(identifier for identifier, _ in SELECTED)
        or deferred != tuple(identifier for identifier, _ in DEFERRED)
        or set(selected).intersection(deferred)
        or set(selected).union(deferred) != set(matrix_ids)
    ):
        raise ReleaseError("development artifact partition is not exact")
    missing = tuple(entry["id"] for entry in document["missing_artifacts"])
    if missing != tuple(identifier for identifier, _ in MISSING) or set(missing) & set(
        matrix_ids
    ):
        raise ReleaseError("development missing-artifact inventory is invalid")


def _validate_schema(root: Path) -> None:
    path = _repository_path(root, SCHEMA_PATH)
    _regular_file(path, SCHEMA_PATH)
    schema = load_json(path)
    if (
        not isinstance(schema, dict)
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != "https://cigar.invalid/schemas/development-local-macos-aarch64.v1.schema.json"
    ):
        raise ReleaseError("development profile schema identity is invalid")
    if sha256_file(path) != SCHEMA_SHA256:
        raise ReleaseError("development profile schema digest drifted")


def generate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError("repository root is not a directory")
    _validate_schema(resolved)
    _validate_sources(resolved)
    destination = _repository_path(resolved, PROFILE_PATH)
    if destination.exists():
        _regular_file(destination, PROFILE_PATH)
    write_json(destination, expected_profile())


def validate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError("repository root is not a directory")
    _validate_schema(resolved)
    matrix_ids = _validate_sources(resolved)
    profile = _load_canonical(_repository_path(resolved, PROFILE_PATH), PROFILE_PATH)
    _validate_document(profile, matrix_ids)
    if sha256_file(_repository_path(resolved, PROFILE_PATH)) != PROFILE_SHA256:
        raise ReleaseError("development profile manifest digest drifted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
            "development profile source generation/checking does not emit release evidence"
        ),
    )
    arguments = parser.parse_args()
    reject_evidence_directory(arguments.evidence_dir, "development profile operation")
    if arguments.command == "generate":
        generate(arguments.root)
        print(f"generated development profile {PROFILE_ID}")
    else:
        validate(arguments.root)
        print(f"validated development profile {PROFILE_ID}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"development profile operation failed: {error}") from error
