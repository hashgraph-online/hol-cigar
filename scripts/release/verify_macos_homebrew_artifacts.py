#!/usr/bin/env python3
"""Reverify exact development-only Apple-silicon Homebrew artifact bytes."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile
from typing import Any

from build_macos_homebrew_artifacts import (
    BOTTLE_ARTIFACT_ID,
    BOTTLE_CELLAR,
    BOTTLE_REBUILD,
    BOTTLE_TAG,
    BUILD_RECEIPT,
    FORMULA_ARTIFACT_ID,
    HOMEBREW_RECEIPT_COMPATIBILITY_VERSION,
    MAX_ARCHIVE_BYTES,
    MAX_RECEIPT_BYTES,
    NATIVE_ARTIFACT_ID,
    REPOSITORY_ROOT,
    TARGET_TRIPLE,
    Configuration,
    _authority_digests,
    _bottle_entries,
    _formula,
    _load_configuration,
    _native_members,
    _read_stable_file,
    _runtime_payload,
    _tap_entries,
    _validate_bottle_host,
    _validate_native_receipt,
    _write_archive,
)
from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    require_source_date_epoch,
    selected_evidence_directory,
    sha256_bytes,
)
from verify_package import verify as verify_package


VERIFICATION_SCHEMA = "cigar.development-homebrew-verification.v1"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--native-archive", type=Path, required=True)
    parser.add_argument("--native-build-receipt", type=Path, required=True)
    parser.add_argument("--bottle", type=Path, required=True)
    parser.add_argument("--tap-archive", type=Path, required=True)
    parser.add_argument("--homebrew-build-receipt", type=Path, required=True)
    parser.add_argument("--source-date-epoch")
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
            f"cannot open Homebrew verification evidence: {error}"
        ) from error
    try:
        workspace.read_files(set())
        workspace.write_json(relative, result)
        workspace.read_files({relative})
    finally:
        workspace.close()


def _absolute_external(path: Path, label: str, root: Path) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise ReleaseError(f"{label} must be an absolute canonical path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(f"cannot resolve {label}: {error}") from error
    if resolved != path:
        raise ReleaseError(f"{label} must not traverse a symlink")
    try:
        inside_repository = os.path.commonpath(
            (os.fspath(resolved), os.fspath(root))
        ) == os.fspath(root)
    except ValueError:
        inside_repository = False
    if inside_repository:
        raise ReleaseError(f"{label} must be outside the repository")
    return resolved


def _stage(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite verifier staging path: {path}")
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verification_summary(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: document[key]
        for key in ("schema_version", "status", "file_count", "expanded_bytes")
    }


def _expected_build_receipt(
    configuration: Configuration,
    *,
    host: dict[str, str],
    epoch: int,
    source: dict[str, Any],
    native_payload: bytes,
    native_receipt_payload: bytes,
    runtime_payload: dict[str, dict[str, object]],
    native_verification: dict[str, Any],
    bottle_payload: bytes,
    bottle_verification: dict[str, Any],
    tap_payload: bytes,
    tap_verification: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "cigar.development-homebrew-build.v1",
        "status": "built-unqualified",
        "product_version": configuration.version,
        "context_abi": configuration.context_abi,
        "target": TARGET_TRIPLE,
        "source_date_epoch": epoch,
        "source": source,
        "host": host,
        "input_native_archive": {
            "artifact_id": NATIVE_ARTIFACT_ID,
            "path": configuration.native_filename,
            "sha256": sha256_bytes(native_payload),
            "bytes": len(native_payload),
            "build_receipt": {
                "filename": "macos-aarch64-development-build.json",
                "sha256": sha256_bytes(native_receipt_payload),
                "bytes": len(native_receipt_payload),
            },
            "runtime_payload": runtime_payload,
        },
        "artifacts": [
            {
                "artifact_id": FORMULA_ARTIFACT_ID,
                "kind": "homebrew-tap-archive",
                "path": configuration.tap_filename,
                "sha256": sha256_bytes(tap_payload),
                "bytes": len(tap_payload),
                "contract": {
                    "path": "packaging/contracts/homebrew-tap.v1.json",
                    "sha256": configuration.authority[
                        "packaging/contracts/homebrew-tap.v1.json"
                    ]["sha256"],
                },
                "package_verification": _verification_summary(tap_verification),
            },
            {
                "artifact_id": BOTTLE_ARTIFACT_ID,
                "kind": "homebrew-bottle",
                "path": configuration.bottle_filename,
                "sha256": sha256_bytes(bottle_payload),
                "bytes": len(bottle_payload),
                "contract": {
                    "path": "packaging/contracts/homebrew-bottle.v1.json",
                    "sha256": configuration.authority[
                        "packaging/contracts/homebrew-bottle.v1.json"
                    ]["sha256"],
                },
                "package_verification": _verification_summary(bottle_verification),
            },
        ],
        "native_package_verification": _verification_summary(native_verification),
        "bottle_binding": {
            "tag": BOTTLE_TAG,
            "rebuild": BOTTLE_REBUILD,
            "cellar": BOTTLE_CELLAR,
            "cellar_path": f"cigar/{configuration.version}",
            "formula_member": f"cigar/{configuration.version}/.brew/cigar.rb",
            "install_receipt_member": (
                f"cigar/{configuration.version}/INSTALL_RECEIPT.json"
            ),
            "receipt_format_compatibility": (
                f"homebrew-{HOMEBREW_RECEIPT_COMPATIBILITY_VERSION}"
            ),
            "sbom_member": f"cigar/{configuration.version}/sbom.spdx.json",
            "sbom_scope": "development-source-binding",
            "installed_runtime_members": [
                "bin/cigar",
                "bin/cigard",
                "bin/cigar-mcp",
                "bin/cigar-claude-hook",
            ],
        },
        "authority": configuration.authority,
        "external_requirements": {
            "native_code_signing": "not-evidenced",
            "notarization": "not-evidenced",
            "artifact_signatures": "not-evidenced",
            "installed_byte_qualification": "not-evidenced",
            "homebrew_publication": "not-performed",
        },
        "claims": {
            "development_build": True,
            "release_built": False,
            "distribution_signed": False,
            "notarized": False,
            "qualified": False,
            "published": False,
            "supported": False,
            "release": False,
        },
    }


def verify(
    root: Path,
    native_archive: Path,
    native_build_receipt: Path,
    bottle: Path,
    tap_archive: Path,
    homebrew_build_receipt: Path,
    epoch: int,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    configuration = _load_configuration(root)
    paths = {
        "native archive": _absolute_external(native_archive, "native archive", root),
        "native build receipt": _absolute_external(
            native_build_receipt, "native build receipt", root
        ),
        "Homebrew bottle": _absolute_external(bottle, "Homebrew bottle", root),
        "Homebrew tap archive": _absolute_external(
            tap_archive, "Homebrew tap archive", root
        ),
        "Homebrew build receipt": _absolute_external(
            homebrew_build_receipt, "Homebrew build receipt", root
        ),
    }
    expected_names = {
        "native archive": configuration.native_filename,
        "native build receipt": "macos-aarch64-development-build.json",
        "Homebrew bottle": configuration.bottle_filename,
        "Homebrew tap archive": configuration.tap_filename,
        "Homebrew build receipt": BUILD_RECEIPT,
    }
    if len(set(paths.values())) != len(paths):
        raise ReleaseError("Homebrew verification inputs must be distinct files")
    for label, path in paths.items():
        if path.name != expected_names[label]:
            raise ReleaseError(f"{label} filename does not match the artifact matrix")

    payloads = {
        "native archive": _read_stable_file(
            paths["native archive"], MAX_ARCHIVE_BYTES, "native archive"
        ),
        "native build receipt": _read_stable_file(
            paths["native build receipt"],
            MAX_RECEIPT_BYTES,
            "native build receipt",
        ),
        "Homebrew bottle": _read_stable_file(
            paths["Homebrew bottle"], MAX_ARCHIVE_BYTES, "Homebrew bottle"
        ),
        "Homebrew tap archive": _read_stable_file(
            paths["Homebrew tap archive"],
            MAX_ARCHIVE_BYTES,
            "Homebrew tap archive",
        ),
        "Homebrew build receipt": _read_stable_file(
            paths["Homebrew build receipt"],
            MAX_RECEIPT_BYTES,
            "Homebrew build receipt",
        ),
    }
    native_receipt = _validate_native_receipt(
        payloads["native build receipt"],
        configuration,
        sha256_bytes(payloads["native archive"]),
        len(payloads["native archive"]),
        epoch,
    )
    source = native_receipt["source"]
    native_members = _native_members(
        payloads["native archive"], configuration, epoch, source
    )
    runtime_payload = _runtime_payload(native_members)
    if native_receipt.get("runtime_payload") != runtime_payload:
        raise ReleaseError("native receipt does not bind every Homebrew runtime byte")

    receipt = load_json_bytes(
        payloads["Homebrew build receipt"], "Homebrew build receipt"
    )
    if not isinstance(receipt, dict) or payloads[
        "Homebrew build receipt"
    ] != canonical_json_bytes(receipt):
        raise ReleaseError("Homebrew build receipt is not canonical JSON")
    host = receipt.get("host")
    if not isinstance(host, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in host.items()
    ):
        raise ReleaseError("Homebrew build receipt host identity is malformed")
    validated_host = _validate_bottle_host(host)

    with tempfile.TemporaryDirectory(prefix="cigar-homebrew-verify-") as raw:
        scratch = Path(raw).resolve(strict=True)
        # Exact-byte reconstruction remains private until every binding is checked.
        os.chmod(scratch, 0o700)  # fmt: skip  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        staged_native = scratch / configuration.native_filename
        staged_bottle = scratch / configuration.bottle_filename
        staged_tap = scratch / configuration.tap_filename
        for staged, key in (
            (staged_native, "native archive"),
            (staged_bottle, "Homebrew bottle"),
            (staged_tap, "Homebrew tap archive"),
        ):
            _stage(staged, payloads[key])

        native_verification = verify_package(
            staged_native,
            root / "packaging/contracts/macos-runtime-archive.v1.json",
            configuration.version,
            configuration.context_abi,
            epoch,
        )
        bottle_verification = verify_package(
            staged_bottle,
            configuration.bottle_contract,
            None,
            None,
            epoch,
        )
        tap_verification = verify_package(
            staged_tap,
            configuration.tap_contract,
            configuration.version,
            configuration.context_abi,
            epoch,
        )

        expected_bottle = scratch / f"expected-{configuration.bottle_filename}"
        _write_archive(
            expected_bottle,
            _bottle_entries(
                configuration,
                native_members,
                _formula(
                    configuration,
                    sha256_bytes(payloads["native archive"]),
                    None,
                ),
                sha256_bytes(payloads["native archive"]),
                epoch,
            ),
            epoch,
        )
        expected_bottle_payload = _read_stable_file(
            expected_bottle, MAX_ARCHIVE_BYTES, "reconstructed Homebrew bottle"
        )
        if expected_bottle_payload != payloads["Homebrew bottle"]:
            raise ReleaseError(
                "Homebrew bottle differs from the exact native-bound reconstruction"
            )

        bottle_sha256 = sha256_bytes(payloads["Homebrew bottle"])
        expected_tap = scratch / f"expected-{configuration.tap_filename}"
        _write_archive(
            expected_tap,
            _tap_entries(
                configuration,
                _formula(
                    configuration,
                    sha256_bytes(payloads["native archive"]),
                    bottle_sha256,
                ),
                bottle_sha256,
                len(payloads["Homebrew bottle"]),
                sha256_bytes(payloads["native archive"]),
                len(payloads["native archive"]),
                source,
                epoch,
            ),
            epoch,
        )
        expected_tap_payload = _read_stable_file(
            expected_tap, MAX_ARCHIVE_BYTES, "reconstructed Homebrew tap archive"
        )
        if expected_tap_payload != payloads["Homebrew tap archive"]:
            raise ReleaseError(
                "Homebrew tap differs from the exact bottle-bound reconstruction"
            )

    expected_receipt = _expected_build_receipt(
        configuration,
        host=validated_host,
        epoch=epoch,
        source=source,
        native_payload=payloads["native archive"],
        native_receipt_payload=payloads["native build receipt"],
        runtime_payload=runtime_payload,
        native_verification=native_verification,
        bottle_payload=payloads["Homebrew bottle"],
        bottle_verification=bottle_verification,
        tap_payload=payloads["Homebrew tap archive"],
        tap_verification=tap_verification,
    )
    if receipt != expected_receipt:
        raise ReleaseError("Homebrew build receipt is stale, incomplete, or overclaims")
    if _authority_digests(root) != configuration.authority:
        raise ReleaseError(
            "Homebrew verification authority changed during verification"
        )
    for label, path in paths.items():
        maximum = MAX_RECEIPT_BYTES if "receipt" in label else MAX_ARCHIVE_BYTES
        if _read_stable_file(path, maximum, label) != payloads[label]:
            raise ReleaseError(f"{label} changed during verification")

    return {
        "schema_version": VERIFICATION_SCHEMA,
        "status": "verified-built-unqualified",
        "product_version": configuration.version,
        "context_abi": configuration.context_abi,
        "target": TARGET_TRIPLE,
        "source_date_epoch": epoch,
        "source": source,
        "artifacts": expected_receipt["artifacts"],
        "build_receipt": {
            "path": BUILD_RECEIPT,
            "sha256": sha256_bytes(payloads["Homebrew build receipt"]),
            "bytes": len(payloads["Homebrew build receipt"]),
        },
        "claims": expected_receipt["claims"],
        "external_requirements": expected_receipt["external_requirements"],
    }


def main() -> int:
    arguments = parse_arguments()
    report = verify(
        arguments.root,
        arguments.native_archive,
        arguments.native_build_receipt,
        arguments.bottle,
        arguments.tap_archive,
        arguments.homebrew_build_receipt,
        require_source_date_epoch(arguments.source_date_epoch),
    )
    _publish_report(arguments, report)
    print(canonical_json_bytes(report).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, OSError, ReleaseError) as error:
        raise SystemExit(f"macOS Homebrew verification failed: {error}") from error
