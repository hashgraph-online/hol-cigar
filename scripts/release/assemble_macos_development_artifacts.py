#!/usr/bin/env python3
"""Assemble the complete, unqualified Apple-silicon development artifact set.

This command is deliberately not a release builder.  It accepts only the exact
owner-private workspaces emitted by the selected development producers, validates
their receipts and package contracts, and copies the already-built bytes without
rebuilding them.  The resulting ``release-build.json`` uses the existing
``cigar.local-archive-build.v1`` identity so production evidence and live runbook
gates continue to reject it.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unicodedata
from typing import Any

from development_macos_profile import SELECTED, validate as validate_profile
from evidence_workspace import (
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    digest_secure_file,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    require_source_date_epoch,
    resolve_beneath,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
)
from verify_macos_homebrew_artifacts import verify as verify_homebrew
from verify_package import verify as verify_package


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROFILE_ID = "cigar.development.local.macos-aarch64.v1"
TARGET_TRIPLE = "aarch64-apple-darwin"
BUILD_MANIFEST = "release-build.json"
CHECKSUM_MANIFEST = "SHA256SUMS"
BUILD_SCHEMA = "cigar.local-archive-build.v1"
MAX_INPUT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_OUTPUT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ASSEMBLY_PAYLOAD_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class ArtifactSpec:
    identifier: str
    kind: str
    filename_template: str
    contract: str
    producer: str
    workspace: str
    receipt: str
    receipt_schema: str
    target: str | None


@dataclass(frozen=True)
class Artifact:
    spec: ArtifactSpec
    payload: bytes
    source: dict[str, Any]

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.payload)

    @property
    def bytes(self) -> int:
        return len(self.payload)


@dataclass(frozen=True)
class Configuration:
    root: Path
    version: str
    context_abi: str
    host: dict[str, str]
    specs: tuple[ArtifactSpec, ...]
    rows: Mapping[str, dict[str, Any]]


@dataclass(frozen=True)
class RepositoryState:
    revision: str
    status_sha256: str
    clean: bool


ARTIFACT_SPECS = (
    ArtifactSpec(
        "source",
        "source-archive",
        "cigar-{version}-source.tar.gz",
        "contracts/source-archive.v1.json",
        "python3 scripts/release/build_archives.py",
        "portable",
        "build-manifest.json",
        "cigar.local-archive-build.v1",
        None,
    ),
    ArtifactSpec(
        "docs",
        "documentation-archive",
        "cigar-{version}-docs.tar.gz",
        "contracts/docs-archive.v1.json",
        "python3 scripts/release/build_archives.py",
        "portable",
        "build-manifest.json",
        "cigar.local-archive-build.v1",
        None,
    ),
    ArtifactSpec(
        "schemas",
        "schema-archive",
        "cigar-{version}-schemas.tar.gz",
        "contracts/schemas-archive.v1.json",
        "python3 scripts/release/build_archives.py",
        "portable",
        "build-manifest.json",
        "cigar.local-archive-build.v1",
        None,
    ),
    ArtifactSpec(
        "conformance",
        "conformance-archive",
        "cigar-{version}-conformance.tar.gz",
        "contracts/conformance-archive.v1.json",
        "python3 scripts/release/build_archives.py",
        "portable",
        "build-manifest.json",
        "cigar.local-archive-build.v1",
        None,
    ),
    ArtifactSpec(
        "benchmarks",
        "benchmark-fixture-archive",
        "cigar-{version}-benchmarks.tar.gz",
        "contracts/benchmark-archive.v1.json",
        "python3 scripts/release/build_archives.py",
        "portable",
        "build-manifest.json",
        "cigar.local-archive-build.v1",
        None,
    ),
    ArtifactSpec(
        "licenses",
        "license-archive",
        "cigar-{version}-licenses.tar.gz",
        "contracts/license-archive.v1.json",
        "python3 scripts/release/build_archives.py",
        "portable",
        "build-manifest.json",
        "cigar.local-archive-build.v1",
        None,
    ),
    ArtifactSpec(
        "cli-daemon-macos-aarch64",
        "binary-archive",
        "cigar-{version}-aarch64-apple-darwin.tar.gz",
        "contracts/macos-runtime-archive.v1.json",
        "python3 scripts/release/build_macos_aarch64_archive.py",
        "native",
        "macos-aarch64-development-build.json",
        "cigar.development-native-archive-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "cigar-conformance-macos-aarch64",
        "conformance-runner-archive",
        "cigar-conformance-{version}-aarch64-apple-darwin.tar.gz",
        "contracts/macos-conformance-runner.v1.json",
        "python3 scripts/release/build_macos_qualification_tools.py conformance",
        "conformance_tool",
        "macos-conformance-development-build.json",
        "cigar.development-qualification-tool-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "cigarbench-macos-aarch64",
        "benchmark-tool-archive",
        "cigarbench-{version}-aarch64-apple-darwin.tar.gz",
        "contracts/macos-cigarbench-tool.v1.json",
        "python3 scripts/release/build_macos_qualification_tools.py cigarbench",
        "cigarbench_tool",
        "macos-cigarbench-development-build.json",
        "cigar.development-qualification-tool-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "macos-homebrew-formula-arm64",
        "homebrew-tap-archive",
        "cigar-{version}-homebrew-tap.tar.gz",
        "contracts/homebrew-tap.v1.json",
        "python3 scripts/release/build_macos_homebrew_artifacts.py",
        "homebrew",
        "macos-homebrew-development-build.json",
        "cigar.development-homebrew-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "macos-installer-arm64",
        "homebrew-bottle",
        "cigar--{version}.arm64_sequoia.bottle.tar.gz",
        "contracts/homebrew-bottle.v1.json",
        "python3 scripts/release/build_macos_homebrew_artifacts.py",
        "homebrew",
        "macos-homebrew-development-build.json",
        "cigar.development-homebrew-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "typescript-sdk",
        "npm-package",
        "cigar-sdk-{version}.tgz",
        "contracts/npm-package.v1.json",
        "python3 scripts/release/build_typescript_sdk.py",
        "typescript",
        "typescript-sdk-development-build.json",
        "cigar.development-typescript-sdk-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "rust-sdk-crate",
        "cargo-crate",
        "cigar-sdk-{version}.crate",
        "contracts/cargo-crate.v1.json",
        "python3 scripts/release/build_rust_sdk_crate.py",
        "rust",
        "rust-sdk-crate-development-build.json",
        "cigar.development-rust-sdk-crate-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "python-sdk-sdist",
        "python-sdist",
        "cigar_sdk-{python_version}.tar.gz",
        "contracts/python-sdist.v1.json",
        "python3 scripts/release/build_python_sdk_artifacts.py",
        "python",
        "python-sdk-development-build.json",
        "cigar.development-python-sdk-build.v1",
        "python3-none-any-on-macos-arm64",
    ),
    ArtifactSpec(
        "python-sdk-wheel",
        "python-wheel",
        "cigar_sdk-{python_version}-py3-none-any.whl",
        "contracts/python-wheel.v1.json",
        "python3 scripts/release/build_python_sdk_artifacts.py",
        "python",
        "python-sdk-development-build.json",
        "cigar.development-python-sdk-build.v1",
        "python3-none-any-on-macos-arm64",
    ),
    ArtifactSpec(
        "go-sdk",
        "go-module",
        "cigar-go-sdk-{version}.zip",
        "contracts/go-module.v1.json",
        "python3 scripts/release/build_go_sdk.py",
        "go",
        "go-sdk-development-build.json",
        "cigar.development-go-sdk-build.v1",
        TARGET_TRIPLE,
    ),
    ArtifactSpec(
        "claude-code-plugin",
        "plugin-archive",
        "cigar-claude-code-{version}.tar.gz",
        "contracts/plugin-archive.v1.json",
        "python3 scripts/release/build_claude_code_plugin.py",
        "claude",
        "claude-code-plugin-development-build.json",
        "cigar.development-claude-code-plugin-build.v1",
        TARGET_TRIPLE,
    ),
)

WORKSPACE_ARGUMENTS = {
    "portable": "portable_workspace",
    "native": "native_workspace",
    "conformance_tool": "conformance_workspace",
    "cigarbench_tool": "cigarbench_workspace",
    "homebrew": "homebrew_workspace",
    "typescript": "typescript_workspace",
    "rust": "rust_workspace",
    "python": "python_workspace",
    "go": "go_workspace",
    "claude": "claude_workspace",
}


PackageVerifier = Callable[
    [bytes, ArtifactSpec, Configuration, int, dict[str, Any]], dict[str, Any]
]
HomebrewVerifier = Callable[[Configuration, Mapping[str, Path], int], Any]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--portable-workspace", type=Path, required=True)
    parser.add_argument("--native-workspace", type=Path, required=True)
    parser.add_argument("--conformance-workspace", type=Path, required=True)
    parser.add_argument("--cigarbench-workspace", type=Path, required=True)
    parser.add_argument("--homebrew-workspace", type=Path, required=True)
    parser.add_argument("--typescript-workspace", type=Path, required=True)
    parser.add_argument("--rust-workspace", type=Path, required=True)
    parser.add_argument("--python-workspace", type=Path, required=True)
    parser.add_argument("--go-workspace", type=Path, required=True)
    parser.add_argument("--claude-workspace", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        required=True,
        help="absolute external empty owner-only assembly workspace",
    )
    parser.add_argument("--source-date-epoch")
    return parser.parse_args()


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _python_version(version: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)-dev\.(\d+)", version)
    if match is None:
        raise ReleaseError("development product version has no Python mapping")
    major, minor, patch, prerelease = match.groups()
    return f"{major}.{minor}.{patch}.dev{prerelease}"


def _filename(spec: ArtifactSpec, version: str) -> str:
    value = spec.filename_template.format(
        version=version, python_version=_python_version(version)
    )
    if safe_relative_path(value) != value or "/" in value:
        raise ReleaseError(f"artifact filename is not a portable basename: {value}")
    return value


def load_configuration(root: Path) -> Configuration:
    root = root.resolve(strict=True)
    validate_profile(root)
    product = load_json(root / "packaging/product-version.v1.json")
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    profile = load_json(root / "packaging/development/local-macos-aarch64.v1.json")
    if (
        not isinstance(product, dict)
        or product.get("schema_version") != "cigar.product-version.v1"
        or product.get("release_state") != "development"
        or product.get("channel") != "development"
        or product.get("prerelease") is not True
        or product.get("published") is not False
        or product.get("supported") is not False
        or product.get("tag") is not None
        or not isinstance(product.get("version"), str)
        or product.get("context_abi") != "cigar.context.v1"
    ):
        raise ReleaseError(
            "product authority is not an unpublished development identity"
        )
    version = product["version"]
    context_abi = product["context_abi"]
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("product_version") != version
        or matrix.get("context_abi") != context_abi
        or matrix.get("release_state") != "development"
        or not isinstance(matrix.get("artifacts"), list)
    ):
        raise ReleaseError("artifact matrix is stale relative to product authority")
    rows: dict[str, dict[str, Any]] = {}
    for row in matrix["artifacts"]:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ReleaseError("artifact matrix contains a malformed row")
        if row["id"] in rows:
            raise ReleaseError(f"duplicate artifact matrix id: {row['id']}")
        rows[row["id"]] = row
    selected = tuple(entry["id"] for entry in profile["selected_artifacts"])
    expected_selected = tuple(identifier for identifier, _group in SELECTED)
    specs_by_id = {spec.identifier: spec for spec in ARTIFACT_SPECS}
    if (
        profile.get("profile_id") != PROFILE_ID
        or profile.get("release_state") != "development"
        or profile.get("published") is not False
        or profile.get("supported") is not False
        or profile.get("fail_closed") is not True
        or selected != expected_selected
        or tuple(spec.identifier for spec in ARTIFACT_SPECS) != expected_selected
        or set(specs_by_id) != set(selected)
    ):
        raise ReleaseError(
            "development profile selection is not the exact reviewed set"
        )
    aliases: set[str] = set()
    for identifier in selected:
        spec = specs_by_id[identifier]
        row = rows.get(identifier)
        filename = _filename(spec, version)
        alias = _portable_key(filename)
        if alias in aliases:
            raise ReleaseError(f"selected artifact filename collision: {filename}")
        aliases.add(alias)
        if (
            not isinstance(row, dict)
            or row.get("kind") != spec.kind
            or row.get("filename") != filename
            or row.get("contract") != spec.contract
            or row.get("producer") != spec.producer
            or row.get("required_for_release") is not True
            or (
                spec.target == TARGET_TRIPLE
                and row.get("platform") not in {None, TARGET_TRIPLE}
            )
        ):
            raise ReleaseError(
                f"selected artifact row is incomplete or stale: {identifier}"
            )
        contract = resolve_beneath(root, f"packaging/{spec.contract}")
        metadata = contract.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ReleaseError(
                f"artifact contract is not a regular unlinked file: {identifier}"
            )
    observed = profile.get("observed_host")
    if not isinstance(observed, dict):
        raise ReleaseError("development profile host observation is missing")
    host = {
        "platform": observed.get("os"),
        "architecture": observed.get("architecture"),
        "target_triple": TARGET_TRIPLE,
        "macos_version": observed.get("version"),
    }
    if host != {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": "15.6",
    }:
        raise ReleaseError(
            "development profile host binding is not the reviewed macOS host"
        )
    return Configuration(
        root=root,
        version=version,
        context_abi=context_abi,
        host=host,
        specs=ARTIFACT_SPECS,
        rows=rows,
    )


def _repository_state(root: Path) -> RepositoryState:
    revision = run_bounded(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=root,
        timeout=60,
        max_stdout=1024,
        max_stderr=1024 * 1024,
    )
    if revision.returncode != 0:
        raise ReleaseError("development assembly requires an existing source commit")
    revision_text = revision.stdout.decode("ascii", errors="strict").strip()
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision_text) is None:
        raise ReleaseError("repository HEAD is not a canonical lowercase revision")
    status = run_bounded(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        timeout=60,
        max_stdout=32 * 1024 * 1024,
        max_stderr=1024 * 1024,
    )
    if status.returncode != 0:
        raise ReleaseError("cannot obtain repository status for source binding")
    return RepositoryState(
        revision=revision_text,
        status_sha256=sha256_bytes(status.stdout),
        clean=not bool(status.stdout.strip()),
    )


def _validate_source(
    source: Any, state: RepositoryState, *, label: str
) -> dict[str, Any]:
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or source.get("revision") != state.revision
        or re.fullmatch(r"[0-9a-f]{64}", str(source.get("tree_sha256"))) is None
        or source.get("committed") is not True
        or source.get("clean") is not state.clean
    ):
        raise ReleaseError(f"{label} is stale relative to the repository source state")
    return source


def _canonical_document(payload: bytes, label: str) -> dict[str, Any]:
    document = load_json_bytes(payload, label)
    if not isinstance(document, dict) or payload != canonical_json_bytes(document):
        raise ReleaseError(f"{label} is not a canonical JSON object")
    return document


def _validate_authority(
    receipt: Mapping[str, Any], configuration: Configuration, contract: str
) -> None:
    authority = receipt.get("authority")
    if not isinstance(authority, dict) or not authority:
        raise ReleaseError("producer receipt has no source authority inventory")
    required = {
        "packaging/product-version.v1.json",
        "packaging/artifact-matrix.v1.json",
        "packaging/development/local-macos-aarch64.v1.json",
        f"packaging/{contract}",
    }
    if not required.issubset(authority):
        raise ReleaseError("producer receipt omits required source authority")
    aliases: set[str] = set()
    for relative, reference in authority.items():
        if not isinstance(relative, str) or safe_relative_path(relative) != relative:
            raise ReleaseError("producer receipt contains an unsafe authority path")
        alias = _portable_key(relative)
        if alias in aliases:
            raise ReleaseError("producer receipt contains an authority path collision")
        aliases.add(alias)
        if (
            not isinstance(reference, dict)
            or set(reference) != {"sha256", "bytes"}
            or re.fullmatch(r"[0-9a-f]{64}", str(reference.get("sha256"))) is None
            or not isinstance(reference.get("bytes"), int)
            or isinstance(reference.get("bytes"), bool)
            or reference["bytes"] <= 0
        ):
            raise ReleaseError(f"invalid authority reference: {relative}")
        path = resolve_beneath(configuration.root, relative)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != reference["bytes"]
        ):
            raise ReleaseError(f"authority file type or size changed: {relative}")
        digest = digest_secure_file(path, max_bytes=64 * 1024 * 1024)
        if digest.bytes != reference["bytes"] or digest.sha256 != reference["sha256"]:
            raise ReleaseError(f"authority file digest changed: {relative}")


def _validate_claims(receipt: Mapping[str, Any]) -> None:
    claims = receipt.get("claims")
    if not isinstance(claims, dict) or claims.get("development_build") is not True:
        raise ReleaseError("producer receipt is not explicitly a development build")
    for key in (
        "distribution_signed",
        "qualified",
        "published",
        "supported",
        "release",
    ):
        if claims.get(key) is not False:
            raise ReleaseError(f"producer receipt must keep {key}=false")
    for key in (
        "candidate",
        "installed_qualified",
        "release_built",
        "signed",
        "installable",
        "registry_signature",
        "notarized",
    ):
        if key in claims and claims[key] is not False:
            raise ReleaseError(f"producer receipt overclaims {key}")


def _reference_matches(reference: Any, filename: str, payload: bytes) -> bool:
    return reference == {
        "path": filename,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _contract_reference(
    configuration: Configuration, spec: ArtifactSpec
) -> dict[str, object]:
    relative = f"packaging/{spec.contract}"
    digest = digest_secure_file(
        resolve_beneath(configuration.root, relative), max_bytes=64 * 1024 * 1024
    )
    return {"path": relative, "sha256": digest.sha256}


def _common_receipt(
    receipt: dict[str, Any],
    spec: ArtifactSpec,
    payload: bytes,
    configuration: Configuration,
    epoch: int,
    state: RepositoryState,
) -> dict[str, Any]:
    filename = _filename(spec, configuration.version)
    if (
        receipt.get("schema_version") != spec.receipt_schema
        or receipt.get("status") != "built-unqualified"
        or receipt.get("artifact_id") != spec.identifier
        or receipt.get("target") != spec.target
        or receipt.get("product_version") != configuration.version
        or receipt.get("context_abi") != configuration.context_abi
        or receipt.get("source_date_epoch") != epoch
        or receipt.get("host") != configuration.host
        or not _reference_matches(receipt.get("archive"), filename, payload)
        or receipt.get("contract") != _contract_reference(configuration, spec)
    ):
        raise ReleaseError(f"producer receipt is stale or malformed: {spec.identifier}")
    source = _validate_source(receipt.get("source"), state, label=spec.identifier)
    _validate_authority(receipt, configuration, spec.contract)
    _validate_claims(receipt)
    if (
        spec.workspace in {"typescript", "rust"}
        and receipt.get("producer_declared_in_artifact_matrix") is not True
    ):
        raise ReleaseError(f"producer declaration is not bound: {spec.identifier}")
    return source


def _python_receipt(
    receipt: dict[str, Any],
    artifacts: Mapping[str, bytes],
    specs: tuple[ArtifactSpec, ...],
    configuration: Configuration,
    epoch: int,
    state: RepositoryState,
) -> dict[str, Any]:
    by_id = {spec.identifier: spec for spec in specs}
    ordered_ids = ["python-sdk-sdist", "python-sdk-wheel"]
    expected_artifacts = {
        "sdist": {
            "path": _filename(by_id[ordered_ids[0]], configuration.version),
            "sha256": sha256_bytes(artifacts[ordered_ids[0]]),
            "bytes": len(artifacts[ordered_ids[0]]),
        },
        "wheel": {
            "path": _filename(by_id[ordered_ids[1]], configuration.version),
            "sha256": sha256_bytes(artifacts[ordered_ids[1]]),
            "bytes": len(artifacts[ordered_ids[1]]),
        },
    }
    expected_contracts = {
        identifier: _contract_reference(configuration, by_id[identifier])
        for identifier in ordered_ids
    }
    if (
        receipt.get("schema_version") != specs[0].receipt_schema
        or receipt.get("status") != "built-unqualified"
        or receipt.get("artifact_ids") != ordered_ids
        or receipt.get("target") != specs[0].target
        or receipt.get("product_version") != configuration.version
        or receipt.get("python_distribution_version")
        != _python_version(configuration.version)
        or receipt.get("context_abi") != configuration.context_abi
        or receipt.get("source_date_epoch") != epoch
        or receipt.get("host") != configuration.host
        or receipt.get("artifacts") != expected_artifacts
        or receipt.get("contracts") != expected_contracts
    ):
        raise ReleaseError("Python producer receipt is stale or malformed")
    source = _validate_source(receipt.get("source"), state, label="Python SDK")
    for spec in specs:
        _validate_authority(receipt, configuration, spec.contract)
    _validate_claims(receipt)
    return source


def _homebrew_receipt(
    receipt: dict[str, Any],
    artifacts: Mapping[str, bytes],
    specs: tuple[ArtifactSpec, ...],
    configuration: Configuration,
    epoch: int,
    state: RepositoryState,
    native: Artifact,
    native_receipt_payload: bytes,
) -> dict[str, Any]:
    by_id = {spec.identifier: spec for spec in specs}
    raw_records = receipt.get("artifacts")
    if (
        not isinstance(raw_records, list)
        or len(raw_records) != 2
        or not all(isinstance(record, dict) for record in raw_records)
    ):
        raise ReleaseError("Homebrew receipt artifact inventory is malformed")
    expected_records = []
    for index, identifier in enumerate(
        ("macos-homebrew-formula-arm64", "macos-installer-arm64")
    ):
        spec = by_id[identifier]
        summary = raw_records[index].get("package_verification")
        if (
            not isinstance(summary, dict)
            or set(summary)
            != {"schema_version", "status", "file_count", "expanded_bytes"}
            or summary.get("schema_version") != "cigar.package-verification.v1"
            or summary.get("status") != "passed"
            or not isinstance(summary.get("file_count"), int)
            or isinstance(summary.get("file_count"), bool)
            or summary["file_count"] <= 0
            or not isinstance(summary.get("expanded_bytes"), int)
            or isinstance(summary.get("expanded_bytes"), bool)
            or summary["expanded_bytes"] <= 0
        ):
            raise ReleaseError("Homebrew receipt package verification is malformed")
        expected_records.append(
            {
                "artifact_id": identifier,
                "kind": spec.kind,
                "path": _filename(spec, configuration.version),
                "sha256": sha256_bytes(artifacts[identifier]),
                "bytes": len(artifacts[identifier]),
                "contract": _contract_reference(configuration, spec),
                "package_verification": summary,
            }
        )
    input_native = receipt.get("input_native_archive")
    if (
        receipt.get("schema_version") != specs[0].receipt_schema
        or receipt.get("status") != "built-unqualified"
        or receipt.get("target") != TARGET_TRIPLE
        or receipt.get("product_version") != configuration.version
        or receipt.get("context_abi") != configuration.context_abi
        or receipt.get("source_date_epoch") != epoch
        or receipt.get("host") != configuration.host
        or receipt.get("artifacts") != expected_records
        or not isinstance(input_native, dict)
        or input_native.get("artifact_id") != native.spec.identifier
        or input_native.get("path") != _filename(native.spec, configuration.version)
        or input_native.get("sha256") != native.sha256
        or input_native.get("bytes") != native.bytes
        or input_native.get("build_receipt")
        != {
            "filename": native.spec.receipt,
            "sha256": sha256_bytes(native_receipt_payload),
            "bytes": len(native_receipt_payload),
        }
    ):
        raise ReleaseError("Homebrew producer receipt is stale or malformed")
    source = _validate_source(receipt.get("source"), state, label="Homebrew")
    if source != native.source:
        raise ReleaseError("Homebrew producer source does not match its native input")
    for spec in specs:
        _validate_authority(receipt, configuration, spec.contract)
    _validate_claims(receipt)
    external = receipt.get("external_requirements")
    if not isinstance(external, dict) or any(
        external.get(key) != value
        for key, value in {
            "native_code_signing": "not-evidenced",
            "notarization": "not-evidenced",
            "artifact_signatures": "not-evidenced",
            "installed_byte_qualification": "not-evidenced",
            "homebrew_publication": "not-performed",
        }.items()
    ):
        raise ReleaseError("Homebrew receipt does not preserve external release gates")
    return source


def _verify_artifact_payload(
    payload: bytes,
    spec: ArtifactSpec,
    configuration: Configuration,
    epoch: int,
    source: dict[str, Any],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="cigar-development-assembly-verify-"
    ) as raw:
        directory = Path(raw).resolve(strict=True)
        # Unpublished archive verification inputs must remain owner-private.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            directory, 0o700
        )
        path = directory / _filename(spec, configuration.version)
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
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise ReleaseError("short write while staging package verification")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        expected_version = (
            None
            if spec.identifier == "macos-installer-arm64"
            else configuration.version
        )
        expected_abi = (
            None
            if spec.identifier == "macos-installer-arm64"
            else configuration.context_abi
        )
        verification = verify_package(
            path,
            resolve_beneath(configuration.root, f"packaging/{spec.contract}"),
            expected_version,
            expected_abi,
            epoch,
        )
    metadata = verification.get("metadata")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or metadata.get("artifact_id") != spec.identifier
        or metadata.get("product_version") != configuration.version
        or metadata.get("context_abi") != configuration.context_abi
        or metadata.get("source_date_epoch") != epoch
        or metadata.get("source") != source
    ):
        raise ReleaseError(f"package metadata binding is stale: {spec.identifier}")
    return verification


def _verify_homebrew_inputs(
    configuration: Configuration, paths: Mapping[str, Path], epoch: int
) -> Any:
    return verify_homebrew(
        configuration.root,
        paths["native_archive"],
        paths["native_receipt"],
        paths["bottle"],
        paths["tap"],
        paths["homebrew_receipt"],
        epoch,
    )


def _workspace_inventory(
    key: str, specs: tuple[ArtifactSpec, ...], configuration: Configuration
) -> frozenset[str]:
    names = {_filename(spec, configuration.version) for spec in specs}
    if key == "portable":
        names.update({"build-manifest.json", "SHA256SUMS"})
    else:
        receipts = {spec.receipt for spec in specs}
        if len(receipts) != 1:
            raise ReleaseError(f"workspace receipt inventory is ambiguous: {key}")
        names.update(receipts)
    return frozenset(names)


def _input_limits(inventory: frozenset[str]) -> EvidenceLimits:
    return EvidenceLimits(
        max_files=max(32, len(inventory)),
        max_directories=8,
        max_file_bytes=64 * 1024 * 1024,
        max_total_bytes=MAX_INPUT_TOTAL_BYTES,
        max_json_bytes=16 * 1024 * 1024,
        max_path_depth=4,
    )


def _path_outside_repository(path: Path, root: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise ReleaseError(f"{label} must be an absolute canonical path")
    try:
        inside = os.path.commonpath((os.fspath(path), os.fspath(root))) == os.fspath(
            root
        )
    except ValueError:
        inside = False
    if inside:
        raise ReleaseError(f"{label} must be outside the source repository")
    return path


def _open_inputs(
    arguments: argparse.Namespace, configuration: Configuration
) -> tuple[dict[str, EvidenceWorkspace], dict[str, frozenset[str]]]:
    specs_by_workspace: dict[str, tuple[ArtifactSpec, ...]] = {
        key: tuple(spec for spec in configuration.specs if spec.workspace == key)
        for key in WORKSPACE_ARGUMENTS
    }
    inventories = {
        key: _workspace_inventory(key, specs, configuration)
        for key, specs in specs_by_workspace.items()
    }
    workspaces: dict[str, EvidenceWorkspace] = {}
    identities: dict[tuple[int, int], str] = {}
    output = _path_outside_repository(
        arguments.evidence_dir, configuration.root, "assembly output"
    )
    try:
        for key, attribute in WORKSPACE_ARGUMENTS.items():
            selected = _path_outside_repository(
                getattr(arguments, attribute), configuration.root, f"{key} workspace"
            )
            try:
                metadata = selected.lstat()
            except OSError as error:
                raise ReleaseError(
                    f"cannot inspect {key} workspace: {error}"
                ) from error
            if not stat.S_ISDIR(metadata.st_mode):
                raise ReleaseError(f"{key} workspace must already exist as a directory")
            workspace = EvidenceWorkspace.create(
                selected,
                repository_root=configuration.root,
                limits=_input_limits(inventories[key]),
            )
            identity_metadata = workspace.root.stat()
            identity = (identity_metadata.st_dev, identity_metadata.st_ino)
            if identity in identities:
                raise ReleaseError(
                    f"input workspaces alias each other: {identities[identity]} and {key}"
                )
            identities[identity] = key
            for previous_key, previous_workspace in workspaces.items():
                try:
                    common = os.path.commonpath(
                        (os.fspath(workspace.root), os.fspath(previous_workspace.root))
                    )
                    nested = common in {
                        os.fspath(workspace.root),
                        os.fspath(previous_workspace.root),
                    }
                except ValueError:
                    nested = False
                if nested:
                    raise ReleaseError(
                        f"input workspaces must not be nested: {previous_key} and {key}"
                    )
            for other_label, other in (("assembly output", output),):
                try:
                    nested = os.path.commonpath(
                        (os.fspath(workspace.root), os.fspath(other))
                    ) in {os.fspath(workspace.root), os.fspath(other)}
                except ValueError:
                    nested = False
                if nested:
                    raise ReleaseError(
                        f"{key} workspace must be distinct from {other_label}"
                    )
            workspaces[key] = workspace
        return workspaces, inventories
    except BaseException:
        for workspace in workspaces.values():
            workspace.close()
        raise


def _parse_checksums(payload: bytes, expected: Mapping[str, bytes], label: str) -> None:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReleaseError(f"{label} is not ASCII") from error
    canonical = "".join(
        f"{sha256_bytes(value)}  {name}\n"
        for name, value in sorted(
            expected.items(), key=lambda item: item[0].encode("utf-8")
        )
    )
    if text != canonical:
        raise ReleaseError(f"{label} is stale, unsorted, duplicated, or unreferenced")


def validate_inputs(
    arguments: argparse.Namespace,
    *,
    package_verifier: PackageVerifier = _verify_artifact_payload,
    homebrew_verifier: HomebrewVerifier = _verify_homebrew_inputs,
    repository_state: RepositoryState | None = None,
) -> tuple[Configuration, RepositoryState, dict[str, Artifact], dict[str, Any]]:
    configuration = load_configuration(arguments.root)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    state = repository_state or _repository_state(configuration.root)
    workspaces, inventories = _open_inputs(arguments, configuration)
    artifacts: dict[str, Artifact] = {}
    receipts: dict[str, Any] = {}
    try:
        snapshots: dict[str, dict[str, bytes]] = {}
        aggregate_bytes = 0
        for key, workspace in workspaces.items():
            snapshot = workspace.read_files(inventories[key], strict_read_only=True)
            aggregate_bytes += sum(len(payload) for payload in snapshot.values())
            if aggregate_bytes > MAX_ASSEMBLY_PAYLOAD_BYTES:
                raise ReleaseError(
                    "selected producer workspaces exceed the bounded assembly payload"
                )
            snapshots[key] = snapshot
        portable_specs = tuple(
            spec for spec in configuration.specs if spec.workspace == "portable"
        )
        portable_payloads = snapshots["portable"]
        portable_receipt_payload = portable_payloads["build-manifest.json"]
        portable_receipt = _canonical_document(
            portable_receipt_payload, "portable build manifest"
        )
        portable_artifact_payloads = {
            spec.identifier: portable_payloads[_filename(spec, configuration.version)]
            for spec in portable_specs
        }
        expected_records = [
            {
                "id": spec.identifier,
                "path": _filename(spec, configuration.version),
                "sha256": sha256_bytes(portable_artifact_payloads[spec.identifier]),
                "bytes": len(portable_artifact_payloads[spec.identifier]),
                "contract": f"packaging/{spec.contract}",
            }
            for spec in sorted(portable_specs, key=lambda item: item.identifier)
        ]
        if (
            set(portable_receipt)
            != {
                "schema_version",
                "product_version",
                "context_abi",
                "source_date_epoch",
                "source",
                "artifacts",
            }
            or portable_receipt.get("schema_version") != BUILD_SCHEMA
            or portable_receipt.get("product_version") != configuration.version
            or portable_receipt.get("context_abi") != configuration.context_abi
            or portable_receipt.get("source_date_epoch") != epoch
            or portable_receipt.get("artifacts") != expected_records
        ):
            raise ReleaseError("portable build manifest is incomplete or stale")
        portable_source = _validate_source(
            portable_receipt.get("source"), state, label="portable archives"
        )
        _parse_checksums(
            portable_payloads["SHA256SUMS"],
            {
                _filename(spec, configuration.version): portable_artifact_payloads[
                    spec.identifier
                ]
                for spec in portable_specs
            },
            "portable SHA256SUMS",
        )
        for spec in portable_specs:
            payload = portable_artifact_payloads[spec.identifier]
            package_verifier(payload, spec, configuration, epoch, portable_source)
            artifacts[spec.identifier] = Artifact(spec, payload, portable_source)
        receipts["portable"] = portable_receipt

        native_spec = next(
            spec for spec in configuration.specs if spec.workspace == "native"
        )
        native_snapshot = snapshots["native"]
        native_payload = native_snapshot[_filename(native_spec, configuration.version)]
        native_receipt_payload = native_snapshot[native_spec.receipt]
        native_receipt = _canonical_document(native_receipt_payload, "native receipt")
        native_source = _common_receipt(
            native_receipt,
            native_spec,
            native_payload,
            configuration,
            epoch,
            state,
        )
        package_verifier(
            native_payload, native_spec, configuration, epoch, native_source
        )
        native_artifact = Artifact(native_spec, native_payload, native_source)
        artifacts[native_spec.identifier] = native_artifact
        receipts["native"] = native_receipt

        for key in (
            "conformance_tool",
            "cigarbench_tool",
            "typescript",
            "rust",
            "go",
            "claude",
        ):
            spec = next(item for item in configuration.specs if item.workspace == key)
            snapshot = snapshots[key]
            payload = snapshot[_filename(spec, configuration.version)]
            receipt = _canonical_document(snapshot[spec.receipt], f"{key} receipt")
            source = _common_receipt(
                receipt, spec, payload, configuration, epoch, state
            )
            package_verifier(payload, spec, configuration, epoch, source)
            artifacts[spec.identifier] = Artifact(spec, payload, source)
            receipts[key] = receipt

        python_specs = tuple(
            spec for spec in configuration.specs if spec.workspace == "python"
        )
        python_snapshot = snapshots["python"]
        python_payloads = {
            spec.identifier: python_snapshot[_filename(spec, configuration.version)]
            for spec in python_specs
        }
        python_receipt = _canonical_document(
            python_snapshot[python_specs[0].receipt], "Python receipt"
        )
        python_source = _python_receipt(
            python_receipt,
            python_payloads,
            python_specs,
            configuration,
            epoch,
            state,
        )
        for spec in python_specs:
            payload = python_payloads[spec.identifier]
            package_verifier(payload, spec, configuration, epoch, python_source)
            artifacts[spec.identifier] = Artifact(spec, payload, python_source)
        receipts["python"] = python_receipt

        homebrew_specs = tuple(
            spec for spec in configuration.specs if spec.workspace == "homebrew"
        )
        homebrew_snapshot = snapshots["homebrew"]
        homebrew_payloads = {
            spec.identifier: homebrew_snapshot[_filename(spec, configuration.version)]
            for spec in homebrew_specs
        }
        homebrew_receipt = _canonical_document(
            homebrew_snapshot[homebrew_specs[0].receipt], "Homebrew receipt"
        )
        homebrew_source = _homebrew_receipt(
            homebrew_receipt,
            homebrew_payloads,
            homebrew_specs,
            configuration,
            epoch,
            state,
            native_artifact,
            native_receipt_payload,
        )
        for spec in homebrew_specs:
            payload = homebrew_payloads[spec.identifier]
            package_verifier(payload, spec, configuration, epoch, homebrew_source)
            artifacts[spec.identifier] = Artifact(spec, payload, homebrew_source)
        homebrew_verifier(
            configuration,
            {
                "native_archive": workspaces["native"].root
                / _filename(native_spec, configuration.version),
                "native_receipt": workspaces["native"].root / native_spec.receipt,
                "bottle": workspaces["homebrew"].root
                / _filename(
                    next(
                        spec
                        for spec in homebrew_specs
                        if spec.identifier == "macos-installer-arm64"
                    ),
                    configuration.version,
                ),
                "tap": workspaces["homebrew"].root
                / _filename(
                    next(
                        spec
                        for spec in homebrew_specs
                        if spec.identifier == "macos-homebrew-formula-arm64"
                    ),
                    configuration.version,
                ),
                "homebrew_receipt": workspaces["homebrew"].root
                / homebrew_specs[0].receipt,
            },
            epoch,
        )
        receipts["homebrew"] = homebrew_receipt

        selected_ids = tuple(identifier for identifier, _group in SELECTED)
        if set(artifacts) != set(selected_ids) or len(artifacts) != len(selected_ids):
            raise ReleaseError(
                "validated artifact set does not contain every selected id exactly once"
            )
        current_state = repository_state or _repository_state(configuration.root)
        if current_state != state:
            raise ReleaseError("repository state changed during artifact validation")
        # Re-read every exact producer inventory after all contract checks.  This catches
        # post-receipt replacement before any assembled output is created.
        for key, workspace in workspaces.items():
            repeated = workspace.read_files(inventories[key], strict_read_only=True)
            if repeated != snapshots[key]:
                raise ReleaseError(
                    f"{key} producer workspace changed during validation"
                )
        return configuration, state, artifacts, receipts
    finally:
        for workspace in workspaces.values():
            workspace.close()


def _build_manifest(
    configuration: Configuration,
    epoch: int,
    source: dict[str, Any],
    artifacts: Mapping[str, Artifact],
) -> dict[str, Any]:
    return {
        "schema_version": BUILD_SCHEMA,
        "product_version": configuration.version,
        "context_abi": configuration.context_abi,
        "source_date_epoch": epoch,
        "source": source,
        "artifacts": [
            {
                "id": identifier,
                "path": _filename(artifacts[identifier].spec, configuration.version),
                "sha256": artifacts[identifier].sha256,
                "bytes": artifacts[identifier].bytes,
                "contract": f"packaging/{artifacts[identifier].spec.contract}",
            }
            for identifier in sorted(artifacts)
        ],
    }


def _checksum_payload(
    configuration: Configuration, artifacts: Mapping[str, Artifact]
) -> bytes:
    records = sorted(
        (
            _filename(artifact.spec, configuration.version),
            artifact.sha256,
        )
        for artifact in artifacts.values()
    )
    return "".join(f"{digest}  {path}\n" for path, digest in records).encode("ascii")


def _publish_payload(
    workspace: EvidenceWorkspace, relative: str, payload: bytes
) -> None:
    """Attach validated in-memory bytes through the public stable-file API."""

    with tempfile.TemporaryDirectory(prefix="cigar-development-assembly-copy-") as raw:
        directory = Path(raw).resolve(strict=True)
        # Unpublished assembly payloads must remain owner-private until publication.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            directory, 0o700
        )
        source = directory / "payload"
        descriptor = os.open(
            source,
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
                    raise ReleaseError("short write while staging assembled payload")
                offset += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        workspace.attach_file(
            source,
            relative,
            read_only=True,
            expected_sha256=sha256_bytes(payload),
            expected_bytes=len(payload),
        )


def assemble(
    arguments: argparse.Namespace,
    *,
    package_verifier: PackageVerifier = _verify_artifact_payload,
    homebrew_verifier: HomebrewVerifier = _verify_homebrew_inputs,
    repository_state: RepositoryState | None = None,
) -> dict[str, Any]:
    configuration, state, artifacts, _receipts = validate_inputs(
        arguments,
        package_verifier=package_verifier,
        homebrew_verifier=homebrew_verifier,
        repository_state=repository_state,
    )
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    source = artifacts["source"].source
    manifest = _build_manifest(configuration, epoch, source, artifacts)
    checksum_payload = _checksum_payload(configuration, artifacts)
    output = _path_outside_repository(
        arguments.evidence_dir, configuration.root, "assembly output"
    )
    limits = EvidenceLimits(
        max_files=64,
        max_directories=8,
        max_file_bytes=64 * 1024 * 1024,
        max_total_bytes=MAX_OUTPUT_TOTAL_BYTES,
        max_json_bytes=16 * 1024 * 1024,
        max_path_depth=4,
    )
    workspace = EvidenceWorkspace.create(
        output, repository_root=configuration.root, limits=limits
    )
    try:
        workspace.read_files(set(), strict_read_only=False)
        # Artifacts are copied only after every producer workspace and contract passed.
        for identifier in sorted(artifacts):
            artifact = artifacts[identifier]
            _publish_payload(
                workspace,
                _filename(artifact.spec, configuration.version),
                artifact.payload,
            )
        # The two authoritative manifests are intentionally emitted last.
        workspace.write_json(BUILD_MANIFEST, manifest)
        _publish_payload(workspace, CHECKSUM_MANIFEST, checksum_payload)
        expected_inventory = {
            *(
                _filename(artifact.spec, configuration.version)
                for artifact in artifacts.values()
            ),
            BUILD_MANIFEST,
            CHECKSUM_MANIFEST,
        }
        workspace.read_files(expected_inventory, strict_read_only=True)
    finally:
        workspace.close()
    if repository_state is None and _repository_state(configuration.root) != state:
        raise ReleaseError("repository state changed while publishing the assembly")
    return manifest


def main() -> int:
    manifest = assemble(parse_arguments())
    print(canonical_json_bytes(manifest).decode("utf-8"), end="")
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
        raise SystemExit(f"macOS development assembly failed: {error}") from error
