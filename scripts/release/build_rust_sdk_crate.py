#!/usr/bin/env python3
"""Build the deterministic, unpublished development Rust SDK crate on macOS."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    expand_files,
    git_state,
    load_json,
    load_json_bytes,
    process_failure_summary,
    require_source_date_epoch,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    tree_digest,
)
from verify_package import verify as verify_package


ARTIFACT_ID = "rust-sdk-crate"
TARGET_TRIPLE = "aarch64-apple-darwin"
PRODUCER = "python3 scripts/release/build_rust_sdk_crate.py"
BUILD_RECEIPT = "rust-sdk-crate-development-build.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SDK_RELATIVE = "sdk/rust"
EXPECTED_QUICKSTART_IDENTITY = (
    "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"
)
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
MAX_TOOL_BYTES = 64 * 1024 * 1024
MAX_REGISTRY_FILES = 10_000
MAX_REGISTRY_BYTES = 2 * 1024 * 1024 * 1024

AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/cargo-crate.v1.json",
    "Cargo.toml",
    "Cargo.lock",
    f"{SDK_RELATIVE}/Cargo.toml",
    f"{SDK_RELATIVE}/README.md",
    f"{SDK_RELATIVE}/PUBLISHING.md",
    f"{SDK_RELATIVE}/release.json",
)

SDK_SOURCE_PATHS = frozenset(
    {
        "Cargo.toml",
        "README.md",
        "LICENSE",
        "NOTICE",
        "release.json",
        "examples/quickstart.rs",
        "fixtures/semantic-bundle-v1.json",
        "src/client.rs",
        "src/daemon_embedded.rs",
        "src/embedded.rs",
        "src/error.rs",
        "src/lib.rs",
        "src/options.rs",
        "src/remote.rs",
        "src/transport.rs",
        "src/verify.rs",
    }
)


@dataclass(frozen=True)
class PackageSpec:
    name: str
    source_relative: str
    fixed_version: str | None = None


PACKAGE_SPECS = (
    PackageSpec("cigar-aws-creds", "crates/cigar-aws-creds", "0.39.1-cigar.1"),
    PackageSpec("cigar-rust-s3", "crates/cigar-rust-s3", "0.37.2-cigar.1"),
    PackageSpec("cigar-canon", "crates/cigar-canon"),
    PackageSpec("cigar-protocol", "crates/cigar-protocol"),
    PackageSpec("cigar-testkit", "crates/cigar-testkit"),
    PackageSpec("cigar-windows-ipc", "crates/cigar-windows-ipc"),
    PackageSpec("cigar-crypto", "crates/cigar-crypto"),
    PackageSpec("cigar-replay", "crates/cigar-replay"),
    PackageSpec("cigar-policy", "crates/cigar-policy"),
    PackageSpec("cigar-store", "crates/cigar-store"),
    PackageSpec("cigar-effects", "crates/cigar-effects"),
    PackageSpec("cigar-retrieval", "crates/cigar-retrieval"),
    PackageSpec("cigar-space", "crates/cigar-space"),
    PackageSpec("cigar-catalog", "crates/cigar-catalog"),
    PackageSpec("cigar-code-intel", "crates/cigar-code-intel"),
    PackageSpec("cigar-compiler", "crates/cigar-compiler"),
    PackageSpec("cigar-api", "crates/cigar-api"),
    PackageSpec("cigar-observe", "crates/cigar-observe"),
    PackageSpec("cigar-daemon", "crates/cigar-daemon"),
    PackageSpec("cigar-sdk", SDK_RELATIVE),
)
SDK_LOCK_REQUIRED_PACKAGE_NAMES = frozenset(
    specification.name
    for specification in PACKAGE_SPECS
    if specification.name != "cigar-testkit"
)

SOURCE_INCLUDES = (
    "Cargo.toml",
    "Cargo.lock",
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/cargo-crate.v1.json",
    *(f"{spec.source_relative}/**" for spec in PACKAGE_SPECS),
    "scripts/release/build_rust_sdk_crate.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/verify_package.py",
)
SOURCE_EXCLUDES = (
    "**/.DS_Store",
    "**/.ruff_cache/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/target/**",
)


@dataclass(frozen=True)
class CrateEntry:
    path: str
    payload: bytes
    mode: int = 0o644


@dataclass(frozen=True)
class BuildConfiguration:
    root: Path
    sdk_root: Path
    version: str
    context_abi: str
    filename: str
    crate_root: str
    contract_path: Path
    contract_relative: str
    authority: dict[str, dict[str, object]]
    sdk_sources: dict[str, bytes]
    producer_declared: bool


@dataclass(frozen=True)
class BuiltCrate:
    entries: tuple[CrateEntry, ...]
    raw_cargo_package_sha256: str
    raw_cargo_package_bytes: int
    package_chain: tuple[dict[str, object], ...]
    dependency_registry: dict[str, object]
    tools: tuple[dict[str, object], ...]
    validation: dict[str, object]


CrateBuilder = Callable[
    [BuildConfiguration, dict[str, Any], int, Path, argparse.Namespace], BuiltCrate
]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external empty output workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--cargo-local-registry", type=Path)
    parser.add_argument("--protoc", type=Path)
    parser.add_argument(
        "--cargo-cache",
        type=Path,
        help="owner-controlled Cargo home containing the exact locked crate cache",
    )
    return parser.parse_args()


def _selected_evidence_directory(arguments: argparse.Namespace) -> Path:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment and Path(argument) != Path(environment):
        raise ReleaseError(
            "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide one location"
        )
    raw = argument if argument is not None else environment
    if raw is None or os.fspath(raw) == "":
        raise ReleaseError("--evidence-dir or CIGAR_EVIDENCE_DIR is required")
    selected = Path(raw)
    if not selected.is_absolute():
        raise ReleaseError("evidence directory must be an absolute path")
    return selected


def _require_host() -> dict[str, str]:
    machine = platform.machine().casefold()
    if sys.platform != "darwin" or machine not in {"arm64", "aarch64"}:
        raise ReleaseError(
            "the development Rust SDK producer requires Apple-silicon macOS; "
            f"observed platform={sys.platform} architecture={machine}"
        )
    return {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": platform.mac_ver()[0],
    }


def _read_stable_file(
    path: Path, maximum: int, label: str, *, allow_empty: bool = False
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or (before.st_size == 0 and not allow_empty)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise ReleaseError(
                f"{label} is not a bounded owner-controlled regular file"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds {maximum} bytes")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise ReleaseError(f"{label} changed while it was read")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise ReleaseError(f"{label} changed length while it was read")
        return payload
    except OSError as error:
        raise ReleaseError(f"cannot securely read {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _authority_digests(root: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for relative in AUTHORITY_PATHS:
        payload = _read_stable_file(
            root.joinpath(*relative.split("/")), MAX_SOURCE_BYTES, relative
        )
        records[relative] = {"sha256": sha256_bytes(payload), "bytes": len(payload)}
    return records


def _read_sdk_sources(sdk_root: Path) -> dict[str, bytes]:
    actual: set[str] = set()
    for current, directories, files in os.walk(
        sdk_root, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        directories[:] = [
            name
            for name in sorted(directories)
            if name not in {"__pycache__", ".ruff_cache"}
        ]
        for name in directories:
            if (current_path / name).is_symlink():
                raise ReleaseError("Rust SDK source contains a directory symlink")
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(sdk_root).as_posix()
            if path.is_symlink():
                raise ReleaseError(f"Rust SDK source contains a symlink: {relative}")
            if not path.is_file():
                raise ReleaseError(f"Rust SDK source is not a regular file: {relative}")
            if relative in SDK_SOURCE_PATHS:
                actual.add(relative)
    if actual != SDK_SOURCE_PATHS:
        raise ReleaseError("Rust SDK package source inventory differs from review")

    sources: dict[str, bytes] = {}
    aliases: set[str] = set()
    for relative in sorted(SDK_SOURCE_PATHS, key=lambda value: value.encode("utf-8")):
        canonical = safe_relative_path(relative)
        alias = unicodedata.normalize("NFC", canonical).casefold()
        if alias in aliases:
            raise ReleaseError("Rust SDK package source paths collide portably")
        aliases.add(alias)
        payload = _read_stable_file(
            sdk_root.joinpath(*canonical.split("/")),
            MAX_SOURCE_BYTES,
            f"Rust SDK source {canonical}",
        )
        if b"\r" in payload:
            raise ReleaseError(f"Rust SDK package source is not LF-only: {canonical}")
        sources[canonical] = payload
    return sources


def _validate_contract(contract: Any, crate_root: str) -> None:
    source_members = {
        f"{crate_root}/{relative}"
        for relative in SDK_SOURCE_PATHS
        if relative != "Cargo.toml"
    }
    generated = {
        f"{crate_root}/Cargo.toml",
        f"{crate_root}/Cargo.toml.orig",
        f"{crate_root}/Cargo.lock",
        f"{crate_root}/.cargo_vcs_info.json",
    }
    expected_members = source_members | generated
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id") != "cargo-crate-v1"
        or contract.get("formats") != ["tar.gz"]
        or set(contract.get("allow", []))
        != {
            f"{crate_root}/Cargo.toml",
            f"{crate_root}/Cargo.toml.orig",
            f"{crate_root}/Cargo.lock",
            f"{crate_root}/README.md",
            f"{crate_root}/.cargo_vcs_info.json",
            f"{crate_root}/LICENSE",
            f"{crate_root}/NOTICE",
            f"{crate_root}/release.json",
            f"{crate_root}/examples/quickstart.rs",
            f"{crate_root}/fixtures/semantic-bundle-v1.json",
            f"{crate_root}/src/**",
        }
        or set(contract.get("required", []))
        != {
            f"{crate_root}/Cargo.toml",
            f"{crate_root}/Cargo.toml.orig",
            f"{crate_root}/Cargo.lock",
            f"{crate_root}/README.md",
            f"{crate_root}/.cargo_vcs_info.json",
            f"{crate_root}/LICENSE",
            f"{crate_root}/NOTICE",
            f"{crate_root}/release.json",
            f"{crate_root}/examples/quickstart.rs",
            f"{crate_root}/fixtures/semantic-bundle-v1.json",
            f"{crate_root}/src/lib.rs",
        }
        or contract.get("required_patterns") != [f"{crate_root}/src/*.rs"]
        or contract.get("deny")
        != [
            "**/.git/**",
            "**/.env*",
            "**/*.key",
            "**/*.pem",
            "**/target/**",
            "**/tests/**",
            "**/*.profraw",
        ]
        or contract.get("symlinks") != "forbid"
        or contract.get("line_endings") != "lf"
        or contract.get("modes") != ["0644"]
        or contract.get("max_entries") != 10_000
        or contract.get("max_member_bytes") != MAX_ARCHIVE_MEMBER_BYTES
        or contract.get("max_total_bytes") != MAX_ARCHIVE_EXPANDED_BYTES
        or contract.get("content_scan") is not True
        or contract.get("content_scan_exemptions") != []
        or contract.get("version_binding")
        != {
            "path_pattern": f"{crate_root}/release.json",
            "format": "json",
            "json_pointer": "/version",
        }
        or contract.get("abi_binding")
        != {
            "path_pattern": f"{crate_root}/release.json",
            "format": "json",
            "json_pointer": "/context_abi",
        }
        or not expected_members
    ):
        raise ReleaseError("Rust SDK crate package contract is incomplete or stale")


def _load_configuration(root: Path) -> BuildConfiguration:
    root = root.resolve(strict=True)
    sdk_root = root / SDK_RELATIVE
    authority = _authority_digests(root)
    product = load_json(root / "packaging/product-version.v1.json")
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    profile = load_json(root / "packaging/development/local-macos-aarch64.v1.json")
    contract_relative = "packaging/contracts/cargo-crate.v1.json"
    contract_path = root / contract_relative
    contract = load_json(contract_path)
    sdk_sources = _read_sdk_sources(sdk_root)

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
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+", product["version"])
        is None
        or product.get("context_abi") != "cigar.context.v1"
    ):
        raise ReleaseError("product version authority is not a development identity")
    version = product["version"]
    context_abi = product["context_abi"]
    filename = f"cigar-sdk-{version}.crate"
    crate_root = f"cigar-sdk-{version}"

    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("release_state") != "development"
        or matrix.get("product_version") != version
        or matrix.get("context_abi") != context_abi
        or not isinstance(matrix.get("artifacts"), list)
    ):
        raise ReleaseError("artifact matrix is stale relative to product authority")
    rows = [
        row
        for row in matrix["artifacts"]
        if isinstance(row, dict) and row.get("id") == ARTIFACT_ID
    ]
    if len(rows) != 1:
        raise ReleaseError("rust-sdk-crate artifact matrix row is missing or duplicate")
    row = rows[0]
    allowed_keys = {
        "id",
        "kind",
        "filename",
        "contract",
        "ecosystem",
        "producer",
        "required_for_release",
        "qualification",
    }
    if (
        not set(row).issubset(allowed_keys)
        or set(row) - {"producer"}
        != {
            "id",
            "kind",
            "filename",
            "contract",
            "ecosystem",
            "required_for_release",
            "qualification",
        }
        or row.get("kind") != "cargo-crate"
        or row.get("filename") != filename
        or row.get("contract") != "contracts/cargo-crate.v1.json"
        or row.get("ecosystem") != "crates.io"
        or row.get("required_for_release") is not True
        or row.get("qualification")
        != [
            "cargo-package",
            "clean-install",
            "offline",
            "version-abi-consistency",
            "sbom",
            "license",
            "signature",
        ]
        or ("producer" in row and row.get("producer") != PRODUCER)
    ):
        raise ReleaseError("rust-sdk-crate artifact matrix row is incomplete or stale")

    selected = profile.get("selected_artifacts") if isinstance(profile, dict) else None
    selected_rows = (
        [
            item
            for item in selected
            if isinstance(item, dict) and item.get("id") == ARTIFACT_ID
        ]
        if isinstance(selected, list)
        else []
    )
    if (
        profile.get("schema_version") != "cigar.development-artifact-profile.v1"
        or profile.get("release_state") != "development"
        or profile.get("published") is not False
        or profile.get("supported") is not False
        or profile.get("target")
        != {
            "host_arch": "arm64",
            "host_os": "macos",
            "target_triple": TARGET_TRIPLE,
        }
        or selected_rows
        != [
            {
                "built": False,
                "id": ARTIFACT_ID,
                "qualified": False,
                "selection_group": "sdk-rust",
                "status": "planned",
            }
        ]
    ):
        raise ReleaseError("development profile does not leave rust-sdk-crate planned")

    _validate_contract(contract, crate_root)
    sdk_manifest = tomllib.loads(sdk_sources["Cargo.toml"].decode("utf-8"))
    package = sdk_manifest.get("package")
    expected_include = [
        "src/**",
        "examples/quickstart.rs",
        "fixtures/semantic-bundle-v1.json",
        "Cargo.toml",
        "README.md",
        "LICENSE",
        "NOTICE",
        "release.json",
    ]
    if (
        not isinstance(package, dict)
        or package.get("name") != "cigar-sdk"
        or package.get("version") != version
        or package.get("edition") != "2024"
        or package.get("rust-version") != "1.92"
        or package.get("license") != "Apache-2.0"
        or package.get("publish") != ["crates-io"]
        or package.get("include") != expected_include
    ):
        raise ReleaseError("Rust SDK Cargo package identity is incomplete or stale")
    dependencies = sdk_manifest.get("dependencies")
    expected_internal = {
        "cigar-api",
        "cigar-canon",
        "cigar-daemon",
        "cigar-protocol",
    }
    if not isinstance(dependencies, dict) or not expected_internal.issubset(
        dependencies
    ):
        raise ReleaseError("Rust SDK internal dependency declarations are incomplete")
    for name in expected_internal:
        specification = dependencies[name]
        if (
            not isinstance(specification, dict)
            or specification.get("version") != f"={version}"
            or not isinstance(specification.get("path"), str)
        ):
            raise ReleaseError(f"Rust SDK dependency {name} is not exactly versioned")

    release = load_json_bytes(sdk_sources["release.json"], "sdk/rust/release.json")
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": "cigar-sdk",
        "version": version,
        "context_abi": context_abi,
    }:
        raise ReleaseError("Rust SDK release metadata is stale")

    workspace_manifest = tomllib.loads(
        _read_stable_file(root / "Cargo.toml", MAX_SOURCE_BYTES, "Cargo.toml").decode(
            "utf-8"
        )
    )
    if (
        workspace_manifest.get("workspace", {}).get("package", {}).get("version")
        != version
    ):
        raise ReleaseError("workspace Cargo version differs from product authority")
    workspace_lock = tomllib.loads(
        _read_stable_file(root / "Cargo.lock", MAX_SOURCE_BYTES, "Cargo.lock").decode(
            "utf-8"
        )
    )
    lock_packages = workspace_lock.get("package")
    if (
        workspace_lock.get("version") != 4
        or not isinstance(lock_packages, list)
        or len(
            [
                item
                for item in lock_packages
                if isinstance(item, dict)
                and item.get("name") == "cigar-sdk"
                and item.get("version") == version
            ]
        )
        != 1
    ):
        raise ReleaseError("workspace Cargo.lock does not bind the Rust SDK identity")

    return BuildConfiguration(
        root=root,
        sdk_root=sdk_root,
        version=version,
        context_abi=context_abi,
        filename=filename,
        crate_root=crate_root,
        contract_path=contract_path,
        contract_relative=contract_relative,
        authority=authority,
        sdk_sources=sdk_sources,
        producer_declared=row.get("producer") == PRODUCER,
    )


def _source_identity(root: Path) -> dict[str, Any]:
    files = expand_files(root, list(SOURCE_INCLUDES), list(SOURCE_EXCLUDES))
    if not files:
        raise ReleaseError("Rust SDK crate build source inventory is empty")
    identity = git_state(root, tree_digest(files))
    if (
        identity.get("committed") is not True
        or not isinstance(identity.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", identity["revision"]) is None
        or not isinstance(identity.get("clean"), bool)
        or not isinstance(identity.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["tree_sha256"]) is None
    ):
        raise ReleaseError(
            "Rust SDK crate build requires a committed Git source identity"
        )
    return identity


def _secure_executable(value: Path | None, name: str) -> Path:
    supplied = value
    if supplied is None:
        discovered = shutil.which(name)
        if discovered is None:
            raise ReleaseError(f"required executable is unavailable: {name}")
        supplied = Path(discovered)
    if not supplied.is_absolute():
        raise ReleaseError(f"{name} executable path must be absolute")
    try:
        resolved = supplied.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(f"cannot resolve {name} executable: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(supplied, os.X_OK)
    ):
        raise ReleaseError(f"{name} must resolve to an owner-controlled executable")
    return supplied


def _owned_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ReleaseError(f"{label} must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(f"cannot resolve {label}: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseError(f"{label} must be an owner-controlled directory")
    return resolved


def _run_checked(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    label: str,
    maximum: int = MAX_COMMAND_OUTPUT,
) -> bytes:
    try:
        result = run_bounded(
            command,
            cwd=cwd,
            env=environment,
            timeout=timeout,
            max_stdout=maximum,
            max_stderr=maximum,
        )
    except (OSError, subprocess.SubprocessError, ReleaseError) as error:
        raise ReleaseError(f"{label} could not run safely: {error}") from error
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, label))
    return result.stdout


def _tool_record(path: Path, name: str, version: str) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    payload = _read_stable_file(resolved, MAX_TOOL_BYTES, f"{name} executable")
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _package_version(specification: PackageSpec, product_version: str) -> str:
    return specification.fixed_version or product_version


def _dependency_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []

    def collect(table: Any, kind: str | None, target: str | None) -> None:
        if not isinstance(table, dict):
            return
        for alias, raw in table.items():
            specification = {"version": raw} if isinstance(raw, str) else raw
            if not isinstance(specification, dict) or "path" in specification:
                raise ReleaseError(f"normalized dependency {alias} is invalid")
            package = specification.get("package")
            features = specification.get("features", [])
            if not isinstance(features, list):
                raise ReleaseError(
                    f"normalized dependency {alias} features are invalid"
                )
            dependencies.append(
                {
                    "name": alias,
                    "req": specification.get("version", "*"),
                    "features": sorted(features),
                    "optional": specification.get("optional", False),
                    "default_features": specification.get(
                        "default-features", specification.get("default_features", True)
                    ),
                    "target": target,
                    "kind": kind,
                    "package": package if package != alias else None,
                }
            )

    collect(manifest.get("dependencies"), None, None)
    collect(manifest.get("build-dependencies"), "build", None)
    collect(manifest.get("dev-dependencies"), "dev", None)
    target_tables = manifest.get("target", {})
    if isinstance(target_tables, dict):
        for target, target_manifest in target_tables.items():
            if not isinstance(target_manifest, dict):
                continue
            collect(target_manifest.get("dependencies"), None, target)
            collect(target_manifest.get("build-dependencies"), "build", target)
            collect(target_manifest.get("dev-dependencies"), "dev", target)
    dependencies.sort(
        key=lambda item: (item["name"], item["kind"] or "", item["target"] or "")
    )
    return dependencies


def _index_path(registry: Path, package_name: str) -> Path:
    name = package_name.casefold()
    if len(name) == 1:
        relative = Path("1", name)
    elif len(name) == 2:
        relative = Path("2", name)
    elif len(name) == 3:
        relative = Path("3", name[0], name)
    else:
        relative = Path(name[:2], name[2:4], name)
    return registry / "index" / relative


def _add_to_registry(
    registry: Path, crate_path: Path, manifest: dict[str, Any]
) -> dict[str, object]:
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ReleaseError("normalized package manifest lacks package metadata")
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ReleaseError("normalized package identity is invalid")
    payload = _read_stable_file(crate_path, MAX_ARCHIVE_BYTES, f"{name} crate")
    checksum = sha256_bytes(payload)
    features = manifest.get("features", {})
    if not isinstance(features, dict):
        raise ReleaseError(f"normalized package {name} features are invalid")
    record = {
        "name": name,
        "vers": version,
        "deps": _dependency_rows(manifest),
        "cksum": checksum,
        "features": features,
        "yanked": False,
    }
    destination = registry / f"{name}-{version}.crate"
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"local registry already contains {destination.name}")
    destination.write_bytes(payload)
    destination.chmod(0o600)

    package_index = _index_path(registry, name)
    package_index.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing: list[dict[str, Any]] = []
    if package_index.exists():
        existing = [
            json.loads(line)
            for line in package_index.read_text(encoding="utf-8").splitlines()
            if line
        ]
    if any(item.get("vers") == version for item in existing):
        raise ReleaseError(f"local registry index already contains {name} {version}")
    existing.append(record)
    existing.sort(key=lambda item: str(item.get("vers", "")).encode("utf-8"))
    package_index.write_text(
        "\n".join(
            json.dumps(item, separators=(",", ":"), sort_keys=True) for item in existing
        )
        + "\n",
        encoding="utf-8",
    )
    package_index.chmod(0o600)
    return {
        "name": name,
        "version": version,
        "sha256": checksum,
        "bytes": len(payload),
    }


def _normalized_manifest(crate_path: Path, name: str, version: str) -> dict[str, Any]:
    expected = f"{name}-{version}/Cargo.toml"
    try:
        with tarfile.open(crate_path, mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                candidate = PurePosixPath(member.name)
                if candidate.is_absolute() or ".." in candidate.parts:
                    raise ReleaseError(f"unsafe Cargo package path: {member.name}")
                if member.issym() or member.islnk():
                    raise ReleaseError(f"Cargo package contains a link: {member.name}")
            matches = [member for member in members if member.name == expected]
            if len(matches) != 1 or not matches[0].isfile():
                raise ReleaseError(f"Cargo package lacks normalized manifest: {name}")
            handle = archive.extractfile(matches[0])
            if handle is None:
                raise ReleaseError(f"cannot read normalized manifest: {name}")
            payload = handle.read(MAX_SOURCE_BYTES + 1)
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError(
            f"cannot inspect Cargo package {crate_path}: {error}"
        ) from error
    if len(payload) > MAX_SOURCE_BYTES:
        raise ReleaseError(f"normalized Cargo manifest is too large: {name}")
    try:
        manifest = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError(f"normalized Cargo manifest is invalid: {name}") from error
    package = manifest.get("package")
    if (
        not isinstance(package, dict)
        or package.get("name") != name
        or package.get("version") != version
        or package.get("publish") != ["crates-io"]
    ):
        raise ReleaseError(f"normalized Cargo package identity differs: {name}")
    _dependency_rows(manifest)
    return manifest


def _registry_identity(registry: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    file_count = 0
    total = 0
    for current, directories, files in os.walk(
        registry, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        directories[:] = sorted(directories)
        for name in directories:
            if (current_path / name).is_symlink():
                raise ReleaseError(
                    "local dependency registry contains a directory symlink"
                )
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise ReleaseError(
                    "local dependency registry contains a non-regular file"
                )
            relative = path.relative_to(registry).as_posix()
            payload = _read_stable_file(
                path, MAX_ARCHIVE_BYTES, f"local registry {relative}", allow_empty=True
            )
            file_count += 1
            total += len(payload)
            if file_count > MAX_REGISTRY_FILES or total > MAX_REGISTRY_BYTES:
                raise ReleaseError("local dependency registry exceeds its bounds")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(len(payload)).encode("ascii"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(sha256_bytes(payload)))
            digest.update(b"\n")
    if file_count == 0:
        raise ReleaseError("local dependency registry is empty")
    return {
        "schema_version": "cigar.cargo-dependency-registry-snapshot.v1",
        "source": "workspace-Cargo.lock-and-owner-cache",
        "offline": True,
        "file_count": file_count,
        "bytes": total,
        "tree_sha256": digest.hexdigest(),
    }


def _expected_vcs_document(source: dict[str, Any]) -> dict[str, object]:
    git: dict[str, object] = {"sha1": source["revision"]}
    if source["clean"] is False:
        git["dirty"] = True
    return {"git": git, "path_in_vcs": SDK_RELATIVE}


def _read_sdk_crate(
    crate_path: Path,
    configuration: BuildConfiguration,
    source: dict[str, Any],
) -> tuple[CrateEntry, ...]:
    entries: dict[str, CrateEntry] = {}
    aliases: set[str] = set()
    total = 0
    try:
        with tarfile.open(crate_path, mode="r:gz") as archive:
            for member in archive:
                path = safe_relative_path(member.name)
                if member.issym() or member.islnk() or not member.isfile():
                    raise ReleaseError(
                        f"Rust SDK Cargo package member is not regular: {path}"
                    )
                if not path.startswith(f"{configuration.crate_root}/"):
                    raise ReleaseError(f"Rust SDK Cargo package root differs: {path}")
                alias = unicodedata.normalize("NFC", path).casefold()
                if path in entries or alias in aliases:
                    raise ReleaseError(f"Rust SDK Cargo package path collides: {path}")
                if member.size <= 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ReleaseError(
                        f"Rust SDK Cargo package member is unbounded: {path}"
                    )
                total += member.size
                if total > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise ReleaseError(
                        "Rust SDK Cargo package exceeds expanded-size bound"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseError(f"cannot read Rust SDK Cargo member: {path}")
                payload = handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(payload) != member.size:
                    raise ReleaseError(
                        f"Rust SDK Cargo package member changed length: {path}"
                    )
                entries[path] = CrateEntry(path, payload)
                aliases.add(alias)
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError(f"cannot inspect Rust SDK Cargo package: {error}") from error

    expected = {
        f"{configuration.crate_root}/Cargo.toml",
        f"{configuration.crate_root}/Cargo.toml.orig",
        f"{configuration.crate_root}/Cargo.lock",
        f"{configuration.crate_root}/.cargo_vcs_info.json",
        *(
            f"{configuration.crate_root}/{relative}"
            for relative in SDK_SOURCE_PATHS
            if relative != "Cargo.toml"
        ),
    }
    if set(entries) != expected:
        raise ReleaseError(
            "Rust SDK Cargo package differs from the exact reviewed inventory"
        )
    by_path = {path: entry.payload for path, entry in entries.items()}
    for relative, source_payload in configuration.sdk_sources.items():
        packaged = (
            f"{configuration.crate_root}/Cargo.toml.orig"
            if relative == "Cargo.toml"
            else f"{configuration.crate_root}/{relative}"
        )
        if by_path[packaged] != source_payload:
            raise ReleaseError(f"Rust SDK Cargo package source differs: {relative}")

    normalized_path = f"{configuration.crate_root}/Cargo.toml"
    try:
        normalized = tomllib.loads(by_path[normalized_path].decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("Rust SDK normalized Cargo.toml is invalid") from error
    package = normalized.get("package")
    if (
        not isinstance(package, dict)
        or package.get("name") != "cigar-sdk"
        or package.get("version") != configuration.version
        or package.get("publish") != ["crates-io"]
    ):
        raise ReleaseError("Rust SDK normalized Cargo identity differs")
    dependencies = _dependency_rows(normalized)
    dependency_names = {item["name"] for item in dependencies}
    if not {"cigar-api", "cigar-canon", "cigar-daemon", "cigar-protocol"}.issubset(
        dependency_names
    ):
        raise ReleaseError("Rust SDK normalized internal dependencies are incomplete")

    try:
        lock = tomllib.loads(
            by_path[f"{configuration.crate_root}/Cargo.lock"].decode("utf-8")
        )
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("Rust SDK packaged Cargo.lock is invalid") from error
    lock_packages = lock.get("package")
    if (
        lock.get("version") != 4
        or not isinstance(lock_packages, list)
        or len(
            [
                item
                for item in lock_packages
                if isinstance(item, dict)
                and item.get("name") == "cigar-sdk"
                and item.get("version") == configuration.version
            ]
        )
        != 1
    ):
        raise ReleaseError("Rust SDK packaged Cargo.lock is incomplete")
    locked_names = {
        item.get("name") for item in lock_packages if isinstance(item, dict)
    }
    missing_locked = SDK_LOCK_REQUIRED_PACKAGE_NAMES - locked_names
    if missing_locked:
        raise ReleaseError(
            "Rust SDK packaged Cargo.lock omits internal packages: "
            f"{sorted(missing_locked)}"
        )

    vcs = load_json_bytes(
        by_path[f"{configuration.crate_root}/.cargo_vcs_info.json"],
        "Rust SDK .cargo_vcs_info.json",
    )
    if vcs != _expected_vcs_document(source):
        raise ReleaseError("Rust SDK Cargo VCS metadata differs from source identity")
    release = load_json_bytes(
        by_path[f"{configuration.crate_root}/release.json"],
        "packaged Rust SDK release.json",
    )
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": "cigar-sdk",
        "version": configuration.version,
        "context_abi": configuration.context_abi,
    }:
        raise ReleaseError("packaged Rust SDK release identity differs")

    return tuple(
        entries[path]
        for path in sorted(entries, key=lambda value: value.encode("utf-8"))
    )


def _write_canonical_crate(
    path: Path, entries: tuple[CrateEntry, ...], epoch: int
) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite staged Rust SDK crate: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for entry in entries:
                        information = tarfile.TarInfo(entry.path)
                        information.size = len(entry.payload)
                        information.mode = entry.mode
                        information.mtime = epoch
                        information.uid = 0
                        information.gid = 0
                        information.uname = ""
                        information.gname = ""
                        archive.addfile(information, io.BytesIO(entry.payload))
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _extract_crate(
    entries: tuple[CrateEntry, ...], destination: Path, crate_root: str
) -> Path:
    if destination.exists() or destination.is_symlink():
        raise ReleaseError("Rust SDK extraction destination already exists")
    destination.mkdir(mode=0o700)
    for entry in entries:
        parts = PurePosixPath(entry.path).parts
        if not parts or parts[0] != crate_root:
            raise ReleaseError("Rust SDK extraction member has an unexpected root")
        target = destination.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.exists() or target.is_symlink():
            raise ReleaseError("Rust SDK extraction member collides")
        target.write_bytes(entry.payload)
        target.chmod(entry.mode)
    return destination / crate_root


def _cargo_config(cargo_home: Path, registry: Path) -> None:
    cargo_home.mkdir(mode=0o700)
    config = cargo_home / "config.toml"
    config.write_text(
        "[source.crates-io]\n"
        'replace-with = "cigar-local"\n\n'
        "[source.cigar-local]\n"
        f"local-registry = {json.dumps(str(registry))}\n\n"
        "[net]\noffline = true\n",
        encoding="utf-8",
    )
    config.chmod(0o600)


def _base_environment(
    scratch: Path,
    cargo_home: Path,
    rustup_home: Path,
    cargo: Path,
    rustc: Path,
    protoc: Path,
    epoch: int,
) -> dict[str, str]:
    home = scratch / "home"
    temporary = scratch / "tmp"
    target = scratch / "target"
    for directory in (home, temporary, target):
        directory.mkdir(mode=0o700)
    path_entries: list[str] = []
    for directory in (
        cargo.parent,
        cargo.resolve(strict=True).parent,
        rustc.parent,
        rustc.resolve(strict=True).parent,
        protoc.parent,
        protoc.resolve(strict=True).parent,
        Path("/usr/bin"),
        Path("/bin"),
    ):
        value = os.fspath(directory)
        if value not in path_entries:
            path_entries.append(value)
    return {
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(home),
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_PROXY": "*",
        "PATH": os.pathsep.join(path_entries),
        "PROTOC": str(protoc),
        "RUSTC": str(rustc),
        "RUSTUP_HOME": str(rustup_home),
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "ZERO_AR_DATE": "1",
    }


def _default_crate_builder(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltCrate:
    cargo = _secure_executable(arguments.cargo, "cargo")
    rustc = _secure_executable(arguments.rustc, "rustc")
    local_registry_tool = _secure_executable(
        arguments.cargo_local_registry, "cargo-local-registry"
    )
    protoc = _secure_executable(arguments.protoc, "protoc")
    rustup_home = _owned_directory(
        Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup")), "RUSTUP_HOME"
    )
    cargo_cache = _owned_directory(
        arguments.cargo_cache
        or Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")),
        "Cargo dependency cache",
    )

    registry = scratch / "registry"
    sync_home = scratch / "sync-home"
    sync_tmp = scratch / "sync-tmp"
    sync_home.mkdir(mode=0o700)
    sync_tmp.mkdir(mode=0o700)
    sync_environment = {
        "CARGO_HOME": str(cargo_cache),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "HOME": str(sync_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(
            [
                str(local_registry_tool.parent),
                str(cargo.parent),
                str(cargo.resolve(strict=True).parent),
                "/usr/bin",
                "/bin",
            ]
        ),
        "RUSTUP_HOME": str(rustup_home),
        "TMPDIR": str(sync_tmp),
        "TZ": "UTC",
    }
    _run_checked(
        [
            str(local_registry_tool),
            "sync",
            "--quiet",
            str(configuration.root / "Cargo.lock"),
            str(registry),
        ],
        cwd=configuration.root,
        environment=sync_environment,
        timeout=300,
        label="offline locked Cargo dependency registry sync",
    )
    dependency_registry = _registry_identity(registry)

    cargo_home = scratch / "cargo-home"
    _cargo_config(cargo_home, registry)
    environment = _base_environment(
        scratch, cargo_home, rustup_home, cargo, rustc, protoc, epoch
    )
    cargo_identity = (
        _run_checked(
            [str(cargo), "-V"],
            cwd=configuration.root,
            environment=environment,
            timeout=30,
            label="Cargo identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    rustc_identity = (
        _run_checked(
            [str(rustc), "-vV"],
            cwd=configuration.root,
            environment=environment,
            timeout=30,
            label="rustc identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    registry_tool_identity = (
        _run_checked(
            [str(local_registry_tool), "--version"],
            cwd=configuration.root,
            environment=sync_environment,
            timeout=30,
            label="cargo-local-registry identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    protoc_identity = (
        _run_checked(
            [str(protoc), "--version"],
            cwd=configuration.root,
            environment=environment,
            timeout=30,
            label="protoc identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if (
        re.fullmatch(
            r"cargo 1\.92\.0 \([0-9a-f]+ [0-9]{4}-[0-9]{2}-[0-9]{2}\)", cargo_identity
        )
        is None
        or "release: 1.92.0" not in rustc_identity.splitlines()
        or f"host: {TARGET_TRIPLE}" not in rustc_identity.splitlines()
        or registry_tool_identity != "cargo-local-registry 0.2.12"
        or re.fullmatch(r"libprotoc [0-9]+(?:\.[0-9]+)+", protoc_identity) is None
    ):
        raise ReleaseError("Rust SDK build tool cohort differs from the frozen profile")

    target_package = Path(environment["CARGO_TARGET_DIR"]) / "package"
    records: list[dict[str, object]] = []
    raw_sdk: Path | None = None
    raw_sdk_manifest: dict[str, Any] | None = None
    for specification in PACKAGE_SPECS:
        version = _package_version(specification, configuration.version)
        _run_checked(
            [
                str(cargo),
                "package",
                "--locked",
                "--allow-dirty",
                "--offline",
                "--no-verify",
                "-p",
                specification.name,
            ],
            cwd=configuration.root,
            environment=environment,
            timeout=600,
            label=f"Cargo package {specification.name}",
        )
        crate_path = target_package / f"{specification.name}-{version}.crate"
        manifest = _normalized_manifest(crate_path, specification.name, version)
        if specification.name == "cigar-sdk":
            raw_sdk = crate_path
            raw_sdk_manifest = manifest
            break
        records.append(_add_to_registry(registry, crate_path, manifest))

    if raw_sdk is None or raw_sdk_manifest is None:
        raise ReleaseError("Cargo did not produce the Rust SDK package")
    raw_payload = _read_stable_file(raw_sdk, MAX_ARCHIVE_BYTES, "raw Cargo SDK crate")
    entries = _read_sdk_crate(raw_sdk, configuration, source)
    canonical_root = scratch / "canonical-package"
    canonical_root.mkdir(mode=0o700)
    canonical = canonical_root / configuration.filename
    _write_canonical_crate(canonical, entries, epoch)
    canonical_manifest = tomllib.loads(
        next(
            entry.payload
            for entry in entries
            if entry.path == f"{configuration.crate_root}/Cargo.toml"
        ).decode("utf-8")
    )
    records.append(_add_to_registry(registry, canonical, canonical_manifest))

    extracted_root = _extract_crate(
        entries, scratch / "extracted", configuration.crate_root
    )
    validation_target = scratch / "validation-target"
    validation_target.mkdir(mode=0o700)
    validation_environment = dict(environment)
    validation_environment["CARGO_TARGET_DIR"] = str(validation_target)
    quickstart_output = (
        _run_checked(
            [
                str(cargo),
                "run",
                "--locked",
                "--offline",
                "--no-default-features",
                "--manifest-path",
                str(extracted_root / "Cargo.toml"),
                "--example",
                "quickstart",
            ],
            cwd=extracted_root,
            environment=validation_environment,
            timeout=1200,
            label="extracted Rust SDK quickstart",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if quickstart_output != EXPECTED_QUICKSTART_IDENTITY:
        raise ReleaseError("extracted Rust SDK quickstart identity differs")
    _run_checked(
        [
            str(cargo),
            "test",
            "--locked",
            "--offline",
            "--no-default-features",
            "--manifest-path",
            str(extracted_root / "Cargo.toml"),
            "--lib",
        ],
        cwd=extracted_root,
        environment=validation_environment,
        timeout=1200,
        label="extracted Rust SDK library tests",
    )

    consumer = scratch / "consumer"
    (consumer / "src").mkdir(parents=True, mode=0o700)
    (consumer / "Cargo.toml").write_text(
        '[package]\nname = "cigar-sdk-development-consumer"\nversion = "0.0.0"\n'
        'edition = "2024"\nrust-version = "1.92"\npublish = false\n\n'
        f'[dependencies]\ncigar-sdk = "={configuration.version}"\n',
        encoding="utf-8",
    )
    (consumer / "src/main.rs").write_text(
        'fn main() { assert_eq!(cigar_sdk::CONTEXT_ABI, "cigar.context.v1"); }\n',
        encoding="utf-8",
    )
    for path in (consumer / "Cargo.toml", consumer / "src/main.rs"):
        path.chmod(0o600)
    _run_checked(
        [
            str(cargo),
            "check",
            "--offline",
            "--manifest-path",
            str(consumer / "Cargo.toml"),
        ],
        cwd=consumer,
        environment=validation_environment,
        timeout=1800,
        label="local-registry default-feature Rust SDK consumer",
    )

    if len(records) != len(PACKAGE_SPECS):
        raise ReleaseError("Rust SDK local publication chain is incomplete")
    expected_identities = [
        (spec.name, _package_version(spec, configuration.version))
        for spec in PACKAGE_SPECS
    ]
    if [
        (record.get("name"), record.get("version")) for record in records
    ] != expected_identities:
        raise ReleaseError("Rust SDK local publication chain order differs")

    return BuiltCrate(
        entries=entries,
        raw_cargo_package_sha256=sha256_bytes(raw_payload),
        raw_cargo_package_bytes=len(raw_payload),
        package_chain=tuple(records),
        dependency_registry=dependency_registry,
        tools=(
            _tool_record(cargo, "cargo", cargo_identity),
            _tool_record(rustc, "rustc", rustc_identity),
            _tool_record(
                local_registry_tool, "cargo-local-registry", registry_tool_identity
            ),
            _tool_record(protoc, "protoc", protoc_identity),
        ),
        validation={
            "schema_version": "cigar.rust-sdk-crate-build-validation.v1",
            "status": "passed-local-registry",
            "offline": True,
            "external_publish_performed": False,
            "artifact_under_test": "canonical-cargo-generated-crate",
            "checks": {
                "cargo-package-chain": "passed",
                "extracted-library-tests-no-default-features": "passed",
                "extracted-quickstart-no-default-features": "passed",
                "local-registry-default-feature-consumer": "passed",
            },
            "quickstart_identity": quickstart_output,
            "workspace_integration_tests": {
                "executed": False,
                "reason": "not packaged; repository integration tests depend on external shared schemas and fixtures",
            },
        },
    )


def _validate_built_crate(
    built: BuiltCrate,
    configuration: BuildConfiguration,
    source: dict[str, Any],
) -> None:
    if not isinstance(built, BuiltCrate):
        raise ReleaseError("Rust SDK crate builder returned an invalid result")
    paths: set[str] = set()
    aliases: set[str] = set()
    for entry in built.entries:
        path = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", path).casefold()
        if path in paths or alias in aliases:
            raise ReleaseError(f"Rust SDK crate result path collides: {path}")
        if (
            entry.mode != 0o644
            or not entry.payload
            or len(entry.payload) > MAX_ARCHIVE_MEMBER_BYTES
        ):
            raise ReleaseError(f"Rust SDK crate result entry is invalid: {path}")
        paths.add(path)
        aliases.add(alias)
    expected = {
        f"{configuration.crate_root}/Cargo.toml",
        f"{configuration.crate_root}/Cargo.toml.orig",
        f"{configuration.crate_root}/Cargo.lock",
        f"{configuration.crate_root}/.cargo_vcs_info.json",
        *(
            f"{configuration.crate_root}/{relative}"
            for relative in SDK_SOURCE_PATHS
            if relative != "Cargo.toml"
        ),
    }
    if paths != expected:
        raise ReleaseError("Rust SDK crate result inventory differs from review")
    by_path = {entry.path: entry.payload for entry in built.entries}
    for relative, source_payload in configuration.sdk_sources.items():
        packaged = (
            f"{configuration.crate_root}/Cargo.toml.orig"
            if relative == "Cargo.toml"
            else f"{configuration.crate_root}/{relative}"
        )
        if by_path[packaged] != source_payload:
            raise ReleaseError(f"Rust SDK crate result source differs: {relative}")
    try:
        normalized = tomllib.loads(
            by_path[f"{configuration.crate_root}/Cargo.toml"].decode("utf-8")
        )
        packaged_lock = tomllib.loads(
            by_path[f"{configuration.crate_root}/Cargo.lock"].decode("utf-8")
        )
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("Rust SDK crate result Cargo metadata is invalid") from error
    package = normalized.get("package")
    if (
        not isinstance(package, dict)
        or package.get("name") != "cigar-sdk"
        or package.get("version") != configuration.version
        or package.get("publish") != ["crates-io"]
    ):
        raise ReleaseError("Rust SDK crate result normalized identity differs")
    normalized_dependencies = {row["name"] for row in _dependency_rows(normalized)}
    if not {"cigar-api", "cigar-canon", "cigar-daemon", "cigar-protocol"}.issubset(
        normalized_dependencies
    ):
        raise ReleaseError(
            "Rust SDK crate result normalized dependencies are incomplete"
        )
    packaged_packages = packaged_lock.get("package")
    if (
        packaged_lock.get("version") != 4
        or not isinstance(packaged_packages, list)
        or not SDK_LOCK_REQUIRED_PACKAGE_NAMES.issubset(
            {item.get("name") for item in packaged_packages if isinstance(item, dict)}
        )
    ):
        raise ReleaseError("Rust SDK crate result Cargo.lock is incomplete")
    release = load_json_bytes(
        by_path[f"{configuration.crate_root}/release.json"],
        "built Rust SDK release.json",
    )
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": "cigar-sdk",
        "version": configuration.version,
        "context_abi": configuration.context_abi,
    }:
        raise ReleaseError("Rust SDK crate result release identity differs")
    if (
        not isinstance(built.raw_cargo_package_bytes, int)
        or isinstance(built.raw_cargo_package_bytes, bool)
        or built.raw_cargo_package_bytes <= 0
        or re.fullmatch(r"[0-9a-f]{64}", built.raw_cargo_package_sha256) is None
    ):
        raise ReleaseError("raw Cargo package identity is incomplete")
    if len(built.package_chain) != len(PACKAGE_SPECS):
        raise ReleaseError("Rust SDK package chain evidence is incomplete")
    for record, specification in zip(built.package_chain, PACKAGE_SPECS, strict=True):
        if (
            set(record) != {"name", "version", "sha256", "bytes"}
            or record.get("name") != specification.name
            or record.get("version")
            != _package_version(specification, configuration.version)
            or re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))) is None
            or not isinstance(record.get("bytes"), int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] <= 0
        ):
            raise ReleaseError("Rust SDK package chain evidence is invalid")
    registry = built.dependency_registry
    if (
        not isinstance(registry, dict)
        or registry.get("schema_version")
        != "cigar.cargo-dependency-registry-snapshot.v1"
        or registry.get("source") != "workspace-Cargo.lock-and-owner-cache"
        or registry.get("offline") is not True
        or not isinstance(registry.get("file_count"), int)
        or registry["file_count"] <= 0
        or not isinstance(registry.get("bytes"), int)
        or registry["bytes"] <= 0
        or re.fullmatch(r"[0-9a-f]{64}", str(registry.get("tree_sha256"))) is None
    ):
        raise ReleaseError("Cargo dependency registry evidence is invalid")
    if not built.tools or any(
        not isinstance(record, dict)
        or set(record) != {"name", "version", "sha256", "bytes"}
        or not isinstance(record.get("name"), str)
        or not record["name"]
        or not isinstance(record.get("version"), str)
        or not record["version"]
        or re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))) is None
        or not isinstance(record.get("bytes"), int)
        or isinstance(record["bytes"], bool)
        or record["bytes"] <= 0
        for record in built.tools
    ):
        raise ReleaseError("Rust SDK build tool evidence is incomplete")
    validation = built.validation
    if (
        not isinstance(validation, dict)
        or validation.get("schema_version")
        != "cigar.rust-sdk-crate-build-validation.v1"
        or validation.get("status") != "passed-local-registry"
        or validation.get("offline") is not True
        or validation.get("external_publish_performed") is not False
        or validation.get("artifact_under_test") != "canonical-cargo-generated-crate"
        or validation.get("quickstart_identity") != EXPECTED_QUICKSTART_IDENTITY
        or validation.get("checks")
        != {
            "cargo-package-chain": "passed",
            "extracted-library-tests-no-default-features": "passed",
            "extracted-quickstart-no-default-features": "passed",
            "local-registry-default-feature-consumer": "passed",
        }
        or validation.get("workspace_integration_tests")
        != {
            "executed": False,
            "reason": "not packaged; repository integration tests depend on external shared schemas and fixtures",
        }
    ):
        raise ReleaseError("Rust SDK build validation evidence is incomplete")

    vcs = load_json_bytes(
        by_path[f"{configuration.crate_root}/.cargo_vcs_info.json"],
        "built Rust SDK .cargo_vcs_info.json",
    )
    if vcs != _expected_vcs_document(source):
        raise ReleaseError("built Rust SDK VCS metadata is not source-bound")


def _entry_tree(entries: tuple[CrateEntry, ...]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item.path.encode("utf-8")):
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(entry.payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(f"{entry.mode:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entry.payload).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def produce(
    arguments: argparse.Namespace,
    *,
    crate_builder: CrateBuilder = _default_crate_builder,
) -> dict[str, Any]:
    root = arguments.root.resolve(strict=True)
    host = _require_host()
    evidence_root = _selected_evidence_directory(arguments)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    configuration = _load_configuration(root)
    source_before = _source_identity(root)

    workspace = EvidenceWorkspace.create(evidence_root, repository_root=root)
    try:
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(prefix="cigar-rust-sdk-crate-build-") as raw:
            scratch = Path(raw).resolve(strict=True)
            # Unpublished crate bytes and the private local registry must remain owner-only.
            # fmt: off
            os.chmod(scratch, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            # fmt: on
            built = crate_builder(
                configuration, source_before, epoch, scratch, arguments
            )
            _validate_built_crate(built, configuration, source_before)
            if _source_identity(root) != source_before:
                raise ReleaseError(
                    "Rust SDK crate build source changed during construction"
                )
            if _authority_digests(root) != configuration.authority:
                raise ReleaseError(
                    "Rust SDK crate build authority changed during construction"
                )

            staged_archive = scratch / configuration.filename
            _write_canonical_crate(staged_archive, built.entries, epoch)
            validated = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "staged Rust SDK crate"
            )
            validated_bytes = len(validated)
            validated_sha256 = sha256_bytes(validated)
            verification = verify_package(
                staged_archive,
                configuration.contract_path,
                configuration.version,
                configuration.context_abi,
                epoch,
            )
            if verification.get("status") != "passed":
                raise ReleaseError(
                    "Rust SDK crate package-contract verification failed"
                )
            if _source_identity(root) != source_before:
                raise ReleaseError(
                    "Rust SDK crate build source changed during verification"
                )
            if _authority_digests(root) != configuration.authority:
                raise ReleaseError(
                    "Rust SDK crate build authority changed during verification"
                )
            verified = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "verified Rust SDK crate"
            )
            if (
                len(verified) != validated_bytes
                or sha256_bytes(verified) != validated_sha256
            ):
                raise ReleaseError("Rust SDK crate changed during package verification")
            archive_reference = workspace.attach_file(
                staged_archive,
                configuration.filename,
                expected_sha256=validated_sha256,
                expected_bytes=validated_bytes,
            )

        dependency_packages = [
            {"name": record["name"], "version": record["version"]}
            for record in built.package_chain[:-1]
        ]
        receipt = {
            "schema_version": "cigar.development-rust-sdk-crate-build.v1",
            "status": "built-unqualified",
            "artifact_id": ARTIFACT_ID,
            "target": TARGET_TRIPLE,
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": epoch,
            "source": source_before,
            "host": host,
            "archive": archive_reference.as_dict(),
            "contract": {
                "path": configuration.contract_relative,
                "sha256": configuration.authority[configuration.contract_relative][
                    "sha256"
                ],
            },
            "authority": configuration.authority,
            "producer_declared_in_artifact_matrix": configuration.producer_declared,
            "payload_file_count": len(built.entries),
            "payload_tree_sha256": _entry_tree(built.entries),
            "cargo_package": {
                "generated_by_cargo": True,
                "canonical_repack": True,
                "raw_sha256": built.raw_cargo_package_sha256,
                "raw_bytes": built.raw_cargo_package_bytes,
                "canonical_payloads_equal_raw": True,
            },
            "package_chain": list(built.package_chain),
            "dependency_registry": built.dependency_registry,
            "build_tools": list(built.tools),
            "build_validation": built.validation,
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "unpublished_dependency_chain": {
                "required_before_crates_io_install": dependency_packages,
                "package_count": len(dependency_packages),
                "resolved_only_from_private_local_registry": True,
                "crates_io_resolution_verified": False,
            },
            "claims": {
                "development_build": True,
                "cargo_package_generated": True,
                "package_contract_verified": True,
                "registry_signature": False,
                "distribution_signed": False,
                "signed": False,
                "installable": False,
                "installed_compatibility": False,
                "clean_install_from_crates_io": False,
                "crates_io_dependency_resolution": False,
                "crates_io_published": False,
                "published": False,
                "qualified": False,
                "supported": False,
                "release": False,
            },
        }
        workspace.write_json(BUILD_RECEIPT, receipt)
        workspace.read_files(
            {configuration.filename, BUILD_RECEIPT}, strict_read_only=True
        )
        return receipt
    finally:
        workspace.close()


def main() -> int:
    receipt = produce(parse_arguments())
    print(canonical_json_bytes(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, OSError, ReleaseError) as error:
        raise SystemExit(f"Rust SDK development build failed: {error}") from error
