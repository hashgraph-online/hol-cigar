#!/usr/bin/env python3
"""Build the unsigned development CIGAR archive for native Apple-silicon macOS."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    expand_files,
    git_state,
    load_json,
    load_json_bytes,
    normalized_mode,
    process_failure_summary,
    require_source_date_epoch,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
)
from verify_package import verify as verify_package


ARTIFACT_ID = "macos-runtime-aarch64"
DEVELOPMENT_ARTIFACT_ID = "cli-daemon-macos-aarch64"
TARGET_TRIPLE = "aarch64-apple-darwin"
RUNTIME_PROFILE = "cigar.full.local-macos-aarch64.v1"
BUILD_RECEIPT = "native-build-receipt.json"
DEVELOPMENT_BUILD_RECEIPT = "macos-aarch64-development-build.json"
MACOS_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
MACOS_NO_EGRESS_POLICY = "(version 1)(allow default)(deny network*)"
MACOS_NO_EGRESS_ENFORCEMENT = "darwin-sandbox-exec-deny-network-v1"
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 512 * 1024 * 1024
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEVELOPMENT_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/local-archives.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/macos-runtime-archive.v1.json",
    "adapters/claude-code/package-manifest.json",
)
AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/local-archives.v1.json",
    "packaging/honey/release-requirements.v1.json",
    "packaging/contracts/macos-runtime-archive.v1.json",
    "adapters/claude-code/package-manifest.json",
)
ASSET_PATHS = {
    "LICENSE": "LICENSE",
    "NOTICE": "NOTICE",
    "share/man/man1/cigar.1": "crates/cigar-cli/man/cigar.1",
    "completions/cigar.bash": "crates/cigar-cli/completions/cigar.bash",
    "completions/_cigar": "crates/cigar-cli/completions/_cigar",
    "completions/cigar.fish": "crates/cigar-cli/completions/cigar.fish",
}
SOURCE_INCLUDES = (
    ".cargo/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "clippy.toml",
    "crates/**",
    "conformance/runner/**",
    "sdk/rust/**",
    "schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json",
    "spec/api/**",
    "adapters/claude-code/**",
    "scripts/release/build_macos_aarch64_archive.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/verify_package.py",
    "LICENSE",
    "NOTICE",
)
SOURCE_EXCLUDES = (
    "**/.DS_Store",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/target/**",
)


@dataclass(frozen=True)
class PackageEntry:
    path: str
    payload: bytes
    mode: int


@dataclass(frozen=True)
class SourceInput:
    """One immutable source member used for identity and private-tree construction."""

    path: str
    payload: bytes
    mode: int


@dataclass(frozen=True)
class BuildConfiguration:
    root: Path
    version: str
    context_abi: str
    filename: str
    artifact_id: str
    receipt_name: str
    release_state: str
    contract_path: Path
    contract_relative: str
    authority: dict[str, dict[str, object]]
    assets: dict[str, bytes]


@dataclass(frozen=True)
class BuiltRuntime:
    cigar: bytes
    cigard: bytes
    cigar_mcp: bytes
    cigar_claude_hook: bytes
    cigar_version: dict[str, Any]
    cigard_version: dict[str, Any]
    cigar_mcp_probe: dict[str, Any]
    cigar_claude_hook_probe: dict[str, Any]
    generated_assets: dict[str, bytes]
    tools: tuple[dict[str, object], ...]


RuntimeBuilder = Callable[
    [BuildConfiguration, dict[str, Any], int, Path, argparse.Namespace], BuiltRuntime
]


def _runtime_build_command(cargo: Path) -> list[str]:
    """Return the closed full-product build command for the native runtime."""

    return [
        str(cargo),
        "build",
        "--locked",
        "--offline",
        "--release",
        "--target",
        TARGET_TRIPLE,
        "--no-default-features",
        "--features",
        "full",
        "-p",
        "cigar-cli",
        "-p",
        "cigar-daemon",
        "-p",
        "cigar-mcp",
        "-p",
        "cigar-claude-hook",
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
    parser.add_argument("--protoc", type=Path)
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
            "the development native producer requires Apple-silicon macOS; "
            f"observed platform={sys.platform} architecture={machine}"
        )
    return {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": platform.mac_ver()[0],
    }


def _read_stable_file(path: Path, maximum: int, label: str) -> bytes:
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
            or before.st_size <= 0
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


def _authority_digests(
    root: Path, paths: tuple[str, ...] = AUTHORITY_PATHS
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for relative in paths:
        path = root.joinpath(*relative.split("/"))
        payload = _read_stable_file(path, 16 * 1024 * 1024, relative)
        records[relative] = {
            "sha256": sha256_bytes(payload),
            "bytes": len(payload),
        }
    return records


def _load_configuration(root: Path) -> BuildConfiguration:
    root = root.resolve(strict=True)
    product = load_json(root / "packaging/product-version.v1.json")
    honey = (
        isinstance(product, dict)
        and product.get("release_state") == "developer-preview"
        and product.get("channel") == "honey"
    )
    authority_paths = AUTHORITY_PATHS if honey else DEVELOPMENT_AUTHORITY_PATHS
    authority = _authority_digests(root, authority_paths)
    matrix_relative = (
        "packaging/honey/artifact-matrix.v1.json"
        if honey
        else "packaging/artifact-matrix.v1.json"
    )
    archives_relative = (
        "packaging/honey/local-archives.v1.json"
        if honey
        else "packaging/local-archives.v1.json"
    )
    profile_relative = (
        "packaging/honey/capability-profile.v1.json"
        if honey
        else "packaging/development/local-macos-aarch64.v1.json"
    )
    matrix = load_json(root / matrix_relative)
    archives = load_json(root / archives_relative)
    profile = load_json(root / profile_relative)
    contract = load_json(root / "packaging/contracts/macos-runtime-archive.v1.json")

    development_identity = (
        isinstance(product, dict)
        and product.get("release_state") == "development"
        and product.get("channel") == "development"
        and product.get("tag") is None
    )
    honey_identity = (
        honey
        and isinstance(product, dict)
        and isinstance(product.get("version"), str)
        and product.get("tag") == f"v{product['version']}"
    )
    if (
        not isinstance(product, dict)
        or product.get("schema_version") != "cigar.product-version.v1"
        or not (development_identity or honey_identity)
        or product.get("prerelease") is not True
        or product.get("published") is not False
        or product.get("supported") is not False
        or not isinstance(product.get("version"), str)
        or product.get("context_abi") != "cigar.context.v1"
    ):
        raise ReleaseError(
            "product version authority is not an unpublished development or Honey identity"
        )
    version = product["version"]
    context_abi = product["context_abi"]
    artifact_id = ARTIFACT_ID if honey else DEVELOPMENT_ARTIFACT_ID
    receipt_name = BUILD_RECEIPT if honey else DEVELOPMENT_BUILD_RECEIPT
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version")
        != ("cigar.honey.artifact-matrix.v1" if honey else "cigar.artifact-matrix.v1")
        or matrix.get("release_state")
        != ("developer-preview" if honey else "development")
        or matrix.get("product_version") != version
        or matrix.get("context_abi") != context_abi
        or not isinstance(matrix.get("artifacts"), list)
    ):
        raise ReleaseError(
            "artifact matrix is stale relative to product version authority"
        )
    matching = [
        entry
        for entry in matrix["artifacts"]
        if isinstance(entry, dict) and entry.get("id") == artifact_id
    ]
    if len(matching) != 1:
        raise ReleaseError(
            f"artifact matrix must contain exactly one {artifact_id} row"
        )
    artifact = matching[0]
    expected_filename = f"cigar-{version}-{TARGET_TRIPLE}.tar.gz"
    if honey:
        expected_receipt = {
            "filename": receipt_name,
            "required": True,
            "schema_version": "cigar.development-native-archive-build.v1",
        }
        if (
            artifact.get("kind") != "native-runtime-archive"
            or artifact.get("filename") != expected_filename
            or artifact.get("contract")
            != "packaging/contracts/macos-runtime-archive.v1.json"
            or artifact.get("producer")
            != ["python3", "scripts/release/build_macos_aarch64_archive.py"]
            or artifact.get("workspace") != "native"
            or artifact.get("generated_by_assembler") is not False
            or artifact.get("public_attachment") is not True
            or artifact.get("required") is not True
            or artifact.get("receipt") != expected_receipt
        ):
            raise ReleaseError(
                "Honey macOS runtime artifact row is incomplete or stale"
            )
    else:
        expected_producer = "python3 scripts/release/build_macos_aarch64_archive.py"
        if (
            artifact.get("kind") != "binary-archive"
            or artifact.get("platform") != TARGET_TRIPLE
            or artifact.get("filename") != expected_filename
            or artifact.get("contract") != "contracts/macos-runtime-archive.v1.json"
            or artifact.get("producer") != expected_producer
            or artifact.get("signature_purpose") != "macos-runtime-distribution"
            or artifact.get("install_target") != "bin"
            or artifact.get("evidence_map")
            != [
                "package-contract",
                "installed-artifact",
                "unprivileged",
                "offline",
                "upgrade",
                "uninstall",
                "sbom",
                "license",
                "signature",
                "platform-signing",
                "notarization",
                "provenance",
            ]
        ):
            raise ReleaseError("macOS arm64 artifact row is incomplete or stale")
    if (
        not isinstance(archives, dict)
        or archives.get("schema_version") != "cigar.local-archives.v1"
        or archives.get("product_version") != version
        or archives.get("context_abi") != context_abi
    ):
        raise ReleaseError("local archive authority is stale")
    if honey:
        identity = profile.get("identity") if isinstance(profile, dict) else None
        platform_profile = (
            profile.get("platform") if isinstance(profile, dict) else None
        )
        artifact_ids = (
            profile.get("artifact_ids") if isinstance(profile, dict) else None
        )
        if (
            not isinstance(profile, dict)
            or profile.get("schema_version") != "cigar.honey.capability-profile.v1"
            or not isinstance(identity, dict)
            or identity.get("product_version") != version
            or identity.get("context_abi") != context_abi
            or identity.get("release_state") != "developer-preview"
            or identity.get("supported") is not False
            or identity.get("production_qualified") is not False
            or not isinstance(platform_profile, dict)
            or platform_profile.get("host_os") != "macos"
            or platform_profile.get("host_arch") != "arm64"
            or platform_profile.get("target_triple") != TARGET_TRIPLE
            or not isinstance(artifact_ids, list)
            or artifact_id not in artifact_ids
        ):
            raise ReleaseError("Honey macOS capability profile is stale")
    else:
        if not isinstance(profile, dict):
            raise ReleaseError("development macOS arm64 profile is malformed")
        selected = profile.get("selected_artifacts")
        missing = profile.get("missing_artifacts")
        selected_rows = (
            [
                row
                for row in selected
                if isinstance(row, dict) and row.get("id") == artifact_id
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
            or len(selected_rows) != 1
            or selected_rows[0].get("status") != "planned"
            or selected_rows[0].get("built") is not False
            or selected_rows[0].get("qualified") is not False
            or missing != []
        ):
            raise ReleaseError(
                "development macOS arm64 profile does not remain planned, unclaimed, and sidecar-complete"
            )
    required_allow = {
        "RELEASE-METADATA.json",
        "bin/cigar",
        "bin/cigard",
        "bin/cigar-mcp",
        "bin/cigar-claude-hook",
        "share/man/man1/cigar.1",
        "completions/**",
        "LICENSE",
        "NOTICE",
        "SHA256SUMS",
    }
    required_members = {
        "RELEASE-METADATA.json",
        "bin/cigar",
        "bin/cigard",
        "bin/cigar-mcp",
        "bin/cigar-claude-hook",
        "share/man/man1/cigar.1",
        "completions/cigar.bash",
        "completions/_cigar",
        "completions/cigar.fish",
        "LICENSE",
        "NOTICE",
        "SHA256SUMS",
    }
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id") != "macos-runtime-archive-v1"
        or contract.get("formats") != ["tar.gz"]
        or not isinstance(contract.get("allow"), list)
        or set(contract["allow"]) != required_allow
        or not isinstance(contract.get("required"), list)
        or set(contract["required"]) != required_members
        or contract.get("checksum_manifest")
        != {"path": "SHA256SUMS", "scope": "all-payload-files"}
        or contract.get("symlinks") != "forbid"
        or contract.get("content_scan") is not True
    ):
        raise ReleaseError(
            "macOS runtime archive contract does not cover the native payload"
        )

    assets: dict[str, bytes] = {}
    for destination, relative in ASSET_PATHS.items():
        assets[destination] = _read_stable_file(
            root.joinpath(*relative.split("/")), 16 * 1024 * 1024, relative
        )
        if b"\r" in assets[destination]:
            raise ReleaseError(f"packaged text asset is not LF-only: {relative}")
    return BuildConfiguration(
        root=root,
        version=version,
        context_abi=context_abi,
        filename=expected_filename,
        artifact_id=artifact_id,
        receipt_name=receipt_name,
        release_state=("developer-preview" if honey else "development"),
        contract_path=root / "packaging/contracts/macos-runtime-archive.v1.json",
        contract_relative="packaging/contracts/macos-runtime-archive.v1.json",
        authority=authority,
        assets=assets,
    )


def _source_snapshot(root: Path) -> tuple[SourceInput, ...]:
    files = expand_files(root, SOURCE_INCLUDES, SOURCE_EXCLUDES)
    if not files:
        raise ReleaseError("native build source inventory is empty")
    snapshot: list[SourceInput] = []
    aggregate = 0
    for relative, path in files:
        payload = _read_stable_file(path, MAX_SOURCE_FILE_BYTES, relative)
        aggregate += len(payload)
        if aggregate > MAX_SOURCE_TOTAL_BYTES:
            raise ReleaseError(
                "native build source snapshot exceeds the aggregate limit"
            )
        snapshot.append(
            SourceInput(
                path=relative,
                payload=payload,
                mode=normalized_mode(relative),
            )
        )
    return tuple(snapshot)


def _source_tree_digest(snapshot: tuple[SourceInput, ...]) -> str:
    digest = hashlib.sha256()
    for entry in snapshot:
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(entry.payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(f"{entry.mode:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entry.payload).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def _source_identity(
    root: Path, snapshot: tuple[SourceInput, ...] | None = None
) -> dict[str, Any]:
    selected = snapshot if snapshot is not None else _source_snapshot(root)
    identity = git_state(root, _source_tree_digest(selected))
    if (
        identity.get("committed") is not True
        or not isinstance(identity.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", identity["revision"]) is None
        or not isinstance(identity.get("clean"), bool)
        or not isinstance(identity.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["tree_sha256"]) is None
    ):
        raise ReleaseError("native build requires a committed Git source identity")
    return identity


def _write_source_snapshot(
    snapshot: tuple[SourceInput, ...], destination: Path
) -> None:
    destination.mkdir(mode=0o700)
    for entry in snapshot:
        relative = safe_relative_path(entry.path)
        output = destination.joinpath(*relative.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            entry.mode,
        )
        try:
            written = 0
            while written < len(entry.payload):
                count = os.write(descriptor, entry.payload[written:])
                if count <= 0:
                    raise ReleaseError(
                        f"native source snapshot write made no progress: {relative}"
                    )
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(output, entry.mode)


def _verify_source_snapshot(root: Path, snapshot: tuple[SourceInput, ...]) -> None:
    files = expand_files(root, SOURCE_INCLUDES, SOURCE_EXCLUDES)
    if tuple(relative for relative, _path in files) != tuple(
        entry.path for entry in snapshot
    ):
        raise ReleaseError("native build source changed after its immutable snapshot")
    for entry, (relative, path) in zip(snapshot, files, strict=True):
        if (
            relative != entry.path
            or normalized_mode(relative) != entry.mode
            or _read_stable_file(path, MAX_SOURCE_FILE_BYTES, relative) != entry.payload
        ):
            raise ReleaseError(
                "native build source changed after its immutable snapshot"
            )


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


def _private_tool_directory(raw: str | None, fallback: Path, label: str) -> Path:
    selected = Path(raw).expanduser() if raw else fallback
    try:
        resolved = selected.resolve(strict=True)
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


def _cargo_environment(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    cargo: Path,
    rustc: Path,
    protoc: Path,
) -> dict[str, str]:
    target = scratch / "target"
    home = scratch / "home"
    temporary = scratch / "tmp"
    for directory in (target, home, temporary):
        directory.mkdir(mode=0o700)
    cargo_home = _private_tool_directory(
        os.environ.get("CARGO_HOME"), Path.home() / ".cargo", "CARGO_HOME"
    )
    rustup_home = _private_tool_directory(
        os.environ.get("RUSTUP_HOME"), Path.home() / ".rustup", "RUSTUP_HOME"
    )
    owner_home = Path.home().resolve(strict=True)
    remap_candidates = (
        (configuration.root, "/usr/src/cigar"),
        (scratch, "/usr/src/cigar-build"),
        (cargo_home, "/usr/src/cargo-home"),
        (rustup_home, "/usr/src/rustup-home"),
        (owner_home, "/usr/src/owner-home"),
    )
    remap_flags: list[str] = []
    remapped_sources: set[Path] = set()
    for remap_source, destination in remap_candidates:
        if remap_source in remapped_sources:
            continue
        source_text = os.fspath(remap_source)
        if "\x1f" in source_text or "\x1f" in destination:
            raise ReleaseError("compiler path remapping contains an invalid separator")
        remapped_sources.add(remap_source)
        remap_flags.append(f"--remap-path-prefix={source_text}={destination}")
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
        text = str(directory)
        if text not in path_entries:
            path_entries.append(text)
    return {
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(remap_flags),
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "CIGAR_SOURCE_REVISION": str(source["revision"]),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "PATH": os.pathsep.join(path_entries),
        "PROTOC": str(protoc),
        "RUSTC": str(rustc),
        "RUSTUP_HOME": str(rustup_home),
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "ZERO_AR_DATE": "1",
    }


def _run_checked(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    label: str,
    maximum: int = MAX_COMMAND_OUTPUT,
) -> bytes:
    sandbox = _validated_macos_sandbox()
    try:
        result = run_bounded(
            [str(sandbox), "-p", MACOS_NO_EGRESS_POLICY, *command],
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


def _validated_macos_sandbox() -> Path:
    """Return the fixed root-controlled Seatbelt launcher for build subprocesses."""

    try:
        metadata = MACOS_SANDBOX_EXEC.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(
            "the fixed macOS no-egress sandbox launcher is unavailable"
        ) from error
    if (
        MACOS_SANDBOX_EXEC.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(MACOS_SANDBOX_EXEC, os.X_OK)
    ):
        raise ReleaseError(
            "the fixed macOS no-egress sandbox launcher is not root-controlled"
        )
    return MACOS_SANDBOX_EXEC


def _tool_record(path: Path, name: str, version: str) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    payload = _read_stable_file(resolved, 64 * 1024 * 1024, f"{name} executable")
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _version_document(
    binary: Path,
    arguments: list[str],
    environment: dict[str, str],
    root: Path,
    label: str,
) -> dict[str, Any]:
    payload = _run_checked(
        [str(binary), *arguments],
        cwd=root,
        environment=environment,
        timeout=30,
        label=f"{label} version probe",
        maximum=256 * 1024,
    )
    document = load_json_bytes(payload, f"{label} version probe")
    if not isinstance(document, dict):
        raise ReleaseError(f"{label} version probe is not an object")
    return document


def _default_runtime_builder(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltRuntime:
    cargo = _secure_executable(arguments.cargo, "cargo")
    rustc = _secure_executable(arguments.rustc, "rustc")
    protoc = _secure_executable(arguments.protoc, "protoc")
    environment = _cargo_environment(
        configuration, source, epoch, scratch, cargo, rustc, protoc
    )
    rustc_identity = _run_checked(
        [str(rustc), "-vV"],
        cwd=configuration.root,
        environment=environment,
        timeout=30,
        label="rustc identity",
        maximum=256 * 1024,
    ).decode("utf-8", errors="strict")
    cargo_identity = (
        _run_checked(
            [str(cargo), "-V"],
            cwd=configuration.root,
            environment=environment,
            timeout=30,
            label="cargo identity",
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
    if f"host: {TARGET_TRIPLE}" not in rustc_identity:
        raise ReleaseError("rustc host is not native aarch64-apple-darwin")
    _run_checked(
        _runtime_build_command(cargo),
        cwd=configuration.root,
        environment=environment,
        timeout=1_800,
        label="native macOS arm64 Cargo build",
    )
    binary_root = scratch / "target" / TARGET_TRIPLE / "release"
    cigar_path = binary_root / "cigar"
    cigard_path = binary_root / "cigard"
    cigar_mcp_path = binary_root / "cigar-mcp"
    cigar_claude_hook_path = binary_root / "cigar-claude-hook"
    runtime_environment = {
        "HOME": str(scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(scratch / "tmp"),
        "TZ": "UTC",
    }
    cigar_version = _version_document(
        cigar_path,
        ["--output", "json", "version"],
        runtime_environment,
        configuration.root,
        "cigar",
    )
    cigard_version = _version_document(
        cigard_path,
        ["--version"],
        runtime_environment,
        configuration.root,
        "cigard",
    )
    cigar_mcp_probe = load_json_bytes(
        _run_checked(
            [str(cigar_mcp_path), "schema-noop"],
            cwd=configuration.root,
            environment=runtime_environment,
            timeout=30,
            label="cigar-mcp schema probe",
            maximum=256 * 1024,
        ),
        "cigar-mcp schema probe",
    )
    cigar_claude_hook_probe = load_json_bytes(
        _run_checked(
            [str(cigar_claude_hook_path), "schema-noop"],
            cwd=configuration.root,
            environment=runtime_environment,
            timeout=30,
            label="cigar-claude-hook schema probe",
            maximum=256 * 1024,
        ),
        "cigar-claude-hook schema probe",
    )
    generated_assets = {
        "share/man/man1/cigar.1": _run_checked(
            [str(cigar_path), "man"],
            cwd=configuration.root,
            environment=runtime_environment,
            timeout=30,
            label="cigar manual generation",
            maximum=4 * 1024 * 1024,
        ),
        **{
            destination: _run_checked(
                [str(cigar_path), "completion", shell],
                cwd=configuration.root,
                environment=runtime_environment,
                timeout=30,
                label=f"cigar {shell} completion generation",
                maximum=4 * 1024 * 1024,
            )
            for shell, destination in (
                ("bash", "completions/cigar.bash"),
                ("zsh", "completions/_cigar"),
                ("fish", "completions/cigar.fish"),
            )
        },
    }
    return BuiltRuntime(
        cigar=_read_stable_file(cigar_path, MAX_BINARY_BYTES, "built cigar"),
        cigard=_read_stable_file(cigard_path, MAX_BINARY_BYTES, "built cigard"),
        cigar_mcp=_read_stable_file(
            cigar_mcp_path, MAX_BINARY_BYTES, "built cigar-mcp"
        ),
        cigar_claude_hook=_read_stable_file(
            cigar_claude_hook_path, MAX_BINARY_BYTES, "built cigar-claude-hook"
        ),
        cigar_version=cigar_version,
        cigard_version=cigard_version,
        cigar_mcp_probe=cigar_mcp_probe,
        cigar_claude_hook_probe=cigar_claude_hook_probe,
        generated_assets=generated_assets,
        tools=(
            _tool_record(cargo, "cargo", cargo_identity),
            _tool_record(protoc, "protoc", protoc_identity),
            _tool_record(rustc, "rustc", rustc_identity.strip()),
        ),
    )


def _validate_macho_arm64(payload: bytes, label: str) -> None:
    if not 32 <= len(payload) <= MAX_BINARY_BYTES:
        raise ReleaseError(f"{label} is outside the bounded executable size")
    try:
        magic, cpu_type, cpu_subtype, file_type = struct.unpack("<IIII", payload[:16])
    except struct.error as error:
        raise ReleaseError(f"{label} has a truncated Mach-O header") from error
    if (
        magic != 0xFEEDFACF
        or cpu_type != 0x0100000C
        or cpu_subtype != 0
        or file_type != 2
    ):
        raise ReleaseError(f"{label} is not a thin arm64 macOS executable")


def _validate_version_document(
    document: dict[str, Any], configuration: BuildConfiguration, source: dict[str, Any]
) -> None:
    if (
        set(document)
        != {
            "version",
            "source_revision",
            "context_abi",
            "protocol_min",
            "protocol_max",
            "build_profile",
            "enabled_features",
        }
        or document.get("version") != configuration.version
        or document.get("source_revision") != source["revision"]
        or document.get("context_abi") != configuration.context_abi
        or document.get("protocol_min") != "1.0"
        or document.get("protocol_max") != "1.x"
        or document.get("build_profile") != "release"
        or document.get("enabled_features") != []
    ):
        raise ReleaseError("built runtime version identity is stale or malformed")


def _validate_runtime(
    runtime: BuiltRuntime,
    configuration: BuildConfiguration,
    source: dict[str, Any],
) -> None:
    _validate_macho_arm64(runtime.cigar, "cigar")
    _validate_macho_arm64(runtime.cigard, "cigard")
    _validate_macho_arm64(runtime.cigar_mcp, "cigar-mcp")
    _validate_macho_arm64(runtime.cigar_claude_hook, "cigar-claude-hook")
    _validate_version_document(runtime.cigar_version, configuration, source)
    _validate_version_document(runtime.cigard_version, configuration, source)
    if runtime.cigar_version != runtime.cigard_version:
        raise ReleaseError("cigar and cigard version identities differ")
    if runtime.cigar_mcp_probe != {
        "status": "ok",
        "protocol_version": "2025-06-18",
        "build": runtime.cigar_version,
    }:
        raise ReleaseError("cigar-mcp schema probe is stale or malformed")
    if runtime.cigar_claude_hook_probe != {
        "schema_version": "cigar.claude-hook-event.v1",
        "ok": True,
        "maximum_input_bytes": 65_536,
        "model_calls": 0,
        "effect_precheck": "fail_closed",
    }:
        raise ReleaseError("cigar-claude-hook schema probe is stale or malformed")
    generated_expected = {
        path: configuration.assets[path]
        for path in (
            "share/man/man1/cigar.1",
            "completions/cigar.bash",
            "completions/_cigar",
            "completions/cigar.fish",
        )
    }
    if runtime.generated_assets != generated_expected:
        raise ReleaseError("generated manual or completion assets are stale")
    if not runtime.tools or any(
        not isinstance(record, dict)
        or set(record) != {"name", "version", "sha256", "bytes"}
        or not isinstance(record.get("name"), str)
        or not record["name"]
        or not isinstance(record.get("version"), str)
        or not record["version"]
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or not isinstance(record.get("bytes"), int)
        or isinstance(record["bytes"], bool)
        or record["bytes"] <= 0
        for record in runtime.tools
    ):
        raise ReleaseError("native build tool identity is incomplete")


def _payload_tree(entries: list[PackageEntry]) -> str:
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


def _validate_entries(entries: list[PackageEntry]) -> None:
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in entries:
        name = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", name).casefold()
        if name in names or alias in aliases:
            raise ReleaseError(f"duplicate or portable-colliding package path: {name}")
        if entry.mode not in {0o644, 0o755} or not entry.payload:
            raise ReleaseError(
                f"package entry has invalid mode or empty payload: {name}"
            )
        names.add(name)
        aliases.add(alias)


def _write_archive(
    path: Path,
    entries: list[PackageEntry],
    metadata: dict[str, Any],
    epoch: int,
) -> None:
    complete = [
        PackageEntry("RELEASE-METADATA.json", canonical_json_bytes(metadata), 0o644),
        *entries,
    ]
    _validate_entries(complete)
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite staged archive: {path}")
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
                    for entry in sorted(
                        complete, key=lambda item: item.path.encode("utf-8")
                    ):
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


def _package_entries(
    runtime: BuiltRuntime, configuration: BuildConfiguration
) -> list[PackageEntry]:
    base = [
        PackageEntry("LICENSE", configuration.assets["LICENSE"], 0o644),
        PackageEntry("NOTICE", configuration.assets["NOTICE"], 0o644),
        PackageEntry("bin/cigar", runtime.cigar, 0o755),
        PackageEntry("bin/cigard", runtime.cigard, 0o755),
        PackageEntry("bin/cigar-mcp", runtime.cigar_mcp, 0o755),
        PackageEntry("bin/cigar-claude-hook", runtime.cigar_claude_hook, 0o755),
        *[
            PackageEntry(path, payload, 0o644)
            for path, payload in sorted(
                runtime.generated_assets.items(),
                key=lambda item: item[0].encode("utf-8"),
            )
        ],
    ]
    checksums = "".join(
        f"{sha256_bytes(entry.payload)}  {entry.path}\n"
        for entry in sorted(base, key=lambda item: item.path.encode("utf-8"))
    ).encode("ascii")
    return [*base, PackageEntry("SHA256SUMS", checksums, 0o644)]


def produce(
    arguments: argparse.Namespace,
    *,
    runtime_builder: RuntimeBuilder = _default_runtime_builder,
) -> dict[str, Any]:
    root = arguments.root.resolve(strict=True)
    host = _require_host()
    evidence_root = _selected_evidence_directory(arguments)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    configuration = _load_configuration(root)
    source_snapshot = _source_snapshot(root)
    source_before = _source_identity(root, source_snapshot)
    if (
        configuration.release_state == "developer-preview"
        and source_before.get("clean") is not True
    ):
        raise ReleaseError("Honey native build requires a committed, clean source tree")

    workspace = EvidenceWorkspace.create(evidence_root, repository_root=root)
    try:
        # This producer owns an exact two-file workspace. Existing output is never reused.
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(prefix="cigar-macos-aarch64-build-") as raw:
            scratch = Path(raw).resolve(strict=True)
            # Native build staging contains unpublished executable payloads and receipts.
            # 0700 is the intended least-privilege mode, not a permissive default.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                scratch,
                0o700,
            )
            build_root = scratch / "source"
            _write_source_snapshot(source_snapshot, build_root)
            build_configuration = replace(configuration, root=build_root)
            runtime = runtime_builder(
                build_configuration, source_before, epoch, scratch, arguments
            )
            _validate_runtime(runtime, configuration, source_before)
            _verify_source_snapshot(root, source_snapshot)
            if _source_identity(root) != source_before:
                raise ReleaseError("native build source changed during construction")
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError("native build authority changed during construction")

            entries = _package_entries(runtime, configuration)
            contract_sha256 = str(
                configuration.authority[
                    "packaging/contracts/macos-runtime-archive.v1.json"
                ]["sha256"]
            )
            metadata = {
                "schema_version": "cigar.release-metadata.v1",
                "artifact_id": configuration.artifact_id,
                "product_version": configuration.version,
                "context_abi": configuration.context_abi,
                "source_date_epoch": epoch,
                "source": source_before,
                "input_tree_sha256": _payload_tree(entries),
                "input_file_count": len(entries),
                "contract": configuration.contract_relative,
                "contract_sha256": contract_sha256,
            }
            staged_archive = scratch / configuration.filename
            _write_archive(staged_archive, entries, metadata, epoch)
            validated_archive = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "staged native archive"
            )
            validated_archive_bytes = len(validated_archive)
            validated_archive_sha256 = sha256_bytes(validated_archive)
            verification = verify_package(
                staged_archive,
                configuration.contract_path,
                configuration.version,
                configuration.context_abi,
                epoch,
            )
            _verify_source_snapshot(root, source_snapshot)
            if _source_identity(root) != source_before:
                raise ReleaseError("native build source changed during verification")
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError("native build authority changed during verification")
            verified_archive = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "verified native archive"
            )
            if (
                len(verified_archive) != validated_archive_bytes
                or sha256_bytes(verified_archive) != validated_archive_sha256
            ):
                raise ReleaseError("native archive changed during package verification")
            archive_reference = workspace.attach_file(
                staged_archive,
                configuration.filename,
                expected_sha256=validated_archive_sha256,
                expected_bytes=validated_archive_bytes,
            )

        receipt = {
            "schema_version": "cigar.development-native-archive-build.v1",
            "status": "built-unqualified",
            "artifact_id": configuration.artifact_id,
            "target": TARGET_TRIPLE,
            "product_version": configuration.version,
            "context_abi": configuration.context_abi,
            "runtime_profile": RUNTIME_PROFILE,
            "source_date_epoch": epoch,
            "source": source_before,
            "host": host,
            "archive": archive_reference.as_dict(),
            "contract": {
                "path": configuration.contract_relative,
                "sha256": contract_sha256,
            },
            "authority": configuration.authority,
            "build_tools": list(runtime.tools),
            "build_environment": {
                "cargo_network_offline": True,
                "network_enforcement": MACOS_NO_EGRESS_ENFORCEMENT,
                "sandbox_launcher": str(MACOS_SANDBOX_EXEC),
                "sandbox_policy": MACOS_NO_EGRESS_POLICY,
            },
            "runtime_payload": {
                name: {
                    "path": f"bin/{name}",
                    "sha256": sha256_bytes(payload),
                    "bytes": len(payload),
                }
                for name, payload in (
                    ("cigar", runtime.cigar),
                    ("cigard", runtime.cigard),
                    ("cigar-mcp", runtime.cigar_mcp),
                    ("cigar-claude-hook", runtime.cigar_claude_hook),
                )
            },
            "payload_file_count": len(entries) + 1,
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "claims": {
                "development_build": configuration.release_state == "development",
                "developer_preview_build": configuration.release_state
                == "developer-preview",
                "distribution_signed": False,
                "notarized": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        }
        workspace.write_json(configuration.receipt_name, receipt)
        workspace.read_files(
            {configuration.filename, configuration.receipt_name}, strict_read_only=True
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
        raise SystemExit(f"macOS arm64 development build failed: {error}") from error
