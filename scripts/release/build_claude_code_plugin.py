#!/usr/bin/env python3
"""Build the unsigned development Claude Code plugin for Apple-silicon macOS."""

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
from dataclasses import dataclass
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
    process_failure_summary,
    require_source_date_epoch,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    tree_digest,
)
from verify_package import verify as verify_package


ARTIFACT_ID = "claude-code-plugin"
DEVELOPMENT_RUNTIME_ARTIFACT_ID = "cli-daemon-macos-aarch64"
HONEY_RUNTIME_ARTIFACT_ID = "macos-runtime-aarch64"
TARGET_TRIPLE = "aarch64-apple-darwin"
PRODUCER = "python3 scripts/release/build_claude_code_plugin.py"
PRODUCER_ARGV = ["python3", "scripts/release/build_claude_code_plugin.py"]
BUILD_RECEIPT = "claude-code-plugin-development-build.json"
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_RELATIVE = "adapters/claude-code"
AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/plugin-archive.v1.json",
    "packaging/contracts/macos-runtime-archive.v1.json",
    f"{ADAPTER_RELATIVE}/package-manifest.json",
)
HONEY_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
    "packaging/contracts/plugin-archive.v1.json",
    "packaging/contracts/macos-runtime-archive.v1.json",
    f"{ADAPTER_RELATIVE}/package-manifest.json",
)
SOURCE_RELEASE_PATHS = frozenset(
    {
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "README.md",
        "agents/context-curator.md",
        "agents/effect-reviewer.md",
        "agents/handoff-curator.md",
        "compatibility.json",
        "hooks/hooks.json",
        "schemas/hook-fixture.schema.json",
        "skills/checkpoint/SKILL.md",
        "skills/compile/SKILL.md",
        "skills/effect/SKILL.md",
        "skills/handoff/SKILL.md",
        "skills/why/SKILL.md",
    }
)
SOURCE_INCLUDES = (
    ".cargo/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "clippy.toml",
    "crates/**",
    f"{ADAPTER_RELATIVE}/**",
    "scripts/release/build_claude_code_plugin.py",
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
class BuildConfiguration:
    root: Path
    adapter_root: Path
    version: str
    context_abi: str
    filename: str
    receipt_filename: str
    contract_path: Path
    contract_relative: str
    authority: dict[str, dict[str, object]]
    assets: dict[str, bytes]
    honey: bool


@dataclass(frozen=True)
class BuiltHook:
    executable: bytes
    mcp_executable: bytes
    schema_probe: dict[str, Any]
    tools: tuple[dict[str, object], ...]
    runtime_binding: dict[str, object] | None = None


HookBuilder = Callable[
    [BuildConfiguration, dict[str, Any], int, Path, argparse.Namespace], BuiltHook
]
SourceValidator = Callable[[BuildConfiguration, Path], dict[str, object]]


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
    parser.add_argument(
        "--runtime-archive",
        type=Path,
        help="verified native macOS archive supplying the exact installed hook bytes",
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
            "the development plugin producer requires Apple-silicon macOS; "
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
        payload = _read_stable_file(
            root.joinpath(*relative.split("/")), 16 * 1024 * 1024, relative
        )
        records[relative] = {
            "sha256": sha256_bytes(payload),
            "bytes": len(payload),
        }
    return records


def _manifest_assets(adapter_root: Path) -> dict[str, bytes]:
    manifest_path = adapter_root / "package-manifest.json"
    manifest = load_json(manifest_path)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "files"}
        or manifest.get("schema_version") != "cigar.claude-code-package.v1"
        or not isinstance(manifest.get("files"), list)
        or not manifest["files"]
    ):
        raise ReleaseError("Claude Code source package manifest is malformed")

    declared: list[str] = []
    aliases: set[str] = set()
    assets: dict[str, bytes] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            raise ReleaseError("Claude Code source package manifest entry is malformed")
        relative = entry.get("path")
        expected_sha256 = entry.get("sha256")
        expected_bytes = entry.get("bytes")
        if not isinstance(relative, str) or safe_relative_path(relative) != relative:
            raise ReleaseError("Claude Code source package manifest path is unsafe")
        alias = unicodedata.normalize("NFC", relative).casefold()
        if relative in declared or alias in aliases:
            raise ReleaseError(
                f"Claude Code source package manifest path collides: {relative}"
            )
        if (
            not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes <= 0
            or expected_bytes > 16 * 1024 * 1024
        ):
            raise ReleaseError(
                f"Claude Code source package manifest binding is invalid: {relative}"
            )
        payload = _read_stable_file(
            adapter_root.joinpath(*relative.split("/")),
            16 * 1024 * 1024,
            f"Claude Code source package file {relative}",
        )
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise ReleaseError(
                f"Claude Code source package manifest binding differs: {relative}"
            )
        declared.append(relative)
        aliases.add(alias)
        if not relative.startswith("tests/"):
            assets[relative] = payload

    if declared != sorted(declared, key=lambda value: value.encode("utf-8")):
        raise ReleaseError("Claude Code source package manifest is not sorted")
    actual: list[str] = []
    for path in adapter_root.rglob("*"):
        if path.is_symlink():
            raise ReleaseError(f"Claude Code source package contains a symlink: {path}")
        if path.is_file() and path != manifest_path:
            actual.append(path.relative_to(adapter_root).as_posix())
    actual.sort(key=lambda value: value.encode("utf-8"))
    if actual != declared:
        raise ReleaseError(
            "Claude Code source package manifest does not cover the exact source tree"
        )
    if set(assets) != SOURCE_RELEASE_PATHS:
        raise ReleaseError(
            "Claude Code release asset inventory differs from the reviewed package set"
        )
    return assets


def _is_honey_product(product: Any) -> bool:
    return (
        isinstance(product, dict)
        and product.get("release_state") == "developer-preview"
        and product.get("channel") == "honey"
        and isinstance(product.get("version"), str)
        and product.get("tag") == f"v{product['version']}"
    )


def _runtime_artifact_id(configuration: BuildConfiguration) -> str:
    return (
        HONEY_RUNTIME_ARTIFACT_ID
        if configuration.honey
        else DEVELOPMENT_RUNTIME_ARTIFACT_ID
    )


def _validate_honey_authority(
    product: dict[str, Any],
    matrix: Any,
    profile: Any,
    requirements: Any,
    authority: dict[str, dict[str, object]],
) -> None:
    version = product["version"]
    python_match = re.fullmatch(
        r"([0-9]+\.[0-9]+\.[0-9]+)-honey\.([1-9][0-9]*)", version
    )
    if python_match is None:
        raise ReleaseError("Honey version cannot be mapped to the capability profile")
    python_version = f"{python_match.group(1)}.dev{python_match.group(2)}"
    identity = {
        "channel": "honey",
        "context_abi": product["context_abi"],
        "ecosystem_versions": {
            "archive": version,
            "plugin": version,
            "python": python_version,
            "rust": version,
            "typescript": version,
        },
        "marketing_name": "CIGAR Honey v0.9",
        "prerelease": True,
        "product_version": version,
        "production_qualified": False,
        "published": False,
        "python_distribution_version": python_version,
        "release_state": "developer-preview",
        "supported": False,
        "tag": f"v{version}",
    }
    capabilities = profile.get("capabilities", []) if isinstance(profile, dict) else []
    required_capabilities = {
        capability.get("id")
        for capability in capabilities
        if isinstance(capability, dict)
        and capability.get("status") == "required"
        and capability.get("support_level") == "developer-preview"
    }
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.honey.artifact-matrix.v1"
        or matrix.get("release_state") != "developer-preview"
        or matrix.get("product_version") != version
        or matrix.get("context_abi") != product["context_abi"]
        or matrix.get("profile_id")
        != "cigar.honey.local-developer-preview.macos-arm64.v1"
        or matrix.get("fail_closed") is not True
        or not isinstance(matrix.get("artifacts"), list)
        or not isinstance(profile, dict)
        or profile.get("schema_version") != "cigar.honey.capability-profile.v1"
        or profile.get("profile_id") != matrix.get("profile_id")
        or profile.get("fail_closed") is not True
        or profile.get("identity") != identity
        or profile.get("platform")
        != {
            "deployment_modes": ["embedded", "local-sidecar"],
            "host_arch": "arm64",
            "host_os": "macos",
            "network_required": False,
            "target_triple": TARGET_TRIPLE,
            "trust_model": "single-local-os-user-with-explicit-agent-principals",
        }
        or profile.get("product_version_binding")
        != {
            "path": "packaging/product-version.v1.json",
            "sha256": authority["packaging/product-version.v1.json"]["sha256"],
        }
        or profile.get("artifact_ids") != [row.get("id") for row in matrix["artifacts"]]
        or not {"claude-code", "mcp-2025-06-18-stdio"}.issubset(
            set(profile.get("integrations", []))
        )
        or not {"claude-code", "mcp"}.issubset(required_capabilities)
    ):
        raise ReleaseError(
            "Honey Claude/MCP capability authority is incomplete or stale"
        )
    expected_bindings = {
        "artifact_matrix": {
            "path": "packaging/honey/artifact-matrix.v1.json",
            "sha256": authority["packaging/honey/artifact-matrix.v1.json"]["sha256"],
        },
        "capability_profile": {
            "path": "packaging/honey/capability-profile.v1.json",
            "sha256": authority["packaging/honey/capability-profile.v1.json"]["sha256"],
        },
    }
    mandatory_gates = profile.get("mandatory_gate_ids")
    if (
        not isinstance(requirements, dict)
        or requirements.get("schema_version") != "cigar.honey.release-requirements.v1"
        or requirements.get("profile_id") != matrix.get("profile_id")
        or requirements.get("fail_closed") is not True
        or requirements.get("machine_claims")
        != {
            "prerelease": True,
            "production_qualified": False,
            "supported": False,
        }
        or requirements.get("required_source_state")
        != {"clean": True, "committed": True, "tagged_before_build": False}
        or requirements.get("authority_bindings") != expected_bindings
        or not isinstance(mandatory_gates, list)
        or requirements.get("mandatory_gates")
        != [
            {
                "evidence_status": "required-not-implied",
                "id": gate,
                "required": True,
            }
            for gate in mandatory_gates
        ]
    ):
        raise ReleaseError("Honey release requirements are incomplete or stale")


def _load_configuration(root: Path) -> BuildConfiguration:
    root = root.resolve(strict=True)
    initial_product = load_json(root / "packaging/product-version.v1.json")
    honey = _is_honey_product(initial_product)
    authority_paths = HONEY_AUTHORITY_PATHS if honey else AUTHORITY_PATHS
    authority = _authority_digests(root, authority_paths)
    product = load_json(root / "packaging/product-version.v1.json")
    if honey:
        matrix = load_json(root / "packaging/honey/artifact-matrix.v1.json")
        profile = load_json(root / "packaging/honey/capability-profile.v1.json")
        requirements = load_json(root / "packaging/honey/release-requirements.v1.json")
    else:
        matrix = load_json(root / "packaging/artifact-matrix.v1.json")
        profile = load_json(root / "packaging/development/local-macos-aarch64.v1.json")
        requirements = None
    contract = load_json(root / "packaging/contracts/plugin-archive.v1.json")
    adapter_root = root / ADAPTER_RELATIVE
    assets = _manifest_assets(adapter_root)

    development_identity = (
        isinstance(product, dict)
        and product.get("release_state") == "development"
        and product.get("channel") == "development"
        and product.get("tag") is None
    )
    if (
        not isinstance(product, dict)
        or product.get("schema_version") != "cigar.product-version.v1"
        or not (development_identity or _is_honey_product(product))
        or honey != _is_honey_product(product)
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
    expected_filename = f"cigar-claude-code-{version}.tar.gz"
    if honey:
        _validate_honey_authority(product, matrix, profile, requirements, authority)
        matching = [
            entry
            for entry in matrix["artifacts"]
            if isinstance(entry, dict) and entry.get("id") == ARTIFACT_ID
        ]
        expected_artifact = {
            "contract": "packaging/contracts/plugin-archive.v1.json",
            "filename": expected_filename,
            "generated_by_assembler": False,
            "id": ARTIFACT_ID,
            "kind": "plugin-archive",
            "order": 9,
            "producer": PRODUCER_ARGV,
            "public_attachment": True,
            "qualification_gate_ids": ["claude-lifecycle", "archive-contracts"],
            "receipt": {
                "filename": "claude-code-plugin-build-receipt.json",
                "required": True,
                "schema_version": "cigar.development-claude-code-plugin-build.v1",
            },
            "required": True,
            "sha256_required": True,
            "workspace": "claude",
        }
        if len(matching) != 1 or matching[0] != expected_artifact:
            raise ReleaseError("Claude Code Honey artifact row is incomplete or stale")
        receipt_filename = expected_artifact["receipt"]["filename"]
    else:
        if (
            not isinstance(matrix, dict)
            or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
            or matrix.get("release_state") != "development"
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
            if isinstance(entry, dict) and entry.get("id") == ARTIFACT_ID
        ]
        if len(matching) != 1:
            raise ReleaseError(
                f"artifact matrix must contain exactly one {ARTIFACT_ID} row"
            )
        artifact = matching[0]
        if (
            artifact.get("kind") != "plugin-archive"
            or artifact.get("filename") != expected_filename
            or artifact.get("contract") != "contracts/plugin-archive.v1.json"
            or artifact.get("producer") != PRODUCER
        ):
            raise ReleaseError("Claude Code plugin artifact row is incomplete or stale")
        if not isinstance(profile, dict):
            raise ReleaseError("development macOS arm64 profile is malformed")
        selected = profile.get("selected_artifacts")
        selected_rows = (
            [
                row
                for row in selected
                if isinstance(row, dict) and row.get("id") == ARTIFACT_ID
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
        ):
            raise ReleaseError(
                "development macOS arm64 profile does not keep the plugin unclaimed"
            )
        receipt_filename = BUILD_RECEIPT

    plugin = load_json_bytes(assets[".claude-plugin/plugin.json"], "plugin.json")
    compatibility = load_json_bytes(
        assets["compatibility.json"], "Claude Code compatibility"
    )
    if (
        not isinstance(plugin, dict)
        or plugin.get("name") != "cigar"
        or plugin.get("version") != version
    ):
        raise ReleaseError("Claude Code plugin manifest identity is stale")
    if compatibility != {
        "schema_version": "cigar.claude-code-compatibility.v1",
        "context_abi": context_abi,
        "claude_code": {
            "minimum_inclusive": "2.1.207",
            "maximum_exclusive": "2.1.208",
        },
        "platforms": ["macos-aarch64", "macos-arm64"],
        "public_surfaces_only": True,
    }:
        raise ReleaseError("Claude Code compatibility authority is stale")

    required_allow = {
        "RELEASE-METADATA.json",
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "README.md",
        "agents/**",
        "compatibility.json",
        "hooks/**",
        "schemas/**",
        "skills/**",
        "bin/cigar-claude-hook",
        "bin/cigar-mcp",
        "LICENSE",
        "NOTICE",
        "SHA256SUMS",
    }
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id") != "plugin-archive-v1"
        or not isinstance(contract.get("formats"), list)
        or "tar.gz" not in contract["formats"]
        or not isinstance(contract.get("allow"), list)
        or not required_allow.issubset(set(contract["allow"]))
        or "tests/**" not in contract.get("deny", [])
        or contract.get("required_any") != []
        or not {"bin/cigar-claude-hook", "bin/cigar-mcp"}.issubset(
            set(contract.get("required", []))
        )
        or contract.get("checksum_manifest")
        != {"path": "SHA256SUMS", "scope": "all-payload-files"}
        or contract.get("version_binding")
        != {
            "path_pattern": ".claude-plugin/plugin.json",
            "format": "json",
            "json_pointer": "/version",
        }
        or contract.get("abi_binding")
        != {
            "path_pattern": "compatibility.json",
            "format": "json",
            "json_pointer": "/context_abi",
        }
        or contract.get("symlinks") != "forbid"
        or contract.get("line_endings") != "lf"
        or contract.get("content_scan") is not True
    ):
        raise ReleaseError("plugin archive contract does not cover the exact payload")

    for relative, payload in assets.items():
        if b"\r" in payload or not payload.endswith(b"\n"):
            raise ReleaseError(
                f"packaged plugin text is not canonical LF text: {relative}"
            )
    for destination in ("LICENSE", "NOTICE"):
        payload = _read_stable_file(root / destination, 16 * 1024 * 1024, destination)
        if b"\r" in payload or not payload.endswith(b"\n"):
            raise ReleaseError(
                f"packaged legal text is not canonical LF text: {destination}"
            )
        assets[destination] = payload
    return BuildConfiguration(
        root=root,
        adapter_root=adapter_root,
        version=version,
        context_abi=context_abi,
        filename=expected_filename,
        receipt_filename=receipt_filename,
        contract_path=root / "packaging/contracts/plugin-archive.v1.json",
        contract_relative="packaging/contracts/plugin-archive.v1.json",
        authority=authority,
        assets=assets,
        honey=honey,
    )


def _source_identity(root: Path) -> dict[str, Any]:
    honey = _is_honey_product(load_json(root / "packaging/product-version.v1.json"))
    includes = list(SOURCE_INCLUDES)
    if honey:
        includes.extend(
            [
                "packaging/product-version.v1.json",
                "packaging/honey/capability-profile.v1.json",
                "packaging/honey/artifact-matrix.v1.json",
                "packaging/honey/release-requirements.v1.json",
                "packaging/contracts/plugin-archive.v1.json",
                "packaging/contracts/macos-runtime-archive.v1.json",
            ]
        )
    files = expand_files(root, includes, SOURCE_EXCLUDES)
    if not files:
        raise ReleaseError("Claude Code plugin build source inventory is empty")
    identity = git_state(root, tree_digest(files))
    if (
        identity.get("committed") is not True
        or not isinstance(identity.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", identity["revision"]) is None
        or not isinstance(identity.get("clean"), bool)
        or (honey and identity.get("clean") is not True)
        or not isinstance(identity.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["tree_sha256"]) is None
    ):
        raise ReleaseError("plugin build requires a committed Git source identity")
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
    epoch: int,
    scratch: Path,
    cargo: Path,
    rustc: Path,
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
        (scratch, "/usr/src/cigar-plugin-build"),
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
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "MACOSX_DEPLOYMENT_TARGET": "11.0",
        "PATH": os.pathsep.join(path_entries),
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
    payload = _read_stable_file(resolved, 64 * 1024 * 1024, f"{name} executable")
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _default_source_validator(
    configuration: BuildConfiguration, scratch: Path
) -> dict[str, object]:
    python = _secure_executable(Path(sys.executable), "python3")
    validator_home = scratch / "validator-home"
    validator_tmp = scratch / "validator-tmp"
    validator_home.mkdir(mode=0o700)
    validator_tmp.mkdir(mode=0o700)
    environment = {
        "HOME": str(validator_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(validator_tmp),
        "TZ": "UTC",
    }
    output = _run_checked(
        [str(python), str(configuration.adapter_root / "tests/validate_package.py")],
        cwd=configuration.root,
        environment=environment,
        timeout=120,
        label="Claude Code source package validation",
        maximum=1024 * 1024,
    )
    if output != b"CIGAR Claude plugin package validation passed\n":
        raise ReleaseError("Claude Code source package validator output is unexpected")
    return {
        "validator": f"{ADAPTER_RELATIVE}/tests/validate_package.py",
        "status": "passed",
    }


def _compiled_hook_builder(
    configuration: BuildConfiguration,
    _source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltHook:
    cargo = _secure_executable(arguments.cargo, "cargo")
    rustc = _secure_executable(arguments.rustc, "rustc")
    environment = _cargo_environment(configuration, epoch, scratch, cargo, rustc)
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
    if f"host: {TARGET_TRIPLE}" not in rustc_identity:
        raise ReleaseError("rustc host is not native aarch64-apple-darwin")
    _run_checked(
        [
            str(cargo),
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            TARGET_TRIPLE,
            "-p",
            "cigar-claude-hook",
            "-p",
            "cigar-mcp",
        ],
        cwd=configuration.root,
        environment=environment,
        timeout=1_800,
        label="Claude Code hook Cargo build",
    )
    binary = scratch / "target" / TARGET_TRIPLE / "release/cigar-claude-hook"
    mcp_binary = scratch / "target" / TARGET_TRIPLE / "release/cigar-mcp"
    runtime_environment = {
        "HOME": str(scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(scratch / "tmp"),
        "TZ": "UTC",
    }
    probe_payload = _run_checked(
        [str(binary), "schema-noop"],
        cwd=configuration.root,
        environment=runtime_environment,
        timeout=30,
        label="Claude Code hook schema probe",
        maximum=256 * 1024,
    )
    probe = load_json_bytes(probe_payload, "Claude Code hook schema probe")
    if not isinstance(probe, dict):
        raise ReleaseError("Claude Code hook schema probe is not an object")
    return BuiltHook(
        executable=_read_stable_file(binary, MAX_BINARY_BYTES, "built Claude hook"),
        mcp_executable=_read_stable_file(
            mcp_binary, MAX_BINARY_BYTES, "built Claude MCP server"
        ),
        schema_probe=probe,
        tools=(
            _tool_record(cargo, "cargo", cargo_identity),
            _tool_record(rustc, "rustc", rustc_identity.strip()),
        ),
    )


def _archive_member(payload: bytes, name: str, maximum: int) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            matches = [member for member in archive.getmembers() if member.name == name]
            if len(matches) != 1:
                raise ReleaseError(
                    f"native runtime archive must contain exactly one {name} member"
                )
            member = matches[0]
            if not member.isfile() or member.size <= 0 or member.size > maximum:
                raise ReleaseError(f"native runtime archive member is invalid: {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise ReleaseError(
                    f"native runtime archive member is unreadable: {name}"
                )
            with handle:
                extracted = handle.read(maximum + 1)
            if len(extracted) != member.size or len(extracted) > maximum:
                raise ReleaseError(
                    f"native runtime archive member changed length: {name}"
                )
            return extracted
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError(f"cannot inspect native runtime archive: {error}") from error


def _default_hook_builder(
    configuration: BuildConfiguration,
    source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltHook:
    selected = getattr(arguments, "runtime_archive", None)
    if selected is None:
        raise ReleaseError(
            "--runtime-archive is required; plugin hook bytes must come from the native package"
        )
    if not selected.is_absolute():
        raise ReleaseError("runtime archive path must be absolute")
    try:
        runtime_archive = selected.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(f"cannot resolve runtime archive: {error}") from error
    before = _read_stable_file(
        runtime_archive, MAX_RUNTIME_ARCHIVE_BYTES, "native runtime archive"
    )
    archive_sha256 = sha256_bytes(before)
    archive_bytes = len(before)
    runtime_contract = (
        configuration.root / "packaging/contracts/macos-runtime-archive.v1.json"
    )
    verification = verify_package(
        runtime_archive,
        runtime_contract,
        configuration.version,
        configuration.context_abi,
        epoch,
    )
    after = _read_stable_file(
        runtime_archive, MAX_RUNTIME_ARCHIVE_BYTES, "verified native runtime archive"
    )
    if len(after) != archive_bytes or sha256_bytes(after) != archive_sha256:
        raise ReleaseError("native runtime archive changed during verification")
    metadata = verification.get("metadata")
    runtime_source = metadata.get("source") if isinstance(metadata, dict) else None
    runtime_artifact_id = _runtime_artifact_id(configuration)
    if (
        not isinstance(metadata, dict)
        or metadata.get("artifact_id") != runtime_artifact_id
        or metadata.get("product_version") != configuration.version
        or metadata.get("context_abi") != configuration.context_abi
        or metadata.get("source_date_epoch") != epoch
        or not isinstance(runtime_source, dict)
        or runtime_source.get("committed") is not True
        or runtime_source.get("revision") != source.get("revision")
        or runtime_source.get("clean") != source.get("clean")
    ):
        raise ReleaseError(
            "native runtime archive is not bound to the plugin build source identity"
        )

    hook = _archive_member(after, "bin/cigar-claude-hook", MAX_BINARY_BYTES)
    mcp = _archive_member(after, "bin/cigar-mcp", MAX_BINARY_BYTES)
    hook_path = scratch / "runtime-cigar-claude-hook"
    with hook_path.open("xb") as handle:
        handle.write(hook)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(hook_path, 0o500)
    runtime_environment = {
        "HOME": str(scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(scratch / "tmp"),
        "TZ": "UTC",
    }
    for directory in (scratch / "home", scratch / "tmp"):
        directory.mkdir(mode=0o700, exist_ok=True)
    probe_payload = _run_checked(
        [str(hook_path), "schema-noop"],
        cwd=configuration.root,
        environment=runtime_environment,
        timeout=30,
        label="installed Claude Code hook schema probe",
        maximum=256 * 1024,
    )
    probe = load_json_bytes(probe_payload, "installed Claude Code hook schema probe")
    if not isinstance(probe, dict):
        raise ReleaseError("installed Claude Code hook schema probe is not an object")
    python = _secure_executable(Path(sys.executable), "python3")
    python_identity = (
        _run_checked(
            [str(python), "--version"],
            cwd=configuration.root,
            environment=runtime_environment,
            timeout=30,
            label="Python identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    return BuiltHook(
        executable=hook,
        mcp_executable=mcp,
        schema_probe=probe,
        tools=(_tool_record(python, "python3", python_identity),),
        runtime_binding={
            "artifact_id": runtime_artifact_id,
            "archive": {"sha256": archive_sha256, "bytes": archive_bytes},
            "source": runtime_source,
            "hook": {"sha256": sha256_bytes(hook), "bytes": len(hook)},
            "mcp": {"sha256": sha256_bytes(mcp), "bytes": len(mcp)},
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "distribution_signature_qualified": False,
        },
    )


def _validate_macho_arm64(payload: bytes) -> None:
    if not 32 <= len(payload) <= MAX_BINARY_BYTES:
        raise ReleaseError("Claude Code hook is outside the bounded executable size")
    try:
        magic, cpu_type, cpu_subtype, file_type = struct.unpack("<IIII", payload[:16])
    except struct.error as error:
        raise ReleaseError("Claude Code hook has a truncated Mach-O header") from error
    if (
        magic != 0xFEEDFACF
        or cpu_type != 0x0100000C
        or cpu_subtype != 0
        or file_type != 2
    ):
        raise ReleaseError("Claude Code hook is not a thin arm64 macOS executable")


def _validate_hook(hook: BuiltHook) -> None:
    _validate_macho_arm64(hook.executable)
    _validate_macho_arm64(hook.mcp_executable)
    if hook.schema_probe != {
        "schema_version": "cigar.claude-hook-event.v1",
        "ok": True,
        "maximum_input_bytes": 65_536,
        "model_calls": 0,
        "effect_precheck": "fail_closed",
    }:
        raise ReleaseError("Claude Code hook schema probe is stale or malformed")
    if not hook.tools or any(
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
        for record in hook.tools
    ):
        raise ReleaseError("Claude Code hook build tool identity is incomplete")


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
        raise ReleaseError(f"refusing to overwrite staged plugin archive: {path}")
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
    hook: BuiltHook, configuration: BuildConfiguration
) -> list[PackageEntry]:
    base = [
        *[
            PackageEntry(relative, payload, 0o644)
            for relative, payload in sorted(
                configuration.assets.items(), key=lambda item: item[0].encode("utf-8")
            )
        ],
        PackageEntry("bin/cigar-claude-hook", hook.executable, 0o755),
        PackageEntry("bin/cigar-mcp", hook.mcp_executable, 0o755),
    ]
    checksums = "".join(
        f"{sha256_bytes(entry.payload)}  {entry.path}\n"
        for entry in sorted(base, key=lambda item: item.path.encode("utf-8"))
    ).encode("ascii")
    return [*base, PackageEntry("SHA256SUMS", checksums, 0o644)]


def produce(
    arguments: argparse.Namespace,
    *,
    hook_builder: HookBuilder = _default_hook_builder,
    source_validator: SourceValidator = _default_source_validator,
) -> dict[str, Any]:
    root = arguments.root.resolve(strict=True)
    host = _require_host()
    evidence_root = _selected_evidence_directory(arguments)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    configuration = _load_configuration(root)
    source_before = _source_identity(root)

    workspace = EvidenceWorkspace.create(evidence_root, repository_root=root)
    try:
        # This producer owns an exact two-file workspace. Existing output is never reused.
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(
            prefix="cigar-claude-code-plugin-build-"
        ) as raw:
            scratch = Path(raw).resolve(strict=True)
            # Plugin build staging contains an unpublished executable and package payload.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                scratch, 0o700
            )
            validation = source_validator(configuration, scratch)
            if validation != {
                "validator": f"{ADAPTER_RELATIVE}/tests/validate_package.py",
                "status": "passed",
            }:
                raise ReleaseError(
                    "Claude Code source package validation is incomplete"
                )
            hook = hook_builder(configuration, source_before, epoch, scratch, arguments)
            _validate_hook(hook)
            if _source_identity(root) != source_before:
                raise ReleaseError("plugin build source changed during construction")
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError("plugin build authority changed during construction")

            entries = _package_entries(hook, configuration)
            contract_sha256 = str(
                configuration.authority["packaging/contracts/plugin-archive.v1.json"][
                    "sha256"
                ]
            )
            metadata = {
                "schema_version": "cigar.release-metadata.v1",
                "artifact_id": ARTIFACT_ID,
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
                staged_archive, MAX_ARCHIVE_BYTES, "staged Claude Code plugin archive"
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
            if _source_identity(root) != source_before:
                raise ReleaseError("plugin build source changed during verification")
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError("plugin build authority changed during verification")
            verified_archive = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "verified Claude Code plugin archive"
            )
            if (
                len(verified_archive) != validated_archive_bytes
                or sha256_bytes(verified_archive) != validated_archive_sha256
            ):
                raise ReleaseError(
                    "Claude Code plugin archive changed during package verification"
                )
            archive_reference = workspace.attach_file(
                staged_archive,
                configuration.filename,
                expected_sha256=validated_archive_sha256,
                expected_bytes=validated_archive_bytes,
            )

        receipt = {
            "schema_version": "cigar.development-claude-code-plugin-build.v1",
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
                "sha256": contract_sha256,
            },
            "authority": configuration.authority,
            "source_package_validation": validation,
            "build_tools": list(hook.tools),
            "runtime_binding": hook.runtime_binding,
            "payload_file_count": len(entries) + 1,
            "hook_schema_probe": hook.schema_probe,
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "claims": {
                "development_build": True,
                "installed_compatibility": False,
                "distribution_signed": False,
                "qualified": False,
                "published": False,
                "supported": False,
                "release": False,
            },
        }
        workspace.write_json(configuration.receipt_filename, receipt)
        workspace.read_files(
            {configuration.filename, configuration.receipt_filename},
            strict_read_only=True,
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
        raise SystemExit(
            f"Claude Code plugin development build failed: {error}"
        ) from error
