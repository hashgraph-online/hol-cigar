#!/usr/bin/env python3
"""Build the deterministic, unsigned development TypeScript SDK package on macOS."""

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


ARTIFACT_ID = "typescript-sdk"
TARGET_TRIPLE = "aarch64-apple-darwin"
PRODUCER = "python3 scripts/release/build_typescript_sdk.py"
PRODUCER_ARGV = ["python3", "scripts/release/build_typescript_sdk.py"]
BUILD_RECEIPT = "typescript-sdk-development-build.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SDK_RELATIVE = "sdk/typescript"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_DEPENDENCY_FILE_BYTES = 64 * 1024 * 1024
MAX_DEPENDENCY_TREE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
EXPECTED_QUICKSTART_IDENTITY = (
    "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"
)

AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/npm-package.v1.json",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    f"{SDK_RELATIVE}/package.json",
    f"{SDK_RELATIVE}/release.json",
)
HONEY_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
    "packaging/contracts/npm-package.v1.json",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    f"{SDK_RELATIVE}/package.json",
    f"{SDK_RELATIVE}/release.json",
)

SOURCE_TYPESCRIPT_PATHS = frozenset(
    {
        "src/client.ts",
        "src/digest.ts",
        "src/errors.ts",
        "src/examples/quickstart.ts",
        "src/examples/two-agent-observer.ts",
        "src/examples/verify-shared-bundle.ts",
        "src/generated/cigar_service_pb.ts",
        "src/generated/context_abi_pb.ts",
        "src/generated/errors.ts",
        "src/generated/generated/error_codes_pb.ts",
        "src/generated/models.ts",
        "src/generated/operations.ts",
        "src/idempotency.ts",
        "src/index.ts",
        "src/tests/client.test.ts",
        "src/tests/digest.test.ts",
        "src/tests/hardening.test.ts",
        "src/tests/release-contract.test.ts",
        "src/types.ts",
        "src/verify-replay.ts",
        "src/verify-vectors.ts",
    }
)
PACKAGED_MODULES = frozenset(
    path.removeprefix("src/").removesuffix(".ts")
    for path in SOURCE_TYPESCRIPT_PATHS
    if not path.startswith("src/tests/")
)
SDK_BUILD_SOURCE_PATHS = frozenset(
    {
        "LICENSE",
        "NOTICE",
        "README.md",
        "fixtures/semantic-bundle-v1.json",
        "package.json",
        "release.json",
        "tools/inline-sources.mjs",
        "tsconfig.json",
        *SOURCE_TYPESCRIPT_PATHS,
    }
)
WORKSPACE_SOURCE_PATHS = frozenset(
    {"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"}
)
SOURCE_INCLUDES = (
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    f"{SDK_RELATIVE}/**",
    "scripts/release/build_typescript_sdk.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/verify_package.py",
)
SOURCE_EXCLUDES = (
    "**/.DS_Store",
    "**/__pycache__/**",
    "**/*.pyc",
    f"{SDK_RELATIVE}/dist/**",
    f"{SDK_RELATIVE}/node_modules/**",
)


@dataclass(frozen=True)
class PackageEntry:
    path: str
    payload: bytes
    mode: int = 0o644


@dataclass(frozen=True)
class DependencySpec:
    name: str
    version: str
    source_relative: str
    destination_relative: str


DEPENDENCY_SPECS = (
    DependencySpec(
        "typescript",
        "7.0.2",
        "node_modules/.pnpm/typescript@7.0.2/node_modules/typescript",
        "typescript",
    ),
    DependencySpec(
        "@typescript/typescript-darwin-arm64",
        "7.0.2",
        "node_modules/.pnpm/@typescript+typescript-darwin-arm64@7.0.2/"
        "node_modules/@typescript/typescript-darwin-arm64",
        "@typescript/typescript-darwin-arm64",
    ),
    DependencySpec(
        "@bufbuild/protobuf",
        "2.12.1",
        "node_modules/.pnpm/@bufbuild+protobuf@2.12.1/node_modules/@bufbuild/protobuf",
        "@bufbuild/protobuf",
    ),
    DependencySpec(
        "@types/node",
        "24.10.0",
        "node_modules/.pnpm/@types+node@24.10.0/node_modules/@types/node",
        "@types/node",
    ),
    DependencySpec(
        "undici-types",
        "7.16.0",
        "node_modules/.pnpm/undici-types@7.16.0/node_modules/undici-types",
        "undici-types",
    ),
)


@dataclass(frozen=True)
class BuildConfiguration:
    root: Path
    sdk_root: Path
    version: str
    context_abi: str
    filename: str
    receipt_filename: str
    contract_path: Path
    contract_relative: str
    authority: dict[str, dict[str, object]]
    sdk_sources: dict[str, bytes]
    workspace_sources: dict[str, bytes]
    producer_declared: bool
    honey: bool


@dataclass(frozen=True)
class BuiltPackage:
    entries: tuple[PackageEntry, ...]
    tools: tuple[dict[str, object], ...]
    dependency_snapshot: dict[str, object]
    lock_validation: dict[str, object]
    npm_pack: dict[str, object]
    smoke_probe: dict[str, object]
    clean_install_validation: dict[str, object]


PackageBuilder = Callable[
    [BuildConfiguration, dict[str, Any], int, Path, argparse.Namespace], BuiltPackage
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
    parser.add_argument("--node", type=Path)
    parser.add_argument("--pnpm", type=Path)
    parser.add_argument("--npm", type=Path)
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
            "the development TypeScript SDK producer requires Apple-silicon macOS; "
            f"observed platform={sys.platform} architecture={machine}"
        )
    return {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": platform.mac_ver()[0],
    }


def _read_stable_file(
    path: Path,
    maximum: int,
    label: str,
    *,
    allow_empty: bool = False,
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


def _authority_digests(
    root: Path, paths: tuple[str, ...] = AUTHORITY_PATHS
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for relative in paths:
        payload = _read_stable_file(
            root.joinpath(*relative.split("/")), MAX_SOURCE_BYTES, relative
        )
        records[relative] = {"sha256": sha256_bytes(payload), "bytes": len(payload)}
    return records


def _read_source_set(
    root: Path, relatives: frozenset[str], label: str
) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    aliases: set[str] = set()
    for relative in sorted(relatives, key=lambda value: value.encode("utf-8")):
        canonical = safe_relative_path(relative)
        alias = unicodedata.normalize("NFC", canonical).casefold()
        if alias in aliases:
            raise ReleaseError(f"{label} source paths have a portable collision")
        aliases.add(alias)
        sources[canonical] = _read_stable_file(
            root.joinpath(*canonical.split("/")),
            MAX_SOURCE_BYTES,
            f"{label} {canonical}",
        )
    return sources


def _validate_source_inventory(sdk_root: Path) -> None:
    actual_typescript: set[str] = set()
    for path in (sdk_root / "src").rglob("*"):
        if path.is_symlink():
            raise ReleaseError(f"TypeScript SDK source contains a symlink: {path}")
        if path.is_file() and path.suffix == ".ts":
            actual_typescript.add(path.relative_to(sdk_root).as_posix())
    if actual_typescript != SOURCE_TYPESCRIPT_PATHS:
        raise ReleaseError("TypeScript SDK source module inventory differs from review")

    exact_directories = {
        "fixtures": {"fixtures/semantic-bundle-v1.json"},
        "tools": {"tools/inline-sources.mjs"},
    }
    for directory, expected in exact_directories.items():
        actual: set[str] = set()
        for path in (sdk_root / directory).rglob("*"):
            if path.is_symlink():
                raise ReleaseError(f"TypeScript SDK {directory} contains a symlink")
            if path.is_file():
                actual.add(path.relative_to(sdk_root).as_posix())
        if actual != expected:
            raise ReleaseError(
                f"TypeScript SDK {directory} inventory differs from review"
            )


def _expected_package_paths() -> frozenset[str]:
    paths = {
        "package/package.json",
        "package/README.md",
        "package/LICENSE",
        "package/NOTICE",
        "package/fixtures/semantic-bundle-v1.json",
        "package/dist/release.json",
    }
    for module in PACKAGED_MODULES:
        for suffix in (".d.ts", ".d.ts.map", ".js", ".js.map"):
            paths.add(f"package/dist/{module}{suffix}")
    return frozenset(paths)


EXPECTED_PACKAGE_PATHS = _expected_package_paths()


def _is_honey_product(product: Any) -> bool:
    return (
        isinstance(product, dict)
        and product.get("release_state") == "developer-preview"
        and product.get("channel") == "honey"
        and isinstance(product.get("version"), str)
        and product.get("tag") == f"v{product['version']}"
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
        "marketing_name": "CIGAR Honey v0.9.1",
        "prerelease": True,
        "product_version": version,
        "production_qualified": False,
        "published": False,
        "python_distribution_version": python_version,
        "release_state": "developer-preview",
        "supported": False,
        "tag": f"v{version}",
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
        or "typescript-direct-tarball" not in profile.get("integrations", [])
        or not any(
            isinstance(capability, dict)
            and capability.get("id") == "typescript-sdk"
            and capability.get("status") == "required"
            and capability.get("support_level") == "developer-preview"
            for capability in profile.get("capabilities", [])
        )
    ):
        raise ReleaseError(
            "Honey TypeScript capability authority is incomplete or stale"
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
    sdk_root = root / SDK_RELATIVE
    _validate_source_inventory(sdk_root)
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
    contract = load_json(root / "packaging/contracts/npm-package.v1.json")
    package = load_json(sdk_root / "package.json")
    release = load_json(sdk_root / "release.json")
    workspace = load_json(root / "package.json")

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
    expected_filename = f"cigar-sdk-{version}.tgz"

    if honey:
        _validate_honey_authority(product, matrix, profile, requirements, authority)
        matching = [
            row
            for row in matrix["artifacts"]
            if isinstance(row, dict) and row.get("id") == ARTIFACT_ID
        ]
        expected_artifact = {
            "contract": "packaging/contracts/npm-package.v1.json",
            "filename": expected_filename,
            "generated_by_assembler": False,
            "id": ARTIFACT_ID,
            "kind": "npm-tarball",
            "order": 5,
            "producer": PRODUCER_ARGV,
            "public_attachment": True,
            "qualification_gate_ids": ["sdk-clean-installs", "archive-contracts"],
            "receipt": {
                "filename": "typescript-sdk-build-receipt.json",
                "required": True,
                "schema_version": "cigar.development-typescript-sdk-build.v1",
            },
            "required": True,
            "sha256_required": True,
            "workspace": "typescript",
        }
        if len(matching) != 1 or matching[0] != expected_artifact:
            raise ReleaseError(
                "TypeScript SDK Honey artifact row is incomplete or stale"
            )
        artifact = matching[0]
        receipt_filename = artifact["receipt"]["filename"]
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
            row
            for row in matrix["artifacts"]
            if isinstance(row, dict) and row.get("id") == ARTIFACT_ID
        ]
        if len(matching) != 1:
            raise ReleaseError(
                f"artifact matrix must contain exactly one {ARTIFACT_ID} row"
            )
        artifact = matching[0]
        if (
            artifact.get("kind") != "npm-package"
            or artifact.get("filename") != expected_filename
            or artifact.get("contract") != "contracts/npm-package.v1.json"
            or artifact.get("ecosystem") != "npm"
            or artifact.get("required_for_release") is not True
            or artifact.get("producer") != PRODUCER
        ):
            raise ReleaseError("TypeScript SDK artifact row is incomplete or stale")

        selected = (
            profile.get("selected_artifacts") if isinstance(profile, dict) else None
        )
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
            not isinstance(profile, dict)
            or profile.get("schema_version") != "cigar.development-artifact-profile.v1"
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
                "development macOS profile does not keep the SDK unclaimed"
            )
        receipt_filename = BUILD_RECEIPT

    expected_package_files = [
        "dist/",
        "fixtures/",
        "README.md",
        "LICENSE",
        "NOTICE",
    ]
    expected_dependencies = {"@bufbuild/protobuf": "2.12.1"}
    expected_dev_dependencies = {
        "@bufbuild/protoc-gen-es": "2.12.1",
        "@types/node": "24.10.0",
        "typescript": "7.0.2",
    }
    lifecycle_scripts = ("preinstall", "install", "postinstall", "prepare")
    if (
        not isinstance(package, dict)
        or package.get("name") != "@cigar/sdk"
        or package.get("version") != version
        or package.get("license") != "Apache-2.0"
        or package.get("type") != "module"
        or package.get("packageManager") != "pnpm@10.34.5"
        or package.get("engines") != {"node": ">=24.10.0 <25"}
        or package.get("files") != expected_package_files
        or package.get("sideEffects") is not False
        or package.get("dependencies") != expected_dependencies
        or package.get("devDependencies") != expected_dev_dependencies
        or not isinstance(package.get("scripts"), dict)
        or any(name in package["scripts"] for name in lifecycle_scripts)
        or package["scripts"].get("build")
        != "pnpm run clean && tsc && node tools/inline-sources.mjs && node -e \"require('node:fs').copyFileSync('release.json','dist/release.json')\""
        or package["scripts"].get("prepack")
        != "pnpm run build && node -e \"require('node:fs').rmSync('dist/tests',{recursive:true,force:true})\""
    ):
        raise ReleaseError("TypeScript SDK package authority is stale or unsafe")
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": "@cigar/sdk",
        "version": version,
        "context_abi": context_abi,
    }:
        raise ReleaseError("TypeScript SDK release identity is stale")
    if (
        not isinstance(workspace, dict)
        or workspace.get("private") is not True
        or workspace.get("packageManager") != "pnpm@10.34.5"
        or workspace.get("engines") != {"node": ">=24.0.0 <25", "pnpm": "10.34.5"}
    ):
        raise ReleaseError("npm workspace package-manager authority is stale")

    expected_contract = {
        "formats": ["tar.gz"],
        "allow": [
            "package/package.json",
            "package/README.md",
            "package/LICENSE",
            "package/NOTICE",
            "package/dist/**",
            "package/fixtures/**",
        ],
        "required": [
            "package/package.json",
            "package/README.md",
            "package/LICENSE",
            "package/NOTICE",
            "package/dist/release.json",
        ],
        "required_patterns": ["package/dist/*.js", "package/dist/*.d.ts"],
        "version_binding": {
            "path_pattern": "package/package.json",
            "format": "json",
            "json_pointer": "/version",
        },
        "abi_binding": {
            "path_pattern": "package/dist/release.json",
            "format": "json",
            "json_pointer": "/context_abi",
        },
    }
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id") != "npm-package-v1"
        or any(contract.get(key) != value for key, value in expected_contract.items())
        or contract.get("symlinks") != "forbid"
        or contract.get("line_endings") != "lf"
        or contract.get("content_scan") is not True
        or "**/node_modules/**" not in contract.get("deny", [])
        or "**/src/**" not in contract.get("deny", [])
        or "**/tests/**" not in contract.get("deny", [])
    ):
        raise ReleaseError("npm package contract does not cover the exact SDK payload")

    sdk_sources = _read_source_set(sdk_root, SDK_BUILD_SOURCE_PATHS, "SDK source")
    workspace_sources = _read_source_set(
        root, WORKSPACE_SOURCE_PATHS, "workspace source"
    )
    for relative, payload in sdk_sources.items():
        if relative.endswith((".ts", ".mjs", ".json", ".md")) or relative in {
            "LICENSE",
            "NOTICE",
        }:
            if b"\r" in payload or not payload.endswith(b"\n"):
                raise ReleaseError(
                    f"TypeScript SDK source is not canonical LF text: {relative}"
                )

    return BuildConfiguration(
        root=root,
        sdk_root=sdk_root,
        version=version,
        context_abi=context_abi,
        filename=expected_filename,
        receipt_filename=receipt_filename,
        contract_path=root / "packaging/contracts/npm-package.v1.json",
        contract_relative="packaging/contracts/npm-package.v1.json",
        authority=authority,
        sdk_sources=sdk_sources,
        workspace_sources=workspace_sources,
        producer_declared=True,
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
                "packaging/contracts/npm-package.v1.json",
            ]
        )
    files = expand_files(root, includes, list(SOURCE_EXCLUDES))
    if not files:
        raise ReleaseError("TypeScript SDK build source inventory is empty")
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
        raise ReleaseError(
            "TypeScript SDK build requires a committed Git source identity"
        )
    return identity


def _secure_tool(value: Path | None, name: str) -> Path:
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
        or not os.access(resolved, os.X_OK)
    ):
        raise ReleaseError(f"{name} must resolve to an owner-controlled executable")
    return resolved


def _run(arguments: list[str], *, cwd: Path, env: dict[str, str], label: str) -> bytes:
    result = run_bounded(
        arguments,
        cwd=cwd,
        env=env,
        timeout=300,
        max_stdout=MAX_COMMAND_OUTPUT,
        max_stderr=MAX_COMMAND_OUTPUT,
    )
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, label))
    return result.stdout


def _tool_record(path: Path, name: str, version: str) -> dict[str, object]:
    payload = _read_stable_file(path, MAX_DEPENDENCY_FILE_BYTES, f"{name} executable")
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _private_build_environment(scratch: Path, node: Path, epoch: int) -> dict[str, str]:
    home = scratch / "home"
    temporary = scratch / "tmp"
    cache = scratch / "npm-cache"
    for directory in (home, temporary, cache):
        directory.mkdir(mode=0o700)
    return {
        "PATH": f"{node.parent}:/usr/bin:/bin",
        "HOME": os.fspath(home),
        "TMPDIR": os.fspath(temporary),
        "npm_config_cache": os.fspath(cache),
        "npm_config_offline": "true",
        "NPM_CONFIG_OFFLINE": "true",
        "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
        "COREPACK_ENABLE_NETWORK": "0",
        "CI": "1",
        "NO_COLOR": "1",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _write_private(path: Path, payload: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite staged build input: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o700 if executable else 0o600)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise ReleaseError(f"short write while staging {path}")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stage_sources(configuration: BuildConfiguration, stage: Path) -> Path:
    stage.mkdir(mode=0o700)
    for relative, payload in configuration.workspace_sources.items():
        _write_private(stage.joinpath(*relative.split("/")), payload)
    sdk_stage = stage / SDK_RELATIVE
    for relative, payload in configuration.sdk_sources.items():
        _write_private(sdk_stage.joinpath(*relative.split("/")), payload)
    return sdk_stage


def _dependency_files(root: Path, spec: DependencySpec) -> list[tuple[str, Path, int]]:
    source = root.joinpath(*spec.source_relative.split("/"))
    try:
        resolved = source.resolve(strict=True)
        node_modules = (root / "node_modules").resolve(strict=True)
    except OSError as error:
        raise ReleaseError(
            f"locked build dependency is unavailable: {spec.name}: {error}"
        ) from error
    if os.path.commonpath((os.fspath(resolved), os.fspath(node_modules))) != os.fspath(
        node_modules
    ):
        raise ReleaseError(f"locked build dependency escapes node_modules: {spec.name}")
    if source.is_symlink() or not resolved.is_dir():
        raise ReleaseError(f"locked build dependency path is unsafe: {spec.name}")
    package = load_json(resolved / "package.json")
    if (
        not isinstance(package, dict)
        or package.get("name") != spec.name
        or package.get("version") != spec.version
    ):
        raise ReleaseError(f"locked build dependency identity is stale: {spec.name}")

    files: list[tuple[str, Path, int]] = []
    for current, directories, names in os.walk(
        resolved, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        for directory in sorted(directories):
            if (current_path / directory).is_symlink():
                raise ReleaseError(
                    f"locked build dependency contains a symlink: {spec.name}"
                )
        for name in sorted(names):
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise ReleaseError(
                    f"locked build dependency contains an unsafe file: {spec.name}"
                )
            relative = path.relative_to(resolved).as_posix()
            safe_relative_path(relative)
            mode = 0o700 if os.access(path, os.X_OK) else 0o600
            files.append((relative, path, mode))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    if not files:
        raise ReleaseError(f"locked build dependency is empty: {spec.name}")
    return files


def _dependency_identity(root: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    total = 0
    count = 0
    packages: list[dict[str, str]] = []
    for spec in DEPENDENCY_SPECS:
        packages.append({"name": spec.name, "version": spec.version})
        for relative, path, mode in _dependency_files(root, spec):
            payload = _read_stable_file(
                path,
                MAX_DEPENDENCY_FILE_BYTES,
                f"locked dependency {spec.name}/{relative}",
                allow_empty=True,
            )
            total += len(payload)
            count += 1
            if total > MAX_DEPENDENCY_TREE_BYTES or count > 50_000:
                raise ReleaseError("locked build dependency tree exceeds its bounds")
            destination = f"{spec.destination_relative}/{relative}"
            digest.update(destination.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(len(payload)).encode("ascii"))
            digest.update(b"\0")
            digest.update(f"{mode:04o}".encode("ascii"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(payload).digest())
            digest.update(b"\n")
    return {
        "schema_version": "cigar.npm-build-dependencies.v1",
        "packages": packages,
        "file_count": count,
        "bytes": total,
        "tree_sha256": digest.hexdigest(),
    }


def _copy_dependencies(root: Path, sdk_stage: Path) -> None:
    destination_root = sdk_stage / "node_modules"
    destination_root.mkdir(mode=0o700)
    for spec in DEPENDENCY_SPECS:
        for relative, path, mode in _dependency_files(root, spec):
            payload = _read_stable_file(
                path,
                MAX_DEPENDENCY_FILE_BYTES,
                f"locked dependency {spec.name}/{relative}",
                allow_empty=True,
            )
            _write_private(
                destination_root.joinpath(
                    *spec.destination_relative.split("/"), *relative.split("/")
                ),
                payload,
                executable=mode == 0o700,
            )


def _read_npm_pack(path: Path) -> tuple[PackageEntry, ...]:
    raw = _read_stable_file(path, MAX_ARCHIVE_BYTES, "raw npm pack archive")
    entries: dict[str, PackageEntry] = {}
    aliases: set[str] = set()
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 1_000:
                raise ReleaseError("raw npm pack archive member count is invalid")
            for member in members:
                if (
                    not member.isfile()
                    or member.size <= 0
                    or member.size > MAX_ARCHIVE_MEMBER_BYTES
                ):
                    raise ReleaseError(f"raw npm pack member is unsafe: {member.name}")
                relative = safe_relative_path(member.name)
                alias = unicodedata.normalize("NFC", relative).casefold()
                if relative in entries or alias in aliases:
                    raise ReleaseError(f"raw npm pack path collides: {relative}")
                aliases.add(alias)
                expanded += member.size
                if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise ReleaseError(
                        "raw npm pack archive exceeds expanded-byte limit"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseError(f"cannot read raw npm pack member: {relative}")
                payload = handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(payload) != member.size:
                    raise ReleaseError(
                        f"raw npm pack member length differs: {relative}"
                    )
                entries[relative] = PackageEntry(relative, payload)
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ReleaseError(f"cannot parse raw npm pack archive: {error}") from error
    if set(entries) != EXPECTED_PACKAGE_PATHS:
        raise ReleaseError(
            "raw npm pack contents differ from the exact reviewed SDK package inventory"
        )
    return tuple(
        entries[path]
        for path in sorted(entries, key=lambda value: value.encode("utf-8"))
    )


def _qualify_clean_install(
    configuration: BuildConfiguration,
    archive: Path,
    entries: tuple[PackageEntry, ...],
    node: Path,
    npm: Path,
    environment: dict[str, str],
    scratch: Path,
) -> dict[str, object]:
    dependency = DEPENDENCY_SPECS[2]
    if dependency.name != "@bufbuild/protobuf":
        raise ReleaseError("TypeScript SDK runtime dependency specification differs")
    dependency_source = configuration.root.joinpath(
        *dependency.source_relative.split("/")
    ).resolve(strict=True)
    dependency_archives = scratch / "clean-install-dependencies"
    dependency_archives.mkdir(mode=0o700)
    packed_name = (
        _run(
            [
                os.fspath(node),
                os.fspath(npm),
                "pack",
                "--silent",
                "--offline",
                "--ignore-scripts",
                "--pack-destination",
                os.fspath(dependency_archives),
                os.fspath(dependency_source),
            ],
            cwd=scratch,
            env=environment,
            label="local TypeScript runtime dependency pack",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if re.fullmatch(r"bufbuild-protobuf-2\.12\.1\.tgz", packed_name) is None:
        raise ReleaseError("npm packed an unexpected TypeScript runtime dependency")
    dependency_archive = dependency_archives / packed_name
    if {path.name for path in dependency_archives.iterdir()} != {packed_name}:
        raise ReleaseError("npm produced an unexpected runtime dependency inventory")
    dependency_payload = _read_stable_file(
        dependency_archive,
        MAX_ARCHIVE_BYTES,
        "packed TypeScript runtime dependency",
    )

    consumer = scratch / "clean-installed-consumer"
    consumer.mkdir(mode=0o700)
    _write_private(
        consumer / "package.json",
        canonical_json_bytes(
            {
                "name": "cigar-sdk-install-qualification",
                "version": "0.0.0",
                "private": True,
                "type": "module",
            }
        ),
    )
    _run(
        [
            os.fspath(node),
            os.fspath(npm),
            "install",
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
            os.fspath(archive),
            os.fspath(dependency_archive),
        ],
        cwd=consumer,
        env=environment,
        label="offline clean TypeScript SDK install",
    )
    installed_modules = (consumer / "node_modules").resolve(strict=True)
    installed_sdk = consumer / "node_modules/@cigar/sdk"
    installed_dependency = consumer / "node_modules/@bufbuild/protobuf"
    for path, label in (
        (installed_sdk, "installed TypeScript SDK"),
        (installed_dependency, "installed TypeScript runtime dependency"),
    ):
        if path.is_symlink() or not path.is_dir():
            raise ReleaseError(f"{label} is not a materialized package directory")
        resolved = path.resolve(strict=True)
        if os.path.commonpath(
            (os.fspath(resolved), os.fspath(installed_modules))
        ) != os.fspath(installed_modules):
            raise ReleaseError(f"{label} escaped the clean node_modules tree")
    if (
        _read_stable_file(
            installed_sdk / "package.json", MAX_SOURCE_BYTES, "installed package.json"
        )
        != configuration.sdk_sources["package.json"]
        or _read_stable_file(
            installed_sdk / "dist/release.json",
            MAX_SOURCE_BYTES,
            "installed release.json",
        )
        != configuration.sdk_sources["release.json"]
        or _read_stable_file(
            installed_sdk / "LICENSE", MAX_SOURCE_BYTES, "installed LICENSE"
        )
        != configuration.sdk_sources["LICENSE"]
        or _read_stable_file(
            installed_sdk / "NOTICE", MAX_SOURCE_BYTES, "installed NOTICE"
        )
        != configuration.sdk_sources["NOTICE"]
    ):
        raise ReleaseError("clean-installed TypeScript SDK bytes differ from authority")
    identity = (
        _run(
            [
                os.fspath(node),
                os.fspath(installed_sdk / "dist/examples/quickstart.js"),
            ],
            cwd=consumer,
            env=environment,
            label="clean-installed TypeScript SDK semantic workflow",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if identity != EXPECTED_QUICKSTART_IDENTITY:
        raise ReleaseError("clean-installed TypeScript SDK identity differs")
    _run(
        [
            os.fspath(node),
            "--input-type=module",
            "--eval",
            "import {CigarClient,CONTEXT_ABI} from '@cigar/sdk';"
            "if(CONTEXT_ABI!=='cigar.context.v1')throw new Error('ABI drift');"
            "new CigarClient({baseUrl:'http://localhost',allowInsecureLoopback:true});",
        ],
        cwd=consumer,
        env=environment,
        label="clean-installed TypeScript SDK public import",
    )
    return {
        "schema_version": "cigar.typescript-sdk-clean-install.v1",
        "status": "passed-semantic-workflow",
        "offline": True,
        "scripts": False,
        "dependency_mode": "local-reviewed-package-archive",
        "package": f"@cigar/sdk@{configuration.version}",
        "package_payload_tree_sha256": _payload_tree(entries),
        "dependency": {
            "name": dependency.name,
            "version": dependency.version,
            "sha256": sha256_bytes(dependency_payload),
            "bytes": len(dependency_payload),
        },
        "semantic_bundle_identity": identity,
        "checks": {
            "materialized-package": "passed",
            "public-import": "passed",
            "release-assets": "passed",
            "semantic-workflow": "passed",
        },
    }


def _default_package_builder(
    configuration: BuildConfiguration,
    _source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltPackage:
    node = _secure_tool(arguments.node, "node")
    pnpm_default = Path.home() / ".cache/node/corepack/v1/pnpm/10.34.5/bin/pnpm.cjs"
    pnpm = _secure_tool(arguments.pnpm or pnpm_default, "pnpm")
    npm = _secure_tool(arguments.npm, "npm")
    environment = _private_build_environment(scratch, node, epoch)
    stage = scratch / "workspace"
    sdk_stage = _stage_sources(configuration, stage)

    node_version = (
        _run(
            [os.fspath(node), "--version"],
            cwd=stage,
            env=environment,
            label="Node version probe",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    pnpm_version = (
        _run(
            [os.fspath(node), os.fspath(pnpm), "--version"],
            cwd=stage,
            env=environment,
            label="pnpm version probe",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    npm_version = (
        _run(
            [os.fspath(node), os.fspath(npm), "--version"],
            cwd=stage,
            env=environment,
            label="npm version probe",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if (
        node_version != "v24.10.0"
        or pnpm_version != "10.34.5"
        or npm_version != "11.6.0"
    ):
        raise ReleaseError(
            "TypeScript SDK build tool versions differ from the frozen macOS cohort"
        )

    _run(
        [
            os.fspath(node),
            os.fspath(pnpm),
            "install",
            "--offline",
            "--frozen-lockfile",
            "--lockfile-only",
            "--ignore-scripts",
        ],
        cwd=stage,
        env=environment,
        label="offline frozen pnpm lock validation",
    )
    for relative, payload in configuration.workspace_sources.items():
        observed = _read_stable_file(
            stage.joinpath(*relative.split("/")), MAX_SOURCE_BYTES, f"staged {relative}"
        )
        if observed != payload:
            raise ReleaseError(
                f"pnpm lock validation changed staged source: {relative}"
            )
    observed_package = _read_stable_file(
        sdk_stage / "package.json", MAX_SOURCE_BYTES, "staged SDK package.json"
    )
    if observed_package != configuration.sdk_sources["package.json"]:
        raise ReleaseError("pnpm lock validation changed staged SDK package authority")
    generated_root_modules = stage / "node_modules"
    if generated_root_modules.exists():
        if generated_root_modules.is_symlink() or not generated_root_modules.is_dir():
            raise ReleaseError(
                "pnpm lock validation created an unsafe node_modules path"
            )
        shutil.rmtree(generated_root_modules)

    dependency_before = _dependency_identity(configuration.root)
    _copy_dependencies(configuration.root, sdk_stage)
    dependency_after_copy = _dependency_identity(configuration.root)
    if dependency_after_copy != dependency_before:
        raise ReleaseError("locked build dependencies changed while they were staged")

    _run(
        [
            os.fspath(node),
            os.fspath(sdk_stage / "node_modules/typescript/bin/tsc"),
            "--project",
            "tsconfig.json",
        ],
        cwd=sdk_stage,
        env=environment,
        label="TypeScript compilation",
    )
    _run(
        [os.fspath(node), "tools/inline-sources.mjs"],
        cwd=sdk_stage,
        env=environment,
        label="TypeScript source-map inlining",
    )
    release_payload = configuration.sdk_sources["release.json"]
    _write_private(sdk_stage / "dist/release.json", release_payload)
    tests_output = sdk_stage / "dist/tests"
    if not tests_output.is_dir() or tests_output.is_symlink():
        raise ReleaseError(
            "TypeScript compilation did not produce its expected test output"
        )
    shutil.rmtree(tests_output)

    smoke = (
        _run(
            [os.fspath(node), "dist/examples/quickstart.js"],
            cwd=sdk_stage,
            env=environment,
            label="TypeScript SDK build smoke probe",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if smoke != EXPECTED_QUICKSTART_IDENTITY:
        raise ReleaseError("TypeScript SDK build smoke identity differs")

    raw_output = scratch / "npm-pack"
    raw_output.mkdir(mode=0o700)
    _run(
        [
            os.fspath(node),
            os.fspath(npm),
            "pack",
            "--ignore-scripts",
            "--pack-destination",
            os.fspath(raw_output),
        ],
        cwd=sdk_stage,
        env=environment,
        label="npm pack",
    )
    raw_archive = raw_output / configuration.filename
    if set(path.name for path in raw_output.iterdir()) != {configuration.filename}:
        raise ReleaseError(
            "npm pack did not create exactly the expected package archive"
        )
    entries = _read_npm_pack(raw_archive)
    clean_install_validation = _qualify_clean_install(
        configuration,
        raw_archive,
        entries,
        node,
        npm,
        environment,
        scratch,
    )
    dependency_after = _dependency_identity(configuration.root)
    if dependency_after != dependency_before:
        raise ReleaseError("locked build dependencies changed during the SDK build")

    typescript_compiler = configuration.root.joinpath(
        *DEPENDENCY_SPECS[1].source_relative.split("/"), "lib", "tsc"
    )
    pnpm_bundle = pnpm.parent.parent / "dist/pnpm.cjs"
    return BuiltPackage(
        entries=entries,
        tools=(
            _tool_record(node, "node", node_version),
            _tool_record(pnpm_bundle, "pnpm", pnpm_version),
            _tool_record(npm, "npm", npm_version),
            _tool_record(typescript_compiler, "typescript", "7.0.2"),
        ),
        dependency_snapshot=dependency_before,
        lock_validation={
            "package_manager": "pnpm@10.34.5",
            "mode": "offline-frozen-lockfile-only",
            "scripts": False,
            "status": "passed",
        },
        npm_pack={
            "package_manager": "npm@11.6.0",
            "ignore_scripts": True,
            "raw_file_count": len(entries),
            "status": "passed",
        },
        smoke_probe={
            "command": "node dist/examples/quickstart.js",
            "identity": smoke,
            "status": "passed",
        },
        clean_install_validation=clean_install_validation,
    )


def _validate_built_package(
    package: BuiltPackage, configuration: BuildConfiguration
) -> None:
    if not isinstance(package, BuiltPackage):
        raise ReleaseError("TypeScript SDK package builder returned an invalid result")
    paths: set[str] = set()
    aliases: set[str] = set()
    for entry in package.entries:
        path = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", path).casefold()
        if path in paths or alias in aliases:
            raise ReleaseError(f"TypeScript SDK package path collides: {path}")
        if (
            entry.mode != 0o644
            or not entry.payload
            or len(entry.payload) > MAX_ARCHIVE_MEMBER_BYTES
        ):
            raise ReleaseError(f"TypeScript SDK package entry is invalid: {path}")
        paths.add(path)
        aliases.add(alias)
    if paths != EXPECTED_PACKAGE_PATHS:
        raise ReleaseError(
            "TypeScript SDK package inventory differs from the exact allowlist"
        )
    by_path = {entry.path: entry.payload for entry in package.entries}
    if by_path["package/package.json"] != configuration.sdk_sources["package.json"]:
        raise ReleaseError("packed TypeScript SDK package.json differs from authority")
    if (
        by_path["package/dist/release.json"]
        != configuration.sdk_sources["release.json"]
    ):
        raise ReleaseError(
            "packed TypeScript SDK release identity differs from authority"
        )
    if by_path["package/README.md"] != configuration.sdk_sources["README.md"]:
        raise ReleaseError("packed TypeScript SDK README differs from source")
    if by_path["package/LICENSE"] != configuration.sdk_sources["LICENSE"]:
        raise ReleaseError("packed TypeScript SDK license differs from source")
    if by_path["package/NOTICE"] != configuration.sdk_sources["NOTICE"]:
        raise ReleaseError("packed TypeScript SDK notice differs from source")
    if (
        by_path["package/fixtures/semantic-bundle-v1.json"]
        != configuration.sdk_sources["fixtures/semantic-bundle-v1.json"]
    ):
        raise ReleaseError("packed TypeScript SDK fixture differs from source")

    for path, payload in by_path.items():
        if path.endswith(".map"):
            document = load_json_bytes(payload, path)
            if (
                not isinstance(document, dict)
                or not isinstance(document.get("sources"), list)
                or not document["sources"]
                or not isinstance(document.get("sourcesContent"), list)
                or len(document["sources"]) != len(document["sourcesContent"])
                or not all(
                    isinstance(value, str) for value in document["sourcesContent"]
                )
            ):
                raise ReleaseError(
                    f"packed source map lacks inline source content: {path}"
                )

    if not package.tools or any(
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
        for record in package.tools
    ):
        raise ReleaseError("TypeScript SDK build tool identity is incomplete")
    dependency = package.dependency_snapshot
    if (
        not isinstance(dependency, dict)
        or dependency.get("schema_version") != "cigar.npm-build-dependencies.v1"
        or not isinstance(dependency.get("packages"), list)
        or dependency.get("file_count", 0) <= 0
        or dependency.get("bytes", 0) <= 0
        or not isinstance(dependency.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", dependency["tree_sha256"]) is None
    ):
        raise ReleaseError("TypeScript SDK dependency snapshot is incomplete")
    if package.lock_validation != {
        "package_manager": "pnpm@10.34.5",
        "mode": "offline-frozen-lockfile-only",
        "scripts": False,
        "status": "passed",
    }:
        raise ReleaseError("TypeScript SDK lock validation is incomplete")
    if package.npm_pack != {
        "package_manager": "npm@11.6.0",
        "ignore_scripts": True,
        "raw_file_count": len(package.entries),
        "status": "passed",
    }:
        raise ReleaseError("TypeScript SDK npm pack validation is incomplete")
    if package.smoke_probe != {
        "command": "node dist/examples/quickstart.js",
        "identity": EXPECTED_QUICKSTART_IDENTITY,
        "status": "passed",
    }:
        raise ReleaseError("TypeScript SDK smoke probe is incomplete")
    clean_install = package.clean_install_validation
    dependency = (
        clean_install.get("dependency") if isinstance(clean_install, dict) else None
    )
    if (
        not isinstance(clean_install, dict)
        or set(clean_install)
        != {
            "schema_version",
            "status",
            "offline",
            "scripts",
            "dependency_mode",
            "package",
            "package_payload_tree_sha256",
            "dependency",
            "semantic_bundle_identity",
            "checks",
        }
        or clean_install.get("schema_version")
        != "cigar.typescript-sdk-clean-install.v1"
        or clean_install.get("status") != "passed-semantic-workflow"
        or clean_install.get("offline") is not True
        or clean_install.get("scripts") is not False
        or clean_install.get("dependency_mode") != "local-reviewed-package-archive"
        or clean_install.get("package") != f"@cigar/sdk@{configuration.version}"
        or clean_install.get("package_payload_tree_sha256")
        != _payload_tree(package.entries)
        or not isinstance(dependency, dict)
        or set(dependency) != {"name", "version", "sha256", "bytes"}
        or dependency.get("name") != "@bufbuild/protobuf"
        or dependency.get("version") != "2.12.1"
        or re.fullmatch(r"[0-9a-f]{64}", str(dependency.get("sha256"))) is None
        or not isinstance(dependency.get("bytes"), int)
        or isinstance(dependency["bytes"], bool)
        or dependency["bytes"] <= 0
        or clean_install.get("semantic_bundle_identity") != EXPECTED_QUICKSTART_IDENTITY
        or clean_install.get("checks")
        != {
            "materialized-package": "passed",
            "public-import": "passed",
            "release-assets": "passed",
            "semantic-workflow": "passed",
        }
    ):
        raise ReleaseError("TypeScript SDK clean-install validation is incomplete")


def _payload_tree(entries: tuple[PackageEntry, ...]) -> str:
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


def _write_archive(path: Path, entries: tuple[PackageEntry, ...], epoch: int) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseError(
            f"refusing to overwrite staged TypeScript SDK archive: {path}"
        )
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
                        entries, key=lambda item: item.path.encode("utf-8")
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


def produce(
    arguments: argparse.Namespace,
    *,
    package_builder: PackageBuilder = _default_package_builder,
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
        with tempfile.TemporaryDirectory(prefix="cigar-typescript-sdk-build-") as raw:
            scratch = Path(raw).resolve(strict=True)
            # Unpublished package bytes and clean-install caches must remain owner-only.
            # fmt: off
            os.chmod(scratch, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            # fmt: on
            package = package_builder(
                configuration, source_before, epoch, scratch, arguments
            )
            _validate_built_package(package, configuration)
            if _dependency_identity(root) != package.dependency_snapshot:
                raise ReleaseError(
                    "locked build dependencies changed after construction"
                )
            if _source_identity(root) != source_before:
                raise ReleaseError(
                    "TypeScript SDK build source changed during construction"
                )
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError(
                    "TypeScript SDK build authority changed during construction"
                )

            staged_archive = scratch / configuration.filename
            _write_archive(staged_archive, package.entries, epoch)
            validated = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "staged TypeScript SDK archive"
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
            if _dependency_identity(root) != package.dependency_snapshot:
                raise ReleaseError(
                    "locked build dependencies changed during verification"
                )
            if _source_identity(root) != source_before:
                raise ReleaseError(
                    "TypeScript SDK build source changed during verification"
                )
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError(
                    "TypeScript SDK build authority changed during verification"
                )
            verified = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "verified TypeScript SDK archive"
            )
            if (
                len(verified) != validated_bytes
                or sha256_bytes(verified) != validated_sha256
            ):
                raise ReleaseError(
                    "TypeScript SDK archive changed during package verification"
                )
            archive_reference = workspace.attach_file(
                staged_archive,
                configuration.filename,
                expected_sha256=validated_sha256,
                expected_bytes=validated_bytes,
            )

        contract_sha256 = str(
            configuration.authority[configuration.contract_relative]["sha256"]
        )
        receipt = {
            "schema_version": "cigar.development-typescript-sdk-build.v1",
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
            "producer_declared_in_artifact_matrix": configuration.producer_declared,
            "input_tree_sha256": _payload_tree(package.entries),
            "payload_file_count": len(package.entries),
            "build_tools": list(package.tools),
            "build_dependencies": package.dependency_snapshot,
            "lock_validation": package.lock_validation,
            "npm_pack": package.npm_pack,
            "smoke_probe": package.smoke_probe,
            "clean_install_validation": package.clean_install_validation,
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "claims": {
                "development_build": True,
                "registry_signature": False,
                "distribution_signed": False,
                "installed_compatibility": False,
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
        raise SystemExit(f"TypeScript SDK development build failed: {error}") from error
