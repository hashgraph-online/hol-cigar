#!/usr/bin/env python3
"""Build deterministic, unsigned Python SDK development distributions on macOS."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import unicodedata
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path
from typing import Any, Callable

from evidence_workspace import EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    expand_files,
    git_state,
    load_json,
    process_failure_summary,
    require_source_date_epoch,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    tree_digest,
)
from verify_package import verify as verify_package


SDIST_ARTIFACT_ID = "python-sdk-sdist"
WHEEL_ARTIFACT_ID = "python-sdk-wheel"
PRODUCER = "python3 scripts/release/build_python_sdk_artifacts.py"
PRODUCER_ARGV = ["python3", "scripts/release/build_python_sdk_artifacts.py"]
BUILD_RECEIPT = "python-sdk-development-build.json"
TARGET_TRIPLE = "aarch64-apple-darwin"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SDK_RELATIVE = "sdk/python"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
EXPECTED_QUICKSTART_IDENTITY = (
    "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"
)
AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/python-sdist.v1.json",
    "packaging/contracts/python-wheel.v1.json",
    f"{SDK_RELATIVE}/pyproject.toml",
    f"{SDK_RELATIVE}/uv.lock",
    f"{SDK_RELATIVE}/src/cigar_sdk/release.json",
)
HONEY_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
    "packaging/contracts/python-sdist.v1.json",
    "packaging/contracts/python-wheel.v1.json",
    f"{SDK_RELATIVE}/pyproject.toml",
    f"{SDK_RELATIVE}/uv.lock",
    f"{SDK_RELATIVE}/src/cigar_sdk/release.json",
)
SOURCE_INCLUDES = (
    ".gitignore",
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/python-sdist.v1.json",
    "packaging/contracts/python-wheel.v1.json",
    "sdk/fixtures/problem-index-unavailable-v1.json",
    "sdk/fixtures/semantic-bundle-v1.json",
    "sdk/python/**",
    "scripts/release/build_python_sdk_artifacts.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/verify_package.py",
)
SOURCE_EXCLUDES = (
    "**/.DS_Store",
    "**/__pycache__/**",
    "**/*.pyc",
    "sdk/python/.mypy_cache/**",
    "sdk/python/.pytest_cache/**",
    "sdk/python/.ruff_cache/**",
    "sdk/python/.venv/**",
    "sdk/python/dist/**",
)
STATIC_PACKAGE_PATHS = (
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "README.md",
    "pyproject.toml",
)


@dataclass(frozen=True)
class BuildConfiguration:
    root: Path
    sdk_root: Path
    version: str
    python_version: str
    context_abi: str
    sdist_filename: str
    wheel_filename: str
    receipt_filename: str
    contracts: dict[str, Path]
    authority: dict[str, dict[str, object]]
    source_assets: dict[str, bytes]
    lock_summary: dict[str, object]
    honey: bool


@dataclass(frozen=True)
class BuiltPackages:
    sdist: Path
    wheel: Path
    tools: tuple[dict[str, object], ...]
    build_policy: dict[str, object]
    clean_install_validation: dict[str, object]


PackageBuilder = Callable[
    [BuildConfiguration, dict[str, Any], int, Path, argparse.Namespace],
    BuiltPackages,
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
    parser.add_argument("--uv", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--uv-cache-dir", type=Path)
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
            "the development Python SDK producer requires Apple-silicon macOS; "
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
            root.joinpath(*relative.split("/")), MAX_SOURCE_BYTES, relative
        )
        records[relative] = {"sha256": sha256_bytes(payload), "bytes": len(payload)}
    return records


def _python_distribution_version(version: str) -> str:
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-dev\.([1-9][0-9]*)",
        version,
    )
    if match is None:
        match = re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-honey\.([1-9][0-9]*)",
            version,
        )
    if match is None:
        raise ReleaseError(
            "development or Honey product version cannot be normalized to PEP 440"
        )
    major, minor, patch, sequence = match.groups()
    return f"{major}.{minor}.{patch}.dev{sequence}"


def _expected_contracts(python_version: str) -> dict[str, dict[str, object]]:
    prefix = f"cigar_sdk-{python_version}"
    return {
        SDIST_ARTIFACT_ID: {
            "schema_version": "cigar.package-contract.v1",
            "id": "python-sdist-v1",
            "formats": ["tar.gz"],
            "allow": [
                f"{prefix}/.gitignore",
                f"{prefix}/README.md",
                f"{prefix}/LICENSE",
                f"{prefix}/NOTICE",
                f"{prefix}/pyproject.toml",
                f"{prefix}/src/**",
                f"{prefix}/tests/**",
                f"{prefix}/PKG-INFO",
            ],
            "deny": [
                "**/.git/**",
                "**/.env*",
                "**/*.key",
                "**/*.pem",
                "**/__pycache__/**",
                "**/.pytest_cache/**",
                "**/.mypy_cache/**",
                "**/*.pyc",
            ],
            "required": [
                f"{prefix}/.gitignore",
                f"{prefix}/README.md",
                f"{prefix}/LICENSE",
                f"{prefix}/NOTICE",
                f"{prefix}/pyproject.toml",
                f"{prefix}/src/cigar_sdk/release.json",
                f"{prefix}/PKG-INFO",
            ],
            "required_patterns": [f"{prefix}/src/cigar_sdk/*.py"],
            "symlinks": "forbid",
            "line_endings": "lf",
            "modes": ["0644", "0755"],
            "max_entries": 10_000,
            "max_member_bytes": 16_777_216,
            "max_total_bytes": 67_108_864,
            "content_scan": True,
            "content_scan_exemptions": [],
            "version_binding": {
                "path_pattern": f"{prefix}/src/cigar_sdk/release.json",
                "format": "json",
                "json_pointer": "/version",
            },
            "abi_binding": {
                "path_pattern": f"{prefix}/src/cigar_sdk/release.json",
                "format": "json",
                "json_pointer": "/context_abi",
            },
        },
        WHEEL_ARTIFACT_ID: {
            "schema_version": "cigar.package-contract.v1",
            "id": "python-wheel-v1",
            "formats": ["wheel"],
            "allow": ["cigar_sdk/**", f"{prefix}.dist-info/**"],
            "deny": [
                "**/.git/**",
                "**/.env*",
                "**/*.key",
                "**/*.pem",
                "**/__pycache__/**",
                "**/tests/**",
                "**/*.pyc",
            ],
            "required": [
                "cigar_sdk/release.json",
                f"{prefix}.dist-info/METADATA",
                f"{prefix}.dist-info/RECORD",
                f"{prefix}.dist-info/WHEEL",
            ],
            "required_patterns": [f"{prefix}.dist-info/licenses/*"],
            "symlinks": "forbid",
            "line_endings": "lf",
            "modes": ["0644", "0755"],
            "max_entries": 10_000,
            "max_member_bytes": 16_777_216,
            "max_total_bytes": 67_108_864,
            "content_scan": True,
            "content_scan_exemptions": [],
            "version_binding": {
                "path_pattern": "cigar_sdk/release.json",
                "format": "json",
                "json_pointer": "/version",
            },
            "abi_binding": {
                "path_pattern": "cigar_sdk/release.json",
                "format": "json",
                "json_pointer": "/context_abi",
            },
        },
    }


def _load_toml(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError(f"cannot parse {label}: {error}") from error
    if not isinstance(document, dict):
        raise ReleaseError(f"{label} is not a TOML table")
    return document


def _validate_pyproject(document: dict[str, Any], python_version: str) -> None:
    project = document.get("project")
    if (
        not isinstance(project, dict)
        or project.get("name") != "cigar-sdk"
        or project.get("version") != python_version
        or project.get("description") != "CIGAR v1 Python SDK"
        or project.get("readme") != "README.md"
        or project.get("license") != "Apache-2.0"
        or project.get("license-files") != ["LICENSE", "NOTICE"]
        or project.get("requires-python") != ">=3.14,<3.15"
        or project.get("dependencies") != ["protobuf==6.33.5"]
        or project.get("scripts")
        != {
            "cigar-agent-b-handoff": "cigar_sdk.examples.agent_b_handoff:main",
            "cigar-qualify-bundle": "cigar_sdk.qualify_bundle:main",
        }
    ):
        raise ReleaseError("Python project identity or runtime metadata is stale")
    if project.get("urls") != {
        "Homepage": "https://github.com/CIGAR/cigar",
        "Repository": "https://github.com/CIGAR/cigar",
    }:
        raise ReleaseError("Python project URL metadata is stale")
    if document.get("build-system") != {
        "requires": ["hatchling==1.28.0"],
        "build-backend": "hatchling.build",
    }:
        raise ReleaseError("Python build backend is not exactly pinned")
    hatch = document.get("tool", {}).get("hatch", {})
    if (
        not isinstance(hatch, dict)
        or hatch.get("build", {}).get("targets", {}).get("wheel")
        != {"packages": ["src/cigar_sdk"]}
        or hatch.get("build", {}).get("targets", {}).get("sdist")
        != {
            "include": [
                "src/cigar_sdk",
                "tests",
                "README.md",
                "LICENSE",
                "NOTICE",
                "pyproject.toml",
            ]
        }
    ):
        raise ReleaseError("Python Hatchling package targets are stale")


def _validate_lock(document: dict[str, Any], python_version: str) -> dict[str, object]:
    if (
        document.get("version") != 1
        or document.get("revision") != 3
        or document.get("requires-python") != "==3.14.*"
        or not isinstance(document.get("package"), list)
    ):
        raise ReleaseError("Python uv lock header is stale")
    packages = document["package"]
    sdk_rows = [
        row
        for row in packages
        if isinstance(row, dict) and row.get("name") == "cigar-sdk"
    ]
    protobuf_rows = [
        row
        for row in packages
        if isinstance(row, dict) and row.get("name") == "protobuf"
    ]
    expected_sdk = {
        "name": "cigar-sdk",
        "version": python_version,
        "source": {"editable": "."},
        "dependencies": [{"name": "protobuf"}],
        "dev-dependencies": {
            "dev": [{"name": "mypy"}, {"name": "pytest"}, {"name": "ruff"}]
        },
        "metadata": {
            "requires-dist": [{"name": "protobuf", "specifier": "==6.33.5"}],
            "requires-dev": {
                "dev": [
                    {"name": "mypy", "specifier": "==1.19.1"},
                    {"name": "pytest", "specifier": "==9.0.2"},
                    {"name": "ruff", "specifier": "==0.14.10"},
                ]
            },
        },
    }
    if len(sdk_rows) != 1 or sdk_rows[0] != expected_sdk:
        raise ReleaseError("Python SDK lock metadata is stale")
    if len(protobuf_rows) != 1:
        raise ReleaseError("Python runtime dependency lock is incomplete")
    protobuf = protobuf_rows[0]
    if (
        protobuf.get("version") != "6.33.5"
        or protobuf.get("source") != {"registry": "https://pypi.org/simple"}
        or not isinstance(protobuf.get("sdist"), dict)
        or not isinstance(protobuf.get("wheels"), list)
        or not protobuf["wheels"]
    ):
        raise ReleaseError("Python protobuf lock record is stale")
    distributions = [protobuf["sdist"], *protobuf["wheels"]]
    for distribution in distributions:
        if (
            not isinstance(distribution, dict)
            or not isinstance(distribution.get("url"), str)
            or not distribution["url"].startswith("https://files.pythonhosted.org/")
            or not isinstance(distribution.get("hash"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", distribution["hash"]) is None
            or not isinstance(distribution.get("size"), int)
            or isinstance(distribution["size"], bool)
            or distribution["size"] <= 0
        ):
            raise ReleaseError("Python protobuf distribution lock is malformed")
    return {
        "format_version": 1,
        "revision": 3,
        "requires_python": "==3.14.*",
        "runtime_dependency": "protobuf==6.33.5",
        "development_dependencies": [
            "mypy==1.19.1",
            "pytest==9.0.2",
            "ruff==0.14.10",
        ],
        "build_backend": "hatchling==1.28.0",
    }


def _source_assets(root: Path) -> dict[str, bytes]:
    sdk_root = root / SDK_RELATIVE
    expanded = expand_files(
        root,
        ["sdk/python/src/cigar_sdk/**", "sdk/python/tests/**"],
        list(SOURCE_EXCLUDES),
    )
    assets: dict[str, bytes] = {}
    for repository_relative, path in expanded:
        relative = repository_relative.removeprefix(f"{SDK_RELATIVE}/")
        if relative.startswith("src/cigar_sdk/"):
            name = Path(relative).name
            if name != ".gitkeep" and Path(name).suffix not in {
                ".py",
                ".json",
                ".typed",
            }:
                raise ReleaseError(
                    f"Python package source type is not allowlisted: {relative}"
                )
        elif relative.startswith("tests/"):
            name = Path(relative).name
            if not name.startswith("test_") or Path(name).suffix != ".py":
                raise ReleaseError(
                    f"Python package test is not allowlisted: {relative}"
                )
        else:
            raise ReleaseError(
                f"Python package input is outside the exact roots: {relative}"
            )
        assets[relative] = _read_stable_file(path, MAX_SOURCE_BYTES, relative)
    for relative in STATIC_PACKAGE_PATHS:
        path = root / ".gitignore" if relative == ".gitignore" else sdk_root / relative
        assets[relative] = _read_stable_file(path, MAX_SOURCE_BYTES, relative)
    required = {
        ".gitignore",
        "LICENSE",
        "NOTICE",
        "README.md",
        "pyproject.toml",
        "src/cigar_sdk/__init__.py",
        "src/cigar_sdk/release.json",
        "src/cigar_sdk/py.typed",
    }
    if not required.issubset(assets) or not any(
        path.startswith("tests/test_") for path in assets
    ):
        raise ReleaseError("Python package source inventory is incomplete")
    for fixture in (
        "problem-index-unavailable-v1.json",
        "semantic-bundle-v1.json",
    ):
        packaged = assets.get(f"src/cigar_sdk/fixtures/{fixture}")
        reference = _read_stable_file(
            root / "sdk/fixtures" / fixture,
            MAX_SOURCE_BYTES,
            f"sdk/fixtures/{fixture}",
        )
        if packaged != reference:
            raise ReleaseError(f"packaged Python SDK fixture is stale: {fixture}")
    aliases: set[str] = set()
    for relative, payload in assets.items():
        safe_relative_path(relative)
        alias = unicodedata.normalize("NFC", relative).casefold()
        if alias in aliases:
            raise ReleaseError(f"Python package source path collides: {relative}")
        aliases.add(alias)
        if b"\r" in payload or not payload.endswith(b"\n"):
            raise ReleaseError(
                f"Python package source is not canonical LF text: {relative}"
            )
    return dict(sorted(assets.items(), key=lambda item: item[0].encode("utf-8")))


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
    python_version: str,
    matrix: Any,
    profile: Any,
    requirements: Any,
    authority: dict[str, dict[str, object]],
) -> None:
    version = product["version"]
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
        or "python-wheel-sdist" not in profile.get("integrations", [])
        or not any(
            isinstance(capability, dict)
            and capability.get("id") == "python-sdk"
            and capability.get("status") == "required"
            and capability.get("support_level") == "developer-preview"
            for capability in profile.get("capabilities", [])
        )
    ):
        raise ReleaseError("Honey Python capability authority is incomplete or stale")
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
    release = load_json(root / "sdk/python/src/cigar_sdk/release.json")
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
    python_version = _python_distribution_version(version)
    context_abi = product["context_abi"]
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": "cigar-sdk",
        "version": version,
        "context_abi": context_abi,
    }:
        raise ReleaseError("Python SDK release identity is stale")
    if honey:
        _validate_honey_authority(
            product, python_version, matrix, profile, requirements, authority
        )
        common_receipt = {
            "filename": "python-sdk-build-receipt.json",
            "required": True,
            "schema_version": "cigar.development-python-sdk-build.v1",
        }
        expected_rows = {
            WHEEL_ARTIFACT_ID: {
                "contract": "packaging/contracts/python-wheel.v1.json",
                "filename": f"cigar_sdk-{python_version}-py3-none-any.whl",
                "generated_by_assembler": False,
                "id": WHEEL_ARTIFACT_ID,
                "kind": "python-wheel",
                "order": 6,
                "producer": PRODUCER_ARGV,
                "public_attachment": True,
                "qualification_gate_ids": [
                    "sdk-clean-installs",
                    "archive-contracts",
                ],
                "receipt": common_receipt,
                "required": True,
                "sha256_required": True,
                "workspace": "python",
            },
            SDIST_ARTIFACT_ID: {
                "contract": "packaging/contracts/python-sdist.v1.json",
                "filename": f"cigar_sdk-{python_version}.tar.gz",
                "generated_by_assembler": False,
                "id": SDIST_ARTIFACT_ID,
                "kind": "python-sdist",
                "order": 7,
                "producer": PRODUCER_ARGV,
                "public_attachment": True,
                "qualification_gate_ids": [
                    "sdk-clean-installs",
                    "archive-contracts",
                ],
                "receipt": common_receipt,
                "required": True,
                "sha256_required": True,
                "workspace": "python",
            },
        }
        receipt_filename = common_receipt["filename"]
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
        expected_rows = {
            SDIST_ARTIFACT_ID: {
                "id": SDIST_ARTIFACT_ID,
                "kind": "python-sdist",
                "filename": f"cigar_sdk-{python_version}.tar.gz",
                "contract": "contracts/python-sdist.v1.json",
                "ecosystem": "python",
                "producer": PRODUCER,
                "required_for_release": True,
                "qualification": [
                    "twine-check",
                    "clean-install",
                    "offline",
                    "version-abi-consistency",
                    "sbom",
                    "license",
                    "signature",
                ],
            },
            WHEEL_ARTIFACT_ID: {
                "id": WHEEL_ARTIFACT_ID,
                "kind": "python-wheel",
                "filename": f"cigar_sdk-{python_version}-py3-none-any.whl",
                "contract": "contracts/python-wheel.v1.json",
                "ecosystem": "python",
                "producer": PRODUCER,
                "required_for_release": True,
                "qualification": [
                    "wheel-matrix",
                    "clean-install",
                    "offline",
                    "version-abi-consistency",
                    "sbom",
                    "license",
                    "signature",
                ],
            },
        }
        receipt_filename = BUILD_RECEIPT
    for identifier, expected in expected_rows.items():
        matching = [
            row
            for row in matrix["artifacts"]
            if isinstance(row, dict) and row.get("id") == identifier
        ]
        if len(matching) != 1 or matching[0] != expected:
            raise ReleaseError(f"{identifier} artifact row is incomplete or stale")
    if not honey:
        selected = (
            profile.get("selected_artifacts") if isinstance(profile, dict) else None
        )
        selected_rows = (
            {
                row.get("id"): row
                for row in selected
                if isinstance(row, dict) and row.get("id") in expected_rows
            }
            if isinstance(selected, list)
            else {}
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
            or set(selected_rows) != set(expected_rows)
            or any(
                row.get("status") != "planned"
                or row.get("built") is not False
                or row.get("qualified") is not False
                for row in selected_rows.values()
            )
        ):
            raise ReleaseError(
                "development profile does not keep Python packages unclaimed"
            )
    expected_contracts = _expected_contracts(python_version)
    contracts = {
        SDIST_ARTIFACT_ID: root / "packaging/contracts/python-sdist.v1.json",
        WHEEL_ARTIFACT_ID: root / "packaging/contracts/python-wheel.v1.json",
    }
    for identifier, path in contracts.items():
        if load_json(path) != expected_contracts[identifier]:
            raise ReleaseError(f"{identifier} package contract is not exact")
    source_assets = _source_assets(root)
    pyproject = _load_toml(source_assets["pyproject.toml"], "sdk/python/pyproject.toml")
    _validate_pyproject(pyproject, python_version)
    uv_lock_payload = _read_stable_file(
        root / "sdk/python/uv.lock", MAX_SOURCE_BYTES, "sdk/python/uv.lock"
    )
    lock_summary = _validate_lock(
        _load_toml(uv_lock_payload, "sdk/python/uv.lock"), python_version
    )
    return BuildConfiguration(
        root=root,
        sdk_root=root / SDK_RELATIVE,
        version=version,
        python_version=python_version,
        context_abi=context_abi,
        sdist_filename=expected_rows[SDIST_ARTIFACT_ID]["filename"],
        wheel_filename=expected_rows[WHEEL_ARTIFACT_ID]["filename"],
        receipt_filename=receipt_filename,
        contracts=contracts,
        authority=authority,
        source_assets=source_assets,
        lock_summary=lock_summary,
        honey=honey,
    )


def _source_identity(root: Path) -> dict[str, Any]:
    honey = _is_honey_product(load_json(root / "packaging/product-version.v1.json"))
    includes = list(SOURCE_INCLUDES)
    if honey:
        includes.extend(
            [
                "packaging/honey/capability-profile.v1.json",
                "packaging/honey/artifact-matrix.v1.json",
                "packaging/honey/release-requirements.v1.json",
            ]
        )
    files = expand_files(root, includes, list(SOURCE_EXCLUDES))
    if not files:
        raise ReleaseError("Python SDK build source inventory is empty")
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
        raise ReleaseError("Python SDK build requires a committed Git source identity")
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
        or not os.access(resolved, os.X_OK)
    ):
        raise ReleaseError(f"{name} must resolve to an owner-controlled executable")
    return resolved


def _private_cache_directory(value: Path | None) -> Path:
    selected = value or (Path.home() / ".cache/uv")
    if not selected.is_absolute():
        raise ReleaseError("uv cache directory must be absolute")
    try:
        resolved = selected.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError(f"cannot resolve uv cache directory: {error}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseError("uv cache directory must be owner-controlled")
    return resolved


def _run_checked(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
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
    except subprocess.TimeoutExpired as error:
        raise ReleaseError(f"{label} timed out after {timeout:g} seconds") from error
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, label))
    return result.stdout


def _tool_record(path: Path, name: str, version: str) -> dict[str, object]:
    payload = _read_stable_file(path, MAX_ARTIFACT_BYTES, f"{name} executable")
    return {
        "name": name,
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _stage_sources(configuration: BuildConfiguration, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for relative, payload in configuration.source_assets.items():
        path = destination.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise ReleaseError(
                f"cannot stage Python package input {relative}: {error}"
            ) from error


def _qualify_clean_installs(
    artifacts: dict[str, Path],
    *,
    uv: Path,
    python: Path,
    scratch: Path,
    environment: dict[str, str],
) -> dict[str, object]:
    results: dict[str, dict[str, object]] = {}
    for kind, artifact in artifacts.items():
        qualification_root = scratch / f"clean-install-{kind}"
        qualification_root.mkdir(mode=0o700)
        virtual_environment = qualification_root / "venv"
        _run_checked(
            [
                str(uv),
                "venv",
                "--python",
                str(python),
                "--no-python-downloads",
                "--no-config",
                str(virtual_environment),
            ],
            cwd=qualification_root,
            environment=environment,
            timeout=120,
            label=f"clean {kind} virtual environment",
        )
        interpreter = virtual_environment / "bin/python"
        qualifier = virtual_environment / "bin/cigar-qualify-bundle"
        agent_b_example = virtual_environment / "bin/cigar-agent-b-handoff"
        _run_checked(
            [
                str(uv),
                "pip",
                "install",
                "--python",
                str(interpreter),
                "--offline",
                "--no-config",
                "--no-sources",
                "--no-python-downloads",
                str(artifact),
            ],
            cwd=qualification_root,
            environment=environment,
            timeout=300,
            label=f"clean {kind} package installation",
        )
        _run_checked(
            [
                str(interpreter),
                "-c",
                "import cigar_sdk, google.protobuf;"
                "assert cigar_sdk.CONTEXT_ABI == 'cigar.context.v1';"
                "assert cigar_sdk.OPERATION_COUNT == 45;"
                "assert len(cigar_sdk.PAYLOAD_TYPES) == 70;"
                "assert google.protobuf.__version__ == '6.33.5'",
            ],
            cwd=qualification_root,
            environment=environment,
            timeout=60,
            label=f"clean {kind} public SDK import",
        )
        identity = (
            _run_checked(
                [str(qualifier)],
                cwd=qualification_root,
                environment=environment,
                timeout=60,
                label=f"clean {kind} semantic-bundle workflow",
            )
            .decode("utf-8", errors="strict")
            .strip()
        )
        if identity != EXPECTED_QUICKSTART_IDENTITY:
            raise ReleaseError(f"clean {kind} semantic-bundle identity differs")
        help_output = _run_checked(
            [str(agent_b_example), "--help"],
            cwd=qualification_root,
            environment=environment,
            timeout=60,
            label=f"clean {kind} Agent B handoff example",
        )
        if b"--handoff-id" not in help_output or b"--evidence" not in help_output:
            raise ReleaseError(f"clean {kind} Agent B handoff example is incomplete")
        payload = _read_stable_file(
            artifact, MAX_ARTIFACT_BYTES, f"qualified Python SDK {kind}"
        )
        results[kind] = {
            "artifact_sha256": sha256_bytes(payload),
            "artifact_bytes": len(payload),
            "identity": identity,
            "public_import": "passed",
            "agent_b_example": "passed-help",
            "status": "passed",
        }
    return {
        "schema_version": "cigar.python-sdk-clean-install.v1",
        "status": "passed",
        "offline": True,
        "dependency_mode": "offline-exact-runtime-dependencies",
        "runtime_dependencies": {"protobuf": "6.33.5"},
        "runtime": "cpython-3.14-macos-arm64",
        "artifacts": results,
    }


def _default_package_builder(
    configuration: BuildConfiguration,
    _source: dict[str, Any],
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> BuiltPackages:
    uv = _secure_executable(arguments.uv, "uv")
    python = _secure_executable(arguments.python, "python3")
    cache_argument = arguments.uv_cache_dir
    if cache_argument is None and os.environ.get("UV_CACHE_DIR"):
        cache_argument = Path(os.environ["UV_CACHE_DIR"])
    cache = _private_cache_directory(cache_argument)
    source = scratch / "source"
    output = scratch / "dist"
    home = scratch / "home"
    temporary = scratch / "tmp"
    for directory in (output, home, temporary):
        directory.mkdir(mode=0o700)
    _stage_sources(configuration, source)
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "UV_CACHE_DIR": str(cache),
        "UV_NO_CONFIG": "1",
        "UV_NO_PROGRESS": "1",
        "UV_NO_SOURCES": "1",
        "UV_OFFLINE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
    }
    uv_identity = (
        _run_checked(
            [str(uv), "--version"],
            cwd=scratch,
            environment=environment,
            timeout=30,
            label="uv identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    python_identity = (
        _run_checked(
            [str(python), "--version"],
            cwd=scratch,
            environment=environment,
            timeout=30,
            label="Python identity",
            maximum=256 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if (
        len(uv_identity.encode("utf-8")) > 256
        or re.fullmatch(
            r"uv [0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?"
            r"(?: \([A-Za-z0-9 ._+/-]+\))?",
            uv_identity,
        )
        is None
    ):
        raise ReleaseError("uv identity is malformed")
    if re.fullmatch(r"Python 3\.14\.[0-9]+", python_identity) is None:
        raise ReleaseError("Python build interpreter is not CPython 3.14")
    _run_checked(
        [
            str(uv),
            "build",
            str(source),
            "--offline",
            "--no-progress",
            "--no-sources",
            "--no-python-downloads",
            "--no-config",
            "--python",
            str(python),
            "--out-dir",
            str(output),
            "--no-create-gitignore",
        ],
        cwd=scratch,
        environment=environment,
        timeout=300,
        label="offline Python SDK package build",
    )
    expected = {configuration.sdist_filename, configuration.wheel_filename}
    observed = {path.name for path in output.iterdir() if path.is_file()}
    if observed != expected or any(path.is_symlink() for path in output.iterdir()):
        raise ReleaseError(
            f"Python build output inventory differs: expected={sorted(expected)}, observed={sorted(observed)}"
        )
    sdist = output / configuration.sdist_filename
    wheel = output / configuration.wheel_filename
    clean_install_validation = _qualify_clean_installs(
        {"sdist": sdist, "wheel": wheel},
        uv=uv,
        python=python,
        scratch=scratch,
        environment=environment,
    )
    return BuiltPackages(
        sdist=sdist,
        wheel=wheel,
        tools=(
            _tool_record(uv, "uv", uv_identity),
            _tool_record(python, "python", python_identity),
        ),
        build_policy={
            "backend": "hatchling==1.28.0",
            "network": "disabled",
            "source_staging": "exact-allowlist",
            "wheel_input": "built-sdist",
        },
        clean_install_validation=clean_install_validation,
    )


def _validate_tools(tools: tuple[dict[str, object], ...]) -> None:
    if not tools or any(
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
        for record in tools
    ):
        raise ReleaseError("Python build tool identity is incomplete")


def _validate_clean_install(
    validation: dict[str, object], built: BuiltPackages
) -> None:
    artifacts = validation.get("artifacts")
    if (
        set(validation)
        != {
            "schema_version",
            "status",
            "offline",
            "dependency_mode",
            "runtime_dependencies",
            "runtime",
            "artifacts",
        }
        or validation.get("schema_version") != "cigar.python-sdk-clean-install.v1"
        or validation.get("status") != "passed"
        or validation.get("offline") is not True
        or validation.get("dependency_mode") != "offline-exact-runtime-dependencies"
        or validation.get("runtime_dependencies") != {"protobuf": "6.33.5"}
        or validation.get("runtime") != "cpython-3.14-macos-arm64"
        or not isinstance(artifacts, dict)
        or set(artifacts) != {"sdist", "wheel"}
    ):
        raise ReleaseError("Python clean-install validation is incomplete")
    for kind, path in (("sdist", built.sdist), ("wheel", built.wheel)):
        record = artifacts.get(kind)
        payload = _read_stable_file(
            path, MAX_ARTIFACT_BYTES, f"validated Python SDK {kind}"
        )
        if record != {
            "artifact_sha256": sha256_bytes(payload),
            "artifact_bytes": len(payload),
            "identity": EXPECTED_QUICKSTART_IDENTITY,
            "public_import": "passed",
            "agent_b_example": "passed-help",
            "status": "passed",
        }:
            raise ReleaseError(f"Python clean-install {kind} binding differs")


def _metadata_summary(
    payload: bytes, configuration: BuildConfiguration
) -> dict[str, object]:
    try:
        message = BytesParser(policy=email_policy).parsebytes(payload)
    except (TypeError, ValueError) as error:
        raise ReleaseError(f"Python core metadata cannot be parsed: {error}") from error
    expected_items = [
        ("Metadata-Version", "2.4"),
        ("Name", "cigar-sdk"),
        ("Version", configuration.python_version),
        ("Summary", "CIGAR v1 Python SDK"),
        ("Project-URL", "Homepage, https://github.com/CIGAR/cigar"),
        ("Project-URL", "Repository, https://github.com/CIGAR/cigar"),
        ("License-Expression", "Apache-2.0"),
        ("License-File", "LICENSE"),
        ("License-File", "NOTICE"),
        ("Requires-Python", "<3.15,>=3.14"),
        ("Requires-Dist", "protobuf==6.33.5"),
        ("Description-Content-Type", "text/markdown"),
    ]
    if list(message.items()) != expected_items:
        raise ReleaseError("Python core metadata fields are stale or unexpected")
    body = message.get_payload()
    if (
        not isinstance(body, str)
        or body.encode("utf-8") != configuration.source_assets["README.md"]
    ):
        raise ReleaseError(
            "Python core metadata long description differs from README.md"
        )
    return {
        "metadata_version": "2.4",
        "name": "cigar-sdk",
        "version": configuration.python_version,
        "requires_python": ">=3.14,<3.15",
        "requires_dist": ["protobuf==6.33.5"],
        "license_expression": "Apache-2.0",
    }


def _expected_source_member_paths(configuration: BuildConfiguration) -> set[str]:
    prefix = f"cigar_sdk-{configuration.python_version}"
    return {
        *(f"{prefix}/{relative}" for relative in configuration.source_assets),
        f"{prefix}/PKG-INFO",
    }


def _read_sdist(
    path: Path, configuration: BuildConfiguration, epoch: int
) -> tuple[dict[str, bytes], dict[str, object]]:
    header = _read_stable_file(path, MAX_ARTIFACT_BYTES, "Python SDK sdist")[:10]
    if (
        len(header) != 10
        or header[:4] != b"\x1f\x8b\x08\x00"
        or int.from_bytes(header[4:8], "little") != epoch
        or header[8:] != b"\x02\xff"
    ):
        raise ReleaseError("Python sdist gzip header is not deterministic")
    payloads: dict[str, bytes] = {}
    aliases: set[str] = set()
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                safe_relative_path(member.name)
                alias = unicodedata.normalize("NFC", member.name).casefold()
                if member.name in payloads or alias in aliases:
                    raise ReleaseError(f"Python sdist member collides: {member.name}")
                aliases.add(alias)
                if (
                    not member.isfile()
                    or member.uid != 0
                    or member.gid != 0
                    or member.mode != 0o644
                    or member.mtime != epoch
                    or member.size <= 0
                    or member.size > MAX_SOURCE_BYTES
                ):
                    raise ReleaseError(
                        f"Python sdist member metadata is invalid: {member.name}"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseError(
                        f"cannot read Python sdist member: {member.name}"
                    )
                payload = handle.read(member.size + 1)
                if len(payload) != member.size:
                    raise ReleaseError(
                        f"Python sdist member length differs: {member.name}"
                    )
                payloads[member.name] = payload
    except (gzip.BadGzipFile, OSError, tarfile.TarError) as error:
        raise ReleaseError(f"cannot read Python SDK sdist: {error}") from error
    expected = _expected_source_member_paths(configuration)
    if set(payloads) != expected:
        raise ReleaseError(
            f"Python sdist inventory differs: extra={sorted(set(payloads) - expected)}, missing={sorted(expected - set(payloads))}"
        )
    prefix = f"cigar_sdk-{configuration.python_version}"
    for relative, source_payload in configuration.source_assets.items():
        if payloads[f"{prefix}/{relative}"] != source_payload:
            raise ReleaseError(f"Python sdist source payload differs: {relative}")
    metadata = payloads[f"{prefix}/PKG-INFO"]
    return payloads, {
        "status": "passed",
        "format": "sdist",
        "file_count": len(payloads),
        "metadata": _metadata_summary(metadata, configuration),
        "metadata_sha256": sha256_bytes(metadata),
        "exact_source_inventory": True,
        "deterministic_gzip": True,
    }


def _wheel_source_paths(configuration: BuildConfiguration) -> dict[str, bytes]:
    return {
        relative.removeprefix("src/"): payload
        for relative, payload in configuration.source_assets.items()
        if relative.startswith("src/cigar_sdk/")
    }


def _wheel_metadata_paths(configuration: BuildConfiguration) -> set[str]:
    dist_info = f"cigar_sdk-{configuration.python_version}.dist-info"
    return {
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/licenses/NOTICE",
        f"{dist_info}/RECORD",
    }


def _validate_wheel_record(payloads: dict[str, bytes], record_path: str) -> None:
    try:
        text = payloads[record_path].decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeError, csv.Error) as error:
        raise ReleaseError(f"Python wheel RECORD cannot be parsed: {error}") from error
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or row[0] in records:
            raise ReleaseError("Python wheel RECORD has an invalid or duplicate row")
        safe_relative_path(row[0])
        records[row[0]] = (row[1], row[2])
    if set(records) != set(payloads):
        raise ReleaseError("Python wheel RECORD inventory differs from wheel members")
    for name, payload in payloads.items():
        digest, size = records[name]
        if name == record_path:
            if digest or size:
                raise ReleaseError("Python wheel RECORD self-entry must be unhashed")
            continue
        encoded = (
            base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if digest != f"sha256={encoded}" or size != str(len(payload)):
            raise ReleaseError(f"Python wheel RECORD binding differs: {name}")


def _read_wheel(
    path: Path, configuration: BuildConfiguration, epoch: int
) -> tuple[dict[str, bytes], dict[str, object]]:
    payloads: dict[str, bytes] = {}
    aliases: set[str] = set()
    expected_time = time.gmtime(epoch - (epoch % 2))[:6]
    try:
        with zipfile.ZipFile(path, mode="r") as archive:
            if archive.testzip() is not None:
                raise ReleaseError("Python wheel CRC validation failed")
            for member in archive.infolist():
                safe_relative_path(member.filename)
                alias = unicodedata.normalize("NFC", member.filename).casefold()
                if member.filename in payloads or alias in aliases:
                    raise ReleaseError(
                        f"Python wheel member collides: {member.filename}"
                    )
                aliases.add(alias)
                mode = (member.external_attr >> 16) & 0xFFFF
                if (
                    member.is_dir()
                    or stat.S_IMODE(mode) != 0o644
                    or member.date_time != expected_time
                    or member.flag_bits & 0x1
                    or member.file_size <= 0
                    or member.file_size > MAX_SOURCE_BYTES
                ):
                    raise ReleaseError(
                        f"Python wheel member metadata is invalid: {member.filename}"
                    )
                payload = archive.read(member)
                if len(payload) != member.file_size:
                    raise ReleaseError(
                        f"Python wheel member length differs: {member.filename}"
                    )
                payloads[member.filename] = payload
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ReleaseError(f"cannot read Python SDK wheel: {error}") from error
    sources = _wheel_source_paths(configuration)
    metadata_paths = _wheel_metadata_paths(configuration)
    expected = set(sources) | metadata_paths
    if set(payloads) != expected:
        raise ReleaseError(
            f"Python wheel inventory differs: extra={sorted(set(payloads) - expected)}, missing={sorted(expected - set(payloads))}"
        )
    for relative, source_payload in sources.items():
        if payloads[relative] != source_payload:
            raise ReleaseError(f"Python wheel source payload differs: {relative}")
    dist_info = f"cigar_sdk-{configuration.python_version}.dist-info"
    if (
        payloads[f"{dist_info}/licenses/LICENSE"]
        != configuration.source_assets["LICENSE"]
    ):
        raise ReleaseError("Python wheel LICENSE differs from package source")
    if (
        payloads[f"{dist_info}/licenses/NOTICE"]
        != configuration.source_assets["NOTICE"]
    ):
        raise ReleaseError("Python wheel NOTICE differs from package source")
    if payloads[f"{dist_info}/WHEEL"] != (
        b"Wheel-Version: 1.0\n"
        b"Generator: hatchling 1.28.0\n"
        b"Root-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    ):
        raise ReleaseError("Python wheel compatibility metadata is stale")
    if payloads[f"{dist_info}/entry_points.txt"] != (
        b"[console_scripts]\n"
        b"cigar-agent-b-handoff = cigar_sdk.examples.agent_b_handoff:main\n"
        b"cigar-qualify-bundle = cigar_sdk.qualify_bundle:main\n"
    ):
        raise ReleaseError("Python wheel console entry point is stale")
    record_path = f"{dist_info}/RECORD"
    _validate_wheel_record(payloads, record_path)
    metadata = payloads[f"{dist_info}/METADATA"]
    return payloads, {
        "status": "passed",
        "format": "wheel",
        "tag": "py3-none-any",
        "file_count": len(payloads),
        "metadata": _metadata_summary(metadata, configuration),
        "metadata_sha256": sha256_bytes(metadata),
        "record_bindings": "passed",
        "exact_source_inventory": True,
    }


def _package_verification_summary(report: dict[str, Any]) -> dict[str, object]:
    return {
        "schema_version": report["schema_version"],
        "status": report["status"],
        "format": report["format"],
        "file_count": report["file_count"],
        "expanded_bytes": report["expanded_bytes"],
    }


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
        with tempfile.TemporaryDirectory(prefix="cigar-python-sdk-build-") as raw:
            scratch = Path(raw).resolve(strict=True)
            # Unpublished package bytes and clean-install environments must remain owner-only.
            # fmt: off
            os.chmod(scratch, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            # fmt: on
            built = package_builder(
                configuration, source_before, epoch, scratch, arguments
            )
            _validate_tools(built.tools)
            _validate_clean_install(built.clean_install_validation, built)
            if built.build_policy != {
                "backend": "hatchling==1.28.0",
                "network": "disabled",
                "source_staging": "exact-allowlist",
                "wheel_input": "built-sdist",
            }:
                raise ReleaseError("Python package build policy is incomplete")
            if (
                built.sdist.name != configuration.sdist_filename
                or built.wheel.name != configuration.wheel_filename
            ):
                raise ReleaseError(
                    "Python package builder returned unexpected filenames"
                )
            if _source_identity(root) != source_before:
                raise ReleaseError("Python SDK source changed during construction")
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError("Python SDK authority changed during construction")

            sdist_payloads, sdist_validation = _read_sdist(
                built.sdist, configuration, epoch
            )
            wheel_payloads, wheel_validation = _read_wheel(
                built.wheel, configuration, epoch
            )
            sdist_verification = verify_package(
                built.sdist,
                configuration.contracts[SDIST_ARTIFACT_ID],
                configuration.version,
                configuration.context_abi,
                epoch,
            )
            wheel_verification = verify_package(
                built.wheel,
                configuration.contracts[WHEEL_ARTIFACT_ID],
                configuration.version,
                configuration.context_abi,
                epoch,
            )
            if (
                sdist_validation["metadata_sha256"]
                != wheel_validation["metadata_sha256"]
            ):
                raise ReleaseError("Python sdist and wheel core metadata differ")
            if _source_identity(root) != source_before:
                raise ReleaseError(
                    "Python SDK source changed during package verification"
                )
            if (
                _authority_digests(root, tuple(configuration.authority))
                != configuration.authority
            ):
                raise ReleaseError(
                    "Python SDK authority changed during package verification"
                )
            sdist_bytes = _read_stable_file(
                built.sdist, MAX_ARTIFACT_BYTES, "verified Python SDK sdist"
            )
            wheel_bytes = _read_stable_file(
                built.wheel, MAX_ARTIFACT_BYTES, "verified Python SDK wheel"
            )
            sdist_binding = (sha256_bytes(sdist_bytes), len(sdist_bytes))
            wheel_binding = (sha256_bytes(wheel_bytes), len(wheel_bytes))
            sdist_reference = workspace.attach_file(
                built.sdist,
                configuration.sdist_filename,
                expected_sha256=sdist_binding[0],
                expected_bytes=sdist_binding[1],
            )
            wheel_reference = workspace.attach_file(
                built.wheel,
                configuration.wheel_filename,
                expected_sha256=wheel_binding[0],
                expected_bytes=wheel_binding[1],
            )

        receipt = {
            "schema_version": "cigar.development-python-sdk-build.v1",
            "status": "built-unqualified",
            "artifact_ids": [SDIST_ARTIFACT_ID, WHEEL_ARTIFACT_ID],
            "target": "python3-none-any-on-macos-arm64",
            "product_version": configuration.version,
            "python_distribution_version": configuration.python_version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": epoch,
            "source": source_before,
            "host": host,
            "artifacts": {
                "sdist": sdist_reference.as_dict(),
                "wheel": wheel_reference.as_dict(),
            },
            "contracts": {
                SDIST_ARTIFACT_ID: {
                    "path": "packaging/contracts/python-sdist.v1.json",
                    "sha256": configuration.authority[
                        "packaging/contracts/python-sdist.v1.json"
                    ]["sha256"],
                },
                WHEEL_ARTIFACT_ID: {
                    "path": "packaging/contracts/python-wheel.v1.json",
                    "sha256": configuration.authority[
                        "packaging/contracts/python-wheel.v1.json"
                    ]["sha256"],
                },
            },
            "authority": configuration.authority,
            "locked_metadata": configuration.lock_summary,
            "build_tools": list(built.tools),
            "build_policy": built.build_policy,
            "package_validation": {
                "sdist": sdist_validation,
                "wheel": wheel_validation,
                "core_metadata_identical": True,
                "source_payload_files": len(configuration.source_assets),
                "sdist_payload_files": len(sdist_payloads),
                "wheel_payload_files": len(wheel_payloads),
            },
            "package_contract_verification": {
                SDIST_ARTIFACT_ID: _package_verification_summary(sdist_verification),
                WHEEL_ARTIFACT_ID: _package_verification_summary(wheel_verification),
            },
            "clean_install_validation": built.clean_install_validation,
            "external_requirements": {
                "twine_check": "not-performed",
                "clean_sdist_install": "passed-offline-with-runtime-dependencies",
                "clean_wheel_install": "passed-offline-with-runtime-dependencies",
                "wheel_interpreter_matrix": "native-cpython-3.14-passed",
                "artifact_signatures": "not-evidenced",
                "pypi_publication": "not-performed",
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
            {
                configuration.sdist_filename,
                configuration.wheel_filename,
                configuration.receipt_filename,
            },
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
        raise SystemExit(f"Python SDK development build failed: {error}") from error
