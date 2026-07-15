#!/usr/bin/python3
"""Create and verify content-free evidence for authoritative xtask gates.

This helper is intentionally narrow: ``snapshot`` captures a bounded Git source
identity, ``record`` binds an already-successful gate to a protected attachment,
``verify`` independently reopens the published receipt and attachment, and the
specialized ``coverage`` and ``mutations`` routes run their exact source-bound
gates. It never signs, publishes release artifacts, fuzzes, or performs soak
execution; cargo-mutants changes only its disposable private source copies.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
QUALITY_TOOLS = REPOSITORY_ROOT / "tools" / "quality"
if str(RELEASE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(RELEASE_SCRIPTS))
if str(QUALITY_TOOLS) not in sys.path:
    sys.path.insert(0, str(QUALITY_TOOLS))

from evidence_workspace import (  # noqa: E402
    Attachment,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    canonical_json_bytes,
    safe_relative_path,
    validate_metrics,
)
from release_lib import (  # noqa: E402
    ReleaseError,
    child_environment_without_evidence,
    load_json,
    load_json_bytes,
    run_bounded,
    sha256_bytes,
    sha256_file,
)
from hermetic_execution import (  # noqa: E402
    HermeticExecutionError,
    no_network_command,
    sanitized_environment,
)
from mutation_campaign import (  # noqa: E402
    MutationCampaignError,
    campaign_command as mutation_campaign_command,
    list_files_command as mutation_list_files_command,
    load_policy as load_mutation_policy,
    validate_campaign_documents,
    workspace_package_inventory as mutation_package_inventory,
)


MANIFEST_PATH = "crates/xtask/prd-28.1-command-manifest.v1.json"
HELPER_PATH = "crates/xtask/command_plane_evidence.py"
HELPER_CLOSURE = (
    HELPER_PATH,
    "crates/xtask/route-tools.v1.json",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "tools/quality/hermetic_execution.py",
    "tools/quality/mutation_campaign.py",
)
REQUIREMENTS_PATH = "packaging/release-requirements.v1.json"
MAXIMUM_STATUS_BYTES = 16 * 1024 * 1024
MAXIMUM_STATUS_ENTRIES = 100_000
MAXIMUM_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_NATIVE_RUNTIME_BYTES = 128 * 1024 * 1024
HEX_40 = frozenset("0123456789abcdef")
HEX_64 = frozenset("0123456789abcdef")
NATIVE_RAW_SCHEMA = "cigar.xtask-native-macos-command-raw.v1"
NATIVE_PRODUCER_CLOSURE = {
    "crates/xtask/native_macos_command_plane.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/signatures.py",
}
NATIVE_RAW_COMMANDS = frozenset(
    {
        "bench-micro-verify",
        "bench-macro-verify",
        "bench-efficacy",
        "package-all",
        "package-smoke",
        "release-sbom",
        "release-sign",
        "release-attest",
        "release-verify",
        "test-sanitizers",
    }
)
ROUTE_TOOL_PATH = "crates/xtask/route-tools.v1.json"
ROUTE_TOOL_SCHEMA = "cigar.xtask-route-tools.v1"


def _load_route_tools() -> dict[str, frozenset[str]]:
    try:
        document = load_json(REPOSITORY_ROOT / ROUTE_TOOL_PATH)
    except (OSError, ReleaseError) as error:
        raise RuntimeError("route tool manifest is unavailable") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"routes", "schema_version"}
        or document.get("schema_version") != ROUTE_TOOL_SCHEMA
        or not isinstance(document.get("routes"), dict)
        or not document["routes"]
    ):
        raise RuntimeError("route tool manifest is malformed")
    result: dict[str, frozenset[str]] = {}
    for command_id, tools in document["routes"].items():
        if (
            not isinstance(command_id, str)
            or not isinstance(tools, list)
            or any(not isinstance(tool, str) or not tool for tool in tools)
            or tools != sorted(set(tools))
        ):
            raise RuntimeError("route tool manifest inventory is malformed")
        result[command_id] = frozenset(tools)
    return result


ROUTE_TOOLS = _load_route_tools()
NATIVE_EXECUTION_TOOLS = {
    "bench-micro-verify": ("qualified performance replay",),
    "bench-macro-verify": (
        "qualified performance replay",
        "physical local-scale receipt verifier",
    ),
    "bench-efficacy": ("qualified CIGARBench matrix replay",),
    "package-all": (
        "portable archive producer",
        "native macOS runtime producer",
        "native conformance-tool producer",
        "native CIGARBench-tool producer",
        "TypeScript SDK producer",
        "Rust SDK producer",
        "Python SDK producer",
        "Go SDK producer",
        "Homebrew artifact producer",
        "Claude Code plugin producer",
        "17-artifact macOS assembler",
        "17-artifact assembly verifier",
    ),
    "package-smoke": (
        "exact package matrix verifier",
        "installed artifact package smoke",
    ),
    "release-sbom": ("candidate SBOM generator",),
    "release-attest": ("candidate provenance generator",),
    "release-verify": ("independent offline release verifier",),
    "test-sanitizers": (
        "sanitizer manifest verifier",
        "production sanitizer qualification",
        "production sanitizer receipt verifier",
    ),
}
NATIVE_OUTPUT_ROLES = {
    "bench-micro-verify": ("performance-comparison-report",),
    "bench-macro-verify": (
        "performance-comparison-report",
        "physical-scale-binding",
        "physical-scale-receipt",
    ),
    "bench-efficacy": ("efficacy-matrix-report",),
    "package-all": ("assembled-build-manifest", "assembled-checksums"),
    "package-smoke": ("install-qualification",),
    "release-sbom": (
        "sbom.spdx.json",
        "sbom.cyclonedx.json",
        "sbom-artifacts.json",
    ),
    "release-attest": ("provenance",),
    "release-verify": ("offline-release-verification",),
    "test-sanitizers": ("sanitizer-receipt",),
}
NATIVE_DETAIL_KEYS = {
    "bench-micro-verify": {
        "qualified_performance_replay",
        "physical_scale_receipt_verified",
    },
    "bench-macro-verify": {
        "qualified_performance_replay",
        "physical_scale_receipt_verified",
    },
    "bench-efficacy": {"qualified_comparator_count", "matrix_reproduced"},
    "package-all": {"artifact_count", "development_only", "producer_count", "signed"},
    "package-smoke": {"artifact_count", "installed_bytes_executed", "source_revision"},
    "release-sbom": {
        "artifact_count",
        "sbom_document_count",
        "sidecars_pending_offline_reconciliation",
    },
    "release-attest": {
        "artifact_count",
        "subject_count",
        "network_mode",
        "sidecars_pending_offline_reconciliation",
    },
    "release-sign": {
        "signature_count",
        "signing_executed",
        "signing_phase",
        "release_evidence_signature_deferred",
        "sidecars_pending_offline_reconciliation",
    },
    "release-verify": {
        "artifact_count",
        "offline_verified",
        "reviewed_openssl_sha256",
        "sidecar_inventory_reconciled",
    },
    "test-sanitizers": {"case_count", "test_exclusions", "rust_ubsan_claimed"},
}
NATIVE_BASE_DETAIL_KEYS = {
    "platform_scope",
    "fuzz_executed",
    "soak_executed",
    "mutation_campaign_executed",
    "hundred_gib_scale_executed",
}
COVERAGE_REPORT_DIRECTORY_ENV = "CIGAR_COVERAGE_REPORT_DIR"
COVERAGE_RUST_TOOLCHAIN = "nightly-2026-07-13"
COVERAGE_EXCLUDED_PACKAGES = {
    "cigar-soak": "soak execution is explicitly deferred for this qualification run",
    "cigar-windows-ipc": "Windows-only implementation is not applicable to native macOS",
}
COVERAGE_PROPERTY_DEPENDENCIES = (
    "cigar-canon",
    "cigar-catalog",
    "cigar-compiler",
    "cigar-crypto",
    "cigar-effects",
    "cigar-policy",
    "cigar-protocol",
)
COVERAGE_CONTROL_ENVIRONMENT = frozenset(
    {
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_FLAGS",
        "CARGO_TARGET_DIR",
        "LLVM_COV",
        "LLVM_PROFDATA",
        "LLVM_PROFILE_FILE",
        "LLVM_PROFILE_FILE_NAME",
        "NEXTEST_CONFIG_FILE",
        "NEXTEST_FILTER_EXPR",
        "NEXTEST_MAX_THREADS",
        "NEXTEST_PARTITION",
        "NEXTEST_PROFILE",
        "NEXTEST_RETRIES",
        "NEXTEST_TEST_THREADS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
    }
)
COVERAGE_METRIC_NAMES = frozenset(
    {
        "coverage.line_count",
        "coverage.line_covered",
        "coverage.line_percent",
        "coverage.branch_count",
        "coverage.branch_covered",
        "coverage.branch_percent",
        "coverage.function_count",
        "coverage.function_covered",
        "coverage.function_percent",
        "coverage.package_count",
        "coverage.collection_count",
        "coverage.package_min_line_percent",
        "coverage.package_min_branch_percent",
        "coverage.property_workspace_executed",
    }
)
MUTATION_METRIC_NAMES = frozenset(
    {
        "mutation.score_percent",
        "mutation.duration_seconds",
        "mutation.production_package_fraction",
        "mutation.timeout_count",
        "mutation.critical_viable_survivor_count",
    }
)
MUTATION_CONTROL_ENVIRONMENT = COVERAGE_CONTROL_ENVIRONMENT | frozenset(
    {
        "CARGO_MUTANTS_JOBS",
        "CARGO_MUTANTS_MINIMUM_TEST_TIMEOUT",
        "CARGO_MUTANTS_OUTPUT",
        "CARGO_MUTANTS_TRACE_LEVEL",
        "NEXTEST_EXPERIMENTAL_LIBTEST_JSON",
        "RUST_TEST_THREADS",
    }
)
MUTATION_MAXIMUM_PROCESS_SECONDS = 24 * 60 * 60


# Cargo features are additive, but several supported CIGAR compositions are mutually exclusive.
# Keep each supported non-default composition explicit instead of using a misleading
# ``--all-features`` invocation. The metadata preflight below rejects any newly introduced feature
# that is not activated by at least one collection.
COVERAGE_COLLECTIONS: tuple[dict[str, object], ...] = (
    {
        "id": "workspace-default",
        "scope": "workspace",
        "arguments": (
            "--workspace",
            "--exclude",
            "cigar-soak",
            "--exclude",
            "cigar-windows-ipc",
            "--all-targets",
        ),
        "default_features": True,
        "features": (),
    },
    {
        "id": "cigar-cli-beta-embedded",
        "scope": "cigar-cli",
        "arguments": (
            "--package",
            "cigar-cli",
            "--no-default-features",
            "--features",
            "beta-embedded",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("beta-embedded",),
    },
    {
        "id": "cigar-sdk-remote",
        "scope": "cigar-sdk",
        "arguments": (
            "--package",
            "cigar-sdk",
            "--no-default-features",
            "--all-targets",
        ),
        "default_features": False,
        "features": (),
    },
    {
        "id": "cigar-aws-creds-no-http",
        "scope": "cigar-aws-creds",
        "arguments": (
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--all-targets",
        ),
        "default_features": False,
        "features": (),
    },
    {
        "id": "cigar-aws-creds-http-no-tls",
        "scope": "cigar-aws-creds",
        "arguments": (
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "http-credentials",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("http-credentials",),
    },
    {
        "id": "cigar-aws-creds-native-tls",
        "scope": "cigar-aws-creds",
        "arguments": (
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "native-tls",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("native-tls",),
    },
    {
        "id": "cigar-aws-creds-native-tls-vendored",
        "scope": "cigar-aws-creds",
        "arguments": (
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "native-tls-vendored",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("native-tls-vendored",),
    },
    {
        "id": "cigar-aws-creds-rustls",
        "scope": "cigar-aws-creds",
        "arguments": (
            "--package",
            "cigar-aws-creds",
            "--no-default-features",
            "--features",
            "rustls-tls",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("rustls-tls",),
    },
    {
        "id": "cigar-rust-s3-sync-no-tls",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("sync",),
    },
    {
        "id": "cigar-rust-s3-sync-native-tls",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-native-tls",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("sync-native-tls",),
    },
    {
        "id": "cigar-rust-s3-sync-native-tls-vendored",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-native-tls-vendored",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("sync-native-tls-vendored",),
    },
    {
        "id": "cigar-rust-s3-sync-rustls",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-rustls-tls",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("sync-rustls-tls",),
    },
    {
        "id": "cigar-rust-s3-sync-orthogonal",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "sync-rustls-tls,fail-on-err,http-credentials,tags",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("sync-rustls-tls", "fail-on-err", "http-credentials", "tags"),
    },
    {
        "id": "cigar-rust-s3-tokio-no-tls",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "with-tokio",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("with-tokio",),
    },
    {
        "id": "cigar-rust-s3-tokio-native-tls",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "tokio-native-tls",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("tokio-native-tls",),
    },
    {
        "id": "cigar-rust-s3-tokio-rustls",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "tokio-rustls-tls",
            "--all-targets",
        ),
        "default_features": False,
        "features": ("tokio-rustls-tls",),
    },
    {
        "id": "cigar-rust-s3-tokio-orthogonal",
        "scope": "cigar-rust-s3",
        "arguments": (
            "--package",
            "cigar-rust-s3",
            "--no-default-features",
            "--features",
            "tokio-rustls-tls,blocking,fail-on-err,http-credentials,tags",
            "--all-targets",
        ),
        "default_features": False,
        "features": (
            "tokio-rustls-tls",
            "blocking",
            "fail-on-err",
            "http-credentials",
            "tags",
        ),
    },
    {
        "id": "cigar-store-fault-injection",
        "scope": "cigar-store",
        "arguments": (
            "--package",
            "cigar-store",
            "--features",
            "migration-fault-injection,projection-fault-injection",
            "--all-targets",
        ),
        "default_features": True,
        "features": ("migration-fault-injection", "projection-fault-injection"),
    },
)


class CommandPlaneError(RuntimeError):
    """An authoritative command-plane invariant failed."""


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _utc_from_unix_ms(value: int) -> str:
    if isinstance(value, bool) or not 0 <= value <= 253_402_300_799_999:
        raise CommandPlaneError("gate start time is outside the supported range")
    try:
        return (
            datetime.fromtimestamp(value / 1000, timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError) as error:
        raise CommandPlaneError("gate start time is invalid") from error


def _require_native_macos_arm64() -> dict[str, str]:
    architecture = platform.machine().casefold()
    if sys.platform != "darwin" or architecture not in {"arm64", "aarch64"}:
        raise CommandPlaneError(
            "authoritative command receipts currently support only native "
            "Apple-silicon macOS"
        )
    return {
        "platform": "macos",
        "architecture": "arm64",
        "macos_version": platform.mac_ver()[0],
    }


def _validated_root(value: Path) -> Path:
    if not value.is_absolute():
        raise CommandPlaneError("repository root must be absolute")
    try:
        root = value.resolve(strict=True)
        metadata = root.lstat()
    except OSError as error:
        raise CommandPlaneError(f"repository root is unavailable: {error}") from error
    if (
        root != value
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise CommandPlaneError(
            "repository root must be a canonical, real absolute directory"
        )
    if root != REPOSITORY_ROOT.resolve(strict=True):
        raise CommandPlaneError("repository root does not contain this command helper")
    return root


def _git_executable() -> str:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise CommandPlaneError("Git is unavailable on the system executable path")
    path = Path(executable)
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise CommandPlaneError(f"Git executable is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise CommandPlaneError("Git executable is not a protected regular file")
    return os.fspath(resolved)


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.defpath,
        "HOME": os.devnull,
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
    }
    return environment


def _git(root: Path, arguments: Sequence[str], *, maximum: int = 4096) -> bytes:
    command = [
        _git_executable(),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.sparseCheckout=false",
        "-c",
        "core.sparseCheckoutCone=false",
        "-c",
        "core.preloadIndex=false",
        "-c",
        "core.fileMode=true",
        "-c",
        "core.ignoreCase=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "index.sparse=false",
        "-c",
        "filter.lfs.required=false",
        "-c",
        "diff.external=",
        *arguments,
    ]
    try:
        result = run_bounded(
            command,
            cwd=root,
            env=_git_environment(),
            timeout=30,
            max_stdout=maximum,
            max_stderr=4096,
        )
    except ReleaseError as error:
        raise CommandPlaneError(f"Git source inspection failed: {error}") from error
    if result.returncode != 0:
        raise CommandPlaneError(
            "Git source inspection returned a nonzero status; diagnostic output was suppressed"
        )
    return result.stdout


_MAXIMUM_GIT_CONTROL_BYTES = 64 * 1024 * 1024
_MAXIMUM_TRACKED_BYTES = 2 * 1024 * 1024 * 1024
_MAXIMUM_TRACKED_FILE_BYTES = 512 * 1024 * 1024
_TRACKED_INSPECTION_SECONDS = 30.0
_GIT_FALSE_VALUES = frozenset({b"", b"0", b"false", b"no", b"off"})
_UNSAFE_BOOLEAN_CONFIG = frozenset(
    {
        b"core.fsmonitor",
        b"core.ignorestat",
        b"core.untrackedcache",
        b"core.sparsecheckout",
        b"core.sparsecheckoutcone",
        b"extensions.worktreeconfig",
        b"index.sparse",
    }
)


def _repository_configuration(root: Path) -> bytes:
    """Reject local settings that can make Git's cached view non-authoritative."""

    payload = _git(
        root,
        ["config", "--local", "--no-includes", "--null", "--list"],
        maximum=_MAXIMUM_GIT_CONTROL_BYTES,
    )
    for encoded in payload.split(b"\0"):
        if not encoded:
            continue
        key, separator, value = encoded.partition(b"\n")
        if not separator or not key:
            raise CommandPlaneError("local Git configuration is malformed")
        normalized_key = key.lower()
        normalized_value = value.strip().lower()
        if normalized_key in _UNSAFE_BOOLEAN_CONFIG and (
            normalized_value not in _GIT_FALSE_VALUES
        ):
            raise CommandPlaneError(
                "local Git configuration enables unsupported cached source state"
            )
        if normalized_key.startswith(
            (b"include.", b"includeif.", b"filter.")
        ) or normalized_key in {
            b"core.attributesfile",
            b"core.excludesfile",
            b"core.worktree",
        }:
            raise CommandPlaneError(
                "local Git configuration can alter source discovery or filtering"
            )
    return hashlib.sha256(payload).digest()


def _git_control_path(root: Path, relative: str) -> Path:
    encoded = _git(root, ["rev-parse", "--git-path", relative], maximum=16 * 1024)
    if not encoded.endswith(b"\n") or b"\n" in encoded[:-1]:
        raise CommandPlaneError("Git control path is malformed")
    raw_path = encoded[:-1]
    if not raw_path:
        raise CommandPlaneError("Git control path is empty")
    path = Path(os.fsdecode(raw_path))
    if not path.is_absolute():
        path = root / path
    return path


def _read_git_control_file(
    path: Path, *, maximum: int, required: bool
) -> tuple[bytes, bytes]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise CommandPlaneError(
                "required Git control file is unavailable"
            ) from None
        return b"", hashlib.sha256(b"").digest()
    except OSError as error:
        raise CommandPlaneError("Git control file is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size > maximum
    ):
        raise CommandPlaneError(
            "Git control file is not a protected bounded regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened_before = os.fstat(descriptor)
            if _stat_identity(metadata) != _stat_identity(opened_before):
                raise CommandPlaneError(
                    "Git control file changed between named and opened inspection"
                )
            payload = bytearray()
            while len(payload) <= maximum:
                chunk = os.read(
                    descriptor, min(1024 * 1024, maximum + 1 - len(payload))
                )
                if not chunk:
                    break
                payload.extend(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CommandPlaneError("Git control file could not be read safely") from error
    try:
        named_after = path.lstat()
    except OSError as error:
        raise CommandPlaneError("Git control file changed after inspection") from error
    if len(payload) > maximum or not (
        _stat_identity(metadata)
        == _stat_identity(opened_before)
        == _stat_identity(opened_after)
        == _stat_identity(named_after)
    ):
        raise CommandPlaneError("Git control file changed while it was inspected")
    result = bytes(payload)
    return result, hashlib.sha256(result).digest()


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _repository_info_state(root: Path) -> bytes:
    identity = hashlib.sha256()
    for relative in ("info/attributes", "info/exclude"):
        payload, digest = _read_git_control_file(
            _git_control_path(root, relative), maximum=1024 * 1024, required=False
        )
        identity.update(relative.encode("ascii"))
        identity.update(digest)
        if any(
            line.strip() and not line.startswith(b"#") for line in payload.splitlines()
        ):
            raise CommandPlaneError(
                "effective local Git info attributes or excludes are unsupported"
            )
    return identity.digest()


def _parse_index_state(payload: bytes) -> tuple[int, bytes]:
    """Inspect v2/v3 index flags directly so Git config cannot mask them."""

    if len(payload) < 32 or payload[:4] != b"DIRC":
        raise CommandPlaneError("Git index header is invalid")
    version = int.from_bytes(payload[4:8], "big")
    entry_count = int.from_bytes(payload[8:12], "big")
    if version not in {2, 3}:
        raise CommandPlaneError(
            "only non-sparse Git index versions 2 and 3 are supported"
        )
    if entry_count > MAXIMUM_STATUS_ENTRIES:
        raise CommandPlaneError("Git index exceeds the bounded entry count")
    content = payload[:-20]
    checksum = payload[-20:]
    # Git index v2/v3 mandates this checksum; it is never a security digest.
    calculated = hashlib.sha1(content, usedforsecurity=False).digest()  # fmt: skip  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    if checksum != calculated:
        raise CommandPlaneError("Git index checksum is invalid")

    offset = 12
    for _ in range(entry_count):
        entry_start = offset
        if offset + 62 > len(content):
            raise CommandPlaneError("Git index entry is truncated")
        flags = int.from_bytes(content[offset + 60 : offset + 62], "big")
        offset += 62
        extended_flags = 0
        if flags & 0x4000:
            if version < 3 or offset + 2 > len(content):
                raise CommandPlaneError("Git index extended flags are malformed")
            extended_flags = int.from_bytes(content[offset : offset + 2], "big")
            offset += 2
        terminator = content.find(b"\0", offset)
        if terminator < 0:
            raise CommandPlaneError("Git index path is unterminated")
        name_length = flags & 0x0FFF
        if name_length != 0x0FFF and terminator - offset != name_length:
            raise CommandPlaneError("Git index path length is inconsistent")
        if flags & 0x8000:
            raise CommandPlaneError("Git index contains assume-unchanged entries")
        if extended_flags & 0x4020:
            raise CommandPlaneError(
                "Git index contains skip-worktree or fsmonitor-valid entries"
            )
        entry_length = terminator + 1 - entry_start
        offset = entry_start + ((entry_length + 7) & ~7)
        if offset > len(content):
            raise CommandPlaneError("Git index entry padding is invalid")

    while offset < len(content):
        if offset + 8 > len(content):
            raise CommandPlaneError("Git index extension is truncated")
        signature = content[offset : offset + 4]
        extension_bytes = int.from_bytes(content[offset + 4 : offset + 8], "big")
        offset += 8
        if extension_bytes > len(content) - offset:
            raise CommandPlaneError("Git index extension length is invalid")
        if signature in {b"FSMN", b"UNTR", b"link", b"sdir"}:
            raise CommandPlaneError(
                "Git index contains an unsupported cached or sparse extension"
            )
        if signature[:1].islower():
            raise CommandPlaneError("Git index contains an unknown mandatory extension")
        offset += extension_bytes
    return entry_count, hashlib.sha256(payload).digest()


def _index_state(root: Path) -> tuple[int, bytes]:
    payload, digest = _read_git_control_file(
        _git_control_path(root, "index"),
        maximum=_MAXIMUM_GIT_CONTROL_BYTES,
        required=True,
    )
    count, parsed_digest = _parse_index_state(payload)
    if digest != parsed_digest:
        raise CommandPlaneError("Git index identity is inconsistent")
    return count, digest


def _validate_tracked_path(path: bytes) -> None:
    components = path.split(b"/")
    if (
        not path
        or path.startswith(b"/")
        or any(component in {b"", b".", b".."} for component in components)
    ):
        raise CommandPlaneError("Git tracked path is unsafe")


def _parse_head_manifest(payload: bytes) -> dict[bytes, tuple[bytes, bytes]]:
    entries: dict[bytes, tuple[bytes, bytes]] = {}
    for encoded in payload.split(b"\0"):
        if not encoded:
            continue
        metadata, separator, path = encoded.partition(b"\t")
        parts = metadata.split(b" ")
        if not separator or len(parts) != 3:
            raise CommandPlaneError("Git tree manifest is malformed")
        mode, object_type, object_id = parts
        _validate_tracked_path(path)
        if mode not in {b"100644", b"100755"} or object_type != b"blob":
            raise CommandPlaneError(
                "tracked symlinks, submodules, and non-regular entries are unsupported"
            )
        if len(object_id) != 40 or any(
            byte not in b"0123456789abcdef" for byte in object_id
        ):
            raise CommandPlaneError("Git tree object ID is invalid")
        if path in entries:
            raise CommandPlaneError("Git tree contains duplicate paths")
        entries[path] = (mode, object_id)
    if len(entries) > MAXIMUM_STATUS_ENTRIES:
        raise CommandPlaneError("Git tree exceeds the bounded entry count")
    return entries


def _parse_index_manifest(payload: bytes) -> dict[bytes, tuple[bytes, bytes]]:
    entries: dict[bytes, tuple[bytes, bytes]] = {}
    for encoded in payload.split(b"\0"):
        if not encoded:
            continue
        metadata, separator, path = encoded.partition(b"\t")
        parts = metadata.split(b" ")
        if not separator or len(parts) != 3:
            raise CommandPlaneError("Git staged manifest is malformed")
        mode, object_id, stage = parts
        _validate_tracked_path(path)
        if stage != b"0":
            raise CommandPlaneError("unmerged Git index entries are unsupported")
        if mode not in {b"100644", b"100755"}:
            raise CommandPlaneError(
                "staged symlinks, submodules, and non-regular entries are unsupported"
            )
        if len(object_id) != 40 or any(
            byte not in b"0123456789abcdef" for byte in object_id
        ):
            raise CommandPlaneError("Git staged object ID is invalid")
        if path in entries:
            raise CommandPlaneError("Git index contains duplicate paths")
        entries[path] = (mode, object_id)
    if len(entries) > MAXIMUM_STATUS_ENTRIES:
        raise CommandPlaneError("Git index exceeds the bounded entry count")
    return entries


def _validate_source_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_nlink < 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o700, 0o750, 0o755}
    ):
        raise CommandPlaneError(
            "repository source directories must be owner-owned protected real directories"
        )


def _open_source_directory(parent_descriptor: int, name: bytes) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        _validate_source_directory(named)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        try:
            opened = os.fstat(descriptor)
            _validate_source_directory(opened)
        except (OSError, CommandPlaneError):
            os.close(descriptor)
            raise
    except OSError as error:
        raise CommandPlaneError(
            "repository source directory could not be opened safely"
        ) from error
    if _stat_identity(named) != _stat_identity(opened):
        os.close(descriptor)
        raise CommandPlaneError(
            "repository source directory changed between named and opened inspection"
        )
    return descriptor


def _validate_tracked_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o644, 0o755}
    ):
        raise CommandPlaneError(
            "tracked worktree entries require owner-owned, single-link exact 0644 or 0755 regular files"
        )


def _tracked_named_metadata(root_descriptor: int, path: bytes) -> os.stat_result | None:
    components = path.split(b"/")
    directory = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            try:
                child = _open_source_directory(directory, component)
            except CommandPlaneError as error:
                if isinstance(error.__cause__, (FileNotFoundError, NotADirectoryError)):
                    return None
                raise
            except (FileNotFoundError, NotADirectoryError):
                return None
            os.close(directory)
            directory = child
        name = components[-1]
        try:
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None
        _validate_tracked_file_metadata(metadata)
        return metadata
    finally:
        os.close(directory)


def _open_tracked_file(
    root_descriptor: int, path: bytes
) -> tuple[int, os.stat_result] | None:
    components = path.split(b"/")
    directory = os.dup(root_descriptor)
    file_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in components[:-1]:
            try:
                child = _open_source_directory(directory, component)
            except CommandPlaneError as error:
                if isinstance(error.__cause__, (FileNotFoundError, NotADirectoryError)):
                    return None
                raise
            os.close(directory)
            directory = child
        name = components[-1]
        try:
            named_before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None
        _validate_tracked_file_metadata(named_before)
        descriptor = os.open(name, file_flags, dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
        except OSError:
            os.close(descriptor)
            raise
        if _stat_identity(named_before) != _stat_identity(opened):
            os.close(descriptor)
            raise CommandPlaneError(
                "tracked worktree entry changed between named and opened inspection"
            )
        return descriptor, named_before
    except OSError as error:
        raise CommandPlaneError(
            "tracked worktree entry could not be opened safely"
        ) from error
    finally:
        os.close(directory)


def _tracked_worktree_state(
    root: Path, entries: Mapping[bytes, tuple[bytes, bytes]]
) -> tuple[bool, int, bytes]:
    deadline = time.monotonic() + _TRACKED_INSPECTION_SECONDS
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_named_before = root.lstat()
        root_descriptor = os.open(root, root_flags)
        try:
            root_opened_before = os.fstat(root_descriptor)
        except OSError:
            os.close(root_descriptor)
            raise
    except OSError as error:
        raise CommandPlaneError("repository root could not be opened safely") from error
    try:
        _validate_source_directory(root_named_before)
        _validate_source_directory(root_opened_before)
    except CommandPlaneError:
        os.close(root_descriptor)
        raise
    if _stat_identity(root_named_before) != _stat_identity(root_opened_before):
        os.close(root_descriptor)
        raise CommandPlaneError(
            "repository root changed between named and opened inspection"
        )
    total_bytes = 0
    matches_index = True
    identity = hashlib.sha256()
    try:
        for path in sorted(entries):
            if time.monotonic() > deadline:
                raise CommandPlaneError(
                    "tracked worktree inspection exceeded its time bound"
                )
            expected_mode, expected_object = entries[path]
            opened = _open_tracked_file(root_descriptor, path)
            identity.update(len(path).to_bytes(8, "big"))
            identity.update(path)
            if opened is None:
                identity.update(b"missing")
                matches_index = False
                continue
            descriptor, named_before = opened
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size > _MAXIMUM_TRACKED_FILE_BYTES
                    or total_bytes + before.st_size > _MAXIMUM_TRACKED_BYTES
                ):
                    raise CommandPlaneError(
                        "tracked worktree content exceeds its byte bound"
                    )
                actual_mode = (
                    b"100755" if stat.S_IMODE(before.st_mode) == 0o755 else b"100644"
                )
                # Git's object format mandates SHA-1 here; SHA-256 binds evidence separately.
                object_hash = hashlib.sha1(usedforsecurity=False)  # fmt: skip  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
                content_hash = hashlib.sha256()
                object_hash.update(f"blob {before.st_size}\0".encode("ascii"))
                read_bytes = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    if (
                        read_bytes > before.st_size
                        or total_bytes + read_bytes > _MAXIMUM_TRACKED_BYTES
                    ):
                        raise CommandPlaneError(
                            "tracked worktree content changed or exceeded its byte bound"
                        )
                    object_hash.update(chunk)
                    content_hash.update(chunk)
                    if time.monotonic() > deadline:
                        raise CommandPlaneError(
                            "tracked worktree inspection exceeded its time bound"
                        )
                after = os.fstat(descriptor)
                named_after = _tracked_named_metadata(root_descriptor, path)
                if named_after is None:
                    raise CommandPlaneError(
                        "tracked worktree entry changed after inspection"
                    )
            finally:
                os.close(descriptor)
            if read_bytes != before.st_size or not (
                _stat_identity(named_before)
                == _stat_identity(before)
                == _stat_identity(after)
                == _stat_identity(named_after)
            ):
                raise CommandPlaneError(
                    "tracked worktree content changed while it was inspected"
                )
            total_bytes += read_bytes
            identity.update(actual_mode)
            identity.update(content_hash.digest())
            if actual_mode != expected_mode or (
                object_hash.hexdigest().encode() != expected_object
            ):
                matches_index = False
    finally:
        root_opened_after = os.fstat(root_descriptor)
        os.close(root_descriptor)
    try:
        root_named_after = root.lstat()
    except OSError as error:
        raise CommandPlaneError("repository root changed after inspection") from error
    if not (
        _stat_identity(root_named_before)
        == _stat_identity(root_opened_before)
        == _stat_identity(root_opened_after)
        == _stat_identity(root_named_after)
    ):
        raise CommandPlaneError("repository root changed while it was inspected")
    return matches_index, total_bytes, identity.digest()


def _generated_target_identity(root: Path) -> bytes:
    """Validate Cargo's one permitted ignored root without traversing its output."""

    path = root / "target"
    try:
        root_metadata = root.lstat()
        named_before = path.lstat()
    except OSError as error:
        raise CommandPlaneError("Cargo generated root is unavailable") from error
    mode = stat.S_IMODE(named_before.st_mode)
    if (
        not stat.S_ISDIR(named_before.st_mode)
        or named_before.st_uid != os.getuid()
        or named_before.st_dev != root_metadata.st_dev
        or mode not in {0o700, 0o750, 0o755}
    ):
        raise CommandPlaneError(
            "Cargo generated root must be an owner-owned protected real directory"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named_after = path.lstat()
    except OSError as error:
        raise CommandPlaneError(
            "Cargo generated root could not be inspected safely"
        ) from error
    if not (
        _stat_identity(named_before)
        == _stat_identity(opened)
        == _stat_identity(named_after)
    ):
        raise CommandPlaneError("Cargo generated root changed while it was inspected")
    return hashlib.sha256(canonical_json_bytes(list(_stat_identity(opened)))).digest()


def _status_state(root: Path) -> tuple[bytes, int, bytes]:
    ordinary = _git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        maximum=MAXIMUM_STATUS_BYTES,
    )
    ignored = _git(
        root,
        [
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
        ],
        maximum=MAXIMUM_STATUS_BYTES,
    )
    ordinary_entries = tuple(item for item in ordinary.split(b"\0") if item)
    ignored_entries = tuple(item for item in ignored.split(b"\0") if item)
    generated_identity = hashlib.sha256(b"").digest()
    if ignored_entries:
        if ignored_entries != (b"target/",):
            raise CommandPlaneError(
                "ignored untracked content outside the protected Cargo target root is unsupported"
            )
        generated_identity = _generated_target_identity(root)
        ignored_entries = ()
        ignored = b""
    count = len(ordinary_entries)
    if count > MAXIMUM_STATUS_ENTRIES:
        raise CommandPlaneError("Git status exceeds the bounded entry count")
    if not count:
        return b"", 0, generated_identity
    encoded = (
        b"ordinary\0"
        + len(ordinary).to_bytes(8, "big")
        + ordinary
        + b"ignored\0"
        + len(ignored).to_bytes(8, "big")
        + ignored
    )
    if len(encoded) > MAXIMUM_STATUS_BYTES * 2 + 64:
        raise CommandPlaneError("Git status identity exceeds its byte bound")
    return encoded, count, generated_identity


def _single_hex(value: bytes, label: str) -> str:
    try:
        text = value.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise CommandPlaneError(f"Git {label} is not ASCII") from error
    if len(text) != 40 or any(character not in HEX_40 for character in text):
        raise CommandPlaneError(f"Git {label} is not one full lowercase object ID")
    return text


def source_binding(root: Path) -> dict[str, Any]:
    """Capture a bounded, content-free Git source binding twice for stability.

    Qualification deliberately supports only byte-identical, owner-owned,
    single-link 0644/0755 files below protected owner-owned directories and a
    v2/v3 SHA-1 index. Gitlinks, symlinks, sparse/split indexes, local filters,
    local attributes/excludes, transformed worktree content, and ignored paths
    other than one protected root ``target/`` fail closed because those states
    cannot be represented by the content-free receipt schema.
    """

    top_level = _git(root, ["rev-parse", "--show-toplevel"])
    try:
        reported_root = Path(
            top_level.decode("utf-8", errors="strict").strip()
        ).resolve(strict=True)
    except (UnicodeError, OSError) as error:
        raise CommandPlaneError("Git top-level path is invalid") from error
    if reported_root != root:
        raise CommandPlaneError(
            "repository root must be the exact Git worktree top level"
        )
    object_format = _git(root, ["rev-parse", "--show-object-format"])
    if object_format != b"sha1\n":
        raise CommandPlaneError("only SHA-1-format Git repositories are supported")

    def capture() -> tuple[Any, ...]:
        configuration = _repository_configuration(root)
        info_state = _repository_info_state(root)
        physical_index_count, physical_index_digest = _index_state(root)
        revision = _single_hex(
            _git(root, ["rev-parse", "--verify", "HEAD^{commit}"]), "revision"
        )
        tree = _single_hex(_git(root, ["rev-parse", "--verify", "HEAD^{tree}"]), "tree")
        head_entries = _parse_head_manifest(
            _git(
                root,
                ["ls-tree", "-r", "-z", "--full-tree", tree],
                maximum=MAXIMUM_STATUS_BYTES,
            )
        )
        index_entries = _parse_index_manifest(
            _git(
                root,
                ["ls-files", "--cached", "--stage", "-z"],
                maximum=MAXIMUM_STATUS_BYTES,
            )
        )
        if physical_index_count != len(index_entries):
            raise CommandPlaneError("physical and logical Git index counts disagree")
        worktree_matches_index, tracked_bytes, worktree_identity = (
            _tracked_worktree_state(root, index_entries)
        )
        status, status_count, generated_identity = _status_state(root)
        if not status_count and (
            head_entries != index_entries or not worktree_matches_index
        ):
            raise CommandPlaneError(
                "Git reported clean while tracked HEAD, index, or worktree state differed"
            )
        return (
            revision,
            tree,
            status,
            status_count,
            configuration,
            info_state,
            physical_index_digest,
            generated_identity,
            hashlib.sha256(
                canonical_json_bytes(
                    [
                        [
                            hashlib.sha256(path).hexdigest(),
                            mode.decode("ascii"),
                            object_id.decode("ascii"),
                        ]
                        for path, (mode, object_id) in sorted(head_entries.items())
                    ]
                )
            ).digest(),
            hashlib.sha256(
                canonical_json_bytes(
                    [
                        [
                            hashlib.sha256(path).hexdigest(),
                            mode.decode("ascii"),
                            object_id.decode("ascii"),
                        ]
                        for path, (mode, object_id) in sorted(index_entries.items())
                    ]
                )
            ).digest(),
            worktree_matches_index,
            tracked_bytes,
            worktree_identity,
        )

    first = capture()
    second = capture()
    if first != second:
        raise CommandPlaneError("Git source changed while its binding was captured")
    revision, tree, status, status_count = first[:4]
    return {
        "kind": "git",
        "revision": revision,
        "tree": tree,
        "committed": True,
        "clean": status_count == 0,
        "status_entry_count": status_count,
        "status_sha256": hashlib.sha256(status).hexdigest(),
    }


def _validate_source_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "kind",
        "revision",
        "tree",
        "committed",
        "clean",
        "status_entry_count",
        "status_sha256",
    }:
        raise CommandPlaneError("source binding has an unexpected shape")
    for key in ("revision", "tree"):
        item = value.get(key)
        if (
            not isinstance(item, str)
            or len(item) != 40
            or any(character not in HEX_40 for character in item)
        ):
            raise CommandPlaneError(f"source binding {key} is invalid")
    status_digest = value.get("status_sha256")
    if (
        not isinstance(status_digest, str)
        or len(status_digest) != 64
        or any(character not in HEX_40 for character in status_digest)
    ):
        raise CommandPlaneError("source binding status digest is invalid")
    count = value.get("status_entry_count")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 0 <= count <= MAXIMUM_STATUS_ENTRIES
    ):
        raise CommandPlaneError("source binding status count is invalid")
    if (
        value.get("kind") != "git"
        or value.get("committed") is not True
        or not isinstance(value.get("clean"), bool)
        or value["clean"] != (count == 0)
        or (value["clean"] and status_digest != hashlib.sha256(b"").hexdigest())
    ):
        raise CommandPlaneError("source binding consistency check failed")
    return dict(value)


def _load_expected_source(encoded: str) -> dict[str, Any]:
    try:
        payload = encoded.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise CommandPlaneError("expected source binding is not UTF-8") from error
    try:
        value = load_json_bytes(payload, "expected xtask source binding")
    except ReleaseError as error:
        raise CommandPlaneError(
            f"expected source binding is invalid: {error}"
        ) from error
    return _validate_source_binding(value)


def _require_clean_source(source: Mapping[str, Any]) -> None:
    if source.get("committed") is not True or source.get("clean") is not True:
        raise CommandPlaneError(
            "PRD 28.1 command evidence requires a fresh clean committed checkout"
        )


def _preflight_workspace(root: Path, evidence_directory: Path) -> None:
    workspace = EvidenceWorkspace.create(evidence_directory, repository_root=root)
    try:
        workspace.read_files(set())
    finally:
        workspace.close()


def _load_manifest(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / MANIFEST_PATH
    try:
        payload = path.read_bytes()
        document = load_json_bytes(payload, "xtask command manifest")
    except (OSError, ReleaseError) as error:
        raise CommandPlaneError(
            f"command manifest is unavailable or invalid: {error}"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or document.get("authority") != "crates/xtask/src/lib.rs::PRD_28_1_COMMANDS"
        or not isinstance(document.get("commands"), list)
        or document.get("command_count") != len(document["commands"])
        or not isinstance(document.get("additional_commands"), list)
        or document.get("additional_command_count")
        != len(document["additional_commands"])
    ):
        raise CommandPlaneError("command manifest identity is invalid")
    identifiers: list[str] = []
    commands: list[str] = []
    for entry in [*document["commands"], *document["additional_commands"]]:
        if not isinstance(entry, dict):
            raise CommandPlaneError("command manifest contains a non-object entry")
        identifier = entry.get("id")
        command = entry.get("command")
        if not isinstance(identifier, str) or not identifier:
            raise CommandPlaneError("command manifest contains an invalid command ID")
        if not isinstance(command, str) or not command:
            raise CommandPlaneError(
                "command manifest contains an invalid command display"
            )
        identifiers.append(identifier)
        commands.append(command)
    if len(identifiers) != len(set(identifiers)):
        raise CommandPlaneError("command manifest contains a duplicate command ID")
    if len(commands) != len(set(commands)):
        raise CommandPlaneError("command manifest contains a duplicate command display")
    return document, payload


def _command_entry(root: Path, command_id: str) -> tuple[dict[str, Any], str]:
    manifest, payload = _load_manifest(root)
    matches = [
        item
        for item in [*manifest["commands"], *manifest["additional_commands"]]
        if isinstance(item, dict) and item.get("id") == command_id
    ]
    if len(matches) != 1:
        raise CommandPlaneError("command ID is absent or duplicated in the manifest")
    entry = matches[0]
    if (
        entry.get("gate_state") == "unavailable"
        or not isinstance(entry.get("command"), str)
        or not entry["command"].startswith("cargo xtask ")
        or entry.get("receipt", {}).get("required") is not True
    ):
        raise CommandPlaneError("command is not eligible for a successful receipt")
    return entry, sha256_bytes(payload)


def _attachment_from_payload(path: str, payload: bytes) -> Attachment:
    if not payload:
        raise CommandPlaneError("gate attachment is empty")
    return Attachment(path=path, sha256=sha256_bytes(payload), bytes=len(payload))


def _validate_command_metrics(
    command_id: str, metrics: Mapping[str, int | float] | None
) -> dict[str, int | float]:
    validated = dict(metrics or {})
    try:
        validate_metrics(validated)
    except EvidenceWorkspaceError as error:
        raise CommandPlaneError(f"command metrics are invalid: {error}") from error
    if command_id not in {"test-coverage-verify", "test-mutations-verify"}:
        if validated:
            raise CommandPlaneError(
                "command receipt contains synthetic metrics for a non-metric gate"
            )
        return validated
    if command_id == "test-mutations-verify":
        if set(validated) != MUTATION_METRIC_NAMES:
            missing = sorted(MUTATION_METRIC_NAMES - set(validated))
            unexpected = sorted(set(validated) - MUTATION_METRIC_NAMES)
            raise CommandPlaneError(
                "mutation receipt metric inventory mismatch; "
                f"missing={missing}, unexpected={unexpected}"
            )
        score = validated["mutation.score_percent"]
        duration = validated["mutation.duration_seconds"]
        package_fraction = validated["mutation.production_package_fraction"]
        timeouts = validated["mutation.timeout_count"]
        critical = validated["mutation.critical_viable_survivor_count"]
        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not 90.0 <= float(score) <= 100.0
            or isinstance(duration, bool)
            or not isinstance(duration, int)
            or not 14_400 <= duration <= MUTATION_MAXIMUM_PROCESS_SECONDS
            or isinstance(package_fraction, bool)
            or not isinstance(package_fraction, (int, float))
            or float(package_fraction) != 1.0
            or isinstance(timeouts, bool)
            or not isinstance(timeouts, int)
            or timeouts != 0
            or isinstance(critical, bool)
            or not isinstance(critical, int)
            or critical != 0
        ):
            raise CommandPlaneError(
                "mutation receipt metrics do not satisfy the release thresholds"
            )
        return validated
    if set(validated) != COVERAGE_METRIC_NAMES:
        missing = sorted(COVERAGE_METRIC_NAMES - set(validated))
        unexpected = sorted(set(validated) - COVERAGE_METRIC_NAMES)
        raise CommandPlaneError(
            "coverage receipt metric inventory mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )
    for singular in ("line", "branch", "function"):
        count = validated[f"coverage.{singular}_count"]
        covered = validated[f"coverage.{singular}_covered"]
        percent = validated[f"coverage.{singular}_percent"]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count <= 0
            or isinstance(covered, bool)
            or not isinstance(covered, int)
            or not 0 <= covered <= count
            or not isinstance(percent, (int, float))
            or isinstance(percent, bool)
            or round(float(percent), 6) != round(100.0 * covered / count, 6)
        ):
            raise CommandPlaneError(
                f"coverage receipt {singular} metrics do not reconcile"
            )
    package_count = validated["coverage.package_count"]
    collection_count = validated["coverage.collection_count"]
    property_executed = validated["coverage.property_workspace_executed"]
    if (
        isinstance(package_count, bool)
        or not isinstance(package_count, int)
        or package_count <= 0
        or isinstance(collection_count, bool)
        or not isinstance(collection_count, int)
        or collection_count != len(COVERAGE_COLLECTIONS)
        or isinstance(property_executed, bool)
        or not isinstance(property_executed, int)
        or property_executed != 1
    ):
        raise CommandPlaneError("coverage receipt execution counts are invalid")
    for name in (
        "coverage.package_min_line_percent",
        "coverage.package_min_branch_percent",
    ):
        value = validated[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0.0 <= float(value) <= 100.0
        ):
            raise CommandPlaneError(f"coverage receipt metric {name} is invalid")
    return validated


def _validate_existing_attachment(
    workspace: EvidenceWorkspace,
    relative: str,
    command_id: str,
    source: Mapping[str, Any],
) -> Attachment:
    canonical = "/".join(safe_relative_path(relative))
    payloads = workspace.read_files({canonical})
    payload = payloads[canonical]
    attachment = _attachment_from_payload(canonical, payload)
    try:
        document = load_json_bytes(payload, f"{command_id} gate attachment")
    except ReleaseError as error:
        raise CommandPlaneError(
            f"gate attachment is not strict JSON: {error}"
        ) from error
    if command_id in NATIVE_RAW_COMMANDS:
        _validate_native_raw(document, command_id, source, canonical)
        return attachment
    if not isinstance(document, dict) or document.get("status") not in {
        "passed",
        "pass",
    }:
        raise CommandPlaneError("gate attachment does not report a passing status")
    attachment_source = document.get("source")
    if (
        not isinstance(attachment_source, dict)
        or attachment_source.get("revision") != source["revision"]
        or attachment_source.get("committed") is not True
        or attachment_source.get("clean") is not True
    ):
        raise CommandPlaneError(
            "gate attachment is not bound to the clean source revision"
        )
    tree = attachment_source.get("tree")
    if tree is not None and tree != source["tree"]:
        raise CommandPlaneError("gate attachment is bound to another source tree")
    return attachment


def _lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX_64 for character in value)
    )


def _validate_native_stream(value: object, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"bytes", "sha256"}
        or isinstance(value.get("bytes"), bool)
        or not isinstance(value.get("bytes"), int)
        or not 0 <= value["bytes"] <= MAXIMUM_COMMAND_OUTPUT_BYTES
        or not _lower_sha256(value.get("sha256"))
    ):
        raise CommandPlaneError(f"native raw {label} binding is invalid")


def _stable_executable_digest(
    path: Path, *, maximum_bytes: int
) -> tuple[os.stat_result, int, str]:
    """Hash one executable through a no-follow descriptor and reject replacement."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        named_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CommandPlaneError("native raw runtime cannot be opened safely") from error
    try:
        opened_before = os.fstat(descriptor)
        if _stat_identity(named_before) != _stat_identity(opened_before):
            raise CommandPlaneError(
                "native raw runtime changed between named and opened inspection"
            )
        if opened_before.st_size <= 0 or opened_before.st_size > maximum_bytes:
            raise CommandPlaneError("native raw runtime exceeds its byte bound")
        digest = hashlib.sha256()
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = path.lstat()
    except OSError as error:
        raise CommandPlaneError(
            "native raw runtime changed after inspection"
        ) from error
    if total > maximum_bytes or not (
        _stat_identity(named_before)
        == _stat_identity(opened_before)
        == _stat_identity(opened_after)
        == _stat_identity(named_after)
    ):
        raise CommandPlaneError("native raw runtime changed while it was inspected")
    return opened_before, total, digest.hexdigest()


def _validate_native_runtime(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "bytes",
        "sha256",
        "authority",
        "limitation",
        "version",
        "version_probe",
    }:
        raise CommandPlaneError("native raw runtime binding has an unexpected shape")
    path_value = value.get("path")
    byte_count = value.get("bytes")
    version = value.get("version")
    probe = value.get("version_probe")
    probe_fields = {
        "exit_code",
        "stderr_bytes",
        "stderr_sha256",
        "stdout_bytes",
        "stdout_sha256",
        "version",
    }
    expected_output = (
        f"Python {version}\n".encode("utf-8") if isinstance(version, str) else b""
    )
    empty_digest = sha256_bytes(b"")
    expected_digest = sha256_bytes(expected_output)
    probe_streams_are_exact = isinstance(probe, dict) and (
        (
            probe.get("stdout_bytes") == len(expected_output)
            and probe.get("stdout_sha256") == expected_digest
            and probe.get("stderr_bytes") == 0
            and probe.get("stderr_sha256") == empty_digest
        )
        or (
            probe.get("stderr_bytes") == len(expected_output)
            and probe.get("stderr_sha256") == expected_digest
            and probe.get("stdout_bytes") == 0
            and probe.get("stdout_sha256") == empty_digest
        )
    )
    if (
        not isinstance(path_value, str)
        or not path_value
        or not Path(path_value).is_absolute()
        or os.path.normpath(path_value) != path_value
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in path_value
        )
        or isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or not 0 < byte_count <= MAXIMUM_NATIVE_RUNTIME_BYTES
        or not _lower_sha256(value.get("sha256"))
        or value.get("authority") != "operator-reviewed-sha256"
        or value.get("limitation") != "transitive-runtime-files-not-bound"
        or not isinstance(version, str)
        or version != "3.14.6"
        or not isinstance(probe, dict)
        or set(probe) != probe_fields
        or probe.get("exit_code") != 0
        or probe.get("version") != version
        or not probe_streams_are_exact
    ):
        raise CommandPlaneError("native raw runtime binding is invalid")
    path = Path(path_value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CommandPlaneError("native raw runtime is unavailable") from error
    metadata, actual_bytes, actual_sha256 = _stable_executable_digest(
        path, maximum_bytes=MAXIMUM_NATIVE_RUNTIME_BYTES
    )
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not metadata.st_mode & stat.S_IXUSR
        or (metadata.st_uid != 0 and metadata.st_nlink != 1)
        or actual_bytes != byte_count
        or actual_sha256 != value.get("sha256")
    ):
        raise CommandPlaneError(
            "native raw runtime does not match its operator-reviewed executable"
        )
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        try:
            ancestor = current.lstat()
        except OSError as error:
            raise CommandPlaneError(
                "native raw runtime parent is unavailable"
            ) from error
        mode = stat.S_IMODE(ancestor.st_mode)
        sticky_root = ancestor.st_uid == 0 and bool(ancestor.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(ancestor.st_mode)
            or stat.S_ISLNK(ancestor.st_mode)
            or ancestor.st_uid not in {0, os.geteuid()}
            or (mode & 0o022 and not sticky_root)
        ):
            raise CommandPlaneError("native raw runtime parent is unprotected")


def _validate_native_producer(value: object, root: Path) -> None:
    if not isinstance(value, dict) or set(value) != {"closure"}:
        raise CommandPlaneError("native raw producer binding has an unexpected shape")
    closure = value.get("closure")
    if not isinstance(closure, dict) or set(closure) != NATIVE_PRODUCER_CLOSURE:
        raise CommandPlaneError("native raw producer closure is incomplete")
    for relative, binding in closure.items():
        if (
            not isinstance(binding, dict)
            or set(binding) != {"bytes", "sha256"}
            or isinstance(binding.get("bytes"), bool)
            or not isinstance(binding.get("bytes"), int)
            or not 0 < binding["bytes"] <= 16 * 1024 * 1024
            or not _lower_sha256(binding.get("sha256"))
        ):
            raise CommandPlaneError("native raw producer file binding is invalid")
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CommandPlaneError(
                "native raw producer file is unavailable"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size != binding["bytes"]
            or sha256_file(path) != binding["sha256"]
        ):
            raise CommandPlaneError("native raw producer file binding is stale")


def _validate_native_raw(
    value: object,
    command_id: str,
    source: Mapping[str, Any],
    relative: str,
) -> None:
    if relative != f"command-plane/{command_id}.raw.json":
        raise CommandPlaneError("native raw attachment path is not exact")
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "command_id",
        "source",
        "status",
        "exit_code",
        "runtime",
        "producer",
        "authority",
        "executions",
        "outputs",
        "details",
    }:
        raise CommandPlaneError("native raw attachment has an unexpected shape")
    _validate_native_runtime(value.get("runtime"))
    _validate_native_producer(value.get("producer"), REPOSITORY_ROOT)
    authority = value.get("authority")
    if command_id == "test-sanitizers":
        if authority is not None:
            raise CommandPlaneError("sanitizer raw attachment has ambient authority")
    else:
        _validate_native_stream(authority, "authority")
        if authority["bytes"] <= 0 or authority["bytes"] > 256 * 1024:
            raise CommandPlaneError("native raw authority size is invalid")
    if (
        value.get("schema_version") != NATIVE_RAW_SCHEMA
        or value.get("command_id") != command_id
        or value.get("source") != dict(source)
        or value.get("status") != "passed"
        or value.get("exit_code") != 0
    ):
        raise CommandPlaneError("native raw attachment is stale or non-passing")

    executions = value.get("executions")
    if not isinstance(executions, list) or not executions:
        raise CommandPlaneError("native raw execution inventory is empty")
    tools: list[str] = []
    for execution in executions:
        if not isinstance(execution, dict) or set(execution) != {
            "tool",
            "exit_code",
            "stdout",
            "stderr",
            "command_sha256",
        }:
            raise CommandPlaneError("native raw execution has an unexpected shape")
        tool = execution.get("tool")
        if (
            not isinstance(tool, str)
            or not tool
            or len(tool) > 128
            or execution.get("exit_code") != 0
            or not _lower_sha256(execution.get("command_sha256"))
        ):
            raise CommandPlaneError("native raw execution identity is invalid")
        _validate_native_stream(execution.get("stdout"), "stdout")
        _validate_native_stream(execution.get("stderr"), "stderr")
        tools.append(tool)
    if command_id == "release-sign":
        if len(tools) % 2 != 0 or tools != [
            label
            for _ in range(len(tools) // 2)
            for label in ("release signature producer", "release signature verifier")
        ]:
            raise CommandPlaneError(
                "native raw signing execution inventory is incomplete"
            )
    elif tuple(tools) != NATIVE_EXECUTION_TOOLS[command_id]:
        raise CommandPlaneError("native raw execution inventory is not route-exact")

    outputs = value.get("outputs")
    if not isinstance(outputs, list):
        raise CommandPlaneError("native raw output inventory is invalid")
    roles: list[str] = []
    for output in outputs:
        if not isinstance(output, dict) or set(output) != {"role", "bytes", "sha256"}:
            raise CommandPlaneError("native raw output binding has an unexpected shape")
        role = output.get("role")
        if (
            not isinstance(role, str)
            or not role
            or isinstance(output.get("bytes"), bool)
            or not isinstance(output.get("bytes"), int)
            or output["bytes"] <= 0
            or not _lower_sha256(output.get("sha256"))
        ):
            raise CommandPlaneError("native raw output binding is invalid")
        roles.append(role)
    if command_id == "release-sign":
        if roles != ["signature-envelope"] * (len(tools) // 2):
            raise CommandPlaneError(
                "native raw signature output inventory is incomplete"
            )
    elif tuple(roles) != NATIVE_OUTPUT_ROLES[command_id]:
        raise CommandPlaneError("native raw output inventory is not route-exact")

    details = value.get("details")
    expected_detail_keys = NATIVE_BASE_DETAIL_KEYS | NATIVE_DETAIL_KEYS[command_id]
    if not isinstance(details, dict) or set(details) != expected_detail_keys:
        raise CommandPlaneError("native raw detail inventory is not route-exact")
    if (
        details.get("platform_scope") != ["macos-arm64"]
        or details.get("fuzz_executed") is not False
        or details.get("soak_executed") is not False
        or details.get("mutation_campaign_executed") is not False
        or details.get("hundred_gib_scale_executed") is not False
    ):
        raise CommandPlaneError("native raw prohibited-work claims are invalid")
    if command_id == "bench-micro-verify" and details != {
        **{key: details[key] for key in NATIVE_BASE_DETAIL_KEYS},
        "qualified_performance_replay": True,
        "physical_scale_receipt_verified": False,
    }:
        raise CommandPlaneError("microbenchmark raw details overclaim verification")
    if command_id == "bench-macro-verify" and (
        details.get("qualified_performance_replay") is not True
        or details.get("physical_scale_receipt_verified") is not True
    ):
        raise CommandPlaneError("macrobenchmark raw details are incomplete")
    if command_id == "bench-efficacy" and (
        details.get("qualified_comparator_count") != 12
        or details.get("matrix_reproduced") is not True
    ):
        raise CommandPlaneError("efficacy raw details are incomplete")
    if command_id == "package-all" and (
        details.get("artifact_count") != 17
        or details.get("development_only") is not True
        or details.get("producer_count") != 10
        or details.get("signed") is not False
    ):
        raise CommandPlaneError("package-all raw details are inconsistent")
    if command_id == "package-smoke" and (
        details.get("artifact_count") != 17
        or details.get("installed_bytes_executed") is not True
        or details.get("source_revision") != source.get("revision")
    ):
        raise CommandPlaneError("package-smoke raw details are inconsistent")
    if command_id == "release-sbom" and (
        details.get("artifact_count") != 17
        or details.get("sbom_document_count") != 3
        or details.get("sidecars_pending_offline_reconciliation") is not True
    ):
        raise CommandPlaneError("release-sbom raw details are incomplete")
    if command_id == "release-attest" and (
        details.get("artifact_count") != 17
        or details.get("subject_count") != 17
        or details.get("network_mode") != "disabled"
        or details.get("sidecars_pending_offline_reconciliation") is not True
    ):
        raise CommandPlaneError("release-attest raw details are incomplete")
    if command_id == "release-sign" and (
        details.get("signature_count") != len(outputs)
        or details.get("signing_executed") is not True
        or details.get("signing_phase") != "supporting"
        or details.get("release_evidence_signature_deferred") is not True
        or details.get("sidecars_pending_offline_reconciliation") is not True
    ):
        raise CommandPlaneError("release-sign raw details are incomplete")
    if command_id == "release-verify" and (
        details.get("artifact_count") != 17
        or details.get("offline_verified") is not True
        or details.get("sidecar_inventory_reconciled") is not True
        or not _lower_sha256(details.get("reviewed_openssl_sha256"))
    ):
        raise CommandPlaneError("release-verify raw details are incomplete")
    if command_id == "test-sanitizers" and (
        details.get("case_count") != 10
        or details.get("test_exclusions") != 0
        or details.get("rust_ubsan_claimed") is not False
    ):
        raise CommandPlaneError("sanitizer raw details are inconsistent")


def _reviewed_tool_authority(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "command_id",
        "executions",
        "manifest",
        "network_enforcement",
        "review_status",
        "tools",
    }:
        raise CommandPlaneError("reviewed tool authority binding is invalid")
    manifest = value.get("manifest")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"bytes", "sha256"}
        or isinstance(manifest.get("bytes"), bool)
        or not isinstance(manifest.get("bytes"), int)
        or not 0 < manifest["bytes"] <= 1024 * 1024
        or not _lower_sha256(manifest.get("sha256"))
        or value.get("network_enforcement") != "not-enforced"
        or value.get("review_status")
        not in {"operator-reviewed", "diagnostic-self-observed"}
    ):
        raise CommandPlaneError("reviewed tool authority manifest binding is invalid")
    command_id = value.get("command_id")
    if not isinstance(command_id, str) or command_id not in ROUTE_TOOLS:
        raise CommandPlaneError("reviewed tool authority route is unsupported")
    expected_tools = ROUTE_TOOLS[command_id]
    if not expected_tools:
        raise CommandPlaneError("route must not carry an unrelated tool authority")
    tools = value.get("tools")
    if (
        not isinstance(tools, dict)
        or set(tools) != expected_tools
        or any(not _lower_sha256(digest) for digest in tools.values())
    ):
        raise CommandPlaneError("reviewed tool digest inventory is not exact")
    executions = value.get("executions")
    if not isinstance(executions, list) or len(executions) > 4096:
        raise CommandPlaneError("reviewed tool execution inventory is invalid")
    execution_fields = {
        "command_sha256",
        "executable_sha256",
        "exit_code",
        "stderr_bytes",
        "stderr_sha256",
        "stdout_bytes",
        "stdout_sha256",
        "tool",
    }
    for execution in executions:
        if not isinstance(execution, dict) or set(execution) != execution_fields:
            raise CommandPlaneError("reviewed tool execution has an unexpected shape")
        if (
            not isinstance(execution.get("tool"), str)
            or re.fullmatch(r"[A-Za-z0-9._:+-]{1,128}", execution["tool"]) is None
            or execution.get("exit_code") != 0
            or not _lower_sha256(execution.get("command_sha256"))
            or not _lower_sha256(execution.get("executable_sha256"))
        ):
            raise CommandPlaneError("reviewed tool execution identity is invalid")
        tool_name = execution["tool"]
        selected_name: str | None
        if tool_name.startswith("nested-protoc-plugin:"):
            selected_name = tool_name.removeprefix("nested-protoc-plugin:")
        elif tool_name.startswith("derived-target:"):
            selected_name = None
        else:
            selected_name = tool_name
        if selected_name is not None and (
            selected_name not in tools
            or execution.get("executable_sha256") != tools[selected_name]
        ):
            raise CommandPlaneError(
                "reviewed tool execution differs from the route authority"
            )
        for stream in ("stdout", "stderr"):
            size = execution.get(f"{stream}_bytes")
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 <= size <= 32 * 1024 * 1024
                or not _lower_sha256(execution.get(f"{stream}_sha256"))
            ):
                raise CommandPlaneError("reviewed tool stream binding is invalid")
    return {
        "command_id": command_id,
        "executions": [dict(execution) for execution in executions],
        "manifest": dict(manifest),
        "network_enforcement": "not-enforced",
        "review_status": value["review_status"],
        "tools": dict(tools),
    }


def _reviewed_tool_authority_argument(value: str | None) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        decoded = load_json_bytes(value.encode("utf-8"), "reviewed tool authority")
    except (UnicodeError, ReleaseError) as error:
        raise CommandPlaneError(
            "reviewed tool authority argument is not strict JSON"
        ) from error
    if canonical_json_bytes(decoded).decode("utf-8").strip() != value:
        raise CommandPlaneError(
            "reviewed tool authority argument must be canonical JSON"
        )
    return _reviewed_tool_authority(decoded)


def _require_route_tool_authority(
    command_id: str, reviewed: Mapping[str, object] | None
) -> None:
    expected = ROUTE_TOOLS.get(command_id)
    if expected is None:
        raise CommandPlaneError("command is absent from the route tool authority")
    if bool(expected) != (reviewed is not None):
        raise CommandPlaneError(
            "command tool authority presence differs from its exact route policy"
        )
    if reviewed is not None and reviewed.get("command_id") != command_id:
        raise CommandPlaneError("reviewed tool authority is bound to another route")


def _receipt(
    *,
    root: Path,
    command_id: str,
    source: dict[str, Any],
    command: dict[str, Any],
    manifest_sha256: str,
    attachment: Attachment,
    started_at: str,
    finished_at: str,
    duration_ms: int,
    tool_authority: Mapping[str, object] | None,
    metrics: Mapping[str, int | float] | None = None,
) -> dict[str, Any]:
    display = command["command"]
    runtime_path = Path(sys.executable).resolve(strict=True)
    runtime_metadata = runtime_path.lstat()
    if (
        not stat.S_ISREG(runtime_metadata.st_mode)
        or stat.S_IMODE(runtime_metadata.st_mode) & 0o022
        or runtime_metadata.st_size <= 0
        or runtime_metadata.st_size > MAXIMUM_NATIVE_RUNTIME_BYTES
    ):
        raise CommandPlaneError("command evidence Python runtime is not protected")
    return {
        "schema_version": "cigar.xtask-command-receipt.v1",
        "id": f"xtask-{command_id}",
        "category": "command-plane",
        "command": {
            "id": command_id,
            "display": display,
            "sha256": sha256_bytes(canonical_json_bytes(display.split())),
            "manifest": {
                "path": MANIFEST_PATH,
                "sha256": manifest_sha256,
            },
        },
        "producer": {
            "path": HELPER_PATH,
            "sha256": sha256_file(root / HELPER_PATH),
            "closure": {path: sha256_file(root / path) for path in HELPER_CLOSURE},
            "runtime": {
                "path": os.fspath(runtime_path),
                "bytes": runtime_metadata.st_size,
                "sha256": sha256_file(runtime_path),
            },
        },
        "tool_authority": None if tool_authority is None else dict(tool_authority),
        "source": source,
        "source_descriptor_bound": False,
        "source_archive_bound": False,
        "host": _require_native_macos_arm64(),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "status": "passed",
        "metrics": dict(metrics or {}),
        "attachments": [attachment.as_dict()],
        "release_eligible": False,
        "limitations": [
            "unsigned-command-receipt",
            "source-descriptor-not-supplied",
            "source-archive-not-supplied",
        ],
    }


def publish_record(
    *,
    root: Path,
    evidence_directory: Path,
    command_id: str,
    expected_source: dict[str, Any],
    attachment_relative: str | None,
    started_unix_ms: int,
    duration_ms: int,
    raw_metrics: Mapping[str, int | float] | None = None,
    raw_details: Mapping[str, Any] | None = None,
    tool_authority: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    if (
        isinstance(duration_ms, bool)
        or duration_ms < 0
        or duration_ms > 7 * 24 * 60 * 60 * 1000
    ):
        raise CommandPlaneError("gate duration is outside the bounded range")
    metrics = _validate_command_metrics(command_id, raw_metrics)
    reviewed_tools = _reviewed_tool_authority(tool_authority)
    _require_route_tool_authority(command_id, reviewed_tools)
    _require_clean_source(expected_source)
    source = source_binding(root)
    _require_clean_source(source)
    if source != expected_source:
        raise CommandPlaneError("Git source changed while the command gate executed")
    command, manifest_sha256 = _command_entry(root, command_id)
    workspace = EvidenceWorkspace.create(evidence_directory, repository_root=root)
    try:
        if attachment_relative is None:
            workspace.read_files(set())
            raw = {
                "schema_version": "cigar.xtask-command-raw.v1",
                "command_id": command_id,
                "source": source,
                "status": "passed",
                "exit_code": 0,
                "metrics": metrics,
                "details": {
                    "fuzz_executed": False,
                    "soak_executed": False,
                    **dict(raw_details or {}),
                },
            }
            raw_path = f"command-plane/{command_id}.raw.json"
            attachment = workspace.write_json(raw_path, raw)
        else:
            attachment = _validate_existing_attachment(
                workspace, attachment_relative, command_id, source
            )
        started_at = _utc_from_unix_ms(started_unix_ms)
        finished_at = _utc_now()
        receipt = _receipt(
            root=root,
            command_id=command_id,
            source=source,
            command=command,
            manifest_sha256=manifest_sha256,
            attachment=attachment,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            tool_authority=reviewed_tools,
            metrics=metrics,
        )
        receipt_path = f"command-plane/{command_id}.receipt.json"
        workspace.write_json(receipt_path, receipt)
        expected_inventory = {attachment.path, receipt_path}
        snapshot = workspace.read_files(expected_inventory)
        if any(not payload for payload in snapshot.values()):
            raise CommandPlaneError("command evidence contains an empty file")
        return receipt
    finally:
        workspace.close()


def _load_canonical_document(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = load_json_bytes(payload, label)
    except ReleaseError as error:
        raise CommandPlaneError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(document, dict):
        raise CommandPlaneError(f"{label} must be a JSON object")
    if canonical_json_bytes(document) != payload:
        raise CommandPlaneError(f"{label} is not canonical JSON")
    return document


def verify_record(
    *,
    root: Path,
    evidence_directory: Path,
    command_id: str,
    expected_source: dict[str, Any],
    attachment_relative: str | None,
    tool_authority: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Independently re-open and verify a published command receipt and attachment."""

    _require_native_macos_arm64()
    _require_clean_source(expected_source)
    source = source_binding(root)
    _require_clean_source(source)
    if source != expected_source:
        raise CommandPlaneError(
            "Git source changed before command evidence verification"
        )
    command, manifest_sha256 = _command_entry(root, command_id)
    attachment_path = (
        f"command-plane/{command_id}.raw.json"
        if attachment_relative is None
        else "/".join(safe_relative_path(attachment_relative))
    )
    receipt_path = f"command-plane/{command_id}.receipt.json"
    workspace = EvidenceWorkspace.create(evidence_directory, repository_root=root)
    try:
        payloads = workspace.read_files({attachment_path, receipt_path})
    finally:
        workspace.close()
    attachment_payload = payloads[attachment_path]
    receipt_payload = payloads[receipt_path]
    attachment = _attachment_from_payload(attachment_path, attachment_payload)
    receipt = _load_canonical_document(receipt_payload, "xtask command receipt")
    expected_command = {
        "id": command_id,
        "display": command["command"],
        "sha256": sha256_bytes(canonical_json_bytes(command["command"].split())),
        "manifest": {"path": MANIFEST_PATH, "sha256": manifest_sha256},
    }
    runtime_path = Path(sys.executable).resolve(strict=True)
    runtime_metadata = runtime_path.lstat()
    expected_producer = {
        "path": HELPER_PATH,
        "sha256": sha256_file(root / HELPER_PATH),
        "closure": {path: sha256_file(root / path) for path in HELPER_CLOSURE},
        "runtime": {
            "path": os.fspath(runtime_path),
            "bytes": runtime_metadata.st_size,
            "sha256": sha256_file(runtime_path),
        },
    }
    expected_attachment = attachment.as_dict()
    reviewed_tools = _reviewed_tool_authority(tool_authority)
    _require_route_tool_authority(command_id, reviewed_tools)
    if set(receipt) != {
        "schema_version",
        "id",
        "category",
        "command",
        "producer",
        "tool_authority",
        "source",
        "source_descriptor_bound",
        "source_archive_bound",
        "host",
        "started_at",
        "finished_at",
        "duration_ms",
        "status",
        "metrics",
        "attachments",
        "release_eligible",
        "limitations",
    }:
        raise CommandPlaneError("xtask command receipt has an unexpected shape")
    duration_ms = receipt.get("duration_ms")
    metrics_value = receipt.get("metrics")
    if not isinstance(metrics_value, dict):
        raise CommandPlaneError("xtask command receipt metrics must be an object")
    metrics = _validate_command_metrics(command_id, metrics_value)
    if (
        receipt.get("schema_version") != "cigar.xtask-command-receipt.v1"
        or receipt.get("id") != f"xtask-{command_id}"
        or receipt.get("category") != "command-plane"
        or receipt.get("command") != expected_command
        or receipt.get("producer") != expected_producer
        or receipt.get("tool_authority") != reviewed_tools
        or receipt.get("source") != source
        or receipt.get("source_descriptor_bound") is not False
        or receipt.get("source_archive_bound") is not False
        or receipt.get("host") != _require_native_macos_arm64()
        or not isinstance(receipt.get("started_at"), str)
        or not receipt["started_at"]
        or not isinstance(receipt.get("finished_at"), str)
        or not receipt["finished_at"]
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or not 0 <= duration_ms <= 7 * 24 * 60 * 60 * 1000
        or receipt.get("status") != "passed"
        or receipt.get("attachments") != [expected_attachment]
        or receipt.get("release_eligible") is not False
        or receipt.get("limitations")
        != [
            "unsigned-command-receipt",
            "source-descriptor-not-supplied",
            "source-archive-not-supplied",
        ]
    ):
        raise CommandPlaneError(
            "xtask command receipt is stale, substituted, or has a prohibited status"
        )
    attachment_document = _load_canonical_document(
        attachment_payload, "xtask command attachment"
    )
    if attachment_relative is None:
        if set(attachment_document) != {
            "schema_version",
            "command_id",
            "source",
            "status",
            "exit_code",
            "metrics",
            "details",
        }:
            raise CommandPlaneError(
                "xtask raw command attachment has an unexpected shape"
            )
        details = attachment_document.get("details")
        if (
            attachment_document.get("schema_version") != "cigar.xtask-command-raw.v1"
            or attachment_document.get("command_id") != command_id
            or attachment_document.get("source") != source
            or attachment_document.get("status") != "passed"
            or attachment_document.get("exit_code") != 0
            or attachment_document.get("metrics") != metrics
            or not isinstance(details, dict)
            or details.get("fuzz_executed") is not False
            or details.get("soak_executed") is not False
        ):
            raise CommandPlaneError(
                "xtask raw command attachment is stale, synthetic, or non-passing"
            )
        if command_id == "test-mutations-verify":
            with tempfile.TemporaryDirectory(
                prefix="cigar-xtask-mutation-verify-"
            ) as raw:
                temporary_root = Path(raw).resolve(strict=True)
                # Owner-only mode protects unpublished mutation replay inputs from local accounts.
                os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                    temporary_root,
                    0o700,
                )
                environment = _mutation_environment(temporary_root)
                _validate_mutation_raw_details(
                    root=root,
                    details=details,
                    metrics=metrics,
                    environment=environment,
                )
    else:
        if command_id in NATIVE_RAW_COMMANDS:
            _validate_native_raw(
                attachment_document, command_id, source, attachment_relative
            )
        else:
            status = attachment_document.get("status")
            attachment_source = attachment_document.get("source")
            if (
                status not in {"passed", "pass"}
                or not isinstance(attachment_source, dict)
                or attachment_source.get("revision") != source["revision"]
                or attachment_source.get("committed") is not True
                or attachment_source.get("clean") is not True
                or (
                    attachment_source.get("tree") is not None
                    and attachment_source.get("tree") != source["tree"]
                )
            ):
                raise CommandPlaneError(
                    "external command attachment is stale or has a prohibited status"
                )
    final_source = source_binding(root)
    _require_clean_source(final_source)
    if final_source != expected_source:
        raise CommandPlaneError(
            "Git source changed during command evidence verification"
        )
    return receipt


def _coverage_metric(
    value: object, label: str, *, allow_empty: bool = False
) -> dict[str, int | float]:
    if not isinstance(value, dict):
        raise CommandPlaneError(f"LLVM {label} coverage totals are missing")
    count = value.get("count")
    covered = value.get("covered")
    percent = value.get("percent")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or (count == 0 and not allow_empty)
        or isinstance(covered, bool)
        or not isinstance(covered, int)
        or not 0 <= covered <= count
        or isinstance(percent, bool)
        or not isinstance(percent, (int, float))
        or not math.isfinite(float(percent))
        or not 0.0 <= float(percent) <= 100.0
    ):
        raise CommandPlaneError(f"LLVM {label} coverage totals are invalid")
    recomputed = 0.0 if count == 0 else 100.0 * covered / count
    if abs(recomputed - float(percent)) > 0.01:
        raise CommandPlaneError(f"LLVM {label} coverage percentage is inconsistent")
    return {"count": count, "covered": covered, "percent": round(recomputed, 6)}


def _coverage_totals(document: object) -> dict[str, int | float]:
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise CommandPlaneError("LLVM coverage output has an unexpected root")
    data = document["data"]
    if len(data) != 1 or not isinstance(data[0], dict):
        raise CommandPlaneError("LLVM coverage output must contain one aggregate")
    totals = data[0].get("totals")
    if not isinstance(totals, dict):
        raise CommandPlaneError("LLVM coverage totals are missing")
    result: dict[str, int | float] = {}
    for name, metric in (
        ("lines", "line"),
        ("branches", "branch"),
        ("functions", "function"),
    ):
        parsed = _coverage_metric(totals.get(name), name)
        result[f"coverage.{metric}_count"] = parsed["count"]
        result[f"coverage.{metric}_covered"] = parsed["covered"]
        result[f"coverage.{metric}_percent"] = parsed["percent"]
    return result


def _coverage_thresholds(root: Path) -> tuple[dict[str, float], str]:
    path = root / REQUIREMENTS_PATH
    try:
        payload = path.read_bytes()
        document = load_json_bytes(payload, "release coverage policy")
    except (OSError, ReleaseError) as error:
        raise CommandPlaneError(
            f"release coverage policy is unavailable: {error}"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "cigar.release-requirements.v1"
        or not isinstance(document.get("metric_gates"), list)
    ):
        raise CommandPlaneError("release coverage policy has an unexpected identity")
    expected = {
        "coverage.line_percent": "line_percent",
        "coverage.branch_percent": "branch_percent",
    }
    thresholds: dict[str, float] = {}
    for metric_name, output_name in expected.items():
        matches = [
            gate
            for gate in document["metric_gates"]
            if isinstance(gate, dict) and gate.get("name") == metric_name
        ]
        if len(matches) != 1:
            raise CommandPlaneError(
                f"release coverage policy must define {metric_name} exactly once"
            )
        gate = matches[0]
        threshold = gate.get("threshold")
        if (
            gate.get("category") != "coverage"
            or gate.get("aggregation") != "min"
            or gate.get("comparison") != "gte"
            or gate.get("valid_min") != 0
            or gate.get("valid_max") != 100
            or isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(float(threshold))
            or not 0.0 <= float(threshold) <= 100.0
        ):
            raise CommandPlaneError(f"release coverage gate {metric_name} is invalid")
        thresholds[output_name] = float(threshold)
    return thresholds, sha256_bytes(payload)


def _coverage_collection_commands(root: Path) -> list[tuple[str, list[str]]]:
    commands: list[tuple[str, list[str]]] = []
    for collection in COVERAGE_COLLECTIONS:
        identifier = collection["id"]
        arguments = collection["arguments"]
        if not isinstance(identifier, str) or not isinstance(arguments, tuple):
            raise CommandPlaneError("coverage collection declaration is invalid")
        commands.append(
            (
                identifier,
                [
                    "cargo",
                    f"+{COVERAGE_RUST_TOOLCHAIN}",
                    "llvm-cov",
                    "nextest",
                    "--no-report",
                    "--branch",
                    "--locked",
                    "--offline",
                    *arguments,
                    "-P",
                    "macos-qualification",
                    "--no-tests",
                    "fail",
                ],
            )
        )
    commands.append(
        (
            "independent-properties",
            [
                "cargo",
                f"+{COVERAGE_RUST_TOOLCHAIN}",
                "llvm-cov",
                "nextest",
                "--no-report",
                "--branch",
                "--locked",
                "--offline",
                "--manifest-path",
                "tests/properties/Cargo.toml",
                "--workspace",
                "--all-targets",
                "--dep-coverage",
                ",".join(COVERAGE_PROPERTY_DEPENDENCIES),
                "--config-file",
                os.fspath(root / "tests/properties/.config/nextest.toml"),
                "--user-config-file",
                "none",
                "-P",
                "macos-qualification",
                "--no-tests",
                "fail",
            ],
        )
    )
    return commands


def _coverage_report_command(output: Path, report_format: str) -> list[str]:
    if report_format not in {"json", "lcov"}:
        raise CommandPlaneError("coverage report format is unsupported")
    return [
        "cargo",
        f"+{COVERAGE_RUST_TOOLCHAIN}",
        "llvm-cov",
        "report",
        "--locked",
        "--offline",
        f"--{report_format}",
        *(["--summary-only"] if report_format == "json" else []),
        "--output-path",
        os.fspath(output),
    ]


def _coverage_environment(temporary_root: Path) -> dict[str, str]:
    environment = child_environment_without_evidence()
    for name in COVERAGE_CONTROL_ENVIRONMENT:
        environment.pop(name, None)
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "CARGO_LLVM_COV_TARGET_DIR": os.fspath(temporary_root / "target"),
            "NO_COLOR": "1",
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _coverage_toolchain(
    root: Path, environment: Mapping[str, str]
) -> dict[str, dict[str, int | str]]:
    requirements = (
        ("cargo", ["cargo", "--version"], b"cargo 1.92.0 ", ()),
        ("rustc", ["rustc", "--version"], b"rustc 1.92.0 ", ()),
        (
            "coverage-rustc",
            ["rustc", f"+{COVERAGE_RUST_TOOLCHAIN}", "--version", "--verbose"],
            b"rustc 1.99.0-nightly (77cf889bc 2026-07-12)",
            (
                b"commit-hash: 77cf889bc178ddb44d6a1c78e5a820b5abb31d8d",
                b"host: aarch64-apple-darwin",
                b"LLVM version: 22.1.8",
            ),
        ),
        (
            "coverage-cargo",
            ["cargo", f"+{COVERAGE_RUST_TOOLCHAIN}", "--version", "--verbose"],
            b"cargo 1.99.0-nightly (59800466c 2026-07-07)",
            (
                b"commit-hash: 59800466c5c41c444d264b1010b4d57e85a7117f",
                b"host: aarch64-apple-darwin",
            ),
        ),
        (
            "coverage-components",
            [
                "rustup",
                "component",
                "list",
                "--toolchain",
                COVERAGE_RUST_TOOLCHAIN,
                "--installed",
            ],
            b"cargo-aarch64-apple-darwin",
            (b"llvm-tools-aarch64-apple-darwin",),
        ),
        (
            "cargo-nextest",
            ["cargo", f"+{COVERAGE_RUST_TOOLCHAIN}", "nextest", "--version"],
            b"cargo-nextest 0.9.140 ",
            (b"release: 0.9.140", b"host: aarch64-apple-darwin"),
        ),
        (
            "cargo-llvm-cov",
            ["cargo", f"+{COVERAGE_RUST_TOOLCHAIN}", "llvm-cov", "--version"],
            b"cargo-llvm-cov 0.8.7",
            (),
        ),
    )
    tools: dict[str, dict[str, int | str]] = {}
    for name, command, prefix, required in requirements:
        try:
            result = run_bounded(
                command,
                cwd=root,
                env=environment,
                timeout=30,
                max_stdout=16 * 1024,
                max_stderr=16 * 1024,
            )
        except ReleaseError as error:
            raise CommandPlaneError(
                f"coverage tool {name} is unavailable: {error}"
            ) from error
        output = result.stdout.strip()
        if (
            result.returncode != 0
            or not output.startswith(prefix)
            or any(item not in output for item in required)
        ):
            raise CommandPlaneError(
                f"coverage tool {name} is not the pinned native version"
            )
        tools[name] = {
            "stdout_bytes": len(result.stdout),
            "stdout_sha256": sha256_bytes(result.stdout),
            "stderr_bytes": len(result.stderr),
            "stderr_sha256": sha256_bytes(result.stderr),
        }
    return tools


def _run_coverage_process(
    command: Sequence[str],
    *,
    root: Path,
    environment: Mapping[str, str],
    label: str,
) -> dict[str, int | str]:
    try:
        result = run_bounded(
            command,
            cwd=root,
            env=environment,
            timeout=4 * 60 * 60,
            max_stdout=MAXIMUM_COMMAND_OUTPUT_BYTES,
            max_stderr=MAXIMUM_COMMAND_OUTPUT_BYTES,
        )
    except ReleaseError as error:
        raise CommandPlaneError(f"coverage {label} failed: {error}") from error
    if result.returncode != 0:
        raise CommandPlaneError(
            f"coverage {label} returned a nonzero status; output was suppressed "
            f"(stdout_bytes={len(result.stdout)}, stdout_sha256={sha256_bytes(result.stdout)}, "
            f"stderr_bytes={len(result.stderr)}, stderr_sha256={sha256_bytes(result.stderr)})"
        )
    return {
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256_bytes(result.stderr),
    }


def _cargo_metadata(root: Path, environment: Mapping[str, str]) -> dict[str, object]:
    try:
        result = run_bounded(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--locked",
                "--offline",
            ],
            cwd=root,
            env=environment,
            timeout=180,
            max_stdout=MAXIMUM_COMMAND_OUTPUT_BYTES,
            max_stderr=MAXIMUM_COMMAND_OUTPUT_BYTES,
        )
    except ReleaseError as error:
        raise CommandPlaneError(
            f"coverage metadata preflight failed: {error}"
        ) from error
    if result.returncode != 0:
        raise CommandPlaneError(
            "coverage metadata preflight returned a nonzero status; output was suppressed"
        )
    try:
        document = load_json_bytes(result.stdout, "coverage Cargo metadata")
    except ReleaseError as error:
        raise CommandPlaneError(
            f"coverage Cargo metadata is invalid: {error}"
        ) from error
    if not isinstance(document, dict):
        raise CommandPlaneError("coverage Cargo metadata has an unexpected root")
    return document


def _expand_package_features(
    feature_map: Mapping[str, object], seeds: Sequence[str]
) -> set[str]:
    pending = list(seeds)
    expanded: set[str] = set()
    while pending:
        feature = pending.pop()
        if feature in expanded or feature not in feature_map:
            continue
        expanded.add(feature)
        entries = feature_map[feature]
        if not isinstance(entries, list) or not all(
            isinstance(entry, str) for entry in entries
        ):
            raise CommandPlaneError("Cargo metadata contains an invalid feature map")
        for entry in entries:
            candidate = entry.split("/", 1)[0].removesuffix("?")
            if not candidate.startswith("dep:") and candidate in feature_map:
                pending.append(candidate)
    return expanded


def _coverage_package_inventory(
    root: Path, metadata: Mapping[str, object]
) -> dict[str, dict[str, object]]:
    packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    workspace_root = metadata.get("workspace_root")
    if (
        not isinstance(packages, list)
        or not isinstance(workspace_members, list)
        or not all(isinstance(member, str) for member in workspace_members)
        or workspace_root != os.fspath(root)
    ):
        raise CommandPlaneError("coverage Cargo metadata identity is invalid")
    member_ids = set(workspace_members)
    inventory: dict[str, dict[str, object]] = {}
    for package in packages:
        if not isinstance(package, dict) or package.get("id") not in member_ids:
            continue
        name = package.get("name")
        manifest = package.get("manifest_path")
        features = package.get("features")
        targets = package.get("targets")
        if (
            not isinstance(name, str)
            or not isinstance(manifest, str)
            or not isinstance(features, dict)
            or not isinstance(targets, list)
            or not targets
            or name in inventory
        ):
            raise CommandPlaneError("coverage workspace package metadata is invalid")
        manifest_path = Path(manifest)
        try:
            canonical_manifest = manifest_path.resolve(strict=True)
            canonical_manifest.relative_to(root)
        except (OSError, ValueError) as error:
            raise CommandPlaneError(
                f"coverage package {name} is outside the repository"
            ) from error
        if canonical_manifest.name != "Cargo.toml":
            raise CommandPlaneError(f"coverage package {name} has an invalid manifest")
        normalized_targets: list[dict[str, object]] = []
        for target in targets:
            if (
                not isinstance(target, dict)
                or not isinstance(target.get("name"), str)
                or not isinstance(target.get("kind"), list)
                or not target["kind"]
                or not all(isinstance(kind, str) for kind in target["kind"])
            ):
                raise CommandPlaneError(
                    f"coverage package {name} has invalid target metadata"
                )
            normalized_targets.append(
                {"name": target["name"], "kind": sorted(target["kind"])}
            )
        inventory[name] = {
            "root": canonical_manifest.parent,
            "features": features,
            "targets": sorted(
                normalized_targets,
                key=lambda item: (str(item["name"]), canonical_json_bytes(item)),
            ),
        }
    if set(COVERAGE_EXCLUDED_PACKAGES) - set(inventory):
        raise CommandPlaneError("coverage exclusion names a missing workspace package")
    if len(inventory) != len(member_ids):
        raise CommandPlaneError("coverage workspace package inventory is incomplete")
    return inventory


def _validate_coverage_feature_plan(
    inventory: Mapping[str, Mapping[str, object]],
) -> None:
    covered: dict[str, set[str]] = {name: set() for name in inventory}
    for collection in COVERAGE_COLLECTIONS:
        scope = collection["scope"]
        if scope == "workspace":
            names = [
                name for name in inventory if name not in COVERAGE_EXCLUDED_PACKAGES
            ]
        elif isinstance(scope, str) and scope in inventory:
            names = [scope]
        else:
            raise CommandPlaneError(
                "coverage collection names an unknown package scope"
            )
        features = collection["features"]
        default_features = collection["default_features"]
        if not isinstance(features, tuple) or not isinstance(default_features, bool):
            raise CommandPlaneError(
                "coverage collection feature declaration is invalid"
            )
        for name in names:
            feature_map = inventory[name]["features"]
            if not isinstance(feature_map, dict):
                raise CommandPlaneError("coverage feature inventory is invalid")
            seeds = list(features)
            if default_features:
                seeds.append("default")
            covered[name].update(_expand_package_features(feature_map, seeds))
    for name, package in inventory.items():
        if name in COVERAGE_EXCLUDED_PACKAGES:
            continue
        feature_map = package["features"]
        if not isinstance(feature_map, dict):
            raise CommandPlaneError("coverage feature inventory is invalid")
        expected = set(feature_map) - {"default"}
        missing = sorted(expected - covered[name])
        if missing:
            raise CommandPlaneError(
                f"coverage plan omits features for {name}: {', '.join(missing)}"
            )


def _path_package(
    path: Path, inventory: Mapping[str, Mapping[str, object]]
) -> str | None:
    matches: list[tuple[int, str]] = []
    for name, package in inventory.items():
        package_root = package.get("root")
        if not isinstance(package_root, Path):
            raise CommandPlaneError("coverage package root inventory is invalid")
        try:
            path.relative_to(package_root)
        except ValueError:
            continue
        matches.append((len(package_root.parts), name))
    if not matches:
        return None
    matches.sort(reverse=True)
    return matches[0][1]


def _coverage_packages(
    root: Path,
    document: object,
    inventory: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise CommandPlaneError("LLVM coverage output has an unexpected root")
    data = document["data"]
    if len(data) != 1 or not isinstance(data[0], dict):
        raise CommandPlaneError("LLVM coverage output must contain one aggregate")
    files = data[0].get("files")
    if not isinstance(files, list) or not files:
        raise CommandPlaneError("LLVM coverage output contains no source files")
    counts: dict[str, dict[str, list[int]]] = {
        name: {metric: [0, 0] for metric in ("lines", "branches", "functions")}
        for name in inventory
        if name not in COVERAGE_EXCLUDED_PACKAGES
    }
    file_counts = {name: 0 for name in counts}
    for file_record in files:
        if not isinstance(file_record, dict):
            raise CommandPlaneError("LLVM coverage file record is invalid")
        filename = file_record.get("filename")
        summary = file_record.get("summary")
        if not isinstance(filename, str) or not isinstance(summary, dict):
            raise CommandPlaneError("LLVM coverage file record is incomplete")
        source = Path(filename)
        if not source.is_absolute():
            raise CommandPlaneError("LLVM coverage source path is not absolute")
        try:
            source = source.resolve(strict=True)
            source.relative_to(root)
        except (OSError, ValueError) as error:
            raise CommandPlaneError(
                "LLVM coverage includes source outside the repository"
            ) from error
        package_name = _path_package(source, inventory)
        if package_name is None:
            raise CommandPlaneError(
                "LLVM coverage source is not owned by a workspace package"
            )
        if package_name in COVERAGE_EXCLUDED_PACKAGES:
            raise CommandPlaneError(
                f"LLVM coverage unexpectedly includes excluded package {package_name}"
            )
        file_counts[package_name] += 1
        for metric in ("lines", "branches", "functions"):
            parsed = _coverage_metric(
                summary.get(metric), f"{filename} {metric}", allow_empty=True
            )
            counts[package_name][metric][0] += int(parsed["count"])
            counts[package_name][metric][1] += int(parsed["covered"])
    packages: list[dict[str, object]] = []
    for name in sorted(counts):
        if file_counts[name] <= 0:
            raise CommandPlaneError(
                f"LLVM coverage is missing workspace package {name}"
            )
        metrics: dict[str, object] = {}
        for metric in ("lines", "branches", "functions"):
            count, covered_count = counts[name][metric]
            if count <= 0 or not 0 <= covered_count <= count:
                raise CommandPlaneError(
                    f"LLVM coverage package {name} has no {metric} denominator"
                )
            metrics[metric] = {
                "count": count,
                "covered": covered_count,
                "percent": round(100.0 * covered_count / count, 6),
            }
        package = inventory[name]
        packages.append(
            {
                "name": name,
                "source_file_count": file_counts[name],
                "targets": package["targets"],
                "metrics": metrics,
            }
        )
    return packages


def _validate_package_totals(
    metrics: Mapping[str, int | float], packages: Sequence[Mapping[str, object]]
) -> None:
    for singular, plural in (
        ("line", "lines"),
        ("branch", "branches"),
        ("function", "functions"),
    ):
        count = 0
        covered = 0
        for package in packages:
            package_metrics = package.get("metrics")
            if not isinstance(package_metrics, dict):
                raise CommandPlaneError("coverage package metrics are invalid")
            value = package_metrics.get(plural)
            if not isinstance(value, dict):
                raise CommandPlaneError("coverage package metric is missing")
            count += int(value["count"])
            covered += int(value["covered"])
        if (
            count != metrics[f"coverage.{singular}_count"]
            or covered != metrics[f"coverage.{singular}_covered"]
        ):
            raise CommandPlaneError(
                f"coverage package {plural} do not reconcile to the LLVM aggregate"
            )


def _validate_lcov(
    payload: bytes,
    *,
    root: Path,
    inventory: Mapping[str, Mapping[str, object]],
    metrics: Mapping[str, int | float],
) -> dict[str, int]:
    if not payload or b"\x00" in payload:
        raise CommandPlaneError("LCOV coverage report is empty or contains NUL")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise CommandPlaneError("LCOV coverage report is not UTF-8") from error
    records: list[list[str]] = []
    pending: list[str] = []
    for line in text.splitlines():
        if line == "end_of_record":
            if not pending:
                raise CommandPlaneError("LCOV coverage report contains an empty record")
            records.append(pending)
            pending = []
        else:
            pending.append(line)
    if pending:
        raise CommandPlaneError("LCOV coverage report is truncated")
    if not records:
        raise CommandPlaneError("LCOV coverage report has no records")
    totals = {"lines": 0, "lines_covered": 0, "branches": 0, "branches_covered": 0}
    packages: set[str] = set()
    for record in records:
        fields: dict[str, list[str]] = {}
        for line in record:
            if not line:
                continue
            key, separator, value = line.partition(":")
            if not separator:
                raise CommandPlaneError(
                    "LCOV coverage report contains a malformed field"
                )
            fields.setdefault(key, []).append(value)
        sources = fields.get("SF", [])
        if len(sources) != 1:
            raise CommandPlaneError(
                "LCOV coverage record does not name exactly one source"
            )
        source = Path(sources[0])
        if not source.is_absolute():
            raise CommandPlaneError("LCOV coverage source path is not absolute")
        try:
            source = source.resolve(strict=True)
            source.relative_to(root)
        except (OSError, ValueError) as error:
            raise CommandPlaneError(
                "LCOV coverage source is outside the repository"
            ) from error
        package_name = _path_package(source, inventory)
        if package_name is None or package_name in COVERAGE_EXCLUDED_PACKAGES:
            raise CommandPlaneError("LCOV coverage source has an invalid package owner")
        packages.add(package_name)
        values: dict[str, int] = {}
        for field in ("LF", "LH", "BRF", "BRH"):
            entries = fields.get(field, [])
            if len(entries) != 1:
                raise CommandPlaneError(f"LCOV coverage record is missing {field}")
            try:
                parsed = int(entries[0], 10)
            except ValueError as error:
                raise CommandPlaneError(
                    f"LCOV coverage record contains invalid {field}"
                ) from error
            if parsed < 0:
                raise CommandPlaneError(
                    f"LCOV coverage record contains negative {field}"
                )
            values[field] = parsed
        if values["LH"] > values["LF"] or values["BRH"] > values["BRF"]:
            raise CommandPlaneError(
                "LCOV coverage record contains impossible hit totals"
            )
        totals["lines"] += values["LF"]
        totals["lines_covered"] += values["LH"]
        totals["branches"] += values["BRF"]
        totals["branches_covered"] += values["BRH"]
    expected_packages = set(inventory) - set(COVERAGE_EXCLUDED_PACKAGES)
    if packages != expected_packages:
        raise CommandPlaneError("LCOV coverage report omits a workspace package")
    expected = {
        "lines": metrics["coverage.line_count"],
        "lines_covered": metrics["coverage.line_covered"],
        "branches": metrics["coverage.branch_count"],
        "branches_covered": metrics["coverage.branch_covered"],
    }
    if totals != expected or totals["branches"] <= 0:
        raise CommandPlaneError(
            "LCOV line/branch totals are missing or do not match the LLVM JSON report"
        )
    return totals


def _enforce_coverage_thresholds(
    metrics: Mapping[str, int | float],
    packages: Sequence[Mapping[str, object]],
    thresholds: Mapping[str, float],
) -> None:
    scopes: list[tuple[str, Mapping[str, object]]] = [
        (
            "aggregate",
            {
                "lines": {"percent": metrics["coverage.line_percent"]},
                "branches": {"percent": metrics["coverage.branch_percent"]},
            },
        )
    ]
    for package in packages:
        name = package.get("name")
        package_metrics = package.get("metrics")
        if not isinstance(name, str) or not isinstance(package_metrics, dict):
            raise CommandPlaneError("coverage package threshold input is invalid")
        scopes.append((name, package_metrics))
    for scope, scope_metrics in scopes:
        for plural, threshold_name in (
            ("lines", "line_percent"),
            ("branches", "branch_percent"),
        ):
            value = scope_metrics.get(plural)
            if not isinstance(value, dict):
                raise CommandPlaneError("coverage threshold metric is missing")
            percent = value.get("percent")
            if not isinstance(percent, (int, float)) or isinstance(percent, bool):
                raise CommandPlaneError("coverage threshold metric is invalid")
            if float(percent) < thresholds[threshold_name]:
                raise CommandPlaneError(
                    f"{scope} {plural} coverage {float(percent):.6f}% is below "
                    f"{thresholds[threshold_name]:.1f}%"
                )


def _publish_coverage_reports(
    root: Path,
    report_directory: Path,
    lcov_path: Path,
    report: Mapping[str, object],
) -> list[dict[str, object]]:
    workspace = EvidenceWorkspace.create(report_directory, repository_root=root)
    try:
        workspace.read_files(set())
        lcov = workspace.attach_file(lcov_path, "lcov.info")
        summary = workspace.write_json("coverage-report.v1.json", dict(report))
        workspace.read_files({lcov.path, summary.path})
        return [lcov.as_dict(), summary.as_dict()]
    finally:
        workspace.close()


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    # Owner-only mode protects unpublished qualification state from other local accounts.
    os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        path,
        0o700,
    )


def _mutation_environment(temporary_root: Path) -> dict[str, str]:
    private_home = temporary_root / "home"
    private_tmp = temporary_root / "tmp"
    target = temporary_root / "target"
    for directory in (private_home, private_tmp, target):
        _private_directory(directory)
    overrides = {
        "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
        "CARGO_TARGET_DIR": os.fspath(target),
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
    }
    try:
        environment = sanitized_environment(
            private_home=private_home,
            private_tmp=private_tmp,
            overrides=overrides,
        )
    except HermeticExecutionError as error:
        raise CommandPlaneError(
            f"cannot construct the mutation campaign environment: {error}"
        ) from error
    # CARGO_TARGET_DIR is deliberately reintroduced with a fresh owner-private value after the
    # ambient value is removed. Every other mutation/test control must remain absent.
    inherited_controls = set(environment).intersection(
        MUTATION_CONTROL_ENVIRONMENT - {"CARGO_TARGET_DIR"}
    )
    if inherited_controls:
        raise CommandPlaneError(
            "mutation campaign inherited an execution-control variable"
        )
    if environment.get("CARGO_TARGET_DIR") != os.fspath(target):
        raise CommandPlaneError("mutation campaign target directory is not private")
    return environment


def _mutation_toolchain(
    root: Path, environment: Mapping[str, str], policy: Mapping[str, Any]
) -> dict[str, object]:
    requirements = (
        ("cargo", ["cargo", "--version"], "cargo 1.92.0 "),
        ("rustc", ["rustc", "--version"], "rustc 1.92.0 "),
        (
            "cargo-mutants",
            ["cargo", "mutants", "--version"],
            f"cargo-mutants {policy['cargo_mutants_version']}",
        ),
        (
            "cargo-nextest",
            ["cargo", "nextest", "--version"],
            "cargo-nextest 0.9.140 ",
        ),
    )
    tools: dict[str, object] = {}
    for name, command, expected_prefix in requirements:
        try:
            result = run_bounded(
                command,
                cwd=root,
                env=dict(environment),
                timeout=30,
                max_stdout=16 * 1024,
                max_stderr=16 * 1024,
            )
        except ReleaseError as error:
            raise CommandPlaneError(
                f"mutation tool {name} is unavailable: {error}"
            ) from error
        output = result.stdout.decode("utf-8", errors="strict").strip()
        if result.returncode != 0 or not output.startswith(expected_prefix):
            raise CommandPlaneError(
                f"mutation tool {name} is not the pinned native version"
            )
        tools[name] = {
            "stdout_bytes": len(result.stdout),
            "stdout_sha256": sha256_bytes(result.stdout),
            "stderr_bytes": len(result.stderr),
            "stderr_sha256": sha256_bytes(result.stderr),
        }
    executable = shutil.which("cargo-mutants", path=environment.get("PATH"))
    if executable is None:
        raise CommandPlaneError("cargo-mutants executable is unavailable")
    try:
        binary = Path(executable).resolve(strict=True)
        metadata = binary.stat()
    except OSError as error:
        raise CommandPlaneError(
            f"cargo-mutants executable is unavailable: {error}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise CommandPlaneError(
            "cargo-mutants executable is not a protected regular file"
        )
    tools["cargo-mutants-binary"] = {
        "path_sha256": sha256_bytes(os.fspath(binary).encode("utf-8")),
        "content_sha256": sha256_file(binary),
        "bytes": metadata.st_size,
    }
    return tools


def _run_mutation_process(
    command: list[str],
    *,
    root: Path,
    environment: Mapping[str, str],
    timeout: int,
    label: str,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, object], float]:
    try:
        sandboxed, enforcement = no_network_command(command)
    except HermeticExecutionError as error:
        raise CommandPlaneError(
            f"mutation {label} cannot enforce no-network execution: {error}"
        ) from error
    started = time.monotonic()
    try:
        result = run_bounded(
            sandboxed,
            cwd=root,
            env=dict(environment),
            timeout=timeout,
            max_stdout=MAXIMUM_COMMAND_OUTPUT_BYTES,
            max_stderr=MAXIMUM_COMMAND_OUTPUT_BYTES,
        )
    except ReleaseError as error:
        raise CommandPlaneError(f"mutation {label} failed: {error}") from error
    return result, enforcement, time.monotonic() - started


def _strict_json_process_output(payload: bytes, label: str) -> object:
    try:
        return load_json_bytes(payload, label)
    except ReleaseError as error:
        raise CommandPlaneError(f"{label} is invalid: {error}") from error


def _mutation_execution_record(
    result: subprocess.CompletedProcess[bytes],
    *,
    duration_seconds: float,
    command: Sequence[str],
    enforcement: Mapping[str, object],
) -> dict[str, object]:
    return {
        "command_sha256": sha256_bytes(canonical_json_bytes(list(command))),
        "duration_seconds": round(duration_seconds, 6),
        "exit_code": result.returncode,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": sha256_bytes(result.stderr),
        "network_enforcement": dict(enforcement),
    }


def _load_mutation_output(path: Path, label: str) -> object:
    try:
        return load_json(path)
    except (OSError, ReleaseError) as error:
        raise CommandPlaneError(
            f"cargo-mutants {label} is unavailable: {error}"
        ) from error


def _validate_mutation_execution_record(
    value: object,
    *,
    command: Sequence[str],
    expected_enforcement: Mapping[str, object],
    maximum_duration_seconds: int,
) -> dict[str, object]:
    fields = {
        "command_sha256",
        "duration_seconds",
        "exit_code",
        "stdout_bytes",
        "stdout_sha256",
        "stderr_bytes",
        "stderr_sha256",
        "network_enforcement",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CommandPlaneError("mutation execution record has an unexpected shape")
    duration = value.get("duration_seconds")
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or not math.isfinite(float(duration))
        or not 0 <= float(duration) <= maximum_duration_seconds
        or value.get("command_sha256")
        != sha256_bytes(canonical_json_bytes(list(command)))
        or value.get("network_enforcement") != expected_enforcement
    ):
        raise CommandPlaneError(
            "mutation command, duration, or sandbox binding is stale"
        )
    for stream in ("stdout", "stderr"):
        byte_count = value.get(f"{stream}_bytes")
        digest = value.get(f"{stream}_sha256")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or not 0 <= byte_count <= MAXIMUM_COMMAND_OUTPUT_BYTES
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise CommandPlaneError("mutation execution output binding is malformed")
    return value


def _validate_mutation_raw_details(
    *,
    root: Path,
    details: object,
    metrics: Mapping[str, int | float],
    environment: Mapping[str, str],
) -> dict[str, Any]:
    if not isinstance(details, dict) or set(details) != {
        "fuzz_executed",
        "soak_executed",
        "runner",
        "network_mode",
        "platform_scope",
        "toolchain",
        "list_files_execution",
        "campaign_execution",
        "validation",
        "control_environment_removed",
    }:
        raise CommandPlaneError("mutation raw evidence has an unexpected detail shape")
    if (
        details.get("fuzz_executed") is not False
        or details.get("soak_executed") is not False
        or details.get("runner") != "cargo-mutants-full-production-workspace"
        or details.get("network_mode") != "darwin-sandbox-deny-network"
        or details.get("platform_scope") != ["macos-arm64"]
        or details.get("control_environment_removed")
        != sorted(MUTATION_CONTROL_ENVIRONMENT)
    ):
        raise CommandPlaneError(
            "mutation raw evidence overclaims its runner or platform"
        )
    try:
        policy = load_mutation_policy(root)
        metadata = _cargo_metadata(root, environment)
        inventory = mutation_package_inventory(root, metadata, policy)
    except MutationCampaignError as error:
        raise CommandPlaneError(
            f"mutation policy or package scope is invalid: {error}"
        ) from error
    validation = details.get("validation")
    if not isinstance(validation, dict) or set(validation) != {
        "policy",
        "production_packages",
        "excluded_packages",
        "excluded_source_globs",
        "source_files",
        "discovered_mutants",
        "outcomes",
        "counts",
        "viable_denominator",
        "critical_survivor_identities",
    }:
        raise CommandPlaneError("mutation validation evidence has an unexpected shape")
    try:
        _, expected_enforcement = no_network_command([])
    except HermeticExecutionError as error:
        raise CommandPlaneError(
            f"cannot independently verify mutation no-network execution: {error}"
        ) from error
    list_execution = _validate_mutation_execution_record(
        details.get("list_files_execution"),
        command=mutation_list_files_command(policy),
        expected_enforcement=expected_enforcement,
        maximum_duration_seconds=30 * 60,
    )
    campaign_execution = _validate_mutation_execution_record(
        details.get("campaign_execution"),
        command=mutation_campaign_command(policy, Path("<external-mutants-output>")),
        expected_enforcement=expected_enforcement,
        maximum_duration_seconds=MUTATION_MAXIMUM_PROCESS_SECONDS,
    )
    observed_duration = campaign_execution.get("duration_seconds")
    if float(observed_duration) < float(policy["minimum_campaign_seconds"]):
        raise CommandPlaneError("mutation campaign observed duration is below policy")
    try:
        recomputed_metrics, recomputed_validation = validate_campaign_documents(
            outcomes=validation["outcomes"],
            discovered_mutants=[
                {**mutant, "diff": "withheld-after-discovery-validation"}
                for mutant in validation["discovered_mutants"]
            ],
            source_files=validation["source_files"],
            inventory=inventory,
            policy=policy,
            observed_duration_seconds=float(observed_duration),
        )
    except MutationCampaignError as error:
        raise CommandPlaneError(f"mutation raw evidence is invalid: {error}") from error
    # The upstream diff is intentionally omitted from retained content-free evidence. Its value is
    # not an input to mutant identity or any release metric.
    recomputed_validation["discovered_mutants"] = validation["discovered_mutants"]
    if recomputed_metrics != dict(metrics) or recomputed_validation != validation:
        raise CommandPlaneError(
            "mutation raw evidence does not recompute to its receipt"
        )
    expected_toolchain = _mutation_toolchain(root, environment, policy)
    if details.get("toolchain") != expected_toolchain:
        raise CommandPlaneError("mutation toolchain binding is stale or substituted")
    if list_execution.get("exit_code") != 0 or campaign_execution.get(
        "exit_code"
    ) not in {0, 2}:
        raise CommandPlaneError("mutation execution status is not release-qualifying")
    return validation


def run_mutations(arguments: argparse.Namespace) -> dict[str, Any]:
    root = _validated_root(arguments.root)
    _require_native_macos_arm64()
    expected = _load_expected_source(arguments.expected_source)
    _require_clean_source(expected)
    if source_binding(root) != expected:
        raise CommandPlaneError("Git source changed before mutation execution")
    command_id = "test-mutations-verify"
    _command_entry(root, command_id)
    try:
        policy = load_mutation_policy(root)
    except MutationCampaignError as error:
        raise CommandPlaneError(f"mutation policy is invalid: {error}") from error
    started_unix_ms = time.time_ns() // 1_000_000
    overall_started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cigar-xtask-mutations-") as raw:
        temporary_root = Path(raw).resolve(strict=True)
        # Owner-only mode protects unpublished mutation campaign inputs from local accounts.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            temporary_root,
            0o700,
        )
        environment = _mutation_environment(temporary_root)
        toolchain = _mutation_toolchain(root, environment, policy)
        metadata = _cargo_metadata(root, environment)
        try:
            inventory = mutation_package_inventory(root, metadata, policy)
        except MutationCampaignError as error:
            raise CommandPlaneError(
                f"mutation package scope is invalid: {error}"
            ) from error

        list_command = mutation_list_files_command(policy)
        list_result, list_enforcement, list_duration = _run_mutation_process(
            list_command,
            root=root,
            environment=environment,
            timeout=30 * 60,
            label="source-file discovery",
        )
        if list_result.returncode != 0:
            raise CommandPlaneError(
                "mutation source-file discovery returned a nonzero status; output was suppressed"
            )
        source_files = _strict_json_process_output(
            list_result.stdout, "cargo-mutants source-file inventory"
        )

        output_parent = temporary_root / "output"
        _private_directory(output_parent)
        campaign_command = mutation_campaign_command(policy, output_parent)
        campaign_result, campaign_enforcement, campaign_duration = (
            _run_mutation_process(
                campaign_command,
                root=root,
                environment=environment,
                timeout=MUTATION_MAXIMUM_PROCESS_SECONDS,
                label="release campaign",
            )
        )
        if campaign_result.returncode not in {0, 2, 3}:
            raise CommandPlaneError(
                "mutation campaign returned a baseline/configuration failure; output was suppressed"
            )
        output = output_parent / "mutants.out"
        outcomes = _load_mutation_output(output / "outcomes.json", "outcomes.json")
        discovered = _load_mutation_output(output / "mutants.json", "mutants.json")
        try:
            metrics, validation = validate_campaign_documents(
                outcomes=outcomes,
                discovered_mutants=discovered,
                source_files=source_files,
                inventory=inventory,
                policy=policy,
                observed_duration_seconds=campaign_duration,
            )
        except MutationCampaignError as error:
            raise CommandPlaneError(
                f"mutation campaign failed validation: {error}"
            ) from error
        list_record_command = mutation_list_files_command(policy)
        campaign_record_command = mutation_campaign_command(
            policy, Path("<external-mutants-output>")
        )
        details = {
            "runner": "cargo-mutants-full-production-workspace",
            "network_mode": "darwin-sandbox-deny-network",
            "platform_scope": ["macos-arm64"],
            "toolchain": toolchain,
            "list_files_execution": _mutation_execution_record(
                list_result,
                duration_seconds=list_duration,
                command=list_record_command,
                enforcement=list_enforcement,
            ),
            "campaign_execution": _mutation_execution_record(
                campaign_result,
                duration_seconds=campaign_duration,
                command=campaign_record_command,
                enforcement=campaign_enforcement,
            ),
            "validation": validation,
            "control_environment_removed": sorted(MUTATION_CONTROL_ENVIRONMENT),
        }
        if source_binding(root) != expected:
            raise CommandPlaneError(
                "Git source changed while mutation analysis executed"
            )
        _validate_mutation_raw_details(
            root=root,
            details={"fuzz_executed": False, "soak_executed": False, **details},
            metrics=metrics,
            environment=environment,
        )
        duration_ms = round((time.monotonic() - overall_started) * 1000)
    return publish_record(
        root=root,
        evidence_directory=arguments.evidence_dir,
        command_id=command_id,
        expected_source=expected,
        attachment_relative=None,
        started_unix_ms=started_unix_ms,
        duration_ms=duration_ms,
        raw_metrics=metrics,
        raw_details=details,
        tool_authority=_reviewed_tool_authority_argument(
            arguments.tool_authority_binding
        ),
    )


def run_coverage(arguments: argparse.Namespace) -> dict[str, Any]:
    root = _validated_root(arguments.root)
    _require_native_macos_arm64()
    expected = _load_expected_source(arguments.expected_source)
    _require_clean_source(expected)
    if source_binding(root) != expected:
        raise CommandPlaneError("Git source changed before coverage execution")
    command_id = "test-coverage-verify"
    _command_entry(root, command_id)
    thresholds, policy_sha256 = _coverage_thresholds(root)
    started_unix_ms = time.time_ns() // 1_000_000
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cigar-xtask-coverage-") as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        summary_path = temporary_root / "llvm-coverage-summary.json"
        lcov_path = temporary_root / "lcov.info"
        environment = _coverage_environment(temporary_root)
        toolchain = _coverage_toolchain(root, environment)
        metadata = _cargo_metadata(root, environment)
        inventory = _coverage_package_inventory(root, metadata)
        _validate_coverage_feature_plan(inventory)
        executions: list[dict[str, object]] = []
        commands = _coverage_collection_commands(root)
        for collection_id, command in commands:
            outcome = _run_coverage_process(
                command,
                root=root,
                environment=environment,
                label=f"collection {collection_id}",
            )
            executions.append(
                {
                    "id": collection_id,
                    "command_sha256": sha256_bytes(canonical_json_bytes(command)),
                    **outcome,
                }
            )
        for report_format, output in (("json", summary_path), ("lcov", lcov_path)):
            report_command = _coverage_report_command(output, report_format)
            outcome = _run_coverage_process(
                report_command,
                root=root,
                environment=environment,
                label=f"{report_format} report",
            )
            executions.append(
                {
                    "id": f"report-{report_format}",
                    "command_sha256": sha256_bytes(
                        canonical_json_bytes(report_command)
                    ),
                    **outcome,
                }
            )
        try:
            document = load_json(summary_path)
        except (OSError, ReleaseError) as error:
            raise CommandPlaneError(
                f"coverage summary is unavailable: {error}"
            ) from error
        metrics = _coverage_totals(document)
        packages = _coverage_packages(root, document, inventory)
        _validate_package_totals(metrics, packages)
        try:
            lcov_payload = lcov_path.read_bytes()
        except OSError as error:
            raise CommandPlaneError(
                f"LCOV coverage report is unavailable: {error}"
            ) from error
        lcov_totals = _validate_lcov(
            lcov_payload,
            root=root,
            inventory=inventory,
            metrics=metrics,
        )
        threshold_failure: str | None = None
        try:
            _enforce_coverage_thresholds(metrics, packages, thresholds)
        except CommandPlaneError as error:
            threshold_failure = str(error)
        package_line_percentages = [
            float(package["metrics"]["lines"]["percent"]) for package in packages
        ]
        package_branch_percentages = [
            float(package["metrics"]["branches"]["percent"]) for package in packages
        ]
        metrics.update(
            {
                "coverage.package_count": len(packages),
                "coverage.collection_count": len(commands),
                "coverage.package_min_line_percent": round(
                    min(package_line_percentages), 6
                ),
                "coverage.package_min_branch_percent": round(
                    min(package_branch_percentages), 6
                ),
                "coverage.property_workspace_executed": 1,
            }
        )
        final_source = source_binding(root)
        _require_clean_source(final_source)
        if final_source != expected:
            raise CommandPlaneError("Git source changed while coverage executed")
        duration_ms = round((time.monotonic() - started) * 1000)
        coverage_report = {
            "schema_version": "cigar.coverage-report.v1",
            "status": "failed" if threshold_failure is not None else "passed",
            "source": expected,
            "platform_scope": ["macos-arm64"],
            "thresholds": {
                "line_percent": thresholds["line_percent"],
                "branch_percent": thresholds["branch_percent"],
                "applied_to_each_package": True,
            },
            "totals": {
                key.removeprefix("coverage."): value
                for key, value in metrics.items()
                if key.startswith("coverage.")
            },
            "packages": packages,
            "coverage_plan": {
                "collection_ids": [collection_id for collection_id, _ in commands],
                "all_targets": True,
                "branch_instrumentation": True,
                "independent_property_workspace": "tests/properties/Cargo.toml",
                "property_dependency_coverage": list(COVERAGE_PROPERTY_DEPENDENCIES),
                "excluded_packages": [
                    {"name": name, "reason": reason}
                    for name, reason in sorted(COVERAGE_EXCLUDED_PACKAGES.items())
                ],
                "fuzz_executed": False,
                "soak_executed": False,
            },
            "lcov": {
                "bytes": len(lcov_payload),
                "sha256": sha256_bytes(lcov_payload),
                **lcov_totals,
            },
            "threshold_failure": threshold_failure,
        }
        published_reports: list[dict[str, object]] = []
        report_directory_value = os.environ.get(COVERAGE_REPORT_DIRECTORY_ENV)
        if report_directory_value is not None:
            published_reports = _publish_coverage_reports(
                root,
                Path(report_directory_value),
                lcov_path,
                coverage_report,
            )
        if threshold_failure is not None:
            raise CommandPlaneError(threshold_failure)
        details = {
            "runner": "cargo-llvm-cov-nextest-cumulative",
            "network_mode": "offline",
            "platform_scope": ["macos-arm64"],
            "excluded_packages": [
                {"name": name, "reason": reason}
                for name, reason in sorted(COVERAGE_EXCLUDED_PACKAGES.items())
            ],
            "all_targets": True,
            "all_declared_features_covered": True,
            "independent_property_workspace_executed": True,
            "control_environment_removed": sorted(COVERAGE_CONTROL_ENVIRONMENT),
            "toolchain": toolchain,
            "fuzz_executed": False,
            "soak_executed": False,
            "executions": executions,
            "coverage_report_sha256": sha256_bytes(
                canonical_json_bytes(coverage_report)
            ),
            "lcov": coverage_report["lcov"],
            "published_reports": published_reports,
            "thresholds": {
                "line_percent": thresholds["line_percent"],
                "branch_percent": thresholds["branch_percent"],
                "applied_to_each_package": True,
            },
            "threshold_policy": {
                "path": REQUIREMENTS_PATH,
                "sha256": policy_sha256,
            },
        }
    return publish_record(
        root=root,
        evidence_directory=arguments.evidence_dir,
        command_id=command_id,
        expected_source=expected,
        attachment_relative=None,
        started_unix_ms=started_unix_ms,
        duration_ms=duration_ms,
        raw_metrics=metrics,
        raw_details=details,
        tool_authority=_reviewed_tool_authority_argument(
            arguments.tool_authority_binding
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)

    snapshot = subcommands.add_parser("snapshot")
    snapshot.add_argument("--root", type=Path, required=True)
    snapshot.add_argument("--evidence-dir", type=Path, required=True)

    record = subcommands.add_parser("record")
    record.add_argument("--root", type=Path, required=True)
    record.add_argument("--evidence-dir", type=Path, required=True)
    record.add_argument("--command-id", required=True)
    record.add_argument("--expected-source", required=True)
    record.add_argument("--started-unix-ms", type=int, required=True)
    record.add_argument("--duration-ms", type=int, required=True)
    record.add_argument("--attachment-relative")
    record.add_argument("--tool-authority-binding")

    verify = subcommands.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--evidence-dir", type=Path, required=True)
    verify.add_argument("--command-id", required=True)
    verify.add_argument("--expected-source", required=True)
    verify.add_argument("--attachment-relative")
    verify.add_argument("--tool-authority-binding")

    coverage = subcommands.add_parser("coverage")
    coverage.add_argument("--root", type=Path, required=True)
    coverage.add_argument("--evidence-dir", type=Path, required=True)
    coverage.add_argument("--expected-source", required=True)
    coverage.add_argument("--tool-authority-binding")

    mutations = subcommands.add_parser("mutations")
    mutations.add_argument("--root", type=Path, required=True)
    mutations.add_argument("--evidence-dir", type=Path, required=True)
    mutations.add_argument("--expected-source", required=True)
    mutations.add_argument("--tool-authority-binding")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.action == "snapshot":
        root = _validated_root(arguments.root)
        _require_native_macos_arm64()
        source = source_binding(root)
        _require_clean_source(source)
        _preflight_workspace(root, arguments.evidence_dir)
        print(canonical_json_bytes(source).decode("utf-8"), end="")
        return 0
    if arguments.action == "coverage":
        receipt = run_coverage(arguments)
        print(canonical_json_bytes(receipt).decode("utf-8"), end="")
        return 0
    if arguments.action == "mutations":
        receipt = run_mutations(arguments)
        print(canonical_json_bytes(receipt).decode("utf-8"), end="")
        return 0

    root = _validated_root(arguments.root)
    expected = _load_expected_source(arguments.expected_source)
    if arguments.action == "verify":
        receipt = verify_record(
            root=root,
            evidence_directory=arguments.evidence_dir,
            command_id=arguments.command_id,
            expected_source=expected,
            attachment_relative=arguments.attachment_relative,
            tool_authority=_reviewed_tool_authority_argument(
                arguments.tool_authority_binding
            ),
        )
        print(canonical_json_bytes(receipt).decode("utf-8"), end="")
        return 0
    receipt = publish_record(
        root=root,
        evidence_directory=arguments.evidence_dir,
        command_id=arguments.command_id,
        expected_source=expected,
        attachment_relative=arguments.attachment_relative,
        started_unix_ms=arguments.started_unix_ms,
        duration_ms=arguments.duration_ms,
        tool_authority=_reviewed_tool_authority_argument(
            arguments.tool_authority_binding
        ),
    )
    print(canonical_json_bytes(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CommandPlaneError, EvidenceWorkspaceError, OSError, ValueError) as error:
        print(f"xtask command evidence failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
