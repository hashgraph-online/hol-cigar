#!/usr/bin/env python3
"""Build and validate the unpublished development Go module archive on macOS."""

from __future__ import annotations

import argparse
import calendar
import datetime
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
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


ARTIFACT_ID = "go-sdk"
TARGET_TRIPLE = "aarch64-apple-darwin"
MODULE_PATH = "github.com/CIGAR/cigar/sdk/go"
PRODUCER = "python3 scripts/release/build_go_sdk.py"
BUILD_RECEIPT = "go-sdk-development-build.json"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODULE_RELATIVE = "sdk/go"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
EXPECTED_QUICKSTART_IDENTITY = (
    "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"
)
MINIMUM_GO_VERSION = (1, 26, 5)
MINIMUM_GO_VERSION_TEXT = ".".join(str(component) for component in MINIMUM_GO_VERSION)
NATIVE_GO_VERSION_PATTERN = re.compile(
    r"go version go(?P<major>[0-9]+)\.(?P<minor>[0-9]+)"
    r"(?:\.(?P<patch>[0-9]+))? darwin/arm64"
)
MINIMUM_ZIP_EPOCH = calendar.timegm((1980, 1, 1, 0, 0, 0))
MAXIMUM_ZIP_EPOCH = calendar.timegm((2107, 12, 31, 23, 59, 58))

AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/go-module.v1.json",
    f"{MODULE_RELATIVE}/go.mod",
    f"{MODULE_RELATIVE}/go.sum",
    f"{MODULE_RELATIVE}/release.json",
)
SOURCE_RELEASE_PATHS = frozenset(
    {
        "LICENSE",
        "NOTICE",
        "README.md",
        "client.go",
        "client_test.go",
        "capabilities-v1.json",
        "cmd/cigar-qualify-bundle/main.go",
        "cmd/cigar-verify-replay/main.go",
        "cmd/cigar-verify-vectors/main.go",
        "digest.go",
        "digest_test.go",
        "errors.go",
        "errors_gen.go",
        "examples/quickstart/main.go",
        "fixtures/semantic-bundle-v1.json",
        "fixtures/problem-index-unavailable-v1.json",
        "gen/cigarv1/cigar_service.pb.go",
        "gen/cigarv1/cigar_service_grpc.pb.go",
        "gen/contextv1/context_abi.pb.go",
        "gen/contextv1/error_codes.pb.go",
        "go.mod",
        "go.sum",
        "grpc_client.go",
        "grpc_contract_test.go",
        "json_value.go",
        "models_gen.go",
        "operations_gen.go",
        "pagination.go",
        "proto_snapshot.go",
        "release.json",
        "release_contract_test.go",
        "stream.go",
        "stream_test.go",
        "typed_runtime.go",
        "typed_runtime_test.go",
        "types.go",
    }
)
EXPECTED_PACKAGES = (
    MODULE_PATH,
    f"{MODULE_PATH}/cmd/cigar-qualify-bundle",
    f"{MODULE_PATH}/cmd/cigar-verify-replay",
    f"{MODULE_PATH}/cmd/cigar-verify-vectors",
    f"{MODULE_PATH}/examples/quickstart",
    f"{MODULE_PATH}/gen/cigarv1",
    f"{MODULE_PATH}/gen/contextv1",
)
SOURCE_INCLUDES = (
    "packaging/product-version.v1.json",
    "packaging/artifact-matrix.v1.json",
    "packaging/development/local-macos-aarch64.v1.json",
    "packaging/contracts/go-module.v1.json",
    f"{MODULE_RELATIVE}/**",
    "scripts/release/build_go_sdk.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/verify_package.py",
)
SOURCE_EXCLUDES = (
    "**/.DS_Store",
    "**/.ruff_cache/**",
    "**/__pycache__/**",
    "**/*.pyc",
)


@dataclass(frozen=True)
class PackageEntry:
    path: str
    payload: bytes
    mode: int = 0o644


@dataclass(frozen=True)
class BuildConfiguration:
    root: Path
    module_root: Path
    product_version: str
    module_version: str
    context_abi: str
    module_path: str
    module_prefix: str
    filename: str
    contract_path: Path
    contract_relative: str
    authority: dict[str, dict[str, object]]
    assets: dict[str, bytes]


GoValidator = Callable[
    [BuildConfiguration, Path, int, Path, argparse.Namespace], dict[str, Any]
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
    parser.add_argument("--go", type=Path)
    parser.add_argument(
        "--dependency-proxy",
        type=Path,
        help="absolute local Go file-proxy root; defaults to GOMODCACHE/cache/download",
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
            "the development Go SDK producer requires Apple-silicon macOS; "
            f"observed platform={sys.platform} architecture={machine}"
        )
    return {
        "platform": "macos",
        "architecture": "arm64",
        "target_triple": TARGET_TRIPLE,
        "macos_version": platform.mac_ver()[0],
    }


def _require_supported_go_toolchain(version_output: str) -> tuple[int, int, int]:
    match = NATIVE_GO_VERSION_PATTERN.fullmatch(version_output)
    if match is None:
        raise ReleaseError("Go tool is not a native macOS arm64 toolchain")
    version = (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch") or "0"),
    )
    if version < MINIMUM_GO_VERSION:
        raise ReleaseError(
            "Go SDK packaging requires Go "
            f">={MINIMUM_GO_VERSION_TEXT} because earlier toolchains contain "
            f"known standard-library vulnerabilities; observed {version_output}"
        )
    return version


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


def _authority_digests(root: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for relative in AUTHORITY_PATHS:
        payload = _read_stable_file(
            root.joinpath(*relative.split("/")), MAX_SOURCE_FILE_BYTES, relative
        )
        records[relative] = {"sha256": sha256_bytes(payload), "bytes": len(payload)}
    return records


def _module_assets(module_root: Path) -> dict[str, bytes]:
    actual_paths: set[str] = set()
    for current, directories, files in os.walk(
        module_root, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        kept_directories: list[str] = []
        for directory in sorted(directories):
            path = current_path / directory
            if directory in {".ruff_cache", "__pycache__"}:
                continue
            if path.is_symlink():
                raise ReleaseError(f"Go SDK source contains a symlink: {path}")
            kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in sorted(files):
            if filename == ".DS_Store" or filename.endswith(".pyc"):
                continue
            path = current_path / filename
            relative = path.relative_to(module_root).as_posix()
            if path.is_symlink():
                raise ReleaseError(f"Go SDK source contains a symlink: {relative}")
            if not path.is_file():
                raise ReleaseError(f"Go SDK source is not a regular file: {relative}")
            actual_paths.add(relative)
    if actual_paths != SOURCE_RELEASE_PATHS:
        missing = sorted(SOURCE_RELEASE_PATHS - actual_paths)
        unexpected = sorted(actual_paths - SOURCE_RELEASE_PATHS)
        raise ReleaseError(
            "Go SDK source inventory differs from the reviewed module set: "
            f"missing={missing} unexpected={unexpected}"
        )

    assets: dict[str, bytes] = {}
    aliases: set[str] = set()
    for relative in sorted(
        SOURCE_RELEASE_PATHS, key=lambda value: value.encode("utf-8")
    ):
        canonical = safe_relative_path(relative)
        alias = unicodedata.normalize("NFC", canonical).casefold()
        if alias in aliases:
            raise ReleaseError(f"Go SDK release path collides portably: {relative}")
        aliases.add(alias)
        payload = _read_stable_file(
            module_root.joinpath(*relative.split("/")),
            MAX_SOURCE_FILE_BYTES,
            f"Go SDK source file {relative}",
        )
        if b"\r" in payload:
            raise ReleaseError(f"Go SDK source is not canonical LF content: {relative}")
        assets[relative] = payload
    return assets


def _validate_contract(contract: Any, module_prefix: str, product_version: str) -> None:
    required = {
        f"{module_prefix}go.mod",
        f"{module_prefix}README.md",
        f"{module_prefix}LICENSE",
        f"{module_prefix}NOTICE",
        f"{module_prefix}release.json",
    }
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != "cigar.package-contract.v1"
        or contract.get("id") != "go-module-v1"
        or contract.get("formats") != ["zip"]
        or contract.get("allow") != [f"{module_prefix}**"]
        or set(contract.get("required", [])) != required
        or contract.get("required_patterns") != [f"{module_prefix}*.go"]
        or contract.get("symlinks") != "forbid"
        or contract.get("line_endings") != "lf"
        or contract.get("modes") != ["0644"]
        or contract.get("content_scan") is not True
        or contract.get("content_scan_exemptions") != []
        or contract.get("version_binding")
        != {
            "path_pattern": f"{module_prefix}release.json",
            "format": "json",
            "json_pointer": "/version",
        }
        or contract.get("abi_binding")
        != {
            "path_pattern": f"{module_prefix}release.json",
            "format": "json",
            "json_pointer": "/context_abi",
        }
        or product_version not in module_prefix
    ):
        raise ReleaseError("Go module package contract is incomplete or stale")


def _load_configuration(root: Path) -> BuildConfiguration:
    root = root.resolve(strict=True)
    authority = _authority_digests(root)
    product = load_json(root / "packaging/product-version.v1.json")
    matrix = load_json(root / "packaging/artifact-matrix.v1.json")
    profile = load_json(root / "packaging/development/local-macos-aarch64.v1.json")
    contract_relative = "packaging/contracts/go-module.v1.json"
    contract_path = root / contract_relative
    contract = load_json(contract_path)
    module_root = root / MODULE_RELATIVE
    assets = _module_assets(module_root)

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
        raise ReleaseError(
            "product version authority is not an unpublished development identity"
        )
    product_version = product["version"]
    module_version = f"v{product_version}"
    context_abi = product["context_abi"]
    module_prefix = f"{MODULE_PATH}@{module_version}/"
    filename = f"cigar-go-sdk-{product_version}.zip"

    if (
        not isinstance(matrix, dict)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("release_state") != "development"
        or matrix.get("product_version") != product_version
        or matrix.get("context_abi") != context_abi
        or not isinstance(matrix.get("artifacts"), list)
    ):
        raise ReleaseError("artifact matrix is stale relative to product authority")
    rows = [
        row
        for row in matrix["artifacts"]
        if isinstance(row, dict) and row.get("id") == ARTIFACT_ID
    ]
    expected_row = {
        "id": ARTIFACT_ID,
        "kind": "go-module",
        "filename": filename,
        "contract": "contracts/go-module.v1.json",
        "ecosystem": "go",
        "producer": PRODUCER,
        "required_for_release": True,
        "qualification": [
            "go-list",
            "go-vet",
            "clean-install",
            "offline",
            "version-abi-consistency",
            "sbom",
            "license",
            "signature",
        ],
    }
    if rows != [expected_row]:
        raise ReleaseError("go-sdk artifact matrix row is incomplete or stale")

    selected = profile.get("selected_artifacts") if isinstance(profile, dict) else None
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
        or selected_rows
        != [
            {
                "built": False,
                "id": ARTIFACT_ID,
                "qualified": False,
                "selection_group": "sdk-go",
                "status": "planned",
            }
        ]
    ):
        raise ReleaseError("development profile does not leave go-sdk planned")

    _validate_contract(contract, module_prefix, product_version)
    release = load_json_bytes(assets["release.json"], "sdk/go/release.json")
    if release != {
        "schema_version": "cigar.sdk-release.v1",
        "name": MODULE_PATH,
        "version": product_version,
        "context_abi": context_abi,
    }:
        raise ReleaseError("Go SDK release metadata is stale")
    if not assets["go.mod"].startswith(f"module {MODULE_PATH}\n\n".encode("utf-8")):
        raise ReleaseError("Go module path differs from the package authority")
    sum_lines = assets["go.sum"].decode("utf-8", errors="strict").splitlines()
    if (
        not sum_lines
        or sum_lines != sorted(sum_lines, key=lambda value: value.encode("utf-8"))
        or len(sum_lines) != len(set(sum_lines))
        or any(
            re.fullmatch(r"\S+ \S+(?:/go\.mod)? h1:[A-Za-z0-9+/=]+", line) is None
            for line in sum_lines
        )
    ):
        raise ReleaseError(
            "Go SDK lock data is empty, unsorted, duplicate, or malformed"
        )

    return BuildConfiguration(
        root=root,
        module_root=module_root,
        product_version=product_version,
        module_version=module_version,
        context_abi=context_abi,
        module_path=MODULE_PATH,
        module_prefix=module_prefix,
        filename=filename,
        contract_path=contract_path,
        contract_relative=contract_relative,
        authority=authority,
        assets=assets,
    )


def _source_identity(root: Path) -> dict[str, Any]:
    files = expand_files(root, list(SOURCE_INCLUDES), list(SOURCE_EXCLUDES))
    if not files:
        raise ReleaseError("Go SDK build source inventory is empty")
    identity = git_state(root, tree_digest(files))
    if (
        identity.get("committed") is not True
        or not isinstance(identity.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", identity["revision"]) is None
        or not isinstance(identity.get("clean"), bool)
        or not isinstance(identity.get("tree_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["tree_sha256"]) is None
    ):
        raise ReleaseError("Go SDK build requires a committed Git source identity")
    return identity


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    if epoch < MINIMUM_ZIP_EPOCH or epoch > MAXIMUM_ZIP_EPOCH:
        raise ReleaseError("SOURCE_DATE_EPOCH is outside the deterministic ZIP range")
    value = time.gmtime(epoch - (epoch % 2))
    return (
        value.tm_year,
        value.tm_mon,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec,
    )


def _package_entries(configuration: BuildConfiguration) -> list[PackageEntry]:
    entries = [
        PackageEntry(f"{configuration.module_prefix}{relative}", payload)
        for relative, payload in configuration.assets.items()
    ]
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in entries:
        canonical = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", canonical).casefold()
        if canonical in names or alias in aliases:
            raise ReleaseError(
                f"duplicate or portable-colliding Go module path: {canonical}"
            )
        if entry.mode != 0o644 or not entry.payload:
            raise ReleaseError(
                f"Go module entry has invalid mode or payload: {canonical}"
            )
        names.add(canonical)
        aliases.add(alias)
    expected = {
        f"{configuration.module_prefix}{relative}" for relative in SOURCE_RELEASE_PATHS
    }
    if names != expected:
        raise ReleaseError("Go module package inventory differs from the reviewed set")
    return sorted(entries, key=lambda entry: entry.path.encode("utf-8"))


def _write_archive(path: Path, entries: list[PackageEntry], epoch: int) -> None:
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"refusing to overwrite staged Go module archive: {path}")
    date_time = _zip_datetime(epoch)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as raw:
            temporary = Path(raw.name)
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=True,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for entry in entries:
                information = zipfile.ZipInfo(entry.path, date_time=date_time)
                information.create_system = 3
                information.compress_type = zipfile.ZIP_DEFLATED
                information.external_attr = (stat.S_IFREG | entry.mode) << 16
                information.extra = b""
                information.comment = b""
                archive.writestr(information, entry.payload, compresslevel=9)
        with temporary.open("r+b") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


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


def _tool_record(path: Path, version: str) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    payload = _read_stable_file(resolved, 64 * 1024 * 1024, "go executable")
    return {
        "name": "go",
        "version": version,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
    }


def _escape_proxy_path(module_path: str) -> str:
    escaped: list[str] = []
    for character in module_path:
        if character == "!" or ord(character) >= 128:
            raise ReleaseError("Go module path cannot be escaped for a file proxy")
        if "A" <= character <= "Z":
            escaped.extend(("!", character.lower()))
        else:
            escaped.append(character)
    return "".join(escaped)


def _write_proxy_module(
    proxy: Path,
    configuration: BuildConfiguration,
    archive: Path,
    epoch: int,
) -> None:
    escaped = _escape_proxy_path(configuration.module_path)
    version_root = proxy.joinpath(*escaped.split("/"), "@v")
    version_root.mkdir(parents=True, mode=0o700)
    archive_payload = _read_stable_file(archive, MAX_ARCHIVE_BYTES, "staged Go module")
    timestamp = (
        datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    files = {
        f"{configuration.module_version}.zip": archive_payload,
        f"{configuration.module_version}.mod": configuration.assets["go.mod"],
        f"{configuration.module_version}.info": canonical_json_bytes(
            {"Version": configuration.module_version, "Time": timestamp}
        ),
        "list": f"{configuration.module_version}\n".encode("ascii"),
    }
    for name, payload in files.items():
        destination = version_root / name
        destination.write_bytes(payload)
        os.chmod(destination, 0o600)


def _base_go_environment(go: Path, scratch: Path, epoch: int) -> dict[str, str]:
    if not scratch.exists():
        scratch.mkdir(mode=0o700)
    home = scratch / "home"
    temporary = scratch / "tmp"
    build_cache = scratch / "build-cache"
    module_cache = scratch / "module-cache"
    for directory in (home, temporary, build_cache, module_cache):
        directory.mkdir(mode=0o700)
    path_entries: list[str] = []
    for directory in (
        go.parent,
        go.resolve(strict=True).parent,
        Path("/usr/bin"),
        Path("/bin"),
    ):
        value = os.fspath(directory)
        if value not in path_entries:
            path_entries.append(value)
    return {
        "CGO_ENABLED": "0",
        "GO111MODULE": "on",
        "GOCACHE": str(build_cache),
        "GOENV": "off",
        "GOMODCACHE": str(module_cache),
        "GONOPROXY": "none",
        "GONOSUMDB": "*",
        "GOPRIVATE": "",
        "GOSUMDB": "off",
        "GOTELEMETRY": "off",
        "GOTOOLCHAIN": "local",
        "GOVCS": "*:off",
        "GOWORK": "off",
        "HOME": str(home),
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_PROXY": "",
        "PATH": os.pathsep.join(path_entries),
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }


def _discover_dependency_proxy(go: Path, scratch: Path, epoch: int) -> Path:
    environment = _base_go_environment(go, scratch / "discovery", epoch)
    environment["HOME"] = str(Path.home().resolve(strict=True))
    environment.pop("GOMODCACHE")
    output = _run_checked(
        [str(go), "env", "GOMODCACHE"],
        cwd=scratch,
        environment=environment,
        timeout=30,
        label="Go module-cache discovery",
        maximum=16 * 1024,
    )
    try:
        cache = Path(output.decode("utf-8", errors="strict").strip())
    except UnicodeError as error:
        raise ReleaseError("Go module-cache path is not UTF-8") from error
    return _owned_directory(cache / "cache/download", "Go dependency file proxy")


def _validate_extracted_module(
    configuration: BuildConfiguration, module_root: Path
) -> None:
    actual: dict[str, bytes] = {}
    for current, directories, files in os.walk(
        module_root, topdown=True, followlinks=False
    ):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for directory in directories:
            if (current_path / directory).is_symlink():
                raise ReleaseError("downloaded Go module contains a directory symlink")
        for filename in files:
            path = current_path / filename
            relative = path.relative_to(module_root).as_posix()
            if path.is_symlink():
                raise ReleaseError(
                    f"downloaded Go module contains a symlink: {relative}"
                )
            actual[relative] = _read_stable_file(
                path, MAX_SOURCE_FILE_BYTES, f"downloaded Go module file {relative}"
            )
    if actual != configuration.assets:
        raise ReleaseError(
            "Go tool extracted bytes differ from the reviewed module assets"
        )


def _validate_go_result(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "status",
        "offline",
        "fresh_module_cache",
        "module_path",
        "module_version",
        "module_sum",
        "go_mod_sum",
        "packages",
        "checks",
        "semantic_bundle_identity",
        "tool",
    }
    tool = result.get("tool")
    if (
        set(result) != required
        or result.get("schema_version") != "cigar.go-sdk-build-validation.v1"
        or result.get("status") != "passed"
        or result.get("offline") is not True
        or result.get("fresh_module_cache") is not True
        or result.get("module_path") != MODULE_PATH
        or not isinstance(result.get("module_version"), str)
        or re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+", result["module_version"]
        )
        is None
        or not isinstance(result.get("module_sum"), str)
        or re.fullmatch(r"h1:[A-Za-z0-9+/=]+", result["module_sum"]) is None
        or not isinstance(result.get("go_mod_sum"), str)
        or re.fullmatch(r"h1:[A-Za-z0-9+/=]+", result["go_mod_sum"]) is None
        or result.get("packages") != list(EXPECTED_PACKAGES)
        or result.get("checks")
        != {
            "go-mod-download": "passed",
            "go-mod-verify": "passed",
            "go-list": "passed",
            "go-vet": "passed",
            "go-test": "passed",
            "semantic-bundle": "passed",
        }
        or result.get("semantic_bundle_identity") != EXPECTED_QUICKSTART_IDENTITY
        or not isinstance(tool, dict)
        or set(tool) != {"name", "version", "sha256", "bytes"}
        or tool.get("name") != "go"
        or not isinstance(tool.get("version"), str)
        or not isinstance(tool.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", tool["sha256"]) is None
        or not isinstance(tool.get("bytes"), int)
        or isinstance(tool["bytes"], bool)
        or tool["bytes"] <= 0
    ):
        raise ReleaseError(
            "Go SDK offline validation result is incomplete or malformed"
        )
    _require_supported_go_toolchain(tool["version"])


def _default_go_validator(
    configuration: BuildConfiguration,
    archive: Path,
    epoch: int,
    scratch: Path,
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    go = _secure_executable(arguments.go, "go")
    environment = _base_go_environment(go, scratch / "go-validation", epoch)
    version_output = (
        _run_checked(
            [str(go), "version"],
            cwd=scratch,
            environment=environment,
            timeout=30,
            label="Go tool identity",
            maximum=64 * 1024,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    _require_supported_go_toolchain(version_output)

    dependency_proxy = (
        _owned_directory(arguments.dependency_proxy, "Go dependency file proxy")
        if arguments.dependency_proxy is not None
        else _discover_dependency_proxy(go, scratch, epoch)
    )
    local_proxy = scratch / "module-proxy"
    local_proxy.mkdir(mode=0o700)
    _write_proxy_module(local_proxy, configuration, archive, epoch)
    environment["GOPROXY"] = f"{local_proxy.as_uri()},{dependency_proxy.as_uri()},off"
    environment_output = _run_checked(
        [str(go), "env", "-json", "GOVERSION", "GOOS", "GOARCH"],
        cwd=scratch,
        environment=environment,
        timeout=30,
        label="Go environment identity",
        maximum=64 * 1024,
    )
    go_environment = load_json_bytes(environment_output, "Go environment identity")
    if (
        not isinstance(go_environment, dict)
        or go_environment.get("GOOS") != "darwin"
        or go_environment.get("GOARCH") != "arm64"
        or not isinstance(go_environment.get("GOVERSION"), str)
        or go_environment["GOVERSION"] not in version_output
    ):
        raise ReleaseError("Go environment is not native macOS arm64")

    download_output = _run_checked(
        [
            str(go),
            "mod",
            "download",
            "-json",
            f"{configuration.module_path}@{configuration.module_version}",
        ],
        cwd=scratch,
        environment=environment,
        timeout=300,
        label="Go module archive download",
    )
    download = load_json_bytes(download_output, "Go module download result")
    if (
        not isinstance(download, dict)
        or download.get("Path") != configuration.module_path
        or download.get("Version") != configuration.module_version
        or not isinstance(download.get("Zip"), str)
        or not isinstance(download.get("Dir"), str)
        or not isinstance(download.get("GoMod"), str)
        or not isinstance(download.get("Sum"), str)
        or not isinstance(download.get("GoModSum"), str)
        or "Error" in download
    ):
        raise ReleaseError("Go tool did not accept the exact module archive")
    module_cache = Path(environment["GOMODCACHE"]).resolve(strict=True)
    downloaded_zip = Path(download["Zip"]).resolve(strict=True)
    downloaded_root = Path(download["Dir"]).resolve(strict=True)
    downloaded_mod = Path(download["GoMod"]).resolve(strict=True)
    for path, label in (
        (downloaded_zip, "downloaded ZIP"),
        (downloaded_root, "downloaded module"),
        (downloaded_mod, "downloaded go.mod"),
    ):
        if os.path.commonpath((os.fspath(path), os.fspath(module_cache))) != os.fspath(
            module_cache
        ):
            raise ReleaseError(f"{label} escaped the fresh Go module cache")
    staged_payload = _read_stable_file(archive, MAX_ARCHIVE_BYTES, "staged Go module")
    cached_payload = _read_stable_file(
        downloaded_zip, MAX_ARCHIVE_BYTES, "downloaded Go module ZIP"
    )
    if cached_payload != staged_payload:
        raise ReleaseError("Go tool cached bytes differ from the staged module archive")
    if (
        _read_stable_file(downloaded_mod, MAX_SOURCE_FILE_BYTES, "downloaded go.mod")
        != configuration.assets["go.mod"]
    ):
        raise ReleaseError("Go tool cached go.mod differs from the reviewed module")
    _validate_extracted_module(configuration, downloaded_root)

    packages_output = _run_checked(
        [str(go), "list", "-mod=readonly", "./..."],
        cwd=downloaded_root,
        environment=environment,
        timeout=300,
        label="offline Go package listing",
    )
    packages = tuple(
        line
        for line in packages_output.decode("utf-8", errors="strict").splitlines()
        if line
    )
    if packages != EXPECTED_PACKAGES:
        raise ReleaseError("Go package inventory differs from the reviewed SDK set")
    _run_checked(
        [str(go), "vet", "-mod=readonly", "./..."],
        cwd=downloaded_root,
        environment=environment,
        timeout=600,
        label="offline Go vet",
    )
    _run_checked(
        [str(go), "test", "-mod=readonly", "-count=1", "./..."],
        cwd=downloaded_root,
        environment=environment,
        timeout=900,
        label="offline Go package tests",
    )
    semantic_bundle_identity = (
        _run_checked(
            [
                str(go),
                "run",
                "-mod=readonly",
                "./cmd/cigar-qualify-bundle",
            ],
            cwd=downloaded_root,
            environment=environment,
            timeout=300,
            label="offline Go semantic-bundle workflow",
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    if semantic_bundle_identity != EXPECTED_QUICKSTART_IDENTITY:
        raise ReleaseError("Go semantic-bundle identity differs")
    verify_output = _run_checked(
        [str(go), "mod", "verify"],
        cwd=downloaded_root,
        environment=environment,
        timeout=300,
        label="offline Go module verification",
    )
    if verify_output != b"all modules verified\n":
        raise ReleaseError("Go module verification output is unexpected")

    result = {
        "schema_version": "cigar.go-sdk-build-validation.v1",
        "status": "passed",
        "offline": True,
        "fresh_module_cache": True,
        "module_path": configuration.module_path,
        "module_version": configuration.module_version,
        "module_sum": download["Sum"],
        "go_mod_sum": download["GoModSum"],
        "packages": list(packages),
        "checks": {
            "go-mod-download": "passed",
            "go-mod-verify": "passed",
            "go-list": "passed",
            "go-vet": "passed",
            "go-test": "passed",
            "semantic-bundle": "passed",
        },
        "semantic_bundle_identity": semantic_bundle_identity,
        "tool": _tool_record(go, version_output),
    }
    _validate_go_result(result)
    return result


def produce(
    arguments: argparse.Namespace,
    *,
    go_validator: GoValidator = _default_go_validator,
) -> dict[str, Any]:
    root = arguments.root.resolve(strict=True)
    host = _require_host()
    evidence_root = _selected_evidence_directory(arguments)
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    _zip_datetime(epoch)
    configuration = _load_configuration(root)
    source_before = _source_identity(root)

    workspace = EvidenceWorkspace.create(evidence_root, repository_root=root)
    try:
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(prefix="cigar-go-sdk-build-") as raw:
            scratch = Path(raw).resolve(strict=True)
            # Unpublished module bytes and validation caches must remain owner-only.
            # fmt: off
            os.chmod(scratch, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            # fmt: on
            entries = _package_entries(configuration)
            staged_archive = scratch / configuration.filename
            _write_archive(staged_archive, entries, epoch)
            validated_payload = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "staged Go module archive"
            )
            validated_bytes = len(validated_payload)
            validated_sha256 = sha256_bytes(validated_payload)
            verification = verify_package(
                staged_archive,
                configuration.contract_path,
                configuration.product_version,
                configuration.context_abi,
                epoch,
            )
            if verification.get("status") != "passed":
                raise ReleaseError("Go module contract verification did not pass")
            go_validation = go_validator(
                configuration, staged_archive, epoch, scratch, arguments
            )
            _validate_go_result(go_validation)
            if go_validation["module_version"] != configuration.module_version:
                raise ReleaseError("Go SDK validation used a different module version")
            if _source_identity(root) != source_before:
                raise ReleaseError("Go SDK source changed during construction")
            if _authority_digests(root) != configuration.authority:
                raise ReleaseError("Go SDK authority changed during construction")
            final_payload = _read_stable_file(
                staged_archive, MAX_ARCHIVE_BYTES, "verified Go module archive"
            )
            if (
                len(final_payload) != validated_bytes
                or sha256_bytes(final_payload) != validated_sha256
            ):
                raise ReleaseError("Go module archive changed during verification")
            archive_reference = workspace.attach_file(
                staged_archive,
                configuration.filename,
                expected_sha256=validated_sha256,
                expected_bytes=validated_bytes,
            )

        receipt = {
            "schema_version": "cigar.development-go-sdk-build.v1",
            "status": "built-unqualified",
            "artifact_id": ARTIFACT_ID,
            "target": TARGET_TRIPLE,
            "product_version": configuration.product_version,
            "context_abi": configuration.context_abi,
            "source_date_epoch": epoch,
            "source": source_before,
            "host": host,
            "archive": archive_reference.as_dict(),
            "module": {
                "path": configuration.module_path,
                "version": configuration.module_version,
                "prefix": configuration.module_prefix,
            },
            "contract": {
                "path": configuration.contract_relative,
                "sha256": configuration.authority[configuration.contract_relative][
                    "sha256"
                ],
            },
            "authority": configuration.authority,
            "payload_file_count": len(configuration.assets),
            "package_verification": {
                "schema_version": verification["schema_version"],
                "status": verification["status"],
                "file_count": verification["file_count"],
                "expanded_bytes": verification["expanded_bytes"],
            },
            "go_validation": go_validation,
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
        raise SystemExit(f"Go SDK development build failed: {error}") from error
