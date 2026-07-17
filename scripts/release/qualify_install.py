#!/usr/bin/env python3
"""Install, exercise, and uninstall one verified binary archive as an unprivileged offline user."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    load_json_bytes,
    process_failure_summary,
    require_distinct_output,
    run_bounded,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
)
from verify_package import verify as verify_package


DEFAULT_PRODUCT_VERSION = "0.9.0-honey.1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_CONTRACT_BYTES = 8 * 1024 * 1024
MAX_BUILD_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_DRIVER_BYTES = 512 * 1024 * 1024
RUNTIME_ARTIFACT_ID = "macos-runtime-aarch64"
RUNTIME_CONTRACT_ID = "macos-runtime-archive-v1"
RUNTIME_PROFILE = "cigar.full.local-macos-aarch64.v1"
INSTALLED_WORKFLOW_PROFILE = "cigar.full.offline-read-only.macos-aarch64.v1"
QUALIFICATION_TOOL_ARTIFACT_ID = "cigar-conformance-macos-aarch64"
QUALIFICATION_TOOL_CONTRACT_ID = "macos-conformance-runner-v1"
MACOS_TARGET = "aarch64-apple-darwin"
MACOS_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
MACOS_NO_EGRESS_ENFORCEMENT = "darwin-seatbelt-deny-network-mach-confine-writes-protect-candidate-workspace-unix-v1"
MACOS_PROCESS_ENFORCEMENT = "darwin-seatbelt-deny-process-fork-signal-v1"
BUILD_RECEIPT_AUTHENTICATION = "not-authenticated-external-signing-required-v1"
MACOS_PRIVATE_TMP = Path("/private/tmp")
MAX_MACOS_SOCKET_PATH_BYTES = 96
DRIVER_RUNTIME_LABELS = ("governed", "contracts", "upgrade")
RUNTIME_BUILD_RECEIPT_SCHEMA = "cigar.development-native-archive-build.v1"
QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA = (
    "cigar.development-qualification-tool-build.v1"
)
RUNTIME_RECEIPT_AUTHORITY_PATHS = frozenset(
    {
        "packaging/product-version.v1.json",
        "packaging/honey/capability-profile.v1.json",
        "packaging/honey/artifact-matrix.v1.json",
        "packaging/honey/local-archives.v1.json",
        "packaging/honey/release-requirements.v1.json",
        "packaging/contracts/macos-runtime-archive.v1.json",
        "adapters/claude-code/package-manifest.json",
    }
)
QUALIFICATION_TOOL_RECEIPT_AUTHORITY_PATHS = frozenset(
    {
        "packaging/product-version.v1.json",
        "packaging/honey/capability-profile.v1.json",
        "packaging/honey/artifact-matrix.v1.json",
        "packaging/honey/release-requirements.v1.json",
        "packaging/contracts/macos-conformance-runner.v1.json",
    }
)
SHARED_BUILD_AUTHORITY_PATHS = (
    "packaging/product-version.v1.json",
    "packaging/honey/capability-profile.v1.json",
    "packaging/honey/artifact-matrix.v1.json",
    "packaging/honey/release-requirements.v1.json",
)
PROHIBITED_BUILD_COMMANDS = (
    "ar",
    "cargo",
    "cc",
    "clang",
    "clang++",
    "cmake",
    "c++",
    "g++",
    "gcc",
    "ld",
    "make",
    "ninja",
    "rustc",
)
REQUIRED_DRIVER_CHECKS = frozenset(
    {
        "approved-source-config",
        "backup-restore",
        "catalog-query-retrieval",
        "compile",
        "daemon-lifecycle",
        "delta",
        "doctor",
        "effect-reconcile-cli-contract",
        "excluded-surface-negative",
        "explain",
        "full-surface",
        "handoff-preview-cli-contract",
        "ingest",
        "init",
        "materialize",
        "no-egress",
        "offline-restart",
        "permission-denial",
        "revalidate",
        "replay-cli-contract",
        "source-add",
        "upgrade",
        "version-binding",
    }
)
REQUIRED_QUALIFICATION_CHECKS = tuple(
    sorted(
        {
            *REQUIRED_DRIVER_CHECKS,
            "claude-hook-schema",
            "help",
            "mcp-schema",
            "version",
        }
    )
)
REQUIRED_INSTALLED_BINARIES = (
    "cigar",
    "cigar-claude-hook",
    "cigar-mcp",
    "cigard",
)
REQUIRED_PATH_CASES = (
    "spaces",
    "unicode",
    "long",
    "read-only-parent",
    "non-admin",
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--runtime-build-receipt", type=Path, required=True)
    parser.add_argument("--qualification-tool-archive", type=Path, required=True)
    parser.add_argument("--qualification-tool-contract", type=Path, required=True)
    parser.add_argument("--qualification-tool-build-receipt", type=Path, required=True)
    parser.add_argument("--expected-artifact-id", required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-version", default=DEFAULT_PRODUCT_VERSION)
    parser.add_argument("--expected-abi", default="cigar.context.v1")
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external qualification workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    return parser.parse_args()


def _selected_evidence_directory(arguments: argparse.Namespace) -> Path | None:
    argument = arguments.evidence_dir
    environment = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument is not None and environment:
        if Path(argument) != Path(environment):
            raise ReleaseError(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide one location"
            )
    raw = argument if argument is not None else environment
    if raw is None or os.fspath(raw) == "":
        return None
    selected = Path(raw)
    if not selected.is_absolute():
        raise ReleaseError("evidence directory must be an absolute path")
    return selected


class _ReportOutput:
    """Pinned create-new destination for one candidate qualification report."""

    def __init__(self, workspace: EvidenceWorkspace, relative: str) -> None:
        self.workspace = workspace
        self.relative = relative

    @classmethod
    def open(cls, arguments: argparse.Namespace) -> _ReportOutput | None:
        evidence_root = _selected_evidence_directory(arguments)
        if arguments.report is None:
            return None
        if evidence_root is None:
            raise ReleaseError(
                "qualification --report requires --evidence-dir or CIGAR_EVIDENCE_DIR"
            )
        if arguments.report.is_absolute():
            raise ReleaseError(
                "--report must be relative to the selected evidence directory"
            )
        parts = safe_evidence_path(os.fspath(arguments.report))
        relative = "/".join(parts)
        tentative = evidence_root.joinpath(*parts)
        require_distinct_output(
            tentative,
            [
                arguments.archive,
                arguments.contract,
                arguments.runtime_build_receipt,
                arguments.qualification_tool_archive,
                arguments.qualification_tool_contract,
                arguments.qualification_tool_build_receipt,
            ],
            "install qualification",
        )
        workspace = EvidenceWorkspace.create(
            evidence_root,
            repository_root=REPOSITORY_ROOT,
        )
        try:
            require_distinct_output(
                workspace.root.joinpath(*parts),
                [
                    arguments.archive,
                    arguments.contract,
                    arguments.runtime_build_receipt,
                    arguments.qualification_tool_archive,
                    arguments.qualification_tool_contract,
                    arguments.qualification_tool_build_receipt,
                ],
                "install qualification",
            )
            return cls(workspace, relative)
        except BaseException:
            workspace.close()
            raise

    def publish(self, report: dict[str, Any]) -> None:
        self.workspace.write_json(self.relative, report)

    def close(self) -> None:
        self.workspace.close()


def _destination(root: Path, relative: str) -> Path:
    relative = safe_relative_path(relative)
    destination = root.joinpath(*relative.split("/"))
    resolved_parent = destination.parent.resolve()
    root_resolved = root.resolve()
    if (
        resolved_parent != root_resolved
        and root_resolved not in resolved_parent.parents
    ):
        raise ReleaseError(f"archive extraction escapes install root: {relative}")
    return destination


def _extract(archive_path: Path, destination: Path) -> None:
    if archive_path.name.lower().endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path, "r:*") as archive:
            for tar_member in archive:
                if tar_member.isdir():
                    continue
                if not tar_member.isfile():
                    raise ReleaseError(f"non-regular install member: {tar_member.name}")
                output = _destination(destination, tar_member.name)
                output.parent.mkdir(parents=True, exist_ok=True)
                handle = archive.extractfile(tar_member)
                if handle is None:
                    raise ReleaseError(f"cannot read install member: {tar_member.name}")
                with handle, output.open("xb") as target:
                    shutil.copyfileobj(handle, target, 1024 * 1024)
                os.chmod(output, tar_member.mode & 0o777)
        return
    with zipfile.ZipFile(archive_path) as archive:
        for zip_member in archive.infolist():
            if zip_member.is_dir():
                continue
            mode = (zip_member.external_attr >> 16) & 0o177777
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise ReleaseError(f"linked install member: {zip_member.filename}")
            output = _destination(destination, zip_member.filename)
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(zip_member) as source, output.open("xb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
            os.chmod(output, (mode & 0o777) or 0o644)


def _stage_secure_input(
    source: Path,
    destination: Path,
    maximum: int,
    label: str,
    *,
    executable: bool = False,
) -> tuple[str, int]:
    """Copy one stable, owner-controlled, symlink-free input to a create-new file."""

    if maximum <= 0:
        raise ReleaseError(f"{label} maximum is invalid")
    source = source.absolute()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = -1
    destination_descriptor = -1
    try:
        source_descriptor = os.open(source, flags)
        before = os.fstat(source_descriptor)
        named_before = os.stat(source, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > maximum
            or (executable and not before.st_mode & 0o111)
        ):
            raise ReleaseError(
                f"{label} is not a bounded owner-controlled regular file"
            )
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o500 if executable else 0o400,
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds {maximum} bytes")
            digest.update(chunk)
            written = 0
            while written < len(chunk):
                count = os.write(destination_descriptor, chunk[written:])
                if count <= 0:
                    raise ReleaseError(f"cannot stage {label}")
                written += count
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        named_after = os.stat(source, follow_symlinks=False)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            total != before.st_size
            or any(getattr(before, field) != getattr(after, field) for field in stable)
            or any(
                getattr(before, field) != getattr(named_after, field)
                for field in stable
            )
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise ReleaseError(f"{label} changed while it was staged")
        staged = os.fstat(destination_descriptor)
        if staged.st_size != total or staged.st_nlink != 1:
            raise ReleaseError(f"staged {label} identity is invalid")
        return digest.hexdigest(), total
    except OSError as error:
        raise ReleaseError(f"cannot securely stage {label}: {error}") from error
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)


def _run(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    expected: int = 0,
    *,
    ipc_root: Path | None = None,
    protected_roots: tuple[Path, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    if platform.system().lower() == "darwin":
        command = [
            str(_validated_macos_sandbox()),
            "-p",
            _macos_no_egress_policy(ipc_root or cwd, protected_roots),
            *command,
        ]
    result = run_bounded(
        command,
        cwd=cwd,
        env=environment,
        timeout=300,
        max_stdout=8 * 1024 * 1024,
        max_stderr=8 * 1024 * 1024,
    )
    if result.returncode != expected:
        raise ReleaseError(process_failure_summary(result, "installed command"))
    return result


def _run_qualification_driver(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    """Run the verified Rust driver directly; it owns the single child Seatbelt boundary."""

    result = run_bounded(
        command,
        cwd=cwd,
        env=environment,
        timeout=300,
        max_stdout=8 * 1024 * 1024,
        max_stderr=8 * 1024 * 1024,
    )
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, "qualification driver"))
    return result


def _macos_no_egress_policy(
    ipc_root: Path,
    protected_roots: tuple[Path, ...] = (),
) -> str:
    """Deny IP/ambient IPC and make exact candidate inputs immutable to children."""

    try:
        root = ipc_root.resolve(strict=True)
        metadata = ipc_root.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseError("the macOS IPC qualification root is unavailable") from error
    if (
        ipc_root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseError(
            "the macOS IPC qualification root is not an owner-controlled directory"
        )
    # SBPL string literals use the same escaping needed for JSON strings.  The enclosing
    # TemporaryDirectory is private, while this scoped exception permits the installed daemon's
    # owner-only Unix socket without reopening IP, DNS, or ambient system-socket access.
    protected: list[str] = []
    seen: set[Path] = set()
    for candidate in protected_roots:
        try:
            resolved = candidate.resolve(strict=True)
            candidate_metadata = candidate.stat(follow_symlinks=False)
        except OSError as error:
            raise ReleaseError(
                "a protected macOS qualification root is unavailable"
            ) from error
        if (
            candidate.is_symlink()
            or not stat.S_ISDIR(candidate_metadata.st_mode)
            or candidate_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(candidate_metadata.st_mode) & 0o022
        ):
            raise ReleaseError(
                "a protected macOS qualification root is not owner-controlled"
            )
        if resolved in seen:
            raise ReleaseError("duplicate protected macOS qualification root")
        seen.add(resolved)
        protected.append(
            f"(deny file-write* (subpath {json.dumps(os.fspath(resolved), ensure_ascii=False)}))"
        )
    encoded_root = json.dumps(os.fspath(root), ensure_ascii=False)
    return "".join(
        [
            "(version 1)(allow default)(deny network*)(deny mach-lookup)(deny file-write*)",
            "(deny process-fork)(deny signal)",
            f"(allow file-write* (subpath {encoded_root}))",
            *protected,
            "(allow network-bind network-inbound network-outbound ",
            f"(subpath {encoded_root}))",
        ]
    )


def _validated_macos_sandbox() -> Path:
    """Return the fixed root-controlled Seatbelt launcher used for candidate processes."""

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


def _no_egress_enforcement(target: str) -> str:
    if target == "aarch64-apple-darwin":
        _validated_macos_sandbox()
        return MACOS_NO_EGRESS_ENFORCEMENT
    return "external-runner-attestation-v1"


def _validated_private_tmp() -> Path:
    """Return the canonical root-owned sticky macOS temporary directory."""

    try:
        metadata = MACOS_PRIVATE_TMP.stat(follow_symlinks=False)
        resolved = MACOS_PRIVATE_TMP.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(
            "the fixed macOS qualification temp root is unavailable"
        ) from error
    if (
        MACOS_PRIVATE_TMP.is_symlink()
        or resolved != MACOS_PRIVATE_TMP
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o1777
    ):
        raise ReleaseError(
            "the fixed macOS qualification temp root is not root-owned sticky 01777"
        )
    return MACOS_PRIVATE_TMP


@contextmanager
def _qualification_directory() -> Iterator[Path]:
    """Allocate one short, private qualification root beneath canonical /private/tmp."""

    root = _validated_private_tmp()
    with tempfile.TemporaryDirectory(prefix="cigar-q-", dir=root) as temporary:
        base = Path(temporary)
        # Installed candidate bytes and IPC endpoints must remain private to the qualifier user.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            base,
            0o700,
        )
        metadata = base.stat(follow_symlinks=False)
        if (
            base.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or base.parent.resolve(strict=True) != root
        ):
            raise ReleaseError(
                "the macOS qualification root is not private and canonical"
            )
        yield base


def _driver_socket_paths(temporary_root: Path) -> tuple[Path, ...]:
    """Derive and bound every Unix socket path allocated by the Rust driver."""

    root = temporary_root.resolve(strict=True)
    metadata = temporary_root.stat(follow_symlinks=False)
    if (
        temporary_root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseError("the driver temporary root is not owner-controlled")
    paths = tuple(
        root / f"cigar-q-{label}" / "cigard.sock" for label in DRIVER_RUNTIME_LABELS
    )
    if any(len(os.fsencode(path)) > MAX_MACOS_SOCKET_PATH_BYTES for path in paths):
        raise ReleaseError("a qualification driver socket path exceeds 96 bytes")
    return paths


def _is_administrator() -> bool:
    if os.name != "nt":
        if os.getuid() == 0 or os.geteuid() == 0:
            return True
        if platform.system().lower() != "darwin":
            return False
        try:
            admin_gid = grp.getgrnam("admin").gr_gid
        except KeyError as error:
            raise ReleaseError(
                "cannot resolve the root-controlled macOS admin group"
            ) from error
        gids = {os.getgid(), os.getegid(), *os.getgroups()}
        return admin_gid in gids
    import ctypes

    return bool(getattr(ctypes, "windll").shell32.IsUserAnAdmin())


def _host_target() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    architecture = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(
        machine, machine
    )
    if system == "linux":
        libc_name = platform.libc_ver()[0].lower()
        if libc_name not in {"glibc", "gnu libc"}:
            raise ReleaseError(
                f"the binary matrix requires GNU libc, found {libc_name or 'unknown libc'}"
            )
        return f"{architecture}-unknown-linux-gnu"
    if system == "darwin":
        return f"{architecture}-apple-darwin"
    if system == "windows":
        return f"{architecture}-pc-windows-msvc"
    raise ReleaseError(f"unsupported qualification host: {system}-{architecture}")


def _qualification_environment(install: Path, base: Path) -> dict[str, str]:
    """Build the minimal child environment without the parent's evidence target."""

    environment = {
        "PATH": str(install / "bin"),
        "HOME": str(base / "empty-home"),
        "USERPROFILE": str(base / "empty-home"),
        "TMPDIR": str(base / "tmp"),
        "TMP": str(base / "tmp"),
        "TEMP": str(base / "tmp"),
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
        "NO_COLOR": "1",
        "CIGAR_NO_EGRESS_ENFORCED": "1",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR"):
            if value := os.environ.get(key):
                environment[key] = value
    # The installed driver returns its nested receipt through bounded stdout.
    # Never let a child reuse or mutate the pinned parent evidence workspace.
    environment.pop("CIGAR_EVIDENCE_DIR", None)
    return environment


def _required_binary_names(contract: Path) -> tuple[str, ...]:
    document = load_json_bytes(contract.read_bytes(), "installed package contract")
    required = document.get("required") if isinstance(document, dict) else None
    if not isinstance(required, list) or not all(
        isinstance(value, str) for value in required
    ):
        raise ReleaseError("installed package contract has no exact required inventory")
    names = ["cigar", "cigard"]
    for sidecar in ("cigar-mcp", "cigar-claude-hook"):
        if f"bin/{sidecar}" in required:
            names.append(sidecar)
    return tuple(names)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _is_positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _content_free_digest(domain: str, values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in [domain, *values]:
        payload = value.encode("utf-8")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _installed_workflow_binding(
    *,
    artifact_id: str,
    artifact_sha256: str,
    source_revision: str,
    workflow: dict[str, object],
) -> str:
    return _content_free_digest(
        "cigar.installed-workflow-binding.v1",
        [
            artifact_id,
            artifact_sha256,
            source_revision,
            RUNTIME_PROFILE,
            INSTALLED_WORKFLOW_PROFILE,
            str(workflow["full_surface_sha256"]),
            str(workflow["semantic_identity_sha256"]),
            str(workflow["cigar_sha256"]),
            str(workflow["cigard_sha256"]),
            MACOS_NO_EGRESS_ENFORCEMENT,
            MACOS_PROCESS_ENFORCEMENT,
        ],
    )


def _validate_receipt_source(
    source: object, expected: dict[str, Any], label: str
) -> None:
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or source != expected
        or source.get("committed") is not True
        or source.get("clean") is not True
        or not isinstance(source.get("revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"]) is None
        or not _is_sha256(source.get("tree_sha256"))
    ):
        raise ReleaseError(f"{label} source identity is not exact")


def _validate_same_source_identity(
    runtime_source: object, tool_source: object
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Require distinct producer inputs to originate at one clean Git commit."""

    if not isinstance(runtime_source, dict):
        raise ReleaseError("runtime archive source identity is not exact")
    _validate_receipt_source(runtime_source, runtime_source, "runtime archive metadata")
    if not isinstance(tool_source, dict):
        raise ReleaseError("qualification-tool archive source identity is not exact")
    _validate_receipt_source(
        tool_source, tool_source, "qualification-tool archive metadata"
    )
    if tool_source["revision"] != runtime_source["revision"]:
        raise ReleaseError(
            "runtime and qualification-tool archives do not share one clean committed revision"
        )
    return runtime_source, tool_source


def _validate_shared_build_authority(
    runtime_receipt: dict[str, Any], tool_receipt: dict[str, Any]
) -> None:
    """Bind independently produced artifacts to identical shared authority bytes."""

    runtime_authority = runtime_receipt.get("authority")
    tool_authority = tool_receipt.get("authority")
    if not isinstance(runtime_authority, dict) or not isinstance(tool_authority, dict):
        raise ReleaseError("build receipt shared authority is not exact")
    for path in SHARED_BUILD_AUTHORITY_PATHS:
        if (
            path not in runtime_authority
            or path not in tool_authority
            or runtime_authority[path] != tool_authority[path]
        ):
            raise ReleaseError(
                f"runtime and qualification-tool build receipts disagree on {path}"
            )


def _validate_receipt_archive(
    archive: object,
    expected_name: str,
    expected_sha256: str,
    expected_bytes: int,
    label: str,
) -> None:
    if archive != {
        "path": expected_name,
        "sha256": expected_sha256,
        "bytes": expected_bytes,
    }:
        raise ReleaseError(f"{label} archive binding is not exact")


def _validate_receipt_contract(
    contract: object,
    expected_path: str,
    expected_sha256: str,
    label: str,
) -> None:
    if contract != {"path": expected_path, "sha256": expected_sha256}:
        raise ReleaseError(f"{label} package-contract binding is not exact")


def _validate_receipt_authority(
    authority: object,
    expected_paths: frozenset[str],
    contract_path: str,
    contract_sha256: str,
    contract_bytes: int,
    label: str,
) -> None:
    if not isinstance(authority, dict) or set(authority) != expected_paths:
        raise ReleaseError(f"{label} authority inventory is not exact")
    for path, record in authority.items():
        if (
            not isinstance(path, str)
            or not isinstance(record, dict)
            or set(record) != {"sha256", "bytes"}
            or not _is_sha256(record.get("sha256"))
            or not _is_positive_integer(record.get("bytes"))
        ):
            raise ReleaseError(f"{label} authority record is malformed")
    if authority.get(contract_path) != {
        "sha256": contract_sha256,
        "bytes": contract_bytes,
    }:
        raise ReleaseError(f"{label} authority does not bind the staged contract")


def _validate_build_tools(tools: object, label: str) -> None:
    if not isinstance(tools, list) or len(tools) != 3:
        raise ReleaseError(f"{label} build-tool inventory is not exact")
    names: list[str] = []
    for tool in tools:
        if (
            not isinstance(tool, dict)
            or set(tool) != {"name", "version", "sha256", "bytes"}
            or not isinstance(tool.get("name"), str)
            or not isinstance(tool.get("version"), str)
            or not tool["version"]
            or not _is_sha256(tool.get("sha256"))
            or not _is_positive_integer(tool.get("bytes"))
        ):
            raise ReleaseError(f"{label} build-tool record is malformed")
        names.append(tool["name"])
    if names != ["cargo", "protoc", "rustc"]:
        raise ReleaseError(f"{label} build-tool identities are not exact")


def _validate_package_verification(value: object, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "status", "file_count", "expanded_bytes"}
        or value.get("schema_version") != "cigar.package-verification.v1"
        or value.get("status") != "passed"
        or not _is_positive_integer(value.get("file_count"))
        or not _is_positive_integer(value.get("expanded_bytes"))
    ):
        raise ReleaseError(f"{label} package verification is not exact")


def _validate_receipt_host(host: object, label: str) -> None:
    if (
        not isinstance(host, dict)
        or set(host) != {"platform", "architecture", "target_triple", "macos_version"}
        or host.get("platform") != "macos"
        or host.get("architecture") != "arm64"
        or host.get("target_triple") != MACOS_TARGET
        or not isinstance(host.get("macos_version"), str)
        or not host["macos_version"]
    ):
        raise ReleaseError(f"{label} host identity is not exact")


def _validate_runtime_build_receipt(
    payload: bytes,
    *,
    archive_name: str,
    archive_sha256: str,
    archive_bytes: int,
    contract_sha256: str,
    contract_bytes: int,
    product_version: str,
    context_abi: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    receipt = load_json_bytes(payload, "runtime build receipt")
    required_keys = {
        "schema_version",
        "status",
        "artifact_id",
        "target",
        "product_version",
        "context_abi",
        "runtime_profile",
        "source_date_epoch",
        "source",
        "host",
        "archive",
        "contract",
        "authority",
        "build_tools",
        "build_environment",
        "runtime_payload",
        "payload_file_count",
        "package_verification",
        "claims",
    }
    if not isinstance(receipt, dict) or set(receipt) != required_keys:
        raise ReleaseError("runtime build receipt shape is not exact")
    if (
        receipt.get("schema_version") != RUNTIME_BUILD_RECEIPT_SCHEMA
        or receipt.get("status") != "built-unqualified"
        or receipt.get("artifact_id") != RUNTIME_ARTIFACT_ID
        or receipt.get("target") != MACOS_TARGET
        or receipt.get("product_version") != product_version
        or receipt.get("context_abi") != context_abi
        or receipt.get("runtime_profile") != RUNTIME_PROFILE
        or not isinstance(receipt.get("source_date_epoch"), int)
        or isinstance(receipt.get("source_date_epoch"), bool)
        or not 0 <= receipt["source_date_epoch"] <= 4_294_967_295
        or not _is_positive_integer(receipt.get("payload_file_count"))
    ):
        raise ReleaseError("runtime build receipt identity is not exact")
    _validate_receipt_source(receipt.get("source"), source, "runtime build receipt")
    _validate_receipt_host(receipt.get("host"), "runtime build receipt")
    _validate_receipt_archive(
        receipt.get("archive"),
        archive_name,
        archive_sha256,
        archive_bytes,
        "runtime build receipt",
    )
    contract_path = "packaging/contracts/macos-runtime-archive.v1.json"
    _validate_receipt_contract(
        receipt.get("contract"), contract_path, contract_sha256, "runtime build receipt"
    )
    _validate_receipt_authority(
        receipt.get("authority"),
        RUNTIME_RECEIPT_AUTHORITY_PATHS,
        contract_path,
        contract_sha256,
        contract_bytes,
        "runtime build receipt",
    )
    _validate_build_tools(receipt.get("build_tools"), "runtime build receipt")
    if receipt.get("build_environment") != {
        "cargo_network_offline": True,
        "network_enforcement": "darwin-sandbox-exec-deny-network-v1",
        "sandbox_launcher": "/usr/bin/sandbox-exec",
        "sandbox_policy": "(version 1)(allow default)(deny network*)",
    }:
        raise ReleaseError("runtime build receipt environment is not exact")
    payloads = receipt.get("runtime_payload")
    if not isinstance(payloads, dict) or set(payloads) != set(
        REQUIRED_INSTALLED_BINARIES
    ):
        raise ReleaseError("runtime build receipt payload inventory is not exact")
    for name, record in payloads.items():
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "bytes"}
            or record.get("path") != f"bin/{name}"
            or not _is_sha256(record.get("sha256"))
            or not _is_positive_integer(record.get("bytes"))
        ):
            raise ReleaseError("runtime build receipt payload identity is malformed")
    _validate_package_verification(
        receipt.get("package_verification"), "runtime build receipt"
    )
    if receipt.get("claims") != {
        "development_build": False,
        "developer_preview_build": True,
        "distribution_signed": False,
        "notarized": False,
        "qualified": False,
        "published": False,
        "supported": False,
        "release": False,
    }:
        raise ReleaseError("runtime build receipt claims are not exact and unqualified")
    return receipt


def _validate_qualification_tool_build_receipt(
    payload: bytes,
    *,
    archive_name: str,
    archive_sha256: str,
    archive_bytes: int,
    contract_sha256: str,
    contract_bytes: int,
    product_version: str,
    context_abi: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    receipt = load_json_bytes(payload, "qualification-tool build receipt")
    required_keys = {
        "schema_version",
        "status",
        "artifact_id",
        "target",
        "product_version",
        "context_abi",
        "source_date_epoch",
        "source",
        "host",
        "archive",
        "install_target",
        "contract",
        "authority",
        "build_tools",
        "build_environment",
        "invocation_probes",
        "payload",
        "package_verification",
        "claims",
    }
    if not isinstance(receipt, dict) or set(receipt) != required_keys:
        raise ReleaseError("qualification-tool build receipt shape is not exact")
    if (
        receipt.get("schema_version") != QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA
        or receipt.get("status") != "built-unqualified"
        or receipt.get("artifact_id") != QUALIFICATION_TOOL_ARTIFACT_ID
        or receipt.get("target") != MACOS_TARGET
        or receipt.get("product_version") != product_version
        or receipt.get("context_abi") != context_abi
        or receipt.get("install_target") != "bin/cigar-conformance"
        or not isinstance(receipt.get("source_date_epoch"), int)
        or isinstance(receipt.get("source_date_epoch"), bool)
        or not 0 <= receipt["source_date_epoch"] <= 4_294_967_295
    ):
        raise ReleaseError("qualification-tool build receipt identity is not exact")
    _validate_receipt_source(
        receipt.get("source"), source, "qualification-tool build receipt"
    )
    _validate_receipt_host(receipt.get("host"), "qualification-tool build receipt")
    _validate_receipt_archive(
        receipt.get("archive"),
        archive_name,
        archive_sha256,
        archive_bytes,
        "qualification-tool build receipt",
    )
    contract_path = "packaging/contracts/macos-conformance-runner.v1.json"
    _validate_receipt_contract(
        receipt.get("contract"),
        contract_path,
        contract_sha256,
        "qualification-tool build receipt",
    )
    _validate_receipt_authority(
        receipt.get("authority"),
        QUALIFICATION_TOOL_RECEIPT_AUTHORITY_PATHS,
        contract_path,
        contract_sha256,
        contract_bytes,
        "qualification-tool build receipt",
    )
    _validate_build_tools(
        receipt.get("build_tools"), "qualification-tool build receipt"
    )
    if receipt.get("build_environment") != {
        "network_enforcement": "darwin-sandbox-exec-deny-network-v1",
        "sandbox_launcher": "/usr/bin/sandbox-exec",
        "sandbox_policy": "(version 1)(allow default)(deny network*)",
    }:
        raise ReleaseError("qualification-tool build receipt environment is not exact")
    if receipt.get("invocation_probes") != [
        {
            "command": "bin/cigar-conformance --help",
            "status": "passed",
            "scope": "invocation-only",
            "qualifying_evidence": False,
        },
        {
            "command": "bin/cigar-install-qualifier --help",
            "status": "passed",
            "scope": "invocation-only",
            "qualifying_evidence": False,
        },
    ]:
        raise ReleaseError("qualification-tool invocation probes are not exact")
    payload_inventory = receipt.get("payload")
    if not isinstance(payload_inventory, dict) or not {
        "bin/cigar-conformance",
        "bin/cigar-install-qualifier",
    }.issubset(payload_inventory):
        raise ReleaseError("qualification-tool payload inventory is not exact")
    for path, record in payload_inventory.items():
        if (
            not isinstance(path, str)
            or not isinstance(record, dict)
            or set(record) != {"sha256", "bytes", "mode"}
            or not _is_sha256(record.get("sha256"))
            or not _is_positive_integer(record.get("bytes"))
            or record.get("mode") not in {"0644", "0755"}
        ):
            raise ReleaseError("qualification-tool payload record is malformed")
    for path in ("bin/cigar-conformance", "bin/cigar-install-qualifier"):
        if payload_inventory[path].get("mode") != "0755":
            raise ReleaseError("qualification-tool executable mode is not exact")
    _validate_package_verification(
        receipt.get("package_verification"), "qualification-tool build receipt"
    )
    if receipt.get("claims") != {
        "development_build": False,
        "developer_preview_build": True,
        "candidate": False,
        "distribution_signed": False,
        "notarized": False,
        "installed_qualified": False,
        "conformance_qualified": False,
        "benchmark_efficacy": False,
        "qualified": False,
        "published": False,
        "supported": False,
        "release": False,
    }:
        raise ReleaseError(
            "qualification-tool build receipt claims are not exact and unqualified"
        )
    return receipt


def _inspect_macho_arm64_executable(
    path: Path, label: str, maximum: int = MAX_DRIVER_BYTES
) -> tuple[str, int]:
    """Return the digest/size of one stable, thin arm64 MH_EXECUTE regular file."""

    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        named_before = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not before.st_mode & 0o111
            or before.st_size < 32
            or before.st_size > maximum
        ):
            raise ReleaseError(f"{label} is not a bounded owner-controlled executable")
        digest = hashlib.sha256()
        header = b""
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds {maximum} bytes")
            if len(header) < 16:
                header = (header + chunk)[:16]
            digest.update(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=False)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            total != before.st_size
            or any(getattr(before, field) != getattr(after, field) for field in stable)
            or any(
                getattr(before, field) != getattr(named_after, field)
                for field in stable
            )
        ):
            raise ReleaseError(f"{label} changed while its Mach-O identity was read")
        try:
            magic, cpu_type, cpu_subtype, file_type = struct.unpack("<IIII", header)
        except struct.error as error:
            raise ReleaseError(f"{label} has a truncated Mach-O header") from error
        if (
            magic != 0xFEEDFACF
            or cpu_type != 0x0100000C
            or cpu_subtype != 0
            or file_type != 2
        ):
            raise ReleaseError(f"{label} is not a thin arm64 macOS executable")
        return digest.hexdigest(), total
    except OSError as error:
        raise ReleaseError(f"cannot inspect {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_driver_receipt(
    payload: bytes,
    artifact_id: str,
    artifact_sha256: str,
    product_version: str,
    context_abi: str,
    source_revision: str,
) -> tuple[dict[str, object], list[str]]:
    receipt = load_json_bytes(payload, "installed qualification driver")
    required_keys = {
        "schema_version",
        "status",
        "artifact_id",
        "artifact_sha256",
        "product_version",
        "context_abi",
        "source_revision",
        "runtime_profile",
        "installed_workflow",
        "process_enforcement",
        "checks",
    }
    if not isinstance(receipt, dict) or set(receipt) != required_keys:
        raise ReleaseError(
            "installed qualification driver returned an unexpected receipt shape"
        )
    if (
        receipt.get("schema_version") != "cigar.installed-driver.v1"
        or receipt.get("status") != "passed"
        or receipt.get("artifact_id") != artifact_id
        or receipt.get("artifact_sha256") != artifact_sha256
        or receipt.get("product_version") != product_version
        or receipt.get("context_abi") != context_abi
        or receipt.get("source_revision") != source_revision
        or receipt.get("runtime_profile") != RUNTIME_PROFILE
        or receipt.get("process_enforcement") != MACOS_PROCESS_ENFORCEMENT
    ):
        raise ReleaseError(
            "installed qualification driver receipt is stale or bound to another artifact"
        )
    workflow = receipt.get("installed_workflow")
    workflow_keys = {
        "profile",
        "full_surface_sha256",
        "semantic_identity_sha256",
        "cigar_sha256",
        "cigard_sha256",
        "binding_sha256",
        "no_egress_enforcement",
    }
    if (
        not isinstance(workflow, dict)
        or set(workflow) != workflow_keys
        or workflow.get("profile") != INSTALLED_WORKFLOW_PROFILE
        or workflow.get("no_egress_enforcement") != MACOS_NO_EGRESS_ENFORCEMENT
        or any(
            not _is_sha256(workflow.get(field))
            for field in (
                "full_surface_sha256",
                "semantic_identity_sha256",
                "cigar_sha256",
                "cigard_sha256",
                "binding_sha256",
            )
        )
        or workflow.get("binding_sha256")
        != _installed_workflow_binding(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            source_revision=source_revision,
            workflow=workflow,
        )
    ):
        raise ReleaseError(
            "installed qualification driver workflow binding is stale or malformed"
        )
    checks = receipt.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ReleaseError("installed qualification driver returned no checks")
    check_ids: list[str] = []
    for check in checks:
        if (
            not isinstance(check, dict)
            or set(check) != {"id", "status"}
            or check.get("status") != "passed"
        ):
            raise ReleaseError(
                "installed qualification driver returned a malformed or non-passing check"
            )
        identifier = check.get("id")
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", identifier) is None
            or len(identifier.encode("utf-8")) > 128
        ):
            raise ReleaseError(
                "installed qualification driver returned an invalid check id"
            )
        check_ids.append(identifier)
    if len(set(check_ids)) != len(check_ids):
        raise ReleaseError(
            "installed qualification driver returned duplicate check ids"
        )
    required_checks = set(REQUIRED_DRIVER_CHECKS)
    if os.name == "nt":
        required_checks.add("read-only-parent")
    observed_checks = set(check_ids)
    missing = required_checks - observed_checks
    unexpected = observed_checks - required_checks
    if missing or unexpected:
        raise ReleaseError(
            "installed qualification driver check inventory is not exact: "
            f"missing={sorted(missing)} unexpected={sorted(unexpected)}"
        )
    return receipt, check_ids


def _validate_report(report: dict[str, Any]) -> None:
    """Fail closed before publishing one macOS installed-artifact receipt."""

    required_keys = {
        "schema_version",
        "status",
        "artifact_id",
        "artifact_sha256",
        "artifact_bytes",
        "product_version",
        "context_abi",
        "source_revision",
        "target",
        "runtime_build_receipt",
        "qualification_tool",
        "build_receipt_authentication",
        "driver_receipt_sha256",
        "installed_binary_sha256",
        "installed_workflow",
        "unprivileged",
        "non_admin",
        "no_compiler_path",
        "no_egress",
        "no_egress_enforcement",
        "process_enforcement",
        "path_cases",
        "checks",
        "uninstalled",
        "state_retained",
        "package_contract_sha256",
    }
    digest_fields = (
        "artifact_sha256",
        "driver_receipt_sha256",
        "package_contract_sha256",
    )
    if set(report) != required_keys:
        raise ReleaseError("install qualification report shape is not exact")
    if (
        report.get("schema_version") != "cigar.install-qualification.v1"
        or report.get("status") != "passed"
        or report.get("artifact_id") != RUNTIME_ARTIFACT_ID
        or report.get("target") != MACOS_TARGET
        or report.get("context_abi") != "cigar.context.v1"
        or report.get("no_egress_enforcement") != MACOS_NO_EGRESS_ENFORCEMENT
        or report.get("process_enforcement") != MACOS_PROCESS_ENFORCEMENT
        or report.get("build_receipt_authentication") != BUILD_RECEIPT_AUTHENTICATION
        or not isinstance(report.get("product_version"), str)
        or re.fullmatch(
            r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?",
            report["product_version"],
        )
        is None
        or not isinstance(report.get("source_revision"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", report["source_revision"])
        is None
        or not isinstance(report.get("artifact_bytes"), int)
        or isinstance(report.get("artifact_bytes"), bool)
        or report["artifact_bytes"] <= 0
        or any(
            not isinstance(report.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", report[field]) is None
            for field in digest_fields
        )
        or any(
            report.get(field) is not True
            for field in (
                "unprivileged",
                "non_admin",
                "no_compiler_path",
                "no_egress",
                "uninstalled",
                "state_retained",
            )
        )
        or report.get("path_cases") != list(REQUIRED_PATH_CASES)
        or report.get("checks") != list(REQUIRED_QUALIFICATION_CHECKS)
    ):
        raise ReleaseError("install qualification report is stale or malformed")

    runtime_receipt = report.get("runtime_build_receipt")
    if (
        not isinstance(runtime_receipt, dict)
        or set(runtime_receipt) != {"schema_version", "status", "sha256", "bytes"}
        or runtime_receipt.get("schema_version") != RUNTIME_BUILD_RECEIPT_SCHEMA
        or runtime_receipt.get("status") != "built-unqualified"
        or not _is_sha256(runtime_receipt.get("sha256"))
        or not _is_positive_integer(runtime_receipt.get("bytes"))
    ):
        raise ReleaseError("runtime build receipt report binding is not exact")

    binaries = report.get("installed_binary_sha256")
    if (
        not isinstance(binaries, dict)
        or tuple(sorted(binaries)) != REQUIRED_INSTALLED_BINARIES
        or any(
            not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in binaries.values()
        )
    ):
        raise ReleaseError("installed binary digest inventory is not exact")

    workflow = report.get("installed_workflow")
    if (
        not isinstance(workflow, dict)
        or set(workflow)
        != {
            "profile",
            "full_surface_sha256",
            "semantic_identity_sha256",
            "cigar_sha256",
            "cigard_sha256",
            "binding_sha256",
            "no_egress_enforcement",
        }
        or workflow.get("profile") != INSTALLED_WORKFLOW_PROFILE
        or workflow.get("no_egress_enforcement") != MACOS_NO_EGRESS_ENFORCEMENT
        or workflow.get("cigar_sha256") != binaries["cigar"]
        or workflow.get("cigard_sha256") != binaries["cigard"]
        or any(
            not _is_sha256(workflow.get(field))
            for field in (
                "full_surface_sha256",
                "semantic_identity_sha256",
                "cigar_sha256",
                "cigard_sha256",
                "binding_sha256",
            )
        )
        or workflow.get("binding_sha256")
        != _installed_workflow_binding(
            artifact_id=report["artifact_id"],
            artifact_sha256=report["artifact_sha256"],
            source_revision=report["source_revision"],
            workflow=workflow,
        )
    ):
        raise ReleaseError("installed workflow report binding is not exact")

    tool = report.get("qualification_tool")
    if (
        not isinstance(tool, dict)
        or set(tool)
        != {
            "artifact_id",
            "archive_sha256",
            "archive_bytes",
            "contract_id",
            "contract_sha256",
            "source_revision",
            "build_receipt_schema_version",
            "build_receipt_status",
            "build_receipt_sha256",
            "build_receipt_bytes",
            "runner_path",
            "runner_sha256",
            "driver_path",
            "driver_sha256",
        }
        or tool.get("artifact_id") != QUALIFICATION_TOOL_ARTIFACT_ID
        or tool.get("contract_id") != QUALIFICATION_TOOL_CONTRACT_ID
        or tool.get("build_receipt_schema_version")
        != QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA
        or tool.get("build_receipt_status") != "built-unqualified"
        or tool.get("runner_path") != "bin/cigar-conformance"
        or tool.get("driver_path") != "bin/cigar-install-qualifier"
        or tool.get("source_revision") != report["source_revision"]
        or not isinstance(tool.get("archive_bytes"), int)
        or isinstance(tool.get("archive_bytes"), bool)
        or tool["archive_bytes"] <= 0
        or not _is_positive_integer(tool.get("build_receipt_bytes"))
        or any(
            not isinstance(tool.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", tool[field]) is None
            for field in (
                "archive_sha256",
                "contract_sha256",
                "build_receipt_sha256",
                "runner_sha256",
                "driver_sha256",
            )
        )
    ):
        raise ReleaseError("qualification tool provenance is not exact")


def _qualify(arguments: argparse.Namespace) -> dict[str, Any]:
    archive = arguments.archive.absolute()
    contract = arguments.contract.absolute()
    runtime_build_receipt = arguments.runtime_build_receipt.absolute()
    tool_archive = arguments.qualification_tool_archive.absolute()
    tool_contract = arguments.qualification_tool_contract.absolute()
    tool_build_receipt = arguments.qualification_tool_build_receipt.absolute()
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", arguments.expected_artifact_id) is None:
        raise ReleaseError("expected artifact id is invalid")
    if re.fullmatch(r"[a-z0-9_]+-[a-z0-9_.-]+", arguments.expected_target) is None:
        raise ReleaseError("expected target triple is invalid")
    if (
        re.fullmatch(
            r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", arguments.expected_version
        )
        is None
    ):
        raise ReleaseError("expected product version is invalid")
    if arguments.expected_abi != "cigar.context.v1":
        raise ReleaseError("expected Context ABI is invalid")
    if (
        arguments.expected_artifact_id != RUNTIME_ARTIFACT_ID
        or arguments.expected_target != MACOS_TARGET
    ):
        raise ReleaseError(
            "install qualification supports only the closed Apple-silicon runtime artifact"
        )
    if _is_administrator():
        raise ReleaseError(
            "install qualification must run as a standard non-admin user"
        )
    if os.environ.get("CIGAR_NO_EGRESS_ENFORCED") != "1":
        raise ReleaseError(
            "the runner must enforce no egress and set CIGAR_NO_EGRESS_ENFORCED=1"
        )
    target = _host_target()
    if target != arguments.expected_target:
        raise ReleaseError(
            f"qualification host target {target} does not match expected target {arguments.expected_target}"
        )
    no_egress_enforcement = _no_egress_enforcement(target)
    with _qualification_directory() as base:
        staged_directory = base / "immutable candidate"
        staged_directory.mkdir()
        staged_archive = staged_directory / archive.name
        original_digest, original_size = _stage_secure_input(
            archive,
            staged_archive,
            MAX_ARCHIVE_BYTES,
            "candidate archive",
        )
        staged_contract = staged_directory / "package-contract.json"
        contract_digest, contract_size = _stage_secure_input(
            contract,
            staged_contract,
            MAX_CONTRACT_BYTES,
            "package contract",
        )
        staged_runtime_build_receipt = staged_directory / "runtime-build-receipt.json"
        runtime_build_receipt_digest, runtime_build_receipt_size = _stage_secure_input(
            runtime_build_receipt,
            staged_runtime_build_receipt,
            MAX_BUILD_RECEIPT_BYTES,
            "runtime build receipt",
        )
        staged_tool_archive = staged_directory / tool_archive.name
        tool_archive_digest, tool_archive_size = _stage_secure_input(
            tool_archive,
            staged_tool_archive,
            MAX_ARCHIVE_BYTES,
            "qualification-tool archive",
        )
        staged_tool_contract = staged_directory / "qualification-tool-contract.json"
        tool_contract_digest, tool_contract_size = _stage_secure_input(
            tool_contract,
            staged_tool_contract,
            MAX_CONTRACT_BYTES,
            "qualification-tool contract",
        )
        staged_tool_build_receipt = (
            staged_directory / "qualification-tool-build-receipt.json"
        )
        tool_build_receipt_digest, tool_build_receipt_size = _stage_secure_input(
            tool_build_receipt,
            staged_tool_build_receipt,
            MAX_BUILD_RECEIPT_BYTES,
            "qualification-tool build receipt",
        )
        if (
            sha256_file(staged_archive) != original_digest
            or staged_archive.stat().st_size != original_size
            or sha256_file(staged_contract) != contract_digest
            or sha256_file(staged_runtime_build_receipt) != runtime_build_receipt_digest
            or sha256_file(staged_tool_archive) != tool_archive_digest
            or staged_tool_archive.stat().st_size != tool_archive_size
            or sha256_file(staged_tool_contract) != tool_contract_digest
            or sha256_file(staged_tool_build_receipt) != tool_build_receipt_digest
        ):
            raise ReleaseError(
                "candidate or qualification-tool input changed while it was staged"
            )
        verification = verify_package(
            staged_archive,
            staged_contract,
            arguments.expected_version,
            arguments.expected_abi,
        )
        required_binary_names = _required_binary_names(staged_contract)
        if (
            contract_digest != verification["contract"]["sha256"]
            or verification["contract"].get("id") != RUNTIME_CONTRACT_ID
            or required_binary_names
            != ("cigar", "cigard", "cigar-mcp", "cigar-claude-hook")
        ):
            raise ReleaseError("package contract changed during qualification")
        metadata = verification.get("metadata")
        source = metadata.get("source") if isinstance(metadata, dict) else None
        if (
            not isinstance(metadata, dict)
            or metadata.get("artifact_id") != arguments.expected_artifact_id
            or metadata.get("product_version") != arguments.expected_version
            or metadata.get("context_abi") != arguments.expected_abi
            or not isinstance(source, dict)
            or set(source) != {"revision", "tree_sha256", "committed", "clean"}
            or source.get("committed") is not True
            or source.get("clean") is not True
            or not isinstance(source.get("revision"), str)
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"])
            is None
            or not _is_sha256(source.get("tree_sha256"))
        ):
            raise ReleaseError(
                "binary archive metadata is not bound to the expected committed, clean candidate"
            )
        runtime_receipt = _validate_runtime_build_receipt(
            staged_runtime_build_receipt.read_bytes(),
            archive_name=archive.name,
            archive_sha256=original_digest,
            archive_bytes=original_size,
            contract_sha256=contract_digest,
            contract_bytes=contract_size,
            product_version=arguments.expected_version,
            context_abi=arguments.expected_abi,
            source=source,
        )
        tool_verification = verify_package(
            staged_tool_archive,
            staged_tool_contract,
            arguments.expected_version,
            arguments.expected_abi,
        )
        tool_metadata = tool_verification.get("metadata")
        tool_source = (
            tool_metadata.get("source") if isinstance(tool_metadata, dict) else None
        )
        if (
            tool_contract_digest != tool_verification["contract"]["sha256"]
            or tool_verification["contract"].get("id") != QUALIFICATION_TOOL_CONTRACT_ID
            or not isinstance(tool_metadata, dict)
            or tool_metadata.get("artifact_id") != QUALIFICATION_TOOL_ARTIFACT_ID
            or tool_metadata.get("product_version") != arguments.expected_version
            or tool_metadata.get("context_abi") != arguments.expected_abi
            or not isinstance(tool_source, dict)
        ):
            raise ReleaseError(
                "qualification-tool archive is not an exact same-source official-format tool"
            )
        source, tool_source = _validate_same_source_identity(source, tool_source)
        tool_receipt = _validate_qualification_tool_build_receipt(
            staged_tool_build_receipt.read_bytes(),
            archive_name=tool_archive.name,
            archive_sha256=tool_archive_digest,
            archive_bytes=tool_archive_size,
            contract_sha256=tool_contract_digest,
            contract_bytes=tool_contract_size,
            product_version=arguments.expected_version,
            context_abi=arguments.expected_abi,
            source=tool_source,
        )
        _validate_shared_build_authority(runtime_receipt, tool_receipt)
        long_path = (
            base
            / "path with spaces"
            / "δοκιμή"
            / ("long-segment-" * 10)
            / ("nested-segment-" * 10)
        )
        install = long_path / "prefix"
        tool_install = long_path / "qualification tool"
        workspace = long_path / "retained project state"
        install.mkdir(parents=True)
        tool_install.mkdir(parents=True)
        workspace.mkdir(parents=True)
        marker = workspace / "retention-marker"
        marker.write_text("retain\n", encoding="utf-8")
        _extract(staged_archive, install)
        _extract(staged_tool_archive, tool_install)
        staged_runner = tool_install / "bin" / "cigar-conformance"
        staged_driver = tool_install / "bin" / "cigar-install-qualifier"
        runner_digest, runner_size = _inspect_macho_arm64_executable(
            staged_runner, "verified cigar-conformance"
        )
        driver_digest, driver_size = _inspect_macho_arm64_executable(
            staged_driver, "verified cigar-install-qualifier"
        )
        tool_payload = tool_receipt["payload"]
        if tool_payload["bin/cigar-conformance"] != {
            "sha256": runner_digest,
            "bytes": runner_size,
            "mode": "0755",
        } or tool_payload["bin/cigar-install-qualifier"] != {
            "sha256": driver_digest,
            "bytes": driver_size,
            "mode": "0755",
        }:
            raise ReleaseError(
                "qualification-tool build receipt does not bind extracted executable identities"
            )
        suffix = ".exe" if os.name == "nt" else ""
        binaries = {
            name: install / "bin" / f"{name}{suffix}" for name in required_binary_names
        }
        cigar = binaries["cigar"]
        cigard = binaries["cigard"]
        binary_identities = {
            name: _inspect_macho_arm64_executable(path, f"installed {name}")
            for name, path in binaries.items()
        }
        binary_digests = {
            name: identity[0] for name, identity in binary_identities.items()
        }
        runtime_payload = runtime_receipt["runtime_payload"]
        for name, (digest, byte_count) in binary_identities.items():
            if runtime_payload[name] != {
                "path": f"bin/{name}",
                "sha256": digest,
                "bytes": byte_count,
            }:
                raise ReleaseError(
                    "runtime build receipt does not bind installed executable identities"
                )
        protected_roots = (staged_directory, install, tool_install)

        environment = _qualification_environment(install, base)
        Path(environment["HOME"]).mkdir()
        Path(environment["TMPDIR"]).mkdir()
        _driver_socket_paths(Path(environment["TMPDIR"]))
        if any(
            shutil.which(command, path=environment["PATH"])
            for command in PROHIBITED_BUILD_COMMANDS
        ):
            raise ReleaseError("compiler is visible in qualification PATH")
        version_result = _run(
            [str(cigar), "--output", "json", "version"],
            workspace,
            environment,
            protected_roots=protected_roots,
        )
        version_output = load_json_bytes(
            version_result.stdout, "installed cigar version"
        )
        if version_output != {
            "version": arguments.expected_version,
            "source_revision": source["revision"],
            "context_abi": arguments.expected_abi,
            "protocol_min": "1.0",
            "protocol_max": "1.x",
            "build_profile": "release",
            "enabled_features": [],
        }:
            raise ReleaseError(
                "installed cigar reports a stale or malformed build identity"
            )
        _run(
            [str(cigar), "help"],
            workspace,
            environment,
            protected_roots=protected_roots,
        )
        qualification_checks = {"version", "help"}
        if mcp := binaries.get("cigar-mcp"):
            mcp_probe = load_json_bytes(
                _run(
                    [str(mcp), "schema-noop"],
                    workspace,
                    environment,
                    protected_roots=protected_roots,
                ).stdout,
                "installed cigar-mcp schema probe",
            )
            if mcp_probe != {
                "status": "ok",
                "protocol_version": "2025-06-18",
                "build": version_output,
            }:
                raise ReleaseError("installed cigar-mcp schema probe is malformed")
            qualification_checks.add("mcp-schema")
        if hook := binaries.get("cigar-claude-hook"):
            hook_probe = load_json_bytes(
                _run(
                    [str(hook), "schema-noop"],
                    workspace,
                    environment,
                    protected_roots=protected_roots,
                ).stdout,
                "installed cigar-claude-hook schema probe",
            )
            if hook_probe != {
                "schema_version": "cigar.claude-hook-event.v1",
                "ok": True,
                "maximum_input_bytes": 65_536,
                "model_calls": 0,
                "effect_precheck": "fail_closed",
            }:
                raise ReleaseError(
                    "installed cigar-claude-hook schema probe is malformed"
                )
            qualification_checks.add("claude-hook-schema")

        readonly = base / "read-only-parent"
        readonly.mkdir()
        os.chmod(readonly, 0o555)
        try:
            _run(
                [str(cigar), "version"],
                readonly,
                environment,
                protected_roots=protected_roots,
            )
        finally:
            # This content-free directory remains beneath a 0700 temporary ancestor; restoring
            # traversal is required only so deterministic cleanup can remove it.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                readonly,
                0o755,
            )

        driver_result = _run_qualification_driver(
            [
                str(staged_driver),
                "--cigar",
                str(cigar),
                "--cigard",
                str(cigard),
                "--workspace",
                str(workspace),
                "--artifact-id",
                arguments.expected_artifact_id,
                "--artifact-sha256",
                original_digest,
                "--product-version",
                arguments.expected_version,
                "--context-abi",
                arguments.expected_abi,
                "--source-revision",
                source["revision"],
                "--sandbox-root",
                str(base),
                "--candidate-input-root",
                str(staged_directory),
            ],
            workspace,
            environment,
        )
        driver_receipt, driver_checks = _validate_driver_receipt(
            driver_result.stdout,
            arguments.expected_artifact_id,
            original_digest,
            arguments.expected_version,
            arguments.expected_abi,
            source["revision"],
        )
        installed_workflow = driver_receipt["installed_workflow"]
        if (
            installed_workflow["cigar_sha256"] != binary_digests["cigar"]
            or installed_workflow["cigard_sha256"] != binary_digests["cigard"]
        ):
            raise ReleaseError(
                "installed workflow receipt is not bound to the extracted runtime bytes"
            )
        if (
            sha256_file(staged_archive) != original_digest
            or sha256_file(staged_contract) != contract_digest
            or sha256_file(staged_runtime_build_receipt) != runtime_build_receipt_digest
            or sha256_file(staged_tool_archive) != tool_archive_digest
            or sha256_file(staged_tool_contract) != tool_contract_digest
            or sha256_file(staged_tool_build_receipt) != tool_build_receipt_digest
            or sha256_file(staged_runner) != runner_digest
            or sha256_file(staged_driver) != driver_digest
            or any(
                sha256_file(path) != binary_digests[name]
                for name, path in binaries.items()
            )
        ):
            raise ReleaseError(
                "candidate, qualification tool, or installed binary changed during qualification"
            )

        shutil.rmtree(install)
        uninstalled = not install.exists()
        retained = marker.read_text(encoding="utf-8") == "retain\n"
        if not uninstalled or not retained:
            raise ReleaseError(
                "uninstall removed retained state or left installed files"
            )
        report = {
            "schema_version": "cigar.install-qualification.v1",
            "status": "passed",
            "artifact_id": arguments.expected_artifact_id,
            "artifact_sha256": original_digest,
            "artifact_bytes": original_size,
            "product_version": arguments.expected_version,
            "context_abi": arguments.expected_abi,
            "source_revision": source["revision"],
            "target": target,
            "runtime_build_receipt": {
                "schema_version": RUNTIME_BUILD_RECEIPT_SCHEMA,
                "status": "built-unqualified",
                "sha256": runtime_build_receipt_digest,
                "bytes": runtime_build_receipt_size,
            },
            "qualification_tool": {
                "artifact_id": QUALIFICATION_TOOL_ARTIFACT_ID,
                "archive_sha256": tool_archive_digest,
                "archive_bytes": tool_archive_size,
                "contract_id": QUALIFICATION_TOOL_CONTRACT_ID,
                "contract_sha256": tool_contract_digest,
                "source_revision": source["revision"],
                "build_receipt_schema_version": (
                    QUALIFICATION_TOOL_BUILD_RECEIPT_SCHEMA
                ),
                "build_receipt_status": "built-unqualified",
                "build_receipt_sha256": tool_build_receipt_digest,
                "build_receipt_bytes": tool_build_receipt_size,
                "runner_path": "bin/cigar-conformance",
                "runner_sha256": runner_digest,
                "driver_path": "bin/cigar-install-qualifier",
                "driver_sha256": driver_digest,
            },
            "build_receipt_authentication": BUILD_RECEIPT_AUTHENTICATION,
            "driver_receipt_sha256": sha256_bytes(driver_result.stdout),
            "installed_binary_sha256": binary_digests,
            "installed_workflow": installed_workflow,
            "unprivileged": True,
            "non_admin": True,
            "no_compiler_path": True,
            "no_egress": True,
            "no_egress_enforcement": no_egress_enforcement,
            "process_enforcement": MACOS_PROCESS_ENFORCEMENT,
            "path_cases": [
                "spaces",
                "unicode",
                "long",
                "read-only-parent",
                "non-admin",
            ],
            "checks": sorted({*qualification_checks, *driver_checks}),
            "uninstalled": uninstalled,
            "state_retained": retained,
            "package_contract_sha256": verification["contract"]["sha256"],
        }
        _validate_report(report)
    return report


def main() -> int:
    arguments = parse_arguments()
    report_output = _ReportOutput.open(arguments)
    try:
        report = _qualify(arguments)
        if report_output is not None:
            report_output.publish(report)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        if report_output is not None:
            report_output.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EvidenceWorkspaceError,
        OSError,
        subprocess.TimeoutExpired,
        ReleaseError,
    ) as error:
        raise SystemExit(f"install qualification failed: {error}") from error
