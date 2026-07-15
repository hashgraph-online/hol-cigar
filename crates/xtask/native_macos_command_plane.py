#!/usr/bin/env python3
"""Run the external-input native macOS xtask gates without ambient fallback.

The PRD command spellings deliberately do not carry evaluator keys, release
trust roots, signer handles, or producer workspaces.  This adapter accepts one
canonical, owner-protected, single-route authority document through
``CIGAR_XTASK_COMMAND_INPUTS``.  It delegates to the existing benchmark,
package, sanitizer, supply-chain, signing, provenance, and offline-verification
tools.  The authority's contents and paths never enter retained command
evidence; only its byte count and SHA-256 bind the content-free raw result.

This file never runs fuzzing, soak tests, mutation campaigns, the 100-GiB scale
workload, or release signing on its own.  A signing invocation is possible only
for the exact ``release-sign`` route with an explicit protected authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
if str(RELEASE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(RELEASE_SCRIPTS))

from evidence_workspace import (  # noqa: E402
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    canonical_json_bytes,
    safe_relative_path,
)
from release_lib import ReleaseError, load_json_bytes, run_bounded  # noqa: E402
from signatures import public_key_id as release_public_key_id  # noqa: E402


SCHEMA = "cigar.xtask-native-macos-command-inputs.v1"
RAW_SCHEMA = "cigar.xtask-native-macos-command-raw.v1"
SELECTOR = "CIGAR_XTASK_COMMAND_INPUTS"
SELECTOR_SHA256 = "CIGAR_XTASK_COMMAND_INPUTS_SHA256"
MAX_AUTHORITY_BYTES = 256 * 1024
MAX_TOOL_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RUNTIME_BYTES = 128 * 1024 * 1024
REQUIRED_PYTHON_VERSION = "3.14.6"
MAX_PRODUCER_SOURCE_BYTES = 16 * 1024 * 1024
PRODUCER_CLOSURE = (
    "crates/xtask/native_macos_command_plane.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/release_lib.py",
    "scripts/release/signatures.py",
)
MAX_TREE_FILES = 100_000
MAX_TREE_BYTES = 4 * 1024 * 1024 * 1024
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
SIGNATURE_PURPOSE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
PERFORMANCE_REPORT_KEYS = {
    "schema_version",
    "report_id",
    "report_type",
    "decision",
    "reasons",
    "thresholds",
    "candidate",
    "baseline",
    "comparisons",
}
SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
ROUTES = frozenset(
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


class NativeCommandError(RuntimeError):
    """A native command-plane invariant failed."""


@dataclass(frozen=True)
class RuntimeSnapshot:
    path: Path
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    bytes: int
    modified_ns: int
    changed_ns: int
    sha256: str
    version: str
    version_probe: dict[str, Any]

    @property
    def binding(self) -> dict[str, Any]:
        return {
            "path": os.fspath(self.path),
            "bytes": self.bytes,
            "sha256": self.sha256,
            "authority": "operator-reviewed-sha256",
            "limitation": "transitive-runtime-files-not-bound",
            "version": self.version,
            "version_probe": dict(self.version_probe),
        }


@dataclass(frozen=True)
class ProducerFileSnapshot:
    path: Path
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    bytes: int
    modified_ns: int
    changed_ns: int
    sha256: str

    @property
    def binding(self) -> dict[str, Any]:
        return {"bytes": self.bytes, "sha256": self.sha256}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeCommandError("authority contains a duplicate JSON key")
        result[key] = value
    return result


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _snapshot_runtime(
    expected_path: object, expected_sha256: object, expected_version: object
) -> RuntimeSnapshot:
    if (
        not isinstance(expected_path, str)
        or not expected_path
        or not Path(expected_path).is_absolute()
        or os.path.normpath(expected_path) != expected_path
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in expected_path
        )
        or HEX_64.fullmatch(str(expected_sha256)) is None
        or not isinstance(expected_version, str)
        or expected_version != REQUIRED_PYTHON_VERSION
    ):
        raise NativeCommandError("reviewed Python runtime identity is invalid")
    try:
        running = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise NativeCommandError("running Python runtime is unavailable") from error
    path = Path(expected_path)
    if running != path:
        raise NativeCommandError("running Python runtime path is not operator-reviewed")
    _path_lineage(path, "reviewed Python runtime")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        named_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeCommandError("reviewed Python runtime cannot be opened") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not before.st_mode & stat.S_IXUSR
            or before.st_size <= 0
            or before.st_size > MAX_RUNTIME_BYTES
        ):
            raise NativeCommandError(
                "reviewed Python runtime is not a protected executable file"
            )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NativeCommandError(
                    "reviewed Python runtime ended before its recorded size"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NativeCommandError("reviewed Python runtime grew while inspected")
        after = os.fstat(descriptor)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise NativeCommandError("reviewed Python runtime changed while inspected")
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256:
            raise NativeCommandError(
                "reviewed Python runtime SHA-256 does not match operator authority"
            )
        try:
            probe = run_bounded(
                [os.fspath(path), "--version"],
                cwd=REPOSITORY_ROOT,
                env=_child_environment(),
                timeout=30,
                max_stdout=16 * 1024,
                max_stderr=16 * 1024,
            )
        except (OSError, ReleaseError, subprocess.SubprocessError) as error:
            raise NativeCommandError(
                "reviewed Python runtime version probe failed"
            ) from error
        stdout = probe.stdout or b""
        stderr = probe.stderr or b""
        try:
            reported_version = (
                (stdout + stderr).decode("utf-8", errors="strict").strip()
            )
        except UnicodeDecodeError as error:
            raise NativeCommandError(
                "reviewed Python runtime version output is not UTF-8"
            ) from error
        if probe.returncode != 0 or reported_version != f"Python {expected_version}":
            raise NativeCommandError(
                "reviewed Python runtime reported the wrong version"
            )
        version_probe = {
            "exit_code": probe.returncode,
            "stdout_bytes": len(stdout),
            "stdout_sha256": _sha256(stdout),
            "stderr_bytes": len(stderr),
            "stderr_sha256": _sha256(stderr),
            "version": expected_version,
        }
        final_opened = os.fstat(descriptor)
        final_named = path.lstat()
        if (
            any(
                getattr(before, field) != getattr(final_opened, field)
                for field in stable
            )
            or any(
                getattr(named_before, field) != getattr(final_named, field)
                for field in stable
            )
            or (final_opened.st_dev, final_opened.st_ino)
            != (final_named.st_dev, final_named.st_ino)
        ):
            raise NativeCommandError(
                "reviewed Python runtime changed during its version probe"
            )
        return RuntimeSnapshot(
            path=path,
            device=before.st_dev,
            inode=before.st_ino,
            mode=before.st_mode,
            owner=before.st_uid,
            links=before.st_nlink,
            bytes=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
            sha256=actual_sha256,
            version=expected_version,
            version_probe=version_probe,
        )
    finally:
        os.close(descriptor)


def _recheck_runtime(snapshot: RuntimeSnapshot) -> None:
    if (
        _snapshot_runtime(os.fspath(snapshot.path), snapshot.sha256, snapshot.version)
        != snapshot
    ):
        raise NativeCommandError(
            "reviewed Python runtime changed or was substituted during execution"
        )


def _snapshot_producer_file(relative: str) -> ProducerFileSnapshot:
    path = REPOSITORY_ROOT / relative
    if path.resolve(strict=True) != path:
        raise NativeCommandError("native adapter producer path contains an alias")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeCommandError("native adapter producer is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > MAX_PRODUCER_SOURCE_BYTES
        ):
            raise NativeCommandError(
                "native adapter producer is not a protected regular file"
            )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NativeCommandError("native adapter producer changed while read")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NativeCommandError("native adapter producer grew while read")
        after = os.fstat(descriptor)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise NativeCommandError("native adapter producer changed while read")
        return ProducerFileSnapshot(
            path=path,
            device=before.st_dev,
            inode=before.st_ino,
            mode=before.st_mode,
            owner=before.st_uid,
            links=before.st_nlink,
            bytes=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
            sha256=digest.hexdigest(),
        )
    finally:
        os.close(descriptor)


def _snapshot_producer_closure() -> dict[str, ProducerFileSnapshot]:
    return {
        relative: _snapshot_producer_file(relative) for relative in PRODUCER_CLOSURE
    }


def _recheck_producer_closure(
    expected: Mapping[str, ProducerFileSnapshot],
) -> None:
    current = _snapshot_producer_closure()
    if current != dict(expected):
        raise NativeCommandError(
            "native adapter producer closure changed or was substituted"
        )


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise NativeCommandError(f"{label} has unknown or missing fields")
    return value


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _safe_relative(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or any(character in value for character in ("\\", ":", "\x00"))
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise NativeCommandError(f"{label} must be a safe relative path")
    try:
        parts = safe_relative_path(value)
    except EvidenceWorkspaceError as error:
        raise NativeCommandError(f"{label} must be a safe relative path") from error
    rendered = "/".join(parts)
    if rendered != value.rstrip("/"):
        raise NativeCommandError(f"{label} is not a normalized relative path")
    return rendered


def _safe_direct_child(value: object, label: str) -> str:
    rendered = _safe_relative(value, label)
    if "/" in rendered:
        raise NativeCommandError(f"{label} must be a direct child name")
    return rendered


def _path_lineage(path: Path, label: str) -> tuple[tuple[object, ...], ...]:
    """Snapshot every parent used to resolve an authority-selected path.

    Owner- or root-controlled parents are required.  The only writable ancestor
    admitted is a root-owned sticky directory such as ``/private/tmp``; the
    owner-private directory below it remains the authority boundary.
    """

    records: list[tuple[object, ...]] = []
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise NativeCommandError(f"{label} parent is unavailable") from error
        mode = stat.S_IMODE(metadata.st_mode)
        writable = bool(mode & 0o022)
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or (writable and not sticky_root)
        ):
            raise NativeCommandError(f"{label} has an unprotected parent directory")
        records.append(
            (
                os.fspath(current),
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
        )
    return tuple(records)


def _canonical_absolute(value: object, label: str, *, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise NativeCommandError(f"{label} must be an absolute canonical path")
    path = Path(value)
    if (
        not path.is_absolute()
        or os.path.normpath(value) != value
        or value != os.fspath(path)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise NativeCommandError(f"{label} must be an absolute canonical path")
    if not must_exist:
        return path
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise NativeCommandError(f"{label} is unavailable") from error
    if resolved != path:
        raise NativeCommandError(f"{label} contains a symlink or path alias")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise NativeCommandError(f"{label} is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise NativeCommandError(f"{label} contains a symlink component")
    _path_lineage(path, label)
    return path


def _require_external(path: Path, label: str) -> None:
    try:
        path.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return
    raise NativeCommandError(f"{label} must be outside the source repository")


def _is_beneath(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    bytes: int
    modified_ns: int
    changed_ns: int
    sha256: str
    lineage: tuple[tuple[object, ...], ...]


def _open_file_snapshot(
    value: object,
    label: str,
    *,
    secret: bool = False,
    executable: bool = False,
    max_bytes: int = MAX_TREE_BYTES,
) -> FileSnapshot:
    path = _canonical_absolute(value, label)
    _require_external(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeCommandError(f"{label} cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        named = path.lstat()
        permitted_owners = {os.geteuid()}
        if executable:
            permitted_owners.add(0)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            or metadata.st_nlink != 1
            or metadata.st_uid not in permitted_owners
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or (secret and stat.S_IMODE(metadata.st_mode) & 0o077)
            or not metadata.st_mode & stat.S_IRUSR
            or (executable and not metadata.st_mode & stat.S_IXUSR)
            or metadata.st_size <= 0
            or metadata.st_size > max_bytes
        ):
            raise NativeCommandError(
                f"{label} is not a protected single-link regular file"
            )
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise NativeCommandError(f"{label} ended before its recorded size")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NativeCommandError(f"{label} grew while inspected")
        after = os.fstat(descriptor)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(metadata, field) != getattr(after, field) for field in stable):
            raise NativeCommandError(f"{label} changed while inspected")
        return FileSnapshot(
            path=path,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            owner=metadata.st_uid,
            links=metadata.st_nlink,
            bytes=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
            sha256=digest.hexdigest(),
            lineage=_path_lineage(path, label),
        )
    finally:
        os.close(descriptor)


def _recheck_file(snapshot: FileSnapshot, label: str) -> None:
    current = _open_file_snapshot(
        os.fspath(snapshot.path),
        label,
        secret=stat.S_IMODE(snapshot.mode) & 0o077 == 0,
        executable=bool(snapshot.mode & stat.S_IXUSR),
        max_bytes=max(snapshot.bytes, 1),
    )
    if current != snapshot:
        raise NativeCommandError(f"{label} changed or was substituted during execution")


@dataclass(frozen=True)
class DirectorySnapshot:
    path: Path
    device: int
    inode: int
    mode: int
    owner: int
    lineage: tuple[tuple[object, ...], ...] = ()


def _open_directory(
    value: object, label: str, *, empty: bool = False
) -> DirectorySnapshot:
    path = _canonical_absolute(value, label)
    _require_external(path, label)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise NativeCommandError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not metadata.st_mode & stat.S_IRUSR
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise NativeCommandError(f"{label} must be an owner-private directory")
    try:
        entries = tuple(path.iterdir())
    except OSError as error:
        raise NativeCommandError(f"{label} cannot be enumerated") from error
    if empty and entries:
        raise NativeCommandError(f"{label} must be empty")
    aliases: set[str] = set()
    for entry in entries:
        alias = _portable_key(entry.name)
        if alias in aliases:
            raise NativeCommandError(f"{label} contains a portable-name collision")
        aliases.add(alias)
    return DirectorySnapshot(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        owner=metadata.st_uid,
        lineage=_path_lineage(path, label),
    )


def _recheck_directory(snapshot: DirectorySnapshot, label: str) -> None:
    current = _open_directory(os.fspath(snapshot.path), label)
    if current != snapshot:
        raise NativeCommandError(f"{label} was rebound during execution")


def _resolve_beneath(
    directory: DirectorySnapshot, relative: object, label: str
) -> Path:
    normalized = _safe_relative(relative, label)
    candidate = directory.path.joinpath(*normalized.split("/"))
    selected = _canonical_absolute(os.fspath(candidate), label)
    try:
        selected.relative_to(directory.path)
    except ValueError as error:
        raise NativeCommandError(
            f"{label} escapes its external artifact root"
        ) from error
    return selected


def _tree_fingerprint(directory: DirectorySnapshot, label: str) -> dict[str, Any]:
    records: list[bytes] = []
    file_count = 0
    total_bytes = 0
    pending = [directory.path]
    while pending:
        parent = pending.pop()
        try:
            entries = sorted(
                parent.iterdir(), key=lambda item: item.name.encode("utf-8")
            )
        except (OSError, UnicodeError) as error:
            raise NativeCommandError(f"{label} cannot be enumerated safely") from error
        aliases: set[str] = set()
        for entry in entries:
            alias = _portable_key(entry.name)
            if alias in aliases:
                raise NativeCommandError(f"{label} contains a portable-name collision")
            aliases.add(alias)
            relative = entry.relative_to(directory.path).as_posix()
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise NativeCommandError(f"{label} contains a symlink")
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise NativeCommandError(f"{label} contains an unprotected entry")
            if stat.S_ISDIR(metadata.st_mode):
                records.append(
                    canonical_json_bytes(
                        [relative, "directory", stat.S_IMODE(metadata.st_mode)]
                    )
                )
                pending.append(entry)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise NativeCommandError(
                    f"{label} contains a non-regular or linked entry"
                )
            snapshot = _open_file_snapshot(os.fspath(entry), f"{label} input")
            file_count += 1
            total_bytes += snapshot.bytes
            if file_count > MAX_TREE_FILES or total_bytes > MAX_TREE_BYTES:
                raise NativeCommandError(f"{label} exceeds the bounded tree inventory")
            records.append(
                canonical_json_bytes(
                    [
                        relative,
                        "file",
                        stat.S_IMODE(snapshot.mode),
                        snapshot.bytes,
                        snapshot.sha256,
                    ]
                )
            )
    digest = hashlib.sha256()
    for record in sorted(records):
        digest.update(record)
    return {
        "file_count": file_count,
        "bytes": total_bytes,
        "sha256": digest.hexdigest(),
    }


def _tree_inventory(
    directory: DirectorySnapshot, label: str
) -> dict[str, tuple[object, ...]]:
    inventory: dict[str, tuple[object, ...]] = {}
    file_count = 0
    total_bytes = 0
    pending = [directory.path]
    while pending:
        parent = pending.pop()
        try:
            entries = sorted(
                parent.iterdir(), key=lambda item: item.name.encode("utf-8")
            )
        except (OSError, UnicodeError) as error:
            raise NativeCommandError(f"{label} cannot be inventoried safely") from error
        aliases: set[str] = set()
        for entry in entries:
            alias = _portable_key(entry.name)
            if alias in aliases:
                raise NativeCommandError(f"{label} contains a portable-name collision")
            aliases.add(alias)
            relative = entry.relative_to(directory.path).as_posix()
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise NativeCommandError(f"{label} contains a symlink")
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise NativeCommandError(f"{label} contains an unprotected entry")
            if stat.S_ISDIR(metadata.st_mode):
                inventory[relative] = ("directory", stat.S_IMODE(metadata.st_mode))
                pending.append(entry)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise NativeCommandError(
                    f"{label} contains a non-regular or linked entry"
                )
            snapshot = _open_file_snapshot(os.fspath(entry), f"{label} input")
            file_count += 1
            total_bytes += snapshot.bytes
            if file_count > MAX_TREE_FILES or total_bytes > MAX_TREE_BYTES:
                raise NativeCommandError(f"{label} exceeds the bounded tree inventory")
            inventory[relative] = (
                "file",
                stat.S_IMODE(snapshot.mode),
                snapshot.bytes,
                snapshot.sha256,
            )
    return inventory


def _require_tree_delta(
    before: Mapping[str, tuple[object, ...]],
    after: Mapping[str, tuple[object, ...]],
    additions: set[str],
    label: str,
) -> None:
    changed = {path for path, record in before.items() if after.get(path) != record}
    removed = set(before) - set(after)
    added = set(after) - set(before)
    if changed or removed or added != additions:
        raise NativeCommandError(
            f"{label} changed outside its exact create-new output inventory"
        )


def _integer(
    value: object, label: str, *, minimum: int = 0, maximum: int = 4_294_967_295
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise NativeCommandError(f"{label} is outside its permitted integer range")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise NativeCommandError(f"{label} is not a bounded identifier")
    return value


def _bounded_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise NativeCommandError(f"{label} is invalid")
    return value


@dataclass
class Authority:
    path: FileSnapshot
    route: str
    source: dict[str, Any]
    inputs: dict[str, Any]
    files: dict[str, FileSnapshot]
    directories: dict[str, DirectorySnapshot]
    trees: dict[str, dict[str, Any]]

    @property
    def binding(self) -> dict[str, Any]:
        return {"bytes": self.path.bytes, "sha256": self.path.sha256}

    def recheck(self) -> None:
        _recheck_file(self.path, "command input authority")
        for label, snapshot in self.files.items():
            _recheck_file(snapshot, label)
        for label, snapshot in self.directories.items():
            _recheck_directory(snapshot, label)
        for label, expected in self.trees.items():
            if _tree_fingerprint(self.directories[label], label) != expected:
                raise NativeCommandError(
                    f"{label} contents changed or were substituted during execution"
                )


def _validate_source(value: object, expected: Mapping[str, Any]) -> dict[str, Any]:
    keys = {
        "kind",
        "revision",
        "tree",
        "committed",
        "clean",
        "status_entry_count",
        "status_sha256",
    }
    source = _exact_object(value, keys, "authority source binding")
    if (
        source.get("kind") != "git"
        or HEX_40.fullmatch(str(source.get("revision"))) is None
        or HEX_40.fullmatch(str(source.get("tree"))) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
        or source.get("status_entry_count") != 0
        or source.get("status_sha256") != hashlib.sha256(b"").hexdigest()
        or source != dict(expected)
    ):
        raise NativeCommandError("authority is not bound to the exact clean source")
    return source


MICRO_FILES = {
    "candidate_manifest": False,
    "candidate_samples": False,
    "candidate_attestation": False,
    "candidate_attestation_key_file": True,
    "baseline_manifest": False,
    "baseline_samples": False,
    "baseline_attestation": False,
    "baseline_attestation_key_file": True,
    "comparison_report": False,
}


def _register_files(
    inputs: Mapping[str, Any],
    specification: Mapping[str, bool],
    files: dict[str, FileSnapshot],
) -> None:
    for field, secret in specification.items():
        files[field] = _open_file_snapshot(
            inputs[field],
            field.replace("_", " "),
            secret=secret,
            max_bytes=1024 * 1024 if secret else MAX_TREE_BYTES,
        )


def _require_independent_benchmark_evidence(files: Mapping[str, FileSnapshot]) -> None:
    for candidate, baseline in (
        ("candidate_manifest", "baseline_manifest"),
        ("candidate_samples", "baseline_samples"),
        ("candidate_attestation", "baseline_attestation"),
    ):
        left = files[candidate]
        right = files[baseline]
        if (left.device, left.inode) == (
            right.device,
            right.inode,
        ) or left.sha256 == right.sha256:
            raise NativeCommandError(
                "candidate and baseline benchmark evidence are not independent"
            )


def _load_authority(route: str, expected_source: Mapping[str, Any]) -> Authority:
    if route == "test-sanitizers":
        raise NativeCommandError("sanitizer route does not accept an input authority")
    selected = os.environ.get(SELECTOR)
    expected_authority_sha256 = os.environ.get(SELECTOR_SHA256)
    if not selected or HEX_64.fullmatch(str(expected_authority_sha256)) is None:
        raise NativeCommandError("required native command inputs are unavailable")
    path = _open_file_snapshot(
        selected,
        "command input authority",
        secret=True,
        max_bytes=MAX_AUTHORITY_BYTES,
    )
    if path.bytes > MAX_AUTHORITY_BYTES:
        raise NativeCommandError("command input authority exceeds the size bound")
    payload = path.path.read_bytes()
    if len(payload) != path.bytes or _sha256(payload) != path.sha256:
        raise NativeCommandError("command input authority changed while it was read")
    if path.sha256 != expected_authority_sha256:
        raise NativeCommandError(
            "command input authority differs from the operator-reviewed digest"
        )
    _recheck_file(path, "command input authority")
    if any(marker in payload for marker in SECRET_MARKERS):
        raise NativeCommandError("command input authority embeds secret key bytes")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise NativeCommandError(
            "command input authority is not strict JSON"
        ) from error
    if payload != canonical_json_bytes(document):
        raise NativeCommandError("command input authority must be canonical JSON")
    authority = _exact_object(
        document,
        {"schema_version", "route", "source", "inputs"},
        "command input authority",
    )
    selected_route = authority.get("route")
    if authority.get("schema_version") != SCHEMA or selected_route not in ROUTES:
        raise NativeCommandError(
            "command input authority has an unsupported identity or route"
        )
    if selected_route != route:
        raise NativeCommandError("command input authority is for another route")
    source = _validate_source(authority.get("source"), expected_source)
    inputs = authority.get("inputs")
    if not isinstance(inputs, dict):
        raise NativeCommandError("command input authority inputs must be an object")
    files: dict[str, FileSnapshot] = {}
    directories: dict[str, DirectorySnapshot] = {}
    tree_labels: set[str] = set()

    if route == "bench-micro-verify":
        _exact_object(inputs, set(MICRO_FILES), "microbenchmark inputs")
        _register_files(inputs, MICRO_FILES, files)
        _require_independent_benchmark_evidence(files)
    elif route == "bench-macro-verify":
        extra = {
            "local_scale_driver": False,
            "local_scale_profile": False,
            "local_scale_binding": False,
            "local_scale_receipt": False,
        }
        _exact_object(inputs, set(MICRO_FILES) | set(extra), "macrobenchmark inputs")
        _register_files(inputs, MICRO_FILES, files)
        _require_independent_benchmark_evidence(files)
        files["local_scale_driver"] = _open_file_snapshot(
            inputs["local_scale_driver"], "local scale driver", executable=True
        )
        _register_files(
            inputs, {key: False for key in extra if key != "local_scale_driver"}, files
        )
    elif route == "bench-efficacy":
        keys = {
            "evidence_root",
            "environment",
            "seed_file",
            "attestation_key_file",
            "matrix_report",
        }
        _exact_object(inputs, keys, "efficacy inputs")
        directories["evidence_root"] = _open_directory(
            inputs["evidence_root"], "efficacy evidence root"
        )
        tree_labels.add("evidence_root")
        _register_files(
            inputs,
            {
                "environment": False,
                "seed_file": True,
                "attestation_key_file": True,
                "matrix_report": False,
            },
            files,
        )
    elif route == "package-all":
        workspace_fields = {
            "portable_workspace",
            "native_workspace",
            "conformance_workspace",
            "cigarbench_workspace",
            "homebrew_workspace",
            "typescript_workspace",
            "rust_workspace",
            "python_workspace",
            "go_workspace",
            "claude_workspace",
        }
        tool_fields = {
            "cargo",
            "rustc",
            "protoc",
            "cargo_local_registry",
            "node",
            "pnpm",
            "npm",
            "uv",
            "python",
            "go",
        }
        dependency_fields = {
            "cargo_cache",
            "rustup_home",
            "uv_cache_dir",
            "go_dependency_proxy",
        }
        _exact_object(
            inputs,
            workspace_fields
            | tool_fields
            | dependency_fields
            | {"output_root", "source_date_epoch"},
            "package-all inputs",
        )
        _integer(inputs["source_date_epoch"], "source date epoch")
        for field in sorted(workspace_fields):
            directories[field] = _open_directory(
                inputs[field], field.replace("_", " "), empty=True
            )
        for field in sorted(dependency_fields):
            directories[field] = _open_directory(inputs[field], field.replace("_", " "))
            tree_labels.add(field)
        for field in sorted(tool_fields):
            files[field] = _open_file_snapshot(
                inputs[field], field.replace("_", " "), executable=True
            )
        directories["output_root"] = _open_directory(
            inputs["output_root"], "package output root", empty=True
        )
    elif route == "package-smoke":
        keys = {
            "artifact_root",
            "runtime_build_receipt",
            "qualification_tool_build_receipt",
            "install_evidence_root",
        }
        _exact_object(inputs, keys, "package-smoke inputs")
        directories["artifact_root"] = _open_directory(
            inputs["artifact_root"], "artifact root"
        )
        tree_labels.add("artifact_root")
        directories["install_evidence_root"] = _open_directory(
            inputs["install_evidence_root"], "install evidence root", empty=True
        )
        _register_files(
            inputs,
            {"runtime_build_receipt": False, "qualification_tool_build_receipt": False},
            files,
        )
    elif route in {"release-sbom", "release-attest"}:
        common = {
            "artifact_root",
            "artifact_directory",
            "source_date_epoch",
            "output_path",
        }
        extra = set()
        if route == "release-attest":
            extra = {
                "builder_id",
                "workflow_id",
                "network_mode",
                "commands",
                "materials",
            }
        _exact_object(inputs, common | extra, f"{route} inputs")
        directories["artifact_root"] = _open_directory(
            inputs["artifact_root"], "artifact root"
        )
        _safe_relative(inputs["artifact_directory"], "artifact directory")
        output_path = _safe_direct_child(inputs["output_path"], "release output path")
        if route == "release-sbom" and output_path != "sbom":
            raise NativeCommandError(
                "SBOM output path must be the fixed sbom directory"
            )
        if route == "release-attest" and output_path != "provenance.json":
            raise NativeCommandError(
                "provenance output path must be the fixed provenance.json sidecar"
            )
        _integer(inputs["source_date_epoch"], "source date epoch")
        if route == "release-attest":
            _bounded_text(inputs["builder_id"], "builder id", maximum=512)
            _bounded_text(inputs["workflow_id"], "workflow id", maximum=512)
            if inputs["network_mode"] != "disabled":
                raise NativeCommandError(
                    "release attestation requires enforced disabled-network mode"
                )
            commands = inputs["commands"]
            if not isinstance(commands, list) or not commands or len(commands) > 256:
                raise NativeCommandError(
                    "release attestation command inventory is invalid"
                )
            for command in commands:
                command = _exact_object(
                    command,
                    {"tool_id", "argv_sha256"},
                    "release attestation command descriptor",
                )
                _identifier(command["tool_id"], "attested command tool id")
                if HEX_64.fullmatch(str(command["argv_sha256"])) is None:
                    raise NativeCommandError(
                        "attested command argument digest is invalid"
                    )
            materials = inputs["materials"]
            if not isinstance(materials, list) or len(materials) > 1024:
                raise NativeCommandError(
                    "release attestation material inventory is invalid"
                )
            for index, material in enumerate(materials):
                files[f"material-{index}"] = _open_file_snapshot(
                    material, "release material"
                )
    elif route == "release-sign":
        keys = {
            "artifact_root",
            "artifact_directory",
            "private_key_file",
            "public_key_file",
            "trust_policy",
            "signer_principal",
            "openssl",
            "openssl_sha256",
            "signed_at",
            "expires_at",
            "signature_directory",
            "evidence_directory",
            "signing_phase",
            "payloads",
        }
        _exact_object(inputs, keys, "release-sign inputs")
        directories["artifact_root"] = _open_directory(
            inputs["artifact_root"], "artifact root"
        )
        _safe_relative(inputs["artifact_directory"], "artifact directory")
        signature_directory = _safe_direct_child(
            inputs["signature_directory"], "signature directory"
        )
        if signature_directory != "signatures":
            raise NativeCommandError(
                "signature output path must be the fixed signatures directory"
            )
        evidence_relative = _safe_relative(
            inputs["evidence_directory"], "qualification evidence directory"
        )
        if inputs["signing_phase"] != "supporting":
            raise NativeCommandError(
                "release signing currently supports only the explicit supporting phase"
            )
        files["private_key_file"] = _open_file_snapshot(
            inputs["private_key_file"],
            "private signing key",
            secret=True,
            max_bytes=1024 * 1024,
        )
        files["public_key_file"] = _open_file_snapshot(
            inputs["public_key_file"], "public signing key", max_bytes=1024 * 1024
        )
        files["trust_policy"] = _open_file_snapshot(
            inputs["trust_policy"], "signing trust policy", max_bytes=16 * 1024 * 1024
        )
        files["openssl"] = _open_file_snapshot(
            inputs["openssl"], "reviewed OpenSSL", executable=True
        )
        if inputs["openssl_sha256"] != files["openssl"].sha256:
            raise NativeCommandError(
                "reviewed OpenSSL digest does not match its authority"
            )
        _bounded_text(inputs["signer_principal"], "signer principal", maximum=256)
        _integer(inputs["signed_at"], "signing time", maximum=253_402_300_799)
        if inputs["expires_at"] is not None:
            expires = _integer(
                inputs["expires_at"], "signature expiry", maximum=253_402_300_799
            )
            if expires <= inputs["signed_at"]:
                raise NativeCommandError("signature expiry must follow signing time")
        payloads = inputs["payloads"]
        if not isinstance(payloads, list) or not payloads or len(payloads) > 4096:
            raise NativeCommandError("release signature payload inventory is invalid")
        seen_paths: set[str] = set()
        aliases: set[str] = set()
        envelope_names: set[str] = set()
        for item in payloads:
            item = _exact_object(item, {"path", "purpose"}, "signature payload")
            relative = _safe_relative(item["path"], "signature payload path")
            alias = _portable_key(relative)
            if relative in seen_paths or alias in aliases:
                raise NativeCommandError(
                    "release signature payload inventory contains an alias or duplicate"
                )
            seen_paths.add(relative)
            aliases.add(alias)
            purpose = item["purpose"]
            if (
                not isinstance(purpose, str)
                or SIGNATURE_PURPOSE.fullmatch(purpose) is None
            ):
                raise NativeCommandError("signature purpose is invalid")
        dist = _resolve_beneath(
            directories["artifact_root"],
            inputs["artifact_directory"],
            "release candidate directory",
        )
        directories["signing_evidence"] = _open_directory(
            os.fspath(dist.joinpath(*evidence_relative.split("/"))),
            "qualification evidence directory",
        )
        tree_labels.add("signing_evidence")
        for index, item in enumerate(payloads):
            relative = _safe_relative(item["path"], "signature payload path")
            files[f"signature-payload-{index}"] = _open_file_snapshot(
                os.fspath(dist.joinpath(*relative.split("/"))),
                "signature payload",
            )
            envelope_name = f"{files[f'signature-payload-{index}'].sha256}.{item['purpose']}.sig.json"
            alias = _portable_key(envelope_name)
            if alias in envelope_names:
                raise NativeCommandError(
                    "signature payloads collide at their detached-envelope output"
                )
            envelope_names.add(alias)
    elif route == "release-verify":
        keys = {
            "artifact_root",
            "trust_policy",
            "openssl",
            "openssl_sha256",
            "verification_time",
            "verification_evidence_root",
        }
        _exact_object(inputs, keys, "release-verify inputs")
        directories["artifact_root"] = _open_directory(
            inputs["artifact_root"], "artifact root"
        )
        tree_labels.add("artifact_root")
        directories["verification_evidence_root"] = _open_directory(
            inputs["verification_evidence_root"],
            "verification evidence root",
            empty=True,
        )
        files["trust_policy"] = _open_file_snapshot(
            inputs["trust_policy"], "offline trust policy", max_bytes=16 * 1024 * 1024
        )
        files["openssl"] = _open_file_snapshot(
            inputs["openssl"], "reviewed offline OpenSSL", executable=True
        )
        if inputs["openssl_sha256"] != files["openssl"].sha256:
            raise NativeCommandError(
                "reviewed offline OpenSSL digest does not match its authority"
            )
        _integer(
            inputs["verification_time"], "verification time", maximum=253_402_300_799
        )
    else:
        raise NativeCommandError("native route has no authority schema")

    for label, directory in directories.items():
        if _is_beneath(path.path, directory.path):
            raise NativeCommandError(
                f"command input authority overlaps mutable directory role {label}"
            )
    if route == "release-sign":
        artifact_root = directories["artifact_root"].path
        for label in (
            "private_key_file",
            "public_key_file",
            "trust_policy",
            "openssl",
        ):
            if _is_beneath(files[label].path, artifact_root):
                raise NativeCommandError(
                    "release signer key or tool material overlaps the candidate root"
                )
    if route == "release-verify":
        artifact_root = directories["artifact_root"].path
        for label in ("trust_policy", "openssl"):
            if _is_beneath(files[label].path, artifact_root):
                raise NativeCommandError(
                    "offline trust or verifier material overlaps the candidate root"
                )

    all_paths = [os.fspath(item.path) for item in files.values()] + [
        os.fspath(item.path) for item in directories.values()
    ]
    canonical_aliases: dict[str, str] = {}
    for value in all_paths:
        alias = _portable_key(value)
        previous = canonical_aliases.get(alias)
        if previous is not None and previous != value:
            raise NativeCommandError(
                "authority references a case or Unicode path alias"
            )
        canonical_aliases[alias] = value
    directory_identities: dict[tuple[int, int], str] = {}
    for label, snapshot in directories.items():
        identity = (snapshot.device, snapshot.inode)
        previous = directory_identities.get(identity)
        if previous is not None:
            raise NativeCommandError(
                f"authority directory roles {previous} and {label} alias one location"
            )
        directory_identities[identity] = label
    trees = {
        label: _tree_fingerprint(directories[label], label)
        for label in sorted(tree_labels)
    }
    result = Authority(
        path=path,
        route=route,
        source=source,
        inputs=dict(inputs),
        files=files,
        directories=directories,
        trees=trees,
    )
    result.recheck()
    return result


@dataclass(frozen=True)
class Execution:
    tool: str
    exit_code: int
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str
    command_sha256: str = hashlib.sha256(b"").hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "exit_code": self.exit_code,
            "stdout": {"bytes": self.stdout_bytes, "sha256": self.stdout_sha256},
            "stderr": {"bytes": self.stderr_bytes, "sha256": self.stderr_sha256},
            "command_sha256": self.command_sha256,
        }


def _child_environment(*, source_date_epoch: int | None = None) -> dict[str, str]:
    """Construct a closed child environment; never inherit ambient authority."""

    empty_home = Path("/private/var/empty")
    if not empty_home.is_dir():
        empty_home = Path("/")
    environment = {
        "HOME": os.fspath(empty_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": SYSTEM_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": "/private/tmp",
        "TZ": "UTC",
    }
    if source_date_epoch is not None:
        environment["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    return environment


def _package_environment(authority: Authority, epoch: int) -> dict[str, str]:
    environment = _child_environment(source_date_epoch=epoch)
    environment.update(
        {
            "CARGO_HOME": os.fspath(authority.directories["cargo_cache"].path),
            "RUSTUP_HOME": os.fspath(authority.directories["rustup_home"].path),
        }
    )
    return environment


def _sanitizer_environment() -> dict[str, str]:
    """Expose only the system-account Rust launcher location to the public gate.

    The sanitizer driver independently binds the launcher, toolchain binaries,
    native runtimes, and receipt to exact digests before it executes a case.
    """

    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as error:
        raise NativeCommandError("sanitizer account home is unavailable") from error
    environment = _child_environment()
    environment["HOME"] = os.fspath(account_home)
    environment["PATH"] = os.pathsep.join(
        (os.fspath(account_home / ".cargo/bin"), SYSTEM_PATH)
    )
    return environment


Runner = Callable[
    [str, Sequence[str], int, Optional[Mapping[str, str]]], tuple[Execution, bytes]
]


def _run_tool(
    tool: str,
    command: Sequence[str],
    timeout: int,
    environment: Mapping[str, str] | None = None,
) -> tuple[Execution, bytes]:
    try:
        result = run_bounded(
            list(command),
            cwd=REPOSITORY_ROOT,
            env=dict(environment or _child_environment()),
            timeout=timeout,
            max_stdout=MAX_TOOL_OUTPUT_BYTES,
            max_stderr=MAX_TOOL_OUTPUT_BYTES,
        )
    except (OSError, ReleaseError, subprocess.SubprocessError) as error:
        raise NativeCommandError(f"{tool} could not complete") from error
    stdout = result.stdout or b""
    stderr = result.stderr or b""
    execution = Execution(
        tool=tool,
        exit_code=result.returncode,
        stdout_bytes=len(stdout),
        stdout_sha256=_sha256(stdout),
        stderr_bytes=len(stderr),
        stderr_sha256=_sha256(stderr),
        command_sha256=_sha256(canonical_json_bytes(list(command))),
    )
    if result.returncode != 0:
        raise NativeCommandError(f"{tool} reported a blocked or failing gate")
    return execution, stdout


def _python() -> str:
    return os.fspath(Path(sys.executable).resolve(strict=True))


def _load_canonical_json(path: Path, label: str) -> dict[str, Any]:
    snapshot = _open_file_snapshot(os.fspath(path), label)
    payload = snapshot.path.read_bytes()
    if len(payload) != snapshot.bytes or _sha256(payload) != snapshot.sha256:
        raise NativeCommandError(f"{label} changed while it was read")
    _recheck_file(snapshot, label)
    try:
        document = load_json_bytes(payload, label)
    except Exception as error:
        raise NativeCommandError(f"{label} is not strict JSON") from error
    if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
        raise NativeCommandError(f"{label} is not a canonical JSON object")
    return document


def _performance_replay(authority: Authority, runner: Runner) -> list[Execution]:
    command = [
        _python(),
        "benches/cigarbench/performance.py",
        "replay",
        "--report",
        os.fspath(authority.files["comparison_report"].path),
        "--candidate-manifest",
        os.fspath(authority.files["candidate_manifest"].path),
        "--candidate-samples",
        os.fspath(authority.files["candidate_samples"].path),
        "--candidate-attestation",
        os.fspath(authority.files["candidate_attestation"].path),
        "--candidate-attestation-key-file",
        os.fspath(authority.files["candidate_attestation_key_file"].path),
        "--baseline-manifest",
        os.fspath(authority.files["baseline_manifest"].path),
        "--baseline-samples",
        os.fspath(authority.files["baseline_samples"].path),
        "--baseline-attestation",
        os.fspath(authority.files["baseline_attestation"].path),
        "--baseline-attestation-key-file",
        os.fspath(authority.files["baseline_attestation_key_file"].path),
    ]
    execution, _ = runner(
        "qualified performance replay", command, 2 * 60 * 60, _child_environment()
    )
    report = _load_canonical_json(
        authority.files["comparison_report"].path, "performance comparison report"
    )
    if (
        set(report) != PERFORMANCE_REPORT_KEYS
        or report.get("schema_version") != "cigar.performance-report.v1"
        or report.get("report_type") != "comparison"
        or report.get("decision") != "pass"
    ):
        raise NativeCommandError("performance comparison is not passing")
    return [execution]


def _load_release_build(
    dist: Path,
    *,
    require_release: bool,
    expected_source: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, FileSnapshot]]:
    manifest = _load_canonical_json(
        dist / "release-build.json", "release build manifest"
    )
    expected_schema = (
        "cigar.release-build.v1" if require_release else "cigar.local-archive-build.v1"
    )
    if manifest.get("schema_version") != expected_schema:
        raise NativeCommandError(
            "artifact directory has the wrong build-manifest lifecycle"
        )
    if set(manifest) != {
        "schema_version",
        "product_version",
        "context_abi",
        "source_date_epoch",
        "source",
        "artifacts",
    }:
        raise NativeCommandError("release build manifest has an unexpected shape")
    source = manifest.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree_sha256", "committed", "clean"}
        or source.get("revision") != expected_source.get("revision")
        or HEX_64.fullmatch(str(source.get("tree_sha256"))) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        raise NativeCommandError(
            "artifact directory is not bound to the exact current clean source"
        )
    _bounded_text(manifest.get("product_version"), "product version", maximum=128)
    if manifest.get("context_abi") != "cigar.context.v1":
        raise NativeCommandError("release build manifest has the wrong context ABI")
    _integer(manifest.get("source_date_epoch"), "release source date epoch")
    artifacts = manifest.get("artifacts")
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or not all(isinstance(item, dict) for item in artifacts)
    ):
        raise NativeCommandError("release build artifact inventory is missing")
    ids: set[str] = set()
    paths: set[str] = set()
    aliases: set[str] = set()
    snapshots: dict[str, FileSnapshot] = {}
    for item in artifacts:
        if set(item) != {"id", "path", "sha256", "bytes", "contract"}:
            raise NativeCommandError(
                "release build artifact record has an unexpected shape"
            )
        identifier = _identifier(item["id"], "artifact id")
        relative = _safe_relative(item["path"], "artifact path")
        alias = _portable_key(relative)
        if (
            identifier in ids
            or relative in paths
            or alias in aliases
            or HEX_64.fullmatch(str(item["sha256"])) is None
        ):
            raise NativeCommandError(
                "release build artifact inventory has a collision or invalid digest"
            )
        _integer(item["bytes"], "artifact bytes", minimum=1, maximum=MAX_TREE_BYTES)
        ids.add(identifier)
        paths.add(relative)
        aliases.add(alias)
        snapshot = _open_file_snapshot(os.fspath(dist / relative), "release artifact")
        if snapshot.bytes != item["bytes"] or snapshot.sha256 != item["sha256"]:
            raise NativeCommandError(
                "release artifact does not match its build manifest"
            )
        snapshots[identifier] = snapshot
    source_records = [item for item in artifacts if item.get("id") == "source"]
    if (
        len(source_records) != 1
        or source_records[0].get("contract")
        != "packaging/contracts/source-archive.v1.json"
    ):
        raise NativeCommandError(
            "release build manifest lacks the exact source archive binding"
        )
    if require_release:
        expected_version, expected = _required_release_artifacts()
        actual = {
            item["id"]: (item["path"], item["contract"])
            for item in artifacts
            if isinstance(item, dict)
        }
        if manifest.get("product_version") != expected_version or actual != expected:
            raise NativeCommandError(
                "release build artifact inventory differs from the exact required matrix"
            )
    snapshots["release-build-manifest"] = _open_file_snapshot(
        os.fspath(dist / "release-build.json"), "release build manifest"
    )
    return manifest, artifacts, snapshots


def _artifact_by_id(
    artifacts: Sequence[Mapping[str, Any]], identifier: str
) -> Mapping[str, Any]:
    matches = [item for item in artifacts if item.get("id") == identifier]
    if len(matches) != 1:
        raise NativeCommandError(
            f"required artifact {identifier} is absent or duplicated"
        )
    return matches[0]


def _unique_candidate_basename(dist: Path, basename: str) -> str:
    matches = [
        path
        for path in dist.rglob(basename)
        if path.is_file() and not path.is_symlink()
    ]
    if len(matches) != 1:
        raise NativeCommandError(
            f"release candidate lacks one exact required {basename} payload"
        )
    return matches[0].relative_to(dist).as_posix()


def _require_exact_supporting_signature_set(
    authority: Authority,
    dist: Path,
    artifacts: Sequence[Mapping[str, Any]],
) -> None:
    required = {item["path"]: "release-artifact" for item in artifacts}
    required[_unique_candidate_basename(dist, "SHA256SUMS")] = "release-checksums"
    for basename in ("sbom.spdx.json", "sbom.cyclonedx.json", "sbom-artifacts.json"):
        required[_unique_candidate_basename(dist, basename)] = "release-sbom"
    required[_unique_candidate_basename(dist, "provenance.json")] = "release-provenance"
    evidence = authority.directories["signing_evidence"].path
    required_categories = {"conformance", "benchmark"}
    found_categories: set[str] = set()
    for receipt_path in sorted(evidence.glob("*.json"), key=lambda item: item.name):
        receipt = _load_canonical_json(receipt_path, "qualification evidence receipt")
        category = receipt.get("category")
        if category not in required_categories:
            continue
        if (
            set(receipt)
            != {
                "schema_version",
                "id",
                "category",
                "source_revision",
                "status",
                "artifact_ids",
                "producer",
                "checks",
                "metrics",
                "attachments",
            }
            or receipt.get("schema_version") != "cigar.qualification-evidence.v1"
            or receipt.get("source_revision") != authority.source["revision"]
            or receipt.get("status") != "passed"
        ):
            raise NativeCommandError(
                "required signed qualification receipt is stale or malformed"
            )
        found_categories.add(category)
        purpose = f"release-{category}"
        required[receipt_path.relative_to(dist).as_posix()] = purpose
        references = receipt.get("attachments")
        if not isinstance(references, list) or not references:
            raise NativeCommandError(
                "required signed qualification receipt has no attachments"
            )
        for reference in references:
            if not isinstance(reference, dict) or set(reference) != {
                "path",
                "sha256",
                "bytes",
                "media_type",
            }:
                raise NativeCommandError(
                    "required signed qualification attachment is malformed"
                )
            relative = _safe_relative(
                reference.get("path"), "qualification attachment path"
            )
            snapshot = _open_file_snapshot(
                os.fspath(dist.joinpath(*relative.split("/"))),
                "qualification attachment",
            )
            if snapshot.sha256 != reference.get(
                "sha256"
            ) or snapshot.bytes != reference.get("bytes"):
                raise NativeCommandError(
                    "required signed qualification attachment is stale"
                )
            required[relative] = purpose
    if found_categories != required_categories:
        raise NativeCommandError(
            "supporting signature phase lacks conformance or benchmark evidence"
        )
    supplied = {item["path"]: item["purpose"] for item in authority.inputs["payloads"]}
    if supplied != required:
        raise NativeCommandError(
            "release signature authority differs from the exact supporting payload set"
        )


def _validate_signing_trust_policy(authority: Authority) -> None:
    policy = _load_canonical_json(
        authority.files["trust_policy"].path, "signing trust policy"
    )
    if (
        set(policy) != {"schema_version", "keys"}
        or policy.get("schema_version") != "cigar.release-trust-policy.v1"
    ):
        raise NativeCommandError("signing trust policy has an unexpected shape")
    entries = policy.get("keys")
    if not isinstance(entries, list) or not entries or len(entries) > 256:
        raise NativeCommandError("signing trust policy key inventory is invalid")
    public = authority.files["public_key_file"]
    matches: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) not in (
            {
                "key_id",
                "public_key",
                "public_key_sha256",
                "signer_principal",
                "purposes",
                "status",
                "active_from",
            },
            {
                "key_id",
                "public_key",
                "public_key_sha256",
                "signer_principal",
                "purposes",
                "status",
                "active_from",
                "retired_at",
            },
        ):
            raise NativeCommandError("signing trust policy key has an unexpected shape")
        relative = _safe_relative(entry.get("public_key"), "trusted public key path")
        trusted_path = _canonical_absolute(
            os.fspath(
                authority.files["trust_policy"].path.parent.joinpath(
                    *relative.split("/")
                )
            ),
            "trusted public key",
        )
        if (
            trusted_path == public.path
            and entry.get("public_key_sha256") == public.sha256
        ):
            matches.append(entry)
    if len(matches) != 1:
        raise NativeCommandError(
            "signing public key is absent or ambiguous in the independent trust policy"
        )
    selected = matches[0]
    purposes = selected.get("purposes")
    required_purposes = {item["purpose"] for item in authority.inputs["payloads"]}
    if (
        selected.get("status") != "active"
        or selected.get("signer_principal") != authority.inputs["signer_principal"]
        or not isinstance(purposes, list)
        or len(purposes) != len(set(purposes))
        or not required_purposes.issubset(set(purposes))
        or _integer(
            selected.get("active_from"),
            "signing key activation time",
            maximum=253_402_300_799,
        )
        > authority.inputs["signed_at"]
        or "retired_at" in selected
    ):
        raise NativeCommandError(
            "signing key status, scope, principal, or activation is not authorized"
        )
    try:
        key_id = release_public_key_id(
            public.path,
            openssl_path=authority.files["openssl"].path,
            openssl_sha256=authority.inputs["openssl_sha256"],
        )
    except (OSError, ReleaseError) as error:
        raise NativeCommandError(
            "signing public key identity could not be verified"
        ) from error
    if selected.get("key_id") != key_id:
        raise NativeCommandError("signing trust policy key identity is stale")


def _development_product_version() -> str:
    path = REPOSITORY_ROOT / "packaging/product-version.v1.json"
    try:
        before = path.lstat()
        payload = path.read_bytes()
        after = path.lstat()
        document = load_json_bytes(payload, "product version authority")
    except (OSError, Exception) as error:
        raise NativeCommandError("product version authority is unavailable") from error
    stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        any(getattr(before, field) != getattr(after, field) for field in stable)
        or not stat.S_ISREG(before.st_mode)
        or not isinstance(document, dict)
        or document.get("schema_version") != "cigar.product-version.v1"
        or document.get("product") != "cigar"
        or document.get("context_abi") != "cigar.context.v1"
        or document.get("release_state") != "development"
        or document.get("published") is not False
    ):
        raise NativeCommandError("product version authority is stale or changed")
    version = document.get("version")
    if (
        not isinstance(version, str)
        or len(version) > 128
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version)
        is None
    ):
        raise NativeCommandError("product version authority has an invalid version")
    return version


def _required_release_artifacts() -> tuple[str, dict[str, tuple[str, str]]]:
    path = REPOSITORY_ROOT / "packaging/artifact-matrix.v1.json"
    try:
        before = path.lstat()
        payload = path.read_bytes()
        after = path.lstat()
        matrix = load_json_bytes(payload, "artifact matrix")
    except Exception as error:
        raise NativeCommandError("artifact matrix authority is unavailable") from error
    stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    rows = matrix.get("artifacts") if isinstance(matrix, dict) else None
    if (
        any(getattr(before, field) != getattr(after, field) for field in stable)
        or not stat.S_ISREG(before.st_mode)
        or matrix.get("schema_version") != "cigar.artifact-matrix.v1"
        or matrix.get("product") != "cigar"
        or matrix.get("context_abi") != "cigar.context.v1"
        or matrix.get("release_state") not in {"beta", "release"}
        or not isinstance(rows, list)
    ):
        raise NativeCommandError("artifact matrix authority is stale or changed")
    expected: dict[str, tuple[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("required_for_release") is not True:
            continue
        identifier = _identifier(row.get("id"), "matrix artifact id")
        filename = _safe_relative(row.get("filename"), "matrix artifact filename")
        contract = _safe_relative(row.get("contract"), "matrix artifact contract")
        if identifier in expected:
            raise NativeCommandError("artifact matrix contains a duplicate release id")
        expected[identifier] = (filename, f"packaging/{contract}")
    if not expected:
        raise NativeCommandError("artifact matrix has no required release artifacts")
    product_version = matrix.get("product_version")
    if not isinstance(product_version, str) or not product_version:
        raise NativeCommandError("artifact matrix product version is invalid")
    return product_version, expected


def _package_all(
    authority: Authority, runner: Runner
) -> tuple[list[Execution], dict[str, Any]]:
    inputs = authority.inputs
    epoch = inputs["source_date_epoch"]
    version = _development_product_version()
    python = _python()
    root = os.fspath(REPOSITORY_ROOT)

    def workspace(name: str) -> str:
        return os.fspath(authority.directories[name].path)

    def tool(name: str) -> str:
        return os.fspath(authority.files[name].path)

    common_rust = [
        "--cargo",
        tool("cargo"),
        "--rustc",
        tool("rustc"),
        "--protoc",
        tool("protoc"),
    ]
    commands: list[tuple[str, list[str], int]] = [
        (
            "portable archive producer",
            [
                python,
                "scripts/release/build_archives.py",
                "--root",
                root,
                "--out",
                "portable",
                "--evidence-dir",
                workspace("portable_workspace"),
                "--source-date-epoch",
                str(epoch),
                "--require-committed-clean",
            ],
            60 * 60,
        ),
        (
            "native macOS runtime producer",
            [
                python,
                "scripts/release/build_macos_aarch64_archive.py",
                "--root",
                root,
                "--evidence-dir",
                workspace("native_workspace"),
                "--source-date-epoch",
                str(epoch),
                *common_rust,
            ],
            2 * 60 * 60,
        ),
        (
            "native conformance-tool producer",
            [
                python,
                "scripts/release/build_macos_qualification_tools.py",
                "conformance",
                "--root",
                root,
                "--evidence-dir",
                workspace("conformance_workspace"),
                "--source-date-epoch",
                str(epoch),
                *common_rust,
            ],
            2 * 60 * 60,
        ),
        (
            "native CIGARBench-tool producer",
            [
                python,
                "scripts/release/build_macos_qualification_tools.py",
                "cigarbench",
                "--root",
                root,
                "--evidence-dir",
                workspace("cigarbench_workspace"),
                "--source-date-epoch",
                str(epoch),
                *common_rust,
            ],
            2 * 60 * 60,
        ),
        (
            "TypeScript SDK producer",
            [
                python,
                "scripts/release/build_typescript_sdk.py",
                "--root",
                root,
                "--evidence-dir",
                workspace("typescript_workspace"),
                "--source-date-epoch",
                str(epoch),
                "--node",
                tool("node"),
                "--pnpm",
                tool("pnpm"),
                "--npm",
                tool("npm"),
            ],
            60 * 60,
        ),
        (
            "Rust SDK producer",
            [
                python,
                "scripts/release/build_rust_sdk_crate.py",
                "--root",
                root,
                "--evidence-dir",
                workspace("rust_workspace"),
                "--source-date-epoch",
                str(epoch),
                *common_rust,
                "--cargo-local-registry",
                tool("cargo_local_registry"),
                "--cargo-cache",
                workspace("cargo_cache"),
            ],
            2 * 60 * 60,
        ),
        (
            "Python SDK producer",
            [
                python,
                "scripts/release/build_python_sdk_artifacts.py",
                "--root",
                root,
                "--evidence-dir",
                workspace("python_workspace"),
                "--source-date-epoch",
                str(epoch),
                "--uv",
                tool("uv"),
                "--python",
                tool("python"),
                "--uv-cache-dir",
                workspace("uv_cache_dir"),
            ],
            60 * 60,
        ),
        (
            "Go SDK producer",
            [
                python,
                "scripts/release/build_go_sdk.py",
                "--root",
                root,
                "--evidence-dir",
                workspace("go_workspace"),
                "--source-date-epoch",
                str(epoch),
                "--go",
                tool("go"),
                "--dependency-proxy",
                workspace("go_dependency_proxy"),
            ],
            60 * 60,
        ),
    ]
    native_archive = Path(workspace("native_workspace")) / (
        f"cigar-{version}-aarch64-apple-darwin.tar.gz"
    )
    native_receipt = (
        Path(workspace("native_workspace")) / "macos-aarch64-development-build.json"
    )
    commands.extend(
        [
            (
                "Homebrew artifact producer",
                [
                    python,
                    "scripts/release/build_macos_homebrew_artifacts.py",
                    "--root",
                    root,
                    "--native-archive",
                    os.fspath(native_archive),
                    "--native-build-receipt",
                    os.fspath(native_receipt),
                    "--evidence-dir",
                    workspace("homebrew_workspace"),
                    "--source-date-epoch",
                    str(epoch),
                ],
                60 * 60,
            ),
            (
                "Claude Code plugin producer",
                [
                    python,
                    "scripts/release/build_claude_code_plugin.py",
                    "--root",
                    root,
                    "--evidence-dir",
                    workspace("claude_workspace"),
                    "--source-date-epoch",
                    str(epoch),
                    "--cargo",
                    tool("cargo"),
                    "--rustc",
                    tool("rustc"),
                    "--runtime-archive",
                    os.fspath(native_archive),
                ],
                2 * 60 * 60,
            ),
        ]
    )
    executions: list[Execution] = []
    environment = _package_environment(authority, epoch)
    for label, command, timeout in commands:
        execution, _ = runner(label, command, timeout, environment)
        executions.append(execution)

    command = [python, "scripts/release/assemble_macos_development_artifacts.py"]
    for field, flag in (
        ("portable_workspace", "--portable-workspace"),
        ("native_workspace", "--native-workspace"),
        ("conformance_workspace", "--conformance-workspace"),
        ("cigarbench_workspace", "--cigarbench-workspace"),
        ("homebrew_workspace", "--homebrew-workspace"),
        ("typescript_workspace", "--typescript-workspace"),
        ("rust_workspace", "--rust-workspace"),
        ("python_workspace", "--python-workspace"),
        ("go_workspace", "--go-workspace"),
        ("claude_workspace", "--claude-workspace"),
    ):
        selected = Path(workspace(field))
        if field == "portable_workspace":
            selected /= "portable"
        command.extend([flag, os.fspath(selected)])
    command.extend(
        [
            "--root",
            root,
            "--evidence-dir",
            workspace("output_root"),
            "--source-date-epoch",
            str(epoch),
        ]
    )
    execution, _ = runner(
        "17-artifact macOS assembler", command, 4 * 60 * 60, environment
    )
    executions.append(execution)
    verify = [
        python,
        "scripts/release/verify_macos_development_assembly.py",
        "--root",
        root,
        "--dist",
        workspace("output_root"),
    ]
    execution, stdout = runner(
        "17-artifact assembly verifier", verify, 2 * 60 * 60, _child_environment()
    )
    executions.append(execution)
    try:
        document = json.loads(stdout.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise NativeCommandError("17-artifact verifier output is invalid") from error
    source = document.get("source")
    if (
        document.get("status") != "verified-development-only"
        or document.get("artifact_count") != 17
        or not isinstance(source, dict)
        or source.get("revision") != authority.source["revision"]
        or source.get("committed") is not True
        or source.get("clean") is not True
    ):
        raise NativeCommandError("assembled macOS matrix did not verify exactly")
    return executions, {
        "artifact_count": 17,
        "development_only": True,
        "producer_count": len(commands),
        "signed": False,
    }


def _execute_route(
    authority: Authority, relative_directory: str | None, runner: Runner = _run_tool
) -> tuple[list[Execution], list[dict[str, Any]], dict[str, Any]]:
    route = authority.route
    executions: list[Execution] = []
    outputs: list[dict[str, Any]] = []
    details: dict[str, Any] = {}
    if route in {"bench-micro-verify", "bench-macro-verify"}:
        executions.extend(_performance_replay(authority, runner))
        comparison = authority.files["comparison_report"]
        outputs.append(
            {
                "role": "performance-comparison-report",
                "bytes": comparison.bytes,
                "sha256": comparison.sha256,
            }
        )
        if route == "bench-macro-verify":
            command = [
                os.fspath(authority.files["local_scale_driver"].path),
                "verify",
                "--profile",
                os.fspath(authority.files["local_scale_profile"].path),
                "--binding",
                os.fspath(authority.files["local_scale_binding"].path),
                "--receipt",
                os.fspath(authority.files["local_scale_receipt"].path),
            ]
            execution, _ = runner(
                "physical local-scale receipt verifier",
                command,
                30 * 60,
                _child_environment(),
            )
            executions.append(execution)
            for role, label in (
                ("physical-scale-binding", "local_scale_binding"),
                ("physical-scale-receipt", "local_scale_receipt"),
            ):
                snapshot = authority.files[label]
                outputs.append(
                    {"role": role, "bytes": snapshot.bytes, "sha256": snapshot.sha256}
                )
        details = {
            "qualified_performance_replay": True,
            "physical_scale_receipt_verified": route == "bench-macro-verify",
        }
    elif route == "bench-efficacy":
        before = _tree_fingerprint(
            authority.directories["evidence_root"], "efficacy evidence root"
        )
        with tempfile.TemporaryDirectory(
            prefix="cigar-xtask-efficacy-", dir="/private/tmp"
        ) as temporary:
            output = Path(temporary) / "matrix-report.json"
            command = [
                _python(),
                "baselines/cigarbench/qualify_matrix.py",
                "--evidence-root",
                os.fspath(authority.directories["evidence_root"].path),
                "--datasets",
                "benches/cigarbench/datasets/manifest.json",
                "--baselines",
                "baselines/cigarbench/manifest.json",
                "--canaries",
                "benches/cigarbench/canaries.json",
                "--environment",
                os.fspath(authority.files["environment"].path),
                "--seed-file",
                os.fspath(authority.files["seed_file"].path),
                "--attestation-key-file",
                os.fspath(authority.files["attestation_key_file"].path),
                "--output",
                os.fspath(output),
            ]
            execution, _ = runner(
                "qualified CIGARBench matrix replay",
                command,
                4 * 60 * 60,
                _child_environment(),
            )
            executions.append(execution)
            produced = _open_file_snapshot(
                os.fspath(output), "reproduced efficacy matrix report"
            )
            expected = authority.files["matrix_report"]
            if produced.bytes != expected.bytes or produced.sha256 != expected.sha256:
                raise NativeCommandError(
                    "efficacy matrix report does not reproduce exactly"
                )
        after = _tree_fingerprint(
            authority.directories["evidence_root"], "efficacy evidence root"
        )
        if after != before:
            raise NativeCommandError("efficacy evidence changed during replay")
        details = {"qualified_comparator_count": 12, "matrix_reproduced": True}
        expected = authority.files["matrix_report"]
        outputs.append(
            {
                "role": "efficacy-matrix-report",
                "bytes": expected.bytes,
                "sha256": expected.sha256,
            }
        )
    elif route == "package-all":
        executions, details = _package_all(authority, runner)
        for role, name in (
            ("assembled-build-manifest", "release-build.json"),
            ("assembled-checksums", "SHA256SUMS"),
        ):
            snapshot = _open_file_snapshot(
                os.fspath(authority.directories["output_root"].path / name), role
            )
            outputs.append(
                {"role": role, "bytes": snapshot.bytes, "sha256": snapshot.sha256}
            )
    elif route == "package-smoke":
        if relative_directory is None:
            raise NativeCommandError(
                "package smoke requires its safe relative directory"
            )
        dist = _resolve_beneath(
            authority.directories["artifact_root"],
            relative_directory,
            "package directory",
        )
        authority.directories["package_candidate"] = _open_directory(
            os.fspath(dist), "package directory"
        )
        candidate_before = _tree_inventory(
            authority.directories["package_candidate"], "package directory"
        )
        manifest, artifacts, artifact_snapshots = _load_release_build(
            dist, require_release=False, expected_source=authority.source
        )
        authority.files.update(
            {
                f"package-artifact-{identifier}": snapshot
                for identifier, snapshot in artifact_snapshots.items()
            }
        )
        command = [
            _python(),
            "scripts/release/verify_macos_development_assembly.py",
            "--dist",
            os.fspath(dist),
        ]
        execution, stdout = runner(
            "exact package matrix verifier", command, 2 * 60 * 60, _child_environment()
        )
        executions.append(execution)
        verification = json.loads(
            stdout.decode("utf-8"), object_pairs_hook=_strict_object
        )
        if (
            verification.get("status") != "verified-development-only"
            or verification.get("artifact_count") != 17
        ):
            raise NativeCommandError("package matrix verification did not pass")
        runtime = _artifact_by_id(artifacts, "cli-daemon-macos-aarch64")
        qualifier = _artifact_by_id(artifacts, "cigar-conformance-macos-aarch64")
        install_command = [
            _python(),
            "scripts/release/qualify_install.py",
            os.fspath(dist / runtime["path"]),
            "--contract",
            "packaging/contracts/macos-runtime-archive.v1.json",
            "--runtime-build-receipt",
            os.fspath(authority.files["runtime_build_receipt"].path),
            "--qualification-tool-archive",
            os.fspath(dist / qualifier["path"]),
            "--qualification-tool-contract",
            "packaging/contracts/macos-conformance-runner.v1.json",
            "--qualification-tool-build-receipt",
            os.fspath(authority.files["qualification_tool_build_receipt"].path),
            "--expected-artifact-id",
            "cli-daemon-macos-aarch64",
            "--expected-target",
            "aarch64-apple-darwin",
            "--evidence-dir",
            os.fspath(authority.directories["install_evidence_root"].path),
            "--report",
            "package-smoke/install-qualification.json",
        ]
        environment = _child_environment()
        if os.environ.get("CIGAR_NO_EGRESS_ENFORCED") == "1":
            environment["CIGAR_NO_EGRESS_ENFORCED"] = "1"
        execution, _ = runner(
            "installed artifact package smoke",
            install_command,
            2 * 60 * 60,
            environment,
        )
        executions.append(execution)
        report = _open_file_snapshot(
            os.fspath(
                authority.directories["install_evidence_root"].path
                / "package-smoke/install-qualification.json"
            ),
            "installed package qualification report",
        )
        outputs.append(
            {
                "role": "install-qualification",
                "bytes": report.bytes,
                "sha256": report.sha256,
            }
        )
        details = {
            "artifact_count": len(artifacts),
            "installed_bytes_executed": True,
            "source_revision": manifest.get("source", {}).get("revision"),
        }
        candidate_after = _tree_inventory(
            authority.directories["package_candidate"], "package directory"
        )
        _require_tree_delta(
            candidate_before, candidate_after, set(), "package smoke candidate"
        )
    elif route in {"release-sbom", "release-attest", "release-sign", "release-verify"}:
        executions, outputs, details = _execute_release_route(
            authority, relative_directory, runner
        )
    else:
        raise NativeCommandError("native route has no executable dispatch")
    authority.recheck()
    return executions, outputs, details


def _produce_supporting_signatures(
    authority: Authority,
    dist: Path,
    signature_dir: Path,
    runner: Runner,
) -> tuple[list[Execution], list[dict[str, Any]], set[str]]:
    inputs = authority.inputs
    staging = Path(
        tempfile.mkdtemp(prefix=".cigar-signatures-staging-", dir=dist)
    ).resolve(strict=True)
    # Signature staging must remain inaccessible to other local accounts.
    os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        staging, 0o700
    )
    executions: list[Execution] = []
    outputs: list[dict[str, Any]] = []
    expected: dict[str, FileSnapshot] = {}
    published = False
    renamed = False
    try:
        for index, item in enumerate(inputs["payloads"]):
            relative = _safe_relative(item["path"], "signature payload path")
            payload = _canonical_absolute(
                os.fspath(dist.joinpath(*relative.split("/"))), "signature payload"
            )
            try:
                payload.relative_to(dist)
            except ValueError as error:
                raise NativeCommandError(
                    "signature payload escapes the candidate"
                ) from error
            payload_snapshot = authority.files[f"signature-payload-{index}"]
            if payload != payload_snapshot.path:
                raise NativeCommandError("signature payload authority is inconsistent")
            name = f"{payload_snapshot.sha256}.{item['purpose']}.sig.json"
            envelope = staging / name
            command = [
                _python(),
                "scripts/release/signatures.py",
                "sign",
                os.fspath(payload),
                "--private-key",
                os.fspath(authority.files["private_key_file"].path),
                "--public-key",
                os.fspath(authority.files["public_key_file"].path),
                "--signer-principal",
                inputs["signer_principal"],
                "--purpose",
                item["purpose"],
                "--signed-at",
                str(inputs["signed_at"]),
                "--out",
                os.fspath(envelope),
                "--openssl",
                os.fspath(authority.files["openssl"].path),
                "--openssl-sha256",
                inputs["openssl_sha256"],
            ]
            if inputs["expires_at"] is not None:
                command.extend(["--expires-at", str(inputs["expires_at"])])
            execution, _ = runner(
                "release signature producer", command, 10 * 60, _child_environment()
            )
            executions.append(execution)
            verify = [
                _python(),
                "scripts/release/signatures.py",
                "verify",
                os.fspath(envelope),
                "--payload",
                os.fspath(payload),
                "--public-key",
                os.fspath(authority.files["public_key_file"].path),
                "--expected-purpose",
                item["purpose"],
                "--expected-signer",
                inputs["signer_principal"],
                "--verification-time",
                str(inputs["signed_at"]),
                "--openssl",
                os.fspath(authority.files["openssl"].path),
                "--openssl-sha256",
                inputs["openssl_sha256"],
            ]
            execution, _ = runner(
                "release signature verifier", verify, 10 * 60, _child_environment()
            )
            executions.append(execution)
            expected[name] = _open_file_snapshot(
                os.fspath(envelope), "staged release signature envelope"
            )
        os.rename(staging, signature_dir)
        renamed = True
        for name, staged in expected.items():
            snapshot = _open_file_snapshot(
                os.fspath(signature_dir / name), "published release signature envelope"
            )
            if (
                snapshot.bytes != staged.bytes
                or snapshot.sha256 != staged.sha256
                or stat.S_IMODE(snapshot.mode) != stat.S_IMODE(staged.mode)
            ):
                raise NativeCommandError(
                    "release signature envelope changed during atomic publication"
                )
            outputs.append(
                {
                    "role": "signature-envelope",
                    "bytes": snapshot.bytes,
                    "sha256": snapshot.sha256,
                }
            )
        published = True
    finally:
        if not published:
            cleanup = signature_dir if renamed else staging
            if cleanup.exists():
                shutil.rmtree(cleanup)
    additions = {"signatures"} | {f"signatures/{name}" for name in expected}
    return executions, outputs, additions


def _execute_release_route(
    authority: Authority, relative_directory: str | None, runner: Runner
) -> tuple[list[Execution], list[dict[str, Any]], dict[str, Any]]:
    inputs = authority.inputs
    root = authority.directories["artifact_root"]
    if authority.route == "release-verify":
        if relative_directory is None:
            raise NativeCommandError(
                "release verification requires its safe relative directory"
            )
        dist = _resolve_beneath(root, relative_directory, "release candidate directory")
    else:
        dist = _resolve_beneath(
            root, inputs["artifact_directory"], "release candidate directory"
        )
    authority.directories["release_candidate"] = _open_directory(
        os.fspath(dist), "release candidate directory"
    )
    candidate_before = _tree_inventory(
        authority.directories["release_candidate"], "release candidate directory"
    )
    manifest, artifacts, artifact_snapshots = _load_release_build(
        dist, require_release=True, expected_source=authority.source
    )
    authority.files.update(
        {
            f"release-artifact-{identifier}": snapshot
            for identifier, snapshot in artifact_snapshots.items()
        }
    )
    executions: list[Execution] = []
    outputs: list[dict[str, Any]] = []
    details: dict[str, Any]
    expected_additions: set[str]
    if authority.route in {"release-sbom", "release-attest"} and inputs[
        "source_date_epoch"
    ] != manifest.get("source_date_epoch"):
        raise NativeCommandError(
            "release sidecar epoch differs from the candidate build epoch"
        )
    if authority.route == "release-sbom":
        output = dist / _safe_direct_child(
            inputs["output_path"], "SBOM output directory"
        )
        if output.exists() or output.is_symlink():
            raise NativeCommandError("SBOM output must be create-new")
        command = [
            _python(),
            "scripts/release/generate_sbom.py",
            "--root",
            os.fspath(REPOSITORY_ROOT),
        ]
        for item in artifacts:
            command.extend(["--artifact", os.fspath(dist / item["path"])])
        command.extend(
            [
                "--out",
                os.fspath(output),
                "--source-date-epoch",
                str(inputs["source_date_epoch"]),
                "--require-reviewed-licenses",
            ]
        )
        execution, _ = runner(
            "candidate SBOM generator",
            command,
            60 * 60,
            _child_environment(source_date_epoch=inputs["source_date_epoch"]),
        )
        executions.append(execution)
        for name in ("sbom.spdx.json", "sbom.cyclonedx.json", "sbom-artifacts.json"):
            snapshot = _open_file_snapshot(
                os.fspath(output / name), "generated SBOM document"
            )
            outputs.append(
                {"role": name, "bytes": snapshot.bytes, "sha256": snapshot.sha256}
            )
        expected_additions = {
            "sbom",
            "sbom/sbom.spdx.json",
            "sbom/sbom.cyclonedx.json",
            "sbom/sbom-artifacts.json",
        }
        details = {
            "artifact_count": len(artifacts),
            "sbom_document_count": 3,
            "sidecars_pending_offline_reconciliation": True,
        }
    elif authority.route == "release-attest":
        output = dist / _safe_direct_child(
            inputs["output_path"], "provenance output path"
        )
        if output.exists() or output.is_symlink():
            raise NativeCommandError("provenance output must be create-new")
        source_archive = _artifact_by_id(artifacts, "source")
        source = manifest.get("source")
        revision = source.get("revision") if isinstance(source, dict) else None
        if revision != authority.source["revision"]:
            raise NativeCommandError(
                "release manifest is bound to another source revision"
            )
        command = [
            _python(),
            "scripts/release/generate_provenance.py",
            "--root",
            os.fspath(REPOSITORY_ROOT),
        ]
        for item in artifacts:
            command.extend(["--artifact", os.fspath(dist / item["path"])])
        command.extend(
            [
                "--source-archive",
                os.fspath(dist / source_archive["path"]),
                "--source-revision",
                revision,
            ]
        )
        for index in range(len(inputs["materials"])):
            command.extend(
                ["--material", os.fspath(authority.files[f"material-{index}"].path)]
            )
        command.extend(
            [
                "--builder-id",
                inputs["builder_id"],
                "--workflow-id",
                inputs["workflow_id"],
                "--network-mode",
                inputs["network_mode"],
            ]
        )
        for item in inputs["commands"]:
            command.extend(
                ["--command", f"{item['tool_id']}@sha256:{item['argv_sha256']}"]
            )
        command.extend(
            [
                "--source-date-epoch",
                str(inputs["source_date_epoch"]),
                "--out",
                os.fspath(output),
            ]
        )
        environment = _child_environment(source_date_epoch=inputs["source_date_epoch"])
        if os.environ.get("CIGAR_NO_EGRESS_ENFORCED") != "1":
            raise NativeCommandError(
                "disabled-network attestation lacks an outer enforcement marker"
            )
        environment["CIGAR_NO_EGRESS_ENFORCED"] = "1"
        execution, _ = runner(
            "candidate provenance generator", command, 60 * 60, environment
        )
        executions.append(execution)
        snapshot = _open_file_snapshot(os.fspath(output), "generated provenance")
        outputs.append(
            {"role": "provenance", "bytes": snapshot.bytes, "sha256": snapshot.sha256}
        )
        expected_additions = {"provenance.json"}
        details = {
            "artifact_count": len(artifacts),
            "subject_count": len(artifacts),
            "network_mode": inputs["network_mode"],
            "sidecars_pending_offline_reconciliation": True,
        }
    elif authority.route == "release-sign":
        _validate_signing_trust_policy(authority)
        _require_exact_supporting_signature_set(authority, dist, artifacts)
        signature_dir = dist / _safe_direct_child(
            inputs["signature_directory"], "signature directory"
        )
        if signature_dir.exists() or signature_dir.is_symlink():
            raise NativeCommandError("signature output directory must be create-new")
        executions, outputs, expected_additions = _produce_supporting_signatures(
            authority, dist, signature_dir, runner
        )
        details = {
            "signature_count": len(inputs["payloads"]),
            "signing_executed": True,
            "signing_phase": "supporting",
            "release_evidence_signature_deferred": True,
            "sidecars_pending_offline_reconciliation": True,
        }
    else:
        evidence = authority.directories["verification_evidence_root"]
        command = [
            _python(),
            "scripts/release/verify_release.py",
            os.fspath(dist),
            "--root",
            os.fspath(REPOSITORY_ROOT),
            "--trust-policy",
            os.fspath(authority.files["trust_policy"].path),
            "--openssl",
            os.fspath(authority.files["openssl"].path),
            "--openssl-sha256",
            inputs["openssl_sha256"],
            "--verification-time",
            str(inputs["verification_time"]),
            "--evidence-dir",
            os.fspath(evidence.path),
            "--report",
            "release-verification.json",
        ]
        execution, _ = runner(
            "independent offline release verifier",
            command,
            2 * 60 * 60,
            _child_environment(),
        )
        executions.append(execution)
        report_path = evidence.path / "release-verification.json"
        report = _load_canonical_json(
            report_path, "offline release verification report"
        )
        if report.get("status") not in {"passed", "pass"}:
            raise NativeCommandError("offline release verification is not passing")
        if report.get("reviewed_openssl_sha256") != inputs["openssl_sha256"]:
            raise NativeCommandError(
                "offline release report lacks the reviewed verifier binding"
            )
        snapshot = _open_file_snapshot(
            os.fspath(report_path), "offline release verification report"
        )
        outputs.append(
            {
                "role": "offline-release-verification",
                "bytes": snapshot.bytes,
                "sha256": snapshot.sha256,
            }
        )
        details = {
            "artifact_count": len(artifacts),
            "offline_verified": True,
            "reviewed_openssl_sha256": inputs["openssl_sha256"],
            "sidecar_inventory_reconciled": True,
        }
        expected_additions = set()
    candidate_after = _tree_inventory(
        authority.directories["release_candidate"], "release candidate directory"
    )
    _require_tree_delta(
        candidate_before,
        candidate_after,
        expected_additions,
        f"{authority.route} candidate",
    )
    return executions, outputs, details


def _execute_sanitizers(
    expected_source: Mapping[str, Any], runner: Runner = _run_tool
) -> tuple[list[Execution], list[dict[str, Any]], dict[str, Any]]:
    executions: list[Execution] = []
    command = [_python(), "tools/quality/production_sanitizers.py", "verify-manifest"]
    execution, stdout = runner(
        "sanitizer manifest verifier", command, 5 * 60, _sanitizer_environment()
    )
    executions.append(execution)
    manifest_result = json.loads(
        stdout.decode("utf-8"), object_pairs_hook=_strict_object
    )
    case_ids = manifest_result.get("case_ids")
    if (
        manifest_result.get("fuzz_built_or_run") is not False
        or manifest_result.get("soak_built_or_run") is not False
        or manifest_result.get("test_exclusions") != []
        or not isinstance(case_ids, list)
        or len(case_ids) != 10
        or len(set(case_ids)) != len(case_ids)
    ):
        raise NativeCommandError("sanitizer manifest verification is incomplete")
    with tempfile.TemporaryDirectory(
        prefix="cigar-xtask-sanitizers-", dir="/private/tmp"
    ) as temporary:
        receipt = Path(temporary) / "sanitizers.json"
        command = [
            _python(),
            "tools/quality/production_sanitizers.py",
            "run",
            "--receipt",
            os.fspath(receipt),
        ]
        execution, _ = runner(
            "production sanitizer qualification",
            command,
            3 * 60 * 60,
            _sanitizer_environment(),
        )
        executions.append(execution)
        command = [
            _python(),
            "tools/quality/production_sanitizers.py",
            "verify-receipt",
            "--receipt",
            os.fspath(receipt),
        ]
        execution, stdout = runner(
            "production sanitizer receipt verifier",
            command,
            10 * 60,
            _sanitizer_environment(),
        )
        executions.append(execution)
        verification = json.loads(
            stdout.decode("utf-8"), object_pairs_hook=_strict_object
        )
        claims = verification.get("claims")
        source = verification.get("source")
        if (
            not isinstance(claims, dict)
            or claims.get("sanitizer_checks_passed") is not True
            or claims.get("fuzz_built_or_run") is not False
            or claims.get("soak_built_or_run") is not False
            or claims.get("test_exclusions") != []
            or claims.get("release_eligible") is not False
            or not isinstance(source, dict)
            or source.get("revision") != expected_source.get("revision")
        ):
            raise NativeCommandError(
                "sanitizer receipt verification overclaims or is stale"
            )
        snapshot = _open_file_snapshot(os.fspath(receipt), "sanitizer receipt")
    return (
        executions,
        [
            {
                "role": "sanitizer-receipt",
                "bytes": snapshot.bytes,
                "sha256": snapshot.sha256,
            }
        ],
        {
            "case_count": len(case_ids),
            "test_exclusions": 0,
            "rust_ubsan_claimed": False,
        },
    )


def _publish_raw(
    evidence_directory: Path,
    route: str,
    source: Mapping[str, Any],
    runtime: Mapping[str, Any],
    producer: Mapping[str, Any],
    authority_binding: Mapping[str, Any] | None,
    executions: Sequence[Execution],
    outputs: Sequence[Mapping[str, Any]],
    details: Mapping[str, Any],
) -> None:
    raw = {
        "schema_version": RAW_SCHEMA,
        "command_id": route,
        "source": dict(source),
        "status": "passed",
        "exit_code": 0,
        "runtime": dict(runtime),
        "producer": dict(producer),
        "authority": None if authority_binding is None else dict(authority_binding),
        "executions": [item.as_dict() for item in executions],
        "outputs": [dict(item) for item in outputs],
        "details": {
            "platform_scope": ["macos-arm64"],
            "fuzz_executed": False,
            "soak_executed": False,
            "mutation_campaign_executed": False,
            "hundred_gib_scale_executed": False,
            **dict(details),
        },
    }
    with EvidenceWorkspace.create(
        evidence_directory, repository_root=REPOSITORY_ROOT
    ) as workspace:
        workspace.read_files(set())
        workspace.write_json(f"command-plane/{route}.raw.json", raw)
        workspace.read_files({f"command-plane/{route}.raw.json"})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", choices=["run"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--route", choices=sorted(ROUTES), required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--expected-python-path", required=True)
    parser.add_argument("--expected-python-sha256", required=True)
    parser.add_argument("--expected-python-version", required=True)
    parser.add_argument("--relative-directory")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if (
        arguments.root != REPOSITORY_ROOT
        or arguments.root.resolve(strict=True) != REPOSITORY_ROOT
    ):
        raise NativeCommandError(
            "repository root does not contain this command adapter"
        )
    if sys.platform != "darwin" or platform.machine().casefold() not in {
        "arm64",
        "aarch64",
    }:
        raise NativeCommandError(
            "native command adapter currently supports only Apple-silicon macOS"
        )
    if arguments.route == "test-sanitizers" and os.environ.get(SELECTOR) is not None:
        raise NativeCommandError("sanitizer route rejects an unrelated input authority")
    producer = _snapshot_producer_closure()
    runtime = _snapshot_runtime(
        arguments.expected_python_path,
        arguments.expected_python_sha256,
        arguments.expected_python_version,
    )
    try:
        expected = json.loads(
            arguments.expected_source, object_pairs_hook=_strict_object
        )
    except json.JSONDecodeError as error:
        raise NativeCommandError("expected source binding is invalid") from error
    expected = _validate_source(expected, expected)
    relative = None
    if arguments.relative_directory is not None:
        relative = _safe_relative(arguments.relative_directory, "command directory")
    needs_relative = arguments.route in {"package-smoke", "release-verify"}
    if needs_relative != (relative is not None):
        raise NativeCommandError("route directory argument is missing or unexpected")
    evidence = _canonical_absolute(
        os.fspath(arguments.evidence_dir), "command evidence directory"
    )
    if arguments.route == "test-sanitizers":
        executions, outputs, details = _execute_sanitizers(expected)
        binding = None
    else:
        authority = _load_authority(arguments.route, expected)
        executions, outputs, details = _execute_route(authority, relative)
        authority.recheck()
        binding = authority.binding
    _recheck_runtime(runtime)
    _recheck_producer_closure(producer)
    _publish_raw(
        evidence,
        arguments.route,
        expected,
        runtime.binding,
        {
            "closure": {
                relative: snapshot.binding
                for relative, snapshot in sorted(producer.items())
            }
        },
        binding,
        executions,
        outputs,
        details,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, NativeCommandError, OSError, ValueError):
        print(
            "native xtask gate failed or is blocked; sensitive diagnostics were suppressed",
            file=sys.stderr,
        )
        raise SystemExit(2)
