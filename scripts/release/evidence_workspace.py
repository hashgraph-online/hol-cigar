#!/usr/bin/env python3
"""Fail-closed storage primitives for external release evidence.

The workspace deliberately supports only private POSIX filesystems.  Evidence is
created beneath an absolute, owner-only directory outside the source repository.
All traversal and publication uses directory file descriptors so a symlink or
rename cannot silently redirect a write into the repository.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping


class EvidenceWorkspaceError(RuntimeError):
    """An external-evidence invariant was not satisfied."""


@dataclass(frozen=True)
class EvidenceLimits:
    """Hard limits applied to one evidence workspace."""

    max_files: int = 16_384
    max_directories: int = 2_048
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_json_bytes: int = 16 * 1024 * 1024
    max_path_depth: int = 32

    def validate(self) -> None:
        for name, value in vars(self).items():
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > _LIMIT_CEILINGS[name]
            ):
                raise EvidenceWorkspaceError(
                    f"evidence limit {name} must be a bounded positive integer"
                )
        if self.max_json_bytes > self.max_file_bytes:
            raise EvidenceWorkspaceError("max_json_bytes cannot exceed max_file_bytes")


@dataclass(frozen=True)
class Attachment:
    """Content binding for a file copied into the evidence workspace."""

    path: str
    sha256: str
    bytes: int

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "bytes": self.bytes}


_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_FILE_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _NOFOLLOW | _CLOEXEC
_FILE_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
_RESERVED_TEMP_PREFIX = ".cigar-evidence-tmp-"
_MAX_SEGMENT_BYTES = 255
_MAX_PATH_BYTES = 4096
_MAX_JSON_DEPTH = 64
_MAX_JSON_ITEMS = 100_000
_MAX_DIRECTORY_ENTRIES = 65_536
_LIMIT_CEILINGS = {
    "max_files": 100_000,
    "max_directories": 16_384,
    "max_file_bytes": 64 * 1024 * 1024,
    "max_total_bytes": 64 * 1024 * 1024 * 1024,
    "max_json_bytes": 16 * 1024 * 1024,
    "max_path_depth": 64,
}


def _require_supported_platform() -> None:
    if os.name != "posix" or _NOFOLLOW == 0 or not hasattr(os, "geteuid"):
        raise EvidenceWorkspaceError(
            "secure evidence workspaces require POSIX dirfd and O_NOFOLLOW support"
        )


def _portable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _validate_name(name: str, label: str) -> None:
    if not name or name in {".", ".."}:
        raise EvidenceWorkspaceError(f"{label} contains an unsafe path segment")
    if name != unicodedata.normalize("NFC", name):
        raise EvidenceWorkspaceError(f"{label} is not NFC-normalized")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise EvidenceWorkspaceError(f"{label} contains a control character")
    if "\x00" in name or "/" in name or "\\" in name:
        raise EvidenceWorkspaceError(f"{label} contains a path separator")
    if name.startswith(_RESERVED_TEMP_PREFIX):
        raise EvidenceWorkspaceError(f"{label} uses a reserved temporary name")
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise EvidenceWorkspaceError(f"{label} is not valid UTF-8 text") from error
    if len(encoded) > _MAX_SEGMENT_BYTES:
        raise EvidenceWorkspaceError(f"{label} exceeds {_MAX_SEGMENT_BYTES} bytes")


def safe_relative_path(value: str, *, max_depth: int = 32) -> tuple[str, ...]:
    """Validate a canonical portable relative path and return its segments."""

    if not isinstance(value, str) or not value or value.startswith("/"):
        raise EvidenceWorkspaceError("evidence path must be a non-empty relative path")
    if "\\" in value or value.endswith("/"):
        raise EvidenceWorkspaceError("evidence path must use canonical '/' separators")
    parts = value.split("/")
    if len(parts) > max_depth:
        raise EvidenceWorkspaceError(f"evidence path exceeds {max_depth} segments")
    for index, part in enumerate(parts):
        _validate_name(part, f"evidence path segment {index}")
    if len(value.encode("utf-8")) > _MAX_PATH_BYTES:
        raise EvidenceWorkspaceError(
            f"evidence path exceeds {_MAX_PATH_BYTES} UTF-8 bytes"
        )
    return tuple(parts)


def _validate_absolute_path(path: Path, label: str) -> tuple[str, ...]:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not os.path.isabs(raw):
        raise EvidenceWorkspaceError(f"{label} must be an absolute path")
    if os.path.normpath(raw) != raw:
        raise EvidenceWorkspaceError(f"{label} must be lexically canonical")
    parts = Path(raw).parts
    if not parts or parts[0] != os.path.sep:
        raise EvidenceWorkspaceError(f"{label} must use the POSIX root")
    for index, part in enumerate(parts[1:]):
        _validate_name(part, f"{label} segment {index}")
    return tuple(parts[1:])


def _directory_entries(directory_fd: int, label: str) -> dict[str, str]:
    try:
        iterator = os.scandir(directory_fd)
    except OSError as error:
        raise EvidenceWorkspaceError(f"cannot enumerate {label}: {error}") from error
    aliases: dict[str, str] = {}
    try:
        for index, entry in enumerate(iterator):
            if index >= _MAX_DIRECTORY_ENTRIES:
                raise EvidenceWorkspaceError(
                    f"directory entry limit exceeded while enumerating {label}"
                )
            name = entry.name
            _validate_name(name, f"existing entry in {label}")
            key = _portable_key(name)
            previous = aliases.get(key)
            if previous is not None and previous != name:
                raise EvidenceWorkspaceError(
                    f"case/Unicode collision in {label}: {previous!r} and {name!r}"
                )
            aliases[key] = name
    finally:
        iterator.close()
    return aliases


def _exact_entry(directory_fd: int, requested: str, label: str) -> bool:
    requested_key = _portable_key(requested)
    matching: str | None = None
    try:
        iterator = os.scandir(directory_fd)
    except OSError as error:
        raise EvidenceWorkspaceError(f"cannot enumerate {label}: {error}") from error
    try:
        for index, entry in enumerate(iterator):
            if index >= _MAX_DIRECTORY_ENTRIES:
                raise EvidenceWorkspaceError(
                    f"directory entry limit exceeded while enumerating {label}"
                )
            name = entry.name
            if _portable_key(name) != requested_key:
                continue
            if matching is not None and matching != name:
                raise EvidenceWorkspaceError(
                    f"case/Unicode collision in {label}: {matching!r} and {name!r}"
                )
            matching = name
    finally:
        iterator.close()
    if matching is not None and matching != requested:
        raise EvidenceWorkspaceError(
            f"case/Unicode path collision in {label}: {requested!r} aliases {matching!r}"
        )
    return matching == requested


def _check_owned_directory(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceWorkspaceError(f"{label} is not a directory")
    if metadata.st_uid != os.geteuid():
        raise EvidenceWorkspaceError(f"{label} is not owned by the effective user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise EvidenceWorkspaceError(f"{label} must have exact mode 0700")


def _open_absolute_directory(
    path: Path, *, create_final: bool, private_final: bool
) -> int:
    parts = _validate_absolute_path(path, "directory")
    flags = _DIRECTORY_FLAGS | _NOFOLLOW | _CLOEXEC
    try:
        current = os.open(os.path.sep, flags)
    except OSError as error:
        raise EvidenceWorkspaceError(f"cannot open filesystem root: {error}") from error
    try:
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            exists = _exact_entry(current, part, str(path))
            if not exists:
                if not (create_final and final):
                    raise EvidenceWorkspaceError(f"directory does not exist: {path}")
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    os.fsync(current)
                except OSError as error:
                    raise EvidenceWorkspaceError(
                        f"cannot create private evidence directory {path}: {error}"
                    ) from error
            try:
                following = os.open(part, flags, dir_fd=current)
            except OSError as error:
                raise EvidenceWorkspaceError(
                    f"directory traversal is unsafe at {part!r}: {error}"
                ) from error
            os.close(current)
            current = following
        metadata = os.fstat(current)
        if private_final:
            _check_owned_directory(metadata, str(path))
        elif not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceWorkspaceError(f"not a directory: {path}")
        return current
    except BaseException:
        os.close(current)
        raise


def _path_is_within(candidate: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.fspath(candidate), os.fspath(parent))
        ) == os.fspath(parent)
    except ValueError:
        return False


def _read_all_bounded(handle: BinaryIO, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = handle.read(min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise EvidenceWorkspaceError(f"{label} exceeds {maximum} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _open_absolute_regular(path: Path, maximum: int) -> tuple[int, os.stat_result]:
    parts = _validate_absolute_path(path, "attachment source")
    if not parts:
        raise EvidenceWorkspaceError("attachment source cannot be the filesystem root")
    directory = _open_absolute_directory(
        Path(os.path.sep).joinpath(*parts[:-1]),
        create_final=False,
        private_final=False,
    )
    try:
        final = parts[-1]
        if not _exact_entry(directory, final, str(path.parent)):
            raise EvidenceWorkspaceError(f"attachment source does not exist: {path}")
        try:
            file_fd = os.open(final, _FILE_READ_FLAGS, dir_fd=directory)
        except OSError as error:
            raise EvidenceWorkspaceError(
                f"cannot securely open attachment source {path}: {error}"
            ) from error
    finally:
        os.close(directory)
    try:
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceWorkspaceError(f"attachment source is not regular: {path}")
        if metadata.st_nlink != 1:
            raise EvidenceWorkspaceError(f"attachment source is hardlinked: {path}")
        if metadata.st_uid != os.geteuid():
            raise EvidenceWorkspaceError(
                f"attachment source is not owned by the effective user: {path}"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise EvidenceWorkspaceError(
                f"attachment source is group/world writable: {path}"
            )
        if metadata.st_size < 0 or metadata.st_size > maximum:
            raise EvidenceWorkspaceError(
                f"attachment source exceeds {maximum} bytes: {path}"
            )
        return file_fd, metadata
    except BaseException:
        os.close(file_fd)
        raise


def digest_secure_file(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> Attachment:
    """Digest one owner-controlled, symlink-free, stable regular file."""

    _require_supported_platform()
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise EvidenceWorkspaceError("max_bytes must be a positive integer")
    if max_bytes > _LIMIT_CEILINGS["max_file_bytes"]:
        raise EvidenceWorkspaceError("max_bytes exceeds the secure digest hard limit")
    absolute = path if path.is_absolute() else Path()
    if not absolute.is_absolute():
        raise EvidenceWorkspaceError("secure digest input must be an absolute path")
    file_fd, before = _open_absolute_regular(absolute, max_bytes)
    try:
        with os.fdopen(file_fd, "rb", closefd=True) as handle:
            payload = _read_all_bounded(handle, max_bytes, str(path))
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise EvidenceWorkspaceError(
            f"cannot read secure input {path}: {error}"
        ) from error
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise EvidenceWorkspaceError(f"secure input changed while reading: {path}")
    return Attachment(
        path=absolute.name,
        sha256=hashlib.sha256(payload).hexdigest(),
        bytes=len(payload),
    )


def validate_metrics(
    metrics: Mapping[str, int | float], *, max_metrics: int = 4096
) -> None:
    """Reject ambiguous, non-finite, or unbounded metric documents."""

    if (
        isinstance(max_metrics, bool)
        or not isinstance(max_metrics, int)
        or max_metrics <= 0
        or max_metrics > _MAX_JSON_ITEMS
    ):
        raise EvidenceWorkspaceError("max_metrics must be a bounded positive integer")
    if not isinstance(metrics, Mapping) or len(metrics) > max_metrics:
        raise EvidenceWorkspaceError("metrics must be a bounded mapping")
    portable: set[str] = set()
    for key, value in metrics.items():
        if not isinstance(key, str):
            raise EvidenceWorkspaceError("metric names must be strings")
        _validate_name(key, "metric name")
        alias = _portable_key(key)
        if alias in portable:
            raise EvidenceWorkspaceError(f"case/Unicode metric-name collision: {key}")
        portable.add(alias)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise EvidenceWorkspaceError(f"metric {key} must be an integer or float")
        if isinstance(value, int) and not -(1 << 63) <= value < (1 << 63):
            raise EvidenceWorkspaceError(f"metric {key} exceeds signed 64-bit range")
        if isinstance(value, float) and not math.isfinite(value):
            raise EvidenceWorkspaceError(f"metric {key} is not finite")


def _validate_json(value: Any) -> None:
    items = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal items
        if depth > _MAX_JSON_DEPTH:
            raise EvidenceWorkspaceError(
                f"JSON exceeds the {_MAX_JSON_DEPTH}-level depth limit"
            )
        items += 1
        if items > _MAX_JSON_ITEMS:
            raise EvidenceWorkspaceError(
                f"JSON exceeds the {_MAX_JSON_ITEMS}-item limit"
            )
        if current is None or isinstance(current, (str, bool, int)):
            return
        if isinstance(current, float):
            if not math.isfinite(current):
                raise EvidenceWorkspaceError("JSON contains a non-finite number")
            return
        if isinstance(current, list):
            for child in current:
                visit(child, depth + 1)
            return
        if isinstance(current, dict):
            aliases: set[str] = set()
            for key, child in current.items():
                if not isinstance(key, str):
                    raise EvidenceWorkspaceError("JSON object keys must be strings")
                if key != unicodedata.normalize("NFC", key):
                    raise EvidenceWorkspaceError(
                        "JSON object key is not NFC-normalized"
                    )
                alias = _portable_key(key)
                if alias in aliases:
                    raise EvidenceWorkspaceError(
                        f"JSON object contains a case/Unicode key collision: {key}"
                    )
                aliases.add(alias)
                visit(child, depth + 1)
            return
        raise EvidenceWorkspaceError(
            f"unsupported JSON value type: {type(current).__name__}"
        )

    visit(value, 0)


def canonical_json_bytes(value: Any) -> bytes:
    """Encode bounded, finite JSON with one canonical representation."""

    _validate_json(value)
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise EvidenceWorkspaceError(
            f"cannot encode canonical JSON: {error}"
        ) from error


class EvidenceWorkspace:
    """A private, create-new-only external evidence directory."""

    def __init__(
        self,
        root: Path,
        repository_root: Path,
        root_fd: int,
        limits: EvidenceLimits,
    ) -> None:
        self.root = root
        self.repository_root = repository_root
        self._root_fd = root_fd
        root_metadata = os.fstat(root_fd)
        self._root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        self.limits = limits
        self._files = 0
        self._directories = 0
        self._bytes = 0
        self._inventory: frozenset[str] = frozenset()
        self._refresh_inventory()

    @classmethod
    def create(
        cls,
        root: Path,
        *,
        repository_root: Path,
        limits: EvidenceLimits | None = None,
    ) -> EvidenceWorkspace:
        """Create or securely open an external owner-only workspace."""

        _require_supported_platform()
        selected_limits = limits or EvidenceLimits()
        if not isinstance(selected_limits, EvidenceLimits):
            raise EvidenceWorkspaceError("limits must be an EvidenceLimits instance")
        selected_limits.validate()
        root_parts = _validate_absolute_path(root, "evidence root")
        repo_parts = _validate_absolute_path(repository_root, "repository root")
        canonical_root = Path(os.path.sep).joinpath(*root_parts)
        canonical_repo = Path(os.path.sep).joinpath(*repo_parts)
        repo_fd = _open_absolute_directory(
            canonical_repo, create_final=False, private_final=False
        )
        repo_metadata = os.fstat(repo_fd)
        repo_identity = (repo_metadata.st_dev, repo_metadata.st_ino)
        os.close(repo_fd)
        resolved_repo = canonical_repo.resolve(strict=True)
        if _path_is_within(canonical_root, resolved_repo):
            raise EvidenceWorkspaceError(
                "evidence root must be outside the source repository"
            )
        root_fd = _open_absolute_directory(
            canonical_root, create_final=True, private_final=True
        )
        try:
            resolved_root = canonical_root.resolve(strict=True)
            root_metadata = os.fstat(root_fd)
            if (root_metadata.st_dev, root_metadata.st_ino) == repo_identity:
                raise EvidenceWorkspaceError(
                    "evidence root must not alias the source repository"
                )
            if _path_is_within(resolved_root, resolved_repo):
                raise EvidenceWorkspaceError(
                    "evidence root must be outside the source repository"
                )
            return cls(
                resolved_root,
                resolved_repo,
                root_fd,
                selected_limits,
            )
        except BaseException:
            os.close(root_fd)
            raise

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> EvidenceWorkspace:
        if self._root_fd < 0:
            raise EvidenceWorkspaceError("evidence workspace is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._root_fd < 0:
            raise EvidenceWorkspaceError("evidence workspace is closed")
        _check_owned_directory(os.fstat(self._root_fd), str(self.root))
        rebound = _open_absolute_directory(
            self.root, create_final=False, private_final=True
        )
        try:
            metadata = os.fstat(rebound)
            if (metadata.st_dev, metadata.st_ino) != self._root_identity:
                raise EvidenceWorkspaceError(
                    "evidence root path no longer names the opened workspace"
                )
        finally:
            os.close(rebound)

    def _refresh_inventory(self) -> None:
        self._require_open()
        files = 0
        directories = 1
        total = 0
        inventory: set[str] = set()

        def scan(directory_fd: int, label: str, relative: str, depth: int) -> None:
            nonlocal files, directories, total
            aliases = _directory_entries(directory_fd, label)
            for name in sorted(
                aliases.values(), key=lambda value: value.encode("utf-8")
            ):
                try:
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    raise EvidenceWorkspaceError(
                        f"cannot inspect evidence entry {label}/{name}: {error}"
                    ) from error
                child_label = f"{label}/{name}"
                if stat.S_ISDIR(metadata.st_mode):
                    if depth >= self.limits.max_path_depth:
                        raise EvidenceWorkspaceError(
                            "evidence directory depth limit exceeded"
                        )
                    _check_owned_directory(metadata, child_label)
                    directories += 1
                    if directories > self.limits.max_directories:
                        raise EvidenceWorkspaceError(
                            "evidence directory limit exceeded"
                        )
                    try:
                        child_fd = os.open(
                            name,
                            _DIRECTORY_FLAGS | _NOFOLLOW | _CLOEXEC,
                            dir_fd=directory_fd,
                        )
                    except OSError as error:
                        raise EvidenceWorkspaceError(
                            f"cannot securely open evidence directory {child_label}: {error}"
                        ) from error
                    try:
                        child_relative = f"{relative}/{name}" if relative else name
                        scan(child_fd, child_label, child_relative, depth + 1)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise EvidenceWorkspaceError(
                        f"evidence entry is not a regular file: {child_label}"
                    )
                if metadata.st_uid != os.geteuid():
                    raise EvidenceWorkspaceError(
                        f"evidence file is not owned by the effective user: {child_label}"
                    )
                if stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise EvidenceWorkspaceError(
                        f"evidence file is not owner-only: {child_label}"
                    )
                if metadata.st_nlink != 1:
                    raise EvidenceWorkspaceError(
                        f"evidence file is hardlinked: {child_label}"
                    )
                if (
                    metadata.st_size < 0
                    or metadata.st_size > self.limits.max_file_bytes
                ):
                    raise EvidenceWorkspaceError(
                        f"evidence file exceeds the per-file limit: {child_label}"
                    )
                files += 1
                total += metadata.st_size
                inventory.add(f"{relative}/{name}" if relative else name)
                if files > self.limits.max_files:
                    raise EvidenceWorkspaceError("evidence file-count limit exceeded")
                if total > self.limits.max_total_bytes:
                    raise EvidenceWorkspaceError("evidence total-byte limit exceeded")

        scan(self._root_fd, str(self.root), "", 0)
        self._files = files
        self._directories = directories
        self._bytes = total
        self._inventory = frozenset(inventory)

    def read_files(
        self,
        relatives: set[str] | frozenset[str],
        *,
        strict_read_only: bool = True,
    ) -> dict[str, bytes]:
        """Read one exact inventory through held directory descriptors.

        Each file is opened relative to the pinned workspace descriptor with
        ``O_NOFOLLOW`` and checked for stable identity before and after the read.
        The inventory is refreshed before and after the snapshot so callers never
        continue from pathname-based reads of an audited workspace.
        """

        if not isinstance(relatives, (set, frozenset)) or not all(
            isinstance(relative, str) for relative in relatives
        ):
            raise EvidenceWorkspaceError("snapshot inventory must be a set of paths")
        if not isinstance(strict_read_only, bool):
            raise EvidenceWorkspaceError("strict_read_only must be boolean")
        requested: set[str] = set()
        aliases: set[str] = set()
        for relative in relatives:
            parts = safe_relative_path(relative, max_depth=self.limits.max_path_depth)
            canonical = "/".join(parts)
            alias = _portable_key(canonical)
            if alias in aliases:
                raise EvidenceWorkspaceError(
                    f"snapshot inventory has a portable collision: {canonical}"
                )
            aliases.add(alias)
            requested.add(canonical)
        self._refresh_inventory()
        if self._inventory != requested:
            raise EvidenceWorkspaceError(
                "evidence snapshot inventory mismatch; "
                f"missing={sorted(requested - set(self._inventory))}, "
                f"extra={sorted(set(self._inventory) - requested)}"
            )
        payloads: dict[str, bytes] = {}
        total = 0
        for relative in sorted(requested, key=lambda value: value.encode("utf-8")):
            parts = safe_relative_path(relative, max_depth=self.limits.max_path_depth)
            directory_fd = os.dup(self._root_fd)
            file_fd = -1
            try:
                for segment in parts[:-1]:
                    if not _exact_entry(directory_fd, segment, relative):
                        raise EvidenceWorkspaceError(
                            f"snapshot directory disappeared: {relative}"
                        )
                    following = os.open(
                        segment,
                        _DIRECTORY_FLAGS | _NOFOLLOW | _CLOEXEC,
                        dir_fd=directory_fd,
                    )
                    _check_owned_directory(os.fstat(following), relative)
                    os.close(directory_fd)
                    directory_fd = following
                final_name = parts[-1]
                if not _exact_entry(directory_fd, final_name, relative):
                    raise EvidenceWorkspaceError(
                        f"snapshot file disappeared: {relative}"
                    )
                file_fd = os.open(final_name, _FILE_READ_FLAGS, dir_fd=directory_fd)
                before = os.fstat(file_fd)
                allowed_modes = {0o400} if strict_read_only else {0o400, 0o600}
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) not in allowed_modes
                    or before.st_nlink != 1
                    or before.st_uid != os.geteuid()
                    or before.st_size < 0
                    or before.st_size > self.limits.max_file_bytes
                ):
                    raise EvidenceWorkspaceError(
                        f"snapshot file mode/type/link is invalid: {relative}"
                    )
                with os.fdopen(file_fd, "rb", closefd=True) as handle:
                    file_fd = -1
                    payload = _read_all_bounded(
                        handle, self.limits.max_file_bytes, relative
                    )
                    after = os.fstat(handle.fileno())
                stable_fields = (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
                if any(
                    getattr(before, field) != getattr(after, field)
                    for field in stable_fields
                ):
                    raise EvidenceWorkspaceError(
                        f"snapshot file changed while reading: {relative}"
                    )
                payloads[relative] = payload
                total += len(payload)
                if total > self.limits.max_total_bytes:
                    raise EvidenceWorkspaceError("snapshot total-byte limit exceeded")
            except OSError as error:
                raise EvidenceWorkspaceError(
                    f"cannot read snapshot file {relative}: {error}"
                ) from error
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
                os.close(directory_fd)
        self._refresh_inventory()
        if self._inventory != requested:
            raise EvidenceWorkspaceError("evidence inventory changed during snapshot")
        return payloads

    def _open_parent(self, relative: str) -> tuple[int, str]:
        self._require_open()
        parts = safe_relative_path(relative, max_depth=self.limits.max_path_depth)
        current = os.dup(self._root_fd)
        try:
            for part in parts[:-1]:
                exists = _exact_entry(current, part, relative)
                if not exists:
                    if self._directories >= self.limits.max_directories:
                        raise EvidenceWorkspaceError(
                            "evidence directory limit exceeded"
                        )
                    try:
                        os.mkdir(part, 0o700, dir_fd=current)
                        os.fsync(current)
                    except OSError as error:
                        raise EvidenceWorkspaceError(
                            f"cannot create evidence directory {part!r}: {error}"
                        ) from error
                    self._directories += 1
                try:
                    following = os.open(
                        part,
                        _DIRECTORY_FLAGS | _NOFOLLOW | _CLOEXEC,
                        dir_fd=current,
                    )
                except OSError as error:
                    raise EvidenceWorkspaceError(
                        f"cannot securely traverse evidence directory {part!r}: {error}"
                    ) from error
                _check_owned_directory(os.fstat(following), part)
                os.close(current)
                current = following
            if _exact_entry(current, parts[-1], relative):
                raise EvidenceWorkspaceError(
                    f"refusing to overwrite existing evidence: {relative}"
                )
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def _publish(self, relative: str, payload: bytes, *, read_only: bool) -> Attachment:
        self._refresh_inventory()
        if len(payload) > self.limits.max_file_bytes:
            raise EvidenceWorkspaceError("evidence payload exceeds the per-file limit")
        if self._files >= self.limits.max_files:
            raise EvidenceWorkspaceError("evidence file-count limit exceeded")
        if self._bytes + len(payload) > self.limits.max_total_bytes:
            raise EvidenceWorkspaceError("evidence total-byte limit exceeded")
        parent_fd, final_name = self._open_parent(relative)
        temporary_name: str | None = None
        temporary_fd = -1
        published = False
        try:
            for _ in range(128):
                candidate = f"{_RESERVED_TEMP_PREFIX}{secrets.token_hex(16)}"
                try:
                    temporary_fd = os.open(
                        candidate, _FILE_CREATE_FLAGS, 0o600, dir_fd=parent_fd
                    )
                    temporary_name = candidate
                    break
                except FileExistsError:
                    continue
                except OSError as error:
                    raise EvidenceWorkspaceError(
                        f"cannot create private evidence temporary file: {error}"
                    ) from error
            if temporary_fd < 0 or temporary_name is None:
                raise EvidenceWorkspaceError(
                    "cannot allocate a unique evidence temporary file"
                )
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(temporary_fd, view[written:])
                if count <= 0:
                    raise EvidenceWorkspaceError("short write while creating evidence")
                written += count
            os.fsync(temporary_fd)
            os.fchmod(temporary_fd, 0o400 if read_only else 0o600)
            os.fsync(temporary_fd)
            metadata = os.fstat(temporary_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise EvidenceWorkspaceError("evidence temporary file changed type")
            try:
                os.link(
                    temporary_name,
                    final_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                published = True
            except FileExistsError as error:
                raise EvidenceWorkspaceError(
                    f"refusing to overwrite existing evidence: {relative}"
                ) from error
            except OSError as error:
                raise EvidenceWorkspaceError(
                    f"cannot atomically publish evidence {relative}: {error}"
                ) from error
            os.unlink(temporary_name, dir_fd=parent_fd)
            temporary_name = None
            os.fsync(parent_fd)
            final = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            expected_mode = 0o400 if read_only else 0o600
            if (
                not stat.S_ISREG(final.st_mode)
                or stat.S_IMODE(final.st_mode) != expected_mode
                or final.st_nlink != 1
                or final.st_uid != os.geteuid()
                or final.st_size != len(payload)
            ):
                raise EvidenceWorkspaceError(
                    f"published evidence failed final verification: {relative}"
                )
            self._files += 1
            self._bytes += len(payload)
            return Attachment(
                path=relative,
                sha256=hashlib.sha256(payload).hexdigest(),
                bytes=len(payload),
            )
        except BaseException:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except OSError:
                    pass
            if published:
                try:
                    os.unlink(final_name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError:
                    pass
            raise
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            os.close(parent_fd)

    def write_json(
        self, relative: str, value: Any, *, read_only: bool = True
    ) -> Attachment:
        """Atomically publish create-new canonical JSON as 0400 (or 0600)."""

        if not isinstance(read_only, bool):
            raise EvidenceWorkspaceError("read_only must be boolean")
        payload = canonical_json_bytes(value)
        if len(payload) > self.limits.max_json_bytes:
            raise EvidenceWorkspaceError("canonical JSON exceeds the JSON byte limit")
        return self._publish(relative, payload, read_only=read_only)

    def attach_file(
        self,
        source: Path,
        relative: str,
        *,
        read_only: bool = True,
        expected_sha256: str | None = None,
        expected_bytes: int | None = None,
    ) -> Attachment:
        """Copy a stable private source file into a create-new evidence path.

        Optional expected content bindings are checked after the stable read and
        before any destination is created.
        """

        if not isinstance(read_only, bool):
            raise EvidenceWorkspaceError("read_only must be boolean")
        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise EvidenceWorkspaceError(
                "expected attachment SHA-256 must be 64 lowercase hexadecimal characters"
            )
        if expected_bytes is not None and (
            isinstance(expected_bytes, bool)
            or not isinstance(expected_bytes, int)
            or expected_bytes < 0
            or expected_bytes > self.limits.max_file_bytes
        ):
            raise EvidenceWorkspaceError(
                "expected attachment byte count is invalid or exceeds the file limit"
            )
        self._refresh_inventory()
        file_fd, before = _open_absolute_regular(source, self.limits.max_file_bytes)
        try:
            with os.fdopen(file_fd, "rb", closefd=True) as handle:
                payload = _read_all_bounded(
                    handle, self.limits.max_file_bytes, str(source)
                )
                after = os.fstat(handle.fileno())
        except OSError as error:
            raise EvidenceWorkspaceError(
                f"cannot read attachment source {source}: {error}"
            ) from error
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise EvidenceWorkspaceError(
                f"attachment source changed while reading: {source}"
            )
        if expected_bytes is not None and len(payload) != expected_bytes:
            raise EvidenceWorkspaceError(
                f"attachment source byte count differs from validated content: {source}"
            )
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise EvidenceWorkspaceError(
                f"attachment source SHA-256 differs from validated content: {source}"
            )
        return self._publish(relative, payload, read_only=read_only)
