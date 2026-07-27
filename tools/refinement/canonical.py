"""Strict JSON, canonical bytes, content identities, and safe relative paths."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64
# A full 30-task x nine-stratum x two-seed paired comparison carries three
# independently derived metric vectors per pair. The 16 MiB byte cap remains
# the primary bound; one million JSON nodes admits that qualified shape without
# admitting unbounded parsing.
MAX_ITEMS = 1_000_000
MAX_STRING_BYTES = 1024 * 1024
MAX_KEY_BYTES = 256
MAX_PATH_BYTES = 4096
MAX_PATH_SEGMENTS = 32


class CanonicalError(ValueError):
    """Input is not bounded strict JSON or a safe portable path."""


def _reject_constant(value: str) -> None:
    raise CanonicalError(f"non-finite JSON number is forbidden: {value}")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _validate_tree(
    value: Any, *, depth: int = 0, counter: list[int] | None = None
) -> None:
    if counter is None:
        counter = [0]
    if depth > MAX_DEPTH:
        raise CanonicalError("JSON nesting exceeds the depth limit")
    counter[0] += 1
    if counter[0] > MAX_ITEMS:
        raise CanonicalError("JSON item count exceeds the limit")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError("non-finite JSON number is forbidden")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="strict")) > MAX_STRING_BYTES:
            raise CanonicalError("JSON string exceeds the byte limit")
        return
    if isinstance(value, list):
        for item in value:
            _validate_tree(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("JSON object keys must be strings")
            if len(key.encode("utf-8", errors="strict")) > MAX_KEY_BYTES:
                raise CanonicalError("JSON object key exceeds the byte limit")
            _validate_tree(item, depth=depth + 1, counter=counter)
        return
    raise CanonicalError(f"value is not JSON: {type(value).__name__}")


def loads(payload: bytes, *, maximum_bytes: int = MAX_JSON_BYTES) -> Any:
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes < 1
        or maximum_bytes > MAX_JSON_BYTES
    ):
        raise CanonicalError("JSON byte limit is invalid")
    if not isinstance(payload, bytes) or len(payload) > maximum_bytes:
        raise CanonicalError("JSON payload exceeds the byte limit")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise CanonicalError("JSON must not contain a UTF-8 byte-order mark")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalError("JSON is not strict UTF-8 JSON") from error
    _validate_tree(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _validate_tree(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CanonicalError("value cannot be represented as canonical JSON") from error


def sha256_bytes(payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise CanonicalError("SHA-256 input must be bytes")
    return hashlib.sha256(payload).hexdigest()


def multihash_bytes(payload: bytes) -> str:
    return "1220" + sha256_bytes(payload)


def identity(value: Any) -> str:
    return multihash_bytes(canonical_bytes(value))


def secure_read(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> bytes:
    if not path.is_absolute():
        raise CanonicalError("secure input path must be absolute")
    if path.is_symlink():
        raise CanonicalError("secure input must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CanonicalError("cannot securely open input") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise CanonicalError("input is not a bounded single-link regular file")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            while remaining > 0:
                chunk = stream.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(stream.fileno())
        if remaining == 0:
            raise CanonicalError("input exceeds the byte limit")
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise CanonicalError("input changed while it was read")
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_file(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> Any:
    return loads(secure_read(path, maximum_bytes=maximum_bytes))


def safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise CanonicalError("path must be a non-empty string")
    if value != unicodedata.normalize("NFC", value):
        raise CanonicalError("path must be NFC-normalized")
    if "\\" in value or "\x00" in value or value.startswith("/") or value.endswith("/"):
        raise CanonicalError("path must be canonical relative POSIX syntax")
    if len(value.encode("utf-8", errors="strict")) > MAX_PATH_BYTES:
        raise CanonicalError("path exceeds the byte limit")
    path = PurePosixPath(value)
    if path.is_absolute() or len(path.parts) > MAX_PATH_SEGMENTS:
        raise CanonicalError("path is absolute or exceeds the segment limit")
    for segment in path.parts:
        if (
            segment in {"", ".", ".."}
            or len(segment.encode("utf-8")) > 255
            or any(
                ord(character) < 32 or ord(character) == 127 for character in segment
            )
        ):
            raise CanonicalError("path contains an unsafe segment")
    canonical = path.as_posix()
    if canonical != value:
        raise CanonicalError("path is not lexically canonical")
    return canonical
