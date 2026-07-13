#!/usr/bin/env python3
"""Assemble and offline-verify the signed initial-beta release inventory.

This module never creates signing keys and never executes release artifacts.  The
workflow is deliberately split so an external signer can authorize the exact
canonical release-evidence document produced by ``plan`` before ``assemble``
materializes a create-new, owner-only release directory.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import beta_artifacts
import beta_profile
from evidence_workspace import EvidenceLimits, EvidenceWorkspace, EvidenceWorkspaceError
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    repo_root,
    safe_relative_path,
    sha256_bytes,
    sha256_file,
)
from signatures import public_key_id, verify as verify_signature


class BetaReleaseError(ReleaseError):
    """The beta release inputs or final inventory are not trustworthy."""


RELEASE_EVIDENCE_NAME = "release-evidence.json"
RELEASE_SIGNATURE_NAME = "release-evidence.json.sig.json"
TRUST_POLICY_SCHEMA = "cigar.beta.trust-policy.v1"
QUALIFICATION_POLICY_SCHEMA = "cigar.beta.qualification-policy.v1"
QUALIFICATION_SCHEMA = "cigar.beta.qualification-evidence.v1"
RELEASE_EVIDENCE_SCHEMA = "cigar.beta.release-evidence.v1"
QUALIFICATION_PURPOSE = "cigar-beta-qualification-evidence-v1"
RELEASE_EVIDENCE_PURPOSE = "cigar-beta-release-evidence-v1"

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_WORKSPACE_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 100_000
MAX_DIRECTORIES = 16_384
MAX_TAR_ENTRIES = 20_000
MAX_TAR_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TAR_TOTAL_BYTES = 256 * 1024 * 1024
MAX_TIMESTAMP = 253_402_300_799
MAX_CLOCK_SKEW_SECONDS = 300

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    public_key: Path
    signer_principal: str
    purposes: frozenset[str]
    status: str
    active_from: int
    active_until: int
    status_changed_at: int | None


@dataclass(frozen=True)
class TrustPolicy:
    policy_id: str
    digest: str
    keys: Mapping[str, TrustedKey]
    openssl_path: Path | None
    openssl_sha256: str
    valid_from: int
    valid_until: int


@dataclass(frozen=True)
class SignedPayload:
    path: Path
    final_path: str
    purpose: str

    def identity(self) -> tuple[str, str, int]:
        return (self.path.name, sha256_file(self.path), self.path.stat().st_size)


@dataclass(frozen=True)
class QualificationSet:
    receipts: tuple[dict[str, Any], ...]
    receipt_paths: tuple[tuple[Path, str], ...]
    attachment_paths: tuple[tuple[Path, str], ...]


@dataclass(frozen=True)
class SupportingSignatures:
    references: tuple[dict[str, object], ...]
    paths: tuple[tuple[Path, str], ...]


@dataclass
class PreparedInputs:
    temporary: tempfile.TemporaryDirectory[str]
    candidate: Path
    document: dict[str, object]
    qualification: QualificationSet
    signatures: SupportingSignatures
    trust: TrustPolicy

    def close(self) -> None:
        self.temporary.cleanup()


def _timestamp(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_TIMESTAMP
    ):
        raise BetaReleaseError(f"{label} is not a valid Unix timestamp")
    return value


def _current_verification_time(requested: object) -> int:
    supplied = _timestamp(requested, "verification time")
    current = int(time.time())
    if (
        supplied < current - MAX_CLOCK_SKEW_SECONDS
        or supplied > current + MAX_CLOCK_SKEW_SECONDS
    ):
        raise BetaReleaseError(
            "verification time is not current according to the trusted host clock"
        )
    return current


def _identity(
    value: object, label: str, *, pattern: re.Pattern[str] | None = None
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise BetaReleaseError(f"{label} is invalid")
    return value


def _canonical_document(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BetaReleaseError(f"{label} must be a regular, non-symlink file")
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_JSON_BYTES
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BetaReleaseError(f"{label} has unsafe metadata")
    before = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise BetaReleaseError(f"cannot read {label}: {error}") from error
    after_metadata = path.stat(follow_symlinks=False)
    after = (
        after_metadata.st_dev,
        after_metadata.st_ino,
        after_metadata.st_size,
        after_metadata.st_mtime_ns,
        after_metadata.st_ctime_ns,
    )
    if before != after:
        raise BetaReleaseError(f"{label} changed while it was read")
    try:
        document = load_json_bytes(payload, label)
    except ReleaseError as error:
        raise BetaReleaseError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(document, dict):
        raise BetaReleaseError(f"{label} is not a JSON object")
    if canonical_json_bytes(document) != payload:
        raise BetaReleaseError(f"{label} is not canonical JSON")
    return document


def _file_reference(path: Path, relative: str) -> dict[str, object]:
    safe_relative_path(relative)
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_FILE_BYTES
    ):
        raise BetaReleaseError(
            f"release input is not a bounded regular file: {relative}"
        )
    return {
        "path": relative,
        "sha256": sha256_file(path),
        "bytes": metadata.st_size,
    }


def _validate_reference(
    root: Path,
    reference: object,
    *,
    expected_path: str | None = None,
    maximum_bytes: int = MAX_FILE_BYTES,
) -> Path:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256", "bytes"}:
        raise BetaReleaseError("release file reference has an unexpected shape")
    relative = reference.get("path")
    if not isinstance(relative, str):
        raise BetaReleaseError("release file reference path is invalid")
    safe_relative_path(relative)
    if expected_path is not None and relative != expected_path:
        raise BetaReleaseError(f"release file reference path mismatch: {expected_path}")
    path = root.joinpath(*relative.split("/"))
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise BetaReleaseError(
            f"cannot resolve release file reference: {relative}"
        ) from error
    if resolved_root not in resolved.parents or path.is_symlink() or not path.is_file():
        raise BetaReleaseError(f"release file reference escapes its root: {relative}")
    metadata = path.stat(follow_symlinks=False)
    digest = reference.get("sha256")
    size = reference.get("bytes")
    if (
        not isinstance(digest, str)
        or _HEX_64.fullmatch(digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or size > maximum_bytes
        or metadata.st_size > maximum_bytes
        or digest != sha256_file(path)
        or size != metadata.st_size
    ):
        raise BetaReleaseError(f"release file reference bytes changed: {relative}")
    return path


def _secure_inventory(
    root: Path,
    *,
    label: str,
    require_private_root: bool = True,
) -> set[str]:
    if not root.is_absolute() or root != Path(os.path.normpath(root)):
        raise BetaReleaseError(f"{label} path must be absolute and canonical")
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise BetaReleaseError(f"cannot resolve {label}: {error}") from error
    root_metadata = root.stat(follow_symlinks=False)
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise BetaReleaseError(f"{label} must be a non-symlink directory")
    if require_private_root and (
        root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise BetaReleaseError(f"{label} must be owner-controlled with mode 0700")
    files: set[str] = set()
    portable_paths: set[str] = set()
    directory_count = 0
    total = 0
    nonempty_directories: set[Path] = set()
    observed_directories: set[Path] = {resolved}
    for current, directories, names in os.walk(
        resolved, topdown=True, followlinks=False
    ):
        directory_count += 1
        if directory_count > MAX_DIRECTORIES:
            raise BetaReleaseError(f"{label} directory limit exceeded")
        current_path = Path(current)
        current_metadata = current_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(current_metadata.st_mode)
            or current_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(current_metadata.st_mode) != 0o700
        ):
            raise BetaReleaseError(f"{label} contains an unsafe directory")
        directories.sort(key=lambda value: value.encode("utf-8"))
        names.sort(key=lambda value: value.encode("utf-8"))
        for name in directories:
            relative = (current_path / name).relative_to(resolved).as_posix()
            safe_relative_path(relative)
            portable = unicodedata.normalize("NFC", relative).casefold()
            if (
                relative != unicodedata.normalize("NFC", relative)
                or portable in portable_paths
            ):
                raise BetaReleaseError(f"{label} contains a path collision: {relative}")
            portable_paths.add(portable)
            child = current_path / name
            if child.is_symlink():
                raise BetaReleaseError(
                    f"{label} contains a symlink directory: {relative}"
                )
            observed_directories.add(child)
        for name in names:
            path = current_path / name
            relative = path.relative_to(resolved).as_posix()
            safe_relative_path(relative)
            portable = unicodedata.normalize("NFC", relative).casefold()
            if (
                relative != unicodedata.normalize("NFC", relative)
                or portable in portable_paths
            ):
                raise BetaReleaseError(f"{label} contains a path collision: {relative}")
            portable_paths.add(portable)
            metadata = path.stat(follow_symlinks=False)
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_size < 0
                or metadata.st_size > MAX_FILE_BYTES
            ):
                raise BetaReleaseError(f"{label} contains an unsafe file: {relative}")
            total += metadata.st_size
            if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                raise BetaReleaseError(f"{label} file or byte limit exceeded")
            files.add(relative)
            parent = path.parent
            while parent != resolved:
                nonempty_directories.add(parent)
                parent = parent.parent
            nonempty_directories.add(resolved)
    empty = observed_directories - nonempty_directories
    if empty:
        paths = sorted(path.relative_to(resolved).as_posix() for path in empty)
        raise BetaReleaseError(f"{label} contains empty directories: {paths}")
    return files


def _stable_file_bytes(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BetaReleaseError(f"cannot securely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        named_before = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 0
            or before.st_size > maximum
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
        ):
            raise BetaReleaseError(f"{label} is not a stable, bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise BetaReleaseError(f"{label} exceeds the fixed input bound")
        after = os.fstat(descriptor)
        named_after = path.stat(follow_symlinks=False)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise BetaReleaseError(f"{label} changed while it was snapshotted")
        if (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino):
            raise BetaReleaseError(f"{label} path changed while it was snapshotted")
        return b"".join(chunks)
    except OSError as error:
        raise BetaReleaseError(f"cannot read {label}: {error}") from error
    finally:
        os.close(descriptor)


def _write_snapshot_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o400)
    except OSError as error:
        raise BetaReleaseError(
            f"cannot create immutable input snapshot: {path}"
        ) from error


def _snapshot_files(
    source_root: Path,
    relatives: Sequence[str],
    destination: Path,
    *,
    label: str,
) -> Path:
    if not source_root.is_absolute() or source_root != Path(
        os.path.normpath(source_root)
    ):
        raise BetaReleaseError(f"{label} root must be absolute and canonical")
    source_root = source_root.resolve(strict=True)
    root_before = source_root.stat(follow_symlinks=False)
    if source_root.is_symlink() or not stat.S_ISDIR(root_before.st_mode):
        raise BetaReleaseError(f"{label} root is not a stable directory")
    destination.mkdir(mode=0o700)
    unique = tuple(sorted(set(relatives), key=lambda value: value.encode("utf-8")))
    if len(unique) != len(relatives):
        raise BetaReleaseError(f"{label} inventory contains duplicate paths")
    captured: dict[str, bytes] = {}
    total = 0
    for relative in unique:
        safe_relative_path(relative)
        source = source_root.joinpath(*relative.split("/"))
        try:
            resolved = source.resolve(strict=True)
        except OSError as error:
            raise BetaReleaseError(
                f"cannot resolve {label} input: {relative}"
            ) from error
        if source_root not in resolved.parents:
            raise BetaReleaseError(f"{label} input escapes its root: {relative}")
        payload = _stable_file_bytes(
            source, MAX_FILE_BYTES, f"{label} input {relative}"
        )
        total += len(payload)
        if total > MAX_TOTAL_BYTES:
            raise BetaReleaseError(f"{label} snapshot exceeds the total byte bound")
        captured[relative] = payload
        _write_snapshot_file(destination.joinpath(*relative.split("/")), payload)
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
    ):
        os.chmod(directory, 0o700)
    for relative, expected in captured.items():
        observed = _stable_file_bytes(
            source_root.joinpath(*relative.split("/")),
            MAX_FILE_BYTES,
            f"{label} input {relative}",
        )
        if observed != expected:
            raise BetaReleaseError(f"{label} changed while its snapshot was assembled")
    root_after = source_root.stat(follow_symlinks=False)
    stable_root = ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
    if any(
        getattr(root_before, field) != getattr(root_after, field)
        for field in stable_root
    ):
        raise BetaReleaseError(f"{label} root changed while its snapshot was assembled")
    observed = _secure_inventory(destination, label=f"immutable {label} snapshot")
    if observed != set(unique):
        raise BetaReleaseError(f"immutable {label} snapshot inventory mismatch")
    return destination


def _snapshot_directory(source: Path, destination: Path, *, label: str) -> Path:
    inventory = _secure_inventory(source, label=label)
    snapshot = _snapshot_files(
        source,
        tuple(inventory),
        destination,
        label=label,
    )
    if _secure_inventory(source, label=label) != inventory:
        raise BetaReleaseError(f"{label} inventory changed while it was snapshotted")
    return snapshot


def _snapshot_trust_policy(path: Path, destination: Path) -> Path:
    document = _canonical_document(path, "beta trust policy")
    entries = document.get("keys")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise BetaReleaseError("beta trust policy public-root inventory is invalid")
    relatives = [path.name]
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("public_key"), str):
            raise BetaReleaseError("beta trust policy public-root reference is invalid")
        relative = entry["public_key"]
        safe_relative_path(relative)
        relatives.append(relative)
    _snapshot_files(path.parent, relatives, destination, label="beta trust policy")
    return destination / path.name


def _load_trust_policy(
    path: Path, verification_time: int, openssl_path: Path | None = None
) -> TrustPolicy:
    document = _canonical_document(path, "beta trust policy")
    required = {
        "schema_version",
        "policy_id",
        "release_profile",
        "product_version",
        "approved_at",
        "valid_from",
        "valid_until",
        "signature_verifier",
        "keys",
    }
    if (
        set(document) != required
        or document.get("schema_version") != TRUST_POLICY_SCHEMA
    ):
        raise BetaReleaseError("beta trust policy has an unexpected shape or schema")
    if (
        document.get("release_profile") != beta_profile.PROFILE_ID
        or document.get("product_version") != beta_profile.VERSION
    ):
        raise BetaReleaseError(
            "beta trust policy is for a different profile or version"
        )
    policy_id = _identity(
        document.get("policy_id"), "trust policy id", pattern=_IDENTIFIER
    )
    approved_at = _timestamp(document.get("approved_at"), "trust policy approval time")
    valid_from = _timestamp(document.get("valid_from"), "trust policy activation time")
    valid_until = _timestamp(document.get("valid_until"), "trust policy expiry time")
    if not valid_from <= approved_at <= verification_time < valid_until:
        raise BetaReleaseError(
            "beta trust policy is unapproved or outside its validity window"
        )
    if not valid_from <= verification_time < valid_until:
        raise BetaReleaseError("beta trust policy is not valid at verification time")
    verifier = document.get("signature_verifier")
    if (
        not isinstance(verifier, dict)
        or set(verifier) != {"implementation", "sha256"}
        or verifier.get("implementation") != "openssl"
        or not isinstance(verifier.get("sha256"), str)
        or _HEX_64.fullmatch(verifier["sha256"]) is None
    ):
        raise BetaReleaseError("beta trust policy signature verifier is invalid")
    openssl_sha256 = verifier["sha256"]
    entries = document.get("keys")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise BetaReleaseError("beta trust policy contains no public roots")
    allowed_purposes = set(beta_profile.BETA_SIGNATURE_PURPOSES)
    keys: dict[str, TrustedKey] = {}
    key_paths: set[Path] = set()
    required_key = {
        "key_id",
        "public_key",
        "public_key_sha256",
        "signer_principal",
        "purposes",
        "status",
        "active_from",
        "active_until",
        "status_changed_at",
    }
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required_key:
            raise BetaReleaseError("beta trust-policy key has an unexpected shape")
        identifier = entry.get("key_id")
        if (
            not isinstance(identifier, str)
            or not identifier.startswith("sha256:")
            or _HEX_64.fullmatch(identifier.removeprefix("sha256:")) is None
            or identifier in keys
        ):
            raise BetaReleaseError(
                "beta trust policy has an invalid or duplicate key id"
            )
        relative = entry.get("public_key")
        if not isinstance(relative, str):
            raise BetaReleaseError("trusted public-key path is invalid")
        safe_relative_path(relative)
        key_path = path.parent.joinpath(*relative.split("/"))
        try:
            resolved_parent = path.parent.resolve(strict=True)
            resolved_key = key_path.resolve(strict=True)
        except OSError as error:
            raise BetaReleaseError(
                f"cannot resolve trusted public key: {relative}"
            ) from error
        if (
            resolved_parent not in resolved_key.parents
            or key_path.is_symlink()
            or not key_path.is_file()
            or resolved_key in key_paths
        ):
            raise BetaReleaseError(f"trusted public-key path is unsafe: {relative}")
        key_paths.add(resolved_key)
        key_metadata = key_path.stat(follow_symlinks=False)
        digest = entry.get("public_key_sha256")
        if (
            key_metadata.st_nlink != 1
            or stat.S_IMODE(key_metadata.st_mode) & 0o022
            or not isinstance(digest, str)
            or _HEX_64.fullmatch(digest) is None
            or sha256_file(key_path) != digest
            or public_key_id(
                key_path,
                openssl_path=openssl_path,
                openssl_sha256=openssl_sha256,
            )
            != identifier
        ):
            raise BetaReleaseError(f"trusted public-key binding is invalid: {relative}")
        principal = _identity(entry.get("signer_principal"), "trusted signer principal")
        purposes = entry.get("purposes")
        if (
            not isinstance(purposes, list)
            or not purposes
            or purposes != sorted(purposes)
            or len(set(purposes)) != len(purposes)
            or any(
                not isinstance(purpose, str)
                or _PURPOSE.fullmatch(purpose) is None
                or purpose not in allowed_purposes
                for purpose in purposes
            )
        ):
            raise BetaReleaseError(f"trusted purpose scope is invalid: {identifier}")
        status = entry.get("status")
        if status not in {"active", "retired", "revoked"}:
            raise BetaReleaseError(f"trusted key status is invalid: {identifier}")
        active_from = _timestamp(
            entry.get("active_from"), "trusted-key activation time"
        )
        active_until = _timestamp(entry.get("active_until"), "trusted-key expiry time")
        if active_until <= active_from:
            raise BetaReleaseError(
                f"trusted-key validity window is invalid: {identifier}"
            )
        changed_value = entry.get("status_changed_at")
        changed = (
            None
            if changed_value is None
            else _timestamp(changed_value, "trusted-key status-change time")
        )
        if status == "active" and changed is not None:
            raise BetaReleaseError(
                "active trusted key cannot have a status-change time"
            )
        if status != "active" and (
            changed is None or not active_from < changed <= active_until
        ):
            raise BetaReleaseError(
                "non-active trusted key has an invalid status-change time"
            )
        keys[identifier] = TrustedKey(
            key_id=identifier,
            public_key=key_path,
            signer_principal=principal,
            purposes=frozenset(purposes),
            status=status,
            active_from=active_from,
            active_until=active_until,
            status_changed_at=changed,
        )
    return TrustPolicy(
        policy_id=policy_id,
        digest=sha256_file(path),
        keys=keys,
        openssl_path=openssl_path,
        openssl_sha256=openssl_sha256,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _verify_envelope(
    envelope_path: Path,
    payload: Path,
    purpose: str,
    trust: TrustPolicy,
    verification_time: int,
) -> dict[str, Any]:
    envelope = _canonical_document(envelope_path, "beta signature envelope")
    try:
        beta_profile.validate_beta_signature_identity(envelope)
    except ReleaseError as error:
        raise BetaReleaseError(
            f"beta signature envelope is outside the profile: {error}"
        ) from error
    identifier = envelope.get("key_id")
    if not isinstance(identifier, str) or identifier not in trust.keys:
        raise BetaReleaseError("beta signature uses an untrusted public key")
    trusted = trust.keys[identifier]
    if trusted.status != "active":
        raise BetaReleaseError(
            f"beta signature uses a non-active ({trusted.status}) public key"
        )
    if not trusted.active_from <= verification_time < trusted.active_until:
        raise BetaReleaseError("beta signing key is not active at verification time")
    if purpose not in trusted.purposes:
        raise BetaReleaseError("beta signing key is outside its purpose scope")
    try:
        unsigned = verify_signature(
            envelope_path,
            payload,
            trusted.public_key,
            expected_purpose=purpose,
            expected_signer=trusted.signer_principal,
            verification_time=verification_time,
            openssl_path=trust.openssl_path,
            openssl_sha256=trust.openssl_sha256,
        )
    except ReleaseError as error:
        raise BetaReleaseError(
            f"beta detached signature failed verification: {error}"
        ) from error
    signed_at = _timestamp(unsigned.get("signed_at"), "signature signing time")
    if not trusted.active_from <= signed_at < trusted.active_until:
        raise BetaReleaseError("beta signature is outside trusted-key validity")
    return unsigned


def _revalidate_signature_times(
    trust: TrustPolicy,
    envelope_paths: Sequence[Path],
    verification_time: int,
) -> int:
    current = _timestamp(verification_time, "current verification time")
    if not trust.valid_from <= current < trust.valid_until:
        raise BetaReleaseError("beta trust policy expired during verification")
    for path in envelope_paths:
        envelope = _canonical_document(path, "beta signature envelope")
        identifier = envelope.get("key_id")
        trusted = trust.keys.get(identifier) if isinstance(identifier, str) else None
        if (
            trusted is None
            or trusted.status != "active"
            or not trusted.active_from <= current < trusted.active_until
        ):
            raise BetaReleaseError(
                "beta signing key became inactive during verification"
            )
        signed_at = _timestamp(envelope.get("signed_at"), "signature signing time")
        expires_at = envelope.get("expires_at")
        if signed_at > current or (
            expires_at is not None
            and current >= _timestamp(expires_at, "signature expiry time")
        ):
            raise BetaReleaseError("beta signature expired during verification")
    return current


def _candidate_paths() -> tuple[str, ...]:
    paths = beta_artifacts._expected_candidate_paths(include_verification=True)
    return tuple(sorted(paths, key=lambda value: value.encode("utf-8")))


def _candidate_signed_payloads(candidate: Path) -> tuple[SignedPayload, ...]:
    matrix = beta_profile.expected_artifact_matrix()
    result = [
        SignedPayload(
            path=candidate / f"artifacts/{entry['filename']}",
            final_path=f"artifacts/{entry['filename']}",
            purpose="cigar-beta-release-artifact-v1",
        )
        for entry in matrix["artifacts"]
    ]
    auxiliary = (
        (beta_artifacts.CHECKSUM_PATH, "cigar-beta-release-checksums-v1"),
        (beta_artifacts.SBOM_PATH, "cigar-beta-release-sbom-v1"),
        (beta_artifacts.PROVENANCE_PATH, "cigar-beta-release-provenance-v1"),
    )
    for relative, purpose in auxiliary:
        result.append(SignedPayload(candidate / relative, relative, purpose))
    spdx_path = getattr(beta_artifacts, "SPDX_PATH", None)
    if isinstance(spdx_path, str):
        result.append(
            SignedPayload(
                candidate / spdx_path,
                spdx_path,
                "cigar-beta-release-spdx-v1",
            )
        )
    for payload in result:
        if payload.final_path not in _candidate_paths() or not payload.path.is_file():
            raise BetaReleaseError(
                f"required signed beta payload is missing: {payload.final_path}"
            )
    return tuple(result)


def _candidate_manifest(candidate: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _canonical_document(
        candidate / beta_artifacts.BUILD_MANIFEST_PATH, "beta build manifest"
    )
    descriptor = _canonical_document(
        candidate / beta_artifacts.SOURCE_DESCRIPTOR_PATH, "beta source descriptor"
    )
    if (
        manifest.get("schema_version") != "cigar.beta.build-manifest.v1"
        or manifest.get("release_profile") != beta_profile.PROFILE_ID
        or manifest.get("product_version") != beta_profile.VERSION
        or manifest.get("tag") != beta_profile.TAG
        or manifest.get("prerelease") is not True
        or manifest.get("production_ready") is not False
    ):
        raise BetaReleaseError("beta build manifest identity is invalid")
    source = manifest.get("source")
    descriptor_git = descriptor.get("git")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree", "committed", "clean"}
        or not isinstance(descriptor_git, dict)
        or source.get("revision") != descriptor_git.get("revision")
        or source.get("tree") != descriptor_git.get("tree")
        or not isinstance(source.get("revision"), str)
        or _GIT_OBJECT.fullmatch(source["revision"]) is None
        or not isinstance(source.get("tree"), str)
        or _GIT_OBJECT.fullmatch(source["tree"]) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
        or descriptor_git.get("committed") is not True
        or descriptor_git.get("clean") is not True
    ):
        raise BetaReleaseError("beta source identity binding is invalid")
    artifacts = manifest.get("artifacts")
    matrix = beta_profile.expected_artifact_matrix()
    if not isinstance(artifacts, list) or len(artifacts) != len(matrix["artifacts"]):
        raise BetaReleaseError("beta manifest does not bind the exact artifact set")
    for record, entry in zip(artifacts, matrix["artifacts"], strict=True):
        expected_path = f"artifacts/{entry['filename']}"
        if (
            not isinstance(record, dict)
            or set(record) != {"id", "path", "sha256", "bytes", "contract", "status"}
            or record.get("id") != entry["id"]
            or record.get("path") != expected_path
            or record.get("contract") != entry["contract"]
            or record.get("status") != "passed"
        ):
            raise BetaReleaseError(
                f"beta artifact manifest binding is invalid: {entry['id']}"
            )
        _validate_reference(
            candidate,
            {
                "path": record["path"],
                "sha256": record["sha256"],
                "bytes": record["bytes"],
            },
            expected_path=expected_path,
        )
    return manifest, descriptor


def _extract_source_archive(
    archive: Path, destination: Path, epoch: int
) -> dict[str, beta_artifacts.CommittedEntry]:
    metadata = archive.stat(follow_symlinks=False)
    if (
        metadata.st_size <= 0
        or metadata.st_size > beta_artifacts.MAX_SOURCE_ARCHIVE_BYTES
    ):
        raise BetaReleaseError(
            "signed beta source archive exceeds the fixed input bound"
        )
    archive_payload = _stable_file_bytes(
        archive,
        beta_artifacts.MAX_SOURCE_ARCHIVE_BYTES,
        "signed beta source archive",
    )
    beta_artifacts._validate_gzip_header(archive_payload, epoch)
    raw_limit = min(
        512 * 1024 * 1024,
        MAX_TAR_TOTAL_BYTES + MAX_TAR_ENTRIES * 8192 + tarfile.RECORDSIZE,
    )
    decompressor = zlib.decompressobj(wbits=31)
    expanded = bytearray()
    try:
        for offset in range(0, len(archive_payload), 1024 * 1024):
            remaining = raw_limit + 1 - len(expanded)
            if remaining <= 0:
                raise BetaReleaseError(
                    "signed source archive exceeds the raw expansion bound"
                )
            expanded.extend(
                decompressor.decompress(
                    archive_payload[offset : offset + 1024 * 1024], remaining
                )
            )
            if len(expanded) > raw_limit:
                raise BetaReleaseError(
                    "signed source archive exceeds the raw expansion bound"
                )
            if decompressor.unused_data:
                raise BetaReleaseError(
                    "signed source archive contains trailing or concatenated gzip data"
                )
        expanded.extend(decompressor.flush(raw_limit + 1 - len(expanded)))
    except zlib.error as error:
        raise BetaReleaseError(
            f"signed source archive gzip stream is invalid: {error}"
        ) from error
    if (
        len(expanded) > raw_limit
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise BetaReleaseError(
            "signed source archive is truncated, ambiguous, or exceeds expansion bounds"
        )
    destination.mkdir(mode=0o700)
    total = 0
    portable: set[str] = set()
    committed: dict[str, beta_artifacts.CommittedEntry] = {}
    names: list[str] = []
    canonical = io.BytesIO()
    try:
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=9, fileobj=canonical, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as canonical_archive:
                with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as handle:
                    for member in handle:
                        if len(names) >= MAX_TAR_ENTRIES:
                            raise BetaReleaseError(
                                "signed beta source archive entry count exceeds the fixed bound"
                            )
                        name = member.name
                        safe_relative_path(name)
                        if name != unicodedata.normalize("NFC", name):
                            raise BetaReleaseError(
                                "signed source archive path is not NFC-normalized"
                            )
                        alias = name.casefold()
                        if alias in portable:
                            raise BetaReleaseError(
                                "signed source archive contains a path collision"
                            )
                        portable.add(alias)
                        if (
                            not member.isfile()
                            or member.uid != 0
                            or member.gid != 0
                            or member.uname != ""
                            or member.gname != ""
                            or member.mtime != epoch
                            or member.mode not in {0o644, 0o755}
                            or set(member.pax_headers) - {"path"}
                            or member.size < 0
                            or member.size > MAX_TAR_MEMBER_BYTES
                        ):
                            raise BetaReleaseError(
                                "signed source archive contains a non-canonical member"
                            )
                        total += member.size
                        if total > MAX_TAR_TOTAL_BYTES:
                            raise BetaReleaseError(
                                "signed source archive exceeds extraction bounds"
                            )
                        extracted = handle.extractfile(member)
                        if extracted is None:
                            raise BetaReleaseError(
                                "cannot read signed source archive member"
                            )
                        payload = extracted.read(MAX_TAR_MEMBER_BYTES + 1)
                        if len(payload) != member.size:
                            raise BetaReleaseError(
                                "signed source archive member size changed"
                            )
                        information = tarfile.TarInfo(name)
                        information.size = len(payload)
                        information.mode = member.mode
                        information.mtime = epoch
                        information.uid = 0
                        information.gid = 0
                        information.uname = ""
                        information.gname = ""
                        canonical_archive.addfile(information, io.BytesIO(payload))
                        names.append(name)
                        if name == "RELEASE-METADATA.json":
                            continue
                        output = destination.joinpath(*name.split("/"))
                        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        try:
                            with output.open("xb") as destination_file:
                                destination_file.write(payload)
                                destination_file.flush()
                                os.fsync(destination_file.fileno())
                            os.chmod(output, 0o400)
                        except OSError as error:
                            raise BetaReleaseError(
                                f"cannot materialize signed source input: {name}"
                            ) from error
                        committed[name] = beta_artifacts.CommittedEntry(
                            name,
                            payload,
                            member.mode,
                        )
    except (OSError, tarfile.TarError) as error:
        raise BetaReleaseError(
            f"cannot parse signed beta source archive: {error}"
        ) from error
    if not names or names != sorted(names, key=lambda value: value.encode("utf-8")):
        raise BetaReleaseError("signed source archive member order is not canonical")
    if canonical.getvalue() != archive_payload:
        raise BetaReleaseError(
            "signed source archive is not the canonical gzip/PAX byte representation"
        )
    if not committed:
        raise BetaReleaseError("signed beta source archive contains no source inputs")
    return committed


def _copy_candidate_subset(candidate: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for relative in _candidate_paths():
        source = candidate.joinpath(*relative.split("/"))
        target = destination.joinpath(*relative.split("/"))
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = source.stat(follow_symlinks=False)
        if (
            source.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > MAX_FILE_BYTES
        ):
            raise BetaReleaseError(f"candidate input is unsafe: {relative}")
        try:
            with source.open("rb") as input_file, target.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
                output_file.flush()
                os.fsync(output_file.fileno())
            os.chmod(target, 0o600)
        except OSError as error:
            raise BetaReleaseError(
                f"cannot materialize candidate input: {relative}"
            ) from error


def _verify_candidate_offline(candidate: Path) -> dict[str, object]:
    manifest, descriptor = _candidate_manifest(candidate)
    source = manifest["source"]
    source_epoch = _timestamp(manifest.get("source_date_epoch"), "source date epoch")
    generated_at = descriptor.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise BetaReleaseError("beta source descriptor timestamp is invalid")
    snapshot = beta_artifacts.GitSnapshot(
        revision=source["revision"],
        tree=source["tree"],
        source_date_epoch=source_epoch,
        generated_at=generated_at,
    )
    source_entry = beta_profile.expected_artifact_matrix()["artifacts"][0]
    source_archive = candidate / f"artifacts/{source_entry['filename']}"
    with tempfile.TemporaryDirectory(prefix="cigar-beta-offline-") as raw:
        temporary = Path(raw)
        os.chmod(temporary, 0o700)
        source_root = temporary / "source"
        candidate_copy = temporary / "candidate"
        committed = _extract_source_archive(source_archive, source_root, source_epoch)
        _copy_candidate_subset(candidate, candidate_copy)
        try:
            report = beta_artifacts.verify_beta_candidate(
                root=source_root,
                candidate=candidate_copy,
                strict_read_only=False,
                execute_binary=False,
                snapshot_override=snapshot,
                committed_override=committed,
                require_recorded_verification=True,
            )
        except ReleaseError as error:
            raise BetaReleaseError(
                f"offline beta candidate verification failed: {error}"
            ) from error
    if (
        report.get("status") != "passed"
        or report.get("source_revision") != source["revision"]
    ):
        raise BetaReleaseError(
            "offline beta candidate verification returned a stale report"
        )
    checks = report.get("checks")
    if not isinstance(checks, dict) or checks.get("binary_executed") is not False:
        raise BetaReleaseError(
            "offline beta verification unexpectedly executed the binary"
        )
    return report


def _artifact_records(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    records = manifest.get("artifacts")
    if not isinstance(records, list):
        raise BetaReleaseError("beta artifact records are missing")
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            raise BetaReleaseError("beta artifact record is invalid")
        identifier = record["id"]
        if identifier in result:
            raise BetaReleaseError("beta artifact ids are duplicated")
        result[identifier] = record
    return result


def _validate_metrics(metrics: object) -> dict[str, int]:
    if not isinstance(metrics, dict) or len(metrics) > 4096:
        raise BetaReleaseError("qualification metrics are invalid")
    result: dict[str, int] = {}
    for key, value in metrics.items():
        if (
            not isinstance(key, str)
            or _IDENTIFIER.fullmatch(key) is None
            or isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < (1 << 63)
        ):
            raise BetaReleaseError("qualification metric name or value is invalid")
        result[key] = value
    return result


def _qualification_policy() -> dict[str, dict[str, Any]]:
    policy = beta_profile.expected_qualification_policy()
    if (
        not isinstance(policy, dict)
        or set(policy)
        != {"schema_version", "release_profile", "product_version", "categories"}
        or policy.get("schema_version") != QUALIFICATION_POLICY_SCHEMA
        or policy.get("release_profile") != beta_profile.PROFILE_ID
        or policy.get("product_version") != beta_profile.VERSION
    ):
        raise BetaReleaseError("beta qualification policy identity is invalid")
    categories = policy.get("categories")
    if not isinstance(categories, list) or not 1 <= len(categories) <= 64:
        raise BetaReleaseError("beta qualification policy categories are invalid")

    matrix = beta_profile.expected_artifact_matrix()
    matrix_artifacts = matrix.get("artifacts")
    if not isinstance(matrix_artifacts, list):
        raise BetaReleaseError("beta artifact matrix is invalid")
    artifact_ids: list[str] = []
    matrix_categories: dict[str, list[str]] = {}
    for artifact in matrix_artifacts:
        if not isinstance(artifact, dict):
            raise BetaReleaseError("beta artifact matrix entry is invalid")
        artifact_id = _identity(
            artifact.get("id"), "beta artifact id", pattern=_IDENTIFIER
        )
        qualification = artifact.get("qualification")
        if (
            artifact_id in artifact_ids
            or not isinstance(qualification, list)
            or not qualification
        ):
            raise BetaReleaseError("beta artifact matrix qualification is invalid")
        artifact_ids.append(artifact_id)
        for category in qualification:
            category_id = _identity(
                category, "beta qualification category", pattern=_IDENTIFIER
            )
            matrix_categories.setdefault(category_id, []).append(artifact_id)

    result: dict[str, dict[str, Any]] = {}
    observed_order: list[str] = []
    for category in categories:
        if not isinstance(category, dict) or set(category) != {
            "id",
            "artifact_ids",
            "required_checks",
            "metric_gates",
            "minimum_attachments",
        }:
            raise BetaReleaseError("beta qualification policy category is invalid")
        identifier = _identity(
            category.get("id"), "beta qualification category", pattern=_IDENTIFIER
        )
        bound_artifacts = category.get("artifact_ids")
        required_checks = category.get("required_checks")
        gates = category.get("metric_gates")
        minimum_attachments = category.get("minimum_attachments")
        if (
            identifier in result
            or not isinstance(bound_artifacts, list)
            or not bound_artifacts
            or len(bound_artifacts) > len(artifact_ids)
            or any(
                not isinstance(value, str) or value not in artifact_ids
                for value in bound_artifacts
            )
            or len(set(bound_artifacts)) != len(bound_artifacts)
            or bound_artifacts != matrix_categories.get(identifier)
            or not isinstance(required_checks, list)
            or not 1 <= len(required_checks) <= 64
            or not isinstance(gates, list)
            or not 1 <= len(gates) <= 64
            or isinstance(minimum_attachments, bool)
            or not isinstance(minimum_attachments, int)
            or not 1 <= minimum_attachments <= 4096
        ):
            raise BetaReleaseError(
                f"beta qualification policy binding is invalid: {identifier}"
            )
        check_ids = [
            _identity(value, "required qualification check", pattern=_IDENTIFIER)
            for value in required_checks
        ]
        if len(set(check_ids)) != len(check_ids) or check_ids != sorted(check_ids):
            raise BetaReleaseError(
                f"beta qualification policy checks are invalid: {identifier}"
            )
        gate_ids: list[str] = []
        for gate in gates:
            if not isinstance(gate, dict) or set(gate) != {
                "id",
                "type",
                "operator",
                "value",
            }:
                raise BetaReleaseError(
                    f"beta qualification metric gate is invalid: {identifier}"
                )
            gate_id = _identity(
                gate.get("id"), "qualification metric gate id", pattern=_IDENTIFIER
            )
            threshold = gate.get("value")
            if (
                gate.get("type") != "integer"
                or gate.get("operator") not in {"eq", "gte", "lte"}
                or isinstance(threshold, bool)
                or not isinstance(threshold, int)
                or not 0 <= threshold < (1 << 63)
            ):
                raise BetaReleaseError(
                    f"beta qualification metric gate is invalid: {identifier}"
                )
            gate_ids.append(gate_id)
        if len(set(gate_ids)) != len(gate_ids) or gate_ids != sorted(gate_ids):
            raise BetaReleaseError(
                f"beta qualification metric gates are invalid: {identifier}"
            )
        observed_order.append(identifier)
        result[identifier] = category
    if observed_order != sorted(observed_order) or set(result) != set(
        matrix_categories
    ):
        raise BetaReleaseError(
            "beta qualification policy category set is incomplete or unordered"
        )
    return result


def _qualification_policy_reference() -> dict[str, object]:
    document = beta_profile.expected_qualification_policy()
    return {
        "schema_version": QUALIFICATION_POLICY_SCHEMA,
        "path": beta_profile.MANIFEST_PATHS["qualification_policy"],
        "sha256": sha256_bytes(canonical_json_bytes(document)),
    }


def _enforce_metric_gates(
    metrics: object,
    gates: Sequence[Mapping[str, Any]],
    category: str,
) -> None:
    observed = _validate_metrics(metrics)
    expected_ids = [gate["id"] for gate in gates]
    if list(observed) != expected_ids:
        raise BetaReleaseError(
            f"qualification metric set is incomplete, extra, or unordered: {category}"
        )
    for gate in gates:
        value = observed[gate["id"]]
        threshold = gate["value"]
        operator = gate["operator"]
        passed = (
            value == threshold
            if operator == "eq"
            else value >= threshold
            if operator == "gte"
            else value <= threshold
        )
        if not passed:
            raise BetaReleaseError(
                f"qualification metric gate failed: {category}/{gate['id']}"
            )


def _validate_qualification(
    directory: Path,
    manifest: Mapping[str, Any],
) -> QualificationSet:
    inventory = _secure_inventory(directory, label="beta qualification workspace")
    receipt_files = sorted(
        (
            relative
            for relative in inventory
            if relative.startswith("receipts/") and relative.endswith(".json")
        ),
        key=lambda value: value.encode("utf-8"),
    )
    if not receipt_files or any(relative.count("/") != 1 for relative in receipt_files):
        raise BetaReleaseError(
            "qualification receipts must be direct canonical JSON files"
        )
    artifact_records = _artifact_records(manifest)
    policy_by_category = _qualification_policy()
    source = manifest["source"]
    source_record = artifact_records.get("source")
    if source_record is None:
        raise BetaReleaseError("beta source artifact record is missing")
    expected_source = {
        "revision": source["revision"],
        "tree": source["tree"],
        "archive": {
            "id": "source",
            "sha256": source_record["sha256"],
            "bytes": source_record["bytes"],
        },
    }
    receipts: list[dict[str, Any]] = []
    receipt_paths: list[tuple[Path, str]] = []
    attachment_paths: dict[str, tuple[Path, str]] = {}
    seen_ids: set[str] = set()
    seen_categories: set[str] = set()
    required_receipt = {
        "schema_version",
        "release_profile",
        "product_version",
        "evidence_purpose",
        "id",
        "category",
        "source",
        "status",
        "artifact_bindings",
        "producer",
        "checks",
        "metrics",
        "attachments",
    }
    for relative in receipt_files:
        path = directory.joinpath(*relative.split("/"))
        receipt = _canonical_document(path, f"qualification receipt {relative}")
        if set(receipt) != required_receipt:
            raise BetaReleaseError(
                f"qualification receipt has an unexpected shape: {relative}"
            )
        if (
            receipt.get("schema_version") != QUALIFICATION_SCHEMA
            or receipt.get("release_profile") != beta_profile.PROFILE_ID
            or receipt.get("product_version") != beta_profile.VERSION
            or receipt.get("evidence_purpose") != QUALIFICATION_PURPOSE
            or receipt.get("status") != "passed"
            or receipt.get("source") != expected_source
        ):
            raise BetaReleaseError(
                f"qualification identity/source/status mismatch: {relative}"
            )
        identifier = _identity(
            receipt.get("id"), "qualification receipt id", pattern=_IDENTIFIER
        )
        category = _identity(
            receipt.get("category"), "qualification category", pattern=_IDENTIFIER
        )
        if identifier in seen_ids or category in seen_categories:
            raise BetaReleaseError(
                "qualification receipt ids or categories are duplicated"
            )
        seen_ids.add(identifier)
        seen_categories.add(category)
        policy = policy_by_category.get(category)
        if policy is None:
            raise BetaReleaseError(
                f"qualification category is outside the beta matrix: {category}"
            )
        expected_ids = policy["artifact_ids"]
        expected_bindings = [
            {
                "id": artifact_id,
                "sha256": artifact_records[artifact_id]["sha256"],
                "bytes": artifact_records[artifact_id]["bytes"],
            }
            for artifact_id in expected_ids
        ]
        if receipt.get("artifact_bindings") != expected_bindings:
            raise BetaReleaseError(
                f"qualification artifact binding mismatch: {category}"
            )
        producer = receipt.get("producer")
        if not isinstance(producer, dict) or set(producer) != {
            "name",
            "version",
            "invocation_id",
        }:
            raise BetaReleaseError(f"qualification producer is invalid: {category}")
        for key in ("name", "version", "invocation_id"):
            _identity(producer.get(key), f"qualification producer {key}")
        checks = receipt.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= 4096:
            raise BetaReleaseError(f"qualification checks are missing: {category}")
        check_ids: list[str] = []
        for check in checks:
            if (
                not isinstance(check, dict)
                or set(check) != {"id", "status"}
                or check.get("status") != "passed"
            ):
                raise BetaReleaseError(
                    f"qualification contains a non-passing check: {category}"
                )
            check_ids.append(
                _identity(
                    check.get("id"), "qualification check id", pattern=_IDENTIFIER
                )
            )
        if check_ids != policy["required_checks"]:
            raise BetaReleaseError(
                f"qualification check set is incomplete, extra, or unordered: {category}"
            )
        _enforce_metric_gates(receipt.get("metrics"), policy["metric_gates"], category)
        attachments = receipt.get("attachments")
        if (
            not isinstance(attachments, list)
            or not policy["minimum_attachments"] <= len(attachments) <= 4096
        ):
            raise BetaReleaseError(f"qualification attachments are missing: {category}")
        observed_attachment_paths: list[str] = []
        for reference in attachments:
            attachment = _validate_reference(
                directory, reference, maximum_bytes=MAX_WORKSPACE_FILE_BYTES
            )
            attachment_relative = reference["path"]
            if not attachment_relative.startswith("attachments/"):
                raise BetaReleaseError(
                    "qualification attachment is outside attachments/"
                )
            if attachment_relative in attachment_paths:
                raise BetaReleaseError(
                    "qualification attachment is referenced more than once"
                )
            final_path = f"qualification/{attachment_relative}"
            attachment_paths[attachment_relative] = (attachment, final_path)
            observed_attachment_paths.append(attachment_relative)
        if observed_attachment_paths != sorted(observed_attachment_paths):
            raise BetaReleaseError(
                f"qualification attachments are not ordered: {category}"
            )
        receipts.append(receipt)
        receipt_paths.append((path, f"qualification/{relative}"))
    if seen_categories != set(policy_by_category):
        raise BetaReleaseError(
            "qualification category set is incomplete; "
            f"missing={sorted(set(policy_by_category) - seen_categories)}, "
            f"extra={sorted(seen_categories - set(policy_by_category))}"
        )
    discovered_attachments = {
        relative for relative in inventory if relative.startswith("attachments/")
    }
    expected_files = set(receipt_files) | set(attachment_paths)
    if inventory != expected_files or discovered_attachments != set(attachment_paths):
        raise BetaReleaseError(
            "qualification workspace inventory is incomplete or contains extras"
        )
    ordered = sorted(
        zip(receipts, receipt_paths, strict=True),
        key=lambda item: (item[0]["category"], item[0]["id"]),
    )
    return QualificationSet(
        receipts=tuple(item[0] for item in ordered),
        receipt_paths=tuple(item[1] for item in ordered),
        attachment_paths=tuple(
            attachment_paths[key]
            for key in sorted(attachment_paths, key=lambda value: value.encode("utf-8"))
        ),
    )


def _qualification_signed_payloads(
    qualification: QualificationSet,
) -> tuple[SignedPayload, ...]:
    return tuple(
        SignedPayload(path=path, final_path=final_path, purpose=QUALIFICATION_PURPOSE)
        for path, final_path in (
            *qualification.receipt_paths,
            *qualification.attachment_paths,
        )
    )


def _verify_supporting_signatures(
    directory: Path,
    payloads: Sequence[SignedPayload],
    trust: TrustPolicy,
    verification_time: int,
) -> SupportingSignatures:
    inventory = _secure_inventory(
        directory, label="beta supporting-signature workspace"
    )
    if not inventory or any(
        "/" in relative or not relative.endswith(".sig.json") for relative in inventory
    ):
        raise BetaReleaseError(
            "supporting signatures must be a flat set of .sig.json files"
        )
    expected: dict[tuple[str, str, int], SignedPayload] = {}
    for payload in payloads:
        identity = payload.identity()
        if identity in expected:
            raise BetaReleaseError(
                "two required payloads have an ambiguous signature identity"
            )
        expected[identity] = payload
    matched: set[tuple[str, str, int]] = set()
    paths: list[tuple[Path, str]] = []
    references: list[dict[str, object]] = []
    for relative in sorted(inventory, key=lambda value: value.encode("utf-8")):
        path = directory / relative
        envelope = _canonical_document(path, f"supporting signature {relative}")
        payload_reference = envelope.get("payload")
        if not isinstance(payload_reference, dict):
            raise BetaReleaseError("supporting signature payload reference is invalid")
        identity = (
            payload_reference.get("name"),
            payload_reference.get("sha256"),
            payload_reference.get("bytes"),
        )
        payload = expected.get(identity)
        if payload is None:
            raise BetaReleaseError("supporting signature targets an unexpected payload")
        if identity in matched:
            raise BetaReleaseError(
                "required payload has duplicate supporting signatures"
            )
        _verify_envelope(path, payload.path, payload.purpose, trust, verification_time)
        matched.add(identity)
        final_path = f"signatures/{relative}"
        paths.append((path, final_path))
        references.append(_file_reference(path, final_path))
    if matched != set(expected):
        missing = sorted(
            expected_identity[0] for expected_identity in set(expected) - matched
        )
        raise BetaReleaseError(f"required supporting signatures are missing: {missing}")
    return SupportingSignatures(references=tuple(references), paths=tuple(paths))


def _qualification_references(
    qualification: QualificationSet,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for receipt, (source_path, final_path) in zip(
        qualification.receipts, qualification.receipt_paths, strict=True
    ):
        reference = _file_reference(source_path, final_path)
        result.append(
            {
                "id": receipt["id"],
                "category": receipt["category"],
                "artifact_ids": [
                    binding["id"] for binding in receipt["artifact_bindings"]
                ],
                "receipt": reference,
            }
        )
    return result


def _build_release_evidence(
    candidate: Path,
    qualification: QualificationSet,
    signatures: SupportingSignatures,
    trust: TrustPolicy,
) -> dict[str, object]:
    manifest, _ = _candidate_manifest(candidate)
    artifacts = [dict(record) for record in manifest["artifacts"]]
    source_record = next(record for record in artifacts if record["id"] == "source")
    candidate_files = [
        _file_reference(candidate.joinpath(*relative.split("/")), relative)
        for relative in _candidate_paths()
        if not relative.startswith("artifacts/")
    ]
    return {
        "schema_version": RELEASE_EVIDENCE_SCHEMA,
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "tag": beta_profile.TAG,
        "target": beta_profile.TARGET_TRIPLE,
        "prerelease": True,
        "production_ready": False,
        "source": {
            "revision": manifest["source"]["revision"],
            "tree": manifest["source"]["tree"],
            "source_date_epoch": manifest["source_date_epoch"],
            "archive": {
                "id": "source",
                "path": source_record["path"],
                "sha256": source_record["sha256"],
                "bytes": source_record["bytes"],
            },
        },
        "trust_policy": {
            "schema_version": TRUST_POLICY_SCHEMA,
            "policy_id": trust.policy_id,
            "sha256": trust.digest,
        },
        "qualification_policy": _qualification_policy_reference(),
        "candidate_files": candidate_files,
        "artifacts": artifacts,
        "qualification": _qualification_references(qualification),
        "signatures": list(signatures.references),
        "claims": {
            "supporting_payloads_signed": True,
            "release_evidence_signature_required": True,
            "published": False,
            "production_ready": False,
        },
    }


def _prepare_inputs(
    *,
    candidate: Path,
    qualification_directory: Path,
    signature_directory: Path,
    trust_policy: Path,
    verification_time: int,
    openssl_path: Path | None = None,
) -> PreparedInputs:
    temporary = tempfile.TemporaryDirectory(prefix="cigar-beta-inputs-")
    try:
        base = Path(temporary.name).resolve(strict=True)
        os.chmod(base, 0o700)
        candidate = candidate.resolve(strict=True)
        qualification_directory = qualification_directory.resolve(strict=True)
        signature_directory = signature_directory.resolve(strict=True)
        trust_policy = trust_policy.resolve(strict=True)
        expected_candidate = set(_candidate_paths())
        actual_candidate = _secure_inventory(candidate, label="unsigned beta candidate")
        if actual_candidate != expected_candidate:
            raise BetaReleaseError(
                "unsigned beta candidate inventory mismatch; "
                f"missing={sorted(expected_candidate - actual_candidate)}, "
                f"extra={sorted(actual_candidate - expected_candidate)}"
            )
        snapshot_candidate = _snapshot_files(
            candidate,
            tuple(actual_candidate),
            base / "candidate",
            label="unsigned beta candidate",
        )
        if (
            _secure_inventory(candidate, label="unsigned beta candidate")
            != actual_candidate
        ):
            raise BetaReleaseError(
                "unsigned beta candidate inventory changed while it was snapshotted"
            )
        snapshot_qualification = _snapshot_directory(
            qualification_directory,
            base / "qualification",
            label="beta qualification workspace",
        )
        snapshot_signatures = _snapshot_directory(
            signature_directory,
            base / "signatures",
            label="beta supporting-signature workspace",
        )
        snapshot_trust = _snapshot_trust_policy(trust_policy, base / "trust")
        manifest, _ = _candidate_manifest(snapshot_candidate)
        qualification = _validate_qualification(snapshot_qualification, manifest)
        trust = _load_trust_policy(
            snapshot_trust, verification_time, openssl_path=openssl_path
        )
        payloads = (
            *_candidate_signed_payloads(snapshot_candidate),
            *_qualification_signed_payloads(qualification),
        )
        signatures = _verify_supporting_signatures(
            snapshot_signatures, payloads, trust, verification_time
        )
        _verify_candidate_offline(snapshot_candidate)
        _revalidate_signature_times(
            trust,
            [path for path, _ in signatures.paths],
            int(time.time()),
        )
        document = _build_release_evidence(
            snapshot_candidate, qualification, signatures, trust
        )
        return PreparedInputs(
            temporary=temporary,
            candidate=snapshot_candidate,
            document=document,
            qualification=qualification,
            signatures=signatures,
            trust=trust,
        )
    except BaseException:
        temporary.cleanup()
        raise


def plan_release(
    *,
    root: Path,
    candidate: Path,
    qualification_directory: Path,
    signature_directory: Path,
    trust_policy: Path,
    verification_time: int,
    output: Path,
    openssl_path: Path | None = None,
) -> dict[str, object]:
    verification_time = _current_verification_time(verification_time)
    prepared = _prepare_inputs(
        candidate=candidate,
        qualification_directory=qualification_directory,
        signature_directory=signature_directory,
        trust_policy=trust_policy,
        verification_time=verification_time,
        openssl_path=openssl_path,
    )
    try:
        document = prepared.document
        if not output.is_absolute() or output != Path(os.path.normpath(output)):
            raise BetaReleaseError(
                "release-evidence output must be absolute and canonical"
            )
        if output.exists() or output.is_symlink():
            raise BetaReleaseError("refusing to overwrite release-evidence output")
        with EvidenceWorkspace.create(
            output.parent,
            repository_root=root.resolve(strict=True),
            limits=EvidenceLimits(
                max_files=MAX_FILES,
                max_directories=MAX_DIRECTORIES,
                max_file_bytes=MAX_WORKSPACE_FILE_BYTES,
                max_total_bytes=MAX_TOTAL_BYTES,
                max_json_bytes=MAX_JSON_BYTES,
                max_path_depth=32,
            ),
        ) as workspace:
            workspace.write_json(output.name, document)
    except EvidenceWorkspaceError as error:
        raise BetaReleaseError(
            f"cannot materialize beta release-evidence plan: {error}"
        ) from error
    finally:
        prepared.close()
    return document


def _verify_release_signature(
    document_path: Path,
    signature_path: Path,
    trust: TrustPolicy,
    verification_time: int,
) -> None:
    if signature_path.name != RELEASE_SIGNATURE_NAME:
        raise BetaReleaseError(
            f"release-evidence signature must be named {RELEASE_SIGNATURE_NAME}"
        )
    _verify_envelope(
        signature_path,
        document_path,
        RELEASE_EVIDENCE_PURPOSE,
        trust,
        verification_time,
    )


def _workspace_limits() -> EvidenceLimits:
    return EvidenceLimits(
        max_files=MAX_FILES,
        max_directories=MAX_DIRECTORIES,
        max_file_bytes=MAX_WORKSPACE_FILE_BYTES,
        max_total_bytes=MAX_TOTAL_BYTES,
        max_json_bytes=MAX_JSON_BYTES,
        max_path_depth=32,
    )


def assemble_release(
    *,
    root: Path,
    candidate: Path,
    qualification_directory: Path,
    signature_directory: Path,
    trust_policy: Path,
    verification_time: int,
    release_evidence: Path,
    release_signature: Path,
    output: Path,
    openssl_path: Path | None = None,
) -> dict[str, object]:
    verification_time = _current_verification_time(verification_time)
    prepared = _prepare_inputs(
        candidate=candidate,
        qualification_directory=qualification_directory,
        signature_directory=signature_directory,
        trust_policy=trust_policy,
        verification_time=verification_time,
        openssl_path=openssl_path,
    )
    try:
        prepared_root = Path(prepared.temporary.name).resolve(strict=True)
        evidence_snapshot = (
            _snapshot_files(
                release_evidence.parent.resolve(strict=True),
                (release_evidence.name,),
                prepared_root / "release-evidence",
                label="signed beta release evidence",
            )
            / release_evidence.name
        )
        signature_snapshot = (
            _snapshot_files(
                release_signature.parent.resolve(strict=True),
                (release_signature.name,),
                prepared_root / "release-signature",
                label="beta release-evidence signature",
            )
            / release_signature.name
        )
        supplied = _canonical_document(
            evidence_snapshot, "signed beta release evidence"
        )
        if supplied != prepared.document:
            raise BetaReleaseError(
                "signed beta release evidence differs from the canonical plan"
            )
        current = _revalidate_signature_times(
            prepared.trust,
            [path for path, _ in prepared.signatures.paths],
            int(time.time()),
        )
        _verify_release_signature(
            evidence_snapshot,
            signature_snapshot,
            prepared.trust,
            current,
        )
        if not output.is_absolute() or output != Path(os.path.normpath(output)):
            raise BetaReleaseError("beta release output must be absolute and canonical")
        if output.exists() or output.is_symlink():
            raise BetaReleaseError("beta release output must not already exist")
        with EvidenceWorkspace.create(
            output,
            repository_root=root.resolve(strict=True),
            limits=_workspace_limits(),
        ) as workspace:
            for relative in _candidate_paths():
                workspace.attach_file(
                    prepared.candidate.joinpath(*relative.split("/")), relative
                )
            for source, final_path in (
                *prepared.qualification.receipt_paths,
                *prepared.qualification.attachment_paths,
            ):
                workspace.attach_file(source, final_path)
            for source, final_path in prepared.signatures.paths:
                workspace.attach_file(source, final_path)
            workspace.attach_file(evidence_snapshot, RELEASE_EVIDENCE_NAME)
            workspace.attach_file(signature_snapshot, RELEASE_SIGNATURE_NAME)
    except EvidenceWorkspaceError as error:
        raise BetaReleaseError(
            f"cannot assemble private beta release inventory: {error}"
        ) from error
    finally:
        prepared.close()
    return verify_final_release(
        release_directory=output,
        trust_policy=trust_policy,
        verification_time=int(time.time()),
        openssl_path=openssl_path,
    )


def _qualification_from_final(
    release_directory: Path,
    document: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> QualificationSet:
    qualification_root = release_directory / "qualification"
    qualification = _validate_qualification(qualification_root, manifest)
    observed = document.get("qualification")
    expected = _qualification_references(qualification)
    if observed != expected:
        raise BetaReleaseError("final qualification summaries are stale or substituted")
    return qualification


def _supporting_signatures_from_final(
    release_directory: Path,
    document: Mapping[str, Any],
) -> SupportingSignatures:
    references = document.get("signatures")
    if not isinstance(references, list) or not references:
        raise BetaReleaseError("final beta release has no supporting signatures")
    paths: list[tuple[Path, str]] = []
    observed: set[str] = set()
    for reference in references:
        path = _validate_reference(release_directory, reference)
        relative = reference["path"]
        if not relative.startswith("signatures/") or relative in observed:
            raise BetaReleaseError(
                "final supporting signature path is invalid or duplicated"
            )
        observed.add(relative)
        paths.append((path, relative))
    if [reference["path"] for reference in references] != sorted(observed):
        raise BetaReleaseError("final supporting signature references are not ordered")
    return SupportingSignatures(references=tuple(references), paths=tuple(paths))


def _verify_final_snapshot(
    *,
    release_directory: Path,
    trust_policy: Path,
    verification_time: int,
    openssl_path: Path | None = None,
) -> dict[str, object]:
    release_directory = release_directory.resolve(strict=True)
    inventory = _secure_inventory(release_directory, label="final beta release")
    evidence_path = release_directory / RELEASE_EVIDENCE_NAME
    signature_path = release_directory / RELEASE_SIGNATURE_NAME
    document = _canonical_document(evidence_path, "final beta release evidence")
    trust = _load_trust_policy(
        trust_policy.resolve(strict=True),
        verification_time,
        openssl_path=openssl_path,
    )
    _verify_release_signature(evidence_path, signature_path, trust, verification_time)
    if (
        document.get("schema_version") != RELEASE_EVIDENCE_SCHEMA
        or document.get("release_profile") != beta_profile.PROFILE_ID
        or document.get("product_version") != beta_profile.VERSION
        or document.get("tag") != beta_profile.TAG
        or document.get("target") != beta_profile.TARGET_TRIPLE
        or document.get("prerelease") is not True
        or document.get("production_ready") is not False
        or document.get("claims")
        != {
            "supporting_payloads_signed": True,
            "release_evidence_signature_required": True,
            "published": False,
            "production_ready": False,
        }
        or document.get("trust_policy")
        != {
            "schema_version": TRUST_POLICY_SCHEMA,
            "policy_id": trust.policy_id,
            "sha256": trust.digest,
        }
        or document.get("qualification_policy") != _qualification_policy_reference()
    ):
        raise BetaReleaseError(
            "final beta release identity, trust, or claims are invalid"
        )
    expected_candidate = set(_candidate_paths())
    for relative in expected_candidate:
        if relative not in inventory:
            raise BetaReleaseError(
                f"final beta release is missing candidate input: {relative}"
            )
    manifest, _ = _candidate_manifest(release_directory)
    qualification = _qualification_from_final(release_directory, document, manifest)
    signatures = _supporting_signatures_from_final(release_directory, document)
    payloads = (
        *_candidate_signed_payloads(release_directory),
        *_qualification_signed_payloads(qualification),
    )
    signature_staging = tempfile.TemporaryDirectory(prefix="cigar-beta-signatures-")
    try:
        staging = Path(signature_staging.name)
        os.chmod(staging, 0o700)
        for source, final_path in signatures.paths:
            target = staging / Path(final_path).name
            with source.open("rb") as input_file, target.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file)
            os.chmod(target, 0o600)
        verified_signatures = _verify_supporting_signatures(
            staging, payloads, trust, verification_time
        )
    finally:
        signature_staging.cleanup()
    if verified_signatures.references != signatures.references:
        raise BetaReleaseError("final supporting signature inventory was substituted")
    _verify_candidate_offline(release_directory)
    expected_document = _build_release_evidence(
        release_directory, qualification, verified_signatures, trust
    )
    if document != expected_document:
        raise BetaReleaseError("final beta release evidence is stale or non-canonical")
    expected_inventory = (
        expected_candidate
        | {final_path for _, final_path in qualification.receipt_paths}
        | {final_path for _, final_path in qualification.attachment_paths}
        | {final_path for _, final_path in signatures.paths}
        | {RELEASE_EVIDENCE_NAME, RELEASE_SIGNATURE_NAME}
    )
    if inventory != expected_inventory:
        raise BetaReleaseError(
            "final beta release inventory mismatch; "
            f"missing={sorted(expected_inventory - inventory)}, "
            f"extra={sorted(inventory - expected_inventory)}"
        )
    verification_time = _revalidate_signature_times(
        trust,
        [signature_path, *(path for path, _ in signatures.paths)],
        int(time.time()),
    )
    return {
        "schema_version": "cigar.beta.final-release-verification.v1",
        "status": "passed",
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "source_revision": manifest["source"]["revision"],
        "artifact_count": 6,
        "qualification_count": len(qualification.receipts),
        "signature_count": len(signatures.paths) + 1,
        "qualification_policy_sha256": _qualification_policy_reference()["sha256"],
        "trust_policy_sha256": trust.digest,
        "verification_time": verification_time,
        "binary_executed": False,
        "published": False,
        "production_ready": False,
    }


def verify_final_release(
    *,
    release_directory: Path,
    trust_policy: Path,
    verification_time: int,
    openssl_path: Path | None = None,
) -> dict[str, object]:
    verification_time = _current_verification_time(verification_time)
    temporary = tempfile.TemporaryDirectory(prefix="cigar-beta-final-snapshot-")
    try:
        base = Path(temporary.name).resolve(strict=True)
        os.chmod(base, 0o700)
        release_directory = release_directory.resolve(strict=True)
        trust_policy = trust_policy.resolve(strict=True)
        snapshot_release = _snapshot_directory(
            release_directory,
            base / "release",
            label="final beta release",
        )
        snapshot_trust = _snapshot_trust_policy(trust_policy, base / "trust")
        return _verify_final_snapshot(
            release_directory=snapshot_release,
            trust_policy=snapshot_trust,
            verification_time=verification_time,
            openssl_path=openssl_path,
        )
    finally:
        temporary.cleanup()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("plan", "assemble"):
        description = (
            "materialize the canonical release-evidence signature payload"
            if action == "plan"
            else "materialize a signed private release inventory; this does not publish it"
        )
        command = subparsers.add_parser(action, help=description)
        command.add_argument("--candidate", type=Path, required=True)
        command.add_argument("--qualification", type=Path, required=True)
        command.add_argument("--signatures", type=Path, required=True)
        command.add_argument("--trust-policy", type=Path, required=True)
        command.add_argument(
            "--openssl",
            type=Path,
            help="absolute OpenSSL executable matching the trust-policy digest",
        )
    plan = subparsers.choices["plan"]
    plan.add_argument("--out", type=Path, required=True)
    assemble = subparsers.choices["assemble"]
    assemble.add_argument("--release-evidence", type=Path, required=True)
    assemble.add_argument("--release-signature", type=Path, required=True)
    assemble.add_argument("--out", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--release", type=Path, required=True)
    verify.add_argument("--trust-policy", type=Path, required=True)
    verify.add_argument(
        "--openssl",
        type=Path,
        help="absolute OpenSSL executable matching the trust-policy digest",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    verification_time = int(time.time())
    if arguments.action == "plan":
        document = plan_release(
            root=arguments.root,
            candidate=arguments.candidate,
            qualification_directory=arguments.qualification,
            signature_directory=arguments.signatures,
            trust_policy=arguments.trust_policy,
            verification_time=verification_time,
            output=arguments.out,
            openssl_path=arguments.openssl,
        )
        print(canonical_json_bytes(document).decode("utf-8"), end="")
    elif arguments.action == "assemble":
        report = assemble_release(
            root=arguments.root,
            candidate=arguments.candidate,
            qualification_directory=arguments.qualification,
            signature_directory=arguments.signatures,
            trust_policy=arguments.trust_policy,
            verification_time=verification_time,
            release_evidence=arguments.release_evidence,
            release_signature=arguments.release_signature,
            output=arguments.out,
            openssl_path=arguments.openssl,
        )
        print(canonical_json_bytes(report).decode("utf-8"), end="")
    else:
        report = verify_final_release(
            release_directory=arguments.release,
            trust_policy=arguments.trust_policy,
            verification_time=verification_time,
            openssl_path=arguments.openssl,
        )
        print(canonical_json_bytes(report).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BetaReleaseError, OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"beta release operation failed: {error}") from error
