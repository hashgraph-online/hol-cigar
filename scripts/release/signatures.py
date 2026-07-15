#!/usr/bin/env python3
"""Create and verify detached Ed25519 release envelopes using explicit key files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    safe_relative_path as safe_evidence_path,
)
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    process_failure_summary,
    reject_evidence_directory,
    repo_root,
    require_distinct_output,
    run_bounded,
    safe_relative_path,
    selected_evidence_directory,
    write_bytes,
)


_SIGNATURE_DOMAIN = b"CIGAR-RELEASE-SIGNATURE-V1\x00"
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
_MAX_KEY_BYTES = 1024 * 1024
_MAX_ENVELOPE_BYTES = 16 * 1024 * 1024
_OPENSSL_CANDIDATES = (
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/opt/homebrew/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
    "/usr/local/bin/openssl",
    "/usr/bin/openssl",
    "/bin/openssl",
    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    r"C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
)
_OPENSSL_LOCK = threading.RLock()
_STAGED_OPENSSL: (
    tuple[
        tempfile.TemporaryDirectory[str],
        tuple[int, int, int, int, int, str],
        Path,
        tuple[int, int, int, int, int, str],
    ]
    | None
) = None


@dataclass(frozen=True)
class StableFileState:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    sign = subparsers.add_parser(
        "sign", help="sign a payload with an existing Ed25519 private PEM"
    )
    sign.add_argument("payload", type=Path)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    sign.add_argument("--signer-principal", required=True)
    sign.add_argument("--purpose", required=True)
    sign.add_argument(
        "--signed-at",
        type=int,
        required=True,
        help="Unix timestamp recorded in the signed envelope",
    )
    sign.add_argument(
        "--expires-at", type=int, help="optional exclusive Unix expiry timestamp"
    )
    sign.add_argument("--out", type=Path, required=True)
    sign.add_argument("--root", type=Path, default=repo_root())
    sign.add_argument(
        "--evidence-dir",
        type=Path,
        help="absolute external signature workspace (or set CIGAR_EVIDENCE_DIR)",
    )
    sign.add_argument(
        "--openssl",
        type=Path,
        help="absolute reviewed OpenSSL executable (fixed system locations by default)",
    )
    sign.add_argument(
        "--openssl-sha256",
        required=True,
        help="independently reviewed SHA-256 of the OpenSSL executable",
    )
    verify = subparsers.add_parser(
        "verify", help="verify a signature envelope with a trusted public PEM"
    )
    verify.add_argument("envelope", type=Path)
    verify.add_argument("--payload", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--expected-purpose", required=True)
    verify.add_argument("--expected-signer")
    verify.add_argument(
        "--verification-time",
        type=int,
        help="Unix time used for expiry checks; defaults to the current time",
    )
    verify.add_argument(
        "--openssl",
        type=Path,
        help="absolute reviewed OpenSSL executable (fixed system locations by default)",
    )
    verify.add_argument(
        "--openssl-sha256",
        required=True,
        help="independently reviewed SHA-256 of the OpenSSL executable",
    )
    verify.add_argument("--root", type=Path, default=repo_root())
    verify.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector; verification is stdout-only and "
            "does not emit a report"
        ),
    )
    return parser.parse_args()


def _fixed_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "OPENSSL_CONF": os.devnull,
        "OPENSSL_ENGINES": "/nonexistent",
        "OPENSSL_MODULES": "/nonexistent",
        "PATH": os.defpath,
        "TZ": "UTC",
    }


def _executable_identity(path: Path) -> tuple[int, int, int, int, int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseError(f"cannot securely open reviewed OpenSSL: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
            or (
                os.name != "nt"
                and (
                    (
                        hasattr(os, "geteuid")
                        and metadata.st_uid not in {0, os.geteuid()}
                    )
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                )
            )
            or metadata.st_size <= 0
            or metadata.st_size > 128 * 1024 * 1024
        ):
            raise ReleaseError("reviewed OpenSSL executable metadata is unsafe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(metadata, field) != getattr(after, field) for field in stable_fields
        ):
            raise ReleaseError("reviewed OpenSSL executable changed while inspected")
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            digest.hexdigest(),
        )
    except OSError as error:
        raise ReleaseError(f"cannot inspect reviewed OpenSSL: {error}") from error
    finally:
        os.close(descriptor)


def _secure_openssl(supplied: Path | None, expected_sha256: str | None = None) -> Path:
    if expected_sha256 is not None and _SHA256.fullmatch(expected_sha256) is None:
        raise ReleaseError("reviewed OpenSSL SHA-256 is invalid")
    if supplied is not None and not supplied.is_absolute():
        raise ReleaseError("OpenSSL executable path must be absolute")
    candidates = (
        [supplied]
        if supplied is not None
        else [Path(value) for value in _OPENSSL_CANDIDATES]
    )
    if supplied is None and os.name != "nt":
        discovered = shutil.which("openssl", path=os.defpath)
        if discovered is not None:
            candidates.append(Path(discovered))
    observed: set[Path] = set()
    for candidate in candidates:
        if candidate is None or not candidate.is_absolute() or not candidate.is_file():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in observed or not os.access(resolved, os.X_OK):
            continue
        observed.add(resolved)
        try:
            identity = _executable_identity(resolved)
        except ReleaseError:
            if supplied is not None:
                raise
            continue
        if expected_sha256 is None or identity[-1] == expected_sha256:
            return resolved
    if expected_sha256 is not None:
        raise ReleaseError("no reviewed OpenSSL matches the pinned SHA-256")
    raise ReleaseError(
        "reviewed OpenSSL is unavailable; supply an absolute --openssl path"
    )


def openssl_sha256(openssl_path: Path | None = None) -> str:
    """Return the digest to record only after independent executable review."""
    selected = _secure_openssl(openssl_path)
    return _executable_identity(selected)[-1]


def _validate_regular_metadata(
    opened: os.stat_result,
    named: os.stat_result,
    maximum: int,
    label: str,
    *,
    owner_only: bool,
) -> None:
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or (
            os.name != "nt"
            and (
                (hasattr(os, "geteuid") and opened.st_uid not in {0, os.geteuid()})
                or stat.S_IMODE(opened.st_mode) & 0o022
                or (
                    owner_only
                    and (
                        opened.st_uid != os.geteuid()
                        or stat.S_IMODE(opened.st_mode) & 0o077
                    )
                )
            )
        )
        or opened.st_size <= 0
        or opened.st_size > maximum
    ):
        raise ReleaseError(f"{label} is not a stable, bounded regular file")


def _state_from_metadata(metadata: os.stat_result, digest: str) -> StableFileState:
    return StableFileState(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
        sha256=digest,
    )


def _stable_file_state(
    path: Path,
    maximum: int,
    label: str,
    *,
    owner_only: bool = False,
) -> StableFileState:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseError(f"cannot securely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        named_before = path.lstat()
        _validate_regular_metadata(
            before, named_before, maximum, label, owner_only=owner_only
        )
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds the reviewed byte limit")
        after = os.fstat(descriptor)
        named_after = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ) or (after.st_dev, after.st_ino) != (
            named_after.st_dev,
            named_after.st_ino,
        ):
            raise ReleaseError(f"{label} changed while it was read")
        if total != before.st_size:
            raise ReleaseError(f"{label} size changed while it was read")
        return _state_from_metadata(before, digest.hexdigest())
    except OSError as error:
        raise ReleaseError(f"cannot read {label}: {error}") from error
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes, label: str) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as error:
            raise ReleaseError(f"cannot write {label}: {error}") from error
        if written <= 0:
            raise ReleaseError(f"cannot make progress writing {label}")
        offset += written


def _snapshot_regular_file(
    source: Path,
    destination: Path,
    maximum: int,
    label: str,
    *,
    owner_only: bool = False,
) -> StableFileState:
    source_flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError as error:
        raise ReleaseError(f"cannot securely open {label}: {error}") from error
    destination_descriptor: int | None = None
    completed = False
    try:
        before = os.fstat(source_descriptor)
        named_before = source.lstat()
        _validate_regular_metadata(
            before, named_before, maximum, label, owner_only=owner_only
        )
        try:
            destination_descriptor = os.open(destination, destination_flags, 0o400)
            if os.name != "nt":
                os.fchmod(destination_descriptor, 0o400)
        except OSError as error:
            raise ReleaseError(
                f"cannot create private {label} snapshot: {error}"
            ) from error
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(source_descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds the reviewed byte limit")
            _write_all(destination_descriptor, chunk, f"{label} snapshot")
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        named_after = source.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ) or (after.st_dev, after.st_ino) != (
            named_after.st_dev,
            named_after.st_ino,
        ):
            raise ReleaseError(f"{label} changed while it was snapshotted")
        if total != before.st_size or os.fstat(destination_descriptor).st_size != total:
            raise ReleaseError(f"private {label} snapshot is incomplete")
        completed = True
        return _state_from_metadata(before, digest.hexdigest())
    except OSError as error:
        raise ReleaseError(f"cannot snapshot {label}: {error}") from error
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if not completed:
            destination.unlink(missing_ok=True)


def _stable_regular_bytes(
    path: Path,
    maximum: int,
    label: str,
    *,
    owner_only: bool = False,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseError(f"cannot securely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        named_before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or (
                os.name != "nt"
                and (
                    (hasattr(os, "geteuid") and before.st_uid not in {0, os.geteuid()})
                    or stat.S_IMODE(before.st_mode) & 0o022
                    or (
                        owner_only
                        and (
                            before.st_uid != os.geteuid()
                            or stat.S_IMODE(before.st_mode) & 0o077
                        )
                    )
                )
            )
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise ReleaseError(f"{label} is not a stable, bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ReleaseError(f"{label} exceeds the reviewed byte limit")
        after = os.fstat(descriptor)
        named_after = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise ReleaseError(f"{label} changed while it was read")
        if (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino):
            raise ReleaseError(f"{label} path changed while it was read")
        return b"".join(chunks)
    except OSError as error:
        raise ReleaseError(f"cannot read {label}: {error}") from error
    finally:
        os.close(descriptor)


def _run(
    arguments: list[str], openssl_path: Path, openssl_sha256: str | None = None
) -> bytes:
    if not arguments or arguments[0] != "openssl":
        raise ReleaseError("OpenSSL argument vector is invalid")
    selected = _secure_openssl(openssl_path, openssl_sha256)
    before = _executable_identity(selected)
    global _STAGED_OPENSSL
    with _OPENSSL_LOCK:
        if os.name == "nt":
            result = run_bounded(
                [str(selected), *arguments[1:]],
                env=_fixed_environment(),
                timeout=30,
                max_stdout=1024 * 1024,
                max_stderr=1024 * 1024,
            )
            if _executable_identity(selected) != before:
                raise ReleaseError("reviewed OpenSSL changed while it was executing")
            if result.returncode != 0:
                raise ReleaseError(process_failure_summary(result, "OpenSSL operation"))
            return result.stdout
        if _STAGED_OPENSSL is None or _STAGED_OPENSSL[1] != before:
            if _STAGED_OPENSSL is not None:
                _STAGED_OPENSSL[0].cleanup()
            temporary = tempfile.TemporaryDirectory(prefix="cigar-openssl-")
            directory = Path(temporary.name).resolve(strict=True)
            # The pinned signer executable snapshot must be inaccessible to other local users.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                directory,
                0o700,
            )
            staged = directory / ("openssl.exe" if os.name == "nt" else "openssl")
            try:
                with selected.open("rb") as source, staged.open("xb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                    destination.flush()
                    os.fsync(destination.fileno())
                os.chmod(staged, 0o500)
            except OSError as error:
                temporary.cleanup()
                raise ReleaseError(f"cannot stage reviewed OpenSSL: {error}") from error
            staged_identity = _executable_identity(staged)
            if (
                staged_identity[-1] != before[-1]
                or _executable_identity(selected) != before
            ):
                temporary.cleanup()
                raise ReleaseError("reviewed OpenSSL changed while it was staged")
            _STAGED_OPENSSL = (temporary, before, staged, staged_identity)
        _, _, staged, staged_identity = _STAGED_OPENSSL
        result = run_bounded(
            [str(staged), *arguments[1:]],
            env=_fixed_environment(),
            timeout=30,
            max_stdout=1024 * 1024,
            max_stderr=1024 * 1024,
        )
        if _executable_identity(staged) != staged_identity:
            raise ReleaseError("private OpenSSL snapshot changed while executing")
        if _executable_identity(selected) != before:
            raise ReleaseError("reviewed OpenSSL changed while it was executing")
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, "OpenSSL operation"))
    return result.stdout


def _public_der(
    public_key: Path, openssl_path: Path, openssl_sha256: str | None = None
) -> bytes:
    key_payload = _stable_regular_bytes(public_key, 1024 * 1024, "release public key")
    with tempfile.TemporaryDirectory(prefix="cigar-public-key-") as raw:
        directory = Path(raw).resolve(strict=True)
        # Key conversion staging is private even though this particular payload is public.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            directory,
            0o700,
        )
        snapshot = directory / "public.pem"
        write_bytes(snapshot, key_payload)
        os.chmod(snapshot, 0o400)
        payload = _run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(snapshot),
                "-outform",
                "DER",
            ],
            openssl_path,
            openssl_sha256,
        )
    if len(payload) != len(_ED25519_SPKI_PREFIX) + 32 or not payload.startswith(
        _ED25519_SPKI_PREFIX
    ):
        raise ReleaseError(
            "release public key is not an Ed25519 SubjectPublicKeyInfo key"
        )
    return payload


def public_key_id(
    public_key: Path,
    *,
    openssl_path: Path | None = None,
    openssl_sha256: str | None = None,
) -> str:
    """Return the stable key identifier used by signature envelopes."""
    selected = _secure_openssl(openssl_path, openssl_sha256)
    effective_digest = openssl_sha256 or _executable_identity(selected)[-1]
    return f"sha256:{hashlib.sha256(_public_der(public_key, selected, effective_digest)).hexdigest()}"


def _timestamp(value: Any, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 253_402_300_799
    ):
        raise ReleaseError(f"signature {label} is not a valid Unix timestamp")
    return value


def _identity(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or value != value.strip()
    ):
        raise ReleaseError(f"signature {label} is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ReleaseError(f"signature {label} contains a control character")
    return value


def _unsigned_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError("signature envelope is not an object")
    required = {
        "schema_version",
        "algorithm",
        "key_id",
        "signer_principal",
        "purpose",
        "signed_at",
        "payload",
    }
    allowed = required | {"expires_at"}
    keys = set(value)
    if keys != required and keys != allowed:
        raise ReleaseError("signature envelope has an unexpected shape")
    if (
        value.get("schema_version") != "cigar.signature-envelope.v1"
        or value.get("algorithm") != "Ed25519"
    ):
        raise ReleaseError("unsupported signature envelope")
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ReleaseError("signature key identifier is invalid")
    _identity(value.get("signer_principal"), "signer principal")
    purpose = value.get("purpose")
    if not isinstance(purpose, str) or _PURPOSE.fullmatch(purpose) is None:
        raise ReleaseError("signature purpose is invalid")
    signed_at = _timestamp(value.get("signed_at"), "signed-at")
    if "expires_at" in value:
        expires_at = _timestamp(value["expires_at"], "expires-at")
        if expires_at <= signed_at:
            raise ReleaseError("signature expiry must be later than signing time")
    reference = value.get("payload")
    if not isinstance(reference, dict) or set(reference) != {"name", "sha256", "bytes"}:
        raise ReleaseError("signature payload reference is invalid")
    safe_relative_path(reference.get("name", ""))
    digest = reference.get("sha256")
    size = reference.get("bytes")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReleaseError("signature payload digest is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ReleaseError("signature payload size is invalid")
    return value


def _signature_input(unsigned: dict[str, Any]) -> bytes:
    return _SIGNATURE_DOMAIN + canonical_json_bytes(unsigned)


def _write_private_snapshot(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o400)
    except OSError as error:
        path.unlink(missing_ok=True)
        raise ReleaseError(
            f"cannot create private signature snapshot: {error}"
        ) from error


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ReleaseError(
            f"cannot durably sync signature directory: {error}"
        ) from error


def _write_new_private_json(path: Path, value: object) -> None:
    payload = canonical_json_bytes(value)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ReleaseError("signature output path must be absolute and canonical")
    original_parent = path.parent
    try:
        parent = original_parent.resolve(strict=True)
        metadata = parent.lstat()
    except OSError as error:
        raise ReleaseError(
            f"cannot resolve signature output directory: {error}"
        ) from error
    path = parent / path.name
    if (
        original_parent != parent
        or original_parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (
            os.name != "nt"
            and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            )
        )
    ):
        raise ReleaseError("signature output directory is not owner-controlled")
    if path.exists() or path.is_symlink():
        raise ReleaseError("refusing to overwrite signature output")
    descriptor: int | None = None
    temporary: Path | None = None
    linked = False
    published = False
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=parent
        )
        temporary = Path(raw_temporary)
        _write_all(descriptor, payload, "signature envelope")
        if os.name != "nt":
            os.fchmod(descriptor, 0o400)
        else:
            os.chmod(temporary, 0o400)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ReleaseError("refusing to overwrite signature output") from error
        linked = True
        _fsync_directory(parent)
        temporary.unlink()
        temporary = None
        _fsync_directory(parent)
        published = True
    except OSError as error:
        raise ReleaseError(
            f"cannot atomically publish signature output: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if linked and not published:
            path.unlink(missing_ok=True)
            _fsync_directory(parent)


def sign(
    payload: Path,
    private_key: Path,
    public_key: Path,
    output: Path,
    *,
    signer_principal: str,
    purpose: str,
    signed_at: int,
    expires_at: int | None = None,
    openssl_path: Path | None = None,
    openssl_sha256: str | None = None,
) -> None:
    selected_openssl = _secure_openssl(openssl_path, openssl_sha256)
    effective_openssl_sha256 = (
        openssl_sha256 or _executable_identity(selected_openssl)[-1]
    )
    resolved_inputs = {
        payload.resolve(strict=False),
        private_key.resolve(strict=False),
        public_key.resolve(strict=False),
    }
    if output.resolve(strict=False) in resolved_inputs:
        raise ReleaseError(
            "signature output must not replace its payload or key material"
        )
    with tempfile.TemporaryDirectory(prefix="cigar-signature-") as raw:
        directory = Path(raw).resolve(strict=True)
        # Signature staging contains a private-key snapshot and must be owner-only.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            directory,
            0o700,
        )
        payload_snapshot = directory / "payload.bin"
        private_key_snapshot = directory / "private.pem"
        public_key_snapshot = directory / "public.pem"
        signature_input = directory / "signature-input.bin"
        signature = directory / "signature.bin"
        payload_state = _snapshot_regular_file(
            payload, payload_snapshot, _MAX_PAYLOAD_BYTES, "signature payload"
        )
        private_key_state = _snapshot_regular_file(
            private_key,
            private_key_snapshot,
            _MAX_KEY_BYTES,
            "private signing key",
            owner_only=True,
        )
        public_key_state = _snapshot_regular_file(
            public_key,
            public_key_snapshot,
            _MAX_KEY_BYTES,
            "release public key",
        )
        key_id = public_key_id(
            public_key_snapshot,
            openssl_path=selected_openssl,
            openssl_sha256=effective_openssl_sha256,
        )
        unsigned: dict[str, Any] = {
            "schema_version": "cigar.signature-envelope.v1",
            "algorithm": "Ed25519",
            "key_id": key_id,
            "signer_principal": signer_principal,
            "purpose": purpose,
            "signed_at": signed_at,
            "payload": {
                "name": payload.name,
                "sha256": payload_state.sha256,
                "bytes": payload_state.size,
            },
        }
        if expires_at is not None:
            unsigned["expires_at"] = expires_at
        _unsigned_envelope(unsigned)
        _write_private_snapshot(signature_input, _signature_input(unsigned))
        _run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key_snapshot),
                "-in",
                str(signature_input),
                "-out",
                str(signature),
            ],
            selected_openssl,
            effective_openssl_sha256,
        )
        _run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key_snapshot),
                "-in",
                str(signature_input),
                "-sigfile",
                str(signature),
            ],
            selected_openssl,
            effective_openssl_sha256,
        )
        signature_bytes = _stable_regular_bytes(
            signature, 64, "generated Ed25519 signature"
        )
    if (
        _stable_file_state(payload, _MAX_PAYLOAD_BYTES, "signature payload")
        != payload_state
    ):
        raise ReleaseError("signature payload changed while it was being signed")
    if (
        _stable_file_state(
            private_key,
            _MAX_KEY_BYTES,
            "private signing key",
            owner_only=True,
        )
        != private_key_state
    ):
        raise ReleaseError("private signing key changed while it was being used")
    if (
        _stable_file_state(public_key, _MAX_KEY_BYTES, "release public key")
        != public_key_state
    ):
        raise ReleaseError("release public key changed while it was being used")
    if len(signature_bytes) != 64:
        raise ReleaseError("OpenSSL produced an invalid Ed25519 signature length")
    envelope = {
        **unsigned,
        "signature_base64": base64.b64encode(signature_bytes).decode("ascii"),
    }
    _write_new_private_json(output, envelope)


def verify(
    envelope_path: Path,
    payload: Path,
    public_key: Path,
    *,
    expected_purpose: str,
    expected_signer: str | None = None,
    verification_time: int | None = None,
    openssl_path: Path | None = None,
    openssl_sha256: str | None = None,
) -> dict[str, Any]:
    selected_openssl = _secure_openssl(openssl_path, openssl_sha256)
    effective_openssl_sha256 = (
        openssl_sha256 or _executable_identity(selected_openssl)[-1]
    )
    with tempfile.TemporaryDirectory(prefix="cigar-verify-inputs-") as raw:
        directory = Path(raw).resolve(strict=True)
        # Verification snapshots remain private until every input identity is rechecked.
        os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            directory,
            0o700,
        )
        envelope_snapshot = directory / "envelope.json"
        payload_snapshot = directory / "payload.bin"
        public_key_snapshot = directory / "public.pem"
        envelope_state = _snapshot_regular_file(
            envelope_path,
            envelope_snapshot,
            _MAX_ENVELOPE_BYTES,
            "signature envelope",
        )
        payload_state = _snapshot_regular_file(
            payload, payload_snapshot, _MAX_PAYLOAD_BYTES, "signature payload"
        )
        public_key_state = _snapshot_regular_file(
            public_key,
            public_key_snapshot,
            _MAX_KEY_BYTES,
            "trusted release public key",
        )
        unsigned = _verify_with_public_key(
            envelope_snapshot,
            payload_snapshot,
            public_key_snapshot,
            expected_payload_name=payload.name,
            expected_purpose=expected_purpose,
            expected_signer=expected_signer,
            verification_time=verification_time,
            openssl_path=selected_openssl,
            openssl_sha256=effective_openssl_sha256,
        )
    if (
        _stable_file_state(envelope_path, _MAX_ENVELOPE_BYTES, "signature envelope")
        != envelope_state
    ):
        raise ReleaseError("signature envelope changed while it was being verified")
    if (
        _stable_file_state(payload, _MAX_PAYLOAD_BYTES, "signature payload")
        != payload_state
    ):
        raise ReleaseError("signature payload changed while it was being verified")
    if (
        _stable_file_state(public_key, _MAX_KEY_BYTES, "trusted release public key")
        != public_key_state
    ):
        raise ReleaseError("trusted public key changed while it was being verified")
    return unsigned


def _sign_to_evidence_workspace(
    arguments: argparse.Namespace,
    selected: Path,
) -> bytes:
    """Stage a signature, then bind and publish it through EvidenceWorkspace."""

    try:
        root = arguments.root.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(f"cannot resolve repository root: {error}") from error
    if not root.is_dir():
        raise ReleaseError("repository root is not a directory")
    try:
        parts = safe_evidence_path(os.fspath(arguments.out))
        workspace = EvidenceWorkspace.create(selected, repository_root=root)
    except EvidenceWorkspaceError as error:
        raise ReleaseError(f"unsafe evidence workspace: {error}") from error

    payload = arguments.payload.absolute()
    private_key = arguments.private_key.absolute()
    public_key = arguments.public_key.absolute()
    final_path = workspace.root.joinpath(*parts)
    try:
        require_distinct_output(
            final_path,
            (payload, private_key, public_key),
            "signature",
        )
        with tempfile.TemporaryDirectory(prefix="cigar-signature-output-") as raw:
            staging_directory = Path(raw).resolve(strict=True)
            # Unpublished signature envelopes are assembled in an owner-private directory.
            os.chmod(  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                staging_directory,
                0o700,
            )
            staged = staging_directory / "signature-envelope.json"
            sign(
                payload,
                private_key,
                public_key,
                staged,
                signer_principal=arguments.signer_principal,
                purpose=arguments.purpose,
                signed_at=arguments.signed_at,
                expires_at=arguments.expires_at,
                openssl_path=arguments.openssl,
                openssl_sha256=arguments.openssl_sha256,
            )
            envelope = _stable_regular_bytes(
                staged,
                _MAX_ENVELOPE_BYTES,
                "staged signature output",
            )
            workspace.attach_file(
                staged,
                "/".join(parts),
                expected_sha256=hashlib.sha256(envelope).hexdigest(),
                expected_bytes=len(envelope),
            )
            return envelope
    except EvidenceWorkspaceError as error:
        raise ReleaseError(f"cannot publish signature evidence: {error}") from error
    finally:
        workspace.close()


def _verify_with_public_key(
    envelope_path: Path,
    payload: Path,
    public_key: Path,
    *,
    expected_payload_name: str,
    expected_purpose: str,
    expected_signer: str | None,
    verification_time: int | None,
    openssl_path: Path,
    openssl_sha256: str,
) -> dict[str, Any]:
    selected_openssl = _secure_openssl(openssl_path, openssl_sha256)
    envelope_payload = _stable_regular_bytes(
        envelope_path, _MAX_ENVELOPE_BYTES, "signature envelope snapshot"
    )
    envelope = load_json_bytes(envelope_payload, "signature envelope snapshot")
    if canonical_json_bytes(envelope) != envelope_payload:
        raise ReleaseError("signature envelope is not canonical JSON")
    if not isinstance(envelope, dict) or "signature_base64" not in envelope:
        raise ReleaseError("signature encoding is missing")
    encoded = envelope["signature_base64"]
    unsigned = _unsigned_envelope(
        {key: value for key, value in envelope.items() if key != "signature_base64"}
    )
    expected_key = public_key_id(
        public_key,
        openssl_path=selected_openssl,
        openssl_sha256=openssl_sha256,
    )
    if unsigned["key_id"] != expected_key:
        raise ReleaseError("signature key is not the supplied trusted key")
    if unsigned["purpose"] != expected_purpose:
        raise ReleaseError(
            f"signature purpose is {unsigned['purpose']}, expected {expected_purpose}"
        )
    if expected_signer is not None and unsigned["signer_principal"] != expected_signer:
        raise ReleaseError("signature signer principal is outside the trusted scope")
    verification_time = (
        int(time.time())
        if verification_time is None
        else _timestamp(verification_time, "verification-time")
    )
    if unsigned["signed_at"] > verification_time:
        raise ReleaseError("signature signing time is in the future")
    if "expires_at" in unsigned and verification_time >= unsigned["expires_at"]:
        raise ReleaseError("signature has expired")
    reference = unsigned["payload"]
    payload_state = _stable_file_state(
        payload, _MAX_PAYLOAD_BYTES, "signature payload snapshot"
    )
    if (
        reference.get("name") != expected_payload_name
        or reference.get("sha256") != payload_state.sha256
        or reference.get("bytes") != payload_state.size
    ):
        raise ReleaseError("signature envelope is bound to different payload bytes")
    if not isinstance(encoded, str):
        raise ReleaseError("signature encoding is missing")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ReleaseError("signature is not canonical base64") from error
    if base64.b64encode(signature).decode("ascii") != encoded:
        raise ReleaseError("signature is not canonical base64")
    if len(signature) != 64:
        raise ReleaseError("signature is not a 64-byte Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="cigar-signature-") as directory:
        signature_input = Path(directory) / "signature-input.bin"
        signature_path = Path(directory) / "signature.bin"
        _write_private_snapshot(signature_input, _signature_input(unsigned))
        _write_private_snapshot(signature_path, signature)
        _run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-in",
                str(signature_input),
                "-sigfile",
                str(signature_path),
            ],
            selected_openssl,
            openssl_sha256,
        )
    return unsigned


def main() -> int:
    arguments = parse_arguments()
    if arguments.action == "sign":
        selected = selected_evidence_directory(arguments.evidence_dir)
        if selected is None:
            payload = arguments.payload.absolute()
            private_key = arguments.private_key.absolute()
            public_key = arguments.public_key.absolute()
            output = arguments.out.absolute()
            sign(
                payload,
                private_key,
                public_key,
                output,
                signer_principal=arguments.signer_principal,
                purpose=arguments.purpose,
                signed_at=arguments.signed_at,
                expires_at=arguments.expires_at,
                openssl_path=arguments.openssl,
                openssl_sha256=arguments.openssl_sha256,
            )
            envelope = _stable_regular_bytes(
                output,
                _MAX_ENVELOPE_BYTES,
                "signature output",
            )
        else:
            envelope = _sign_to_evidence_workspace(arguments, selected)
        print(envelope.decode("utf-8"), end="")
    else:
        reject_evidence_directory(
            arguments.evidence_dir,
            "signature verification",
        )
        verify(
            arguments.envelope.absolute(),
            arguments.payload.absolute(),
            arguments.public_key.absolute(),
            expected_purpose=arguments.expected_purpose,
            expected_signer=arguments.expected_signer,
            verification_time=arguments.verification_time,
            openssl_path=arguments.openssl,
            openssl_sha256=arguments.openssl_sha256,
        )
        print("signature verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (subprocess.TimeoutExpired, ReleaseError) as error:
        raise SystemExit(f"signature operation failed: {error}") from error
