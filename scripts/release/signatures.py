#!/usr/bin/env python3
"""Create and verify detached Ed25519 release envelopes using explicit key files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    process_failure_summary,
    run_bounded,
    safe_relative_path,
    sha256_file,
    write_bytes,
    write_json,
)


_SIGNATURE_DOMAIN = b"CIGAR-RELEASE-SIGNATURE-V1\x00"
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")


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
    return parser.parse_args()


def _run(arguments: list[str]) -> bytes:
    result = run_bounded(
        arguments, timeout=30, max_stdout=1024 * 1024, max_stderr=1024 * 1024
    )
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, "OpenSSL operation"))
    return result.stdout


def _public_der(public_key: Path) -> bytes:
    payload = _run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"]
    )
    if len(payload) != len(_ED25519_SPKI_PREFIX) + 32 or not payload.startswith(
        _ED25519_SPKI_PREFIX
    ):
        raise ReleaseError(
            "release public key is not an Ed25519 SubjectPublicKeyInfo key"
        )
    return payload


def public_key_id(public_key: Path) -> str:
    """Return the stable key identifier used by signature envelopes."""
    return f"sha256:{hashlib.sha256(_public_der(public_key)).hexdigest()}"


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
) -> None:
    resolved_inputs = {payload.resolve(), private_key.resolve(), public_key.resolve()}
    if output.resolve() in resolved_inputs:
        raise ReleaseError(
            "signature output must not replace its payload or key material"
        )
    if not payload.is_file() or not private_key.is_file() or not public_key.is_file():
        raise ReleaseError("payload and key arguments must be regular files")
    if payload.is_symlink() or private_key.is_symlink() or public_key.is_symlink():
        raise ReleaseError("payload and key arguments must not be symlinks")
    if os.name != "nt" and stat.S_IMODE(private_key.stat().st_mode) & 0o077:
        raise ReleaseError("private signing key must not be group- or world-accessible")
    key_id = public_key_id(public_key)
    unsigned: dict[str, Any] = {
        "schema_version": "cigar.signature-envelope.v1",
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signer_principal": signer_principal,
        "purpose": purpose,
        "signed_at": signed_at,
        "payload": {
            "name": payload.name,
            "sha256": sha256_file(payload),
            "bytes": payload.stat().st_size,
        },
    }
    if expires_at is not None:
        unsigned["expires_at"] = expires_at
    _unsigned_envelope(unsigned)
    with tempfile.TemporaryDirectory(prefix="cigar-signature-") as directory:
        signature_input = Path(directory) / "signature-input.bin"
        signature = Path(directory) / "signature.bin"
        write_bytes(signature_input, _signature_input(unsigned))
        _run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(signature_input),
                "-out",
                str(signature),
            ]
        )
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
                str(signature),
            ]
        )
        signature_bytes = signature.read_bytes()
    if (
        unsigned["payload"]["sha256"] != sha256_file(payload)
        or unsigned["payload"]["bytes"] != payload.stat().st_size
    ):
        raise ReleaseError("signature payload changed while it was being signed")
    if len(signature_bytes) != 64:
        raise ReleaseError("OpenSSL produced an invalid Ed25519 signature length")
    envelope = {
        **unsigned,
        "signature_base64": base64.b64encode(signature_bytes).decode("ascii"),
    }
    write_json(output, envelope)


def verify(
    envelope_path: Path,
    payload: Path,
    public_key: Path,
    *,
    expected_purpose: str,
    expected_signer: str | None = None,
    verification_time: int | None = None,
) -> dict[str, Any]:
    if envelope_path.is_symlink() or payload.is_symlink() or public_key.is_symlink():
        raise ReleaseError("envelope, payload, and public key must not be symlinks")
    if not envelope_path.is_file() or not payload.is_file() or not public_key.is_file():
        raise ReleaseError("envelope, payload, and public key must be regular files")
    envelope = load_json(envelope_path)
    if not isinstance(envelope, dict) or "signature_base64" not in envelope:
        raise ReleaseError("signature encoding is missing")
    encoded = envelope["signature_base64"]
    unsigned = _unsigned_envelope(
        {key: value for key, value in envelope.items() if key != "signature_base64"}
    )
    expected_key = public_key_id(public_key)
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
    observed_digest = sha256_file(payload)
    observed_size = payload.stat().st_size
    if (
        reference.get("name") != payload.name
        or reference.get("sha256") != observed_digest
        or reference.get("bytes") != observed_size
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
        write_bytes(signature_input, _signature_input(unsigned))
        write_bytes(signature_path, signature)
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
            ]
        )
    if (
        sha256_file(payload) != observed_digest
        or payload.stat().st_size != observed_size
    ):
        raise ReleaseError("signature payload changed while it was being verified")
    return unsigned


def main() -> int:
    arguments = parse_arguments()
    if arguments.action == "sign":
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
        )
        print(canonical_json_bytes(load_json(output)).decode("utf-8"), end="")
    else:
        verify(
            arguments.envelope.absolute(),
            arguments.payload.absolute(),
            arguments.public_key.absolute(),
            expected_purpose=arguments.expected_purpose,
            expected_signer=arguments.expected_signer,
            verification_time=arguments.verification_time,
        )
        print("signature verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (subprocess.TimeoutExpired, ReleaseError) as error:
        raise SystemExit(f"signature operation failed: {error}") from error
