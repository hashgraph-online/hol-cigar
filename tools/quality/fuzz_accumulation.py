#!/usr/bin/env python3
"""Append and verify signed, candidate-bound libFuzzer accumulation receipts.

This module never starts a fuzzer. Workers submit canonical, Ed25519-signed
receipts produced by the separately controlled campaign runner. The ledger is a
create-new hash chain of immutable files; a final verifier recomputes every
per-target duration and refuses aggregate-only claims.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "scripts" / "release"
if str(RELEASE) not in sys.path:
    sys.path.insert(0, str(RELEASE))

from release_lib import (  # noqa: E402
    ReleaseError,
    canonical_json_bytes,
    load_json_bytes,
    sha256_file,
)
from signatures import public_key_id, verify as verify_signature  # noqa: E402


CAMPAIGN_PATH = ROOT / "fuzz" / "campaign-v1.json"
ENTRY_SCHEMA = "cigar.fuzz-accumulation-entry.v1"
RECEIPT_SCHEMA = "cigar.fuzz-worker-receipt.v1"
BUNDLE_SCHEMA = "cigar.fuzz-worker-receipt-bundle.v1"
AUTHORITY_SCHEMA = "cigar.fuzz-worker-authority.v1"
SUMMARY_SCHEMA = "cigar.fuzz-accumulation-summary.v1"
SIGNATURE_PURPOSE = "fuzz-worker-receipt"
RECEIPT_PAYLOAD_NAME = "fuzz-worker-receipt.json"
ZERO_DIGEST = "0" * 64
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
ENTRY_NAME = re.compile(r"^([0-9]{20})-([0-9a-f]{64})\.json$")
MAXIMUM_DOCUMENT_BYTES = 16 * 1024 * 1024
MAXIMUM_ENTRIES = 1_000_000
MAXIMUM_RUN_SECONDS = 24 * 60 * 60
MAXIMUM_SIGNING_DELAY_SECONDS = 24 * 60 * 60
DEFECT_KINDS = frozenset({"crash", "hang", "oom", "sanitizer"})
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | _NOFOLLOW | _DIRECTORY | _CLOEXEC
_READ_FILE_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NONBLOCK
_LOCK_FILE_FLAGS = os.O_RDWR | _NOFOLLOW | _CLOEXEC | _NONBLOCK
_CREATE_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
MAXIMUM_PATH_DEPTH = 64
MAXIMUM_DIRECTORY_ENTRIES = 1_100_000


class FuzzLedgerError(RuntimeError):
    """A fuzz accumulation authority, receipt, or ledger invariant failed."""


SignatureVerifier = Callable[[dict[str, Any], dict[str, Any]], None]
RaceHook = Callable[[str], None]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _receipt_content_id(receipt: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in receipt.items() if key != "receipt_id"}
    return _sha256_bytes(canonical_json_bytes(payload))


def _strict_canonical_document(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise FuzzLedgerError(f"{label} is not a regular non-symlink file")
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or not 0 < metadata.st_size <= MAXIMUM_DOCUMENT_BYTES
    ):
        raise FuzzLedgerError(f"{label} has unsafe mode, links, or size")
    before = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    try:
        payload = path.read_bytes()
        document = load_json_bytes(payload, label)
    except (OSError, ReleaseError) as error:
        raise FuzzLedgerError(f"cannot read {label}: {error}") from error
    after_metadata = path.stat(follow_symlinks=False)
    after = (
        after_metadata.st_dev,
        after_metadata.st_ino,
        after_metadata.st_size,
        after_metadata.st_mtime_ns,
    )
    if before != after or len(payload) != metadata.st_size:
        raise FuzzLedgerError(f"{label} changed while it was read")
    if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
        raise FuzzLedgerError(f"{label} is not a canonical JSON object")
    return document


def _campaign() -> tuple[list[str], int, str]:
    try:
        document = json.loads(CAMPAIGN_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FuzzLedgerError(f"cannot read fuzz campaign policy: {error}") from error
    targets = document.get("targets")
    threshold = document.get("minimum_clean_cpu_seconds_per_target")
    if (
        document.get("schema_version") != "cigar.fuzz-campaign.v1"
        or not isinstance(targets, list)
        or len(targets) != 14
        or len(set(targets)) != 14
        or any(
            not isinstance(target, str) or SAFE_ID.fullmatch(target) is None
            for target in targets
        )
        or isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or threshold != 604_800
        or document.get("sanitizers") != ["address"]
    ):
        raise FuzzLedgerError("fuzz campaign policy is malformed or weakened")
    return targets, threshold, sha256_file(CAMPAIGN_PATH)


def _safe_authority_member(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FuzzLedgerError("worker public-key path is invalid")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise FuzzLedgerError("worker public-key path is unsafe")
    try:
        path = root.joinpath(*relative.parts).resolve(strict=True)
        path.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise FuzzLedgerError(
            "worker public-key path escapes its authority root"
        ) from error
    return path


def load_authority(path: Path, *, openssl_path: Path | None = None) -> dict[str, Any]:
    document = _strict_canonical_document(path, "fuzz worker authority")
    workers = document.get("workers")
    openssl_digest = document.get("openssl_sha256")
    if (
        set(document)
        != {"schema_version", "campaign_sha256", "openssl_sha256", "workers"}
        or document.get("schema_version") != AUTHORITY_SCHEMA
        or HEX_64.fullmatch(str(document.get("campaign_sha256"))) is None
        or HEX_64.fullmatch(str(openssl_digest)) is None
        or not isinstance(workers, list)
        or not workers
    ):
        raise FuzzLedgerError("fuzz worker authority has an unexpected shape")
    targets, _threshold, campaign_sha256 = _campaign()
    del targets
    if document["campaign_sha256"] != campaign_sha256:
        raise FuzzLedgerError("fuzz worker authority is bound to another campaign")

    normalized: dict[str, dict[str, Any]] = {}
    for worker in workers:
        if not isinstance(worker, dict) or set(worker) != {
            "id",
            "signer_principal",
            "key_id",
            "public_key",
            "public_key_sha256",
            "active_from",
            "active_until",
        }:
            raise FuzzLedgerError("fuzz worker authority entry has an unexpected shape")
        identifier = worker.get("id")
        principal = worker.get("signer_principal")
        active_from = worker.get("active_from")
        active_until = worker.get("active_until")
        if (
            not isinstance(identifier, str)
            or SAFE_ID.fullmatch(identifier) is None
            or identifier in normalized
            or not isinstance(principal, str)
            or SAFE_ID.fullmatch(principal) is None
            or isinstance(active_from, bool)
            or not isinstance(active_from, int)
            or isinstance(active_until, bool)
            or not isinstance(active_until, int)
            or not 0 <= active_from < active_until
        ):
            raise FuzzLedgerError(
                "fuzz worker authority identity or interval is invalid"
            )
        public_key = _safe_authority_member(path.parent, worker["public_key"])
        metadata = public_key.stat(follow_symlinks=False)
        if (
            public_key.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or worker.get("public_key_sha256") != sha256_file(public_key)
        ):
            raise FuzzLedgerError(
                "fuzz worker public key is unsafe or has the wrong digest"
            )
        try:
            observed_key_id = public_key_id(
                public_key,
                openssl_path=openssl_path,
                openssl_sha256=openssl_digest,
            )
        except ReleaseError as error:
            raise FuzzLedgerError(
                f"cannot validate fuzz worker public key: {error}"
            ) from error
        if worker.get("key_id") != observed_key_id:
            raise FuzzLedgerError("fuzz worker public key ID is stale or substituted")
        normalized[identifier] = {
            **worker,
            "public_key_path": public_key,
            "openssl_path": openssl_path,
            "openssl_sha256": openssl_digest,
        }
    return {
        "campaign_sha256": campaign_sha256,
        "workers": normalized,
    }


def _validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise FuzzLedgerError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _validate_receipt(
    receipt: object, targets: set[str], campaign_sha256: str
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "receipt_id",
        "candidate",
        "target",
        "worker_id",
        "started_at",
        "finished_at",
        "clean_cpu_seconds",
        "outcome",
        "defect_kind",
        "crash_artifact_count",
        "private_mutable_corpus",
        "bindings",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise FuzzLedgerError("fuzz worker receipt has an unexpected shape")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise FuzzLedgerError("fuzz worker receipt schema is unsupported")
    _validate_digest(receipt.get("receipt_id"), "fuzz receipt ID")
    candidate = receipt.get("candidate")
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"revision", "tree", "source_sha256"}
        or HEX_40.fullmatch(str(candidate.get("revision"))) is None
        or HEX_40.fullmatch(str(candidate.get("tree"))) is None
        or HEX_64.fullmatch(str(candidate.get("source_sha256"))) is None
    ):
        raise FuzzLedgerError("fuzz worker candidate binding is invalid")
    target = receipt.get("target")
    worker = receipt.get("worker_id")
    started = receipt.get("started_at")
    finished = receipt.get("finished_at")
    seconds = receipt.get("clean_cpu_seconds")
    artifacts = receipt.get("crash_artifact_count")
    if (
        target not in targets
        or not isinstance(worker, str)
        or SAFE_ID.fullmatch(worker) is None
        or isinstance(started, bool)
        or not isinstance(started, int)
        or isinstance(finished, bool)
        or not isinstance(finished, int)
        or not 0 <= started < finished
        or finished - started > MAXIMUM_RUN_SECONDS
        or isinstance(seconds, bool)
        or not isinstance(seconds, int)
        or seconds < 0
        or seconds > MAXIMUM_RUN_SECONDS
        or isinstance(artifacts, bool)
        or not isinstance(artifacts, int)
        or not 0 <= artifacts <= 1_000_000
        or receipt.get("private_mutable_corpus") is not True
    ):
        raise FuzzLedgerError(
            "fuzz worker receipt timing, worker, or corpus mode is invalid"
        )
    outcome = receipt.get("outcome")
    defect = receipt.get("defect_kind")
    if outcome == "clean":
        if defect is not None or artifacts != 0 or seconds <= 0:
            raise FuzzLedgerError(
                "clean fuzz receipt contains a defect or no clean CPU time"
            )
    elif outcome == "defect":
        if defect not in DEFECT_KINDS or artifacts <= 0 or seconds != 0:
            raise FuzzLedgerError(
                "defect fuzz receipt has an invalid defect disposition"
            )
    else:
        raise FuzzLedgerError("fuzz worker outcome is invalid")
    bindings = receipt.get("bindings")
    if not isinstance(bindings, dict) or set(bindings) != {
        "binary_sha256",
        "toolchain_sha256",
        "sanitizer",
        "target_source_sha256",
        "campaign_sha256",
        "corpus_before_sha256",
        "corpus_after_sha256",
    }:
        raise FuzzLedgerError("fuzz worker receipt bindings have an unexpected shape")
    for field in (
        "binary_sha256",
        "toolchain_sha256",
        "target_source_sha256",
        "campaign_sha256",
        "corpus_before_sha256",
        "corpus_after_sha256",
    ):
        _validate_digest(bindings.get(field), f"fuzz binding {field}")
    if (
        bindings.get("campaign_sha256") != campaign_sha256
        or bindings.get("sanitizer") != "address"
    ):
        raise FuzzLedgerError("fuzz receipt campaign or sanitizer binding is stale")
    if receipt["receipt_id"] != _receipt_content_id(receipt):
        raise FuzzLedgerError("fuzz receipt ID is not its canonical content digest")
    return receipt


def _verify_embedded_signature(
    receipt: dict[str, Any], signature: dict[str, Any], worker: dict[str, Any]
) -> None:
    with tempfile.TemporaryDirectory(prefix="cigar-fuzz-receipt-verify-") as raw:
        directory = Path(raw)
        # Signature verification inputs must remain private to the qualifier account.
        os.chmod(directory, 0o700)  # fmt: skip  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        payload = directory / RECEIPT_PAYLOAD_NAME
        envelope = directory / "receipt.sig.json"
        payload.write_bytes(canonical_json_bytes(receipt))
        envelope.write_bytes(canonical_json_bytes(signature))
        payload.chmod(0o600)
        envelope.chmod(0o600)
        try:
            unsigned = verify_signature(
                envelope,
                payload,
                worker["public_key_path"],
                expected_purpose=SIGNATURE_PURPOSE,
                expected_signer=worker["signer_principal"],
                verification_time=signature.get("signed_at"),
                openssl_path=worker["openssl_path"],
                openssl_sha256=worker["openssl_sha256"],
            )
        except (ReleaseError, TypeError) as error:
            raise FuzzLedgerError(
                f"fuzz worker signature is invalid: {error}"
            ) from error
    signed_at = unsigned.get("signed_at")
    if (
        isinstance(signed_at, bool)
        or not isinstance(signed_at, int)
        or not receipt["finished_at"] <= signed_at
        or signed_at - receipt["finished_at"] > MAXIMUM_SIGNING_DELAY_SECONDS
        or not worker["active_from"] <= signed_at < worker["active_until"]
    ):
        raise FuzzLedgerError(
            "fuzz worker signature is outside its trusted time window"
        )


def validate_entries(
    entries: Sequence[Mapping[str, Any]],
    authority: Mapping[str, Any],
    *,
    require_threshold: bool,
    signature_verifier: SignatureVerifier | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    targets, threshold, campaign_sha256 = _campaign()
    workers = authority.get("workers")
    if authority.get("campaign_sha256") != campaign_sha256 or not isinstance(
        workers, dict
    ):
        raise FuzzLedgerError("fuzz worker authority is invalid or stale")
    verify_worker_signature = signature_verifier or _verify_embedded_signature
    if len(entries) > MAXIMUM_ENTRIES:
        raise FuzzLedgerError("fuzz ledger exceeds its entry-count bound")
    current_time = int(time.time()) if now is None else now
    expected_previous = ZERO_DIGEST
    candidate: dict[str, Any] | None = None
    receipt_ids: set[str] = set()
    target_bindings: dict[str, tuple[str, ...]] = {}
    worker_finished: dict[str, int] = {}
    corpus_heads: dict[tuple[str, str], str] = {}
    defective_targets: set[str] = set()
    target_seconds = {target: 0 for target in targets}
    previous_appended_at = 0

    for index, raw_entry in enumerate(entries, start=1):
        entry = dict(raw_entry)
        if (
            set(entry)
            != {
                "schema_version",
                "sequence",
                "previous_entry_sha256",
                "appended_at",
                "receipt",
                "signature",
            }
            or entry.get("schema_version") != ENTRY_SCHEMA
        ):
            raise FuzzLedgerError("fuzz ledger entry has an unexpected shape")
        if (
            entry.get("sequence") != index
            or entry.get("previous_entry_sha256") != expected_previous
        ):
            raise FuzzLedgerError("fuzz ledger sequence or hash chain is broken")
        appended_at = entry.get("appended_at")
        if (
            isinstance(appended_at, bool)
            or not isinstance(appended_at, int)
            or appended_at < 0
            or appended_at < previous_appended_at
            or appended_at > current_time + 300
        ):
            raise FuzzLedgerError("fuzz ledger append time is invalid")
        previous_appended_at = appended_at
        receipt = _validate_receipt(entry.get("receipt"), set(targets), campaign_sha256)
        signature = entry.get("signature")
        if not isinstance(signature, dict):
            raise FuzzLedgerError("fuzz ledger signature is not an object")
        worker = workers.get(receipt["worker_id"])
        if not isinstance(worker, dict):
            raise FuzzLedgerError("fuzz receipt names an untrusted worker")
        verify_worker_signature(receipt, signature, worker)
        signed_at = signature.get("signed_at")
        if (
            isinstance(signed_at, bool)
            or not isinstance(signed_at, int)
            or not receipt["finished_at"] <= signed_at <= appended_at
            or appended_at - signed_at > MAXIMUM_SIGNING_DELAY_SECONDS
            or not worker.get("active_from", 1) <= signed_at
            or not signed_at < worker.get("active_until", 0)
        ):
            raise FuzzLedgerError(
                "fuzz receipt signature/append clock order is invalid"
            )

        receipt_id = receipt["receipt_id"]
        if receipt_id in receipt_ids:
            raise FuzzLedgerError(
                "fuzz ledger contains a duplicate or replayed receipt ID"
            )
        receipt_ids.add(receipt_id)
        if candidate is None:
            candidate = dict(receipt["candidate"])
        elif receipt["candidate"] != candidate:
            raise FuzzLedgerError("fuzz ledger mixes release candidates")

        previous_finished = worker_finished.get(receipt["worker_id"])
        if previous_finished is not None and receipt["started_at"] < previous_finished:
            raise FuzzLedgerError("fuzz worker intervals overlap or reverse the clock")
        worker_finished[receipt["worker_id"]] = receipt["finished_at"]
        target = receipt["target"]
        if target in defective_targets:
            raise FuzzLedgerError("fuzz ledger accumulates after a target defect")
        bindings = receipt["bindings"]
        immutable_binding = (
            bindings["binary_sha256"],
            bindings["toolchain_sha256"],
            bindings["sanitizer"],
            bindings["target_source_sha256"],
            bindings["campaign_sha256"],
        )
        prior_binding = target_bindings.setdefault(target, immutable_binding)
        if prior_binding != immutable_binding:
            raise FuzzLedgerError(
                "fuzz target binary, toolchain, or source binding changed"
            )
        corpus_key = (receipt["worker_id"], target)
        prior_corpus = corpus_heads.get(corpus_key)
        if (
            prior_corpus is not None
            and bindings["corpus_before_sha256"] != prior_corpus
        ):
            raise FuzzLedgerError("fuzz worker corpus lineage is broken")
        corpus_heads[corpus_key] = bindings["corpus_after_sha256"]
        if receipt["outcome"] == "defect":
            defective_targets.add(target)
            target_seconds[target] = 0
        else:
            target_seconds[target] += receipt["clean_cpu_seconds"]
        expected_previous = _sha256_bytes(canonical_json_bytes(entry))

    metrics = {
        **{
            f"fuzz.target_seconds.{target}": target_seconds[target]
            for target in targets
        },
        "fuzz.total_seconds": sum(target_seconds.values()),
        "fuzz.unresolved_defect_count": len(defective_targets),
    }
    missing = [target for target in targets if target_seconds[target] < threshold]
    if require_threshold and (candidate is None or missing or defective_targets):
        raise FuzzLedgerError(
            "fuzz accumulation is incomplete or defective; "
            f"missing_or_under_time={missing}, defective={sorted(defective_targets)}"
        )
    return {
        "schema_version": SUMMARY_SCHEMA,
        "status": "passed" if not missing and not defective_targets else "incomplete",
        "candidate": candidate,
        "campaign": {
            "path": "fuzz/campaign-v1.json",
            "sha256": campaign_sha256,
            "target_count": len(targets),
            "minimum_clean_cpu_seconds_per_target": threshold,
            "minimum_total_clean_cpu_seconds": threshold * len(targets),
        },
        "entry_count": len(entries),
        "head_sha256": expected_previous,
        "metrics": metrics,
        "missing_or_under_time_targets": missing,
        "defective_targets": sorted(defective_targets),
    }


@dataclass(frozen=True)
class _FsIdentity:
    device: int
    inode: int
    owner: int
    group: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass
class _PinnedDirectory:
    name: str
    descriptor: int
    identity: _FsIdentity
    private: bool


@dataclass(frozen=True)
class _EntrySnapshot:
    name: str
    identity: _FsIdentity
    payload_sha256: str


def _identity(metadata: os.stat_result) -> _FsIdentity:
    return _FsIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        group=metadata.st_gid,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _directory_identity(identity: _FsIdentity) -> tuple[int, ...]:
    return (
        identity.device,
        identity.inode,
        identity.owner,
        identity.group,
        identity.mode,
        identity.links,
    )


def _directory_object(identity: _FsIdentity) -> tuple[int, ...]:
    return (
        identity.device,
        identity.inode,
        identity.owner,
        identity.group,
        identity.mode,
    )


def _same_object(left: _FsIdentity, right: _FsIdentity) -> bool:
    return left.device == right.device and left.inode == right.inode


def _portable_name(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _directory_names(descriptor: int, label: str) -> list[str]:
    try:
        names = os.listdir(descriptor)
    except OSError as error:
        raise FuzzLedgerError(f"cannot enumerate {label}: {error}") from error
    if len(names) > MAXIMUM_DIRECTORY_ENTRIES:
        raise FuzzLedgerError(f"{label} exceeds the bounded directory-entry limit")
    if any(not isinstance(name, str) for name in names):
        raise FuzzLedgerError(f"{label} contains a non-text filename")
    return names


def _lookup_exact_name(descriptor: int, name: str, label: str) -> bool:
    aliases = [
        observed
        for observed in _directory_names(descriptor, label)
        if _portable_name(observed) == _portable_name(name)
    ]
    if aliases == [name]:
        return True
    if not aliases:
        return False
    raise FuzzLedgerError(
        f"{label} contains a case or Unicode alias for required name {name!r}"
    )


def _reject_portable_aliases(names: Sequence[str], label: str) -> None:
    observed: dict[str, str] = {}
    for name in names:
        portable = _portable_name(name)
        prior = observed.setdefault(portable, name)
        if prior != name:
            raise FuzzLedgerError(f"{label} contains case or Unicode filename aliases")


def _lstat_at(descriptor: int, name: str, label: str) -> _FsIdentity:
    try:
        return _identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
    except OSError as error:
        raise FuzzLedgerError(f"cannot inspect {label}: {error}") from error


def _validate_directory(
    identity: _FsIdentity,
    label: str,
    *,
    private: bool,
) -> None:
    if not stat.S_ISDIR(identity.mode) or identity.links < 1:
        raise FuzzLedgerError(f"{label} is not a real directory")
    if private and (
        identity.owner != os.geteuid() or stat.S_IMODE(identity.mode) != 0o700
    ):
        raise FuzzLedgerError(f"{label} must be an owner-private mode-0700 directory")


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    label: str,
    *,
    private: bool,
) -> tuple[int, _FsIdentity]:
    before = _lstat_at(parent_descriptor, name, label)
    _validate_directory(before, label, private=private)
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_descriptor)
    except OSError as error:
        raise FuzzLedgerError(f"cannot pin {label}: {error}") from error
    try:
        opened = _identity(os.fstat(descriptor))
        after = _lstat_at(parent_descriptor, name, label)
        _validate_directory(opened, label, private=private)
        if before != opened or after != opened:
            raise FuzzLedgerError(f"{label} was substituted while it was opened")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _validate_regular_file(
    identity: _FsIdentity,
    label: str,
    *,
    mode: int,
    links: set[int],
    device: int,
    allow_empty: bool,
) -> None:
    size_ok = 0 <= identity.size <= MAXIMUM_DOCUMENT_BYTES
    if not allow_empty:
        size_ok = 0 < identity.size <= MAXIMUM_DOCUMENT_BYTES
    if (
        not stat.S_ISREG(identity.mode)
        or identity.owner != os.geteuid()
        or stat.S_IMODE(identity.mode) != mode
        or identity.links not in links
        or identity.device != device
        or not size_ok
    ):
        raise FuzzLedgerError(
            f"{label} has unsafe owner, mode, type, links, device, or size"
        )


def _validate_lock_file(identity: _FsIdentity, device: int) -> None:
    _validate_regular_file(
        identity,
        "fuzz ledger lock file",
        mode=0o600,
        links={1},
        device=device,
        allow_empty=True,
    )
    if identity.size != 0:
        raise FuzzLedgerError("fuzz ledger lock file must remain empty")


def _open_regular_at(
    parent_descriptor: int,
    name: str,
    label: str,
    *,
    flags: int,
    mode: int,
    links: set[int],
    device: int,
    allow_empty: bool,
) -> tuple[int, _FsIdentity]:
    before = _lstat_at(parent_descriptor, name, label)
    _validate_regular_file(
        before,
        label,
        mode=mode,
        links=links,
        device=device,
        allow_empty=allow_empty,
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise FuzzLedgerError(f"cannot pin {label}: {error}") from error
    try:
        opened = _identity(os.fstat(descriptor))
        after = _lstat_at(parent_descriptor, name, label)
        _validate_regular_file(
            opened,
            label,
            mode=mode,
            links=links,
            device=device,
            allow_empty=allow_empty,
        )
        if before != opened or after != opened:
            raise FuzzLedgerError(f"{label} was substituted while it was opened")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _absolute_components(root: Path) -> tuple[str, ...]:
    if not root.is_absolute() or root.anchor != os.sep:
        raise FuzzLedgerError("fuzz ledger directory must be absolute")
    components = tuple(part for part in root.parts if part != root.anchor)
    if (
        not components
        or len(components) > MAXIMUM_PATH_DEPTH
        or any(
            part in {"", ".", ".."} or unicodedata.normalize("NFC", part) != part
            for part in components
        )
    ):
        raise FuzzLedgerError("fuzz ledger path is non-canonical or too deep")
    return components


class _PinnedLedger:
    """A no-follow, descriptor-relative authority for one ledger operation."""

    def __init__(
        self,
        *,
        path: Path,
        chain: list[_PinnedDirectory],
        entries: _PinnedDirectory,
        lock_descriptor: int,
        lock_identity: _FsIdentity,
        exclusive: bool,
        race_hook: RaceHook | None,
    ) -> None:
        self.path = path
        self.chain = chain
        self.entries = entries
        self.lock_descriptor = lock_descriptor
        self.lock_identity = lock_identity
        self.exclusive = exclusive
        self.race_hook = race_hook
        self._locked = True
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        create: bool,
        create_lock: bool,
        exclusive: bool,
        race_hook: RaceHook | None = None,
    ) -> _PinnedLedger:
        if not _NOFOLLOW or not _DIRECTORY:
            raise FuzzLedgerError(
                "this platform lacks required no-follow directory-descriptor support"
            )
        components = _absolute_components(path)
        descriptors: list[int] = []
        lock_descriptor: int | None = None
        locked = False
        try:
            filesystem_root = os.open(os.sep, _DIRECTORY_FLAGS)
            descriptors.append(filesystem_root)
            root_identity = _identity(os.fstat(filesystem_root))
            _validate_directory(root_identity, "filesystem root", private=False)
            chain = [
                _PinnedDirectory(
                    name=os.sep,
                    descriptor=filesystem_root,
                    identity=root_identity,
                    private=False,
                )
            ]
            parent_descriptor = filesystem_root
            for index, component in enumerate(components):
                label = f"fuzz ledger path component {component!r}"
                exists = _lookup_exact_name(parent_descriptor, component, label)
                created = False
                if not exists:
                    if not create:
                        raise FuzzLedgerError(f"{label} does not exist")
                    try:
                        os.mkdir(component, 0o700, dir_fd=parent_descriptor)
                        os.fsync(parent_descriptor)
                    except OSError as error:
                        raise FuzzLedgerError(
                            f"cannot create {label}: {error}"
                        ) from error
                    created = True
                    if not _lookup_exact_name(parent_descriptor, component, label):
                        raise FuzzLedgerError(f"created {label} disappeared")
                private = created or index == len(components) - 1
                descriptor, identity = _open_directory_at(
                    parent_descriptor,
                    component,
                    label,
                    private=private,
                )
                descriptors.append(descriptor)
                chain.append(
                    _PinnedDirectory(
                        name=component,
                        descriptor=descriptor,
                        identity=identity,
                        private=private,
                    )
                )
                parent_descriptor = descriptor

            root_pin = chain[-1]
            _validate_directory(root_pin.identity, "fuzz ledger root", private=True)
            entries_created = False
            if not _lookup_exact_name(
                root_pin.descriptor, "entries", "fuzz ledger root"
            ):
                if not create:
                    raise FuzzLedgerError(
                        "fuzz ledger entries directory does not exist"
                    )
                try:
                    os.mkdir("entries", 0o700, dir_fd=root_pin.descriptor)
                    os.fsync(root_pin.descriptor)
                    entries_created = True
                except OSError as error:
                    raise FuzzLedgerError(
                        f"cannot create fuzz ledger entries directory: {error}"
                    ) from error
            entries_descriptor, entries_identity = _open_directory_at(
                root_pin.descriptor,
                "entries",
                "fuzz ledger entries directory",
                private=True,
            )
            if entries_created:
                os.fsync(entries_descriptor)
            descriptors.append(entries_descriptor)
            if entries_identity.device != root_pin.identity.device:
                raise FuzzLedgerError(
                    "fuzz ledger root and entries directory cross devices"
                )
            entries = _PinnedDirectory(
                name="entries",
                descriptor=entries_descriptor,
                identity=entries_identity,
                private=True,
            )

            lock_exists = _lookup_exact_name(
                root_pin.descriptor, ".append.lock", "fuzz ledger root"
            )
            if not lock_exists:
                if not create_lock:
                    raise FuzzLedgerError("fuzz ledger lock file does not exist")
                try:
                    lock_descriptor = os.open(
                        ".append.lock",
                        _LOCK_FILE_FLAGS | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=root_pin.descriptor,
                    )
                except OSError as error:
                    raise FuzzLedgerError(
                        f"cannot create fuzz ledger lock file: {error}"
                    ) from error
                os.fchmod(lock_descriptor, 0o600)
                os.fsync(lock_descriptor)
                os.fsync(root_pin.descriptor)
                lock_identity = _identity(os.fstat(lock_descriptor))
                _validate_lock_file(lock_identity, root_pin.identity.device)
                named_lock = _lstat_at(
                    root_pin.descriptor, ".append.lock", "fuzz ledger lock file"
                )
                if named_lock != lock_identity:
                    raise FuzzLedgerError(
                        "fuzz ledger lock file was substituted while it was created"
                    )
            else:
                lock_descriptor, lock_identity = _open_regular_at(
                    root_pin.descriptor,
                    ".append.lock",
                    "fuzz ledger lock file",
                    flags=_LOCK_FILE_FLAGS,
                    mode=0o600,
                    links={1},
                    device=root_pin.identity.device,
                    allow_empty=True,
                )
                _validate_lock_file(lock_identity, root_pin.identity.device)

            fcntl.flock(lock_descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            locked = True

            # Directory link counts can legitimately change while the owned structure is
            # created. Freeze every descriptor identity only after setup and lock acquisition.
            for pin in chain:
                pin.identity = _identity(os.fstat(pin.descriptor))
                _validate_directory(
                    pin.identity,
                    "fuzz ledger directory authority",
                    private=pin.private,
                )
            entries.identity = _identity(os.fstat(entries.descriptor))
            lock_identity = _identity(os.fstat(lock_descriptor))
            authority = cls(
                path=path,
                chain=chain,
                entries=entries,
                lock_descriptor=lock_descriptor,
                lock_identity=lock_identity,
                exclusive=exclusive,
                race_hook=race_hook,
            )
            authority.checkpoint("lock-held")
            return authority
        except Exception:
            if locked and lock_descriptor is not None:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    @property
    def root(self) -> _PinnedDirectory:
        return self.chain[-1]

    def _run_hook(self, label: str) -> None:
        if self.race_hook is not None:
            self.race_hook(label)

    def _validate_held_descriptors(self) -> None:
        for index, pin in enumerate(self.chain):
            observed = _identity(os.fstat(pin.descriptor))
            _validate_directory(
                observed, "fuzz ledger directory authority", private=pin.private
            )
            stable = (
                observed == pin.identity
                if index == len(self.chain) - 1
                else _directory_identity(observed) == _directory_identity(pin.identity)
            )
            if not stable:
                raise FuzzLedgerError(
                    "fuzz ledger ancestor or root descriptor identity changed"
                )
        observed_entries = _identity(os.fstat(self.entries.descriptor))
        _validate_directory(
            observed_entries, "fuzz ledger entries directory", private=True
        )
        if observed_entries != self.entries.identity:
            raise FuzzLedgerError("fuzz ledger entries descriptor identity changed")
        observed_lock = _identity(os.fstat(self.lock_descriptor))
        _validate_lock_file(observed_lock, self.root.identity.device)
        if observed_lock != self.lock_identity:
            raise FuzzLedgerError("fuzz ledger lock descriptor identity changed")

    def _rewalk_authority(self) -> None:
        descriptors: list[int] = []
        try:
            descriptor = os.open(os.sep, _DIRECTORY_FLAGS)
            descriptors.append(descriptor)
            observed_root = _identity(os.fstat(descriptor))
            if _directory_identity(observed_root) != _directory_identity(
                self.chain[0].identity
            ):
                raise FuzzLedgerError("filesystem root authority was substituted")
            for index, expected in enumerate(self.chain[1:], start=1):
                if not _lookup_exact_name(
                    descriptor, expected.name, "fuzz ledger ancestor"
                ):
                    raise FuzzLedgerError("fuzz ledger ancestor disappeared")
                child, observed = _open_directory_at(
                    descriptor,
                    expected.name,
                    "fuzz ledger ancestor",
                    private=expected.private,
                )
                descriptors.append(child)
                stable = (
                    observed == expected.identity
                    if index == len(self.chain) - 1
                    else _directory_identity(observed)
                    == _directory_identity(expected.identity)
                )
                if not stable:
                    raise FuzzLedgerError(
                        "fuzz ledger ancestor or root was renamed or substituted"
                    )
                descriptor = child

            if not _lookup_exact_name(descriptor, "entries", "fuzz ledger root"):
                raise FuzzLedgerError("fuzz ledger entries directory disappeared")
            entries_descriptor, observed_entries = _open_directory_at(
                descriptor,
                "entries",
                "fuzz ledger entries directory",
                private=True,
            )
            descriptors.append(entries_descriptor)
            if observed_entries != self.entries.identity:
                raise FuzzLedgerError(
                    "fuzz ledger entries directory was renamed or substituted"
                )

            if not _lookup_exact_name(descriptor, ".append.lock", "fuzz ledger root"):
                raise FuzzLedgerError("fuzz ledger lock file disappeared")
            lock_descriptor, observed_lock = _open_regular_at(
                descriptor,
                ".append.lock",
                "fuzz ledger lock file",
                flags=_LOCK_FILE_FLAGS,
                mode=0o600,
                links={1},
                device=self.root.identity.device,
                allow_empty=True,
            )
            _validate_lock_file(observed_lock, self.root.identity.device)
            descriptors.append(lock_descriptor)
            if observed_lock != self.lock_identity:
                raise FuzzLedgerError(
                    "fuzz ledger lock file was renamed or substituted"
                )
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def checkpoint(self, label: str) -> None:
        if self._closed:
            raise FuzzLedgerError("fuzz ledger authority is already closed")
        self._run_hook(label)
        self._validate_held_descriptors()
        self._rewalk_authority()

    def refresh_entries_after_mutation(self) -> None:
        """Advance the expected directory link identity after our own dirfd mutation."""
        observed = _identity(os.fstat(self.entries.descriptor))
        _validate_directory(observed, "fuzz ledger entries directory", private=True)
        if _directory_object(observed) != _directory_object(self.entries.identity):
            raise FuzzLedgerError("fuzz ledger entries descriptor identity changed")
        self.entries.identity = observed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._locked:
                fcntl.flock(self.lock_descriptor, fcntl.LOCK_UN)
                self._locked = False
        finally:
            os.close(self.lock_descriptor)
            os.close(self.entries.descriptor)
            for pin in reversed(self.chain):
                os.close(pin.descriptor)

    def __enter__(self) -> _PinnedLedger:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()


def _read_bounded(descriptor: int, expected_size: int, label: str) -> bytes:
    chunks: list[bytes] = []
    observed = 0
    while True:
        try:
            chunk = os.read(
                descriptor, min(1024 * 1024, MAXIMUM_DOCUMENT_BYTES + 1 - observed)
            )
        except OSError as error:
            raise FuzzLedgerError(f"cannot read {label}: {error}") from error
        if not chunk:
            break
        chunks.append(chunk)
        observed += len(chunk)
        if observed > MAXIMUM_DOCUMENT_BYTES:
            raise FuzzLedgerError(f"{label} exceeds the bounded document size")
    payload = b"".join(chunks)
    if len(payload) != expected_size:
        raise FuzzLedgerError(f"{label} changed size while it was read")
    return payload


def _entry_names(authority: _PinnedLedger) -> list[str]:
    names = _directory_names(authority.entries.descriptor, "fuzz ledger entries")
    _reject_portable_aliases(names, "fuzz ledger entries")
    return sorted(names)


def _validate_entry_snapshots(
    authority: _PinnedLedger, snapshots: Sequence[_EntrySnapshot]
) -> None:
    if _entry_names(authority) != [snapshot.name for snapshot in snapshots]:
        raise FuzzLedgerError("fuzz ledger entry inventory changed while it was read")
    for snapshot in snapshots:
        descriptor, observed = _open_regular_at(
            authority.entries.descriptor,
            snapshot.name,
            f"fuzz ledger entry {snapshot.name}",
            flags=_READ_FILE_FLAGS,
            mode=0o400,
            links={1},
            device=authority.entries.identity.device,
            allow_empty=False,
        )
        try:
            if observed != snapshot.identity:
                raise FuzzLedgerError(
                    f"fuzz ledger entry {snapshot.name} changed while it was read"
                )
            payload = _read_bounded(
                descriptor,
                observed.size,
                f"fuzz ledger entry {snapshot.name}",
            )
            if (
                _identity(os.fstat(descriptor)) != snapshot.identity
                or _lstat_at(
                    authority.entries.descriptor,
                    snapshot.name,
                    f"fuzz ledger entry {snapshot.name}",
                )
                != snapshot.identity
                or _sha256_bytes(payload) != snapshot.payload_sha256
            ):
                raise FuzzLedgerError(
                    f"fuzz ledger entry {snapshot.name} content changed while it was read"
                )
        finally:
            os.close(descriptor)


def _read_entries(
    authority: _PinnedLedger,
) -> tuple[list[dict[str, Any]], list[_EntrySnapshot]]:
    authority.checkpoint("before-entry-scan")
    names = _entry_names(authority)
    documents: list[dict[str, Any]] = []
    snapshots: list[_EntrySnapshot] = []
    expected_sequence = 1
    for name in names:
        match = ENTRY_NAME.fullmatch(name)
        if match is None or int(match.group(1)) != expected_sequence:
            raise FuzzLedgerError(
                "fuzz ledger contains an unexpected or gapped entry name"
            )
        label = f"fuzz ledger entry {name}"
        descriptor, opened = _open_regular_at(
            authority.entries.descriptor,
            name,
            label,
            flags=_READ_FILE_FLAGS,
            mode=0o400,
            links={1},
            device=authority.entries.identity.device,
            allow_empty=False,
        )
        try:
            authority.checkpoint(f"entry-opened:{name}")
            named = _lstat_at(authority.entries.descriptor, name, label)
            if named != opened:
                raise FuzzLedgerError(f"{label} was substituted after it was opened")
            payload = _read_bounded(descriptor, opened.size, label)
            after = _identity(os.fstat(descriptor))
            named_after = _lstat_at(authority.entries.descriptor, name, label)
            if after != opened or named_after != opened:
                raise FuzzLedgerError(f"{label} changed while it was read")
        finally:
            os.close(descriptor)
        try:
            document = load_json_bytes(payload, label)
        except ReleaseError as error:
            raise FuzzLedgerError(f"cannot decode {label}: {error}") from error
        if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
            raise FuzzLedgerError(f"{label} is not a canonical JSON object")
        if document.get("sequence") != expected_sequence:
            raise FuzzLedgerError("fuzz ledger filename and sequence disagree")
        receipt = document.get("receipt")
        if not isinstance(receipt, dict) or receipt.get("receipt_id") != match.group(2):
            raise FuzzLedgerError("fuzz ledger filename and receipt ID disagree")
        documents.append(document)
        snapshots.append(
            _EntrySnapshot(
                name=name,
                identity=opened,
                payload_sha256=_sha256_bytes(payload),
            )
        )
        expected_sequence += 1
    authority.checkpoint("after-entry-scan")
    _validate_entry_snapshots(authority, snapshots)
    return documents, snapshots


def verify_ledger(
    ledger: Path,
    authority_path: Path,
    *,
    require_threshold: bool = True,
    openssl_path: Path | None = None,
    race_hook: RaceHook | None = None,
) -> dict[str, Any]:
    authority = load_authority(authority_path, openssl_path=openssl_path)
    with _PinnedLedger.open(
        ledger,
        create=False,
        create_lock=False,
        exclusive=False,
        race_hook=race_hook,
    ) as pinned:
        entries, snapshots = _read_entries(pinned)
        summary = validate_entries(
            entries, authority, require_threshold=require_threshold
        )
        pinned.checkpoint("verification-complete")
        _validate_entry_snapshots(pinned, snapshots)
        return summary


def _write_new_immutable(
    authority: _PinnedLedger,
    destination_name: str,
    document: Mapping[str, Any],
) -> None:
    if ENTRY_NAME.fullmatch(destination_name) is None:
        raise FuzzLedgerError("fuzz ledger destination name is invalid")
    payload = canonical_json_bytes(dict(document))
    if not 0 < len(payload) <= MAXIMUM_DOCUMENT_BYTES:
        raise FuzzLedgerError("fuzz ledger entry exceeds the document-size bound")
    authority.checkpoint("publication-start")
    if _lookup_exact_name(
        authority.entries.descriptor, destination_name, "fuzz ledger entries"
    ):
        raise FuzzLedgerError("refusing to overwrite a fuzz ledger entry")
    descriptor: int | None = None
    temporary_name = ""
    created_identity: _FsIdentity | None = None
    for _attempt in range(16):
        temporary_name = f".pending-entry-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                temporary_name,
                _CREATE_FILE_FLAGS,
                0o600,
                dir_fd=authority.entries.descriptor,
            )
            break
        except FileExistsError:
            continue
        except OSError as error:
            raise FuzzLedgerError(
                f"cannot create pending fuzz ledger entry: {error}"
            ) from error
    if descriptor is None:
        raise FuzzLedgerError("cannot allocate a unique pending fuzz ledger entry")
    authority.refresh_entries_after_mutation()
    created_identity = _identity(os.fstat(descriptor))
    _validate_regular_file(
        created_identity,
        "pending fuzz ledger entry",
        mode=0o600,
        links={1},
        device=authority.entries.identity.device,
        allow_empty=True,
    )
    try:
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise FuzzLedgerError(
                    "pending fuzz ledger entry write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        created_identity = _identity(os.fstat(descriptor))
        _validate_regular_file(
            created_identity,
            "pending fuzz ledger entry",
            mode=0o400,
            links={1},
            device=authority.entries.identity.device,
            allow_empty=False,
        )
        named_pending = _lstat_at(
            authority.entries.descriptor,
            temporary_name,
            "pending fuzz ledger entry",
        )
        if named_pending != created_identity:
            raise FuzzLedgerError("pending fuzz ledger entry was substituted")
        authority.checkpoint("publication-ready")
        if _lookup_exact_name(
            authority.entries.descriptor, destination_name, "fuzz ledger entries"
        ):
            raise FuzzLedgerError("refusing to overwrite a fuzz ledger entry")
        os.link(
            temporary_name,
            destination_name,
            src_dir_fd=authority.entries.descriptor,
            dst_dir_fd=authority.entries.descriptor,
            follow_symlinks=False,
        )
        authority.refresh_entries_after_mutation()
        linked_pending = _identity(os.fstat(descriptor))
        linked_destination = _lstat_at(
            authority.entries.descriptor,
            destination_name,
            "new fuzz ledger entry",
        )
        if (
            not _same_object(linked_pending, created_identity)
            or linked_pending.links != 2
            or linked_destination != linked_pending
        ):
            raise FuzzLedgerError("fuzz ledger create-new publication was substituted")
        os.fsync(authority.entries.descriptor)
        authority.checkpoint("publication-linked")
        if (
            _lstat_at(
                authority.entries.descriptor,
                temporary_name,
                "pending fuzz ledger entry",
            )
            != linked_pending
            or _lstat_at(
                authority.entries.descriptor,
                destination_name,
                "new fuzz ledger entry",
            )
            != linked_pending
        ):
            raise FuzzLedgerError("linked fuzz ledger entry was substituted")
        os.unlink(temporary_name, dir_fd=authority.entries.descriptor)
        authority.refresh_entries_after_mutation()
        os.fsync(authority.entries.descriptor)
        authority.checkpoint("publication-complete")
        published = _lstat_at(
            authority.entries.descriptor,
            destination_name,
            "new fuzz ledger entry",
        )
        _validate_regular_file(
            published,
            "new fuzz ledger entry",
            mode=0o400,
            links={1},
            device=authority.entries.identity.device,
            allow_empty=False,
        )
        if not _same_object(published, created_identity):
            raise FuzzLedgerError("published fuzz ledger entry changed identity")
    except FileExistsError as error:
        raise FuzzLedgerError("refusing to overwrite a fuzz ledger entry") from error
    finally:
        active_error = sys.exc_info()[0] is not None
        try:
            if created_identity is not None:
                try:
                    pending_exists = _lookup_exact_name(
                        authority.entries.descriptor,
                        temporary_name,
                        "fuzz ledger entries",
                    )
                    if pending_exists:
                        pending = _lstat_at(
                            authority.entries.descriptor,
                            temporary_name,
                            "pending fuzz ledger entry",
                        )
                        if not _same_object(pending, created_identity):
                            if not active_error:
                                raise FuzzLedgerError(
                                    "pending fuzz ledger entry was substituted during cleanup"
                                )
                        else:
                            os.unlink(
                                temporary_name,
                                dir_fd=authority.entries.descriptor,
                            )
                            authority.refresh_entries_after_mutation()
                            os.fsync(authority.entries.descriptor)
                except (FuzzLedgerError, OSError):
                    if not active_error:
                        raise
        finally:
            os.close(descriptor)


def append_bundle(
    ledger: Path,
    authority_path: Path,
    bundle_path: Path,
    *,
    openssl_path: Path | None = None,
    appended_at: int | None = None,
    race_hook: RaceHook | None = None,
) -> dict[str, Any]:
    authority = load_authority(authority_path, openssl_path=openssl_path)
    bundle = _strict_canonical_document(bundle_path, "fuzz worker receipt bundle")
    if (
        set(bundle) != {"schema_version", "receipt", "signature"}
        or bundle.get("schema_version") != BUNDLE_SCHEMA
        or not isinstance(bundle.get("receipt"), dict)
        or not isinstance(bundle.get("signature"), dict)
    ):
        raise FuzzLedgerError("fuzz worker receipt bundle has an unexpected shape")
    with _PinnedLedger.open(
        ledger,
        create=True,
        create_lock=True,
        exclusive=True,
        race_hook=race_hook,
    ) as pinned:
        entries, _snapshots = _read_entries(pinned)
        timestamp = int(time.time()) if appended_at is None else appended_at
        previous = (
            ZERO_DIGEST
            if not entries
            else _sha256_bytes(canonical_json_bytes(entries[-1]))
        )
        entry = {
            "schema_version": ENTRY_SCHEMA,
            "sequence": len(entries) + 1,
            "previous_entry_sha256": previous,
            "appended_at": timestamp,
            "receipt": bundle["receipt"],
            "signature": bundle["signature"],
        }
        validate_entries(
            [*entries, entry],
            authority,
            require_threshold=False,
            now=max(int(time.time()), timestamp),
        )
        receipt_id = bundle["receipt"]["receipt_id"]
        destination_name = f"{len(entries) + 1:020d}-{receipt_id}.json"
        _write_new_immutable(pinned, destination_name, entry)
        published, snapshots = _read_entries(pinned)
        summary = validate_entries(
            published,
            authority,
            require_threshold=False,
            now=max(int(time.time()), timestamp),
        )
        pinned.checkpoint("append-complete")
        _validate_entry_snapshots(pinned, snapshots)
        return summary


def recover_pending(ledger: Path, *, race_hook: RaceHook | None = None) -> int:
    removed = 0
    with _PinnedLedger.open(
        ledger,
        create=False,
        create_lock=True,
        exclusive=True,
        race_hook=race_hook,
    ) as authority:
        names = _entry_names(authority)
        for name in names:
            if not name.startswith(".pending-entry-"):
                continue
            if re.fullmatch(r"\.pending-entry-[0-9a-z]{6,64}", name) is None:
                raise FuzzLedgerError("pending fuzz ledger entry name is invalid")
            pending_identity = _lstat_at(
                authority.entries.descriptor, name, "pending fuzz ledger entry"
            )
            pending_mode = stat.S_IMODE(pending_identity.mode)
            if pending_mode not in {0o400, 0o600}:
                raise FuzzLedgerError("pending fuzz ledger entry has an unsafe mode")
            pending_descriptor, opened = _open_regular_at(
                authority.entries.descriptor,
                name,
                "pending fuzz ledger entry",
                flags=_READ_FILE_FLAGS,
                mode=pending_mode,
                links={1, 2},
                device=authority.entries.identity.device,
                allow_empty=True,
            )
            try:
                linked_entries: list[tuple[str, _FsIdentity]] = []
                for candidate in names:
                    if ENTRY_NAME.fullmatch(candidate) is None:
                        continue
                    candidate_identity = _lstat_at(
                        authority.entries.descriptor,
                        candidate,
                        f"fuzz ledger entry {candidate}",
                    )
                    if _same_object(candidate_identity, opened):
                        linked_entries.append((candidate, candidate_identity))
                expected_links = 1 if not linked_entries else 2
                if opened.links != expected_links or len(linked_entries) > 1:
                    raise FuzzLedgerError(
                        "pending fuzz ledger entry has an unrecognized hard link"
                    )
                authority.checkpoint(f"recovery-before-unlink:{name}")
                if (
                    _lstat_at(
                        authority.entries.descriptor,
                        name,
                        "pending fuzz ledger entry",
                    )
                    != opened
                ):
                    raise FuzzLedgerError("pending fuzz ledger entry was substituted")
                for candidate, candidate_identity in linked_entries:
                    if (
                        _lstat_at(
                            authority.entries.descriptor,
                            candidate,
                            f"fuzz ledger entry {candidate}",
                        )
                        != candidate_identity
                    ):
                        raise FuzzLedgerError(
                            "linked fuzz ledger entry was substituted during recovery"
                        )
                os.unlink(name, dir_fd=authority.entries.descriptor)
                authority.refresh_entries_after_mutation()
                removed += 1
                os.fsync(authority.entries.descriptor)
            finally:
                os.close(pending_descriptor)
        _documents, snapshots = _read_entries(authority)
        authority.checkpoint("recovery-complete")
        _validate_entry_snapshots(authority, snapshots)
    return removed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("append", "verify", "inspect"):
        command = subparsers.add_parser(action)
        command.add_argument("--ledger", type=Path, required=True)
        command.add_argument("--authority", type=Path, required=True)
        command.add_argument("--openssl", type=Path)
        if action == "append":
            command.add_argument("--bundle", type=Path, required=True)
    recover = subparsers.add_parser("recover")
    recover.add_argument("--ledger", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.action == "append":
        summary = append_bundle(
            arguments.ledger,
            arguments.authority,
            arguments.bundle,
            openssl_path=arguments.openssl,
        )
    elif arguments.action == "recover":
        print(f"removed {recover_pending(arguments.ledger)} incomplete entry files")
        return 0
    else:
        summary = verify_ledger(
            arguments.ledger,
            arguments.authority,
            require_threshold=arguments.action == "verify",
            openssl_path=arguments.openssl,
        )
    print(canonical_json_bytes(summary).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FuzzLedgerError, OSError, ValueError) as error:
        print(f"fuzz accumulation failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
