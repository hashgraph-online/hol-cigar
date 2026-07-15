#!/usr/bin/env python3
"""Publish and verify content-free receipts for native macOS CI workflow lanes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "cigar.macos-ci-workflow-receipt.v1"
MAX_ATTACHMENT_BYTES = 64 * 1024 * 1024
MAX_GIT_STATUS_BYTES = 16 * 1024 * 1024
GIT_OBJECT_ID = re.compile(r"[0-9a-f]{40,64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SAFE_JOB = re.compile(r"[A-Za-z0-9_-]{1,128}")
CREATED_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
LANES = frozenset(
    {
        "effect-rc",
        "mutation",
        "performance-diagnostic",
        "production-sanitizers",
        "rc-macos-package-chain",
        "rc-source-security-reproducibility",
        "scale-diagnostic",
    }
)


class ReceiptError(RuntimeError):
    """A workflow receipt or one of its bindings is unsafe or inconsistent."""


def fail(message: str) -> None:
    raise ReceiptError(message)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_json(payload: bytes, label: str) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                fail(f"{label} contains a duplicate key")
            document[key] = value
        return document

    try:
        value = json.loads(
            payload,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda token: fail(
                f"{label} contains a non-finite number: {token}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} is not strict JSON") from error
    if canonical_bytes(value) != payload:
        fail(f"{label} is not canonical JSON")
    return value


def _canonical_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is unavailable") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail(f"{label} must be canonical, real, owner-owned, and mode 0700")
    try:
        path.relative_to(ROOT)
    except ValueError:
        pass
    else:
        fail(f"{label} must be outside the repository")
    return path


def _read_stable_file(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        before = path.lstat()
    except OSError as error:
        raise ReceiptError(f"{label} is unavailable") from error
    if (
        resolved != path
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or not 1 <= before.st_size <= MAX_ATTACHMENT_BYTES
    ):
        fail(f"{label} must be a protected, single-link regular file")
    try:
        path.relative_to(ROOT)
    except ValueError:
        pass
    else:
        fail(f"{label} must be outside the repository")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
        ):
            fail(f"{label} changed before it was read")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{label} was truncated while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{label} grew while it was read")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            fail(f"{label} changed while it was read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _git(arguments: Sequence[str], maximum: int) -> bytes:
    environment = {
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReceiptError("Git source identity could not be captured") from error
    if result.returncode != 0 or result.stderr or len(result.stdout) > maximum:
        fail("Git source identity command failed or exceeded its bound")
    return result.stdout


def source_identity(event_sha: str) -> dict[str, object]:
    if GIT_OBJECT_ID.fullmatch(event_sha) is None:
        fail("event SHA is malformed")
    revision = _git(("rev-parse", "--verify", "HEAD"), 128).strip().decode("ascii")
    tree = _git(("rev-parse", "--verify", "HEAD^{tree}"), 128).strip().decode("ascii")
    status = _git(
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        MAX_GIT_STATUS_BYTES,
    )
    if (
        revision != event_sha
        or GIT_OBJECT_ID.fullmatch(revision) is None
        or GIT_OBJECT_ID.fullmatch(tree) is None
        or status
    ):
        fail("workflow source is not the exact clean event revision")
    return {
        "revision": revision,
        "tree": tree,
        "committed": True,
        "clean": True,
        "status": {"bytes": 0, "sha256": sha256_bytes(status)},
    }


def _builder(
    *, repository: str, run_id: str, run_attempt: str, job: str
) -> dict[str, object]:
    if (
        REPOSITORY_NAME.fullmatch(repository) is None
        or not run_id.isdecimal()
        or int(run_id) <= 0
        or not run_attempt.isdecimal()
        or int(run_attempt) <= 0
        or SAFE_JOB.fullmatch(job) is None
    ):
        fail("GitHub Actions builder identity is malformed")
    identity = (
        f"github-actions://{repository}/actions/runs/{run_id}/"
        f"attempts/{run_attempt}/jobs/{job}"
    )
    return {
        "kind": "github-actions",
        "repository": repository,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
        "job": job,
        "identity": identity,
    }


def _platform() -> dict[str, str]:
    machine = platform.machine().casefold()
    if sys.platform != "darwin" or machine not in {"arm64", "aarch64"}:
        fail("workflow receipts support only native Apple-silicon macOS")
    return {
        "system": "Darwin",
        "machine": "arm64",
        "target": "aarch64-apple-darwin",
    }


def _parse_attachments(values: Sequence[str]) -> list[tuple[str, Path]]:
    parsed: list[tuple[str, Path]] = []
    identifiers: set[str] = set()
    for value in values:
        identifier, separator, raw_path = value.partition("=")
        if (
            not separator
            or SAFE_ID.fullmatch(identifier) is None
            or identifier in identifiers
            or not raw_path
        ):
            fail("attachment must be a unique safe-id=/absolute/path binding")
        identifiers.add(identifier)
        parsed.append((identifier, Path(raw_path)))
    if not parsed:
        fail("at least one content-free attachment is required")
    return sorted(parsed, key=lambda item: item[0])


def attachment_records(values: Sequence[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    identities: set[tuple[int, int]] = set()
    for identifier, path in _parse_attachments(values):
        payload, metadata = _read_stable_file(path, f"attachment {identifier}")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            fail("attachments alias the same file")
        identities.add(identity)
        records.append(
            {
                "id": identifier,
                "bytes": len(payload),
                "sha256": sha256_bytes(payload),
            }
        )
    return records


def _receipt_body(arguments: argparse.Namespace) -> dict[str, object]:
    if arguments.lane not in LANES:
        fail("workflow lane is not authorized")
    command_payload = arguments.command.encode("utf-8")
    if not 1 <= len(command_payload) <= 16 * 1024 or "\0" in arguments.command:
        fail("workflow command binding is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "lane": arguments.lane,
        "status": "passed",
        "release_eligible": False,
        "platform": _platform(),
        "source": source_identity(arguments.event_sha),
        "builder": _builder(
            repository=arguments.repository,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            job=arguments.job,
        ),
        "command_sha256": sha256_bytes(command_payload),
        "attachments": attachment_records(arguments.attachment),
        "claims": {
            "fuzz_executed": False,
            "soak_executed": False,
            "distribution_signed": False,
            "notarized": False,
            "published": False,
            "release_qualified": False,
        },
        "created_utc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }


def _with_receipt_id(body: dict[str, object]) -> dict[str, object]:
    return {**body, "receipt_id": sha256_bytes(canonical_bytes(body))}


def _valid_created_utc(value: object) -> bool:
    if not isinstance(value, str) or CREATED_UTC.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _write_new(output: Path, payload: bytes) -> None:
    parent = _canonical_directory(output.parent, "receipt output directory")
    if output.name in {"", ".", ".."} or output.parent / output.name != output:
        fail("receipt output must be a direct child of its evidence directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output, flags, 0o600)
    except OSError as error:
        raise ReceiptError("receipt output is not create-new") from error
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                fail("receipt output write made no progress")
            written += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_document(document: object) -> dict[str, Any]:
    expected = {
        "schema_version",
        "lane",
        "status",
        "release_eligible",
        "platform",
        "source",
        "builder",
        "command_sha256",
        "attachments",
        "claims",
        "created_utc",
        "receipt_id",
    }
    if not isinstance(document, dict) or set(document) != expected:
        fail("workflow receipt has an unexpected shape")
    body = {key: value for key, value in document.items() if key != "receipt_id"}
    created_utc = document.get("created_utc")
    if (
        document.get("schema_version") != SCHEMA_VERSION
        or document.get("lane") not in LANES
        or document.get("status") != "passed"
        or document.get("release_eligible") is not False
        or document.get("platform")
        != {"system": "Darwin", "machine": "arm64", "target": "aarch64-apple-darwin"}
        or SHA256.fullmatch(str(document.get("command_sha256"))) is None
        or document.get("claims")
        != {
            "fuzz_executed": False,
            "soak_executed": False,
            "distribution_signed": False,
            "notarized": False,
            "published": False,
            "release_qualified": False,
        }
        or not _valid_created_utc(created_utc)
        or document.get("receipt_id") != sha256_bytes(canonical_bytes(body))
    ):
        fail("workflow receipt identity or claims are invalid")
    source = document.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree", "committed", "clean", "status"}
        or GIT_OBJECT_ID.fullmatch(str(source.get("revision"))) is None
        or GIT_OBJECT_ID.fullmatch(str(source.get("tree"))) is None
        or source.get("committed") is not True
        or source.get("clean") is not True
        or source.get("status") != {"bytes": 0, "sha256": sha256_bytes(b"")}
    ):
        fail("workflow receipt source binding is invalid")
    builder = document.get("builder")
    if not isinstance(builder, dict) or set(builder) != {
        "kind",
        "repository",
        "run_id",
        "run_attempt",
        "job",
        "identity",
    }:
        fail("workflow receipt builder binding is invalid")
    expected_builder = _builder(
        repository=str(builder.get("repository")),
        run_id=str(builder.get("run_id")),
        run_attempt=str(builder.get("run_attempt")),
        job=str(builder.get("job")),
    )
    if builder != expected_builder:
        fail("workflow receipt builder identity is inconsistent")
    attachments = document.get("attachments")
    if not isinstance(attachments, list) or not attachments:
        fail("workflow receipt attachment inventory is empty")
    ids: list[str] = []
    for attachment in attachments:
        if (
            not isinstance(attachment, dict)
            or set(attachment) != {"id", "bytes", "sha256"}
            or SAFE_ID.fullmatch(str(attachment.get("id"))) is None
            or isinstance(attachment.get("bytes"), bool)
            or not isinstance(attachment.get("bytes"), int)
            or not 1 <= attachment["bytes"] <= MAX_ATTACHMENT_BYTES
            or SHA256.fullmatch(str(attachment.get("sha256"))) is None
        ):
            fail("workflow receipt attachment binding is invalid")
        ids.append(str(attachment["id"]))
    if ids != sorted(set(ids)):
        fail("workflow receipt attachment inventory is duplicated or unordered")
    return document


def publish(arguments: argparse.Namespace) -> None:
    output = arguments.output
    _canonical_directory(output.parent, "receipt output directory")
    document = _with_receipt_id(_receipt_body(arguments))
    validate_document(document)
    _write_new(output, canonical_bytes(document))


def verify(arguments: argparse.Namespace) -> None:
    payload, _ = _read_stable_file(arguments.receipt, "workflow receipt")
    document = validate_document(_strict_json(payload, "workflow receipt"))
    if document["platform"] != _platform():
        fail("workflow receipt platform is stale for the current builder")
    if document["source"]["revision"] != arguments.event_sha:
        fail("workflow receipt event SHA binding is stale")
    if document["source"] != source_identity(arguments.event_sha):
        fail("workflow receipt is stale for the current source")
    if document["builder"] != _builder(
        repository=arguments.repository,
        run_id=arguments.run_id,
        run_attempt=arguments.run_attempt,
        job=arguments.job,
    ):
        fail("workflow receipt builder binding is stale")
    if document["command_sha256"] != sha256_bytes(arguments.command.encode("utf-8")):
        fail("workflow receipt command binding is stale")
    if document["attachments"] != attachment_records(arguments.attachment):
        fail("workflow receipt attachment binding is stale")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--output", type=Path, required=True)
    publish_parser.add_argument("--lane", choices=sorted(LANES), required=True)
    publish_parser.add_argument("--event-sha", required=True)
    publish_parser.add_argument("--repository", required=True)
    publish_parser.add_argument("--run-id", required=True)
    publish_parser.add_argument("--run-attempt", required=True)
    publish_parser.add_argument("--job", required=True)
    publish_parser.add_argument("--command", required=True)
    publish_parser.add_argument("--attachment", action="append", default=[])
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser.add_argument("--event-sha", required=True)
    verify_parser.add_argument("--repository", required=True)
    verify_parser.add_argument("--run-id", required=True)
    verify_parser.add_argument("--run-attempt", required=True)
    verify_parser.add_argument("--job", required=True)
    verify_parser.add_argument("--command", required=True)
    verify_parser.add_argument("--attachment", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.action == "publish":
        publish(arguments)
    else:
        verify(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReceiptError as error:
        raise SystemExit(f"macOS CI workflow receipt failed: {error}") from error
