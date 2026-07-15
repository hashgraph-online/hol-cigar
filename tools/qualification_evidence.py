#!/usr/bin/env python3
"""Run live WP18 qualifications with fail-closed external evidence.

The shell drivers remain responsible for the qualification itself.  This broker
owns the evidence boundary: it pins one empty owner-private external directory,
removes its selector from the worker environment, captures bounded output, and
publishes an immutable log plus canonical receipt only through
``EvidenceWorkspace``.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Mapping


RELEASE_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "release"
if str(RELEASE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(RELEASE_SCRIPTS))

from evidence_workspace import (  # noqa: E402
    EvidenceLimits,
    EvidenceWorkspace,
    EvidenceWorkspaceError,
    canonical_json_bytes,
    digest_secure_file,
    safe_relative_path,
)
from release_lib import ReleaseError, run_bounded  # noqa: E402


class QualificationEvidenceError(RuntimeError):
    """The live qualification could not produce trustworthy evidence."""


@dataclass(frozen=True)
class Profile:
    identifier: str
    script: str
    schema_version: str
    receipt_path: str
    log_path: str


PROFILES = {
    profile.identifier: profile
    for profile in (
        Profile(
            "shared-profile",
            "tools/qualify-shared-profile.sh",
            "cigar.shared-qualification.v1",
            "wp18-shared-profile.json",
            "wp18-shared-profile.log",
        ),
        Profile(
            "failover",
            "tools/wp18-failover/qualify.sh",
            "cigar.wp18-failover-qualification.v1",
            "wp18-failover.json",
            "wp18-failover.log",
        ),
        Profile(
            "shared-scale",
            "tools/qualify-shared-scale.sh",
            "cigar.shared-scale-qualification.v1",
            "wp18-shared-scale.json",
            "wp18-shared-scale.log",
        ),
    )
}

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_GIT_BYTES = 64 * 1024 * 1024
_MAX_LOG_BYTES = 64 * 1024 * 1024
_MAX_STATE_BYTES = 1024 * 1024
_MAX_UNTRACKED_FILES = 16_384
_MAX_UNTRACKED_BYTES = 1024 * 1024 * 1024
_WORKER_STATE_FD = 198
_LOG_OVERFLOW_MARKER = b"\n[CIGAR qualification log exceeded the 64 MiB limit]\n"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repository_root(value: Path) -> Path:
    raw = os.fspath(value)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise QualificationEvidenceError(
            "repository root must be an absolute lexically canonical path"
        )
    try:
        resolved = value.resolve(strict=True)
        metadata = os.stat(value, follow_symlinks=False)
    except OSError as error:
        raise QualificationEvidenceError(
            f"cannot resolve repository root: {error}"
        ) from error
    if resolved != value or not stat.S_ISDIR(metadata.st_mode):
        raise QualificationEvidenceError(
            "repository root must name a real canonical directory"
        )
    return resolved


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TZ": "UTC",
    }


def _git(root: Path, *arguments: str, maximum: int = _MAX_GIT_BYTES) -> bytes:
    command = [
        "/usr/bin/git",
        "--no-replace-objects",
        "-c",
        "core.quotePath=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.allow=never",
        "--literal-pathspecs",
        *arguments,
    ]
    try:
        completed = run_bounded(
            command,
            cwd=root,
            env=_git_environment(),
            timeout=120,
            max_stdout=maximum,
            max_stderr=1024 * 1024,
        )
    except (OSError, ReleaseError, subprocess.SubprocessError) as error:
        raise QualificationEvidenceError(
            f"cannot inspect qualification source: {error}"
        ) from error
    if completed.returncode != 0:
        raise QualificationEvidenceError(
            "Git source inspection failed; "
            f"exit={completed.returncode} "
            f"stderr_sha256={hashlib.sha256(completed.stderr).hexdigest()}"
        )
    return completed.stdout


def _one_object(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise QualificationEvidenceError(f"Git {label} is not ASCII") from error
    if _GIT_OBJECT.fullmatch(value) is None:
        raise QualificationEvidenceError(f"Git {label} is not a full object ID")
    return value


def _source_snapshot_once(root: Path) -> dict[str, object]:
    revision = _one_object(
        _git(root, "rev-parse", "--verify", "HEAD^{commit}"), "revision"
    )
    tree = _one_object(_git(root, "rev-parse", "--verify", "HEAD^{tree}"), "tree")
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    difference = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "--full-index",
        "HEAD",
        "--",
    )
    untracked_payload = _git(root, "ls-files", "-z", "--others", "--exclude-standard")
    raw_paths = [path for path in untracked_payload.split(b"\0") if path]
    if len(raw_paths) > _MAX_UNTRACKED_FILES:
        raise QualificationEvidenceError("untracked source inventory is too large")
    records: list[dict[str, object]] = []
    total = 0
    portable: set[str] = set()
    for raw_path in raw_paths:
        try:
            relative = raw_path.decode("utf-8", errors="strict")
            parts = safe_relative_path(relative)
        except (UnicodeError, EvidenceWorkspaceError) as error:
            raise QualificationEvidenceError(
                f"Git returned an unsafe untracked source path: {error}"
            ) from error
        alias = relative.casefold()
        if alias in portable:
            raise QualificationEvidenceError(
                "untracked source inventory has a case/Unicode collision"
            )
        portable.add(alias)
        try:
            binding = digest_secure_file(root.joinpath(*parts))
        except EvidenceWorkspaceError as error:
            raise QualificationEvidenceError(
                f"cannot bind untracked source {relative}: {error}"
            ) from error
        total += binding.bytes
        if total > _MAX_UNTRACKED_BYTES:
            raise QualificationEvidenceError("untracked source bytes exceed 1 GiB")
        records.append(
            {"path": relative, "sha256": binding.sha256, "bytes": binding.bytes}
        )
    records.sort(key=lambda record: str(record["path"]).encode("utf-8"))
    inventory_payload = canonical_json_bytes(records)
    material = {
        "revision": revision,
        "tree": tree,
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "difference_sha256": hashlib.sha256(difference).hexdigest(),
        "untracked_count": len(records),
        "untracked_bytes": total,
        "untracked_sha256": hashlib.sha256(inventory_payload).hexdigest(),
    }
    fingerprint = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    return {
        "algorithm": "cigar.git-worktree-snapshot.v1",
        **material,
        "fingerprint": fingerprint,
    }


def capture_source_snapshot(root: Path) -> dict[str, object]:
    """Capture an exact stable Git worktree fingerprint twice."""

    first = _source_snapshot_once(root)
    second = _source_snapshot_once(root)
    if first != second:
        raise QualificationEvidenceError("source changed while it was being captured")
    return first


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in values:
            if key in document:
                raise QualificationEvidenceError(
                    f"{label} contains a duplicate JSON key"
                )
            document[key] = value
        return document

    try:
        decoded = payload.decode("utf-8", errors="strict")
        document = json.loads(
            decoded,
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite number {value}")
            ),
        )
    except (
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        MemoryError,
        OverflowError,
        RecursionError,
    ) as error:
        raise QualificationEvidenceError(
            f"{label} is not strict JSON: {error}"
        ) from error
    if not isinstance(document, dict):
        raise QualificationEvidenceError(f"{label} must be a JSON object")
    try:
        canonical_json_bytes(document)
    except EvidenceWorkspaceError as error:
        raise QualificationEvidenceError(
            f"{label} exceeds the bounded canonical JSON contract: {error}"
        ) from error
    return document


def _bool(document: Mapping[str, object], key: str) -> bool:
    return document.get(key) is True


def _worker_passes(profile: Profile, document: Mapping[str, object]) -> bool:
    if document.get("schema_version") != profile.schema_version:
        return False
    if document.get("packet") != "WP18" or document.get("result") != "pass":
        return False
    if profile.identifier == "shared-profile":
        return all(
            _bool(document, key)
            for key in (
                "postgres_dump_restore",
                "postgres_basebackup_manifest_verified",
                "postgres_private_ca_tls",
                "s3_compatible_live",
                "s3_fresh_namespace_restore",
                "s3_runtime_immutable_delete_denied",
                "deployment_assets",
            )
        )
    if profile.identifier == "failover":
        return (
            _bool(document, "passed")
            and _bool(document, "cleanup_complete")
            and document.get("production_phases_completed") == 3
            and _bool(document, "production_postgres_store")
            and _bool(document, "postgres_private_ca_tls")
            and _bool(document, "replica_lag_ack_blocked")
            and _bool(document, "postgres_physical_backup_verified")
            and _bool(document, "physical_restore_ready")
            and _bool(document, "physical_restore_root_match")
            and document.get("acknowledged_write_loss") == 0
            and document.get("duplicate_revisions") == 0
            and document.get("duplicate_effects") == 0
            and document.get("duplicate_claims") == 0
        )
    if profile.identifier == "shared-scale":
        dataset = document.get("dataset")
        failures = document.get("failures")
        curve = document.get("curve")
        return (
            document.get("migration_sequence") == 4
            and document.get("physical_row_count") == 10_000_000
            and _bool(document, "production_projection")
            and _bool(document, "public_commit_atomic_projection")
            and _bool(document, "public_rebuild_verified")
            and _bool(document, "forced_rls_isolation_verified")
            and isinstance(dataset, dict)
            and dataset.get("total_rows") == 10_000_000
            and isinstance(curve, list)
            and [point.get("target_rows") for point in curve if isinstance(point, dict)]
            == [1_000, 10_000, 100_000, 1_000_000, 10_000_000]
            and all(
                isinstance(point, dict)
                and point.get("exact_count") == point.get("target_rows")
                for point in curve
            )
            and isinstance(failures, dict)
            and failures.get("unexpected_batch_failures") == 0
            and failures.get("unexpected_query_failures") == 0
        )
    return False


def _failure_worker(profile: Profile) -> dict[str, object]:
    return {
        "schema_version": profile.schema_version,
        "packet": "WP18",
        "result": "fail",
    }


def _read_state(handle: BinaryIO, result: dict[str, object]) -> None:
    payload = bytearray()
    overflow = False
    try:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            remaining = _MAX_STATE_BYTES - len(payload)
            if remaining > 0:
                payload.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow = True
    except OSError as error:
        result["error"] = str(error)
    finally:
        handle.close()
    result["payload"] = bytes(payload)
    result["overflow"] = overflow


def _stream_worker(
    *,
    root: Path,
    profile: Profile,
    log_handle: BinaryIO,
    output: BinaryIO,
) -> tuple[int, bytes, bool, str, int]:
    read_fd, write_fd = os.pipe()
    environment = dict(os.environ)
    environment.pop("CIGAR_EVIDENCE_DIR", None)
    environment.pop("CIGAR_QUALIFICATION_INTERNAL_PROFILE", None)
    environment.pop("CIGAR_QUALIFICATION_STATE_FD", None)
    environment["CIGAR_QUALIFICATION_INTERNAL_PROFILE"] = profile.identifier
    environment["CIGAR_QUALIFICATION_STATE_FD"] = str(_WORKER_STATE_FD)
    script = root.joinpath(*safe_relative_path(profile.script))
    state_result: dict[str, object] = {}
    state_handle = os.fdopen(read_fd, "rb", closefd=True)
    duplicated_state_fd = write_fd != _WORKER_STATE_FD
    if duplicated_state_fd:
        try:
            os.fstat(_WORKER_STATE_FD)
        except OSError as error:
            if error.errno != errno.EBADF:
                os.close(write_fd)
                state_handle.close()
                raise QualificationEvidenceError(
                    f"cannot inspect reserved qualification descriptor: {error}"
                ) from error
        else:
            os.close(write_fd)
            state_handle.close()
            raise QualificationEvidenceError(
                "reserved qualification state descriptor is already open"
            )
        try:
            os.dup2(write_fd, _WORKER_STATE_FD, inheritable=True)
        except OSError:
            os.close(write_fd)
            state_handle.close()
            raise
    else:
        os.set_inheritable(_WORKER_STATE_FD, True)
    state_thread: threading.Thread | None = None
    try:
        process = subprocess.Popen(
            ["/bin/bash", str(script)],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            pass_fds=(_WORKER_STATE_FD,),
            start_new_session=True,
        )
    except BaseException:
        os.close(write_fd)
        if duplicated_state_fd:
            os.close(_WORKER_STATE_FD)
        state_handle.close()
        raise
    os.close(write_fd)
    if duplicated_state_fd:
        os.close(_WORKER_STATE_FD)
    state_thread = threading.Thread(
        target=_read_state, args=(state_handle, state_result), daemon=True
    )
    state_thread.start()
    log_bytes = 0
    log_digest = hashlib.sha256()
    log_overflow = False
    try:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                break
            try:
                output.write(chunk)
                output.flush()
            except (BrokenPipeError, OSError):
                pass
            remaining = _MAX_LOG_BYTES - len(_LOG_OVERFLOW_MARKER) - log_bytes
            if remaining > 0:
                accepted = chunk[:remaining]
                log_handle.write(accepted)
                log_digest.update(accepted)
                log_bytes += len(accepted)
            if len(chunk) > max(remaining, 0):
                log_overflow = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        return_code = process.wait()
    except KeyboardInterrupt:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        return_code = process.wait()
        if return_code == 0:
            return_code = 130
    finally:
        if process.stdout is not None:
            process.stdout.close()
    if log_overflow:
        log_handle.write(_LOG_OVERFLOW_MARKER)
        log_digest.update(_LOG_OVERFLOW_MARKER)
        log_bytes += len(_LOG_OVERFLOW_MARKER)
    log_handle.flush()
    os.fsync(log_handle.fileno())
    state_thread.join(timeout=30)
    if state_thread.is_alive():
        raise QualificationEvidenceError("qualification state pipe did not close")
    state_payload = state_result.get("payload", b"")
    if not isinstance(state_payload, bytes):
        state_payload = b""
    state_invalid = bool(state_result.get("overflow") or state_result.get("error"))
    return (
        return_code,
        state_payload,
        log_overflow or state_invalid,
        log_digest.hexdigest(),
        log_bytes,
    )


def run_qualification(
    *,
    root: Path,
    evidence_root: Path,
    profile: Profile,
    output: BinaryIO | None = None,
) -> int:
    root = _repository_root(root)
    expected_script = root.joinpath(*safe_relative_path(profile.script))
    try:
        script_metadata = os.stat(expected_script, follow_symlinks=False)
    except OSError as error:
        raise QualificationEvidenceError(
            f"qualification worker is unavailable: {error}"
        ) from error
    if not stat.S_ISREG(script_metadata.st_mode) or expected_script.is_symlink():
        raise QualificationEvidenceError("qualification worker must be a regular file")
    limits = EvidenceLimits(
        max_files=2,
        max_directories=1,
        max_file_bytes=_MAX_LOG_BYTES,
        max_total_bytes=_MAX_LOG_BYTES + 2 * 1024 * 1024,
        max_json_bytes=2 * 1024 * 1024,
        max_path_depth=1,
    )
    selected_output = output if output is not None else sys.stdout.buffer
    started_at = _utc_now()
    before = capture_source_snapshot(root)
    with EvidenceWorkspace.create(
        evidence_root, repository_root=root, limits=limits
    ) as workspace:
        workspace.read_files(set())
        with tempfile.TemporaryDirectory(
            prefix="cigar-wp18-qualification-", dir="/private/tmp"
        ) as staging_text:
            staging = Path(staging_text)
            staging_metadata = os.stat(staging, follow_symlinks=False)
            if (
                not stat.S_ISDIR(staging_metadata.st_mode)
                or staging_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(staging_metadata.st_mode) != 0o700
            ):
                raise QualificationEvidenceError(
                    "private qualification staging directory is unsafe"
                )
            log_source = staging / "qualification.log"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
            log_fd = os.open(log_source, flags, 0o600)
            with os.fdopen(log_fd, "wb", closefd=True) as log_handle:
                (
                    return_code,
                    state_payload,
                    stream_invalid,
                    expected_log_sha256,
                    expected_log_bytes,
                ) = _stream_worker(
                    root=root,
                    profile=profile,
                    log_handle=log_handle,
                    output=selected_output,
                )
            after = capture_source_snapshot(root)
            source_stable = before == after
            worker_valid = False
            try:
                worker = _strict_json(state_payload, "qualification worker state")
                worker_valid = _worker_passes(profile, worker)
            except QualificationEvidenceError:
                worker = _failure_worker(profile)
            passed = (
                return_code == 0
                and not stream_invalid
                and source_stable
                and worker_valid
            )
            effective_exit = return_code if return_code != 0 else (0 if passed else 1)
            log_attachment = workspace.attach_file(
                log_source,
                profile.log_path,
                read_only=True,
                expected_sha256=expected_log_sha256,
                expected_bytes=expected_log_bytes,
            )
            receipt: dict[str, object] = dict(worker)
            receipt.update(
                {
                    "schema_version": profile.schema_version,
                    "packet": "WP18",
                    "profile": profile.identifier,
                    "started_at": started_at,
                    "finished_at": _utc_now(),
                    "result": "pass" if passed else "fail",
                    "passed": passed,
                    "exit_code": effective_exit,
                    "source": before,
                    "source_after": after,
                    "source_stable": source_stable,
                    "worker_report_valid": worker_valid,
                    "bounded_log_complete": not stream_invalid,
                    "evidence_selector_forwarded": False,
                    "log": log_attachment.as_dict(),
                }
            )
            receipt_attachment = workspace.write_json(
                profile.receipt_path, receipt, read_only=True
            )
            payloads = workspace.read_files({profile.log_path, profile.receipt_path})
            staged_log = digest_secure_file(log_source, max_bytes=_MAX_LOG_BYTES)
            if (
                staged_log.bytes != len(payloads[profile.log_path])
                or staged_log.sha256
                != hashlib.sha256(payloads[profile.log_path]).hexdigest()
            ):
                raise QualificationEvidenceError(
                    "published qualification log changed during verification"
                )
            if payloads[profile.receipt_path] != canonical_json_bytes(receipt):
                raise QualificationEvidenceError(
                    "published qualification receipt is not canonical"
                )
            if (
                receipt_attachment.path != profile.receipt_path
                or log_attachment.sha256
                != hashlib.sha256(payloads[profile.log_path]).hexdigest()
            ):
                raise QualificationEvidenceError(
                    "published qualification attachment binding is invalid"
                )
    selected_output.write(
        (
            f"External qualification evidence: {evidence_root}/{profile.receipt_path}\n"
        ).encode("utf-8")
    )
    selected_output.flush()
    return effective_exit


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run one protected live qualification")
    run.add_argument("--profile", choices=sorted(PROFILES), required=True)
    run.add_argument("--repository", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command != "run":
        raise QualificationEvidenceError("unsupported qualification evidence command")
    selector = os.environ.get("CIGAR_EVIDENCE_DIR")
    if selector is None or selector == "":
        raise QualificationEvidenceError(
            "live qualification requires an absolute external CIGAR_EVIDENCE_DIR"
        )
    return run_qualification(
        root=arguments.repository,
        evidence_root=Path(selector),
        profile=PROFILES[arguments.profile],
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceWorkspaceError, QualificationEvidenceError, OSError) as error:
        print(f"qualification evidence failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
