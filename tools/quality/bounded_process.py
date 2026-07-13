#!/usr/bin/env python3
"""Private, bounded subprocess capture for qualification tooling."""

from __future__ import annotations

import hashlib
import os
import select
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Any


class BoundedProcessError(RuntimeError):
    """The bounded runner could not safely execute or preserve diagnostics."""


def require_supported_process_model(*, os_name: str | None = None) -> None:
    host = os.name if os_name is None else os_name
    if host != "posix":
        raise BoundedProcessError(
            f"bounded descendant-safe execution is not implemented for {host}; failing closed"
        )


def _terminate_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        if process.poll() is None:
            process.kill()
            return True
        return False


def run_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
    timeout_seconds: float,
    maximum_output_bytes: int,
    tail_bytes: int = 64 * 1024,
    failure_markers: tuple[str, ...] = (),
) -> dict[str, Any]:
    require_supported_process_model()
    if not command:
        raise BoundedProcessError("bounded command must not be empty")
    if timeout_seconds <= 0 or maximum_output_bytes < 1 or tail_bytes < 1:
        raise BoundedProcessError("bounded process limits must be positive")
    if log_path.exists() or log_path.is_symlink():
        raise BoundedProcessError(f"refusing to overwrite subprocess log: {log_path}")
    if log_path.parent.is_symlink() or not log_path.parent.is_dir():
        raise BoundedProcessError(f"unsafe subprocess log parent: {log_path.parent}")
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    tail = bytearray()
    total = 0
    timed_out = False
    output_overflow = False
    group_cleanup_required = False
    marker_bytes = {marker: marker.encode() for marker in failure_markers}
    marker_seen = {marker: False for marker in failure_markers}
    overlap = b""
    maximum_marker = max((len(value) for value in marker_bytes.values()), default=1)
    body_digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "wb") as log:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            assert process.stdout is not None
            output_descriptor = process.stdout.fileno()
            os.set_blocking(output_descriptor, False)
            deadline = started + timeout_seconds
            pipe_open = True
            while pipe_open:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    timed_out = True
                    group_cleanup_required |= _terminate_group(process)
                    break
                ready, _, _ = select.select(
                    [output_descriptor], [], [], max(0.0, min(0.1, remaining_time))
                )
                if not ready:
                    if process.poll() is not None:
                        # A final nonblocking read below observes EOF or buffered bytes.
                        ready = [output_descriptor]
                    else:
                        continue
                try:
                    chunk = os.read(output_descriptor, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    pipe_open = False
                    break
                scan = overlap + chunk
                for marker, encoded in marker_bytes.items():
                    if encoded in scan:
                        marker_seen[marker] = True
                overlap = scan[-maximum_marker:]
                available = maximum_output_bytes - total
                if len(chunk) > available:
                    if available > 0:
                        accepted = chunk[:available]
                        log.write(accepted)
                        body_digest.update(accepted)
                        tail.extend(accepted)
                        del tail[:-tail_bytes]
                        total += len(accepted)
                    output_overflow = True
                    group_cleanup_required |= _terminate_group(process)
                    break
                log.write(chunk)
                body_digest.update(chunk)
                tail.extend(chunk)
                del tail[:-tail_bytes]
                total += len(chunk)
            if timed_out or output_overflow:
                group_cleanup_required |= _terminate_group(process)
            else:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    group_cleanup_required |= _terminate_group(process)
                # Once the direct child is reaped, any surviving member of its original
                # process group is an untrusted descendant and must be killed and reported.
                group_cleanup_required |= _terminate_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                group_cleanup_required |= _terminate_group(process)
                raise BoundedProcessError(
                    "subprocess group did not terminate"
                ) from error
            process.stdout.close()
            log.flush()
            os.fsync(log.fileno())
    except BaseException:
        if process is not None:
            _terminate_group(process)
        raise
    parent_descriptor = os.open(log_path.parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    metadata = log_path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o600:
        raise BoundedProcessError(
            f"subprocess log is not a private regular file: {log_path}"
        )
    return {
        "exit_code": process.returncode if process is not None else -1,
        "duration_seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out,
        "output_overflow": output_overflow,
        "descendant_cleanup_required": group_cleanup_required,
        "captured_output_bytes": total,
        "maximum_output_bytes": maximum_output_bytes,
        "log_sha256": body_digest.hexdigest(),
        "log_size": metadata.st_size,
        "tail": bytes(tail).decode("utf-8", "replace"),
        "failure_markers": marker_seen,
    }
