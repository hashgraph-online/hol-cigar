"""Named, shell-free, bounded command execution for refinement gates."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from .canonical import canonical_bytes, identity, sha256_bytes

MAXIMUM_COMMANDS = 512
MAXIMUM_ARGUMENTS = 128
MAXIMUM_ARGUMENT_BYTES = 4096
MAXIMUM_OUTPUT_BYTES = 64 * 1024 * 1024
LAUNCHER = Path(__file__).with_name("exec_bounded.py").resolve(strict=True)


class CommandError(RuntimeError):
    """A command is unknown, unsafe, unbounded, or failed its process contract."""


@dataclass(frozen=True)
class CommandSpec:
    identifier: str
    argv: tuple[str, ...]
    timeout_seconds: int
    maximum_stdout_bytes: int = 8 * 1024 * 1024
    maximum_stderr_bytes: int = 8 * 1024 * 1024
    maximum_memory_bytes: int | None = None

    def validate(self) -> None:
        if (
            not self.identifier
            or len(self.identifier) > 128
            or any(
                not (character.isalnum() or character in "._:-")
                for character in self.identifier
            )
        ):
            raise CommandError("command identifier is invalid")
        if (
            not self.argv
            or len(self.argv) > MAXIMUM_ARGUMENTS
            or any(
                not isinstance(argument, str)
                or not argument
                or "\x00" in argument
                or len(argument.encode("utf-8")) > MAXIMUM_ARGUMENT_BYTES
                for argument in self.argv
            )
        ):
            raise CommandError("command arguments are invalid")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= 86400
        ):
            raise CommandError("command timeout is outside its bound")
        for limit in (self.maximum_stdout_bytes, self.maximum_stderr_bytes):
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 1 <= limit <= MAXIMUM_OUTPUT_BYTES
            ):
                raise CommandError("command output limit is outside its bound")
        if self.maximum_memory_bytes is not None and (
            isinstance(self.maximum_memory_bytes, bool)
            or not isinstance(self.maximum_memory_bytes, int)
            or not 16 * 1024 * 1024
            <= self.maximum_memory_bytes
            <= 1024 * 1024 * 1024 * 1024
        ):
            raise CommandError("command memory limit is outside its bound")


class CommandRegistry:
    def __init__(self, specs: tuple[CommandSpec, ...]) -> None:
        if not specs or len(specs) > MAXIMUM_COMMANDS:
            raise CommandError("command registry size is invalid")
        self._specs: dict[str, CommandSpec] = {}
        for spec in specs:
            spec.validate()
            if spec.identifier in self._specs:
                raise CommandError("command registry contains a duplicate identifier")
            self._specs[spec.identifier] = spec

    def get(self, identifier: str) -> CommandSpec:
        try:
            return self._specs[identifier]
        except KeyError as error:
            raise CommandError(
                "command is not present in the named registry"
            ) from error

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))


def default_registry() -> CommandRegistry:
    return CommandRegistry(
        (
            CommandSpec(
                "refinement-contracts",
                (
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tools/refinement/tests",
                    "-q",
                ),
                300,
            ),
            CommandSpec(
                "retrieval-tests",
                (
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    "cigar-retrieval",
                    "--all-targets",
                ),
                1800,
            ),
            CommandSpec(
                "compiler-tests",
                (
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    "cigar-compiler",
                    "--all-targets",
                ),
                1800,
            ),
            CommandSpec(
                "python-sdk-tests",
                (
                    "uv",
                    "run",
                    "--offline",
                    "--frozen",
                    "--project",
                    "sdk/python",
                    "python",
                    "-m",
                    "pytest",
                    "sdk/python/tests",
                    "-q",
                ),
                900,
            ),
        )
    )


def sanitized_environment(state: Path) -> dict[str, str]:
    if not state.is_absolute() or state.is_symlink():
        raise CommandError("command state path must be an absolute real directory")
    parent = state.parent.resolve(strict=True)
    if state.parent != parent or state != parent / state.name:
        raise CommandError("command state path must not contain aliases or symlinks")
    if state.exists():
        metadata = state.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or state.resolve(strict=True) != state
        ):
            raise CommandError("existing command state directory is unsafe")
    else:
        state.mkdir(mode=0o700)
        metadata = state.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or state.resolve(strict=True) != state
        ):
            raise CommandError("created command state directory is unsafe")
    allowed = {
        "CARGO_HOME",
        "COREPACK_HOME",
        "GOMODCACHE",
        "NPM_CONFIG_STORE_DIR",
        "PATH",
        "RUSTUP_HOME",
        "SYSTEMROOT",
        "UV_CACHE_DIR",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "CI": "true",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(state),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NPM_CONFIG_OFFLINE": "true",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "TMPDIR": str(state),
            "TZ": "UTC",
            "UV_OFFLINE": "1",
        }
    )
    return environment


def _digest_executable(path: Path) -> tuple[str, str]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 0
        or metadata.st_size > 1024 * 1024 * 1024
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(resolved, os.X_OK)
    ):
        raise CommandError("named command executable metadata is unsafe")
    with resolved.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return str(resolved), digest


def _resolved_executable(argv0: str, environment: dict[str, str]) -> tuple[str, str]:
    selected = (
        shutil.which(argv0, path=environment.get("PATH"))
        if not os.path.isabs(argv0)
        else argv0
    )
    if selected is None:
        raise CommandError("named command executable is unavailable")
    return _digest_executable(Path(selected))


def _kill_group(process: subprocess.Popen[bytes]) -> bool:
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


def _drain(
    stream: BinaryIO,
    destination: bytearray,
    *,
    stream_limit: int,
    total_limit: int,
    other: bytearray,
    lock: threading.Lock,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            with lock:
                permitted = min(
                    stream_limit - len(destination),
                    total_limit - len(destination) - len(other),
                )
                retained = max(0, min(len(chunk), permitted))
                destination.extend(chunk[:retained])
                exceeded = retained != len(chunk)
            if exceeded:
                overflow.set()
                _kill_group(process)
                return
    except OSError:
        overflow.set()
        _kill_group(process)
    finally:
        stream.close()


def run_named(
    registry: CommandRegistry,
    identifier: str,
    *,
    cwd: Path,
    state: Path,
) -> dict[str, Any]:
    spec = registry.get(identifier)
    if not cwd.is_absolute() or not cwd.is_dir() or cwd.is_symlink():
        raise CommandError("command cwd must be an absolute real directory")
    if cwd.resolve(strict=True) != cwd:
        raise CommandError("command cwd must not contain aliases or symlinks")
    environment = sanitized_environment(state)
    executable_path, executable_sha256 = _resolved_executable(spec.argv[0], environment)
    launcher_python, launcher_python_sha256 = _resolved_executable(
        sys.executable, environment
    )
    launcher_path, launcher_sha256 = _digest_executable(LAUNCHER)
    argv = (
        launcher_python,
        launcher_path,
        str(spec.timeout_seconds),
        str(spec.maximum_memory_bytes or 0),
        executable_path,
        *spec.argv[1:],
    )
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CommandError("named command could not be started") from error
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    lock = threading.Lock()
    total_limit = spec.maximum_stdout_bytes + spec.maximum_stderr_bytes
    threads = [
        threading.Thread(
            target=_drain,
            args=(process.stdout, stdout),
            kwargs={
                "stream_limit": spec.maximum_stdout_bytes,
                "total_limit": total_limit,
                "other": stderr,
                "lock": lock,
                "overflow": overflow,
                "process": process,
            },
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(process.stderr, stderr),
            kwargs={
                "stream_limit": spec.maximum_stderr_bytes,
                "total_limit": total_limit,
                "other": stdout,
                "lock": lock,
                "overflow": overflow,
                "process": process,
            },
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=spec.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(process)
        process.wait(timeout=5)
    descendant_cleanup_required = _kill_group(process)
    for thread in threads:
        thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        _kill_group(process)
        raise CommandError("named command output readers did not terminate")
    duration = round(time.monotonic() - started, 6)
    environment_record = {
        key: "<STATE>" if key in {"HOME", "TMPDIR"} else environment[key]
        for key in sorted(environment)
    }
    result: dict[str, Any] = {
        "schema_version": "cigar.refinement-command-result.v1",
        "result_id": "",
        "command_id": identifier,
        "command_sha256": sha256_bytes(canonical_bytes(list(spec.argv))),
        "executable_path": executable_path,
        "executable_sha256": executable_sha256,
        "launcher_python_path": launcher_python,
        "launcher_python_sha256": launcher_python_sha256,
        "launcher_path": launcher_path,
        "launcher_sha256": launcher_sha256,
        "environment_keys": sorted(environment),
        "environment_sha256": sha256_bytes(canonical_bytes(environment_record)),
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "output_overflow": overflow.is_set(),
        "descendant_cleanup_required": descendant_cleanup_required,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "duration_seconds": duration,
        "duration_sha256": sha256_bytes(canonical_bytes(duration)),
        "memory_limit_enforced": (
            spec.maximum_memory_bytes is not None and sys.platform.startswith("linux")
        ),
        "status": (
            "passed"
            if process.returncode == 0
            and not timed_out
            and not overflow.is_set()
            and not descendant_cleanup_required
            else "failed"
        ),
    }
    unsigned = dict(result)
    unsigned.pop("result_id")
    result["result_id"] = identity(unsigned)
    return result
