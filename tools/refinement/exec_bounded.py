#!/usr/bin/env python3
"""Set POSIX child limits and replace this launcher with one exact executable."""

from __future__ import annotations

import os
import resource
import stat
import sys
from pathlib import Path

MAXIMUM_TIMEOUT_SECONDS = 86_400
MAXIMUM_MEMORY_BYTES = 1024 * 1024 * 1024 * 1024
MAXIMUM_ARGUMENTS = 128


def _bounded_limit(resource_name: int, requested: int) -> tuple[int, int]:
    _, inherited_hard = resource.getrlimit(resource_name)
    if inherited_hard == resource.RLIM_INFINITY:
        return requested, requested
    selected = min(requested, inherited_hard)
    return selected, selected


def _fail() -> int:
    os.write(2, b"bounded launcher rejected its execution contract\n")
    return 126


def main() -> int:
    if len(sys.argv) < 4 or len(sys.argv) > MAXIMUM_ARGUMENTS + 3:
        return _fail()
    try:
        timeout = int(sys.argv[1])
        memory = int(sys.argv[2])
    except ValueError:
        return _fail()
    executable = Path(sys.argv[3])
    arguments = sys.argv[4:]
    if (
        not 1 <= timeout <= MAXIMUM_TIMEOUT_SECONDS
        or not 0 <= memory <= MAXIMUM_MEMORY_BYTES
        or not executable.is_absolute()
        or executable.is_symlink()
        or executable.resolve(strict=True) != executable
    ):
        return _fail()
    metadata = executable.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(executable, os.X_OK)
        or any("\x00" in argument for argument in arguments)
    ):
        return _fail()
    cpu_soft, _ = _bounded_limit(resource.RLIMIT_CPU, timeout)
    _, inherited_cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
    requested_cpu_hard = timeout + 1
    cpu_hard = (
        requested_cpu_hard
        if inherited_cpu_hard == resource.RLIM_INFINITY
        else min(requested_cpu_hard, inherited_cpu_hard)
    )
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
    resource.setrlimit(
        resource.RLIMIT_NOFILE, _bounded_limit(resource.RLIMIT_NOFILE, 256)
    )
    if memory and sys.platform.startswith("linux"):
        resource.setrlimit(
            resource.RLIMIT_AS, _bounded_limit(resource.RLIMIT_AS, memory)
        )
    os.execve(executable, [str(executable), *arguments], os.environ)
    return _fail()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        raise SystemExit(_fail()) from None
