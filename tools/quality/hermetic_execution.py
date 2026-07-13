#!/usr/bin/env python3
"""Hermetic child environments and fail-closed Darwin no-network wrapping."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
from pathlib import Path
from typing import Mapping


SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
NO_NETWORK_PROFILE = (
    "(version 1)\n"
    "(allow default)\n"
    "(deny network*)\n"
    '(deny file-read* (regex #".*/credentials(\\.toml)?$"))\n'
)
AMBIENT_ALLOWLIST = {
    "PATH",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SDKROOT",
    "DEVELOPER_DIR",
    "MACOSX_DEPLOYMENT_TARGET",
}
OVERRIDE_ALLOWLIST = AMBIENT_ALLOWLIST | {
    "CARGO",
    "HOME",
    "TMPDIR",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "MIRIFLAGS",
    "RUSTUP_TOOLCHAIN",
    "RUSTFLAGS",
}
LOCKED_OFFLINE_CARGO_COMMANDS = {
    "bench",
    "build",
    "check",
    "clippy",
    "doc",
    "fuzz",
    "metadata",
    "run",
    "rustc",
    "test",
}
DIRECT_CARGO_FUZZ_MODE = "direct-cargo-fuzz-with-inner-locked-offline-cargo-wrapper"


class HermeticExecutionError(RuntimeError):
    """Hermetic child execution cannot be enforced on this host."""


def direct_cargo_fuzz_environment(
    environment: Mapping[str, str], *, cargo_wrapper: Path
) -> dict[str, str]:
    """Select nightly and force cargo-fuzz's inner Cargo through our wrapper."""

    unexpected = set(environment) - OVERRIDE_ALLOWLIST
    if unexpected:
        raise HermeticExecutionError(
            f"unreviewed base child environment keys: {sorted(unexpected)}"
        )
    wrapper = cargo_wrapper.absolute()
    if wrapper.is_symlink() or not wrapper.is_file():
        raise HermeticExecutionError(
            f"inner Cargo wrapper is missing or unsafe: {wrapper}"
        )
    metadata = wrapper.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o700:
        raise HermeticExecutionError(
            f"inner Cargo wrapper is not a private executable: {wrapper}"
        )
    path_entries = environment.get("PATH", "").split(os.pathsep)
    if not path_entries or Path(path_entries[0]).absolute() != wrapper.parent:
        raise HermeticExecutionError(
            "inner Cargo wrapper directory must be the first PATH entry"
        )
    selected = dict(environment)
    selected.update(
        {
            "CARGO": str(wrapper),
            "RUSTUP_TOOLCHAIN": "nightly",
        }
    )
    return selected


def cargo_wrapper_source(*, real_cargo: str, python: str) -> bytes:
    commands = repr(tuple(sorted(LOCKED_OFFLINE_CARGO_COMMANDS)))
    return f"""#!{python}
import os
import sys

REAL_CARGO = {real_cargo!r}
LOCKED_OFFLINE_COMMANDS = {commands}
arguments = sys.argv[1:]
insertion = 1 if arguments and arguments[0].startswith("+") else 0
if len(arguments) > insertion and arguments[insertion] in LOCKED_OFFLINE_COMMANDS:
    required = []
    if "--locked" not in arguments and "--frozen" not in arguments:
        required.append("--locked")
    if "--offline" not in arguments and "--frozen" not in arguments:
        required.append("--offline")
    arguments[insertion:insertion] = required
os.execv(REAL_CARGO, [REAL_CARGO, *arguments])
""".encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitized_environment(
    *,
    private_home: Path,
    private_tmp: Path,
    overrides: Mapping[str, str] | None = None,
    ambient: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source = os.environ if ambient is None else ambient
    environment = {
        key: value for key, value in source.items() if key in AMBIENT_ALLOWLIST
    }
    requested = dict(overrides or {})
    unknown = set(requested) - OVERRIDE_ALLOWLIST
    if unknown:
        raise HermeticExecutionError(
            f"unreviewed child environment overrides: {sorted(unknown)}"
        )
    for directory in (private_home, private_tmp):
        if directory.is_symlink() or not directory.is_dir():
            raise HermeticExecutionError(
                f"private child directory is unsafe: {directory}"
            )
        if directory.stat().st_mode & 0o777 != 0o700:
            raise HermeticExecutionError(
                f"private child directory is not mode 0700: {directory}"
            )
    environment.update(requested)
    environment.update(
        {
            "HOME": str(private_home),
            "TMPDIR": str(private_tmp),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
    )
    return environment


def execution_enforcement(*, system: str | None = None) -> dict[str, object]:
    host = platform.system() if system is None else system
    if host != "Darwin":
        raise HermeticExecutionError(
            f"no reviewed no-network process sandbox is configured for {host}"
        )
    if SANDBOX_EXEC.is_symlink() or not SANDBOX_EXEC.is_file():
        raise HermeticExecutionError("Darwin sandbox-exec is unavailable or unsafe")
    metadata = SANDBOX_EXEC.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise HermeticExecutionError("Darwin sandbox-exec is not a regular file")
    return {
        "schema_version": "cigar.no-network-enforcement.v1",
        "engine": "darwin-sandbox-exec",
        "deny_network_star": True,
        "cargo_credential_files_readable": False,
        "profile_sha256": hashlib.sha256(NO_NETWORK_PROFILE.encode()).hexdigest(),
        "binary_sha256": _sha256_file(SANDBOX_EXEC),
        "binary_size": metadata.st_size,
    }


def no_network_command(
    command: list[str], *, system: str | None = None
) -> tuple[list[str], dict[str, object]]:
    enforcement = execution_enforcement(system=system)
    return [str(SANDBOX_EXEC), "-p", NO_NETWORK_PROFILE, *command], enforcement
