#!/usr/bin/env python3
"""Run bounded WP19 memory/fuzz gates and emit content-free evidence.

This runner deliberately records only commands, digests, counters, timings, and outcomes. Fuzzer
inputs and subprocess output never enter qualification artifacts. A smoke result can never satisfy
the separately declared seven-day-equivalent accumulation requirement.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


QUALITY_TOOL_DIR = Path(__file__).resolve().parent
if str(QUALITY_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(QUALITY_TOOL_DIR))
from bounded_process import BoundedProcessError, run_bounded  # noqa: E402
from corpus_manager import (  # noqa: E402
    CorpusFailure as CorpusManagerFailure,
    candidate_checkout_state,
    create_execution_source_mirror,
    expected_execution_source_state,
    execution_source_state,
    remove_owned_scratch_tree,
    tracked_index_entries,
    verify_minimized_output,
)
from hermetic_execution import (  # noqa: E402
    DIRECT_CARGO_FUZZ_MODE,
    HermeticExecutionError,
    cargo_wrapper_source,
    direct_cargo_fuzz_environment,
    execution_enforcement,
    no_network_command,
    sanitized_environment,
)


ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN = ROOT / "fuzz" / "campaign-v1.json"
POLICY = ROOT / "fuzz" / "corpus-policy.v1.json"
SMOKE_EVIDENCE_NAME = "wp19-quality-smoke.json"
MUTATION_EVIDENCE_NAME = "wp19-quality-mutation.json"
MUTATION_FILTER = (
    "(encode_head|from_deterministic_cbor|semantic_envelope_v1|"
    "semantic_multihash_v1|digest_v1)"
)
MUTATION_THRESHOLD_PERCENT = 90.0
MAXIMUM_SUBPROCESS_OUTPUT_BYTES = 16 * 1024 * 1024
SAFE_TARGET = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
EXCLUDED_SOURCE_DIRECTORIES = {"target", "artifacts", ".work", "__pycache__"}
SOURCE_STATUS_SCOPE = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "crates",
    "vendor",
    "fuzz",
    "tests/properties",
    "tests/miri",
    "tools/quality/corpus_manager.py",
    "tools/quality/fuzz_and_mutation.py",
    "tools/quality/bounded_process.py",
    "tools/quality/hermetic_execution.py",
)


class GateFailure(RuntimeError):
    """A qualification command or threshold failed."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_files(files: Iterable[Path]) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for path in sorted({path.resolve() for path in files}):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT.resolve()).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256_file(path)))
        count += 1
    return digest.hexdigest(), count


def source_digest() -> dict[str, Any]:
    files: list[Path] = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "rust-toolchain.toml",
        ROOT / ".cargo" / "config.toml",
        ROOT / "tools" / "quality" / "corpus_manager.py",
        ROOT / "tools" / "quality" / "bounded_process.py",
        ROOT / "tools" / "quality" / "hermetic_execution.py",
        Path(__file__).resolve(),
    ]
    for base in (
        ROOT / "crates",
        ROOT / "vendor",
        ROOT / "fuzz",
        ROOT / "tests" / "properties",
        ROOT / "tests" / "miri",
    ):
        for path in base.rglob("*"):
            if path.is_symlink():
                raise GateFailure(f"source tree contains a symlink: {path}")
            if not path.is_file() or any(
                part in EXCLUDED_SOURCE_DIRECTORIES
                for part in path.relative_to(base).parts[:-1]
            ):
                continue
            files.append(path)
    digest, count = digest_files(files)
    return {
        "algorithm": "sha256-path-and-content-v1",
        "digest": digest,
        "file_count": count,
    }


def corpus_state(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_dir():
        raise GateFailure(f"corpus directory is missing or unsafe: {path}")
    files: list[Path] = []
    for candidate in path.iterdir():
        if candidate.is_symlink():
            raise GateFailure(f"corpus contains a symlink: {candidate}")
        metadata = candidate.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise GateFailure(f"corpus contains a nested or special entry: {candidate}")
        files.append(candidate)
    digest = hashlib.sha256()
    total_bytes = 0
    for candidate in sorted(files):
        relative = candidate.relative_to(path).as_posix().encode()
        body_digest = bytes.fromhex(sha256_file(candidate))
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(body_digest)
        total_bytes += candidate.stat().st_size
    return {
        "algorithm": "sha256-path-and-content-v1",
        "digest": digest.hexdigest(),
        "file_count": len(files),
        "total_bytes": total_bytes,
    }


def artifact_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise GateFailure(f"required artifact directory disappeared: {path}")
    if path.is_symlink() or not path.is_dir():
        raise GateFailure(f"artifact directory is unsafe: {path}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        directory_metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise GateFailure(f"artifact path is not a directory: {path}")
        if directory_metadata.st_mode & 0o777 != 0o700:
            raise GateFailure(f"artifact directory is not mode 0700: {path}")
        digests: list[str] = []
        for name in os.listdir(descriptor):
            file_descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                file_metadata = os.fstat(file_descriptor)
                if not stat.S_ISREG(file_metadata.st_mode):
                    raise GateFailure(
                        f"artifact directory contains a nested/special entry: {name}"
                    )
                body_digest = hashlib.sha256()
                while chunk := os.read(file_descriptor, 1024 * 1024):
                    body_digest.update(chunk)
                digests.append(body_digest.hexdigest())
            finally:
                os.close(file_descriptor)
        try:
            current_metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise GateFailure(
                f"artifact directory disappeared while scanning: {path}"
            ) from error
        if (
            current_metadata.st_dev != directory_metadata.st_dev
            or current_metadata.st_ino != directory_metadata.st_ino
        ):
            raise GateFailure(f"artifact directory was replaced while scanning: {path}")
        return {
            "file_count": len(digests),
            "digests": sorted(digests),
            "directory_identity": {
                "device": directory_metadata.st_dev,
                "inode": directory_metadata.st_ino,
            },
        }
    finally:
        os.close(descriptor)


def redacted_path(path: Path) -> str:
    absolute = absolute_without_resolving(path)
    try:
        relative = absolute.resolve(strict=False).relative_to(ROOT.resolve())
        return f"<repo>/{relative.as_posix()}"
    except ValueError:
        identifier = sha256_bytes(str(absolute).encode())[:16]
        return f"<external-path:{identifier}>"


def redacted_command(command: list[str]) -> str:
    rendered: list[str] = []
    for argument in command:
        prefix, separator, value = argument.partition("=")
        candidate = value.rstrip(os.sep) if separator else argument.rstrip(os.sep)
        if candidate and Path(candidate).is_absolute():
            replacement = redacted_path(Path(candidate))
            rendered.append(f"{prefix}={replacement}" if separator else replacement)
        else:
            rendered.append(argument)
    return " ".join(rendered)


def run(
    command: list[str],
    *,
    log_path: Path,
    timeout_seconds: float,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    rendered = redacted_command(command)
    print(f"running: {rendered}", flush=True)
    started = utc_now()
    if env is None:
        raise GateFailure(
            "qualification subprocess requires an authoritative sanitized environment"
        )
    merged_env = dict(env)
    private_mkdir(log_path.parent)
    try:
        sandboxed_command, enforcement = no_network_command(
            [
                "/bin/sh",
                "-c",
                'umask 077; exec "$@"',
                "cigar-private-exec",
                *command,
            ]
        )
        process = run_bounded(
            sandboxed_command,
            cwd=cwd,
            env=merged_env,
            log_path=log_path,
            timeout_seconds=timeout_seconds,
            maximum_output_bytes=MAXIMUM_SUBPROCESS_OUTPUT_BYTES,
        )
    except (BoundedProcessError, HermeticExecutionError) as error:
        raise GateFailure(f"bounded subprocess execution failed: {error}") from error
    if (
        process["timed_out"]
        or process["output_overflow"]
        or process["descendant_cleanup_required"]
    ):
        raise GateFailure(
            "subprocess exceeded a bound or leaked a descendant; private log preserved"
        )
    return {
        "command": rendered,
        "started_at": started,
        "finished_at": utc_now(),
        "duration_seconds": process["duration_seconds"],
        "exit_code": process["exit_code"],
        "timed_out": process["timed_out"],
        "output_overflow": process["output_overflow"],
        "descendant_cleanup_required": process["descendant_cleanup_required"],
        "captured_output_bytes": process["captured_output_bytes"],
        "maximum_output_bytes": process["maximum_output_bytes"],
        "private_log": {
            "name": log_path.name,
            "sha256": process["log_sha256"],
            "size": process["log_size"],
            "mode": "0600",
        },
        "execution_enforcement": enforcement,
        "_output": process["tail"],
        "_log_path": str(log_path),
    }


def public_result(result: dict[str, Any], **extra: Any) -> dict[str, Any]:
    redacted = {key: value for key, value in result.items() if not key.startswith("_")}
    redacted.update(extra)
    return redacted


def tool_version(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    return (result.stdout or result.stderr).strip().splitlines()[0]


def tool_value(command: list[str]) -> str:
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise GateFailure(f"cannot resolve tool input: {' '.join(command)}")
    return result.stdout.strip()


def direct_cargo_fuzz_binary() -> Path:
    found = shutil.which("cargo-fuzz")
    if found is None:
        raise GateFailure("required tool binary is unavailable: cargo-fuzz")
    try:
        resolved = Path(found).resolve(strict=True)
    except OSError as error:
        raise GateFailure(
            f"cannot resolve direct cargo-fuzz binary: {error}"
        ) from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise GateFailure("direct cargo-fuzz binary is not a regular executable")
    return resolved


def binary_binding(path: Path) -> dict[str, Any]:
    requested = absolute_without_resolving(path)
    resolved = requested.resolve(strict=True)
    if not resolved.is_file():
        raise GateFailure(f"tool binary is not a regular file: {requested}")
    return {
        "basename": requested.name,
        "requested_path_sha256": sha256_bytes(str(requested).encode()),
        "resolved_path_sha256": sha256_bytes(str(resolved).encode()),
        "content_sha256": sha256_file(resolved),
        "size": resolved.stat().st_size,
    }


def tool_binary_bindings() -> dict[str, dict[str, Any]]:
    discovered: dict[str, Path] = {
        "python": Path(sys.executable),
        "cargo_fuzz": direct_cargo_fuzz_binary(),
    }
    for label, executable in (
        ("cargo_launcher", "cargo"),
        ("rustc_launcher", "rustc"),
    ):
        found = shutil.which(executable)
        if found is None:
            raise GateFailure(f"required tool binary is unavailable: {executable}")
        discovered[label] = Path(found)
    for prefix, command in (
        ("default", ["rustc", "--print", "sysroot"]),
        ("nightly", ["rustc", "+nightly", "--print", "sysroot"]),
    ):
        sysroot = Path(tool_value(command))
        discovered[f"{prefix}_rustc"] = sysroot / "bin" / "rustc"
        discovered[f"{prefix}_cargo"] = sysroot / "bin" / "cargo"
    return {label: binary_binding(path) for label, path in sorted(discovered.items())}


def source_binding_identity() -> dict[str, Any]:
    status_process = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            *SOURCE_STATUS_SCOPE,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    head_process = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if status_process.returncode != 0 or head_process.returncode != 0:
        raise GateFailure("cannot establish Git source binding")
    status = status_process.stdout
    lockfiles: dict[str, str] = {}
    for relative in (
        "Cargo.lock",
        "fuzz/Cargo.lock",
        "tests/properties/Cargo.lock",
        "tests/miri/Cargo.lock",
    ):
        path = ROOT / relative
        if path.is_file():
            lockfiles[relative] = sha256_file(path)
    return {
        "schema_version": "cigar.fuzz-source-binding.v1",
        "git_head": head_process.stdout.decode().strip(),
        "git_scoped_status": {
            "algorithm": "sha256-git-porcelain-v1-z",
            "digest": sha256_bytes(status),
            "entry_count": len([item for item in status.split(b"\0") if item]),
            "dirty": bool(status),
        },
        "qualification_source": source_digest(),
        "lockfiles": lockfiles,
        "toolchain": {
            "python": sys.version.split()[0],
            "rustc": tool_version(["rustc", "--version"]),
            "cargo": tool_version(["cargo", "--version"]),
            "cargo_nightly": tool_version(["cargo", "+nightly", "--version"]),
            "cargo_fuzz": tool_version([str(direct_cargo_fuzz_binary()), "--version"]),
            "binaries": tool_binary_bindings(),
        },
    }


def cargo_fuzz_execution_record(
    cargo_wrapper: Path, source_binding: dict[str, Any]
) -> dict[str, Any]:
    real_cargo = shutil.which("cargo")
    if real_cargo is None:
        raise GateFailure("cargo is unavailable while binding cargo-fuzz execution")
    expected = cargo_wrapper_source(real_cargo=real_cargo, python=sys.executable)
    if cargo_wrapper.is_symlink() or not cargo_wrapper.is_file():
        raise GateFailure("cargo-fuzz inner Cargo wrapper is missing or unsafe")
    if cargo_wrapper.stat().st_mode & 0o777 != 0o700:
        raise GateFailure("cargo-fuzz inner Cargo wrapper is not mode 0700")
    if cargo_wrapper.read_bytes() != expected:
        raise GateFailure("cargo-fuzz inner Cargo wrapper content is unexpected")
    binaries = source_binding.get("toolchain", {}).get("binaries", {})
    required = {"cargo_fuzz", "nightly_cargo", "nightly_rustc"}
    if not isinstance(binaries, dict) or not required.issubset(binaries):
        raise GateFailure("source binding lacks direct cargo-fuzz/nightly binaries")
    return {
        "mode": DIRECT_CARGO_FUZZ_MODE,
        "outer_invocation": "direct-content-bound-cargo-fuzz-binary",
        "environment_contract": {
            "PATH": "private-cargo-wrapper-prefix-plus-reviewed-ambient-path",
            "CARGO": "generated-content-bound-cargo-wrapper",
            "RUSTUP_TOOLCHAIN": "nightly",
        },
        "inner_cargo_required_global_flags": ["--locked", "--offline"],
        "cargo_wrapper": {
            **binary_binding(cargo_wrapper),
            "mode": "0700",
        },
        "cargo_fuzz_binary": binaries["cargo_fuzz"],
        "nightly_cargo_binary": binaries["nightly_cargo"],
        "nightly_rustc_binary": binaries["nightly_rustc"],
    }


def recorded_cargo_fuzz_execution_is_valid(
    record: object, source_binding: dict[str, Any]
) -> bool:
    if not isinstance(record, dict):
        return False
    binaries = source_binding.get("toolchain", {}).get("binaries", {})
    wrapper = record.get("cargo_wrapper")
    real_cargo = shutil.which("cargo")
    if (
        not isinstance(binaries, dict)
        or real_cargo is None
        or not isinstance(wrapper, dict)
    ):
        return False
    expected_wrapper = cargo_wrapper_source(
        real_cargo=real_cargo, python=sys.executable
    )
    expected_keys = {
        "mode",
        "outer_invocation",
        "environment_contract",
        "inner_cargo_required_global_flags",
        "cargo_wrapper",
        "cargo_fuzz_binary",
        "nightly_cargo_binary",
        "nightly_rustc_binary",
    }
    if set(record) != expected_keys:
        return False
    return (
        record.get("mode") == DIRECT_CARGO_FUZZ_MODE
        and record.get("outer_invocation") == "direct-content-bound-cargo-fuzz-binary"
        and record.get("environment_contract")
        == {
            "PATH": "private-cargo-wrapper-prefix-plus-reviewed-ambient-path",
            "CARGO": "generated-content-bound-cargo-wrapper",
            "RUSTUP_TOOLCHAIN": "nightly",
        }
        and record.get("inner_cargo_required_global_flags") == ["--locked", "--offline"]
        and record.get("cargo_fuzz_binary") == binaries.get("cargo_fuzz")
        and record.get("nightly_cargo_binary") == binaries.get("nightly_cargo")
        and record.get("nightly_rustc_binary") == binaries.get("nightly_rustc")
        and set(wrapper)
        == {
            "basename",
            "requested_path_sha256",
            "resolved_path_sha256",
            "content_sha256",
            "size",
            "mode",
        }
        and wrapper.get("basename") == "cargo"
        and wrapper.get("requested_path_sha256") == wrapper.get("resolved_path_sha256")
        and isinstance(wrapper.get("requested_path_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", wrapper["requested_path_sha256"]) is not None
        and wrapper.get("content_sha256") == sha256_bytes(expected_wrapper)
        and wrapper.get("size") == len(expected_wrapper)
        and wrapper.get("mode") == "0700"
    )


def platform_record() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def write_evidence(path: Path, document: dict[str, Any]) -> None:
    body = json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
    if path.exists() or path.is_symlink():
        raise GateFailure(f"refusing to overwrite evidence: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        fsync_directory(path.parent)
    except FileExistsError as error:
        raise GateFailure(f"refusing to overwrite evidence: {path}") from error
    finally:
        temporary.unlink(missing_ok=True)
        fsync_directory(path.parent)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def absolute_without_resolving(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def reject_symlink_components(path: Path) -> None:
    absolute = absolute_without_resolving(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise GateFailure(f"path traverses a symlink: {current}")
        if not current.exists():
            break


def private_mkdir(path: Path, *, exist_ok: bool = True) -> None:
    absolute = absolute_without_resolving(path)
    reject_symlink_components(absolute)
    missing: list[Path] = []
    current = absolute
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise GateFailure(f"unsafe directory ancestor: {current}")
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    if not missing and not exist_ok:
        raise GateFailure(f"refusing existing directory: {absolute}")
    if absolute.is_symlink() or not absolute.is_dir():
        raise GateFailure(f"unsafe directory: {absolute}")
    if absolute.stat().st_mode & 0o777 != 0o700:
        raise GateFailure(f"directory is not private mode 0700: {absolute}")


def external_private_tempdir(parent: Path, prefix: str) -> Path:
    reject_symlink_components(parent)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    os.chmod(path, 0o700)
    return path


def write_private_executable(path: Path, body: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    fsync_directory(path.parent)


def locked_cargo_environment(build_root: Path) -> dict[str, str]:
    private_mkdir(build_root)
    wrapper_directory = build_root / "cargo-wrapper"
    private_mkdir(wrapper_directory, exist_ok=False)
    real_cargo = shutil.which("cargo")
    if real_cargo is None:
        raise GateFailure("cargo is unavailable")
    wrapper = wrapper_directory / "cargo"
    source = cargo_wrapper_source(real_cargo=real_cargo, python=sys.executable)
    write_private_executable(wrapper, source)
    cargo_target = build_root / "cargo-target"
    private_home = build_root / "home"
    private_tmp = build_root / "tmp"
    private_mkdir(cargo_target, exist_ok=False)
    private_mkdir(private_home, exist_ok=False)
    private_mkdir(private_tmp, exist_ok=False)
    overrides = {
        "PATH": str(wrapper_directory) + os.pathsep + os.environ.get("PATH", ""),
        "CARGO_TARGET_DIR": str(cargo_target),
        "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
    }
    try:
        return sanitized_environment(
            private_home=private_home,
            private_tmp=private_tmp,
            overrides=overrides,
        )
    except HermeticExecutionError as error:
        raise GateFailure(
            f"cannot construct hermetic Cargo environment: {error}"
        ) from error


def evidence_dir(args: argparse.Namespace) -> Path:
    argument_value = args.evidence_dir
    environment_value = os.environ.get("CIGAR_EVIDENCE_DIR")
    if argument_value and environment_value:
        argument_path = absolute_without_resolving(Path(argument_value))
        environment_path = absolute_without_resolving(Path(environment_value))
        if argument_path != environment_path:
            raise GateFailure(
                "--evidence-dir conflicts with CIGAR_EVIDENCE_DIR; provide only one location"
            )
    raw = argument_value or environment_value
    if not raw:
        raise GateFailure(
            "set --evidence-dir or CIGAR_EVIDENCE_DIR to a directory outside the repository"
        )
    requested = Path(raw).expanduser()
    reject_symlink_components(requested)
    path = absolute_without_resolving(requested).resolve(strict=False)
    if is_within(path, ROOT.resolve()):
        raise GateFailure(f"evidence directory must be outside the repository: {path}")
    if path.is_symlink():
        raise GateFailure(f"evidence directory must not be a symlink: {path}")
    private_mkdir(path)
    if not path.is_dir():
        raise GateFailure(f"evidence path is not a directory: {path}")
    if path.stat().st_mode & 0o777 != 0o700:
        raise GateFailure(f"evidence directory must be mode 0700: {path}")
    return path


def load_corpus_policy(targets: list[str]) -> dict[str, Any]:
    try:
        policy = json.loads(POLICY.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise GateFailure(f"cannot read corpus policy: {error}") from error
    if policy.get("schema_version") != "cigar.fuzz-corpus-policy.v1":
        raise GateFailure("unexpected corpus policy schema")
    target_policy = policy.get("targets")
    if not isinstance(target_policy, dict) or set(target_policy) != set(targets):
        raise GateFailure("corpus policy target set does not match the campaign")
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise GateFailure("corpus policy limits are missing")
    for name in (
        "maximum_files_per_target",
        "maximum_input_bytes",
        "maximum_total_bytes_per_target",
    ):
        value = limits.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise GateFailure(f"invalid corpus policy limit: {name}")
    seed_base = policy.get("deterministic_minimization_seed_base")
    if not isinstance(seed_base, int) or isinstance(seed_base, bool) or seed_base < 1:
        raise GateFailure("invalid deterministic minimization seed base")
    return policy


def validate_named_fixtures(
    directory: Path, target: str, policy: dict[str, Any]
) -> None:
    fixtures = policy["targets"][target].get("named_fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise GateFailure(f"{target}: corpus policy has no named fixtures")
    for fixture in fixtures:
        name = fixture.get("name")
        if not isinstance(name, str) or Path(name).name != name:
            raise GateFailure(f"{target}: unsafe named fixture in policy")
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise GateFailure(f"{target}: named fixture is missing or unsafe: {name}")
        body = path.read_bytes()
        if hashlib.sha1(body).hexdigest() != fixture.get("sha1") or sha256_bytes(
            body
        ) != fixture.get("sha256"):
            raise GateFailure(f"{target}: named fixture digest mismatch: {name}")


def corpus_tree_states(
    root: Path, targets: list[str], policy: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise GateFailure(f"corpus root is missing or unsafe: {root}")
    children = list(root.iterdir())
    if {entry.name for entry in children} != set(targets) or any(
        entry.is_symlink() or not entry.is_dir() for entry in children
    ):
        raise GateFailure("corpus target directory set does not match the campaign")
    limits = policy["limits"]
    states: dict[str, dict[str, Any]] = {}
    for target in targets:
        directory = root / target
        validate_named_fixtures(directory, target, policy)
        state = corpus_state(directory)
        if state["file_count"] == 0:
            raise GateFailure(f"{target}: corpus is empty")
        if state["file_count"] > limits["maximum_files_per_target"]:
            raise GateFailure(f"{target}: corpus exceeds the file-count ceiling")
        if state["total_bytes"] > limits["maximum_total_bytes_per_target"]:
            raise GateFailure(f"{target}: corpus exceeds the total-byte ceiling")
        for candidate in directory.iterdir():
            if (
                candidate.stat(follow_symlinks=False).st_size
                > limits["maximum_input_bytes"]
            ):
                raise GateFailure(f"{target}: corpus contains an oversized input")
        states[target] = state
    return states


def checked_in_corpus_descriptor(
    targets: list[str], policy: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    root = ROOT / "fuzz" / "corpus"
    states = corpus_tree_states(root, targets, policy)
    return root, {
        "kind": "checked-in-corpus",
        "policy_sha256": sha256_file(POLICY),
        "targets": states,
    }


def external_corpus_descriptor(
    path: Path, targets: list[str], policy: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    reject_symlink_components(path)
    if path.is_symlink() or not path.is_dir():
        raise GateFailure(f"external corpus directory is missing or unsafe: {path}")
    path = path.resolve()
    if is_within(path, ROOT.resolve()):
        raise GateFailure("--corpus-dir must be external when explicitly supplied")
    states = corpus_tree_states(path, targets, policy)
    report_path = path.parent / "minimization-report.json"
    if report_path.is_symlink() or not report_path.is_file():
        raise GateFailure("external corpus lacks its minimization report")
    try:
        verification = verify_minimized_output(path.parent, require_all_targets=True)
    except CorpusManagerFailure as error:
        raise GateFailure(f"external corpus verification failed: {error}") from error
    if [item.get("target") for item in verification.get("targets", [])] != targets:
        raise GateFailure("external corpus verification target set is incomplete")
    return path, {
        "kind": "external-minimized-corpus",
        "root_path_sha256": sha256_bytes(str(path).encode()),
        "report_sha256": sha256_file(report_path),
        "policy_sha256": sha256_file(POLICY),
        "targets": states,
    }


def seed_corpus_root(
    args: argparse.Namespace, targets: list[str]
) -> tuple[Path, dict[str, Any]]:
    policy = load_corpus_policy(targets)
    if not args.corpus_dir:
        return checked_in_corpus_descriptor(targets, policy)
    return external_corpus_descriptor(
        Path(args.corpus_dir).expanduser(), targets, policy
    )


def require_clean(
    result: dict[str, Any], label: str, *, include_output: bool = True
) -> None:
    if (
        result["exit_code"] != 0
        or result.get("timed_out") is not False
        or result.get("output_overflow") is not False
    ):
        raise GateFailure(
            f"{label} failed with exit {result['exit_code']}; timed_out="
            f"{result.get('timed_out')}; output_overflow={result.get('output_overflow')}; "
            "subprocess output withheld in a private bounded log"
        )


def count_passed_tests(output: str) -> int:
    return sum(
        int(match) for match in re.findall(r"test result: ok\. (\d+) passed", output)
    )


def parse_fuzzer_runs(output: str) -> int | None:
    matches = re.findall(r"stat::number_of_executed_units:\s*(\d+)", output)
    if matches:
        return int(matches[-1])
    matches = re.findall(r"Done\s+(\d+)\s+runs", output)
    return int(matches[-1]) if matches else None


def parse_fuzzer_elapsed_seconds(output: str) -> int | None:
    matches = re.findall(r"Done\s+\d+\s+runs in\s+(\d+)\s+second", output)
    return int(matches[-1]) if matches else None


def mutation_campaign_passed(
    result: dict[str, Any], score: float, missed: int, timeout: int
) -> bool:
    return (
        result.get("exit_code") == 0
        and score >= MUTATION_THRESHOLD_PERCENT
        and missed == 0
        and timeout == 0
    )


def mutation_survivor_digests(outcomes: list[dict[str, Any]]) -> list[str]:
    survivors: list[str] = []
    for item in outcomes:
        if str(item.get("summary", "")).lower() not in {"missed", "timeout"}:
            continue
        canonical = json.dumps(
            item, sort_keys=True, separators=(",", ":"), default=str
        ).encode()
        survivors.append(sha256_bytes(canonical))
    return sorted(survivors)


def validate_campaign(campaign: dict[str, Any]) -> list[str]:
    targets = campaign.get("targets")
    if not isinstance(targets, list) or len(targets) != 14 or len(set(targets)) != 14:
        raise GateFailure("campaign must contain exactly fourteen unique targets")
    if any(
        not isinstance(target, str)
        or SAFE_TARGET.fullmatch(target) is None
        or Path(target).name != target
        for target in targets
    ):
        raise GateFailure("campaign contains an unsafe target name")
    if len({target.casefold() for target in targets}) != len(targets):
        raise GateFailure("campaign target names collide case-insensitively")
    if campaign.get("sanitizers") != ["address"]:
        raise GateFailure("native smoke sanitizer must be exactly AddressSanitizer")
    declared = {
        match.group(1)
        for match in re.finditer(
            r'^name\s*=\s*"([^"]+)"',
            (ROOT / "fuzz" / "Cargo.toml").read_text(),
            flags=re.MULTILINE,
        )
    }
    missing = sorted(set(targets) - declared)
    if missing:
        raise GateFailure(f"campaign targets missing Cargo bins: {missing}")
    for target in targets:
        if not (ROOT / "fuzz" / "fuzz_targets" / f"{target}.rs").is_file():
            raise GateFailure(f"missing target wrapper: {target}")
        if not (ROOT / "fuzz" / "corpus" / target).is_dir():
            raise GateFailure(f"missing seed corpus: {target}")
    return targets


def smoke(args: argparse.Namespace) -> None:
    output_directory = evidence_dir(args)
    smoke_evidence = output_directory / SMOKE_EVIDENCE_NAME
    campaign = json.loads(CAMPAIGN.read_text())
    targets = validate_campaign(campaign)
    seed_root, seed_descriptor = seed_corpus_root(args, targets)
    started_at = utc_now()
    source_binding = source_binding_identity()
    build_root = external_private_tempdir(output_directory, "wp19-smoke-build-")
    log_root = external_private_tempdir(output_directory, "wp19-smoke-logs-")
    cargo_environment = locked_cargo_environment(build_root)
    try:
        index_entries = tracked_index_entries()
        candidate_before = candidate_checkout_state(
            index_entries, require_read_only=True
        )
        execution_root, execution_source_before, source_checkout = (
            create_execution_source_mirror(
                build_root,
                index_entries,
                cargo_environment,
                checkout_log_path=log_root / "source-checkout.log",
            )
        )
    except CorpusManagerFailure as error:
        raise GateFailure(
            f"cannot construct smoke execution source: {error}"
        ) from error
    execution_fuzz_root = execution_root / "fuzz"
    try:
        cargo_fuzz_environment = direct_cargo_fuzz_environment(
            cargo_environment,
            cargo_wrapper=build_root / "cargo-wrapper" / "cargo",
        )
    except HermeticExecutionError as error:
        raise GateFailure(
            f"cannot construct direct cargo-fuzz environment: {error}"
        ) from error
    cargo_fuzz_execution = cargo_fuzz_execution_record(
        build_root / "cargo-wrapper" / "cargo", source_binding
    )

    check = run(
        [
            "cargo",
            "check",
            "--locked",
            "--manifest-path",
            str(execution_fuzz_root / "Cargo.toml"),
            "--all-targets",
        ],
        log_path=log_root / "harness-check.log",
        timeout_seconds=900,
        cwd=execution_root,
        env=cargo_environment,
    )
    require_clean(check, "fuzz harness check")

    properties = run(
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            str(execution_root / "tests" / "properties" / "Cargo.toml"),
            "--all-targets",
        ],
        log_path=log_root / "properties-and-loom.log",
        timeout_seconds=1800,
        cwd=execution_root,
        env=cargo_environment,
    )
    require_clean(properties, "property and Loom suite")

    miri = run(
        [
            "cargo",
            "+nightly",
            "miri",
            "test",
            "--locked",
            "--manifest-path",
            str(execution_root / "tests" / "miri" / "Cargo.toml"),
            "--target",
            "x86_64-unknown-linux-gnu",
            "--test",
            "memory_model",
        ],
        log_path=log_root / "strict-miri.log",
        timeout_seconds=1800,
        cwd=execution_root,
        env={
            **cargo_environment,
            "MIRIFLAGS": "-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check",
        },
    )
    require_clean(miri, "strict Miri slice")

    campaign_smoke_seconds = int(campaign["smoke_seconds_per_target"])
    qualifying_smoke = args.runs is None
    requested_seconds = args.seconds if qualifying_smoke else None
    if qualifying_smoke and requested_seconds < campaign_smoke_seconds:
        raise GateFailure(
            f"--seconds must be at least the campaign smoke threshold ({campaign_smoke_seconds})"
        )

    raw_root = external_private_tempdir(output_directory, "wp19-smoke-artifacts-")
    with tempfile.TemporaryDirectory(prefix="cigar-wp19-worker-corpus-") as temporary:
        worker_root = Path(temporary)

        def fuzz_one(index: int, target: str) -> dict[str, Any]:
            source_corpus = seed_root / target
            source_corpus_before = corpus_state(source_corpus)
            corpus = worker_root / target
            shutil.copytree(source_corpus, corpus, copy_function=shutil.copyfile)
            os.chmod(corpus, 0o700)
            before_corpus = corpus_state(corpus)
            if before_corpus != source_corpus_before:
                raise GateFailure(f"private worker corpus copy mismatch: {target}")
            artifact_directory = raw_root / target
            artifact_directory.mkdir(mode=0o700)
            before_artifacts = artifact_state(artifact_directory)
            if before_artifacts["file_count"] != 0:
                raise GateFailure(
                    f"ASan fuzz target {target} has a pre-existing crash artifact"
                )
            seed = args.seed + index
            limiter = (
                f"-max_total_time={requested_seconds}"
                if qualifying_smoke
                else f"-runs={args.runs}"
            )
            command = [
                str(direct_cargo_fuzz_binary()),
                "run",
                "--sanitizer",
                "address",
                "--target-dir",
                cargo_environment["CARGO_TARGET_DIR"],
                "--fuzz-dir",
                str(execution_fuzz_root),
                target,
                str(corpus),
                "--",
                f"-dict={execution_fuzz_root / 'dictionaries' / 'cigar.dict'}",
                limiter,
                f"-seed={seed}",
                f"-timeout={campaign['timeout_seconds']}",
                f"-rss_limit_mb={campaign['rss_limit_mib']}",
                f"-max_len={campaign['maximum_input_bytes']}",
                f"-artifact_prefix={artifact_directory}{os.sep}",
                "-print_final_stats=1",
            ]
            result = run(
                command,
                log_path=log_root / f"fuzz-{target}.log",
                timeout_seconds=(requested_seconds + 180) if qualifying_smoke else 600,
                cwd=execution_root,
                env=cargo_fuzz_environment,
            )
            after_artifacts = artifact_state(artifact_directory)
            if (
                after_artifacts["directory_identity"]
                != before_artifacts["directory_identity"]
            ):
                raise GateFailure(
                    f"ASan fuzz target {target} replaced its artifact directory"
                )
            after_corpus = corpus_state(corpus)
            source_corpus_after = corpus_state(source_corpus)
            if source_corpus_after != source_corpus_before:
                raise GateFailure(
                    f"checked-in corpus changed while fuzzing private worker copy: {target}"
                )
            require_clean(result, f"ASan fuzz target {target}", include_output=False)
            if after_artifacts["file_count"] != 0:
                raise GateFailure(
                    f"ASan fuzz target {target} created a crash artifact; preserved at "
                    f"{artifact_directory}"
                )
            observed_runs = parse_fuzzer_runs(result["_output"])
            observed_seconds = parse_fuzzer_elapsed_seconds(result["_output"])
            if observed_runs is None or observed_runs < 1:
                raise GateFailure(
                    f"ASan fuzz target {target} reported no executed units"
                )
            if not qualifying_smoke and observed_runs < args.runs:
                raise GateFailure(
                    f"ASan fuzz target {target} did not report at least {args.runs} executed units"
                )
            if qualifying_smoke and (
                observed_seconds is None or observed_seconds < requested_seconds
            ):
                raise GateFailure(
                    f"ASan fuzz target {target} did not report {requested_seconds} elapsed seconds"
                )
            return public_result(
                result,
                target=target,
                sanitizer="address",
                deterministic_seed=seed,
                qualification_mode="time-threshold"
                if qualifying_smoke
                else "run-count-viability",
                requested_minimum_seconds=requested_seconds,
                requested_minimum_runs=None if qualifying_smoke else args.runs,
                observed_fuzzer_seconds=observed_seconds,
                observed_executed_units=observed_runs,
                source_corpus=source_corpus_before,
                corpus_before=before_corpus,
                corpus_after=after_corpus,
                corpus_is_private_worker_copy=True,
                source_corpus_unchanged=True,
                crash_artifacts_before=before_artifacts["file_count"],
                crash_artifacts_after=after_artifacts["file_count"],
                artifact_directory_unchanged=True,
                clean=True,
                cargo_fuzz_invocation=DIRECT_CARGO_FUZZ_MODE,
            )

        indexed_results: dict[int, dict[str, Any]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(fuzz_one, index, target): index
                for index, target in enumerate(targets)
            }
            for future in concurrent.futures.as_completed(futures):
                indexed_results[futures[future]] = future.result()
        fuzz_results = [indexed_results[index] for index in range(len(targets))]

    try:
        execution_source_after = execution_source_state(
            execution_root,
            index_entries,
            expected_artifact_targets=set(targets),
        )
        candidate_after = candidate_checkout_state(
            index_entries, require_read_only=True
        )
    except CorpusManagerFailure as error:
        raise GateFailure(
            f"smoke execution source verification failed: {error}"
        ) from error
    if (
        execution_source_before["tracked_source"]
        != execution_source_after["tracked_source"]
        or candidate_before != candidate_after
    ):
        raise GateFailure("smoke execution source or read-only candidate changed")

    scratch_bindings = [
        {
            "path_sha256": sha256_bytes(str(build_root).encode()),
            "kind": "tool-owned-external-smoke-build-scratch",
        },
        {
            "path_sha256": sha256_bytes(str(raw_root).encode()),
            "kind": "tool-owned-external-smoke-artifact-scratch",
        },
    ]
    try:
        remove_owned_scratch_tree(build_root, label="smoke-build-root")
        remove_owned_scratch_tree(raw_root, label="smoke-artifact-root")
    except CorpusManagerFailure as error:
        raise GateFailure(f"cannot remove successful smoke scratch: {error}") from error

    minimum_cpu_seconds = int(campaign["minimum_clean_cpu_seconds_per_target"])
    finished_source_binding = source_binding_identity()
    finished_source = finished_source_binding["qualification_source"]
    if finished_source_binding != source_binding:
        raise GateFailure(
            "qualification source, Git state, locks, or toolchain changed while smoke ran"
        )
    document = {
        "schema_version": "cigar.wp19-quality-smoke.v1",
        "content_policy": "metadata-only-no-corpus-no-subprocess-output",
        "started_at": started_at,
        "finished_at": utc_now(),
        "source": finished_source,
        "source_binding": finished_source_binding,
        "campaign": {
            "path": "fuzz/campaign-v1.json",
            "sha256": sha256_file(CAMPAIGN),
            "target_count": len(targets),
            "smoke_seconds_per_target": campaign_smoke_seconds,
            "minimum_clean_cpu_seconds_per_target": minimum_cpu_seconds,
        },
        "seed_corpus": seed_descriptor,
        "dependency_execution": {
            "mode": "locked-offline-cargo-wrapper",
            "cargo_fuzz_execution": cargo_fuzz_execution,
            "source_checkout": source_checkout,
            "execution_source_before": execution_source_before,
            "execution_source_after": execution_source_after,
            "read_only_candidate": candidate_after,
            "success_scratch_cleanup": {
                "bindings": scratch_bindings,
                "removed": True,
            },
            "build_outputs_external_to_repository": True,
            "private_directory_modes": True,
            "ambient_environment": "strict-reviewed-allowlist",
            "credentials_proxies_cloud_ci_variables_inherited": False,
            "network_enforcement": check["execution_enforcement"],
        },
        "toolchains": {
            "rustc": tool_version(["rustc", "--version"]),
            "cargo_nightly": tool_version(["cargo", "+nightly", "--version"]),
            "cargo_fuzz": tool_version([str(direct_cargo_fuzz_binary()), "--version"]),
            "miri": tool_version(["cargo", "+nightly", "miri", "--version"]),
        },
        "platform": platform_record(),
        "gates": {
            "harness_check": public_result(check, clean=True),
            "properties_and_loom": public_result(
                properties,
                passed_test_count=count_passed_tests(properties["_output"]),
                clean=True,
            ),
            "strict_miri": public_result(
                miri,
                passed_test_count=count_passed_tests(miri["_output"]),
                clean=True,
            ),
            "asan_libfuzzer": fuzz_results,
        },
        "outcome": {
            "viability_passed": True,
            "campaign_smoke_passed": qualifying_smoke,
            "all_fourteen_targets_executed": len(fuzz_results) == 14,
            "crash_count": 0,
            "sanitizer_failure_count": 0,
            "seven_day_equivalent_satisfied": False,
            "release_threshold_status": "not-satisfied-by-smoke",
            "required_clean_cpu_seconds_per_target": minimum_cpu_seconds,
            "note": (
                "The campaign smoke threshold is distinct from the release accumulation. This "
                "evidence intentionally does not claim the cumulative 604800 clean CPU-seconds "
                "required for each target."
            ),
        },
    }
    write_evidence(smoke_evidence, document)
    print(f"wrote {smoke_evidence}", flush=True)


def mutation(args: argparse.Namespace) -> None:
    output_directory = evidence_dir(args)
    mutation_evidence = output_directory / MUTATION_EVIDENCE_NAME
    started_at = utc_now()
    source_binding = source_binding_identity()
    build_root = external_private_tempdir(output_directory, "wp19-mutation-build-")
    log_root = external_private_tempdir(output_directory, "wp19-mutation-logs-")
    cargo_environment = locked_cargo_environment(build_root)
    with tempfile.TemporaryDirectory(prefix="cigar-wp19-mutants-") as temporary:
        output_parent = Path(temporary)
        command = [
            "cargo",
            "mutants",
            "--cargo-arg=--locked",
            "--cargo-arg=--offline",
            "--manifest-path",
            "crates/cigar-canon/Cargo.toml",
            "--file",
            "crates/cigar-canon/src/lib.rs",
            "--re",
            MUTATION_FILTER,
            "--baseline",
            "run",
            "--jobs",
            "4",
            "--timeout",
            "120",
            "--minimum-test-timeout",
            "20",
            "--colors",
            "never",
            "--annotations",
            "none",
            "--output",
            str(output_parent),
        ]
        result = run(
            command,
            log_path=log_root / "representative-mutation.log",
            timeout_seconds=14_400,
            env=cargo_environment,
        )
        if result["exit_code"] not in {0, 2, 3}:
            require_clean(result, "representative mutation campaign")
        outcomes_path = output_parent / "mutants.out" / "outcomes.json"
        if not outcomes_path.is_file():
            raise GateFailure("cargo-mutants did not emit outcomes.json")
        outcome_document = json.loads(outcomes_path.read_text())

    if not isinstance(outcome_document, dict) or not isinstance(
        outcome_document.get("outcomes"), list
    ):
        raise GateFailure("unexpected cargo-mutants outcome schema")
    outcomes = outcome_document["outcomes"]
    counts = {
        name: int(outcome_document.get(name, 0))
        for name in ("caught", "missed", "timeout", "unviable")
    }
    survivor_digests = mutation_survivor_digests(outcomes)

    caught = counts.get("caught", 0)
    missed = counts.get("missed", 0)
    timeout = counts.get("timeout", 0)
    denominator = caught + missed + timeout
    if denominator == 0:
        raise GateFailure(f"no viable mutation outcomes found: {counts}")
    score = round(100.0 * caught / denominator, 3)
    passed = mutation_campaign_passed(result, score, missed, timeout)
    finished_source_binding = source_binding_identity()
    finished_source = finished_source_binding["qualification_source"]
    if finished_source_binding != source_binding:
        raise GateFailure(
            "qualification source, Git state, locks, or toolchain changed while mutation ran"
        )
    document = {
        "schema_version": "cigar.wp19-quality-mutation.v1",
        "content_policy": "metadata-only-no-build-logs-no-mutated-source",
        "started_at": started_at,
        "finished_at": utc_now(),
        "source": finished_source,
        "source_binding": finished_source_binding,
        "toolchain": {
            "cargo_mutants": tool_version(["cargo", "mutants", "--version"]),
            "rustc": tool_version(["rustc", "--version"]),
        },
        "platform": platform_record(),
        "scope": {
            "package": "cigar-canon",
            "file": "crates/cigar-canon/src/lib.rs",
            "filter": MUTATION_FILTER,
            "representative_not_full_workspace": True,
            "dependency_mode": "locked-offline-cargo-wrapper",
            "build_outputs_external_to_repository": True,
            "ambient_environment": "strict-reviewed-allowlist",
            "credentials_proxies_cloud_ci_variables_inherited": False,
            "network_enforcement": result["execution_enforcement"],
        },
        "command": public_result(result),
        "outcomes": {
            "counts": counts,
            "viable_denominator": denominator,
            "caught": caught,
            "missed": missed,
            "timeout": timeout,
            "score_percent": score,
            "required_score_percent": MUTATION_THRESHOLD_PERCENT,
            "survivor_count": len(survivor_digests),
            "survivor_digests": survivor_digests,
        },
        "outcome": {
            "representative_campaign_passed": passed,
            "full_release_candidate_campaign_satisfied": False,
            "note": (
                "This deterministic trust-boundary slice is a real threshold gate, but it does "
                "not claim the PRD's four-hour full release-candidate mutation campaign."
            ),
        },
    }
    write_evidence(mutation_evidence, document)
    print(f"wrote {mutation_evidence}", flush=True)
    if not passed:
        raise GateFailure(
            f"mutation threshold failed: {score}% caught, {missed} missed, {timeout} timeout"
        )


def verify_evidence(args: argparse.Namespace) -> None:
    """Fail closed on stale, incomplete, threshold-failing, or overclaiming evidence."""

    problems: list[str] = []
    try:
        current_enforcement = execution_enforcement()
    except HermeticExecutionError as error:
        raise GateFailure(
            f"no-network enforcement cannot be verified: {error}"
        ) from error
    output_directory = evidence_dir(args)
    smoke_evidence = output_directory / SMOKE_EVIDENCE_NAME
    mutation_evidence = output_directory / MUTATION_EVIDENCE_NAME

    def expect(condition: bool, message: str) -> None:
        if not condition:
            problems.append(message)

    def expect_bounded_process(result: dict[str, Any], label: str) -> None:
        expect(result.get("timed_out") is False, f"{label}: process timed out")
        expect(
            result.get("output_overflow") is False,
            f"{label}: subprocess output overflowed",
        )
        expect(
            result.get("descendant_cleanup_required") is False,
            f"{label}: subprocess leaked a descendant",
        )
        expect(
            result.get("maximum_output_bytes") == MAXIMUM_SUBPROCESS_OUTPUT_BYTES,
            f"{label}: subprocess output bound is missing",
        )
        expect(
            result.get("execution_enforcement") == current_enforcement,
            f"{label}: no-network enforcement binding is stale",
        )

    try:
        smoke_document = json.loads(smoke_evidence.read_text())
        mutation_document = json.loads(mutation_evidence.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise GateFailure(f"cannot read quality evidence: {error}") from error

    current_source_binding = source_binding_identity()
    current_source = current_source_binding["qualification_source"]
    expect(
        smoke_document.get("schema_version") == "cigar.wp19-quality-smoke.v1",
        "unexpected smoke evidence schema",
    )
    expect(
        mutation_document.get("schema_version") == "cigar.wp19-quality-mutation.v1",
        "unexpected mutation evidence schema",
    )
    expect(smoke_document.get("source") == current_source, "smoke evidence is stale")
    expect(
        mutation_document.get("source") == current_source, "mutation evidence is stale"
    )
    expect(
        smoke_document.get("source") == mutation_document.get("source"),
        "smoke and mutation evidence bind different source trees",
    )
    expect(
        smoke_document.get("source_binding") == current_source_binding,
        "smoke evidence Git/source/toolchain binding is stale",
    )
    expect(
        mutation_document.get("source_binding") == current_source_binding,
        "mutation evidence Git/source/toolchain binding is stale",
    )
    expect(
        smoke_document.get("source_binding") == mutation_document.get("source_binding"),
        "smoke and mutation evidence bind different Git/source/toolchain states",
    )

    campaign = json.loads(CAMPAIGN.read_text())
    targets = validate_campaign(campaign)
    policy = load_corpus_policy(targets)
    recorded_seed = smoke_document.get("seed_corpus")
    if not isinstance(recorded_seed, dict):
        raise GateFailure("smoke evidence has no seed corpus descriptor")
    if recorded_seed.get("kind") == "checked-in-corpus":
        _, current_seed = checked_in_corpus_descriptor(targets, policy)
    elif recorded_seed.get("kind") == "external-minimized-corpus":
        raw_root = getattr(args, "corpus_dir", None)
        if not isinstance(raw_root, str) or not raw_root:
            raise GateFailure("verifying external seed evidence requires --corpus-dir")
        _, current_seed = external_corpus_descriptor(Path(raw_root), targets, policy)
    else:
        raise GateFailure("smoke evidence has an unknown seed corpus kind")
    expect(
        recorded_seed == current_seed, "seed corpus evidence is stale or substituted"
    )
    expected_seed_states = current_seed["targets"]
    evidence_campaign = smoke_document.get("campaign", {})
    expect(
        evidence_campaign.get("sha256") == sha256_file(CAMPAIGN),
        "smoke evidence binds a different campaign",
    )
    fuzz_results = smoke_document.get("gates", {}).get("asan_libfuzzer", [])
    expect(isinstance(fuzz_results, list), "ASan result set is not a list")
    if isinstance(fuzz_results, list):
        expect(
            [item.get("target") for item in fuzz_results] == targets,
            "ASan result set does not exactly match the fourteen campaign targets",
        )
        for item in fuzz_results:
            target = item.get("target", "unknown")
            expect_bounded_process(item, str(target))
            expect(item.get("exit_code") == 0, f"{target}: nonzero fuzz exit")
            expect(item.get("clean") is True, f"{target}: not marked clean")
            expect(item.get("sanitizer") == "address", f"{target}: wrong sanitizer")
            expect(
                item.get("cargo_fuzz_invocation") == DIRECT_CARGO_FUZZ_MODE,
                f"{target}: direct cargo-fuzz execution proof is missing",
            )
            expect(
                item.get("qualification_mode") == "time-threshold",
                f"{target}: only a run-count viability check was recorded",
            )
            expect(
                int(item.get("observed_fuzzer_seconds") or -1)
                >= int(campaign["smoke_seconds_per_target"]),
                f"{target}: campaign smoke duration was not met",
            )
            expect(
                int(item.get("observed_executed_units") or 0) > 0,
                f"{target}: no executed units",
            )
            expect(
                item.get("crash_artifacts_before") == 0
                and item.get("crash_artifacts_after") == 0,
                f"{target}: crash artifact present",
            )
            expect(
                item.get("artifact_directory_unchanged") is True,
                f"{target}: artifact-directory identity proof is missing",
            )
            expected_state = expected_seed_states.get(target)
            expect(
                item.get("source_corpus") == expected_state,
                f"{target}: fuzz evidence does not bind the current seed corpus",
            )
            expect(
                item.get("corpus_before") == expected_state,
                f"{target}: private worker corpus did not start from the seed digest",
            )
            expect(
                item.get("source_corpus_unchanged") is True
                and item.get("corpus_is_private_worker_copy") is True,
                f"{target}: source immutability/private-worker proof is missing",
            )

    expect(
        smoke_document.get("dependency_execution", {}).get("mode")
        == "locked-offline-cargo-wrapper",
        "smoke dependencies were not recorded as locked and offline",
    )
    dependency_execution = smoke_document.get("dependency_execution", {})
    expect(
        isinstance(dependency_execution, dict)
        and set(dependency_execution)
        == {
            "mode",
            "cargo_fuzz_execution",
            "source_checkout",
            "execution_source_before",
            "execution_source_after",
            "read_only_candidate",
            "success_scratch_cleanup",
            "build_outputs_external_to_repository",
            "private_directory_modes",
            "ambient_environment",
            "credentials_proxies_cloud_ci_variables_inherited",
            "network_enforcement",
        },
        "smoke dependency-execution field set is not exact",
    )
    expect(
        dependency_execution.get("ambient_environment") == "strict-reviewed-allowlist"
        and dependency_execution.get("credentials_proxies_cloud_ci_variables_inherited")
        is False
        and dependency_execution.get("build_outputs_external_to_repository") is True
        and dependency_execution.get("private_directory_modes") is True
        and dependency_execution.get("network_enforcement") == current_enforcement,
        "smoke hermetic/no-network execution proof is incomplete",
    )
    expect(
        recorded_cargo_fuzz_execution_is_valid(
            dependency_execution.get("cargo_fuzz_execution"),
            current_source_binding,
        ),
        "smoke direct cargo-fuzz/inner Cargo execution binding is invalid",
    )
    try:
        current_index_entries = tracked_index_entries()
        current_candidate = candidate_checkout_state(
            current_index_entries, require_read_only=True
        )
    except CorpusManagerFailure as error:
        raise GateFailure(
            f"cannot verify smoke read-only candidate: {error}"
        ) from error
    expect(
        dependency_execution.get("read_only_candidate") == current_candidate,
        "smoke read-only candidate binding is stale",
    )
    expect(
        dependency_execution.get("execution_source_before")
        == expected_execution_source_state(current_candidate["tracked_source"], set()),
        "smoke execution-source pre-run state is invalid",
    )
    expect(
        dependency_execution.get("execution_source_after")
        == expected_execution_source_state(
            current_candidate["tracked_source"], set(targets)
        ),
        "smoke execution-source post-run state is invalid",
    )
    checkout = dependency_execution.get("source_checkout")
    checkout_private_log = (
        checkout.get("private_log") if isinstance(checkout, dict) else None
    )
    expect(
        isinstance(checkout, dict)
        and set(checkout)
        == {
            "command",
            "exit_code",
            "timed_out",
            "output_overflow",
            "descendant_cleanup_required",
            "captured_output_bytes",
            "maximum_output_bytes",
            "execution_enforcement",
            "private_log",
        }
        and checkout.get("command")
        == "git checkout-index --all --prefix=<external-execution-source>"
        and checkout.get("exit_code") == 0
        and checkout.get("timed_out") is False
        and checkout.get("output_overflow") is False
        and checkout.get("descendant_cleanup_required") is False
        and checkout.get("maximum_output_bytes") == 1024 * 1024
        and checkout.get("execution_enforcement") == current_enforcement
        and isinstance(checkout_private_log, dict)
        and set(checkout_private_log) == {"name", "sha256", "size", "mode"}
        and checkout_private_log.get("name") == "source-checkout.log"
        and checkout_private_log.get("mode") == "0600"
        and type(checkout.get("captured_output_bytes")) is int
        and type(checkout_private_log.get("size")) is int
        and 0 <= checkout_private_log["size"] <= 1024 * 1024
        and checkout.get("captured_output_bytes") == checkout_private_log.get("size"),
        "smoke execution-source checkout proof is invalid",
    )
    cleanup = dependency_execution.get("success_scratch_cleanup")
    cleanup_bindings = cleanup.get("bindings") if isinstance(cleanup, dict) else None
    expected_cleanup_kinds = {
        "tool-owned-external-smoke-build-scratch",
        "tool-owned-external-smoke-artifact-scratch",
    }
    expect(
        isinstance(cleanup, dict)
        and set(cleanup) == {"bindings", "removed"}
        and cleanup.get("removed") is True
        and isinstance(cleanup_bindings, list)
        and {item.get("kind") for item in cleanup_bindings if isinstance(item, dict)}
        == expected_cleanup_kinds
        and len(cleanup_bindings) == 2
        and all(
            isinstance(item, dict)
            and set(item) == {"path_sha256", "kind"}
            and re.fullmatch(r"[0-9a-f]{64}", str(item.get("path_sha256", "")))
            is not None
            for item in cleanup_bindings
        ),
        "smoke scratch cleanup proof is invalid",
    )
    retained_smoke_scratch = [
        path.name
        for path in output_directory.iterdir()
        if path.name.startswith("wp19-smoke-build-")
        or path.name.startswith("wp19-smoke-artifacts-")
    ]
    expect(
        not retained_smoke_scratch, "successful smoke retained build/artifact scratch"
    )

    smoke_log_roots = [
        path
        for path in output_directory.iterdir()
        if path.name.startswith("wp19-smoke-logs-")
    ]
    expect(len(smoke_log_roots) == 1, "smoke private-log root set is not exact")
    if len(smoke_log_roots) == 1:
        smoke_log_root = smoke_log_roots[0]
        expected_log_records = [
            checkout,
            smoke_document.get("gates", {}).get("harness_check"),
            smoke_document.get("gates", {}).get("properties_and_loom"),
            smoke_document.get("gates", {}).get("strict_miri"),
            *fuzz_results,
        ]
        log_records = [
            item.get("private_log") if isinstance(item, dict) else None
            for item in expected_log_records
        ]
        expected_log_names_ordered = [
            "source-checkout.log",
            "harness-check.log",
            "properties-and-loom.log",
            "strict-miri.log",
            *(f"fuzz-{target}.log" for target in targets),
        ]
        expected_log_maxima = [
            1024 * 1024,
            *(
                MAXIMUM_SUBPROCESS_OUTPUT_BYTES
                for _ in range(len(expected_log_names_ordered) - 1)
            ),
        ]
        expected_log_names = set(expected_log_names_ordered)
        expect(
            len(log_records) == len(expected_log_records)
            and len(expected_log_names) == len(expected_log_records)
            and not smoke_log_root.is_symlink()
            and smoke_log_root.is_dir()
            and smoke_log_root.stat().st_mode & 0o777 == 0o700
            and {path.name for path in smoke_log_root.iterdir()} == expected_log_names,
            "smoke private-log attachment set is invalid",
        )
        for expected_name, expected_maximum, process_record, record in zip(
            expected_log_names_ordered,
            expected_log_maxima,
            expected_log_records,
            log_records,
        ):
            if (
                not isinstance(process_record, dict)
                or not isinstance(record, dict)
                or set(record) != {"name", "sha256", "size", "mode"}
                or record.get("name") != expected_name
                or process_record.get("maximum_output_bytes") != expected_maximum
                or type(process_record.get("captured_output_bytes")) is not int
                or type(record.get("size")) is not int
                or not 0 <= record["size"] <= expected_maximum
                or process_record.get("captured_output_bytes") != record.get("size")
            ):
                expect(False, "smoke private-log record is malformed")
                continue
            log_path = smoke_log_root / record["name"]
            expect(
                not log_path.is_symlink()
                and log_path.is_file()
                and log_path.stat().st_mode & 0o777 == 0o600
                and record.get("mode") == "0600"
                and record.get("size") == log_path.stat().st_size
                and record.get("sha256") == sha256_file(log_path),
                f"smoke private log is stale or unsafe: {record['name']}",
            )

    gates = smoke_document.get("gates", {})
    properties = gates.get("properties_and_loom", {})
    miri = gates.get("strict_miri", {})
    harness = gates.get("harness_check", {})
    expect_bounded_process(harness, "harness check")
    expect_bounded_process(properties, "properties and Loom")
    expect_bounded_process(miri, "strict Miri")
    expect(
        properties.get("exit_code") == 0
        and int(properties.get("passed_test_count") or 0) >= 15,
        "property/Loom gate is incomplete",
    )
    expect(
        miri.get("exit_code") == 0 and int(miri.get("passed_test_count") or 0) >= 1,
        "strict Miri gate is incomplete",
    )
    smoke_outcome = smoke_document.get("outcome", {})
    expect(smoke_outcome.get("campaign_smoke_passed") is True, "campaign smoke failed")
    expect(
        smoke_outcome.get("seven_day_equivalent_satisfied") is False,
        "bounded smoke must not claim seven-day-equivalent accumulation",
    )

    mutation_outcomes = mutation_document.get("outcomes", {})
    mutation_outcome = mutation_document.get("outcome", {})
    mutation_command = mutation_document.get("command", {})
    mutation_scope = mutation_document.get("scope", {})
    expect(
        mutation_scope.get("ambient_environment") == "strict-reviewed-allowlist"
        and mutation_scope.get("credentials_proxies_cloud_ci_variables_inherited")
        is False
        and mutation_scope.get("network_enforcement") == current_enforcement,
        "mutation hermetic/no-network execution proof is incomplete",
    )
    expect_bounded_process(mutation_command, "mutation campaign")
    expect(
        mutation_command.get("exit_code") == 0,
        "cargo-mutants command did not exit cleanly",
    )
    expect(
        mutation_outcomes.get("missed") == 0
        and mutation_outcomes.get("timeout") == 0
        and mutation_outcomes.get("survivor_count") == 0
        and mutation_outcomes.get("survivor_digests") == [],
        "mutation survivors or timeouts remain",
    )
    expect(
        float(mutation_outcomes.get("score_percent") or 0)
        >= MUTATION_THRESHOLD_PERCENT,
        "representative mutation score is below threshold",
    )
    expect(
        mutation_outcome.get("representative_campaign_passed") is True,
        "representative mutation campaign failed",
    )
    expect(
        mutation_outcome.get("full_release_candidate_campaign_satisfied") is False,
        "representative mutation evidence must not claim the full RC campaign",
    )
    if problems:
        raise GateFailure("evidence verification failed:\n- " + "\n- ".join(problems))
    print(
        "verified source-bound WP19 ASan smoke, property/Loom, strict Miri, and "
        "representative mutation evidence",
        flush=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_smoke_options(command_parser: argparse.ArgumentParser) -> None:
        limit = command_parser.add_mutually_exclusive_group()
        limit.add_argument("--seconds", type=int, default=60)
        limit.add_argument("--runs", type=int)
        command_parser.add_argument("--jobs", type=int, default=4)
        command_parser.add_argument("--seed", type=int, default=190000)
        command_parser.add_argument(
            "--corpus-dir",
            help="external digest-bound minimized corpus root; defaults to checked-in seeds",
        )

    def add_evidence_option(command_parser: argparse.ArgumentParser) -> None:
        command_parser.add_argument(
            "--evidence-dir",
            help="external output directory (or set CIGAR_EVIDENCE_DIR)",
        )

    smoke_parser = subparsers.add_parser("smoke")
    add_smoke_options(smoke_parser)
    add_evidence_option(smoke_parser)
    smoke_parser.set_defaults(function=smoke)
    mutation_parser = subparsers.add_parser("mutation")
    add_evidence_option(mutation_parser)
    mutation_parser.set_defaults(function=mutation)
    verify_parser = subparsers.add_parser("verify")
    add_evidence_option(verify_parser)
    verify_parser.add_argument(
        "--corpus-dir",
        help="required to revalidate an external minimized corpus receipt",
    )
    verify_parser.set_defaults(function=verify_evidence)
    all_parser = subparsers.add_parser("all")
    add_smoke_options(all_parser)
    add_evidence_option(all_parser)

    def run_all(args: argparse.Namespace) -> None:
        smoke(args)
        mutation(args)

    all_parser.set_defaults(function=run_all)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runs = getattr(args, "runs", None)
    seconds = getattr(args, "seconds", 1)
    jobs = getattr(args, "jobs", 1)
    seed = getattr(args, "seed", 1)
    if runs is not None and not 1 <= runs <= 1_000_000:
        raise GateFailure("--runs must be between 1 and 1000000")
    if not 1 <= seconds <= 3_600:
        raise GateFailure("--seconds must be between 1 and 3600")
    if not 1 <= jobs <= 14:
        raise GateFailure(
            "--jobs must be between 1 and the fourteen-target campaign size"
        )
    if not 1 <= seed <= 2_147_483_647 - 13:
        raise GateFailure("--seed is outside the reviewed positive libFuzzer range")
    args.function(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as error:
        print(f"quality gate failed: {error}", file=sys.stderr)
        raise SystemExit(1)
