#!/usr/bin/env python3
"""Inventory and safely minimize CIGAR's libFuzzer corpora.

The checked-in corpus is an immutable input to this tool.  Inventory reports and minimized
corpora must be written outside the repository, and an output path must be new.  Missing tracked
entries are read from Git's index so an interrupted fuzz run cannot silently discard them.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable


QUALITY_TOOL_DIR = Path(__file__).resolve().parent
if str(QUALITY_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(QUALITY_TOOL_DIR))
from bounded_process import BoundedProcessError, run_bounded  # noqa: E402
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
FUZZ_ROOT = ROOT / "fuzz"
CORPUS_ROOT = FUZZ_ROOT / "corpus"
ARTIFACT_ROOT = FUZZ_ROOT / "artifacts"
CAMPAIGN_PATH = FUZZ_ROOT / "campaign-v1.json"
POLICY_PATH = FUZZ_ROOT / "corpus-policy.v1.json"
HEX_SHA1 = re.compile(r"^[0-9a-f]{40}$")
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


class CorpusFailure(RuntimeError):
    """The corpus cannot be classified or minimized without losing evidence."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def digest(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def digest_file(path: Path) -> str:
    state = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            state.update(chunk)
    return state.hexdigest()


def git_bytes(*arguments: str) -> bytes:
    process = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        diagnostic = process.stderr.decode("utf-8", "replace").strip()
        raise CorpusFailure(f"git {' '.join(arguments)} failed: {diagnostic}")
    return process.stdout


def git_paths(*arguments: str) -> set[str]:
    body = git_bytes(*arguments)
    return {
        item.decode("utf-8", "surrogateescape") for item in body.split(b"\0") if item
    }


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
            raise CorpusFailure(f"path traverses a symlink: {current}")
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
        raise CorpusFailure(f"unsafe directory ancestor: {current}")
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    if not missing and not exist_ok:
        raise CorpusFailure(f"refusing existing directory: {absolute}")
    if absolute.is_symlink() or not absolute.is_dir():
        raise CorpusFailure(f"unsafe directory: {absolute}")
    if absolute.stat().st_mode & 0o077:
        raise CorpusFailure(f"directory is not private mode 0700: {absolute}")


def external_new_path(raw: Path, *, directory: bool) -> Path:
    reject_symlink_components(raw)
    path = absolute_without_resolving(raw).resolve(strict=False)
    if is_within(path, ROOT.resolve()):
        raise CorpusFailure(f"output must be outside the repository: {path}")
    if path.exists() or path.is_symlink():
        raise CorpusFailure(f"refusing to overwrite existing output: {path}")
    parent = path.parent
    private_mkdir(parent)
    if directory:
        private_mkdir(path, exist_ok=False)
    return path


def write_new_json(path: Path, document: dict[str, Any]) -> None:
    body = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_bytes(
    path: Path,
    body: bytes,
    *,
    mode: int = 0o600,
    private_parent: bool = True,
    sync_parent: bool = True,
) -> None:
    if private_parent:
        private_mkdir(path.parent)
    elif path.parent.is_symlink() or not path.parent.is_dir():
        raise CorpusFailure(f"unsafe destination parent: {path.parent}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
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
    if path.read_bytes() != body:
        raise CorpusFailure(f"copy verification failed: {path}")
    if sync_parent:
        fsync_directory(path.parent)


def locked_cargo_environment(directory: Path) -> dict[str, str]:
    private_mkdir(directory, exist_ok=False)
    real_cargo = shutil.which("cargo")
    if real_cargo is None:
        raise CorpusFailure("cargo is unavailable")
    wrapper = directory / "cargo"
    source = cargo_wrapper_source(real_cargo=real_cargo, python=sys.executable)
    write_new_bytes(wrapper, source, mode=0o700)
    private_home = directory / "home"
    private_tmp = directory / "tmp"
    private_mkdir(private_home, exist_ok=False)
    private_mkdir(private_tmp, exist_ok=False)
    overrides = {
        "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
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
        raise CorpusFailure(
            f"cannot construct hermetic Cargo environment: {error}"
        ) from error


def private_subprocess_command(command: list[str]) -> list[str]:
    """Run a child with a restrictive umask without changing this process."""

    return [
        "/bin/sh",
        "-c",
        'umask 077; exec "$@"',
        "cigar-private-exec",
        *command,
    ]


def redacted_path(path: Path) -> str:
    absolute = absolute_without_resolving(path)
    try:
        relative = absolute.resolve(strict=False).relative_to(ROOT.resolve())
        return f"<repo>/{relative.as_posix()}"
    except ValueError:
        identifier = digest(str(absolute).encode(), "sha256")[:16]
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


def external_path_binding(path: Path) -> dict[str, str]:
    absolute = absolute_without_resolving(path)
    return {
        "kind": "external-private-path",
        "path_sha256": digest(str(absolute).encode(), "sha256"),
    }


def tracked_index_entries() -> list[dict[str, Any]]:
    """Return the closed regular-file set from the clean candidate's index."""

    records = git_bytes("ls-files", "--stage", "-z").split(b"\0")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_oid, raw_stage = metadata.split(b" ")
            path = raw_path.decode("utf-8", "strict")
            mode = raw_mode.decode("ascii", "strict")
            oid = raw_oid.decode("ascii", "strict")
            stage = raw_stage.decode("ascii", "strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise CorpusFailure("Git index contains an unparseable entry") from error
        logical = PurePosixPath(path)
        if (
            not path
            or logical.is_absolute()
            or ".." in logical.parts
            or path in seen
            or stage != "0"
        ):
            raise CorpusFailure(f"Git index contains an unsafe entry: {path!r}")
        if mode not in {"100644", "100755"}:
            raise CorpusFailure(
                f"Git index mirror rejects symlink/submodule/special mode {mode}: {path}"
            )
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None:
            raise CorpusFailure(f"Git index contains an invalid object id: {path}")
        source = ROOT / Path(*logical.parts)
        if source.is_symlink():
            raise CorpusFailure(f"candidate tracked source is a symlink: {path}")
        try:
            metadata_stat = source.stat(follow_symlinks=False)
        except OSError as error:
            raise CorpusFailure(
                f"candidate tracked source is missing: {path}"
            ) from error
        if not stat.S_ISREG(metadata_stat.st_mode):
            raise CorpusFailure(f"candidate tracked source is not regular: {path}")
        seen.add(path)
        entries.append(
            {
                "path": path,
                "git_mode": mode,
                "git_oid": oid,
                "size": metadata_stat.st_size,
                "sha256": digest_file(source),
            }
        )
    if not entries:
        raise CorpusFailure("Git index source set is empty")
    entries.sort(key=lambda item: item["path"])
    if len({item["path"].casefold() for item in entries}) != len(entries):
        raise CorpusFailure("Git index paths collide case-insensitively")
    return entries


def tracked_source_digest(entries: list[dict[str, Any]]) -> dict[str, Any]:
    state = hashlib.sha256()
    total_bytes = 0
    for entry in entries:
        path = entry["path"].encode("utf-8")
        mode = entry["git_mode"].encode("ascii")
        oid = entry["git_oid"].encode("ascii")
        state.update(len(path).to_bytes(8, "big"))
        state.update(path)
        state.update(len(mode).to_bytes(8, "big"))
        state.update(mode)
        state.update(len(oid).to_bytes(8, "big"))
        state.update(oid)
        state.update(bytes.fromhex(entry["sha256"]))
        state.update(entry["size"].to_bytes(8, "big"))
        total_bytes += entry["size"]
    return {
        "algorithm": "sha256-path-git-mode-oid-content-size-v1",
        "digest": state.hexdigest(),
        "file_count": len(entries),
        "total_bytes": total_bytes,
    }


def candidate_checkout_state(
    entries: list[dict[str, Any]], *, require_read_only: bool
) -> dict[str, Any]:
    status = git_bytes("status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status:
        raise CorpusFailure("qualification candidate is not Git-clean")
    root_mode = stat.S_IMODE(ROOT.stat(follow_symlinks=False).st_mode)
    if require_read_only and root_mode != 0o555:
        raise CorpusFailure("qualification candidate root is not mode 0555")
    directories = {ROOT}
    for entry in entries:
        path = ROOT / Path(*PurePosixPath(entry["path"]).parts)
        expected_mode = 0o555 if entry["git_mode"] == "100755" else 0o444
        actual_mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
        if require_read_only and actual_mode != expected_mode:
            raise CorpusFailure(
                f"qualification candidate tracked mode is not read-only: {entry['path']}"
            )
        if path.stat(follow_symlinks=False).st_size != entry["size"]:
            raise CorpusFailure(
                f"qualification candidate size changed: {entry['path']}"
            )
        if digest_file(path) != entry["sha256"]:
            raise CorpusFailure(
                f"qualification candidate content changed: {entry['path']}"
            )
        current = path.parent
        while is_within(current, ROOT) and current not in directories:
            directories.add(current)
            if current == ROOT:
                break
            current = current.parent
    if require_read_only:
        for directory in directories:
            if directory.is_symlink() or not directory.is_dir():
                raise CorpusFailure(
                    "qualification candidate contains an unsafe tracked directory"
                )
            if stat.S_IMODE(directory.stat(follow_symlinks=False).st_mode) != 0o555:
                raise CorpusFailure(
                    "qualification candidate tracked directories are not mode 0555"
                )
    return {
        "schema_version": "cigar.read-only-candidate.v1",
        "git_head": git_bytes("rev-parse", "HEAD").decode().strip(),
        "git_tree": git_bytes("rev-parse", "HEAD^{tree}").decode().strip(),
        "git_status": {
            "algorithm": "sha256-git-porcelain-v1-z",
            "digest": digest(status, "sha256"),
            "entry_count": 0,
            "dirty": False,
        },
        "tracked_source": tracked_source_digest(entries),
        "root_mode": "0555" if require_read_only else f"{root_mode:04o}",
        "tracked_files_read_only": require_read_only,
        "tracked_directories_read_only": require_read_only,
    }


def _expected_tracked_directories(entries: list[dict[str, Any]]) -> set[str]:
    directories: set[str] = set()
    for entry in entries:
        current = PurePosixPath(entry["path"]).parent
        while current != PurePosixPath("."):
            directories.add(current.as_posix())
            current = current.parent
    return directories


def execution_source_state(
    mirror: Path,
    entries: list[dict[str, Any]],
    *,
    expected_artifact_targets: set[str],
) -> dict[str, Any]:
    if mirror.is_symlink() or not mirror.is_dir():
        raise CorpusFailure("execution source mirror is missing or unsafe")
    expected_files = {entry["path"]: entry for entry in entries}
    expected_directories = _expected_tracked_directories(entries)
    artifact_root_name = "fuzz/artifacts"
    observed_files: dict[str, Path] = {}
    observed_directories: set[str] = set()
    for path in mirror.rglob("*"):
        relative = path.relative_to(mirror).as_posix()
        if path.is_symlink():
            raise CorpusFailure(f"execution source contains a symlink: {relative}")
        metadata = path.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            observed_directories.add(relative)
        elif stat.S_ISREG(metadata.st_mode):
            observed_files[relative] = path
        else:
            raise CorpusFailure(
                f"execution source contains a special entry: {relative}"
            )
    allowed_runtime_directories = {artifact_root_name} | {
        f"{artifact_root_name}/{target}" for target in expected_artifact_targets
    }
    if set(observed_files) != set(expected_files):
        raise CorpusFailure("execution source tracked file set changed")
    if observed_directories != expected_directories | allowed_runtime_directories:
        raise CorpusFailure("execution source has an unexpected/missing directory")
    if stat.S_IMODE(mirror.stat(follow_symlinks=False).st_mode) != 0o500:
        raise CorpusFailure("execution source root is not hardened mode 0500")
    mirror_entries: list[dict[str, Any]] = []
    for relative, entry in expected_files.items():
        path = observed_files[relative]
        expected_mode = 0o500 if entry["git_mode"] == "100755" else 0o400
        metadata = path.stat(follow_symlinks=False)
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise CorpusFailure(f"execution source file mode changed: {relative}")
        current = {
            "path": relative,
            "git_mode": entry["git_mode"],
            "git_oid": entry["git_oid"],
            "size": metadata.st_size,
            "sha256": digest_file(path),
        }
        if current["size"] != entry["size"] or current["sha256"] != entry["sha256"]:
            raise CorpusFailure(f"execution source content changed: {relative}")
        mirror_entries.append(current)
    for relative in expected_directories:
        mode = stat.S_IMODE(
            (mirror / Path(*PurePosixPath(relative).parts))
            .stat(follow_symlinks=False)
            .st_mode
        )
        expected_mode = 0o700 if relative == "fuzz" else 0o500
        if mode != expected_mode:
            raise CorpusFailure(f"execution source directory mode changed: {relative}")
    artifact_root = mirror / "fuzz" / "artifacts"
    for relative in allowed_runtime_directories:
        path = mirror / Path(*PurePosixPath(relative).parts)
        if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o700:
            raise CorpusFailure("execution artifact scratch is not mode 0700")
    artifact_files = [path for path in artifact_root.rglob("*") if path.is_file()]
    if artifact_files:
        raise CorpusFailure("execution source retained a crash artifact")
    tracked_state = tracked_source_digest(mirror_entries)
    if tracked_state != tracked_source_digest(entries):
        raise CorpusFailure("execution source aggregate differs from candidate")
    return expected_execution_source_state(tracked_state, expected_artifact_targets)


def expected_execution_source_state(
    tracked_state: dict[str, Any], artifact_targets: set[str]
) -> dict[str, Any]:
    return {
        "schema_version": "cigar.execution-source-state.v1",
        "tracked_source": tracked_state,
        "tracked_file_modes": "0400-or-0500-preserving-git-executable-bit",
        "tracked_directory_mode": "0500",
        "writable_directories": [
            "fuzz",
            "fuzz/artifacts",
            "fuzz/artifacts/<campaign-target>",
        ],
        "artifact_targets": sorted(artifact_targets),
        "artifact_file_count": 0,
        "unexpected_entry_count": 0,
    }


def harden_execution_source(mirror: Path, entries: list[dict[str, Any]]) -> None:
    expected_files = {entry["path"]: entry for entry in entries}
    observed_files = {
        path.relative_to(mirror).as_posix(): path
        for path in mirror.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if set(observed_files) != set(expected_files):
        raise CorpusFailure("Git checkout-index emitted an unexpected tracked file set")
    for relative, path in observed_files.items():
        mode = 0o500 if expected_files[relative]["git_mode"] == "100755" else 0o400
        path.chmod(mode)
    artifact_root = mirror / "fuzz" / "artifacts"
    private_mkdir(artifact_root, exist_ok=False)
    directories = [path for path in mirror.rglob("*") if path.is_dir()]
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        directory.chmod(0o500)
    mirror.chmod(0o500)
    (mirror / "fuzz").chmod(0o700)
    artifact_root.chmod(0o700)
    fsync_directory(artifact_root)


def create_execution_source_mirror(
    output_root: Path,
    entries: list[dict[str, Any]],
    environment: dict[str, str],
    *,
    checkout_log_path: Path | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    mirror = output_root / "execution-source"
    private_mkdir(mirror, exist_ok=False)
    log_path = checkout_log_path or output_root / "preflight" / "source-checkout.log"
    private_mkdir(log_path.parent)
    command = [
        "git",
        "checkout-index",
        "--all",
        f"--prefix={mirror}{os.sep}",
    ]
    try:
        sandboxed_command, enforcement = no_network_command(
            private_subprocess_command(command)
        )
        process = run_bounded(
            sandboxed_command,
            cwd=ROOT,
            env=environment,
            log_path=log_path,
            timeout_seconds=300,
            maximum_output_bytes=1024 * 1024,
        )
    except (BoundedProcessError, HermeticExecutionError) as error:
        raise CorpusFailure(
            f"bounded source mirror checkout failed: {error}"
        ) from error
    if (
        process["exit_code"] != 0
        or process["timed_out"]
        or process["output_overflow"]
        or process["descendant_cleanup_required"]
    ):
        raise CorpusFailure("source mirror checkout-index did not complete cleanly")
    harden_execution_source(mirror, entries)
    state = execution_source_state(mirror, entries, expected_artifact_targets=set())
    return (
        mirror,
        state,
        {
            "command": "git checkout-index --all --prefix=<external-execution-source>",
            "exit_code": 0,
            "timed_out": False,
            "output_overflow": False,
            "descendant_cleanup_required": False,
            "captured_output_bytes": process["captured_output_bytes"],
            "maximum_output_bytes": process["maximum_output_bytes"],
            "execution_enforcement": enforcement,
            "private_log": {
                "name": log_path.name,
                "sha256": process["log_sha256"],
                "size": process["log_size"],
                "mode": "0600",
            },
        },
    )


def remove_success_scratch(output_root: Path) -> list[str]:
    names = ["build-target", "cargo-wrapper", "execution-source", "work"]
    for name in names:
        path = output_root / name
        remove_owned_scratch_tree(path, label=name)
        fsync_directory(output_root)
    return names


def remove_owned_scratch_tree(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise CorpusFailure(f"tool-owned success scratch is missing or unsafe: {label}")
    for entry in [path, *path.rglob("*")]:
        if entry.is_symlink():
            continue
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            entry.chmod(0o700)
        elif stat.S_ISREG(metadata.st_mode):
            entry.chmod(0o600)
    shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        raise CorpusFailure(f"tool-owned success scratch was not removed: {label}")
    fsync_directory(path.parent)


def qualification_source_state() -> dict[str, Any]:
    files: list[Path] = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "rust-toolchain.toml",
        ROOT / ".cargo" / "config.toml",
        ROOT / "tools" / "quality" / "corpus_manager.py",
        ROOT / "tools" / "quality" / "fuzz_and_mutation.py",
        ROOT / "tools" / "quality" / "bounded_process.py",
        ROOT / "tools" / "quality" / "hermetic_execution.py",
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
                raise CorpusFailure(f"qualification source contains a symlink: {path}")
            if not path.is_file() or any(
                part in EXCLUDED_SOURCE_DIRECTORIES
                for part in path.relative_to(base).parts[:-1]
            ):
                continue
            files.append(path)
    state = hashlib.sha256()
    count = 0
    for path in sorted({path.resolve() for path in files}):
        if not path.is_file():
            raise CorpusFailure(f"qualification source file disappeared: {path}")
        relative = path.relative_to(ROOT.resolve()).as_posix().encode()
        state.update(len(relative).to_bytes(8, "big"))
        state.update(relative)
        state.update(bytes.fromhex(digest_file(path)))
        count += 1
    return {
        "algorithm": "sha256-path-and-content-v1",
        "digest": state.hexdigest(),
        "file_count": count,
    }


def command_version(command: list[str]) -> str:
    process = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    if process.returncode != 0 or not process.stdout.strip():
        raise CorpusFailure(f"cannot identify toolchain command: {' '.join(command)}")
    return process.stdout.strip().splitlines()[0]


def command_value(command: list[str]) -> str:
    process = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )
    if process.returncode != 0 or not process.stdout.strip():
        raise CorpusFailure(f"cannot resolve tool input: {' '.join(command)}")
    return process.stdout.strip()


def direct_cargo_fuzz_binary() -> Path:
    found = shutil.which("cargo-fuzz")
    if found is None:
        raise CorpusFailure("required tool binary is unavailable: cargo-fuzz")
    try:
        resolved = Path(found).resolve(strict=True)
    except OSError as error:
        raise CorpusFailure(
            f"cannot resolve direct cargo-fuzz binary: {error}"
        ) from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise CorpusFailure("direct cargo-fuzz binary is not a regular executable")
    return resolved


def binary_binding(path: Path) -> dict[str, Any]:
    requested = absolute_without_resolving(path)
    resolved = requested.resolve(strict=True)
    if not resolved.is_file():
        raise CorpusFailure(f"tool binary is not a regular file: {requested}")
    return {
        "basename": requested.name,
        "requested_path_sha256": digest(str(requested).encode(), "sha256"),
        "resolved_path_sha256": digest(str(resolved).encode(), "sha256"),
        "content_sha256": digest_file(resolved),
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
            raise CorpusFailure(f"required tool binary is unavailable: {executable}")
        discovered[label] = Path(found)
    for prefix, command in (
        ("default", ["rustc", "--print", "sysroot"]),
        ("nightly", ["rustc", "+nightly", "--print", "sysroot"]),
    ):
        sysroot = Path(command_value(command))
        discovered[f"{prefix}_rustc"] = sysroot / "bin" / "rustc"
        discovered[f"{prefix}_cargo"] = sysroot / "bin" / "cargo"
    return {label: binary_binding(path) for label, path in sorted(discovered.items())}


def source_binding_document() -> dict[str, Any]:
    status = git_bytes(
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        *SOURCE_STATUS_SCOPE,
    )
    lockfiles: dict[str, str] = {}
    for relative in (
        "Cargo.lock",
        "fuzz/Cargo.lock",
        "tests/properties/Cargo.lock",
        "tests/miri/Cargo.lock",
    ):
        path = ROOT / relative
        if path.is_file():
            lockfiles[relative] = digest_file(path)
    return {
        "schema_version": "cigar.fuzz-source-binding.v1",
        "git_head": git_bytes("rev-parse", "HEAD").decode().strip(),
        "git_scoped_status": {
            "algorithm": "sha256-git-porcelain-v1-z",
            "digest": digest(status, "sha256"),
            "entry_count": len([item for item in status.split(b"\0") if item]),
            "dirty": bool(status),
        },
        "qualification_source": qualification_source_state(),
        "lockfiles": lockfiles,
        "toolchain": {
            "python": sys.version.split()[0],
            "rustc": command_version(["rustc", "--version"]),
            "cargo": command_version(["cargo", "--version"]),
            "cargo_nightly": command_version(["cargo", "+nightly", "--version"]),
            "cargo_fuzz": command_version(
                [str(direct_cargo_fuzz_binary()), "--version"]
            ),
            "binaries": tool_binary_bindings(),
        },
    }


def cargo_fuzz_execution_record(
    cargo_wrapper: Path, source_binding: dict[str, Any]
) -> dict[str, Any]:
    real_cargo = shutil.which("cargo")
    if real_cargo is None:
        raise CorpusFailure("cargo is unavailable while binding cargo-fuzz execution")
    expected = cargo_wrapper_source(real_cargo=real_cargo, python=sys.executable)
    if cargo_wrapper.is_symlink() or not cargo_wrapper.is_file():
        raise CorpusFailure("cargo-fuzz inner Cargo wrapper is missing or unsafe")
    if cargo_wrapper.stat().st_mode & 0o777 != 0o700:
        raise CorpusFailure("cargo-fuzz inner Cargo wrapper is not mode 0700")
    if cargo_wrapper.read_bytes() != expected:
        raise CorpusFailure("cargo-fuzz inner Cargo wrapper content is unexpected")
    binaries = source_binding.get("toolchain", {}).get("binaries", {})
    required = {"cargo_fuzz", "nightly_cargo", "nightly_rustc"}
    if not isinstance(binaries, dict) or not required.issubset(binaries):
        raise CorpusFailure("source binding lacks direct cargo-fuzz/nightly binaries")
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
    record: object,
    source_binding: dict[str, Any],
    *,
    expected_wrapper_path: Path,
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
    expected_source = cargo_wrapper_source(real_cargo=real_cargo, python=sys.executable)
    expected_path = absolute_without_resolving(expected_wrapper_path)
    path_digest = digest(str(expected_path).encode(), "sha256")
    return (
        set(record)
        == {
            "mode",
            "outer_invocation",
            "environment_contract",
            "inner_cargo_required_global_flags",
            "cargo_wrapper",
            "cargo_fuzz_binary",
            "nightly_cargo_binary",
            "nightly_rustc_binary",
        }
        and record.get("mode") == DIRECT_CARGO_FUZZ_MODE
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
        and wrapper.get("requested_path_sha256") == path_digest
        and wrapper.get("resolved_path_sha256") == path_digest
        and wrapper.get("content_sha256") == digest(expected_source, "sha256")
        and wrapper.get("size") == len(expected_source)
        and wrapper.get("mode") == "0700"
    )


def load_policy() -> tuple[dict[str, Any], list[str]]:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        campaign = json.loads(CAMPAIGN_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"cannot read fuzz corpus policy: {error}") from error
    if policy.get("schema_version") != "cigar.fuzz-corpus-policy.v1":
        raise CorpusFailure("unexpected corpus policy schema")
    targets = campaign.get("targets")
    if not isinstance(targets, list) or len(targets) != 14 or len(set(targets)) != 14:
        raise CorpusFailure("campaign must declare exactly fourteen unique targets")
    if any(
        not isinstance(target, str)
        or SAFE_TARGET.fullmatch(target) is None
        or Path(target).name != target
        for target in targets
    ):
        raise CorpusFailure("campaign contains an unsafe target name")
    if len({target.casefold() for target in targets}) != len(targets):
        raise CorpusFailure("campaign target names collide case-insensitively")
    target_policy = policy.get("targets")
    if not isinstance(target_policy, dict) or set(target_policy) != set(targets):
        raise CorpusFailure("corpus policy targets must exactly match the campaign")
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise CorpusFailure("corpus policy limits are missing")
    for name in (
        "maximum_files_per_target",
        "maximum_input_bytes",
        "maximum_total_bytes_per_target",
    ):
        value = limits.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise CorpusFailure(f"invalid positive corpus limit: {name}")
    prefixes = policy.get("artifact_prefixes")
    if (
        not isinstance(prefixes, list)
        or not prefixes
        or any(not isinstance(prefix, str) or not prefix for prefix in prefixes)
    ):
        raise CorpusFailure("artifact prefixes must be a non-empty string list")
    seed_base = policy.get("deterministic_minimization_seed_base")
    if not isinstance(seed_base, int) or isinstance(seed_base, bool) or seed_base < 1:
        raise CorpusFailure("deterministic minimization seed base must be positive")
    for name in (
        "maximum_subprocess_output_bytes",
        "minimization_wall_timeout_seconds",
    ):
        value = policy.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise CorpusFailure(f"invalid positive minimization process limit: {name}")
    for target in targets:
        fixtures = target_policy[target].get("named_fixtures")
        if not isinstance(fixtures, list) or not fixtures:
            raise CorpusFailure(f"{target}: at least one named fixture is required")
        names: set[str] = set()
        for fixture in fixtures:
            name = fixture.get("name")
            classification = fixture.get("classification")
            if (
                not isinstance(name, str)
                or not name
                or Path(name).name != name
                or name in {".", ".."}
                or HEX_SHA1.fullmatch(name)
            ):
                raise CorpusFailure(f"{target}: unsafe or ambiguous fixture name")
            if name in names:
                raise CorpusFailure(f"{target}: duplicate fixture name {name}")
            names.add(name)
            if classification not in {"hand-authored-seed", "minimized-regression"}:
                raise CorpusFailure(f"{target}/{name}: invalid fixture classification")
            if not re.fullmatch(r"[0-9a-f]{40}", str(fixture.get("sha1", ""))):
                raise CorpusFailure(f"{target}/{name}: invalid SHA-1 pin")
            if not re.fullmatch(r"[0-9a-f]{64}", str(fixture.get("sha256", ""))):
                raise CorpusFailure(f"{target}/{name}: invalid SHA-256 pin")
    return policy, targets


def index_body(relative: str) -> bytes:
    return git_bytes("show", f":{relative}")


def collect_entries(target: str, policy: dict[str, Any]) -> list[dict[str, Any]]:
    directory = CORPUS_ROOT / target
    if not directory.is_dir() or directory.is_symlink():
        raise CorpusFailure(f"missing or unsafe corpus directory: {target}")
    prefix = f"fuzz/corpus/{target}/"
    tracked = git_paths("ls-files", "-z", "--", f"{prefix}*")
    untracked = git_paths(
        "ls-files", "--others", "--exclude-standard", "-z", "--", f"{prefix}*"
    )
    current: set[str] = set()
    for path in directory.iterdir():
        if path.is_symlink():
            raise CorpusFailure(f"symlink is forbidden in corpus: {path}")
        if path.is_file():
            current.add(path.relative_to(ROOT).as_posix())
        elif path.is_dir():
            raise CorpusFailure(f"nested corpus directory is forbidden: {path}")
    unexpected = current - tracked - untracked
    if unexpected:
        raise CorpusFailure(f"cannot classify corpus paths: {sorted(unexpected)[:3]}")
    fixture_by_name = {
        fixture["name"]: fixture
        for fixture in policy["targets"][target]["named_fixtures"]
    }
    entries: list[dict[str, Any]] = []
    for relative in sorted(current | tracked):
        name = Path(relative).name
        present = relative in current
        is_tracked = relative in tracked
        body = (ROOT / relative).read_bytes() if present else index_body(relative)
        sha1 = digest(body, "sha1")
        sha256 = digest(body, "sha256")
        fixture = fixture_by_name.get(name)
        if fixture is not None:
            if fixture["sha1"] != sha1 or fixture["sha256"] != sha256:
                raise CorpusFailure(f"named fixture digest mismatch: {target}/{name}")
            base_classification = (
                fixture["classification"]
                if present
                else "named-fixture-deletion-recovered-from-index"
            )
        elif is_tracked and present:
            base_classification = "reusable-corpus"
        elif is_tracked:
            base_classification = "tracked-deletion-recovered-from-index"
        else:
            base_classification = "transient-corpus"
        entries.append(
            {
                "path": relative,
                "name": name,
                "present": present,
                "tracked": is_tracked,
                "base_classification": base_classification,
                "classification": base_classification,
                "sha1": sha1,
                "sha256": sha256,
                "size": len(body),
                "hashed_filename_valid": (
                    name == sha1 if HEX_SHA1.fullmatch(name) else None
                ),
                "_body": body,
            }
        )
    known_fixtures = {
        entry["name"] for entry in entries if entry["name"] in fixture_by_name
    }
    missing_fixtures = sorted(set(fixture_by_name) - known_fixtures)
    if missing_fixtures:
        raise CorpusFailure(f"{target}: missing named fixtures: {missing_fixtures}")

    def canonical_rank(entry: dict[str, Any]) -> tuple[int, str]:
        classification = entry["base_classification"]
        if classification in {"hand-authored-seed", "minimized-regression"}:
            rank = 0
        elif entry["tracked"]:
            rank = 1
        else:
            rank = 2
        return rank, entry["path"]

    by_digest: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for entry in entries:
        by_digest[entry["sha256"]].append(entry)
    for duplicates in by_digest.values():
        ordered = sorted(duplicates, key=canonical_rank)
        for duplicate in ordered[1:]:
            duplicate["classification"] = "duplicate"
            duplicate["duplicate_of"] = ordered[0]["path"]
    return entries


def corpus_state(
    entries: list[dict[str, Any]], *, present_only: bool
) -> dict[str, Any]:
    selected = [entry for entry in entries if entry["present"] or not present_only]
    state = hashlib.sha256()
    total_bytes = 0
    for entry in sorted(selected, key=lambda item: item["path"]):
        relative = entry["path"].encode("utf-8", "surrogateescape")
        state.update(len(relative).to_bytes(8, "big"))
        state.update(relative)
        state.update(bytes.fromhex(entry["sha256"]))
        total_bytes += entry["size"]
    return {
        "algorithm": "sha256-path-and-content-v1",
        "digest": state.hexdigest(),
        "file_count": len(selected),
        "total_bytes": total_bytes,
    }


def public_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "_body"}


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def scan_artifacts(
    targets: list[str], prefixes: list[str]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    by_target = {target: [] for target in targets}
    unexpected: list[dict[str, Any]] = []
    if not ARTIFACT_ROOT.exists():
        return by_target, unexpected
    if ARTIFACT_ROOT.is_symlink() or not ARTIFACT_ROOT.is_dir():
        raise CorpusFailure(f"unsafe artifact root: {ARTIFACT_ROOT}")
    expected = set(targets)
    for path in sorted(ARTIFACT_ROOT.rglob("*")):
        if path.is_symlink():
            raise CorpusFailure(f"symlink is forbidden in fuzz artifacts: {path}")
        relative = path.relative_to(ARTIFACT_ROOT)
        parts = relative.parts
        if path.is_dir():
            if len(parts) == 1 and parts[0] in expected:
                continue
            unexpected.append(
                {
                    "path": display_path(path),
                    "classification": "unexpected-artifact-directory",
                    "size": 0,
                }
            )
            continue
        if not path.is_file():
            raise CorpusFailure(f"non-regular fuzz artifact entry: {path}")
        body = path.read_bytes()
        record = {
            "path": display_path(path),
            "classification": "crash-or-fault-artifact"
            if len(parts) == 2
            and parts[0] in expected
            and any(path.name.startswith(prefix) for prefix in prefixes)
            else "unclassified-artifact",
            "sha1": digest(body, "sha1"),
            "sha256": digest(body, "sha256"),
            "size": len(body),
        }
        if len(parts) == 2 and parts[0] in expected:
            by_target[parts[0]].append(record)
        else:
            unexpected.append(record)
    return by_target, unexpected


def inventory_document() -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    policy, targets = load_policy()
    artifacts_by_target, unexpected_artifacts = scan_artifacts(
        targets, policy["artifact_prefixes"]
    )
    all_entries: dict[str, list[dict[str, Any]]] = {}
    target_documents: list[dict[str, Any]] = []
    totals: collections.Counter[str] = collections.Counter()
    artifact_total = len(unexpected_artifacts)
    compliance_targets: list[dict[str, Any]] = []
    for target in targets:
        entries = collect_entries(target, policy)
        all_entries[target] = entries
        classifications = collections.Counter(
            entry["classification"] for entry in entries
        )
        totals.update(classifications)
        artifacts = artifacts_by_target[target]
        artifact_total += len(artifacts)
        working = corpus_state(entries, present_only=True)
        oversized = [
            entry["path"]
            for entry in entries
            if entry["present"]
            and entry["size"] > policy["limits"]["maximum_input_bytes"]
        ]
        violations: list[str] = []
        if working["file_count"] > policy["limits"]["maximum_files_per_target"]:
            violations.append("maximum_files_per_target")
        if working["total_bytes"] > policy["limits"]["maximum_total_bytes_per_target"]:
            violations.append("maximum_total_bytes_per_target")
        if oversized:
            violations.append("maximum_input_bytes")
        compliance_targets.append(
            {
                "target": target,
                "passed": not violations,
                "violations": violations,
                "oversized_input_count": len(oversized),
            }
        )
        target_documents.append(
            {
                "target": target,
                "working_tree": working,
                "review_input_with_index_recovery": corpus_state(
                    entries, present_only=False
                ),
                "classifications": dict(sorted(classifications.items())),
                "entries": [public_entry(entry) for entry in entries],
                "artifacts": artifacts,
            }
        )
    document = {
        "schema_version": "cigar.fuzz-corpus-inventory.v1",
        "created_at": utc_now(),
        "source_revision": git_bytes("rev-parse", "HEAD").decode().strip(),
        "policy": {
            "path": "fuzz/corpus-policy.v1.json",
            "sha256": digest(POLICY_PATH.read_bytes(), "sha256"),
        },
        "campaign": {
            "path": "fuzz/campaign-v1.json",
            "sha256": digest(CAMPAIGN_PATH.read_bytes(), "sha256"),
        },
        "summary": {
            "target_count": len(targets),
            "classifications": dict(sorted(totals.items())),
            "artifact_count": artifact_total,
            "unexpected_artifact_count": len(unexpected_artifacts),
        },
        "unexpected_artifacts": unexpected_artifacts,
        "policy_compliance": {
            "passed": all(item["passed"] for item in compliance_targets),
            "limits": policy["limits"],
            "targets": compliance_targets,
        },
        "targets": target_documents,
    }
    return document, all_entries


def load_inventory_report(path: Path) -> dict[str, Any]:
    requested = path.expanduser()
    if requested.is_symlink() or not requested.is_file():
        raise CorpusFailure(
            f"inventory report must be a regular non-symlink file: {path}"
        )
    resolved = requested.resolve()
    if is_within(resolved, ROOT.resolve()):
        raise CorpusFailure(
            "reconciliation inventory report must be outside the repository"
        )
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"cannot read reconciliation inventory: {error}") from error
    if document.get("schema_version") != "cigar.fuzz-corpus-inventory.v1":
        raise CorpusFailure("unexpected reconciliation inventory schema")
    return document


def assert_inventory_unchanged(
    preserved: dict[str, Any], current: dict[str, Any]
) -> None:
    for key in (
        "source_revision",
        "policy",
        "campaign",
        "summary",
        "unexpected_artifacts",
        "policy_compliance",
    ):
        if preserved.get(key) != current.get(key):
            raise CorpusFailure(f"inventory binding changed since preservation: {key}")
    preserved_targets = preserved.get("targets")
    current_targets = current.get("targets")
    if not isinstance(preserved_targets, list) or preserved_targets != current_targets:
        raise CorpusFailure("corpus or artifact inventory changed since preservation")


def reconciliation_plan(
    all_entries: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    transients: list[dict[str, Any]] = []
    restorations: list[dict[str, Any]] = []
    known = {
        "duplicate",
        "hand-authored-seed",
        "minimized-regression",
        "named-fixture-deletion-recovered-from-index",
        "reusable-corpus",
        "tracked-deletion-recovered-from-index",
        "transient-corpus",
    }
    for target in sorted(all_entries):
        for entry in all_entries[target]:
            classification = entry.get("classification")
            base = entry.get("base_classification")
            if classification not in known or base not in known - {"duplicate"}:
                raise CorpusFailure(
                    f"refusing unclassified corpus entry: {entry['path']}"
                )
            if base == "transient-corpus":
                if (
                    entry["tracked"]
                    or not entry["present"]
                    or classification
                    not in {
                        "transient-corpus",
                        "duplicate",
                    }
                ):
                    raise CorpusFailure(
                        f"refusing ambiguous transient: {entry['path']}"
                    )
                transients.append(entry)
            elif base in {
                "tracked-deletion-recovered-from-index",
                "named-fixture-deletion-recovered-from-index",
            }:
                if not entry["tracked"] or entry["present"]:
                    raise CorpusFailure(
                        f"refusing ambiguous tracked deletion: {entry['path']}"
                    )
                restorations.append(entry)
            elif base in {"hand-authored-seed", "minimized-regression"}:
                if not entry["tracked"] or not entry["present"]:
                    raise CorpusFailure(
                        f"refusing missing/untracked named fixture: {entry['path']}"
                    )
    return transients, restorations


def prepare_quarantine(
    transients: list[dict[str, Any]], quarantine: Path, *, source_root: Path = ROOT
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    corpus_output = quarantine / "corpus"
    private_mkdir(corpus_output, exist_ok=False)
    target_directories: set[Path] = set()
    for entry in sorted(transients, key=lambda item: item["path"]):
        source = source_root / entry["path"]
        if source.is_symlink() or not source.is_file():
            raise CorpusFailure(
                f"transient disappeared or became unsafe: {entry['path']}"
            )
        body = source.read_bytes()
        if (
            len(body) != entry["size"]
            or digest(body, "sha1") != entry["sha1"]
            or digest(body, "sha256") != entry["sha256"]
        ):
            raise CorpusFailure(f"transient changed after inventory: {entry['path']}")
        relative = Path(entry["path"]).relative_to("fuzz/corpus")
        destination = corpus_output / relative
        write_new_bytes(destination, body)
        target_directories.add(destination.parent)
        actions.append(
            {
                "action": "quarantine-transient",
                "source_path": entry["path"],
                "quarantine_path": destination.relative_to(quarantine).as_posix(),
                "sha1": entry["sha1"],
                "sha256": entry["sha256"],
                "size": entry["size"],
                "copy_verified": True,
            }
        )
    for directory in sorted(target_directories):
        fsync_directory(directory)
    fsync_directory(corpus_output)
    return actions


def append_progress(path: Path, record: dict[str, Any]) -> None:
    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, body)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def atomic_remove_verified_transient(
    source: Path,
    entry: dict[str, Any],
    *,
    post_move_hook: Callable[[Path, Path], None] | None = None,
) -> None:
    if source.parent.is_symlink() or not source.parent.is_dir():
        raise CorpusFailure(f"unsafe transient parent: {source.parent}")
    holding_directory = Path(
        tempfile.mkdtemp(prefix=".cigar-reconcile-", dir=source.parent)
    )
    os.chmod(holding_directory, 0o700)
    holding = holding_directory / "verified-transient"
    try:
        os.rename(source, holding)
        fsync_directory(source.parent)
        descriptor = os.open(holding, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if not (metadata.st_mode & 0o170000) == 0o100000:
                raise CorpusFailure(f"transient is not a regular file: {entry['path']}")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                body = handle.read()
        finally:
            os.close(descriptor)
        if (
            len(body) != entry["size"]
            or digest(body, "sha1") != entry["sha1"]
            or digest(body, "sha256") != entry["sha256"]
        ):
            raise CorpusFailure(
                f"transient changed before atomic move: {entry['path']}"
            )
        if post_move_hook is not None:
            post_move_hook(source, holding)
        holding.unlink()
        fsync_directory(holding_directory)
        holding_directory.rmdir()
        fsync_directory(source.parent)
    except BaseException:
        if holding.exists() and not source.exists():
            try:
                os.link(holding, source, follow_symlinks=False)
                fsync_directory(source.parent)
                holding.unlink()
                holding_directory.rmdir()
            except OSError:
                pass
        raise


def apply_reconciliation(
    transients: list[dict[str, Any]],
    restorations: list[dict[str, Any]],
    *,
    source_root: Path = ROOT,
    progress_path: Path | None = None,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for entry in sorted(restorations, key=lambda item: item["path"]):
        destination = source_root / entry["path"]
        if destination.exists() or destination.is_symlink():
            raise CorpusFailure(
                f"tracked restoration destination appeared: {entry['path']}"
            )
        write_new_bytes(destination, entry["_body"], mode=0o644, private_parent=False)
        action = {
            "action": "restore-tracked-from-index",
            "source_path": entry["path"],
            "sha1": entry["sha1"],
            "sha256": entry["sha256"],
            "size": entry["size"],
            "restored_and_verified": True,
        }
        actions.append(action)
        if progress_path is not None:
            append_progress(progress_path, action)
    for entry in sorted(transients, key=lambda item: item["path"]):
        source = source_root / entry["path"]
        atomic_remove_verified_transient(source, entry)
        action = {
            "action": "atomic-move-and-unlink-verified-quarantined-transient",
            "source_path": entry["path"],
            "sha1": entry["sha1"],
            "sha256": entry["sha256"],
            "size": entry["size"],
            "unlinked": True,
        }
        actions.append(action)
        if progress_path is not None:
            append_progress(progress_path, action)
    touched_directories = {
        (source_root / entry["path"]).parent for entry in transients + restorations
    }
    for directory in sorted(touched_directories):
        fsync_directory(directory)
    return actions


def create_minimizer_input(
    directory: Path, entries: list[dict[str, Any]], maximum_input_bytes: int
) -> None:
    private_mkdir(directory, exist_ok=False)
    unique: dict[str, bytes] = {}
    sha1_owners: dict[str, str] = {}
    for entry in entries:
        if entry["size"] > maximum_input_bytes:
            raise CorpusFailure(
                f"input exceeds maximum_input_bytes: {entry['path']} ({entry['size']})"
            )
        sha256 = entry["sha256"]
        if sha256 in unique:
            continue
        sha1 = entry["sha1"]
        previous = sha1_owners.get(sha1)
        if previous is not None and previous != sha256:
            raise CorpusFailure(f"SHA-1 collision in target corpus: {sha1}")
        sha1_owners[sha1] = sha256
        unique[sha256] = entry["_body"]
        write_new_bytes(directory / sha1, entry["_body"], sync_parent=False)
    fsync_directory(directory)


def run_cmin(
    target: str,
    corpus: Path,
    artifacts: Path,
    campaign: dict[str, Any],
    *,
    seed: int,
    target_dir: Path,
    log_path: Path,
    environment: dict[str, str],
    execution_root: Path,
    execution_fuzz_root: Path,
) -> dict[str, Any]:
    private_mkdir(artifacts)
    private_mkdir(target_dir)
    private_mkdir(log_path.parent)
    command = [
        str(direct_cargo_fuzz_binary()),
        "cmin",
        "--sanitizer",
        "address",
        "--target-dir",
        str(target_dir),
        "--fuzz-dir",
        str(execution_fuzz_root),
        target,
        str(corpus),
        "--",
        f"-dict={execution_fuzz_root / 'dictionaries' / 'cigar.dict'}",
        f"-timeout={campaign['timeout_seconds']}",
        f"-rss_limit_mb={campaign['rss_limit_mib']}",
        f"-max_len={campaign['maximum_input_bytes']}",
        f"-artifact_prefix={artifacts}{os.sep}",
        f"-seed={seed}",
    ]
    try:
        sandboxed_command, enforcement = no_network_command(
            private_subprocess_command(command)
        )
        process = run_bounded(
            sandboxed_command,
            cwd=execution_root,
            env=environment,
            log_path=log_path,
            timeout_seconds=campaign["minimization_wall_timeout_seconds"],
            maximum_output_bytes=campaign["maximum_subprocess_output_bytes"],
            failure_markers=("Failed to minimize corpus:",),
        )
    except (BoundedProcessError, HermeticExecutionError) as error:
        raise CorpusFailure(
            f"bounded minimizer execution failed for {target}: {error}"
        ) from error
    artifact_entries = list(artifacts.rglob("*"))
    if (
        process["exit_code"] != 0
        or process["timed_out"]
        or process["output_overflow"]
        or process["descendant_cleanup_required"]
        or process["failure_markers"]["Failed to minimize corpus:"]
        or artifact_entries
    ):
        raise CorpusFailure(
            f"coverage minimization failed for {target}; artifacts preserved at "
            f"{artifacts}; exit={process['exit_code']}; timed_out={process['timed_out']}; "
            f"output_overflow={process['output_overflow']}; descendant_cleanup_required="
            f"{process['descendant_cleanup_required']}; private log preserved"
        )
    if not any(path.is_file() for path in corpus.iterdir()):
        raise CorpusFailure(f"coverage minimizer emitted an empty corpus: {target}")
    return {
        "target": target,
        "command": redacted_command(command),
        "exit_code": process["exit_code"],
        "artifact_count": 0,
        "deterministic_seed": seed,
        "dependency_mode": "locked-offline-cargo-wrapper",
        "cargo_fuzz_invocation": DIRECT_CARGO_FUZZ_MODE,
        "target_dir": external_path_binding(target_dir),
        "timed_out": False,
        "output_overflow": False,
        "descendant_cleanup_required": False,
        "captured_output_bytes": process["captured_output_bytes"],
        "maximum_output_bytes": process["maximum_output_bytes"],
        "private_log": {
            "name": log_path.name,
            "sha256": process["log_sha256"],
            "size": process["log_size"],
            "mode": "0600",
        },
        "execution_enforcement": enforcement,
    }


def emit_deterministic_corpus(
    target: str,
    minimized: Path,
    output: Path,
    entries: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fixture_by_name = {
        fixture["name"]: fixture
        for fixture in policy["targets"][target]["named_fixtures"]
    }
    source_fixture = {
        entry["name"]: entry for entry in entries if entry["name"] in fixture_by_name
    }
    selected: dict[str, bytes] = {}
    source_digests = {entry["sha256"] for entry in entries}
    for path in minimized.iterdir():
        if path.is_symlink() or not path.is_file():
            raise CorpusFailure(f"unsafe minimizer output: {path}")
        body = path.read_bytes()
        sha256 = digest(body, "sha256")
        if sha256 not in source_digests:
            raise CorpusFailure(
                f"minimizer emitted content outside its source corpus: {target}"
            )
        selected[sha256] = body
    for name, entry in source_fixture.items():
        fixture = fixture_by_name[name]
        if entry["sha1"] != fixture["sha1"] or entry["sha256"] != fixture["sha256"]:
            raise CorpusFailure(f"fixture changed during minimization: {target}/{name}")
        selected[entry["sha256"]] = entry["_body"]

    private_mkdir(output, exist_ok=False)
    output_names: dict[str, list[str]] = collections.defaultdict(list)
    emitted_digests: set[str] = set()
    for name in sorted(source_fixture):
        entry = source_fixture[name]
        write_new_bytes(output / name, entry["_body"], sync_parent=False)
        output_names[entry["sha256"]].append(name)
        emitted_digests.add(entry["sha256"])
    for sha256, body in sorted(
        selected.items(), key=lambda item: (digest(item[1], "sha1"), item[0])
    ):
        if sha256 in emitted_digests:
            continue
        name = digest(body, "sha1")
        path = output / name
        if path.exists():
            raise CorpusFailure(f"output filename collision: {target}/{name}")
        write_new_bytes(path, body, sync_parent=False)
        output_names[sha256].append(name)
        emitted_digests.add(sha256)

    limits = policy["limits"]
    files = sorted(path for path in output.iterdir() if path.is_file())
    total_bytes = sum(path.stat().st_size for path in files)
    if len(files) > limits["maximum_files_per_target"]:
        raise CorpusFailure(
            f"{target}: minimized corpus has {len(files)} files, above ceiling "
            f"{limits['maximum_files_per_target']}"
        )
    if total_bytes > limits["maximum_total_bytes_per_target"]:
        raise CorpusFailure(
            f"{target}: minimized corpus has {total_bytes} bytes, above ceiling "
            f"{limits['maximum_total_bytes_per_target']}"
        )
    for path in files:
        if path.stat().st_size > limits["maximum_input_bytes"]:
            raise CorpusFailure(
                f"{target}: minimized input exceeds byte ceiling: {path.name}"
            )

    output_entries: list[dict[str, Any]] = []
    for path in files:
        body = path.read_bytes()
        output_entries.append(
            {
                "path": path.name,
                "present": True,
                "size": len(body),
                "sha1": digest(body, "sha1"),
                "sha256": digest(body, "sha256"),
            }
        )
    fsync_directory(output)
    state = corpus_state(output_entries, present_only=True)
    mapping = [
        {
            "old_path": entry["path"],
            "old_sha256": entry["sha256"],
            "classification": entry["classification"],
            "retained": entry["sha256"] in output_names,
            "new_names": sorted(output_names.get(entry["sha256"], [])),
        }
        for entry in entries
    ]
    return state, mapping


def validate_private_tree(root: Path) -> None:
    """Reject symlinks, special entries, and non-private evidence modes."""

    for path in [root, *sorted(root.rglob("*"))]:
        if path.is_symlink():
            raise CorpusFailure(f"symlink is forbidden in minimized output: {path}")
        if path.is_dir():
            if path.stat().st_mode & 0o777 != 0o700:
                raise CorpusFailure(
                    f"minimized output directory is not mode 0700: {path}"
                )
        elif path.is_file():
            if path.stat().st_mode & 0o777 != 0o600:
                raise CorpusFailure(f"minimized output file is not mode 0600: {path}")
        else:
            raise CorpusFailure(
                f"special entry is forbidden in minimized output: {path}"
            )


def staged_corpus_state(
    directory: Path, target: str, policy: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    if directory.is_symlink() or not directory.is_dir():
        raise CorpusFailure(f"missing safe staged corpus directory: {target}")
    fixture_by_name = {
        fixture["name"]: fixture
        for fixture in policy["targets"][target]["named_fixtures"]
    }
    entries: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise CorpusFailure(f"unsafe staged corpus entry: {path}")
        body = path.read_bytes()
        sha1 = digest(body, "sha1")
        sha256 = digest(body, "sha256")
        fixture = fixture_by_name.get(path.name)
        if fixture is not None:
            if fixture["sha1"] != sha1 or fixture["sha256"] != sha256:
                raise CorpusFailure(
                    f"staged named fixture digest mismatch: {target}/{path.name}"
                )
        elif not HEX_SHA1.fullmatch(path.name) or path.name != sha1:
            raise CorpusFailure(
                f"non-canonical staged corpus filename: {target}/{path.name}"
            )
        entries.append(
            {
                "path": path.name,
                "present": True,
                "size": len(body),
                "sha1": sha1,
                "sha256": sha256,
            }
        )
    if not entries:
        raise CorpusFailure(f"staged corpus is empty: {target}")
    if not set(fixture_by_name).issubset({entry["path"] for entry in entries}):
        raise CorpusFailure(f"staged corpus is missing a named fixture: {target}")
    state = corpus_state(entries, present_only=True)
    limits = policy["limits"]
    if state["file_count"] > limits["maximum_files_per_target"]:
        raise CorpusFailure(f"staged corpus exceeds file ceiling: {target}")
    if state["total_bytes"] > limits["maximum_total_bytes_per_target"]:
        raise CorpusFailure(f"staged corpus exceeds byte ceiling: {target}")
    if any(entry["size"] > limits["maximum_input_bytes"] for entry in entries):
        raise CorpusFailure(f"staged corpus contains an oversized input: {target}")
    return state, sorted(fixture_by_name)


def validate_empty_artifact_tree(root: Path, targets: list[str]) -> None:
    if root.is_symlink() or not root.is_dir():
        raise CorpusFailure("minimization output has no safe artifact directory")
    children = list(root.iterdir())
    if {path.name for path in children} != set(targets):
        raise CorpusFailure(
            "staged artifact target directories do not match the report"
        )
    for target_directory in children:
        if target_directory.is_symlink() or not target_directory.is_dir():
            raise CorpusFailure(f"unexpected staged artifact entry: {target_directory}")
        runs = list(target_directory.iterdir())
        if {path.name for path in runs} != {"primary", "repeat"}:
            raise CorpusFailure(
                f"staged artifact run directories are incomplete: {target_directory.name}"
            )
        for run in runs:
            if run.is_symlink() or not run.is_dir() or any(run.iterdir()):
                raise CorpusFailure(f"staged minimization retained an artifact: {run}")


def verify_minimized_output(
    output_root: Path, *, require_all_targets: bool
) -> dict[str, Any]:
    requested = output_root.expanduser()
    reject_symlink_components(requested)
    if requested.is_symlink() or not requested.is_dir():
        raise CorpusFailure(
            f"minimized output must be a non-symlink directory: {output_root}"
        )
    resolved = requested.resolve()
    if is_within(resolved, ROOT.resolve()):
        raise CorpusFailure("minimized output must be outside the repository")
    expected_top_level = {
        "artifacts",
        "corpus",
        "equivalence",
        "logs",
        "minimization-report.json",
        "preflight",
    }
    if {path.name for path in resolved.iterdir()} != expected_top_level:
        raise CorpusFailure(
            "minimized output has unexpected or retained scratch entries"
        )
    validate_private_tree(resolved)
    report_path = resolved / "minimization-report.json"
    if (
        report_path.is_symlink()
        or not report_path.is_file()
        or report_path.stat().st_mode & 0o777 != 0o600
    ):
        raise CorpusFailure(f"missing safe minimization report: {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"cannot read minimization report: {error}") from error
    if report.get("schema_version") != "cigar.fuzz-corpus-minimization.v1":
        raise CorpusFailure("unexpected minimization report schema")
    if set(report) != {
        "schema_version",
        "created_at",
        "source_revision",
        "source_binding",
        "policy",
        "campaign",
        "source_working_corpus_unchanged",
        "source_corpus_before",
        "source_corpus_after",
        "all_fourteen_targets_snapshotted",
        "dependency_mode",
        "cargo_fuzz_execution",
        "read_only_candidate",
        "execution_source",
        "success_scratch_cleanup",
        "execution_enforcement",
        "environment_policy",
        "metadata_preflight",
        "targets",
    }:
        raise CorpusFailure("minimization report field set is not exact")
    current_source_binding = source_binding_document()
    if report.get("source_binding") != current_source_binding:
        raise CorpusFailure(
            "minimized output binds a different source, Git state, lockfile, or toolchain"
        )
    if report.get("source_revision") != current_source_binding["git_head"]:
        raise CorpusFailure(
            "minimized output source revision does not match current HEAD"
        )
    if report.get("source_working_corpus_unchanged") is not True:
        raise CorpusFailure("minimization did not prove the source corpus unchanged")
    if report.get("all_fourteen_targets_snapshotted") is not True:
        raise CorpusFailure("minimization did not snapshot all campaign source corpora")
    if report.get("dependency_mode") != "locked-offline-cargo-wrapper":
        raise CorpusFailure("minimization dependencies were not locked and offline")
    if not recorded_cargo_fuzz_execution_is_valid(
        report.get("cargo_fuzz_execution"),
        current_source_binding,
        expected_wrapper_path=resolved / "cargo-wrapper" / "cargo",
    ):
        raise CorpusFailure(
            "minimization does not bind direct cargo-fuzz and its inner Cargo wrapper"
        )
    index_entries = tracked_index_entries()
    current_candidate = candidate_checkout_state(index_entries, require_read_only=True)
    candidate_record = report.get("read_only_candidate")
    if candidate_record != {
        "before": current_candidate,
        "after": current_candidate,
        "unchanged": True,
    }:
        raise CorpusFailure("minimization read-only candidate binding is stale")
    if report.get("success_scratch_cleanup") != {
        "removed": ["build-target", "cargo-wrapper", "execution-source", "work"],
        "completed": True,
    }:
        raise CorpusFailure("minimization success scratch cleanup proof is incomplete")
    try:
        current_enforcement = execution_enforcement()
    except HermeticExecutionError as error:
        raise CorpusFailure(
            f"no-network enforcement cannot be verified: {error}"
        ) from error
    if report.get("execution_enforcement") != current_enforcement:
        raise CorpusFailure("minimization no-network enforcement binding is stale")
    if report.get("environment_policy") != {
        "ambient_environment": "strict-reviewed-allowlist",
        "credentials_proxies_cloud_ci_variables_inherited": False,
        "private_home_and_tmp": True,
    }:
        raise CorpusFailure("minimization hermetic environment proof is incomplete")
    preflight_directory = resolved / "preflight"
    if (
        preflight_directory.is_symlink()
        or not preflight_directory.is_dir()
        or {path.name for path in preflight_directory.iterdir()}
        != {"cargo-metadata.log", "source-checkout.log"}
    ):
        raise CorpusFailure("minimization preflight file set is invalid")
    preflight = report.get("metadata_preflight")
    preflight_private_log = (
        preflight.get("private_log") if isinstance(preflight, dict) else None
    )
    preflight_log = resolved / "preflight" / "cargo-metadata.log"
    if (
        not isinstance(preflight, dict)
        or set(preflight)
        != {
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
        or not isinstance(preflight_private_log, dict)
        or set(preflight_private_log) != {"name", "sha256", "size", "mode"}
        or preflight.get("exit_code") != 0
        or preflight.get("timed_out") is not False
        or preflight.get("output_overflow") is not False
        or preflight.get("descendant_cleanup_required") is not False
        or preflight.get("maximum_output_bytes") != 1024 * 1024
        or preflight.get("execution_enforcement") != current_enforcement
        or preflight.get("command")
        != redacted_command(
            [
                "cargo",
                "metadata",
                "--manifest-path",
                str(resolved / "execution-source" / "fuzz" / "Cargo.toml"),
                "--no-deps",
                "--format-version",
                "1",
            ]
        )
        or preflight_log.is_symlink()
        or not preflight_log.is_file()
        or type(preflight.get("captured_output_bytes")) is not int
        or preflight.get("captured_output_bytes") != preflight_log.stat().st_size
        or preflight_log.stat().st_size > 1024 * 1024
        or preflight_log.stat().st_mode & 0o777 != 0o600
        or preflight_private_log.get("name") != preflight_log.name
        or preflight_private_log.get("mode") != "0600"
        or preflight_private_log.get("sha256") != digest_file(preflight_log)
        or type(preflight_private_log.get("size")) is not int
        or preflight_private_log.get("size") != preflight_log.stat().st_size
    ):
        raise CorpusFailure("minimization metadata preflight proof is invalid")
    execution_source_record = report.get("execution_source")
    checkout_preflight = (
        execution_source_record.get("checkout_preflight")
        if isinstance(execution_source_record, dict)
        else None
    )
    checkout_private_log = (
        checkout_preflight.get("private_log")
        if isinstance(checkout_preflight, dict)
        else None
    )
    checkout_log = preflight_directory / "source-checkout.log"
    if (
        not isinstance(checkout_preflight, dict)
        or set(checkout_preflight)
        != {
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
        or not isinstance(checkout_private_log, dict)
        or set(checkout_private_log) != {"name", "sha256", "size", "mode"}
        or checkout_preflight.get("command")
        != "git checkout-index --all --prefix=<external-execution-source>"
        or checkout_preflight.get("exit_code") != 0
        or checkout_preflight.get("timed_out") is not False
        or checkout_preflight.get("output_overflow") is not False
        or checkout_preflight.get("descendant_cleanup_required") is not False
        or checkout_preflight.get("execution_enforcement") != current_enforcement
        or checkout_preflight.get("maximum_output_bytes") != 1024 * 1024
        or checkout_log.is_symlink()
        or not checkout_log.is_file()
        or type(checkout_preflight.get("captured_output_bytes")) is not int
        or checkout_log.stat().st_mode & 0o777 != 0o600
        or checkout_private_log.get("name") != checkout_log.name
        or checkout_private_log.get("mode") != "0600"
        or checkout_private_log.get("sha256") != digest_file(checkout_log)
        or type(checkout_private_log.get("size")) is not int
        or checkout_private_log.get("size") != checkout_log.stat().st_size
        or checkout_preflight.get("captured_output_bytes")
        != checkout_log.stat().st_size
        or checkout_log.stat().st_size > 1024 * 1024
    ):
        raise CorpusFailure("execution source checkout preflight proof is invalid")
    policy, campaign_targets = load_policy()
    campaign_document = json.loads(CAMPAIGN_PATH.read_text(encoding="utf-8"))
    current_corpus_entries = {
        target: collect_entries(target, policy) for target in campaign_targets
    }
    expected_source_snapshots = {
        target: corpus_state(current_corpus_entries[target], present_only=True)
        for target in campaign_targets
    }
    before = report.get("source_corpus_before")
    after = report.get("source_corpus_after")
    if (
        not isinstance(before, dict)
        or set(before) != set(campaign_targets)
        or before != expected_source_snapshots
        or before != after
    ):
        raise CorpusFailure(
            "all-fourteen source corpus snapshots are incomplete or changed"
        )
    expected_policy = {
        "path": "fuzz/corpus-policy.v1.json",
        "sha256": digest(POLICY_PATH.read_bytes(), "sha256"),
    }
    expected_campaign = {
        "path": "fuzz/campaign-v1.json",
        "sha256": digest(CAMPAIGN_PATH.read_bytes(), "sha256"),
    }
    if (
        report.get("policy") != expected_policy
        or report.get("campaign") != expected_campaign
    ):
        raise CorpusFailure("minimized output binds a stale policy or campaign")
    report_targets = report.get("targets")
    if not isinstance(report_targets, list) or not report_targets:
        raise CorpusFailure("minimization report has no targets")
    names = [item.get("target") for item in report_targets if isinstance(item, dict)]
    if len(names) != len(report_targets) or len(set(names)) != len(names):
        raise CorpusFailure("minimization report target set is invalid")
    if any(name not in campaign_targets for name in names):
        raise CorpusFailure("minimization report contains an unknown target")
    if names != [target for target in campaign_targets if target in set(names)]:
        raise CorpusFailure("minimization report targets are not in campaign order")
    if require_all_targets and names != campaign_targets:
        raise CorpusFailure(
            "minimization report does not contain all campaign targets in order"
        )
    expected_execution_before = expected_execution_source_state(
        current_candidate["tracked_source"], set()
    )
    expected_execution_after = expected_execution_source_state(
        current_candidate["tracked_source"], set(names)
    )
    if execution_source_record != {
        "construction": "git-checkout-index-closed-regular-file-set",
        "checkout_preflight": checkout_preflight,
        "before": expected_execution_before,
        "after": expected_execution_after,
        "tracked_source_unchanged": True,
        "candidate_tracked_source_equal": True,
        "compiled_only_from_execution_source": True,
    }:
        raise CorpusFailure("execution source mirror proof is incomplete or stale")

    corpus_root = resolved / "corpus"
    equivalence_root = resolved / "equivalence"
    for root, label in ((corpus_root, "corpus"), (equivalence_root, "equivalence")):
        if root.is_symlink() or not root.is_dir():
            raise CorpusFailure(f"minimization output has no safe {label} directory")
        children = list(root.iterdir())
        if {path.name for path in children} != set(names) or any(
            path.is_symlink() or not path.is_dir() for path in children
        ):
            raise CorpusFailure(f"staged {label} directories do not match the report")
    validate_empty_artifact_tree(resolved / "artifacts", names)
    logs_root = resolved / "logs"
    if logs_root.is_symlink() or not logs_root.is_dir():
        raise CorpusFailure("minimization output has no safe private-log directory")
    log_targets = list(logs_root.iterdir())
    if {path.name for path in log_targets} != set(names) or any(
        path.is_symlink() or not path.is_dir() for path in log_targets
    ):
        raise CorpusFailure("private-log target directories do not match the report")

    verified: list[dict[str, Any]] = []
    for target_index, target_report in enumerate(report_targets):
        target = target_report["target"]
        if set(target_report) != {
            "target",
            "input",
            "output",
            "engine",
            "repeat_engine",
            "repeat_output",
            "deterministic_equivalence_proved",
            "old_to_new",
        }:
            raise CorpusFailure(f"{target}: minimization target field set is invalid")
        source_entries = current_corpus_entries[target]
        if target_report.get("input") != corpus_state(
            source_entries, present_only=False
        ):
            raise CorpusFailure(f"{target}: minimization input binding is stale")
        expected_seed = policy[
            "deterministic_minimization_seed_base"
        ] + campaign_targets.index(target)
        engine = target_report.get("engine")
        repeat_engine = target_report.get("repeat_engine")
        target_log_directory = logs_root / target
        if {path.name for path in target_log_directory.iterdir()} != {
            "primary.log",
            "repeat.log",
        }:
            raise CorpusFailure(f"{target}: private minimizer log set is not exact")
        for label, run in (("primary", engine), ("repeat", repeat_engine)):
            if not isinstance(run, dict):
                raise CorpusFailure(f"{target}: missing {label} minimizer evidence")
            expected_command = redacted_command(
                [
                    str(direct_cargo_fuzz_binary()),
                    "cmin",
                    "--sanitizer",
                    "address",
                    "--target-dir",
                    str(resolved / "build-target"),
                    "--fuzz-dir",
                    str(resolved / "execution-source" / "fuzz"),
                    target,
                    str(resolved / "work" / target / label),
                    "--",
                    (
                        "-dict="
                        f"{resolved / 'execution-source' / 'fuzz' / 'dictionaries' / 'cigar.dict'}"
                    ),
                    f"-timeout={campaign_document['timeout_seconds']}",
                    f"-rss_limit_mb={campaign_document['rss_limit_mib']}",
                    f"-max_len={campaign_document['maximum_input_bytes']}",
                    f"-artifact_prefix={resolved / 'artifacts' / target / label}{os.sep}",
                    f"-seed={expected_seed}",
                ]
            )
            if (
                set(run)
                != {
                    "target",
                    "command",
                    "exit_code",
                    "artifact_count",
                    "deterministic_seed",
                    "dependency_mode",
                    "cargo_fuzz_invocation",
                    "target_dir",
                    "timed_out",
                    "output_overflow",
                    "descendant_cleanup_required",
                    "captured_output_bytes",
                    "maximum_output_bytes",
                    "private_log",
                    "execution_enforcement",
                    "execution_source_after",
                    "read_only_candidate_unchanged",
                }
                or run.get("target") != target
                or run.get("command") != expected_command
                or run.get("exit_code") != 0
                or run.get("artifact_count") != 0
                or run.get("deterministic_seed") != expected_seed
                or run.get("dependency_mode") != "locked-offline-cargo-wrapper"
                or run.get("cargo_fuzz_invocation") != DIRECT_CARGO_FUZZ_MODE
                or run.get("execution_enforcement") != current_enforcement
                or run.get("target_dir")
                != external_path_binding(resolved / "build-target")
                or run.get("timed_out") is not False
                or run.get("output_overflow") is not False
                or run.get("descendant_cleanup_required") is not False
                or run.get("maximum_output_bytes")
                != policy["maximum_subprocess_output_bytes"]
                or run.get("execution_source_after")
                != expected_execution_source_state(
                    current_candidate["tracked_source"],
                    set(names[: target_index + 1]),
                )
                or run.get("read_only_candidate_unchanged") is not True
            ):
                raise CorpusFailure(f"{target}: invalid {label} minimizer evidence")
            log_path = logs_root / target / f"{label}.log"
            private_log = run.get("private_log")
            if (
                log_path.is_symlink()
                or not log_path.is_file()
                or log_path.stat().st_mode & 0o777 != 0o600
                or not isinstance(private_log, dict)
                or set(private_log) != {"name", "sha256", "size", "mode"}
                or type(run.get("captured_output_bytes")) is not int
                or private_log.get("name") != log_path.name
                or private_log.get("mode") != "0600"
                or type(private_log.get("size")) is not int
                or private_log.get("size") != log_path.stat().st_size
                or private_log.get("sha256") != digest_file(log_path)
                or run.get("captured_output_bytes") != log_path.stat().st_size
                or log_path.stat().st_size > policy["maximum_subprocess_output_bytes"]
            ):
                raise CorpusFailure(f"{target}: invalid {label} private minimizer log")
        state, fixtures = staged_corpus_state(corpus_root / target, target, policy)
        repeat_state, repeat_fixtures = staged_corpus_state(
            equivalence_root / target, target, policy
        )
        if (
            target_report.get("deterministic_equivalence_proved") is not True
            or state != repeat_state
            or state != target_report.get("output")
            or repeat_state != target_report.get("repeat_output")
            or fixtures != repeat_fixtures
        ):
            raise CorpusFailure(f"deterministic second-run proof failed: {target}")
        output_names: dict[str, list[str]] = collections.defaultdict(list)
        for path in sorted((corpus_root / target).iterdir()):
            output_names[digest_file(path)].append(path.name)
        if not set(output_names).issubset(
            {entry["sha256"] for entry in source_entries}
        ):
            raise CorpusFailure(
                f"{target}: staged output is not a source-corpus subset"
            )
        expected_mapping = [
            {
                "old_path": entry["path"],
                "old_sha256": entry["sha256"],
                "classification": entry["classification"],
                "retained": entry["sha256"] in output_names,
                "new_names": sorted(output_names.get(entry["sha256"], [])),
            }
            for entry in source_entries
        ]
        if target_report.get("old_to_new") != expected_mapping:
            raise CorpusFailure(f"{target}: old-to-new digest map is stale or forged")
        verified.append({"target": target, **state, "named_fixtures": fixtures})
    return {
        "schema_version": "cigar.fuzz-corpus-minimization-verification.v1",
        "output_root": str(resolved),
        "source_revision": report.get("source_revision"),
        "source_binding": current_source_binding,
        "policy": expected_policy,
        "campaign": expected_campaign,
        "source_corpus_before": before,
        "source_corpus_after": after,
        "read_only_candidate": current_candidate,
        "execution_source_before": expected_execution_before,
        "execution_source_after": expected_execution_after,
        "success_scratch_absent": True,
        "all_fourteen_targets_snapshotted": True,
        "deterministic_second_run_equivalent": True,
        "target_count": len(verified),
        "targets": verified,
        "status": "passed",
    }


def inventory_command(args: argparse.Namespace) -> None:
    report = external_new_path(args.report, directory=False)
    document, _ = inventory_document()
    write_new_json(report, document)
    print(
        f"wrote content-free inventory {report} "
        f"({document['summary']['classifications']})",
        flush=True,
    )
    if args.require_policy_compliant and not document["policy_compliance"]["passed"]:
        raise CorpusFailure("working corpus exceeds corpus-policy ceilings")


def minimize_command(args: argparse.Namespace) -> None:
    output_root = external_new_path(args.output_dir, directory=True)
    source_binding_before = source_binding_document()
    index_entries = tracked_index_entries()
    candidate_before = candidate_checkout_state(index_entries, require_read_only=True)
    if candidate_before["tracked_source"] != tracked_source_digest(index_entries):
        raise CorpusFailure(
            "candidate tracked-source binding is internally inconsistent"
        )
    inventory, all_entries = inventory_document()
    policy, campaign_targets = load_policy()
    campaign = json.loads(CAMPAIGN_PATH.read_text(encoding="utf-8"))
    campaign["maximum_subprocess_output_bytes"] = policy[
        "maximum_subprocess_output_bytes"
    ]
    campaign["minimization_wall_timeout_seconds"] = policy[
        "minimization_wall_timeout_seconds"
    ]
    requested_targets = args.target or campaign_targets
    unknown = sorted(set(requested_targets) - set(campaign_targets))
    if unknown:
        raise CorpusFailure(f"unknown fuzz targets: {unknown}")
    if len(set(requested_targets)) != len(requested_targets):
        raise CorpusFailure("target list contains duplicates")
    targets = [
        target for target in campaign_targets if target in set(requested_targets)
    ]
    before = {
        target: corpus_state(all_entries[target], present_only=True)
        for target in campaign_targets
    }
    wrapper_directory = output_root / "cargo-wrapper"
    cargo_environment = locked_cargo_environment(wrapper_directory)
    preflight_directory = output_root / "preflight"
    private_mkdir(preflight_directory, exist_ok=False)
    execution_root, execution_source_before, checkout_preflight = (
        create_execution_source_mirror(
            output_root,
            index_entries,
            cargo_environment,
        )
    )
    execution_fuzz_root = execution_root / "fuzz"
    try:
        cargo_fuzz_environment = direct_cargo_fuzz_environment(
            cargo_environment, cargo_wrapper=wrapper_directory / "cargo"
        )
    except HermeticExecutionError as error:
        raise CorpusFailure(
            f"cannot construct direct cargo-fuzz environment: {error}"
        ) from error
    cargo_fuzz_execution = cargo_fuzz_execution_record(
        wrapper_directory / "cargo", source_binding_before
    )
    metadata_command = [
        "cargo",
        "metadata",
        "--manifest-path",
        str(execution_fuzz_root / "Cargo.toml"),
        "--no-deps",
        "--format-version",
        "1",
    ]
    preflight_log = preflight_directory / "cargo-metadata.log"
    try:
        sandboxed_metadata, enforcement = no_network_command(
            private_subprocess_command(metadata_command)
        )
        metadata = run_bounded(
            sandboxed_metadata,
            cwd=execution_root,
            env=cargo_environment,
            log_path=preflight_log,
            timeout_seconds=60,
            maximum_output_bytes=1024 * 1024,
        )
    except (BoundedProcessError, HermeticExecutionError) as error:
        raise CorpusFailure(
            f"bounded Cargo metadata preflight failed: {error}"
        ) from error
    if (
        metadata["exit_code"] != 0
        or metadata["timed_out"]
        or metadata["output_overflow"]
        or metadata["descendant_cleanup_required"]
    ):
        raise CorpusFailure("locked offline fuzz Cargo metadata preflight failed")
    metadata_preflight = {
        "command": redacted_command(metadata_command),
        "exit_code": 0,
        "timed_out": False,
        "output_overflow": False,
        "descendant_cleanup_required": False,
        "captured_output_bytes": metadata["captured_output_bytes"],
        "maximum_output_bytes": metadata["maximum_output_bytes"],
        "execution_enforcement": enforcement,
        "private_log": {
            "name": preflight_log.name,
            "sha256": metadata["log_sha256"],
            "size": metadata["log_size"],
            "mode": "0600",
        },
    }
    if (
        execution_source_state(
            execution_root,
            index_entries,
            expected_artifact_targets=set(),
        )
        != execution_source_before
    ):
        raise CorpusFailure("Cargo metadata mutated the execution source mirror")
    target_reports: list[dict[str, Any]] = []
    completed_artifact_targets: set[str] = set()
    for target in targets:
        print(f"minimizing {target} into external fresh output", flush=True)
        seed = policy["deterministic_minimization_seed_base"] + campaign_targets.index(
            target
        )
        work = output_root / "work" / target / "primary"
        repeat_work = output_root / "work" / target / "repeat"
        create_minimizer_input(
            work, all_entries[target], policy["limits"]["maximum_input_bytes"]
        )
        create_minimizer_input(
            repeat_work,
            all_entries[target],
            policy["limits"]["maximum_input_bytes"],
        )
        engine = run_cmin(
            target,
            work,
            output_root / "artifacts" / target / "primary",
            campaign,
            seed=seed,
            target_dir=output_root / "build-target",
            log_path=output_root / "logs" / target / "primary.log",
            environment=cargo_fuzz_environment,
            execution_root=execution_root,
            execution_fuzz_root=execution_fuzz_root,
        )
        completed_artifact_targets.add(target)
        primary_execution_state = execution_source_state(
            execution_root,
            index_entries,
            expected_artifact_targets=completed_artifact_targets,
        )
        if (
            candidate_checkout_state(index_entries, require_read_only=True)
            != candidate_before
        ):
            raise CorpusFailure("read-only candidate changed after primary cmin")
        engine["execution_source_after"] = primary_execution_state
        engine["read_only_candidate_unchanged"] = True
        repeat_engine = run_cmin(
            target,
            repeat_work,
            output_root / "artifacts" / target / "repeat",
            campaign,
            seed=seed,
            target_dir=output_root / "build-target",
            log_path=output_root / "logs" / target / "repeat.log",
            environment=cargo_fuzz_environment,
            execution_root=execution_root,
            execution_fuzz_root=execution_fuzz_root,
        )
        repeat_execution_state = execution_source_state(
            execution_root,
            index_entries,
            expected_artifact_targets=completed_artifact_targets,
        )
        if repeat_execution_state != primary_execution_state:
            raise CorpusFailure(
                f"execution source state changed across deterministic runs: {target}"
            )
        if (
            candidate_checkout_state(index_entries, require_read_only=True)
            != candidate_before
        ):
            raise CorpusFailure("read-only candidate changed after repeat cmin")
        repeat_engine["execution_source_after"] = repeat_execution_state
        repeat_engine["read_only_candidate_unchanged"] = True
        state, mapping = emit_deterministic_corpus(
            target,
            work,
            output_root / "corpus" / target,
            all_entries[target],
            policy,
        )
        repeat_state, _ = emit_deterministic_corpus(
            target,
            repeat_work,
            output_root / "equivalence" / target,
            all_entries[target],
            policy,
        )
        if state != repeat_state:
            raise CorpusFailure(
                f"deterministic second-run minimization mismatch: {target}"
            )
        target_reports.append(
            {
                "target": target,
                "input": corpus_state(all_entries[target], present_only=False),
                "output": state,
                "engine": engine,
                "repeat_engine": repeat_engine,
                "repeat_output": repeat_state,
                "deterministic_equivalence_proved": True,
                "old_to_new": mapping,
            }
        )
    _, after_entries = inventory_document()
    after = {
        target: corpus_state(after_entries[target], present_only=True)
        for target in campaign_targets
    }
    if before != after:
        raise CorpusFailure(
            "checked-in working corpus changed during minimization; external output was preserved"
        )
    source_binding_after = source_binding_document()
    if source_binding_before != source_binding_after:
        raise CorpusFailure(
            "qualification source, Git state, locks, or toolchain changed during minimization"
        )
    candidate_after = candidate_checkout_state(index_entries, require_read_only=True)
    if candidate_after != candidate_before:
        raise CorpusFailure("read-only candidate changed during minimization")
    execution_source_after = execution_source_state(
        execution_root,
        index_entries,
        expected_artifact_targets=set(targets),
    )
    if (
        execution_source_before["tracked_source"]
        != execution_source_after["tracked_source"]
        or execution_source_after["artifact_file_count"] != 0
        or execution_source_after["unexpected_entry_count"] != 0
    ):
        raise CorpusFailure("execution source mirror changed or retained an artifact")
    removed_scratch = remove_success_scratch(output_root)
    report = {
        "schema_version": "cigar.fuzz-corpus-minimization.v1",
        "created_at": utc_now(),
        "source_revision": inventory["source_revision"],
        "source_binding": source_binding_after,
        "policy": inventory["policy"],
        "campaign": inventory["campaign"],
        "source_working_corpus_unchanged": True,
        "source_corpus_before": before,
        "source_corpus_after": after,
        "all_fourteen_targets_snapshotted": len(before) == 14 and before == after,
        "dependency_mode": "locked-offline-cargo-wrapper",
        "cargo_fuzz_execution": cargo_fuzz_execution,
        "read_only_candidate": {
            "before": candidate_before,
            "after": candidate_after,
            "unchanged": True,
        },
        "execution_source": {
            "construction": "git-checkout-index-closed-regular-file-set",
            "checkout_preflight": checkout_preflight,
            "before": execution_source_before,
            "after": execution_source_after,
            "tracked_source_unchanged": True,
            "candidate_tracked_source_equal": True,
            "compiled_only_from_execution_source": True,
        },
        "success_scratch_cleanup": {
            "removed": removed_scratch,
            "completed": True,
        },
        "execution_enforcement": enforcement,
        "environment_policy": {
            "ambient_environment": "strict-reviewed-allowlist",
            "credentials_proxies_cloud_ci_variables_inherited": False,
            "private_home_and_tmp": True,
        },
        "metadata_preflight": metadata_preflight,
        "targets": target_reports,
    }
    write_new_json(output_root / "minimization-report.json", report)
    verify_minimized_output(
        output_root, require_all_targets=targets == campaign_targets
    )
    print(
        f"wrote minimized corpora and digest map to {output_root}; source corpus unchanged",
        flush=True,
    )


def reconcile_command(args: argparse.Namespace) -> None:
    if not args.apply:
        raise CorpusFailure("reconciliation requires explicit --apply")
    preserved = load_inventory_report(args.inventory_report)
    current, all_entries = inventory_document()
    assert_inventory_unchanged(preserved, current)
    if not current["policy_compliance"]["passed"]:
        raise CorpusFailure(
            "refusing reconciliation while corpus ceilings are exceeded"
        )
    if int(current["summary"].get("artifact_count", -1)) != 0:
        raise CorpusFailure("refusing reconciliation while fuzz artifacts await triage")
    transients, restorations = reconciliation_plan(all_entries)
    if not transients and not restorations:
        raise CorpusFailure("inventory contains no corpus churn to reconcile")
    quarantine = external_new_path(args.quarantine_dir, directory=True)
    quarantine_actions = prepare_quarantine(transients, quarantine)
    prepared = {
        "schema_version": "cigar.fuzz-corpus-reconciliation.v1",
        "status": "prepared-before-source-mutation",
        "created_at": utc_now(),
        "source_revision": current["source_revision"],
        "inventory_report_sha256": digest(
            args.inventory_report.expanduser().resolve().read_bytes(), "sha256"
        ),
        "policy": current["policy"],
        "campaign": current["campaign"],
        "quarantine_actions": quarantine_actions,
        "planned_restorations": [
            {
                "source_path": entry["path"],
                "sha1": entry["sha1"],
                "sha256": entry["sha256"],
                "size": entry["size"],
            }
            for entry in restorations
        ],
    }
    write_new_json(quarantine / "prepared-manifest.json", prepared)
    fsync_directory(quarantine)
    progress_path = quarantine / "source-progress.jsonl"
    source_actions = apply_reconciliation(
        transients, restorations, progress_path=progress_path
    )
    after, _ = inventory_document()
    classifications = after["summary"]["classifications"]
    if (
        classifications.get("transient-corpus", 0) != 0
        or classifications.get("tracked-deletion-recovered-from-index", 0) != 0
        or classifications.get("named-fixture-deletion-recovered-from-index", 0) != 0
    ):
        raise CorpusFailure(
            "post-reconciliation corpus still contains transient or missing tracked entries"
        )
    if after["summary"]["artifact_count"] != 0:
        raise CorpusFailure("post-reconciliation fuzz artifacts remain")
    if not after["policy_compliance"]["passed"]:
        raise CorpusFailure("post-reconciliation corpus exceeds policy ceilings")
    progress_body = progress_path.read_bytes()
    final = {
        **prepared,
        "status": "completed",
        "finished_at": utc_now(),
        "source_actions": source_actions,
        "durable_progress": {
            "path": progress_path.name,
            "sha256": digest(progress_body, "sha256"),
            "line_count": len(progress_body.splitlines()),
            "fsync_after_each_action": True,
        },
        "postcondition": {
            "working_tree_corpus": {
                target["target"]: target["working_tree"] for target in after["targets"]
            },
            "classifications": classifications,
            "artifact_count": after["summary"]["artifact_count"],
            "tracked_deletions": 0,
            "untracked_transients": 0,
        },
    }
    write_new_json(quarantine / "reconciliation-manifest.json", final)
    fsync_directory(quarantine)
    print(
        f"reconciled {len(restorations)} tracked deletions and quarantined "
        f"{len(transients)} transient inputs at {quarantine}",
        flush=True,
    )


def verify_command(args: argparse.Namespace) -> None:
    result = verify_minimized_output(
        args.output_dir, require_all_targets=args.require_all_targets
    )
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)


def application_plan_command(args: argparse.Namespace) -> None:
    """Write a reviewable, digest-bound plan without mutating checked-in corpora."""

    plan_path = external_new_path(args.plan, directory=False)
    verification = verify_minimized_output(args.output_dir, require_all_targets=True)
    current, all_entries = inventory_document()
    if current["summary"]["artifact_count"] != 0:
        raise CorpusFailure("cannot plan corpus application while artifacts remain")
    classifications = current["summary"]["classifications"]
    for classification in (
        "transient-corpus",
        "tracked-deletion-recovered-from-index",
        "named-fixture-deletion-recovered-from-index",
    ):
        if classifications.get(classification, 0) != 0:
            raise CorpusFailure(
                f"cannot plan application while {classification} entries remain"
            )
    _, targets = load_policy()
    current_states = {
        target: corpus_state(all_entries[target], present_only=True)
        for target in targets
    }
    if verification["source_revision"] != current["source_revision"]:
        raise CorpusFailure("staged corpus was minimized from a different Git revision")
    if verification["source_corpus_before"] != current_states:
        raise CorpusFailure("checked-in corpus changed since staged minimization")
    staged_states = {
        item["target"]: {
            key: item[key]
            for key in ("algorithm", "digest", "file_count", "total_bytes")
        }
        for item in verification["targets"]
    }
    output_root = Path(verification["output_root"])
    report_path = output_root / "minimization-report.json"
    document = {
        "schema_version": "cigar.fuzz-corpus-application-plan.v1",
        "created_at": utc_now(),
        "status": "ready-for-human-review-no-source-mutation",
        "source_revision": current["source_revision"],
        "source_binding": verification["source_binding"],
        "policy": verification["policy"],
        "campaign": verification["campaign"],
        "minimization_report": {
            "path": str(report_path),
            "sha256": digest(report_path.read_bytes(), "sha256"),
        },
        "checked_in_corpus_before": current_states,
        "staged_corpus_after": staged_states,
        "operations": [
            {
                "target": target,
                "replace_only": f"fuzz/corpus/{target}",
                "from_directory": str(output_root / "corpus" / target),
                "expected_current": current_states[target],
                "expected_replacement": staged_states[target],
            }
            for target in targets
        ],
        "safety": {
            "application_performed": False,
            "explicit_review_required_before_application": True,
            "exact_campaign_target_set": True,
            "source_snapshot_target_count": len(current_states),
            "deterministic_second_run_equivalent": verification[
                "deterministic_second_run_equivalent"
            ],
            "named_fixtures_verified": True,
            "policy_limits_verified": True,
            "artifact_count": 0,
        },
    }
    write_new_json(plan_path, document)
    print(f"wrote non-mutating digest-bound application plan {plan_path}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory = subparsers.add_parser(
        "inventory", help="classify corpus without mutation"
    )
    inventory.add_argument("--report", type=Path, required=True)
    inventory.add_argument("--require-policy-compliant", action="store_true")
    inventory.set_defaults(function=inventory_command)
    minimize = subparsers.add_parser(
        "minimize", help="coverage-minimize into a fresh external output"
    )
    minimize.add_argument("--output-dir", type=Path, required=True)
    minimize.add_argument("--target", action="append")
    minimize.set_defaults(function=minimize_command)
    reconcile = subparsers.add_parser(
        "reconcile",
        help="restore tracked inputs and quarantine verified transient growth",
    )
    reconcile.add_argument("--inventory-report", type=Path, required=True)
    reconcile.add_argument("--quarantine-dir", type=Path, required=True)
    reconcile.add_argument("--apply", action="store_true")
    reconcile.set_defaults(function=reconcile_command)
    verify = subparsers.add_parser(
        "verify", help="verify staged corpus digests, fixtures, artifacts, and limits"
    )
    verify.add_argument("--output-dir", type=Path, required=True)
    verify.add_argument("--require-all-targets", action="store_true")
    verify.set_defaults(function=verify_command)
    application_plan = subparsers.add_parser(
        "application-plan",
        help="write a digest-bound review plan without changing checked-in corpus files",
    )
    application_plan.add_argument("--output-dir", type=Path, required=True)
    application_plan.add_argument("--plan", type=Path, required=True)
    application_plan.set_defaults(function=application_plan_command)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.function(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CorpusFailure as error:
        print(f"corpus management failed: {error}", file=sys.stderr)
        raise SystemExit(1)
