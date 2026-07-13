#!/usr/bin/env python3
"""Create a deterministic, content-only descriptor for a Git source candidate."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from evidence_workspace import (
    EvidenceWorkspaceError,
    digest_secure_file,
    safe_relative_path,
)
from release_lib import ReleaseError, run_bounded


class SourceDescriptorError(RuntimeError):
    """The release source cannot be described without ambiguity."""


_HEX_DIGEST = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(
    r"(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_MAX_GIT_OUTPUT = 32 * 1024 * 1024
_MAX_INPUTS = 4096
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_BYTES = (1 << 63) - 1
_MAX_STATUS_ENTRIES = 1_000_000


def _git_environment() -> dict[str, str]:
    """Return a fixed environment; deliberately never copy the ambient environment."""

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


def _run_git(root: Path, git: str, arguments: list[str]) -> bytes:
    try:
        result = run_bounded(
            [
                git,
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
            ],
            cwd=root,
            env=_git_environment(),
            timeout=60,
            max_stdout=_MAX_GIT_OUTPUT,
            max_stderr=1024 * 1024,
        )
    except (OSError, subprocess.SubprocessError, ReleaseError) as error:
        raise SourceDescriptorError(f"cannot inspect Git source: {error}") from error
    if result.returncode != 0:
        raise SourceDescriptorError(
            "Git source inspection failed; "
            f"exit={result.returncode} stderr_bytes={len(result.stderr)} "
            f"stderr_sha256={hashlib.sha256(result.stderr).hexdigest()}"
        )
    return result.stdout


def _secure_git_executable(path: Path) -> str:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise SourceDescriptorError(
            f"cannot resolve Git executable: {error}"
        ) from error
    if (
        not resolved.is_absolute()
        or not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or metadata.st_mode & 0o022
    ):
        raise SourceDescriptorError(
            "Git executable must be a non-writable executable regular file"
        )
    return str(resolved)


def _single_ascii(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise SourceDescriptorError(f"Git {label} is not ASCII") from error
    if not _HEX_DIGEST.fullmatch(value):
        raise SourceDescriptorError(f"Git {label} is not a full object identifier")
    return value


def _reject_git_replacement_state(root: Path, git: str) -> None:
    replacement_refs = _run_git(
        root, git, ["for-each-ref", "--format=%(refname)", "refs/replace"]
    )
    if replacement_refs:
        raise SourceDescriptorError("Git replacement refs are forbidden")
    graft_payload = _run_git(root, git, ["rev-parse", "--git-path", "info/grafts"])
    try:
        graft_text = graft_payload.decode("utf-8", errors="strict").strip()
        if not graft_text or "\n" in graft_text or "\r" in graft_text:
            raise ValueError("invalid graft path")
        graft_path = Path(graft_text)
        if not graft_path.is_absolute():
            graft_path = root / graft_path
    except (UnicodeError, ValueError) as error:
        raise SourceDescriptorError(f"Git graft path is invalid: {error}") from error
    if graft_path.is_symlink() or graft_path.exists():
        raise SourceDescriptorError("legacy Git graft state is forbidden")


def _validate_timestamp(value: str) -> None:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise SourceDescriptorError(
            "generated_at must be caller-supplied UTC with YYYY-MM-DDTHH:MM:SSZ form"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise SourceDescriptorError(
            "generated_at is not a real UTC timestamp"
        ) from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise SourceDescriptorError("generated_at is not canonical")


def _archive_input(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"name", "sha256", "bytes"}:
        raise SourceDescriptorError(
            "source_archive must contain exactly name, sha256, and bytes"
        )
    name = value.get("name")
    digest = value.get("sha256")
    size = value.get("bytes")
    if not isinstance(name, str):
        raise SourceDescriptorError("source archive name must be a string")
    parts = safe_relative_path(name, max_depth=1)
    if len(parts) != 1:
        raise SourceDescriptorError("source archive name must be a basename")
    if (
        not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest == "0" * 64
    ):
        raise SourceDescriptorError("source archive SHA-256 is invalid")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or size > _MAX_ARCHIVE_BYTES
    ):
        raise SourceDescriptorError("source archive byte count must be positive")
    return {"name": name, "sha256": digest, "bytes": size}


def _digest_inputs(
    root: Path, paths: Iterable[str], label: str
) -> list[dict[str, object]]:
    requested: list[str] = []
    for index, path in enumerate(paths):
        if index >= _MAX_INPUTS:
            raise SourceDescriptorError(
                f"{label} inputs exceed the {_MAX_INPUTS}-path limit"
            )
        requested.append(path)
    if not requested:
        raise SourceDescriptorError(
            f"{label} inputs must contain between 1 and {_MAX_INPUTS} paths"
        )
    aliases: set[str] = set()
    records: list[dict[str, object]] = []
    for relative in requested:
        try:
            parts = safe_relative_path(relative)
        except EvidenceWorkspaceError as error:
            raise SourceDescriptorError(
                f"invalid {label} input path: {error}"
            ) from error
        portable = unicodedata.normalize("NFC", relative).casefold()
        if portable in aliases:
            raise SourceDescriptorError(f"duplicate portable {label} input: {relative}")
        aliases.add(portable)
        candidate = root.joinpath(*parts)
        try:
            digest = digest_secure_file(candidate, max_bytes=_MAX_INPUT_BYTES)
        except EvidenceWorkspaceError as error:
            raise SourceDescriptorError(
                f"cannot bind {label} input {relative}: {error}"
            ) from error
        records.append(
            {"path": relative, "sha256": digest.sha256, "bytes": digest.bytes}
        )
    records.sort(key=lambda record: str(record["path"]).encode("utf-8"))
    return records


def _require_committed_inputs(
    root: Path, git: str, records: list[dict[str, object]], label: str
) -> None:
    """Require every bound policy/tool path to be a regular blob in HEAD."""

    paths = [str(record["path"]) for record in records]
    index = 0
    while index < len(paths):
        chunk: list[str] = []
        argument_bytes = 0
        while index < len(paths):
            path = paths[index]
            encoded_bytes = len(path.encode("utf-8")) + 1
            if chunk and argument_bytes + encoded_bytes > 64 * 1024:
                break
            chunk.append(path)
            argument_bytes += encoded_bytes
            index += 1
        payload = _run_git(
            root,
            git,
            ["ls-tree", "-z", "--full-tree", "HEAD", "--", *chunk],
        )
        found: set[str] = set()
        for raw_record in payload.split(b"\0"):
            if not raw_record:
                continue
            try:
                metadata, raw_path = raw_record.split(b"\t", 1)
                mode, kind, _object_id = metadata.decode(
                    "ascii", errors="strict"
                ).split(" ", 2)
                path = raw_path.decode("utf-8", errors="strict")
            except (UnicodeError, ValueError) as error:
                raise SourceDescriptorError(
                    f"Git returned an invalid {label} tree record"
                ) from error
            if mode not in {"100644", "100755"} or kind != "blob":
                raise SourceDescriptorError(
                    f"{label} input is not a committed regular blob: {path}"
                )
            if path in found:
                raise SourceDescriptorError(
                    f"Git returned a duplicate {label} tree path: {path}"
                )
            found.add(path)
        if found != set(chunk):
            missing = sorted(set(chunk) - found, key=lambda path: path.encode("utf-8"))
            raise SourceDescriptorError(
                f"{label} inputs are not committed regular blobs: {missing}"
            )


def _validate_digest_records(value: object, label: str) -> None:
    if not isinstance(value, list) or not value or len(value) > _MAX_INPUTS:
        raise SourceDescriptorError(f"{label} must be a bounded non-empty list")
    paths: list[str] = []
    aliases: set[str] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            raise SourceDescriptorError(f"{label} record has an unexpected shape")
        path = record.get("path")
        digest = record.get("sha256")
        size = record.get("bytes")
        if not isinstance(path, str):
            raise SourceDescriptorError(f"{label} path must be a string")
        try:
            safe_relative_path(path)
        except EvidenceWorkspaceError as error:
            raise SourceDescriptorError(f"invalid {label} path: {error}") from error
        alias = unicodedata.normalize("NFC", path).casefold()
        if alias in aliases:
            raise SourceDescriptorError(f"duplicate portable {label} path: {path}")
        aliases.add(alias)
        paths.append(path)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise SourceDescriptorError(f"{label} SHA-256 is invalid")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > _MAX_INPUT_BYTES
        ):
            raise SourceDescriptorError(f"{label} byte count is invalid")
    if paths != sorted(paths, key=lambda path: path.encode("utf-8")):
        raise SourceDescriptorError(f"{label} paths are not canonically ordered")


def validate_source_descriptor(document: object) -> None:
    """Validate the complete in-memory descriptor without third-party packages."""

    required = {
        "schema_version",
        "generated_at",
        "git",
        "source_archive",
        "policy_inputs",
        "tool_inputs",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise SourceDescriptorError("source descriptor has an unexpected shape")
    if document.get("schema_version") != "cigar.source-descriptor.v1":
        raise SourceDescriptorError("source descriptor schema identity is invalid")
    _validate_timestamp(document.get("generated_at"))
    git = document.get("git")
    git_keys = {
        "revision",
        "tree",
        "committed",
        "clean",
        "status_entry_count",
        "status_sha256",
    }
    if not isinstance(git, dict) or set(git) != git_keys:
        raise SourceDescriptorError("source descriptor Git binding is invalid")
    if (
        not isinstance(git.get("revision"), str)
        or _HEX_DIGEST.fullmatch(git["revision"]) is None
    ):
        raise SourceDescriptorError("source descriptor revision is invalid")
    if (
        not isinstance(git.get("tree"), str)
        or _HEX_DIGEST.fullmatch(git["tree"]) is None
    ):
        raise SourceDescriptorError("source descriptor tree is invalid")
    if git.get("committed") is not True or not isinstance(git.get("clean"), bool):
        raise SourceDescriptorError("source descriptor source-state flags are invalid")
    status_count = git.get("status_entry_count")
    if (
        isinstance(status_count, bool)
        or not isinstance(status_count, int)
        or not 0 <= status_count <= _MAX_STATUS_ENTRIES
    ):
        raise SourceDescriptorError("source descriptor status count is invalid")
    status_digest = git.get("status_sha256")
    if not isinstance(status_digest, str) or _SHA256.fullmatch(status_digest) is None:
        raise SourceDescriptorError("source descriptor status digest is invalid")
    if git["clean"] != (status_count == 0):
        raise SourceDescriptorError(
            "source descriptor clean flag contradicts status count"
        )
    if git["clean"] and status_digest != hashlib.sha256(b"").hexdigest():
        raise SourceDescriptorError("clean source has a non-empty status digest")
    try:
        _archive_input(document["source_archive"])
    except (EvidenceWorkspaceError, SourceDescriptorError) as error:
        raise SourceDescriptorError(
            f"source archive binding is invalid: {error}"
        ) from error
    _validate_digest_records(document.get("policy_inputs"), "policy input")
    _validate_digest_records(document.get("tool_inputs"), "tool input")


def build_source_descriptor(
    *,
    repository_root: Path,
    generated_at: str,
    source_archive: Mapping[str, object],
    policy_inputs: Iterable[str],
    tool_inputs: Iterable[str],
    require_clean: bool = True,
    git_executable: Path | None = None,
) -> dict[str, Any]:
    """Bind a source archive and reviewed inputs to one full Git commit/tree.

    ``generated_at`` and the source archive digest are explicit caller inputs.
    The descriptor never reads environment variables, usernames, hostnames, Git
    remotes, or dirty-path names.
    """

    _validate_timestamp(generated_at)
    if not isinstance(require_clean, bool):
        raise SourceDescriptorError("require_clean must be boolean")
    root = repository_root
    if not root.is_absolute():
        raise SourceDescriptorError("repository root must be absolute")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise SourceDescriptorError(
            f"cannot resolve repository root: {error}"
        ) from error
    if root.is_symlink() or not root.is_dir():
        raise SourceDescriptorError("repository root must be a real directory")
    if git_executable is None:
        discovered = shutil.which("git", path=os.defpath)
        if discovered is None:
            raise SourceDescriptorError("Git executable is unavailable")
        git = _secure_git_executable(Path(discovered))
    else:
        git = _secure_git_executable(git_executable)
    _reject_git_replacement_state(root, git)
    revision = _single_ascii(
        _run_git(root, git, ["rev-parse", "--verify", "HEAD^{commit}"]), "commit"
    )
    tree = _single_ascii(
        _run_git(root, git, ["rev-parse", "--verify", "HEAD^{tree}"]), "tree"
    )
    top_level_payload = _run_git(root, git, ["rev-parse", "--show-toplevel"])
    try:
        top_level = Path(top_level_payload.decode("utf-8", errors="strict").strip())
        top_level = top_level.resolve(strict=True)
    except (UnicodeError, OSError) as error:
        raise SourceDescriptorError(
            f"Git top-level path is invalid: {error}"
        ) from error
    if top_level != root:
        raise SourceDescriptorError(
            "repository_root must be the exact Git worktree top level"
        )
    status = _run_git(
        root,
        git,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    entries = [entry for entry in status.split(b"\0") if entry]
    if len(entries) > _MAX_STATUS_ENTRIES:
        raise SourceDescriptorError("Git status entry-count limit exceeded")
    clean = not entries
    if require_clean and not clean:
        raise SourceDescriptorError("source descriptor requires a clean Git worktree")
    try:
        archive = _archive_input(source_archive)
    except EvidenceWorkspaceError as error:
        raise SourceDescriptorError(f"invalid source archive input: {error}") from error
    policies = _digest_inputs(root, policy_inputs, "policy")
    tools = _digest_inputs(root, tool_inputs, "tool")
    _require_committed_inputs(root, git, policies, "policy")
    _require_committed_inputs(root, git, tools, "tool")
    finished_revision = _single_ascii(
        _run_git(root, git, ["rev-parse", "--verify", "HEAD^{commit}"]), "commit"
    )
    finished_tree = _single_ascii(
        _run_git(root, git, ["rev-parse", "--verify", "HEAD^{tree}"]), "tree"
    )
    finished_status = _run_git(
        root,
        git,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    if (revision, tree, status) != (
        finished_revision,
        finished_tree,
        finished_status,
    ):
        raise SourceDescriptorError("Git source changed while building its descriptor")
    descriptor = {
        "schema_version": "cigar.source-descriptor.v1",
        "generated_at": generated_at,
        "git": {
            "revision": revision,
            "tree": tree,
            "committed": True,
            "clean": clean,
            "status_entry_count": len(entries),
            "status_sha256": hashlib.sha256(status).hexdigest(),
        },
        "source_archive": archive,
        "policy_inputs": policies,
        "tool_inputs": tools,
    }
    validate_source_descriptor(descriptor)
    return descriptor
