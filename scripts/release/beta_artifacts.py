#!/usr/bin/env python3
"""Freeze source, build, or verify the unsigned, nonqualifying CIGAR beta."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unicodedata
import urllib.parse
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import beta_profile
from evidence_workspace import EvidenceLimits, EvidenceWorkspace, EvidenceWorkspaceError
from generate_license_inventory import _status as license_policy_status
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    load_json_bytes,
    matches,
    normalized_mode,
    resolve_beneath,
    run_bounded,
    safe_relative_path,
    scan_payload,
    sha256_bytes,
    sha256_file,
)
from source_descriptor import (
    SourceDescriptorError,
    validate_source_descriptor,
)
from verify_package import (
    _TEXT_NAMES,
    _TEXT_SUFFIXES,
    _validate_checksum_manifest,
)


class BetaArtifactError(ReleaseError):
    """The beta artifact set is unsafe, incomplete, or outside the profile."""


MAX_SOURCE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 60 * 1024 * 1024
MAX_GIT_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_CARGO_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_CRATE_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_CRATE_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_VENDOR_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_CRATE_ENTRIES = 20_000

ARTIFACT_DIRECTORY = "artifacts"
CHECKSUM_PATH = "checksums/SHA256SUMS"
SOURCE_DESCRIPTOR_PATH = "evidence/source-descriptor.json"
SBOM_PATH = "evidence/sbom.cdx.json"
SPDX_PATH = "evidence/sbom.spdx.json"
PROVENANCE_PATH = "evidence/provenance.json"
BUILD_MANIFEST_PATH = "evidence/build-manifest.json"
VERIFICATION_PATH = "evidence/verification.json"
SOURCE_ARCHIVE_PATH = f"{ARTIFACT_DIRECTORY}/cigar-{beta_profile.VERSION}-source.tar.gz"
SOURCE_FREEZE_PATHS = frozenset({SOURCE_ARCHIVE_PATH, SOURCE_DESCRIPTOR_PATH})

SOURCE_TOOL_INPUTS = (
    "scripts/release/beta_artifacts.py",
    "scripts/release/generate_beta_licenses.py",
    "scripts/release/beta_profile.py",
    "scripts/release/beta_release.py",
    "scripts/release/evidence_workspace.py",
    "scripts/release/generate_license_inventory.py",
    "scripts/release/generate_sbom.py",
    "scripts/release/release_lib.py",
    "scripts/release/signatures.py",
    "scripts/release/source_descriptor.py",
    "scripts/release/verify_package.py",
)
SOURCE_POLICY_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/cigar-canon/Cargo.toml",
    "crates/cigar-cli/Cargo.toml",
    "crates/cigar-cli/assets/cigar-help-beta.txt",
    "packaging/beta/artifact-matrix.v1.json",
    "packaging/beta/capability-policy.v1.json",
    "packaging/beta/cargo-resolution.v1.json",
    "packaging/beta/build-projection/Cargo.lock",
    "packaging/beta/build-projection/Cargo.toml",
    "packaging/beta/build-projection/cigar-canon.Cargo.toml",
    "packaging/beta/build-projection/cigar-cli.Cargo.toml",
    "packaging/beta/build-projection/projection.v1.json",
    "packaging/beta/contracts/cigar-binary-archive.v1.json",
    "packaging/beta/contracts/conformance-archive.v1.json",
    "packaging/beta/contracts/docs-archive.v1.json",
    "packaging/beta/contracts/license-archive.v1.json",
    "packaging/beta/contracts/schemas-archive.v1.json",
    "packaging/beta/product-version.v1.json",
    "packaging/beta/qualification-policy.v1.json",
    "packaging/beta/release-profile.v1.json",
    "packaging/beta/source-archives.v1.json",
    "packaging/beta/contracts/source-archive.v1.json",
    "packaging/licenses/beta-third-party-inventory.v1.json",
    "packaging/licenses/beta-third-party-license-manifest.v1.json",
    "packaging/licenses/rust/COPYRIGHT-library.html",
    "packaging/licenses/third-party-policy.v1.json",
    "packaging/schemas/source-descriptor.v1.schema.json",
    *beta_profile.SCHEMA_PATHS,
)

EXPECTED_VERSION_KEYS = {
    "schema_version",
    "version",
    "source_revision",
    "build_profile",
    "release_profile",
    "channel",
    "production_ready",
    "qualification_status",
    "required_target_triple",
    "required_host_profile",
    "required_distribution",
    "required_distribution_version",
    "required_libc",
    "required_libc_version",
    "target_os",
    "target_arch",
    "target_env",
    "capability_profile",
    "enabled_features",
}

FORBIDDEN_BETA_PACKAGES = {
    "cigar-api",
    "cigar-catalog",
    "cigar-code-intel",
    "cigar-compiler",
    "cigar-crypto",
    "cigar-daemon",
    "cigar-effects",
    "cigar-mcp",
    "cigar-policy",
    "cigar-protocol",
    "cigar-replay",
    "cigar-retrieval",
    "cigar-space",
    "cigar-store",
}
REVIEWED_BETA_WORKSPACE_PACKAGES = {"cigar-cli", "cigar-canon"}
REVIEWED_BETA_WORKSPACE_MANIFESTS = {
    "cigar-cli": "crates/cigar-cli/Cargo.toml",
    "cigar-canon": "crates/cigar-canon/Cargo.toml",
}
REQUIRED_PROVENANCE_TOOLS = {
    "cargo",
    "git",
    "linker",
    "python",
    "python-gzip",
    "python-tarfile",
    "python-zlib",
    "rustc",
}
OPTIONAL_PROVENANCE_TOOLS = {"rustup"}


@dataclass(frozen=True)
class GitSnapshot:
    revision: str
    tree: str
    source_date_epoch: int
    generated_at: str

    def source_identity(self) -> dict[str, object]:
        return {
            "revision": self.revision,
            "tree": self.tree,
            "committed": True,
            "clean": True,
        }


@dataclass(frozen=True)
class CommittedEntry:
    path: str
    payload: bytes
    mode: int
    kind: str = "file"


@dataclass(frozen=True)
class BinaryBuild:
    payload: bytes
    version_document: dict[str, object]
    help_sha256: str
    components: tuple[dict[str, object], ...]
    dependencies: tuple[dict[str, object], ...]
    tools: tuple[dict[str, object], ...]
    dependency_materials: tuple[dict[str, object], ...]
    toolchain_materials: tuple[dict[str, object], ...]


BinaryBuilder = Callable[[Path, Path, GitSnapshot, bytes], BinaryBuild]


@dataclass(frozen=True)
class VerifiedSourceFreeze:
    snapshot: GitSnapshot
    committed: Mapping[str, CommittedEntry]
    archive_payload: bytes
    descriptor_payload: bytes
    descriptor: Mapping[str, object]
    source_record: Mapping[str, object]
    report: Mapping[str, object]


def _fixed_environment() -> dict[str, str]:
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


def _run_checked(
    arguments: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    maximum: int,
    label: str,
) -> bytes:
    try:
        result = run_bounded(
            arguments,
            cwd=cwd,
            env=env,
            timeout=timeout,
            max_stdout=maximum,
            max_stderr=maximum,
        )
    except (OSError, subprocess.SubprocessError, ReleaseError) as error:
        raise BetaArtifactError(f"{label} could not run safely: {error}") from error
    if result.returncode != 0:
        raise BetaArtifactError(
            f"{label} failed; exit={result.returncode} "
            f"stdout_bytes={len(result.stdout)} stdout_sha256={sha256_bytes(result.stdout)} "
            f"stderr_bytes={len(result.stderr)} stderr_sha256={sha256_bytes(result.stderr)}"
        )
    return result.stdout


def _secure_executable(value: Path | None, name: str) -> Path:
    supplied = value
    if supplied is None:
        discovered = shutil.which(name)
        if discovered is None:
            raise BetaArtifactError(f"required executable is unavailable: {name}")
        supplied = Path(discovered)
    if not supplied.is_absolute():
        raise BetaArtifactError(f"{name} executable path must be absolute")
    try:
        resolved = supplied.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise BetaArtifactError(f"cannot resolve {name} executable: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(supplied, os.X_OK)
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BetaArtifactError(
            f"{name} must resolve to a non-group/world-writable executable"
        )
    return supplied if name in {"cargo", "rustc"} else resolved


def _stage_executable(source: Path, name: str, directory: Path) -> Path:
    resolved = source.resolve(strict=True)
    before = resolved.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) & 0o022
        or not 0 < before.st_size <= 64 * 1024 * 1024
    ):
        raise BetaArtifactError(f"{name} executable backing file is unsafe")
    payload = resolved.read_bytes()
    after = resolved.stat(follow_symlinks=False)
    if (
        any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        )
        or len(payload) != before.st_size
    ):
        raise BetaArtifactError(f"{name} executable backing file changed while read")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = directory / name
    _write_private(destination, payload)
    os.chmod(destination, 0o500)
    return destination


def _actual_rust_tool(source: Path, name: str, root: Path) -> Path:
    resolved = source.resolve(strict=True)
    if resolved.name != "rustup":
        return resolved
    environment = _fixed_environment()
    rustup_home_raw = os.environ.get("RUSTUP_HOME")
    rustup_home = (
        Path(rustup_home_raw).expanduser()
        if rustup_home_raw
        else Path.home() / ".rustup"
    ).resolve(strict=True)
    environment["RUSTUP_HOME"] = str(rustup_home)
    output = _run_checked(
        [str(resolved), "which", name],
        cwd=root,
        env=environment,
        timeout=30,
        maximum=64 * 1024,
        label=f"rustup selected {name}",
    )
    try:
        selected_text = output.decode("utf-8", errors="strict").strip()
    except UnicodeError as error:
        raise BetaArtifactError(f"rustup {name} path is not UTF-8") from error
    selected = Path(selected_text)
    if not selected.is_absolute() or "\n" in selected_text or "\r" in selected_text:
        raise BetaArtifactError(f"rustup {name} path is invalid")
    actual = selected.resolve(strict=True)
    metadata = actual.stat(follow_symlinks=False)
    if (
        actual == resolved
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(actual, os.X_OK)
    ):
        raise BetaArtifactError(f"rustup selected an unsafe {name} executable")
    return actual


def _git_bytes(
    root: Path,
    git: Path,
    arguments: list[str],
    *,
    maximum: int = MAX_JSON_BYTES,
) -> bytes:
    return _run_checked(
        [
            str(git),
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
        env=_fixed_environment(),
        timeout=120,
        maximum=maximum,
        label="Git source inspection",
    )


def _ascii_line(payload: bytes, pattern: str, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise BetaArtifactError(f"{label} is not ASCII") from error
    if re.fullmatch(pattern, value) is None:
        raise BetaArtifactError(f"{label} is invalid")
    return value


def inspect_clean_snapshot(root: Path, git: Path | None = None) -> GitSnapshot:
    root = root.resolve(strict=True)
    selected_git = _secure_executable(git, "git")
    top = _git_bytes(root, selected_git, ["rev-parse", "--show-toplevel"])
    try:
        top_level = Path(top.decode("utf-8", errors="strict").strip()).resolve(
            strict=True
        )
    except (UnicodeError, OSError) as error:
        raise BetaArtifactError(f"Git top-level is invalid: {error}") from error
    if top_level != root:
        raise BetaArtifactError("repository root must be the exact Git worktree root")
    replacement_refs = _git_bytes(
        root,
        selected_git,
        ["for-each-ref", "--format=%(refname)", "refs/replace"],
    )
    if replacement_refs:
        raise BetaArtifactError("Git replacement refs are forbidden for beta releases")
    graft_path_payload = _git_bytes(
        root, selected_git, ["rev-parse", "--git-path", "info/grafts"]
    )
    try:
        graft_text = graft_path_payload.decode("utf-8", errors="strict").strip()
        if not graft_text or "\n" in graft_text or "\r" in graft_text:
            raise ValueError("invalid graft path")
        graft_path = Path(graft_text)
        if not graft_path.is_absolute():
            graft_path = root / graft_path
    except (UnicodeError, ValueError) as error:
        raise BetaArtifactError(f"Git graft path is invalid: {error}") from error
    if graft_path.is_symlink() or graft_path.exists():
        raise BetaArtifactError("legacy Git graft state is forbidden for beta releases")
    revision = _ascii_line(
        _git_bytes(root, selected_git, ["rev-parse", "--verify", "HEAD^{commit}"]),
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
        "Git revision",
    )
    tree = _ascii_line(
        _git_bytes(root, selected_git, ["rev-parse", "--verify", "HEAD^{tree}"]),
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
        "Git tree",
    )
    commit_payload = _git_bytes(
        root, selected_git, ["cat-file", "commit", revision], maximum=64 * 1024 * 1024
    )
    tree_payload = _git_bytes(
        root, selected_git, ["cat-file", "tree", tree], maximum=MAX_GIT_ARCHIVE_BYTES
    )
    if _git_object_digest("commit", commit_payload, len(revision)) != revision:
        raise BetaArtifactError("Git commit bytes do not match the claimed object id")
    if _git_object_digest("tree", tree_payload, len(tree)) != tree:
        raise BetaArtifactError("Git tree bytes do not match the claimed object id")
    if not commit_payload.startswith(f"tree {tree}\n".encode("ascii")):
        raise BetaArtifactError("Git commit does not bind the claimed root tree")
    status = _git_bytes(
        root,
        selected_git,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        maximum=64 * 1024 * 1024,
    )
    if status:
        entries = len([record for record in status.split(b"\0") if record])
        raise BetaArtifactError(
            f"beta artifacts require a clean Git worktree; status_entries={entries} "
            f"status_sha256={sha256_bytes(status)}"
        )
    epoch_text = _ascii_line(
        _git_bytes(root, selected_git, ["show", "-s", "--format=%ct", "HEAD"]),
        r"[0-9]{1,10}",
        "Git commit timestamp",
    )
    epoch = int(epoch_text)
    if not 0 <= epoch <= 4_294_967_295:
        raise BetaArtifactError("Git commit timestamp is outside the release range")
    generated_at = dt.datetime.fromtimestamp(epoch, tz=dt.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return GitSnapshot(revision, tree, epoch, generated_at)


def _require_unchanged_snapshot(root: Path, expected: GitSnapshot, git: Path) -> None:
    observed = inspect_clean_snapshot(root, git)
    if observed != expected:
        raise BetaArtifactError("Git source changed during beta artifact assembly")


def _git_with_input(
    root: Path,
    git: Path,
    arguments: Sequence[str],
    input_payload: bytes,
    *,
    maximum: int,
    label: str,
) -> bytes:
    command = [
        str(git),
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
        result = run_bounded(
            command,
            cwd=root,
            env=_fixed_environment(),
            timeout=120,
            max_stdout=maximum,
            max_stderr=MAX_JSON_BYTES,
            input_payload=input_payload,
            max_stdin=16 * 1024 * 1024,
        )
    except (OSError, subprocess.SubprocessError, ReleaseError) as error:
        raise BetaArtifactError(f"{label} could not run safely: {error}") from error
    if result.returncode != 0:
        raise BetaArtifactError(
            f"{label} failed; exit={result.returncode} "
            f"stdout_bytes={len(result.stdout)} stdout_sha256={sha256_bytes(result.stdout)} "
            f"stderr_bytes={len(result.stderr)} stderr_sha256={sha256_bytes(result.stderr)}"
        )
    return result.stdout


def _git_object_digest(kind: str, payload: bytes, object_id_length: int) -> str:
    if kind not in {"blob", "commit", "tree"}:
        raise BetaArtifactError("Git object uses an unsupported type")
    framed = (
        kind.encode("ascii")
        + b" "
        + str(len(payload)).encode("ascii")
        + b"\0"
        + payload
    )
    if object_id_length == 40:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    if object_id_length == 64:
        return hashlib.sha256(framed).hexdigest()
    raise BetaArtifactError("Git blob uses an unsupported object format")


def _git_blob_digest(payload: bytes, object_id_length: int) -> str:
    return _git_object_digest("blob", payload, object_id_length)


def read_committed_tree(
    root: Path, snapshot: GitSnapshot, git: Path | None = None
) -> dict[str, CommittedEntry]:
    selected_git = _secure_executable(git, "git")
    tree_bytes = _git_bytes(
        root,
        selected_git,
        ["ls-tree", "-rz", "--full-tree", snapshot.tree],
        maximum=64 * 1024 * 1024,
    )
    declarations: list[tuple[str, str, int]] = []
    aliases: dict[str, str] = {}
    records = [record for record in tree_bytes.split(b"\0") if record]
    if not records or len(records) > 100_000:
        raise BetaArtifactError("committed Git tree has an invalid entry count")
    for record in records:
        try:
            header, raw_name = record.split(b"\t", 1)
            raw_mode, raw_kind, raw_object = header.split(b" ", 2)
            name = safe_relative_path(raw_name.decode("utf-8", errors="strict"))
            mode_text = raw_mode.decode("ascii", errors="strict")
            kind = raw_kind.decode("ascii", errors="strict")
            object_id = raw_object.decode("ascii", errors="strict")
        except (ValueError, UnicodeError, ReleaseError) as error:
            raise BetaArtifactError(
                f"committed Git tree entry is unsafe: {error}"
            ) from error
        if (
            mode_text not in {"100644", "100755"}
            or kind != "blob"
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id) is None
        ):
            raise BetaArtifactError(
                f"committed Git tree contains a link, submodule, or special entry: {name}"
            )
        portable = unicodedata.normalize("NFC", name).casefold()
        previous = aliases.get(portable)
        if previous is not None:
            raise BetaArtifactError(
                f"committed paths collide portably: {previous} and {name}"
            )
        aliases[portable] = name
        declarations.append(
            (name, object_id, 0o755 if mode_text == "100755" else 0o644)
        )

    object_ids = sorted({object_id for _, object_id, _ in declarations})
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in object_ids)
    checks = _git_with_input(
        root,
        selected_git,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        request,
        maximum=max(1024, len(object_ids) * 160),
        label="Git blob size inspection",
    )
    sizes: dict[str, int] = {}
    total = 0
    check_lines = checks.splitlines()
    if len(check_lines) != len(object_ids):
        raise BetaArtifactError("Git blob size inventory is incomplete")
    for expected_object, line in zip(object_ids, check_lines, strict=True):
        try:
            observed_raw, kind_raw, size_raw = line.split(b" ", 2)
            observed = observed_raw.decode("ascii", errors="strict")
            kind = kind_raw.decode("ascii", errors="strict")
            size_text = size_raw.decode("ascii", errors="strict")
        except (ValueError, UnicodeError) as error:
            raise BetaArtifactError("Git blob size record is invalid") from error
        if (
            observed != expected_object
            or kind != "blob"
            or re.fullmatch(r"[0-9]+", size_text) is None
        ):
            raise BetaArtifactError("Git blob size identity is invalid")
        size = int(size_text)
        if size > 64 * 1024 * 1024:
            raise BetaArtifactError("committed Git blob exceeds the per-file limit")
        total += size
        if total > MAX_GIT_ARCHIVE_BYTES:
            raise BetaArtifactError("committed tree exceeds the source byte limit")
        sizes[observed] = size

    batch = _git_with_input(
        root,
        selected_git,
        ["cat-file", "--batch"],
        request,
        maximum=total + len(object_ids) * 192,
        label="Git blob object read",
    )
    cursor = 0
    blobs: dict[str, bytes] = {}
    for object_id in object_ids:
        newline = batch.find(b"\n", cursor)
        if newline < 0:
            raise BetaArtifactError("Git blob batch header is truncated")
        header = batch[cursor:newline]
        expected_header = f"{object_id} blob {sizes[object_id]}".encode("ascii")
        if header != expected_header:
            raise BetaArtifactError("Git blob batch header is substituted")
        start = newline + 1
        end = start + sizes[object_id]
        if end >= len(batch) or batch[end : end + 1] != b"\n":
            raise BetaArtifactError("Git blob batch payload is truncated")
        payload = batch[start:end]
        if _git_blob_digest(payload, len(object_id)) != object_id:
            raise BetaArtifactError("Git blob content does not match its object id")
        blobs[object_id] = payload
        cursor = end + 1
    if cursor != len(batch):
        raise BetaArtifactError("Git blob batch contains trailing data")
    entries = {
        name: CommittedEntry(name, blobs[object_id], mode)
        for name, object_id, mode in declarations
    }
    if not entries:
        raise BetaArtifactError("committed Git tree is empty")
    return entries


def _project_beta_source(
    committed: Mapping[str, CommittedEntry],
) -> dict[str, CommittedEntry]:
    """Construct the closed, buildable beta source projection from committed blobs."""

    projection_path = "packaging/beta/build-projection/projection.v1.json"
    projection_entry = committed.get(projection_path)
    if projection_entry is None or projection_entry.kind != "file":
        raise BetaArtifactError("committed beta build projection manifest is missing")
    projection_document = load_json_bytes(
        projection_entry.payload, "committed beta build projection manifest"
    )
    if (
        projection_entry.payload != canonical_json_bytes(projection_document)
        or projection_document != beta_profile.expected_build_projection()
    ):
        raise BetaArtifactError(
            "committed beta build projection manifest is substituted"
        )
    projected: dict[str, CommittedEntry] = {}
    aliases: dict[str, str] = {}

    def add(path: str, entry: CommittedEntry) -> None:
        normalized = safe_relative_path(path)
        alias = unicodedata.normalize("NFC", normalized).casefold()
        previous = aliases.get(alias)
        if normalized in projected or previous is not None:
            raise BetaArtifactError(
                f"beta source projection path collides: {previous or normalized} and {normalized}"
            )
        aliases[alias] = normalized
        projected[normalized] = CommittedEntry(
            normalized, entry.payload, normalized_mode(normalized)
        )

    for path in sorted(committed, key=lambda value: value.encode("utf-8")):
        if not matches(path, beta_profile.BETA_PROJECTION_INCLUDE):
            continue
        entry = committed[path]
        if entry.kind != "file":
            raise BetaArtifactError(f"beta projection selected a non-file: {path}")
        add(path, entry)
    for source, destination in beta_profile.BETA_PROJECTION_REMAP.items():
        entry = committed.get(source)
        if entry is None or entry.kind != "file":
            raise BetaArtifactError(
                f"beta projection remap source is missing: {source}"
            )
        add(destination, entry)
    required = {
        "Cargo.toml",
        "Cargo.lock",
        "crates/cigar-cli/Cargo.toml",
        "crates/cigar-cli/src/main.rs",
        "crates/cigar-canon/Cargo.toml",
        "crates/cigar-canon/src/lib.rs",
        projection_path,
    }
    if not required.issubset(projected):
        raise BetaArtifactError(
            f"beta source projection is incomplete: {sorted(required - set(projected))}"
        )
    forbidden_prefixes = (
        "adapters/",
        "connectors/",
        "sdk/",
        "vendor/",
    )
    forbidden_cli = {
        "crates/cigar-cli/src/administration.rs",
        "crates/cigar-cli/src/claude_plugin.rs",
        "crates/cigar-cli/src/client.rs",
        "crates/cigar-cli/src/configuration.rs",
    }
    if (
        any(path.startswith(forbidden_prefixes) for path in projected)
        or set(projected) & forbidden_cli
    ):
        raise BetaArtifactError("beta source projection includes a full-only surface")
    return projected


def _materialize_committed_tree(
    destination: Path, committed: Mapping[str, CommittedEntry]
) -> str:
    if destination.exists() or destination.is_symlink():
        raise BetaArtifactError("committed source stage already exists")
    destination.mkdir(mode=0o700)
    directories = {destination}
    for name in sorted(committed, key=lambda value: value.encode("utf-8")):
        entry = committed[name]
        if entry.kind != "file" or entry.mode not in {0o644, 0o755}:
            raise BetaArtifactError(
                f"committed source stage rejects non-regular input: {name}"
            )
        path = destination.joinpath(*safe_relative_path(name).split("/"))
        current = path.parent
        while current != destination:
            directories.add(current)
            current = current.parent
        _write_private(path, entry.payload)
        os.chmod(path, 0o555 if entry.mode == 0o755 else 0o444)
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        os.chmod(directory, 0o555)
    identity = _payload_tree(committed.values())
    if _verify_materialized_tree(destination, committed) != identity:
        raise BetaArtifactError("committed source stage identity is unstable")
    return identity


def _verify_materialized_tree(
    source: Path, committed: Mapping[str, CommittedEntry]
) -> str:
    try:
        root_metadata = source.stat(follow_symlinks=False)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot inspect committed source stage: {error}"
        ) from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o555
    ):
        raise BetaArtifactError("committed source stage root is writable or unsafe")
    observed: set[str] = set()
    for directory, directory_names, file_names in os.walk(source, followlinks=False):
        directory_path = Path(directory)
        directory_names.sort()
        file_names.sort()
        for child_name in directory_names:
            child = directory_path / child_name
            metadata = child.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o555
            ):
                raise BetaArtifactError(
                    "committed source stage contains a writable/link/special directory"
                )
        for child_name in file_names:
            child = directory_path / child_name
            relative = child.relative_to(source).as_posix()
            safe_relative_path(relative)
            expected = committed.get(relative)
            before = child.stat(follow_symlinks=False)
            expected_mode = (
                0o555 if expected is not None and expected.mode == 0o755 else 0o444
            )
            if (
                expected is None
                or expected.kind != "file"
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != expected_mode
                or before.st_size != len(expected.payload)
            ):
                raise BetaArtifactError(
                    f"committed source stage metadata changed: {relative}"
                )
            try:
                payload = child.read_bytes()
                after = child.stat(follow_symlinks=False)
            except OSError as error:
                raise BetaArtifactError(
                    f"cannot read committed source stage file {relative}: {error}"
                ) from error
            if payload != expected.payload or any(
                getattr(before, field) != getattr(after, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            ):
                raise BetaArtifactError(
                    f"committed source stage bytes changed: {relative}"
                )
            observed.add(relative)
    if observed != set(committed):
        raise BetaArtifactError(
            "committed source stage inventory differs from the Git object tree"
        )
    return _payload_tree(committed.values())


def _select_entries(
    committed: Mapping[str, CommittedEntry],
    includes: Sequence[str],
    excludes: Sequence[str],
    identifier: str,
) -> list[CommittedEntry]:
    selected: list[CommittedEntry] = []
    for name in sorted(committed, key=lambda value: value.encode("utf-8")):
        if not matches(name, includes) or matches(name, excludes):
            continue
        entry = committed[name]
        if entry.kind != "file":
            raise BetaArtifactError(
                f"beta archive {identifier} selected a non-regular path: {name}"
            )
        selected.append(
            CommittedEntry(
                name,
                entry.payload,
                normalized_mode(name),
            )
        )
    if not selected:
        raise BetaArtifactError(
            f"beta archive {identifier} selected no committed files"
        )
    return selected


def _source_archive_selections(
    committed: Mapping[str, CommittedEntry],
) -> tuple[
    dict[str, object],
    dict[str, object],
    tuple[tuple[CommittedEntry, ...], ...],
    dict[str, CommittedEntry],
]:
    """Resolve the one reviewed source projection into all source-derived archives."""

    matrix = beta_profile.expected_artifact_matrix()
    archive_manifest = beta_profile.expected_source_archives()
    matrix_entries = matrix.get("artifacts")
    manifest_entries = archive_manifest.get("archives")
    if (
        not isinstance(matrix_entries, list)
        or len(matrix_entries) != 6
        or not all(isinstance(entry, dict) for entry in matrix_entries)
        or not isinstance(manifest_entries, list)
        or len(manifest_entries) != 5
        or not all(isinstance(entry, dict) for entry in manifest_entries)
        or [entry.get("id") for entry in manifest_entries]
        != [entry.get("id") for entry in matrix_entries[:5]]
    ):
        raise BetaArtifactError(
            "source archive manifest and beta artifact matrix disagree"
        )
    always_exclude = archive_manifest.get("always_exclude")
    if not isinstance(always_exclude, list) or not all(
        isinstance(pattern, str) for pattern in always_exclude
    ):
        raise BetaArtifactError("source archive exclusion policy is invalid")

    selections: list[tuple[CommittedEntry, ...]] = []
    for manifest_entry, matrix_entry in zip(
        manifest_entries, matrix_entries[:5], strict=True
    ):
        if (
            not isinstance(manifest_entry, dict)
            or not isinstance(matrix_entry, dict)
            or manifest_entry.get("id") != matrix_entry.get("id")
            or manifest_entry.get("filename") != matrix_entry.get("filename")
            or manifest_entry.get("contract") != matrix_entry.get("contract")
            or not isinstance(manifest_entry.get("include"), list)
            or not all(
                isinstance(pattern, str) for pattern in manifest_entry["include"]
            )
        ):
            raise BetaArtifactError(
                f"source archive declaration mismatch: {matrix_entry.get('id')}"
            )
        selections.append(
            tuple(
                _select_entries(
                    committed,
                    manifest_entry["include"],
                    always_exclude,
                    str(matrix_entry["id"]),
                )
            )
        )
    source_committed = {entry.path: entry for entry in selections[0]}
    if len(source_committed) != len(selections[0]):
        raise BetaArtifactError("beta source archive selection contains duplicates")
    for selection in selections[1:]:
        if not {entry.path for entry in selection}.issubset(source_committed):
            raise BetaArtifactError(
                "source-derived beta archive reaches a path absent from the source archive"
            )
    expected_source_path = f"{ARTIFACT_DIRECTORY}/{matrix_entries[0].get('filename')}"
    if expected_source_path != SOURCE_ARCHIVE_PATH:
        raise BetaArtifactError("beta source archive path constant is stale")
    return matrix, archive_manifest, tuple(selections), source_committed


def _is_materialized_beta_projection(
    committed: Mapping[str, CommittedEntry],
) -> bool:
    marker = committed.get("packaging/beta/build-projection/projection.v1.json")
    if marker is None or marker.kind != "file":
        return False
    try:
        document = load_json_bytes(marker.payload, "beta build projection")
    except ReleaseError:
        return False
    if (
        marker.payload != canonical_json_bytes(document)
        or document != beta_profile.expected_build_projection()
    ):
        return False
    for source, destination in beta_profile.BETA_PROJECTION_REMAP.items():
        source_entry = committed.get(source)
        destination_entry = committed.get(destination)
        if (
            source_entry is None
            or destination_entry is None
            or source_entry.kind != "file"
            or destination_entry.kind != "file"
            or source_entry.payload != destination_entry.payload
            or source_entry.mode != destination_entry.mode
        ):
            return False
    return True


def _source_descriptor_from_committed(
    *,
    committed: Mapping[str, CommittedEntry],
    snapshot: GitSnapshot,
    source_archive: Mapping[str, object],
) -> dict[str, object]:
    def records(paths: Sequence[str], label: str) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for relative in paths:
            entry = committed.get(relative)
            if entry is None or entry.kind != "file":
                raise BetaArtifactError(
                    f"committed source omits required {label}: {relative}"
                )
            result.append(
                {
                    "path": relative,
                    "sha256": sha256_bytes(entry.payload),
                    "bytes": len(entry.payload),
                }
            )
        result.sort(key=lambda item: str(item["path"]).encode("utf-8"))
        return result

    return {
        "schema_version": "cigar.source-descriptor.v1",
        "generated_at": snapshot.generated_at,
        "git": {
            "revision": snapshot.revision,
            "tree": snapshot.tree,
            "committed": True,
            "clean": True,
            "status_entry_count": 0,
            "status_sha256": sha256_bytes(b""),
        },
        "source_archive": dict(source_archive),
        "policy_inputs": records(SOURCE_POLICY_INPUTS, "policy input"),
        "tool_inputs": records(SOURCE_TOOL_INPUTS, "tool input"),
    }


def _payload_tree(entries: Iterable[CommittedEntry]) -> str:
    digest = hashlib.sha256()
    count = 0
    for entry in sorted(entries, key=lambda item: item.path.encode("utf-8")):
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(entry.payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(f"{entry.mode:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(entry.payload).digest())
        digest.update(b"\n")
        count += 1
    if count == 0:
        raise BetaArtifactError("artifact payload tree cannot be empty")
    return digest.hexdigest()


def _metadata(
    *,
    artifact_id: str,
    contract_path: str,
    contract_sha256: str,
    snapshot: GitSnapshot,
    payload: Sequence[CommittedEntry],
    build: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "cigar.beta.release-metadata.v1",
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "tag": beta_profile.TAG,
        "prerelease": True,
        "production_ready": False,
        "artifact_id": artifact_id,
        "source_date_epoch": snapshot.source_date_epoch,
        "source": snapshot.source_identity(),
        "contract": {"path": contract_path, "sha256": contract_sha256},
        "payload": {
            "tree_sha256": _payload_tree(payload),
            "file_count": len(payload),
        },
        "build": build,
    }


def _validate_entry_inventory(entries: Sequence[CommittedEntry]) -> None:
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in entries:
        name = safe_relative_path(entry.path)
        alias = unicodedata.normalize("NFC", name).casefold()
        if name in names or alias in aliases:
            raise BetaArtifactError(
                f"duplicate or portable-colliding archive path: {name}"
            )
        names.add(name)
        aliases.add(alias)
        if entry.mode not in {0o644, 0o755}:
            raise BetaArtifactError(f"archive path has an invalid mode: {name}")


def write_deterministic_archive(
    output: Path,
    entries: Sequence[CommittedEntry],
    metadata: Mapping[str, object],
    epoch: int,
) -> None:
    if output.exists() or output.is_symlink():
        raise BetaArtifactError(f"refusing to overwrite staged artifact: {output}")
    metadata_entry = CommittedEntry(
        "RELEASE-METADATA.json", canonical_json_bytes(metadata), 0o644
    )
    complete = [metadata_entry, *entries]
    _validate_entry_inventory(complete)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output.parent, prefix=f".{output.name}.", delete=False
        ) as raw:
            temporary = Path(raw.name)
            with gzip.GzipFile(
                filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=epoch
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for entry in sorted(
                        complete, key=lambda item: item.path.encode("utf-8")
                    ):
                        information = tarfile.TarInfo(entry.path)
                        information.size = len(entry.payload)
                        information.mode = entry.mode
                        information.mtime = epoch
                        information.uid = 0
                        information.gid = 0
                        information.uname = ""
                        information.gname = ""
                        archive.addfile(information, io.BytesIO(entry.payload))
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o600)
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        directory_fd = os.open(output.parent, directory_flags)
        try:
            try:
                os.link(
                    temporary.name,
                    output.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise BetaArtifactError(
                    f"refusing to overwrite staged artifact: {output}"
                ) from error
            os.unlink(temporary.name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            final = os.stat(output.name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(final.st_mode)
                or stat.S_IMODE(final.st_mode) != 0o600
                or final.st_nlink != 1
            ):
                raise BetaArtifactError(
                    f"staged artifact failed no-clobber publication: {output}"
                )
        finally:
            os.close(directory_fd)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def expected_version_document(snapshot: GitSnapshot) -> dict[str, object]:
    return {
        "schema_version": "cigar.beta.build-metadata.v1",
        "version": beta_profile.VERSION,
        "source_revision": snapshot.revision,
        "build_profile": "release",
        "release_profile": beta_profile.PROFILE_ID,
        "channel": "beta",
        "production_ready": False,
        "qualification_status": "requires-external-release-evidence",
        "required_target_triple": beta_profile.TARGET_TRIPLE,
        "required_host_profile": beta_profile.RUNTIME_BASELINE,
        "required_distribution": beta_profile.QUALIFIED_DISTRIBUTION,
        "required_distribution_version": beta_profile.QUALIFIED_DISTRIBUTION_VERSION,
        "required_libc": "glibc",
        "required_libc_version": beta_profile.MINIMUM_GLIBC_VERSION,
        "target_os": "linux",
        "target_arch": "x86_64",
        "target_env": "gnu",
        "capability_profile": "workspace-metadata-only",
        "enabled_features": ["beta-embedded"],
    }


def validate_elf_linux_x86_64(payload: bytes) -> None:
    if len(payload) < 64 or len(payload) > MAX_BINARY_BYTES:
        raise BetaArtifactError("beta binary size is outside the reviewed bounds")
    if payload[:4] != b"\x7fELF" or payload[4:7] != b"\x02\x01\x01":
        raise BetaArtifactError("beta binary is not a 64-bit little-endian ELF")
    elf_type, machine, version = struct.unpack_from("<HHI", payload, 16)
    if elf_type != 3 or machine != 62 or version != 1:
        raise BetaArtifactError("beta ELF type, architecture, or version is invalid")
    entry, program_header_offset = struct.unpack_from("<QQ", payload, 24)
    header_size, program_header_size, program_header_count = struct.unpack_from(
        "<HHH", payload, 52
    )
    if (
        entry == 0
        or header_size != 64
        or program_header_size != 56
        or not 1 <= program_header_count <= 128
        or program_header_offset < 64
        or program_header_offset + program_header_size * program_header_count
        > len(payload)
    ):
        raise BetaArtifactError("beta ELF header is incomplete")
    executable_entry = False
    dynamic = False
    interpreter: bytes | None = None
    gnu_stack_count = 0
    gnu_relro_count = 0
    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_size
        (
            segment_type,
            flags,
            file_offset,
            virtual_address,
            _physical_address,
            file_size,
            memory_size,
            alignment,
        ) = struct.unpack_from("<IIQQQQQQ", payload, offset)
        if (
            flags & ~0x7
            or file_size > memory_size
            or file_offset > len(payload)
            or file_size > len(payload) - file_offset
            or virtual_address + memory_size > (1 << 64)
            or alignment not in {0, 1}
            and (alignment & (alignment - 1)) != 0
        ):
            raise BetaArtifactError("beta ELF program segment is malformed")
        if segment_type == 1:
            if flags & 0x3 == 0x3:
                raise BetaArtifactError(
                    "beta ELF contains a writable executable segment"
                )
            if flags & 0x1 and virtual_address <= entry < virtual_address + memory_size:
                executable_entry = True
        elif segment_type == 2:
            dynamic = True
        elif segment_type == 3:
            if interpreter is not None or not 2 <= file_size <= 4096:
                raise BetaArtifactError("beta ELF interpreter declaration is malformed")
            interpreter = payload[file_offset : file_offset + file_size]
        elif segment_type == 0x6474E551:
            gnu_stack_count += 1
            if flags != 0x6 or file_size != 0 or memory_size != 0:
                raise BetaArtifactError(
                    "beta ELF GNU stack must be non-executable and non-file-backed"
                )
        elif segment_type == 0x6474E552:
            gnu_relro_count += 1
            if not file_size or flags & 0x2:
                raise BetaArtifactError("beta ELF GNU RELRO segment is malformed")
    if not executable_entry or not dynamic:
        raise BetaArtifactError("beta ELF lacks an executable entry or dynamic table")
    allowed_interpreters = {
        b"/lib64/ld-linux-x86-64.so.2\0",
        b"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\0",
    }
    if interpreter not in allowed_interpreters:
        raise BetaArtifactError("beta ELF is not bound to the reviewed GNU interpreter")
    if gnu_stack_count != 1:
        raise BetaArtifactError("beta ELF must contain one non-executable GNU stack")
    if gnu_relro_count != 1:
        raise BetaArtifactError("beta ELF must contain one GNU RELRO segment")
    # This second parser binds the dynamic hardening policy as well as the loader ABI.
    elf_needed_libraries(payload)


def elf_needed_libraries(payload: bytes) -> tuple[str, ...]:
    program_header_offset = struct.unpack_from("<Q", payload, 32)[0]
    program_header_size, program_header_count = struct.unpack_from("<HH", payload, 54)
    loads: list[tuple[int, int, int, int]] = []
    dynamic_range: tuple[int, int] | None = None
    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_size
        segment_type, _flags, file_offset, virtual_address, _physical = (
            struct.unpack_from("<IIQQQ", payload, offset)
        )
        file_size, memory_size = struct.unpack_from("<QQ", payload, offset + 32)
        if segment_type == 1:
            loads.append((virtual_address, memory_size, file_offset, file_size))
        elif segment_type == 2:
            dynamic_range = (file_offset, file_size)
    if dynamic_range is None or dynamic_range[1] % 16 != 0:
        raise BetaArtifactError("beta ELF dynamic table is malformed")
    string_table_address: int | None = None
    string_table_size: int | None = None
    needed_offsets: list[int] = []
    terminated = False
    bind_now = False
    start, size = dynamic_range
    for offset in range(start, start + size, 16):
        tag, value = struct.unpack_from("<QQ", payload, offset)
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 22:
            raise BetaArtifactError("beta ELF contains text relocations")
        elif tag == 24:
            bind_now = True
        elif tag == 30:
            if value & 0x4:
                raise BetaArtifactError("beta ELF contains text relocations")
            bind_now = bind_now or bool(value & 0x8)
        elif tag == 0x6FFFFFFB:
            bind_now = bind_now or bool(value & 0x1)
        elif tag in {15, 29, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}:
            raise BetaArtifactError(
                "beta ELF contains an unsupported loader search/audit/filter directive"
            )
        elif tag == 5:
            string_table_address = value
        elif tag == 10:
            string_table_size = value
    if (
        not terminated
        or string_table_address is None
        or string_table_size is None
        or not 0 < string_table_size <= 16 * 1024 * 1024
    ):
        raise BetaArtifactError("beta ELF dynamic string table is missing")
    if not bind_now:
        raise BetaArtifactError(
            "beta ELF does not enforce immediate binding/full RELRO"
        )
    string_table_offset: int | None = None
    for virtual_address, memory_size, file_offset, file_size in loads:
        if virtual_address <= string_table_address < virtual_address + memory_size:
            delta = string_table_address - virtual_address
            if delta + string_table_size <= file_size:
                string_table_offset = file_offset + delta
                break
    if string_table_offset is None:
        raise BetaArtifactError(
            "beta ELF dynamic string table is outside load segments"
        )
    string_table = payload[
        string_table_offset : string_table_offset + string_table_size
    ]
    libraries: list[str] = []
    for needed in needed_offsets:
        if needed >= len(string_table):
            raise BetaArtifactError("beta ELF needed-library offset is invalid")
        end = string_table.find(b"\0", needed)
        if end < 0:
            raise BetaArtifactError("beta ELF needed-library name is unterminated")
        try:
            name = string_table[needed:end].decode("ascii", errors="strict")
        except UnicodeError as error:
            raise BetaArtifactError(
                "beta ELF needed-library name is not ASCII"
            ) from error
        if re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*", name) is None:
            raise BetaArtifactError("beta ELF needed-library name is unsafe")
        libraries.append(name)
    if len(libraries) != len(set(libraries)):
        raise BetaArtifactError("beta ELF repeats a needed library")
    return tuple(sorted(libraries, key=lambda value: value.encode("ascii")))


def _native_components(libraries: Sequence[str]) -> tuple[dict[str, object], ...]:
    license_by_name = {
        "libc.so.6": "LGPL-2.1-or-later",
        "libdl.so.2": "LGPL-2.1-or-later",
        "libgcc_s.so.1": "GPL-3.0-or-later WITH GCC-exception-3.1",
        "libm.so.6": "LGPL-2.1-or-later",
        "libpthread.so.0": "LGPL-2.1-or-later",
        "librt.so.1": "LGPL-2.1-or-later",
    }
    unknown = sorted(set(libraries) - set(license_by_name))
    if unknown:
        raise BetaArtifactError(
            f"beta ELF reaches unreviewed native libraries: {unknown}"
        )
    return tuple(
        {
            "type": "library",
            "name": name,
            "version": beta_profile.RUNTIME_BASELINE,
            "purl": (
                f"pkg:generic/{urllib.parse.quote(name, safe='')}"
                f"@{beta_profile.RUNTIME_BASELINE}"
            ),
            "bom-ref": (
                f"pkg:generic/{urllib.parse.quote(name, safe='')}"
                f"@{beta_profile.RUNTIME_BASELINE}"
            ),
            "licenses": [{"expression": license_by_name[name]}],
        }
        for name in sorted(libraries, key=lambda value: value.encode("ascii"))
    )


def _rust_standard_library_component(
    material: Mapping[str, object],
) -> dict[str, object]:
    digest = material.get("digest")
    annotations = material.get("annotations")
    if not isinstance(digest, dict) or not isinstance(annotations, dict):
        raise BetaArtifactError("Rust standard-library material is incomplete")
    target_digest = digest.get("sha256")
    required_annotations = {
        "bytes",
        "fileCount",
        "noticeBytes",
        "noticeSha256",
        "rustcCommit",
        "target",
        "toolchainVersion",
    }
    if (
        material.get("name") != "rust-target-libdir"
        or re.fullmatch(r"[0-9a-f]{64}", str(target_digest or "")) is None
        or set(annotations) != required_annotations
        or annotations.get("target") != beta_profile.TARGET_TRIPLE
        or annotations.get("toolchainVersion") != beta_profile.RUST_TOOLCHAIN_VERSION
        or re.fullmatch(r"[0-9a-f]{40}", str(annotations.get("rustcCommit", "")))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(annotations.get("noticeSha256", "")))
        is None
        or any(
            isinstance(annotations.get(key), bool)
            or not isinstance(annotations.get(key), int)
            or annotations[key] <= 0
            for key in ("bytes", "fileCount", "noticeBytes")
        )
    ):
        raise BetaArtifactError("Rust standard-library material identity is invalid")
    purl = (
        f"pkg:generic/rust-std@{beta_profile.RUST_TOOLCHAIN_VERSION}"
        f"?target={urllib.parse.quote(beta_profile.TARGET_TRIPLE, safe='-_.')}"
    )
    return {
        "type": "library",
        "name": "rust-std",
        "version": beta_profile.RUST_TOOLCHAIN_VERSION,
        "purl": purl,
        "bom-ref": purl,
        "licenses": [{"expression": "Apache-2.0 OR MIT"}],
        "hashes": [{"alg": "SHA-256", "content": target_digest}],
        "properties": [
            {"name": "cigar:linkage", "value": "statically-linked"},
            {"name": "cigar:notice-bytes", "value": str(annotations["noticeBytes"])},
            {
                "name": "cigar:notice-sha256",
                "value": str(annotations["noticeSha256"]),
            },
            {"name": "cigar:rustc-commit", "value": str(annotations["rustcCommit"])},
            {"name": "cigar:target", "value": beta_profile.TARGET_TRIPLE},
            {"name": "cigar:target-libdir-bytes", "value": str(annotations["bytes"])},
            {
                "name": "cigar:target-libdir-file-count",
                "value": str(annotations["fileCount"]),
            },
            {"name": "cigar:target-libdir-sha256", "value": str(target_digest)},
        ],
    }


def _augment_native_resolution(
    components: Sequence[Mapping[str, object]],
    dependencies: Sequence[Mapping[str, object]],
    libraries: Sequence[str],
    rust_component: Mapping[str, object] | None = None,
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    native = _native_components(libraries)
    if not native or not any(component["name"] == "libc.so.6" for component in native):
        raise BetaArtifactError("beta ELF has no reviewed GNU libc dependency")
    combined_components = tuple(
        sorted(
            (
                *(dict(component) for component in components),
                *native,
                *([dict(rust_component)] if rust_component is not None else []),
            ),
            key=lambda item: (str(item["name"]), str(item["version"])),
        )
    )
    dependency_records = [dict(record) for record in dependencies]
    root_refs = [
        component["bom-ref"]
        for component in components
        if component.get("name") == "cigar-cli"
    ]
    if len(root_refs) != 1:
        raise BetaArtifactError("beta Cargo dependency graph has no cigar-cli root")
    root_edges = [
        record for record in dependency_records if record.get("ref") == root_refs[0]
    ]
    if len(root_edges) != 1 or not isinstance(root_edges[0].get("dependsOn"), list):
        raise BetaArtifactError("beta Cargo dependency graph has no cigar-cli edge")
    root_edges[0]["dependsOn"] = sorted(
        {
            *root_edges[0]["dependsOn"],
            *(str(component["bom-ref"]) for component in native),
            *([str(rust_component["bom-ref"])] if rust_component is not None else []),
        },
        key=lambda value: value.encode("utf-8"),
    )
    dependency_records.extend(
        {"ref": component["bom-ref"], "dependsOn": []} for component in native
    )
    if rust_component is not None:
        dependency_records.append({"ref": rust_component["bom-ref"], "dependsOn": []})
    dependency_records.sort(key=lambda item: str(item["ref"]).encode("utf-8"))
    return combined_components, tuple(dependency_records)


def validate_version_document(
    document: object, snapshot: GitSnapshot
) -> dict[str, object]:
    if not isinstance(document, dict) or set(document) != EXPECTED_VERSION_KEYS:
        raise BetaArtifactError("beta binary version document has an unexpected shape")
    expected = expected_version_document(snapshot)
    if document != expected:
        raise BetaArtifactError(
            "beta binary version identity does not match the profile"
        )
    return dict(document)


def _run_beta_binary(
    binary: Path, snapshot: GitSnapshot, expected_help: bytes
) -> tuple[dict[str, object], str]:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TZ": "UTC",
    }
    version_bytes = _run_checked(
        [str(binary), "version"],
        cwd=binary.parent,
        env=environment,
        timeout=30,
        maximum=1024 * 1024,
        label="packaged beta version command",
    )
    document = load_json_bytes(version_bytes, "packaged beta version output")
    version = validate_version_document(document, snapshot)
    help_bytes = _run_checked(
        [str(binary), "help"],
        cwd=binary.parent,
        env=environment,
        timeout=30,
        maximum=1024 * 1024,
        label="packaged beta help command",
    )
    if help_bytes != expected_help:
        raise BetaArtifactError(
            "packaged beta help differs from the committed beta surface"
        )
    return version, sha256_bytes(help_bytes)


def _host_platform() -> dict[str, str]:
    machine = platform.machine().casefold()
    libc_name, libc_version = platform.libc_ver()
    distribution = ""
    distribution_version = ""
    glibc_identity = ""
    if sys.platform == "linux":
        try:
            os_release = platform.freedesktop_os_release()
        except OSError:
            os_release = {}
        distribution = str(os_release.get("ID", "")).casefold()
        distribution_version = str(os_release.get("VERSION_ID", ""))
        try:
            glibc_identity = os.confstr("CS_GNU_LIBC_VERSION") or ""
        except (OSError, ValueError):
            glibc_identity = ""
    return {
        "system": sys.platform,
        "machine": machine,
        "libc": libc_name.casefold(),
        "libc_version": libc_version,
        "glibc_identity": glibc_identity,
        "distribution": distribution,
        "distribution_version": distribution_version,
    }


def require_declared_host() -> dict[str, str]:
    host = _host_platform()
    if (
        host["system"] != "linux"
        or host["machine"] != "x86_64"
        or host["libc"] != "glibc"
        or host["libc_version"] != beta_profile.MINIMUM_GLIBC_VERSION
        or host["glibc_identity"] != f"glibc {beta_profile.MINIMUM_GLIBC_VERSION}"
        or host["distribution"] != beta_profile.QUALIFIED_DISTRIBUTION
        or host["distribution_version"] != beta_profile.QUALIFIED_DISTRIBUTION_VERSION
    ):
        raise BetaArtifactError(
            "beta binary build/execution requires the qualified Ubuntu 24.04 "
            "x86_64 glibc 2.39 baseline; "
            f"observed system={host['system']} machine={host['machine']} "
            f"distribution={host['distribution']} "
            f"distribution_version={host['distribution_version']} "
            f"libc={host['libc']} libc_version={host['libc_version']} "
            f"glibc_identity={host['glibc_identity']}"
        )
    return {
        **host,
        "runtime_baseline": beta_profile.RUNTIME_BASELINE,
        "target": beta_profile.TARGET_TRIPLE,
    }


def _read_stable_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise BetaArtifactError(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise BetaArtifactError(f"{label} is not a bounded, singly-linked regular file")
    try:
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise BetaArtifactError(f"cannot read {label}: {error}") from error
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise BetaArtifactError(f"{label} changed while it was read")
    if len(payload) != before.st_size:
        raise BetaArtifactError(f"{label} byte count changed while it was read")
    return payload


def _tool_record(path: Path, name: str, version: str) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    before = resolved.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) & 0o022
        or not 0 < before.st_size <= 64 * 1024 * 1024
    ):
        raise BetaArtifactError(f"{name} executable is unsafe")
    payload = resolved.read_bytes()
    after = resolved.stat(follow_symlinks=False)
    if (
        any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        )
        or len(payload) != before.st_size
    ):
        raise BetaArtifactError(f"{name} executable changed while read")
    return {
        "name": name,
        "sha256": sha256_bytes(payload),
        "bytes": len(payload),
        "version": version,
    }


def _tool_version(
    path: Path,
    arguments: Sequence[str],
    *,
    root: Path,
    environment: dict[str, str],
    name: str,
) -> str:
    payload = _run_checked(
        [str(path), *arguments],
        cwd=root,
        env=environment,
        timeout=30,
        maximum=64 * 1024,
        label=f"{name} version identity",
    )
    try:
        value = payload.decode("utf-8", errors="strict").strip()
    except UnicodeError as error:
        raise BetaArtifactError(f"{name} version identity is not UTF-8") from error
    if (
        not value
        or len(value.encode("utf-8")) > 4096
        or "\r" in value
        or any(
            ord(character) < 0x20 and character not in {"\n", "\t"}
            for character in value
        )
    ):
        raise BetaArtifactError(f"{name} version identity is invalid")
    return value


def _canonical_identity(fields: Mapping[str, object]) -> str:
    return canonical_json_bytes(dict(fields)).decode("utf-8").rstrip("\n")


def _runtime_module_path(module: object, name: str) -> Path:
    value = getattr(module, "__file__", None)
    if not isinstance(value, str) or not value:
        raise BetaArtifactError(f"Python {name} module has no file identity")
    try:
        return Path(value).resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot resolve Python {name} module identity: {error}"
        ) from error


def _python_runtime_tool_records(python: Path) -> list[dict[str, object]]:
    python_identity = _canonical_identity(
        {
            "abi_flags": sys.abiflags,
            "build": list(platform.python_build()),
            "cache_tag": sys.implementation.cache_tag,
            "compiler": platform.python_compiler(),
            "implementation": platform.python_implementation(),
            "implementation_version": list(sys.implementation.version),
            "version": platform.python_version(),
            "version_hex": sys.hexversion,
        }
    )
    gzip_identity = _canonical_identity(
        {
            "compresslevel": 9,
            "module": "gzip",
            "python_cache_tag": sys.implementation.cache_tag,
        }
    )
    tar_identity = _canonical_identity(
        {
            "block_size": tarfile.BLOCKSIZE,
            "format": "PAX_FORMAT",
            "format_id": tarfile.PAX_FORMAT,
            "module": "tarfile",
            "python_cache_tag": sys.implementation.cache_tag,
            "record_size": tarfile.RECORDSIZE,
        }
    )
    zlib_identity = _canonical_identity(
        {
            "compile_version": zlib.ZLIB_VERSION,
            "module": "zlib",
            "python_cache_tag": sys.implementation.cache_tag,
            "runtime_version": zlib.ZLIB_RUNTIME_VERSION,
        }
    )
    return [
        _tool_record(python, "python", python_identity),
        _tool_record(_runtime_module_path(gzip, "gzip"), "python-gzip", gzip_identity),
        _tool_record(
            _runtime_module_path(tarfile, "tarfile"),
            "python-tarfile",
            tar_identity,
        ),
        _tool_record(_runtime_module_path(zlib, "zlib"), "python-zlib", zlib_identity),
    ]


def _validate_python_runtime(path: Path) -> Path:
    selected = _secure_executable(path, "python")
    try:
        current = Path(sys.executable).resolve(strict=True)
        resolved = selected.resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(f"cannot resolve Python runtime: {error}") from error
    if (
        resolved != current
        or platform.python_version() != beta_profile.PYTHON_TOOLCHAIN_VERSION
    ):
        raise BetaArtifactError(
            "beta archive generator must run through the explicit pinned "
            f"Python {beta_profile.PYTHON_TOOLCHAIN_VERSION} runtime"
        )
    return resolved


def _required_rust_toolchain(root: Path) -> str:
    payload = _read_stable_file(
        resolve_beneath(root, "rust-toolchain.toml"),
        64 * 1024,
        "pinned Rust toolchain",
    )
    try:
        document = tomllib.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BetaArtifactError(f"pinned Rust toolchain is invalid: {error}") from error
    toolchain = document.get("toolchain") if isinstance(document, dict) else None
    channel = toolchain.get("channel") if isinstance(toolchain, dict) else None
    if channel != beta_profile.RUST_TOOLCHAIN_VERSION:
        raise BetaArtifactError("Rust toolchain pin differs from the beta profile")
    return channel


def _validate_rust_verbose_identity(
    identity: str, *, name: str, required_version: str
) -> None:
    first_line = identity.splitlines()[0] if identity else ""
    release = re.findall(r"^release: ([^\s]+)$", identity, flags=re.MULTILINE)
    host = re.findall(r"^host: ([^\s]+)$", identity, flags=re.MULTILINE)
    if (
        re.fullmatch(
            rf"{re.escape(name)} {re.escape(required_version)} \([0-9a-f]+ [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\)",
            first_line,
        )
        is None
        or release != [required_version]
        or host != [beta_profile.TARGET_TRIPLE]
    ):
        raise BetaArtifactError(
            f"{name} identity does not match the pinned {required_version} native toolchain"
        )


def _validate_rust_toolchain(
    *,
    root: Path,
    cargo: Path,
    rustc: Path,
    environment: dict[str, str],
) -> tuple[str, str, Path]:
    required = _required_rust_toolchain(root)
    cargo_identity = _tool_version(
        cargo,
        ["--version", "--verbose"],
        root=root,
        environment=environment,
        name="cargo",
    )
    rustc_identity = _tool_version(
        rustc,
        ["--version", "--verbose"],
        root=root,
        environment=environment,
        name="rustc",
    )
    _validate_rust_verbose_identity(
        cargo_identity, name="cargo", required_version=required
    )
    _validate_rust_verbose_identity(
        rustc_identity, name="rustc", required_version=required
    )
    target_libdir_payload = _run_checked(
        [
            str(rustc),
            "--print",
            "target-libdir",
            "--target",
            beta_profile.TARGET_TRIPLE,
        ],
        cwd=root,
        env=environment,
        timeout=30,
        maximum=64 * 1024,
        label="pinned Rust target library",
    )
    try:
        target_text = target_libdir_payload.decode("utf-8", errors="strict").strip()
        if "\n" in target_text or "\r" in target_text:
            raise ValueError("multiple target library paths")
        target_libdir = Path(target_text).resolve(strict=True)
        metadata = target_libdir.stat(follow_symlinks=False)
    except (UnicodeError, OSError, ValueError) as error:
        raise BetaArtifactError(
            f"Rust target library identity is invalid: {error}"
        ) from error
    if (
        not target_libdir.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not any(
            path.is_file() and not path.is_symlink()
            for path in target_libdir.glob("libstd-*.rlib")
        )
    ):
        raise BetaArtifactError(
            f"pinned Rust target is not safely installed: {beta_profile.TARGET_TRIPLE}"
        )
    return cargo_identity, rustc_identity, target_libdir


def _rust_standard_library_notice(
    *, root: Path, rustc: Path, environment: Mapping[str, str]
) -> bytes:
    sysroot_payload = _run_checked(
        [str(rustc), "--print", "sysroot"],
        cwd=root,
        env=dict(environment),
        timeout=30,
        maximum=64 * 1024,
        label="pinned Rust sysroot",
    )
    try:
        sysroot_text = sysroot_payload.decode("utf-8", errors="strict").strip()
        if "\n" in sysroot_text or "\r" in sysroot_text:
            raise ValueError("multiple Rust sysroot paths")
        sysroot = Path(sysroot_text).resolve(strict=True)
        sysroot_metadata = sysroot.stat(follow_symlinks=False)
    except (UnicodeError, OSError, ValueError) as error:
        raise BetaArtifactError(f"Rust sysroot identity is invalid: {error}") from error
    if (
        not sysroot.is_absolute()
        or not stat.S_ISDIR(sysroot_metadata.st_mode)
        or stat.S_IMODE(sysroot_metadata.st_mode) & 0o022
    ):
        raise BetaArtifactError("Rust sysroot is not a safe immutable input")
    relative = "share/doc/rust/COPYRIGHT-library.html"
    notice = resolve_beneath(sysroot, relative)
    metadata = notice.stat(follow_symlinks=False)
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise BetaArtifactError(
            "Rust standard-library notice is writable by group or world"
        )
    return _read_stable_file(
        notice, 8 * 1024 * 1024, "Rust standard-library copyright notice"
    )


def _rustc_commit_hash(identity: str) -> str:
    values = re.findall(r"^commit-hash: ([0-9a-f]{40})$", identity, flags=re.MULTILINE)
    if len(values) != 1:
        raise BetaArtifactError("rustc identity has no exact commit hash")
    return values[0]


def _rust_target_material(
    target_libdir: Path, *, rustc_identity: str, rust_notice: bytes
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    total = 0
    try:
        root_metadata = target_libdir.stat(follow_symlinks=False)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot inspect Rust target library tree: {error}"
        ) from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise BetaArtifactError(
            "Rust target library root is writable by group or world"
        )
    for directory, directory_names, file_names in os.walk(
        target_libdir, followlinks=False
    ):
        directory_path = Path(directory)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            metadata = (directory_path / name).stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise BetaArtifactError(
                    "Rust target library contains an unsafe directory"
                )
        for name in file_names:
            path = directory_path / name
            relative = safe_relative_path(path.relative_to(target_libdir).as_posix())
            payload = _read_stable_file(
                path, 128 * 1024 * 1024, f"Rust target library {relative}"
            )
            metadata = path.stat(follow_symlinks=False)
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise BetaArtifactError("Rust target library contains a writable file")
            total += len(payload)
            if len(records) >= 4096 or total > 512 * 1024 * 1024:
                raise BetaArtifactError("Rust target library tree exceeds its bounds")
            records.append(
                {
                    "path": relative,
                    "sha256": sha256_bytes(payload),
                    "bytes": len(payload),
                }
            )
    if not records or not any(
        str(record["path"]).startswith("libstd-") for record in records
    ):
        raise BetaArtifactError("Rust target library tree has no standard library")
    digest = sha256_bytes(canonical_json_bytes(records))
    return {
        "uri": f"urn:cigar:rust-target-libdir:{beta_profile.TARGET_TRIPLE}:{digest}",
        "name": "rust-target-libdir",
        "digest": {"sha256": digest},
        "annotations": {
            "bytes": total,
            "fileCount": len(records),
            "noticeBytes": len(rust_notice),
            "noticeSha256": sha256_bytes(rust_notice),
            "rustcCommit": _rustc_commit_hash(rustc_identity),
            "target": beta_profile.TARGET_TRIPLE,
            "toolchainVersion": beta_profile.RUST_TOOLCHAIN_VERSION,
        },
    }


def _cargo_environment(
    *,
    root: Path,
    target_directory: Path,
    snapshot: GitSnapshot,
    cargo: Path,
    rustc: Path,
    linker: Path,
    cargo_home: Path,
) -> dict[str, str]:
    path_entries = []
    for candidate in (
        cargo.parent,
        cargo.resolve(strict=True).parent,
        rustc.parent,
        rustc.resolve(strict=True).parent,
        linker.parent,
        linker.resolve(strict=True).parent,
        Path("/usr/bin"),
        Path("/bin"),
    ):
        text = str(candidate)
        if text not in path_entries:
            path_entries.append(text)
    try:
        cargo_home = cargo_home.resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot resolve private CARGO_HOME: {error}"
        ) from error
    if not cargo_home.is_dir() or stat.S_IMODE(cargo_home.stat().st_mode) != 0o700:
        raise BetaArtifactError("private CARGO_HOME is not a mode-0700 directory")
    environment = {
        "CARGO_ENCODED_RUSTFLAGS": (
            f"--remap-path-prefix={root}=/usr/src/cigar\x1f"
            f"--remap-path-prefix={target_directory}=/usr/src/cigar/target"
        ),
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target_directory),
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": str(linker),
        "CIGAR_SOURCE_REVISION": snapshot.revision,
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(path_entries),
        "RUSTC": str(rustc),
        "SOURCE_DATE_EPOCH": str(snapshot.source_date_epoch),
        "TZ": "UTC",
    }
    rustup_home = os.environ.get("RUSTUP_HOME")
    rustup_candidate = (
        Path(rustup_home).expanduser() if rustup_home else Path.home() / ".rustup"
    )
    if rustup_home or rustup_candidate.exists():
        try:
            resolved_rustup = rustup_candidate.resolve(strict=True)
        except OSError as error:
            raise BetaArtifactError(f"cannot resolve RUSTUP_HOME: {error}") from error
        if not resolved_rustup.is_dir():
            raise BetaArtifactError("RUSTUP_HOME is not a directory")
        environment["RUSTUP_HOME"] = str(resolved_rustup)
    return environment


def _cargo_command(cargo: Path, vendor: Path, arguments: Sequence[str]) -> list[str]:
    vendor_text = str(vendor)
    if any(character in vendor_text for character in ('"', "\\", "\n", "\r")):
        raise BetaArtifactError(
            "verified Cargo vendor path is not safely representable"
        )
    return [
        str(cargo),
        "--config",
        'source.crates-io.replace-with="cigar-beta-vendor"',
        "--config",
        f'source.cigar-beta-vendor.directory="{vendor_text}"',
        "--config",
        "net.offline=true",
        *arguments,
    ]


def _purl(name: str, version: str) -> str:
    return (
        "pkg:cargo/"
        + urllib.parse.quote(name, safe="")
        + "@"
        + urllib.parse.quote(version, safe=".+-_")
    )


def _cargo_lock_checksums(root: Path) -> dict[tuple[str, str, str], str]:
    projected_lock = resolve_beneath(root, "packaging/beta/build-projection/Cargo.lock")
    payload = _read_stable_file(
        projected_lock,
        16 * 1024 * 1024,
        "pinned Cargo lockfile",
    )
    try:
        document = tomllib.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BetaArtifactError(f"Cargo lockfile is invalid: {error}") from error
    packages = document.get("package") if isinstance(document, dict) else None
    if not isinstance(packages, list):
        raise BetaArtifactError("Cargo lockfile package inventory is missing")
    result: dict[tuple[str, str, str], str] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise BetaArtifactError("Cargo lockfile package record is invalid")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        checksum = package.get("checksum")
        if source is None and checksum is None:
            continue
        if (
            not all(
                isinstance(value, str) and value for value in (name, version, source)
            )
            or not isinstance(checksum, str)
            or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
        ):
            raise BetaArtifactError(
                "Cargo lockfile external package is not checksummed"
            )
        identity = (name, version, source)
        if identity in result:
            raise BetaArtifactError(
                "Cargo lockfile repeats an external package identity"
            )
        result[identity] = checksum
    return result


def _pinned_crate_set(root: Path, key: str) -> tuple[dict[str, str], ...]:
    path = resolve_beneath(root, "packaging/beta/cargo-resolution.v1.json")
    payload = _read_stable_file(path, MAX_JSON_BYTES, "pinned Cargo resolution")
    document = load_json_bytes(payload, "pinned Cargo resolution")
    if payload != canonical_json_bytes(document) or not isinstance(document, dict):
        raise BetaArtifactError("pinned Cargo resolution is not canonical JSON")
    packages = document.get(key)
    if not isinstance(packages, list) or not packages or len(packages) > 256:
        raise BetaArtifactError(f"pinned Cargo resolution has no exact {key}")
    lock_checksums = _cargo_lock_checksums(root)
    if key == "external_packages":
        component_count = document.get("component_count")
        if (
            isinstance(component_count, bool)
            or not isinstance(component_count, int)
            or len(packages) != component_count - len(REVIEWED_BETA_WORKSPACE_PACKAGES)
        ):
            raise BetaArtifactError(
                "pinned external Cargo closure count is inconsistent"
            )
    elif key == "vendor_packages":
        if len(packages) != len(lock_checksums):
            raise BetaArtifactError("pinned Cargo vendor set differs from Cargo.lock")
    else:
        raise BetaArtifactError("unsupported pinned Cargo package set")
    records: list[dict[str, str]] = []
    identities: set[tuple[str, str, str]] = set()
    filenames: set[str] = set()
    for record in packages:
        if (
            not isinstance(record, dict)
            or set(record) != {"checksum", "name", "source", "version"}
            or not all(
                isinstance(record.get(key), str) and record[key]
                for key in ("checksum", "name", "source", "version")
            )
            or re.fullmatch(r"[0-9a-f]{64}", record["checksum"]) is None
            or record["source"]
            != "registry+https://github.com/rust-lang/crates.io-index"
            or re.fullmatch(r"[A-Za-z0-9_+-]+", record["name"]) is None
            or re.fullmatch(r"[A-Za-z0-9.+_-]+", record["version"]) is None
        ):
            raise BetaArtifactError("pinned external Cargo package is invalid")
        identity = (record["name"], record["version"], record["source"])
        filename = f"{record['name']}-{record['version']}.crate"
        if (
            identity in identities
            or filename in filenames
            or lock_checksums.get(identity) != record["checksum"]
        ):
            raise BetaArtifactError(
                "pinned external Cargo package conflicts with Cargo.lock"
            )
        identities.add(identity)
        filenames.add(filename)
        records.append(dict(record))
    expected_order = sorted(
        records, key=lambda item: (item["name"], item["version"], item["source"])
    )
    if records != expected_order:
        raise BetaArtifactError("pinned external Cargo packages are not ordered")
    return tuple(records)


def _pinned_external_crates(root: Path) -> tuple[dict[str, str], ...]:
    """Return the exact Linux-reachable external beta closure without running Cargo."""

    return _pinned_crate_set(root, "external_packages")


def _pinned_vendor_crates(root: Path) -> tuple[dict[str, str], ...]:
    """Return every external package represented in the projected lockfile."""

    return _pinned_crate_set(root, "vendor_packages")


def _bounded_gzip_decompress(payload: bytes, maximum: int, label: str) -> bytes:
    decompressor = zlib.decompressobj(wbits=31)
    expanded = bytearray()
    try:
        for offset in range(0, len(payload), 1024 * 1024):
            remaining = maximum + 1 - len(expanded)
            if remaining <= 0:
                raise BetaArtifactError(f"{label} exceeds its expansion limit")
            expanded.extend(
                decompressor.decompress(
                    payload[offset : offset + 1024 * 1024], remaining
                )
            )
            if len(expanded) > maximum or decompressor.unused_data:
                raise BetaArtifactError(f"{label} is oversized or concatenated")
        expanded.extend(decompressor.flush(maximum + 1 - len(expanded)))
    except zlib.error as error:
        raise BetaArtifactError(f"{label} gzip stream is invalid: {error}") from error
    if (
        len(expanded) > maximum
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise BetaArtifactError(f"{label} gzip stream is truncated or ambiguous")
    return bytes(expanded)


def _crate_cache_directories(crate_cache: Path) -> tuple[Path, ...]:
    if not crate_cache.is_absolute() or crate_cache != Path(
        os.path.normpath(crate_cache)
    ):
        raise BetaArtifactError("crate cache path must be absolute and canonical")
    try:
        supplied_metadata = crate_cache.lstat()
        resolved = crate_cache.resolve(strict=True)
        resolved_metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise BetaArtifactError(f"cannot resolve crate cache: {error}") from error
    if (
        stat.S_ISLNK(supplied_metadata.st_mode)
        or resolved != crate_cache
        or not stat.S_ISDIR(resolved_metadata.st_mode)
    ):
        raise BetaArtifactError("crate cache must be a real canonical directory")
    directories = [resolved]
    try:
        children = sorted(
            resolved.iterdir(), key=lambda item: item.name.encode("utf-8")
        )
        for child in children:
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(child)
            elif stat.S_ISLNK(metadata.st_mode):
                continue
    except OSError as error:
        raise BetaArtifactError(f"cannot inspect crate cache: {error}") from error
    return tuple(directories)


def _read_pinned_crate(
    directories: Sequence[Path], package: Mapping[str, str]
) -> tuple[str, bytes]:
    filename = f"{package['name']}-{package['version']}.crate"
    candidates: list[Path] = []
    for directory in directories:
        candidate = directory / filename
        try:
            metadata = candidate.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise BetaArtifactError(
                f"cannot inspect cached crate {filename}: {error}"
            ) from error
        if not stat.S_ISREG(metadata.st_mode):
            raise BetaArtifactError(
                f"cached crate is a link or special file: {filename}"
            )
        candidates.append(candidate)
    if len(candidates) != 1:
        raise BetaArtifactError(
            f"expected one cached archive for {filename}; observed={len(candidates)}"
        )
    payload = _read_stable_file(
        candidates[0], MAX_CRATE_ARCHIVE_BYTES, f"cached crate {filename}"
    )
    if sha256_bytes(payload) != package["checksum"]:
        raise BetaArtifactError(
            f"cached crate checksum differs from Cargo.lock: {filename}"
        )
    return filename, payload


def _extract_verified_crate(
    *, package: Mapping[str, str], filename: str, archive_payload: bytes
) -> tuple[list[CommittedEntry], str]:
    expanded = _bounded_gzip_decompress(
        archive_payload, MAX_CRATE_EXPANDED_BYTES, f"cached crate {filename}"
    )
    prefix = f"{package['name']}-{package['version']}"
    entries: list[CommittedEntry] = []
    aliases: dict[str, str] = {}
    file_hashes: dict[str, str] = {}
    total = 0
    member_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_CRATE_ENTRIES:
                    raise BetaArtifactError(
                        f"cached crate has too many entries: {filename}"
                    )
                raw_name = (
                    member.name[:-1]
                    if member.isdir() and member.name.endswith("/")
                    else member.name
                )
                name = safe_relative_path(raw_name)
                if name == prefix and member.isdir():
                    continue
                required_prefix = f"{prefix}/"
                if not name.startswith(required_prefix):
                    raise BetaArtifactError(
                        f"cached crate escapes its package root: {filename}"
                    )
                relative = safe_relative_path(name[len(required_prefix) :])
                alias = unicodedata.normalize("NFC", relative).casefold()
                if relative in file_hashes or alias in aliases:
                    raise BetaArtifactError(
                        f"cached crate repeats or portably collides: {filename}:{relative}"
                    )
                if member.isdir():
                    aliases[alias] = relative
                    continue
                if (
                    not member.isfile()
                    or member.size < 0
                    or member.size > MAX_CRATE_EXPANDED_BYTES
                ):
                    raise BetaArtifactError(
                        f"cached crate contains a link, special, or oversized entry: {filename}"
                    )
                if relative == ".cargo-checksum.json":
                    raise BetaArtifactError(
                        f"cached crate contains reserved Cargo checksum metadata: {filename}"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise BetaArtifactError(
                        f"cannot read cached crate member: {filename}"
                    )
                payload = handle.read(member.size + 1)
                if len(payload) != member.size:
                    raise BetaArtifactError(
                        f"cached crate member is truncated: {filename}"
                    )
                total += len(payload)
                if total > MAX_CRATE_EXPANDED_BYTES:
                    raise BetaArtifactError(
                        f"cached crate exceeds its byte limit: {filename}"
                    )
                aliases[alias] = relative
                file_hashes[relative] = sha256_bytes(payload)
                entries.append(
                    CommittedEntry(
                        f"{prefix}/{relative}",
                        payload,
                        0o755 if member.mode & 0o111 else 0o644,
                    )
                )
    except (tarfile.TarError, ReleaseError) as error:
        raise BetaArtifactError(
            f"cached crate tar is unsafe: {filename}: {error}"
        ) from error
    if not entries or "Cargo.toml" not in file_hashes:
        raise BetaArtifactError(
            f"cached crate has no Cargo package manifest: {filename}"
        )
    package_entries = [
        CommittedEntry(entry.path[len(prefix) + 1 :], entry.payload, entry.mode)
        for entry in entries
    ]
    source_tree_sha256 = _payload_tree(package_entries)
    checksum_payload = canonical_json_bytes(
        {"files": file_hashes, "package": package["checksum"]}
    )
    entries.append(
        CommittedEntry(f"{prefix}/.cargo-checksum.json", checksum_payload, 0o644)
    )
    return entries, source_tree_sha256


def _prepare_verified_vendor(
    *, root: Path, crate_cache: Path, staging: Path
) -> tuple[
    Path,
    tuple[Path, Path],
    dict[str, CommittedEntry],
    str,
    tuple[dict[str, object], ...],
]:
    packages = _pinned_vendor_crates(root)
    directories = _crate_cache_directories(crate_cache)
    vendor_entries: dict[str, CommittedEntry] = {}
    materials: list[dict[str, object]] = []
    total = 0
    for package in packages:
        filename, archive_payload = _read_pinned_crate(directories, package)
        entries, source_tree_sha256 = _extract_verified_crate(
            package=package, filename=filename, archive_payload=archive_payload
        )
        for entry in entries:
            if entry.path in vendor_entries:
                raise BetaArtifactError("verified Cargo vendor tree repeats a path")
            vendor_entries[entry.path] = entry
            total += len(entry.payload)
            if total > MAX_VENDOR_EXPANDED_BYTES:
                raise BetaArtifactError(
                    "verified Cargo vendor tree exceeds its byte limit"
                )
        materials.append(
            {
                "uri": _purl(package["name"], package["version"]),
                "name": filename,
                "digest": {"sha256": package["checksum"]},
                "annotations": {
                    "archiveBytes": len(archive_payload),
                    "source": package["source"],
                    "sourceTreeSha256": source_tree_sha256,
                },
            }
        )
    vendor = staging / "verified-vendor"
    vendor_identity = _materialize_committed_tree(vendor, vendor_entries)
    config = (
        '[source.crates-io]\nreplace-with = "cigar-beta-vendor"\n\n'
        '[source.cigar-beta-vendor]\ndirectory = "../verified-vendor"\n\n'
        "[net]\noffline = true\n"
    ).encode("ascii")
    cargo_homes = (staging / "cargo-home-first", staging / "cargo-home-second")
    for cargo_home in cargo_homes:
        cargo_home.mkdir(mode=0o700)
        _write_private(cargo_home / "config.toml", config)
    materials.sort(key=lambda item: str(item["uri"]).encode("utf-8"))
    return vendor, cargo_homes, vendor_entries, vendor_identity, tuple(materials)


def _license_file_kind(relative: str) -> str | None:
    """Classify exact upstream legal files without inferring content from prose."""

    basename = relative.rsplit("/", 1)[-1].casefold()
    if basename.startswith(("license", "licence", "copying", "unlicense")):
        return "license-text"
    if basename.startswith(("notice", "copyright")):
        return "notice"
    return None


def _crate_license_expression(
    package: Mapping[str, str], vendor_entries: Mapping[str, CommittedEntry]
) -> str:
    prefix = f"{package['name']}-{package['version']}"
    manifest = vendor_entries.get(f"{prefix}/Cargo.toml")
    if manifest is None or manifest.kind != "file":
        raise BetaArtifactError(f"verified crate has no Cargo.toml: {prefix}")
    try:
        document = tomllib.loads(manifest.payload.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BetaArtifactError(
            f"verified crate Cargo.toml is invalid: {prefix}: {error}"
        ) from error
    table = document.get("package") if isinstance(document, dict) else None
    expression = table.get("license") if isinstance(table, dict) else None
    if (
        table is None
        or table.get("name") != package["name"]
        or table.get("version") != package["version"]
        or not isinstance(expression, str)
        or not expression
        or expression != expression.strip()
        or len(expression.encode("utf-8")) > 1024
    ):
        raise BetaArtifactError(
            f"verified crate has no exact license identity: {prefix}"
        )
    return expression


def _expected_beta_license_documents(
    *,
    root: Path,
    vendor_entries: Mapping[str, CommittedEntry],
    rust_notice: bytes,
) -> tuple[dict[str, object], dict[str, object], dict[str, bytes]]:
    """Derive the committed beta legal payload from verified build inputs."""

    if not rust_notice or len(rust_notice) > 8 * 1024 * 1024:
        raise BetaArtifactError(
            "pinned Rust standard-library notice is missing or oversized"
        )
    policy_path = resolve_beneath(root, "packaging/licenses/third-party-policy.v1.json")
    policy = load_json(policy_path)
    if not isinstance(policy, dict):
        raise BetaArtifactError("third-party license policy is invalid")
    accepted = set(policy.get("accepted_expressions", []))
    review = set(policy.get("review_required", []))
    if not accepted or not all(isinstance(value, str) for value in accepted | review):
        raise BetaArtifactError("third-party license policy sets are invalid")

    runtime = {
        (package["name"], package["version"], package["source"])
        for package in _pinned_external_crates(root)
    }
    packages: list[dict[str, object]] = []
    inventory_records: list[dict[str, object]] = []
    expected_files: dict[str, bytes] = {}
    runtime_file_count = 0
    runtime_package_count = 0
    resolver_only_package_count = 0
    for package in _pinned_vendor_crates(root):
        identity = (package["name"], package["version"], package["source"])
        role = "target-runtime" if identity in runtime else "resolver-only"
        if role == "target-runtime":
            runtime_package_count += 1
        else:
            resolver_only_package_count += 1
        expression = _crate_license_expression(package, vendor_entries)
        policy_status = license_policy_status(expression, accepted, review)
        prefix = f"{package['name']}-{package['version']}"
        file_records: list[dict[str, object]] = []
        if role == "target-runtime":
            for path, entry in sorted(
                vendor_entries.items(), key=lambda item: item[0].encode("utf-8")
            ):
                required_prefix = f"{prefix}/"
                if not path.startswith(required_prefix) or entry.kind != "file":
                    continue
                archive_path = safe_relative_path(path[len(required_prefix) :])
                kind = _license_file_kind(archive_path)
                if kind is None:
                    continue
                distribution_path = (
                    "packaging/licenses/beta-third-party-license-files/"
                    f"{prefix}/{archive_path}"
                )
                if distribution_path in expected_files:
                    raise BetaArtifactError("beta legal payload repeats a path")
                expected_files[distribution_path] = entry.payload
                file_records.append(
                    {
                        "archive_path": archive_path,
                        "bytes": len(entry.payload),
                        "kind": kind,
                        "path": distribution_path,
                        "sha256": sha256_bytes(entry.payload),
                    }
                )
            if not file_records:
                raise BetaArtifactError(
                    f"runtime crate has no upstream legal file: {prefix}"
                )
            runtime_file_count += len(file_records)
            inventory_records.append(
                {
                    "license_expression": expression,
                    "name": package["name"],
                    "policy_status": policy_status,
                    "purl": _purl(package["name"], package["version"]),
                    "version": package["version"],
                }
            )
        packages.append(
            {
                "archive_sha256": package["checksum"],
                "files": file_records,
                "license_expression": expression,
                "name": package["name"],
                "policy_status": policy_status,
                "purl": _purl(package["name"], package["version"]),
                "role": role,
                "source": package["source"],
                "source_files_distributed": role == "target-runtime",
                "version": package["version"],
            }
        )

    if runtime_package_count != 43 or resolver_only_package_count != 4:
        raise BetaArtifactError(
            "beta legal package roles differ from the pinned closure"
        )
    if runtime_file_count != 91:
        raise BetaArtifactError(
            "beta runtime legal-file count differs from the reviewed 91-file set"
        )
    inventory_records.sort(key=lambda item: (str(item["name"]), str(item["version"])))
    runtime_review_count = sum(
        record["policy_status"] != "accepted-by-policy" for record in inventory_records
    )
    inventory: dict[str, object] = {
        "schema_version": "cigar.beta.third-party-license-inventory.v1",
        "policy_sha256": sha256_file(policy_path),
        "status": (
            "accepted-by-policy" if runtime_review_count == 0 else "review-required"
        ),
        "component_count": len(inventory_records),
        "components": inventory_records,
        "release_profile": beta_profile.PROFILE_ID,
    }
    rust_path = "packaging/licenses/rust/COPYRIGHT-library.html"
    expected_files[rust_path] = rust_notice
    manifest: dict[str, object] = {
        "schema_version": "cigar.beta.third-party-license-files.v1",
        "release_profile": beta_profile.PROFILE_ID,
        "package_count": len(packages),
        "runtime_package_count": runtime_package_count,
        "resolver_only_package_count": resolver_only_package_count,
        "runtime_license_file_count": runtime_file_count,
        "packages": packages,
        "rust_standard_library": {
            "bytes": len(rust_notice),
            "path": rust_path,
            "sha256": sha256_bytes(rust_notice),
            "source_path": "share/doc/rust/COPYRIGHT-library.html",
            "target": beta_profile.TARGET_TRIPLE,
            "toolchain_version": beta_profile.RUST_TOOLCHAIN_VERSION,
        },
    }
    return inventory, manifest, expected_files


def _verify_beta_license_sources(
    *,
    root: Path,
    vendor_entries: Mapping[str, CommittedEntry],
    rust_notice: bytes,
) -> None:
    root = root.resolve(strict=True)
    inventory, manifest, expected_files = _expected_beta_license_documents(
        root=root, vendor_entries=vendor_entries, rust_notice=rust_notice
    )
    documents = {
        "packaging/licenses/beta-third-party-inventory.v1.json": inventory,
        "packaging/licenses/beta-third-party-license-manifest.v1.json": manifest,
    }
    for relative, expected in documents.items():
        payload = _read_stable_file(
            resolve_beneath(root, relative), MAX_JSON_BYTES, relative
        )
        if payload != canonical_json_bytes(expected):
            raise BetaArtifactError(
                f"committed beta legal manifest differs from verified sources: {relative}"
            )

    roots = (
        "packaging/licenses/beta-third-party-license-files",
        "packaging/licenses/rust",
    )
    observed: set[str] = set()
    for relative_root in roots:
        directory = resolve_beneath(root, relative_root)
        root_metadata = directory.stat(follow_symlinks=False)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise BetaArtifactError(
                f"beta legal payload root is not a directory: {relative_root}"
            )
        for directory_name, directory_names, file_names in os.walk(
            directory, followlinks=False
        ):
            directory_names.sort()
            file_names.sort()
            current = Path(directory_name)
            for name in directory_names:
                metadata = (current / name).stat(follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise BetaArtifactError(
                        "beta legal payload contains a linked directory"
                    )
            for name in file_names:
                path = current / name
                relative = safe_relative_path(path.relative_to(root).as_posix())
                expected_payload = expected_files.get(relative)
                if expected_payload is None or relative in observed:
                    raise BetaArtifactError(
                        f"beta legal payload contains an extra file: {relative}"
                    )
                if (
                    _read_stable_file(path, 8 * 1024 * 1024, relative)
                    != expected_payload
                ):
                    raise BetaArtifactError(
                        f"beta legal payload differs from verified source: {relative}"
                    )
                observed.add(relative)
    if observed != set(expected_files):
        raise BetaArtifactError(
            "beta legal payload omits files derived from verified runtime sources"
        )


def _cargo_components(
    document: object,
    *,
    root: Path,
    enforce_pinned: bool = True,
    resolution_output: list[dict[str, object]] | None = None,
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    if not isinstance(document, dict):
        raise BetaArtifactError("Cargo metadata is not an object")
    packages_value = document.get("packages")
    resolve = document.get("resolve")
    if not isinstance(packages_value, list) or not isinstance(resolve, dict):
        raise BetaArtifactError("Cargo metadata has no package resolution")
    workspace_members_value = document.get("workspace_members")
    if not isinstance(workspace_members_value, list) or not all(
        isinstance(identifier, str) and identifier
        for identifier in workspace_members_value
    ):
        raise BetaArtifactError("Cargo metadata workspace member inventory is invalid")
    workspace_members = set(workspace_members_value)
    if len(workspace_members) != len(workspace_members_value):
        raise BetaArtifactError("Cargo metadata repeats a workspace member")
    lock_checksums = _cargo_lock_checksums(root)
    packages: dict[str, dict[str, object]] = {}
    root_ids: list[str] = []
    for package in packages_value:
        if not isinstance(package, dict):
            raise BetaArtifactError("Cargo metadata package is invalid")
        identifier = package.get("id")
        name = package.get("name")
        version = package.get("version")
        if not all(
            isinstance(value, str) and value for value in (identifier, name, version)
        ):
            raise BetaArtifactError("Cargo metadata package identity is invalid")
        if identifier in packages:
            raise BetaArtifactError("Cargo metadata contains a duplicate package id")
        packages[identifier] = package
        if name == "cigar-cli":
            root_ids.append(identifier)
    if len(root_ids) != 1:
        raise BetaArtifactError("Cargo metadata does not contain one cigar-cli package")
    nodes_value = resolve.get("nodes")
    if not isinstance(nodes_value, list):
        raise BetaArtifactError("Cargo metadata resolution nodes are missing")
    nodes: dict[str, dict[str, object]] = {}
    for node in nodes_value:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise BetaArtifactError("Cargo metadata resolution node is invalid")
        identifier = node["id"]
        if identifier in nodes:
            raise BetaArtifactError(
                "Cargo metadata contains a duplicate resolution node"
            )
        nodes[identifier] = node
    root_id = root_ids[0]
    root_node = nodes.get(root_id)
    if root_node is None or root_node.get("features") != ["beta-embedded"]:
        raise BetaArtifactError(
            "cigar-cli Cargo resolution must enable only beta-embedded"
        )

    def runtime_dependencies(node: Mapping[str, object]) -> list[str]:
        dependencies = node.get("deps")
        if not isinstance(dependencies, list):
            raise BetaArtifactError("Cargo resolution dependency edges are invalid")
        selected: list[str] = []
        for dependency in dependencies:
            if not isinstance(dependency, dict) or not isinstance(
                dependency.get("pkg"), str
            ):
                raise BetaArtifactError("Cargo resolution dependency edge is invalid")
            kinds = dependency.get("dep_kinds")
            if not isinstance(kinds, list) or not kinds:
                raise BetaArtifactError("Cargo dependency edge has no dependency kind")
            include = False
            for kind_record in kinds:
                if not isinstance(kind_record, dict) or set(kind_record) != {
                    "kind",
                    "target",
                }:
                    raise BetaArtifactError("Cargo dependency kind is invalid")
                kind = kind_record.get("kind")
                target = kind_record.get("target")
                if kind not in {None, "build", "dev"} or not (
                    target is None or isinstance(target, str)
                ):
                    raise BetaArtifactError("Cargo dependency kind is invalid")
                include = include or kind in {None, "build"}
            if include:
                selected.append(dependency["pkg"])
        return selected

    reachable: set[str] = set()
    pending = [root_id]
    while pending:
        identifier = pending.pop()
        if identifier in reachable:
            continue
        node = nodes.get(identifier)
        if node is None:
            raise BetaArtifactError("Cargo resolution references a missing node")
        reachable.add(identifier)
        pending.extend(runtime_dependencies(node))
    names = {str(packages[identifier]["name"]) for identifier in reachable}
    forbidden = sorted(names & FORBIDDEN_BETA_PACKAGES)
    if forbidden:
        raise BetaArtifactError(
            f"beta Cargo dependency closure reaches excluded packages: {forbidden}"
        )
    local_names: set[str] = set()
    for identifier in reachable:
        package = packages[identifier]
        name = str(package["name"])
        source = package.get("source")
        is_workspace_member = identifier in workspace_members
        if source is None:
            if not is_workspace_member:
                raise BetaArtifactError(
                    "beta Cargo dependency closure reaches a non-workspace path package"
                )
            expected_manifest = REVIEWED_BETA_WORKSPACE_MANIFESTS.get(name)
            manifest = package.get("manifest_path")
            if expected_manifest is None or not isinstance(manifest, str):
                raise BetaArtifactError(
                    "beta Cargo dependency closure reaches an unreviewed workspace package"
                )
            try:
                actual_manifest = Path(manifest).resolve(strict=True)
                reviewed_manifest = resolve_beneath(root, expected_manifest)
            except (OSError, ReleaseError) as error:
                raise BetaArtifactError(
                    f"cannot validate beta workspace package path: {error}"
                ) from error
            if actual_manifest != reviewed_manifest:
                raise BetaArtifactError(
                    "beta Cargo workspace package manifest path is substituted"
                )
            local_names.add(name)
        elif not isinstance(source, str) or not source or is_workspace_member:
            raise BetaArtifactError("Cargo package source identity is invalid")
    if local_names != REVIEWED_BETA_WORKSPACE_PACKAGES:
        raise BetaArtifactError(
            "beta Cargo dependency closure differs from the exact reviewed workspace set; "
            f"observed={sorted(local_names)}"
        )
    components: list[dict[str, object]] = []
    for identifier in reachable:
        package = packages[identifier]
        name = str(package["name"])
        version = str(package["version"])
        component: dict[str, object] = {
            "type": "application" if name == "cigar-cli" else "library",
            "name": name,
            "version": version,
            "purl": _purl(name, version),
        }
        source = package.get("source")
        checksum = package.get("checksum")
        if checksum is None and isinstance(source, str):
            checksum = lock_checksums.get((name, version, source))
        if isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum):
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        license_value = package.get("license")
        if not isinstance(license_value, str) or not license_value:
            raise BetaArtifactError(f"Cargo package has no declared license: {name}")
        component["bom-ref"] = component["purl"]
        component["licenses"] = [{"expression": license_value}]
        components.append(component)
    components.sort(key=lambda item: (str(item["name"]), str(item["version"])))
    references = {
        identifier: _purl(
            str(packages[identifier]["name"]), str(packages[identifier]["version"])
        )
        for identifier in reachable
    }
    dependencies = [
        {
            "ref": references[identifier],
            "dependsOn": sorted(
                {
                    references[dependency]
                    for dependency in runtime_dependencies(nodes[identifier])
                    if dependency in reachable
                },
                key=lambda value: value.encode("utf-8"),
            ),
        }
        for identifier in reachable
    ]
    dependencies.sort(key=lambda item: str(item["ref"]).encode("utf-8"))
    resolution_records: list[dict[str, object]] = []
    for identifier in reachable:
        package = packages[identifier]
        node = nodes[identifier]
        features = node.get("features")
        if (
            not isinstance(features, list)
            or not all(isinstance(feature, str) and feature for feature in features)
            or features != sorted(set(features))
        ):
            raise BetaArtifactError("Cargo resolution feature inventory is invalid")
        name = str(package["name"])
        source = package.get("source")
        checksum = package.get("checksum")
        if checksum is None and isinstance(source, str):
            checksum = lock_checksums.get((name, str(package["version"]), source))
        if source is None:
            source_identity = "workspace"
            checksum_identity: str | None = None
            manifest = REVIEWED_BETA_WORKSPACE_MANIFESTS[name]
        else:
            if (
                not isinstance(source, str)
                or not source
                or not isinstance(checksum, str)
                or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
            ):
                raise BetaArtifactError(
                    "external Cargo dependency has no exact source/checksum identity: "
                    f"{name}"
                )
            source_identity = source
            checksum_identity = checksum
            manifest = None
        resolution_records.append(
            {
                "ref": references[identifier],
                "source": source_identity,
                "checksum": checksum_identity,
                "features": features,
                "workspace_manifest": manifest,
            }
        )
    resolution_records.sort(key=lambda item: str(item["ref"]).encode("utf-8"))
    if resolution_output is not None:
        resolution_output.extend(dict(item) for item in resolution_records)
    if enforce_pinned:
        _validate_pinned_cargo_resolution(
            root=root,
            components=components,
            dependencies=dependencies,
            resolution=resolution_records,
        )
    return tuple(components), tuple(dependencies)


def _pinned_cargo_resolution(root: Path) -> dict[str, object]:
    path = resolve_beneath(root, "packaging/beta/cargo-resolution.v1.json")
    document = load_json(path)
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "component_count",
            "dependencies",
            "dependency_edge_count",
            "external_packages",
            "metadata_resolution_sha256",
            "release_profile",
            "resolution",
            "sbom_resolution_sha256",
            "schema_version",
            "target",
            "vendor_packages",
            "workspace_packages",
        }
        or document.get("schema_version") != "cigar.beta.cargo-resolution.v1"
        or document.get("release_profile") != beta_profile.PROFILE_ID
        or document.get("target") != beta_profile.TARGET_TRIPLE
        or document.get("workspace_packages")
        != sorted(REVIEWED_BETA_WORKSPACE_PACKAGES)
        or isinstance(document.get("component_count"), bool)
        or not isinstance(document.get("component_count"), int)
        or document["component_count"] <= 0
        or isinstance(document.get("dependency_edge_count"), bool)
        or not isinstance(document.get("dependency_edge_count"), int)
        or document["dependency_edge_count"] < 0
        or any(
            not isinstance(document.get(key), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(document[key])) is None
            for key in ("metadata_resolution_sha256", "sbom_resolution_sha256")
        )
    ):
        raise BetaArtifactError("pinned beta Cargo resolution identity is invalid")
    if canonical_json_bytes(document) != path.read_bytes():
        raise BetaArtifactError("pinned beta Cargo resolution is not canonical")
    _pinned_external_crates(root)
    _pinned_vendor_crates(root)
    return document


def _validate_pinned_cargo_resolution(
    *,
    root: Path,
    components: Sequence[Mapping[str, object]],
    dependencies: Sequence[Mapping[str, object]],
    resolution: Sequence[Mapping[str, object]],
) -> None:
    pinned = _pinned_cargo_resolution(root)
    sbom_identity = {
        "components": [dict(component) for component in components],
        "dependencies": [dict(dependency) for dependency in dependencies],
    }
    metadata_identity = {
        **sbom_identity,
        "resolution": [dict(item) for item in resolution],
    }
    components_by_ref = {
        str(component["bom-ref"]): component for component in components
    }
    external_packages: list[dict[str, object]] = []
    for record in resolution:
        if record.get("source") == "workspace":
            continue
        component = components_by_ref.get(str(record.get("ref")))
        if component is None:
            raise BetaArtifactError("Cargo resolution has an unbound external package")
        external_packages.append(
            {
                "checksum": record.get("checksum"),
                "name": component.get("name"),
                "source": record.get("source"),
                "version": component.get("version"),
            }
        )
    external_packages.sort(
        key=lambda item: (str(item["name"]), str(item["version"]), str(item["source"]))
    )
    edge_count = sum(len(edge["dependsOn"]) for edge in dependencies)
    if (
        pinned["component_count"] != len(components)
        or pinned["dependency_edge_count"] != edge_count
        or pinned["sbom_resolution_sha256"]
        != sha256_bytes(canonical_json_bytes(sbom_identity))
        or pinned["metadata_resolution_sha256"]
        != sha256_bytes(canonical_json_bytes(metadata_identity))
        or pinned["external_packages"] != external_packages
        or pinned["dependencies"] != [dict(item) for item in dependencies]
        or pinned["resolution"] != [dict(item) for item in resolution]
    ):
        raise BetaArtifactError(
            "Cargo metadata differs from the committed beta resolution pin"
        )


def _validate_component_licenses(
    root: Path, components: Sequence[Mapping[str, object]]
) -> None:
    inventory = load_json(
        resolve_beneath(root, "packaging/licenses/beta-third-party-inventory.v1.json")
    )
    records = inventory.get("components") if isinstance(inventory, dict) else None
    policy_path = resolve_beneath(root, "packaging/licenses/third-party-policy.v1.json")
    policy = load_json(policy_path)
    if not isinstance(policy, dict):
        raise BetaArtifactError("third-party license policy is invalid")
    if (
        not isinstance(inventory, dict)
        or set(inventory)
        != {
            "component_count",
            "components",
            "policy_sha256",
            "release_profile",
            "schema_version",
            "status",
        }
        or inventory.get("schema_version")
        != "cigar.beta.third-party-license-inventory.v1"
        or inventory.get("release_profile") != beta_profile.PROFILE_ID
        or inventory.get("status") != "accepted-by-policy"
        or inventory.get("policy_sha256") != sha256_file(policy_path)
        or not isinstance(records, list)
        or inventory.get("component_count") != len(records)
    ):
        raise BetaArtifactError("approved beta license inventory is invalid")
    accepted = set(policy.get("accepted_expressions", []))
    review = set(policy.get("review_required", []))
    approved: dict[str, dict[str, object]] = {}
    for record in records:
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "license_expression",
                "name",
                "policy_status",
                "purl",
                "version",
            }
            or not all(
                isinstance(record.get(key), str) and record[key]
                for key in ("license_expression", "name", "purl", "version")
            )
            or record.get("policy_status") != "accepted-by-policy"
            or record["purl"] in approved
        ):
            raise BetaArtifactError("approved beta license record is invalid")
        approved[str(record["purl"])] = record
    if records != sorted(
        records, key=lambda item: (str(item["name"]), str(item["version"]))
    ):
        raise BetaArtifactError("approved beta license inventory is not ordered")
    observed_third_party: set[str] = set()
    for component in components:
        licenses = component.get("licenses")
        expression = (
            licenses[0].get("expression")
            if isinstance(licenses, list)
            and len(licenses) == 1
            and isinstance(licenses[0], dict)
            else None
        )
        if component.get("name") in REVIEWED_BETA_WORKSPACE_PACKAGES:
            if expression != "Apache-2.0":
                raise BetaArtifactError("beta workspace package license is unexpected")
            continue
        record = approved.get(component.get("purl"))
        purl = component.get("purl")
        if not isinstance(purl, str):
            raise BetaArtifactError("beta dependency purl is invalid")
        observed_third_party.add(purl)
        if (
            license_policy_status(str(expression), accepted, review)
            != "accepted-by-policy"
        ):
            raise BetaArtifactError(
                f"beta dependency is outside the approved license policy: {component.get('purl')}"
            )
        if not isinstance(record, dict) or record != {
            "license_expression": expression,
            "name": component.get("name"),
            "policy_status": "accepted-by-policy",
            "purl": purl,
            "version": component.get("version"),
        }:
            raise BetaArtifactError(
                f"beta dependency is absent from or conflicts with the reviewed "
                f"license inventory: {purl}"
            )
    if observed_third_party != set(approved):
        missing = sorted(set(approved) - observed_third_party)
        extra = sorted(observed_third_party - set(approved))
        raise BetaArtifactError(
            "beta Cargo closure differs from the reviewed license inventory; "
            f"missing={missing}, extra={extra}"
        )


def _default_binary_builder(
    root: Path,
    staging: Path,
    snapshot: GitSnapshot,
    expected_help: bytes,
    committed: Mapping[str, CommittedEntry],
    committed_tree_identity: str,
    *,
    python_path: Path | None,
    cargo_path: Path | None,
    rustc_path: Path | None,
    linker_path: Path | None,
    git_path: Path | None,
    crate_cache_path: Path | None,
) -> BinaryBuild:
    require_declared_host()
    if _verify_materialized_tree(root, committed) != committed_tree_identity:
        raise BetaArtifactError("staged build source differs before Cargo invocation")
    cargo_source = _secure_executable(cargo_path, "cargo")
    rustc_source = _secure_executable(rustc_path, "rustc")
    cargo = _actual_rust_tool(cargo_source, "cargo", root)
    rustc = _actual_rust_tool(rustc_source, "rustc", root)
    linker = _secure_executable(linker_path, "cc")
    git = _secure_executable(git_path, "git")
    if python_path is None:
        raise BetaArtifactError("beta release build requires an explicit Python path")
    if crate_cache_path is None:
        raise BetaArtifactError("beta release build requires an explicit crate cache")
    python = _validate_python_runtime(python_path)
    (
        vendor,
        cargo_homes,
        vendor_entries,
        vendor_identity,
        dependency_materials,
    ) = _prepare_verified_vendor(
        root=root, crate_cache=crate_cache_path, staging=staging
    )

    def verify_dependency_sources() -> None:
        if _verify_materialized_tree(vendor, vendor_entries) != vendor_identity:
            raise BetaArtifactError("verified Cargo dependency source tree changed")

    verify_dependency_sources()
    target_directory = staging / "cargo-target"
    target_directory.mkdir(mode=0o700)
    environment = _cargo_environment(
        root=root,
        target_directory=target_directory,
        snapshot=snapshot,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        cargo_home=cargo_homes[0],
    )
    cargo_identity, rustc_identity, target_libdir = _validate_rust_toolchain(
        root=root,
        cargo=cargo,
        rustc=rustc,
        environment=environment,
    )
    rust_notice = _rust_standard_library_notice(
        root=root, rustc=rustc, environment=environment
    )
    _verify_beta_license_sources(
        root=root, vendor_entries=vendor_entries, rust_notice=rust_notice
    )
    rust_target_material = _rust_target_material(
        target_libdir, rustc_identity=rustc_identity, rust_notice=rust_notice
    )

    def capture_tools() -> tuple[dict[str, object], ...]:
        records = [
            _tool_record(cargo, "cargo", cargo_identity),
            _tool_record(rustc, "rustc", rustc_identity),
            _tool_record(
                linker,
                "linker",
                _tool_version(
                    linker,
                    ["--version"],
                    root=root,
                    environment=environment,
                    name="linker",
                ),
            ),
            _tool_record(
                git,
                "git",
                _tool_version(
                    git,
                    ["--version"],
                    root=root,
                    environment=environment,
                    name="git",
                ),
            ),
            *_python_runtime_tool_records(python),
        ]
        if cargo_source.resolve(strict=True).name == "rustup":
            rustup = cargo_source.resolve(strict=True)
            records.append(
                _tool_record(
                    rustup,
                    "rustup",
                    _tool_version(
                        rustup,
                        ["--version"],
                        root=root,
                        environment=environment,
                        name="rustup",
                    ),
                )
            )
        return tuple(sorted(records, key=lambda item: str(item["name"])))

    tools = capture_tools()
    metadata_command = _cargo_command(
        cargo,
        vendor,
        [
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
            "crates/cigar-cli/Cargo.toml",
            "--filter-platform",
            beta_profile.TARGET_TRIPLE,
            "--no-default-features",
            "--features",
            "beta-embedded",
        ],
    )
    metadata_payload = _run_checked(
        metadata_command,
        cwd=root,
        env=environment,
        timeout=300,
        maximum=MAX_CARGO_OUTPUT_BYTES,
        label="beta Cargo metadata",
    )
    if _verify_materialized_tree(root, committed) != committed_tree_identity:
        raise BetaArtifactError("staged build source changed during Cargo metadata")
    verify_dependency_sources()
    components, dependencies = _cargo_components(
        load_json_bytes(metadata_payload, "beta Cargo metadata"), root=root
    )
    _validate_component_licenses(root, components)
    command = _cargo_command(cargo, vendor, beta_profile.BETA_BUILD_COMMAND[1:])
    _run_checked(
        command,
        cwd=root,
        env=environment,
        timeout=3600,
        maximum=MAX_CARGO_OUTPUT_BYTES,
        label="beta Cargo build",
    )
    if _verify_materialized_tree(root, committed) != committed_tree_identity:
        raise BetaArtifactError("staged build source changed during the first build")
    verify_dependency_sources()
    binary = target_directory / beta_profile.TARGET_TRIPLE / "release" / "cigar"
    payload = _read_stable_file(binary, MAX_BINARY_BYTES, "built beta binary")
    validate_elf_linux_x86_64(payload)
    second_target = staging / "cargo-target-same-builder-repeatability"
    second_target.mkdir(mode=0o700)
    second_environment = _cargo_environment(
        root=root,
        target_directory=second_target,
        snapshot=snapshot,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        cargo_home=cargo_homes[1],
    )
    _run_checked(
        command,
        cwd=root,
        env=second_environment,
        timeout=3600,
        maximum=MAX_CARGO_OUTPUT_BYTES,
        label="second clean-target same-builder repeatability build",
    )
    if _verify_materialized_tree(root, committed) != committed_tree_identity:
        raise BetaArtifactError("staged build source changed during the second build")
    verify_dependency_sources()
    second_binary = second_target / beta_profile.TARGET_TRIPLE / "release" / "cigar"
    second_payload = _read_stable_file(
        second_binary,
        MAX_BINARY_BYTES,
        "second clean-target same-builder repeatability binary",
    )
    if second_payload != payload:
        raise BetaArtifactError(
            "same-builder clean-target repeatability builds are not byte-identical; "
            f"first_sha256={sha256_bytes(payload)} "
            f"second_sha256={sha256_bytes(second_payload)}"
        )
    components, dependencies = _augment_native_resolution(
        components,
        dependencies,
        elf_needed_libraries(payload),
        _rust_standard_library_component(rust_target_material),
    )
    executable_snapshot = staging / "binary-execution-snapshot" / "cigar"
    _write_private(executable_snapshot, payload)
    os.chmod(executable_snapshot, 0o500)
    version_document, help_sha256 = _run_beta_binary(
        executable_snapshot, snapshot, expected_help
    )
    if (
        _read_stable_file(
            executable_snapshot, MAX_BINARY_BYTES, "executed beta binary snapshot"
        )
        != payload
    ):
        raise BetaArtifactError(
            "executed beta binary snapshot changed during inspection"
        )
    verify_dependency_sources()
    if capture_tools() != tools:
        raise BetaArtifactError(
            "release build tool bytes or identities changed during use"
        )
    if (
        _rust_standard_library_notice(root=root, rustc=rustc, environment=environment)
        != rust_notice
    ):
        raise BetaArtifactError("Rust standard-library notice changed during the build")
    if (
        _rust_target_material(
            target_libdir, rustc_identity=rustc_identity, rust_notice=rust_notice
        )
        != rust_target_material
    ):
        raise BetaArtifactError("Rust target library bytes changed during the build")
    return BinaryBuild(
        payload,
        version_document,
        help_sha256,
        components,
        dependencies,
        tools,
        dependency_materials,
        (rust_target_material,),
    )


def _resolved_cargo_evidence(
    root: Path, snapshot: GitSnapshot, crate_cache: Path
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    with tempfile.TemporaryDirectory(prefix="cigar-beta-metadata-") as raw:
        staging = Path(raw)
        os.chmod(staging, 0o700)
        cargo_source = _secure_executable(None, "cargo")
        rustc_source = _secure_executable(None, "rustc")
        cargo = _actual_rust_tool(cargo_source, "cargo", root)
        rustc = _actual_rust_tool(rustc_source, "rustc", root)
        linker = _secure_executable(None, "cc")
        vendor, cargo_homes, vendor_entries, vendor_identity, _materials = (
            _prepare_verified_vendor(
                root=root, crate_cache=crate_cache, staging=staging
            )
        )
        target = staging / "target"
        target.mkdir(mode=0o700)
        environment = _cargo_environment(
            root=root,
            target_directory=target,
            snapshot=snapshot,
            cargo=cargo,
            rustc=rustc,
            linker=linker,
            cargo_home=cargo_homes[0],
        )
        _cargo_identity, _rustc_identity, _target_libdir = _validate_rust_toolchain(
            root=root,
            cargo=cargo,
            rustc=rustc,
            environment=environment,
        )
        rust_notice = _rust_standard_library_notice(
            root=root, rustc=rustc, environment=environment
        )
        _verify_beta_license_sources(
            root=root, vendor_entries=vendor_entries, rust_notice=rust_notice
        )
        payload = _run_checked(
            _cargo_command(
                cargo,
                vendor,
                [
                    "metadata",
                    "--locked",
                    "--offline",
                    "--format-version",
                    "1",
                    "--manifest-path",
                    "crates/cigar-cli/Cargo.toml",
                    "--filter-platform",
                    beta_profile.TARGET_TRIPLE,
                    "--no-default-features",
                    "--features",
                    "beta-embedded",
                ],
            ),
            cwd=root,
            env=environment,
            timeout=300,
            maximum=MAX_CARGO_OUTPUT_BYTES,
            label="isolated beta Cargo metadata recomputation",
        )
        if _verify_materialized_tree(vendor, vendor_entries) != vendor_identity:
            raise BetaArtifactError("verified Cargo dependency source tree changed")
    components, dependencies = _cargo_components(
        load_json_bytes(payload, "isolated beta Cargo metadata recomputation"),
        root=root,
    )
    _validate_component_licenses(root, components)
    return components, dependencies


def _internal_checksums(entries: Sequence[CommittedEntry]) -> bytes:
    return "".join(
        f"{sha256_bytes(entry.payload)}  {entry.path}\n"
        for entry in sorted(entries, key=lambda item: item.path.encode("utf-8"))
    ).encode("ascii")


def _artifact_record(
    path: Path, identifier: str, relative: str, contract: str
) -> dict[str, object]:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BetaArtifactError(f"staged artifact is not a regular file: {path}")
    return {
        "id": identifier,
        "path": relative,
        "sha256": sha256_file(path),
        "bytes": metadata.st_size,
        "contract": contract,
        "status": "passed",
    }


def _file_reference(path: Path, relative: str) -> dict[str, object]:
    metadata = path.stat(follow_symlinks=False)
    return {
        "path": relative,
        "sha256": sha256_file(path),
        "bytes": metadata.st_size,
    }


def _member_records(
    attributes: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    return [
        {
            "path": name,
            "sha256": attributes[name]["sha256"],
            "bytes": attributes[name]["size"],
            "mode": f"{int(attributes[name]['mode']):04o}",
        }
        for name in sorted(attributes, key=lambda value: value.encode("utf-8"))
    ]


def build_beta_sbom(
    *,
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    components: Sequence[Mapping[str, object]],
    dependencies: Sequence[Mapping[str, object]],
    member_bindings: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    artifact_binding = [
        {
            "id": record["id"],
            "path": record["path"],
            "sha256": record["sha256"],
            "bytes": record["bytes"],
        }
        for record in artifacts
    ]
    seed = sha256_bytes(
        canonical_json_bytes(
            {
                "artifacts": artifact_binding,
                "members": list(member_bindings),
                "dependencies": list(dependencies),
            }
        )
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}",
        "version": 1,
        "metadata": {
            "timestamp": snapshot.generated_at,
            "component": {
                "type": "application",
                "name": "cigar",
                "version": beta_profile.VERSION,
                "properties": [
                    {"name": "cigar:channel", "value": "beta"},
                    {
                        "name": "cigar:release-profile",
                        "value": beta_profile.PROFILE_ID,
                    },
                    {
                        "name": "cigar:source-revision",
                        "value": snapshot.revision,
                    },
                    {
                        "name": "cigar:target-triple",
                        "value": beta_profile.TARGET_TRIPLE,
                    },
                    {"name": "cigar:default-features", "value": "false"},
                    {"name": "cigar:enabled-features", "value": "beta-embedded"},
                    {"name": "cigar:production-ready", "value": "false"},
                ],
            },
        },
        "components": [dict(component) for component in components],
        "dependencies": [dict(dependency) for dependency in dependencies],
        "properties": [
            {
                "name": "cigar:artifact-binding",
                "value": canonical_json_bytes(artifact_binding)
                .decode("utf-8")
                .rstrip("\n"),
            },
            {
                "name": "cigar:archive-member-binding",
                "value": canonical_json_bytes(list(member_bindings))
                .decode("utf-8")
                .rstrip("\n"),
            },
        ],
    }


def _spdx_identifier(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", value)


def build_beta_spdx(
    *,
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    components: Sequence[Mapping[str, object]],
    dependencies: Sequence[Mapping[str, object]],
    member_bindings: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    component_ids = {
        str(component["bom-ref"]): _spdx_identifier(
            "Package-" + sha256_bytes(str(component["bom-ref"]).encode())[:24]
        )
        for component in components
    }
    packages = []
    for component in components:
        licenses = component.get("licenses")
        if (
            not isinstance(licenses, list)
            or len(licenses) != 1
            or not isinstance(licenses[0], dict)
            or not isinstance(licenses[0].get("expression"), str)
        ):
            raise BetaArtifactError("SPDX component license binding is incomplete")
        package = {
            "name": component["name"],
            "SPDXID": component_ids[str(component["bom-ref"])],
            "versionInfo": component["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": licenses[0]["expression"],
            "licenseDeclared": licenses[0]["expression"],
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component["purl"],
                }
            ],
        }
        packages.append(package)
    packages.sort(key=lambda item: str(item["SPDXID"]).encode("utf-8"))
    files = []
    file_ids: list[str] = []
    for binding in member_bindings:
        artifact_path = str(binding["path"])
        members = binding.get("members")
        if not isinstance(members, list):
            raise BetaArtifactError("SPDX archive member binding is invalid")
        for member in members:
            if not isinstance(member, dict):
                raise BetaArtifactError("SPDX archive member record is invalid")
            file_name = f"{artifact_path}!/{member['path']}"
            identifier = _spdx_identifier(
                "File-" + sha256_bytes(file_name.encode("utf-8"))[:32]
            )
            file_ids.append(identifier)
            files.append(
                {
                    "fileName": file_name,
                    "SPDXID": identifier,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": member["sha256"],
                        }
                    ],
                    "licenseConcluded": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "comment": f"mode={member['mode']};bytes={member['bytes']}",
                }
            )
    files.sort(key=lambda item: str(item["fileName"]).encode("utf-8"))
    root_refs = [
        str(component["bom-ref"])
        for component in components
        if component.get("name") == "cigar-cli"
    ]
    if len(root_refs) != 1:
        raise BetaArtifactError("SPDX requires exactly one cigar-cli root package")
    root_id = component_ids[root_refs[0]]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        },
        *(
            {
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": identifier,
            }
            for identifier in sorted(file_ids, key=lambda value: value.encode("utf-8"))
        ),
    ]
    for edge in dependencies:
        source_id = component_ids.get(str(edge["ref"]))
        targets = edge.get("dependsOn")
        if source_id is None or not isinstance(targets, list):
            raise BetaArtifactError("SPDX dependency edge is invalid")
        for target in targets:
            target_id = component_ids.get(str(target))
            if target_id is None:
                raise BetaArtifactError("SPDX dependency target is missing")
            relationships.append(
                {
                    "spdxElementId": source_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target_id,
                }
            )
    relationships.sort(
        key=lambda item: (
            str(item["spdxElementId"]),
            str(item["relationshipType"]),
            str(item["relatedSpdxElement"]),
        )
    )
    artifact_binding = [
        {
            "id": record["id"],
            "path": record["path"],
            "sha256": record["sha256"],
            "bytes": record["bytes"],
        }
        for record in artifacts
    ]
    namespace_seed = sha256_bytes(
        canonical_json_bytes(
            {"artifacts": artifact_binding, "members": list(member_bindings)}
        )
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"cigar-{beta_profile.VERSION}-beta-candidate",
        "documentNamespace": f"https://cigar.invalid/spdx/{namespace_seed}",
        "creationInfo": {
            "created": snapshot.generated_at,
            "creators": [f"Tool: cigar-beta-artifacts-{beta_profile.VERSION}"],
        },
        "documentDescribes": [root_id],
        "documentComment": canonical_json_bytes(artifact_binding)
        .decode("utf-8")
        .rstrip("\n"),
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }


def _provenance_host(host: Mapping[str, str]) -> dict[str, str]:
    expected = {
        "system": "linux",
        "machine": "x86_64",
        "distribution": beta_profile.QUALIFIED_DISTRIBUTION,
        "distribution_version": beta_profile.QUALIFIED_DISTRIBUTION_VERSION,
        "libc": "glibc",
        "libc_version": beta_profile.MINIMUM_GLIBC_VERSION,
        "glibc_identity": f"glibc {beta_profile.MINIMUM_GLIBC_VERSION}",
        "runtime_baseline": beta_profile.RUNTIME_BASELINE,
        "target": beta_profile.TARGET_TRIPLE,
    }
    if dict(host) != expected:
        raise BetaArtifactError(
            "beta provenance host identity is not the exact baseline"
        )
    return {
        "system": host["system"],
        "machine": host["machine"],
        "distribution": host["distribution"],
        "distributionVersion": host["distribution_version"],
        "libc": host["libc"],
        "libcVersion": host["libc_version"],
        "glibcIdentity": host["glibc_identity"],
        "runtimeBaseline": host["runtime_baseline"],
        "target": host["target"],
    }


def build_beta_provenance(
    *,
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    source_descriptor: Mapping[str, object],
    source_descriptor_reference: Mapping[str, object],
    tools: Sequence[Mapping[str, object]],
    dependency_materials: Sequence[Mapping[str, object]],
    toolchain_materials: Sequence[Mapping[str, object]],
    host: Mapping[str, str],
    builder_id: str,
    started_on: str,
    finished_on: str,
) -> dict[str, object]:
    if (
        not builder_id
        or builder_id != builder_id.strip()
        or len(builder_id.encode("utf-8")) > 256
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in builder_id
        )
    ):
        raise BetaArtifactError("builder id is invalid")
    parsed_builder = urllib.parse.urlsplit(builder_id)
    if (
        re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed_builder.scheme) is None
        or parsed_builder.fragment
        or (parsed_builder.scheme != "urn" and not parsed_builder.netloc)
        or parsed_builder.username is not None
        or parsed_builder.password is not None
    ):
        raise BetaArtifactError("builder id must be an absolute non-credential URI")
    subjects = [
        {
            "name": record["path"],
            "digest": {"sha256": record["sha256"]},
        }
        for record in artifacts
    ]
    input_materials = [
        {
            "name": record["path"],
            "digest": {"sha256": record["sha256"]},
            "annotations": {"kind": kind},
        }
        for kind, records in (
            ("policy-input", source_descriptor["policy_inputs"]),
            ("tool-input", source_descriptor["tool_inputs"]),
        )
        for record in records
    ]
    source_archive = source_descriptor.get("source_archive")
    if not isinstance(source_archive, dict):
        raise BetaArtifactError("SLSA source archive binding is missing")
    git_source_material = {
        "uri": f"urn:cigar:git:{snapshot.revision}",
        "name": "committed-source",
        "digest": {
            "gitCommit": snapshot.revision,
            "gitTree": snapshot.tree,
        },
        "annotations": {"committed": True},
    }
    source_archive_material = {
        "uri": f"urn:cigar:source-archive:{source_archive.get('sha256')}",
        "name": source_archive.get("name"),
        "digest": {"sha256": source_archive.get("sha256")},
        "annotations": {
            "archiveBytes": source_archive.get("bytes"),
            "kind": "canonical-source-archive",
        },
    }
    dependency_records = [dict(record) for record in dependency_materials]
    if not 1 <= len(dependency_records) <= 256:
        raise BetaArtifactError(
            "SLSA dependency materials are outside the reviewed bounds"
        )
    dependency_uris: set[str] = set()
    for record in dependency_records:
        annotations = record.get("annotations")
        digest = record.get("digest")
        uri = record.get("uri")
        if (
            set(record) != {"annotations", "digest", "name", "uri"}
            or not isinstance(uri, str)
            or not uri.startswith("pkg:cargo/")
            or uri in dependency_uris
            or not isinstance(record.get("name"), str)
            or not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", digest["sha256"]) is None
            or not isinstance(annotations, dict)
            or set(annotations) != {"archiveBytes", "source", "sourceTreeSha256"}
            or isinstance(annotations.get("archiveBytes"), bool)
            or not isinstance(annotations.get("archiveBytes"), int)
            or annotations["archiveBytes"] <= 0
            or annotations.get("source")
            != "registry+https://github.com/rust-lang/crates.io-index"
            or not isinstance(annotations.get("sourceTreeSha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", annotations["sourceTreeSha256"]) is None
        ):
            raise BetaArtifactError("SLSA dependency material is invalid")
        dependency_uris.add(uri)
    dependency_records.sort(key=lambda item: str(item["uri"]).encode("utf-8"))
    toolchain_records = [dict(record) for record in toolchain_materials]
    if len(toolchain_records) != 1:
        raise BetaArtifactError("SLSA must bind one Rust target library material")
    rust_material = toolchain_records[0]
    rust_annotations = rust_material.get("annotations")
    if (
        set(rust_material) != {"annotations", "digest", "name", "uri"}
        or rust_material.get("name") != "rust-target-libdir"
        or not isinstance(rust_material.get("uri"), str)
        or not str(rust_material["uri"]).startswith(
            f"urn:cigar:rust-target-libdir:{beta_profile.TARGET_TRIPLE}:"
        )
        or not isinstance(rust_material.get("digest"), dict)
        or re.fullmatch(r"[0-9a-f]{64}", str(rust_material["digest"].get("sha256", "")))
        is None
        or not isinstance(rust_annotations, dict)
        or set(rust_annotations)
        != {
            "bytes",
            "fileCount",
            "noticeBytes",
            "noticeSha256",
            "rustcCommit",
            "target",
            "toolchainVersion",
        }
        or rust_annotations.get("target") != beta_profile.TARGET_TRIPLE
        or rust_annotations.get("toolchainVersion")
        != beta_profile.RUST_TOOLCHAIN_VERSION
        or re.fullmatch(r"[0-9a-f]{40}", str(rust_annotations.get("rustcCommit", "")))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(rust_annotations.get("noticeSha256", "")))
        is None
        or any(
            isinstance(rust_annotations.get(key), bool)
            or not isinstance(rust_annotations.get(key), int)
            or rust_annotations[key] <= 0
            for key in ("bytes", "fileCount", "noticeBytes")
        )
    ):
        raise BetaArtifactError("SLSA Rust target library material is invalid")
    materials = [
        git_source_material,
        source_archive_material,
        *input_materials,
        *dependency_records,
        *toolchain_records,
    ]
    materials.sort(
        key=lambda item: (
            str(item.get("uri", "")).encode("utf-8"),
            str(item.get("name", "")).encode("utf-8"),
        )
    )
    started = started_on
    finished = finished_on
    for value, label in ((started, "start"), (finished, "finish")):
        if (
            not isinstance(value, str)
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
            )
            is None
        ):
            raise BetaArtifactError(f"SLSA build {label} timestamp is invalid")
    if finished < started:
        raise BetaArtifactError("SLSA build finish precedes its start")
    external_parameters = {
        "releaseProfile": beta_profile.PROFILE_ID,
        "productVersion": beta_profile.VERSION,
        "tag": beta_profile.TAG,
        "target": beta_profile.TARGET_TRIPLE,
        "command": list(beta_profile.BETA_BUILD_COMMAND),
        "defaultFeatures": False,
        "enabledFeatures": ["beta-embedded"],
        "sourceRevisionEnvironment": "CIGAR_SOURCE_REVISION",
    }
    internal_parameters = {
        "sourceDateEpoch": snapshot.source_date_epoch,
        "source": snapshot.source_identity(),
        "sourceDescriptor": dict(source_descriptor_reference),
        "networkMode": "cargo-offline-requested",
        "dependencySource": {
            "mode": "verified-read-only-directory-source",
            "packageCount": len(dependency_records),
            "snapshotSha256": sha256_bytes(canonical_json_bytes(dependency_records)),
        },
        "toolchainSource": {
            "targetLibdirSha256": rust_material["digest"]["sha256"],
            "fileCount": rust_annotations["fileCount"],
            "bytes": rust_annotations["bytes"],
            "noticeBytes": rust_annotations["noticeBytes"],
            "noticeSha256": rust_annotations["noticeSha256"],
            "rustcCommit": rust_annotations["rustcCommit"],
            "target": rust_annotations["target"],
            "toolchainVersion": rust_annotations["toolchainVersion"],
        },
        "locale": "C",
        "timezone": "UTC",
        "host": _provenance_host(host),
        "tools": [dict(record) for record in tools],
        "binaryRepeatability": {
            "scope": "bin/cigar-payload",
            "sameBuilder": True,
            "cleanTargetDirectoryCount": 2,
            "buildCount": 2,
            "byteIdentical": True,
        },
    }
    invocation_id = "sha256:" + sha256_bytes(
        canonical_json_bytes(
            {
                "builder": builder_id,
                "subjects": subjects,
                "externalParameters": external_parameters,
                "internalParameters": internal_parameters,
                "resolvedDependencies": materials,
                "startedOn": started,
                "finishedOn": finished,
            }
        )
    )
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": beta_profile.BETA_SLSA_BUILD_TYPE,
                "externalParameters": external_parameters,
                "internalParameters": internal_parameters,
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started,
                    "finishedOn": finished,
                },
                "byproducts": [
                    {
                        "name": source_descriptor_reference["path"],
                        "digest": {"sha256": source_descriptor_reference["sha256"]},
                    }
                ],
            },
        },
    }


def _source_build_record() -> dict[str, object]:
    return {
        "kind": "committed-source-selection",
        "source": "git-ls-tree-and-cat-file-object-traversal",
        "generator": "scripts/release/beta_artifacts.py",
    }


def _binary_build_record(
    version_document: Mapping[str, object], help_sha256: str
) -> dict[str, object]:
    return {
        "kind": "rust-binary",
        "command": list(beta_profile.BETA_BUILD_COMMAND),
        "package": "cigar-cli",
        "binary": "cigar",
        "target": beta_profile.TARGET_TRIPLE,
        "default_features": False,
        "enabled_features": ["beta-embedded"],
        "source_revision_environment": "CIGAR_SOURCE_REVISION",
        "same_builder_repeatability": {
            "scope": "binary-payload",
            "clean_target_directories": 2,
            "builds": 2,
            "byte_identical": True,
        },
        "version_identity": dict(version_document),
        "version_identity_sha256": sha256_bytes(canonical_json_bytes(version_document)),
        "help_sha256": help_sha256,
    }


def _write_private(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise BetaArtifactError(f"refusing to overwrite staged output: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise BetaArtifactError(
                        f"short write creating staged output: {path}"
                    )
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot create staged output {path}: {error}"
        ) from error


def _write_private_json(path: Path, value: object) -> None:
    _write_private(path, canonical_json_bytes(value))


def _contract_policy(
    root: Path, matrix_entry: Mapping[str, object]
) -> dict[str, object]:
    relative = matrix_entry.get("contract")
    if not isinstance(relative, str):
        raise BetaArtifactError("artifact matrix contract path is invalid")
    path = resolve_beneath(root, relative)
    expected_digest = beta_profile.EXPECTED_CONTRACT_SHA256.get(relative)
    if expected_digest is None or sha256_file(path) != expected_digest:
        raise BetaArtifactError("beta package contract is not digest-pinned")
    document = load_json(path)
    factory = beta_profile.GENERATED_DOCUMENTS.get(relative)
    if factory is not None:
        if document != factory():
            raise BetaArtifactError(
                "beta package contract differs from its pinned definition"
            )
        return {
            "path": path,
            "relative": relative,
            "allow": document["allow"],
            "deny": document["deny"],
            "required": document["required"],
            "modes": document["modes"],
            "max_entries": document["max_entries"],
            "max_member_bytes": document["max_member_bytes"],
            "max_total_bytes": document["max_total_bytes"],
            "line_endings": document["line_endings"],
            "content_scan": document["content_scan"],
            "content_scan_exemptions": document["content_scan_exemptions"],
            "checksum_manifest": document.get("checksum_manifest"),
        }
    required_keys = {
        "schema_version",
        "id",
        "formats",
        "allow",
        "deny",
        "required",
        "symlinks",
        "line_endings",
        "modes",
        "max_entries",
        "max_member_bytes",
        "max_total_bytes",
        "content_scan",
        "content_scan_exemptions",
    }
    if (
        not isinstance(document, dict)
        or not required_keys.issubset(document)
        or document.get("schema_version") != "cigar.package-contract.v1"
        or document.get("formats") != ["tar.gz"]
        or document.get("symlinks") != "forbid"
        or document.get("line_endings") != "lf"
        or document.get("content_scan") is not True
    ):
        raise BetaArtifactError(
            "source-derived package contract is weakened or invalid"
        )
    return {
        "path": path,
        "relative": relative,
        "allow": document["allow"],
        "deny": document["deny"],
        "required": document["required"],
        "modes": document["modes"],
        "max_entries": document["max_entries"],
        "max_member_bytes": document["max_member_bytes"],
        "max_total_bytes": document["max_total_bytes"],
        "line_endings": document["line_endings"],
        "content_scan": document["content_scan"],
        "content_scan_exemptions": document["content_scan_exemptions"],
        "checksum_manifest": document.get("checksum_manifest"),
    }


def _validate_gzip_header(payload: bytes, epoch: int) -> None:
    header = payload[:10]
    if (
        len(header) != 10
        or header[:3] != b"\x1f\x8b\x08"
        or header[3] != 0
        or int.from_bytes(header[4:8], "little") != epoch
        or header[8] != 2
        or header[9] != 255
    ):
        raise BetaArtifactError("artifact gzip header is not deterministic")


def _read_canonical_tar(
    payload: bytes,
    *,
    epoch: int,
    policy: Mapping[str, object],
    retained: Sequence[str],
) -> tuple[dict[str, bytes | None], dict[str, dict[str, object]], list[str]]:
    if not payload or len(payload) > 64 * 1024 * 1024:
        raise BetaArtifactError(
            "compressed beta archive exceeds the reviewed byte limit"
        )
    _validate_gzip_header(payload, epoch)
    raw_limit = min(
        512 * 1024 * 1024,
        int(policy["max_total_bytes"])
        + int(policy["max_entries"]) * 8192
        + tarfile.RECORDSIZE,
    )
    decompressor = zlib.decompressobj(wbits=31)
    expanded = bytearray()
    try:
        for offset in range(0, len(payload), 1024 * 1024):
            remaining = raw_limit + 1 - len(expanded)
            if remaining <= 0:
                raise BetaArtifactError(
                    "beta archive raw tar exceeds the header/payload expansion limit"
                )
            expanded.extend(
                decompressor.decompress(
                    payload[offset : offset + 1024 * 1024], remaining
                )
            )
            if len(expanded) > raw_limit:
                raise BetaArtifactError(
                    "beta archive raw tar exceeds the header/payload expansion limit"
                )
            if decompressor.unused_data:
                raise BetaArtifactError(
                    "beta archive contains trailing or concatenated gzip data"
                )
        expanded.extend(decompressor.flush(raw_limit + 1 - len(expanded)))
    except zlib.error as error:
        raise BetaArtifactError(
            f"beta archive gzip stream is invalid: {error}"
        ) from error
    if (
        len(expanded) > raw_limit
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise BetaArtifactError("beta archive gzip stream is truncated or ambiguous")
    names: list[str] = []
    payloads: dict[str, bytes | None] = {}
    attributes: dict[str, dict[str, object]] = {}
    aliases: dict[str, str] = {}
    total = 0
    canonical = io.BytesIO()
    try:
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=9, fileobj=canonical, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as canonical_archive:
                with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
                    for member in archive:
                        if len(names) >= int(policy["max_entries"]):
                            raise BetaArtifactError(
                                "beta archive entry count exceeds its contract"
                            )
                        name = safe_relative_path(member.name)
                        alias = unicodedata.normalize("NFC", name).casefold()
                        if name in attributes or alias in aliases:
                            raise BetaArtifactError(
                                f"duplicate or portable-colliding archive member: {name}"
                            )
                        aliases[alias] = name
                        if not member.isfile():
                            raise BetaArtifactError(
                                f"beta archive member is not a regular file: {name}"
                            )
                        if (
                            member.uid != 0
                            or member.gid != 0
                            or member.uname != ""
                            or member.gname != ""
                            or member.mtime != epoch
                            or member.mode not in {0o644, 0o755}
                        ):
                            raise BetaArtifactError(
                                f"beta archive member metadata is not normalized: {name}"
                            )
                        if set(member.pax_headers) - {"path"}:
                            raise BetaArtifactError(
                                f"beta archive has unexpected PAX metadata: {name}"
                            )
                        if member.size < 0 or member.size > int(
                            policy["max_member_bytes"]
                        ):
                            raise BetaArtifactError(
                                f"beta archive member exceeds its contract: {name}"
                            )
                        total += member.size
                        if total > int(policy["max_total_bytes"]):
                            raise BetaArtifactError(
                                "beta archive expanded bytes exceed its contract"
                            )
                        handle = archive.extractfile(member)
                        if handle is None:
                            raise BetaArtifactError(
                                f"cannot read beta archive member: {name}"
                            )
                        member_payload = handle.read(member.size + 1)
                        if len(member_payload) != member.size:
                            raise BetaArtifactError(
                                f"beta archive member changed size: {name}"
                            )
                        findings = scan_payload(
                            name,
                            member_payload,
                            list(policy["content_scan_exemptions"]),
                        )
                        attributes[name] = {
                            "kind": "file",
                            "mode": member.mode,
                            "mtime": member.mtime,
                            "uid": member.uid,
                            "gid": member.gid,
                            "size": member.size,
                            "sha256": sha256_bytes(member_payload),
                            "contains_cr": b"\r" in member_payload,
                            "content_findings": findings,
                        }
                        payloads[name] = (
                            member_payload if matches(name, retained) else None
                        )
                        names.append(name)
                        information = tarfile.TarInfo(name)
                        information.size = len(member_payload)
                        information.mode = member.mode
                        information.mtime = epoch
                        information.uid = 0
                        information.gid = 0
                        information.uname = ""
                        information.gname = ""
                        canonical_archive.addfile(
                            information, io.BytesIO(member_payload)
                        )
    except (OSError, tarfile.TarError) as error:
        raise BetaArtifactError(
            f"cannot inspect canonical beta archive: {error}"
        ) from error
    if names != sorted(names, key=lambda value: value.encode("utf-8")):
        raise BetaArtifactError(
            "beta archive members are not deterministically ordered"
        )
    if canonical.getvalue() != payload:
        raise BetaArtifactError(
            "beta archive is not the single canonical gzip/PAX byte representation"
        )
    return payloads, attributes, names


def _archive_member_bindings(
    *,
    root: Path,
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    artifact_payloads: Mapping[str, bytes],
) -> list[dict[str, object]]:
    matrix = beta_profile.expected_artifact_matrix()
    bindings: list[dict[str, object]] = []
    for record, matrix_entry in zip(artifacts, matrix["artifacts"], strict=True):
        relative = str(record["path"])
        payload = artifact_payloads.get(relative)
        if payload is None:
            raise BetaArtifactError(f"cannot bind archive members for {relative}")
        policy = _contract_policy(root, matrix_entry)
        _, attributes, _ = _read_canonical_tar(
            payload,
            epoch=snapshot.source_date_epoch,
            policy=policy,
            retained=[],
        )
        bindings.append(
            {
                "id": record["id"],
                "path": relative,
                "sha256": record["sha256"],
                "bytes": record["bytes"],
                "members": _member_records(attributes),
            }
        )
    return bindings


def _attribute_tree(
    attributes: Mapping[str, Mapping[str, object]], names: Iterable[str]
) -> str:
    digest = hashlib.sha256()
    count = 0
    for name in sorted(names, key=lambda value: value.encode("utf-8")):
        attribute = attributes[name]
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(attribute["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(f"{attribute['mode']:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(str(attribute["sha256"])))
        digest.update(b"\n")
        count += 1
    if count == 0:
        raise BetaArtifactError("verified artifact has no payload files")
    return digest.hexdigest()


def _validate_beta_metadata(
    *,
    payload: bytes,
    matrix_entry: Mapping[str, object],
    policy: Mapping[str, object],
    source_descriptor: Mapping[str, object],
    snapshot: GitSnapshot,
    attributes: Mapping[str, Mapping[str, object]],
    expected_help_sha256: str,
) -> dict[str, object]:
    document = load_json_bytes(payload, "beta RELEASE-METADATA.json")
    if canonical_json_bytes(document) != payload:
        raise BetaArtifactError("beta release metadata is not canonical JSON")
    required = {
        "schema_version",
        "release_profile",
        "product_version",
        "tag",
        "prerelease",
        "production_ready",
        "artifact_id",
        "source_date_epoch",
        "source",
        "contract",
        "payload",
        "build",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise BetaArtifactError("beta release metadata has an unexpected shape")
    expected_scalars = {
        "schema_version": "cigar.beta.release-metadata.v1",
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "tag": beta_profile.TAG,
        "prerelease": True,
        "production_ready": False,
        "artifact_id": matrix_entry["id"],
        "source_date_epoch": snapshot.source_date_epoch,
        "source": snapshot.source_identity(),
        "contract": {
            "path": policy["relative"],
            "sha256": sha256_file(policy["path"]),
        },
    }
    for key, expected in expected_scalars.items():
        if document.get(key) != expected:
            raise BetaArtifactError(f"beta release metadata {key} binding mismatch")
    descriptor_git = source_descriptor.get("git")
    if not isinstance(descriptor_git, dict) or (
        descriptor_git.get("revision"),
        descriptor_git.get("tree"),
    ) != (snapshot.revision, snapshot.tree):
        raise BetaArtifactError("source descriptor and artifact metadata disagree")
    payload_names = [name for name in attributes if name != "RELEASE-METADATA.json"]
    expected_payload = {
        "tree_sha256": _attribute_tree(attributes, payload_names),
        "file_count": len(payload_names),
    }
    if document.get("payload") != expected_payload:
        raise BetaArtifactError("beta release metadata payload binding mismatch")
    if matrix_entry.get("kind") == "binary-archive":
        version = expected_version_document(snapshot)
        expected_build = _binary_build_record(version, expected_help_sha256)
        observed_build = document.get("build")
        if not isinstance(observed_build, dict):
            raise BetaArtifactError("beta binary build metadata is invalid")
        if observed_build != expected_build:
            raise BetaArtifactError(
                "beta binary build feature or command binding mismatch"
            )
        if (
            not isinstance(observed_build.get("help_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", observed_build["help_sha256"]) is None
        ):
            raise BetaArtifactError("beta binary help binding is invalid")
    elif document.get("build") != _source_build_record():
        raise BetaArtifactError("source-derived artifact build binding mismatch")
    return document


def _validate_committed_payload(
    *,
    matrix_entry: Mapping[str, object],
    attributes: Mapping[str, Mapping[str, object]],
    committed: Mapping[str, CommittedEntry],
) -> None:
    observed_names = set(attributes) - {"RELEASE-METADATA.json"}
    if matrix_entry.get("kind") == "binary-archive":
        for name in ("LICENSE", "NOTICE"):
            expected = committed.get(name)
            observed = attributes.get(name)
            if expected is None or expected.kind != "file" or observed is None:
                raise BetaArtifactError(
                    f"beta binary archive is missing committed payload: {name}"
                )
            if (
                observed.get("sha256") != sha256_bytes(expected.payload)
                or observed.get("size") != len(expected.payload)
                or observed.get("mode") != 0o644
            ):
                raise BetaArtifactError(
                    f"beta binary archive substituted committed payload: {name}"
                )
        return
    manifest = beta_profile.expected_source_archives()
    declarations = [
        entry
        for entry in manifest["archives"]
        if entry.get("id") == matrix_entry.get("id")
    ]
    if len(declarations) != 1:
        raise BetaArtifactError("source-derived beta archive declaration is ambiguous")
    selected = _select_entries(
        committed,
        declarations[0]["include"],
        manifest["always_exclude"],
        str(matrix_entry["id"]),
    )
    expected_by_name = {entry.path: entry for entry in selected}
    if observed_names != set(expected_by_name):
        raise BetaArtifactError(
            f"beta archive differs from committed source selection: {matrix_entry['id']}"
        )
    for name, expected in expected_by_name.items():
        observed = attributes[name]
        if (
            observed.get("sha256") != sha256_bytes(expected.payload)
            or observed.get("size") != len(expected.payload)
            or observed.get("mode") != expected.mode
        ):
            raise BetaArtifactError(
                f"beta archive substituted committed source bytes: {name}"
            )


def verify_beta_archive(
    *,
    root: Path,
    archive_payload: bytes,
    archive_name: str,
    matrix_entry: Mapping[str, object],
    source_descriptor: Mapping[str, object],
    snapshot: GitSnapshot,
    committed: Mapping[str, CommittedEntry],
    execute_binary: bool,
) -> dict[str, object]:
    policy = _contract_policy(root, matrix_entry)
    retained = ["RELEASE-METADATA.json"]
    checksum_spec = policy.get("checksum_manifest")
    if isinstance(checksum_spec, dict):
        retained.append(str(checksum_spec["path"]))
    if matrix_entry.get("kind") == "binary-archive":
        retained.append("bin/cigar")
    attributes_payloads, attributes, ordered_names = _read_canonical_tar(
        archive_payload,
        epoch=snapshot.source_date_epoch,
        policy=policy,
        retained=retained,
    )
    if list(attributes) != ordered_names:
        raise BetaArtifactError("beta archive parser inventory disagreement")
    allowed_modes = {int(value, 8) for value in policy["modes"]}
    for name, attribute in attributes.items():
        if attribute.get("kind") != "file":
            raise BetaArtifactError(f"beta artifact contains a non-file: {name}")
        if not matches(name, policy["allow"]) or matches(name, policy["deny"]):
            raise BetaArtifactError(
                f"beta artifact path is outside its contract: {name}"
            )
        if attribute.get("mode") not in allowed_modes:
            raise BetaArtifactError(
                f"beta artifact mode is outside its contract: {name}"
            )
        if attribute.get("mtime") != snapshot.source_date_epoch:
            raise BetaArtifactError(
                f"beta artifact timestamp is not deterministic: {name}"
            )
        if attribute.get("uid") != 0 or attribute.get("gid") != 0:
            raise BetaArtifactError(
                f"beta artifact ownership is not normalized: {name}"
            )
        findings = attribute.get("content_findings")
        if findings:
            raise BetaArtifactError(
                f"beta artifact content scan failed: {name}: {findings}"
            )
        if (
            Path(name).suffix.lower() in _TEXT_SUFFIXES
            or Path(name).name in _TEXT_NAMES
        ) and attribute.get("contains_cr"):
            raise BetaArtifactError(f"beta artifact has non-LF line endings: {name}")
    names = set(attributes)
    missing = set(policy["required"]) - names
    if missing:
        raise BetaArtifactError(
            f"beta artifact is missing required files: {sorted(missing)}"
        )
    if isinstance(checksum_spec, dict):
        try:
            _validate_checksum_manifest(attributes_payloads, attributes, checksum_spec)
        except ReleaseError as error:
            raise BetaArtifactError(
                f"beta binary checksum manifest failed: {error}"
            ) from error
    metadata_payload = attributes_payloads.get("RELEASE-METADATA.json")
    if metadata_payload is None:
        raise BetaArtifactError("beta release metadata is missing or too large")
    metadata = _validate_beta_metadata(
        payload=metadata_payload,
        matrix_entry=matrix_entry,
        policy=policy,
        source_descriptor=source_descriptor,
        snapshot=snapshot,
        attributes=attributes,
        expected_help_sha256=sha256_file(
            resolve_beneath(root, "crates/cigar-cli/assets/cigar-help-beta.txt")
        ),
    )
    _validate_committed_payload(
        matrix_entry=matrix_entry,
        attributes=attributes,
        committed=committed,
    )
    if matrix_entry.get("kind") == "binary-archive":
        binary_payload = attributes_payloads.get("bin/cigar")
        if (
            not isinstance(binary_payload, bytes)
            or len(binary_payload) > MAX_BINARY_BYTES
        ):
            raise BetaArtifactError("beta binary member is missing or too large")
        validate_elf_linux_x86_64(binary_payload)
        needed_libraries = list(elf_needed_libraries(binary_payload))
        if execute_binary:
            require_declared_host()
            with tempfile.TemporaryDirectory(prefix="cigar-beta-verify-") as raw:
                directory = Path(raw)
                os.chmod(directory, 0o700)
                binary = directory / "cigar"
                _write_private(binary, binary_payload)
                os.chmod(binary, 0o700)
                expected_help = _read_stable_file(
                    resolve_beneath(
                        root, "crates/cigar-cli/assets/cigar-help-beta.txt"
                    ),
                    1024 * 1024,
                    "committed beta help asset",
                )
                version, help_sha256 = _run_beta_binary(binary, snapshot, expected_help)
            build = metadata["build"]
            if (
                build.get("version_identity") != version
                or build.get("help_sha256") != help_sha256
            ):
                raise BetaArtifactError(
                    "executed beta binary identity disagrees with archive metadata"
                )
    else:
        needed_libraries = []
    return {
        "id": matrix_entry["id"],
        "path": archive_name,
        "sha256": sha256_bytes(archive_payload),
        "bytes": len(archive_payload),
        "file_count": len(attributes),
        "members": _member_records(attributes),
        "needed_libraries": needed_libraries,
        "status": "passed",
    }


def _expected_candidate_paths(*, include_verification: bool) -> set[str]:
    matrix = beta_profile.expected_artifact_matrix()
    paths = {
        *(f"{ARTIFACT_DIRECTORY}/{entry['filename']}" for entry in matrix["artifacts"]),
        CHECKSUM_PATH,
        SOURCE_DESCRIPTOR_PATH,
        SBOM_PATH,
        SPDX_PATH,
        PROVENANCE_PATH,
        BUILD_MANIFEST_PATH,
    }
    if include_verification:
        paths.add(VERIFICATION_PATH)
    return paths


def _candidate_inventory(
    root: Path,
    candidate: Path,
    *,
    strict_read_only: bool,
    include_verification: bool,
) -> dict[str, bytes]:
    if not candidate.is_absolute() or candidate != Path(os.path.normpath(candidate)):
        raise BetaArtifactError(
            "candidate path must be absolute and lexically canonical"
        )
    try:
        resolved = candidate.resolve(strict=True)
        repository = root.resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(f"cannot resolve beta candidate: {error}") from error
    if resolved != candidate:
        raise BetaArtifactError(
            "beta candidate path must not traverse aliases or links"
        )
    if resolved == repository or repository in resolved.parents:
        raise BetaArtifactError("beta candidate must be outside the source repository")
    expected = _expected_candidate_paths(include_verification=include_verification)
    try:
        with EvidenceWorkspace.create(
            resolved,
            repository_root=repository,
            limits=EvidenceLimits(
                max_files=128,
                max_directories=32,
                max_file_bytes=64 * 1024 * 1024,
                max_total_bytes=512 * 1024 * 1024,
                max_json_bytes=16 * 1024 * 1024,
                max_path_depth=8,
            ),
        ) as workspace:
            return workspace.read_files(expected, strict_read_only=strict_read_only)
    except EvidenceWorkspaceError as error:
        raise BetaArtifactError(
            f"beta candidate workspace is unsafe: {error}"
        ) from error


def _source_freeze_inventory(
    root: Path,
    source_freeze: Path,
    *,
    strict_read_only: bool,
) -> dict[str, bytes]:
    if not source_freeze.is_absolute() or source_freeze != Path(
        os.path.normpath(source_freeze)
    ):
        raise BetaArtifactError(
            "source freeze path must be absolute and lexically canonical"
        )
    try:
        resolved = source_freeze.resolve(strict=True)
        repository = root.resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot resolve beta source freeze: {error}"
        ) from error
    if resolved != source_freeze:
        raise BetaArtifactError("source freeze path must not traverse aliases or links")
    if resolved == repository or repository in resolved.parents:
        raise BetaArtifactError("source freeze must be outside the source repository")
    try:
        with EvidenceWorkspace.create(
            resolved,
            repository_root=repository,
            limits=EvidenceLimits(
                max_files=2,
                max_directories=3,
                max_file_bytes=64 * 1024 * 1024,
                max_total_bytes=128 * 1024 * 1024,
                max_json_bytes=MAX_JSON_BYTES,
                max_path_depth=3,
            ),
        ) as workspace:
            return workspace.read_files(
                SOURCE_FREEZE_PATHS, strict_read_only=strict_read_only
            )
    except EvidenceWorkspaceError as error:
        raise BetaArtifactError(
            f"beta source freeze workspace is unsafe: {error}"
        ) from error


def _load_canonical_candidate_json(
    candidate: Mapping[str, bytes], relative: str
) -> dict[str, object]:
    payload = candidate.get(relative)
    if payload is None or len(payload) > MAX_JSON_BYTES:
        raise BetaArtifactError(f"candidate JSON is missing or too large: {relative}")
    document = load_json_bytes(payload, relative)
    if not isinstance(document, dict):
        raise BetaArtifactError(f"candidate JSON is not an object: {relative}")
    if canonical_json_bytes(document) != payload:
        raise BetaArtifactError(f"candidate JSON is not canonical: {relative}")
    return document


def _validate_file_reference(
    candidate: Mapping[str, bytes], reference: object, expected_path: str
) -> dict[str, object]:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256", "bytes"}:
        raise BetaArtifactError(
            f"file reference has an unexpected shape: {expected_path}"
        )
    if reference.get("path") != expected_path:
        raise BetaArtifactError(f"file reference path mismatch: {expected_path}")
    payload = candidate.get(expected_path)
    if payload is None:
        raise BetaArtifactError(
            f"referenced candidate file is missing: {expected_path}"
        )
    if reference.get("sha256") != sha256_bytes(payload) or reference.get(
        "bytes"
    ) != len(payload):
        raise BetaArtifactError(f"file reference bytes changed: {expected_path}")
    return reference


def _validate_source_descriptor_binding(
    *,
    root: Path,
    document: dict[str, object],
    snapshot: GitSnapshot,
    source_record: Mapping[str, object],
) -> None:
    try:
        validate_source_descriptor(document)
    except SourceDescriptorError as error:
        raise BetaArtifactError(f"source descriptor is invalid: {error}") from error
    if document.get("generated_at") != snapshot.generated_at:
        raise BetaArtifactError("source descriptor timestamp does not match the commit")
    git = document.get("git")
    if not isinstance(git, dict) or git != {
        "revision": snapshot.revision,
        "tree": snapshot.tree,
        "committed": True,
        "clean": True,
        "status_entry_count": 0,
        "status_sha256": sha256_bytes(b""),
    }:
        raise BetaArtifactError("source descriptor Git identity mismatch")
    if document.get("source_archive") != {
        "name": Path(str(source_record["path"])).name,
        "sha256": source_record["sha256"],
        "bytes": source_record["bytes"],
    }:
        raise BetaArtifactError("source descriptor archive binding mismatch")
    for key, expected_paths in (
        ("policy_inputs", SOURCE_POLICY_INPUTS),
        ("tool_inputs", SOURCE_TOOL_INPUTS),
    ):
        records = document.get(key)
        if not isinstance(records, list):
            raise BetaArtifactError(f"source descriptor {key} is invalid")
        by_path = {
            record.get("path"): record for record in records if isinstance(record, dict)
        }
        if set(by_path) != set(expected_paths) or len(by_path) != len(records):
            raise BetaArtifactError(f"source descriptor {key} inventory mismatch")
        for relative in expected_paths:
            path = resolve_beneath(root, relative)
            metadata = path.stat(follow_symlinks=False)
            if by_path[relative] != {
                "path": relative,
                "sha256": sha256_file(path),
                "bytes": metadata.st_size,
            }:
                raise BetaArtifactError(
                    f"source descriptor input binding mismatch: {relative}"
                )


def _snapshot_from_source_descriptor(
    document: Mapping[str, object],
) -> GitSnapshot:
    try:
        validate_source_descriptor(document)
    except SourceDescriptorError as error:
        raise BetaArtifactError(f"source descriptor is invalid: {error}") from error
    generated_at = document.get("generated_at")
    git = document.get("git")
    if not isinstance(generated_at, str) or not isinstance(git, dict):
        raise BetaArtifactError("source descriptor identity is invalid")
    try:
        parsed = dt.datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.UTC
        )
    except ValueError as error:
        raise BetaArtifactError("source descriptor timestamp is invalid") from error
    epoch = int(parsed.timestamp())
    if (
        not 0 <= epoch <= 4_294_967_295
        or parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != generated_at
    ):
        raise BetaArtifactError(
            "source descriptor timestamp is outside the release range"
        )
    revision = git.get("revision")
    tree = git.get("tree")
    if (
        not isinstance(revision, str)
        or not isinstance(tree, str)
        or len(revision) != len(tree)
        or revision == "0" * len(revision)
        or tree == "0" * len(tree)
    ):
        raise BetaArtifactError("source descriptor Git identity is invalid")
    return GitSnapshot(revision, tree, epoch, generated_at)


def _verified_source_freeze_payloads(
    payloads: Mapping[str, bytes],
) -> VerifiedSourceFreeze:
    if set(payloads) != set(SOURCE_FREEZE_PATHS):
        raise BetaArtifactError("beta source freeze has an unexpected inventory")
    descriptor_payload = payloads[SOURCE_DESCRIPTOR_PATH]
    if not descriptor_payload or len(descriptor_payload) > MAX_JSON_BYTES:
        raise BetaArtifactError("beta source descriptor is missing or too large")
    descriptor = load_json_bytes(descriptor_payload, "beta source descriptor")
    if (
        not isinstance(descriptor, dict)
        or canonical_json_bytes(descriptor) != descriptor_payload
    ):
        raise BetaArtifactError("beta source descriptor is not canonical JSON")
    snapshot = _snapshot_from_source_descriptor(descriptor)
    archive_payload = payloads[SOURCE_ARCHIVE_PATH]
    archive_binding = descriptor.get("source_archive")
    if archive_binding != {
        "name": Path(SOURCE_ARCHIVE_PATH).name,
        "sha256": sha256_bytes(archive_payload),
        "bytes": len(archive_payload),
    }:
        raise BetaArtifactError("source descriptor archive binding mismatch")

    bootstrap_policy = {
        "max_entries": 4096,
        "max_member_bytes": 16 * 1024 * 1024,
        "max_total_bytes": 128 * 1024 * 1024,
        "content_scan_exemptions": [],
    }
    _, bootstrap_attributes, ordered_names = _read_canonical_tar(
        archive_payload,
        epoch=snapshot.source_date_epoch,
        policy=bootstrap_policy,
        retained=[],
    )
    retained_payloads, attributes, repeated_names = _read_canonical_tar(
        archive_payload,
        epoch=snapshot.source_date_epoch,
        policy=bootstrap_policy,
        retained=ordered_names,
    )
    if attributes != bootstrap_attributes or repeated_names != ordered_names:
        raise BetaArtifactError("beta source archive changed during inspection")
    metadata = retained_payloads.pop("RELEASE-METADATA.json", None)
    metadata_attributes = attributes.get("RELEASE-METADATA.json")
    if not isinstance(metadata, bytes) or not isinstance(metadata_attributes, dict):
        raise BetaArtifactError("beta source archive release metadata is missing")
    committed: dict[str, CommittedEntry] = {}
    for name in ordered_names:
        if name == "RELEASE-METADATA.json":
            continue
        payload = retained_payloads.get(name)
        attribute = attributes.get(name)
        if not isinstance(payload, bytes) or not isinstance(attribute, dict):
            raise BetaArtifactError(
                f"beta source archive member is unavailable: {name}"
            )
        mode = attribute.get("mode")
        if mode not in {0o644, 0o755}:
            raise BetaArtifactError(f"beta source archive mode is invalid: {name}")
        committed[name] = CommittedEntry(name, payload, mode)
    if not committed or not _is_materialized_beta_projection(committed):
        raise BetaArtifactError(
            "beta source archive is not the reviewed materialized projection"
        )

    with tempfile.TemporaryDirectory(prefix="cigar-beta-source-verify-") as raw:
        staging_parent = Path(raw).resolve()
        os.chmod(staging_parent, 0o700)
        staged_source = staging_parent / "source"
        committed_identity = _materialize_committed_tree(staged_source, committed)
        beta_profile.validate(staged_source)
        matrix, _archive_manifest, selections, source_committed = (
            _source_archive_selections(committed)
        )
        if source_committed != committed or tuple(source_committed) != tuple(committed):
            raise BetaArtifactError(
                "beta source archive differs from its closed source selection"
            )
        source_matrix_entry = matrix["artifacts"][0]
        source_record = {
            "id": source_matrix_entry["id"],
            "path": SOURCE_ARCHIVE_PATH,
            "sha256": sha256_bytes(archive_payload),
            "bytes": len(archive_payload),
            "contract": source_matrix_entry["contract"],
            "status": "passed",
        }
        _validate_source_descriptor_binding(
            root=staged_source,
            document=descriptor,
            snapshot=snapshot,
            source_record=source_record,
        )
        archive_result = verify_beta_archive(
            root=staged_source,
            archive_payload=archive_payload,
            archive_name=Path(SOURCE_ARCHIVE_PATH).name,
            matrix_entry=source_matrix_entry,
            source_descriptor=descriptor,
            snapshot=snapshot,
            committed=committed,
            execute_binary=False,
        )
        if (
            archive_result.get("sha256") != source_record["sha256"]
            or archive_result.get("bytes") != source_record["bytes"]
            or archive_result.get("file_count") != len(selections[0]) + 1
            or _verify_materialized_tree(staged_source, committed) != committed_identity
        ):
            raise BetaArtifactError("beta source freeze verification is inconsistent")

    descriptor_reference = {
        "path": SOURCE_DESCRIPTOR_PATH,
        "sha256": sha256_bytes(descriptor_payload),
        "bytes": len(descriptor_payload),
    }
    report = {
        "schema_version": "cigar.beta.source-freeze-verification.v1",
        "status": "passed",
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "prerelease": True,
        "production_ready": False,
        "source_date_epoch": snapshot.source_date_epoch,
        "source": snapshot.source_identity(),
        "source_archive": {
            "path": SOURCE_ARCHIVE_PATH,
            "sha256": source_record["sha256"],
            "bytes": source_record["bytes"],
            "file_count": archive_result["file_count"],
        },
        "source_descriptor": descriptor_reference,
        "checks": {
            "archive_canonical": True,
            "archive_contract_validated": True,
            "descriptor_validated": True,
            "source_inputs_bound": True,
            "source_materialized_read_only": True,
            "native_host_qualification_performed": False,
        },
        "claims": {
            "signed": False,
            "published": False,
            "production_ready": False,
        },
    }
    return VerifiedSourceFreeze(
        snapshot=snapshot,
        committed=committed,
        archive_payload=archive_payload,
        descriptor_payload=descriptor_payload,
        descriptor=descriptor,
        source_record=source_record,
        report=report,
    )


def _load_verified_source_freeze(
    *,
    root: Path,
    source_freeze: Path,
    strict_read_only: bool,
) -> VerifiedSourceFreeze:
    return _verified_source_freeze_payloads(
        _source_freeze_inventory(root, source_freeze, strict_read_only=strict_read_only)
    )


def _require_source_freeze_git_binding(
    *,
    root: Path,
    verified: VerifiedSourceFreeze,
    git: Path,
) -> None:
    observed = inspect_clean_snapshot(root, git)
    if observed != verified.snapshot:
        raise BetaArtifactError(
            "checkout identity does not match the verified source freeze"
        )
    projected = _project_beta_source(read_committed_tree(root, observed, git))
    _matrix, _manifest, _selections, expected_source = _source_archive_selections(
        projected
    )
    if expected_source != dict(verified.committed):
        raise BetaArtifactError(
            "beta source freeze differs from the exact committed Git projection"
        )
    _require_unchanged_snapshot(root, observed, git)


def _source_freeze_report(
    verified: VerifiedSourceFreeze, *, git_projection_recomputed: bool
) -> dict[str, object]:
    report = dict(verified.report)
    checks = report.get("checks")
    if not isinstance(checks, dict):
        raise BetaArtifactError("beta source freeze report checks are invalid")
    report["checks"] = {
        **checks,
        "git_projection_recomputed": git_projection_recomputed,
    }
    return report


def _validate_artifact_record(
    candidate: Mapping[str, bytes],
    record: object,
    matrix_entry: Mapping[str, object],
) -> dict[str, object]:
    required = {"id", "path", "sha256", "bytes", "contract", "status"}
    expected_path = f"{ARTIFACT_DIRECTORY}/{matrix_entry['filename']}"
    if not isinstance(record, dict) or set(record) != required:
        raise BetaArtifactError(
            "build manifest artifact record has an unexpected shape"
        )
    if (
        record.get("id") != matrix_entry["id"]
        or record.get("path") != expected_path
        or record.get("contract") != matrix_entry["contract"]
        or record.get("status") != "passed"
    ):
        raise BetaArtifactError(f"artifact identity mismatch: {matrix_entry['id']}")
    payload = candidate.get(expected_path)
    if payload is None:
        raise BetaArtifactError(f"artifact is missing: {matrix_entry['id']}")
    if record.get("sha256") != sha256_bytes(payload) or record.get("bytes") != len(
        payload
    ):
        raise BetaArtifactError(f"artifact byte binding mismatch: {matrix_entry['id']}")
    return record


def _build_manifest_document(
    *,
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    source_descriptor_reference: Mapping[str, object],
    checksums_reference: Mapping[str, object],
    sbom_reference: Mapping[str, object],
    spdx_reference: Mapping[str, object],
    provenance_reference: Mapping[str, object],
    binary_build: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "cigar.beta.build-manifest.v1",
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "tag": beta_profile.TAG,
        "prerelease": True,
        "production_ready": False,
        "target": beta_profile.TARGET_TRIPLE,
        "source_date_epoch": snapshot.source_date_epoch,
        "source": snapshot.source_identity(),
        "source_descriptor": dict(source_descriptor_reference),
        "artifacts": [dict(record) for record in artifacts],
        "checksums": dict(checksums_reference),
        "sbom": dict(sbom_reference),
        "spdx": dict(spdx_reference),
        "provenance": dict(provenance_reference),
        "binary_build": dict(binary_build),
        "claims": {
            "signed": False,
            "published": False,
            "production_ready": False,
        },
    }


def _validate_sbom(
    *,
    document: dict[str, object],
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    member_bindings: Sequence[Mapping[str, object]],
    expected_components: Sequence[Mapping[str, object]],
    expected_dependencies: Sequence[Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    components = document.get("components")
    dependencies = document.get("dependencies")
    if not isinstance(components, list) or not components:
        raise BetaArtifactError("beta SBOM has no dependency components")
    if not isinstance(dependencies, list) or len(dependencies) != len(components):
        raise BetaArtifactError("beta SBOM dependency graph is incomplete")
    if components != [dict(component) for component in expected_components]:
        raise BetaArtifactError(
            "beta SBOM omits or substitutes the resolved component closure"
        )
    if dependencies != [dict(edge) for edge in expected_dependencies]:
        raise BetaArtifactError(
            "beta SBOM omits or substitutes the resolved dependency graph"
        )
    names: list[str] = []
    identities: set[tuple[str, str]] = set()
    for component in components:
        if not isinstance(component, dict):
            raise BetaArtifactError("beta SBOM component is invalid")
        required = {"type", "name", "version", "purl", "bom-ref", "licenses"}
        if not required.issubset(component) or set(component) - (
            required | {"hashes", "properties"}
        ):
            raise BetaArtifactError("beta SBOM component shape is invalid")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise BetaArtifactError("beta SBOM component identity is invalid")
        if (
            not name
            or not version
            or component.get("bom-ref") != component.get("purl")
            or component.get("type")
            != ("application" if name == "cigar-cli" else "library")
            or not isinstance(component.get("purl"), str)
            or not str(component["purl"]).startswith(("pkg:cargo/", "pkg:generic/"))
            or not isinstance(component.get("licenses"), list)
            or len(component["licenses"]) != 1
            or not isinstance(component["licenses"][0], dict)
            or set(component["licenses"][0]) != {"expression"}
            or not isinstance(component["licenses"][0]["expression"], str)
            or not component["licenses"][0]["expression"]
        ):
            raise BetaArtifactError("beta SBOM component metadata is incomplete")
        identity = (name, version)
        if identity in identities:
            raise BetaArtifactError("beta SBOM contains duplicate components")
        identities.add(identity)
        names.append(name)
    if "cigar-cli" not in names or set(names) & FORBIDDEN_BETA_PACKAGES:
        raise BetaArtifactError(
            "beta SBOM component closure violates the capability profile"
        )
    if components != sorted(
        components, key=lambda item: (str(item["name"]), str(item["version"]))
    ):
        raise BetaArtifactError(
            "beta SBOM components are not deterministically ordered"
        )
    references = {str(component["bom-ref"]) for component in components}
    observed_dependency_refs: list[str] = []
    for edge in dependencies:
        if (
            not isinstance(edge, dict)
            or set(edge) != {"ref", "dependsOn"}
            or edge.get("ref") not in references
            or not isinstance(edge.get("dependsOn"), list)
            or edge["dependsOn"]
            != sorted(
                set(edge["dependsOn"]), key=lambda value: str(value).encode("utf-8")
            )
            or not set(edge["dependsOn"]).issubset(references)
        ):
            raise BetaArtifactError("beta SBOM dependency edge is invalid")
        observed_dependency_refs.append(str(edge["ref"]))
    if observed_dependency_refs != sorted(
        references, key=lambda value: value.encode("utf-8")
    ):
        raise BetaArtifactError("beta SBOM dependency refs are incomplete or unordered")
    expected = build_beta_sbom(
        snapshot=snapshot,
        artifacts=artifacts,
        components=components,
        dependencies=dependencies,
        member_bindings=member_bindings,
    )
    if document != expected:
        raise BetaArtifactError("beta SBOM profile or artifact binding mismatch")
    return components, dependencies


def _declared_cargo_resolution(
    root: Path, document: Mapping[str, object]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    components = document.get("components")
    dependencies = document.get("dependencies")
    if not isinstance(components, list) or not isinstance(dependencies, list):
        raise BetaArtifactError("beta SBOM has no declared dependency resolution")
    cargo_components = [
        dict(component)
        for component in components
        if isinstance(component, dict)
        and str(component.get("purl", "")).startswith("pkg:cargo/")
    ]
    cargo_refs = {str(component.get("bom-ref")) for component in cargo_components}
    cargo_dependencies: list[dict[str, object]] = []
    for edge in dependencies:
        if not isinstance(edge, dict) or edge.get("ref") not in cargo_refs:
            continue
        targets = edge.get("dependsOn")
        if not isinstance(targets, list):
            raise BetaArtifactError("beta SBOM Cargo dependency edge is invalid")
        cargo_dependencies.append(
            {
                "ref": edge["ref"],
                "dependsOn": [target for target in targets if target in cargo_refs],
            }
        )
    cargo_dependencies.sort(key=lambda item: str(item["ref"]).encode("utf-8"))
    _validate_component_licenses(root, cargo_components)
    pinned = _pinned_cargo_resolution(root)
    identity = {
        "components": cargo_components,
        "dependencies": cargo_dependencies,
    }
    edge_count = sum(len(edge["dependsOn"]) for edge in cargo_dependencies)
    if (
        pinned["component_count"] != len(cargo_components)
        or pinned["dependency_edge_count"] != edge_count
        or pinned["sbom_resolution_sha256"]
        != sha256_bytes(canonical_json_bytes(identity))
    ):
        raise BetaArtifactError(
            "candidate Cargo graph differs from the committed beta resolution pin"
        )
    return cargo_components, cargo_dependencies


def _rust_material_from_provenance(
    root: Path, document: Mapping[str, object]
) -> dict[str, object]:
    predicate = document.get("predicate")
    definition = (
        predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    )
    internal = (
        definition.get("internalParameters") if isinstance(definition, dict) else None
    )
    materials = (
        definition.get("resolvedDependencies") if isinstance(definition, dict) else None
    )
    tools = internal.get("tools") if isinstance(internal, dict) else None
    if not isinstance(materials, list) or not isinstance(tools, list):
        raise BetaArtifactError("beta provenance has no Rust material inputs")
    selected = [
        dict(record)
        for record in materials
        if isinstance(record, dict) and record.get("name") == "rust-target-libdir"
    ]
    rustc_tools = [
        record
        for record in tools
        if isinstance(record, dict) and record.get("name") == "rustc"
    ]
    if len(selected) != 1 or len(rustc_tools) != 1:
        raise BetaArtifactError("beta provenance Rust identity is ambiguous")
    material = selected[0]
    _rust_standard_library_component(material)
    annotations = material["annotations"]
    if (
        _rustc_commit_hash(str(rustc_tools[0].get("version", "")))
        != annotations["rustcCommit"]
    ):
        raise BetaArtifactError("Rust standard-library material uses another compiler")

    manifest_path = resolve_beneath(
        root, "packaging/licenses/beta-third-party-license-manifest.v1.json"
    )
    manifest_payload = _read_stable_file(
        manifest_path, MAX_JSON_BYTES, "beta third-party license-file manifest"
    )
    manifest = load_json_bytes(
        manifest_payload, "beta third-party license-file manifest"
    )
    if manifest_payload != canonical_json_bytes(manifest) or not isinstance(
        manifest, dict
    ):
        raise BetaArtifactError(
            "beta third-party license-file manifest is not canonical"
        )
    notice_record = manifest.get("rust_standard_library")
    if not isinstance(notice_record, dict):
        raise BetaArtifactError("beta legal manifest omits the Rust standard library")
    notice_path = notice_record.get("path")
    if not isinstance(notice_path, str):
        raise BetaArtifactError("beta Rust notice path is invalid")
    notice_payload = _read_stable_file(
        resolve_beneath(root, notice_path),
        8 * 1024 * 1024,
        "committed Rust standard-library notice",
    )
    if notice_record != {
        "bytes": len(notice_payload),
        "path": "packaging/licenses/rust/COPYRIGHT-library.html",
        "sha256": sha256_bytes(notice_payload),
        "source_path": "share/doc/rust/COPYRIGHT-library.html",
        "target": beta_profile.TARGET_TRIPLE,
        "toolchain_version": beta_profile.RUST_TOOLCHAIN_VERSION,
    } or (
        annotations["noticeBytes"] != len(notice_payload)
        or annotations["noticeSha256"] != sha256_bytes(notice_payload)
    ):
        raise BetaArtifactError("Rust standard-library notice binding is substituted")
    return material


def _validate_spdx(
    *,
    document: dict[str, object],
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    components: Sequence[Mapping[str, object]],
    dependencies: Sequence[Mapping[str, object]],
    member_bindings: Sequence[Mapping[str, object]],
) -> None:
    expected = build_beta_spdx(
        snapshot=snapshot,
        artifacts=artifacts,
        components=components,
        dependencies=dependencies,
        member_bindings=member_bindings,
    )
    if document != expected:
        raise BetaArtifactError(
            "beta SPDX component, dependency, or member binding mismatch"
        )


def _validate_provenance(
    *,
    root: Path,
    document: dict[str, object],
    snapshot: GitSnapshot,
    artifacts: Sequence[Mapping[str, object]],
    source_descriptor: Mapping[str, object],
    source_descriptor_reference: Mapping[str, object],
) -> None:
    if set(document) != {"_type", "predicate", "predicateType", "subject"}:
        raise BetaArtifactError("beta provenance statement shape is invalid")
    if (
        document.get("_type") != "https://in-toto.io/Statement/v1"
        or document.get("predicateType") != "https://slsa.dev/provenance/v1"
    ):
        raise BetaArtifactError("beta provenance statement domain is invalid")
    predicate = document.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {
        "buildDefinition",
        "runDetails",
    }:
        raise BetaArtifactError("beta SLSA predicate shape is invalid")
    definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if (
        not isinstance(definition, dict)
        or set(definition)
        != {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        }
        or definition.get("buildType") != beta_profile.BETA_SLSA_BUILD_TYPE
        or not isinstance(run_details, dict)
        or set(run_details) != {"builder", "byproducts", "metadata"}
    ):
        raise BetaArtifactError("beta SLSA build definition is invalid")
    builder = run_details.get("builder")
    metadata = run_details.get("metadata")
    internal = definition.get("internalParameters")
    materials = definition.get("resolvedDependencies")
    if (
        not isinstance(builder, dict)
        or set(builder) != {"id"}
        or not isinstance(builder.get("id"), str)
        or not isinstance(metadata, dict)
        or set(metadata) != {"finishedOn", "invocationId", "startedOn"}
        or not isinstance(internal, dict)
        or not isinstance(materials, list)
    ):
        raise BetaArtifactError("beta SLSA run identity is invalid")
    builder_id = builder["id"]
    started_on = metadata.get("startedOn")
    finished_on = metadata.get("finishedOn")
    try:
        started = dt.datetime.strptime(str(started_on), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.UTC
        )
        finished = dt.datetime.strptime(str(finished_on), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.UTC
        )
    except (TypeError, ValueError) as error:
        raise BetaArtifactError(
            f"beta SLSA execution timestamp is invalid: {error}"
        ) from error
    if finished < started:
        raise BetaArtifactError("beta SLSA execution timestamps are reversed")
    tools = internal.get("tools")
    if not isinstance(tools, list) or not tools:
        raise BetaArtifactError("beta provenance tool inventory is missing")
    provenance_host = internal.get("host")
    host_keys = {
        "system",
        "machine",
        "distribution",
        "distributionVersion",
        "libc",
        "libcVersion",
        "glibcIdentity",
        "runtimeBaseline",
        "target",
    }
    if not isinstance(provenance_host, dict) or set(provenance_host) != host_keys:
        raise BetaArtifactError("beta provenance host identity is malformed")
    host = {
        "system": str(provenance_host["system"]),
        "machine": str(provenance_host["machine"]),
        "distribution": str(provenance_host["distribution"]),
        "distribution_version": str(provenance_host["distributionVersion"]),
        "libc": str(provenance_host["libc"]),
        "libc_version": str(provenance_host["libcVersion"]),
        "glibc_identity": str(provenance_host["glibcIdentity"]),
        "runtime_baseline": str(provenance_host["runtimeBaseline"]),
        "target": str(provenance_host["target"]),
    }
    tool_names: set[str] = set()
    for record in tools:
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "sha256", "bytes", "version"}
            or not isinstance(record.get("name"), str)
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or isinstance(record.get("bytes"), bool)
            or not isinstance(record.get("bytes"), int)
            or record["bytes"] <= 0
            or not isinstance(record.get("version"), str)
            or not record["version"]
            or len(record["version"].encode("utf-8")) > 16 * 1024
        ):
            raise BetaArtifactError("beta provenance tool record is invalid")
        if record["name"] in tool_names:
            raise BetaArtifactError("beta provenance tool names are duplicated")
        tool_names.add(record["name"])
    if not REQUIRED_PROVENANCE_TOOLS.issubset(tool_names) or not tool_names.issubset(
        REQUIRED_PROVENANCE_TOOLS | OPTIONAL_PROVENANCE_TOOLS
    ):
        raise BetaArtifactError("beta provenance tool inventory is incomplete")
    expected_packages = {
        _purl(package["name"], package["version"]): package
        for package in _pinned_vendor_crates(root)
    }
    dependency_materials = [
        dict(record)
        for record in materials
        if isinstance(record, dict)
        and isinstance(record.get("uri"), str)
        and str(record["uri"]).startswith("pkg:cargo/")
    ]
    if len(dependency_materials) != len(expected_packages):
        raise BetaArtifactError(
            "beta provenance dependency material closure is incomplete"
        )
    observed_uris: set[str] = set()
    for record in dependency_materials:
        uri = str(record["uri"])
        package = expected_packages.get(uri)
        annotations = record.get("annotations")
        if (
            package is None
            or uri in observed_uris
            or record.get("name") != f"{package['name']}-{package['version']}.crate"
            or record.get("digest") != {"sha256": package["checksum"]}
            or not isinstance(annotations, dict)
            or annotations.get("source") != package["source"]
            or isinstance(annotations.get("archiveBytes"), bool)
            or not isinstance(annotations.get("archiveBytes"), int)
            or annotations["archiveBytes"] <= 0
            or not isinstance(annotations.get("sourceTreeSha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", annotations["sourceTreeSha256"]) is None
        ):
            raise BetaArtifactError(
                "beta provenance dependency material is substituted"
            )
        observed_uris.add(uri)
    if observed_uris != set(expected_packages):
        raise BetaArtifactError("beta provenance omits a pinned dependency material")
    toolchain_materials = [
        dict(record)
        for record in materials
        if isinstance(record, dict) and record.get("name") == "rust-target-libdir"
    ]
    if len(toolchain_materials) != 1:
        raise BetaArtifactError(
            "beta provenance omits the Rust target library material"
        )
    expected = build_beta_provenance(
        snapshot=snapshot,
        artifacts=artifacts,
        source_descriptor=source_descriptor,
        source_descriptor_reference=source_descriptor_reference,
        tools=tools,
        dependency_materials=dependency_materials,
        toolchain_materials=toolchain_materials,
        host=host,
        builder_id=builder_id,
        started_on=str(started_on),
        finished_on=str(finished_on),
    )
    if document != expected:
        raise BetaArtifactError("beta provenance binding mismatch")


def _verification_document(
    *,
    snapshot: GitSnapshot,
    manifest_reference: Mapping[str, object],
    artifacts: Sequence[Mapping[str, object]],
    binary_executed: bool,
) -> dict[str, object]:
    return {
        "schema_version": "cigar.beta.release-verification.v1",
        "status": "passed",
        "release_profile": beta_profile.PROFILE_ID,
        "product_version": beta_profile.VERSION,
        "tag": beta_profile.TAG,
        "target": beta_profile.TARGET_TRIPLE,
        "source_revision": snapshot.revision,
        "manifest": dict(manifest_reference),
        "artifacts": [
            {
                "id": record["id"],
                "path": record["path"],
                "sha256": record["sha256"],
                "bytes": record["bytes"],
                "status": "passed",
            }
            for record in artifacts
        ],
        "checks": {
            "artifact_count": 6,
            "signed": False,
            "published": False,
            "production_ready": False,
            "binary_executed": binary_executed,
        },
    }


def _validate_external_checksums(
    candidate: Mapping[str, bytes], artifacts: Sequence[Mapping[str, object]]
) -> None:
    payload = candidate.get(CHECKSUM_PATH)
    if payload is None or len(payload) > 1024 * 1024:
        raise BetaArtifactError(
            "external beta checksum manifest is missing or too large"
        )
    expected = "".join(
        f"{record['sha256']}  {record['path']}\n"
        for record in sorted(
            artifacts, key=lambda item: str(item["path"]).encode("utf-8")
        )
    ).encode("ascii")
    if payload != expected:
        raise BetaArtifactError("external beta checksum manifest mismatch")


def verify_beta_candidate(
    *,
    root: Path,
    candidate: Path,
    strict_read_only: bool = True,
    execute_binary: bool = False,
    snapshot_override: GitSnapshot | None = None,
    committed_override: Mapping[str, CommittedEntry] | None = None,
    resolution_override: tuple[
        Sequence[Mapping[str, object]], Sequence[Mapping[str, object]]
    ]
    | None = None,
    recompute_cargo_resolution: bool = False,
    crate_cache_path: Path | None = None,
    require_recorded_verification: bool = True,
) -> dict[str, object]:
    """Return unsigned structural/integrity results, never release qualification."""
    _validate_python_runtime(Path(sys.executable))
    root = root.resolve(strict=True)
    beta_profile.validate(root)
    snapshot = snapshot_override or inspect_clean_snapshot(root)
    if execute_binary:
        require_declared_host()
    candidate_payloads = _candidate_inventory(
        root,
        candidate,
        strict_read_only=strict_read_only,
        include_verification=require_recorded_verification,
    )
    manifest = _load_canonical_candidate_json(candidate_payloads, BUILD_MANIFEST_PATH)
    source_descriptor = _load_canonical_candidate_json(
        candidate_payloads, SOURCE_DESCRIPTOR_PATH
    )
    sbom = _load_canonical_candidate_json(candidate_payloads, SBOM_PATH)
    spdx = _load_canonical_candidate_json(candidate_payloads, SPDX_PATH)
    provenance = _load_canonical_candidate_json(candidate_payloads, PROVENANCE_PATH)
    recorded_verification = (
        _load_canonical_candidate_json(candidate_payloads, VERIFICATION_PATH)
        if require_recorded_verification
        else None
    )
    committed = (
        dict(committed_override)
        if committed_override is not None
        else read_committed_tree(root, snapshot)
    )
    if (
        "packaging/beta/build-projection/projection.v1.json" in committed
        and not _is_materialized_beta_projection(committed)
    ):
        committed = _project_beta_source(committed)
    matrix = beta_profile.expected_artifact_matrix()
    manifest_artifacts = manifest.get("artifacts")
    if not isinstance(manifest_artifacts, list) or len(manifest_artifacts) != 6:
        raise BetaArtifactError("beta build manifest does not bind six artifacts")
    artifacts = [
        _validate_artifact_record(candidate_payloads, record, matrix_entry)
        for record, matrix_entry in zip(
            manifest_artifacts, matrix["artifacts"], strict=True
        )
    ]
    source_descriptor_reference = _validate_file_reference(
        candidate_payloads, manifest.get("source_descriptor"), SOURCE_DESCRIPTOR_PATH
    )
    checksums_reference = _validate_file_reference(
        candidate_payloads, manifest.get("checksums"), CHECKSUM_PATH
    )
    sbom_reference = _validate_file_reference(
        candidate_payloads, manifest.get("sbom"), SBOM_PATH
    )
    spdx_reference = _validate_file_reference(
        candidate_payloads, manifest.get("spdx"), SPDX_PATH
    )
    provenance_reference = _validate_file_reference(
        candidate_payloads, manifest.get("provenance"), PROVENANCE_PATH
    )
    _validate_source_descriptor_binding(
        root=root,
        document=source_descriptor,
        snapshot=snapshot,
        source_record=artifacts[0],
    )
    binary_build = manifest.get("binary_build")
    help_entry = committed.get("crates/cigar-cli/assets/cigar-help-beta.txt")
    if help_entry is None or help_entry.kind != "file":
        raise BetaArtifactError("committed beta help asset is missing")
    expected_binary_build = _binary_build_record(
        expected_version_document(snapshot),
        sha256_bytes(help_entry.payload),
    )
    if binary_build != expected_binary_build:
        raise BetaArtifactError("beta build manifest feature/binary binding mismatch")
    expected_manifest = _build_manifest_document(
        snapshot=snapshot,
        artifacts=artifacts,
        source_descriptor_reference=source_descriptor_reference,
        checksums_reference=checksums_reference,
        sbom_reference=sbom_reference,
        spdx_reference=spdx_reference,
        provenance_reference=provenance_reference,
        binary_build=expected_binary_build,
    )
    if manifest != expected_manifest:
        raise BetaArtifactError("beta build manifest identity or claim mismatch")
    _validate_external_checksums(candidate_payloads, artifacts)
    archive_results = []
    for record, matrix_entry in zip(artifacts, matrix["artifacts"], strict=True):
        result = verify_beta_archive(
            root=root,
            archive_payload=candidate_payloads[str(record["path"])],
            archive_name=Path(str(record["path"])).name,
            matrix_entry=matrix_entry,
            source_descriptor=source_descriptor,
            snapshot=snapshot,
            committed=committed,
            execute_binary=execute_binary and matrix_entry["kind"] == "binary-archive",
        )
        if result["sha256"] != record["sha256"] or result["bytes"] != record["bytes"]:
            raise BetaArtifactError(
                f"archive verifier binding mismatch: {record['id']}"
            )
        archive_results.append(result)
    member_bindings = [
        {
            "id": result["id"],
            "path": record["path"],
            "sha256": record["sha256"],
            "bytes": record["bytes"],
            "members": result["members"],
        }
        for result, record in zip(archive_results, artifacts, strict=True)
    ]
    if resolution_override is not None:
        cargo_components, cargo_dependencies = resolution_override
    elif recompute_cargo_resolution:
        if crate_cache_path is None:
            raise BetaArtifactError(
                "Cargo resolution recomputation requires an explicit crate cache"
            )
        cargo_components, cargo_dependencies = _resolved_cargo_evidence(
            root, snapshot, crate_cache_path
        )
    else:
        cargo_components, cargo_dependencies = _declared_cargo_resolution(root, sbom)
    binary_results = [
        result for result in archive_results if result["id"] == "cigar-linux-x86_64-gnu"
    ]
    if len(binary_results) != 1:
        raise BetaArtifactError("beta archive results have no unique binary artifact")
    rust_component = _rust_standard_library_component(
        _rust_material_from_provenance(root, provenance)
    )
    expected_components, expected_dependencies = _augment_native_resolution(
        cargo_components,
        cargo_dependencies,
        binary_results[0]["needed_libraries"],
        rust_component,
    )
    components, dependencies = _validate_sbom(
        document=sbom,
        snapshot=snapshot,
        artifacts=artifacts,
        member_bindings=member_bindings,
        expected_components=expected_components,
        expected_dependencies=expected_dependencies,
    )
    _validate_spdx(
        document=spdx,
        snapshot=snapshot,
        artifacts=artifacts,
        components=components,
        dependencies=dependencies,
        member_bindings=member_bindings,
    )
    _validate_provenance(
        root=root,
        document=provenance,
        snapshot=snapshot,
        artifacts=artifacts,
        source_descriptor=source_descriptor,
        source_descriptor_reference=source_descriptor_reference,
    )
    manifest_payload = candidate_payloads[BUILD_MANIFEST_PATH]
    manifest_reference = {
        "path": BUILD_MANIFEST_PATH,
        "sha256": sha256_bytes(manifest_payload),
        "bytes": len(manifest_payload),
    }
    verification = _verification_document(
        snapshot=snapshot,
        manifest_reference=manifest_reference,
        artifacts=artifacts,
        binary_executed=execute_binary,
    )
    if require_recorded_verification:
        expected_recorded = _verification_document(
            snapshot=snapshot,
            manifest_reference=manifest_reference,
            artifacts=artifacts,
            binary_executed=True,
        )
        if recorded_verification != expected_recorded:
            raise BetaArtifactError("beta verification receipt is substituted or stale")
    return verification


def _require_new_external_output(root: Path, output: Path, label: str) -> None:
    if not output.is_absolute() or output != Path(os.path.normpath(output)):
        raise BetaArtifactError(f"{label} must be an absolute canonical path")
    if output.exists() or output.is_symlink():
        raise BetaArtifactError(f"{label} must not already exist")
    try:
        repository = root.resolve(strict=True)
        resolved_parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(f"cannot resolve {label} parent: {error}") from error
    resolved_output = resolved_parent / output.name
    if resolved_output == repository or repository in resolved_output.parents:
        raise BetaArtifactError(f"{label} must be outside the source repository")


def _require_disjoint_external_paths(
    first: Path, second: Path, first_label: str, second_label: str
) -> None:
    try:
        first_resolved = first.resolve(strict=True)
        second_parent = second.parent.resolve(strict=True)
    except OSError as error:
        raise BetaArtifactError(
            f"cannot resolve external workspace paths: {error}"
        ) from error
    second_resolved = second_parent / second.name
    if (
        first_resolved == second_resolved
        or first_resolved in second_resolved.parents
        or second_resolved in first_resolved.parents
    ):
        raise BetaArtifactError(f"{first_label} and {second_label} must not be nested")


def freeze_beta_source(
    *,
    root: Path,
    output: Path,
    git_path: Path | None = None,
) -> dict[str, object]:
    """Freeze one exact clean Git projection without qualifying a native host."""

    _validate_python_runtime(Path(sys.executable))
    root = root.resolve(strict=True)
    beta_profile.validate(root)
    _require_new_external_output(root, output, "beta source-freeze output")
    if git_path is None:
        raise BetaArtifactError(
            "beta source freeze requires an explicit absolute Git path"
        )
    selected_git = _secure_executable(git_path, "git")
    snapshot = inspect_clean_snapshot(root, selected_git)
    projected = _project_beta_source(read_committed_tree(root, snapshot, selected_git))
    matrix, _archive_manifest, selections, source_committed = (
        _source_archive_selections(projected)
    )

    with tempfile.TemporaryDirectory(prefix="cigar-beta-source-freeze-") as raw:
        staging_parent = Path(raw).resolve()
        os.chmod(staging_parent, 0o700)
        staged_source = staging_parent / "source"
        committed_identity = _materialize_committed_tree(
            staged_source, source_committed
        )
        staged_freeze = staging_parent / "freeze"
        staged_freeze.mkdir(mode=0o700)
        source_matrix_entry = matrix["artifacts"][0]
        policy = _contract_policy(staged_source, source_matrix_entry)
        metadata = _metadata(
            artifact_id=str(source_matrix_entry["id"]),
            contract_path=str(source_matrix_entry["contract"]),
            contract_sha256=sha256_file(policy["path"]),
            snapshot=snapshot,
            payload=selections[0],
            build=_source_build_record(),
        )
        archive_path = staged_freeze / SOURCE_ARCHIVE_PATH
        write_deterministic_archive(
            archive_path,
            selections[0],
            metadata,
            snapshot.source_date_epoch,
        )
        if archive_path.stat().st_size > 64 * 1024 * 1024:
            raise BetaArtifactError(
                "beta source archive exceeds the external workspace limit"
            )
        source_record = _artifact_record(
            archive_path,
            str(source_matrix_entry["id"]),
            SOURCE_ARCHIVE_PATH,
            str(source_matrix_entry["contract"]),
        )
        descriptor = _source_descriptor_from_committed(
            committed=source_committed,
            snapshot=snapshot,
            source_archive={
                "name": Path(SOURCE_ARCHIVE_PATH).name,
                "sha256": source_record["sha256"],
                "bytes": source_record["bytes"],
            },
        )
        descriptor_path = staged_freeze / SOURCE_DESCRIPTOR_PATH
        _write_private_json(descriptor_path, descriptor)
        staged_payloads = {
            SOURCE_ARCHIVE_PATH: _read_stable_file(
                archive_path, 64 * 1024 * 1024, "staged beta source archive"
            ),
            SOURCE_DESCRIPTOR_PATH: _read_stable_file(
                descriptor_path, MAX_JSON_BYTES, "staged beta source descriptor"
            ),
        }
        verified = _verified_source_freeze_payloads(staged_payloads)
        if (
            verified.snapshot != snapshot
            or dict(verified.committed) != source_committed
            or _verify_materialized_tree(staged_source, source_committed)
            != committed_identity
        ):
            raise BetaArtifactError("staged beta source freeze identity changed")
        _require_unchanged_snapshot(root, snapshot, selected_git)
        try:
            with EvidenceWorkspace.create(
                output,
                repository_root=root,
                limits=EvidenceLimits(
                    max_files=2,
                    max_directories=3,
                    max_file_bytes=64 * 1024 * 1024,
                    max_total_bytes=128 * 1024 * 1024,
                    max_json_bytes=MAX_JSON_BYTES,
                    max_path_depth=3,
                ),
            ) as workspace:
                for relative in sorted(
                    SOURCE_FREEZE_PATHS, key=lambda value: value.encode("utf-8")
                ):
                    workspace.attach_file(staged_freeze / relative, relative)
        except EvidenceWorkspaceError as error:
            raise BetaArtifactError(
                f"cannot materialize private beta source freeze: {error}"
            ) from error
    final = _load_verified_source_freeze(
        root=root, source_freeze=output, strict_read_only=True
    )
    if final.snapshot != snapshot or final.report != verified.report:
        raise BetaArtifactError("published beta source freeze identity changed")
    _require_unchanged_snapshot(root, snapshot, selected_git)
    _require_source_freeze_git_binding(
        root=root,
        verified=final,
        git=selected_git,
    )
    return _source_freeze_report(final, git_projection_recomputed=True)


def verify_beta_source_freeze(
    *,
    root: Path,
    source_freeze: Path,
    git_path: Path | None = None,
) -> dict[str, object]:
    """Independently verify a frozen source package without native qualification."""

    _validate_python_runtime(Path(sys.executable))
    root = root.resolve(strict=True)
    beta_profile.validate(root)
    if git_path is None:
        raise BetaArtifactError(
            "beta source verification requires an explicit absolute Git path"
        )
    selected_git = _secure_executable(git_path, "git")
    verified = _load_verified_source_freeze(
        root=root,
        source_freeze=source_freeze,
        strict_read_only=True,
    )
    _require_source_freeze_git_binding(
        root=root,
        verified=verified,
        git=selected_git,
    )
    return _source_freeze_report(verified, git_projection_recomputed=True)


def build_beta_candidate(
    *,
    root: Path,
    output: Path,
    source_freeze: Path,
    builder_id: str,
    python_path: Path | None = None,
    cargo_path: Path | None = None,
    rustc_path: Path | None = None,
    linker_path: Path | None = None,
    git_path: Path | None = None,
    crate_cache_path: Path | None = None,
    binary_builder: BinaryBuilder | None = None,
) -> dict[str, object]:
    _validate_python_runtime(Path(sys.executable))
    build_started_on = (
        dt.datetime.now(tz=dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    root = root.resolve(strict=True)
    beta_profile.validate(root)
    qualified_host = require_declared_host()
    if git_path is None:
        raise BetaArtifactError(
            "beta release build requires an explicit absolute Git path"
        )
    if binary_builder is None and any(
        path is None
        for path in (
            python_path,
            cargo_path,
            rustc_path,
            linker_path,
            crate_cache_path,
        )
    ):
        raise BetaArtifactError(
            "beta release build requires explicit absolute Python, Cargo, rustc, linker, "
            "and crate-cache paths"
        )
    _require_new_external_output(root, output, "beta output workspace")
    _require_disjoint_external_paths(
        source_freeze,
        output,
        "beta source freeze",
        "beta output workspace",
    )
    selected_git = _secure_executable(git_path, "git")
    verified_source = _load_verified_source_freeze(
        root=root,
        source_freeze=source_freeze,
        strict_read_only=True,
    )
    snapshot = verified_source.snapshot
    _require_source_freeze_git_binding(
        root=root,
        verified=verified_source,
        git=selected_git,
    )
    committed = dict(verified_source.committed)
    matrix, archive_manifest, archive_selections, source_committed = (
        _source_archive_selections(committed)
    )
    expected_help_entry = committed.get("crates/cigar-cli/assets/cigar-help-beta.txt")
    if expected_help_entry is None or expected_help_entry.kind != "file":
        raise BetaArtifactError("committed beta help asset is missing")
    for required in ("LICENSE", "NOTICE"):
        entry = committed.get(required)
        if entry is None or entry.kind != "file":
            raise BetaArtifactError(f"committed binary payload is missing {required}")

    final: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(prefix="cigar-beta-stage-") as raw:
        staging_parent = Path(raw).resolve()
        os.chmod(staging_parent, 0o700)
        candidate = staging_parent / "candidate"
        candidate.mkdir(mode=0o700)
        staged_source = staging_parent / "committed-source"
        committed_tree_identity = _materialize_committed_tree(
            staged_source, source_committed
        )
        artifact_records: list[dict[str, object]] = []
        source_descriptor = dict(verified_source.descriptor)

        for manifest_entry, matrix_entry, selected in zip(
            archive_manifest["archives"],
            matrix["artifacts"][:5],
            archive_selections,
            strict=True,
        ):
            relative = f"{ARTIFACT_DIRECTORY}/{matrix_entry['filename']}"
            archive_path = candidate / relative
            if matrix_entry["id"] == "source":
                if relative != SOURCE_ARCHIVE_PATH:
                    raise BetaArtifactError("beta source archive destination changed")
                _write_private(archive_path, verified_source.archive_payload)
            else:
                policy = _contract_policy(staged_source, matrix_entry)
                metadata = _metadata(
                    artifact_id=str(matrix_entry["id"]),
                    contract_path=str(matrix_entry["contract"]),
                    contract_sha256=sha256_file(policy["path"]),
                    snapshot=snapshot,
                    payload=selected,
                    build=_source_build_record(),
                )
                write_deterministic_archive(
                    archive_path, selected, metadata, snapshot.source_date_epoch
                )
            if archive_path.stat().st_size > 64 * 1024 * 1024:
                raise BetaArtifactError(
                    f"beta source-derived archive exceeds external workspace limit: {relative}"
                )
            artifact_records.append(
                _artifact_record(
                    archive_path,
                    str(matrix_entry["id"]),
                    relative,
                    str(matrix_entry["contract"]),
                )
            )

        source_archive_record = artifact_records[0]
        if source_archive_record != verified_source.source_record:
            raise BetaArtifactError("build substituted the frozen source archive")
        source_descriptor_path = candidate / SOURCE_DESCRIPTOR_PATH
        _write_private(source_descriptor_path, verified_source.descriptor_payload)
        source_descriptor_reference = _file_reference(
            source_descriptor_path, SOURCE_DESCRIPTOR_PATH
        )
        if source_descriptor_reference != verified_source.report["source_descriptor"]:
            raise BetaArtifactError("build substituted the frozen source descriptor")

        if binary_builder is None:
            binary = _default_binary_builder(
                staged_source,
                staging_parent,
                snapshot,
                expected_help_entry.payload,
                source_committed,
                committed_tree_identity,
                python_path=python_path,
                cargo_path=cargo_path,
                rustc_path=rustc_path,
                linker_path=linker_path,
                git_path=selected_git,
                crate_cache_path=crate_cache_path,
            )
        else:
            binary = binary_builder(
                staged_source,
                staging_parent,
                snapshot,
                expected_help_entry.payload,
            )
        if (
            _verify_materialized_tree(staged_source, source_committed)
            != committed_tree_identity
        ):
            raise BetaArtifactError("staged source changed during binary construction")
        validate_elf_linux_x86_64(binary.payload)
        validate_version_document(binary.version_document, snapshot)
        expected_help_sha256 = sha256_bytes(expected_help_entry.payload)
        if binary.help_sha256 != expected_help_sha256:
            raise BetaArtifactError("built beta binary help binding is invalid")
        if not binary.components:
            raise BetaArtifactError("built beta binary has no SBOM dependency closure")

        matrix_entry = matrix["artifacts"][5]
        base_entries = [
            CommittedEntry("LICENSE", committed["LICENSE"].payload, 0o644),
            CommittedEntry("NOTICE", committed["NOTICE"].payload, 0o644),
            CommittedEntry("bin/cigar", binary.payload, 0o755),
        ]
        checksum_entry = CommittedEntry(
            "SHA256SUMS", _internal_checksums(base_entries), 0o644
        )
        binary_entries = [*base_entries, checksum_entry]
        policy = _contract_policy(staged_source, matrix_entry)
        binary_build = _binary_build_record(binary.version_document, binary.help_sha256)
        metadata = _metadata(
            artifact_id=str(matrix_entry["id"]),
            contract_path=str(matrix_entry["contract"]),
            contract_sha256=sha256_file(policy["path"]),
            snapshot=snapshot,
            payload=binary_entries,
            build=binary_build,
        )
        relative = f"{ARTIFACT_DIRECTORY}/{matrix_entry['filename']}"
        binary_archive = candidate / relative
        write_deterministic_archive(
            binary_archive,
            binary_entries,
            metadata,
            snapshot.source_date_epoch,
        )
        if binary_archive.stat().st_size > 64 * 1024 * 1024:
            raise BetaArtifactError(
                "beta binary archive exceeds external workspace limit"
            )
        artifact_records.append(
            _artifact_record(
                binary_archive,
                str(matrix_entry["id"]),
                relative,
                str(matrix_entry["contract"]),
            )
        )

        checksums_payload = "".join(
            f"{record['sha256']}  {record['path']}\n"
            for record in sorted(
                artifact_records,
                key=lambda item: str(item["path"]).encode("utf-8"),
            )
        ).encode("ascii")
        checksums_path = candidate / CHECKSUM_PATH
        _write_private(checksums_path, checksums_payload)
        checksums_reference = _file_reference(checksums_path, CHECKSUM_PATH)

        artifact_payloads = {
            str(record["path"]): _read_stable_file(
                candidate / str(record["path"]),
                64 * 1024 * 1024,
                str(record["path"]),
            )
            for record in artifact_records
        }
        member_bindings = _archive_member_bindings(
            root=staged_source,
            snapshot=snapshot,
            artifacts=artifact_records,
            artifact_payloads=artifact_payloads,
        )

        sbom = build_beta_sbom(
            snapshot=snapshot,
            artifacts=artifact_records,
            components=binary.components,
            dependencies=binary.dependencies,
            member_bindings=member_bindings,
        )
        sbom_path = candidate / SBOM_PATH
        _write_private_json(sbom_path, sbom)
        sbom_reference = _file_reference(sbom_path, SBOM_PATH)

        spdx = build_beta_spdx(
            snapshot=snapshot,
            artifacts=artifact_records,
            components=binary.components,
            dependencies=binary.dependencies,
            member_bindings=member_bindings,
        )
        spdx_path = candidate / SPDX_PATH
        _write_private_json(spdx_path, spdx)
        spdx_reference = _file_reference(spdx_path, SPDX_PATH)

        build_finished_on = (
            dt.datetime.now(tz=dt.UTC)
            .replace(microsecond=0)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        provenance = build_beta_provenance(
            snapshot=snapshot,
            artifacts=artifact_records,
            source_descriptor=source_descriptor,
            source_descriptor_reference=source_descriptor_reference,
            tools=binary.tools,
            dependency_materials=binary.dependency_materials,
            toolchain_materials=binary.toolchain_materials,
            host=qualified_host,
            builder_id=builder_id,
            started_on=build_started_on,
            finished_on=build_finished_on,
        )
        provenance_path = candidate / PROVENANCE_PATH
        _write_private_json(provenance_path, provenance)
        provenance_reference = _file_reference(provenance_path, PROVENANCE_PATH)

        manifest = _build_manifest_document(
            snapshot=snapshot,
            artifacts=artifact_records,
            source_descriptor_reference=source_descriptor_reference,
            checksums_reference=checksums_reference,
            sbom_reference=sbom_reference,
            spdx_reference=spdx_reference,
            provenance_reference=provenance_reference,
            binary_build=binary_build,
        )
        manifest_path = candidate / BUILD_MANIFEST_PATH
        _write_private_json(manifest_path, manifest)
        verification = verify_beta_candidate(
            root=staged_source,
            candidate=candidate,
            strict_read_only=False,
            execute_binary=True,
            snapshot_override=snapshot,
            committed_override=source_committed,
            resolution_override=_declared_cargo_resolution(staged_source, sbom),
            require_recorded_verification=False,
        )
        _write_private_json(candidate / VERIFICATION_PATH, verification)
        verify_beta_candidate(
            root=staged_source,
            candidate=candidate,
            strict_read_only=False,
            execute_binary=False,
            snapshot_override=snapshot,
            committed_override=source_committed,
        )
        if (
            _verify_materialized_tree(staged_source, source_committed)
            != committed_tree_identity
        ):
            raise BetaArtifactError(
                "staged source changed during candidate verification"
            )
        if _source_freeze_inventory(root, source_freeze, strict_read_only=True) != {
            SOURCE_ARCHIVE_PATH: verified_source.archive_payload,
            SOURCE_DESCRIPTOR_PATH: verified_source.descriptor_payload,
        }:
            raise BetaArtifactError("beta source freeze changed before publication")
        _require_unchanged_snapshot(root, snapshot, selected_git)
        try:
            with EvidenceWorkspace.create(
                output,
                repository_root=root,
                limits=EvidenceLimits(
                    max_files=128,
                    max_directories=32,
                    max_file_bytes=64 * 1024 * 1024,
                    max_total_bytes=512 * 1024 * 1024,
                    max_json_bytes=16 * 1024 * 1024,
                    max_path_depth=8,
                ),
            ) as workspace:
                for output_relative in sorted(
                    _expected_candidate_paths(include_verification=True),
                    key=lambda value: value.encode("utf-8"),
                ):
                    workspace.attach_file(candidate / output_relative, output_relative)
        except EvidenceWorkspaceError as error:
            raise BetaArtifactError(
                f"cannot materialize private beta candidate: {error}"
            ) from error
        final = verify_beta_candidate(
            root=staged_source,
            candidate=output,
            snapshot_override=snapshot,
            committed_override=committed,
        )
        if _source_freeze_inventory(root, source_freeze, strict_read_only=True) != {
            SOURCE_ARCHIVE_PATH: verified_source.archive_payload,
            SOURCE_DESCRIPTOR_PATH: verified_source.descriptor_payload,
        }:
            raise BetaArtifactError(
                "beta source freeze changed during candidate publication"
            )
        _require_unchanged_snapshot(root, snapshot, selected_git)
    if final is None:
        raise BetaArtifactError("beta candidate verification did not complete")
    return final


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser(
        "freeze-source",
        help="freeze and verify one clean deterministic beta source package",
    )
    freeze.add_argument("--root", type=Path, default=beta_profile.repo_root())
    freeze.add_argument("--out", type=Path, required=True)
    freeze.add_argument("--git", type=Path, required=True)
    verify_source = subparsers.add_parser(
        "verify-source",
        help="independently verify a frozen beta source package without a native host",
    )
    verify_source.add_argument("--root", type=Path, default=beta_profile.repo_root())
    verify_source.add_argument("--source-freeze", type=Path, required=True)
    verify_source.add_argument("--git", type=Path, required=True)
    build = subparsers.add_parser(
        "build", help="build and structurally verify a new unsigned beta candidate"
    )
    build.add_argument("--root", type=Path, default=beta_profile.repo_root())
    build.add_argument("--out", type=Path, required=True)
    build.add_argument("--source-freeze", type=Path, required=True)
    build.add_argument("--builder-id", required=True)
    build.add_argument("--python", type=Path, required=True)
    build.add_argument("--cargo", type=Path, required=True)
    build.add_argument("--rustc", type=Path, required=True)
    build.add_argument("--linker", type=Path, required=True)
    build.add_argument("--git", type=Path, required=True)
    build.add_argument("--crate-cache", type=Path, required=True)
    verify = subparsers.add_parser(
        "verify",
        help="structurally verify an unsigned candidate offline; this is nonqualifying",
    )
    verify.add_argument("--root", type=Path, default=beta_profile.repo_root())
    verify.add_argument("--candidate", type=Path, required=True)
    verify.add_argument(
        "--recompute-cargo",
        action="store_true",
        help="optionally recompute the locked Cargo graph with a hydrated offline cache",
    )
    verify.add_argument("--crate-cache", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.command == "freeze-source":
        report = freeze_beta_source(
            root=arguments.root,
            output=arguments.out,
            git_path=arguments.git,
        )
    elif arguments.command == "verify-source":
        report = verify_beta_source_freeze(
            root=arguments.root,
            source_freeze=arguments.source_freeze,
            git_path=arguments.git,
        )
    elif arguments.command == "build":
        report = build_beta_candidate(
            root=arguments.root,
            output=arguments.out,
            source_freeze=arguments.source_freeze,
            builder_id=arguments.builder_id,
            python_path=arguments.python,
            cargo_path=arguments.cargo,
            rustc_path=arguments.rustc,
            linker_path=arguments.linker,
            git_path=arguments.git,
            crate_cache_path=arguments.crate_cache,
        )
    elif arguments.command == "verify":
        report = verify_beta_candidate(
            root=arguments.root,
            candidate=arguments.candidate,
            recompute_cargo_resolution=arguments.recompute_cargo,
            crate_cache_path=arguments.crate_cache,
        )
    else:  # pragma: no cover - argparse enforces the closed command set.
        raise BetaArtifactError("unsupported beta artifact command")
    print(canonical_json_bytes(report).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, EvidenceWorkspaceError, SourceDescriptorError) as error:
        raise SystemExit(f"beta artifact operation failed: {error}") from error
