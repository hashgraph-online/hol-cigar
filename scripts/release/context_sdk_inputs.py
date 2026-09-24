"""Source binding for local context SDK builds; not a hermetic-build attestation."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess

from evidence_workspace import digest_secure_file
from release_lib import ReleaseError, canonical_json_bytes


EXACT_INPUTS = (
    ".gitattributes",
    ".github/actionlint.yaml",
    "Cargo.toml",
    "Cargo.lock",
    "pnpm-lock.yaml",
    "sdk/generate_clients.py",
    "sdk/generate_local_assets.py",
    "sdk/native-platforms.v1.json",
    "sdk/LOCAL_CONTEXT_GUIDE.md",
    "sdk/local-context-llms.txt",
    "sdk/local-context-release.v1.json",
    "sdk/capabilities-v1.json",
    "sdk/workflow-context-session.v1.json",
    "sdk/fixtures/stalled-worker.rs",
    "scripts/release/context_sdk_inputs.py",
    "scripts/release/context_platforms.py",
    "scripts/release/build_context_worker.py",
    "scripts/release/context_distribution.py",
    "scripts/release/context_distribution_release.py",
    "scripts/release/qualify_context_distribution.py",
    "scripts/release/context_sdk_cases.py",
    "scripts/release/containers/context-consumer.Dockerfile",
    "scripts/release/containers/context-python.sh",
    "scripts/release/context_sdk_consumer.py",
    "scripts/release/context-sdk-consumer.mjs",
    "scripts/release/prepare_context_sdk_rc.py",
    "scripts/release/qualify_context_sdk_rc.py",
    "scripts/release/finalize_context_sdk_rc.py",
    "scripts/release/context_sdk_handoff.py",
    "scripts/release/context_sdk_beta.py",
    "scripts/release/context_sdk_release.py",
    "docs/release/context-sdk-0.11.0-notes.md",
    "docs/release/context-sdk-beta-notes.md",
    "scripts/release/release_lib.py",
    "scripts/release/evidence_workspace.py",
    ".github/workflows/context-sdk-rc.yml",
    ".github/workflows/context-sdk-beta.yml",
    ".github/workflows/context-sdk-release.yml",
    ".github/workflows/context-native.yml",
    ".github/workflows/context-distribution.yml",
    ".github/workflows/publish-hol-cigar.yml",
    ".github/workflows/stage-hol-cigar-npm.yml",
    ".github/workflows/npm-sdk-readiness.yml",
    ".github/workflows/fast-ci.yml",
)
SOURCE_DIRECTORIES = ("crates/cigar-context", "sdk/python", "sdk/typescript")
SOURCE_SUFFIXES = {
    ".rs",
    ".py",
    ".ts",
    ".mjs",
    ".json",
    ".toml",
    ".lock",
    ".md",
    ".typed",
    ".txt",
}


def windows_source_digest(root: Path, path: Path) -> str:
    """Bind a regular checkout input on Windows, without a POSIX-storage claim.

    Git cleanliness is checked separately at both build boundaries. Reject
    junctions/reparse points and changed file identity rather than following them.
    The private POSIX evidence workspace remains a separate, unchanged contract.
    """
    if not path.is_absolute() or not path.is_relative_to(root):
        raise ReleaseError("source input is outside the checkout")
    for current in [path, *path.parents]:
        metadata = current.lstat()
        if current.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ReleaseError("source input uses a link or reparse point")
        if current == root:
            break
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ReleaseError("source input must be a regular, unlinked file")
    if not 0 <= before.st_size <= 64 * 1024 * 1024:
        raise ReleaseError("source input exceeds byte limit")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        payload = stream.read(64 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    # Windows can report different ctime values through path and handle APIs.
    # Check ctime stability within each API, and file identity/mtime across both.
    for initial, other, compared in (
        (before, opened, fields),
        (opened, after, (*fields, "st_ctime_ns")),
        (before, path.lstat(), (*fields, "st_ctime_ns")),
    ):
        changed = {
            key: [getattr(initial, key), getattr(other, key)]
            for key in compared
            if getattr(initial, key) != getattr(other, key)
        }
        if changed:
            raise ReleaseError(
                f"source input changed while reading {path.relative_to(root)}: {changed}"
            )
    if len(payload) != before.st_size:
        raise ReleaseError("source input size changed while reading")
    return hashlib.sha256(payload).hexdigest()


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise ReleaseError("cannot bind SDK inputs to the Git checkout")
    return result.stdout


def capture(root: Path, *, allow_dirty: bool = False) -> dict[str, object]:
    """Bind tracked source bytes and revision without reading envs or generated trees.

    Dirty work is allowed only for explicitly requested diagnostic builds. A
    final release still needs independent clean builders and signed provenance.
    """
    root = root.resolve(strict=True)
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=normal")
    if status and not allow_dirty:
        raise ReleaseError(
            "SDK release build requires a clean checkout; --allow-dirty is diagnostic only"
        )
    tracked = _git(root, "ls-files", "-z", "--", *EXACT_INPUTS, *SOURCE_DIRECTORIES)
    names = sorted(name.decode("utf-8") for name in tracked.split(b"\0") if name)
    source = {}
    for name in names:
        path = Path(name)
        if name not in EXACT_INPUTS:
            if any(part.startswith(".") for part in path.parts):
                continue
            if path.suffix not in SOURCE_SUFFIXES and path.name not in {
                "LICENSE",
                "NOTICE",
            }:
                continue
        source[name] = (
            windows_source_digest(root, root / name)
            if os.name == "nt"
            else digest_secure_file(root / name).sha256
        )
    if not set(EXACT_INPUTS) <= set(source):
        raise ReleaseError("SDK source binding is missing a tracked build input")
    epoch = int(_git(root, "show", "-s", "--format=%ct", "HEAD").decode().strip())
    if not 0 <= epoch <= 253_402_300_799:
        raise ReleaseError("invalid source commit timestamp")
    return {
        "schema": "cigar.context-sdk-source-binding.v1",
        "commit": _git(root, "rev-parse", "HEAD").decode().strip(),
        "clean": not bool(status),
        "source_date_epoch": epoch,
        "files": source,
        "sha256": hashlib.sha256(canonical_json_bytes(source)).hexdigest(),
        "limitation": "Source-byte binding only; not proof of hermetic or independent compilation.",
    }


def require_unchanged(
    root: Path, initial: dict[str, object], *, allow_dirty: bool = False
) -> None:
    if capture(root, allow_dirty=allow_dirty) != initial:
        raise ReleaseError(
            "SDK source changed during build; discard this diagnostic candidate"
        )
