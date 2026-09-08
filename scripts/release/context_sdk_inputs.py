"""Source binding for local context SDK builds; not a hermetic-build attestation."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

from evidence_workspace import digest_secure_file
from release_lib import ReleaseError, canonical_json_bytes


EXACT_INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "pnpm-lock.yaml",
    "sdk/generate_clients.py",
    "sdk/local-context-release.v1.json",
    "sdk/capabilities-v1.json",
    "sdk/workflow-context-session.v1.json",
    "sdk/fixtures/stalled-worker.rs",
    "scripts/release/context_sdk_inputs.py",
    "scripts/release/context_sdk_consumer.py",
    "scripts/release/context-sdk-consumer.mjs",
    "scripts/release/prepare_context_sdk_rc.py",
    "scripts/release/qualify_context_sdk_rc.py",
    "scripts/release/finalize_context_sdk_rc.py",
    "scripts/release/release_lib.py",
    "scripts/release/evidence_workspace.py",
    ".github/workflows/context-sdk-rc.yml",
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
}


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
        source[name] = digest_secure_file(root / name).sha256
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
