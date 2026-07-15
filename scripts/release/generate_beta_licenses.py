#!/usr/bin/env python3
"""Regenerate beta legal files from checksum-verified Cargo and Rust inputs."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

import beta_artifacts
import beta_profile
from release_lib import (
    ReleaseError,
    reject_evidence_directory,
    repo_root,
    run_bounded,
    write_bytes,
    write_json,
)


def _replace_generated_directory(root: Path, relative: str) -> None:
    destination = root / relative
    if destination.is_symlink():
        raise ReleaseError(
            f"refusing to replace linked generated directory: {relative}"
        )
    if destination.exists():
        if not destination.is_dir():
            raise ReleaseError(f"generated path is not a directory: {relative}")
        for path in destination.rglob("*"):
            metadata = path.stat(follow_symlinks=False)
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ReleaseError(
                    f"generated directory contains a link or special file: {path}"
                )
        shutil.rmtree(destination)
    destination.mkdir(parents=True, mode=0o755)


def _selected_rust_notice(root: Path, rustc: Path) -> bytes:
    rustc = rustc.resolve(strict=True)
    environment = beta_artifacts._fixed_environment()
    result = run_bounded(
        [str(rustc), "--version", "--verbose"],
        cwd=root,
        env=environment,
        timeout=30,
        max_stdout=64 * 1024,
        max_stderr=64 * 1024,
    )
    if result.returncode != 0:
        raise ReleaseError("cannot inspect the Rust compiler selected for legal files")
    try:
        identity = result.stdout.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ReleaseError("Rust compiler identity is not UTF-8") from error
    releases = re.findall(r"^release: ([^\s]+)$", identity, flags=re.MULTILINE)
    if releases != [beta_profile.RUST_TOOLCHAIN_VERSION]:
        raise ReleaseError(
            "Rust legal files must come from the exact pinned "
            f"{beta_profile.RUST_TOOLCHAIN_VERSION} toolchain"
        )
    return beta_artifacts._rust_standard_library_notice(
        root=root, rustc=rustc, environment=environment
    )


def generate(*, root: Path, crate_cache: Path, rustc: Path) -> None:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ReleaseError("repository root is not a directory")
    with tempfile.TemporaryDirectory(prefix="cigar-beta-license-vendor-") as raw:
        staging = Path(raw)
        # License generation stages verified dependency sources in an owner-private directory.
        os.chmod(
            staging, 0o700
        )  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        _vendor, _homes, entries, _identity, _materials = (
            beta_artifacts._prepare_verified_vendor(
                root=root,
                crate_cache=crate_cache.resolve(strict=True),
                staging=staging,
            )
        )
        rust_notice = _selected_rust_notice(root, rustc)
        inventory, manifest, files = beta_artifacts._expected_beta_license_documents(
            root=root, vendor_entries=entries, rust_notice=rust_notice
        )

    _replace_generated_directory(
        root, "packaging/licenses/beta-third-party-license-files"
    )
    _replace_generated_directory(root, "packaging/licenses/rust")
    for relative, payload in sorted(files.items()):
        write_bytes(root / relative, payload)
    write_json(
        root / "packaging/licenses/beta-third-party-inventory.v1.json", inventory
    )
    write_json(
        root / "packaging/licenses/beta-third-party-license-manifest.v1.json",
        manifest,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--crate-cache", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
            "legal-source regeneration writes reviewed repository inputs, not release evidence"
        ),
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    reject_evidence_directory(arguments.evidence_dir, "beta legal-source regeneration")
    generate(
        root=arguments.root,
        crate_cache=arguments.crate_cache,
        rustc=arguments.rustc,
    )
    print("generated exact beta legal payload")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseError) as error:
        raise SystemExit(f"beta legal payload generation failed: {error}") from error
