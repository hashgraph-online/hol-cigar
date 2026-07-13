#!/usr/bin/env python3
"""Black-box conformance check for the exact embedded-local beta executable."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/release"))
from release_lib import ReleaseError, run_bounded  # noqa: E402


def run(binary: Path, *arguments: str):
    try:
        return run_bounded(
            [str(binary), *arguments],
            timeout=30,
            max_stdout=1024 * 1024,
            max_stderr=1024 * 1024,
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
                "TZ": "UTC",
            },
        )
    except ReleaseError as error:
        raise SystemExit(f"beta command execution failed: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    arguments = parser.parse_args()
    binary = arguments.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("beta binary must be an executable regular file")

    expected_help = (ROOT / "crates/cigar-cli/assets/cigar-help-beta.txt").read_bytes()
    help_result = run(binary, "help")
    if help_result.returncode != 0 or help_result.stdout != expected_help or help_result.stderr:
        raise SystemExit("beta help surface mismatch")

    version_result = run(binary, "version")
    if version_result.returncode != 0 or version_result.stderr:
        raise SystemExit("beta version command failed")
    try:
        version = json.loads(version_result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"beta version output is invalid: {error}") from error
    expected = {
        "build_profile": "release",
        "capability_profile": "workspace-metadata-only",
        "channel": "beta",
        "enabled_features": ["beta-embedded"],
        "production_ready": False,
        "qualification_status": "requires-external-release-evidence",
        "required_distribution": "ubuntu",
        "required_distribution_version": "24.04",
        "required_host_profile": "ubuntu-24.04-x86_64-glibc-2.39",
        "required_libc": "glibc",
        "required_libc_version": "2.39",
        "required_target_triple": "x86_64-unknown-linux-gnu",
        "release_profile": "cigar.beta.embedded-local.linux-x86_64.v1",
        "schema_version": "cigar.beta.build-metadata.v1",
        "target_arch": "x86_64",
        "target_env": "gnu",
        "target_os": "linux",
        "version": "0.1.0-beta.1",
    }
    revision = version.pop("source_revision", None) if isinstance(version, dict) else None
    if version != expected or not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40,64}", revision) is None:
        raise SystemExit("beta version identity mismatch")

    for rejected in ("catalog", "completion", "context", "daemon", "man", "mcp", "serve"):
        result = run(binary, rejected)
        if result.returncode == 0:
            raise SystemExit(f"excluded beta command was accepted: {rejected}")
    print("beta conformance passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
