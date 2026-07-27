#!/usr/bin/env python3
"""Capture the repaired R00 baseline from one exact clean committed source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RELEASE_TOOLS = ROOT / "scripts" / "release"
QUALITY_TOOLS = ROOT / "tools" / "quality"
for import_root in (RELEASE_TOOLS, QUALITY_TOOLS):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from bounded_process import BoundedProcessError, run_bounded
from evidence_workspace import (
    EvidenceWorkspace,
    EvidenceWorkspaceError,
)

SCHEMA_VERSION = "cigar.refinement-baseline.v1"
ANCHOR_PATH = Path("refinement/baselines/honey-anchor.v1.json")
IDENTITY = re.compile(r"^[0-9a-f]{40}$")
MULTIHASH = re.compile(r"^1220[0-9a-f]{64}$")
UNITTEST_COUNT = re.compile(r"Ran ([0-9]+) tests? in ")
PYTEST_COUNT = re.compile(r"([0-9]+) passed in ")
RUST_COUNT = re.compile(r"test result: ok\. ([0-9]+) passed;")
MAXIMUM_OUTPUT = 32 * 1024 * 1024

COMMANDS: tuple[tuple[str, tuple[str, ...], int, int], ...] = (
    (
        "local-scale-probe",
        (
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--manifest-path",
            "benches/cigarbench/local_scale_probe/Cargo.toml",
        ),
        1,
        600,
    ),
    (
        "cigarbench",
        (
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "benches/cigarbench/tests",
            "-q",
        ),
        66,
        900,
    ),
    (
        "demos",
        (
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "demos/tests",
            "-q",
        ),
        17,
        900,
    ),
    (
        "focused-rust",
        (
            "cargo",
            "test",
            "--locked",
            "-p",
            "cigar-compiler",
            "-p",
            "cigar-retrieval",
            "-p",
            "cigar-code-intel",
            "--all-targets",
        ),
        99,
        1_800,
    ),
    (
        "python-sdk",
        (
            "uv",
            "run",
            "--offline",
            "--frozen",
            "--project",
            "sdk/python",
            "python",
            "-m",
            "pytest",
            "sdk/python/tests",
            "-q",
        ),
        22,
        900,
    ),
)


class BaselineError(RuntimeError):
    """The R00 baseline cannot be captured safely."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def multihash(payload: bytes) -> str:
    return "1220" + sha256(payload)


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise BaselineError("unable to inspect source identity")
    return result.stdout


def source_identity(root: Path) -> dict[str, Any]:
    top = Path(git(root, "rev-parse", "--show-toplevel").decode().strip())
    if top.resolve(strict=True) != root:
        raise BaselineError("--root must be the Git worktree root")
    revision = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = git(root, "rev-parse", "--verify", "HEAD^{tree}").decode().strip()
    if not IDENTITY.fullmatch(revision) or not IDENTITY.fullmatch(tree):
        raise BaselineError("Git returned a malformed source identity")
    status = git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--no-renames",
    )
    if status:
        raise BaselineError("baseline capture requires a clean committed worktree")
    return {"revision": revision, "tree": tree, "committed": True, "clean": True}


def sanitized_environment() -> dict[str, str]:
    allowed = {
        "CARGO_HOME",
        "COREPACK_HOME",
        "GOCACHE",
        "GOMODCACHE",
        "HOME",
        "NPM_CONFIG_STORE_DIR",
        "PATH",
        "RUSTUP_HOME",
        "SYSTEMROOT",
        "TMPDIR",
        "UV_CACHE_DIR",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "CI": "true",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NPM_CONFIG_OFFLINE": "true",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "UV_OFFLINE": "1",
        }
    )
    for key in tuple(environment):
        upper = key.upper()
        if (
            upper.endswith("_PROXY")
            or "TOKEN" in upper
            or "PASSWORD" in upper
            or "SECRET" in upper
            or "CREDENTIAL" in upper
        ):
            environment.pop(key, None)
    return environment


def test_count(identifier: str, payload: bytes) -> int:
    text = payload.decode("utf-8", errors="replace")
    if identifier == "local-scale-probe":
        lines = [line for line in text.splitlines() if line.startswith("{")]
        if len(lines) != 1:
            raise BaselineError("local-scale probe did not emit one JSON record")
        try:
            record = json.loads(lines[0])
        except json.JSONDecodeError as error:
            raise BaselineError("local-scale probe emitted invalid JSON") from error
        if record != {
            "atom_cbor_bytes": 938,
            "edge_cbor_bytes": 373,
            "schema_version": "cigar.local-scale-record-probe.v1",
            "uuid_cbor_text_bytes": 38,
            "version_cbor_text_bytes": 70,
        }:
            raise BaselineError("local-scale probe measurements changed")
        return 1
    if identifier in {"cigarbench", "demos"}:
        matches = UNITTEST_COUNT.findall(text)
        if len(matches) != 1:
            raise BaselineError(f"{identifier} emitted an ambiguous test count")
        return int(matches[0])
    if identifier == "python-sdk":
        matches = PYTEST_COUNT.findall(text)
        if len(matches) != 1:
            raise BaselineError("Python SDK emitted an ambiguous test count")
        return int(matches[0])
    if identifier == "focused-rust":
        matches = [int(value) for value in RUST_COUNT.findall(text)]
        if not matches:
            raise BaselineError("focused Rust checks emitted no test counts")
        return sum(matches)
    raise BaselineError(f"unknown baseline command: {identifier}")


def run_checks(root: Path) -> list[dict[str, Any]]:
    environment = sanitized_environment()
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="cigar-r00-baseline-") as temporary:
        log_root = Path(temporary)
        for identifier, command, expected_tests, timeout in COMMANDS:
            log_path = log_root / f"{identifier}.log"
            result = run_bounded(
                list(command),
                cwd=root,
                env=environment,
                log_path=log_path,
                timeout_seconds=timeout,
                maximum_output_bytes=MAXIMUM_OUTPUT,
            )
            if (
                result["exit_code"] != 0
                or result["timed_out"]
                or result["output_overflow"]
                or result["descendant_cleanup_required"]
            ):
                raise BaselineError(f"baseline command failed: {identifier}")
            payload = log_path.read_bytes()
            observed_tests = test_count(identifier, payload)
            if observed_tests != expected_tests:
                raise BaselineError(
                    f"{identifier} test count changed: "
                    f"expected {expected_tests}, observed {observed_tests}"
                )
            records.append(
                {
                    "id": identifier,
                    "command": list(command),
                    "command_sha256": sha256(canonical(list(command))),
                    "status": "passed",
                    "exit_code": 0,
                    "tests": observed_tests,
                    "output_bytes": len(payload),
                    "output_sha256": sha256(payload),
                    "duration_seconds": result["duration_seconds"],
                }
            )
    return records


def capture(root: Path, evidence_dir: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    before = source_identity(root)
    anchor_path = root / ANCHOR_PATH
    anchor_payload = anchor_path.read_bytes()
    anchor = json.loads(anchor_payload)
    if anchor.get(
        "schema_version"
    ) != "cigar.refinement-honey-anchor.v1" or not MULTIHASH.fullmatch(
        "1220" + sha256(anchor_payload)
    ):
        raise BaselineError("Honey anchor is invalid")
    commands = run_checks(root)
    after = source_identity(root)
    if after != before:
        raise BaselineError("source identity changed during baseline capture")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "evidence_class": "diagnostic-baseline",
        "source": before,
        "honey_anchor": {
            "path": ANCHOR_PATH.as_posix(),
            "sha256": sha256(anchor_payload),
        },
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "commands": commands,
        "limitations": [
            "not-release-evidence",
            "not-installed-artifact-qualified",
            "cigarbench-corpus-is-harness-smoke",
        ],
    }
    receipt["receipt_id"] = multihash(canonical(receipt))
    with EvidenceWorkspace.create(evidence_dir, repository_root=root) as workspace:
        workspace.write_json("r00-baseline.json", receipt)
        workspace.read_files({"r00-baseline.json"}, strict_read_only=True)
    if source_identity(root) != before:
        raise BaselineError(
            "source identity changed while publishing baseline evidence"
        )
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, default=ROOT)
    result.add_argument("--evidence-dir", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    receipt = capture(arguments.root, arguments.evidence_dir)
    print(
        canonical(
            {
                "schema_version": SCHEMA_VERSION,
                "status": receipt["status"],
                "receipt_id": receipt["receipt_id"],
            }
        ).decode()
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        BaselineError,
        BoundedProcessError,
        EvidenceWorkspaceError,
        OSError,
    ) as error:
        raise SystemExit(f"R00 baseline capture failed: {error}") from error
