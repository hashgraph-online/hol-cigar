#!/usr/bin/env python3
"""Build deterministic local archives twice in isolated homes and compare payload SHA-256 values."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from release_lib import ReleaseError, load_json, process_failure_summary, repo_root, require_source_date_epoch, run_bounded, write_json


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--require-committed-clean", action="store_true")
    return parser.parse_args()


def _build(root: Path, destination: Path, home: Path, epoch: int, require_clean: bool) -> dict[str, Any]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "TMPDIR": str(home / "tmp"),
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONHASHSEED": "0",
        "NO_COLOR": "1",
    }
    (home / "tmp").mkdir(parents=True)
    command = [sys.executable, str(root / "scripts/release/build_archives.py"), "--root", str(root), "--out", str(destination), "--source-date-epoch", str(epoch)]
    if require_clean:
        command.append("--require-committed-clean")
    result = run_bounded(command, cwd=root, env=environment, timeout=600, max_stdout=16 * 1024 * 1024)
    if result.returncode != 0:
        raise ReleaseError(process_failure_summary(result, "isolated archive build"))
    return load_json(destination / "build-manifest.json")


def main() -> int:
    arguments = parse_arguments()
    root = arguments.root.resolve()
    epoch = require_source_date_epoch(arguments.source_date_epoch)
    with tempfile.TemporaryDirectory(prefix="cigar-reproducibility-") as directory:
        temporary = Path(directory)
        first = _build(root, temporary / "builder-a/dist", temporary / "builder-a/home", epoch, arguments.require_committed_clean)
        second = _build(root, temporary / "builder-b/dist", temporary / "builder-b/home", epoch, arguments.require_committed_clean)
        first_artifacts = {item["id"]: (item["sha256"], item["bytes"]) for item in first["artifacts"]}
        second_artifacts = {item["id"]: (item["sha256"], item["bytes"]) for item in second["artifacts"]}
        if first.get("source") != second.get("source"):
            raise ReleaseError("isolated builders reported different source identities")
        if first_artifacts != second_artifacts:
            differences = sorted(set(first_artifacts) | set(second_artifacts))
            raise ReleaseError(f"isolated archive payloads differ: {differences}")
        report = {
            "schema_version": "cigar.reproducibility-report.v1",
            "scope": "source-derived-local-archives",
            "status": "passed",
            "source_date_epoch": epoch,
            "source": first["source"],
            "environment": {"timezone": "UTC", "locale": "C", "python_hash_seed": "0", "network_required": False},
            "artifacts": [
                {"id": identifier, "builder_a_sha256": value[0], "builder_b_sha256": second_artifacts[identifier][0], "bytes": value[1]}
                for identifier, value in sorted(first_artifacts.items())
            ],
        }
    if arguments.report is not None:
        write_json(arguments.report.resolve(), report)
    print(f"reproducibility passed for {len(report['artifacts'])} local archive payloads")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (subprocess.TimeoutExpired, ReleaseError) as error:
        raise SystemExit(f"reproducibility check failed: {error}") from error
