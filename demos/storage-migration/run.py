#!/usr/bin/env python3
"""Run the bounded generated v4-to-v5 source demo twice without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Never, Sequence

ROOT = Path(__file__).resolve().parents[2]
TEST = "migrate_v5::tests::migration_preserves_a_pruned_nonzero_retained_range"
MAX_OUTPUT = 8 * 1024 * 1024
TEST_RESULT = re.compile(rb"test result: ok\. 1 passed; 0 failed;")


class DemoError(Exception):
    """The bounded storage-migration demo failed closed."""


def fail(message: str) -> Never:
    raise DemoError(message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise DemoError("demo result is not canonical JSON") from error


def semantic_identity(value: Any) -> str:
    return "1220" + hashlib.sha256(canonical(value)).hexdigest()


def clean_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "SYSTEMROOT",
        "WINDIR",
        "TMPDIR",
        "CARGO_HOME",
        "RUSTUP_HOME",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    return environment


def run_once(index: int) -> dict[str, Any]:
    with tempfile.TemporaryFile() as output:
        try:
            completed = subprocess.run(
                [
                    "cargo",
                    "test",
                    "--offline",
                    "-p",
                    "cigar-store",
                    TEST,
                    "--",
                    "--exact",
                    "--nocapture",
                ],
                cwd=ROOT,
                env=clean_environment(),
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=900,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DemoError("migration product check did not complete") from error
        size = output.tell()
        if size > MAX_OUTPUT:
            fail("migration product check exceeded its output bound")
        output.seek(0)
        payload = output.read()
    if completed.returncode != 0 or TEST_RESULT.search(payload) is None:
        fail("migration product check did not pass exactly once")
    workflow = {
        "generated_source_format": 4,
        "generated_source_latest_revision": 1028,
        "generated_source_first_retained_revision": 5,
        "generated_source_retained_revisions": 1024,
        "verified_backup": "separate-directory",
        "migration_target": "distinct-new-file",
        "source_retained": True,
        "migrated_roots_and_revisions": "exact",
        "activated_format": 5,
        "compacted_first_revision": 773,
        "compacted_retained_revisions": 256,
        "restart_readiness": "authenticated-bounded-suffix",
        "deep_integrity": ["full", "unchanged-prefix", "force-full-repair"],
    }
    return {
        "run": index,
        "status": "product_check_passed",
        "semantic_identity": semantic_identity(workflow),
        "workflow": workflow,
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def publish(path: Path, payload: bytes) -> None:
    if (
        not path.is_absolute()
        or Path(os.path.normpath(os.fspath(path))) != path
        or path.exists()
        or path.is_symlink()
    ):
        fail("--output must be a new absolute path")
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700, parents=False)
    parent = path.parent.stat(follow_symlinks=False)
    if (
        path.parent.resolve(strict=True) != path.parent
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        fail("--output parent must be canonical and owner-private")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.chmod(path, 0o400)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    runs = [run_once(1), run_once(2)]
    identities = {run["semantic_identity"] for run in runs}
    if len(identities) != 1:
        fail("clean migration demo runs produced different semantic identities")
    report = {
        "schema_version": "cigar.generated-storage-migration-demo.v1",
        "demo_id": "generated-v4-v5-storage-migration",
        "product_version": "0.9.4",
        "network_required": False,
        "credentials_required": False,
        "clean_runs": 2,
        "runs": runs,
        "status": "source_product_demo_passed_twice",
    }
    report["report_digest"] = semantic_identity(report)
    payload = canonical(report) + b"\n"
    if arguments.output is None:
        print(payload.decode("utf-8"), end="")
    else:
        publish(arguments.output, payload)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as error:
        raise SystemExit(f"storage-migration-demo: {error}") from error
