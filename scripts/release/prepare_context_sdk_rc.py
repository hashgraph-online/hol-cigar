#!/usr/bin/env python3
"""Stage local SDK RC archives, never publish. Output must be a new directory.

Requires pinned repo dependencies already installed, uv, pnpm, npm, Rust 1.92 and
Python 3.14. RC1 native packaging is deliberately restricted to macOS ARM64.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from release_lib import reject_evidence_directory
import context_sdk_inputs

ROOT = Path(__file__).resolve().parents[2]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if sys.flags.optimize:
        raise SystemExit(
            "SDK qualification requires assertions enabled; do not use Python -O"
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--pnpm", required=True)
    parser.add_argument("--npm", required=True)
    parser.add_argument("--uv", required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="diagnostic builds only; never qualifies a release",
    )
    parser.add_argument(
        "--evidence-dir", type=Path, help="inapplicable to local diagnostic builds"
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "local SDK diagnostic build")
    source_binding = context_sdk_inputs.capture(ROOT, allow_dirty=args.allow_dirty)
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise SystemExit(
            "RC1 bundled-native profile supports macOS ARM64 only; do not mislabel another target"
        )
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "logs"
    artifacts = output / "artifacts"
    logs.mkdir()
    artifacts.mkdir()
    env = os.environ.copy()
    env["PATH"] = (
        str(Path(args.cargo).absolute().parent)
        + os.pathsep
        + str(Path(args.pnpm).absolute().parent)
        + os.pathsep
        + env["PATH"]
    )
    env["CARGO_TARGET_DIR"] = str(args.target_dir.absolute())
    env["MACOSX_DEPLOYMENT_TARGET"] = "11.0"
    env["SOURCE_DATE_EPOCH"] = str(source_binding["source_date_epoch"])
    env["npm_config_cache"] = str(output / "npm-cache")
    records = []

    def run(name, command, cwd=ROOT, extra=None):
        command = [str(part) for part in command]
        started = time.monotonic()
        print(name, flush=True)
        with (logs / f"{name}.log").open("wb") as log:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=env | (extra or {}),
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=1200,
            )
        record = {
            "name": name,
            "argv": command,
            "cwd": str(cwd),
            "exit_code": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "log_sha256": sha(logs / f"{name}.log"),
        }
        records.append(record)
        (output / "checks.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(f"{name} failed; inspect {logs / (name + '.log')}")
        return (logs / f"{name}.log").read_text()

    run("rust-version", [args.cargo, "--version"])
    run("node-version", ["node", "--version"])
    run("python-version", [sys.executable, "--version"])
    run("pnpm-version", [args.pnpm, "--version"])
    run("rust-format", [args.cargo, "fmt", "--all", "--check"])
    run(
        "rust-clippy",
        [
            args.cargo,
            "clippy",
            "--locked",
            "-p",
            "cigar-context",
            "--all-targets",
            "--features",
            "bpe",
            "--",
            "-D",
            "warnings",
        ],
    )
    run(
        "rust-tests",
        [
            args.cargo,
            "test",
            "--locked",
            "-p",
            "cigar-context",
            "--features",
            "bpe",
            "--",
            "--test-threads=1",
        ],
    )
    run(
        "rust-core-tests",
        [
            args.cargo,
            "test",
            "--locked",
            "-p",
            "cigar-context",
            "--no-default-features",
            "--",
            "--test-threads=1",
        ],
    )
    run(
        "rust-package",
        [
            args.cargo,
            "package",
            "--locked",
            "-p",
            "cigar-context",
            *(["--allow-dirty"] if args.allow_dirty else []),
            "--no-verify",
        ],
    )
    archive = args.target_dir / "package/cigar-context-0.10.0.crate"
    shutil.copy2(archive, artifacts / archive.name)
    native_source = output / "native-source"
    native_source.mkdir()
    with tarfile.open(archive) as packed:
        packed.extractall(native_source, filter="data")
    native_root = native_source / "cigar-context-0.10.0"
    run(
        "native-build-from-package",
        [args.cargo, "build", "--locked", "--release", "--features", "bpe", "--bins"],
        native_root,
    )
    worker = args.target_dir / "release/cigar-context-worker"
    run("native-version", [worker, "--version"])
    run("native-linkage", ["/usr/bin/otool", "-L", worker])
    run("native-deployment", ["/usr/bin/otool", "-l", worker])
    manifest = {
        "protocol": "cigar.context-worker.v1",
        "core_version": "0.10.0",
        "sdk_release": "0.10.0-rc.1",
        "target": "aarch64-apple-darwin",
        "sha256": sha(worker),
        "source_archive_sha256": sha(archive),
    }
    native = output / "native/darwin-arm64"
    native.mkdir(parents=True)
    shutil.copy2(worker, native / worker.name)
    (native / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    metadata = json.loads(
        run(
            "native-dependencies",
            [
                args.cargo,
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--features",
                "bpe",
            ],
            native_root,
        )
    )
    notices = [
        "CIGAR context worker bundled dependency notices. Source versions are locked in the accompanying Rust crate.\n"
    ]
    dependencies = []
    for package in sorted(
        metadata["packages"], key=lambda p: (p["name"], p["version"])
    ):
        dependencies.append(
            {key: package[key] for key in ("name", "version", "license", "source")}
        )
        notices.append(
            f"\n=== {package['name']} {package['version']} ({package['license']}) ===\n"
        )
        directory = Path(package["manifest_path"]).parent
        license_files = sorted(
            p
            for p in directory.iterdir()
            if p.is_file()
            and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
        )
        for path in license_files:
            notices.append(f"\n{path.name}\n{path.read_text(errors='replace')}\n")
    (native / "THIRD_PARTY_NOTICES.txt").write_text("".join(notices))
    (native / "dependencies.json").write_text(json.dumps(dependencies, indent=2) + "\n")
    stalled = output / "stalled-worker"
    run(
        "transport-fixture-build",
        [
            Path(args.cargo).parent / "rustc",
            ROOT / "sdk/fixtures/stalled-worker.rs",
            "-o",
            stalled,
        ],
    )
    test_env = {
        "CIGAR_TEST_WORKER": str(worker),
        "CIGAR_TEST_STALLED_WORKER": str(stalled),
    }
    python = ROOT / "sdk/python/.venv/bin/python"
    run(
        "python-source-tests",
        [python, "-m", "pytest", "sdk/python/tests", "-q"],
        extra=test_env,
    )
    run(
        "python-types",
        [ROOT / "sdk/python/.venv/bin/mypy", "src/cigar_sdk"],
        ROOT / "sdk/python",
    )
    run(
        "python-lint",
        [ROOT / "sdk/python/.venv/bin/ruff", "check", "."],
        ROOT / "sdk/python",
    )
    run(
        "typescript-tests",
        [args.pnpm, "--dir", "sdk/typescript", "test"],
        extra=test_env,
    )
    run("typescript-types", [args.pnpm, "--dir", "sdk/typescript", "run", "typecheck"])

    # Stage from allowlisted package inputs; no credentials, VCS metadata, envs, or unrelated files.
    py_stage = output / "python"
    py_stage.mkdir()
    for name in [
        "src",
        "tests",
        "README.md",
        "LICENSE",
        "NOTICE",
        "pyproject.toml",
        "hatch_build.py",
    ]:
        source = ROOT / "sdk/python" / name
        if source.is_dir():
            shutil.copytree(
                source,
                py_stage / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "_native"),
            )
        else:
            shutil.copy2(source, py_stage / name)
    shutil.copytree(native.parent, py_stage / "src/cigar_sdk/_native")
    ts_stage = output / "typescript"
    ts_stage.mkdir()
    for name in ["dist", "fixtures", "README.md", "LICENSE", "NOTICE", "package.json"]:
        source = ROOT / "sdk/typescript" / name
        if source.is_dir():
            shutil.copytree(
                source, ts_stage / name, ignore=shutil.ignore_patterns("tests")
            )
        else:
            shutil.copy2(source, ts_stage / name)
    shutil.copytree(native.parent, ts_stage / "native")
    for index in [1, 2]:
        destination = output / f"pack-{index}"
        destination.mkdir()
        run(
            f"python-pack-{index}",
            [args.uv, "build", "--sdist", "--wheel", "--out-dir", destination],
            py_stage,
        )
        run(
            f"npm-pack-{index}",
            [args.npm, "pack", "--ignore-scripts", "--pack-destination", destination],
            ts_stage,
        )
    for first in sorted((output / "pack-1").iterdir()):
        if first.name == ".gitignore":
            continue
        second = output / "pack-2" / first.name
        if first.read_bytes() != second.read_bytes():
            raise SystemExit(f"non-reproducible archive: {first.name}")
        shutil.copy2(first, artifacts / first.name)
    inventories = []
    for path in sorted(artifacts.iterdir()):
        inventories.append(
            {"file": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
        )
    report = {
        "schema": "cigar.context-sdk-rc.v1",
        "python": "0.10.0rc1",
        "npm": "0.10.0-rc.1",
        "published": False,
        "source_binding": source_binding,
        "native_qualified_host": platform.platform(),
        "worker": manifest,
        "byte_reproducible_sdk_archives": True,
        "artifacts": inventories,
        "checks": records,
        "status": "staged; clean installed-consumer qualification still required",
    }
    context_sdk_inputs.require_unchanged(
        ROOT, source_binding, allow_dirty=args.allow_dirty
    )
    (output / "release.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
