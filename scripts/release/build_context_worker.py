#!/usr/bin/env python3
"""Build and execute one source-bound native context worker; never publish.

Run this on the target platform (Linux builds use the corresponding PyPA image).
The output is create-new. A release needs two independent matching builds and
installed SDK qualification in addition to this worker receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import time

import context_platforms
import context_sdk_inputs
from release_lib import ReleaseError, canonical_json_bytes, reject_evidence_directory

ROOT = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_matches(identity: str) -> bool:
    system, machine, *libc = identity.split("-")
    actual_system = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}.get(
        platform.system()
    )
    actual_machine = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if (system, machine) != (actual_system, actual_machine):
        return False
    if not libc:
        return True
    glibc = platform.libc_ver()[0].lower() == "glibc"
    musl = "musl" in " ".join(
        str(sysconfig.get_config_var(key) or "")
        for key in ("MULTIARCH", "HOST_GNU_TYPE", "SOABI")
    )
    return glibc if libc == ["gnu"] else musl


def main() -> None:
    if sys.flags.optimize:
        raise ReleaseError("native qualification requires assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform", choices=context_platforms.platforms(), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="local diagnostics only; cannot qualify a release",
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "native distribution worker build")
    if not host_matches(args.platform):
        raise ReleaseError(
            "native build must execute on the declared OS, architecture and libc"
        )
    metadata = context_platforms.platforms()[args.platform]
    source = context_sdk_inputs.capture(ROOT, allow_dirty=args.allow_dirty)
    identity = json.loads((ROOT / "sdk/local-context-release.v1.json").read_bytes())
    version = identity["core_version"]
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "logs"
    logs.mkdir()
    native = output / "native" / args.platform
    native.mkdir(parents=True)
    sources = output / "source"
    sources.mkdir()
    oracle = output / "oracle"
    oracle.mkdir()
    target_dir = args.target_dir.absolute()
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env["SOURCE_DATE_EPOCH"] = str(source["source_date_epoch"])
    env["MACOSX_DEPLOYMENT_TARGET"] = "11.0"
    cargo = shutil.which(args.cargo)
    if cargo is None:
        raise ReleaseError("the pinned Cargo executable is unavailable")
    env["PATH"] = str(Path(cargo).parent) + os.pathsep + env.get("PATH", "")
    checks = []

    def run(
        name: str, command: list, *, cwd: Path = ROOT, input_bytes: bytes | None = None
    ) -> bytes:
        print(name, flush=True)
        started = time.monotonic()
        result = subprocess.run(
            [str(item) for item in command],
            cwd=cwd,
            env=env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,
        )
        stdout = logs / f"{name}.stdout"
        stderr = logs / f"{name}.stderr"
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        checks.append(
            {
                "name": name,
                "argv": [str(item) for item in command],
                "exit_code": result.returncode,
                "elapsed_seconds": time.monotonic() - started,
                "stdout_sha256": digest(stdout),
                "stderr_sha256": digest(stderr),
            }
        )
        (output / "checks.json").write_bytes(canonical_json_bytes(checks))
        if result.returncode:
            raise ReleaseError(f"{name} failed; inspect {logs}")
        return result.stdout

    cargo_version = run("cargo-version", [cargo, "--version"]).decode().strip()
    if not cargo_version.startswith("cargo 1.92.0 "):
        raise ReleaseError("native builds require Cargo/Rust 1.92.0")
    rustc_version = (
        run(
            "rustc-version",
            [
                Path(cargo).with_name("rustc.exe" if os.name == "nt" else "rustc"),
                "--version",
            ],
        )
        .decode()
        .strip()
    )
    if not rustc_version.startswith("rustc 1.92.0 "):
        raise ReleaseError("native builds require Cargo/Rust 1.92.0")
    run(
        "package",
        [
            cargo,
            "package",
            "--locked",
            "--no-verify",
            "-p",
            "cigar-context",
            *(["--allow-dirty"] if args.allow_dirty else []),
        ],
    )
    archive = sources / f"cigar-context-{version}.crate"
    shutil.copyfile(target_dir / "package" / archive.name, archive)
    unpacked = output / "unpacked"
    unpacked.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(unpacked, filter="data")
    crate = unpacked / f"cigar-context-{version}"
    flags = [
        f"--remap-path-prefix={crate}=/cigar/native",
        f"--remap-path-prefix={ROOT}=/cigar/source",
    ]
    windows_flags = []
    linker = None
    if args.platform == "win32-x64":
        # Hosted Windows images can roll between independent jobs. Use the
        # linker shipped by the exact Rust toolchain, not the image's link.exe.
        # https://doc.rust-lang.org/rustc/codegen-options/index.html#linker-flavor
        rustc = Path(cargo).with_name("rustc.exe")
        sysroot = Path(
            subprocess.check_output(
                [rustc, "--print", "sysroot"], text=True, timeout=30
            ).strip()
        )
        pinned_linker = (
            sysroot / "lib/rustlib" / metadata["target"] / "bin/rust-lld.exe"
        )
        if not pinned_linker.is_file():
            raise ReleaseError("the pinned Rust distribution has no Windows linker")
        linker_version = (
            run("linker-version", [pinned_linker, "-flavor", "link", "--version"])
            .decode()
            .strip()
        )
        if not linker_version.startswith("LLD "):
            raise ReleaseError("the pinned Windows linker has an unexpected identity")
        linker = {"version": linker_version, "sha256": digest(pinned_linker)}
        windows_flags = [
            "-C",
            "target-feature=+crt-static",
            "-C",
            "link-arg=/Brepro",
            "-C",
            f"linker={pinned_linker}",
            "-C",
            "linker-flavor=lld-link",
        ]
        flags += windows_flags
    # Cargo's encoded form preserves paths containing spaces without shell parsing.
    env.pop("RUSTFLAGS", None)
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    run(
        "build",
        [
            cargo,
            "build",
            "--locked",
            "--release",
            "--features",
            "bpe",
            "--bins",
            "--target",
            metadata["target"],
        ],
        cwd=crate,
    )
    run(
        "core-tests",
        [
            cargo,
            "test",
            "--locked",
            "--features",
            "bpe",
            "--target",
            metadata["target"],
            "--",
            "--test-threads=1",
        ],
        cwd=crate,
    )
    executable = target_dir / metadata["target"] / "release" / metadata["executable"]
    worker = native / metadata["executable"]
    shutil.copyfile(executable, worker)
    worker.chmod(0o755)
    cli_name = "cigar-context.exe" if args.platform == "win32-x64" else "cigar-context"
    cli = oracle / cli_name
    shutil.copyfile(executable.parent / cli_name, cli)
    cli.chmod(0o755)
    fixture = oracle / ("stalled-worker.exe" if os.name == "nt" else "stalled-worker")
    run(
        "stalled-worker-build",
        [
            Path(cargo).with_name("rustc.exe" if os.name == "nt" else "rustc"),
            "--edition=2024",
            "--target",
            metadata["target"],
            ROOT / "sdk/fixtures/stalled-worker.rs",
            "-o",
            fixture,
            *windows_flags,
        ],
    )
    binary = context_platforms.inspect_binary(worker, args.platform)
    context_platforms.inspect_binary(cli, args.platform)
    run("worker-version", [worker, "--version"])
    commands = [
        {"op": "init", "domain": "native-build-probe", "limits": {}},
        {
            "op": "upsert",
            "document": {
                "id": "probe",
                "source": "cigar:probe",
                "text": "Local source-bound compilation.",
            },
        },
        {
            "op": "compile",
            "request": {"required": ["probe"], "allowed": ["probe"], "max_tokens": 256},
        },
    ]
    payload = b"".join(
        canonical_json_bytes({"id": index, "command": command})
        for index, command in enumerate(commands, 1)
    )
    responses = [
        json.loads(line)
        for line in run("worker-compile", [worker], input_bytes=payload).splitlines()
    ]
    if len(responses) != 3 or not all(row.get("ok") for row in responses):
        raise ReleaseError("native worker compile probe failed")
    if (
        responses[0]["result"]["core_version"] != version
        or responses[2]["result"]["snapshot"]["stats"]["rendered_tokens"] > 256
    ):
        raise ReleaseError("native worker compile/version mismatch")
    dependencies = json.loads(
        run(
            "dependencies",
            [
                cargo,
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--features",
                "bpe",
                "--filter-platform",
                metadata["target"],
            ],
            cwd=crate,
        )
    )
    records = []
    notices = [
        "CIGAR context worker dependency notices. Exact source versions are in the accompanying Rust crate.\n"
    ]
    active = {node["id"] for node in dependencies["resolve"]["nodes"]}
    for package in sorted(
        dependencies["packages"], key=lambda item: (item["name"], item["version"])
    ):
        if package["id"] not in active:
            continue
        records.append(
            {key: package[key] for key in ("name", "version", "license", "source")}
        )
        notices.append(
            f"\n=== {package['name']} {package['version']} ({package['license']}) ===\n"
        )
        for license_file in sorted(Path(package["manifest_path"]).parent.iterdir()):
            if license_file.is_file() and license_file.name.upper().startswith(
                ("LICENSE", "COPYING", "NOTICE")
            ):
                notices.append(
                    f"\n{license_file.name}\n{license_file.read_text(errors='replace')}\n"
                )
    (native / "dependencies.json").write_bytes(canonical_json_bytes(records))
    (native / "THIRD_PARTY_NOTICES.txt").write_text("".join(notices), encoding="utf-8")
    manifest = {
        "protocol": identity["protocol"],
        "core_version": version,
        "sdk_release": identity["versions"]["typescript"],
        "target": metadata["target"],
        "sha256": digest(worker),
        "source_archive_sha256": digest(archive),
    }
    (native / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    files = {}
    for directory in [native, oracle, sources, logs]:
        for path in sorted(directory.iterdir()):
            files[path.relative_to(output).as_posix()] = {
                "sha256": digest(path),
                "bytes": path.stat().st_size,
            }
    context_sdk_inputs.require_unchanged(ROOT, source, allow_dirty=args.allow_dirty)
    report = {
        "schema": "cigar.native-worker-build.v1",
        "status": "native-tested",
        "release_ready": False,
        "platform": args.platform,
        "target": metadata["target"],
        "source_binding": source,
        "worker": manifest,
        "binary": binary,
        "checks": checks,
        "files": files,
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "limitations": [
            "Requires independent-build byte comparison and installed SDK qualification before release."
        ],
    }
    if linker is not None:
        report["linker"] = linker
    (output / "build.json").write_bytes(canonical_json_bytes(report))
    # Only stable payloads/receipts are uploaded. The source extraction is build scratch.
    print(
        json.dumps(
            {
                "status": report["status"],
                "platform": args.platform,
                "worker_sha256": manifest["sha256"],
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"native build failed: {error}") from error
