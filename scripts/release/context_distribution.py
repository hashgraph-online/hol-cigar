#!/usr/bin/env python3
"""Build and inspect the local SDK distribution; never publish packages.

One npm archive contains every worker; each Python wheel contains exactly one.
Native build receipts are required inputs, not substitutes for installed tests.
"""

from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile

import context_platforms
import context_sdk_inputs
from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    reject_evidence_directory,
)

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = load_json(ROOT / "sdk/local-context-release.v1.json")
VERSION = IDENTITY["core_version"]
PROTOCOL = IDENTITY["protocol"]
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def file_record(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "expected a regular artifact")
    require(0 <= path.stat().st_size <= MAX_FILE, "artifact exceeds size limit")
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }


def inventory(directory: Path) -> dict:
    require(
        directory.is_dir() and not directory.is_symlink(), "missing artifact directory"
    )
    require(
        all(path.is_file() for path in directory.iterdir()),
        "unexpected artifact directory entry",
    )
    return {path.name: file_record(path) for path in sorted(directory.iterdir())}


def artifact_names(platform_ids: set[str]) -> set[str]:
    platforms = context_platforms.platforms()
    require(
        bool(platform_ids) and platform_ids <= platforms.keys(), "invalid platform set"
    )
    return {
        f"cigar-context-{VERSION}.crate",
        f"hol-org-cigar-{VERSION}.tgz",
        f"hol_cigar-{VERSION}.tar.gz",
        *(
            f"hol_cigar-{VERSION}-py3-none-{platforms[key]['wheel_tag']}.whl"
            for key in platform_ids
        ),
    }


def archive_files(path: Path) -> dict[str, bytes]:
    """Inspect bounded regular members without extracting attacker-chosen paths."""
    result = {}
    total = 0

    def add(name: str, size: int, read) -> None:
        nonlocal total
        parts = PurePosixPath(name)
        require(
            name
            and not parts.is_absolute()
            and ".." not in parts.parts
            and "\\" not in name,
            "unsafe archive member path",
        )
        require(
            parts.as_posix() == name and name not in result,
            "duplicate or noncanonical archive member",
        )
        total += size
        require(
            0 <= size <= MAX_FILE and total <= MAX_TOTAL and len(result) < 5000,
            "archive exceeds limits",
        )
        payload = read()
        require(len(payload) == size, "archive member length mismatch")
        result[name] = payload

    file_record(path)
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                require(not member.is_dir(), "unexpected directory member in wheel")
                mode = member.external_attr >> 16
                require(not stat.S_ISLNK(mode), "wheel contains a link")
                add(member.filename, member.file_size, lambda m=member: archive.read(m))
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            require(len(members) <= 6000, "archive member count exceeds limit")
            for member in members:
                if member.isdir():
                    require(
                        not PurePosixPath(member.name).is_absolute()
                        and ".." not in PurePosixPath(member.name).parts,
                        "unsafe archive directory",
                    )
                    continue
                require(member.isfile(), "archive contains a link or special file")
                add(
                    member.name,
                    member.size,
                    lambda m=member: archive.extractfile(m).read(MAX_FILE + 1),
                )
    return result


def validate_native(
    directory: Path, platform_id: str, binding: dict, *, diagnostic: bool = False
) -> dict:
    metadata = context_platforms.platforms()[platform_id]
    report = load_json(directory / "build.json")
    require(
        report.get("schema") == "cigar.native-worker-build.v1"
        and report.get("status") == "native-tested",
        "native worker has not passed its build tests",
    )
    require(
        report.get("platform") == platform_id
        and report.get("target") == metadata["target"],
        "native receipt platform mismatch",
    )
    recorded_source = report["source_binding"]
    if diagnostic:
        core_inputs = {
            name: value
            for name, value in binding["files"].items()
            if name.startswith("crates/cigar-context/")
            or name in {"Cargo.toml", "Cargo.lock"}
        }
        require(
            bool(core_inputs)
            and all(
                recorded_source["files"].get(name) == value
                for name, value in core_inputs.items()
            ),
            "diagnostic worker core differs from current source",
        )
    else:
        require(
            binding.get("clean") is True and recorded_source == binding,
            "native worker source binding mismatch",
        )
    required = {
        "cargo-version",
        "rustc-version",
        "package",
        "build",
        "core-tests",
        "worker-version",
        "worker-compile",
        "dependencies",
    }
    if platform_id == "win32-x64" and (
        not diagnostic
        or any(row["name"] == "linker-version" for row in report["checks"])
    ):
        required.add("linker-version")
        require(
            report.get("linker", {}).get("version", "").startswith("LLD ")
            and len(report["linker"].get("sha256", "")) == 64,
            "Windows build must use the pinned Rust linker",
        )
    if not diagnostic or any(
        row["name"] == "stalled-worker-build" for row in report["checks"]
    ):
        required.add("stalled-worker-build")
    checks = report["checks"]
    require(
        {row["name"] for row in checks} == required
        and len(checks) == len(required)
        and all(row["exit_code"] == 0 for row in checks),
        "native build checks are incomplete",
    )
    for name, record in report["files"].items():
        require(
            not PurePosixPath(name).is_absolute()
            and ".." not in PurePosixPath(name).parts
            and "\\" not in name,
            "invalid native receipt path",
        )
        require(file_record(directory / name) == record, "native receipt file mismatch")
    for row in checks:
        for stream in ("stdout", "stderr"):
            require(
                file_record(directory / f"logs/{row['name']}.{stream}")["sha256"]
                == row[f"{stream}_sha256"],
                "native build log mismatch",
            )
    native = directory / "native" / platform_id
    manifest = load_json(native / "manifest.json")
    require(manifest == report["worker"], "native manifest differs from build receipt")
    require(
        manifest.get("core_version") == manifest.get("sdk_release") == VERSION
        and manifest.get("protocol") == PROTOCOL
        and manifest.get("target") == metadata["target"],
        "native worker version/protocol/target mismatch",
    )
    require(
        file_record(native / metadata["executable"])["sha256"] == manifest["sha256"],
        "native worker hash mismatch",
    )
    require(
        file_record(directory / f"source/cigar-context-{VERSION}.crate")["sha256"]
        == manifest["source_archive_sha256"],
        "native source archive mismatch",
    )
    require(
        context_platforms.inspect_binary(native / metadata["executable"], platform_id)
        == report["binary"],
        "native binary inspection differs from build receipt",
    )
    return report


def verify_packages(artifacts: Path, workers: dict[str, dict]) -> dict:
    platforms = context_platforms.platforms()
    require(
        set(inventory(artifacts)) == artifact_names(set(workers)),
        "archive inventory does not match the platform set",
    )

    def worker_files(files: dict, prefix: str, expected: set[str]) -> None:
        actual = {
            name[len(prefix) :].split("/")[0]
            for name in files
            if name.startswith(prefix)
        }
        require(
            actual == expected,
            "package is missing a worker or contains an unexpected platform",
        )
        for key in expected:
            manifest = json.loads(files[f"{prefix}{key}/manifest.json"])
            require(
                manifest == workers[key]["worker"],
                "packaged manifest differs from native build",
            )
            require(
                hashlib.sha256(
                    files[f"{prefix}{key}/{platforms[key]['executable']}"]
                ).hexdigest()
                == manifest["sha256"],
                "packaged worker checksum mismatch",
            )
            require(
                files[f"{prefix}{key}/THIRD_PARTY_NOTICES.txt"]
                and files[f"{prefix}{key}/dependencies.json"],
                "native dependency notices are missing",
            )

    npm = archive_files(artifacts / f"hol-org-cigar-{VERSION}.tgz")
    package = json.loads(npm["package/package.json"])
    require(
        package["name"] == "@hol-org/cigar" and package["version"] == VERSION,
        "npm identity mismatch",
    )
    require(
        package["publishConfig"]
        == {
            "access": "public",
            "registry": "https://registry.npmjs.org/",
            "tag": "latest",
        },
        "npm publication target mismatch",
    )
    require(
        package["engines"]["node"] == ">=24.10.0 <25" and package["type"] == "module",
        "npm runtime contract mismatch",
    )
    require(
        package["dependencies"] == {"@bufbuild/protobuf": "2.12.1"},
        "npm runtime dependencies changed",
    )
    require(
        not {"preinstall", "install", "postinstall"} & package["scripts"].keys(),
        "npm must not download workers on install",
    )
    require(
        package["bin"] == {"cigar-context": "./dist/local-cli.js"},
        "npm diagnostic entrypoint missing",
    )
    for export in (".", "./context", "./examples/local-workflow"):
        for target in package["exports"][export].values():
            require(
                "package/" + target.removeprefix("./") in npm,
                "npm export target missing",
            )
    for name in (
        "README.md",
        "AGENT_GUIDE.md",
        "llms.txt",
        "LICENSE",
        "NOTICE",
        "dist/local-cli.js",
    ):
        require(
            bool(npm.get("package/" + name)),
            "npm standalone documentation or diagnostic missing",
        )
    require(
        not any(name.startswith("package/dist/tests/") for name in npm),
        "source tests leaked into npm package",
    )
    for name, content in npm.items():
        if name.endswith(".js.map"):
            source_map = json.loads(content)
            require(
                len(source_map["sources"]) == len(source_map["sourcesContent"])
                and all(
                    isinstance(value, str) for value in source_map["sourcesContent"]
                ),
                "npm source map is not self-contained",
            )
    worker_files(npm, "package/native/", set(workers))
    for key in workers:
        tag = "py3-none-" + platforms[key]["wheel_tag"]
        wheel = archive_files(artifacts / f"hol_cigar-{VERSION}-{tag}.whl")
        info = f"hol_cigar-{VERSION}.dist-info/"
        metadata = BytesParser().parsebytes(wheel[info + "METADATA"])
        require(
            metadata["Name"] == "hol-cigar" and metadata["Version"] == VERSION,
            "wheel identity mismatch",
        )
        require(
            set(metadata["Requires-Python"].replace(" ", "").split(","))
            == {">=3.14", "<3.15"},
            "wheel Python contract mismatch",
        )
        require(
            metadata.get_all("Requires-Dist") == ["protobuf<8,>=6.33.5"],
            "wheel runtime dependencies changed",
        )
        require("cigar_sdk/py.typed" in wheel, "wheel typing marker missing")
        require(
            metadata["License-Expression"] == "Apache-2.0"
            and metadata.get_all("License-File") == ["LICENSE", "NOTICE"],
            "wheel license metadata mismatch",
        )
        for name in ("LICENSE", "NOTICE"):
            require(
                bool(wheel.get(info + "licenses/" + name)), "wheel license file missing"
            )
        require(
            f"Tag: {tag}\n" in wheel[info + "WHEEL"].decode()
            and b"Root-Is-Purelib: false\n" in wheel[info + "WHEEL"],
            "wheel native tag mismatch",
        )
        require(
            b"cigar-context = cigar_sdk.local_cli:main"
            in wheel[info + "entry_points.txt"],
            "wheel diagnostic entrypoint missing",
        )
        for name in (
            "AGENT_GUIDE.md",
            "llms.txt",
            "local_cli.py",
            "examples/local_workflow.py",
        ):
            require(
                bool(wheel.get("cigar_sdk/" + name)),
                "wheel standalone guide/example missing",
            )
        rows = list(csv.reader(io.StringIO(wheel[info + "RECORD"].decode())))
        require(
            len(rows) == len(wheel) and {row[0] for row in rows} == wheel.keys(),
            "wheel RECORD inventory mismatch",
        )
        for name, checksum, size in rows:
            if name == info + "RECORD":
                require(
                    not checksum and not size, "wheel RECORD self-hash must be empty"
                )
            else:
                value = (
                    base64.urlsafe_b64encode(hashlib.sha256(wheel[name]).digest())
                    .decode()
                    .rstrip("=")
                )
                require(
                    checksum == "sha256=" + value and size == str(len(wheel[name])),
                    "wheel RECORD hash mismatch",
                )
        worker_files(wheel, "cigar_sdk/_native/", {key})
    sdist = archive_files(artifacts / f"hol_cigar-{VERSION}.tar.gz")
    require(
        not any("/_native/" in name for name in sdist),
        "portable sdist must not contain a host-specific worker",
    )
    for name in (
        "PKG-INFO",
        "LICENSE",
        "NOTICE",
        "CHANGELOG.md",
        "src/cigar_sdk/py.typed",
        "AGENT_GUIDE.md",
        "llms.txt",
        "hatch_build.py",
        "src/cigar_sdk/examples/local_workflow.py",
    ):
        require(
            f"hol_cigar-{VERSION}/{name}" in sdist, "sdist standalone asset missing"
        )
    source_hash = file_record(artifacts / f"cigar-context-{VERSION}.crate")["sha256"]
    require(
        all(
            row["worker"]["source_archive_sha256"] == source_hash
            for row in workers.values()
        ),
        "workers were not built from the distributed source archive",
    )
    return {
        "platforms": sorted(workers),
        "artifacts": inventory(artifacts),
        "archive_contracts": "passed",
    }


class Runner:
    def __init__(self, output: Path, environment: dict | None = None):
        self.output = output
        self.logs = output / "logs"
        self.logs.mkdir()
        self.environment = os.environ.copy() | (environment or {})
        self.checks = []

    def run(
        self, name: str, command: list, *, cwd: Path = ROOT, expected_exit: int = 0
    ) -> bytes:
        print(name, flush=True)
        started = time.monotonic()
        stdout, stderr = self.logs / f"{name}.stdout", self.logs / f"{name}.stderr"
        with stdout.open("xb") as out, stderr.open("xb") as err:
            result = subprocess.run(
                [str(item) for item in command],
                cwd=cwd,
                env=self.environment,
                stdout=out,
                stderr=err,
                timeout=900,
            )
        self.checks.append(
            {
                "name": name,
                "exit_code": result.returncode,
                "expected_exit": expected_exit,
                "elapsed_seconds": time.monotonic() - started,
                "stdout": file_record(stdout),
                "stderr": file_record(stderr),
            }
        )
        (self.output / "checks.json").write_bytes(canonical_json_bytes(self.checks))
        require(
            result.returncode == expected_exit, f"{name} failed; inspect {self.logs}"
        )
        return stdout.read_bytes()


def npm_command(executable: str) -> list[str]:
    path = Path(shutil.which(executable) or executable).absolute()
    if os.name == "nt" or path.suffix.lower() == ".cmd":
        script = path.parent / "node_modules/npm/bin/npm-cli.js"
        require(script.is_file(), "cannot locate npm's JavaScript entrypoint")
        return ["node", str(script)]
    return [str(path)]


def stage_package(source: Path, destination: Path, names: tuple[str, ...]) -> None:
    destination.mkdir()
    for name in names:
        incoming = source / name
        if incoming.is_dir():
            shutil.copytree(
                incoming,
                destination / name,
                ignore=shutil.ignore_patterns(
                    "__pycache__",
                    "*.pyc",
                    "_native",
                    "tests" if name == "dist" else "__unused__",
                ),
            )
        else:
            shutil.copyfile(incoming, destination / name)


def build(args) -> None:
    diagnostic = args.diagnostic_worker is not None
    binding = context_sdk_inputs.capture(ROOT, allow_dirty=diagnostic)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    worker_reports = {}
    if diagnostic:
        item = load_json(args.diagnostic_worker / "build.json")["platform"]
        directories = {item: args.diagnostic_worker.absolute()}
    else:
        require(
            args.workers is not None and args.builder in {"first", "second"},
            "complete builds require worker inputs and builder identity",
        )
        directories = {
            key: args.workers / f"context-worker-{key}-{args.builder}"
            for key in context_platforms.platforms()
        }
        identity = load_json(ROOT / "sdk/local-context-release.v1.json")
        require(
            set(identity["bundled_native_targets"])
            == {row["target"] for row in context_platforms.platforms().values()},
            "release identity does not declare the complete native matrix",
        )
    workers = output / "workers"
    workers.mkdir()
    for key, directory in directories.items():
        report = validate_native(directory, key, binding, diagnostic=diagnostic)
        worker_reports[key] = report
        destination = workers / key
        destination.mkdir()
        for relative in (*report["files"], "build.json", "checks.json"):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / relative, target)
        (
            destination
            / "native"
            / key
            / context_platforms.platforms()[key]["executable"]
        ).chmod(0o755)
    environment = {
        "SOURCE_DATE_EPOCH": str(binding["source_date_epoch"]),
        "npm_config_cache": str(output / "npm-cache"),
        "PATH": str(Path(shutil.which(args.pnpm) or args.pnpm).absolute().parent)
        + os.pathsep
        + os.environ["PATH"],
    }
    runner = Runner(output, environment)
    runner.run(
        "generated-local-assets",
        [sys.executable, "sdk/generate_local_assets.py", "--check"],
    )
    runner.run(
        "typescript-build", [args.pnpm, "--dir", "sdk/typescript", "run", "build"]
    )
    ts_stage = output / "typescript"
    stage_package(
        ROOT / "sdk/typescript",
        ts_stage,
        (
            "dist",
            "fixtures",
            "README.md",
            "AGENT_GUIDE.md",
            "llms.txt",
            "LICENSE",
            "NOTICE",
            "package.json",
        ),
    )
    for key in directories:
        shutil.copytree(workers / key / "native" / key, ts_stage / "native" / key)
    packed = output / "packed"
    packed.mkdir()
    npm = npm_command(args.npm)
    runner.run(
        "npm-pack",
        [*npm, "pack", "--ignore-scripts", "--pack-destination", packed],
        cwd=ts_stage,
    )
    py_names = (
        "src",
        "tests",
        "README.md",
        "CHANGELOG.md",
        "AGENT_GUIDE.md",
        "llms.txt",
        "LICENSE",
        "NOTICE",
        "pyproject.toml",
        "hatch_build.py",
    )
    py_stage = output / "python-source"
    stage_package(ROOT / "sdk/python", py_stage, py_names)
    runner.run(
        "python-sdist",
        [args.uv, "build", "--sdist", "--out-dir", packed],
        cwd=py_stage,
    )
    for key in directories:
        stage = output / ("python-" + key)
        shutil.copytree(py_stage, stage)
        shutil.copytree(
            workers / key / "native" / key, stage / "src/cigar_sdk/_native" / key
        )
        runner.run(
            "python-wheel-" + key,
            [args.uv, "build", "--wheel", "--out-dir", packed],
            cwd=stage,
        )
    first = next(iter(directories))
    shutil.copyfile(
        workers / first / f"source/cigar-context-{VERSION}.crate",
        packed / f"cigar-context-{VERSION}.crate",
    )
    artifacts = output / "artifacts"
    artifacts.mkdir()
    require(
        set(inventory(packed)) - {".gitignore"} == artifact_names(set(worker_reports)),
        "package tools produced unexpected archives",
    )
    for name in sorted(artifact_names(set(worker_reports))):
        shutil.copyfile(packed / name, artifacts / name)
    verification = verify_packages(artifacts, worker_reports)
    # Consumers use compiled tests from the same checkout against installed modules.
    shutil.copytree(ROOT / "sdk/typescript/dist/tests", output / "typescript-tests")
    context_sdk_inputs.require_unchanged(ROOT, binding, allow_dirty=diagnostic)
    report = {
        "schema": "cigar.context-distribution-candidate.v1",
        "release": VERSION,
        "status": "archives-verified; installed qualification required",
        "release_ready": False,
        "diagnostic": diagnostic,
        "builder": args.builder,
        "source_binding": binding,
        "workers": worker_reports,
        "checks": runner.checks,
        **verification,
    }
    (output / "candidate.json").write_bytes(canonical_json_bytes(report))
    print(
        json.dumps(
            {
                key: report[key]
                for key in ("status", "diagnostic", "platforms", "artifacts")
            }
        )
    )


def verify_candidate(directory: Path, *, release: bool = True) -> dict:
    report = load_json(directory / "candidate.json")
    require(
        report.get("schema") == "cigar.context-distribution-candidate.v1"
        and report.get("release") == VERSION,
        "invalid distribution candidate",
    )
    if release:
        require(
            report.get("diagnostic") is False
            and report["source_binding"]["clean"] is True,
            "diagnostic or dirty builds cannot qualify a release",
        )
        require(
            set(report["platforms"]) == context_platforms.platforms().keys(),
            "complete native matrix required",
        )
    actual = verify_packages(directory / "artifacts", report["workers"])
    require(
        actual["artifacts"] == report["artifacts"]
        and actual["platforms"] == report["platforms"],
        "candidate archive bytes changed",
    )
    for key in report["platforms"]:
        native = validate_native(
            directory / "workers" / key,
            key,
            report["source_binding"],
            diagnostic=report["diagnostic"],
        )
        require(native == report["workers"][key], "candidate native receipt changed")
    for check in report["checks"]:
        require(check["exit_code"] == 0, "candidate build check failed")
        for stream in ("stdout", "stderr"):
            require(
                file_record(directory / f"logs/{check['name']}.{stream}")
                == check[stream],
                "candidate build log changed",
            )
    return report


def main() -> None:
    require(
        not sys.flags.optimize, "distribution qualification requires assertions enabled"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "verify-candidate", "compare"))
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--workers", type=Path)
    parser.add_argument("--builder", choices=("first", "second"))
    parser.add_argument("--diagnostic-worker", type=Path)
    parser.add_argument("--allow-diagnostic", action="store_true")
    parser.add_argument("--pnpm", default="pnpm")
    parser.add_argument("--npm", default="npm")
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "distribution candidate preparation")
    if args.command == "build":
        require(args.output is not None, "build requires a create-new output directory")
        build(args)
    elif args.command == "compare":
        require(
            args.first is not None
            and args.second is not None
            and args.commit is not None,
            "comparison requires two candidate directories and their exact commit",
        )
        print(json.dumps(compare_candidates(args.first, args.second, args.commit)))
    else:
        require(args.directory is not None, "verify requires a candidate directory")
        report = verify_candidate(args.directory, release=not args.allow_diagnostic)
        print(
            json.dumps(
                {
                    "status": "candidate-bytes-verified",
                    "release_ready": False,
                    "platforms": report["platforms"],
                }
            )
        )


def compare_candidates(first: Path, second: Path, commit: str) -> dict:
    require(
        first.resolve() != second.resolve(),
        "two distinct candidate directories required",
    )
    left, right = verify_candidate(first), verify_candidate(second)
    require(
        left["builder"] == "first" and right["builder"] == "second",
        "candidate builder identities differ",
    )
    require(
        left["source_binding"] == right["source_binding"]
        and left["source_binding"]["commit"] == commit,
        "independent builders used different source",
    )
    require(
        left["artifacts"] == right["artifacts"], "independent SDK archive bytes differ"
    )
    require(
        all(
            left["workers"][key]["worker"] == right["workers"][key]["worker"]
            for key in left["platforms"]
        ),
        "independent native worker bytes differ",
    )
    require(
        left["workers"].get("win32-x64", {}).get("linker")
        == right["workers"].get("win32-x64", {}).get("linker"),
        "independent Windows linker identities differ",
    )
    return {
        "schema": "cigar.context-distribution-comparison.v1",
        "status": "identical",
        "release_ready": False,
        "source_commit": commit,
        "platforms": left["platforms"],
        "artifacts": left["artifacts"],
        "independent_builds": 2,
        "limitation": "Hosted workflow job separation establishes builder independence; matching files alone do not.",
    }


if __name__ == "__main__":
    try:
        main()
    except (
        ReleaseError,
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(f"distribution preparation failed: {error}") from error
