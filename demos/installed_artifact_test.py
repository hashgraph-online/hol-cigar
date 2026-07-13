#!/usr/bin/env python3
"""Qualify native and SDK quickstarts from clean, supplied distribution artifacts.

This driver never builds from the checkout. Every artifact path is explicit,
digested before use, unpacked without links or traversal, and exercised with
network package resolution disabled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Never, Sequence

EXPECTED = "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"
IDENTITY = re.compile(r"^1220[0-9a-f]{64}$")
MAX_ARTIFACT = 512 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_OUTPUT = 8 * 1024 * 1024


class InstallError(Exception):
    pass


def fail(message: str) -> Never:
    raise InstallError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT:
        fail("artifact must be a bounded regular non-symlink file")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return "1220" + hasher.hexdigest()


def safe_relative(name: str) -> Path:
    pure = PurePosixPath(name.replace("\\", "/"))
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        fail("archive contains an unsafe member path")
    if re.match(r"^[A-Za-z]:", pure.parts[0]):
        fail("archive contains an absolute drive path")
    return Path(*pure.parts)


def unpack_tar(archive: Path, destination: Path) -> None:
    total = 0
    with tarfile.open(archive, "r:*") as source:
        members = source.getmembers()
        if len(members) > MAX_MEMBERS:
            fail("archive member count exceeds the limit")
        seen: set[Path] = set()
        for member in members:
            relative = safe_relative(member.name)
            if relative in seen:
                fail("archive contains duplicate normalized paths")
            seen.add(relative)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            if (
                not member.isfile()
                or member.issym()
                or member.islnk()
                or member.size < 0
            ):
                fail("archive contains a link or special file")
            total += member.size
            if total > MAX_EXPANDED:
                fail("archive expanded bytes exceed the limit")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            stream = source.extractfile(member)
            if stream is None:
                fail("archive regular file has no payload")
            with target.open("xb") as output:
                shutil.copyfileobj(stream, output, 1024 * 1024)
            target.chmod(0o644)


def unpack_zip(archive: Path, destination: Path) -> None:
    total = 0
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > MAX_MEMBERS:
            fail("archive member count exceeds the limit")
        seen: set[Path] = set()
        for member in members:
            relative = safe_relative(member.filename.rstrip("/"))
            if relative in seen:
                fail("archive contains duplicate normalized paths")
            seen.add(relative)
            target = destination / relative
            mode = member.external_attr >> 16
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            if mode and (mode & 0o170000) not in (0, 0o100000):
                fail("archive contains a link or special file")
            total += member.file_size
            if total > MAX_EXPANDED:
                fail("archive expanded bytes exceed the limit")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with source.open(member) as stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output, 1024 * 1024)
            target.chmod(0o644)


def unpack(archive: Path, destination: Path) -> None:
    try:
        digest(archive)
        if zipfile.is_zipfile(archive):
            unpack_zip(archive, destination)
        elif tarfile.is_tarfile(archive):
            unpack_tar(archive, destination)
        else:
            fail("artifact archive format is unsupported")
    except InstallError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise InstallError("artifact archive is malformed") from error


def clean_environment(
    home: Path, extra: dict[str, str] | None = None
) -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TMPDIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "HOME": str(home),
            "CARGO_NET_OFFLINE": "true",
            "UV_OFFLINE": "1",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOPROXY": "off",
            "GONOSUMDB": "*",
            "GOSUMDB": "off",
            "GOCACHE": str(home / "go-build-cache"),
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    environment.update(extra or {})
    return environment


def run(
    command: Sequence[str],
    cwd: Path,
    home: Path,
    timeout: int = 900,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=clean_environment(home, extra_environment),
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InstallError("installed artifact process did not complete") from error
        stdout.seek(0, os.SEEK_END)
        stderr.seek(0, os.SEEK_END)
        if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
            fail("installed artifact process exceeded its output bound")
        stdout.seek(0)
        stderr.seek(0)
        stdout_payload = stdout.read()
        stderr_payload = stderr.read()
    if completed.returncode != 0:
        fail("installed artifact process returned a non-zero status")
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        stdout=stdout_payload,
        stderr=stderr_payload,
    )


def identity(completed: subprocess.CompletedProcess[bytes]) -> str:
    try:
        lines = [
            line.strip()
            for line in completed.stdout.decode("utf-8").splitlines()
            if line.strip()
        ]
    except UnicodeDecodeError as error:
        raise InstallError("installed quickstart output is not UTF-8") from error
    if len(lines) != 1 or not IDENTITY.fullmatch(lines[0]) or lines[0] != EXPECTED:
        fail("installed quickstart identity differs from the frozen fixture")
    return lines[0]


def exactly_one(root: Path, name: str) -> Path:
    matches = [
        path for path in root.rglob(name) if path.is_file() and not path.is_symlink()
    ]
    if len(matches) != 1:
        fail(f"installed archive must contain exactly one {name}")
    return matches[0]


def qualify_native(
    binary: Path, expected_version: str, directory: Path, home: Path
) -> dict[str, Any]:
    binary_digest = digest(binary)
    completed = run(
        [str(binary.resolve()), "--version", "--output", "json"], directory, home, 60
    )
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallError("installed native version output is not JSON") from error
    if not isinstance(value, dict) or value.get("version") != expected_version:
        fail("installed native artifact reports an unexpected version")
    project = directory / "native-project"
    project.mkdir()
    (project / "README.md").write_text("# installed qualification\n", encoding="utf-8")

    def cli(*arguments: str) -> dict[str, Any]:
        result = run(
            [str(binary.resolve()), "--output", "json", "--embedded", *arguments],
            project,
            home,
            60,
        )
        try:
            payload = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InstallError(
                "installed native workflow output is not JSON"
            ) from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != "cigar.cli.output.v1"
            or payload.get("ok") is not True
            or not isinstance(payload.get("result"), dict)
        ):
            fail("installed native workflow returned an invalid envelope")
        return payload

    initialized = cli("--yes", "init")
    source = cli("--yes", "source", "add", "qualification-source", str(project))
    listed = cli("source", "list")
    if (
        initialized["command"] != "init"
        or initialized["result"].get("initialized") is not True
        or source["command"] != "source.add"
        or source["result"].get("source_id") != "qualification-source"
        or listed["command"] != "source.list"
        or [entry.get("source_id") for entry in listed["result"].get("sources", [])]
        != ["qualification-source"]
    ):
        fail("installed native workflow did not persist its governed source")
    return {
        "artifact": "cigar",
        "artifact_digest": binary_digest,
        "workflow": ["version", "init", "source.add", "source.list"],
        "status": "installed_public_surface_probe_passed",
    }


def qualify_rust(
    archive: Path,
    cargo_home: Path,
    rustup_home: Path,
    directory: Path,
    home: Path,
) -> dict[str, Any]:
    root = directory / "rust"
    root.mkdir()
    unpack(archive, root)
    manifest = exactly_one(root, "Cargo.toml")
    completed = run(
        [
            "cargo",
            "run",
            "--offline",
            "--quiet",
            "--manifest-path",
            str(manifest),
            "--example",
            "quickstart",
        ],
        manifest.parent,
        home,
        extra_environment={
            "CARGO_HOME": str(cargo_home.resolve()),
            "RUSTUP_HOME": str(rustup_home.resolve()),
            "RUSTUP_DIST_SERVER": "http://127.0.0.1:9",
            "RUSTUP_UPDATE_ROOT": "http://127.0.0.1:9",
        },
    )
    return {
        "artifact": "rust",
        "artifact_digest": digest(archive),
        "bundle_id": identity(completed),
        "status": "package_fixture_identity_passed",
    }


def qualify_typescript(
    archive: Path, pnpm_store: Path, directory: Path, home: Path
) -> dict[str, Any]:
    project = directory / "typescript"
    project.mkdir()
    package = {
        "name": "cigar-installed-qualification",
        "version": "1.0.0",
        "private": True,
        "type": "module",
        "dependencies": {"@cigar/sdk": f"file:{archive.resolve()}"},
    }
    (project / "package.json").write_bytes(canonical(package) + b"\n")
    run(
        [
            "pnpm",
            "install",
            "--offline",
            "--ignore-scripts",
            "--lockfile=false",
            "--store-dir",
            str(pnpm_store.resolve()),
        ],
        project,
        home,
    )
    quickstart = (
        project
        / "node_modules"
        / "@cigar"
        / "sdk"
        / "dist"
        / "examples"
        / "quickstart.js"
    )
    if quickstart.is_symlink() or not quickstart.is_file():
        fail("installed TypeScript package lacks its quickstart")
    completed = run(["node", str(quickstart)], project, home)
    return {
        "artifact": "typescript",
        "artifact_digest": digest(archive),
        "bundle_id": identity(completed),
        "status": "package_fixture_identity_passed",
    }


def qualify_python(
    wheel: Path, wheelhouse: Path, directory: Path, home: Path
) -> dict[str, Any]:
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        fail("Python wheelhouse must be a regular directory")
    wheels = list(wheelhouse.glob("*.whl"))
    if (
        not wheels
        or len(wheels) > 128
        or any(
            path.is_symlink() or path.stat().st_size > MAX_ARTIFACT for path in wheels
        )
    ):
        fail("Python wheelhouse is empty or unsafe")
    if sum(path.stat().st_size for path in wheels) > MAX_EXPANDED:
        fail("Python wheelhouse exceeds the aggregate byte limit")
    environment = directory / "python-venv"
    run([sys.executable, "-m", "venv", str(environment)], directory, home)
    scripts = "Scripts" if os.name == "nt" else "bin"
    python = environment / scripts / ("python.exe" if os.name == "nt" else "python")
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse.resolve()),
            str(wheel.resolve()),
        ],
        directory,
        home,
    )
    completed = run([str(python), "-m", "cigar_sdk.qualify_bundle"], directory, home)
    return {
        "artifact": "python",
        "artifact_digest": digest(wheel),
        "bundle_id": identity(completed),
        "status": "package_fixture_identity_passed",
    }


def qualify_go(
    archive: Path, module_cache: Path, directory: Path, home: Path
) -> dict[str, Any]:
    root = directory / "go"
    root.mkdir()
    unpack(archive, root)
    module = exactly_one(root, "go.mod")
    completed = run(
        ["go", "run", "./examples/quickstart"],
        module.parent,
        home,
        extra_environment={"GOMODCACHE": str(module_cache.resolve())},
    )
    return {
        "artifact": "go",
        "artifact_digest": digest(archive),
        "bundle_id": identity(completed),
        "status": "package_fixture_identity_passed",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--cigar-binary", type=Path, required=True)
    result.add_argument("--expected-version", required=True)
    result.add_argument("--rust-archive", type=Path, required=True)
    result.add_argument("--cargo-home", type=Path, required=True)
    result.add_argument("--rustup-home", type=Path, required=True)
    result.add_argument("--typescript-tarball", type=Path, required=True)
    result.add_argument("--pnpm-store", type=Path, required=True)
    result.add_argument("--python-wheel", type=Path, required=True)
    result.add_argument("--python-wheelhouse", type=Path, required=True)
    result.add_argument("--go-archive", type=Path, required=True)
    result.add_argument("--go-mod-cache", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        for store in (
            args.cargo_home,
            args.rustup_home,
            args.pnpm_store,
            args.python_wheelhouse,
            args.go_mod_cache,
        ):
            if store.is_symlink() or not store.is_dir():
                fail("offline dependency store must be a regular directory")
        with tempfile.TemporaryDirectory(
            prefix="cigar-installed-artifacts-"
        ) as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            if not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", args.expected_version
            ):
                fail("expected native version is invalid")
            qualifications = [
                qualify_native(args.cigar_binary, args.expected_version, root, home),
                qualify_rust(
                    args.rust_archive,
                    args.cargo_home,
                    args.rustup_home,
                    root,
                    home,
                ),
                qualify_typescript(
                    args.typescript_tarball, args.pnpm_store, root, home
                ),
                qualify_python(args.python_wheel, args.python_wheelhouse, root, home),
                qualify_go(args.go_archive, args.go_mod_cache, root, home),
            ]
        report: dict[str, Any] = {
            "schema_version": "cigar.installed-artifact-demo-report.v1",
            "bundle_id": EXPECTED,
            "version": args.expected_version,
            "network_package_resolution": "disabled",
            "clean_install_roots": True,
            "explicit_offline_dependency_stores": True,
            "qualification_scope": "version-and-package-fixture-identity",
            "release_demo_qualified": False,
            "qualifications": qualifications,
        }
        report["report_digest"] = "1220" + hashlib.sha256(canonical(report)).hexdigest()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical(report) + b"\n"
        temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, args.output)
        finally:
            temporary.unlink(missing_ok=True)
        print(EXPECTED)
        return 0
    except InstallError as error:
        print(f"installed-artifact-demo: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print(
            "installed-artifact-demo: local artifact operation failed", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
