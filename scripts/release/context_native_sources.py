"""Verify and prepare the complete packaged native source closure.

Cargo strips workspace path dependencies when packaging. The Windows adapter is
distributed alongside the context crate and patched to that exact extracted
archive, without requiring a separately published crates.io package. Only its
registry source/checksum fields change in the build lock; all other lock data
remain identical. The original archives are never rewritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib

from release_lib import ReleaseError, canonical_json_bytes

CONTEXT = "cigar-context"
ADAPTER = "cigar-windows-ipc"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_BYTES = 64 * 1024 * 1024
RELEASE_PROFILE = {
    "codegen-units": 1,
    "lto": "thin",
    "panic": "abort",
    "strip": "symbols",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def versions(root: Path) -> dict[str, str]:
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    require(
        workspace["profile"]["release"] == RELEASE_PROFILE,
        "native release profile differs from reviewed workspace policy",
    )
    result = {}
    for name in (CONTEXT, ADAPTER):
        manifest = tomllib.loads((root / "crates" / name / "Cargo.toml").read_text())
        version = manifest["package"]["version"]
        if version == {"workspace": True}:
            version = workspace["workspace"]["package"]["version"]
        require(isinstance(version, str), "native source version is not explicit")
        result[name] = version
    return result


def archive_names(releases: dict[str, str]) -> set[str]:
    require(set(releases) == {CONTEXT, ADAPTER}, "native source set is incomplete")
    return {f"{name}-{version}.crate" for name, version in releases.items()}


def read_archive(path: Path, prefix: str) -> dict[str, bytes]:
    require(
        path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES,
        "missing or invalid native source archive",
    )
    result = {}
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for index, member in enumerate(archive):
            parts = PurePosixPath(member.name)
            require(
                index < 4096
                and parts.parts
                and parts.parts[0] == prefix
                and not parts.is_absolute()
                and ".." not in parts.parts
                and "\\" not in member.name
                and parts.as_posix() == member.name,
                "unsafe native source member",
            )
            if member.isdir():
                continue
            require(
                member.isfile() and len(parts.parts) > 1,
                "native source contains a link or special file",
            )
            relative = PurePosixPath(*parts.parts[1:]).as_posix()
            total += member.size
            require(
                relative not in result
                and 0 <= member.size <= MAX_BYTES
                and total <= MAX_BYTES,
                "duplicate or oversized native source member",
            )
            stream = archive.extractfile(member)
            require(stream is not None, "unreadable native source member")
            payload = stream.read(MAX_BYTES + 1)
            require(len(payload) == member.size, "native source length mismatch")
            result[relative] = payload
    return result


def local_adapter_lock(payload: bytes, version: str, checksum: str) -> bytes:
    original = tomllib.loads(payload.decode())
    expected = tomllib.loads(payload.decode())
    matches = [row for row in expected["package"] if row["name"] == ADAPTER]
    require(len(matches) == 1, "native lock must contain exactly one Windows adapter")
    adapter = matches[0]
    require(
        adapter["version"] == version
        and adapter.get("source") == REGISTRY
        and adapter.get("checksum") == checksum,
        "packaged Windows adapter does not match the context lock",
    )
    del adapter["source"]
    del adapter["checksum"]
    sections = payload.decode().split("[[package]]")
    for index, section in enumerate(sections[1:], 1):
        row = tomllib.loads("[[package]]" + section)["package"][0]
        if row["name"] == ADAPTER:
            sections[index] = "".join(
                line
                for line in section.splitlines(keepends=True)
                if not line.startswith(("source = ", "checksum = "))
            )
    result = "[[package]]".join(sections).encode()
    require(
        tomllib.loads(result.decode()) == expected and original != expected,
        "native lock adaptation changed unrelated dependency data",
    )
    return result


def inspect(sources: Path, releases: dict[str, str]) -> tuple[dict, dict, bytes, bytes]:
    archive_names(releases)
    files = {}
    records = {}
    for name, version in releases.items():
        prefix = f"{name}-{version}"
        path = sources / f"{prefix}.crate"
        files[name] = read_archive(path, prefix)
        records[path.name] = sha256(path.read_bytes())
        manifest = tomllib.loads(files[name]["Cargo.toml"].decode())
        require(
            manifest["package"]["name"] == name
            and manifest["package"]["version"] == version,
            "native archive package identity mismatch",
        )
    manifest = tomllib.loads(files[CONTEXT]["Cargo.toml"].decode())
    dependency = manifest["target"]["cfg(windows)"]["dependencies"][ADAPTER]
    require(
        dependency["version"] == "=" + releases[ADAPTER]
        and dependency.get("default-features") is False
        and dependency.get("optional") is True
        and "path" not in dependency,
        "context archive does not pin the expected Windows adapter",
    )
    original = files[CONTEXT]["Cargo.lock"]
    lock = local_adapter_lock(
        original, releases[ADAPTER], records[f"{ADAPTER}-{releases[ADAPTER]}.crate"]
    )
    config = (
        "[patch.crates-io]\n"
        + ADAPTER
        + " = { path = "
        + json.dumps(f"../{ADAPTER}-{releases[ADAPTER]}")
        + " }\n"
        + "\n[profile.release]\n"
        + "".join(
            f"{key} = {json.dumps(value)}\n" for key, value in RELEASE_PROFILE.items()
        )
    ).encode()
    receipt = {
        "schema": "cigar.native-source-closure.v1",
        "archives": records,
        "original_lock_sha256": sha256(original),
        "effective_lock_sha256": sha256(lock),
        "cargo_config_sha256": sha256(config),
        "release_profile": RELEASE_PROFILE,
        "adaptation": "Windows adapter registry identity replaced by its verified sibling archive; no dependency version or edge changes.",
    }
    return receipt, files, lock, config


def prepare(sources: Path, output: Path, releases: dict[str, str]) -> tuple[dict, dict]:
    receipt, files, lock, config = inspect(sources, releases)
    output.mkdir(parents=True, exist_ok=False)
    directories = {}
    for name, contents in files.items():
        directory = output / f"{name}-{releases[name]}"
        directories[name] = directory
        for relative, payload in contents.items():
            destination = directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(payload)
    (directories[CONTEXT] / "Cargo.lock").write_bytes(lock)
    config_directory = directories[CONTEXT] / ".cargo"
    config_directory.mkdir(exist_ok=False)
    (config_directory / "config.toml").write_bytes(config)
    return directories, receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    _, receipt = prepare(
        args.sources, args.output, versions(Path(__file__).resolve().parents[2])
    )
    print(canonical_json_bytes(receipt).decode(), end="")
