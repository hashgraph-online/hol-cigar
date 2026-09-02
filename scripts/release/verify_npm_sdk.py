#!/usr/bin/env python3
"""Assess an npm SDK tarball without extracting it or contacting a registry."""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILE = REPOSITORY_ROOT / "packaging/npm/release-profile.v1.json"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 256
MAX_PROFILE_BYTES = 1024 * 1024
MAX_STAGE_REPORT_BYTES = 8 * 1024 * 1024
REQUIRED_PATHS = frozenset(
    {
        "package/package.json",
        "package/README.md",
        "package/LICENSE",
        "package/NOTICE",
        "package/dist/index.js",
        "package/dist/index.d.ts",
        "package/dist/release.json",
        "package/dist/generated/operations.js",
        "package/fixtures/semantic-bundle-v1.json",
    }
)
FORBIDDEN_PATH_PATTERNS = (
    "**/.git/**",
    "**/.env*",
    "**/.npmrc",
    "**/*.key",
    "**/*.pem",
    "**/node_modules/**",
    "**/src/**",
    "**/tests/**",
    "**/*.tsbuildinfo",
)
LIFECYCLE_SCRIPTS = frozenset(
    {"preinstall", "install", "postinstall", "prepare"}
)
PRIVATE_PATH_PATTERNS = (
    re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+/"),
    re.compile(rb"/private/tmp/"),
    re.compile(rb"[A-Za-z]:\\\\Users\\\\[^\\\r\n]+"),
)
SECRET_PATTERNS = (
    re.compile(rb"npm_[A-Za-z0-9]{36}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class VerificationError(RuntimeError):
    """A fail-closed package or profile validation error."""


def _read_stable_file(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise VerificationError(f"{label} is not a bounded owner-controlled file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise VerificationError(f"{label} exceeds its byte bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise VerificationError(f"{label} changed while it was read")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise VerificationError(f"{label} length changed while it was read")
        return payload
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(payload: bytes, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid {label}: {error}") from error


def _load_profile(path: Path) -> dict[str, Any]:
    value = _load_json_bytes(
        _read_stable_file(path, MAX_PROFILE_BYTES, "npm release profile"),
        "npm release profile",
    )
    if not isinstance(value, dict):
        raise VerificationError("npm release profile must be an object")
    required = {
        "schema_version",
        "package",
        "source",
        "canonical_release_asset",
        "registry",
        "workflow",
        "release_decision",
    }
    if set(value) != required:
        raise VerificationError("npm release profile fields differ from review")
    if value.get("schema_version") != "cigar.npm-release-profile.v1":
        raise VerificationError("npm release profile schema differs")
    return value


def _safe_path(raw: str) -> str:
    if not raw or "\\" in raw or "\x00" in raw or unicodedata.normalize("NFC", raw) != raw:
        raise VerificationError(f"non-canonical archive path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise VerificationError(f"unsafe archive path: {raw!r}")
    if path.parts[0] != "package":
        raise VerificationError(f"archive member is outside package/: {raw!r}")
    return path.as_posix()


def _read_archive(path: Path) -> tuple[bytes, dict[str, tuple[bytes, int, int]]]:
    payload = _read_stable_file(path, MAX_ARCHIVE_BYTES, "npm archive")
    entries: dict[str, tuple[bytes, int, int]] = {}
    aliases: set[str] = set()
    expanded = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_MEMBERS:
                raise VerificationError("archive member count is outside the reviewed bound")
            for member in members:
                name = _safe_path(member.name)
                alias = unicodedata.normalize("NFC", name).casefold()
                if name in entries or alias in aliases:
                    raise VerificationError(f"archive path collision: {name}")
                aliases.add(alias)
                if not member.isfile() or member.issparse():
                    raise VerificationError(f"archive member is not a regular file: {name}")
                if member.size <= 0 or member.size > MAX_MEMBER_BYTES:
                    raise VerificationError(f"archive member size is invalid: {name}")
                if member.uid != 0 or member.gid != 0 or member.mode != 0o644:
                    raise VerificationError(f"archive ownership or mode is not canonical: {name}")
                handle = archive.extractfile(member)
                if handle is None:
                    raise VerificationError(f"archive member cannot be read: {name}")
                member_payload = handle.read(MAX_MEMBER_BYTES + 1)
                if len(member_payload) != member.size:
                    raise VerificationError(f"archive member length changed: {name}")
                expanded += len(member_payload)
                if expanded > MAX_EXPANDED_BYTES:
                    raise VerificationError("archive expanded size exceeds the reviewed bound")
                entries[name] = (member_payload, member.mode, member.mtime)
    except (tarfile.TarError, OSError, EOFError) as error:
        raise VerificationError(f"cannot parse npm archive: {error}") from error
    return payload, entries


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be an object")
    return value


def _semantic_tree(entries: dict[str, tuple[bytes, int, int]]) -> str:
    digest = hashlib.sha256()
    for name in sorted(entries, key=lambda value: value.encode("utf-8")):
        payload, mode, _mtime = entries[name]
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{mode:04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(payload)
    return digest.hexdigest()


def _inventory(entries: dict[str, tuple[bytes, int, int]]) -> list[dict[str, Any]]:
    return [
        {
            "path": name,
            "bytes": len(entries[name][0]),
            "mode": f"{entries[name][1]:04o}",
            "sha256": hashlib.sha256(entries[name][0]).hexdigest(),
        }
        for name in sorted(entries, key=lambda value: value.encode("utf-8"))
    ]


def _scan_entries(entries: dict[str, tuple[bytes, int, int]]) -> None:
    for name, (payload, _mode, _mtime) in entries.items():
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in FORBIDDEN_PATH_PATTERNS):
            raise VerificationError(f"forbidden package path: {name}")
        if any(pattern.search(payload) for pattern in PRIVATE_PATH_PATTERNS):
            raise VerificationError(f"private absolute path appears in: {name}")
        if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
            raise VerificationError(f"secret-shaped value appears in: {name}")
        if name.endswith(".map"):
            source_map = _require_dict(_load_json_bytes(payload, name), name)
            sources = source_map.get("sources")
            contents = source_map.get("sourcesContent")
            if (
                not isinstance(sources, list)
                or not sources
                or not all(isinstance(item, str) for item in sources)
                or not isinstance(contents, list)
                or len(contents) != len(sources)
                or not all(isinstance(item, str) for item in contents)
            ):
                raise VerificationError(f"source map lacks exact inline sources: {name}")
            for source in sources:
                if source.startswith(("/", "file:", "http:", "https:")) or "\\" in source:
                    raise VerificationError(f"source map exposes a non-relative source: {name}")


def _metadata_checks(
    entries: dict[str, tuple[bytes, int, int]], profile: dict[str, Any]
) -> tuple[dict[str, bool], dict[str, Any]]:
    package_profile = _require_dict(profile["package"], "profile package")
    source = _require_dict(profile["source"], "profile source")
    package = _require_dict(
        _load_json_bytes(entries["package/package.json"][0], "package.json"),
        "package.json",
    )
    release = _require_dict(
        _load_json_bytes(entries["package/dist/release.json"][0], "release.json"),
        "release.json",
    )
    repository = package.get("repository")
    expected_repository = {
        "type": "git",
        "url": source.get("repository_manifest_url"),
        "directory": source.get("repository_directory"),
    }
    scripts = package.get("scripts")
    exports = package.get("exports")
    root_export = exports.get(".") if isinstance(exports, dict) else None
    runtime = _require_dict(package_profile["runtime_dependency"], "runtime dependency")
    operation_payload = entries["package/dist/generated/operations.js"][0]
    operation_ids = set(
        item.decode("ascii")
        for item in re.findall(
            rb'"operationId"\s*:\s*"([A-Za-z][A-Za-z0-9]*)"',
            operation_payload,
        )
    )
    checks = {
        "package_name": package.get("name") == package_profile.get("name"),
        "package_version": package.get("version") == package_profile.get("requested_version"),
        "license": package.get("license") == "Apache-2.0",
        "repository": repository == expected_repository,
        "homepage": package.get("homepage") == f"{source.get('repository')}#readme",
        "bugs": package.get("bugs") == {"url": f"{source.get('repository')}/issues"},
        "public_alpha_channel": package.get("publishConfig")
        == {
            "access": "public",
            "registry": "https://registry.npmjs.org/",
            "tag": "alpha",
        },
        "esm_only": package.get("type") == "module"
        and root_export == {"types": "./dist/index.d.ts", "import": "./dist/index.js"},
        "types": package.get("types") == "./dist/index.d.ts",
        "side_effects": package.get("sideEffects") is False,
        "node_engine": package.get("engines") == {"node": ">=24.10.0 <25"},
        "package_manager": package.get("packageManager") == "pnpm@10.34.5",
        "files": package.get("files")
        == ["dist/", "fixtures/", "README.md", "LICENSE", "NOTICE"],
        "dependencies": package.get("dependencies")
        == {runtime.get("name"): runtime.get("version")},
        "no_lifecycle_scripts": isinstance(scripts, dict)
        and not LIFECYCLE_SCRIPTS.intersection(scripts),
        "release_identity": release
        == {
            "schema_version": "cigar.sdk-release.v1",
            "name": package_profile.get("name"),
            "version": package_profile.get("requested_version"),
            "context_abi": package_profile.get("context_abi"),
        },
        "context_abi_export": package_profile.get("context_abi", "").encode("ascii")
        in entries["package/dist/index.js"][0],
        "operation_count": len(operation_ids) == package_profile.get("operation_count"),
    }
    return checks, package


def assess(
    archive_path: Path,
    profile_path: Path = DEFAULT_PROFILE,
    *,
    require_canonical_bytes: bool = False,
) -> dict[str, Any]:
    profile = _load_profile(profile_path)
    archive_payload, entries = _read_archive(archive_path)
    missing = sorted(REQUIRED_PATHS.difference(entries))
    if missing:
        raise VerificationError(f"required package paths are missing: {missing}")
    _scan_entries(entries)
    checks, package = _metadata_checks(entries, profile)
    asset = _require_dict(profile["canonical_release_asset"], "canonical asset")
    sha256 = hashlib.sha256(archive_payload).hexdigest()
    # npm exposes the registry's legacy SHA-1 shasum alongside SRI. It is compared
    # for metadata parity only; SHA-256 and SRI remain the security boundaries.
    sha1 = hashlib.sha1(archive_payload, usedforsecurity=False).hexdigest()  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    semantic_tree = _semantic_tree(entries)
    canonical_checks = {
        "filename": archive_path.name == asset.get("filename"),
        "sha256": sha256 == asset.get("sha256"),
        "sha1": sha1 == asset.get("sha1"),
        "bytes": len(archive_payload) == asset.get("bytes"),
        "file_count": len(entries) == asset.get("file_count"),
        "semantic_tree_sha256": semantic_tree == asset.get("semantic_tree_sha256"),
    }
    if require_canonical_bytes and not all(canonical_checks.values()):
        raise VerificationError("archive bytes differ from the reviewed npm candidate")
    decision = _require_dict(profile["release_decision"], "release decision")
    metadata_ready = all(checks.values())
    publishable = metadata_ready and decision.get("publishable") is True
    return {
        "schema_version": "cigar.npm-sdk-assessment.v1",
        "status": "publishable" if publishable else "blocked",
        "archive": {
            "path": archive_path.name,
            "bytes": len(archive_payload),
            "sha256": sha256,
            "sha1": sha1,
            "npm_integrity": "sha512-"
            + base64.b64encode(hashlib.sha512(archive_payload).digest()).decode("ascii"),
            "semantic_tree_sha256": semantic_tree,
            "file_count": len(entries),
        },
        "package": {
            "name": package.get("name"),
            "version": package.get("version"),
            "context_abi": profile["package"]["context_abi"],
            "operation_count": profile["package"]["operation_count"],
        },
        "checks": checks,
        "canonical_asset_checks": canonical_checks,
        "blockers": decision.get("blockers", []),
        "inventory": _inventory(entries),
    }


def _verify_stage_dry_run(path: Path, assessment: dict[str, Any]) -> None:
    report = _load_json_bytes(
        _read_stable_file(path, MAX_STAGE_REPORT_BYTES, "npm stage dry-run report"),
        "npm stage dry-run report",
    )
    package = _require_dict(assessment["package"], "assessed package")
    archive = _require_dict(assessment["archive"], "assessed archive")
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise VerificationError("assessed npm package identity is invalid")
    inventory = assessment.get("inventory")
    if not isinstance(inventory, list):
        raise VerificationError("assessed npm inventory is invalid")
    files: list[dict[str, Any]] = []
    for item in inventory:
        if not isinstance(item, dict):
            raise VerificationError("assessed npm inventory entry is invalid")
        member_path = item.get("path")
        member_bytes = item.get("bytes")
        member_mode = item.get("mode")
        if (
            not isinstance(member_path, str)
            or not member_path.startswith("package/")
            or not isinstance(member_bytes, int)
            or not isinstance(member_mode, str)
        ):
            raise VerificationError("assessed npm inventory entry is invalid")
        files.append(
            {
                "path": member_path.removeprefix("package/"),
                "size": member_bytes,
                "mode": int(member_mode, 8),
            }
        )
    expected = {
        name: {
            "id": f"{name}@{version}",
            "name": name,
            "version": version,
            "size": archive.get("bytes"),
            "unpackedSize": sum(item["size"] for item in files),
            "shasum": archive.get("sha1"),
            "integrity": archive.get("npm_integrity"),
            "filename": archive.get("path"),
            "files": files,
            "entryCount": archive.get("file_count"),
            "bundled": [],
        }
    }
    if report != expected:
        raise VerificationError(
            "npm stage dry-run report differs from the assessed archive"
        )


def _write_report(path: Path, report: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise VerificationError("report path must be absolute")
    parent = path.parent
    if parent.is_symlink() or parent.resolve(strict=True) != parent:
        raise VerificationError("report parent must be a canonical directory")
    parent_metadata = parent.stat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise VerificationError("report parent must be an owner-only directory")
    payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o400)
    try:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise VerificationError("short write while creating report")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="owner-only root for a relative --report path",
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--stage-dry-run",
        type=Path,
        help="exact npm 12 stage --dry-run JSON report to bind to the archive",
    )
    parser.add_argument("--require-canonical-bytes", action="store_true")
    parser.add_argument("--require-publishable", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report_path = arguments.report
        if arguments.evidence_dir is not None:
            if report_path is None or report_path.is_absolute():
                raise VerificationError(
                    "--evidence-dir requires a relative --report path"
                )
            evidence_root = Path(os.path.abspath(arguments.evidence_dir))
            if (
                evidence_root.is_symlink()
                or evidence_root.resolve(strict=True) != evidence_root
            ):
                raise VerificationError("evidence root must be a canonical directory")
            report_path = evidence_root / report_path
        report = assess(
            Path(os.path.abspath(arguments.archive)),
            Path(os.path.abspath(arguments.profile)),
            require_canonical_bytes=arguments.require_canonical_bytes,
        )
        if arguments.stage_dry_run is not None:
            _verify_stage_dry_run(
                Path(os.path.abspath(arguments.stage_dry_run)), report
            )
        if report_path is not None:
            _write_report(Path(os.path.abspath(report_path)), report)
        else:
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        if arguments.require_publishable and report["status"] != "publishable":
            raise VerificationError("npm SDK release profile is not publishable")
        return 0
    except (OSError, VerificationError) as error:
        print(f"verify_npm_sdk: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
