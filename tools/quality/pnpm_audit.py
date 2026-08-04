#!/usr/bin/env python3
"""Run the production pnpm audit through a pinned, isolated pnpm 11 auditor.

The repository intentionally remains pinned to pnpm 10 for builds.  npm retired
the audit endpoints used by that release line, so this gate projects only the
checked lock metadata into an owner-private temporary workspace and invokes a
separately pinned pnpm 11 distribution.  It never installs dependencies and it
publishes only a content-free, create-new receipt outside the checkout.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = Path(__file__).with_name("pnpm-audit-policy.v1.json")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_METADATA_BYTES = 16 * 1024 * 1024
_MAX_GIT_BYTES = 64 * 1024 * 1024
_MAX_NODE_BYTES = 128 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class PolicyError(RuntimeError):
    """The audit policy, source, tool, result, or evidence failed closed."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(f"non-finite number {item}")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise PolicyError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a JSON object")
    return value


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _safe_relative(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise PolicyError(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PolicyError(f"{label} is not a canonical relative path")
    return path.parts


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    payload = _secure_regular_bytes(path, "pnpm audit policy", _MAX_METADATA_BYTES)
    policy = strict_json_bytes(payload, "pnpm audit policy")
    if policy.get("schema_version") != "cigar.pnpm-audit-policy.v1":
        raise PolicyError("unsupported pnpm audit policy schema")
    if set(policy) != {"schema_version", "host", "project", "auditor", "audit"}:
        raise PolicyError("pnpm audit policy has an unexpected top-level field")

    expected_node = {
        "bytes": 117561248,
        "code_signing": {
            "candidate_cdhash_full_sha256": (
                "e89ac81c24e645fa48a2c4ca49c10c58b9db488e4cd8229ee77d866b84882275"
            ),
            "format": "Mach-O thin (arm64)",
            "identifier": "node",
            "leaf_authority": (
                "Developer ID Application: Node.js Foundation (HX7739G8FX)"
            ),
            "team_identifier": "HX7739G8FX",
        },
        "sha256": "9e759d34d97af8a71b75854d20af297794611155406997f06d796b5e0f6d573b",
        "version": "24.10.0",
    }
    host = policy.get("host")
    if host != {
        "architecture": "arm64",
        "node": expected_node,
        "operating_system": "Darwin",
    }:
        raise PolicyError("pnpm audit host authority is not the native macOS cohort")

    project = policy.get("project")
    if not isinstance(project, dict) or set(project) != {
        "package_manager",
        "metadata_files",
        "package_manifests",
        "importers",
        "workspace_packages",
    }:
        raise PolicyError("pnpm audit project authority is missing")
    if project.get("package_manager") != {"name": "pnpm", "version": "10.34.5"}:
        raise PolicyError("project pnpm build-tool authority changed")
    metadata_files = project.get("metadata_files")
    package_manifests = project.get("package_manifests")
    importers = project.get("importers")
    workspace_packages = project.get("workspace_packages")
    if (
        not isinstance(metadata_files, list)
        or not metadata_files
        or len(metadata_files) != len(set(metadata_files))
        or not isinstance(package_manifests, dict)
        or set(package_manifests)
        != {
            item
            for item in metadata_files
            if isinstance(item, str) and item.endswith("package.json")
        }
    ):
        raise PolicyError("project metadata-file authority is inconsistent")
    portable: set[str] = set()
    for relative in metadata_files:
        _safe_relative(relative, "project metadata path")
        alias = unicodedata.normalize("NFC", relative).casefold()
        if alias in portable:
            raise PolicyError("project metadata paths have a portable collision")
        portable.add(alias)
    for label, values in (
        ("lockfile importers", importers),
        ("workspace package selectors", workspace_packages),
    ):
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(item, str) and item for item in values)
            or len(values) != len(set(values))
        ):
            raise PolicyError(f"{label} are invalid")
    if importers[0] != ".":
        raise PolicyError("the root lockfile importer is missing")
    for relative, expected in package_manifests.items():
        _safe_relative(relative, "package manifest path")
        if (
            not isinstance(expected, dict)
            or set(expected) != {"name", "packageManager", "engines"}
            or not isinstance(expected.get("name"), str)
            or not isinstance(expected.get("packageManager"), str)
            or not isinstance(expected.get("engines"), dict)
        ):
            raise PolicyError("package manifest authority is invalid")

    auditor = policy.get("auditor")
    if (
        not isinstance(auditor, dict)
        or set(auditor)
        != {"name", "version", "corepack_hash", "distribution", "entrypoint"}
        or auditor.get("name") != "pnpm"
    ):
        raise PolicyError("pnpm auditor authority is missing")
    if auditor.get("version") != "11.13.0":
        raise PolicyError("pnpm auditor version is not pinned")
    if not re.fullmatch(r"sha512\.[0-9a-f]{128}", str(auditor.get("corepack_hash"))):
        raise PolicyError("pnpm Corepack distribution hash is invalid")
    distribution = auditor.get("distribution")
    entrypoint = auditor.get("entrypoint")
    if (
        not isinstance(distribution, dict)
        or set(distribution) != {"files", "bytes", "manifest_sha256"}
        or not isinstance(distribution.get("files"), int)
        or distribution["files"] <= 0
        or not isinstance(distribution.get("bytes"), int)
        or distribution["bytes"] <= 0
        or not _valid_digest(distribution.get("manifest_sha256"))
        or not isinstance(entrypoint, dict)
        or set(entrypoint) != {"path", "bytes", "sha256"}
        or not _valid_digest(entrypoint.get("sha256"))
        or not isinstance(entrypoint.get("bytes"), int)
        or entrypoint["bytes"] <= 0
    ):
        raise PolicyError("pnpm auditor distribution descriptor is invalid")
    _safe_relative(entrypoint.get("path"), "pnpm entrypoint")

    audit = policy.get("audit")
    expected_arguments = ["audit", "--prod", "--audit-level", "high", "--json"]
    if (
        not isinstance(audit, dict)
        or set(audit)
        != {
            "arguments",
            "registry",
            "timeout_seconds",
            "maximum_output_bytes",
            "expected_metadata",
            "expected_report",
        }
        or audit.get("arguments") != expected_arguments
        or audit.get("registry") != "https://registry.npmjs.org/"
        or not isinstance(audit.get("timeout_seconds"), int)
        or not 1 <= audit["timeout_seconds"] <= 300
        or not isinstance(audit.get("maximum_output_bytes"), int)
        or not 1024 <= audit["maximum_output_bytes"] <= 16 * 1024 * 1024
        or not isinstance(audit.get("expected_metadata"), dict)
        or set(audit["expected_metadata"])
        != {
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "totalDependencies",
        }
        or not all(
            isinstance(value, int) and value >= 0
            for value in audit["expected_metadata"].values()
        )
        or audit.get("expected_report")
        != {
            "bytes": 274,
            "sha256": "c35a9f736e407c8e5f41f4e97d972cf18b7d5910cf0770ddc7602a1ac216fa0a",
        }
    ):
        raise PolicyError("pnpm audit invocation authority is invalid")
    return policy


def _open_directory_at(parent_fd: int, name: str) -> int:
    try:
        return os.open(
            name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=parent_fd
        )
    except OSError as error:
        raise PolicyError(
            f"cannot open protected metadata directory {name!r}: {error}"
        ) from error


def read_secure_file(
    root: Path, relative: str, maximum: int = _MAX_METADATA_BYTES
) -> bytes:
    parts = _safe_relative(relative, "metadata path")
    try:
        descriptor = os.open(root, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except OSError as error:
        raise PolicyError(f"cannot open repository root: {error}") from error
    try:
        for part in parts[:-1]:
            child = _open_directory_at(descriptor, part)
            os.close(descriptor)
            descriptor = child
        try:
            file_descriptor = os.open(
                parts[-1], os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=descriptor
            )
        except OSError as error:
            raise PolicyError(
                f"cannot open protected metadata file {relative}: {error}"
            ) from error
        try:
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size < 0
                or before.st_size > maximum
            ):
                raise PolicyError(
                    f"metadata file {relative} is not a bounded single-link regular file"
                )
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining > 0:
                chunk = os.read(file_descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(file_descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_uid",
                "st_gid",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if len(payload) > maximum or any(
                getattr(before, field) != getattr(after, field)
                for field in stable_fields
            ):
                raise PolicyError(f"metadata file {relative} changed while it was read")
            if len(payload) != before.st_size:
                raise PolicyError(f"metadata file {relative} was not read completely")
            return payload
        finally:
            os.close(file_descriptor)
    finally:
        os.close(descriptor)


def _parse_workspace_packages(payload: bytes) -> list[str]:
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise PolicyError("pnpm workspace metadata is not UTF-8") from error
    if not lines or lines[0] != "packages:":
        raise PolicyError("pnpm workspace package list is not first")
    packages: list[str] = []
    index = 1
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        match = re.fullmatch(r"  - ([A-Za-z0-9_./@-]+)", line)
        if match is None:
            break
        packages.append(match.group(1))
        index += 1
    if not packages or len(packages) != len(set(packages)):
        raise PolicyError("pnpm workspace package list is invalid")
    forbidden = re.compile(
        r"(?mi)^\s*(?:auditConfig|audit-level|ignore-registry-errors|ignoreCves|ignoreGhsas)\s*:"
    )
    if forbidden.search(payload.decode("utf-8")) is not None:
        raise PolicyError("pnpm workspace metadata contains an audit suppression")
    return packages


def _parse_lockfile_importers(payload: bytes) -> list[str]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise PolicyError("pnpm lockfile is not UTF-8") from error
    if not re.match(r"\AlockfileVersion: '9\.0'\n", text):
        raise PolicyError("pnpm lockfile version changed")
    lines = text.splitlines()
    try:
        start = lines.index("importers:") + 1
        end = lines.index("packages:", start)
    except ValueError as error:
        raise PolicyError("pnpm lockfile importer framing is invalid") from error
    importers: list[str] = []
    for line in lines[start:end]:
        match = re.fullmatch(r"  (?:'([^']+)'|([^\s':][^:]*)):(?: \{\})?", line)
        if match is not None:
            importers.append(match.group(1) or match.group(2))
    if not importers or len(importers) != len(set(importers)):
        raise PolicyError("pnpm lockfile importers are invalid")
    return importers


def _contains_audit_suppression(value: object) -> bool:
    forbidden = {
        "auditconfig",
        "auditlevel",
        "audit-level",
        "ignorecves",
        "ignoreghsas",
        "ignoreregistryerrors",
        "ignore-registry-errors",
    }
    if isinstance(value, dict):
        return any(
            str(key).replace("_", "").casefold() in forbidden
            or _contains_audit_suppression(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_audit_suppression(child) for child in value)
    return False


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def _git(root: Path, *arguments: str, maximum: int = _MAX_GIT_BYTES) -> bytes:
    command = [
        "/usr/bin/git",
        "--no-replace-objects",
        "-c",
        "core.quotePath=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.allow=never",
        "--literal-pathspecs",
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PolicyError(f"cannot inspect audit source: {error}") from error
    if len(completed.stdout) > maximum or len(completed.stderr) > 1024 * 1024:
        raise PolicyError("Git source inspection output exceeded its bound")
    if completed.returncode != 0:
        raise PolicyError(
            "Git source inspection failed; "
            f"exit={completed.returncode} stderr_sha256={sha256_bytes(completed.stderr)}"
        )
    return completed.stdout


def _git_object(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeError as error:
        raise PolicyError(f"Git {label} is not ASCII") from error
    if _GIT_OBJECT.fullmatch(value) is None:
        raise PolicyError(f"Git {label} is not a complete object ID")
    return value


def source_snapshot(root: Path) -> dict[str, object]:
    try:
        canonical = root.resolve(strict=True)
        metadata = root.lstat()
    except OSError as error:
        raise PolicyError(f"cannot resolve repository root: {error}") from error
    if canonical != root or not stat.S_ISDIR(metadata.st_mode):
        raise PolicyError("repository root must be a canonical real directory")
    top_level = Path(
        _git(root, "rev-parse", "--show-toplevel")
        .decode("utf-8", errors="strict")
        .strip()
    )
    if top_level.resolve(strict=True) != root:
        raise PolicyError("audit root is not the Git worktree root")
    revision = _git_object(
        _git(root, "rev-parse", "--verify", "HEAD^{commit}"), "revision"
    )
    tree = _git_object(_git(root, "rev-parse", "--verify", "HEAD^{tree}"), "tree")
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    difference = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "--full-index",
        "HEAD",
        "--",
    )
    source_paths = _git(
        root,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    )
    try:
        packages = sorted(
            item.decode("utf-8", errors="strict")
            for item in source_paths.split(b"\0")
            if item and (item == b"package.json" or item.endswith(b"/package.json"))
        )
    except UnicodeError as error:
        raise PolicyError("Git package manifest inventory is not UTF-8") from error
    material: dict[str, object] = {
        "revision": revision,
        "tree": tree,
        "clean": status == b"",
        "status_sha256": sha256_bytes(status),
        "difference_sha256": sha256_bytes(difference),
        "package_manifests": packages,
    }
    material["fingerprint"] = sha256_bytes(canonical_json_bytes(material))
    return material


def source_metadata(policy: dict[str, Any], root: Path) -> dict[str, bytes]:
    project = policy["project"]
    snapshot = source_snapshot(root)
    expected_manifests = sorted(project["package_manifests"])
    if snapshot["package_manifests"] != expected_manifests:
        raise PolicyError("tracked or untracked package manifest inventory changed")
    payloads = {
        relative: read_secure_file(root, relative)
        for relative in project["metadata_files"]
    }
    for relative, expected in project["package_manifests"].items():
        manifest = strict_json_bytes(payloads[relative], relative)
        if _contains_audit_suppression(manifest):
            raise PolicyError(
                f"package manifest {relative} contains an audit suppression"
            )
        for field in ("name", "packageManager", "engines"):
            if manifest.get(field) != expected[field]:
                raise PolicyError(
                    f"package manifest authority changed: {relative}:{field}"
                )
    if (
        _parse_workspace_packages(payloads["pnpm-workspace.yaml"])
        != project["workspace_packages"]
    ):
        raise PolicyError("pnpm workspace package authority changed")
    if _parse_lockfile_importers(payloads["pnpm-lock.yaml"]) != project["importers"]:
        raise PolicyError("pnpm lockfile importer authority changed")
    return payloads


def project_metadata(
    policy: dict[str, Any], payloads: dict[str, bytes]
) -> dict[str, bytes]:
    projected = dict(payloads)
    root_manifest = strict_json_bytes(payloads["package.json"], "root package manifest")
    transformed = copy.deepcopy(root_manifest)
    transformed["packageManager"] = f"pnpm@{policy['auditor']['version']}"
    engines = transformed.get("engines")
    if not isinstance(engines, dict):
        raise PolicyError("root package engine authority is missing")
    engines["pnpm"] = policy["auditor"]["version"]
    projected["package.json"] = canonical_json_bytes(transformed)
    for relative, payload in payloads.items():
        if relative != "package.json" and projected[relative] != payload:
            raise AssertionError("the audit projection changed non-root metadata")
    return projected


def _write_private_file(path: Path, payload: bytes, mode: int = 0o600) -> None:
    if mode not in {0o400, 0o500, 0o600}:
        raise PolicyError("private file mode is not in the closed write policy")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Audit projections may contain unpublished dependency metadata and stay owner-private.
    os.chmod(path.parent, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise PolicyError(f"cannot create private projection file: {error}") from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PolicyError("short write while creating audit projection")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def write_projection(root: Path, payloads: dict[str, bytes]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for relative in sorted(payloads):
        destination = root.joinpath(*_safe_relative(relative, "projection path"))
        _write_private_file(destination, payloads[relative])
        records.append(
            {
                "path": relative,
                "bytes": len(payloads[relative]),
                "sha256": sha256_bytes(payloads[relative]),
            }
        )
    return records


def _trusted_regular(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PolicyError(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or metadata.st_uid not in {0, os.getuid()}
    ):
        raise PolicyError(f"{label} is not a trusted single-link regular file")
    return metadata


def _secure_regular_bytes(path: Path, label: str, maximum: int) -> bytes:
    """Read one canonical file through a stable no-follow descriptor."""

    if not path.is_absolute() or os.path.normpath(os.fspath(path)) != os.fspath(path):
        raise PolicyError(f"{label} path is not absolute and lexically canonical")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PolicyError(f"cannot resolve {label}: {error}") from error
    if resolved != path:
        raise PolicyError(f"{label} path must not contain a symbolic link")
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except OSError as error:
        raise PolicyError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_uid not in {0, os.getuid()}
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise PolicyError(f"{label} is not a bounded trusted regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if len(payload) > maximum or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise PolicyError(f"{label} changed while it was read")
        if len(payload) != before.st_size:
            raise PolicyError(f"{label} was not read completely")
        return payload
    finally:
        os.close(descriptor)


def _auditor_materials(
    policy: dict[str, Any], root: Path
) -> tuple[dict[str, object], dict[str, bytes]]:
    try:
        canonical = root.resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as error:
        raise PolicyError(f"cannot resolve pnpm auditor root: {error}") from error
    if canonical != root or not stat.S_ISDIR(root_metadata.st_mode):
        raise PolicyError("pnpm auditor root must be a canonical real directory")
    if root_metadata.st_mode & 0o022 or root_metadata.st_uid not in {0, os.getuid()}:
        raise PolicyError("pnpm auditor root is not protected from other users")
    try:
        if root == ROOT or root.is_relative_to(ROOT):
            raise PolicyError(
                "pnpm auditor distribution must be outside the source tree"
            )
    except AttributeError:  # pragma: no cover - Python 3.8 compatibility guard
        try:
            root.relative_to(ROOT)
        except ValueError:
            pass
        else:
            raise PolicyError(
                "pnpm auditor distribution must be outside the source tree"
            )

    records: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}
    directories: set[str] = set()
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(root).as_posix()
        directories.add(relative_directory)
        names.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        for name in names:
            path = directory_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_mode & 0o022
                or metadata.st_uid not in {0, os.getuid()}
            ):
                raise PolicyError("pnpm auditor contains an unsafe directory")
        for name in filenames:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            _trusted_regular(path, "pnpm auditor file")
            payload = read_secure_file(root, relative)
            payloads[relative] = payload
            records.append(
                {
                    "path": relative,
                    "bytes": len(payload),
                    "sha256": sha256_bytes(payload),
                }
            )
    records.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    expected_directories = {"."}
    for record in records:
        parent = PurePosixPath(str(record["path"])).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if directories != expected_directories:
        raise PolicyError("pnpm auditor contains an unbound empty or missing directory")
    distribution = {
        "files": len(records),
        "bytes": sum(int(record["bytes"]) for record in records),
        "manifest_sha256": sha256_bytes(canonical_json_bytes(records)),
    }
    if distribution != policy["auditor"]["distribution"]:
        raise PolicyError("pnpm auditor distribution digest changed")

    package = strict_json_bytes(payloads["package.json"], "pnpm package manifest")
    if (
        package.get("name") != policy["auditor"]["name"]
        or package.get("version") != policy["auditor"]["version"]
        or package.get("engines") != {"node": ">=22.13"}
        or package.get("bin")
        != {
            "pnpm": "bin/pnpm.mjs",
            "pnpx": "bin/pnpx.mjs",
            "pn": "bin/pnpm.mjs",
            "pnx": "bin/pnpx.mjs",
        }
    ):
        raise PolicyError("pnpm package manifest identity changed")
    corepack = strict_json_bytes(payloads[".corepack"], "Corepack pnpm descriptor")
    if corepack != {
        "locator": {"name": "pnpm", "reference": policy["auditor"]["version"]},
        "bin": {"pnpm": "./bin/pnpm.cjs", "pnpx": "./bin/pnpx.cjs"},
        "hash": policy["auditor"]["corepack_hash"],
    }:
        raise PolicyError("Corepack pnpm integrity authority changed")
    entrypoint = payloads[policy["auditor"]["entrypoint"]["path"]]
    if {
        "bytes": len(entrypoint),
        "sha256": sha256_bytes(entrypoint),
    } != {
        "bytes": policy["auditor"]["entrypoint"]["bytes"],
        "sha256": policy["auditor"]["entrypoint"]["sha256"],
    }:
        raise PolicyError("pnpm auditor entrypoint changed")
    return distribution, payloads


def auditor_distribution(policy: dict[str, Any], root: Path) -> dict[str, object]:
    distribution, _ = _auditor_materials(policy, root)
    return distribution


def _identity_command(
    command: list[str], label: str
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TZ": "UTC",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PolicyError(f"cannot execute {label}: {error}") from error
    if len(completed.stdout) > 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
        raise PolicyError(f"{label} output exceeded its bound")
    return completed


def _codesign_value(details: str, key: str) -> str:
    values = [
        line[len(key) + 1 :]
        for line in details.splitlines()
        if line.startswith(f"{key}=")
    ]
    if len(values) != 1 or not values[0]:
        raise PolicyError(f"Node code signature has an invalid {key} field")
    return values[0]


def _node_material(
    policy: dict[str, Any], executable: Path
) -> tuple[Path, dict[str, object], bytes]:
    try:
        resolved = executable.resolve(strict=True)
    except OSError as error:
        raise PolicyError(f"cannot resolve Node executable: {error}") from error
    if not executable.is_absolute() or resolved != executable:
        raise PolicyError(
            "Node executable must be an absolute canonical non-symlink path"
        )
    payload = _secure_regular_bytes(resolved, "Node executable", _MAX_NODE_BYTES)
    expected_node = policy["host"]["node"]
    if {
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    } != {
        "bytes": expected_node["bytes"],
        "sha256": expected_node["sha256"],
    }:
        raise PolicyError("Node executable bytes do not match the reviewed authority")

    verification = _identity_command(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "--verbose=4",
            os.fspath(resolved),
        ],
        "Node code-signature verification",
    )
    if verification.returncode != 0 or verification.stdout:
        raise PolicyError("Node code signature is invalid")
    display = _identity_command(
        ["/usr/bin/codesign", "--display", "--verbose=4", os.fspath(resolved)],
        "Node code-signature inspection",
    )
    try:
        details = display.stderr.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise PolicyError("Node code-signature details are not UTF-8") from error
    if display.returncode != 0 or display.stdout:
        raise PolicyError("Node code-signature identity cannot be inspected")
    authorities = [
        line.removeprefix("Authority=")
        for line in details.splitlines()
        if line.startswith("Authority=")
    ]
    actual_signing = {
        "candidate_cdhash_full_sha256": _codesign_value(
            details, "CandidateCDHashFull sha256"
        ),
        "format": _codesign_value(details, "Format"),
        "identifier": _codesign_value(details, "Identifier"),
        "leaf_authority": authorities[0] if authorities else "",
        "team_identifier": _codesign_value(details, "TeamIdentifier"),
    }
    if actual_signing != expected_node["code_signing"]:
        raise PolicyError("Node code-signature identity changed")

    version = _identity_command(
        [os.fspath(resolved), "--version"], "Node runtime identity check"
    )
    expected_version = f"v{expected_node['version']}\n".encode("ascii")
    if version.returncode != 0 or version.stdout != expected_version or version.stderr:
        raise PolicyError("Node runtime identity changed")
    if _secure_regular_bytes(resolved, "Node executable", _MAX_NODE_BYTES) != payload:
        raise PolicyError("Node executable changed during identity verification")
    return resolved, copy.deepcopy(expected_node), payload


def node_identity(
    policy: dict[str, Any], executable: Path
) -> tuple[Path, dict[str, object]]:
    resolved, identity, _ = _node_material(policy, executable)
    return resolved, identity


def stage_runtime(
    runtime_root: Path, node_payload: bytes, auditor_payloads: dict[str, bytes]
) -> tuple[Path, Path]:
    """Create a private, read-only execution copy from already validated bytes."""

    if runtime_root.exists() or runtime_root.is_symlink():
        raise PolicyError("staged runtime root is create-new")
    runtime_root.mkdir(mode=0o700)
    node_path = runtime_root / "node"
    pnpm_root = runtime_root / "pnpm"
    pnpm_root.mkdir(mode=0o700)
    _write_private_file(node_path, node_payload, mode=0o500)
    for relative, payload in sorted(auditor_payloads.items()):
        destination = pnpm_root.joinpath(
            *_safe_relative(relative, "staged pnpm auditor path")
        )
        _write_private_file(destination, payload, mode=0o400)
    for directory, names, _ in os.walk(runtime_root, topdown=False, followlinks=False):
        for name in names:
            child = Path(directory) / name
            if child.is_symlink() or not child.is_dir():
                raise PolicyError("staged runtime contains an unsafe directory")
        os.chmod(directory, 0o500)
    return node_path, pnpm_root


def _thaw_staged_runtime(runtime_root: Path) -> None:
    """Restore owner write permission solely so TemporaryDirectory can erase it."""

    if not runtime_root.exists():
        return
    for directory, _, _ in os.walk(runtime_root, topdown=True, followlinks=False):
        # Thaw only for owner cleanup; no group or other access is introduced.
        os.chmod(directory, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions


def verify_host(policy: dict[str, Any]) -> dict[str, str]:
    actual = {
        "operating_system": platform.system(),
        "architecture": platform.machine(),
    }
    expected = {
        "operating_system": policy["host"]["operating_system"],
        "architecture": policy["host"]["architecture"],
    }
    if actual != expected:
        raise PolicyError(
            f"pnpm production audit requires {expected['operating_system']} {expected['architecture']}"
        )
    return actual


def _kill_process_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        if process.poll() is None:
            process.kill()
            return True
        return False


def run_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    maximum_output_bytes: int,
) -> dict[str, object]:
    started = time.monotonic()
    process: Optional[subprocess.Popen[bytes]] = None
    stdout = bytearray()
    stderr = bytearray()
    timed_out = False
    overflow = False
    descendant_cleanup = False
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
        assert process.stdout is not None and process.stderr is not None
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = started + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                descendant_cleanup |= _kill_process_group(process)
                break
            events = selector.select(min(0.1, remaining))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in list(selector.get_map().values())
                ]
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                destination = stdout if key.data == "stdout" else stderr
                remaining_bytes = maximum_output_bytes - len(stdout) - len(stderr)
                if len(chunk) > remaining_bytes:
                    if remaining_bytes > 0:
                        destination.extend(chunk[:remaining_bytes])
                    overflow = True
                    descendant_cleanup |= _kill_process_group(process)
                    break
                destination.extend(chunk)
            if overflow:
                break
        if timed_out or overflow:
            descendant_cleanup |= _kill_process_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            descendant_cleanup |= _kill_process_group(process)
            raise PolicyError("pnpm audit process group did not terminate") from error
        if not timed_out and not overflow:
            descendant_cleanup |= _kill_process_group(process)
    except OSError as error:
        if process is not None:
            _kill_process_group(process)
        raise PolicyError(f"cannot execute bounded pnpm audit: {error}") from error
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        selector.unregister(stream)
                    except (KeyError, ValueError):
                        pass
                    stream.close()
        selector.close()
    return {
        "exit_code": process.returncode if process is not None else -1,
        "duration_seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out,
        "output_overflow": overflow,
        "descendant_cleanup_required": descendant_cleanup,
        "stdout": bytes(stdout),
        "stderr": bytes(stderr),
    }


def audit_environment(scratch: Path, policy: dict[str, Any]) -> dict[str, str]:
    home = scratch / "home"
    config = scratch / "config"
    cache = scratch / "cache"
    data = scratch / "data"
    for directory in (home, config, cache, data):
        directory.mkdir(mode=0o700)
    return {
        "CI": "true",
        "HOME": os.fspath(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "NPM_CONFIG_GLOBALCONFIG": os.fspath(config / "global-npmrc"),
        "NPM_CONFIG_REGISTRY": policy["audit"]["registry"],
        "NPM_CONFIG_USERCONFIG": os.fspath(config / "user-npmrc"),
        "PATH": "/usr/bin:/bin",
        "PNPM_HOME": os.fspath(data / "pnpm"),
        "TZ": "UTC",
        "XDG_CACHE_HOME": os.fspath(cache),
        "XDG_CONFIG_HOME": os.fspath(config),
        "XDG_DATA_HOME": os.fspath(data),
    }


def evaluate_result(payload: bytes, policy: dict[str, Any]) -> dict[str, object]:
    if {
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    } != policy["audit"]["expected_report"]:
        raise PolicyError("pnpm audit report bytes changed from the reviewed authority")
    report = strict_json_bytes(payload, "pnpm audit report")
    if set(report) != {"advisories", "metadata"} or report.get("advisories") != {}:
        raise PolicyError("pnpm production audit reported one or more advisories")
    metadata = report.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {
        "vulnerabilities",
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "totalDependencies",
    }:
        raise PolicyError("pnpm audit result metadata is incomplete or expanded")
    vulnerabilities = metadata.get("vulnerabilities")
    expected_vulnerabilities = {
        "info": 0,
        "low": 0,
        "moderate": 0,
        "high": 0,
        "critical": 0,
    }
    if vulnerabilities != expected_vulnerabilities:
        raise PolicyError(
            "pnpm production audit vulnerability counts are nonzero or malformed"
        )
    counts = {key: metadata[key] for key in policy["audit"]["expected_metadata"]}
    if counts != policy["audit"]["expected_metadata"]:
        raise PolicyError("pnpm production dependency counts changed")
    if counts["totalDependencies"] != (
        counts["dependencies"]
        + counts["devDependencies"]
        + counts["optionalDependencies"]
    ):
        raise PolicyError("pnpm audit dependency totals are inconsistent")
    return {"vulnerabilities": expected_vulnerabilities, **counts}


def expected_result(policy: dict[str, Any]) -> dict[str, object]:
    return {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 0,
        },
        **policy["audit"]["expected_metadata"],
    }


def semantic_command(
    policy: dict[str, Any], node: dict[str, object]
) -> dict[str, object]:
    return {
        "node": copy.deepcopy(node),
        "auditor": {
            "name": policy["auditor"]["name"],
            "version": policy["auditor"]["version"],
            "entrypoint_sha256": policy["auditor"]["entrypoint"]["sha256"],
        },
        "arguments": list(policy["audit"]["arguments"]),
        "registry": policy["audit"]["registry"],
    }


def expected_claims(source: dict[str, object]) -> dict[str, bool]:
    eligible = bool(source["clean"])
    return {
        "production_dependencies_audited": True,
        "development_dependencies_audited": False,
        "zero_known_vulnerabilities": True,
        "dependency_install_performed": False,
        "source_clean": eligible,
        "release_eligible": eligible,
        "native_macos_arm64": True,
        "isolated_runtime_staged": True,
        "source_runtime_revalidated": True,
        "staged_runtime_revalidated": True,
        "fuzz_executed": False,
        "soak_executed": False,
    }


def _external_receipt_path(path: Path, root: Path) -> Path:
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise PolicyError("receipt path must be absolute and lexically canonical")
    if path.exists() or path.is_symlink():
        raise PolicyError("receipt publication is create-new")
    try:
        parent = path.parent.resolve(strict=True)
        parent_metadata = path.parent.lstat()
    except OSError as error:
        raise PolicyError(f"cannot inspect receipt parent: {error}") from error
    if parent != path.parent or not stat.S_ISDIR(parent_metadata.st_mode):
        raise PolicyError("receipt parent must be a canonical real directory")
    if (
        stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or parent_metadata.st_uid != os.getuid()
    ):
        raise PolicyError("receipt parent must be owner-controlled mode 0700")
    try:
        parent.relative_to(root)
    except ValueError:
        pass
    else:
        raise PolicyError("receipt must be outside the source checkout")
    return path


def publish_receipt(path: Path, payload: dict[str, object], root: Path) -> None:
    destination = _external_receipt_path(path, root)
    body = canonical_json_bytes(payload)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
    try:
        descriptor = os.open(destination, flags, 0o400)
    except OSError as error:
        raise PolicyError(f"cannot create pnpm audit receipt: {error}") from error
    try:
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PolicyError("short write while publishing pnpm audit receipt")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(destination.parent, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def run_scan(
    *,
    root: Path,
    policy_path: Path,
    node_executable: Path,
    pnpm_root: Path,
    receipt: Path,
) -> dict[str, object]:
    policy = load_policy(policy_path)
    host = verify_host(policy)
    before_source = source_snapshot(root)
    metadata = source_metadata(policy, root)
    auditor_before, auditor_payloads = _auditor_materials(policy, pnpm_root)
    _, node_before, node_payload = _node_material(policy, node_executable)
    projection = project_metadata(policy, metadata)

    with tempfile.TemporaryDirectory(prefix="cigar-pnpm-production-audit-") as raw:
        scratch = Path(raw).resolve(strict=True)
        # The projected production graph is audit-only and must stay owner-private.
        os.chmod(scratch, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        if scratch == root or scratch.is_relative_to(root):
            raise PolicyError(
                "pnpm audit scratch directory is inside the source checkout"
            )
        projected_root = scratch / "project"
        projected_root.mkdir(mode=0o700)
        projection_records = write_projection(projected_root, projection)
        environment = audit_environment(scratch, policy)
        runtime_root = scratch / "runtime"
        staged_node, staged_pnpm = stage_runtime(
            runtime_root, node_payload, auditor_payloads
        )
        try:
            _, staged_node_before = node_identity(policy, staged_node)
            staged_auditor_before = auditor_distribution(policy, staged_pnpm)
            if (
                staged_node_before != node_before
                or staged_auditor_before != auditor_before
            ):
                raise PolicyError("staged pnpm execution runtime changed authority")
            entrypoint = staged_pnpm.joinpath(
                *_safe_relative(
                    policy["auditor"]["entrypoint"]["path"], "pnpm entrypoint"
                )
            )
            command = [
                os.fspath(staged_node),
                os.fspath(entrypoint),
                *policy["audit"]["arguments"],
            ]
            outcome = run_bounded(
                command,
                cwd=projected_root,
                env=environment,
                timeout_seconds=policy["audit"]["timeout_seconds"],
                maximum_output_bytes=policy["audit"]["maximum_output_bytes"],
            )
            stdout = outcome.pop("stdout")
            stderr = outcome.pop("stderr")
            assert isinstance(stdout, bytes) and isinstance(stderr, bytes)
            _, staged_node_after = node_identity(policy, staged_node)
            staged_auditor_after = auditor_distribution(policy, staged_pnpm)
            if (
                staged_node_after != staged_node_before
                or staged_auditor_after != staged_auditor_before
            ):
                raise PolicyError("staged pnpm execution runtime changed during audit")
        finally:
            _thaw_staged_runtime(runtime_root)

    after_source = source_snapshot(root)
    if after_source != before_source or source_metadata(policy, root) != metadata:
        raise PolicyError("source changed during the pnpm production audit")
    auditor_after = auditor_distribution(policy, pnpm_root)
    _, node_after = node_identity(policy, node_executable)
    if auditor_after != auditor_before or node_after != node_before:
        raise PolicyError("pnpm auditor or Node runtime changed during the audit")
    if (
        outcome["exit_code"] != 0
        or outcome["timed_out"]
        or outcome["output_overflow"]
        or outcome["descendant_cleanup_required"]
        or stderr
    ):
        raise PolicyError(
            "pnpm production audit did not complete cleanly; "
            f"exit={outcome['exit_code']} stdout_sha256={sha256_bytes(stdout)} "
            f"stderr_sha256={sha256_bytes(stderr)}"
        )
    result = evaluate_result(stdout, policy)
    policy_payload = _secure_regular_bytes(
        policy_path, "pnpm audit policy", _MAX_METADATA_BYTES
    )
    metadata_records = [
        {"path": relative, "bytes": len(payload), "sha256": sha256_bytes(payload)}
        for relative, payload in sorted(metadata.items())
    ]
    command_authority = semantic_command(policy, node_before)
    receipt_payload: dict[str, object] = {
        "schema_version": "cigar.pnpm-production-audit-receipt.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy": {
            "schema_version": policy["schema_version"],
            "bytes": len(policy_payload),
            "sha256": sha256_bytes(policy_payload),
        },
        "source": before_source,
        "source_metadata": metadata_records,
        "host": host,
        "node": node_before,
        "auditor": {
            "name": policy["auditor"]["name"],
            "version": policy["auditor"]["version"],
            "corepack_hash": policy["auditor"]["corepack_hash"],
            "distribution": auditor_before,
        },
        "runtime": {
            "algorithm": "cigar.private-staged-pnpm-runtime.v1",
            "node": node_before,
            "auditor_distribution": auditor_before,
            "private_create_new": True,
            "source_revalidated": True,
            "staged_revalidated": True,
        },
        "projection": {
            "algorithm": "cigar.pnpm-audit-metadata-projection.v1",
            "files": projection_records,
            "root_package_manager_only": True,
        },
        "command": {
            **command_authority,
            "sha256": sha256_bytes(canonical_json_bytes(command_authority)),
        },
        "process": {
            **outcome,
            "stdout_bytes": len(stdout),
            "stdout_sha256": sha256_bytes(stdout),
            "stderr_bytes": len(stderr),
            "stderr_sha256": sha256_bytes(stderr),
        },
        "result": result,
        "claims": expected_claims(before_source),
    }
    publish_receipt(receipt, receipt_payload, root)
    return receipt_payload


def verify_receipt(
    *,
    root: Path,
    policy_path: Path,
    node_executable: Path,
    pnpm_root: Path,
    receipt: Path,
) -> dict[str, Any]:
    raw_receipt = os.fspath(receipt)
    if (
        not receipt.is_absolute()
        or os.path.normpath(raw_receipt) != raw_receipt
        or receipt.resolve(strict=True) != receipt
    ):
        raise PolicyError("pnpm audit receipt path is not absolute and canonical")
    try:
        parent = receipt.parent.resolve(strict=True)
        parent_metadata = receipt.parent.lstat()
    except OSError as error:
        raise PolicyError(
            f"cannot inspect pnpm audit receipt parent: {error}"
        ) from error
    if (
        parent != receipt.parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or parent_metadata.st_uid != os.getuid()
    ):
        raise PolicyError("pnpm audit receipt parent is not owner-controlled mode 0700")
    try:
        parent.relative_to(root)
    except ValueError:
        pass
    else:
        raise PolicyError("pnpm audit receipt must remain outside the source checkout")
    try:
        metadata = receipt.lstat()
    except OSError as error:
        raise PolicyError(f"cannot read pnpm audit receipt: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o400
    ):
        raise PolicyError("pnpm audit receipt is not a protected regular file")
    payload = _secure_regular_bytes(receipt, "pnpm audit receipt", _MAX_METADATA_BYTES)
    document = strict_json_bytes(payload, "pnpm audit receipt")
    if (
        set(document)
        != {
            "schema_version",
            "generated_utc",
            "policy",
            "source",
            "source_metadata",
            "host",
            "node",
            "auditor",
            "runtime",
            "projection",
            "command",
            "process",
            "result",
            "claims",
        }
        or document.get("schema_version") != "cigar.pnpm-production-audit-receipt.v1"
    ):
        raise PolicyError("unsupported pnpm audit receipt schema")
    generated = document.get("generated_utc")
    if (
        not isinstance(generated, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", generated
        )
        is None
    ):
        raise PolicyError("pnpm audit receipt timestamp is malformed")
    try:
        generated_time = datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise PolicyError("pnpm audit receipt timestamp is invalid") from error
    if generated_time.timestamp() > datetime.now(timezone.utc).timestamp() + 300:
        raise PolicyError("pnpm audit receipt timestamp is in the future")

    policy = load_policy(policy_path)
    policy_payload = _secure_regular_bytes(
        policy_path, "pnpm audit policy", _MAX_METADATA_BYTES
    )
    if document.get("policy") != {
        "schema_version": policy["schema_version"],
        "bytes": len(policy_payload),
        "sha256": sha256_bytes(policy_payload),
    }:
        raise PolicyError("pnpm audit receipt policy binding changed")
    source = source_snapshot(root)
    if document.get("source") != source:
        raise PolicyError("pnpm audit receipt source binding changed")
    metadata_payloads = source_metadata(policy, root)
    expected_metadata = [
        {"path": relative, "bytes": len(value), "sha256": sha256_bytes(value)}
        for relative, value in sorted(metadata_payloads.items())
    ]
    if document.get("source_metadata") != expected_metadata:
        raise PolicyError("pnpm audit receipt metadata binding changed")
    if document.get("host") != verify_host(policy):
        raise PolicyError("pnpm audit receipt host binding changed")
    distribution = auditor_distribution(policy, pnpm_root)
    _, node = node_identity(policy, node_executable)
    expected_auditor = {
        "name": policy["auditor"]["name"],
        "version": policy["auditor"]["version"],
        "corepack_hash": policy["auditor"]["corepack_hash"],
        "distribution": distribution,
    }
    if document.get("auditor") != expected_auditor:
        raise PolicyError("pnpm audit receipt auditor binding changed")
    if document.get("node") != node:
        raise PolicyError("pnpm audit receipt Node binding changed")
    expected_runtime = {
        "algorithm": "cigar.private-staged-pnpm-runtime.v1",
        "node": node,
        "auditor_distribution": distribution,
        "private_create_new": True,
        "source_revalidated": True,
        "staged_revalidated": True,
    }
    if document.get("runtime") != expected_runtime:
        raise PolicyError("pnpm audit receipt staged-runtime binding changed")

    projected = project_metadata(policy, metadata_payloads)
    projection_records = [
        {"path": relative, "bytes": len(value), "sha256": sha256_bytes(value)}
        for relative, value in sorted(projected.items())
    ]
    expected_projection = {
        "algorithm": "cigar.pnpm-audit-metadata-projection.v1",
        "files": projection_records,
        "root_package_manager_only": True,
    }
    if document.get("projection") != expected_projection:
        raise PolicyError("pnpm audit receipt projection binding changed")

    command_authority = semantic_command(policy, node)
    expected_command = {
        **command_authority,
        "sha256": sha256_bytes(canonical_json_bytes(command_authority)),
    }
    if document.get("command") != expected_command:
        raise PolicyError("pnpm audit receipt command binding changed")

    process = document.get("process")
    expected_process_fields = {
        "exit_code",
        "duration_seconds",
        "timed_out",
        "output_overflow",
        "descendant_cleanup_required",
        "stdout_bytes",
        "stdout_sha256",
        "stderr_bytes",
        "stderr_sha256",
    }
    if not isinstance(process, dict) or set(process) != expected_process_fields:
        raise PolicyError("pnpm audit receipt process schema changed")
    if (
        type(process["exit_code"]) is not int
        or type(process["stdout_bytes"]) is not int
        or type(process["stderr_bytes"]) is not int
        or type(process["timed_out"]) is not bool
        or type(process["output_overflow"]) is not bool
        or type(process["descendant_cleanup_required"]) is not bool
        or not isinstance(process["stdout_sha256"], str)
        or not isinstance(process["stderr_sha256"], str)
    ):
        raise PolicyError("pnpm audit receipt process field types changed")
    duration = process.get("duration_seconds")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration < 0
        or duration > policy["audit"]["timeout_seconds"] + 10
    ):
        raise PolicyError("pnpm audit receipt duration is invalid")
    expected_report = policy["audit"]["expected_report"]
    expected_empty_digest = sha256_bytes(b"")
    if {
        key: process[key] for key in expected_process_fields - {"duration_seconds"}
    } != {
        "exit_code": 0,
        "timed_out": False,
        "output_overflow": False,
        "descendant_cleanup_required": False,
        "stdout_bytes": expected_report["bytes"],
        "stdout_sha256": expected_report["sha256"],
        "stderr_bytes": 0,
        "stderr_sha256": expected_empty_digest,
    }:
        raise PolicyError("pnpm audit receipt process outcome changed")
    if document.get("result") != expected_result(policy):
        raise PolicyError("pnpm audit receipt result changed")
    if document.get("claims") != expected_claims(source):
        raise PolicyError("pnpm audit receipt claims changed")
    return document


def parse_arguments(arguments: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-policy")
    tool = subparsers.add_parser("verify-tool")
    tool.add_argument("--node", type=Path, required=True)
    tool.add_argument("--pnpm-root", type=Path, required=True)
    scan = subparsers.add_parser("scan")
    scan.add_argument("--node", type=Path, required=True)
    scan.add_argument("--pnpm-root", type=Path, required=True)
    scan.add_argument("--receipt", type=Path, required=True)
    verify = subparsers.add_parser("verify-receipt")
    verify.add_argument("--node", type=Path, required=True)
    verify.add_argument("--pnpm-root", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Optional[list[str]] = None) -> int:
    options = parse_arguments(arguments)
    try:
        root = options.root.resolve(strict=True)
        policy_path = options.policy.resolve(strict=True)
        if options.command == "verify-policy":
            load_policy(policy_path)
        elif options.command == "verify-tool":
            policy = load_policy(policy_path)
            verify_host(policy)
            auditor_distribution(policy, options.pnpm_root.resolve(strict=True))
            node_identity(policy, options.node)
        elif options.command == "scan":
            run_scan(
                root=root,
                policy_path=policy_path,
                node_executable=options.node,
                pnpm_root=options.pnpm_root.resolve(strict=True),
                receipt=options.receipt,
            )
        elif options.command == "verify-receipt":
            verify_receipt(
                root=root,
                policy_path=policy_path,
                node_executable=options.node,
                pnpm_root=options.pnpm_root.resolve(strict=True),
                receipt=options.receipt,
            )
        else:  # pragma: no cover - argparse enforces the closed command set
            raise PolicyError("unsupported pnpm audit command")
    except (OSError, PolicyError, subprocess.SubprocessError) as error:
        print(f"pnpm audit policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
