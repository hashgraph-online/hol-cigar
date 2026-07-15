#!/usr/bin/python3
"""Draft or validate the externally reviewed macOS xtask tool authority.

``draft`` never computes an approval digest for the operator.  It accepts a
protected reviewed-tool document containing explicit paths and SHA-256 values,
reopens every target, rejects mismatches, binds the current clean Git source,
and creates the final route authority outside the checkout.  ``validate``
independently repeats those checks and prints only a content-free binding.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SCRIPTS = REPOSITORY_ROOT / "scripts" / "release"
XTASK = REPOSITORY_ROOT / "crates" / "xtask"
for directory in (RELEASE_SCRIPTS, XTASK):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from command_plane_evidence import source_binding  # noqa: E402
from evidence_workspace import canonical_json_bytes  # noqa: E402
from release_lib import ReleaseError, load_json_bytes  # noqa: E402


AUTHORITY_SCHEMA = "cigar.xtask-tool-inputs.v2"
REVIEW_SCHEMA = "cigar.xtask-reviewed-tools.v1"
ROUTE_TOOL_SCHEMA = "cigar.xtask-route-tools.v1"
ROUTE_TOOL_PATH = XTASK / "route-tools.v1.json"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024


def _load_route_tools() -> dict[str, frozenset[str]]:
    try:
        document = load_json_bytes(ROUTE_TOOL_PATH.read_bytes(), "route tool manifest")
    except (OSError, ReleaseError) as error:
        raise RuntimeError("route tool manifest is unavailable") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"routes", "schema_version"}
        or document.get("schema_version") != ROUTE_TOOL_SCHEMA
        or not isinstance(document.get("routes"), dict)
        or not document["routes"]
    ):
        raise RuntimeError("route tool manifest is malformed")
    result: dict[str, frozenset[str]] = {}
    for command_id, tools in document["routes"].items():
        if (
            not isinstance(command_id, str)
            or not isinstance(tools, list)
            or any(
                not isinstance(tool, str)
                or not tool
                or any(
                    not (
                        character.isascii()
                        and (character.isalnum() or character in "+-._")
                    )
                    for character in tool
                )
                for tool in tools
            )
            or tools != sorted(set(tools))
        ):
            raise RuntimeError("route tool manifest inventory is malformed")
        result[command_id] = frozenset(tools)
    return result


ROUTE_TOOLS = _load_route_tools()
TOOLS = frozenset(tool for tools in ROUTE_TOOLS.values() for tool in tools)
ENVIRONMENT = frozenset(
    {
        "CARGO_HOME",
        "COREPACK_HOME",
        "GOCACHE",
        "GOMODCACHE",
        "HOME",
        "NPM_CONFIG_CACHE",
        "RUSTUP_HOME",
        "UV_CACHE_DIR",
    }
)


class ToolAuthorityError(RuntimeError):
    """The reviewed tool authority is unsafe, stale, or malformed."""


def _protected_lineage(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        metadata = current.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or (mode & 0o022 and not sticky_root)
        ):
            raise ToolAuthorityError(f"{label} has an unprotected path ancestor")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _protected_document(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ToolAuthorityError(f"{label} must be an absolute canonical file")
    _protected_lineage(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        named_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ToolAuthorityError(f"{label} cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size <= 0
            or before.st_size > MAX_DOCUMENT_BYTES
        ):
            raise ToolAuthorityError(f"{label} must be one owner-private file")
        payload = b""
        while len(payload) <= MAX_DOCUMENT_BYTES:
            chunk = os.read(
                descriptor, min(64 * 1024, MAX_DOCUMENT_BYTES + 1 - len(payload))
            )
            if not chunk:
                break
            payload += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = path.lstat()
    except OSError as error:
        raise ToolAuthorityError(f"{label} changed after inspection") from error
    stable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        len(payload) != before.st_size
        or any(getattr(before, field) != getattr(after, field) for field in stable)
        or any(
            getattr(named_before, field) != getattr(named_after, field)
            for field in stable
        )
        or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
    ):
        raise ToolAuthorityError(f"{label} changed while read")
    try:
        document = load_json_bytes(payload, label)
    except ReleaseError as error:
        raise ToolAuthorityError(f"{label} is not strict JSON") from error
    if not isinstance(document, dict) or canonical_json_bytes(document) != payload:
        raise ToolAuthorityError(f"{label} must be a canonical JSON object")
    return document, payload


def _private_directory(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ToolAuthorityError(f"{label} must be a path string")
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ToolAuthorityError(f"{label} must be an absolute canonical directory")
    metadata = path.lstat()
    _protected_lineage(path, label)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ToolAuthorityError(f"{label} must be owner-private")
    return os.fspath(path)


def _reviewed_tool(value: object, name: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ToolAuthorityError(f"reviewed tool {name} has an unexpected shape")
    path_value = value.get("path")
    expected = value.get("sha256")
    if (
        not isinstance(path_value, str)
        or not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ToolAuthorityError(f"reviewed tool {name} identity is invalid")
    original = Path(path_value)
    if (
        not original.is_absolute()
        or os.path.normpath(path_value) != path_value
        or os.fspath(original) != path_value
    ):
        raise ToolAuthorityError(
            f"reviewed tool {name} path must be absolute and canonical"
        )
    try:
        path = original.resolve(strict=True)
    except OSError as error:
        raise ToolAuthorityError(f"reviewed tool {name} is unavailable") from error
    if path != original:
        raise ToolAuthorityError(
            f"reviewed tool {name} path must not contain aliases or symlinks"
        )
    _protected_lineage(path, f"reviewed tool {name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        named_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ToolAuthorityError(
            f"reviewed tool {name} cannot be opened safely"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (named_before.st_dev, named_before.st_ino)
            or before.st_uid not in {0, os.geteuid()}
            or (before.st_uid != 0 and before.st_nlink != 1)
            or stat.S_IMODE(before.st_mode) & 0o022
            or not before.st_mode & stat.S_IXUSR
            or before.st_size <= 0
            or before.st_size > MAX_TOOL_BYTES
        ):
            raise ToolAuthorityError(
                f"reviewed tool {name} differs from operator approval"
            )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ToolAuthorityError(f"reviewed tool {name} changed while read")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ToolAuthorityError(f"reviewed tool {name} grew while read")
        after = os.fstat(descriptor)
        named_after = path.lstat()
    finally:
        os.close(descriptor)
    stable = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(getattr(before, field) != getattr(after, field) for field in stable)
        or any(
            getattr(named_before, field) != getattr(named_after, field)
            for field in stable
        )
        or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        or digest.hexdigest() != expected
    ):
        raise ToolAuthorityError(f"reviewed tool {name} changed or was substituted")
    return {"path": os.fspath(path), "sha256": expected}


def _validate_tools(
    value: object, expected: frozenset[str]
) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ToolAuthorityError(
            "reviewed tools must equal the exact least-privilege route tool set"
        )
    return {name: _reviewed_tool(value[name], name) for name in sorted(expected)}


def _parse_environment(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        name, separator, path = item.partition("=")
        if not separator or name in result:
            raise ToolAuthorityError(
                "environment entries must be unique NAME=/absolute/path"
            )
        result[name] = _private_directory(path, f"environment {name}")
    if set(result) != ENVIRONMENT:
        raise ToolAuthorityError(
            "environment must equal the exact private cache-root set"
        )
    return dict(sorted(result.items()))


def _validate_source(value: object, expected: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or value != dict(expected):
        raise ToolAuthorityError(
            "tool authority is not bound to the current clean source"
        )
    if value.get("clean") is not True or value.get("committed") is not True:
        raise ToolAuthorityError("tool authority source is not release-qualifying")
    return dict(value)


def draft(arguments: argparse.Namespace) -> dict[str, object]:
    reviewed, _payload = _protected_document(arguments.reviewed_tools, "reviewed tools")
    if (
        set(reviewed) != {"schema_version", "tools"}
        or reviewed.get("schema_version") != REVIEW_SCHEMA
    ):
        raise ToolAuthorityError("reviewed tools have an unsupported schema")
    expected_tools = ROUTE_TOOLS[arguments.command_id]
    if not expected_tools:
        raise ToolAuthorityError(
            "selected route does not use the standard tool authority"
        )
    tools = _validate_tools(reviewed.get("tools"), expected_tools)
    environment = _parse_environment(arguments.environment)
    source = source_binding(REPOSITORY_ROOT)
    _validate_source(source, source)
    document = {
        "command_id": arguments.command_id,
        "environment": environment,
        "schema_version": AUTHORITY_SCHEMA,
        "source": source,
        "tools": tools,
    }
    output = arguments.output
    if (
        not output.is_absolute()
        or output.exists()
        or output.is_symlink()
        or output.name in {"", ".", ".."}
        or REPOSITORY_ROOT in output.parents
    ):
        raise ToolAuthorityError(
            "authority output must be create-new and outside the repository"
        )
    parent = output.parent.resolve(strict=True)
    if output.parent != parent:
        raise ToolAuthorityError("authority output parent must be canonical")
    _private_directory(os.fspath(parent), "authority output parent")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory = os.open(parent, directory_flags)
    descriptor: int | None = None
    created = False
    payload = canonical_json_bytes(document)
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(output.name, flags, 0o400, dir_fd=directory)
        created = True
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise ToolAuthorityError("authority output was not written completely")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size != len(payload)
        ):
            raise ToolAuthorityError("authority output identity is invalid")
        os.fsync(directory)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                os.unlink(output.name, dir_fd=directory)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
    return {
        "bytes": len(payload),
        "schema_version": AUTHORITY_SCHEMA,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "tool_count": len(tools),
    }


def validate(arguments: argparse.Namespace) -> dict[str, object]:
    document, payload = _protected_document(arguments.authority, "tool authority")
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if (
        not isinstance(arguments.expected_sha256, str)
        or len(arguments.expected_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in arguments.expected_sha256
        )
        or arguments.expected_sha256 != actual_sha256
    ):
        raise ToolAuthorityError(
            "tool authority differs from the independently reviewed digest"
        )
    if set(document) != {
        "command_id",
        "environment",
        "schema_version",
        "source",
        "tools",
    }:
        raise ToolAuthorityError("tool authority has an unexpected shape")
    if document.get("schema_version") != AUTHORITY_SCHEMA:
        raise ToolAuthorityError("tool authority has an unsupported schema")
    command_id = document.get("command_id")
    if not isinstance(command_id, str) or command_id not in ROUTE_TOOLS:
        raise ToolAuthorityError("tool authority command identity is unsupported")
    source = source_binding(REPOSITORY_ROOT)
    _validate_source(document.get("source"), source)
    environment = document.get("environment")
    if not isinstance(environment, dict) or set(environment) != ENVIRONMENT:
        raise ToolAuthorityError("tool authority environment is not exact")
    for name, path in environment.items():
        _private_directory(path, f"environment {name}")
    tools = _validate_tools(document.get("tools"), ROUTE_TOOLS[command_id])
    return {
        "bytes": len(payload),
        "schema_version": AUTHORITY_SCHEMA,
        "sha256": actual_sha256,
        "tool_count": len(tools),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    draft_parser = subcommands.add_parser("draft")
    draft_parser.add_argument(
        "--command-id", choices=sorted(ROUTE_TOOLS), required=True
    )
    draft_parser.add_argument("--reviewed-tools", type=Path, required=True)
    draft_parser.add_argument("--environment", action="append", default=[])
    draft_parser.add_argument("--output", type=Path, required=True)
    validate_parser = subcommands.add_parser("validate")
    validate_parser.add_argument("--authority", type=Path, required=True)
    validate_parser.add_argument("--expected-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = draft(arguments) if arguments.action == "draft" else validate(arguments)
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ToolAuthorityError, ValueError):
        print(
            "xtask tool authority failed; sensitive diagnostics were suppressed",
            file=sys.stderr,
        )
        raise SystemExit(2)
