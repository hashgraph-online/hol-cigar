#!/usr/bin/env python3
"""Fail-closed validation for CIGAR's append-only migration authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

AUTHORITY_RELATIVE = Path("migrations/authority-v1.json")
MAX_AUTHORITY_BYTES = 1_048_576
TOP_LEVEL_KEYS = {
    "schema_version",
    "application_major",
    "backends",
    "qualification",
}
BACKEND_KEYS = {"backend", "transaction_owner", "retained_sequences", "migrations"}
MIGRATION_KEYS = {
    "sequence",
    "name",
    "source",
    "crate_mirror",
    "sha256",
    "minimum_application_major",
    "maximum_application_major",
    "online",
}
QUALIFICATION_KEYS = {"claimed_host", "sqlite", "postgres"}
BACKEND_NAMES = ("sqlite", "postgres")
TRANSACTION_CONTROL = re.compile(
    r"^\s*(?:BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b", re.IGNORECASE
)


class AuthorityError(ValueError):
    """Content-free validation failure."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError("authority contains a duplicate JSON field")
        result[key] = value
    return result


def _read_authority(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AuthorityError("authority must be one regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_AUTHORITY_BYTES:
        raise AuthorityError("authority size is outside the fixed bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuthorityError("authority is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AuthorityError("authority root must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise AuthorityError(f"{label} fields do not match the closed schema")


def _safe_file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise AuthorityError("migration path is invalid")
    lexical = Path(relative)
    if lexical.is_absolute() or any(part in ("", ".", "..") for part in lexical.parts):
        raise AuthorityError("migration path escapes its repository authority")
    candidate = root.joinpath(*lexical.parts)
    current = root
    for part in lexical.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise AuthorityError("migration path is missing") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise AuthorityError("migration path contains a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise AuthorityError("migration path resolves outside the repository") from error
    if not resolved.is_file():
        raise AuthorityError("migration source is not a regular file")
    return resolved


def _integer(value: Any, label: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuthorityError(f"{label} is outside its integer bound")
    return value


def _validate_header(text: str, migration: dict[str, Any]) -> None:
    sequence = migration["sequence"]
    name = migration["name"]
    minimum = migration["minimum_application_major"]
    maximum = migration["maximum_application_major"]
    classification = "online" if migration["online"] else "offline"
    required = (
        f"-- sequence/name: {sequence} / {name}",
        f"-- application compatibility: major {minimum} through major {maximum}",
        f"-- classification/lock: {classification} /",
        "-- verification:",
        "-- rollback or restore:",
    )
    for marker in required:
        if marker not in text:
            raise AuthorityError("migration source metadata does not match authority")
    for line in text.splitlines():
        if not line.lstrip().startswith("--") and TRANSACTION_CONTROL.match(line):
            raise AuthorityError("migration source owns transaction control")


def validate(repo_root: Path) -> dict[str, int]:
    root = repo_root.resolve(strict=True)
    authority = _read_authority(_safe_file(root, AUTHORITY_RELATIVE.as_posix()))
    _exact_keys(authority, TOP_LEVEL_KEYS, "authority")
    if authority["schema_version"] != "cigar.migration-authority.v1":
        raise AuthorityError("authority schema version is unsupported")
    application_major = _integer(authority["application_major"], "application major")
    backends = authority["backends"]
    if not isinstance(backends, list) or len(backends) != len(BACKEND_NAMES):
        raise AuthorityError("authority must define each backend exactly once")

    seen_backends: list[str] = []
    seen_sources: set[str] = set()
    seen_mirrors: set[str] = set()
    migration_count = 0
    retained_count = 0
    for backend in backends:
        if not isinstance(backend, dict):
            raise AuthorityError("backend authority must be an object")
        _exact_keys(backend, BACKEND_KEYS, "backend")
        backend_name = backend["backend"]
        if backend_name not in BACKEND_NAMES or backend_name in seen_backends:
            raise AuthorityError("backend order or identity is invalid")
        seen_backends.append(backend_name)
        if not isinstance(backend["transaction_owner"], str) or not backend["transaction_owner"]:
            raise AuthorityError("transaction owner is invalid")
        migrations = backend["migrations"]
        if not isinstance(migrations, list) or not migrations or len(migrations) > 4096:
            raise AuthorityError("migration inventory is outside its fixed bound")
        retained = backend["retained_sequences"]
        if (
            not isinstance(retained, list)
            or not retained
            or retained != sorted(set(retained))
            or any(isinstance(value, bool) or not isinstance(value, int) for value in retained)
        ):
            raise AuthorityError("retained sequence fixture list is invalid")

        expected_sources: set[str] = set()
        expected_mirrors: set[str] = set()
        for index, migration in enumerate(migrations, start=1):
            if not isinstance(migration, dict):
                raise AuthorityError("migration authority row must be an object")
            _exact_keys(migration, MIGRATION_KEYS, "migration")
            sequence = _integer(migration["sequence"], "migration sequence")
            minimum = _integer(
                migration["minimum_application_major"], "minimum application major"
            )
            maximum = _integer(
                migration["maximum_application_major"], "maximum application major"
            )
            if sequence != index or minimum > maximum:
                raise AuthorityError("migration sequence or compatibility interval is invalid")
            if not isinstance(migration["online"], bool):
                raise AuthorityError("migration online classification is invalid")
            name = migration["name"]
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", name)
            ):
                raise AuthorityError("migration name is invalid")
            expected_filename = f"{sequence:04d}_{name}.sql"
            source_relative = migration["source"]
            mirror_relative = migration["crate_mirror"]
            if (
                not isinstance(source_relative, str)
                or not isinstance(mirror_relative, str)
                or Path(source_relative).name != expected_filename
                or Path(mirror_relative).name != expected_filename
                or source_relative in seen_sources
                or mirror_relative in seen_mirrors
            ):
                raise AuthorityError("migration filename or uniqueness is invalid")
            seen_sources.add(source_relative)
            seen_mirrors.add(mirror_relative)
            expected_sources.add(source_relative)
            expected_mirrors.add(mirror_relative)
            source = _safe_file(root, source_relative)
            mirror = _safe_file(root, mirror_relative)
            source_bytes = source.read_bytes()
            mirror_bytes = mirror.read_bytes()
            if source_bytes != mirror_bytes:
                raise AuthorityError("migration source and crate mirror differ")
            digest = migration["sha256"]
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or hashlib.sha256(source_bytes).hexdigest() != digest
            ):
                raise AuthorityError("migration source digest differs from append-only authority")
            try:
                text = source_bytes.decode("utf-8")
            except UnicodeDecodeError as error:
                raise AuthorityError("migration source is not UTF-8") from error
            _validate_header(text, migration)
            migration_count += 1

        if retained != list(range(1, max(retained) + 1)) or max(retained) > len(migrations):
            raise AuthorityError("retained sequences are not a contiguous installed fixture set")
        retained_count += len(retained)
        source_dir = root / "migrations" / backend_name
        mirror_dir = root / "crates" / "cigar-store" / "migrations" / backend_name
        actual_sources = {
            path.relative_to(root).as_posix()
            for path in source_dir.glob("*.sql")
            if path.is_file()
        }
        actual_mirrors = {
            path.relative_to(root).as_posix()
            for path in mirror_dir.glob("*.sql")
            if path.is_file()
        }
        if actual_sources != expected_sources or actual_mirrors != expected_mirrors:
            raise AuthorityError("migration directory contains an unlisted, missing, or renamed source")

    if seen_backends != list(BACKEND_NAMES):
        raise AuthorityError("backend authority order is not canonical")
    qualification = authority["qualification"]
    if not isinstance(qualification, dict):
        raise AuthorityError("qualification boundary must be an object")
    _exact_keys(qualification, QUALIFICATION_KEYS, "qualification")
    if qualification["claimed_host"] != "macos-aarch64" or any(
        not isinstance(qualification[key], str) or not qualification[key]
        for key in ("sqlite", "postgres")
    ):
        raise AuthorityError("qualification boundary is invalid")
    if application_major != 1:
        raise AuthorityError("this authority is bound to application major one")
    return {
        "backends": len(backends),
        "migrations": migration_count,
        "retained_fixtures": retained_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    arguments = parser.parse_args()
    try:
        counts = validate(arguments.repo_root)
    except (AuthorityError, OSError) as error:
        print(f"migration authority validation failed: {error}")
        return 1
    print(
        "migration authority validated: "
        f"backends={counts['backends']} migrations={counts['migrations']} "
        f"retained_fixtures={counts['retained_fixtures']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
