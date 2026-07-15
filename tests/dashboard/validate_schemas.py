#!/usr/bin/env python3
"""Validate dashboard schema documents and local references without third-party packages."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "schemas" / "dashboard"
EXPECTED_DRAFT = "https://json-schema.org/draft/2020-12/schema"
RECEIPT_NAME = "dashboard-schema-check.v1.json"
SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class ValidationFailure(Exception):
    """A dashboard schema or reference is malformed."""


def load_documents() -> dict[Path, dict[str, Any]]:
    """Load strict UTF-8 JSON objects and reject duplicate schema identities."""
    documents: dict[Path, dict[str, Any]] = {}
    identities: set[str] = set()
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValidationFailure(f"{path}: invalid strict JSON") from error
        if not isinstance(value, dict):
            raise ValidationFailure(f"{path}: schema root is not an object")
        if value.get("$schema") != EXPECTED_DRAFT:
            raise ValidationFailure(f"{path}: unexpected or missing JSON Schema draft")
        identity = value.get("$id")
        if not isinstance(identity, str) or not identity.startswith(
            "https://cigar.dev/schemas/dashboard/"
        ):
            raise ValidationFailure(f"{path}: invalid schema identity")
        if identity in identities:
            raise ValidationFailure(f"{path}: duplicate schema identity")
        identities.add(identity)
        documents[path.resolve()] = value
    if not documents:
        raise ValidationFailure("no dashboard schemas found")
    return documents


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationFailure(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def walk(value: Any) -> list[dict[str, Any]]:
    """Return every object node in deterministic depth-first order."""
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        for key in sorted(value):
            found.extend(walk(value[key]))
    elif isinstance(value, list):
        for item in value:
            found.extend(walk(item))
    return found


def resolve_pointer(document: Any, fragment: str, source: Path) -> None:
    """Resolve a local JSON Pointer and reject absent nodes."""
    if fragment in ("", "#"):
        return
    if not fragment.startswith("#/"):
        raise ValidationFailure(f"{source}: unsupported reference fragment {fragment}")
    current = document
    for encoded in fragment[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise ValidationFailure(
                f"{source}: unresolved reference fragment {fragment}"
            )


def validate_references(documents: dict[Path, dict[str, Any]]) -> int:
    """Resolve every relative dashboard schema reference and return its count."""
    references = 0
    for source, document in documents.items():
        for node in walk(document):
            reference = node.get("$ref")
            if reference is None:
                continue
            if not isinstance(reference, str) or reference.startswith(
                ("http://", "https://")
            ):
                raise ValidationFailure(f"{source}: external or malformed reference")
            path_text, separator, fragment_text = reference.partition("#")
            target = source if not path_text else (source.parent / path_text).resolve()
            target_document = documents.get(target)
            if target_document is None:
                raise ValidationFailure(
                    f"{source}: missing referenced schema {path_text}"
                )
            fragment = f"#{fragment_text}" if separator else ""
            resolve_pointer(target_document, fragment, source)
            references += 1
    return references


def schema_set_digest(documents: dict[Path, dict[str, Any]]) -> str:
    """Bind the receipt to every validated schema path and exact byte sequence."""
    digest = hashlib.sha256()
    for path in sorted(documents):
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        source = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(source).to_bytes(8, "big"))
        digest.update(source)
    return digest.hexdigest()


def write_receipt_if_requested(
    documents: dict[Path, dict[str, Any]], references: int
) -> None:
    """Write one create-new, content-safe receipt into a supervisor-owned root."""
    configured = os.environ.get("CIGAR_EVIDENCE_DIR")
    if configured is None:
        return
    evidence_root = Path(configured)
    if not evidence_root.is_absolute():
        raise ValidationFailure("CIGAR_EVIDENCE_DIR must be absolute")
    metadata = evidence_root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValidationFailure("evidence root must be an owner-only directory")
    resolved_root = evidence_root.resolve(strict=True)
    if resolved_root == ROOT or ROOT in resolved_root.parents:
        raise ValidationFailure("evidence root must be outside the source checkout")
    source_revision = os.environ.get("CIGAR_SOURCE_REVISION", "")
    if not SOURCE_REVISION.fullmatch(source_revision):
        raise ValidationFailure("CIGAR_SOURCE_REVISION is missing or malformed")
    host_platform = "macos" if sys.platform == "darwin" else sys.platform
    architecture = platform.machine().lower()
    if architecture == "aarch64":
        architecture = "arm64"
    receipt = {
        "host": {"architecture": architecture, "platform": host_platform},
        "reference_count": references,
        "schema_count": len(documents),
        "schema_set_sha256": schema_set_digest(documents),
        "schema_version": "cigar.dashboard-schema-check.v1",
        "source_revision": source_revision,
        "status": "passed",
    }
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    destination = evidence_root / RECEIPT_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory = os.open(evidence_root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
    """Run dashboard schema checks."""
    try:
        documents = load_documents()
        references = validate_references(documents)
        write_receipt_if_requested(documents, references)
    except ValidationFailure as error:
        print(f"dashboard schema validation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"validated {len(documents)} dashboard schemas and {references} local references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
