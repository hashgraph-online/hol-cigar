#!/usr/bin/env python3
"""Validate dashboard schema documents and local references without third-party packages."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "schemas" / "dashboard"
EXPECTED_DRAFT = "https://json-schema.org/draft/2020-12/schema"


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


def main() -> int:
    """Run dashboard schema checks."""
    try:
        documents = load_documents()
        references = validate_references(documents)
    except ValidationFailure as error:
        print(f"dashboard schema validation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"validated {len(documents)} dashboard schemas and {references} local references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
