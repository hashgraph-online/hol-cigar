#!/usr/bin/env python3
"""Validate and compare the CIGAR v1 development compatibility policy offline."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


POLICY_PATH = "spec/compatibility/policy-v1.json"
POLICY_SCHEMA_PATH = "spec/compatibility/compatibility-policy-v1.schema.json"
POLICY_ID = "cigar.protocol-compatibility-policy.v1"
POLICY_STATUS = "development-source-policy"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
MAX_CONTAINER_ITEMS = 100_000
MAX_STRING_BYTES = 1024 * 1024
MAX_PATHS = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
MIGRATION_RE = re.compile(r"^(?P<sequence>[0-9]{4})_(?P<name>[a-z][a-z0-9_]*)\.sql$")
CLI_PROJECTION_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
MCP_PROJECTION_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class CompatibilityError(RuntimeError):
    """A compatibility policy, authority, or comparison is invalid."""


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise CompatibilityError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_constant(value: str) -> Any:
    raise CompatibilityError(f"non-finite JSON number is forbidden: {value}")


def _parse_integer(value: str) -> int:
    if len(value) > 20:
        raise CompatibilityError("JSON integer exceeds signed 64-bit range")
    parsed = int(value, 10)
    if not -(1 << 63) <= parsed <= (1 << 63) - 1:
        raise CompatibilityError("JSON integer exceeds signed 64-bit range")
    return parsed


def _parse_float(value: str) -> float:
    if len(value) > 128:
        raise CompatibilityError("JSON floating-point literal is unbounded")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CompatibilityError("non-finite JSON number is forbidden")
    return parsed


def _validate_json_tree(value: Any) -> Any:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise CompatibilityError("JSON exceeds the aggregate node limit")
        if depth > MAX_JSON_DEPTH:
            raise CompatibilityError("JSON exceeds the nesting-depth limit")
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int):
            if not -(1 << 63) <= current <= (1 << 63) - 1:
                raise CompatibilityError("JSON integer exceeds signed 64-bit range")
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise CompatibilityError("non-finite JSON number is forbidden")
            continue
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_STRING_BYTES:
                raise CompatibilityError("JSON string exceeds the byte limit")
            if current != unicodedata.normalize("NFC", current):
                raise CompatibilityError("JSON string is not NFC-normalized")
            continue
        if isinstance(current, list):
            if len(current) > MAX_CONTAINER_ITEMS:
                raise CompatibilityError("JSON array exceeds the item limit")
            stack.extend((item, depth + 1) for item in reversed(current))
            continue
        if isinstance(current, dict):
            if len(current) > MAX_CONTAINER_ITEMS:
                raise CompatibilityError("JSON object exceeds the property limit")
            for key, item in reversed(tuple(current.items())):
                if not isinstance(key, str):
                    raise CompatibilityError("JSON object key is not a string")
                if len(key.encode("utf-8")) > 1024:
                    raise CompatibilityError("JSON object key exceeds the byte limit")
                if key != unicodedata.normalize("NFC", key):
                    raise CompatibilityError("JSON object key is not NFC-normalized")
                stack.append((item, depth + 1))
            continue
        raise CompatibilityError(f"unsupported JSON value: {type(current).__name__}")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    _validate_json_tree(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CompatibilityError(f"cannot encode canonical JSON: {error}") from error
    return (encoded + "\n").encode("utf-8")


def canonical_policy_bytes(value: Any) -> bytes:
    """Canonical review-friendly encoding used only by the policy source file."""
    _validate_json_tree(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CompatibilityError(
            f"cannot encode canonical policy JSON: {error}"
        ) from error
    return (encoded + "\n").encode("utf-8")


def load_json_bytes(payload: bytes, label: str, *, canonical: bool = False) -> Any:
    if not payload or len(payload) > MAX_JSON_BYTES:
        raise CompatibilityError(f"{label} has an invalid bounded size")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise CompatibilityError(f"{label} must not contain a UTF-8 BOM")
    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_integer,
            parse_float=_parse_float,
        )
        _validate_json_tree(value)
    except CompatibilityError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise CompatibilityError(
            f"cannot parse strict JSON {label}: {error}"
        ) from error
    if canonical and canonical_json_bytes(value) != payload:
        raise CompatibilityError(f"{label} is not canonical JSON")
    return value


def _safe_relative_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or value != unicodedata.normalize("NFC", value)
        or "\\" in value
        or ":" in value
        or "//" in value
        or value.endswith("/")
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise CompatibilityError(f"unsafe repository path: {value!r}")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or any(
        part in {"", ".", ".."} for part in value.split("/")
    ):
        raise CompatibilityError(f"unsafe repository path: {value!r}")
    return value


def _read_bytes(root: Path, relative: str) -> bytes:
    relative = _safe_relative_path(relative)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise CompatibilityError(f"cannot resolve repository root: {error}") from error
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors: list[int] = []
    try:
        root_fd = os.open("/", directory_flags)
        descriptors.append(root_fd)
        for part in resolved_root.parts[1:]:
            next_fd = os.open(part, directory_flags, dir_fd=root_fd)
            descriptors.append(next_fd)
            root_fd = next_fd
        root_metadata = os.fstat(root_fd)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise CompatibilityError("repository root descriptor is not a directory")

        current_fd = root_fd
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            descriptors.append(next_fd)
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                raise CompatibilityError(
                    f"authority parent is not a real directory: {relative}"
                )
            current_fd = next_fd

        file_fd = os.open(parts[-1], file_flags, dir_fd=current_fd)
        descriptors.append(file_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise CompatibilityError(f"authority must be a regular file: {relative}")
        if before.st_nlink != 1:
            raise CompatibilityError(f"authority must not be hard-linked: {relative}")
        if before.st_size < 1 or before.st_size > MAX_TEXT_BYTES:
            raise CompatibilityError(
                f"authority has an invalid bounded size: {relative}"
            )

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(64 * 1024, MAX_TEXT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > before.st_size or total > MAX_TEXT_BYTES:
                raise CompatibilityError(
                    f"authority changed size while being read: {relative}"
                )
        payload = b"".join(chunks)
        after = os.fstat(file_fd)
    except OSError as error:
        raise CompatibilityError(
            f"cannot read authority {relative}: {error}"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(payload) != before.st_size:
        raise CompatibilityError(f"authority changed while being read: {relative}")
    return payload


def _read_text(root: Path, relative: str) -> str:
    payload = _read_bytes(root, relative)
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise CompatibilityError(f"authority is not UTF-8: {relative}") from error
    if text.startswith("\ufeff") or text != unicodedata.normalize("NFC", text):
        raise CompatibilityError(
            f"authority text is not canonical UTF-8/NFC: {relative}"
        )
    return text


def _load_json(root: Path, relative: str, *, canonical: bool = False) -> Any:
    return load_json_bytes(_read_bytes(root, relative), relative, canonical=canonical)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _expect_object(value: Any, label: str, keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CompatibilityError(f"{label} must be an object")
    expected = set(keys)
    observed = set(value)
    if observed != expected:
        unknown = sorted(observed - expected)
        missing = sorted(expected - observed)
        raise CompatibilityError(
            f"{label} fields drifted; unknown={unknown}, missing={missing}"
        )
    return value


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CompatibilityError(f"{label} must be a non-empty string")
    return value


def _expect_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise CompatibilityError(f"{label} must be a boolean")
    return value


def _expect_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CompatibilityError(f"{label} must be an integer >= {minimum}")
    return value


def _expect_string_list(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise CompatibilityError(f"{label} must be a non-empty array")
    output = [_expect_string(item, f"{label} item") for item in value]
    if output != sorted(set(output)):
        raise CompatibilityError(f"{label} must be sorted and unique")
    if len(output) > MAX_PATHS:
        raise CompatibilityError(f"{label} exceeds the path-count limit")
    return output


def _validate_binding(value: Any, label: str) -> dict[str, Any]:
    binding = _expect_object(
        value, label, ("file_count", "inventory_sha256", "total_bytes")
    )
    _expect_int(binding["file_count"], f"{label}.file_count", minimum=1)
    _expect_int(binding["total_bytes"], f"{label}.total_bytes", minimum=1)
    digest = _expect_string(binding["inventory_sha256"], f"{label}.inventory_sha256")
    if not SHA256_RE.fullmatch(digest):
        raise CompatibilityError(f"{label}.inventory_sha256 must be lowercase SHA-256")
    return binding


def _inventory(
    root: Path, paths: Sequence[str]
) -> tuple[dict[str, Any], dict[str, bytes]]:
    if not paths or len(paths) > MAX_PATHS or list(paths) != sorted(set(paths)):
        raise CompatibilityError(
            "authority inventory paths must be non-empty, sorted, and unique"
        )
    records: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    total = 0
    for relative in paths:
        _safe_relative_path(relative)
        payload = _read_bytes(root, relative)
        payloads[relative] = payload
        total += len(payload)
        records.append(
            {"bytes": len(payload), "path": relative, "sha256": _sha256(payload)}
        )
    return (
        {
            "file_count": len(records),
            "inventory_sha256": _sha256(canonical_json_bytes(records)),
            "total_bytes": total,
        },
        payloads,
    )


RULES: dict[str, tuple[tuple[str, ...], tuple[str, ...], str, str]] = {
    "public_schemas": (
        (
            "add-versioned-schema-family",
            "broaden-reader-with-baseline-writer-emission",
            "optional-property-with-negotiated-writer-emission",
        ),
        (
            "add-required-property",
            "narrow-existing-reader-domain",
            "remove-or-rename-existing-schema-family",
            "unsupported-schema-keyword-change",
        ),
        "required",
        "baseline-emission-or-explicit-negotiation",
    ),
    "operations": (
        ("add-uniquely-bound-operation",),
        (
            "change-existing-auth-or-mutation-contract",
            "change-existing-operation-identity-or-route",
            "change-existing-stream-kind",
            "remove-existing-operation",
        ),
        "required",
        "new-operation-use-requires-capability-negotiation",
    ),
    "interface_projections": (
        ("add-operation-backed-interface-mapping",),
        (
            "add-unimplemented-surface-route",
            "change-or-remove-existing-interface-mapping",
            "expose-unknown-or-semantically-mismatched-operation",
        ),
        "required",
        "new-interface-exposure-requires-client-capability-negotiation",
    ),
    "errors": (
        ("add-unique-error-code-and-name",),
        (
            "change-existing-code-name-transport-retry-or-disclosure",
            "remove-existing-error",
            "reuse-code-or-name",
        ),
        "required",
        "new-error-emission-requires-negotiation-or-unknown-error-fallback",
    ),
    "payloads": (
        ("add-payload-contract-for-new-operation",),
        (
            "change-existing-envelope-field",
            "change-existing-operation-payload-bound-or-type",
            "remove-existing-payload-contract",
        ),
        "required",
        "new-payload-use-requires-operation-negotiation",
    ),
    "cursor_stream": (
        ("add-independent-versioned-cursor-or-stream",),
        (
            "change-existing-cursor-codec-or-scope",
            "change-existing-resume-or-ordering-semantics",
            "change-existing-stream-kind-or-event-contract",
        ),
        "required",
        "new-state-emission-requires-version-or-capability-negotiation",
    ),
    "extensions": (
        (
            "add-versioned-abi-world",
            "add-versioned-extension-record",
            "broaden-manifest-reader-with-negotiated-emission",
        ),
        (
            "change-existing-wit-world",
            "narrow-existing-extension-reader-domain",
            "remove-existing-abi-or-record",
        ),
        "required",
        "new-abi-or-field-emission-requires-range-negotiation",
    ),
    "claude_plugin": (
        ("add-platform", "widen-tested-version-window"),
        (
            "change-context-abi-or-record-schema",
            "narrow-tested-version-window",
            "remove-platform",
        ),
        "required",
        "candidate-must-select-version-platform-intersection",
    ),
    "stored_records": (
        (
            "add-versioned-record-envelope-with-retained-reader",
            "append-versioned-migration-after-mixed-version-review",
        ),
        (
            "change-or-remove-applied-migration",
            "change-unversioned-record-codec",
            "drop-retained-record-reader",
            "reuse-migration-sequence-or-name",
        ),
        "retained-record-fixtures-required",
        "mixed-version-writer-safety-required",
    ),
}


DOMAIN_KEYS: dict[str, tuple[str, ...]] = {
    "public_schemas": ("binding", "manifest_path", "path_prefix", "rules"),
    "operations": (
        "binding",
        "operation_count",
        "path",
        "rules",
        "service_count",
    ),
    "interface_projections": (
        "binding",
        "cli_mapping_count",
        "mcp_mapping_count",
        "paths",
        "rules",
        "source_path",
    ),
    "errors": ("binding", "error_count", "paths", "rules"),
    "payloads": (
        "binding",
        "envelope_field_count",
        "operation_count",
        "paths",
        "payload_type_count",
        "rules",
    ),
    "cursor_stream": (
        "binding",
        "cursor_wire_version",
        "paths",
        "rules",
        "stream_operations",
    ),
    "extensions": (
        "abi_package",
        "binding",
        "manifest_schema",
        "paths",
        "rules",
    ),
    "claude_plugin": ("binding", "path", "rules"),
    "stored_records": (
        "binding",
        "codec_paths",
        "migration_paths",
        "postgres_migration_count",
        "rules",
        "sqlite_migration_count",
    ),
}


def _validate_rules(value: Any, domain: str) -> dict[str, Any]:
    rules = _expect_object(
        value,
        f"domains.{domain}.rules",
        (
            "additive_minor",
            "baseline_reader_of_candidate_writer",
            "breaking_major",
            "candidate_reader_of_baseline_writer",
        ),
    )
    additive, breaking, candidate_reader, baseline_reader = RULES[domain]
    _expect_string_list(
        rules["additive_minor"], f"domains.{domain}.rules.additive_minor"
    )
    _expect_string_list(
        rules["breaking_major"], f"domains.{domain}.rules.breaking_major"
    )
    if rules["additive_minor"] != list(additive):
        raise CompatibilityError(
            f"domains.{domain}.rules additive-minor policy drifted"
        )
    if rules["breaking_major"] != list(breaking):
        raise CompatibilityError(
            f"domains.{domain}.rules breaking-major policy drifted"
        )
    if rules["candidate_reader_of_baseline_writer"] != candidate_reader:
        raise CompatibilityError(
            f"domains.{domain}.rules candidate-reader policy drifted"
        )
    if rules["baseline_reader_of_candidate_writer"] != baseline_reader:
        raise CompatibilityError(
            f"domains.{domain}.rules baseline-reader policy drifted"
        )
    return rules


def validate_policy_document(document: Any) -> dict[str, Any]:
    policy = _expect_object(
        document,
        "compatibility policy",
        (
            "$schema",
            "claim_scope",
            "directions",
            "domains",
            "policy_id",
            "policy_schema_sha256",
            "protocol_line",
            "status",
        ),
    )
    if policy["$schema"] != "compatibility-policy-v1.schema.json":
        raise CompatibilityError(
            "compatibility policy $schema is not the local v1 schema"
        )
    if policy["policy_id"] != POLICY_ID or policy["status"] != POLICY_STATUS:
        raise CompatibilityError("compatibility policy identity or status drifted")
    schema_digest = _expect_string(
        policy["policy_schema_sha256"], "policy_schema_sha256"
    )
    if not SHA256_RE.fullmatch(schema_digest):
        raise CompatibilityError("policy_schema_sha256 must be lowercase SHA-256")

    claims = _expect_object(
        policy["claim_scope"],
        "claim_scope",
        (
            "cross_platform_qualified",
            "development_source_only",
            "migration_qualified",
            "release_frozen",
        ),
    )
    if claims != {
        "cross_platform_qualified": False,
        "development_source_only": True,
        "migration_qualified": False,
        "release_frozen": False,
    }:
        raise CompatibilityError(
            "development policy must not claim release or qualification"
        )

    directions = _expect_object(
        policy["directions"],
        "directions",
        (
            "backward_reader",
            "forward_reader",
            "reader_definition",
            "writer_definition",
        ),
    )
    expected_directions = {
        "backward_reader": "candidate-reader-accepts-all-baseline-writer-output",
        "forward_reader": "baseline-reader-accepts-candidate-writer-output",
        "reader_definition": "accepted-input-language-and-observable-semantics",
        "writer_definition": "possible-output-language-not-merely-current-fixtures",
    }
    if directions != expected_directions:
        raise CompatibilityError("directional compatibility definitions drifted")

    protocol = _expect_object(
        policy["protocol_line"],
        "protocol_line",
        ("context_abi", "major", "minor", "protocol_max", "protocol_min"),
    )
    if protocol != {
        "context_abi": "cigar.context.v1",
        "major": 1,
        "minor": 0,
        "protocol_max": "1.x",
        "protocol_min": "1.0",
    }:
        raise CompatibilityError("protocol line identity drifted")

    domains = _expect_object(policy["domains"], "domains", DOMAIN_KEYS)
    for domain, keys in DOMAIN_KEYS.items():
        record = _expect_object(domains[domain], f"domains.{domain}", keys)
        _validate_binding(record["binding"], f"domains.{domain}.binding")
        _validate_rules(record["rules"], domain)

    schemas = domains["public_schemas"]
    _safe_relative_path(
        _expect_string(schemas["manifest_path"], "public schema manifest")
    )
    prefix = _expect_string(schemas["path_prefix"], "public schema prefix")
    if prefix != "schemas/":
        raise CompatibilityError("public schema prefix must be schemas/")

    operations = domains["operations"]
    _safe_relative_path(_expect_string(operations["path"], "operations path"))
    _expect_int(operations["operation_count"], "operation_count", minimum=1)
    _expect_int(operations["service_count"], "service_count", minimum=1)

    projections = domains["interface_projections"]
    projection_paths = _expect_string_list(
        projections["paths"], "interface projection paths"
    )
    for path in projection_paths:
        _safe_relative_path(path)
    projection_source = _safe_relative_path(
        _expect_string(projections["source_path"], "interface projection source path")
    )
    if projection_source not in projection_paths:
        raise CompatibilityError("interface projection source must be baseline-bound")
    _expect_int(projections["cli_mapping_count"], "CLI mapping count", minimum=1)
    _expect_int(projections["mcp_mapping_count"], "MCP mapping count", minimum=1)

    errors = domains["errors"]
    error_paths = _expect_string_list(errors["paths"], "error paths")
    for path in error_paths:
        _safe_relative_path(path)
    _expect_int(errors["error_count"], "error_count", minimum=1)

    payloads = domains["payloads"]
    payload_paths = _expect_string_list(payloads["paths"], "payload paths")
    for path in payload_paths:
        _safe_relative_path(path)
    for field in ("envelope_field_count", "operation_count", "payload_type_count"):
        _expect_int(payloads[field], field, minimum=1)

    cursor = domains["cursor_stream"]
    cursor_paths = _expect_string_list(cursor["paths"], "cursor/stream paths")
    for path in cursor_paths:
        _safe_relative_path(path)
    _expect_int(cursor["cursor_wire_version"], "cursor wire version", minimum=1)
    _expect_string_list(cursor["stream_operations"], "stream operations")

    extensions = domains["extensions"]
    extension_paths = _expect_string_list(extensions["paths"], "extension paths")
    for path in extension_paths:
        _safe_relative_path(path)
    if extensions["abi_package"] != "cigar:extension@1.0.0":
        raise CompatibilityError("extension ABI package identity drifted")
    if extensions["manifest_schema"] != "cigar.extension-manifest.v1":
        raise CompatibilityError("extension manifest schema identity drifted")

    claude = domains["claude_plugin"]
    _safe_relative_path(_expect_string(claude["path"], "Claude compatibility path"))

    stored = domains["stored_records"]
    migration_paths = _expect_string_list(stored["migration_paths"], "migration paths")
    codec_paths = _expect_string_list(stored["codec_paths"], "stored codec paths")
    for path in (*migration_paths, *codec_paths):
        _safe_relative_path(path)
    if set(migration_paths) & set(codec_paths):
        raise CompatibilityError("migration and codec paths overlap")
    _expect_int(stored["sqlite_migration_count"], "SQLite migration count", minimum=1)
    _expect_int(
        stored["postgres_migration_count"], "PostgreSQL migration count", minimum=1
    )
    return policy


def load_policy(root: Path, relative: str = POLICY_PATH) -> dict[str, Any]:
    _safe_relative_path(relative)
    payload = _read_bytes(root, relative)
    document = load_json_bytes(payload, relative)
    if canonical_policy_bytes(document) != payload:
        raise CompatibilityError(f"{relative} is not canonical policy JSON")
    return validate_policy_document(document)


def _public_schema_paths(root: Path, domain: Mapping[str, Any]) -> list[str]:
    manifest_path = domain["manifest_path"]
    manifest = _load_json(root, manifest_path)
    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("artifacts"), list
    ):
        raise CompatibilityError("generated schema manifest has no artifacts array")
    artifacts = _expect_string_list(manifest["artifacts"], "generated schema artifacts")
    paths: list[str] = []
    for artifact in artifacts:
        if artifact.startswith("-") or not artifact.startswith("json/"):
            raise CompatibilityError(f"unsafe generated schema artifact: {artifact!r}")
        path = f"{domain['path_prefix']}{artifact}"
        _safe_relative_path(path)
        paths.append(path)
    return sorted(paths)


def authority_paths(root: Path, policy: Mapping[str, Any]) -> dict[str, list[str]]:
    domains = policy["domains"]
    result = {
        "public_schemas": _public_schema_paths(root, domains["public_schemas"]),
        "operations": [domains["operations"]["path"]],
        "interface_projections": list(domains["interface_projections"]["paths"]),
        "errors": list(domains["errors"]["paths"]),
        "payloads": list(domains["payloads"]["paths"]),
        "cursor_stream": list(domains["cursor_stream"]["paths"]),
        "extensions": list(domains["extensions"]["paths"]),
        "claude_plugin": [domains["claude_plugin"]["path"]],
        "stored_records": sorted(
            [
                *domains["stored_records"]["migration_paths"],
                *domains["stored_records"]["codec_paths"],
            ]
        ),
    }
    for domain, paths in result.items():
        if paths != sorted(set(paths)):
            raise CompatibilityError(
                f"{domain} authority paths are not sorted and unique"
            )
    return result


def refresh_bindings(root: Path, policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return a reviewed-policy snapshot rebound to one source tree; never writes files."""
    refreshed = copy.deepcopy(validate_policy_document(copy.deepcopy(policy)))
    refreshed["policy_schema_sha256"] = _sha256(_read_bytes(root, POLICY_SCHEMA_PATH))
    paths = authority_paths(root, refreshed)
    for domain, domain_paths in paths.items():
        refreshed["domains"][domain]["binding"] = _inventory(root, domain_paths)[0]
    _validate_schema_inventory(root, paths["public_schemas"], "public schemas")
    _validate_extension_authorities(root, refreshed["domains"]["extensions"])

    operations = _operation_catalog(root, refreshed["domains"]["operations"])
    refreshed["domains"]["operations"]["operation_count"] = len(operations.operations)
    refreshed["domains"]["operations"]["service_count"] = operations.service_count

    projections = _interface_projection_catalog(
        root, refreshed["domains"]["interface_projections"], operations
    )
    refreshed["domains"]["interface_projections"]["cli_mapping_count"] = len(
        projections.cli
    )
    refreshed["domains"]["interface_projections"]["mcp_mapping_count"] = len(
        projections.mcp
    )

    errors = _error_catalog(root, refreshed["domains"]["errors"])
    refreshed["domains"]["errors"]["error_count"] = len(errors)

    payload = _payload_catalog(root, refreshed["domains"]["payloads"])
    refreshed["domains"]["payloads"]["operation_count"] = len(payload.operations)
    refreshed["domains"]["payloads"]["envelope_field_count"] = len(
        payload.envelope_fields
    )
    refreshed["domains"]["payloads"]["payload_type_count"] = payload.payload_type_count

    cursor = refreshed["domains"]["cursor_stream"]
    cursor["stream_operations"] = sorted(
        operation_id
        for operation_id, record in operations.operations.items()
        if record["stream_kind"] != "unary"
    )
    claude_record(root, refreshed["domains"]["claude_plugin"])
    migration_chains(root, refreshed["domains"]["stored_records"])
    return validate_policy_document(refreshed)


def validate_repository(root: Path, policy: Mapping[str, Any]) -> None:
    validate_policy_document(policy)
    schema_payload = _read_bytes(root, POLICY_SCHEMA_PATH)
    if _sha256(schema_payload) != policy["policy_schema_sha256"]:
        raise CompatibilityError("compatibility policy JSON Schema digest drifted")
    schema = load_json_bytes(schema_payload, POLICY_SCHEMA_PATH)
    if (
        not isinstance(schema, dict)
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
    ):
        raise CompatibilityError("compatibility policy JSON Schema identity drifted")
    paths = authority_paths(root, policy)
    for domain, domain_paths in paths.items():
        observed, _payloads = _inventory(root, domain_paths)
        expected = policy["domains"][domain]["binding"]
        if observed != expected:
            raise CompatibilityError(
                f"{domain} authority binding drifted: expected {expected}, observed {observed}"
            )

    operations = _operation_catalog(root, policy["domains"]["operations"])
    operation_domain = policy["domains"]["operations"]
    if len(operations.operations) != operation_domain["operation_count"]:
        raise CompatibilityError("operation authority count drifted")
    if operations.service_count != operation_domain["service_count"]:
        raise CompatibilityError("service authority count drifted")

    projections = _interface_projection_catalog(
        root, policy["domains"]["interface_projections"], operations
    )
    projection_domain = policy["domains"]["interface_projections"]
    if len(projections.cli) != projection_domain["cli_mapping_count"]:
        raise CompatibilityError("CLI interface projection count drifted")
    if len(projections.mcp) != projection_domain["mcp_mapping_count"]:
        raise CompatibilityError("MCP interface projection count drifted")

    errors = _error_catalog(root, policy["domains"]["errors"])
    if len(errors) != policy["domains"]["errors"]["error_count"]:
        raise CompatibilityError("error authority count drifted")

    payloads = _payload_catalog(root, policy["domains"]["payloads"])
    payload_domain = policy["domains"]["payloads"]
    if len(payloads.operations) != payload_domain["operation_count"]:
        raise CompatibilityError("payload operation count drifted")
    if len(payloads.envelope_fields) != payload_domain["envelope_field_count"]:
        raise CompatibilityError("payload envelope count drifted")
    if payloads.payload_type_count != payload_domain["payload_type_count"]:
        raise CompatibilityError("payload type count drifted")
    if set(payloads.operations) != set(operations.operations):
        raise CompatibilityError(
            "operation and payload registries do not have exact parity"
        )

    stream_operations = sorted(
        operation_id
        for operation_id, record in operations.operations.items()
        if record["stream_kind"] != "unary"
    )
    if stream_operations != policy["domains"]["cursor_stream"]["stream_operations"]:
        raise CompatibilityError("stream-operation inventory drifted")

    _validate_schema_inventory(root, paths["public_schemas"], "public schemas")
    _validate_extension_authorities(root, policy["domains"]["extensions"])
    claude_record(root, policy["domains"]["claude_plugin"])
    migration_chains(root, policy["domains"]["stored_records"])


@dataclass(frozen=True)
class OperationCatalog:
    service_count: int
    operations: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class InterfaceProjectionCatalog:
    cli: dict[str, dict[str, Any]]
    mcp: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class PayloadCatalog:
    envelope_fields: dict[str, dict[str, Any]]
    operations: dict[str, dict[str, Any]]
    payload_type_count: int


def _interface_projection_catalog(
    root: Path,
    domain: Mapping[str, Any],
    operations: OperationCatalog,
) -> InterfaceProjectionCatalog:
    value = _load_json(root, domain["source_path"])
    catalog = _expect_object(
        value,
        "interface projection catalog",
        ("cli", "mcp", "schema_version", "status"),
    )
    if catalog["schema_version"] != 1 or catalog["status"] != "development-closed":
        raise CompatibilityError("interface projection identity drifted")

    def surface(name: str) -> tuple[int, list[Any]]:
        record = _expect_object(
            catalog[name], f"{name} projection", ("mapping_count", "mappings")
        )
        count = _expect_int(record["mapping_count"], f"{name} mapping count", minimum=1)
        if not isinstance(record["mappings"], list) or len(record["mappings"]) != count:
            raise CompatibilityError(f"{name} projection mapping count drifted")
        return count, record["mappings"]

    _cli_count, cli_rows = surface("cli")
    cli: dict[str, dict[str, Any]] = {}
    canonical_by_operation: dict[str, str] = {}
    for index, raw in enumerate(cli_rows):
        if not isinstance(raw, dict):
            raise CompatibilityError(f"CLI projection {index} is not an object")
        keys = tuple(sorted(raw))
        allowed = (
            ("exposed_name", "operation_id", "operation_kind"),
            ("alias_of", "exposed_name", "operation_id", "operation_kind"),
        )
        if keys not in allowed:
            raise CompatibilityError(f"CLI projection {index} fields drifted")
        exposed = _expect_string(raw["exposed_name"], "CLI exposed name")
        operation_id = _expect_string(raw["operation_id"], "CLI operation ID")
        kind = _expect_string(raw["operation_kind"], "CLI operation kind")
        alias_of = raw.get("alias_of")
        if not CLI_PROJECTION_RE.fullmatch(exposed) or exposed in cli:
            raise CompatibilityError(f"invalid or duplicate CLI projection: {exposed}")
        operation = operations.operations.get(operation_id)
        expected_kind = "mutation" if operation and operation["mutation"] else "read"
        if operation is None or kind != expected_kind:
            raise CompatibilityError(f"CLI projection operation mismatch: {exposed}")
        if alias_of is not None:
            alias_of = _expect_string(alias_of, "CLI alias target")
        elif operation_id in canonical_by_operation:
            raise CompatibilityError(
                f"duplicate canonical CLI operation: {operation_id}"
            )
        else:
            canonical_by_operation[operation_id] = exposed
        cli[exposed] = {
            "alias_of": alias_of,
            "operation_id": operation_id,
            "operation_kind": kind,
        }
    for exposed, mapping in cli.items():
        alias_of = mapping["alias_of"]
        if alias_of is None:
            continue
        canonical = cli.get(alias_of)
        if (
            alias_of == exposed
            or canonical is None
            or canonical["alias_of"] is not None
            or canonical["operation_id"] != mapping["operation_id"]
            or canonical_by_operation.get(mapping["operation_id"]) != alias_of
        ):
            raise CompatibilityError(f"invalid CLI projection alias: {exposed}")

    _mcp_count, mcp_rows = surface("mcp")
    mcp: dict[str, dict[str, Any]] = {}
    mcp_operations: set[str] = set()
    lanes = {
        "catalog_read",
        "context_read",
        "coordination_write",
        "effect_commit",
        "effect_prepare",
        "effect_read",
    }
    for index, raw in enumerate(mcp_rows):
        mapping = _expect_object(
            raw,
            f"MCP projection {index}",
            ("authority_lane", "exposed_name", "operation_id", "operation_kind"),
        )
        exposed = _expect_string(mapping["exposed_name"], "MCP exposed name")
        operation_id = _expect_string(mapping["operation_id"], "MCP operation ID")
        kind = _expect_string(mapping["operation_kind"], "MCP operation kind")
        lane = _expect_string(mapping["authority_lane"], "MCP authority lane")
        operation = operations.operations.get(operation_id)
        expected_kind = "mutation" if operation and operation["mutation"] else "read"
        if (
            not MCP_PROJECTION_RE.fullmatch(exposed)
            or exposed in mcp
            or operation_id in mcp_operations
            or operation is None
            or kind != expected_kind
            or lane not in lanes
        ):
            raise CompatibilityError(f"invalid or duplicate MCP projection: {exposed}")
        mcp_operations.add(operation_id)
        mcp[exposed] = {
            "authority_lane": lane,
            "operation_id": operation_id,
            "operation_kind": kind,
        }
    return InterfaceProjectionCatalog(cli=cli, mcp=mcp)


def _operation_catalog(root: Path, domain: Mapping[str, Any]) -> OperationCatalog:
    value = _load_json(root, domain["path"])
    catalog = _expect_object(
        value,
        "operation catalog",
        (
            "http_base",
            "operation_count",
            "package",
            "schema_version",
            "services",
            "status",
        ),
    )
    if catalog["schema_version"] != 1 or catalog["package"] != "cigar.v1":
        raise CompatibilityError("operation catalog protocol identity drifted")
    if not isinstance(catalog["services"], list) or not catalog["services"]:
        raise CompatibilityError("operation catalog services must be non-empty")
    operations: dict[str, dict[str, Any]] = {}
    rpc_names: set[str] = set()
    routes: set[tuple[str, str]] = set()
    service_names: set[str] = set()
    for service_index, raw_service in enumerate(catalog["services"]):
        service = _expect_object(
            raw_service,
            f"operation service {service_index}",
            ("name", "operations"),
        )
        service_name = _expect_string(service["name"], "service name")
        if service_name in service_names:
            raise CompatibilityError(f"duplicate operation service: {service_name}")
        service_names.add(service_name)
        if not isinstance(service["operations"], list) or not service["operations"]:
            raise CompatibilityError(f"service has no operations: {service_name}")
        for raw_operation in service["operations"]:
            operation = _expect_object(
                raw_operation,
                f"operation in {service_name}",
                (
                    "auth_class",
                    "http_method",
                    "http_path",
                    "idempotency_requirement",
                    "mutation",
                    "operation_id",
                    "revision_requirement",
                    "rpc",
                    "stream_kind",
                ),
            )
            operation_id = _expect_string(operation["operation_id"], "operation ID")
            rpc = _expect_string(operation["rpc"], "RPC name")
            method = _expect_string(operation["http_method"], "HTTP method")
            path = _expect_string(operation["http_path"], "HTTP path")
            if (
                operation_id in operations
                or rpc in rpc_names
                or (method, path) in routes
            ):
                raise CompatibilityError(
                    f"duplicate operation identity: {operation_id}"
                )
            if method not in {
                "DELETE",
                "GET",
                "PATCH",
                "POST",
                "PUT",
            } or not path.startswith("/"):
                raise CompatibilityError(f"invalid operation route: {operation_id}")
            if operation["stream_kind"] not in {"unary", "server_stream"}:
                raise CompatibilityError(f"invalid stream kind: {operation_id}")
            if not isinstance(operation["mutation"], bool):
                raise CompatibilityError(
                    f"operation mutation flag is not boolean: {operation_id}"
                )
            enriched = dict(operation)
            enriched["service"] = service_name
            operations[operation_id] = enriched
            rpc_names.add(rpc)
            routes.add((method, path))
    if catalog["operation_count"] != len(operations):
        raise CompatibilityError("declared operation count does not match catalog")
    return OperationCatalog(len(service_names), operations)


def _payload_fields(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CompatibilityError(f"{label} must be an array")
    fields: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw in enumerate(value):
        field = _expect_object(raw, f"{label}[{index}]", ("bound", "name", "source"))
        name = _expect_string(field["name"], f"{label} field name")
        _expect_string(field["bound"], f"{label}.{name}.bound")
        _expect_string(field["source"], f"{label}.{name}.source")
        if name in names:
            raise CompatibilityError(f"duplicate payload field: {label}.{name}")
        names.add(name)
        fields.append(dict(field))
    return fields


def _payload_catalog(root: Path, domain: Mapping[str, Any]) -> PayloadCatalog:
    registry_path = next(
        path for path in domain["paths"] if path.endswith("operation-payloads-v1.json")
    )
    types_path = next(
        path
        for path in domain["paths"]
        if path.endswith("api-payload-types-v1.schema.json")
    )
    value = _load_json(root, registry_path)
    registry = _expect_object(
        value,
        "payload catalog",
        (
            "envelope_fields",
            "operation_count",
            "operations",
            "schema_version",
            "status",
        ),
    )
    if registry["schema_version"] != 1:
        raise CompatibilityError("payload catalog schema version drifted")
    envelope: dict[str, dict[str, Any]] = {}
    for field in _payload_fields(registry["envelope_fields"], "envelope_fields"):
        envelope[field["name"]] = field
    if not isinstance(registry["operations"], list):
        raise CompatibilityError("payload operations must be an array")
    operations: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(registry["operations"]):
        operation = _expect_object(
            raw,
            f"payload operation {index}",
            (
                "event_fields",
                "event_max_bytes",
                "event_schema",
                "operation_id",
                "request_fields",
                "request_max_bytes",
                "request_schema",
                "response_fields",
                "response_max_bytes",
                "response_schema",
            ),
        )
        operation_id = _expect_string(operation["operation_id"], "payload operation ID")
        if operation_id in operations:
            raise CompatibilityError(f"duplicate payload operation ID: {operation_id}")
        normalized = dict(operation)
        for prefix in ("request", "response", "event"):
            maximum = operation[f"{prefix}_max_bytes"]
            _expect_int(maximum, f"{operation_id}.{prefix}_max_bytes")
            schema = operation[f"{prefix}_schema"]
            if prefix == "event" and schema is None:
                if maximum != 0 or operation["event_fields"] != []:
                    raise CompatibilityError(
                        f"null event schema has event data: {operation_id}"
                    )
            else:
                _expect_string(schema, f"{operation_id}.{prefix}_schema")
            normalized[f"{prefix}_fields"] = _payload_fields(
                operation[f"{prefix}_fields"], f"{operation_id}.{prefix}_fields"
            )
        operations[operation_id] = normalized
    if registry["operation_count"] != len(operations):
        raise CompatibilityError(
            "declared payload operation count does not match catalog"
        )

    types = _load_json(root, types_path)
    if not isinstance(types, dict) or types.get("operation_count") != len(operations):
        raise CompatibilityError("payload type schema operation count drifted")
    type_definitions = types.get("types")
    if not isinstance(type_definitions, dict) or not type_definitions:
        raise CompatibilityError("payload type schema has no types object")
    if types.get("type_count") != len(type_definitions):
        raise CompatibilityError("payload type schema declared count drifted")
    for name in type_definitions:
        _expect_string(name, "payload type name")
        _lint_schema_node(type_definitions[name], f"payload type {name}")
    return PayloadCatalog(envelope, operations, len(type_definitions))


def _error_catalog(root: Path, domain: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    path = next(
        path for path in domain["paths"] if path.endswith("error-registry-v1.json")
    )
    value = _load_json(root, path)
    registry = _expect_object(
        value,
        "error registry",
        ("errors", "generator", "schema_version", "status"),
    )
    if registry["schema_version"] != 1 or not isinstance(registry["errors"], list):
        raise CompatibilityError("error registry identity drifted")
    errors: dict[str, dict[str, Any]] = {}
    codes: set[int] = set()
    for index, raw in enumerate(registry["errors"]):
        error = _expect_object(
            raw,
            f"error registry item {index}",
            (
                "code",
                "disclose_identity",
                "grpc",
                "http",
                "message",
                "name",
                "remediation",
                "retry",
            ),
        )
        name = _expect_string(error["name"], "error name")
        code = _expect_int(error["code"], f"{name}.code", minimum=1)
        _expect_int(error["http"], f"{name}.http", minimum=100)
        for field in ("grpc", "message", "remediation", "retry"):
            _expect_string(error[field], f"{name}.{field}")
        _expect_bool(error["disclose_identity"], f"{name}.disclose_identity")
        if name in errors or code in codes:
            raise CompatibilityError(f"duplicate error code or name: {name}/{code}")
        errors[name] = dict(error)
        codes.add(code)
    source_path = next(
        path for path in domain["paths"] if path.endswith("catalog.yaml")
    )
    source = _source_error_catalog(root, source_path)
    if source != errors:
        raise CompatibilityError("error source catalog and generated registry differ")
    proto_path = next(
        path for path in domain["paths"] if path.endswith("error_codes.proto")
    )
    proto_text = _read_text(root, proto_path)
    proto_errors = {
        name: int(code)
        for name, code in re.findall(
            r"^  ERROR_CODE_([A-Z][A-Z0-9_]*) = ([0-9]+);$", proto_text, re.MULTILINE
        )
        if name != "UNSPECIFIED"
    }
    if proto_errors != {name: record["code"] for name, record in errors.items()}:
        raise CompatibilityError(
            "error source catalog and generated Protobuf enum differ"
        )
    rust_path = next(
        path for path in domain["paths"] if path.endswith("error_registry.rs")
    )
    rust_text = _read_text(root, rust_path)
    rust_symbols = re.findall(
        r'^    symbol: "([A-Z][A-Z0-9_]*)",$', rust_text, re.MULTILINE
    )
    if len(rust_symbols) != len(errors) or set(rust_symbols) != set(errors):
        raise CompatibilityError(
            "error source catalog and generated Rust registry differ"
        )
    return errors


ERROR_SOURCE_RE = re.compile(
    r"^  - \{ code: (?P<code>[1-9][0-9]*), name: (?P<name>[A-Z][A-Z0-9_]*), "
    r"http: (?P<http>[1-5][0-9]{2}), grpc: (?P<grpc>[A-Z][A-Z0-9_]*), "
    r'retry: (?P<retry>[a-z][a-z_]*), message: "(?P<message>[^"\\]*)", '
    r'remediation: "(?P<remediation>[^"\\]*)", disclose_identity: '
    r"(?P<disclose>true|false) \}$"
)


def _source_error_catalog(root: Path, path: str) -> dict[str, dict[str, Any]]:
    text = _read_text(root, path)
    lines = text.splitlines()
    if lines and lines[-1] == "":
        lines.pop()
    if lines[:3] != [
        "schema_version: 1",
        "status: v1-codes-frozen-mappings-await-wp02-generation",
        "errors:",
    ]:
        raise CompatibilityError("error source catalog header drifted")
    output: dict[str, dict[str, Any]] = {}
    codes: set[int] = set()
    for line in lines[3:]:
        match = ERROR_SOURCE_RE.fullmatch(line)
        if match is None:
            raise CompatibilityError("error source catalog contains noncanonical YAML")
        fields = match.groupdict()
        name = fields["name"]
        code = int(fields["code"])
        if name in output or code in codes:
            raise CompatibilityError(
                f"error source catalog reuses code or name: {name}/{code}"
            )
        output[name] = {
            "code": code,
            "disclose_identity": fields["disclose"] == "true",
            "grpc": fields["grpc"],
            "http": int(fields["http"]),
            "message": fields["message"],
            "name": name,
            "remediation": fields["remediation"],
            "retry": fields["retry"],
        }
        codes.add(code)
    if not output:
        raise CompatibilityError("error source catalog is empty")
    return output


def _validate_json_schema_document(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise CompatibilityError(f"{label} must be a non-empty JSON Schema object")
    draft = value.get("$schema")
    if draft != "https://json-schema.org/draft/2020-12/schema":
        raise CompatibilityError(f"{label} must declare JSON Schema draft 2020-12")
    _lint_schema_node(value, label)
    return value


def _lint_schema_node(value: Any, label: str) -> None:
    if isinstance(value, bool):
        return
    if not isinstance(value, dict):
        raise CompatibilityError(f"{label} contains a non-object schema node")
    if "$ref" in value:
        reference = value["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise CompatibilityError(f"{label} contains a nonlocal or invalid $ref")
    if "type" in value:
        types = value["type"] if isinstance(value["type"], list) else [value["type"]]
        allowed = {"array", "boolean", "integer", "null", "number", "object", "string"}
        if (
            not types
            or not all(isinstance(item, str) and item in allowed for item in types)
            or len(types) != len(set(types))
        ):
            raise CompatibilityError(f"{label} contains an invalid type declaration")
    if "required" in value:
        required = value["required"]
        if (
            not isinstance(required, list)
            or not all(isinstance(item, str) and item for item in required)
            or len(required) != len(set(required))
        ):
            raise CompatibilityError(f"{label} contains an invalid required array")
    if "enum" in value:
        enum = value["enum"]
        if not isinstance(enum, list) or not enum:
            raise CompatibilityError(f"{label} contains an invalid enum")
        encoded = [canonical_json_bytes(item) for item in enum]
        if len(encoded) != len(set(encoded)):
            raise CompatibilityError(f"{label} contains duplicate enum values")
    for keyword in UPPER_BOUNDS | LOWER_BOUNDS:
        if keyword in value and (
            isinstance(value[keyword], bool)
            or not isinstance(value[keyword], (int, float))
        ):
            raise CompatibilityError(f"{label}/{keyword} is not numeric")
    for keyword in ("properties", "patternProperties", "$defs", "dependentSchemas"):
        if keyword not in value:
            continue
        mapping = value[keyword]
        if not isinstance(mapping, dict):
            raise CompatibilityError(f"{label}/{keyword} is not an object")
        for name, schema in mapping.items():
            _lint_schema_node(schema, f"{label}/{keyword}/{name}")
    for keyword in (
        "additionalProperties",
        "items",
        "contains",
        "not",
        "if",
        "then",
        "else",
    ):
        if keyword in value:
            _lint_schema_node(value[keyword], f"{label}/{keyword}")
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if keyword not in value:
            continue
        branches = value[keyword]
        if not isinstance(branches, list) or not branches:
            raise CompatibilityError(f"{label}/{keyword} is not a non-empty array")
        for index, schema in enumerate(branches):
            _lint_schema_node(schema, f"{label}/{keyword}/{index}")
    for keyword in ("pattern", "format", "contentEncoding"):
        if keyword in value and not isinstance(value[keyword], str):
            raise CompatibilityError(f"{label}/{keyword} is not a string")
    if "uniqueItems" in value and not isinstance(value["uniqueItems"], bool):
        raise CompatibilityError(f"{label}/uniqueItems is not a boolean")


def _validate_schema_inventory(root: Path, paths: Sequence[str], label: str) -> None:
    for path in paths:
        _validate_json_schema_document(_load_json(root, path), f"{label} {path}")


def _validate_extension_authorities(root: Path, domain: Mapping[str, Any]) -> None:
    wit_paths = [path for path in domain["paths"] if path.endswith(".wit")]
    schema_paths = [path for path in domain["paths"] if path.endswith(".schema.json")]
    if not wit_paths or not schema_paths:
        raise CompatibilityError(
            "extension authority set must contain WIT and JSON Schema files"
        )
    for path in wit_paths:
        text = _read_text(root, path)
        package_line = next(
            (line.strip() for line in text.splitlines() if line.startswith("package ")),
            "",
        )
        if package_line != f"package {domain['abi_package']};":
            raise CompatibilityError(f"extension WIT package drifted: {path}")
    _validate_schema_inventory(root, schema_paths, "extension schemas")
    manifest_path = next(path for path in schema_paths if "extension-manifest" in path)
    manifest = _load_json(root, manifest_path)
    schema_property = manifest.get("properties", {}).get("schema_version", {})
    pattern = schema_property.get("pattern")
    if not isinstance(pattern, str) or "\\.v" not in pattern:
        raise CompatibilityError("extension manifest schema-version contract drifted")


def _parse_semver(value: Any, label: str) -> tuple[int, int, int]:
    text = _expect_string(value, label)
    match = SEMVER_RE.fullmatch(text)
    if match is None:
        raise CompatibilityError(f"{label} must be canonical three-component SemVer")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def claude_record(root: Path, domain: Mapping[str, Any]) -> dict[str, Any]:
    value = _load_json(root, domain["path"])
    record = _expect_object(
        value,
        "Claude compatibility record",
        (
            "claude_code",
            "context_abi",
            "platforms",
            "public_surfaces_only",
            "schema_version",
        ),
    )
    if record["schema_version"] != "cigar.claude-code-compatibility.v1":
        raise CompatibilityError("Claude compatibility schema identity drifted")
    if (
        record["context_abi"] != "cigar.context.v1"
        or record["public_surfaces_only"] is not True
    ):
        raise CompatibilityError("Claude compatibility record overclaims its surface")
    versions = _expect_object(
        record["claude_code"],
        "Claude Code version window",
        ("maximum_exclusive", "minimum_inclusive"),
    )
    minimum = _parse_semver(versions["minimum_inclusive"], "Claude minimum version")
    maximum = _parse_semver(versions["maximum_exclusive"], "Claude maximum version")
    if minimum >= maximum:
        raise CompatibilityError("Claude compatibility version window is empty")
    platforms = _expect_string_list(record["platforms"], "Claude platforms")
    for platform in platforms:
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", platform) is None:
            raise CompatibilityError(f"noncanonical Claude platform: {platform}")
    return record


@dataclass(frozen=True)
class Migration:
    backend: str
    sequence: int
    name: str
    minimum_major: int
    maximum_major: int
    path: str
    payload: bytes


def _parse_migration(root: Path, path: str) -> Migration:
    filename = PurePosixPath(path).name
    match = MIGRATION_RE.fullmatch(filename)
    if match is None:
        raise CompatibilityError(f"noncanonical migration filename: {path}")
    sequence = int(match.group("sequence"))
    name = match.group("name")
    text = _read_text(root, path)
    lines = text.splitlines()
    backend = (
        "sqlite" if "/sqlite/" in path else "postgres" if "/postgres/" in path else ""
    )
    label = (
        "SQLite"
        if backend == "sqlite"
        else "PostgreSQL"
        if backend == "postgres"
        else ""
    )
    if not label or not lines or not lines[0].startswith(f"-- CIGAR {label} schema v"):
        raise CompatibilityError(f"migration backend/header drifted: {path}")
    expected_identity = f"-- sequence/name: {sequence} / {name}"
    if expected_identity not in lines[:8]:
        raise CompatibilityError(f"migration sequence/name header drifted: {path}")
    compatibility_line = next(
        (
            line
            for line in lines[:12]
            if line.startswith("-- application compatibility: ")
        ),
        "",
    )
    compatibility = re.fullmatch(
        r"-- application compatibility: major ([1-9][0-9]*) through major ([1-9][0-9]*)",
        compatibility_line,
    )
    if compatibility is None:
        raise CompatibilityError(f"migration compatibility header is invalid: {path}")
    required_headers = (
        "-- classification/lock:",
        "-- data backfill:",
        "-- verification:",
        "-- rollback or restore:",
    )
    for header in required_headers:
        if not any(line.startswith(header) and line != header for line in lines[:16]):
            raise CompatibilityError(
                f"migration required header is missing: {path}: {header}"
            )
    minimum = int(compatibility.group(1))
    maximum = int(compatibility.group(2))
    if minimum > maximum:
        raise CompatibilityError(f"migration compatibility range is reversed: {path}")
    return Migration(
        backend, sequence, name, minimum, maximum, path, text.encode("utf-8")
    )


def migration_chains(
    root: Path, domain: Mapping[str, Any]
) -> dict[str, list[Migration]]:
    migrations = [_parse_migration(root, path) for path in domain["migration_paths"]]
    # The repository mirror and the crate-consumed copies must be byte-identical.
    by_suffix: dict[tuple[str, str], list[Migration]] = {}
    for migration in migrations:
        by_suffix.setdefault(
            (migration.backend, PurePosixPath(migration.path).name), []
        ).append(migration)
    for key, copies in by_suffix.items():
        if len(copies) != 2 or copies[0].payload != copies[1].payload:
            raise CompatibilityError(f"migration mirror drifted: {key[0]}/{key[1]}")
    chains: dict[str, list[Migration]] = {"sqlite": [], "postgres": []}
    for copies in by_suffix.values():
        canonical = next(
            (
                migration
                for migration in copies
                if migration.path.startswith("migrations/")
            ),
            copies[0],
        )
        chains[canonical.backend].append(canonical)
    for backend, chain in chains.items():
        chain.sort(key=lambda item: item.sequence)
        expected = list(range(1, len(chain) + 1))
        if [item.sequence for item in chain] != expected:
            raise CompatibilityError(
                f"{backend} migration sequences are not contiguous"
            )
        if len({item.name for item in chain}) != len(chain):
            raise CompatibilityError(f"{backend} migration names are not unique")
        count_field = f"{backend}_migration_count"
        if len(chain) != domain[count_field]:
            raise CompatibilityError(f"{backend} migration policy count drifted")
    return chains


@dataclass(frozen=True, order=True)
class Issue:
    domain: str
    severity: str
    code: str
    backward_reader: str
    forward_reader: str
    detail: str

    def as_json(self) -> dict[str, str]:
        return {
            "backward_reader": self.backward_reader,
            "code": self.code,
            "detail": self.detail,
            "domain": self.domain,
            "forward_reader": self.forward_reader,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class Comparison:
    classification: str
    backward_reader: str
    forward_reader: str
    issues: tuple[Issue, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "backward_reader": self.backward_reader,
            "classification": self.classification,
            "forward_reader": self.forward_reader,
            "issues": [issue.as_json() for issue in self.issues],
            "policy_id": POLICY_ID,
        }


class _Collector:
    def __init__(self) -> None:
        self._issues: set[Issue] = set()

    def minor(self, domain: str, code: str, detail: str) -> None:
        self._issues.add(
            Issue(
                domain,
                "additive-minor",
                code,
                "compatible",
                "conditional",
                detail,
            )
        )

    def major(self, domain: str, code: str, detail: str) -> None:
        self._issues.add(
            Issue(
                domain,
                "breaking-major",
                code,
                "incompatible",
                "incompatible",
                detail,
            )
        )

    def manual(self, domain: str, code: str, detail: str) -> None:
        self._issues.add(
            Issue(
                domain,
                "manual-review",
                code,
                "unproven",
                "unproven",
                detail,
            )
        )

    def finish(self) -> Comparison:
        issues = tuple(sorted(self._issues))
        severities = {issue.severity for issue in issues}
        if "breaking-major" in severities:
            classification = "breaking-major"
        elif "manual-review" in severities:
            classification = "manual-review"
        elif "additive-minor" in severities:
            classification = "additive-minor"
        else:
            classification = "exact"
        if any(issue.backward_reader == "incompatible" for issue in issues):
            backward = "incompatible"
        elif any(issue.backward_reader == "unproven" for issue in issues):
            backward = "unproven"
        else:
            backward = "compatible"
        if any(issue.forward_reader == "incompatible" for issue in issues):
            forward = "incompatible"
        elif any(issue.forward_reader == "unproven" for issue in issues):
            forward = "unproven"
        elif any(issue.forward_reader == "conditional" for issue in issues):
            forward = "conditional"
        else:
            forward = "compatible"
        return Comparison(classification, backward, forward, issues)


ANNOTATION_KEYWORDS = {
    "$comment",
    "default",
    "deprecated",
    "description",
    "examples",
    "readOnly",
    "title",
    "writeOnly",
}
UPPER_BOUNDS = {"exclusiveMaximum", "maxItems", "maxLength", "maxProperties", "maximum"}
LOWER_BOUNDS = {"exclusiveMinimum", "minItems", "minLength", "minProperties", "minimum"}


def _canonical_semantic(value: Any) -> bytes:
    if isinstance(value, dict):
        value = {
            key: item for key, item in value.items() if key not in ANNOTATION_KEYWORDS
        }
    return canonical_json_bytes(value)


def _type_set(value: Any) -> set[str] | None:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return None


def _compare_schema_node(
    baseline: Any,
    candidate: Any,
    collector: _Collector,
    domain: str,
    location: str,
) -> None:
    if _canonical_semantic(baseline) == _canonical_semantic(candidate):
        return
    if isinstance(baseline, bool) or isinstance(candidate, bool):
        if baseline is False and candidate is True:
            collector.minor(
                domain,
                "schema-reader-broadened",
                f"{location}: false schema became true",
            )
        else:
            collector.major(
                domain,
                "schema-boolean-changed",
                f"{location}: boolean schema changed incompatibly",
            )
        return
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        collector.major(
            domain, "schema-shape-changed", f"{location}: schema node shape changed"
        )
        return

    handled = set(ANNOTATION_KEYWORDS)
    baseline_type = _type_set(baseline.get("type")) if "type" in baseline else None
    candidate_type = _type_set(candidate.get("type")) if "type" in candidate else None
    if baseline_type != candidate_type:
        if (
            baseline_type is not None
            and candidate_type is not None
            and baseline_type <= candidate_type
        ):
            collector.minor(
                domain,
                "schema-type-domain-broadened",
                f"{location}: accepted type set broadened",
            )
        elif baseline_type is not None and "type" not in candidate:
            collector.minor(
                domain,
                "schema-type-constraint-removed",
                f"{location}: type constraint removed",
            )
        else:
            collector.major(
                domain,
                "schema-type-domain-narrowed",
                f"{location}: accepted type set narrowed or changed",
            )
    handled.add("type")

    for keyword in ("enum",):
        if keyword in baseline or keyword in candidate:
            before = baseline.get(keyword)
            after = candidate.get(keyword)
            if isinstance(before, list) and isinstance(after, list):
                before_values = {_canonical_semantic(item) for item in before}
                after_values = {_canonical_semantic(item) for item in after}
                if before_values <= after_values:
                    if before_values != after_values:
                        collector.minor(
                            domain,
                            "schema-enum-broadened",
                            f"{location}: enum gained values",
                        )
                else:
                    collector.major(
                        domain,
                        "schema-enum-narrowed",
                        f"{location}: enum removed or changed values",
                    )
            elif before is not None and after is None:
                collector.minor(
                    domain,
                    "schema-enum-removed",
                    f"{location}: enum constraint removed",
                )
            else:
                collector.major(
                    domain,
                    "schema-enum-changed",
                    f"{location}: enum changed incompatibly",
                )
        handled.add(keyword)

    sentinel = object()
    if baseline.get("const", sentinel) != candidate.get("const", sentinel):
        if "const" in baseline and "const" not in candidate:
            collector.minor(
                domain, "schema-const-removed", f"{location}: const constraint removed"
            )
        else:
            collector.major(
                domain,
                "schema-const-changed",
                f"{location}: const changed or was added",
            )
    handled.add("const")

    before_required = baseline.get("required", [])
    after_required = candidate.get("required", [])
    if not isinstance(before_required, list) or not isinstance(after_required, list):
        collector.major(
            domain, "schema-required-invalid", f"{location}: required is not an array"
        )
    else:
        before_set = set(before_required)
        after_set = set(after_required)
        if not all(
            isinstance(item, str) for item in (*before_required, *after_required)
        ):
            collector.major(
                domain,
                "schema-required-invalid",
                f"{location}: required contains non-string entries",
            )
        elif not after_set <= before_set:
            collector.major(
                domain,
                "schema-required-added",
                f"{location}: required properties were added",
            )
        elif after_set != before_set:
            collector.minor(
                domain,
                "schema-required-removed",
                f"{location}: required properties were relaxed",
            )
    handled.add("required")

    for keyword in ("properties", "$defs"):
        before_map = baseline.get(keyword, {})
        after_map = candidate.get(keyword, {})
        if not isinstance(before_map, dict) or not isinstance(after_map, dict):
            collector.major(
                domain, "schema-map-invalid", f"{location}/{keyword}: expected object"
            )
        else:
            removed = set(before_map) - set(after_map)
            added = set(after_map) - set(before_map)
            for name in sorted(removed):
                collector.major(
                    domain,
                    "schema-member-removed",
                    f"{location}/{keyword}/{name}: member removed",
                )
            for name in sorted(added):
                code = (
                    "schema-optional-property-added"
                    if keyword == "properties"
                    else "schema-definition-added"
                )
                collector.minor(
                    domain, code, f"{location}/{keyword}/{name}: member added"
                )
            for name in sorted(set(before_map) & set(after_map)):
                _compare_schema_node(
                    before_map[name],
                    after_map[name],
                    collector,
                    domain,
                    f"{location}/{keyword}/{name}",
                )
        handled.add(keyword)

    for keyword in ("oneOf", "anyOf"):
        if keyword in baseline or keyword in candidate:
            before = baseline.get(keyword, [])
            after = candidate.get(keyword, [])
            if not isinstance(before, list) or not isinstance(after, list):
                collector.major(
                    domain,
                    "schema-union-invalid",
                    f"{location}/{keyword}: expected arrays",
                )
            else:
                before_branches = {_canonical_semantic(branch) for branch in before}
                after_branches = {_canonical_semantic(branch) for branch in after}
                if before_branches <= after_branches:
                    if before_branches != after_branches:
                        collector.minor(
                            domain,
                            "schema-union-broadened",
                            f"{location}/{keyword}: union gained branches",
                        )
                else:
                    collector.major(
                        domain,
                        "schema-union-changed",
                        f"{location}/{keyword}: existing branch changed or was removed",
                    )
        handled.add(keyword)

    for keyword in UPPER_BOUNDS | LOWER_BOUNDS:
        if keyword not in baseline and keyword not in candidate:
            handled.add(keyword)
            continue
        before = baseline.get(keyword)
        after = candidate.get(keyword)
        if before == after:
            handled.add(keyword)
            continue
        if before is not None and not isinstance(before, (int, float)):
            collector.major(
                domain,
                "schema-bound-invalid",
                f"{location}/{keyword}: baseline bound is invalid",
            )
        elif after is not None and not isinstance(after, (int, float)):
            collector.major(
                domain,
                "schema-bound-invalid",
                f"{location}/{keyword}: candidate bound is invalid",
            )
        elif after is None:
            collector.minor(
                domain, "schema-bound-relaxed", f"{location}/{keyword}: bound removed"
            )
        elif before is None:
            collector.major(
                domain,
                "schema-bound-added",
                f"{location}/{keyword}: new bound narrows inputs",
            )
        elif (keyword in UPPER_BOUNDS and after >= before) or (
            keyword in LOWER_BOUNDS and after <= before
        ):
            collector.minor(
                domain, "schema-bound-relaxed", f"{location}/{keyword}: bound relaxed"
            )
        else:
            collector.major(
                domain,
                "schema-bound-tightened",
                f"{location}/{keyword}: bound tightened",
            )
        handled.add(keyword)

    before_additional = baseline.get("additionalProperties", True)
    after_additional = candidate.get("additionalProperties", True)
    if _canonical_semantic(before_additional) != _canonical_semantic(after_additional):
        if before_additional is False and after_additional is True:
            collector.minor(
                domain,
                "schema-additional-properties-broadened",
                f"{location}: additional properties now accepted",
            )
        elif isinstance(before_additional, dict) and isinstance(after_additional, dict):
            _compare_schema_node(
                before_additional,
                after_additional,
                collector,
                domain,
                f"{location}/additionalProperties",
            )
        else:
            collector.major(
                domain,
                "schema-additional-properties-changed",
                f"{location}: additional-properties policy narrowed or changed",
            )
    handled.add("additionalProperties")

    before_unique = baseline.get("uniqueItems", False)
    after_unique = candidate.get("uniqueItems", False)
    if before_unique != after_unique:
        if before_unique is True and after_unique is False:
            collector.minor(
                domain,
                "schema-uniqueness-relaxed",
                f"{location}: uniqueness constraint removed",
            )
        else:
            collector.major(
                domain,
                "schema-uniqueness-tightened",
                f"{location}: uniqueness constraint added or changed",
            )
    handled.add("uniqueItems")

    for keyword in ("pattern", "format", "contentEncoding"):
        before = baseline.get(keyword)
        after = candidate.get(keyword)
        if before != after:
            if before is not None and after is None:
                collector.minor(
                    domain,
                    "schema-lexical-constraint-removed",
                    f"{location}/{keyword}: constraint removed",
                )
            else:
                collector.major(
                    domain,
                    "schema-lexical-constraint-changed",
                    f"{location}/{keyword}: constraint added or changed",
                )
        handled.add(keyword)

    for keyword in ("$schema", "$id"):
        if baseline.get(keyword) != candidate.get(keyword):
            collector.major(
                domain,
                "schema-identity-changed",
                f"{location}/{keyword}: schema identity changed",
            )
        handled.add(keyword)

    unknown = (set(baseline) | set(candidate)) - handled
    for keyword in sorted(unknown):
        if _canonical_semantic(baseline.get(keyword)) != _canonical_semantic(
            candidate.get(keyword)
        ):
            collector.major(
                domain,
                "unsupported-schema-keyword-change",
                f"{location}/{keyword}: comparator does not prove this keyword change safe",
            )


def _compare_schema_sets(
    baseline_root: Path,
    candidate_root: Path,
    baseline_paths: Sequence[str],
    candidate_paths: Sequence[str],
    collector: _Collector,
    domain: str,
) -> None:
    before = set(baseline_paths)
    after = set(candidate_paths)
    for path in sorted(before - after):
        collector.major(
            domain, "schema-family-removed", f"{path}: schema authority removed"
        )
    for path in sorted(after - before):
        if re.search(r"-v[1-9][0-9]*\.schema\.json$", path) is None:
            collector.major(
                domain,
                "unversioned-schema-added",
                f"{path}: new schema has no versioned identity",
            )
        else:
            _validate_json_schema_document(_load_json(candidate_root, path), path)
            collector.minor(
                domain,
                "versioned-schema-added",
                f"{path}: versioned schema authority added",
            )
    for path in sorted(before & after):
        baseline_payload = _read_bytes(baseline_root, path)
        candidate_payload = _read_bytes(candidate_root, path)
        if baseline_payload == candidate_payload:
            continue
        baseline_schema = _validate_json_schema_document(
            load_json_bytes(baseline_payload, f"baseline {path}"), f"baseline {path}"
        )
        candidate_schema = _validate_json_schema_document(
            load_json_bytes(candidate_payload, f"candidate {path}"), f"candidate {path}"
        )
        _compare_schema_node(baseline_schema, candidate_schema, collector, domain, path)


def _compare_operations(
    baseline: OperationCatalog,
    candidate: OperationCatalog,
    collector: _Collector,
) -> None:
    before = set(baseline.operations)
    after = set(candidate.operations)
    for operation_id in sorted(before - after):
        collector.major(
            "operations", "operation-removed", f"{operation_id}: operation removed"
        )
    for operation_id in sorted(after - before):
        collector.minor(
            "operations", "operation-added", f"{operation_id}: unique operation added"
        )
    for operation_id in sorted(before & after):
        if baseline.operations[operation_id] != candidate.operations[operation_id]:
            changed = sorted(
                key
                for key in set(baseline.operations[operation_id])
                | set(candidate.operations[operation_id])
                if baseline.operations[operation_id].get(key)
                != candidate.operations[operation_id].get(key)
            )
            collector.major(
                "operations",
                "operation-contract-changed",
                f"{operation_id}: existing fields changed: {', '.join(changed)}",
            )


def _compare_errors(
    baseline: Mapping[str, Mapping[str, Any]],
    candidate: Mapping[str, Mapping[str, Any]],
    collector: _Collector,
) -> None:
    before = set(baseline)
    after = set(candidate)
    for name in sorted(before - after):
        collector.major("errors", "error-removed", f"{name}: error removed")
    baseline_codes = {record["code"] for record in baseline.values()}
    for name in sorted(after - before):
        record = candidate[name]
        if record["code"] in baseline_codes:
            collector.major(
                "errors",
                "error-code-reused",
                f"{name}: reused numeric code {record['code']}",
            )
        else:
            collector.minor(
                "errors", "error-added", f"{name}: unique error {record['code']} added"
            )
    for name in sorted(before & after):
        if baseline[name] != candidate[name]:
            changed = sorted(
                key
                for key in baseline[name]
                if baseline[name][key] != candidate[name][key]
            )
            collector.major(
                "errors",
                "error-contract-changed",
                f"{name}: existing fields changed: {', '.join(changed)}",
            )


def _compare_interface_projections(
    baseline: InterfaceProjectionCatalog,
    candidate: InterfaceProjectionCatalog,
    collector: _Collector,
) -> None:
    for surface, before, after in (
        ("cli", baseline.cli, candidate.cli),
        ("mcp", baseline.mcp, candidate.mcp),
    ):
        for exposed in sorted(set(before) - set(after)):
            collector.major(
                "interface_projections",
                "interface-mapping-removed",
                f"{surface}:{exposed}: exposed operation mapping removed",
            )
        for exposed in sorted(set(after) - set(before)):
            collector.minor(
                "interface_projections",
                "interface-mapping-added",
                f"{surface}:{exposed}: operation-backed mapping added",
            )
        for exposed in sorted(set(before) & set(after)):
            if before[exposed] != after[exposed]:
                collector.major(
                    "interface_projections",
                    "interface-mapping-changed",
                    f"{surface}:{exposed}: operation, kind, alias, or authority lane changed",
                )


def _compare_payload_type_bundle(
    baseline_root: Path,
    candidate_root: Path,
    baseline_domain: Mapping[str, Any],
    candidate_domain: Mapping[str, Any],
    added_operations: set[str],
    collector: _Collector,
) -> None:
    baseline_path = next(
        path
        for path in baseline_domain["paths"]
        if path.endswith("api-payload-types-v1.schema.json")
    )
    candidate_path = next(
        path
        for path in candidate_domain["paths"]
        if path.endswith("api-payload-types-v1.schema.json")
    )
    baseline = _load_json(baseline_root, baseline_path)
    candidate = _load_json(candidate_root, candidate_path)
    expected_keys = {
        "$id",
        "$schema",
        "api_status",
        "operation_count",
        "operations",
        "schema_version",
        "type_count",
        "types",
    }
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        collector.major(
            "payloads",
            "payload-type-bundle-invalid",
            "payload type bundle is not an object",
        )
        return
    if set(baseline) != expected_keys or set(candidate) != expected_keys:
        collector.major(
            "payloads",
            "payload-type-bundle-fields-changed",
            "payload type bundle root fields drifted",
        )
        return
    for key in ("$id", "$schema", "api_status", "schema_version"):
        if baseline[key] != candidate[key]:
            collector.major(
                "payloads",
                "payload-type-bundle-identity-changed",
                f"payload bundle {key} changed",
            )

    def mapping(records: Any, label: str) -> dict[str, dict[str, Any]]:
        if not isinstance(records, list):
            raise CompatibilityError(f"{label} must be an array")
        output: dict[str, dict[str, Any]] = {}
        for raw in records:
            record = _expect_object(
                raw,
                label,
                ("event_type", "operation_id", "request_type", "response_type"),
            )
            operation_id = _expect_string(
                record["operation_id"], f"{label} operation_id"
            )
            if operation_id in output:
                raise CompatibilityError(f"duplicate {label} operation: {operation_id}")
            output[operation_id] = dict(record)
        return output

    before_ops = mapping(baseline["operations"], "baseline payload type mapping")
    after_ops = mapping(candidate["operations"], "candidate payload type mapping")
    for operation_id in sorted(set(before_ops) - set(after_ops)):
        collector.major(
            "payloads",
            "payload-type-mapping-removed",
            f"{operation_id}: nominal mapping removed",
        )
    for operation_id in sorted(set(after_ops) - set(before_ops)):
        if operation_id in added_operations:
            collector.minor(
                "payloads",
                "payload-type-mapping-added",
                f"{operation_id}: nominal mapping added",
            )
        else:
            collector.major(
                "payloads",
                "payload-type-mapping-orphaned",
                f"{operation_id}: mapping added without new operation",
            )
    for operation_id in sorted(set(before_ops) & set(after_ops)):
        if before_ops[operation_id] != after_ops[operation_id]:
            collector.major(
                "payloads",
                "payload-type-mapping-changed",
                f"{operation_id}: nominal mapping changed",
            )

    before_types = baseline["types"]
    after_types = candidate["types"]
    if not isinstance(before_types, dict) or not isinstance(after_types, dict):
        collector.major(
            "payloads", "payload-types-invalid", "payload types must be objects"
        )
        return
    for name in sorted(set(before_types) - set(after_types)):
        collector.major(
            "payloads", "payload-type-removed", f"{name}: payload type removed"
        )
    for name in sorted(set(after_types) - set(before_types)):
        collector.minor("payloads", "payload-type-added", f"{name}: payload type added")
    for name in sorted(set(before_types) & set(after_types)):
        _compare_schema_node(
            before_types[name],
            after_types[name],
            collector,
            "payloads",
            f"payload-types/{name}",
        )
    if baseline["type_count"] != len(before_types) or candidate["type_count"] != len(
        after_types
    ):
        collector.major(
            "payloads",
            "payload-type-count-invalid",
            "payload type_count does not match the type map",
        )


def _compare_payloads(
    baseline_root: Path,
    candidate_root: Path,
    baseline_domain: Mapping[str, Any],
    candidate_domain: Mapping[str, Any],
    baseline: PayloadCatalog,
    candidate: PayloadCatalog,
    added_operations: set[str],
    collector: _Collector,
) -> None:
    if baseline.envelope_fields != candidate.envelope_fields:
        before = set(baseline.envelope_fields)
        after = set(candidate.envelope_fields)
        if before != after:
            collector.major(
                "payloads",
                "envelope-field-set-changed",
                "shared envelope field set changed",
            )
        for name in sorted(before & after):
            if baseline.envelope_fields[name] != candidate.envelope_fields[name]:
                collector.major(
                    "payloads",
                    "envelope-field-changed",
                    f"{name}: envelope contract changed",
                )
    before = set(baseline.operations)
    after = set(candidate.operations)
    for operation_id in sorted(before - after):
        collector.major(
            "payloads",
            "payload-contract-removed",
            f"{operation_id}: payload contract removed",
        )
    for operation_id in sorted(after - before):
        if operation_id in added_operations:
            collector.minor(
                "payloads",
                "payload-contract-added",
                f"{operation_id}: payload contract added for new operation",
            )
        else:
            collector.major(
                "payloads",
                "orphan-payload-contract",
                f"{operation_id}: payload contract has no new operation",
            )
    for operation_id in sorted(before & after):
        if baseline.operations[operation_id] != candidate.operations[operation_id]:
            collector.major(
                "payloads",
                "payload-contract-changed",
                f"{operation_id}: existing payload type, field, or bound changed",
            )
    _compare_payload_type_bundle(
        baseline_root,
        candidate_root,
        baseline_domain,
        candidate_domain,
        added_operations,
        collector,
    )


def _compare_cursor_stream(
    baseline_root: Path,
    candidate_root: Path,
    baseline_domain: Mapping[str, Any],
    candidate_domain: Mapping[str, Any],
    collector: _Collector,
) -> None:
    before_paths = set(baseline_domain["paths"])
    after_paths = set(candidate_domain["paths"])
    for path in sorted(before_paths - after_paths):
        collector.major(
            "cursor_stream",
            "cursor-stream-authority-removed",
            f"{path}: authority removed",
        )
    for path in sorted(after_paths - before_paths):
        if re.search(r"-v[1-9][0-9]*", path):
            collector.minor(
                "cursor_stream",
                "versioned-cursor-stream-added",
                f"{path}: versioned authority added",
            )
        else:
            collector.major(
                "cursor_stream",
                "unversioned-cursor-stream-added",
                f"{path}: unversioned authority added",
            )
    for path in sorted(before_paths & after_paths):
        baseline_payload = _read_bytes(baseline_root, path)
        candidate_payload = _read_bytes(candidate_root, path)
        if baseline_payload == candidate_payload:
            continue
        if path.endswith(".schema.json"):
            _compare_schema_sets(
                baseline_root,
                candidate_root,
                [path],
                [path],
                collector,
                "cursor_stream",
            )
        elif path.endswith("cursor.rs"):
            collector.major(
                "cursor_stream",
                "cursor-codec-changed",
                f"{path}: opaque cursor wire/scope authority changed",
            )
        # Operation and payload authorities are compared in their own semantic domains.
    before_streams = set(baseline_domain["stream_operations"])
    after_streams = set(candidate_domain["stream_operations"])
    for operation_id in sorted(before_streams - after_streams):
        collector.major(
            "cursor_stream",
            "stream-removed",
            f"{operation_id}: stream operation removed",
        )
    for operation_id in sorted(after_streams - before_streams):
        collector.minor(
            "cursor_stream",
            "stream-added",
            f"{operation_id}: independent stream operation added",
        )
    if (
        baseline_domain["cursor_wire_version"]
        != candidate_domain["cursor_wire_version"]
    ):
        collector.major(
            "cursor_stream",
            "cursor-version-changed-in-place",
            "cursor wire version changed inside v1 policy",
        )


def _compare_extensions(
    baseline_root: Path,
    candidate_root: Path,
    baseline_domain: Mapping[str, Any],
    candidate_domain: Mapping[str, Any],
    collector: _Collector,
) -> None:
    before = set(baseline_domain["paths"])
    after = set(candidate_domain["paths"])
    for path in sorted(before - after):
        collector.major(
            "extensions",
            "extension-authority-removed",
            f"{path}: extension ABI/record removed",
        )
    for path in sorted(after - before):
        if re.search(r"-v[1-9][0-9]*\.(?:wit|schema\.json)$", path):
            collector.minor(
                "extensions",
                "versioned-extension-authority-added",
                f"{path}: versioned extension authority added",
            )
        else:
            collector.major(
                "extensions",
                "unversioned-extension-authority-added",
                f"{path}: unversioned extension authority added",
            )
    schema_before = sorted(
        path for path in before & after if path.endswith(".schema.json")
    )
    _compare_schema_sets(
        baseline_root,
        candidate_root,
        schema_before,
        schema_before,
        collector,
        "extensions",
    )
    for path in sorted(path for path in before & after if path.endswith(".wit")):
        if _read_bytes(baseline_root, path) != _read_bytes(candidate_root, path):
            collector.major(
                "extensions", "wit-world-changed", f"{path}: existing WIT world changed"
            )
    if baseline_domain["abi_package"] != candidate_domain["abi_package"]:
        collector.major(
            "extensions",
            "abi-package-changed",
            "extension ABI package changed in place",
        )
    if baseline_domain["manifest_schema"] != candidate_domain["manifest_schema"]:
        collector.major(
            "extensions",
            "manifest-schema-changed",
            "extension manifest schema identity changed in place",
        )


def _compare_claude(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    collector: _Collector,
) -> None:
    for field in ("schema_version", "context_abi", "public_surfaces_only"):
        if baseline[field] != candidate[field]:
            collector.major(
                "claude_plugin",
                "claude-record-contract-changed",
                f"Claude compatibility {field} changed",
            )
    before_platforms = set(baseline["platforms"])
    after_platforms = set(candidate["platforms"])
    for platform in sorted(before_platforms - after_platforms):
        collector.major(
            "claude_plugin", "claude-platform-removed", f"{platform}: platform removed"
        )
    for platform in sorted(after_platforms - before_platforms):
        collector.minor(
            "claude_plugin", "claude-platform-added", f"{platform}: platform added"
        )
    before_min = _parse_semver(
        baseline["claude_code"]["minimum_inclusive"], "baseline Claude minimum"
    )
    before_max = _parse_semver(
        baseline["claude_code"]["maximum_exclusive"], "baseline Claude maximum"
    )
    after_min = _parse_semver(
        candidate["claude_code"]["minimum_inclusive"], "candidate Claude minimum"
    )
    after_max = _parse_semver(
        candidate["claude_code"]["maximum_exclusive"], "candidate Claude maximum"
    )
    if after_min > before_min or after_max < before_max:
        collector.major(
            "claude_plugin",
            "claude-window-narrowed",
            "Claude Code compatibility window narrowed",
        )
    elif after_min < before_min or after_max > before_max:
        collector.minor(
            "claude_plugin",
            "claude-window-widened",
            "Claude Code compatibility window widened",
        )


def _compare_stored_records(
    baseline_root: Path,
    candidate_root: Path,
    baseline_domain: Mapping[str, Any],
    candidate_domain: Mapping[str, Any],
    collector: _Collector,
) -> None:
    baseline_chains = migration_chains(baseline_root, baseline_domain)
    candidate_chains = migration_chains(candidate_root, candidate_domain)
    for backend in ("sqlite", "postgres"):
        before = baseline_chains[backend]
        after = candidate_chains[backend]
        common = min(len(before), len(after))
        for index in range(common):
            old = before[index]
            new = after[index]
            if (old.sequence, old.name, old.payload) != (
                new.sequence,
                new.name,
                new.payload,
            ):
                collector.major(
                    "stored_records",
                    "applied-migration-changed",
                    f"{backend} migration {old.sequence:04d}_{old.name} changed or was replaced",
                )
        if len(after) < len(before):
            collector.major(
                "stored_records",
                "applied-migration-removed",
                f"{backend} migration chain was shortened",
            )
        for migration in after[len(before) :]:
            if not migration.minimum_major <= 1 <= migration.maximum_major:
                collector.major(
                    "stored_records",
                    "migration-excludes-current-major",
                    f"{migration.path}: appended migration excludes protocol major 1",
                )
            else:
                collector.manual(
                    "stored_records",
                    "appended-migration-requires-evidence",
                    f"{migration.path}: append-only identity is valid; upgrade, interruption, rollback, and mixed-version behavior remain unproven",
                )

    before_paths = set(baseline_domain["codec_paths"])
    after_paths = set(candidate_domain["codec_paths"])
    for path in sorted(before_paths - after_paths):
        collector.major(
            "stored_records",
            "stored-codec-removed",
            f"{path}: persisted-record codec authority removed",
        )
    for path in sorted(after_paths - before_paths):
        collector.manual(
            "stored_records",
            "stored-codec-added",
            f"{path}: new codec authority needs retained-state fixtures",
        )
    for path in sorted(before_paths & after_paths):
        if _read_bytes(baseline_root, path) != _read_bytes(candidate_root, path):
            collector.manual(
                "stored_records",
                "stored-codec-source-changed",
                f"{path}: static comparison cannot prove retained-record reader/writer compatibility",
            )


def compare_repositories(
    baseline_root: Path,
    baseline_policy: Mapping[str, Any],
    candidate_root: Path,
    candidate_policy: Mapping[str, Any],
) -> Comparison:
    validate_repository(baseline_root, baseline_policy)
    validate_repository(candidate_root, candidate_policy)
    collector = _Collector()
    if (
        baseline_policy["policy_schema_sha256"]
        != candidate_policy["policy_schema_sha256"]
    ):
        collector.major(
            "policy",
            "policy-schema-changed",
            "the compatibility policy JSON Schema changed and requires an explicit policy-major review",
        )

    baseline_paths = authority_paths(baseline_root, baseline_policy)
    candidate_paths = authority_paths(candidate_root, candidate_policy)
    _compare_schema_sets(
        baseline_root,
        candidate_root,
        baseline_paths["public_schemas"],
        candidate_paths["public_schemas"],
        collector,
        "public_schemas",
    )

    before_operations = _operation_catalog(
        baseline_root, baseline_policy["domains"]["operations"]
    )
    after_operations = _operation_catalog(
        candidate_root, candidate_policy["domains"]["operations"]
    )
    _compare_operations(before_operations, after_operations, collector)
    added_operations = set(after_operations.operations) - set(
        before_operations.operations
    )

    _compare_interface_projections(
        _interface_projection_catalog(
            baseline_root,
            baseline_policy["domains"]["interface_projections"],
            before_operations,
        ),
        _interface_projection_catalog(
            candidate_root,
            candidate_policy["domains"]["interface_projections"],
            after_operations,
        ),
        collector,
    )

    _compare_errors(
        _error_catalog(baseline_root, baseline_policy["domains"]["errors"]),
        _error_catalog(candidate_root, candidate_policy["domains"]["errors"]),
        collector,
    )

    before_payloads = _payload_catalog(
        baseline_root, baseline_policy["domains"]["payloads"]
    )
    after_payloads = _payload_catalog(
        candidate_root, candidate_policy["domains"]["payloads"]
    )
    _compare_payloads(
        baseline_root,
        candidate_root,
        baseline_policy["domains"]["payloads"],
        candidate_policy["domains"]["payloads"],
        before_payloads,
        after_payloads,
        added_operations,
        collector,
    )
    _compare_cursor_stream(
        baseline_root,
        candidate_root,
        baseline_policy["domains"]["cursor_stream"],
        candidate_policy["domains"]["cursor_stream"],
        collector,
    )
    _compare_extensions(
        baseline_root,
        candidate_root,
        baseline_policy["domains"]["extensions"],
        candidate_policy["domains"]["extensions"],
        collector,
    )
    _compare_claude(
        claude_record(baseline_root, baseline_policy["domains"]["claude_plugin"]),
        claude_record(candidate_root, candidate_policy["domains"]["claude_plugin"]),
        collector,
    )
    _compare_stored_records(
        baseline_root,
        candidate_root,
        baseline_policy["domains"]["stored_records"],
        candidate_policy["domains"]["stored_records"],
        collector,
    )
    return collector.finish()


def _root(value: str) -> Path:
    try:
        path = Path(value).resolve(strict=True)
    except OSError as error:
        raise argparse.ArgumentTypeError(
            f"repository root is unavailable: {error}"
        ) from error
    if not path.is_dir():
        raise argparse.ArgumentTypeError("repository root must be a directory")
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate or compare the offline CIGAR v1 development compatibility policy."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser(
        "validate", help="validate one policy and its exact source bindings"
    )
    validate.add_argument("--root", type=_root, default=Path.cwd())
    validate.add_argument("--policy", default=POLICY_PATH)

    snapshot = subcommands.add_parser(
        "snapshot",
        help="print a canonical policy rebound to reviewed source; never changes files",
    )
    snapshot.add_argument("--root", type=_root, default=Path.cwd())
    snapshot.add_argument("--policy", default=POLICY_PATH)

    compare = subcommands.add_parser(
        "compare",
        help="compare baseline and candidate source trees directionally",
    )
    compare.add_argument("--baseline-root", type=_root, required=True)
    compare.add_argument("--candidate-root", type=_root, required=True)
    compare.add_argument("--baseline-policy", default=POLICY_PATH)
    compare.add_argument("--candidate-policy", default=POLICY_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            policy = load_policy(arguments.root, arguments.policy)
            validate_repository(arguments.root, policy)
            sys.stdout.buffer.write(
                canonical_json_bytes(
                    {
                        "policy_id": POLICY_ID,
                        "result": "valid-development-source-policy",
                        "release_frozen": False,
                    }
                )
            )
            return 0
        if arguments.command == "snapshot":
            policy = load_policy(arguments.root, arguments.policy)
            refreshed = refresh_bindings(arguments.root, policy)
            # The refreshed snapshot must satisfy every semantic invariant before it is shown.
            validate_repository(arguments.root, refreshed)
            sys.stdout.buffer.write(canonical_policy_bytes(refreshed))
            return 0
        if arguments.command == "compare":
            baseline = load_policy(arguments.baseline_root, arguments.baseline_policy)
            candidate = load_policy(
                arguments.candidate_root, arguments.candidate_policy
            )
            comparison = compare_repositories(
                arguments.baseline_root,
                baseline,
                arguments.candidate_root,
                candidate,
            )
            sys.stdout.buffer.write(canonical_json_bytes(comparison.as_json()))
            if comparison.classification in {"exact", "additive-minor"}:
                return 0
            if comparison.classification == "manual-review":
                return 2
            return 3
        raise CompatibilityError(f"unsupported command: {arguments.command}")
    except CompatibilityError as error:
        print(f"compatibility validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
