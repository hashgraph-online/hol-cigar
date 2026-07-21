#!/usr/bin/env python3
"""Generate and validate the development-only CIGAR protocol drift baseline."""

from __future__ import annotations

import argparse
import re
import stat
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

from release_lib import (
    ReleaseError,
    canonical_json_bytes,
    load_json,
    reject_evidence_directory,
    repo_root,
    sha256_bytes,
    sha256_file,
    write_json,
)


BASELINE_ID = "cigar.development.protocol-baseline.v1"
BASELINE_PATH = "packaging/development/protocol-baseline.v1.json"
SCHEMA_PATH = "packaging/development/schemas/protocol-baseline.v1.schema.json"
SCHEMA_SHA256 = "35f9bc9eb346fec90e75be1a626d1d0d62cba29440e25ad2c713cb295018a945"
BASELINE_SHA256 = "59d2d60e8db87b2e4b78cd59ec0c2f091cd476dbca00ded0a347e2497ba521d3"

CONTEXT_ABI = "cigar.context.v1"
PROTOCOL_MIN = "1.0"
PROTOCOL_MAX = "1.x"
OPERATION_COUNT = 45
PAYLOAD_TYPE_COUNT = 70
ERROR_COUNT = 34
CANONICAL_VALID_COUNT = 348
CANONICAL_INVALID_COUNT = 15
CANONICAL_DIFFERENTIAL_COUNT = 100_000
CONFORMANCE_CASE_COUNT = 24
CONFORMANCE_PROFILE_COUNT = 8
REPLAY_RETAINED_COUNT = 3
REPLAY_ARTIFACT_COUNT = 11
MAX_BOUND_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BOUND_BYTES = 32 * 1024 * 1024

PROTOCOL_AUTHORITIES = (
    "packaging/product-version.v1.json",
    "crates/cigar-protocol/src/lib.rs",
    "schemas/generated-manifest.json",
    "schemas/proto/context_abi.proto",
    "spec/api/operations-v1.json",
    "spec/api/operation-payloads-v1.json",
    "spec/errors/catalog.yaml",
)

GENERATED_JSON_SCHEMAS = (
    "schemas/json/candidate-disposition-v1.schema.json",
    "schemas/json/capability-grant-v1.schema.json",
    "schemas/json/compatibility-report-v1.schema.json",
    "schemas/json/compensation-link-v1.schema.json",
    "schemas/json/context-atom-v1.schema.json",
    "schemas/json/context-block-v1.schema.json",
    "schemas/json/context-bundle-v1.schema.json",
    "schemas/json/context-commit-v1.schema.json",
    "schemas/json/context-contract-v1.schema.json",
    "schemas/json/context-delta-v1.schema.json",
    "schemas/json/context-edge-v1.schema.json",
    "schemas/json/context-plan-v1.schema.json",
    "schemas/json/decision-record-v1.schema.json",
    "schemas/json/effect-approval-v1.schema.json",
    "schemas/json/effect-attempt-v1.schema.json",
    "schemas/json/effect-intent-v1.schema.json",
    "schemas/json/effect-journal-event-v1.schema.json",
    "schemas/json/effect-receipt-v1.schema.json",
    "schemas/json/extension-cancel-v1.schema.json",
    "schemas/json/extension-host-call-v1.schema.json",
    "schemas/json/extension-invocation-v1.schema.json",
    "schemas/json/extension-manifest-v1.schema.json",
    "schemas/json/extension-observation-v1.schema.json",
    "schemas/json/extension-response-v1.schema.json",
    "schemas/json/handoff-acceptance-v1.schema.json",
    "schemas/json/handoff-capsule-v1.schema.json",
    "schemas/json/handoff-delta-v1.schema.json",
    "schemas/json/health-report-v1.schema.json",
    "schemas/json/lease-v1.schema.json",
    "schemas/json/materialized-context-v1.schema.json",
    "schemas/json/overlay-v1.schema.json",
    "schemas/json/page-cursor-v1.schema.json",
    "schemas/json/plan-lane-v1.schema.json",
    "schemas/json/problem-v1.schema.json",
    "schemas/json/reconciliation-report-v1.schema.json",
    "schemas/json/replay-completeness-v1.schema.json",
    "schemas/json/replay-diff-v1.schema.json",
    "schemas/json/replay-execution-v1.schema.json",
    "schemas/json/replay-request-v1.schema.json",
    "schemas/json/selection-manifest-v1.schema.json",
    "schemas/json/source-snapshot-v1.schema.json",
    "schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json",
    "schemas/json/verification-receipt-v1.schema.json",
)

GENERATED_ERROR_REGISTRY = (
    "crates/cigar-protocol/src/generated/error_registry.rs",
    "schemas/proto/generated/error_codes.proto",
    "schemas/openapi/error-registry-v1.json",
)

GENERATED_API_CONTRACTS = (
    "crates/cigar-api/src/generated/operations.rs",
    "crates/cigar-api/proto/cigar_service.proto",
    "schemas/json/api-payload-types-v1.schema.json",
    "schemas/proto/cigar_service.proto",
    "schemas/openapi/cigar-v1.json",
)

INTERFACE_PROJECTIONS = (
    "crates/cigar-cli/src/generated/operation_mappings.rs",
    "crates/cigar-dashboard/src/generated/protocol-catalog-v1.json",
    "crates/cigar-mcp/src/generated/operation_mappings.rs",
    "schemas/dashboard/dashboard-protocol-v1.schema.json",
    "spec/api/interface-projections-v1.json",
    "spec/api/operations-v1.md",
)

GENERATED_WIRE_BINDINGS = (
    "crates/cigar-protocol/src/generated/cigar/context/v1/cigar.context.v1.rs",
    "sdk/typescript/src/generated/cigar_service_pb.ts",
    "sdk/typescript/src/generated/context_abi_pb.ts",
    "sdk/typescript/src/generated/generated/error_codes_pb.ts",
    "sdk/python/src/cigar_sdk/generated/cigar_service_pb2.py",
    "sdk/python/src/cigar_sdk/generated/context_abi_pb2.py",
    "sdk/python/src/cigar_sdk/generated/generated/error_codes_pb2.py",
    "sdk/go/gen/cigarv1/cigar_service.pb.go",
    "sdk/go/gen/cigarv1/cigar_service_grpc.pb.go",
    "sdk/go/gen/contextv1/context_abi.pb.go",
    "sdk/go/gen/contextv1/error_codes.pb.go",
)

SDK_CAPABILITY_MAPPINGS = (
    "sdk/capabilities-v1.json",
    "sdk/typescript/src/generated/operations.ts",
    "sdk/python/src/cigar_sdk/generated/operations.py",
    "sdk/go/operations_gen.go",
)

GENERATED_SCHEMA_FIXTURES = ("schemas/fixtures/wp01/manifest.json",)

PROTOCOL_VECTORS = (
    "schemas/vectors/canonical-v1.json",
    "schemas/vectors/replay-v1.json",
    "conformance/vectors/v1/core-v1.json",
)

BINDING_GROUPS = (
    ("protocol-authorities", PROTOCOL_AUTHORITIES),
    ("generated-json-schemas", GENERATED_JSON_SCHEMAS),
    ("generated-error-registry", GENERATED_ERROR_REGISTRY),
    ("generated-api-contracts", GENERATED_API_CONTRACTS),
    ("interface-projections", INTERFACE_PROJECTIONS),
    ("generated-wire-bindings", GENERATED_WIRE_BINDINGS),
    ("sdk-capability-mappings", SDK_CAPABILITY_MAPPINGS),
    ("generated-schema-fixtures", GENERATED_SCHEMA_FIXTURES),
    ("protocol-vectors", PROTOCOL_VECTORS),
)


def _all_bound_paths() -> tuple[str, ...]:
    return tuple(path for _group, paths in BINDING_GROUPS for path in paths)


def _validate_relative_path(relative: str) -> PurePosixPath:
    if (
        not isinstance(relative, str)
        or not relative
        or relative != unicodedata.normalize("NFC", relative)
        or relative.startswith("-")
        or "\\" in relative
        or ":" in relative
        or any(
            unicodedata.category(character).startswith("C") for character in relative
        )
    ):
        raise ReleaseError(f"unsafe protocol-baseline path: {relative!r}")
    parsed = PurePosixPath(relative)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "//" in relative
        or relative.endswith("/")
    ):
        raise ReleaseError(f"unsafe protocol-baseline path: {relative!r}")
    return parsed


def _repository_path(root: Path, relative: str) -> Path:
    parsed = _validate_relative_path(relative)
    current = root
    for part in parsed.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ReleaseError(
                f"cannot inspect protocol-baseline parent {relative!r}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseError(
                f"protocol-baseline parent must be a real directory: {relative!r}"
            )
    return root.joinpath(*parsed.parts)


def _regular_file(path: Path, label: str) -> int:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{label} must be a regular file")
    if metadata.st_nlink != 1:
        raise ReleaseError(f"{label} must not be hard-linked")
    if metadata.st_size < 1 or metadata.st_size > MAX_BOUND_FILE_BYTES:
        raise ReleaseError(f"{label} has an invalid bounded size")
    return metadata.st_size


def _load_bound_json(root: Path, relative: str) -> Any:
    path = _repository_path(root, relative)
    _regular_file(path, relative)
    return load_json(path)


def _read_bound_text(root: Path, relative: str) -> str:
    path = _repository_path(root, relative)
    _regular_file(path, relative)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReleaseError(
            f"cannot read UTF-8 protocol file {relative}: {error}"
        ) from error


def _unique_strings(values: list[Any], label: str, expected_count: int) -> list[str]:
    if (
        len(values) != expected_count
        or not all(isinstance(value, str) and value for value in values)
        or len(set(values)) != len(values)
    ):
        raise ReleaseError(f"{label} must contain {expected_count} unique strings")
    return values


def _inventory_digest(values: Any) -> str:
    return sha256_bytes(canonical_json_bytes(values))


def _validate_inventory_definition() -> None:
    paths = _all_bound_paths()
    if len(BINDING_GROUPS) != 9 or len(paths) != 83:
        raise ReleaseError("protocol binding inventory count drifted")
    if len(set(paths)) != len(paths):
        raise ReleaseError("protocol binding inventory contains duplicate paths")
    portable: set[str] = set()
    for path in paths:
        parsed = _validate_relative_path(path)
        key = "/".join(part.casefold() for part in parsed.parts)
        if key in portable:
            raise ReleaseError(
                "protocol binding inventory has a portable path collision"
            )
        portable.add(key)


def _validate_generator_manifest(root: Path) -> None:
    manifest = _load_bound_json(root, "schemas/generated-manifest.json")
    expected_keys = {
        "schema_version",
        "generator",
        "protocol_min",
        "protocol_max",
        "artifacts",
        "error_artifacts",
        "api_artifacts",
        "wire_artifacts",
        "sdk_artifacts",
        "fixture_manifest",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise ReleaseError("generated schema manifest shape drifted")
    expected = {
        "schema_version": 1,
        "generator": "cargo xtask generate",
        "protocol_min": PROTOCOL_MIN,
        "protocol_max": PROTOCOL_MAX,
        "artifacts": [path.removeprefix("schemas/") for path in GENERATED_JSON_SCHEMAS],
        "error_artifacts": list(GENERATED_ERROR_REGISTRY),
        "api_artifacts": [
            path
            for path in GENERATED_API_CONTRACTS
            if path != "crates/cigar-api/proto/cigar_service.proto"
        ],
        "wire_artifacts": list(GENERATED_WIRE_BINDINGS),
        "sdk_artifacts": list(SDK_CAPABILITY_MAPPINGS),
        "fixture_manifest": "fixtures/wp01/manifest.json",
    }
    if manifest != expected:
        raise ReleaseError(
            "generated schema manifest inventory or protocol range drifted"
        )


def _operation_contract(
    root: Path,
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    catalog = _load_bound_json(root, "spec/api/operations-v1.json")
    if (
        not isinstance(catalog, dict)
        or catalog.get("schema_version") != 1
        or catalog.get("status") != "frozen-v1"
        or catalog.get("package") != "cigar.v1"
        or catalog.get("http_base") != "/v1"
        or catalog.get("operation_count") != OPERATION_COUNT
        or not isinstance(catalog.get("services"), list)
        or len(catalog["services"]) != 7
    ):
        raise ReleaseError("operation catalog identity or count drifted")
    operations: list[dict[str, Any]] = []
    for service in catalog["services"]:
        if (
            not isinstance(service, dict)
            or not isinstance(service.get("name"), str)
            or not isinstance(service.get("operations"), list)
        ):
            raise ReleaseError("operation service entry is invalid")
        operations.extend(service["operations"])
    if len(operations) != OPERATION_COUNT or not all(
        isinstance(operation, dict) for operation in operations
    ):
        raise ReleaseError("operation catalog does not contain exactly 45 operations")
    operation_ids = _unique_strings(
        [operation.get("operation_id") for operation in operations],
        "operation IDs",
        OPERATION_COUNT,
    )
    rpc_names = _unique_strings(
        [operation.get("rpc") for operation in operations],
        "operation RPC names",
        OPERATION_COUNT,
    )
    routes = [
        f"{operation.get('http_method')} {operation.get('http_path')}"
        for operation in operations
    ]
    _unique_strings(routes, "operation HTTP routes", OPERATION_COUNT)

    payloads = _load_bound_json(root, "spec/api/operation-payloads-v1.json")
    if (
        not isinstance(payloads, dict)
        or payloads.get("schema_version") != 1
        or payloads.get("status") != "frozen-v1"
        or payloads.get("operation_count") != OPERATION_COUNT
        or not isinstance(payloads.get("operations"), list)
        or len(payloads["operations"]) != OPERATION_COUNT
        or not isinstance(payloads.get("envelope_fields"), list)
        or len(payloads["envelope_fields"]) != 6
    ):
        raise ReleaseError("operation payload catalog identity or count drifted")
    payload_rows = payloads["operations"]
    payload_ids = _unique_strings(
        [row.get("operation_id") for row in payload_rows if isinstance(row, dict)],
        "payload operation IDs",
        OPERATION_COUNT,
    )
    if payload_ids != operation_ids:
        raise ReleaseError("operation and payload registry order/parity drifted")
    return operation_ids, rpc_names, payload_rows


def _payload_bundle(
    root: Path, operation_ids: list[str], payload_rows: list[dict[str, Any]]
) -> tuple[list[str], list[dict[str, Any]]]:
    bundle = _load_bound_json(root, "schemas/json/api-payload-types-v1.schema.json")
    if (
        not isinstance(bundle, dict)
        or bundle.get("schema_version") != "cigar.api-payload-schema-bundle.v1"
        or bundle.get("api_status") != "frozen-v1"
        or bundle.get("operation_count") != OPERATION_COUNT
        or bundle.get("type_count") != PAYLOAD_TYPE_COUNT
        or not isinstance(bundle.get("operations"), list)
        or len(bundle["operations"]) != OPERATION_COUNT
        or not isinstance(bundle.get("types"), dict)
        or len(bundle["types"]) != PAYLOAD_TYPE_COUNT
    ):
        raise ReleaseError("nominal payload schema bundle identity or count drifted")
    type_names = sorted(bundle["types"])
    _unique_strings(type_names, "nominal payload type names", PAYLOAD_TYPE_COUNT)
    bundle_ids = _unique_strings(
        [
            row.get("operation_id")
            for row in bundle["operations"]
            if isinstance(row, dict)
        ],
        "schema-bundle operation IDs",
        OPERATION_COUNT,
    )
    if bundle_ids != operation_ids:
        raise ReleaseError("operation and nominal payload bundle order/parity drifted")
    expected_rows = [
        {
            "event_type": row.get("event_schema"),
            "operation_id": row.get("operation_id"),
            "request_type": row.get("request_schema"),
            "response_type": row.get("response_schema"),
        }
        for row in payload_rows
    ]
    if bundle["operations"] != expected_rows:
        raise ReleaseError("nominal payload operation mapping drifted")
    referenced = {
        value
        for row in bundle["operations"]
        for key in ("request_type", "response_type", "event_type")
        if isinstance((value := row.get(key)), str)
    }
    if referenced != set(type_names):
        raise ReleaseError("nominal payload registry has unreferenced or missing types")
    for name, schema in bundle["types"].items():
        if (
            not isinstance(schema, dict)
            or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or schema.get("title") != name
            or not isinstance(schema.get("$id"), str)
        ):
            raise ReleaseError(f"nominal payload schema is invalid: {name}")
    return type_names, expected_rows


def _validate_openapi_and_proto(
    root: Path, operation_ids: list[str], rpc_names: list[str]
) -> None:
    catalog = _load_bound_json(root, "spec/api/operations-v1.json")
    expected_routes = {
        (operation["http_path"], operation["http_method"].lower()): operation[
            "operation_id"
        ]
        for service in catalog["services"]
        for operation in service["operations"]
    }
    openapi = _load_bound_json(root, "schemas/openapi/cigar-v1.json")
    if (
        not isinstance(openapi, dict)
        or openapi.get("openapi") != "3.1.0"
        or not isinstance(openapi.get("paths"), dict)
    ):
        raise ReleaseError("OpenAPI identity is invalid")
    observed_routes: dict[tuple[str, str], str] = {}
    for route, path_item in openapi["paths"].items():
        if not isinstance(route, str) or not isinstance(path_item, dict):
            raise ReleaseError("OpenAPI path entry is invalid")
        for method, operation in path_item.items():
            if method not in {"delete", "get", "patch", "post", "put"}:
                continue
            if not isinstance(operation, dict) or not isinstance(
                operation.get("operationId"), str
            ):
                raise ReleaseError("OpenAPI operation is missing operationId")
            observed_routes[(route, method)] = operation["operationId"]
    if observed_routes != expected_routes or set(observed_routes.values()) != set(
        operation_ids
    ):
        raise ReleaseError("OpenAPI operation route/parity drifted")

    schema_proto = _read_bound_text(root, "schemas/proto/cigar_service.proto")
    crate_proto = _read_bound_text(root, "crates/cigar-api/proto/cigar_service.proto")
    if schema_proto != crate_proto:
        raise ReleaseError("runtime and packaged service Proto files differ")
    if len(re.findall(r"^package cigar\.v1;$", schema_proto, re.MULTILINE)) != 1:
        raise ReleaseError("service Proto package identity drifted")
    observed_rpcs = re.findall(
        r"^\s*rpc\s+([A-Za-z][A-Za-z0-9]*)\(", schema_proto, re.MULTILINE
    )
    if observed_rpcs != rpc_names:
        raise ReleaseError("service Proto RPC order/parity drifted")


def _validate_sdk_capabilities(
    root: Path,
    operation_ids: list[str],
    type_names: list[str],
    expected_payload_rows: list[dict[str, Any]],
) -> None:
    capabilities = _load_bound_json(root, "sdk/capabilities-v1.json")
    if (
        not isinstance(capabilities, dict)
        or capabilities.get("schema_version") != "cigar.sdk-capabilities.v1"
        or capabilities.get("api_status") != "frozen-v1"
        or capabilities.get("operation_count") != OPERATION_COUNT
        or capabilities.get("type_count") != PAYLOAD_TYPE_COUNT
        or not isinstance(capabilities.get("operations"), list)
        or not isinstance(capabilities.get("sdks"), dict)
        or set(capabilities["sdks"]) != {"rust", "typescript", "python", "go"}
    ):
        raise ReleaseError("SDK capability registry identity or count drifted")
    capability_ids = _unique_strings(
        [
            row.get("operation_id")
            for row in capabilities["operations"]
            if isinstance(row, dict)
        ],
        "SDK capability operation IDs",
        OPERATION_COUNT,
    )
    if capability_ids != operation_ids:
        raise ReleaseError("SDK capability operation order/parity drifted")
    observed_payload_rows = [
        {
            "event_type": row.get("event_type"),
            "operation_id": row.get("operation_id"),
            "request_type": row.get("request_type"),
            "response_type": row.get("response_type"),
        }
        for row in capabilities["operations"]
    ]
    if observed_payload_rows != expected_payload_rows:
        raise ReleaseError("SDK capability nominal payload mapping drifted")
    for name, sdk in capabilities["sdks"].items():
        if (
            not isinstance(sdk, dict)
            or sdk.get("operation_count") != OPERATION_COUNT
            or sdk.get("type_count") != PAYLOAD_TYPE_COUNT
            or sdk.get("model_source")
            != "schemas/json/api-payload-types-v1.schema.json"
            or sdk.get("nominal_models") is not True
            or sdk.get("runtime_schema_validation") is not True
            or sdk.get("operations") != operation_ids
            or sdk.get("types") != type_names
        ):
            raise ReleaseError(f"SDK capability parity drifted for {name}")


def _validate_errors(root: Path) -> list[dict[str, Any]]:
    registry = _load_bound_json(root, "schemas/openapi/error-registry-v1.json")
    if (
        not isinstance(registry, dict)
        or registry.get("schema_version") != 1
        or not isinstance(registry.get("errors"), list)
        or len(registry["errors"]) != ERROR_COUNT
    ):
        raise ReleaseError("error registry identity or count drifted")
    errors = registry["errors"]
    names = _unique_strings(
        [entry.get("name") for entry in errors if isinstance(entry, dict)],
        "error names",
        ERROR_COUNT,
    )
    codes = [entry.get("code") for entry in errors if isinstance(entry, dict)]
    if (
        len(codes) != ERROR_COUNT
        or not all(
            isinstance(code, int) and not isinstance(code, bool) for code in codes
        )
        or len(set(codes)) != ERROR_COUNT
    ):
        raise ReleaseError("error codes must contain exactly 34 unique integers")

    source = _read_bound_text(root, "spec/errors/catalog.yaml")
    source_pairs = [
        (int(code), name)
        for code, name in re.findall(
            r"^\s*- \{ code: ([0-9]+), name: ([A-Z][A-Z0-9_]+),",
            source,
            re.MULTILINE,
        )
    ]
    expected_pairs = list(zip(codes, names, strict=True))
    if source_pairs != expected_pairs:
        raise ReleaseError("error source and generated registry parity drifted")

    proto = _read_bound_text(root, "schemas/proto/generated/error_codes.proto")
    proto_pairs = [
        (int(code), name)
        for name, code in re.findall(
            r"^\s*ERROR_CODE_([A-Z][A-Z0-9_]+) = ([0-9]+);$", proto, re.MULTILINE
        )
        if name != "UNSPECIFIED"
    ]
    if proto_pairs != expected_pairs:
        raise ReleaseError("error Proto and registry parity drifted")
    rust = _read_bound_text(
        root, "crates/cigar-protocol/src/generated/error_registry.rs"
    )
    rust_names = re.findall(r'^\s*symbol: "([A-Z][A-Z0-9_]+)",$', rust, re.MULTILINE)
    if rust_names != names:
        raise ReleaseError("Rust error registry and public registry parity drifted")
    return [{"code": code, "name": name} for code, name in expected_pairs]


def _validate_protocol_identity(root: Path) -> None:
    product = _load_bound_json(root, "packaging/product-version.v1.json")
    release_identity = (
        (
            product.get("release_state"),
            product.get("channel"),
        )
        if isinstance(product, dict)
        else None
    )
    if (
        not isinstance(product, dict)
        or product.get("context_abi") != CONTEXT_ABI
        or release_identity
        not in {
            ("development", "development"),
            ("developer-preview", "honey"),
        }
        or product.get("published") is not False
        or product.get("supported") is not False
    ):
        raise ReleaseError("development/Honey product Context ABI binding is invalid")
    protocol_source = _read_bound_text(root, "crates/cigar-protocol/src/lib.rs")
    for declaration in (
        f'pub const PROTOCOL_MIN: &str = "{PROTOCOL_MIN}";',
        f'pub const PROTOCOL_MAX: &str = "{PROTOCOL_MAX}";',
    ):
        if protocol_source.count(declaration) != 1:
            raise ReleaseError("Rust protocol range declaration drifted")
    context_proto = _read_bound_text(root, "schemas/proto/context_abi.proto")
    if (
        len(re.findall(r"^package cigar\.context\.v1;$", context_proto, re.MULTILINE))
        != 1
    ):
        raise ReleaseError("Context ABI Proto package drifted")
    _validate_generator_manifest(root)


def _validate_vectors(root: Path) -> dict[str, int]:
    canonical = _load_bound_json(root, "schemas/vectors/canonical-v1.json")
    if (
        not isinstance(canonical, dict)
        or canonical.get("schema_version") != 1
        or canonical.get("profile") != "cigar-canonical-v1"
        or canonical.get("valid_count") != CANONICAL_VALID_COUNT
        or canonical.get("invalid_count") != CANONICAL_INVALID_COUNT
        or not isinstance(canonical.get("valid"), list)
        or len(canonical["valid"]) != CANONICAL_VALID_COUNT
        or not isinstance(canonical.get("invalid"), list)
        or len(canonical["invalid"]) != CANONICAL_INVALID_COUNT
        or not isinstance(canonical.get("differential"), dict)
        or canonical["differential"].get("count") != CANONICAL_DIFFERENTIAL_COUNT
    ):
        raise ReleaseError("canonical vector count or identity drifted")
    valid_ids = _unique_strings(
        [row.get("id") for row in canonical["valid"] if isinstance(row, dict)],
        "valid canonical vector IDs",
        CANONICAL_VALID_COUNT,
    )
    invalid_ids = _unique_strings(
        [row.get("id") for row in canonical["invalid"] if isinstance(row, dict)],
        "invalid canonical vector IDs",
        CANONICAL_INVALID_COUNT,
    )
    if set(valid_ids).intersection(invalid_ids):
        raise ReleaseError("valid and invalid canonical vector IDs overlap")

    conformance = _load_bound_json(root, "conformance/vectors/v1/core-v1.json")
    if (
        not isinstance(conformance, dict)
        or conformance.get("schema_version") != "cigar.conformance.vectors.v1"
        or conformance.get("source_vector") != "schemas/vectors/canonical-v1.json"
        or conformance.get("source_vector_sha256")
        != sha256_file(_repository_path(root, "schemas/vectors/canonical-v1.json"))
        or not isinstance(conformance.get("cases"), list)
        or len(conformance["cases"]) != CONFORMANCE_CASE_COUNT
        or not isinstance(conformance.get("profiles"), list)
        or len(conformance["profiles"]) != CONFORMANCE_PROFILE_COUNT
    ):
        raise ReleaseError(
            "conformance vector count, identity, or source binding drifted"
        )
    _unique_strings(
        [row.get("id") for row in conformance["cases"] if isinstance(row, dict)],
        "conformance case IDs",
        CONFORMANCE_CASE_COUNT,
    )
    profiles = _unique_strings(
        conformance["profiles"], "conformance profiles", CONFORMANCE_PROFILE_COUNT
    )
    if any(
        not isinstance(row, dict) or row.get("profile") not in profiles
        for row in conformance["cases"]
    ):
        raise ReleaseError("conformance case references an unknown profile")

    replay = _load_bound_json(root, "schemas/vectors/replay-v1.json")
    if (
        not isinstance(replay, dict)
        or replay.get("schema_version") != "cigar.replay-vector.v1"
        or not isinstance(replay.get("retained"), dict)
        or len(replay["retained"]) != REPLAY_RETAINED_COUNT
        or not isinstance(replay.get("retained_artifacts"), list)
        or len(replay["retained_artifacts"]) != REPLAY_ARTIFACT_COUNT
        or not isinstance(replay.get("required_dependencies"), list)
        or len(replay["required_dependencies"]) != REPLAY_ARTIFACT_COUNT
        or not isinstance(replay.get("expected"), dict)
        or replay["expected"].get("complete") is not True
        or replay["expected"].get("missing_dependencies") != []
    ):
        raise ReleaseError("replay vector count or completeness contract drifted")
    retained_kinds = [
        item.get("kind")
        for item in replay["retained_artifacts"]
        if isinstance(item, dict)
    ]
    dependencies = _unique_strings(
        replay["required_dependencies"],
        "replay required dependencies",
        REPLAY_ARTIFACT_COUNT,
    )
    if retained_kinds != dependencies:
        raise ReleaseError("replay retained artifacts and dependencies drifted")
    return {
        "canonical_valid": CANONICAL_VALID_COUNT,
        "canonical_invalid": CANONICAL_INVALID_COUNT,
        "canonical_differential_records": CANONICAL_DIFFERENTIAL_COUNT,
        "conformance_cases": CONFORMANCE_CASE_COUNT,
        "conformance_profiles": CONFORMANCE_PROFILE_COUNT,
        "replay_retained_inputs": REPLAY_RETAINED_COUNT,
        "replay_retained_artifacts": REPLAY_ARTIFACT_COUNT,
    }


def _semantic_contract(root: Path) -> dict[str, Any]:
    _validate_protocol_identity(root)
    operation_ids, rpc_names, payload_rows = _operation_contract(root)
    type_names, expected_payload_rows = _payload_bundle(
        root, operation_ids, payload_rows
    )
    _validate_openapi_and_proto(root, operation_ids, rpc_names)
    _validate_sdk_capabilities(root, operation_ids, type_names, expected_payload_rows)
    errors = _validate_errors(root)
    vectors = _validate_vectors(root)
    return {
        "context_abi": CONTEXT_ABI,
        "protocol_min": PROTOCOL_MIN,
        "protocol_max": PROTOCOL_MAX,
        "operation_registry": {
            "count": OPERATION_COUNT,
            "id_inventory_sha256": _inventory_digest(operation_ids),
        },
        "nominal_payload_registry": {
            "count": PAYLOAD_TYPE_COUNT,
            "id_inventory_sha256": _inventory_digest(type_names),
        },
        "error_registry": {
            "count": ERROR_COUNT,
            "id_inventory_sha256": _inventory_digest(errors),
        },
        "sdk_capability_registry": {
            "sdks": ["go", "python", "rust", "typescript"],
            "operation_parity": True,
            "nominal_payload_parity": True,
        },
        "vectors": vectors,
    }


def _binding_groups(root: Path) -> tuple[list[dict[str, Any]], int]:
    groups: list[dict[str, Any]] = []
    total_bytes = 0
    for group_id, relative_paths in BINDING_GROUPS:
        files: list[dict[str, str]] = []
        for relative in relative_paths:
            path = _repository_path(root, relative)
            total_bytes += _regular_file(path, relative)
            if total_bytes > MAX_TOTAL_BOUND_BYTES:
                raise ReleaseError(
                    "protocol binding inventory exceeds its total byte limit"
                )
            files.append({"path": relative, "sha256": sha256_file(path)})
        groups.append(
            {"id": group_id, "file_count": len(relative_paths), "files": files}
        )
    return groups, total_bytes


def expected_baseline(root: Path) -> dict[str, Any]:
    _validate_inventory_definition()
    semantic_contract = _semantic_contract(root)
    bindings, total_bytes = _binding_groups(root)
    paths = _all_bound_paths()
    return {
        "schema_version": "cigar.development-protocol-baseline.v1",
        "baseline_id": BASELINE_ID,
        "lifecycle": {
            "state": "development",
            "purpose": "drift-detection-only",
            "release_claimed": False,
            "candidate_frozen": False,
        },
        "execution_scope": {
            "host_os": "macos",
            "host_arch": "arm64",
            "target_triple": "aarch64-apple-darwin",
            "cross_platform_qualification_claimed": False,
        },
        "schema_binding": {"path": SCHEMA_PATH, "sha256": SCHEMA_SHA256},
        "semantic_contract": semantic_contract,
        "binding_inventory": {
            "file_count": len(paths),
            "total_bytes": total_bytes,
            "path_inventory_sha256": _inventory_digest(list(paths)),
            "groups": bindings,
        },
        "fail_closed": True,
    }


def _validate_document_shape(document: Any) -> None:
    required = {
        "schema_version",
        "baseline_id",
        "lifecycle",
        "execution_scope",
        "schema_binding",
        "semantic_contract",
        "binding_inventory",
        "fail_closed",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise ReleaseError("protocol baseline has missing or unexpected fields")
    lifecycle = document.get("lifecycle")
    if (
        not isinstance(lifecycle, dict)
        or lifecycle.get("release_claimed") is not False
        or lifecycle.get("candidate_frozen") is not False
        or lifecycle.get("state") != "development"
    ):
        raise ReleaseError("protocol baseline inflates its lifecycle claims")
    inventory = document.get("binding_inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("groups"), list):
        raise ReleaseError("protocol baseline binding inventory is invalid")
    observed_paths: list[str] = []
    observed_group_ids: list[str] = []
    for group in inventory["groups"]:
        if (
            not isinstance(group, dict)
            or set(group) != {"id", "file_count", "files"}
            or not isinstance(group.get("id"), str)
            or not isinstance(group.get("files"), list)
            or group.get("file_count") != len(group["files"])
        ):
            raise ReleaseError("protocol baseline binding group is invalid")
        observed_group_ids.append(group["id"])
        for binding in group["files"]:
            if (
                not isinstance(binding, dict)
                or set(binding) != {"path", "sha256"}
                or not isinstance(binding.get("path"), str)
                or not isinstance(binding.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", binding["sha256"]) is None
            ):
                raise ReleaseError("protocol baseline file binding is invalid")
            _validate_relative_path(binding["path"])
            observed_paths.append(binding["path"])
    if len(set(observed_group_ids)) != len(observed_group_ids):
        raise ReleaseError("protocol baseline contains duplicate group IDs")
    if len(set(observed_paths)) != len(observed_paths):
        raise ReleaseError("protocol baseline contains duplicate file paths")
    if len({path.casefold() for path in observed_paths}) != len(observed_paths):
        raise ReleaseError("protocol baseline contains portable path collisions")
    if inventory.get("file_count") != len(observed_paths):
        raise ReleaseError("protocol baseline file count is inconsistent")


def _validate_schema(root: Path) -> None:
    path = _repository_path(root, SCHEMA_PATH)
    _regular_file(path, SCHEMA_PATH)
    schema = load_json(path)
    if (
        not isinstance(schema, dict)
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != "https://cigar.invalid/schemas/development-protocol-baseline.v1.schema.json"
    ):
        raise ReleaseError("development protocol baseline schema identity is invalid")
    if sha256_file(path) != SCHEMA_SHA256:
        raise ReleaseError("development protocol baseline schema digest drifted")


def _require_reviewed_projection(document: dict[str, Any]) -> None:
    digest = sha256_bytes(canonical_json_bytes(document))
    if digest != BASELINE_SHA256:
        raise ReleaseError(
            "development protocol baseline projection changed without updating its reviewed digest"
        )


def generate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError("repository root is not a directory")
    _validate_schema(resolved)
    document = expected_baseline(resolved)
    _require_reviewed_projection(document)
    destination = _repository_path(resolved, BASELINE_PATH)
    if destination.exists():
        _regular_file(destination, BASELINE_PATH)
    write_json(destination, document)


def validate(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ReleaseError("repository root is not a directory")
    _validate_schema(resolved)
    expected = expected_baseline(resolved)
    _require_reviewed_projection(expected)
    path = _repository_path(resolved, BASELINE_PATH)
    _regular_file(path, BASELINE_PATH)
    document = load_json(path)
    if path.read_bytes() != canonical_json_bytes(document):
        raise ReleaseError("development protocol baseline is not canonical JSON")
    _validate_document_shape(document)
    if document != expected:
        raise ReleaseError(
            "development protocol baseline digest or semantic binding drifted"
        )
    if sha256_file(path) != BASELINE_SHA256:
        raise ReleaseError("development protocol baseline manifest digest drifted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("--root", type=Path, default=repo_root())
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help=(
            "reserved external evidence selector (or set CIGAR_EVIDENCE_DIR); "
            "protocol-baseline source generation/checking emits no release evidence"
        ),
    )
    arguments = parser.parse_args()
    reject_evidence_directory(
        arguments.evidence_dir,
        "development protocol-baseline operation",
    )
    if arguments.command == "generate":
        generate(arguments.root)
        print(f"generated development protocol baseline {BASELINE_ID}")
    else:
        validate(arguments.root)
        print(f"validated development protocol baseline {BASELINE_ID}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        raise SystemExit(f"development protocol baseline failed: {error}") from error
