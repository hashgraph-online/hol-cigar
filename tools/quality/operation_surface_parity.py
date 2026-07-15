#!/usr/bin/env python3
"""Fail closed when the frozen v1 operation semantics diverge between surfaces.

This is a development source-tree sentinel.  It emits no candidate, package,
installation, publication, or support claim.  CLI and MCP are deliberately
closed subsets of the service protocol, while metrics deliberately aggregate
operations to avoid an attacker-controlled cardinality dimension.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import re
import stat
import sys
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any


OPERATION_COUNT = 45
SERVICE_COUNT = 7
ERROR_COUNT = 34
CLI_MAPPING_COUNT = 34
CLI_OPERATION_COUNT = 33
MCP_MAPPING_COUNT = 10
METRIC_FAMILY_COUNT = 43
METRIC_SERIES_MAXIMUM = 137
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
PROBLEM_FIELDS = {
    "schema_version",
    "code",
    "http_status",
    "retry",
    "message",
    "remediation",
    "correlation_id",
    "details",
}
METRIC_LABEL_KEYS = {
    "outcome",
    "stage",
    "lane",
    "phase",
    "kind",
    "state",
    "worker",
    "event",
}

SOURCE_FILES = (
    "tools/quality/operation_surface_parity.py",
    "spec/api/operations-v1.json",
    "spec/api/operation-payloads-v1.json",
    "spec/api/interface-projections-v1.json",
    "schemas/openapi/cigar-v1.json",
    "schemas/openapi/error-registry-v1.json",
    "schemas/json/problem-v1.schema.json",
    "schemas/proto/cigar_service.proto",
    "crates/cigar-api/proto/cigar_service.proto",
    "crates/cigar-api/src/generated/operations.rs",
    "crates/cigar-api/src/typed.rs",
    "crates/cigar-api/src/context.rs",
    "crates/cigar-cli/src/generated/operation_mappings.rs",
    "crates/cigar-cli/src/command.rs",
    "crates/cigar-mcp/src/generated/operation_mappings.rs",
    "crates/cigar-mcp/src/server.rs",
    "crates/cigar-dashboard/src/generated/protocol-catalog-v1.json",
    "crates/cigar-observe/src/lib.rs",
    "sdk/capabilities-v1.json",
    "sdk/go/capabilities-v1.json",
    "sdk/python/src/cigar_sdk/capabilities-v1.json",
    "sdk/typescript/src/generated/operations.ts",
    "sdk/typescript/src/generated/errors.ts",
    "sdk/python/src/cigar_sdk/generated/operations.py",
    "sdk/python/src/cigar_sdk/generated/errors.py",
    "sdk/go/operations_gen.go",
    "sdk/go/errors_gen.go",
)


class ParityError(RuntimeError):
    """A closed operation projection disagreed with its authority."""


def _reject_duplicate(key_value_pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in key_value_pairs:
        if key in output:
            raise ParityError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_nonfinite(value: str) -> Any:
    raise ParityError(f"non-finite JSON number is forbidden: {value}")


def _parse_integer(value: str) -> int:
    if len(value) > 20:
        raise ParityError("JSON integer exceeds the signed 64-bit bound")
    parsed = int(value, 10)
    if not -(1 << 63) <= parsed <= (1 << 63) - 1:
        raise ParityError("JSON integer exceeds the signed 64-bit bound")
    return parsed


def _parse_float(value: str) -> float:
    if len(value) > 128:
        raise ParityError("JSON floating-point literal exceeds its bound")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ParityError("non-finite JSON number is forbidden")
    return parsed


class RepositoryReader:
    """Read a bounded set of real repository files without following links."""

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        self.total_bytes = 0
        self.digests: dict[str, str] = {}

    @staticmethod
    def _relative(value: str) -> PurePosixPath:
        if (
            not value
            or value.startswith("-")
            or value.startswith("/")
            or "\\" in value
            or ":" in value
            or value != unicodedata.normalize("NFC", value)
            or any(
                unicodedata.category(character).startswith("C") for character in value
            )
        ):
            raise ParityError(f"unsafe source path: {value!r}")
        relative = PurePosixPath(value)
        if any(part in {"", ".", ".."} for part in relative.parts):
            raise ParityError(f"unsafe source path: {value!r}")
        return relative

    def bytes(self, relative_value: str) -> bytes:
        relative = self._relative(relative_value)
        current = self.root
        for part in relative.parts[:-1]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError as error:
                raise ParityError(
                    f"cannot inspect source parent {relative_value!r}: {error}"
                ) from error
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ParityError(
                    f"source parent is not a real directory: {relative_value!r}"
                )
        path = self.root.joinpath(*relative.parts)
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ParityError(
                f"cannot inspect source file {relative_value!r}: {error}"
            ) from error
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ParityError(f"source is not a real regular file: {relative_value!r}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_FILE_BYTES:
            raise ParityError(f"source size is outside its bound: {relative_value!r}")
        self.total_bytes += metadata.st_size
        if self.total_bytes > MAX_TOTAL_BYTES:
            raise ParityError(
                "operation-surface source inventory exceeds its total byte bound"
            )
        try:
            data = path.read_bytes()
        except OSError as error:
            raise ParityError(
                f"cannot read source file {relative_value!r}: {error}"
            ) from error
        if len(data) != metadata.st_size:
            raise ParityError(f"source changed while it was read: {relative_value!r}")
        self.digests[relative_value] = hashlib.sha256(data).hexdigest()
        return data

    def text(self, relative: str) -> str:
        try:
            return self.bytes(relative).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ParityError(f"source is not UTF-8: {relative!r}") from error

    def json(self, relative: str) -> Any:
        try:
            return json.loads(
                self.text(relative),
                object_pairs_hook=_reject_duplicate,
                parse_constant=_reject_nonfinite,
                parse_int=_parse_integer,
                parse_float=_parse_float,
            )
        except (json.JSONDecodeError, RecursionError, UnicodeError) as error:
            raise ParityError(f"source is not strict JSON: {relative!r}") from error


@dataclass(frozen=True)
class Operation:
    service: str
    rpc: str
    operation_id: str
    http_method: str
    http_path: str
    mutation: bool
    idempotency: str
    revision: str
    stream: str
    auth: str
    request_type: str
    response_type: str
    event_type: str | None
    request_max_bytes: int
    response_max_bytes: int
    event_max_bytes: int
    path_fields: tuple[str, ...]


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ParityError(f"{label} fields drifted")
    return value


def _unique(values: list[Any], count: int, label: str) -> None:
    if (
        len(values) != count
        or not all(isinstance(value, str) and value for value in values)
        or len(set(values)) != count
    ):
        raise ParityError(f"{label} must contain exactly {count} unique strings")


def _path_fields(path: str) -> tuple[str, ...]:
    fields = tuple(re.findall(r"\{([a-z][a-z0-9_]*)\}", path))
    if path.count("{") != len(fields) or path.count("}") != len(fields):
        raise ParityError(f"invalid HTTP path template: {path}")
    if len(fields) != len(set(fields)) or len(fields) > 8:
        raise ParityError(f"duplicate or excessive HTTP path fields: {path}")
    return fields


def _catalog(reader: RepositoryReader) -> tuple[list[Operation], dict[str, Any]]:
    catalog = _exact_keys(
        reader.json("spec/api/operations-v1.json"),
        {
            "schema_version",
            "status",
            "package",
            "http_base",
            "operation_count",
            "services",
        },
        "operation catalog",
    )
    if (
        catalog["schema_version"] != 1
        or catalog["status"] != "frozen-v1"
        or catalog["package"] != "cigar.v1"
        or catalog["http_base"] != "/v1"
        or catalog["operation_count"] != OPERATION_COUNT
        or not isinstance(catalog["services"], list)
        or len(catalog["services"]) != SERVICE_COUNT
    ):
        raise ParityError("operation catalog identity or count drifted")

    payloads = _exact_keys(
        reader.json("spec/api/operation-payloads-v1.json"),
        {
            "schema_version",
            "status",
            "operation_count",
            "envelope_fields",
            "operations",
        },
        "payload catalog",
    )
    if (
        payloads["schema_version"] != 1
        or payloads["status"] != "frozen-v1"
        or payloads["operation_count"] != OPERATION_COUNT
        or not isinstance(payloads["operations"], list)
        or len(payloads["operations"]) != OPERATION_COUNT
        or not isinstance(payloads["envelope_fields"], list)
        or len(payloads["envelope_fields"]) != 6
    ):
        raise ParityError("payload catalog identity or count drifted")
    payload_by_id: dict[str, dict[str, Any]] = {}
    payload_order: list[str] = []
    for raw in payloads["operations"]:
        row = _exact_keys(
            raw,
            {
                "operation_id",
                "request_schema",
                "response_schema",
                "event_schema",
                "request_max_bytes",
                "response_max_bytes",
                "event_max_bytes",
                "request_fields",
                "response_fields",
                "event_fields",
            },
            "payload operation",
        )
        operation_id = row["operation_id"]
        if not isinstance(operation_id, str) or operation_id in payload_by_id:
            raise ParityError("payload operation identifiers are invalid or duplicated")
        payload_by_id[operation_id] = row
        payload_order.append(operation_id)

    operations: list[Operation] = []
    operation_keys = {
        "rpc",
        "operation_id",
        "http_method",
        "http_path",
        "mutation",
        "idempotency_requirement",
        "revision_requirement",
        "stream_kind",
        "auth_class",
    }
    service_names: list[str] = []
    routes: list[str] = []
    for raw_service in catalog["services"]:
        service = _exact_keys(raw_service, {"name", "operations"}, "operation service")
        name = service["name"]
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Z][A-Za-z0-9]*Service", name
        ):
            raise ParityError("operation service name is invalid")
        if not isinstance(service["operations"], list) or not service["operations"]:
            raise ParityError("operation service is empty or invalid")
        service_names.append(name)
        for raw_operation in service["operations"]:
            row = _exact_keys(raw_operation, operation_keys, "operation")
            operation_id = row["operation_id"]
            rpc = row["rpc"]
            if (
                not isinstance(rpc, str)
                or not re.fullmatch(r"[A-Z][A-Za-z0-9]*", rpc)
                or not isinstance(operation_id, str)
                or operation_id != rpc[0].lower() + rpc[1:]
            ):
                raise ParityError("RPC and lower-camel operation identity diverged")
            if row["http_method"] not in {"GET", "POST"}:
                raise ParityError(f"unsupported HTTP method for {operation_id}")
            if not isinstance(row["http_path"], str) or not row["http_path"].startswith(
                "/"
            ):
                raise ParityError(f"invalid HTTP path for {operation_id}")
            if not isinstance(row["mutation"], bool):
                raise ParityError(f"invalid mutation flag for {operation_id}")
            expected_idempotency = "required" if row["mutation"] else "not_applicable"
            if row["idempotency_requirement"] != expected_idempotency:
                raise ParityError(f"mutation/idempotency drift for {operation_id}")
            if row["revision_requirement"] not in {"none", "required"} or (
                row["revision_requirement"] == "required" and not row["mutation"]
            ):
                raise ParityError(f"revision contract drift for {operation_id}")
            if row["stream_kind"] not in {"unary", "server_stream"}:
                raise ParityError(f"stream contract drift for {operation_id}")
            if row["auth_class"] not in {"tenant", "operator", "health", "anonymous"}:
                raise ParityError(f"authentication contract drift for {operation_id}")
            payload = payload_by_id.get(operation_id)
            if payload is None:
                raise ParityError(f"payload mapping is absent for {operation_id}")
            event_type = payload["event_schema"]
            expected_event_bytes = (
                1_048_576 if row["stream_kind"] == "server_stream" else 0
            )
            if (
                not isinstance(payload["request_schema"], str)
                or not isinstance(payload["response_schema"], str)
                or payload["request_max_bytes"] != 16_777_216
                or payload["response_max_bytes"] != 16_777_216
                or payload["event_max_bytes"] != expected_event_bytes
                or (row["stream_kind"] == "server_stream")
                != isinstance(event_type, str)
                or (row["stream_kind"] == "unary" and payload["event_fields"] != [])
            ):
                raise ParityError(
                    f"payload bounds or stream mapping drift for {operation_id}"
                )
            fields = _path_fields(row["http_path"])
            operations.append(
                Operation(
                    service=name,
                    rpc=rpc,
                    operation_id=operation_id,
                    http_method=row["http_method"],
                    http_path=row["http_path"],
                    mutation=row["mutation"],
                    idempotency=row["idempotency_requirement"],
                    revision=row["revision_requirement"],
                    stream=row["stream_kind"],
                    auth=row["auth_class"],
                    request_type=payload["request_schema"],
                    response_type=payload["response_schema"],
                    event_type=event_type,
                    request_max_bytes=payload["request_max_bytes"],
                    response_max_bytes=payload["response_max_bytes"],
                    event_max_bytes=payload["event_max_bytes"],
                    path_fields=fields,
                )
            )
            routes.append(f"{row['http_method']} {row['http_path']}")

    _unique(service_names, SERVICE_COUNT, "service names")
    _unique(
        [operation.operation_id for operation in operations],
        OPERATION_COUNT,
        "operation IDs",
    )
    _unique([operation.rpc for operation in operations], OPERATION_COUNT, "RPC names")
    _unique(routes, OPERATION_COUNT, "HTTP routes")
    if payload_order != [operation.operation_id for operation in operations]:
        raise ParityError("payload and operation catalog order drifted")
    if sum(operation.stream == "server_stream" for operation in operations) != 1:
        raise ParityError(
            "the frozen v1 surface must contain exactly one server stream"
        )
    return operations, payloads


def _validate_openapi(
    reader: RepositoryReader, operations: list[Operation], errors: list[dict[str, Any]]
) -> None:
    document = reader.json("schemas/openapi/cigar-v1.json")
    if not isinstance(document, dict) or document.get("openapi") != "3.1.0":
        raise ParityError("OpenAPI identity drifted")
    paths = document.get("paths")
    if not isinstance(paths, dict) or set(paths) != {
        operation.http_path for operation in operations
    }:
        raise ParityError("OpenAPI path inventory drifted")
    for operation in operations:
        path_item = paths[operation.http_path]
        method = operation.http_method.lower()
        if not isinstance(path_item, dict) or set(path_item) != {method}:
            raise ParityError(
                f"OpenAPI method inventory drifted for {operation.operation_id}"
            )
        item = path_item[method]
        expected = {
            "operationId": operation.operation_id,
            "x-cigar-service": operation.service,
            "x-cigar-rpc": operation.rpc,
            "x-cigar-mutation": operation.mutation,
            "x-cigar-idempotency-requirement": operation.idempotency,
            "x-cigar-revision-requirement": operation.revision,
            "x-cigar-stream-kind": operation.stream,
            "x-cigar-auth-class": operation.auth,
            "x-cigar-request-schema": operation.request_type,
            "x-cigar-response-schema": operation.response_type,
        }
        if operation.event_type is not None:
            expected["x-cigar-event-schema"] = operation.event_type
        if any(item.get(key) != value for key, value in expected.items()):
            raise ParityError(
                f"OpenAPI semantic metadata drifted for {operation.operation_id}"
            )
        expected_parameters = [("path", field, True) for field in operation.path_fields]
        if operation.mutation:
            expected_parameters.append(("header", "Idempotency-Key", True))
        if operation.revision == "required":
            expected_parameters.append(("header", "If-Match", True))
        raw_parameters = item.get("parameters")
        if not isinstance(raw_parameters, list) or not all(
            isinstance(parameter, dict) for parameter in raw_parameters
        ):
            raise ParityError(
                f"OpenAPI parameters are invalid for {operation.operation_id}"
            )
        observed_parameters = [
            (parameter.get("in"), parameter.get("name"), parameter.get("required"))
            for parameter in raw_parameters
        ]
        if observed_parameters != expected_parameters:
            raise ParityError(
                f"OpenAPI parameter contract drifted for {operation.operation_id}"
            )
        expected_security = (
            [{"tenantBearer": []}]
            if operation.auth == "tenant"
            else [{"operatorBearer": []}]
            if operation.auth == "operator"
            else []
        )
        if item.get("security") != expected_security:
            raise ParityError(
                f"OpenAPI authentication contract drifted for {operation.operation_id}"
            )
        default_schema = (
            item.get("responses", {})
            .get("default", {})
            .get("content", {})
            .get("application/problem+json", {})
            .get("schema")
        )
        if default_schema != {"$ref": "#/components/schemas/Problem"}:
            raise ParityError(
                f"OpenAPI problem response drifted for {operation.operation_id}"
            )

    components = document.get("components")
    if not isinstance(components, dict) or not isinstance(
        components.get("schemas"), dict
    ):
        raise ParityError("OpenAPI components are absent")
    problem = components["schemas"].get("Problem")
    _validate_problem_schema(
        problem, [entry["name"] for entry in errors], "OpenAPI Problem"
    )
    for envelope in ("OperationRequest", "OperationResponse", "OperationEvent"):
        schema = components["schemas"].get(envelope)
        operation_property = (
            schema.get("properties", {}).get("operation_id")
            if isinstance(schema, dict)
            else None
        )
        if (
            not isinstance(operation_property, dict)
            or operation_property.get("type") != "string"
            or operation_property.get("maxLength") != 128
        ):
            raise ParityError(f"OpenAPI {envelope} operation identity bound drifted")


def _validate_proto(reader: RepositoryReader, operations: list[Operation]) -> None:
    packaged = reader.text("schemas/proto/cigar_service.proto")
    runtime = reader.text("crates/cigar-api/proto/cigar_service.proto")
    if packaged != runtime:
        raise ParityError("packaged and runtime service Proto files differ")
    pattern = re.compile(
        r"^\s*// (GET|POST) (\S+) \| operation_id=([a-z][A-Za-z0-9]*) "
        r"\| mutation=(true|false) \| idempotency=(required|not_applicable) "
        r"\| revision=(none|required) \| auth=(tenant|operator|health|anonymous)\n"
        r"\s*rpc ([A-Z][A-Za-z0-9]*)\(OperationRequest\) returns \((stream )?(OperationResponse|OperationEvent)\);$",
        re.MULTILINE,
    )
    observed = pattern.findall(packaged)
    if len(observed) != OPERATION_COUNT:
        raise ParityError("Proto operation annotations or RPC count drifted")
    for operation, row in zip(operations, observed, strict=True):
        (
            method,
            path,
            operation_id,
            mutation,
            idempotency,
            revision,
            auth,
            rpc,
            stream_prefix,
            response,
        ) = row
        expected_response = (
            "OperationEvent"
            if operation.stream == "server_stream"
            else "OperationResponse"
        )
        if (
            method,
            path,
            operation_id,
            mutation,
            idempotency,
            revision,
            auth,
            rpc,
            response,
        ) != (
            operation.http_method,
            operation.http_path,
            operation.operation_id,
            str(operation.mutation).lower(),
            operation.idempotency,
            operation.revision,
            operation.auth,
            operation.rpc,
            expected_response,
        ) or bool(stream_prefix) != (operation.stream == "server_stream"):
            raise ParityError(f"Proto semantics drifted for {operation.operation_id}")


def _validate_rust(reader: RepositoryReader, operations: list[Operation]) -> None:
    generated = reader.text("crates/cigar-api/src/generated/operations.rs")
    block = re.compile(
        r"OperationContract \{\s*service: \"([^\"]+)\",\s*rpc: \"([^\"]+)\",\s*"
        r"operation_id: \"([^\"]+)\",\s*http_method: HttpMethod::(Get|Post),\s*"
        r"http_path: \"([^\"]+)\",\s*mutation: (true|false),\s*"
        r"idempotency_requirement: IdempotencyRequirement::(Required|NotApplicable),\s*"
        r"revision_requirement: RevisionRequirement::(None|Required),\s*"
        r"stream_kind: StreamKind::(Unary|ServerStream),\s*auth_class: AuthClass::(Tenant|Operator|Health|Anonymous),\s*\}",
        re.MULTILINE,
    )
    observed = block.findall(generated)
    if len(observed) != OPERATION_COUNT:
        raise ParityError("Rust generated operation registry count drifted")
    for operation, row in zip(operations, observed, strict=True):
        expected = (
            operation.service,
            operation.rpc,
            operation.operation_id,
            operation.http_method.title(),
            operation.http_path,
            str(operation.mutation).lower(),
            "Required" if operation.mutation else "NotApplicable",
            operation.revision.title(),
            "ServerStream" if operation.stream == "server_stream" else "Unary",
            operation.auth.title(),
        )
        if row != expected:
            raise ParityError(
                f"Rust generated semantics drifted for {operation.operation_id}"
            )
    if generated.count("pub fn is_known_operation_id(operation_id: &str) -> bool") != 1:
        raise ParityError(
            "Rust audit/telemetry operation lookup is absent or duplicated"
        )

    typed = reader.text("crates/cigar-api/src/typed.rs")
    typed_rows = re.findall(
        r"^\s*([A-Z][A-Za-z0-9]*Operation) => \(\"([^\"]+)\", ([A-Z][A-Za-z0-9]*), \"([^\"]+)\", "
        r"([A-Z][A-Za-z0-9]*), \"([^\"]+)\", ([A-Z][A-Za-z0-9]*), (None|Some\(\"[^\"]+\"\))\),$",
        typed,
        re.MULTILINE,
    )
    if len(typed_rows) != OPERATION_COUNT:
        raise ParityError("Rust typed operation mapping count drifted")
    for operation, row in zip(operations, typed_rows, strict=True):
        (
            marker,
            operation_id,
            request,
            request_name,
            response,
            response_name,
            event,
            event_name,
        ) = row
        expected_event = operation.event_type or "NoEvent"
        expected_event_name = (
            f'Some("{operation.event_type}")' if operation.event_type else "None"
        )
        if row != (
            f"{operation.rpc}Operation",
            operation.operation_id,
            operation.request_type,
            operation.request_type,
            operation.response_type,
            operation.response_type,
            expected_event,
            expected_event_name,
        ):
            raise ParityError(
                f"Rust typed payload mapping drifted for {operation.operation_id}"
            )


def _projection_rows(
    reader: RepositoryReader, operations: list[Operation]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    authority = _exact_keys(
        reader.json("spec/api/interface-projections-v1.json"),
        {"schema_version", "status", "cli", "mcp"},
        "interface projection authority",
    )
    if authority["schema_version"] != 1 or authority["status"] != "development-closed":
        raise ParityError("interface projection authority identity drifted")
    operation_by_id = {operation.operation_id: operation for operation in operations}
    output: list[list[dict[str, Any]]] = []
    for surface, count in (("cli", CLI_MAPPING_COUNT), ("mcp", MCP_MAPPING_COUNT)):
        section = _exact_keys(
            authority[surface], {"mapping_count", "mappings"}, f"{surface} projection"
        )
        mappings = section["mappings"]
        if (
            section["mapping_count"] != count
            or not isinstance(mappings, list)
            or len(mappings) != count
        ):
            raise ParityError(f"{surface} mapping count drifted")
        names: list[str] = []
        for row in mappings:
            if not isinstance(row, dict):
                raise ParityError(f"{surface} mapping is not an object")
            required = {"exposed_name", "operation_id", "operation_kind"}
            allowed = required | (
                {"alias_of"} if surface == "cli" else {"authority_lane"}
            )
            if not required.issubset(row) or not set(row).issubset(allowed):
                raise ParityError(f"{surface} mapping fields drifted")
            operation = operation_by_id.get(row["operation_id"])
            expected_kind = "mutation" if operation and operation.mutation else "read"
            if operation is None or row["operation_kind"] != expected_kind:
                raise ParityError(
                    f"{surface} mapping semantics drifted for {row.get('exposed_name')}"
                )
            names.append(row["exposed_name"])
        _unique(names, count, f"{surface} exposed names")
        if surface == "cli":
            if len({row["operation_id"] for row in mappings}) != CLI_OPERATION_COUNT:
                raise ParityError("CLI operation coverage drifted")
            by_name = {row["exposed_name"]: row for row in mappings}
            for row in mappings:
                alias = row.get("alias_of")
                if alias is not None and (
                    alias not in by_name
                    or by_name[alias]["operation_id"] != row["operation_id"]
                    or by_name[alias]["operation_kind"] != row["operation_kind"]
                ):
                    raise ParityError(f"CLI alias drifted for {row['exposed_name']}")
        elif len({row["operation_id"] for row in mappings}) != MCP_MAPPING_COUNT:
            raise ParityError("MCP operation coverage drifted")
        output.append(mappings)
    return output[0], output[1]


def _parse_generated_mapping(text: str, kind: str) -> list[dict[str, Any]]:
    if kind == "cli":
        pattern = re.compile(
            r"CliOperationMapping \{\s*exposed_name: \"([^\"]+)\",\s*operation_id: \"([^\"]+)\",\s*mutation: (true|false),\s*\}",
            re.MULTILINE,
        )
    else:
        pattern = re.compile(
            r"McpOperationMapping \{\s*exposed_name: \"([^\"]+)\",\s*operation_id: \"([^\"]+)\",\s*mutation: (true|false),\s*authority_lane: \"([^\"]+)\",\s*\}",
            re.MULTILINE,
        )
    rows = []
    for match in pattern.findall(text):
        row = {
            "exposed_name": match[0],
            "operation_id": match[1],
            "operation_kind": "mutation" if match[2] == "true" else "read",
        }
        if kind == "mcp":
            row["authority_lane"] = match[3]
        rows.append(row)
    return rows


def _validate_cli_mcp(
    reader: RepositoryReader, cli: list[dict[str, Any]], mcp: list[dict[str, Any]]
) -> None:
    observed_cli = _parse_generated_mapping(
        reader.text("crates/cigar-cli/src/generated/operation_mappings.rs"), "cli"
    )
    expected_cli = [
        {key: value for key, value in row.items() if key != "alias_of"} for row in cli
    ]
    if observed_cli != expected_cli:
        raise ParityError("generated CLI operation projection drifted")
    command_source = reader.text("crates/cigar-cli/src/command.rs")
    full_source = command_source.split("Compile-time closed initial-beta surface", 1)[0]
    exposed_commands = set(
        re.findall(r'CommandSpec::operation\("([^\"]+)"', full_source)
    )
    if exposed_commands != {row["exposed_name"] for row in cli}:
        raise ParityError(
            "CLI runtime command and generated operation projections drifted"
        )

    observed_mcp = _parse_generated_mapping(
        reader.text("crates/cigar-mcp/src/generated/operation_mappings.rs"), "mcp"
    )
    if observed_mcp != mcp:
        raise ParityError("generated MCP operation projection drifted")
    server = reader.text("crates/cigar-mcp/src/server.rs")
    match = re.search(
        r"const TOOLS: \[ToolSpec; 10\] = \[(.*?)\n\];", server, re.DOTALL
    )
    tool_names = (
        re.findall(r'^\s*name: "([^"]+)",$', match.group(1), re.MULTILINE)
        if match
        else []
    )
    if tool_names != [row["exposed_name"] for row in mcp]:
        raise ParityError(
            "MCP runtime tool and generated operation projections drifted"
        )


def _expected_sdk_row(operation: Operation) -> dict[str, Any]:
    return {
        "operationId": operation.operation_id,
        "rpc": operation.rpc,
        "service": operation.service,
        "httpMethod": operation.http_method,
        "httpPath": operation.http_path,
        "mutation": operation.mutation,
        "idempotencyRequired": operation.mutation,
        "revisionRequired": operation.revision == "required",
        "stream": operation.stream == "server_stream",
        "authClass": operation.auth,
        "requestType": operation.request_type,
        "responseType": operation.response_type,
        "eventType": operation.event_type,
        "requestMaxBytes": operation.request_max_bytes,
        "responseMaxBytes": operation.response_max_bytes,
        "eventMaxBytes": operation.event_max_bytes,
        "pathFields": list(operation.path_fields),
    }


def _python_dict_calls(text: str, assignment: str) -> dict[str, dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError as error:
        raise ParityError(f"generated Python {assignment} is invalid") from error
    node: ast.Dict | None = None
    for statement in tree.body:
        target_name = None
        value = None
        if isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            target_name, value = statement.target.id, statement.value
        elif (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            target_name, value = statement.targets[0].id, statement.value
        if target_name == assignment and isinstance(value, ast.Dict):
            node = value
            break
    if node is None:
        raise ParityError(f"generated Python {assignment} mapping is absent")
    output: dict[str, dict[str, Any]] = {}
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        key = ast.literal_eval(key_node)
        if (
            not isinstance(key, str)
            or key in output
            or not isinstance(value_node, ast.Call)
        ):
            raise ParityError(f"generated Python {assignment} entry is invalid")
        if value_node.keywords and len(value_node.args) == 0:
            values = {
                keyword.arg: ast.literal_eval(keyword.value)
                for keyword in value_node.keywords
                if keyword.arg
            }
        elif (
            len(value_node.args) == 0
            and isinstance(value_node.func, ast.Name)
            and value_node.func.id == "OperationDefinition"
        ):
            values = {}
        elif (
            len(value_node.args) == 0
            and isinstance(value_node.func, ast.Name)
            and value_node.func.id == "ErrorDefinition"
        ):
            values = {
                keyword.arg: ast.literal_eval(keyword.value)
                for keyword in value_node.keywords
                if keyword.arg
            }
        else:
            values = {}
        # OperationDefinition(**{...}) stores the mapping as a starred keyword.
        if len(value_node.keywords) == 1 and value_node.keywords[0].arg is None:
            literal = ast.literal_eval(value_node.keywords[0].value)
            if isinstance(literal, dict):
                values = literal
        if not values:
            raise ParityError(f"generated Python {assignment} entry is not literal")
        output[key] = values
    return output


def _validate_sdks(
    reader: RepositoryReader, operations: list[Operation], errors: list[dict[str, Any]]
) -> None:
    capability = _exact_keys(
        reader.json("sdk/capabilities-v1.json"),
        {
            "schema_version",
            "api_status",
            "operation_count",
            "type_count",
            "operations",
            "sdks",
        },
        "SDK capability registry",
    )
    for copy in (
        "sdk/go/capabilities-v1.json",
        "sdk/python/src/cigar_sdk/capabilities-v1.json",
    ):
        if reader.json(copy) != capability:
            raise ParityError(f"packaged SDK capability registry drifted: {copy}")
    operation_ids = [operation.operation_id for operation in operations]
    type_names = sorted(
        {
            schema
            for operation in operations
            for schema in (
                operation.request_type,
                operation.response_type,
                operation.event_type,
            )
            if schema is not None
        }
    )
    if len(type_names) != 70:
        raise ParityError("SDK nominal payload type count drifted")
    expected_capability_rows = [
        {
            "operation_id": operation.operation_id,
            "request_type": operation.request_type,
            "response_type": operation.response_type,
            "event_type": operation.event_type,
            "stream": operation.stream,
            "retry_class": (
                "never_automatic"
                if operation.operation_id == "dispatchEffect"
                else "idempotency_bound_mutation"
                if operation.mutation
                else "safe_read"
            ),
        }
        for operation in operations
    ]
    if (
        not isinstance(capability, dict)
        or capability.get("schema_version") != "cigar.sdk-capabilities.v1"
        or capability.get("api_status") != "frozen-v1"
        or capability.get("operation_count") != OPERATION_COUNT
        or capability.get("type_count") != 70
        or capability.get("operations") != expected_capability_rows
        or set(capability.get("sdks", {})) != {"rust", "typescript", "python", "go"}
    ):
        raise ParityError("SDK capability operation mapping drifted")
    expected_transports = {
        "rust": ["embedded", "http"],
        "typescript": ["http"],
        "python": ["http"],
        "go": ["http", "grpc"],
    }
    expected_modules = {
        "typescript": "@cigar/sdk",
        "python": "cigar_sdk",
        "go": "github.com/CIGAR/cigar/sdk/go",
    }
    required_features = {
        "deadlines",
        "pagination",
        "stream_resume",
        "typed_errors",
        "idempotency",
        "safe_retry",
        "version_negotiation",
        "digest_verification",
        "delta_verification",
    }
    for language, raw_sdk in capability["sdks"].items():
        sdk_fields = {
            "operation_count",
            "type_count",
            "model_source",
            "nominal_models",
            "runtime_schema_validation",
            "operations",
            "types",
            "transport",
            "features",
        }
        if language != "rust":
            sdk_fields.add("module")
        sdk = _exact_keys(
            raw_sdk,
            sdk_fields,
            f"{language} SDK capability",
        )
        if (
            sdk["operation_count"] != OPERATION_COUNT
            or sdk["type_count"] != len(type_names)
            or sdk["model_source"] != "schemas/json/api-payload-types-v1.schema.json"
            or sdk["nominal_models"] is not True
            or sdk["runtime_schema_validation"] is not True
            or sdk["operations"] != operation_ids
            or sdk["types"] != type_names
            or sdk["transport"] != expected_transports[language]
            or (language != "rust" and sdk["module"] != expected_modules[language])
            or not isinstance(sdk["features"], list)
            or not required_features.issubset(sdk["features"])
        ):
            raise ParityError(f"SDK operation/error capability drifted for {language}")

    expected_ts = {
        operation.operation_id: _expected_sdk_row(operation) for operation in operations
    }
    ts_text = reader.text("sdk/typescript/src/generated/operations.ts")
    ts_rows: dict[str, Any] = {}
    for name, raw in re.findall(
        r"^  ([a-z][A-Za-z0-9]*): (\{.*\}),$", ts_text, re.MULTILINE
    ):
        if name in ts_rows:
            raise ParityError("duplicate TypeScript generated operation")
        ts_rows[name] = json.loads(raw, object_pairs_hook=_reject_duplicate)
    if ts_rows != expected_ts:
        raise ParityError("TypeScript generated operation semantics drifted")

    expected_python = {
        operation.operation_id: {
            "operation_id": operation.operation_id,
            "rpc": operation.rpc,
            "service": operation.service,
            "http_method": operation.http_method,
            "http_path": operation.http_path,
            "mutation": operation.mutation,
            "idempotency_required": operation.mutation,
            "revision_required": operation.revision == "required",
            "stream": operation.stream == "server_stream",
            "auth_class": operation.auth,
            "request_type": operation.request_type,
            "response_type": operation.response_type,
            "event_type": operation.event_type,
            "request_max_bytes": operation.request_max_bytes,
            "response_max_bytes": operation.response_max_bytes,
            "event_max_bytes": operation.event_max_bytes,
            "path_fields": operation.path_fields,
        }
        for operation in operations
    }
    python_operations = _python_dict_calls(
        reader.text("sdk/python/src/cigar_sdk/generated/operations.py"), "OPERATIONS"
    )
    if python_operations != expected_python:
        raise ParityError("Python generated operation semantics drifted")

    go_text = reader.text("sdk/go/operations_gen.go")
    go_operation_ids = re.findall(
        r'^\s*"([a-z][A-Za-z0-9]*)"\s*:', go_text, re.MULTILINE
    )
    if go_operation_ids != operation_ids:
        raise ParityError("Go generated operation inventory drifted")
    for operation in operations:
        lines = [
            line
            for line in go_text.splitlines()
            if re.match(rf'^\s*"{re.escape(operation.operation_id)}"\s*:', line)
        ]
        if len(lines) != 1:
            raise ParityError(
                f"Go generated operation is absent or duplicated: {operation.operation_id}"
            )
        line = lines[0]
        required_fragments = (
            f'OperationID: "{operation.operation_id}"',
            f'RPC: "{operation.rpc}"',
            f'Service: "{operation.service}"',
            f'HTTPMethod: "{operation.http_method}"',
            f'HTTPPath: "{operation.http_path}"',
            f"Mutation: {str(operation.mutation).lower()}",
            f"IdempotencyRequired: {str(operation.mutation).lower()}",
            f"RevisionRequired: {str(operation.revision == 'required').lower()}",
            f"Stream: {str(operation.stream == 'server_stream').lower()}",
            f'AuthClass: "{operation.auth}"',
            f'RequestType: "{operation.request_type}"',
            f'ResponseType: "{operation.response_type}"',
            f'EventType: "{operation.event_type or ""}"',
            f"RequestMaxBytes: {operation.request_max_bytes}",
            f"ResponseMaxBytes: {operation.response_max_bytes}",
            f"EventMaxBytes: {operation.event_max_bytes}",
            "PathFields: []string{"
            + ", ".join(json.dumps(field) for field in operation.path_fields)
            + "}",
        )
        if any(fragment not in line for fragment in required_fragments):
            raise ParityError(
                f"Go generated operation semantics drifted: {operation.operation_id}"
            )

    expected_error_ts = {
        entry["name"]: {
            "numericCode": entry["code"],
            "httpStatus": entry["http"],
            "retry": entry["retry"],
            "message": entry["message"],
            "remediation": entry["remediation"],
        }
        for entry in errors
    }
    ts_errors: dict[str, Any] = {}
    for name, raw in re.findall(
        r"^  ([A-Z][A-Z0-9_]+): (\{.*\}),$",
        reader.text("sdk/typescript/src/generated/errors.ts"),
        re.MULTILINE,
    ):
        if name in ts_errors:
            raise ParityError("duplicate TypeScript generated error")
        ts_errors[name] = json.loads(raw, object_pairs_hook=_reject_duplicate)
    if ts_errors != expected_error_ts:
        raise ParityError("TypeScript generated error catalog drifted")
    expected_error_python = {
        entry["name"]: {
            "numeric_code": entry["code"],
            "http_status": entry["http"],
            "retry": entry["retry"],
            "message": entry["message"],
            "remediation": entry["remediation"],
        }
        for entry in errors
    }
    if (
        _python_dict_calls(
            reader.text("sdk/python/src/cigar_sdk/generated/errors.py"), "ERROR_CATALOG"
        )
        != expected_error_python
    ):
        raise ParityError("Python generated error catalog drifted")
    go_errors = reader.text("sdk/go/errors_gen.go")
    go_error_names = re.findall(r'^\s*"([A-Z][A-Z0-9_]+)"\s*:', go_errors, re.MULTILINE)
    if go_error_names != [entry["name"] for entry in errors]:
        raise ParityError("Go generated error inventory drifted")
    for entry in errors:
        lines = [
            line
            for line in go_errors.splitlines()
            if re.match(rf'^\s*"{entry["name"]}"\s*:', line)
        ]
        fragments = (
            f"NumericCode: {entry['code']}",
            f"HTTPStatus: {entry['http']}",
            f"GRPCStatus: {json.dumps(entry['grpc'])}",
            f"Retry: {json.dumps(entry['retry'])}",
            f"Message: {json.dumps(entry['message'])}",
            f"Remediation: {json.dumps(entry['remediation'])}",
        )
        if len(lines) != 1 or any(fragment not in lines[0] for fragment in fragments):
            raise ParityError(f"Go generated error semantics drifted: {entry['name']}")


def _error_registry(reader: RepositoryReader) -> list[dict[str, Any]]:
    document = _exact_keys(
        reader.json("schemas/openapi/error-registry-v1.json"),
        {"schema_version", "status", "generator", "errors"},
        "error registry",
    )
    errors = document["errors"]
    if (
        document["schema_version"] != 1
        or not isinstance(errors, list)
        or len(errors) != ERROR_COUNT
    ):
        raise ParityError("error registry identity or count drifted")
    required = {
        "code",
        "name",
        "http",
        "grpc",
        "retry",
        "message",
        "remediation",
        "disclose_identity",
    }
    for entry in errors:
        _exact_keys(entry, required, "error registry entry")
        if not isinstance(entry["code"], int) or isinstance(entry["code"], bool):
            raise ParityError("error numeric code is invalid")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]+", entry["name"]):
            raise ParityError("error symbol is invalid")
        if entry["disclose_identity"] is not False:
            raise ParityError("public error unexpectedly permits identity disclosure")
    if (
        len({entry["code"] for entry in errors}) != ERROR_COUNT
        or len({entry["name"] for entry in errors}) != ERROR_COUNT
    ):
        raise ParityError("error codes or symbols are duplicated")
    _validate_problem_schema(
        reader.json("schemas/json/problem-v1.schema.json"),
        [entry["name"] for entry in errors],
        "JSON Schema Problem",
    )
    return errors


def _collect_symbolic_constants(value: Any) -> list[str]:
    output: list[str] = []
    if isinstance(value, dict):
        constant = value.get("const")
        if isinstance(constant, str) and re.fullmatch(r"[A-Z][A-Z0-9_]+", constant):
            output.append(constant)
        for child in value.values():
            output.extend(_collect_symbolic_constants(child))
    elif isinstance(value, list):
        for child in value:
            output.extend(_collect_symbolic_constants(child))
    return output


def _validate_problem_schema(value: Any, error_symbols: list[str], label: str) -> None:
    if not isinstance(value, dict):
        raise ParityError(f"{label} is absent or invalid")
    required = value.get("required")
    if (
        not isinstance(required, list)
        or len(required) != len(PROBLEM_FIELDS)
        or set(required) != PROBLEM_FIELDS
    ):
        raise ParityError(f"{label} required fields drifted")
    properties = value.get("properties")
    if (
        not isinstance(properties, dict)
        or set(properties) != PROBLEM_FIELDS
        or value.get("additionalProperties") is not False
    ):
        raise ParityError(f"{label} property set drifted")
    constants = _collect_symbolic_constants(value)
    if constants != error_symbols:
        raise ParityError(f"{label} error-code vocabulary drifted")


def _validate_dashboard(
    reader: RepositoryReader, operations: list[Operation], errors: list[dict[str, Any]]
) -> None:
    document = reader.json(
        "crates/cigar-dashboard/src/generated/protocol-catalog-v1.json"
    )
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "cigar.dashboard-protocol.v1"
        or document.get("operation_count") != OPERATION_COUNT
        or document.get("service_count") != SERVICE_COUNT
        or document.get("error_count") != ERROR_COUNT
        or not isinstance(document.get("services"), list)
    ):
        raise ParityError("dashboard protocol projection identity or count drifted")
    observed: list[dict[str, Any]] = []
    for service in document["services"]:
        if not isinstance(service, dict) or not isinstance(
            service.get("operations"), list
        ):
            raise ParityError("dashboard service projection is invalid")
        observed.extend(service["operations"])
    if len(observed) != OPERATION_COUNT:
        raise ParityError("dashboard operation projection count drifted")
    for operation, row in zip(operations, observed, strict=True):
        expected = {
            "service": operation.service,
            "rpc": operation.rpc,
            "operation_id": operation.operation_id,
            "http_method": operation.http_method,
            "http_path": operation.http_path,
            "mutation": operation.mutation,
            "idempotency": operation.idempotency,
            "revision": operation.revision,
            "stream": operation.stream,
            "auth": operation.auth,
        }
        if any(row.get(key) != value for key, value in expected.items()):
            raise ParityError(
                f"dashboard operation semantics drifted for {operation.operation_id}"
            )
        payload = row.get("payload")
        if not isinstance(payload, dict) or any(
            payload.get(key) != value
            for key, value in {
                "request_schema": operation.request_type,
                "response_schema": operation.response_type,
                "event_schema": operation.event_type,
                "request_max_bytes": operation.request_max_bytes,
                "response_max_bytes": operation.response_max_bytes,
                "event_max_bytes": operation.event_max_bytes,
            }.items()
        ):
            raise ParityError(
                f"dashboard payload semantics drifted for {operation.operation_id}"
            )
    expected_errors = [
        {
            "numeric_code": entry["code"],
            "symbol": entry["name"],
            "http_status": entry["http"],
            "grpc_status": entry["grpc"],
            "retry": entry["retry"],
            "disclose_identity": entry["disclose_identity"],
        }
        for entry in errors
    ]
    if document.get("errors") != expected_errors:
        raise ParityError("dashboard error projection drifted")


def _validate_observability(
    reader: RepositoryReader, operations: list[Operation]
) -> None:
    context = reader.text("crates/cigar-api/src/context.rs")
    if context.count('.field("operation", &self.operation)') != 1:
        raise ParityError(
            "request log/debug context lost its single operation identity"
        )
    metrics = reader.text("crates/cigar-observe/src/lib.rs")
    start = metrics.find("pub const DAEMON_METRICS: &[MetricDefinition] = &[")
    end = metrics.find("\n];", start)
    if start < 0 or end < 0:
        raise ParityError("daemon metric catalog is absent")
    catalog = metrics[start:end]
    family_names = re.findall(
        r'MetricDefinition::(?:counter|gauge)\(\s*"([a-z][a-z0-9_]*)"', catalog
    )
    label_rows = re.findall(r'label\("([a-z][a-z0-9_]*)", ([A-Z][A-Z0-9_]*)\)', catalog)
    labels = {key for key, _constant in label_rows}
    value_domains: dict[str, tuple[str, ...]] = {}
    for constant, raw_values in re.findall(
        r"(?:pub )?const ([A-Z][A-Z0-9_]*): &\[&str\] = &\[(.*?)\];",
        metrics,
        re.DOTALL,
    ):
        values = tuple(re.findall(r'"([a-z][a-z0-9_]*)"', raw_values))
        if values:
            value_domains[constant] = values
    if (
        len(family_names) != METRIC_FAMILY_COUNT
        or len(set(family_names)) != METRIC_FAMILY_COUNT
        or family_names.count("cigar_api_requests_total") != 1
        or labels != METRIC_LABEL_KEYS
    ):
        raise ParityError("metric family or closed label vocabulary drifted")
    labelled_series = 0
    for _key, constant in label_rows:
        values = value_domains.get(constant)
        if values is None or len(values) > 16 or len(values) != len(set(values)):
            raise ParityError(f"metric label domain drifted: {constant}")
        labelled_series += len(values)
    series_maximum = len(family_names) - len(label_rows) + labelled_series
    if series_maximum != METRIC_SERIES_MAXIMUM:
        raise ParityError("metric maximum series bound drifted")
    if (
        "operation" in labels
        or 'label("operation"' in metrics
        or 'label("operation_id"' in metrics
    ):
        raise ParityError("metrics introduced a high-cardinality operation dimension")
    if metrics.count("pub fn maximum_daemon_series() -> usize") != 1:
        raise ParityError("aggregate API metric or series-bound function is absent")
    # Bind the policy to the current complete registry without introducing operation labels.
    if len(operations) != OPERATION_COUNT:
        raise ParityError(
            "observability validation did not receive the complete registry"
        )


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def validate(root: Path) -> dict[str, Any]:
    reader = RepositoryReader(root)
    operations, _payloads = _catalog(reader)
    errors = _error_registry(reader)
    _validate_openapi(reader, operations, errors)
    _validate_proto(reader, operations)
    _validate_rust(reader, operations)
    cli, mcp = _projection_rows(reader, operations)
    _validate_cli_mcp(reader, cli, mcp)
    _validate_sdks(reader, operations, errors)
    _validate_dashboard(reader, operations, errors)
    _validate_observability(reader, operations)
    # Bind the validator itself and reject accidental omissions in the reviewed source list.
    for relative in SOURCE_FILES:
        if relative not in reader.digests:
            reader.bytes(relative)
    if set(reader.digests) != set(SOURCE_FILES):
        unexpected = sorted(set(reader.digests).difference(SOURCE_FILES))
        raise ParityError(
            f"unreviewed operation-surface source files were consumed: {unexpected}"
        )

    normalized = [asdict(operation) for operation in operations]
    semantic_sha256 = hashlib.sha256(
        _canonical({"operations": normalized, "errors": errors})
    ).hexdigest()
    source_rows = [
        {"path": path, "sha256": reader.digests[path]}
        for path in sorted(reader.digests)
    ]
    source_sha256 = hashlib.sha256(_canonical(source_rows)).hexdigest()
    return {
        "schema_version": "cigar.operation-surface-parity.v1",
        "status": "pass",
        "profile": "development-source-macos-aarch64",
        "release_eligible": False,
        "candidate_frozen": False,
        "operation_count": OPERATION_COUNT,
        "service_count": SERVICE_COUNT,
        "error_count": ERROR_COUNT,
        "semantic_sha256": semantic_sha256,
        "source_binding": {
            "file_count": len(source_rows),
            "sha256": source_sha256,
        },
        "surfaces": {
            "http": {"coverage": OPERATION_COUNT, "mode": "complete"},
            "grpc": {"coverage": OPERATION_COUNT, "mode": "complete"},
            "rust_typed": {"coverage": OPERATION_COUNT, "mode": "complete"},
            "sdk": {
                "coverage": OPERATION_COUNT,
                "languages": ["go", "python", "rust", "typescript"],
            },
            "cli": {
                "mapping_count": CLI_MAPPING_COUNT,
                "operation_count": CLI_OPERATION_COUNT,
                "mode": "closed-subset",
            },
            "mcp": {
                "mapping_count": MCP_MAPPING_COUNT,
                "operation_count": MCP_MAPPING_COUNT,
                "mode": "closed-subset",
            },
            "logs": {"coverage": OPERATION_COUNT, "mode": "single-generated-identity"},
            "metrics": {
                "coverage": OPERATION_COUNT,
                "family_count": METRIC_FAMILY_COUNT,
                "maximum_series": METRIC_SERIES_MAXIMUM,
                "mode": "aggregate-no-operation-label",
            },
            "errors": {
                "operation_count": OPERATION_COUNT,
                "error_count": ERROR_COUNT,
                "mode": "shared-closed-catalog",
            },
        },
    }


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_root())
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        report = validate(arguments.root)
    except ParityError as error:
        raise SystemExit(f"operation surface parity failed: {error}") from error
    if not arguments.quiet:
        sys.stdout.buffer.write(_canonical(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
