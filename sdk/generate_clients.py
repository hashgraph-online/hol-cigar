#!/usr/bin/env python3
"""Generate the non-Rust SDK operation surfaces and parity manifest.

The frozen operation registry is authoritative.  This generator deliberately does
not infer semantics from OpenAPI prose: it joins the operation and payload
registries by operation_id and emits deterministic, checked-in files.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdk"
PAYLOAD_DEFINITIONS: dict[str, dict[str, Any]] = {}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def quote(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def operations() -> list[dict[str, Any]]:
    registry = load_json(ROOT / "spec/api/operations-v1.json")
    payloads = load_json(ROOT / "spec/api/operation-payloads-v1.json")
    payload_by_id = {item["operation_id"]: item for item in payloads["operations"]}
    result: list[dict[str, Any]] = []
    for service in registry["services"]:
        for operation in service["operations"]:
            payload = payload_by_id.get(operation["operation_id"])
            if payload is None:
                raise ValueError(
                    f"missing payload mapping for {operation['operation_id']}"
                )
            result.append({"service": service["name"], **operation, **payload})
    if (
        len(result) != registry["operation_count"]
        or len(result) != payloads["operation_count"]
    ):
        raise ValueError("operation registries disagree")
    if len({item["operation_id"] for item in result}) != len(result):
        raise ValueError("operation ids are not unique")
    return result


def errors() -> list[dict[str, Any]]:
    registry = load_json(ROOT / "schemas/openapi/error-registry-v1.json")
    result = list(registry["errors"])
    if not result or len({item["name"] for item in result}) != len(result):
        raise ValueError("error registry is empty or duplicated")
    return result


def payload_schema_bundle() -> dict[str, Any]:
    bundle = deepcopy(load_json(ROOT / "schemas/json/api-payload-types-v1.schema.json"))
    if (
        bundle.get("schema_version") != "cigar.api-payload-schema-bundle.v1"
        or bundle.get("operation_count") != 45
        or bundle.get("type_count") != 70
        or len(bundle.get("types", {})) != 70
    ):
        raise ValueError("payload schema bundle is incomplete")

    # Rust omits Option::None on the wire and the deterministic-CBOR profile has
    # no null state.  Schemars describes Option as nullable even when serde skips
    # it, so normalize generated SDK contracts to the actual serialization form.
    def omission_only(value: Any) -> Any:
        if isinstance(value, list):
            return [omission_only(item) for item in value]
        if not isinstance(value, dict):
            return value
        normalized = {key: omission_only(child) for key, child in value.items()}
        declared = normalized.get("type")
        if isinstance(declared, list) and "null" in declared:
            remaining = [kind for kind in declared if kind != "null"]
            normalized["type"] = remaining[0] if len(remaining) == 1 else remaining
        for keyword in ("oneOf", "anyOf"):
            variants = normalized.get(keyword)
            if isinstance(variants, list):
                normalized[keyword] = [
                    item for item in variants if schema_types(item) != ["null"]
                ]
        return normalized

    bundle["types"] = {
        name: omission_only(schema) for name, schema in bundle["types"].items()
    }
    PAYLOAD_DEFINITIONS.clear()
    for schema in bundle["types"].values():
        for name, definition in schema.get("$defs", {}).items():
            existing = PAYLOAD_DEFINITIONS.get(name)
            if existing is not None and json.dumps(
                existing, sort_keys=True
            ) != json.dumps(definition, sort_keys=True):
                raise ValueError(f"conflicting payload definition {name}")
            PAYLOAD_DEFINITIONS[name] = definition
    return bundle


def schema_types(schema: dict[str, Any]) -> list[str]:
    raw = schema.get("type")
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return raw
    return []


def ts_schema_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        name = str(schema["$ref"]).replace("#/$defs/", "")
        definition = PAYLOAD_DEFINITIONS.get(name)
        variants = None if definition is None else definition.get("oneOf")
        if (
            isinstance(variants, list)
            and variants
            and all(isinstance(item, dict) and "const" in item for item in variants)
        ):
            return ts_schema_type(definition)
        return "JsonObject"
    variants = schema.get("oneOf") or schema.get("anyOf")
    if isinstance(variants, list):
        return " | ".join(f"({ts_schema_type(item)})" for item in variants)
    if "const" in schema:
        return quote(schema["const"])
    kinds = schema_types(schema)
    if len(kinds) > 1:
        return " | ".join(
            "null" if kind == "null" else ts_schema_type({**schema, "type": kind})
            for kind in kinds
        )
    kind = kinds[0] if kinds else ""
    if kind == "string":
        return "string"
    if kind in {"integer", "number"}:
        return "bigint" if schema.get("format") in {"int64", "uint64"} else "number"
    if kind == "boolean":
        return "boolean"
    if kind == "null":
        return "null"
    if kind == "array":
        items = schema.get("items", {})
        return f"readonly ({ts_schema_type(items)})[]"
    if kind == "object" or "properties" in schema or "additionalProperties" in schema:
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        fields = [
            f"readonly {quote(name)}{'?' if name not in required else ''}: {ts_schema_type(child)};"
            for name, child in properties.items()
        ]
        additional = schema.get("additionalProperties")
        if not properties and isinstance(additional, dict):
            return f"Readonly<Record<string, {ts_schema_type(additional)}>>"
        if not properties and additional is not False:
            return "JsonObject"
        return "{ " + " ".join(fields) + " }"
    return "JsonValue"


def generate_typescript_models(bundle: dict[str, Any]) -> None:
    target = SDK / "typescript/src/generated/models.ts"
    target.parent.mkdir(parents=True, exist_ok=True)
    declarations: list[str] = []
    for name, schema in bundle["types"].items():
        if schema_types(schema) == ["object"]:
            required = set(schema.get("required", []))
            fields = "\n".join(
                f"  readonly {quote(field)}{'?' if field not in required else ''}: {ts_schema_type(child)};"
                for field, child in schema.get("properties", {}).items()
            )
            declarations.append(f"export interface {name} {{\n{fields}\n}}")
        else:
            declarations.append(f"export type {name} = {ts_schema_type(schema)};")
        declarations.append(
            f"export const {name}: PayloadModel<{name}> = payloadModel({quote(name)}, {json.dumps(schema, separators=(',', ':'))});"
        )
    content = (
        r"""// @generated by sdk/generate_clients.py; do not edit.
import { ValidationError } from "../errors.js";

export type JsonValue = boolean | bigint | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject { readonly [key: string]: JsonValue; }
export interface PayloadModel<T> {
  readonly name: string;
  readonly schema: Readonly<Record<string, unknown>>;
  create(value: T): Readonly<T>;
}
function fail(path: string, message: string): never { throw new ValidationError(`${path}: ${message}`); }
function matchesSchemaPattern(pattern: unknown, value: string, path: string): boolean {
  switch (pattern) {
    case "^1220[0-9a-f]{64}$": return /^1220[0-9a-f]{64}$/u.test(value);
    case "^[!-~]+$": return /^[!-~]+$/u.test(value);
    case "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$": return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value);
    case "^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$": return /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/u.test(value);
    case "^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$": return /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u.test(value);
    case "^[A-Za-z0-9._~-]+$": return /^[A-Za-z0-9._~-]+$/u.test(value);
    case "^[A-Za-z][A-Za-z0-9+.-]*:[^\\x00-\\x20]+$": return /^[A-Za-z][A-Za-z0-9+.-]*:[^\x00-\x20]+$/u.test(value);
    case "^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$": return /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*$/u.test(value);
    case "^[a-z0-9][a-z0-9._/-]{0,127}$": return /^[a-z0-9][a-z0-9._\/-]{0,127}$/u.test(value);
    case "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\\.v[1-9][0-9]{0,4}$": return /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\.v[1-9][0-9]{0,4}$/u.test(value);
    case "^[a-z][a-z0-9_]*$": return /^[a-z][a-z0-9_]*$/u.test(value);
    default: fail(path, "schema uses an unsupported pattern");
  }
}
interface ValidationBudget { nodes: number; }
function validateContextBlockReceipts(value: unknown, path: string): void {
  if (!Array.isArray(value)) fail(path, "expected context block array");
  value.forEach((block, index) => {
    if (typeof block !== "object" || block === null || Array.isArray(block)) fail(`${path}/${index}`, "expected context block");
    const record = block as Record<string, unknown>;
    const representation = record["representation"];
    const receiptRequired = representation === "extracted" || representation === "summarized";
    const receiptPresent = Object.hasOwn(record, "transform_receipt");
    if (receiptRequired !== receiptPresent) {
      fail(`${path}/${index}/transform_receipt`, "extracted and summarized representations require exactly one transform receipt");
    }
  });
}
function validateSemantic(name: string, value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return;
  const record = value as Record<string, unknown>;
  if (name === "ContextBundle") {
    validateContextBlockReceipts(record["blocks"], `${name}/blocks`);
  } else if (name === "ContextDeltaResponse") {
    const delta = record["delta"];
    if (typeof delta !== "object" || delta === null || Array.isArray(delta)) fail(`${name}/delta`, "expected context delta");
    validateContextBlockReceipts((delta as Record<string, unknown>)["added_blocks"], `${name}/delta/added_blocks`);
  }
}
function validate(schema: Record<string, unknown>, value: unknown, root: Record<string, unknown>, path: string, depth = 0, budget: ValidationBudget = { nodes: 0 }): void {
  if (depth > 64 || ++budget.nodes > 100_000) fail(path, "payload exceeds nesting or node bounds");
  const reference = schema["$ref"];
  if (typeof reference === "string") {
    const name = reference.replace("#/$defs/", "");
    const definitions = root["$defs"];
    if (typeof definitions !== "object" || definitions === null || Array.isArray(definitions)) fail(path, "schema reference is unresolved");
    const target = (definitions as Record<string, unknown>)[name];
    if (typeof target !== "object" || target === null || Array.isArray(target)) fail(path, "schema reference is unresolved");
    validate(target as Record<string, unknown>, value, root, path, depth + 1, budget);
    return;
  }
  const alternatives = schema["oneOf"] ?? schema["anyOf"];
  if (Array.isArray(alternatives)) {
    let matches = 0;
    for (const alternative of alternatives) {
      try {
        validate(alternative as Record<string, unknown>, value, root, path, depth + 1, budget);
        matches += 1;
      } catch { /* oneOf probe */ }
    }
    if ("oneOf" in schema ? matches !== 1 : matches < 1) fail(path, "value does not match its schema variants");
    return;
  }
  if ("const" in schema && value !== schema["const"]) fail(path, "value differs from its const");
  const declared = schema["type"];
  if (Array.isArray(declared)) {
    let matches = 0;
    for (const kind of declared) {
      try { validate({ ...schema, type: kind }, value, root, path, depth + 1, budget); matches += 1; } catch { /* union probe */ }
    }
    if (matches !== 1) fail(path, "value does not match its type union");
    return;
  }
  if (declared === "null") { if (value !== null) fail(path, "expected null"); return; }
  if (declared === "string") {
    if (typeof value !== "string") fail(path, "expected string");
    const length = Buffer.byteLength(value);
    if (typeof schema["minLength"] === "number" && length < schema["minLength"]) fail(path, "string is too short");
    if (typeof schema["maxLength"] === "number" && length > schema["maxLength"]) fail(path, "string is too long");
    if (schema["pattern"] !== undefined && !matchesSchemaPattern(schema["pattern"], value, path)) fail(path, "string does not match pattern");
    return;
  }
  if (declared === "integer" || declared === "number") {
    const wide = schema["format"] === "int64" || schema["format"] === "uint64";
    let numeric: bigint;
    if (wide && typeof value === "bigint") numeric = value;
    else if (!wide && typeof value === "number" && Number.isSafeInteger(value)) numeric = BigInt(value);
    else fail(path, "expected exact integer");
    if (typeof schema["minimum"] === "number" && numeric < BigInt(schema["minimum"])) fail(path, "integer is below minimum");
    if (typeof schema["maximum"] === "number" && numeric > BigInt(schema["maximum"])) fail(path, "integer exceeds maximum");
    return;
  }
  if (declared === "boolean") { if (typeof value !== "boolean") fail(path, "expected boolean"); return; }
  if (declared === "array") {
    if (!Array.isArray(value)) fail(path, "expected array");
    if (typeof schema["minItems"] === "number" && value.length < schema["minItems"]) fail(path, "array is too short");
    if (typeof schema["maxItems"] === "number" && value.length > schema["maxItems"]) fail(path, "array is too long");
    const itemSchema = schema["items"];
    if (typeof itemSchema === "object" && itemSchema !== null) value.forEach((item, index) => validate(itemSchema as Record<string, unknown>, item, root, `${path}/${index}`, depth + 1, budget));
    return;
  }
  if (declared === "object" || "properties" in schema || "additionalProperties" in schema) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) fail(path, "expected object");
    const record = value as Record<string, unknown>;
    const properties = (schema["properties"] ?? {}) as Record<string, Record<string, unknown>>;
    const patternProperties = (schema["patternProperties"] ?? {}) as Record<string, Record<string, unknown>>;
    const required = new Set(Array.isArray(schema["required"]) ? schema["required"] as string[] : []);
    for (const name of required) if (!(name in record)) fail(`${path}/${name}`, "required field is missing");
    if (typeof schema["minProperties"] === "number" && Object.keys(record).length < schema["minProperties"]) fail(path, "object has too few fields");
    if (typeof schema["maxProperties"] === "number" && Object.keys(record).length > schema["maxProperties"]) fail(path, "object has too many fields");
    for (const [name, child] of Object.entries(record)) {
      const childSchema = properties[name];
      if (childSchema !== undefined) validate(childSchema, child, root, `${path}/${name}`, depth + 1, budget);
      else {
        const matches = Object.entries(patternProperties).filter(([pattern]) => matchesSchemaPattern(pattern, name, path));
        if (matches.length > 0) for (const [, matched] of matches) validate(matched, child, root, `${path}/${name}`, depth + 1, budget);
        else if (schema["additionalProperties"] === false) fail(`${path}/${name}`, "unknown field");
        else if (typeof schema["additionalProperties"] === "object" && schema["additionalProperties"] !== null) validate(schema["additionalProperties"] as Record<string, unknown>, child, root, `${path}/${name}`, depth + 1, budget);
      }
    }
  }
}
function coerce(schema: Record<string, unknown>, value: unknown, root: Record<string, unknown>): unknown {
  const reference = schema["$ref"];
  if (typeof reference === "string") {
    const definitions = root["$defs"] as Record<string, Record<string, unknown>>;
    return coerce(definitions[reference.replace("#/$defs/", "")] ?? {}, value, root);
  }
  const alternatives = schema["oneOf"] ?? schema["anyOf"];
  if (Array.isArray(alternatives)) {
    for (const alternative of alternatives) {
      try { validate(alternative as Record<string, unknown>, value, root, "payload"); return coerce(alternative as Record<string, unknown>, value, root); } catch { /* variant probe */ }
    }
    return value;
  }
  const declared = schema["type"];
  if (Array.isArray(declared)) {
    for (const kind of declared) {
      try { return coerce({ ...schema, type: kind }, value, root); } catch { /* union probe */ }
    }
  }
  if (declared === "integer") {
    const wide = schema["format"] === "int64" || schema["format"] === "uint64";
    if (wide && typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
    if (!wide && typeof value === "bigint" && value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  }
  if (declared === "array" && Array.isArray(value)) {
    const item = schema["items"] as Record<string, unknown> | undefined;
    return item === undefined ? value : value.map((child) => coerce(item, child, root));
  }
  if ((declared === "object" || "properties" in schema) && typeof value === "object" && value !== null && !Array.isArray(value)) {
    const properties = (schema["properties"] ?? {}) as Record<string, Record<string, unknown>>;
    const patterns = (schema["patternProperties"] ?? {}) as Record<string, Record<string, unknown>>;
    return Object.fromEntries(Object.entries(value).map(([key, child]) => {
      const matched = properties[key] ?? Object.entries(patterns).find(([pattern]) => matchesSchemaPattern(pattern, key, "payload"))?.[1];
      return [key, matched === undefined ? child : coerce(matched, child, root)];
    }));
  }
  return value;
}
function deepFreeze<T>(value: T, depth = 0, budget: ValidationBudget = { nodes: 0 }): Readonly<T> {
  if (depth > 64 || ++budget.nodes > 100_000) fail("payload", "value exceeds nesting or node bounds");
  if (typeof value === "object" && value !== null) {
    for (const child of Object.values(value)) deepFreeze(child, depth + 1, budget);
    Object.freeze(value);
  }
  return value;
}
function payloadModel<T>(name: string, schema: Record<string, unknown>): PayloadModel<T> {
  const frozenSchema = deepFreeze(schema);
  return Object.freeze({
    name,
    schema: frozenSchema,
    create(value: T): Readonly<T> {
      const normalized = coerce(frozenSchema, structuredClone(value), frozenSchema);
      validate(frozenSchema, normalized, frozenSchema, name);
      validateSemantic(name, normalized);
      return deepFreeze(normalized as T);
    },
  });
}

"""
        + "\n\n".join(declarations)
        + "\n"
    )
    target.write_text(content, encoding="utf-8")


def py_schema_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        name = str(schema["$ref"]).replace("#/$defs/", "")
        definition = PAYLOAD_DEFINITIONS.get(name)
        variants = None if definition is None else definition.get("oneOf")
        if (
            isinstance(variants, list)
            and variants
            and all(isinstance(item, dict) and "const" in item for item in variants)
        ):
            return (
                "Literal[" + ", ".join(repr(item["const"]) for item in variants) + "]"
            )
        return "JsonObject"
    variants = schema.get("oneOf") or schema.get("anyOf")
    if isinstance(variants, list):
        return " | ".join(py_schema_type(item) for item in variants)
    if "const" in schema:
        return (
            "str"
            if isinstance(schema["const"], str)
            else type(schema["const"]).__name__
        )
    kinds = schema_types(schema)
    if len(kinds) > 1:
        parts = [
            "None" if kind == "null" else py_schema_type({**schema, "type": kind})
            for kind in kinds
        ]
        return " | ".join(dict.fromkeys(parts))
    kind = kinds[0] if kinds else ""
    if kind == "string":
        return "str"
    if kind == "integer":
        return "int"
    if kind == "number":
        return "float"
    if kind == "boolean":
        return "bool"
    if kind == "null":
        return "None"
    if kind == "array":
        return f"tuple[{py_schema_type(schema.get('items', {}))}, ...]"
    if kind == "object" or "properties" in schema or "additionalProperties" in schema:
        return "JsonObject"
    return "JsonValue"


def generate_python_models(bundle: dict[str, Any]) -> None:
    target = SDK / "python/src/cigar_sdk/generated/models.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    classes: list[str] = []
    schema_rows: list[str] = []
    for name, schema in bundle["types"].items():
        schema_rows.append(f"    {name!r}: {schema!r},")
        properties = (
            schema.get("properties", {}) if schema_types(schema) == ["object"] else None
        )
        if isinstance(properties, dict):
            required = list(schema.get("required", []))
            optional = sorted(set(properties) - set(required))
            fields = [
                f"    {field}: {py_schema_type(properties[field])}"
                for field in required
            ]
            for field in optional:
                annotation = py_schema_type(properties[field])
                if "None" not in annotation.split(" | "):
                    annotation += " | None"
                fields.append(f"    {field}: {annotation} = None")
            if not fields:
                fields = ["    pass"]
            classes.append(
                f"@dataclass(frozen=True, slots=True)\nclass {name}:\n"
                + "\n".join(fields)
            )
        else:
            classes.append(
                f"@dataclass(frozen=True, slots=True)\nclass {name}:\n    value: {py_schema_type(schema)}"
            )
    content = (
        """# @generated by sdk/generate_clients.py; do not edit.
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypeAlias

JsonValue: TypeAlias = object
JsonObject: TypeAlias = Mapping[str, object]

"""
        + "\n\n".join(classes)
        + """

def _freeze_schema(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_schema(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_schema(child) for child in value)
    return value

PAYLOAD_SCHEMAS: Mapping[str, JsonObject] = _freeze_schema({
"""
        + "\n".join(schema_rows)
        + "\n})  # type: ignore[assignment]\n"
    )
    target.write_text(content, encoding="utf-8")


def go_name(value: str) -> str:
    acronyms = {
        "id": "ID",
        "ids": "IDs",
        "api": "API",
        "http": "HTTP",
        "grpc": "GRPC",
        "ipc": "IPC",
        "ttl": "TTL",
        "cbor": "CBOR",
        "etag": "ETag",
        "uri": "URI",
    }
    parts = [part.lower() if part.isupper() else part for part in value.split("_")]
    return "".join(acronyms.get(part, part[:1].upper() + part[1:]) for part in parts)


def go_schema_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        name = str(schema["$ref"]).replace("#/$defs/", "")
        definition = PAYLOAD_DEFINITIONS.get(name)
        variants = None if definition is None else definition.get("oneOf")
        if (
            isinstance(variants, list)
            and variants
            and all(
                isinstance(item, dict) and isinstance(item.get("const"), str)
                for item in variants
            )
        ):
            return name
        return "JSONValue"
    variants = schema.get("oneOf") or schema.get("anyOf")
    if isinstance(variants, list):
        if variants and all(
            isinstance(item, dict) and isinstance(item.get("const"), str)
            for item in variants
        ):
            return "string"
        return "JSONValue"
    kinds = schema_types(schema)
    if len(kinds) > 1:
        nonnull = [kind for kind in kinds if kind != "null"]
        if len(nonnull) == 1:
            return "*" + go_schema_type({**schema, "type": nonnull[0]})
        return "JSONValue"
    kind = kinds[0] if kinds else ""
    if kind == "string":
        return "string"
    if kind == "integer":
        return (
            "int64"
            if schema.get("format") == "int64" or schema.get("minimum", 0) < 0
            else "uint64"
        )
    if kind == "number":
        return "float64"
    if kind == "boolean":
        return "bool"
    if kind == "array":
        return "JSONValue"
    if kind == "object" or "properties" in schema or "additionalProperties" in schema:
        return "JSONValue"
    return "JSONValue"


def generate_go_models(bundle: dict[str, Any]) -> None:
    target = SDK / "go/models_gen.go"
    target.parent.mkdir(parents=True, exist_ok=True)
    declarations: list[str] = []
    enum_declarations: list[str] = []
    for name, definition in sorted(PAYLOAD_DEFINITIONS.items()):
        variants = definition.get("oneOf")
        if not (
            isinstance(variants, list)
            and variants
            and all(
                isinstance(item, dict) and isinstance(item.get("const"), str)
                for item in variants
            )
        ):
            continue
        constants = "\n".join(
            f"\t{name}{go_name(item['const'])} {name} = {json.dumps(item['const'])}"
            for item in variants
        )
        enum_declarations.append(f"type {name} string\n\nconst (\n{constants}\n)")
    schema_rows: list[str] = []
    for name, schema in bundle["types"].items():
        schema_rows.append(
            f'\t"{name}": {json.dumps(json.dumps(schema, separators=(",", ":")))},'
        )
        properties = (
            schema.get("properties", {}) if schema_types(schema) == ["object"] else None
        )
        if isinstance(properties, dict):
            required = set(schema.get("required", []))
            fields = []
            for field, child in properties.items():
                field_type = go_schema_type(child)
                if field not in required and not field_type.startswith("*"):
                    field_type = "*" + field_type
                tag = field if field in required else field + ",omitempty"
                fields.append(f'\t{go_name(field)} {field_type} `json:"{tag}"`')
            declarations.append(f"type {name} struct {{\n" + "\n".join(fields) + "\n}")
        else:
            declarations.append(
                f"""type {name} struct {{ value JSONValue }}

func New{name}(value any) ({name}, error) {{
	wrapped, err := NewJSONValue(value)
	return {name}{{value: wrapped}}, err
}}

func (value {name}) Value() JSONValue {{ return value.value }}
func (value {name}) MarshalJSON() ([]byte, error) {{ return value.value.MarshalJSON() }}
func (value *{name}) UnmarshalJSON(source []byte) error {{
	wrapped, err := ParseJSONValue(source)
	if err == nil {{ value.value = wrapped }}
	return err
}}"""
            )
    content = (
        """// Code generated by sdk/generate_clients.py. DO NOT EDIT.
package cigar

"""
        + "\n\n".join(enum_declarations + declarations)
        + """

var payloadSchemaJSON = map[string]string{
"""
        + "\n".join(schema_rows)
        + """
}

// PayloadSchema returns an owned JSON Schema document for one nominal payload type.
func PayloadSchema(name string) ([]byte, bool) {
	value, ok := payloadSchemaJSON[name]
	return append([]byte(nil), []byte(value)...), ok
}
"""
    )
    target.write_text(content, encoding="utf-8")


def generate_typescript_errors(items: list[dict[str, Any]]) -> None:
    target = SDK / "typescript/src/generated/errors.ts"
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        f"  {item['name']}: "
        + quote(
            {
                "numericCode": item["code"],
                "httpStatus": item["http"],
                "retry": item["retry"],
                "message": item["message"],
                "remediation": item["remediation"],
            }
        )
        + ","
        for item in items
    ]
    target.write_text(
        "// @generated by sdk/generate_clients.py; do not edit.\n"
        "export const ERROR_CATALOG = {\n"
        + "\n".join(rows)
        + "\n} as const;\n"
        + "export type ErrorCode = keyof typeof ERROR_CATALOG;\n",
        encoding="utf-8",
    )


def generate_python_errors(items: list[dict[str, Any]]) -> None:
    target = SDK / "python/src/cigar_sdk/generated/errors.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        f"    {item['name']!r}: ErrorDefinition("
        f"numeric_code={item['code']}, http_status={item['http']}, retry={item['retry']!r}, "
        f"message={item['message']!r}, remediation={item['remediation']!r}),"
        for item in items
    ]
    target.write_text(
        """# @generated by sdk/generate_clients.py; do not edit.
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ErrorDefinition:
    numeric_code: int
    http_status: int
    retry: str
    message: str
    remediation: str


ERROR_CATALOG: dict[str, ErrorDefinition] = {
"""
        + "\n".join(rows)
        + "\n}\n",
        encoding="utf-8",
    )


def generate_go_errors(items: list[dict[str, Any]]) -> None:
    target = SDK / "go/errors_gen.go"
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        f'\t"{item["name"]}": {{NumericCode: {item["code"]}, HTTPStatus: {item["http"]}, '
        f'GRPCStatus: "{item["grpc"]}", Retry: "{item["retry"]}", Message: {json.dumps(item["message"])}, '
        f"Remediation: {json.dumps(item['remediation'])}}},"
        for item in items
    ]
    target.write_text(
        "// Code generated by sdk/generate_clients.py. DO NOT EDIT.\n"
        "package cigar\n\n"
        "var errorCatalog = map[string]ErrorDefinition{\n" + "\n".join(rows) + "\n}\n",
        encoding="utf-8",
    )


def generate_typescript(items: list[dict[str, Any]]) -> None:
    target = SDK / "typescript/src/generated/operations.ts"
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    methods = []
    for item in items:
        row = {
            "operationId": item["operation_id"],
            "rpc": item["rpc"],
            "service": item["service"],
            "httpMethod": item["http_method"],
            "httpPath": item["http_path"],
            "mutation": item["mutation"],
            "idempotencyRequired": item["idempotency_requirement"] == "required",
            "revisionRequired": item["revision_requirement"] == "required",
            "stream": item["stream_kind"] == "server_stream",
            "authClass": item["auth_class"],
            "requestType": item["request_schema"],
            "responseType": item["response_schema"],
            "eventType": item["event_schema"],
            "requestMaxBytes": item["request_max_bytes"],
            "responseMaxBytes": item["response_max_bytes"],
            "eventMaxBytes": item["event_max_bytes"],
            "pathFields": [
                field["name"]
                for field in item["request_fields"]
                if field["source"] == "path"
            ],
        }
        rows.append(f"  {item['operation_id']}: {quote(row)},")
        if item["stream_kind"] == "server_stream":
            result = f"TypedEventStream<{item['event_schema']}>"
        else:
            result = f"Promise<TypedOperationResponse<{item['response_schema']}>>"
        methods.append(
            f"  {item['operation_id']}(request: TypedOperationRequest<{item['request_schema']}>, options?: CallOptions): {result};"
        )
    payload_names = sorted(
        {
            str(item[key])
            for item in items
            for key in ("request_schema", "response_schema", "event_schema")
            if item[key] is not None
        }
    )
    content = f"""// @generated by sdk/generate_clients.py; do not edit.
import type {{ CallOptions, TypedEventStream, TypedOperationRequest, TypedOperationResponse }} from "../types.js";
import type {{ {", ".join(payload_names)} }} from "./models.js";

export const OPERATIONS = {{
{chr(10).join(rows)}
}} as const;

export type OperationId = keyof typeof OPERATIONS;
export type OperationDefinition = (typeof OPERATIONS)[OperationId];
export const OPERATION_COUNT = {len(items)} as const;
export const PAYLOAD_TYPES = {quote(payload_names)} as const;
export type PayloadTypeName = (typeof PAYLOAD_TYPES)[number];

export interface GeneratedOperations {{
{chr(10).join(methods)}
}}
"""
    target.write_text(content, encoding="utf-8")


def generate_python(items: list[dict[str, Any]]) -> None:
    target = SDK / "python/src/cigar_sdk/generated/operations.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    async_methods = []
    sync_methods = []
    for item in items:
        name = snake(item["operation_id"])
        row = {
            "operation_id": item["operation_id"],
            "rpc": item["rpc"],
            "service": item["service"],
            "http_method": item["http_method"],
            "http_path": item["http_path"],
            "mutation": item["mutation"],
            "idempotency_required": item["idempotency_requirement"] == "required",
            "revision_required": item["revision_requirement"] == "required",
            "stream": item["stream_kind"] == "server_stream",
            "auth_class": item["auth_class"],
            "request_type": item["request_schema"],
            "response_type": item["response_schema"],
            "event_type": item["event_schema"],
            "request_max_bytes": item["request_max_bytes"],
            "response_max_bytes": item["response_max_bytes"],
            "event_max_bytes": item["event_max_bytes"],
            "path_fields": tuple(
                field["name"]
                for field in item["request_fields"]
                if field["source"] == "path"
            ),
        }
        rows.append(f"    {item['operation_id']!r}: OperationDefinition(**{row!r}),")
        if item["stream_kind"] == "server_stream":
            async_methods.append(
                f"    def {name}(self, request: TypedOperationRequest[{item['request_schema']}], *, options: CallOptions | None = None) -> TypedAsyncEventStream[{item['event_schema']}]:\n"
                f"        return self._stream_typed({item['operation_id']!r}, request, {item['event_schema']}, options)"
            )
            sync_methods.append(
                f"    def {name}(self, request: TypedOperationRequest[{item['request_schema']}], *, options: CallOptions | None = None) -> TypedEventStream[{item['event_schema']}]:\n"
                f"        return self._stream_typed_sync({item['operation_id']!r}, request, {item['event_schema']}, options)"
            )
        else:
            async_methods.append(
                f"    async def {name}(self, request: TypedOperationRequest[{item['request_schema']}], *, options: CallOptions | None = None) -> TypedOperationResponse[{item['response_schema']}]:\n"
                f"        return await self._call_typed({item['operation_id']!r}, request, {item['response_schema']}, options)"
            )
            sync_methods.append(
                f"    def {name}(self, request: TypedOperationRequest[{item['request_schema']}], *, options: CallOptions | None = None) -> TypedOperationResponse[{item['response_schema']}]:\n"
                f"        return self._call_typed_sync({item['operation_id']!r}, request, {item['response_schema']}, options)"
            )
    payload_names = sorted(
        {
            str(item[key])
            for item in items
            for key in ("request_schema", "response_schema", "event_schema")
            if item[key] is not None
        }
    )
    content = f"""# @generated by sdk/generate_clients.py; do not edit.
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cigar_sdk.generated.models import (
    {("," + chr(10) + "    ").join(payload_names)},
)
from cigar_sdk.types import (
    CallOptions,
    TypedAsyncEventStream,
    TypedEventStream,
    TypedOperationRequest,
    TypedOperationResponse,
)


@dataclass(frozen=True, slots=True)
class OperationDefinition:
    operation_id: str
    rpc: str
    service: str
    http_method: str
    http_path: str
    mutation: bool
    idempotency_required: bool
    revision_required: bool
    stream: bool
    auth_class: str
    request_type: str
    response_type: str
    event_type: str | None
    request_max_bytes: int
    response_max_bytes: int
    event_max_bytes: int
    path_fields: tuple[str, ...]


OPERATIONS: dict[str, OperationDefinition] = {{
{chr(10).join(rows)}
}}
OPERATION_COUNT = {len(items)}
PAYLOAD_TYPES = {tuple(payload_names)!r}


class AsyncGeneratedOperations:
    async def _call_typed(self, operation_id: str, request: TypedOperationRequest[Any], response_type: type[Any], options: CallOptions | None) -> TypedOperationResponse[Any]:
        raise NotImplementedError

    def _stream_typed(self, operation_id: str, request: TypedOperationRequest[Any], event_type: type[Any], options: CallOptions | None) -> TypedAsyncEventStream[Any]:
        raise NotImplementedError

{chr(10).join(async_methods)}


class GeneratedOperations:
    def _call_typed_sync(self, operation_id: str, request: TypedOperationRequest[Any], response_type: type[Any], options: CallOptions | None) -> TypedOperationResponse[Any]:
        raise NotImplementedError

    def _stream_typed_sync(self, operation_id: str, request: TypedOperationRequest[Any], event_type: type[Any], options: CallOptions | None) -> TypedEventStream[Any]:
        raise NotImplementedError

{chr(10).join(sync_methods)}
"""
    target.write_text(content, encoding="utf-8")


def generate_go(items: list[dict[str, Any]]) -> None:
    target = SDK / "go/operations_gen.go"
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    methods = []
    grpc_methods = []
    for item in items:
        path_fields = [
            field["name"]
            for field in item["request_fields"]
            if field["source"] == "path"
        ]
        go_path_fields = (
            "[]string{" + ", ".join(json.dumps(field) for field in path_fields) + "}"
        )
        row = (
            f'\t"{item["operation_id"]}": {{OperationID: "{item["operation_id"]}", '
            f'RPC: "{item["rpc"]}", Service: "{item["service"]}", HTTPMethod: "{item["http_method"]}", '
            f'HTTPPath: "{item["http_path"]}", Mutation: {str(item["mutation"]).lower()}, '
            f"IdempotencyRequired: {str(item['idempotency_requirement'] == 'required').lower()}, "
            f"RevisionRequired: {str(item['revision_requirement'] == 'required').lower()}, "
            f'Stream: {str(item["stream_kind"] == "server_stream").lower()}, AuthClass: "{item["auth_class"]}", '
            f'RequestType: "{item["request_schema"]}", ResponseType: "{item["response_schema"]}", '
            f'EventType: "{item["event_schema"] or ""}", RequestMaxBytes: {item["request_max_bytes"]}, '
            f"ResponseMaxBytes: {item['response_max_bytes']}, EventMaxBytes: {item['event_max_bytes']}, PathFields: {go_path_fields}}},"
        )
        rows.append(row)
        if item["stream_kind"] == "server_stream":
            methods.append(
                f"// {item['rpc']} opens the resumable {item['operation_id']} event stream.\n"
                f"func (client *Client) {item['rpc']}(ctx context.Context, payload {item['request_schema']}, options ...InvocationOption) (*TypedEventStream[{item['event_schema']}], error) {{\n"
                f'\treturn streamTyped[{item["request_schema"]}, {item["event_schema"]}](client, ctx, "{item["operation_id"]}", payload, options...)\n}}'
            )
            grpc_methods.append(
                f"// {item['rpc']} opens the resumable {item['operation_id']} gRPC event stream.\n"
                f"func (client *GRPCClient) {item['rpc']}(ctx context.Context, payload {item['request_schema']}, options ...InvocationOption) (*TypedEventStream[{item['event_schema']}], error) {{\n"
                f'\treturn streamGRPCTyped[{item["request_schema"]}, {item["event_schema"]}](client, ctx, "{item["operation_id"]}", payload, options...)\n}}'
            )
        else:
            methods.append(
                f"// {item['rpc']} invokes {item['operation_id']}.\n"
                f"func (client *Client) {item['rpc']}(ctx context.Context, payload {item['request_schema']}, options ...InvocationOption) (TypedResponse[{item['response_schema']}], error) {{\n"
                f'\treturn callTyped[{item["request_schema"]}, {item["response_schema"]}](client, ctx, "{item["operation_id"]}", payload, options...)\n}}'
            )
            grpc_methods.append(
                f"// {item['rpc']} invokes {item['operation_id']} over gRPC.\n"
                f"func (client *GRPCClient) {item['rpc']}(ctx context.Context, payload {item['request_schema']}, options ...InvocationOption) (TypedResponse[{item['response_schema']}], error) {{\n"
                f'\treturn callGRPCTyped[{item["request_schema"]}, {item["response_schema"]}](client, ctx, "{item["operation_id"]}", payload, options...)\n}}'
            )
    payload_names = sorted(
        {
            str(item[key])
            for item in items
            for key in ("request_schema", "response_schema", "event_schema")
            if item[key] is not None
        }
    )
    payload_rows = "\n".join(f'\t"{name}",' for name in payload_names)
    content = f"""// Code generated by sdk/generate_clients.py. DO NOT EDIT.
package cigar

import "context"

// OperationCount is the frozen v1 operation count.
const OperationCount = {len(items)}

// Operations contains the immutable v1 operation descriptors. Call Operation to receive a copy.
var operations = map[string]OperationDefinition{{
{chr(10).join(rows)}
}}

var payloadTypes = []string{{
{payload_rows}
}}

// PayloadTypeNames returns a copy of operation-specific payload names in canonical order.
func PayloadTypeNames() []string {{ return append([]string(nil), payloadTypes...) }}

{chr(10).join(methods)}

{chr(10).join(grpc_methods)}
"""
    target.write_text(content, encoding="utf-8")


def generate_manifest(items: list[dict[str, Any]]) -> None:
    payload_names = sorted(
        {
            str(item[key])
            for item in items
            for key in ("request_schema", "response_schema", "event_schema")
            if item[key] is not None
        }
    )
    operation_rows = [
        {
            "operation_id": item["operation_id"],
            "request_type": item["request_schema"],
            "response_type": item["response_schema"],
            "event_type": item["event_schema"],
            "stream": item["stream_kind"],
            "retry_class": (
                "never_automatic"
                if item["operation_id"] == "dispatchEffect"
                else "idempotency_bound_mutation"
                if item["mutation"]
                else "safe_read"
            ),
        }
        for item in items
    ]
    common = {
        "operation_count": len(items),
        "type_count": len(payload_names),
        "model_source": "schemas/json/api-payload-types-v1.schema.json",
        "nominal_models": True,
        "runtime_schema_validation": True,
        "operations": [item["operation_id"] for item in items],
        "types": payload_names,
    }
    manifest = {
        "schema_version": "cigar.sdk-capabilities.v1",
        "api_status": "frozen-v1",
        "operation_count": len(items),
        "type_count": len(payload_names),
        "operations": operation_rows,
        "sdks": {
            "rust": {
                **common,
                "transport": ["embedded", "http"],
                "features": [
                    "deadlines",
                    "pagination",
                    "stream_resume",
                    "cancellation",
                    "typed_errors",
                    "idempotency",
                    "safe_retry",
                    "version_negotiation",
                    "digest_verification",
                    "delta_verification",
                ],
            },
            "typescript": {
                **common,
                "transport": ["http"],
                "module": "@cigar/sdk",
                "features": [
                    "deadlines",
                    "pagination",
                    "stream_resume",
                    "abort_signal",
                    "typed_errors",
                    "idempotency",
                    "safe_retry",
                    "version_negotiation",
                    "digest_verification",
                    "delta_verification",
                    "async_iterable",
                ],
            },
            "python": {
                **common,
                "transport": ["http"],
                "module": "cigar_sdk",
                "features": [
                    "deadlines",
                    "pagination",
                    "stream_resume",
                    "cancellation",
                    "typed_errors",
                    "idempotency",
                    "safe_retry",
                    "version_negotiation",
                    "digest_verification",
                    "delta_verification",
                    "async_sync_clients",
                    "context_managers",
                ],
            },
            "go": {
                **common,
                "transport": ["http", "grpc"],
                "module": "github.com/CIGAR/cigar/sdk/go",
                "features": [
                    "deadlines",
                    "pagination",
                    "stream_resume",
                    "context_cancellation",
                    "typed_errors",
                    "idempotency",
                    "safe_retry",
                    "version_negotiation",
                    "digest_verification",
                    "delta_verification",
                    "closable_streams",
                    "copy_safe_records",
                    "generated_grpc_clients",
                ],
            },
        },
    }
    (SDK / "capabilities-v1.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


GENERATED_PATHS = (
    Path("typescript/src/generated/models.ts"),
    Path("typescript/src/generated/operations.ts"),
    Path("typescript/src/generated/errors.ts"),
    Path("python/src/cigar_sdk/generated/models.py"),
    Path("python/src/cigar_sdk/generated/operations.py"),
    Path("python/src/cigar_sdk/generated/errors.py"),
    Path("go/models_gen.go"),
    Path("go/operations_gen.go"),
    Path("go/errors_gen.go"),
    Path("capabilities-v1.json"),
)


def generate_all(
    items: list[dict[str, Any]],
    error_items: list[dict[str, Any]],
    payload_bundle: dict[str, Any],
) -> None:
    """Write the complete deterministic generated surface under ``SDK``."""

    generate_typescript_models(payload_bundle)
    generate_typescript(items)
    generate_typescript_errors(error_items)
    generate_python_models(payload_bundle)
    generate_python(items)
    generate_python_errors(error_items)
    generate_go_models(payload_bundle)
    generate_go(items)
    generate_go_errors(error_items)
    subprocess.run(
        [
            "gofmt",
            "-w",
            str(SDK / "go/models_gen.go"),
            str(SDK / "go/operations_gen.go"),
            str(SDK / "go/errors_gen.go"),
        ],
        check=True,
    )
    generate_manifest(items)
    assert_generated_surface(len(items), len(payload_bundle["types"]))


def assert_generated_surface(operation_count: int, type_count: int) -> None:
    """Reject accidental regression to generic high-level request signatures."""

    ts_operations = (SDK / "typescript/src/generated/operations.ts").read_text(
        encoding="utf-8"
    )
    py_operations = (SDK / "python/src/cigar_sdk/generated/operations.py").read_text(
        encoding="utf-8"
    )
    go_operations = (SDK / "go/operations_gen.go").read_text(encoding="utf-8")
    if ts_operations.count("request: TypedOperationRequest["):
        raise AssertionError("TypeScript generator emitted Python generic syntax")
    if ts_operations.count("request: TypedOperationRequest<") != operation_count:
        raise AssertionError("TypeScript generated method count drifted")
    if (
        len(
            re.findall(
                r"^    (?:async )?def [a-z].*request: TypedOperationRequest\[",
                py_operations,
                re.MULTILINE,
            )
        )
        != operation_count * 2
    ):
        raise AssertionError("Python generated method count drifted")
    if (
        len(re.findall(r"^func \(client \*Client\) [A-Z]", go_operations, re.MULTILINE))
        != operation_count
    ):
        raise AssertionError("Go generated method count drifted")
    if (
        len(
            re.findall(
                r"^func \(client \*GRPCClient\) [A-Z]", go_operations, re.MULTILINE
            )
        )
        != operation_count
    ):
        raise AssertionError("Go generated gRPC method count drifted")
    if re.search(r"payload Request(?:[,)]|\s)", go_operations):
        raise AssertionError("Go high-level methods regressed to generic Request")
    if len(payload_schema_bundle()["types"]) != type_count:
        raise AssertionError("payload model count drifted")


def assert_packaged_fixtures() -> None:
    """Keep every independently installable SDK on the exact shared quickstart bytes."""

    shared = (SDK / "fixtures/semantic-bundle-v1.json").read_bytes()
    copies = (
        SDK / "typescript/fixtures/semantic-bundle-v1.json",
        SDK / "python/src/cigar_sdk/fixtures/semantic-bundle-v1.json",
        SDK / "go/fixtures/semantic-bundle-v1.json",
        SDK / "rust/fixtures/semantic-bundle-v1.json",
    )
    drift = [
        str(path.relative_to(SDK))
        for path in copies
        if not path.is_file() or path.read_bytes() != shared
    ]
    if drift:
        raise AssertionError(
            "packaged semantic bundle fixture drift: " + ", ".join(drift)
        )


def assert_release_contracts() -> None:
    """Bind all installed SDK declarations to one version, ABI, license, and notice."""

    package_match = re.search(
        r"^package\s+([a-z][a-z0-9.]*)\s*;\s*$",
        (ROOT / "schemas/proto/context_abi.proto").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if package_match is None:
        raise AssertionError("Context ABI protobuf package declaration is missing")
    context_abi = package_match.group(1)
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    version = workspace["workspace"]["package"]["version"]
    if not isinstance(version, str):
        raise AssertionError("workspace package version is invalid")

    manifests = {
        "rust": tomllib.loads((SDK / "rust/Cargo.toml").read_text(encoding="utf-8"))[
            "package"
        ]["version"],
        "typescript": load_json(SDK / "typescript/package.json")["version"],
        "python": tomllib.loads(
            (SDK / "python/pyproject.toml").read_text(encoding="utf-8")
        )["project"]["version"],
    }
    if any(value != version for value in manifests.values()):
        raise AssertionError(f"SDK package version drift: {manifests}")

    releases = {
        "rust": (SDK / "rust/release.json", "cigar-sdk"),
        "typescript": (SDK / "typescript/release.json", "@cigar/sdk"),
        "python": (SDK / "python/src/cigar_sdk/release.json", "cigar-sdk"),
        "go": (SDK / "go/release.json", "github.com/CIGAR/cigar/sdk/go"),
    }
    for language, (path, name) in releases.items():
        actual = load_json(path)
        expected = {
            "schema_version": "cigar.sdk-release.v1",
            "name": name,
            "version": version,
            "context_abi": context_abi,
        }
        if actual != expected:
            raise AssertionError(f"{language} release metadata drift")

    constant_patterns = {
        "rust": (SDK / "rust/src/lib.rs", r'pub const CONTEXT_ABI: &str = "([^"]+)";'),
        "typescript": (
            SDK / "typescript/src/index.ts",
            r'export const CONTEXT_ABI = "([^"]+)" as const;',
        ),
        "python": (
            SDK / "python/src/cigar_sdk/__init__.py",
            r'CONTEXT_ABI: Final = "([^"]+)"',
        ),
        "go": (SDK / "go/types.go", r'const ContextABI = "([^"]+)"'),
    }
    for language, (path, pattern) in constant_patterns.items():
        matches = re.findall(pattern, path.read_text(encoding="utf-8"))
        if matches != [context_abi]:
            raise AssertionError(f"{language} Context ABI constant drift")

    license_bytes = (ROOT / "LICENSE").read_bytes()
    notice_bytes = (ROOT / "NOTICE").read_bytes()
    for language in ("rust", "typescript", "python", "go"):
        if (SDK / language / "LICENSE").read_bytes() != license_bytes:
            raise AssertionError(f"{language} packaged LICENSE drift")
        if (SDK / language / "NOTICE").read_bytes() != notice_bytes:
            raise AssertionError(f"{language} packaged NOTICE drift")


def check(
    items: list[dict[str, Any]],
    error_items: list[dict[str, Any]],
    payload_bundle: dict[str, Any],
) -> None:
    """Fail on generated drift without modifying the working tree."""

    global SDK
    actual_sdk = SDK
    with tempfile.TemporaryDirectory(prefix="cigar-sdk-generate-") as temporary:
        SDK = Path(temporary)
        try:
            generate_all(items, error_items, payload_bundle)
            drift = [
                str(path)
                for path in GENERATED_PATHS
                if not (actual_sdk / path).is_file()
                or (actual_sdk / path).read_bytes() != (SDK / path).read_bytes()
            ]
        finally:
            SDK = actual_sdk
    if drift:
        raise SystemExit("generated SDK drift: " + ", ".join(drift))


def main() -> None:
    assert_packaged_fixtures()
    assert_release_contracts()
    items = operations()
    error_items = errors()
    payload_bundle = payload_schema_bundle()
    if sys.argv[1:] == ["--check"]:
        check(items, error_items, payload_bundle)
    elif not sys.argv[1:]:
        generate_all(items, error_items, payload_bundle)
    else:
        raise SystemExit("usage: sdk/generate_clients.py [--check]")


if __name__ == "__main__":
    main()
