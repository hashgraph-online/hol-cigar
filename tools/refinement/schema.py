"""Small closed JSON-Schema 2020-12 subset used by refinement control records."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, load_file, safe_relative_path


class SchemaError(ValueError):
    """A schema is unsafe or an instance fails validation."""


class SchemaRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        self._schemas: dict[str, dict[str, Any]] = {}

    def load(self, filename: str) -> dict[str, Any]:
        safe_relative_path(filename)
        if "/" in filename or not filename.endswith(".schema.json"):
            raise SchemaError("schema filename must be a direct .schema.json child")
        cached = self._schemas.get(filename)
        if cached is not None:
            return cached
        path = (self.root / filename).absolute()
        if path.parent != self.root or path.is_symlink():
            raise SchemaError("schema escaped the registry root")
        value = load_file(path)
        if not isinstance(value, dict):
            raise SchemaError("schema root must be an object")
        self.audit(value)
        self._schemas[filename] = value
        return value

    def audit(self, schema: dict[str, Any]) -> None:
        def visit(node: Any, location: str) -> None:
            if isinstance(node, list):
                for index, item in enumerate(node):
                    visit(item, f"{location}/{index}")
                return
            if not isinstance(node, dict):
                return
            node_type = node.get("type")
            if node_type == "string" and not any(
                key in node for key in ("maxLength", "const", "enum")
            ):
                raise SchemaError(f"unbounded string schema at {location}")
            if node_type == "array" and "maxItems" not in node:
                raise SchemaError(f"unbounded array schema at {location}")
            if node_type == "object" and node.get("additionalProperties") is not False:
                raise SchemaError(f"open object schema at {location}")
            for key, item in node.items():
                if key != "examples":
                    visit(item, f"{location}/{key}")

        visit(schema, "#")

    def validate(self, filename: str, value: Any) -> None:
        schema = self.load(filename)
        self._validate(schema, value, schema, filename, "$", 0)

    def _resolve(
        self,
        reference: str,
        document: dict[str, Any],
        filename: str,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        if not isinstance(reference, str):
            raise SchemaError("$ref must be a string")
        if reference.startswith("#/"):
            target_document = document
            target_filename = filename
            fragment = reference[2:]
        elif "#/" in reference:
            target_filename, fragment = reference.split("#/", 1)
            target_document = self.load(target_filename)
        elif reference.endswith(".schema.json"):
            target_filename = reference
            target_document = self.load(target_filename)
            return target_document, target_document, target_filename
        else:
            raise SchemaError("only local schema references are supported")
        target: Any = target_document
        for raw in fragment.split("/"):
            key = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or key not in target:
                raise SchemaError(f"unresolved schema reference: {reference}")
            target = target[key]
        if not isinstance(target, dict):
            raise SchemaError("$ref must resolve to a schema object")
        return target, target_document, target_filename

    def _validate(
        self,
        schema: dict[str, Any],
        value: Any,
        document: dict[str, Any],
        filename: str,
        path: str,
        depth: int,
    ) -> None:
        if depth > 128:
            raise SchemaError("schema validation recursion limit exceeded")
        reference = schema.get("$ref")
        if reference is not None:
            target, target_document, target_filename = self._resolve(
                reference, document, filename
            )
            self._validate(
                target,
                value,
                target_document,
                target_filename,
                path,
                depth + 1,
            )
            return
        branches = schema.get("allOf", [])
        if not isinstance(branches, list):
            raise SchemaError(f"allOf is malformed at {path}")
        for branch in branches:
            if not isinstance(branch, dict):
                raise SchemaError(f"allOf branch is malformed at {path}")
            self._validate(branch, value, document, filename, path, depth + 1)
        one_of = schema.get("oneOf")
        if one_of is not None:
            if not isinstance(one_of, list) or not one_of:
                raise SchemaError(f"oneOf is malformed at {path}")
            matches = 0
            for branch in one_of:
                try:
                    self._validate(branch, value, document, filename, path, depth + 1)
                except SchemaError:
                    continue
                matches += 1
            if matches != 1:
                raise SchemaError(f"{path} must match exactly one schema branch")
            return
        if "const" in schema and value != schema["const"]:
            raise SchemaError(f"{path} does not equal its required constant")
        if "enum" in schema and value not in schema["enum"]:
            raise SchemaError(f"{path} is not an allowed enum value")
        expected = schema.get("type")
        if expected is not None:
            valid = {
                "null": value is None,
                "boolean": isinstance(value, bool),
                "integer": isinstance(value, int) and not isinstance(value, bool),
                "number": (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and (not isinstance(value, float) or math.isfinite(value))
                ),
                "string": isinstance(value, str),
                "array": isinstance(value, list),
                "object": isinstance(value, dict),
            }.get(expected)
            if valid is None:
                raise SchemaError(f"unsupported schema type at {path}: {expected}")
            if not valid:
                raise SchemaError(f"{path} must be {expected}")
        if isinstance(value, dict):
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list):
                raise SchemaError(f"object schema is malformed at {path}")
            missing = [key for key in required if key not in value]
            if missing:
                raise SchemaError(f"{path} is missing required fields: {missing}")
            if schema.get("additionalProperties") is False:
                unknown = sorted(set(value) - set(properties))
                if unknown:
                    raise SchemaError(f"{path} has unknown fields: {unknown}")
            for key, item in value.items():
                child = properties.get(key)
                if child is not None:
                    self._validate(
                        child,
                        item,
                        document,
                        filename,
                        f"{path}.{key}",
                        depth + 1,
                    )
        if isinstance(value, list):
            minimum = schema.get("minItems", 0)
            maximum = schema.get("maxItems")
            if len(value) < minimum or (maximum is not None and len(value) > maximum):
                raise SchemaError(f"{path} array length is outside its bounds")
            if schema.get("uniqueItems"):
                encoded = [canonical_bytes(item) for item in value]
                if len(encoded) != len(set(encoded)):
                    raise SchemaError(f"{path} array items must be unique")
            item_schema = schema.get("items")
            if item_schema is not None:
                if not isinstance(item_schema, dict):
                    raise SchemaError(f"items schema is malformed at {path}")
                for index, item in enumerate(value):
                    self._validate(
                        item_schema,
                        item,
                        document,
                        filename,
                        f"{path}[{index}]",
                        depth + 1,
                    )
        if isinstance(value, str):
            minimum = schema.get("minLength", 0)
            maximum = schema.get("maxLength")
            if len(value) < minimum or (maximum is not None and len(value) > maximum):
                raise SchemaError(f"{path} string length is outside its bounds")
            pattern = schema.get("pattern")
            if pattern is not None and re.search(pattern, value) is None:
                raise SchemaError(f"{path} does not match its pattern")
            if schema.get("format") == "safe-relative-path":
                try:
                    safe_relative_path(value)
                except ValueError as error:
                    raise SchemaError(f"{path} is not a safe relative path") from error
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and ("minimum" in schema or "maximum" in schema)
        ):
            if "minimum" in schema and value < schema["minimum"]:
                raise SchemaError(f"{path} is below its minimum")
            if "maximum" in schema and value > schema["maximum"]:
                raise SchemaError(f"{path} exceeds its maximum")
