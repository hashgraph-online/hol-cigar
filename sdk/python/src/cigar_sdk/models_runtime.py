"""Schema-backed nominal payload construction and canonical CBOR codec."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from types import MappingProxyType
from typing import Any

from cigar_sdk.digest import _deterministic_cbor
from cigar_sdk.errors import ValidationError
from cigar_sdk.generated.models import PAYLOAD_SCHEMAS


def _plain(value: Any, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValidationError("payload exceeds nesting or node bounds")
    if is_dataclass(value) and not isinstance(value, type):
        result: dict[str, Any] = {}
        for field in fields(value):
            child = getattr(value, field.name)
            if child is not None:
                result[field.name] = _plain(child, depth + 1, budget)
        return result
    if isinstance(value, Mapping):
        return {str(key): _plain(child, depth + 1, budget) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(child, depth + 1, budget) for child in value]
    if isinstance(value, (bool, int, str, bytes)):
        return value
    raise ValidationError("payload contains an unsupported value")


def _validate(
    schema: Mapping[str, Any],
    value: Any,
    root: Mapping[str, Any],
    path: str,
    depth: int = 0,
    budget: list[int] | None = None,
) -> None:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValidationError(f"{path}: payload exceeds nesting or node bounds")
    reference = schema.get("$ref")
    if isinstance(reference, str):
        definitions = root.get("$defs")
        if not isinstance(definitions, Mapping):
            raise ValidationError(f"{path}: schema reference is unresolved")
        target = definitions.get(reference.removeprefix("#/$defs/"))
        if not isinstance(target, Mapping):
            raise ValidationError(f"{path}: schema reference is unresolved")
        _validate(target, value, root, path, depth + 1, budget)
        return
    alternatives = schema.get("oneOf", schema.get("anyOf"))
    if isinstance(alternatives, Sequence) and not isinstance(alternatives, (str, bytes)):
        matches = 0
        for alternative in alternatives:
            try:
                _validate(alternative, value, root, path, depth + 1, budget)
                matches += 1
            except ValidationError:
                pass
        if ("oneOf" in schema and matches != 1) or ("anyOf" in schema and matches < 1):
            raise ValidationError(f"{path}: payload does not match its schema variants")
        return
    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{path}: payload differs from its const")
    declared = schema.get("type")
    if isinstance(declared, list):
        matches = 0
        for kind in declared:
            try:
                _validate({**schema, "type": kind}, value, root, path, depth + 1, budget)
                matches += 1
            except ValidationError:
                pass
        if matches != 1:
            raise ValidationError(f"{path}: payload does not match its type union")
        return
    if declared == "null":
        if value is not None:
            raise ValidationError(f"{path}: expected null")
        return
    if declared == "string":
        if not isinstance(value, str):
            raise ValidationError(f"{path}: expected string")
        length = len(value.encode())
        if isinstance(schema.get("minLength"), int) and length < schema["minLength"]:
            raise ValidationError(f"{path}: string is too short")
        if isinstance(schema.get("maxLength"), int) and length > schema["maxLength"]:
            raise ValidationError(f"{path}: string is too long")
        if isinstance(schema.get("pattern"), str) and re.search(schema["pattern"], value) is None:
            raise ValidationError(f"{path}: string does not match pattern")
        return
    if declared in {"integer", "number"}:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{path}: expected exact integer")
        if isinstance(schema.get("minimum"), int) and value < schema["minimum"]:
            raise ValidationError(f"{path}: integer is below minimum")
        if isinstance(schema.get("maximum"), int) and value > schema["maximum"]:
            raise ValidationError(f"{path}: integer exceeds maximum")
        return
    if declared == "boolean":
        if not isinstance(value, bool):
            raise ValidationError(f"{path}: expected boolean")
        return
    if declared == "array":
        if not isinstance(value, (tuple, list)):
            raise ValidationError(f"{path}: expected array")
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            raise ValidationError(f"{path}: array is too short")
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            raise ValidationError(f"{path}: array is too long")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, child in enumerate(value):
                _validate(item_schema, child, root, f"{path}/{index}", depth + 1, budget)
        return
    if declared == "object" or "properties" in schema or "additionalProperties" in schema:
        if not isinstance(value, Mapping):
            raise ValidationError(f"{path}: expected object")
        properties = schema.get("properties", {})
        pattern_properties = schema.get("patternProperties", {})
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                raise ValidationError(f"{path}/{name}: required field is missing")
        if isinstance(schema.get("minProperties"), int) and len(value) < schema["minProperties"]:
            raise ValidationError(f"{path}: object has too few fields")
        if isinstance(schema.get("maxProperties"), int) and len(value) > schema["maxProperties"]:
            raise ValidationError(f"{path}: object has too many fields")
        for name, child in value.items():
            child_schema = properties.get(name) if isinstance(properties, Mapping) else None
            if isinstance(child_schema, Mapping):
                _validate(child_schema, child, root, f"{path}/{name}", depth + 1, budget)
                continue
            pattern_matches = (
                [candidate for pattern, candidate in pattern_properties.items() if re.search(pattern, name)]
                if isinstance(pattern_properties, Mapping)
                else []
            )
            if pattern_matches:
                for candidate in pattern_matches:
                    _validate(candidate, child, root, f"{path}/{name}", depth + 1, budget)
            elif schema.get("additionalProperties") is False:
                raise ValidationError(f"{path}/{name}: unknown field")
            elif isinstance(schema.get("additionalProperties"), Mapping):
                _validate(schema["additionalProperties"], child, root, f"{path}/{name}", depth + 1, budget)


def _coerce(
    schema: Mapping[str, Any],
    value: Any,
    root: Mapping[str, Any],
    depth: int = 0,
    budget: list[int] | None = None,
) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValidationError("payload exceeds nesting or node bounds")
    reference = schema.get("$ref")
    if isinstance(reference, str):
        definitions = root.get("$defs", {})
        return _coerce(definitions.get(reference.removeprefix("#/$defs/"), {}), value, root, depth + 1, budget)
    alternatives = schema.get("oneOf", schema.get("anyOf"))
    if isinstance(alternatives, Sequence) and not isinstance(alternatives, (str, bytes)):
        for alternative in alternatives:
            try:
                _validate(alternative, value, root, "payload")
                return _coerce(alternative, value, root, depth + 1, budget)
            except ValidationError:
                pass
        return value
    declared = schema.get("type")
    if isinstance(declared, list):
        for kind in declared:
            candidate = {**schema, "type": kind}
            try:
                _validate(candidate, value, root, "payload")
                return _coerce(candidate, value, root, depth + 1, budget)
            except ValidationError:
                pass
        return value
    if declared == "array" and isinstance(value, (list, tuple)):
        item = schema.get("items", {})
        return tuple(_coerce(item, child, root, depth + 1, budget) for child in value)
    if (declared == "object" or "properties" in schema) and isinstance(value, Mapping):
        properties = schema.get("properties", {})
        patterns = schema.get("patternProperties", {})
        result: dict[str, Any] = {}
        for name, child in value.items():
            property_schema: Any = properties.get(name) if isinstance(properties, Mapping) else None
            if property_schema is None and isinstance(patterns, Mapping):
                property_schema = next((item for pattern, item in patterns.items() if re.search(pattern, name)), None)
            result[name] = _coerce(property_schema or {}, child, root, depth + 1, budget)
        return result
    return value


def _freeze(value: Any, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValidationError("payload exceeds nesting or node bounds")
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child, depth + 1, budget) for key, child in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(child, depth + 1, budget) for child in value)
    return value


def payload_value(payload: object) -> Any:
    name = type(payload).__name__
    schema = PAYLOAD_SCHEMAS.get(name)
    if schema is None:
        raise ValidationError(f"unknown nominal payload model {name}")
    plain = _plain(payload.value) if schema.get("type") != "object" and hasattr(payload, "value") else _plain(payload)
    _validate(schema, plain, schema, name)
    return plain


def construct_payload[T](model: type[T], value: Any) -> T:
    schema = PAYLOAD_SCHEMAS.get(model.__name__)
    if schema is None:
        raise ValidationError(f"unknown nominal payload model {model.__name__}")
    coerced = _coerce(schema, value, schema)
    _validate(schema, coerced, schema, model.__name__)
    frozen = _freeze(coerced)
    if isinstance(frozen, Mapping) and schema.get("type") == "object":
        return model(**frozen)
    return model(value=frozen)  # type: ignore[call-arg]


class _CborParser:
    def __init__(self, source: bytes) -> None:
        self.source = source
        self.position = 0
        self.nodes = 0

    def exact(self, length: int) -> bytes:
        end = self.position + length
        if length < 0 or end > len(self.source):
            raise ValidationError("payload CBOR is truncated")
        value = self.source[self.position : end]
        self.position = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise ValidationError("payload CBOR uses a reserved or indefinite form")
        value = int.from_bytes(self.exact(width), "big")
        if value < {1: 24, 2: 0x100, 4: 0x1_0000, 8: 0x1_0000_0000}[width]:
            raise ValidationError("payload CBOR integer is non-canonical")
        return value

    def parse(self, depth: int = 0) -> Any:
        self.nodes += 1
        if depth > 64 or self.nodes > 100_000:
            raise ValidationError("payload CBOR exceeds nesting or node bounds")
        initial = self.exact(1)[0]
        major, additional = initial >> 5, initial & 31
        if major == 0:
            return self.argument(additional)
        if major == 1:
            value = -1 - self.argument(additional)
            if value < -(1 << 63):
                raise ValidationError("payload CBOR integer exceeds i64")
            return value
        if major in {2, 3}:
            raw = self.exact(self.argument(additional))
            if major == 2:
                return raw
            try:
                return unicodedata.normalize("NFC", raw.decode("utf-8"))
            except UnicodeDecodeError as error:
                raise ValidationError("payload CBOR text is invalid UTF-8") from error
        if major == 4:
            length = self.argument(additional)
            if length > 100_000:
                raise ValidationError("payload CBOR collection exceeds its node bound")
            return [self.parse(depth + 1) for _ in range(length)]
        if major == 5:
            result: dict[str, Any] = {}
            previous: bytes | None = None
            length = self.argument(additional)
            if length > 100_000:
                raise ValidationError("payload CBOR collection exceeds its node bound")
            for _ in range(length):
                start = self.position
                key = self.parse(depth + 1)
                encoded = self.source[start : self.position]
                if not isinstance(key, str) or (previous is not None and previous >= encoded) or key in result:
                    raise ValidationError("payload CBOR map keys are not canonical and unique")
                previous = encoded
                result[key] = self.parse(depth + 1)
            return result
        if major == 7 and additional == 20:
            return False
        if major == 7 and additional == 21:
            return True
        raise ValidationError("payload CBOR contains a forbidden tag, null, float, or simple value")


def encode_operation_payload(payload: object) -> bytes:
    return _deterministic_cbor(payload_value(payload))


def decode_operation_payload(source: bytes) -> Any:
    parser = _CborParser(source)
    value = parser.parse()
    if parser.position != len(source) or _deterministic_cbor(value) != source:
        raise ValidationError("payload CBOR is not deterministic")
    return value
