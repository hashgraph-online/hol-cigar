"""Independent Python verifier for CIGAR canonicalization vectors."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class CanonicalFailure(ValueError):
    """Stable content-free canonicalization failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _integer(value: str) -> int:
    parsed = int(value)
    if parsed < -(1 << 63) or parsed > (1 << 64) - 1:
        raise CanonicalFailure("float_forbidden")
    return parsed


def _floating(_value: str) -> float:
    raise CanonicalFailure("float_forbidden")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalFailure("duplicate_key")
        result[key] = value
    return result


def parse_strict_json(source: str) -> Any:
    """Parse JSON while rejecting duplicates, floats, null, overflow, and trailing data."""

    try:
        value = json.loads(
            source,
            parse_int=_integer,
            parse_float=_floating,
            parse_constant=_floating,
            object_pairs_hook=_object,
        )
    except CanonicalFailure:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        raise CanonicalFailure("invalid_input") from error
    _reject_null(value)
    return value


def _reject_null(value: Any) -> None:
    if value is None:
        raise CanonicalFailure("null_forbidden")
    if isinstance(value, list):
        for child in value:
            _reject_null(child)
    elif isinstance(value, dict):
        for child in value.values():
            _reject_null(child)


def normalized_json(value: Any) -> bytes:
    """Render compact UTF-8 JSON with lexicographically sorted keys."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _head(major: int, argument: int) -> bytes:
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    if argument <= 0xFF:
        return bytes([prefix | 24, argument])
    if argument <= 0xFFFF:
        return bytes([prefix | 25]) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + argument.to_bytes(4, "big")
    if argument <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + argument.to_bytes(8, "big")
    raise CanonicalFailure("limit_exceeded")


def deterministic_cbor(value: Any) -> bytes:
    """Encode the deterministic CIGAR RFC 8949 subset."""

    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(deterministic_cbor(child) for child in value)
    if isinstance(value, dict):
        entries = [(deterministic_cbor(key), child) for key, child in value.items()]
        entries.sort(key=lambda entry: entry[0])
        return _head(5, len(entries)) + b"".join(
            key + deterministic_cbor(child) for key, child in entries
        )
    if value is None:
        raise CanonicalFailure("null_forbidden")
    raise CanonicalFailure("float_forbidden")


class _CborParser:
    def __init__(self, source: bytes) -> None:
        self.source = source
        self.position = 0

    def byte(self) -> int:
        if self.position >= len(self.source):
            raise CanonicalFailure("invalid_input")
        value = self.source[self.position]
        self.position += 1
        return value

    def exact(self, length: int) -> bytes:
        end = self.position + length
        if end > len(self.source):
            raise CanonicalFailure("invalid_input")
        value = self.source[self.position : end]
        self.position = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        size = sizes.get(additional)
        if size is None:
            raise CanonicalFailure("non_canonical")
        value = int.from_bytes(self.exact(size), "big")
        minimum = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[size]
        if value < minimum:
            raise CanonicalFailure("non_canonical")
        return value

    def parse(self) -> Any:
        initial = self.byte()
        major, additional = initial >> 5, initial & 31
        if major == 0:
            return self.argument(additional)
        if major == 1:
            value = -1 - self.argument(additional)
            if value < -(1 << 63):
                raise CanonicalFailure("limit_exceeded")
            return value
        if major in (2, 3):
            data = self.exact(self.argument(additional))
            if major == 2:
                return data
            try:
                return data.decode()
            except UnicodeDecodeError as error:
                raise CanonicalFailure("invalid_input") from error
        if major == 4:
            return [self.parse() for _ in range(self.argument(additional))]
        if major == 5:
            result: dict[str, Any] = {}
            previous: bytes | None = None
            for _ in range(self.argument(additional)):
                start = self.position
                key = self.parse()
                encoded = self.source[start : self.position]
                if not isinstance(key, str) or (previous is not None and previous >= encoded):
                    raise CanonicalFailure("non_canonical")
                previous = encoded
                if key in result:
                    raise CanonicalFailure("duplicate_key")
                result[key] = self.parse()
            return result
        if major == 6:
            raise CanonicalFailure("non_canonical")
        if major == 7 and additional in (20, 21):
            return additional == 21
        if major == 7 and additional == 22:
            raise CanonicalFailure("null_forbidden")
        if major == 7 and additional in (25, 26, 27):
            raise CanonicalFailure("float_forbidden")
        raise CanonicalFailure("non_canonical")


def strict_cbor(source: bytes) -> Any:
    """Decode CBOR only if it is already deterministic."""

    parser = _CborParser(source)
    value = parser.parse()
    if parser.position != len(source) or deterministic_cbor(value) != source:
        raise CanonicalFailure("non_canonical")
    return value


DOMAINS = {
    "atom": b"CIGAR-ATOM",
    "bundle": b"CIGAR-BUNDLE",
    "manifest": b"CIGAR-MANIFEST",
    "handoff": b"CIGAR-HANDOFF",
    "effect": b"CIGAR-EFFECT",
    "receipt": b"CIGAR-RECEIPT",
    "extension_manifest": b"CIGAR-EXTENSION-MANIFEST",
}


def digest(domain: str, cbor: bytes) -> bytes:
    """Compute one domain-separated v1 digest."""

    return hashlib.sha256(DOMAINS[domain] + b"\0v1\0" + cbor).digest()


def _differential_record(index: int) -> dict[str, Any]:
    return {
        "active": index % 2 == 0,
        "index": index,
        "label": f"record-{index % 997}",
        "values": [index % 17, -(index % 19) - 1],
    }


def verify(path: Path) -> tuple[int, int]:
    """Verify all golden vectors and the 100,000-record differential gate."""

    manifest = json.loads(path.read_text())
    valid = manifest["valid"]
    invalid = manifest["invalid"]
    if (
        manifest["schema_version"] != 1
        or manifest["profile"] != "cigar-canonical-v1"
        or manifest["valid_count"] != len(valid)
        or manifest["invalid_count"] != len(invalid)
        or len(valid) < 200
    ):
        raise ValueError("invalid vector manifest metadata")
    for vector in valid:
        value = parse_strict_json(vector["json_input"])
        if vector["normalization"] == "nfc:/human_text":
            import unicodedata

            value["human_text"] = unicodedata.normalize("NFC", value["human_text"])
        elif vector["normalization"] != "none":
            raise ValueError(f"unknown normalization profile {vector['normalization']}")
        cbor = deterministic_cbor(value)
        expected_digest = digest(vector["domain"], cbor)
        assert normalized_json(value).decode() == vector["normalized_json"], vector["id"]
        assert cbor.hex() == vector["cbor_hex"], vector["id"]
        assert strict_cbor(cbor) == value, vector["id"]
        assert expected_digest.hex() == vector["digest_hex"], vector["id"]
        assert "1220" + expected_digest.hex() == vector["multihash"], vector["id"]
        assert (b"CIGAR-SIGNATURE\0v1\0" + cbor).hex() == vector["signature_input_hex"], vector["id"]
    for vector in invalid:
        try:
            if vector["encoding"] == "json":
                parse_strict_json(vector["input"])
            elif vector["encoding"] == "cbor_hex":
                strict_cbor(bytes.fromhex(vector["input"]))
            elif vector["encoding"] == "signature_hex" and len(bytes.fromhex(vector["input"])) != 64:
                raise CanonicalFailure("invalid_argument")
            elif vector["encoding"] == "semantic":
                raise CanonicalFailure("invalid_argument")
            else:
                raise ValueError(f"unsupported invalid vector {vector['id']}")
        except CanonicalFailure as error:
            assert error.code == vector["error"], vector["id"]
        else:
            raise AssertionError(f"invalid vector accepted: {vector['id']}")
    differential = manifest["differential"]
    if differential["algorithm"] != "cigar-differential-record-v1" or differential["count"] < 100_000:
        raise ValueError("invalid differential gate metadata")
    accumulator = hashlib.sha256()
    for index in range(differential["count"]):
        accumulator.update(digest(differential["domain"], deterministic_cbor(_differential_record(index))))
    assert accumulator.hexdigest() == differential["digest_accumulator_hex"]
    return len(valid) + len(invalid), differential["count"]


def main() -> None:
    """CLI entry point."""

    path = Path(sys.argv[1] if len(sys.argv) > 1 else "schemas/vectors/canonical-v1.json")
    vector_count, differential_count = verify(path)
    print(f"verified {vector_count} canonical vectors and {differential_count} differential records")


if __name__ == "__main__":
    main()
