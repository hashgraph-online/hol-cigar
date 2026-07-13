"""Local semantic bundle and sealed-delta verification."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

from cigar_sdk.errors import ValidationError

_DIGEST = re.compile(r"^1220[0-9a-f]{64}$")
_LANES = {"rules": 0, "task": 1, "evidence": 2, "history": 3, "tools": 4}
_REPRESENTATIONS = {"exact", "extracted", "summarized", "redacted"}


def _head(major: int, argument: int) -> bytes:
    if argument < 0 or argument > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValidationError("canonical integer exceeds its bound")
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    for maximum, additional, width in (
        (0xFF, 24, 1),
        (0xFFFF, 25, 2),
        (0xFFFF_FFFF, 26, 4),
        (0xFFFF_FFFF_FFFF_FFFF, 27, 8),
    ):
        if argument <= maximum:
            return bytes([prefix | additional]) + argument.to_bytes(width, "big")
    raise ValidationError("canonical integer exceeds its bound")


def _deterministic_cbor(value: Any, depth: int = 0, budget: list[int] | None = None) -> bytes:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValidationError("canonical value exceeds nesting or node bounds")
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        if value < -(1 << 63):
            raise ValidationError("canonical signed integer is below i64")
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(_deterministic_cbor(child, depth + 1, budget) for child in value)
    if isinstance(value, Mapping):
        entries = [(_deterministic_cbor(str(key), depth + 1, budget), child) for key, child in value.items()]
        entries.sort(key=lambda entry: entry[0])
        return _head(5, len(entries)) + b"".join(
            key + _deterministic_cbor(child, depth + 1, budget) for key, child in entries
        )
    raise ValidationError("semantic record contains a non-canonical value")


def _exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ValidationError(f"{context} has unknown or missing fields")


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValidationError(f"{context} must be a lowercase SHA-256 multihash")
    return value


def _normalize(value: Any, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValidationError("semantic record exceeds nesting or node bounds")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, bytes):
        return value
    if isinstance(value, list):
        return [_normalize(item, depth + 1, budget) for item in value]
    if isinstance(value, Mapping):
        return {
            unicodedata.normalize("NFC", str(key)): _normalize(child, depth + 1, budget) for key, child in value.items()
        }
    raise ValidationError("semantic records contain an unsupported canonical value")


def _block(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"block {index} must be an object")
    block = dict(value)
    expected = {"block_id", "lane", "representation", "content_digest", "token_count", "provenance"}
    if "transform_receipt" in block:
        expected.add("transform_receipt")
    _exact_keys(block, expected, f"block {index}")
    _digest(block["block_id"], f"block {index} id")
    _digest(block["content_digest"], f"block {index} content digest")
    if block["lane"] not in _LANES or block["representation"] not in _REPRESENTATIONS:
        raise ValidationError(f"block {index} has an unknown enum")
    tokens = block["token_count"]
    if isinstance(tokens, bool) or not isinstance(tokens, int) or not 1 <= tokens <= 0xFFFF_FFFF:
        raise ValidationError(f"block {index} token count is invalid")
    provenance = block["provenance"]
    if not isinstance(provenance, list) or not 1 <= len(provenance) <= 10_000:
        raise ValidationError(f"block {index} provenance is invalid")
    for item in provenance:
        _digest(item, f"block {index} provenance")
    if provenance != sorted(set(provenance)):
        raise ValidationError(f"block {index} provenance must be sorted and unique")
    receipt = block.get("transform_receipt")
    if receipt is None:
        block.pop("transform_receipt", None)
    else:
        _digest(receipt, f"block {index} transform receipt")
    return block


def bundle_id(bundle: Mapping[str, Any]) -> str:
    fields = dict(bundle)
    fields.pop("bundle_id", None)
    encoded = _deterministic_cbor([2, _normalize(fields)])
    separated = b"CIGAR-BUNDLE\0v1\0" + encoded
    return "1220" + hashlib.sha256(separated).hexdigest()


def verify_bundle(bundle: Mapping[str, Any]) -> None:
    _exact_keys(
        bundle,
        {"schema_version", "bundle_id", "contract_digest", "manifest_digest", "blocks", "total_tokens", "extensions"},
        "bundle",
    )
    if bundle["schema_version"] != "cigar.context-bundle.v1":
        raise ValidationError("unsupported bundle schema")
    _digest(bundle["bundle_id"], "bundle id")
    _digest(bundle["contract_digest"], "contract digest")
    _digest(bundle["manifest_digest"], "manifest digest")
    blocks = bundle["blocks"]
    if not isinstance(blocks, list) or len(blocks) > 10_000:
        raise ValidationError("bundle block count is invalid")
    checked = [_block(value, index) for index, value in enumerate(blocks)]
    ordering = [(_LANES[item["lane"]], item["block_id"]) for item in checked]
    if ordering != sorted(set(ordering)):
        raise ValidationError("bundle blocks must be lane/id sorted and unique")
    total = sum(item["token_count"] for item in checked)
    if total > 0xFFFF_FFFF or bundle["total_tokens"] != total:
        raise ValidationError("bundle token total is not exact")
    if not isinstance(bundle["extensions"], Mapping):
        raise ValidationError("bundle extensions must be an object")
    if bundle_id(bundle) != bundle["bundle_id"]:
        raise ValidationError("bundle identity verification failed")


def _delta_bytes(delta: Mapping[str, Any]) -> bytes:
    ordered = {
        "schema_version": delta["schema_version"],
        "base_bundle_id": delta["base_bundle_id"],
        "target_bundle_id": delta["target_bundle_id"],
        "added_blocks": [_block(value, index) for index, value in enumerate(delta["added_blocks"])],
        "removed_block_ids": list(delta["removed_block_ids"]),
        "resulting_tokens": delta["resulting_tokens"],
    }
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def delta_digest(delta: Mapping[str, Any]) -> str:
    return "1220" + hashlib.sha256(_delta_bytes(delta)).hexdigest()


def apply_context_delta(
    base: Mapping[str, Any],
    expected_target: Mapping[str, Any],
    delta: Mapping[str, Any],
    sealed_digest: str,
) -> dict[str, Any]:
    verify_bundle(base)
    verify_bundle(expected_target)
    _exact_keys(
        delta,
        {
            "schema_version",
            "base_bundle_id",
            "target_bundle_id",
            "added_blocks",
            "removed_block_ids",
            "resulting_tokens",
        },
        "delta",
    )
    if delta["schema_version"] != "cigar.context-delta.v1":
        raise ValidationError("unsupported delta schema")
    if delta["base_bundle_id"] != base["bundle_id"]:
        raise ValidationError("delta base does not match")
    if delta["target_bundle_id"] != expected_target["bundle_id"]:
        raise ValidationError("delta target does not match")
    if delta_digest(delta) != sealed_digest:
        raise ValidationError("sealed delta digest does not match")
    blocks = {item["block_id"]: dict(item) for item in base["blocks"]}
    removed = delta["removed_block_ids"]
    if not isinstance(removed, list) or removed != sorted(set(removed)):
        raise ValidationError("delta removal set must be sorted and unique")
    for item in removed:
        _digest(item, "removed block id")
        if blocks.pop(item, None) is None:
            raise ValidationError("delta removes a block absent from the base")
    added = [_block(value, index) for index, value in enumerate(delta["added_blocks"])]
    if [item["block_id"] for item in added] != sorted({item["block_id"] for item in added}):
        raise ValidationError("delta additions must be block-id sorted and unique")
    for item in added:
        if item["block_id"] in blocks or item["block_id"] in removed:
            raise ValidationError("delta addition conflicts with base or removal")
        blocks[item["block_id"]] = item
    targets = {item["block_id"]: dict(item) for item in expected_target["blocks"]}
    if blocks != targets or delta["resulting_tokens"] != expected_target["total_tokens"]:
        raise ValidationError("delta result does not reproduce the target")
    return copy.deepcopy(dict(expected_target))
