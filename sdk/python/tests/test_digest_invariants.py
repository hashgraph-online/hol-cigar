"""Nonempty semantic bundles and sealed deltas must commit to every entry."""

from __future__ import annotations

import copy

import pytest

from cigar_sdk import ValidationError, apply_context_delta, bundle_id, delta_digest, verify_bundle
from cigar_sdk.digest import _deterministic_cbor


def digest(n):
    return "1220" + f"{n:064x}"


def block(n, lane="evidence"):
    return {
        "block_id": digest(n),
        "lane": lane,
        "representation": "exact",
        "content_digest": digest(100 + n),
        "token_count": 17,
        "provenance": [digest(200 + n)],
        "transform_receipt": digest(300 + n),
    }


def bundle(blocks):
    result = {
        "schema_version": "cigar.context-bundle.v1",
        "contract_digest": digest(900),
        "manifest_digest": digest(901),
        "blocks": blocks,
        "total_tokens": sum(item["token_count"] for item in blocks),
        "extensions": {},
    }
    result["bundle_id"] = bundle_id(result)
    return result


def transition():
    base, target = bundle([block(1), block(2)]), bundle([block(2), block(3)])
    delta = {
        "schema_version": "cigar.context-delta.v1",
        "base_bundle_id": base["bundle_id"],
        "target_bundle_id": target["bundle_id"],
        "added_blocks": [block(3)],
        "removed_block_ids": [digest(1)],
        "resulting_tokens": target["total_tokens"],
    }
    return base, target, delta


def test_nonempty_delta_round_trip_and_copy_isolation():
    base, target, delta = transition()
    before = copy.deepcopy((base, target, delta))
    result = apply_context_delta(base, target, delta, delta_digest(delta))
    assert result == target
    result["blocks"][0]["provenance"].append(digest(999))
    assert (base, target, delta) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "wrong"),
        ("contract_digest", "BAD"),
        ("manifest_digest", "BAD"),
        ("blocks", None),
        ("blocks", [block(1)] * 10001),
        ("blocks", ["not a block"]),
        ("blocks", [block(2), block(1)]),
        ("blocks", [block(1), block(1)]),
        ("blocks", [{**block(1), "token_count": 0xFFFFFFFF}, {**block(2), "token_count": 1}]),
        ("total_tokens", 18),
        ("extensions", []),
        ("bundle_id", digest(999)),
        ("extra", True),
    ],
)
def test_bundle_tampering_is_rejected(field, value):
    record = bundle([block(1)])
    record[field] = value
    with pytest.raises(ValidationError):
        verify_bundle(record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("lane", "other"),
        ("representation", "other"),
        ("token_count", True),
        ("token_count", 0),
        ("token_count", 0x100000000),
        ("token_count", 1.5),
        ("provenance", []),
        ("provenance", [digest(2), digest(1)]),
        ("provenance", [digest(1)] * 2),
        ("provenance", [digest(1)] * 10001),
        ("provenance", ["bad"]),
        ("transform_receipt", "bad"),
        ("content_digest", "bad"),
        ("extra", 1),
    ],
)
def test_invalid_blocks_cannot_be_resealed(field, value):
    record = bundle([block(1)])
    record["blocks"][0][field] = value
    with pytest.raises(ValidationError):
        record["bundle_id"] = bundle_id(record)
        verify_bundle(record)


def test_optional_transform_receipt_can_be_omitted():
    item = block(1)
    del item["transform_receipt"]
    verify_bundle(bundle([item]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "wrong"),
        ("base_bundle_id", digest(99)),
        ("target_bundle_id", digest(98)),
        ("removed_block_ids", [digest(1), digest(1)]),
        ("removed_block_ids", [digest(98)]),
        ("removed_block_ids", ["invalid"]),
        ("added_blocks", [block(3), block(3)]),
        ("added_blocks", [block(4), block(3)]),
        ("added_blocks", [block(2)]),
        ("added_blocks", [block(1)]),
        ("added_blocks", []),
        ("resulting_tokens", 1),
        ("extra", True),
    ],
)
def test_delta_tampering_is_rejected_even_if_resealed(field, value):
    base, target, delta = transition()
    delta[field] = value
    with pytest.raises(ValidationError):
        apply_context_delta(base, target, delta, delta_digest(delta))


def test_unsealed_change_is_rejected():
    base, target, delta = transition()
    with pytest.raises(ValidationError):
        apply_context_delta(base, target, delta, digest(0))


@pytest.mark.parametrize("value", [1.5, None, -(2**63) - 1, 2**64])
def test_noncanonical_scalar_is_rejected(value):
    with pytest.raises(ValidationError):
        _deterministic_cbor(value)


@pytest.mark.parametrize(
    "value,prefix",
    [
        (False, "f4"),
        (True, "f5"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (65536, "1a00010000"),
        (2**32, "1b0000000100000000"),
        (-1, "20"),
        (-(2**63), "3b7fffffffffffffff"),
    ],
)
def test_cbor_integer_boundaries_keep_standard_bytes(value, prefix):
    assert _deterministic_cbor(value).hex() == prefix
