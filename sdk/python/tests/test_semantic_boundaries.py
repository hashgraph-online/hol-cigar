"""Shared semantic admission cases must agree with the Rust/TypeScript contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from importlib import resources

import pytest

from cigar_sdk import ValidationError, apply_context_delta, bundle_id, delta_digest, models, verify_bundle
from cigar_sdk.digest import _deterministic_cbor, _normalize
from cigar_sdk.models_runtime import (
    construct_payload,
    decode_operation_payload,
    encode_operation_payload,
    payload_value,
)

VECTORS = json.loads(resources.files("cigar_sdk.fixtures").joinpath("semantic-boundaries-v1.json").read_text())
DIGEST = "1220" + "1" * 64


def unchecked_bundle(blocks):
    value = {
        "schema_version": "cigar.context-bundle.v1",
        "contract_digest": DIGEST,
        "manifest_digest": DIGEST,
        "blocks": blocks,
        "total_tokens": sum(block["token_count"] for block in blocks),
        "extensions": {},
    }
    value["bundle_id"] = (
        "1220" + hashlib.sha256(b"CIGAR-BUNDLE\0v1\0" + _deterministic_cbor([2, _normalize(value)])).hexdigest()
    )
    return value


@pytest.mark.parametrize("case", VECTORS["representation_receipts"])
def test_representation_receipts_at_every_public_boundary(case):
    block = {
        "block_id": DIGEST,
        "lane": "evidence",
        "representation": case["representation"],
        "content_digest": DIGEST,
        "token_count": 1,
        "provenance": [DIGEST],
    }
    if case["receipt"]:
        block["transform_receipt"] = DIGEST
    target = unchecked_bundle([block])
    base = unchecked_bundle([])
    delta = {
        "schema_version": "cigar.context-delta.v1",
        "base_bundle_id": base["bundle_id"],
        "target_bundle_id": target["bundle_id"],
        "added_blocks": [block],
        "removed_block_ids": [],
        "resulting_tokens": 1,
    }
    response = {"delta": delta, "delta_digest": DIGEST}
    operations = [
        lambda: verify_bundle(target),
        lambda: bundle_id(target),
        lambda: delta_digest(delta),
        lambda: construct_payload(models.ContextBundle, target),
        lambda: payload_value(models.ContextBundle(**target)),
        lambda: encode_operation_payload(models.ContextBundle(**target)),
        lambda: construct_payload(models.ContextDeltaResponse, response),
        lambda: encode_operation_payload(models.ContextDeltaResponse(**response)),
    ]
    original = copy.deepcopy((base, target, delta))
    if case["valid"]:
        for operation in operations:
            operation()
        assert bundle_id(target) == target["bundle_id"]
        assert apply_context_delta(base, target, delta, delta_digest(delta)) == target
    else:
        for operation in operations:
            with pytest.raises(ValidationError, match="transform receipt"):
                operation()
        with pytest.raises(ValidationError, match="transform receipt"):
            apply_context_delta(base, target, delta, DIGEST)
    assert (base, target, delta) == original


@pytest.mark.parametrize("receipt", [None, "invalid", 3, True])
def test_receipt_is_never_silently_omitted_or_reinterpreted(receipt):
    block = {
        "block_id": DIGEST,
        "lane": "evidence",
        "representation": "summarized",
        "content_digest": DIGEST,
        "token_count": 1,
        "provenance": [DIGEST],
        "transform_receipt": receipt,
    }
    target = unchecked_bundle([{key: value for key, value in block.items() if key != "transform_receipt"}])
    target["blocks"] = [block]
    for operation in (
        lambda: bundle_id(target),
        lambda: verify_bundle(target),
        lambda: construct_payload(models.ContextBundle, target),
        lambda: encode_operation_payload(models.ContextBundle(**target)),
    ):
        with pytest.raises(ValidationError):
            operation()


def test_shared_reserved_keys_survive_nominal_and_cbor_boundaries():
    record = unchecked_bundle([])
    record["extensions"] = {"example": {"type": "object", "value": VECTORS["operation_map"]}}
    model = construct_payload(models.ContextBundle, record)
    encoded = encode_operation_payload(model)
    assert decode_operation_payload(encoded) == record
    assert encoded == _deterministic_cbor(record)
    assert set(decode_operation_payload(encoded)["extensions"]["example"]["value"]) == set(VECTORS["operation_map"])


def test_sealing_never_discards_duplicate_block_members():
    class DuplicateBlock(dict):
        def items(self):
            return [*super().items(), ("block_id", DIGEST)]

    block = {
        "block_id": DIGEST,
        "lane": "evidence",
        "representation": "exact",
        "content_digest": DIGEST,
        "token_count": 1,
        "provenance": [DIGEST],
    }
    record = unchecked_bundle([block])
    record["blocks"] = [DuplicateBlock(block)]
    for operation in (lambda: bundle_id(record), lambda: verify_bundle(record)):
        with pytest.raises(ValidationError, match="collide"):
            operation()
