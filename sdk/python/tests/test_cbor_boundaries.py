"""Canonical CBOR conformance vectors at the untrusted response boundary."""

from __future__ import annotations

import pytest

from cigar_sdk import ValidationError
from cigar_sdk.digest import _deterministic_cbor
from cigar_sdk.models_runtime import decode_operation_payload


@pytest.mark.parametrize(
    "wire",
    [
        b"",
        b"\x18",
        b"\x18\x01",
        b"\x1f",
        b"\xff",
        b"\xf6",
        b"\xf9\x00\x00",
        b"\x61\xff",
        b"\x82\x00",
        b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\xa1\x01\x02",
        b"\xa2\x61b\x01\x61a\x02",
        b"\xa2\x61a\x01\x61a\x02",
        b"\xa2\x62\xc3\xa9\x01\x63e\xcc\x81\x02",
        b"\x00\x00",
        b"\x9a\x00\x01\x86\xa1",
        b"\xba\x00\x01\x86\xa1",
        b"\x81" * 66 + b"\x00",
    ],
)
def test_noncanonical_or_truncated_frames_are_rejected(wire):
    with pytest.raises(ValidationError):
        decode_operation_payload(wire)


@pytest.mark.parametrize(
    "value", [False, True, b"\x00\xff", -(2**63), 2**64 - 1, "café", [1, "a"], {"a": 1, "b": False}]
)
def test_valid_boundaries_round_trip_without_changing_bytes(value):
    wire = _deterministic_cbor(value)
    assert decode_operation_payload(wire) == value
    assert _deterministic_cbor(decode_operation_payload(wire)) == wire
