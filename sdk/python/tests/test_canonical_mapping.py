"""Public integrity and payload admission must never discard a mapping entry."""

from __future__ import annotations

import copy
import json
import unicodedata
from collections import UserDict
from importlib.resources import files
from types import MappingProxyType

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cigar_sdk import ValidationError, bundle_id, models, verify_bundle
from cigar_sdk.digest import _deterministic_cbor, _normalize
from cigar_sdk.models_runtime import construct_payload, encode_operation_payload, payload_value
from cigar_sdk.qualify_bundle import _unique_object


def bundle():
    return json.loads(files("cigar_sdk.fixtures").joinpath("semantic-bundle-v1.json").read_text())["bundle"]


@pytest.mark.parametrize("keys", [(1, "1"), (True, "True"), (b"key", "b'key'"), ("é", "e\u0301")])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("equal_values", [False, True])
def test_ambiguous_nested_bundle_cannot_verify_as_one_entry(keys, reverse, equal_values):
    pairs = [(keys[0], "hidden"), (keys[1], "hidden" if equal_values else "visible")]
    if reverse:
        pairs.reverse()
    ambiguous = {"nested": dict(pairs)}
    original = copy.deepcopy(ambiguous)
    candidate = bundle()
    canonical_last_key = unicodedata.normalize("NFC", str(pairs[-1][0]))
    candidate["extensions"] = {"nested": {canonical_last_key: pairs[-1][1]}}
    candidate["bundle_id"] = bundle_id(candidate)
    verify_bundle(candidate)
    candidate["extensions"] = ambiguous
    with pytest.raises(ValidationError):
        bundle_id(candidate)
    with pytest.raises(ValidationError):
        verify_bundle(candidate)
    assert ambiguous == original


@pytest.mark.parametrize("wrapper", [dict, UserDict, MappingProxyType])
@pytest.mark.parametrize("mapping", [{1: b"a"}, {"é": b"a", "e\u0301": b"b"}])
def test_shared_encoder_and_nominal_payload_reject_before_copy(wrapper, mapping):
    wrapped = wrapper(mapping)
    with pytest.raises(ValidationError):
        _deterministic_cbor(wrapped)
    value = bundle()
    value["extensions"] = {"nested": wrapped}
    payload = models.ContextBundle(**value)
    for operation in (payload_value, encode_operation_payload):
        with pytest.raises(ValidationError):
            operation(payload)
    with pytest.raises(ValidationError):
        construct_payload(models.ContextBundle, value)


@settings(max_examples=300, derandomize=True)
@given(st.dictionaries(st.text(), st.integers(min_value=0, max_value=100), max_size=30))
def test_normalization_preserves_admitted_key_cardinality(value):
    keys = [unicodedata.normalize("NFC", key) for key in value]
    if len(set(keys)) != len(keys):
        with pytest.raises(ValidationError):
            _normalize(value)
    else:
        result = _normalize(value)
        assert len(result) == len(value)
        assert result == _normalize(dict(reversed(list(value.items()))))
        assert result == _normalize(result)


@settings(max_examples=100, derandomize=True)
@given(st.sampled_from(["é", "Å", "ǵ", "ñ", "가", "ḋ"]), st.integers())
def test_normalization_collisions_are_rejected_for_arbitrary_values(key, value):
    decomposed = unicodedata.normalize("NFD", key)
    assert decomposed != key
    with pytest.raises(ValidationError):
        _normalize({key: value, decomposed: value})


def test_raw_encoder_keeps_field_specific_text_and_bytes():
    assert _deterministic_cbor("e\u0301") == b"\x63e\xcc\x81"
    assert _deterministic_cbor(b"\x00\xff") == b"\x42\x00\xff"
    a, b = bundle(), bundle()
    a["extensions"] = {"é": ["café", b"\x00\xff"]}
    b["extensions"] = {"e\u0301": ["cafe\u0301", b"\x00\xff"]}
    assert bundle_id(a) == bundle_id(b)


def test_cli_parser_rejects_raw_duplicate_members_before_dictionary_creation():
    with pytest.raises(ValidationError):
        json.loads('{"extensions":{"x":1,"x":2}}', object_pairs_hook=_unique_object)


def test_recursive_values_and_large_maps_retain_bounds():
    value = []
    value.append(value)
    for operation in (_normalize, _deterministic_cbor):
        with pytest.raises(ValidationError, match="bound"):
            operation(value)
        with pytest.raises(ValidationError, match="bound"):
            operation({str(i): i for i in range(100_001)})
