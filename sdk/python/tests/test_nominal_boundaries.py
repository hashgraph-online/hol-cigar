"""The published request schemas reject invalid values before encoding."""

from __future__ import annotations

import copy

import pytest

from cigar_sdk import ValidationError, models
from cigar_sdk.models_runtime import construct_payload, decode_operation_payload, encode_operation_payload


def query():
    return {
        "max_results": 10,
        "requirements": [
            {
                "semantic_type": "source_code",
                "selector": {"type": "query", "value": "authorization"},
                "minimum_authority": 0,
                "minimum_coverage": 1,
                "blocking": True,
            }
        ],
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_results", True),
        ("max_results", -1),
        ("max_results", 65536),
        ("requirements", "not an array"),
        ("requirements", []),
        ("requirements", [query()["requirements"][0]] * 257),
    ],
)
def test_catalog_request_bounds(field, value):
    value = {**query(), field: value}
    with pytest.raises(ValidationError):
        construct_payload(models.QueryCatalogRequest, value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("blocking", 1),
        ("minimum_authority", 65536),
        ("semantic_type", "unknown"),
        ("selector", {"type": "query", "value": ""}),
        ("selector", {"type": "query", "value": "x" * 16385}),
        ("selector", {"type": "exact", "value": "z" * 68}),
        ("selector", {"type": "query", "value": 1}),
    ],
)
def test_nested_catalog_request_bounds(field, value):
    record = query()
    record["requirements"][0][field] = value
    with pytest.raises(ValidationError):
        construct_payload(models.QueryCatalogRequest, record)


def test_nominal_request_freezes_nested_caller_data_and_round_trips():
    record = query()
    expected = copy.deepcopy(record)
    payload = construct_payload(models.QueryCatalogRequest, record)
    record["requirements"][0]["selector"]["value"] = "changed"
    assert decode_operation_payload(encode_operation_payload(payload)) == expected
    with pytest.raises(TypeError):
        payload.requirements[0]["blocking"] = False


def test_unknown_models_and_unsupported_fields_are_rejected():
    with pytest.raises(ValidationError):
        construct_payload(dict, {})
    with pytest.raises(ValidationError):
        encode_operation_payload(object())
    with pytest.raises(ValidationError):
        encode_operation_payload(models.QueryCatalogRequest(max_results=1, requirements=(object(),)))
