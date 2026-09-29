"""Remote ABI negative controls run entirely against injected local fixtures."""

from __future__ import annotations

import asyncio
import json

import pytest
from test_client import _EVENT_LINE, _PROBLEM, _UUID, FakeStream, FakeTransport, ok

from cigar_sdk import (
    AsyncCigarClient,
    CallOptions,
    CigarApiError,
    CigarClient,
    CompatibilityError,
    OperationRequest,
    PathParameter,
    TransportError,
    TypedOperationRequest,
    ValidationError,
    create_idempotency_key,
    models,
    validate_idempotency_key,
)
from cigar_sdk.transport import HttpResponse


def client(transport, **options):
    return CigarClient(
        "http://localhost",
        allow_insecure_loopback=True,
        transport=transport,
        trust_custom_transport=True,
        max_attempts=1,
        **options,
    )


@pytest.mark.parametrize(
    "url",
    [
        "ftp://localhost",
        "https://name:secret@example.invalid",
        "https://example.invalid?q=a",
        "https://example.invalid#fragment",
        "https://example.invalid/path",
        "http://example.invalid",
        "https://",
    ],
)
def test_invalid_origins_are_rejected(url):
    with pytest.raises(ValidationError):
        CigarClient(url, bearer_token="fixture", allow_insecure_loopback=True)


@pytest.mark.parametrize("timeout", [True, 0, -1, 301, float("nan"), "1"])
def test_timeout_bounds(timeout):
    with pytest.raises(ValidationError):
        CigarClient("https://fixture.invalid", bearer_token="fixture", timeout=timeout)


@pytest.mark.parametrize("attempts", [True, 0, 9])
def test_attempt_bounds(attempts):
    with pytest.raises(ValidationError):
        CigarClient("https://fixture.invalid", bearer_token="fixture", max_attempts=attempts)
    with pytest.raises(ValidationError):
        list(
            client(FakeTransport()).paginate(
                "getVersion", OperationRequest(), options=CallOptions(max_attempts=attempts)
            )
        )


@pytest.mark.parametrize("token", ["", "bad\nheader", "x" * 8193, 42])
def test_invalid_tokens_never_reach_transport(token):
    fake = FakeTransport()
    with pytest.raises(ValidationError):
        list(client(fake, bearer_token=token).paginate("getVersion", OperationRequest()))
    assert not fake.requests


def test_token_provider_failure_is_sanitized():
    def failure(timeout):
        raise RuntimeError("PRIVATE_TOKEN")

    with pytest.raises(TransportError) as raised:
        list(client(FakeTransport(), bearer_token=failure).paginate("getVersion", OperationRequest()))
    assert "PRIVATE_TOKEN" not in str(raised.value)


@pytest.mark.parametrize(
    "operation_request",
    [
        OperationRequest(payload_cbor=b"x"),
        OperationRequest(dry_run=True),
        OperationRequest(page_cursor="x" * 4097),
        OperationRequest(page_size=0),
        OperationRequest(page_size=True),
        OperationRequest(path_parameters=(PathParameter("extra", "value"),)),
        OperationRequest(path_parameters=(PathParameter("a", "../secret"),)),
        OperationRequest(path_parameters=(PathParameter("a", "1"), PathParameter("a", "2"))),
        OperationRequest(path_parameters=tuple(PathParameter(str(i), "v") for i in range(9))),
    ],
)
def test_invalid_get_metadata_does_not_dispatch(operation_request):
    fake = FakeTransport()
    with pytest.raises(ValidationError):
        list(client(fake).paginate("getVersion", operation_request))
    assert not fake.requests


@pytest.mark.parametrize(
    "operation,operation_request",
    [
        ("ingestCatalog", OperationRequest()),
        ("getVersion", OperationRequest(payload_cbor=b"x" * (1024 * 1024 + 1))),
        ("discoverSources", OperationRequest(idempotency_key="unexpected")),
        ("discoverSources", OperationRequest(expected_revision="unexpected")),
        ("recordHandoffResult", OperationRequest(idempotency_key="valid")),
        ("recordHandoffResult", OperationRequest(idempotency_key="valid", expected_revision="x" * 257)),
        ("unknown", OperationRequest()),
        ("subscribeSpaceEvents", OperationRequest()),
    ],
)
def test_invalid_mutation_metadata_does_not_dispatch(operation, operation_request):
    fake = FakeTransport()
    with pytest.raises(ValidationError):
        list(client(fake).paginate(operation, operation_request))
    assert not fake.requests


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"operation_id":"other","payload_cbor":"oA"}',
        b'{"operation_id":"getVersion","payload_cbor":"oA","unknown":1}',
        b'{"operation_id":"getVersion","payload_cbor":null}',
        b'{"operation_id":"getVersion","payload_cbor":"!"}',
        b'{"operation_id":"getVersion","payload_cbor":"A"}',
        b'{"operation_id":"getVersion","payload_cbor":"oB"}',
        b'{"operation_id":"getVersion","payload_cbor":"oA","next_page_cursor":42}',
        b'{"operation_id":"getVersion","operation_id":"getVersion","payload_cbor":"oA"}',
        b'{"operation_id":"getVersion","payload_cbor":NaN}',
        b"\xff",
    ],
)
def test_malformed_envelopes_cannot_be_accepted(body):
    fake = FakeTransport()
    fake.responses = [HttpResponse(200, {"content-type": "application/json"}, body)]
    with pytest.raises(TransportError):
        list(client(fake).paginate("getVersion", OperationRequest()))


@pytest.mark.parametrize(
    "headers",
    [
        {"x-cigar-api-version": "2"},
        {"content-length": "-1"},
        {"content-length": "999999999"},
        {"content-type": "text/html"},
    ],
)
def test_invalid_response_headers_are_rejected(headers):
    fake = FakeTransport()
    response = ok("getVersion")
    fake.responses = [HttpResponse(200, {**response.headers, **headers}, response.body)]
    with pytest.raises(CompatibilityError if "x-cigar-api-version" in headers else TransportError):
        list(client(fake).paginate("getVersion", OperationRequest()))


def test_overlong_semantic_etag_in_envelope_is_rejected():
    fake = FakeTransport()
    response = ok("getVersion")
    body = {**json.loads(response.body), "semantic_etag": "x" * 257}
    fake.responses = [HttpResponse(200, response.headers, json.dumps(body).encode())]
    with pytest.raises(TransportError):
        list(client(fake).paginate("getVersion", OperationRequest()))


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": "wrong"},
        {"error_code": "unknown"},
        {"http_status": 200},
        {"retryable": False},
        {"message": "x" * 4097},
        {"remediation": None},
        {"correlation_id": "bad"},
        {"details": []},
        {"extra": True},
    ],
)
def test_problem_metadata_must_match_error_catalog(change):
    fake = FakeTransport()
    body = {**json.loads(_PROBLEM), **change}
    fake.responses = [HttpResponse(503, {"content-type": "application/problem+json"}, json.dumps(body).encode())]
    with pytest.raises(TransportError):
        list(client(fake).paginate("getVersion", OperationRequest()))


@pytest.mark.parametrize(
    "lines",
    [
        [b"data: nope\n", b"\n"],
        [b"data: []\n", b"\n"],
        [b"\xff\n"],
        [b"event: problem\n", b"data: {}\n", b"\n"],
        [_EVENT_LINE, b"\n"],
        [b"id: wrong\n", _EVENT_LINE, b"\n"],
    ],
)
def test_invalid_stream_events_close_response(lines):
    fake = FakeTransport()
    stream = FakeStream(lines)
    fake.streams = [stream]
    with pytest.raises(TransportError):
        list(client(fake).subscribe_space_events(TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID))))
    assert stream.closed


def test_stream_problem_propagates_catalog_error_and_closes():
    fake = FakeTransport()
    stream = FakeStream([b"event: problem\n", b"data: " + _PROBLEM.strip() + b"\n", b"\n"])
    fake.streams = [stream]
    with pytest.raises(CigarApiError):
        list(client(fake).subscribe_space_events(TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID))))
    assert stream.closed


def test_async_stream_and_pagination_terminate_and_close():
    async def run():
        fake = FakeTransport()
        stream = FakeStream([b": comment\n", b"id: event-1\n", _EVENT_LINE, b"\n"])
        fake.streams = [stream]
        fake.responses = [ok("getVersion", cursor="next"), ok("getVersion")]
        async with AsyncCigarClient(
            "http://localhost",
            allow_insecure_loopback=True,
            transport=fake,
            trust_custom_transport=True,
            max_attempts=1,
        ) as instance:
            async with instance.subscribe_space_events(
                TypedOperationRequest(models.SpaceIdRequest(space_id=_UUID))
            ) as events:
                received = [event async for event in events]
                assert len(received) == 1 and events.last_event_id == "event-1"
            assert stream.closed
            assert len([page async for page in instance.paginate("getVersion", OperationRequest())]) == 2

    asyncio.run(run())


def test_idempotency_keys_are_unique_and_invalid_input_is_rejected():
    keys = {create_idempotency_key("offline") for _ in range(10)}
    assert len(keys) == 10 and all(validate_idempotency_key(key) == key for key in keys)
    for value in ("", "bad space", "é", "x" * 257):
        with pytest.raises(ValidationError):
            validate_idempotency_key(value)
        with pytest.raises(ValidationError):
            create_idempotency_key(value)
