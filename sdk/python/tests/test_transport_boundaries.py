"""Exercise HTTP resource ownership and byte limits without external services."""

from __future__ import annotations

import io
from email.message import Message
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from cigar_sdk.errors import CigarTimeoutError, TransportError
from cigar_sdk.transport import UrllibTransport


class Response(io.BytesIO):
    def __init__(self, data=b"ok", headers=()):
        super().__init__(data)
        self.status = 200
        self.headers = Message()
        for name, value in headers:
            self.headers[name] = value


def transport(response=None, error=None):
    client = UrllibTransport()
    client._opener = Mock()
    client._opener.open = Mock(return_value=response, side_effect=error)
    return client


def call(client, streaming):
    if streaming:
        return client.stream("GET", "https://fixture.invalid/", {}, 1.0)
    return client.request("GET", "https://fixture.invalid/", {}, None, 1.0)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "header", ["Content-Type", "Content-Length", "ETag", "X-Cigar-Api-Version", "X-Cigar-Next-Page-Cursor"]
)
def test_duplicate_singleton_headers_reject_and_close(streaming, header):
    response = Response(headers=[(header, "one"), (header.lower(), "two")])
    with pytest.raises(TransportError):
        call(transport(response), streaming)
    assert response.closed


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "error,expected",
    [
        (TimeoutError("SECRET"), CigarTimeoutError),
        (URLError(TimeoutError("SECRET")), CigarTimeoutError),
        (URLError("SECRET"), TransportError),
    ],
)
def test_transport_errors_are_stable_and_content_free(streaming, error, expected):
    with pytest.raises(expected) as raised:
        call(transport(error=error), streaming)
    assert "SECRET" not in str(raised.value)


@pytest.mark.parametrize("limit,extra", [(24 * 1024 * 1024, 0), (24 * 1024 * 1024, 1)])
def test_response_byte_boundary(limit, extra):
    response = Response(b"x" * (limit + extra), [("X-Trace", "a"), ("X-Trace", "b")])
    if extra:
        with pytest.raises(TransportError):
            call(transport(response), False)
    else:
        result = call(transport(response), False)
        assert len(result.body) == limit and result.headers["x-trace"] == "b"
    assert response.closed


@pytest.mark.parametrize("extra", [0, 1])
def test_http_problem_byte_boundary_and_resource_close(extra):
    body = io.BytesIO(b"x" * (65536 + extra))
    error = HTTPError("https://fixture.invalid/", 400, "problem", Message(), body)
    if extra:
        with pytest.raises(TransportError):
            call(transport(error=error), False)
    else:
        result = call(transport(error=error), False)
        assert result.status == 400 and len(result.body) == 65536
    assert body.closed


def test_http_error_stream_is_owned_by_caller():
    body = io.BytesIO(b"error\n")
    error = HTTPError("https://fixture.invalid/", 400, "problem", Message(), body)
    stream = call(transport(error=error), True)
    assert list(stream) == [b"error\n"] and stream.status == 400
    stream.close()
    assert body.closed


@pytest.mark.parametrize("extra", [0, 1])
def test_stream_line_byte_boundary(extra):
    response = Response(b"x" * (2 * 1024 * 1024 - 1 + extra) + b"\n")
    stream = call(transport(response), True)
    try:
        if extra:
            with pytest.raises(TransportError):
                list(stream)
        else:
            lines = list(stream)
            assert len(lines) == 1 and len(lines[0]) == 2 * 1024 * 1024
    finally:
        stream.close()
    assert response.closed


@pytest.mark.parametrize(
    "error,expected", [(TimeoutError("SECRET"), CigarTimeoutError), (OSError("SECRET"), TransportError)]
)
def test_stream_read_failure_retains_explicit_close(error, expected):
    response = Response()
    response.readline = Mock(side_effect=error)
    stream = call(transport(response), True)
    with pytest.raises(expected) as raised:
        list(stream)
    assert "SECRET" not in str(raised.value)
    stream.close()
    assert response.closed
