"""Small injectable bounded HTTP transport used by both facades."""

from __future__ import annotations

import http.client
import io
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from cigar_sdk.errors import CigarTimeoutError, TransportError


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CigarTimeoutError("CIGAR response deadline elapsed")
    return remaining


class _DeadlineReader(io.RawIOBase):
    """Bound each actual socket read, including reads hidden inside readline/read."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._socket = sock
        self._deadline = deadline
        self._raw = sock.makefile("rb", buffering=0)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int | None:
        self._socket.settimeout(_remaining(self._deadline))
        result = self._raw.readinto(buffer)
        _remaining(self._deadline)
        return result

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _ResponseSocket:
    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.socket = sock
        self.deadline = deadline

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("HTTP response reader requires binary mode")
        return io.BufferedReader(_DeadlineReader(self.socket, self.deadline))


def _response_class(deadline: float) -> type[http.client.HTTPResponse]:
    class Response(http.client.HTTPResponse):
        def __init__(self, sock: socket.socket, **kwargs: Any) -> None:
            self._deadline_socket = sock
            # HTTPResponse only uses makefile on its socket. Retain the standard
            # HTTP parser while enforcing the budget below its buffered reads.
            super().__init__(cast(socket.socket, _ResponseSocket(sock, deadline)), **kwargs)

        def abort(self) -> None:
            try:
                self._deadline_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Already closed; explicit close remains idempotent.

    return Response


class _DeadlineRequest(urllib.request.Request):
    def __init__(self, *args: Any, deadline: float, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.deadline = deadline


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request: urllib.request.Request) -> http.client.HTTPResponse:
        deadline = cast(_DeadlineRequest, request).deadline

        def connection(host: str, **kwargs: Any) -> http.client.HTTPConnection:
            kwargs["timeout"] = _remaining(deadline)
            conn = http.client.HTTPConnection(host, **kwargs)
            conn.response_class = _response_class(deadline)
            return conn

        return self.do_open(connection, request)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request: urllib.request.Request) -> http.client.HTTPResponse:
        deadline = cast(_DeadlineRequest, request).deadline

        def connection(host: str, **kwargs: Any) -> http.client.HTTPSConnection:
            kwargs["timeout"] = _remaining(deadline)
            # HTTPSConnection's default context verifies certificates and hostnames.
            conn = http.client.HTTPSConnection(host, **kwargs)
            conn.response_class = _response_class(deadline)
            return conn

        return self.do_open(connection, request)


def _abort(response: object) -> None:
    if isinstance(response, urllib.error.HTTPError):
        response = response.fp
    abort = getattr(response, "abort", None)
    if callable(abort):
        abort()


_SINGLETON_RESPONSE_HEADERS = {
    "content-length",
    "content-type",
    "etag",
    "x-cigar-api-version",
    "x-cigar-next-page-cursor",
}


class _HeaderSource(Protocol):
    def items(self) -> Iterable[tuple[str, str]]: ...


def _response_headers(raw: _HeaderSource) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for key, value in raw.items():
        normalized = key.lower()
        if normalized in result and normalized in _SINGLETON_RESPONSE_HEADERS:
            raise TransportError(f"HTTP response duplicated {normalized}")
        result[normalized] = value
    return result


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class StreamResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def __iter__(self) -> Iterator[bytes]: ...

    def close(self) -> None: ...


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse: ...

    def stream(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> StreamResponse: ...


class _RawResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def __iter__(self) -> Iterator[bytes]: ...

    def readline(self, limit: int = -1) -> bytes: ...

    def close(self) -> None: ...


class _UrllibStream:
    def __init__(self, response: object, deadline: float) -> None:
        self._response = cast(_RawResponse, response)
        self._deadline = deadline
        self.status = int(self._response.status)
        raw_headers = self._response.headers
        self.headers: Mapping[str, str]
        try:
            self.headers = _response_headers(raw_headers)
        except TransportError:
            self._response.close()
            raise

    def __iter__(self) -> Iterator[bytes]:
        while True:
            try:
                _remaining(self._deadline)
                line = self._response.readline(2 * 1024 * 1024 + 1)
                _remaining(self._deadline)
            except TimeoutError as error:
                raise CigarTimeoutError("CIGAR stream deadline elapsed") from error
            except OSError as error:
                raise TransportError("CIGAR stream read failed") from error
            if not line:
                return
            if len(line) > 2 * 1024 * 1024:
                raise TransportError("event stream line exceeds its bound")
            yield line

    def close(self) -> None:
        # Wake an in-flight reader before close waits for the buffered-reader lock.
        _abort(self._response)
        self._response.close()


class UrllibTransport:
    """Dependency-free transport with no ambient proxy bypasses or unbounded reads."""

    def __init__(self) -> None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: object, **kwargs: object) -> None:
                del args, kwargs
                return None

        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(), _HTTPHandler(), _HTTPSHandler()
        )

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        deadline = time.monotonic() + timeout
        request = _DeadlineRequest(url=url, data=body, headers=dict(headers), method=method, deadline=deadline)
        try:
            with self._opener.open(request, timeout=_remaining(deadline)) as response:
                _remaining(deadline)
                payload = response.read(24 * 1024 * 1024 + 1)
                _remaining(deadline)
                if len(payload) > 24 * 1024 * 1024:
                    raise TransportError("HTTP response exceeds its bound")
                return HttpResponse(
                    status=int(response.status),
                    headers=_response_headers(response.headers),
                    body=payload,
                )
        except urllib.error.HTTPError as error:
            try:
                payload = error.read(65_537)
                _remaining(deadline)
                if len(payload) > 65_536:
                    raise TransportError("HTTP problem exceeds its bound") from error
                return HttpResponse(
                    status=error.code,
                    headers=_response_headers(error.headers),
                    body=payload,
                )
            except TimeoutError as timeout_error:
                raise CigarTimeoutError("CIGAR request deadline elapsed") from timeout_error
            finally:
                error.close()
        except TimeoutError as error:
            raise CigarTimeoutError("CIGAR request deadline elapsed") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise CigarTimeoutError("CIGAR request deadline elapsed") from error
            raise TransportError("CIGAR transport failed") from error

    def stream(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> StreamResponse:
        deadline = time.monotonic() + timeout
        request = _DeadlineRequest(url=url, headers=dict(headers), method=method, deadline=deadline)
        try:
            response = self._opener.open(request, timeout=_remaining(deadline))
            try:
                _remaining(deadline)
                return _UrllibStream(response, deadline)
            except BaseException:
                response.close()
                raise
        except urllib.error.HTTPError as error:
            return _UrllibStream(error, deadline)
        except TimeoutError as error:
            raise CigarTimeoutError("CIGAR stream deadline elapsed") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise CigarTimeoutError("CIGAR stream deadline elapsed") from error
            raise TransportError("CIGAR stream transport failed") from error
