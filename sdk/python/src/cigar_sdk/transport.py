"""Small injectable bounded HTTP transport used by both facades."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from cigar_sdk.errors import CigarTimeoutError, TransportError

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
    def __init__(self, response: object) -> None:
        self._response = cast(_RawResponse, response)
        self.status = int(self._response.status)
        raw_headers = self._response.headers
        self.headers: Mapping[str, str]
        self.headers = _response_headers(raw_headers)

    def __iter__(self) -> Iterator[bytes]:
        while True:
            try:
                line = self._response.readline(2 * 1024 * 1024 + 1)
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
        self._response.close()


class UrllibTransport:
    """Dependency-free transport with no ambient proxy bypasses or unbounded reads."""

    def __init__(self) -> None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: object, **kwargs: object) -> None:
                del args, kwargs
                return None

        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        request = urllib.request.Request(url=url, data=body, headers=dict(headers), method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                payload = response.read(24 * 1024 * 1024 + 1)
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
                if len(payload) > 65_536:
                    raise TransportError("HTTP problem exceeds its bound") from error
                return HttpResponse(
                    status=error.code,
                    headers=_response_headers(error.headers),
                    body=payload,
                )
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
        request = urllib.request.Request(url=url, headers=dict(headers), method=method)
        try:
            return _UrllibStream(self._opener.open(request, timeout=timeout))
        except urllib.error.HTTPError as error:
            return _UrllibStream(error)
        except TimeoutError as error:
            raise CigarTimeoutError("CIGAR stream deadline elapsed") from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise CigarTimeoutError("CIGAR stream deadline elapsed") from error
            raise TransportError("CIGAR stream transport failed") from error
