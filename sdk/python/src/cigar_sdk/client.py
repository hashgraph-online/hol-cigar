"""Synchronous and asynchronous CIGAR v1 HTTP clients."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any, Self
from urllib.parse import urlencode, urlsplit

from cigar_sdk.errors import (
    CigarApiError,
    CigarTimeoutError,
    CompatibilityError,
    ProblemDetails,
    TransportError,
    ValidationError,
    is_retryable,
)
from cigar_sdk.generated.errors import ERROR_CATALOG
from cigar_sdk.generated.operations import (
    OPERATIONS,
    AsyncGeneratedOperations,
    GeneratedOperations,
    OperationDefinition,
)
from cigar_sdk.idempotency import validate_idempotency_key
from cigar_sdk.models_runtime import (
    construct_payload,
    decode_operation_payload,
    encode_operation_payload,
    payload_value,
)
from cigar_sdk.transport import HttpResponse, HttpTransport, StreamResponse, UrllibTransport
from cigar_sdk.types import (
    CallOptions,
    OperationEvent,
    OperationRequest,
    OperationResponse,
    PathParameter,
    TypedOperationEvent,
    TypedOperationRequest,
    TypedOperationResponse,
)

_MAX_TIMEOUT = 300.0
_MAX_PAYLOAD = 16 * 1024 * 1024
_MAX_PROBLEM = 64 * 1024
_MAX_EVENT = 1024 * 1024
_PATH_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PATH_VALUE = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")
_CORRELATION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
type BearerTokenProvider = str | Callable[[float], str]


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= _MAX_TIMEOUT:
        raise ValidationError("timeout must be in (0, 300] seconds")
    return float(value)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: Any, maximum: int) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise TransportError("server returned invalid base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except ValueError as error:
        raise TransportError("server returned invalid base64url") from error
    if len(decoded) > maximum or _base64url(decoded) != value:
        raise TransportError("server returned non-canonical or oversized base64url")
    return decoded


def _strict_json(source: bytes | str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    return json.loads(source, object_pairs_hook=unique, parse_constant=invalid_constant)


def _parameters(values: tuple[PathParameter, ...]) -> tuple[PathParameter, ...]:
    ordered = tuple(sorted(values))
    if len(ordered) > 8:
        raise ValidationError("at most eight path parameters are allowed")
    previous = ""
    for item in ordered:
        if _PATH_NAME.fullmatch(item.name) is None or _PATH_VALUE.fullmatch(item.value) is None:
            raise ValidationError("path parameter violates the frozen alphabet")
        if item.name <= previous:
            raise ValidationError("path parameter names must be unique")
        previous = item.name
    return ordered


def _bounded_stream_body(stream: StreamResponse, maximum: int) -> bytes:
    retained = bytearray()
    for chunk in stream:
        if len(chunk) > maximum - len(retained):
            raise TransportError("stream response exceeds its bound")
        retained.extend(chunk)
    return bytes(retained)


def _path(template: str, parameters: tuple[PathParameter, ...]) -> str:
    expected = re.findall(r"\{([a-z][a-z0-9_]*)\}", template)
    supplied = {item.name for item in parameters}
    if len(expected) != len(parameters) or supplied != set(expected):
        raise ValidationError("request path parameters do not exactly match the operation path")
    result = template
    for item in parameters:
        result = result.replace("{" + item.name + "}", item.value)
    return result


def _problem(response: HttpResponse) -> CigarApiError:
    declared = response.headers.get("content-length")
    if declared is not None and (not declared.isascii() or not declared.isdigit() or int(declared) > _MAX_PROBLEM):
        raise TransportError("HTTP problem Content-Length exceeds its bound")
    if len(response.body) > _MAX_PROBLEM:
        raise TransportError("HTTP problem exceeds its bound")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
    if content_type != "application/problem+json":
        raise TransportError(f"HTTP {response.status} did not use application/problem+json")
    return _decode_problem(response.status, response.body)


def _decode_problem(status: int, body: bytes) -> CigarApiError:
    if len(body) == 0 or len(body) > _MAX_PROBLEM:
        raise TransportError(f"HTTP {status} problem body exceeds its bound")
    try:
        value = _strict_json(body)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise TransportError(f"HTTP {status} did not contain a CIGAR problem") from error
    expected = {
        "schema_version",
        "code",
        "http_status",
        "retry",
        "message",
        "remediation",
        "correlation_id",
        "details",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise TransportError(f"HTTP {status} contained unknown or missing problem fields")
    code = value["code"]
    if value["schema_version"] != "cigar.problem.v1" or not isinstance(code, str) or code not in ERROR_CATALOG:
        raise TransportError(f"HTTP {status} contained an unsupported CIGAR problem")
    definition = ERROR_CATALOG[code]
    if (
        value["http_status"] != status
        or value["http_status"] != definition.http_status
        or value["retry"] != definition.retry
    ):
        raise TransportError(f"HTTP {status} problem disagrees with the frozen error catalog")
    message = value["message"]
    remediation = value["remediation"]
    correlation_id = value["correlation_id"]
    details = value["details"]
    if (
        not isinstance(message, str)
        or not 1 <= len(message.encode()) <= 4096
        or not isinstance(remediation, str)
        or not 1 <= len(remediation.encode()) <= 4096
        or not isinstance(correlation_id, str)
        or _CORRELATION_ID.fullmatch(correlation_id) is None
        or not isinstance(details, dict)
        or len(details) > 256
    ):
        raise TransportError(f"HTTP {status} contained an invalid bounded CIGAR problem")
    try:
        return CigarApiError(
            status,
            ProblemDetails(
                schema_version="cigar.problem.v1",
                code=code,
                numeric_code=definition.numeric_code,
                http_status=status,
                retry=value["retry"],
                message=message,
                remediation=remediation,
                correlation_id=correlation_id,
                details=details,
            ),
        )
    except ValueError as error:
        raise TransportError(f"HTTP {status} problem details violate their bounds") from error


def _response(operation_id: str, response: HttpResponse) -> OperationResponse:
    if not 200 <= response.status < 300:
        raise _problem(response)
    server_version = response.headers.get("x-cigar-api-version")
    if server_version is not None and server_version != "1":
        raise CompatibilityError(f"server API version {server_version} is incompatible with 1")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
    definition = OPERATIONS[operation_id]
    maximum = (
        definition.response_max_bytes
        if content_type == "application/openmetrics-text"
        else definition.response_max_bytes * 4 // 3 + 16 * 1024
    )
    declared = response.headers.get("content-length")
    if declared is not None and (not declared.isascii() or not declared.isdigit() or int(declared) > maximum):
        raise TransportError("HTTP response Content-Length exceeds its bound")
    if len(response.body) > maximum:
        raise TransportError("HTTP response exceeds its bound")
    if content_type == "application/openmetrics-text":
        return OperationResponse(operation_id=operation_id, payload_cbor=response.body)
    if content_type != "application/json":
        raise TransportError(f"unexpected response content type {content_type}")
    try:
        value = _strict_json(response.body)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise TransportError("server response is not valid JSON") from error
    allowed_fields = {"operation_id", "payload_cbor", "semantic_etag", "next_page_cursor"}
    if not isinstance(value, dict) or set(value) - allowed_fields:
        raise TransportError("server response has unknown fields")
    if value.get("operation_id") != operation_id:
        raise TransportError("server operation identity mismatch")
    semantic_etag = value.get("semantic_etag")
    next_cursor = value.get("next_page_cursor")
    if semantic_etag is not None and (not isinstance(semantic_etag, str) or len(semantic_etag) > 256):
        raise TransportError("server semantic ETag is invalid")
    if next_cursor is not None and (not isinstance(next_cursor, str) or len(next_cursor.encode()) > 4096):
        raise TransportError("server pagination cursor is invalid")
    return OperationResponse(
        operation_id=operation_id,
        payload_cbor=_decode_base64url(value.get("payload_cbor"), _MAX_PAYLOAD),
        semantic_etag=semantic_etag,
        next_page_cursor=next_cursor,
    )


class _Core:
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: BearerTokenProvider | None,
        timeout: float,
        max_attempts: int,
        transport: HttpTransport | None,
        trust_custom_transport: bool,
        allow_insecure_loopback: bool,
    ) -> None:
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
        except ValueError as error:
            raise ValidationError("base_url must be a valid HTTP(S) origin") from error
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValidationError("base_url must be an HTTP(S) origin without credentials")
        if parsed.query or parsed.fragment:
            raise ValidationError("base_url must not contain a query or fragment")
        if parsed.path not in {"", "/"}:
            raise ValidationError("base_url must be an origin with no path prefix")
        loopback = hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and (not loopback or not allow_insecure_loopback):
            raise ValidationError("cleartext HTTP requires explicit allow_insecure_loopback for loopback")
        if parsed.scheme == "https" and bearer_token is None:
            raise ValidationError("remote HTTPS requires an explicit bearer token provider")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout = _timeout(timeout)
        if isinstance(max_attempts, bool) or not 1 <= max_attempts <= 8:
            raise ValidationError("max_attempts must be in 1..8")
        self.max_attempts = max_attempts
        if transport is not None and not trust_custom_transport:
            raise ValidationError("custom transport requires explicit trust_custom_transport acknowledgement")
        self.transport = transport or UrllibTransport()

    def headers(self, operation_id: str, timeout: float) -> dict[str, str]:
        headers = {
            "accept": "application/json, application/problem+json",
            "x-cigar-api-version": "1",
            "x-cigar-operation-id": operation_id,
            "x-cigar-timeout-ms": str(round(timeout * 1000)),
        }
        if self.bearer_token is not None:
            try:
                token = self.bearer_token(timeout) if callable(self.bearer_token) else self.bearer_token
            except Exception as error:
                raise TransportError("bearer token provider failed") from error
            if not isinstance(token, str) or re.fullmatch(r"[\x21-\x7e]{1,8192}", token) is None:
                raise ValidationError("bearer token must be 1..8192 visible ASCII bytes")
            headers["authorization"] = f"Bearer {token}"
        return headers

    def attempts(self, operation_id: str, request: OperationRequest, options: CallOptions | None) -> int:
        attempts = options.max_attempts if options and options.max_attempts is not None else self.max_attempts
        if isinstance(attempts, bool) or not 1 <= attempts <= 8:
            raise ValidationError("max_attempts must be in 1..8")
        definition = OPERATIONS[operation_id]
        if operation_id == "dispatchEffect":
            return 1
        if definition.mutation and request.idempotency_key is None:
            return 1
        return attempts

    def call(self, operation_id: str, request: OperationRequest, options: CallOptions | None) -> OperationResponse:
        definition = OPERATIONS.get(operation_id)
        if definition is None or definition.stream:
            raise ValidationError("operation is unknown or streaming")
        attempts = self.attempts(operation_id, request, options)
        timeout = _timeout(options.timeout if options and options.timeout is not None else self.timeout)
        deadline = time.monotonic() + timeout
        for attempt in range(1, attempts + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CigarTimeoutError("CIGAR request deadline elapsed")
            try:
                return self._call_once(definition, request, remaining)
            except (CigarApiError, TransportError, CigarTimeoutError) as error:
                if attempt == attempts or not is_retryable(error):
                    raise
                delay = min(0.1 * (2 ** (attempt - 1)), 1.0)
                remaining = deadline - time.monotonic()
                if remaining <= delay:
                    if remaining > 0:
                        time.sleep(remaining)
                    raise CigarTimeoutError("CIGAR request deadline elapsed") from error
                time.sleep(delay)
        raise AssertionError("unreachable")

    def _call_once(
        self,
        definition: OperationDefinition,
        request: OperationRequest,
        timeout: float,
    ) -> OperationResponse:
        timeout = _timeout(timeout)
        parameters = _parameters(request.path_parameters)
        path = _path(definition.http_path, parameters)
        headers = self.headers(definition.operation_id, timeout)
        if len(request.payload_cbor) > definition.request_max_bytes:
            raise ValidationError("request payload exceeds operation bound")
        body: bytes | None = None
        if definition.http_method == "GET":
            if request.payload_cbor or request.idempotency_key or request.expected_revision or request.dry_run:
                raise ValidationError("GET operations do not carry payload or mutation metadata")
            query: dict[str, str] = {}
            if request.page_cursor is not None:
                if len(request.page_cursor.encode()) > 4096:
                    raise ValidationError("page cursor exceeds its bound")
                query["page_cursor"] = request.page_cursor
            if request.page_size is not None:
                if isinstance(request.page_size, bool) or not 1 <= request.page_size <= 1000:
                    raise ValidationError("page_size must be in 1..1000")
                query["page_size"] = str(request.page_size)
            if query:
                path += "?" + urlencode(query)
        else:
            if definition.idempotency_required:
                if request.idempotency_key is None:
                    raise ValidationError(f"{definition.operation_id} requires an idempotency key")
                headers["idempotency-key"] = validate_idempotency_key(request.idempotency_key)
            elif request.idempotency_key is not None:
                raise ValidationError(f"{definition.operation_id} does not accept an idempotency key")
            if definition.revision_required:
                if request.expected_revision is None or not 1 <= len(request.expected_revision) <= 256:
                    raise ValidationError(f"{definition.operation_id} requires an expected revision")
                headers["if-match"] = request.expected_revision
            elif request.expected_revision is not None:
                raise ValidationError(f"{definition.operation_id} does not accept an expected revision")
            headers["content-type"] = "application/json"
            wire = {
                "operation_id": definition.operation_id,
                "payload_cbor": _base64url(request.payload_cbor),
                "dry_run": request.dry_run,
                "path_parameters": [{"name": item.name, "value": item.value} for item in parameters],
            }
            if request.idempotency_key is not None:
                wire["idempotency_key"] = request.idempotency_key
            if request.expected_revision is not None:
                wire["expected_revision"] = request.expected_revision
            if request.page_cursor is not None:
                wire["page_cursor"] = request.page_cursor
            if request.page_size is not None:
                wire["page_size"] = request.page_size
            body = json.dumps(wire, separators=(",", ":")).encode()
        response = self.transport.request(
            definition.http_method,
            self.base_url + path,
            headers,
            body,
            timeout,
        )
        return _response(definition.operation_id, response)


class _EventStream(Iterator[OperationEvent]):
    def __init__(self, core: _Core, operation_id: str, request: OperationRequest, options: CallOptions | None) -> None:
        self._core = core
        self._operation_id = operation_id
        self._request = request
        self._options = options
        self._closed = False
        if request.page_cursor is not None:
            raise ValidationError("SSE resume uses CallOptions.resume_from, not a pagination cursor")
        self._last_event_id = options.resume_from if options and options.resume_from else None
        if self._last_event_id is not None and re.fullmatch(r"[\x21-\x7e]{1,256}", self._last_event_id) is None:
            raise ValidationError("resume_from must be a bounded visible-ASCII event ID")
        self._iterator = self._events()
        self._current: StreamResponse | None = None
        self._seen_event_ids: set[str] = {self._last_event_id} if self._last_event_id is not None else set()

    @property
    def last_event_id(self) -> str | None:
        return self._last_event_id

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> OperationEvent:
        return next(self._iterator)

    def close(self) -> None:
        self._closed = True
        if self._current is not None:
            self._current.close()
            self._current = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _events(self) -> Iterator[OperationEvent]:
        definition = OPERATIONS[self._operation_id]
        timeout = _timeout(
            self._options.timeout if self._options and self._options.timeout is not None else self._core.timeout
        )
        deadline = time.monotonic() + timeout
        parameters = _parameters(self._request.path_parameters)
        path = _path(definition.http_path, parameters)
        attempts = (
            self._options.max_attempts
            if self._options and self._options.max_attempts is not None
            else self._core.max_attempts
        )
        if isinstance(attempts, bool) or not 1 <= attempts <= 8:
            raise ValidationError("max_attempts must be in 1..8")
        for attempt in range(1, attempts + 1):
            if self._closed:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CigarTimeoutError("CIGAR stream deadline elapsed")
            headers = self._core.headers(self._operation_id, remaining)
            headers["accept"] = "text/event-stream, application/problem+json"
            if self._last_event_id is not None:
                headers["last-event-id"] = self._last_event_id
            current: StreamResponse | None = None
            try:
                current = self._core.transport.stream("GET", self._core.base_url + path, headers, remaining)
                self._current = current
                if not 200 <= current.status < 300:
                    declared = current.headers.get("content-length")
                    if declared is not None and (
                        not declared.isascii() or not declared.isdigit() or int(declared) > _MAX_PROBLEM
                    ):
                        raise TransportError("stream problem Content-Length exceeds its bound")
                    body = _bounded_stream_body(current, _MAX_PROBLEM)
                    raise _problem(HttpResponse(current.status, current.headers, body))
                content_type = current.headers.get("content-type", "").split(";", 1)[0].strip()
                if content_type != "text/event-stream":
                    raise TransportError("stream response must use text/event-stream")
                yield from self._parse(iter(current))
            except (CigarApiError, TransportError, CigarTimeoutError) as error:
                if attempt == attempts or not is_retryable(error):
                    raise
            finally:
                if current is not None:
                    current.close()
                self._current = None
            if attempt < attempts and not self._closed:
                delay = min(0.1 * (2 ** (attempt - 1)), 1.0)
                remaining = deadline - time.monotonic()
                if remaining <= delay:
                    if remaining > 0:
                        time.sleep(remaining)
                    raise CigarTimeoutError("CIGAR stream deadline elapsed")
                time.sleep(delay)

    def _parse(self, lines: Iterator[bytes]) -> Iterator[OperationEvent]:
        event_type = "message"
        event_id: str | None = None
        data: list[str] = []
        retained = 0
        for raw in lines:
            if self._closed:
                return
            retained += len(raw)
            if retained > _MAX_EVENT * 2:
                raise TransportError("event frame exceeds its bound")
            try:
                line = raw.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as error:
                raise TransportError("event stream is not UTF-8") from error
            if line == "":
                if data:
                    event = self._event(event_type, event_id, "\n".join(data))
                    if event is not None:
                        yield event
                event_type, event_id, data, retained = "message", None, [], 0
                continue
            if line.startswith(":"):
                continue
            field, separator, value = line.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if field == "event":
                event_type = value
            elif field == "id":
                event_id = value
            elif field == "data":
                data.append(value)

    def _event(self, event_type: str, event_id: str | None, data: str) -> OperationEvent | None:
        try:
            value = _strict_json(data)
        except (json.JSONDecodeError, ValueError) as error:
            raise TransportError("event data is not valid JSON") from error
        if event_type == "problem":
            if not isinstance(value, dict) or not isinstance(value.get("http_status"), int):
                raise TransportError("problem event lacks its HTTP status")
            raise _decode_problem(value["http_status"], data.encode())
        if not isinstance(value, dict) or value.get("operation_id") != self._operation_id:
            raise TransportError("event operation identity mismatch")
        if set(value) != {"operation_id", "event_id", "payload_cbor"}:
            raise TransportError("event contains unknown or missing fields")
        if (
            not isinstance(value.get("event_id"), str)
            or re.fullmatch(r"[\x21-\x7e]{1,256}", value["event_id"]) is None
            or value["event_id"] != event_id
        ):
            raise TransportError("event resume identity mismatch")
        if event_id in self._seen_event_ids:
            return None
        if len(self._seen_event_ids) >= 100_000:
            raise TransportError("event identity set exceeds its bound")
        self._seen_event_ids.add(event_id)
        self._last_event_id = event_id
        return OperationEvent(
            operation_id=self._operation_id,
            event_id=event_id,
            payload_cbor=_decode_base64url(value.get("payload_cbor"), _MAX_EVENT),
        )


class _AsyncEventStream(AsyncIterator[OperationEvent]):
    def __init__(self, stream: _EventStream) -> None:
        self._stream = stream

    @property
    def last_event_id(self) -> str | None:
        return self._stream.last_event_id

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> OperationEvent:
        present, event = await asyncio.to_thread(_next_event, self._stream)
        if not present or event is None:
            raise StopAsyncIteration
        return event

    async def aclose(self) -> None:
        await asyncio.to_thread(self._stream.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.aclose()


def _next_event(stream: _EventStream) -> tuple[bool, OperationEvent | None]:
    try:
        return True, next(stream)
    except StopIteration:
        return False, None


class _TypedEventStream[T](Iterator[TypedOperationEvent[T]]):
    def __init__(self, stream: _EventStream, model: type[T]) -> None:
        self._stream = stream
        self._model = model

    @property
    def last_event_id(self) -> str | None:
        return self._stream.last_event_id

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> TypedOperationEvent[T]:
        event = next(self._stream)
        payload = construct_payload(self._model, decode_operation_payload(event.payload_cbor))
        return TypedOperationEvent(
            operation_id=event.operation_id,
            event_id=event.event_id,
            payload=payload,
            payload_cbor=event.payload_cbor,
        )

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class _TypedAsyncEventStream[T](AsyncIterator[TypedOperationEvent[T]]):
    def __init__(self, stream: _TypedEventStream[T]) -> None:
        self._stream = stream

    @property
    def last_event_id(self) -> str | None:
        return self._stream.last_event_id

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> TypedOperationEvent[T]:
        present, event = await asyncio.to_thread(_next_typed_event, self._stream)
        if not present or event is None:
            raise StopAsyncIteration
        return event

    async def aclose(self) -> None:
        await asyncio.to_thread(self._stream.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.aclose()


def _next_typed_event[T](stream: _TypedEventStream[T]) -> tuple[bool, TypedOperationEvent[T] | None]:
    try:
        return True, next(stream)
    except StopIteration:
        return False, None


def _typed_request(operation_id: str, request: TypedOperationRequest[object]) -> OperationRequest:
    definition = OPERATIONS[operation_id]
    if definition.stream and request.page_cursor is not None:
        raise ValidationError("SSE resume uses CallOptions.resume_from, not a pagination cursor")
    plain = payload_value(request.payload)
    if not isinstance(plain, dict):
        raise ValidationError(f"{definition.request_type} payload must be an object")
    parameters: list[PathParameter] = []
    for name in definition.path_fields:
        value = plain.get(name)
        if not isinstance(value, str):
            raise ValidationError(f"{definition.request_type}.{name} must be a path string")
        parameters.append(PathParameter(name, value))
    return OperationRequest(
        payload_cbor=b"" if definition.http_method == "GET" else encode_operation_payload(request.payload),
        path_parameters=tuple(parameters),
        idempotency_key=request.idempotency_key,
        expected_revision=request.expected_revision,
        dry_run=request.dry_run,
        page_cursor=request.page_cursor,
        page_size=request.page_size,
    )


class CigarClient(GeneratedOperations):
    """Blocking facade. It owns no background thread and is safe as a context manager."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: BearerTokenProvider | None = None,
        timeout: float = 30.0,
        max_attempts: int = 3,
        transport: HttpTransport | None = None,
        trust_custom_transport: bool = False,
        allow_insecure_loopback: bool = False,
    ) -> None:
        self._core = _Core(
            base_url,
            bearer_token=bearer_token,
            timeout=timeout,
            max_attempts=max_attempts,
            transport=transport,
            trust_custom_transport=trust_custom_transport,
            allow_insecure_loopback=allow_insecure_loopback,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def _call_typed_sync(
        self,
        operation_id: str,
        request: TypedOperationRequest[Any],
        response_type: type[Any],
        options: CallOptions | None,
    ) -> TypedOperationResponse[Any]:
        raw = self._core.call(operation_id, _typed_request(operation_id, request), options)
        payload = construct_payload(response_type, decode_operation_payload(raw.payload_cbor))
        return TypedOperationResponse(
            operation_id=raw.operation_id,
            payload=payload,
            payload_cbor=raw.payload_cbor,
            semantic_etag=raw.semantic_etag,
            next_page_cursor=raw.next_page_cursor,
        )

    def _stream_typed_sync(
        self,
        operation_id: str,
        request: TypedOperationRequest[Any],
        event_type: type[Any],
        options: CallOptions | None,
    ) -> _TypedEventStream[Any]:
        raw = _EventStream(self._core, operation_id, _typed_request(operation_id, request), options)
        return _TypedEventStream(raw, event_type)

    def paginate(
        self, operation_id: str, request: OperationRequest, *, options: CallOptions | None = None
    ) -> Iterator[OperationResponse]:
        cursor = request.page_cursor
        seen: set[str] = set()
        while True:
            current = OperationRequest(
                payload_cbor=request.payload_cbor,
                path_parameters=request.path_parameters,
                idempotency_key=request.idempotency_key,
                expected_revision=request.expected_revision,
                dry_run=request.dry_run,
                page_cursor=cursor,
                page_size=request.page_size,
            )
            response = self._core.call(operation_id, current, options)
            yield response
            cursor = response.next_page_cursor
            if cursor is None:
                return
            if cursor in seen:
                raise TransportError("pagination cursor cycle detected")
            seen.add(cursor)

    def negotiate(
        self, *, options: CallOptions | None = None
    ) -> tuple[TypedOperationResponse[Any], TypedOperationResponse[Any]]:
        from cigar_sdk.generated.models import EmptyRequest

        empty = TypedOperationRequest(EmptyRequest())
        return self.get_version(empty, options=options), self.get_capabilities(empty, options=options)


class AsyncCigarClient(AsyncGeneratedOperations):
    """Async facade with cancellation and bounded synchronous transport offload."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: BearerTokenProvider | None = None,
        timeout: float = 30.0,
        max_attempts: int = 3,
        transport: HttpTransport | None = None,
        trust_custom_transport: bool = False,
        allow_insecure_loopback: bool = False,
    ) -> None:
        self._core = _Core(
            base_url,
            bearer_token=bearer_token,
            timeout=timeout,
            max_attempts=max_attempts,
            transport=transport,
            trust_custom_transport=trust_custom_transport,
            allow_insecure_loopback=allow_insecure_loopback,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    async def _call_typed(
        self,
        operation_id: str,
        request: TypedOperationRequest[Any],
        response_type: type[Any],
        options: CallOptions | None,
    ) -> TypedOperationResponse[Any]:
        raw_request = _typed_request(operation_id, request)
        raw = await asyncio.to_thread(self._core.call, operation_id, raw_request, options)
        payload = construct_payload(response_type, decode_operation_payload(raw.payload_cbor))
        return TypedOperationResponse(
            operation_id=raw.operation_id,
            payload=payload,
            payload_cbor=raw.payload_cbor,
            semantic_etag=raw.semantic_etag,
            next_page_cursor=raw.next_page_cursor,
        )

    def _stream_typed(
        self,
        operation_id: str,
        request: TypedOperationRequest[Any],
        event_type: type[Any],
        options: CallOptions | None,
    ) -> _TypedAsyncEventStream[Any]:
        raw = _EventStream(self._core, operation_id, _typed_request(operation_id, request), options)
        return _TypedAsyncEventStream(_TypedEventStream(raw, event_type))

    async def paginate(
        self, operation_id: str, request: OperationRequest, *, options: CallOptions | None = None
    ) -> AsyncIterator[OperationResponse]:
        cursor = request.page_cursor
        seen: set[str] = set()
        while True:
            current = OperationRequest(
                payload_cbor=request.payload_cbor,
                path_parameters=request.path_parameters,
                idempotency_key=request.idempotency_key,
                expected_revision=request.expected_revision,
                dry_run=request.dry_run,
                page_cursor=cursor,
                page_size=request.page_size,
            )
            response = await asyncio.to_thread(self._core.call, operation_id, current, options)
            yield response
            cursor = response.next_page_cursor
            if cursor is None:
                return
            if cursor in seen:
                raise TransportError("pagination cursor cycle detected")
            seen.add(cursor)

    async def negotiate(
        self, *, options: CallOptions | None = None
    ) -> tuple[TypedOperationResponse[Any], TypedOperationResponse[Any]]:
        from cigar_sdk.generated.models import EmptyRequest

        empty = TypedOperationRequest(EmptyRequest())
        return await self.get_version(empty, options=options), await self.get_capabilities(empty, options=options)
