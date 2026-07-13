"""Copy-safe public wire and client types."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Protocol, Self


@dataclass(frozen=True, slots=True, order=True)
class PathParameter:
    name: str
    value: str


@dataclass(frozen=True, slots=True)
class OperationRequest:
    payload_cbor: bytes = b""
    path_parameters: tuple[PathParameter, ...] = field(default_factory=tuple)
    idempotency_key: str | None = None
    expected_revision: str | None = None
    dry_run: bool = False
    page_cursor: str | None = None
    page_size: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload_cbor", bytes(self.payload_cbor))
        object.__setattr__(self, "path_parameters", tuple(self.path_parameters))


@dataclass(frozen=True, slots=True)
class TypedOperationRequest[T]:
    payload: T
    idempotency_key: str | None = None
    expected_revision: str | None = None
    dry_run: bool = False
    page_cursor: str | None = None
    page_size: int | None = None


@dataclass(frozen=True, slots=True)
class OperationResponse:
    operation_id: str
    payload_cbor: bytes
    semantic_etag: str | None = None
    next_page_cursor: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload_cbor", bytes(self.payload_cbor))


@dataclass(frozen=True, slots=True)
class TypedOperationResponse[T]:
    operation_id: str
    payload: T
    payload_cbor: bytes
    semantic_etag: str | None = None
    next_page_cursor: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload_cbor", bytes(self.payload_cbor))


@dataclass(frozen=True, slots=True)
class OperationEvent:
    operation_id: str
    event_id: str
    payload_cbor: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload_cbor", bytes(self.payload_cbor))


@dataclass(frozen=True, slots=True)
class TypedOperationEvent[T]:
    operation_id: str
    event_id: str
    payload: T
    payload_cbor: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload_cbor", bytes(self.payload_cbor))


@dataclass(frozen=True, slots=True)
class CallOptions:
    timeout: float | None = None
    max_attempts: int | None = None
    resume_from: str | None = None


class EventStream(Iterator[OperationEvent], Protocol):
    @property
    def last_event_id(self) -> str | None: ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class AsyncEventStream(AsyncIterator[OperationEvent], Protocol):
    @property
    def last_event_id(self) -> str | None: ...

    async def aclose(self) -> None: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class TypedEventStream[T](Iterator[TypedOperationEvent[T]], Protocol):
    @property
    def last_event_id(self) -> str | None: ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class TypedAsyncEventStream[T](AsyncIterator[TypedOperationEvent[T]], Protocol):
    @property
    def last_event_id(self) -> str | None: ...

    async def aclose(self) -> None: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None: ...
