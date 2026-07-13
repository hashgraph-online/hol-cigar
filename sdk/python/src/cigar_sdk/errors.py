"""Stable typed CIGAR failures."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

RetryClass = Literal[
    "never",
    "safe",
    "after_backoff",
    "after_reauthorization",
    "after_reconciliation",
]


class CigarError(Exception):
    """Base SDK failure."""


class ValidationError(CigarError):
    """Caller input failed a frozen bound before I/O."""


class CompatibilityError(CigarError):
    """The server advertises an incompatible API major."""


class CigarTimeoutError(CigarError):
    """The bounded request deadline elapsed."""


class TransportError(CigarError):
    """The HTTP exchange failed or returned an invalid wire record."""


@dataclass(frozen=True, slots=True)
class ProblemDetails:
    schema_version: str
    code: str
    numeric_code: int
    http_status: int
    retry: RetryClass
    message: str
    remediation: str
    correlation_id: str
    details: Mapping[str, object]


def _immutable_json(value: object, depth: int = 0, budget: list[int] | None = None) -> object:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 64 or budget[0] > 100_000:
        raise ValueError("problem details exceed nesting or node bounds")
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _immutable_json(child, depth + 1, budget) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_immutable_json(child, depth + 1, budget) for child in value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise ValueError("problem details contain a non-JSON value")


class CigarApiError(CigarError):
    """Stable server problem with numeric code and retry classification."""

    def __init__(self, status: int, problem: ProblemDetails) -> None:
        super().__init__(f"{problem.message} (CIGAR {problem.code})")
        self.status = status
        self.code = problem.code
        self.numeric_code = problem.numeric_code
        self.retry = problem.retry
        self.remediation = problem.remediation
        self.correlation_id = problem.correlation_id
        immutable = _immutable_json(problem.details)
        if not isinstance(immutable, Mapping):
            raise ValueError("problem details must be an object")
        self.details: Mapping[str, object] = immutable


def is_retryable(error: BaseException) -> bool:
    if isinstance(error, CigarApiError):
        return error.retry in {"safe", "after_backoff"}
    return isinstance(error, (TransportError, CigarTimeoutError))
