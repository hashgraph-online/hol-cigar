"""Idempotency-key helpers."""

from __future__ import annotations

import re
import uuid

from cigar_sdk.errors import ValidationError

_PREFIX = re.compile(r"^[A-Za-z0-9._~-]{1,32}$")
_KEY = re.compile(r"^[\x21-\x7e]{1,256}$")


def create_idempotency_key(prefix: str = "cigar") -> str:
    if _PREFIX.fullmatch(prefix) is None:
        raise ValidationError("idempotency prefix must be 1..32 unreserved ASCII characters")
    return f"{prefix}-{uuid.uuid4()}"


def validate_idempotency_key(value: str) -> str:
    if _KEY.fullmatch(value) is None:
        raise ValidationError("idempotency key must be 1..256 visible ASCII characters")
    return value
