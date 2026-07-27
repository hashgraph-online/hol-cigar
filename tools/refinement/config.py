"""Strict, closed refinement TOML configuration without ambient interpolation."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any

from .canonical import CanonicalError, safe_relative_path, secure_read

CONFIG_VERSION = "cigar.refinement-config.v1"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SECRET_HANDLE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
INTERPOLATION = re.compile(r"\$\{|\$\(|%[A-Za-z_][A-Za-z0-9_]*%")

SCHEMA: dict[str, Any] = {
    "schema_version": str,
    "profile_id": str,
    "mode": str,
    "evidence": {"class": str},
    "limits": {
        "max_iterations": int,
        "max_wall_seconds": int,
        "max_cost_usd": float,
        "max_input_tokens": int,
        "max_output_tokens": int,
        "max_files_changed": int,
        "max_lines_changed": int,
    },
    "proposal": {
        "adapter": str,
        "model": str,
        "credential_handle": (str, type(None)),
        "maximum_turns": int,
        "maximum_repairs": int,
    },
    "consumer": {
        "matrix": str,
        "primary_profile": str,
    },
    "statistics": {
        "bootstrap_repetitions": int,
        "confidence_percent": int,
        "assignment_seeds": int,
        "holm_correction": bool,
    },
    "paths": {
        "development_manifest": str,
        "proposal_profiles": str,
        "intervention_families": str,
    },
}


class ConfigError(ValueError):
    """Refinement configuration is malformed, open, or unsafe."""


def _validate_shape(value: Any, shape: Any, path: str) -> None:
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            raise ConfigError(f"{path} must be a table")
        missing = sorted(set(shape) - set(value))
        unknown = sorted(set(value) - set(shape))
        if missing or unknown:
            raise ConfigError(
                f"{path} fields differ: missing={missing}, unknown={unknown}"
            )
        for key, child in shape.items():
            _validate_shape(value[key], child, f"{path}.{key}")
        return
    expected = shape if isinstance(shape, tuple) else (shape,)
    if int in expected and isinstance(value, bool):
        raise ConfigError(f"{path} must not be boolean")
    if float in expected and isinstance(value, int) and not isinstance(value, bool):
        return
    if not isinstance(value, expected):
        names = ", ".join(item.__name__ for item in expected)
        raise ConfigError(f"{path} must be {names}")


def load(path: Path) -> dict[str, Any]:
    try:
        payload = secure_read(path.absolute(), maximum_bytes=1024 * 1024)
        value = tomllib.loads(payload.decode("utf-8", errors="strict"))
    except (
        CanonicalError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        OSError,
    ) as error:
        raise ConfigError("configuration is not strict bounded TOML") from error
    _validate_shape(value, SCHEMA, "$")
    if value["schema_version"] != CONFIG_VERSION:
        raise ConfigError("configuration schema version is unsupported")
    for key in ("profile_id",):
        if IDENTIFIER.fullmatch(value[key]) is None:
            raise ConfigError(f"{key} is not a bounded identifier")
    if value["mode"] not in {"suggest", "patch", "pr"}:
        raise ConfigError("mode is unsupported")
    if value["evidence"]["class"] not in {
        "diagnostic",
        "development",
        "shadow",
        "promotion",
        "release",
    }:
        raise ConfigError("evidence class is unsupported")
    credential = value["proposal"]["credential_handle"]
    if credential is not None and SECRET_HANDLE.fullmatch(credential) is None:
        raise ConfigError("credential_handle is not a named environment handle")
    for key, item in value.items():
        stack = [(key, item)]
        while stack:
            location, current = stack.pop()
            if isinstance(current, dict):
                stack.extend(
                    (f"{location}.{name}", child) for name, child in current.items()
                )
            elif isinstance(current, str) and INTERPOLATION.search(current):
                raise ConfigError(
                    f"environment interpolation is forbidden at {location}"
                )
    for path_key, configured in value["paths"].items():
        try:
            safe_relative_path(configured)
        except CanonicalError as error:
            raise ConfigError(f"paths.{path_key} is unsafe") from error
    limits = value["limits"]
    integer_limits = (
        "max_iterations",
        "max_wall_seconds",
        "max_input_tokens",
        "max_output_tokens",
        "max_files_changed",
        "max_lines_changed",
    )
    if any(limits[name] < 1 for name in integer_limits):
        raise ConfigError("all integer limits must be positive")
    if not 0 <= limits["max_cost_usd"] <= 1_000_000:
        raise ConfigError("max_cost_usd is outside its bound")
    proposal = value["proposal"]
    if not 1 <= proposal["maximum_turns"] <= 1_000:
        raise ConfigError("maximum_turns is outside its bound")
    if not 0 <= proposal["maximum_repairs"] <= 2:
        raise ConfigError("maximum_repairs is outside its bound")
    statistics = value["statistics"]
    if not 100 <= statistics["bootstrap_repetitions"] <= 1_000_000:
        raise ConfigError("bootstrap_repetitions is outside its bound")
    if statistics["confidence_percent"] not in {90, 95, 99}:
        raise ConfigError("confidence_percent is unsupported")
    if not 1 <= statistics["assignment_seeds"] <= 16:
        raise ConfigError("assignment_seeds is outside its bound")
    return value


def resolve_secret_handle(config: dict[str, Any]) -> str | None:
    handle = config["proposal"]["credential_handle"]
    if handle is None:
        return None
    value = os.environ.get(handle)
    if value is None or not value:
        raise ConfigError(f"credential handle is not present: {handle}")
    return value
