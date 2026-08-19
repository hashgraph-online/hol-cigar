"""Factory for loopback OpenAI-compatible proposal servers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters import OpenAICompatibleAdapter, Transport

ROOT = Path(__file__).resolve().parents[2]


def local_adapter(
    *,
    endpoint: str,
    model: str,
    transport: Transport | None = None,
    maximum_turns: int = 64,
) -> OpenAICompatibleAdapter:
    instructions = (ROOT / "refinement/prompts/system-v1.md").read_text(
        encoding="utf-8"
    )
    arguments: dict[str, Any] = {
        "endpoint": endpoint,
        "model": model,
        "instructions": instructions,
        "maximum_turns": maximum_turns,
        "temperature": 0,
    }
    if transport is not None:
        arguments["transport"] = transport
    return OpenAICompatibleAdapter(**arguments)
