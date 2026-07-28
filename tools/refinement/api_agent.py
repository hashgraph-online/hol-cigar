"""Factory for the official hosted OpenAI Responses proposal profile."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters import OpenAIResponsesAdapter, Transport

ROOT = Path(__file__).resolve().parents[2]


def hosted_adapter(
    *,
    transport: Transport | None = None,
    model: str = "gpt-5.6-sol",
    credential_handle: str = "OPENAI_API_KEY",
    maximum_turns: int = 64,
) -> OpenAIResponsesAdapter:
    instructions = (ROOT / "refinement/prompts/system-v1.md").read_text(
        encoding="utf-8"
    )
    arguments: dict[str, Any] = {
        "model": model,
        "instructions": instructions,
        "credential_handle": credential_handle,
        "maximum_turns": maximum_turns,
        "reasoning_effort": "medium",
    }
    if transport is not None:
        arguments["transport"] = transport
    return OpenAIResponsesAdapter(**arguments)
