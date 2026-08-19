"""Factory for bounded GPT-5.6 Sol proposals through authenticated Codex CLI."""

from __future__ import annotations

from pathlib import Path

from .adapters import CodexCliAdapter

ROOT = Path(__file__).resolve().parents[2]


def codex_cli_adapter(
    *,
    executable: Path,
    model: str = "gpt-5.6-sol",
    maximum_turns: int = 64,
    timeout_seconds: int = 120,
    maximum_response_bytes: int = 1024 * 1024,
    reasoning_effort: str = "medium",
) -> CodexCliAdapter:
    instructions = (ROOT / "refinement/prompts/system-v1.md").read_text(
        encoding="utf-8"
    )
    return CodexCliAdapter(
        executable=executable,
        model=model,
        instructions=instructions,
        maximum_turns=maximum_turns,
        timeout_seconds=timeout_seconds,
        maximum_response_bytes=maximum_response_bytes,
        reasoning_effort=reasoning_effort,
    )
