#!/usr/bin/env python3
"""Fail if runtime assets depend on private provider storage or model hooks."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    runtime_files = [
        ROOT / ".claude-plugin/plugin.json",
        ROOT / ".mcp.json",
        ROOT / "compatibility.json",
        ROOT / "hooks/hooks.json",
        ROOT / "README.md",
        *sorted(ROOT.glob("skills/*/SKILL.md")),
        *sorted(ROOT.glob("agents/*.md")),
    ]
    forbidden = [
        ".claude" + "/projects",
        ".claude" + ".json",
        "transcript" + "_path).read",
        "open(transcript" + "_path",
        "cat ${transcript" + "_path}",
    ]
    for path in runtime_files:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                fail(f"private provider dependency in {path}: {pattern}")

    hooks = json.loads((ROOT / "hooks/hooks.json").read_text(encoding="utf-8"))["hooks"]
    if "WorktreeCreate" in hooks:
        fail("WorktreeCreate registration would replace Claude's default Git behavior")
    for event, groups in hooks.items():
        for group in groups:
            for handler in group["hooks"]:
                if handler.get("type") != "command":
                    fail(f"model, agent, HTTP, or MCP hook is forbidden: {event}")
                if handler.get("command") != "cigar-claude-hook":
                    fail(f"hook shell indirection is forbidden: {event}")
                args = handler.get("args", [])
                if "${CLAUDE_PLUGIN_ROOT}" not in args or "${CLAUDE_PLUGIN_DATA}" not in args:
                    fail(f"hook does not use documented plugin paths: {event}")

    mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    if set(mcp) != {"cigar"} or mcp["cigar"].get("command") != "cigar-mcp":
        fail("MCP configuration may execute only the signed installed cigar-mcp package")

    for fixture in sorted((ROOT / "tests/fixtures/events").glob("*.json")):
        value = json.loads(fixture.read_text(encoding="utf-8"))
        if "transcript_path" not in value:
            fail(f"documented opaque transcript field missing: {fixture}")
    print("CIGAR Claude plugin private-path scan passed")


if __name__ == "__main__":
    main()
