#!/usr/bin/env python3
"""Validate plugin structure, fixtures, text, and the byte-exact package manifest."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVENTS = {
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "InstructionsLoaded",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "PreCompact",
    "PostCompact",
    "CwdChanged",
    "WorktreeCreate",
    "WorktreeRemove",
    "Stop",
    "StopFailure",
    "Setup",
    "UserPromptExpansion",
    "PermissionRequest",
    "PermissionDenied",
    "Notification",
    "MessageDisplay",
    "TeammateIdle",
    "ConfigChange",
    "FileChanged",
    "Elicitation",
    "ElicitationResult",
}
REGISTERED = {
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "InstructionsLoaded",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "PreCompact",
    "PostCompact",
    "CwdChanged",
    "WorktreeRemove",
    "Stop",
    "StopFailure",
}
HOOK_ARGS = [
    "run",
    "--plugin-root",
    "${CLAUDE_PLUGIN_ROOT}",
    "--plugin-data",
    "${CLAUDE_PLUGIN_DATA}",
]


def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def validate_text() -> None:
    for path in ROOT.rglob("*"):
        require(not path.is_symlink(), f"symlink is forbidden: {path}")
        if not path.is_file():
            continue
        data = path.read_bytes()
        require(b"\x00" not in data, f"NUL byte in {path}")
        require(b"\r" not in data, f"non-LF line ending in {path}")
        data.decode("utf-8")
        require(data.endswith(b"\n"), f"missing final newline: {path}")

    markdown = sorted(ROOT.glob("skills/*/SKILL.md")) + sorted(ROOT.glob("agents/*.md"))
    require(len(markdown) == 8, "expected five skills and three agents")
    for path in markdown:
        text = path.read_text(encoding="utf-8")
        require(text.startswith("---\n"), f"frontmatter missing: {path}")
        end = text.find("\n---\n", 4)
        require(end > 4, f"frontmatter is not closed: {path}")
        frontmatter = text[4:end]
        require(
            re.search(r"(?m)^name: [a-z][a-z0-9-]*$", frontmatter) is not None,
            f"name missing: {path}",
        )
        descriptions = re.findall(r"(?m)^description: (.+)$", frontmatter)
        require(
            len(descriptions) == 1 and len(descriptions[0]) <= 240,
            f"description invalid: {path}",
        )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for heading in [
        "## Qualified host",
        "## What is registered",
        "## Limitations",
        "## Qualification",
    ]:
        require(heading in readme, f"README section missing: {heading}")


def validate_json_files() -> None:
    malformed = ROOT / "tests/fixtures/invalid/malformed.json"
    for path in sorted(ROOT.rglob("*.json")):
        if path == malformed:
            continue
        load_json(path)
    try:
        load_json(malformed)
    except (json.JSONDecodeError, ValueError):
        pass
    else:
        raise SystemExit("malformed fixture unexpectedly parsed")


def validate_plugin() -> None:
    metadata = sorted(path.name for path in (ROOT / ".claude-plugin").iterdir())
    require(metadata == ["plugin.json"], ".claude-plugin must contain only plugin.json")
    plugin = load_json(ROOT / ".claude-plugin/plugin.json")
    require(plugin.get("name") == "cigar", "plugin name mismatch")
    require(plugin.get("version") == "0.1.0", "plugin version mismatch")
    for redundant in ["skills", "agents", "hooks", "mcpServers", "commands"]:
        require(
            redundant not in plugin,
            f"default component path is redundantly declared: {redundant}",
        )

    compatibility = load_json(ROOT / "compatibility.json")
    require(
        compatibility
        == {
            "schema_version": "cigar.claude-code-compatibility.v1",
            "claude_code": {
                "minimum_inclusive": "2.1.207",
                "maximum_exclusive": "2.1.208",
            },
            "platforms": ["macos-aarch64", "macos-arm64"],
            "public_surfaces_only": True,
        },
        "compatibility matrix is not the qualified range",
    )

    mcp = load_json(ROOT / ".mcp.json")
    require(set(mcp) == {"mcpServers"}, "unexpected MCP root field")
    require(set(mcp["mcpServers"]) == {"cigar"}, "unexpected MCP server")
    server = mcp["mcpServers"]["cigar"]
    require(
        server.get("command") == "cigar-mcp",
        "MCP must use the installed long-lived MCP executable",
    )
    require(server.get("args") == ["serve"], "MCP arguments mismatch")
    require(
        server.get("env", {}).get("CIGAR_CLAUDE_PLUGIN_ROOT")
        == "${CLAUDE_PLUGIN_ROOT}",
        "MCP root is not public plugin data",
    )
    require(
        server.get("env", {}).get("CIGAR_CLAUDE_PLUGIN_DATA")
        == "${CLAUDE_PLUGIN_DATA}",
        "MCP data path is not public plugin data",
    )


def validate_hooks_and_fixtures() -> None:
    hooks = load_json(ROOT / "hooks/hooks.json")["hooks"]
    require(
        set(hooks) == REGISTERED,
        "hook registration differs from the safe qualified set",
    )
    require(
        "WorktreeCreate" not in hooks,
        "WorktreeCreate must not replace Claude's Git behavior",
    )
    for event, groups in hooks.items():
        require(
            isinstance(groups, list) and len(groups) == 1,
            f"hook group invalid: {event}",
        )
        group = groups[0]
        require(set(group) == {"hooks"}, f"unsupported group field: {event}")
        require(
            isinstance(group["hooks"], list) and len(group["hooks"]) == 1,
            f"handler count invalid: {event}",
        )
        handler = group["hooks"][0]
        require(
            handler
            == {
                "type": "command",
                "command": "cigar-claude-hook",
                "args": HOOK_ARGS,
                "timeout": 1,
            },
            f"handler is not the bounded exec-form public command: {event}",
        )

    seen: set[str] = set()
    fixtures = sorted((ROOT / "tests/fixtures/events").glob("*.json"))
    require(
        len(fixtures) == len(EVENTS),
        "one fixture per documented parser event is required",
    )
    for path in fixtures:
        event = load_json(path)
        require(
            event.get("transcript_path") == "/opaque/provider-transcript.jsonl",
            f"opaque transcript field missing: {path}",
        )
        name = event.get("hook_event_name")
        require(name in EVENTS, f"unknown event fixture: {name}")
        require(name not in seen, f"duplicate event fixture: {name}")
        seen.add(name)
    require(seen == EVENTS, "event fixture coverage is incomplete")


def validate_scripts() -> None:
    shell = sorted(ROOT.glob("tests/*.sh"))
    require(shell, "shell qualification scripts missing")
    for path in shell:
        if os.name != "nt":
            require(os.access(path, os.X_OK), f"script is not executable: {path}")
        subprocess.run(["bash", "-n", str(path)], check=True)


def validate_manifest() -> None:
    manifest_path = ROOT / "package-manifest.json"
    require(manifest_path.is_file(), "package-manifest.json is missing")
    manifest = load_json(manifest_path)
    require(
        manifest.get("schema_version") == "cigar.claude-code-package.v1",
        "manifest schema mismatch",
    )
    entries = manifest.get("files")
    require(isinstance(entries, list) and entries, "manifest is empty")
    actual = sorted(
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file() and path != manifest_path
    )
    paths = [entry.get("path") for entry in entries]
    require(
        paths == sorted(paths) and len(paths) == len(set(paths)),
        "manifest paths are not strict and unique",
    )
    require(
        paths == actual,
        "manifest does not cover exactly every package file except itself",
    )
    for entry in entries:
        path = ROOT / entry["path"]
        data = path.read_bytes()
        require(
            entry.get("bytes") == len(data), f"manifest byte count mismatch: {path}"
        )
        require(
            entry.get("sha256") == hashlib.sha256(data).hexdigest(),
            f"manifest digest mismatch: {path}",
        )


def main() -> None:
    validate_text()
    validate_json_files()
    validate_plugin()
    validate_hooks_and_fixtures()
    validate_scripts()
    validate_manifest()
    print("CIGAR Claude plugin package validation passed")


if __name__ == "__main__":
    main()
