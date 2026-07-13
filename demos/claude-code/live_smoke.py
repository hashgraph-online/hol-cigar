#!/usr/bin/env python3
"""Explicit paid Claude Code smoke; emits no model or credential content."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_OUTPUT = 2 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]


def accepted_outcome(value: Any) -> bool:
    if value == {"status": "ok"}:
        return True
    return (
        isinstance(value, dict)
        and value.get("type") == "result"
        and value.get("structured_output") == {"status": "ok"}
    )


def main() -> int:
    model = os.environ.get("CIGAR_CLAUDE_LIVE_MODEL", "")
    if not os.environ.get("ANTHROPIC_API_KEY") or not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,128}", model
    ):
        print("claude-live-smoke: prerequisites are absent", file=sys.stderr)
        return 2
    executable = shutil.which("claude")
    hook = shutil.which("cigar-claude-hook")
    if executable is None or hook is None:
        print("claude-live-smoke: installed tools are unavailable", file=sys.stderr)
        return 2
    schema = json.dumps(
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["status"],
            "properties": {"status": {"const": "ok"}},
        },
        separators=(",", ":"),
    )
    prompt = "Exercise the installed CIGAR plugin hooks, then return the schema object with status ok. Do not use tools."
    with tempfile.TemporaryDirectory(prefix="cigar-claude-live-") as temporary:
        root = Path(temporary)
        bin_directory = root / "bin"
        bin_directory.mkdir()
        sentinel = root / "hook-invoked"
        wrapper = bin_directory / "cigar-claude-hook"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"printf invoked > {shlex.quote(str(sentinel))}\n"
            f'exec {shlex.quote(hook)} "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        environment = dict(os.environ)
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ):
            environment.pop(name, None)
        environment["PATH"] = (
            str(bin_directory) + os.pathsep + environment.get("PATH", "")
        )
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    [
                        executable,
                        "--print",
                        "--bare",
                        "--no-session-persistence",
                        "--output-format",
                        "json",
                        "--json-schema",
                        schema,
                        "--max-budget-usd",
                        "0.10",
                        "--model",
                        model,
                        "--disallowedTools",
                        "Bash,Edit,Write,Read,WebFetch,WebSearch",
                        "--plugin-dir",
                        str(ROOT / "adapters" / "claude-code"),
                        prompt,
                    ],
                    cwd=temporary,
                    env=environment,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=180,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                print(
                    "claude-live-smoke: controlled invocation did not complete",
                    file=sys.stderr,
                )
                return 2
            stdout.seek(0, os.SEEK_END)
            stderr.seek(0, os.SEEK_END)
            if stdout.tell() > MAX_OUTPUT or stderr.tell() > MAX_OUTPUT:
                print(
                    "claude-live-smoke: controlled invocation failed", file=sys.stderr
                )
                return 2
            stdout.seek(0)
            stdout_payload = stdout.read()
        hook_invoked = (
            sentinel.is_file() and sentinel.read_text(encoding="utf-8") == "invoked"
        )
    if completed.returncode != 0 or not hook_invoked:
        print("claude-live-smoke: controlled invocation failed", file=sys.stderr)
        return 2
    try:
        response = json.loads(stdout_payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        print("claude-live-smoke: response was not bounded JSON", file=sys.stderr)
        return 2
    if not accepted_outcome(response):
        print("claude-live-smoke: structured outcome was not accepted", file=sys.stderr)
        return 2
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
