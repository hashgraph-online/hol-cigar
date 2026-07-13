#!/usr/bin/env python3
"""Measure warm prompt-hook latency through the installed command-hook binary."""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import time


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: measure_prompt.py HOOK PLUGIN_ROOT FAKE_CIGAR")
    hook, root, fake = sys.argv[1:]
    environment = os.environ.copy()
    environment.update(
        {
            "CIGAR_CLI_BINARY": fake,
            "CIGAR_CLAUDE_PLAN_ID": "plan-fixture",
            "CIGAR_CLAUDE_SPACE_ID": "space-fixture",
            "CIGAR_CLAUDE_FOCUS_ID": "focus-fixture",
        }
    )
    measurements: list[float] = []
    with tempfile.TemporaryDirectory(prefix="cigar-claude-latency-") as data:
        command = [hook, "run", "--plugin-root", root, "--plugin-data", data]
        for index in range(55):
            event = {
                "session_id": f"latency-{index}",
                "transcript_path": "/opaque/provider-transcript.jsonl",
                "cwd": "/workspace/cigar-fixture",
                "hook_event_name": "UserPromptSubmit",
                "prompt": f"fixture prompt {index}",
            }
            started = time.perf_counter()
            completed = subprocess.run(
                command,
                input=json.dumps(event, separators=(",", ":")),
                text=True,
                capture_output=True,
                env=environment,
                timeout=1.0,
                check=False,
            )
            elapsed = (time.perf_counter() - started) * 1000.0
            if completed.returncode != 0:
                raise SystemExit(f"prompt hook failed: {completed.stderr.strip()}")
            json.loads(completed.stdout)
            if index >= 5:
                measurements.append(elapsed)
    p95 = percentile(measurements, 0.95)
    p99 = percentile(measurements, 0.99)
    result = {
        "samples": len(measurements),
        "median_ms": round(statistics.median(measurements), 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
    }
    print(json.dumps(result, sort_keys=True))
    if p95 > 150.0 or p99 > 1000.0:
        raise SystemExit("prompt hook latency exceeds the qualified budget")


if __name__ == "__main__":
    main()
