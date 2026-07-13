#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import json
print(json.dumps({
    "session_id": "fixture-oversized",
    "transcript_path": "/opaque/provider-transcript.jsonl",
    "cwd": "/workspace/cigar-fixture",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "x" * 70000,
}, separators=(",", ":")))
PY
