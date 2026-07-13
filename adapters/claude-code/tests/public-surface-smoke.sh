#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLAUDE=${CIGAR_CLAUDE_BINARY:-claude}
HOOK=${CIGAR_CLAUDE_HOOK_BINARY:-cigar-claude-hook}
MCP=${CIGAR_MCP_BINARY:-cigar-mcp}

version=$($CLAUDE --version)
case "$version" in
  *2.1.207*) ;;
  *)
    echo "Claude Code 2.1.207 is required; received: $version" >&2
    exit 1
    ;;
esac

"$CLAUDE" plugin validate "$ROOT" --strict
"$HOOK" doctor --plugin-root "$ROOT"
"$MCP" schema-noop

if test "${CIGAR_CLAUDE_LIVE_SMOKE:-0}" = 1; then
  response=$($CLAUDE --plugin-dir "$ROOT" -p '/cigar:why current' --output-format json --max-turns 1 --permission-mode dontAsk)
  python3 -c 'import json,sys; value=json.load(sys.stdin); assert isinstance(value,dict)' <<<"$response"
else
  printf '%s\n' 'Recorded public-surface smoke passed; authenticated model smoke was not requested.'
fi
