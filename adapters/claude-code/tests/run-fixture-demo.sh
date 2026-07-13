#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HOOK=${CIGAR_CLAUDE_HOOK_BINARY:-cigar-claude-hook}
DATA=$(mktemp -d "${TMPDIR:-/tmp}/cigar-claude-fixture.XXXXXX")
trap 'rm -rf "$DATA"' EXIT

export CIGAR_CLI_BINARY="$ROOT/tests/fake-cigar.sh"
export CIGAR_CLAUDE_PLAN_ID=plan-fixture
export CIGAR_CLAUDE_SPACE_ID=space-fixture
export CIGAR_CLAUDE_FOCUS_ID=focus-fixture
export CIGAR_CLAUDE_HANDOFF_RECIPIENT_ROLE=fixture-recipient
export CIGAR_CLAUDE_HANDOFF_PROJECT_ID=project-fixture
export CIGAR_CLAUDE_HANDOFF_AUDIENCE=fixture-runtime

run_hook() {
  "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA" < "$1"
}

ORDER=(
  session-start user-prompt-submit instructions-loaded pre-tool-use post-tool-use
  post-tool-use-failure post-tool-batch subagent-start subagent-stop task-created
  task-completed pre-compact post-compact cwd-changed worktree-create worktree-remove
  setup user-prompt-expansion permission-request permission-denied notification
  message-display teammate-idle config-change file-changed elicitation
  elicitation-result stop stop-failure session-end
)

for name in "${ORDER[@]}"; do
  output=$(run_hook "$ROOT/tests/fixtures/events/$name.json")
  python3 -c 'import json,sys; value=json.load(sys.stdin); assert isinstance(value,dict)' <<<"$output"
done

first=$(run_hook "$ROOT/tests/fixtures/events/user-prompt-submit.json")
second=$(run_hook "$ROOT/tests/fixtures/events/user-prompt-submit.json")
test "$first" = "$second"

effect=$(run_hook "$ROOT/tests/fixtures/scenarios/governed-effect.json")
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["hookSpecificOutput"]["hookEventName"] == "PreToolUse"; assert "permissionDecision" not in value["hookSpecificOutput"]' <<<"$effect"

sed 's/fixture-session/fixture-degraded-session/g' "$ROOT/tests/fixtures/events/user-prompt-submit.json" |
  CIGAR_CLI_BINARY=/definitely/not/a/cigar-command \
  "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA" > "$DATA/degraded.json"
python3 -c 'import json,sys; value=json.load(sys.stdin); assert "CIGAR degraded" in value["systemMessage"]' < "$DATA/degraded.json"

sed 's/fixture-effect-session/fixture-denied-session/g' "$ROOT/tests/fixtures/scenarios/governed-effect.json" |
  CIGAR_CLI_BINARY=/definitely/not/a/cigar-command \
  "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA" > "$DATA/denied.json"
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["hookSpecificOutput"]["permissionDecision"] == "deny"' < "$DATA/denied.json"

if "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA" < "$ROOT/tests/fixtures/invalid/malformed.json" >/dev/null 2>&1; then
  echo "malformed hook event was accepted" >&2
  exit 1
fi
if "$ROOT/tests/generate-oversized.sh" | "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA" >/dev/null 2>&1; then
  echo "oversized hook event was accepted" >&2
  exit 1
fi

touch "$DATA/not-a-directory"
if "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA/not-a-directory" < "$ROOT/tests/fixtures/events/stop.json" >/dev/null 2>&1; then
  echo "invalid plugin-data boundary was accepted" >&2
  exit 1
fi

bootstrap=$(sed 's/fixture-session/fixture-bootstrap-budget/g' "$ROOT/tests/fixtures/events/session-start.json" |
  "$HOOK" run --plugin-root "$ROOT" --plugin-data "$DATA")
python3 -c 'import json,sys; value=json.load(sys.stdin); context=value["hookSpecificOutput"]["additionalContext"]; assert len(context.split()) <= 500' <<<"$bootstrap"

python3 "$ROOT/tests/measure_prompt.py" "$HOOK" "$ROOT" "$ROOT/tests/fake-cigar.sh"
printf '%s\n' 'CIGAR Claude recorded fixture demo passed without a model or network call'
