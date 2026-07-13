#!/usr/bin/env bash
set -euo pipefail

case "${1:-}:${2:-}" in
  context:compile)
    printf '%s\n' '{"ok":true,"result":{"bundle_id":"1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","snapshot_id":"snapshot-fixture"}}'
    ;;
  focus:checkpoint)
    printf '%s\n' '{"ok":true,"result":{"checkpoint_id":"checkpoint-fixture"}}'
    ;;
  handoff:create)
    printf '%s\n' '{"ok":true,"result":{"capsule":{"schema_version":"cigar.handoff.v1","handoff_id":"handoff-fixture","recipient":{"type":"role","value":"fixture-recipient"},"task":"Execute the bounded Claude subagent assignment for Explore:agent-fixture-1.","project_ids":["project-fixture"],"delegated_capabilities":["read_context"],"bundle_id":"1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","audience":"fixture-runtime","reusable":false,"signature":[1,2,3]},"preview":{"accepted_projects":["project-fixture"],"accepted_capabilities":["read_context"]}}}'
    ;;
  handoff:accept)
    printf '%s\n' '{"ok":true,"result":{"schema_version":"cigar.handoff-acceptance.v1","acceptance_id":"acceptance-fixture","handoff_id":"handoff-fixture","recipient_id":"recipient-fixture","accepted_capabilities":["read_context"],"rejected_capabilities":[],"bundle_id":"1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
    ;;
  effect:inspect)
    printf '%s\n' '{"ok":true,"result":{"state":"authorized"}}'
    ;;
  *)
    printf '%s\n' '{"ok":true,"result":{}}'
    ;;
esac
