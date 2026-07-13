@echo off
if "%~1"=="context" if "%~2"=="compile" (
  echo {"ok":true,"result":{"bundle_id":"1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","snapshot_id":"snapshot-fixture"}}
  exit /b 0
)
if "%~1"=="focus" if "%~2"=="checkpoint" (
  echo {"ok":true,"result":{"checkpoint_id":"checkpoint-fixture"}}
  exit /b 0
)
if "%~1"=="handoff" if "%~2"=="create" (
  echo {"ok":true,"result":{"capsule":{"schema_version":"cigar.handoff.v1","handoff_id":"handoff-fixture","recipient":{"type":"role","value":"fixture-recipient"},"task":"Execute the bounded Claude subagent assignment for Explore:agent-fixture-1.","project_ids":["project-fixture"],"delegated_capabilities":["read_context"],"bundle_id":"1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","audience":"fixture-runtime","reusable":false,"signature":[1,2,3]},"preview":{"accepted_projects":["project-fixture"],"accepted_capabilities":["read_context"]}}}
  exit /b 0
)
if "%~1"=="handoff" if "%~2"=="accept" (
  echo {"ok":true,"result":{"schema_version":"cigar.handoff-acceptance.v1","acceptance_id":"acceptance-fixture","handoff_id":"handoff-fixture","recipient_id":"recipient-fixture","accepted_capabilities":["read_context"],"rejected_capabilities":[],"bundle_id":"1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
  exit /b 0
)
if "%~1"=="effect" if "%~2"=="inspect" (
  echo {"ok":true,"result":{"state":"authorized"}}
  exit /b 0
)
echo {"ok":true,"result":{}}
