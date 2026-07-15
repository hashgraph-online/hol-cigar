#!/usr/bin/env bash
# Qualifies WP18 production repository behavior through physical PostgreSQL failover.
set -Eeuo pipefail

SOURCE_DIRECTORY="${BASH_SOURCE[0]%/*}"
if [[ "$SOURCE_DIRECTORY" == "${BASH_SOURCE[0]}" ]]; then
  SOURCE_DIRECTORY=.
fi
readonly ROOT="$(cd "$SOURCE_DIRECTORY/../.." && pwd -P)"
unset SOURCE_DIRECTORY
readonly COMPOSE_FILE="$ROOT/deploy/compose/failover/compose.yaml"
readonly PROJECT="${CIGAR_FAILOVER_PROJECT:-cigar-wp18-failover-${PPID}-$$}"
readonly ROUTER_PORT="${CIGAR_FAILOVER_ROUTER_PORT:-55433}"
KEEP="${CIGAR_KEEP_FAILOVER_DEPS:-0}"
SYNTAX_ONLY=0
QUALIFICATION_STATE_FD=""
TLS_DIRECTORY=""

PRODUCTION_BEFORE=0
PRODUCTION_OUTAGE=0
PRODUCTION_AFTER=0
ROUTER_FAILED_CLOSED=0
LIVE_COMPLETED=0
REPLICA_LAG_ACK_BLOCKED=0
PHYSICAL_BACKUP_VERIFIED=0
PHYSICAL_RESTORE_READY=0
PHYSICAL_RESTORE_ROOT_MATCH=0
POSTGRES_PRIVATE_CA_TLS=0
CLEANUP_COMPLETE=0
OLD_TIMELINE=""
NEW_TIMELINE=""
PRE_LSN=""
PRE_REPLAY_LSN=""
POST_LSN=""
POST_REPLAY_LSN=""
LAG_COMMIT_LSN=""
LAG_REPLAY_LSN=""
BACKUP_MANIFEST_DIGEST=""
BACKUP_MANIFEST_CHECKSUM=""
PHYSICAL_BACKUP_START_LSN=""
PHYSICAL_BACKUP_END_LSN=""
PHYSICAL_BACKUP_TIMELINE=""
PHYSICAL_SOURCE_FLUSH_LSN=""
PHYSICAL_RECOVERY_TARGET_LSN=""
PHYSICAL_RESTORE_REPLAY_LSN=""
PHYSICAL_RESTORE_TIMELINE=""
PHYSICAL_RESTORE_SOURCE_TIMELINE=""
PHYSICAL_RESTORE_HISTORY_FORK_LSN=""
PHYSICAL_SOURCE_REVISION=""
PHYSICAL_RESTORED_REVISION=""
PHYSICAL_RESTORE_MIGRATION_SEQUENCE=""
PHYSICAL_SOURCE_SEMANTIC_ROOT=""
PHYSICAL_RESTORED_SEMANTIC_ROOT=""
LAG_WRITE_PID=""

usage() {
  printf 'usage: %s [--syntax-only]\n' "${0##*/}"
}

case "${1:-}" in
  '') ;;
  --syntax-only) SYNTAX_ONLY=1 ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 64 ;;
esac
[[ $# -le 1 ]] || { usage >&2; exit 64; }

if [[ "$SYNTAX_ONLY" == 0 ]]; then
  if [[ "${CIGAR_QUALIFICATION_INTERNAL_PROFILE:-}" != "failover" ]]; then
    exec /usr/bin/python3 -I -B "$ROOT/tools/qualification_evidence.py" run \
      --profile failover --repository "$ROOT"
  fi
  QUALIFICATION_STATE_FD="${CIGAR_QUALIFICATION_STATE_FD:-}"
  [[ "$QUALIFICATION_STATE_FD" == 198 ]] \
    && { true >&198; } 2>/dev/null || {
    printf 'protected qualification state descriptor is unavailable\n' >&2
    exit 70
  }
  unset CIGAR_EVIDENCE_DIR CIGAR_QUALIFICATION_INTERNAL_PROFILE \
    CIGAR_QUALIFICATION_STATE_FD
else
  unset CIGAR_EVIDENCE_DIR CIGAR_QUALIFICATION_INTERNAL_PROFILE \
    CIGAR_QUALIFICATION_STATE_FD
fi
readonly QUALIFICATION_STATE_FD

external() {
  /usr/bin/env -u CIGAR_EVIDENCE_DIR \
    -u CIGAR_QUALIFICATION_INTERNAL_PROFILE \
    -u CIGAR_QUALIFICATION_STATE_FD "$@" 198>&-
}

readonly STARTED_AT="$(external date -u '+%Y-%m-%dT%H:%M:%SZ')"

for command in bash docker openssl; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required qualification command is unavailable: %s\n' "$command" >&2
    exit 69
  }
done

new_secret() {
  external openssl rand -hex 32
}

# Caller overrides must retain the generated format so URLs remain unambiguous and output
# redaction is exact. No secret is written to the repository or emitted by this runner.
export CIGAR_FAILOVER_OWNER_PASSWORD="${CIGAR_FAILOVER_OWNER_PASSWORD:-$(new_secret)}"
export CIGAR_FAILOVER_REPLICATION_PASSWORD="${CIGAR_FAILOVER_REPLICATION_PASSWORD:-$(new_secret)}"
export CIGAR_FAILOVER_REWIND_PASSWORD="${CIGAR_FAILOVER_REWIND_PASSWORD:-$(new_secret)}"
export CIGAR_FAILOVER_ROUTER_PASSWORD="${CIGAR_FAILOVER_ROUTER_PASSWORD:-$(new_secret)}"
export CIGAR_FAILOVER_RUNTIME_PASSWORD="${CIGAR_FAILOVER_RUNTIME_PASSWORD:-$(new_secret)}"

for variable in \
  CIGAR_FAILOVER_OWNER_PASSWORD \
  CIGAR_FAILOVER_REPLICATION_PASSWORD \
  CIGAR_FAILOVER_REWIND_PASSWORD \
  CIGAR_FAILOVER_ROUTER_PASSWORD \
  CIGAR_FAILOVER_RUNTIME_PASSWORD; do
  value="${!variable}"
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s must contain exactly 64 lowercase hexadecimal characters\n' "$variable" >&2
    exit 64
  }
done
unset value
[[ "$ROUTER_PORT" =~ ^[0-9]+$ ]] && (( ROUTER_PORT >= 1024 && ROUTER_PORT <= 65535 )) || {
  printf 'CIGAR_FAILOVER_ROUTER_PORT must be an integer from 1024 through 65535\n' >&2
  exit 64
}
[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,99}$ ]] || {
  printf 'CIGAR_FAILOVER_PROJECT must be a bounded lowercase Compose project name\n' >&2
  exit 64
}

sanitize_output() {
  local line matched
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//${CIGAR_FAILOVER_OWNER_PASSWORD}/[REDACTED]}"
    line="${line//${CIGAR_FAILOVER_REPLICATION_PASSWORD}/[REDACTED]}"
    line="${line//${CIGAR_FAILOVER_REWIND_PASSWORD}/[REDACTED]}"
    line="${line//${CIGAR_FAILOVER_ROUTER_PASSWORD}/[REDACTED]}"
    line="${line//${CIGAR_FAILOVER_RUNTIME_PASSWORD}/[REDACTED]}"
    while [[ "$line" =~ postgres(ql)?://[^[:space:]]+ ]]; do
      matched="${BASH_REMATCH[0]}"
      line="${line//$matched/[REDACTED_DATABASE_URL]}"
    done
    printf '%s\n' "$line"
  done
}

if [[ "$SYNTAX_ONLY" == 0 ]]; then
  exec > >(sanitize_output 198>&-) 2>&1
fi

compose() {
  external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" "$@"
}

for script in \
  "$ROOT/deploy/compose/failover/primary-init.sh" \
  "$ROOT/deploy/compose/failover/tls-entrypoint.sh" \
  "$ROOT/deploy/compose/failover/standby-entrypoint.sh" \
  "$ROOT/deploy/compose/failover/rejoin-primary.sh" \
  "$ROOT/deploy/compose/failover/physical-backup.sh" \
  "$ROOT/deploy/compose/failover/physical-restore-entrypoint.sh" \
  "$ROOT/tools/wp18-failover/qualify.sh"; do
  external bash -n "$script"
done
for script in \
  "$ROOT/deploy/compose/failover/check-primary.sh" \
  "$ROOT/deploy/compose/failover/client-psql.sh"; do
  external sh -n "$script"
done
compose --profile operations config --quiet

if [[ "$SYNTAX_ONLY" == 1 ]]; then
  printf 'WP18 failover Compose and shell syntax validation passed.\n'
  exit 0
fi

for command in cargo find python3 shasum sort; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required live qualification command is unavailable: %s\n' "$command" >&2
    exit 69
  }
done

cleanup_topology() {
  local containers volumes networks image_id
  if [[ -n "$LAG_WRITE_PID" ]] && kill -0 "$LAG_WRITE_PID" 2>/dev/null; then
    kill "$LAG_WRITE_PID" 2>/dev/null || true
    wait "$LAG_WRITE_PID" 2>/dev/null || true
    LAG_WRITE_PID=""
  fi
  if [[ "$KEEP" == 1 ]]; then
    printf 'preserving failover project %s because CIGAR_KEEP_FAILOVER_DEPS=1\n' "$PROJECT" >&2
    return 1
  fi
  compose --profile operations down --volumes --remove-orphans --rmi local \
    >/dev/null 2>&1 || return 1
  containers="$(external docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")"
  volumes="$(external docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")"
  networks="$(external docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")"
  image_id="$(external docker image ls -q "${PROJECT}-router:latest")"
  if [[ -n "$containers" || -n "$volumes" || -n "$networks" || -n "$image_id" ]]; then
    printf 'Compose cleanup left resources for project %s\n' "$PROJECT" >&2
    return 1
  fi
  CLEANUP_COMPLETE=1
}

cleanup_tls_directory() {
  if [[ -n "$TLS_DIRECTORY" ]]; then
    external rm -rf "$TLS_DIRECTORY"
    TLS_DIRECTORY=""
  fi
}

diagnostics() {
  local exit_code="$?"
  if [[ "$exit_code" != 0 ]]; then
    printf '\nWP18 failover diagnostics for project %s:\n' "$PROJECT" >&2
    compose ps >&2 || true
    compose --profile operations logs --no-color --tail=120 \
      primary standby router physical-restore >&2 || true
  fi
  return "$exit_code"
}

json_string_or_null() {
  local value="$1"
  if [[ -n "$value" ]]; then
    printf '"%s"' "$value"
  else
    printf 'null'
  fi
}

json_integer_or_null() {
  local value="$1"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s' "$value"
  else
    printf 'null'
  fi
}

finish() {
  local exit_code="$?"
  local finished_at result passed_bool phase_count
  local lsn_pre_json lsn_pre_replay_json lsn_post_json lsn_post_replay_json
  local lsn_lag_commit_json lsn_lag_replay_json
  local manifest_digest_json manifest_checksum_json backup_start_json backup_end_json
  local source_flush_json recovery_target_json restore_replay_json source_root_json restored_root_json
  local restore_history_fork_json
  local backup_timeline_json restore_timeline_json restore_source_timeline_json
  local source_revision_json restored_revision_json
  local restore_migration_json
  local old_timeline_json new_timeline_json
  trap - ERR EXIT INT TERM

  finished_at="$(external date -u '+%Y-%m-%dT%H:%M:%SZ')"
  phase_count=$((PRODUCTION_BEFORE + PRODUCTION_OUTAGE + PRODUCTION_AFTER))
  result=fail
  passed_bool=false
  if [[ "$exit_code" == 0 \
    && "$phase_count" == 3 \
    && "$ROUTER_FAILED_CLOSED" == 1 \
    && "$REPLICA_LAG_ACK_BLOCKED" == 1 \
    && "$PHYSICAL_BACKUP_VERIFIED" == 1 \
    && "$PHYSICAL_RESTORE_READY" == 1 \
    && "$PHYSICAL_RESTORE_ROOT_MATCH" == 1 \
    && "$POSTGRES_PRIVATE_CA_TLS" == 1 \
    && "$LIVE_COMPLETED" == 1 \
    && "$OLD_TIMELINE" =~ ^[0-9]+$ \
    && "$NEW_TIMELINE" =~ ^[0-9]+$ \
    && "$PRE_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PRE_REPLAY_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$POST_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$POST_REPLAY_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$LAG_COMMIT_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$LAG_REPLAY_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$BACKUP_MANIFEST_DIGEST" =~ ^sha256:[0-9a-f]{64}$ \
    && "$BACKUP_MANIFEST_CHECKSUM" =~ ^[0-9a-fA-F]{64}$ \
    && "$PHYSICAL_BACKUP_START_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PHYSICAL_BACKUP_END_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PHYSICAL_SOURCE_FLUSH_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PHYSICAL_RECOVERY_TARGET_LSN" == "$PHYSICAL_BACKUP_END_LSN" \
    && "$PHYSICAL_RESTORE_REPLAY_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PHYSICAL_BACKUP_TIMELINE" =~ ^[0-9]+$ \
    && "$PHYSICAL_RESTORE_TIMELINE" =~ ^[0-9]+$ \
    && "$PHYSICAL_RESTORE_SOURCE_TIMELINE" =~ ^[0-9]+$ \
    && "$PHYSICAL_RESTORE_HISTORY_FORK_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PHYSICAL_SOURCE_REVISION" == 2 \
    && "$PHYSICAL_RESTORED_REVISION" == 2 \
    && "$PHYSICAL_RESTORE_MIGRATION_SEQUENCE" == 4 \
    && "$PHYSICAL_SOURCE_SEMANTIC_ROOT" =~ ^1220[0-9a-f]{64}$ \
    && "$PHYSICAL_RESTORED_SEMANTIC_ROOT" == "$PHYSICAL_SOURCE_SEMANTIC_ROOT" ]]; then
    result=pass
    passed_bool=true
  else
    exit_code=1
  fi

  if ! cleanup_topology; then
    result=fail
    passed_bool=false
    exit_code=1
  fi
  cleanup_tls_directory
  printf 'WP18 failover qualification result=%s production_phases=%s cleanup=%s\n' \
    "$result" "$phase_count" "$CLEANUP_COMPLETE"

  lsn_pre_json="$(json_string_or_null "$PRE_LSN")"
  lsn_pre_replay_json="$(json_string_or_null "$PRE_REPLAY_LSN")"
  lsn_post_json="$(json_string_or_null "$POST_LSN")"
  lsn_post_replay_json="$(json_string_or_null "$POST_REPLAY_LSN")"
  lsn_lag_commit_json="$(json_string_or_null "$LAG_COMMIT_LSN")"
  lsn_lag_replay_json="$(json_string_or_null "$LAG_REPLAY_LSN")"
  old_timeline_json="$(json_integer_or_null "$OLD_TIMELINE")"
  new_timeline_json="$(json_integer_or_null "$NEW_TIMELINE")"
  manifest_digest_json="$(json_string_or_null "$BACKUP_MANIFEST_DIGEST")"
  manifest_checksum_json="$(json_string_or_null "$BACKUP_MANIFEST_CHECKSUM")"
  backup_start_json="$(json_string_or_null "$PHYSICAL_BACKUP_START_LSN")"
  backup_end_json="$(json_string_or_null "$PHYSICAL_BACKUP_END_LSN")"
  source_flush_json="$(json_string_or_null "$PHYSICAL_SOURCE_FLUSH_LSN")"
  recovery_target_json="$(json_string_or_null "$PHYSICAL_RECOVERY_TARGET_LSN")"
  restore_replay_json="$(json_string_or_null "$PHYSICAL_RESTORE_REPLAY_LSN")"
  source_root_json="$(json_string_or_null "$PHYSICAL_SOURCE_SEMANTIC_ROOT")"
  restored_root_json="$(json_string_or_null "$PHYSICAL_RESTORED_SEMANTIC_ROOT")"
  backup_timeline_json="$(json_integer_or_null "$PHYSICAL_BACKUP_TIMELINE")"
  restore_timeline_json="$(json_integer_or_null "$PHYSICAL_RESTORE_TIMELINE")"
  restore_source_timeline_json="$(json_integer_or_null "$PHYSICAL_RESTORE_SOURCE_TIMELINE")"
  restore_history_fork_json="$(json_string_or_null "$PHYSICAL_RESTORE_HISTORY_FORK_LSN")"
  source_revision_json="$(json_integer_or_null "$PHYSICAL_SOURCE_REVISION")"
  restored_revision_json="$(json_integer_or_null "$PHYSICAL_RESTORED_REVISION")"
  restore_migration_json="$(json_integer_or_null "$PHYSICAL_RESTORE_MIGRATION_SEQUENCE")"

  printf '%s\n' \
    '{' \
    '  "schema_version": "cigar.wp18-failover-qualification.v1",' \
    "  \"result\": \"$result\"," \
    "  \"passed\": $passed_bool," \
    "  \"cleanup_complete\": $([[ "$CLEANUP_COMPLETE" == 1 ]] && printf true || printf false)," \
    "  \"started_at\": \"$STARTED_AT\"," \
    "  \"finished_at\": \"$finished_at\"," \
    '  "packet": "WP18",' \
    '  "live_tests_required": true,' \
    "  \"zero_skips\": $passed_bool," \
    '  "skip_count": 0,' \
    "  \"production_phases_completed\": $phase_count," \
    "  \"production_postgres_store\": $passed_bool," \
    "  \"postgres_private_ca_tls\": $([[ "$POSTGRES_PRIVATE_CA_TLS" == 1 ]] && printf true || printf false)," \
    '  "replication": "physical",' \
    '  "synchronous_commit": "remote_apply",' \
    '  "router_policy": "primary-only",' \
    "  \"router_port\": $ROUTER_PORT," \
    "  \"same_write_endpoint_before_after\": $passed_bool," \
    "  \"router_recovery_false_before_after\": $passed_bool," \
    "  \"timeline_before\": $old_timeline_json," \
    "  \"timeline_after\": $new_timeline_json," \
    "  \"pre_commit_lsn\": $lsn_pre_json," \
    "  \"pre_replay_lsn\": $lsn_pre_replay_json," \
    "  \"post_commit_lsn\": $lsn_post_json," \
    "  \"post_replay_lsn\": $lsn_post_replay_json," \
    "  \"replica_lag_commit_lsn\": $lsn_lag_commit_json," \
    "  \"replica_lag_replay_lsn\": $lsn_lag_replay_json," \
    "  \"replica_lag_ack_blocked\": $passed_bool," \
    '  "replica_lag_observation_ms": 3000,' \
    '  "promotion": "explicit",' \
    '  "former_primary_rejoin": "pg_rewind",' \
    "  \"rewind_divergence_removed\": $passed_bool," \
    "  \"acknowledged_write_loss\": $([[ "$passed_bool" == true ]] && printf 0 || printf null)," \
    "  \"effect_revision_before\": $([[ "$passed_bool" == true ]] && printf 1 || printf null)," \
    "  \"effect_revision_after\": $([[ "$passed_bool" == true ]] && printf 2 || printf null)," \
    "  \"effect_idempotent_replay\": $passed_bool," \
    "  \"skip_locked_claims_exactly_once\": $passed_bool," \
    "  \"duplicate_revisions\": $([[ "$passed_bool" == true ]] && printf 0 || printf null)," \
    "  \"duplicate_effects\": $([[ "$passed_bool" == true ]] && printf 0 || printf null)," \
    "  \"duplicate_claims\": $([[ "$passed_bool" == true ]] && printf 0 || printf null)," \
    "  \"postgres_physical_backup_verified\": $([[ "$PHYSICAL_BACKUP_VERIFIED" == 1 ]] && printf true || printf false)," \
    "  \"physical_restore_ready\": $([[ "$PHYSICAL_RESTORE_READY" == 1 ]] && printf true || printf false)," \
    "  \"physical_restore_root_match\": $([[ "$PHYSICAL_RESTORE_ROOT_MATCH" == 1 ]] && printf true || printf false)," \
    "  \"backup_manifest_digest\": $manifest_digest_json," \
    "  \"backup_manifest_checksum\": $manifest_checksum_json," \
    "  \"physical_backup_source_lsn\": $backup_start_json," \
    "  \"physical_backup_end_lsn\": $backup_end_json," \
    "  \"physical_source_flush_lsn\": $source_flush_json," \
    "  \"physical_backup_timeline\": $backup_timeline_json," \
    "  \"physical_recovery_target_lsn\": $recovery_target_json," \
    "  \"physical_restore_replay_lsn\": $restore_replay_json," \
    "  \"physical_restore_timeline\": $restore_timeline_json," \
    "  \"physical_restore_source_timeline\": $restore_source_timeline_json," \
    "  \"physical_restore_history_fork_lsn\": $restore_history_fork_json," \
    "  \"physical_source_revision\": $source_revision_json," \
    "  \"physical_restored_revision\": $restored_revision_json," \
    "  \"physical_restore_migration_sequence\": $restore_migration_json," \
    '  "physical_semantic_root_algorithm": "sha256:cigar-postgres-semantic-v1",' \
    "  \"physical_source_semantic_root\": $source_root_json," \
    "  \"physical_restored_semantic_root\": $restored_root_json," \
    '  "commands": [' \
    '    "docker compose --profile operations config --quiet",' \
    '    "docker compose up --build --detach --wait primary standby router",' \
    '    "CIGAR_REQUIRE_LIVE_FAILOVER_TESTS=1 CIGAR_WP18_FAILOVER_PHASE=before cargo test --locked --package cigar-store --test postgres_failover -- --nocapture",' \
    '    "pg_wal_replay_pause; asynchronous router write; bounded SyncRep observation; pg_wal_replay_resume",' \
    '    "docker compose stop --timeout 30 primary",' \
    '    "CIGAR_REQUIRE_LIVE_FAILOVER_TESTS=1 CIGAR_WP18_FAILOVER_PHASE=outage cargo test --locked --package cigar-store --test postgres_failover -- --nocapture",' \
    '    "pg_ctl promote --wait --timeout=30",' \
    '    "docker compose run --rm --no-deps rejoin-primary",' \
    '    "CIGAR_REQUIRE_LIVE_FAILOVER_TESTS=1 CIGAR_WP18_FAILOVER_PHASE=after cargo test --locked --package cigar-store --test postgres_failover -- --nocapture",' \
    '    "pg_basebackup --wal-method=stream --manifest-checksums=SHA256",' \
    '    "pg_verifybackup /backup",' \
    '    "boot isolated restore with recovery_target_lsn=backup_manifest.WAL-Ranges.End-LSN",' \
    '    "compare restored CIGAR revision and canonical semantic root"' \
    '  ],' \
    '  "database_urls": "redacted"' \
    '}' >&"$QUALIFICATION_STATE_FD"
  exit "$exit_code"
}

sql() {
  local service="$1"
  local database="$2"
  local statement="$3"
  compose exec -T "$service" \
    psql -XqAt --set=ON_ERROR_STOP=1 --username=cigar_owner --dbname="$database" \
    --command="$statement"
}

client_sql() {
  local statement="$1"
  compose run --rm --no-deps client \
    -qAt --set=ON_ERROR_STOP=1 --command="$statement"
}

wait_sql() {
  local service="$1"
  local database="$2"
  local statement="$3"
  local expected="$4"
  local description="$5"
  local deadline=$((SECONDS + 90))
  local actual
  while (( SECONDS < deadline )); do
    actual="$(sql "$service" "$database" "$statement" 2>/dev/null || true)"
    if [[ "$actual" == "$expected" ]]; then
      printf 'ready: %s\n' "$description"
      return 0
    fi
    external sleep 1
  done
  printf 'timed out waiting for %s (last value: %q)\n' "$description" "$actual" >&2
  return 1
}

wait_client_value() {
  local statement="$1"
  local expected="$2"
  local description="$3"
  local deadline=$((SECONDS + 60))
  local actual
  while (( SECONDS < deadline )); do
    actual="$(client_sql "$statement" 2>/dev/null || true)"
    if [[ "$actual" == "$expected" ]]; then
      printf 'ready: %s\n' "$description"
      return 0
    fi
    external sleep 1
  done
  printf 'timed out waiting for %s (last value: %q)\n' "$description" "$actual" >&2
  return 1
}

readonly OWNER_URL="postgresql://cigar_owner:${CIGAR_FAILOVER_OWNER_PASSWORD}@127.0.0.1:${ROUTER_PORT}/cigar"
readonly RUNTIME_URL="postgresql://cigar_runtime:${CIGAR_FAILOVER_RUNTIME_PASSWORD}@127.0.0.1:${ROUTER_PORT}/cigar"

run_repository_phase() {
  local phase="$1"
  printf 'Running required production PostgresStore failover phase: %s\n' "$phase"
  CIGAR_REQUIRE_LIVE_FAILOVER_TESTS=1 \
  CIGAR_WP18_FAILOVER_PHASE="$phase" \
  CIGAR_WP18_FAILOVER_OWNER_URL="$OWNER_URL" \
  CIGAR_WP18_FAILOVER_RUNTIME_URL="$RUNTIME_URL" \
  CIGAR_WP18_FAILOVER_CA_PATH="$TLS_DIRECTORY/postgres-ca.pem" \
  CIGAR_WP18_FAILOVER_SERVER_NAME='127.0.0.1' \
    /usr/bin/env -u CIGAR_EVIDENCE_DIR \
      -u CIGAR_QUALIFICATION_INTERNAL_PROFILE \
      -u CIGAR_QUALIFICATION_STATE_FD \
      cargo test --locked --package cigar-store --test postgres_failover -- --nocapture \
        198>&-
  case "$phase" in
    before) PRODUCTION_BEFORE=1 ;;
    outage) PRODUCTION_OUTAGE=1 ;;
    after) PRODUCTION_AFTER=1 ;;
    *) return 64 ;;
  esac
}

qualify_replica_lag() {
  local marker deadline sync_wait
  marker="lag_${PPID}_$$_$(external date -u '+%s')"
  printf 'Pausing standby WAL replay to prove remote_apply does not acknowledge lagged writes.\n'
  sql standby postgres 'SELECT pg_wal_replay_pause()' >/dev/null
  wait_sql standby postgres \
    "SELECT pg_get_wal_replay_pause_state()" \
    paused "standby WAL replay is paused"

  compose run --rm --no-deps \
    -e PGAPPNAME=cigar-wp18-lag-write \
    client -qAt --set=ON_ERROR_STOP=1 \
    --command="INSERT INTO public.wp18_failover_probe(marker, phase, revision_id, effect_id, claim_id) VALUES ('$marker', 'replica_lag', 1000, 'effect_$marker', 'claim_$marker')" \
    >/dev/null &
  LAG_WRITE_PID="$!"

  deadline=$((SECONDS + 20))
  sync_wait=0
  while (( SECONDS < deadline )); do
    if ! kill -0 "$LAG_WRITE_PID" 2>/dev/null; then
      wait "$LAG_WRITE_PID"
      printf 'lag qualification write acknowledged before entering SyncRep wait\n' >&2
      return 1
    fi
    sync_wait="$(sql primary postgres \
      "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'cigar-wp18-lag-write' AND wait_event = 'SyncRep'" \
      2>/dev/null || true)"
    [[ "$sync_wait" == 1 ]] && break
    external sleep 1
  done
  [[ "$sync_wait" == 1 ]] || {
    printf 'lag qualification write did not enter a synchronous replication wait\n' >&2
    return 1
  }

  LAG_COMMIT_LSN="$(sql primary postgres 'SELECT pg_current_wal_flush_lsn()')"
  external sleep 3
  kill -0 "$LAG_WRITE_PID" 2>/dev/null || {
    wait "$LAG_WRITE_PID" || true
    LAG_WRITE_PID=""
    printf 'remote_apply acknowledged while standby WAL replay remained paused\n' >&2
    return 1
  }
  sync_wait="$(sql primary postgres \
    "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'cigar-wp18-lag-write' AND wait_event = 'SyncRep'")"
  [[ "$sync_wait" == 1 ]] || {
    printf 'lagged write left SyncRep wait before replay resumed\n' >&2
    return 1
  }
  REPLICA_LAG_ACK_BLOCKED=1

  sql standby postgres 'SELECT pg_wal_replay_resume()' >/dev/null
  deadline=$((SECONDS + 30))
  while kill -0 "$LAG_WRITE_PID" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      printf 'lag qualification write did not acknowledge after replay resumed\n' >&2
      return 1
    fi
    external sleep 1
  done
  wait "$LAG_WRITE_PID"
  LAG_WRITE_PID=""
  wait_sql standby postgres \
    "SELECT pg_last_wal_replay_lsn() >= '$LAG_COMMIT_LSN'::pg_lsn" \
    t "lagged write acknowledged only after its commit LSN replayed"
  LAG_REPLAY_LSN="$(sql standby postgres 'SELECT pg_last_wal_replay_lsn()')"
}

semantic_material() {
  local service="$1"
  printf 'CIGAR-POSTGRES-PHYSICAL-SEMANTIC-v1\n'
  printf 'repository\n'
  sql "$service" cigar \
    "SELECT singleton::text || '|' || revision::text FROM cigar_repository_revision ORDER BY singleton"
  printf 'migrations\n'
  sql "$service" cigar \
    "SELECT sequence::text || '|' || name || '|' || checksum || '|' || minimum_application_major::text || '|' || maximum_application_major::text || '|' || online::text FROM schema_migrations ORDER BY sequence"
  printf 'tenant_states\n'
  sql "$service" cigar \
    "WITH latest AS (SELECT DISTINCT ON (tenant_id) tenant_id, revision, checksum, state FROM cigar_tenant_states ORDER BY tenant_id, revision DESC) SELECT tenant_id || '|' || revision::text || '|' || checksum || '|' || encode(state, 'hex') FROM latest ORDER BY tenant_id"
  printf 'objects\n'
  sql "$service" cigar \
    "SELECT tenant_id || '|' || storage_key || '|' || digest || '|' || size_bytes::text FROM cigar_object_commits ORDER BY tenant_id, storage_key"
  printf 'atom_projection\n'
  sql "$service" cigar \
    "SELECT tenant_id || '|' || atom_id || '|' || lineage_id || '|' || version_id || '|' || record_checksum || '|' || published_revision::text || '|' || encode(record, 'hex') FROM cigar_atom_projection ORDER BY tenant_id, version_id"
}

semantic_root() {
  local service="$1"
  local digest
  digest="$(semantic_material "$service" | external shasum -a 256 | external awk '{print $1}')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '1220%s' "$digest"
}

backup_file() {
  local path="$1"
  compose run --rm --no-deps --entrypoint /bin/cat physical-backup "$path"
}

qualify_physical_restore() {
  local source_root_after fields replay_ok schema_shape probe_count manifest_sha
  local history_evidence history_file
  printf 'Creating and verifying a streamed physical base backup of the promoted primary.\n'
  PHYSICAL_SOURCE_REVISION="$(sql standby cigar \
    'SELECT revision FROM cigar_repository_revision WHERE singleton = true')"
  PHYSICAL_SOURCE_SEMANTIC_ROOT="$(semantic_root standby)"
  compose run --rm --no-deps physical-backup

  manifest_sha="$(backup_file /backup/backup_manifest | external shasum -a 256 | external awk '{print $1}')"
  [[ "$manifest_sha" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'physical backup manifest digest is invalid\n' >&2
    return 1
  }
  BACKUP_MANIFEST_DIGEST="sha256:$manifest_sha"
  fields="$(
    backup_file /backup/backup_manifest | external python3 -c '
import json, sys
manifest = json.load(sys.stdin)
ranges = manifest.get("WAL-Ranges")
if not isinstance(ranges, list) or len(ranges) != 1:
    raise SystemExit("physical backup must contain one exact WAL range")
entry = ranges[0]
checksum = manifest.get("Manifest-Checksum")
if not isinstance(checksum, str):
    raise SystemExit("physical backup manifest checksum is missing")
print("{}|{}|{}|{}".format(
    entry.get("Timeline"), entry.get("Start-LSN"), entry.get("End-LSN"), checksum
))
'
  )"
  IFS='|' read -r \
    PHYSICAL_BACKUP_TIMELINE \
    PHYSICAL_BACKUP_START_LSN \
    PHYSICAL_BACKUP_END_LSN \
    BACKUP_MANIFEST_CHECKSUM <<<"$fields"
  [[ "$PHYSICAL_BACKUP_TIMELINE" == "$NEW_TIMELINE" \
    && "$PHYSICAL_BACKUP_START_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$PHYSICAL_BACKUP_END_LSN" =~ ^[0-9A-F]+/[0-9A-F]+$ \
    && "$BACKUP_MANIFEST_CHECKSUM" =~ ^[0-9a-fA-F]{64}$ ]] || {
    printf 'physical backup manifest WAL evidence is invalid\n' >&2
    return 1
  }
  [[ "$(sql standby postgres \
    "SELECT '$PHYSICAL_BACKUP_END_LSN'::pg_lsn >= '$PHYSICAL_BACKUP_START_LSN'::pg_lsn")" == t ]] || {
    printf 'physical backup WAL range is reversed\n' >&2
    return 1
  }
  PHYSICAL_SOURCE_FLUSH_LSN="$(sql standby postgres 'SELECT pg_current_wal_flush_lsn()')"
  [[ "$(sql standby postgres \
    "SELECT '$PHYSICAL_SOURCE_FLUSH_LSN'::pg_lsn >= '$PHYSICAL_BACKUP_END_LSN'::pg_lsn")" == t ]] || {
    printf 'source did not retain the physical backup end LSN\n' >&2
    return 1
  }
  source_root_after="$(semantic_root standby)"
  [[ "$source_root_after" == "$PHYSICAL_SOURCE_SEMANTIC_ROOT" ]] || {
    printf 'CIGAR semantic root changed during physical backup\n' >&2
    return 1
  }
  PHYSICAL_BACKUP_VERIFIED=1
  PHYSICAL_RECOVERY_TARGET_LSN="$PHYSICAL_BACKUP_END_LSN"

  printf 'Booting the exact base backup to its manifest recovery target without networking.\n'
  compose up --detach --wait --no-deps physical-restore
  replay_ok="$(sql physical-restore postgres \
    "SELECT COALESCE(pg_last_wal_replay_lsn(), (SELECT min_recovery_end_lsn FROM pg_control_recovery())) >= '$PHYSICAL_RECOVERY_TARGET_LSN'::pg_lsn")"
  [[ "$replay_ok" == t ]] || {
    printf 'physical restore did not replay through its recovery target\n' >&2
    return 1
  }
  PHYSICAL_RESTORE_REPLAY_LSN="$(sql physical-restore postgres \
    'SELECT COALESCE(pg_last_wal_replay_lsn(), (SELECT min_recovery_end_lsn FROM pg_control_recovery()))')"
  sql physical-restore postgres 'CHECKPOINT' >/dev/null
  PHYSICAL_RESTORE_TIMELINE="$(sql physical-restore postgres \
    'SELECT timeline_id FROM pg_control_checkpoint()')"
  history_file="$(printf '%08X.history' "$PHYSICAL_RESTORE_TIMELINE")"
  history_evidence="$(
    compose exec -T --user postgres physical-restore \
      awk '
        $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9A-F]+\/[0-9A-F]+$/ {
          source_timeline = $1
          fork_lsn = $2
        }
        END {
          if (source_timeline == "" || fork_lsn == "") exit 1
          print source_timeline "|" fork_lsn
        }
      ' "/var/lib/postgresql/18/docker/pg_wal/$history_file"
  )"
  IFS='|' read -r PHYSICAL_RESTORE_SOURCE_TIMELINE PHYSICAL_RESTORE_HISTORY_FORK_LSN \
    <<<"$history_evidence"
  PHYSICAL_RESTORED_REVISION="$(sql physical-restore cigar \
    'SELECT revision FROM cigar_repository_revision WHERE singleton = true')"
  schema_shape="$(sql physical-restore cigar \
    "SELECT count(*)::text || '|' || max(sequence)::text FROM schema_migrations")"
  # Parse the one-delimiter result directly. This is equivalent to the previous suffix expansion,
  # while remaining visible to static analyzers whose Bash parser rejects `##*|` patterns.
  IFS='|' read -r _ PHYSICAL_RESTORE_MIGRATION_SEQUENCE <<<"$schema_shape"
  probe_count="$(sql physical-restore cigar \
    "SELECT count(*) FROM public.wp18_failover_probe WHERE phase IN ('replica_lag', 'before', 'after')")"
  # PostgreSQL may place the promoted timeline fork at the next WAL segment boundary after the
  # requested recovery target. The control-file replay endpoint and timeline-history fork must
  # agree exactly; replay_ok above separately proves that endpoint reached the manifest End-LSN.
  [[ "$schema_shape" == '4|4' && "$probe_count" == 3 \
    && "$PHYSICAL_RESTORED_REVISION" == "$PHYSICAL_SOURCE_REVISION" \
    && "$PHYSICAL_RESTORE_SOURCE_TIMELINE" == "$PHYSICAL_BACKUP_TIMELINE" \
    && "$PHYSICAL_RESTORE_HISTORY_FORK_LSN" == "$PHYSICAL_RESTORE_REPLAY_LSN" \
    && "$PHYSICAL_RESTORE_TIMELINE" -gt "$PHYSICAL_BACKUP_TIMELINE" ]] || {
    printf 'booted physical restore metadata does not match its source\n' >&2
    return 1
  }
  PHYSICAL_RESTORED_SEMANTIC_ROOT="$(semantic_root physical-restore)"
  [[ "$PHYSICAL_RESTORED_SEMANTIC_ROOT" == "$PHYSICAL_SOURCE_SEMANTIC_ROOT" ]] || {
    printf 'booted physical restore CIGAR semantic root does not match its source\n' >&2
    return 1
  }
  PHYSICAL_RESTORE_ROOT_MATCH=1
  PHYSICAL_RESTORE_READY=1
  printf 'Physical restore is writable and CIGAR semantic root/revision exact.\n'
}

umask 077
trap diagnostics ERR
trap finish EXIT
trap 'exit 130' INT TERM

printf 'Starting required WP18 failover qualification project %s.\n' "$PROJECT"
compose up --build --detach --wait primary standby router

readonly PRIMARY_CONTAINER="$(compose ps -q primary)"
[[ -n "$PRIMARY_CONTAINER" ]] || {
  printf 'primary container identity is unavailable\n' >&2
  exit 1
}
TLS_DIRECTORY="$(external mktemp -d "${TMPDIR:-/tmp}/cigar-wp18-failover-tls.XXXXXX")"
external chmod 0700 "$TLS_DIRECTORY"
external docker cp \
  "$PRIMARY_CONTAINER:/var/lib/postgresql/cigar-failover-tls/ca.crt" \
  "$TLS_DIRECTORY/postgres-ca.pem" >/dev/null
external chmod 0600 "$TLS_DIRECTORY/postgres-ca.pem"

# The standby must exist before the synchronous gate is enabled; otherwise first-time database
# initialization would correctly block waiting for a synchronous receiver that cannot yet exist.
wait_sql primary postgres \
  "SELECT count(*) FROM pg_stat_replication WHERE application_name = 'cigar_standby' AND state = 'streaming'" \
  1 "physical standby streaming from the original primary"
sql primary postgres \
  "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (cigar_standby)'" >/dev/null
sql primary postgres "SELECT pg_reload_conf()" >/dev/null
wait_sql primary postgres \
  "SELECT count(*) FROM pg_stat_replication WHERE application_name = 'cigar_standby' AND state = 'streaming' AND sync_state = 'sync'" \
  1 "synchronous standby acknowledged by the original primary"
wait_sql primary postgres \
  "SELECT current_setting('synchronous_commit') = 'remote_apply'" \
  t "original primary uses synchronous_commit=remote_apply"
wait_client_value \
  "SELECT CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END" \
  primary "HAProxy admits only the original primary"

run_repository_phase before
POSTGRES_PRIVATE_CA_TLS=1
qualify_replica_lag

readonly PRE_MARKER="pre_${PPID}_$$_$(external date -u '+%s')"
client_sql "INSERT INTO public.wp18_failover_probe(marker, phase, revision_id, effect_id, claim_id) VALUES ('$PRE_MARKER', 'before', 1001, 'effect_$PRE_MARKER', 'claim_$PRE_MARKER') RETURNING marker" \
  >/dev/null
PRE_LSN="$(sql primary postgres 'SELECT pg_current_wal_flush_lsn()')"
wait_sql standby postgres \
  "SELECT pg_last_wal_replay_lsn() >= '$PRE_LSN'::pg_lsn" \
  t "pre-failover production commit applied on the standby"
PRE_REPLAY_LSN="$(sql standby postgres 'SELECT pg_last_wal_replay_lsn()')"
OLD_TIMELINE="$(sql primary postgres 'SELECT timeline_id FROM pg_control_checkpoint()')"

printf 'Stopping the original primary and proving the router fails closed.\n'
compose stop --timeout 30 primary
for _ in {1..20}; do
  if ! client_sql 'SELECT 1' >/dev/null 2>&1; then
    ROUTER_FAILED_CLOSED=1
    break
  fi
  external sleep 1
done
[[ "$ROUTER_FAILED_CLOSED" == 1 ]] || {
  printf 'HAProxy continued admitting a backend while both nodes lacked primary authority\n' >&2
  exit 1
}
run_repository_phase outage

printf 'Promoting the physical standby explicitly.\n'
compose exec -T --user postgres standby \
  pg_ctl --pgdata=/var/lib/postgresql/18/docker promote --wait --timeout=30
wait_sql standby postgres 'SELECT pg_is_in_recovery()' f "standby promotion completed"
sql standby postgres 'CHECKPOINT' >/dev/null
NEW_TIMELINE="$(sql standby postgres 'SELECT timeline_id FROM pg_control_checkpoint()')"
(( NEW_TIMELINE > OLD_TIMELINE )) || {
  printf 'promotion did not advance the PostgreSQL timeline (%s -> %s)\n' \
    "$OLD_TIMELINE" "$NEW_TIMELINE" >&2
  exit 1
}
wait_client_value \
  "SELECT phase FROM public.wp18_failover_probe WHERE marker = '$PRE_MARKER'" \
  before "router moved to the promoted primary without losing the acknowledged write"
wait_client_value \
  "SELECT CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END" \
  primary "the same router endpoint admits only the promoted primary"

sql standby postgres \
  "SELECT (pg_create_physical_replication_slot('cigar_rejoined_slot')).slot_name" \
  >/dev/null
sql standby postgres 'CHECKPOINT' >/dev/null

printf 'Rewinding and rejoining the former primary as a physical standby.\n'
compose run --rm --no-deps rejoin-primary
compose start primary
wait_sql primary postgres 'SELECT pg_is_in_recovery()' t "former primary is now a standby"
wait_sql primary cigar \
  "SELECT count(*) FROM public.wp18_failover_probe WHERE marker = 'rewind_divergence_only'" \
  0 "pg_rewind removed the isolated former-primary divergence"
wait_sql standby postgres \
  "SELECT count(*) FROM pg_stat_replication WHERE application_name = 'cigar_standby' AND state = 'streaming'" \
  1 "rewound former primary caught up over physical streaming replication"

sql standby postgres \
  "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (cigar_standby)'" >/dev/null
sql standby postgres "SELECT pg_reload_conf()" >/dev/null
wait_sql standby postgres \
  "SELECT count(*) FROM pg_stat_replication WHERE application_name = 'cigar_standby' AND state = 'streaming' AND sync_state = 'sync'" \
  1 "rejoined former primary accepted as synchronous standby"
wait_sql standby postgres \
  "SELECT current_setting('synchronous_commit') = 'remote_apply'" \
  t "promoted primary uses synchronous_commit=remote_apply"

run_repository_phase after

readonly POST_MARKER="post_${PPID}_$$_$(external date -u '+%s')"
client_sql "INSERT INTO public.wp18_failover_probe(marker, phase, revision_id, effect_id, claim_id) VALUES ('$POST_MARKER', 'after', 1002, 'effect_$POST_MARKER', 'claim_$POST_MARKER') RETURNING marker" \
  >/dev/null
POST_LSN="$(sql standby postgres 'SELECT pg_current_wal_flush_lsn()')"
wait_sql primary postgres \
  "SELECT pg_last_wal_replay_lsn() >= '$POST_LSN'::pg_lsn" \
  t "post-promotion production commit applied on the rejoined former primary"
POST_REPLAY_LSN="$(sql primary postgres 'SELECT pg_last_wal_replay_lsn()')"
wait_client_value \
  "SELECT count(*) FROM public.wp18_failover_probe WHERE marker IN ('$PRE_MARKER', '$POST_MARKER')" \
  2 "both qualification writes visible through the primary-only router"
wait_client_value \
  "SELECT count(*) = count(DISTINCT revision_id) AND count(*) = count(DISTINCT effect_id) AND count(*) = count(DISTINCT claim_id) FROM public.wp18_failover_probe WHERE marker IN ('$PRE_MARKER', '$POST_MARKER')" \
  t "revision, effect, and claim identifiers remain unique"
if client_sql \
  "INSERT INTO public.wp18_failover_probe(marker, phase, revision_id, effect_id, claim_id) VALUES ('duplicate_$POST_MARKER', 'duplicate', 1002, 'effect_$POST_MARKER', 'claim_$POST_MARKER')" \
  >/dev/null 2>&1; then
  printf 'promoted primary accepted duplicate revision/effect/claim identifiers\n' >&2
  exit 1
fi
wait_client_value \
  "SELECT count(*) FROM public.wp18_failover_probe WHERE marker IN ('$PRE_MARKER', '$POST_MARKER')" \
  2 "failed duplicate transaction left no partial row"

qualify_physical_restore
LIVE_COMPLETED=1
