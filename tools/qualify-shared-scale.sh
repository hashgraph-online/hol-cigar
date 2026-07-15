#!/usr/bin/env bash
# Live, fail-closed WP18 qualification for 10M production atom projection rows.
set -euo pipefail

SOURCE_DIRECTORY="${BASH_SOURCE[0]%/*}"
if [[ "$SOURCE_DIRECTORY" == "${BASH_SOURCE[0]}" ]]; then
  SOURCE_DIRECTORY=.
fi
readonly ROOT="$(cd "$SOURCE_DIRECTORY/.." && pwd -P)"
unset SOURCE_DIRECTORY
readonly COMPOSE_FILE="$ROOT/deploy/compose/shared.yaml"
readonly PROJECT="cigar-wp18-scale-${PPID}-$$"

if [[ "${CIGAR_QUALIFICATION_INTERNAL_PROFILE:-}" != "shared-scale" ]]; then
  exec /usr/bin/python3 -I -B "$ROOT/tools/qualification_evidence.py" run \
    --profile shared-scale --repository "$ROOT"
fi
readonly QUALIFICATION_STATE_FD="${CIGAR_QUALIFICATION_STATE_FD:-}"
[[ "$QUALIFICATION_STATE_FD" == 198 ]] && { true >&198; } 2>/dev/null || {
  printf 'protected qualification state descriptor is unavailable\n' >&2
  exit 70
}
unset CIGAR_EVIDENCE_DIR CIGAR_QUALIFICATION_INTERNAL_PROFILE \
  CIGAR_QUALIFICATION_STATE_FD

external() {
  /usr/bin/env -u CIGAR_EVIDENCE_DIR \
    -u CIGAR_QUALIFICATION_INTERNAL_PROFILE \
    -u CIGAR_QUALIFICATION_STATE_FD "$@" 198>&-
}

TLS_DIRECTORY=""
WORK_DIRECTORY=""
STATE_WRITTEN=0
KEEP_DEPS="${CIGAR_KEEP_SHARED_SCALE_DEPS:-0}"

cleanup() {
  if [[ "$KEEP_DEPS" != "1" ]]; then
    external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "$TLS_DIRECTORY" ]]; then
    external rm -rf "$TLS_DIRECTORY"
  fi
  if [[ -n "$WORK_DIRECTORY" ]]; then
    external rm -rf "$WORK_DIRECTORY"
  fi
}

finish() {
  local exit_code="$?"
  if [[ "$STATE_WRITTEN" != 1 ]]; then
    printf '%s\n' \
      '{' \
      '  "schema_version": "cigar.shared-scale-qualification.v1",' \
      '  "packet": "WP18",' \
      '  "result": "fail"' \
      '}' >&"$QUALIFICATION_STATE_FD"
  fi
  cleanup
  trap - EXIT
  exit "$exit_code"
}

source_digest() {
  {
    printf '%s\n' \
      "$ROOT/Cargo.lock" \
      "$ROOT/crates/cigar-store/src/postgres.rs" \
      "$ROOT/crates/cigar-store/tests/postgres_scale.rs" \
      "$ROOT/migrations/postgres/0001_shared_metadata.sql" \
      "$ROOT/migrations/postgres/0002_object_outbox.sql" \
      "$ROOT/migrations/postgres/0003_atom_projection.sql" \
      "$ROOT/migrations/postgres/0004_gc_revision_guard.sql" \
      "$ROOT/deploy/compose/shared.yaml" \
      "$ROOT/deploy/compose/postgres-shared-init.sql" \
      "$ROOT/deploy/compose/postgres-tls-entrypoint.sh" \
      "$ROOT/tools/qualify-shared-scale.sh"
  } | external /usr/bin/env LC_ALL=C sort | while IFS= read -r file; do
    external shasum -a 256 "$file"
  done | external shasum -a 256 | external awk '{printf "1220%s", $1}'
}

trap finish EXIT
trap 'exit 130' INT TERM

for command in cargo docker python3 shasum; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required scale qualification command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

cd "$ROOT"
external docker compose --file "$COMPOSE_FILE" config --quiet
external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
  up --detach --wait postgres

export CIGAR_TEST_POSTGRES_ADMIN_URL='postgresql://cigar_migrator:cigar-migrator-development-only@127.0.0.1:55432/cigar'
readonly POSTGRES_CONTAINER="$(
  external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" ps -q postgres
)"
if [[ -z "$POSTGRES_CONTAINER" ]]; then
  printf 'live PostgreSQL container identity is unavailable\n' >&2
  exit 3
fi
TLS_DIRECTORY="$(external mktemp -d "${TMPDIR:-/tmp}/cigar-wp18-scale-postgres-tls.XXXXXX")"
external chmod 0700 "$TLS_DIRECTORY"
external docker cp \
  "$POSTGRES_CONTAINER:/var/lib/postgresql/cigar-development-tls/ca.crt" \
  "$TLS_DIRECTORY/postgres-ca.pem" >/dev/null
external chmod 0600 "$TLS_DIRECTORY/postgres-ca.pem"
export CIGAR_TEST_POSTGRES_CA_PATH="$TLS_DIRECTORY/postgres-ca.pem"
export CIGAR_TEST_POSTGRES_SERVER_NAME='127.0.0.1'
export CIGAR_REQUIRE_LIVE_SCALE_TESTS=1
WORK_DIRECTORY="$(external mktemp -d /private/tmp/cigar-wp18-scale-worker.XXXXXX)"
external chmod 0700 "$WORK_DIRECTORY"
readonly WORKER_RECEIPT="$WORK_DIRECTORY/wp18-shared-scale.worker.json"
export CIGAR_SCALE_RECEIPT_PATH="$WORKER_RECEIPT"
export CIGAR_SCALE_SOURCE_DIGEST
CIGAR_SCALE_SOURCE_DIGEST="$(source_digest)"

printf 'WP18 scale source digest: %s\n' "$CIGAR_SCALE_SOURCE_DIGEST"
printf 'WP18 scale gate requires exactly 10,000,000 physical production projection rows.\n'
external cargo test --release --locked --package cigar-store --test postgres_scale -- --nocapture

WORKER_STATE="$(external python3 - "$WORKER_RECEIPT" "$CIGAR_SCALE_SOURCE_DIGEST" <<'PY'
import json
import sys

path, source = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    receipt = json.load(handle)
assert receipt["schema_version"] == "cigar.shared-scale-qualification.v1"
assert receipt["packet"] == "WP18"
assert receipt["result"] == "pass"
assert receipt["migration_sequence"] == 4
assert receipt["physical_row_count"] == 10_000_000
assert receipt["production_projection"] is True
assert receipt["public_commit_atomic_projection"] is True
assert receipt["public_rebuild_verified"] is True
assert receipt["forced_rls_isolation_verified"] is True
assert receipt["dataset"]["total_rows"] == 10_000_000
assert receipt["dataset"]["source_digest"] == source
assert receipt["dataset"]["canonical_digest"].startswith("1220")
assert len(receipt["dataset"]["canonical_digest"]) == 68
assert [point["target_rows"] for point in receipt["curve"]] == [
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
]
assert all(point["exact_count"] == point["target_rows"] for point in receipt["curve"])
assert receipt["failures"]["unexpected_batch_failures"] == 0
assert receipt["failures"]["unexpected_query_failures"] == 0
print(json.dumps(receipt, allow_nan=False, separators=(",", ":"), sort_keys=True))
PY
)"
printf '%s\n' "$WORKER_STATE" >&"$QUALIFICATION_STATE_FD"
STATE_WRITTEN=1

printf 'WP18 live 10M production atom projection qualification passed.\n'
