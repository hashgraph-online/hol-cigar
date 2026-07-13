#!/usr/bin/env bash
# Live, fail-closed WP18 qualification for 10M production atom projection rows.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly COMPOSE_FILE="$ROOT/deploy/compose/shared.yaml"
readonly PROJECT="cigar-wp18-scale-${PPID}-$$"
readonly RECEIPT_DIRECTORY="$ROOT/artifacts/qualification"
readonly RECEIPT="$RECEIPT_DIRECTORY/wp18-shared-scale.json"
readonly LOG="$RECEIPT_DIRECTORY/wp18-shared-scale.log"
KEEP_DEPS="${CIGAR_KEEP_SHARED_SCALE_DEPS:-0}"

cleanup() {
  if [[ "$KEEP_DEPS" != "1" ]]; then
    docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
}

finish() {
  local exit_code="$?"
  if [[ "$exit_code" != "0" ]]; then
    rm -f "$RECEIPT"
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
      "$ROOT/tools/qualify-shared-scale.sh"
  } | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done | shasum -a 256 | awk '{printf "1220%s", $1}'
}

mkdir -p "$RECEIPT_DIRECTORY"
rm -f "$RECEIPT"
: >"$LOG"
exec > >(tee -a "$LOG") 2>&1
trap finish EXIT
trap 'exit 130' INT TERM

for command in cargo docker python3 shasum; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required scale qualification command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

cd "$ROOT"
docker compose --file "$COMPOSE_FILE" config --quiet
docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
  up --detach --wait postgres

export CIGAR_TEST_POSTGRES_ADMIN_URL='postgresql://cigar_migrator:cigar-migrator-development-only@127.0.0.1:55432/cigar'
export CIGAR_REQUIRE_LIVE_SCALE_TESTS=1
export CIGAR_SCALE_RECEIPT_PATH="$RECEIPT"
export CIGAR_SCALE_SOURCE_DIGEST
CIGAR_SCALE_SOURCE_DIGEST="$(source_digest)"

printf 'WP18 scale source digest: %s\n' "$CIGAR_SCALE_SOURCE_DIGEST"
printf 'WP18 scale gate requires exactly 10,000,000 physical production projection rows.\n'
cargo test --release --locked --package cigar-store --test postgres_scale -- --nocapture

python3 - "$RECEIPT" "$CIGAR_SCALE_SOURCE_DIGEST" <<'PY'
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
PY

printf 'WP18 live 10M production atom projection qualification passed.\n'
