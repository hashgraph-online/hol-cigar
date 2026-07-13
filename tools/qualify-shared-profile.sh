#!/usr/bin/env bash
# Runs the WP18 live shared-storage qualification against the checked-in development dependencies.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly COMPOSE_FILE="$ROOT/deploy/compose/shared.yaml"
readonly PROJECT="cigar-wp18-${PPID}-$$"
readonly RECEIPT_DIRECTORY="$ROOT/artifacts/qualification"
readonly RECEIPT="$RECEIPT_DIRECTORY/wp18-shared-profile.json"
readonly LOG="$RECEIPT_DIRECTORY/wp18-shared-profile.log"
readonly STARTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
KEEP_DEPS="${CIGAR_KEEP_SHARED_TEST_DEPS:-0}"
POSTGRES_DUMP_RESTORE=false
POSTGRES_BASEBACKUP_MANIFEST=false
S3_COMPATIBLE_LIVE=false
S3_FRESH_NAMESPACE_RESTORE=false
S3_RUNTIME_IMMUTABLE_DELETE_DENIED=false
DEPLOYMENT_ASSETS=false

cleanup() {
  if [[ "$KEEP_DEPS" != "1" ]]; then
    docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
}

workspace_source() {
  local commit
  if commit="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null)" \
    && git -C "$ROOT" diff --quiet \
    && git -C "$ROOT" diff --cached --quiet \
    && [[ -z "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]]; then
    printf '%s' "$commit"
    return
  fi
  local digest
  digest="$({
    find "$ROOT/crates/cigar-store" "$ROOT/crates/cigar-daemon" \
      "$ROOT/migrations/postgres" "$ROOT/deploy/compose" \
      "$ROOT/deploy/kubernetes/shared" "$ROOT/deploy/shared" \
      "$ROOT/deploy/observability" "$ROOT/docs/runbooks" \
      -type f -print
    printf '%s\n' "$ROOT/Cargo.lock" "$ROOT/tools/qualify-shared-profile.sh"
  } | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done | shasum -a 256 | awk '{print $1}')"
  printf 'workspace:%s' "$digest"
}

finish() {
  local exit_code="$?"
  local result="fail"
  if [[ "$exit_code" == "0" ]]; then
    result="pass"
  fi
  local finished_at source temporary
  finished_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  source="$(workspace_source)"
  temporary="$RECEIPT.tmp.$$"
  printf '%s\n' \
    '{' \
    '  "schema_version": "cigar.shared-qualification.v1",' \
    '  "packet": "WP18",' \
    "  \"source\": \"$source\"," \
    "  \"started_at\": \"$STARTED_AT\"," \
    "  \"finished_at\": \"$finished_at\"," \
    "  \"result\": \"$result\"," \
    "  \"exit_code\": $exit_code," \
    '  "live_tests_required": true,' \
    "  \"postgres_dump_restore\": $POSTGRES_DUMP_RESTORE," \
    "  \"postgres_basebackup_manifest_verified\": $POSTGRES_BASEBACKUP_MANIFEST," \
    "  \"s3_compatible_live\": $S3_COMPATIBLE_LIVE," \
    "  \"s3_fresh_namespace_restore\": $S3_FRESH_NAMESPACE_RESTORE," \
    "  \"s3_runtime_immutable_delete_denied\": $S3_RUNTIME_IMMUTABLE_DELETE_DENIED," \
    "  \"deployment_assets\": $DEPLOYMENT_ASSETS," \
    '  "commands": [' \
    '    "docker compose config --quiet",' \
    '    "kubectl kustomize deploy/kubernetes/shared",' \
    '    "cargo test --locked --package cigar-store --test postgres_shared -- --nocapture",' \
    '    "cargo test --locked --package cigar-store --test object_s3 -- --nocapture",' \
    '    "cargo test --locked --package cigar-daemon --test deployment_assets",' \
    '    "pg_basebackup --wal-method=stream --manifest-checksums=SHA256",' \
    '    "pg_verifybackup"' \
    '  ],' \
    '  "log": "artifacts/qualification/wp18-shared-profile.log"' \
    '}' >"$temporary"
  mv "$temporary" "$RECEIPT"
  cleanup
  trap - EXIT
  exit "$exit_code"
}

mkdir -p "$RECEIPT_DIRECTORY"
: >"$LOG"
exec > >(tee -a "$LOG") 2>&1
trap finish EXIT
trap 'exit 130' INT TERM

for command in docker cargo kubectl; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required qualification command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

cd "$ROOT"
docker compose --file "$COMPOSE_FILE" config --quiet
kubectl kustomize deploy/kubernetes/shared >/dev/null

docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
  up --detach --wait postgres object-storage
docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
  run --rm object-bootstrap

export CIGAR_TEST_POSTGRES_ADMIN_URL='postgresql://cigar_migrator:cigar-migrator-development-only@127.0.0.1:55432/cigar'
export CIGAR_TEST_S3_ENDPOINT='http://127.0.0.1:59000'
export CIGAR_TEST_S3_ACCESS_KEY='cigar-runtime'
export CIGAR_TEST_S3_SECRET_KEY='cigar-object-development-only'
export CIGAR_TEST_S3_ADMIN_ACCESS_KEY='cigar-minio-admin'
export CIGAR_TEST_S3_ADMIN_SECRET_KEY='cigar-minio-development-only'
export CIGAR_TEST_S3_BUCKET='cigar-shared'
export CIGAR_REQUIRE_LIVE_SHARED_TESTS=1
export CIGAR_TEST_POSTGRES_CONTAINER="$(
  docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" ps -q postgres
)"
export CIGAR_TEST_POSTGRES_MIGRATOR_USER='cigar_migrator'

if [[ -z "$CIGAR_TEST_POSTGRES_CONTAINER" ]]; then
  printf 'live PostgreSQL container identity is unavailable\n' >&2
  exit 3
fi

cargo test --locked --package cigar-store --test postgres_shared -- --nocapture
POSTGRES_DUMP_RESTORE=true
cargo test --locked --package cigar-store --test object_s3 -- --nocapture
S3_COMPATIBLE_LIVE=true
S3_FRESH_NAMESPACE_RESTORE=true
S3_RUNTIME_IMMUTABLE_DELETE_DENIED=true
cargo test --locked --package cigar-daemon --test deployment_assets
DEPLOYMENT_ASSETS=true

readonly PHYSICAL_BACKUP='/tmp/cigar-wp18-physical-backup'
docker exec "$CIGAR_TEST_POSTGRES_CONTAINER" rm -rf "$PHYSICAL_BACKUP"
docker exec --user postgres "$CIGAR_TEST_POSTGRES_CONTAINER" \
  pg_basebackup --pgdata="$PHYSICAL_BACKUP" --username=cigar_migrator \
  --checkpoint=fast --wal-method=stream --manifest-checksums=SHA256 --no-password
docker exec --user postgres "$CIGAR_TEST_POSTGRES_CONTAINER" \
  pg_verifybackup "$PHYSICAL_BACKUP"
POSTGRES_BASEBACKUP_MANIFEST=true
docker exec "$CIGAR_TEST_POSTGRES_CONTAINER" rm -rf "$PHYSICAL_BACKUP"

printf 'WP18 live shared-profile qualification passed.\n'
