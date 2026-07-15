#!/usr/bin/env bash
# Runs the WP18 live shared-storage qualification against the checked-in development dependencies.
set -euo pipefail

SOURCE_DIRECTORY="${BASH_SOURCE[0]%/*}"
if [[ "$SOURCE_DIRECTORY" == "${BASH_SOURCE[0]}" ]]; then
  SOURCE_DIRECTORY=.
fi
readonly ROOT="$(cd "$SOURCE_DIRECTORY/.." && pwd -P)"
unset SOURCE_DIRECTORY
readonly COMPOSE_FILE="$ROOT/deploy/compose/shared.yaml"
readonly PROJECT="cigar-wp18-${PPID}-$$"

if [[ "${CIGAR_QUALIFICATION_INTERNAL_PROFILE:-}" != "shared-profile" ]]; then
  exec /usr/bin/python3 -I -B "$ROOT/tools/qualification_evidence.py" run \
    --profile shared-profile --repository "$ROOT"
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

readonly STARTED_AT="$(external date -u '+%Y-%m-%dT%H:%M:%SZ')"

TLS_DIRECTORY=""
KEEP_DEPS="${CIGAR_KEEP_SHARED_TEST_DEPS:-0}"
POSTGRES_DUMP_RESTORE=false
POSTGRES_BASEBACKUP_MANIFEST=false
POSTGRES_PRIVATE_CA_TLS=false
S3_COMPATIBLE_LIVE=false
S3_FRESH_NAMESPACE_RESTORE=false
S3_RUNTIME_IMMUTABLE_DELETE_DENIED=false
DEPLOYMENT_ASSETS=false

cleanup() {
  if [[ "$KEEP_DEPS" != "1" ]]; then
    external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "$TLS_DIRECTORY" ]]; then
    external rm -rf "$TLS_DIRECTORY"
  fi
}

finish() {
  local exit_code="$?"
  local result="fail"
  if [[ "$exit_code" == "0" ]]; then
    result="pass"
  fi
  local finished_at
  finished_at="$(external date -u '+%Y-%m-%dT%H:%M:%SZ')"
  cleanup
  trap - EXIT
  printf '%s\n' \
    '{' \
    '  "schema_version": "cigar.shared-qualification.v1",' \
    '  "packet": "WP18",' \
    "  \"started_at\": \"$STARTED_AT\"," \
    "  \"finished_at\": \"$finished_at\"," \
    "  \"result\": \"$result\"," \
    "  \"exit_code\": $exit_code," \
    '  "live_tests_required": true,' \
    "  \"postgres_dump_restore\": $POSTGRES_DUMP_RESTORE," \
    "  \"postgres_basebackup_manifest_verified\": $POSTGRES_BASEBACKUP_MANIFEST," \
    "  \"postgres_private_ca_tls\": $POSTGRES_PRIVATE_CA_TLS," \
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
    '  ]' \
    '}' >&"$QUALIFICATION_STATE_FD"
  exit "$exit_code"
}

trap finish EXIT
trap 'exit 130' INT TERM

for command in docker cargo kubectl; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required qualification command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

cd "$ROOT"
external docker compose --file "$COMPOSE_FILE" config --quiet
external kubectl kustomize deploy/kubernetes/shared >/dev/null

external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
  up --detach --wait postgres object-storage
external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" \
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
  external docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" ps -q postgres
)"
export CIGAR_TEST_POSTGRES_MIGRATOR_USER='cigar_migrator'

if [[ -z "$CIGAR_TEST_POSTGRES_CONTAINER" ]]; then
  printf 'live PostgreSQL container identity is unavailable\n' >&2
  exit 3
fi

TLS_DIRECTORY="$(external mktemp -d "${TMPDIR:-/tmp}/cigar-wp18-postgres-tls.XXXXXX")"
external chmod 0700 "$TLS_DIRECTORY"
external docker cp \
  "$CIGAR_TEST_POSTGRES_CONTAINER:/var/lib/postgresql/cigar-development-tls/ca.crt" \
  "$TLS_DIRECTORY/postgres-ca.pem" >/dev/null
external chmod 0600 "$TLS_DIRECTORY/postgres-ca.pem"
export CIGAR_TEST_POSTGRES_CA_PATH="$TLS_DIRECTORY/postgres-ca.pem"
export CIGAR_TEST_POSTGRES_SERVER_NAME='127.0.0.1'

external cargo test --locked --package cigar-store --test postgres_shared -- --nocapture
POSTGRES_PRIVATE_CA_TLS=true
POSTGRES_DUMP_RESTORE=true
external cargo test --locked --package cigar-store --test object_s3 -- --nocapture
S3_COMPATIBLE_LIVE=true
S3_FRESH_NAMESPACE_RESTORE=true
S3_RUNTIME_IMMUTABLE_DELETE_DENIED=true
external cargo test --locked --package cigar-daemon --test deployment_assets
DEPLOYMENT_ASSETS=true

readonly PHYSICAL_BACKUP='/tmp/cigar-wp18-physical-backup'
external docker exec "$CIGAR_TEST_POSTGRES_CONTAINER" rm -rf "$PHYSICAL_BACKUP"
external docker exec --user postgres "$CIGAR_TEST_POSTGRES_CONTAINER" \
  pg_basebackup --pgdata="$PHYSICAL_BACKUP" --username=cigar_migrator \
  --checkpoint=fast --wal-method=stream --manifest-checksums=SHA256 --no-password
external docker exec --user postgres "$CIGAR_TEST_POSTGRES_CONTAINER" \
  pg_verifybackup "$PHYSICAL_BACKUP"
POSTGRES_BASEBACKUP_MANIFEST=true
external docker exec "$CIGAR_TEST_POSTGRES_CONTAINER" rm -rf "$PHYSICAL_BACKUP"

printf 'WP18 live shared-profile qualification passed.\n'
