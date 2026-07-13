#!/usr/bin/env bash
set -Eeuo pipefail

readonly SECRET=/run/secrets/replication_password
readonly PGPASS=/var/lib/postgresql/.physical-backup.pgpass
readonly SOURCE_HOST="${CIGAR_BACKUP_SOURCE_HOST:-standby}"
readonly BACKUP=/backup

if [[ "$(id -u)" == 0 ]]; then
  [[ -f "$SECRET" ]] || {
    printf 'replication password secret is missing\n' >&2
    exit 64
  }
  secret="$(<"$SECRET")"
  [[ -n "$secret" && ${#secret} -le 1024 && "$secret" != *$'\n'* && "$secret" != *$'\r'* ]] || {
    printf 'replication password must be one non-empty logical line of at most 1024 bytes\n' >&2
    exit 64
  }
  escaped="${secret//\\/\\\\}"
  escaped="${escaped//:/\\:}"
  install -d -o postgres -g postgres -m 0700 /var/lib/postgresql "$BACKUP"
  printf '*:5432:*:cigar_replication:%s\n' "$escaped" >"$PGPASS"
  chown postgres:postgres "$PGPASS" "$BACKUP"
  chmod 0600 "$PGPASS"
  unset secret escaped
  exec gosu postgres "$0" "$@"
fi

[[ "$(id -un)" == postgres ]] || {
  printf 'physical backup must run as postgres\n' >&2
  exit 70
}
if find "$BACKUP" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  printf 'refusing to overwrite a non-empty physical backup volume\n' >&2
  exit 65
fi

pg_basebackup \
  --dbname="host=$SOURCE_HOST port=5432 dbname=postgres user=cigar_replication application_name=cigar-physical-backup passfile=$PGPASS connect_timeout=5" \
  --pgdata="$BACKUP" \
  --format=plain \
  --wal-method=stream \
  --checkpoint=fast \
  --manifest-checksums=SHA256 \
  --no-password \
  --progress
pg_verifybackup "$BACKUP"

[[ -s "$BACKUP/backup_manifest" && -s "$BACKUP/backup_label" ]] || {
  printf 'verified physical backup lacks its manifest or backup label\n' >&2
  exit 66
}
printf 'verified exact physical base backup from the promoted primary\n'
