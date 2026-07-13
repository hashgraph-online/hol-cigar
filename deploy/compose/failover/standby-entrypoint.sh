#!/usr/bin/env bash
set -Eeuo pipefail

readonly SECRET=/run/secrets/replication_password
readonly PGPASS=/var/lib/postgresql/.replication.pgpass
export PGDATA="${PGDATA:-/var/lib/postgresql/data}"

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
  install -d -o postgres -g postgres -m 0700 /var/lib/postgresql
  printf '*:5432:*:cigar_replication:%s\n' "$escaped" >"$PGPASS"
  chown postgres:postgres "$PGPASS"
  chmod 0600 "$PGPASS"
  unset secret escaped
  install -d -o postgres -g postgres -m 0700 "$PGDATA"
  exec gosu postgres "$0" "$@"
fi

[[ "$(id -un)" == postgres ]] || {
  printf 'standby entrypoint must run as postgres\n' >&2
  exit 70
}

if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
  if find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    printf 'refusing to initialize a non-empty standby data directory\n' >&2
    exit 65
  fi
  until pg_isready -q -h primary -p 5432 -U cigar_replication -d postgres; do
    sleep 1
  done
  pg_basebackup \
    --dbname="host=primary port=5432 dbname=postgres user=cigar_replication application_name=cigar_standby passfile=$PGPASS connect_timeout=5" \
    --pgdata="$PGDATA" \
    --format=plain \
    --wal-method=stream \
    --checkpoint=fast \
    --create-slot \
    --slot=cigar_standby_slot \
    --write-recovery-conf \
    --progress
fi

[[ -f "$PGDATA/standby.signal" ]] || {
  printf 'standby data directory lacks standby.signal\n' >&2
  exit 66
}

exec "$@"
