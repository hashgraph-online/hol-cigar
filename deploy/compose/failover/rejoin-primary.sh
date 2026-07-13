#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPLICATION_SECRET=/run/secrets/replication_password
readonly REWIND_SECRET=/run/secrets/rewind_password
readonly REPLICATION_PGPASS=/var/lib/postgresql/.replication.pgpass
readonly REWIND_PGPASS=/var/lib/postgresql/.rewind.pgpass
readonly RUNTIME_REPLICATION_PGPASS=/var/lib/postgresql/18/docker/.replication.pgpass
readonly SOURCE_HOST="${CIGAR_REWIND_SOURCE_HOST:-standby}"
readonly SLOT="${CIGAR_REJOIN_SLOT:-cigar_rejoined_slot}"
readonly APPLICATION_NAME="${CIGAR_REJOIN_APPLICATION_NAME:-cigar_standby}"
export PGDATA="${PGDATA:-/target}"

write_pgpass() {
  local source="$1"
  local destination="$2"
  local user="$3"
  local secret escaped
  [[ -f "$source" ]] || {
    printf 'required Docker secret is missing: %s\n' "$source" >&2
    return 1
  }
  secret="$(<"$source")"
  [[ -n "$secret" && ${#secret} -le 1024 && "$secret" != *$'\n'* && "$secret" != *$'\r'* ]] || {
    printf 'Docker secret must be one non-empty logical line of at most 1024 bytes: %s\n' "$source" >&2
    return 1
  }
  escaped="${secret//\\/\\\\}"
  escaped="${escaped//:/\\:}"
  printf '*:5432:*:%s:%s\n' "$user" "$escaped" >"$destination"
  chown postgres:postgres "$destination"
  chmod 0600 "$destination"
  unset secret escaped
}

if [[ "$(id -u)" == 0 ]]; then
  install -d -o postgres -g postgres -m 0700 /var/lib/postgresql
  write_pgpass "$REPLICATION_SECRET" "$REPLICATION_PGPASS" cigar_replication
  write_pgpass "$REWIND_SECRET" "$REWIND_PGPASS" cigar_rewind
  exec gosu postgres "$0" "$@"
fi

[[ "$(id -un)" == postgres ]] || {
  printf 'rejoin operation must run as postgres\n' >&2
  exit 70
}
[[ -s "$PGDATA/PG_VERSION" ]] || {
  printf 'former primary data directory is not initialized: %s\n' "$PGDATA" >&2
  exit 65
}
[[ ! -e "$PGDATA/postmaster.pid" ]] || {
  printf 'refusing to rewind a data directory with postmaster.pid present\n' >&2
  exit 66
}

if [[ "${CIGAR_FORCE_REWIND_DIVERGENCE:-0}" == 1 ]]; then
  cleanup_divergence() {
    pg_ctl --pgdata="$PGDATA" status >/dev/null 2>&1 || return 0
    pg_ctl --pgdata="$PGDATA" --mode=fast --wait stop >/dev/null
  }
  trap cleanup_divergence EXIT
  pg_ctl --pgdata="$PGDATA" \
    --options="-c listen_addresses='' -c port=55434 -c unix_socket_directories=/tmp -c synchronous_standby_names=''" \
    --wait start
  psql -XqAt --set=ON_ERROR_STOP=1 \
    --host=/tmp --port=55434 --username=cigar_owner --dbname=cigar \
    --command="INSERT INTO public.wp18_failover_probe(marker, phase, revision_id, effect_id, claim_id) VALUES ('rewind_divergence_only', 'must_be_removed', 9000000001, 'effect_rewind_divergence_only', 'claim_rewind_divergence_only')" \
    >/dev/null
  cleanup_divergence
  trap - EXIT
  printf 'created an isolated target-only WAL divergence for pg_rewind qualification\n'
fi

pg_rewind \
  --target-pgdata="$PGDATA" \
  --source-server="host=$SOURCE_HOST port=5432 dbname=postgres user=cigar_rewind passfile=$REWIND_PGPASS connect_timeout=5 application_name=cigar-pg-rewind" \
  --progress

install -m 0600 "$REPLICATION_PGPASS" "$PGDATA/.replication.pgpass"
touch "$PGDATA/standby.signal"
cat >>"$PGDATA/postgresql.auto.conf" <<EOF
primary_conninfo = 'host=$SOURCE_HOST port=5432 user=cigar_replication passfile=$RUNTIME_REPLICATION_PGPASS application_name=$APPLICATION_NAME connect_timeout=5'
primary_slot_name = '$SLOT'
EOF

printf 'former primary rewound; recovery target=%s slot=%s application_name=%s\n' \
  "$SOURCE_HOST" "$SLOT" "$APPLICATION_NAME"
