#!/usr/bin/env bash
set -Eeuo pipefail

readonly BACKUP=/backup
export PGDATA="${PGDATA:-/var/lib/postgresql/18/docker}"

manifest_value() {
  local key="$1"
  awk -v key="\"$key\"" '
    index($0, key) {
      value = $0
      sub("^.*" key "[[:space:]]*:[[:space:]]*\"", "", value)
      sub("\".*$", "", value)
      observed = value
    }
    END { print observed }
  ' "$BACKUP/backup_manifest"
}

if [[ "$(id -u)" == 0 ]]; then
  pg_verifybackup "$BACKUP"
  [[ ! -s "$PGDATA/PG_VERSION" ]] || {
    printf 'refusing to overwrite an initialized physical restore volume\n' >&2
    exit 65
  }
  install -d -o postgres -g postgres -m 0700 "$PGDATA" /var/run/postgresql
  cp -a "$BACKUP/." "$PGDATA/"
  chown -R postgres:postgres "$PGDATA" /var/run/postgresql
  exec gosu postgres "$0" "$@"
fi

[[ "$(id -un)" == postgres ]] || {
  printf 'physical restore must run as postgres\n' >&2
  exit 70
}
target_lsn="$(manifest_value End-LSN)"
source_timeline="$(
  awk '
    /"WAL-Ranges"/ { ranges = 1 }
    ranges && /"Timeline"/ {
      value = $0
      sub("^.*\"Timeline\"[[:space:]]*:[[:space:]]*", "", value)
      sub("[^0-9].*$", "", value)
      observed = value
    }
    END { print observed }
  ' "$BACKUP/backup_manifest"
)"
[[ "$target_lsn" =~ ^[0-9A-F]+/[0-9A-F]+$ && "$source_timeline" =~ ^[0-9]+$ ]] || {
  printf 'physical backup manifest has no valid WAL recovery target\n' >&2
  exit 66
}

rm -f "$PGDATA/standby.signal"
touch "$PGDATA/recovery.signal"
cat >>"$PGDATA/postgresql.auto.conf" <<EOF
primary_conninfo = ''
primary_slot_name = ''
restore_command = '/bin/false'
recovery_target_lsn = '$target_lsn'
recovery_target_inclusive = 'on'
recovery_target_timeline = 'current'
recovery_target_action = 'promote'
EOF
chmod 0600 "$PGDATA/postgresql.auto.conf" "$PGDATA/recovery.signal"

printf 'booting network-isolated physical restore to LSN %s on source timeline %s\n' \
  "$target_lsn" "$source_timeline"
exec "$@"
