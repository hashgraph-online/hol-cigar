#!/bin/sh
set -eu

secret_file=/run/secrets/runtime_password
[ -r "$secret_file" ] || {
  printf 'runtime password secret is missing\n' >&2
  exit 64
}
password="$(cat "$secret_file")"
[ -n "$password" ] || {
  printf 'runtime password secret is empty\n' >&2
  exit 64
}

export PGPASSWORD="$password"
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-5}"
export PGAPPNAME="${PGAPPNAME:-cigar-wp18-failover-client}"
exec psql -X --no-password --host=router --port=5432 --username=cigar_runtime --dbname=cigar "$@"
