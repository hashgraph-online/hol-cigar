#!/bin/sh
set -eu

: "${HAPROXY_SERVER_ADDR:?HAProxy did not provide a server address}"
: "${HAPROXY_SERVER_PORT:?HAProxy did not provide a server port}"

secret_file=/run/secrets/router_password
[ -r "$secret_file" ] || exit 1
password="$(cat "$secret_file")"
[ -n "$password" ] || exit 1

export PGPASSWORD="$password"
export PGCONNECT_TIMEOUT=2
export PGAPPNAME=cigar-haproxy-primary-check

role="$(
  psql -XqAt \
    --host="$HAPROXY_SERVER_ADDR" \
    --port="$HAPROXY_SERVER_PORT" \
    --username=cigar_router \
    --dbname=cigar \
    --no-password \
    --command="SELECT CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END" \
    2>/dev/null
)" || exit 1

[ "$role" = primary ]
