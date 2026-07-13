#!/usr/bin/env bash
set -Eeuo pipefail

read_secret() {
  local path="$1"
  local value
  [[ -f "$path" ]] || {
    printf 'required Docker secret is missing: %s\n' "$path" >&2
    return 1
  }
  value="$(<"$path")"
  [[ -n "$value" && ${#value} -le 1024 && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || {
    printf 'Docker secret must be one non-empty logical line of at most 1024 bytes: %s\n' "$path" >&2
    return 1
  }
  printf '%s' "$value"
}

replication_password="$(read_secret /run/secrets/replication_password)"
rewind_password="$(read_secret /run/secrets/rewind_password)"
router_password="$(read_secret /run/secrets/router_password)"
runtime_password="$(read_secret /run/secrets/runtime_password)"

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=replication_password="$replication_password" \
  --set=rewind_password="$rewind_password" \
  --set=router_password="$router_password" \
  --set=runtime_password="$runtime_password" <<'SQL'
CREATE ROLE cigar_replication LOGIN REPLICATION PASSWORD :'replication_password';
CREATE ROLE cigar_rewind LOGIN PASSWORD :'rewind_password';
CREATE ROLE cigar_router LOGIN PASSWORD :'router_password';
CREATE ROLE cigar_runtime LOGIN PASSWORD :'runtime_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

GRANT CONNECT ON DATABASE cigar TO cigar_router, cigar_runtime;

GRANT EXECUTE ON FUNCTION pg_catalog.pg_ls_dir(text, boolean, boolean) TO cigar_rewind;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_file(text, boolean) TO cigar_rewind;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_binary_file(text) TO cigar_rewind;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_binary_file(text, bigint, bigint, boolean)
  TO cigar_rewind;

CREATE TABLE public.wp18_failover_probe (
  marker text PRIMARY KEY,
  phase text NOT NULL,
  revision_id bigint NOT NULL UNIQUE,
  effect_id text NOT NULL UNIQUE,
  claim_id text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON TABLE public.wp18_failover_probe FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.wp18_failover_probe TO cigar_runtime;
SQL

# pg_rewind connects to the maintenance database, so its least-privilege function grants must
# exist there as well as in the application database.
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
GRANT EXECUTE ON FUNCTION pg_catalog.pg_ls_dir(text, boolean, boolean) TO cigar_rewind;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_file(text, boolean) TO cigar_rewind;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_binary_file(text) TO cigar_rewind;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_binary_file(text, bigint, bigint, boolean)
  TO cigar_rewind;
SQL

unset replication_password rewind_password router_password runtime_password

cat >>"$PGDATA/pg_hba.conf" <<'HBA'

# WP18 failover qualification network. Every TCP identity uses SCRAM; local bootstrap remains
# governed by the official image's local-socket rule.
host replication cigar_replication 0.0.0.0/0 scram-sha-256
host replication cigar_replication ::0/0 scram-sha-256
host postgres cigar_rewind 0.0.0.0/0 scram-sha-256
host postgres cigar_rewind ::0/0 scram-sha-256
host cigar cigar_router 0.0.0.0/0 scram-sha-256
host cigar cigar_router ::0/0 scram-sha-256
host cigar cigar_runtime 0.0.0.0/0 scram-sha-256
host cigar cigar_runtime ::0/0 scram-sha-256
HBA
