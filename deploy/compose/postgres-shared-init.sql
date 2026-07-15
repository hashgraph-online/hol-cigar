-- Development-only identities. Production credentials come from a managed secret provider.
CREATE ROLE cigar_runtime LOGIN PASSWORD 'cigar-runtime-development-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

CREATE ROLE cigar_backup LOGIN PASSWORD 'cigar-backup-development-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;

CREATE ROLE cigar_gc LOGIN PASSWORD 'cigar-gc-development-only'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;

GRANT CONNECT ON DATABASE cigar TO cigar_runtime;
GRANT USAGE ON SCHEMA public TO cigar_runtime;
GRANT CONNECT ON DATABASE cigar TO cigar_backup;
GRANT USAGE ON SCHEMA public TO cigar_backup;
GRANT CONNECT ON DATABASE cigar TO cigar_gc;
GRANT USAGE ON SCHEMA public TO cigar_gc;
REVOKE ALL ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO cigar_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE cigar_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cigar_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE cigar_migrator IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO cigar_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE cigar_migrator IN SCHEMA public
  GRANT SELECT ON TABLES TO cigar_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE cigar_migrator IN SCHEMA public
  GRANT SELECT ON TABLES TO cigar_gc;
ALTER DEFAULT PRIVILEGES FOR ROLE cigar_migrator IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- After migrations create cigar_gc_lock_repository_revision(), apply the checked-in
-- postgres-shared-post-migration.sql policy before opening any runtime/backup/GC store.
