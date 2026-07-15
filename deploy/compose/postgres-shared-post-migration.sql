\set ON_ERROR_STOP on

BEGIN;

-- The backup and GC principals deliberately share cross-tenant read access but no
-- authority-bearing function. Each receives exactly one mutually exclusive capability.
REVOKE ALL ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC;
REVOKE ALL ON FUNCTION pg_catalog.pg_control_system() FROM cigar_runtime, cigar_gc;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO cigar_backup;

REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision()
  FROM cigar_runtime, cigar_backup;
GRANT EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() TO cigar_gc;

COMMIT;
