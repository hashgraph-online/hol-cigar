-- CIGAR PostgreSQL schema v4. Append-only least-privilege GC revision guard.
-- sequence/name: 4 / gc_revision_guard
-- application compatibility: major 1 through major 2
-- classification/lock: online / function catalog update only
-- data backfill: none
-- verification: SECURITY DEFINER, fixed search path, and PUBLIC execute revoked
-- rollback or restore: old binaries ignore the function; restore the pre-migration backup to remove it
CREATE OR REPLACE FUNCTION public.cigar_gc_lock_repository_revision()
RETURNS bigint
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT revision
    FROM public.cigar_repository_revision
    WHERE singleton = true
    FOR UPDATE
$function$;

REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision() FROM PUBLIC;
