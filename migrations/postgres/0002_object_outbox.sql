-- CIGAR PostgreSQL schema v2. Append-only rolling-compatible expansion.
-- sequence/name: 2 / object_outbox
-- application compatibility: major 1 through major 2
-- classification/lock: online / bounded ACCESS EXCLUSIVE locks on new empty tables only
-- data backfill: none; workers populate rows lazily
-- verification: object commit and worker claim tables exist with RLS enabled/forced
-- rollback or restore: old binaries ignore these tables; restore the pre-migration backup to remove them
CREATE TABLE IF NOT EXISTS cigar_object_commits (
    tenant_id text NOT NULL,
    storage_key text NOT NULL CHECK (length(storage_key) BETWEEN 1 AND 512),
    digest text NOT NULL CHECK (length(digest) = 68),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, storage_key)
);

ALTER TABLE cigar_object_commits ENABLE ROW LEVEL SECURITY;
ALTER TABLE cigar_object_commits FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cigar_object_commits_isolation ON cigar_object_commits;
CREATE POLICY cigar_object_commits_isolation ON cigar_object_commits
    USING (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''));

CREATE TABLE IF NOT EXISTS cigar_worker_claims (
    tenant_id text NOT NULL,
    worker text NOT NULL CHECK (length(worker) BETWEEN 1 AND 128),
    item_key text NOT NULL CHECK (length(item_key) BETWEEN 1 AND 512),
    owner text NOT NULL CHECK (length(owner) BETWEEN 1 AND 128),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    lease_expires_at timestamptz NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, worker, item_key)
);

CREATE INDEX IF NOT EXISTS cigar_worker_claims_expiry
    ON cigar_worker_claims (tenant_id, worker, lease_expires_at, item_key);

ALTER TABLE cigar_worker_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE cigar_worker_claims FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cigar_worker_claims_isolation ON cigar_worker_claims;
CREATE POLICY cigar_worker_claims_isolation ON cigar_worker_claims
    USING (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''));

