-- CIGAR PostgreSQL schema v1. Append-only; checksum recorded in schema_migrations.
-- sequence/name: 1 / shared_metadata
-- application compatibility: major 1 through major 2
-- classification/lock: online / bounded ACCESS EXCLUSIVE locks on new empty tables only
-- data backfill: none
-- verification: singleton revision zero and RLS enabled/forced on every tenant table
-- rollback or restore: drop only on a fresh install; otherwise restore the mandatory pre-migration backup
CREATE TABLE IF NOT EXISTS cigar_repository_revision (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision >= 0)
);

INSERT INTO cigar_repository_revision (singleton, revision)
VALUES (true, 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS cigar_repository_revisions (
    revision bigint PRIMARY KEY CHECK (revision >= 0),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO cigar_repository_revisions (revision)
VALUES (0)
ON CONFLICT (revision) DO NOTHING;

CREATE TABLE IF NOT EXISTS cigar_tenant_states (
    tenant_id text NOT NULL,
    revision bigint NOT NULL REFERENCES cigar_repository_revisions(revision),
    state bytea NOT NULL,
    checksum text NOT NULL CHECK (length(checksum) = 68),
    PRIMARY KEY (tenant_id, revision)
);

CREATE INDEX IF NOT EXISTS cigar_tenant_states_latest
    ON cigar_tenant_states (tenant_id, revision DESC);

ALTER TABLE cigar_tenant_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE cigar_tenant_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cigar_tenant_states_isolation ON cigar_tenant_states;
CREATE POLICY cigar_tenant_states_isolation ON cigar_tenant_states
    USING (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''));

CREATE TABLE IF NOT EXISTS cigar_shared_wakeups (
    tenant_id text NOT NULL,
    revision bigint NOT NULL REFERENCES cigar_repository_revisions(revision),
    topic text NOT NULL CHECK (length(topic) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, revision, topic)
);

CREATE INDEX IF NOT EXISTS cigar_shared_wakeups_by_revision
    ON cigar_shared_wakeups (tenant_id, revision, topic);

ALTER TABLE cigar_shared_wakeups ENABLE ROW LEVEL SECURITY;
ALTER TABLE cigar_shared_wakeups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cigar_shared_wakeups_isolation ON cigar_shared_wakeups;
CREATE POLICY cigar_shared_wakeups_isolation ON cigar_shared_wakeups
    USING (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''));

