-- CIGAR PostgreSQL schema v3. Append-only rolling-compatible atom projection.
-- sequence/name: 3 / atom_projection
-- application compatibility: major 1 through major 2
-- classification/lock: online / bounded ACCESS EXCLUSIVE locks on one new empty table only
-- data backfill: explicit bounded rebuild; old binaries continue to use protected tenant snapshots
-- verification: atom projection exists with forced RLS and immutable identity constraints
-- rollback or restore: old binaries ignore this table; restore the pre-migration backup to remove it
CREATE TABLE IF NOT EXISTS cigar_atom_projection (
    tenant_id text NOT NULL CHECK (length(tenant_id) = 36),
    atom_id text NOT NULL CHECK (length(atom_id) = 36),
    lineage_id text NOT NULL CHECK (length(lineage_id) = 36),
    version_id text NOT NULL CHECK (length(version_id) = 68),
    record bytea NOT NULL CHECK (octet_length(record) > 0),
    record_checksum text NOT NULL CHECK (length(record_checksum) = 68),
    published_revision bigint NOT NULL
        REFERENCES cigar_repository_revisions(revision),
    projected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, version_id),
    UNIQUE (tenant_id, atom_id)
);

CREATE INDEX IF NOT EXISTS cigar_atom_projection_lineage
    ON cigar_atom_projection (tenant_id, lineage_id, version_id);

ALTER TABLE cigar_atom_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE cigar_atom_projection FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cigar_atom_projection_isolation ON cigar_atom_projection;
CREATE POLICY cigar_atom_projection_isolation ON cigar_atom_projection
    USING (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cigar.tenant_id', true), ''));
