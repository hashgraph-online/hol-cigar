-- CIGAR SQLite schema v3. Append-only generation-bound atom/FTS projections.
-- sequence/name: 3 / generation_bound_atom_projection
-- application compatibility: major 1 through major 1
-- classification/lock: offline / one bounded exclusive SQLite schema transaction
-- data backfill: startup builds and verifies the first generation from authoritative state
-- verification: active generation, revision watermark, state digest, row root, and FTS parity
-- rollback or restore: restore the verified pre-migration backup; historical readers reject this ledger
CREATE TABLE IF NOT EXISTS atom_projection_generations (
    generation INTEGER PRIMARY KEY CHECK (generation > 0),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_checksum TEXT NOT NULL CHECK (length(state_checksum) = 68),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    projection_root TEXT NOT NULL CHECK (length(projection_root) = 68),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    created_at_unix_nanos TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS atom_projection_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL REFERENCES atom_projection_generations(generation),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_checksum TEXT NOT NULL CHECK (length(state_checksum) = 68),
    activated_at_unix_nanos TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS atom_projection_rows (
    generation INTEGER NOT NULL REFERENCES atom_projection_generations(generation) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    exact_text TEXT NOT NULL,
    record BLOB NOT NULL,
    record_checksum TEXT NOT NULL CHECK (length(record_checksum) = 68),
    PRIMARY KEY (generation, tenant_id, version_id)
) STRICT;

CREATE INDEX IF NOT EXISTS atom_projection_rows_by_lineage
    ON atom_projection_rows (generation, tenant_id, lineage_id, version_id);

CREATE VIRTUAL TABLE IF NOT EXISTS atom_projection_fts USING fts5(
    generation UNINDEXED,
    tenant_id UNINDEXED,
    version_id UNINDEXED,
    exact_text,
    tokenize = 'unicode61'
);
