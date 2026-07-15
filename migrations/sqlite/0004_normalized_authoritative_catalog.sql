-- CIGAR SQLite schema v4. Offline normalized authoritative atom/edge catalog.
-- sequence/name: 4 / normalized_authoritative_catalog
-- application compatibility: major 1 through major 1
-- classification/lock: offline / one bounded exclusive SQLite schema transaction plus restart-safe application backfill
-- data backfill: startup atomically extracts every retained legacy revision before deleting legacy whole-state bytes
-- verification: catalog-free residual checksums, revision roots, ordered catalog roots, indexed row checksums, lineage heads, and empty legacy snapshots
-- rollback or restore: restore the verified pre-migration backup; v3 binaries reject the sequence-four ledger
CREATE TABLE IF NOT EXISTS cigar_catalog_authority (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version INTEGER NOT NULL CHECK (format_version = 4),
    capacity_profile TEXT NOT NULL CHECK (capacity_profile IN ('standard', 'large_local')),
    activated INTEGER NOT NULL CHECK (activated IN (0, 1)),
    activated_at_unix_nanos TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS cigar_repository_revisions_v4 (
    revision INTEGER PRIMARY KEY CHECK (revision >= 0),
    residual_state BLOB NOT NULL,
    residual_checksum TEXT NOT NULL CHECK (length(residual_checksum) = 68),
    catalog_root TEXT NOT NULL CHECK (length(catalog_root) = 68),
    semantic_root TEXT NOT NULL CHECK (length(semantic_root) = 68),
    semantic_root_format INTEGER NOT NULL CHECK (semantic_root_format IN (1, 4)),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    referenced_blob_bytes INTEGER NOT NULL CHECK (referenced_blob_bytes >= 0)
) STRICT;

CREATE TABLE IF NOT EXISTS cigar_catalog_atoms (
    tenant_id TEXT NOT NULL,
    version_id TEXT NOT NULL,
    atom_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    observed_at_unix_nanos TEXT NOT NULL,
    exact_text TEXT NOT NULL,
    referenced_blob_bytes INTEGER NOT NULL CHECK (referenced_blob_bytes >= 0),
    root_bucket INTEGER NOT NULL CHECK (root_bucket BETWEEN 0 AND 65535),
    published_revision INTEGER NOT NULL CHECK (published_revision >= 0),
    record BLOB NOT NULL,
    record_checksum TEXT NOT NULL CHECK (length(record_checksum) = 68),
    PRIMARY KEY (tenant_id, version_id),
    UNIQUE (tenant_id, atom_id)
) STRICT;

CREATE INDEX IF NOT EXISTS cigar_catalog_atoms_query
    ON cigar_catalog_atoms (tenant_id, version_id, published_revision);
CREATE INDEX IF NOT EXISTS cigar_catalog_atoms_kind_query
    ON cigar_catalog_atoms (tenant_id, kind, version_id, published_revision);
CREATE INDEX IF NOT EXISTS cigar_catalog_atoms_revision
    ON cigar_catalog_atoms (published_revision, tenant_id, version_id);
CREATE INDEX IF NOT EXISTS cigar_catalog_atoms_root_bucket
    ON cigar_catalog_atoms (root_bucket, tenant_id, version_id);
CREATE INDEX IF NOT EXISTS cigar_catalog_atoms_lineage
    ON cigar_catalog_atoms (tenant_id, lineage_id, published_revision, version_id);

CREATE TABLE IF NOT EXISTS cigar_catalog_lineage_heads (
    tenant_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    valid_from_revision INTEGER NOT NULL CHECK (valid_from_revision >= 0),
    valid_to_revision INTEGER CHECK (
        valid_to_revision IS NULL OR valid_to_revision > valid_from_revision
    ),
    version_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, lineage_id, valid_from_revision),
    FOREIGN KEY (tenant_id, version_id)
        REFERENCES cigar_catalog_atoms(tenant_id, version_id)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS cigar_catalog_lineage_open_head
    ON cigar_catalog_lineage_heads (tenant_id, lineage_id)
    WHERE valid_to_revision IS NULL;
CREATE INDEX IF NOT EXISTS cigar_catalog_lineage_at_revision
    ON cigar_catalog_lineage_heads
       (tenant_id, lineage_id, valid_from_revision, valid_to_revision, version_id);

CREATE TABLE IF NOT EXISTS cigar_catalog_edges (
    tenant_id TEXT NOT NULL,
    edge_id TEXT NOT NULL,
    from_version TEXT NOT NULL,
    to_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    root_bucket INTEGER NOT NULL CHECK (root_bucket BETWEEN 0 AND 65535),
    published_revision INTEGER NOT NULL CHECK (published_revision >= 0),
    record BLOB NOT NULL,
    record_checksum TEXT NOT NULL CHECK (length(record_checksum) = 68),
    PRIMARY KEY (tenant_id, edge_id),
    FOREIGN KEY (tenant_id, from_version)
        REFERENCES cigar_catalog_atoms(tenant_id, version_id),
    FOREIGN KEY (tenant_id, to_version)
        REFERENCES cigar_catalog_atoms(tenant_id, version_id)
) STRICT;

CREATE INDEX IF NOT EXISTS cigar_catalog_edges_from
    ON cigar_catalog_edges
       (tenant_id, from_version, kind, edge_id, published_revision);
CREATE INDEX IF NOT EXISTS cigar_catalog_edges_revision
    ON cigar_catalog_edges (published_revision, tenant_id, edge_id);
CREATE INDEX IF NOT EXISTS cigar_catalog_edges_root_bucket
    ON cigar_catalog_edges (root_bucket, tenant_id, edge_id);
CREATE INDEX IF NOT EXISTS cigar_catalog_edges_derived
    ON cigar_catalog_edges
       (tenant_id, from_version, to_version, published_revision)
    WHERE kind = 'derived_from';

CREATE TABLE IF NOT EXISTS cigar_catalog_root_buckets (
    root_bucket INTEGER PRIMARY KEY CHECK (root_bucket BETWEEN 0 AND 65535),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    referenced_blob_bytes INTEGER NOT NULL CHECK (referenced_blob_bytes >= 0),
    atom_root TEXT NOT NULL CHECK (length(atom_root) = 68),
    edge_root TEXT NOT NULL CHECK (length(edge_root) = 68)
) STRICT;
