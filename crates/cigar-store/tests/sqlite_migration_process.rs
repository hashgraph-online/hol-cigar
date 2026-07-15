//! Process-death qualification for the retained SQLite v1-to-v4 migration chain.

#![cfg(all(feature = "migration-fault-injection", target_os = "macos"))]

use cigar_store::{SqliteMigrationFailpoint, SqliteStore, StoreRevision};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, params};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::fs::{self, Permissions};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const CHILD_BOUNDARY: &str = "CIGAR_SQLITE_MIGRATION_ABORT_BOUNDARY";
const CHILD_PATH: &str = "CIGAR_SQLITE_MIGRATION_ABORT_PATH";
const INITIAL_MIGRATION: &str = include_str!("../migrations/sqlite/0001_initial.sql");

fn boundary_name(boundary: SqliteMigrationFailpoint) -> String {
    match boundary {
        SqliteMigrationFailpoint::AfterLedgerBootstrap => "after-ledger-bootstrap".to_owned(),
        SqliteMigrationFailpoint::AfterTransactionBegin(sequence) => {
            format!("after-transaction-begin-{sequence}")
        }
        SqliteMigrationFailpoint::AfterMigrationSql(sequence) => {
            format!("after-migration-sql-{sequence}")
        }
        SqliteMigrationFailpoint::BeforeLedgerInsert(sequence) => {
            format!("before-ledger-insert-{sequence}")
        }
        SqliteMigrationFailpoint::AfterLedgerInsert(sequence) => {
            format!("after-ledger-insert-{sequence}")
        }
        SqliteMigrationFailpoint::BeforeCommit(sequence) => {
            format!("before-commit-{sequence}")
        }
        SqliteMigrationFailpoint::AfterCommit(sequence) => {
            format!("after-commit-{sequence}")
        }
    }
}

fn parse_boundary(value: &str) -> Result<SqliteMigrationFailpoint, Box<dyn std::error::Error>> {
    if value == "after-ledger-bootstrap" {
        return Ok(SqliteMigrationFailpoint::AfterLedgerBootstrap);
    }
    for (prefix, constructor) in [
        (
            "after-transaction-begin-",
            SqliteMigrationFailpoint::AfterTransactionBegin as fn(u32) -> _,
        ),
        (
            "after-migration-sql-",
            SqliteMigrationFailpoint::AfterMigrationSql as fn(u32) -> _,
        ),
        (
            "before-ledger-insert-",
            SqliteMigrationFailpoint::BeforeLedgerInsert as fn(u32) -> _,
        ),
        (
            "after-ledger-insert-",
            SqliteMigrationFailpoint::AfterLedgerInsert as fn(u32) -> _,
        ),
        (
            "before-commit-",
            SqliteMigrationFailpoint::BeforeCommit as fn(u32) -> _,
        ),
        (
            "after-commit-",
            SqliteMigrationFailpoint::AfterCommit as fn(u32) -> _,
        ),
    ] {
        if let Some(sequence) = value.strip_prefix(prefix) {
            return Ok(constructor(sequence.parse()?));
        }
    }
    Err(format!("unknown SQLite migration boundary `{value}`").into())
}

fn multihash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("1220{suffix}")
}

fn genesis_snapshot() -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct LegacyGenesis {
        revision: StoreRevision,
        tenants: BTreeMap<cigar_protocol::RecordId, ()>,
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &LegacyGenesis {
            revision: StoreRevision(0),
            tenants: BTreeMap::new(),
        },
        &mut bytes,
    )?;
    let checksum = multihash(&bytes);
    Ok((bytes, checksum))
}

fn create_retained_v1(
    path: &Path,
    genesis: &(Vec<u8>, String),
) -> Result<(), Box<dyn std::error::Error>> {
    fs::set_permissions(
        path.parent().ok_or("retained fixture path has no parent")?,
        Permissions::from_mode(0o700),
    )?;
    drop(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?,
    );
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(30))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA cache_size = -32768;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA temp_store = MEMORY;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = ON;",
    )?;
    if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)? {
        return Err("SQLite defensive mode was unavailable".into());
    }
    connection.execute_batch(INITIAL_MIGRATION)?;
    connection.execute(
        "INSERT INTO schema_migrations
           (sequence, name, checksum, applied_at_unix_nanos)
         VALUES (1, 'initial', ?1, '1700000000000000000')",
        params![multihash(INITIAL_MIGRATION.as_bytes())],
    )?;
    connection.execute(
        "INSERT INTO state_snapshots (revision, state, checksum) VALUES (0, ?1, ?2)",
        params![&genesis.0, genesis.1.as_str()],
    )?;
    drop(connection);
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            fs::set_permissions(sidecar, Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn durable_prefix(boundary: SqliteMigrationFailpoint) -> u32 {
    match boundary {
        SqliteMigrationFailpoint::AfterLedgerBootstrap => 1,
        SqliteMigrationFailpoint::AfterCommit(sequence) => sequence,
        SqliteMigrationFailpoint::AfterTransactionBegin(sequence)
        | SqliteMigrationFailpoint::AfterMigrationSql(sequence)
        | SqliteMigrationFailpoint::BeforeLedgerInsert(sequence)
        | SqliteMigrationFailpoint::AfterLedgerInsert(sequence)
        | SqliteMigrationFailpoint::BeforeCommit(sequence) => sequence - 1,
    }
}

fn ledger(connection: &Connection) -> Result<Vec<(u32, String)>, Box<dyn std::error::Error>> {
    let mut statement =
        connection.prepare("SELECT sequence, name FROM schema_migrations ORDER BY sequence")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
         )",
        params![name],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

#[test]
fn sqlite_migration_abort_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(boundary) = std::env::var(CHILD_BOUNDARY) else {
        return Ok(());
    };
    let path = PathBuf::from(std::env::var(CHILD_PATH)?);
    SqliteStore::migrate_with_process_abort(path, parse_boundary(&boundary)?)?;
    Err("SQLite migration process-abort boundary unexpectedly returned".into())
}

#[test]
fn process_death_at_every_sqlite_migration_boundary_recovers_exact_prefix_and_root()
-> Result<(), Box<dyn std::error::Error>> {
    let mut boundaries = vec![SqliteMigrationFailpoint::AfterLedgerBootstrap];
    for sequence in 2..=4 {
        boundaries.extend([
            SqliteMigrationFailpoint::AfterTransactionBegin(sequence),
            SqliteMigrationFailpoint::AfterMigrationSql(sequence),
            SqliteMigrationFailpoint::BeforeLedgerInsert(sequence),
            SqliteMigrationFailpoint::AfterLedgerInsert(sequence),
            SqliteMigrationFailpoint::BeforeCommit(sequence),
            SqliteMigrationFailpoint::AfterCommit(sequence),
        ]);
    }
    let genesis = genesis_snapshot()?;
    let executable = std::env::current_exe()?;
    for boundary in boundaries {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join(format!("{}.sqlite3", boundary_name(boundary)));
        create_retained_v1(&path, &genesis)?;
        let status = Command::new(&executable)
            .args(["--exact", "sqlite_migration_abort_child", "--nocapture"])
            .env(CHILD_BOUNDARY, boundary_name(boundary))
            .env(CHILD_PATH, &path)
            .status()?;
        assert!(!status.success());

        let expected_prefix = durable_prefix(boundary);
        let interrupted = Connection::open(&path)?;
        let expected_ledger = [
            (1, "initial".to_owned()),
            (2, "compatibility_ledger".to_owned()),
            (3, "generation_bound_atom_projection".to_owned()),
            (4, "normalized_authoritative_catalog".to_owned()),
        ];
        let expected_prefix_ledger = expected_ledger
            .get(..usize::try_from(expected_prefix)?)
            .ok_or("durable migration prefix exceeded the catalog")?;
        assert_eq!(ledger(&interrupted)?, expected_prefix_ledger);
        assert_eq!(
            table_exists(&interrupted, "atom_projection_generations")?,
            expected_prefix >= 3
        );
        drop(interrupted);

        let recovered = SqliteStore::open(&path)?;
        assert_eq!(recovered.revision()?, StoreRevision(0));
        assert_eq!(recovered.semantic_root()?.as_str(), genesis.1);
        recovered.integrity_check()?;
        drop(recovered);
        let connection = Connection::open(path)?;
        assert_eq!(ledger(&connection)?, expected_ledger);
        assert!(table_exists(&connection, "atom_projection_generations")?);
        assert!(table_exists(&connection, "cigar_catalog_authority")?);
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
    }
    Ok(())
}
