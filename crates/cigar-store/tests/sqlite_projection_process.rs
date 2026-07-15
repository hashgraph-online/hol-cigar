//! Process-death qualification for generation-bound SQLite/FTS activation.

#![cfg(feature = "projection-fault-injection")]

use cigar_store::{
    CancellationToken, MAX_RETAINED_SQLITE_PROJECTION_GENERATIONS, SqliteProjectionFailpoint,
    SqliteStore,
};
use rusqlite::Connection;
use std::path::PathBuf;
use std::process::Command;

const CHILD_BOUNDARY: &str = "CIGAR_SQLITE_PROJECTION_ABORT_BOUNDARY";
const CHILD_PATH: &str = "CIGAR_SQLITE_PROJECTION_ABORT_PATH";

fn boundary_name(boundary: SqliteProjectionFailpoint) -> &'static str {
    match boundary {
        SqliteProjectionFailpoint::AfterBeginImmediate => "after-begin-immediate",
        SqliteProjectionFailpoint::AfterGenerationReserved => "after-generation-reserved",
        SqliteProjectionFailpoint::AfterRowsBuilt => "after-rows-built",
        SqliteProjectionFailpoint::AfterGenerationVerified => "after-generation-verified",
        SqliteProjectionFailpoint::BeforeActivation => "before-activation",
        SqliteProjectionFailpoint::AfterActivation => "after-activation",
        SqliteProjectionFailpoint::BeforeCommit => "before-commit",
        SqliteProjectionFailpoint::AfterCommit => "after-commit",
    }
}

fn parse_boundary(value: &str) -> Result<SqliteProjectionFailpoint, Box<dyn std::error::Error>> {
    Ok(match value {
        "after-begin-immediate" => SqliteProjectionFailpoint::AfterBeginImmediate,
        "after-generation-reserved" => SqliteProjectionFailpoint::AfterGenerationReserved,
        "after-rows-built" => SqliteProjectionFailpoint::AfterRowsBuilt,
        "after-generation-verified" => SqliteProjectionFailpoint::AfterGenerationVerified,
        "before-activation" => SqliteProjectionFailpoint::BeforeActivation,
        "after-activation" => SqliteProjectionFailpoint::AfterActivation,
        "before-commit" => SqliteProjectionFailpoint::BeforeCommit,
        "after-commit" => SqliteProjectionFailpoint::AfterCommit,
        _ => return Err(format!("unknown projection boundary `{value}`").into()),
    })
}

#[test]
fn sqlite_projection_abort_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(boundary) = std::env::var(CHILD_BOUNDARY) else {
        return Ok(());
    };
    let path = PathBuf::from(std::env::var(CHILD_PATH)?);
    let store = SqliteStore::open(path)?;
    let boundary = parse_boundary(&boundary)?;
    let _never_returns =
        store.rebuild_atom_projection_with_process_abort(&CancellationToken::default(), boundary);
    Err("process-abort boundary unexpectedly returned".into())
}

#[test]
fn process_death_at_every_projection_boundary_recovers_one_complete_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let boundaries = [
        SqliteProjectionFailpoint::AfterBeginImmediate,
        SqliteProjectionFailpoint::AfterGenerationReserved,
        SqliteProjectionFailpoint::AfterRowsBuilt,
        SqliteProjectionFailpoint::AfterGenerationVerified,
        SqliteProjectionFailpoint::BeforeActivation,
        SqliteProjectionFailpoint::AfterActivation,
        SqliteProjectionFailpoint::BeforeCommit,
        SqliteProjectionFailpoint::AfterCommit,
    ];
    let executable = std::env::current_exe()?;
    for boundary in boundaries {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join(format!("{}.sqlite3", boundary_name(boundary)));
        let before = {
            let store = SqliteStore::open(&path)?;
            store.projection_status()?
        };
        let status = Command::new(&executable)
            .args(["--exact", "sqlite_projection_abort_child", "--nocapture"])
            .env(CHILD_BOUNDARY, boundary_name(boundary))
            .env(CHILD_PATH, &path)
            .status()?;
        assert!(!status.success());

        let recovered = {
            let store = SqliteStore::open(&path)?;
            store.projection_status()?
        };
        if boundary == SqliteProjectionFailpoint::AfterCommit {
            assert!(recovered.generation > before.generation);
        } else {
            assert_eq!(recovered.generation, before.generation);
        }
        let connection = Connection::open(&path)?;
        let retained = connection.query_row(
            "SELECT COUNT(*) FROM atom_projection_generations",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert!(retained >= 1);
        assert!(usize::try_from(retained)? <= MAX_RETAINED_SQLITE_PROJECTION_GENERATIONS);
    }
    Ok(())
}
