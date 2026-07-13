//! Subprocess crash-boundary tests for SQLite WAL durability.

use cigar_protocol::{RecordId, SourceSnapshot};
use cigar_store::{
    AccessContext, CancellationToken, Repository, SqliteStore, StoreRevision, WriteTransaction,
};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Command;

const CHILD_MODE: &str = "CIGAR_SQLITE_CRASH_MODE";
const CHILD_PATH: &str = "CIGAR_SQLITE_CRASH_PATH";

fn fixture_snapshot() -> Result<SourceSnapshot, Box<dyn std::error::Error>> {
    let fixture = cigar_testkit::deterministic_protocol_fixture("SourceSnapshot")
        .ok_or("missing source snapshot fixture")?;
    Ok(serde_json::from_value(fixture.input)?)
}

fn context() -> Result<AccessContext, Box<dyn std::error::Error>> {
    Ok(AccessContext::new(
        RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        "sqlite-crash-test",
    )?)
}

#[test]
fn sqlite_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return Ok(());
    };
    let path = PathBuf::from(std::env::var(CHILD_PATH)?);
    let store = SqliteStore::open(path)?;
    let mut write =
        store.begin_write(context()?, StoreRevision(0), CancellationToken::default())?;
    write.stage_snapshot(fixture_snapshot()?)?;
    if mode == "before-commit" {
        std::process::exit(90);
    }
    write.commit(None)?;
    std::process::exit(91);
}

#[test]
fn process_termination_preserves_exact_commit_boundary_and_wal_rpo()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let executable = std::env::current_exe()?;
    for (mode, expected_status, expected_revision) in [
        ("before-commit", 90, StoreRevision(0)),
        ("after-commit", 91, StoreRevision(1)),
    ] {
        let path = directory.path().join(format!("{mode}.sqlite3"));
        let status = Command::new(&executable)
            .args(["--exact", "sqlite_process_child", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_PATH, &path)
            .status()?;
        assert_eq!(status.code(), Some(expected_status));
        let reopened = SqliteStore::open(path)?;
        assert_eq!(reopened.revision()?, expected_revision);
        reopened.integrity_check()?;
    }
    Ok(())
}

#[test]
fn truncated_committed_wal_never_opens_as_silent_older_state()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("wal-damage.sqlite3");
    let status = Command::new(std::env::current_exe()?)
        .args(["--exact", "sqlite_process_child", "--nocapture"])
        .env(CHILD_MODE, "after-commit")
        .env(CHILD_PATH, &path)
        .status()?;
    assert_eq!(status.code(), Some(91));
    let wal = path.with_extension("sqlite3-wal");
    let length = std::fs::metadata(&wal)?.len();
    assert!(length > 1);
    OpenOptions::new()
        .write(true)
        .open(&wal)?
        .set_len(length - 1)?;
    match SqliteStore::open(path) {
        Ok(store) => assert_eq!(store.revision()?, StoreRevision(1)),
        Err(_error) => {}
    }
    Ok(())
}
