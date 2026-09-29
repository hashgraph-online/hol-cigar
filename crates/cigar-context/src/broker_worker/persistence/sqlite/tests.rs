#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
use super::*;
use cigar_context::broker::{AgentGrantSpec, AgentLimits, SourceOrigin, SourceProvenance};
use cigar_context::{ContextRequest, ContextViewSpec, Document, Utf8ByteCounter};
use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use tempfile::TempDir;

struct TestDirectory {
    _parent: TempDir,
    path: PathBuf,
}
impl TestDirectory {
    fn path(&self) -> &Path {
        &self.path
    }
}
fn private_directory() -> TestDirectory {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("store");
    #[cfg(unix)]
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    #[cfg(windows)]
    drop(cigar_windows_ipc::PrivateStorageDirectory::open(&path, true).unwrap());
    TestDirectory {
        _parent: parent,
        path,
    }
}

fn options(directory: &TestDirectory) -> BrokerStorageOptions {
    let mut options = BrokerStorageOptions::new(directory.path());
    options.max_checkpoint_bytes = 4 * 1024 * 1024;
    options.max_database_bytes = 16 * 1024 * 1024;
    options.max_journal_records = 3;
    options
}
fn open(options: BrokerStorageOptions) -> Result<(ContextBroker, Store, bool), BrokerError> {
    Store::open(
        "durable-test".into(),
        GraphLimits::default(),
        BrokerLimits::default(),
        options,
    )
}
fn provenance() -> SourceProvenance {
    SourceProvenance {
        authority: "test-host".into(),
        upstream_revision: "one".into(),
        observed_at_ms: 1,
        valid_until_ms: None,
        origin: SourceOrigin::Host,
        derived_from: vec![],
    }
}
fn change(broker: &mut ContextBroker, text: &str) -> Event {
    let expected = broker.host_source_revision("docs").unwrap();
    broker
        .host_replace_source(
            "docs",
            &expected,
            if text.is_empty() {
                vec![]
            } else {
                vec![Document::new("fact", "docs", text)]
            },
            provenance(),
        )
        .unwrap();
    Event {
        operation: Operation::ReplaceSource,
        epoch: broker.epoch().into(),
        expected: BTreeMap::from([("docs".into(), expected)]),
        resulting: BTreeMap::from([("docs".into(), broker.host_source_revision("docs").unwrap())]),
    }
}
fn grant(broker: &mut ContextBroker) -> cigar_context::broker::BrokerCredential {
    broker
        .host_grant(AgentGrantSpec {
            view: ContextViewSpec {
                id: "reader".into(),
                policy_revision: "one".into(),
                allowed_sources: BTreeSet::from(["docs".into()]),
                writable_sources: BTreeSet::new(),
            },
            limits: AgentLimits::default(),
            lease_ms: 60_000,
        })
        .unwrap()
}

#[cfg(windows)]
#[test]
#[allow(clippy::expect_used)] // Named test phases diagnose the redacted public error boundary.
fn windows_sqlite_vfs_preserves_pinned_private_file() {
    // Keep individual phase assertions: the public boundary deliberately redacts OS/SQLite
    // failures to Unavailable, but this fixture must identify which interoperability failed.
    let directory = private_directory();
    let options = options(&directory);
    let (path, created) = PrivatePath::prepare(&options).expect("prepare private NTFS path");
    assert!(created);
    let mut connection = Connection::open_with_flags(
        &path.database,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .expect("open pinned NTFS database through SQLite VFS");
    path.verify(&options).expect("verify after VFS open");
    configure(&connection, &options).expect("configure SQLite safety limits");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .expect("acquire SQLite exclusive transaction");
    transaction.execute_batch(META).expect("create metadata");
    transaction.execute_batch(JOURNAL).expect("create journal");
    transaction.commit().expect("commit initialization");
    path.verify(&options).expect("verify after SQLite commit");
    path.sync_creation()
        .expect("flush retained database handle");
}

#[test]
fn source_batches_write_one_committed_image_and_restore_no_pending_staging() {
    use super::super::Persistence;
    use cigar_context::broker::protocol::HostCommand;
    let directory = private_directory();
    let mut opts = options(&directory);
    opts.max_journal_records = 16;
    let start = || {
        Persistence::open(
            "durable-test".into(),
            GraphLimits::default(),
            BrokerLimits::default(),
            Some(opts.clone()),
        )
        .unwrap()
    };
    let (mut broker, mut persistence, _) = start();
    let original = change(&mut broker, "old committed evidence");
    persistence.commit(&broker, original).unwrap();
    let source = broker.host_source_revision("docs").unwrap();
    let begin = HostCommand::BeginSourceReplace {
        source: "docs".into(),
        expected: source.clone(),
        provenance: provenance(),
        lease_ms: 60_000,
    };
    assert!(persistence.prepare(&broker, &begin).unwrap().is_none());
    let pending = broker
        .host_begin_source_replace("docs", &source, provenance(), 60_000)
        .unwrap();
    let before = fs::read(&persistence.store.as_ref().unwrap().path.database).unwrap();
    let append = HostCommand::AppendSourceDocuments {
        transaction: pending.clone(),
        documents: vec![Document::new("fact", "docs", "STAGED_NOT_COMMITTED")],
    };
    assert!(persistence.prepare(&broker, &append).unwrap().is_none());
    broker
        .host_append_source_documents(
            &pending,
            vec![Document::new("fact", "docs", "STAGED_NOT_COMMITTED")],
        )
        .unwrap();
    assert_eq!(
        fs::read(&persistence.store.as_ref().unwrap().path.database).unwrap(),
        before
    );
    drop(persistence);
    drop(broker);

    let (mut broker, mut persistence, restored) = start();
    assert!(restored);
    assert_eq!(
        broker.host_commit_source_replace(&pending),
        Err(BrokerError::Stale)
    );
    assert_eq!(
        broker.host_source_revision("docs").unwrap().version,
        source.version
    );
    let credential = grant(&mut broker);
    let request = ContextRequest {
        query: "evidence".into(),
        required: BTreeSet::from(["fact".into()]),
        ..Default::default()
    };
    assert!(
        broker
            .compile(&credential, &request, &Utf8ByteCounter)
            .unwrap()
            .rendered
            .contains("old committed evidence")
    );
    let source = broker.host_source_revision("docs").unwrap();
    let transaction = broker
        .host_begin_source_replace("docs", &source, provenance(), 60_000)
        .unwrap();
    broker
        .host_append_source_documents(
            &transaction,
            vec![Document::new("fact", "docs", "new committed evidence")],
        )
        .unwrap();
    let before: i64 = persistence
        .store
        .as_ref()
        .unwrap()
        .connection
        .query_row("SELECT count(*) FROM broker_journal", [], |row| row.get(0))
        .unwrap();
    let event = persistence
        .prepare(
            &broker,
            &HostCommand::CommitSourceReplace {
                transaction: transaction.clone(),
            },
        )
        .unwrap()
        .unwrap();
    let receipt = broker.host_commit_source_replace(&transaction).unwrap();
    persistence.commit(&broker, event).unwrap();
    let after: i64 = persistence
        .store
        .as_ref()
        .unwrap()
        .connection
        .query_row("SELECT count(*) FROM broker_journal", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, before + 1);
    drop(persistence);
    drop(broker);
    let (mut broker, _persistence, _) = start();
    assert_eq!(
        broker.host_source_revision("docs").unwrap().version,
        receipt.revision.version
    );
    assert_eq!(
        broker.host_commit_source_replace(&transaction),
        Err(BrokerError::Stale)
    );
    let credential = grant(&mut broker);
    assert!(
        broker
            .compile(&credential, &request, &Utf8ByteCounter)
            .unwrap()
            .rendered
            .contains("new committed evidence")
    );
}

#[test]
fn private_directory_creation_is_explicit_and_never_creates_missing_parents() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("store");
    let mut options = BrokerStorageOptions::new(&directory);
    assert!(open(options.clone()).is_err());
    assert!(!directory.exists());
    options.create_directory = true;
    let (_, store, restored) = open(options.clone()).unwrap();
    assert!(!restored);
    drop(store);
    let (_, store, restored) = open(options.clone()).unwrap();
    assert!(restored);
    drop(store);
    options.directory = parent.path().join("missing-parent").join("store");
    assert!(open(options).is_err());
    assert!(!parent.path().join("missing-parent").exists());
}

#[test]
fn restart_preserves_commits_and_tombstones_with_bounded_receipts_and_fresh_authority() {
    let directory = private_directory();
    let opts = options(&directory);
    let (mut broker, mut store, restored) = open(opts.clone()).unwrap();
    assert!(!restored);
    let old_credential = grant(&mut broker);
    for text in ["one", "two", "three", "four", ""] {
        let event = change(&mut broker, text);
        store.commit(&broker, &event).unwrap();
    }
    let old = broker.host_source_revision("docs").unwrap();
    assert_eq!(old.version, 5);
    let count: i64 = store
        .connection
        .query_row("SELECT count(*) FROM broker_journal", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 3);
    assert!(
        open(opts.clone()).is_err(),
        "a second owner must not acquire the store"
    );
    let file = fs::read(&store.path.database).unwrap();
    assert!(
        !file
            .windows(old_credential.secret.len())
            .any(|v| v == old_credential.secret.as_bytes())
    );
    drop(store);
    let (mut broker, _store, restored) = open(opts).unwrap();
    assert!(restored);
    let current = broker.host_source_revision("docs").unwrap();
    assert_eq!(current.version, old.version);
    assert_ne!(current.epoch, old.epoch);
    assert!(
        broker
            .compile(
                &old_credential,
                &ContextRequest::default(),
                &Utf8ByteCounter
            )
            .is_err()
    );
    assert_eq!(
        broker.host_replace_source("docs", &old, vec![], provenance()),
        Err(BrokerError::Conflict)
    );
    let credential = grant(&mut broker);
    let context = broker
        .compile(
            &credential,
            &ContextRequest {
                query: "evidence".into(),
                ..ContextRequest::default()
            },
            &Utf8ByteCounter,
        )
        .unwrap();
    assert!(!context.rendered.contains("four"));
}

#[test]
fn interrupted_transactions_restore_only_the_last_commit() {
    for point in 0..=3 {
        let directory = private_directory();
        let opts = options(&directory);
        let (mut broker, mut store, _) = open(opts.clone()).unwrap();
        let event = change(&mut broker, "old evidence");
        store.commit(&broker, &event).unwrap();
        drop(store);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "broker_worker::persistence::sqlite::tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("CIGAR_TEST_STORE_DIRECTORY", directory.path())
            .env("CIGAR_TEST_CRASH_POINT", point.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("crash fixture exceeded its process deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(91),
            "crash fixture did not run: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (mut restored, _store, _) = open(opts).unwrap();
        assert_eq!(
            restored.host_source_revision("docs").unwrap().version,
            if point == 3 { 2 } else { 1 }
        );
        let credential = grant(&mut restored);
        let context = restored
            .compile(
                &credential,
                &ContextRequest {
                    query: "evidence".into(),
                    ..ContextRequest::default()
                },
                &Utf8ByteCounter,
            )
            .unwrap();
        assert_eq!(context.rendered.contains("old evidence"), point != 3);
    }
}

#[test]
#[ignore = "invoked by the bounded crash parent with a dedicated private directory"]
fn crash_child() {
    let directory = std::env::var_os("CIGAR_TEST_STORE_DIRECTORY").unwrap();
    let point: u8 = std::env::var("CIGAR_TEST_CRASH_POINT")
        .unwrap()
        .parse()
        .unwrap();
    let mut opts = BrokerStorageOptions::new(directory);
    opts.max_checkpoint_bytes = 4 * 1024 * 1024;
    opts.max_database_bytes = 16 * 1024 * 1024;
    opts.max_journal_records = 3;
    let (mut broker, mut store, _) = open(opts).unwrap();
    // Force dirty pages to spill before COMMIT, exercising actual hot-journal rollback.
    store
        .connection
        .pragma_update(None, "cache_size", 2)
        .unwrap();
    let event = change(&mut broker, &"new evidence ".repeat(16_000));
    store
        .commit_with_hook(&broker, &event, |boundary| {
            if boundary == point {
                std::process::exit(91);
            }
        })
        .unwrap();
    panic!("fault boundary was not reached");
}

#[test]
fn corruption_and_unknown_schema_are_rejected_without_reset() {
    for sql in [
        "UPDATE broker_meta SET checkpoint=x'00'",
        "UPDATE broker_journal SET previous='corrupt'",
        "UPDATE broker_journal SET event=x'7b7d'",
        "UPDATE broker_journal SET event=zeroblob(32769)",
        "DELETE FROM broker_journal",
        "UPDATE broker_meta SET sequence=99",
        "PRAGMA user_version=2",
        "CREATE TABLE unexpected(data BLOB)",
    ] {
        let directory = private_directory();
        let opts = options(&directory);
        let (mut broker, mut store, _) = open(opts.clone()).unwrap();
        let event = change(&mut broker, "private evidence");
        store.commit(&broker, &event).unwrap();
        drop(store);
        let database = directory.path().join("broker.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();
        assert!(open(opts).is_err());
        assert_eq!(fs::read(&database).unwrap(), before);
    }
}

#[test]
fn exhausted_forged_sequence_is_rejected_without_integer_overflow() {
    let directory = private_directory();
    let opts = options(&directory);
    let (_, store, _) = open(opts.clone()).unwrap();
    drop(store);
    let database = directory.path().join("broker.sqlite3");
    let connection = Connection::open(&database).unwrap();
    let (checkpoint, event): (String, Vec<u8>) = connection
        .query_row(
            "SELECT checkpoint_digest,event FROM broker_journal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let head = receipt_hash(i64::MAX, ZERO, &checkpoint, &event);
    connection
        .execute(
            "UPDATE broker_meta SET sequence=?1,anchor_sequence=?2,head_digest=?3",
            params![i64::MAX, i64::MAX - 1, head],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE broker_journal SET sequence=?1,digest=?2",
            params![i64::MAX, head],
        )
        .unwrap();
    drop(connection);
    assert!(open(opts).is_err());
}

#[test]
fn maximum_escaped_source_locators_fit_durable_relation_receipts() {
    let directory = private_directory();
    let opts = options(&directory);
    let (mut broker, mut store, _) = open(opts.clone()).unwrap();
    let sources = [
        format!("{}a", "\\".repeat(2047)),
        format!("{}b", "\\".repeat(2047)),
    ];
    for (source, id) in sources.iter().zip(["left", "right"]) {
        let before = broker.host_source_revision(source).unwrap();
        broker
            .host_replace_source(
                source,
                &before,
                vec![Document::new(id, source, "evidence")],
                provenance(),
            )
            .unwrap();
        let event = Event {
            operation: Operation::ReplaceSource,
            epoch: broker.epoch().into(),
            expected: BTreeMap::from([(source.clone(), before)]),
            resulting: BTreeMap::from([(
                source.clone(),
                broker.host_source_revision(source).unwrap(),
            )]),
        };
        store.commit(&broker, &event).unwrap();
    }
    let expected = sources
        .iter()
        .map(|source| (source.clone(), broker.host_source_revision(source).unwrap()))
        .collect();
    let resulting = broker
        .host_set_edge(
            "left",
            "right",
            cigar_context::EdgeKind::Contradicts,
            true,
            &expected,
        )
        .unwrap();
    let event = Event {
        operation: Operation::SetEdge,
        epoch: broker.epoch().into(),
        expected,
        resulting,
    };
    assert!(event_bytes(&event).unwrap().len() > 16 * 1024);
    store.commit(&broker, &event).unwrap();
    drop(store);
    let (broker, _store, _) = open(opts).unwrap();
    for source in sources {
        assert_eq!(broker.host_source_revision(&source).unwrap().version, 2);
    }
}

#[test]
fn rejected_checkpoint_and_disk_bounds_leave_the_previous_durable_evidence() {
    let directory = private_directory();
    let mut opts = options(&directory);
    opts.max_checkpoint_bytes = 4096;
    opts.max_database_bytes = 131_072;
    let (mut broker, mut store, _) = open(opts.clone()).unwrap();
    let event = change(&mut broker, "old");
    store.commit(&broker, &event).unwrap();
    let event = change(&mut broker, &"x".repeat(8192));
    assert_eq!(store.commit(&broker, &event), Err(BrokerError::Quota));
    drop(store);
    let (broker, _store, _) = open(opts).unwrap();
    assert_eq!(broker.host_source_revision("docs").unwrap().version, 1);

    let directory = private_directory();
    let opts = options(&directory);
    let (mut broker, mut store, _) = open(opts.clone()).unwrap();
    let pages: i64 = store
        .connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    store
        .connection
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let event = change(&mut broker, &"large evidence".repeat(10_000));
    assert!(store.commit(&broker, &event).is_err());
    drop(store);
    let (broker, _store, _) = open(opts).unwrap();
    assert_eq!(broker.host_source_revision("docs").unwrap().version, 0);
}

#[test]
#[cfg(unix)]
fn unsafe_paths_and_replaced_files_are_rejected_without_chmod_or_following() {
    let directory = private_directory();
    let opts = options(&directory);
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(open(opts.clone()).is_err());
    assert!(!directory.path().join("broker.sqlite3").exists());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (mut broker, mut store, _) = open(opts.clone()).unwrap();
    let held = directory.path().join("held.sqlite3");
    fs::rename(&store.path.database, &held).unwrap();
    symlink(&held, &store.path.database).unwrap();
    let event = change(&mut broker, "never acknowledged");
    assert!(store.commit(&broker, &event).is_err());
    assert!(open(opts.clone()).is_err());
    drop(store);
    fs::remove_file(directory.path().join("broker.sqlite3")).unwrap();
    fs::hard_link(&held, directory.path().join("broker.sqlite3")).unwrap();
    assert!(open(opts).is_err());

    let directory = private_directory();
    let opts = options(&directory);
    let (_, store, _) = open(opts.clone()).unwrap();
    drop(store);
    let target = directory.path().join("private-target");
    fs::write(&target, b"untouched").unwrap();
    symlink(&target, directory.path().join("broker.sqlite3-journal")).unwrap();
    assert!(open(opts).is_err());
    assert_eq!(fs::read(target).unwrap(), b"untouched");

    let parent = private_directory();
    let child = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent.path())
        .unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(open(BrokerStorageOptions::new(child.path())).is_err());
    assert!(!child.path().join("broker.sqlite3").exists());
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
}
