//! Bounded evidence checkpoints and a rolling receipt chain in one SQLite transaction.
//! The chain detects inconsistent bytes, not a privileged replacement of the whole database.
use super::{Event, Operation};
use cigar_context::broker::{
    BrokerCheckpoint, BrokerError, BrokerLimits, BrokerStorageOptions, ContextBroker,
};
use cigar_context::{ContextError, GraphLimits};
use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

#[cfg(unix)]
mod path;
#[cfg(windows)]
#[path = "sqlite/windows_path.rs"]
mod path;
use path::PrivatePath;

const META: &str = "CREATE TABLE broker_meta (id INTEGER PRIMARY KEY CHECK(id=1), sequence INTEGER NOT NULL, anchor_sequence INTEGER NOT NULL, anchor_digest TEXT NOT NULL, head_digest TEXT NOT NULL, checkpoint_digest TEXT NOT NULL, checkpoint BLOB NOT NULL) STRICT";
const JOURNAL: &str = "CREATE TABLE broker_journal (sequence INTEGER PRIMARY KEY, previous TEXT NOT NULL, digest TEXT NOT NULL, checkpoint_digest TEXT NOT NULL, event BLOB NOT NULL) STRICT";
const APPLICATION_ID: i64 = 0x4349_4742;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
// Two maximum 2048-byte source locators, possibly JSON-escaped, appear in both CAS maps.
const EVENT_BYTES: usize = 32 * 1024;

pub(super) struct Store {
    connection: Connection,
    path: PrivatePath,
    options: BrokerStorageOptions,
    sequence: i64,
    head: String,
    checkpoint: Vec<u8>,
}

impl Store {
    pub(super) fn open(
        domain: String,
        graph: GraphLimits,
        limits: BrokerLimits,
        options: BrokerStorageOptions,
    ) -> Result<(ContextBroker, Self, bool), BrokerError> {
        validate_options(&options)?;
        let fresh = ContextBroker::new(domain.clone(), graph, limits)?;
        let (path, created) = PrivatePath::prepare(&options)?;
        let mut connection = Connection::open_with_flags(
            &path.database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(unavailable)?;
        path.verify(&options)?;
        if !created {
            validate_schema(&connection)?;
        }
        configure(&connection, &options)?;
        // EXCLUSIVE mode retains the acquired writer lock between commits for this connection.
        // Reading PRAGMA locking_mode alone would not acquire it.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(unavailable)?;
        if created {
            transaction.execute_batch(META).map_err(unavailable)?;
            transaction.execute_batch(JOURNAL).map_err(unavailable)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(unavailable)?;
            transaction
                .pragma_update(None, "user_version", 1)
                .map_err(unavailable)?;
        } else {
            validate_schema(&transaction)?;
        }
        transaction.commit().map_err(unavailable)?;
        let mut store = Self {
            connection,
            path,
            options,
            sequence: 0,
            head: ZERO.into(),
            checkpoint: Vec::new(),
        };
        let broker = if created {
            fresh
        } else {
            let checkpoint = store.load()?;
            ContextBroker::from_checkpoint(domain, graph, limits, &checkpoint)?
        };
        // Persist the new epoch before the listener/hello can expose it. This also refreshes the
        // saved monotonic expiry cap; credentials and transient review state are never restored.
        let event = Event {
            operation: if created {
                Operation::Initialize
            } else {
                Operation::Resume
            },
            epoch: broker.epoch().into(),
            expected: BTreeMap::new(),
            resulting: BTreeMap::new(),
        };
        store.commit(&broker, &event)?;
        store.path.sync_creation()?;
        Ok((broker, store, !created))
    }

    fn load(&mut self) -> Result<BrokerCheckpoint, BrokerError> {
        let quick: String = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(unavailable)?;
        if quick != "ok" {
            return Err(integrity());
        }
        let count: i64 = self
            .connection
            .query_row("SELECT count(*) FROM broker_meta", [], |row| row.get(0))
            .map_err(unavailable)?;
        if count != 1 {
            return Err(integrity());
        }
        let (sequence, anchor_sequence, anchor, head, checkpoint_hash, bytes): (i64, i64, String, String, String, Vec<u8>) = self.connection
            .query_row("SELECT sequence,anchor_sequence,anchor_digest,head_digest,checkpoint_digest,checkpoint FROM broker_meta WHERE id=1", [], |row| {
                Ok((row.get(0)?, row.get(1)?, read_hash(row, 2)?, read_hash(row, 3)?, read_hash(row, 4)?, read_blob(row, 5, self.options.max_checkpoint_bytes)?))
            }).map_err(unavailable)?;
        if sequence <= 0
            || sequence == i64::MAX
            || anchor_sequence < 0
            || anchor_sequence >= sequence
            || sequence - anchor_sequence > self.options.max_journal_records as i64
            || !hex(&anchor)
            || !hex(&head)
            || checkpoint_hash != sha(&bytes)
            || (anchor_sequence == 0 && anchor != ZERO)
        {
            return Err(integrity());
        }
        let count: i64 = self
            .connection
            .query_row("SELECT count(*) FROM broker_journal", [], |row| row.get(0))
            .map_err(unavailable)?;
        if count != sequence - anchor_sequence {
            return Err(integrity());
        }
        let mut statement = self.connection.prepare("SELECT sequence,previous,digest,checkpoint_digest,event FROM broker_journal ORDER BY sequence").map_err(unavailable)?;
        let mut rows = statement.query([]).map_err(unavailable)?;
        let mut next = anchor_sequence + 1;
        let mut previous = anchor;
        let mut last_checkpoint_hash = String::new();
        while let Some(row) = rows.next().map_err(unavailable)? {
            let current: i64 = row.get(0).map_err(unavailable)?;
            let parent = read_hash(row, 1).map_err(unavailable)?;
            let stored = read_hash(row, 2).map_err(unavailable)?;
            let checkpoint_digest = read_hash(row, 3).map_err(unavailable)?;
            let body = read_blob(row, 4, EVENT_BYTES).map_err(unavailable)?;
            let event: Event = serde_json::from_slice(&body).map_err(|_| integrity())?;
            if current != next
                || parent != previous
                || !hex(&checkpoint_digest)
                || event_bytes(&event)? != body
                || stored != receipt_hash(current, &parent, &checkpoint_digest, &body)
            {
                return Err(integrity());
            }
            next += 1;
            previous = stored;
            last_checkpoint_hash = checkpoint_digest;
        }
        if next != sequence + 1 || previous != head || last_checkpoint_hash != checkpoint_hash {
            return Err(integrity());
        }
        let checkpoint = BrokerCheckpoint::decode(&bytes, self.options.max_checkpoint_bytes)?;
        self.sequence = sequence;
        self.head = head;
        Ok(checkpoint)
    }

    pub(super) fn commit(
        &mut self,
        broker: &ContextBroker,
        event: &Event,
    ) -> Result<(), BrokerError> {
        self.commit_with_hook(broker, event, |_| {})
    }

    fn commit_with_hook(
        &mut self,
        broker: &ContextBroker,
        event: &Event,
        mut boundary: impl FnMut(u8),
    ) -> Result<(), BrokerError> {
        let body = event_bytes(event)?;
        if event.epoch != broker.epoch() {
            return Err(integrity());
        }
        broker
            .host_checkpoint(self.options.max_checkpoint_bytes)?
            .encode_into(&mut self.checkpoint, self.options.max_checkpoint_bytes)?;
        let checkpoint = &self.checkpoint;
        let checkpoint_hash = sha(checkpoint);
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n < i64::MAX)
            .ok_or(BrokerError::Quota)?;
        let head = receipt_hash(sequence, &self.head, &checkpoint_hash, &body);
        self.path.verify(&self.options)?;
        boundary(0);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(unavailable)?;
        transaction.execute("INSERT INTO broker_journal(sequence,previous,digest,checkpoint_digest,event) VALUES(?1,?2,?3,?4,?5)",
            params![sequence, self.head, head, checkpoint_hash, body]).map_err(unavailable)?;
        boundary(1);
        let anchor_sequence = (sequence - self.options.max_journal_records as i64).max(0);
        let anchor = if anchor_sequence == 0 {
            ZERO.to_owned()
        } else {
            transaction
                .query_row(
                    "SELECT digest FROM broker_journal WHERE sequence=?1",
                    [anchor_sequence],
                    |row| row.get::<_, String>(0),
                )
                .map_err(unavailable)?
        };
        transaction.execute("INSERT INTO broker_meta(id,sequence,anchor_sequence,anchor_digest,head_digest,checkpoint_digest,checkpoint) VALUES(1,?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET sequence=excluded.sequence,anchor_sequence=excluded.anchor_sequence,anchor_digest=excluded.anchor_digest,head_digest=excluded.head_digest,checkpoint_digest=excluded.checkpoint_digest,checkpoint=excluded.checkpoint",
            params![sequence, anchor_sequence, anchor, head, checkpoint_hash, checkpoint]).map_err(unavailable)?;
        transaction
            .execute(
                "DELETE FROM broker_journal WHERE sequence<=?1",
                [anchor_sequence],
            )
            .map_err(unavailable)?;
        boundary(2);
        transaction.commit().map_err(unavailable)?;
        boundary(3);
        self.path.verify(&self.options)?;
        self.sequence = sequence;
        self.head = head;
        Ok(())
    }
}

fn validate_options(options: &BrokerStorageOptions) -> Result<(), BrokerError> {
    if !options.directory.is_absolute()
        || !(1024..=512 * 1024 * 1024).contains(&options.max_checkpoint_bytes)
        || options.max_database_bytes
            < options
                .max_checkpoint_bytes
                .saturating_mul(2)
                .saturating_add(65536)
        || options.max_database_bytes > 2 * 1024 * 1024 * 1024
        || !(1..=4096).contains(&options.max_journal_records)
    {
        return Err(BrokerError::InvalidInput);
    }
    Ok(())
}

fn configure(connection: &Connection, options: &BrokerStorageOptions) -> Result<(), BrokerError> {
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(unavailable)?;
    connection
        .set_limit(
            Limit::SQLITE_LIMIT_LENGTH,
            (options.max_checkpoint_bytes + 65536) as i32,
        )
        .map_err(unavailable)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 16384)
        .map_err(unavailable)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(unavailable)?
    {
        return Err(integrity());
    }
    connection
        .execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA trusted_schema=OFF;
        PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-4096;
        PRAGMA journal_size_limit=0;",
        )
        .map_err(unavailable)?;
    // Refuse stores using a different page size instead of silently changing the disk bound.
    for (name, wanted) in [
        ("synchronous", 3),
        ("trusted_schema", 0),
        ("secure_delete", 1),
        ("temp_store", 2),
        ("page_size", 4096),
        ("fullfsync", 1),
    ] {
        let value: i64 = connection
            .pragma_query_value(None, name, |row| row.get(0))
            .map_err(unavailable)?;
        if value != wanted {
            return Err(integrity());
        }
    }
    for (name, wanted) in [("locking_mode", "exclusive"), ("journal_mode", "delete")] {
        let value: String = connection
            .pragma_query_value(None, name, |row| row.get(0))
            .map_err(unavailable)?;
        if value != wanted {
            return Err(integrity());
        }
    }
    let pages = (options.max_database_bytes / 4096) as i64;
    connection
        .pragma_update(None, "max_page_count", pages)
        .map_err(unavailable)?;
    let effective: i64 = connection
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .map_err(unavailable)?;
    if effective != pages {
        return Err(BrokerError::Quota);
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), BrokerError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(unavailable)?;
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(unavailable)?;
    let mut statement = connection
        .prepare("SELECT name,sql FROM sqlite_schema ORDER BY name")
        .map_err(unavailable)?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(unavailable)?;
    if version != 1
        || application != APPLICATION_ID
        || objects
            != [
                ("broker_journal".into(), JOURNAL.into()),
                ("broker_meta".into(), META.into()),
            ]
    {
        return Err(integrity());
    }
    Ok(())
}

fn event_bytes(event: &Event) -> Result<Vec<u8>, BrokerError> {
    if !hex(&event.epoch)
        || event.expected.len() > 2
        || event.expected.len() != event.resulting.len()
    {
        return Err(integrity());
    }
    match event.operation {
        Operation::Initialize | Operation::Resume if !event.expected.is_empty() => {
            return Err(integrity());
        }
        Operation::ReplaceSource | Operation::AdmitProposal if event.expected.len() != 1 => {
            return Err(integrity());
        }
        Operation::SetEdge if event.expected.is_empty() => return Err(integrity()),
        _ => {}
    }
    for (source, before) in &event.expected {
        let after = event.resulting.get(source).ok_or_else(integrity)?;
        if before.epoch != event.epoch
            || after.epoch != event.epoch
            || after.version < before.version
            || after.version - before.version > 1
        {
            return Err(integrity());
        }
    }
    let bytes = serde_json::to_vec(event).map_err(|_| integrity())?;
    if bytes.len() > EVENT_BYTES {
        return Err(BrokerError::Quota);
    }
    Ok(bytes)
}

fn receipt_hash(sequence: i64, previous: &str, checkpoint: &str, event: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cigar.broker-journal.v1\0");
    digest.update(sequence.to_be_bytes());
    digest.update(previous.as_bytes());
    digest.update(checkpoint.as_bytes());
    digest.update((event.len() as u64).to_be_bytes());
    digest.update(event);
    hex_bytes(&digest.finalize())
}

fn read_blob(row: &rusqlite::Row<'_>, column: usize, limit: usize) -> rusqlite::Result<Vec<u8>> {
    let bytes = row
        .get_ref(column)?
        .as_blob()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if bytes.len() > limit {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(bytes.to_vec())
}

fn read_hash(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<String> {
    let value = row
        .get_ref(column)?
        .as_str()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if !hex(value) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(value.to_owned())
}
fn sha(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}
fn hex_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unavailable(_: rusqlite::Error) -> BrokerError {
    BrokerError::Unavailable
}
fn integrity() -> BrokerError {
    BrokerError::Context(ContextError::Integrity)
}

#[cfg(test)]
mod tests;
