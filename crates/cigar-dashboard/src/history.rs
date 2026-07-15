//! Owner-protected SQLite journal for strict content-safe dashboard events.

use crate::{
    CursorKind, DashboardHistoryConfig, EventError, EvidenceDescriptor, EvidenceStatus,
    PagePosition, RunRecord, RunState, SafeEvent, SafeEventSink,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, Transaction, params};
use std::fmt;
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const SCHEMA_VERSION: i64 = 4;
const SUPERVISOR_GENERATION: i64 = 1;
const WRITER_QUEUE_CAPACITY: usize = 64;
const WRITER_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const BACKUP_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const SQLITE_BACKUP_PAGES_PER_STEP: i32 = 64;
const SQLITE_BACKUP_RETRY_PAUSE: Duration = Duration::from_millis(1);
const DATABASE_SIZE_OVERHEAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SEED_EVENTS: usize = 10_000;
const MAX_SEED_BYTES: usize = 16 * 1024 * 1024;

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Stable content-free history failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// The configured database path, type, owner, permissions, or link count was unsafe.
    UnsafePath,
    /// The SQLite schema was unknown, corrupt, or incompatible.
    InvalidDatabase,
    /// A retained event failed strict schema or byte validation.
    InvalidEvent,
    /// A persisted run failed strict schema validation.
    InvalidRun,
    /// The requested run does not exist.
    RunNotFound,
    /// The requested run lifecycle edge is not allowed.
    InvalidTransition,
    /// A persisted evidence descriptor failed its closed schema.
    InvalidEvidence,
    /// The requested evidence descriptor does not exist.
    EvidenceNotFound,
    /// A retention, database, or writer queue bound was exceeded.
    LimitExceeded,
    /// SQLite could not durably commit because the backing volume was full.
    DiskFull,
    /// The single writer was unavailable or did not acknowledge within its deadline.
    WriterUnavailable,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "dashboard history path is unsafe",
            Self::InvalidDatabase => "dashboard history database is invalid",
            Self::InvalidEvent => "dashboard history event is invalid",
            Self::InvalidRun => "dashboard history run is invalid",
            Self::RunNotFound => "dashboard history run was not found",
            Self::InvalidTransition => "dashboard history run transition is invalid",
            Self::InvalidEvidence => "dashboard history evidence descriptor is invalid",
            Self::EvidenceNotFound => "dashboard history evidence descriptor was not found",
            Self::LimitExceeded => "dashboard history limit was exceeded",
            Self::DiskFull => "dashboard history volume is full",
            Self::WriterUnavailable => "dashboard history writer is unavailable",
        })
    }
}

impl std::error::Error for HistoryError {}

#[derive(Clone, Copy)]
struct Retention {
    max_runs: i64,
    max_events: i64,
    max_bytes: i64,
    max_age_days: i64,
    max_event_bytes: usize,
}

struct RecordMessage {
    sequence: i64,
    observed_at: String,
    event_json: String,
    encoded_bytes: i64,
    acknowledgement: SyncSender<Result<(), HistoryError>>,
}

/// Exact per-run aggregate byte reservations persisted before child creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunResourceReservation {
    output_bytes: i64,
    evidence_bytes: i64,
}

impl RunResourceReservation {
    pub(crate) fn new(output_bytes: u64, evidence_bytes: u64) -> Result<Self, HistoryError> {
        let reservation = Self {
            output_bytes: i64::try_from(output_bytes)
                .map_err(|_error| HistoryError::LimitExceeded)?,
            evidence_bytes: i64::try_from(evidence_bytes)
                .map_err(|_error| HistoryError::LimitExceeded)?,
        };
        if reservation.output_bytes <= 0 || reservation.evidence_bytes <= 0 {
            return Err(HistoryError::LimitExceeded);
        }
        Ok(reservation)
    }
}

/// Exact aggregate usage observed only after every owned descendant and output pipe settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunResourceUsage {
    output_bytes: i64,
    evidence_bytes: i64,
}

impl RunResourceUsage {
    pub(crate) fn new(output_bytes: u64, evidence_bytes: u64) -> Result<Self, HistoryError> {
        Ok(Self {
            output_bytes: i64::try_from(output_bytes)
                .map_err(|_error| HistoryError::LimitExceeded)?,
            evidence_bytes: i64::try_from(evidence_bytes)
                .map_err(|_error| HistoryError::LimitExceeded)?,
        })
    }
}

/// Private durable identity for one macOS process group owned by a dashboard run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunProcessIdentity {
    pid: i64,
    process_group_id: i64,
    identity_sha256: String,
}

impl RunProcessIdentity {
    pub(crate) fn new(
        pid: u32,
        process_group_id: u32,
        identity_sha256: String,
    ) -> Result<Self, HistoryError> {
        let pid = i64::from(pid);
        let process_group_id = i64::from(process_group_id);
        let identity = Self {
            pid,
            process_group_id,
            identity_sha256,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn pid(&self) -> u32 {
        u32::try_from(self.pid).unwrap_or_default()
    }

    pub(crate) fn process_group_id(&self) -> u32 {
        u32::try_from(self.process_group_id).unwrap_or_default()
    }

    pub(crate) fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    fn validate(&self) -> Result<(), HistoryError> {
        if self.pid <= 0
            || self.pid > i64::from(i32::MAX)
            || self.process_group_id != self.pid
            || !lower_sha256(&self.identity_sha256)
        {
            return Err(HistoryError::InvalidRun);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RecoverableRun {
    run: RunRecord,
    supervisor_generation: i64,
    process: Option<RunProcessIdentity>,
    resources_reserved: bool,
}

impl RecoverableRun {
    pub(crate) fn run(&self) -> &RunRecord {
        &self.run
    }

    pub(crate) const fn supervisor_generation(&self) -> i64 {
        self.supervisor_generation
    }

    pub(crate) fn process(&self) -> Option<&RunProcessIdentity> {
        self.process.as_ref()
    }

    pub(crate) const fn resources_reserved(&self) -> bool {
        self.resources_reserved
    }
}

enum WriterMessage {
    Record(RecordMessage),
    CreateRun {
        run: Box<RunRecord>,
        resources: Option<RunResourceReservation>,
        acknowledgement: SyncSender<Result<(), HistoryError>>,
    },
    TransitionRun {
        run_id: String,
        next: RunState,
        executable_digest: Option<String>,
        receipt_id: Option<String>,
        failure_code: Option<String>,
        acknowledgement: SyncSender<Result<RunRecord, HistoryError>>,
    },
    ActivateRun {
        run_id: String,
        process: RunProcessIdentity,
        acknowledgement: SyncSender<Result<RunRecord, HistoryError>>,
    },
    CompleteRun {
        run_id: String,
        next: RunState,
        receipt_id: Option<String>,
        failure_code: Option<String>,
        resources: RunResourceUsage,
        descriptors: Vec<EvidenceDescriptor>,
        acknowledgement: SyncSender<Result<RunRecord, HistoryError>>,
    },
    RecoverableRuns {
        acknowledgement: SyncSender<Result<Vec<RecoverableRun>, HistoryError>>,
    },
    ListRuns {
        limit: usize,
        after: Option<PagePosition>,
        acknowledgement: SyncSender<Result<RunHistoryPage, HistoryError>>,
    },
    GetRun {
        run_id: String,
        acknowledgement: SyncSender<Result<RunRecord, HistoryError>>,
    },
    #[cfg(test)]
    RecordEvidence {
        descriptor: Box<EvidenceDescriptor>,
        acknowledgement: SyncSender<Result<(), HistoryError>>,
    },
    ListEvidence {
        limit: usize,
        after: Option<PagePosition>,
        acknowledgement: SyncSender<Result<EvidenceHistoryPage, HistoryError>>,
    },
    GetEvidence {
        evidence_id: String,
        acknowledgement: SyncSender<Result<EvidenceDescriptor, HistoryError>>,
    },
    Backup {
        destination: PathBuf,
        acknowledgement: SyncSender<Result<(), HistoryError>>,
    },
    Shutdown(SyncSender<()>),
}

pub(crate) struct RunHistoryPage {
    pub(crate) records: Vec<RunRecord>,
    pub(crate) next: Option<PagePosition>,
}

pub(crate) struct EvidenceHistoryPage {
    pub(crate) records: Vec<EvidenceDescriptor>,
    pub(crate) next: Option<PagePosition>,
}

/// Cloneable bounded request endpoint for dashboard-owned run history.
#[derive(Clone)]
pub struct HistoryClient {
    sender: SyncSender<WriterMessage>,
}

impl HistoryClient {
    /// Persists one validated queued record before any child process is spawned.
    pub fn create_run(&self, run: RunRecord) -> Result<(), HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::CreateRun {
            run: Box::new(run),
            resources: None,
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Persists a queued run and its exact aggregate byte reservations in one transaction.
    pub(crate) fn create_run_with_resources(
        &self,
        run: RunRecord,
        resources: RunResourceReservation,
    ) -> Result<(), HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::CreateRun {
            run: Box::new(run),
            resources: Some(resources),
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Applies and persists one monotonic lifecycle transition.
    pub fn transition_run(
        &self,
        run_id: &str,
        next: RunState,
        executable_digest: Option<&str>,
        receipt_id: Option<&str>,
        failure_code: Option<&str>,
    ) -> Result<RunRecord, HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::TransitionRun {
            run_id: run_id.to_owned(),
            next,
            executable_digest: executable_digest.map(str::to_owned),
            receipt_id: receipt_id.map(str::to_owned),
            failure_code: failure_code.map(str::to_owned),
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Atomically persists the verified process identity and the `running` lifecycle edge.
    pub(crate) fn activate_run(
        &self,
        run_id: &str,
        process: RunProcessIdentity,
    ) -> Result<RunRecord, HistoryError> {
        process.validate()?;
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::ActivateRun {
            run_id: run_id.to_owned(),
            process,
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Atomically settles lifecycle, process identity, byte ledger, and sanitized evidence rows.
    pub(crate) fn complete_run(
        &self,
        run_id: &str,
        next: RunState,
        receipt_id: Option<&str>,
        failure_code: Option<&str>,
        resources: RunResourceUsage,
        descriptors: Vec<EvidenceDescriptor>,
    ) -> Result<RunRecord, HistoryError> {
        if !next.is_terminal() || next == RunState::Lost {
            return Err(HistoryError::InvalidTransition);
        }
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::CompleteRun {
            run_id: run_id.to_owned(),
            next,
            receipt_id: receipt_id.map(str::to_owned),
            failure_code: failure_code.map(str::to_owned),
            resources,
            descriptors,
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Loads every non-terminal run plus its private persisted process identity for startup repair.
    pub(crate) fn recoverable_runs(&self) -> Result<Vec<RecoverableRun>, HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::RecoverableRuns { acknowledgement })?;
        receive_ack(receiver)
    }

    /// Returns at most `limit` newest runs with event arrays omitted from the summary rows.
    pub fn list_runs(&self, limit: usize) -> Result<Vec<RunRecord>, HistoryError> {
        Ok(self.list_runs_page(limit, None)?.records)
    }

    pub(crate) fn list_runs_page(
        &self,
        limit: usize,
        after: Option<PagePosition>,
    ) -> Result<RunHistoryPage, HistoryError> {
        if !(1..=100).contains(&limit) {
            return Err(HistoryError::LimitExceeded);
        }
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::ListRuns {
            limit,
            after,
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Returns one run with its currently retained content-safe events.
    pub fn get_run(&self, run_id: &str) -> Result<RunRecord, HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::GetRun {
            run_id: run_id.to_owned(),
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Persists metadata already produced by an independent strict receipt verifier.
    #[cfg(test)]
    pub(crate) fn record_evidence(
        &self,
        descriptor: EvidenceDescriptor,
    ) -> Result<(), HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::RecordEvidence {
            descriptor: Box::new(descriptor),
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Returns at most `limit` newest sanitized evidence descriptors.
    pub fn list_evidence(&self, limit: usize) -> Result<Vec<EvidenceDescriptor>, HistoryError> {
        Ok(self.list_evidence_page(limit, None)?.records)
    }

    pub(crate) fn list_evidence_page(
        &self,
        limit: usize,
        after: Option<PagePosition>,
    ) -> Result<EvidenceHistoryPage, HistoryError> {
        if !(1..=100).contains(&limit) {
            return Err(HistoryError::LimitExceeded);
        }
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::ListEvidence {
            limit,
            after,
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Returns one sanitized evidence descriptor by opaque identifier.
    pub fn get_evidence(&self, evidence_id: &str) -> Result<EvidenceDescriptor, HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::GetEvidence {
            evidence_id: evidence_id.to_owned(),
            acknowledgement,
        })?;
        receive_ack(receiver)
    }

    /// Creates one consistent, create-new SQLite snapshot in an owner-only directory.
    ///
    /// The destination must be absolute and absent. Existing files are never replaced, and this
    /// API never reads from or writes to daemon-owned persistence.
    pub fn backup_to(&self, destination: &Path) -> Result<(), HistoryError> {
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.try_send(WriterMessage::Backup {
            destination: destination.to_owned(),
            acknowledgement,
        })?;
        receiver
            .recv_timeout(BACKUP_ACK_TIMEOUT)
            .map_err(|_error| HistoryError::WriterUnavailable)?
    }

    fn try_send(&self, message: WriterMessage) -> Result<(), HistoryError> {
        self.sender.try_send(message).map_err(|error| match error {
            TrySendError::Full(_message) => HistoryError::LimitExceeded,
            TrySendError::Disconnected(_message) => HistoryError::WriterUnavailable,
        })
    }
}

impl fmt::Debug for HistoryClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryClient")
            .finish_non_exhaustive()
    }
}

fn receive_ack<T>(receiver: Receiver<Result<T, HistoryError>>) -> Result<T, HistoryError> {
    receiver
        .recv_timeout(WRITER_ACK_TIMEOUT)
        .map_err(|_error| HistoryError::WriterUnavailable)?
}

/// Cloneable persistence endpoint attached to a safe-event broker.
#[derive(Clone)]
pub struct HistorySink {
    sender: SyncSender<WriterMessage>,
    max_event_bytes: usize,
}

impl SafeEventSink for HistorySink {
    fn record(&self, event: &SafeEvent) -> Result<(), EventError> {
        self.record_event(event).map_err(map_history_event_error)
    }
}

impl HistorySink {
    fn record_event(&self, event: &SafeEvent) -> Result<(), HistoryError> {
        let event_json = event
            .to_json()
            .map_err(|_error| HistoryError::InvalidEvent)?;
        let encoded_bytes = event_json.len();
        if encoded_bytes == 0 || encoded_bytes > self.max_event_bytes {
            return Err(HistoryError::LimitExceeded);
        }
        let sequence =
            i64::try_from(event.sequence()).map_err(|_error| HistoryError::LimitExceeded)?;
        let encoded_bytes =
            i64::try_from(encoded_bytes).map_err(|_error| HistoryError::LimitExceeded)?;
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        let message = WriterMessage::Record(RecordMessage {
            sequence,
            observed_at: event.observed_at().to_owned(),
            event_json,
            encoded_bytes,
            acknowledgement,
        });
        self.sender.try_send(message).map_err(|error| match error {
            TrySendError::Full(_message) => HistoryError::LimitExceeded,
            TrySendError::Disconnected(_message) => HistoryError::WriterUnavailable,
        })?;
        receiver
            .recv_timeout(WRITER_ACK_TIMEOUT)
            .map_err(|_error| HistoryError::WriterUnavailable)?
    }
}

impl fmt::Debug for HistorySink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistorySink")
            .field("max_event_bytes", &self.max_event_bytes)
            .finish_non_exhaustive()
    }
}

/// Owner-protected event journal and its dedicated bounded writer thread.
pub struct HistoryStore {
    sink: Arc<HistorySink>,
    client: HistoryClient,
    retained_events: Vec<SafeEvent>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl HistoryStore {
    /// Opens, migrates, prunes, and validates the dashboard-only history database.
    pub fn open(
        config: &DashboardHistoryConfig,
        max_event_bytes: usize,
    ) -> Result<Self, HistoryError> {
        let retention = retention(config, max_event_bytes)?;
        let before = prepare_database_file(&config.database_file, config.max_bytes)?;
        let mut connection = open_connection(&config.database_file)?;
        let after = fs::symlink_metadata(&config.database_file)
            .map_err(|_error| HistoryError::UnsafePath)?;
        validate_private_file(&after)?;
        if !same_file(&before, &after) {
            return Err(HistoryError::UnsafePath);
        }
        migrate(&connection)?;
        verify_integrity(&connection)?;
        prune_connection(&mut connection, retention)?;
        let retained_events = load_retained_events(&connection, retention)?;
        let (sender, receiver) = mpsc::sync_channel(WRITER_QUEUE_CAPACITY);
        let worker = thread::Builder::new()
            .name("cigar-dashboard-history".to_owned())
            .spawn(move || writer_loop(connection, receiver, retention))
            .map_err(|_error| HistoryError::WriterUnavailable)?;
        Ok(Self {
            sink: Arc::new(HistorySink {
                sender: sender.clone(),
                max_event_bytes,
            }),
            client: HistoryClient { sender },
            retained_events,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Returns retained events already revalidated and ordered by sequence.
    #[must_use]
    pub fn retained_events(&self) -> Vec<SafeEvent> {
        self.retained_events.clone()
    }

    /// Returns the persistence endpoint attached before the broker publishes new events.
    #[must_use]
    pub fn sink(&self) -> Arc<dyn SafeEventSink> {
        self.sink.clone()
    }

    /// Returns a cloneable bounded endpoint for run persistence and read APIs.
    #[must_use]
    pub fn client(&self) -> HistoryClient {
        self.client.clone()
    }

    /// Flushes the writer queue, closes SQLite, and joins the dedicated writer.
    pub fn shutdown(&self) -> Result<(), HistoryError> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_poisoned| HistoryError::WriterUnavailable)?;
        let Some(handle) = worker.take() else {
            return Ok(());
        };
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.sink
            .sender
            .send(WriterMessage::Shutdown(acknowledgement))
            .map_err(|_error| HistoryError::WriterUnavailable)?;
        receiver
            .recv_timeout(WRITER_ACK_TIMEOUT)
            .map_err(|_error| HistoryError::WriterUnavailable)?;
        handle
            .join()
            .map_err(|_panic| HistoryError::WriterUnavailable)
    }
}

impl fmt::Debug for HistoryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryStore")
            .field("retained_events", &self.retained_events.len())
            .field(
                "writer_running",
                &self.worker.lock().is_ok_and(|worker| worker.is_some()),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for HistoryStore {
    fn drop(&mut self) {
        let _ignored = self.shutdown();
    }
}

fn retention(
    config: &DashboardHistoryConfig,
    max_event_bytes: usize,
) -> Result<Retention, HistoryError> {
    if !(256..=1024 * 1024).contains(&max_event_bytes) {
        return Err(HistoryError::LimitExceeded);
    }
    Ok(Retention {
        max_runs: i64::try_from(config.max_runs).map_err(|_error| HistoryError::LimitExceeded)?,
        max_events: i64::try_from(config.max_events_per_run)
            .map_err(|_error| HistoryError::LimitExceeded)?,
        max_bytes: i64::try_from(config.max_bytes).map_err(|_error| HistoryError::LimitExceeded)?,
        max_age_days: i64::from(config.max_age_days),
        max_event_bytes,
    })
}

fn prepare_database_file(path: &Path, max_bytes: u64) -> Result<fs::Metadata, HistoryError> {
    if !path.is_absolute() {
        return Err(HistoryError::UnsafePath);
    }
    let parent = path.parent().ok_or(HistoryError::UnsafePath)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_error| HistoryError::UnsafePath)?;
    validate_private_directory(&parent_metadata)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_file(&metadata)?;
            if metadata.len() > max_bytes.saturating_add(DATABASE_SIZE_OVERHEAD_BYTES) {
                return Err(HistoryError::LimitExceeded);
            }
            Ok(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options
                .open(path)
                .map_err(|_error| HistoryError::UnsafePath)?;
            file.sync_all().map_err(|_error| HistoryError::UnsafePath)?;
            let metadata = file.metadata().map_err(|_error| HistoryError::UnsafePath)?;
            validate_private_file(&metadata)?;
            Ok(metadata)
        }
        Err(_error) => Err(HistoryError::UnsafePath),
    }
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), HistoryError> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HistoryError::UnsafePath);
    }
    validate_private_owner_mode(metadata)
}

fn validate_private_file(metadata: &fs::Metadata) -> Result<(), HistoryError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HistoryError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(HistoryError::UnsafePath);
        }
    }
    validate_private_owner_mode(metadata)
}

fn validate_private_owner_mode(metadata: &fs::Metadata) -> Result<(), HistoryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(HistoryError::UnsafePath);
        }
    }
    Ok(())
}

fn open_connection(path: &Path) -> Result<Connection, HistoryError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_error| HistoryError::InvalidDatabase)?;
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA trusted_schema = OFF;
             PRAGMA temp_store = MEMORY;
             PRAGMA cache_size = -2048;",
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(HistoryError::InvalidDatabase);
    }
    Ok(connection)
}

fn create_backup(
    source: &Connection,
    destination: &Path,
    retention: Retention,
) -> Result<(), HistoryError> {
    let (file, created_metadata) = prepare_backup_file(destination)?;
    let result = write_backup(source, destination, &file, &created_metadata, retention);
    if result.is_err() {
        drop(file);
        remove_created_backup(destination, &created_metadata);
    }
    result
}

fn prepare_backup_file(destination: &Path) -> Result<(fs::File, fs::Metadata), HistoryError> {
    if !destination.is_absolute() {
        return Err(HistoryError::UnsafePath);
    }
    let parent = destination.parent().ok_or(HistoryError::UnsafePath)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_error| HistoryError::UnsafePath)?;
    validate_private_directory(&parent_metadata)?;
    match fs::symlink_metadata(destination) {
        Ok(_metadata) => return Err(HistoryError::UnsafePath),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_error) => return Err(HistoryError::UnsafePath),
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(destination)
        .map_err(|_error| HistoryError::UnsafePath)?;
    let created_metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_error) => {
            drop(file);
            let _ignored = fs::remove_file(destination);
            return Err(HistoryError::UnsafePath);
        }
    };
    let validation = (|| {
        validate_private_file(&created_metadata)?;
        let path_metadata =
            fs::symlink_metadata(destination).map_err(|_error| HistoryError::UnsafePath)?;
        validate_private_file(&path_metadata)?;
        if !same_file(&created_metadata, &path_metadata) {
            return Err(HistoryError::UnsafePath);
        }
        Ok(())
    })();
    if let Err(error) = validation {
        drop(file);
        remove_created_backup(destination, &created_metadata);
        return Err(error);
    }
    Ok((file, created_metadata))
}

fn write_backup(
    source: &Connection,
    destination: &Path,
    file: &fs::File,
    created_metadata: &fs::Metadata,
    retention: Retention,
) -> Result<(), HistoryError> {
    let mut target = Connection::open_with_flags(
        destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_error| HistoryError::InvalidDatabase)?;
    let opened_metadata =
        fs::symlink_metadata(destination).map_err(|_error| HistoryError::UnsafePath)?;
    validate_private_file(&opened_metadata)?;
    if !same_file(created_metadata, &opened_metadata) {
        return Err(HistoryError::UnsafePath);
    }
    target
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    target
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA trusted_schema = OFF;
             PRAGMA temp_store = MEMORY;",
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let journal_mode: String = target
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(HistoryError::InvalidDatabase);
    }
    {
        let backup = rusqlite::backup::Backup::new(source, &mut target)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        backup
            .run_to_completion(
                SQLITE_BACKUP_PAGES_PER_STEP,
                SQLITE_BACKUP_RETRY_PAUSE,
                None,
            )
            .map_err(|_error| HistoryError::InvalidDatabase)?;
    }
    let version: i64 = target
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    if version != SCHEMA_VERSION {
        return Err(HistoryError::InvalidDatabase);
    }
    verify_integrity(&target)?;
    drop(target);

    file.sync_all()
        .map_err(|_error| HistoryError::WriterUnavailable)?;
    let final_metadata = file
        .metadata()
        .map_err(|_error| HistoryError::WriterUnavailable)?;
    validate_private_file(&final_metadata)?;
    if !same_file(created_metadata, &final_metadata) {
        return Err(HistoryError::UnsafePath);
    }
    let max_bytes =
        u64::try_from(retention.max_bytes).map_err(|_error| HistoryError::LimitExceeded)?;
    if final_metadata.len() > max_bytes.saturating_add(DATABASE_SIZE_OVERHEAD_BYTES) {
        return Err(HistoryError::LimitExceeded);
    }
    let path_metadata =
        fs::symlink_metadata(destination).map_err(|_error| HistoryError::UnsafePath)?;
    validate_private_file(&path_metadata)?;
    if !same_file(created_metadata, &path_metadata) {
        return Err(HistoryError::UnsafePath);
    }
    sync_parent_directory(destination)?;
    Ok(())
}

fn remove_created_backup(destination: &Path, created_metadata: &fs::Metadata) {
    let Ok(path_metadata) = fs::symlink_metadata(destination) else {
        return;
    };
    if validate_private_file(&path_metadata).is_ok() && same_file(created_metadata, &path_metadata)
    {
        let _ignored = fs::remove_file(destination);
    }
}

#[cfg(unix)]
fn sync_parent_directory(destination: &Path) -> Result<(), HistoryError> {
    let parent = destination.parent().ok_or(HistoryError::UnsafePath)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| HistoryError::WriterUnavailable)
}

#[cfg(not(unix))]
fn sync_parent_directory(_destination: &Path) -> Result<(), HistoryError> {
    Ok(())
}

fn migrate(connection: &Connection) -> Result<(), HistoryError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    match version {
        0 => connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE safe_events (
                   sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   event_json TEXT NOT NULL,
                   encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0)
                 ) STRICT;
                 CREATE INDEX safe_events_observed_at ON safe_events(observed_at);
                 CREATE TABLE runs (
                   run_id TEXT PRIMARY KEY CHECK (length(run_id) = 36),
                   profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
                   state TEXT NOT NULL CHECK (state IN (
                     'queued', 'preparing', 'running', 'cancelling', 'cancelled',
                     'passed', 'failed', 'timed_out', 'lost'
                   )),
                   created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
                   started_at TEXT CHECK (started_at IS NULL OR length(started_at) BETWEEN 1 AND 64),
                   finished_at TEXT CHECK (finished_at IS NULL OR length(finished_at) BETWEEN 1 AND 64),
                   profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 64),
                   registry_digest TEXT NOT NULL CHECK (length(registry_digest) = 64),
                   source_revision TEXT NOT NULL CHECK (length(source_revision) BETWEEN 1 AND 128),
                   executable_digest TEXT CHECK (executable_digest IS NULL OR length(executable_digest) = 64),
                   receipt_id TEXT CHECK (receipt_id IS NULL OR length(receipt_id) BETWEEN 1 AND 128),
                   failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
                   supervisor_generation INTEGER NOT NULL DEFAULT 0
                     CHECK (supervisor_generation IN (0, 1))
                 ) STRICT;
                 CREATE INDEX runs_created_at ON runs(created_at DESC, run_id DESC);
                 CREATE INDEX runs_state ON runs(state);
                 CREATE TABLE run_transitions (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                   state TEXT NOT NULL CHECK (state IN (
                     'queued', 'preparing', 'running', 'cancelling', 'cancelled',
                     'passed', 'failed', 'timed_out', 'lost'
                   )),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128)
                 ) STRICT;
                 CREATE INDEX run_transitions_run_sequence ON run_transitions(run_id, sequence);
                 CREATE TABLE run_processes (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   pid INTEGER NOT NULL CHECK (pid BETWEEN 1 AND 2147483647),
                   process_group_id INTEGER NOT NULL CHECK (process_group_id = pid),
                   identity_sha256 TEXT NOT NULL CHECK (length(identity_sha256) = 64),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   settled_at TEXT CHECK (settled_at IS NULL OR length(settled_at) BETWEEN 1 AND 64)
                 ) STRICT;
                 CREATE TABLE run_resource_ledgers (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   output_limit_bytes INTEGER NOT NULL CHECK (output_limit_bytes > 0),
                   evidence_limit_bytes INTEGER NOT NULL CHECK (evidence_limit_bytes > 0),
                   output_bytes INTEGER CHECK (output_bytes IS NULL OR output_bytes >= 0),
                   evidence_bytes INTEGER CHECK (evidence_bytes IS NULL OR evidence_bytes >= 0),
                   accounting_state TEXT NOT NULL CHECK (accounting_state IN (
                     'active', 'settled', 'indeterminate'
                   )),
                   CHECK (
                     (accounting_state = 'active' AND output_bytes IS NULL AND evidence_bytes IS NULL)
                     OR (accounting_state = 'settled' AND output_bytes IS NOT NULL AND evidence_bytes IS NOT NULL)
                     OR accounting_state = 'indeterminate'
                   )
                 ) STRICT;
                 CREATE TABLE evidence_descriptors (
                   evidence_id TEXT PRIMARY KEY CHECK (length(evidence_id) BETWEEN 1 AND 128),
                   run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
                   schema_id TEXT NOT NULL CHECK (length(schema_id) BETWEEN 1 AND 128),
                   category TEXT NOT NULL CHECK (category IN (
                     'sample', 'development', 'candidate-bound', 'installed-artifact',
                     'release-qualifying'
                   )),
                   status TEXT NOT NULL CHECK (status IN ('valid', 'invalid', 'partial')),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 64),
                   source_revision TEXT NOT NULL CHECK (length(source_revision) BETWEEN 1 AND 128),
                   artifact_digest TEXT CHECK (artifact_digest IS NULL OR length(artifact_digest) = 64)
                 ) STRICT;
                 CREATE INDEX evidence_descriptors_run_id ON evidence_descriptors(run_id);
                 CREATE TABLE preferences (
                   preference_key TEXT PRIMARY KEY CHECK (preference_key IN (
                     'theme', 'density', 'motion'
                   )),
                   preference_value TEXT NOT NULL CHECK (preference_value IN (
                     'light', 'dark', 'system', 'comfortable', 'compact', 'standard', 'reduced'
                   )),
                   updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64)
                 ) STRICT;
                 PRAGMA user_version = 4;
                 COMMIT;",
            )
            .map_err(|_error| HistoryError::InvalidDatabase),
        1 => connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE runs (
                   run_id TEXT PRIMARY KEY CHECK (length(run_id) = 36),
                   profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
                   state TEXT NOT NULL CHECK (state IN (
                     'queued', 'preparing', 'running', 'cancelling', 'cancelled',
                     'passed', 'failed', 'timed_out', 'lost'
                   )),
                   created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
                   started_at TEXT CHECK (started_at IS NULL OR length(started_at) BETWEEN 1 AND 64),
                   finished_at TEXT CHECK (finished_at IS NULL OR length(finished_at) BETWEEN 1 AND 64),
                   profile_digest TEXT NOT NULL CHECK (length(profile_digest) = 64),
                   registry_digest TEXT NOT NULL CHECK (length(registry_digest) = 64),
                   source_revision TEXT NOT NULL CHECK (length(source_revision) BETWEEN 1 AND 128),
                   executable_digest TEXT CHECK (executable_digest IS NULL OR length(executable_digest) = 64),
                   receipt_id TEXT CHECK (receipt_id IS NULL OR length(receipt_id) BETWEEN 1 AND 128),
                   failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
                   supervisor_generation INTEGER NOT NULL DEFAULT 0
                     CHECK (supervisor_generation IN (0, 1))
                 ) STRICT;
                 CREATE INDEX runs_created_at ON runs(created_at DESC, run_id DESC);
                 CREATE INDEX runs_state ON runs(state);
                 CREATE TABLE run_transitions (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                   state TEXT NOT NULL CHECK (state IN (
                     'queued', 'preparing', 'running', 'cancelling', 'cancelled',
                     'passed', 'failed', 'timed_out', 'lost'
                   )),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128)
                 ) STRICT;
                 CREATE INDEX run_transitions_run_sequence ON run_transitions(run_id, sequence);
                 CREATE TABLE run_processes (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   pid INTEGER NOT NULL CHECK (pid BETWEEN 1 AND 2147483647),
                   process_group_id INTEGER NOT NULL CHECK (process_group_id = pid),
                   identity_sha256 TEXT NOT NULL CHECK (length(identity_sha256) = 64),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   settled_at TEXT CHECK (settled_at IS NULL OR length(settled_at) BETWEEN 1 AND 64)
                 ) STRICT;
                 CREATE TABLE run_resource_ledgers (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   output_limit_bytes INTEGER NOT NULL CHECK (output_limit_bytes > 0),
                   evidence_limit_bytes INTEGER NOT NULL CHECK (evidence_limit_bytes > 0),
                   output_bytes INTEGER CHECK (output_bytes IS NULL OR output_bytes >= 0),
                   evidence_bytes INTEGER CHECK (evidence_bytes IS NULL OR evidence_bytes >= 0),
                   accounting_state TEXT NOT NULL CHECK (accounting_state IN (
                     'active', 'settled', 'indeterminate'
                   )),
                   CHECK (
                     (accounting_state = 'active' AND output_bytes IS NULL AND evidence_bytes IS NULL)
                     OR (accounting_state = 'settled' AND output_bytes IS NOT NULL AND evidence_bytes IS NOT NULL)
                     OR accounting_state = 'indeterminate'
                   )
                 ) STRICT;
                 CREATE TABLE evidence_descriptors (
                   evidence_id TEXT PRIMARY KEY CHECK (length(evidence_id) BETWEEN 1 AND 128),
                   run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
                   schema_id TEXT NOT NULL CHECK (length(schema_id) BETWEEN 1 AND 128),
                   category TEXT NOT NULL CHECK (category IN (
                     'sample', 'development', 'candidate-bound', 'installed-artifact',
                     'release-qualifying'
                   )),
                   status TEXT NOT NULL CHECK (status IN ('valid', 'invalid', 'partial')),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 64),
                   source_revision TEXT NOT NULL CHECK (length(source_revision) BETWEEN 1 AND 128),
                   artifact_digest TEXT CHECK (artifact_digest IS NULL OR length(artifact_digest) = 64)
                 ) STRICT;
                 CREATE INDEX evidence_descriptors_run_id ON evidence_descriptors(run_id);
                 CREATE TABLE preferences (
                   preference_key TEXT PRIMARY KEY CHECK (preference_key IN (
                     'theme', 'density', 'motion'
                   )),
                   preference_value TEXT NOT NULL CHECK (preference_value IN (
                     'light', 'dark', 'system', 'comfortable', 'compact', 'standard', 'reduced'
                   )),
                   updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64)
                 ) STRICT;
                 PRAGMA user_version = 4;
                 COMMIT;",
            )
            .map_err(|_error| HistoryError::InvalidDatabase),
        2 => connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE runs ADD COLUMN supervisor_generation INTEGER NOT NULL DEFAULT 0
                   CHECK (supervisor_generation IN (0, 1));
                 CREATE TABLE run_processes (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   pid INTEGER NOT NULL CHECK (pid BETWEEN 1 AND 2147483647),
                   process_group_id INTEGER NOT NULL CHECK (process_group_id = pid),
                   identity_sha256 TEXT NOT NULL CHECK (length(identity_sha256) = 64),
                   observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
                   settled_at TEXT CHECK (settled_at IS NULL OR length(settled_at) BETWEEN 1 AND 64)
                 ) STRICT;
                 CREATE TABLE run_resource_ledgers (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   output_limit_bytes INTEGER NOT NULL CHECK (output_limit_bytes > 0),
                   evidence_limit_bytes INTEGER NOT NULL CHECK (evidence_limit_bytes > 0),
                   output_bytes INTEGER CHECK (output_bytes IS NULL OR output_bytes >= 0),
                   evidence_bytes INTEGER CHECK (evidence_bytes IS NULL OR evidence_bytes >= 0),
                   accounting_state TEXT NOT NULL CHECK (accounting_state IN (
                     'active', 'settled', 'indeterminate'
                   )),
                   CHECK (
                     (accounting_state = 'active' AND output_bytes IS NULL AND evidence_bytes IS NULL)
                     OR (accounting_state = 'settled' AND output_bytes IS NOT NULL AND evidence_bytes IS NOT NULL)
                     OR accounting_state = 'indeterminate'
                   )
                 ) STRICT;
                 PRAGMA user_version = 4;
                 COMMIT;",
            )
            .map_err(|_error| HistoryError::InvalidDatabase),
        3 => connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE run_resource_ledgers (
                   run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                   output_limit_bytes INTEGER NOT NULL CHECK (output_limit_bytes > 0),
                   evidence_limit_bytes INTEGER NOT NULL CHECK (evidence_limit_bytes > 0),
                   output_bytes INTEGER CHECK (output_bytes IS NULL OR output_bytes >= 0),
                   evidence_bytes INTEGER CHECK (evidence_bytes IS NULL OR evidence_bytes >= 0),
                   accounting_state TEXT NOT NULL CHECK (accounting_state IN (
                     'active', 'settled', 'indeterminate'
                   )),
                   CHECK (
                     (accounting_state = 'active' AND output_bytes IS NULL AND evidence_bytes IS NULL)
                     OR (accounting_state = 'settled' AND output_bytes IS NOT NULL AND evidence_bytes IS NOT NULL)
                     OR accounting_state = 'indeterminate'
                   )
                 ) STRICT;
                 PRAGMA user_version = 4;
                 COMMIT;",
            )
            .map_err(|_error| HistoryError::InvalidDatabase),
        SCHEMA_VERSION => connection
            .query_row(
                "SELECT safe_events.sequence, runs.run_id, run_transitions.sequence,
                        run_processes.run_id, evidence_descriptors.evidence_id,
                        preferences.preference_key, runs.supervisor_generation,
                        run_resource_ledgers.run_id
                 FROM safe_events, runs, run_transitions, run_processes,
                      evidence_descriptors, preferences, run_resource_ledgers LIMIT 0",
                [],
                |_row| Ok(()),
            )
            .or_else(|error| {
                if error == rusqlite::Error::QueryReturnedNoRows {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_error| HistoryError::InvalidDatabase),
        _ => Err(HistoryError::InvalidDatabase),
    }
}

fn verify_integrity(connection: &Connection) -> Result<(), HistoryError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    if result != "ok" {
        return Err(HistoryError::InvalidDatabase);
    }
    let foreign_key_violation = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    if foreign_key_violation.is_some() {
        return Err(HistoryError::InvalidDatabase);
    }
    Ok(())
}

fn prune_connection(connection: &mut Connection, retention: Retention) -> Result<(), HistoryError> {
    let transaction = connection
        .transaction()
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    prune(&transaction, retention)?;
    prune_runs(&transaction, retention)?;
    transaction
        .commit()
        .map_err(|_error| HistoryError::InvalidDatabase)
}

fn prune(transaction: &Transaction<'_>, retention: Retention) -> Result<(), HistoryError> {
    let cutoff = (OffsetDateTime::now_utc() - time::Duration::days(retention.max_age_days))
        .format(&Rfc3339)
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    transaction
        .execute(
            "DELETE FROM safe_events WHERE observed_at < ?1",
            params![cutoff],
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    transaction
        .execute(
            "DELETE FROM runs
             WHERE finished_at IS NOT NULL AND finished_at < ?1
               AND run_id NOT IN (SELECT run_id FROM evidence_descriptors)",
            params![cutoff],
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    transaction
        .execute(
            "DELETE FROM safe_events
             WHERE sequence NOT IN (
               SELECT sequence FROM safe_events ORDER BY sequence DESC LIMIT ?1
             )",
            params![retention.max_events],
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    loop {
        let (count, bytes): (i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(encoded_bytes), 0) FROM safe_events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        if count <= retention.max_events && bytes <= retention.max_bytes {
            return Ok(());
        }
        let removed = transaction
            .execute(
                "DELETE FROM safe_events
                 WHERE sequence = (SELECT MIN(sequence) FROM safe_events)",
                [],
            )
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        if removed != 1 {
            return Err(HistoryError::InvalidDatabase);
        }
    }
}

fn prune_runs(transaction: &Transaction<'_>, retention: Retention) -> Result<(), HistoryError> {
    let count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let excess = count.saturating_sub(retention.max_runs);
    if excess > 0 {
        transaction
            .execute(
                "DELETE FROM runs
                 WHERE run_id IN (
                   SELECT run_id FROM runs
                   WHERE finished_at IS NOT NULL
                     AND run_id NOT IN (SELECT run_id FROM evidence_descriptors)
                   ORDER BY finished_at ASC, run_id ASC LIMIT ?1
                 )",
                params![excess],
            )
            .map_err(|_error| HistoryError::InvalidDatabase)?;
    }
    let retained: i64 = transaction
        .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    if retained > retention.max_runs {
        return Err(HistoryError::LimitExceeded);
    }
    Ok(())
}

fn load_retained_events(
    connection: &Connection,
    retention: Retention,
) -> Result<Vec<SafeEvent>, HistoryError> {
    let seed_limit = retention
        .max_events
        .min(i64::try_from(MAX_SEED_EVENTS).map_err(|_error| HistoryError::LimitExceeded)?);
    let mut statement = connection
        .prepare(
            "SELECT sequence, event_json, encoded_bytes
             FROM safe_events ORDER BY sequence DESC LIMIT ?1",
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let rows = statement
        .query_map(params![seed_limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let mut reversed = Vec::new();
    let mut total_bytes = 0_usize;
    for row in rows {
        let (sequence, source, declared_bytes) =
            row.map_err(|_error| HistoryError::InvalidDatabase)?;
        let bytes = source.len();
        if bytes == 0
            || bytes > retention.max_event_bytes
            || i64::try_from(bytes).ok() != Some(declared_bytes)
        {
            return Err(HistoryError::InvalidEvent);
        }
        if total_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > MAX_SEED_BYTES)
        {
            break;
        }
        let event = SafeEvent::from_json(&source).map_err(|_error| HistoryError::InvalidEvent)?;
        if i64::try_from(event.sequence()).ok() != Some(sequence) {
            return Err(HistoryError::InvalidEvent);
        }
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or(HistoryError::LimitExceeded)?;
        reversed.push(event);
    }
    reversed.reverse();
    Ok(reversed)
}

fn writer_loop(
    mut connection: Connection,
    receiver: Receiver<WriterMessage>,
    retention: Retention,
) {
    while let Ok(message) = receiver.recv() {
        match message {
            WriterMessage::Record(record) => {
                let result = persist(&mut connection, &record, retention);
                let _ignored = record.acknowledgement.send(result);
            }
            WriterMessage::CreateRun {
                run,
                resources,
                acknowledgement,
            } => {
                let result = create_run(&mut connection, &run, resources, retention);
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::TransitionRun {
                run_id,
                next,
                executable_digest,
                receipt_id,
                failure_code,
                acknowledgement,
            } => {
                let result = transition_run(
                    &mut connection,
                    &run_id,
                    next,
                    TransitionValues {
                        executable_digest: executable_digest.as_deref(),
                        receipt_id: receipt_id.as_deref(),
                        failure_code: failure_code.as_deref(),
                        process: None,
                    },
                    retention,
                );
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::ActivateRun {
                run_id,
                process,
                acknowledgement,
            } => {
                let result = transition_run(
                    &mut connection,
                    &run_id,
                    RunState::Running,
                    TransitionValues {
                        executable_digest: None,
                        receipt_id: None,
                        failure_code: None,
                        process: Some(&process),
                    },
                    retention,
                );
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::CompleteRun {
                run_id,
                next,
                receipt_id,
                failure_code,
                resources,
                descriptors,
                acknowledgement,
            } => {
                let result = complete_run(
                    &mut connection,
                    &run_id,
                    next,
                    receipt_id.as_deref(),
                    failure_code.as_deref(),
                    resources,
                    &descriptors,
                    retention,
                );
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::RecoverableRuns { acknowledgement } => {
                let result = recoverable_runs(&connection);
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::ListRuns {
                limit,
                after,
                acknowledgement,
            } => {
                let result = list_runs_page(&connection, limit, after.as_ref());
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::GetRun {
                run_id,
                acknowledgement,
            } => {
                let result = get_run_with_events(&connection, &run_id, retention);
                let _ignored = acknowledgement.send(result);
            }
            #[cfg(test)]
            WriterMessage::RecordEvidence {
                descriptor,
                acknowledgement,
            } => {
                let result = record_evidence(&mut connection, &descriptor);
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::ListEvidence {
                limit,
                after,
                acknowledgement,
            } => {
                let result = list_evidence_page(&connection, limit, after.as_ref());
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::GetEvidence {
                evidence_id,
                acknowledgement,
            } => {
                let result = get_evidence(&connection, &evidence_id)
                    .and_then(|descriptor| descriptor.ok_or(HistoryError::EvidenceNotFound));
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::Backup {
                destination,
                acknowledgement,
            } => {
                let result = create_backup(&connection, &destination, retention);
                let _ignored = acknowledgement.send(result);
            }
            WriterMessage::Shutdown(acknowledgement) => {
                let _ignored = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                let _ignored = acknowledgement.send(());
                return;
            }
        }
    }
}

fn persist(
    connection: &mut Connection,
    record: &RecordMessage,
    retention: Retention,
) -> Result<(), HistoryError> {
    if record.event_json.len() > retention.max_event_bytes
        || i64::try_from(record.event_json.len()).ok() != Some(record.encoded_bytes)
    {
        return Err(HistoryError::InvalidEvent);
    }
    let transaction = connection.transaction().map_err(map_write_error)?;
    transaction
        .execute(
            "INSERT INTO safe_events(sequence, observed_at, event_json, encoded_bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.sequence,
                record.observed_at,
                record.event_json,
                record.encoded_bytes
            ],
        )
        .map_err(map_write_error)?;
    prune(&transaction, retention)?;
    transaction.commit().map_err(map_write_error)
}

fn create_run(
    connection: &mut Connection,
    run: &RunRecord,
    resources: Option<RunResourceReservation>,
    retention: Retention,
) -> Result<(), HistoryError> {
    run.validate().map_err(|_error| HistoryError::InvalidRun)?;
    if run.state() != RunState::Queued {
        return Err(HistoryError::InvalidRun);
    }
    let transaction = connection.transaction().map_err(map_write_error)?;
    transaction
        .execute(
            "INSERT INTO runs(
               run_id, profile_id, state, created_at, started_at, finished_at,
               profile_digest, registry_digest, source_revision, executable_digest,
               receipt_id, failure_code, supervisor_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                run.run_id(),
                run.profile_id(),
                run.state().as_str(),
                run.created_at(),
                run.started_at(),
                run.finished_at(),
                run.profile_digest(),
                run.registry_digest(),
                run.source_revision(),
                run.executable_digest(),
                run.receipt_id(),
                run.failure_code(),
                SUPERVISOR_GENERATION,
            ],
        )
        .map_err(map_invalid_run_write_error)?;
    if let Some(resources) = resources {
        transaction
            .execute(
                "INSERT INTO run_resource_ledgers(
                   run_id, output_limit_bytes, evidence_limit_bytes, output_bytes,
                   evidence_bytes, accounting_state
                 ) VALUES (?1, ?2, ?3, NULL, NULL, 'active')",
                params![
                    run.run_id(),
                    resources.output_bytes,
                    resources.evidence_bytes,
                ],
            )
            .map_err(map_write_error)?;
    }
    transaction
        .execute(
            "INSERT INTO run_transitions(run_id, state, observed_at, failure_code)
             VALUES (?1, ?2, ?3, NULL)",
            params![run.run_id(), run.state().as_str(), run.created_at()],
        )
        .map_err(map_write_error)?;
    prune_runs(&transaction, retention)?;
    transaction.commit().map_err(map_write_error)
}

struct TransitionValues<'a> {
    executable_digest: Option<&'a str>,
    receipt_id: Option<&'a str>,
    failure_code: Option<&'a str>,
    process: Option<&'a RunProcessIdentity>,
}

fn transition_run(
    connection: &mut Connection,
    run_id: &str,
    next: RunState,
    values: TransitionValues<'_>,
    retention: Retention,
) -> Result<RunRecord, HistoryError> {
    if (next == RunState::Running) != values.process.is_some() {
        return Err(HistoryError::InvalidTransition);
    }
    if let Some(identity) = values.process {
        identity.validate()?;
    }
    let mut run = get_run(connection, run_id)?.ok_or(HistoryError::RunNotFound)?;
    let prior = run.state();
    let supervisor_generation: i64 = connection
        .query_row(
            "SELECT supervisor_generation FROM runs WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let transition_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_error| HistoryError::WriterUnavailable)?;
    run.transition_at(
        next,
        values.executable_digest,
        values.receipt_id,
        values.failure_code,
        &transition_at,
    )
    .map_err(|error| match error {
        crate::RunError::InvalidTransition => HistoryError::InvalidTransition,
        crate::RunError::InvalidRun => HistoryError::InvalidRun,
        crate::RunError::IdentityUnavailable => HistoryError::WriterUnavailable,
    })?;
    let transaction = connection.transaction().map_err(map_write_error)?;
    let updated = transaction
        .execute(
            "UPDATE runs SET
               state = ?1, started_at = ?2, finished_at = ?3, executable_digest = ?4,
               receipt_id = ?5, failure_code = ?6
             WHERE run_id = ?7 AND state = ?8",
            params![
                run.state().as_str(),
                run.started_at(),
                run.finished_at(),
                run.executable_digest(),
                run.receipt_id(),
                run.failure_code(),
                run.run_id(),
                prior.as_str(),
            ],
        )
        .map_err(map_write_error)?;
    if updated != 1 {
        return Err(HistoryError::InvalidTransition);
    }
    if let Some(identity) = values.process {
        let inserted = transaction
            .execute(
                "INSERT INTO run_processes(
                   run_id, pid, process_group_id, identity_sha256, observed_at, settled_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    run.run_id(),
                    identity.pid,
                    identity.process_group_id,
                    identity.identity_sha256,
                    transition_at,
                ],
            )
            .map_err(map_invalid_transition_write_error)?;
        if inserted != 1 {
            return Err(HistoryError::InvalidTransition);
        }
    } else if next.is_terminal() {
        let settled = transaction
            .execute(
                "UPDATE run_processes SET settled_at = ?1
                 WHERE run_id = ?2 AND settled_at IS NULL",
                params![transition_at, run.run_id()],
            )
            .map_err(map_write_error)?;
        if supervisor_generation == SUPERVISOR_GENERATION
            && matches!(prior, RunState::Running | RunState::Cancelling)
            && settled != 1
        {
            return Err(HistoryError::InvalidTransition);
        }
        transaction
            .execute(
                "UPDATE run_resource_ledgers
                 SET accounting_state = 'indeterminate'
                 WHERE run_id = ?1 AND accounting_state = 'active'",
                params![run.run_id()],
            )
            .map_err(map_write_error)?;
    }
    transaction
        .execute(
            "INSERT INTO run_transitions(run_id, state, observed_at, failure_code)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                run.run_id(),
                run.state().as_str(),
                transition_at,
                run.failure_code()
            ],
        )
        .map_err(map_write_error)?;
    prune_runs(&transaction, retention)?;
    transaction.commit().map_err(map_write_error)?;
    Ok(run)
}

#[allow(clippy::too_many_arguments)]
fn complete_run(
    connection: &mut Connection,
    run_id: &str,
    next: RunState,
    receipt_id: Option<&str>,
    failure_code: Option<&str>,
    resources: RunResourceUsage,
    descriptors: &[EvidenceDescriptor],
    retention: Retention,
) -> Result<RunRecord, HistoryError> {
    if !next.is_terminal() || next == RunState::Lost {
        return Err(HistoryError::InvalidTransition);
    }
    for descriptor in descriptors {
        descriptor
            .validate()
            .map_err(|_error| HistoryError::InvalidEvidence)?;
        if descriptor.run_id() != run_id {
            return Err(HistoryError::InvalidEvidence);
        }
    }
    let mut run = get_run(connection, run_id)?.ok_or(HistoryError::RunNotFound)?;
    let prior = run.state();
    if !matches!(prior, RunState::Running | RunState::Cancelling) {
        return Err(HistoryError::InvalidTransition);
    }
    let (output_limit, evidence_limit, accounting_state): (i64, i64, String) = connection
        .query_row(
            "SELECT output_limit_bytes, evidence_limit_bytes, accounting_state
             FROM run_resource_ledgers WHERE run_id = ?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let resource_limit_exceeded =
        resources.output_bytes > output_limit || resources.evidence_bytes > evidence_limit;
    if accounting_state != "active"
        || resource_limit_exceeded && next != RunState::Failed
        || next == RunState::Passed
            && (receipt_id.is_none()
                || descriptors.len() != 2
                || descriptors
                    .iter()
                    .any(|descriptor| descriptor.status() != EvidenceStatus::Valid)
                || descriptors
                    .iter()
                    .filter(|descriptor| {
                        descriptor.schema_id() == "cigar.dashboard-supervisor-receipt.v1"
                    })
                    .count()
                    != 1)
    {
        return Err(HistoryError::InvalidTransition);
    }
    let transition_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_error| HistoryError::WriterUnavailable)?;
    run.transition_at(next, None, receipt_id, failure_code, &transition_at)
        .map_err(|error| match error {
            crate::RunError::InvalidTransition => HistoryError::InvalidTransition,
            crate::RunError::InvalidRun => HistoryError::InvalidRun,
            crate::RunError::IdentityUnavailable => HistoryError::WriterUnavailable,
        })?;

    let transaction = connection.transaction().map_err(map_write_error)?;
    let updated = transaction
        .execute(
            "UPDATE runs SET
               state = ?1, started_at = ?2, finished_at = ?3, executable_digest = ?4,
               receipt_id = ?5, failure_code = ?6
             WHERE run_id = ?7 AND state = ?8",
            params![
                run.state().as_str(),
                run.started_at(),
                run.finished_at(),
                run.executable_digest(),
                run.receipt_id(),
                run.failure_code(),
                run.run_id(),
                prior.as_str(),
            ],
        )
        .map_err(map_write_error)?;
    if updated != 1 {
        return Err(HistoryError::InvalidTransition);
    }
    let settled = transaction
        .execute(
            "UPDATE run_processes SET settled_at = ?1
             WHERE run_id = ?2 AND settled_at IS NULL",
            params![transition_at, run.run_id()],
        )
        .map_err(map_write_error)?;
    if settled != 1 {
        return Err(HistoryError::InvalidTransition);
    }
    let accounted = transaction
        .execute(
            "UPDATE run_resource_ledgers SET
               output_bytes = ?1, evidence_bytes = ?2, accounting_state = 'settled'
             WHERE run_id = ?3 AND accounting_state = 'active'",
            params![
                resources.output_bytes,
                resources.evidence_bytes,
                run.run_id()
            ],
        )
        .map_err(map_write_error)?;
    if accounted != 1 {
        return Err(HistoryError::InvalidTransition);
    }
    transaction
        .execute(
            "INSERT INTO run_transitions(run_id, state, observed_at, failure_code)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                run.run_id(),
                run.state().as_str(),
                transition_at,
                run.failure_code()
            ],
        )
        .map_err(map_write_error)?;
    for descriptor in descriptors {
        insert_evidence_row(&transaction, descriptor)?;
    }
    prune_runs(&transaction, retention)?;
    transaction.commit().map_err(map_write_error)?;
    Ok(run)
}

#[derive(Debug)]
struct StoredRun {
    run_id: String,
    profile_id: String,
    state: String,
    created_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    profile_digest: String,
    registry_digest: String,
    source_revision: String,
    executable_digest: Option<String>,
    receipt_id: Option<String>,
    failure_code: Option<String>,
}

impl StoredRun {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            run_id: row.get(0)?,
            profile_id: row.get(1)?,
            state: row.get(2)?,
            created_at: row.get(3)?,
            started_at: row.get(4)?,
            finished_at: row.get(5)?,
            profile_digest: row.get(6)?,
            registry_digest: row.get(7)?,
            source_revision: row.get(8)?,
            executable_digest: row.get(9)?,
            receipt_id: row.get(10)?,
            failure_code: row.get(11)?,
        })
    }

    fn decode(self) -> Result<RunRecord, HistoryError> {
        RunRecord::from_storage(
            self.run_id,
            self.profile_id,
            self.state,
            self.created_at,
            self.started_at,
            self.finished_at,
            self.profile_digest,
            self.registry_digest,
            self.source_revision,
            self.executable_digest,
            self.receipt_id,
            self.failure_code,
        )
        .map_err(|_error| HistoryError::InvalidRun)
    }
}

const RUN_COLUMNS: &str = "run_id, profile_id, state, created_at, started_at, finished_at, profile_digest, \
     registry_digest, source_revision, executable_digest, receipt_id, failure_code";

fn get_run(connection: &Connection, run_id: &str) -> Result<Option<RunRecord>, HistoryError> {
    if !crate::events::uuid_v7_is_valid(run_id) {
        return Err(HistoryError::InvalidRun);
    }
    let source = format!("SELECT {RUN_COLUMNS} FROM runs WHERE run_id = ?1");
    connection
        .query_row(&source, params![run_id], StoredRun::from_row)
        .optional()
        .map_err(|_error| HistoryError::InvalidDatabase)?
        .map(StoredRun::decode)
        .transpose()
}

fn recoverable_runs(connection: &Connection) -> Result<Vec<RecoverableRun>, HistoryError> {
    let mut statement = connection
        .prepare(
            "SELECT
               r.run_id, r.profile_id, r.state, r.created_at, r.started_at, r.finished_at,
               r.profile_digest, r.registry_digest, r.source_revision, r.executable_digest,
               r.receipt_id, r.failure_code, r.supervisor_generation,
               p.pid, p.process_group_id, p.identity_sha256, p.settled_at,
               l.accounting_state
             FROM runs AS r
             LEFT JOIN run_processes AS p ON p.run_id = r.run_id
             LEFT JOIN run_resource_ledgers AS l ON l.run_id = r.run_id
             WHERE r.state IN ('queued', 'preparing', 'running', 'cancelling')
             ORDER BY r.created_at ASC, r.run_id ASC",
        )
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                StoredRun::from_row(row)?,
                row.get::<_, i64>(12)?,
                row.get::<_, Option<i64>>(13)?,
                row.get::<_, Option<i64>>(14)?,
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
            ))
        })
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let mut recoverable = Vec::new();
    for row in rows {
        let (stored, generation, pid, process_group_id, identity_sha256, settled_at, accounting) =
            row.map_err(|_error| HistoryError::InvalidDatabase)?;
        if !matches!(generation, 0 | SUPERVISOR_GENERATION) || settled_at.is_some() {
            return Err(HistoryError::InvalidDatabase);
        }
        let process = match (pid, process_group_id, identity_sha256) {
            (None, None, None) => None,
            (Some(pid), Some(process_group_id), Some(identity_sha256)) => {
                let identity = RunProcessIdentity {
                    pid,
                    process_group_id,
                    identity_sha256,
                };
                identity.validate()?;
                Some(identity)
            }
            _ => return Err(HistoryError::InvalidDatabase),
        };
        let run = stored.decode()?;
        let valid_identity_shape = matches!(
            (generation, run.state(), process.is_some()),
            (0, _, false)
                | (
                    SUPERVISOR_GENERATION,
                    RunState::Queued | RunState::Preparing,
                    false
                )
                | (
                    SUPERVISOR_GENERATION,
                    RunState::Running | RunState::Cancelling,
                    true
                )
        );
        if !valid_identity_shape {
            return Err(HistoryError::InvalidDatabase);
        }
        let resources_reserved = match accounting.as_deref() {
            Some("active") => true,
            None => false,
            Some(_) => return Err(HistoryError::InvalidDatabase),
        };
        recoverable.push(RecoverableRun {
            run,
            supervisor_generation: generation,
            process,
            resources_reserved,
        });
    }
    Ok(recoverable)
}

fn list_runs_page(
    connection: &Connection,
    limit: usize,
    after: Option<&PagePosition>,
) -> Result<RunHistoryPage, HistoryError> {
    if !(1..=100).contains(&limit) {
        return Err(HistoryError::LimitExceeded);
    }
    let fetch_limit = limit.checked_add(1).ok_or(HistoryError::LimitExceeded)?;
    let fetch_limit = i64::try_from(fetch_limit).map_err(|_error| HistoryError::LimitExceeded)?;
    let mut runs = Vec::new();
    if let Some(position) = after {
        let source = format!(
            "SELECT {RUN_COLUMNS} FROM runs
             WHERE created_at < ?1 OR (created_at = ?1 AND run_id < ?2)
             ORDER BY created_at DESC, run_id DESC LIMIT ?3"
        );
        let mut statement = connection
            .prepare(&source)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        let rows = statement
            .query_map(
                params![position.sort_at(), position.id(), fetch_limit],
                StoredRun::from_row,
            )
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        for row in rows {
            runs.push(
                row.map_err(|_error| HistoryError::InvalidDatabase)?
                    .decode()?,
            );
        }
    } else {
        let source = format!(
            "SELECT {RUN_COLUMNS} FROM runs ORDER BY created_at DESC, run_id DESC LIMIT ?1"
        );
        let mut statement = connection
            .prepare(&source)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        let rows = statement
            .query_map(params![fetch_limit], StoredRun::from_row)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        for row in rows {
            runs.push(
                row.map_err(|_error| HistoryError::InvalidDatabase)?
                    .decode()?,
            );
        }
    }
    let has_more = runs.len() > limit;
    if has_more {
        let _discarded = runs.pop();
    }
    let next = if has_more {
        runs.last()
            .map(|run| PagePosition::new(CursorKind::Runs, run.created_at(), run.run_id()))
            .transpose()
            .map_err(|_error| HistoryError::InvalidRun)?
    } else {
        None
    };
    Ok(RunHistoryPage {
        records: runs,
        next,
    })
}

fn get_run_with_events(
    connection: &Connection,
    run_id: &str,
    retention: Retention,
) -> Result<RunRecord, HistoryError> {
    let mut run = get_run(connection, run_id)?.ok_or(HistoryError::RunNotFound)?;
    let mut statement = connection
        .prepare("SELECT event_json FROM safe_events ORDER BY sequence ASC")
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_error| HistoryError::InvalidDatabase)?;
    let mut events = Vec::new();
    for row in rows {
        let source = row.map_err(|_error| HistoryError::InvalidDatabase)?;
        if source.len() > retention.max_event_bytes {
            return Err(HistoryError::InvalidEvent);
        }
        let event = SafeEvent::from_json(&source).map_err(|_error| HistoryError::InvalidEvent)?;
        if event.run_id() == Some(run_id) {
            events.push(event);
        }
    }
    run.attach_events(events);
    run.validate().map_err(|_error| HistoryError::InvalidRun)?;
    Ok(run)
}

#[cfg(test)]
fn record_evidence(
    connection: &mut Connection,
    descriptor: &EvidenceDescriptor,
) -> Result<(), HistoryError> {
    descriptor
        .validate()
        .map_err(|_error| HistoryError::InvalidEvidence)?;
    let run = get_run(connection, descriptor.run_id())?.ok_or(HistoryError::InvalidEvidence)?;
    if !run.state().is_terminal() {
        return Err(HistoryError::InvalidEvidence);
    }
    let transaction = connection.transaction().map_err(map_write_error)?;
    insert_evidence_row(&transaction, descriptor)?;
    transaction.commit().map_err(map_write_error)
}

fn insert_evidence_row(
    transaction: &Transaction<'_>,
    descriptor: &EvidenceDescriptor,
) -> Result<(), HistoryError> {
    transaction
        .execute(
            "INSERT INTO evidence_descriptors(
               evidence_id, run_id, schema_id, category, status, observed_at,
               receipt_digest, source_revision, artifact_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                descriptor.evidence_id(),
                descriptor.run_id(),
                descriptor.schema_id(),
                descriptor.category().as_str(),
                descriptor.status().as_str(),
                descriptor.observed_at(),
                descriptor.receipt_digest(),
                descriptor.source_revision(),
                descriptor.artifact_digest(),
            ],
        )
        .map_err(map_invalid_evidence_write_error)?;
    Ok(())
}

#[derive(Debug)]
struct StoredEvidence {
    evidence_id: String,
    run_id: String,
    schema_id: String,
    category: String,
    status: String,
    observed_at: String,
    receipt_digest: String,
    source_revision: String,
    artifact_digest: Option<String>,
}

impl StoredEvidence {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            evidence_id: row.get(0)?,
            run_id: row.get(1)?,
            schema_id: row.get(2)?,
            category: row.get(3)?,
            status: row.get(4)?,
            observed_at: row.get(5)?,
            receipt_digest: row.get(6)?,
            source_revision: row.get(7)?,
            artifact_digest: row.get(8)?,
        })
    }

    fn decode(self) -> Result<EvidenceDescriptor, HistoryError> {
        EvidenceDescriptor::from_storage(
            self.evidence_id,
            self.run_id,
            self.schema_id,
            self.category,
            self.status,
            self.observed_at,
            self.receipt_digest,
            self.source_revision,
            self.artifact_digest,
        )
        .map_err(|_error| HistoryError::InvalidEvidence)
    }
}

const EVIDENCE_COLUMNS: &str = "evidence_id, run_id, schema_id, category, status, observed_at, receipt_digest, \
     source_revision, artifact_digest";

fn get_evidence(
    connection: &Connection,
    evidence_id: &str,
) -> Result<Option<EvidenceDescriptor>, HistoryError> {
    if !crate::events::bounded_identifier(evidence_id) || !evidence_id.starts_with("evidence-") {
        return Err(HistoryError::InvalidEvidence);
    }
    let source =
        format!("SELECT {EVIDENCE_COLUMNS} FROM evidence_descriptors WHERE evidence_id = ?1");
    connection
        .query_row(&source, params![evidence_id], StoredEvidence::from_row)
        .optional()
        .map_err(|_error| HistoryError::InvalidDatabase)?
        .map(StoredEvidence::decode)
        .transpose()
}

fn list_evidence_page(
    connection: &Connection,
    limit: usize,
    after: Option<&PagePosition>,
) -> Result<EvidenceHistoryPage, HistoryError> {
    if !(1..=100).contains(&limit) {
        return Err(HistoryError::LimitExceeded);
    }
    let fetch_limit = limit.checked_add(1).ok_or(HistoryError::LimitExceeded)?;
    let fetch_limit = i64::try_from(fetch_limit).map_err(|_error| HistoryError::LimitExceeded)?;
    let mut descriptors = Vec::new();
    if let Some(position) = after {
        let source = format!(
            "SELECT {EVIDENCE_COLUMNS} FROM evidence_descriptors
             WHERE observed_at < ?1 OR (observed_at = ?1 AND evidence_id < ?2)
             ORDER BY observed_at DESC, evidence_id DESC LIMIT ?3"
        );
        let mut statement = connection
            .prepare(&source)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        let rows = statement
            .query_map(
                params![position.sort_at(), position.id(), fetch_limit],
                StoredEvidence::from_row,
            )
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        for row in rows {
            descriptors.push(
                row.map_err(|_error| HistoryError::InvalidDatabase)?
                    .decode()?,
            );
        }
    } else {
        let source = format!(
            "SELECT {EVIDENCE_COLUMNS} FROM evidence_descriptors
             ORDER BY observed_at DESC, evidence_id DESC LIMIT ?1"
        );
        let mut statement = connection
            .prepare(&source)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        let rows = statement
            .query_map(params![fetch_limit], StoredEvidence::from_row)
            .map_err(|_error| HistoryError::InvalidDatabase)?;
        for row in rows {
            descriptors.push(
                row.map_err(|_error| HistoryError::InvalidDatabase)?
                    .decode()?,
            );
        }
    }
    let has_more = descriptors.len() > limit;
    if has_more {
        let _discarded = descriptors.pop();
    }
    let next = if has_more {
        descriptors
            .last()
            .map(|descriptor| {
                PagePosition::new(
                    CursorKind::Evidence,
                    descriptor.observed_at(),
                    descriptor.evidence_id(),
                )
            })
            .transpose()
            .map_err(|_error| HistoryError::InvalidEvidence)?
    } else {
        None
    };
    Ok(EvidenceHistoryPage {
        records: descriptors,
        next,
    })
}

fn map_history_event_error(error: HistoryError) -> EventError {
    match error {
        HistoryError::InvalidEvent
        | HistoryError::InvalidRun
        | HistoryError::RunNotFound
        | HistoryError::InvalidTransition
        | HistoryError::InvalidEvidence
        | HistoryError::EvidenceNotFound
        | HistoryError::InvalidDatabase
        | HistoryError::UnsafePath => EventError::StoreUnavailable,
        HistoryError::LimitExceeded => EventError::LimitExceeded,
        HistoryError::DiskFull | HistoryError::WriterUnavailable => EventError::StoreUnavailable,
    }
}

fn map_write_error(error: rusqlite::Error) -> HistoryError {
    match &error {
        rusqlite::Error::SqliteFailure(failure, _message)
            if failure.code == rusqlite::ErrorCode::DiskFull =>
        {
            HistoryError::DiskFull
        }
        _ => HistoryError::WriterUnavailable,
    }
}

fn map_invalid_run_write_error(error: rusqlite::Error) -> HistoryError {
    if map_write_error(error) == HistoryError::DiskFull {
        HistoryError::DiskFull
    } else {
        HistoryError::InvalidRun
    }
}

fn map_invalid_transition_write_error(error: rusqlite::Error) -> HistoryError {
    if map_write_error(error) == HistoryError::DiskFull {
        HistoryError::DiskFull
    } else {
        HistoryError::InvalidTransition
    }
}

fn map_invalid_evidence_write_error(error: rusqlite::Error) -> HistoryError {
    if map_write_error(error) == HistoryError::DiskFull {
        HistoryError::DiskFull
    } else {
        HistoryError::InvalidEvidence
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HistoryClient, HistoryError, HistoryStore, RunProcessIdentity, RunResourceReservation,
        RunResourceUsage, map_write_error,
    };
    use crate::{
        DashboardHistoryConfig, EvidenceCategory, EvidenceDescriptor, EvidenceStatus, RunRecord,
        RunState, SafeEventAttribute, SafeEventAttributes, SafeEventBroker, SafeEventKind,
    };
    use std::fs;

    fn config(path: std::path::PathBuf, max_events: usize) -> DashboardHistoryConfig {
        DashboardHistoryConfig {
            database_file: path,
            max_runs: 10,
            max_events_per_run: max_events,
            max_age_days: 30,
            max_bytes: 1024 * 1024,
        }
    }

    fn publish(broker: &SafeEventBroker, value: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut attributes = SafeEventAttributes::new();
        attributes.insert("value".to_owned(), SafeEventAttribute::Unsigned(value));
        broker.publish(SafeEventKind::Status, "status.observed", None, attributes)?;
        Ok(())
    }

    fn pass_run(client: &HistoryClient, run_id: &str, digest: &str) -> Result<(), HistoryError> {
        client.transition_run(run_id, RunState::Preparing, Some(digest), None, None)?;
        client.activate_run(run_id, process_identity()?)?;
        client.transition_run(run_id, RunState::Passed, None, Some("receipt-1"), None)?;
        Ok(())
    }

    fn process_identity() -> Result<RunProcessIdentity, HistoryError> {
        RunProcessIdentity::new(
            42_424,
            42_424,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned(),
        )
    }

    #[test]
    fn sqlite_disk_full_has_a_stable_fail_closed_category() {
        let error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert_eq!(map_write_error(error), HistoryError::DiskFull);
    }

    #[test]
    fn terminal_run_resource_and_evidence_commit_is_atomic()
    -> Result<(), Box<dyn std::error::Error>> {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let store = HistoryStore::open(&config(path.clone(), 10), 4096)?;
        let client = store.client();
        let run = RunRecord::queued("dashboard-contracts", DIGEST, DIGEST, "revision-1")?;
        let run_id = run.run_id().to_owned();
        client.create_run_with_resources(run, RunResourceReservation::new(100, 200)?)?;
        client.transition_run(&run_id, RunState::Preparing, Some(DIGEST), None, None)?;
        client.activate_run(&run_id, process_identity()?)?;
        let product = EvidenceDescriptor::verified(
            &run_id,
            "cigar.dashboard-schema-check.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            DIGEST,
            "revision-1",
            None,
        )?;
        let supervisor = EvidenceDescriptor::verified(
            &run_id,
            "cigar.dashboard-supervisor-receipt.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            DIGEST,
            "revision-1",
            None,
        )?;
        assert_eq!(
            client
                .complete_run(
                    &run_id,
                    RunState::Passed,
                    Some("receipt-forged"),
                    None,
                    RunResourceUsage::new(75, 150)?,
                    vec![supervisor.clone(), supervisor.clone()],
                )
                .err(),
            Some(HistoryError::InvalidTransition)
        );
        assert_eq!(client.get_run(&run_id)?.state(), RunState::Running);
        client.complete_run(
            &run_id,
            RunState::Passed,
            Some("receipt-product"),
            None,
            RunResourceUsage::new(75, 150)?,
            vec![product, supervisor],
        )?;
        let connection = rusqlite::Connection::open(&path)?;
        let ledger: (i64, i64, i64, i64, String) = connection.query_row(
            "SELECT output_limit_bytes, evidence_limit_bytes, output_bytes,
                    evidence_bytes, accounting_state
             FROM run_resource_ledgers WHERE run_id = ?1",
            [&run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        assert_eq!(ledger, (100, 200, 75, 150, "settled".to_owned()));
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM evidence_descriptors WHERE run_id = ?1",
                [&run_id],
                |row| row.get::<_, i64>(0),
            )?,
            2
        );
        assert!(connection.query_row(
            "SELECT settled_at IS NOT NULL FROM run_processes WHERE run_id = ?1",
            [&run_id],
            |row| row.get::<_, bool>(0),
        )?);

        let rejected = RunRecord::queued("dashboard-contracts", DIGEST, DIGEST, "revision-2")?;
        let rejected_id = rejected.run_id().to_owned();
        client.create_run_with_resources(rejected, RunResourceReservation::new(10, 10)?)?;
        client.transition_run(&rejected_id, RunState::Preparing, Some(DIGEST), None, None)?;
        client.activate_run(&rejected_id, process_identity()?)?;
        assert_eq!(
            client
                .complete_run(
                    &rejected_id,
                    RunState::Passed,
                    Some("receipt-forged"),
                    None,
                    RunResourceUsage::new(11, 10)?,
                    Vec::new(),
                )
                .err(),
            Some(HistoryError::InvalidTransition)
        );
        assert_eq!(client.get_run(&rejected_id)?.state(), RunState::Running);
        client.complete_run(
            &rejected_id,
            RunState::Failed,
            None,
            Some("run.output_limit"),
            RunResourceUsage::new(11, 10)?,
            Vec::new(),
        )?;
        store.shutdown()?;
        Ok(())
    }

    #[test]
    fn version_three_adds_empty_resource_ledger_without_inventing_usage()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let store = HistoryStore::open(&config(path.clone(), 10), 4096)?;
        store.shutdown()?;
        drop(store);
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE run_resource_ledgers;
             PRAGMA user_version = 3;",
        )?;
        drop(connection);
        let migrated = HistoryStore::open(&config(path.clone(), 10), 4096)?;
        migrated.shutdown()?;
        let connection = rusqlite::Connection::open(path)?;
        assert_eq!(
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
            4
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM run_resource_ledgers", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        Ok(())
    }

    #[test]
    fn committed_events_reload_in_order_and_retention_is_enforced()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let config = config(directory.path().join("history.sqlite3"), 2);
        let store = HistoryStore::open(&config, 4096)?;
        let broker = SafeEventBroker::new_seeded(2, config.max_bytes, 4096, 2, Vec::new())?;
        broker.attach_sink(store.sink())?;
        publish(&broker, 1)?;
        publish(&broker, 2)?;
        publish(&broker, 3)?;
        drop(broker);
        store.shutdown()?;
        drop(store);

        let reopened = HistoryStore::open(&config, 4096)?;
        let retained = reopened.retained_events();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained.first().map(|event| event.sequence()), Some(2));
        assert_eq!(retained.last().map(|event| event.sequence()), Some(3));
        reopened.shutdown()?;
        Ok(())
    }

    #[test]
    fn event_byte_retention_is_durable_and_never_exceeds_the_configured_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let mut retention_config = config(path.clone(), 100);
        retention_config.max_bytes = 512;
        let store = HistoryStore::open(&retention_config, 4096)?;
        let broker = SafeEventBroker::new_seeded(100, 512, 4096, 2, Vec::new())?;
        broker.attach_sink(store.sink())?;
        for value in 1..=20 {
            publish(&broker, value)?;
        }
        drop(broker);
        store.shutdown()?;
        drop(store);

        let connection = rusqlite::Connection::open(&path)?;
        let (count, bytes): (i64, i64) = connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(encoded_bytes), 0) FROM safe_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert!(count > 0 && count < 20);
        assert!(bytes > 0 && bytes <= 512);
        drop(connection);

        let reopened = HistoryStore::open(&retention_config, 4096)?;
        assert_eq!(i64::try_from(reopened.retained_events().len())?, count);
        reopened.shutdown()?;
        Ok(())
    }

    #[test]
    fn age_retention_prunes_unreferenced_terminal_runs_but_keeps_evidence_links()
    -> Result<(), Box<dyn std::error::Error>> {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let mut retention_config = config(path.clone(), 10);
        retention_config.max_age_days = 1;
        let store = HistoryStore::open(&retention_config, 4096)?;
        let client = store.client();

        let retained = RunRecord::queued("dashboard-contracts", DIGEST, DIGEST, "revision-1")?;
        let retained_id = retained.run_id().to_owned();
        client.create_run(retained)?;
        pass_run(&client, &retained_id, DIGEST)?;
        client.record_evidence(EvidenceDescriptor::verified(
            &retained_id,
            "cigar.dashboard-schema-check.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            DIGEST,
            "revision-1",
            None,
        )?)?;

        let expired = RunRecord::queued("dashboard-contracts", DIGEST, DIGEST, "revision-1")?;
        let expired_id = expired.run_id().to_owned();
        client.create_run(expired)?;
        pass_run(&client, &expired_id, DIGEST)?;
        store.shutdown()?;
        drop(store);

        let connection = rusqlite::Connection::open(&path)?;
        connection.execute(
            "UPDATE runs SET created_at = '2020-01-01T00:00:00Z',
                    started_at = '2020-01-01T00:00:01Z',
                    finished_at = '2020-01-01T00:00:02Z'
             WHERE run_id IN (?1, ?2)",
            [&retained_id, &expired_id],
        )?;
        drop(connection);

        let reopened = HistoryStore::open(&retention_config, 4096)?;
        assert_eq!(reopened.client().list_runs(10)?.len(), 1);
        assert_eq!(
            reopened.client().get_run(&expired_id).err(),
            Some(HistoryError::RunNotFound)
        );
        assert_eq!(
            reopened.client().get_run(&retained_id)?.state(),
            RunState::Passed
        );
        assert_eq!(reopened.client().list_evidence(10)?.len(), 1);
        reopened.shutdown()?;
        Ok(())
    }

    #[test]
    fn symlink_and_permissive_parent_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let target = directory.path().join("target.sqlite3");
        fs::write(&target, [])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};

            let link = directory.path().join("history.sqlite3");
            symlink(&target, &link)?;
            assert_eq!(
                HistoryStore::open(&config(link, 2), 4096).err(),
                Some(HistoryError::UnsafePath)
            );

            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
            let hard_link = directory.path().join("hard-linked.sqlite3");
            fs::hard_link(&target, &hard_link)?;
            assert_eq!(
                HistoryStore::open(&config(target, 2), 4096).err(),
                Some(HistoryError::UnsafePath)
            );

            let permissive = directory.path().join("permissive");
            fs::create_dir(&permissive)?;
            fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755))?;
            assert_eq!(
                HistoryStore::open(&config(permissive.join("history.sqlite3"), 2), 4096).err(),
                Some(HistoryError::UnsafePath)
            );
        }
        Ok(())
    }

    #[test]
    fn unknown_migration_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch("PRAGMA user_version = 99;")?;
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            HistoryStore::open(&config(path, 2), 4096).err(),
            Some(HistoryError::InvalidDatabase)
        );
        Ok(())
    }

    #[test]
    fn corruption_and_foreign_key_damage_fail_startup() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let corrupt_path = directory.path().join("corrupt.sqlite3");
        fs::write(&corrupt_path, b"not a sqlite database")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            HistoryStore::open(&config(corrupt_path, 2), 4096).err(),
            Some(HistoryError::InvalidDatabase)
        );

        let damaged_path = directory.path().join("damaged.sqlite3");
        let store = HistoryStore::open(&config(damaged_path.clone(), 2), 4096)?;
        store.shutdown()?;
        drop(store);
        let connection = rusqlite::Connection::open(&damaged_path)?;
        connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
        connection.execute(
            "INSERT INTO run_transitions(run_id, state, observed_at, failure_code)
             VALUES (?1, 'queued', '2026-07-13T12:00:00Z', NULL)",
            ["01980c69-9d00-7000-8000-000000000001"],
        )?;
        drop(connection);
        assert_eq!(
            HistoryStore::open(&config(damaged_path, 2), 4096).err(),
            Some(HistoryError::InvalidDatabase)
        );
        Ok(())
    }

    #[test]
    fn online_backup_is_private_consistent_and_reopenable() -> Result<(), Box<dyn std::error::Error>>
    {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let source_path = directory.path().join("history.sqlite3");
        let backup_path = directory.path().join("history-backup.sqlite3");
        let source_config = config(source_path, 10);
        let store = HistoryStore::open(&source_config, 4096)?;
        let client = store.client();

        let run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        let run_id = run.run_id().to_owned();
        client.create_run(run)?;
        pass_run(&client, &run_id, DIGEST)?;
        let descriptor = EvidenceDescriptor::verified(
            &run_id,
            "cigar.soak-result.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            DIGEST,
            "revision-1",
            Some(DIGEST),
        )?;
        let evidence_id = descriptor.evidence_id().to_owned();
        client.record_evidence(descriptor)?;

        let broker = SafeEventBroker::new_seeded(10, source_config.max_bytes, 4096, 2, Vec::new())?;
        broker.attach_sink(store.sink())?;
        publish(&broker, 1)?;
        client.backup_to(&backup_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let metadata = fs::symlink_metadata(&backup_path)?;
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert!(!directory.path().join("history-backup.sqlite3-wal").exists());
        assert!(!directory.path().join("history-backup.sqlite3-shm").exists());

        let later = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-later")?;
        client.create_run(later)?;
        drop(broker);
        store.shutdown()?;
        drop(store);

        let backup_config = config(backup_path, 10);
        let reopened = HistoryStore::open(&backup_config, 4096)?;
        assert_eq!(reopened.retained_events().len(), 1);
        assert_eq!(reopened.client().list_runs(10)?.len(), 1);
        assert_eq!(
            reopened.client().get_run(&run_id)?.state(),
            RunState::Passed
        );
        assert_eq!(
            reopened.client().get_evidence(&evidence_id)?.status(),
            EvidenceStatus::Valid
        );
        reopened.shutdown()?;
        Ok(())
    }

    #[test]
    fn backup_rejects_existing_relative_and_unsafe_destinations()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let store =
            HistoryStore::open(&config(directory.path().join("history.sqlite3"), 10), 4096)?;
        let client = store.client();

        let existing = directory.path().join("existing.sqlite3");
        fs::write(&existing, b"keep-me")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&existing, fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            client.backup_to(&existing).err(),
            Some(HistoryError::UnsafePath)
        );
        assert_eq!(fs::read(&existing)?, b"keep-me");
        assert_eq!(
            client
                .backup_to(std::path::Path::new("relative.sqlite3"))
                .err(),
            Some(HistoryError::UnsafePath)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};

            let link = directory.path().join("linked-backup.sqlite3");
            symlink(&existing, &link)?;
            assert_eq!(
                client.backup_to(&link).err(),
                Some(HistoryError::UnsafePath)
            );
            assert_eq!(fs::read(&existing)?, b"keep-me");

            let permissive = directory.path().join("permissive-backups");
            fs::create_dir(&permissive)?;
            fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755))?;
            let rejected = permissive.join("backup.sqlite3");
            assert_eq!(
                client.backup_to(&rejected).err(),
                Some(HistoryError::UnsafePath)
            );
            assert!(!rejected.exists());
        }

        store.shutdown()?;
        Ok(())
    }

    #[test]
    fn run_records_transition_persist_and_reload_with_safe_events()
    -> Result<(), Box<dyn std::error::Error>> {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let config = config(directory.path().join("history.sqlite3"), 10);
        let store = HistoryStore::open(&config, 4096)?;
        let client = store.client();
        let run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        let run_id = run.run_id().to_owned();
        client.create_run(run)?;
        assert_eq!(client.list_runs(10)?.len(), 1);
        assert_eq!(
            client
                .transition_run(&run_id, RunState::Running, Some(DIGEST), None, None)
                .err(),
            Some(HistoryError::InvalidTransition)
        );
        assert_eq!(client.get_run(&run_id)?.state(), RunState::Queued);
        client.transition_run(&run_id, RunState::Preparing, Some(DIGEST), None, None)?;
        client.activate_run(&run_id, process_identity()?)?;

        let premature = EvidenceDescriptor::verified(
            &run_id,
            "cigar.soak-result.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Partial,
            DIGEST,
            "revision-1",
            None,
        )?;
        assert_eq!(
            client.record_evidence(premature).err(),
            Some(HistoryError::InvalidEvidence)
        );

        let broker = SafeEventBroker::new_seeded(10, config.max_bytes, 4096, 2, Vec::new())?;
        broker.attach_sink(store.sink())?;
        let mut attributes = SafeEventAttributes::new();
        attributes.insert(
            "phase".to_owned(),
            SafeEventAttribute::Text("verify".to_owned()),
        );
        broker.publish(SafeEventKind::Run, "run.phase", Some(&run_id), attributes)?;
        client.transition_run(
            &run_id,
            RunState::Failed,
            None,
            Some("receipt-1"),
            Some("threshold-failed"),
        )?;
        let descriptor = EvidenceDescriptor::verified(
            &run_id,
            "cigar.soak-result.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Invalid,
            DIGEST,
            "revision-1",
            Some(DIGEST),
        )?;
        let evidence_id = descriptor.evidence_id().to_owned();
        client.record_evidence(descriptor)?;
        assert_eq!(client.list_evidence(10)?.len(), 1);
        assert_eq!(client.get_evidence(&evidence_id)?.run_id(), run_id);
        let detail = client.get_run(&run_id)?;
        assert_eq!(detail.state(), RunState::Failed);
        assert_eq!(
            serde_json::to_value(detail)?
                .get("events")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        drop(broker);
        store.shutdown()?;
        drop(store);

        let reopened = HistoryStore::open(&config, 4096)?;
        assert_eq!(
            reopened.client().get_run(&run_id)?.state(),
            RunState::Failed
        );
        assert_eq!(
            reopened.client().get_evidence(&evidence_id)?.status(),
            EvidenceStatus::Invalid
        );
        reopened.shutdown()?;
        Ok(())
    }

    #[test]
    fn version_one_event_journal_migrates_append_only() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE safe_events (
               sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
               observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
               event_json TEXT NOT NULL,
               encoded_bytes INTEGER NOT NULL CHECK (encoded_bytes > 0)
             ) STRICT;
             CREATE INDEX safe_events_observed_at ON safe_events(observed_at);
             PRAGMA user_version = 1;",
        )?;
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        let store = HistoryStore::open(&config(path.clone(), 2), 4096)?;
        assert!(store.client().list_runs(10)?.is_empty());
        store.shutdown()?;
        drop(store);
        let connection = rusqlite::Connection::open(path)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(version, 4);
        Ok(())
    }

    #[test]
    fn version_two_runs_migrate_as_explicit_legacy_supervisor_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        const RUN_ID: &str = "01980c69-9d00-7000-8000-000000000001";
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE runs (
               run_id TEXT PRIMARY KEY,
               profile_id TEXT NOT NULL,
               state TEXT NOT NULL,
               created_at TEXT NOT NULL,
               started_at TEXT,
               finished_at TEXT,
               profile_digest TEXT NOT NULL,
               registry_digest TEXT NOT NULL,
               source_revision TEXT NOT NULL,
               executable_digest TEXT,
               receipt_id TEXT,
               failure_code TEXT
             ) STRICT;
             INSERT INTO runs(
               run_id, profile_id, state, created_at, started_at, finished_at,
               profile_digest, registry_digest, source_revision, executable_digest,
               receipt_id, failure_code
             ) VALUES (
               '01980c69-9d00-7000-8000-000000000001', 'soak-smoke', 'queued',
               '2026-07-13T12:00:00Z', NULL, NULL,
               '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
               '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
               'revision-1', NULL, NULL, NULL
             );
             PRAGMA user_version = 2;",
        )?;

        super::migrate(&connection)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(version, 4);
        let generation: i64 = connection.query_row(
            "SELECT supervisor_generation FROM runs WHERE run_id = ?1",
            [RUN_ID],
            |row| row.get(0),
        )?;
        assert_eq!(generation, 0);
        let columns: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('run_processes')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(columns, 6);
        let recovered = super::recoverable_runs(&connection)?;
        assert_eq!(recovered.len(), 1);
        let recovered = recovered.first().ok_or(HistoryError::InvalidRun)?;
        assert_eq!(recovered.run().run_id(), RUN_ID);
        assert_eq!(recovered.supervisor_generation(), 0);
        assert!(recovered.process().is_none());
        assert_eq!(recovered.run().profile_digest(), DIGEST);
        Ok(())
    }

    #[test]
    fn active_process_identity_is_atomic_reloadable_and_settled()
    -> Result<(), Box<dyn std::error::Error>> {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let config = config(path.clone(), 10);
        let store = HistoryStore::open(&config, 4096)?;
        let client = store.client();
        let run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        let run_id = run.run_id().to_owned();
        client.create_run(run)?;
        client.transition_run(&run_id, RunState::Preparing, Some(DIGEST), None, None)?;
        assert_eq!(
            client
                .transition_run(&run_id, RunState::Running, None, None, None)
                .err(),
            Some(HistoryError::InvalidTransition)
        );
        client.activate_run(&run_id, process_identity()?)?;
        let active = client.recoverable_runs()?;
        assert_eq!(active.len(), 1);
        let active = active.first().ok_or(HistoryError::InvalidRun)?;
        assert_eq!(active.run().state(), RunState::Running);
        assert_eq!(active.process().map(RunProcessIdentity::pid), Some(42_424));
        assert_eq!(active.supervisor_generation(), 1);
        store.shutdown()?;
        drop(store);

        let reopened = HistoryStore::open(&config, 4096)?;
        let client = reopened.client();
        assert_eq!(client.recoverable_runs()?.len(), 1);
        client.transition_run(
            &run_id,
            RunState::Lost,
            None,
            None,
            Some("run.recovered_without_live_child"),
        )?;
        assert!(client.recoverable_runs()?.is_empty());
        reopened.shutdown()?;
        drop(reopened);

        let connection = rusqlite::Connection::open(path)?;
        let settled: i64 = connection.query_row(
            "SELECT settled_at IS NOT NULL FROM run_processes WHERE run_id = ?1",
            [&run_id],
            |row| row.get(0),
        )?;
        assert_eq!(settled, 1);
        Ok(())
    }

    #[test]
    fn malformed_persisted_process_identity_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let path = directory.path().join("history.sqlite3");
        let config = config(path.clone(), 10);
        let store = HistoryStore::open(&config, 4096)?;
        let client = store.client();
        let run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        let run_id = run.run_id().to_owned();
        client.create_run(run)?;
        client.transition_run(&run_id, RunState::Preparing, Some(DIGEST), None, None)?;
        client.activate_run(&run_id, process_identity()?)?;
        store.shutdown()?;
        drop(store);

        let connection = rusqlite::Connection::open(&path)?;
        connection.execute(
            "UPDATE run_processes SET identity_sha256 = ?1 WHERE run_id = ?2",
            [
                "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
                &run_id,
            ],
        )?;
        drop(connection);
        let reopened = HistoryStore::open(&config, 4096)?;
        assert_eq!(
            reopened.client().recoverable_runs().err(),
            Some(HistoryError::InvalidRun)
        );
        reopened.shutdown()?;
        Ok(())
    }

    #[test]
    fn run_and_evidence_tuple_pagination_has_no_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let config = config(directory.path().join("history.sqlite3"), 10);
        let store = HistoryStore::open(&config, 4096)?;
        let client = store.client();
        let mut run_ids = Vec::new();
        for ordinal in 1..=3 {
            let run =
                RunRecord::queued("soak-smoke", DIGEST, DIGEST, &format!("revision-{ordinal}"))?;
            run_ids.push(run.run_id().to_owned());
            client.create_run(run)?;
        }

        let first_runs = client.list_runs_page(2, None)?;
        assert_eq!(first_runs.records.len(), 2);
        let second_runs = client.list_runs_page(2, first_runs.next.clone())?;
        assert_eq!(second_runs.records.len(), 1);
        assert!(second_runs.next.is_none());
        let returned_runs: std::collections::BTreeSet<_> = first_runs
            .records
            .iter()
            .chain(&second_runs.records)
            .map(|run| run.run_id().to_owned())
            .collect();
        assert_eq!(returned_runs.len(), 3);

        for run_id in &run_ids {
            client.transition_run(run_id, RunState::Preparing, Some(DIGEST), None, None)?;
            client.activate_run(run_id, process_identity()?)?;
            client.transition_run(run_id, RunState::Passed, None, Some("receipt-1"), None)?;
            client.record_evidence(EvidenceDescriptor::verified(
                run_id,
                "cigar.soak-result.v1",
                EvidenceCategory::Development,
                EvidenceStatus::Valid,
                DIGEST,
                "revision-1",
                Some(DIGEST),
            )?)?;
        }
        let first_evidence = client.list_evidence_page(2, None)?;
        assert_eq!(first_evidence.records.len(), 2);
        let second_evidence = client.list_evidence_page(2, first_evidence.next.clone())?;
        assert_eq!(second_evidence.records.len(), 1);
        assert!(second_evidence.next.is_none());
        let returned_evidence: std::collections::BTreeSet<_> = first_evidence
            .records
            .iter()
            .chain(&second_evidence.records)
            .map(|descriptor| descriptor.evidence_id().to_owned())
            .collect();
        assert_eq!(returned_evidence.len(), 3);
        store.shutdown()?;
        Ok(())
    }

    #[test]
    fn run_retention_removes_only_unreferenced_terminal_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir()?;
        restrict_directory(directory.path())?;
        let mut retention_config = config(directory.path().join("history.sqlite3"), 10);
        retention_config.max_runs = 2;
        let store = HistoryStore::open(&retention_config, 4096)?;
        let client = store.client();

        let first = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        let first_id = first.run_id().to_owned();
        client.create_run(first)?;
        pass_run(&client, &first_id, DIGEST)?;
        client.record_evidence(EvidenceDescriptor::verified(
            &first_id,
            "cigar.soak-result.v1",
            EvidenceCategory::Development,
            EvidenceStatus::Valid,
            DIGEST,
            "revision-1",
            None,
        )?)?;

        let second = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-2")?;
        let second_id = second.run_id().to_owned();
        client.create_run(second)?;
        pass_run(&client, &second_id, DIGEST)?;

        let third = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-3")?;
        let third_id = third.run_id().to_owned();
        client.create_run(third)?;
        pass_run(&client, &third_id, DIGEST)?;

        assert_eq!(client.list_runs(10)?.len(), 2);
        assert_eq!(
            client.get_run(&second_id).err(),
            Some(HistoryError::RunNotFound)
        );
        assert_eq!(client.get_run(&first_id)?.state(), RunState::Passed);
        assert_eq!(client.get_run(&third_id)?.state(), RunState::Passed);
        store.shutdown()?;

        let mut active_config = config(directory.path().join("active.sqlite3"), 10);
        active_config.max_runs = 1;
        let active_store = HistoryStore::open(&active_config, 4096)?;
        let active_client = active_store.client();
        active_client.create_run(RunRecord::queued(
            "soak-smoke",
            DIGEST,
            DIGEST,
            "revision-active-1",
        )?)?;
        assert_eq!(
            active_client
                .create_run(RunRecord::queued(
                    "soak-smoke",
                    DIGEST,
                    DIGEST,
                    "revision-active-2",
                )?)
                .err(),
            Some(HistoryError::LimitExceeded)
        );
        assert_eq!(active_client.list_runs(10)?.len(), 1);
        active_store.shutdown()?;
        Ok(())
    }

    fn restrict_directory(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}
