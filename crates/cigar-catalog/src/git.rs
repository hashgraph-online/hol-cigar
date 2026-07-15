//! Immutable Git-commit discovery and object reads without trusting worktree bytes.

use crate::ignore::{IgnorePatterns, IgnoreWorkBudget, MAX_IGNORE_BYTES, path_has_prefix};
use crate::{
    BoundedBytes, ByteRange, CatalogError, CatalogErrorCode, ChangeKind, ChangeWatermark,
    ConnectorContext, DiscoveryDisposition, DiscoveryEntry, DiscoveryPlan, DiscoveryReason,
    DiscoveryRequest, GIT_CONNECTOR_ID, SourceChange, SourceConnector, SourceConnectorDescriptor,
    SourceHealth, SourceHealthState, SourceRecord, SourceSnapshotBatch, scan_secrets_with_patterns,
};
use cigar_protocol::{
    ContentDigest, ExtensionMap, MediaType, RecordId, RelativePath, SourceSnapshot, SourceUri,
    UtcTimestamp,
};
use cigar_store::CancellationToken;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_GIT_OUTPUT_BYTES: usize = 67_108_864;
const MAX_RETAINED_EVENTS: usize = 100_000;
const GIT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Clone, Eq, PartialEq)]
struct GitRecord {
    record: SourceRecord,
    object_id: String,
}

#[derive(Default)]
struct GitState {
    request: Option<DiscoveryRequest>,
    commit: Option<String>,
    records: BTreeMap<String, GitRecord>,
    snapshot: Option<SourceSnapshotBatch>,
    events: VecDeque<SourceChange>,
    watermark: ChangeWatermark,
}

/// Connector exposing one repository's committed Git objects as immutable source records.
pub struct GitConnector {
    root: PathBuf,
    root_uri: SourceUri,
    state: Mutex<GitState>,
}

impl GitConnector {
    /// Opens an exact Git worktree root and rejects nested or escaped roots.
    pub fn new(root: impl AsRef<Path>, root_uri: SourceUri) -> Result<Self, CatalogError> {
        let root = std::fs::canonicalize(root)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        let startup_context = ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + GIT_STARTUP_TIMEOUT,
        );
        let top = run_git(
            &root,
            &["rev-parse", "--show-toplevel"],
            16_384,
            &startup_context,
        )?;
        let top = std::str::from_utf8(trim_line(&top))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
        let top = std::fs::canonicalize(top)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        if top != root {
            return Err(CatalogError::new(CatalogErrorCode::Denied));
        }
        Ok(Self {
            root,
            root_uri,
            state: Mutex::new(GitState::default()),
        })
    }

    /// Refreshes to the current `HEAD` and appends commit-diff change events.
    pub fn refresh(&self, context: &ConnectorContext) -> Result<DiscoveryPlan, CatalogError> {
        let request = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?
            .request
            .clone()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
        let (plan, commit, records) = self.build_plan(&request, context)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        for mut change in compare_git_records(&state.records, &records) {
            state.watermark = ChangeWatermark(
                state
                    .watermark
                    .0
                    .checked_add(1)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
            );
            change.watermark = state.watermark;
            state.events.push_back(change);
            while state.events.len() > MAX_RETAINED_EVENTS {
                let _expired = state.events.pop_front();
            }
        }
        if state.commit.as_ref() != Some(&commit) {
            state.snapshot = None;
        }
        state.commit = Some(commit);
        state.records = records;
        Ok(plan)
    }

    fn build_plan(
        &self,
        request: &DiscoveryRequest,
        context: &ConnectorContext,
    ) -> Result<(DiscoveryPlan, String, BTreeMap<String, GitRecord>), CatalogError> {
        context.check()?;
        request.policy.validate()?;
        if request.root != self.root_uri {
            return Err(CatalogError::new(CatalogErrorCode::Denied));
        }
        let commit = git_head(&self.root, context)?;
        let tree = run_git(
            &self.root,
            &["ls-tree", "-r", "-z", "-l", "--full-tree", &commit],
            MAX_GIT_OUTPUT_BYTES,
            context,
        )?;
        let mut raw = parse_tree(&tree, context)?;
        raw.sort_by(|left, right| left.path.cmp(&right.path));
        crate::connector::validate_source_paths(raw.iter().map(|entry| entry.path.as_slice()))?;
        let ignore_patterns = if let Some(entry) = raw.iter().find(|entry| {
            entry.path == b".cigarignore" && entry.regular_blob() && entry.size.is_some()
        }) {
            let size = entry
                .size
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
            if size > MAX_IGNORE_BYTES {
                return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
            }
            let bytes = read_object(&self.root, &entry.object_id, size, context)?;
            IgnorePatterns::parse(&bytes, context)?
        } else {
            IgnorePatterns::default()
        };
        let mut entries = Vec::with_capacity(raw.len());
        let mut included = BTreeMap::new();
        let mut total_bytes = 0_u64;
        let mut materialized_items = 0_usize;
        let mut materialized_bytes = 0_u64;
        let mut ignore_work = IgnoreWorkBudget::default();
        for entry in raw {
            context.check()?;
            let path = RelativePath::new(entry.path.clone())
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
            let media_type = media_type(&entry.path)?;
            let special = !entry.regular_blob() || secret_path(&entry.path);
            let size_bytes = entry.size.unwrap_or_default();
            let record_id = format!("git:path:{}", digest_bytes(&entry.path));
            let mut record = SourceRecord {
                record_id: record_id.clone(),
                relative_path: path.clone(),
                revision: format!("{}:{}", entry.object_id, entry.mode),
                size_bytes,
                executable: entry.mode == "100755",
                media_type,
                content_digest: None,
            };
            let policy_excluded = request
                .policy
                .excluded_prefixes
                .iter()
                .any(|prefix| path_has_prefix(path.as_bytes(), prefix.as_bytes()));
            let (mut disposition, mut reason) = if special {
                (
                    DiscoveryDisposition::Exclude,
                    DiscoveryReason::HardExclusion,
                )
            } else if policy_excluded {
                (
                    DiscoveryDisposition::Exclude,
                    DiscoveryReason::PolicyExclusion,
                )
            } else if ignore_patterns.matches_git(&entry.path, &mut ignore_work, context)? {
                (DiscoveryDisposition::Exclude, DiscoveryReason::CigarIgnore)
            } else if size_bytes > request.policy.max_record_bytes {
                (DiscoveryDisposition::Exclude, DiscoveryReason::SizeLimit)
            } else if !request
                .policy
                .allowed_media_types
                .contains(&record.media_type)
            {
                (DiscoveryDisposition::Exclude, DiscoveryReason::MediaType)
            } else {
                (DiscoveryDisposition::Include, DiscoveryReason::Eligible)
            };
            if request.include_overrides.contains(&path)
                && request.policy.allow_user_broadening
                && disposition == DiscoveryDisposition::Exclude
                && reason == DiscoveryReason::CigarIgnore
            {
                disposition = DiscoveryDisposition::Include;
                reason = DiscoveryReason::UserOverride;
            }
            if disposition == DiscoveryDisposition::Include {
                let next_work_bytes = materialized_bytes
                    .checked_add(size_bytes)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
                if materialized_items == request.policy.max_items
                    || next_work_bytes > request.policy.max_total_bytes
                {
                    disposition = DiscoveryDisposition::Exclude;
                    reason = DiscoveryReason::SizeLimit;
                } else {
                    materialized_items = materialized_items
                        .checked_add(1)
                        .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
                    materialized_bytes = next_work_bytes;
                    let bytes = read_object(&self.root, &entry.object_id, size_bytes, context)?;
                    record.content_digest = Some(digest(&bytes)?);
                    if scan_secrets_with_patterns(&bytes, &request.policy.secret_patterns)
                        .must_quarantine()
                    {
                        disposition = DiscoveryDisposition::Quarantine;
                        reason = DiscoveryReason::SecretDetected;
                    } else {
                        total_bytes = total_bytes
                            .checked_add(size_bytes)
                            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
                        included.insert(
                            record_id,
                            GitRecord {
                                record: record.clone(),
                                object_id: entry.object_id,
                            },
                        );
                    }
                }
            }
            entries.push(DiscoveryEntry {
                record,
                disposition,
                reason,
            });
        }
        let plan_digest = digest_plan(&commit, &entries)?;
        Ok((
            DiscoveryPlan {
                root: request.root.clone(),
                entries,
                included_count: u64::try_from(included.len())
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
                included_bytes: total_bytes,
                plan_digest,
            },
            commit,
            included,
        ))
    }
}

impl fmt::Debug for GitConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitConnector")
            .finish_non_exhaustive()
    }
}

impl SourceConnector for GitConnector {
    fn descriptor(&self) -> SourceConnectorDescriptor {
        SourceConnectorDescriptor {
            id: GIT_CONNECTOR_ID.to_owned(),
            root: self.root_uri.clone(),
        }
    }

    fn discover(
        &self,
        request: &DiscoveryRequest,
        context: &ConnectorContext,
    ) -> Result<DiscoveryPlan, CatalogError> {
        let (plan, commit, records) = self.build_plan(request, context)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        state.request = Some(request.clone());
        if state.commit.as_ref() != Some(&commit) {
            state.snapshot = None;
        }
        state.commit = Some(commit);
        state.records = records;
        Ok(plan)
    }

    fn snapshot(
        &self,
        previous_revision: Option<&str>,
        context: &ConnectorContext,
    ) -> Result<SourceSnapshotBatch, CatalogError> {
        context.check()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        let commit = state
            .commit
            .clone()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
        if previous_revision == Some(commit.as_str()) {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        if let Some(snapshot) = &state.snapshot {
            return Ok(snapshot.clone());
        }
        let records: Vec<_> = state
            .records
            .values()
            .map(|entry| entry.record.clone())
            .collect();
        let manifest_digest = digest_records(&commit, &records)?;
        let total_bytes = records.iter().try_fold(0_u64, |total, record| {
            total
                .checked_add(record.size_bytes)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))
        })?;
        let snapshot = SourceSnapshot {
            schema_version: "cigar.source-snapshot.v1"
                .parse()
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            snapshot_id: RecordId::new(deterministic_uuid(&[
                b"CIGAR-GIT-SNAPSHOT\0v1\0",
                self.root_uri.as_str().as_bytes(),
                commit.as_bytes(),
                manifest_digest.as_str().as_bytes(),
            ]))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            source_uri: self.root_uri.clone(),
            source_revision: commit,
            captured_at: now_utc()?,
            manifest_digest,
            entry_count: u64::try_from(records.len())
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
            total_bytes,
            complete: true,
            extensions: ExtensionMap::default(),
        };
        let batch = SourceSnapshotBatch { snapshot, records };
        state.snapshot = Some(batch.clone());
        Ok(batch)
    }

    fn read(
        &self,
        record: &SourceRecord,
        range: ByteRange,
        context: &ConnectorContext,
    ) -> Result<BoundedBytes, CatalogError> {
        context.check()?;
        let entry = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?
            .records
            .get(&record.record_id)
            .cloned()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::NotFound))?;
        if entry.record != *record {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let bytes = read_object(&self.root, &entry.object_id, record.size_bytes, context)?;
        if Some(digest(&bytes)?) != record.content_digest {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let start = usize::try_from(range.start)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let length = usize::try_from(range.length)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        BoundedBytes::new(
            bytes
                .get(start..end)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?
                .to_vec(),
        )
    }

    fn subscribe(
        &self,
        watermark: ChangeWatermark,
        limit: usize,
        context: &ConnectorContext,
    ) -> Result<Vec<SourceChange>, CatalogError> {
        context.check()?;
        if limit == 0 || limit > crate::MAX_CONNECTOR_ITEMS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        if state
            .events
            .front()
            .is_some_and(|first| watermark.0.saturating_add(1) < first.watermark.0)
        {
            return Ok(vec![SourceChange {
                watermark: state.watermark,
                kind: ChangeKind::Overflow,
                record: None,
                prior_path: None,
            }]);
        }
        Ok(state
            .events
            .iter()
            .filter(|event| event.watermark > watermark)
            .take(limit)
            .cloned()
            .collect())
    }

    fn health(&self) -> SourceHealth {
        match self.state.lock() {
            Ok(state) => SourceHealth {
                state: SourceHealthState::Ready,
                watermark: state.watermark,
            },
            Err(_error) => SourceHealth {
                state: SourceHealthState::Unavailable,
                watermark: ChangeWatermark::default(),
            },
        }
    }
}

struct TreeEntry {
    mode: String,
    object_type: String,
    object_id: String,
    size: Option<u64>,
    path: Vec<u8>,
}

impl TreeEntry {
    fn regular_blob(&self) -> bool {
        self.object_type == "blob" && matches!(self.mode.as_str(), "100644" | "100755")
    }
}

fn parse_tree(bytes: &[u8], context: &ConnectorContext) -> Result<Vec<TreeEntry>, CatalogError> {
    parse_tree_with_limit(bytes, context, crate::MAX_CONNECTOR_ITEMS)
}

fn parse_tree_with_limit(
    bytes: &[u8],
    context: &ConnectorContext,
    entry_limit: usize,
) -> Result<Vec<TreeEntry>, CatalogError> {
    let mut entries = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        context.check()?;
        if entries.len() == entry_limit {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let metadata = record
            .get(..tab)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let path = record
            .get(tab + 1..)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let mut fields = metadata
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let mode = utf8_field(fields.next())?;
        let object_type = utf8_field(fields.next())?;
        let object_id = utf8_field(fields.next())?;
        let size_field = utf8_field(fields.next())?;
        if fields.next().is_some()
            || !matches!(object_type.as_str(), "blob" | "commit")
            || !valid_object_id(&object_id)
            || path.len() > cigar_protocol::limits::MAX_PATH_BYTES
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        let size = if size_field == "-" {
            None
        } else {
            Some(
                size_field
                    .parse::<u64>()
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            )
        };
        if object_type == "blob" && size.is_none() || object_type == "commit" && size.is_some() {
            return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
        }
        entries.push(TreeEntry {
            mode,
            object_type,
            object_id,
            size,
            path: path.to_vec(),
        });
    }
    Ok(entries)
}

fn utf8_field(field: Option<&[u8]>) -> Result<String, CatalogError> {
    std::str::from_utf8(field.ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?)
        .map(str::to_owned)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn git_head(root: &Path, context: &ConnectorContext) -> Result<String, CatalogError> {
    let bytes = run_git(
        root,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        256,
        context,
    )?;
    let value = std::str::from_utf8(trim_line(&bytes))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
    if !valid_object_id(value) {
        return Err(CatalogError::new(CatalogErrorCode::InvalidRecord));
    }
    Ok(value.to_owned())
}

fn read_object(
    root: &Path,
    object_id: &str,
    expected_size: u64,
    context: &ConnectorContext,
) -> Result<Vec<u8>, CatalogError> {
    if !valid_object_id(object_id) {
        return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
    }
    let limit = usize::try_from(expected_size)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
    if limit > MAX_GIT_OUTPUT_BYTES {
        return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
    }
    let bytes = run_git(root, &["cat-file", "blob", object_id], limit, context)?;
    if bytes.len() != limit {
        return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
    }
    Ok(bytes)
}

fn run_git(
    root: &Path,
    arguments: &[&str],
    limit: usize,
    context: &ConnectorContext,
) -> Result<Vec<u8>, CatalogError> {
    context.check()?;
    let mut child = Command::new(git_executable())
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let reader = thread::spawn(move || read_git_stdout(stdout, limit));
    let status = loop {
        if let Err(error) = context.check() {
            terminate_child(&mut child);
            let _reader_result = reader.join();
            return Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(CHILD_POLL_INTERVAL),
            Err(_error) => {
                terminate_child(&mut child);
                let _reader_result = reader.join();
                return Err(CatalogError::new(CatalogErrorCode::Unavailable));
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_panic| CatalogError::new(CatalogErrorCode::Unavailable))??;
    if !status.success() {
        return Err(CatalogError::new(CatalogErrorCode::Unavailable));
    }
    Ok(bytes)
}

fn read_git_stdout(
    mut stdout: std::process::ChildStdout,
    limit: usize,
) -> Result<Vec<u8>, CatalogError> {
    let take_limit = u64::try_from(limit)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
    let mut bytes = Vec::new();
    stdout
        .by_ref()
        .take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    if bytes.len() > limit {
        return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
    }
    Ok(bytes)
}

fn terminate_child(child: &mut Child) {
    let _kill_result = child.kill();
    let _wait_result = child.wait();
}

fn compare_git_records(
    previous: &BTreeMap<String, GitRecord>,
    current: &BTreeMap<String, GitRecord>,
) -> Vec<SourceChange> {
    let mut changes = Vec::new();
    for (identity, old) in previous {
        match current.get(identity) {
            Some(new) if old.record.relative_path != new.record.relative_path => {
                changes.push(SourceChange {
                    watermark: ChangeWatermark::default(),
                    kind: ChangeKind::Renamed,
                    record: Some(new.record.clone()),
                    prior_path: Some(old.record.relative_path.clone()),
                });
            }
            Some(new) if old.record.executable != new.record.executable => {
                changes.push(SourceChange {
                    watermark: ChangeWatermark::default(),
                    kind: ChangeKind::PermissionChanged,
                    record: Some(new.record.clone()),
                    prior_path: None,
                });
            }
            Some(new) if old.record.revision != new.record.revision => {
                changes.push(SourceChange {
                    watermark: ChangeWatermark::default(),
                    kind: ChangeKind::Modified,
                    record: Some(new.record.clone()),
                    prior_path: None,
                });
            }
            Some(_new) => {}
            None => changes.push(SourceChange {
                watermark: ChangeWatermark::default(),
                kind: ChangeKind::Deleted,
                record: None,
                prior_path: Some(old.record.relative_path.clone()),
            }),
        }
    }
    for (identity, new) in current {
        if !previous.contains_key(identity) {
            changes.push(SourceChange {
                watermark: ChangeWatermark::default(),
                kind: ChangeKind::Added,
                record: Some(new.record.clone()),
                prior_path: None,
            });
        }
    }
    changes.sort_by_key(|change| {
        change
            .record
            .as_ref()
            .map(|record| record.relative_path.as_bytes().to_vec())
            .or_else(|| {
                change
                    .prior_path
                    .as_ref()
                    .map(|path| path.as_bytes().to_vec())
            })
            .unwrap_or_default()
    });
    changes
}

fn secret_path(path: &[u8]) -> bool {
    crate::connector::sensitive_source_path(path)
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest_bytes(bytes: &[u8]) -> String {
    multihash(&Sha256::digest(bytes))
}

#[cfg(target_os = "macos")]
fn git_executable() -> &'static str {
    "/usr/bin/git"
}

#[cfg(not(target_os = "macos"))]
fn git_executable() -> &'static str {
    "git"
}

fn media_type(path: &[u8]) -> Result<MediaType, CatalogError> {
    let extension = path.rsplit(|byte| *byte == b'.').next().unwrap_or_default();
    let value = match extension {
        b"md" => "text/markdown",
        b"json" => "application/json",
        b"yaml" | b"yml" => "application/yaml",
        b"toml" => "application/toml",
        b"xml" => "application/xml",
        b"proto" => "text/x-protobuf",
        b"rs" => "text/x-rust",
        b"ts" | b"tsx" => "text/typescript",
        b"js" | b"jsx" => "text/javascript",
        b"py" => "text/x-python",
        b"go" => "text/x-go",
        b"java" => "text/x-java",
        b"c" | b"h" => "text/x-c",
        b"cc" | b"cpp" | b"cxx" | b"hpp" => "text/x-c++",
        b"txt" | b"gitignore" => "text/plain",
        _ => "application/octet-stream",
    };
    MediaType::new(value).map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn digest(bytes: &[u8]) -> Result<ContentDigest, CatalogError> {
    let digest = Sha256::digest(bytes);
    ContentDigest::new(multihash(&digest))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn digest_plan(commit: &str, entries: &[DiscoveryEntry]) -> Result<ContentDigest, CatalogError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-GIT-DISCOVERY\0v1\0");
    hasher.update(commit.as_bytes());
    for entry in entries {
        hasher.update(entry.record.relative_path.as_bytes());
        hasher.update(entry.record.revision.as_bytes());
        hasher.update([u8::from(entry.record.executable)]);
        hasher.update([entry.disposition as u8, entry.reason as u8]);
    }
    ContentDigest::new(multihash(&hasher.finalize()))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn digest_records(commit: &str, records: &[SourceRecord]) -> Result<ContentDigest, CatalogError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-GIT-MANIFEST\0v1\0");
    hasher.update(commit.as_bytes());
    for record in records {
        hasher.update(record.record_id.as_bytes());
        hasher.update(record.relative_path.as_bytes());
        hasher.update(record.revision.as_bytes());
        hasher.update([u8::from(record.executable)]);
    }
    ContentDigest::new(multihash(&hasher.finalize()))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn multihash(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in bytes {
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}

fn deterministic_uuid(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    )
}

fn now_utc() -> Result<UtcTimestamp, CatalogError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?
        .as_nanos();
    UtcTimestamp::from_unix_nanos(
        i128::try_from(nanos)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
    )
    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn trim_line(mut bytes: &[u8]) -> &[u8] {
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = bytes
            .get(..bytes.len().saturating_sub(1))
            .unwrap_or_default();
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{GitConnector, parse_tree_with_limit};
    use crate::{
        ByteRange, CatalogErrorCode, ConnectorContext, DiscoveryDisposition, DiscoveryPolicy,
        DiscoveryReason, DiscoveryRequest, SourceConnector,
    };
    use cigar_protocol::{MediaType, SourceUri};
    use cigar_store::CancellationToken;
    use std::collections::BTreeSet;
    use std::fs;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn committed_objects_ignore_dirty_worktree_and_block_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let run = |arguments: &[&str]| -> Result<(), Box<dyn std::error::Error>> {
            let status = Command::new("git")
                .arg("-C")
                .arg(root.path())
                .args(arguments)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err("git fixture command failed".into())
            }
        };
        let revision = || -> Result<String, Box<dyn std::error::Error>> {
            let output = Command::new("git")
                .arg("-C")
                .arg(root.path())
                .args(["rev-parse", "HEAD"])
                .output()?;
            if !output.status.success() {
                return Err("Git fixture revision failed".into());
            }
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
        };
        run(&["init", "-q"])?;
        run(&["config", "user.email", "fixture@example.invalid"])?;
        run(&["config", "user.name", "Fixture"])?;
        fs::write(root.path().join("safe.rs"), b"fn committed() {}")?;
        fs::write(root.path().join(".ENV.PRODUCTION"), b"TOKEN=fixture")?;
        fs::write(
            root.path().join("application_default_credentials.json"),
            b"{}",
        )?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("../outside", root.path().join("escape.txt"))?;
        run(&["add", "-A"])?;
        run(&["commit", "-qm", "fixture"])?;
        let original = revision()?;
        fs::write(root.path().join("safe.rs"), b"fn replacement() {}")?;
        run(&["add", "safe.rs"])?;
        run(&["commit", "-qm", "replacement fixture"])?;
        let replacement = revision()?;
        run(&["reset", "--hard", &original])?;
        run(&["replace", &original, &replacement])?;
        fs::write(root.path().join("safe.rs"), b"password=dirty-secret-value")?;
        let uri = SourceUri::new("git+file:///fixture")?;
        let connector = GitConnector::new(root.path(), uri.clone())?;
        let context = ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(10),
        );
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: DiscoveryPolicy {
                    max_items: 10,
                    max_total_bytes: 1_000_000,
                    max_record_bytes: 1_000_000,
                    excluded_prefixes: Vec::new(),
                    allowed_media_types: [MediaType::new("text/x-rust")?].into_iter().collect(),
                    allow_user_broadening: false,
                    follow_internal_symlinks: false,
                    secret_patterns: Vec::new(),
                },
                include_overrides: BTreeSet::new(),
            },
            &context,
        )?;
        assert_eq!(plan.included_count, 1);
        for sensitive_path in [
            b".ENV.PRODUCTION".as_slice(),
            b"application_default_credentials.json".as_slice(),
        ] {
            assert!(plan.entries.iter().any(|entry| {
                entry.record.relative_path.as_bytes() == sensitive_path
                    && entry.reason == crate::DiscoveryReason::HardExclusion
                    && entry.disposition == crate::DiscoveryDisposition::Exclude
            }));
        }
        #[cfg(unix)]
        assert!(plan.entries.iter().any(|entry| {
            entry.reason == crate::DiscoveryReason::HardExclusion
                && entry.disposition == crate::DiscoveryDisposition::Exclude
        }));
        let snapshot = connector.snapshot(None, &context)?;
        let record = snapshot.records.first().ok_or("missing Git record")?;
        let bytes = connector.read(record, ByteRange::new(0, record.size_bytes)?, &context)?;
        assert_eq!(bytes.as_slice(), b"fn committed() {}");
        let second_uri = SourceUri::new("git+file:///other-fixture")?;
        let second = GitConnector::new(root.path(), second_uri.clone())?;
        second.discover(
            &DiscoveryRequest {
                root: second_uri,
                policy: DiscoveryPolicy {
                    max_items: 10,
                    max_total_bytes: 1_000_000,
                    max_record_bytes: 1_000_000,
                    excluded_prefixes: Vec::new(),
                    allowed_media_types: [MediaType::new("text/x-rust")?].into_iter().collect(),
                    allow_user_broadening: false,
                    follow_internal_symlinks: false,
                    secret_patterns: Vec::new(),
                },
                include_overrides: BTreeSet::new(),
            },
            &context,
        )?;
        assert_ne!(
            snapshot.snapshot.snapshot_id,
            second.snapshot(None, &context)?.snapshot.snapshot_id
        );
        Ok(())
    }

    #[test]
    fn tree_parser_preserves_header_sizes_and_rejects_the_first_excess_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(10),
        );
        let record = b"100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 7\tfile.txt\0";
        let parsed = parse_tree_with_limit(record, &context, 1)?;
        assert_eq!(parsed.first().and_then(|entry| entry.size), Some(7));

        let mut excess = record.to_vec();
        excess.extend_from_slice(record);
        let error = parse_tree_with_limit(&excess, &context, 1)
            .err()
            .ok_or("the first excess tree record must fail")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn oversized_git_blob_is_excluded_from_header_metadata_without_a_content_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let run = |arguments: &[&str]| -> Result<(), Box<dyn std::error::Error>> {
            let status = Command::new("git")
                .arg("-C")
                .arg(root.path())
                .args(arguments)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err("git fixture command failed".into())
            }
        };
        run(&["init", "-q"])?;
        run(&["config", "user.email", "fixture@example.invalid"])?;
        run(&["config", "user.name", "Fixture"])?;
        fs::write(root.path().join("large.txt"), vec![b'a'; 1_024])?;
        run(&["add", "large.txt"])?;
        run(&["commit", "-qm", "fixture"])?;

        let uri = SourceUri::new("git+file:///fixture")?;
        let connector = GitConnector::new(root.path(), uri.clone())?;
        let context = ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(10),
        );
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: DiscoveryPolicy {
                    max_items: 10,
                    max_total_bytes: 100,
                    max_record_bytes: 100,
                    excluded_prefixes: Vec::new(),
                    allowed_media_types: [MediaType::new("text/plain")?].into_iter().collect(),
                    allow_user_broadening: false,
                    follow_internal_symlinks: false,
                    secret_patterns: Vec::new(),
                },
                include_overrides: BTreeSet::new(),
            },
            &context,
        )?;
        let entry = plan.entries.first().ok_or("missing oversized entry")?;
        assert_eq!(entry.record.size_bytes, 1_024);
        assert!(entry.record.content_digest.is_none());
        assert_eq!(entry.disposition, DiscoveryDisposition::Exclude);
        assert_eq!(entry.reason, DiscoveryReason::SizeLimit);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn supervised_git_child_observes_deadline_while_running()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let status = Command::new("git")
            .arg("-C")
            .arg(root.path())
            .args(["init", "-q"])
            .status()?;
        if !status.success() {
            return Err("git fixture command failed".into());
        }
        let context = ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_millis(20),
        );
        let started = Instant::now();
        let error = super::run_git(
            root.path(),
            &["-c", "alias.pause=!sleep 0.2", "pause"],
            1_024,
            &context,
        )
        .err()
        .ok_or("the running child must observe the connector deadline")?;
        assert_eq!(error.code(), CatalogErrorCode::DeadlineExceeded);
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }
}
