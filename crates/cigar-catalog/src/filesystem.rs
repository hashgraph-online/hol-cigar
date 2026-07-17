//! Safe local-filesystem discovery, immutable reads, refresh, and change cursors.

use crate::connector::{
    BoundedBytes, ByteRange, CatalogError, CatalogErrorCode, ChangeKind, ChangeWatermark,
    ConnectorContext, DiscoveryDisposition, DiscoveryEntry, DiscoveryPlan, DiscoveryPolicy,
    DiscoveryReason, DiscoveryRequest, FILESYSTEM_CONNECTOR_ID, MAX_CONNECTOR_ITEMS, SourceChange,
    SourceConnector, SourceConnectorDescriptor, SourceHealth, SourceHealthState, SourceRecord,
    SourceSnapshotBatch,
};
use crate::ignore::{IgnorePatterns, IgnoreWorkBudget, MAX_IGNORE_BYTES, path_has_prefix};
use crate::secret::scan_secrets_with_patterns;
use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as CapabilityMetadataExt, OpenOptionsFollowExt,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use cigar_protocol::{
    ContentDigest, ExtensionMap, MediaType, RecordId, RelativePath, SourceSnapshot, SourceUri,
    UtcTimestamp,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RETAINED_EVENTS: usize = 100_000;
const MAX_FILESYSTEM_DEPTH: usize = 256;
const MAX_FILE_BYTES: u64 = 67_108_864;
const READ_CHUNK_BYTES: usize = 64 * 1_024;
const MAX_AGGREGATE_GIT_IGNORE_BYTES: usize = 8 * 1_048_576;
const MAX_AGGREGATE_GIT_IGNORE_PATTERNS: usize = 32_768;

#[derive(Clone, Eq, PartialEq)]
struct LocatedRecord {
    record: SourceRecord,
    bytes: Arc<[u8]>,
}

#[derive(Default)]
struct FilesystemState {
    last_request: Option<DiscoveryRequest>,
    records_by_id: BTreeMap<String, LocatedRecord>,
    last_snapshot: Option<SourceSnapshotBatch>,
    events: VecDeque<SourceChange>,
    watermark: ChangeWatermark,
    overflowed: bool,
}

/// Filesystem connector rooted at one canonical directory.
pub struct LocalFilesystemConnector {
    root: Dir,
    root_uri: SourceUri,
    state: Mutex<FilesystemState>,
}

impl LocalFilesystemConnector {
    /// Opens one canonical directory under an explicit normalized source URI.
    pub fn new(root: impl AsRef<Path>, root_uri: SourceUri) -> Result<Self, CatalogError> {
        let root = Dir::open_ambient_dir(root, ambient_authority())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        Ok(Self {
            root,
            root_uri,
            state: Mutex::new(FilesystemState::default()),
        })
    }

    /// Performs a complete rescan and appends deterministic change events.
    pub fn refresh(&self, context: &ConnectorContext) -> Result<DiscoveryPlan, CatalogError> {
        context.check()?;
        let request = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?
            .last_request
            .clone()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
        let (plan, current) = self.build_plan(&request, context)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        let changes = compare_records(&state.records_by_id, &current);
        for change in changes {
            append_change(&mut state, change);
        }
        if state.records_by_id != current || state.overflowed {
            state.last_snapshot = None;
        }
        state.records_by_id = current;
        state.overflowed = false;
        Ok(plan)
    }

    /// Records watcher overflow; the next subscriber receives a typed overflow event.
    pub fn notify_overflow(&self) -> Result<ChangeWatermark, CatalogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        state.overflowed = true;
        state.last_snapshot = None;
        let next = next_watermark(state.watermark)?;
        state.watermark = next;
        state.events.push_back(SourceChange {
            watermark: next,
            kind: ChangeKind::Overflow,
            record: None,
            prior_path: None,
        });
        trim_events(&mut state);
        Ok(next)
    }

    fn build_plan(
        &self,
        request: &DiscoveryRequest,
        context: &ConnectorContext,
    ) -> Result<(DiscoveryPlan, BTreeMap<String, LocatedRecord>), CatalogError> {
        context.check()?;
        request.policy.validate()?;
        if request.root != self.root_uri {
            return Err(CatalogError::new(CatalogErrorCode::Denied));
        }
        let cigar_ignore = load_ignore(&self.root, Path::new(".cigarignore"), context)?;
        let mut candidates = Vec::new();
        let mut git_ignores = Vec::new();
        let mut walk_budget = WalkBudget::default();
        let mut traversal_ignore_work = IgnoreWorkBudget::default();
        {
            let mut walker = FilesystemWalker {
                root: &self.root,
                policy: &request.policy,
                include_overrides: &request.include_overrides,
                cigar_ignore: &cigar_ignore,
                active_git_ignores: Vec::new(),
                directory_identities: Vec::new(),
                collected_git_ignores: &mut git_ignores,
                loaded_git_ignore_bytes: 0,
                loaded_git_ignore_patterns: 0,
                ignore_work: &mut traversal_ignore_work,
                context,
                budget: &mut walk_budget,
                output: &mut candidates,
            };
            walker.walk(Path::new(""), &[], 0)?;
        }
        if candidates.len() > MAX_CONNECTOR_ITEMS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        candidates.sort_by(|left, right| left.relative.cmp(&right.relative));
        crate::connector::validate_source_paths(
            candidates
                .iter()
                .map(|candidate| candidate.relative.as_slice()),
        )?;

        let mut entries = Vec::with_capacity(candidates.len());
        let mut included = BTreeMap::new();
        let mut included_bytes = 0_u64;
        let mut materialized_items = 0_usize;
        let mut materialized_bytes = 0_u64;
        let mut ignore_work = IgnoreWorkBudget::default();
        let mut classifier = MetadataClassifier {
            policy: &request.policy,
            cigar_ignore: &cigar_ignore,
            git_ignores: &git_ignores,
            ignore_work: &mut ignore_work,
            context,
        };
        for candidate in candidates {
            context.check()?;
            let relative_path = RelativePath::new(candidate.relative.clone())
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
            let mut record = source_record_metadata(&candidate, relative_path.clone())?;
            let override_requested = request.include_overrides.contains(&relative_path);
            let (mut disposition, mut reason) =
                classifier.decide(&candidate, &relative_path, &record)?;
            if override_requested
                && request.policy.allow_user_broadening
                && disposition == DiscoveryDisposition::Exclude
                && matches!(
                    reason,
                    DiscoveryReason::CigarIgnore | DiscoveryReason::GitIgnore
                )
            {
                disposition = DiscoveryDisposition::Include;
                reason = DiscoveryReason::UserOverride;
            }
            if disposition == DiscoveryDisposition::Include {
                let next_work_bytes = materialized_bytes
                    .checked_add(candidate.metadata.len())
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
                    let bytes = read_candidate(&self.root, &candidate, context)?;
                    apply_content_revision(&mut record, &bytes)?;
                    if scan_secrets_with_patterns(&bytes, &request.policy.secret_patterns)
                        .must_quarantine()
                    {
                        disposition = DiscoveryDisposition::Quarantine;
                        reason = DiscoveryReason::SecretDetected;
                    } else {
                        let located = LocatedRecord {
                            record: record.clone(),
                            bytes: Arc::from(bytes),
                        };
                        if included.insert(record.record_id.clone(), located).is_some() {
                            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
                        }
                        included_bytes = included_bytes
                            .checked_add(record.size_bytes)
                            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
                    }
                }
            }
            entries.push(DiscoveryEntry {
                record,
                disposition,
                reason,
            });
        }
        let included_count = u64::try_from(included.len())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let plan_digest = digest_plan(&entries)?;
        Ok((
            DiscoveryPlan {
                root: request.root.clone(),
                entries,
                included_count,
                included_bytes,
                plan_digest,
            },
            included,
        ))
    }
}

impl fmt::Debug for LocalFilesystemConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFilesystemConnector")
            .finish_non_exhaustive()
    }
}

impl SourceConnector for LocalFilesystemConnector {
    fn descriptor(&self) -> SourceConnectorDescriptor {
        SourceConnectorDescriptor {
            id: FILESYSTEM_CONNECTOR_ID.to_owned(),
            root: self.root_uri.clone(),
        }
    }

    fn discover(
        &self,
        request: &DiscoveryRequest,
        context: &ConnectorContext,
    ) -> Result<DiscoveryPlan, CatalogError> {
        let (plan, records) = self.build_plan(request, context)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        state.last_request = Some(request.clone());
        if state.records_by_id != records {
            state.last_snapshot = None;
        }
        state.records_by_id = records;
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
        if state.last_request.is_none() {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let records: Vec<_> = state
            .records_by_id
            .values()
            .map(|located| located.record.clone())
            .collect();
        let manifest_digest = digest_records(&records)?;
        if let Some(snapshot) = &state.last_snapshot
            && snapshot.snapshot.manifest_digest == manifest_digest
        {
            return Ok(snapshot.clone());
        }
        if previous_revision == Some(manifest_digest.as_str()) {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let total_bytes = records.iter().try_fold(0_u64, |total, record| {
            total
                .checked_add(record.size_bytes)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))
        })?;
        let captured_at = now_utc()?;
        let snapshot_id = RecordId::new(deterministic_uuid(&[
            b"CIGAR-FILESYSTEM-SNAPSHOT\0v1\0",
            self.root_uri.as_str().as_bytes(),
            manifest_digest.as_str().as_bytes(),
        ]))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let snapshot = SourceSnapshot {
            schema_version: "cigar.source-snapshot.v1"
                .parse()
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
            snapshot_id,
            source_uri: self.root_uri.clone(),
            source_revision: manifest_digest.as_str().to_owned(),
            captured_at,
            manifest_digest,
            entry_count: u64::try_from(records.len())
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
            total_bytes,
            complete: !state.overflowed,
            extensions: ExtensionMap::default(),
        };
        let batch = SourceSnapshotBatch { snapshot, records };
        state.last_snapshot = Some(batch.clone());
        Ok(batch)
    }

    fn read(
        &self,
        record: &SourceRecord,
        range: ByteRange,
        context: &ConnectorContext,
    ) -> Result<BoundedBytes, CatalogError> {
        context.check()?;
        let located = self
            .state
            .lock()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?
            .records_by_id
            .get(&record.record_id)
            .cloned()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::NotFound))?;
        if located.record != *record {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let bytes = located.bytes;
        if Some(
            ContentDigest::new(raw_digest(bytes.as_ref())?)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
        ) != record.content_digest
        {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let start = usize::try_from(range.start)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let length = usize::try_from(range.length)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let selected = bytes
            .get(start..end)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidMetadata))?;
        BoundedBytes::new(selected.to_vec())
    }

    fn subscribe(
        &self,
        watermark: ChangeWatermark,
        limit: usize,
        context: &ConnectorContext,
    ) -> Result<Vec<SourceChange>, CatalogError> {
        context.check()?;
        if limit == 0 || limit > MAX_CONNECTOR_ITEMS {
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
                state: if state.overflowed {
                    SourceHealthState::Degraded
                } else {
                    SourceHealthState::Ready
                },
                watermark: state.watermark,
            },
            Err(_error) => SourceHealth {
                state: SourceHealthState::Unavailable,
                watermark: ChangeWatermark::default(),
            },
        }
    }
}

struct Candidate {
    relative_path: PathBuf,
    relative: Vec<u8>,
    metadata: Metadata,
    identity: Option<FileIdentity>,
    follow_final_symlink: bool,
    hard_excluded: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct MetadataFingerprint {
    identity: FileIdentity,
    len: u64,
    modified: Option<cap_std::time::SystemTime>,
    executable: bool,
    links: u64,
}

#[derive(Default)]
struct WalkBudget {
    visited_entries: usize,
}

impl WalkBudget {
    fn charge(&mut self) -> Result<(), CatalogError> {
        if self.visited_entries == MAX_CONNECTOR_ITEMS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        self.visited_entries = self
            .visited_entries
            .checked_add(1)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        Ok(())
    }
}

struct FilesystemWalker<'a> {
    root: &'a Dir,
    policy: &'a DiscoveryPolicy,
    include_overrides: &'a std::collections::BTreeSet<RelativePath>,
    cigar_ignore: &'a IgnorePatterns,
    active_git_ignores: Vec<ScopedIgnorePatterns>,
    directory_identities: Vec<FileIdentity>,
    collected_git_ignores: &'a mut Vec<ScopedIgnorePatterns>,
    loaded_git_ignore_bytes: usize,
    loaded_git_ignore_patterns: usize,
    ignore_work: &'a mut IgnoreWorkBudget,
    context: &'a ConnectorContext,
    budget: &'a mut WalkBudget,
    output: &'a mut Vec<Candidate>,
}

#[derive(Clone, Copy)]
enum WalkEntryKind {
    Directory,
    Symlink,
    File,
    Other,
}

struct WalkEntry {
    name: PathBuf,
    name_bytes: Vec<u8>,
    kind: WalkEntryKind,
}

struct PendingDirectory {
    name: PathBuf,
    name_bytes: Vec<u8>,
    expected_identity: FileIdentity,
}

struct WalkFrame {
    relative_path: PathBuf,
    relative: Vec<u8>,
    depth: usize,
    pending_directories: Vec<PendingDirectory>,
}

impl FilesystemWalker<'_> {
    fn walk(
        &mut self,
        relative_directory: &Path,
        relative_directory_bytes: &[u8],
        depth: usize,
    ) -> Result<(), CatalogError> {
        debug_assert!(self.active_git_ignores.is_empty());
        debug_assert!(self.directory_identities.is_empty());
        // Explicit frames keep both descriptor use and the native call stack
        // independent of attacker-controlled directory depth.
        let first = self.enter_directory(
            relative_directory.to_path_buf(),
            relative_directory_bytes.to_vec(),
            depth,
        )?;
        let mut frames = vec![first];
        while let Some(frame) = frames.last_mut() {
            self.context.check()?;
            let Some(pending) = frame.pending_directories.pop() else {
                let _frame = frames.pop();
                let _scoped = self.active_git_ignores.pop();
                if !frames.is_empty() {
                    let _identity = self.directory_identities.pop();
                }
                continue;
            };
            let relative_path = frame.relative_path.join(&pending.name);
            let relative = join_relative_bytes(&frame.relative, pending.name_bytes)?;
            let next_depth = frame
                .depth
                .checked_add(1)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
            self.directory_identities.push(pending.expected_identity);
            let child = match self.enter_directory(relative_path, relative, next_depth) {
                Ok(child) => child,
                Err(error) => {
                    let _identity = self.directory_identities.pop();
                    return Err(error);
                }
            };
            frames.push(child);
        }
        debug_assert!(self.active_git_ignores.is_empty());
        debug_assert!(self.directory_identities.is_empty());
        Ok(())
    }

    fn enter_directory(
        &mut self,
        relative_directory: PathBuf,
        relative_directory_bytes: Vec<u8>,
        depth: usize,
    ) -> Result<WalkFrame, CatalogError> {
        self.context.check()?;
        if depth > MAX_FILESYSTEM_DEPTH {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let directory =
            reopen_walk_directory(self.root, &relative_directory, &self.directory_identities)?;
        let patterns = load_ignore(&directory, Path::new(".gitignore"), self.context)?;
        self.loaded_git_ignore_bytes = self
            .loaded_git_ignore_bytes
            .checked_add(patterns.source_bytes())
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        self.loaded_git_ignore_patterns = self
            .loaded_git_ignore_patterns
            .checked_add(patterns.pattern_count())
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        if self.loaded_git_ignore_bytes > MAX_AGGREGATE_GIT_IGNORE_BYTES
            || self.loaded_git_ignore_patterns > MAX_AGGREGATE_GIT_IGNORE_PATTERNS
        {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let scoped = ScopedIgnorePatterns {
            base: relative_directory_bytes.clone(),
            patterns,
        };
        self.collected_git_ignores.push(scoped.clone());
        self.active_git_ignores.push(scoped);
        let iterator = directory
            .read_dir(".")
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        let mut entries = Vec::new();
        for entry in iterator {
            self.context.check()?;
            self.budget.charge()?;
            let entry = entry.map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
            let name = entry.file_name();
            let name_bytes = os_bytes(name.clone());
            let file_type = entry
                .file_type()
                .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
            let kind = if file_type.is_dir() {
                WalkEntryKind::Directory
            } else if file_type.is_symlink() {
                WalkEntryKind::Symlink
            } else if file_type.is_file() {
                WalkEntryKind::File
            } else {
                WalkEntryKind::Other
            };
            // DirEntry retains its ReadDir descriptor through an Arc. Keep
            // only owned values so the iterator descriptor closes here.
            entries.push(WalkEntry {
                name: PathBuf::from(name),
                name_bytes,
                kind,
            });
        }
        entries.sort_by(|left, right| left.name_bytes.cmp(&right.name_bytes));
        let mut pending_directories = Vec::new();
        for entry in entries {
            self.context.check()?;
            let relative_path = relative_directory.join(&entry.name);
            let relative_bytes =
                join_relative_bytes(&relative_directory_bytes, entry.name_bytes.clone())?;
            if matches!(entry.kind, WalkEntryKind::Directory) {
                if !is_hard_directory(&relative_bytes) && !self.prune_directory(&relative_bytes)? {
                    let child = directory
                        .open_dir_nofollow(&entry.name)
                        .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
                    if !has_nested_git_marker(&child, self.context)? {
                        let next_depth = depth
                            .checked_add(1)
                            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
                        if next_depth > MAX_FILESYSTEM_DEPTH {
                            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
                        }
                        let metadata = child
                            .dir_metadata()
                            .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
                        if !metadata.is_dir() {
                            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
                        }
                        pending_directories.push(PendingDirectory {
                            name: entry.name,
                            name_bytes: entry.name_bytes,
                            expected_identity: file_identity(&metadata),
                        });
                    }
                }
                continue;
            }
            if matches!(entry.kind, WalkEntryKind::Symlink) {
                if self.policy.follow_internal_symlinks
                    && let Some(metadata) = internal_symlink_metadata(self.root, &relative_path)?
                {
                    self.output.push(Candidate {
                        relative_path,
                        relative: relative_bytes,
                        identity: Some(file_identity(&metadata)),
                        metadata,
                        follow_final_symlink: true,
                        hard_excluded: false,
                    });
                    continue;
                }
                let metadata = directory
                    .symlink_metadata(&entry.name)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
                self.output.push(Candidate {
                    relative_path,
                    relative: relative_bytes,
                    metadata,
                    identity: None,
                    follow_final_symlink: false,
                    hard_excluded: true,
                });
                continue;
            }
            if matches!(entry.kind, WalkEntryKind::File) {
                let file = open_file_in(&directory, &entry.name, false)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
                let metadata = file
                    .metadata()
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
                if !metadata.is_file() {
                    return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
                }
                self.output.push(Candidate {
                    relative_path,
                    relative: relative_bytes.clone(),
                    identity: Some(file_identity(&metadata)),
                    metadata,
                    follow_final_symlink: false,
                    hard_excluded: is_hard_file(&relative_bytes),
                });
            }
        }
        drop(directory);
        pending_directories.reverse();
        Ok(WalkFrame {
            relative_path: relative_directory,
            relative: relative_directory_bytes,
            depth,
            pending_directories,
        })
    }

    fn prune_directory(&mut self, path: &[u8]) -> Result<bool, CatalogError> {
        if self.policy.allow_user_broadening
            && self.include_overrides.iter().any(|override_path| {
                override_path.as_bytes() != path && path_has_prefix(override_path.as_bytes(), path)
            })
        {
            return Ok(false);
        }
        if self
            .cigar_ignore
            .matches_filesystem(path, self.ignore_work, self.context)?
        {
            return Ok(true);
        }
        for scoped in &self.active_git_ignores {
            let Some(scoped_path) = scoped.path(path) else {
                continue;
            };
            if scoped
                .patterns
                .matches_filesystem(scoped_path, self.ignore_work, self.context)?
            {
                return Ok(true);
            }
            let mut directory_path = scoped_path.to_vec();
            directory_path.push(b'/');
            if scoped.patterns.matches_filesystem(
                &directory_path,
                self.ignore_work,
                self.context,
            )? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn reopen_walk_directory(
    root: &Dir,
    relative: &Path,
    expected_identities: &[FileIdentity],
) -> Result<Dir, CatalogError> {
    let mut directory = root
        .try_clone()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let mut identities = expected_identities.iter();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        };
        let expected_identity = identities
            .next()
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::SourceChanged))?;
        directory = directory
            .open_dir_nofollow(name)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
        let metadata = directory
            .dir_metadata()
            .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
        if !metadata.is_dir() || file_identity(&metadata) != *expected_identity {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
    }
    if identities.next().is_some() {
        return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
    }
    Ok(directory)
}

fn source_record_metadata(
    candidate: &Candidate,
    relative_path: RelativePath,
) -> Result<SourceRecord, CatalogError> {
    let media_type = detect_media_type(&candidate.relative)?;
    let record_id = if let Some(identity) = candidate.identity {
        if candidate.follow_final_symlink {
            format!(
                "fs:{}:{}:symlink:{}",
                identity.device,
                identity.inode,
                raw_digest(&candidate.relative)?
            )
        } else {
            format!("fs:{}:{}", identity.device, identity.inode)
        }
    } else {
        format!("fs:path:{}", raw_digest(&candidate.relative)?)
    };
    Ok(SourceRecord {
        record_id,
        relative_path,
        revision: format!(
            "metadata:{}:{}:{}",
            raw_digest(&candidate.relative)?,
            candidate.metadata.len(),
            if executable(&candidate.metadata) {
                "x"
            } else {
                "n"
            }
        ),
        size_bytes: candidate.metadata.len(),
        executable: executable(&candidate.metadata),
        media_type,
        content_digest: None,
    })
}

fn apply_content_revision(record: &mut SourceRecord, bytes: &[u8]) -> Result<(), CatalogError> {
    let digest = raw_digest(bytes)?;
    record.revision = format!("{}:{}", digest, if record.executable { "x" } else { "n" });
    record.content_digest = Some(
        ContentDigest::new(digest)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
    );
    Ok(())
}

struct MetadataClassifier<'a> {
    policy: &'a DiscoveryPolicy,
    cigar_ignore: &'a IgnorePatterns,
    git_ignores: &'a [ScopedIgnorePatterns],
    ignore_work: &'a mut IgnoreWorkBudget,
    context: &'a ConnectorContext,
}

impl MetadataClassifier<'_> {
    fn decide(
        &mut self,
        candidate: &Candidate,
        relative: &RelativePath,
        record: &SourceRecord,
    ) -> Result<(DiscoveryDisposition, DiscoveryReason), CatalogError> {
        if candidate.hard_excluded || link_count(&candidate.metadata) != 1 {
            return Ok((
                DiscoveryDisposition::Exclude,
                DiscoveryReason::HardExclusion,
            ));
        }
        if self
            .policy
            .excluded_prefixes
            .iter()
            .any(|prefix| path_has_prefix(relative.as_bytes(), prefix.as_bytes()))
        {
            return Ok((
                DiscoveryDisposition::Exclude,
                DiscoveryReason::PolicyExclusion,
            ));
        }
        if self.cigar_ignore.matches_filesystem(
            relative.as_bytes(),
            self.ignore_work,
            self.context,
        )? {
            return Ok((DiscoveryDisposition::Exclude, DiscoveryReason::CigarIgnore));
        }
        for scoped in self.git_ignores {
            if let Some(scoped_path) = scoped.path(relative.as_bytes())
                && scoped.patterns.matches_filesystem(
                    scoped_path,
                    self.ignore_work,
                    self.context,
                )?
            {
                return Ok((DiscoveryDisposition::Exclude, DiscoveryReason::GitIgnore));
            }
        }
        if record.size_bytes > self.policy.max_record_bytes {
            return Ok((DiscoveryDisposition::Exclude, DiscoveryReason::SizeLimit));
        }
        if !self.policy.allowed_media_types.contains(&record.media_type) {
            return Ok((DiscoveryDisposition::Exclude, DiscoveryReason::MediaType));
        }
        Ok((DiscoveryDisposition::Include, DiscoveryReason::Eligible))
    }
}

#[derive(Clone)]
struct ScopedIgnorePatterns {
    base: Vec<u8>,
    patterns: IgnorePatterns,
}

impl ScopedIgnorePatterns {
    fn path<'a>(&self, path: &'a [u8]) -> Option<&'a [u8]> {
        if self.base.is_empty() {
            Some(path)
        } else {
            path.strip_prefix(self.base.as_slice())?.strip_prefix(b"/")
        }
    }
}

fn read_candidate(
    root: &Dir,
    candidate: &Candidate,
    context: &ConnectorContext,
) -> Result<Vec<u8>, CatalogError> {
    let identity = candidate
        .identity
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::SourceChanged))?;
    read_capability_file(
        root,
        &candidate.relative_path,
        candidate.follow_final_symlink,
        identity,
        candidate.metadata.len(),
        context,
    )
}

fn read_capability_file(
    root: &Dir,
    path: &Path,
    follow_final_symlink: bool,
    expected_identity: FileIdentity,
    expected_size: u64,
    context: &ConnectorContext,
) -> Result<Vec<u8>, CatalogError> {
    context.check()?;
    let mut file = open_relative_file(root, path, follow_final_symlink)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
    let before = file
        .metadata()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let fingerprint = metadata_fingerprint(&before);
    if !before.is_file()
        || fingerprint.identity != expected_identity
        || fingerprint.len != expected_size
        || fingerprint.links != 1
        || fingerprint.len > MAX_FILE_BYTES
    {
        return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
    }
    read_open_file(&mut file, fingerprint, MAX_FILE_BYTES, context)
}

fn read_open_file(
    file: &mut File,
    before: MetadataFingerprint,
    byte_limit: u64,
    context: &ConnectorContext,
) -> Result<Vec<u8>, CatalogError> {
    if before.len > byte_limit {
        return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
    }
    let capacity = usize::try_from(before.len)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
    let mut bytes = Vec::with_capacity(capacity);
    let read_limit = before
        .len
        .checked_add(1)
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        context.check()?;
        let bytes_len = u64::try_from(bytes.len())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        if bytes_len == read_limit {
            break;
        }
        let remaining = usize::try_from(read_limit - bytes_len)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let read_len = remaining.min(chunk.len());
        let count = file
            .read(
                chunk
                    .get_mut(..read_len)
                    .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
            )
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(
            chunk
                .get(..count)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::Unavailable))?,
        );
    }
    let after = file
        .metadata()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    if metadata_fingerprint(&after) != before || u64::try_from(bytes.len()).ok() != Some(before.len)
    {
        return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
    }
    Ok(bytes)
}

fn open_relative_file(root: &Dir, path: &Path, follow: bool) -> std::io::Result<File> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let directory = reopen_relative_directory(root, parent)?;
    open_file_in(&directory, name, follow)
}

fn reopen_relative_directory(root: &Dir, relative: &Path) -> std::io::Result<Dir> {
    // cap-std's full-path resolver retains ancestor handles for `..` safety.
    // These paths are already normalized relative paths, so reopening one
    // no-follow component at a time provides the same confinement with a
    // constant number of descriptors.
    let mut directory = root.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        directory = directory.open_dir_nofollow(name)?;
    }
    Ok(directory)
}

fn open_file_in(directory: &Dir, path: impl AsRef<Path>, follow: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(if follow {
        FollowSymlinks::Yes
    } else {
        FollowSymlinks::No
    });
    directory.open_with(path, &options)
}

fn metadata_fingerprint(metadata: &Metadata) -> MetadataFingerprint {
    MetadataFingerprint {
        identity: file_identity(metadata),
        len: metadata.len(),
        modified: metadata.modified().ok(),
        executable: executable(metadata),
        links: link_count(metadata),
    }
}

fn internal_symlink_metadata(
    root: &Dir,
    link_path: &Path,
) -> Result<Option<Metadata>, CatalogError> {
    let resolved_before = match root.canonicalize(link_path) {
        Ok(path) => path,
        Err(_error) => return Ok(None),
    };
    let resolved_bytes = path_bytes(&resolved_before);
    if is_hard_directory(&resolved_bytes) || is_hard_file(&resolved_bytes) {
        return Ok(None);
    }
    let target = match open_relative_file(root, &resolved_before, false) {
        Ok(file) => file,
        Err(_error) => return Ok(None),
    };
    let target_metadata = target
        .metadata()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    if !target_metadata.is_file() {
        return Ok(None);
    }
    let linked = match open_relative_file(root, link_path, true) {
        Ok(file) => file,
        Err(_error) => return Ok(None),
    };
    let linked_metadata = linked
        .metadata()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let resolved_after = match root.canonicalize(link_path) {
        Ok(path) => path,
        Err(_error) => return Ok(None),
    };
    if resolved_before != resolved_after
        || metadata_fingerprint(&target_metadata) != metadata_fingerprint(&linked_metadata)
    {
        return Ok(None);
    }
    Ok(Some(linked_metadata))
}

fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        device: CapabilityMetadataExt::dev(metadata),
        inode: CapabilityMetadataExt::ino(metadata),
    }
}

fn link_count(metadata: &Metadata) -> u64 {
    CapabilityMetadataExt::nlink(metadata)
}

fn has_nested_git_marker(
    directory: &Dir,
    context: &ConnectorContext,
) -> Result<bool, CatalogError> {
    let entries = directory
        .read_dir(".")
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let mut inspected = 0_usize;
    for entry in entries {
        context.check()?;
        inspected = inspected
            .checked_add(1)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        if inspected > MAX_CONNECTOR_ITEMS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let entry = entry.map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        if os_bytes(entry.file_name()).eq_ignore_ascii_case(b".git") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn join_relative_bytes(parent: &[u8], name: Vec<u8>) -> Result<Vec<u8>, CatalogError> {
    let separator = usize::from(!parent.is_empty());
    let capacity = parent
        .len()
        .checked_add(separator)
        .and_then(|len| len.checked_add(name.len()))
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
    if capacity > cigar_protocol::limits::MAX_PATH_BYTES {
        return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
    }
    let mut relative = Vec::with_capacity(capacity);
    relative.extend_from_slice(parent);
    if separator == 1 {
        relative.push(b'/');
    }
    relative.extend_from_slice(&name);
    Ok(relative)
}

fn compare_records(
    previous: &BTreeMap<String, LocatedRecord>,
    current: &BTreeMap<String, LocatedRecord>,
) -> Vec<SourceChange> {
    let mut changes = Vec::new();
    for (identity, prior) in previous {
        match current.get(identity) {
            None => changes.push(SourceChange {
                watermark: ChangeWatermark::default(),
                kind: ChangeKind::Deleted,
                record: None,
                prior_path: Some(prior.record.relative_path.clone()),
            }),
            Some(next) if next.record.relative_path != prior.record.relative_path => {
                changes.push(SourceChange {
                    watermark: ChangeWatermark::default(),
                    kind: ChangeKind::Renamed,
                    record: Some(next.record.clone()),
                    prior_path: Some(prior.record.relative_path.clone()),
                });
            }
            Some(next) if next.record.executable != prior.record.executable => {
                changes.push(SourceChange {
                    watermark: ChangeWatermark::default(),
                    kind: ChangeKind::PermissionChanged,
                    record: Some(next.record.clone()),
                    prior_path: None,
                });
            }
            Some(next) if next.record.revision != prior.record.revision => {
                changes.push(SourceChange {
                    watermark: ChangeWatermark::default(),
                    kind: ChangeKind::Modified,
                    record: Some(next.record.clone()),
                    prior_path: None,
                });
            }
            Some(_next) => {}
        }
    }
    for (identity, record) in current {
        if !previous.contains_key(identity) {
            changes.push(SourceChange {
                watermark: ChangeWatermark::default(),
                kind: ChangeKind::Added,
                record: Some(record.record.clone()),
                prior_path: None,
            });
        }
    }
    changes.sort_by_key(change_key);
    changes
}

fn change_key(change: &SourceChange) -> (ChangeKindKey, Vec<u8>) {
    let kind = match change.kind {
        ChangeKind::Deleted => ChangeKindKey::Deleted,
        ChangeKind::Renamed => ChangeKindKey::Renamed,
        ChangeKind::Modified | ChangeKind::PermissionChanged => ChangeKindKey::Modified,
        ChangeKind::Added => ChangeKindKey::Added,
        ChangeKind::Overflow => ChangeKindKey::Overflow,
    };
    let path = change
        .record
        .as_ref()
        .map(|record| record.relative_path.as_bytes().to_vec())
        .or_else(|| {
            change
                .prior_path
                .as_ref()
                .map(|path| path.as_bytes().to_vec())
        })
        .unwrap_or_default();
    (kind, path)
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ChangeKindKey {
    Deleted,
    Renamed,
    Modified,
    Added,
    Overflow,
}

fn append_change(state: &mut FilesystemState, mut change: SourceChange) {
    let Ok(next) = next_watermark(state.watermark) else {
        state.overflowed = true;
        return;
    };
    state.watermark = next;
    change.watermark = next;
    state.events.push_back(change);
    trim_events(state);
}

fn trim_events(state: &mut FilesystemState) {
    while state.events.len() > MAX_RETAINED_EVENTS {
        let _removed = state.events.pop_front();
        state.overflowed = true;
    }
}

fn next_watermark(current: ChangeWatermark) -> Result<ChangeWatermark, CatalogError> {
    current
        .0
        .checked_add(1)
        .map(ChangeWatermark)
        .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))
}

fn load_ignore(
    root: &Dir,
    path: &Path,
    context: &ConnectorContext,
) -> Result<IgnorePatterns, CatalogError> {
    let metadata = match root.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(IgnorePatterns::default());
        }
        Err(_error) => return Err(CatalogError::new(CatalogErrorCode::Unavailable)),
    };
    if metadata.is_symlink() {
        return Ok(IgnorePatterns::default());
    }
    if metadata.len() > MAX_IGNORE_BYTES || !metadata.is_file() {
        return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
    }
    let mut file = open_relative_file(root, path, false)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
    let opened = file
        .metadata()
        .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    let fingerprint = metadata_fingerprint(&opened);
    if !opened.is_file() || fingerprint.links != 1 {
        return Ok(IgnorePatterns::default());
    }
    let bytes = read_open_file(&mut file, fingerprint, MAX_IGNORE_BYTES, context)?;
    IgnorePatterns::parse(&bytes, context)
}

fn is_hard_directory(relative: &[u8]) -> bool {
    relative.split(|byte| *byte == b'/').any(|component| {
        component.eq_ignore_ascii_case(b".git") || component.eq_ignore_ascii_case(b".cigar")
    })
}

fn is_hard_file(relative: &[u8]) -> bool {
    crate::connector::sensitive_source_path(relative)
}

fn detect_media_type(path: &[u8]) -> Result<MediaType, CatalogError> {
    let extension = path.rsplit(|byte| *byte == b'.').next().unwrap_or_default();
    let value = match extension {
        b"md" | b"markdown" => "text/markdown",
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

fn digest_plan(entries: &[DiscoveryEntry]) -> Result<ContentDigest, CatalogError> {
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-DISCOVERY-PLAN\0v1\0");
    for entry in entries {
        hasher.update(entry.record.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.record.revision.as_bytes());
        hasher.update([u8::from(entry.record.executable)]);
        hasher.update([entry.disposition as u8, entry.reason as u8]);
    }
    digest_from_hasher(hasher)
}

fn digest_records(records: &[SourceRecord]) -> Result<ContentDigest, CatalogError> {
    let mut ordered = records.to_vec();
    ordered.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-SOURCE-MANIFEST\0v1\0");
    for record in ordered {
        hasher.update(record.record_id.as_bytes());
        hasher.update([0]);
        hasher.update(record.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(record.revision.as_bytes());
        hasher.update(record.size_bytes.to_be_bytes());
        hasher.update([u8::from(record.executable)]);
    }
    digest_from_hasher(hasher)
}

fn digest_from_hasher(hasher: Sha256) -> Result<ContentDigest, CatalogError> {
    let digest = hasher.finalize();
    ContentDigest::new(encode_multihash(&digest)?)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn raw_digest(bytes: &[u8]) -> Result<String, CatalogError> {
    let digest = Sha256::digest(bytes);
    let value = encode_multihash(&digest)?;
    ContentDigest::new(value.clone())
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
    Ok(value)
}

fn encode_multihash(digest: &[u8]) -> Result<String, CatalogError> {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    for byte in digest {
        write!(&mut value, "{byte:02x}")
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
    }
    Ok(value)
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
    let nanos = i128::try_from(nanos)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
    UtcTimestamp::from_unix_nanos(nanos)
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

#[cfg(unix)]
fn executable(metadata: &Metadata) -> bool {
    use cap_std::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn os_bytes(value: std::ffi::OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt;
    value.into_vec()
}

#[cfg(not(unix))]
fn os_bytes(value: std::ffi::OsString) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn path_bytes(value: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(value: &Path) -> Vec<u8> {
    value.to_string_lossy().replace('\\', "/").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{LocalFilesystemConnector, MAX_FILESYSTEM_DEPTH};
    #[cfg(unix)]
    use super::{file_identity, reopen_walk_directory};
    use crate::{
        ByteRange, ChangeKind, ChangeWatermark, ConnectorContext, DiscoveryDisposition,
        DiscoveryPolicy, DiscoveryReason, DiscoveryRequest, SourceConnector, SourceHealthState,
    };
    use cigar_protocol::{MediaType, RelativePath, SourceUri};
    use cigar_store::CancellationToken;
    use std::collections::{BTreeSet, HashSet};
    use std::fs;
    use std::sync::{Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    static DEEP_FILESYSTEM_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn deep_filesystem_fixture_guard() -> MutexGuard<'static, ()> {
        DEEP_FILESYSTEM_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn context() -> ConnectorContext {
        ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(10),
        )
    }

    fn policy() -> Result<DiscoveryPolicy, Box<dyn std::error::Error>> {
        Ok(DiscoveryPolicy {
            max_items: 100,
            max_total_bytes: 1_000_000,
            max_record_bytes: 1_000_000,
            excluded_prefixes: Vec::new(),
            allowed_media_types: [
                MediaType::new("text/plain")?,
                MediaType::new("text/x-rust")?,
            ]
            .into_iter()
            .collect(),
            allow_user_broadening: false,
            follow_internal_symlinks: false,
            secret_patterns: Vec::new(),
        })
    }

    #[test]
    fn preview_scans_secrets_before_inclusion_and_reads_exact_ranges()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("safe.rs"), b"fn main() {}")?;
        fs::write(root.path().join("leak.txt"), b"password=very-secret-value")?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let mut secret_policy = policy()?;
        secret_policy.allow_user_broadening = true;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: secret_policy,
                include_overrides: [RelativePath::new(b"leak.txt".to_vec())?]
                    .into_iter()
                    .collect(),
            },
            &context(),
        )?;
        assert_eq!(plan.included_count, 1);
        assert!(plan.entries.iter().any(|entry| {
            entry.disposition == DiscoveryDisposition::Quarantine
                && entry.reason == DiscoveryReason::SecretDetected
        }));
        let batch = connector.snapshot(None, &context())?;
        let record = batch.records.first().ok_or("missing safe record")?;
        assert_eq!(
            connector
                .read(record, ByteRange::new(0, 2)?, &context())?
                .as_slice(),
            b"fn"
        );
        Ok(())
    }

    #[test]
    fn rename_preserves_identity_and_watcher_overflow_is_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let old = root.path().join("old.rs");
        let new = root.path().join("new.rs");
        fs::write(&old, b"fn renamed() {}")?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let request = DiscoveryRequest {
            root: uri,
            policy: policy()?,
            include_overrides: BTreeSet::new(),
        };
        let initial = connector.discover(&request, &context())?;
        let identities: HashSet<_> = initial
            .entries
            .iter()
            .map(|entry| entry.record.record_id.clone())
            .collect();
        fs::rename(old, &new)?;
        let refreshed = connector.refresh(&context())?;
        assert!(
            refreshed
                .entries
                .iter()
                .all(|entry| identities.contains(&entry.record.record_id))
        );
        let events = connector.subscribe(ChangeWatermark(0), 10, &context())?;
        assert_eq!(
            events.first().map(|event| event.kind),
            Some(ChangeKind::Renamed)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let rename_watermark = events
                .last()
                .map(|event| event.watermark)
                .ok_or("missing rename watermark")?;
            let mut permissions = fs::metadata(&new)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&new, permissions)?;
            connector.refresh(&context())?;
            let permission_events = connector.subscribe(rename_watermark, 10, &context())?;
            assert_eq!(
                permission_events.first().map(|event| event.kind),
                Some(ChangeKind::PermissionChanged)
            );
        }
        let overflow = connector.notify_overflow()?;
        let events = connector.subscribe(ChangeWatermark(overflow.0 - 1), 10, &context())?;
        assert_eq!(
            events.first().map(|event| event.kind),
            Some(ChangeKind::Overflow)
        );
        assert_eq!(connector.health().state, SourceHealthState::Degraded);
        assert!(!connector.snapshot(None, &context())?.snapshot.complete);
        connector.refresh(&context())?;
        assert_eq!(connector.health().state, SourceHealthState::Ready);
        assert!(connector.snapshot(None, &context())?.snapshot.complete);
        let restarted = LocalFilesystemConnector::new(root.path(), request.root.clone())?;
        restarted.discover(&request, &context())?;
        assert!(
            restarted
                .subscribe(ChangeWatermark::default(), 10, &context())?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn ordered_ignore_and_policy_stages_are_inspectable_and_non_bypassable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join(".cigarignore"), b"ignored.rs\n")?;
        fs::write(root.path().join(".gitignore"), b"git_ignored.rs\n")?;
        fs::write(root.path().join("ignored.rs"), b"fn ignored() {}")?;
        fs::write(root.path().join("git_ignored.rs"), b"fn ignored() {}")?;
        fs::create_dir(root.path().join("nested"))?;
        fs::write(root.path().join("nested/.gitignore"), b"private.rs\n")?;
        fs::write(
            root.path().join("nested/private.rs"),
            b"fn nested_private() {}",
        )?;
        fs::write(
            root.path().join("organization.rs"),
            b"ORG_RULE_fixture_value",
        )?;
        fs::write(root.path().join(".ENV.PRODUCTION"), b"TOKEN=fixture")?;
        fs::write(
            root.path().join("application_default_credentials.json"),
            b"{}",
        )?;
        fs::create_dir(root.path().join("protected"))?;
        fs::write(root.path().join("protected/denied.rs"), b"fn denied() {}")?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let mut discovery_policy = policy()?;
        discovery_policy.allow_user_broadening = true;
        discovery_policy.excluded_prefixes = vec![RelativePath::new(b"protected".to_vec())?];
        discovery_policy.secret_patterns = vec![b"ORG_RULE_".to_vec()];
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: discovery_policy,
                include_overrides: [
                    RelativePath::new(b"ignored.rs".to_vec())?,
                    RelativePath::new(b"protected/denied.rs".to_vec())?,
                ]
                .into_iter()
                .collect(),
            },
            &context(),
        )?;
        assert!(plan.entries.iter().any(|entry| {
            entry.reason == DiscoveryReason::UserOverride
                && entry.disposition == DiscoveryDisposition::Include
        }));
        assert!(plan.entries.iter().any(|entry| {
            entry.reason == DiscoveryReason::GitIgnore
                && entry.disposition == DiscoveryDisposition::Exclude
        }));
        assert!(plan.entries.iter().any(|entry| {
            entry.record.relative_path.as_bytes() == b"nested/private.rs"
                && entry.reason == DiscoveryReason::GitIgnore
                && entry.disposition == DiscoveryDisposition::Exclude
        }));
        assert!(plan.entries.iter().any(|entry| {
            entry.reason == DiscoveryReason::PolicyExclusion
                && entry.disposition == DiscoveryDisposition::Exclude
        }));
        assert!(plan.entries.iter().any(|entry| {
            entry.reason == DiscoveryReason::SecretDetected
                && entry.disposition == DiscoveryDisposition::Quarantine
        }));
        for sensitive_path in [
            b".ENV.PRODUCTION".as_slice(),
            b"application_default_credentials.json".as_slice(),
            b".gitignore".as_slice(),
        ] {
            assert!(plan.entries.iter().any(|entry| {
                entry.record.relative_path.as_bytes() == sensitive_path
                    && entry.reason == DiscoveryReason::HardExclusion
                    && entry.disposition == DiscoveryDisposition::Exclude
            }));
        }
        Ok(())
    }

    #[test]
    fn ignored_directory_is_pruned_before_hostile_depth_is_charged()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = deep_filesystem_fixture_guard();
        let root = tempfile::tempdir()?;
        fs::write(root.path().join(".gitignore"), b"ignored\n")?;
        let mut nested = root.path().join("ignored");
        fs::create_dir(&nested)?;
        for _index in 0..=MAX_FILESYSTEM_DEPTH {
            nested = nested.join("d");
            fs::create_dir(&nested)?;
        }
        fs::write(nested.join("unreachable.rs"), b"fn unreachable() {}")?;

        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        assert!(plan.entries.iter().all(|entry| {
            !entry
                .record
                .relative_path
                .as_bytes()
                .starts_with(b"ignored/")
        }));
        Ok(())
    }

    #[test]
    fn nested_repository_is_pruned_before_hostile_depth_is_charged()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = deep_filesystem_fixture_guard();
        let root = tempfile::tempdir()?;
        let mut nested = root.path().to_path_buf();
        for _depth in 0..=MAX_FILESYSTEM_DEPTH {
            nested.push("d");
            fs::create_dir(&nested)?;
        }
        fs::create_dir(nested.join(".git"))?;

        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        assert!(plan.entries.is_empty());
        Ok(())
    }

    #[test]
    fn aggregate_nested_ignore_inputs_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        use crate::CatalogErrorCode;

        let root = tempfile::tempdir()?;
        let mut comment = vec![b'a'; 1_048_576];
        *comment.first_mut().ok_or("missing ignore comment byte")? = b'#';
        let mut directory = root.path().to_path_buf();
        for _depth in 0..9 {
            fs::write(directory.join(".gitignore"), &comment)?;
            directory = directory.join("d");
            fs::create_dir(&directory)?;
        }
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let error = connector
            .discover(
                &DiscoveryRequest {
                    root: uri,
                    policy: policy()?,
                    include_overrides: BTreeSet::new(),
                },
                &context(),
            )
            .err()
            .ok_or("aggregate ignore input must be bounded")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn nested_repository_is_not_traversed_and_unapproved_media_is_excluded()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join("nested-repository/.git"))?;
        fs::write(
            root.path().join("nested-repository/private.rs"),
            b"fn private() {}",
        )?;
        fs::create_dir_all(root.path().join("uppercase-repository/.GIT"))?;
        fs::write(
            root.path().join("uppercase-repository/private.rs"),
            b"fn private() {}",
        )?;
        fs::write(
            root.path().join("opaque.bin"),
            b"not an approved media type",
        )?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        assert!(plan.entries.iter().all(|entry| {
            let path = entry.record.relative_path.as_bytes();
            !path.starts_with(b"nested-repository/") && !path.starts_with(b"uppercase-repository/")
        }));
        let opaque = plan
            .entries
            .iter()
            .find(|entry| entry.record.relative_path.as_bytes() == b"opaque.bin")
            .ok_or("missing opaque file preview")?;
        assert_eq!(opaque.disposition, DiscoveryDisposition::Exclude);
        assert_eq!(opaque.reason, DiscoveryReason::MediaType);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_symlink_is_never_followed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        symlink(outside.path(), root.path().join("escape.txt"))?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        assert_eq!(plan.included_count, 0);
        assert_eq!(
            plan.entries.first().map(|entry| entry.reason),
            Some(DiscoveryReason::HardExclusion)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_symlinked_directory_is_never_traversed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("private.rs"), b"fn private() {}")?;
        symlink(outside.path(), root.path().join("escape"))?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        assert_eq!(plan.entries.len(), 1);
        let escape = plan.entries.first().ok_or("missing symlink entry")?;
        assert_eq!(escape.record.relative_path.as_bytes(), b"escape");
        assert_eq!(escape.disposition, DiscoveryDisposition::Exclude);
        assert_eq!(escape.reason, DiscoveryReason::HardExclusion);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ignore_file_cannot_observe_or_control_external_content()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        fs::write(outside.path(), b"probe.txt\n")?;
        symlink(outside.path(), root.path().join(".cigarignore"))?;
        fs::write(root.path().join("probe.txt"), b"visible")?;

        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;

        let probe = plan
            .entries
            .iter()
            .find(|entry| entry.record.relative_path.as_bytes() == b"probe.txt")
            .ok_or("missing probe record")?;
        assert_eq!(probe.disposition, DiscoveryDisposition::Include);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sealed_snapshot_survives_path_substitution_and_refresh_rejects_the_old_record()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::CatalogErrorCode;
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let source = root.path().join("source.txt");
        let outside = tempfile::NamedTempFile::new()?;
        fs::write(&source, b"same")?;
        fs::write(outside.path(), b"same")?;

        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        let record = plan
            .entries
            .iter()
            .find(|entry| entry.record.relative_path.as_bytes() == b"source.txt")
            .map(|entry| entry.record.clone())
            .ok_or("missing source record")?;

        fs::remove_file(&source)?;
        symlink(outside.path(), &source)?;
        assert_eq!(
            connector
                .read(&record, ByteRange::new(0, 4)?, &context())?
                .as_slice(),
            b"same"
        );
        connector.refresh(&context())?;
        let error = connector
            .read(&record, ByteRange::new(0, 4)?, &context())
            .err()
            .ok_or("refresh must retire a substituted path from the sealed snapshot")?;
        assert!(matches!(
            error.code(),
            CatalogErrorCode::NotFound | CatalogErrorCode::SourceChanged
        ));
        Ok(())
    }

    #[test]
    fn hard_link_aliases_and_hard_linked_ignore_controls_are_excluded()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let outside_content = outside.path().join("content.txt");
        fs::write(&outside_content, b"outside")?;
        fs::hard_link(&outside_content, root.path().join("alias.txt"))?;

        let outside_ignore = outside.path().join("ignore.txt");
        fs::write(&outside_ignore, b"probe.txt\n")?;
        fs::hard_link(&outside_ignore, root.path().join(".cigarignore"))?;
        fs::write(root.path().join("probe.txt"), b"visible")?;

        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;

        let alias = plan
            .entries
            .iter()
            .find(|entry| entry.record.relative_path.as_bytes() == b"alias.txt")
            .ok_or("missing hard-link alias")?;
        assert_eq!(alias.disposition, DiscoveryDisposition::Exclude);
        assert_eq!(alias.reason, DiscoveryReason::HardExclusion);
        let probe = plan
            .entries
            .iter()
            .find(|entry| entry.record.relative_path.as_bytes() == b"probe.txt")
            .ok_or("missing probe record")?;
        assert_eq!(probe.disposition, DiscoveryDisposition::Include);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn internal_symlinks_are_capability_bounded_and_cannot_bypass_hard_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("src"))?;
        fs::write(root.path().join("src/target.txt"), b"inside")?;
        symlink("src/target.txt", root.path().join("link.txt"))?;
        fs::write(root.path().join(".env"), b"not-a-recognized-secret")?;
        symlink(".env", root.path().join("env-alias.txt"))?;
        fs::create_dir(root.path().join(".git"))?;
        fs::write(root.path().join(".git/private.txt"), b"private")?;
        symlink(".git/private.txt", root.path().join("git-alias.txt"))?;

        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let mut discovery_policy = policy()?;
        discovery_policy.follow_internal_symlinks = true;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: discovery_policy,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;

        let link = plan
            .entries
            .iter()
            .find(|entry| entry.record.relative_path.as_bytes() == b"link.txt")
            .ok_or("missing internal link")?;
        assert_eq!(link.disposition, DiscoveryDisposition::Include);
        assert_eq!(
            connector
                .read(&link.record, ByteRange::new(0, 6)?, &context())?
                .as_slice(),
            b"inside"
        );
        for path in [b"env-alias.txt".as_slice(), b"git-alias.txt".as_slice()] {
            let entry = plan
                .entries
                .iter()
                .find(|entry| entry.record.relative_path.as_bytes() == path)
                .ok_or("missing hard-path alias")?;
            assert_eq!(entry.disposition, DiscoveryDisposition::Exclude);
            assert_eq!(entry.reason, DiscoveryReason::HardExclusion);
        }
        assert_eq!(plan.included_count, 2);
        Ok(())
    }

    fn assert_recursive_walk_accepts_paths_at_the_depth_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = deep_filesystem_fixture_guard();
        let root = tempfile::tempdir()?;
        let mut directory = root.path().to_path_buf();
        for _depth in 0..MAX_FILESYSTEM_DEPTH {
            directory.push("d");
            fs::create_dir(&directory)?;
        }
        fs::write(directory.join("at-limit.rs"), b"fn at_limit() {}")?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let plan = connector.discover(
            &DiscoveryRequest {
                root: uri,
                policy: policy()?,
                include_overrides: BTreeSet::new(),
            },
            &context(),
        )?;
        assert_eq!(plan.included_count, 1);
        assert!(plan.entries.iter().any(|entry| {
            entry
                .record
                .relative_path
                .as_bytes()
                .ends_with(b"at-limit.rs")
        }));
        Ok(())
    }

    fn assert_recursive_walk_rejects_paths_beyond_the_depth_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::CatalogErrorCode;

        let _guard = deep_filesystem_fixture_guard();
        let root = tempfile::tempdir()?;
        let mut directory = root.path().to_path_buf();
        for _depth in 0..=MAX_FILESYSTEM_DEPTH {
            directory.push("d");
            fs::create_dir(&directory)?;
        }
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri.clone())?;
        let error = connector
            .discover(
                &DiscoveryRequest {
                    root: uri,
                    policy: policy()?,
                    include_overrides: BTreeSet::new(),
                },
                &context(),
            )
            .err()
            .ok_or("over-depth traversal must fail closed")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn recursive_walk_accepts_paths_at_the_depth_budget() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_recursive_walk_accepts_paths_at_the_depth_budget()
    }

    #[test]
    fn recursive_walk_rejects_paths_beyond_the_depth_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_recursive_walk_rejects_paths_beyond_the_depth_budget()
    }

    #[cfg(unix)]
    #[test]
    fn recursive_walk_depth_budget_low_fd_child() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("CIGAR_CATALOG_LOW_NOFILE_CHILD").is_none() {
            return Ok(());
        }
        assert_recursive_walk_accepts_paths_at_the_depth_budget()?;
        assert_recursive_walk_rejects_paths_beyond_the_depth_budget()
    }

    #[cfg(unix)]
    #[test]
    fn recursive_walk_depth_budget_holds_under_low_fd_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = deep_filesystem_fixture_guard();
        let executable = std::env::current_exe()?;
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -n 64 && exec \"$@\"")
            .arg("cigar-catalog-low-nofile")
            .arg(executable)
            .arg("filesystem::tests::recursive_walk_depth_budget_low_fd_child")
            .arg("--exact")
            .arg("--test-threads=1")
            .env("CIGAR_CATALOG_LOW_NOFILE_CHILD", "1")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "low-NOFILE depth subprocess failed: status={}; stdout={}; stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
            .into());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn reopened_walk_rejects_an_ancestor_swap_even_when_the_child_identity_is_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::CatalogErrorCode;

        let root = tempfile::tempdir()?;
        fs::create_dir_all(root.path().join("a/b"))?;
        let uri = SourceUri::new("file:///fixture")?;
        let connector = LocalFilesystemConnector::new(root.path(), uri)?;
        let first = connector.root.open_dir("a")?;
        let second = first.open_dir("b")?;
        let identities = [
            file_identity(&first.dir_metadata()?),
            file_identity(&second.dir_metadata()?),
        ];
        drop(second);
        drop(first);

        fs::rename(root.path().join("a"), root.path().join("old-a"))?;
        fs::create_dir(root.path().join("a"))?;
        fs::rename(root.path().join("old-a/b"), root.path().join("a/b"))?;

        let error =
            reopen_walk_directory(&connector.root, std::path::Path::new("a/b"), &identities)
                .err()
                .ok_or("ancestor replacement must fail closed")?;
        assert_eq!(error.code(), CatalogErrorCode::SourceChanged);
        Ok(())
    }
}
