//! Closed benchmark assignment and digest-bound fixture archive handling.

use crate::ConsumerError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_canon::{parse_strict_json, to_normalized_json};
use cigar_catalog::{
    BoundedBytes, ByteRange, CatalogError, CatalogErrorCode, ChangeWatermark, ConnectorContext,
    DiscoveryDisposition, DiscoveryEntry, DiscoveryPlan, DiscoveryReason, DiscoveryRequest,
    SourceChange, SourceConnector, SourceConnectorDescriptor, SourceHealth, SourceHealthState,
    SourceRecord, SourceSnapshotBatch,
};
use cigar_protocol::{
    AtomKind, ContentDigest, ExtensionMap, MediaType, RecordId, RelativePath, SchemaVersion,
    SourceSnapshot, SourceUri, UtcTimestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization as _;

const MAX_ASSIGNMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 1_024;
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 16 * 1024;

/// Candidate source identity fixed by the controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Exact Git revision.
    pub revision: String,
    /// Exact Git tree.
    pub tree: String,
}

/// Optional production subsystems exercised after materialization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSelection {
    /// Exercise handoff authority/disclosure preview.
    pub handoff: bool,
    /// Exercise the deterministic effect recovery campaign.
    pub effect: bool,
    /// Exercise structured replay comparison.
    pub replay: bool,
}

/// Execution mode for one production-backed observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerMode {
    /// Preserve measured wall-clock phase times.
    Production,
    /// Normalize non-semantic timing facts to zero for byte-identical replay.
    Recorded,
}

/// Treatment identity for paired comparison.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Treatment {
    /// Current accepted implementation.
    Champion,
    /// Proposed implementation.
    Candidate,
    /// Explicit non-CIGAR baseline.
    Baseline,
}

/// Supported semantic selector kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticType {
    /// Source-code atoms.
    SourceCode,
    /// Documentation atoms.
    Documentation,
    /// Structured schema atoms.
    Schema,
    /// Artifact atoms.
    Artifact,
}

impl SemanticType {
    pub(crate) const fn atom_kind(self) -> AtomKind {
        match self {
            Self::SourceCode => AtomKind::SourceCode,
            Self::Documentation => AtomKind::Documentation,
            Self::Schema => AtomKind::Schema,
            Self::Artifact => AtomKind::Artifact,
        }
    }
}

/// Benchmark-only retrieval/compiler intelligence selection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IntelligenceProfile {
    /// Frozen Honey behavior.
    #[serde(rename = "balanced.v1")]
    BalancedV1,
    /// First experimental versioned candidate.
    #[serde(rename = "balanced.v2-candidate.1")]
    BalancedV2Candidate1,
}

/// One strict assignment consumed by exactly one process invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    /// Must be `cigar.benchmark-assignment.v2`.
    pub schema_version: String,
    /// Parent refinement run.
    pub run_id: String,
    /// Paired experiment identity.
    pub pair_id: String,
    /// Benchmark task identity.
    pub task_id: String,
    /// Champion, candidate, or explicit baseline treatment.
    pub treatment: Treatment,
    /// Measured or deterministic-recorded execution.
    pub consumer_mode: ConsumerMode,
    /// Candidate source under test.
    pub source: SourceIdentity,
    /// Absolute path to the immutable fixture archive.
    pub archive_path: String,
    /// SHA-256 multihash of the exact canonical archive bytes.
    pub archive_digest: ContentDigest,
    /// Authorized retrieval query, without oracle labels.
    pub query: String,
    /// Human-readable compilation goal, without oracle labels.
    pub job_goal: String,
    /// Atom kind required by the contract.
    pub semantic_type: SemanticType,
    /// Exact input-token budget.
    pub token_budget: u32,
    /// Reserved consumer output budget.
    pub output_reserve_tokens: u32,
    /// Target context window.
    pub max_context_tokens: u32,
    /// Non-bypassable paths excluded before ingestion.
    pub excluded_prefixes: Vec<String>,
    /// Optional production paths to exercise.
    pub flows: FlowSelection,
    /// Pinned consumer model identity.
    pub model: String,
    /// Pinned prompt digest.
    pub prompt_digest: ContentDigest,
    /// Optional benchmark-only intelligence profile; absence is frozen balanced.v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_profile: Option<IntelligenceProfile>,
}

impl Assignment {
    /// Reads and validates one exact canonical assignment from standard input.
    pub fn read_stdin() -> Result<(Self, Vec<u8>), ConsumerError> {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(
                u64::try_from(MAX_ASSIGNMENT_BYTES + 1)
                    .map_err(|_error| ConsumerError::new("assignment_limit"))?,
            )
            .read_to_end(&mut bytes)
            .map_err(|_error| ConsumerError::new("assignment_read"))?;
        if bytes.is_empty() || bytes.len() > MAX_ASSIGNMENT_BYTES {
            return Err(ConsumerError::new("assignment_limit"));
        }
        let node =
            parse_strict_json(&bytes).map_err(|_error| ConsumerError::new("assignment_json"))?;
        let normalized =
            to_normalized_json(&node).map_err(|_error| ConsumerError::new("assignment_json"))?;
        if normalized != bytes {
            return Err(ConsumerError::new("assignment_noncanonical"));
        }
        let assignment: Self = serde_json::from_slice(&bytes)
            .map_err(|_error| ConsumerError::new("assignment_shape"))?;
        assignment.validate()?;
        Ok((assignment, bytes))
    }

    fn validate(&self) -> Result<(), ConsumerError> {
        if self.schema_version != "cigar.benchmark-assignment.v2" {
            return Err(ConsumerError::new("assignment_version"));
        }
        for identifier in [
            self.run_id.as_str(),
            self.pair_id.as_str(),
            self.task_id.as_str(),
            self.model.as_str(),
        ] {
            validate_identifier(identifier)?;
        }
        for text in [self.query.as_str(), self.job_goal.as_str()] {
            if text.is_empty()
                || text.len() > MAX_TEXT_BYTES
                || text.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(ConsumerError::new("assignment_text"));
            }
        }
        if !valid_git_object(&self.source.revision) || !valid_git_object(&self.source.tree) {
            return Err(ConsumerError::new("assignment_source"));
        }
        if self.token_budget == 0
            || self.output_reserve_tokens == 0
            || self.max_context_tokens
                < self
                    .token_budget
                    .checked_add(self.output_reserve_tokens)
                    .ok_or_else(|| ConsumerError::new("assignment_budget"))?
        {
            return Err(ConsumerError::new("assignment_budget"));
        }
        let archive = Path::new(&self.archive_path);
        if !archive.is_absolute() || archive.as_os_str().is_empty() {
            return Err(ConsumerError::new("assignment_archive"));
        }
        let mut previous: Option<&str> = None;
        for prefix in &self.excluded_prefixes {
            validate_relative_path(prefix)?;
            if previous.is_some_and(|value| value >= prefix.as_str()) {
                return Err(ConsumerError::new("assignment_exclusions"));
            }
            previous = Some(prefix);
        }
        Ok(())
    }

    /// Returns validated protocol path prefixes.
    pub fn exclusion_paths(&self) -> Result<Vec<RelativePath>, ConsumerError> {
        self.excluded_prefixes
            .iter()
            .map(|path| {
                RelativePath::new(path.as_bytes().to_vec())
                    .map_err(|_error| ConsumerError::new("assignment_exclusions"))
            })
            .collect()
    }
}

/// One source fixture retained by the archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveFile {
    path: String,
    media_type: MediaType,
    bytes_base64url: String,
}

/// Canonical, bounded, content-addressed fixture archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureArchive {
    schema_version: String,
    files: Vec<ArchiveFile>,
}

/// Extracted fixture root and the exact media types admitted by policy.
pub struct ExtractedFixture {
    directory: TempDir,
    media_types: BTreeSet<MediaType>,
    archive_bytes: Vec<u8>,
    archive_digest: ContentDigest,
    entries: Vec<FixtureEntry>,
}

#[derive(Clone)]
struct FixtureEntry {
    path: String,
    media_type: MediaType,
    size_bytes: u64,
    content_digest: ContentDigest,
}

impl ExtractedFixture {
    /// Loads, verifies, and safely extracts an assignment's archive.
    pub fn from_assignment(assignment: &Assignment) -> Result<Self, ConsumerError> {
        let path = PathBuf::from(&assignment.archive_path);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_error| ConsumerError::new("archive_open"))?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.len()
                > u64::try_from(MAX_ARCHIVE_BYTES)
                    .map_err(|_error| ConsumerError::new("archive_limit"))?
        {
            return Err(ConsumerError::new("archive_metadata"));
        }
        let mut archive_bytes = Vec::new();
        File::open(&path)
            .map_err(|_error| ConsumerError::new("archive_open"))?
            .take(
                u64::try_from(MAX_ARCHIVE_BYTES + 1)
                    .map_err(|_error| ConsumerError::new("archive_limit"))?,
            )
            .read_to_end(&mut archive_bytes)
            .map_err(|_error| ConsumerError::new("archive_read"))?;
        if archive_bytes.is_empty() || archive_bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(ConsumerError::new("archive_limit"));
        }
        if multihash(&archive_bytes)? != assignment.archive_digest {
            return Err(ConsumerError::new("archive_digest"));
        }
        let node = parse_strict_json(&archive_bytes)
            .map_err(|_error| ConsumerError::new("archive_json"))?;
        if to_normalized_json(&node).map_err(|_error| ConsumerError::new("archive_json"))?
            != archive_bytes
        {
            return Err(ConsumerError::new("archive_noncanonical"));
        }
        let archive: FixtureArchive = serde_json::from_slice(&archive_bytes)
            .map_err(|_error| ConsumerError::new("archive_shape"))?;
        if archive.schema_version != "cigar.fixture-archive.v1"
            || archive.files.is_empty()
            || archive.files.len() > MAX_ARCHIVE_FILES
        {
            return Err(ConsumerError::new("archive_shape"));
        }
        let directory =
            tempfile::tempdir().map_err(|_error| ConsumerError::new("fixture_create"))?;
        let mut media_types = BTreeSet::new();
        let mut entries = Vec::with_capacity(archive.files.len());
        let mut previous: Option<&str> = None;
        let mut total = 0_usize;
        for entry in &archive.files {
            validate_relative_path(&entry.path)?;
            if previous.is_some_and(|value| value >= entry.path.as_str())
                || detected_media_type(&entry.path)? != entry.media_type.as_str()
            {
                return Err(ConsumerError::new("archive_entries"));
            }
            previous = Some(&entry.path);
            let bytes = URL_SAFE_NO_PAD
                .decode(entry.bytes_base64url.as_bytes())
                .map_err(|_error| ConsumerError::new("archive_base64"))?;
            if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
                return Err(ConsumerError::new("archive_file_limit"));
            }
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| ConsumerError::new("archive_limit"))?;
            if total > MAX_ARCHIVE_BYTES {
                return Err(ConsumerError::new("archive_limit"));
            }
            extract_file(directory.path(), &entry.path, &bytes)?;
            media_types.insert(entry.media_type.clone());
            entries.push(FixtureEntry {
                path: entry.path.clone(),
                media_type: entry.media_type.clone(),
                size_bytes: u64::try_from(bytes.len())
                    .map_err(|_error| ConsumerError::new("archive_file_limit"))?,
                content_digest: multihash(&bytes)?,
            });
        }
        let archive_digest = multihash(&archive_bytes)?;
        Ok(Self {
            directory,
            media_types,
            archive_bytes,
            archive_digest,
            entries,
        })
    }

    /// Exact media types declared by the verified archive.
    #[must_use]
    pub const fn media_types(&self) -> &BTreeSet<MediaType> {
        &self.media_types
    }

    /// Exact canonical archive bytes, retained for digest verification only.
    #[must_use]
    pub fn archive_bytes(&self) -> &[u8] {
        &self.archive_bytes
    }

    /// Creates the deterministic benchmark connector over the extracted files.
    pub fn connector(&self, root: SourceUri) -> FixtureConnector {
        FixtureConnector {
            directory: self.directory.path().to_path_buf(),
            root,
            entries: self.entries.clone(),
            archive_digest: self.archive_digest.clone(),
        }
    }
}

/// Deterministic archive connector used only to drive the production ingestion service.
///
/// The adapter reads extracted temporary files but derives every public record identity from
/// canonical path and content bytes, never filesystem inode or timestamp metadata.
pub struct FixtureConnector {
    directory: PathBuf,
    root: SourceUri,
    entries: Vec<FixtureEntry>,
    archive_digest: ContentDigest,
}

impl FixtureConnector {
    fn records(&self) -> Result<Vec<SourceRecord>, CatalogError> {
        self.entries
            .iter()
            .map(|entry| {
                let path_digest = multihash(entry.path.as_bytes())
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
                Ok(SourceRecord {
                    record_id: format!("fixture:{}", path_digest.as_str()),
                    relative_path: RelativePath::new(entry.path.as_bytes().to_vec())
                        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
                    revision: entry.content_digest.as_str().to_owned(),
                    size_bytes: entry.size_bytes,
                    executable: false,
                    media_type: entry.media_type.clone(),
                    content_digest: Some(entry.content_digest.clone()),
                })
            })
            .collect()
    }
}

impl SourceConnector for FixtureConnector {
    fn descriptor(&self) -> SourceConnectorDescriptor {
        SourceConnectorDescriptor {
            id: "cigar.benchmark-fixture.v1".to_owned(),
            root: self.root.clone(),
        }
    }

    fn discover(
        &self,
        request: &DiscoveryRequest,
        context: &ConnectorContext,
    ) -> Result<DiscoveryPlan, CatalogError> {
        context.check()?;
        request.policy.validate()?;
        if request.root != self.root || !request.include_overrides.is_empty() {
            return Err(CatalogError::new(CatalogErrorCode::Denied));
        }
        let mut included_count = 0_u64;
        let mut included_bytes = 0_u64;
        let mut entries = Vec::new();
        for record in self.records()? {
            context.check()?;
            let excluded =
                request.policy.excluded_prefixes.iter().any(|prefix| {
                    path_has_prefix(record.relative_path.as_bytes(), prefix.as_bytes())
                });
            let permitted_media = request
                .policy
                .allowed_media_types
                .contains(&record.media_type);
            let next_count = included_count.saturating_add(1);
            let next_bytes = included_bytes.saturating_add(record.size_bytes);
            let within_limits = record.size_bytes <= request.policy.max_record_bytes
                && usize::try_from(next_count)
                    .ok()
                    .is_some_and(|count| count <= request.policy.max_items)
                && next_bytes <= request.policy.max_total_bytes;
            let (disposition, reason) = if excluded {
                (
                    DiscoveryDisposition::Exclude,
                    DiscoveryReason::PolicyExclusion,
                )
            } else if !permitted_media {
                (DiscoveryDisposition::Exclude, DiscoveryReason::MediaType)
            } else if !within_limits {
                (DiscoveryDisposition::Exclude, DiscoveryReason::SizeLimit)
            } else {
                included_count = next_count;
                included_bytes = next_bytes;
                (DiscoveryDisposition::Include, DiscoveryReason::Eligible)
            };
            entries.push(DiscoveryEntry {
                record,
                disposition,
                reason,
            });
        }
        #[derive(Serialize)]
        struct PlanRow<'a> {
            path: &'a str,
            revision: &'a str,
            disposition: &'static str,
            reason: &'static str,
        }
        let rows: Vec<_> = entries
            .iter()
            .map(|entry| PlanRow {
                path: std::str::from_utf8(entry.record.relative_path.as_bytes())
                    .unwrap_or_default(),
                revision: &entry.record.revision,
                disposition: match entry.disposition {
                    DiscoveryDisposition::Include => "include",
                    DiscoveryDisposition::Exclude => "exclude",
                    DiscoveryDisposition::Quarantine => "quarantine",
                },
                reason: match entry.reason {
                    DiscoveryReason::HardExclusion => "hard_exclusion",
                    DiscoveryReason::SecretDetected => "secret_detected",
                    DiscoveryReason::PolicyExclusion => "policy_exclusion",
                    DiscoveryReason::CigarIgnore => "cigar_ignore",
                    DiscoveryReason::GitIgnore => "git_ignore",
                    DiscoveryReason::SizeLimit => "size_limit",
                    DiscoveryReason::MediaType => "media_type",
                    DiscoveryReason::UserOverride => "user_override",
                    DiscoveryReason::Eligible => "eligible",
                },
            })
            .collect();
        let bytes = serde_json::to_vec(&rows)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let plan_digest = multihash(&bytes)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        Ok(DiscoveryPlan {
            root: self.root.clone(),
            entries,
            included_count,
            included_bytes,
            plan_digest,
        })
    }

    fn snapshot(
        &self,
        _previous_revision: Option<&str>,
        context: &ConnectorContext,
    ) -> Result<SourceSnapshotBatch, CatalogError> {
        context.check()?;
        let records = self.records()?;
        let total_bytes = records.iter().try_fold(0_u64, |total, record| {
            total
                .checked_add(record.size_bytes)
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))
        })?;
        Ok(SourceSnapshotBatch {
            snapshot: SourceSnapshot {
                schema_version: SchemaVersion::new("cigar.source-snapshot", 1)
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
                snapshot_id: RecordId::new("01890f47-8e7d-7b42-a1d2-000000000104")
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
                source_uri: self.root.clone(),
                source_revision: self.archive_digest.as_str().to_owned(),
                captured_at: UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?,
                manifest_digest: self.archive_digest.clone(),
                entry_count: u64::try_from(records.len())
                    .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?,
                total_bytes,
                complete: true,
                extensions: ExtensionMap::default(),
            },
            records,
        })
    }

    fn read(
        &self,
        record: &SourceRecord,
        range: ByteRange,
        context: &ConnectorContext,
    ) -> Result<BoundedBytes, CatalogError> {
        context.check()?;
        let expected = self
            .records()?
            .into_iter()
            .find(|candidate| candidate.relative_path == record.relative_path)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::SourceChanged))?;
        if expected != *record
            || range.start.checked_add(range.length) != Some(record.size_bytes)
            || range.start != 0
        {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        let relative = std::str::from_utf8(record.relative_path.as_bytes())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        validate_relative_path(relative)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        let mut file = File::open(self.directory.join(relative))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        file.seek(SeekFrom::Start(range.start))
            .map_err(|_error| CatalogError::new(CatalogErrorCode::Unavailable))?;
        let length = usize::try_from(range.length)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)
            .map_err(|_error| CatalogError::new(CatalogErrorCode::SourceChanged))?;
        if multihash(&bytes).map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?
            != expected
                .content_digest
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::InvalidRecord))?
        {
            return Err(CatalogError::new(CatalogErrorCode::SourceChanged));
        }
        BoundedBytes::new(bytes)
    }

    fn subscribe(
        &self,
        _watermark: ChangeWatermark,
        _limit: usize,
        context: &ConnectorContext,
    ) -> Result<Vec<SourceChange>, CatalogError> {
        context.check()?;
        Ok(Vec::new())
    }

    fn health(&self) -> SourceHealth {
        SourceHealth {
            state: SourceHealthState::Ready,
            watermark: ChangeWatermark(1),
        }
    }
}

fn path_has_prefix(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix || (path.starts_with(prefix) && path.get(prefix.len()).copied() == Some(b'/'))
}

fn extract_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), ConsumerError> {
    let relative_path = Path::new(relative);
    let parent = relative_path
        .parent()
        .ok_or_else(|| ConsumerError::new("archive_path"))?;
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(segment) = component else {
            return Err(ConsumerError::new("archive_path"));
        };
        current.push(segment);
        match std::fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&current)
                    .map_err(|_error| ConsumerError::new("archive_extract"))?;
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(ConsumerError::new("archive_extract"));
                }
            }
            Err(_error) => return Err(ConsumerError::new("archive_extract")),
        }
    }
    let target = root.join(relative_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|_error| ConsumerError::new("archive_extract"))?;
    file.write_all(bytes)
        .map_err(|_error| ConsumerError::new("archive_extract"))?;
    file.sync_all()
        .map_err(|_error| ConsumerError::new("archive_extract"))
}

fn validate_identifier(value: &str) -> Result<(), ConsumerError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Err(ConsumerError::new("assignment_identifier"))
    } else {
        Ok(())
    }
}

fn valid_git_object(value: &str) -> bool {
    (40..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_relative_path(value: &str) -> Result<(), ConsumerError> {
    let segments: Vec<_> = value.split('/').collect();
    if value.is_empty()
        || value.len() > 4_096
        || value.contains('\\')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.nfc().collect::<String>() != value
        || segments.len() > 32
        || segments
            .iter()
            .any(|segment| segment.is_empty() || matches!(*segment, "." | ".."))
        || segments.iter().any(|segment| segment.len() > 255)
    {
        return Err(ConsumerError::new("archive_path"));
    }
    let path = Path::new(value);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
        || path
            .components()
            .any(|component| component.as_os_str().as_encoded_bytes().len() > 255)
    {
        return Err(ConsumerError::new("archive_path"));
    }
    Ok(())
}

fn detected_media_type(path: &str) -> Result<&'static str, ConsumerError> {
    let extension = path
        .as_bytes()
        .rsplit(|byte| *byte == b'.')
        .next()
        .unwrap_or_default();
    match extension {
        b"txt" => Ok("text/plain"),
        b"md" | b"markdown" => Ok("text/markdown"),
        b"json" => Ok("application/json"),
        b"yaml" | b"yml" => Ok("application/yaml"),
        b"toml" => Ok("application/toml"),
        b"xml" => Ok("application/xml"),
        b"proto" => Ok("text/x-protobuf"),
        b"rs" => Ok("text/x-rust"),
        b"ts" | b"tsx" => Ok("text/typescript"),
        b"js" | b"jsx" => Ok("text/javascript"),
        b"py" => Ok("text/x-python"),
        b"go" => Ok("text/x-go"),
        b"java" => Ok("text/x-java"),
        b"c" | b"h" => Ok("text/x-c"),
        b"cc" | b"cpp" | b"cxx" | b"hh" | b"hpp" | b"hxx" => Ok("text/x-c++"),
        _ => Err(ConsumerError::new("archive_media_type")),
    }
}

/// Computes the repository-wide SHA-256 multihash representation.
pub fn multihash(bytes: &[u8]) -> Result<ContentDigest, ConsumerError> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(68);
    encoded.push_str("1220");
    use std::fmt::Write as _;
    for byte in hash {
        write!(&mut encoded, "{byte:02x}").map_err(|_error| ConsumerError::new("digest_format"))?;
    }
    ContentDigest::new(encoded).map_err(|_error| ConsumerError::new("digest_format"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_multihash_matches_the_repository_profile() -> Result<(), ConsumerError> {
        let digest = multihash(b"abc")?;
        assert_eq!(
            digest.as_str(),
            "1220ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        Ok(())
    }

    #[test]
    fn path_validation_and_prefix_matching_are_segment_safe() {
        for invalid in [
            "",
            "/absolute",
            "trailing/",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            "a/\u{0000}b",
        ] {
            assert!(validate_relative_path(invalid).is_err(), "{invalid:?}");
        }
        assert!(validate_relative_path("allowed/nested.txt").is_ok());
        assert!(path_has_prefix(b"denied/secret.txt", b"denied"));
        assert!(path_has_prefix(b"denied", b"denied"));
        assert!(!path_has_prefix(b"denied-adjacent/file.txt", b"denied"));
    }

    #[test]
    fn media_type_is_bound_to_the_canonical_extension() -> Result<(), ConsumerError> {
        let rust = detected_media_type("src/lib.rs")?;
        let markdown = detected_media_type("README.md")?;
        assert_eq!(rust, "text/x-rust");
        assert_eq!(markdown, "text/markdown");
        assert!(detected_media_type("secret.bin").is_err());
        Ok(())
    }
}
