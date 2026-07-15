//! Backend-neutral source discovery, streaming, atomization, and invalidation contracts.

use cigar_protocol::{
    AtomKind, Classification, ContentDigest, ContextAtomV1, ContextEdge, GovernanceEnvelope,
    InstructionAuthority, MediaType, QualityEnvelope, RecordId, RelativePath, ScopeEnvelope,
    SourceSnapshot, SourceUri, VersionId,
};
use cigar_store::{CancellationToken, StoreRevision};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Instant;

/// Maximum entries returned by one connector operation.
pub const MAX_CONNECTOR_ITEMS: usize = 100_000;
/// Maximum bytes returned by one bounded source read.
pub const MAX_CONNECTOR_READ_BYTES: u64 = 67_108_864;
/// Maximum aggregate bytes retained by one sealed local snapshot.
pub const MAX_CONNECTOR_SNAPSHOT_BYTES: u64 = 268_435_456;
/// Maximum atomization input bytes.
pub const MAX_ATOMIZATION_BYTES: usize = 67_108_864;
/// Maximum organization secret patterns attached to one discovery policy.
pub const MAX_SECRET_PATTERNS: usize = 128;
/// Stable identity for the capability-confined local filesystem connector.
pub const FILESYSTEM_CONNECTOR_ID: &str = "cigar.builtin.filesystem.v1";
/// Stable identity for the immutable committed-object Git connector.
pub const GIT_CONNECTOR_ID: &str = "cigar.builtin.git.v1";

/// Rejects traversal/platform-ambiguous paths and portable case/Unicode collisions.
///
/// Connector paths are exact bytes, but every downstream surface must still address one record
/// unambiguously.  In particular, a case-sensitive source can otherwise publish two records that
/// collapse to one name on the default macOS filesystem, and canonically equivalent Unicode names
/// can be substituted by a client that normalizes paths.  Invalid UTF-8 remains supported and is
/// compared with an ASCII-only fold.
pub(crate) fn validate_source_paths<'a>(
    paths: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), CatalogError> {
    let mut portable = BTreeSet::new();
    for path in paths {
        if path.is_empty()
            || path.contains(&b'\\')
            || path
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || matches!(component, b"." | b".."))
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let key = portable_path_key(path);
        if !portable.insert(key) {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
    }
    Ok(())
}

/// Rejects well-known credential and repository-control names without relying on host casing.
pub(crate) fn sensitive_source_path(path: &[u8]) -> bool {
    const EXACT_NAMES: &[&[u8]] = &[
        b".cigarignore",
        b".env",
        b".envrc",
        b".git-credentials",
        b".gitattributes",
        b".gitignore",
        b".gitmodules",
        b".netrc",
        b".npmrc",
        b".pypirc",
        b"_netrc",
        b"application_default_credentials.json",
        b"auth.json",
        b"credentials",
        b"credentials.json",
        b"credentials.toml",
        b"id_dsa",
        b"id_ecdsa",
        b"id_ed25519",
        b"id_rsa",
        b"secrets.json",
        b"secrets.yaml",
        b"secrets.yml",
    ];
    const SENSITIVE_SUFFIXES: &[&[u8]] =
        &[b".jks", b".key", b".keystore", b".p12", b".pem", b".pfx"];

    let name = path.split(|byte| *byte == b'/').next_back().unwrap_or(path);
    EXACT_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
        || name
            .get(..b".env.".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b".env."))
        || SENSITIVE_SUFFIXES.iter().any(|suffix| {
            name.get(name.len().saturating_sub(suffix.len())..)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix))
        })
}

fn portable_path_key(path: &[u8]) -> Vec<u8> {
    if let Ok(value) = std::str::from_utf8(path) {
        let normalized = cigar_canon::normalize_nfc(value);
        let lowered: String = normalized.chars().flat_map(char::to_lowercase).collect();
        cigar_canon::normalize_nfc(&lowered).into_bytes()
    } else {
        path.iter().map(u8::to_ascii_lowercase).collect()
    }
}

/// Stable content-free catalog and connector failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogErrorCode {
    /// Root, path, range, MIME, revision, or descriptor metadata is invalid.
    InvalidMetadata,
    /// Policy forbids the requested discovery, read, or publication.
    Denied,
    /// Requested source record or revision does not exist.
    NotFound,
    /// Source content changed after preview or snapshot selection.
    SourceChanged,
    /// A byte, item, graph, or output bound was exceeded.
    LimitExceeded,
    /// Cooperative cancellation was requested.
    Cancelled,
    /// The operation exceeded its exact deadline.
    DeadlineExceeded,
    /// Connector, parser, filesystem, or repository state was unavailable.
    Unavailable,
    /// Atom, edge, lifecycle, or invalidation semantics are inconsistent.
    InvalidRecord,
}

/// Content-free catalog error that never formats paths, bytes, or secret findings.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CatalogError {
    code: CatalogErrorCode,
}

impl CatalogError {
    /// Creates a content-free error from one stable category.
    #[must_use]
    pub const fn new(code: CatalogErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn code(self) -> CatalogErrorCode {
        self.code
    }
}

impl fmt::Debug for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "catalog operation failed: {:?}", self.code)
    }
}

impl std::error::Error for CatalogError {}

/// Cancellation and exact monotonic deadline shared by connector operations.
#[derive(Clone)]
pub struct ConnectorContext {
    cancellation: CancellationToken,
    deadline: Instant,
}

impl ConnectorContext {
    /// Creates one bounded connector operation context.
    #[must_use]
    pub const fn new(cancellation: CancellationToken, deadline: Instant) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    /// Fails when cancellation or the monotonic deadline has been reached.
    pub fn check(&self) -> Result<(), CatalogError> {
        if self.cancellation.is_cancelled() {
            Err(CatalogError::new(CatalogErrorCode::Cancelled))
        } else if Instant::now() >= self.deadline {
            Err(CatalogError::new(CatalogErrorCode::DeadlineExceeded))
        } else {
            Ok(())
        }
    }

    /// Returns the shared cancellation capability for a transactional boundary.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl fmt::Debug for ConnectorContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorContext")
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// Exact bounded byte range for a stable source record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    /// Inclusive byte offset.
    pub start: u64,
    /// Number of requested bytes.
    pub length: u64,
}

impl ByteRange {
    /// Creates a non-empty range within the connector read maximum.
    pub fn new(start: u64, length: u64) -> Result<Self, CatalogError> {
        if length == 0 || length > MAX_CONNECTOR_READ_BYTES || start.checked_add(length).is_none() {
            Err(CatalogError::new(CatalogErrorCode::LimitExceeded))
        } else {
            Ok(Self { start, length })
        }
    }
}

/// Caller-owned connector bytes whose length cannot exceed the declared range.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedBytes(Vec<u8>);

impl BoundedBytes {
    /// Validates and owns one bounded read result.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CatalogError> {
        if bytes.len()
            > usize::try_from(MAX_CONNECTOR_READ_BYTES)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
        {
            Err(CatalogError::new(CatalogErrorCode::LimitExceeded))
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns exact source bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for BoundedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedBytes")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// One stable record address emitted by discovery and snapshot operations.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceRecord {
    /// Connector-stable record identity independent of its current path.
    pub record_id: String,
    /// Exact platform-neutral source-relative path.
    pub relative_path: RelativePath,
    /// Immutable connector revision containing this record.
    pub revision: String,
    /// Exact record size.
    pub size_bytes: u64,
    /// Whether the immutable source revision is executable.
    pub executable: bool,
    /// Deterministically detected media type.
    pub media_type: MediaType,
    /// Digest of exact bytes when discovery policy permits hashing.
    pub content_digest: Option<ContentDigest>,
}

impl fmt::Debug for SourceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceRecord")
            .field("record_id_bytes", &self.record_id.len())
            .field("path_bytes", &self.relative_path.as_bytes().len())
            .field("revision_bytes", &self.revision.len())
            .field("size_bytes", &self.size_bytes)
            .field("executable", &self.executable)
            .field("media_type", &self.media_type)
            .field("hashed", &self.content_digest.is_some())
            .finish()
    }
}

/// Ordered policy outcome for one preview entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryDisposition {
    /// Entry is eligible for ingestion.
    Include,
    /// Entry is omitted without content processing.
    Exclude,
    /// Entry is isolated pending explicit review.
    Quarantine,
}

/// Stable reason showing the first decisive discovery-policy stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiscoveryReason {
    /// Hard platform or secret-path exclusion.
    HardExclusion,
    /// Content or path matched a configured secret detector before indexing.
    SecretDetected,
    /// Organization or tenant policy exclusion.
    PolicyExclusion,
    /// `.cigarignore` exclusion.
    CigarIgnore,
    /// Git ignore exclusion.
    GitIgnore,
    /// File size exceeds the configured maximum.
    SizeLimit,
    /// Media type is not permitted.
    MediaType,
    /// User preview override permitted by policy.
    UserOverride,
    /// Entry passed every discovery stage.
    Eligible,
}

/// One explicit, inspectable first-ingestion preview decision.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryEntry {
    /// Stable source record metadata.
    pub record: SourceRecord,
    /// Include, exclude, or quarantine decision.
    pub disposition: DiscoveryDisposition,
    /// First decisive ordered policy reason.
    pub reason: DiscoveryReason,
}

impl fmt::Debug for DiscoveryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryEntry")
            .field("record", &self.record)
            .field("disposition", &self.disposition)
            .field("reason", &self.reason)
            .finish()
    }
}

/// Ordered discovery policy; user overrides cannot bypass hard or policy exclusions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryPolicy {
    /// Maximum included source entries.
    pub max_items: usize,
    /// Maximum aggregate included source bytes.
    pub max_total_bytes: u64,
    /// Maximum bytes for one included source record.
    pub max_record_bytes: u64,
    /// Exact path prefixes excluded by non-bypassable policy.
    pub excluded_prefixes: Vec<RelativePath>,
    /// Permitted media types; empty denies every type.
    pub allowed_media_types: BTreeSet<MediaType>,
    /// Whether authorized preview overrides may broaden ignore-only decisions.
    pub allow_user_broadening: bool,
    /// Whether in-root symlink targets may be followed.
    pub follow_internal_symlinks: bool,
    /// Bounded organization-specific byte prefixes that force quarantine.
    pub secret_patterns: Vec<Vec<u8>>,
}

impl DiscoveryPolicy {
    /// Validates explicit item and byte ceilings.
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.max_items == 0
            || self.max_items > MAX_CONNECTOR_ITEMS
            || self.max_total_bytes == 0
            || self.max_total_bytes > MAX_CONNECTOR_SNAPSHOT_BYTES
            || self.max_record_bytes == 0
            || self.max_record_bytes > self.max_total_bytes
            || self.max_record_bytes > MAX_CONNECTOR_READ_BYTES
            || self.secret_patterns.len() > MAX_SECRET_PATTERNS
            || self
                .secret_patterns
                .iter()
                .any(|pattern| pattern.len() < 4 || pattern.len() > 256)
        {
            Err(CatalogError::new(CatalogErrorCode::LimitExceeded))
        } else {
            Ok(())
        }
    }
}

/// One discovery request with explicit root, policy, and authorized overrides.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryRequest {
    /// Authorized connector root.
    pub root: SourceUri,
    /// Ordered discovery policy.
    pub policy: DiscoveryPolicy,
    /// Paths explicitly included after preview, subject to policy.
    pub include_overrides: BTreeSet<RelativePath>,
}

impl fmt::Debug for DiscoveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryRequest")
            .field("policy", &self.policy)
            .field("override_count", &self.include_overrides.len())
            .finish_non_exhaustive()
    }
}

/// Deterministic explicit preview required before initial ingestion.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryPlan {
    /// Root covered by this plan.
    pub root: SourceUri,
    /// Sorted preview entries.
    pub entries: Vec<DiscoveryEntry>,
    /// Included entry count.
    pub included_count: u64,
    /// Included aggregate bytes.
    pub included_bytes: u64,
    /// Digest of normalized preview semantics.
    pub plan_digest: ContentDigest,
}

impl fmt::Debug for DiscoveryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryPlan")
            .field("entry_count", &self.entries.len())
            .field("included_count", &self.included_count)
            .field("included_bytes", &self.included_bytes)
            .field("plan_digest", &self.plan_digest)
            .finish_non_exhaustive()
    }
}

/// Complete atomic connector snapshot and its sorted stable records.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceSnapshotBatch {
    /// Protocol snapshot metadata.
    pub snapshot: SourceSnapshot,
    /// Sorted records included in the snapshot manifest.
    pub records: Vec<SourceRecord>,
}

impl fmt::Debug for SourceSnapshotBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSnapshotBatch")
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// Monotonic connector change position.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChangeWatermark(pub u64);

/// Closed source change registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// New source record.
    Added,
    /// Existing identity has new bytes or metadata.
    Modified,
    /// Existing identity was removed.
    Deleted,
    /// Stable identity moved to a new path.
    Renamed,
    /// Permission or executable metadata changed.
    PermissionChanged,
    /// Watcher overflow requires a complete refresh.
    Overflow,
}

/// One bounded connector change event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceChange {
    /// Monotonic event position.
    pub watermark: ChangeWatermark,
    /// Change class.
    pub kind: ChangeKind,
    /// Current record when one remains.
    pub record: Option<SourceRecord>,
    /// Prior path for a rename without exposing it through formatting.
    pub prior_path: Option<RelativePath>,
}

/// Stable health state for connector readiness decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceHealthState {
    /// Connector can serve bounded operations.
    Ready,
    /// Connector can serve reads but should be refreshed.
    Degraded,
    /// Connector cannot safely serve requests.
    Unavailable,
}

/// Content-free source health report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceHealth {
    /// Current state.
    pub state: SourceHealthState,
    /// Last observed change position.
    pub watermark: ChangeWatermark,
}

/// Stable source connector contract shared by filesystem, Git, and future adapters.
pub trait SourceConnector: Send + Sync {
    /// Binds the injected implementation to its exact authorized root without exposing content.
    fn descriptor(&self) -> SourceConnectorDescriptor;
    /// Produces an explicit preview before first ingestion.
    fn discover(
        &self,
        request: &DiscoveryRequest,
        context: &ConnectorContext,
    ) -> Result<DiscoveryPlan, CatalogError>;
    /// Produces a complete atomic snapshot after an optional prior revision.
    fn snapshot(
        &self,
        previous_revision: Option<&str>,
        context: &ConnectorContext,
    ) -> Result<SourceSnapshotBatch, CatalogError>;
    /// Reads one exact bounded range from one immutable record revision.
    fn read(
        &self,
        record: &SourceRecord,
        range: ByteRange,
        context: &ConnectorContext,
    ) -> Result<BoundedBytes, CatalogError>;
    /// Returns bounded ordered changes strictly after the supplied watermark.
    fn subscribe(
        &self,
        watermark: ChangeWatermark,
        limit: usize,
        context: &ConnectorContext,
    ) -> Result<Vec<SourceChange>, CatalogError>;
    /// Returns content-free connector health.
    fn health(&self) -> SourceHealth;
}

/// Content-free identity of one configured connector implementation and root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConnectorDescriptor {
    /// Stable connector implementation identity.
    pub id: String,
    /// Exact root this connector capability was opened against.
    pub root: SourceUri,
}

/// Immutable atomizer capability metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomizerDescriptor {
    /// Stable atomizer identity.
    pub id: String,
    /// Deterministic semantic version.
    pub version: String,
    /// Sorted supported media types.
    pub media_types: BTreeSet<MediaType>,
    /// Maximum accepted bytes.
    pub max_input_bytes: usize,
    /// Sorted semantic atom kinds the adapter may produce.
    pub produced_kinds: BTreeSet<AtomKind>,
    /// Maximum instruction authority this configured atomizer may assign.
    pub authority_ceiling: InstructionAuthority,
    /// Digest of this atomizer identity, version, scope, governance, quality, and feature profile.
    pub configuration_digest: ContentDigest,
    /// Exact tenant/project scope the atomizer must assign.
    pub scope: ScopeEnvelope,
    /// Exact governance envelope the atomizer must assign.
    pub governance: GovernanceEnvelope,
    /// Exact quality envelope the atomizer must assign.
    pub quality: QualityEnvelope,
    /// Exact lexical-index eligibility the atomizer must assign.
    pub lexical_enabled: bool,
    /// Exact embedding eligibility the atomizer must assign.
    pub embedding_eligible: bool,
    /// Inputs whose changes invalidate this atomizer's output.
    pub invalidation: AtomizerInvalidation,
}

/// Digests the exact trusted configuration one atomizer must declare and reproduce in its output.
pub fn atomizer_configuration_digest(
    id: &str,
    version: &str,
    scope: &ScopeEnvelope,
    governance: &GovernanceEnvelope,
    quality: QualityEnvelope,
    lexical_enabled: bool,
    embedding_eligible: bool,
) -> Result<ContentDigest, CatalogError> {
    if id.is_empty()
        || id.len() > 256
        || version.is_empty()
        || version.len() > 64
        || id
            .bytes()
            .chain(version.bytes())
            .any(|byte| byte.is_ascii_control())
        || scope.project_ids.is_empty()
        || scope
            .project_ids
            .windows(2)
            .any(|pair| pair.first() >= pair.get(1))
        || governance.allowed_purposes.is_empty()
        || governance
            .allowed_purposes
            .windows(2)
            .any(|pair| pair.first() >= pair.get(1))
        || governance
            .processor_constraints
            .windows(2)
            .any(|pair| pair.first() >= pair.get(1))
        || governance
            .allowed_purposes
            .iter()
            .chain(&governance.processor_constraints)
            .any(|value| {
                value.is_empty()
                    || value.len() > 256
                    || value.bytes().any(|byte| byte.is_ascii_control())
            })
        || quality.authority == 0
    {
        return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-ATOMIZER-CONFIGURATION\0v1\0");
    hash_framed(&mut hasher, id.as_bytes())?;
    hash_framed(&mut hasher, version.as_bytes())?;
    hash_framed(&mut hasher, scope.tenant_id.as_str().as_bytes())?;
    hash_sequence(
        &mut hasher,
        scope
            .project_ids
            .iter()
            .map(|project| project.as_str().as_bytes()),
    )?;
    hasher.update([classification_code(governance.classification)]);
    hash_sequence(
        &mut hasher,
        governance.allowed_purposes.iter().map(String::as_bytes),
    )?;
    hash_sequence(
        &mut hasher,
        governance
            .processor_constraints
            .iter()
            .map(String::as_bytes),
    )?;
    hasher.update([instruction_authority_code(governance.instruction_authority)]);
    hasher.update(quality.confidence.millionths().to_be_bytes());
    hasher.update(quality.coverage.millionths().to_be_bytes());
    hasher.update(quality.authority.to_be_bytes());
    hasher.update([u8::from(lexical_enabled), u8::from(embedding_eligible)]);
    content_digest(hasher)
}

/// Digests one canonical, strictly ordered atomizer registry.
///
/// The digest deliberately binds ordering as well as implementation and profile identities. This
/// prevents durable source configuration from being reattached to a substituted, partial, or
/// differently ordered runtime registry after restart.
pub fn atomizer_registry_digest(
    descriptors: &[AtomizerDescriptor],
) -> Result<ContentDigest, CatalogError> {
    if descriptors.is_empty()
        || descriptors.windows(2).any(|pair| {
            pair.first().zip(pair.get(1)).is_none_or(|(left, right)| {
                (&left.id, &left.version) >= (&right.id, &right.version)
            })
        })
    {
        return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-ATOMIZER-REGISTRY\0v1\0");
    hasher.update(
        u64::try_from(descriptors.len())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    let mut media_registry = BTreeSet::new();
    for descriptor in descriptors {
        if descriptor.id.is_empty()
            || descriptor.id.len() > 256
            || descriptor.version.is_empty()
            || descriptor.version.len() > 64
            || descriptor.max_input_bytes == 0
            || descriptor.max_input_bytes > MAX_ATOMIZATION_BYTES
            || descriptor.media_types.is_empty()
            || descriptor.produced_kinds.is_empty()
            || descriptor.authority_ceiling != descriptor.governance.instruction_authority
            || descriptor.id.bytes().any(|byte| byte.is_ascii_control())
            || descriptor
                .version
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        for media_type in &descriptor.media_types {
            if !media_registry.insert(media_type.clone()) {
                return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
            }
        }
        if atomizer_configuration_digest(
            &descriptor.id,
            &descriptor.version,
            &descriptor.scope,
            &descriptor.governance,
            descriptor.quality,
            descriptor.lexical_enabled,
            descriptor.embedding_eligible,
        )? != descriptor.configuration_digest
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        hash_framed(&mut hasher, descriptor.id.as_bytes())?;
        hash_framed(&mut hasher, descriptor.version.as_bytes())?;
        hash_framed(
            &mut hasher,
            descriptor.configuration_digest.as_str().as_bytes(),
        )?;
        hasher.update(
            u64::try_from(descriptor.max_input_bytes)
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
                .to_be_bytes(),
        );
        hasher.update([instruction_authority_code(descriptor.authority_ceiling)]);
        hasher.update([
            u8::from(descriptor.invalidation.source_bytes),
            u8::from(descriptor.invalidation.source_metadata),
            u8::from(descriptor.invalidation.adapter_version),
        ]);
        hasher.update(
            u64::try_from(descriptor.media_types.len())
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
                .to_be_bytes(),
        );
        for media_type in &descriptor.media_types {
            hash_framed(&mut hasher, media_type.as_str().as_bytes())?;
        }
        hasher.update(
            u64::try_from(descriptor.produced_kinds.len())
                .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
                .to_be_bytes(),
        );
        for kind in &descriptor.produced_kinds {
            hasher.update([atom_kind_code(*kind)]);
        }
    }
    content_digest(hasher)
}

fn content_digest(hasher: Sha256) -> Result<ContentDigest, CatalogError> {
    let mut encoded = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
    }
    ContentDigest::new(encoded).map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))
}

fn hash_sequence<'a>(
    hasher: &mut Sha256,
    values: impl ExactSizeIterator<Item = &'a [u8]>,
) -> Result<(), CatalogError> {
    hasher.update(
        u64::try_from(values.len())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for value in values {
        hash_framed(hasher, value)?;
    }
    Ok(())
}

const fn instruction_authority_code(authority: InstructionAuthority) -> u8 {
    match authority {
        InstructionAuthority::Data => 0,
        InstructionAuthority::Advisory => 1,
        InstructionAuthority::Project => 2,
        InstructionAuthority::System => 3,
    }
}

const fn classification_code(classification: Classification) -> u8 {
    match classification {
        Classification::Public => 0,
        Classification::Internal => 1,
        Classification::Confidential => 2,
        Classification::Restricted => 3,
    }
}

const fn atom_kind_code(kind: AtomKind) -> u8 {
    match kind {
        AtomKind::Instruction => 0,
        AtomKind::SourceCode => 1,
        AtomKind::Documentation => 2,
        AtomKind::Decision => 3,
        AtomKind::Conversation => 4,
        AtomKind::ToolResult => 5,
        AtomKind::Schema => 6,
        AtomKind::Policy => 7,
        AtomKind::Test => 8,
        AtomKind::Artifact => 9,
    }
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), CatalogError> {
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_error| CatalogError::new(CatalogErrorCode::LimitExceeded))?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(())
}

/// Declared deterministic invalidation behavior for one atomizer version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomizerInvalidation {
    /// Exact source-byte changes invalidate output.
    pub source_bytes: bool,
    /// Source path, executable bit, or connector metadata changes invalidate output.
    pub source_metadata: bool,
    /// Atomizer/parser version changes invalidate output.
    pub adapter_version: bool,
}

/// Exact immutable input to one deterministic atomizer.
#[derive(Clone, Copy)]
pub struct AtomizationRequest<'a> {
    /// Source record metadata.
    pub record: &'a SourceRecord,
    /// Exact source bytes.
    pub bytes: &'a [u8],
    /// Snapshot proving the source revision.
    pub snapshot: &'a SourceSnapshot,
}

impl fmt::Debug for AtomizationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomizationRequest")
            .field("record", self.record)
            .field("input_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Deterministic atom and edge output for one source record.
#[derive(Clone, Eq, PartialEq)]
pub struct AtomizationOutput {
    /// Sorted immutable atoms.
    pub atoms: Vec<ContextAtomV1>,
    /// Sorted provenance/dependency edges.
    pub edges: Vec<ContextEdge>,
}

impl fmt::Debug for AtomizationOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomizationOutput")
            .field("atom_count", &self.atoms.len())
            .field("edge_count", &self.edges.len())
            .finish()
    }
}

/// Deterministic bounded source atomizer.
pub trait Atomizer: Send + Sync {
    /// Declares supported media, version, bounds, and produced semantic kinds.
    fn descriptor(&self) -> AtomizerDescriptor;
    /// Produces validated deterministic atoms or fails without partial output.
    fn atomize(
        &self,
        request: AtomizationRequest<'_>,
        context: &ConnectorContext,
    ) -> Result<AtomizationOutput, CatalogError>;
}

/// Atomic ingestion publication receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestionReceipt {
    /// Published repository revision.
    pub revision: StoreRevision,
    /// Published source snapshot.
    pub snapshot_id: RecordId,
    /// Number of new immutable atom versions.
    pub published_atoms: u64,
    /// Number of tombstoned prior versions.
    pub tombstoned_atoms: u64,
    /// Canonical publication digest.
    pub publication_digest: ContentDigest,
}

/// Root cause class controlling invalidation priority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvalidationCause {
    /// Authorization or revocation change; highest priority.
    Revocation,
    /// Source record bytes or identity changed.
    SourceChanged,
    /// Policy semantics changed.
    PolicyChanged,
    /// Index or derived projection requires repair.
    ProjectionRepair,
}

/// One bounded idempotent invalidation traversal batch.
#[derive(Clone, Eq, PartialEq)]
pub struct InvalidationBatch {
    /// Stable root version or tombstone selector.
    pub root: VersionId,
    /// Priority cause.
    pub cause: InvalidationCause,
    /// Prior version when invalidating a replacement.
    pub prior_version: Option<VersionId>,
    /// New version when one remains.
    pub new_version: Option<VersionId>,
    /// Canonical causal repository revision.
    pub causal_revision: StoreRevision,
    /// Sorted continuation frontier not yet traversed.
    pub frontier: BTreeSet<VersionId>,
    /// Sorted idempotent invalidation closure accumulated so far.
    pub invalidated: BTreeSet<VersionId>,
}

impl fmt::Debug for InvalidationBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvalidationBatch")
            .field("root", &self.root)
            .field("cause", &self.cause)
            .field("prior_version", &self.prior_version)
            .field("new_version", &self.new_version)
            .field("causal_revision", &self.causal_revision)
            .field("frontier_count", &self.frontier.len())
            .field("invalidated_count", &self.invalidated.len())
            .finish()
    }
}

/// Bounded invalidation graph worker contract.
pub trait InvalidationWorker: Send + Sync {
    /// Traverses at most `limit` new relationships and returns the continuation state.
    fn process(
        &self,
        batch: InvalidationBatch,
        limit: usize,
        context: &ConnectorContext,
    ) -> Result<InvalidationBatch, CatalogError>;
}

#[cfg(test)]
mod tests {
    use super::{
        AtomizerDescriptor, AtomizerInvalidation, BoundedBytes, ByteRange, CatalogErrorCode,
        ConnectorContext, DiscoveryPolicy, MAX_CONNECTOR_ITEMS, MAX_CONNECTOR_READ_BYTES,
        MAX_CONNECTOR_SNAPSHOT_BYTES, atomizer_configuration_digest, atomizer_registry_digest,
        validate_source_paths,
    };
    use cigar_protocol::{
        AtomKind, Classification, FixedPoint, GovernanceEnvelope, InstructionAuthority, MediaType,
        QualityEnvelope, RecordId, ScopeEnvelope,
    };
    use cigar_store::CancellationToken;
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    #[test]
    fn byte_and_discovery_limits_fail_closed() {
        assert!(ByteRange::new(0, MAX_CONNECTOR_READ_BYTES).is_ok());
        assert_eq!(
            ByteRange::new(0, MAX_CONNECTOR_READ_BYTES + 1).map_err(|error| error.code()),
            Err(CatalogErrorCode::LimitExceeded)
        );
        assert!(ByteRange::new(u64::MAX, 1).is_err());
        assert!(BoundedBytes::new(Vec::new()).is_ok());
        let policy = DiscoveryPolicy {
            max_items: MAX_CONNECTOR_ITEMS + 1,
            max_total_bytes: 1,
            max_record_bytes: 1,
            excluded_prefixes: Vec::new(),
            allowed_media_types: BTreeSet::new(),
            allow_user_broadening: false,
            follow_internal_symlinks: false,
            secret_patterns: Vec::new(),
        };
        assert_eq!(
            policy.validate().map_err(|error| error.code()),
            Err(CatalogErrorCode::LimitExceeded)
        );
        let aggregate = DiscoveryPolicy {
            max_items: 1,
            max_total_bytes: MAX_CONNECTOR_SNAPSHOT_BYTES + 1,
            max_record_bytes: 1,
            excluded_prefixes: Vec::new(),
            allowed_media_types: BTreeSet::new(),
            allow_user_broadening: false,
            follow_internal_symlinks: false,
            secret_patterns: Vec::new(),
        };
        assert_eq!(
            aggregate.validate().map_err(|error| error.code()),
            Err(CatalogErrorCode::LimitExceeded)
        );
    }

    #[test]
    fn connector_context_distinguishes_cancel_and_deadline() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            ConnectorContext::new(cancellation, Instant::now() + Duration::from_secs(1))
                .check()
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::Cancelled)
        );
        assert_eq!(
            ConnectorContext::new(CancellationToken::default(), Instant::now())
                .check()
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::DeadlineExceeded)
        );
    }

    #[test]
    fn connector_paths_reject_traversal_case_and_unicode_aliases() {
        for invalid in [
            vec![b"../escape.rs".as_slice()],
            vec![b"nested//file.rs".as_slice()],
            vec![b"windows\\alias.rs".as_slice()],
            vec![b"Readme.md".as_slice(), b"README.md".as_slice()],
            vec!["caf\u{e9}.md".as_bytes(), "cafe\u{301}.md".as_bytes()],
        ] {
            assert_eq!(
                validate_source_paths(invalid).map_err(|error| error.code()),
                Err(CatalogErrorCode::InvalidMetadata)
            );
        }
        assert!(validate_source_paths([b"src/lib.rs".as_slice(), b"README.md"]).is_ok());
    }

    #[test]
    fn atomizer_registry_digest_rejects_reordering_and_binds_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = |id: &str,
                          lexical_enabled: bool|
         -> Result<AtomizerDescriptor, Box<dyn std::error::Error>> {
            let version = "1.0.0".to_owned();
            let scope = ScopeEnvelope {
                tenant_id: RecordId::new("01890f47-8e7d-7b42-a1d2-000000000001")?,
                project_ids: vec![RecordId::new("01890f47-8e7d-7b42-a1d2-000000000002")?],
            };
            let governance = GovernanceEnvelope {
                classification: Classification::Internal,
                allowed_purposes: vec!["coding".to_owned()],
                processor_constraints: Vec::new(),
                instruction_authority: InstructionAuthority::Data,
            };
            let quality = QualityEnvelope {
                confidence: FixedPoint::new(FixedPoint::ONE)?,
                coverage: FixedPoint::new(FixedPoint::ONE)?,
                authority: 1,
            };
            let configuration_digest = atomizer_configuration_digest(
                id,
                &version,
                &scope,
                &governance,
                quality,
                lexical_enabled,
                false,
            )?;
            Ok(AtomizerDescriptor {
                id: id.to_owned(),
                version,
                media_types: BTreeSet::from([MediaType::new(if id == "a" {
                    "text/plain"
                } else {
                    "text/markdown"
                })?]),
                max_input_bytes: 1_024,
                produced_kinds: BTreeSet::from([AtomKind::Documentation]),
                authority_ceiling: InstructionAuthority::Data,
                configuration_digest,
                scope,
                governance,
                quality,
                lexical_enabled,
                embedding_eligible: false,
                invalidation: AtomizerInvalidation {
                    source_bytes: true,
                    source_metadata: true,
                    adapter_version: true,
                },
            })
        };
        let first = descriptor("a", true)?;
        let second = descriptor("b", true)?;
        let baseline = atomizer_registry_digest(&[first.clone(), second.clone()])?;
        assert_eq!(
            atomizer_registry_digest(&[second.clone(), first.clone()])
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::InvalidMetadata)
        );
        let substituted = descriptor("b", false)?;
        assert_ne!(
            baseline,
            atomizer_registry_digest(&[first.clone(), substituted])?
        );
        let mut dishonest_profile = second.clone();
        dishonest_profile.lexical_enabled = false;
        assert_eq!(
            atomizer_registry_digest(&[first.clone(), dishonest_profile])
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::InvalidMetadata)
        );
        let mut overlapping_media = second.clone();
        overlapping_media.media_types = first.media_types.clone();
        assert_eq!(
            atomizer_registry_digest(&[first.clone(), overlapping_media])
                .map_err(|error| error.code()),
            Err(CatalogErrorCode::InvalidMetadata)
        );
        let mut capability_substitution = second;
        capability_substitution.max_input_bytes += 1;
        assert_ne!(
            baseline,
            atomizer_registry_digest(&[first, capability_substitution])?
        );
        Ok(())
    }
}
