//! Backend-neutral source discovery, streaming, atomization, and invalidation contracts.

use cigar_protocol::{
    AtomKind, ContentDigest, ContextAtomV1, ContextEdge, InstructionAuthority, MediaType, RecordId,
    RelativePath, SourceSnapshot, SourceUri, VersionId,
};
use cigar_store::{CancellationToken, StoreRevision};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Instant;

/// Maximum entries returned by one connector operation.
pub const MAX_CONNECTOR_ITEMS: usize = 100_000;
/// Maximum bytes returned by one bounded source read.
pub const MAX_CONNECTOR_READ_BYTES: u64 = 67_108_864;
/// Maximum atomization input bytes.
pub const MAX_ATOMIZATION_BYTES: usize = 67_108_864;
/// Maximum organization secret patterns attached to one discovery policy.
pub const MAX_SECRET_PATTERNS: usize = 128;

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
    /// Inputs whose changes invalidate this atomizer's output.
    pub invalidation: AtomizerInvalidation,
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
        BoundedBytes, ByteRange, CatalogErrorCode, ConnectorContext, DiscoveryPolicy,
        MAX_CONNECTOR_ITEMS, MAX_CONNECTOR_READ_BYTES,
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
}
