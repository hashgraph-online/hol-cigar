//! Public repository capability types and transaction contracts.

use cigar_protocol::{
    AtomKind, BlobRef, ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge,
    ContextSpaceId, EdgeKind, EffectJournalEvent, IdempotencyKey, RecordId, SourceSnapshot,
    VersionId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum page size supported by repository atom queries.
pub const MAX_QUERY_PAGE_ITEMS: usize = 1_000;
/// Maximum public atom identities resolved by one snapshot-pinned batch lookup.
pub const MAX_ATOM_BATCH_ITEMS: usize = 1_000;
/// Maximum purpose selector bytes carried by a transaction capability.
pub const MAX_PURPOSE_BYTES: usize = 256;
/// Maximum outbox topic bytes.
pub const MAX_OUTBOX_TOPIC_BYTES: usize = 256;
/// Maximum in-memory blob bytes accepted by one oracle record.
pub const MAX_BLOB_BYTES: usize = 67_108_864;
/// Maximum canonical bytes in one current durable effect record.
pub const MAX_EFFECT_RECORD_BYTES: usize = 16_777_216;

/// Stable content-free repository failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorCode {
    /// A tenant, purpose, or transaction capability was invalid.
    InvalidContext,
    /// Requested revision or record does not exist in this tenant snapshot.
    NotFound,
    /// Optimistic expected revision did not match the current store revision.
    RevisionConflict,
    /// A staged record violates a protocol or repository invariant.
    InvalidRecord,
    /// A bounded query, blob, topic, or batch limit was exceeded.
    LimitExceeded,
    /// A cursor belongs to another immutable snapshot.
    MixedSnapshot,
    /// The operation was cancelled before publication.
    Cancelled,
    /// A failpoint aborted publication before any new state became visible.
    InjectedAbort,
    /// A lock or provider boundary could not be used safely.
    Unavailable,
}

/// Safe repository error that never contains record or tenant content.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StoreError {
    code: StoreErrorCode,
}

impl StoreError {
    pub(crate) const fn new(code: StoreErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> StoreErrorCode {
        self.code
    }
}

impl fmt::Debug for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "repository operation failed: {:?}", self.code)
    }
}

impl std::error::Error for StoreError {}

/// Immutable tenant and purpose capability required to open any transaction.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessContext {
    tenant_id: RecordId,
    purpose: String,
}

impl AccessContext {
    /// Creates a bounded transaction capability.
    pub fn new(tenant_id: RecordId, purpose: impl Into<String>) -> Result<Self, StoreError> {
        let purpose = purpose.into();
        if purpose.is_empty()
            || purpose.len() > MAX_PURPOSE_BYTES
            || purpose.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        Ok(Self { tenant_id, purpose })
    }

    /// Returns the exact tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the bounded declared purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

impl fmt::Debug for AccessContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessContext")
            .field("tenant_id", &self.tenant_id)
            .field("purpose_bytes", &self.purpose.len())
            .finish()
    }
}

/// Monotonic committed repository revision.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StoreRevision(pub u64);

/// Requested immutable read snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotSelection {
    /// Current committed state at transaction open.
    Latest,
    /// Exact historical committed revision when it remains inside the backend's bounded window.
    Revision(StoreRevision),
}

/// Cloneable cooperative cancellation capability.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Requests cancellation for all holders of this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn check(&self) -> Result<(), StoreError> {
        if self.is_cancelled() {
            Err(StoreError::new(StoreErrorCode::Cancelled))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CancellationToken")
            .field(&self.is_cancelled())
            .finish()
    }
}

/// Optional bounded selector for a paged atom query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AtomSelector {
    /// Exact semantic atom kind, if constrained.
    pub kind: Option<AtomKind>,
}

/// Opaque snapshot-pinned continuation position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomCursor {
    pub(crate) revision: StoreRevision,
    pub(crate) last_version: VersionId,
}

/// One bounded atom query page and its snapshot-pinned continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomPage {
    /// Sorted immutable atoms.
    pub items: Vec<ContextAtomV1>,
    /// Continuation cursor when more matching atoms exist.
    pub next: Option<AtomCursor>,
}

/// Protected blob bytes and their public integrity metadata.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobRecord {
    /// Public content-addressed metadata.
    pub reference: BlobRef,
    bytes: Vec<u8>,
}

impl BlobRecord {
    /// Creates a bounded blob whose byte length exactly matches its reference.
    pub fn new(reference: BlobRef, bytes: Vec<u8>) -> Result<Self, StoreError> {
        if bytes.len() > MAX_BLOB_BYTES
            || u64::try_from(bytes.len()).ok() != Some(reference.size_bytes)
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        Ok(Self { reference, bytes })
    }

    /// Returns protected bytes to an authorized transaction caller.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for BlobRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobRecord")
            .field("reference", &self.reference)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Caller identity for one idempotent mutation result.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct IdempotencyIdentity {
    /// Bounded operation scope, distinct from the secret-safe key.
    pub scope: String,
    /// Caller-supplied secret-safe idempotency key.
    pub key: IdempotencyKey,
    /// Digest of the exact normalized mutation request bound to this key.
    pub request_digest: ContentDigest,
}

impl IdempotencyIdentity {
    /// Creates a bounded idempotency scope and key pair.
    pub fn new(
        scope: impl Into<String>,
        key: IdempotencyKey,
        request_digest: ContentDigest,
    ) -> Result<Self, StoreError> {
        let scope = scope.into();
        if scope.is_empty()
            || scope.len() > MAX_PURPOSE_BYTES
            || scope.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        Ok(Self {
            scope,
            key,
            request_digest,
        })
    }
}

impl fmt::Debug for IdempotencyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyIdentity")
            .field("scope", &self.scope)
            .field("key", &self.key)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

/// Outbox message staged with its causal state change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboxMessage {
    /// Unique immutable message identity.
    pub message_id: RecordId,
    /// Bounded stable routing topic.
    pub topic: String,
    /// Digest of protected message content.
    pub payload_digest: ContentDigest,
}

impl OutboxMessage {
    /// Validates a bounded routing topic.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.topic.is_empty()
            || self.topic.len() > MAX_OUTBOX_TOPIC_BYTES
            || self.topic.bytes().any(|byte| byte.is_ascii_control())
        {
            Err(StoreError::new(StoreErrorCode::InvalidRecord))
        } else {
            Ok(())
        }
    }
}

/// Committed outbox record with exact causal repository revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboxRecord {
    /// Original message.
    pub message: OutboxMessage,
    /// Atomic commit that made its causal state visible.
    pub causal_revision: StoreRevision,
}

/// Integrity-checked current effect record encoded by the effect kernel.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectRecordEnvelope {
    /// Logical effect identity.
    pub effect_id: RecordId,
    /// Monotonic effect projection version, beginning at zero for durable intent.
    pub effect_version: u64,
    /// SHA-256 multihash of the exact canonical record bytes.
    pub record_digest: ContentDigest,
    bytes: Vec<u8>,
}

impl EffectRecordEnvelope {
    /// Creates a bounded envelope whose bytes exactly match the declared digest.
    pub fn new(
        effect_id: RecordId,
        effect_version: u64,
        record_digest: ContentDigest,
        bytes: Vec<u8>,
    ) -> Result<Self, StoreError> {
        if bytes.is_empty()
            || bytes.len() > MAX_EFFECT_RECORD_BYTES
            || sha256_multihash(&bytes) != record_digest.as_str()
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        Ok(Self {
            effect_id,
            effect_version,
            record_digest,
            bytes,
        })
    }

    /// Returns exact canonical bytes to an authorized transaction caller.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EffectRecordEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectRecordEnvelope")
            .field("effect_id", &self.effect_id)
            .field("effect_version", &self.effect_version)
            .field("record_digest", &self.record_digest)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// Result of one successful or idempotently replayed commit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitReceipt {
    /// Committed revision.
    pub revision: StoreRevision,
    /// True when a prior result was returned without another mutation.
    pub replayed: bool,
}

/// Immutable read transaction contract. Tenant and purpose are fixed at open.
pub trait ReadTransaction {
    /// Snapshot revision pinned by this transaction.
    fn revision(&self) -> StoreRevision;
    /// Gets one atom by semantic version.
    fn get_atom(&self, version: &VersionId) -> Result<Option<ContextAtomV1>, StoreError>;
    /// Resolves unique public atom identities in request order.
    ///
    /// A missing identity and an identity outside this transaction's tenant both return `None`.
    /// The entire lookup is evaluated against this transaction's one immutable snapshot.
    fn get_atoms_by_id(
        &self,
        atom_ids: &[RecordId],
    ) -> Result<Vec<Option<ContextAtomV1>>, StoreError>;
    /// Resolves an atom only when it is the current active record in its lineage.
    ///
    /// Missing, historical, tombstoned, and cross-tenant identities all return `None`.
    fn get_active_atom_by_id(
        &self,
        atom_id: &RecordId,
    ) -> Result<Option<ContextAtomV1>, StoreError>;
    /// Queries sorted atoms with a bounded snapshot-pinned cursor.
    fn query_atoms(
        &self,
        selector: AtomSelector,
        limit: usize,
        cursor: Option<&AtomCursor>,
    ) -> Result<AtomPage, StoreError>;
    /// Gets sorted edges from one semantic version, optionally restricted by kind.
    fn edges_from(
        &self,
        version: &VersionId,
        kind: Option<EdgeKind>,
        limit: usize,
    ) -> Result<Vec<ContextEdge>, StoreError>;
    /// Gets one compiled bundle.
    fn get_bundle(&self, bundle: &VersionId) -> Result<Option<ContextBundle>, StoreError>;
    /// Gets one source snapshot.
    fn get_snapshot(&self, snapshot: &RecordId) -> Result<Option<SourceSnapshot>, StoreError>;
    /// Gets the ordered immutable commit history for one context space.
    fn context_commits(&self, space: &ContextSpaceId) -> Result<Vec<ContextCommit>, StoreError>;
    /// Gets the ordered effect journal for one logical effect.
    fn get_effect(&self, effect: &RecordId) -> Result<Vec<EffectJournalEvent>, StoreError>;
    /// Gets the integrity-checked current effect projection and protected records.
    fn get_effect_record(
        &self,
        effect: &RecordId,
    ) -> Result<Option<EffectRecordEnvelope>, StoreError>;
    /// Gets one protected blob by public digest.
    fn get_blob(&self, digest: &ContentDigest) -> Result<Option<BlobRecord>, StoreError>;
    /// Gets committed outbox records in revision and message order.
    fn outbox(&self) -> Result<Vec<OutboxRecord>, StoreError>;
    /// Gets a prior idempotent mutation result.
    fn idempotent_result(
        &self,
        identity: &IdempotencyIdentity,
    ) -> Result<Option<CommitReceipt>, StoreError>;
}

/// Mutable transaction contract. Staged changes remain invisible until `commit` succeeds.
pub trait WriteTransaction: Sized {
    /// Stages one source snapshot.
    fn stage_snapshot(&mut self, snapshot: SourceSnapshot) -> Result<(), StoreError>;
    /// Stages an atomic atom and edge publication batch.
    fn publish_atoms(
        &mut self,
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
    ) -> Result<(), StoreError>;
    /// Stages one immutable bundle.
    fn put_bundle(&mut self, bundle: ContextBundle) -> Result<(), StoreError>;
    /// Stages one context-space commit.
    fn append_context_commit(&mut self, commit: ContextCommit) -> Result<(), StoreError>;
    /// Stages one effect journal event.
    fn append_effect_event(&mut self, event: EffectJournalEvent) -> Result<(), StoreError>;
    /// Stages a new or next-version durable effect record.
    fn put_effect_record(&mut self, record: EffectRecordEnvelope) -> Result<(), StoreError>;
    /// Stages one protected blob.
    fn put_blob(&mut self, blob: BlobRecord) -> Result<(), StoreError>;
    /// Stages one outbox message with the transaction's causal state.
    fn enqueue_outbox(&mut self, message: OutboxMessage) -> Result<(), StoreError>;
    /// Atomically publishes all changes or returns an earlier idempotent result.
    fn commit(self, idempotency: Option<IdempotencyIdentity>) -> Result<CommitReceipt, StoreError>;
}

fn sha256_multihash(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    for byte in hash {
        use std::fmt::Write as _;
        let _result = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

/// Repository factory for capability-bound read and write transactions.
pub trait Repository: Send + Sync {
    /// Immutable transaction type tied to this repository borrow.
    type Read<'store>: ReadTransaction + Send
    where
        Self: 'store;
    /// Mutable transaction type tied to this repository borrow.
    type Write<'store>: WriteTransaction + Send
    where
        Self: 'store;

    /// Opens an immutable tenant snapshot.
    fn begin_read(
        &self,
        context: AccessContext,
        selection: SnapshotSelection,
        cancellation: CancellationToken,
    ) -> Result<Self::Read<'_>, StoreError>;

    /// Opens a mutable transaction with an exact optimistic revision.
    fn begin_write(
        &self,
        context: AccessContext,
        expected_revision: StoreRevision,
        cancellation: CancellationToken,
    ) -> Result<Self::Write<'_>, StoreError>;
}
