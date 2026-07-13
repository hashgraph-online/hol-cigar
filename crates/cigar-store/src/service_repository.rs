//! Object-safe durable records used by embedded services and daemon workers.

use crate::memory::{CommittedState, TenantState};
use crate::{
    CancellationToken, EffectRecordEnvelope, OutboxRecord, StoreError, StoreErrorCode,
    StoreRevision,
};
use cigar_protocol::{ContentDigest, EffectJournalEvent, IdempotencyKey, RecordId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum UTF-8 bytes in one service namespace.
pub const MAX_SERVICE_NAMESPACE_BYTES: usize = 128;
/// Maximum UTF-8 bytes in one service record key.
pub const MAX_SERVICE_KEY_BYTES: usize = 512;
/// Maximum exact bytes in one service record.
pub const MAX_SERVICE_RECORD_BYTES: usize = 16_777_216;
/// Maximum exact idempotent response bytes, including bounded semantic-envelope framing.
pub const MAX_SERVICE_RESPONSE_BYTES: usize = MAX_SERVICE_RECORD_BYTES + 8_192;
/// Maximum exact record bytes staged by one atomic service batch.
pub const MAX_SERVICE_BATCH_BYTES: usize = 67_108_864;
/// Maximum records staged by one atomic service batch.
pub const MAX_SERVICE_BATCH_RECORDS: usize = 256;
/// Maximum records returned by one service or recovery page.
pub const MAX_SERVICE_PAGE_ITEMS: usize = 1_000;
/// Maximum exact bytes in one durable worker cursor.
pub const MAX_WORKER_CURSOR_BYTES: usize = 65_536;
/// Maximum bytes in a worker name or lease owner selector.
pub const MAX_WORKER_SELECTOR_BYTES: usize = 128;
/// Maximum durable idempotency bindings retained for one tenant.
pub const MAX_RETAINED_SERVICE_IDEMPOTENCY_ENTRIES: usize = 16_384;
/// Maximum logical service-record keys retained for one tenant.
pub const MAX_RETAINED_SERVICE_RECORD_KEYS: usize = 16_384;
/// Maximum immutable versions retained for one logical service-record key.
pub const MAX_RETAINED_SERVICE_VERSIONS_PER_KEY: usize = 1_024;
/// Maximum immutable service-record versions retained across one tenant.
pub const MAX_RETAINED_SERVICE_VERSIONS_PER_TENANT: usize = 65_536;
/// Maximum exact serialized bytes retained by service records, replay receipts, and workers.
pub const MAX_RETAINED_SERVICE_STATE_BYTES: usize = 67_108_864;

/// Stable, content-free service repository failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceErrorCode {
    /// A selector, record, response, or update was malformed.
    InvalidInput,
    /// A requested record, revision, or worker does not exist.
    NotFound,
    /// An optimistic record, store, worker, or lease version did not match.
    RevisionConflict,
    /// An idempotency scope and key were reused for different request bytes.
    IdempotencyConflict,
    /// A continuation cursor was presented with a different tenant or query scope.
    CursorScopeMismatch,
    /// A configured record, batch, page, or cursor limit was exceeded.
    LimitExceeded,
    /// Cooperative cancellation was observed before durable publication.
    Cancelled,
    /// An injected durability failpoint aborted before publication.
    InjectedAbort,
    /// The storage provider could not safely complete the operation.
    Unavailable,
}

/// Safe service repository error that never contains tenant or record content.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServiceError {
    code: ServiceErrorCode,
}

impl ServiceError {
    pub(crate) const fn new(code: ServiceErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable content-free category.
    #[must_use]
    pub const fn code(self) -> ServiceErrorCode {
        self.code
    }
}

impl fmt::Debug for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "service repository operation failed: {:?}",
            self.code
        )
    }
}

impl std::error::Error for ServiceError {}

/// Fully tenant-scoped location of one logical service record.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ServiceRecordLocator {
    tenant_id: RecordId,
    namespace: String,
    key: String,
}

impl ServiceRecordLocator {
    /// Creates a bounded printable record location.
    pub fn new(
        tenant_id: RecordId,
        namespace: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Self, ServiceError> {
        let namespace = namespace.into();
        let key = key.into();
        validate_selector(&namespace, MAX_SERVICE_NAMESPACE_BYTES, false)?;
        validate_selector(&key, MAX_SERVICE_KEY_BYTES, false)?;
        Ok(Self {
            tenant_id,
            namespace,
            key,
        })
    }

    /// Returns the exact tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the stable namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the stable record key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Debug for ServiceRecordLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRecordLocator")
            .field("tenant_id", &self.tenant_id)
            .field("namespace", &self.namespace)
            .field("key_bytes", &self.key.len())
            .finish()
    }
}

/// Immutable exact bytes at one monotonic logical-record version.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceRecord {
    locator: ServiceRecordLocator,
    version: u64,
    store_revision: StoreRevision,
    digest: ContentDigest,
    bytes: Vec<u8>,
}

impl ServiceRecord {
    /// Returns the fully tenant-scoped logical location.
    #[must_use]
    pub const fn locator(&self) -> &ServiceRecordLocator {
        &self.locator
    }

    /// Returns the immutable logical version, beginning at one.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the MVCC publication revision.
    #[must_use]
    pub const fn store_revision(&self) -> StoreRevision {
        self.store_revision
    }

    /// Returns the SHA-256 multihash of the exact protected bytes.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Returns the exact protected bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ServiceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRecord")
            .field("locator", &self.locator)
            .field("version", &self.version)
            .field("store_revision", &self.store_revision)
            .field("digest", &self.digest)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// Exact record version requested from an immutable logical history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRecordSelection {
    /// Current immutable version in the selected snapshot.
    Latest,
    /// One exact retained logical version.
    Version(u64),
}

/// Optimistic expectation for one logical record or worker state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceExpectedVersion {
    /// The logical record must not exist.
    Absent,
    /// The current logical version must equal this nonzero value.
    Version(u64),
}

/// One bounded exact record staged in an atomic batch.
#[derive(Clone, Eq, PartialEq)]
pub struct ServiceRecordWrite {
    namespace: String,
    key: String,
    expected: ServiceExpectedVersion,
    bytes: Vec<u8>,
}

impl ServiceRecordWrite {
    /// Creates a bounded exact record write.
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        expected: ServiceExpectedVersion,
        bytes: Vec<u8>,
    ) -> Result<Self, ServiceError> {
        let namespace = namespace.into();
        let key = key.into();
        validate_selector(&namespace, MAX_SERVICE_NAMESPACE_BYTES, false)?;
        validate_selector(&key, MAX_SERVICE_KEY_BYTES, false)?;
        validate_expected(expected)?;
        if bytes.is_empty() || bytes.len() > MAX_SERVICE_RECORD_BYTES {
            return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
        }
        Ok(Self {
            namespace,
            key,
            expected,
            bytes,
        })
    }
}

impl fmt::Debug for ServiceRecordWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRecordWrite")
            .field("namespace", &self.namespace)
            .field("key_bytes", &self.key.len())
            .field("expected", &self.expected)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// Exact response retained for request-bound idempotent replay.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceResponse {
    status_code: u16,
    content_type: String,
    digest: ContentDigest,
    bytes: Vec<u8>,
}

impl ServiceResponse {
    /// Creates a bounded exact service response.
    pub fn new(
        status_code: u16,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, ServiceError> {
        let content_type = content_type.into();
        if !(100..=599).contains(&status_code)
            || content_type.is_empty()
            || content_type.len() > 128
            || !content_type.bytes().all(|byte| byte.is_ascii_graphic())
            || bytes.len() > MAX_SERVICE_RESPONSE_BYTES
        {
            return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
        }
        Ok(Self {
            status_code,
            content_type,
            digest: exact_digest(&bytes)?,
            bytes,
        })
    }

    /// Returns the transport-neutral status code retained with the response.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Returns the exact content type.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Returns the response-body digest.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Returns the exact response bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ServiceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceResponse")
            .field("status_code", &self.status_code)
            .field("content_type", &self.content_type)
            .field("digest", &self.digest)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// Request identity that binds one exact response to one normalized request digest.
#[derive(Clone, Eq, PartialEq)]
pub struct ServiceIdempotency {
    operation: String,
    key: IdempotencyKey,
    request_digest: ContentDigest,
}

impl ServiceIdempotency {
    /// Creates a bounded operation-scoped request identity.
    pub fn new(
        operation: impl Into<String>,
        key: IdempotencyKey,
        request_digest: ContentDigest,
    ) -> Result<Self, ServiceError> {
        let operation = operation.into();
        validate_selector(&operation, MAX_SERVICE_NAMESPACE_BYTES, false)?;
        Ok(Self {
            operation,
            key,
            request_digest,
        })
    }
}

impl fmt::Debug for ServiceIdempotency {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceIdempotency")
            .field("operation", &self.operation)
            .field("key", &self.key)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

/// Atomic service mutation request.
#[derive(Clone, Eq, PartialEq)]
pub struct ServiceBatch {
    tenant_id: RecordId,
    expected_store_revision: Option<StoreRevision>,
    writes: Vec<ServiceRecordWrite>,
    idempotency: Option<ServiceIdempotency>,
    response: ServiceResponse,
}

impl ServiceBatch {
    /// Creates a non-empty bounded atomic batch.
    pub fn new(
        tenant_id: RecordId,
        writes: Vec<ServiceRecordWrite>,
        response: ServiceResponse,
    ) -> Result<Self, ServiceError> {
        validate_writes(&writes)?;
        Ok(Self {
            tenant_id,
            expected_store_revision: None,
            writes,
            idempotency: None,
            response,
        })
    }

    /// Requires one exact global MVCC revision in addition to per-record CAS.
    #[must_use]
    pub const fn with_expected_store_revision(mut self, revision: StoreRevision) -> Self {
        self.expected_store_revision = Some(revision);
        self
    }

    /// Persists the exact response for request-bound replay.
    #[must_use]
    pub fn with_idempotency(mut self, idempotency: ServiceIdempotency) -> Self {
        self.idempotency = Some(idempotency);
        self
    }

    pub(crate) const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }
}

impl fmt::Debug for ServiceBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceBatch")
            .field("tenant_id", &self.tenant_id)
            .field("expected_store_revision", &self.expected_store_revision)
            .field("write_count", &self.writes.len())
            .field("has_idempotency", &self.idempotency.is_some())
            .field("response", &self.response)
            .finish()
    }
}

/// Immutable identity of a record version published by one batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceRecordVersion {
    /// Stable namespace.
    pub namespace: String,
    /// Stable logical key.
    pub key: String,
    /// New monotonic logical version.
    pub version: u64,
    /// Digest of exact immutable bytes.
    pub digest: ContentDigest,
}

/// Result of a newly committed or idempotently replayed service batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceBatchReceipt {
    /// Original atomic MVCC revision.
    pub revision: StoreRevision,
    /// Exact published logical versions in batch order.
    pub records: Vec<ServiceRecordVersion>,
    /// Exact original response.
    pub response: ServiceResponse,
    /// True only when an earlier request-bound result was returned.
    pub replayed: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ServiceIdempotencyEntry {
    pub(crate) request_digest: ContentDigest,
    pub(crate) receipt: ServiceBatchReceipt,
}

/// Tenant, namespace, and optional key-prefix scope for one immutable listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceListScope {
    tenant_id: RecordId,
    namespace: String,
    key_prefix: Option<String>,
}

impl ServiceListScope {
    /// Creates a bounded exact listing scope.
    pub fn new(
        tenant_id: RecordId,
        namespace: impl Into<String>,
        key_prefix: Option<String>,
    ) -> Result<Self, ServiceError> {
        let namespace = namespace.into();
        validate_selector(&namespace, MAX_SERVICE_NAMESPACE_BYTES, false)?;
        if let Some(prefix) = &key_prefix {
            validate_selector(prefix, MAX_SERVICE_KEY_BYTES, true)?;
        }
        Ok(Self {
            tenant_id,
            namespace,
            key_prefix,
        })
    }

    /// Returns the exact tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the exact namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the optional exact key prefix.
    #[must_use]
    pub fn key_prefix(&self) -> Option<&str> {
        self.key_prefix.as_deref()
    }
}

/// Opaque repository continuation pinned to tenant, query, and MVCC revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceListCursor {
    scope: ServiceListScope,
    revision: StoreRevision,
    last_key: String,
}

impl ServiceListCursor {
    /// Reconstructs a validated position decoded from an authenticated API or worker cursor.
    pub fn resume(
        scope: ServiceListScope,
        revision: StoreRevision,
        last_key: impl Into<String>,
    ) -> Result<Self, ServiceError> {
        let last_key = last_key.into();
        validate_selector(&last_key, MAX_SERVICE_KEY_BYTES, false)?;
        if revision == StoreRevision(0)
            || scope
                .key_prefix
                .as_ref()
                .is_some_and(|prefix| !last_key.starts_with(prefix))
        {
            return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
        }
        Ok(Self {
            scope,
            revision,
            last_key,
        })
    }

    /// Returns the exact scope bound into this continuation.
    #[must_use]
    pub const fn scope(&self) -> &ServiceListScope {
        &self.scope
    }

    /// Returns the immutable MVCC snapshot revision.
    #[must_use]
    pub const fn snapshot_revision(&self) -> StoreRevision {
        self.revision
    }

    /// Returns the last emitted logical key.
    #[must_use]
    pub fn last_key(&self) -> &str {
        &self.last_key
    }
}

/// Bounded immutable service record listing request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceListQuery {
    scope: ServiceListScope,
    limit: usize,
    cursor: Option<ServiceListCursor>,
}

impl ServiceListQuery {
    /// Creates a bounded snapshot-pinned listing request.
    pub fn new(
        scope: ServiceListScope,
        limit: usize,
        cursor: Option<ServiceListCursor>,
    ) -> Result<Self, ServiceError> {
        validate_page_limit(limit)?;
        if cursor.as_ref().is_some_and(|cursor| cursor.scope != scope) {
            return Err(ServiceError::new(ServiceErrorCode::CursorScopeMismatch));
        }
        Ok(Self {
            scope,
            limit,
            cursor,
        })
    }

    pub(crate) fn revision(&self) -> Option<StoreRevision> {
        self.cursor.as_ref().map(|cursor| cursor.revision)
    }

    pub(crate) const fn tenant_id(&self) -> &RecordId {
        self.scope.tenant_id()
    }
}

/// One deterministic snapshot-pinned service record page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceListPage {
    /// Immutable snapshot revision used by this page.
    pub revision: StoreRevision,
    /// Current logical record versions in ascending key order.
    pub items: Vec<ServiceRecord>,
    /// Continuation within the exact same tenant, query, and revision.
    pub next: Option<ServiceListCursor>,
}

/// Opaque tenant and snapshot-bound effect recovery continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecoveryCursor {
    tenant_id: RecordId,
    revision: StoreRevision,
    last_effect_id: RecordId,
}

impl EffectRecoveryCursor {
    /// Reconstructs a position decoded from an authenticated durable worker cursor.
    pub fn resume(
        tenant_id: RecordId,
        revision: StoreRevision,
        last_effect_id: RecordId,
    ) -> Result<Self, ServiceError> {
        if revision == StoreRevision(0) {
            return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
        }
        Ok(Self {
            tenant_id,
            revision,
            last_effect_id,
        })
    }

    /// Returns the exact tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the immutable MVCC snapshot revision.
    #[must_use]
    pub const fn snapshot_revision(&self) -> StoreRevision {
        self.revision
    }

    /// Returns the last emitted effect identity.
    #[must_use]
    pub const fn last_effect_id(&self) -> &RecordId {
        &self.last_effect_id
    }
}

/// Bounded effect recovery enumeration request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecoveryQuery {
    tenant_id: RecordId,
    limit: usize,
    cursor: Option<EffectRecoveryCursor>,
}

impl EffectRecoveryQuery {
    /// Creates a bounded tenant-scoped effect recovery request.
    pub fn new(
        tenant_id: RecordId,
        limit: usize,
        cursor: Option<EffectRecoveryCursor>,
    ) -> Result<Self, ServiceError> {
        validate_page_limit(limit)?;
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.tenant_id != tenant_id)
        {
            return Err(ServiceError::new(ServiceErrorCode::CursorScopeMismatch));
        }
        Ok(Self {
            tenant_id,
            limit,
            cursor,
        })
    }

    pub(crate) fn revision(&self) -> Option<StoreRevision> {
        self.cursor.as_ref().map(|cursor| cursor.revision)
    }

    pub(crate) const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }
}

/// Opaque current effect envelope and its latest append-only event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecoveryItem {
    /// Integrity-checked exact current record bytes.
    pub record: EffectRecordEnvelope,
    /// Latest event, or none for a version-zero prepared effect.
    pub latest_event: Option<EffectJournalEvent>,
}

/// One deterministic snapshot-pinned effect recovery page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecoveryPage {
    /// Immutable snapshot revision used by this page.
    pub revision: StoreRevision,
    /// Current opaque envelopes in ascending effect-ID order.
    pub items: Vec<EffectRecoveryItem>,
    /// Continuation within the exact same tenant and revision.
    pub next: Option<EffectRecoveryCursor>,
}

/// Opaque tenant and snapshot-bound outbox recovery continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxRecoveryCursor {
    tenant_id: RecordId,
    revision: StoreRevision,
    last_causal_revision: StoreRevision,
    last_message_id: RecordId,
}

impl OutboxRecoveryCursor {
    /// Reconstructs a position decoded from an authenticated durable worker cursor.
    pub fn resume(
        tenant_id: RecordId,
        revision: StoreRevision,
        last_causal_revision: StoreRevision,
        last_message_id: RecordId,
    ) -> Result<Self, ServiceError> {
        if revision == StoreRevision(0)
            || last_causal_revision == StoreRevision(0)
            || last_causal_revision > revision
        {
            return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
        }
        Ok(Self {
            tenant_id,
            revision,
            last_causal_revision,
            last_message_id,
        })
    }

    /// Returns the exact tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the immutable MVCC snapshot revision.
    #[must_use]
    pub const fn snapshot_revision(&self) -> StoreRevision {
        self.revision
    }

    /// Returns the causal revision of the last emitted wakeup.
    #[must_use]
    pub const fn last_causal_revision(&self) -> StoreRevision {
        self.last_causal_revision
    }

    /// Returns the last emitted message identity.
    #[must_use]
    pub const fn last_message_id(&self) -> &RecordId {
        &self.last_message_id
    }
}

/// Bounded outbox recovery enumeration request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxRecoveryQuery {
    tenant_id: RecordId,
    limit: usize,
    cursor: Option<OutboxRecoveryCursor>,
}

impl OutboxRecoveryQuery {
    /// Creates a bounded tenant-scoped outbox recovery request.
    pub fn new(
        tenant_id: RecordId,
        limit: usize,
        cursor: Option<OutboxRecoveryCursor>,
    ) -> Result<Self, ServiceError> {
        validate_page_limit(limit)?;
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.tenant_id != tenant_id)
        {
            return Err(ServiceError::new(ServiceErrorCode::CursorScopeMismatch));
        }
        Ok(Self {
            tenant_id,
            limit,
            cursor,
        })
    }

    pub(crate) fn revision(&self) -> Option<StoreRevision> {
        self.cursor.as_ref().map(|cursor| cursor.revision)
    }

    pub(crate) const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }
}

/// One deterministic snapshot-pinned outbox recovery page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxRecoveryPage {
    /// Immutable snapshot revision used by this page.
    pub revision: StoreRevision,
    /// Current pending wakeups in causal-revision and message-ID order.
    pub items: Vec<OutboxRecord>,
    /// Continuation within the exact same tenant and revision.
    pub next: Option<OutboxRecoveryCursor>,
}

/// Tenant-scoped durable worker identity.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WorkerLocator {
    tenant_id: RecordId,
    worker: String,
}

impl WorkerLocator {
    /// Creates a bounded worker identity.
    pub fn new(tenant_id: RecordId, worker: impl Into<String>) -> Result<Self, ServiceError> {
        let worker = worker.into();
        validate_selector(&worker, MAX_WORKER_SELECTOR_BYTES, false)?;
        Ok(Self { tenant_id, worker })
    }

    /// Returns the exact tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the stable worker name.
    #[must_use]
    pub fn worker(&self) -> &str {
        &self.worker
    }
}

impl fmt::Debug for WorkerLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerLocator")
            .field("tenant_id", &self.tenant_id)
            .field("worker", &self.worker)
            .finish()
    }
}

/// Durable worker checkpoint, heartbeat, and renewable fencing lease.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkerState {
    locator: WorkerLocator,
    version: u64,
    store_revision: StoreRevision,
    cursor_digest: ContentDigest,
    cursor: Vec<u8>,
    heartbeat_unix_nanos: u64,
    lease_owner: Option<String>,
    fencing_token: u64,
    lease_expires_at_unix_nanos: Option<u64>,
}

impl WorkerState {
    /// Returns the tenant-scoped worker identity.
    #[must_use]
    pub const fn locator(&self) -> &WorkerLocator {
        &self.locator
    }

    /// Returns the monotonic worker-state version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the MVCC publication revision.
    #[must_use]
    pub const fn store_revision(&self) -> StoreRevision {
        self.store_revision
    }

    /// Returns exact opaque checkpoint bytes.
    #[must_use]
    pub fn cursor(&self) -> &[u8] {
        &self.cursor
    }

    /// Returns the checkpoint digest.
    #[must_use]
    pub const fn cursor_digest(&self) -> &ContentDigest {
        &self.cursor_digest
    }

    /// Returns the caller-supplied heartbeat instant.
    #[must_use]
    pub const fn heartbeat_unix_nanos(&self) -> u64 {
        self.heartbeat_unix_nanos
    }

    /// Returns the current lease owner when claimed.
    #[must_use]
    pub fn lease_owner(&self) -> Option<&str> {
        self.lease_owner.as_deref()
    }

    /// Returns the monotonic fencing token retained across release and expiry.
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Returns the lease expiry when claimed.
    #[must_use]
    pub const fn lease_expires_at_unix_nanos(&self) -> Option<u64> {
        self.lease_expires_at_unix_nanos
    }
}

impl fmt::Debug for WorkerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerState")
            .field("locator", &self.locator)
            .field("version", &self.version)
            .field("store_revision", &self.store_revision)
            .field("cursor_digest", &self.cursor_digest)
            .field("cursor_bytes", &self.cursor.len())
            .field("heartbeat_unix_nanos", &self.heartbeat_unix_nanos)
            .field("has_lease", &self.lease_owner.is_some())
            .field("fencing_token", &self.fencing_token)
            .field(
                "lease_expires_at_unix_nanos",
                &self.lease_expires_at_unix_nanos,
            )
            .finish()
    }
}

/// One optimistic worker lease or checkpoint transition.
#[derive(Clone, Eq, PartialEq)]
pub enum WorkerUpdate {
    /// Claims an absent, released, or expired lease and advances its fence.
    Claim {
        /// Expected worker-state version.
        expected: ServiceExpectedVersion,
        /// Bounded owner identity.
        owner: String,
        /// Trusted current time supplied by the runtime.
        now_unix_nanos: u64,
        /// Exclusive lease expiry.
        expires_at_unix_nanos: u64,
    },
    /// Atomically checkpoints progress, heartbeats, and renews the active lease.
    Checkpoint {
        /// Expected worker-state version.
        expected: ServiceExpectedVersion,
        /// Exact active owner.
        owner: String,
        /// Exact active fencing token.
        fencing_token: u64,
        /// Opaque durable cursor.
        cursor: Vec<u8>,
        /// Monotonic heartbeat time.
        heartbeat_unix_nanos: u64,
        /// Exclusive renewed lease expiry.
        expires_at_unix_nanos: u64,
    },
    /// Releases an exact active fence while retaining its cursor and fence history.
    Release {
        /// Expected worker-state version.
        expected: ServiceExpectedVersion,
        /// Exact active owner.
        owner: String,
        /// Exact active fencing token.
        fencing_token: u64,
        /// Monotonic release heartbeat time.
        heartbeat_unix_nanos: u64,
    },
}

impl fmt::Debug for WorkerUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claim {
                expected,
                owner,
                now_unix_nanos,
                expires_at_unix_nanos,
            } => formatter
                .debug_struct("WorkerUpdate::Claim")
                .field("expected", expected)
                .field("owner_bytes", &owner.len())
                .field("now_unix_nanos", now_unix_nanos)
                .field("expires_at_unix_nanos", expires_at_unix_nanos)
                .finish(),
            Self::Checkpoint {
                expected,
                owner,
                fencing_token,
                cursor,
                heartbeat_unix_nanos,
                expires_at_unix_nanos,
            } => formatter
                .debug_struct("WorkerUpdate::Checkpoint")
                .field("expected", expected)
                .field("owner_bytes", &owner.len())
                .field("fencing_token", fencing_token)
                .field("cursor_bytes", &cursor.len())
                .field("heartbeat_unix_nanos", heartbeat_unix_nanos)
                .field("expires_at_unix_nanos", expires_at_unix_nanos)
                .finish(),
            Self::Release {
                expected,
                owner,
                fencing_token,
                heartbeat_unix_nanos,
            } => formatter
                .debug_struct("WorkerUpdate::Release")
                .field("expected", expected)
                .field("owner_bytes", &owner.len())
                .field("fencing_token", fencing_token)
                .field("heartbeat_unix_nanos", heartbeat_unix_nanos)
                .finish(),
        }
    }
}

/// Object-safe durable repository used by embedded and transported service facades.
pub trait ServiceRepository: Send + Sync {
    /// Gets one current or retained immutable logical record version.
    fn service_get(
        &self,
        locator: &ServiceRecordLocator,
        selection: ServiceRecordSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<ServiceRecord>, ServiceError>;

    /// Lists current logical records in one snapshot-pinned scope.
    fn service_list(
        &self,
        query: &ServiceListQuery,
        cancellation: &CancellationToken,
    ) -> Result<ServiceListPage, ServiceError>;

    /// Atomically publishes a bounded CAS batch and exact idempotent response.
    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError>;

    /// Enumerates every current opaque effect envelope for kernel-owned startup recovery.
    fn effect_recovery(
        &self,
        query: &EffectRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<EffectRecoveryPage, ServiceError>;

    /// Enumerates pending wakeups; durable worker cursors record consumption progress.
    fn outbox_recovery(
        &self,
        query: &OutboxRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<OutboxRecoveryPage, ServiceError>;

    /// Gets one durable worker checkpoint and lease.
    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError>;

    /// Atomically claims, checkpoints, renews, or releases one fenced worker lease.
    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError>;
}

pub(crate) fn check_cancellation(cancellation: &CancellationToken) -> Result<(), ServiceError> {
    cancellation.check().map_err(map_store_error)
}

pub(crate) fn map_store_error(error: StoreError) -> ServiceError {
    let code = match error.code() {
        StoreErrorCode::InvalidContext | StoreErrorCode::InvalidRecord => {
            ServiceErrorCode::InvalidInput
        }
        StoreErrorCode::NotFound | StoreErrorCode::MixedSnapshot => ServiceErrorCode::NotFound,
        StoreErrorCode::RevisionConflict => ServiceErrorCode::RevisionConflict,
        StoreErrorCode::LimitExceeded => ServiceErrorCode::LimitExceeded,
        StoreErrorCode::Cancelled => ServiceErrorCode::Cancelled,
        StoreErrorCode::InjectedAbort => ServiceErrorCode::InjectedAbort,
        StoreErrorCode::Unavailable => ServiceErrorCode::Unavailable,
    };
    ServiceError::new(code)
}

pub(crate) fn service_get_from_state(
    state: &CommittedState,
    locator: &ServiceRecordLocator,
    selection: ServiceRecordSelection,
) -> Result<Option<ServiceRecord>, ServiceError> {
    let history = state.tenants.get(&locator.tenant_id).and_then(|tenant| {
        tenant
            .service_records
            .get(&(locator.namespace.clone(), locator.key.clone()))
    });
    let Some(history) = history else {
        return Ok(None);
    };
    validate_record_history(
        state.revision,
        &locator.tenant_id,
        &locator.namespace,
        &locator.key,
        history,
    )?;
    let record = match selection {
        ServiceRecordSelection::Latest => history.last(),
        ServiceRecordSelection::Version(version) if version > 0 => history.get(
            usize::try_from(version - 1)
                .map_err(|_error| ServiceError::new(ServiceErrorCode::LimitExceeded))?,
        ),
        ServiceRecordSelection::Version(_) => {
            return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
        }
    };
    Ok(record.cloned())
}

pub(crate) fn service_list_from_state(
    state: &CommittedState,
    query: &ServiceListQuery,
) -> Result<ServiceListPage, ServiceError> {
    if query
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.scope != query.scope || cursor.revision != state.revision)
    {
        return Err(ServiceError::new(ServiceErrorCode::CursorScopeMismatch));
    }
    let after = query.cursor.as_ref().map(|cursor| cursor.last_key.as_str());
    let prefix = query.scope.key_prefix.as_deref();
    let mut matching = state
        .tenants
        .get(&query.scope.tenant_id)
        .into_iter()
        .flat_map(|tenant| tenant.service_records.iter())
        .filter(|((namespace, key), history)| {
            namespace == &query.scope.namespace
                && history.last().is_some()
                && prefix.is_none_or(|prefix| key.starts_with(prefix))
                && after.is_none_or(|after| key.as_str() > after)
        })
        .filter_map(|(_key, history)| history.last().cloned())
        .take(query.limit.saturating_add(1))
        .collect::<Vec<_>>();
    for record in &matching {
        let history = state
            .tenants
            .get(&query.scope.tenant_id)
            .and_then(|tenant| {
                tenant
                    .service_records
                    .get(&(query.scope.namespace.clone(), record.locator.key.clone()))
            })
            .ok_or_else(corrupt)?;
        validate_record_history(
            state.revision,
            &query.scope.tenant_id,
            &query.scope.namespace,
            &record.locator.key,
            history,
        )?;
    }
    let has_more = matching.len() > query.limit;
    matching.truncate(query.limit);
    let next = has_more
        .then(|| matching.last())
        .flatten()
        .map(|record| ServiceListCursor {
            scope: query.scope.clone(),
            revision: state.revision,
            last_key: record.locator.key.clone(),
        });
    Ok(ServiceListPage {
        revision: state.revision,
        items: matching,
        next,
    })
}

pub(crate) fn effect_recovery_from_state(
    state: &CommittedState,
    query: &EffectRecoveryQuery,
) -> Result<EffectRecoveryPage, ServiceError> {
    if query.cursor.as_ref().is_some_and(|cursor| {
        cursor.tenant_id != query.tenant_id || cursor.revision != state.revision
    }) {
        return Err(ServiceError::new(ServiceErrorCode::CursorScopeMismatch));
    }
    let after = query.cursor.as_ref().map(|cursor| &cursor.last_effect_id);
    let tenant = state.tenants.get(&query.tenant_id);
    let mut matching = tenant
        .into_iter()
        .flat_map(|tenant| tenant.effect_records.iter())
        .filter(|(effect_id, _record)| after.is_none_or(|after| *effect_id > after))
        .map(|(effect_id, record)| EffectRecoveryItem {
            record: record.clone(),
            latest_event: tenant
                .and_then(|tenant| tenant.effects.get(effect_id))
                .and_then(|events| events.last())
                .cloned(),
        })
        .take(query.limit.saturating_add(1))
        .collect::<Vec<_>>();
    for item in &matching {
        if exact_digest(item.record.bytes())? != item.record.record_digest
            || tenant.is_none_or(|tenant| {
                tenant.effect_records.get(&item.record.effect_id) != Some(&item.record)
            })
        {
            return Err(corrupt());
        }
    }
    let has_more = matching.len() > query.limit;
    matching.truncate(query.limit);
    let next = has_more
        .then(|| matching.last())
        .flatten()
        .map(|item| EffectRecoveryCursor {
            tenant_id: query.tenant_id.clone(),
            revision: state.revision,
            last_effect_id: item.record.effect_id.clone(),
        });
    Ok(EffectRecoveryPage {
        revision: state.revision,
        items: matching,
        next,
    })
}

pub(crate) fn outbox_recovery_from_state(
    state: &CommittedState,
    query: &OutboxRecoveryQuery,
) -> Result<OutboxRecoveryPage, ServiceError> {
    if query.cursor.as_ref().is_some_and(|cursor| {
        cursor.tenant_id != query.tenant_id || cursor.revision != state.revision
    }) {
        return Err(ServiceError::new(ServiceErrorCode::CursorScopeMismatch));
    }
    let after = query
        .cursor
        .as_ref()
        .map(|cursor| (cursor.last_causal_revision, cursor.last_message_id.clone()));
    let mut matching = state
        .tenants
        .get(&query.tenant_id)
        .into_iter()
        .flat_map(|tenant| tenant.outbox.iter())
        .filter(|record| {
            after.as_ref().is_none_or(|(revision, message_id)| {
                (record.causal_revision, &record.message.message_id) > (*revision, message_id)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    for record in &matching {
        record.message.validate().map_err(|_error| corrupt())?;
    }
    matching.sort_by(|left, right| {
        (left.causal_revision, &left.message.message_id)
            .cmp(&(right.causal_revision, &right.message.message_id))
    });
    matching.truncate(query.limit.saturating_add(1));
    let has_more = matching.len() > query.limit;
    matching.truncate(query.limit);
    let next = has_more
        .then(|| matching.last())
        .flatten()
        .map(|record| OutboxRecoveryCursor {
            tenant_id: query.tenant_id.clone(),
            revision: state.revision,
            last_causal_revision: record.causal_revision,
            last_message_id: record.message.message_id.clone(),
        });
    Ok(OutboxRecoveryPage {
        revision: state.revision,
        items: matching,
        next,
    })
}

pub(crate) fn worker_get_from_state(
    state: &CommittedState,
    locator: &WorkerLocator,
) -> Result<Option<WorkerState>, ServiceError> {
    let worker = state
        .tenants
        .get(&locator.tenant_id)
        .and_then(|tenant| tenant.worker_states.get(&locator.worker))
        .cloned();
    if let Some(worker) = &worker {
        validate_worker_state(state.revision, locator, worker)?;
    }
    Ok(worker)
}

pub(crate) fn apply_service_batch(
    latest: &CommittedState,
    batch: ServiceBatch,
) -> Result<(Option<CommittedState>, ServiceBatchReceipt), ServiceError> {
    validate_writes(&batch.writes)?;
    if let Some(idempotency) = &batch.idempotency
        && let Some(entry) = latest.tenants.get(&batch.tenant_id).and_then(|tenant| {
            tenant
                .service_idempotency
                .get(&(idempotency.operation.clone(), idempotency.key.clone()))
        })
    {
        validate_idempotency_entry(latest, &batch.tenant_id, entry)?;
        if entry.request_digest != idempotency.request_digest {
            return Err(ServiceError::new(ServiceErrorCode::IdempotencyConflict));
        }
        let mut receipt = entry.receipt.clone();
        receipt.replayed = true;
        return Ok((None, receipt));
    }
    if batch
        .expected_store_revision
        .is_some_and(|expected| expected != latest.revision)
    {
        return Err(ServiceError::new(ServiceErrorCode::RevisionConflict));
    }
    validate_service_batch_retention(latest, &batch)?;
    let revision = next_revision(latest.revision)?;
    let mut next = latest.clone();
    next.revision = revision;
    let tenant = next.tenants.entry(batch.tenant_id.clone()).or_default();
    let mut versions = Vec::with_capacity(batch.writes.len());
    for write in batch.writes {
        let map_key = (write.namespace.clone(), write.key.clone());
        let history = tenant.service_records.entry(map_key).or_default();
        validate_record_history(
            latest.revision,
            &batch.tenant_id,
            &write.namespace,
            &write.key,
            history,
        )?;
        check_expected(write.expected, history.last().map(ServiceRecord::version))?;
        let version = u64::try_from(history.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| ServiceError::new(ServiceErrorCode::LimitExceeded))?;
        let digest = exact_digest(&write.bytes)?;
        let record = ServiceRecord {
            locator: ServiceRecordLocator {
                tenant_id: batch.tenant_id.clone(),
                namespace: write.namespace.clone(),
                key: write.key.clone(),
            },
            version,
            store_revision: revision,
            digest: digest.clone(),
            bytes: write.bytes,
        };
        history.push(record);
        versions.push(ServiceRecordVersion {
            namespace: write.namespace,
            key: write.key,
            version,
            digest,
        });
    }
    let receipt = ServiceBatchReceipt {
        revision,
        records: versions,
        response: batch.response,
        replayed: false,
    };
    if let Some(idempotency) = batch.idempotency {
        tenant.service_idempotency.insert(
            (idempotency.operation, idempotency.key),
            ServiceIdempotencyEntry {
                request_digest: idempotency.request_digest,
                receipt: receipt.clone(),
            },
        );
    }
    validate_tenant_service_retention(tenant)?;
    Ok((Some(next), receipt))
}

fn validate_service_batch_retention(
    latest: &CommittedState,
    batch: &ServiceBatch,
) -> Result<(), ServiceError> {
    let tenant = latest.tenants.get(&batch.tenant_id);
    let idempotency_count = tenant.map_or(0, |state| state.service_idempotency.len());
    if batch.idempotency.is_some() && idempotency_count >= MAX_RETAINED_SERVICE_IDEMPOTENCY_ENTRIES
    {
        return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
    }
    let record_key_count = tenant.map_or(0, |state| state.service_records.len());
    let new_keys = batch
        .writes
        .iter()
        .filter(|write| {
            tenant.is_none_or(|state| {
                !state
                    .service_records
                    .contains_key(&(write.namespace.clone(), write.key.clone()))
            })
        })
        .count();
    if record_key_count.saturating_add(new_keys) > MAX_RETAINED_SERVICE_RECORD_KEYS {
        return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
    }
    let retained_versions = tenant.map_or(0, |state| {
        state
            .service_records
            .values()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add)
    });
    if retained_versions.saturating_add(batch.writes.len())
        > MAX_RETAINED_SERVICE_VERSIONS_PER_TENANT
    {
        return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
    }
    for write in &batch.writes {
        let versions = tenant
            .and_then(|state| {
                state
                    .service_records
                    .get(&(write.namespace.clone(), write.key.clone()))
            })
            .map_or(0, Vec::len);
        if versions >= MAX_RETAINED_SERVICE_VERSIONS_PER_KEY {
            return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
        }
    }
    Ok(())
}

fn validate_tenant_service_retention(tenant: &TenantState) -> Result<(), ServiceError> {
    if tenant.service_idempotency.len() > MAX_RETAINED_SERVICE_IDEMPOTENCY_ENTRIES
        || tenant.service_records.len() > MAX_RETAINED_SERVICE_RECORD_KEYS
        || tenant
            .service_records
            .values()
            .any(|history| history.len() > MAX_RETAINED_SERVICE_VERSIONS_PER_KEY)
        || tenant
            .service_records
            .values()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add)
            > MAX_RETAINED_SERVICE_VERSIONS_PER_TENANT
    {
        return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &(
            &tenant.service_records,
            &tenant.service_idempotency,
            &tenant.worker_states,
        ),
        &mut bytes,
    )
    .map_err(|_error| ServiceError::new(ServiceErrorCode::Unavailable))?;
    if bytes.len() > MAX_RETAINED_SERVICE_STATE_BYTES {
        Err(ServiceError::new(ServiceErrorCode::LimitExceeded))
    } else {
        Ok(())
    }
}

pub(crate) fn apply_worker_update(
    latest: &CommittedState,
    locator: &WorkerLocator,
    update: WorkerUpdate,
) -> Result<(CommittedState, WorkerState), ServiceError> {
    validate_worker_update(&update)?;
    let revision = next_revision(latest.revision)?;
    let mut next = latest.clone();
    next.revision = revision;
    let tenant = next.tenants.entry(locator.tenant_id.clone()).or_default();
    let current = tenant.worker_states.get(&locator.worker).cloned();
    if let Some(current) = &current {
        validate_worker_state(latest.revision, locator, current)?;
    }
    let state = transition_worker(locator, current.as_ref(), update, revision)?;
    tenant
        .worker_states
        .insert(locator.worker.clone(), state.clone());
    Ok((next, state))
}

fn transition_worker(
    locator: &WorkerLocator,
    current: Option<&WorkerState>,
    update: WorkerUpdate,
    revision: StoreRevision,
) -> Result<WorkerState, ServiceError> {
    match update {
        WorkerUpdate::Claim {
            expected,
            owner,
            now_unix_nanos,
            expires_at_unix_nanos,
        } => {
            check_expected(expected, current.map(WorkerState::version))?;
            if current.is_some_and(|state| {
                state.lease_owner.is_some()
                    && state
                        .lease_expires_at_unix_nanos
                        .is_some_and(|expiry| expiry > now_unix_nanos)
            }) {
                return Err(ServiceError::new(ServiceErrorCode::RevisionConflict));
            }
            if current.is_some_and(|state| state.heartbeat_unix_nanos > now_unix_nanos) {
                return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
            }
            let version = current.map_or(Ok(1), |state| increment(state.version))?;
            let fencing_token = current.map_or(Ok(1), |state| increment(state.fencing_token))?;
            let cursor = current.map_or_else(Vec::new, |state| state.cursor.clone());
            Ok(WorkerState {
                locator: locator.clone(),
                version,
                store_revision: revision,
                cursor_digest: exact_digest(&cursor)?,
                cursor,
                heartbeat_unix_nanos: now_unix_nanos,
                lease_owner: Some(owner),
                fencing_token,
                lease_expires_at_unix_nanos: Some(expires_at_unix_nanos),
            })
        }
        WorkerUpdate::Checkpoint {
            expected,
            owner,
            fencing_token,
            cursor,
            heartbeat_unix_nanos,
            expires_at_unix_nanos,
        } => {
            let state = current.ok_or_else(|| ServiceError::new(ServiceErrorCode::NotFound))?;
            check_expected(expected, Some(state.version))?;
            if state.lease_owner.as_deref() != Some(owner.as_str())
                || state.fencing_token != fencing_token
                || state
                    .lease_expires_at_unix_nanos
                    .is_none_or(|expiry| expiry <= heartbeat_unix_nanos)
                || heartbeat_unix_nanos < state.heartbeat_unix_nanos
            {
                return Err(ServiceError::new(ServiceErrorCode::RevisionConflict));
            }
            Ok(WorkerState {
                locator: locator.clone(),
                version: increment(state.version)?,
                store_revision: revision,
                cursor_digest: exact_digest(&cursor)?,
                cursor,
                heartbeat_unix_nanos,
                lease_owner: Some(owner),
                fencing_token,
                lease_expires_at_unix_nanos: Some(expires_at_unix_nanos),
            })
        }
        WorkerUpdate::Release {
            expected,
            owner,
            fencing_token,
            heartbeat_unix_nanos,
        } => {
            let state = current.ok_or_else(|| ServiceError::new(ServiceErrorCode::NotFound))?;
            check_expected(expected, Some(state.version))?;
            if state.lease_owner.as_deref() != Some(owner.as_str())
                || state.fencing_token != fencing_token
                || heartbeat_unix_nanos < state.heartbeat_unix_nanos
            {
                return Err(ServiceError::new(ServiceErrorCode::RevisionConflict));
            }
            Ok(WorkerState {
                locator: locator.clone(),
                version: increment(state.version)?,
                store_revision: revision,
                cursor_digest: state.cursor_digest.clone(),
                cursor: state.cursor.clone(),
                heartbeat_unix_nanos,
                lease_owner: None,
                fencing_token,
                lease_expires_at_unix_nanos: None,
            })
        }
    }
}

fn validate_writes(writes: &[ServiceRecordWrite]) -> Result<(), ServiceError> {
    if writes.is_empty() || writes.len() > MAX_SERVICE_BATCH_RECORDS {
        return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
    }
    let mut total = 0_usize;
    let mut keys = BTreeSet::new();
    for write in writes {
        validate_selector(&write.namespace, MAX_SERVICE_NAMESPACE_BYTES, false)?;
        validate_selector(&write.key, MAX_SERVICE_KEY_BYTES, false)?;
        validate_expected(write.expected)?;
        if write.bytes.is_empty() || write.bytes.len() > MAX_SERVICE_RECORD_BYTES {
            return Err(ServiceError::new(ServiceErrorCode::LimitExceeded));
        }
        total = total
            .checked_add(write.bytes.len())
            .ok_or_else(|| ServiceError::new(ServiceErrorCode::LimitExceeded))?;
        if total > MAX_SERVICE_BATCH_BYTES
            || !keys.insert((write.namespace.clone(), write.key.clone()))
        {
            return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
        }
    }
    Ok(())
}

fn validate_worker_update(update: &WorkerUpdate) -> Result<(), ServiceError> {
    let (expected, owner, heartbeat, expiry, cursor_length) = match update {
        WorkerUpdate::Claim {
            expected,
            owner,
            now_unix_nanos,
            expires_at_unix_nanos,
        } => (
            *expected,
            owner,
            *now_unix_nanos,
            Some(*expires_at_unix_nanos),
            0,
        ),
        WorkerUpdate::Checkpoint {
            expected,
            owner,
            cursor,
            heartbeat_unix_nanos,
            expires_at_unix_nanos,
            ..
        } => (
            *expected,
            owner,
            *heartbeat_unix_nanos,
            Some(*expires_at_unix_nanos),
            cursor.len(),
        ),
        WorkerUpdate::Release {
            expected,
            owner,
            heartbeat_unix_nanos,
            ..
        } => (*expected, owner, *heartbeat_unix_nanos, None, 0),
    };
    validate_expected(expected)?;
    validate_selector(owner, MAX_WORKER_SELECTOR_BYTES, false)?;
    if heartbeat == 0
        || expiry.is_some_and(|expiry| expiry <= heartbeat)
        || cursor_length > MAX_WORKER_CURSOR_BYTES
    {
        return Err(ServiceError::new(ServiceErrorCode::InvalidInput));
    }
    Ok(())
}

fn check_expected(
    expected: ServiceExpectedVersion,
    actual: Option<u64>,
) -> Result<(), ServiceError> {
    let matches = match expected {
        ServiceExpectedVersion::Absent => actual.is_none(),
        ServiceExpectedVersion::Version(version) => actual == Some(version),
    };
    if matches {
        Ok(())
    } else {
        Err(ServiceError::new(ServiceErrorCode::RevisionConflict))
    }
}

fn validate_expected(expected: ServiceExpectedVersion) -> Result<(), ServiceError> {
    if matches!(expected, ServiceExpectedVersion::Version(0)) {
        Err(ServiceError::new(ServiceErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn validate_selector(value: &str, maximum: usize, allow_empty: bool) -> Result<(), ServiceError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(ServiceError::new(ServiceErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn validate_page_limit(limit: usize) -> Result<(), ServiceError> {
    if limit == 0 || limit > MAX_SERVICE_PAGE_ITEMS {
        Err(ServiceError::new(ServiceErrorCode::LimitExceeded))
    } else {
        Ok(())
    }
}

fn exact_digest(bytes: &[u8]) -> Result<ContentDigest, ServiceError> {
    let hash = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_error| ServiceError::new(ServiceErrorCode::Unavailable))?;
    }
    ContentDigest::new(encoded).map_err(|_error| ServiceError::new(ServiceErrorCode::Unavailable))
}

fn next_revision(revision: StoreRevision) -> Result<StoreRevision, ServiceError> {
    revision
        .0
        .checked_add(1)
        .map(StoreRevision)
        .ok_or_else(|| ServiceError::new(ServiceErrorCode::LimitExceeded))
}

fn increment(value: u64) -> Result<u64, ServiceError> {
    value
        .checked_add(1)
        .ok_or_else(|| ServiceError::new(ServiceErrorCode::LimitExceeded))
}

pub(crate) fn validate_committed_service_state(state: &CommittedState) -> Result<(), ServiceError> {
    for (tenant_id, tenant) in &state.tenants {
        validate_tenant_service_retention(tenant)?;
        for ((namespace, key), history) in &tenant.service_records {
            validate_record_history(state.revision, tenant_id, namespace, key, history)?;
        }
        for entry in tenant.service_idempotency.values() {
            validate_idempotency_entry(state, tenant_id, entry)?;
        }
        for (worker_name, worker) in &tenant.worker_states {
            let locator = WorkerLocator {
                tenant_id: tenant_id.clone(),
                worker: worker_name.clone(),
            };
            validate_worker_state(state.revision, &locator, worker)?;
        }
    }
    Ok(())
}

fn validate_record_history(
    state_revision: StoreRevision,
    tenant_id: &RecordId,
    namespace: &str,
    key: &str,
    history: &[ServiceRecord],
) -> Result<(), ServiceError> {
    if history.is_empty() {
        return Ok(());
    }
    let mut prior_revision = StoreRevision(0);
    for (index, record) in history.iter().enumerate() {
        let expected_version = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or_else(corrupt)?;
        if record.locator.tenant_id != *tenant_id
            || record.locator.namespace != namespace
            || record.locator.key != key
            || record.version != expected_version
            || record.store_revision <= prior_revision
            || record.store_revision > state_revision
            || record.bytes.is_empty()
            || record.bytes.len() > MAX_SERVICE_RECORD_BYTES
            || exact_digest(&record.bytes)? != record.digest
        {
            return Err(corrupt());
        }
        prior_revision = record.store_revision;
    }
    Ok(())
}

fn validate_idempotency_entry(
    state: &CommittedState,
    tenant_id: &RecordId,
    entry: &ServiceIdempotencyEntry,
) -> Result<(), ServiceError> {
    validate_response(&entry.receipt.response)?;
    if entry.receipt.replayed
        || entry.receipt.revision == StoreRevision(0)
        || entry.receipt.revision > state.revision
        || entry.receipt.records.is_empty()
        || entry.receipt.records.len() > MAX_SERVICE_BATCH_RECORDS
    {
        return Err(corrupt());
    }
    for version in &entry.receipt.records {
        validate_selector(&version.namespace, MAX_SERVICE_NAMESPACE_BYTES, false)
            .map_err(|_error| corrupt())?;
        validate_selector(&version.key, MAX_SERVICE_KEY_BYTES, false)
            .map_err(|_error| corrupt())?;
        if version.version == 0 {
            return Err(corrupt());
        }
        let record = state
            .tenants
            .get(tenant_id)
            .and_then(|tenant| {
                tenant
                    .service_records
                    .get(&(version.namespace.clone(), version.key.clone()))
            })
            .and_then(|history| {
                usize::try_from(version.version - 1)
                    .ok()
                    .and_then(|index| history.get(index))
            })
            .ok_or_else(corrupt)?;
        if record.digest != version.digest || record.store_revision != entry.receipt.revision {
            return Err(corrupt());
        }
    }
    Ok(())
}

fn validate_response(response: &ServiceResponse) -> Result<(), ServiceError> {
    if !(100..=599).contains(&response.status_code)
        || response.content_type.is_empty()
        || response.content_type.len() > 128
        || !response
            .content_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || response.bytes.len() > MAX_SERVICE_RESPONSE_BYTES
        || exact_digest(&response.bytes)? != response.digest
    {
        Err(corrupt())
    } else {
        Ok(())
    }
}

fn validate_worker_state(
    state_revision: StoreRevision,
    locator: &WorkerLocator,
    worker: &WorkerState,
) -> Result<(), ServiceError> {
    let lease_shape_valid = match (
        worker.lease_owner.as_deref(),
        worker.lease_expires_at_unix_nanos,
    ) {
        (Some(owner), Some(expiry)) => {
            validate_selector(owner, MAX_WORKER_SELECTOR_BYTES, false).is_ok()
                && expiry > worker.heartbeat_unix_nanos
        }
        (None, None) => true,
        _ => false,
    };
    if worker.locator != *locator
        || worker.version == 0
        || worker.store_revision == StoreRevision(0)
        || worker.store_revision > state_revision
        || worker.cursor.len() > MAX_WORKER_CURSOR_BYTES
        || exact_digest(&worker.cursor)? != worker.cursor_digest
        || worker.heartbeat_unix_nanos == 0
        || worker.fencing_token == 0
        || !lease_shape_valid
    {
        Err(corrupt())
    } else {
        Ok(())
    }
}

fn corrupt() -> ServiceError {
    ServiceError::new(ServiceErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        EffectRecoveryQuery, MAX_RETAINED_SERVICE_IDEMPOTENCY_ENTRIES,
        MAX_RETAINED_SERVICE_VERSIONS_PER_KEY, OutboxRecoveryQuery, ServiceBatch, ServiceErrorCode,
        ServiceExpectedVersion, ServiceIdempotency, ServiceListCursor, ServiceListQuery,
        ServiceListScope, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite,
        ServiceRepository, ServiceResponse, WorkerLocator, WorkerUpdate, apply_service_batch,
        exact_digest,
    };
    use crate::memory::CommittedState;
    use crate::{
        AccessContext, CancellationToken, EffectRecordEnvelope, InMemoryStore,
        MAX_RETAINED_SQLITE_SNAPSHOTS, OutboxMessage, Repository, ServiceRecord, SnapshotSelection,
        SqliteFailpoint, SqliteStore, StoreRevision, WriteTransaction,
    };
    use ciborium::value::Value;
    use cigar_protocol::{IdempotencyKey, RecordId};
    use std::error::Error;

    fn required<T>(value: Option<T>, message: &'static str) -> Result<T, Box<dyn Error>> {
        value
            .ok_or_else(|| std::io::Error::other(message))
            .map_err(Into::into)
    }

    fn required_at<T>(values: &[T], index: usize) -> Result<&T, Box<dyn Error>> {
        values
            .get(index)
            .ok_or_else(|| std::io::Error::other("required test item missing"))
            .map_err(Into::into)
    }

    fn error_code<T>(
        result: Result<T, super::ServiceError>,
    ) -> Result<ServiceErrorCode, Box<dyn Error>> {
        match result {
            Ok(_value) => Err(std::io::Error::other("operation unexpectedly succeeded").into()),
            Err(error) => Ok(error.code()),
        }
    }

    fn record(suffix: u64) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{suffix:012x}"
        ))?)
    }

    fn response(bytes: &[u8]) -> Result<ServiceResponse, Box<dyn Error>> {
        Ok(ServiceResponse::new(
            200,
            "application/json",
            bytes.to_vec(),
        )?)
    }

    fn write(
        key: &str,
        expected: ServiceExpectedVersion,
        bytes: &[u8],
    ) -> Result<ServiceRecordWrite, Box<dyn Error>> {
        Ok(ServiceRecordWrite::new(
            "spaces",
            key,
            expected,
            bytes.to_vec(),
        )?)
    }

    fn idempotency(key: &str, request: &[u8]) -> Result<ServiceIdempotency, Box<dyn Error>> {
        Ok(ServiceIdempotency::new(
            "createSpace",
            IdempotencyKey::new(key)?,
            exact_digest(request)?,
        )?)
    }

    fn get(
        repository: &dyn ServiceRepository,
        tenant: &RecordId,
        key: &str,
    ) -> Result<Option<ServiceRecord>, Box<dyn Error>> {
        let locator = ServiceRecordLocator::new(tenant.clone(), "spaces", key)?;
        Ok(repository.service_get(
            &locator,
            ServiceRecordSelection::Latest,
            &CancellationToken::default(),
        )?)
    }

    fn exercise_cas_atomicity_and_idempotency(
        repository: &dyn ServiceRepository,
        tenant: &RecordId,
    ) -> Result<(), Box<dyn Error>> {
        let first_response = response(br#"{"space":"one"}"#)?;
        let identity = idempotency("request-one", b"normalized-request-one")?;
        let first = ServiceBatch::new(
            tenant.clone(),
            vec![write("one", ServiceExpectedVersion::Absent, b"record-v1")?],
            first_response.clone(),
        )?
        .with_idempotency(identity.clone());
        let committed = repository.service_commit(first, &CancellationToken::default())?;
        assert_eq!(committed.revision, StoreRevision(1));
        assert!(!committed.replayed);
        assert_eq!(committed.response, first_response);
        assert_eq!(required_at(&committed.records, 0)?.version, 1);

        let replay = ServiceBatch::new(
            tenant.clone(),
            vec![write("one", ServiceExpectedVersion::Absent, b"ignored")?],
            response(b"ignored-response")?,
        )?
        .with_idempotency(identity);
        let replayed = repository.service_commit(replay, &CancellationToken::default())?;
        assert!(replayed.replayed);
        assert_eq!(replayed.revision, committed.revision);
        assert_eq!(replayed.response, first_response);
        assert_eq!(
            required(get(repository, tenant, "one")?, "record missing")?.bytes(),
            b"record-v1"
        );

        let collision = ServiceBatch::new(
            tenant.clone(),
            vec![write("other", ServiceExpectedVersion::Absent, b"other")?],
            response(b"collision")?,
        )?
        .with_idempotency(idempotency("request-one", b"different-request")?);
        assert_eq!(
            error_code(repository.service_commit(collision, &CancellationToken::default()))?,
            ServiceErrorCode::IdempotencyConflict
        );

        let update = ServiceBatch::new(
            tenant.clone(),
            vec![write(
                "one",
                ServiceExpectedVersion::Version(1),
                b"record-v2",
            )?],
            response(b"updated")?,
        )?;
        let updated = repository.service_commit(update, &CancellationToken::default())?;
        assert_eq!(required_at(&updated.records, 0)?.version, 2);
        let locator = ServiceRecordLocator::new(tenant.clone(), "spaces", "one")?;
        let original = required(
            repository.service_get(
                &locator,
                ServiceRecordSelection::Version(1),
                &CancellationToken::default(),
            )?,
            "retained immutable version missing",
        )?;
        assert_eq!(original.bytes(), b"record-v1");
        assert_eq!(
            required(get(repository, tenant, "one")?, "current record missing")?.bytes(),
            b"record-v2"
        );

        let revision_before = updated.revision;
        let partially_conflicting = ServiceBatch::new(
            tenant.clone(),
            vec![
                write(
                    "would-leak",
                    ServiceExpectedVersion::Absent,
                    b"must-not-publish",
                )?,
                write("one", ServiceExpectedVersion::Absent, b"conflict")?,
            ],
            response(b"must-not-return")?,
        )?;
        assert_eq!(
            error_code(
                repository.service_commit(partially_conflicting, &CancellationToken::default(),)
            )?,
            ServiceErrorCode::RevisionConflict
        );
        assert!(get(repository, tenant, "would-leak")?.is_none());
        let stale_global = ServiceBatch::new(
            tenant.clone(),
            vec![write("stale", ServiceExpectedVersion::Absent, b"stale")?],
            response(b"stale")?,
        )?
        .with_expected_store_revision(StoreRevision(revision_before.0.saturating_sub(1)));
        assert_eq!(
            error_code(repository.service_commit(stale_global, &CancellationToken::default()),)?,
            ServiceErrorCode::RevisionConflict
        );
        Ok(())
    }

    #[test]
    fn object_safe_memory_repository_enforces_cas_atomicity_and_exact_replay()
    -> Result<(), Box<dyn Error>> {
        let store = InMemoryStore::default();
        let repository: &dyn ServiceRepository = &store;
        exercise_cas_atomicity_and_idempotency(repository, &record(1)?)
    }

    #[test]
    fn sqlite_repository_enforces_cas_atomicity_and_exact_replay() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("service.sqlite3"))?;
        exercise_cas_atomicity_and_idempotency(&store, &record(2)?)
    }

    #[test]
    fn retained_service_quotas_fail_before_cloning_and_preserve_exact_replay()
    -> Result<(), Box<dyn Error>> {
        let tenant = record(20)?;
        let initial_identity = idempotency("request-0", b"normalized-request")?;
        let initial = ServiceBatch::new(
            tenant.clone(),
            vec![write("quota", ServiceExpectedVersion::Absent, b"record")?],
            response(b"response")?,
        )?
        .with_idempotency(initial_identity.clone());
        let (state, original_receipt) = apply_service_batch(&CommittedState::default(), initial)?;
        let mut state = required(state, "initial quota state missing")?;
        let tenant_state = state
            .tenants
            .get_mut(&tenant)
            .ok_or("initial quota tenant missing")?;
        let template = tenant_state
            .service_idempotency
            .values()
            .next()
            .cloned()
            .ok_or("initial idempotency entry missing")?;
        for index in 1..MAX_RETAINED_SERVICE_IDEMPOTENCY_ENTRIES {
            tenant_state.service_idempotency.insert(
                (
                    "createSpace".to_owned(),
                    IdempotencyKey::new(format!("request-{index}"))?,
                ),
                template.clone(),
            );
        }

        let replay = ServiceBatch::new(
            tenant.clone(),
            vec![write("quota", ServiceExpectedVersion::Absent, b"ignored")?],
            response(b"ignored")?,
        )?
        .with_idempotency(initial_identity);
        let (unchanged, replayed) = apply_service_batch(&state, replay)?;
        assert!(unchanged.is_none());
        assert!(replayed.replayed);
        assert_eq!(replayed.response, original_receipt.response);

        let rejected = ServiceBatch::new(
            tenant,
            vec![write("new-quota", ServiceExpectedVersion::Absent, b"new")?],
            response(b"new")?,
        )?
        .with_idempotency(idempotency("request-over-limit", b"new-request")?);
        assert_eq!(
            error_code(apply_service_batch(&state, rejected))?,
            ServiceErrorCode::LimitExceeded
        );
        Ok(())
    }

    #[test]
    fn service_version_history_has_a_hard_tenant_local_ceiling() -> Result<(), Box<dyn Error>> {
        let store = InMemoryStore::default();
        let tenant = record(21)?;
        for version in 0..MAX_RETAINED_SERVICE_VERSIONS_PER_KEY {
            let expected = if version == 0 {
                ServiceExpectedVersion::Absent
            } else {
                ServiceExpectedVersion::Version(u64::try_from(version)?)
            };
            store.service_commit(
                ServiceBatch::new(
                    tenant.clone(),
                    vec![write("bounded-history", expected, b"record")?],
                    response(b"response")?,
                )?,
                &CancellationToken::default(),
            )?;
        }
        let revision = store.revision()?;
        let rejected = ServiceBatch::new(
            tenant.clone(),
            vec![write(
                "bounded-history",
                ServiceExpectedVersion::Version(u64::try_from(
                    MAX_RETAINED_SERVICE_VERSIONS_PER_KEY,
                )?),
                b"over-limit",
            )?],
            response(b"over-limit")?,
        )?;
        assert_eq!(
            error_code(store.service_commit(rejected, &CancellationToken::default()))?,
            ServiceErrorCode::LimitExceeded
        );
        assert_eq!(store.revision()?, revision);
        assert_eq!(
            required(get(&store, &tenant, "bounded-history")?, "history missing")?.version(),
            u64::try_from(MAX_RETAINED_SERVICE_VERSIONS_PER_KEY)?
        );
        Ok(())
    }

    #[test]
    fn sqlite_retains_only_the_bounded_recent_snapshot_window() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("bounded-snapshots.sqlite3"))?;
        let locator = WorkerLocator::new(record(22)?, "snapshot-compactor")?;
        let mut state = store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "daemon-a".to_owned(),
                now_unix_nanos: 1,
                expires_at_unix_nanos: 1_000_000,
            },
            &CancellationToken::default(),
        )?;
        for heartbeat in 2..=u64::try_from(MAX_RETAINED_SQLITE_SNAPSHOTS + 2)? {
            state = store.worker_update(
                &locator,
                WorkerUpdate::Checkpoint {
                    expected: ServiceExpectedVersion::Version(state.version()),
                    owner: "daemon-a".to_owned(),
                    fencing_token: state.fencing_token(),
                    cursor: heartbeat.to_be_bytes().to_vec(),
                    heartbeat_unix_nanos: heartbeat,
                    expires_at_unix_nanos: 1_000_000 + heartbeat,
                },
                &CancellationToken::default(),
            )?;
        }
        let statistics = store.storage_statistics()?;
        assert_eq!(
            statistics.retained_snapshots,
            u64::try_from(MAX_RETAINED_SQLITE_SNAPSHOTS)?
        );
        assert!(statistics.database_bytes <= crate::MAX_SQLITE_DATABASE_BYTES);
        assert!(matches!(
            store.begin_read(
                AccessContext::new(locator.tenant_id().clone(), "expired-snapshot")?,
                SnapshotSelection::Revision(StoreRevision(0)),
                CancellationToken::default(),
            ),
            Err(error) if error.code() == crate::StoreErrorCode::NotFound
        ));
        assert!(
            store
                .worker_get(&locator, &CancellationToken::default())?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn paging_is_deterministic_scope_bound_and_snapshot_pinned() -> Result<(), Box<dyn Error>> {
        let store = InMemoryStore::default();
        let tenant = record(3)?;
        let writes = ["delta", "alpha", "charlie", "bravo"]
            .into_iter()
            .map(|key| write(key, ServiceExpectedVersion::Absent, key.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        store.service_commit(
            ServiceBatch::new(tenant.clone(), writes, response(b"page-one")?)?,
            &CancellationToken::default(),
        )?;
        let scope = ServiceListScope::new(tenant.clone(), "spaces", None)?;
        let first = store.service_list(
            &ServiceListQuery::new(scope.clone(), 2, None)?,
            &CancellationToken::default(),
        )?;
        assert_eq!(
            first
                .items
                .iter()
                .map(|item| item.locator().key())
                .collect::<Vec<_>>(),
            ["alpha", "bravo"]
        );
        let cursor = required(first.next.clone(), "continuation missing")?;
        let resumed = ServiceListCursor::resume(
            scope.clone(),
            cursor.snapshot_revision(),
            cursor.last_key(),
        )?;
        assert_eq!(resumed, cursor);

        store.service_commit(
            ServiceBatch::new(
                tenant.clone(),
                vec![write("between", ServiceExpectedVersion::Absent, b"new")?],
                response(b"later")?,
            )?,
            &CancellationToken::default(),
        )?;
        let second = store.service_list(
            &ServiceListQuery::new(scope.clone(), 2, Some(cursor.clone()))?,
            &CancellationToken::default(),
        )?;
        assert_eq!(second.revision, first.revision);
        assert_eq!(
            second
                .items
                .iter()
                .map(|item| item.locator().key())
                .collect::<Vec<_>>(),
            ["charlie", "delta"]
        );
        let other_scope = ServiceListScope::new(record(4)?, "spaces", None)?;
        assert_eq!(
            error_code(ServiceListQuery::new(other_scope, 2, Some(cursor)))?,
            ServiceErrorCode::CursorScopeMismatch
        );
        let fresh = store.service_list(
            &ServiceListQuery::new(scope, 10, None)?,
            &CancellationToken::default(),
        )?;
        assert_eq!(fresh.items.len(), 5);
        assert_eq!(required_at(&fresh.items, 1)?.locator().key(), "between");
        Ok(())
    }

    #[test]
    fn worker_checkpoint_lease_and_fencing_are_optimistic_and_durable() -> Result<(), Box<dyn Error>>
    {
        let store = InMemoryStore::default();
        let locator = WorkerLocator::new(record(5)?, "outbox-indexer")?;
        let first = store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "daemon-a".to_owned(),
                now_unix_nanos: 10,
                expires_at_unix_nanos: 100,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!((first.version(), first.fencing_token()), (1, 1));
        assert_eq!(
            error_code(store.worker_update(
                &locator,
                WorkerUpdate::Claim {
                    expected: ServiceExpectedVersion::Version(1),
                    owner: "daemon-b".to_owned(),
                    now_unix_nanos: 20,
                    expires_at_unix_nanos: 120,
                },
                &CancellationToken::default(),
            ))?,
            ServiceErrorCode::RevisionConflict
        );
        let checkpoint = store.worker_update(
            &locator,
            WorkerUpdate::Checkpoint {
                expected: ServiceExpectedVersion::Version(1),
                owner: "daemon-a".to_owned(),
                fencing_token: 1,
                cursor: b"revision:42".to_vec(),
                heartbeat_unix_nanos: 30,
                expires_at_unix_nanos: 130,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(checkpoint.version(), 2);
        assert_eq!(checkpoint.cursor(), b"revision:42");
        let released = store.worker_update(
            &locator,
            WorkerUpdate::Release {
                expected: ServiceExpectedVersion::Version(2),
                owner: "daemon-a".to_owned(),
                fencing_token: 1,
                heartbeat_unix_nanos: 40,
            },
            &CancellationToken::default(),
        )?;
        assert!(released.lease_owner().is_none());
        let reclaimed = store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Version(3),
                owner: "daemon-b".to_owned(),
                now_unix_nanos: 50,
                expires_at_unix_nanos: 150,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!((reclaimed.version(), reclaimed.fencing_token()), (4, 2));
        assert_eq!(reclaimed.cursor(), b"revision:42");
        let expired_reclaim = store.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Version(4),
                owner: "daemon-c".to_owned(),
                now_unix_nanos: 151,
                expires_at_unix_nanos: 251,
            },
            &CancellationToken::default(),
        )?;
        assert_eq!(expired_reclaim.fencing_token(), 3);
        assert_eq!(
            required(
                store.worker_get(&locator, &CancellationToken::default())?,
                "worker missing after reclaim",
            )?,
            expired_reclaim
        );
        Ok(())
    }

    fn seed_recovery<R: Repository>(
        repository: &R,
        tenant: &RecordId,
    ) -> Result<(RecordId, RecordId), Box<dyn Error>> {
        let effect_id = record(100)?;
        let message_id = record(101)?;
        let effect_bytes = b"opaque-effect-record".to_vec();
        let effect = EffectRecordEnvelope::new(
            effect_id.clone(),
            0,
            exact_digest(&effect_bytes)?,
            effect_bytes,
        )?;
        let mut transaction = repository.begin_write(
            AccessContext::new(tenant.clone(), "effect-recovery")?,
            StoreRevision(0),
            CancellationToken::default(),
        )?;
        transaction.put_effect_record(effect)?;
        transaction.enqueue_outbox(OutboxMessage {
            message_id: message_id.clone(),
            topic: "effect.dispatch".to_owned(),
            payload_digest: exact_digest(b"wakeup")?,
        })?;
        let receipt = transaction.commit(None)?;
        assert_eq!(receipt.revision, StoreRevision(1));
        Ok((effect_id, message_id))
    }

    #[test]
    fn current_effects_and_pending_outbox_are_enumerable_for_recovery() -> Result<(), Box<dyn Error>>
    {
        let store = InMemoryStore::default();
        let tenant = record(6)?;
        let (effect_id, message_id) = seed_recovery(&store, &tenant)?;
        let effects = store.effect_recovery(
            &EffectRecoveryQuery::new(tenant.clone(), 1, None)?,
            &CancellationToken::default(),
        )?;
        assert_eq!(effects.items.len(), 1);
        let effect = required_at(&effects.items, 0)?;
        assert_eq!(effect.record.effect_id, effect_id);
        assert!(effect.latest_event.is_none());
        let outbox = store.outbox_recovery(
            &OutboxRecoveryQuery::new(tenant, 1, None)?,
            &CancellationToken::default(),
        )?;
        assert_eq!(outbox.items.len(), 1);
        let outbox_item = required_at(&outbox.items, 0)?;
        assert_eq!(outbox_item.message.message_id, message_id);
        assert_eq!(outbox_item.causal_revision, StoreRevision(1));
        Ok(())
    }

    #[test]
    fn sqlite_restart_preserves_records_exact_replay_workers_and_recovery()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("restart.sqlite3");
        let tenant = record(7)?;
        let identity = idempotency("restart-request", b"restart-normalized")?;
        let expected_response = response(b"restart-response")?;
        let worker = WorkerLocator::new(tenant.clone(), "reconciliation")?;
        let (effect_id, message_id) = {
            let store = SqliteStore::open(&path)?;
            let (effect_id, message_id) = seed_recovery(&store, &tenant)?;
            let receipt = store.service_commit(
                ServiceBatch::new(
                    tenant.clone(),
                    vec![write(
                        "restart",
                        ServiceExpectedVersion::Absent,
                        b"exact-record",
                    )?],
                    expected_response.clone(),
                )?
                .with_idempotency(identity.clone()),
                &CancellationToken::default(),
            )?;
            assert_eq!(receipt.revision, StoreRevision(2));
            store.worker_update(
                &worker,
                WorkerUpdate::Claim {
                    expected: ServiceExpectedVersion::Absent,
                    owner: "daemon-restart".to_owned(),
                    now_unix_nanos: 10,
                    expires_at_unix_nanos: 100,
                },
                &CancellationToken::default(),
            )?;
            (effect_id, message_id)
        };

        let reopened = SqliteStore::open(&path)?;
        assert_eq!(
            required(
                get(&reopened, &tenant, "restart")?,
                "record missing after restart",
            )?
            .bytes(),
            b"exact-record"
        );
        let replayed = reopened.service_commit(
            ServiceBatch::new(
                tenant.clone(),
                vec![write(
                    "restart",
                    ServiceExpectedVersion::Absent,
                    b"ignored",
                )?],
                response(b"ignored")?,
            )?
            .with_idempotency(identity),
            &CancellationToken::default(),
        )?;
        assert!(replayed.replayed);
        assert_eq!(replayed.response, expected_response);
        let worker_state = required(
            reopened.worker_get(&worker, &CancellationToken::default())?,
            "worker missing after restart",
        )?;
        assert_eq!(worker_state.fencing_token(), 1);
        let effects = reopened.effect_recovery(
            &EffectRecoveryQuery::new(tenant.clone(), 10, None)?,
            &CancellationToken::default(),
        )?;
        assert_eq!(required_at(&effects.items, 0)?.record.effect_id, effect_id);
        let outbox = reopened.outbox_recovery(
            &OutboxRecoveryQuery::new(tenant.clone(), 10, None)?,
            &CancellationToken::default(),
        )?;
        assert_eq!(
            required_at(&outbox.items, 0)?.message.message_id,
            message_id
        );
        let read = reopened.begin_read(
            AccessContext::new(tenant, "verify-revision")?,
            SnapshotSelection::Latest,
            CancellationToken::default(),
        )?;
        assert_eq!(crate::ReadTransaction::revision(&read), StoreRevision(3));
        Ok(())
    }

    #[test]
    fn injected_abort_never_publishes_partial_service_state() -> Result<(), Box<dyn Error>> {
        let store = InMemoryStore::default();
        let tenant = record(8)?;
        store.fail_next_commit();
        let result = store.service_commit(
            ServiceBatch::new(
                tenant.clone(),
                vec![write("aborted", ServiceExpectedVersion::Absent, b"hidden")?],
                response(b"hidden")?,
            )?,
            &CancellationToken::default(),
        );
        assert_eq!(error_code(result)?, ServiceErrorCode::InjectedAbort);
        assert_eq!(store.revision()?, StoreRevision(0));
        assert!(get(&store, &tenant, "aborted")?.is_none());
        Ok(())
    }

    #[test]
    fn sqlite_service_failpoint_rolls_back_state_and_restart_anchor() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("service-abort.sqlite3");
        let tenant = record(10)?;
        {
            let store = SqliteStore::open(&path)?;
            store.inject_failpoint(SqliteFailpoint::BeforeCommit)?;
            let result = store.service_commit(
                ServiceBatch::new(
                    tenant.clone(),
                    vec![write(
                        "aborted-sqlite",
                        ServiceExpectedVersion::Absent,
                        b"hidden",
                    )?],
                    response(b"hidden")?,
                )?,
                &CancellationToken::default(),
            );
            assert_eq!(error_code(result)?, ServiceErrorCode::InjectedAbort);
            assert_eq!(store.revision()?, StoreRevision(0));
        }
        let reopened = SqliteStore::open(&path)?;
        assert_eq!(reopened.revision()?, StoreRevision(0));
        assert!(get(&reopened, &tenant, "aborted-sqlite")?.is_none());
        Ok(())
    }

    #[test]
    fn legacy_tenant_snapshots_decode_with_empty_service_state() -> Result<(), Box<dyn Error>> {
        let tenant_id = record(9)?;
        let mut state = crate::memory::CommittedState::default();
        state
            .tenants
            .insert(tenant_id.clone(), crate::memory::TenantState::default());
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&state, &mut encoded)?;
        let mut value: Value = ciborium::de::from_reader(encoded.as_slice())?;
        let Value::Map(root) = &mut value else {
            return Err(std::io::Error::other("state must encode as a CBOR map").into());
        };
        let tenants = root
            .iter_mut()
            .find_map(|(key, value)| (key == &Value::Text("tenants".to_owned())).then_some(value));
        let Value::Map(tenants) = required(tenants, "tenants field missing")? else {
            return Err(std::io::Error::other("tenants must encode as a CBOR map").into());
        };
        let tenant = tenants.first_mut().map(|(_key, value)| value);
        let Value::Map(tenant) = required(tenant, "tenant state missing")? else {
            return Err(std::io::Error::other("tenant must encode as a CBOR map").into());
        };
        tenant.retain(|(key, _value)| {
            !matches!(
                key,
                Value::Text(name)
                    if matches!(
                        name.as_str(),
                        "service_records" | "service_idempotency" | "worker_states"
                    )
            )
        });
        let mut legacy = Vec::new();
        ciborium::ser::into_writer(&value, &mut legacy)?;
        let decoded: crate::memory::CommittedState = ciborium::de::from_reader(legacy.as_slice())?;
        let tenant = required(decoded.tenants.get(&tenant_id), "decoded tenant missing")?;
        assert!(tenant.service_records.is_empty());
        assert!(tenant.service_idempotency.is_empty());
        assert!(tenant.worker_states.is_empty());
        Ok(())
    }
}
