//! Strict canonical records for SQLite repository format v5.

#![allow(
    dead_code,
    reason = "H91-220 staged-delta and replay helpers are intentionally landed before store wiring"
)]

use crate::memory::{BlobState, CommittedState, StagedMutation, TenantState, apply_mutation};
use crate::service_repository::{ServiceIdempotencyEntry, validate_committed_service_state};
use crate::{
    AccessContext, CommitReceipt, EffectRecordEnvelope, IdempotencyIdentity, OutboxRecord,
    ServiceBatchReceipt, ServiceRecord, StoreError, StoreErrorCode, StoreRevision, WorkerState,
};
use cigar_canon::{CanonicalNode, from_deterministic_cbor, to_deterministic_cbor};
use cigar_protocol::{
    BlobRef, ContentDigest, ContextBundle, ContextCommit, ContextSpaceId, EffectJournalEvent,
    IdempotencyKey, RecordId, SourceSnapshot, Validate, VersionId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Fresh-target-only SQLite v5 schema. Ordinary `SqliteStore::open` never applies this SQL.
pub const SQLITE_FRESH_TARGET_SCHEMA_V5: &str =
    include_str!("../migrations/sqlite/0005_incremental_repository_state.sql");
/// Exact public JSON Schema authenticated by every v5 repository authority.
pub const SQLITE_V4_V5_MIGRATION_RECEIPT_SCHEMA_V1: &str =
    include_str!("../../../schemas/json/sqlite-v4-v5-migration-receipt-v1.schema.json");
/// Exact durable record format for the initial v5 implementation.
pub const REPOSITORY_FORMAT_V5: u64 = 5;
/// Maximum typed residual and catalog mutations represented by one delta.
pub const MAX_REPOSITORY_DELTA_OPERATIONS_V5: usize = 4_096;
/// Maximum canonical bytes in one encoded v5 delta.
pub const MAX_REPOSITORY_DELTA_BYTES_V5: usize = 67_108_864;
/// Maximum deterministic bytes in one typed mutation record.
pub const MAX_REPOSITORY_DELTA_RECORD_BYTES_V5: usize = 16_777_216;
/// Maximum canonical catalog-free state bytes in one checkpoint.
pub const MAX_REPOSITORY_CHECKPOINT_BYTES_V5: usize = 268_435_456;
/// Maximum deltas replayed from the latest authenticated checkpoint.
pub const MAX_DELTAS_SINCE_CHECKPOINT_V5: usize = 256;
/// Maximum accumulated canonical delta bytes replayed from one checkpoint.
pub const MAX_ACCUMULATED_DELTA_BYTES_V5: usize = 268_435_456;
/// Maximum typed operations admitted across one bounded replay suffix.
pub const MAX_REPLAY_OPERATIONS_V5: usize =
    MAX_REPOSITORY_DELTA_OPERATIONS_V5 * MAX_DELTAS_SINCE_CHECKPOINT_V5;

const _: () = {
    assert!(MAX_REPOSITORY_DELTA_BYTES_V5 <= MAX_ACCUMULATED_DELTA_BYTES_V5);
    assert!(MAX_DELTAS_SINCE_CHECKPOINT_V5 > 0);
    assert!(MAX_REPLAY_OPERATIONS_V5 > MAX_REPOSITORY_DELTA_OPERATIONS_V5);
};

const DELTA_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-DELTA";
const CHECKPOINT_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-CHECKPOINT";
const STATE_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-STATE";
const SEMANTIC_ROOT_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-SEMANTIC-ROOT";
const CHAIN_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-CHAIN";
const GENESIS_PARENT_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-GENESIS-PARENT";
const PURPOSE_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-PURPOSE";
const CATALOG_MUTATIONS_DOMAIN: &[u8] = b"CIGAR-REPOSITORY-V5-CATALOG-MUTATIONS";

fn invalid_record() -> StoreError {
    StoreError::new(StoreErrorCode::InvalidRecord)
}

fn limit_exceeded() -> StoreError {
    StoreError::new(StoreErrorCode::LimitExceeded)
}

fn checked_next(revision: StoreRevision) -> Result<StoreRevision, StoreError> {
    revision
        .0
        .checked_add(1)
        .map(StoreRevision)
        .ok_or_else(limit_exceeded)
}

fn digest(domain: &[u8], fields: &[&[u8]]) -> Result<ContentDigest, StoreError> {
    let mut hash = Sha256::new();
    hash.update(
        u64::try_from(domain.len())
            .map_err(|_error| limit_exceeded())?
            .to_be_bytes(),
    );
    hash.update(domain);
    for field in fields {
        hash.update(
            u64::try_from(field.len())
                .map_err(|_error| limit_exceeded())?
                .to_be_bytes(),
        );
        hash.update(field);
    }
    let suffix = hash.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    for byte in suffix {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| invalid_record())?;
    }
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

fn raw_sha256_multihash(bytes: &[u8]) -> Result<ContentDigest, StoreError> {
    let suffix = Sha256::digest(bytes);
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    for byte in suffix {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_error| invalid_record())?;
    }
    ContentDigest::new(value).map_err(|_error| invalid_record())
}

/// Raw SHA-256 multihash of the exact migration-receipt JSON Schema bytes.
pub fn migration_receipt_schema_digest_v1() -> Result<ContentDigest, StoreError> {
    raw_sha256_multihash(SQLITE_V4_V5_MIGRATION_RECEIPT_SCHEMA_V1.as_bytes())
}

fn canonical_map(
    entries: impl IntoIterator<Item = (&'static str, CanonicalNode)>,
) -> CanonicalNode {
    CanonicalNode::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn exact_map(
    node: CanonicalNode,
    required: &[&str],
) -> Result<BTreeMap<String, CanonicalNode>, StoreError> {
    let CanonicalNode::Map(values) = node else {
        return Err(invalid_record());
    };
    if values.len() != required.len() || required.iter().any(|key| !values.contains_key(*key)) {
        return Err(invalid_record());
    }
    Ok(values)
}

fn remove_unsigned(
    values: &mut BTreeMap<String, CanonicalNode>,
    key: &str,
) -> Result<u64, StoreError> {
    match values.remove(key) {
        Some(CanonicalNode::Unsigned(value)) => Ok(value),
        _ => Err(invalid_record()),
    }
}

fn remove_text(
    values: &mut BTreeMap<String, CanonicalNode>,
    key: &str,
) -> Result<String, StoreError> {
    match values.remove(key) {
        Some(CanonicalNode::Text(value)) => Ok(value),
        _ => Err(invalid_record()),
    }
}

fn remove_bytes(
    values: &mut BTreeMap<String, CanonicalNode>,
    key: &str,
) -> Result<Vec<u8>, StoreError> {
    match values.remove(key) {
        Some(CanonicalNode::Bytes(value)) => Ok(value),
        _ => Err(invalid_record()),
    }
}

fn remove_digest(
    values: &mut BTreeMap<String, CanonicalNode>,
    key: &str,
) -> Result<ContentDigest, StoreError> {
    ContentDigest::new(remove_text(values, key)?).map_err(|_error| invalid_record())
}

fn encode_typed<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_error| invalid_record())?;
    if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_DELTA_RECORD_BYTES_V5 {
        return Err(limit_exceeded());
    }
    Ok(bytes)
}

fn decode_typed<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_DELTA_RECORD_BYTES_V5 {
        return Err(limit_exceeded());
    }
    let value: T = ciborium::de::from_reader(bytes).map_err(|_error| invalid_record())?;
    if encode_typed(&value)? != bytes {
        return Err(invalid_record());
    }
    Ok(value)
}

fn encode_typed_checkpoint<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_error| invalid_record())?;
    if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5 {
        return Err(limit_exceeded());
    }
    Ok(bytes)
}

fn decode_typed_checkpoint<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5 {
        return Err(limit_exceeded());
    }
    let value: T = ciborium::de::from_reader(bytes).map_err(|_error| invalid_record())?;
    if encode_typed_checkpoint(&value)? != bytes {
        return Err(invalid_record());
    }
    Ok(value)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogFreeStateV5 {
    format_version: u8,
    revision: StoreRevision,
    tenants: BTreeMap<RecordId, CatalogFreeTenantStateV5>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogFreeTenantStateV5 {
    bundles: BTreeMap<VersionId, ContextBundle>,
    snapshots: BTreeMap<RecordId, SourceSnapshot>,
    context_commits: BTreeMap<ContextSpaceId, Vec<ContextCommit>>,
    effects: BTreeMap<RecordId, Vec<EffectJournalEvent>>,
    effect_records: BTreeMap<RecordId, EffectRecordEnvelope>,
    blobs: BTreeMap<ContentDigest, BlobState>,
    outbox: Vec<OutboxRecord>,
    idempotency: BTreeMap<(String, IdempotencyKey), (ContentDigest, CommitReceipt)>,
    service_records: BTreeMap<(String, String), Vec<ServiceRecord>>,
    service_idempotency: BTreeMap<(String, IdempotencyKey), ServiceIdempotencyEntry>,
    worker_states: BTreeMap<String, WorkerState>,
}

impl CatalogFreeStateV5 {
    fn from_state(state: &CommittedState) -> Self {
        Self {
            format_version: 5,
            revision: state.revision,
            tenants: state
                .tenants
                .iter()
                .map(|(tenant_id, tenant)| {
                    (
                        tenant_id.clone(),
                        CatalogFreeTenantStateV5 {
                            bundles: tenant.bundles.clone(),
                            snapshots: tenant.snapshots.clone(),
                            context_commits: tenant.context_commits.clone(),
                            effects: tenant.effects.clone(),
                            effect_records: tenant.effect_records.clone(),
                            blobs: tenant
                                .blobs
                                .iter()
                                .map(|(digest, blob)| {
                                    (
                                        digest.clone(),
                                        BlobState {
                                            reference: blob.reference.clone(),
                                            bytes: None,
                                        },
                                    )
                                })
                                .collect(),
                            outbox: tenant.outbox.clone(),
                            idempotency: tenant.idempotency.clone(),
                            service_records: tenant.service_records.clone(),
                            service_idempotency: tenant.service_idempotency.clone(),
                            worker_states: tenant.worker_states.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn into_state(self) -> Result<CommittedState, StoreError> {
        if self.format_version != 5 {
            return Err(invalid_record());
        }
        let state = CommittedState {
            revision: self.revision,
            tenants: self
                .tenants
                .into_iter()
                .map(|(tenant_id, tenant)| {
                    (
                        tenant_id,
                        TenantState {
                            atoms: BTreeMap::new(),
                            atom_versions_by_id: BTreeMap::new(),
                            current_versions_by_lineage: BTreeMap::new(),
                            edges: BTreeMap::new(),
                            bundles: tenant.bundles,
                            snapshots: tenant.snapshots,
                            context_commits: tenant.context_commits,
                            effects: tenant.effects,
                            effect_records: tenant.effect_records,
                            blobs: tenant.blobs,
                            outbox: tenant.outbox,
                            idempotency: tenant.idempotency,
                            service_records: tenant.service_records,
                            service_idempotency: tenant.service_idempotency,
                            worker_states: tenant.worker_states,
                        },
                    )
                })
                .collect(),
        };
        validate_committed_service_state(&state).map_err(|_error| invalid_record())?;
        Ok(state)
    }
}

/// Encodes complete catalog-free state as a bounded canonical v5 checkpoint payload.
pub(crate) fn encode_catalog_free_state_v5(state: &CommittedState) -> Result<Vec<u8>, StoreError> {
    let record = encode_typed_checkpoint(&CatalogFreeStateV5::from_state(state))?;
    let encoded = to_deterministic_cbor(&canonical_map([
        (
            "format_version",
            CanonicalNode::Unsigned(REPOSITORY_FORMAT_V5),
        ),
        ("residual_record", CanonicalNode::Bytes(record)),
    ]))
    .map_err(|_error| invalid_record())?;
    if encoded.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5 {
        return Err(limit_exceeded());
    }
    Ok(encoded)
}

/// Decodes and strictly re-encodes one complete catalog-free v5 checkpoint payload.
pub(crate) fn decode_catalog_free_state_v5(bytes: &[u8]) -> Result<CommittedState, StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5 {
        return Err(limit_exceeded());
    }
    let node = from_deterministic_cbor(bytes).map_err(|_error| invalid_record())?;
    let mut values = exact_map(node, &["format_version", "residual_record"])?;
    if remove_unsigned(&mut values, "format_version")? != REPOSITORY_FORMAT_V5 {
        return Err(invalid_record());
    }
    let record = remove_bytes(&mut values, "residual_record")?;
    let state = decode_typed_checkpoint::<CatalogFreeStateV5>(&record)?.into_state()?;
    if encode_catalog_free_state_v5(&state)? != bytes {
        return Err(invalid_record());
    }
    Ok(state)
}

/// Exact request-idempotency insertion represented by one v5 delta mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestIdempotencyMutationV5 {
    scope: String,
    key: IdempotencyKey,
    request_digest: ContentDigest,
    receipt: CommitReceipt,
}

impl RequestIdempotencyMutationV5 {
    /// Creates one bounded request-idempotency record.
    pub fn new(
        scope: impl Into<String>,
        key: IdempotencyKey,
        request_digest: ContentDigest,
        receipt: CommitReceipt,
    ) -> Result<Self, StoreError> {
        let result = Self {
            scope: scope.into(),
            key,
            request_digest,
            receipt,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.scope.is_empty()
            || self.scope.len() > 256
            || self.scope.bytes().any(|byte| byte.is_ascii_control())
            || self.receipt.revision.0 == 0
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

/// Exact service-idempotency state inserted with an applied service batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdempotencyMutationV5 {
    operation: String,
    key: IdempotencyKey,
    request_digest: ContentDigest,
    receipt: ServiceBatchReceipt,
}

impl ServiceIdempotencyMutationV5 {
    fn from_entry(operation: String, key: IdempotencyKey, entry: &ServiceIdempotencyEntry) -> Self {
        Self {
            operation,
            key,
            request_digest: entry.request_digest.clone(),
            receipt: entry.receipt.clone(),
        }
    }
}

/// Exact resulting records and optional receipt from one atomic service batch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBatchMutationV5 {
    records: Vec<ServiceRecord>,
    idempotency: Option<ServiceIdempotencyMutationV5>,
}

impl ServiceBatchMutationV5 {
    fn from_states(
        latest: &CommittedState,
        next: &CommittedState,
        tenant_id: &RecordId,
        receipt: &ServiceBatchReceipt,
    ) -> Result<Self, StoreError> {
        let next_tenant = next.tenants.get(tenant_id).ok_or_else(invalid_record)?;
        let records = receipt
            .records
            .iter()
            .map(|published| {
                next_tenant
                    .service_records
                    .get(&(published.namespace.clone(), published.key.clone()))
                    .and_then(|history| {
                        history
                            .iter()
                            .find(|record| record.version() == published.version)
                    })
                    .filter(|record| record.digest() == &published.digest)
                    .cloned()
                    .ok_or_else(invalid_record)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let latest_tenant = latest.tenants.get(tenant_id);
        let mut added_idempotency = next_tenant
            .service_idempotency
            .iter()
            .filter(|(identity, entry)| {
                latest_tenant.and_then(|tenant| tenant.service_idempotency.get(*identity))
                    != Some(*entry)
            })
            .map(|((operation, key), entry)| {
                ServiceIdempotencyMutationV5::from_entry(operation.clone(), key.clone(), entry)
            });
        let idempotency = added_idempotency.next();
        if added_idempotency.next().is_some() {
            return Err(invalid_record());
        }
        Ok(Self {
            records,
            idempotency,
        })
    }
}

/// Closed typed catalog-free mutation domain for v5.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryMutationV5 {
    /// Insert one immutable source snapshot.
    InsertSourceSnapshot(SourceSnapshot),
    /// Insert one immutable compiled context bundle.
    InsertBundle(ContextBundle),
    /// Append one context-space commit.
    AppendContextCommit(ContextCommit),
    /// Append one effect journal event.
    AppendEffectJournalEvent(EffectJournalEvent),
    /// Replace one monotonic effect record envelope.
    ReplaceEffectRecord(EffectRecordEnvelope),
    /// Insert one immutable external blob reference; plaintext is never copied into the delta.
    InsertBlobReference(BlobRef),
    /// Append one causal outbox record.
    AppendOutbox(OutboxRecord),
    /// Insert one request-bound repository idempotency receipt.
    InsertRequestIdempotency(RequestIdempotencyMutationV5),
    /// Apply one exact service batch result.
    ApplyServiceBatch(ServiceBatchMutationV5),
    /// Replace one exact worker state after a validated transition.
    TransitionWorker(WorkerState),
}

impl RepositoryMutationV5 {
    fn kind(&self) -> &'static str {
        match self {
            Self::InsertSourceSnapshot(_) => "insert_source_snapshot",
            Self::InsertBundle(_) => "insert_bundle",
            Self::AppendContextCommit(_) => "append_context_commit",
            Self::AppendEffectJournalEvent(_) => "append_effect_journal_event",
            Self::ReplaceEffectRecord(_) => "replace_effect_record",
            Self::InsertBlobReference(_) => "insert_blob_reference",
            Self::AppendOutbox(_) => "append_outbox",
            Self::InsertRequestIdempotency(_) => "insert_request_idempotency",
            Self::ApplyServiceBatch(_) => "apply_service_batch",
            Self::TransitionWorker(_) => "transition_worker",
        }
    }

    fn encode_record(&self) -> Result<Vec<u8>, StoreError> {
        match self {
            Self::InsertSourceSnapshot(value) => encode_typed(value),
            Self::InsertBundle(value) => encode_typed(value),
            Self::AppendContextCommit(value) => encode_typed(value),
            Self::AppendEffectJournalEvent(value) => encode_typed(value),
            Self::ReplaceEffectRecord(value) => encode_typed(value),
            Self::InsertBlobReference(value) => encode_typed(value),
            Self::AppendOutbox(value) => encode_typed(value),
            Self::InsertRequestIdempotency(value) => encode_typed(value),
            Self::ApplyServiceBatch(value) => encode_typed(value),
            Self::TransitionWorker(value) => encode_typed(value),
        }
    }

    fn decode(kind: &str, bytes: &[u8]) -> Result<Self, StoreError> {
        match kind {
            "insert_source_snapshot" => Ok(Self::InsertSourceSnapshot(decode_typed(bytes)?)),
            "insert_bundle" => Ok(Self::InsertBundle(decode_typed(bytes)?)),
            "append_context_commit" => Ok(Self::AppendContextCommit(decode_typed(bytes)?)),
            "append_effect_journal_event" => {
                Ok(Self::AppendEffectJournalEvent(decode_typed(bytes)?))
            }
            "replace_effect_record" => Ok(Self::ReplaceEffectRecord(decode_typed(bytes)?)),
            "insert_blob_reference" => Ok(Self::InsertBlobReference(decode_typed(bytes)?)),
            "append_outbox" => Ok(Self::AppendOutbox(decode_typed(bytes)?)),
            "insert_request_idempotency" => {
                Ok(Self::InsertRequestIdempotency(decode_typed(bytes)?))
            }
            "apply_service_batch" => Ok(Self::ApplyServiceBatch(decode_typed(bytes)?)),
            "transition_worker" => Ok(Self::TransitionWorker(decode_typed(bytes)?)),
            _ => Err(invalid_record()),
        }
    }

    fn validate(&self, result_revision: StoreRevision) -> Result<(), StoreError> {
        match self {
            Self::InsertSourceSnapshot(value) => {
                value.validate().map_err(|_error| invalid_record())?
            }
            Self::InsertBundle(value) => value.validate().map_err(|_error| invalid_record())?,
            Self::AppendContextCommit(value) => {
                value.validate().map_err(|_error| invalid_record())?
            }
            Self::AppendEffectJournalEvent(value) => {
                value.validate().map_err(|_error| invalid_record())?
            }
            Self::ReplaceEffectRecord(value) => {
                if raw_sha256_multihash(value.bytes())? != value.record_digest {
                    return Err(invalid_record());
                }
            }
            Self::InsertBlobReference(_value) => {}
            Self::AppendOutbox(value) => {
                value.message.validate()?;
                if value.causal_revision != result_revision {
                    return Err(invalid_record());
                }
            }
            Self::InsertRequestIdempotency(value) => {
                value.validate()?;
                if value.receipt.revision != result_revision {
                    return Err(invalid_record());
                }
            }
            Self::ApplyServiceBatch(value) => {
                if value.records.len() > crate::MAX_SERVICE_BATCH_RECORDS
                    || value
                        .records
                        .iter()
                        .any(|record| record.store_revision() != result_revision)
                    || value.idempotency.as_ref().is_some_and(|record| {
                        record.operation.is_empty()
                            || record.operation.len() > 256
                            || record.receipt.revision != result_revision
                            || record.receipt.replayed
                    })
                {
                    return Err(invalid_record());
                }
            }
            Self::TransitionWorker(value) => {
                if value.store_revision() != result_revision {
                    return Err(invalid_record());
                }
            }
        }
        let _ = self.encode_record()?;
        Ok(())
    }
}

/// Closed exact mutation counts authenticated by one v5 delta.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryMutationCountsV5 {
    /// Source snapshot insertions.
    pub source_snapshots: u32,
    /// Bundle insertions.
    pub bundles: u32,
    /// Context commit appends.
    pub context_commits: u32,
    /// Effect journal appends.
    pub effect_events: u32,
    /// Effect record replacements.
    pub effect_records: u32,
    /// External blob-reference insertions.
    pub blob_references: u32,
    /// Causal outbox appends.
    pub outbox_records: u32,
    /// Repository idempotency insertions.
    pub request_idempotency: u32,
    /// Service batch applications.
    pub service_batches: u32,
    /// Worker transitions.
    pub worker_transitions: u32,
    /// Ordered normalized catalog mutations bound outside the residual record list.
    pub catalog_mutations: u32,
}

impl RepositoryMutationCountsV5 {
    fn from_mutations(
        mutations: &[RepositoryMutationV5],
        catalog_mutations: u32,
    ) -> Result<Self, StoreError> {
        let mut counts = Self {
            catalog_mutations,
            ..Self::default()
        };
        for mutation in mutations {
            let counter = match mutation {
                RepositoryMutationV5::InsertSourceSnapshot(_) => &mut counts.source_snapshots,
                RepositoryMutationV5::InsertBundle(_) => &mut counts.bundles,
                RepositoryMutationV5::AppendContextCommit(_) => &mut counts.context_commits,
                RepositoryMutationV5::AppendEffectJournalEvent(_) => &mut counts.effect_events,
                RepositoryMutationV5::ReplaceEffectRecord(_) => &mut counts.effect_records,
                RepositoryMutationV5::InsertBlobReference(_) => &mut counts.blob_references,
                RepositoryMutationV5::AppendOutbox(_) => &mut counts.outbox_records,
                RepositoryMutationV5::InsertRequestIdempotency(_) => {
                    &mut counts.request_idempotency
                }
                RepositoryMutationV5::ApplyServiceBatch(_) => &mut counts.service_batches,
                RepositoryMutationV5::TransitionWorker(_) => &mut counts.worker_transitions,
            };
            *counter = counter.checked_add(1).ok_or_else(limit_exceeded)?;
        }
        Ok(counts)
    }

    /// Returns the checked total residual plus catalog mutation count.
    pub fn total(self) -> Result<u64, StoreError> {
        [
            self.source_snapshots,
            self.bundles,
            self.context_commits,
            self.effect_events,
            self.effect_records,
            self.blob_references,
            self.outbox_records,
            self.request_idempotency,
            self.service_batches,
            self.worker_transitions,
            self.catalog_mutations,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(u64::from(value)))
        .ok_or_else(limit_exceeded)
    }

    fn to_node(self) -> CanonicalNode {
        canonical_map([
            (
                "blob_references",
                CanonicalNode::Unsigned(u64::from(self.blob_references)),
            ),
            ("bundles", CanonicalNode::Unsigned(u64::from(self.bundles))),
            (
                "catalog_mutations",
                CanonicalNode::Unsigned(u64::from(self.catalog_mutations)),
            ),
            (
                "context_commits",
                CanonicalNode::Unsigned(u64::from(self.context_commits)),
            ),
            (
                "effect_events",
                CanonicalNode::Unsigned(u64::from(self.effect_events)),
            ),
            (
                "effect_records",
                CanonicalNode::Unsigned(u64::from(self.effect_records)),
            ),
            (
                "outbox_records",
                CanonicalNode::Unsigned(u64::from(self.outbox_records)),
            ),
            (
                "request_idempotency",
                CanonicalNode::Unsigned(u64::from(self.request_idempotency)),
            ),
            (
                "service_batches",
                CanonicalNode::Unsigned(u64::from(self.service_batches)),
            ),
            (
                "source_snapshots",
                CanonicalNode::Unsigned(u64::from(self.source_snapshots)),
            ),
            (
                "worker_transitions",
                CanonicalNode::Unsigned(u64::from(self.worker_transitions)),
            ),
        ])
    }

    fn from_node(node: CanonicalNode) -> Result<Self, StoreError> {
        let keys = [
            "blob_references",
            "bundles",
            "catalog_mutations",
            "context_commits",
            "effect_events",
            "effect_records",
            "outbox_records",
            "request_idempotency",
            "service_batches",
            "source_snapshots",
            "worker_transitions",
        ];
        let mut values = exact_map(node, &keys)?;
        let convert = |value: u64| u32::try_from(value).map_err(|_error| limit_exceeded());
        Ok(Self {
            blob_references: convert(remove_unsigned(&mut values, "blob_references")?)?,
            bundles: convert(remove_unsigned(&mut values, "bundles")?)?,
            catalog_mutations: convert(remove_unsigned(&mut values, "catalog_mutations")?)?,
            context_commits: convert(remove_unsigned(&mut values, "context_commits")?)?,
            effect_events: convert(remove_unsigned(&mut values, "effect_events")?)?,
            effect_records: convert(remove_unsigned(&mut values, "effect_records")?)?,
            outbox_records: convert(remove_unsigned(&mut values, "outbox_records")?)?,
            request_idempotency: convert(remove_unsigned(&mut values, "request_idempotency")?)?,
            service_batches: convert(remove_unsigned(&mut values, "service_batches")?)?,
            source_snapshots: convert(remove_unsigned(&mut values, "source_snapshots")?)?,
            worker_transitions: convert(remove_unsigned(&mut values, "worker_transitions")?)?,
        })
    }
}

/// Strict typed residual delta and normalized-catalog commitment for one repository revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryDeltaV5 {
    parent_revision: StoreRevision,
    result_revision: StoreRevision,
    tenant_id: RecordId,
    purpose_digest: ContentDigest,
    catalog_mutation_digest: ContentDigest,
    mutations: Vec<RepositoryMutationV5>,
    counts: RepositoryMutationCountsV5,
    logical_bytes: u64,
}

impl RepositoryDeltaV5 {
    /// Creates and validates one consecutive bounded delta.
    pub fn new(
        parent_revision: StoreRevision,
        tenant_id: RecordId,
        purpose_digest: ContentDigest,
        catalog_mutation_digest: ContentDigest,
        catalog_mutations: u32,
        mutations: Vec<RepositoryMutationV5>,
        logical_bytes: u64,
    ) -> Result<Self, StoreError> {
        let counts = RepositoryMutationCountsV5::from_mutations(&mutations, catalog_mutations)?;
        let result = Self {
            parent_revision,
            result_revision: checked_next(parent_revision)?,
            tenant_id,
            purpose_digest,
            catalog_mutation_digest,
            mutations,
            counts,
            logical_bytes,
        };
        result.validate()?;
        Ok(result)
    }

    /// Returns the exact parent revision.
    #[must_use]
    pub const fn parent_revision(&self) -> StoreRevision {
        self.parent_revision
    }

    /// Returns the consecutive result revision.
    #[must_use]
    pub const fn result_revision(&self) -> StoreRevision {
        self.result_revision
    }

    /// Returns the exact closed mutation counts.
    #[must_use]
    pub const fn counts(&self) -> RepositoryMutationCountsV5 {
        self.counts
    }

    /// Returns exact logical bytes changed for content-free telemetry.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.result_revision != checked_next(self.parent_revision)?
            || self.counts
                != RepositoryMutationCountsV5::from_mutations(
                    &self.mutations,
                    self.counts.catalog_mutations,
                )?
            || self.counts.total()? == 0
            || self.counts.total()?
                > u64::try_from(MAX_REPOSITORY_DELTA_OPERATIONS_V5)
                    .map_err(|_error| limit_exceeded())?
            || self.logical_bytes == 0
        {
            return Err(invalid_record());
        }
        let mut identities = BTreeSet::new();
        for mutation in &self.mutations {
            mutation.validate(self.result_revision)?;
            let record = mutation.encode_record()?;
            let identity = digest(mutation.kind().as_bytes(), &[&record])?;
            if !identities.insert((mutation.kind(), identity)) {
                return Err(invalid_record());
            }
        }
        Ok(())
    }

    fn to_node(&self) -> Result<CanonicalNode, StoreError> {
        let mutations = self
            .mutations
            .iter()
            .map(|mutation| {
                Ok(canonical_map([
                    ("kind", CanonicalNode::Text(mutation.kind().to_owned())),
                    ("record", CanonicalNode::Bytes(mutation.encode_record()?)),
                ]))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(canonical_map([
            (
                "catalog_mutation_digest",
                CanonicalNode::Text(self.catalog_mutation_digest.as_str().to_owned()),
            ),
            ("counts", self.counts.to_node()),
            (
                "format_version",
                CanonicalNode::Unsigned(REPOSITORY_FORMAT_V5),
            ),
            ("logical_bytes", CanonicalNode::Unsigned(self.logical_bytes)),
            ("mutations", CanonicalNode::Array(mutations)),
            (
                "parent_revision",
                CanonicalNode::Unsigned(self.parent_revision.0),
            ),
            (
                "purpose_digest",
                CanonicalNode::Text(self.purpose_digest.as_str().to_owned()),
            ),
            (
                "result_revision",
                CanonicalNode::Unsigned(self.result_revision.0),
            ),
            (
                "tenant_id",
                CanonicalNode::Text(self.tenant_id.as_str().to_owned()),
            ),
        ]))
    }

    /// Encodes this record with the strict deterministic CBOR profile.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        self.validate()?;
        let bytes = to_deterministic_cbor(&self.to_node()?).map_err(|_error| invalid_record())?;
        if bytes.len() > MAX_REPOSITORY_DELTA_BYTES_V5 {
            return Err(limit_exceeded());
        }
        Ok(bytes)
    }

    /// Decodes only the exact supported canonical representation and rejects unknown mutations.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_DELTA_BYTES_V5 {
            return Err(limit_exceeded());
        }
        let root = from_deterministic_cbor(bytes).map_err(|_error| invalid_record())?;
        let keys = [
            "catalog_mutation_digest",
            "counts",
            "format_version",
            "logical_bytes",
            "mutations",
            "parent_revision",
            "purpose_digest",
            "result_revision",
            "tenant_id",
        ];
        let mut values = exact_map(root, &keys)?;
        if remove_unsigned(&mut values, "format_version")? != REPOSITORY_FORMAT_V5 {
            return Err(invalid_record());
        }
        let counts = RepositoryMutationCountsV5::from_node(
            values.remove("counts").ok_or_else(invalid_record)?,
        )?;
        let mutation_nodes = match values.remove("mutations") {
            Some(CanonicalNode::Array(found)) => found,
            _ => return Err(invalid_record()),
        };
        if mutation_nodes.len() > MAX_REPOSITORY_DELTA_OPERATIONS_V5 {
            return Err(limit_exceeded());
        }
        let mutations = mutation_nodes
            .into_iter()
            .map(|node| {
                let mut record = exact_map(node, &["kind", "record"])?;
                let kind = remove_text(&mut record, "kind")?;
                let bytes = remove_bytes(&mut record, "record")?;
                RepositoryMutationV5::decode(&kind, &bytes)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let result = Self {
            parent_revision: StoreRevision(remove_unsigned(&mut values, "parent_revision")?),
            result_revision: StoreRevision(remove_unsigned(&mut values, "result_revision")?),
            tenant_id: RecordId::new(remove_text(&mut values, "tenant_id")?)
                .map_err(|_error| invalid_record())?,
            purpose_digest: remove_digest(&mut values, "purpose_digest")?,
            catalog_mutation_digest: remove_digest(&mut values, "catalog_mutation_digest")?,
            mutations,
            counts,
            logical_bytes: remove_unsigned(&mut values, "logical_bytes")?,
        };
        result.validate()?;
        if result.encode()? != bytes {
            return Err(invalid_record());
        }
        Ok(result)
    }

    /// Returns the domain-separated digest of the exact canonical delta.
    pub fn delta_digest(&self) -> Result<ContentDigest, StoreError> {
        digest(DELTA_DOMAIN, &[&self.encode()?])
    }

    /// Returns the exact tenant scope committed by this delta.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Returns the ordered typed residual mutations.
    #[must_use]
    pub fn mutations(&self) -> &[RepositoryMutationV5] {
        &self.mutations
    }

    /// Returns the canonical commitment to normalized catalog rows changed by this revision.
    #[must_use]
    pub const fn catalog_mutation_digest(&self) -> &ContentDigest {
        &self.catalog_mutation_digest
    }

    /// Canonicalizes and authenticates this delta before the final SQLite write transaction.
    pub fn prepare(self) -> Result<PreparedRepositoryDeltaV5, StoreError> {
        let canonical_delta = self.encode()?;
        let delta_digest = digest(DELTA_DOMAIN, &[&canonical_delta])?;
        Ok(PreparedRepositoryDeltaV5 {
            delta: self,
            canonical_delta,
            delta_digest,
        })
    }
}

/// Fully bounded canonical delta prepared before the final SQLite write transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRepositoryDeltaV5 {
    delta: RepositoryDeltaV5,
    canonical_delta: Vec<u8>,
    delta_digest: ContentDigest,
}

impl PreparedRepositoryDeltaV5 {
    /// Returns the validated typed delta.
    #[must_use]
    pub const fn delta(&self) -> &RepositoryDeltaV5 {
        &self.delta
    }

    /// Returns the exact canonical bytes bounded before transaction entry.
    #[must_use]
    pub fn canonical_delta(&self) -> &[u8] {
        &self.canonical_delta
    }

    /// Returns the domain-separated digest of the canonical bytes.
    #[must_use]
    pub const fn delta_digest(&self) -> &ContentDigest {
        &self.delta_digest
    }
}

fn purpose_digest(value: &str) -> Result<ContentDigest, StoreError> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid_record());
    }
    digest(PURPOSE_DOMAIN, &[value.as_bytes()])
}

fn catalog_mutation_commitment(
    staged: &[StagedMutation],
) -> Result<(ContentDigest, u32), StoreError> {
    let mut records = Vec::new();
    for mutation in staged {
        if let StagedMutation::Atoms(atoms, edges) = mutation {
            for atom in atoms {
                records.push(("atom".to_owned(), encode_typed(atom)?));
            }
            for edge in edges {
                records.push(("edge".to_owned(), encode_typed(edge)?));
            }
        }
    }
    catalog_mutation_commitment_from_records_v5(records)
}

pub(crate) fn catalog_mutation_commitment_from_records_v5(
    mut records: Vec<(String, Vec<u8>)>,
) -> Result<(ContentDigest, u32), StoreError> {
    if records.iter().any(|(kind, bytes)| {
        !matches!(kind.as_str(), "atom" | "edge")
            || bytes.is_empty()
            || bytes.len() > MAX_REPOSITORY_DELTA_RECORD_BYTES_V5
    }) {
        return Err(invalid_record());
    }
    records.sort();
    let count = u32::try_from(records.len()).map_err(|_error| limit_exceeded())?;
    let records = records
        .into_iter()
        .map(|(kind, record)| {
            canonical_map([
                ("kind", CanonicalNode::Text(kind)),
                ("record", CanonicalNode::Bytes(record)),
            ])
        })
        .collect();
    let canonical =
        to_deterministic_cbor(&CanonicalNode::Array(records)).map_err(|_error| invalid_record())?;
    Ok((digest(CATALOG_MUTATIONS_DOMAIN, &[&canonical])?, count))
}

fn empty_catalog_mutation_commitment() -> Result<ContentDigest, StoreError> {
    let canonical = to_deterministic_cbor(&CanonicalNode::Array(Vec::new()))
        .map_err(|_error| invalid_record())?;
    digest(CATALOG_MUTATIONS_DOMAIN, &[&canonical])
}

/// Derives one deterministic typed v5 delta from validated repository staging before publication.
pub(crate) fn repository_delta_from_staged_v5(
    parent_revision: StoreRevision,
    context: &AccessContext,
    staged: &[StagedMutation],
    idempotency: Option<&IdempotencyIdentity>,
    logical_bytes: u64,
) -> Result<RepositoryDeltaV5, StoreError> {
    let result_revision = checked_next(parent_revision)?;
    let mut mutations = Vec::new();
    for mutation in staged {
        match mutation {
            StagedMutation::Snapshot(record) => {
                mutations.push(RepositoryMutationV5::InsertSourceSnapshot(record.clone()));
            }
            StagedMutation::Atoms(_, _) => {}
            StagedMutation::Bundle(record) => {
                mutations.push(RepositoryMutationV5::InsertBundle(record.clone()));
            }
            StagedMutation::ContextCommit(record) => {
                mutations.push(RepositoryMutationV5::AppendContextCommit(record.clone()));
            }
            StagedMutation::EffectEvent(record) => {
                mutations.push(RepositoryMutationV5::AppendEffectJournalEvent(
                    record.clone(),
                ));
            }
            StagedMutation::EffectRecord(record) => {
                mutations.push(RepositoryMutationV5::ReplaceEffectRecord(record.clone()));
            }
            StagedMutation::Blob(record) => {
                mutations.push(RepositoryMutationV5::InsertBlobReference(
                    record.reference.clone(),
                ));
            }
            StagedMutation::Outbox(message) => {
                mutations.push(RepositoryMutationV5::AppendOutbox(OutboxRecord {
                    message: message.clone(),
                    causal_revision: result_revision,
                }));
            }
        }
    }
    if let Some(identity) = idempotency {
        mutations.push(RepositoryMutationV5::InsertRequestIdempotency(
            RequestIdempotencyMutationV5::new(
                identity.scope.clone(),
                identity.key.clone(),
                identity.request_digest.clone(),
                CommitReceipt {
                    revision: result_revision,
                    replayed: false,
                },
            )?,
        ));
    }
    let (catalog_digest, catalog_count) = catalog_mutation_commitment(staged)?;
    RepositoryDeltaV5::new(
        parent_revision,
        context.tenant_id().clone(),
        purpose_digest(context.purpose())?,
        catalog_digest,
        catalog_count,
        mutations,
        logical_bytes,
    )
}

/// Derives one deterministic typed v5 delta from a validated service state transition.
pub(crate) fn repository_delta_from_service_v5(
    latest: &CommittedState,
    next: &CommittedState,
    tenant_id: &RecordId,
    receipt: &ServiceBatchReceipt,
    logical_bytes: u64,
) -> Result<RepositoryDeltaV5, StoreError> {
    RepositoryDeltaV5::new(
        latest.revision,
        tenant_id.clone(),
        purpose_digest("service_repository")?,
        empty_catalog_mutation_commitment()?,
        0,
        vec![RepositoryMutationV5::ApplyServiceBatch(
            ServiceBatchMutationV5::from_states(latest, next, tenant_id, receipt)?,
        )],
        logical_bytes,
    )
}

/// Derives one deterministic typed v5 delta from a validated worker-state transition.
pub(crate) fn repository_delta_from_worker_v5(
    parent_revision: StoreRevision,
    state: WorkerState,
    logical_bytes: u64,
) -> Result<RepositoryDeltaV5, StoreError> {
    RepositoryDeltaV5::new(
        parent_revision,
        state.locator().tenant_id().clone(),
        purpose_digest("worker_repository")?,
        empty_catalog_mutation_commitment()?,
        0,
        vec![RepositoryMutationV5::TransitionWorker(state)],
        logical_bytes,
    )
}

/// Applies one authenticated delta to catalog-free state and validates the exact result.
pub(crate) fn apply_repository_delta_v5(
    mut state: CommittedState,
    delta: &RepositoryDeltaV5,
) -> Result<CommittedState, StoreError> {
    if state.revision != delta.parent_revision {
        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
    }
    let revision = delta.result_revision;
    let tenant = state.tenants.entry(delta.tenant_id.clone()).or_default();
    for mutation in &delta.mutations {
        match mutation {
            RepositoryMutationV5::InsertSourceSnapshot(record) => {
                apply_mutation(tenant, StagedMutation::Snapshot(record.clone()), revision)?
            }
            RepositoryMutationV5::InsertBundle(record) => {
                apply_mutation(tenant, StagedMutation::Bundle(record.clone()), revision)?
            }
            RepositoryMutationV5::AppendContextCommit(record) => apply_mutation(
                tenant,
                StagedMutation::ContextCommit(record.clone()),
                revision,
            )?,
            RepositoryMutationV5::AppendEffectJournalEvent(record) => apply_mutation(
                tenant,
                StagedMutation::EffectEvent(record.clone()),
                revision,
            )?,
            RepositoryMutationV5::ReplaceEffectRecord(record) => apply_mutation(
                tenant,
                StagedMutation::EffectRecord(record.clone()),
                revision,
            )?,
            RepositoryMutationV5::InsertBlobReference(reference) => {
                if tenant.blobs.contains_key(&reference.digest) {
                    return Err(invalid_record());
                }
                tenant.blobs.insert(
                    reference.digest.clone(),
                    BlobState {
                        reference: reference.clone(),
                        bytes: None,
                    },
                );
            }
            RepositoryMutationV5::AppendOutbox(record) => {
                if tenant
                    .outbox
                    .iter()
                    .any(|current| current.message.message_id == record.message.message_id)
                    || record.causal_revision != revision
                {
                    return Err(invalid_record());
                }
                tenant.outbox.push(record.clone());
            }
            RepositoryMutationV5::InsertRequestIdempotency(record) => {
                if tenant
                    .idempotency
                    .insert(
                        (record.scope.clone(), record.key.clone()),
                        (record.request_digest.clone(), record.receipt),
                    )
                    .is_some()
                {
                    return Err(invalid_record());
                }
            }
            RepositoryMutationV5::ApplyServiceBatch(batch) => {
                for record in &batch.records {
                    if record.locator().tenant_id() != &delta.tenant_id
                        || record.store_revision() != revision
                    {
                        return Err(invalid_record());
                    }
                    let history = tenant
                        .service_records
                        .entry((
                            record.locator().namespace().to_owned(),
                            record.locator().key().to_owned(),
                        ))
                        .or_default();
                    let expected = u64::try_from(history.len())
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        .ok_or_else(limit_exceeded)?;
                    if record.version() != expected {
                        return Err(StoreError::new(StoreErrorCode::RevisionConflict));
                    }
                    history.push(record.clone());
                }
                if let Some(record) = &batch.idempotency
                    && tenant
                        .service_idempotency
                        .insert(
                            (record.operation.clone(), record.key.clone()),
                            ServiceIdempotencyEntry {
                                request_digest: record.request_digest.clone(),
                                receipt: record.receipt.clone(),
                            },
                        )
                        .is_some()
                {
                    return Err(invalid_record());
                }
            }
            RepositoryMutationV5::TransitionWorker(record) => {
                if record.locator().tenant_id() != &delta.tenant_id
                    || record.store_revision() != revision
                {
                    return Err(invalid_record());
                }
                tenant
                    .worker_states
                    .insert(record.locator().worker().to_owned(), record.clone());
            }
        }
    }
    state.revision = revision;
    validate_committed_service_state(&state).map_err(|_error| invalid_record())?;
    Ok(state)
}

/// Computes the incremental result-state commitment for an ordinary delta.
pub fn repository_result_state_digest_v5(
    parent_state_digest: &ContentDigest,
    delta_digest: &ContentDigest,
) -> Result<ContentDigest, StoreError> {
    digest(
        STATE_DOMAIN,
        &[
            b"delta_result",
            parent_state_digest.as_str().as_bytes(),
            delta_digest.as_str().as_bytes(),
        ],
    )
}

/// Closed reason permitting a complete v5 checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryCheckpointReasonV5 {
    /// Initial empty revision.
    Genesis,
    /// Authenticated v4-to-v5 migration boundary.
    Migration,
    /// Maximum delta-count trigger.
    DeltaCount,
    /// Maximum accumulated-delta-byte trigger.
    DeltaBytes,
    /// Signed compaction output.
    Compaction,
}

impl RepositoryCheckpointReasonV5 {
    fn name(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::Migration => "migration",
            Self::DeltaCount => "delta_count",
            Self::DeltaBytes => "delta_bytes",
            Self::Compaction => "compaction",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "genesis" => Ok(Self::Genesis),
            "migration" => Ok(Self::Migration),
            "delta_count" => Ok(Self::DeltaCount),
            "delta_bytes" => Ok(Self::DeltaBytes),
            "compaction" => Ok(Self::Compaction),
            _ => Err(invalid_record()),
        }
    }
}

/// Exact logical catalog totals authenticated at a v5 revision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepositoryLogicalTotalsV5 {
    /// Authoritative atom rows visible at the revision.
    pub atom_count: u64,
    /// Authoritative edge rows visible at the revision.
    pub edge_count: u64,
    /// Logical plaintext bytes referenced by authoritative blob atoms.
    pub referenced_blob_bytes: u64,
}

impl RepositoryLogicalTotalsV5 {
    fn to_node(self) -> CanonicalNode {
        canonical_map([
            ("atom_count", CanonicalNode::Unsigned(self.atom_count)),
            ("edge_count", CanonicalNode::Unsigned(self.edge_count)),
            (
                "referenced_blob_bytes",
                CanonicalNode::Unsigned(self.referenced_blob_bytes),
            ),
        ])
    }

    fn from_node(node: CanonicalNode) -> Result<Self, StoreError> {
        let mut values = exact_map(node, &["atom_count", "edge_count", "referenced_blob_bytes"])?;
        Ok(Self {
            atom_count: remove_unsigned(&mut values, "atom_count")?,
            edge_count: remove_unsigned(&mut values, "edge_count")?,
            referenced_blob_bytes: remove_unsigned(&mut values, "referenced_blob_bytes")?,
        })
    }
}

/// Complete bounded catalog-free state checkpoint for one v5 revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCheckpointV5 {
    revision: StoreRevision,
    canonical_state: Vec<u8>,
    state_digest: ContentDigest,
    catalog_root: ContentDigest,
    semantic_root: ContentDigest,
    parent_chain_head: ContentDigest,
    totals: RepositoryLogicalTotalsV5,
    reason: RepositoryCheckpointReasonV5,
}

impl RepositoryCheckpointV5 {
    /// Creates a bounded checkpoint over exact canonical catalog-free state bytes.
    pub fn new(
        revision: StoreRevision,
        canonical_state: Vec<u8>,
        catalog_root: ContentDigest,
        semantic_root: ContentDigest,
        parent_chain_head: ContentDigest,
        totals: RepositoryLogicalTotalsV5,
        reason: RepositoryCheckpointReasonV5,
    ) -> Result<Self, StoreError> {
        if canonical_state.is_empty() || canonical_state.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5
        {
            return Err(limit_exceeded());
        }
        from_deterministic_cbor(&canonical_state).map_err(|_error| invalid_record())?;
        if revision.0 > 0 && reason == RepositoryCheckpointReasonV5::Genesis {
            return Err(invalid_record());
        }
        let state_digest = repository_state_digest_v5(&canonical_state)?;
        Ok(Self {
            revision,
            canonical_state,
            state_digest,
            catalog_root,
            semantic_root,
            parent_chain_head,
            totals,
            reason,
        })
    }

    fn to_node(&self) -> CanonicalNode {
        canonical_map([
            (
                "canonical_state",
                CanonicalNode::Bytes(self.canonical_state.clone()),
            ),
            (
                "catalog_root",
                CanonicalNode::Text(self.catalog_root.as_str().to_owned()),
            ),
            (
                "format_version",
                CanonicalNode::Unsigned(REPOSITORY_FORMAT_V5),
            ),
            (
                "parent_chain_head",
                CanonicalNode::Text(self.parent_chain_head.as_str().to_owned()),
            ),
            ("reason", CanonicalNode::Text(self.reason.name().to_owned())),
            ("revision", CanonicalNode::Unsigned(self.revision.0)),
            (
                "semantic_root",
                CanonicalNode::Text(self.semantic_root.as_str().to_owned()),
            ),
            (
                "state_digest",
                CanonicalNode::Text(self.state_digest.as_str().to_owned()),
            ),
            ("totals", self.totals.to_node()),
        ])
    }

    /// Encodes this checkpoint with the strict deterministic CBOR profile.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let bytes = to_deterministic_cbor(&self.to_node()).map_err(|_error| invalid_record())?;
        if bytes.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5.saturating_add(4_096) {
            return Err(limit_exceeded());
        }
        Ok(bytes)
    }

    /// Decodes only the exact canonical checkpoint representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.is_empty()
            || bytes.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5.saturating_add(4_096)
        {
            return Err(limit_exceeded());
        }
        let root = from_deterministic_cbor(bytes).map_err(|_error| invalid_record())?;
        let keys = [
            "canonical_state",
            "catalog_root",
            "format_version",
            "parent_chain_head",
            "reason",
            "revision",
            "semantic_root",
            "state_digest",
            "totals",
        ];
        let mut values = exact_map(root, &keys)?;
        if remove_unsigned(&mut values, "format_version")? != REPOSITORY_FORMAT_V5 {
            return Err(invalid_record());
        }
        let revision = StoreRevision(remove_unsigned(&mut values, "revision")?);
        let canonical_state = remove_bytes(&mut values, "canonical_state")?;
        let state_digest = remove_digest(&mut values, "state_digest")?;
        let result = Self {
            revision,
            canonical_state,
            state_digest: state_digest.clone(),
            catalog_root: remove_digest(&mut values, "catalog_root")?,
            semantic_root: remove_digest(&mut values, "semantic_root")?,
            parent_chain_head: remove_digest(&mut values, "parent_chain_head")?,
            totals: RepositoryLogicalTotalsV5::from_node(
                values.remove("totals").ok_or_else(invalid_record)?,
            )?,
            reason: RepositoryCheckpointReasonV5::parse(&remove_text(&mut values, "reason")?)?,
        };
        if repository_state_digest_v5(&result.canonical_state)? != state_digest
            || result.revision.0 > 0 && result.reason == RepositoryCheckpointReasonV5::Genesis
            || result.encode()? != bytes
        {
            return Err(invalid_record());
        }
        Ok(result)
    }

    /// Returns the domain-separated digest of the exact canonical checkpoint.
    pub fn checkpoint_digest(&self) -> Result<ContentDigest, StoreError> {
        digest(CHECKPOINT_DOMAIN, &[&self.encode()?])
    }

    /// Returns the exact checkpoint revision.
    #[must_use]
    pub const fn revision(&self) -> StoreRevision {
        self.revision
    }

    /// Returns the canonical catalog-free state bytes.
    #[must_use]
    pub fn canonical_state(&self) -> &[u8] {
        &self.canonical_state
    }

    /// Returns the authenticated state digest stored by this checkpoint.
    #[must_use]
    pub const fn state_digest(&self) -> &ContentDigest {
        &self.state_digest
    }

    /// Returns the normalized catalog root bound to this checkpoint.
    #[must_use]
    pub const fn catalog_root(&self) -> &ContentDigest {
        &self.catalog_root
    }

    /// Returns the complete semantic root bound to this checkpoint.
    #[must_use]
    pub const fn semantic_root(&self) -> &ContentDigest {
        &self.semantic_root
    }

    /// Returns the prior authenticated chain head.
    #[must_use]
    pub const fn parent_chain_head(&self) -> &ContentDigest {
        &self.parent_chain_head
    }

    /// Returns exact normalized catalog totals at this checkpoint.
    #[must_use]
    pub const fn totals(&self) -> RepositoryLogicalTotalsV5 {
        self.totals
    }

    /// Returns the closed reason that authorized this checkpoint.
    #[must_use]
    pub const fn reason(&self) -> RepositoryCheckpointReasonV5 {
        self.reason
    }
}

/// Returns the domain-separated digest of canonical catalog-free state bytes.
pub fn repository_state_digest_v5(bytes: &[u8]) -> Result<ContentDigest, StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_REPOSITORY_CHECKPOINT_BYTES_V5 {
        return Err(limit_exceeded());
    }
    from_deterministic_cbor(bytes).map_err(|_error| invalid_record())?;
    digest(STATE_DOMAIN, &[bytes])
}

/// Computes the complete v5 semantic root from the result state, catalog, and logical totals.
pub fn repository_semantic_root_v5(
    revision: StoreRevision,
    state_digest: &ContentDigest,
    catalog_root: &ContentDigest,
    totals: RepositoryLogicalTotalsV5,
) -> Result<ContentDigest, StoreError> {
    digest(
        SEMANTIC_ROOT_DOMAIN,
        &[
            &revision.0.to_be_bytes(),
            state_digest.as_str().as_bytes(),
            catalog_root.as_str().as_bytes(),
            &totals.atom_count.to_be_bytes(),
            &totals.edge_count.to_be_bytes(),
            &totals.referenced_blob_bytes.to_be_bytes(),
        ],
    )
}

/// Returns the fixed domain-separated parent value for the genesis chain link.
pub fn repository_genesis_parent_chain_head_v5() -> Result<ContentDigest, StoreError> {
    digest(GENESIS_PARENT_DOMAIN, &[])
}

/// Complete authenticated input to one v5 chain-head transition.
pub struct RepositoryChainLinkV5<'a> {
    /// Exact prior chain head.
    pub previous_chain_head: &'a ContentDigest,
    /// Consecutive result revision.
    pub revision: StoreRevision,
    /// Exact delta or checkpoint payload digest.
    pub delta_or_checkpoint_digest: &'a ContentDigest,
    /// Resulting catalog-free state digest.
    pub state_digest: &'a ContentDigest,
    /// Resulting normalized catalog root.
    pub catalog_root: &'a ContentDigest,
    /// Resulting complete semantic root.
    pub semantic_root: &'a ContentDigest,
    /// Resulting logical catalog totals.
    pub totals: RepositoryLogicalTotalsV5,
    /// Closed SQLite capacity profile name.
    pub capacity_profile: &'a str,
}

/// Computes a chain head binding one consecutive revision and all resulting authenticated roots.
pub fn repository_chain_head_v5(
    link: &RepositoryChainLinkV5<'_>,
) -> Result<ContentDigest, StoreError> {
    if !matches!(link.capacity_profile, "standard" | "large_local") {
        return Err(invalid_record());
    }
    let revision_bytes = link.revision.0.to_be_bytes();
    let atom_bytes = link.totals.atom_count.to_be_bytes();
    let edge_bytes = link.totals.edge_count.to_be_bytes();
    let blob_bytes = link.totals.referenced_blob_bytes.to_be_bytes();
    digest(
        CHAIN_DOMAIN,
        &[
            link.previous_chain_head.as_str().as_bytes(),
            &revision_bytes,
            link.delta_or_checkpoint_digest.as_str().as_bytes(),
            link.state_digest.as_str().as_bytes(),
            link.catalog_root.as_str().as_bytes(),
            link.semantic_root.as_str().as_bytes(),
            &atom_bytes,
            &edge_bytes,
            &blob_bytes,
            link.capacity_profile.as_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CommitReceipt, ServiceExpectedVersion, StoreErrorCode, WorkerLocator, WorkerUpdate,
    };
    use rusqlite::Connection;

    fn content(character: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            character.to_string().repeat(64)
        ))?)
    }

    fn tenant() -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f78f1")?)
    }

    fn delta() -> Result<RepositoryDeltaV5, Box<dyn std::error::Error>> {
        Ok(RepositoryDeltaV5::new(
            StoreRevision(0),
            tenant()?,
            content('a')?,
            content('b')?,
            0,
            vec![RepositoryMutationV5::InsertRequestIdempotency(
                RequestIdempotencyMutationV5::new(
                    "test",
                    IdempotencyKey::new("idempotency-test")?,
                    content('c')?,
                    CommitReceipt {
                        revision: StoreRevision(1),
                        replayed: false,
                    },
                )?,
            )],
            12,
        )?)
    }

    #[test]
    fn delta_encoding_is_canonical_round_trip_and_domain_separated()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = delta()?;
        let encoded = value.encode()?;
        assert_eq!(RepositoryDeltaV5::decode(&encoded)?, value);
        assert_eq!(RepositoryDeltaV5::decode(&encoded)?.encode()?, encoded);
        assert_ne!(value.delta_digest()?, repository_state_digest_v5(&encoded)?);
        Ok(())
    }

    #[test]
    fn delta_rejects_unknown_kind_duplicate_and_revision_overflow()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoded = delta()?.encode()?;
        let mut node = from_deterministic_cbor(&encoded)?;
        let CanonicalNode::Map(root) = &mut node else {
            return Err("root missing".into());
        };
        let Some(CanonicalNode::Array(mutations)) = root.get_mut("mutations") else {
            return Err("mutations missing".into());
        };
        let Some(CanonicalNode::Map(first)) = mutations.first_mut() else {
            return Err("mutation missing".into());
        };
        first.insert("kind".to_owned(), CanonicalNode::Text("unknown".to_owned()));
        let unknown = to_deterministic_cbor(&node)?;
        assert_eq!(
            RepositoryDeltaV5::decode(&unknown).map_err(|error| error.code()),
            Err(StoreErrorCode::InvalidRecord)
        );

        let mutation = delta()?
            .mutations
            .first()
            .ok_or("mutation missing")?
            .clone();
        assert_eq!(
            RepositoryDeltaV5::new(
                StoreRevision(0),
                tenant()?,
                content('a')?,
                content('b')?,
                0,
                vec![mutation.clone(), mutation],
                1
            )
            .map_err(|error| error.code()),
            Err(StoreErrorCode::InvalidRecord)
        );
        assert_eq!(
            RepositoryDeltaV5::new(
                StoreRevision(u64::MAX),
                tenant()?,
                content('a')?,
                content('b')?,
                1,
                Vec::new(),
                1
            )
            .map_err(|error| error.code()),
            Err(StoreErrorCode::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn generated_catalog_permutations_and_sequential_delta_application_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let records = vec![
            ("atom".to_owned(), vec![3, 1, 4]),
            ("edge".to_owned(), vec![1, 5, 9]),
            ("atom".to_owned(), vec![2, 6, 5]),
            ("edge".to_owned(), vec![3, 5, 8]),
        ];
        let expected = catalog_mutation_commitment_from_records_v5(records.clone())?;
        let mut seed = 0x517c_c1b7_2722_0a95_u64;
        for _case in 0..128 {
            let mut permutation = records.clone();
            for index in (1..permutation.len()).rev() {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let other = usize::try_from(seed % u64::try_from(index + 1)?)?;
                permutation.swap(index, other);
            }
            assert_eq!(
                catalog_mutation_commitment_from_records_v5(permutation)?,
                expected
            );
        }

        let context = AccessContext::new(tenant()?, "sequence")?;
        let first_identity = IdempotencyIdentity::new(
            "sequence",
            IdempotencyKey::new("sequence-one")?,
            content('1')?,
        )?;
        let second_identity = IdempotencyIdentity::new(
            "sequence",
            IdempotencyKey::new("sequence-two")?,
            content('2')?,
        )?;
        let first = repository_delta_from_staged_v5(
            StoreRevision(0),
            &context,
            &[],
            Some(&first_identity),
            1,
        )?;
        let second = repository_delta_from_staged_v5(
            StoreRevision(1),
            &context,
            &[],
            Some(&second_identity),
            1,
        )?;
        let initial = CommittedState::default();
        let after_first = apply_repository_delta_v5(
            initial.clone(),
            &RepositoryDeltaV5::decode(&first.encode()?)?,
        )?;
        let composed = apply_repository_delta_v5(
            after_first.clone(),
            &RepositoryDeltaV5::decode(&second.encode()?)?,
        )?;
        assert_eq!(composed.revision, StoreRevision(2));
        assert_eq!(
            composed
                .tenants
                .get(context.tenant_id())
                .map(|tenant| tenant.idempotency.len()),
            Some(2)
        );
        assert_eq!(
            apply_repository_delta_v5(initial, &second)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::RevisionConflict)
        );
        assert_eq!(
            apply_repository_delta_v5(composed, &second)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::RevisionConflict)
        );
        Ok(())
    }

    #[test]
    fn oversized_delta_operation_array_fails_before_record_decoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoded = delta()?.encode()?;
        let mut node = from_deterministic_cbor(&encoded)?;
        let CanonicalNode::Map(root) = &mut node else {
            return Err("root missing".into());
        };
        let Some(CanonicalNode::Array(mutations)) = root.get_mut("mutations") else {
            return Err("mutations missing".into());
        };
        let mutation = mutations.first().ok_or("mutation missing")?.clone();
        mutations.resize(MAX_REPOSITORY_DELTA_OPERATIONS_V5 + 1, mutation);
        let oversized = to_deterministic_cbor(&node)?;
        assert_eq!(
            RepositoryDeltaV5::decode(&oversized)
                .err()
                .map(|error| error.code()),
            Some(StoreErrorCode::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn checkpoint_round_trip_authenticates_state_and_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let totals = RepositoryLogicalTotalsV5 {
            atom_count: 2,
            edge_count: 1,
            referenced_blob_bytes: 9,
        };
        let checkpoint = RepositoryCheckpointV5::new(
            StoreRevision(0),
            vec![0xa0],
            content('a')?,
            content('b')?,
            content('c')?,
            totals,
            RepositoryCheckpointReasonV5::Genesis,
        )?;
        let encoded = checkpoint.encode()?;
        assert_eq!(RepositoryCheckpointV5::decode(&encoded)?, checkpoint);
        let previous = content('c')?;
        let checkpoint_digest = checkpoint.checkpoint_digest()?;
        let state_digest = repository_state_digest_v5(&[0xa0])?;
        let catalog_root = content('a')?;
        let semantic_root = content('b')?;
        let head = repository_chain_head_v5(&RepositoryChainLinkV5 {
            previous_chain_head: &previous,
            revision: StoreRevision(0),
            delta_or_checkpoint_digest: &checkpoint_digest,
            state_digest: &state_digest,
            catalog_root: &catalog_root,
            semantic_root: &semantic_root,
            totals,
            capacity_profile: "standard",
        })?;
        assert_ne!(head, checkpoint.checkpoint_digest()?);
        Ok(())
    }

    #[test]
    fn catalog_free_checkpoint_codec_round_trips_exact_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = CommittedState::default();
        let encoded = encode_catalog_free_state_v5(&state)?;
        let decoded = decode_catalog_free_state_v5(&encoded)?;
        assert_eq!(decoded.revision, StoreRevision(0));
        assert!(decoded.tenants.is_empty());
        assert_eq!(encode_catalog_free_state_v5(&decoded)?, encoded);
        Ok(())
    }

    #[test]
    fn worker_delta_applies_exact_transition_once() -> Result<(), Box<dyn std::error::Error>> {
        let initial = CommittedState::default();
        let locator = WorkerLocator::new(tenant()?, "worker")?;
        let (next, worker) = crate::service_repository::apply_worker_update(
            &initial,
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "test".to_owned(),
                now_unix_nanos: 1,
                expires_at_unix_nanos: 10,
            },
        )?;
        let delta = repository_delta_from_worker_v5(StoreRevision(0), worker.clone(), 12)?;
        let applied = apply_repository_delta_v5(initial.clone(), &delta)?;
        assert_eq!(applied.revision, next.revision);
        assert_eq!(
            applied
                .tenants
                .get(locator.tenant_id())
                .and_then(|state| state.worker_states.get(locator.worker())),
            Some(&worker)
        );
        assert!(matches!(
            apply_repository_delta_v5(applied, &delta),
            Err(error) if error.code() == StoreErrorCode::RevisionConflict
        ));
        Ok(())
    }

    #[test]
    fn receipt_only_delta_does_not_encode_a_full_state() -> Result<(), Box<dyn std::error::Error>> {
        let initial = CommittedState::default();
        let context = AccessContext::new(tenant()?, "test")?;
        let identity =
            IdempotencyIdentity::new("test", IdempotencyKey::new("receipt-only")?, content('a')?)?;
        let delta =
            repository_delta_from_staged_v5(StoreRevision(0), &context, &[], Some(&identity), 1)?;
        let checkpoint_bytes = encode_catalog_free_state_v5(&initial)?.len();
        assert!(delta.encode()?.len() < checkpoint_bytes.saturating_add(2_048));
        let applied = apply_repository_delta_v5(initial, &delta)?;
        assert_eq!(applied.revision, StoreRevision(1));
        assert_eq!(
            applied
                .tenants
                .get(context.tenant_id())
                .map(|tenant| tenant.idempotency.len()),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn fresh_target_schema_enforces_consecutive_chain_and_is_not_an_open_migration()
    -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        connection.execute_batch(SQLITE_FRESH_TARGET_SCHEMA_V5)?;
        let tables: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('repository_authority_v5', 'repository_revisions_v5', 'repository_checkpoints_v5', 'repository_deltas_v5', 'repository_retention_pins_v5')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(tables, 5);
        let digest_a = content('a')?;
        let digest_b = content('b')?;
        let digest_c = content('c')?;
        let genesis_parent = content('d')?;
        let genesis_chain = content('e')?;
        let revision_one_chain = content('f')?;
        connection.execute(
            "INSERT INTO repository_revisions_v5
                (revision, parent_revision, state_digest, catalog_root, semantic_root,
                 atom_count, edge_count, referenced_blob_bytes, previous_chain_head, chain_head)
             VALUES (0, NULL, ?1, ?2, ?3, 0, 0, 0, ?4, ?5)",
            rusqlite::params![
                digest_a.as_str(),
                digest_b.as_str(),
                digest_c.as_str(),
                genesis_parent.as_str(),
                genesis_chain.as_str()
            ],
        )?;
        connection.execute(
            "INSERT INTO repository_revisions_v5
                (revision, parent_revision, state_digest, catalog_root, semantic_root,
                 atom_count, edge_count, referenced_blob_bytes, previous_chain_head, chain_head)
             VALUES (1, 0, ?1, ?2, ?3, 0, 0, 0, ?4, ?5)",
            rusqlite::params![
                digest_a.as_str(),
                digest_b.as_str(),
                digest_c.as_str(),
                genesis_chain.as_str(),
                revision_one_chain.as_str()
            ],
        )?;
        assert!(
            connection
                .execute(
                    "INSERT INTO repository_revisions_v5
                        (revision, parent_revision, state_digest, catalog_root, semantic_root,
                         atom_count, edge_count, referenced_blob_bytes,
                         previous_chain_head, chain_head)
                     VALUES (2, 1, ?1, ?2, ?3, 0, 0, 0, ?4, ?5)",
                    rusqlite::params![
                        digest_a.as_str(),
                        digest_b.as_str(),
                        digest_c.as_str(),
                        genesis_parent.as_str(),
                        content('9')?.as_str()
                    ],
                )
                .is_err()
        );
        assert!(SQLITE_FRESH_TARGET_SCHEMA_V5.contains("never ordinary SqliteStore::open"));
        assert!(
            !super::super::sqlite::sqlite_migration_plan()?
                .migrations()
                .iter()
                .any(|migration| migration.name == "incremental_repository_state")
        );
        Ok(())
    }
}
