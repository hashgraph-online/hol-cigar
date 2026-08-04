//! In-memory MVCC repository used as the backend-independent behavioral oracle.

use crate::model::{
    AccessContext, AtomCursor, AtomPage, AtomSelector, BlobRecord, CancellationToken,
    CommitReceipt, EffectRecordEnvelope, IdempotencyIdentity, MAX_ATOM_BATCH_ITEMS,
    MAX_QUERY_PAGE_ITEMS, OutboxMessage, OutboxRecord, ReadTransaction, Repository,
    SnapshotSelection, StoreError, StoreErrorCode, StoreRevision, WriteTransaction,
};
use crate::service_repository::{
    EffectRecoveryPage, EffectRecoveryQuery, OutboxRecoveryPage, OutboxRecoveryQuery, ServiceBatch,
    ServiceBatchReceipt, ServiceError, ServiceIdempotencyEntry, ServiceListPage, ServiceListQuery,
    ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRepository, WorkerLocator,
    WorkerState, WorkerUpdate, apply_service_batch, apply_worker_update, check_cancellation,
    effect_recovery_from_state, outbox_recovery_from_state, service_get_from_state,
    service_list_from_state, worker_get_from_state,
};
use cigar_protocol::{
    ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, ContextSpaceId,
    EdgeKind, EffectJournalEvent, Lifecycle, LineageId, RecordId, SourceSnapshot, Validate,
    VersionId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const MAX_LEGACY_ATOM_INDEX_REBUILD_ITEMS: usize = 100_000;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BlobState {
    pub(crate) reference: cigar_protocol::BlobRef,
    pub(crate) bytes: Option<Vec<u8>>,
}

impl BlobState {
    fn in_memory(blob: BlobRecord) -> Self {
        let bytes = blob.bytes().to_vec();
        Self {
            reference: blob.reference,
            bytes: Some(bytes),
        }
    }

    pub(crate) fn record(&self) -> Result<Option<BlobRecord>, StoreError> {
        self.bytes
            .as_ref()
            .map(|bytes| BlobRecord::new(self.reference.clone(), bytes.clone()))
            .transpose()
    }
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct TenantState {
    pub(crate) atoms: BTreeMap<VersionId, ContextAtomV1>,
    #[serde(default)]
    pub(crate) atom_versions_by_id: BTreeMap<RecordId, VersionId>,
    #[serde(default)]
    pub(crate) current_versions_by_lineage: BTreeMap<LineageId, VersionId>,
    pub(crate) edges: BTreeMap<RecordId, ContextEdge>,
    pub(crate) bundles: BTreeMap<VersionId, ContextBundle>,
    pub(crate) snapshots: BTreeMap<RecordId, SourceSnapshot>,
    pub(crate) context_commits: BTreeMap<ContextSpaceId, Vec<ContextCommit>>,
    pub(crate) effects: BTreeMap<RecordId, Vec<EffectJournalEvent>>,
    #[serde(default)]
    pub(crate) effect_records: BTreeMap<RecordId, EffectRecordEnvelope>,
    pub(crate) blobs: BTreeMap<ContentDigest, BlobState>,
    pub(crate) outbox: Vec<OutboxRecord>,
    pub(crate) idempotency:
        BTreeMap<(String, cigar_protocol::IdempotencyKey), (ContentDigest, CommitReceipt)>,
    #[serde(default)]
    pub(crate) service_records: BTreeMap<(String, String), Vec<ServiceRecord>>,
    #[serde(default)]
    pub(crate) service_idempotency:
        BTreeMap<(String, cigar_protocol::IdempotencyKey), ServiceIdempotencyEntry>,
    #[serde(default)]
    pub(crate) worker_states: BTreeMap<String, WorkerState>,
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct CommittedState {
    pub(crate) revision: StoreRevision,
    pub(crate) tenants: BTreeMap<RecordId, TenantState>,
}

impl CommittedState {
    pub(crate) fn ensure_atom_indexes(&mut self) -> Result<(), StoreError> {
        for tenant in self.tenants.values_mut() {
            let index_missing = tenant.atom_versions_by_id.len() != tenant.atoms.len()
                || (!tenant.atoms.is_empty() && tenant.current_versions_by_lineage.is_empty());
            if index_missing {
                tenant.rebuild_atom_indexes()?;
            }
        }
        Ok(())
    }
}

impl TenantState {
    fn rebuild_atom_indexes(&mut self) -> Result<(), StoreError> {
        if self.atoms.len() > MAX_LEGACY_ATOM_INDEX_REBUILD_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut by_id = BTreeMap::new();
        let mut current = BTreeMap::new();
        for atom in self.atoms.values() {
            if let Some(existing) = by_id.insert(atom.atom_id.clone(), atom.version_id.clone())
                && existing != atom.version_id
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            update_current_lineage(&self.atoms, &mut current, atom)?;
        }
        self.atom_versions_by_id = by_id;
        self.current_versions_by_lineage = current;
        Ok(())
    }
}

/// Thread-safe whole-state MVCC oracle. It favors explicit semantics over storage efficiency.
pub struct InMemoryStore {
    history: Mutex<Vec<Arc<CommittedState>>>,
    fail_next_commit: AtomicBool,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self {
            history: Mutex::new(vec![Arc::new(CommittedState::default())]),
            fail_next_commit: AtomicBool::new(false),
        }
    }
}

impl fmt::Debug for InMemoryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryStore")
    }
}

impl InMemoryStore {
    /// Arms a one-shot abort after validation and before atomic publication.
    pub fn fail_next_commit(&self) {
        self.fail_next_commit.store(true, Ordering::Release);
    }

    /// Returns the latest committed revision without opening a transaction.
    pub fn revision(&self) -> Result<StoreRevision, StoreError> {
        let history = self.lock_history()?;
        history
            .last()
            .map(|state| state.revision)
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))
    }

    fn lock_history(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Vec<Arc<CommittedState>>>, StoreError> {
        self.history
            .lock()
            .map_err(|_error| StoreError::new(StoreErrorCode::Unavailable))
    }
}

impl Repository for InMemoryStore {
    type Read<'store>
        = InMemoryReadTransaction
    where
        Self: 'store;
    type Write<'store>
        = InMemoryWriteTransaction<'store>
    where
        Self: 'store;

    fn begin_read(
        &self,
        context: AccessContext,
        selection: SnapshotSelection,
        cancellation: CancellationToken,
    ) -> Result<Self::Read<'_>, StoreError> {
        cancellation.check()?;
        let history = self.lock_history()?;
        let state = match selection {
            SnapshotSelection::Latest => history.last().cloned(),
            SnapshotSelection::Revision(revision) => history
                .iter()
                .find(|state| state.revision == revision)
                .cloned(),
        }
        .ok_or_else(|| StoreError::new(StoreErrorCode::NotFound))?;
        Ok(InMemoryReadTransaction {
            state,
            context,
            cancellation,
            blob_repository: None,
        })
    }

    fn begin_write(
        &self,
        context: AccessContext,
        expected_revision: StoreRevision,
        cancellation: CancellationToken,
    ) -> Result<Self::Write<'_>, StoreError> {
        cancellation.check()?;
        Ok(InMemoryWriteTransaction {
            store: self,
            context,
            expected_revision,
            cancellation,
            staged: Vec::new(),
        })
    }
}

impl ServiceRepository for InMemoryStore {
    fn service_get(
        &self,
        locator: &ServiceRecordLocator,
        selection: ServiceRecordSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<ServiceRecord>, ServiceError> {
        check_cancellation(cancellation)?;
        let history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let state = history
            .last()
            .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::Unavailable))?;
        service_get_from_state(state, locator, selection)
    }

    fn service_list(
        &self,
        query: &ServiceListQuery,
        cancellation: &CancellationToken,
    ) -> Result<ServiceListPage, ServiceError> {
        check_cancellation(cancellation)?;
        let history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let state = match query.revision() {
            Some(revision) => history.iter().find(|state| state.revision == revision),
            None => history.last(),
        }
        .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::NotFound))?;
        service_list_from_state(state, query)
    }

    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError> {
        check_cancellation(cancellation)?;
        let mut history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let latest = history
            .last()
            .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::Unavailable))?;
        let (next, receipt) = apply_service_batch(latest, batch)?;
        if receipt.replayed {
            return Ok(receipt);
        }
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(crate::ServiceErrorCode::InjectedAbort));
        }
        history.push(Arc::new(next.ok_or_else(|| {
            ServiceError::new(crate::ServiceErrorCode::Unavailable)
        })?));
        Ok(receipt)
    }

    fn effect_recovery(
        &self,
        query: &EffectRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<EffectRecoveryPage, ServiceError> {
        check_cancellation(cancellation)?;
        let history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let state = match query.revision() {
            Some(revision) => history.iter().find(|state| state.revision == revision),
            None => history.last(),
        }
        .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::NotFound))?;
        effect_recovery_from_state(state, query)
    }

    fn outbox_recovery(
        &self,
        query: &OutboxRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<OutboxRecoveryPage, ServiceError> {
        check_cancellation(cancellation)?;
        let history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let state = match query.revision() {
            Some(revision) => history.iter().find(|state| state.revision == revision),
            None => history.last(),
        }
        .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::NotFound))?;
        outbox_recovery_from_state(state, query)
    }

    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError> {
        check_cancellation(cancellation)?;
        let history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let state = history
            .last()
            .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::Unavailable))?;
        worker_get_from_state(state, locator)
    }

    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError> {
        check_cancellation(cancellation)?;
        let mut history = self
            .lock_history()
            .map_err(crate::service_repository::map_store_error)?;
        let latest = history
            .last()
            .ok_or_else(|| ServiceError::new(crate::ServiceErrorCode::Unavailable))?;
        let (next, state) = apply_worker_update(latest, locator, update)?;
        check_cancellation(cancellation)?;
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(ServiceError::new(crate::ServiceErrorCode::InjectedAbort));
        }
        history.push(Arc::new(next));
        Ok(state)
    }
}

/// Immutable transaction backed by one retained whole-state snapshot.
pub struct InMemoryReadTransaction {
    pub(crate) state: Arc<CommittedState>,
    pub(crate) context: AccessContext,
    pub(crate) cancellation: CancellationToken,
    pub(crate) blob_repository: Option<Arc<dyn crate::RepositoryBlobStore>>,
}

impl fmt::Debug for InMemoryReadTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryReadTransaction")
            .field("revision", &self.state.revision)
            .field("context", &self.context)
            .finish()
    }
}

impl InMemoryReadTransaction {
    fn tenant(&self) -> Option<&TenantState> {
        self.state.tenants.get(self.context.tenant_id())
    }

    fn check(&self) -> Result<(), StoreError> {
        self.cancellation.check()
    }
}

impl ReadTransaction for InMemoryReadTransaction {
    fn revision(&self) -> StoreRevision {
        self.state.revision
    }

    fn get_atom(&self, version: &VersionId) -> Result<Option<ContextAtomV1>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .and_then(|tenant| tenant.atoms.get(version))
            .cloned())
    }

    fn get_atoms_by_id(
        &self,
        atom_ids: &[RecordId],
    ) -> Result<Vec<Option<ContextAtomV1>>, StoreError> {
        self.check()?;
        if atom_ids.len() > MAX_ATOM_BATCH_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        let mut unique = BTreeSet::new();
        let mut atoms = Vec::with_capacity(atom_ids.len());
        for atom_id in atom_ids {
            self.check()?;
            if !unique.insert(atom_id) {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            let atom = match self.tenant() {
                Some(tenant) => match tenant.atom_versions_by_id.get(atom_id) {
                    Some(version) => {
                        let atom = tenant
                            .atoms
                            .get(version)
                            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
                        if &atom.atom_id != atom_id {
                            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                        }
                        Some(atom.clone())
                    }
                    None => None,
                },
                None => None,
            };
            atoms.push(atom);
        }
        Ok(atoms)
    }

    fn get_active_atom_by_id(
        &self,
        atom_id: &RecordId,
    ) -> Result<Option<ContextAtomV1>, StoreError> {
        self.check()?;
        let Some(tenant) = self.tenant() else {
            return Ok(None);
        };
        let Some(version) = tenant.atom_versions_by_id.get(atom_id) else {
            return Ok(None);
        };
        let atom = tenant
            .atoms
            .get(version)
            .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
        if &atom.atom_id != atom_id {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        Ok((atom.lifecycle == Lifecycle::Active
            && tenant.current_versions_by_lineage.get(&atom.lineage_id) == Some(version))
        .then_some(atom.clone()))
    }

    fn query_atoms(
        &self,
        selector: AtomSelector,
        limit: usize,
        cursor: Option<&AtomCursor>,
    ) -> Result<AtomPage, StoreError> {
        self.check()?;
        if limit == 0 || limit > MAX_QUERY_PAGE_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        if cursor.is_some_and(|cursor| cursor.revision != self.state.revision) {
            return Err(StoreError::new(StoreErrorCode::MixedSnapshot));
        }
        let after = cursor.map(|cursor| &cursor.last_version);
        let mut items: Vec<_> = self
            .tenant()
            .into_iter()
            .flat_map(|tenant| tenant.atoms.iter())
            .filter(|(version, atom)| {
                after.is_none_or(|after| *version > after)
                    && selector.kind.is_none_or(|kind| atom.kind == kind)
            })
            .take(limit + 1)
            .map(|(_version, atom)| atom.clone())
            .collect();
        let has_more = items.len() > limit;
        if has_more {
            items.truncate(limit);
        }
        let next = if has_more {
            items.last().map(|atom| AtomCursor {
                revision: self.state.revision,
                last_version: atom.version_id.clone(),
            })
        } else {
            None
        };
        Ok(AtomPage { items, next })
    }

    fn edges_from(
        &self,
        version: &VersionId,
        kind: Option<cigar_protocol::EdgeKind>,
        limit: usize,
    ) -> Result<Vec<ContextEdge>, StoreError> {
        self.check()?;
        if limit == 0 || limit > MAX_QUERY_PAGE_ITEMS {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        Ok(self
            .tenant()
            .into_iter()
            .flat_map(|tenant| tenant.edges.values())
            .filter(|edge| {
                &edge.from_version == version && kind.is_none_or(|kind| edge.kind == kind)
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn get_bundle(&self, bundle: &VersionId) -> Result<Option<ContextBundle>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .and_then(|tenant| tenant.bundles.get(bundle))
            .cloned())
    }

    fn get_snapshot(&self, snapshot: &RecordId) -> Result<Option<SourceSnapshot>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .and_then(|tenant| tenant.snapshots.get(snapshot))
            .cloned())
    }

    fn context_commits(&self, space: &ContextSpaceId) -> Result<Vec<ContextCommit>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .and_then(|tenant| tenant.context_commits.get(space))
            .cloned()
            .unwrap_or_default())
    }

    fn get_effect(&self, effect: &RecordId) -> Result<Vec<EffectJournalEvent>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .and_then(|tenant| tenant.effects.get(effect))
            .cloned()
            .unwrap_or_default())
    }

    fn get_effect_record(
        &self,
        effect: &RecordId,
    ) -> Result<Option<EffectRecordEnvelope>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .and_then(|tenant| tenant.effect_records.get(effect))
            .cloned())
    }

    fn get_blob(&self, digest: &ContentDigest) -> Result<Option<BlobRecord>, StoreError> {
        self.check()?;
        let Some(blob) = self.tenant().and_then(|tenant| tenant.blobs.get(digest)) else {
            return Ok(None);
        };
        if let Some(record) = blob.record()? {
            return Ok(Some(record));
        }
        self.blob_repository
            .as_ref()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?
            .get(self.context.tenant_id(), &blob.reference)
    }

    fn outbox(&self) -> Result<Vec<OutboxRecord>, StoreError> {
        self.check()?;
        Ok(self
            .tenant()
            .map(|tenant| tenant.outbox.clone())
            .unwrap_or_default())
    }

    fn idempotent_result(
        &self,
        identity: &IdempotencyIdentity,
    ) -> Result<Option<CommitReceipt>, StoreError> {
        self.check()?;
        let Some((digest, receipt)) = self.tenant().and_then(|tenant| {
            tenant
                .idempotency
                .get(&(identity.scope.clone(), identity.key.clone()))
        }) else {
            return Ok(None);
        };
        if digest != &identity.request_digest {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        Ok(Some(*receipt))
    }
}

pub(crate) enum StagedMutation {
    Snapshot(SourceSnapshot),
    Atoms(Vec<ContextAtomV1>, Vec<ContextEdge>),
    Bundle(ContextBundle),
    ContextCommit(ContextCommit),
    EffectEvent(EffectJournalEvent),
    EffectRecord(EffectRecordEnvelope),
    Blob(BlobRecord),
    Outbox(OutboxMessage),
}

/// Mutable transaction whose tenant, purpose, revision, and cancellation are immutable.
pub struct InMemoryWriteTransaction<'store> {
    store: &'store InMemoryStore,
    context: AccessContext,
    expected_revision: StoreRevision,
    cancellation: CancellationToken,
    staged: Vec<StagedMutation>,
}

impl fmt::Debug for InMemoryWriteTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryWriteTransaction")
            .field("context", &self.context)
            .field("expected_revision", &self.expected_revision)
            .field("staged", &self.staged.len())
            .finish()
    }
}

impl InMemoryWriteTransaction<'_> {
    fn stage(&mut self, mutation: StagedMutation) -> Result<(), StoreError> {
        self.cancellation.check()?;
        self.staged.push(mutation);
        Ok(())
    }
}

impl WriteTransaction for InMemoryWriteTransaction<'_> {
    fn stage_snapshot(&mut self, snapshot: SourceSnapshot) -> Result<(), StoreError> {
        validate(&snapshot)?;
        self.stage(StagedMutation::Snapshot(snapshot))
    }

    fn publish_atoms(
        &mut self,
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
    ) -> Result<(), StoreError> {
        if atoms.is_empty() {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        for atom in &atoms {
            validate(atom)?;
            if &atom.scope.tenant_id != self.context.tenant_id() {
                return Err(StoreError::new(StoreErrorCode::InvalidContext));
            }
        }
        for edge in &edges {
            validate(edge)?;
        }
        self.stage(StagedMutation::Atoms(atoms, edges))
    }

    fn put_bundle(&mut self, bundle: ContextBundle) -> Result<(), StoreError> {
        validate(&bundle)?;
        self.stage(StagedMutation::Bundle(bundle))
    }

    fn append_context_commit(&mut self, commit: ContextCommit) -> Result<(), StoreError> {
        validate(&commit)?;
        if commit.purpose != self.context.purpose() {
            return Err(StoreError::new(StoreErrorCode::InvalidContext));
        }
        self.stage(StagedMutation::ContextCommit(commit))
    }

    fn append_effect_event(&mut self, event: EffectJournalEvent) -> Result<(), StoreError> {
        validate(&event)?;
        self.stage(StagedMutation::EffectEvent(event))
    }

    fn put_effect_record(&mut self, record: EffectRecordEnvelope) -> Result<(), StoreError> {
        self.stage(StagedMutation::EffectRecord(record))
    }

    fn put_blob(&mut self, blob: BlobRecord) -> Result<(), StoreError> {
        if blob_digest(blob.bytes()) != blob.reference.digest.as_str() {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        self.stage(StagedMutation::Blob(blob))
    }

    fn enqueue_outbox(&mut self, message: OutboxMessage) -> Result<(), StoreError> {
        message.validate()?;
        self.stage(StagedMutation::Outbox(message))
    }

    fn commit(self, idempotency: Option<IdempotencyIdentity>) -> Result<CommitReceipt, StoreError> {
        self.cancellation.check()?;
        if self.staged.is_empty()
            || (self
                .staged
                .iter()
                .any(|mutation| matches!(mutation, StagedMutation::Outbox(_)))
                && !self
                    .staged
                    .iter()
                    .any(|mutation| !matches!(mutation, StagedMutation::Outbox(_))))
        {
            return Err(StoreError::new(StoreErrorCode::InvalidRecord));
        }
        let mut history = self.store.lock_history()?;
        let latest = history
            .last()
            .ok_or_else(|| StoreError::new(StoreErrorCode::Unavailable))?;
        if let Some(identity) = &idempotency
            && let Some((digest, receipt)) =
                latest
                    .tenants
                    .get(self.context.tenant_id())
                    .and_then(|tenant| {
                        tenant
                            .idempotency
                            .get(&(identity.scope.clone(), identity.key.clone()))
                    })
        {
            if digest != &identity.request_digest {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            return Ok(CommitReceipt {
                revision: receipt.revision,
                replayed: true,
            });
        }
        if latest.revision != self.expected_revision {
            return Err(StoreError::new(StoreErrorCode::RevisionConflict));
        }
        let revision = StoreRevision(
            latest
                .revision
                .0
                .checked_add(1)
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?,
        );
        let mut next = latest.as_ref().clone();
        next.revision = revision;
        let tenant = next
            .tenants
            .entry(self.context.tenant_id().clone())
            .or_default();
        for mutation in self.staged {
            apply_mutation(tenant, mutation, revision)?;
        }
        let receipt = CommitReceipt {
            revision,
            replayed: false,
        };
        if let Some(identity) = idempotency {
            tenant.idempotency.insert(
                (identity.scope, identity.key),
                (identity.request_digest, receipt),
            );
        }
        self.cancellation.check()?;
        if self.store.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(StoreError::new(StoreErrorCode::InjectedAbort));
        }
        history.push(Arc::new(next));
        Ok(receipt)
    }
}

pub(crate) fn apply_mutation(
    tenant: &mut TenantState,
    mutation: StagedMutation,
    revision: StoreRevision,
) -> Result<(), StoreError> {
    match mutation {
        StagedMutation::Snapshot(snapshot) => insert_immutable(
            &mut tenant.snapshots,
            snapshot.snapshot_id.clone(),
            snapshot,
        ),
        StagedMutation::Atoms(atoms, edges) => {
            for atom in atoms {
                if tenant
                    .atom_versions_by_id
                    .get(&atom.atom_id)
                    .is_some_and(|version| version != &atom.version_id)
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
                let atom_id = atom.atom_id.clone();
                let version_id = atom.version_id.clone();
                insert_immutable(&mut tenant.atoms, atom.version_id.clone(), atom)?;
                tenant
                    .atom_versions_by_id
                    .insert(atom_id, version_id.clone());
                let atom = tenant
                    .atoms
                    .get(&version_id)
                    .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
                update_current_lineage(
                    &tenant.atoms,
                    &mut tenant.current_versions_by_lineage,
                    atom,
                )?;
            }
            for edge in edges {
                if !tenant.atoms.contains_key(&edge.from_version)
                    || !tenant.atoms.contains_key(&edge.to_version)
                    || creates_derivation_cycle(&tenant.edges, &edge)?
                {
                    return Err(StoreError::new(StoreErrorCode::InvalidRecord));
                }
                insert_immutable(&mut tenant.edges, edge.edge_id.clone(), edge)?;
            }
            Ok(())
        }
        StagedMutation::Bundle(bundle) => {
            insert_immutable(&mut tenant.bundles, bundle.bundle_id.clone(), bundle)
        }
        StagedMutation::ContextCommit(commit) => {
            let commits = tenant
                .context_commits
                .entry(commit.space_id.clone())
                .or_default();
            let expected_sequence = u64::try_from(commits.len())
                .ok()
                .and_then(|length| length.checked_add(1))
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            let expected_parent = commits.last().map(|current| &current.commit_id);
            if commit.sequence != expected_sequence
                || commit.parent_commit_id.as_ref() != expected_parent
            {
                return Err(StoreError::new(StoreErrorCode::RevisionConflict));
            }
            commits.push(commit);
            Ok(())
        }
        StagedMutation::EffectEvent(event) => {
            let events = tenant.effects.entry(event.effect_id.clone()).or_default();
            let expected_sequence = u64::try_from(events.len())
                .ok()
                .and_then(|length| length.checked_add(1))
                .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?;
            if event.sequence != expected_sequence
                || event.expected_effect_version
                    != u64::try_from(events.len())
                        .map_err(|_error| StoreError::new(StoreErrorCode::LimitExceeded))?
                || event.previous_event_digest.as_ref()
                    != events.last().map(|current| &current.event_digest)
                || events
                    .last()
                    .is_some_and(|current| current.to_state != event.from_state)
            {
                return Err(StoreError::new(StoreErrorCode::RevisionConflict));
            }
            events.push(event);
            Ok(())
        }
        StagedMutation::EffectRecord(record) => {
            let expected_version = match tenant.effect_records.get(&record.effect_id) {
                Some(current) => current
                    .effect_version
                    .checked_add(1)
                    .ok_or_else(|| StoreError::new(StoreErrorCode::LimitExceeded))?,
                None => 0,
            };
            if record.effect_version != expected_version {
                return Err(StoreError::new(StoreErrorCode::RevisionConflict));
            }
            tenant
                .effect_records
                .insert(record.effect_id.clone(), record);
            Ok(())
        }
        StagedMutation::Blob(blob) => insert_immutable(
            &mut tenant.blobs,
            blob.reference.digest.clone(),
            BlobState::in_memory(blob),
        ),
        StagedMutation::Outbox(message) => {
            if tenant
                .outbox
                .iter()
                .any(|record| record.message.message_id == message.message_id)
            {
                return Err(StoreError::new(StoreErrorCode::InvalidRecord));
            }
            tenant.outbox.push(OutboxRecord {
                message,
                causal_revision: revision,
            });
            Ok(())
        }
    }
}

fn update_current_lineage(
    atoms: &BTreeMap<VersionId, ContextAtomV1>,
    current: &mut BTreeMap<LineageId, VersionId>,
    candidate: &ContextAtomV1,
) -> Result<(), StoreError> {
    let replace = match current.get(&candidate.lineage_id) {
        Some(version) => {
            let existing = atoms
                .get(version)
                .ok_or_else(|| StoreError::new(StoreErrorCode::InvalidRecord))?;
            (candidate.temporal.observed_at, &candidate.version_id)
                > (existing.temporal.observed_at, &existing.version_id)
        }
        None => true,
    };
    if replace {
        current.insert(candidate.lineage_id.clone(), candidate.version_id.clone());
    }
    Ok(())
}

fn creates_derivation_cycle(
    edges: &BTreeMap<RecordId, ContextEdge>,
    candidate: &ContextEdge,
) -> Result<bool, StoreError> {
    if candidate.kind != EdgeKind::DerivedFrom {
        return Ok(false);
    }
    let mut pending = vec![candidate.to_version.clone()];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if current == candidate.from_version {
            return Ok(true);
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        if visited.len() > 100_000 {
            return Err(StoreError::new(StoreErrorCode::LimitExceeded));
        }
        pending.extend(
            edges
                .values()
                .filter(|edge| edge.kind == EdgeKind::DerivedFrom && edge.from_version == current)
                .map(|edge| edge.to_version.clone()),
        );
    }
    Ok(false)
}

fn insert_immutable<K: Ord, V: Eq>(
    values: &mut BTreeMap<K, V>,
    key: K,
    value: V,
) -> Result<(), StoreError> {
    if let Some(existing) = values.get(&key) {
        if existing == &value {
            Ok(())
        } else {
            Err(StoreError::new(StoreErrorCode::InvalidRecord))
        }
    } else {
        values.insert(key, value);
        Ok(())
    }
}

pub(crate) fn validate<T: Validate>(value: &T) -> Result<(), StoreError> {
    value
        .validate()
        .map_err(|_error| StoreError::new(StoreErrorCode::InvalidRecord))
}

pub(crate) fn blob_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        let _result = write!(&mut value, "{byte:02x}");
    }
    value
}
