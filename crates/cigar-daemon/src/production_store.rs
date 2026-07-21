//! Closed production repository composition over local and shared durable profiles.

use cigar_protocol::{
    ContentDigest, ContextAtomV1, ContextBundle, ContextCommit, ContextEdge, ContextSpaceId,
    EdgeKind, EffectJournalEvent, RecordId, SourceSnapshot, VersionId,
};
use cigar_store::{
    AccessContext, AtomCursor, AtomPage, AtomSelector, BlobRecord, CancellationToken,
    CommitReceipt, EffectRecordEnvelope, EffectRecoveryPage, EffectRecoveryQuery,
    IdempotencyIdentity, InMemoryReadTransaction, OutboxMessage, OutboxRecord, OutboxRecoveryPage,
    OutboxRecoveryQuery, PostgresStore, PostgresWriteTransaction, ReadTransaction, Repository,
    ServiceBatch, ServiceBatchReceipt, ServiceError, ServiceListPage, ServiceListQuery,
    ServiceRecord, ServiceRecordLocator, ServiceRecordSelection, ServiceRepository,
    SnapshotSelection, SqliteReadTransaction, SqliteStore, SqliteV5Store, SqliteV5WriteTransaction,
    SqliteWriteTransaction, StoreError, StoreRevision, WorkerLocator, WorkerState, WorkerUpdate,
    WriteTransaction,
};
use std::fmt;

/// Exact local SQLite or shared PostgreSQL repository selected by validated composition.
pub enum ProductionStore {
    /// Durable single-node local v4 compatibility profile.
    Local(SqliteStore),
    /// Activated incremental single-node local v5 profile.
    LocalV5(SqliteV5Store),
    /// Transactional shared PostgreSQL/object profile.
    Shared(PostgresStore),
}

impl ProductionStore {
    /// Wraps a verified local repository.
    #[must_use]
    pub const fn local(store: SqliteStore) -> Self {
        Self::Local(store)
    }

    /// Wraps an authenticated activated local v5 repository.
    #[must_use]
    pub const fn local_v5(store: SqliteV5Store) -> Self {
        Self::LocalV5(store)
    }

    /// Wraps a verified shared repository.
    #[must_use]
    pub const fn shared(store: PostgresStore) -> Self {
        Self::Shared(store)
    }

    /// Returns the current global MVCC revision.
    pub fn revision(&self) -> Result<StoreRevision, StoreError> {
        match self {
            Self::Local(store) => store.revision(),
            Self::LocalV5(store) => store.revision(),
            Self::Shared(store) => store.revision(),
        }
    }

    /// Verifies the active append-only migration level without executing DDL.
    pub fn verify_migration_level(&self) -> Result<(), StoreError> {
        match self {
            Self::Local(store) => store.verify_migration_level(),
            Self::LocalV5(store) => store.verify_migration_level(),
            Self::Shared(store) => store.verify_migration_level(),
        }
    }

    /// Performs an exact encrypted blob readiness probe.
    pub fn blob_readiness_probe(
        &self,
        tenant: &RecordId,
        blob: &BlobRecord,
    ) -> Result<(), StoreError> {
        match self {
            Self::Local(store) => store.blob_readiness_probe(tenant, blob),
            Self::LocalV5(store) => store.blob_readiness_probe(tenant, blob),
            Self::Shared(store) => store.blob_readiness_probe(tenant, blob),
        }
    }

    /// Reconciles live metadata roots against the selected blob profile.
    pub fn reconcile_blob_roots(&self, tenants: &[RecordId]) -> Result<(), StoreError> {
        match self {
            Self::Local(store) => store.reconcile_blob_roots(),
            Self::LocalV5(store) => store.reconcile_blob_roots(),
            Self::Shared(store) => store.reconcile_blob_roots(tenants),
        }
    }
}

impl fmt::Debug for ProductionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(_store) => formatter.write_str("ProductionStore::Local"),
            Self::LocalV5(_store) => formatter.write_str("ProductionStore::LocalV5"),
            Self::Shared(_store) => formatter.write_str("ProductionStore::Shared"),
        }
    }
}

/// Closed immutable transaction for the selected production repository.
pub enum ProductionReadTransaction {
    /// Snapshot-pinned normalized SQLite reader.
    Local(SqliteReadTransaction),
    /// Snapshot-pinned shared PostgreSQL reader.
    Shared(InMemoryReadTransaction),
}

impl fmt::Debug for ProductionReadTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(transaction) => transaction.fmt(formatter),
            Self::Shared(transaction) => transaction.fmt(formatter),
        }
    }
}

impl ReadTransaction for ProductionReadTransaction {
    fn revision(&self) -> StoreRevision {
        match self {
            Self::Local(transaction) => transaction.revision(),
            Self::Shared(transaction) => transaction.revision(),
        }
    }

    fn get_atom(&self, version: &VersionId) -> Result<Option<ContextAtomV1>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_atom(version),
            Self::Shared(transaction) => transaction.get_atom(version),
        }
    }

    fn get_atoms_by_id(
        &self,
        atom_ids: &[RecordId],
    ) -> Result<Vec<Option<ContextAtomV1>>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_atoms_by_id(atom_ids),
            Self::Shared(transaction) => transaction.get_atoms_by_id(atom_ids),
        }
    }

    fn get_active_atom_by_id(
        &self,
        atom_id: &RecordId,
    ) -> Result<Option<ContextAtomV1>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_active_atom_by_id(atom_id),
            Self::Shared(transaction) => transaction.get_active_atom_by_id(atom_id),
        }
    }

    fn query_atoms(
        &self,
        selector: AtomSelector,
        limit: usize,
        cursor: Option<&AtomCursor>,
    ) -> Result<AtomPage, StoreError> {
        match self {
            Self::Local(transaction) => transaction.query_atoms(selector, limit, cursor),
            Self::Shared(transaction) => transaction.query_atoms(selector, limit, cursor),
        }
    }

    fn edges_from(
        &self,
        version: &VersionId,
        kind: Option<EdgeKind>,
        limit: usize,
    ) -> Result<Vec<ContextEdge>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.edges_from(version, kind, limit),
            Self::Shared(transaction) => transaction.edges_from(version, kind, limit),
        }
    }

    fn get_bundle(&self, bundle: &VersionId) -> Result<Option<ContextBundle>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_bundle(bundle),
            Self::Shared(transaction) => transaction.get_bundle(bundle),
        }
    }

    fn get_snapshot(&self, snapshot: &RecordId) -> Result<Option<SourceSnapshot>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_snapshot(snapshot),
            Self::Shared(transaction) => transaction.get_snapshot(snapshot),
        }
    }

    fn context_commits(&self, space: &ContextSpaceId) -> Result<Vec<ContextCommit>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.context_commits(space),
            Self::Shared(transaction) => transaction.context_commits(space),
        }
    }

    fn get_effect(&self, effect: &RecordId) -> Result<Vec<EffectJournalEvent>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_effect(effect),
            Self::Shared(transaction) => transaction.get_effect(effect),
        }
    }

    fn get_effect_record(
        &self,
        effect: &RecordId,
    ) -> Result<Option<EffectRecordEnvelope>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_effect_record(effect),
            Self::Shared(transaction) => transaction.get_effect_record(effect),
        }
    }

    fn get_blob(&self, digest: &ContentDigest) -> Result<Option<BlobRecord>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.get_blob(digest),
            Self::Shared(transaction) => transaction.get_blob(digest),
        }
    }

    fn outbox(&self) -> Result<Vec<OutboxRecord>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.outbox(),
            Self::Shared(transaction) => transaction.outbox(),
        }
    }

    fn idempotent_result(
        &self,
        identity: &IdempotencyIdentity,
    ) -> Result<Option<CommitReceipt>, StoreError> {
        match self {
            Self::Local(transaction) => transaction.idempotent_result(identity),
            Self::Shared(transaction) => transaction.idempotent_result(identity),
        }
    }
}

/// Closed mutable transaction for the selected production repository.
pub enum ProductionWriteTransaction<'store> {
    /// SQLite v4 compatibility write transaction.
    Local(SqliteWriteTransaction<'store>),
    /// SQLite v5 incremental write transaction.
    LocalV5(SqliteV5WriteTransaction<'store>),
    /// PostgreSQL write transaction.
    Shared(PostgresWriteTransaction<'store>),
}

impl fmt::Debug for ProductionWriteTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(transaction) => transaction.fmt(formatter),
            Self::LocalV5(transaction) => transaction.fmt(formatter),
            Self::Shared(transaction) => transaction.fmt(formatter),
        }
    }
}

impl WriteTransaction for ProductionWriteTransaction<'_> {
    fn stage_snapshot(&mut self, snapshot: SourceSnapshot) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.stage_snapshot(snapshot),
            Self::LocalV5(transaction) => transaction.stage_snapshot(snapshot),
            Self::Shared(transaction) => transaction.stage_snapshot(snapshot),
        }
    }

    fn publish_atoms(
        &mut self,
        atoms: Vec<ContextAtomV1>,
        edges: Vec<ContextEdge>,
    ) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.publish_atoms(atoms, edges),
            Self::LocalV5(transaction) => transaction.publish_atoms(atoms, edges),
            Self::Shared(transaction) => transaction.publish_atoms(atoms, edges),
        }
    }

    fn put_bundle(&mut self, bundle: ContextBundle) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.put_bundle(bundle),
            Self::LocalV5(transaction) => transaction.put_bundle(bundle),
            Self::Shared(transaction) => transaction.put_bundle(bundle),
        }
    }

    fn append_context_commit(&mut self, commit: ContextCommit) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.append_context_commit(commit),
            Self::LocalV5(transaction) => transaction.append_context_commit(commit),
            Self::Shared(transaction) => transaction.append_context_commit(commit),
        }
    }

    fn append_effect_event(&mut self, event: EffectJournalEvent) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.append_effect_event(event),
            Self::LocalV5(transaction) => transaction.append_effect_event(event),
            Self::Shared(transaction) => transaction.append_effect_event(event),
        }
    }

    fn put_effect_record(&mut self, record: EffectRecordEnvelope) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.put_effect_record(record),
            Self::LocalV5(transaction) => transaction.put_effect_record(record),
            Self::Shared(transaction) => transaction.put_effect_record(record),
        }
    }

    fn put_blob(&mut self, blob: BlobRecord) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.put_blob(blob),
            Self::LocalV5(transaction) => transaction.put_blob(blob),
            Self::Shared(transaction) => transaction.put_blob(blob),
        }
    }

    fn enqueue_outbox(&mut self, message: OutboxMessage) -> Result<(), StoreError> {
        match self {
            Self::Local(transaction) => transaction.enqueue_outbox(message),
            Self::LocalV5(transaction) => transaction.enqueue_outbox(message),
            Self::Shared(transaction) => transaction.enqueue_outbox(message),
        }
    }

    fn commit(self, idempotency: Option<IdempotencyIdentity>) -> Result<CommitReceipt, StoreError> {
        match self {
            Self::Local(transaction) => transaction.commit(idempotency),
            Self::LocalV5(transaction) => transaction.commit(idempotency),
            Self::Shared(transaction) => transaction.commit(idempotency),
        }
    }
}

impl Repository for ProductionStore {
    type Read<'store>
        = ProductionReadTransaction
    where
        Self: 'store;
    type Write<'store>
        = ProductionWriteTransaction<'store>
    where
        Self: 'store;

    fn begin_read(
        &self,
        context: AccessContext,
        selection: SnapshotSelection,
        cancellation: CancellationToken,
    ) -> Result<Self::Read<'_>, StoreError> {
        match self {
            Self::Local(store) => store
                .begin_read(context, selection, cancellation)
                .map(ProductionReadTransaction::Local),
            Self::LocalV5(store) => store
                .begin_read(context, selection, cancellation)
                .map(ProductionReadTransaction::Local),
            Self::Shared(store) => store
                .begin_read(context, selection, cancellation)
                .map(ProductionReadTransaction::Shared),
        }
    }

    fn begin_write(
        &self,
        context: AccessContext,
        expected_revision: StoreRevision,
        cancellation: CancellationToken,
    ) -> Result<Self::Write<'_>, StoreError> {
        match self {
            Self::Local(store) => store
                .begin_write(context, expected_revision, cancellation)
                .map(ProductionWriteTransaction::Local),
            Self::LocalV5(store) => store
                .begin_write(context, expected_revision, cancellation)
                .map(ProductionWriteTransaction::LocalV5),
            Self::Shared(store) => store
                .begin_write(context, expected_revision, cancellation)
                .map(ProductionWriteTransaction::Shared),
        }
    }
}

impl ServiceRepository for ProductionStore {
    fn service_get(
        &self,
        locator: &ServiceRecordLocator,
        selection: ServiceRecordSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<ServiceRecord>, ServiceError> {
        match self {
            Self::Local(store) => store.service_get(locator, selection, cancellation),
            Self::LocalV5(store) => store.service_get(locator, selection, cancellation),
            Self::Shared(store) => store.service_get(locator, selection, cancellation),
        }
    }

    fn service_list(
        &self,
        query: &ServiceListQuery,
        cancellation: &CancellationToken,
    ) -> Result<ServiceListPage, ServiceError> {
        match self {
            Self::Local(store) => store.service_list(query, cancellation),
            Self::LocalV5(store) => store.service_list(query, cancellation),
            Self::Shared(store) => store.service_list(query, cancellation),
        }
    }

    fn service_commit(
        &self,
        batch: ServiceBatch,
        cancellation: &CancellationToken,
    ) -> Result<ServiceBatchReceipt, ServiceError> {
        match self {
            Self::Local(store) => store.service_commit(batch, cancellation),
            Self::LocalV5(store) => store.service_commit(batch, cancellation),
            Self::Shared(store) => store.service_commit(batch, cancellation),
        }
    }

    fn effect_recovery(
        &self,
        query: &EffectRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<EffectRecoveryPage, ServiceError> {
        match self {
            Self::Local(store) => store.effect_recovery(query, cancellation),
            Self::LocalV5(store) => store.effect_recovery(query, cancellation),
            Self::Shared(store) => store.effect_recovery(query, cancellation),
        }
    }

    fn outbox_recovery(
        &self,
        query: &OutboxRecoveryQuery,
        cancellation: &CancellationToken,
    ) -> Result<OutboxRecoveryPage, ServiceError> {
        match self {
            Self::Local(store) => store.outbox_recovery(query, cancellation),
            Self::LocalV5(store) => store.outbox_recovery(query, cancellation),
            Self::Shared(store) => store.outbox_recovery(query, cancellation),
        }
    }

    fn worker_get(
        &self,
        locator: &WorkerLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<WorkerState>, ServiceError> {
        match self {
            Self::Local(store) => store.worker_get(locator, cancellation),
            Self::LocalV5(store) => store.worker_get(locator, cancellation),
            Self::Shared(store) => store.worker_get(locator, cancellation),
        }
    }

    fn worker_update(
        &self,
        locator: &WorkerLocator,
        update: WorkerUpdate,
        cancellation: &CancellationToken,
    ) -> Result<WorkerState, ServiceError> {
        match self {
            Self::Local(store) => store.worker_update(locator, update, cancellation),
            Self::LocalV5(store) => store.worker_update(locator, update, cancellation),
            Self::Shared(store) => store.worker_update(locator, update, cancellation),
        }
    }
}
