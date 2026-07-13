//! Repository-backed mandatory catalog index reconstruction and maintenance.

use crate::{
    AuthorityClock, LifecycleError, ProductionDomainMaintenance, ProductionIndexTarget,
    ProductionStore, ProductionTenantProvider, WorkerJob, WorkerKind,
};
use cigar_protocol::{ContentDigest, ContextAtomV1, ContextEdge, RecordId, UtcTimestamp};
use cigar_retrieval::{
    InMemoryIndexManager, IndexBuild, IndexSnapshot, IndexSnapshotProvider, IndexWorker,
    RetrievalContext, RetrievalError, RetrievalErrorCode,
};
use cigar_store::{
    AccessContext, AtomSelector, CancellationToken, OutboxRecord, ReadTransaction, Repository,
    SnapshotSelection, StoreRevision,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

const INDEX_PURPOSE: &str = "daemon.mandatory-index.v1";
const CATALOG_TOPIC: &str = "catalog.committed";
const MAX_CATALOG_OUTBOX_RECORDS: usize = 1_000_000;
const MAX_INDEX_EDGE_FANOUT: usize = 1_000;
const INDEX_DEADLINE: Duration = Duration::from_secs(120);

/// Concrete catalog watermark, snapshot loader, and supported domain maintenance processor.
pub struct RepositoryCatalogIndex {
    store: Arc<ProductionStore>,
    tenants: Arc<dyn ProductionTenantProvider>,
    manager: Arc<InMemoryIndexManager>,
    worker: Arc<IndexWorker>,
    clock: Arc<dyn AuthorityClock>,
    configuration_digest: ContentDigest,
}

impl RepositoryCatalogIndex {
    /// Creates a repository-backed mandatory index coordinator.
    pub fn new(
        store: Arc<ProductionStore>,
        tenants: Arc<dyn ProductionTenantProvider>,
        manager: Arc<InMemoryIndexManager>,
        worker: Arc<IndexWorker>,
        clock: Arc<dyn AuthorityClock>,
    ) -> Result<Self, LifecycleError> {
        Ok(Self {
            store,
            tenants,
            manager,
            worker,
            clock,
            configuration_digest: multihash(b"cigar.mandatory-index.configuration.v1")?,
        })
    }

    /// Reconstructs and activates the complete mandatory generation from durable catalog outbox
    /// truth. This is called before readiness can open and after each indexing wakeup.
    pub fn rebuild(&self) -> Result<(), LifecycleError> {
        let records = self.catalog_outbox()?;
        let context = self.context();
        let now = self
            .clock
            .now()
            .map_err(|_error| LifecycleError::action_failed())?;
        if records.is_empty() {
            if self
                .manager
                .active_generation()
                .map_err(retrieval_lifecycle)?
                .is_none()
            {
                self.activate_empty(now, &context)?;
            }
            return Ok(());
        }
        let receipt = self
            .worker
            .process(
                &records,
                self,
                &self.manager,
                self.configuration_digest.clone(),
                None,
                now,
                &context,
            )
            .map_err(retrieval_lifecycle)?;
        if receipt.active_generation.is_none() {
            return Err(LifecycleError::action_failed());
        }
        Ok(())
    }

    /// Returns the concrete manager used as the application retriever and readiness projection.
    #[must_use]
    pub fn manager(&self) -> Arc<InMemoryIndexManager> {
        Arc::clone(&self.manager)
    }

    /// Returns the activation-backed worker checked by readiness.
    #[must_use]
    pub fn worker(&self) -> Arc<IndexWorker> {
        Arc::clone(&self.worker)
    }

    fn context(&self) -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + INDEX_DEADLINE,
        }
    }

    fn active_tenants(&self) -> Result<Vec<RecordId>, LifecycleError> {
        let tenants = self.tenants.active_tenants()?;
        if tenants.is_empty()
            || tenants
                .windows(2)
                .any(|pair| pair.first().zip(pair.get(1)).is_some_and(|(a, b)| a >= b))
        {
            return Err(LifecycleError::action_failed());
        }
        Ok(tenants)
    }

    fn catalog_outbox(&self) -> Result<Vec<OutboxRecord>, LifecycleError> {
        let mut records = Vec::new();
        for tenant in self.active_tenants()? {
            let access = AccessContext::new(tenant, INDEX_PURPOSE)
                .map_err(|_error| LifecycleError::action_failed())?;
            let read = self
                .store
                .begin_read(
                    access,
                    SnapshotSelection::Latest,
                    CancellationToken::default(),
                )
                .map_err(|_error| LifecycleError::action_failed())?;
            records.extend(
                read.outbox()
                    .map_err(|_error| LifecycleError::action_failed())?
                    .into_iter()
                    .filter(|record| record.message.topic == CATALOG_TOPIC),
            );
            if records.len() > MAX_CATALOG_OUTBOX_RECORDS {
                return Err(LifecycleError::action_failed());
            }
        }
        records.sort_by(|left, right| {
            left.causal_revision
                .cmp(&right.causal_revision)
                .then_with(|| left.message.message_id.cmp(&right.message.message_id))
        });
        Ok(records)
    }

    fn load_snapshot(
        &self,
        revision: StoreRevision,
        context: &RetrievalContext,
    ) -> Result<IndexSnapshot, RetrievalError> {
        let tenants = self
            .active_tenants()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        let mut atoms: BTreeMap<_, ContextAtomV1> = BTreeMap::new();
        let mut edges: BTreeMap<_, ContextEdge> = BTreeMap::new();
        for tenant in tenants {
            context.check()?;
            let access = AccessContext::new(tenant, INDEX_PURPOSE)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?;
            let read = self
                .store
                .begin_read(
                    access,
                    SnapshotSelection::Revision(revision),
                    context.cancellation.clone(),
                )
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
            let mut cursor = None;
            loop {
                context.check()?;
                let page = read
                    .query_atoms(AtomSelector::default(), 1_000, cursor.as_ref())
                    .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
                for atom in page.items {
                    let outgoing = read
                        .edges_from(&atom.version_id, None, MAX_INDEX_EDGE_FANOUT)
                        .map_err(|_error| {
                            RetrievalError::new(RetrievalErrorCode::IndexUnavailable)
                        })?;
                    for edge in outgoing {
                        if edges.insert(edge.edge_id.clone(), edge).is_some() {
                            return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
                        }
                    }
                    if atoms.insert(atom.version_id.clone(), atom).is_some() {
                        return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
                    }
                }
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(IndexSnapshot {
            atoms: atoms.into_values().collect(),
            edges: edges.into_values().collect(),
        })
    }

    fn activate_empty(
        &self,
        verified_at: UtcTimestamp,
        context: &RetrievalContext,
    ) -> Result<(), LifecycleError> {
        let descriptor = self
            .manager
            .build_generation(
                IndexBuild {
                    atoms: Vec::new(),
                    edges: Vec::new(),
                    built_through_revision: StoreRevision(0),
                    configuration_digest: self.configuration_digest.clone(),
                    verified_at,
                    vector_fingerprint: None,
                },
                context,
            )
            .map_err(retrieval_lifecycle)?;
        self.manager
            .activate(&descriptor.generation_id, None)
            .map(|_active| ())
            .map_err(retrieval_lifecycle)
    }

    fn verify_projection(&self) -> Result<(), LifecycleError> {
        let target = self.target_revision()?;
        let active = self
            .manager
            .active_generation()
            .map_err(retrieval_lifecycle)?
            .ok_or_else(LifecycleError::action_failed)?;
        let watermark = self.worker.watermark().map_err(retrieval_lifecycle)?;
        if active.built_through_revision == watermark && watermark >= target {
            Ok(())
        } else {
            Err(LifecycleError::action_failed())
        }
    }
}

impl IndexSnapshotProvider for RepositoryCatalogIndex {
    fn load(
        &self,
        revision: StoreRevision,
        context: &RetrievalContext,
    ) -> Result<IndexSnapshot, RetrievalError> {
        self.load_snapshot(revision, context)
    }
}

impl ProductionIndexTarget for RepositoryCatalogIndex {
    fn target_revision(&self) -> Result<StoreRevision, LifecycleError> {
        Ok(self
            .catalog_outbox()?
            .last()
            .map_or(StoreRevision(0), |record| record.causal_revision))
    }
}

impl ProductionDomainMaintenance for RepositoryCatalogIndex {
    fn cleanup_expired_leases(&self) -> Result<(), LifecycleError> {
        // Current repository-backed catalog/index composition owns no renewable domain lease;
        // runtime worker leases are fenced and expired by `RepositoryOperationalState`.
        self.verify_projection()
    }

    fn verify_worker_cursors(&self) -> Result<(), LifecycleError> {
        // The catalog outbox is durable truth and the activation-backed watermark is its cursor.
        self.verify_projection()
    }

    fn checkpoint_workers(&self) -> Result<(), LifecycleError> {
        // Index generations are disposable; durable catalog outbox records are the restart cursor.
        self.verify_projection()
    }

    fn release_renewable_leases(&self) -> Result<(), LifecycleError> {
        self.verify_projection()
    }

    fn process_worker_job(&self, kind: WorkerKind, _job: &WorkerJob) -> Result<(), LifecycleError> {
        match kind {
            WorkerKind::Indexing | WorkerKind::Invalidation => self.rebuild(),
            WorkerKind::LeaseCleanup => self.cleanup_expired_leases(),
            WorkerKind::Ingestion
            | WorkerKind::Compilation
            | WorkerKind::Outbox
            | WorkerKind::Reconciliation
            | WorkerKind::Backup
            | WorkerKind::GarbageCollection => Err(LifecycleError::action_failed()),
        }
    }

    fn poll_durable_work(&self) -> Result<bool, LifecycleError> {
        let watermark = self.worker.watermark().map_err(retrieval_lifecycle)?;
        let next = self
            .catalog_outbox()?
            .into_iter()
            .find(|record| record.causal_revision > watermark);
        let Some(next) = next else {
            return Ok(false);
        };
        let context = self.context();
        let now = self
            .clock
            .now()
            .map_err(|_error| LifecycleError::action_failed())?;
        let receipt = self
            .worker
            .process(
                &[next],
                self,
                &self.manager,
                self.configuration_digest.clone(),
                None,
                now,
                &context,
            )
            .map_err(retrieval_lifecycle)?;
        if receipt.claimed_messages == 1 && receipt.watermark > watermark {
            Ok(true)
        } else {
            Err(LifecycleError::action_failed())
        }
    }
}

impl fmt::Debug for RepositoryCatalogIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryCatalogIndex")
            .field("store", &self.store)
            .field("manager", &self.manager)
            .field("worker", &self.worker)
            .finish_non_exhaustive()
    }
}

fn multihash(bytes: &[u8]) -> Result<ContentDigest, LifecycleError> {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| LifecycleError::action_failed())?;
    }
    ContentDigest::new(encoded).map_err(|_error| LifecycleError::action_failed())
}

fn retrieval_lifecycle(_error: RetrievalError) -> LifecycleError {
    LifecycleError::action_failed()
}

#[cfg(test)]
mod tests {
    use super::RepositoryCatalogIndex;
    use crate::{
        AuthorityClock, AuthorityError, ProductionDomainMaintenance, ProductionIndexTarget,
        ProductionTenantProvider,
    };
    use cigar_protocol::{ContentDigest, ContextAtomV1, RecordId, UtcTimestamp};
    use cigar_retrieval::{InMemoryIndexManager, IndexWorker};
    use cigar_store::{
        AccessContext, CancellationToken, OutboxMessage, Repository, SqliteStore, StoreRevision,
        WriteTransaction,
    };
    use cigar_testkit::deterministic_protocol_fixture;
    use std::error::Error;
    use std::sync::Arc;

    struct Tenants(Vec<RecordId>);

    impl ProductionTenantProvider for Tenants {
        fn active_tenants(&self) -> Result<Vec<RecordId>, crate::LifecycleError> {
            Ok(self.0.clone())
        }
    }

    struct Clock(UtcTimestamp);

    impl AuthorityClock for Clock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            Ok(self.0)
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            i64::try_from(self.0.unix_nanos() / 1_000_000_000)
                .map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    fn digest(byte: char) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            byte.to_string().repeat(64)
        ))?)
    }

    fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn atom() -> Result<ContextAtomV1, Box<dyn Error>> {
        let fixture = deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing ContextAtomV1 fixture")?;
        Ok(serde_json::from_value(fixture.input)?)
    }

    fn coordinator(
        store: Arc<crate::ProductionStore>,
        tenant: RecordId,
    ) -> Result<RepositoryCatalogIndex, Box<dyn Error>> {
        Ok(RepositoryCatalogIndex::new(
            store,
            Arc::new(Tenants(vec![tenant])),
            Arc::new(InMemoryIndexManager::default()),
            Arc::new(IndexWorker::default()),
            Arc::new(Clock(UtcTimestamp::parse_rfc3339("2026-07-11T12:00:00Z")?)),
        )?)
    }

    fn commit_catalog(
        store: &crate::ProductionStore,
        tenant: RecordId,
        expected: StoreRevision,
        atom: Option<ContextAtomV1>,
        message: u64,
    ) -> Result<StoreRevision, Box<dyn Error>> {
        let access = AccessContext::new(tenant, "test.index")?;
        let mut write = store.begin_write(access, expected, CancellationToken::default())?;
        if let Some(atom) = atom {
            write.publish_atoms(vec![atom], Vec::new())?;
        }
        write.enqueue_outbox(OutboxMessage {
            message_id: record(message)?,
            topic: "catalog.committed".to_owned(),
            payload_digest: digest(if message.is_multiple_of(2) { 'a' } else { 'b' })?,
        })?;
        Ok(write.commit(None)?.revision)
    }

    #[test]
    fn empty_activation_commit_rebuild_restart_and_lag_detection_are_exact()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(crate::ProductionStore::local(SqliteStore::open(
            directory.path().join("index.sqlite3"),
        )?));
        let fixture = atom()?;
        let tenant = fixture.scope.tenant_id.clone();

        let first = coordinator(Arc::clone(&store), tenant.clone())?;
        first.rebuild()?;
        let empty = first
            .manager()
            .active_generation()?
            .ok_or("missing empty index")?;
        assert_eq!(empty.built_through_revision, StoreRevision(0));
        assert_eq!(first.target_revision()?, StoreRevision(0));

        let revision = commit_catalog(
            &store,
            tenant.clone(),
            StoreRevision(0),
            Some(fixture.clone()),
            10,
        )?;
        assert_eq!(revision, StoreRevision(1));
        assert!(first.verify_worker_cursors().is_err());
        first.rebuild()?;
        let active = first
            .manager()
            .active_generation()?
            .ok_or("missing active index")?;
        assert_eq!(active.built_through_revision, StoreRevision(1));
        assert_eq!(first.worker().watermark()?, StoreRevision(1));
        first.rebuild()?;
        assert_eq!(first.worker().watermark()?, StoreRevision(1));

        let second_revision = commit_catalog(&store, tenant.clone(), revision, Some(fixture), 11)?;
        assert_eq!(second_revision, StoreRevision(2));
        assert!(first.verify_worker_cursors().is_err());
        first.rebuild()?;
        assert_eq!(first.worker().watermark()?, StoreRevision(2));

        let restarted = coordinator(store, tenant)?;
        restarted.rebuild()?;
        let restarted_active = restarted
            .manager()
            .active_generation()?
            .ok_or("missing restarted index")?;
        assert_eq!(restarted_active.built_through_revision, StoreRevision(2));
        assert_eq!(
            restarted_active.semantic_root,
            first
                .manager()
                .active_generation()?
                .ok_or("missing first index")?
                .semantic_root
        );
        assert!(restarted.verify_worker_cursors().is_ok());
        Ok(())
    }
}
