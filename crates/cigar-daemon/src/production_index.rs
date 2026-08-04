//! Repository-backed mandatory catalog index reconstruction and maintenance.

use crate::{
    AuthorityClock, DaemonTelemetry, LifecycleError, ProductionDomainMaintenance,
    ProductionIndexTarget, ProductionStore, ProductionTenantProvider, WorkerJob, WorkerKind,
};
use cigar_protocol::{ContentDigest, ContextAtomV1, ContextEdge, RecordId, UtcTimestamp};
use cigar_retrieval::{
    InMemoryIndexManager, IndexBuild, IndexSnapshot, IndexSnapshotProvider, IndexWorker,
    RetrievalContext, RetrievalError, RetrievalErrorCode, VectorIndexBinding,
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
const CATALOG_COMMITTED_TOPIC: &str = "catalog.committed";
const CATALOG_TOMBSTONED_TOPIC: &str = "catalog.atom-tombstoned";
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
    telemetry: Option<Arc<DaemonTelemetry>>,
    #[cfg(target_os = "macos")]
    local_vector: Option<Arc<crate::ProductionLocalVectorRuntime>>,
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
            telemetry: None,
            #[cfg(target_os = "macos")]
            local_vector: None,
        })
    }

    /// Attaches process telemetry to the index worker that owns invalidation fan-out counts.
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Arc<DaemonTelemetry>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Installs the explicit macOS local-vector runtime before the first generation is built.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn with_local_vector_runtime(
        mut self,
        runtime: Arc<crate::ProductionLocalVectorRuntime>,
    ) -> Self {
        self.local_vector = Some(runtime);
        self
    }

    /// Reconstructs and activates the complete mandatory generation from durable catalog outbox
    /// truth. This is called before readiness can open and after each indexing wakeup.
    pub fn rebuild(&self) -> Result<(), LifecycleError> {
        let context = self.context();
        let now = self
            .clock
            .now()
            .map_err(|_error| LifecycleError::action_failed())?;
        if self
            .manager
            .active_generation()
            .map_err(retrieval_lifecycle)?
            .is_none()
        {
            let target = self
                .store
                .revision()
                .map_err(|_error| LifecycleError::action_failed())?;
            if target == StoreRevision(0) {
                self.activate_empty(now, &context)?;
            } else {
                let receipt = self
                    .worker
                    .restore(
                        target,
                        self,
                        &self.manager,
                        self.configuration_digest.clone(),
                        self.vector_binding(target, &context)?,
                        now,
                        &context,
                    )
                    .map_err(retrieval_lifecycle)?;
                if receipt.active_generation.is_none() {
                    return Err(LifecycleError::action_failed());
                }
            }
            return Ok(());
        }
        let watermark = self.worker.watermark().map_err(retrieval_lifecycle)?;
        let records: Vec<_> = self
            .catalog_outbox()?
            .into_iter()
            .filter(|record| record.causal_revision > watermark)
            .collect();
        if records.is_empty() {
            return Ok(());
        }
        let receipt = self
            .worker
            .process(
                &records,
                self,
                &self.manager,
                self.configuration_digest.clone(),
                self.vector_binding(
                    records
                        .last()
                        .map_or(StoreRevision(0), |record| record.causal_revision),
                    &context,
                )?,
                now,
                &context,
            )
            .map_err(retrieval_lifecycle)?;
        if receipt.active_generation.is_none() {
            return Err(LifecycleError::action_failed());
        }
        if receipt.claimed_messages > 0
            && let Some(telemetry) = &self.telemetry
        {
            telemetry.record_invalidation_fanout(
                u64::try_from(receipt.claimed_messages).unwrap_or(u64::MAX),
            );
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
                    .filter(|record| {
                        matches!(
                            record.message.topic.as_str(),
                            CATALOG_COMMITTED_TOPIC | CATALOG_TOMBSTONED_TOPIC
                        )
                    }),
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
        let mut tenant_watermarks = BTreeMap::new();
        for tenant in tenants {
            context.check()?;
            let access = AccessContext::new(tenant.clone(), INDEX_PURPOSE)
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?;
            let read = self
                .store
                .begin_read(
                    access,
                    SnapshotSelection::Revision(revision),
                    context.cancellation.clone(),
                )
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
            let tenant_watermark = read
                .outbox()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
                .into_iter()
                .filter(|record| {
                    record.causal_revision <= revision
                        && matches!(
                            record.message.topic.as_str(),
                            CATALOG_COMMITTED_TOPIC | CATALOG_TOMBSTONED_TOPIC
                        )
                })
                .map(|record| record.causal_revision)
                .max();
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
            // A pruned historical catalog revision cannot be reloaded during startup. The
            // selected immutable snapshot is complete through its global revision, which is the
            // safe activation watermark when no retained catalog message supplies a narrower one.
            tenant_watermarks.insert(tenant, tenant_watermark.unwrap_or(revision));
        }
        Ok(IndexSnapshot {
            atoms: atoms.into_values().collect(),
            edges: edges.into_values().collect(),
            tenant_watermarks,
        })
    }

    fn activate_empty(
        &self,
        verified_at: UtcTimestamp,
        context: &RetrievalContext,
    ) -> Result<(), LifecycleError> {
        let tenant_watermarks: BTreeMap<_, _> = self
            .active_tenants()?
            .into_iter()
            .map(|tenant| (tenant, StoreRevision(0)))
            .collect();
        let vector_binding = self.vector_binding_for_snapshot(
            &IndexSnapshot {
                atoms: Vec::new(),
                edges: Vec::new(),
                tenant_watermarks: tenant_watermarks.clone(),
            },
            StoreRevision(0),
            context,
        );
        let descriptor = self
            .manager
            .build_generation(
                IndexBuild {
                    atoms: Vec::new(),
                    edges: Vec::new(),
                    built_through_revision: StoreRevision(0),
                    tenant_watermarks,
                    configuration_digest: self.configuration_digest.clone(),
                    verified_at,
                    vector_binding,
                },
                context,
            )
            .map_err(retrieval_lifecycle)?;
        self.manager
            .activate(&descriptor.generation_id, None)
            .map(|_active| ())
            .map_err(retrieval_lifecycle)
    }

    fn vector_binding(
        &self,
        revision: StoreRevision,
        context: &RetrievalContext,
    ) -> Result<Option<VectorIndexBinding>, LifecycleError> {
        #[cfg(target_os = "macos")]
        if self.local_vector.is_some() {
            let snapshot = self
                .load_snapshot(revision, context)
                .map_err(retrieval_lifecycle)?;
            return Ok(self.vector_binding_for_snapshot(&snapshot, revision, context));
        }
        let _ = (revision, context);
        Ok(None)
    }

    fn vector_binding_for_snapshot(
        &self,
        snapshot: &IndexSnapshot,
        revision: StoreRevision,
        context: &RetrievalContext,
    ) -> Option<VectorIndexBinding> {
        #[cfg(target_os = "macos")]
        if let Some(runtime) = &self.local_vector {
            return runtime.rebuild(snapshot, revision, &self.manager, context);
        }
        let _ = (snapshot, revision, context);
        None
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
        let durable_target = self
            .catalog_outbox()?
            .last()
            .map_or(StoreRevision(0), |record| record.causal_revision);
        let restored_watermark = self.worker.watermark().map_err(retrieval_lifecycle)?;
        Ok(durable_target.max(restored_watermark))
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
        let vector_binding = self.vector_binding(next.causal_revision, &context)?;
        let receipt = self
            .worker
            .process(
                &[next],
                self,
                &self.manager,
                self.configuration_digest.clone(),
                vector_binding,
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
        AuthorityClock, AuthorityError, DaemonTelemetry, ProductionDomainMaintenance,
        ProductionIndexTarget, ProductionTenantProvider,
    };
    use cigar_catalog::CatalogAtomService;
    use cigar_policy::{CompiledPolicyEngine, PolicyProfile, PolicyRequest, PolicyResource};
    use cigar_protocol::{
        ContentDigest, ContextAtomV1, IdempotencyKey, Lifecycle, RecordId, UtcTimestamp,
    };
    use cigar_retrieval::{
        AuthorizedPartition, InMemoryIndexManager, IndexWorker, RetrievalConsistency,
        RetrievalContext, RetrievalRequest, RetrievalStage, Retriever,
    };
    use cigar_store::{
        AccessContext, CancellationToken, OutboxMessage, Repository, SqliteStore, StoreRevision,
        WriteTransaction,
    };
    use cigar_testkit::deterministic_protocol_fixture;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

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

    fn retrieval_policy(atom: &ContextAtomV1) -> Result<Arc<CompiledPolicyEngine>, Box<dyn Error>> {
        let policy = Arc::new(CompiledPolicyEngine::default());
        policy.install(
            PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            },
            atom.temporal.observed_at,
        )?;
        Ok(policy)
    }

    fn authorized_partition_at(
        policy: &Arc<CompiledPolicyEngine>,
        atom: &ContextAtomV1,
        instant: UtcTimestamp,
    ) -> Result<AuthorizedPartition, Box<dyn Error>> {
        let [project_id] = atom.scope.project_ids.as_slice() else {
            return Err("production index fixture must have exactly one project".into());
        };
        let expires_at = UtcTimestamp::from_unix_nanos(
            instant
                .unix_nanos()
                .checked_add(600_000_000_000)
                .ok_or("authorization expiry overflow")?,
        )?;
        let authorization = policy.authorize_retrieval_partition(&[PolicyRequest {
            resource: PolicyResource::Partition,
            input_digest: atom.content_digest.clone(),
            principal_id: record(99)?,
            principal_active: true,
            tenant_id: atom.scope.tenant_id.clone(),
            authenticated_tenant_id: atom.scope.tenant_id.clone(),
            project_id: Some(project_id.clone()),
            allowed_project_ids: BTreeSet::from([project_id.clone()]),
            purpose: "coding".to_owned(),
            allowed_purposes: atom.governance.allowed_purposes.iter().cloned().collect(),
            processor: Some("local".to_owned()),
            allowed_processors: BTreeSet::from(["local".to_owned()]),
            classification: atom.governance.classification,
            maximum_classification: atom.governance.classification,
            residency_allowed: true,
            egress_allowed: true,
            lifecycle: Lifecycle::Active,
            integrity_verified: true,
            valid_at: instant,
            valid_from: atom.temporal.valid_from,
            valid_until: Some(expires_at),
            observed_at: instant,
            observed_as_of: instant,
            freshness_expires_at: None,
            instruction_authority: atom.governance.instruction_authority,
            maximum_instruction_authority: atom.governance.instruction_authority,
            excluded: false,
            modality_supported: true,
            capability: None,
            required_capability: None,
            bound_policy_digest: None,
            effect_risk: None,
            effect_approved: false,
            effect_constraints_satisfied: true,
            fencing_required: false,
            fencing_verified: false,
            decision_expires_at: expires_at,
        }])?;
        Ok(AuthorizedPartition::from_policy_authorization(
            authorization,
        )?)
    }

    fn lineage_request(
        partition: AuthorizedPartition,
        atom: &ContextAtomV1,
        revision: StoreRevision,
    ) -> RetrievalRequest {
        RetrievalRequest {
            stage: RetrievalStage::Exact,
            partition,
            required_revision: revision,
            consistency: RetrievalConsistency::Strong,
            atom_kinds: BTreeSet::new(),
            exact_versions: BTreeSet::new(),
            atom_ids: BTreeSet::new(),
            lineage_ids: BTreeSet::from([atom.lineage_id.clone()]),
            content_digests: BTreeSet::new(),
            canonical_uris: BTreeSet::new(),
            source_revisions: BTreeSet::new(),
            paths: BTreeSet::new(),
            terms: BTreeSet::new(),
            approved_vector: None,
            graph_roots: BTreeSet::new(),
            graph_depth: 0,
            limit: 10,
            allow_fallback: false,
        }
    }

    fn retrieval_context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(10),
        }
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
        let policy = retrieval_policy(&fixture)?;
        let historical_partition = authorized_partition_at(
            &policy,
            &fixture,
            UtcTimestamp::parse_rfc3339("2027-07-11T11:59:59Z")?,
        )?;
        let current_partition = authorized_partition_at(
            &policy,
            &fixture,
            UtcTimestamp::parse_rfc3339("2027-07-11T12:00:01Z")?,
        )?;

        let telemetry = Arc::new(DaemonTelemetry::local());
        let first =
            coordinator(Arc::clone(&store), tenant.clone())?.with_telemetry(Arc::clone(&telemetry));
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
        let active_root = active.semantic_root;
        assert_eq!(first.worker().watermark()?, StoreRevision(1));
        assert_eq!(
            first
                .manager()
                .retrieve(
                    &lineage_request(current_partition.clone(), &fixture, revision),
                    &retrieval_context(),
                )?
                .candidates
                .len(),
            1
        );
        first.rebuild()?;
        assert_eq!(first.worker().watermark()?, StoreRevision(1));
        assert!(
            telemetry
                .render_openmetrics(&[])
                .lines()
                .any(|line| line == "cigar_invalidation_fanout_total 1")
        );

        let second_revision = CatalogAtomService
            .tombstone_atom(
                store.as_ref(),
                AccessContext::new(tenant.clone(), "test.index")?,
                revision,
                IdempotencyKey::new("production-index-tombstone")?,
                fixture.atom_id.clone(),
                UtcTimestamp::parse_rfc3339("2027-07-11T12:00:00Z")?,
                record(11)?,
                CancellationToken::default(),
            )?
            .revision;
        assert_eq!(second_revision, StoreRevision(2));
        assert!(first.verify_worker_cursors().is_err());
        first.rebuild()?;
        assert_eq!(first.worker().watermark()?, StoreRevision(2));
        assert!(
            telemetry
                .render_openmetrics(&[])
                .lines()
                .any(|line| line == "cigar_invalidation_fanout_total 2")
        );
        assert_ne!(
            first
                .manager()
                .active_generation()?
                .ok_or("missing tombstone generation")?
                .semantic_root,
            active_root
        );
        assert!(
            first
                .manager()
                .retrieve(
                    &lineage_request(current_partition.clone(), &fixture, second_revision),
                    &retrieval_context(),
                )?
                .candidates
                .is_empty()
        );
        assert_eq!(
            first
                .manager()
                .retrieve(
                    &lineage_request(historical_partition.clone(), &fixture, second_revision,),
                    &retrieval_context(),
                )?
                .candidates
                .len(),
            1
        );

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
        assert!(
            restarted
                .manager()
                .retrieve(
                    &lineage_request(current_partition, &fixture, second_revision),
                    &retrieval_context(),
                )?
                .candidates
                .is_empty()
        );
        assert_eq!(
            restarted
                .manager()
                .retrieve(
                    &lineage_request(historical_partition, &fixture, second_revision),
                    &retrieval_context(),
                )?
                .candidates
                .len(),
            1
        );
        assert!(restarted.verify_worker_cursors().is_ok());
        Ok(())
    }
}
