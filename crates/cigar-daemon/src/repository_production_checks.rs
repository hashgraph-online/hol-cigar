//! Concrete fail-closed production dependency checks over durable repository primitives.

use crate::{
    ApplicationIdGenerator, AuthorityClock, EffectWorkerOutcome, EffectWorkerProcessor,
    LifecycleError, ProductionDependencyChecks, ProductionStore, WorkerJob, WorkerKind,
};
use cigar_api::TenantId;
use cigar_crypto::{KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, KeyStatus};
use cigar_effects::{
    DurableEffectRecord, EffectEngine, EffectOutboxState, EffectRecordAuthenticator,
};
use cigar_policy::{PolicyEngine, PolicySnapshot};
use cigar_protocol::{
    BlobRef, ContentDigest, EffectState, ExpectedRevision, MediaType, RecordId, UtcTimestamp,
};
use cigar_retrieval::{InMemoryIndexManager, IndexGenerationState, IndexKind, IndexWorker};
use cigar_store::{
    AccessContext, BlobRecord, CancellationToken, EffectRecoveryQuery, OutboxRecoveryQuery,
    ServiceRepository, StoreRevision,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

const EFFECT_RECOVERY_PAGE_SIZE: usize = 1_000;
const MAX_REQUIRED_KEYS: usize = 1_024;
const MAX_CONFIGURED_TENANTS: usize = 100_000;
const MAX_CONFIGURED_EFFECTS: usize = 1_000_000;
const JOURNAL_CHECK_PURPOSE: &str = "daemon.journal-integrity";

/// Authoritative bounded enumeration of every tenant that may own durable effect records.
///
/// `ServiceRepository` intentionally exposes tenant-scoped scans only. Production composition
/// must therefore inject the identity/catalog boundary that owns complete tenant enumeration.
pub trait ProductionTenantProvider: Send + Sync {
    /// Returns every active tenant in strictly ascending identity order.
    fn active_tenants(&self) -> Result<Vec<RecordId>, LifecycleError>;
}

/// Authoritative current catalog revision against which mandatory index lag is measured.
///
/// A generic repository revision is not a valid substitute because unrelated service and effect
/// commits also advance it.
pub trait ProductionIndexTarget: Send + Sync {
    /// Returns the greatest catalog causal revision that the mandatory index must represent.
    fn target_revision(&self) -> Result<StoreRevision, LifecycleError>;
}

/// Required domain-maintenance processors not represented by generic repository operations.
///
/// There is deliberately no healthy default implementation. Production startup must bind the
/// real lease, cursor, checkpoint, and worker processors for every domain.
pub trait ProductionDomainMaintenance: Send + Sync {
    /// Expires domain/effect/space renewable leases after exact fence and time checks.
    fn cleanup_expired_leases(&self) -> Result<(), LifecycleError>;
    /// Verifies every domain worker and event cursor is authentic, scoped, and in range.
    fn verify_worker_cursors(&self) -> Result<(), LifecycleError>;
    /// Persists every domain worker cursor beyond daemon wakeup bookkeeping.
    fn checkpoint_workers(&self) -> Result<(), LifecycleError>;
    /// Releases renewable domain leases without changing effect truth.
    fn release_renewable_leases(&self) -> Result<(), LifecycleError>;
    /// Processes one exact durable worker wakeup.
    fn process_worker_job(&self, kind: WorkerKind, job: &WorkerJob) -> Result<(), LifecycleError>;
    /// Processes at most one durable non-effect item, returning true only on durable progress.
    fn poll_durable_work(&self) -> Result<bool, LifecycleError>;
}

/// One exact production key that readiness must resolve as active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionKeyRequirement {
    /// Opaque provider reference.
    pub key_ref: KeyRef,
    /// Exact owning tenant selector.
    pub tenant: String,
    /// Non-interchangeable required purpose.
    pub purpose: KeyPurpose,
    /// Required algorithm for this deployment role.
    pub algorithm: KeyAlgorithm,
}

/// Stable construction failure for repository production checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryProductionChecksBuildError {
    /// A bound, expected snapshot, or key requirement was incomplete or unsafe.
    InvalidConfiguration,
}

impl fmt::Display for RepositoryProductionChecksBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repository production checks configuration is incomplete")
    }
}

impl std::error::Error for RepositoryProductionChecksBuildError {}

/// Complete explicit dependencies for repository-backed production checks.
pub struct RepositoryProductionChecksDependencies {
    /// Selected production repository composed with the exact production blob adapter.
    pub store: Arc<ProductionStore>,
    /// Current compiled policy boundary.
    pub policy: Arc<dyn PolicyEngine>,
    /// Exact policy snapshot expected by this running deployment.
    pub expected_policy_snapshot: PolicySnapshot,
    /// Mandatory index worker whose activation-backed watermark is checked.
    pub index_worker: Arc<IndexWorker>,
    /// Mandatory active generation manager.
    pub index_manager: Arc<InMemoryIndexManager>,
    /// Current authoritative catalog watermark provider.
    pub index_target: Arc<dyn ProductionIndexTarget>,
    /// Greatest permitted mandatory-index lag in catalog revisions.
    pub max_index_lag_revisions: u64,
    /// Current scoped key provider.
    pub key_provider: Arc<dyn KeyProvider>,
    /// Every key role required for this process to serve safely.
    pub required_keys: Vec<ProductionKeyRequirement>,
    /// Complete authoritative tenant enumeration.
    pub tenants: Arc<dyn ProductionTenantProvider>,
    /// Required real domain maintenance and worker processors.
    pub maintenance: Arc<dyn ProductionDomainMaintenance>,
    /// Real effect outbox and reconciliation processor.
    pub effect_workers: Arc<EffectWorkerProcessor<ProductionStore>>,
    /// Trusted semantic wall clock.
    pub clock: Arc<dyn AuthorityClock>,
    /// Server-owned recovery event identity source.
    pub ids: Arc<dyn ApplicationIdGenerator>,
    /// Required system tenant, which must occur in every tenant enumeration.
    pub system_tenant: RecordId,
    /// Stable server actor recorded on restart-recovery transitions.
    pub recovery_actor: RecordId,
    /// Dedicated tenant scope reserved for non-metadata blob probes.
    pub blob_probe_tenant: RecordId,
    /// Hard ceiling on one authoritative tenant scan.
    pub max_tenants: usize,
    /// Hard ceiling on complete effect records checked or recovered in one pass.
    pub max_effect_records: usize,
}

/// Concrete repository-backed implementation of every production dependency check.
pub struct RepositoryProductionDependencyChecks {
    store: Arc<ProductionStore>,
    policy: Arc<dyn PolicyEngine>,
    expected_policy_snapshot: PolicySnapshot,
    index_worker: Arc<IndexWorker>,
    index_manager: Arc<InMemoryIndexManager>,
    index_target: Arc<dyn ProductionIndexTarget>,
    max_index_lag_revisions: u64,
    key_provider: Arc<dyn KeyProvider>,
    required_keys: Vec<ProductionKeyRequirement>,
    tenants: Arc<dyn ProductionTenantProvider>,
    maintenance: Arc<dyn ProductionDomainMaintenance>,
    effect_workers: Arc<EffectWorkerProcessor<ProductionStore>>,
    effect_authenticator: Option<Arc<dyn EffectRecordAuthenticator>>,
    clock: Arc<dyn AuthorityClock>,
    ids: Arc<dyn ApplicationIdGenerator>,
    system_tenant: RecordId,
    recovery_actor: RecordId,
    blob_probe_tenant: RecordId,
    max_tenants: usize,
    max_effect_records: usize,
}

impl fmt::Debug for RepositoryProductionDependencyChecks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryProductionDependencyChecks")
            .field("store", &self.store)
            .field("required_key_count", &self.required_keys.len())
            .field("max_index_lag_revisions", &self.max_index_lag_revisions)
            .field("max_tenants", &self.max_tenants)
            .field("max_effect_records", &self.max_effect_records)
            .finish_non_exhaustive()
    }
}

impl RepositoryProductionDependencyChecks {
    /// Validates and constructs a check set with no implicit healthy dependencies.
    pub fn new(
        dependencies: RepositoryProductionChecksDependencies,
    ) -> Result<Self, RepositoryProductionChecksBuildError> {
        Self::build(dependencies, None)
    }

    /// Constructs production checks with the same tenant-key effect authenticator as API workers.
    pub fn new_with_effect_authenticator(
        dependencies: RepositoryProductionChecksDependencies,
        effect_authenticator: Arc<dyn EffectRecordAuthenticator>,
    ) -> Result<Self, RepositoryProductionChecksBuildError> {
        Self::build(dependencies, Some(effect_authenticator))
    }

    fn build(
        dependencies: RepositoryProductionChecksDependencies,
        effect_authenticator: Option<Arc<dyn EffectRecordAuthenticator>>,
    ) -> Result<Self, RepositoryProductionChecksBuildError> {
        if !dependencies.expected_policy_snapshot.protected
            || dependencies.expected_policy_snapshot.revision == 0
            || dependencies.required_keys.is_empty()
            || dependencies.required_keys.len() > MAX_REQUIRED_KEYS
            || dependencies.max_tenants == 0
            || dependencies.max_tenants > MAX_CONFIGURED_TENANTS
            || dependencies.max_effect_records == 0
            || dependencies.max_effect_records > MAX_CONFIGURED_EFFECTS
            || dependencies.required_keys.iter().any(|requirement| {
                requirement.tenant.is_empty()
                    || requirement.tenant.len() > 256
                    || requirement
                        .tenant
                        .bytes()
                        .any(|byte| byte.is_ascii_control())
            })
        {
            return Err(RepositoryProductionChecksBuildError::InvalidConfiguration);
        }
        Ok(Self {
            store: dependencies.store,
            policy: dependencies.policy,
            expected_policy_snapshot: dependencies.expected_policy_snapshot,
            index_worker: dependencies.index_worker,
            index_manager: dependencies.index_manager,
            index_target: dependencies.index_target,
            max_index_lag_revisions: dependencies.max_index_lag_revisions,
            key_provider: dependencies.key_provider,
            required_keys: dependencies.required_keys,
            tenants: dependencies.tenants,
            maintenance: dependencies.maintenance,
            effect_workers: dependencies.effect_workers,
            effect_authenticator,
            clock: dependencies.clock,
            ids: dependencies.ids,
            system_tenant: dependencies.system_tenant,
            recovery_actor: dependencies.recovery_actor,
            blob_probe_tenant: dependencies.blob_probe_tenant,
            max_tenants: dependencies.max_tenants,
            max_effect_records: dependencies.max_effect_records,
        })
    }

    fn now(&self) -> Result<UtcTimestamp, LifecycleError> {
        self.clock
            .now()
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn active_tenants(&self) -> Result<Vec<RecordId>, LifecycleError> {
        let tenants = self.tenants.active_tenants()?;
        if tenants.is_empty()
            || tenants.len() > self.max_tenants
            || tenants.windows(2).any(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .is_some_and(|(left, right)| left >= right)
            })
            || tenants.binary_search(&self.system_tenant).is_err()
        {
            return Err(LifecycleError::action_failed());
        }
        Ok(tenants)
    }

    fn effect_engine(
        &self,
        tenant_id: RecordId,
    ) -> Result<EffectEngine<ProductionStore>, LifecycleError> {
        let access = AccessContext::new(tenant_id, JOURNAL_CHECK_PURPOSE)
            .map_err(|_error| LifecycleError::action_failed())?;
        Ok(match &self.effect_authenticator {
            Some(authenticator) => EffectEngine::new_with_authenticator(
                Arc::clone(&self.store),
                access,
                Arc::clone(authenticator),
            ),
            None => EffectEngine::new(Arc::clone(&self.store), access),
        })
    }

    fn for_each_effect<F>(&self, mut visit: F) -> Result<(), LifecycleError>
    where
        F: FnMut(
            &EffectEngine<ProductionStore>,
            &cigar_store::EffectRecoveryItem,
            StoreRevision,
        ) -> Result<(), LifecycleError>,
    {
        let mut total = 0_usize;
        for tenant_id in self.active_tenants()? {
            let engine = self.effect_engine(tenant_id.clone())?;
            let mut cursor = None;
            loop {
                let query =
                    EffectRecoveryQuery::new(tenant_id.clone(), EFFECT_RECOVERY_PAGE_SIZE, cursor)
                        .map_err(|_error| LifecycleError::action_failed())?;
                let page = self
                    .store
                    .effect_recovery(&query, &CancellationToken::default())
                    .map_err(|_error| LifecycleError::action_failed())?;
                total = total
                    .checked_add(page.items.len())
                    .ok_or_else(LifecycleError::action_failed)?;
                if total > self.max_effect_records {
                    return Err(LifecycleError::action_failed());
                }
                for item in &page.items {
                    visit(&engine, item, page.revision)?;
                }
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn tenant_effect_records(
        &self,
        tenant_id: &RecordId,
        total: &mut usize,
    ) -> Result<Vec<DurableEffectRecord>, LifecycleError> {
        let engine = self.effect_engine(tenant_id.clone())?;
        let mut records = Vec::new();
        let mut cursor = None;
        loop {
            let query =
                EffectRecoveryQuery::new(tenant_id.clone(), EFFECT_RECOVERY_PAGE_SIZE, cursor)
                    .map_err(|_error| LifecycleError::action_failed())?;
            let page = self
                .store
                .effect_recovery(&query, &CancellationToken::default())
                .map_err(|_error| LifecycleError::action_failed())?;
            *total = total
                .checked_add(page.items.len())
                .ok_or_else(LifecycleError::action_failed)?;
            if *total > self.max_effect_records {
                return Err(LifecycleError::action_failed());
            }
            for item in page.items {
                let record = engine
                    .get_at_revision(&item.record.effect_id, page.revision)
                    .map_err(|_error| LifecycleError::action_failed())?;
                records.push(record);
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(records)
    }

    fn tenant_effect_outbox(
        &self,
        tenant_id: &RecordId,
        total: &mut usize,
    ) -> Result<BTreeMap<RecordId, ContentDigest>, LifecycleError> {
        let mut messages = BTreeMap::new();
        let mut cursor = None;
        loop {
            let query =
                OutboxRecoveryQuery::new(tenant_id.clone(), EFFECT_RECOVERY_PAGE_SIZE, cursor)
                    .map_err(|_error| LifecycleError::action_failed())?;
            let page = self
                .store
                .outbox_recovery(&query, &CancellationToken::default())
                .map_err(|_error| LifecycleError::action_failed())?;
            *total = total
                .checked_add(page.items.len())
                .ok_or_else(LifecycleError::action_failed)?;
            if *total > self.max_effect_records {
                return Err(LifecycleError::action_failed());
            }
            for item in page.items {
                if item.message.topic == "effect.dispatch.v1"
                    && messages
                        .insert(item.message.message_id, item.message.payload_digest)
                        .is_some()
                {
                    return Err(LifecycleError::action_failed());
                }
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(messages)
    }

    fn next_effect_worker_job(&self) -> Result<Option<(WorkerKind, WorkerJob)>, LifecycleError> {
        if !self.effect_workers.work_admission_allowed() {
            return Ok(None);
        }
        let now = self.now()?;
        let mut effect_total = 0_usize;
        let mut outbox_total = 0_usize;
        let mut reconciliation = None;
        for tenant_id in self.active_tenants()? {
            let records = self.tenant_effect_records(&tenant_id, &mut effect_total)?;
            let messages = self.tenant_effect_outbox(&tenant_id, &mut outbox_total)?;
            for record in records {
                if record.state == EffectState::Dispatching {
                    let outbox = record
                        .outbox
                        .as_ref()
                        .ok_or_else(LifecycleError::action_failed)?;
                    if outbox.state != EffectOutboxState::Claimed
                        || messages.get(&outbox.message_id) != Some(&record.intent_digest)
                    {
                        return Err(LifecycleError::action_failed());
                    }
                    return Ok(Some((
                        WorkerKind::Outbox,
                        effect_worker_job(&tenant_id, &record)?,
                    )));
                }
                if reconciliation.is_none()
                    && record.state == EffectState::Unknown
                    && EffectWorkerProcessor::<ProductionStore>::reconciliation_due(&record, now)
                    && self.effect_workers.reconciliation_supported(&record)
                {
                    reconciliation = Some((
                        WorkerKind::Reconciliation,
                        effect_worker_job(&tenant_id, &record)?,
                    ));
                }
            }
        }
        Ok(reconciliation)
    }
}

fn effect_worker_job(
    tenant_id: &RecordId,
    record: &DurableEffectRecord,
) -> Result<WorkerJob, LifecycleError> {
    Ok(WorkerJob {
        tenant: TenantId::new(tenant_id.as_str())
            .map_err(|_error| LifecycleError::action_failed())?,
        record_id: record.intent.effect_id.clone(),
        expected_revision: Some(ExpectedRevision(record.effect_version)),
    })
}

impl ProductionDependencyChecks for RepositoryProductionDependencyChecks {
    fn migration_level(&self) -> Result<(), LifecycleError> {
        self.store
            .verify_migration_level()
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn blob_read_write(&self) -> Result<(), LifecycleError> {
        let mut bytes = [0_u8; 64];
        getrandom::fill(&mut bytes).map_err(|_error| LifecycleError::action_failed())?;
        let digest = multihash(&bytes)?;
        let reference = BlobRef {
            digest,
            size_bytes: u64::try_from(bytes.len())
                .map_err(|_error| LifecycleError::action_failed())?,
            media_type: MediaType::new("application/octet-stream")
                .map_err(|_error| LifecycleError::action_failed())?,
        };
        let blob = BlobRecord::new(reference, bytes.to_vec())
            .map_err(|_error| LifecycleError::action_failed())?;
        self.store
            .blob_readiness_probe(&self.blob_probe_tenant, &blob)
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn policy_snapshot(&self) -> Result<(), LifecycleError> {
        let snapshot = self
            .policy
            .snapshot()
            .map_err(|_error| LifecycleError::action_failed())?;
        if snapshot == self.expected_policy_snapshot {
            Ok(())
        } else {
            Err(LifecycleError::action_failed())
        }
    }

    fn journal_integrity(&self) -> Result<(), LifecycleError> {
        self.for_each_effect(|engine, item, revision| {
            let record = engine
                .get_at_revision(&item.record.effect_id, revision)
                .map_err(|_error| LifecycleError::action_failed())?;
            if record.effect_version != item.record.effect_version
                || record.journal.last() != item.latest_event.as_ref()
            {
                return Err(LifecycleError::action_failed());
            }
            Ok(())
        })
    }

    fn mandatory_index(&self) -> Result<(), LifecycleError> {
        let target = self.index_target.target_revision()?;
        let watermark = self
            .index_worker
            .watermark()
            .map_err(|_error| LifecycleError::action_failed())?;
        let active = self
            .index_manager
            .active_generation()
            .map_err(|_error| LifecycleError::action_failed())?
            .ok_or_else(LifecycleError::action_failed)?;
        let required_projections = [
            IndexKind::Exact,
            IndexKind::Scope,
            IndexKind::Path,
            IndexKind::Symbol,
            IndexKind::Entity,
            IndexKind::Temporal,
            IndexKind::Authority,
            IndexKind::Lexical,
            IndexKind::Graph,
            IndexKind::ActiveState,
        ];
        let lag = target
            .0
            .checked_sub(active.built_through_revision.0)
            .ok_or_else(LifecycleError::action_failed)?;
        if active.state != IndexGenerationState::Active
            || watermark != active.built_through_revision
            || lag > self.max_index_lag_revisions
            || required_projections
                .iter()
                .any(|projection| !active.projections.contains(projection))
        {
            return Err(LifecycleError::action_failed());
        }
        Ok(())
    }

    fn key_provider(&self) -> Result<(), LifecycleError> {
        let now = self.now()?.unix_nanos();
        for requirement in &self.required_keys {
            let metadata = self
                .key_provider
                .resolve(
                    &requirement.key_ref,
                    &requirement.tenant,
                    requirement.purpose,
                    now,
                )
                .map_err(|_error| LifecycleError::action_failed())?;
            if metadata.key_ref != requirement.key_ref
                || metadata.tenant != requirement.tenant
                || metadata.purpose != requirement.purpose
                || metadata.algorithm != requirement.algorithm
                || metadata.status != KeyStatus::Active
                || metadata.activated_at > now
                || metadata.deactivated_at.is_some()
            {
                return Err(LifecycleError::action_failed());
            }
        }
        Ok(())
    }

    fn reconcile_orphan_blobs(&self) -> Result<(), LifecycleError> {
        let tenants = self.active_tenants()?;
        self.store
            .reconcile_blob_roots(&tenants)
            .map_err(|_error| LifecycleError::action_failed())
    }

    fn cleanup_expired_leases(&self) -> Result<(), LifecycleError> {
        self.maintenance.cleanup_expired_leases()
    }

    fn verify_worker_cursors(&self) -> Result<(), LifecycleError> {
        self.maintenance.verify_worker_cursors()
    }

    fn recover_unreceipted_dispatches(&self) -> Result<(), LifecycleError> {
        let now = self.now()?;
        self.for_each_effect(|engine, item, _revision| {
            let current = engine
                .get(&item.record.effect_id)
                .map_err(|_error| LifecycleError::action_failed())?;
            if current.state != EffectState::Dispatching {
                return Ok(());
            }
            let event_id = self
                .ids
                .generate()
                .map_err(|_error| LifecycleError::action_failed())?;
            let evidence = recovery_evidence(&current.intent.effect_id, current.effect_version)?;
            engine
                .recover_inflight(
                    &current.intent.effect_id,
                    current.effect_version,
                    event_id,
                    self.recovery_actor.clone(),
                    now,
                    evidence,
                )
                .map(|_record| ())
                .map_err(|_error| LifecycleError::action_failed())
        })
    }

    fn checkpoint_workers(&self) -> Result<(), LifecycleError> {
        self.maintenance.checkpoint_workers()
    }

    fn release_renewable_leases(&self) -> Result<(), LifecycleError> {
        self.maintenance.release_renewable_leases()
    }

    fn process_worker_job(&self, kind: WorkerKind, job: &WorkerJob) -> Result<(), LifecycleError> {
        if matches!(kind, WorkerKind::Outbox | WorkerKind::Reconciliation) {
            self.effect_workers
                .process_job(kind, job)
                .map(|_outcome| ())
                .map_err(|_error| LifecycleError::action_failed())
        } else {
            self.maintenance.process_worker_job(kind, job)
        }
    }

    fn poll_durable_work(&self) -> Result<bool, LifecycleError> {
        if let Some((kind, job)) = self.next_effect_worker_job()? {
            match self
                .effect_workers
                .process_job(kind, &job)
                .map_err(|_error| LifecycleError::action_failed())?
            {
                EffectWorkerOutcome::Advanced => return Ok(true),
                EffectWorkerOutcome::AlreadyComplete | EffectWorkerOutcome::Deferred => {}
            }
        }
        self.maintenance.poll_durable_work()
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

fn recovery_evidence(
    effect_id: &RecordId,
    effect_version: u64,
) -> Result<ContentDigest, LifecycleError> {
    let mut digest = Sha256::new();
    digest.update(b"CIGAR-EFFECT-RESTART-RECOVERY\0v1\0");
    digest.update(effect_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(effect_version.to_be_bytes());
    multihash(&digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::{
        ProductionDomainMaintenance, ProductionIndexTarget, ProductionKeyRequirement,
        ProductionTenantProvider, RepositoryProductionChecksDependencies,
        RepositoryProductionDependencyChecks,
    };
    use crate::production_effects::{EffectArgumentVault, EffectArgumentVaultError};
    use crate::{
        ApplicationIdError, ApplicationIdGenerator, AuthorityClock, AuthorityError,
        EffectDispatchGate, EffectWorkerAction, EffectWorkerAuthority, EffectWorkerAuthorityError,
        EffectWorkerProcessor, EffectWorkerProcessorDependencies, LifecycleError,
        ProductionDependencyChecks, WorkerJob, WorkerKind,
    };
    use cigar_crypto::{
        CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider,
    };
    use cigar_effects::{
        ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation,
        EffectAuthorization, EffectConnector, EffectEngine, EffectError, PreconditionReport,
        ReconcileObservation,
    };
    use cigar_policy::{CompiledPolicyEngine, PolicyEngine, PolicyProfile};
    use cigar_protocol::{
        BlobRef, Capability, ContentDigest, EffectIntent, EffectState, ExtensionMap,
        IdempotencyKey, MediaType, RecordId, RetryPolicy, RiskLevel, SchemaVersion, UtcTimestamp,
        VersionId,
    };
    use cigar_retrieval::{InMemoryIndexManager, IndexBuild, IndexWorker, RetrievalContext};
    use cigar_store::{
        AccessContext, CancellationToken, LocalBlobStore, LocalRepositoryBlobStore,
        RepositoryBlobStore, SqliteStore, StoreRevision,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(value: u64) -> Result<ContentDigest, Box<dyn Error>> {
        let hash = Sha256::digest(value.to_be_bytes());
        let mut encoded = String::from("1220");
        for byte in hash {
            write!(&mut encoded, "{byte:02x}")?;
        }
        Ok(ContentDigest::new(encoded)?)
    }

    fn time(second: u8) -> Result<UtcTimestamp, Box<dyn Error>> {
        Ok(UtcTimestamp::parse_rfc3339(&format!(
            "2026-07-11T12:00:{second:02}Z"
        ))?)
    }

    #[derive(Clone)]
    struct FixedClock(UtcTimestamp);

    impl AuthorityClock for FixedClock {
        fn now(&self) -> Result<UtcTimestamp, AuthorityError> {
            Ok(self.0)
        }

        fn unix_seconds(&self) -> Result<i64, AuthorityError> {
            i64::try_from(self.0.unix_nanos() / 1_000_000_000)
                .map_err(|_error| AuthorityError::InvalidClock)
        }
    }

    #[derive(Default)]
    struct SequentialIds(AtomicU64);

    impl ApplicationIdGenerator for SequentialIds {
        fn generate(&self) -> Result<RecordId, ApplicationIdError> {
            let next = self
                .0
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(500_000);
            RecordId::new(format!("01890f47-8e7d-7b42-a1d2-{next:012x}"))
                .map_err(|_error| ApplicationIdError)
        }
    }

    struct Tenants(Mutex<Vec<RecordId>>);

    impl ProductionTenantProvider for Tenants {
        fn active_tenants(&self) -> Result<Vec<RecordId>, LifecycleError> {
            self.0
                .lock()
                .map(|tenants| tenants.clone())
                .map_err(|_error| LifecycleError::action_failed())
        }
    }

    #[derive(Default)]
    struct IndexTarget(AtomicU64);

    impl ProductionIndexTarget for IndexTarget {
        fn target_revision(&self) -> Result<StoreRevision, LifecycleError> {
            Ok(StoreRevision(self.0.load(Ordering::Acquire)))
        }
    }

    #[derive(Default)]
    struct Maintenance {
        cleanup: AtomicUsize,
        cursors: AtomicUsize,
        checkpoints: AtomicUsize,
        releases: AtomicUsize,
        jobs: AtomicUsize,
    }

    impl ProductionDomainMaintenance for Maintenance {
        fn cleanup_expired_leases(&self) -> Result<(), LifecycleError> {
            self.cleanup.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn verify_worker_cursors(&self) -> Result<(), LifecycleError> {
            self.cursors.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn checkpoint_workers(&self) -> Result<(), LifecycleError> {
            self.checkpoints.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn release_renewable_leases(&self) -> Result<(), LifecycleError> {
            self.releases.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn process_worker_job(
            &self,
            _kind: WorkerKind,
            _job: &WorkerJob,
        ) -> Result<(), LifecycleError> {
            self.jobs.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn poll_durable_work(&self) -> Result<bool, LifecycleError> {
            Ok(false)
        }
    }

    struct OpenGate;

    impl EffectDispatchGate for OpenGate {
        fn dispatch_claims_allowed(&self) -> bool {
            true
        }
    }

    struct OpenArgumentVault;

    impl EffectArgumentVault for OpenArgumentVault {
        fn validate(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            Ok(())
        }

        fn stage(
            &self,
            _tenant: &RecordId,
            _intent: &EffectIntent,
        ) -> Result<(), EffectArgumentVaultError> {
            Ok(())
        }
    }

    struct WorkerAuthority {
        actor: RecordId,
    }

    impl EffectWorkerAuthority for WorkerAuthority {
        fn authorize(
            &self,
            _tenant_id: &RecordId,
            _action: EffectWorkerAction,
            _record: &cigar_effects::DurableEffectRecord,
            now: UtcTimestamp,
        ) -> Result<EffectAuthorization, EffectWorkerAuthorityError> {
            Ok(EffectAuthorization {
                actor_id: self.actor.clone(),
                capabilities: [
                    Capability::ProposeEffect,
                    Capability::ApproveEffect,
                    Capability::InvokeTool,
                    Capability::ReconcileEffect,
                ]
                .into_iter()
                .collect(),
                policy_allows: true,
                now,
            })
        }
    }

    struct Fixture {
        _temp: TempDir,
        store: Arc<crate::ProductionStore>,
        checks: RepositoryProductionDependencyChecks,
        tenant_provider: Arc<Tenants>,
        index_target: Arc<IndexTarget>,
        policy: Arc<CompiledPolicyEngine>,
        maintenance: Arc<Maintenance>,
        connector_calls: Arc<AtomicUsize>,
        tenant: RecordId,
        blob_root: std::path::PathBuf,
    }

    fn fixture() -> Result<Fixture, Box<dyn Error>> {
        let temp = tempfile::tempdir()?;
        let tenant = record(1)?;
        let blob_probe_tenant = tenant.clone();
        let now = time(10)?;

        let keys = Arc::new(MemoryKeyProvider::default());
        let wrapping_key = keys.create(CreateKeyRequest {
            tenant: tenant.as_str().to_owned(),
            purpose: KeyPurpose::BlobEncryption,
            algorithm: KeyAlgorithm::XChaCha20Poly1305,
            created_at: time(1)?.unix_nanos(),
            activated_at: time(1)?.unix_nanos(),
        })?;
        let blob_root = temp.path().join("blobs");
        let local = LocalBlobStore::open(&blob_root, Arc::clone(&keys))?;
        let blobs: Arc<dyn RepositoryBlobStore> = Arc::new(LocalRepositoryBlobStore::new(
            local,
            wrapping_key.key_ref.clone(),
            now.unix_nanos(),
        ));
        let store = Arc::new(crate::ProductionStore::local(
            SqliteStore::open_with_blob_repository(temp.path().join("state.sqlite"), blobs)?,
        ));

        let policy = Arc::new(CompiledPolicyEngine::default());
        let expected_policy_snapshot = policy.install(
            PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 1,
                protected: true,
                rules: Vec::new(),
            },
            time(1)?,
        )?;

        let index_manager = Arc::new(InMemoryIndexManager::default());
        let retrieval = RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let staged = index_manager.build_generation(
            IndexBuild {
                atoms: Vec::new(),
                edges: Vec::new(),
                built_through_revision: StoreRevision(0),
                configuration_digest: digest(10)?,
                verified_at: now,
                vector_fingerprint: None,
            },
            &retrieval,
        )?;
        index_manager.activate(&staged.generation_id, None)?;

        let tenant_provider = Arc::new(Tenants(Mutex::new(vec![tenant.clone()])));
        let index_target = Arc::new(IndexTarget::default());
        let maintenance = Arc::new(Maintenance::default());
        let clock = Arc::new(FixedClock(now));
        let ids = Arc::new(SequentialIds::default());
        let connector_calls = Arc::new(AtomicUsize::new(0));
        let effect_workers = Arc::new(EffectWorkerProcessor::new(
            EffectWorkerProcessorDependencies {
                repository: Arc::clone(&store),
                authority: Arc::new(WorkerAuthority { actor: record(5)? }),
                clock: clock.clone(),
                ids: ids.clone(),
                dispatch_gate: Arc::new(OpenGate),
                argument_vault: Arc::new(OpenArgumentVault),
                connectors: vec![Arc::new(Connector {
                    calls: Arc::clone(&connector_calls),
                })],
            },
        )?);
        let policy_object: Arc<dyn PolicyEngine> = policy.clone();
        let key_object: Arc<dyn KeyProvider> = keys;
        let tenant_object: Arc<dyn ProductionTenantProvider> = tenant_provider.clone();
        let target_object: Arc<dyn ProductionIndexTarget> = index_target.clone();
        let maintenance_object: Arc<dyn ProductionDomainMaintenance> = maintenance.clone();
        let checks =
            RepositoryProductionDependencyChecks::new(RepositoryProductionChecksDependencies {
                store: Arc::clone(&store),
                policy: policy_object,
                expected_policy_snapshot,
                index_worker: Arc::new(IndexWorker::default()),
                index_manager,
                index_target: target_object,
                max_index_lag_revisions: 0,
                key_provider: key_object,
                required_keys: vec![ProductionKeyRequirement {
                    key_ref: wrapping_key.key_ref,
                    tenant: tenant.as_str().to_owned(),
                    purpose: KeyPurpose::BlobEncryption,
                    algorithm: KeyAlgorithm::XChaCha20Poly1305,
                }],
                tenants: tenant_object,
                maintenance: maintenance_object,
                effect_workers,
                clock,
                ids,
                system_tenant: tenant.clone(),
                recovery_actor: record(3)?,
                blob_probe_tenant: blob_probe_tenant.clone(),
                max_tenants: 10,
                max_effect_records: 100,
            })?;
        Ok(Fixture {
            _temp: temp,
            store,
            checks,
            tenant_provider,
            index_target,
            policy,
            maintenance,
            connector_calls,
            tenant,
            blob_root,
        })
    }

    #[test]
    fn concrete_checks_probe_real_dependencies_and_fail_closed_on_drift() -> TestResult {
        let fixture = fixture()?;
        fixture.checks.migration_level()?;
        fixture.checks.blob_read_write()?;
        fixture.checks.blob_read_write()?;
        fixture.checks.policy_snapshot()?;
        fixture.checks.journal_integrity()?;
        fixture.checks.mandatory_index()?;
        fixture.checks.key_provider()?;
        fixture.checks.reconcile_orphan_blobs()?;

        let probe_directory = fixture
            .blob_root
            .join(fixture.tenant.as_str())
            .join("blobs");
        assert_eq!(std::fs::read_dir(probe_directory)?.count(), 0);

        fixture.index_target.0.store(1, Ordering::Release);
        assert!(fixture.checks.mandatory_index().is_err());
        fixture.index_target.0.store(0, Ordering::Release);

        fixture.policy.install(
            PolicyProfile {
                schema_version: "cigar.policy-profile.v1".to_owned(),
                revision: 2,
                protected: true,
                rules: Vec::new(),
            },
            time(11)?,
        )?;
        assert!(fixture.checks.policy_snapshot().is_err());

        *fixture
            .tenant_provider
            .0
            .lock()
            .map_err(|_error| "tenant lock poisoned")? = vec![record(4)?, fixture.tenant];
        assert!(fixture.checks.journal_integrity().is_err());
        Ok(())
    }

    struct Connector {
        calls: Arc<AtomicUsize>,
    }

    impl EffectConnector for Connector {
        fn descriptor(&self) -> ConnectorDescriptor {
            ConnectorDescriptor {
                connector: "test".to_owned(),
                operations: vec![ConnectorOperation {
                    operation: "write".to_owned(),
                    same_key_idempotent: false,
                    supports_reconciliation: true,
                    supports_compensation: false,
                }],
                maximum_dispatch_nanos: 60_000_000_000,
            }
        }

        fn check_preconditions(
            &self,
            _intent: &EffectIntent,
            _now: UtcTimestamp,
        ) -> Result<PreconditionReport, EffectError> {
            Ok(PreconditionReport {
                satisfied: true,
                evidence: BTreeSet::new(),
            })
        }

        fn dispatch(
            &self,
            _context: &DispatchContext<'_>,
        ) -> Result<DispatchObservation, EffectError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Ok(DispatchObservation::Succeeded {
                remote_operation_id: "remote-worker-1".to_owned(),
                response_digest: digest(900).map_err(|_error| {
                    EffectError::new(cigar_effects::EffectErrorCode::Unavailable)
                })?,
                verification_digest: digest(901).map_err(|_error| {
                    EffectError::new(cigar_effects::EffectErrorCode::Unavailable)
                })?,
            })
        }

        fn reconcile(
            &self,
            _context: &DispatchContext<'_>,
        ) -> Result<ReconcileObservation, EffectError> {
            unreachable!("restart recovery must not call a connector")
        }
    }

    fn effect_intent(effect_id: RecordId) -> Result<EffectIntent, Box<dyn Error>> {
        Ok(EffectIntent {
            schema_version: SchemaVersion::new("cigar.effect-intent", 1)?,
            effect_id,
            connector: "test".to_owned(),
            operation: "write".to_owned(),
            arguments_digest: digest(100)?,
            encrypted_arguments: BlobRef {
                digest: digest(101)?,
                size_bytes: 64,
                media_type: MediaType::new("application/octet-stream")?,
            },
            target: "target".to_owned(),
            preconditions: Vec::new(),
            result_schema_digest: digest(102)?,
            risk: RiskLevel::Low,
            source_decision_id: VersionId::new(digest(103)?.as_str())?,
            bundle_id: VersionId::new(digest(104)?.as_str())?,
            required_capability: Capability::InvokeTool,
            idempotency_scope: "tenant".to_owned(),
            idempotency_key: IdempotencyKey::new("recovery-key")?,
            retry_policy: RetryPolicy::Never,
            created_at: time(1)?,
            expires_at: time(50)?,
            compensation: None,
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn startup_recovery_verifies_then_classifies_dispatching_without_send() -> TestResult {
        let fixture = fixture()?;
        let access = AccessContext::new(fixture.tenant.clone(), "test")?;
        let engine = EffectEngine::new(Arc::clone(&fixture.store), access);
        engine.register_connector(Arc::new(Connector {
            calls: Arc::clone(&fixture.connector_calls),
        }))?;
        let effect_id = record(200)?;
        let authorization = EffectAuthorization {
            actor_id: record(201)?,
            capabilities: [
                Capability::ProposeEffect,
                Capability::ApproveEffect,
                Capability::InvokeTool,
            ]
            .into_iter()
            .collect(),
            policy_allows: true,
            now: time(10)?,
        };
        let prepared = engine.prepare(effect_intent(effect_id.clone())?, &authorization)?;
        let authorized = engine.authorize(
            &effect_id,
            prepared.effect_version,
            record(202)?,
            None,
            &authorization,
        )?;
        engine.claim_dispatch(
            &effect_id,
            authorized.effect_version,
            record(203)?,
            record(204)?,
            record(205)?,
            time(20)?,
            &authorization,
        )?;

        fixture.checks.journal_integrity()?;
        fixture.checks.recover_unreceipted_dispatches()?;
        let recovered = engine.get(&effect_id)?;
        assert_eq!(recovered.state, EffectState::Unknown);
        assert_eq!(recovered.effect_version, 3);
        assert!(
            recovered.outbox.is_some_and(|outbox| {
                outbox.state == cigar_effects::EffectOutboxState::Completed
            })
        );

        fixture.checks.recover_unreceipted_dispatches()?;
        assert_eq!(engine.get(&effect_id)?.effect_version, 3);
        assert_eq!(fixture.connector_calls.load(Ordering::Acquire), 0);
        assert_eq!(fixture.maintenance.jobs.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn durable_idle_poll_recovers_a_lost_outbox_wakeup_exactly_once() -> TestResult {
        let fixture = fixture()?;
        let access = AccessContext::new(fixture.tenant.clone(), "test.lost-wakeup")?;
        let engine = EffectEngine::new(Arc::clone(&fixture.store), access);
        engine.register_connector(Arc::new(Connector {
            calls: Arc::clone(&fixture.connector_calls),
        }))?;
        let effect_id = record(300)?;
        let authorization = EffectAuthorization {
            actor_id: record(301)?,
            capabilities: [
                Capability::ProposeEffect,
                Capability::ApproveEffect,
                Capability::InvokeTool,
            ]
            .into_iter()
            .collect(),
            policy_allows: true,
            now: time(10)?,
        };
        let prepared = engine.prepare(effect_intent(effect_id.clone())?, &authorization)?;
        let authorized = engine.authorize(
            &effect_id,
            prepared.effect_version,
            record(302)?,
            None,
            &authorization,
        )?;
        engine.claim_dispatch(
            &effect_id,
            authorized.effect_version,
            record(303)?,
            record(304)?,
            record(305)?,
            time(20)?,
            &authorization,
        )?;

        assert!(fixture.checks.poll_durable_work()?);
        let completed = engine.get(&effect_id)?;
        assert_eq!(completed.state, EffectState::Succeeded);
        assert_eq!(completed.receipts.len(), 1);
        assert_eq!(fixture.connector_calls.load(Ordering::Acquire), 1);
        assert!(!fixture.checks.poll_durable_work()?);
        assert_eq!(fixture.connector_calls.load(Ordering::Acquire), 1);
        Ok(())
    }
}
