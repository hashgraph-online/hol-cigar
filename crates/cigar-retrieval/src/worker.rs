//! Idempotent causal-outbox projection worker.

use crate::{
    InMemoryIndexManager, IndexBuild, IndexGenerationDescriptor, RetrievalContext, RetrievalError,
    RetrievalErrorCode, VectorIndexBinding,
};
use cigar_protocol::{ContentDigest, ContextAtomV1, ContextEdge, RecordId, UtcTimestamp};
use cigar_store::{OutboxRecord, StoreRevision};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

const CATALOG_COMMITTED_TOPIC: &str = "catalog.committed";
const CATALOG_TOMBSTONED_TOPIC: &str = "catalog.atom-tombstoned";

/// Canonical repository state loaded at one causal revision.
#[derive(Clone, Debug)]
pub struct IndexSnapshot {
    /// Complete canonical atoms visible at the revision.
    pub atoms: Vec<ContextAtomV1>,
    /// Complete canonical edges visible at the revision.
    pub edges: Vec<ContextEdge>,
    /// Per-tenant catalog revisions represented by the snapshot, including known empty tenants.
    pub tenant_watermarks: BTreeMap<RecordId, StoreRevision>,
}

/// Authorization-bound canonical snapshot loader used by the worker.
pub trait IndexSnapshotProvider: Send + Sync {
    /// Loads a complete immutable snapshot at exactly `revision`.
    fn load(
        &self,
        revision: StoreRevision,
        context: &RetrievalContext,
    ) -> Result<IndexSnapshot, RetrievalError>;
}

#[derive(Default)]
struct WorkerState {
    watermark: StoreRevision,
    processed: BTreeMap<RecordId, ProcessedCatalogMessage>,
}

#[derive(Clone, Eq, PartialEq)]
struct ProcessedCatalogMessage {
    topic: String,
    payload_digest: ContentDigest,
}

/// Result of one idempotent worker pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexWorkerReceipt {
    /// Highest causal catalog revision durably represented by the active generation.
    pub watermark: StoreRevision,
    /// Number of newly claimed causal messages.
    pub claimed_messages: usize,
    /// Active generation after the pass, when one exists.
    pub active_generation: Option<IndexGenerationDescriptor>,
}

/// Serial idempotent outbox consumer with activation-after-verification semantics.
#[derive(Default)]
pub struct IndexWorker {
    state: Mutex<WorkerState>,
}

impl fmt::Debug for IndexWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IndexWorker")
    }
}

impl IndexWorker {
    /// Restores one complete generation from canonical repository state when startup can no
    /// longer replay the historical catalog revision retained by the causal outbox. This is
    /// restricted to a fresh worker and manager so it cannot skip live work or replace an active
    /// generation.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        &self,
        target: StoreRevision,
        provider: &dyn IndexSnapshotProvider,
        manager: &InMemoryIndexManager,
        configuration_digest: ContentDigest,
        vector_binding: Option<VectorIndexBinding>,
        verified_at: UtcTimestamp,
        context: &RetrievalContext,
    ) -> Result<IndexWorkerReceipt, RetrievalError> {
        context.check()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        if state.watermark != StoreRevision(0)
            || !state.processed.is_empty()
            || manager.active_generation()?.is_some()
        {
            return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
        }
        let snapshot = provider.load(target, context)?;
        context.check()?;
        let descriptor = manager.build_generation(
            IndexBuild {
                atoms: snapshot.atoms,
                edges: snapshot.edges,
                built_through_revision: target,
                tenant_watermarks: snapshot.tenant_watermarks,
                configuration_digest,
                verified_at,
                vector_binding,
            },
            context,
        )?;
        context.check()?;
        let active = manager.activate(&descriptor.generation_id, None)?;
        state.watermark = target;
        Ok(IndexWorkerReceipt {
            watermark: target,
            claimed_messages: 0,
            active_generation: Some(active),
        })
    }

    /// Rebuilds through all new ordered catalog mutations and advances only after activation.
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &self,
        records: &[OutboxRecord],
        provider: &dyn IndexSnapshotProvider,
        manager: &InMemoryIndexManager,
        configuration_digest: ContentDigest,
        vector_binding: Option<VectorIndexBinding>,
        verified_at: UtcTimestamp,
        context: &RetrievalContext,
    ) -> Result<IndexWorkerReceipt, RetrievalError> {
        context.check()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?;
        let mut prior_revision = StoreRevision(0);
        let mut new_records = Vec::new();
        for record in records {
            context.check()?;
            if record.causal_revision < prior_revision {
                return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
            }
            prior_revision = record.causal_revision;
            if !catalog_index_topic(&record.message.topic) {
                continue;
            }
            record
                .message
                .validate()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?;
            if let Some(processed) = state.processed.get(&record.message.message_id) {
                if processed.topic != record.message.topic
                    || processed.payload_digest != record.message.payload_digest
                {
                    return Err(RetrievalError::new(RetrievalErrorCode::CorruptGeneration));
                }
                continue;
            }
            if record.causal_revision < state.watermark {
                return Err(RetrievalError::new(RetrievalErrorCode::InvalidMetadata));
            }
            new_records.push(record);
        }
        let Some(target) = new_records.last().map(|record| record.causal_revision) else {
            return Ok(IndexWorkerReceipt {
                watermark: state.watermark,
                claimed_messages: 0,
                active_generation: manager.active_generation()?,
            });
        };
        let snapshot = provider.load(target, context)?;
        context.check()?;
        let descriptor = manager.build_generation(
            IndexBuild {
                atoms: snapshot.atoms,
                edges: snapshot.edges,
                built_through_revision: target,
                tenant_watermarks: snapshot.tenant_watermarks,
                configuration_digest,
                verified_at,
                vector_binding,
            },
            context,
        )?;
        context.check()?;
        let expected_active = manager.active_generation()?;
        let active = manager.activate(
            &descriptor.generation_id,
            expected_active
                .as_ref()
                .map(|generation| &generation.generation_id),
        )?;
        for record in &new_records {
            state.processed.insert(
                record.message.message_id.clone(),
                ProcessedCatalogMessage {
                    topic: record.message.topic.clone(),
                    payload_digest: record.message.payload_digest.clone(),
                },
            );
        }
        state.watermark = target;
        Ok(IndexWorkerReceipt {
            watermark: target,
            claimed_messages: new_records.len(),
            active_generation: Some(active),
        })
    }

    /// Returns the last activation-backed causal watermark.
    pub fn watermark(&self) -> Result<StoreRevision, RetrievalError> {
        Ok(self
            .state
            .lock()
            .map_err(|_error| RetrievalError::new(RetrievalErrorCode::IndexUnavailable))?
            .watermark)
    }
}

fn catalog_index_topic(topic: &str) -> bool {
    matches!(topic, CATALOG_COMMITTED_TOPIC | CATALOG_TOMBSTONED_TOPIC)
}

#[cfg(test)]
mod tests {
    use super::{IndexSnapshot, IndexSnapshotProvider, IndexWorker};
    use crate::{InMemoryIndexManager, RetrievalContext, RetrievalError, RetrievalErrorCode};
    use cigar_protocol::{ContentDigest, ContextAtomV1, RecordId, UtcTimestamp};
    use cigar_store::{CancellationToken, OutboxMessage, OutboxRecord, StoreRevision};
    use cigar_testkit::deterministic_protocol_fixture;
    use std::error::Error;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct StaticProvider {
        snapshot: IndexSnapshot,
    }

    impl IndexSnapshotProvider for StaticProvider {
        fn load(
            &self,
            revision: StoreRevision,
            context: &RetrievalContext,
        ) -> Result<IndexSnapshot, RetrievalError> {
            context.check()?;
            let mut snapshot = self.snapshot.clone();
            for watermark in snapshot.tenant_watermarks.values_mut() {
                *watermark = revision;
            }
            Ok(snapshot)
        }
    }

    struct FailingProvider;

    impl IndexSnapshotProvider for FailingProvider {
        fn load(
            &self,
            _revision: StoreRevision,
            _context: &RetrievalContext,
        ) -> Result<IndexSnapshot, RetrievalError> {
            Err(RetrievalError::new(RetrievalErrorCode::IndexUnavailable))
        }
    }

    fn digest(value: char) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(ContentDigest::new(format!(
            "1220{}",
            value.to_string().repeat(64)
        ))?)
    }

    fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
        ))?)
    }

    fn outbox_with_topic(
        value: u16,
        revision: u64,
        topic: &str,
    ) -> Result<OutboxRecord, Box<dyn Error>> {
        Ok(OutboxRecord {
            message: OutboxMessage {
                message_id: record(value)?,
                topic: topic.to_owned(),
                payload_digest: digest(if value.is_multiple_of(2) { 'a' } else { 'b' })?,
            },
            causal_revision: StoreRevision(revision),
        })
    }

    fn outbox(value: u16, revision: u64) -> Result<OutboxRecord, Box<dyn Error>> {
        outbox_with_topic(value, revision, "catalog.committed")
    }

    fn provider() -> Result<StaticProvider, Box<dyn Error>> {
        let fixture = deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing deterministic ContextAtomV1 fixture")?;
        let atom: ContextAtomV1 = serde_json::from_value(fixture.input)?;
        let tenant_id = atom.scope.tenant_id.clone();
        Ok(StaticProvider {
            snapshot: IndexSnapshot {
                atoms: vec![atom],
                edges: Vec::new(),
                tenant_watermarks: [(tenant_id, StoreRevision(1))].into_iter().collect(),
            },
        })
    }

    fn context() -> RetrievalContext {
        RetrievalContext {
            cancellation: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    #[test]
    fn worker_advances_only_after_activation_and_replay_is_idempotent() -> Result<(), Box<dyn Error>>
    {
        let records = vec![outbox(1, 1)?, outbox(2, 3)?];
        let worker = IndexWorker::default();
        let manager = InMemoryIndexManager::default();
        let first = worker.process(
            &records,
            &provider()?,
            &manager,
            digest('c')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        assert_eq!(first.watermark, StoreRevision(3));
        assert_eq!(first.claimed_messages, 2);
        assert_eq!(
            first
                .active_generation
                .as_ref()
                .map(|generation| generation.built_through_revision),
            Some(StoreRevision(3))
        );
        let replay = worker.process(
            &records,
            &provider()?,
            &manager,
            digest('c')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        assert_eq!(replay.claimed_messages, 0);
        assert_eq!(replay.active_generation, first.active_generation);
        Ok(())
    }

    #[test]
    fn tombstone_only_wakes_projection_and_unknown_topics_are_ignored() -> Result<(), Box<dyn Error>>
    {
        let worker = IndexWorker::default();
        let manager = InMemoryIndexManager::default();
        let unknown = outbox_with_topic(10, 1, "effects.completed")?;
        let ignored = worker.process(
            std::slice::from_ref(&unknown),
            &FailingProvider,
            &manager,
            digest('c')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        assert_eq!(ignored.watermark, StoreRevision(0));
        assert_eq!(ignored.claimed_messages, 0);
        assert!(ignored.active_generation.is_none());

        let tombstone = outbox_with_topic(11, 2, "catalog.atom-tombstoned")?;
        let claimed = worker.process(
            &[unknown, tombstone.clone()],
            &provider()?,
            &manager,
            digest('c')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        assert_eq!(claimed.watermark, StoreRevision(2));
        assert_eq!(claimed.claimed_messages, 1);
        assert_eq!(
            claimed
                .active_generation
                .as_ref()
                .map(|generation| generation.built_through_revision),
            Some(StoreRevision(2))
        );

        let replay = worker.process(
            &[tombstone],
            &FailingProvider,
            &manager,
            digest('c')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        assert_eq!(replay.watermark, StoreRevision(2));
        assert_eq!(replay.claimed_messages, 0);
        Ok(())
    }

    #[test]
    fn accepted_topic_substitution_under_one_message_identity_is_corrupt()
    -> Result<(), Box<dyn Error>> {
        let worker = IndexWorker::default();
        let manager = InMemoryIndexManager::default();
        let committed = outbox_with_topic(12, 1, "catalog.committed")?;
        worker.process(
            std::slice::from_ref(&committed),
            &provider()?,
            &manager,
            digest('c')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        let mut substituted = committed;
        substituted.message.topic = "catalog.atom-tombstoned".to_owned();
        assert_eq!(
            worker
                .process(
                    &[substituted],
                    &FailingProvider,
                    &manager,
                    digest('c')?,
                    None,
                    UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
                    &context(),
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::CorruptGeneration)
        );
        assert_eq!(worker.watermark()?, StoreRevision(1));
        Ok(())
    }

    #[test]
    fn failure_does_not_advance_and_retry_or_order_corruption_is_exact()
    -> Result<(), Box<dyn Error>> {
        let worker = IndexWorker::default();
        let manager = InMemoryIndexManager::default();
        let records = vec![outbox(3, 5)?];
        assert_eq!(
            worker
                .process(
                    &records,
                    &FailingProvider,
                    &manager,
                    digest('d')?,
                    None,
                    UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
                    &context(),
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::IndexUnavailable)
        );
        assert_eq!(worker.watermark()?, StoreRevision(0));
        assert!(manager.active_generation()?.is_none());
        let retry = worker.process(
            &records,
            &provider()?,
            &manager,
            digest('d')?,
            None,
            UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
            &context(),
        )?;
        assert_eq!(retry.watermark, StoreRevision(5));

        let out_of_order = vec![outbox(4, 7)?, outbox(5, 6)?];
        assert_eq!(
            worker
                .process(
                    &out_of_order,
                    &provider()?,
                    &manager,
                    digest('d')?,
                    None,
                    UtcTimestamp::parse_rfc3339("2026-07-10T00:00:03Z")?,
                    &context(),
                )
                .map_err(|error| error.code()),
            Err(RetrievalErrorCode::InvalidMetadata)
        );
        assert_eq!(worker.watermark()?, StoreRevision(5));
        Ok(())
    }
}
