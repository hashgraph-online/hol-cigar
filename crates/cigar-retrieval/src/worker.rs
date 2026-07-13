//! Idempotent causal-outbox projection worker.

use crate::{
    InMemoryIndexManager, IndexBuild, IndexGenerationDescriptor, RetrievalContext, RetrievalError,
    RetrievalErrorCode,
};
use cigar_protocol::{ContentDigest, ContextAtomV1, ContextEdge, RecordId, UtcTimestamp};
use cigar_store::{OutboxRecord, StoreRevision};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

/// Canonical repository state loaded at one causal revision.
#[derive(Clone, Debug)]
pub struct IndexSnapshot {
    /// Complete canonical atoms visible at the revision.
    pub atoms: Vec<ContextAtomV1>,
    /// Complete canonical edges visible at the revision.
    pub edges: Vec<ContextEdge>,
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
    processed: BTreeMap<RecordId, ContentDigest>,
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
    /// Rebuilds through all new ordered catalog commits and advances only after activation.
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &self,
        records: &[OutboxRecord],
        provider: &dyn IndexSnapshotProvider,
        manager: &InMemoryIndexManager,
        configuration_digest: ContentDigest,
        vector_fingerprint: Option<ContentDigest>,
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
            if record.message.topic != "catalog.committed" {
                continue;
            }
            record
                .message
                .validate()
                .map_err(|_error| RetrievalError::new(RetrievalErrorCode::InvalidMetadata))?;
            if let Some(digest) = state.processed.get(&record.message.message_id) {
                if digest != &record.message.payload_digest {
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
                configuration_digest,
                verified_at,
                vector_fingerprint,
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
                record.message.payload_digest.clone(),
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
            _revision: StoreRevision,
            context: &RetrievalContext,
        ) -> Result<IndexSnapshot, RetrievalError> {
            context.check()?;
            Ok(self.snapshot.clone())
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

    fn outbox(value: u16, revision: u64) -> Result<OutboxRecord, Box<dyn Error>> {
        Ok(OutboxRecord {
            message: OutboxMessage {
                message_id: record(value)?,
                topic: "catalog.committed".to_owned(),
                payload_digest: digest(if value.is_multiple_of(2) { 'a' } else { 'b' })?,
            },
            causal_revision: StoreRevision(revision),
        })
    }

    fn provider() -> Result<StaticProvider, Box<dyn Error>> {
        let fixture = deterministic_protocol_fixture("ContextAtomV1")
            .ok_or("missing deterministic ContextAtomV1 fixture")?;
        let atom: ContextAtomV1 = serde_json::from_value(fixture.input)?;
        Ok(StaticProvider {
            snapshot: IndexSnapshot {
                atoms: vec![atom],
                edges: Vec::new(),
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
