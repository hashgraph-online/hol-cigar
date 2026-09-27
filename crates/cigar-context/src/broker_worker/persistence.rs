//! The worker owns durability. No mutable broker reference escapes this process owner.
use cigar_context::GraphLimits;
use cigar_context::broker::protocol::HostCommand;
use cigar_context::broker::{
    BrokerError, BrokerLimits, BrokerStorageOptions, ContextBroker, SourceRevision,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(all(feature = "broker-persistence", any(unix, windows)))]
mod sqlite;

#[derive(Default)]
pub(super) struct Persistence {
    active: bool,
    #[cfg(all(feature = "broker-persistence", any(unix, windows)))]
    store: Option<sqlite::Store>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Initialize,
    Resume,
    ReplaceSource,
    SetEdge,
    AdmitProposal,
}

/// Receipts deliberately omit command text, proposals, credentials and review content.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    operation: Operation,
    epoch: String,
    expected: BTreeMap<String, SourceRevision>,
    resulting: BTreeMap<String, SourceRevision>,
}

impl Persistence {
    pub(super) fn open(
        domain: String,
        graph: GraphLimits,
        limits: BrokerLimits,
        options: Option<BrokerStorageOptions>,
    ) -> Result<(ContextBroker, Self, bool), BrokerError> {
        if let Some(options) = options {
            #[cfg(all(feature = "broker-persistence", any(unix, windows)))]
            {
                let (broker, store, restored) =
                    sqlite::Store::open(domain, graph, limits, options)?;
                return Ok((
                    broker,
                    Self {
                        active: true,
                        store: Some(store),
                    },
                    restored,
                ));
            }
            #[cfg(not(all(feature = "broker-persistence", any(unix, windows))))]
            {
                let _ = options;
                // Never silently downgrade a requested persistent broker to memory-only mode.
                return Err(BrokerError::Unavailable);
            }
        }
        Ok((
            ContextBroker::new(domain, graph, limits)?,
            Self::default(),
            false,
        ))
    }

    pub(super) fn active(&self) -> bool {
        self.active
    }

    /// Capture the exact CAS inputs before mutation. Rejected commands produce no receipt.
    pub(super) fn prepare(
        &self,
        broker: &ContextBroker,
        command: &HostCommand,
    ) -> Result<Option<Event>, BrokerError> {
        if !self.active {
            return Ok(None);
        }
        let (operation, expected) = match command {
            HostCommand::ReplaceSource {
                source, expected, ..
            } => (
                Operation::ReplaceSource,
                BTreeMap::from([(source.clone(), expected.clone())]),
            ),
            HostCommand::SetEdge { expected, .. } => (Operation::SetEdge, expected.clone()),
            HostCommand::AdmitProposal { proposal_id, .. } => {
                let (source, expected, _) = broker.host_proposal(proposal_id)?;
                (
                    Operation::AdmitProposal,
                    BTreeMap::from([(source.into(), expected.clone())]),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(Event {
            operation,
            epoch: broker.epoch().into(),
            expected,
            resulting: BTreeMap::new(),
        }))
    }

    /// Any failure here follows an in-memory mutation and must terminate the owner without a
    /// success or definite-failure reply. A commit may have reached storage before an I/O error.
    pub(super) fn commit(
        &mut self,
        broker: &ContextBroker,
        mut event: Event,
    ) -> Result<(), BrokerError> {
        for source in event.expected.keys() {
            event
                .resulting
                .insert(source.clone(), broker.host_source_revision(source)?);
        }
        #[cfg(all(feature = "broker-persistence", any(unix, windows)))]
        if let Some(store) = &mut self.store {
            return store.commit(broker, &event);
        }
        Err(BrokerError::Unavailable)
    }
}
