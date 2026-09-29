//! Bounded transient host ingestion. Staging is never evidence or restored authority.
use super::{
    BrokerError, ContextBroker, RECORD_ALLOWANCE, SourceProvenance, SourceReceipt, SourceRevision,
    deadline, measure, random_id, valid_source,
};
use crate::{ContextError, Document};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Instant;

const MAX_STAGED_SOURCES: usize = 4;
const MAX_LEASE_MS: u64 = 300_000;

/// Opaque reference to one transient source replacement on the private host channel.
/// This is not agent, reviewer or execution authority. Expiry/restart/consumption invalidates it.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTransaction {
    /// Current broker instance identity.
    pub epoch: String,
    /// Unpredictable staging identifier, with no embedded source content.
    pub id: String,
}

impl std::fmt::Debug for SourceTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceTransaction").finish_non_exhaustive()
    }
}

pub(super) struct StagedSource {
    source: String,
    expected: SourceRevision,
    provenance: SourceProvenance,
    documents: Vec<Document>,
    ids: BTreeSet<String>,
    text_bytes: usize,
    pub(super) bytes: usize,
    pub(super) expires: Instant,
}

impl ContextBroker {
    /// Begin a private, expiring source replacement without changing evidence or authority.
    /// At most four staging handles share the existing aggregate retention ceiling.
    pub fn host_begin_source_replace(
        &mut self,
        source: &str,
        expected: &SourceRevision,
        provenance: SourceProvenance,
        lease_ms: u64,
    ) -> Result<SourceTransaction, BrokerError> {
        self.prune();
        valid_source(source)?;
        if lease_ms == 0 || lease_ms > MAX_LEASE_MS {
            return Err(BrokerError::InvalidInput);
        }
        if self.revision(source) != *expected {
            return Err(BrokerError::Conflict);
        }
        if self.staged_sources.len() >= MAX_STAGED_SOURCES
            || (!self.sources.contains_key(source) && self.sources.len() >= self.limits.max_sources)
        {
            return Err(BrokerError::Quota);
        }
        self.validate_provenance(source, &provenance)?;
        let bytes = measure(
            &(source, expected, &provenance),
            self.limits.max_retained_bytes,
        )?;
        self.check_staging_retention(bytes)?;
        let expires = deadline(lease_ms)?;
        let id = random_id()?;
        if self.staged_sources.contains_key(&id) {
            return Err(BrokerError::Unavailable);
        }
        self.staged_sources.insert(
            id.clone(),
            StagedSource {
                source: source.into(),
                expected: expected.clone(),
                provenance,
                documents: Vec::new(),
                ids: BTreeSet::new(),
                text_bytes: 0,
                bytes,
                expires,
            },
        );
        Ok(SourceTransaction {
            epoch: self.epoch.clone(),
            id,
        })
    }

    /// Read host staging identity for a commit receipt. Missing/expired/consumed handles are stale.
    /// No agent endpoint may expose this unfiltered source locator.
    pub fn host_staged_source(
        &self,
        transaction: &SourceTransaction,
    ) -> Result<(&str, &SourceRevision, usize), BrokerError> {
        let staged = self.live_staging(transaction)?;
        Ok((&staged.source, &staged.expected, staged.documents.len()))
    }

    /// Append a nonempty, fully validated batch without changing the live graph.
    /// Any rejected batch leaves earlier staged documents unchanged. Returns the staged count.
    pub fn host_append_source_documents(
        &mut self,
        transaction: &SourceTransaction,
        documents: Vec<Document>,
    ) -> Result<usize, BrokerError> {
        self.prune();
        let staged = self.live_staging(transaction)?;
        if documents.is_empty() {
            return Err(BrokerError::InvalidInput);
        }
        let count = staged
            .documents
            .len()
            .checked_add(documents.len())
            .filter(|count| *count <= self.graph.limits.max_documents)
            .ok_or(BrokerError::Quota)?;
        self.validate_document_owners(&staged.source, &documents)?;
        let mut incoming = BTreeSet::new();
        let mut text_bytes = staged.text_bytes;
        for document in &documents {
            document.validate_shape()?;
            document.validate_bounds(self.graph.limits.max_document_bytes)?;
            if document.source != staged.source
                || staged.ids.contains(&document.id)
                || !incoming.insert(document.id.as_str())
            {
                return Err(BrokerError::InvalidInput);
            }
            text_bytes = text_bytes
                .checked_add(document.text.len())
                .filter(|bytes| *bytes <= self.graph.limits.max_total_bytes)
                .ok_or(BrokerError::Context(ContextError::LimitExceeded))?;
        }
        let encoded = measure(&documents, self.limits.max_retained_bytes)?;
        let charge = documents
            .len()
            .checked_mul(RECORD_ALLOWANCE)
            .and_then(|allowance| allowance.checked_add(encoded))
            .ok_or(BrokerError::Quota)?;
        self.check_staging_retention(charge)?;
        let staged = self
            .staged_sources
            .get_mut(&transaction.id)
            .ok_or(BrokerError::Stale)?;
        // No fallible validation after this point. Preserve input order for the existing commit path.
        staged
            .ids
            .extend(documents.iter().map(|document| document.id.clone()));
        staged.documents.extend(documents);
        staged.text_bytes = text_bytes;
        staged.bytes += charge;
        Ok(count)
    }

    /// Consume staging and atomically replace the source using the existing CAS/provenance path.
    /// Definite failure leaves the graph unchanged but consumes the handle. No implicit retry.
    pub fn host_commit_source_replace(
        &mut self,
        transaction: &SourceTransaction,
    ) -> Result<SourceReceipt, BrokerError> {
        self.prune();
        self.live_staging(transaction)?;
        let staged = self
            .staged_sources
            .remove(&transaction.id)
            .ok_or(BrokerError::Stale)?;
        self.host_replace_source(
            &staged.source,
            &staged.expected,
            staged.documents,
            staged.provenance,
        )
    }

    /// Discard current-epoch staging. Unknown or expired handles are harmless; no graph change.
    pub fn host_abort_source_replace(&mut self, transaction: &SourceTransaction) -> bool {
        if transaction.epoch != self.epoch {
            return false;
        }
        self.staged_sources.remove(&transaction.id).is_some()
    }

    fn live_staging(&self, transaction: &SourceTransaction) -> Result<&StagedSource, BrokerError> {
        if transaction.epoch != self.epoch {
            return Err(BrokerError::Stale);
        }
        self.staged_sources
            .get(&transaction.id)
            .filter(|staged| staged.expires > Instant::now())
            .ok_or(BrokerError::Stale)
    }

    pub(super) fn staged_bytes(&self) -> usize {
        self.staged_sources
            .values()
            .map(|staged| staged.bytes)
            .sum()
    }

    fn check_staging_retention(&self, additional: usize) -> Result<(), BrokerError> {
        let retained = self
            .tickets
            .values()
            .map(|ticket| ticket.bytes)
            .chain(self.proposals.values().map(|proposal| proposal.bytes))
            .chain(self.staged_sources.values().map(|staged| staged.bytes))
            .try_fold(additional, |total, bytes| total.checked_add(bytes))
            .ok_or(BrokerError::Quota)?;
        if retained > self.limits.max_retained_bytes {
            return Err(BrokerError::Quota);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
