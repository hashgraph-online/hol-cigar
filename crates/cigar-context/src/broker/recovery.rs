//! Evidence-only recovery. This codec does not write files or claim durable commit.
//! Applications must protect checkpoint bytes; a digest is not a publisher signature.

use super::{
    BrokerError, BrokerLimits, ContextBroker, EdgeNode, MAX_PROVENANCE_BYTES, SourceProvenance,
    SourceRecord, measure, unix_ms, valid_label, valid_source,
};
use crate::{ContextError, Document, EdgeKind, GraphLimits, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const SCHEMA: &str = "cigar.broker-checkpoint.v1";
const MAX_BYTES: usize = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceImage {
    source: String,
    version: u64,
    provenance: SourceProvenance,
    // Preserve the remaining monotonic bound. Recovery also rejects a clock before capture.
    remaining_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    domain: String,
    prior_epoch: String,
    captured_at_ms: u64,
    graph_revision: u64,
    sources: Vec<SourceImage>,
    documents: Vec<Document>,
    edges: BTreeMap<String, BTreeSet<(EdgeKind, String)>>,
    edge_owners: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    state: State,
    sha256: String,
}

/// Opaque, bounded evidence checkpoint. It contains source text and must be kept private.
/// It never contains grant secrets, tickets, proposals, drafts, verdicts or effect permissions.
/// Encoding/decoding alone does not provide atomic storage, encryption or authentication.
pub struct BrokerCheckpoint {
    envelope: Envelope,
}

impl std::fmt::Debug for BrokerCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerCheckpoint").finish_non_exhaustive()
    }
}

impl BrokerCheckpoint {
    /// Copy the canonical private bytes, rejecting a caller limit outside 1..=512 MiB.
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, BrokerError> {
        valid_bound(max_bytes)?;
        // The writer enforces the bound while serializing, before building an unbounded buffer.
        bounded_encode(&self.envelope, max_bytes)
    }

    /// Decode only exact versioned canonical bytes with a matching content digest. Restore
    /// performs domain, current limits and graph/lineage validation before exposing any graph.
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self, BrokerError> {
        valid_bound(max_bytes)?;
        if bytes.len() > max_bytes {
            return Err(BrokerError::Quota);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| integrity())?;
        if envelope.schema != SCHEMA
            || envelope.sha256 != digest(SCHEMA, &envelope.state)?
            || bounded_encode(&envelope, max_bytes)? != bytes
        {
            return Err(integrity());
        }
        Ok(Self { envelope })
    }
}

impl ContextBroker {
    /// Capture current evidence and its freshness bounds. This is an explicit in-memory
    /// checkpoint, not a durable commit; credentials and all transient authority are excluded.
    pub fn host_checkpoint(&self, max_bytes: usize) -> Result<BrokerCheckpoint, BrokerError> {
        valid_bound(max_bytes)?;
        self.graph
            .documents
            .values()
            .try_fold(0_usize, |bytes, node| {
                bytes
                    .checked_add(node.document.text.len())
                    .filter(|total| *total <= max_bytes)
                    .ok_or(BrokerError::Quota)
            })?;
        let captured_at_ms = unix_ms()?;
        let instant = Instant::now();
        let state = State {
            domain: self.graph.domain.clone(),
            prior_epoch: self.epoch.clone(),
            captured_at_ms,
            graph_revision: self.graph.revision,
            sources: self
                .sources
                .iter()
                .map(|(source, record)| SourceImage {
                    source: source.clone(),
                    version: record.version,
                    provenance: record.provenance.clone(),
                    remaining_ms: record.expires.map(|expiry| {
                        u64::try_from(expiry.saturating_duration_since(instant).as_millis())
                            .unwrap_or(u64::MAX)
                    }),
                })
                .collect(),
            documents: self
                .graph
                .documents
                .values()
                .map(|node| node.document.clone())
                .collect(),
            edges: self.graph.edges.clone(),
            edge_owners: self
                .edge_nodes
                .iter()
                .map(|(id, node)| (id.clone(), node.source.clone()))
                .collect(),
        };
        measure(&state, max_bytes)?;
        let sha256 = digest(SCHEMA, &state)?;
        let checkpoint = BrokerCheckpoint {
            envelope: Envelope {
                schema: SCHEMA.into(),
                state,
                sha256,
            },
        };
        measure(&checkpoint.envelope, max_bytes)?;
        Ok(checkpoint)
    }

    /// Restore evidence into a fresh authority epoch under explicit current limits. The host
    /// must reissue grants, recompile context and obtain new reviews. Old source CAS handles
    /// remain invalid even though each source's monotonic version and lineage are preserved.
    pub fn from_checkpoint(
        domain: impl Into<String>,
        graph_limits: GraphLimits,
        limits: BrokerLimits,
        checkpoint: &BrokerCheckpoint,
    ) -> Result<Self, BrokerError> {
        let mut broker = Self::new(domain, graph_limits, limits)?;
        let state = &checkpoint.envelope.state;
        let now_ms = unix_ms()?;
        let elapsed = now_ms
            .checked_sub(state.captured_at_ms)
            .ok_or(BrokerError::Stale)?;
        if state.domain != broker.graph.domain
            || state.prior_epoch.len() != 64
            || !state
                .prior_epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || state.sources.len() > limits.max_sources
            || state.documents.len() > graph_limits.max_documents
            || (state.graph_revision == 0
                && (!state.documents.is_empty() || !state.edges.is_empty()))
        {
            return Err(integrity());
        }
        let mut provenance_bytes = 0_usize;
        for saved in &state.sources {
            valid_source(&saved.source)?;
            let mut provenance = saved.provenance.clone();
            if saved.version == 0
                || broker.sources.contains_key(&saved.source)
                || !valid_label(&provenance.authority)
                || !valid_label(&provenance.upstream_revision)
                || provenance.derived_from.len() > 32
                || provenance.valid_until_ms.is_some() != saved.remaining_ms.is_some()
                || provenance
                    .valid_until_ms
                    .is_some_and(|until| until <= provenance.observed_at_ms)
            {
                return Err(integrity());
            }
            let mut seen = BTreeSet::new();
            for dependency in &mut provenance.derived_from {
                valid_source(&dependency.source)?;
                if dependency.source == saved.source
                    || !seen.insert(&dependency.source)
                    || dependency.revision.epoch != state.prior_epoch
                    || dependency.revision.version == 0
                {
                    return Err(integrity());
                }
                // Only internal evidence lineage is re-bound. No external source handle is reused.
                dependency.revision.epoch.clone_from(&broker.epoch);
            }
            let bytes = measure(&(&saved.source, &provenance), MAX_PROVENANCE_BYTES)?;
            provenance_bytes = provenance_bytes
                .checked_add(bytes)
                .ok_or(BrokerError::Quota)?;
            if provenance_bytes > limits.max_provenance_bytes {
                return Err(BrokerError::Quota);
            }
            let expires = match (provenance.valid_until_ms, saved.remaining_ms) {
                (Some(until), Some(remaining)) => {
                    let lifetime = until
                        .saturating_sub(now_ms)
                        .min(remaining.saturating_sub(elapsed));
                    Some(
                        Instant::now()
                            .checked_add(Duration::from_millis(lifetime))
                            .ok_or(BrokerError::Unavailable)?,
                    )
                }
                _ => None,
            };
            broker.sources.insert(
                saved.source.clone(),
                SourceRecord {
                    version: saved.version,
                    provenance,
                    bytes,
                    expires,
                },
            );
        }
        for record in broker.sources.values() {
            for dependency in &record.provenance.derived_from {
                if broker
                    .sources
                    .get(&dependency.source)
                    .is_none_or(|input| input.version < dependency.revision.version)
                {
                    return Err(integrity());
                }
            }
        }
        validate_lineage(&broker.sources)?;
        for document in &state.documents {
            if !broker.sources.contains_key(&document.source)
                || broker.graph.documents.contains_key(&document.id)
            {
                return Err(integrity());
            }
            broker.graph.upsert(document.clone())?;
        }
        broker.graph.restore_relationships(state.edges.clone())?;
        let mut relation_bytes = 0_usize;
        for (from, outgoing) in &state.edges {
            for (kind, to) in outgoing {
                // Contradictions have two stored directions but one logical ownership reference.
                if *kind == EdgeKind::Contradicts && from > to {
                    continue;
                }
                for id in [from, to] {
                    let source = state.edge_owners.get(id).ok_or_else(integrity)?;
                    if !broker.sources.contains_key(source)
                        || broker
                            .graph
                            .documents
                            .get(id)
                            .is_some_and(|doc| &doc.document.source != source)
                    {
                        return Err(integrity());
                    }
                    if let Some(node) = broker.edge_nodes.get_mut(id) {
                        node.references =
                            node.references.checked_add(1).ok_or(BrokerError::Quota)?;
                    } else {
                        let bytes = measure(&(id, source), 8192)?;
                        relation_bytes = relation_bytes
                            .checked_add(bytes)
                            .ok_or(BrokerError::Quota)?;
                        if relation_bytes > limits.max_relation_bytes {
                            return Err(BrokerError::Quota);
                        }
                        broker.edge_nodes.insert(
                            id.clone(),
                            EdgeNode {
                                source: source.clone(),
                                references: 1,
                                bytes,
                            },
                        );
                    }
                }
            }
        }
        if broker.edge_nodes.len() != state.edge_owners.len() {
            return Err(integrity());
        }
        broker.graph.revision = state.graph_revision;
        Ok(broker)
    }
}

fn validate_lineage(sources: &BTreeMap<String, SourceRecord>) -> Result<(), BrokerError> {
    // Validate even stale historical lineage without recursion or checking current validity.
    let mut remaining = BTreeMap::new();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut ready = Vec::new();
    for (source, record) in sources {
        remaining.insert(source.as_str(), record.provenance.derived_from.len());
        if record.provenance.derived_from.is_empty() {
            ready.push(source.as_str());
        }
        for dependency in &record.provenance.derived_from {
            dependents
                .entry(&dependency.source)
                .or_default()
                .push(source);
        }
    }
    let mut seen = 0;
    while let Some(source) = ready.pop() {
        seen += 1;
        for dependent in dependents.get(source).into_iter().flatten() {
            let count = remaining.get_mut(dependent).ok_or_else(integrity)?;
            *count = count.checked_sub(1).ok_or_else(integrity)?;
            if *count == 0 {
                ready.push(dependent);
            }
        }
    }
    if seen != sources.len() {
        return Err(integrity());
    }
    Ok(())
}

fn valid_bound(max_bytes: usize) -> Result<(), BrokerError> {
    if max_bytes == 0 || max_bytes > MAX_BYTES {
        Err(BrokerError::InvalidInput)
    } else {
        Ok(())
    }
}

fn integrity() -> BrokerError {
    BrokerError::Context(ContextError::Integrity)
}

fn bounded_encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, BrokerError> {
    struct Writer {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("checkpoint limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| BrokerError::Quota)?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests;
