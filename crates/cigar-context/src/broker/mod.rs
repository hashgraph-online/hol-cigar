//! Single-owner broker authority, independent of any network transport or scheduler.
//!
//! The host keeps this object private. Only credential-requiring methods belong on an agent
//! transport; `host_*` methods must stay on the host's private control channel. This module does
//! not itself provide transport, durable storage or semantic truth assessment. The separate
//! scheduler provides bounded admission; a runtime must connect it to this authority correctly.
//! It preserves the ordinary graph API and uses its exact selection and answer-review contracts.

mod types;
pub use types::*;
pub mod protocol;
pub mod scheduler;

use crate::{
    AnswerDraft, AnswerPolicy, Citation, ClaimReview, ContextGraph, ContextRequest, ContextView,
    ContextViewAssessment, ContextViewHandle, ContextViews, Document, EdgeKind, GraphLimits,
    TokenCounter, digest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_LIFETIME_MS: u64 = 86_400_000;
const RECORD_ALLOWANCE: usize = 1024;
const MAX_PROVENANCE_BYTES: usize = 32 * 1024;

struct Grant {
    spec: AgentGrantSpec,
    handle: ContextViewHandle,
    expires: Instant,
}

struct SourceRecord {
    version: u64,
    provenance: SourceProvenance,
    bytes: usize,
    expires: Option<Instant>,
}

struct EdgeNode {
    source: String,
    references: usize,
    bytes: usize,
}

struct Ticket {
    owner: String,
    context: ContextView,
    versions: BTreeMap<String, SourceRevision>,
    expires: Instant,
    bytes: usize,
    submission: Option<AnswerSubmission>,
}

struct Proposal {
    owner: String,
    request_key: String,
    source: String,
    expected: SourceRevision,
    documents: Vec<Document>,
    outcome: ProposalOutcome,
    expires: Instant,
    bytes: usize,
}

/// An explicitly created broker authority. All mutations require exclusive ownership (`&mut`).
/// Each new instance obtains a fresh cryptographic epoch, with no credentials restored/imported.
pub struct ContextBroker {
    epoch: String,
    graph: ContextGraph,
    views: ContextViews,
    limits: BrokerLimits,
    grants: BTreeMap<String, Grant>,
    sources: BTreeMap<String, SourceRecord>,
    // Retain an endpoint's source while any edge refers to it, even after source withdrawal.
    edge_nodes: BTreeMap<String, EdgeNode>,
    tickets: BTreeMap<String, Ticket>,
    proposals: BTreeMap<String, Proposal>,
}

impl ContextBroker {
    /// Start an empty host-owned authority with explicit graph and retention bounds.
    pub fn new(
        domain: impl Into<String>,
        graph_limits: GraphLimits,
        limits: BrokerLimits,
    ) -> Result<Self, BrokerError> {
        if limits.max_agents == 0
            || limits.max_agents > 128
            || limits.max_sources == 0
            || limits.max_sources > 100_000
            || limits.max_tickets == 0
            || limits.max_tickets > 65_536
            || limits.max_proposals == 0
            || limits.max_proposals > 65_536
            || limits.max_retained_bytes < RECORD_ALLOWANCE
            || limits.max_retained_bytes > 1024 * 1024 * 1024
            || limits.max_provenance_bytes < RECORD_ALLOWANCE
            || limits.max_provenance_bytes > 256 * 1024 * 1024
            || limits.max_relation_bytes < RECORD_ALLOWANCE
            || limits.max_relation_bytes > 256 * 1024 * 1024
        {
            return Err(BrokerError::InvalidInput);
        }
        Ok(Self {
            epoch: random_id()?,
            graph: ContextGraph::new(domain, graph_limits)?,
            views: ContextViews::default(),
            limits,
            grants: BTreeMap::new(),
            sources: BTreeMap::new(),
            edge_nodes: BTreeMap::new(),
            tickets: BTreeMap::new(),
            proposals: BTreeMap::new(),
        })
    }

    /// Current public authority epoch. It is an instance identity, not a credential.
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// Define/replace one agent. A successful replacement removes all prior tickets/proposals.
    /// Invalid replacement input leaves the old grant unchanged.
    pub fn host_grant(&mut self, spec: AgentGrantSpec) -> Result<BrokerCredential, BrokerError> {
        self.prune();
        self.validate_grant(&spec)?;
        let previous = self
            .grants
            .iter()
            .find(|(_, grant)| grant.spec.view.id == spec.view.id)
            .map(|(owner, _)| owner.clone());
        if previous.is_none() && self.grants.len() >= self.limits.max_agents {
            return Err(BrokerError::Quota);
        }
        let secret = random_id()?;
        let owner = secret_key(&secret);
        if self.grants.contains_key(&owner) {
            return Err(BrokerError::Unavailable);
        }
        let expires = deadline(spec.lease_ms)?;
        let handle = self.views.define(spec.view.clone())?;
        if let Some(previous) = previous {
            // Do not revoke the newly defined view when removing the previous generation.
            self.remove_owner(&previous);
        }
        self.grants.insert(
            owner,
            Grant {
                spec,
                handle,
                expires,
            },
        );
        Ok(BrokerCredential {
            epoch: self.epoch.clone(),
            secret,
        })
    }

    /// Revoke the named agent and release its retained material. Unknown names are harmless.
    pub fn host_revoke(&mut self, agent: &str) -> bool {
        let owner = self
            .grants
            .iter()
            .find(|(_, grant)| grant.spec.view.id == agent)
            .map(|(owner, _)| owner.clone());
        if let Some(owner) = owner {
            self.remove_owner(&owner);
            self.views.revoke(agent);
            true
        } else {
            false
        }
    }

    /// Read current source authority on the host channel, including withdrawal tombstones.
    pub fn host_source_revision(&self, source: &str) -> Result<SourceRevision, BrokerError> {
        valid_source(source)?;
        Ok(self.revision(source))
    }

    /// Read host provenance. No agent transport should expose unfiltered dependency locators.
    pub fn host_provenance(&self, source: &str) -> Option<&SourceProvenance> {
        self.sources.get(source).map(|record| &record.provenance)
    }

    /// Atomically admit authoritative documents with a source compare-and-swap.
    /// Empty input withdraws; metadata-only changes and change-back advance authority too.
    pub fn host_replace_source(
        &mut self,
        source: &str,
        expected: &SourceRevision,
        documents: Vec<Document>,
        provenance: SourceProvenance,
    ) -> Result<SourceReceipt, BrokerError> {
        valid_source(source)?;
        if self.revision(source) != *expected {
            return Err(BrokerError::Conflict);
        }
        if !self.sources.contains_key(source) && self.sources.len() >= self.limits.max_sources {
            return Err(BrokerError::Quota);
        }
        self.validate_document_owners(source, &documents)?;
        let (bytes, expires) = self.validate_provenance(source, &provenance)?;
        let previous = self.sources.get(source);
        let total_bytes = self
            .sources
            .values()
            .map(|record| record.bytes)
            .sum::<usize>();
        if total_bytes - previous.map_or(0, |record| record.bytes) + bytes
            > self.limits.max_provenance_bytes
        {
            return Err(BrokerError::Quota);
        }
        let metadata_changed = previous.is_none_or(|record| record.provenance != provenance);
        let version = expected.version.checked_add(1).ok_or(BrokerError::Quota)?;
        let update = self.graph.replace_source(source, documents)?;
        // Graph replacement validates/indexes before mutation. Nothing fallible follows it.
        let changed = metadata_changed || update.inserted + update.replaced + update.removed > 0;
        if changed {
            self.sources.insert(
                source.to_owned(),
                SourceRecord {
                    version,
                    provenance,
                    bytes,
                    expires,
                },
            );
        }
        Ok(SourceReceipt {
            revision: self.revision(source),
            inserted: update.inserted,
            replaced: update.replaced,
            removed: update.removed,
            unchanged: update.unchanged,
        })
    }

    /// Atomically add/remove a host-declared graph relation with source authority checks.
    /// `expected` must name exactly the source of `from`, plus the source of `to` for a
    /// symmetric contradiction. A changed edge advances those source versions, including
    /// change-back. Unlinking remains possible after either endpoint was withdrawn.
    pub fn host_set_edge(
        &mut self,
        from: &str,
        to: &str,
        kind: EdgeKind,
        present: bool,
        expected: &BTreeMap<String, SourceRevision>,
    ) -> Result<BTreeMap<String, SourceRevision>, BrokerError> {
        let endpoints = BTreeMap::from([
            (from.to_owned(), self.node_source(from)?.to_owned()),
            (to.to_owned(), self.node_source(to)?.to_owned()),
        ]);
        let from_source = self.node_source(from)?;
        let mut affected = BTreeSet::from([from_source.to_owned()]);
        if kind == EdgeKind::Contradicts {
            affected.insert(self.node_source(to)?.to_owned());
        }
        if !affected.iter().eq(expected.keys()) {
            return Err(BrokerError::InvalidInput);
        }
        let mut next = BTreeMap::new();
        for source in &affected {
            if expected.get(source) != Some(&self.revision(source)) {
                return Err(BrokerError::Conflict);
            }
            let record = self.sources.get(source).ok_or(BrokerError::Unavailable)?;
            next.insert(
                source.clone(),
                record.version.checked_add(1).ok_or(BrokerError::Quota)?,
            );
        }
        let mut additions = BTreeMap::new();
        if present {
            for (id, source) in &endpoints {
                if let Some(node) = self.edge_nodes.get(id) {
                    node.references.checked_add(1).ok_or(BrokerError::Quota)?;
                } else {
                    additions.insert(id.clone(), measure(&(id, source), 8192)?);
                }
            }
            let retained = self
                .edge_nodes
                .values()
                .map(|node| node.bytes)
                .sum::<usize>();
            if retained + additions.values().sum::<usize>() > self.limits.max_relation_bytes {
                return Err(BrokerError::Quota);
            }
        }
        let changed = if present {
            self.graph.link(from, to, kind)?
        } else {
            self.graph.unlink(from, to, kind)?
        };
        // All authority, counter, identity and graph validation completes before mutation.
        if changed {
            for (id, source) in endpoints {
                if present {
                    let bytes = additions.get(&id).copied().unwrap_or(0);
                    let node = self.edge_nodes.entry(id).or_insert(EdgeNode {
                        source,
                        references: 0,
                        bytes,
                    });
                    node.references += 1;
                } else if let Some(node) = self.edge_nodes.get_mut(&id) {
                    node.references -= 1;
                    if node.references == 0 {
                        self.edge_nodes.remove(&id);
                    }
                }
            }
            for (source, version) in next {
                if let Some(record) = self.sources.get_mut(&source) {
                    record.version = version;
                }
            }
        }
        Ok(affected
            .into_iter()
            .map(|source| {
                let version = self.revision(&source);
                (source, version)
            })
            .collect())
    }

    /// Read only a source assigned to this current agent; never reveals other sources' versions.
    pub fn source_revision(
        &self,
        credential: &BrokerCredential,
        source: &str,
    ) -> Result<SourceRevision, BrokerError> {
        let (_, grant) = self.authorize(credential)?;
        if !grant.spec.view.allowed_sources.contains(source) {
            return Err(BrokerError::AccessDenied);
        }
        Ok(self.revision(source))
    }

    /// Compile the server-owned view, with a bounded owner-bound ticket for later revalidation.
    pub fn compile(
        &mut self,
        credential: &BrokerCredential,
        request: &ContextRequest,
        tokenizer: &impl TokenCounter,
    ) -> Result<BrokerContext, BrokerError> {
        self.prune();
        let (owner, grant) = self.authorize(credential)?;
        if request.max_tokens > grant.spec.limits.max_tokens
            || self.tickets.len() >= self.limits.max_tickets
            || self
                .tickets
                .values()
                .filter(|ticket| ticket.owner == owner)
                .count()
                >= grant.spec.limits.max_tickets
        {
            return Err(BrokerError::Quota);
        }
        self.validate_scope(grant)?;
        let versions = self.scope_versions(grant);
        let authority = digest(
            "cigar.broker-source-authority.v1",
            &(&self.epoch, &versions),
        )?;
        let context = self.views.compile_bound(
            &self.graph,
            &grant.handle,
            request,
            tokenizer,
            Some(&authority),
        )?;
        let bytes = measure(
            &(
                &owner,
                &context,
                &versions,
                &Option::<AnswerSubmission>::None,
            ),
            grant.spec.limits.max_retained_bytes,
        )?;
        self.check_retention(&owner, 0, bytes)?;
        let expires = deadline(grant.spec.limits.ticket_lifetime_ms)?.min(grant.expires);
        let ticket = random_id()?;
        if self.tickets.contains_key(&ticket) {
            return Err(BrokerError::Unavailable);
        }
        let result = BrokerContext {
            ticket: ticket.clone(),
            rendered: context.snapshot().render(),
            context: context.clone(),
        };
        self.tickets.insert(
            ticket,
            Ticket {
                owner,
                context,
                versions,
                expires,
                bytes,
                submission: None,
            },
        );
        Ok(result)
    }

    /// Revalidate authority, provenance, expiry and all readable evidence, not just citations.
    pub fn revalidate(
        &self,
        credential: &BrokerCredential,
        ticket: &str,
        tokenizer: &impl TokenCounter,
    ) -> Result<(), BrokerError> {
        let (owner, _) = self.authorize(credential)?;
        self.current_ticket(&owner, ticket, tokenizer).map(|_| ())
    }

    /// Resolve a selected node's citation only after current ticket/owner validation.
    pub fn citations(
        &self,
        credential: &BrokerCredential,
        ticket: &str,
        node: &str,
        tokenizer: &impl TokenCounter,
    ) -> Result<Vec<Citation>, BrokerError> {
        let (owner, _) = self.authorize(credential)?;
        let ticket = self.current_ticket(&owner, ticket, tokenizer)?;
        let citations = ticket
            .context
            .snapshot()
            .blocks()
            .iter()
            .flat_map(|block| &block.citations)
            .filter(|citation| citation.node_id == node)
            .cloned()
            .collect::<Vec<_>>();
        if citations.is_empty() {
            return Err(BrokerError::AccessDenied);
        }
        Ok(citations)
    }

    /// Release one own ticket and any submitted draft. Never affects another agent's ticket.
    pub fn forget_ticket(
        &mut self,
        credential: &BrokerCredential,
        ticket: &str,
    ) -> Result<(), BrokerError> {
        let (owner, _) = self.authorize(credential)?;
        if self
            .tickets
            .get(ticket)
            .is_none_or(|entry| entry.owner != owner)
        {
            return Err(BrokerError::AccessDenied);
        }
        self.tickets.remove(ticket);
        Ok(())
    }

    /// Stage a proposed source replacement. This method never mutates the evidence graph.
    /// The request key permits querying a lost response; reusing a live key is rejected.
    pub fn propose_source(
        &mut self,
        credential: &BrokerCredential,
        request_key: &str,
        source: &str,
        expected: &SourceRevision,
        documents: Vec<Document>,
    ) -> Result<ProposalStatus, BrokerError> {
        self.prune();
        let (owner, grant) = self.authorize(credential)?;
        if !grant.spec.view.writable_sources.contains(source) {
            return Err(BrokerError::AccessDenied);
        }
        if !crate::graph::valid_id(request_key) {
            return Err(BrokerError::InvalidInput);
        }
        if self.revision(source) != *expected
            || self
                .proposals
                .values()
                .any(|p| p.owner == owner && p.request_key == request_key)
        {
            return Err(BrokerError::Conflict);
        }
        if self.proposals.len() >= self.limits.max_proposals
            || documents.len() > grant.spec.limits.max_proposal_documents
            || self.proposals.values().filter(|p| p.owner == owner).count()
                >= grant.spec.limits.max_proposals
        {
            return Err(BrokerError::Quota);
        }
        // Validate input against an isolated bounded graph. No pending proposal becomes evidence.
        // Reject cross-source collisions without exposing which other source owns an ID.
        self.validate_document_owners(source, &documents)?;
        let bytes = measure(
            &(&owner, request_key, source, expected, &documents),
            grant.spec.limits.max_proposal_bytes,
        )?;
        self.check_retention(&owner, 0, bytes)?;
        let mut validation = ContextGraph::new("proposal-validation", self.graph.limits)?;
        validation.replace_source(source, documents.clone())?;
        let expires = deadline(grant.spec.limits.proposal_lifetime_ms)?.min(grant.expires);
        let proposal_id = random_id()?;
        if self.proposals.contains_key(&proposal_id) {
            return Err(BrokerError::Unavailable);
        }
        let status = ProposalStatus {
            proposal_id: proposal_id.clone(),
            request_key: request_key.to_owned(),
            outcome: ProposalOutcome::Pending,
        };
        self.proposals.insert(
            proposal_id,
            Proposal {
                owner,
                request_key: request_key.to_owned(),
                source: source.to_owned(),
                expected: expected.clone(),
                documents,
                outcome: ProposalOutcome::Pending,
                expires,
                bytes,
            },
        );
        Ok(status)
    }

    /// Inspect an own retained proposal by request key; does not retry or execute it.
    pub fn proposal_status(
        &self,
        credential: &BrokerCredential,
        request_key: &str,
    ) -> Result<ProposalStatus, BrokerError> {
        let (owner, _) = self.authorize(credential)?;
        let (id, proposal) = self
            .proposals
            .iter()
            .find(|(_, proposal)| {
                proposal.owner == owner
                    && proposal.request_key == request_key
                    && proposal.expires > Instant::now()
            })
            .ok_or(BrokerError::AccessDenied)?;
        Ok(ProposalStatus {
            proposal_id: id.clone(),
            request_key: proposal.request_key.clone(),
            outcome: proposal.outcome.clone(),
        })
    }

    /// Discard an own proposal/receipt. A pending proposal then cannot be admitted by the host.
    pub fn forget_proposal(
        &mut self,
        credential: &BrokerCredential,
        request_key: &str,
    ) -> Result<(), BrokerError> {
        let status = self.proposal_status(credential, request_key)?;
        self.proposals.remove(&status.proposal_id);
        Ok(())
    }

    /// Read the exact pending source/expected version/documents through the host review channel.
    /// The returned data is unverified agent material and must be treated as such by the host.
    pub fn host_proposal(
        &self,
        id: &str,
    ) -> Result<(&str, &SourceRevision, &[Document]), BrokerError> {
        let proposal = self.pending_proposal(id)?;
        Ok((&proposal.source, &proposal.expected, &proposal.documents))
    }

    /// Admit an exact pending proposal with host-supplied provenance and a fresh CAS check.
    pub fn host_admit_proposal(
        &mut self,
        id: &str,
        provenance: SourceProvenance,
    ) -> Result<SourceReceipt, BrokerError> {
        if provenance.origin != SourceOrigin::ReviewedProposal {
            return Err(BrokerError::InvalidInput);
        }
        let proposal = self.pending_proposal(id)?;
        let source = proposal.source.clone();
        let expected = proposal.expected.clone();
        let documents = proposal.documents.clone();
        let receipt = self.host_replace_source(&source, &expected, documents, provenance)?;
        // The exclusive owner cannot lose/revoke this proposal between CAS and receipt storage.
        if let Some(proposal) = self.proposals.get_mut(id) {
            proposal.documents.clear();
            proposal.outcome = ProposalOutcome::Admitted {
                receipt: receipt.clone(),
            };
        }
        Ok(receipt)
    }

    /// Reject a live pending proposal. Retain its terminal outcome for explicit reconciliation.
    pub fn host_reject_proposal(&mut self, id: &str) -> Result<(), BrokerError> {
        self.pending_proposal(id)?;
        if let Some(proposal) = self.proposals.get_mut(id) {
            proposal.documents.clear();
            proposal.outcome = ProposalOutcome::Rejected;
        }
        Ok(())
    }

    /// Submit exact claims against a live ticket. There is no client-supplied reviewer verdict.
    /// Replacing a submission changes its ID, preventing review of an unnoticed substituted draft.
    pub fn submit_answer(
        &mut self,
        credential: &BrokerCredential,
        ticket_id: &str,
        draft: AnswerDraft,
        tokenizer: &impl TokenCounter,
    ) -> Result<String, BrokerError> {
        let (owner, grant) = self.authorize(credential)?;
        let ticket = self.current_ticket(&owner, ticket_id, tokenizer)?;
        if draft.snapshot_id != ticket.context.snapshot().id() {
            return Err(BrokerError::Stale);
        }
        draft.review_keys()?;
        let submission = AnswerSubmission {
            submission_id: random_id()?,
            draft,
        };
        let bytes = measure(
            &(
                &owner,
                &ticket.context,
                &ticket.versions,
                &Some(&submission),
            ),
            grant.spec.limits.max_retained_bytes,
        )?;
        self.check_retention(&owner, ticket.bytes, bytes)?;
        let id = submission.submission_id.clone();
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.submission = Some(submission);
            ticket.bytes = bytes;
        }
        Ok(id)
    }

    /// Read the exact current draft through the private host reviewer port.
    pub fn host_submission(
        &self,
        ticket_id: &str,
        tokenizer: &impl TokenCounter,
    ) -> Result<&AnswerSubmission, BrokerError> {
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or(BrokerError::AccessDenied)?;
        self.current_ticket(&ticket.owner, ticket_id, tokenizer)?
            .submission
            .as_ref()
            .ok_or(BrokerError::Stale)
    }

    /// Apply trusted reviews to an exact current submission. This result is transient and grants
    /// no effect authority. Recheck immediately before handing off to an execution authority.
    pub fn host_check_answer(
        &self,
        ticket_id: &str,
        submission_id: &str,
        reviews: &[ClaimReview],
        policy: &AnswerPolicy,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextViewAssessment, BrokerError> {
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or(BrokerError::AccessDenied)?;
        let ticket = self.current_ticket(&ticket.owner, ticket_id, tokenizer)?;
        let submission = ticket
            .submission
            .as_ref()
            .filter(|submission| submission.submission_id == submission_id)
            .ok_or(BrokerError::Stale)?;
        let assessment = self.graph.check_view_snapshot(
            ticket.context.snapshot(),
            &submission.draft,
            reviews,
            policy,
        )?;
        Ok(ContextViewAssessment {
            context_id: ticket.context.id().to_owned(),
            checked_graph_revision: self.graph.revision(),
            assessment,
        })
    }

    fn validate_grant(&self, spec: &AgentGrantSpec) -> Result<(), BrokerError> {
        let limits = spec.limits;
        if spec.lease_ms == 0
            || spec.lease_ms > MAX_LIFETIME_MS
            || limits.ticket_lifetime_ms == 0
            || limits.ticket_lifetime_ms > MAX_LIFETIME_MS
            || limits.proposal_lifetime_ms == 0
            || limits.proposal_lifetime_ms > MAX_LIFETIME_MS
            || limits.max_tokens == 0
            || limits.max_tokens > 1_048_576
            || limits.max_tickets == 0
            || limits.max_tickets > self.limits.max_tickets
            || limits.max_proposals == 0
            || limits.max_proposals > self.limits.max_proposals
            || limits.max_retained_bytes < RECORD_ALLOWANCE
            || limits.max_retained_bytes > self.limits.max_retained_bytes
            || limits.max_proposal_bytes < RECORD_ALLOWANCE
            || limits.max_proposal_bytes > limits.max_retained_bytes
            || limits.max_proposal_documents == 0
            || limits.max_proposal_documents > self.graph.limits.max_documents
        {
            return Err(BrokerError::InvalidInput);
        }
        Ok(())
    }

    fn authorize(&self, credential: &BrokerCredential) -> Result<(String, &Grant), BrokerError> {
        if credential.epoch != self.epoch
            || credential.secret.len() != 64
            || !credential
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BrokerError::AccessDenied);
        }
        // A hash-indexed lookup does not compare attacker-chosen prefixes with a stored secret.
        let owner = secret_key(&credential.secret);
        let grant = self.live_grant(&owner)?;
        Ok((owner, grant))
    }

    fn live_grant(&self, owner: &str) -> Result<&Grant, BrokerError> {
        self.grants
            .get(owner)
            .filter(|grant| grant.expires > Instant::now())
            .ok_or(BrokerError::AccessDenied)
    }

    fn revision(&self, source: &str) -> SourceRevision {
        SourceRevision {
            epoch: self.epoch.clone(),
            version: self.sources.get(source).map_or(0, |record| record.version),
        }
    }

    fn node_source(&self, id: &str) -> Result<&str, BrokerError> {
        self.graph
            .documents
            .get(id)
            .map(|node| node.document.source.as_str())
            .or_else(|| self.edge_nodes.get(id).map(|node| node.source.as_str()))
            .ok_or(BrokerError::InvalidInput)
    }

    fn validate_document_owners(
        &self,
        source: &str,
        documents: &[Document],
    ) -> Result<(), BrokerError> {
        if documents.iter().any(|document| {
            self.node_source(&document.id)
                .is_ok_and(|owner| owner != source)
        }) {
            return Err(BrokerError::AccessDenied);
        }
        Ok(())
    }

    fn validate_provenance(
        &self,
        source: &str,
        provenance: &SourceProvenance,
    ) -> Result<(usize, Option<Instant>), BrokerError> {
        if !valid_label(&provenance.authority)
            || !valid_label(&provenance.upstream_revision)
            || provenance.derived_from.len() > 32
            || provenance
                .valid_until_ms
                .is_some_and(|until| until <= provenance.observed_at_ms)
        {
            return Err(BrokerError::InvalidInput);
        }
        let bytes = measure(&(source, provenance), MAX_PROVENANCE_BYTES)?;
        let now_ms = unix_ms()?;
        let expires = provenance
            .valid_until_ms
            .map(|until| {
                let remaining = until
                    .checked_sub(now_ms)
                    .filter(|remaining| *remaining > 0)
                    .ok_or(BrokerError::Stale)?;
                deadline(remaining)
            })
            .transpose()?;
        let mut seen = BTreeSet::new();
        let mut checked = BTreeSet::new();
        for dependency in &provenance.derived_from {
            if dependency.source == source || !seen.insert(&dependency.source) {
                return Err(BrokerError::InvalidInput);
            }
            if dependency.revision != self.revision(&dependency.source)
                || !self.graph.sources.contains_key(&dependency.source)
            {
                return Err(BrokerError::Stale);
            }
            let mut visiting = BTreeSet::from([source.to_owned()]);
            self.validate_source(&dependency.source, now_ms, &mut visiting, &mut checked)?;
        }
        Ok((bytes, expires))
    }

    fn validate_source(
        &self,
        source: &str,
        now_ms: u64,
        visiting: &mut BTreeSet<String>,
        checked: &mut BTreeSet<String>,
    ) -> Result<(), BrokerError> {
        if checked.contains(source) {
            return Ok(());
        }
        let Some(record) = self.sources.get(source) else {
            return Ok(());
        };
        if !self.graph.sources.contains_key(source) {
            return Ok(());
        }
        // Bound recursion independently of the number of retained sources.
        if visiting.len() >= 64 || !visiting.insert(source.to_owned()) {
            return Err(BrokerError::Stale);
        }
        if record
            .expires
            .is_some_and(|expires| expires <= Instant::now())
            || record
                .provenance
                .valid_until_ms
                .is_some_and(|until| until <= now_ms)
        {
            return Err(BrokerError::Stale);
        }
        for dependency in &record.provenance.derived_from {
            if dependency.revision != self.revision(&dependency.source)
                || !self.graph.sources.contains_key(&dependency.source)
            {
                return Err(BrokerError::Stale);
            }
            self.validate_source(&dependency.source, now_ms, visiting, checked)?;
        }
        visiting.remove(source);
        checked.insert(source.to_owned());
        Ok(())
    }

    fn validate_scope(&self, grant: &Grant) -> Result<(), BrokerError> {
        let now = unix_ms()?;
        let mut checked = BTreeSet::new();
        for source in &grant.spec.view.allowed_sources {
            self.validate_source(source, now, &mut BTreeSet::new(), &mut checked)?;
        }
        Ok(())
    }

    fn scope_versions(&self, grant: &Grant) -> BTreeMap<String, SourceRevision> {
        grant
            .spec
            .view
            .allowed_sources
            .iter()
            .map(|source| (source.clone(), self.revision(source)))
            .collect()
    }

    fn current_ticket(
        &self,
        owner: &str,
        id: &str,
        tokenizer: &impl TokenCounter,
    ) -> Result<&Ticket, BrokerError> {
        let grant = self.live_grant(owner)?;
        let ticket = self
            .tickets
            .get(id)
            .filter(|ticket| ticket.owner == owner && ticket.expires > Instant::now())
            .ok_or(BrokerError::AccessDenied)?;
        self.validate_scope(grant)?;
        if ticket.versions != self.scope_versions(grant) {
            return Err(BrokerError::Stale);
        }
        let authority = digest(
            "cigar.broker-source-authority.v1",
            &(&self.epoch, &ticket.versions),
        )?;
        self.views.revalidate_bound(
            &self.graph,
            &grant.handle,
            &ticket.context,
            tokenizer,
            Some(&authority),
        )?;
        Ok(ticket)
    }

    fn pending_proposal(&self, id: &str) -> Result<&Proposal, BrokerError> {
        let proposal = self
            .proposals
            .get(id)
            .filter(|proposal| proposal.expires > Instant::now())
            .ok_or(BrokerError::AccessDenied)?;
        let grant = self.live_grant(&proposal.owner)?;
        if !grant.spec.view.writable_sources.contains(&proposal.source) {
            return Err(BrokerError::AccessDenied);
        }
        if proposal.outcome != ProposalOutcome::Pending {
            return Err(BrokerError::Conflict);
        }
        Ok(proposal)
    }

    fn check_retention(
        &self,
        owner: &str,
        replacing: usize,
        bytes: usize,
    ) -> Result<(), BrokerError> {
        let grant = self.live_grant(owner)?;
        let entries = self
            .tickets
            .values()
            .map(|ticket| (&ticket.owner, ticket.bytes))
            .chain(
                self.proposals
                    .values()
                    .map(|proposal| (&proposal.owner, proposal.bytes)),
            );
        let (total, own) = entries.fold(
            (0_usize, 0_usize),
            |(total, own), (entry_owner, entry_bytes)| {
                (
                    total + entry_bytes,
                    own + if entry_owner == owner { entry_bytes } else { 0 },
                )
            },
        );
        if total - replacing + bytes > self.limits.max_retained_bytes
            || own - replacing + bytes > grant.spec.limits.max_retained_bytes
        {
            return Err(BrokerError::Quota);
        }
        Ok(())
    }

    fn remove_owner(&mut self, owner: &str) {
        self.grants.remove(owner);
        self.tickets.retain(|_, ticket| ticket.owner != owner);
        self.proposals.retain(|_, proposal| proposal.owner != owner);
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let expired = self
            .grants
            .iter()
            .filter(|(_, grant)| grant.expires <= now)
            .map(|(owner, grant)| (owner.clone(), grant.spec.view.id.clone()))
            .collect::<Vec<_>>();
        for (owner, agent) in expired {
            self.remove_owner(&owner);
            self.views.revoke(&agent);
        }
        self.tickets.retain(|_, ticket| ticket.expires > now);
        self.proposals.retain(|_, proposal| proposal.expires > now);
    }
}

fn valid_source(source: &str) -> Result<(), BrokerError> {
    if source.is_empty() || source.len() > 2048 || source.chars().any(char::is_control) {
        Err(BrokerError::InvalidInput)
    } else {
        Ok(())
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 2048 && !label.chars().any(char::is_control)
}

fn deadline(ms: u64) -> Result<Instant, BrokerError> {
    Instant::now()
        .checked_add(Duration::from_millis(ms))
        .ok_or(BrokerError::InvalidInput)
}

fn unix_ms() -> Result<u64, BrokerError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerError::Unavailable)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| BrokerError::Unavailable)
}

fn random_id() -> Result<String, BrokerError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| BrokerError::Unavailable)?;
    Ok(hex(&bytes))
}

fn secret_key(secret: &str) -> String {
    hex(&Sha256::digest(secret.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Formatting a fixed integer into String cannot fail.
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn measure(value: &impl Serialize, limit: usize) -> Result<usize, BrokerError> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = self
                .bytes
                .checked_add(bytes.len())
                .filter(|count| *count <= self.limit)
                .ok_or_else(|| std::io::Error::other("retention limit"))?;
            self.bytes = count;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Counter {
        bytes: RECORD_ALLOWANCE,
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| BrokerError::Quota)?;
    writer.flush().map_err(|_| BrokerError::Unavailable)?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests;
