//! Host-scoped views over one graph/index. No scheduler, authentication service or new effect journal.
use crate::{
    AnswerAssessment, AnswerDraft, AnswerPolicy, ClaimReview, ContextError, ContextGraph,
    ContextRequest, ContextSnapshot, Document, SelectionExplanation, SelectionStep, SourceUpdate,
    TokenCounter, digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_VIEWS: usize = 128;
const MAX_SOURCES: usize = 256;

/// Host-owned scope. Source locators are application metadata, not authenticated identities.
/// Keep definition/revocation and the root graph handle outside untrusted agent control.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextViewSpec {
    /// Stable host-assigned agent or task scope name.
    pub id: String,
    /// Exact source locators readable through this view; empty means no access.
    pub allowed_sources: BTreeSet<String>,
    /// Exact source locators replaceable through this view; must be readable too.
    #[serde(default)]
    pub writable_sources: BTreeSet<String>,
    /// Host-owned current authorization/policy epoch. It overrides request policy metadata.
    pub policy_revision: String,
}

/// A live generation prevents use of a superseded/revoked view in this worker session.
/// This is a routing handle, not a bearer credential or a signed capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextViewHandle {
    /// Host-assigned scope name.
    pub id: String,
    /// Monotonically increasing within the owning worker session.
    pub generation: u64,
}

/// Original context plus an independently versioned scope commitment.
/// The legacy snapshot and claim-review keys retain their original exact identities.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextView {
    id: String,
    view: ContextViewHandle,
    request: ContextRequest,
    scope_id: String,
    snapshot: ContextSnapshot,
}

impl std::fmt::Debug for ContextView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextView").finish_non_exhaustive()
    }
}

impl ContextView {
    /// Commitment to the exact scope, request and original legacy snapshot.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Original snapshot supplied to the generator and reviewer.
    #[must_use]
    pub const fn snapshot(&self) -> &ContextSnapshot {
        &self.snapshot
    }

    fn commitment(&self) -> Result<String, ContextError> {
        digest(
            "cigar.context-view.v1",
            &(
                &self.view,
                &self.request,
                &self.scope_id,
                self.snapshot.id(),
            ),
        )
    }
}

/// Transient checked result, not a signature, durable approval, or permission for an effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextViewAssessment {
    /// Exact original view context assessed.
    pub context_id: String,
    /// Current graph revision at atomic in-process assessment.
    pub checked_graph_revision: u64,
    /// Existing answer assessment, bound to the original snapshot and reviews.
    pub assessment: AnswerAssessment,
}

struct Entry {
    handle: ContextViewHandle,
    spec: ContextViewSpec,
}

/// Bounded view definitions for a single host-owned graph. Stores no duplicate documents.
#[derive(Default)]
pub struct ContextViews {
    generation: u64,
    entries: BTreeMap<String, Entry>,
}

impl ContextViews {
    /// Define or replace a host-owned scope. Every replacement invalidates its old handles.
    pub fn define(&mut self, spec: ContextViewSpec) -> Result<ContextViewHandle, ContextError> {
        if !crate::graph::valid_id(&spec.id)
            || spec.allowed_sources.len() > MAX_SOURCES
            || !spec.writable_sources.is_subset(&spec.allowed_sources)
            || spec.allowed_sources.iter().any(|source| {
                source.is_empty() || source.len() > 2048 || source.chars().any(char::is_control)
            })
            || spec.policy_revision.is_empty()
            || spec.policy_revision.len() > 256
        {
            return Err(ContextError::InvalidInput);
        }
        if !self.entries.contains_key(&spec.id) && self.entries.len() >= MAX_VIEWS {
            return Err(ContextError::LimitExceeded);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(ContextError::LimitExceeded)?;
        let handle = ContextViewHandle {
            id: spec.id.clone(),
            generation: self.generation,
        };
        self.entries.insert(
            spec.id.clone(),
            Entry {
                handle: handle.clone(),
                spec,
            },
        );
        Ok(handle)
    }

    /// Revoke a scope. Existing context cannot be used through that view afterward.
    pub fn revoke(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
    }

    fn entry(&self, handle: &ContextViewHandle) -> Result<&Entry, ContextError> {
        self.entries
            .get(&handle.id)
            .filter(|entry| entry.handle == *handle)
            .ok_or(ContextError::RequiredUnavailable)
    }

    /// Compile against current authorized sources. Request `allowed` may only narrow access.
    pub fn compile(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        request: &ContextRequest,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextView, ContextError> {
        self.compile_bound(graph, handle, request, tokenizer, None)
    }

    // The broker binds epoch and source authority into the existing snapshot/review chain.
    // None preserves ordinary view identities and serialized shapes byte-for-byte.
    pub(crate) fn compile_bound(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        request: &ContextRequest,
        tokenizer: &impl TokenCounter,
        authority: Option<&str>,
    ) -> Result<ContextView, ContextError> {
        self.compile_traced(graph, handle, request, tokenizer, authority, None)
    }

    #[allow(clippy::too_many_arguments)] // Optional observation of the unchanged selection path.
    fn compile_traced(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        request: &ContextRequest,
        tokenizer: &impl TokenCounter,
        authority: Option<&str>,
        trace: Option<&mut Vec<SelectionStep>>,
    ) -> Result<ContextView, ContextError> {
        let entry = self.entry(handle)?;
        let authorized = authorized_nodes(graph, &entry.spec);
        let mut scope_id = scope_id(graph, entry, &authorized)?;
        if let Some(authority) = authority {
            scope_id = digest("cigar.context-view-authority.v1", &(&scope_id, authority))?;
        }
        let scoped = scoped_request(request, &scope_id, &authorized);
        let snapshot = graph.compile_traced(&scoped, tokenizer, trace)?;
        let mut context = ContextView {
            id: String::new(),
            view: handle.clone(),
            request: request.clone(),
            scope_id,
            snapshot,
        };
        context.id = context.commitment()?;
        Ok(context)
    }

    /// Atomic replacement restricted to a writable source, including cross-source ID collisions.
    pub fn replace_source(
        &self,
        graph: &mut ContextGraph,
        handle: &ContextViewHandle,
        source: &str,
        documents: Vec<Document>,
    ) -> Result<SourceUpdate, ContextError> {
        let entry = self.entry(handle)?;
        if !entry.spec.writable_sources.contains(source)
            || documents.iter().any(|doc| {
                doc.source != source
                    || graph
                        .documents
                        .get(&doc.id)
                        .is_some_and(|old| old.document.source != source)
            })
        {
            return Err(ContextError::RequiredUnavailable);
        }
        graph.replace_source(source, documents)
    }

    /// Freshly validate the whole readable scope and recompile before applying trusted reviews.
    /// Alpha policy is conservative: ANY authorized document/edge change requires a new review,
    /// including unselected evidence. Unrelated writes outside this view do not invalidate it.
    #[allow(clippy::too_many_arguments)] // Same review contract plus explicit graph/view ownership.
    pub fn check_answer(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        context: &ContextView,
        draft: &AnswerDraft,
        reviews: &[ClaimReview],
        policy: &AnswerPolicy,
        tokenizer: &impl TokenCounter,
    ) -> Result<ContextViewAssessment, ContextError> {
        self.revalidate(graph, handle, context, tokenizer)?;
        let assessment = graph.check_view_snapshot(&context.snapshot, draft, reviews, policy)?;
        Ok(ContextViewAssessment {
            context_id: context.id.clone(),
            checked_graph_revision: graph.revision(),
            assessment,
        })
    }

    // Shared freshness check for the ordinary trusted-host view and the opt-in broker.
    // Never substitute snapshot integrity alone for current authorization and evidence.
    pub(crate) fn revalidate(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        context: &ContextView,
        tokenizer: &impl TokenCounter,
    ) -> Result<(), ContextError> {
        self.revalidate_bound(graph, handle, context, tokenizer, None)
    }

    pub(crate) fn revalidate_bound(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        context: &ContextView,
        tokenizer: &impl TokenCounter,
        authority: Option<&str>,
    ) -> Result<(), ContextError> {
        self.revalidate_traced(graph, handle, context, tokenizer, authority, None)
    }

    /// Reconstruct only successful selection steps after checking the current whole scope.
    /// Revocation and any in-scope change invalidate the explanation, including unselected data.
    pub fn explain(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        context: &ContextView,
        tokenizer: &impl TokenCounter,
    ) -> Result<SelectionExplanation, ContextError> {
        self.explain_bound(graph, handle, context, tokenizer, None)
    }

    pub(crate) fn explain_bound(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        context: &ContextView,
        tokenizer: &impl TokenCounter,
        authority: Option<&str>,
    ) -> Result<SelectionExplanation, ContextError> {
        let mut steps = Vec::new();
        self.revalidate_traced(
            graph,
            handle,
            context,
            tokenizer,
            authority,
            Some(&mut steps),
        )?;
        SelectionExplanation::new(
            &context.snapshot,
            &context.request,
            graph.revision(),
            tokenizer,
            steps,
        )
    }

    #[allow(clippy::too_many_arguments)] // Current-state checks plus an optional trace observer.
    fn revalidate_traced(
        &self,
        graph: &ContextGraph,
        handle: &ContextViewHandle,
        context: &ContextView,
        tokenizer: &impl TokenCounter,
        authority: Option<&str>,
        trace: Option<&mut Vec<SelectionStep>>,
    ) -> Result<(), ContextError> {
        self.entry(handle)?;
        if context.view != *handle {
            return Err(ContextError::BaseMismatch);
        }
        context.snapshot.verify(tokenizer)?;
        if context.id != context.commitment()? {
            return Err(ContextError::Integrity);
        }
        let current =
            self.compile_traced(graph, handle, &context.request, tokenizer, authority, trace)?;
        if context.scope_id != current.scope_id
            || !context.snapshot.same_view_evidence(&current.snapshot)
        {
            return Err(ContextError::BaseMismatch);
        }
        Ok(())
    }
}

fn authorized_nodes(graph: &ContextGraph, spec: &ContextViewSpec) -> BTreeSet<String> {
    spec.allowed_sources
        .iter()
        .filter_map(|source| graph.sources.get(source))
        .flat_map(|ids| ids.iter().cloned())
        .collect()
}

fn scoped_request(
    request: &ContextRequest,
    scope_id: &str,
    authorized: &BTreeSet<String>,
) -> ContextRequest {
    let mut scoped = request.clone();
    scoped.allowed = Some(
        authorized
            .iter()
            .filter(|id| {
                request
                    .allowed
                    .as_ref()
                    .is_none_or(|narrowed| narrowed.contains(*id))
            })
            .cloned()
            .collect(),
    );
    // Bind the entire authorized scope into the EXISTING snapshot/review-key chain.
    // Changing a public envelope digest cannot rebind an old review to new authority/data.
    scoped.policy_revision = scope_id.to_owned();
    scoped
}

fn scope_id(
    graph: &ContextGraph,
    entry: &Entry,
    authorized: &BTreeSet<String>,
) -> Result<String, ContextError> {
    let documents = authorized
        .iter()
        .filter_map(|id| graph.documents.get(id).map(|doc| (id, &doc.digest)))
        .collect::<Vec<_>>();
    let edges = authorized
        .iter()
        .filter_map(|id| graph.edges.get(id).map(|edges| (id, edges)))
        .collect::<Vec<_>>();
    digest(
        "cigar.context-view-scope.v1",
        &(&graph.domain, &entry.handle, &entry.spec, documents, edges),
    )
}
