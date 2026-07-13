//! Thread-safe in-process reference service for context-space semantics.

use crate::{
    AcquireLeaseRequest, ConflictResolutionReceipt, EventCursor, EventPage, FencedLease,
    FocusBranch, LeaseMutationRequest, MAX_EVENT_PAGE, MAX_FOCUS_BRANCHES, MAX_SPACE_CONFLICTS,
    MAX_SPACE_OVERLAYS, MAX_SPACE_PROJECTS, MergeConflict, OverlayState, ProjectContribution,
    ProjectLink, ProjectLinkPreview, ProposedMutation, PublishOutcome, PublishRequest,
    ResolveConflictRequest, ResolverKind, ResourceKey, SpaceError, SpaceEvent, SpaceHierarchy,
    SpaceView, StoredMergeConflict, mutation_version,
};
use cigar_canon::parse_strict_json;
use cigar_protocol::{
    ContentDigest, ContextCommit, ContextSpaceId, CoordinationEvent, CoordinationEventKind,
    ExpectedRevision, ExtensionMap, Lease, LeaseState, Overlay, OverlayMutation, RecordId,
    SchemaVersion, UtcTimestamp, Validate, VersionId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SpaceState {
    hierarchy: SpaceHierarchy,
    head: ContextCommit,
    history: BTreeMap<VersionId, ContextCommit>,
    snapshots: BTreeMap<VersionId, BTreeMap<ResourceKey, OverlayMutation>>,
    resources: BTreeMap<ResourceKey, OverlayMutation>,
    overlays: BTreeMap<RecordId, OverlayState>,
    #[serde(default)]
    conflicts: BTreeMap<RecordId, StoredMergeConflict>,
    #[serde(default)]
    conflict_resolutions: BTreeMap<RecordId, ConflictResolutionReceipt>,
    events: Vec<SpaceEvent>,
    leases: BTreeMap<VersionId, FencedLease>,
    fencing: BTreeMap<VersionId, u64>,
    focus_branches: BTreeMap<RecordId, FocusBranch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_focus: Option<RecordId>,
    project_links: Vec<ProjectLink>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SpaceSnapshot {
    schema_version: String,
    spaces: BTreeMap<ContextSpaceId, SpaceState>,
}

const SPACE_SNAPSHOT_SCHEMA: &str = "cigar.context-space-snapshot.v1";

/// Cloneable thread-safe context-space service.
#[derive(Clone, Default)]
pub struct ContextSpaceService {
    spaces: Arc<RwLock<BTreeMap<ContextSpaceId, SpaceState>>>,
}

impl std::fmt::Debug for ContextSpaceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.spaces.read().map_or(0, |spaces| spaces.len());
        formatter
            .debug_struct("ContextSpaceService")
            .field("space_count", &count)
            .finish()
    }
}

impl ContextSpaceService {
    /// Creates an empty service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes the complete validated service state for an atomic durable publication.
    pub fn export_snapshot(&self) -> Result<Vec<u8>, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        validate_snapshot(&spaces)?;
        serde_json::to_vec(&SpaceSnapshot {
            schema_version: SPACE_SNAPSHOT_SCHEMA.to_owned(),
            spaces: spaces.clone(),
        })
        .map_err(|_error| SpaceError::Integrity)
    }

    /// Restores a strict complete snapshot without substituting current or partial state.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, SpaceError> {
        parse_strict_json(bytes).map_err(|_error| SpaceError::Integrity)?;
        let snapshot: SpaceSnapshot =
            serde_json::from_slice(bytes).map_err(|_error| SpaceError::Integrity)?;
        if snapshot.schema_version != SPACE_SNAPSHOT_SCHEMA {
            return Err(SpaceError::Integrity);
        }
        validate_snapshot(&snapshot.spaces)?;
        Ok(Self {
            spaces: Arc::new(RwLock::new(snapshot.spaces)),
        })
    }

    /// Creates a context space and its immutable sequence-one commit.
    pub fn create_space(
        &self,
        request: crate::CreateSpaceRequest,
    ) -> Result<ContextCommit, SpaceError> {
        validate_text(&request.purpose)?;
        let resources = BTreeMap::new();
        let root_digest = semantic_digest(&resources)?;
        let event = CoordinationEvent {
            event_id: request.event_id,
            kind: CoordinationEventKind::ContextCommitted,
            payload_digest: root_digest.clone(),
        };
        let commit = build_commit(
            request.space_id.clone(),
            1,
            None,
            request.author_id,
            request.purpose,
            vec![event.clone()],
            root_digest,
            request.policy_snapshot_digest,
            request.committed_at,
        )?;
        let space_event = SpaceEvent {
            cursor: EventCursor(1),
            space_id: request.space_id.clone(),
            project_id: request.hierarchy.active_project_id.clone(),
            event,
        };
        let mut history = BTreeMap::new();
        history.insert(commit.commit_id.clone(), commit.clone());
        let mut snapshots = BTreeMap::new();
        snapshots.insert(commit.commit_id.clone(), resources.clone());
        let state = SpaceState {
            hierarchy: request.hierarchy,
            head: commit.clone(),
            history,
            snapshots,
            resources,
            overlays: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            conflict_resolutions: BTreeMap::new(),
            events: vec![space_event],
            leases: BTreeMap::new(),
            fencing: BTreeMap::new(),
            focus_branches: BTreeMap::new(),
            active_focus: None,
            project_links: Vec::new(),
        };
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        if spaces.contains_key(&request.space_id) {
            return Err(SpaceError::Conflict);
        }
        spaces.insert(request.space_id, state);
        Ok(commit)
    }

    /// Returns the current immutable head.
    pub fn head(&self, space_id: &ContextSpaceId) -> Result<ContextCommit, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        Ok(spaces
            .get(space_id)
            .ok_or(SpaceError::NotFound)?
            .head
            .clone())
    }

    /// Returns the immutable active-project binding used to authorize an existing space.
    ///
    /// The hierarchy is fixed at space creation. Callers must resolve this server-owned value
    /// before authorizing any operation addressed only by a space identifier.
    pub fn active_project_id(&self, space_id: &ContextSpaceId) -> Result<RecordId, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        Ok(spaces
            .get(space_id)
            .ok_or(SpaceError::NotFound)?
            .hierarchy
            .active_project_id
            .clone())
    }

    /// Returns the complete immutable commit log in ascending sequence order.
    pub fn log(&self, space_id: &ContextSpaceId) -> Result<Vec<ContextCommit>, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get(space_id).ok_or(SpaceError::NotFound)?;
        let mut commits: Vec<_> = state.history.values().cloned().collect();
        commits.sort_by_key(|commit| commit.sequence);
        Ok(commits)
    }

    /// Creates an empty private overlay over any retained immutable commit.
    pub fn create_overlay(&self, overlay: Overlay) -> Result<(), SpaceError> {
        self.create_overlay_inner(overlay, None)
    }

    /// Creates an empty private overlay only while the canonical head has the expected sequence.
    pub fn create_overlay_at_revision(
        &self,
        overlay: Overlay,
        expected_head: ExpectedRevision,
    ) -> Result<(), SpaceError> {
        self.create_overlay_inner(overlay, Some(expected_head))
    }

    fn create_overlay_inner(
        &self,
        overlay: Overlay,
        expected_head: Option<ExpectedRevision>,
    ) -> Result<(), SpaceError> {
        overlay
            .validate()
            .map_err(|_error| SpaceError::InvalidInput)?;
        if !overlay.mutations.is_empty() {
            return Err(SpaceError::InvalidInput);
        }
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces
            .get_mut(&overlay.space_id)
            .ok_or(SpaceError::NotFound)?;
        if expected_head.is_some_and(|expected| expected.0 != state.head.sequence) {
            return Err(SpaceError::StaleRevision);
        }
        if state.overlays.len() >= MAX_SPACE_OVERLAYS {
            return Err(SpaceError::LimitExceeded);
        }
        let base_resources = state
            .snapshots
            .get(&overlay.base_commit_id)
            .cloned()
            .ok_or(SpaceError::NotFound)?;
        if state.overlays.contains_key(&overlay.overlay_id) {
            return Err(SpaceError::Conflict);
        }
        state.overlays.insert(
            overlay.overlay_id.clone(),
            OverlayState {
                protocol: overlay,
                base_resources,
                proposals: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Adds or replaces one private proposal after exact owner verification.
    pub fn propose(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        actor_id: &RecordId,
        proposal: ProposedMutation,
    ) -> Result<(), SpaceError> {
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        let overlay = private_overlay_mut(state, overlay_id, actor_id)?;
        overlay.proposals.insert(proposal.key, proposal.mutation);
        overlay.protocol.mutations = overlay.proposals.values().cloned().collect();
        overlay
            .protocol
            .validate()
            .map_err(|_error| SpaceError::InvalidInput)
    }

    /// Returns a base-only view or one exact owner's private overlay view.
    pub fn view(
        &self,
        space_id: &ContextSpaceId,
        actor_id: &RecordId,
        overlay_id: Option<&RecordId>,
    ) -> Result<SpaceView, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get(space_id).ok_or(SpaceError::NotFound)?;
        let Some(overlay_id) = overlay_id else {
            return Ok(SpaceView {
                base: state.head.clone(),
                overlay: None,
                resources: resource_vec(&state.resources),
            });
        };
        let overlay = private_overlay(state, overlay_id, actor_id)?;
        let mut resources = overlay.base_resources.clone();
        resources.extend(overlay.proposals.clone());
        let base = state
            .history
            .get(&overlay.protocol.base_commit_id)
            .cloned()
            .ok_or(SpaceError::Integrity)?;
        Ok(SpaceView {
            base,
            overlay: Some(overlay.protocol.clone()),
            resources: resource_vec(&resources),
        })
    }

    /// Discards a private overlay without changing canonical history.
    pub fn discard_overlay(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        actor_id: &RecordId,
    ) -> Result<(), SpaceError> {
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        private_overlay(state, overlay_id, actor_id)?;
        state.overlays.remove(overlay_id);
        state
            .conflicts
            .retain(|_conflict_id, conflict| &conflict.overlay_id != overlay_id);
        Ok(())
    }

    /// Performs an optimistic deterministic three-way merge and immutable publication.
    pub fn publish(
        &self,
        space_id: &ContextSpaceId,
        overlay_id: &RecordId,
        request: PublishRequest,
    ) -> Result<PublishOutcome, SpaceError> {
        validate_text(&request.purpose)?;
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        if request.expected_head.0 != state.head.sequence {
            return Err(SpaceError::StaleRevision);
        }
        let overlay = private_overlay(state, overlay_id, &request.actor_id)?.clone();
        if request.committed_at >= overlay.protocol.expires_at {
            return Err(SpaceError::Forbidden);
        }
        let conflicts = find_conflicts(&overlay, &state.resources);
        if !conflicts.is_empty() {
            state
                .conflicts
                .retain(|_conflict_id, conflict| conflict.overlay_id != *overlay_id);
            if state
                .conflicts
                .len()
                .saturating_add(state.conflict_resolutions.len())
                .saturating_add(conflicts.len())
                > MAX_SPACE_CONFLICTS
            {
                return Err(SpaceError::LimitExceeded);
            }
            for conflict in &conflicts {
                let stored = stored_conflict(
                    space_id,
                    overlay_id,
                    &state.head.commit_id,
                    conflict.clone(),
                )?;
                state.conflicts.insert(stored.conflict_id.clone(), stored);
            }
            return Ok(PublishOutcome::Conflicted(conflicts));
        }
        let mut merged = state.resources.clone();
        let mut changed = false;
        for (key, proposed) in &overlay.proposals {
            if merged.get(key) != Some(proposed) {
                merged.insert(key.clone(), proposed.clone());
                changed = true;
            }
        }
        state.overlays.remove(overlay_id);
        state
            .conflicts
            .retain(|_conflict_id, conflict| conflict.overlay_id != *overlay_id);
        if !changed {
            return Ok(PublishOutcome::Deduplicated(state.head.clone()));
        }
        let root_digest = semantic_digest(&merged)?;
        let event = CoordinationEvent {
            event_id: request.event_id,
            kind: CoordinationEventKind::ContextCommitted,
            payload_digest: root_digest.clone(),
        };
        let sequence = state
            .head
            .sequence
            .checked_add(1)
            .ok_or(SpaceError::LimitExceeded)?;
        let commit = build_commit(
            space_id.clone(),
            sequence,
            Some(state.head.commit_id.clone()),
            request.actor_id,
            request.purpose,
            vec![event.clone()],
            root_digest,
            request.policy_snapshot_digest,
            request.committed_at,
        )?;
        state.resources = merged.clone();
        state.head = commit.clone();
        state
            .history
            .insert(commit.commit_id.clone(), commit.clone());
        state.snapshots.insert(commit.commit_id.clone(), merged);
        let cursor = u64::try_from(state.events.len())
            .map_err(|_error| SpaceError::LimitExceeded)?
            .checked_add(1)
            .ok_or(SpaceError::LimitExceeded)?;
        state.events.push(SpaceEvent {
            cursor: EventCursor(cursor),
            space_id: space_id.clone(),
            project_id: state.hierarchy.active_project_id.clone(),
            event,
        });
        Ok(PublishOutcome::Published(commit))
    }

    /// Lists durable unresolved conflicts visible to one exact private-overlay owner.
    pub fn list_conflicts(
        &self,
        space_id: &ContextSpaceId,
        actor_id: &RecordId,
    ) -> Result<Vec<StoredMergeConflict>, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get(space_id).ok_or(SpaceError::NotFound)?;
        Ok(state
            .conflicts
            .values()
            .filter(|conflict| {
                state
                    .overlays
                    .get(&conflict.overlay_id)
                    .is_some_and(|overlay| &overlay.protocol.owner_id == actor_id)
            })
            .cloned()
            .collect())
    }

    /// Resolves one durable conflict into its private overlay without implicitly publishing it.
    pub fn resolve_conflict(
        &self,
        space_id: &ContextSpaceId,
        conflict_id: &RecordId,
        request: ResolveConflictRequest,
    ) -> Result<ConflictResolutionReceipt, SpaceError> {
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        let stored = state
            .conflicts
            .get(conflict_id)
            .cloned()
            .ok_or(SpaceError::NotFound)?;
        if request.expected_head.0 != state.head.sequence
            || stored.observed_head_id != state.head.commit_id
        {
            return Err(SpaceError::StaleRevision);
        }
        private_overlay(state, &stored.overlay_id, &request.actor_id)?;
        if request.resolver != stored.conflict.required_resolver
            || !resolver_accepts(request.resolver, &stored.conflict, &request.resolution)
            || request.resolved_at < state.head.committed_at
            || request.evidence.is_empty()
            || request.evidence.len() > 1_024
            || !strictly_sorted(&request.evidence)
            || stored
                .conflict
                .evidence
                .iter()
                .any(|evidence| request.evidence.binary_search(evidence).is_err())
        {
            return Err(SpaceError::InvalidInput);
        }
        let overlay = private_overlay_mut(state, &stored.overlay_id, &request.actor_id)?;
        match &stored.conflict.current {
            Some(current) => {
                overlay
                    .base_resources
                    .insert(stored.conflict.key.clone(), current.clone());
            }
            None => {
                overlay.base_resources.remove(&stored.conflict.key);
            }
        }
        overlay
            .proposals
            .insert(stored.conflict.key.clone(), request.resolution.clone());
        overlay.protocol.mutations = overlay.proposals.values().cloned().collect();
        overlay
            .protocol
            .validate()
            .map_err(|_error| SpaceError::InvalidInput)?;
        let receipt = ConflictResolutionReceipt {
            conflict_id: stored.conflict_id.clone(),
            overlay_id: stored.overlay_id,
            actor_id: request.actor_id,
            resolution: request.resolution,
            evidence: request.evidence,
            policy_snapshot_digest: request.policy_snapshot_digest,
            resolved_at: request.resolved_at,
        };
        if !state.conflict_resolutions.contains_key(conflict_id)
            && state
                .conflicts
                .len()
                .saturating_add(state.conflict_resolutions.len())
                >= MAX_SPACE_CONFLICTS
        {
            return Err(SpaceError::LimitExceeded);
        }
        state.conflicts.remove(conflict_id);
        state
            .conflict_resolutions
            .insert(conflict_id.clone(), receipt.clone());
        Ok(receipt)
    }

    /// Polls a stable scoped at-least-once stream after the last acknowledged visible cursor.
    pub fn poll_events(
        &self,
        space_id: &ContextSpaceId,
        authorized_projects: &BTreeSet<RecordId>,
        after: EventCursor,
        limit: usize,
    ) -> Result<EventPage, SpaceError> {
        if limit == 0 || limit > MAX_EVENT_PAGE {
            return Err(SpaceError::InvalidInput);
        }
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get(space_id).ok_or(SpaceError::NotFound)?;
        let start = usize::try_from(after.0).map_err(|_error| SpaceError::InvalidInput)?;
        if start > state.events.len() {
            return Err(SpaceError::InvalidInput);
        }
        let mut events = Vec::new();
        let mut scanned = start;
        let mut has_more = false;
        for event in state.events.iter().skip(start) {
            if authorized_projects.contains(&event.project_id) {
                if events.len() == limit {
                    has_more = true;
                    break;
                }
                events.push(event.clone());
            }
            scanned = scanned.checked_add(1).ok_or(SpaceError::LimitExceeded)?;
        }
        let resume_cursor =
            EventCursor(u64::try_from(scanned).map_err(|_error| SpaceError::LimitExceeded)?);
        Ok(EventPage {
            has_more,
            events,
            resume_cursor,
        })
    }

    /// Resolves a visible immutable event identity to its monotonic resume cursor.
    pub fn event_cursor_for_id(
        &self,
        space_id: &ContextSpaceId,
        authorized_projects: &BTreeSet<RecordId>,
        event_id: &RecordId,
    ) -> Result<EventCursor, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get(space_id).ok_or(SpaceError::NotFound)?;
        state
            .events
            .iter()
            .find(|event| {
                &event.event.event_id == event_id && authorized_projects.contains(&event.project_id)
            })
            .map(|event| event.cursor)
            .ok_or(SpaceError::NotFound)
    }

    /// Appends a resource-neutral immutable commit of prioritized system events.
    pub fn append_events(
        &self,
        space_id: &ContextSpaceId,
        project_id: RecordId,
        request: PublishRequest,
        mut events: Vec<CoordinationEvent>,
    ) -> Result<ContextCommit, SpaceError> {
        validate_text(&request.purpose)?;
        if events.is_empty() || events.len() > 1_024 {
            return Err(SpaceError::InvalidInput);
        }
        events.sort_by(|left, right| {
            event_priority(left.kind)
                .cmp(&event_priority(right.kind))
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        let mut ids: Vec<_> = events.iter().map(|event| &event.event_id).collect();
        ids.sort();
        ids.dedup();
        if ids.len() != events.len() {
            return Err(SpaceError::InvalidInput);
        }
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        if request.expected_head.0 != state.head.sequence {
            return Err(SpaceError::StaleRevision);
        }
        let sequence = state
            .head
            .sequence
            .checked_add(1)
            .ok_or(SpaceError::LimitExceeded)?;
        let commit = build_commit(
            space_id.clone(),
            sequence,
            Some(state.head.commit_id.clone()),
            request.actor_id,
            request.purpose,
            events.clone(),
            state.head.root_digest.clone(),
            request.policy_snapshot_digest,
            request.committed_at,
        )?;
        state.head = commit.clone();
        state
            .history
            .insert(commit.commit_id.clone(), commit.clone());
        state
            .snapshots
            .insert(commit.commit_id.clone(), state.resources.clone());
        for event in events {
            let cursor = u64::try_from(state.events.len())
                .map_err(|_error| SpaceError::LimitExceeded)?
                .checked_add(1)
                .ok_or(SpaceError::LimitExceeded)?;
            state.events.push(SpaceEvent {
                cursor: EventCursor(cursor),
                space_id: space_id.clone(),
                project_id: project_id.clone(),
                event,
            });
        }
        Ok(commit)
    }

    /// Acquires an advisory lease with a monotonically increasing resource fence.
    pub fn acquire_lease(
        &self,
        space_id: &ContextSpaceId,
        request: AcquireLeaseRequest,
    ) -> Result<FencedLease, SpaceError> {
        if request.expires_at <= request.acquired_at {
            return Err(SpaceError::InvalidInput);
        }
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        if state
            .leases
            .get(&request.resource_id)
            .is_some_and(|current| {
                current.lease.state == LeaseState::Active
                    && request.acquired_at < current.lease.expires_at
            })
        {
            return Err(SpaceError::Conflict);
        }
        let fencing_token = state
            .fencing
            .get(&request.resource_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SpaceError::LimitExceeded)?;
        let lease = Lease {
            schema_version: SchemaVersion::new("cigar.lease", 1)
                .map_err(|_error| SpaceError::Integrity)?,
            lease_id: request.lease_id,
            resource_id: request.resource_id.clone(),
            holder_id: request.holder_id,
            kind: request.kind,
            state: LeaseState::Active,
            acquired_at: request.acquired_at,
            expires_at: request.expires_at,
            expected_revision: ExpectedRevision(1),
        };
        lease
            .validate()
            .map_err(|_error| SpaceError::InvalidInput)?;
        let fenced = FencedLease {
            lease,
            fencing_token,
        };
        state
            .fencing
            .insert(request.resource_id.clone(), fencing_token);
        state.leases.insert(request.resource_id, fenced.clone());
        Ok(fenced)
    }

    /// Renews a current lease after exact holder, fence, revision, and expiry checks.
    pub fn renew_lease(
        &self,
        space_id: &ContextSpaceId,
        resource_id: &VersionId,
        request: LeaseMutationRequest,
    ) -> Result<FencedLease, SpaceError> {
        let expires_at = request.expires_at.ok_or(SpaceError::InvalidInput)?;
        if expires_at <= request.now {
            return Err(SpaceError::InvalidInput);
        }
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        let lease = state
            .leases
            .get_mut(resource_id)
            .ok_or(SpaceError::NotFound)?;
        verify_lease_mutation(lease, &request)?;
        lease.lease.expires_at = expires_at;
        lease.lease.expected_revision.0 = lease
            .lease
            .expected_revision
            .0
            .checked_add(1)
            .ok_or(SpaceError::LimitExceeded)?;
        Ok(lease.clone())
    }

    /// Releases a current lease while retaining its fence against stale holders.
    pub fn release_lease(
        &self,
        space_id: &ContextSpaceId,
        resource_id: &VersionId,
        request: LeaseMutationRequest,
    ) -> Result<FencedLease, SpaceError> {
        if request.expires_at.is_some() {
            return Err(SpaceError::InvalidInput);
        }
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        let lease = state
            .leases
            .get_mut(resource_id)
            .ok_or(SpaceError::NotFound)?;
        verify_lease_mutation(lease, &request)?;
        lease.lease.state = LeaseState::Released;
        lease.lease.expected_revision.0 = lease
            .lease
            .expected_revision
            .0
            .checked_add(1)
            .ok_or(SpaceError::LimitExceeded)?;
        Ok(lease.clone())
    }

    /// Verifies that a holder still owns the current active unexpired fence.
    pub fn verify_fence(
        &self,
        space_id: &ContextSpaceId,
        resource_id: &VersionId,
        holder_id: &RecordId,
        fencing_token: u64,
        now: &UtcTimestamp,
    ) -> Result<(), SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let lease = spaces
            .get(space_id)
            .and_then(|state| state.leases.get(resource_id))
            .ok_or(SpaceError::NotFound)?;
        if lease.lease.state != LeaseState::Active
            || &lease.lease.holder_id != holder_id
            || lease.fencing_token != fencing_token
            || now >= &lease.lease.expires_at
        {
            Err(SpaceError::Conflict)
        } else {
            Ok(())
        }
    }

    /// Forks a resumable focus branch from the current head.
    pub fn fork_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: RecordId,
        label: impl Into<String>,
        offline: bool,
    ) -> Result<FocusBranch, SpaceError> {
        self.fork_focus_inner(space_id, branch_id, label.into(), offline, None)
    }

    /// Forks a focus branch atomically against an exact canonical-head sequence.
    pub fn fork_focus_at_revision(
        &self,
        space_id: &ContextSpaceId,
        branch_id: RecordId,
        label: impl Into<String>,
        offline: bool,
        expected_head: ExpectedRevision,
    ) -> Result<FocusBranch, SpaceError> {
        self.fork_focus_inner(
            space_id,
            branch_id,
            label.into(),
            offline,
            Some(expected_head),
        )
    }

    fn fork_focus_inner(
        &self,
        space_id: &ContextSpaceId,
        branch_id: RecordId,
        label: String,
        offline: bool,
        expected_head: Option<ExpectedRevision>,
    ) -> Result<FocusBranch, SpaceError> {
        validate_text(&label)?;
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        if expected_head.is_some_and(|expected| expected.0 != state.head.sequence) {
            return Err(SpaceError::StaleRevision);
        }
        if state.focus_branches.len() >= MAX_FOCUS_BRANCHES
            || state.focus_branches.contains_key(&branch_id)
        {
            return Err(SpaceError::LimitExceeded);
        }
        let branch = FocusBranch {
            branch_id: branch_id.clone(),
            label,
            fork_commit_id: state.head.commit_id.clone(),
            checkpoint_commit_id: None,
            offline,
        };
        state.focus_branches.insert(branch_id, branch.clone());
        Ok(branch)
    }

    /// Checkpoints a focus branch at the current immutable head.
    pub fn checkpoint_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
    ) -> Result<FocusBranch, SpaceError> {
        self.checkpoint_focus_inner(space_id, branch_id, None)
    }

    /// Checkpoints a focus branch atomically against an exact canonical-head sequence.
    pub fn checkpoint_focus_at_revision(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
        expected_head: ExpectedRevision,
    ) -> Result<FocusBranch, SpaceError> {
        self.checkpoint_focus_inner(space_id, branch_id, Some(expected_head))
    }

    fn checkpoint_focus_inner(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
        expected_head: Option<ExpectedRevision>,
    ) -> Result<FocusBranch, SpaceError> {
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        if expected_head.is_some_and(|expected| expected.0 != state.head.sequence) {
            return Err(SpaceError::StaleRevision);
        }
        let branch = state
            .focus_branches
            .get_mut(branch_id)
            .ok_or(SpaceError::NotFound)?;
        branch.checkpoint_commit_id = Some(state.head.commit_id.clone());
        Ok(branch.clone())
    }

    /// Switches the active task focus without deleting any branch checkpoint.
    pub fn switch_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
    ) -> Result<FocusBranch, SpaceError> {
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        let branch = state
            .focus_branches
            .get(branch_id)
            .cloned()
            .ok_or(SpaceError::NotFound)?;
        state.active_focus = Some(branch_id.clone());
        Ok(branch)
    }

    /// Marks an offline branch reconnected and returns its exact checkpoint/fork state.
    pub fn resume_focus(
        &self,
        space_id: &ContextSpaceId,
        branch_id: &RecordId,
    ) -> Result<FocusBranch, SpaceError> {
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        let branch = state
            .focus_branches
            .get_mut(branch_id)
            .ok_or(SpaceError::NotFound)?;
        branch.offline = false;
        Ok(branch.clone())
    }

    /// Creates a directional project link after both endpoints are disclosure-authorized.
    pub fn link_project(
        &self,
        space_id: &ContextSpaceId,
        link: ProjectLink,
        can_disclose: impl Fn(&RecordId) -> bool,
    ) -> Result<ProjectLinkPreview, SpaceError> {
        let relation = link
            .relation
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if relation.is_empty()
            || relation.len() > 256
            || link.contribution_cap_tokens == 0
            || link.from_project_id == link.to_project_id
        {
            return Err(SpaceError::InvalidInput);
        }
        if !can_disclose(&link.from_project_id) || !can_disclose(&link.to_project_id) {
            return Err(SpaceError::NotFound);
        }
        let mut spaces = self
            .spaces
            .write()
            .map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get_mut(space_id).ok_or(SpaceError::NotFound)?;
        if state.project_links.len() >= MAX_SPACE_PROJECTS {
            return Err(SpaceError::LimitExceeded);
        }
        let normalized = ProjectLink { relation, ..link };
        if state.project_links.iter().any(|existing| {
            existing.from_project_id == normalized.from_project_id
                && existing.to_project_id == normalized.to_project_id
        }) {
            return Err(SpaceError::Conflict);
        }
        let preview = ProjectLinkPreview {
            from_project_id: normalized.from_project_id.clone(),
            to_project_id: normalized.to_project_id.clone(),
            relation: normalized.relation.clone(),
            contribution_cap_tokens: normalized.contribution_cap_tokens,
        };
        state.project_links.push(normalized);
        state.project_links.sort_by(|left, right| {
            left.from_project_id
                .cmp(&right.from_project_id)
                .then_with(|| left.to_project_id.cmp(&right.to_project_id))
        });
        Ok(preview)
    }

    /// Returns a link preview only when both projects remain currently visible.
    pub fn project_link_preview(
        &self,
        space_id: &ContextSpaceId,
        from_project_id: &RecordId,
        to_project_id: &RecordId,
        can_disclose: impl Fn(&RecordId) -> bool,
    ) -> Result<ProjectLinkPreview, SpaceError> {
        if !can_disclose(from_project_id) || !can_disclose(to_project_id) {
            return Err(SpaceError::NotFound);
        }
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let link = spaces
            .get(space_id)
            .and_then(|state| {
                state.project_links.iter().find(|link| {
                    &link.from_project_id == from_project_id && &link.to_project_id == to_project_id
                })
            })
            .ok_or(SpaceError::NotFound)?;
        Ok(ProjectLinkPreview {
            from_project_id: link.from_project_id.clone(),
            to_project_id: link.to_project_id.clone(),
            relation: link.relation.clone(),
            contribution_cap_tokens: link.contribution_cap_tokens,
        })
    }

    /// Enforces active-project default visibility and optional directional contribution caps.
    pub fn cap_project_contributions(
        &self,
        space_id: &ContextSpaceId,
        active_project_id: &RecordId,
        authorized_projects: &BTreeSet<RecordId>,
        mut candidates: Vec<ProjectContribution>,
    ) -> Result<Vec<ProjectContribution>, SpaceError> {
        let spaces = self.spaces.read().map_err(|_error| SpaceError::Integrity)?;
        let state = spaces.get(space_id).ok_or(SpaceError::NotFound)?;
        candidates.sort_by(|left, right| left.version_id.cmp(&right.version_id));
        let caps: BTreeMap<_, _> = state
            .project_links
            .iter()
            .filter(|link| &link.from_project_id == active_project_id)
            .map(|link| (link.to_project_id.clone(), link.contribution_cap_tokens))
            .collect();
        let mut used = BTreeMap::<RecordId, u32>::new();
        let mut selected = Vec::new();
        for candidate in candidates {
            if !authorized_projects.contains(&candidate.project_id) {
                continue;
            }
            if &candidate.project_id == active_project_id || candidate.mandatory {
                selected.push(candidate);
                continue;
            }
            let Some(cap) = caps.get(&candidate.project_id) else {
                continue;
            };
            let prior = used.get(&candidate.project_id).copied().unwrap_or(0);
            let Some(total) = prior.checked_add(candidate.tokens) else {
                continue;
            };
            if total <= *cap {
                used.insert(candidate.project_id.clone(), total);
                selected.push(candidate);
            }
        }
        Ok(selected)
    }
}

fn private_overlay<'a>(
    state: &'a SpaceState,
    overlay_id: &RecordId,
    actor_id: &RecordId,
) -> Result<&'a OverlayState, SpaceError> {
    state
        .overlays
        .get(overlay_id)
        .filter(|overlay| &overlay.protocol.owner_id == actor_id)
        .ok_or(SpaceError::NotFound)
}

fn private_overlay_mut<'a>(
    state: &'a mut SpaceState,
    overlay_id: &RecordId,
    actor_id: &RecordId,
) -> Result<&'a mut OverlayState, SpaceError> {
    state
        .overlays
        .get_mut(overlay_id)
        .filter(|overlay| &overlay.protocol.owner_id == actor_id)
        .ok_or(SpaceError::NotFound)
}

fn find_conflicts(
    overlay: &OverlayState,
    current: &BTreeMap<ResourceKey, OverlayMutation>,
) -> Vec<MergeConflict> {
    overlay
        .proposals
        .iter()
        .filter_map(|(key, proposed)| {
            let base = overlay.base_resources.get(key);
            let now = current.get(key);
            if now == base || now == Some(proposed) || base == Some(proposed) {
                return None;
            }
            let mut evidence: Vec<_> = base
                .into_iter()
                .chain(now)
                .chain(std::iter::once(proposed))
                .map(mutation_version)
                .cloned()
                .collect();
            evidence.sort();
            evidence.dedup();
            let required_resolver = match proposed {
                OverlayMutation::Decision(_)
                | OverlayMutation::State(_)
                | OverlayMutation::Instruction(_) => ResolverKind::TypedDecision,
                OverlayMutation::Atom(_)
                | OverlayMutation::Artifact(_)
                | OverlayMutation::Capability(_)
                | OverlayMutation::Lease(_)
                | OverlayMutation::Effect(_) => ResolverKind::ExactBase,
            };
            Some(MergeConflict {
                key: key.clone(),
                base: base.cloned(),
                current: now.cloned(),
                proposed: proposed.clone(),
                evidence,
                required_resolver,
            })
        })
        .collect()
}

fn stored_conflict(
    space_id: &ContextSpaceId,
    overlay_id: &RecordId,
    observed_head_id: &VersionId,
    conflict: MergeConflict,
) -> Result<StoredMergeConflict, SpaceError> {
    #[derive(Serialize)]
    struct ConflictIdentity<'a> {
        domain: &'static str,
        space_id: &'a ContextSpaceId,
        overlay_id: &'a RecordId,
        observed_head_id: &'a VersionId,
        conflict: &'a MergeConflict,
    }
    let identity = ConflictIdentity {
        domain: "cigar.space-merge-conflict.v1",
        space_id,
        overlay_id,
        observed_head_id,
        conflict: &conflict,
    };
    Ok(StoredMergeConflict {
        conflict_id: deterministic_record_id(&identity)?,
        overlay_id: overlay_id.clone(),
        observed_head_id: observed_head_id.clone(),
        conflict,
    })
}

fn resolver_accepts(
    resolver: ResolverKind,
    conflict: &MergeConflict,
    resolution: &OverlayMutation,
) -> bool {
    match resolver {
        ResolverKind::TypedDecision => matches!(resolution, OverlayMutation::Decision(_)),
        ResolverKind::ExactBase => {
            std::mem::discriminant(&conflict.proposed) == std::mem::discriminant(resolution)
                && matches!(
                    resolution,
                    OverlayMutation::Atom(_)
                        | OverlayMutation::Artifact(_)
                        | OverlayMutation::Capability(_)
                        | OverlayMutation::Lease(_)
                        | OverlayMutation::Effect(_)
                )
        }
    }
}

fn deterministic_record_id(value: &impl Serialize) -> Result<RecordId, SpaceError> {
    let bytes = serde_json::to_vec(value).map_err(|_error| SpaceError::Integrity)?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    RecordId::new(format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    ))
    .map_err(|_error| SpaceError::Integrity)
}

fn resource_vec(resources: &BTreeMap<ResourceKey, OverlayMutation>) -> Vec<ProposedMutation> {
    resources
        .iter()
        .map(|(key, mutation)| ProposedMutation {
            key: key.clone(),
            mutation: mutation.clone(),
        })
        .collect()
}

fn validate_snapshot(spaces: &BTreeMap<ContextSpaceId, SpaceState>) -> Result<(), SpaceError> {
    for (space_id, state) in spaces {
        validate_space_snapshot(space_id, state)?;
    }
    Ok(())
}

fn validate_space_snapshot(
    space_id: &ContextSpaceId,
    state: &SpaceState,
) -> Result<(), SpaceError> {
    state
        .head
        .validate()
        .map_err(|_error| SpaceError::Integrity)?;
    if &state.head.space_id != space_id
        || state.history.get(&state.head.commit_id) != Some(&state.head)
        || state.history.len() != state.snapshots.len()
        || state.snapshots.get(&state.head.commit_id) != Some(&state.resources)
        || state.overlays.len() > MAX_SPACE_OVERLAYS
        || state
            .conflicts
            .len()
            .saturating_add(state.conflict_resolutions.len())
            > MAX_SPACE_CONFLICTS
        || state.focus_branches.len() > MAX_FOCUS_BRANCHES
        || state.project_links.len() > MAX_SPACE_PROJECTS
    {
        return Err(SpaceError::Integrity);
    }

    let mut commits: Vec<_> = state.history.values().collect();
    commits.sort_by_key(|commit| commit.sequence);
    let expected_count =
        usize::try_from(state.head.sequence).map_err(|_error| SpaceError::Integrity)?;
    if commits.len() != expected_count || commits.last().copied() != Some(&state.head) {
        return Err(SpaceError::Integrity);
    }
    if state
        .history
        .iter()
        .any(|(commit_id, commit)| commit_id != &commit.commit_id)
    {
        return Err(SpaceError::Integrity);
    }
    for (index, commit) in commits.iter().enumerate() {
        commit.validate().map_err(|_error| SpaceError::Integrity)?;
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(SpaceError::Integrity)?;
        let expected_parent = index
            .checked_sub(1)
            .and_then(|prior| commits.get(prior))
            .map(|prior| &prior.commit_id);
        let snapshot = state
            .snapshots
            .get(&commit.commit_id)
            .ok_or(SpaceError::Integrity)?;
        if &commit.space_id != space_id
            || commit.sequence != expected_sequence
            || commit.parent_commit_id.as_ref() != expected_parent
            || semantic_digest(snapshot)? != commit.root_digest
        {
            return Err(SpaceError::Integrity);
        }
    }

    let commit_events: Vec<_> = commits
        .iter()
        .flat_map(|commit| commit.events.iter())
        .collect();
    if commit_events.len() != state.events.len() {
        return Err(SpaceError::Integrity);
    }
    let mut event_ids = BTreeSet::new();
    for (index, (expected, stored)) in commit_events.iter().zip(&state.events).enumerate() {
        let expected_cursor = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(SpaceError::Integrity)?;
        if stored.cursor != EventCursor(expected_cursor)
            || &stored.space_id != space_id
            || &stored.event != *expected
            || !event_ids.insert(&stored.event.event_id)
        {
            return Err(SpaceError::Integrity);
        }
    }

    for (overlay_id, overlay) in &state.overlays {
        overlay
            .protocol
            .validate()
            .map_err(|_error| SpaceError::Integrity)?;
        let proposals: Vec<_> = overlay.proposals.values().cloned().collect();
        if &overlay.protocol.overlay_id != overlay_id
            || &overlay.protocol.space_id != space_id
            || state.snapshots.get(&overlay.protocol.base_commit_id)
                != Some(&overlay.base_resources)
            || overlay.protocol.mutations != proposals
        {
            return Err(SpaceError::Integrity);
        }
    }

    for (conflict_id, conflict) in &state.conflicts {
        let overlay = state
            .overlays
            .get(&conflict.overlay_id)
            .ok_or(SpaceError::Integrity)?;
        let expected = stored_conflict(
            space_id,
            &conflict.overlay_id,
            &conflict.observed_head_id,
            conflict.conflict.clone(),
        )?;
        if conflict_id != &conflict.conflict_id
            || &expected != conflict
            || !state.history.contains_key(&conflict.observed_head_id)
            || !overlay.proposals.contains_key(&conflict.conflict.key)
            || conflict.conflict.evidence.is_empty()
            || !strictly_sorted(&conflict.conflict.evidence)
        {
            return Err(SpaceError::Integrity);
        }
    }
    for (conflict_id, receipt) in &state.conflict_resolutions {
        if conflict_id != &receipt.conflict_id
            || receipt.evidence.is_empty()
            || !strictly_sorted(&receipt.evidence)
        {
            return Err(SpaceError::Integrity);
        }
    }

    if state.leases.len() != state.fencing.len() {
        return Err(SpaceError::Integrity);
    }
    for (resource_id, lease) in &state.leases {
        lease
            .lease
            .validate()
            .map_err(|_error| SpaceError::Integrity)?;
        if &lease.lease.resource_id != resource_id
            || lease.fencing_token == 0
            || state.fencing.get(resource_id) != Some(&lease.fencing_token)
        {
            return Err(SpaceError::Integrity);
        }
    }

    for (branch_id, branch) in &state.focus_branches {
        if validate_text(&branch.label).is_err()
            || &branch.branch_id != branch_id
            || !state.history.contains_key(&branch.fork_commit_id)
            || branch
                .checkpoint_commit_id
                .as_ref()
                .is_some_and(|commit| !state.history.contains_key(commit))
        {
            return Err(SpaceError::Integrity);
        }
    }
    let links_are_canonical = state.project_links.windows(2).all(|pair| {
        pair.first().zip(pair.get(1)).is_some_and(|(left, right)| {
            (&left.from_project_id, &left.to_project_id)
                < (&right.from_project_id, &right.to_project_id)
        })
    });
    if !links_are_canonical
        || state
            .active_focus
            .as_ref()
            .is_some_and(|branch| !state.focus_branches.contains_key(branch))
        || state.project_links.iter().any(|link| {
            link.from_project_id == link.to_project_id
                || link.relation.is_empty()
                || link.relation.len() > 256
                || link
                    .relation
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    != link.relation
                || link.contribution_cap_tokens == 0
        })
    {
        return Err(SpaceError::Integrity);
    }
    Ok(())
}

fn verify_lease_mutation(
    lease: &FencedLease,
    request: &LeaseMutationRequest,
) -> Result<(), SpaceError> {
    if lease.lease.state != LeaseState::Active
        || lease.lease.holder_id != request.holder_id
        || lease.fencing_token != request.fencing_token
        || lease.lease.expected_revision != request.expected_revision
        || request.now >= lease.lease.expires_at
    {
        Err(SpaceError::Conflict)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn build_commit(
    space_id: ContextSpaceId,
    sequence: u64,
    parent_commit_id: Option<VersionId>,
    author_id: RecordId,
    purpose: String,
    events: Vec<CoordinationEvent>,
    root_digest: ContentDigest,
    policy_snapshot_digest: ContentDigest,
    committed_at: UtcTimestamp,
) -> Result<ContextCommit, SpaceError> {
    #[derive(Serialize)]
    struct Seal<'a> {
        space_id: &'a ContextSpaceId,
        sequence: u64,
        parent_commit_id: &'a Option<VersionId>,
        author_id: &'a RecordId,
        purpose: &'a str,
        events: &'a [CoordinationEvent],
        root_digest: &'a ContentDigest,
        policy_snapshot_digest: &'a ContentDigest,
        committed_at: &'a UtcTimestamp,
    }
    let commit_id = version_digest(&Seal {
        space_id: &space_id,
        sequence,
        parent_commit_id: &parent_commit_id,
        author_id: &author_id,
        purpose: &purpose,
        events: &events,
        root_digest: &root_digest,
        policy_snapshot_digest: &policy_snapshot_digest,
        committed_at: &committed_at,
    })?;
    let commit = ContextCommit {
        schema_version: SchemaVersion::new("cigar.context-commit", 1)
            .map_err(|_error| SpaceError::Integrity)?,
        commit_id,
        space_id,
        sequence,
        parent_commit_id,
        author_id,
        purpose,
        events,
        root_digest,
        policy_snapshot_digest,
        committed_at,
        extensions: ExtensionMap::default(),
    };
    commit
        .validate()
        .map_err(|_error| SpaceError::InvalidInput)?;
    Ok(commit)
}

fn semantic_digest(value: &impl Serialize) -> Result<ContentDigest, SpaceError> {
    let bytes = serde_json::to_vec(value).map_err(|_error| SpaceError::Integrity)?;
    let hash = Sha256::digest(bytes);
    let mut encoded = String::from("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| SpaceError::Integrity)?;
    }
    ContentDigest::new(encoded).map_err(|_error| SpaceError::Integrity)
}

fn version_digest(value: &impl Serialize) -> Result<VersionId, SpaceError> {
    let content = semantic_digest(value)?;
    VersionId::new(content.as_str()).map_err(|_error| SpaceError::Integrity)
}

fn validate_text(value: &str) -> Result<(), SpaceError> {
    if value.trim().is_empty() || value.len() > 4_096 {
        Err(SpaceError::InvalidInput)
    } else {
        Ok(())
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left < right)
    })
}

const fn event_priority(kind: CoordinationEventKind) -> u8 {
    match kind {
        CoordinationEventKind::PolicySnapshotChanged
        | CoordinationEventKind::AtomInvalidated
        | CoordinationEventKind::BundleInvalidated
        | CoordinationEventKind::HandoffRevoked => 0,
        CoordinationEventKind::ContextCommitted
        | CoordinationEventKind::TaskCheckpointed
        | CoordinationEventKind::HandoffCreated
        | CoordinationEventKind::HandoffAccepted
        | CoordinationEventKind::AgentResultProposed
        | CoordinationEventKind::MergeConflictCreated
        | CoordinationEventKind::EffectStateChanged => 1,
    }
}
