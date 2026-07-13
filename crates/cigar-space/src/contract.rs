//! Bounded context-space service contracts.

use cigar_protocol::{
    ContentDigest, ContextCommit, ContextSpaceId, CoordinationEvent, ExpectedRevision, Lease,
    Overlay, OverlayMutation, RecordId, UtcTimestamp, VersionId,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum projects attached to one space or directional federation view.
pub const MAX_SPACE_PROJECTS: usize = 64;
/// Maximum simultaneously retained private overlays in one context space.
pub const MAX_SPACE_OVERLAYS: usize = 10_000;
/// Maximum focus branches retained in one space.
pub const MAX_FOCUS_BRANCHES: usize = 256;
/// Maximum semantic resource key bytes.
pub const MAX_RESOURCE_KEY_BYTES: usize = 512;
/// Maximum event page size.
pub const MAX_EVENT_PAGE: usize = 1_024;
/// Maximum unresolved and resolved merge-conflict records retained per space.
pub const MAX_SPACE_CONFLICTS: usize = 100_000;

/// Stable content-free service failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpaceError {
    /// An identifier or bounded field is malformed.
    InvalidInput,
    /// The resource is absent or intentionally existence-hidden.
    NotFound,
    /// The expected revision is not the current revision.
    StaleRevision,
    /// Current policy or project scope denies the operation.
    Forbidden,
    /// An active lease or unresolved merge conflict prevents mutation.
    Conflict,
    /// A collection or sequence bound was exceeded.
    LimitExceeded,
    /// Digest or serialization failed.
    Integrity,
}

impl fmt::Display for SpaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "context-space operation failed: {self:?}")
    }
}

impl std::error::Error for SpaceError {}

/// Exact hierarchy bound to one context space.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceHierarchy {
    /// Tenant identity.
    pub tenant_id: RecordId,
    /// Workspace identity.
    pub workspace_id: RecordId,
    /// Active project identity.
    pub active_project_id: RecordId,
    /// Branch or worktree identity.
    pub branch_id: RecordId,
    /// Task identity.
    pub task_id: RecordId,
    /// Session identity.
    pub session_id: RecordId,
}

/// Inputs for an immutable genesis commit.
#[derive(Clone, Debug)]
pub struct CreateSpaceRequest {
    /// Caller-selected space identity.
    pub space_id: ContextSpaceId,
    /// Exact hierarchy.
    pub hierarchy: SpaceHierarchy,
    /// Authenticated author.
    pub author_id: RecordId,
    /// Non-empty bounded purpose.
    pub purpose: String,
    /// Current policy snapshot.
    pub policy_snapshot_digest: ContentDigest,
    /// Genesis timestamp.
    pub committed_at: UtcTimestamp,
    /// Unique genesis event identity.
    pub event_id: RecordId,
}

/// Semantic resource key used by deterministic three-way merge.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ResourceKey(String);

impl ResourceKey {
    /// Creates a normalized bounded non-empty key.
    pub fn new(value: impl Into<String>) -> Result<Self, SpaceError> {
        let value = value.into();
        let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.is_empty() || normalized.len() > MAX_RESOURCE_KEY_BYTES {
            Err(SpaceError::InvalidInput)
        } else {
            Ok(Self(normalized))
        }
    }

    /// Returns the normalized key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<ResourceKey> for String {
    fn from(value: ResourceKey) -> Self {
        value.0
    }
}

impl TryFrom<String> for ResourceKey {
    type Error = SpaceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// One private proposed resource mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProposedMutation {
    /// Stable semantic resource key.
    pub key: ResourceKey,
    /// Typed immutable record version.
    pub mutation: OverlayMutation,
}

/// Typed deterministic merge conflict with all three versions retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeConflict {
    /// Conflicting semantic key.
    pub key: ResourceKey,
    /// Value at overlay creation.
    pub base: Option<OverlayMutation>,
    /// Value at current canonical head.
    pub current: Option<OverlayMutation>,
    /// Proposed overlay value.
    pub proposed: OverlayMutation,
    /// Sorted evidence versions involved in the conflict.
    pub evidence: Vec<VersionId>,
    /// Required typed resolver class.
    pub required_resolver: ResolverKind,
}

/// Required resolution policy for a semantic conflict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverKind {
    /// A human or policy decision is required.
    TypedDecision,
    /// Exact base and current resource state must be reconciled.
    ExactBase,
}

/// Durable unresolved merge conflict addressed by the public conflict route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMergeConflict {
    /// Stable content-derived conflict identity.
    pub conflict_id: RecordId,
    /// Private overlay whose proposal conflicted.
    pub overlay_id: RecordId,
    /// Canonical head against which the conflict was observed.
    pub observed_head_id: VersionId,
    /// Complete typed three-way conflict.
    pub conflict: MergeConflict,
}

/// Trusted inputs for resolving one stored conflict without publishing the overlay.
#[derive(Clone, Debug)]
pub struct ResolveConflictRequest {
    /// Exact current canonical head sequence.
    pub expected_head: ExpectedRevision,
    /// Authenticated owner of the private overlay.
    pub actor_id: RecordId,
    /// Resolver class required by policy and the conflict type.
    pub resolver: ResolverKind,
    /// Explicit selected immutable mutation; no last-writer-wins default exists.
    pub resolution: OverlayMutation,
    /// Sorted unique evidence supporting the decision, including all conflict evidence.
    pub evidence: Vec<VersionId>,
    /// Current immutable policy snapshot.
    pub policy_snapshot_digest: ContentDigest,
    /// Server-observed resolution time.
    pub resolved_at: UtcTimestamp,
}

/// Durable receipt proving which private proposal consumed a conflict.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionReceipt {
    /// Consumed conflict identity.
    pub conflict_id: RecordId,
    /// Owning private overlay.
    pub overlay_id: RecordId,
    /// Authenticated resolver.
    pub actor_id: RecordId,
    /// Explicit selected mutation.
    pub resolution: OverlayMutation,
    /// Sorted unique supporting evidence.
    pub evidence: Vec<VersionId>,
    /// Policy snapshot under which resolution was allowed.
    pub policy_snapshot_digest: ContentDigest,
    /// Resolution time.
    pub resolved_at: UtcTimestamp,
}

/// Caller metadata used to publish an overlay.
#[derive(Clone, Debug)]
pub struct PublishRequest {
    /// Exact current revision observed by the caller.
    pub expected_head: ExpectedRevision,
    /// Overlay owner and publishing principal.
    pub actor_id: RecordId,
    /// Non-empty publication purpose.
    pub purpose: String,
    /// Current policy snapshot.
    pub policy_snapshot_digest: ContentDigest,
    /// Publication timestamp.
    pub committed_at: UtcTimestamp,
    /// Unique commit event identity.
    pub event_id: RecordId,
}

/// Exact outcome of an attempted publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    /// A new immutable commit became the head.
    Published(ContextCommit),
    /// Publication changed nothing because all proposals already matched head.
    Deduplicated(ContextCommit),
    /// No canonical state changed; the overlay remains available for resolution.
    Conflicted(Vec<MergeConflict>),
}

/// Authorized base plus at most one private overlay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceView {
    /// Immutable visible base commit.
    pub base: ContextCommit,
    /// Private overlay visible only to its exact owner.
    pub overlay: Option<Overlay>,
    /// Deterministically merged visible resources.
    pub resources: Vec<ProposedMutation>,
}

/// Monotonic acknowledgement cursor for a scoped at-least-once stream.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EventCursor(pub u64);

/// One ordered durable event with project disclosure scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceEvent {
    /// Monotonic cursor beginning at one.
    pub cursor: EventCursor,
    /// Owning context space.
    pub space_id: ContextSpaceId,
    /// Project whose disclosure scope governs the event.
    pub project_id: RecordId,
    /// Immutable protocol event.
    pub event: CoordinationEvent,
}

/// Bounded event page with a contiguous resume cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    /// Events after the supplied acknowledged cursor.
    pub events: Vec<SpaceEvent>,
    /// Highest contiguous scanned cursor, including invisible events.
    pub resume_cursor: EventCursor,
    /// Whether more events remain after this page.
    pub has_more: bool,
}

/// Fencing token paired with a protocol lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FencedLease {
    /// Validated protocol lease.
    pub lease: Lease,
    /// Monotonic resource-specific fencing token.
    pub fencing_token: u64,
}

/// One resumable focus branch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FocusBranch {
    /// Stable branch identity.
    pub branch_id: RecordId,
    /// Bounded display label.
    pub label: String,
    /// Commit from which the branch forked.
    pub fork_commit_id: VersionId,
    /// Most recent explicit checkpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_commit_id: Option<VersionId>,
    /// Whether the branch is temporarily offline.
    pub offline: bool,
}

/// Directional, disclosure-governed project relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectLink {
    /// Source project whose context may refer outward.
    pub from_project_id: RecordId,
    /// Target project eligible for contextual contribution.
    pub to_project_id: RecordId,
    /// Bounded normalized relation.
    pub relation: String,
    /// Maximum optional target contribution in tokens.
    pub contribution_cap_tokens: u32,
}

/// Disclosure-safe project-link preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectLinkPreview {
    /// Directional source project.
    pub from_project_id: RecordId,
    /// Directional target project.
    pub to_project_id: RecordId,
    /// Declared normalized relation.
    pub relation: String,
    /// Contribution cap.
    pub contribution_cap_tokens: u32,
}

/// Candidate contribution used to enforce federation caps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectContribution {
    /// Owning project.
    pub project_id: RecordId,
    /// Immutable candidate identity.
    pub version_id: VersionId,
    /// Exact physical token contribution.
    pub tokens: u32,
    /// Mandatory dependencies bypass optional crowd-out caps.
    pub mandatory: bool,
}

/// Internal overlay snapshot retained for exact three-way merge.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OverlayState {
    pub(crate) protocol: Overlay,
    pub(crate) base_resources: std::collections::BTreeMap<ResourceKey, OverlayMutation>,
    pub(crate) proposals: std::collections::BTreeMap<ResourceKey, OverlayMutation>,
}

/// Inputs for acquiring a fenced advisory lease.
#[derive(Clone, Debug)]
pub struct AcquireLeaseRequest {
    /// Caller-selected lease identity.
    pub lease_id: RecordId,
    /// Immutable resource identity.
    pub resource_id: VersionId,
    /// Exact holder.
    pub holder_id: RecordId,
    /// Lease class.
    pub kind: cigar_protocol::LeaseKind,
    /// Acquisition time.
    pub acquired_at: UtcTimestamp,
    /// Exclusive expiry.
    pub expires_at: UtcTimestamp,
}

/// Inputs for renewing or releasing a current lease.
#[derive(Clone, Debug)]
pub struct LeaseMutationRequest {
    /// Exact current holder.
    pub holder_id: RecordId,
    /// Exact current fencing token.
    pub fencing_token: u64,
    /// Expected lease revision.
    pub expected_revision: ExpectedRevision,
    /// Operation time.
    pub now: UtcTimestamp,
    /// New exclusive expiry for renewal; absent for release.
    pub expires_at: Option<UtcTimestamp>,
}

/// Returns all immutable versions carried by a mutation.
pub(crate) fn mutation_version(mutation: &OverlayMutation) -> &VersionId {
    match mutation {
        OverlayMutation::Atom(version)
        | OverlayMutation::Decision(version)
        | OverlayMutation::State(version)
        | OverlayMutation::Artifact(version)
        | OverlayMutation::Instruction(version)
        | OverlayMutation::Capability(version)
        | OverlayMutation::Lease(version)
        | OverlayMutation::Effect(version) => version,
    }
}
