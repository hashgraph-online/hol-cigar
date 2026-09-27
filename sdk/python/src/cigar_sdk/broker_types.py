"""Typed native broker contracts; source revisions are lossless decimal strings."""

from typing import Literal, NotRequired, TypedDict

from cigar_sdk.context_types import (
    LocalAnswerDraft,
    LocalAnswerPolicy,
    LocalClaimReview,
    LocalDocument,
    LocalViewAssessment,
    LocalViewContext,
)


class LocalBrokerStorageOptions(TypedDict):
    """Private host directory; only evidence is retained across restarts."""

    directory: str
    create_directory: NotRequired[bool]
    max_checkpoint_bytes: NotRequired[int]
    max_database_bytes: NotRequired[int]
    max_journal_records: NotRequired[int]


class LocalBrokerStorageStatus(TypedDict):
    mode: Literal["memory", "sqlite-checkpoint.v1"]
    restored: bool


class LocalBrokerLimits(TypedDict, total=False):
    max_agents: int
    max_sources: int
    max_tickets: int
    max_proposals: int
    max_retained_bytes: int
    max_provenance_bytes: int
    max_relation_bytes: int


class LocalBrokerQueueLimits(TypedDict, total=False):
    max_agents: int
    max_agent_jobs: int
    max_agent_bytes: int
    max_host_jobs: int
    max_host_bytes: int
    max_wait_ms: int


class LocalBrokerTransportLimits(TypedDict, total=False):
    max_connections: int
    max_connections_per_agent: int
    max_inbound_bytes: int
    max_outbound_bytes: int
    frame_timeout_ms: int
    write_timeout_ms: int
    response_timeout_ms: int


class LocalBrokerAgentLimits(TypedDict, total=False):
    max_tokens: int
    max_tickets: int
    max_proposals: int
    max_retained_bytes: int
    max_proposal_bytes: int
    max_proposal_documents: int
    ticket_lifetime_ms: int
    proposal_lifetime_ms: int


class LocalBrokerAgentQueueLimits(TypedDict, total=False):
    max_jobs: int
    max_bytes: int


class LocalBrokerConnectionConfig(TypedDict):
    """Sensitive export for protected IPC. Never put this in logs, argv or environment."""

    schema: Literal["cigar.broker-client.v1"]
    host: Literal["127.0.0.1"]
    port: int
    epoch: str
    secret: str


class LocalBrokerSourceRevision(TypedDict):
    epoch: str
    version: str


class LocalBrokerSourceTransaction(TypedDict):
    """Opaque, expiring host staging handle. Not evidence, agent authority or durable state."""

    epoch: str
    id: str


class LocalBrokerSourceDependency(TypedDict):
    source: str
    revision: LocalBrokerSourceRevision


class LocalBrokerSourceProvenance(TypedDict):
    """Host declarations, not signatures or semantic truth guarantees."""

    authority: str
    upstream_revision: str
    observed_at_ms: int
    valid_until_ms: int | None
    origin: Literal["host", "reviewed_proposal"]
    derived_from: list[LocalBrokerSourceDependency]


class LocalBrokerSourceReceipt(TypedDict):
    revision: LocalBrokerSourceRevision
    inserted: int
    replaced: int
    removed: int
    unchanged: int


class LocalBrokerContext(TypedDict):
    ticket: str
    context: LocalViewContext
    rendered: str


class LocalBrokerProposalPending(TypedDict):
    status: Literal["pending"]


class LocalBrokerProposalAdmitted(TypedDict):
    status: Literal["admitted"]
    receipt: LocalBrokerSourceReceipt


class LocalBrokerProposalRejected(TypedDict):
    status: Literal["rejected"]


class LocalBrokerProposalStatus(TypedDict):
    proposal_id: str
    request_key: str
    outcome: LocalBrokerProposalPending | LocalBrokerProposalAdmitted | LocalBrokerProposalRejected


class LocalBrokerProposal(TypedDict):
    """Unverified agent material, available only to the host admission port."""

    source: str
    expected: LocalBrokerSourceRevision
    documents: list[LocalDocument]


class LocalBrokerSubmission(TypedDict):
    submission_id: str
    draft: LocalAnswerDraft
    review_keys: list[str]


class LocalBrokerExecutionReview(TypedDict):
    """Current host-owned review authority, verdicts and release policy; never agent output."""

    authority_revision: str
    reviews: list[LocalClaimReview]
    policy: LocalAnswerPolicy


class LocalBrokerExecutionBinding(TypedDict):
    """Retained context precondition for an exact external intent, not effect authorization."""

    schema: Literal["cigar.context-execution-binding.v1"]
    id: str
    epoch: str
    ticket: str
    submission_id: str
    context_id: str
    snapshot_id: str
    source_authority_digest: str
    review_digest: str
    effect_id: str
    intent_digest: str


class LocalBrokerExecutionHandoff(TypedDict):
    """One consumed, freshly checked context binding; not a durable dispatch receipt."""

    binding: LocalBrokerExecutionBinding
    checked: LocalViewAssessment


class LocalBrokerCapabilities(TypedDict):
    protocol: Literal["cigar.context-broker.v1"]
    core_version: str
    epoch: str
    host: Literal["127.0.0.1"]
    port: int
    tokenizer: str
    max_frame_bytes: int
    max_response_bytes: int
    host_max_frame_bytes: int
    host_max_response_bytes: int
    execution: Literal["single-owner-fair-dispatch"]
    requires_hol_services: Literal[False]
    capabilities: list[str]
    transport_limits: LocalBrokerTransportLimits
    storage: NotRequired[LocalBrokerStorageStatus]
