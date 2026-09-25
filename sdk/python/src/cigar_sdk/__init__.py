"""Local CIGAR context graphs and compatible remote protocol clients.

Public exports load on first access so local users do not import remote clients.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from cigar_sdk.client import AsyncCigarClient, BearerTokenProvider, CigarClient
    from cigar_sdk.context import (
        LOCAL_CONTEXT_CORE_VERSION,
        LOCAL_CONTEXT_PROTOCOL,
        LocalContextCapabilities,
        LocalContextError,
        LocalContextGraph,
        get_local_context_capabilities,
    )
    from cigar_sdk.context_types import (
        LocalAnswerAssessment,
        LocalAnswerClaim,
        LocalAnswerDraft,
        LocalAnswerPolicy,
        LocalCitation,
        LocalClaimAssessment,
        LocalClaimReview,
        LocalContextDelta,
        LocalContextLimits,
        LocalContextPrompt,
        LocalContextRequest,
        LocalContextResult,
        LocalContextSnapshot,
        LocalDocument,
        LocalEdgeKind,
        LocalEvidenceBlock,
        LocalGraphStats,
        LocalSelectionStats,
        LocalSourceUpdate,
        LocalTokenCacheStats,
    )
    from cigar_sdk.digest import apply_context_delta, bundle_id, delta_digest, verify_bundle
    from cigar_sdk.errors import (
        CigarApiError,
        CigarError,
        CigarTimeoutError,
        CompatibilityError,
        TransportError,
        ValidationError,
    )
    from cigar_sdk.generated import models
    from cigar_sdk.generated.operations import OPERATION_COUNT, OPERATIONS, PAYLOAD_TYPES
    from cigar_sdk.idempotency import create_idempotency_key, validate_idempotency_key
    from cigar_sdk.types import (
        CallOptions,
        OperationEvent,
        OperationRequest,
        OperationResponse,
        PathParameter,
        TypedOperationEvent,
        TypedOperationRequest,
        TypedOperationResponse,
    )
    from cigar_sdk.workflow_session import (
        MAX_WORKFLOW_DELTA_CHAIN_LENGTH,
        MAX_WORKFLOW_REPLAY_CYCLES,
        WORKFLOW_SESSION_EVENT_NAMES,
        WorkflowContextCycleIdentity,
        WorkflowContextPhase,
        WorkflowContextReplayComparison,
        WorkflowContextReplayIdentity,
        WorkflowContextSession,
        WorkflowDeltaReplayIdentity,
        WorkflowEffectReplayIdentity,
        WorkflowQuarantineReason,
        WorkflowReplayDiffStatus,
        WorkflowResumeAction,
        WorkflowSessionError,
        WorkflowSessionErrorCode,
    )

CONTEXT_ABI: Final = "cigar.context.v1"

_EXPORTS: Final[dict[str, tuple[str, str | None]]] = {
    "AsyncCigarClient": ("cigar_sdk.client", "AsyncCigarClient"),
    "BearerTokenProvider": ("cigar_sdk.client", "BearerTokenProvider"),
    "CigarClient": ("cigar_sdk.client", "CigarClient"),
    "LOCAL_CONTEXT_CORE_VERSION": ("cigar_sdk.context", "LOCAL_CONTEXT_CORE_VERSION"),
    "LOCAL_CONTEXT_PROTOCOL": ("cigar_sdk.context", "LOCAL_CONTEXT_PROTOCOL"),
    "LocalContextCapabilities": ("cigar_sdk.context", "LocalContextCapabilities"),
    "LocalContextError": ("cigar_sdk.context", "LocalContextError"),
    "LocalContextGraph": ("cigar_sdk.context", "LocalContextGraph"),
    "get_local_context_capabilities": ("cigar_sdk.context", "get_local_context_capabilities"),
    "LocalAnswerAssessment": ("cigar_sdk.context_types", "LocalAnswerAssessment"),
    "LocalAnswerClaim": ("cigar_sdk.context_types", "LocalAnswerClaim"),
    "LocalAnswerDraft": ("cigar_sdk.context_types", "LocalAnswerDraft"),
    "LocalAnswerPolicy": ("cigar_sdk.context_types", "LocalAnswerPolicy"),
    "LocalCitation": ("cigar_sdk.context_types", "LocalCitation"),
    "LocalClaimAssessment": ("cigar_sdk.context_types", "LocalClaimAssessment"),
    "LocalClaimReview": ("cigar_sdk.context_types", "LocalClaimReview"),
    "LocalContextDelta": ("cigar_sdk.context_types", "LocalContextDelta"),
    "LocalContextLimits": ("cigar_sdk.context_types", "LocalContextLimits"),
    "LocalContextPrompt": ("cigar_sdk.context_types", "LocalContextPrompt"),
    "LocalContextRequest": ("cigar_sdk.context_types", "LocalContextRequest"),
    "LocalContextResult": ("cigar_sdk.context_types", "LocalContextResult"),
    "LocalContextSnapshot": ("cigar_sdk.context_types", "LocalContextSnapshot"),
    "LocalDocument": ("cigar_sdk.context_types", "LocalDocument"),
    "LocalEdgeKind": ("cigar_sdk.context_types", "LocalEdgeKind"),
    "LocalEvidenceBlock": ("cigar_sdk.context_types", "LocalEvidenceBlock"),
    "LocalGraphStats": ("cigar_sdk.context_types", "LocalGraphStats"),
    "LocalSelectionStats": ("cigar_sdk.context_types", "LocalSelectionStats"),
    "LocalSourceUpdate": ("cigar_sdk.context_types", "LocalSourceUpdate"),
    "LocalTokenCacheStats": ("cigar_sdk.context_types", "LocalTokenCacheStats"),
    "apply_context_delta": ("cigar_sdk.digest", "apply_context_delta"),
    "bundle_id": ("cigar_sdk.digest", "bundle_id"),
    "delta_digest": ("cigar_sdk.digest", "delta_digest"),
    "verify_bundle": ("cigar_sdk.digest", "verify_bundle"),
    "CigarApiError": ("cigar_sdk.errors", "CigarApiError"),
    "CigarError": ("cigar_sdk.errors", "CigarError"),
    "CigarTimeoutError": ("cigar_sdk.errors", "CigarTimeoutError"),
    "CompatibilityError": ("cigar_sdk.errors", "CompatibilityError"),
    "TransportError": ("cigar_sdk.errors", "TransportError"),
    "ValidationError": ("cigar_sdk.errors", "ValidationError"),
    "models": ("cigar_sdk.generated.models", None),
    "OPERATION_COUNT": ("cigar_sdk.generated.operations", "OPERATION_COUNT"),
    "OPERATIONS": ("cigar_sdk.generated.operations", "OPERATIONS"),
    "PAYLOAD_TYPES": ("cigar_sdk.generated.operations", "PAYLOAD_TYPES"),
    "create_idempotency_key": ("cigar_sdk.idempotency", "create_idempotency_key"),
    "validate_idempotency_key": ("cigar_sdk.idempotency", "validate_idempotency_key"),
    "CallOptions": ("cigar_sdk.types", "CallOptions"),
    "OperationEvent": ("cigar_sdk.types", "OperationEvent"),
    "OperationRequest": ("cigar_sdk.types", "OperationRequest"),
    "OperationResponse": ("cigar_sdk.types", "OperationResponse"),
    "PathParameter": ("cigar_sdk.types", "PathParameter"),
    "TypedOperationEvent": ("cigar_sdk.types", "TypedOperationEvent"),
    "TypedOperationRequest": ("cigar_sdk.types", "TypedOperationRequest"),
    "TypedOperationResponse": ("cigar_sdk.types", "TypedOperationResponse"),
    "MAX_WORKFLOW_DELTA_CHAIN_LENGTH": ("cigar_sdk.workflow_session", "MAX_WORKFLOW_DELTA_CHAIN_LENGTH"),
    "MAX_WORKFLOW_REPLAY_CYCLES": ("cigar_sdk.workflow_session", "MAX_WORKFLOW_REPLAY_CYCLES"),
    "WORKFLOW_SESSION_EVENT_NAMES": ("cigar_sdk.workflow_session", "WORKFLOW_SESSION_EVENT_NAMES"),
    "WorkflowContextCycleIdentity": ("cigar_sdk.workflow_session", "WorkflowContextCycleIdentity"),
    "WorkflowContextPhase": ("cigar_sdk.workflow_session", "WorkflowContextPhase"),
    "WorkflowContextReplayComparison": ("cigar_sdk.workflow_session", "WorkflowContextReplayComparison"),
    "WorkflowContextReplayIdentity": ("cigar_sdk.workflow_session", "WorkflowContextReplayIdentity"),
    "WorkflowContextSession": ("cigar_sdk.workflow_session", "WorkflowContextSession"),
    "WorkflowDeltaReplayIdentity": ("cigar_sdk.workflow_session", "WorkflowDeltaReplayIdentity"),
    "WorkflowEffectReplayIdentity": ("cigar_sdk.workflow_session", "WorkflowEffectReplayIdentity"),
    "WorkflowQuarantineReason": ("cigar_sdk.workflow_session", "WorkflowQuarantineReason"),
    "WorkflowReplayDiffStatus": ("cigar_sdk.workflow_session", "WorkflowReplayDiffStatus"),
    "WorkflowResumeAction": ("cigar_sdk.workflow_session", "WorkflowResumeAction"),
    "WorkflowSessionError": ("cigar_sdk.workflow_session", "WorkflowSessionError"),
    "WorkflowSessionErrorCode": ("cigar_sdk.workflow_session", "WorkflowSessionErrorCode"),
}

__all__ = [
    "CONTEXT_ABI",
    "LOCAL_CONTEXT_CORE_VERSION",
    "LOCAL_CONTEXT_PROTOCOL",
    "MAX_WORKFLOW_DELTA_CHAIN_LENGTH",
    "MAX_WORKFLOW_REPLAY_CYCLES",
    "OPERATIONS",
    "OPERATION_COUNT",
    "PAYLOAD_TYPES",
    "WORKFLOW_SESSION_EVENT_NAMES",
    "AsyncCigarClient",
    "BearerTokenProvider",
    "CallOptions",
    "CigarApiError",
    "CigarClient",
    "CigarError",
    "CigarTimeoutError",
    "CompatibilityError",
    "LocalAnswerAssessment",
    "LocalAnswerClaim",
    "LocalAnswerDraft",
    "LocalAnswerPolicy",
    "LocalCitation",
    "LocalClaimAssessment",
    "LocalClaimReview",
    "LocalContextCapabilities",
    "LocalContextDelta",
    "LocalContextError",
    "LocalContextGraph",
    "LocalContextLimits",
    "LocalContextPrompt",
    "LocalContextRequest",
    "LocalContextResult",
    "LocalContextSnapshot",
    "LocalDocument",
    "LocalEdgeKind",
    "LocalEvidenceBlock",
    "LocalGraphStats",
    "LocalSelectionStats",
    "LocalSourceUpdate",
    "LocalTokenCacheStats",
    "OperationEvent",
    "OperationRequest",
    "OperationResponse",
    "PathParameter",
    "TransportError",
    "TypedOperationEvent",
    "TypedOperationRequest",
    "TypedOperationResponse",
    "ValidationError",
    "WorkflowContextCycleIdentity",
    "WorkflowContextPhase",
    "WorkflowContextReplayComparison",
    "WorkflowContextReplayIdentity",
    "WorkflowContextSession",
    "WorkflowDeltaReplayIdentity",
    "WorkflowEffectReplayIdentity",
    "WorkflowQuarantineReason",
    "WorkflowReplayDiffStatus",
    "WorkflowResumeAction",
    "WorkflowSessionError",
    "WorkflowSessionErrorCode",
    "apply_context_delta",
    "bundle_id",
    "create_idempotency_key",
    "delta_digest",
    "get_local_context_capabilities",
    "models",
    "validate_idempotency_key",
    "verify_bundle",
]


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module, attribute = target
    imported = import_module(module)
    value = imported if attribute is None else getattr(imported, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
