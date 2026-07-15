//! Portable protocol foundations shared by every CIGAR surface.

mod atom;
mod catalog;
mod compilation;
mod contract;
mod coordination;
mod effect;
mod extension;
mod extension_host;
mod identity;
pub mod limits;
mod primitive;
mod replay;
mod schema;
mod service;
mod validation;

pub use atom::{
    AtomKind, AtomPayload, BlobRef, Classification, ContextAtomV1, GovernanceEnvelope,
    InstructionAuthority, Lifecycle, QualityEnvelope, RetrievalEnvelope, ScopeEnvelope,
    SourceDescriptor, TemporalEnvelope,
};
pub use catalog::{ContextEdge, EdgeKind, SourceSnapshot};
pub use compilation::{
    CandidateDisposition, ContextBlock, ContextBundle, ContextDelta, ContextPlan,
    DispositionReason, ManifestEntry, MaterializedContext, PlanLane, RepresentationKind,
    SelectionManifest,
};
pub use contract::{
    Budget, ConsistencyMode, ContextContract, ContextRequirement, LaneKind, OperationClass,
    RequirementSelector, TargetProfile,
};
pub use coordination::{
    Capability, CapabilityGrant, ContextCommit, CoordinationEvent, CoordinationEventKind,
    CoordinationTopic, HandoffAcceptance, HandoffCapsule, HandoffDelta, HandoffReferences, Lease,
    LeaseKind, LeaseState, Overlay, OverlayMutation, RecipientSelector, ResultClaim,
};
pub use effect::{
    ApprovalKind, CompensationLink, CompensationSpec, EffectApproval, EffectAttempt, EffectIntent,
    EffectJournalEvent, EffectReceipt, EffectState, ReceiptOutcome, ReconciliationOutcome,
    ReconciliationReport, RetryPolicy, RiskLevel,
};
pub use extension::{CanonicalValue, ExtensionKey, ExtensionMap};
pub use extension_host::{
    CigarVersionRange, ExtensionAbiVersionRange, ExtensionCancelReason, ExtensionCancelV1,
    ExtensionComputeBudget, ExtensionDeterminism, ExtensionHandle, ExtensionHostCallKind,
    ExtensionHostCallV1, ExtensionHostCapability, ExtensionId, ExtensionInvocationV1,
    ExtensionKind, ExtensionLimits, ExtensionManifestV1, ExtensionObservationV1,
    ExtensionResponseOutcome, ExtensionResponseV1, ExtensionRuntimeKind, ExtensionSchemaBinding,
    ExtensionSemanticVersion, NetworkEndpoint, NetworkHost, NetworkTransport, SandboxAccess,
    SandboxPath, SandboxPreopen,
};
pub use identity::{
    ContentDigest, ContextSpaceId, ExpectedRevision, IdempotencyKey, LineageId, RecordId, VersionId,
};
pub use primitive::{DurationNanos, FixedPoint, MediaType, RelativePath, SourceUri, UtcTimestamp};
pub use replay::{
    DecisionOutcome, DecisionRecord, DependencyKind, DiffStatus, ReplayCompleteness, ReplayDiff,
    ReplayExecution, ReplayMode, ReplayRequest, ReplayStatus, UsageRecord, VerificationCheck,
    VerificationOutcome, VerificationReceipt,
};
pub use schema::SchemaVersion;
pub use service::{
    CompatibilityReport, ComponentHealth, ERROR_REGISTRY, ErrorCode, ErrorDefinition, HealthReport,
    HealthStatus, PageCursor, Problem, RetryClass,
};
pub use validation::{Validate, ValidationCode, ValidationErrors, ValidationIssue};

/// Generated Protobuf wire types. Semantic validation remains on the sibling domain records.
#[allow(missing_docs)]
pub mod wire {
    include!("generated/cigar/context/v1/cigar.context.v1.rs");
}

/// Earliest protocol version this build accepts.
pub const PROTOCOL_MIN: &str = "1.0";

/// Latest compatible protocol line this build accepts.
pub const PROTOCOL_MAX: &str = "1.x";

/// Stable semantic ABI implemented by this build.
pub const CONTEXT_ABI: &str = "cigar.context.v1";

/// Stable build metadata reported by deployable binaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildMetadata {
    /// Package semantic version.
    pub version: &'static str,
    /// Source revision injected by the release build, or `unknown`.
    pub source_revision: &'static str,
    /// Semantic Context ABI implemented by this build.
    pub context_abi: &'static str,
    /// Minimum accepted protocol version.
    pub protocol_min: &'static str,
    /// Maximum accepted protocol line.
    pub protocol_max: &'static str,
    /// Cargo build profile class.
    pub build_profile: &'static str,
}

impl BuildMetadata {
    /// Returns metadata for the current package without timestamps or host paths.
    #[must_use]
    pub const fn current(version: &'static str) -> Self {
        Self {
            version,
            source_revision: match option_env!("CIGAR_SOURCE_REVISION") {
                Some(revision) => revision,
                None => "unknown",
            },
            context_abi: CONTEXT_ABI,
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
        }
    }

    /// Serializes metadata as stable JSON with a deterministic field order.
    #[must_use]
    pub fn to_stable_json(self) -> String {
        format!(
            concat!(
                "{{\"version\":\"{}\",",
                "\"source_revision\":\"{}\",",
                "\"context_abi\":\"{}\",",
                "\"protocol_min\":\"{}\",",
                "\"protocol_max\":\"{}\",",
                "\"build_profile\":\"{}\",",
                "\"enabled_features\":[]}}"
            ),
            self.version,
            self.source_revision,
            self.context_abi,
            self.protocol_min,
            self.protocol_max,
            self.build_profile
        )
    }
}

#[cfg(test)]
mod tests {
    use super::BuildMetadata;

    #[test]
    fn version_json_has_stable_order_and_no_host_inputs() {
        let actual = BuildMetadata {
            version: "1.2.3",
            source_revision: "abc123",
            context_abi: "cigar.context.v1",
            protocol_min: "1.0",
            protocol_max: "1.x",
            build_profile: "release",
        }
        .to_stable_json();

        assert_eq!(
            actual,
            concat!(
                "{\"version\":\"1.2.3\",",
                "\"source_revision\":\"abc123\",",
                "\"context_abi\":\"cigar.context.v1\",",
                "\"protocol_min\":\"1.0\",",
                "\"protocol_max\":\"1.x\",",
                "\"build_profile\":\"release\",",
                "\"enabled_features\":[]}"
            )
        );
        assert!(!actual.contains(env!("CARGO_MANIFEST_DIR")));
    }
}
