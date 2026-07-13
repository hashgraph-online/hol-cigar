# CIGAR v1 frozen discriminants

All semantic discriminants are unsigned integers. Zero is reserved for an unspecified transport value and is invalid for security-sensitive semantic records. Existing numbers never change or get reused. Unknown values fail closed.

The canonical envelope profiles are `Atom=1`, `Bundle=2`, `Manifest=3`, `Handoff=4`, `Effect=5`, `Receipt=6`, and `ExtensionManifest=7`.

The frozen enum registry is:

- `OperationClass`: Read=1, CodeChange=2, Analysis=3, ExternalMutation=4.
- `ConsistencyMode`: Snapshot=1, Strong=2, BoundedStaleness=3.
- `LaneKind`: Rules=1, Task=2, Evidence=3, History=4, Tools=5.
- `DispositionReason`: ScopeDenied=1, PurposeDenied=2, TemporalMismatch=3, TrustInsufficient=4, InstructionAuthorityDenied=5, ProcessorDenied=6, IntegrityFailed=7, BudgetDisplaced=8, LifecycleIneligible=9, ConflictLost=10, RequiredMissing=11.
- `RepresentationKind`: Exact=1, Extracted=2, Summarized=3, Redacted=4.
- `Capability`: ReadContext=1, CompileContext=2, WriteOverlay=3, PublishOverlay=4, CreateHandoff=5, AcceptHandoff=6, InvokeTool=7, ProposeEffect=8, ApproveEffect=9, ReconcileEffect=10.
- `CoordinationEventKind`: ContextCommitted=1, AtomInvalidated=2, BundleInvalidated=3, TaskCheckpointed=4, HandoffCreated=5, HandoffAccepted=6, HandoffRevoked=7, AgentResultProposed=8, MergeConflictCreated=9, EffectStateChanged=10, PolicySnapshotChanged=11.
- `OverlayMutationKind`: Atom=1, Decision=2, State=3, Artifact=4, Instruction=5, Capability=6, Lease=7, Effect=8.
- `CoordinationTopic`: AtomInvalidation=1, BundleInvalidation=2, TaskCheckpoint=3, HandoffRevocation=4, EffectState=5, PolicySnapshot=6.
- `LeaseKind`: Task=1, Decision=2, EffectReconciliation=3, Publication=4.
- `LeaseState`: Active=1, Released=2, Expired=3, Revoked=4.
- `EffectState`: Prepared=1, PendingApproval=2, Authorized=3, Dispatching=4, Succeeded=5, Failed=6, Unknown=7, AuthorizedForRetry=8, ManualResolution=9, Rejected=10, Expired=11, Cancelled=12, CompensationPending=13, Compensating=14, Compensated=15, CompensationFailed=16.
- `RiskLevel`: Low=1, Medium=2, High=3, Critical=4.
- `RetryPolicyKind`: Never=1, SameKeyIdempotent=2, ReconcileBeforeRetry=3.
- `ApprovalKind`: Human=1, Policy=2.
- `ReceiptOutcome`: Succeeded=1, Failed=2, Unknown=3.
- `ReconciliationOutcome`: ConfirmedSuccess=1, ConfirmedFailure=2, ProvenNotExecuted=3, Inconclusive=4, Manual=5.
- `DecisionOutcome`: Succeeded=1, Failed=2, Partial=3, Cancelled=4.
- `ReplayMode`: EvidenceReproduction=1, InvocationReproduction=2, Observational=3, LiveComparison=4.
- `DependencyKind`: Source=1, Blob=2, Policy=3, Index=4, Manifest=5, Bundle=6, Tokenizer=7, Adapter=8, Consumer=9, ToolSchema=10, Environment=11.
- `ReplayStatus`: Running=1, Complete=2, Failed=3, Incomplete=4.
- `DiffStatus`: Equal=1, Different=2, Unavailable=3.
- `VerificationOutcome`: Passed=1, Failed=2, Indeterminate=3.
- `HealthStatus`: Healthy=1, Degraded=2, Unhealthy=3.
- `EdgeKind`: DependsOn=1, Defines=2, References=3, Supersedes=4, Contradicts=5, Supports=6, DerivedFrom=7, AppliesTo=8.
- `AtomKind`: Instruction=1, SourceCode=2, Documentation=3, Decision=4, Conversation=5, ToolResult=6, Schema=7, Policy=8, Test=9, Artifact=10.
- `Classification`: Public=1, Internal=2, Confidential=3, Restricted=4.
- `InstructionAuthority`: Data=1, Advisory=2, Project=3, System=4.
- `Lifecycle`: Active=1, Superseded=2, Tombstoned=3, Quarantined=4.
- `RetryClass`: Never=1, Safe=2, AfterBackoff=3, AfterReauthorization=4, AfterReconciliation=5.

The stable public `ErrorCode` values are generated from `spec/errors/catalog.yaml`; the frozen range is 1000–2099 and the exact generated mapping lives in `schemas/proto/generated/error_codes.proto`.

Closed union tags use their Protobuf field numbers: requirement selector exact=2/query=3; candidate disposition selected=1/excluded=2/redacted=3/required-missing=4; atom payload inline-text=1/canonical-json=2/blob=3; recipient selector principal=1/role=2. The checked-in Protobuf sources are the machine-readable authority and generation drift is a failing gate.
