package cigar

import (
	"fmt"
	"regexp"
	"slices"
)

// MaxWorkflowDeltaChainLength is the verified-delta bound before a full-bundle checkpoint.
const MaxWorkflowDeltaChainLength uint16 = 8

// MaxWorkflowReplayCycles bounds the exact cycle transcript retained by one workflow.
const MaxWorkflowReplayCycles = 64

// WorkflowContextPhase is one closed context-cycle state shared by every CIGAR SDK.
type WorkflowContextPhase string

const (
	WorkflowPhaseNew                            WorkflowContextPhase = "new"
	WorkflowPhasePlanCreated                    WorkflowContextPhase = "plan_created"
	WorkflowPhaseTargetBundleLoaded             WorkflowContextPhase = "target_bundle_loaded"
	WorkflowPhaseDeltaCompiled                  WorkflowContextPhase = "delta_compiled"
	WorkflowPhaseBundleReady                    WorkflowContextPhase = "bundle_ready"
	WorkflowPhaseMaterialized                   WorkflowContextPhase = "materialized"
	WorkflowPhaseModelInvocationPending         WorkflowContextPhase = "model_invocation_pending"
	WorkflowPhaseModelResultRecorded            WorkflowContextPhase = "model_result_recorded"
	WorkflowPhaseEffectPrepared                 WorkflowContextPhase = "effect_prepared"
	WorkflowPhaseObservationRecorded            WorkflowContextPhase = "observation_recorded"
	WorkflowPhaseEffectAuthorizationRevalidated WorkflowContextPhase = "effect_authorization_revalidated"
	WorkflowPhaseEffectAuthorized               WorkflowContextPhase = "effect_authorized"
	WorkflowPhaseEffectRevalidated              WorkflowContextPhase = "effect_revalidated"
	WorkflowPhaseEffectDispatching              WorkflowContextPhase = "effect_dispatching"
	WorkflowPhaseEffectAmbiguous                WorkflowContextPhase = "effect_ambiguous"
	WorkflowPhaseEffectSettled                  WorkflowContextPhase = "effect_settled"
	WorkflowPhaseCheckpointed                   WorkflowContextPhase = "checkpointed"
	WorkflowPhaseFinished                       WorkflowContextPhase = "finished"
	WorkflowPhaseReplayVerified                 WorkflowContextPhase = "replay_verified"
	WorkflowPhaseQuarantined                    WorkflowContextPhase = "quarantined"
)

var workflowContextPhases = []WorkflowContextPhase{
	WorkflowPhaseNew, WorkflowPhasePlanCreated, WorkflowPhaseTargetBundleLoaded, WorkflowPhaseDeltaCompiled,
	WorkflowPhaseBundleReady, WorkflowPhaseMaterialized, WorkflowPhaseModelInvocationPending,
	WorkflowPhaseModelResultRecorded, WorkflowPhaseEffectPrepared, WorkflowPhaseObservationRecorded,
	WorkflowPhaseEffectAuthorizationRevalidated, WorkflowPhaseEffectAuthorized,
	WorkflowPhaseEffectRevalidated, WorkflowPhaseEffectDispatching,
	WorkflowPhaseEffectAmbiguous, WorkflowPhaseEffectSettled, WorkflowPhaseCheckpointed, WorkflowPhaseFinished,
	WorkflowPhaseReplayVerified, WorkflowPhaseQuarantined,
}

// WorkflowContextPhases returns the closed phase inventory in contract order.
func WorkflowContextPhases() []WorkflowContextPhase { return slices.Clone(workflowContextPhases) }

// WorkflowResumeAction is the exact action a recovered caller must resume.
type WorkflowResumeAction string

const (
	WorkflowActionCreateContextPlan                WorkflowResumeAction = "create_context_plan"
	WorkflowActionCompileContextBundle             WorkflowResumeAction = "compile_context_bundle"
	WorkflowActionCompileContextDelta              WorkflowResumeAction = "compile_context_delta"
	WorkflowActionApplyContextDelta                WorkflowResumeAction = "apply_context_delta"
	WorkflowActionMaterializeContextBundle         WorkflowResumeAction = "materialize_context_bundle"
	WorkflowActionBeginModelInvocation             WorkflowResumeAction = "begin_model_invocation"
	WorkflowActionResumeModelInvocation            WorkflowResumeAction = "resume_model_invocation"
	WorkflowActionPrepareEffectOrIngestObservation WorkflowResumeAction = "prepare_effect_or_ingest_observation"
	WorkflowActionIngestObservation                WorkflowResumeAction = "ingest_observation"
	WorkflowActionAuthorizeEffectOrCheckpoint      WorkflowResumeAction = "authorize_effect_or_checkpoint"
	WorkflowActionRevalidateContextBundle          WorkflowResumeAction = "revalidate_context_bundle"
	WorkflowActionDispatchEffect                   WorkflowResumeAction = "dispatch_effect"
	WorkflowActionObserveEffect                    WorkflowResumeAction = "observe_effect"
	WorkflowActionReconcileEffect                  WorkflowResumeAction = "reconcile_effect"
	WorkflowActionCheckpoint                       WorkflowResumeAction = "checkpoint"
	WorkflowActionMaterializeOrFinish              WorkflowResumeAction = "materialize_or_finish"
	WorkflowActionReplay                           WorkflowResumeAction = "replay"
	WorkflowActionComplete                         WorkflowResumeAction = "complete"
)

var workflowResumeActions = []WorkflowResumeAction{
	WorkflowActionCreateContextPlan, WorkflowActionCompileContextBundle, WorkflowActionCompileContextDelta,
	WorkflowActionApplyContextDelta, WorkflowActionMaterializeContextBundle, WorkflowActionBeginModelInvocation,
	WorkflowActionResumeModelInvocation, WorkflowActionPrepareEffectOrIngestObservation,
	WorkflowActionIngestObservation, WorkflowActionAuthorizeEffectOrCheckpoint,
	WorkflowActionRevalidateContextBundle, WorkflowActionDispatchEffect, WorkflowActionObserveEffect,
	WorkflowActionReconcileEffect, WorkflowActionCheckpoint, WorkflowActionMaterializeOrFinish,
	WorkflowActionReplay, WorkflowActionComplete,
}

// WorkflowResumeActions returns the closed resume-action inventory in contract order.
func WorkflowResumeActions() []WorkflowResumeAction { return slices.Clone(workflowResumeActions) }

// OperationID returns the existing v1 server operation for an action, or an empty string for a local boundary.
func (action WorkflowResumeAction) OperationID() string {
	switch action {
	case WorkflowActionCreateContextPlan:
		return "createContextPlan"
	case WorkflowActionCompileContextBundle:
		return "compileContextBundle"
	case WorkflowActionCompileContextDelta:
		return "compileContextDelta"
	case WorkflowActionMaterializeContextBundle:
		return "materializeContextBundle"
	case WorkflowActionIngestObservation:
		return "ingestCatalog"
	case WorkflowActionAuthorizeEffectOrCheckpoint:
		return "authorizeEffect"
	case WorkflowActionRevalidateContextBundle:
		return "revalidateContextBundle"
	case WorkflowActionDispatchEffect:
		return "dispatchEffect"
	case WorkflowActionObserveEffect:
		return "getEffectStatus"
	case WorkflowActionReconcileEffect:
		return "reconcileEffect"
	case WorkflowActionReplay:
		return "createReplay"
	default:
		return ""
	}
}

// WorkflowSessionErrorCode is a stable local workflow transition failure category.
type WorkflowSessionErrorCode string

const (
	WorkflowErrorInvalidTransition WorkflowSessionErrorCode = "invalid_transition"
	WorkflowErrorInvalidEvent      WorkflowSessionErrorCode = "invalid_event"
	WorkflowErrorIdentityMismatch  WorkflowSessionErrorCode = "identity_mismatch"
	WorkflowErrorInvalidated       WorkflowSessionErrorCode = "invalidated"
	WorkflowErrorLimitExceeded     WorkflowSessionErrorCode = "limit_exceeded"
)

var workflowSessionErrorCodes = []WorkflowSessionErrorCode{
	WorkflowErrorInvalidTransition, WorkflowErrorInvalidEvent, WorkflowErrorIdentityMismatch,
	WorkflowErrorInvalidated, WorkflowErrorLimitExceeded,
}

var workflowSessionEventNames = []string{
	"plan_created", "bundle_compiled", "delta_compiled", "delta_applied", "materialized",
	"model_invocation_started", "model_result_recorded", "effect_prepared", "observation_recorded",
	"effect_authorized", "effect_revalidated", "effect_dispatched", "effect_observed", "cycle_checkpointed",
	"finished", "replay_verified", "context_quarantined",
}

// WorkflowSessionEventNames returns the stable event inventory in contract order.
func WorkflowSessionEventNames() []string { return slices.Clone(workflowSessionEventNames) }

// WorkflowSessionErrorCodes returns the closed failure inventory in contract order.
func WorkflowSessionErrorCodes() []WorkflowSessionErrorCode {
	return slices.Clone(workflowSessionErrorCodes)
}

// WorkflowSessionError is a content-safe local state-machine failure.
type WorkflowSessionError struct{ Code WorkflowSessionErrorCode }

func (failure *WorkflowSessionError) Error() string {
	return "workflow context transition failed: " + string(failure.Code)
}

// WorkflowEffectState is a closed durable effect state used by the workflow helper.
type WorkflowEffectState string

// WorkflowQuarantineReason is a closed terminal late-result fence reason.
type WorkflowQuarantineReason string

const (
	WorkflowQuarantineCancelled   WorkflowQuarantineReason = "cancelled"
	WorkflowQuarantineRevoked     WorkflowQuarantineReason = "revoked"
	WorkflowQuarantineInvalidated WorkflowQuarantineReason = "invalidated"
)

const (
	WorkflowEffectPrepared           WorkflowEffectState = "prepared"
	WorkflowEffectAuthorized         WorkflowEffectState = "authorized"
	WorkflowEffectDispatching        WorkflowEffectState = "dispatching"
	WorkflowEffectUnknown            WorkflowEffectState = "unknown"
	WorkflowEffectAuthorizedForRetry WorkflowEffectState = "authorized_for_retry"
	WorkflowEffectSucceeded          WorkflowEffectState = "succeeded"
	WorkflowEffectFailed             WorkflowEffectState = "failed"
	WorkflowEffectManualResolution   WorkflowEffectState = "manual_resolution"
	WorkflowEffectRejected           WorkflowEffectState = "rejected"
	WorkflowEffectExpired            WorkflowEffectState = "expired"
	WorkflowEffectCancelled          WorkflowEffectState = "cancelled"
	WorkflowEffectCompensated        WorkflowEffectState = "compensated"
	WorkflowEffectCompensationFailed WorkflowEffectState = "compensation_failed"
)

type workflowContextIdentity struct{ planID, bundleID, contractDigest string }
type workflowDeltaIdentity struct{ baseBundleID, targetBundleID, deltaDigest string }
type workflowEffectIdentity struct {
	effectID, intentDigest string
	effectVersion          uint64
	state                  WorkflowEffectState
	attemptCount           uint32
	reconciliationCount    uint32
}
type workflowMaterializationIdentity struct {
	bundleID, tokenizerFingerprint, materializerFingerprint string
	physicalInputTokens                                     uint32
}
type workflowInvocationIdentity struct {
	invocationID, requestDigest, idempotencyKeyDigest string
}

// WorkflowReplayDiffStatus is one exact replay-comparison result.
type WorkflowReplayDiffStatus string

const (
	WorkflowReplayEqual     WorkflowReplayDiffStatus = "equal"
	WorkflowReplayDifferent WorkflowReplayDiffStatus = "different"
)

// WorkflowDeltaReplayIdentity is the exact selected sealed-delta identity.
type WorkflowDeltaReplayIdentity struct {
	BaseBundleID, TargetBundleID, DeltaDigest string
}

// WorkflowEffectReplayIdentity is the exact terminal effect decision identity.
type WorkflowEffectReplayIdentity struct {
	EffectID, IntentDigest string
	EffectVersion          uint64
	State                  WorkflowEffectState
	AttemptCount           uint32
	ReconciliationCount    uint32
}

// WorkflowContextCycleIdentity is one exact content-free completed-cycle transcript.
type WorkflowContextCycleIdentity struct {
	PlanID, BundleID, ContractDigest                  string
	SelectedDelta                                     *WorkflowDeltaReplayIdentity
	MaterializedBundleID, TokenizerFingerprint        string
	MaterializerFingerprint                           string
	PhysicalInputTokens                               uint32
	InvocationID, RequestDigest, IdempotencyKeyDigest string
	ModelResultDigest                                 string
	Effect                                            *WorkflowEffectReplayIdentity
	OutcomeDigest                                     string
	OutcomeRevision                                   uint64
}

// WorkflowContextReplayIdentity is a bounded ordered baseline or replay transcript.
type WorkflowContextReplayIdentity struct {
	Cycles []WorkflowContextCycleIdentity
}

// WorkflowContextReplayComparison separates deterministic selection from result/effect drift.
type WorkflowContextReplayComparison struct {
	BundleDeltaSelection WorkflowReplayDiffStatus
	Materialization      WorkflowReplayDiffStatus
	ModelResultIdentity  WorkflowReplayDiffStatus
	ToolEffectDecisions  WorkflowReplayDiffStatus
	Outcome              WorkflowReplayDiffStatus
	ExactMatch           bool
}

// WorkflowContextSession tracks only identities needed to resume one deterministic context lifecycle.
type WorkflowContextSession struct {
	phase               WorkflowContextPhase
	completedTurns      uint32
	deltaChainLength    uint16
	activeContext       *workflowContextIdentity
	pendingContext      *workflowContextIdentity
	pendingDelta        *workflowDeltaIdentity
	selectedDelta       *workflowDeltaIdentity
	materialization     *workflowMaterializationIdentity
	invocation          *workflowInvocationIdentity
	modelResultDigest   string
	observationDigest   string
	observationRevision uint64
	effect              *workflowEffectIdentity
	completedCycles     []WorkflowContextCycleIdentity
	replayVerified      bool
	quarantineReason    WorkflowQuarantineReason
}

// NewWorkflowContextSession creates an empty context lifecycle.
func NewWorkflowContextSession() *WorkflowContextSession {
	return &WorkflowContextSession{phase: WorkflowPhaseNew}
}

func (session *WorkflowContextSession) String() string {
	effectState := WorkflowEffectState("")
	if session.effect != nil {
		effectState = session.effect.state
	}
	return fmt.Sprintf(
		"WorkflowContextSession(phase=%s completedTurns=%d deltaChainLength=%d active=%t pending=%t delta=%t selectedDelta=%t invocation=%t providerIdempotency=%t result=%t observation=%t effectState=%s completedCycleCount=%d quarantineReason=%s)",
		session.phase, session.completedTurns, session.deltaChainLength, session.activeContext != nil,
		session.pendingContext != nil, session.pendingDelta != nil, session.selectedDelta != nil,
		session.invocation != nil, session.invocation != nil, session.modelResultDigest != "",
		session.observationDigest != "", effectState, len(session.completedCycles), session.quarantineReason,
	)
}

// Phase returns the current closed phase.
func (session *WorkflowContextSession) Phase() WorkflowContextPhase { return session.phase }

// CompletedTurns returns the number of durable completed-cycle checkpoints.
func (session *WorkflowContextSession) CompletedTurns() uint32 { return session.completedTurns }

// DeltaChainLength returns the number of applied deltas since a future full checkpoint reset.
func (session *WorkflowContextSession) DeltaChainLength() uint16 { return session.deltaChainLength }

// ActiveBundleID returns the current semantic root, if one has been loaded.
func (session *WorkflowContextSession) ActiveBundleID() (string, bool) {
	if session.activeContext == nil {
		return "", false
	}
	return session.activeContext.bundleID, true
}

// ReplayIdentity returns an independent copy of the exact transcript after workflow completion.
func (session *WorkflowContextSession) ReplayIdentity() (WorkflowContextReplayIdentity, error) {
	if err := session.requirePhase(WorkflowPhaseFinished, WorkflowPhaseReplayVerified); err != nil {
		return WorkflowContextReplayIdentity{}, err
	}
	if len(session.completedCycles) == 0 {
		return WorkflowContextReplayIdentity{}, workflowFailure(WorkflowErrorInvalidTransition)
	}
	return cloneWorkflowReplayIdentity(WorkflowContextReplayIdentity{Cycles: session.completedCycles}), nil
}

// CompareReplay returns fixed identity dimensions without accepting mismatched replay state.
func (session *WorkflowContextSession) CompareReplay(
	candidate WorkflowContextReplayIdentity,
) (WorkflowContextReplayComparison, error) {
	baseline, err := session.ReplayIdentity()
	if err != nil {
		return WorkflowContextReplayComparison{}, err
	}
	if err := validateWorkflowReplayIdentity(candidate); err != nil {
		return WorkflowContextReplayComparison{}, err
	}
	return compareWorkflowReplay(baseline, candidate), nil
}

// ResumeAction returns the exact next recovery action.
func (session *WorkflowContextSession) ResumeAction() WorkflowResumeAction {
	switch session.phase {
	case WorkflowPhaseNew, WorkflowPhaseObservationRecorded:
		return WorkflowActionCreateContextPlan
	case WorkflowPhasePlanCreated:
		return WorkflowActionCompileContextBundle
	case WorkflowPhaseTargetBundleLoaded:
		return WorkflowActionCompileContextDelta
	case WorkflowPhaseDeltaCompiled:
		return WorkflowActionApplyContextDelta
	case WorkflowPhaseBundleReady:
		if session.modelResultDigest == "" {
			return WorkflowActionMaterializeContextBundle
		}
		if session.effect == nil {
			return WorkflowActionCheckpoint
		}
		return WorkflowActionRevalidateContextBundle
	case WorkflowPhaseMaterialized:
		return WorkflowActionBeginModelInvocation
	case WorkflowPhaseModelInvocationPending:
		return WorkflowActionResumeModelInvocation
	case WorkflowPhaseModelResultRecorded:
		return WorkflowActionPrepareEffectOrIngestObservation
	case WorkflowPhaseEffectPrepared:
		return WorkflowActionIngestObservation
	case WorkflowPhaseEffectAuthorizationRevalidated:
		return WorkflowActionAuthorizeEffectOrCheckpoint
	case WorkflowPhaseEffectAuthorized:
		return WorkflowActionRevalidateContextBundle
	case WorkflowPhaseEffectRevalidated:
		return WorkflowActionDispatchEffect
	case WorkflowPhaseEffectDispatching:
		return WorkflowActionObserveEffect
	case WorkflowPhaseEffectAmbiguous:
		return WorkflowActionReconcileEffect
	case WorkflowPhaseEffectSettled:
		return WorkflowActionCheckpoint
	case WorkflowPhaseCheckpointed:
		return WorkflowActionMaterializeOrFinish
	case WorkflowPhaseFinished:
		return WorkflowActionReplay
	default:
		return WorkflowActionComplete
	}
}

// RecordPlanCreated applies a successful createContextPlan boundary.
func (session *WorkflowContextSession) RecordPlanCreated(planID, bundleID, contractDigest string) error {
	if err := session.requirePhase(WorkflowPhaseNew, WorkflowPhaseObservationRecorded); err != nil {
		return err
	}
	if !validRecordID(planID) || !validDigest(bundleID) || !validDigest(contractDigest) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	session.pendingContext = &workflowContextIdentity{planID, bundleID, contractDigest}
	session.pendingDelta = nil
	session.phase = WorkflowPhasePlanCreated
	return nil
}

// RecordBundleCompiled applies a successful compileContextBundle boundary.
func (session *WorkflowContextSession) RecordBundleCompiled(bundleID, contractDigest string) error {
	if err := session.requirePhase(WorkflowPhasePlanCreated); err != nil {
		return err
	}
	if !validDigest(bundleID) || !validDigest(contractDigest) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	pending := session.pendingContext
	if pending == nil {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	if pending.bundleID != bundleID || pending.contractDigest != contractDigest {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	if session.activeContext == nil || session.activeContext.bundleID == bundleID {
		session.activeContext = pending
		session.pendingContext = nil
		session.selectedDelta = nil
		if session.deltaChainLength >= MaxWorkflowDeltaChainLength {
			session.deltaChainLength = 0
		}
		session.phase = WorkflowPhaseBundleReady
	} else if session.deltaChainLength >= MaxWorkflowDeltaChainLength {
		session.activeContext = pending
		session.pendingContext = nil
		session.selectedDelta = nil
		session.deltaChainLength = 0
		session.phase = WorkflowPhaseBundleReady
	} else {
		session.phase = WorkflowPhaseTargetBundleLoaded
	}
	return nil
}

// RecordDeltaCompiled applies a successful compileContextDelta boundary.
func (session *WorkflowContextSession) RecordDeltaCompiled(baseBundleID, targetBundleID, deltaDigest string) error {
	if err := session.requirePhase(WorkflowPhaseTargetBundleLoaded); err != nil {
		return err
	}
	if session.deltaChainLength >= MaxWorkflowDeltaChainLength {
		return workflowFailure(WorkflowErrorLimitExceeded)
	}
	if !validDigest(baseBundleID) || !validDigest(targetBundleID) || !validDigest(deltaDigest) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if session.activeContext == nil || session.pendingContext == nil {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	if session.activeContext.bundleID != baseBundleID || session.pendingContext.bundleID != targetBundleID {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	session.pendingDelta = &workflowDeltaIdentity{baseBundleID, targetBundleID, deltaDigest}
	session.phase = WorkflowPhaseDeltaCompiled
	return nil
}

// RecordDeltaApplied applies successful local sealed-delta verification.
func (session *WorkflowContextSession) RecordDeltaApplied(baseBundleID, targetBundleID, deltaDigest string) error {
	if err := session.requirePhase(WorkflowPhaseDeltaCompiled); err != nil {
		return err
	}
	if !validDigest(baseBundleID) || !validDigest(targetBundleID) || !validDigest(deltaDigest) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	pending := session.pendingDelta
	if pending == nil {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	if pending.baseBundleID != baseBundleID || pending.targetBundleID != targetBundleID ||
		pending.deltaDigest != deltaDigest {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	if session.deltaChainLength >= MaxWorkflowDeltaChainLength {
		return workflowFailure(WorkflowErrorLimitExceeded)
	}
	session.deltaChainLength++
	selectedDelta := *pending
	session.selectedDelta = &selectedDelta
	session.activeContext = session.pendingContext
	session.pendingContext = nil
	session.pendingDelta = nil
	session.phase = WorkflowPhaseBundleReady
	return nil
}

// RecordMaterialized applies a successful materializeContextBundle boundary.
func (session *WorkflowContextSession) RecordMaterialized(
	bundleID, tokenizerFingerprint, materializerFingerprint string,
	physicalInputTokens uint32,
) error {
	if err := session.requirePhase(WorkflowPhaseBundleReady, WorkflowPhaseCheckpointed); err != nil {
		return err
	}
	if !validDigest(bundleID) || !validDigest(tokenizerFingerprint) || !validDigest(materializerFingerprint) ||
		physicalInputTokens == 0 {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	activeBundleID, active := session.ActiveBundleID()
	if !active || activeBundleID != bundleID {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	if session.modelResultDigest != "" {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	session.materialization = &workflowMaterializationIdentity{
		bundleID, tokenizerFingerprint, materializerFingerprint, physicalInputTokens,
	}
	session.phase = WorkflowPhaseMaterialized
	return nil
}

// BeginModelInvocation persists an invocation identity before crossing the provider boundary.
func (session *WorkflowContextSession) BeginModelInvocation(
	invocationID, requestDigest, idempotencyKeyDigest string,
) error {
	if err := session.requirePhase(WorkflowPhaseMaterialized); err != nil {
		return err
	}
	if !validRecordID(invocationID) || !validDigest(requestDigest) || !validDigest(idempotencyKeyDigest) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	session.invocation = &workflowInvocationIdentity{invocationID, requestDigest, idempotencyKeyDigest}
	session.phase = WorkflowPhaseModelInvocationPending
	return nil
}

// RecordModelResult binds the exact protected result to its durable invocation.
func (session *WorkflowContextSession) RecordModelResult(invocationID, resultDigest string) error {
	if err := session.requirePhase(WorkflowPhaseModelInvocationPending); err != nil {
		return err
	}
	if !validRecordID(invocationID) || !validDigest(resultDigest) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if session.invocation == nil || session.invocation.invocationID != invocationID {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	session.modelResultDigest = resultDigest
	session.phase = WorkflowPhaseModelResultRecorded
	return nil
}

// RecordEffectPrepared binds an immutable effect intent.
func (session *WorkflowContextSession) RecordEffectPrepared(
	effectID, intentDigest string,
	effectVersion uint64,
	state WorkflowEffectState,
	attemptCount, reconciliationCount uint32,
) error {
	if err := session.requirePhase(WorkflowPhaseModelResultRecorded); err != nil {
		return err
	}
	if !validRecordID(effectID) || !validDigest(intentDigest) || effectVersion == 0 ||
		state != WorkflowEffectPrepared || session.effect != nil || attemptCount != 0 || reconciliationCount != 0 {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	session.effect = &workflowEffectIdentity{
		effectID, intentDigest, effectVersion, state, attemptCount, reconciliationCount,
	}
	session.phase = WorkflowPhaseEffectPrepared
	return nil
}

// RecordObservation records governed result or observation publication.
func (session *WorkflowContextSession) RecordObservation(publicationDigest string, revision uint64) error {
	if err := session.requirePhase(WorkflowPhaseModelResultRecorded, WorkflowPhaseEffectPrepared); err != nil {
		return err
	}
	if !validDigest(publicationDigest) || revision == 0 {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	session.observationDigest = publicationDigest
	session.observationRevision = revision
	session.phase = WorkflowPhaseObservationRecorded
	return nil
}

// RecordEffectAuthorized applies an authorization only after the updated bundle is ready.
func (session *WorkflowContextSession) RecordEffectAuthorized(
	effectID, intentDigest string,
	effectVersion uint64,
	state WorkflowEffectState,
	attemptCount, reconciliationCount uint32,
) error {
	if err := session.requirePhase(WorkflowPhaseEffectAuthorizationRevalidated); err != nil {
		return err
	}
	if session.modelResultDigest == "" || state != WorkflowEffectAuthorized {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if session.effect == nil || attemptCount != session.effect.attemptCount ||
		reconciliationCount != session.effect.reconciliationCount {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if err := session.updateEffect(
		effectID, intentDigest, effectVersion, state, attemptCount, reconciliationCount, true,
	); err != nil {
		return err
	}
	session.phase = WorkflowPhaseEffectAuthorized
	return nil
}

// RecordEffectRevalidated fences the current bundle immediately before authorization or dispatch.
func (session *WorkflowContextSession) RecordEffectRevalidated(bundleID string, valid bool) error {
	beforeAuthorization := session.phase == WorkflowPhaseBundleReady && session.modelResultDigest != "" &&
		session.effect != nil && session.effect.state == WorkflowEffectPrepared
	if !beforeAuthorization && session.phase != WorkflowPhaseEffectAuthorized {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	if !validDigest(bundleID) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	activeBundleID, active := session.ActiveBundleID()
	if !active || activeBundleID != bundleID {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	if !valid {
		session.enterQuarantine(WorkflowQuarantineInvalidated)
		return nil
	}
	if beforeAuthorization {
		session.phase = WorkflowPhaseEffectAuthorizationRevalidated
	} else {
		session.phase = WorkflowPhaseEffectRevalidated
	}
	return nil
}

// QuarantineContext terminally fences the exact active bundle after cancellation or revocation.
func (session *WorkflowContextSession) QuarantineContext(bundleID string, reason WorkflowQuarantineReason) error {
	if !validDigest(bundleID) || !validWorkflowQuarantineReason(reason) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if session.phase == WorkflowPhaseNew || session.phase == WorkflowPhaseFinished ||
		session.phase == WorkflowPhaseReplayVerified || session.phase == WorkflowPhaseQuarantined {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	activeBundleID, active := session.ActiveBundleID()
	if !active || activeBundleID != bundleID {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	session.enterQuarantine(reason)
	return nil
}

// RecordEffectDispatched applies the one fenced dispatch result.
func (session *WorkflowContextSession) RecordEffectDispatched(
	effectID, intentDigest string,
	effectVersion uint64,
	state WorkflowEffectState,
	attemptCount, reconciliationCount uint32,
) error {
	if err := session.requirePhase(WorkflowPhaseEffectRevalidated); err != nil {
		return err
	}
	if state != WorkflowEffectDispatching && state != WorkflowEffectUnknown && !terminalWorkflowEffect(state) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if session.effect == nil || session.effect.attemptCount == ^uint32(0) ||
		attemptCount != session.effect.attemptCount+1 ||
		reconciliationCount != session.effect.reconciliationCount {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if err := session.updateEffect(
		effectID, intentDigest, effectVersion, state, attemptCount, reconciliationCount, true,
	); err != nil {
		return err
	}
	phase, err := workflowEffectPhase(state)
	if err != nil {
		return err
	}
	session.phase = phase
	return nil
}

// RecordEffectObserved applies status or reconciliation without redispatching.
func (session *WorkflowContextSession) RecordEffectObserved(
	effectID, intentDigest string,
	effectVersion uint64,
	state WorkflowEffectState,
	attemptCount, reconciliationCount uint32,
) error {
	allowed := session.phase == WorkflowPhaseEffectDispatching &&
		(state == WorkflowEffectDispatching || state == WorkflowEffectUnknown || terminalWorkflowEffect(state))
	allowed = allowed || session.phase == WorkflowPhaseEffectAmbiguous &&
		(state == WorkflowEffectUnknown || state == WorkflowEffectAuthorizedForRetry || terminalWorkflowEffect(state))
	if !allowed {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	if session.effect == nil || attemptCount < session.effect.attemptCount ||
		reconciliationCount < session.effect.reconciliationCount ||
		state == WorkflowEffectAuthorizedForRetry &&
			(attemptCount != session.effect.attemptCount || reconciliationCount <= session.effect.reconciliationCount) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	if err := session.updateEffect(
		effectID, intentDigest, effectVersion, state, attemptCount, reconciliationCount, false,
	); err != nil {
		return err
	}
	phase, err := workflowEffectPhase(state)
	if err != nil {
		return err
	}
	session.phase = phase
	return nil
}

// CheckpointCycle durably completes one result/observation/effect cycle.
func (session *WorkflowContextSession) CheckpointCycle() error {
	effectComplete := session.effect == nil && session.phase == WorkflowPhaseBundleReady
	effectComplete = effectComplete || session.effect != nil && session.phase == WorkflowPhaseEffectSettled &&
		terminalWorkflowEffect(session.effect.state)
	if !effectComplete || session.modelResultDigest == "" || session.observationDigest == "" {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	if len(session.completedCycles) >= MaxWorkflowReplayCycles || session.completedTurns == ^uint32(0) {
		return workflowFailure(WorkflowErrorLimitExceeded)
	}
	if session.activeContext == nil || session.materialization == nil || session.invocation == nil ||
		session.observationRevision == 0 {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	var selectedDelta *WorkflowDeltaReplayIdentity
	if session.selectedDelta != nil {
		selectedDelta = &WorkflowDeltaReplayIdentity{
			session.selectedDelta.baseBundleID,
			session.selectedDelta.targetBundleID,
			session.selectedDelta.deltaDigest,
		}
	}
	var effect *WorkflowEffectReplayIdentity
	if session.effect != nil {
		effect = &WorkflowEffectReplayIdentity{
			session.effect.effectID,
			session.effect.intentDigest,
			session.effect.effectVersion,
			session.effect.state,
			session.effect.attemptCount,
			session.effect.reconciliationCount,
		}
	}
	session.completedCycles = append(session.completedCycles, WorkflowContextCycleIdentity{
		PlanID:                  session.activeContext.planID,
		BundleID:                session.activeContext.bundleID,
		ContractDigest:          session.activeContext.contractDigest,
		SelectedDelta:           selectedDelta,
		MaterializedBundleID:    session.materialization.bundleID,
		TokenizerFingerprint:    session.materialization.tokenizerFingerprint,
		MaterializerFingerprint: session.materialization.materializerFingerprint,
		PhysicalInputTokens:     session.materialization.physicalInputTokens,
		InvocationID:            session.invocation.invocationID,
		RequestDigest:           session.invocation.requestDigest,
		IdempotencyKeyDigest:    session.invocation.idempotencyKeyDigest,
		ModelResultDigest:       session.modelResultDigest,
		Effect:                  effect,
		OutcomeDigest:           session.observationDigest,
		OutcomeRevision:         session.observationRevision,
	})
	session.completedTurns++
	session.pendingContext = nil
	session.pendingDelta = nil
	session.selectedDelta = nil
	session.materialization = nil
	session.invocation = nil
	session.modelResultDigest = ""
	session.observationDigest = ""
	session.observationRevision = 0
	session.effect = nil
	session.phase = WorkflowPhaseCheckpointed
	return nil
}

// Finish marks a checkpointed, non-empty workflow complete.
func (session *WorkflowContextSession) Finish() error {
	if err := session.requirePhase(WorkflowPhaseCheckpointed); err != nil {
		return err
	}
	if session.completedTurns == 0 {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	session.phase = WorkflowPhaseFinished
	return nil
}

// RecordReplayVerified binds a verified observational replay.
func (session *WorkflowContextSession) RecordReplayVerified(
	decisionID, executionID string,
	candidate WorkflowContextReplayIdentity,
) (WorkflowContextReplayComparison, error) {
	if err := session.requirePhase(WorkflowPhaseFinished); err != nil {
		return WorkflowContextReplayComparison{}, err
	}
	if !validDigest(decisionID) || !validRecordID(executionID) {
		return WorkflowContextReplayComparison{}, workflowFailure(WorkflowErrorInvalidEvent)
	}
	comparison, err := session.CompareReplay(candidate)
	if err != nil {
		return WorkflowContextReplayComparison{}, err
	}
	if !comparison.ExactMatch {
		return comparison, workflowFailure(WorkflowErrorIdentityMismatch)
	}
	session.replayVerified = true
	session.phase = WorkflowPhaseReplayVerified
	return comparison, nil
}

func (session *WorkflowContextSession) requirePhase(allowed ...WorkflowContextPhase) error {
	if slices.Contains(allowed, session.phase) {
		return nil
	}
	return workflowFailure(WorkflowErrorInvalidTransition)
}

func (session *WorkflowContextSession) updateEffect(
	effectID, intentDigest string,
	effectVersion uint64,
	state WorkflowEffectState,
	attemptCount, reconciliationCount uint32,
	requireNewVersion bool,
) error {
	if !validRecordID(effectID) || !validDigest(intentDigest) || effectVersion == 0 ||
		!validWorkflowEffectCounts(state, attemptCount, reconciliationCount) {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	current := session.effect
	if current == nil {
		return workflowFailure(WorkflowErrorInvalidTransition)
	}
	versionValid := effectVersion > current.effectVersion || !requireNewVersion &&
		effectVersion == current.effectVersion && state == current.state
	if effectID != current.effectID || intentDigest != current.intentDigest || !versionValid {
		return workflowFailure(WorkflowErrorIdentityMismatch)
	}
	session.effect = &workflowEffectIdentity{
		effectID, intentDigest, effectVersion, state, attemptCount, reconciliationCount,
	}
	return nil
}

func (session *WorkflowContextSession) enterQuarantine(reason WorkflowQuarantineReason) {
	session.pendingContext = nil
	session.pendingDelta = nil
	session.selectedDelta = nil
	session.materialization = nil
	session.invocation = nil
	session.modelResultDigest = ""
	session.observationDigest = ""
	session.observationRevision = 0
	session.effect = nil
	session.replayVerified = false
	session.quarantineReason = reason
	session.phase = WorkflowPhaseQuarantined
}

func cloneWorkflowReplayIdentity(identity WorkflowContextReplayIdentity) WorkflowContextReplayIdentity {
	cycles := make([]WorkflowContextCycleIdentity, len(identity.Cycles))
	for index, cycle := range identity.Cycles {
		cycles[index] = cycle
		if cycle.SelectedDelta != nil {
			selectedDelta := *cycle.SelectedDelta
			cycles[index].SelectedDelta = &selectedDelta
		}
		if cycle.Effect != nil {
			effect := *cycle.Effect
			cycles[index].Effect = &effect
		}
	}
	return WorkflowContextReplayIdentity{Cycles: cycles}
}

func validateWorkflowReplayIdentity(identity WorkflowContextReplayIdentity) error {
	if len(identity.Cycles) == 0 || len(identity.Cycles) > MaxWorkflowReplayCycles {
		return workflowFailure(WorkflowErrorInvalidEvent)
	}
	for _, cycle := range identity.Cycles {
		if !validRecordID(cycle.PlanID) || !validDigest(cycle.BundleID) ||
			!validDigest(cycle.ContractDigest) || !validDigest(cycle.MaterializedBundleID) ||
			!validDigest(cycle.TokenizerFingerprint) || !validDigest(cycle.MaterializerFingerprint) ||
			cycle.PhysicalInputTokens == 0 || !validRecordID(cycle.InvocationID) ||
			!validDigest(cycle.RequestDigest) || !validDigest(cycle.IdempotencyKeyDigest) ||
			!validDigest(cycle.ModelResultDigest) || !validDigest(cycle.OutcomeDigest) ||
			cycle.OutcomeRevision == 0 {
			return workflowFailure(WorkflowErrorInvalidEvent)
		}
		if cycle.SelectedDelta != nil {
			if !validDigest(cycle.SelectedDelta.BaseBundleID) ||
				!validDigest(cycle.SelectedDelta.TargetBundleID) ||
				!validDigest(cycle.SelectedDelta.DeltaDigest) {
				return workflowFailure(WorkflowErrorInvalidEvent)
			}
			if cycle.SelectedDelta.TargetBundleID != cycle.BundleID ||
				cycle.SelectedDelta.BaseBundleID != cycle.MaterializedBundleID ||
				cycle.SelectedDelta.BaseBundleID == cycle.SelectedDelta.TargetBundleID {
				return workflowFailure(WorkflowErrorIdentityMismatch)
			}
		}
		if cycle.Effect != nil && (!validRecordID(cycle.Effect.EffectID) ||
			!validDigest(cycle.Effect.IntentDigest) || cycle.Effect.EffectVersion == 0 ||
			!terminalWorkflowEffect(cycle.Effect.State) ||
			!validWorkflowEffectCounts(
				cycle.Effect.State, cycle.Effect.AttemptCount, cycle.Effect.ReconciliationCount,
			)) {
			return workflowFailure(WorkflowErrorInvalidEvent)
		}
	}
	return nil
}

func compareWorkflowReplay(
	baseline, candidate WorkflowContextReplayIdentity,
) WorkflowContextReplayComparison {
	sameLength := len(baseline.Cycles) == len(candidate.Cycles)
	selectionEqual, materializationEqual, modelEqual, effectEqual, outcomeEqual :=
		sameLength, sameLength, sameLength, sameLength, sameLength
	if sameLength {
		for index, left := range baseline.Cycles {
			right := candidate.Cycles[index]
			selectionEqual = selectionEqual && left.PlanID == right.PlanID &&
				left.BundleID == right.BundleID && left.ContractDigest == right.ContractDigest &&
				equalWorkflowDelta(left.SelectedDelta, right.SelectedDelta)
			materializationEqual = materializationEqual &&
				left.MaterializedBundleID == right.MaterializedBundleID &&
				left.TokenizerFingerprint == right.TokenizerFingerprint &&
				left.MaterializerFingerprint == right.MaterializerFingerprint &&
				left.PhysicalInputTokens == right.PhysicalInputTokens
			modelEqual = modelEqual && left.InvocationID == right.InvocationID &&
				left.RequestDigest == right.RequestDigest &&
				left.IdempotencyKeyDigest == right.IdempotencyKeyDigest &&
				left.ModelResultDigest == right.ModelResultDigest
			effectEqual = effectEqual && equalWorkflowEffect(left.Effect, right.Effect)
			outcomeEqual = outcomeEqual && left.OutcomeDigest == right.OutcomeDigest &&
				left.OutcomeRevision == right.OutcomeRevision
		}
	}
	comparison := WorkflowContextReplayComparison{
		BundleDeltaSelection: workflowComparisonStatus(selectionEqual),
		Materialization:      workflowComparisonStatus(materializationEqual),
		ModelResultIdentity:  workflowComparisonStatus(modelEqual),
		ToolEffectDecisions:  workflowComparisonStatus(effectEqual),
		Outcome:              workflowComparisonStatus(outcomeEqual),
	}
	comparison.ExactMatch = comparison.BundleDeltaSelection == WorkflowReplayEqual &&
		comparison.Materialization == WorkflowReplayEqual &&
		comparison.ModelResultIdentity == WorkflowReplayEqual &&
		comparison.ToolEffectDecisions == WorkflowReplayEqual &&
		comparison.Outcome == WorkflowReplayEqual
	return comparison
}

func workflowComparisonStatus(equal bool) WorkflowReplayDiffStatus {
	if equal {
		return WorkflowReplayEqual
	}
	return WorkflowReplayDifferent
}

func equalWorkflowDelta(left, right *WorkflowDeltaReplayIdentity) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func equalWorkflowEffect(left, right *WorkflowEffectReplayIdentity) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func validWorkflowQuarantineReason(reason WorkflowQuarantineReason) bool {
	return reason == WorkflowQuarantineCancelled || reason == WorkflowQuarantineRevoked ||
		reason == WorkflowQuarantineInvalidated
}

var (
	workflowDigestPattern = regexp.MustCompile(`^1220[0-9a-f]{64}$`)
	workflowRecordPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func validDigest(value string) bool   { return workflowDigestPattern.MatchString(value) }
func validRecordID(value string) bool { return workflowRecordPattern.MatchString(value) }

func workflowFailure(code WorkflowSessionErrorCode) error { return &WorkflowSessionError{Code: code} }

func terminalWorkflowEffect(state WorkflowEffectState) bool {
	return state == WorkflowEffectSucceeded || state == WorkflowEffectFailed ||
		state == WorkflowEffectManualResolution || state == WorkflowEffectRejected ||
		state == WorkflowEffectExpired || state == WorkflowEffectCancelled ||
		state == WorkflowEffectCompensated || state == WorkflowEffectCompensationFailed
}

func validWorkflowEffectCounts(state WorkflowEffectState, attempts, reconciliations uint32) bool {
	if reconciliations != 0 && attempts == 0 {
		return false
	}
	switch state {
	case WorkflowEffectPrepared, WorkflowEffectAuthorized, WorkflowEffectRejected:
		return attempts == 0 && reconciliations == 0
	case WorkflowEffectDispatching, WorkflowEffectSucceeded, WorkflowEffectFailed, WorkflowEffectUnknown,
		WorkflowEffectCompensated, WorkflowEffectCompensationFailed:
		return attempts != 0
	case WorkflowEffectAuthorizedForRetry, WorkflowEffectManualResolution:
		return attempts != 0 && reconciliations != 0
	case WorkflowEffectExpired, WorkflowEffectCancelled:
		return true
	default:
		return false
	}
}

func workflowEffectPhase(state WorkflowEffectState) (WorkflowContextPhase, error) {
	switch {
	case state == WorkflowEffectDispatching:
		return WorkflowPhaseEffectDispatching, nil
	case state == WorkflowEffectUnknown:
		return WorkflowPhaseEffectAmbiguous, nil
	case state == WorkflowEffectAuthorizedForRetry:
		return WorkflowPhaseEffectAuthorized, nil
	case terminalWorkflowEffect(state):
		return WorkflowPhaseEffectSettled, nil
	default:
		return "", workflowFailure(WorkflowErrorInvalidEvent)
	}
}
