package cigar

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func workflowDigest(character string) string { return "1220" + strings.Repeat(character, 64) }
func workflowRecord(suffix uint8) string {
	return fmt.Sprintf("01890f47-8e7d-7b42-a1d2-3c4d5e6f78%02x", suffix)
}

func initialWorkflowCycle(t *testing.T, session *WorkflowContextSession) {
	t.Helper()
	steps := []error{
		session.RecordPlanCreated(workflowRecord(1), workflowDigest("a"), workflowDigest("1")),
		session.RecordBundleCompiled(workflowDigest("a"), workflowDigest("1")),
		session.RecordMaterialized(workflowDigest("a"), workflowDigest("2"), workflowDigest("3"), 10),
		session.BeginModelInvocation(workflowRecord(2), workflowDigest("4"), workflowDigest("8")),
		session.RecordModelResult(workflowRecord(2), workflowDigest("5")),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func advanceWorkflowTarget(t *testing.T, session *WorkflowContextSession) {
	t.Helper()
	steps := []error{
		session.RecordObservation(workflowDigest("6"), 1),
		session.RecordPlanCreated(workflowRecord(3), workflowDigest("b"), workflowDigest("7")),
		session.RecordBundleCompiled(workflowDigest("b"), workflowDigest("7")),
		session.RecordDeltaCompiled(workflowDigest("a"), workflowDigest("b"), workflowDigest("8")),
		session.RecordDeltaApplied(workflowDigest("a"), workflowDigest("b"), workflowDigest("8")),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkflowSharedContractInventoryIsExact(t *testing.T) {
	contractBytes, err := os.ReadFile("../workflow-context-session.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		SchemaVersion           string   `json:"schema_version"`
		MaximumDeltaChainLength uint16   `json:"maximum_delta_chain_length"`
		MaximumReplayCycles     int      `json:"maximum_replay_cycles"`
		Phases                  []string `json:"phases"`
		ErrorCodes              []string `json:"error_codes"`
		ResumeActions           []struct {
			Action      string  `json:"action"`
			OperationID *string `json:"operation_id"`
		} `json:"resume_actions"`
		Events            []string `json:"events"`
		QuarantineReasons []string `json:"quarantine_reasons"`
		RetryFences       struct {
			ProviderInvocation string `json:"provider_invocation"`
			EffectRetry        string `json:"effect_retry"`
		} `json:"retry_fences"`
		ReplayComparisonDimensions []string `json:"replay_comparison_dimensions"`
		ReplayVerification         string   `json:"replay_verification"`
		Telemetry                  struct {
			MaximumAddedSeries int      `json:"maximum_added_series"`
			LabelPolicy        string   `json:"label_policy"`
			Families           []string `json:"families"`
		} `json:"telemetry"`
	}
	if err := json.Unmarshal(contractBytes, &contract); err != nil {
		t.Fatal(err)
	}
	phases := make([]string, 0, len(WorkflowContextPhases()))
	for _, phase := range WorkflowContextPhases() {
		phases = append(phases, string(phase))
	}
	codes := make([]string, 0, len(WorkflowSessionErrorCodes()))
	for _, code := range WorkflowSessionErrorCodes() {
		codes = append(codes, string(code))
	}
	if contract.SchemaVersion != "cigar.sdk-workflow-context-session.v1" ||
		contract.MaximumDeltaChainLength != MaxWorkflowDeltaChainLength ||
		contract.MaximumReplayCycles != MaxWorkflowReplayCycles ||
		!reflect.DeepEqual(contract.Phases, phases) || !reflect.DeepEqual(contract.ErrorCodes, codes) ||
		len(contract.ResumeActions) != len(WorkflowResumeActions()) ||
		!reflect.DeepEqual(contract.Events, WorkflowSessionEventNames()) ||
		!reflect.DeepEqual(contract.QuarantineReasons, []string{"cancelled", "revoked", "invalidated"}) ||
		contract.RetryFences.ProviderInvocation !=
			"durable_invocation_and_idempotency_key_digest_required_before_call" ||
		contract.RetryFences.EffectRetry !=
			"durable_reconciliation_count_must_advance_before_authorized_for_retry" ||
		!reflect.DeepEqual(contract.ReplayComparisonDimensions, []string{
			"bundle_delta_selection", "materialization", "model_result_identity",
			"tool_effect_decisions", "outcome",
		}) || contract.ReplayVerification != "all_exact_identity_dimensions_must_equal" ||
		contract.Telemetry.MaximumAddedSeries != 17 ||
		contract.Telemetry.LabelPolicy != "single_closed_static_dimension_no_identifiers_or_content" ||
		!reflect.DeepEqual(contract.Telemetry.Families, []string{
			"cigar_workflow_context_cycles_total",
			"cigar_workflow_context_selections_total",
			"cigar_workflow_context_delta_blocks_total",
			"cigar_workflow_context_recoveries_total",
			"cigar_workflow_context_replay_dimensions_total",
			"cigar_workflow_context_replay_verifications_total",
		}) {
		t.Fatalf("shared workflow contract differs: %+v", contract)
	}
	for index, action := range WorkflowResumeActions() {
		entry := contract.ResumeActions[index]
		operationID := action.OperationID()
		if entry.Action != string(action) || entry.OperationID == nil && operationID != "" ||
			entry.OperationID != nil && *entry.OperationID != operationID {
			t.Fatalf("resume action %d differs: %+v action=%s operation=%s", index, entry, action, operationID)
		}
	}
}

func TestWorkflowDeltaChainBoundForcesFullBundleCheckpoint(t *testing.T) {
	session := NewWorkflowContextSession()
	initialWorkflowCycle(t, session)
	base := "a"
	for index, target := range []string{"b", "c", "d", "e", "f", "1", "2", "3"} {
		steps := []error{
			session.RecordObservation(workflowDigest("6"), uint64(index+1)),
			session.RecordPlanCreated(workflowRecord(uint8(index+3)), workflowDigest(target), workflowDigest("7")),
			session.RecordBundleCompiled(workflowDigest(target), workflowDigest("7")),
			session.RecordDeltaCompiled(workflowDigest(base), workflowDigest(target), workflowDigest("8")),
			session.RecordDeltaApplied(workflowDigest(base), workflowDigest(target), workflowDigest("8")),
		}
		for _, err := range steps {
			if err != nil {
				t.Fatal(err)
			}
		}
		base = target
		if index+1 < int(MaxWorkflowDeltaChainLength) {
			steps = []error{
				session.CheckpointCycle(),
				session.RecordMaterialized(workflowDigest(base), workflowDigest("2"), workflowDigest("3"), 10),
				session.BeginModelInvocation(
					workflowRecord(uint8(index+20)), workflowDigest("4"), workflowDigest("8"),
				),
				session.RecordModelResult(workflowRecord(uint8(index+20)), workflowDigest("5")),
			}
			for _, err := range steps {
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if session.DeltaChainLength() != MaxWorkflowDeltaChainLength {
		t.Fatalf("delta chain did not reach bound: %d", session.DeltaChainLength())
	}
	steps := []error{
		session.CheckpointCycle(),
		session.RecordMaterialized(workflowDigest(base), workflowDigest("2"), workflowDigest("3"), 10),
		session.BeginModelInvocation(workflowRecord(40), workflowDigest("4"), workflowDigest("8")),
		session.RecordModelResult(workflowRecord(40), workflowDigest("5")),
		session.RecordObservation(workflowDigest("6"), 9),
		session.RecordPlanCreated(workflowRecord(41), workflowDigest("4"), workflowDigest("7")),
		session.RecordBundleCompiled(workflowDigest("4"), workflowDigest("7")),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
	activeBundle, active := session.ActiveBundleID()
	if session.Phase() != WorkflowPhaseBundleReady || !active || activeBundle != workflowDigest("4") ||
		session.DeltaChainLength() != 0 || session.ResumeAction() != WorkflowActionCheckpoint {
		t.Fatalf("full checkpoint not promoted: %s", session)
	}
}

func TestWorkflowNoEffectCycleReachesVerifiedReplay(t *testing.T) {
	session := NewWorkflowContextSession()
	initialWorkflowCycle(t, session)
	advanceWorkflowTarget(t, session)
	bundleID, active := session.ActiveBundleID()
	if !active || bundleID != workflowDigest("b") || session.DeltaChainLength() != 1 ||
		session.ResumeAction() != WorkflowActionCheckpoint {
		t.Fatalf("unexpected ready session: %s", session)
	}
	steps := []error{
		session.CheckpointCycle(),
		session.Finish(),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
	baseline, err := session.ReplayIdentity()
	if err != nil {
		t.Fatal(err)
	}
	exact, err := session.CompareReplay(baseline)
	if err != nil || !exact.ExactMatch {
		t.Fatalf("exact replay did not compare equal: comparison=%+v error=%v", exact, err)
	}
	incoherent, err := session.ReplayIdentity()
	if err != nil || incoherent.Cycles[0].SelectedDelta == nil {
		t.Fatalf("replay delta unavailable: %v", err)
	}
	incoherent.Cycles[0].SelectedDelta.BaseBundleID = workflowDigest("c")
	_, err = session.CompareReplay(incoherent)
	var incoherentError *WorkflowSessionError
	if !errors.As(err, &incoherentError) || incoherentError.Code != WorkflowErrorIdentityMismatch {
		t.Fatalf("incoherent delta base was not rejected: %v", err)
	}
	impossibleEffect, err := session.ReplayIdentity()
	if err != nil {
		t.Fatal(err)
	}
	impossibleEffect.Cycles[0].Effect = &WorkflowEffectReplayIdentity{
		EffectID: workflowRecord(8), IntentDigest: workflowDigest("9"), EffectVersion: 3,
		State: WorkflowEffectSucceeded, AttemptCount: 0, ReconciliationCount: 0,
	}
	_, err = session.CompareReplay(impossibleEffect)
	var invalidEffect *WorkflowSessionError
	if !errors.As(err, &invalidEffect) || invalidEffect.Code != WorkflowErrorInvalidEvent {
		t.Fatalf("impossible terminal effect counts were not rejected: %v", err)
	}
	changed, err := session.ReplayIdentity()
	if err != nil {
		t.Fatal(err)
	}
	changed.Cycles[0].OutcomeDigest = workflowDigest("d")
	comparison, err := session.CompareReplay(changed)
	if err != nil || comparison.Outcome != WorkflowReplayDifferent ||
		comparison.BundleDeltaSelection != WorkflowReplayEqual || comparison.ExactMatch {
		t.Fatalf("unexpected replay difference: comparison=%+v error=%v", comparison, err)
	}
	_, err = session.RecordReplayVerified(workflowDigest("c"), workflowRecord(4), changed)
	var mismatch *WorkflowSessionError
	if !errors.As(err, &mismatch) || mismatch.Code != WorkflowErrorIdentityMismatch ||
		session.Phase() != WorkflowPhaseFinished {
		t.Fatalf("mismatched replay was not rejected atomically: phase=%s error=%v", session.Phase(), err)
	}
	if _, err := session.RecordReplayVerified(workflowDigest("c"), workflowRecord(4), baseline); err != nil {
		t.Fatal(err)
	}
	if session.CompletedTurns() != 1 || session.Phase() != WorkflowPhaseReplayVerified ||
		session.ResumeAction() != WorkflowActionComplete {
		t.Fatalf("unexpected replay session: %s", session)
	}
}

func TestWorkflowAmbiguousRetryRequiresRevalidation(t *testing.T) {
	session := NewWorkflowContextSession()
	effectID := workflowRecord(8)
	initialWorkflowCycle(t, session)
	if err := session.RecordEffectPrepared(
		effectID, workflowDigest("9"), 1, WorkflowEffectPrepared, 0, 0,
	); err != nil {
		t.Fatal(err)
	}
	advanceWorkflowTarget(t, session)
	steps := []error{
		session.RecordEffectRevalidated(workflowDigest("b"), true),
		session.RecordEffectAuthorized(effectID, workflowDigest("9"), 2, WorkflowEffectAuthorized, 0, 0),
		session.RecordEffectRevalidated(workflowDigest("b"), true),
		session.RecordEffectDispatched(effectID, workflowDigest("9"), 3, WorkflowEffectUnknown, 1, 0),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
	missingReconciliation := session.RecordEffectObserved(
		effectID, workflowDigest("9"), 4, WorkflowEffectAuthorizedForRetry, 1, 0,
	)
	var missingProof *WorkflowSessionError
	if !errors.As(missingReconciliation, &missingProof) || missingProof.Code != WorkflowErrorInvalidEvent {
		t.Fatalf("retry without reconciliation proof was accepted: %v", missingReconciliation)
	}
	if err := session.RecordEffectObserved(
		effectID, workflowDigest("9"), 4, WorkflowEffectAuthorizedForRetry, 1, 1,
	); err != nil {
		t.Fatal(err)
	}
	err := session.RecordEffectDispatched(effectID, workflowDigest("9"), 5, WorkflowEffectSucceeded, 2, 1)
	var transition *WorkflowSessionError
	if !errors.As(err, &transition) || transition.Code != WorkflowErrorInvalidTransition ||
		session.Phase() != WorkflowPhaseEffectAuthorized {
		t.Fatalf("retry bypass was not rejected atomically: err=%v session=%s", err, session)
	}
	steps = []error{
		session.RecordEffectRevalidated(workflowDigest("b"), true),
		session.RecordEffectDispatched(effectID, workflowDigest("9"), 5, WorkflowEffectSucceeded, 2, 1),
		session.CheckpointCycle(),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkflowCancellationQuarantinesLateProviderResult(t *testing.T) {
	session := NewWorkflowContextSession()
	steps := []error{
		session.RecordPlanCreated(workflowRecord(1), workflowDigest("a"), workflowDigest("1")),
		session.RecordBundleCompiled(workflowDigest("a"), workflowDigest("1")),
		session.RecordMaterialized(workflowDigest("a"), workflowDigest("2"), workflowDigest("3"), 10),
		session.BeginModelInvocation(workflowRecord(2), workflowDigest("4"), workflowDigest("8")),
		session.QuarantineContext(workflowDigest("a"), WorkflowQuarantineCancelled),
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
	err := session.RecordModelResult(workflowRecord(2), workflowDigest("5"))
	var transition *WorkflowSessionError
	if !errors.As(err, &transition) || transition.Code != WorkflowErrorInvalidTransition ||
		session.Phase() != WorkflowPhaseQuarantined || session.ResumeAction() != WorkflowActionComplete {
		t.Fatalf("late provider result was not quarantined: err=%v session=%s", err, session)
	}
}

func TestWorkflowFailureIsAtomicAndContentFree(t *testing.T) {
	session := NewWorkflowContextSession()
	err := session.RecordBundleCompiled(workflowDigest("a"), workflowDigest("1"))
	var transition *WorkflowSessionError
	if !errors.As(err, &transition) || transition.Code != WorkflowErrorInvalidTransition ||
		session.Phase() != WorkflowPhaseNew || strings.Contains(session.String(), workflowDigest("a")) {
		t.Fatalf("unexpected failure behavior: err=%v session=%s", err, session)
	}
}
