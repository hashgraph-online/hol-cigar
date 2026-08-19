//! Cross-SDK workflow context-session parity and transition tests.

use cigar_sdk::protocol::{ContentDigest, DiffStatus, EffectState, RecordId, VersionId};
use cigar_sdk::{
    MAX_WORKFLOW_DELTA_CHAIN_LENGTH, MAX_WORKFLOW_REPLAY_CYCLES, WORKFLOW_SESSION_EVENT_NAMES,
    WorkflowContextPhase, WorkflowContextSession, WorkflowEffectReplayIdentity,
    WorkflowQuarantineReason, WorkflowResumeAction, WorkflowSessionErrorCode, WorkflowSessionEvent,
};
use serde::Deserialize;
use std::error::Error;

const CONTRACT: &[u8] = include_bytes!("../../workflow-context-session.v1.json");

#[derive(Deserialize)]
struct Contract {
    schema_version: String,
    maximum_delta_chain_length: u16,
    maximum_replay_cycles: usize,
    phases: Vec<String>,
    error_codes: Vec<String>,
    resume_actions: Vec<Action>,
    events: Vec<String>,
    quarantine_reasons: Vec<String>,
    retry_fences: RetryFences,
    replay_comparison_dimensions: Vec<String>,
    replay_verification: String,
    telemetry: TelemetryContract,
}

#[derive(Deserialize)]
struct RetryFences {
    provider_invocation: String,
    effect_retry: String,
}

#[derive(Deserialize)]
struct TelemetryContract {
    maximum_added_series: usize,
    label_policy: String,
    families: Vec<String>,
}

#[derive(Deserialize)]
struct Action {
    action: String,
    operation_id: Option<String>,
}

fn digest(character: char) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        character.to_string().repeat(64)
    ))?)
}

fn version(character: char) -> Result<VersionId, Box<dyn Error>> {
    Ok(VersionId::new(digest(character)?.as_str())?)
}

fn record(suffix: u8) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f78{suffix:02x}"
    ))?)
}

fn initial_cycle(session: &mut WorkflowContextSession) -> Result<(), Box<dyn Error>> {
    session.advance(WorkflowSessionEvent::PlanCreated {
        plan_id: record(1)?,
        bundle_id: version('a')?,
        contract_digest: digest('1')?,
    })?;
    session.advance(WorkflowSessionEvent::BundleCompiled {
        bundle_id: version('a')?,
        contract_digest: digest('1')?,
    })?;
    session.advance(WorkflowSessionEvent::Materialized {
        bundle_id: version('a')?,
        tokenizer_fingerprint: digest('2')?,
        materializer_fingerprint: digest('3')?,
        physical_input_tokens: 10,
    })?;
    session.advance(WorkflowSessionEvent::ModelInvocationStarted {
        invocation_id: record(2)?,
        request_digest: digest('4')?,
        idempotency_key_digest: digest('8')?,
    })?;
    session.advance(WorkflowSessionEvent::ModelResultRecorded {
        invocation_id: record(2)?,
        result_digest: digest('5')?,
    })?;
    Ok(())
}

fn advance_target(session: &mut WorkflowContextSession) -> Result<(), Box<dyn Error>> {
    session.advance(WorkflowSessionEvent::ObservationRecorded {
        publication_digest: digest('6')?,
        revision: 1,
    })?;
    session.advance(WorkflowSessionEvent::PlanCreated {
        plan_id: record(3)?,
        bundle_id: version('b')?,
        contract_digest: digest('7')?,
    })?;
    session.advance(WorkflowSessionEvent::BundleCompiled {
        bundle_id: version('b')?,
        contract_digest: digest('7')?,
    })?;
    session.advance(WorkflowSessionEvent::DeltaCompiled {
        base_bundle_id: version('a')?,
        target_bundle_id: version('b')?,
        delta_digest: digest('8')?,
    })?;
    session.advance(WorkflowSessionEvent::DeltaApplied {
        base_bundle_id: version('a')?,
        target_bundle_id: version('b')?,
        delta_digest: digest('8')?,
    })?;
    Ok(())
}

#[test]
fn shared_contract_inventory_is_exact() -> Result<(), Box<dyn Error>> {
    let contract: Contract = serde_json::from_slice(CONTRACT)?;
    assert_eq!(
        contract.schema_version,
        "cigar.sdk-workflow-context-session.v1"
    );
    assert_eq!(
        contract.maximum_delta_chain_length,
        MAX_WORKFLOW_DELTA_CHAIN_LENGTH
    );
    assert_eq!(contract.maximum_replay_cycles, MAX_WORKFLOW_REPLAY_CYCLES);
    let phases = [
        WorkflowContextPhase::New,
        WorkflowContextPhase::PlanCreated,
        WorkflowContextPhase::TargetBundleLoaded,
        WorkflowContextPhase::DeltaCompiled,
        WorkflowContextPhase::BundleReady,
        WorkflowContextPhase::Materialized,
        WorkflowContextPhase::ModelInvocationPending,
        WorkflowContextPhase::ModelResultRecorded,
        WorkflowContextPhase::EffectPrepared,
        WorkflowContextPhase::ObservationRecorded,
        WorkflowContextPhase::EffectAuthorizationRevalidated,
        WorkflowContextPhase::EffectAuthorized,
        WorkflowContextPhase::EffectRevalidated,
        WorkflowContextPhase::EffectDispatching,
        WorkflowContextPhase::EffectAmbiguous,
        WorkflowContextPhase::EffectSettled,
        WorkflowContextPhase::Checkpointed,
        WorkflowContextPhase::Finished,
        WorkflowContextPhase::ReplayVerified,
        WorkflowContextPhase::Quarantined,
    ];
    let error_codes = [
        WorkflowSessionErrorCode::InvalidTransition,
        WorkflowSessionErrorCode::InvalidEvent,
        WorkflowSessionErrorCode::IdentityMismatch,
        WorkflowSessionErrorCode::Invalidated,
        WorkflowSessionErrorCode::LimitExceeded,
    ];
    let actions = [
        WorkflowResumeAction::CreateContextPlan,
        WorkflowResumeAction::CompileContextBundle,
        WorkflowResumeAction::CompileContextDelta,
        WorkflowResumeAction::ApplyContextDelta,
        WorkflowResumeAction::MaterializeContextBundle,
        WorkflowResumeAction::BeginModelInvocation,
        WorkflowResumeAction::ResumeModelInvocation,
        WorkflowResumeAction::PrepareEffectOrIngestObservation,
        WorkflowResumeAction::IngestObservation,
        WorkflowResumeAction::AuthorizeEffectOrCheckpoint,
        WorkflowResumeAction::RevalidateContextBundle,
        WorkflowResumeAction::DispatchEffect,
        WorkflowResumeAction::ObserveEffect,
        WorkflowResumeAction::ReconcileEffect,
        WorkflowResumeAction::Checkpoint,
        WorkflowResumeAction::MaterializeOrFinish,
        WorkflowResumeAction::Replay,
        WorkflowResumeAction::Complete,
    ];
    assert_eq!(
        contract.phases,
        phases.map(|phase| phase.as_str().to_owned())
    );
    assert_eq!(
        contract.error_codes,
        error_codes.map(|code| code.as_str().to_owned())
    );
    assert_eq!(contract.resume_actions.len(), actions.len());
    for (entry, action) in contract.resume_actions.iter().zip(actions) {
        assert_eq!(entry.action, action.as_str());
        assert_eq!(entry.operation_id.as_deref(), action.operation_id());
    }
    assert_eq!(contract.events, WORKFLOW_SESSION_EVENT_NAMES);
    assert_eq!(
        contract.quarantine_reasons,
        [
            WorkflowQuarantineReason::Cancelled,
            WorkflowQuarantineReason::Revoked,
            WorkflowQuarantineReason::Invalidated,
        ]
        .map(|reason| reason.as_str().to_owned())
    );
    assert_eq!(
        contract.retry_fences.provider_invocation,
        "durable_invocation_and_idempotency_key_digest_required_before_call"
    );
    assert_eq!(
        contract.retry_fences.effect_retry,
        "durable_reconciliation_count_must_advance_before_authorized_for_retry"
    );
    assert_eq!(
        contract.replay_comparison_dimensions,
        [
            "bundle_delta_selection",
            "materialization",
            "model_result_identity",
            "tool_effect_decisions",
            "outcome",
        ]
    );
    assert_eq!(
        contract.replay_verification,
        "all_exact_identity_dimensions_must_equal"
    );
    assert_eq!(contract.telemetry.maximum_added_series, 17);
    assert_eq!(
        contract.telemetry.label_policy,
        "single_closed_static_dimension_no_identifiers_or_content"
    );
    assert_eq!(
        contract.telemetry.families,
        [
            "cigar_workflow_context_cycles_total",
            "cigar_workflow_context_selections_total",
            "cigar_workflow_context_delta_blocks_total",
            "cigar_workflow_context_recoveries_total",
            "cigar_workflow_context_replay_dimensions_total",
            "cigar_workflow_context_replay_verifications_total",
        ]
    );
    Ok(())
}

#[test]
fn delta_chain_bound_forces_full_bundle_checkpoint() -> Result<(), Box<dyn Error>> {
    let mut session = WorkflowContextSession::new();
    initial_cycle(&mut session)?;
    let targets = ['b', 'c', 'd', 'e', 'f', '1', '2', '3'];
    let mut base = 'a';
    for (index, target) in targets.into_iter().enumerate() {
        session.advance(WorkflowSessionEvent::ObservationRecorded {
            publication_digest: digest('6')?,
            revision: u64::try_from(index + 1)?,
        })?;
        session.advance(WorkflowSessionEvent::PlanCreated {
            plan_id: record(u8::try_from(index + 3)?)?,
            bundle_id: version(target)?,
            contract_digest: digest('7')?,
        })?;
        session.advance(WorkflowSessionEvent::BundleCompiled {
            bundle_id: version(target)?,
            contract_digest: digest('7')?,
        })?;
        session.advance(WorkflowSessionEvent::DeltaCompiled {
            base_bundle_id: version(base)?,
            target_bundle_id: version(target)?,
            delta_digest: digest('8')?,
        })?;
        session.advance(WorkflowSessionEvent::DeltaApplied {
            base_bundle_id: version(base)?,
            target_bundle_id: version(target)?,
            delta_digest: digest('8')?,
        })?;
        base = target;
        if index + 1 < usize::from(MAX_WORKFLOW_DELTA_CHAIN_LENGTH) {
            session.advance(WorkflowSessionEvent::CycleCheckpointed)?;
            session.advance(WorkflowSessionEvent::Materialized {
                bundle_id: version(base)?,
                tokenizer_fingerprint: digest('2')?,
                materializer_fingerprint: digest('3')?,
                physical_input_tokens: 10,
            })?;
            let invocation_id = record(u8::try_from(index + 20)?)?;
            session.advance(WorkflowSessionEvent::ModelInvocationStarted {
                invocation_id: invocation_id.clone(),
                request_digest: digest('4')?,
                idempotency_key_digest: digest('8')?,
            })?;
            session.advance(WorkflowSessionEvent::ModelResultRecorded {
                invocation_id,
                result_digest: digest('5')?,
            })?;
        }
    }
    assert_eq!(
        session.delta_chain_length(),
        MAX_WORKFLOW_DELTA_CHAIN_LENGTH
    );

    session.advance(WorkflowSessionEvent::CycleCheckpointed)?;
    session.advance(WorkflowSessionEvent::Materialized {
        bundle_id: version(base)?,
        tokenizer_fingerprint: digest('2')?,
        materializer_fingerprint: digest('3')?,
        physical_input_tokens: 10,
    })?;
    let invocation_id = record(40)?;
    session.advance(WorkflowSessionEvent::ModelInvocationStarted {
        invocation_id: invocation_id.clone(),
        request_digest: digest('4')?,
        idempotency_key_digest: digest('8')?,
    })?;
    session.advance(WorkflowSessionEvent::ModelResultRecorded {
        invocation_id,
        result_digest: digest('5')?,
    })?;
    session.advance(WorkflowSessionEvent::ObservationRecorded {
        publication_digest: digest('6')?,
        revision: 9,
    })?;
    session.advance(WorkflowSessionEvent::PlanCreated {
        plan_id: record(41)?,
        bundle_id: version('4')?,
        contract_digest: digest('7')?,
    })?;
    session.advance(WorkflowSessionEvent::BundleCompiled {
        bundle_id: version('4')?,
        contract_digest: digest('7')?,
    })?;
    assert_eq!(session.phase(), WorkflowContextPhase::BundleReady);
    assert_eq!(session.active_bundle_id(), Some(&version('4')?));
    assert_eq!(session.delta_chain_length(), 0);
    assert_eq!(session.resume_action(), WorkflowResumeAction::Checkpoint);
    Ok(())
}

#[test]
fn no_effect_cycle_reaches_verified_replay() -> Result<(), Box<dyn Error>> {
    let mut session = WorkflowContextSession::new();
    initial_cycle(&mut session)?;
    advance_target(&mut session)?;
    assert_eq!(session.active_bundle_id(), Some(&version('b')?));
    assert_eq!(session.delta_chain_length(), 1);
    assert_eq!(session.resume_action(), WorkflowResumeAction::Checkpoint);
    session.advance(WorkflowSessionEvent::CycleCheckpointed)?;
    session.advance(WorkflowSessionEvent::Finished)?;
    let baseline = session.replay_identity()?;
    let exact = session.compare_replay(&baseline)?;
    assert!(exact.exact_match);
    assert_eq!(exact.bundle_delta_selection, DiffStatus::Equal);
    let mut incoherent = baseline.clone();
    incoherent
        .cycles
        .first_mut()
        .and_then(|cycle| cycle.selected_delta.as_mut())
        .ok_or("missing replay delta")?
        .base_bundle_id = version('c')?;
    assert_eq!(
        session
            .compare_replay(&incoherent)
            .map_err(|error| error.code()),
        Err(WorkflowSessionErrorCode::InvalidEvent)
    );
    let mut impossible_effect = baseline.clone();
    impossible_effect
        .cycles
        .first_mut()
        .ok_or("missing replay cycle")?
        .effect = Some(WorkflowEffectReplayIdentity {
        effect_id: record(8)?,
        intent_digest: digest('9')?,
        effect_version: 3,
        state: EffectState::Succeeded,
        attempt_count: 0,
        reconciliation_count: 0,
    });
    assert_eq!(
        session
            .compare_replay(&impossible_effect)
            .map_err(|error| error.code()),
        Err(WorkflowSessionErrorCode::InvalidEvent)
    );
    let mut changed = baseline.clone();
    let Some(cycle) = changed.cycles.first_mut() else {
        return Err("replay baseline omitted its completed cycle".into());
    };
    cycle.outcome_digest = digest('d')?;
    let comparison = session.compare_replay(&changed)?;
    assert_eq!(comparison.outcome, DiffStatus::Different);
    assert_eq!(comparison.bundle_delta_selection, DiffStatus::Equal);
    assert!(!comparison.exact_match);
    let before = session.clone();
    let Err(error) = session.advance(WorkflowSessionEvent::ReplayVerified {
        decision_id: version('c')?,
        execution_id: record(4)?,
        candidate: changed,
    }) else {
        return Err("mismatched outcome replay unexpectedly verified".into());
    };
    assert_eq!(error.code(), WorkflowSessionErrorCode::IdentityMismatch);
    assert_eq!(session, before);
    session.advance(WorkflowSessionEvent::ReplayVerified {
        decision_id: version('c')?,
        execution_id: record(4)?,
        candidate: baseline,
    })?;
    assert_eq!(session.completed_turns(), 1);
    assert_eq!(session.phase(), WorkflowContextPhase::ReplayVerified);
    assert_eq!(session.resume_action(), WorkflowResumeAction::Complete);
    Ok(())
}

#[test]
fn ambiguous_effect_retry_requires_another_revalidation() -> Result<(), Box<dyn Error>> {
    let mut session = WorkflowContextSession::new();
    let effect_id = record(8)?;
    let intent_digest = digest('9')?;
    initial_cycle(&mut session)?;
    session.advance(WorkflowSessionEvent::EffectPrepared {
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version: 1,
        state: EffectState::Prepared,
        attempt_count: 0,
        reconciliation_count: 0,
    })?;
    advance_target(&mut session)?;
    assert_eq!(
        session.resume_action(),
        WorkflowResumeAction::RevalidateContextBundle
    );
    session.advance(WorkflowSessionEvent::EffectRevalidated {
        bundle_id: version('b')?,
        valid: true,
    })?;
    assert_eq!(
        session.phase(),
        WorkflowContextPhase::EffectAuthorizationRevalidated
    );
    session.advance(WorkflowSessionEvent::EffectAuthorized {
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version: 2,
        state: EffectState::Authorized,
        attempt_count: 0,
        reconciliation_count: 0,
    })?;
    session.advance(WorkflowSessionEvent::EffectRevalidated {
        bundle_id: version('b')?,
        valid: true,
    })?;
    session.advance(WorkflowSessionEvent::EffectDispatched {
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version: 3,
        state: EffectState::Unknown,
        attempt_count: 1,
        reconciliation_count: 0,
    })?;
    let before = session.clone();
    let Err(error) = session.advance(WorkflowSessionEvent::EffectObserved {
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version: 4,
        state: EffectState::AuthorizedForRetry,
        attempt_count: 1,
        reconciliation_count: 0,
    }) else {
        return Err("retry without reconciliation proof unexpectedly succeeded".into());
    };
    assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidEvent);
    assert_eq!(session, before);
    session.advance(WorkflowSessionEvent::EffectObserved {
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version: 4,
        state: EffectState::AuthorizedForRetry,
        attempt_count: 1,
        reconciliation_count: 1,
    })?;
    let before = session.clone();
    let Err(error) = session.advance(WorkflowSessionEvent::EffectDispatched {
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version: 5,
        state: EffectState::Succeeded,
        attempt_count: 2,
        reconciliation_count: 1,
    }) else {
        return Err("retry dispatch without revalidation unexpectedly succeeded".into());
    };
    assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
    assert_eq!(session, before);
    session.advance(WorkflowSessionEvent::EffectRevalidated {
        bundle_id: version('b')?,
        valid: true,
    })?;
    session.advance(WorkflowSessionEvent::EffectDispatched {
        effect_id,
        intent_digest,
        effect_version: 5,
        state: EffectState::Succeeded,
        attempt_count: 2,
        reconciliation_count: 1,
    })?;
    session.advance(WorkflowSessionEvent::CycleCheckpointed)?;
    Ok(())
}

#[test]
fn cancellation_quarantines_a_late_provider_result() -> Result<(), Box<dyn Error>> {
    let mut session = WorkflowContextSession::new();
    session.advance(WorkflowSessionEvent::PlanCreated {
        plan_id: record(1)?,
        bundle_id: version('a')?,
        contract_digest: digest('1')?,
    })?;
    session.advance(WorkflowSessionEvent::BundleCompiled {
        bundle_id: version('a')?,
        contract_digest: digest('1')?,
    })?;
    session.advance(WorkflowSessionEvent::Materialized {
        bundle_id: version('a')?,
        tokenizer_fingerprint: digest('2')?,
        materializer_fingerprint: digest('3')?,
        physical_input_tokens: 10,
    })?;
    session.advance(WorkflowSessionEvent::ModelInvocationStarted {
        invocation_id: record(2)?,
        request_digest: digest('4')?,
        idempotency_key_digest: digest('8')?,
    })?;
    session.advance(WorkflowSessionEvent::ContextQuarantined {
        bundle_id: version('a')?,
        reason: WorkflowQuarantineReason::Cancelled,
    })?;
    let before = session.clone();
    let Err(error) = session.advance(WorkflowSessionEvent::ModelResultRecorded {
        invocation_id: record(2)?,
        result_digest: digest('5')?,
    }) else {
        return Err("late provider result after cancellation was accepted".into());
    };
    assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
    assert_eq!(session, before);
    assert_eq!(session.phase(), WorkflowContextPhase::Quarantined);
    assert_eq!(session.resume_action(), WorkflowResumeAction::Complete);
    Ok(())
}

#[test]
fn failed_transition_is_atomic_and_content_free() -> Result<(), Box<dyn Error>> {
    let mut session = WorkflowContextSession::new();
    let before = session.clone();
    let Err(error) = session.advance(WorkflowSessionEvent::BundleCompiled {
        bundle_id: version('a')?,
        contract_digest: digest('1')?,
    }) else {
        return Err("bundle before plan unexpectedly succeeded".into());
    };
    assert_eq!(error.code(), WorkflowSessionErrorCode::InvalidTransition);
    assert_eq!(session, before);
    assert!(!format!("{session:?}").contains(version('a')?.as_str()));
    Ok(())
}
