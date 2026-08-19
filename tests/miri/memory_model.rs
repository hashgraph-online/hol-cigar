use cigar_canon::{CanonicalNode, from_deterministic_cbor, to_deterministic_cbor};
use cigar_protocol::{
    ContentDigest, ContextBlock, ContextBundle, DiffStatus, EffectState, ExtensionMap, LaneKind,
    RecordId, RepresentationKind, SchemaVersion, Validate, VersionId,
};
use std::collections::BTreeMap;
use workflow_context_session::{
    WorkflowAppliedDeltaRecord, WorkflowContextPhase, WorkflowContextSession, WorkflowDeltaRecord,
    WorkflowEffectStatusRecord, WorkflowMaterializationRecord, WorkflowPlanRecord,
    WorkflowQuarantineReason, WorkflowResumeAction, WorkflowRevalidationRecord,
};

// Compile and execute the exact production state-machine implementation without pulling the
// daemon's TLS, database, keyring, or process runtime into Miri. Its nested unit tests exercise the
// closed transition table, delta application, effect fencing, quarantine, replay, and durable
// restoration under the interpreter.
#[path = "../../crates/cigar-windows-ipc/src/pointer.rs"]
mod windows_pointer;
#[allow(
    dead_code,
    reason = "the isolated Miri slice executes the memory-sensitive transition subset"
)]
#[path = "../../crates/cigar-daemon/src/workflow_context_session.rs"]
mod workflow_context_session;

#[derive(Clone)]
struct PlanRecord {
    valid: bool,
    plan_id: RecordId,
    bundle_id: VersionId,
    contract_digest: ContentDigest,
}

impl WorkflowPlanRecord for PlanRecord {
    fn is_valid(&self) -> bool {
        self.valid
    }

    fn plan_id(&self) -> &RecordId {
        &self.plan_id
    }

    fn bundle_id(&self) -> &VersionId {
        &self.bundle_id
    }

    fn contract_digest(&self) -> &ContentDigest {
        &self.contract_digest
    }
}

#[derive(Clone)]
struct DeltaRecord {
    valid: bool,
    base_bundle_id: VersionId,
    target_bundle_id: VersionId,
    delta_digest: ContentDigest,
}

impl WorkflowDeltaRecord for DeltaRecord {
    fn is_valid(&self) -> bool {
        self.valid
    }

    fn base_bundle_id(&self) -> &VersionId {
        &self.base_bundle_id
    }

    fn target_bundle_id(&self) -> &VersionId {
        &self.target_bundle_id
    }

    fn delta_digest(&self) -> &ContentDigest {
        &self.delta_digest
    }
}

impl WorkflowAppliedDeltaRecord for DeltaRecord {
    fn base_bundle_id(&self) -> &VersionId {
        &self.base_bundle_id
    }

    fn target_bundle_id(&self) -> &VersionId {
        &self.target_bundle_id
    }

    fn delta_digest(&self) -> &ContentDigest {
        &self.delta_digest
    }
}

struct MaterializationRecord {
    valid: bool,
    bundle_id: VersionId,
    tokenizer_fingerprint: ContentDigest,
    materializer_fingerprint: ContentDigest,
    physical_input_tokens: u32,
}

impl WorkflowMaterializationRecord for MaterializationRecord {
    fn is_valid(&self) -> bool {
        self.valid
    }

    fn bundle_id(&self) -> &VersionId {
        &self.bundle_id
    }

    fn tokenizer_fingerprint(&self) -> &ContentDigest {
        &self.tokenizer_fingerprint
    }

    fn materializer_fingerprint(&self) -> &ContentDigest {
        &self.materializer_fingerprint
    }

    fn physical_input_tokens(&self) -> u32 {
        self.physical_input_tokens
    }
}

struct EffectRecord {
    valid: bool,
    effect_id: RecordId,
    intent_digest: ContentDigest,
    effect_version: u64,
    state: EffectState,
    attempt_count: u32,
    reconciliation_count: u32,
}

impl WorkflowEffectStatusRecord for EffectRecord {
    fn is_valid(&self) -> bool {
        self.valid
    }

    fn effect_id(&self) -> &RecordId {
        &self.effect_id
    }

    fn intent_digest(&self) -> &ContentDigest {
        &self.intent_digest
    }

    fn effect_version(&self) -> u64 {
        self.effect_version
    }

    fn state(&self) -> EffectState {
        self.state
    }

    fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    fn reconciliation_count(&self) -> u32 {
        self.reconciliation_count
    }
}

struct RevalidationRecord {
    valid_record: bool,
    bundle_id: VersionId,
    valid: bool,
}

impl WorkflowRevalidationRecord for RevalidationRecord {
    fn is_valid(&self) -> bool {
        self.valid_record
    }

    fn bundle_id(&self) -> &VersionId {
        &self.bundle_id
    }

    fn valid(&self) -> bool {
        self.valid
    }
}

fn digest(character: char) -> ContentDigest {
    ContentDigest::new(format!("1220{}", character.to_string().repeat(64)))
        .expect("test digest must be valid")
}

fn version(character: char) -> VersionId {
    VersionId::new(digest(character).as_str()).expect("test version must be valid")
}

fn record(suffix: u8) -> RecordId {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f78{suffix:02x}"))
        .expect("test record must be valid")
}

fn bundle(
    bundle_character: char,
    block_character: char,
    contract_character: char,
) -> ContextBundle {
    let block_id = version(block_character);
    let bundle = ContextBundle {
        schema_version: SchemaVersion::new("cigar.context-bundle", 1)
            .expect("test schema must be valid"),
        bundle_id: version(bundle_character),
        contract_digest: digest(contract_character),
        manifest_digest: digest('d'),
        blocks: vec![ContextBlock {
            block_id: block_id.clone(),
            lane: LaneKind::Evidence,
            representation: RepresentationKind::Exact,
            content_digest: digest(block_character),
            token_count: 1,
            provenance: vec![block_id],
            transform_receipt: None,
        }],
        total_tokens: 1,
        extensions: ExtensionMap::default(),
    };
    bundle.validate().expect("test bundle must be valid");
    bundle
}

fn plan(plan_suffix: u8, bundle: &ContextBundle) -> PlanRecord {
    PlanRecord {
        valid: true,
        plan_id: record(plan_suffix),
        bundle_id: bundle.bundle_id.clone(),
        contract_digest: bundle.contract_digest.clone(),
    }
}

fn materialization(bundle: &ContextBundle) -> MaterializationRecord {
    MaterializationRecord {
        valid: true,
        bundle_id: bundle.bundle_id.clone(),
        tokenizer_fingerprint: digest('f'),
        materializer_fingerprint: digest('1'),
        physical_input_tokens: 1,
    }
}

fn delta(base: &ContextBundle, target: &ContextBundle) -> DeltaRecord {
    DeltaRecord {
        valid: true,
        base_bundle_id: base.bundle_id.clone(),
        target_bundle_id: target.bundle_id.clone(),
        delta_digest: digest('9'),
    }
}

fn effect(
    effect_id: &RecordId,
    intent_digest: &ContentDigest,
    effect_version: u64,
    state: EffectState,
) -> EffectRecord {
    EffectRecord {
        valid: true,
        effect_id: effect_id.clone(),
        intent_digest: intent_digest.clone(),
        effect_version,
        state,
        attempt_count: match state {
            EffectState::Prepared | EffectState::Authorized => 0,
            _ if effect_version >= 5 => 2,
            _ => 1,
        },
        reconciliation_count: u32::from(effect_version >= 4),
    }
}

fn advance_to_model_result(
    session: &mut WorkflowContextSession,
    bundle: &ContextBundle,
) -> RecordId {
    session
        .record_plan_created(&plan(1, bundle))
        .expect("plan transition must pass");
    session
        .record_bundle_compiled(bundle)
        .expect("bundle transition must pass");
    session
        .record_materialized(&materialization(bundle))
        .expect("materialization transition must pass");
    let invocation_id = record(2);
    session
        .begin_model_invocation(invocation_id.clone(), digest('2'), digest('8'))
        .expect("invocation transition must pass");
    session
        .record_model_result(&invocation_id, digest('3'))
        .expect("model-result transition must pass");
    invocation_id
}

fn advance_delta(
    session: &mut WorkflowContextSession,
    base: &ContextBundle,
    target: &ContextBundle,
) {
    session
        .record_plan_created(&plan(3, target))
        .expect("target plan transition must pass");
    session
        .record_bundle_compiled(target)
        .expect("target bundle transition must pass");
    let delta = delta(base, target);
    session
        .record_delta_compiled(&delta)
        .expect("delta compile transition must pass");
    session
        .record_delta_applied(&delta)
        .expect("delta application transition must pass");
}

#[test]
fn canonical_and_identity_memory_model_is_clean() {
    let node = CanonicalNode::Map(BTreeMap::from([
        ("a".to_owned(), CanonicalNode::Unsigned(1)),
        (
            "b".to_owned(),
            CanonicalNode::Array(vec![CanonicalNode::Text("é".to_owned())]),
        ),
    ]));
    let encoded = to_deterministic_cbor(&node).expect("canonical CBOR encoding");
    assert_eq!(
        from_deterministic_cbor(&encoded).expect("canonical CBOR decoding"),
        node
    );
    assert!(cigar_protocol::RelativePath::new(b"safe/path".to_vec()).is_ok());
    assert!(cigar_protocol::RelativePath::new(b"/absolute".to_vec()).is_err());
    assert!(cigar_protocol::SourceUri::new("file:///bounded/path").is_ok());
}

#[test]
fn windows_pointer_helper_memory_model_is_clean() {
    let valid = [b'S' as u16, b'-' as u16, b'1' as u16, 0];
    // SAFETY: `valid` contains four initialized units and an in-bounds NUL terminator.
    let decoded = unsafe { windows_pointer::bounded_utf16_to_string(valid.as_ptr(), valid.len()) }
        .expect("valid bounded UTF-16 must decode");
    assert_eq!(decoded, "S-1");

    let invalid = [0xd800, 0];
    // SAFETY: `invalid` is initialized and terminated; the helper must reject its unpaired
    // surrogate without reading outside the allocation.
    assert!(
        unsafe { windows_pointer::bounded_utf16_to_string(invalid.as_ptr(), invalid.len()) }
            .is_err()
    );

    let unterminated = [b'S' as u16, b'X' as u16];
    // SAFETY: the exact allocation length is supplied as the scan bound.
    assert!(
        unsafe {
            windows_pointer::bounded_utf16_to_string(unterminated.as_ptr(), unterminated.len())
        }
        .is_err()
    );

    // SAFETY: null is explicitly accepted as a reject-only input and is never dereferenced.
    assert!(unsafe { windows_pointer::bounded_utf16_to_string(std::ptr::null(), 1) }.is_err());
}

#[test]
fn production_workflow_session_memory_model_is_clean() {
    let initial = bundle('a', '1', '2');
    let target = bundle('b', '2', '3');
    let mut session = WorkflowContextSession::new();
    advance_to_model_result(&mut session, &initial);
    session
        .record_observation(digest('4'), 1)
        .expect("observation transition must pass");
    advance_delta(&mut session, &initial, &target);
    assert_eq!(session.resume_action(), WorkflowResumeAction::Checkpoint);
    session
        .checkpoint_cycle()
        .expect("checkpoint transition must pass");
    session.finish().expect("finish transition must pass");
    let baseline = session
        .replay_identity()
        .expect("replay identity must exist");
    let comparison = session
        .compare_replay(&baseline)
        .expect("replay comparison must pass");
    assert!(comparison.exact_match);
    assert_eq!(comparison.bundle_delta_selection, DiffStatus::Equal);
    session
        .record_replay_verified(version('9'), record(9), &baseline)
        .expect("exact replay must verify");
    assert_eq!(session.phase(), WorkflowContextPhase::ReplayVerified);
    let encoded = serde_json::to_vec(&session).expect("session must serialize");
    let restored: WorkflowContextSession =
        serde_json::from_slice(&encoded).expect("session must deserialize");
    assert_eq!(session, restored);
    restored
        .validate_restored()
        .expect("restored session must validate");

    let mut cancelled = WorkflowContextSession::new();
    cancelled
        .record_plan_created(&plan(7, &initial))
        .expect("cancelled-session plan must pass");
    cancelled
        .record_bundle_compiled(&initial)
        .expect("cancelled-session bundle must pass");
    cancelled
        .record_materialized(&materialization(&initial))
        .expect("cancelled-session materialization must pass");
    let invocation_id = record(8);
    cancelled
        .begin_model_invocation(invocation_id.clone(), digest('5'), digest('6'))
        .expect("cancelled-session invocation must pass");
    cancelled
        .quarantine_context(&initial.bundle_id, WorkflowQuarantineReason::Cancelled)
        .expect("cancellation must quarantine the session");
    assert!(
        cancelled
            .record_model_result(&invocation_id, digest('7'))
            .is_err()
    );
    cancelled
        .validate_restored()
        .expect("quarantined session must validate");
}

#[test]
fn production_workflow_effect_fence_memory_model_is_clean() {
    let initial = bundle('a', '1', '2');
    let target = bundle('b', '2', '3');
    let effect_id = record(7);
    let intent_digest = digest('7');
    let mut session = WorkflowContextSession::new();
    advance_to_model_result(&mut session, &initial);
    session
        .record_effect_prepared(&effect(
            &effect_id,
            &intent_digest,
            1,
            EffectState::Prepared,
        ))
        .expect("prepare transition must pass");
    session
        .record_observation(digest('4'), 1)
        .expect("observation transition must pass");
    advance_delta(&mut session, &initial, &target);
    let valid = RevalidationRecord {
        valid_record: true,
        bundle_id: target.bundle_id.clone(),
        valid: true,
    };
    session
        .record_effect_revalidated(&valid)
        .expect("authorization revalidation must pass");
    session
        .record_effect_authorized(&effect(
            &effect_id,
            &intent_digest,
            2,
            EffectState::Authorized,
        ))
        .expect("authorization transition must pass");
    session
        .record_effect_revalidated(&valid)
        .expect("dispatch revalidation must pass");
    session
        .record_effect_dispatched(&effect(&effect_id, &intent_digest, 3, EffectState::Unknown))
        .expect("ambiguous dispatch transition must pass");
    session
        .record_effect_observed(&effect(
            &effect_id,
            &intent_digest,
            4,
            EffectState::AuthorizedForRetry,
        ))
        .expect("reconciliation transition must pass");
    assert_eq!(session.phase(), WorkflowContextPhase::EffectAuthorized);
    assert!(
        session
            .record_effect_dispatched(&effect(
                &effect_id,
                &intent_digest,
                5,
                EffectState::Succeeded,
            ))
            .is_err()
    );
    session
        .record_effect_revalidated(&valid)
        .expect("retry revalidation must pass");
    session
        .record_effect_dispatched(&effect(
            &effect_id,
            &intent_digest,
            5,
            EffectState::Succeeded,
        ))
        .expect("retried dispatch transition must pass");
    session
        .checkpoint_cycle()
        .expect("effect checkpoint must pass");
    session
        .validate_restored()
        .expect("effect session must validate");
}
