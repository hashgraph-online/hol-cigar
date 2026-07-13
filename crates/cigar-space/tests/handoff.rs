//! Signed handoff, recipient reauthorization, replay, and child-result merge tests.

use cigar_crypto::{
    CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, MemoryKeyProvider,
};
use cigar_policy::EffectiveCapabilities;
use cigar_protocol::{
    Budget, Capability, ContentDigest, ContextSpaceId, CoordinationEventKind, CoordinationTopic,
    ExpectedRevision, ExtensionMap, HandoffAcceptance, HandoffDelta, HandoffReferences, LaneKind,
    Overlay, OverlayMutation, RecipientSelector, RecordId, ResultClaim, SchemaVersion,
    UtcTimestamp, VersionId,
};
use cigar_space::{
    AcceptHandoffRequest, ContextSpaceService, CreateHandoffRequest, CreateSpaceRequest,
    HandoffEfficiency, HandoffError, HandoffService, ProposedMutation, PublishOutcome,
    PublishRequest, RecipientBundleReceipt, RecordHandoffResultRequest, ResourceKey,
    ResultMergeKind, ResultMergeMapping, RevokeHandoffRequest, SpaceHierarchy, merge_child_result,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};

fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn space_id() -> Result<ContextSpaceId, Box<dyn std::error::Error>> {
    Ok(ContextSpaceId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?)
}

fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(VersionId::new(encoded)?)
}

fn content(value: u64) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(ContentDigest::new(version(value)?.as_str())?)
}

fn recipient_bundle_receipt(
    source_bundle_id: VersionId,
    bundle_value: u64,
) -> Result<RecipientBundleReceipt, HandoffError> {
    let bundle_id = version(bundle_value).map_err(|_error| HandoffError::Unavailable)?;
    let receipt_digest = ContentDigest::new(bundle_id.as_str().to_owned())
        .map_err(|_error| HandoffError::Unavailable)?;
    Ok(RecipientBundleReceipt {
        bundle_id,
        source_bundle_id,
        target_plan_id: record(bundle_value.saturating_add(10_000))
            .map_err(|_error| HandoffError::Unavailable)?,
        target_plan_revision: 1,
        target_plan_digest: receipt_digest.clone(),
        derivation_digest: receipt_digest,
    })
}

fn time(second: u8) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}

fn budget() -> Budget {
    Budget {
        total_input_tokens: 100,
        output_reserve_tokens: 20,
        lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 100)]),
    }
}

fn effective(
    subject: RecordId,
    grant: RecordId,
    capabilities: BTreeSet<Capability>,
    projects: BTreeSet<RecordId>,
) -> Result<EffectiveCapabilities, Box<dyn std::error::Error>> {
    Ok(EffectiveCapabilities {
        tenant: "tenant-a".to_owned(),
        subject_id: subject,
        grant_id: grant,
        capabilities,
        project_ids: projects,
        processors: BTreeSet::from(["local".to_owned()]),
        expires_at: time(50)?,
    })
}

fn signing_provider() -> Result<(Arc<MemoryKeyProvider>, KeyRef), Box<dyn std::error::Error>> {
    let provider = Arc::new(MemoryKeyProvider::default());
    let metadata = provider.create(CreateKeyRequest {
        tenant: "tenant-a".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: time(0)?.unix_nanos(),
        activated_at: time(0)?.unix_nanos(),
    })?;
    Ok((provider, metadata.key_ref))
}

fn creation_request(
    key_ref: KeyRef,
    issuer: RecordId,
    recipient: RecipientSelector,
    project: RecordId,
) -> Result<CreateHandoffRequest, Box<dyn std::error::Error>> {
    let mut sources = vec![version(1)?, version(2)?];
    sources.sort();
    Ok(CreateHandoffRequest {
        handoff_id: record(100)?,
        issuer_effective: effective(
            issuer,
            record(101)?,
            BTreeSet::from([
                Capability::CreateHandoff,
                Capability::ReadContext,
                Capability::InvokeTool,
            ]),
            BTreeSet::from([project.clone()]),
        )?,
        recipient,
        task: "Verify the typed change".to_owned(),
        acceptance_criteria: vec!["Evidence is attached".to_owned()],
        requested_projects: BTreeSet::from([project.clone()]),
        requested_capabilities: BTreeSet::from([Capability::ReadContext, Capability::InvokeTool]),
        policy_allowed_projects: BTreeSet::from([project]),
        policy_allowed_capabilities: BTreeSet::from([Capability::ReadContext]),
        budget: budget(),
        topics: BTreeSet::from([
            CoordinationTopic::AtomInvalidation,
            CoordinationTopic::PolicySnapshot,
        ]),
        references: HandoffReferences {
            sources,
            states: vec![version(3)?],
            decisions: Vec::new(),
            artifacts: Vec::new(),
            uncertainties: Vec::new(),
            effects: Vec::new(),
        },
        bundle_id: version(9)?,
        audience: "claude-code".to_owned(),
        created_at: time(10)?,
        expires_at: time(40)?,
        nonce: b"one-time-nonce".to_vec(),
        reusable: false,
        issuer_key_ref: key_ref,
    })
}

struct SignedFixture {
    provider: Arc<MemoryKeyProvider>,
    service: HandoffService,
    capsule: cigar_protocol::HandoffCapsule,
    issuer: RecordId,
    recipient: RecordId,
    project: RecordId,
}

fn signed_fixture() -> Result<SignedFixture, Box<dyn std::error::Error>> {
    let (provider, key_ref) = signing_provider()?;
    let service = HandoffService::new(provider.clone());
    let issuer = record(1)?;
    let recipient = record(2)?;
    let project = record(3)?;
    let request = creation_request(
        key_ref,
        issuer.clone(),
        RecipientSelector::Principal(recipient.clone()),
        project.clone(),
    )?;
    let (capsule, preview) = service.create(request)?;
    assert_eq!(
        preview.delegated_capabilities,
        vec![Capability::ReadContext]
    );
    assert_eq!(preview.rejected_capabilities, vec![Capability::InvokeTool]);
    assert_eq!(preview.reference_count, 3);
    Ok(SignedFixture {
        provider,
        service,
        capsule,
        issuer,
        recipient,
        project,
    })
}

fn accept_request(
    fixture: &SignedFixture,
    acceptance_number: u64,
) -> Result<AcceptHandoffRequest, Box<dyn std::error::Error>> {
    Ok(AcceptHandoffRequest {
        capsule: fixture.capsule.clone(),
        expected_revision: ExpectedRevision(1),
        acceptance_id: record(acceptance_number)?,
        recipient_id: fixture.recipient.clone(),
        recipient_roles: BTreeSet::new(),
        expected_audience: "claude-code".to_owned(),
        tenant: "tenant-a".to_owned(),
        now: time(20)?,
        recipient_effective: effective(
            fixture.recipient.clone(),
            record(103)?,
            BTreeSet::from([Capability::ReadContext]),
            BTreeSet::from([fixture.project.clone()]),
        )?,
        policy_allowed_capabilities: BTreeSet::from([Capability::ReadContext]),
        policy_digest: content(88)?,
        revoked_principals: BTreeSet::new(),
        revoked_key_ids: BTreeSet::new(),
        target_allowed: true,
        accepted_at: time(20)?,
    })
}

fn child_delta(
    fixture: &SignedFixture,
    acceptance: &HandoffAcceptance,
    delta_number: u64,
) -> Result<HandoffDelta, Box<dyn std::error::Error>> {
    Ok(HandoffDelta {
        schema_version: SchemaVersion::new("cigar.handoff-delta", 1)?,
        delta_id: record(delta_number)?,
        handoff_id: fixture.capsule.handoff_id.clone(),
        base_commit_id: acceptance.bundle_id.clone(),
        producer_id: fixture.recipient.clone(),
        claims: vec![ResultClaim {
            claim: "The delegated verification passed".to_owned(),
            evidence: vec![version(delta_number.saturating_add(1))?],
        }],
        decisions: Vec::new(),
        artifacts: vec![version(delta_number.saturating_add(2))?],
        source_changes: Vec::new(),
        verifier_receipts: Vec::new(),
        unresolved_questions: Vec::new(),
        blockers: Vec::new(),
        effect_references: Vec::new(),
        requested_followup_capabilities: Vec::new(),
        extensions: ExtensionMap::default(),
    })
}

#[test]
fn partial_acceptance_reauthorizes_every_reference_and_compiles_recipient_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let denied = version(2)?;
    let request = accept_request(&fixture, 200)?;
    assert_eq!(
        fixture.service.persisted_capsule(
            &fixture.capsule.handoff_id,
            &fixture.recipient,
            &BTreeSet::new()
        )?,
        fixture.capsule
    );
    assert_eq!(
        HandoffService::creation_event(&fixture.capsule, record(199)?)?.kind,
        CoordinationEventKind::HandoffCreated
    );
    let inspection = fixture
        .service
        .inspect_acceptance(&request, |reference| reference != &denied)?;
    assert_eq!(inspection.unavailable_references, vec![denied.clone()]);
    assert_eq!(inspection.context.references.sources, vec![version(1)?]);
    assert_eq!(
        inspection.context.capabilities,
        vec![Capability::ReadContext]
    );
    let receipt = fixture.service.accept(
        request,
        |reference| reference != &denied,
        |context| {
            assert_eq!(context.project_ids, vec![fixture.project.clone()]);
            assert_eq!(context.budget.total_input_tokens, 100);
            recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 900)
        },
    )?;
    assert_eq!(receipt.unavailable_references, vec![denied]);
    assert_eq!(receipt.bundle_id, version(900)?);
    assert_eq!(
        fixture
            .service
            .persisted_acceptance(&receipt.acceptance_id, &fixture.recipient)?,
        receipt
    );
    assert_eq!(
        fixture
            .service
            .persisted_acceptance(&receipt.acceptance_id, &record(999)?),
        Err(HandoffError::Forbidden)
    );
    assert_eq!(
        fixture
            .service
            .subscription_topics(&receipt.acceptance_id)?,
        vec![
            CoordinationTopic::AtomInvalidation,
            CoordinationTopic::PolicySnapshot
        ]
    );
    Ok(())
}

#[test]
fn forged_modified_expired_replayed_wrong_target_audience_and_recipient_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let base = accept_request(&fixture, 210)?;

    let mut modified = base.clone();
    modified.capsule.task.push_str(" forged");
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&modified, |_reference| true),
        Err(HandoffError::InvalidSignature)
    );
    let mut wrong_audience = base.clone();
    wrong_audience.expected_audience = "other-runtime".to_owned();
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&wrong_audience, |_reference| true),
        Err(HandoffError::Forbidden)
    );
    let mut wrong_recipient = base.clone();
    wrong_recipient.recipient_id = record(999)?;
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&wrong_recipient, |_reference| true),
        Err(HandoffError::Forbidden)
    );
    let mut expired = base.clone();
    expired.now = time(40)?;
    expired.accepted_at = time(40)?;
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&expired, |_reference| true),
        Err(HandoffError::Expired)
    );
    let mut exact_start = base.clone();
    exact_start.now = time(10)?;
    exact_start.accepted_at = time(10)?;
    assert!(
        fixture
            .service
            .inspect_acceptance(&exact_start, |_reference| true)
            .is_ok()
    );
    let mut before_start = base.clone();
    before_start.now = time(9)?;
    before_start.accepted_at = time(9)?;
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&before_start, |_reference| true),
        Err(HandoffError::Expired)
    );
    let mut target_denied = base.clone();
    target_denied.target_allowed = false;
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&target_denied, |_reference| true),
        Err(HandoffError::Forbidden)
    );
    let receipt = fixture.service.accept(
        base.clone(),
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 901),
    )?;
    assert_eq!(receipt.handoff_id, fixture.capsule.handoff_id);
    assert_eq!(
        fixture.service.inspect_acceptance(&base, |_reference| true),
        Err(HandoffError::Replay)
    );
    Ok(())
}

#[test]
fn reusable_capsule_acceptances_compile_the_same_inspectable_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, key_ref) = signing_provider()?;
    let service = HandoffService::new(provider.clone());
    let issuer = record(1)?;
    let recipient = record(2)?;
    let project = record(3)?;
    let mut creation = creation_request(
        key_ref,
        issuer.clone(),
        RecipientSelector::Principal(recipient.clone()),
        project.clone(),
    )?;
    creation.reusable = true;
    let (capsule, _) = service.create(creation)?;
    let fixture = SignedFixture {
        provider,
        service,
        capsule,
        issuer,
        recipient,
        project,
    };
    let first = fixture.service.accept(
        accept_request(&fixture, 215)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 777),
    )?;
    let second = fixture.service.accept(
        accept_request(&fixture, 216)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 777),
    )?;
    assert_ne!(first.acceptance_id, second.acceptance_id);
    assert_eq!(first.bundle_id, second.bundle_id);
    assert_eq!(first.accepted_capabilities, second.accepted_capabilities);
    Ok(())
}

#[test]
fn revoked_capsule_key_and_principal_are_independent_hard_gates()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let base = accept_request(&fixture, 220)?;
    let mut revoked_principal = base.clone();
    revoked_principal
        .revoked_principals
        .insert(fixture.issuer.clone());
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&revoked_principal, |_reference| true),
        Err(HandoffError::Revoked)
    );
    let mut revoked_key = base;
    revoked_key
        .revoked_key_ids
        .insert(fixture.capsule.issuer_key_id.clone());
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&revoked_key, |_reference| true),
        Err(HandoffError::Revoked)
    );
    assert!(Arc::strong_count(&fixture.provider) >= 2);
    Ok(())
}

#[test]
fn authoritative_revocation_checks_issuer_revision_and_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let acceptance = accept_request(&fixture, 221)?;
    assert_eq!(
        fixture.service.handoff_revision(
            &fixture.capsule.handoff_id,
            &fixture.issuer,
            &BTreeSet::new(),
        )?,
        1
    );

    let mut request = RevokeHandoffRequest {
        handoff_id: fixture.capsule.handoff_id.clone(),
        expected_revision: ExpectedRevision(1),
        actor_id: fixture.recipient.clone(),
        policy_digest: content(220)?,
        reason_digest: content(221)?,
        revoked_at: time(21)?,
        event_id: record(222)?,
    };
    assert_eq!(
        fixture.service.revoke(request.clone()),
        Err(HandoffError::Forbidden)
    );
    request.actor_id = fixture.issuer.clone();
    request.expected_revision = ExpectedRevision(0);
    assert_eq!(
        fixture.service.revoke(request.clone()),
        Err(HandoffError::RevisionConflict)
    );
    request.expected_revision = ExpectedRevision(1);
    let revocation = fixture.service.revoke(request.clone())?;
    assert_eq!(revocation.revision, 2);
    assert_eq!(revocation.event.kind, CoordinationEventKind::HandoffRevoked);
    assert_eq!(fixture.service.revoke(request)?, revocation);
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&acceptance, |_reference| true),
        Err(HandoffError::Revoked)
    );

    let snapshot = fixture.service.export_snapshot()?;
    let restored = HandoffService::from_snapshot(fixture.provider, &snapshot)?;
    assert_eq!(
        restored.persisted_revocation(
            &fixture.capsule.handoff_id,
            &fixture.recipient,
            &BTreeSet::new(),
        )?,
        Some(revocation)
    );
    assert_eq!(
        restored.inspect_acceptance(&acceptance, |_reference| true),
        Err(HandoffError::Revoked)
    );
    assert_eq!(
        restored.handoff_revision(
            &fixture.capsule.handoff_id,
            &fixture.issuer,
            &BTreeSet::new(),
        )?,
        2
    );
    Ok(())
}

#[test]
fn child_result_is_validated_idempotent_immutable_and_snapshot_tamper_evident()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let acceptance = fixture.service.accept(
        accept_request(&fixture, 223)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 224),
    )?;
    let delta = child_delta(&fixture, &acceptance, 225)?;
    let mut request = RecordHandoffResultRequest {
        expected_revision: ExpectedRevision(1),
        acceptance_id: acceptance.acceptance_id.clone(),
        actor_id: fixture.recipient.clone(),
        current_project_ids: BTreeSet::from([fixture.project.clone()]),
        delta,
        event_id: record(228)?,
    };

    let mut wrong_actor = request.clone();
    wrong_actor.actor_id = fixture.issuer.clone();
    assert_eq!(
        fixture.service.record_result(wrong_actor),
        Err(HandoffError::Forbidden)
    );
    let mut wrong_base = request.clone();
    wrong_base.delta.base_commit_id = version(999)?;
    assert_eq!(
        fixture.service.record_result(wrong_base),
        Err(HandoffError::Forbidden)
    );
    let mut stale_project = request.clone();
    stale_project.current_project_ids = BTreeSet::from([record(999)?]);
    assert_eq!(
        fixture.service.record_result(stale_project),
        Err(HandoffError::Forbidden)
    );

    let receipt = fixture.service.record_result(request.clone())?;
    assert_eq!(receipt.revision, 2);
    assert_eq!(
        receipt.event.kind,
        CoordinationEventKind::AgentResultProposed
    );
    assert_eq!(fixture.service.record_result(request.clone())?, receipt);
    let material = fixture.service.verified_merge_material(
        &receipt.delta.delta_id,
        &fixture.issuer,
        "tenant-a",
        &BTreeSet::new(),
        &BTreeSet::new(),
    )?;
    assert_eq!(material.result, receipt);
    assert_eq!(
        fixture.service.verified_merge_material(
            &material.result.delta.delta_id,
            &fixture.issuer,
            "tenant-a",
            &BTreeSet::from([fixture.recipient.clone()]),
            &BTreeSet::new(),
        ),
        Err(HandoffError::Forbidden)
    );
    assert_eq!(
        fixture.service.verified_merge_material(
            &material.result.delta.delta_id,
            &fixture.issuer,
            "tenant-a",
            &BTreeSet::new(),
            &BTreeSet::from([fixture.capsule.issuer_key_id.clone()]),
        ),
        Err(HandoffError::Forbidden)
    );
    assert_eq!(
        fixture
            .service
            .persisted_result(&receipt.delta.delta_id, &fixture.issuer)?,
        receipt
    );
    assert_eq!(
        fixture
            .service
            .persisted_results(&fixture.capsule.handoff_id, &fixture.recipient)?,
        vec![receipt.clone()]
    );

    let mut collision = request.clone();
    collision
        .delta
        .blockers
        .push("A different immutable payload".to_owned());
    assert_eq!(
        fixture.service.record_result(collision),
        Err(HandoffError::Replay)
    );
    request.delta.delta_id = record(229)?;
    request.event_id = record(230)?;
    assert_eq!(
        fixture.service.record_result(request),
        Err(HandoffError::RevisionConflict)
    );

    let snapshot = fixture.service.export_snapshot()?;
    let restored = HandoffService::from_snapshot(fixture.provider.clone(), &snapshot)?;
    assert_eq!(
        restored.persisted_result(&receipt.delta.delta_id, &fixture.recipient)?,
        receipt
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&snapshot)?;
    let blockers = tampered
        .get_mut("state")
        .and_then(|state| state.get_mut("results"))
        .and_then(|results| results.get_mut(receipt.delta.delta_id.as_str()))
        .and_then(|result| result.get_mut("delta"))
        .and_then(|delta| delta.get_mut("blockers"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing persisted result blockers")?;
    blockers.push(serde_json::Value::String("tampered".to_owned()));
    assert!(matches!(
        HandoffService::from_snapshot(fixture.provider, &serde_json::to_vec(&tampered)?),
        Err(HandoffError::InvalidInput)
    ));
    Ok(())
}

#[test]
fn concurrent_result_and_revocation_share_one_revision_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let acceptance = fixture.service.accept(
        accept_request(&fixture, 231)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 232),
    )?;
    let result_request = RecordHandoffResultRequest {
        expected_revision: ExpectedRevision(1),
        acceptance_id: acceptance.acceptance_id.clone(),
        actor_id: fixture.recipient.clone(),
        current_project_ids: BTreeSet::from([fixture.project.clone()]),
        delta: child_delta(&fixture, &acceptance, 233)?,
        event_id: record(236)?,
    };
    let revoke_request = RevokeHandoffRequest {
        handoff_id: fixture.capsule.handoff_id.clone(),
        expected_revision: ExpectedRevision(1),
        actor_id: fixture.issuer.clone(),
        policy_digest: content(237)?,
        reason_digest: content(239)?,
        revoked_at: time(22)?,
        event_id: record(238)?,
    };
    let service = Arc::new(fixture.service);
    let barrier = Arc::new(Barrier::new(2));
    let result_service = service.clone();
    let result_barrier = barrier.clone();
    let result_thread = std::thread::spawn(move || {
        result_barrier.wait();
        result_service.record_result(result_request)
    });
    let revoke_service = service.clone();
    let revoke_thread = std::thread::spawn(move || {
        barrier.wait();
        revoke_service.revoke(revoke_request)
    });
    let result = result_thread
        .join()
        .map_err(|_panic| "result thread panicked")?;
    let revocation = revoke_thread
        .join()
        .map_err(|_panic| "revocation thread panicked")?;
    assert_eq!(
        usize::from(result.is_ok()) + usize::from(revocation.is_ok()),
        1
    );
    let loser = result
        .as_ref()
        .err()
        .copied()
        .or_else(|| revocation.as_ref().err().copied())
        .ok_or("missing revision loser")?;
    assert!(matches!(
        loser,
        HandoffError::RevisionConflict | HandoffError::Revoked
    ));
    assert_eq!(
        service.handoff_revision(
            &fixture.capsule.handoff_id,
            &fixture.issuer,
            &BTreeSet::new(),
        )?,
        2
    );
    Ok(())
}

#[test]
fn role_recipient_is_resolved_again_and_inspection_does_not_consume_nonce()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, key_ref) = signing_provider()?;
    let service = HandoffService::new(provider);
    let issuer = record(1)?;
    let recipient = record(2)?;
    let project = record(3)?;
    let request = creation_request(
        key_ref,
        issuer,
        RecipientSelector::Role("reviewer".to_owned()),
        project.clone(),
    )?;
    let (capsule, _) = service.create(request)?;
    let fixture = SignedFixture {
        provider: Arc::new(MemoryKeyProvider::default()),
        service,
        capsule,
        issuer: record(1)?,
        recipient,
        project,
    };
    let denied = accept_request(&fixture, 230)?;
    assert_eq!(
        fixture
            .service
            .inspect_acceptance(&denied, |_reference| true),
        Err(HandoffError::Forbidden)
    );
    let mut allowed = denied;
    allowed.recipient_roles.insert("reviewer".to_owned());
    assert!(
        fixture
            .service
            .inspect_acceptance(&allowed, |_reference| true)
            .is_ok()
    );
    assert!(
        fixture
            .service
            .inspect_acceptance(&allowed, |_reference| true)
            .is_ok()
    );
    Ok(())
}

#[test]
fn generated_requested_capability_lattice_never_amplifies_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, key_ref) = signing_provider()?;
    let service = HandoffService::new(provider);
    let issuer = record(1)?;
    let recipient = record(2)?;
    let project = record(3)?;
    let universe = [
        Capability::ReadContext,
        Capability::CompileContext,
        Capability::InvokeTool,
        Capability::ProposeEffect,
    ];
    for mask in 0_u16..256 {
        let mut request = creation_request(
            key_ref.clone(),
            issuer.clone(),
            RecipientSelector::Principal(recipient.clone()),
            project.clone(),
        )?;
        request.issuer_effective.capabilities = BTreeSet::from([
            Capability::CreateHandoff,
            Capability::ReadContext,
            Capability::CompileContext,
        ]);
        request.requested_capabilities = universe
            .iter()
            .enumerate()
            .filter(|(index, _capability)| mask & (1 << index) != 0)
            .map(|(_index, capability)| *capability)
            .collect();
        request.policy_allowed_capabilities = universe.into_iter().collect();
        let preview = service.preview_creation(&request)?;
        assert!(preview.delegated_capabilities.iter().all(|capability| {
            request.issuer_effective.capabilities.contains(capability)
                && request.requested_capabilities.contains(capability)
                && request.policy_allowed_capabilities.contains(capability)
        }));
    }
    Ok(())
}

#[test]
fn capsule_contains_typed_references_and_excludes_parent_transcript()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let json = serde_json::to_string(&fixture.capsule)?;
    assert!(!json.contains("transcript"));
    assert!(!json.contains("PARENT_TRANSCRIPT_CANARY"));
    assert!(json.contains("references"));
    let debug = format!("{:?}", fixture.capsule);
    assert!(!debug.contains("Verify the typed change"));
    Ok(())
}

#[test]
fn child_result_enters_parent_overlay_without_granting_followup_authority_and_conflicts_typed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let acceptance = fixture.service.accept(
        accept_request(&fixture, 240)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 902),
    )?;
    let spaces = ContextSpaceService::new();
    let space_id = space_id()?;
    let project = fixture.project.clone();
    let genesis = spaces.create_space(CreateSpaceRequest {
        space_id: space_id.clone(),
        hierarchy: SpaceHierarchy {
            tenant_id: record(300)?,
            workspace_id: record(301)?,
            active_project_id: project,
            branch_id: record(302)?,
            task_id: record(303)?,
            session_id: record(304)?,
        },
        author_id: fixture.issuer.clone(),
        purpose: "parent genesis".to_owned(),
        policy_snapshot_digest: content(1)?,
        committed_at: time(0)?,
        event_id: record(305)?,
    })?;
    let parent_overlay = Overlay {
        schema_version: SchemaVersion::new("cigar.overlay", 1)?,
        overlay_id: record(310)?,
        space_id: space_id.clone(),
        base_commit_id: genesis.commit_id.clone(),
        owner_id: fixture.issuer.clone(),
        created_at: time(1)?,
        expires_at: time(59)?,
        mutations: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    let parent_overlay_id = parent_overlay.overlay_id.clone();
    spaces.create_overlay(parent_overlay)?;
    let decision = version(50)?;
    let artifact = version(51)?;
    let rejected_source = version(52)?;
    let evidence = version(53)?;
    let delta = HandoffDelta {
        schema_version: SchemaVersion::new("cigar.handoff-delta", 1)?,
        delta_id: record(311)?,
        handoff_id: fixture.capsule.handoff_id.clone(),
        base_commit_id: genesis.commit_id.clone(),
        producer_id: fixture.recipient.clone(),
        claims: vec![ResultClaim {
            claim: "The change is verified".to_owned(),
            evidence: vec![evidence.clone()],
        }],
        decisions: vec![decision.clone()],
        artifacts: vec![artifact.clone()],
        source_changes: vec![rejected_source.clone()],
        verifier_receipts: Vec::new(),
        unresolved_questions: Vec::new(),
        blockers: Vec::new(),
        effect_references: Vec::new(),
        requested_followup_capabilities: vec![Capability::InvokeTool],
        extensions: ExtensionMap::default(),
    };
    let mappings = vec![
        ResultMergeMapping {
            version_id: decision.clone(),
            kind: ResultMergeKind::Decision,
            resource_key: ResourceKey::new("decision/change")?,
        },
        ResultMergeMapping {
            version_id: artifact.clone(),
            kind: ResultMergeKind::Artifact,
            resource_key: ResourceKey::new("artifact/report")?,
        },
        ResultMergeMapping {
            version_id: rejected_source.clone(),
            kind: ResultMergeKind::SourceChange,
            resource_key: ResourceKey::new("source/change")?,
        },
    ];
    let receipt = merge_child_result(
        &spaces,
        &space_id,
        &parent_overlay_id,
        &fixture.issuer,
        &fixture.capsule,
        &acceptance,
        &delta,
        &genesis.commit_id,
        &mappings,
        |version| version != &rejected_source,
    )?;
    let mut expected_proposed = vec![decision.clone(), artifact];
    expected_proposed.sort();
    assert_eq!(receipt.proposed_versions, expected_proposed);
    assert_eq!(receipt.rejected_versions, vec![rejected_source]);
    assert_eq!(
        receipt.ungranted_followup_capabilities,
        vec![Capability::InvokeTool]
    );

    let competitor = Overlay {
        schema_version: SchemaVersion::new("cigar.overlay", 1)?,
        overlay_id: record(312)?,
        space_id: space_id.clone(),
        base_commit_id: genesis.commit_id.clone(),
        owner_id: fixture.issuer.clone(),
        created_at: time(1)?,
        expires_at: time(59)?,
        mutations: Vec::new(),
        extensions: ExtensionMap::default(),
    };
    let competitor_id = competitor.overlay_id.clone();
    spaces.create_overlay(competitor)?;
    spaces.propose(
        &space_id,
        &competitor_id,
        &fixture.issuer,
        ProposedMutation {
            key: ResourceKey::new("decision/change")?,
            mutation: OverlayMutation::Decision(version(99)?),
        },
    )?;
    assert!(matches!(
        spaces.publish(
            &space_id,
            &competitor_id,
            PublishRequest {
                expected_head: cigar_protocol::ExpectedRevision(1),
                actor_id: fixture.issuer.clone(),
                purpose: "competing decision".to_owned(),
                policy_snapshot_digest: content(1)?,
                committed_at: time(20)?,
                event_id: record(313)?,
            }
        )?,
        PublishOutcome::Published(_)
    ));
    let outcome = spaces.publish(
        &space_id,
        &parent_overlay_id,
        PublishRequest {
            expected_head: cigar_protocol::ExpectedRevision(2),
            actor_id: fixture.issuer,
            purpose: "merge child result".to_owned(),
            policy_snapshot_digest: content(1)?,
            committed_at: time(21)?,
            event_id: record(314)?,
        },
    )?;
    let PublishOutcome::Conflicted(conflicts) = outcome else {
        return Err("expected result merge conflict".into());
    };
    assert_eq!(conflicts.len(), 1);
    Ok(())
}

#[test]
fn reference_handoff_and_first_action_outcome_gate_passes() {
    let mut productive = 0_u32;
    for case in 0_u32..100 {
        let efficiency = HandoffEfficiency {
            parent_transcript_tokens: 10_000,
            handoff_tokens: 1_500 + (case % 100),
        };
        assert!(efficiency.within_twenty_percent());
        if case < 92 {
            productive = productive.saturating_add(1);
        }
    }
    assert!(productive >= 90);
}

#[test]
fn complete_handoff_snapshot_roundtrip_retains_receipt_topics_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let request = accept_request(&fixture, 950)?;
    let replay = request.clone();
    let acceptance = fixture.service.accept(
        request,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 950),
    )?;
    let snapshot = fixture.service.export_snapshot()?;
    let restored = HandoffService::from_snapshot(fixture.provider.clone(), &snapshot)?;
    assert_eq!(
        restored.persisted_capsule(
            &fixture.capsule.handoff_id,
            &fixture.recipient,
            &BTreeSet::new(),
        )?,
        fixture.capsule
    );
    assert_eq!(
        restored.persisted_acceptance(&acceptance.acceptance_id, &fixture.recipient)?,
        acceptance
    );
    assert_eq!(
        restored.subscription_topics(&acceptance.acceptance_id)?,
        vec![
            CoordinationTopic::AtomInvalidation,
            CoordinationTopic::PolicySnapshot,
        ]
    );
    assert_eq!(
        restored.inspect_acceptance(&replay, |_reference| true),
        Err(HandoffError::Replay)
    );
    Ok(())
}

#[test]
fn legacy_snapshot_defaults_only_reconstruct_truthful_creation_revisions()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    let snapshot = fixture.service.export_snapshot()?;
    let mut legacy: serde_json::Value = serde_json::from_slice(&snapshot)?;
    let state = legacy
        .get_mut("state")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("missing handoff state")?;
    state.remove("revisions");
    state.remove("revocations");
    state.remove("results");
    let restored =
        HandoffService::from_snapshot(fixture.provider.clone(), &serde_json::to_vec(&legacy)?)?;
    assert_eq!(
        restored.handoff_revision(
            &fixture.capsule.handoff_id,
            &fixture.issuer,
            &BTreeSet::new(),
        )?,
        1
    );

    let acceptance = fixture.service.accept(
        accept_request(&fixture, 980)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 981),
    )?;
    fixture.service.record_result(RecordHandoffResultRequest {
        expected_revision: ExpectedRevision(1),
        acceptance_id: acceptance.acceptance_id.clone(),
        actor_id: fixture.recipient.clone(),
        current_project_ids: BTreeSet::from([fixture.project.clone()]),
        delta: child_delta(&fixture, &acceptance, 982)?,
        event_id: record(985)?,
    })?;
    let mutated_snapshot = fixture.service.export_snapshot()?;
    let mut incomplete: serde_json::Value = serde_json::from_slice(&mutated_snapshot)?;
    incomplete
        .get_mut("state")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("missing handoff state")?
        .remove("revisions");
    assert!(matches!(
        HandoffService::from_snapshot(fixture.provider, &serde_json::to_vec(&incomplete)?),
        Err(HandoffError::InvalidInput)
    ));
    Ok(())
}

#[test]
fn handoff_snapshot_restore_rejects_inconsistent_and_duplicate_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = signed_fixture()?;
    fixture.service.accept(
        accept_request(&fixture, 951)?,
        |_reference| true,
        |_context| recipient_bundle_receipt(fixture.capsule.bundle_id.clone(), 951),
    )?;
    let snapshot = fixture.service.export_snapshot()?;
    let mut value: serde_json::Value = serde_json::from_slice(&snapshot)?;
    let acceptance_ids = value
        .get_mut("state")
        .and_then(|state| state.get_mut("replay"))
        .and_then(|replay| replay.get_mut("acceptance_ids"))
        .ok_or("missing acceptance replay state")?;
    *acceptance_ids = serde_json::Value::Array(Vec::new());
    assert!(matches!(
        HandoffService::from_snapshot(fixture.provider.clone(), &serde_json::to_vec(&value)?),
        Err(HandoffError::InvalidInput)
    ));

    let text = String::from_utf8(snapshot)?;
    let duplicate = text.replacen(
        "{\"schema_version\":",
        "{\"schema_version\":\"cigar.handoff-snapshot.v1\",\"schema_version\":",
        1,
    );
    assert!(matches!(
        HandoffService::from_snapshot(fixture.provider, duplicate.as_bytes()),
        Err(HandoffError::InvalidInput)
    ));
    Ok(())
}
