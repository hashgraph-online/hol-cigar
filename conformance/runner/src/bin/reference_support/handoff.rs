use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_conformance::CaseOutcome;
use cigar_crypto::{
    CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, KeyRef, MemoryKeyProvider,
};
use cigar_policy::EffectiveCapabilities;
use cigar_protocol::{
    Budget, Capability, ContentDigest, CoordinationTopic, ExpectedRevision, HandoffReferences,
    LaneKind, RecipientSelector, RecordId, UtcTimestamp, VersionId,
};
use cigar_space::{AcceptHandoffRequest, CreateHandoffRequest, HandoffError, HandoffService};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "handoff_signed_attenuation" => signed_attenuation(input),
        "handoff_expiry_rejection" => expiry_rejection(input),
        _ => Err("unsupported handoff conformance operation".into()),
    }
}

fn signed_attenuation(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "handoff-signed-attenuation-v1")?;
    let fixture = signed_fixture()?;
    let request = acceptance_request(&fixture, 20)?;
    let denied = version(2)?;
    let inspection = fixture
        .service
        .inspect_acceptance(&request, |source| source != &denied)?;
    if fixture.capsule.signature.len() != 64
        || inspection.context.capabilities != vec![Capability::ReadContext]
        || inspection.context.references.sources != vec![version(1)?]
        || inspection.unavailable_references != vec![denied]
        || inspection.context.project_ids != vec![fixture.project.clone()]
    {
        return Err("production handoff attenuation or reference authorization diverged".into());
    }
    let accepted_source = inspection
        .context
        .references
        .sources
        .first()
        .ok_or("production handoff omitted the accepted source")?;
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.handoff.v1",
            &[
                fixture.capsule.handoff_id.as_str(),
                fixture.capsule.issuer_id.as_str(),
                fixture.recipient.as_str(),
                fixture.project.as_str(),
                accepted_source.as_str(),
                "read_context",
                "unavailable=1",
                "signature=ed25519-64",
            ],
        ),
    ))
}

fn expiry_rejection(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "handoff-expired-v1")?;
    let fixture = signed_fixture()?;
    let request = acceptance_request(&fixture, 40)?;
    let error = fixture
        .service
        .inspect_acceptance(&request, |_source| true)
        .err()
        .ok_or("production handoff accepted an expired signed capsule")?;
    if error != HandoffError::Expired {
        return Err("production handoff returned the wrong expiry category".into());
    }
    Ok((CaseOutcome::Rejected, rejected_digest("handoff_expired")))
}

struct SignedFixture {
    service: HandoffService,
    capsule: cigar_protocol::HandoffCapsule,
    recipient: RecordId,
    project: RecordId,
}

fn signed_fixture() -> Result<SignedFixture, Box<dyn std::error::Error>> {
    let provider = Arc::new(MemoryKeyProvider::default());
    let metadata = provider.create(CreateKeyRequest {
        tenant: "tenant-a".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: time(0)?.unix_nanos(),
        activated_at: time(0)?.unix_nanos(),
    })?;
    let service = HandoffService::new(provider);
    let issuer = record(1)?;
    let recipient = record(2)?;
    let project = record(3)?;
    let (capsule, preview) = service.create(creation_request(
        metadata.key_ref,
        issuer,
        recipient.clone(),
        project.clone(),
    )?)?;
    if preview.delegated_capabilities != vec![Capability::ReadContext]
        || preview.rejected_capabilities != vec![Capability::InvokeTool]
        || preview.reference_count != 2
    {
        return Err("production handoff creation preview diverged".into());
    }
    Ok(SignedFixture {
        service,
        capsule,
        recipient,
        project,
    })
}

fn creation_request(
    key_ref: KeyRef,
    issuer: RecordId,
    recipient: RecordId,
    project: RecordId,
) -> Result<CreateHandoffRequest, Box<dyn std::error::Error>> {
    let mut sources = vec![version(1)?, version(2)?];
    sources.sort();
    Ok(CreateHandoffRequest {
        handoff_id: record(100)?,
        issuer_effective: effective(
            issuer,
            record(101)?,
            [
                Capability::CreateHandoff,
                Capability::ReadContext,
                Capability::InvokeTool,
            ]
            .into_iter()
            .collect(),
            [project.clone()].into_iter().collect(),
        )?,
        recipient: RecipientSelector::Principal(recipient),
        task: "Verify the typed change".to_owned(),
        acceptance_criteria: vec!["Evidence is attached".to_owned()],
        requested_projects: [project.clone()].into_iter().collect(),
        requested_capabilities: [Capability::ReadContext, Capability::InvokeTool]
            .into_iter()
            .collect(),
        policy_allowed_projects: [project].into_iter().collect(),
        policy_allowed_capabilities: [Capability::ReadContext].into_iter().collect(),
        budget: Budget {
            total_input_tokens: 100,
            output_reserve_tokens: 20,
            lane_input_tokens: BTreeMap::from([(LaneKind::Evidence, 100)]),
        },
        topics: [CoordinationTopic::AtomInvalidation].into_iter().collect(),
        references: HandoffReferences {
            sources,
            states: Vec::new(),
            decisions: Vec::new(),
            artifacts: Vec::new(),
            uncertainties: Vec::new(),
            effects: Vec::new(),
        },
        bundle_id: version(9)?,
        audience: "claude-code".to_owned(),
        created_at: time(10)?,
        expires_at: time(40)?,
        nonce: b"conformance-one-time-nonce".to_vec(),
        reusable: false,
        issuer_key_ref: key_ref,
    })
}

fn acceptance_request(
    fixture: &SignedFixture,
    now: u8,
) -> Result<AcceptHandoffRequest, Box<dyn std::error::Error>> {
    Ok(AcceptHandoffRequest {
        capsule: fixture.capsule.clone(),
        expected_revision: ExpectedRevision(1),
        acceptance_id: record(200 + u64::from(now))?,
        recipient_id: fixture.recipient.clone(),
        recipient_roles: BTreeSet::new(),
        expected_audience: "claude-code".to_owned(),
        tenant: "tenant-a".to_owned(),
        now: time(now)?,
        recipient_effective: effective(
            fixture.recipient.clone(),
            record(103)?,
            [Capability::ReadContext].into_iter().collect(),
            [fixture.project.clone()].into_iter().collect(),
        )?,
        policy_allowed_capabilities: [Capability::ReadContext].into_iter().collect(),
        policy_digest: content(88)?,
        revoked_principals: BTreeSet::new(),
        revoked_key_ids: BTreeSet::new(),
        target_allowed: true,
        accepted_at: time(now)?,
    })
}

fn effective(
    subject_id: RecordId,
    grant_id: RecordId,
    capabilities: BTreeSet<Capability>,
    project_ids: BTreeSet<RecordId>,
) -> Result<EffectiveCapabilities, Box<dyn std::error::Error>> {
    Ok(EffectiveCapabilities {
        tenant: "tenant-a".to_owned(),
        subject_id,
        grant_id,
        capabilities,
        project_ids,
        processors: ["local".to_owned()].into_iter().collect(),
        expires_at: time(50)?,
    })
}

fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-{value:012x}"
    ))?)
}

fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
    let hash = Sha256::digest(value.to_be_bytes());
    let mut encoded = String::from("1220");
    use std::fmt::Write as _;
    for byte in hash {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(VersionId::new(encoded)?)
}

fn content(value: u64) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(ContentDigest::new(version(value)?.as_str())?)
}

fn time(second: u8) -> Result<UtcTimestamp, Box<dyn std::error::Error>> {
    Ok(UtcTimestamp::parse_rfc3339(&format!(
        "2026-07-11T12:00:{second:02}Z"
    ))?)
}
