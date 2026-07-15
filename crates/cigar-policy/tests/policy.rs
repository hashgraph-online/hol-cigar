//! WP07 policy, capability, redaction, and non-interference acceptance matrix.

use cigar_canon::CanonicalNode;
use cigar_crypto::{CreateKeyRequest, KeyAlgorithm, KeyProvider, KeyPurpose, MemoryKeyProvider};
use cigar_policy::{
    CallerDisposition, CapabilityAuthority, CapabilityContext, CompiledPolicyEngine,
    DisclosureClass, PolicyEngine, PolicyErrorCode, PolicyOutcome, PolicyProfile, PolicyReason,
    PolicyRequest, PolicyResource, PolicyRule, RetrievalResourceAuthorizationRequest,
    StructuralRedactor, TimingClass,
};
use cigar_protocol::{
    Capability, CapabilityGrant, Classification, ContentDigest, ExtensionMap, InstructionAuthority,
    Lifecycle, RecordId, RiskLevel, UtcTimestamp,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

fn record(value: u16) -> Result<RecordId, Box<dyn Error>> {
    Ok(RecordId::new(format!(
        "01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"
    ))?)
}

fn digest(value: char) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        value.to_string().repeat(64)
    ))?)
}

fn unique_digest(value: usize) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!("1220{value:064x}"))?)
}

fn time(value: &str) -> Result<UtcTimestamp, Box<dyn Error>> {
    Ok(UtcTimestamp::parse_rfc3339(value)?)
}

fn empty_profile(revision: u64) -> PolicyProfile {
    PolicyProfile {
        schema_version: "cigar.policy-profile.v1".to_owned(),
        revision,
        protected: true,
        rules: Vec::new(),
    }
}

fn rule(id: &str, priority: i32, action: PolicyOutcome) -> PolicyRule {
    PolicyRule {
        id: id.to_owned(),
        priority,
        depends_on: BTreeSet::new(),
        resources: BTreeSet::new(),
        principal_ids: BTreeSet::new(),
        tenant_ids: BTreeSet::new(),
        project_ids: BTreeSet::new(),
        purposes: BTreeSet::new(),
        processors: BTreeSet::new(),
        classification_at_least: None,
        action,
        redaction_paths: BTreeSet::new(),
        conditions: BTreeSet::new(),
    }
}

fn request(
    resource: PolicyResource,
    input: ContentDigest,
) -> Result<PolicyRequest, Box<dyn Error>> {
    let principal = record(1)?;
    let tenant = record(2)?;
    let project = record(3)?;
    Ok(PolicyRequest {
        resource,
        input_digest: input,
        principal_id: principal.clone(),
        principal_active: true,
        tenant_id: tenant.clone(),
        authenticated_tenant_id: tenant,
        project_id: Some(project.clone()),
        allowed_project_ids: [project.clone()].into_iter().collect(),
        purpose: "coding".to_owned(),
        allowed_purposes: ["coding".to_owned()].into_iter().collect(),
        processor: Some("local".to_owned()),
        allowed_processors: ["local".to_owned()].into_iter().collect(),
        classification: Classification::Internal,
        maximum_classification: Classification::Internal,
        residency_allowed: true,
        egress_allowed: true,
        lifecycle: Lifecycle::Active,
        integrity_verified: true,
        valid_at: time("2026-07-10T00:00:02Z")?,
        valid_from: time("2026-07-10T00:00:00Z")?,
        valid_until: Some(time("2026-07-12T00:00:00Z")?),
        observed_at: time("2026-07-10T00:00:01Z")?,
        observed_as_of: time("2026-07-10T00:00:02Z")?,
        freshness_expires_at: Some(time("2026-07-11T00:00:00Z")?),
        instruction_authority: InstructionAuthority::Data,
        maximum_instruction_authority: InstructionAuthority::Project,
        excluded: false,
        modality_supported: true,
        capability: Some(CapabilityContext {
            subject_id: principal,
            grant_id: Some(record(4)?),
            capabilities: [Capability::ReadContext].into_iter().collect(),
            project_ids: [project].into_iter().collect(),
            processors: ["local".to_owned()].into_iter().collect(),
            expires_at: time("2026-07-11T12:00:00Z")?,
        }),
        required_capability: None,
        bound_policy_digest: None,
        effect_risk: None,
        effect_approved: false,
        effect_constraints_satisfied: true,
        fencing_required: false,
        fencing_verified: false,
        decision_expires_at: time("2026-07-11T18:00:00Z")?,
    })
}

fn installed() -> Result<(CompiledPolicyEngine, cigar_policy::PolicySnapshot), Box<dyn Error>> {
    let engine = CompiledPolicyEngine::default();
    let snapshot = engine.install(empty_profile(1), time("2026-07-10T00:00:00Z")?)?;
    Ok((engine, snapshot))
}

fn installed_arc()
-> Result<(Arc<CompiledPolicyEngine>, cigar_policy::PolicySnapshot), Box<dyn Error>> {
    let engine = Arc::new(CompiledPolicyEngine::default());
    let snapshot = engine.install(empty_profile(1), time("2026-07-10T00:00:00Z")?)?;
    Ok((engine, snapshot))
}

#[test]
fn generated_authorization_lattice_is_monotonic_and_fail_closed() -> Result<(), Box<dyn Error>> {
    let (engine, _) = installed()?;
    let baseline = request(PolicyResource::Content, digest('a')?)?;
    assert_eq!(
        engine.authorize_content(&baseline)?.outcome,
        PolicyOutcome::Allow
    );

    type Mutation = fn(&mut PolicyRequest) -> Result<(), Box<dyn Error>>;
    let mutations: Vec<(PolicyReason, Mutation)> = vec![
        (PolicyReason::TenantMismatch, |value| {
            value.authenticated_tenant_id = record(90)?;
            Ok(())
        }),
        (PolicyReason::ScopeDenied, |value| {
            value.allowed_project_ids.clear();
            Ok(())
        }),
        (PolicyReason::PrincipalDenied, |value| {
            value.principal_active = false;
            Ok(())
        }),
        (PolicyReason::CapabilityDenied, |value| {
            value.required_capability = Some(Capability::CompileContext);
            Ok(())
        }),
        (PolicyReason::PurposeDenied, |value| {
            value.allowed_purposes.clear();
            Ok(())
        }),
        (PolicyReason::ProcessorDenied, |value| {
            value.allowed_processors.clear();
            Ok(())
        }),
        (PolicyReason::ClassificationDenied, |value| {
            value.classification = Classification::Restricted;
            Ok(())
        }),
        (PolicyReason::ClassificationDenied, |value| {
            value.egress_allowed = false;
            Ok(())
        }),
        (PolicyReason::IntegrityDenied, |value| {
            value.integrity_verified = false;
            Ok(())
        }),
        (PolicyReason::IntegrityDenied, |value| {
            value.lifecycle = Lifecycle::Tombstoned;
            Ok(())
        }),
        (PolicyReason::TemporalDenied, |value| {
            value.valid_at = time("2026-07-09T00:00:00Z")?;
            Ok(())
        }),
        (PolicyReason::InstructionAuthorityDenied, |value| {
            value.instruction_authority = InstructionAuthority::System;
            Ok(())
        }),
        (PolicyReason::ContractDenied, |value| {
            value.excluded = true;
            Ok(())
        }),
        (PolicyReason::ContractDenied, |value| {
            value.modality_supported = false;
            Ok(())
        }),
    ];
    for (reason, mutate) in mutations {
        let mut narrowed = baseline.clone();
        mutate(&mut narrowed)?;
        let decision = engine.authorize_content(&narrowed)?;
        assert_ne!(decision.outcome, PolicyOutcome::Allow);
        assert_eq!(decision.reason, reason);
        assert_eq!(decision.disclosure, DisclosureClass::DeniedExistence);
        assert_eq!(
            decision.caller_view().disposition,
            CallerDisposition::Absent
        );
    }
    Ok(())
}

#[test]
fn deny_precedence_and_rule_dag_are_deterministic() -> Result<(), Box<dyn Error>> {
    let mut profile = empty_profile(1);
    let mut allow = rule("allow-first", -100, PolicyOutcome::Allow);
    allow.conditions.insert("allowed-condition".to_owned());
    let mut redact = rule("redact-middle", 0, PolicyOutcome::Redact);
    redact.depends_on.insert(allow.id.clone());
    redact.redaction_paths.insert("/secret".to_owned());
    let mut deny = rule("deny-last", 100, PolicyOutcome::Deny);
    deny.depends_on.insert(redact.id.clone());
    profile.rules = vec![deny, redact, allow];
    let engine = CompiledPolicyEngine::default();
    engine.install(profile, time("2026-07-10T00:00:00Z")?)?;
    let decision = engine.authorize_content(&request(PolicyResource::Content, digest('b')?)?)?;
    assert_eq!(decision.outcome, PolicyOutcome::Deny);
    assert_eq!(decision.reason, PolicyReason::DeclarativeRule);
    assert!(decision.redaction_paths.contains("/secret"));

    let mut cycle = empty_profile(2);
    let mut first = rule("first", 0, PolicyOutcome::Allow);
    let mut second = rule("second", 0, PolicyOutcome::Allow);
    first.depends_on.insert(second.id.clone());
    second.depends_on.insert(first.id.clone());
    cycle.rules = vec![first, second];
    assert_eq!(
        engine
            .install(cycle, time("2026-07-10T00:00:01Z")?)
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::InvalidRuleGraph)
    );
    Ok(())
}

#[test]
fn denied_existence_noninterference_processor_confinement_and_timing_classes()
-> Result<(), Box<dyn Error>> {
    let (engine, _) = installed()?;
    let mut project_denied = request(PolicyResource::Processor, digest('c')?)?;
    project_denied.allowed_project_ids.clear();
    let mut processor_denied = request(PolicyResource::Processor, digest('d')?)?;
    processor_denied.allowed_processors.clear();
    let first = engine.authorize_processor(&project_denied)?;
    let second = engine.authorize_processor(&processor_denied)?;
    assert_eq!(first.caller_view(), second.caller_view());
    assert_eq!(first.timing_class, TimingClass::Denied);
    assert_eq!(second.timing_class, TimingClass::Denied);
    let diagnostics = format!("{project_denied:?} {processor_denied:?} {first:?} {second:?}");
    assert!(!diagnostics.contains(digest('c')?.as_str()));
    assert!(!diagnostics.contains(digest('d')?.as_str()));
    assert!(!diagnostics.contains("local"));
    Ok(())
}

#[test]
fn payload_text_cannot_self_promote_instruction_authority() -> Result<(), Box<dyn Error>> {
    let (engine, _) = installed()?;
    let first = request(PolicyResource::Content, digest('e')?)?;
    let second = request(PolicyResource::Content, digest('f')?)?;
    assert_eq!(
        engine.authorize_content(&first)?.caller_view(),
        engine.authorize_content(&second)?.caller_view()
    );
    let mut promoted = second;
    promoted.instruction_authority = InstructionAuthority::System;
    assert_eq!(
        engine.authorize_content(&promoted)?.reason,
        PolicyReason::InstructionAuthorityDenied
    );
    Ok(())
}

#[test]
fn revocation_and_policy_change_block_old_artifacts_immediately() -> Result<(), Box<dyn Error>> {
    let (engine, first_snapshot) = installed()?;
    let mut bundle = request(PolicyResource::Bundle, digest('1')?)?;
    bundle.bound_policy_digest = Some(first_snapshot.policy_digest.clone());
    assert_eq!(
        engine.authorize_bundle(&bundle)?.outcome,
        PolicyOutcome::Allow
    );
    let second = engine.install(empty_profile(2), time("2026-07-10T00:01:00Z")?)?;
    let stale = engine.authorize_bundle(&bundle)?;
    assert_eq!(stale.outcome, PolicyOutcome::RequireRefresh);
    assert_eq!(stale.reason, PolicyReason::PolicyChanged);
    assert_ne!(first_snapshot.policy_digest, second.policy_digest);
    assert_eq!(engine.invalidations()?.len(), 2);

    let mut content = request(PolicyResource::Content, digest('2')?)?;
    let grant = content
        .capability
        .as_ref()
        .and_then(|capability| capability.grant_id.clone())
        .ok_or("missing grant")?;
    engine.revoke_grant(grant, time("2026-07-10T00:02:00Z")?)?;
    content.required_capability = Some(Capability::ReadContext);
    assert_eq!(
        engine.authorize_content(&content)?.reason,
        PolicyReason::Revoked
    );
    Ok(())
}

#[test]
fn retrieval_authorization_is_opaque_scope_bound_and_live_revalidated() -> Result<(), Box<dyn Error>>
{
    let (engine, first_snapshot) = installed_arc()?;
    let first_project = record(3)?;
    let second_project = record(5)?;
    let projects = BTreeSet::from([first_project.clone(), second_project.clone()]);
    let mut first = request(PolicyResource::Partition, digest('6')?)?;
    first.allowed_project_ids.clone_from(&projects);
    first
        .capability
        .as_mut()
        .ok_or("missing capability")?
        .project_ids
        .clone_from(&projects);
    first.required_capability = Some(Capability::CompileContext);
    first
        .capability
        .as_mut()
        .ok_or("missing capability")?
        .capabilities
        .insert(Capability::CompileContext);
    let mut second = first.clone();
    second.project_id = Some(second_project);

    let authorization = engine.authorize_retrieval_partition(&[first.clone(), second])?;
    let claims = authorization.revalidate()?;
    assert_eq!(claims.principal_id(), &first.principal_id);
    assert_eq!(claims.tenant_id(), &first.tenant_id);
    assert_eq!(claims.project_ids(), &projects);
    assert_eq!(claims.purpose(), "coding");
    assert_eq!(claims.processor(), "local");
    assert_eq!(claims.maximum_classification(), Classification::Internal);
    assert_eq!(
        claims.maximum_instruction_authority(),
        InstructionAuthority::Project
    );
    assert!(claims.vector_allowed());
    assert_eq!(claims.policy_digest(), &first_snapshot.policy_digest);
    assert_eq!(claims.policy_revision(), 1);
    let rendered = format!("{authorization:?} {claims:?}");
    assert!(!rendered.contains(first.principal_id.as_str()));
    assert!(!rendered.contains(first.tenant_id.as_str()));
    assert!(!rendered.contains("coding"));
    assert!(!rendered.contains("local"));
    assert!(!rendered.contains(first_snapshot.policy_digest.as_str()));

    engine.install(empty_profile(2), time("2026-07-10T00:01:00Z")?)?;
    assert_eq!(
        authorization.revalidate().map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );
    Ok(())
}

#[test]
fn retrieval_partition_digest_is_semantic_while_live_proof_time_remains_enforced()
-> Result<(), Box<dyn Error>> {
    let (engine, _) = installed_arc()?;
    let base = request(PolicyResource::Partition, digest('d')?)?;
    let first = engine.authorize_retrieval_partition(std::slice::from_ref(&base))?;
    let first_digest = first.revalidate()?.partition_digest().clone();

    let mut later = base.clone();
    later.valid_at = time("2026-07-10T03:00:00Z")?;
    later.observed_at = time("2026-07-10T02:59:59Z")?;
    later.observed_as_of = time("2026-07-10T03:00:00Z")?;
    later.decision_expires_at = time("2026-07-10T19:00:00Z")?;
    let later_digest = engine
        .authorize_retrieval_partition(std::slice::from_ref(&later))?
        .revalidate()?
        .partition_digest()
        .clone();
    assert_eq!(first_digest, later_digest);

    let mut different_grant = base.clone();
    different_grant
        .capability
        .as_mut()
        .ok_or("missing capability")?
        .grant_id = Some(record(40)?);
    let grant_digest = engine
        .authorize_retrieval_partition(std::slice::from_ref(&different_grant))?
        .revalidate()?
        .partition_digest()
        .clone();
    assert_ne!(first_digest, grant_digest);

    let mut different_scope = base.clone();
    let other_project = record(41)?;
    different_scope.project_id = Some(other_project.clone());
    different_scope.allowed_project_ids = BTreeSet::from([other_project.clone()]);
    different_scope
        .capability
        .as_mut()
        .ok_or("missing capability")?
        .project_ids = BTreeSet::from([other_project]);
    let scope_digest = engine
        .authorize_retrieval_partition(std::slice::from_ref(&different_scope))?
        .revalidate()?
        .partition_digest()
        .clone();
    assert_ne!(first_digest, scope_digest);

    engine.revoke_resource(digest('e')?, time("2026-07-10T00:05:00Z")?)?;
    let revoked_epoch_digest = engine
        .authorize_retrieval_partition(std::slice::from_ref(&base))?
        .revalidate()?
        .partition_digest()
        .clone();
    assert_ne!(first_digest, revoked_epoch_digest);

    let policy_engine = Arc::new(CompiledPolicyEngine::default());
    policy_engine.install(empty_profile(2), time("2026-07-10T00:00:00Z")?)?;
    let policy_digest = policy_engine
        .authorize_retrieval_partition(std::slice::from_ref(&base))?
        .revalidate()?
        .partition_digest()
        .clone();
    assert_ne!(first_digest, policy_digest);

    let mut expiring = base;
    expiring.decision_expires_at = UtcTimestamp::from_unix_nanos(
        expiring
            .observed_as_of
            .unix_nanos()
            .checked_add(1)
            .ok_or("timestamp overflow")?,
    )?;
    let expiring = engine.authorize_retrieval_partition(&[expiring])?;
    std::thread::sleep(Duration::from_millis(1));
    assert_eq!(
        expiring.revalidate().map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );
    Ok(())
}

#[test]
fn retrieval_authorization_rejects_processor_denial_scope_mix_and_revocation()
-> Result<(), Box<dyn Error>> {
    let mut profile = empty_profile(1);
    let mut processor_deny = rule("deny-processor", 0, PolicyOutcome::Deny);
    processor_deny.resources.insert(PolicyResource::Processor);
    profile.rules.push(processor_deny);
    let denied_engine = Arc::new(CompiledPolicyEngine::default());
    denied_engine.install(profile, time("2026-07-10T00:00:00Z")?)?;
    let partition = request(PolicyResource::Partition, digest('7')?)?;
    assert_eq!(
        denied_engine
            .authorize_retrieval_partition(std::slice::from_ref(&partition))
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );

    let (engine, _) = installed_arc()?;
    let mut mixed = partition.clone();
    mixed.purpose = "review".to_owned();
    assert_eq!(
        engine
            .authorize_retrieval_partition(&[partition.clone(), mixed])
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::InvalidInput)
    );
    let authorization = engine.authorize_retrieval_partition(std::slice::from_ref(&partition))?;
    engine.revoke_principal(partition.principal_id, time("2026-07-10T00:02:00Z")?)?;
    assert_eq!(
        authorization.revalidate().map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );
    Ok(())
}

fn retrieval_resource(
    request: &PolicyRequest,
    input_digest: ContentDigest,
) -> Result<RetrievalResourceAuthorizationRequest, Box<dyn Error>> {
    Ok(RetrievalResourceAuthorizationRequest {
        input_digest,
        tenant_id: request.tenant_id.clone(),
        project_ids: request.allowed_project_ids.clone(),
        allowed_purposes: request.allowed_purposes.clone(),
        allowed_processors: request.allowed_processors.clone(),
        classification: Classification::Internal,
        lifecycle: Lifecycle::Active,
        integrity_verified: true,
        valid_from: time("2026-07-10T00:00:00Z")?,
        valid_until: Some(time("2026-07-12T00:00:00Z")?),
        observed_at: time("2026-07-10T00:00:01Z")?,
        instruction_authority: InstructionAuthority::Data,
    })
}

#[test]
fn retrieval_authorization_fails_when_issuer_is_dropped() -> Result<(), Box<dyn Error>> {
    let authorization = {
        let (engine, _) = installed_arc()?;
        let partition = request(PolicyResource::Partition, digest('8')?)?;
        engine.authorize_retrieval_partition(&[partition])?
    };
    assert_eq!(
        authorization.revalidate().map_err(|error| error.code()),
        Err(PolicyErrorCode::Unavailable)
    );
    Ok(())
}

#[test]
fn retrieval_resource_rechecks_revocation_and_content_policy_before_scoring()
-> Result<(), Box<dyn Error>> {
    let (engine, _) = installed_arc()?;
    let partition = request(PolicyResource::Partition, digest('9')?)?;
    let authorization = engine.authorize_retrieval_partition(std::slice::from_ref(&partition))?;
    let resource_digest = digest('a')?;
    let resource = retrieval_resource(&partition, resource_digest.clone())?;
    assert!(authorization.authorize_resource(&resource, false)?);
    engine.revoke_resource(resource_digest, time("2026-07-10T00:00:03Z")?)?;
    assert_eq!(
        authorization
            .authorize_resource(&resource, false)
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );

    let (revoked_engine, _) = installed_arc()?;
    revoked_engine.revoke_resource(resource.input_digest.clone(), time("2026-07-10T00:00:03Z")?)?;
    let revoked_authorization =
        revoked_engine.authorize_retrieval_partition(std::slice::from_ref(&partition))?;
    assert!(!revoked_authorization.authorize_resource(&resource, false)?);

    let mut profile = empty_profile(1);
    let mut deny_content = rule("deny-content-only", 0, PolicyOutcome::Deny);
    deny_content.resources.insert(PolicyResource::Content);
    profile.rules.push(deny_content);
    let content_engine = Arc::new(CompiledPolicyEngine::default());
    content_engine.install(profile, time("2026-07-10T00:00:00Z")?)?;
    let content_authorization =
        content_engine.authorize_retrieval_partition(std::slice::from_ref(&partition))?;
    assert!(!content_authorization.authorize_resource(&resource, false)?);
    Ok(())
}

#[test]
fn protected_policy_outage_fails_closed() -> Result<(), Box<dyn Error>> {
    let (engine, _) = installed()?;
    engine.set_available(false)?;
    let request = request(PolicyResource::Content, digest('3')?)?;
    assert_eq!(
        engine
            .authorize_content(&request)
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::Unavailable)
    );
    assert_eq!(
        engine.snapshot().map_err(|error| error.code()),
        Err(PolicyErrorCode::Unavailable)
    );
    Ok(())
}

#[test]
fn structural_redaction_is_exact_and_preserves_lineage() -> Result<(), Box<dyn Error>> {
    let value = CanonicalNode::Map(BTreeMap::from([
        (
            "public".to_owned(),
            CanonicalNode::Text("visible".to_owned()),
        ),
        (
            "secret".to_owned(),
            CanonicalNode::Map(BTreeMap::from([
                (
                    "token".to_owned(),
                    CanonicalNode::Text("canary-token".to_owned()),
                ),
                ("keep".to_owned(), CanonicalNode::Unsigned(7)),
            ])),
        ),
    ]));
    let paths = ["/secret/token".to_owned()].into_iter().collect();
    let result =
        StructuralRedactor.redact(&value, &paths, &BTreeSet::new(), digest('4')?, digest('5')?)?;
    assert_ne!(result.value, value);
    assert!(!format!("{result:?}").contains("canary-token"));
    let CanonicalNode::Map(fields) = &result.value else {
        return Err("redacted root changed type".into());
    };
    assert_eq!(
        fields.get("public"),
        Some(&CanonicalNode::Text("visible".to_owned()))
    );
    let CanonicalNode::Map(secret) = fields.get("secret").ok_or("missing secret object")? else {
        return Err("secret changed type".into());
    };
    assert_eq!(
        secret.get("token"),
        Some(&CanonicalNode::Text("[REDACTED]".to_owned()))
    );
    assert_eq!(secret.get("keep"), Some(&CanonicalNode::Unsigned(7)));
    assert_eq!(result.source_digest, digest('4')?);
    assert_eq!(result.policy_digest, digest('5')?);
    assert_eq!(
        StructuralRedactor
            .redact(
                &value,
                &paths,
                &["/secret".to_owned()].into_iter().collect(),
                digest('4')?,
                digest('5')?,
            )
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::RequiredField)
    );
    Ok(())
}

fn grant(id: u16, issuer: RecordId, subject: RecordId) -> Result<CapabilityGrant, Box<dyn Error>> {
    Ok(CapabilityGrant {
        schema_version: "cigar.capability-grant.v1".parse()?,
        grant_id: record(id)?,
        issuer_id: issuer,
        subject_id: subject,
        parent_grant_id: None,
        capabilities: vec![Capability::ReadContext, Capability::WriteOverlay],
        project_ids: vec![record(50)?],
        processors: vec!["local".to_owned()],
        not_before: time("2026-07-10T00:00:00Z")?,
        expires_at: time("2026-07-11T00:00:00Z")?,
        delegation_depth: 2,
        extensions: ExtensionMap::default(),
    })
}

#[test]
fn capability_signature_attenuation_tamper_time_and_revocation_fail_closed()
-> Result<(), Box<dyn Error>> {
    let provider = Arc::new(MemoryKeyProvider::default());
    let signed_at = time("2026-07-10T00:00:01Z")?;
    let key = provider.create(CreateKeyRequest {
        tenant: "tenant-a".to_owned(),
        purpose: KeyPurpose::Signing,
        algorithm: KeyAlgorithm::Ed25519,
        created_at: signed_at.unix_nanos(),
        activated_at: signed_at.unix_nanos(),
    })?;
    let authority = CapabilityAuthority::new(provider);
    let root_issuer = record(40)?;
    let delegate = record(41)?;
    let recipient = record(42)?;
    let parent = grant(43, root_issuer, delegate.clone())?;
    let signed_parent = authority.sign(parent.clone(), &key.key_ref, "tenant-a", signed_at)?;
    let mut child = grant(44, delegate, recipient.clone())?;
    child.parent_grant_id = Some(parent.grant_id.clone());
    child.capabilities = vec![Capability::ReadContext];
    child.expires_at = time("2026-07-10T12:00:00Z")?;
    child.delegation_depth = 1;
    authority.validate_attenuation(&child, &parent)?;
    let signed_child = authority.sign(child.clone(), &key.key_ref, "tenant-a", signed_at)?;
    let effective = authority.verify(
        &signed_child,
        "tenant-a",
        &recipient,
        time("2026-07-10T01:00:00Z")?,
        &BTreeSet::new(),
        Some(&signed_parent),
    )?;
    assert_eq!(
        effective.capabilities,
        [Capability::ReadContext].into_iter().collect()
    );

    let mut broadened = child.clone();
    broadened.capabilities.push(Capability::ApproveEffect);
    broadened.capabilities.sort();
    assert_eq!(
        authority
            .validate_attenuation(&broadened, &parent)
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::InvalidCapability)
    );
    let mut tampered = signed_child.clone();
    tampered.grant.processors.push("remote".to_owned());
    assert_eq!(
        authority
            .verify(
                &tampered,
                "tenant-a",
                &recipient,
                time("2026-07-10T01:00:00Z")?,
                &BTreeSet::new(),
                Some(&signed_parent),
            )
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::InvalidCapability)
    );
    assert_eq!(
        authority
            .verify(
                &signed_child,
                "tenant-a",
                &recipient,
                time("2026-07-10T12:00:00Z")?,
                &BTreeSet::new(),
                Some(&signed_parent),
            )
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::InvalidCapability)
    );
    assert_eq!(
        authority
            .verify(
                &signed_child,
                "tenant-a",
                &recipient,
                time("2026-07-10T01:00:00Z")?,
                &[child.grant_id].into_iter().collect(),
                Some(&signed_parent),
            )
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );
    assert_eq!(
        authority
            .verify(
                &signed_child,
                "tenant-a",
                &recipient,
                time("2026-07-10T01:00:00Z")?,
                &[parent.grant_id].into_iter().collect(),
                Some(&signed_parent),
            )
            .map_err(|error| error.code()),
        Err(PolicyErrorCode::Revoked)
    );
    Ok(())
}

#[test]
fn json_and_toml_profiles_compile_to_the_same_snapshot_digest() -> Result<(), Box<dyn Error>> {
    let mut profile = empty_profile(7);
    let mut redact = rule("redact", 10, PolicyOutcome::Redact);
    redact.resources.insert(PolicyResource::Content);
    redact.redaction_paths.insert("/credential".to_owned());
    profile.rules.push(redact);
    let json = serde_json::to_vec(&profile)?;
    let toml = toml::to_string(&profile)?;
    let json_engine = CompiledPolicyEngine::default();
    let toml_engine = CompiledPolicyEngine::default();
    let json_snapshot = json_engine.install_json(&json, time("2026-07-10T00:00:00Z")?)?;
    let toml_snapshot = toml_engine.install_toml(&toml, time("2026-07-10T00:00:00Z")?)?;
    assert_eq!(json_snapshot.policy_digest, toml_snapshot.policy_digest);
    Ok(())
}

#[test]
fn effect_decision_requires_constraints_approval_and_fencing() -> Result<(), Box<dyn Error>> {
    let (engine, snapshot) = installed()?;
    let mut effect = request(PolicyResource::Effect, digest('6')?)?;
    effect.bound_policy_digest = Some(snapshot.policy_digest);
    effect.required_capability = Some(Capability::ReadContext);
    effect.effect_risk = Some(RiskLevel::High);
    effect.fencing_required = true;
    assert_eq!(
        engine.authorize_effect(&effect)?.outcome,
        PolicyOutcome::RequireApproval
    );
    effect.effect_approved = true;
    assert_eq!(
        engine.authorize_effect(&effect)?.outcome,
        PolicyOutcome::Deny
    );
    effect.fencing_verified = true;
    assert_eq!(
        engine.authorize_effect(&effect)?.outcome,
        PolicyOutcome::Allow
    );
    effect.effect_constraints_satisfied = false;
    assert_eq!(
        engine.authorize_effect(&effect)?.outcome,
        PolicyOutcome::Deny
    );
    Ok(())
}

#[test]
fn all_policy_entry_points_share_the_same_hard_gate() -> Result<(), Box<dyn Error>> {
    let (engine, snapshot) = installed()?;
    for resource in [
        PolicyResource::Partition,
        PolicyResource::Metadata,
        PolicyResource::Content,
        PolicyResource::Processor,
        PolicyResource::Bundle,
        PolicyResource::Handoff,
    ] {
        let mut value = request(resource, digest('7')?)?;
        if matches!(resource, PolicyResource::Bundle | PolicyResource::Handoff) {
            value.bound_policy_digest = Some(snapshot.policy_digest.clone());
        }
        value.authenticated_tenant_id = record(99)?;
        let decision = match resource {
            PolicyResource::Partition => engine.authorize_partition(&value)?,
            PolicyResource::Metadata => engine.authorize_metadata(&value)?,
            PolicyResource::Content => engine.authorize_content(&value)?,
            PolicyResource::Processor => engine.authorize_processor(&value)?,
            PolicyResource::Bundle => engine.authorize_bundle(&value)?,
            PolicyResource::Handoff => engine.authorize_handoff(&value)?,
            PolicyResource::Effect => return Err("effect handled separately".into()),
        };
        assert_eq!(decision.reason, PolicyReason::TenantMismatch);
    }
    Ok(())
}

#[test]
fn decision_cache_is_expiry_aware_globally_bounded_and_tenant_fair() -> Result<(), Box<dyn Error>> {
    let (engine, _) = installed()?;

    for value in 0..=cigar_policy::MAX_POLICY_CACHE_ENTRIES {
        let mut candidate = request(PolicyResource::Content, unique_digest(value)?)?;
        let tenant =
            record(100 + (value / cigar_policy::MAX_POLICY_CACHE_ENTRIES_PER_TENANT) as u16)?;
        candidate.tenant_id = tenant.clone();
        candidate.authenticated_tenant_id = tenant;
        assert_eq!(
            engine.authorize_content(&candidate)?.outcome,
            PolicyOutcome::Allow
        );
    }

    let statistics = engine.cache_statistics()?;
    assert_eq!(statistics.entries, cigar_policy::MAX_POLICY_CACHE_ENTRIES);
    assert!(statistics.maximum_tenant_entries <= cigar_policy::MAX_POLICY_CACHE_ENTRIES_PER_TENANT);
    assert!(statistics.capacity_evictions >= 1);

    let repeated = request(PolicyResource::Content, unique_digest(20_000)?)?;
    engine.authorize_content(&repeated)?;
    engine.authorize_content(&repeated)?;
    assert!(engine.cache_statistics()?.hits >= 1);

    let (expiring_engine, _) = installed()?;
    let mut expiring = request(PolicyResource::Content, unique_digest(30_000)?)?;
    expiring.decision_expires_at = time("2026-07-10T00:00:03Z")?;
    expiring_engine.authorize_content(&expiring)?;
    assert_eq!(expiring_engine.cache_statistics()?.entries, 1);

    let mut later = request(PolicyResource::Content, unique_digest(30_001)?)?;
    later.valid_at = time("2026-07-10T00:00:04Z")?;
    later.observed_at = time("2026-07-10T00:00:04Z")?;
    later.observed_as_of = time("2026-07-10T00:00:04Z")?;
    expiring_engine.authorize_content(&later)?;
    let statistics = expiring_engine.cache_statistics()?;
    assert_eq!(statistics.entries, 1);
    assert_eq!(statistics.expired_evictions, 1);
    Ok(())
}
