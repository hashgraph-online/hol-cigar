//! Semantic request key, exact reuse, and execution-correlation qualification.

use cigar_sdk::api::TraceId;
use cigar_sdk::protocol::{ContentDigest, RecordId};
use cigar_sdk::{
    AuthorityStatus, ExecutionArtifactOutcome, ExecutionCorrelation, ReusableSemanticArtifact,
    SemanticExtensionStatus, SemanticRequestKey, SemanticRequestKeyDecision, SemanticReusePins,
    SemanticReuseReason, SemanticReuseRequest, bind_semantic_execution_receipt,
    evaluate_semantic_reuse, semantic_request_key,
};
use std::error::Error;

fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        format!("{value:02x}").repeat(32)
    ))?)
}

fn request() -> Result<SemanticReuseRequest, Box<dyn Error>> {
    Ok(SemanticReuseRequest {
        pins: SemanticReusePins {
            normalized_need_digest: digest(1)?,
            catalog_watermark: digest(2)?,
            authorization_domain_digest: digest(3)?,
            disclosure_domain_digest: digest(4)?,
            policy_digest: digest(5)?,
            target_profile_digest: digest(6)?,
            tokenizer_fingerprint: digest(7)?,
            materializer_fingerprint: digest(8)?,
            compiler_fingerprint: digest(9)?,
        },
        semantic_extensions: SemanticExtensionStatus::Known,
        authority: AuthorityStatus::Certain,
    })
}

fn key(request: &SemanticReuseRequest) -> Result<SemanticRequestKey, Box<dyn Error>> {
    match semantic_request_key(request)? {
        SemanticRequestKeyDecision::Key(key) => Ok(key),
        SemanticRequestKeyDecision::Bypass(reason) => {
            Err(format!("unexpected bypass: {}", reason.as_str()).into())
        }
    }
}

fn candidate(request: &SemanticReuseRequest) -> Result<ReusableSemanticArtifact, Box<dyn Error>> {
    Ok(ReusableSemanticArtifact {
        semantic_request_key: key(request)?,
        artifact_digest: digest(10)?,
        pins: request.pins.clone(),
    })
}

fn correlation(value: u16) -> Result<ExecutionCorrelation, Box<dyn Error>> {
    Ok(ExecutionCorrelation {
        operation_id: RecordId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f{value:04x}"))?,
        trace_id: TraceId::new(format!("{value:032x}"))?,
        run_correlation_digest: Some(digest(11)?),
        job_correlation_digest: Some(digest(12)?),
    })
}

#[test]
fn exact_pins_are_required_before_reuse() -> Result<(), Box<dyn Error>> {
    let request = request()?;
    let candidate = candidate(&request)?;
    let result = evaluate_semantic_reuse(&request, Some(&candidate))?;
    assert!(result.is_hit());
    assert_eq!(result.reason(), SemanticReuseReason::Hit);
    assert_eq!(result.artifact_digest(), Some(&candidate.artifact_digest));

    let mut cases = Vec::new();
    let mut changed = candidate.clone();
    changed.pins.normalized_need_digest = digest(20)?;
    cases.push((changed, SemanticReuseReason::NormalizedNeedMismatch));
    let mut changed = candidate.clone();
    changed.pins.authorization_domain_digest = digest(21)?;
    cases.push((changed, SemanticReuseReason::AuthorizationMismatch));
    let mut changed = candidate.clone();
    changed.pins.disclosure_domain_digest = digest(22)?;
    cases.push((changed, SemanticReuseReason::DisclosureMismatch));
    let mut changed = candidate.clone();
    changed.pins.policy_digest = digest(23)?;
    cases.push((changed, SemanticReuseReason::PolicyMismatch));
    let mut changed = candidate.clone();
    changed.pins.catalog_watermark = digest(24)?;
    cases.push((changed, SemanticReuseReason::WatermarkMismatch));
    let mut changed = candidate.clone();
    changed.pins.target_profile_digest = digest(25)?;
    cases.push((changed, SemanticReuseReason::TargetMismatch));
    let mut changed = candidate.clone();
    changed.pins.tokenizer_fingerprint = digest(26)?;
    cases.push((changed, SemanticReuseReason::TokenizerMismatch));
    let mut changed = candidate.clone();
    changed.pins.materializer_fingerprint = digest(27)?;
    cases.push((changed, SemanticReuseReason::MaterializerMismatch));
    let mut changed = candidate.clone();
    changed.pins.compiler_fingerprint = digest(28)?;
    cases.push((changed, SemanticReuseReason::CompilerMismatch));

    let mut alternate = request.clone();
    alternate.pins.compiler_fingerprint = digest(29)?;
    let mut changed = candidate.clone();
    changed.semantic_request_key = key(&alternate)?;
    cases.push((changed, SemanticReuseReason::SemanticKeyMismatch));

    for (changed, reason) in cases {
        let result = evaluate_semantic_reuse(&request, Some(&changed))?;
        assert!(!result.is_hit());
        assert_eq!(result.reason(), reason);
        assert!(result.semantic_request_key().is_none());
        assert!(result.artifact_digest().is_none());
    }
    Ok(())
}

#[test]
fn absent_unknown_extensions_and_uncertain_authority_fail_closed() -> Result<(), Box<dyn Error>> {
    let request = request()?;
    assert_eq!(
        evaluate_semantic_reuse(&request, None)?.reason(),
        SemanticReuseReason::AbsentEntry
    );

    let mut unknown = request.clone();
    unknown.semantic_extensions = SemanticExtensionStatus::Unknown;
    assert_eq!(
        evaluate_semantic_reuse(&unknown, None)?.reason(),
        SemanticReuseReason::UnknownSemanticExtension
    );

    let mut uncertain = request;
    uncertain.authority = AuthorityStatus::Uncertain;
    assert_eq!(
        evaluate_semantic_reuse(&uncertain, None)?.reason(),
        SemanticReuseReason::UncertainAuthority
    );
    Ok(())
}

#[test]
fn every_semantic_pin_changes_the_stable_key() -> Result<(), Box<dyn Error>> {
    let request = request()?;
    let expected = key(&request)?;
    let mut changed_requests = Vec::new();
    let mut changed = request.clone();
    changed.pins.normalized_need_digest = digest(20)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.catalog_watermark = digest(21)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.authorization_domain_digest = digest(22)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.disclosure_domain_digest = digest(23)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.policy_digest = digest(24)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.target_profile_digest = digest(25)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.tokenizer_fingerprint = digest(26)?;
    changed_requests.push(changed);
    let mut changed = request.clone();
    changed.pins.materializer_fingerprint = digest(27)?;
    changed_requests.push(changed);
    let mut changed = request;
    changed.pins.compiler_fingerprint = digest(28)?;
    changed_requests.push(changed);

    for changed in changed_requests {
        assert_ne!(key(&changed)?, expected);
    }
    Ok(())
}

#[test]
fn correlation_changes_only_the_execution_receipt() -> Result<(), Box<dyn Error>> {
    let request = request()?;
    let semantic_key = key(&request)?;
    let artifact_digest = digest(10)?;
    let first = bind_semantic_execution_receipt(
        semantic_key.clone(),
        artifact_digest.clone(),
        correlation(1)?,
        ExecutionArtifactOutcome::Reused,
        SemanticReuseReason::Hit,
    )?;
    let second = bind_semantic_execution_receipt(
        semantic_key.clone(),
        artifact_digest.clone(),
        correlation(2)?,
        ExecutionArtifactOutcome::Reused,
        SemanticReuseReason::Hit,
    )?;
    assert_eq!(first.semantic_request_key(), &semantic_key);
    assert_eq!(second.semantic_request_key(), &semantic_key);
    assert_eq!(first.artifact_digest(), &artifact_digest);
    assert_eq!(second.artifact_digest(), &artifact_digest);
    assert_ne!(first.receipt_digest(), second.receipt_digest());

    let changed_artifact = bind_semantic_execution_receipt(
        semantic_key,
        digest(30)?,
        correlation(1)?,
        ExecutionArtifactOutcome::Reused,
        SemanticReuseReason::Hit,
    )?;
    assert_ne!(first.receipt_digest(), changed_artifact.receipt_digest());
    Ok(())
}

#[test]
fn receipt_outcome_cannot_contradict_reuse_reason() -> Result<(), Box<dyn Error>> {
    let request = request()?;
    let semantic_key = key(&request)?;
    assert!(
        bind_semantic_execution_receipt(
            semantic_key.clone(),
            digest(10)?,
            correlation(1)?,
            ExecutionArtifactOutcome::Generated,
            SemanticReuseReason::Hit,
        )
        .is_err()
    );
    assert!(
        bind_semantic_execution_receipt(
            semantic_key,
            digest(10)?,
            correlation(2)?,
            ExecutionArtifactOutcome::Reused,
            SemanticReuseReason::AbsentEntry,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reasons_are_a_closed_content_free_vocabulary() {
    let reasons = [
        SemanticReuseReason::Hit,
        SemanticReuseReason::AbsentEntry,
        SemanticReuseReason::NormalizedNeedMismatch,
        SemanticReuseReason::AuthorizationMismatch,
        SemanticReuseReason::DisclosureMismatch,
        SemanticReuseReason::PolicyMismatch,
        SemanticReuseReason::WatermarkMismatch,
        SemanticReuseReason::TargetMismatch,
        SemanticReuseReason::TokenizerMismatch,
        SemanticReuseReason::MaterializerMismatch,
        SemanticReuseReason::CompilerMismatch,
        SemanticReuseReason::SemanticKeyMismatch,
        SemanticReuseReason::UnknownSemanticExtension,
        SemanticReuseReason::UncertainAuthority,
    ];
    for reason in reasons {
        assert!(
            reason
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        assert!(reason.as_str().len() <= 30);
    }
}
