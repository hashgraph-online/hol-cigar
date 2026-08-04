//! Constructs a compatibility-safe semantic key and binds one execution receipt.

use cigar_sdk::api::TraceId;
use cigar_sdk::protocol::{ContentDigest, IdempotencyKey, RecordId};
use cigar_sdk::{
    AuthorityStatus, ExecutionArtifactOutcome, ExecutionCorrelation, ReusableSemanticArtifact,
    SemanticExtensionStatus, SemanticRequestKeyDecision, SemanticReusePins, SemanticReuseReason,
    SemanticReuseRequest, bind_semantic_execution_receipt, evaluate_semantic_reuse,
    semantic_request_key,
};
use std::error::Error;

fn digest(value: u8) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(ContentDigest::new(format!(
        "1220{}",
        format!("{value:02x}").repeat(32)
    ))?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let request = SemanticReuseRequest {
        pins: SemanticReusePins {
            // Produce this from the normalized governed need, never from run/job/trace values.
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
    };
    let key = match semantic_request_key(&request)? {
        SemanticRequestKeyDecision::Key(key) => key,
        SemanticRequestKeyDecision::Bypass(reason) => {
            println!("reuse={}", reason.as_str());
            return Ok(());
        }
    };

    // A caller idempotency key controls mutation replay. It is deliberately not a key input.
    let _mutation_idempotency = IdempotencyKey::new("compile-attempt-0001")?;
    let artifact = ReusableSemanticArtifact {
        semantic_request_key: key.clone(),
        artifact_digest: digest(10)?,
        pins: request.pins.clone(),
    };
    let evaluation = evaluate_semantic_reuse(&request, Some(&artifact))?;
    if !evaluation.is_hit() {
        println!("reuse={}", evaluation.reason().as_str());
        return Ok(());
    }

    // Correlation is bound after reuse selection, so each execution is auditable without changing
    // the stable semantic key or artifact digest.
    let receipt = bind_semantic_execution_receipt(
        key,
        artifact.artifact_digest,
        ExecutionCorrelation {
            operation_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            trace_id: TraceId::new("0123456789abcdef0123456789abcdef")?,
            run_correlation_digest: Some(digest(11)?),
            job_correlation_digest: Some(digest(12)?),
        },
        ExecutionArtifactOutcome::Reused,
        SemanticReuseReason::Hit,
    )?;
    println!(
        "reuse={} receipt={}",
        receipt.reason().as_str(),
        receipt.receipt_digest().as_str()
    );
    Ok(())
}
