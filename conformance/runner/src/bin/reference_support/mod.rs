//! Production-backed cases for the non-core conformance profiles.

mod catalog;
mod compiler;
mod effect;
mod handoff;
mod replay;
mod runtime;
mod service;

use cigar_conformance::{AdapterRequest, CaseOutcome};
use std::error::Error;

type CaseResult = Result<(CaseOutcome, String), Box<dyn Error>>;

pub(super) fn execute(request: &AdapterRequest) -> CaseResult {
    match request.profile.as_str() {
        "cigar-catalog-v1" => catalog::execute(&request.operation, &request.input),
        "cigar-compiler-v1" => compiler::execute(&request.operation, &request.input),
        "cigar-handoff-v1" => handoff::execute(&request.operation, &request.input),
        "cigar-effect-v1" => effect::execute(&request.operation, &request.input),
        "cigar-replay-v1" => replay::execute(&request.operation, &request.input),
        "cigar-service-v1" => service::execute(&request.operation, &request.input),
        "cigar-runtime-claude-code-v1" => runtime::execute(&request.operation, &request.input),
        _ => Err("unsupported conformance profile or operation".into()),
    }
}

fn require_fixture(input: &serde_json::Value, expected: &str) -> Result<(), Box<dyn Error>> {
    let actual = super::field_text(input, "fixture")?;
    if actual != expected {
        return Err("unsupported production fixture selector".into());
    }
    Ok(())
}

fn framed_digest(domain: &str, fields: &[&str]) -> String {
    let mut bytes = domain.as_bytes().to_vec();
    for field in fields {
        bytes.push(0);
        bytes.extend_from_slice(field.as_bytes());
    }
    super::sha256(&bytes)
}

fn rejected_digest(category: &str) -> String {
    super::error_digest(category)
}
