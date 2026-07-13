//! Reference Rust adapter for the executable conformance protocol.

use cigar_canon::{
    CanonicalErrorCode, CanonicalNode, DigestDomain, digest_v1, from_deterministic_cbor,
    multihash_v1, normalize_nfc, parse_strict_json, to_deterministic_cbor,
};
use cigar_conformance::{AdapterRequest, AdapterResponse, CaseOutcome};
use cigar_protocol::{ErrorCode, RetryClass};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};

#[path = "reference_support/mod.rs"]
mod reference_support;

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

fn main() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("request exceeded adapter bound".into());
    }
    let request: AdapterRequest = serde_json::from_slice(&bytes)?;
    if request.schema_version != "cigar.conformance.request.v1" {
        return Err("unsupported request selector".into());
    }
    let (outcome, public_digest) = execute(&request)?;
    let response = AdapterResponse {
        schema_version: "cigar.conformance.response.v1".to_owned(),
        case_id: request.case_id,
        challenge: request.challenge,
        outcome,
        public_digest,
        diagnostic: None,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn execute(request: &AdapterRequest) -> Result<(CaseOutcome, String), Box<dyn Error>> {
    let core = request.profile == "cigar-core-v1";
    match request.operation.as_str() {
        "canonicalize_json" if core => canonicalize_json(&request.input),
        "reject_json" if core => reject_json(&request.input),
        "reject_cbor" if core => reject_cbor(&request.input),
        "unsupported_domain" if core => {
            Ok((CaseOutcome::Rejected, error_digest("unsupported_domain")))
        }
        "public_error" if core => public_error(&request.input),
        "differential_records" if core => differential_records(&request.input),
        _ => reference_support::execute(request),
    }
}

fn canonicalize_json(input: &serde_json::Value) -> Result<(CaseOutcome, String), Box<dyn Error>> {
    let json_input = field_text(input, "json_input")?;
    let normalization = field_text(input, "normalization")?;
    let mut node = parse_strict_json(json_input.as_bytes())?;
    apply_normalization(normalization, &mut node)?;
    let cbor = to_deterministic_cbor(&node)?;
    let domain = domain(field_text(input, "domain")?)?;
    Ok((CaseOutcome::Success, multihash_v1(domain, &cbor)))
}

fn reject_json(input: &serde_json::Value) -> Result<(CaseOutcome, String), Box<dyn Error>> {
    let json_input = field_text(input, "json_input")?;
    let error = parse_strict_json(json_input.as_bytes())
        .err()
        .ok_or("invalid JSON vector unexpectedly passed")?;
    Ok((
        CaseOutcome::Rejected,
        error_digest(error_name(error.code())),
    ))
}

fn reject_cbor(input: &serde_json::Value) -> Result<(CaseOutcome, String), Box<dyn Error>> {
    let bytes = decode_hex(field_text(input, "cbor_hex")?)?;
    let error = from_deterministic_cbor(&bytes)
        .err()
        .ok_or("invalid CBOR vector unexpectedly passed")?;
    Ok((
        CaseOutcome::Rejected,
        error_digest(error_name(error.code())),
    ))
}

fn public_error(input: &serde_json::Value) -> Result<(CaseOutcome, String), Box<dyn Error>> {
    let numeric = input
        .get("code")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("public error code is missing")?;
    let code = error_code(numeric).ok_or("unsupported public error code")?;
    let definition = code.definition();
    let retry = retry_name(definition.retry);
    let parts = [
        "cigar.conformance.public-error.v1",
        &numeric.to_string(),
        definition.symbol,
        &definition.http_status.to_string(),
        definition.grpc_status,
        retry,
    ];
    let mut framed = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            framed.push(0);
        }
        framed.extend_from_slice(part.as_bytes());
    }
    Ok((CaseOutcome::Success, sha256(&framed)))
}

fn differential_records(
    input: &serde_json::Value,
) -> Result<(CaseOutcome, String), Box<dyn Error>> {
    if field_text(input, "algorithm")? != "cigar-differential-record-v1" {
        return Err("unsupported differential algorithm".into());
    }
    let count = input
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value <= 100_000)
        .ok_or("invalid differential record count")?;
    let domain = domain(field_text(input, "domain")?)?;
    let mut accumulator = Sha256::new();
    for index in 0..count {
        let mut record = BTreeMap::new();
        record.insert("active".to_owned(), CanonicalNode::Boolean(index % 2 == 0));
        record.insert(
            "index".to_owned(),
            CanonicalNode::Unsigned(u64::from(index)),
        );
        record.insert(
            "label".to_owned(),
            CanonicalNode::Text(format!("record-{}", index % 997)),
        );
        record.insert(
            "values".to_owned(),
            CanonicalNode::Array(vec![
                CanonicalNode::Unsigned(u64::from(index % 17)),
                CanonicalNode::Negative(-i64::from(index % 19) - 1),
            ]),
        );
        let cbor = to_deterministic_cbor(&CanonicalNode::Map(record))?;
        accumulator.update(digest_v1(domain, &cbor));
    }
    Ok((
        CaseOutcome::Success,
        format!("sha256:{}", lower_hex(&accumulator.finalize())),
    ))
}

fn apply_normalization(profile: &str, node: &mut CanonicalNode) -> Result<(), Box<dyn Error>> {
    match profile {
        "none" => Ok(()),
        "nfc:/human_text" => {
            let CanonicalNode::Map(fields) = node else {
                return Err("NFC vector is not an object".into());
            };
            let Some(CanonicalNode::Text(value)) = fields.get_mut("human_text") else {
                return Err("NFC vector lacks human_text".into());
            };
            *value = normalize_nfc(value);
            Ok(())
        }
        _ => Err("unsupported normalization selector".into()),
    }
}

fn field_text<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.len() <= MAX_REQUEST_BYTES as usize)
        .ok_or_else(|| format!("missing bounded `{field}` field").into())
}

fn domain(value: &str) -> Result<DigestDomain, Box<dyn Error>> {
    match value {
        "atom" => Ok(DigestDomain::Atom),
        "bundle" => Ok(DigestDomain::Bundle),
        "manifest" => Ok(DigestDomain::Manifest),
        "handoff" => Ok(DigestDomain::Handoff),
        "effect" => Ok(DigestDomain::Effect),
        "receipt" => Ok(DigestDomain::Receipt),
        "extension_manifest" => Ok(DigestDomain::ExtensionManifest),
        _ => Err("unsupported digest domain".into()),
    }
}

const fn error_name(code: CanonicalErrorCode) -> &'static str {
    match code {
        CanonicalErrorCode::InvalidInput => "invalid_input",
        CanonicalErrorCode::DuplicateKey => "duplicate_key",
        CanonicalErrorCode::NullForbidden => "null_forbidden",
        CanonicalErrorCode::FloatForbidden => "float_forbidden",
        CanonicalErrorCode::LimitExceeded => "limit_exceeded",
        CanonicalErrorCode::NonCanonical => "non_canonical",
        CanonicalErrorCode::BytesNotJson => "bytes_not_json",
    }
}

const fn retry_name(retry: RetryClass) -> &'static str {
    match retry {
        RetryClass::Never => "never",
        RetryClass::Safe => "safe",
        RetryClass::AfterBackoff => "after_backoff",
        RetryClass::AfterReauthorization => "after_reauthorization",
        RetryClass::AfterReconciliation => "after_reconciliation",
    }
}

const fn error_code(value: u32) -> Option<ErrorCode> {
    match value {
        1000 => Some(ErrorCode::InvalidArgument),
        1001 => Some(ErrorCode::LimitExceeded),
        1002 => Some(ErrorCode::UnsupportedSchema),
        1100 => Some(ErrorCode::UnknownPrincipal),
        1101 => Some(ErrorCode::InvalidCapability),
        1102 => Some(ErrorCode::CapabilityExpired),
        1200 => Some(ErrorCode::SourceUnavailable),
        1201 => Some(ErrorCode::SnapshotIncomplete),
        1202 => Some(ErrorCode::IntegrityFailure),
        1300 => Some(ErrorCode::IndexStale),
        1301 => Some(ErrorCode::IndexUnavailable),
        1302 => Some(ErrorCode::ConsistencyUnsatisfied),
        1400 => Some(ErrorCode::PolicyDenied),
        1401 => Some(ErrorCode::ProcessorDenied),
        1402 => Some(ErrorCode::InstructionAuthorityDenied),
        1500 => Some(ErrorCode::BudgetUnsatisfiable),
        1501 => Some(ErrorCode::MissingRequiredContext),
        1502 => Some(ErrorCode::UnresolvedCriticalConflict),
        1600 => Some(ErrorCode::DeltaBaseMismatch),
        1601 => Some(ErrorCode::BundleInvalidated),
        1700 => Some(ErrorCode::RevisionConflict),
        1701 => Some(ErrorCode::HandoffExpired),
        1702 => Some(ErrorCode::HandoffRecipientMismatch),
        1800 => Some(ErrorCode::ApprovalRequired),
        1801 => Some(ErrorCode::ApprovalStale),
        1802 => Some(ErrorCode::EffectUnknown),
        1803 => Some(ErrorCode::UnsafeRetry),
        1900 => Some(ErrorCode::ReplayIncomplete),
        1901 => Some(ErrorCode::DependencyUnavailable),
        1902 => Some(ErrorCode::LiveAuthorizationRequired),
        2000 => Some(ErrorCode::RateLimited),
        2001 => Some(ErrorCode::DeadlineExceeded),
        2002 => Some(ErrorCode::DependencyDegraded),
        2099 => Some(ErrorCode::Internal),
        _ => None,
    }
}

fn error_digest(name: &str) -> String {
    let mut bytes = b"cigar.conformance.error.v1\0".to_vec();
    bytes.extend_from_slice(name.as_bytes());
    sha256(&bytes)
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", lower_hex(&digest))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) || value.len() > 2 * 1024 * 1024 {
        return Err("invalid hex length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
