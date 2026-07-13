//! Strict protected connector-argument document conformance.

use cigar_effects::EffectErrorCode;
use cigar_effects::reference::{
    DemoIssueRequest, FilesystemWriteRequest, HttpMethod, HttpResourceScope, IdempotentHttpRequest,
};
use cigar_protocol::{ContentDigest, RecordId};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn digest(value: char) -> Result<ContentDigest, cigar_protocol::ValidationErrors> {
    ContentDigest::new(format!("1220{}", value.to_string().repeat(64)))
}

#[test]
fn protected_argument_documents_round_trip_exact_normalized_requests() -> TestResult {
    let demo = DemoIssueRequest::new("project-a", "bounded title", "bounded body")?;
    let demo_bytes = demo.encode_protected_document()?;
    assert_eq!(
        DemoIssueRequest::decode_protected_document(&demo_bytes)?,
        demo
    );

    let filesystem = FilesystemWriteRequest::new(
        "nested/output.bin",
        vec![0, 1, 2, 127, 128, 255],
        Some(digest('a')?),
    )?;
    let filesystem_bytes = filesystem.encode_protected_document()?;
    assert_eq!(
        FilesystemWriteRequest::decode_protected_document(&filesystem_bytes)?,
        filesystem
    );

    let http = IdempotentHttpRequest::new_scoped(
        HttpMethod::Put,
        "application/octet-stream",
        vec![0, 10, 13, 255],
        HttpResourceScope::new(
            RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            "resource-a",
        )?,
    )?;
    let http_bytes = http.encode_protected_document()?;
    assert_eq!(
        IdempotentHttpRequest::decode_protected_document(&http_bytes)?,
        http
    );
    Ok(())
}

#[test]
fn protected_argument_documents_reject_ambiguity_schema_drift_and_invalid_bytes() -> TestResult {
    let duplicate = br#"{
        "schema_version":"cigar.effect-arguments.demo-issue.v1",
        "schema_version":"cigar.effect-arguments.demo-issue.v1",
        "project":"project-a","title":"title","body":"body"
    }"#;
    assert_eq!(
        DemoIssueRequest::decode_protected_document(duplicate).map_err(|error| error.code()),
        Err(EffectErrorCode::InvalidInput)
    );

    let unknown = br#"{
        "schema_version":"cigar.effect-arguments.filesystem-write.v1",
        "relative_path":"output.bin","bytes_base64url":"AA",
        "unexpected":true
    }"#;
    assert_eq!(
        FilesystemWriteRequest::decode_protected_document(unknown).map_err(|error| error.code()),
        Err(EffectErrorCode::InvalidInput)
    );

    let invalid_base64 = br#"{
        "schema_version":"cigar.effect-arguments.idempotent-http.v1",
        "method":"post","content_type":"application/json","body_base64url":"***"
    }"#;
    assert_eq!(
        IdempotentHttpRequest::decode_protected_document(invalid_base64)
            .map_err(|error| error.code()),
        Err(EffectErrorCode::InvalidInput)
    );

    let wrong_schema = br#"{
        "schema_version":"cigar.effect-arguments.demo-issue.v2",
        "project":"project-a","title":"title","body":"body"
    }"#;
    assert_eq!(
        DemoIssueRequest::decode_protected_document(wrong_schema).map_err(|error| error.code()),
        Err(EffectErrorCode::InvalidInput)
    );

    assert_eq!(
        FilesystemWriteRequest::decode_protected_document(&vec![b' '; 2_000_000])
            .map_err(|error| error.code()),
        Err(EffectErrorCode::LimitExceeded)
    );
    Ok(())
}
