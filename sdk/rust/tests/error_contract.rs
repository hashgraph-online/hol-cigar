//! Stable typed error and secret-redaction tests.

use cigar_sdk::protocol::{
    ErrorCode, ExtensionMap, IdempotencyKey, PageCursor, Problem, RecordId, RetryClass,
    SchemaVersion,
};
use cigar_sdk::{AuthorizationValue, CallOptions, ErrorKind, SdkError, StaticAuthorization};

#[test]
fn validated_problem_maps_without_losing_stable_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let problem = Problem {
        schema_version: SchemaVersion::new("cigar.problem", 1)?,
        code: ErrorCode::RateLimited,
        http_status: 429,
        retry: RetryClass::AfterBackoff,
        message: ErrorCode::RateLimited.definition().message.to_owned(),
        remediation: ErrorCode::RateLimited.definition().remediation.to_owned(),
        correlation_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
        details: ExtensionMap::default(),
    };
    let error = SdkError::from_problem(problem)?;
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(error.code(), Some(ErrorCode::RateLimited));
    assert_eq!(error.retry_class(), RetryClass::AfterBackoff);
    assert!(error.correlation_id().is_some());
    Ok(())
}

#[test]
fn authorization_debug_never_discloses_secret() -> Result<(), Box<dyn std::error::Error>> {
    let secret = "Bearer top-secret-token";
    let value = AuthorizationValue::new(secret)?;
    let provider = StaticAuthorization::new(value.clone());
    let rendered = format!("{value:?} {provider:?}");
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("top-secret-token"));
    let options = CallOptions::mutation(IdempotencyKey::new("secret-idempotency")?)
        .with_page(Some(PageCursor::new(b"secret-cursor".to_vec())?), 10)?;
    let rendered = format!("{options:?}");
    assert!(!rendered.contains("secret-idempotency"));
    assert!(!rendered.contains("secret-cursor"));
    Ok(())
}
