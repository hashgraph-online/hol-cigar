use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_api::{
    CursorCodec, CursorError, CursorScope, CursorSigningKey, OperationId, PrincipalId, TenantId,
    registered_http_routes,
};
use cigar_conformance::CaseOutcome;
use cigar_protocol::{ContentDigest, PageCursor, UtcTimestamp};

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "service_cursor_roundtrip" => cursor_roundtrip(input),
        "service_cursor_tamper" => cursor_tamper(input),
        _ => Err("unsupported service conformance operation".into()),
    }
}

fn cursor_roundtrip(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "service-cursor-roundtrip-v1")?;
    let (codec, scope, now, expires_at) = fixture()?;
    let cursor = codec.seal(&scope, b"stable-position-17", expires_at)?;
    let claims = codec.open(&cursor, &scope, now)?;
    if claims.position() != b"stable-position-17" || claims.expires_at() != expires_at {
        return Err("production cursor did not round trip exact claims".into());
    }
    let mut routes = registered_http_routes();
    routes.sort_by(|left, right| left.2.cmp(right.2));
    let route_names = routes
        .iter()
        .map(|route| route.2)
        .collect::<Vec<_>>()
        .join(",");
    let cursor_digest = super::super::sha256(cursor.as_bytes());
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.service-cursor.v1",
            &[
                std::str::from_utf8(claims.position())?,
                &claims.expires_at().unix_nanos().to_string(),
                &cursor_digest,
                &route_names,
            ],
        ),
    ))
}

fn cursor_tamper(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "service-cursor-tamper-v1")?;
    let (codec, scope, now, expires_at) = fixture()?;
    let cursor = codec.seal(&scope, b"stable-position-17", expires_at)?;
    let mut bytes = cursor.as_bytes().to_vec();
    let last = bytes.last_mut().ok_or("cursor bytes unexpectedly empty")?;
    *last ^= 0x01;
    let forged = PageCursor::new(bytes)?;
    let error = codec
        .open(&forged, &scope, now)
        .err()
        .ok_or("production cursor codec accepted a forged tag")?;
    if error != CursorError::Invalid {
        return Err("production cursor codec returned the wrong tamper category".into());
    }
    Ok((
        CaseOutcome::Rejected,
        rejected_digest("service_cursor_invalid"),
    ))
}

fn fixture()
-> Result<(CursorCodec, CursorScope, UtcTimestamp, UtcTimestamp), Box<dyn std::error::Error>> {
    let key = CursorSigningKey::new(b"0123456789abcdef0123456789abcdef".to_vec())?;
    let scope = CursorScope::new(
        TenantId::new("tenant-a")?,
        PrincipalId::new("principal-a")?,
        OperationId::new("listContextAtoms")?,
        ContentDigest::new(format!("1220{}", "a".repeat(64)))?,
        ContentDigest::new(format!("1220{}", "b".repeat(64)))?,
    );
    Ok((
        CursorCodec::new(key),
        scope,
        UtcTimestamp::parse_rfc3339("2026-07-13T12:00:00Z")?,
        UtcTimestamp::parse_rfc3339("2026-07-13T12:05:00Z")?,
    ))
}
