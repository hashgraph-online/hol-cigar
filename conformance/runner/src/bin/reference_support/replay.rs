use super::{CaseResult, framed_digest, rejected_digest, require_fixture};
use cigar_conformance::CaseOutcome;
use cigar_protocol::{ContentDigest, RecordId};
use cigar_replay::{
    ObservationKind, RecordedObservation, RecordedProviderEntry, RecordedProviderErrorCode,
    RecordedProviderExpectation, RecordedProviderTape, protected_response_digest,
};

pub(super) fn execute(operation: &str, input: &serde_json::Value) -> CaseResult {
    match operation {
        "replay_recorded_provider" => recorded_provider(input),
        "replay_request_mismatch" => mismatch_rejection(input),
        _ => Err("unsupported replay conformance operation".into()),
    }
}

fn recorded_provider(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "replay-recorded-provider-v1")?;
    let first = entry(
        1,
        ObservationKind::Consumer,
        b"consumer",
        b"request-1",
        b"response-1",
    )?;
    let second = entry(
        2,
        ObservationKind::Tool,
        b"tool",
        b"request-2",
        b"response-2",
    )?;
    let mut tape = RecordedProviderTape::new(vec![first, second])?;
    let first = tape.consume(&expectation(
        1,
        ObservationKind::Consumer,
        b"consumer",
        b"request-1",
    )?)?;
    let second = tape.consume(&expectation(
        2,
        ObservationKind::Tool,
        b"tool",
        b"request-2",
    )?)?;
    let counters = tape.finish()?;
    if counters.total_observations() != 2
        || counters.consumed_observations() != 2
        || counters.remaining_observations() != 0
        || counters.live_calls() != 0
    {
        return Err("recorded provider counters violated no-live-call replay".into());
    }
    let first_response = std::str::from_utf8(first.protected_response())?;
    let second_response = std::str::from_utf8(second.protected_response())?;
    Ok((
        CaseOutcome::Success,
        framed_digest(
            "cigar.conformance.replay-recorded.v1",
            &[
                first_response,
                second_response,
                "consumed=2",
                "remaining=0",
                "live=0",
            ],
        ),
    ))
}

fn mismatch_rejection(input: &serde_json::Value) -> CaseResult {
    require_fixture(input, "replay-request-mismatch-v1")?;
    let entry = entry(
        1,
        ObservationKind::Connector,
        b"connector",
        b"authorized-request",
        b"recorded-response",
    )?;
    let mut tape = RecordedProviderTape::new(vec![entry])?;
    let error = tape
        .consume(&expectation(
            1,
            ObservationKind::Connector,
            b"connector",
            b"tampered-request",
        )?)
        .err()
        .ok_or("recorded provider accepted a mismatched request")?;
    if error.code() != RecordedProviderErrorCode::RequestMismatch
        || tape.counters().consumed_observations() != 0
        || tape.counters().live_calls() != 0
    {
        return Err("recorded provider mismatch was not fail-closed".into());
    }
    Ok((
        CaseOutcome::Rejected,
        rejected_digest("replay_request_mismatch"),
    ))
}

fn digest(bytes: &[u8]) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    Ok(protected_response_digest(bytes)?)
}

fn entry(
    ordinal: u64,
    kind: ObservationKind,
    provider: &[u8],
    request: &[u8],
    response: &[u8],
) -> Result<RecordedProviderEntry, Box<dyn std::error::Error>> {
    Ok(RecordedProviderEntry::new(
        RecordedObservation {
            ordinal,
            kind,
            request_digest: digest(request)?,
            response_digest: digest(response)?,
            provider_fingerprint: digest(provider)?,
            subject_id: Some(RecordId::new(format!(
                "01890f47-8e7d-7b42-a1d2-{ordinal:012x}"
            ))?),
        },
        response.to_vec(),
    )?)
}

fn expectation(
    ordinal: u64,
    kind: ObservationKind,
    provider: &[u8],
    request: &[u8],
) -> Result<RecordedProviderExpectation, Box<dyn std::error::Error>> {
    Ok(RecordedProviderExpectation::new(
        ordinal,
        kind,
        digest(provider)?,
        digest(request)?,
        Some(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{ordinal:012x}"
        ))?),
    ))
}
