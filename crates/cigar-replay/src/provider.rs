//! Recorded-only provider substitution for observational replay.
//!
//! The tape deliberately has no callback, transport, connector, current-state lookup, or live
//! fallback. A consumer can only request the next exact archived observation and must prove that
//! the tape is exhausted before declaring replay complete.

use crate::contract::{
    MAX_DECISION_ARTIFACT_BYTES, MAX_DECISION_CAPTURE_BYTES, ObservationKind, RecordedObservation,
};
use cigar_protocol::limits::MAX_REPLAY_REFERENCES;
use cigar_protocol::{ContentDigest, RecordId};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;

/// Maximum observations accepted by one recorded provider tape.
pub const MAX_RECORDED_PROVIDER_OBSERVATIONS: usize = MAX_REPLAY_REFERENCES;
/// Maximum protected response bytes in one observation.
pub const MAX_RECORDED_PROVIDER_RESPONSE_BYTES: usize = MAX_DECISION_ARTIFACT_BYTES;
/// Maximum aggregate protected response bytes in one tape.
pub const MAX_RECORDED_PROVIDER_TAPE_BYTES: usize = MAX_DECISION_CAPTURE_BYTES;

/// Stable failure categories for recorded-only provider consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedProviderErrorCode {
    /// A tape entry has a zero, duplicate, gapped, or out-of-order ordinal.
    InvalidSequence,
    /// A response digest does not match the exact protected response bytes.
    CorruptResponse,
    /// An entry, tape, or counter exceeds a fixed bound.
    LimitExceeded,
    /// The consumer requested an observation after the tape was exhausted.
    MissingObservation,
    /// The consumer requested an ordinal other than the exact next ordinal.
    SequenceMismatch,
    /// The next recorded source category differs from the requested category.
    KindMismatch,
    /// The exact recorded component implementation differs from the requested component.
    ComponentMismatch,
    /// The replayed request differs from the exact recorded request.
    RequestMismatch,
    /// The optional effect, attempt, or tool-call subject differs from the transcript.
    SubjectMismatch,
    /// Replay completion was attempted with unconsumed recorded observations.
    ExtraObservations,
}

/// Content-free error returned by the recorded provider tape.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecordedProviderError {
    code: RecordedProviderErrorCode,
}

impl RecordedProviderError {
    const fn new(code: RecordedProviderErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn code(self) -> RecordedProviderErrorCode {
        self.code
    }
}

impl fmt::Debug for RecordedProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedProviderError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for RecordedProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "recorded provider failed: {:?}", self.code)
    }
}

impl std::error::Error for RecordedProviderError {}

/// One archived transcript row paired with its exact protected response bytes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedProviderEntry {
    observation: RecordedObservation,
    protected_response: Vec<u8>,
}

impl RecordedProviderEntry {
    /// Creates and integrity-checks one recorded response entry.
    pub fn new(
        observation: RecordedObservation,
        protected_response: Vec<u8>,
    ) -> Result<Self, RecordedProviderError> {
        let entry = Self {
            observation,
            protected_response,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Returns the immutable archived observation metadata.
    #[must_use]
    pub const fn observation(&self) -> &RecordedObservation {
        &self.observation
    }

    /// Returns the protected recorded response bytes to the replay consumer.
    #[must_use]
    pub fn protected_response(&self) -> &[u8] {
        &self.protected_response
    }

    fn validate(&self) -> Result<(), RecordedProviderError> {
        if self.observation.ordinal == 0 {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::InvalidSequence,
            ));
        }
        if self.protected_response.len() > MAX_RECORDED_PROVIDER_RESPONSE_BYTES {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::LimitExceeded,
            ));
        }
        if protected_response_digest(&self.protected_response)? != self.observation.response_digest
        {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::CorruptResponse,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RecordedProviderEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedProviderEntry")
            .field("ordinal", &self.observation.ordinal)
            .field("kind", &self.observation.kind)
            .field(
                "provider_fingerprint",
                &self.observation.provider_fingerprint,
            )
            .field("request_digest", &self.observation.request_digest)
            .field("response_digest", &self.observation.response_digest)
            .field("subject_id", &self.observation.subject_id)
            .field("protected_response_bytes", &self.protected_response.len())
            .finish_non_exhaustive()
    }
}

/// Exact next-call expectation supplied by an observational replay consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedProviderExpectation {
    ordinal: u64,
    kind: ObservationKind,
    provider_fingerprint: ContentDigest,
    request_digest: ContentDigest,
    subject_id: Option<RecordId>,
}

impl RecordedProviderExpectation {
    /// Creates an exact expectation for the next one-based recorded observation.
    #[must_use]
    pub const fn new(
        ordinal: u64,
        kind: ObservationKind,
        provider_fingerprint: ContentDigest,
        request_digest: ContentDigest,
        subject_id: Option<RecordId>,
    ) -> Self {
        Self {
            ordinal,
            kind,
            provider_fingerprint,
            request_digest,
            subject_id,
        }
    }

    /// Returns the expected one-based ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the expected observation category.
    #[must_use]
    pub const fn kind(&self) -> ObservationKind {
        self.kind
    }

    /// Returns the required component fingerprint.
    #[must_use]
    pub const fn provider_fingerprint(&self) -> &ContentDigest {
        &self.provider_fingerprint
    }

    /// Returns the exact replayed request digest.
    #[must_use]
    pub const fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    /// Returns the optional exact subject identity.
    #[must_use]
    pub const fn subject_id(&self) -> Option<&RecordId> {
        self.subject_id.as_ref()
    }
}

/// Observable call counters for a recorded-only provider tape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordedProviderCounters {
    total_observations: u64,
    consumed_observations: u64,
    remaining_observations: u64,
    live_calls: u64,
}

impl RecordedProviderCounters {
    /// Returns observations initially present in the tape.
    #[must_use]
    pub const fn total_observations(self) -> u64 {
        self.total_observations
    }

    /// Returns observations successfully consumed exactly once.
    #[must_use]
    pub const fn consumed_observations(self) -> u64 {
        self.consumed_observations
    }

    /// Returns observations not yet consumed.
    #[must_use]
    pub const fn remaining_observations(self) -> u64 {
        self.remaining_observations
    }

    /// Returns live dependency calls; recorded tapes always report zero.
    #[must_use]
    pub const fn live_calls(self) -> u64 {
        self.live_calls
    }
}

/// Bounded, strictly ordered, consume-once observation tape with no live provider surface.
pub struct RecordedProviderTape {
    remaining: VecDeque<RecordedProviderEntry>,
    total_observations: u64,
    consumed_observations: u64,
    next_ordinal: u64,
}

impl RecordedProviderTape {
    /// Validates and creates a complete one-based observation tape.
    pub fn new(entries: Vec<RecordedProviderEntry>) -> Result<Self, RecordedProviderError> {
        if entries.len() > MAX_RECORDED_PROVIDER_OBSERVATIONS {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::LimitExceeded,
            ));
        }
        let total_observations = u64::try_from(entries.len()).map_err(|_error| {
            RecordedProviderError::new(RecordedProviderErrorCode::LimitExceeded)
        })?;
        let mut expected_ordinal = 1_u64;
        let mut total_bytes = 0_usize;
        for entry in &entries {
            entry.validate()?;
            if entry.observation.ordinal != expected_ordinal {
                return Err(RecordedProviderError::new(
                    RecordedProviderErrorCode::InvalidSequence,
                ));
            }
            expected_ordinal = expected_ordinal.checked_add(1).ok_or_else(|| {
                RecordedProviderError::new(RecordedProviderErrorCode::LimitExceeded)
            })?;
            total_bytes = total_bytes
                .checked_add(entry.protected_response.len())
                .ok_or_else(|| {
                    RecordedProviderError::new(RecordedProviderErrorCode::LimitExceeded)
                })?;
            if total_bytes > MAX_RECORDED_PROVIDER_TAPE_BYTES {
                return Err(RecordedProviderError::new(
                    RecordedProviderErrorCode::LimitExceeded,
                ));
            }
        }
        Ok(Self {
            remaining: entries.into(),
            total_observations,
            consumed_observations: 0,
            next_ordinal: 1,
        })
    }

    /// Consumes only the exact next observation, leaving the tape unchanged on mismatch.
    pub fn consume(
        &mut self,
        expectation: &RecordedProviderExpectation,
    ) -> Result<RecordedProviderEntry, RecordedProviderError> {
        let Some(next) = self.remaining.front() else {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::MissingObservation,
            ));
        };
        if expectation.ordinal != self.next_ordinal
            || next.observation.ordinal != expectation.ordinal
        {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::SequenceMismatch,
            ));
        }
        if next.observation.kind != expectation.kind {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::KindMismatch,
            ));
        }
        if next.observation.provider_fingerprint != expectation.provider_fingerprint {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::ComponentMismatch,
            ));
        }
        if next.observation.request_digest != expectation.request_digest {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::RequestMismatch,
            ));
        }
        if next.observation.subject_id != expectation.subject_id {
            return Err(RecordedProviderError::new(
                RecordedProviderErrorCode::SubjectMismatch,
            ));
        }
        let consumed = self.remaining.pop_front().ok_or_else(|| {
            RecordedProviderError::new(RecordedProviderErrorCode::MissingObservation)
        })?;
        self.consumed_observations = self
            .consumed_observations
            .checked_add(1)
            .ok_or_else(|| RecordedProviderError::new(RecordedProviderErrorCode::LimitExceeded))?;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or_else(|| RecordedProviderError::new(RecordedProviderErrorCode::LimitExceeded))?;
        Ok(consumed)
    }

    /// Returns content-free progress counters, including the invariant zero live-call count.
    #[must_use]
    pub fn counters(&self) -> RecordedProviderCounters {
        RecordedProviderCounters {
            total_observations: self.total_observations,
            consumed_observations: self.consumed_observations,
            remaining_observations: self
                .total_observations
                .saturating_sub(self.consumed_observations),
            live_calls: 0,
        }
    }

    /// Consumes the tape object and fails if any recorded dependency call was not requested.
    pub fn finish(self) -> Result<RecordedProviderCounters, RecordedProviderError> {
        if self.remaining.is_empty() {
            Ok(self.counters())
        } else {
            Err(RecordedProviderError::new(
                RecordedProviderErrorCode::ExtraObservations,
            ))
        }
    }
}

impl fmt::Debug for RecordedProviderTape {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedProviderTape")
            .field("counters", &self.counters())
            .field("next_ordinal", &self.next_ordinal)
            .finish_non_exhaustive()
    }
}

/// Computes the exact SHA-256 multihash of protected recorded response bytes.
pub fn protected_response_digest(
    protected_response: &[u8],
) -> Result<ContentDigest, RecordedProviderError> {
    crate::digest::raw_content_digest(protected_response)
        .map_err(|_error| RecordedProviderError::new(RecordedProviderErrorCode::CorruptResponse))
}

#[cfg(test)]
mod tests {
    use super::{
        RecordedProviderEntry, RecordedProviderError, RecordedProviderErrorCode,
        RecordedProviderExpectation, RecordedProviderTape, protected_response_digest,
    };
    use crate::contract::{ObservationKind, RecordedObservation};
    use cigar_protocol::{ContentDigest, RecordId};
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    fn digest(value: &[u8]) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(protected_response_digest(value)?)
    }

    fn record(value: u64) -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn entry(
        ordinal: u64,
        kind: ObservationKind,
        component: &[u8],
        request: &[u8],
        response: &[u8],
        subject_id: Option<RecordId>,
    ) -> Result<RecordedProviderEntry, Box<dyn Error>> {
        Ok(RecordedProviderEntry::new(
            RecordedObservation {
                ordinal,
                kind,
                request_digest: digest(request)?,
                response_digest: digest(response)?,
                provider_fingerprint: digest(component)?,
                subject_id,
            },
            response.to_vec(),
        )?)
    }

    fn expectation(
        ordinal: u64,
        kind: ObservationKind,
        component: &[u8],
        request: &[u8],
        subject_id: Option<RecordId>,
    ) -> Result<RecordedProviderExpectation, Box<dyn Error>> {
        Ok(RecordedProviderExpectation::new(
            ordinal,
            kind,
            digest(component)?,
            digest(request)?,
            subject_id,
        ))
    }

    #[test]
    fn consumes_all_closed_kinds_once_in_exact_order_without_live_calls() -> TestResult {
        let fixtures = [
            (ObservationKind::Consumer, b"model".as_slice()),
            (ObservationKind::Tool, b"tool".as_slice()),
            (ObservationKind::Connector, b"connector".as_slice()),
            (ObservationKind::Effect, b"effect".as_slice()),
        ];
        let mut entries = Vec::new();
        let mut expectations = Vec::new();
        for (offset, (kind, label)) in fixtures.into_iter().enumerate() {
            let ordinal = u64::try_from(offset)?.saturating_add(1);
            let subject_id = Some(record(ordinal)?);
            entries.push(entry(
                ordinal,
                kind,
                label,
                label,
                label,
                subject_id.clone(),
            )?);
            expectations.push(expectation(ordinal, kind, label, label, subject_id)?);
        }
        let mut tape = RecordedProviderTape::new(entries)?;
        assert_eq!(tape.counters().live_calls(), 0);
        for expected in &expectations {
            let response = tape.consume(expected)?;
            assert_eq!(response.observation().ordinal, expected.ordinal());
            assert_eq!(
                response.observation().response_digest,
                digest(response.protected_response())?
            );
        }
        let counters = tape.finish()?;
        assert_eq!(counters.total_observations(), 4);
        assert_eq!(counters.consumed_observations(), 4);
        assert_eq!(counters.remaining_observations(), 0);
        assert_eq!(counters.live_calls(), 0);
        Ok(())
    }

    #[test]
    fn every_mismatch_including_subject_leaves_next_entry_unconsumed() -> TestResult {
        let subject = Some(record(20)?);
        let first = entry(
            1,
            ObservationKind::Consumer,
            b"component-a",
            b"request-a",
            b"protected-response",
            subject.clone(),
        )?;
        let mut tape = RecordedProviderTape::new(vec![first])?;
        let cases = [
            (
                expectation(
                    2,
                    ObservationKind::Consumer,
                    b"component-a",
                    b"request-a",
                    subject.clone(),
                )?,
                RecordedProviderErrorCode::SequenceMismatch,
            ),
            (
                expectation(
                    1,
                    ObservationKind::Tool,
                    b"component-a",
                    b"request-a",
                    subject.clone(),
                )?,
                RecordedProviderErrorCode::KindMismatch,
            ),
            (
                expectation(
                    1,
                    ObservationKind::Consumer,
                    b"component-b",
                    b"request-a",
                    subject.clone(),
                )?,
                RecordedProviderErrorCode::ComponentMismatch,
            ),
            (
                expectation(
                    1,
                    ObservationKind::Consumer,
                    b"component-a",
                    b"request-b",
                    subject.clone(),
                )?,
                RecordedProviderErrorCode::RequestMismatch,
            ),
            (
                expectation(
                    1,
                    ObservationKind::Consumer,
                    b"component-a",
                    b"request-a",
                    Some(record(21)?),
                )?,
                RecordedProviderErrorCode::SubjectMismatch,
            ),
        ];
        for (expected, code) in cases {
            assert_eq!(
                tape.consume(&expected)
                    .err()
                    .map(RecordedProviderError::code),
                Some(code)
            );
            assert_eq!(tape.counters().consumed_observations(), 0);
            assert_eq!(tape.counters().remaining_observations(), 1);
            assert_eq!(tape.counters().live_calls(), 0);
        }
        tape.consume(&expectation(
            1,
            ObservationKind::Consumer,
            b"component-a",
            b"request-a",
            subject,
        )?)?;
        assert_eq!(
            tape.consume(&expectation(
                2,
                ObservationKind::Consumer,
                b"component-a",
                b"request-a",
                None,
            )?)
            .err()
            .map(RecordedProviderError::code),
            Some(RecordedProviderErrorCode::MissingObservation)
        );
        Ok(())
    }

    #[test]
    fn rejects_gapped_corrupt_and_extra_entries_but_accepts_exact_empty_response() -> TestResult {
        let first = entry(
            1,
            ObservationKind::Tool,
            b"tool",
            b"request-1",
            b"response-1",
            None,
        )?;
        let third = entry(
            3,
            ObservationKind::Tool,
            b"tool",
            b"request-3",
            b"response-3",
            None,
        )?;
        assert_eq!(
            RecordedProviderTape::new(vec![first.clone(), third])
                .err()
                .map(RecordedProviderError::code),
            Some(RecordedProviderErrorCode::InvalidSequence)
        );
        let corrupt = RecordedObservation {
            ordinal: 1,
            kind: ObservationKind::Tool,
            request_digest: digest(b"request")?,
            response_digest: digest(b"different")?,
            provider_fingerprint: digest(b"tool")?,
            subject_id: None,
        };
        assert_eq!(
            RecordedProviderEntry::new(corrupt, b"response".to_vec())
                .err()
                .map(RecordedProviderError::code),
            Some(RecordedProviderErrorCode::CorruptResponse)
        );
        assert_eq!(
            RecordedProviderTape::new(vec![first])
                .and_then(RecordedProviderTape::finish)
                .err()
                .map(RecordedProviderError::code),
            Some(RecordedProviderErrorCode::ExtraObservations)
        );

        let empty_entry = entry(
            1,
            ObservationKind::Connector,
            b"connector",
            b"empty-response-request",
            b"",
            None,
        )?;
        let mut empty_tape = RecordedProviderTape::new(vec![empty_entry])?;
        let consumed = empty_tape.consume(&expectation(
            1,
            ObservationKind::Connector,
            b"connector",
            b"empty-response-request",
            None,
        )?)?;
        assert!(consumed.protected_response().is_empty());
        assert_eq!(empty_tape.finish()?.live_calls(), 0);
        Ok(())
    }

    #[test]
    fn debug_views_never_disclose_protected_response_bytes() -> TestResult {
        let secret = b"super-secret-recorded-response";
        let entry = entry(
            1,
            ObservationKind::Effect,
            b"effect-journal",
            b"effect-request",
            secret,
            Some(record(30)?),
        )?;
        let entry_debug = format!("{entry:?}");
        assert!(!entry_debug.contains("super-secret"));
        let tape = RecordedProviderTape::new(vec![entry])?;
        let tape_debug = format!("{tape:?}");
        assert!(!tape_debug.contains("super-secret"));
        assert!(tape_debug.contains("live_calls: 0"));
        Ok(())
    }
}
