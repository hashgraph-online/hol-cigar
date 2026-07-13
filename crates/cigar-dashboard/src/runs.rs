//! Strict dashboard-owned run identities and monotonic lifecycle state.

use crate::events::{bounded_identifier, now_rfc3339, uuid_v7, uuid_v7_is_valid};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const RUN_SCHEMA: &str = "cigar.dashboard-run.v1";
const MAX_SOURCE_REVISION_BYTES: usize = 128;

/// Stable content-free run validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunError {
    /// One field was outside the closed run schema.
    InvalidRun,
    /// The requested lifecycle edge is not in the monotonic state machine.
    InvalidTransition,
    /// A UUIDv7 or UTC timestamp could not be generated.
    IdentityUnavailable,
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRun => "dashboard run is invalid",
            Self::InvalidTransition => "dashboard run transition is invalid",
            Self::IdentityUnavailable => "dashboard run identity is unavailable",
        })
    }
}

impl std::error::Error for RunError {}

/// Closed dashboard job lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Persisted and waiting for an allowlisted supervisor permit.
    Queued,
    /// Resolving immutable executable identity and isolated roots.
    Preparing,
    /// A verified child identity is active.
    Running,
    /// Cancellation or orderly terminal collection is in progress.
    Cancelling,
    /// The operator cancelled the run.
    Cancelled,
    /// The harness and independently verified evidence passed.
    Passed,
    /// A stable harness, product, threshold, or evidence failure occurred.
    Failed,
    /// The reviewed profile exceeded its maximum duration.
    TimedOut,
    /// Recovery could not prove a live child or terminal result.
    Lost,
}

impl RunState {
    /// Returns the stable storage and wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Lost => "lost",
        }
    }

    /// Parses one exact storage value.
    pub(crate) fn from_str(value: &str) -> Result<Self, RunError> {
        match value {
            "queued" => Ok(Self::Queued),
            "preparing" => Ok(Self::Preparing),
            "running" => Ok(Self::Running),
            "cancelling" => Ok(Self::Cancelling),
            "cancelled" => Ok(Self::Cancelled),
            "passed" => Ok(Self::Passed),
            "failed" => Ok(Self::Failed),
            "timed_out" => Ok(Self::TimedOut),
            "lost" => Ok(Self::Lost),
            _ => Err(RunError::InvalidRun),
        }
    }

    /// Reports whether the state can never transition again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Passed | Self::Failed | Self::TimedOut | Self::Lost
        )
    }

    const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Preparing)
                | (Self::Preparing, Self::Running | Self::Lost)
                | (
                    Self::Running,
                    Self::Cancelling | Self::Passed | Self::Failed | Self::TimedOut | Self::Lost
                )
                | (
                    Self::Cancelling,
                    Self::Cancelled | Self::Passed | Self::Failed | Self::TimedOut | Self::Lost
                )
        )
    }
}

/// One strict content-safe dashboard run record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    schema_version: String,
    run_id: String,
    profile_id: String,
    state: RunState,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at: Option<String>,
    profile_digest: String,
    registry_digest: String,
    source_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    events: Vec<crate::SafeEvent>,
}

impl RunRecord {
    /// Creates a persisted queued record bound to immutable profile and source digests.
    pub fn queued(
        profile_id: &str,
        profile_digest: &str,
        registry_digest: &str,
        source_revision: &str,
    ) -> Result<Self, RunError> {
        let record = Self {
            schema_version: RUN_SCHEMA.to_owned(),
            run_id: uuid_v7().map_err(|_error| RunError::IdentityUnavailable)?,
            profile_id: profile_id.to_owned(),
            state: RunState::Queued,
            created_at: now_rfc3339().map_err(|_error| RunError::IdentityUnavailable)?,
            started_at: None,
            finished_at: None,
            profile_digest: profile_digest.to_owned(),
            registry_digest: registry_digest.to_owned(),
            source_revision: source_revision.to_owned(),
            executable_digest: None,
            receipt_id: None,
            failure_code: None,
            events: Vec::new(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the opaque UUIDv7 identity.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the reviewed profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the current monotonic state.
    #[must_use]
    pub const fn state(&self) -> RunState {
        self.state
    }

    pub(crate) fn created_at(&self) -> &str {
        &self.created_at
    }

    pub(crate) fn started_at(&self) -> Option<&str> {
        self.started_at.as_deref()
    }

    pub(crate) fn finished_at(&self) -> Option<&str> {
        self.finished_at.as_deref()
    }

    pub(crate) fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    pub(crate) fn registry_digest(&self) -> &str {
        &self.registry_digest
    }

    pub(crate) fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub(crate) fn executable_digest(&self) -> Option<&str> {
        self.executable_digest.as_deref()
    }

    pub(crate) fn receipt_id(&self) -> Option<&str> {
        self.receipt_id.as_deref()
    }

    pub(crate) fn failure_code(&self) -> Option<&str> {
        self.failure_code.as_deref()
    }

    pub(crate) fn attach_events(&mut self, events: Vec<crate::SafeEvent>) {
        self.events = events;
    }

    /// Applies one legal lifecycle edge and revalidates the complete record.
    pub fn transition(
        &mut self,
        next: RunState,
        executable_digest: Option<&str>,
        receipt_id: Option<&str>,
        failure_code: Option<&str>,
    ) -> Result<(), RunError> {
        let observed_at = now_rfc3339().map_err(|_error| RunError::IdentityUnavailable)?;
        self.transition_at(
            next,
            executable_digest,
            receipt_id,
            failure_code,
            &observed_at,
        )
    }

    pub(crate) fn transition_at(
        &mut self,
        next: RunState,
        executable_digest: Option<&str>,
        receipt_id: Option<&str>,
        failure_code: Option<&str>,
        observed_at: &str,
    ) -> Result<(), RunError> {
        let mut candidate = self.clone();
        if !candidate.state.permits(next) || timestamp(observed_at).is_none() {
            return Err(RunError::InvalidTransition);
        }
        if candidate.state == RunState::Queued {
            let digest = executable_digest.ok_or(RunError::InvalidTransition)?;
            if !sha256(digest) {
                return Err(RunError::InvalidTransition);
            }
            candidate.executable_digest = Some(digest.to_owned());
            candidate.started_at = Some(observed_at.to_owned());
        } else if executable_digest.is_some() {
            return Err(RunError::InvalidTransition);
        }
        if next.is_terminal() {
            candidate.finished_at = Some(observed_at.to_owned());
            candidate.receipt_id = receipt_id.map(str::to_owned);
            candidate.failure_code = failure_code.map(str::to_owned);
        } else if receipt_id.is_some() || failure_code.is_some() {
            return Err(RunError::InvalidTransition);
        }
        candidate.state = next;
        candidate
            .validate()
            .map_err(|_error| RunError::InvalidTransition)?;
        *self = candidate;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_storage(
        run_id: String,
        profile_id: String,
        state: String,
        created_at: String,
        started_at: Option<String>,
        finished_at: Option<String>,
        profile_digest: String,
        registry_digest: String,
        source_revision: String,
        executable_digest: Option<String>,
        receipt_id: Option<String>,
        failure_code: Option<String>,
    ) -> Result<Self, RunError> {
        let record = Self {
            schema_version: RUN_SCHEMA.to_owned(),
            run_id,
            profile_id,
            state: RunState::from_str(&state)?,
            created_at,
            started_at,
            finished_at,
            profile_digest,
            registry_digest,
            source_revision,
            executable_digest,
            receipt_id,
            failure_code,
            events: Vec::new(),
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn validate(&self) -> Result<(), RunError> {
        let created_at = timestamp(&self.created_at).ok_or(RunError::InvalidRun)?;
        let started_at = optional_timestamp(self.started_at.as_deref())?;
        let finished_at = optional_timestamp(self.finished_at.as_deref())?;
        let timestamps_valid = started_at.is_none_or(|value| value >= created_at)
            && finished_at.is_none_or(|value| value >= started_at.unwrap_or(created_at));
        let state_shape = match self.state {
            RunState::Queued => started_at.is_none() && finished_at.is_none(),
            RunState::Preparing | RunState::Running | RunState::Cancelling => {
                started_at.is_some() && finished_at.is_none()
            }
            RunState::Cancelled
            | RunState::Passed
            | RunState::Failed
            | RunState::TimedOut
            | RunState::Lost => started_at.is_some() && finished_at.is_some(),
        };
        let failure_shape = match self.state {
            RunState::Failed | RunState::TimedOut | RunState::Lost => self.failure_code.is_some(),
            _ => self.failure_code.is_none(),
        };
        if self.schema_version != RUN_SCHEMA
            || !uuid_v7_is_valid(&self.run_id)
            || !bounded_identifier(&self.profile_id)
            || !sha256(&self.profile_digest)
            || !sha256(&self.registry_digest)
            || !source_revision(&self.source_revision)
            || self
                .executable_digest
                .as_deref()
                .is_some_and(|value| !sha256(value))
            || (self.state != RunState::Queued && self.executable_digest.is_none())
            || self
                .receipt_id
                .as_deref()
                .is_some_and(|value| !bounded_identifier(value))
            || self
                .failure_code
                .as_deref()
                .is_some_and(|value| !bounded_identifier(value))
            || !timestamps_valid
            || !state_shape
            || !failure_shape
            || self.events.len() > 10_000
            || self
                .events
                .iter()
                .any(|event| event.run_id() != Some(self.run_id.as_str()))
        {
            return Err(RunError::InvalidRun);
        }
        Ok(())
    }
}

fn optional_timestamp(value: Option<&str>) -> Result<Option<OffsetDateTime>, RunError> {
    value
        .map(|candidate| timestamp(candidate).ok_or(RunError::InvalidRun))
        .transpose()
}

fn timestamp(value: &str) -> Option<OffsetDateTime> {
    if value.is_empty() || value.len() > 64 {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn source_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SOURCE_REVISION_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::{RunError, RunRecord, RunState};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn legal_state_machine_reaches_passed() -> Result<(), Box<dyn std::error::Error>> {
        let mut run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        run.transition(RunState::Preparing, Some(DIGEST), None, None)?;
        run.transition(RunState::Running, None, None, None)?;
        run.transition(RunState::Passed, None, Some("receipt-1"), None)?;
        assert_eq!(run.state(), RunState::Passed);
        Ok(())
    }

    #[test]
    fn illegal_edges_and_unclassified_failures_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut run = RunRecord::queued("soak-smoke", DIGEST, DIGEST, "revision-1")?;
        assert_eq!(
            run.transition(RunState::Running, Some(DIGEST), None, None),
            Err(RunError::InvalidTransition)
        );
        run.transition(RunState::Preparing, Some(DIGEST), None, None)?;
        run.transition(RunState::Running, None, None, None)?;
        assert_eq!(
            run.transition(RunState::Failed, None, None, None),
            Err(RunError::InvalidTransition)
        );
        Ok(())
    }
}
