//! Deterministic effect crash reference model and stable WP12 failpoint catalog.
//!
//! This module deliberately models only durability and recovery invariants. It does not replace
//! the repository-backed engine or connector integration tests. The serializable snapshot is the
//! process-boundary handoff used by the crash harness: a child persists it at one exact boundary,
//! the parent kills the child, and a fresh model instance evaluates recovery.

use serde::{Deserialize, Serialize};
use std::fmt;

const SNAPSHOT_SCHEMA_VERSION: u8 = 1;

/// Stable release-qualification crash boundaries from the WP12 effect matrix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectCrashPoint {
    /// EFX-C01: process termination before the intent transaction begins.
    BeforeIntentTransaction,
    /// EFX-C02: process termination after staging an intent but before atomic commit.
    IntentWriteBeforeCommit,
    /// EFX-C03: process termination after the intent is durable but before policy evaluation.
    DurableIntentBeforePolicy,
    /// EFX-C04: process termination while approval persistence is uncommitted.
    DuringApprovalPersistence,
    /// EFX-C05: process termination after authorization and before attempt creation.
    AuthorizedBeforeAttempt,
    /// EFX-C06: process termination at the attempt and outbox atomic commit boundary.
    AttemptBeforeOutboxCommit,
    /// EFX-C07: process termination after a durable dispatch claim and before transport.
    DurableDispatchClaimBeforeSend,
    /// EFX-C08: connection failure with proof that no request bytes were sent.
    ConnectFailureBeforeRequestBytes,
    /// EFX-C09: process termination after a request was partially written.
    RequestPartiallyWritten,
    /// EFX-C10: a definitive remote rejection is observed.
    RemoteDefinitiveRejection,
    /// EFX-C11: the remote mutation commits but its response is lost.
    RemoteCommitResponseLost,
    /// EFX-C12: a response is received but the process dies before receipt persistence.
    ResponseReceivedBeforeReceipt,
    /// EFX-C13: a receipt is journaled but the derived projection is not published.
    ReceiptAppendedBeforeProjection,
    /// EFX-C14: a duplicate or reordered response reaches the receipt boundary.
    DuplicateOrReorderedResponse,
    /// EFX-C15: reconciliation is unavailable while the outcome is unknown.
    ReconcilerUnavailable,
    /// EFX-C16: a weakly consistent lookup reports absence inside its certainty window.
    WeakLookupSaysAbsent,
    /// EFX-C17: verification evidence contradicts an otherwise successful receipt.
    VerificationContradictsReceipt,
    /// EFX-C18: approval expires after claim eligibility but before transport.
    ApprovalExpiresBeforeSend,
    /// EFX-C19: current policy or capability is revoked before transport.
    AuthorityRevokedBeforeSend,
    /// EFX-C20: one idempotency key is presented for different normalized semantics.
    SameKeyDifferentIntent,
    /// EFX-C21: a separate compensation effect commits remotely and loses its response.
    CompensationCommitResponseLost,
    /// EFX-C22: receipt persistence fails because the durable store is full.
    DiskFullDuringReceipt,
    /// EFX-C23: restart detects a broken event hash chain.
    HashChainCorruptionAtRestart,
    /// EFX-C24: two workers concurrently contend for one outbox item.
    TwoWorkersClaimOneOutboxItem,
}

impl EffectCrashPoint {
    /// Every stable crash point in normative matrix order.
    pub const ALL: [Self; 24] = [
        Self::BeforeIntentTransaction,
        Self::IntentWriteBeforeCommit,
        Self::DurableIntentBeforePolicy,
        Self::DuringApprovalPersistence,
        Self::AuthorizedBeforeAttempt,
        Self::AttemptBeforeOutboxCommit,
        Self::DurableDispatchClaimBeforeSend,
        Self::ConnectFailureBeforeRequestBytes,
        Self::RequestPartiallyWritten,
        Self::RemoteDefinitiveRejection,
        Self::RemoteCommitResponseLost,
        Self::ResponseReceivedBeforeReceipt,
        Self::ReceiptAppendedBeforeProjection,
        Self::DuplicateOrReorderedResponse,
        Self::ReconcilerUnavailable,
        Self::WeakLookupSaysAbsent,
        Self::VerificationContradictsReceipt,
        Self::ApprovalExpiresBeforeSend,
        Self::AuthorityRevokedBeforeSend,
        Self::SameKeyDifferentIntent,
        Self::CompensationCommitResponseLost,
        Self::DiskFullDuringReceipt,
        Self::HashChainCorruptionAtRestart,
        Self::TwoWorkersClaimOneOutboxItem,
    ];

    /// Returns the normative `EFX-CNN` identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::BeforeIntentTransaction => "EFX-C01",
            Self::IntentWriteBeforeCommit => "EFX-C02",
            Self::DurableIntentBeforePolicy => "EFX-C03",
            Self::DuringApprovalPersistence => "EFX-C04",
            Self::AuthorizedBeforeAttempt => "EFX-C05",
            Self::AttemptBeforeOutboxCommit => "EFX-C06",
            Self::DurableDispatchClaimBeforeSend => "EFX-C07",
            Self::ConnectFailureBeforeRequestBytes => "EFX-C08",
            Self::RequestPartiallyWritten => "EFX-C09",
            Self::RemoteDefinitiveRejection => "EFX-C10",
            Self::RemoteCommitResponseLost => "EFX-C11",
            Self::ResponseReceivedBeforeReceipt => "EFX-C12",
            Self::ReceiptAppendedBeforeProjection => "EFX-C13",
            Self::DuplicateOrReorderedResponse => "EFX-C14",
            Self::ReconcilerUnavailable => "EFX-C15",
            Self::WeakLookupSaysAbsent => "EFX-C16",
            Self::VerificationContradictsReceipt => "EFX-C17",
            Self::ApprovalExpiresBeforeSend => "EFX-C18",
            Self::AuthorityRevokedBeforeSend => "EFX-C19",
            Self::SameKeyDifferentIntent => "EFX-C20",
            Self::CompensationCommitResponseLost => "EFX-C21",
            Self::DiskFullDuringReceipt => "EFX-C22",
            Self::HashChainCorruptionAtRestart => "EFX-C23",
            Self::TwoWorkersClaimOneOutboxItem => "EFX-C24",
        }
    }

    /// Returns the stable instrumentation checkpoint name used by process harnesses.
    #[must_use]
    pub const fn checkpoint(self) -> &'static str {
        match self {
            Self::BeforeIntentTransaction => "effect.v1.prepare.before_tx",
            Self::IntentWriteBeforeCommit => "effect.v1.prepare.intent_staged",
            Self::DurableIntentBeforePolicy => "effect.v1.prepare.intent_committed",
            Self::DuringApprovalPersistence => "effect.v1.approval.staged",
            Self::AuthorizedBeforeAttempt => "effect.v1.authorize.committed",
            Self::AttemptBeforeOutboxCommit => "effect.v1.dispatch.attempt_outbox_staged",
            Self::DurableDispatchClaimBeforeSend => "effect.v1.dispatch.claim_committed",
            Self::ConnectFailureBeforeRequestBytes => "effect.v1.dispatch.before_transport",
            Self::RequestPartiallyWritten => "effect.v1.dispatch.first_request_byte",
            Self::RemoteDefinitiveRejection => "effect.v1.dispatch.rejection_received",
            Self::RemoteCommitResponseLost => "effect.v1.dispatch.response_lost",
            Self::ResponseReceivedBeforeReceipt => "effect.v1.dispatch.observation_received",
            Self::ReceiptAppendedBeforeProjection => "effect.v1.receipt.committed",
            Self::DuplicateOrReorderedResponse => "effect.v1.receipt.duplicate_received",
            Self::ReconcilerUnavailable => "effect.v1.reconcile.before_call",
            Self::WeakLookupSaysAbsent => "effect.v1.reconcile.observation_received",
            Self::VerificationContradictsReceipt => "effect.v1.verify.conflict_committed",
            Self::ApprovalExpiresBeforeSend => "effect.v1.dispatch.current_checks_complete",
            Self::AuthorityRevokedBeforeSend => "effect.v1.dispatch.denial_recorded",
            Self::SameKeyDifferentIntent => "effect.v1.key.collision_returned",
            Self::CompensationCommitResponseLost => "effect.v1.compensation.response_lost",
            Self::DiskFullDuringReceipt => "effect.v1.receipt.before_tx",
            Self::HashChainCorruptionAtRestart => "effect.v1.startup.chain_verified",
            Self::TwoWorkersClaimOneOutboxItem => "effect.v1.dispatch.fence_rechecked",
        }
    }

    /// Parses one normative identifier without accepting aliases.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|point| point.id() == id)
    }

    /// Reports whether request bytes at this boundary can correspond to a remote mutation.
    #[must_use]
    pub const fn can_involve_remote_commit(self) -> bool {
        matches!(
            self,
            Self::RequestPartiallyWritten
                | Self::RemoteCommitResponseLost
                | Self::ResponseReceivedBeforeReceipt
                | Self::ReceiptAppendedBeforeProjection
                | Self::DuplicateOrReorderedResponse
                | Self::ReconcilerUnavailable
                | Self::WeakLookupSaysAbsent
                | Self::VerificationContradictsReceipt
                | Self::CompensationCommitResponseLost
                | Self::DiskFullDuringReceipt
                | Self::TwoWorkersClaimOneOutboxItem
        )
    }
}

/// Minimal observable projection used by the crash reference model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelEffectState {
    /// No durable intent exists.
    Absent,
    /// The durable intent has not yet been authorized.
    Prepared,
    /// The effect is waiting for approval.
    PendingApproval,
    /// Current durable records authorize a future dispatch claim.
    Authorized,
    /// Proven non-execution permits a new fenced attempt under the retry policy.
    AuthorizedForRetry,
    /// A durable fenced attempt exists.
    Dispatching,
    /// Success is definitive.
    Succeeded,
    /// Failure is definitive.
    Failed,
    /// The remote outcome remains explicit and ambiguous.
    Unknown,
    /// A separately authorized compensation effect is in flight.
    Compensating,
    /// The separate compensation effect was confirmed.
    Compensated,
    /// A pre-send deadline expired.
    Expired,
    /// Integrity failure prevents dispatch and replay.
    Quarantined,
}

/// Explicit ambiguity retained after restart.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAmbiguity {
    /// No unresolved ambiguity is present.
    None,
    /// Request bytes may have caused a remote mutation.
    RequestMayHaveCommitted,
    /// A response was observed but not durably journaled.
    ResponseNotDurable,
    /// Reconciliation cannot currently be reached.
    ReconcilerUnavailable,
    /// Apparent absence is not authoritative until the certainty window closes.
    CertaintyWindowOpen,
    /// Verification evidence conflicts with receipt evidence.
    ContradictoryVerification,
    /// Receipt durability failed after a possible remote commit.
    ReceiptNotDurable,
    /// The separate compensation effect may have committed.
    CompensationMayHaveCommitted,
}

/// Recovery decision produced by the deterministic reference model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDisposition {
    /// No recovery work is needed.
    None,
    /// Resume policy evaluation over the durable prepared intent.
    ResumeAuthorization,
    /// Resume approval persistence without accepting a partial approval.
    PersistApproval,
    /// Claim a first durable attempt.
    ClaimDispatch,
    /// Resume the already durable fenced dispatch item.
    ResumeFencedDispatch,
    /// Retry is allowed only because non-execution was proven.
    RetryWithNonExecutionProof,
    /// Reconcile remote state without dispatching again.
    ReconcileWithoutDispatch,
    /// Rebuild the projection from the authoritative journal.
    RebuildProjection,
    /// Ignore a duplicate receipt and retain the first accepted transition.
    IgnoreDuplicateReceipt,
    /// Retain visible unknown state and bounded backoff.
    BackoffWithoutDispatch,
    /// Hold unknown state until an external certainty window closes.
    HoldThroughCertaintyWindow,
    /// Escalate contradictory evidence for explicit resolution.
    EscalateConflict,
    /// Require a fresh approval before any new attempt.
    RequireFreshApproval,
    /// Require restored current policy and capability before any send.
    RequireCurrentAuthority,
    /// Reject an idempotency collision before connector invocation.
    RejectCollision,
    /// Reconcile the separate compensation effect.
    ReconcileCompensation,
    /// Alert an operator and reconcile after receipt persistence failure.
    AlertAndReconcile,
    /// Quarantine the corrupt journal and deny dispatch.
    Quarantine,
    /// Reject the losing worker's stale fencing token.
    FenceLosingWorker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ModelJournalState {
    Absent,
    Valid,
    ReceiptAheadOfProjection,
    Corrupt,
}

/// Serializable durable state captured at one exact injected crash boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultSnapshot {
    schema_version: u8,
    point: EffectCrashPoint,
    seed: u64,
    intent_durable: bool,
    approval_durable: bool,
    authorization_durable: bool,
    attempt_durable: bool,
    outbox_durable: bool,
    state: ModelEffectState,
    journal: ModelJournalState,
    connector_calls: u8,
    remote_commit_count: u8,
    possible_remote_commit: bool,
    accepted_receipts: u8,
    ambiguity: ModelAmbiguity,
    dispatch_denied: bool,
    active_fences: u8,
    claim_contenders: u8,
    blind_redispatches: u8,
    compensation_effect_separate: bool,
}

impl FaultSnapshot {
    /// Returns the injected boundary.
    #[must_use]
    pub const fn point(&self) -> EffectCrashPoint {
        self.point
    }

    /// Returns the deterministic scenario seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the state visible at the instant of process termination.
    #[must_use]
    pub const fn state(&self) -> ModelEffectState {
        self.state
    }

    /// Returns whether intent durability is visible at the crash boundary.
    #[must_use]
    pub const fn intent_is_durable(&self) -> bool {
        self.intent_durable
    }

    /// Returns connector calls visible before the injected process termination.
    #[must_use]
    pub const fn connector_calls(&self) -> u8 {
        self.connector_calls
    }

    /// Serializes the stable checkpoint passed across a real process boundary.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decodes a stable process checkpoint.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Applies deterministic restart recovery without performing a blind remote retry.
    #[must_use]
    pub fn recover(mut self) -> FaultRun {
        let disposition = match self.point {
            EffectCrashPoint::BeforeIntentTransaction
            | EffectCrashPoint::IntentWriteBeforeCommit => RecoveryDisposition::None,
            EffectCrashPoint::DurableIntentBeforePolicy => RecoveryDisposition::ResumeAuthorization,
            EffectCrashPoint::DuringApprovalPersistence => RecoveryDisposition::PersistApproval,
            EffectCrashPoint::AuthorizedBeforeAttempt => RecoveryDisposition::ClaimDispatch,
            EffectCrashPoint::AttemptBeforeOutboxCommit => {
                if self.attempt_durable {
                    RecoveryDisposition::ResumeFencedDispatch
                } else {
                    RecoveryDisposition::ClaimDispatch
                }
            }
            EffectCrashPoint::DurableDispatchClaimBeforeSend => {
                RecoveryDisposition::ResumeFencedDispatch
            }
            EffectCrashPoint::ConnectFailureBeforeRequestBytes => {
                self.state = ModelEffectState::AuthorizedForRetry;
                RecoveryDisposition::RetryWithNonExecutionProof
            }
            EffectCrashPoint::RequestPartiallyWritten => {
                self.state = ModelEffectState::Unknown;
                self.ambiguity = ModelAmbiguity::RequestMayHaveCommitted;
                RecoveryDisposition::ReconcileWithoutDispatch
            }
            EffectCrashPoint::RemoteDefinitiveRejection => RecoveryDisposition::None,
            EffectCrashPoint::RemoteCommitResponseLost
            | EffectCrashPoint::ResponseReceivedBeforeReceipt => {
                self.state = ModelEffectState::Succeeded;
                self.ambiguity = ModelAmbiguity::None;
                self.accepted_receipts = 1;
                RecoveryDisposition::ReconcileWithoutDispatch
            }
            EffectCrashPoint::ReceiptAppendedBeforeProjection => {
                self.state = ModelEffectState::Succeeded;
                self.journal = ModelJournalState::Valid;
                self.ambiguity = ModelAmbiguity::None;
                RecoveryDisposition::RebuildProjection
            }
            EffectCrashPoint::DuplicateOrReorderedResponse => {
                RecoveryDisposition::IgnoreDuplicateReceipt
            }
            EffectCrashPoint::ReconcilerUnavailable => {
                self.state = ModelEffectState::Unknown;
                self.ambiguity = ModelAmbiguity::ReconcilerUnavailable;
                RecoveryDisposition::BackoffWithoutDispatch
            }
            EffectCrashPoint::WeakLookupSaysAbsent => {
                self.state = ModelEffectState::Unknown;
                self.ambiguity = ModelAmbiguity::CertaintyWindowOpen;
                RecoveryDisposition::HoldThroughCertaintyWindow
            }
            EffectCrashPoint::VerificationContradictsReceipt => {
                self.state = ModelEffectState::Unknown;
                self.ambiguity = ModelAmbiguity::ContradictoryVerification;
                RecoveryDisposition::EscalateConflict
            }
            EffectCrashPoint::ApprovalExpiresBeforeSend => {
                self.state = ModelEffectState::Expired;
                self.dispatch_denied = true;
                RecoveryDisposition::RequireFreshApproval
            }
            EffectCrashPoint::AuthorityRevokedBeforeSend => {
                self.dispatch_denied = true;
                RecoveryDisposition::RequireCurrentAuthority
            }
            EffectCrashPoint::SameKeyDifferentIntent => RecoveryDisposition::RejectCollision,
            EffectCrashPoint::CompensationCommitResponseLost => {
                self.state = ModelEffectState::Compensated;
                self.ambiguity = ModelAmbiguity::None;
                self.accepted_receipts = 1;
                RecoveryDisposition::ReconcileCompensation
            }
            EffectCrashPoint::DiskFullDuringReceipt => {
                self.state = ModelEffectState::Unknown;
                self.ambiguity = ModelAmbiguity::ReceiptNotDurable;
                RecoveryDisposition::AlertAndReconcile
            }
            EffectCrashPoint::HashChainCorruptionAtRestart => {
                self.state = ModelEffectState::Quarantined;
                RecoveryDisposition::Quarantine
            }
            EffectCrashPoint::TwoWorkersClaimOneOutboxItem => {
                self.state = ModelEffectState::Succeeded;
                self.ambiguity = ModelAmbiguity::None;
                RecoveryDisposition::FenceLosingWorker
            }
        };
        FaultRun {
            snapshot: self,
            disposition,
        }
    }
}

/// Stateless deterministic crash reference model.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EffectFaultModel;

impl EffectFaultModel {
    /// Captures the durable state exposed by one injected crash boundary.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn inject(point: EffectCrashPoint, seed: u64) -> FaultSnapshot {
        let mut snapshot = FaultSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            point,
            seed,
            intent_durable: true,
            approval_durable: true,
            authorization_durable: true,
            attempt_durable: true,
            outbox_durable: true,
            state: ModelEffectState::Dispatching,
            journal: ModelJournalState::Valid,
            connector_calls: 0,
            remote_commit_count: 0,
            possible_remote_commit: point.can_involve_remote_commit(),
            accepted_receipts: 0,
            ambiguity: ModelAmbiguity::None,
            dispatch_denied: false,
            active_fences: 1,
            claim_contenders: 1,
            blind_redispatches: 0,
            compensation_effect_separate: false,
        };
        match point {
            EffectCrashPoint::BeforeIntentTransaction
            | EffectCrashPoint::IntentWriteBeforeCommit => {
                snapshot.intent_durable = false;
                snapshot.approval_durable = false;
                snapshot.authorization_durable = false;
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Absent;
                snapshot.journal = ModelJournalState::Absent;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::DurableIntentBeforePolicy => {
                snapshot.approval_durable = false;
                snapshot.authorization_durable = false;
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Prepared;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::DuringApprovalPersistence => {
                snapshot.approval_durable = false;
                snapshot.authorization_durable = false;
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::PendingApproval;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::AuthorizedBeforeAttempt => {
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Authorized;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::AttemptBeforeOutboxCommit => {
                let transaction_committed = seed & 1 == 1;
                snapshot.attempt_durable = transaction_committed;
                snapshot.outbox_durable = transaction_committed;
                snapshot.state = if transaction_committed {
                    ModelEffectState::Dispatching
                } else {
                    ModelEffectState::Authorized
                };
                snapshot.active_fences = u8::from(transaction_committed);
                snapshot.claim_contenders = u8::from(transaction_committed);
            }
            EffectCrashPoint::DurableDispatchClaimBeforeSend => {}
            EffectCrashPoint::ConnectFailureBeforeRequestBytes => {
                snapshot.connector_calls = 1;
            }
            EffectCrashPoint::RequestPartiallyWritten => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = u8::from(seed & 1 == 1);
                snapshot.ambiguity = ModelAmbiguity::RequestMayHaveCommitted;
            }
            EffectCrashPoint::RemoteDefinitiveRejection => {
                snapshot.connector_calls = 1;
                snapshot.state = ModelEffectState::Failed;
                snapshot.accepted_receipts = 1;
            }
            EffectCrashPoint::RemoteCommitResponseLost => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.ambiguity = ModelAmbiguity::RequestMayHaveCommitted;
            }
            EffectCrashPoint::ResponseReceivedBeforeReceipt => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.ambiguity = ModelAmbiguity::ResponseNotDurable;
            }
            EffectCrashPoint::ReceiptAppendedBeforeProjection => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.accepted_receipts = 1;
                snapshot.journal = ModelJournalState::ReceiptAheadOfProjection;
            }
            EffectCrashPoint::DuplicateOrReorderedResponse => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.accepted_receipts = 1;
                snapshot.state = ModelEffectState::Succeeded;
            }
            EffectCrashPoint::ReconcilerUnavailable => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = u8::from(seed & 1 == 1);
                snapshot.state = ModelEffectState::Unknown;
                snapshot.accepted_receipts = 1;
                snapshot.ambiguity = ModelAmbiguity::ReconcilerUnavailable;
            }
            EffectCrashPoint::WeakLookupSaysAbsent => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = u8::from(seed & 1 == 1);
                snapshot.state = ModelEffectState::Unknown;
                snapshot.accepted_receipts = 1;
                snapshot.ambiguity = ModelAmbiguity::CertaintyWindowOpen;
            }
            EffectCrashPoint::VerificationContradictsReceipt => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.state = ModelEffectState::Unknown;
                snapshot.accepted_receipts = 1;
                snapshot.ambiguity = ModelAmbiguity::ContradictoryVerification;
            }
            EffectCrashPoint::ApprovalExpiresBeforeSend => {
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Authorized;
                snapshot.connector_calls = 0;
                snapshot.remote_commit_count = 0;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::AuthorityRevokedBeforeSend => {
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Authorized;
                snapshot.connector_calls = 0;
                snapshot.remote_commit_count = 0;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::SameKeyDifferentIntent => {
                snapshot.approval_durable = false;
                snapshot.authorization_durable = false;
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Prepared;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::CompensationCommitResponseLost => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.state = ModelEffectState::Compensating;
                snapshot.ambiguity = ModelAmbiguity::CompensationMayHaveCommitted;
                snapshot.compensation_effect_separate = true;
            }
            EffectCrashPoint::DiskFullDuringReceipt => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.ambiguity = ModelAmbiguity::ReceiptNotDurable;
            }
            EffectCrashPoint::HashChainCorruptionAtRestart => {
                snapshot.approval_durable = false;
                snapshot.authorization_durable = false;
                snapshot.attempt_durable = false;
                snapshot.outbox_durable = false;
                snapshot.state = ModelEffectState::Prepared;
                snapshot.journal = ModelJournalState::Corrupt;
                snapshot.active_fences = 0;
                snapshot.claim_contenders = 0;
            }
            EffectCrashPoint::TwoWorkersClaimOneOutboxItem => {
                snapshot.connector_calls = 1;
                snapshot.remote_commit_count = 1;
                snapshot.accepted_receipts = 1;
                snapshot.active_fences = 1;
                snapshot.claim_contenders = 2;
            }
        }
        snapshot
    }
}

/// Recovered result plus its required operator or dispatcher action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultRun {
    snapshot: FaultSnapshot,
    disposition: RecoveryDisposition,
}

impl FaultRun {
    /// Returns the injected crash point.
    #[must_use]
    pub const fn point(&self) -> EffectCrashPoint {
        self.snapshot.point
    }

    /// Returns the state after restart recovery.
    #[must_use]
    pub const fn state(&self) -> ModelEffectState {
        self.snapshot.state
    }

    /// Returns the explicit recovery action.
    #[must_use]
    pub const fn disposition(&self) -> RecoveryDisposition {
        self.disposition
    }

    /// Returns explicit ambiguity after recovery.
    #[must_use]
    pub const fn ambiguity(&self) -> ModelAmbiguity {
        self.snapshot.ambiguity
    }

    /// Returns total connector dispatch calls represented by the run.
    #[must_use]
    pub const fn connector_calls(&self) -> u8 {
        self.snapshot.connector_calls
    }

    /// Returns the count of distinct committed mutations for the logical key.
    #[must_use]
    pub const fn remote_commit_count(&self) -> u8 {
        self.snapshot.remote_commit_count
    }

    /// Returns accepted durable receipts for the attempt.
    #[must_use]
    pub const fn accepted_receipts(&self) -> u8 {
        self.snapshot.accepted_receipts
    }

    /// Returns whether the original and compensation are separate logical effects.
    #[must_use]
    pub const fn compensation_is_separate(&self) -> bool {
        self.snapshot.compensation_effect_separate
    }

    /// Verifies all cross-row safety invariants and the exact row-specific recovery contract.
    pub fn verify(&self) -> Result<(), FaultInvariantViolation> {
        let snapshot = &self.snapshot;
        if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(FaultInvariantViolation::new("unsupported snapshot version"));
        }
        if snapshot.attempt_durable != snapshot.outbox_durable {
            return Err(FaultInvariantViolation::new(
                "attempt and outbox durability diverged",
            ));
        }
        if snapshot.connector_calls > 0
            && (!snapshot.authorization_durable
                || !snapshot.attempt_durable
                || !snapshot.outbox_durable)
        {
            return Err(FaultInvariantViolation::new(
                "connector call preceded durable authorization, attempt, or outbox",
            ));
        }
        if snapshot.remote_commit_count > 1 {
            return Err(FaultInvariantViolation::new(
                "duplicate remote logical mutation",
            ));
        }
        if snapshot.remote_commit_count > snapshot.connector_calls {
            return Err(FaultInvariantViolation::new(
                "remote mutation exists without a connector call",
            ));
        }
        if snapshot.accepted_receipts > 1 {
            return Err(FaultInvariantViolation::new("duplicate receipt accepted"));
        }
        if snapshot.blind_redispatches > 0 {
            return Err(FaultInvariantViolation::new("unsafe blind redispatch"));
        }
        if snapshot.active_fences > 1 {
            return Err(FaultInvariantViolation::new(
                "multiple simultaneously active fencing tokens",
            ));
        }
        if snapshot.possible_remote_commit
            && !matches!(
                snapshot.state,
                ModelEffectState::Succeeded
                    | ModelEffectState::Failed
                    | ModelEffectState::Compensated
                    | ModelEffectState::Quarantined
            )
            && snapshot.ambiguity == ModelAmbiguity::None
            && self.disposition != RecoveryDisposition::ResumeFencedDispatch
        {
            return Err(FaultInvariantViolation::new(
                "possible remote commit lacks explicit ambiguity",
            ));
        }
        self.verify_row()
    }

    fn verify_row(&self) -> Result<(), FaultInvariantViolation> {
        use EffectCrashPoint as Point;
        use ModelEffectState as State;
        use RecoveryDisposition as Recovery;

        let snapshot = &self.snapshot;
        let valid = match self.point() {
            Point::BeforeIntentTransaction | Point::IntentWriteBeforeCommit => {
                !snapshot.intent_durable
                    && snapshot.journal == ModelJournalState::Absent
                    && self.state() == State::Absent
                    && self.connector_calls() == 0
            }
            Point::DurableIntentBeforePolicy => {
                snapshot.intent_durable
                    && self.state() == State::Prepared
                    && self.disposition() == Recovery::ResumeAuthorization
                    && self.connector_calls() == 0
            }
            Point::DuringApprovalPersistence => {
                !snapshot.approval_durable
                    && self.state() == State::PendingApproval
                    && self.connector_calls() == 0
            }
            Point::AuthorizedBeforeAttempt => {
                self.state() == State::Authorized
                    && !snapshot.attempt_durable
                    && self.disposition() == Recovery::ClaimDispatch
            }
            Point::AttemptBeforeOutboxCommit => {
                snapshot.attempt_durable == snapshot.outbox_durable && self.connector_calls() == 0
            }
            Point::DurableDispatchClaimBeforeSend => {
                snapshot.attempt_durable
                    && self.state() == State::Dispatching
                    && self.disposition() == Recovery::ResumeFencedDispatch
                    && self.connector_calls() == 0
            }
            Point::ConnectFailureBeforeRequestBytes => {
                self.state() == State::AuthorizedForRetry
                    && self.disposition() == Recovery::RetryWithNonExecutionProof
                    && self.remote_commit_count() == 0
            }
            Point::RequestPartiallyWritten => {
                self.state() == State::Unknown
                    && self.ambiguity() == ModelAmbiguity::RequestMayHaveCommitted
                    && self.disposition() == Recovery::ReconcileWithoutDispatch
            }
            Point::RemoteDefinitiveRejection => {
                self.state() == State::Failed && self.accepted_receipts() == 1
            }
            Point::RemoteCommitResponseLost | Point::ResponseReceivedBeforeReceipt => {
                self.state() == State::Succeeded
                    && self.remote_commit_count() == 1
                    && self.connector_calls() == 1
                    && self.disposition() == Recovery::ReconcileWithoutDispatch
            }
            Point::ReceiptAppendedBeforeProjection => {
                self.state() == State::Succeeded
                    && snapshot.journal == ModelJournalState::Valid
                    && self.disposition() == Recovery::RebuildProjection
            }
            Point::DuplicateOrReorderedResponse => {
                self.state() == State::Succeeded
                    && self.accepted_receipts() == 1
                    && self.disposition() == Recovery::IgnoreDuplicateReceipt
            }
            Point::ReconcilerUnavailable => {
                self.state() == State::Unknown
                    && self.ambiguity() == ModelAmbiguity::ReconcilerUnavailable
                    && self.disposition() == Recovery::BackoffWithoutDispatch
            }
            Point::WeakLookupSaysAbsent => {
                self.state() == State::Unknown
                    && self.ambiguity() == ModelAmbiguity::CertaintyWindowOpen
                    && self.disposition() == Recovery::HoldThroughCertaintyWindow
            }
            Point::VerificationContradictsReceipt => {
                self.state() == State::Unknown
                    && self.ambiguity() == ModelAmbiguity::ContradictoryVerification
                    && self.disposition() == Recovery::EscalateConflict
            }
            Point::ApprovalExpiresBeforeSend => {
                self.state() == State::Expired
                    && snapshot.dispatch_denied
                    && self.connector_calls() == 0
                    && self.disposition() == Recovery::RequireFreshApproval
            }
            Point::AuthorityRevokedBeforeSend => {
                self.state() == State::Authorized
                    && snapshot.dispatch_denied
                    && self.connector_calls() == 0
                    && self.disposition() == Recovery::RequireCurrentAuthority
            }
            Point::SameKeyDifferentIntent => {
                self.connector_calls() == 0 && self.disposition() == Recovery::RejectCollision
            }
            Point::CompensationCommitResponseLost => {
                self.state() == State::Compensated
                    && self.compensation_is_separate()
                    && self.remote_commit_count() == 1
                    && self.disposition() == Recovery::ReconcileCompensation
            }
            Point::DiskFullDuringReceipt => {
                self.state() == State::Unknown
                    && self.ambiguity() == ModelAmbiguity::ReceiptNotDurable
                    && snapshot.journal == ModelJournalState::Valid
                    && self.disposition() == Recovery::AlertAndReconcile
            }
            Point::HashChainCorruptionAtRestart => {
                self.state() == State::Quarantined
                    && self.connector_calls() == 0
                    && self.disposition() == Recovery::Quarantine
            }
            Point::TwoWorkersClaimOneOutboxItem => {
                snapshot.claim_contenders == 2
                    && snapshot.active_fences == 1
                    && self.connector_calls() == 1
                    && self.remote_commit_count() == 1
                    && self.disposition() == Recovery::FenceLosingWorker
            }
        };
        if valid {
            Ok(())
        } else {
            Err(FaultInvariantViolation::new(
                "row-specific recovery contract failed",
            ))
        }
    }
}

/// Stable content-free reference-model invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultInvariantViolation {
    reason: &'static str,
}

impl FaultInvariantViolation {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns the stable, content-free invariant reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for FaultInvariantViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for FaultInvariantViolation {}

/// Aggregate metrics from a deterministic pure-model fault campaign.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultCampaignReport {
    logical_effects: u64,
    possible_remote_commit_operations: u64,
    explicit_ambiguities: u64,
    duplicate_logical_effects: u64,
    blind_redispatches: u64,
}

impl FaultCampaignReport {
    /// Returns the number of distinct modeled logical effects.
    #[must_use]
    pub const fn logical_effects(self) -> u64 {
        self.logical_effects
    }

    /// Returns operations whose request could correspond to a remote mutation.
    #[must_use]
    pub const fn possible_remote_commit_operations(self) -> u64 {
        self.possible_remote_commit_operations
    }

    /// Returns outcomes that remain visibly ambiguous after recovery.
    #[must_use]
    pub const fn explicit_ambiguities(self) -> u64 {
        self.explicit_ambiguities
    }

    /// Returns duplicate remote logical mutations observed by the model.
    #[must_use]
    pub const fn duplicate_logical_effects(self) -> u64 {
        self.duplicate_logical_effects
    }

    /// Returns retry attempts made without proof of safety.
    #[must_use]
    pub const fn blind_redispatches(self) -> u64 {
        self.blind_redispatches
    }
}

/// Runs a scalable deterministic campaign over boundaries that can involve remote commit.
///
/// This is a fast reference-model check, not a substitute for the subprocess kill matrix. The
/// caller chooses the operation count so normal CI and release qualification can use the same
/// implementation.
pub fn run_fault_campaign(
    logical_effects: u64,
    seed: u64,
) -> Result<FaultCampaignReport, FaultInvariantViolation> {
    const REMOTE_POINTS: [EffectCrashPoint; 11] = [
        EffectCrashPoint::RequestPartiallyWritten,
        EffectCrashPoint::RemoteCommitResponseLost,
        EffectCrashPoint::ResponseReceivedBeforeReceipt,
        EffectCrashPoint::ReceiptAppendedBeforeProjection,
        EffectCrashPoint::DuplicateOrReorderedResponse,
        EffectCrashPoint::ReconcilerUnavailable,
        EffectCrashPoint::WeakLookupSaysAbsent,
        EffectCrashPoint::VerificationContradictsReceipt,
        EffectCrashPoint::CompensationCommitResponseLost,
        EffectCrashPoint::DiskFullDuringReceipt,
        EffectCrashPoint::TwoWorkersClaimOneOutboxItem,
    ];

    let mut generator = seed;
    let mut possible_remote_commit_operations = 0_u64;
    let mut explicit_ambiguities = 0_u64;
    let mut duplicate_logical_effects = 0_u64;
    let mut blind_redispatches = 0_u64;
    for index in 0..logical_effects {
        generator = splitmix64(generator.wrapping_add(index));
        let point_index = usize::try_from(generator % REMOTE_POINTS.len() as u64)
            .map_err(|_error| FaultInvariantViolation::new("campaign index overflow"))?;
        let point = REMOTE_POINTS
            .get(point_index)
            .copied()
            .ok_or_else(|| FaultInvariantViolation::new("campaign point missing"))?;
        let run = EffectFaultModel::inject(point, generator).recover();
        run.verify()?;
        possible_remote_commit_operations = possible_remote_commit_operations.saturating_add(1);
        explicit_ambiguities =
            explicit_ambiguities.saturating_add(u64::from(run.ambiguity() != ModelAmbiguity::None));
        duplicate_logical_effects =
            duplicate_logical_effects.saturating_add(u64::from(run.remote_commit_count() > 1));
        blind_redispatches =
            blind_redispatches.saturating_add(u64::from(run.snapshot.blind_redispatches > 0));
    }
    Ok(FaultCampaignReport {
        logical_effects,
        possible_remote_commit_operations,
        explicit_ambiguities,
        duplicate_logical_effects,
        blind_redispatches,
    })
}

const fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
