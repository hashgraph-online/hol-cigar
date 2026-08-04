//! Durable effect projection and authorization contracts.

use cigar_protocol::{
    Capability, CompensationLink, ContentDigest, EffectApproval, EffectAttempt, EffectIntent,
    EffectJournalEvent, EffectReceipt, EffectState, ReconciliationReport, RecordId, UtcTimestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Stable content-free effect-kernel failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectErrorCode {
    /// A protocol record, connector descriptor, or request is malformed.
    InvalidInput,
    /// The logical effect does not exist in the caller's tenant.
    NotFound,
    /// Current policy, capability, approval, freshness, or actor denies the operation.
    Unauthorized,
    /// Expected effect or repository revision is stale.
    RevisionConflict,
    /// Idempotency scope/key was already bound to different normalized semantics.
    IdempotencyCollision,
    /// Requested transition is absent from the closed state machine.
    InvalidTransition,
    /// Automatic retry cannot be proven safe.
    UnsafeRetry,
    /// Journal or projection integrity verification failed and the effect is quarantined.
    CorruptJournal,
    /// A deadline or intent/approval expiry elapsed.
    Expired,
    /// The operation was cancelled before a remote call.
    Cancelled,
    /// A storage, connector, or serialization boundary is unavailable.
    Unavailable,
    /// A bounded counter, collection, or size limit was exceeded.
    LimitExceeded,
}

/// Content-free effect error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EffectError {
    code: EffectErrorCode,
}

impl EffectError {
    /// Creates a stable failure.
    #[must_use]
    pub const fn new(code: EffectErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable category.
    #[must_use]
    pub const fn code(self) -> EffectErrorCode {
        self.code
    }
}

impl fmt::Debug for EffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for EffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "effect operation failed: {:?}", self.code)
    }
}

impl std::error::Error for EffectError {}

const EFFECT_RECORD_SIGNATURE_BYTES: usize = 64;

/// Opaque historical signature material retained with a durable effect record.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecordSignedProof {
    signed_at_unix_nanos: i128,
    signature: Vec<u8>,
}

impl EffectRecordSignedProof {
    /// Returns the exact trusted signing time used by the external key provider.
    #[must_use]
    pub const fn signed_at_unix_nanos(&self) -> i128 {
        self.signed_at_unix_nanos
    }

    /// Returns the opaque Ed25519 signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn validate(&self) -> Result<(), EffectError> {
        if self.signature.len() != EFFECT_RECORD_SIGNATURE_BYTES {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        Ok(())
    }
}

impl fmt::Debug for EffectRecordSignedProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectRecordSignedProof")
            .field("signed_at_unix_nanos", &self.signed_at_unix_nanos)
            .field("signature_bytes", &self.signature.len())
            .finish()
    }
}

/// Domain-separated keyed authenticator stored with one canonical durable effect projection.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecordSeal {
    key_id: String,
    authenticator: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_proof: Option<EffectRecordSignedProof>,
}

impl EffectRecordSeal {
    /// Creates a seal issued by one bounded historical signing-key identity.
    pub fn new(
        key_id: impl Into<String>,
        authenticator: ContentDigest,
    ) -> Result<Self, EffectError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > 128
            || key_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        Ok(Self {
            key_id,
            authenticator,
            signed_proof: None,
        })
    }

    /// Creates a seal retaining the exact proof needed for historical Ed25519 verification.
    ///
    /// The authenticator must be a deterministic digest of the signed canonical record or of the
    /// signature envelope, and the authenticator implementation must verify that binding before
    /// advancing an external rollback checkpoint.
    pub fn new_signed(
        key_id: impl Into<String>,
        authenticator: ContentDigest,
        signed_at_unix_nanos: i128,
        signature: [u8; EFFECT_RECORD_SIGNATURE_BYTES],
    ) -> Result<Self, EffectError> {
        let mut seal = Self::new(key_id, authenticator)?;
        seal.signed_proof = Some(EffectRecordSignedProof {
            signed_at_unix_nanos,
            signature: signature.to_vec(),
        });
        Ok(seal)
    }

    /// Returns the exact signing-key epoch identity.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the keyed authenticator without exposing any signing material.
    #[must_use]
    pub const fn authenticator(&self) -> &ContentDigest {
        &self.authenticator
    }

    /// Returns the optional external-signature proof; process-HMAC seals have none.
    #[must_use]
    pub const fn signed_proof(&self) -> Option<&EffectRecordSignedProof> {
        self.signed_proof.as_ref()
    }

    /// Validates all bounded, persisted seal fields before an authenticator sees them.
    pub fn validate(&self) -> Result<(), EffectError> {
        if self.key_id.is_empty()
            || self.key_id.len() > 128
            || self.key_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        if let Some(proof) = &self.signed_proof {
            proof.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for EffectRecordSeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectRecordSeal")
            .field("key_id", &self.key_id)
            .field("authenticator", &self.authenticator)
            .field("has_signed_proof", &self.signed_proof.is_some())
            .finish()
    }
}

/// Tenant-key and external-checkpoint boundary for effect history authenticity.
///
/// Production implementations must keep signing keys and latest accepted checkpoints outside the
/// mutable effect repository, retain authorized historical verification keys, and reject revoked
/// key epochs. `observe_latest` is called only for the latest projection, never for an intentional
/// historical-revision read.
pub trait EffectRecordAuthenticator: Send + Sync {
    /// Seals exact canonical record bytes under the current authorized tenant key.
    fn seal(
        &self,
        tenant_id: &RecordId,
        canonical_record: &[u8],
    ) -> Result<EffectRecordSeal, EffectError>;

    /// Verifies exact canonical bytes under the seal's current or authorized historical key.
    fn verify(
        &self,
        tenant_id: &RecordId,
        canonical_record: &[u8],
        seal: &EffectRecordSeal,
    ) -> Result<(), EffectError>;

    /// Verifies the latest persisted record and its external rollback checkpoint without
    /// advancing or repairing that checkpoint. Compatibility authenticators may delegate to
    /// [`Self::verify`]; production implementations should additionally require an exact current
    /// checkpoint match.
    fn verify_latest_read_only(
        &self,
        tenant_id: &RecordId,
        _effect_id: &RecordId,
        _intent_digest: &ContentDigest,
        _effect_version: u64,
        canonical_record: &[u8],
        seal: &EffectRecordSeal,
    ) -> Result<(), EffectError> {
        self.verify(tenant_id, canonical_record, seal)
    }

    /// Checks and advances the latest externally anchored chain root without permitting rollback.
    ///
    /// The checkpoint identity is `(tenant_id, effect_id)`. Implementations must permanently bind
    /// its first observed `intent_digest`, reject a different intent for the same identity, reject
    /// lower versions, and reject a different authenticator at an already observed version.
    ///
    /// A lower version should be reported as [`EffectErrorCode::RevisionConflict`] so a caller
    /// performing a latest read can retry the complete repository transaction. Intent or
    /// authenticator substitution must remain an integrity failure.
    fn observe_latest(
        &self,
        tenant_id: &RecordId,
        effect_id: &RecordId,
        intent_digest: &ContentDigest,
        effect_version: u64,
        authenticator: &ContentDigest,
    ) -> Result<(), EffectError>;
}

/// Durable semantic state of one dispatch outbox item.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutboxState {
    /// Attempt and wakeup are committed but no worker owns the fence yet.
    Pending,
    /// One worker owns the current fencing token.
    Claimed,
    /// A receipt or explicit unknown transition consumed the item.
    Completed,
}

/// Durable semantic outbox entry bound to one attempt and fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOutboxEntry {
    /// Wakeup message identity.
    pub message_id: RecordId,
    /// Exact attempt identity.
    pub attempt_id: RecordId,
    /// Monotonic active fencing token.
    pub fencing_token: u64,
    /// Current delivery state.
    pub state: EffectOutboxState,
}

/// Complete current effect projection and all records needed for restart recovery.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableEffectRecord {
    /// Immutable normalized intent.
    pub intent: EffectIntent,
    /// Domain-separated intent digest.
    pub intent_digest: ContentDigest,
    /// Current closed state.
    pub state: EffectState,
    /// Monotonic effect version; equals the journal length.
    pub effect_version: u64,
    /// Exact current approval, if any.
    pub approval: Option<EffectApproval>,
    /// Domain-separated digest of the exact persisted approval, if any.
    #[serde(default)]
    pub approval_digest: Option<ContentDigest>,
    /// Ordered dispatch attempts.
    pub attempts: Vec<EffectAttempt>,
    /// Accepted receipts, at most one per attempt.
    pub receipts: Vec<EffectReceipt>,
    /// Ordered reconciliation reports.
    pub reconciliations: Vec<ReconciliationReport>,
    /// Separately authorized compensation relationship.
    pub compensation_link: Option<CompensationLink>,
    /// Ordered verified hash chain.
    pub journal: Vec<EffectJournalEvent>,
    /// Current semantic outbox item, if dispatch work exists.
    pub outbox: Option<EffectOutboxEntry>,
}

impl fmt::Debug for DurableEffectRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableEffectRecord")
            .field("effect_id", &self.intent.effect_id)
            .field("intent_digest", &self.intent_digest)
            .field("state", &self.state)
            .field("effect_version", &self.effect_version)
            .field("has_approval", &self.approval.is_some())
            .field("approval_digest", &self.approval_digest)
            .field("attempt_count", &self.attempts.len())
            .field("receipt_count", &self.receipts.len())
            .field("reconciliation_count", &self.reconciliations.len())
            .field("has_compensation", &self.compensation_link.is_some())
            .field("journal_count", &self.journal.len())
            .field(
                "outbox_state",
                &self.outbox.as_ref().map(|entry| entry.state),
            )
            .finish_non_exhaustive()
    }
}

/// Current authorization inputs evaluated at every privileged transition and immediately pre-send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAuthorization {
    /// Authenticated actor.
    pub actor_id: RecordId,
    /// Current effective capabilities.
    pub capabilities: BTreeSet<Capability>,
    /// Current policy decision.
    pub policy_allows: bool,
    /// Current time.
    pub now: UtcTimestamp,
}

impl EffectAuthorization {
    /// Returns whether the actor may durably propose this exact intent.
    #[must_use]
    pub fn permits_proposal(&self) -> bool {
        self.policy_allows && self.capabilities.contains(&Capability::ProposeEffect)
    }

    /// Returns whether the actor may authorize and send the exact intent.
    #[must_use]
    pub fn permits_dispatch(&self, intent: &EffectIntent) -> bool {
        self.policy_allows
            && self.capabilities.contains(&Capability::ApproveEffect)
            && self.capabilities.contains(&intent.required_capability)
    }

    /// Returns whether the actor may reconcile an ambiguous effect.
    #[must_use]
    pub fn permits_reconciliation(&self) -> bool {
        self.policy_allows && self.capabilities.contains(&Capability::ReconcileEffect)
    }
}

/// Opaque durable permission to perform at most one fenced connector call.
#[derive(Debug, Eq, PartialEq)]
pub struct DispatchPermit {
    pub(crate) effect_id: RecordId,
    pub(crate) attempt_id: RecordId,
    pub(crate) fencing_token: u64,
    pub(crate) effect_version: u64,
    pub(crate) request_digest: ContentDigest,
    pub(crate) seal: ContentDigest,
}

impl DispatchPermit {
    /// Returns the logical effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> &RecordId {
        &self.effect_id
    }

    /// Returns the exact attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> &RecordId {
        &self.attempt_id
    }

    /// Returns the active monotonic fence.
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}
