//! Governed compiler cache and bounded restart-safe provider runtime state.
//!
//! The public v1 operation registry remains frozen. Provider lifecycle state instead enters
//! through a versioned crate-internal HMAC-authenticated adapter boundary. Durable observations
//! are accepted only from opaque verified-delta evidence or exact daemon-derived overflow
//! evidence; caller-authored acknowledgement and repair records never cross this boundary.

#![allow(
    dead_code,
    reason = "the trusted provider boundary is deliberately unreachable from the frozen public v1 registry and is exercised by internal-adapter qualification tests"
)]

use cigar_compiler::{
    AppliedDelta, CacheKey, DeltaAcknowledgement, GovernedCache, TargetOverflowRepairRequest,
    acknowledge_delta,
};
use cigar_protocol::{
    ContentDigest, MaterializedContext, RecordId, TargetProfile, Validate, VersionId,
};
use cigar_store::{
    CancellationToken, ServiceError, ServiceErrorCode, ServiceExpectedVersion, ServiceRepository,
    WorkerLocator, WorkerUpdate,
};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const TARGET_OVERFLOW_WORKER: &str = "context-target-overflow-v1";
const PROVIDER_STATE_WORKER: &str = "context-provider-state-v1";
const OVERFLOW_LEASE_NANOS: u64 = 30_000_000_000;
const PROVIDER_LEASE_NANOS: u64 = 30_000_000_000;
const PROVIDER_INPUT_SCHEMA: &str = "cigar.trusted-provider-input.v1";
const PROVIDER_STATE_SCHEMA: &str = "cigar.provider-state.v1";
const MAX_PROVIDER_INPUT_BYTES: usize = 4_096;
const MAX_PROVIDER_SESSIONS: usize = 32;
const MAX_PROVIDER_SESSION_NANOS: u64 = 3_600_000_000_000;
const MAX_PROVIDER_KEY_ID_BYTES: usize = 64;
const PROVIDER_AUTH_KEY_BYTES: usize = 32;
const PROVIDER_TAG_BYTES: usize = 32;
const MAX_PROVIDER_STATE_BYTES: usize = 60_000;
const MAX_CAS_RETRIES: usize = 16;
const DEFAULT_CACHE_ENTRIES: usize = 256;
const DEFAULT_CACHE_BYTES: usize = 64 * 1_024 * 1_024;

type ProviderHmac = Hmac<Sha256>;

/// Stable, content-free compiler runtime-state failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompilerControlPlaneError {
    /// Authentication, expiry, tenant, or governance binding failed.
    Unauthorized,
    /// An exact materialization or retained record was malformed.
    InvalidInput,
    /// Durable bytes or immutable identities disagreed.
    Integrity,
    /// A concurrent bounded-state update exhausted its retry budget.
    SequenceConflict,
    /// A configured storage or cache bound was exceeded.
    LimitExceeded,
    /// Cancellation or the backing repository prevented a safe result.
    Unavailable,
}

impl fmt::Display for CompilerControlPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compiler control plane failed: {self:?}")
    }
}

impl std::error::Error for CompilerControlPlaneError {}

/// Exact tenant and current policy/revocation state authorizing one runtime-state operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerGovernance {
    tenant_id: RecordId,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
    observed_at_unix_nanos: u64,
}

impl CompilerGovernance {
    /// Binds one operation to current, caller-derived governance state.
    #[must_use]
    pub const fn new(
        tenant_id: RecordId,
        policy_digest: ContentDigest,
        revocation_epoch: u64,
        observed_at_unix_nanos: u64,
    ) -> Self {
        Self {
            tenant_id,
            policy_digest,
            revocation_epoch,
            observed_at_unix_nanos,
        }
    }

    /// Current policy snapshot digest.
    #[must_use]
    pub const fn policy_digest(&self) -> &ContentDigest {
        &self.policy_digest
    }

    /// Current revocation epoch.
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    /// Exact tenant bound to this authorization decision.
    #[must_use]
    pub const fn tenant_id(&self) -> &RecordId {
        &self.tenant_id
    }

    /// Trusted wall-clock observation used for expiry and lease checks.
    #[must_use]
    pub const fn observed_at_unix_nanos(&self) -> u64 {
        self.observed_at_unix_nanos
    }
}

/// Opaque evidence derived from an exact materialization that exceeded its bound.
pub struct VerifiedTargetOverflow {
    repair: TargetOverflowRepairRequest,
}

impl VerifiedTargetOverflow {
    /// Derives evidence only from a validated materialization and its exact target profile.
    pub fn from_materialization(
        materialized: &MaterializedContext,
        target: &TargetProfile,
    ) -> Result<Option<Self>, CompilerControlPlaneError> {
        materialized
            .validate()
            .map_err(|_error| CompilerControlPlaneError::InvalidInput)?;
        let target_fingerprint = target_profile_fingerprint(target)?;
        Ok(TargetOverflowRepairRequest::new(
            materialized.bundle_id.clone(),
            target_fingerprint,
            materialized.token_count,
            target.max_context_tokens,
        )
        .map(|repair| Self { repair }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedOverflow {
    schema_version: String,
    bundle_id: VersionId,
    target_fingerprint: ContentDigest,
    observed_tokens: u32,
    maximum_input_tokens: u32,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
}

/// Opaque provider-session identity and immutable target generation supplied by a trusted
/// adapter. The identity is a digest, never provider content or a bearer credential.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderSessionDescriptor {
    session_id: ContentDigest,
    target_fingerprint: ContentDigest,
    provider_generation: u64,
}

impl ProviderSessionDescriptor {
    /// Creates a non-zero provider generation descriptor.
    pub fn new(
        session_id: ContentDigest,
        target_fingerprint: ContentDigest,
        provider_generation: u64,
    ) -> Result<Self, CompilerControlPlaneError> {
        if provider_generation == 0 {
            return Err(CompilerControlPlaneError::InvalidInput);
        }
        Ok(Self {
            session_id,
            target_fingerprint,
            provider_generation,
        })
    }
}

impl fmt::Debug for ProviderSessionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSessionDescriptor")
            .field("session_id", &"[OPAQUE]")
            .field("target_fingerprint", &"[OPAQUE]")
            .field("provider_generation", &self.provider_generation)
            .finish()
    }
}

/// Reset reason whose distinct authenticated representation prevents compaction from being
/// replayed as a provider reset (or vice versa).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderInvalidationKind {
    /// The provider reported a full session reset.
    Reset,
    /// The provider compacted or otherwise discarded its context cache.
    Compaction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
enum ProviderActionPayload {
    Establish,
    AcknowledgeDelta {
        base_bundle_id: VersionId,
        target_bundle_id: VersionId,
        delta_digest: ContentDigest,
    },
    Invalidate {
        invalidation: ProviderInvalidationKind,
    },
    ConsumeRepair {
        overflow_version: u64,
        overflow_digest: ContentDigest,
    },
    InspectPresent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderInputPayload {
    schema_version: String,
    key_id: String,
    tenant_id: RecordId,
    session_id: ContentDigest,
    target_fingerprint: ContentDigest,
    provider_generation: u64,
    sequence: u64,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
    issued_at_unix_nanos: u64,
    expires_at_unix_nanos: u64,
    action: ProviderActionPayload,
}

/// Untrusted exact bytes plus authentication tag received from the internal provider adapter.
/// Debug output exposes neither bytes nor tag material.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderAdapterInput {
    payload: Vec<u8>,
    tag: [u8; PROVIDER_TAG_BYTES],
}

impl ProviderAdapterInput {
    /// Reconstructs an input at a process or IPC boundary. Authentication remains mandatory.
    pub fn from_untrusted_parts(
        payload: Vec<u8>,
        tag: [u8; PROVIDER_TAG_BYTES],
    ) -> Result<Self, CompilerControlPlaneError> {
        if payload.is_empty() || payload.len() > MAX_PROVIDER_INPUT_BYTES {
            return Err(CompilerControlPlaneError::LimitExceeded);
        }
        Ok(Self { payload, tag })
    }

    /// Returns the exact authenticated payload bytes for a trusted local transport.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the exact authentication tag for a trusted local transport.
    #[must_use]
    pub const fn tag(&self) -> &[u8; PROVIDER_TAG_BYTES] {
        &self.tag
    }
}

impl fmt::Debug for ProviderAdapterInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAdapterInput")
            .field("payload_bytes", &self.payload.len())
            .field("payload", &"[REDACTED]")
            .field("tag", &"[REDACTED]")
            .finish()
    }
}

/// Opaque, exact reference to one daemon-derived target-overflow checkpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingTargetRepair {
    overflow_version: u64,
    overflow_digest: ContentDigest,
    target_fingerprint: ContentDigest,
}

impl fmt::Debug for PendingTargetRepair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTargetRepair")
            .field("overflow_version", &self.overflow_version)
            .field("overflow_digest", &"[OPAQUE]")
            .field("target_fingerprint", &"[OPAQUE]")
            .finish()
    }
}

/// Exact repair evidence returned only after its durable consumption receipt commits.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumedTargetRepair {
    repair: TargetOverflowRepairRequest,
    overflow_digest: ContentDigest,
}

impl ConsumedTargetRepair {
    /// Returns the exact daemon-derived repair request consumed by this transition.
    #[must_use]
    pub const fn repair(&self) -> &TargetOverflowRepairRequest {
        &self.repair
    }

    /// Returns the digest of the exact durable overflow checkpoint.
    #[must_use]
    pub const fn overflow_digest(&self) -> &ContentDigest {
        &self.overflow_digest
    }
}

impl fmt::Debug for ConsumedTargetRepair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedTargetRepair")
            .field("repair", &"[OPAQUE]")
            .field("overflow_digest", &"[OPAQUE]")
            .finish_non_exhaustive()
    }
}

/// Opaque authenticated action. Only [`ProviderAdapterAuthenticator::authenticate`] can mint it.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedProviderAction {
    payload: ProviderInputPayload,
    action_digest: ContentDigest,
}

impl fmt::Debug for AuthenticatedProviderAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedProviderAction")
            .field("session_id", &"[OPAQUE]")
            .field("provider_generation", &self.payload.provider_generation)
            .field("sequence", &self.payload.sequence)
            .field("action", &provider_action_label(&self.payload.action))
            .field("action_digest", &"[OPAQUE]")
            .finish()
    }
}

/// Versioned HMAC authority shared only with a local trusted provider adapter.
pub struct ProviderAdapterAuthenticator {
    key_id: String,
    key: Zeroizing<[u8; PROVIDER_AUTH_KEY_BYTES]>,
}

impl ProviderAdapterAuthenticator {
    /// Creates one exact-key authority. Empty/all-zero keys and unsafe key identifiers fail closed.
    pub fn new(
        key_id: impl Into<String>,
        key: [u8; PROVIDER_AUTH_KEY_BYTES],
    ) -> Result<Self, CompilerControlPlaneError> {
        let key_id = key_id.into();
        if !valid_provider_key_id(&key_id) || key.iter().all(|byte| *byte == 0) {
            return Err(CompilerControlPlaneError::InvalidInput);
        }
        Ok(Self {
            key_id,
            key: Zeroizing::new(key),
        })
    }

    /// Signs an exact session-establishment input at sequence one.
    pub fn seal_establish(
        &self,
        governance: &CompilerGovernance,
        session: &ProviderSessionDescriptor,
        expires_at_unix_nanos: u64,
    ) -> Result<ProviderAdapterInput, CompilerControlPlaneError> {
        self.seal(
            governance,
            session,
            1,
            expires_at_unix_nanos,
            ProviderActionPayload::Establish,
        )
    }

    /// Signs acknowledgement intent from opaque verified application evidence, never caller fields.
    pub fn seal_applied_delta(
        &self,
        governance: &CompilerGovernance,
        session: &ProviderSessionDescriptor,
        sequence: u64,
        expires_at_unix_nanos: u64,
        applied: &AppliedDelta,
    ) -> Result<ProviderAdapterInput, CompilerControlPlaneError> {
        self.seal(
            governance,
            session,
            sequence,
            expires_at_unix_nanos,
            ProviderActionPayload::AcknowledgeDelta {
                base_bundle_id: applied.base_bundle_id().clone(),
                target_bundle_id: applied.target_bundle_id().clone(),
                delta_digest: applied.delta_digest().clone(),
            },
        )
    }

    /// Signs an exact reset or compaction invalidation transition.
    pub fn seal_invalidation(
        &self,
        governance: &CompilerGovernance,
        session: &ProviderSessionDescriptor,
        sequence: u64,
        expires_at_unix_nanos: u64,
        invalidation: ProviderInvalidationKind,
    ) -> Result<ProviderAdapterInput, CompilerControlPlaneError> {
        self.seal(
            governance,
            session,
            sequence,
            expires_at_unix_nanos,
            ProviderActionPayload::Invalidate { invalidation },
        )
    }

    /// Signs consumption of one exact opaque repair reference.
    pub fn seal_repair_consumption(
        &self,
        governance: &CompilerGovernance,
        session: &ProviderSessionDescriptor,
        sequence: u64,
        expires_at_unix_nanos: u64,
        repair: &PendingTargetRepair,
    ) -> Result<ProviderAdapterInput, CompilerControlPlaneError> {
        if repair.target_fingerprint != session.target_fingerprint {
            return Err(CompilerControlPlaneError::InvalidInput);
        }
        self.seal(
            governance,
            session,
            sequence,
            expires_at_unix_nanos,
            ProviderActionPayload::ConsumeRepair {
                overflow_version: repair.overflow_version,
                overflow_digest: repair.overflow_digest.clone(),
            },
        )
    }

    /// Signs a non-mutating present-state query pinned to the latest acknowledged sequence.
    pub fn seal_present_query(
        &self,
        governance: &CompilerGovernance,
        session: &ProviderSessionDescriptor,
        latest_sequence: u64,
        expires_at_unix_nanos: u64,
    ) -> Result<ProviderAdapterInput, CompilerControlPlaneError> {
        self.seal(
            governance,
            session,
            latest_sequence,
            expires_at_unix_nanos,
            ProviderActionPayload::InspectPresent,
        )
    }

    /// Authenticates exact canonical bytes, their key identity, lifetime, tenant, and governance.
    pub fn authenticate(
        &self,
        input: &ProviderAdapterInput,
        governance: &CompilerGovernance,
    ) -> Result<AuthenticatedProviderAction, CompilerControlPlaneError> {
        if input.payload.is_empty() || input.payload.len() > MAX_PROVIDER_INPUT_BYTES {
            return Err(CompilerControlPlaneError::LimitExceeded);
        }
        let mut mac = <ProviderHmac as hmac::KeyInit>::new_from_slice(self.key.as_ref())
            .map_err(|_error| CompilerControlPlaneError::Unavailable)?;
        mac.update(&input.payload);
        mac.verify_slice(&input.tag)
            .map_err(|_error| CompilerControlPlaneError::Unauthorized)?;
        let payload: ProviderInputPayload = serde_json::from_slice(&input.payload)
            .map_err(|_error| CompilerControlPlaneError::Unauthorized)?;
        let canonical =
            serde_json::to_vec(&payload).map_err(|_error| CompilerControlPlaneError::Integrity)?;
        if canonical != input.payload {
            return Err(CompilerControlPlaneError::Unauthorized);
        }
        validate_provider_input(&payload, &self.key_id, governance)?;
        Ok(AuthenticatedProviderAction {
            action_digest: namespaced_digest(b"CIGAR-PROVIDER-ACTION\0v1\0", &input.payload)?,
            payload,
        })
    }

    fn seal(
        &self,
        governance: &CompilerGovernance,
        session: &ProviderSessionDescriptor,
        sequence: u64,
        expires_at_unix_nanos: u64,
        action: ProviderActionPayload,
    ) -> Result<ProviderAdapterInput, CompilerControlPlaneError> {
        let payload = ProviderInputPayload {
            schema_version: PROVIDER_INPUT_SCHEMA.to_owned(),
            key_id: self.key_id.clone(),
            tenant_id: governance.tenant_id.clone(),
            session_id: session.session_id.clone(),
            target_fingerprint: session.target_fingerprint.clone(),
            provider_generation: session.provider_generation,
            sequence,
            policy_digest: governance.policy_digest.clone(),
            revocation_epoch: governance.revocation_epoch,
            issued_at_unix_nanos: governance.observed_at_unix_nanos,
            expires_at_unix_nanos,
            action,
        };
        validate_provider_input(&payload, &self.key_id, governance)?;
        let bytes =
            serde_json::to_vec(&payload).map_err(|_error| CompilerControlPlaneError::Integrity)?;
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_INPUT_BYTES {
            return Err(CompilerControlPlaneError::LimitExceeded);
        }
        let mut mac = <ProviderHmac as hmac::KeyInit>::new_from_slice(self.key.as_ref())
            .map_err(|_error| CompilerControlPlaneError::Unavailable)?;
        mac.update(&bytes);
        let tag: [u8; PROVIDER_TAG_BYTES] = mac.finalize().into_bytes().into();
        Ok(ProviderAdapterInput {
            payload: bytes,
            tag,
        })
    }
}

impl fmt::Debug for ProviderAdapterAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAdapterAuthenticator")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PersistedProviderActionKind {
    Establish,
    AcknowledgeDelta,
    Reset,
    Compaction,
    ConsumeRepair,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedProviderPresent {
    bundle_id: VersionId,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
    observed_sequence: u64,
    confidence_parts_per_million: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedDeltaAcknowledgement {
    base_bundle_id: VersionId,
    target_bundle_id: VersionId,
    delta_digest: ContentDigest,
    target_fingerprint: ContentDigest,
    sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedProviderSession {
    session_id: ContentDigest,
    key_id: String,
    target_fingerprint: ContentDigest,
    provider_generation: u64,
    policy_digest: ContentDigest,
    revocation_epoch: u64,
    expires_at_unix_nanos: u64,
    last_sequence: u64,
    last_action_digest: ContentDigest,
    last_action_kind: PersistedProviderActionKind,
    invalidated: bool,
    acknowledgement: Option<PersistedDeltaAcknowledgement>,
    present: Option<PersistedProviderPresent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRepairConsumption {
    overflow_version: u64,
    overflow_digest: ContentDigest,
    session_id: ContentDigest,
    provider_generation: u64,
    sequence: u64,
    action_digest: ContentDigest,
    repair: PersistedOverflow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedProviderState {
    schema_version: String,
    sessions: BTreeMap<String, PersistedProviderSession>,
    consumed_repair: Option<PersistedRepairConsumption>,
}

impl Default for PersistedProviderState {
    fn default() -> Self {
        Self {
            schema_version: PROVIDER_STATE_SCHEMA.to_owned(),
            sessions: BTreeMap::new(),
            consumed_repair: None,
        }
    }
}

fn valid_provider_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_provider_input(
    payload: &ProviderInputPayload,
    expected_key_id: &str,
    governance: &CompilerGovernance,
) -> Result<(), CompilerControlPlaneError> {
    let lifetime = payload
        .expires_at_unix_nanos
        .checked_sub(payload.issued_at_unix_nanos)
        .ok_or(CompilerControlPlaneError::Unauthorized)?;
    if payload.schema_version != PROVIDER_INPUT_SCHEMA
        || payload.key_id != expected_key_id
        || payload.tenant_id != governance.tenant_id
        || payload.policy_digest != governance.policy_digest
        || payload.revocation_epoch != governance.revocation_epoch
        || payload.provider_generation == 0
        || payload.sequence == 0
        || lifetime == 0
        || lifetime > MAX_PROVIDER_SESSION_NANOS
        || governance.observed_at_unix_nanos < payload.issued_at_unix_nanos
        || governance.observed_at_unix_nanos >= payload.expires_at_unix_nanos
    {
        return Err(CompilerControlPlaneError::Unauthorized);
    }
    if matches!(payload.action, ProviderActionPayload::Establish) && payload.sequence != 1 {
        return Err(CompilerControlPlaneError::Unauthorized);
    }
    Ok(())
}

fn namespaced_digest(
    domain: &[u8],
    bytes: &[u8],
) -> Result<ContentDigest, CompilerControlPlaneError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_error| CompilerControlPlaneError::LimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    let mut output = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut output, "{byte:02x}").map_err(|_error| CompilerControlPlaneError::Integrity)?;
    }
    ContentDigest::new(output).map_err(|_error| CompilerControlPlaneError::Integrity)
}

fn raw_digest(bytes: &[u8]) -> Result<ContentDigest, CompilerControlPlaneError> {
    let hash = Sha256::digest(bytes);
    let mut output = String::from("1220");
    use std::fmt::Write as _;
    for byte in hash {
        write!(&mut output, "{byte:02x}").map_err(|_error| CompilerControlPlaneError::Integrity)?;
    }
    ContentDigest::new(output).map_err(|_error| CompilerControlPlaneError::Integrity)
}

fn provider_session_key(session_id: &ContentDigest) -> String {
    session_id.as_str().to_owned()
}

fn decode_provider_state(
    bytes: &[u8],
) -> Result<PersistedProviderState, CompilerControlPlaneError> {
    if bytes.is_empty() {
        return Ok(PersistedProviderState::default());
    }
    if bytes.len() > MAX_PROVIDER_STATE_BYTES {
        return Err(CompilerControlPlaneError::Integrity);
    }
    let state: PersistedProviderState =
        serde_json::from_slice(bytes).map_err(|_error| CompilerControlPlaneError::Integrity)?;
    validate_provider_state(&state)?;
    Ok(state)
}

fn validate_provider_state(
    state: &PersistedProviderState,
) -> Result<(), CompilerControlPlaneError> {
    if state.schema_version != PROVIDER_STATE_SCHEMA || state.sessions.len() > MAX_PROVIDER_SESSIONS
    {
        return Err(CompilerControlPlaneError::Integrity);
    }
    for (key, session) in &state.sessions {
        if key != session.session_id.as_str()
            || !valid_provider_key_id(&session.key_id)
            || session.provider_generation == 0
            || session.last_sequence == 0
            || session.expires_at_unix_nanos == 0
        {
            return Err(CompilerControlPlaneError::Integrity);
        }
        match session.last_action_kind {
            PersistedProviderActionKind::Reset | PersistedProviderActionKind::Compaction => {
                if !session.invalidated
                    || session.acknowledgement.is_some()
                    || session.present.is_some()
                {
                    return Err(CompilerControlPlaneError::Integrity);
                }
            }
            PersistedProviderActionKind::AcknowledgeDelta => {
                if session.invalidated
                    || session.acknowledgement.is_none()
                    || session.present.is_none()
                {
                    return Err(CompilerControlPlaneError::Integrity);
                }
            }
            PersistedProviderActionKind::Establish => {
                if session.invalidated
                    || session.last_sequence != 1
                    || session.acknowledgement.is_some()
                    || session.present.is_some()
                {
                    return Err(CompilerControlPlaneError::Integrity);
                }
            }
            PersistedProviderActionKind::ConsumeRepair => {
                if session.invalidated
                    || session.acknowledgement.is_some()
                    || session.present.is_some()
                {
                    return Err(CompilerControlPlaneError::Integrity);
                }
            }
        }
        if let Some(present) = &session.present
            && (present.policy_digest != session.policy_digest
                || present.revocation_epoch != session.revocation_epoch
                || present.observed_sequence > session.last_sequence
                || present.observed_sequence == 0
                || present.confidence_parts_per_million != 1_000_000)
        {
            return Err(CompilerControlPlaneError::Integrity);
        }
        if let Some(acknowledgement) = &session.acknowledgement
            && (acknowledgement.target_fingerprint != session.target_fingerprint
                || acknowledgement.sequence == 0
                || acknowledgement.sequence != session.last_sequence
                || session.present.as_ref().is_none_or(|present| {
                    present.bundle_id != acknowledgement.target_bundle_id
                        || present.observed_sequence != acknowledgement.sequence
                }))
        {
            return Err(CompilerControlPlaneError::Integrity);
        }
    }
    if let Some(consumed) = &state.consumed_repair {
        validate_persisted_overflow(&consumed.repair)?;
        let repair_bytes = serde_json::to_vec(&consumed.repair)
            .map_err(|_error| CompilerControlPlaneError::Integrity)?;
        if consumed.overflow_version == 0
            || consumed.provider_generation == 0
            || consumed.sequence == 0
            || raw_digest(&repair_bytes)? != consumed.overflow_digest
        {
            return Err(CompilerControlPlaneError::Integrity);
        }
        if let Some(session) = state
            .sessions
            .get(&provider_session_key(&consumed.session_id))
        {
            if session.provider_generation < consumed.provider_generation
                || (session.provider_generation == consumed.provider_generation
                    && session.last_sequence < consumed.sequence)
            {
                return Err(CompilerControlPlaneError::Integrity);
            }
            if session.provider_generation == consumed.provider_generation
                && session.last_sequence == consumed.sequence
                && (session.last_action_digest != consumed.action_digest
                    || session.last_action_kind != PersistedProviderActionKind::ConsumeRepair)
            {
                return Err(CompilerControlPlaneError::Integrity);
            }
        }
    }
    Ok(())
}

fn validate_action_binding(
    action: &AuthenticatedProviderAction,
    governance: &CompilerGovernance,
) -> Result<(), CompilerControlPlaneError> {
    if action.payload.tenant_id != governance.tenant_id
        || action.payload.policy_digest != governance.policy_digest
        || action.payload.revocation_epoch != governance.revocation_epoch
        || governance.observed_at_unix_nanos < action.payload.issued_at_unix_nanos
        || governance.observed_at_unix_nanos >= action.payload.expires_at_unix_nanos
    {
        Err(CompilerControlPlaneError::Unauthorized)
    } else {
        Ok(())
    }
}

fn validate_session_binding(
    session: &PersistedProviderSession,
    payload: &ProviderInputPayload,
) -> Result<(), CompilerControlPlaneError> {
    if session.session_id != payload.session_id
        || session.key_id != payload.key_id
        || session.target_fingerprint != payload.target_fingerprint
        || session.provider_generation != payload.provider_generation
        || session.policy_digest != payload.policy_digest
        || session.revocation_epoch != payload.revocation_epoch
        || payload.expires_at_unix_nanos > session.expires_at_unix_nanos
    {
        Err(CompilerControlPlaneError::Unauthorized)
    } else {
        Ok(())
    }
}

enum MutationOrder {
    Replay,
    Advance,
}

fn mutation_order(
    session: &PersistedProviderSession,
    action: &AuthenticatedProviderAction,
) -> Result<MutationOrder, CompilerControlPlaneError> {
    if action.payload.sequence == session.last_sequence {
        return if action.action_digest == session.last_action_digest {
            Ok(MutationOrder::Replay)
        } else {
            Err(CompilerControlPlaneError::SequenceConflict)
        };
    }
    let expected = session
        .last_sequence
        .checked_add(1)
        .ok_or(CompilerControlPlaneError::LimitExceeded)?;
    if action.payload.sequence != expected {
        return Err(CompilerControlPlaneError::SequenceConflict);
    }
    Ok(MutationOrder::Advance)
}

fn provider_action_kind(action: &ProviderActionPayload) -> PersistedProviderActionKind {
    match action {
        ProviderActionPayload::Establish => PersistedProviderActionKind::Establish,
        ProviderActionPayload::AcknowledgeDelta { .. } => {
            PersistedProviderActionKind::AcknowledgeDelta
        }
        ProviderActionPayload::Invalidate {
            invalidation: ProviderInvalidationKind::Reset,
        } => PersistedProviderActionKind::Reset,
        ProviderActionPayload::Invalidate {
            invalidation: ProviderInvalidationKind::Compaction,
        } => PersistedProviderActionKind::Compaction,
        ProviderActionPayload::ConsumeRepair { .. } => PersistedProviderActionKind::ConsumeRepair,
        ProviderActionPayload::InspectPresent => PersistedProviderActionKind::Establish,
    }
}

const fn provider_action_label(action: &ProviderActionPayload) -> &'static str {
    match action {
        ProviderActionPayload::Establish => "establish",
        ProviderActionPayload::AcknowledgeDelta { .. } => "acknowledge_delta",
        ProviderActionPayload::Invalidate {
            invalidation: ProviderInvalidationKind::Reset,
        } => "reset",
        ProviderActionPayload::Invalidate {
            invalidation: ProviderInvalidationKind::Compaction,
        } => "compaction",
        ProviderActionPayload::ConsumeRepair { .. } => "consume_repair",
        ProviderActionPayload::InspectPresent => "inspect_present",
    }
}

/// Bounded process-local cache plus one restart-safe latest-overflow checkpoint per tenant.
///
/// Cache contents intentionally start cold after restart. Overflow state uses one mutable fenced
/// worker checkpoint per tenant, so repeated requests cannot amplify record keys or history.
#[derive(Clone)]
pub struct DurableCompilerControlPlane {
    repository: Arc<dyn ServiceRepository>,
    cache: Arc<Mutex<Option<GovernedCache>>>,
}

impl fmt::Debug for DurableCompilerControlPlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableCompilerControlPlane")
            .finish_non_exhaustive()
    }
}

impl DurableCompilerControlPlane {
    /// Creates a control plane with fixed, non-zero cache bounds.
    #[must_use]
    pub fn new(repository: Arc<dyn ServiceRepository>) -> Self {
        Self {
            repository,
            cache: Arc::new(Mutex::new(GovernedCache::new(
                DEFAULT_CACHE_ENTRIES,
                DEFAULT_CACHE_BYTES,
            ))),
        }
    }

    /// Reads only after current policy, revocation, integrity, and eligibility checks.
    pub fn cache_get(
        &self,
        key: &CacheKey,
        policy_digest: &ContentDigest,
        revocation_epoch: u64,
        currently_eligible: impl FnOnce(&CacheKey) -> bool,
    ) -> Result<Option<Vec<u8>>, CompilerControlPlaneError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_error| CompilerControlPlaneError::Unavailable)?;
        let cache = cache
            .as_mut()
            .ok_or(CompilerControlPlaneError::Unavailable)?;
        Ok(cache.get(key, policy_digest, revocation_epoch, currently_eligible))
    }

    /// Inserts one bounded value with the live governance state that authorized it.
    pub fn cache_insert(
        &self,
        key: CacheKey,
        bytes: Vec<u8>,
        policy_digest: ContentDigest,
        revocation_epoch: u64,
    ) -> Result<bool, CompilerControlPlaneError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_error| CompilerControlPlaneError::Unavailable)?;
        let cache = cache
            .as_mut()
            .ok_or(CompilerControlPlaneError::Unavailable)?;
        Ok(cache.insert(key, bytes, policy_digest, revocation_epoch))
    }

    /// Establishes or exactly replays one authenticated bounded provider generation.
    pub fn establish_provider_session(
        &self,
        governance: &CompilerGovernance,
        action: &AuthenticatedProviderAction,
        cancellation: &CancellationToken,
    ) -> Result<(), CompilerControlPlaneError> {
        validate_action_binding(action, governance)?;
        if !matches!(action.payload.action, ProviderActionPayload::Establish)
            || action.payload.sequence != 1
        {
            return Err(CompilerControlPlaneError::InvalidInput);
        }
        self.mutate_provider_state(governance, action, cancellation, |state| {
            state.sessions.retain(|_key, session| {
                session.expires_at_unix_nanos > governance.observed_at_unix_nanos
            });
            let key = provider_session_key(&action.payload.session_id);
            if let Some(current) = state.sessions.get(&key) {
                if current.provider_generation == action.payload.provider_generation {
                    validate_session_binding(current, &action.payload)?;
                    if current.last_sequence == 1
                        && current.last_action_digest == action.action_digest
                        && current.last_action_kind == PersistedProviderActionKind::Establish
                    {
                        return Ok(());
                    }
                    return Err(CompilerControlPlaneError::SequenceConflict);
                }
                let next_generation = current
                    .provider_generation
                    .checked_add(1)
                    .ok_or(CompilerControlPlaneError::LimitExceeded)?;
                if !current.invalidated
                    || action.payload.provider_generation != next_generation
                    || current.target_fingerprint != action.payload.target_fingerprint
                {
                    return Err(CompilerControlPlaneError::SequenceConflict);
                }
            } else if state.sessions.len() >= MAX_PROVIDER_SESSIONS {
                return Err(CompilerControlPlaneError::LimitExceeded);
            }
            state.sessions.insert(
                key,
                PersistedProviderSession {
                    session_id: action.payload.session_id.clone(),
                    key_id: action.payload.key_id.clone(),
                    target_fingerprint: action.payload.target_fingerprint.clone(),
                    provider_generation: action.payload.provider_generation,
                    policy_digest: action.payload.policy_digest.clone(),
                    revocation_epoch: action.payload.revocation_epoch,
                    expires_at_unix_nanos: action.payload.expires_at_unix_nanos,
                    last_sequence: 1,
                    last_action_digest: action.action_digest.clone(),
                    last_action_kind: PersistedProviderActionKind::Establish,
                    invalidated: false,
                    acknowledgement: None,
                    present: None,
                },
            );
            Ok(())
        })
    }

    /// Persists an acknowledgement and provider-present observation derived from one exact
    /// [`AppliedDelta`]. Signed fields and opaque evidence must agree byte-for-byte.
    pub fn acknowledge_provider_delta(
        &self,
        governance: &CompilerGovernance,
        action: &AuthenticatedProviderAction,
        applied: &AppliedDelta,
        cancellation: &CancellationToken,
    ) -> Result<DeltaAcknowledgement, CompilerControlPlaneError> {
        validate_action_binding(action, governance)?;
        let ProviderActionPayload::AcknowledgeDelta {
            base_bundle_id,
            target_bundle_id,
            delta_digest,
        } = &action.payload.action
        else {
            return Err(CompilerControlPlaneError::InvalidInput);
        };
        if base_bundle_id != applied.base_bundle_id()
            || target_bundle_id != applied.target_bundle_id()
            || delta_digest != applied.delta_digest()
        {
            return Err(CompilerControlPlaneError::Unauthorized);
        }
        let acknowledgement = acknowledge_delta(
            action.payload.session_id.as_str(),
            action.payload.target_fingerprint.clone(),
            applied,
            action.payload.sequence,
        )
        .ok_or(CompilerControlPlaneError::InvalidInput)?;
        self.mutate_provider_state(governance, action, cancellation, |state| {
            let key = provider_session_key(&action.payload.session_id);
            let session = state
                .sessions
                .get_mut(&key)
                .ok_or(CompilerControlPlaneError::Unauthorized)?;
            validate_session_binding(session, &action.payload)?;
            if session.invalidated {
                return Err(CompilerControlPlaneError::Unauthorized);
            }
            match mutation_order(session, action)? {
                MutationOrder::Replay => {
                    let exact = session.acknowledgement.as_ref().is_some_and(|persisted| {
                        persisted.base_bundle_id == acknowledgement.base_bundle_id
                            && persisted.target_bundle_id == acknowledgement.target_bundle_id
                            && persisted.delta_digest == acknowledgement.delta_digest
                            && persisted.target_fingerprint == acknowledgement.target_fingerprint
                            && persisted.sequence == acknowledgement.sequence
                    });
                    if session.last_action_kind != PersistedProviderActionKind::AcknowledgeDelta
                        || !exact
                    {
                        return Err(CompilerControlPlaneError::Integrity);
                    }
                    return Ok(acknowledgement.clone());
                }
                MutationOrder::Advance => {}
            }
            if session
                .present
                .as_ref()
                .is_some_and(|present| present.bundle_id != acknowledgement.base_bundle_id)
            {
                return Err(CompilerControlPlaneError::SequenceConflict);
            }
            session.last_sequence = action.payload.sequence;
            session.last_action_digest = action.action_digest.clone();
            session.last_action_kind = PersistedProviderActionKind::AcknowledgeDelta;
            session.acknowledgement = Some(PersistedDeltaAcknowledgement {
                base_bundle_id: acknowledgement.base_bundle_id.clone(),
                target_bundle_id: acknowledgement.target_bundle_id.clone(),
                delta_digest: acknowledgement.delta_digest.clone(),
                target_fingerprint: acknowledgement.target_fingerprint.clone(),
                sequence: acknowledgement.sequence,
            });
            session.present = Some(PersistedProviderPresent {
                bundle_id: acknowledgement.target_bundle_id.clone(),
                policy_digest: action.payload.policy_digest.clone(),
                revocation_epoch: action.payload.revocation_epoch,
                observed_sequence: action.payload.sequence,
                confidence_parts_per_million: 1_000_000,
            });
            Ok(acknowledgement.clone())
        })
    }

    /// Invalidates all present and acknowledgement evidence for an authenticated reset or
    /// compaction. A new generation must be established before further mutation.
    pub fn invalidate_provider_session(
        &self,
        governance: &CompilerGovernance,
        action: &AuthenticatedProviderAction,
        cancellation: &CancellationToken,
    ) -> Result<(), CompilerControlPlaneError> {
        validate_action_binding(action, governance)?;
        let ProviderActionPayload::Invalidate { invalidation } = action.payload.action else {
            return Err(CompilerControlPlaneError::InvalidInput);
        };
        self.mutate_provider_state(governance, action, cancellation, |state| {
            let key = provider_session_key(&action.payload.session_id);
            let session = state
                .sessions
                .get_mut(&key)
                .ok_or(CompilerControlPlaneError::Unauthorized)?;
            validate_session_binding(session, &action.payload)?;
            match mutation_order(session, action)? {
                MutationOrder::Replay => {
                    if session.last_action_kind != provider_action_kind(&action.payload.action)
                        || !session.invalidated
                        || session.present.is_some()
                        || session.acknowledgement.is_some()
                    {
                        return Err(CompilerControlPlaneError::Integrity);
                    }
                    return Ok(());
                }
                MutationOrder::Advance => {}
            }
            if session.invalidated {
                return Err(CompilerControlPlaneError::SequenceConflict);
            }
            session.last_sequence = action.payload.sequence;
            session.last_action_digest = action.action_digest.clone();
            session.last_action_kind = match invalidation {
                ProviderInvalidationKind::Reset => PersistedProviderActionKind::Reset,
                ProviderInvalidationKind::Compaction => PersistedProviderActionKind::Compaction,
            };
            session.invalidated = true;
            session.acknowledgement = None;
            session.present = None;
            Ok(())
        })
    }

    /// Returns an opaque reference only when the latest overflow exactly matches current
    /// governance and target state and has not already been consumed.
    pub fn pending_target_repair(
        &self,
        governance: &CompilerGovernance,
        target_fingerprint: &ContentDigest,
        cancellation: &CancellationToken,
    ) -> Result<Option<PendingTargetRepair>, CompilerControlPlaneError> {
        let overflow_locator =
            WorkerLocator::new(governance.tenant_id.clone(), TARGET_OVERFLOW_WORKER)
                .map_err(map_service_error)?;
        let Some(overflow_state) = self
            .repository
            .worker_get(&overflow_locator, cancellation)
            .map_err(map_service_error)?
        else {
            return Ok(None);
        };
        if overflow_state.cursor().is_empty() {
            return Ok(None);
        }
        let overflow = decode_persisted_overflow(overflow_state.cursor())?;
        if overflow.policy_digest != governance.policy_digest
            || overflow.revocation_epoch != governance.revocation_epoch
            || &overflow.target_fingerprint != target_fingerprint
        {
            return Ok(None);
        }
        let provider_state = self.read_provider_state(governance, cancellation)?;
        if provider_state
            .consumed_repair
            .as_ref()
            .is_some_and(|consumed| {
                consumed.overflow_version == overflow_state.version()
                    && consumed.overflow_digest == *overflow_state.cursor_digest()
            })
        {
            return Ok(None);
        }
        Ok(Some(PendingTargetRepair {
            overflow_version: overflow_state.version(),
            overflow_digest: overflow_state.cursor_digest().clone(),
            target_fingerprint: overflow.target_fingerprint,
        }))
    }

    /// Atomically records one exact repair consumption and clears provider-present evidence for
    /// the affected session. Exact replay returns the same repair evidence.
    pub fn consume_target_repair(
        &self,
        governance: &CompilerGovernance,
        action: &AuthenticatedProviderAction,
        cancellation: &CancellationToken,
    ) -> Result<ConsumedTargetRepair, CompilerControlPlaneError> {
        validate_action_binding(action, governance)?;
        let ProviderActionPayload::ConsumeRepair {
            overflow_version,
            ref overflow_digest,
        } = action.payload.action
        else {
            return Err(CompilerControlPlaneError::InvalidInput);
        };
        let existing = self.read_provider_state(governance, cancellation)?;
        if let Some(consumed) = &existing.consumed_repair
            && consumed.overflow_version == overflow_version
            && consumed.overflow_digest == *overflow_digest
            && consumed.session_id == action.payload.session_id
            && consumed.provider_generation == action.payload.provider_generation
            && consumed.sequence == action.payload.sequence
            && consumed.action_digest == action.action_digest
        {
            let session = existing
                .sessions
                .get(&provider_session_key(&action.payload.session_id))
                .ok_or(CompilerControlPlaneError::Integrity)?;
            validate_session_binding(session, &action.payload)?;
            if session.last_sequence < consumed.sequence {
                return Err(CompilerControlPlaneError::Integrity);
            }
            let repair = TargetOverflowRepairRequest::new(
                consumed.repair.bundle_id.clone(),
                consumed.repair.target_fingerprint.clone(),
                consumed.repair.observed_tokens,
                consumed.repair.maximum_input_tokens,
            )
            .ok_or(CompilerControlPlaneError::Integrity)?;
            return Ok(ConsumedTargetRepair {
                repair,
                overflow_digest: overflow_digest.clone(),
            });
        }
        let overflow_locator =
            WorkerLocator::new(governance.tenant_id.clone(), TARGET_OVERFLOW_WORKER)
                .map_err(map_service_error)?;
        let overflow_state = self
            .repository
            .worker_get(&overflow_locator, cancellation)
            .map_err(map_service_error)?
            .ok_or(CompilerControlPlaneError::InvalidInput)?;
        if overflow_state.version() != overflow_version
            || overflow_state.cursor_digest() != overflow_digest
            || overflow_state.cursor().is_empty()
        {
            return Err(CompilerControlPlaneError::SequenceConflict);
        }
        let overflow = decode_persisted_overflow(overflow_state.cursor())?;
        if overflow.policy_digest != governance.policy_digest
            || overflow.revocation_epoch != governance.revocation_epoch
            || overflow.target_fingerprint != action.payload.target_fingerprint
        {
            return Err(CompilerControlPlaneError::Unauthorized);
        }
        let repair = TargetOverflowRepairRequest::new(
            overflow.bundle_id.clone(),
            overflow.target_fingerprint.clone(),
            overflow.observed_tokens,
            overflow.maximum_input_tokens,
        )
        .ok_or(CompilerControlPlaneError::Integrity)?;
        self.mutate_provider_state(governance, action, cancellation, |state| {
            let key = provider_session_key(&action.payload.session_id);
            let session = state
                .sessions
                .get_mut(&key)
                .ok_or(CompilerControlPlaneError::Unauthorized)?;
            validate_session_binding(session, &action.payload)?;
            if session.invalidated {
                return Err(CompilerControlPlaneError::Unauthorized);
            }
            match mutation_order(session, action)? {
                MutationOrder::Replay => {
                    let exact = state.consumed_repair.as_ref().is_some_and(|consumed| {
                        consumed.overflow_version == overflow_version
                            && consumed.overflow_digest == *overflow_digest
                            && consumed.session_id == action.payload.session_id
                            && consumed.provider_generation == action.payload.provider_generation
                            && consumed.sequence == action.payload.sequence
                            && consumed.action_digest == action.action_digest
                    });
                    if session.last_action_kind != PersistedProviderActionKind::ConsumeRepair
                        || !exact
                    {
                        return Err(CompilerControlPlaneError::Integrity);
                    }
                    return Ok(ConsumedTargetRepair {
                        repair: repair.clone(),
                        overflow_digest: overflow_digest.clone(),
                    });
                }
                MutationOrder::Advance => {}
            }
            if state.consumed_repair.as_ref().is_some_and(|consumed| {
                consumed.overflow_version == overflow_version
                    && consumed.overflow_digest == *overflow_digest
            }) {
                return Err(CompilerControlPlaneError::SequenceConflict);
            }
            session.last_sequence = action.payload.sequence;
            session.last_action_digest = action.action_digest.clone();
            session.last_action_kind = PersistedProviderActionKind::ConsumeRepair;
            session.acknowledgement = None;
            session.present = None;
            state.consumed_repair = Some(PersistedRepairConsumption {
                overflow_version,
                overflow_digest: overflow_digest.clone(),
                session_id: action.payload.session_id.clone(),
                provider_generation: action.payload.provider_generation,
                sequence: action.payload.sequence,
                action_digest: action.action_digest.clone(),
                repair: overflow.clone(),
            });
            Ok(ConsumedTargetRepair {
                repair: repair.clone(),
                overflow_digest: overflow_digest.clone(),
            })
        })
    }

    /// Checks an exact present bundle only through a fresh authenticated query at the current
    /// session sequence and governance state.
    pub fn provider_bundle_present(
        &self,
        governance: &CompilerGovernance,
        action: &AuthenticatedProviderAction,
        bundle_id: &VersionId,
        cancellation: &CancellationToken,
    ) -> Result<bool, CompilerControlPlaneError> {
        validate_action_binding(action, governance)?;
        if !matches!(action.payload.action, ProviderActionPayload::InspectPresent) {
            return Err(CompilerControlPlaneError::InvalidInput);
        }
        let state = self.read_provider_state(governance, cancellation)?;
        let Some(session) = state
            .sessions
            .get(&provider_session_key(&action.payload.session_id))
        else {
            return Ok(false);
        };
        validate_session_binding(session, &action.payload)?;
        if session.invalidated || action.payload.sequence != session.last_sequence {
            return Ok(false);
        }
        Ok(session.present.as_ref().is_some_and(|present| {
            &present.bundle_id == bundle_id
                && present.policy_digest == governance.policy_digest
                && present.revocation_epoch == governance.revocation_epoch
                && present.observed_sequence == session.last_sequence
                && present.confidence_parts_per_million == 1_000_000
        }))
    }

    /// Publishes the latest actual overflow through one mutable, fenced tenant checkpoint.
    pub fn record_target_overflow(
        &self,
        governance: &CompilerGovernance,
        evidence: &VerifiedTargetOverflow,
        cancellation: &CancellationToken,
    ) -> Result<(), CompilerControlPlaneError> {
        let repair = &evidence.repair;
        let persisted = PersistedOverflow {
            schema_version: "cigar.target-overflow-repair.v1".to_owned(),
            bundle_id: repair.bundle_id.clone(),
            target_fingerprint: repair.target_fingerprint.clone(),
            observed_tokens: repair.observed_tokens,
            maximum_input_tokens: repair.maximum_input_tokens,
            policy_digest: governance.policy_digest.clone(),
            revocation_epoch: governance.revocation_epoch,
        };
        let cursor = serde_json::to_vec(&persisted)
            .map_err(|_error| CompilerControlPlaneError::Integrity)?;
        let owner = overflow_owner(&cursor);
        let locator = WorkerLocator::new(governance.tenant_id.clone(), TARGET_OVERFLOW_WORKER)
            .map_err(map_service_error)?;
        let expires_at_unix_nanos = governance
            .observed_at_unix_nanos
            .checked_add(OVERFLOW_LEASE_NANOS)
            .ok_or(CompilerControlPlaneError::LimitExceeded)?;
        for _attempt in 0..MAX_CAS_RETRIES {
            let current = self
                .repository
                .worker_get(&locator, cancellation)
                .map_err(map_service_error)?;
            if let Some(state) = &current
                && !state.cursor().is_empty()
            {
                let found = decode_persisted_overflow(state.cursor())?;
                if found == persisted {
                    return Ok(());
                }
            }
            let claimed = if let Some(state) = current {
                let active = state
                    .lease_expires_at_unix_nanos()
                    .is_some_and(|expiry| expiry > governance.observed_at_unix_nanos);
                if active && state.lease_owner() == Some(owner.as_str()) {
                    state
                } else {
                    if active {
                        return Err(CompilerControlPlaneError::Unavailable);
                    }
                    match self.repository.worker_update(
                        &locator,
                        WorkerUpdate::Claim {
                            expected: ServiceExpectedVersion::Version(state.version()),
                            owner: owner.clone(),
                            now_unix_nanos: governance.observed_at_unix_nanos,
                            expires_at_unix_nanos,
                        },
                        cancellation,
                    ) {
                        Ok(claimed) => claimed,
                        Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                            continue;
                        }
                        Err(error) => return Err(map_service_error(error)),
                    }
                }
            } else {
                match self.repository.worker_update(
                    &locator,
                    WorkerUpdate::Claim {
                        expected: ServiceExpectedVersion::Absent,
                        owner: owner.clone(),
                        now_unix_nanos: governance.observed_at_unix_nanos,
                        expires_at_unix_nanos,
                    },
                    cancellation,
                ) {
                    Ok(claimed) => claimed,
                    Err(error) if error.code() == ServiceErrorCode::RevisionConflict => continue,
                    Err(error) => return Err(map_service_error(error)),
                }
            };
            let checkpointed = self
                .repository
                .worker_update(
                    &locator,
                    WorkerUpdate::Checkpoint {
                        expected: ServiceExpectedVersion::Version(claimed.version()),
                        owner: owner.clone(),
                        fencing_token: claimed.fencing_token(),
                        cursor: cursor.clone(),
                        heartbeat_unix_nanos: governance.observed_at_unix_nanos,
                        expires_at_unix_nanos,
                    },
                    cancellation,
                )
                .map_err(map_service_error)?;
            self.repository
                .worker_update(
                    &locator,
                    WorkerUpdate::Release {
                        expected: ServiceExpectedVersion::Version(checkpointed.version()),
                        owner: owner.clone(),
                        fencing_token: checkpointed.fencing_token(),
                        heartbeat_unix_nanos: governance.observed_at_unix_nanos,
                    },
                    cancellation,
                )
                .map_err(map_service_error)?;
            return Ok(());
        }
        Err(CompilerControlPlaneError::SequenceConflict)
    }

    fn read_provider_state(
        &self,
        governance: &CompilerGovernance,
        cancellation: &CancellationToken,
    ) -> Result<PersistedProviderState, CompilerControlPlaneError> {
        let locator = WorkerLocator::new(governance.tenant_id.clone(), PROVIDER_STATE_WORKER)
            .map_err(map_service_error)?;
        let current = self
            .repository
            .worker_get(&locator, cancellation)
            .map_err(map_service_error)?;
        current.map_or_else(
            || Ok(PersistedProviderState::default()),
            |state| decode_provider_state(state.cursor()),
        )
    }

    fn mutate_provider_state<T>(
        &self,
        governance: &CompilerGovernance,
        action: &AuthenticatedProviderAction,
        cancellation: &CancellationToken,
        transition: impl Fn(&mut PersistedProviderState) -> Result<T, CompilerControlPlaneError>,
    ) -> Result<T, CompilerControlPlaneError> {
        let locator = WorkerLocator::new(governance.tenant_id.clone(), PROVIDER_STATE_WORKER)
            .map_err(map_service_error)?;
        let owner = format!("provider-{}", action.action_digest.as_str());
        let expires_at_unix_nanos = governance
            .observed_at_unix_nanos
            .checked_add(PROVIDER_LEASE_NANOS)
            .ok_or(CompilerControlPlaneError::LimitExceeded)?;
        for _attempt in 0..MAX_CAS_RETRIES {
            let current = self
                .repository
                .worker_get(&locator, cancellation)
                .map_err(map_service_error)?;
            let mut provider_state = current.as_ref().map_or_else(
                || Ok(PersistedProviderState::default()),
                |state| decode_provider_state(state.cursor()),
            )?;
            let before = provider_state.clone();
            let output = transition(&mut provider_state)?;
            validate_provider_state(&provider_state)?;
            if provider_state == before {
                return Ok(output);
            }
            let cursor = serde_json::to_vec(&provider_state)
                .map_err(|_error| CompilerControlPlaneError::Integrity)?;
            if cursor.is_empty() || cursor.len() > MAX_PROVIDER_STATE_BYTES {
                return Err(CompilerControlPlaneError::LimitExceeded);
            }
            let claimed = if let Some(state) = current {
                let active = state
                    .lease_expires_at_unix_nanos()
                    .is_some_and(|expiry| expiry > governance.observed_at_unix_nanos);
                if active && state.lease_owner() == Some(owner.as_str()) {
                    state
                } else {
                    if active {
                        return Err(CompilerControlPlaneError::Unavailable);
                    }
                    match self.repository.worker_update(
                        &locator,
                        WorkerUpdate::Claim {
                            expected: ServiceExpectedVersion::Version(state.version()),
                            owner: owner.clone(),
                            now_unix_nanos: governance.observed_at_unix_nanos,
                            expires_at_unix_nanos,
                        },
                        cancellation,
                    ) {
                        Ok(claimed) => claimed,
                        Err(error) if error.code() == ServiceErrorCode::RevisionConflict => {
                            continue;
                        }
                        Err(error) => return Err(map_service_error(error)),
                    }
                }
            } else {
                match self.repository.worker_update(
                    &locator,
                    WorkerUpdate::Claim {
                        expected: ServiceExpectedVersion::Absent,
                        owner: owner.clone(),
                        now_unix_nanos: governance.observed_at_unix_nanos,
                        expires_at_unix_nanos,
                    },
                    cancellation,
                ) {
                    Ok(claimed) => claimed,
                    Err(error) if error.code() == ServiceErrorCode::RevisionConflict => continue,
                    Err(error) => return Err(map_service_error(error)),
                }
            };
            let checkpointed = match self.repository.worker_update(
                &locator,
                WorkerUpdate::Checkpoint {
                    expected: ServiceExpectedVersion::Version(claimed.version()),
                    owner: owner.clone(),
                    fencing_token: claimed.fencing_token(),
                    cursor,
                    heartbeat_unix_nanos: governance.observed_at_unix_nanos,
                    expires_at_unix_nanos,
                },
                cancellation,
            ) {
                Ok(checkpointed) => checkpointed,
                Err(error) if error.code() == ServiceErrorCode::RevisionConflict => continue,
                Err(error) => return Err(map_service_error(error)),
            };
            self.repository
                .worker_update(
                    &locator,
                    WorkerUpdate::Release {
                        expected: ServiceExpectedVersion::Version(checkpointed.version()),
                        owner: owner.clone(),
                        fencing_token: checkpointed.fencing_token(),
                        heartbeat_unix_nanos: governance.observed_at_unix_nanos,
                    },
                    cancellation,
                )
                .map_err(map_service_error)?;
            return Ok(output);
        }
        Err(CompilerControlPlaneError::SequenceConflict)
    }
}

fn decode_persisted_overflow(bytes: &[u8]) -> Result<PersistedOverflow, CompilerControlPlaneError> {
    let persisted =
        serde_json::from_slice(bytes).map_err(|_error| CompilerControlPlaneError::Integrity)?;
    validate_persisted_overflow(&persisted)?;
    Ok(persisted)
}

fn validate_persisted_overflow(
    persisted: &PersistedOverflow,
) -> Result<(), CompilerControlPlaneError> {
    if persisted.schema_version != "cigar.target-overflow-repair.v1"
        || persisted.maximum_input_tokens == 0
        || persisted.observed_tokens <= persisted.maximum_input_tokens
    {
        Err(CompilerControlPlaneError::Integrity)
    } else {
        Ok(())
    }
}

fn target_profile_fingerprint(
    target: &TargetProfile,
) -> Result<ContentDigest, CompilerControlPlaneError> {
    let bytes =
        serde_json::to_vec(target).map_err(|_error| CompilerControlPlaneError::Integrity)?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-TARGET-PROFILE\0v1\0");
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_error| CompilerControlPlaneError::LimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    let mut output = String::from("1220");
    use std::fmt::Write as _;
    for byte in hasher.finalize() {
        write!(&mut output, "{byte:02x}").map_err(|_error| CompilerControlPlaneError::Integrity)?;
    }
    ContentDigest::new(output).map_err(|_error| CompilerControlPlaneError::Integrity)
}

fn overflow_owner(cursor: &[u8]) -> String {
    let digest = Sha256::digest(cursor);
    let mut output = String::from("overflow-");
    use std::fmt::Write as _;
    for byte in digest {
        let _ignored = write!(&mut output, "{byte:02x}");
    }
    output
}

fn map_service_error(error: ServiceError) -> CompilerControlPlaneError {
    match error.code() {
        ServiceErrorCode::InvalidInput | ServiceErrorCode::NotFound => {
            CompilerControlPlaneError::InvalidInput
        }
        ServiceErrorCode::RevisionConflict | ServiceErrorCode::IdempotencyConflict => {
            CompilerControlPlaneError::SequenceConflict
        }
        ServiceErrorCode::LimitExceeded => CompilerControlPlaneError::LimitExceeded,
        ServiceErrorCode::CursorScopeMismatch
        | ServiceErrorCode::Cancelled
        | ServiceErrorCode::InjectedAbort
        | ServiceErrorCode::Unavailable => CompilerControlPlaneError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompilerControlPlaneError, CompilerGovernance, DurableCompilerControlPlane,
        OVERFLOW_LEASE_NANOS, PROVIDER_LEASE_NANOS, PROVIDER_STATE_WORKER, PersistedOverflow,
        ProviderAdapterAuthenticator, ProviderAdapterInput, ProviderHmac, ProviderInvalidationKind,
        ProviderSessionDescriptor, TARGET_OVERFLOW_WORKER, VerifiedTargetOverflow,
        decode_persisted_overflow, overflow_owner, target_profile_fingerprint,
    };
    use cigar_compiler::{
        AppliedDelta, CacheKey, CacheLayer, apply_delta_verified, generate_delta,
    };
    use cigar_protocol::{
        ContentDigest, ContextBundle, MaterializedContext, RecordId, TargetProfile, VersionId,
    };
    use cigar_store::{
        CancellationToken, InMemoryStore, ServiceExpectedVersion, ServiceRepository, SqliteStore,
        WorkerLocator, WorkerUpdate,
    };
    use hmac::Mac as _;
    use std::sync::{Arc, Barrier};

    fn record(value: u64) -> Result<RecordId, Box<dyn std::error::Error>> {
        Ok(RecordId::new(format!(
            "01890f47-8e7d-7b42-a1d2-{value:012x}"
        ))?)
    }

    fn digest(value: u64) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!("1220{value:064x}"))?)
    }

    fn version(value: u64) -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!("1220{value:064x}"))?)
    }

    fn materialized() -> Result<MaterializedContext, Box<dyn std::error::Error>> {
        let fixture = cigar_testkit::deterministic_protocol_fixture("MaterializedContext")
            .ok_or("missing materialized context fixture")?;
        Ok(serde_json::from_value(fixture.input)?)
    }

    fn applied_delta(
        seed: u64,
    ) -> Result<(AppliedDelta, VersionId, VersionId), Box<dyn std::error::Error>> {
        let fixture = cigar_testkit::deterministic_protocol_fixture("ContextBundle")
            .ok_or("missing context bundle fixture")?;
        let mut base: ContextBundle = serde_json::from_value(fixture.input)?;
        base.bundle_id = version(10_000 + seed)?;
        let mut target = base.clone();
        target.bundle_id = version(20_000 + seed)?;
        let mut added = target
            .blocks
            .first()
            .cloned()
            .ok_or("missing context block fixture")?;
        added.block_id = version(30_000 + seed)?;
        target.total_tokens = target
            .total_tokens
            .checked_add(added.token_count)
            .ok_or("token overflow")?;
        target.blocks.push(added);
        target.blocks.sort_by(|left, right| {
            left.lane
                .cmp(&right.lane)
                .then_with(|| left.block_id.cmp(&right.block_id))
        });
        let sealed = generate_delta(&base, &target)?;
        let applied = apply_delta_verified(&base, &target, &sealed)?;
        Ok((applied, base.bundle_id, target.bundle_id))
    }

    fn provider_authority() -> Result<ProviderAdapterAuthenticator, CompilerControlPlaneError> {
        ProviderAdapterAuthenticator::new("local-provider-key.v1", [0x5a; 32])
    }

    #[test]
    fn provider_inputs_reject_tamper_noncanonical_bytes_expiry_and_cross_governance()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = provider_authority()?;
        let governance = CompilerGovernance::new(record(100)?, digest(101)?, 7, 1_000);
        let session = ProviderSessionDescriptor::new(digest(102)?, digest(103)?, 1)?;
        let sealed = authority.seal_establish(&governance, &session, 2_000)?;
        let authenticated = authority.authenticate(&sealed, &governance)?;
        let debug = format!("{sealed:?} {authenticated:?} {session:?}");
        let payload_text = String::from_utf8_lossy(sealed.payload());
        assert!(!debug.contains(digest(102)?.as_str()));
        assert!(!debug.contains(payload_text.as_ref()));

        let mut tampered_payload = sealed.payload().to_vec();
        let last = tampered_payload
            .last_mut()
            .ok_or("missing authenticated payload")?;
        *last ^= 1;
        let tampered = ProviderAdapterInput::from_untrusted_parts(tampered_payload, *sealed.tag())?;
        assert_eq!(
            authority.authenticate(&tampered, &governance),
            Err(CompilerControlPlaneError::Unauthorized)
        );

        let mut tampered_tag = *sealed.tag();
        let first = tampered_tag.first_mut().ok_or("missing tag byte")?;
        *first ^= 1;
        let tampered =
            ProviderAdapterInput::from_untrusted_parts(sealed.payload().to_vec(), tampered_tag)?;
        assert_eq!(
            authority.authenticate(&tampered, &governance),
            Err(CompilerControlPlaneError::Unauthorized)
        );

        let mut noncanonical = sealed.payload().to_vec();
        noncanonical.push(b' ');
        let mut mac = <ProviderHmac as hmac::KeyInit>::new_from_slice(authority.key.as_ref())?;
        mac.update(&noncanonical);
        let tag: [u8; 32] = mac.finalize().into_bytes().into();
        let noncanonical = ProviderAdapterInput::from_untrusted_parts(noncanonical, tag)?;
        assert_eq!(
            authority.authenticate(&noncanonical, &governance),
            Err(CompilerControlPlaneError::Unauthorized)
        );

        let wrong_tenant = CompilerGovernance::new(record(104)?, digest(101)?, 7, 1_000);
        assert_eq!(
            authority.authenticate(&sealed, &wrong_tenant),
            Err(CompilerControlPlaneError::Unauthorized)
        );
        let wrong_policy = CompilerGovernance::new(record(100)?, digest(105)?, 7, 1_000);
        assert_eq!(
            authority.authenticate(&sealed, &wrong_policy),
            Err(CompilerControlPlaneError::Unauthorized)
        );
        let revoked = CompilerGovernance::new(record(100)?, digest(101)?, 8, 1_000);
        assert_eq!(
            authority.authenticate(&sealed, &revoked),
            Err(CompilerControlPlaneError::Unauthorized)
        );
        let expired = CompilerGovernance::new(record(100)?, digest(101)?, 7, 2_000);
        assert_eq!(
            authority.authenticate(&sealed, &expired),
            Err(CompilerControlPlaneError::Unauthorized)
        );
        assert!(ProviderAdapterAuthenticator::new("bad key id", [1; 32]).is_err());
        assert!(ProviderAdapterAuthenticator::new("valid-key", [0; 32]).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_delta_state_survives_restart_and_reset_and_compaction_invalidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider-state.sqlite3");
        let tenant = record(110)?;
        let policy = digest(111)?;
        let governance = CompilerGovernance::new(tenant, policy, 9, 10_000);
        let authority = provider_authority()?;
        let session = ProviderSessionDescriptor::new(digest(112)?, digest(113)?, 1)?;
        let cancellation = CancellationToken::default();
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let control = DurableCompilerControlPlane::new(repository);

        let establish = authority.authenticate(
            &authority.seal_establish(&governance, &session, 20_000)?,
            &governance,
        )?;
        control.establish_provider_session(&governance, &establish, &cancellation)?;
        control.establish_provider_session(&governance, &establish, &cancellation)?;

        let (applied, _base, target) = applied_delta(1)?;
        let substituted_authority =
            ProviderAdapterAuthenticator::new("substituted-provider-key.v1", [0x6b; 32])?;
        let substituted = substituted_authority.authenticate(
            &substituted_authority.seal_applied_delta(
                &governance,
                &session,
                2,
                20_000,
                &applied,
            )?,
            &governance,
        )?;
        assert_eq!(
            control.acknowledge_provider_delta(&governance, &substituted, &applied, &cancellation,),
            Err(CompilerControlPlaneError::Unauthorized)
        );
        let acknowledgement = authority.authenticate(
            &authority.seal_applied_delta(&governance, &session, 2, 20_000, &applied)?,
            &governance,
        )?;
        let recorded = control.acknowledge_provider_delta(
            &governance,
            &acknowledgement,
            &applied,
            &cancellation,
        )?;
        assert_eq!(recorded.target_bundle_id, target);
        assert_eq!(
            control.acknowledge_provider_delta(
                &governance,
                &acknowledgement,
                &applied,
                &cancellation,
            )?,
            recorded
        );

        drop(control);
        let reopened: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let control = DurableCompilerControlPlane::new(reopened);
        let query = authority.authenticate(
            &authority.seal_present_query(&governance, &session, 2, 20_000)?,
            &governance,
        )?;
        assert!(control.provider_bundle_present(&governance, &query, &target, &cancellation)?);
        assert!(!control.provider_bundle_present(
            &governance,
            &query,
            &version(99_999)?,
            &cancellation,
        )?);

        let skipped = authority.authenticate(
            &authority.seal_invalidation(
                &governance,
                &session,
                4,
                20_000,
                ProviderInvalidationKind::Reset,
            )?,
            &governance,
        )?;
        assert_eq!(
            control.invalidate_provider_session(&governance, &skipped, &cancellation),
            Err(CompilerControlPlaneError::SequenceConflict)
        );

        let (different_applied, _base, _target) = applied_delta(2)?;
        assert_eq!(
            control.acknowledge_provider_delta(
                &governance,
                &acknowledgement,
                &different_applied,
                &cancellation,
            ),
            Err(CompilerControlPlaneError::Unauthorized)
        );

        let reset = authority.authenticate(
            &authority.seal_invalidation(
                &governance,
                &session,
                3,
                20_000,
                ProviderInvalidationKind::Reset,
            )?,
            &governance,
        )?;
        control.invalidate_provider_session(&governance, &reset, &cancellation)?;
        control.invalidate_provider_session(&governance, &reset, &cancellation)?;
        let reset_query = authority.authenticate(
            &authority.seal_present_query(&governance, &session, 3, 20_000)?,
            &governance,
        )?;
        assert!(!control.provider_bundle_present(
            &governance,
            &reset_query,
            &target,
            &cancellation,
        )?);

        let generation_two = ProviderSessionDescriptor::new(digest(112)?, digest(113)?, 2)?;
        let establish_two = authority.authenticate(
            &authority.seal_establish(&governance, &generation_two, 20_000)?,
            &governance,
        )?;
        control.establish_provider_session(&governance, &establish_two, &cancellation)?;
        let compact = authority.authenticate(
            &authority.seal_invalidation(
                &governance,
                &generation_two,
                2,
                20_000,
                ProviderInvalidationKind::Compaction,
            )?,
            &governance,
        )?;
        control.invalidate_provider_session(&governance, &compact, &cancellation)?;
        let old_generation_query = authority.authenticate(
            &authority.seal_present_query(&governance, &session, 3, 20_000)?,
            &governance,
        )?;
        assert_eq!(
            control.provider_bundle_present(
                &governance,
                &old_generation_query,
                &target,
                &cancellation,
            ),
            Err(CompilerControlPlaneError::Unauthorized)
        );
        Ok(())
    }

    #[test]
    fn exact_repair_is_consumed_once_and_clears_present_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider-repair.sqlite3");
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let control = DurableCompilerControlPlane::new(repository);
        let tenant = record(120)?;
        let governance = CompilerGovernance::new(tenant, digest(121)?, 4, 30_000);
        let target = TargetProfile {
            provider: "provider".to_owned(),
            model_family: "model".to_owned(),
            tokenizer_fingerprint: digest(122)?,
            materializer_fingerprint: digest(123)?,
            max_context_tokens: 100,
        };
        let target_fingerprint = target_profile_fingerprint(&target)?;
        let authority = provider_authority()?;
        let first_session =
            ProviderSessionDescriptor::new(digest(124)?, target_fingerprint.clone(), 1)?;
        let second_session =
            ProviderSessionDescriptor::new(digest(125)?, target_fingerprint.clone(), 1)?;
        let cancellation = CancellationToken::default();
        for session in [&first_session, &second_session] {
            let establish = authority.authenticate(
                &authority.seal_establish(&governance, session, 40_000)?,
                &governance,
            )?;
            control.establish_provider_session(&governance, &establish, &cancellation)?;
        }
        let mut materialized = materialized()?;
        materialized.bundle_id = version(126)?;
        materialized.token_count = 101;
        let overflow = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
            .ok_or("expected target overflow")?;
        control.record_target_overflow(&governance, &overflow, &cancellation)?;
        let pending = control
            .pending_target_repair(&governance, &target_fingerprint, &cancellation)?
            .ok_or("missing target repair")?;
        assert!(
            control
                .pending_target_repair(&governance, &digest(127)?, &cancellation)?
                .is_none()
        );

        let first_consume = authority.authenticate(
            &authority.seal_repair_consumption(&governance, &first_session, 2, 40_000, &pending)?,
            &governance,
        )?;
        let consumed = control.consume_target_repair(&governance, &first_consume, &cancellation)?;
        assert_eq!(consumed.repair().bundle_id, materialized.bundle_id);
        assert_eq!(consumed.repair().observed_tokens, 101);
        assert_eq!(
            control.consume_target_repair(&governance, &first_consume, &cancellation)?,
            consumed
        );
        drop(control);
        let reopened: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let control = DurableCompilerControlPlane::new(reopened);
        assert_eq!(
            control.consume_target_repair(&governance, &first_consume, &cancellation)?,
            consumed
        );
        assert!(
            control
                .pending_target_repair(&governance, &target_fingerprint, &cancellation)?
                .is_none()
        );

        let second_consume = authority.authenticate(
            &authority.seal_repair_consumption(
                &governance,
                &second_session,
                2,
                40_000,
                &pending,
            )?,
            &governance,
        )?;
        assert_eq!(
            control.consume_target_repair(&governance, &second_consume, &cancellation),
            Err(CompilerControlPlaneError::SequenceConflict)
        );

        materialized.bundle_id = version(128)?;
        materialized.token_count = 102;
        let next_overflow = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
            .ok_or("expected next target overflow")?;
        control.record_target_overflow(&governance, &next_overflow, &cancellation)?;
        let next_pending = control
            .pending_target_repair(&governance, &target_fingerprint, &cancellation)?
            .ok_or("missing next target repair")?;
        assert_ne!(next_pending.overflow_digest, pending.overflow_digest);
        let (post_repair_delta, _base, _target) = applied_delta(5)?;
        let post_repair_acknowledgement = authority.authenticate(
            &authority.seal_applied_delta(
                &governance,
                &first_session,
                3,
                40_000,
                &post_repair_delta,
            )?,
            &governance,
        )?;
        control.acknowledge_provider_delta(
            &governance,
            &post_repair_acknowledgement,
            &post_repair_delta,
            &cancellation,
        )?;
        assert_eq!(
            control.consume_target_repair(&governance, &first_consume, &cancellation)?,
            consumed
        );
        Ok(())
    }

    #[test]
    fn provider_checkpoint_abort_is_atomic_and_same_action_recovers_crashed_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        let memory = Arc::new(InMemoryStore::default());
        let repository: Arc<dyn ServiceRepository> = memory.clone();
        let control = DurableCompilerControlPlane::new(Arc::clone(&repository));
        let tenant = record(130)?;
        let governance = CompilerGovernance::new(tenant.clone(), digest(131)?, 2, 50_000);
        let authority = provider_authority()?;
        let session = ProviderSessionDescriptor::new(digest(132)?, digest(133)?, 1)?;
        let cancellation = CancellationToken::default();
        let establish = authority.authenticate(
            &authority.seal_establish(&governance, &session, 60_000)?,
            &governance,
        )?;
        control.establish_provider_session(&governance, &establish, &cancellation)?;
        let (applied, _base, target) = applied_delta(3)?;
        let acknowledgement = authority.authenticate(
            &authority.seal_applied_delta(&governance, &session, 2, 60_000, &applied)?,
            &governance,
        )?;

        let locator = WorkerLocator::new(tenant, PROVIDER_STATE_WORKER)?;
        let current = repository
            .worker_get(&locator, &cancellation)?
            .ok_or("provider checkpoint missing")?;
        let owner = format!("provider-{}", acknowledgement.action_digest.as_str());
        repository.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Version(current.version()),
                owner,
                now_unix_nanos: governance.observed_at_unix_nanos,
                expires_at_unix_nanos: governance
                    .observed_at_unix_nanos
                    .checked_add(PROVIDER_LEASE_NANOS)
                    .ok_or("lease overflow")?,
            },
            &cancellation,
        )?;
        memory.fail_next_commit();
        assert_eq!(
            control.acknowledge_provider_delta(
                &governance,
                &acknowledgement,
                &applied,
                &cancellation,
            ),
            Err(CompilerControlPlaneError::Unavailable)
        );
        assert_eq!(
            control
                .read_provider_state(&governance, &cancellation)?
                .sessions
                .get(session.session_id.as_str())
                .ok_or("provider session missing")?
                .last_sequence,
            1
        );

        let restarted = DurableCompilerControlPlane::new(repository);
        restarted.acknowledge_provider_delta(
            &governance,
            &acknowledgement,
            &applied,
            &cancellation,
        )?;
        let query = authority.authenticate(
            &authority.seal_present_query(&governance, &session, 2, 60_000)?,
            &governance,
        )?;
        assert!(restarted.provider_bundle_present(&governance, &query, &target, &cancellation,)?);
        Ok(())
    }

    #[test]
    fn concurrent_same_sequence_actions_publish_exactly_one_valid_cas_transition()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let control = DurableCompilerControlPlane::new(repository);
        let governance = CompilerGovernance::new(record(135)?, digest(136)?, 3, 65_000);
        let authority = provider_authority()?;
        let session = ProviderSessionDescriptor::new(digest(137)?, digest(138)?, 1)?;
        let cancellation = CancellationToken::default();
        let establish = authority.authenticate(
            &authority.seal_establish(&governance, &session, 75_000)?,
            &governance,
        )?;
        control.establish_provider_session(&governance, &establish, &cancellation)?;
        let (applied, _base, _target) = applied_delta(4)?;
        let acknowledgement = authority.authenticate(
            &authority.seal_applied_delta(&governance, &session, 2, 75_000, &applied)?,
            &governance,
        )?;
        let reset = authority.authenticate(
            &authority.seal_invalidation(
                &governance,
                &session,
                2,
                75_000,
                ProviderInvalidationKind::Reset,
            )?,
            &governance,
        )?;
        let barrier = Arc::new(Barrier::new(3));
        let ack_control = control.clone();
        let ack_governance = governance.clone();
        let ack_barrier = Arc::clone(&barrier);
        let ack_thread = std::thread::spawn(move || {
            ack_barrier.wait();
            ack_control
                .acknowledge_provider_delta(
                    &ack_governance,
                    &acknowledgement,
                    &applied,
                    &CancellationToken::default(),
                )
                .map(|_acknowledgement| ())
        });
        let reset_control = control.clone();
        let reset_governance = governance.clone();
        let reset_barrier = Arc::clone(&barrier);
        let reset_thread = std::thread::spawn(move || {
            reset_barrier.wait();
            reset_control.invalidate_provider_session(
                &reset_governance,
                &reset,
                &CancellationToken::default(),
            )
        });
        barrier.wait();
        let ack_result = ack_thread.join().map_err(|_panic| "ack thread panicked")?;
        let reset_result = reset_thread
            .join()
            .map_err(|_panic| "reset thread panicked")?;
        assert_ne!(ack_result.is_ok(), reset_result.is_ok());
        for error in [ack_result.err(), reset_result.err()].into_iter().flatten() {
            assert!(matches!(
                error,
                CompilerControlPlaneError::SequenceConflict
                    | CompilerControlPlaneError::Unavailable
                    | CompilerControlPlaneError::Unauthorized
            ));
        }
        super::validate_provider_state(
            &control.read_provider_state(&governance, &CancellationToken::default())?,
        )?;
        Ok(())
    }

    #[test]
    fn provider_state_has_a_hard_session_bound_and_prunes_only_expired_sessions()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let control = DurableCompilerControlPlane::new(repository);
        let tenant = record(140)?;
        let policy = digest(141)?;
        let governance = CompilerGovernance::new(tenant.clone(), policy.clone(), 1, 70_000);
        let authority = provider_authority()?;
        let cancellation = CancellationToken::default();
        for index in 0..super::MAX_PROVIDER_SESSIONS {
            let index = u64::try_from(index)?;
            let session = ProviderSessionDescriptor::new(digest(50_000 + index)?, digest(142)?, 1)?;
            let establish = authority.authenticate(
                &authority.seal_establish(&governance, &session, 80_000)?,
                &governance,
            )?;
            control.establish_provider_session(&governance, &establish, &cancellation)?;
        }
        let overflow_session = ProviderSessionDescriptor::new(digest(60_000)?, digest(142)?, 1)?;
        let overflow_establish = authority.authenticate(
            &authority.seal_establish(&governance, &overflow_session, 80_000)?,
            &governance,
        )?;
        assert_eq!(
            control.establish_provider_session(&governance, &overflow_establish, &cancellation),
            Err(CompilerControlPlaneError::LimitExceeded)
        );
        assert_eq!(
            control
                .read_provider_state(&governance, &cancellation)?
                .sessions
                .len(),
            super::MAX_PROVIDER_SESSIONS
        );

        let later = CompilerGovernance::new(tenant, policy, 1, 80_000);
        let replacement = ProviderSessionDescriptor::new(digest(60_001)?, digest(142)?, 1)?;
        let replacement_establish = authority.authenticate(
            &authority.seal_establish(&later, &replacement, 90_000)?,
            &later,
        )?;
        control.establish_provider_session(&later, &replacement_establish, &cancellation)?;
        let state = control.read_provider_state(&later, &cancellation)?;
        assert_eq!(state.sessions.len(), 1);
        assert!(state.sessions.contains_key(replacement.session_id.as_str()));
        Ok(())
    }

    #[test]
    fn actual_overflow_checkpoint_survives_restart_and_more_than_1024_updates()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("compiler-control.sqlite3");
        let tenant = record(1)?;
        let policy = digest(2)?;
        let governance = CompilerGovernance::new(tenant.clone(), policy, 7, 1_000_000_000);
        let target = TargetProfile {
            provider: "provider".to_owned(),
            model_family: "model".to_owned(),
            tokenizer_fingerprint: digest(3)?,
            materializer_fingerprint: digest(4)?,
            max_context_tokens: 100,
        };
        let mut materialized = materialized()?;
        materialized.bundle_id = version(5)?;
        materialized.token_count = 101;
        let evidence = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
            .ok_or("expected actual overflow")?;
        let cancellation = CancellationToken::default();
        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let control = DurableCompilerControlPlane::new(repository);
            control.record_target_overflow(&governance, &evidence, &cancellation)?;
        }
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let control = DurableCompilerControlPlane::new(Arc::clone(&repository));
        let changed = CompilerGovernance::new(tenant.clone(), digest(6)?, 8, 1_000_000_000);
        control.record_target_overflow(&changed, &evidence, &cancellation)?;
        let locator = WorkerLocator::new(tenant.clone(), TARGET_OVERFLOW_WORKER)?;
        let checkpoint = repository
            .worker_get(&locator, &cancellation)?
            .ok_or("missing overflow checkpoint")?;
        let persisted = decode_persisted_overflow(checkpoint.cursor())?;
        assert_eq!(persisted.policy_digest, changed.policy_digest);
        assert_eq!(persisted.revocation_epoch, 8);
        assert_eq!(
            persisted.target_fingerprint,
            target_profile_fingerprint(&target)?
        );
        drop(control);
        drop(repository);
        let reopened: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let checkpoint = reopened
            .worker_get(&locator, &cancellation)?
            .ok_or("overflow checkpoint was not restart safe")?;
        assert_eq!(decode_persisted_overflow(checkpoint.cursor())?, persisted);

        let memory: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let control = DurableCompilerControlPlane::new(Arc::clone(&memory));
        for index in 0..1_025_u64 {
            materialized.bundle_id = version(10_000 + index)?;
            materialized.token_count = 101 + u32::try_from(index % 100)?;
            let evidence = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
                .ok_or("expected loop overflow")?;
            control.record_target_overflow(&changed, &evidence, &cancellation)?;
        }
        let checkpoint = memory
            .worker_get(&locator, &cancellation)?
            .ok_or("missing overflow checkpoint")?;
        assert!(checkpoint.version() > 1_024);
        assert!(checkpoint.lease_owner().is_none());
        assert_eq!(
            decode_persisted_overflow(checkpoint.cursor())?.bundle_id,
            materialized.bundle_id
        );

        materialized.token_count = target.max_context_tokens;
        assert!(VerifiedTargetOverflow::from_materialization(&materialized, &target)?.is_none());
        Ok(())
    }

    #[test]
    fn overflow_checkpoint_recovers_crashed_claim_and_exact_checkpoint_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(
            directory.path().join("overflow-recovery.sqlite3"),
        )?);
        let control = DurableCompilerControlPlane::new(Arc::clone(&repository));
        let tenant = record(20)?;
        let policy = digest(21)?;
        let target = TargetProfile {
            provider: "provider".to_owned(),
            model_family: "model".to_owned(),
            tokenizer_fingerprint: digest(22)?,
            materializer_fingerprint: digest(23)?,
            max_context_tokens: 100,
        };
        let mut materialized = materialized()?;
        materialized.bundle_id = version(24)?;
        materialized.token_count = 101;
        let evidence = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
            .ok_or("overflow evidence")?;
        let locator = WorkerLocator::new(tenant.clone(), TARGET_OVERFLOW_WORKER)?;
        let cancellation = CancellationToken::default();
        repository.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Absent,
                owner: "crashed-claim".to_owned(),
                now_unix_nanos: 10,
                expires_at_unix_nanos: 20,
            },
            &cancellation,
        )?;
        let blocked = CompilerGovernance::new(tenant.clone(), policy.clone(), 1, 10);
        assert_eq!(
            control.record_target_overflow(&blocked, &evidence, &cancellation),
            Err(CompilerControlPlaneError::Unavailable)
        );
        let recovered = CompilerGovernance::new(tenant.clone(), policy.clone(), 1, 20);
        control.record_target_overflow(&recovered, &evidence, &cancellation)?;

        materialized.bundle_id = version(25)?;
        let next_evidence = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
            .ok_or("next overflow evidence")?;
        let persisted = PersistedOverflow {
            schema_version: "cigar.target-overflow-repair.v1".to_owned(),
            bundle_id: next_evidence.repair.bundle_id.clone(),
            target_fingerprint: next_evidence.repair.target_fingerprint.clone(),
            observed_tokens: next_evidence.repair.observed_tokens,
            maximum_input_tokens: next_evidence.repair.maximum_input_tokens,
            policy_digest: policy.clone(),
            revocation_epoch: 1,
        };
        let cursor = serde_json::to_vec(&persisted)?;
        let owner = overflow_owner(&cursor);
        let current = repository
            .worker_get(&locator, &cancellation)?
            .ok_or("released overflow checkpoint missing")?;
        let claimed = repository.worker_update(
            &locator,
            WorkerUpdate::Claim {
                expected: ServiceExpectedVersion::Version(current.version()),
                owner: owner.clone(),
                now_unix_nanos: 20,
                expires_at_unix_nanos: 20 + OVERFLOW_LEASE_NANOS,
            },
            &cancellation,
        )?;
        repository.worker_update(
            &locator,
            WorkerUpdate::Checkpoint {
                expected: ServiceExpectedVersion::Version(claimed.version()),
                owner,
                fencing_token: claimed.fencing_token(),
                cursor,
                heartbeat_unix_nanos: 20,
                expires_at_unix_nanos: 20 + OVERFLOW_LEASE_NANOS,
            },
            &cancellation,
        )?;
        control.record_target_overflow(&recovered, &next_evidence, &cancellation)?;

        materialized.bundle_id = version(26)?;
        let distinct = VerifiedTargetOverflow::from_materialization(&materialized, &target)?
            .ok_or("distinct overflow evidence")?;
        assert_eq!(
            control.record_target_overflow(&recovered, &distinct, &cancellation),
            Err(CompilerControlPlaneError::Unavailable)
        );
        let after_expiry = CompilerGovernance::new(tenant, policy, 1, 21 + OVERFLOW_LEASE_NANOS);
        control.record_target_overflow(&after_expiry, &distinct, &cancellation)?;
        Ok(())
    }

    #[test]
    fn governed_cache_is_policy_scoped_and_restarts_cold() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("compiler-cache.sqlite3");
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let control = DurableCompilerControlPlane::new(Arc::clone(&repository));
        let policy = digest(10)?;
        let key = CacheKey::new(
            CacheLayer::Materialization,
            record(11)?.as_str(),
            digest(12)?.as_str(),
            digest(13)?,
        )
        .ok_or("cache key")?;
        assert!(control.cache_insert(key.clone(), b"materialized".to_vec(), policy.clone(), 4,)?);
        assert_eq!(
            control.cache_get(&key, &policy, 4, |_key| true)?,
            Some(b"materialized".to_vec())
        );
        assert!(
            control
                .cache_get(&key, &digest(14)?, 4, |_key| true)?
                .is_none()
        );
        assert!(control.cache_insert(key.clone(), b"materialized".to_vec(), policy.clone(), 4,)?);
        let restarted = DurableCompilerControlPlane::new(repository);
        assert!(
            restarted
                .cache_get(&key, &policy, 4, |_key| true)?
                .is_none()
        );
        Ok(())
    }
}
